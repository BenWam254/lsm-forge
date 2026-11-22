use crate::bloom::BloomFilter;
use crate::cache::{BlockCache, BlockCacheKey};
use crate::coding::{
    crc32c, decode_varint32, decode_varint64, encode_varint32, encode_varint64,
};
use crate::skiplist::InternalKey;
use crate::wal::ValueType;
use std::cmp::Ordering;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const TARGET_BLOCK_SIZE: usize = 4096;
const RESTART_INTERVAL: usize = 16;
const SST_MAGIC: &[u8; 8] = b"LSMFRG01";
const FOOTER_LEN: usize = 44;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHandle {
    pub offset: u64,
    pub size: u64,
}

impl BlockHandle {
    fn encode(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.offset.to_le_bytes());
        dst.extend_from_slice(&self.size.to_le_bytes());
    }

    fn decode(src: &[u8]) -> Option<Self> {
        if src.len() < 16 {
            return None;
        }
        let offset = u64::from_le_bytes(src[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(src[8..16].try_into().unwrap());
        Some(Self { offset, size })
    }
}

/// Encodes an InternalKey as `[user_key][!seq (8B BE)][!kind (1B)]` so raw byte comparison
/// matches `(user_key ASC, seq DESC, kind DESC)` identically to `InternalKey::cmp`.
pub fn encode_internal_key(key: &InternalKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.user_key.len() + 9);
    out.extend_from_slice(&key.user_key);
    out.extend_from_slice(&(!key.seq).to_be_bytes());
    out.push(!(key.kind as u8));
    out
}

pub fn decode_internal_key(raw: &[u8]) -> Option<InternalKey> {
    if raw.len() < 9 {
        return None;
    }
    let split = raw.len() - 9;
    let user_key = raw[..split].to_vec();
    let inv_seq = u64::from_be_bytes(raw[split..split + 8].try_into().unwrap());
    let kind = ValueType::from_u8(!raw[split + 8])?;
    Some(InternalKey {
        user_key,
        seq: !inv_seq,
        kind,
    })
}

fn shared_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

struct DataBlockBuilder {
    buf: Vec<u8>,
    restarts: Vec<u32>,
    counter: usize,
    last_key: Vec<u8>,
}

impl DataBlockBuilder {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(TARGET_BLOCK_SIZE),
            restarts: vec![0],
            counter: 0,
            last_key: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn estimated_size(&self) -> usize {
        self.buf.len() + self.restarts.len() * 4 + 4
    }

    fn add(&mut self, encoded_key: &[u8], value: &[u8]) {
        let shared = if self.counter < RESTART_INTERVAL {
            shared_prefix_len(&self.last_key, encoded_key)
        } else {
            self.restarts.push(self.buf.len() as u32);
            self.counter = 0;
            0
        };
        let unshared = encoded_key.len() - shared;

        encode_varint32(shared as u32, &mut self.buf);
        encode_varint32(unshared as u32, &mut self.buf);
        encode_varint64(value.len() as u64, &mut self.buf);
        self.buf.extend_from_slice(&encoded_key[shared..]);
        self.buf.extend_from_slice(value);

        self.last_key.clear();
        self.last_key.extend_from_slice(encoded_key);
        self.counter += 1;
    }

    fn finish(&mut self) -> Vec<u8> {
        for &r in &self.restarts {
            self.buf.extend_from_slice(&r.to_le_bytes());
        }
        self.buf
            .extend_from_slice(&(self.restarts.len() as u32).to_le_bytes());
        let finished = std::mem::take(&mut self.buf);
        self.restarts = vec![0];
        self.counter = 0;
        self.last_key.clear();
        finished
    }
}

#[derive(Debug, Clone)]
pub struct SstMeta {
    pub id: u64,
    pub level: usize,
    pub file_size: u64,
    pub smallest_key: InternalKey,
    pub largest_key: InternalKey,
    pub entry_count: u64,
}

pub struct SstBuilder {
    id: u64,
    level: usize,
    path: PathBuf,
    file: File,
    offset: u64,
    block_builder: DataBlockBuilder,
    index_entries: Vec<(Vec<u8>, BlockHandle)>,
    user_keys: Vec<Vec<u8>>,
    last_encoded_key: Vec<u8>,
    smallest_key: Option<InternalKey>,
    largest_key: Option<InternalKey>,
    entry_count: u64,
}

impl SstBuilder {
    pub fn create(id: u64, level: usize, path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;
        Ok(Self {
            id,
            level,
            path,
            file,
            offset: 0,
            block_builder: DataBlockBuilder::new(),
            index_entries: Vec::new(),
            user_keys: Vec::new(),
            last_encoded_key: Vec::new(),
            smallest_key: None,
            largest_key: None,
            entry_count: 0,
        })
    }

    pub fn add(&mut self, key: &InternalKey, value: &[u8]) -> io::Result<()> {
        if self.smallest_key.is_none() {
            self.smallest_key = Some(key.clone());
        }
        self.largest_key = Some(key.clone());

        if self.user_keys.last().map(Vec::as_slice) != Some(key.user_key.as_slice()) {
            self.user_keys.push(key.user_key.clone());
        }

        let enc_key = encode_internal_key(key);
        self.block_builder.add(&enc_key, value);
        self.last_encoded_key = enc_key;
        self.entry_count += 1;

        if self.block_builder.estimated_size() >= TARGET_BLOCK_SIZE {
            self.flush_data_block()?;
        }
        Ok(())
    }

    fn flush_data_block(&mut self) -> io::Result<()> {
        if self.block_builder.is_empty() {
            return Ok(());
        }
        let raw_block = self.block_builder.finish();
        let handle = self.write_framed_block(&raw_block)?;
        self.index_entries
            .push((self.last_encoded_key.clone(), handle));
        Ok(())
    }

    fn write_framed_block(&mut self, data: &[u8]) -> io::Result<BlockHandle> {
        let crc = crc32c(data);
        let handle = BlockHandle {
            offset: self.offset,
            size: data.len() as u64,
        };
        self.file.write_all(data)?;
        self.file.write_all(&crc.to_le_bytes())?;
        self.offset += data.len() as u64 + 4;
        Ok(handle)
    }

    pub fn finish(mut self) -> io::Result<SstMeta> {
        self.flush_data_block()?;

        // 1. Write Bloom filter block
        let key_refs: Vec<&[u8]> = self.user_keys.iter().map(Vec::as_slice).collect();
        let bloom = BloomFilter::build(&key_refs, 10);
        let filter_handle = self.write_framed_block(&bloom.encode())?;

        // 2. Write Index block
        let mut index_builder = DataBlockBuilder::new();
        for (sep_key, handle) in &self.index_entries {
            let mut handle_bytes = Vec::with_capacity(16);
            handle.encode(&mut handle_bytes);
            index_builder.add(sep_key, &handle_bytes);
        }
        let index_raw = index_builder.finish();
        let index_handle = self.write_framed_block(&index_raw)?;

        // 3. Write 44-byte Footer
        let mut footer = Vec::with_capacity(FOOTER_LEN);
        index_handle.encode(&mut footer);
        filter_handle.encode(&mut footer);
        let footer_crc = crc32c(&footer);
        footer.extend_from_slice(&footer_crc.to_le_bytes());
        footer.extend_from_slice(SST_MAGIC);
        self.file.write_all(&footer)?;
        self.file.sync_data()?;
        self.offset += FOOTER_LEN as u64;

        Ok(SstMeta {
            id: self.id,
            level: self.level,
            file_size: self.offset,
            smallest_key: self
                .smallest_key
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty SSTable"))?,
            largest_key: self.largest_key.unwrap(),
            entry_count: self.entry_count,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Decoded block entries for fast binary search and sequential iteration.
pub struct DecodedBlock {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl DecodedBlock {
    pub fn decode(raw: &[u8]) -> io::Result<Self> {
        if raw.len() < 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "block too short"));
        }
        let num_restarts = u32::from_le_bytes(raw[raw.len() - 4..].try_into().unwrap()) as usize;
        let restarts_bytes = num_restarts
            .checked_mul(4)
            .and_then(|n| n.checked_add(4))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid restart count"))?;
        if raw.len() < restarts_bytes {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupt block footer"));
        }
        let data_end = raw.len() - restarts_bytes;
        let data = &raw[..data_end];

        let mut entries = Vec::new();
        let mut pos = 0usize;
        let mut last_key = Vec::new();

        while pos < data.len() {
            let (shared, n1) = decode_varint32(&data[pos..])
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad shared varint"))?;
            pos += n1;
            let (unshared, n2) = decode_varint32(&data[pos..])
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad unshared varint"))?;
            pos += n2;
            let (val_len, n3) = decode_varint64(&data[pos..])
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad val_len varint"))?;
            pos += n3;

            let shared = shared as usize;
            let unshared = unshared as usize;
            let val_len = val_len as usize;

            if shared > last_key.len() || pos + unshared + val_len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated block entry"));
            }

            let mut full_key = Vec::with_capacity(shared + unshared);
            full_key.extend_from_slice(&last_key[..shared]);
            full_key.extend_from_slice(&data[pos..pos + unshared]);
            pos += unshared;

            let value = data[pos..pos + val_len].to_vec();
            pos += val_len;

            last_key = full_key.clone();
            entries.push((full_key, value));
        }

        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.entries
    }
}

pub struct SstReader {
    pub meta: SstMeta,
    path: PathBuf,
    bloom: BloomFilter,
    index: Vec<(Vec<u8>, BlockHandle)>,
}

impl SstReader {
    pub fn open(meta: SstMeta, path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = File::open(&path)?;
        let file_len = file.metadata()?.len();
        if file_len < FOOTER_LEN as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "SSTable truncated"));
        }

        file.seek(SeekFrom::End(-(FOOTER_LEN as i64)))?;
        let mut footer = [0u8; FOOTER_LEN];
        file.read_exact(&mut footer)?;

        if &footer[36..44] != SST_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SSTable magic"));
        }
        let expected_footer_crc = u32::from_le_bytes(footer[32..36].try_into().unwrap());
        if crc32c(&footer[0..32]) != expected_footer_crc {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupt SSTable footer"));
        }

        let index_handle = BlockHandle::decode(&footer[0..16]).unwrap();
        let filter_handle = BlockHandle::decode(&footer[16..32]).unwrap();

        let filter_raw = read_verified_block(&mut file, filter_handle)?;
        let bloom = BloomFilter::decode(&filter_raw)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "corrupt Bloom filter"))?;

        let index_raw = read_verified_block(&mut file, index_handle)?;
        let index_block = DecodedBlock::decode(&index_raw)?;
        let mut index = Vec::with_capacity(index_block.entries.len());
        for (k, v) in index_block.entries {
            let handle = BlockHandle::decode(&v)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "corrupt index handle"))?;
            index.push((k, handle));
        }

        Ok(Self {
            meta,
            path,
            bloom,
            index,
        })
    }

    fn read_data_block(
        &self,
        handle: BlockHandle,
        cache: Option<&BlockCache>,
    ) -> io::Result<Arc<[u8]>> {
        let key = BlockCacheKey {
            sst_id: self.meta.id,
            offset: handle.offset,
        };
        if let Some(c) = cache
            && let Some(cached) = c.get(key)
        {
            return Ok(cached);
        }

        let mut file = File::open(&self.path)?;
        let raw = read_verified_block(&mut file, handle)?;
        let arc: Arc<[u8]> = Arc::from(raw);
        if let Some(c) = cache {
            c.insert(key, arc.clone());
        }
        Ok(arc)
    }

    /// MVCC point lookup at `snapshot_seq` using Bloom filter + Index binary search.
    pub fn get(
        &self,
        user_key: &[u8],
        snapshot_seq: u64,
        cache: Option<&BlockCache>,
    ) -> io::Result<Option<Option<Vec<u8>>>> {
        if user_key < self.meta.smallest_key.user_key.as_slice()
            || user_key > self.meta.largest_key.user_key.as_slice()
        {
            return Ok(None);
        }
        if !self.bloom.may_contain(user_key) {
            return Ok(None);
        }

        let seek_encoded = encode_internal_key(&InternalKey {
            user_key: user_key.to_vec(),
            seq: snapshot_seq,
            kind: ValueType::Value,
        });

        // Find the first index block whose largest_key >= seek_encoded
        let block_idx = self
            .index
            .partition_point(|(last_key, _)| last_key.as_slice() < seek_encoded.as_slice());
        let Some((_, handle)) = self.index.get(block_idx) else {
            return Ok(None);
        };

        let raw_block = self.read_data_block(*handle, cache)?;
        let block = DecodedBlock::decode(&raw_block)?;

        let entry_idx = block
            .entries
            .partition_point(|(k, _)| k.as_slice() < seek_encoded.as_slice());
        let Some((found_raw_key, found_val)) = block.entries.get(entry_idx) else {
            return Ok(None);
        };

        let found_key = decode_internal_key(found_raw_key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad internal key"))?;

        if found_key.user_key.as_slice() == user_key && found_key.seq <= snapshot_seq {
            match found_key.kind {
                ValueType::Value => Ok(Some(Some(found_val.clone()))),
                ValueType::Deletion => Ok(Some(None)),
            }
        } else {
            Ok(None)
        }
    }

    /// Scans all `(InternalKey, value)` entries in sorted order (used by compaction).
    pub fn iter_all(&self) -> io::Result<Vec<(InternalKey, Vec<u8>)>> {
        let mut out = Vec::with_capacity(self.meta.entry_count as usize);
        for (_, handle) in &self.index {
            let raw_block = self.read_data_block(*handle, None)?;
            let block = DecodedBlock::decode(&raw_block)?;
            for (raw_k, v) in block.entries {
                let ik = decode_internal_key(&raw_k).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "bad internal key in SSTable")
                })?;
                out.push((ik, v));
            }
        }
        Ok(out)
    }
}

fn read_verified_block(file: &mut File, handle: BlockHandle) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(handle.offset))?;
    let mut buf = vec![0u8; handle.size as usize + 4];
    file.read_exact(&mut buf)?;
    let (data, crc_bytes) = buf.split_at(handle.size as usize);
    let expected_crc = u32::from_le_bytes(crc_bytes.try_into().unwrap());
    if crc32c(data) != expected_crc {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SSTable block CRC32C mismatch",
        ));
    }
    Ok(data.to_vec())
}

pub fn internal_key_cmp(a: &InternalKey, b: &InternalKey) -> Ordering {
    a.cmp(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_sst_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("lsm_forge_sst_{tag}_{nanos}.sst"))
    }

    #[test]
    fn builds_queries_and_verifies_multi_block_sstable() {
        let path = temp_sst_path("multi");
        let mut builder = SstBuilder::create(7, 0, &path).unwrap();

        // Insert 400 keys across multiple 4KB prefix-compressed blocks
        for i in 0..400u32 {
            let key = InternalKey {
                user_key: format!("tenant:acme:order:{i:05}").into_bytes(),
                seq: (i + 1) as u64,
                kind: if i == 250 {
                    ValueType::Deletion
                } else {
                    ValueType::Value
                },
            };
            let val = if i == 250 {
                Vec::new()
            } else {
                format!("payload-{i:05}-xxxxxxxxxxxxxxxxxxxx").into_bytes()
            };
            builder.add(&key, &val).unwrap();
        }
        let meta = builder.finish().unwrap();
        assert_eq!(meta.entry_count, 400);

        let cache = BlockCache::new(64 * 1024);
        let reader = SstReader::open(meta, &path).unwrap();

        // Hit existing key
        let hit = reader
            .get(b"tenant:acme:order:00123", 500, Some(&cache))
            .unwrap();
        assert_eq!(
            hit,
            Some(Some(b"payload-00123-xxxxxxxxxxxxxxxxxxxx".to_vec()))
        );

        // Hit deleted key -> Some(None) tombstone
        let deleted = reader
            .get(b"tenant:acme:order:00250", 500, Some(&cache))
            .unwrap();
        assert_eq!(deleted, Some(None));

        // Snapshot before seq 124 doesn't see order:00123 (seq 124)
        let invisible = reader
            .get(b"tenant:acme:order:00123", 100, Some(&cache))
            .unwrap();
        assert_eq!(invisible, None);

        // Non-existent key rejected by Bloom filter
        let miss = reader
            .get(b"tenant:acme:order:99999", 500, Some(&cache))
            .unwrap();
        assert_eq!(miss, None);

        let _ = std::fs::remove_file(&path);
    }
}