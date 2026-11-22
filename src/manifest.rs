use crate::coding::{
    crc32c, decode_len_prefixed, decode_varint32, decode_varint64, encode_len_prefixed,
    encode_varint32, encode_varint64,
};
use crate::sstable::{decode_internal_key, encode_internal_key, SstMeta};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const NUM_LEVELS: usize = 5;
const MANIFEST_MAGIC: &[u8; 8] = b"LSMMNFT1";

#[derive(Debug, Clone)]
pub struct VersionSet {
    pub next_sst_id: u64,
    pub wal_id: u64,
    pub last_seq: u64,
    pub levels: [Vec<SstMeta>; NUM_LEVELS],
}

impl Default for VersionSet {
    fn default() -> Self {
        Self {
            next_sst_id: 1,
            wal_id: 1,
            last_seq: 0,
            levels: std::array::from_fn(|_| Vec::new()),
        }
    }
}

impl VersionSet {
    pub fn alloc_sst_id(&mut self) -> u64 {
        let id = self.next_sst_id;
        self.next_sst_id += 1;
        id
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        encode_varint64(self.next_sst_id, &mut body);
        encode_varint64(self.wal_id, &mut body);
        encode_varint64(self.last_seq, &mut body);

        for level_tables in &self.levels {
            encode_varint32(level_tables.len() as u32, &mut body);
            for meta in level_tables {
                encode_varint64(meta.id, &mut body);
                encode_varint32(meta.level as u32, &mut body);
                encode_varint64(meta.file_size, &mut body);
                encode_varint64(meta.entry_count, &mut body);
                encode_len_prefixed(&encode_internal_key(&meta.smallest_key), &mut body);
                encode_len_prefixed(&encode_internal_key(&meta.largest_key), &mut body);
            }
        }

        let crc = crc32c(&body);
        let mut out = Vec::with_capacity(8 + 4 + body.len());
        out.extend_from_slice(MANIFEST_MAGIC);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub fn decode(raw: &[u8]) -> io::Result<Self> {
        if raw.len() < 12 || &raw[0..8] != MANIFEST_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid MANIFEST header",
            ));
        }
        let expected_crc = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let body = &raw[12..];
        if crc32c(body) != expected_crc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "corrupt MANIFEST CRC32C",
            ));
        }

        let mut pos = 0usize;
        let (next_sst_id, n1) = decode_varint64(&body[pos..]).ok_or_else(corrupt)?;
        pos += n1;
        let (wal_id, n2) = decode_varint64(&body[pos..]).ok_or_else(corrupt)?;
        pos += n2;
        let (last_seq, n3) = decode_varint64(&body[pos..]).ok_or_else(corrupt)?;
        pos += n3;

        let mut levels: [Vec<SstMeta>; NUM_LEVELS] = std::array::from_fn(|_| Vec::new());
        for level_vec in &mut levels {
            let (count, nc) = decode_varint32(&body[pos..]).ok_or_else(corrupt)?;
            pos += nc;
            for _ in 0..count {
                let (id, a) = decode_varint64(&body[pos..]).ok_or_else(corrupt)?;
                pos += a;
                let (level, b) = decode_varint32(&body[pos..]).ok_or_else(corrupt)?;
                pos += b;
                let (file_size, c) = decode_varint64(&body[pos..]).ok_or_else(corrupt)?;
                pos += c;
                let (entry_count, d) = decode_varint64(&body[pos..]).ok_or_else(corrupt)?;
                pos += d;
                let (sm_bytes, e) = decode_len_prefixed(&body[pos..]).ok_or_else(corrupt)?;
                pos += e;
                let (lg_bytes, f) = decode_len_prefixed(&body[pos..]).ok_or_else(corrupt)?;
                pos += f;

                let smallest_key = decode_internal_key(sm_bytes).ok_or_else(corrupt)?;
                let largest_key = decode_internal_key(lg_bytes).ok_or_else(corrupt)?;
                level_vec.push(SstMeta {
                    id,
                    level: level as usize,
                    file_size,
                    smallest_key,
                    largest_key,
                    entry_count,
                });
            }
        }

        if pos != body.len() {
            return Err(corrupt());
        }

        Ok(Self {
            next_sst_id,
            wal_id,
            last_seq,
            levels,
        })
    }
}

fn corrupt() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "corrupt MANIFEST payload")
}

pub struct ManifestStore {
    dir: PathBuf,
    path: PathBuf,
}

impl ManifestStore {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref().to_path_buf();
        let path = dir.join("MANIFEST");
        Self { dir, path }
    }

    pub fn load_or_init(&self) -> io::Result<VersionSet> {
        if !self.path.exists() {
            let initial = VersionSet::default();
            self.save_atomic(&initial)?;
            return Ok(initial);
        }
        let mut f = File::open(&self.path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        VersionSet::decode(&buf)
    }

    pub fn save_atomic(&self, vs: &VersionSet) -> io::Result<()> {
        let tmp_path = self.dir.join("MANIFEST.tmp");
        let encoded = vs.encode();
        {
            let mut f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp_path)?;
            f.write_all(&encoded)?;
            f.sync_data()?;
        }
        std::fs::rename(&tmp_path, &self.path)?;
        if let Ok(dir_file) = File::open(&self.dir) {
            let _ = dir_file.sync_all();
        }
        Ok(())
    }
}