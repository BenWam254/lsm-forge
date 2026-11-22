use crate::cache::BlockCache;
use crate::manifest::{ManifestStore, VersionSet, NUM_LEVELS};
use crate::skiplist::{InternalKey, SkipListMemTable};
use crate::sstable::{SstBuilder, SstMeta, SstReader};
use crate::wal::{ValueType, Wal, WalEntry};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct EngineOptions {
    pub memtable_limit_bytes: usize,
    pub l0_compaction_trigger: usize,
    pub level1_max_bytes: u64,
    pub target_sst_bytes: u64,
    pub block_cache_bytes: usize,
    pub sync_writes: bool,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            memtable_limit_bytes: 64 * 1024,
            l0_compaction_trigger: 4,
            level1_max_bytes: 256 * 1024,
            target_sst_bytes: 64 * 1024,
            block_cache_bytes: 1024 * 1024,
            sync_writes: true,
        }
    }
}

pub struct LsmEngine {
    dir: PathBuf,
    opts: EngineOptions,
    manifest: ManifestStore,
    versions: VersionSet,
    wal: Wal,
    memtable: SkipListMemTable,
    readers: HashMap<u64, Arc<SstReader>>,
    cache: BlockCache,
    active_snapshots: BTreeMap<u64, usize>,
}

impl LsmEngine {
    pub fn open(dir: impl AsRef<Path>, opts: EngineOptions) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;

        // Clean up any leftover temp files from an interrupted flush/compaction
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().ends_with(".tmp") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }

        let manifest = ManifestStore::new(&dir);
        let mut versions = manifest.load_or_init()?;

        // Open all live SSTables referenced by MANIFEST
        let mut readers = HashMap::new();
        let mut live_sst_ids = HashSet::new();
        for level in &versions.levels {
            for meta in level {
                let sst_path = sst_file_path(&dir, meta.id);
                let reader = SstReader::open(meta.clone(), &sst_path)?;
                readers.insert(meta.id, Arc::new(reader));
                live_sst_ids.insert(meta.id);
            }
        }

        // Garbage-collect orphan SSTables not referenced by MANIFEST
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name();
                let s = fname.to_string_lossy();
                if let Some(id_str) = s.strip_prefix("sst_").and_then(|r| r.strip_suffix(".sst"))
                    && let Ok(id) = id_str.parse::<u64>()
                    && !live_sst_ids.contains(&id)
                {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }

        // Open active WAL and replay recovered records into MemTable
        let wal_path = wal_file_path(&dir, versions.wal_id);
        let (wal, recovered) = Wal::open(&wal_path)?;
        let mut memtable = SkipListMemTable::new(0x517C_C1B7_2722_0A95);
        for rec in recovered {
            if rec.seq > versions.last_seq {
                versions.last_seq = rec.seq;
            }
            memtable.insert(rec.key, rec.seq, rec.kind, rec.value);
        }

        let cache = BlockCache::new(opts.block_cache_bytes);

        Ok(Self {
            dir,
            opts,
            manifest,
            versions,
            wal,
            memtable,
            readers,
            cache,
            active_snapshots: BTreeMap::new(),
        })
    }

    pub fn latest_seq(&self) -> u64 {
        self.versions.last_seq
    }

    /// Acquires an immutable MVCC snapshot sequence number.
    pub fn acquire_snapshot(&mut self) -> u64 {
        let seq = self.versions.last_seq;
        *self.active_snapshots.entry(seq).or_insert(0) += 1;
        seq
    }

    /// Releases a previously acquired MVCC snapshot sequence number.
    pub fn release_snapshot(&mut self, seq: u64) {
        if let Some(count) = self.active_snapshots.get_mut(&seq) {
            if *count <= 1 {
                self.active_snapshots.remove(&seq);
            } else {
                *count -= 1;
            }
        }
    }

    fn oldest_visible_seq(&self) -> u64 {
        self.active_snapshots
            .keys()
            .next()
            .copied()
            .unwrap_or(self.versions.last_seq)
    }

    pub fn put(&mut self, key: &[u8], value: &[u8]) -> io::Result<u64> {
        self.write_internal(key, ValueType::Value, value)
    }

    pub fn delete(&mut self, key: &[u8]) -> io::Result<u64> {
        self.write_internal(key, ValueType::Deletion, &[])
    }

    fn write_internal(&mut self, key: &[u8], kind: ValueType, value: &[u8]) -> io::Result<u64> {
        let seq = self.versions.last_seq + 1;
        let entry = WalEntry {
            seq,
            kind,
            key: key.to_vec(),
            value: value.to_vec(),
        };
        self.wal.append(&entry, self.opts.sync_writes)?;
        self.versions.last_seq = seq;
        self.memtable.insert(key.to_vec(), seq, kind, value.to_vec());

        if self.memtable.approximate_size() >= self.opts.memtable_limit_bytes {
            self.flush_memtable()?;
        }
        Ok(seq)
    }

    pub fn get(&self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        self.get_at(key, self.versions.last_seq)
    }

    /// Point lookup at a specific MVCC `snapshot_seq`.
    pub fn get_at(&self, key: &[u8], snapshot_seq: u64) -> io::Result<Option<Vec<u8>>> {
        // 1. Check active MemTable
        if let Some(res) = self.memtable.get(key, snapshot_seq) {
            return Ok(res.map(<[u8]>::to_vec));
        }

        // 2. Check Level 0 SSTables from newest (highest ID) to oldest
        let mut l0_sorted = self.versions.levels[0].clone();
        l0_sorted.sort_by(|a, b| b.id.cmp(&a.id));
        for meta in &l0_sorted {
            if let Some(reader) = self.readers.get(&meta.id)
                && let Some(res) = reader.get(key, snapshot_seq, Some(&self.cache))?
            {
                return Ok(res);
            }
        }

        // 3. Check Levels 1..NUM_LEVELS (disjoint key ranges -> binary search SSTable)
        for level_tables in &self.versions.levels[1..] {
            let idx = level_tables
                .partition_point(|m| m.largest_key.user_key.as_slice() < key);
            if let Some(meta) = level_tables.get(idx)
                && meta.smallest_key.user_key.as_slice() <= key
                && let Some(reader) = self.readers.get(&meta.id)
                && let Some(res) = reader.get(key, snapshot_seq, Some(&self.cache))?
            {
                return Ok(res);
            }
        }

        Ok(None)
    }

    pub fn flush_memtable(&mut self) -> io::Result<()> {
        if self.memtable.is_empty() {
            return Ok(());
        }

        let sst_id = self.versions.alloc_sst_id();
        let tmp_path = self.dir.join(format!("sst_{sst_id:06}.sst.tmp"));
        let final_path = sst_file_path(&self.dir, sst_id);

        let mut builder = SstBuilder::create(sst_id, 0, &tmp_path)?;
        for (k, v) in self.memtable.iter() {
            builder.add(k, v)?;
        }
        let meta = builder.finish()?;
        std::fs::rename(&tmp_path, &final_path)?;

        let reader = Arc::new(SstReader::open(meta.clone(), &final_path)?);
        self.readers.insert(sst_id, reader);
        self.versions.levels[0].push(meta);

        // Rotate WAL atomically with MANIFEST update
        let old_wal_path = self.wal.path().to_path_buf();
        let next_wal_id = self.versions.wal_id + 1;
        let next_wal_path = wal_file_path(&self.dir, next_wal_id);
        let (new_wal, _) = Wal::open(&next_wal_path)?;
        new_wal.sync()?;

        self.versions.wal_id = next_wal_id;
        self.manifest.save_atomic(&self.versions)?;

        self.wal = new_wal;
        self.memtable = SkipListMemTable::new(sst_id.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let _ = std::fs::remove_file(old_wal_path);

        self.maybe_compact()?;
        Ok(())
    }

    pub fn maybe_compact(&mut self) -> io::Result<()> {
        while self.versions.levels[0].len() >= self.opts.l0_compaction_trigger {
            self.compact_level(0)?;
        }

        for level in 1..(NUM_LEVELS - 1) {
            let max_bytes = self.opts.level1_max_bytes * 10u64.pow((level - 1) as u32);
            loop {
                let level_bytes: u64 = self.versions.levels[level].iter().map(|m| m.file_size).sum();
                if level_bytes <= max_bytes {
                    break;
                }
                self.compact_level(level)?;
            }
        }
        Ok(())
    }

    pub fn compact_level(&mut self, level: usize) -> io::Result<()> {
        if level + 1 >= NUM_LEVELS || self.versions.levels[level].is_empty() {
            return Ok(());
        }

        // Select input tables from `level`
        let input_tables: Vec<SstMeta> = if level == 0 {
            // L0 tables can overlap each other; pull all L0 tables
            self.versions.levels[0].clone()
        } else {
            // Pick largest SSTable in `level`
            let largest = self.versions.levels[level]
                .iter()
                .max_by_key(|m| m.file_size)
                .unwrap()
                .clone();
            vec![largest]
        };

        let min_user_key = input_tables
            .iter()
            .map(|m| m.smallest_key.user_key.clone())
            .min()
            .unwrap();
        let max_user_key = input_tables
            .iter()
            .map(|m| m.largest_key.user_key.clone())
            .max()
            .unwrap();

        // Find all overlapping SSTables in `level + 1`
        let target_level = level + 1;
        let overlapping_next: Vec<SstMeta> = self.versions.levels[target_level]
            .iter()
            .filter(|m| {
                m.largest_key.user_key >= min_user_key && m.smallest_key.user_key <= max_user_key
            })
            .cloned()
            .collect();

        // Check if any deeper level holds keys in [min_user_key, max_user_key] (for tombstone GC)
        let has_deeper_data = self.versions.levels[(target_level + 1)..]
            .iter()
            .flatten()
            .any(|m| {
                m.largest_key.user_key >= min_user_key && m.smallest_key.user_key <= max_user_key
            });

        // Merge-sort all entries from input_tables + overlapping_next
        let mut merged: Vec<(InternalKey, Vec<u8>)> = Vec::new();
        for meta in input_tables.iter().chain(overlapping_next.iter()) {
            let reader = self.readers.get(&meta.id).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "missing SSTReader during compaction")
            })?;
            merged.extend(reader.iter_all()?);
        }
        merged.sort_by(|(a, _), (b, _)| a.cmp(b));

        // Garbage-collect obsolete versions while preserving MVCC snapshot visibility
        let watermark = self.oldest_visible_seq();
        let mut compacted_entries: Vec<(InternalKey, Vec<u8>)> = Vec::with_capacity(merged.len());
        let mut current_user_key: Option<Vec<u8>> = None;
        let mut has_version_at_or_below_watermark = false;

        for (ik, val) in merged {
            if current_user_key.as_ref() != Some(&ik.user_key) {
                current_user_key = Some(ik.user_key.clone());
                has_version_at_or_below_watermark = false;
            }

            if ik.seq > watermark {
                // Newer than oldest snapshot: must keep
                compacted_entries.push((ik, val));
            } else if !has_version_at_or_below_watermark {
                // First version visible to `watermark`
                has_version_at_or_below_watermark = true;
                if ik.kind == ValueType::Deletion && !has_deeper_data {
                    // Safe to drop tombstone completely
                    continue;
                }
                compacted_entries.push((ik, val));
            } else {
                // Shadowed by a newer version at <= watermark: drop!
            }
        }

        // Write output SSTables at `target_level`
        let mut new_metas = Vec::new();
        let mut new_readers = Vec::new();
        let mut idx = 0usize;

        while idx < compacted_entries.len() {
            let sst_id = self.versions.alloc_sst_id();
            let tmp_path = self.dir.join(format!("sst_{sst_id:06}.sst.tmp"));
            let final_path = sst_file_path(&self.dir, sst_id);

            let mut builder = SstBuilder::create(sst_id, target_level, &tmp_path)?;
            let mut approx_written = 0u64;

            while idx < compacted_entries.len() {
                let (ref ik, ref val) = compacted_entries[idx];
                // Never split versions of the same user_key across SSTable boundaries
                let same_user_key_as_prev = approx_written > 0
                    && idx > 0
                    && compacted_entries[idx - 1].0.user_key == ik.user_key;

                if approx_written >= self.opts.target_sst_bytes && !same_user_key_as_prev {
                    break;
                }
                builder.add(ik, val)?;
                approx_written += (ik.user_key.len() + val.len() + 16) as u64;
                idx += 1;
            }

            let meta = builder.finish()?;
            std::fs::rename(&tmp_path, &final_path)?;
            let reader = Arc::new(SstReader::open(meta.clone(), &final_path)?);
            new_metas.push(meta);
            new_readers.push((sst_id, reader));
        }

        // Atomically update VersionSet and persist MANIFEST
        let retired_ids: HashSet<u64> = input_tables
            .iter()
            .chain(overlapping_next.iter())
            .map(|m| m.id)
            .collect();

        for (id, reader) in new_readers {
            self.readers.insert(id, reader);
        }

        self.versions.levels[level].retain(|m| !retired_ids.contains(&m.id));
        self.versions.levels[target_level].retain(|m| !retired_ids.contains(&m.id));
        self.versions.levels[target_level].extend(new_metas);
        self.versions.levels[target_level]
            .sort_by(|a, b| a.smallest_key.user_key.cmp(&b.smallest_key.user_key));

        self.manifest.save_atomic(&self.versions)?;

        // Delete retired SSTable files from disk
        for old_id in retired_ids {
            self.readers.remove(&old_id);
            let _ = std::fs::remove_file(sst_file_path(&self.dir, old_id));
        }

        Ok(())
    }

    pub fn level_counts(&self) -> [usize; NUM_LEVELS] {
        std::array::from_fn(|i| self.versions.levels[i].len())
    }
}

fn wal_file_path(dir: &Path, wal_id: u64) -> PathBuf {
    dir.join(format!("wal_{wal_id:06}.log"))
}

fn sst_file_path(dir: &Path, sst_id: u64) -> PathBuf {
    dir.join(format!("sst_{sst_id:06}.sst"))
}