#[cfg(test)]
mod tests {
    use crate::coding::FastRng;
    use crate::engine::{EngineOptions, LsmEngine};
    use std::collections::BTreeMap;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fresh_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("lsm_forge_chaos_{tag}_{nanos}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn randomized_workload_with_compaction_and_oracle() {
        let dir = fresh_dir("oracle");
        let opts = EngineOptions {
            memtable_limit_bytes: 2 * 1024,
            l0_compaction_trigger: 3,
            level1_max_bytes: 8 * 1024,
            target_sst_bytes: 4 * 1024,
            block_cache_bytes: 32 * 1024,
            sync_writes: false,
        };

        let mut engine = LsmEngine::open(&dir, opts.clone()).unwrap();
        let mut oracle: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        let mut snapshots: Vec<(u64, BTreeMap<Vec<u8>, Option<Vec<u8>>>)> = Vec::new();
        let mut rng = FastRng::new(2026_11_22);

        for step in 0..1_500u32 {
            let key_idx = (rng.next_u64() % 60) as u32;
            let key = format!("key:{key_idx:03}").into_bytes();

            match rng.next_u64() % 10 {
                0..=5 => {
                    let val = format!("val-{step}-{}", rng.next_u64() % 9999).into_bytes();
                    engine.put(&key, &val).unwrap();
                    oracle.insert(key, Some(val));
                }
                6..=7 => {
                    engine.delete(&key).unwrap();
                    oracle.insert(key, None);
                }
                8 => {
                    let snap_seq = engine.acquire_snapshot();
                    snapshots.push((snap_seq, oracle.clone()));
                }
                _ => {
                    if step % 150 == 0 {
                        engine.flush_memtable().unwrap();
                    }
                }
            }

            if step % 100 == 0 {
                for (k, expected) in &oracle {
                    let actual = engine.get(k).unwrap();
                    assert_eq!(&actual, expected, "mismatch on key {:?} at step {step}", k);
                }
            }
        }

        // Verify all historical MVCC snapshots survived multi-level compaction intact
        for (snap_seq, snap_oracle) in &snapshots {
            for k_idx in 0..60u32 {
                let key = format!("key:{k_idx:03}").into_bytes();
                let expected = snap_oracle.get(&key).cloned().flatten();
                let actual = engine.get_at(&key, *snap_seq).unwrap();
                assert_eq!(
                    actual, expected,
                    "MVCC snapshot @{snap_seq} violated on key {:?}",
                    key
                );
            }
            engine.release_snapshot(*snap_seq);
        }

        // Reopen from disk and verify full state persistence
        drop(engine);
        let reopened = LsmEngine::open(&dir, opts).unwrap();
        for (k, expected) in &oracle {
            assert_eq!(&reopened.get(k).unwrap(), expected);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn crash_recovery_after_torn_wal_and_orphan_sstables() {
        let dir = fresh_dir("crash");
        let opts = EngineOptions {
            memtable_limit_bytes: 1024,
            l0_compaction_trigger: 3,
            sync_writes: true,
            ..EngineOptions::default()
        };

        let mut expected = BTreeMap::new();
        {
            let mut engine = LsmEngine::open(&dir, opts.clone()).unwrap();
            for i in 0..120u32 {
                let k = format!("acct:{i:04}").into_bytes();
                let v = format!("bal:{i}").into_bytes();
                engine.put(&k, &v).unwrap();
                expected.insert(k, v);
            }
        }

        // Inject crash artifacts:
        // 1. Orphan SSTable and interrupted .tmp file
        std::fs::write(dir.join("sst_009999.sst"), b"orphan-uncommitted-table").unwrap();
        std::fs::write(dir.join("MANIFEST.tmp"), b"half-written-manifest").unwrap();

        // 2. Append 11 torn bytes to the active WAL file
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("wal_") {
                let mut f = OpenOptions::new().append(true).open(entry.path()).unwrap();
                f.write_all(&[0xFF; 11]).unwrap();
            }
        }

        // Reopen after simulated power loss
        let engine = LsmEngine::open(&dir, opts).unwrap();
        assert!(!dir.join("sst_009999.sst").exists());
        assert!(!dir.join("MANIFEST.tmp").exists());

        for (k, v) in &expected {
            assert_eq!(engine.get(k).unwrap(), Some(v.clone()));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_pins_historical_versions_across_compaction() {
        let dir = fresh_dir("mvcc_pin");
        let opts = EngineOptions {
            memtable_limit_bytes: 256,
            l0_compaction_trigger: 2,
            ..EngineOptions::default()
        };

        let mut engine = LsmEngine::open(&dir, opts).unwrap();
        engine.put(b"item", b"initial_state").unwrap();
        let snap = engine.acquire_snapshot();

        // Overwrite and delete across multiple flushes and compactions
        engine.put(b"item", b"updated_state").unwrap();
        engine.flush_memtable().unwrap();
        engine.delete(b"item").unwrap();
        engine.flush_memtable().unwrap();
        engine.compact_level(0).unwrap();

        // Latest view sees deletion; pinned snapshot still sees initial_state
        assert_eq!(engine.get(b"item").unwrap(), None);
        assert_eq!(
            engine.get_at(b"item", snap).unwrap(),
            Some(b"initial_state".to_vec())
        );

        engine.release_snapshot(snap);
        let _ = std::fs::remove_dir_all(&dir);
    }
}