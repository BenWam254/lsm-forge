# `lsm-forge`

A dependency-free, crash-consistent **Log-Structured Merge-Tree (LSM-Tree) storage engine** implemented from scratch in pure Rust (`std` only, zero external crates).

`lsm-forge` implements the full storage stack underneath modern distributed key-value engines: an append-only Write-Ahead Log with torn-tail recovery, an MVCC multi-version Skiplist MemTable, prefix-compressed 4KB SSTable data blocks with restart points, Kirsch-Mitzenmacher double-hashed Bloom filters, a shared LRU Block Cache, atomic `MANIFEST` version tracking, leveled compaction (`L0`-`L4`), and a randomized oracle + crash-injection verification suite.

---

## Table of Contents

- [Architectural Overview](#architectural-overview)
- [Module Map](#module-map)
- [On-Disk Formats & Binary Specifications](#on-disk-formats--binary-specifications)
  - [Internal Key Ordering & Binary Encoding](#internal-key-ordering--binary-encoding)
  - [Write-Ahead Log (WAL) Record Layout](#write-ahead-log-wal-record-layout)
  - [SSTable File & Prefix-Compressed Block Layout](#sstable-file--prefix-compressed-block-layout)
  - [Atomic MANIFEST Format](#atomic-manifest-format)
- [Read Path, Compaction & MVCC Garbage Collection](#read-path-compaction--mvcc-garbage-collection)
  - [Multi-Level Lookup Pipeline](#multi-level-lookup-pipeline)
  - [Leveled Compaction & Snapshot Watermark](#leveled-compaction--snapshot-watermark)
- [Verification & Crash-Injection Suite](#verification--crash-injection-suite)
- [Quickstart](#quickstart)

---

## Architectural Overview 

```text
Write (put / delete)
   │
   ├──► 1. Append CRC32C-framed record to WAL (wal_000001.log) + sync_data()
   └──► 2. Insert (UserKey, SeqNum, ValueType) into Skiplist MemTable
               │ (when MemTable >= memtable_limit_bytes)
               ▼
        Flush sorted MemTable ──► Level 0 SSTable (sst_000001.sst)
                                       │
        ┌──────────────────────────────┴──────────────────────────────┐
        ▼                                                             ▼
  Atomic MANIFEST Update                                Leveled Compaction (L0 -> L1 -> ... -> L4)
  (MANIFEST.tmp -> sync -> rename)                      • Merge-sort overlapping SSTables
  + Rotate WAL & delete old log                         • Deduplicate versions below snapshot watermark
                                                        • Drop tombstones at bottommost level
Read (get / get_at @ snapshot_seq)                      • Rebuild Bloom filters & 4KB data blocks
   │
   └──► 1. Active MemTable ─► 2. L0 SSTables (newest first) ─► 3. L1..L4 SSTables (disjoint binary search)
   ```

---

## Core Guarantees

- **Zero External Dependencies:** Built purely on Rust `std` (`std::fs`, `std::io`, `std::sync`, `std::collections`). No crc, byteorder, rand, or parking_lot crates.

- **Castagnoli CRC32C End-to-End Integrity:** Every WAL record, SSTable data block, Bloom filter block, index block, SSTable footer, and `MANIFEST` file is guarded by a compile-time generated IEEE/Castagnoli CRC32C (0x82F63B78) checksum.

- **MVCC Snapshot Isolation:** Readers acquire an immutable `snapshot_seq` (`acquire_snapshot()`), isolating point reads from concurrent overwrites, deletions, MemTable flushes, and multi-level compactions until `release_snapshot()` advances the garbage-collection watermark.

- **Crash Consistency at Every Syscall Boundary:** Torn tail bytes in the WAL are automatically truncated to the last valid frame boundary on recovery; interrupted `.tmp` files and orphan `.sst` tables not committed in `MANIFEST` are purged on startup.


## Module Map


| File | Responsibility | Key Primitives |
| :--- | :--- | :--- |
| `src/coding.rs` | Binary Codec & PRNG | Castagnoli `crc32c()`, LEB128 `encode_varint32/64`, length-prefixed slices, `FastRng` (SplitMix64 + Xoshiro256) |
| `src/wal.rs` | Write-Ahead Log | `Wal`, `WalEntry`, `ValueType` (`Value`, `Deletion`), torn-tail frame truncation |
| `src/skiplist.rs` | MemTable | `SkipListMemTable`, `InternalKey`, arena-backed probabilistic skiplist, `get(key, snapshot_seq)` |
| `src/bloom.rs` | Probabilistic Filter | `BloomFilter`, Kirsch-Mitzenmacher double hashing ($g_i(x) = h_1 + i \cdot h_2 \pmod m$) |
| `src/cache.rs` | Block Cache | `BlockCache` (16-shard `Mutex<CacheShard>`), capacity-bounded LRU eviction |
| `src/sstable.rs` | Immutable Disk Tables | `SstBuilder`, `SstReader`, `DataBlockBuilder`, prefix compression, restart points, footer verification |
| `src/manifest.rs` | Version Metadata | `VersionSet`, `ManifestStore`, `save_atomic()` (write -> sync_data -> rename -> dir sync) |
| `src/engine.rs` | Storage Engine | `LsmEngine`, `EngineOptions`, WAL rotation, L0->L4 leveled compaction, MVCC watermark GC |
| `src/chaos.rs` | Verification Suite | 1,500-step randomized `BTreeMap` oracle, MVCC snapshot pinning, torn-WAL + orphan-SST crash injection |

---

# On-Disk Formats & Binary Specifications

## Internal Key Ordering & Binary Encoding
- Every mutation is tagged with a monotonically increasing 64-bit sequence number (`seq`) and operation type (`Value = 1`, `Deletion = 0`).

- In memory (`InternalKey::cmp`), entries sort by `user_key ASC, seq DESC, kind DESC`. To allow binary search over raw SSTable bytes without decoding headers, `encode_internal_key` bitwise-inverts both `seq` and `kind`:

```plaintext
[ user_key (N bytes) ] [ !seq (8 bytes Big-Endian) ] [ !kind (1 byte) ]
```

- Because `!seq` reverses unsigned big-endian ordering, higher sequence numbers sort first in raw lexicographical byte order.
- Because `!kind` maps `Value (1) -> 0xFE and Deletion (0) -> 0xFF`, `seek_encoded(user_key, snapshot_req, Value)` lands directly on the newest entry at or before `snapshot_seq` - whether that entry is a live `Value` or `Deletion` tombstone.

---

## Write-Ahead Log (WAL) Record Layout

```plaintext
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    CRC32C Checksum (u32 LE)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Payload Length (u32 LE)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Sequence Number (u64 LE)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    OpKind     |     Key (varint len + bytes) ...              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Value (varint len + bytes, omitted if OpKind == 0) ...    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Recovery (`Wal::open`): Reads automatically from byte `0`. Any truncated header, incomplete payload, or CRC32C mismatch stops recovery and truncates the file (`file.set_len(valid_offset)`) followed by `sync_data()`.

---

## SSTable File & Prefix-Compressed Block Layout

```plaintext
┌──────────────────────────────────────────────────────────────┐
│ Data Block 0 (~4 KB, prefix-compressed + restart array)      │ + [CRC32C (4B)]
├──────────────────────────────────────────────────────────────┤
│ Data Block 1 (~4 KB, prefix-compressed + restart array)      │ + [CRC32C (4B)]
├──────────────────────────────────────────────────────────────┤
│ ...                                                          │
├──────────────────────────────────────────────────────────────┤
│ Filter Block (Kirsch-Mitzenmacher Bloom bitset + k)          │ + [CRC32C (4B)]
├──────────────────────────────────────────────────────────────┤
│ Index Block (separator_key -> BlockHandle { offset, size })  │ + [CRC32C (4B)]
├──────────────────────────────────────────────────────────────┤
│ Footer (44 Bytes):                                           │
│   index_handle (16B) | filter_handle (16B) | crc32c (4B)     │
│   magic: "LSMFRG01" (8B)                                     │
└──────────────────────────────────────────────────────────────┘
```

#### Within each **Data Block:**

- Adjacent keys share common prefix bytes (`shared_prefix_len`, `unshared_key_len`, `val_len` as LEB128 variants).
- Every 16 entries, prefix compression resets (`shared_prefix_len = 0`) and records the byte offset in a trailing `restarts: [u32]` array, enabling intra-block binary search without decompressing from byte `0`.

### Atomic MANIFEST Format 

```plaintext
[Magic: "LSMMNFT1" (8B)] [CRC32C (u32 LE)] [next_sst_id (varint)] [wal_id (varint)] [last_seq (varint)] [Levels 0..4 SSTMeta...]
```
Updates follow POSIX crash-safe replacement: 
```
write("MANIFEST.tmp") -> sync_data() -> rename("MANIFEST.tmp", "MANIFEST") -> dir.sync_all()
```
---

## Read Path, Compaction & MVCC Garbage Collection

### Multi-Level Lookup Pipeline
`LsmEngine::get_at(user_key, snapshot_seq)` resolves a point query in strict recency order:

1. **Active MemTable:** $O(\log N)$ skiplist seek to `(user_key, snapshot_seq)`. If a Deletion tombstone is found, immediately returns `Ok(None)` without touching disk.

2. **Level 0 SSTables:** Scanned from newest (`highest id`) to oldest, checking key bounds -> Bloom filter -> Block Cache -> verified Data Block.

3. **Levels 1..4 SSTables:** Because compaction maintains disjoint, sorted key ranges within each level $L_i$ ($i \ge 1$), `partition_point` binary-searches directly to the single candidate SSTable covering `user_key`.

### Leveled Compaction & Snapshot Watermark
- **Triggering:** Compaction fires automatically when L0 reaches `l0_compaction_trigger` files or when any level $L_i$ ($i \ge 1$) exceeds `level1_max_bytes * 10^(i-1)`.

- **Watermark Retention:** Before merge-sorting overlapping SSTables, the compactor computes `watermark = active_snapshots.keys().next().unwrap_or(last_seq)`.

    - All versions with `seq > watermark` are preserved intact.

    - For versions with `seq <= watermark`, only the single newest version visible at `watermark` is retained; older shadowed versions are reclaimed.

    - If that newest version is a `Deletion` tombstone and no deeper level ($> \text{target\_level}$) has key-range overlap, the tombstone itself is purged.

---

## Verification & Crash-Injection Suite
- `cargo-test` executes 10 unit, storage-integrity, and randomized chaos tests:

- `coding::tests`: LEB128 varint boundary roundtrips (`0` through `u64::MAX`) and single-bit-flip CRC32C detection.

- `wal::tests::recovers_records_and_truncates_torn_tail`: Appends valid `Put`/`Delete` frames, injects partial/corrupt tail bytes simulating power loss, and verifies truncation back to the exact valid byte boundary.

- `skiplist::tests::mvcc_snapshot_isolation_and_sorted_iteration`: Verifies point-in-time visibility across historical sequence numbers and (`user_key ASC`, `seq DESC`) iteration order.

- `bloom::tests::zero_false_negatives_and_low_false_positives`: Verifies 0% false negatives and `< 1%` false positives at 10 bits/key.

- `cache::tests::evicts_least_recently_used_blocks`: Verifies per-shard LRU touch promotion and capacity eviction.

- `sstable::tests::builds_queries_and_verifies_multi_block_sstable`: Writes 400 keys across multiple 4KB prefix-compressed blocks and verifies hits, tombstones, snapshot filtering, and Bloom filter misses.

- `chaos::tests::randomized_workload_with_compaction_and_oracle`: Executes 1,500 randomized `put`, `delete`, `flush_memtable`, and `acquire_snapshot` operations over a hot keyspace—forcing multi-level `L0 -> L1 -> L2` compactions—and asserts every live read,historical MVCC snapshot, and post-reopen read against a reference `BTreeMap` oracle.

- `chaos::tests::crash_recovery_after_torn_wal_and_orphan_sstables`: Injects torn tail bytes into the active WAL alongside uncommitted `MANIFEST.tmp` and orphan `sst_009999.sst` files, reopens `LsmEngine`, and verifies clean purging and 100% recovery of acknowledged keys.

- `chaos::tests::snapshot_pins_historical_versions_across_compaction`: Acquires a snapshot, overwrites and deletes the key across multiple flushes and compactions, and proves the snapshot preserves the original value while latest reads return `None`.

---

## Quickstart

1. Run the full verification suite:

```bash
cargo test
```

2. Embed `LsmEngine` in Rust:

```rust
use lsm_forge::engine::{EngineOptions, LsmEngine};

fn main() -> std::io::Result<()> {
    let mut db = LsmEngine::open("./data", EngineOptions::default())?;

    db.put(b"account:1001", b"500")?;
    let snap = db.acquire_snapshot();

    db.put(b"account:1001", b"750")?;
    assert_eq!(db.get(b"account:1001")?, Some(b"750".to_vec()));
    assert_eq!(db.get_at(b"account:1001", snap)?, Some(b"500".to_vec()));

    db.release_snapshot(snap);
    db.delete(b"account:1001")?;
    assert_eq!(db.get(b"account:1001")?, None);

    Ok(())
}
```

