use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

const NUM_SHARDS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockCacheKey {
    pub sst_id: u64,
    pub offset: u64,
}

struct CacheShard {
    capacity_bytes: usize,
    used_bytes: usize,
    entries: HashMap<BlockCacheKey, Arc<[u8]>>,
    lru_order: VecDeque<BlockCacheKey>,
}

impl CacheShard {
    fn new(capacity_bytes: usize) -> Self {
        Self {
            capacity_bytes,
            used_bytes: 0,
            entries: HashMap::new(),
            lru_order: VecDeque::new(),
        }
    }

    fn get(&mut self, key: &BlockCacheKey) -> Option<Arc<[u8]>> {
        let val = self.entries.get(key)?.clone();
        self.touch(key);
        Some(val)
    }

    fn insert(&mut self, key: BlockCacheKey, data: Arc<[u8]>) {
        if self.capacity_bytes == 0 {
            return;
        }
        let size = data.len();
        if size > self.capacity_bytes {
            return;
        }
        if let Some(old) = self.entries.remove(&key) {
            self.used_bytes -= old.len();
            self.lru_order.retain(|k| k != &key);
        }

        while self.used_bytes + size > self.capacity_bytes {
            if let Some(evicted_key) = self.lru_order.pop_front() {
                if let Some(evicted_val) = self.entries.remove(&evicted_key) {
                    self.used_bytes -= evicted_val.len();
                }
            } else {
                break;
            }
        }

        self.used_bytes += size;
        self.entries.insert(key, data);
        self.lru_order.push_back(key);
    }

    fn touch(&mut self, key: &BlockCacheKey) {
        if let Some(pos) = self.lru_order.iter().position(|k| k == key) {
            self.lru_order.remove(pos);
            self.lru_order.push_back(*key);
        }
    }
}

pub struct BlockCache {
    shards: Vec<Mutex<CacheShard>>,
}

impl BlockCache {
    pub fn new(total_capacity_bytes: usize) -> Self {
        let per_shard = total_capacity_bytes / NUM_SHARDS;
        let shards = (0..NUM_SHARDS)
            .map(|_| Mutex::new(CacheShard::new(per_shard)))
            .collect();
        Self { shards }
    }

    fn shard_for(&self, key: &BlockCacheKey) -> &Mutex<CacheShard> {
        let hash = key.sst_id.wrapping_mul(0x9E37_79B9) ^ key.offset;
        &self.shards[(hash as usize) % NUM_SHARDS]
    }

    pub fn get(&self, key: BlockCacheKey) -> Option<Arc<[u8]>> {
        self.shard_for(&key).lock().unwrap().get(&key)
    }

    pub fn insert(&self, key: BlockCacheKey, data: Arc<[u8]>) {
        self.shard_for(&key).lock().unwrap().insert(key, data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_least_recently_used_blocks() {
        // 16 shards * 64 bytes = 1024 bytes total
        let cache = BlockCache::new(16 * 64);
        // Keys on the same shard (offset multiples of 16)
        let k1 = BlockCacheKey { sst_id: 1, offset: 0 };
        let k2 = BlockCacheKey { sst_id: 1, offset: 16 };
        let k3 = BlockCacheKey { sst_id: 1, offset: 32 };

        cache.insert(k1, Arc::from(vec![1u8; 32]));
        cache.insert(k2, Arc::from(vec![2u8; 32]));
        // Touch k1 so k2 becomes LRU
        assert!(cache.get(k1).is_some());
        // Inserting k3 (32B) must evict k2
        cache.insert(k3, Arc::from(vec![3u8; 32]));

        assert!(cache.get(k1).is_some());
        assert!(cache.get(k2).is_none());
        assert!(cache.get(k3).is_some());
    }
}