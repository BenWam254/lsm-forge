use crate::coding::FastRng;
use crate::wal::ValueType;
use std::cmp::Ordering;

const MAX_HEIGHT: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalKey {
    pub user_key: Vec<u8>,
    pub seq: u64,
    pub kind: ValueType,
}

impl Ord for InternalKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // User keys ascending; sequence numbers descending (newest version first)
        self.user_key
            .cmp(&other.user_key)
            .then_with(|| other.seq.cmp(&self.seq))
            .then_with(|| (other.kind as u8).cmp(&(self.kind as u8)))
    }
}

impl PartialOrd for InternalKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct Node {
    key: InternalKey,
    value: Vec<u8>,
    next: Vec<Option<usize>>,
}

/// Arena-backed Skiplist MemTable supporting MVCC snapshot reads and deterministic iteration.
pub struct SkipListMemTable {
    nodes: Vec<Node>,
    head_next: [Option<usize>; MAX_HEIGHT],
    max_height: usize,
    approx_bytes: usize,
    rng: FastRng,
}

impl SkipListMemTable {
    pub fn new(seed: u64) -> Self {
        Self {
            nodes: Vec::new(),
            head_next: [None; MAX_HEIGHT],
            max_height: 1,
            approx_bytes: 0,
            rng: FastRng::new(seed),
        }
    }

    pub fn approximate_size(&self) -> usize {
        self.approx_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    fn random_height(&mut self) -> usize {
        let mut h = 1;
        while h < MAX_HEIGHT && (self.rng.next_u64() & 3) == 0 {
            h += 1;
        }
        h
    }

    /// Finds predecessor node indices at every level for `target`.
    fn find_less_than(&self, target: &InternalKey) -> [Option<usize>; MAX_HEIGHT] {
        let mut prev = [None; MAX_HEIGHT];
        let mut current: Option<usize> = None;

        for level in (0..self.max_height).rev() {
            loop {
                let next_idx = match current {
                    Some(idx) => self.nodes[idx].next[level],
                    None => self.head_next[level],
                };
                match next_idx {
                    Some(n_idx) if &self.nodes[n_idx].key < target => {
                        current = Some(n_idx);
                    }
                    _ => break,
                }
            }
            prev[level] = current;
        }
        prev
    }

    pub fn insert(&mut self, user_key: Vec<u8>, seq: u64, kind: ValueType, value: Vec<u8>) {
        let key = InternalKey {
            user_key,
            seq,
            kind,
        };
        let entry_bytes = key.user_key.len() + value.len() + 32;
        let height = self.random_height();
        if height > self.max_height {
            self.max_height = height;
        }

        let prev = self.find_less_than(&key);
        let new_idx = self.nodes.len();
        let mut next = vec![None; height];

        for level in 0..height {
            match prev[level] {
                Some(p_idx) => {
                    next[level] = self.nodes[p_idx].next[level];
                    self.nodes[p_idx].next[level] = Some(new_idx);
                }
                None => {
                    next[level] = self.head_next[level];
                    self.head_next[level] = Some(new_idx);
                }
            }
        }

        self.nodes.push(Node { key, value, next });
        self.approx_bytes += entry_bytes;
    }

    /// Point lookup at `snapshot_seq`.
    /// Returns:
    /// - `Some(Some(&[u8]))` if key exists at `<= snapshot_seq`
    /// - `Some(None)` if key was deleted at `<= snapshot_seq` (tombstone stops lower-level search)
    /// - `None` if no version exists at `<= snapshot_seq` in this MemTable
    pub fn get(&self, user_key: &[u8], snapshot_seq: u64) -> Option<Option<&[u8]>> {
        let seek_key = InternalKey {
            user_key: user_key.to_vec(),
            seq: snapshot_seq,
            kind: ValueType::Value,
        };
        let prev = self.find_less_than(&seek_key);
        let candidate_idx = match prev[0] {
            Some(p_idx) => self.nodes[p_idx].next[0],
            None => self.head_next[0],
        }?;

        let node = &self.nodes[candidate_idx];
        if node.key.user_key.as_slice() == user_key && node.key.seq <= snapshot_seq {
            match node.key.kind {
                ValueType::Value => Some(Some(node.value.as_slice())),
                ValueType::Deletion => Some(None),
            }
        } else {
            None
        }
    }

    /// Iterates all internal entries in sorted `(user_key ASC, seq DESC)` order for SSTable flushing.
    pub fn iter(&self) -> SkipListIter<'_> {
        SkipListIter {
            list: self,
            current: self.head_next[0],
        }
    }
}

pub struct SkipListIter<'a> {
    list: &'a SkipListMemTable,
    current: Option<usize>,
}

impl<'a> Iterator for SkipListIter<'a> {
    type Item = (&'a InternalKey, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.current?;
        let node = &self.list.nodes[idx];
        self.current = node.next[0];
        Some((&node.key, node.value.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mvcc_snapshot_isolation_and_sorted_iteration() {
        let mut mem = SkipListMemTable::new(42);
        mem.insert(b"user:1".to_vec(), 1, ValueType::Value, b"v1".to_vec());
        mem.insert(b"user:2".to_vec(), 2, ValueType::Value, b"v2".to_vec());
        mem.insert(b"user:1".to_vec(), 3, ValueType::Value, b"v3".to_vec());
        mem.insert(b"user:1".to_vec(), 4, ValueType::Deletion, Vec::new());

        // Snapshot @ seq 1 sees v1
        assert_eq!(mem.get(b"user:1", 1), Some(Some(b"v1".as_slice())));
        // Snapshot @ seq 3 sees v3
        assert_eq!(mem.get(b"user:1", 3), Some(Some(b"v3".as_slice())));
        // Snapshot @ seq 4 sees tombstone (Some(None))
        assert_eq!(mem.get(b"user:1", 4), Some(None));
        // Missing key returns None
        assert_eq!(mem.get(b"user:99", 4), None);

        // Iteration order must be user_key ASC, seq DESC
        let order: Vec<(&[u8], u64)> = mem
            .iter()
            .map(|(k, _)| (k.user_key.as_slice(), k.seq))
            .collect();
        assert_eq!(
            order,
            vec![
                (b"user:1".as_slice(), 4),
                (b"user:1".as_slice(), 3),
                (b"user:1".as_slice(), 1),
                (b"user:2".as_slice(), 2),
            ]
        );
    }
}