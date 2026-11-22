pub struct BloomFilter {
    bits: Vec<u8>,
    k: u8,
}

impl BloomFilter {
    /// Builds a Bloom filter sized at `bits_per_key` for the given user keys.
    pub fn build(keys: &[&[u8]], bits_per_key: usize) -> Self {
        let bits_per_key = bits_per_key.max(4);
        let mut num_bits = keys.len() * bits_per_key;
        if num_bits < 64 {
            num_bits = 64;
        }
        let num_bytes = num_bits.div_ceil(8);
        let total_bits = num_bytes * 8;

        // Optimal k ≈ ln(2) * bits_per_key ≈ 0.69 * bits_per_key
        let k = ((bits_per_key as f64 * 0.69) as u8).clamp(1, 30);
        let mut bits = vec![0u8; num_bytes];

        for key in keys {
            let (mut h1, h2) = hash_pair(key);
            for _ in 0..k {
                let bit_pos = (h1 as usize) % total_bits;
                bits[bit_pos / 8] |= 1 << (bit_pos % 8);
                h1 = h1.wrapping_add(h2);
            }
        }

        Self { bits, k }
    }

    pub fn may_contain(&self, user_key: &[u8]) -> bool {
        if self.bits.is_empty() {
            return true;
        }
        let total_bits = self.bits.len() * 8;
        let (mut h1, h2) = hash_pair(user_key);
        for _ in 0..self.k {
            let bit_pos = (h1 as usize) % total_bits;
            if (self.bits[bit_pos / 8] & (1 << (bit_pos % 8))) == 0 {
                return false;
            }
            h1 = h1.wrapping_add(h2);
        }
        true
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.bits.len() + 1);
        out.extend_from_slice(&self.bits);
        out.push(self.k);
        out
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        let (&k, bits) = raw.split_last()?;
        if bits.is_empty() || k == 0 || k > 30 {
            return None;
        }
        Some(Self {
            bits: bits.to_vec(),
            k,
        })
    }
}

fn hash_pair(data: &[u8]) -> (u32, u32) {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x1000_0000_01B3);
    }
    // Finalize with SplitMix64 avalanche
    h ^= h >> 30;
    h = h.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    h ^= h >> 27;
    h = h.wrapping_mul(0x94D0_49BB_1331_11EB);
    h ^= h >> 31;

    let h1 = h as u32;
    let h2 = ((h >> 32) as u32) | 1; // Ensure odd stride for coprime coverage
    (h1, h2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_false_negatives_and_low_false_positives() {
        let keys: Vec<Vec<u8>> = (0..1_000u32)
            .map(|i| format!("account:{i:06}").into_bytes())
            .collect();
        let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
        let filter = BloomFilter::build(&refs, 10);

        let decoded = BloomFilter::decode(&filter.encode()).unwrap();

        for key in &refs {
            assert!(decoded.may_contain(key));
        }

        let mut false_positives = 0;
        for i in 1_000..2_000u32 {
            let probe = format!("account:{i:06}");
            if decoded.may_contain(probe.as_bytes()) {
                false_positives += 1;
            }
        }
        // At 10 bits/key, theoretical FPR is ~0.82% (< 3% generous bound)
        assert!(false_positives < 30, "unexpectedly high FPR: {false_positives}/1000");
    }
}