const CRC32C_POLY: u32 = 0x82F6_3B78;

const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32C_POLY;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_extend(0, data)
}

pub fn crc32c_extend(initial: u32, data: &[u8]) -> u32 {
    let mut crc = !initial;
    for &b in data {
        let idx = ((crc ^ u32::from(b)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32C_TABLE[idx];
    }
    !crc
}

pub fn encode_varint64(mut v: u64, dst: &mut Vec<u8>) {
    while v >= 0x80 {
        dst.push(((v as u8) & 0x7F) | 0x80);
        v >>= 7;
    }
    dst.push(v as u8);
}

pub fn decode_varint64(src: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for (i, &byte) in src.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        let low = u64::from(byte & 0x7F);
        if shift == 63 && low > 1 {
            return None;
        }
        result |= low << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

pub fn encode_varint32(v: u32, dst: &mut Vec<u8>) {
    encode_varint64(u64::from(v), dst);
}

pub fn decode_varint32(src: &[u8]) -> Option<(u32, usize)> {
    let (v, n) = decode_varint64(src)?;
    let v32 = u32::try_from(v).ok()?;
    Some((v32, n))
}

pub fn encode_len_prefixed(bytes: &[u8], dst: &mut Vec<u8>) {
    encode_varint64(bytes.len() as u64, dst);
    dst.extend_from_slice(bytes);
}

pub fn decode_len_prefixed(src: &[u8]) -> Option<(&[u8], usize)> {
    let (len_u64, header_len) = decode_varint64(src)?;
    let len = usize::try_from(len_u64).ok()?;
    let end = header_len.checked_add(len)?;
    let slice = src.get(header_len..end)?;
    Some((slice, end))
}

/// Deterministic Xoshiro256** PRNG seeded via SplitMix64.
#[derive(Debug, Clone)]
pub struct FastRng {
    s: [u64; 4],
}

impl FastRng {
    pub fn new(mut seed: u64) -> Self {
        let mut s = [0u64; 4];
        for slot in &mut s {
            seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *slot = z ^ (z >> 31);
        }
        Self { s }
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = (self.s[1].wrapping_mul(5)).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_varints_and_slices() {
        let samples = [0u64, 1, 127, 128, 255, 16_384, u32::MAX as u64, u64::MAX];
        for &val in &samples {
            let mut buf = Vec::new();
            encode_varint64(val, &mut buf);
            let (decoded, consumed) = decode_varint64(&buf).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, buf.len());
        }

        let mut frame = Vec::new();
        encode_len_prefixed(b"lsm-forge", &mut frame);
        let (slice, consumed) = decode_len_prefixed(&frame).unwrap();
        assert_eq!(slice, b"lsm-forge");
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn crc32c_detects_single_bit_flip() {
        let payload = b"durable-storage-engine";
        let sum = crc32c(payload);
        assert_eq!(sum, crc32c(payload));
        let mut corrupted = payload.to_vec();
        corrupted[5] ^= 0x01;
        assert_ne!(sum, crc32c(&corrupted));
    }
}