use crate::coding::{crc32c, decode_len_prefixed, encode_len_prefixed};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ValueType {
    Deletion = 0,
    Value = 1,
}

impl ValueType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Deletion),
            1 => Some(Self::Value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalEntry {
    pub seq: u64,
    pub kind: ValueType,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

pub struct Wal {
    path: PathBuf,
    file: File,
    bytes_written: u64,
}

impl Wal {
    /// Opens an existing WAL or creates a new one, recovering valid records and
    /// truncating any torn/corrupted tail frames caused by a power loss.
    pub fn open(path: impl AsRef<Path>) -> io::Result<(Self, Vec<WalEntry>)> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)?;

        let mut raw = Vec::new();
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut raw)?;

        let mut entries = Vec::new();
        let mut valid_offset = 0usize;

        while valid_offset + 8 <= raw.len() {
            let expected_crc =
                u32::from_le_bytes(raw[valid_offset..valid_offset + 4].try_into().unwrap());
            let payload_len =
                u32::from_le_bytes(raw[valid_offset + 4..valid_offset + 8].try_into().unwrap())
                    as usize;

            let frame_end = match valid_offset.checked_add(8).and_then(|o| o.checked_add(payload_len)) {
                Some(end) if end <= raw.len() => end,
                _ => break, // Torn frame at EOF
            };

            let payload = &raw[valid_offset + 8..frame_end];
            if crc32c(payload) != expected_crc {
                break; // Corrupted frame at EOF
            }

            match decode_wal_payload(payload) {
                Some(entry) => {
                    entries.push(entry);
                    valid_offset = frame_end;
                }
                None => break,
            }
        }

        if valid_offset < raw.len() {
            file.set_len(valid_offset as u64)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;

        Ok((
            Self {
                path,
                file,
                bytes_written: valid_offset as u64,
            },
            entries,
        ))
    }

    pub fn append(&mut self, entry: &WalEntry, sync: bool) -> io::Result<()> {
        let mut payload = Vec::with_capacity(16 + entry.key.len() + entry.value.len());
        payload.extend_from_slice(&entry.seq.to_le_bytes());
        payload.push(entry.kind as u8);
        encode_len_prefixed(&entry.key, &mut payload);
        if entry.kind == ValueType::Value {
            encode_len_prefixed(&entry.value, &mut payload);
        }

        let crc = crc32c(&payload);
        let len = u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "WAL record exceeds 4GiB"))?;

        let mut frame = Vec::with_capacity(8 + payload.len());
        frame.extend_from_slice(&crc.to_le_bytes());
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(&payload);

        self.file.write_all(&frame)?;
        self.bytes_written += frame.len() as u64;
        if sync {
            self.file.sync_data()?;
        }
        Ok(())
    }

    pub fn sync(&self) -> io::Result<()> {
        self.file.sync_data()
    }

    pub fn size(&self) -> u64 {
        self.bytes_written
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn decode_wal_payload(payload: &[u8]) -> Option<WalEntry> {
    if payload.len() < 9 {
        return None;
    }
    let seq = u64::from_le_bytes(payload[0..8].try_into().unwrap());
    let kind = ValueType::from_u8(payload[8])?;
    let (key_slice, key_consumed) = decode_len_prefixed(&payload[9..])?;
    let rest = &payload[9 + key_consumed..];

    let value = match kind {
        ValueType::Deletion => {
            if !rest.is_empty() {
                return None;
            }
            Vec::new()
        }
        ValueType::Value => {
            let (val_slice, val_consumed) = decode_len_prefixed(rest)?;
            if val_consumed != rest.len() {
                return None;
            }
            val_slice.to_vec()
        }
    };

    Some(WalEntry {
        seq,
        kind,
        key: key_slice.to_vec(),
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_wal_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("lsm_forge_wal_{tag}_{nanos}.log"))
    }

    #[test]
    fn recovers_records_and_truncates_torn_tail() {
        let path = temp_wal_path("torn");
        {
            let (mut wal, initial) = Wal::open(&path).unwrap();
            assert!(initial.is_empty());

            wal.append(
                &WalEntry {
                    seq: 1,
                    kind: ValueType::Value,
                    key: b"alpha".to_vec(),
                    value: b"100".to_vec(),
                },
                true,
            )
            .unwrap();
            wal.append(
                &WalEntry {
                    seq: 2,
                    kind: ValueType::Deletion,
                    key: b"alpha".to_vec(),
                    value: Vec::new(),
                },
                true,
            )
            .unwrap();
        }

        // Simulate a mid-write crash by appending 7 garbage/partial bytes
        let valid_len = std::fs::metadata(&path).unwrap().len();
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&[0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x00, 0x00]).unwrap();
        }
        assert_eq!(std::fs::metadata(&path).unwrap().len(), valid_len + 7);

        // Recovery must preserve records 1 & 2 and truncate the 7 torn bytes
        let (wal, recovered) = Wal::open(&path).unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0].seq, 1);
        assert_eq!(recovered[1].kind, ValueType::Deletion);
        assert_eq!(wal.size(), valid_len);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), valid_len);

        let _ = std::fs::remove_file(&path);
    }
}