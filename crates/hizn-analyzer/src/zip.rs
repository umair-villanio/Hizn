//! Minimal ZIP reader for APKs: parse the central directory, inflate entries on
//! demand. Mirrors the Node `Zip` class (little-endian reads throughout).
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::io::Read;

use indexmap_lite::IndexMap;

/// A tiny insertion-ordered map so entry iteration matches the central
/// directory order (the Node `Map` preserved it).
mod indexmap_lite {
    pub struct IndexMap<V> {
        keys: Vec<String>,
        map: std::collections::HashMap<String, V>,
    }
    impl<V> Default for IndexMap<V> {
        fn default() -> Self {
            Self {
                keys: Vec::new(),
                map: std::collections::HashMap::new(),
            }
        }
    }
    impl<V> IndexMap<V> {
        pub fn insert(&mut self, key: String, value: V) {
            if !self.map.contains_key(&key) {
                self.keys.push(key.clone());
            }
            self.map.insert(key, value);
        }
        pub fn get(&self, key: &str) -> Option<&V> {
            self.map.get(key)
        }
        pub fn keys(&self) -> impl Iterator<Item = &String> {
            self.keys.iter()
        }
        pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
            self.keys
                .iter()
                .map(move |k| (k, self.map.get(k).expect("key present")))
        }
    }
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[derive(Clone)]
struct Entry {
    method: u16,
    comp_size: u32,
    local_offset: u32,
}

pub struct Zip<'a> {
    buf: &'a [u8],
    entries: IndexMap<Entry>,
    /// Central-directory start offset — also where the APK Signing Block ends.
    pub cd_offset: usize,
}

impl<'a> Zip<'a> {
    /// Parse the central directory. Errors only when there's no EOCD record.
    pub fn new(buf: &'a [u8]) -> Result<Self, String> {
        let mut zip = Zip {
            buf,
            entries: IndexMap::default(),
            cd_offset: 0,
        };
        zip.read_central_directory()?;
        Ok(zip)
    }

    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }

    fn read_central_directory(&mut self) -> Result<(), String> {
        let b = self.buf;
        if b.len() < 22 {
            return Err("Not a ZIP/APK (no end-of-central-directory record)".into());
        }
        // Find EOCD (0x06054b50), scanning back from the end.
        let min_pos = b.len().saturating_sub(65557); // max comment 65535 + 22
        let mut eocd = None;
        let mut i = b.len() - 22;
        loop {
            if u32le(b, i) == 0x06054b50 {
                eocd = Some(i);
                break;
            }
            if i == min_pos {
                break;
            }
            i -= 1;
        }
        let eocd = eocd.ok_or("Not a ZIP/APK (no end-of-central-directory record)")?;
        let cd_count = u16le(b, eocd + 10);
        let mut off = u32le(b, eocd + 16) as usize;
        self.cd_offset = off;
        for _ in 0..cd_count {
            if off + 46 > b.len() || u32le(b, off) != 0x02014b50 {
                break;
            }
            let method = u16le(b, off + 10);
            let comp_size = u32le(b, off + 20);
            let name_len = u16le(b, off + 28) as usize;
            let extra_len = u16le(b, off + 30) as usize;
            let comment_len = u16le(b, off + 32) as usize;
            let local_offset = u32le(b, off + 42);
            if off + 46 + name_len > b.len() {
                break;
            }
            let name = String::from_utf8_lossy(&b[off + 46..off + 46 + name_len]).into_owned();
            self.entries.insert(
                name,
                Entry {
                    method,
                    comp_size,
                    local_offset,
                },
            );
            off += 46 + name_len + extra_len + comment_len;
        }
        Ok(())
    }

    pub fn read(&self, name: &str) -> Option<Vec<u8>> {
        self.entries.get(name).and_then(|e| self.read_entry(e))
    }

    fn read_entry(&self, e: &Entry) -> Option<Vec<u8>> {
        let b = self.buf;
        let lo = e.local_offset as usize;
        if lo + 30 > b.len() || u32le(b, lo) != 0x04034b50 {
            return None;
        }
        let name_len = u16le(b, lo + 26) as usize;
        let extra_len = u16le(b, lo + 28) as usize;
        let data_start = lo + 30 + name_len + extra_len;
        let end = data_start.checked_add(e.comp_size as usize)?;
        if end > b.len() {
            return None;
        }
        let data = &b[data_start..end];
        match e.method {
            0 => Some(data.to_vec()),
            8 => {
                let mut out = Vec::new();
                flate2::read::DeflateDecoder::new(data)
                    .read_to_end(&mut out)
                    .ok()?;
                Some(out)
            }
            _ => None,
        }
    }

    /// Iterate every entry's name and inflated bytes (lazily read).
    pub fn all(&self) -> impl Iterator<Item = (&String, Option<Vec<u8>>)> {
        self.entries
            .iter()
            .map(move |(name, e)| (name, self.read_entry(e)))
    }
}
