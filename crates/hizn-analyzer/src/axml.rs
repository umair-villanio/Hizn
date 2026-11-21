//! Binary AndroidManifest.xml (AXML) decoder → a small element tree, and the
//! resources.arsc string decoder. Mirrors the Node `parseAxml` / `parseArsc`.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// android: attribute resource IDs → names (for AXML with empty name strings).
fn attr_res_name(rid: u32) -> &'static str {
    match rid {
        0x0101021b => "versionCode",
        0x0101021c => "versionName",
        0x0101020c => "minSdkVersion",
        0x01010270 => "targetSdkVersion",
        0x01010003 => "name",
        0x01010006 => "permission",
        0x01010010 => "exported",
        0x0101000f => "debuggable",
        0x01010280 => "allowBackup",
        0x010104ec | 0x0101048d => "usesCleartextTraffic",
        0x010104dd => "networkSecurityConfig",
        0x01010009 => "protectionLevel",
        0x0101055b => "compileSdkVersion",
        _ => "",
    }
}

#[derive(Debug, Default)]
pub struct Node {
    pub name: String,
    pub attrs: HashMap<String, String>,
    pub children: Vec<Node>,
}

impl Node {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.get(name).map(String::as_str)
    }

    /// Every descendant element with this name, pre-order.
    pub fn find_all<'a>(&'a self, name: &str, out: &mut Vec<&'a Node>) {
        for c in &self.children {
            if c.name == name {
                out.push(c);
            }
            c.find_all(name, out);
        }
    }

    pub fn find_all_vec(&self, name: &str) -> Vec<&Node> {
        let mut out = Vec::new();
        self.find_all(name, &mut out);
        out
    }

    pub fn find_first(&self, name: &str) -> Option<&Node> {
        self.find_all_vec(name).into_iter().next()
    }
}

/// Decode a UTF-8 or UTF-16LE string-pool entry at offset `o`.
fn read_pool_string(buf: &[u8], o: usize, utf8: bool) -> String {
    let mut o = o;
    if utf8 {
        if o >= buf.len() {
            return String::new();
        }
        // skip char-count (u8/u16 varint), then byte-count, then bytes
        o += if buf[o] & 0x80 != 0 { 2 } else { 1 };
        if o >= buf.len() {
            return String::new();
        }
        let mut len = buf[o] as usize;
        if len & 0x80 != 0 {
            if o + 1 >= buf.len() {
                return String::new();
            }
            len = ((len & 0x7f) << 8) | buf[o + 1] as usize;
            o += 2;
        } else {
            o += 1;
        }
        let end = (o + len).min(buf.len());
        String::from_utf8_lossy(&buf[o..end]).into_owned()
    } else {
        if o + 2 > buf.len() {
            return String::new();
        }
        let mut len = u16le(buf, o) as usize;
        o += 2;
        if len & 0x8000 != 0 {
            if o + 2 > buf.len() {
                return String::new();
            }
            len = ((len & 0x7fff) << 16) | u16le(buf, o) as usize;
            o += 2;
        }
        let end = (o + len * 2).min(buf.len());
        let units: Vec<u16> = buf[o..end]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&units)
    }
}

/// A RES_STRING_POOL chunk (header at `start`) → its strings.
pub fn decode_string_pool(buf: &[u8], start: usize) -> Vec<String> {
    if start + 28 > buf.len() {
        return Vec::new();
    }
    let count = u32le(buf, start + 8) as usize;
    let flags = u32le(buf, start + 16);
    let strings_start = u32le(buf, start + 20) as usize;
    let utf8 = flags & (1 << 8) != 0;
    let base = start + strings_start;
    let mut out = Vec::with_capacity(count.min(1 << 20));
    for i in 0..count {
        let off_pos = start + 28 + i * 4;
        if off_pos + 4 > buf.len() {
            out.push(String::new());
            continue;
        }
        let o = base + u32le(buf, off_pos) as usize;
        out.push(if o < buf.len() {
            read_pool_string(buf, o, utf8)
        } else {
            String::new()
        });
    }
    out
}

/// Decode a binary AndroidManifest into a tree. Errors if it isn't AXML.
pub fn parse_axml(buf: &[u8]) -> Result<Node, String> {
    if buf.len() < 8 || u16le(buf, 0) != 0x0003 {
        return Err("Not a binary AndroidManifest (AXML)".into());
    }
    let mut pos = 8usize;
    let mut strings: Vec<String> = Vec::new();
    let mut res_map: Vec<u32> = Vec::new();

    let str_at =
        |strings: &[String], i: usize| -> String { strings.get(i).cloned().unwrap_or_default() };

    let mut root = Node {
        name: "#root".into(),
        ..Default::default()
    };
    // Indices into the tree stack; we build with a path of raw pointers via ids.
    let mut stack: Vec<Node> = vec![std::mem::take(&mut root)];

    while pos + 8 <= buf.len() {
        let typ = u16le(buf, pos);
        let size = u32le(buf, pos + 4) as usize;
        if size < 8 {
            break;
        }
        match typ {
            0x0001 => {
                strings = decode_string_pool(buf, pos);
            }
            0x0180 => {
                let n = (size - 8) / 4;
                res_map = (0..n)
                    .map(|i| {
                        if pos + 8 + i * 4 + 4 <= buf.len() {
                            u32le(buf, pos + 8 + i * 4)
                        } else {
                            0
                        }
                    })
                    .collect();
            }
            0x0102 => {
                // ResXMLTree_node: header(8) lineNumber(4) comment(4) then attrExt
                let ext = pos + 16;
                if ext + 16 > buf.len() {
                    pos += size;
                    continue;
                }
                let name = str_at(&strings, u32le(buf, ext + 4) as usize);
                let attr_start = u16le(buf, ext + 8) as usize;
                let attr_count = u16le(buf, ext + 12) as usize;
                let mut node = Node {
                    name,
                    ..Default::default()
                };
                let mut ap = ext + attr_start;
                for _ in 0..attr_count {
                    if ap + 20 > buf.len() {
                        break;
                    }
                    let name_idx = u32le(buf, ap + 4) as usize;
                    let a_name = {
                        let s = str_at(&strings, name_idx);
                        if !s.is_empty() {
                            s
                        } else {
                            res_map
                                .get(name_idx)
                                .map(|&r| attr_res_name(r).to_owned())
                                .unwrap_or_default()
                        }
                    };
                    let raw_value =
                        i32::from_le_bytes([buf[ap + 8], buf[ap + 9], buf[ap + 10], buf[ap + 11]]);
                    let data_type = buf[ap + 8 + 4 + 3];
                    let data = u32le(buf, ap + 8 + 4 + 4);
                    let val = if raw_value != -1 {
                        str_at(&strings, raw_value as usize)
                    } else {
                        match data_type {
                            0x12 => {
                                if data != 0 {
                                    "true".into()
                                } else {
                                    "false".into()
                                }
                            }
                            0x10 => (data as i32).to_string(),
                            0x11 => format!("0x{data:x}"),
                            0x03 => str_at(&strings, data as usize),
                            0x01 => format!("@{data:x}"),
                            _ => data.to_string(),
                        }
                    };
                    if !a_name.is_empty() {
                        node.attrs.insert(a_name, val);
                    }
                    ap += 20;
                }
                stack.push(node);
            }
            0x0103 if stack.len() > 1 => {
                let node = stack.pop().expect("stack non-empty");
                stack
                    .last_mut()
                    .expect("parent present")
                    .children
                    .push(node);
            }
            _ => {}
        }
        pos += size;
    }
    // Unwind anything left open (malformed), preserving nesting.
    while stack.len() > 1 {
        let node = stack.pop().expect("stack non-empty");
        stack
            .last_mut()
            .expect("parent present")
            .children
            .push(node);
    }
    Ok(stack.pop().expect("root present"))
}

/// resources.arsc → global string values + resolved name→value string resources.
pub struct Arsc {
    pub values: Vec<String>,
    pub named: Vec<(String, String)>,
}

pub fn parse_arsc(buf: &[u8]) -> Arsc {
    let mut res = Arsc {
        values: Vec::new(),
        named: Vec::new(),
    };
    if buf.len() < 12 || u16le(buf, 0) != 0x0002 {
        return res;
    }
    let mut pos = u16le(buf, 2) as usize; // table headerSize
    if pos + 8 <= buf.len() && u16le(buf, pos) == 0x0001 {
        res.values = decode_string_pool(buf, pos);
        pos += u32le(buf, pos + 4) as usize;
    }
    while pos + 8 <= buf.len() {
        let typ = u16le(buf, pos);
        let size = u32le(buf, pos + 4) as usize;
        if size < 8 {
            break;
        }
        if typ == 0x0200 {
            parse_package(buf, pos, size, &mut res);
        }
        pos = match pos.checked_add(size) {
            Some(p) => p,
            None => break,
        };
    }
    res
}

fn parse_package(buf: &[u8], start: usize, size: usize, res: &mut Arsc) {
    if start + 280 > buf.len() {
        return;
    }
    let hdr_size = u16le(buf, start + 2) as usize;
    let key_strings_off = u32le(buf, start + 276) as usize;
    let key_names = if key_strings_off != 0 {
        decode_string_pool(buf, start + key_strings_off)
    } else {
        Vec::new()
    };
    let mut p = start + hdr_size;
    let end = (start + size).min(buf.len());
    while p + 8 <= end {
        let t = u16le(buf, p);
        let sz = u32le(buf, p + 4) as usize;
        if sz < 8 {
            break;
        }
        if t == 0x0201 {
            parse_type(buf, p, sz, &key_names, res);
        }
        p = match p.checked_add(sz) {
            Some(p) => p,
            None => break,
        };
    }
}

fn parse_type(buf: &[u8], start: usize, size: usize, key_names: &[String], res: &mut Arsc) {
    if start + 20 > buf.len() {
        return;
    }
    let hdr_size = u16le(buf, start + 2) as usize;
    let entry_count = (u32le(buf, start + 12) as usize).min(200_000);
    let entries_start = u32le(buf, start + 16) as usize;
    let off_arr = start + hdr_size;
    let entries_base = start + entries_start;
    let type_end = (start + size).min(buf.len());
    for i in 0..entry_count {
        let off_pos = off_arr + i * 4;
        if off_pos + 4 > buf.len() {
            break;
        }
        let off = u32le(buf, off_pos);
        if off == 0xffffffff {
            continue;
        }
        let e = entries_base + off as usize;
        if e + 8 > type_end || e + 12 > buf.len() {
            continue;
        }
        let flags = u16le(buf, e + 2);
        let key_idx = u32le(buf, e + 4) as usize;
        if flags & 0x0001 != 0 {
            continue; // complex/map entry
        }
        let v = e + 8; // Res_value
        if v + 8 > buf.len() || buf[v + 3] != 0x03 {
            continue; // TYPE_STRING only
        }
        let name = key_names.get(key_idx).cloned().unwrap_or_default();
        let value = res
            .values
            .get(u32le(buf, v + 4) as usize)
            .cloned()
            .unwrap_or_default();
        if !name.is_empty() && !value.is_empty() {
            res.named.push((name, value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_axml() {
        assert!(parse_axml(b"<?xml version").is_err());
        assert!(parse_axml(&[]).is_err());
    }
}
