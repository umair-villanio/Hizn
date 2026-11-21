//! Passive WebSocket frame reader. Watches one direction of a passthrough byte
//! stream and reports each complete data message — reassembled from
//! fragments, unmasked, and inflated if permessage-deflate is in use — plus
//! the close code. It only reads; the bytes are forwarded untouched.
//!
//! Frames are processed as they stream in, so a huge message is never
//! buffered: only the first [`MAX_WS_MSG`] bytes are kept for the UI.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use flate2::{Decompress, FlushDecompress, Status};

/// Cap on message text relayed to the UI (Node's `MAX_WS_MSG`).
pub const MAX_WS_MSG: usize = 64 * 1024;

#[derive(Debug, PartialEq)]
pub enum Event {
    Message {
        binary: bool,
        head: Vec<u8>,
        size: u64,
    },
    /// A close frame: its status code, if it carried one.
    Close(Option<u16>),
}

/// permessage-deflate as negotiated in the handshake response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Deflate {
    pub client_no_context_takeover: bool,
    pub server_no_context_takeover: bool,
}

impl Deflate {
    /// From the server's `Sec-WebSocket-Extensions` header.
    pub fn negotiated(header: &str) -> Option<Self> {
        let ext = header
            .split(',')
            .find(|e| e.trim().split(';').next().map(str::trim) == Some("permessage-deflate"))?;
        let params: Vec<String> = ext
            .split(';')
            .skip(1)
            .map(|p| p.trim().to_ascii_lowercase())
            .collect();
        Some(Self {
            client_no_context_takeover: params.iter().any(|p| p == "client_no_context_takeover"),
            server_no_context_takeover: params.iter().any(|p| p == "server_no_context_takeover"),
        })
    }
}

struct Message {
    binary: bool,
    compressed: bool,
    head: Vec<u8>,
    size: u64,
}

impl Message {
    fn push(&mut self, bytes: &[u8]) {
        self.size += bytes.len() as u64;
        let room = MAX_WS_MSG.saturating_sub(self.head.len());
        self.head.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }
}

pub struct FrameReader {
    header: Vec<u8>,
    in_payload: bool,
    fin: bool,
    opcode: u8,
    mask: Option<[u8; 4]>,
    remaining: u64,
    offset: u64,
    control: Vec<u8>,
    message: Option<Message>,
    /// `Some` when permessage-deflate is on; `bool` = reset after each message.
    deflate: Option<bool>,
    inflater: Option<Decompress>,
    rsv1: bool,
    broken: bool,
}

impl FrameReader {
    /// `deflate`: whether permessage-deflate was negotiated, and if so whether
    /// this direction resets its compression context after every message.
    pub fn new(deflate: Option<bool>) -> Self {
        Self {
            header: Vec::with_capacity(14),
            in_payload: false,
            fin: false,
            opcode: 0,
            mask: None,
            remaining: 0,
            offset: 0,
            control: Vec::new(),
            message: None,
            deflate,
            inflater: None,
            rsv1: false,
            broken: false,
        }
    }

    pub fn push(&mut self, mut data: &[u8]) -> Vec<Event> {
        let mut events = Vec::new();
        while !data.is_empty() && !self.broken {
            if !self.in_payload {
                let need = header_len(&self.header);
                let take = need
                    .saturating_sub(self.header.len())
                    .min(data.len())
                    .max(1);
                self.header.extend_from_slice(&data[..take]);
                data = &data[take..];
                if self.header.len() == header_len(&self.header) {
                    self.start_frame(&mut events);
                }
                continue;
            }
            let n = (self.remaining.min(data.len() as u64)) as usize;
            let mut chunk = data[..n].to_vec();
            data = &data[n..];
            if let Some(key) = self.mask {
                for (i, b) in chunk.iter_mut().enumerate() {
                    *b ^= key[((self.offset + i as u64) % 4) as usize];
                }
            }
            self.offset += n as u64;
            self.remaining -= n as u64;
            self.payload(&chunk);
            if self.remaining == 0 {
                self.finish_frame(&mut events);
            }
        }
        events
    }

    fn start_frame(&mut self, events: &mut Vec<Event>) {
        let h = std::mem::take(&mut self.header);
        self.fin = h[0] & 0x80 != 0;
        self.rsv1 = h[0] & 0x40 != 0;
        self.opcode = h[0] & 0x0f;
        let masked = h[1] & 0x80 != 0;
        let (len, at) = match h[1] & 0x7f {
            126 => (u16::from_be_bytes([h[2], h[3]]) as u64, 4),
            127 => (
                u64::from_be_bytes(h[2..10].try_into().expect("8 bytes")),
                10,
            ),
            n => (n as u64, 2),
        };
        self.mask = masked.then(|| [h[at], h[at + 1], h[at + 2], h[at + 3]]);
        self.remaining = len;
        self.offset = 0;
        self.in_payload = true;
        match self.opcode {
            1 | 2 => {
                self.message = Some(Message {
                    binary: self.opcode == 2,
                    compressed: self.rsv1 && self.deflate.is_some(),
                    head: Vec::new(),
                    size: 0,
                })
            }
            8..=15 => self.control.clear(),
            _ => {}
        }
        if self.remaining == 0 {
            self.finish_frame(events);
        }
    }

    fn payload(&mut self, chunk: &[u8]) {
        match self.opcode {
            0..=2 => {
                if self.message.as_ref().is_some_and(|m| m.compressed) {
                    self.inflate(chunk, FlushDecompress::None);
                } else if let Some(m) = self.message.as_mut() {
                    m.push(chunk);
                }
            }
            8..=15 => {
                let room = 125usize.saturating_sub(self.control.len());
                self.control
                    .extend_from_slice(&chunk[..chunk.len().min(room)]);
            }
            _ => {}
        }
    }

    fn finish_frame(&mut self, events: &mut Vec<Event>) {
        self.in_payload = false;
        match self.opcode {
            8 => events
                .push(Event::Close((self.control.len() >= 2).then(|| {
                    u16::from_be_bytes([self.control[0], self.control[1]])
                }))),
            0..=2 if self.fin => {
                if self.message.as_ref().is_some_and(|m| m.compressed) {
                    // RFC 7692: each message ends with an implied empty block.
                    self.inflate(&[0x00, 0x00, 0xff, 0xff], FlushDecompress::Sync);
                    if self.deflate == Some(true) {
                        self.inflater = None;
                    }
                }
                if let Some(m) = self.message.take() {
                    events.push(Event::Message {
                        binary: m.binary,
                        head: m.head,
                        size: m.size,
                    });
                }
            }
            _ => {}
        }
    }

    fn inflate(&mut self, mut input: &[u8], flush: FlushDecompress) {
        let mut inflater = self
            .inflater
            .take()
            .unwrap_or_else(|| Decompress::new(false));
        let mut out = vec![0u8; 32 * 1024];
        loop {
            let (in_before, out_before) = (inflater.total_in(), inflater.total_out());
            let status = inflater.decompress(input, &mut out, flush);
            let consumed = (inflater.total_in() - in_before) as usize;
            let produced = (inflater.total_out() - out_before) as usize;
            if let Some(m) = self.message.as_mut() {
                m.push(&out[..produced]);
            }
            input = &input[consumed..];
            match status {
                Err(_) => {
                    // Can't follow this stream any more; stop reporting it.
                    self.broken = true;
                    return;
                }
                Ok(Status::StreamEnd) => break,
                Ok(_) => {}
            }
            if (input.is_empty() && produced < out.len()) || (consumed == 0 && produced == 0) {
                break;
            }
        }
        self.inflater = Some(inflater);
    }
}

/// Header length for what's been read so far (2 until the length byte is in).
fn header_len(h: &[u8]) -> usize {
    if h.len() < 2 {
        return 2;
    }
    let ext = match h[1] & 0x7f {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    2 + ext + if h[1] & 0x80 != 0 { 4 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    fn frame(fin: bool, rsv1: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut f = vec![(if fin { 0x80 } else { 0 }) | (if rsv1 { 0x40 } else { 0 }) | opcode];
        let m = if mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => f.push(m | n as u8),
            n if n < 65536 => {
                f.push(m | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                f.push(m | 127);
                f.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        match mask {
            Some(k) => {
                f.extend_from_slice(&k);
                f.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
            }
            None => f.extend_from_slice(payload),
        }
        f
    }

    fn feed_bytewise(r: &mut FrameReader, bytes: &[u8]) -> Vec<Event> {
        bytes
            .iter()
            .flat_map(|b| r.push(std::slice::from_ref(b)))
            .collect()
    }

    #[test]
    fn masked_fragmented_text_with_interleaved_ping_and_close() {
        let k = Some([1, 2, 3, 4]);
        let mut wire = frame(false, false, 1, b"hello ", k);
        wire.extend(frame(true, false, 9, b"ping", k));
        wire.extend(frame(true, false, 0, b"world", k));
        wire.extend(frame(true, false, 8, &[0x03, 0xe8, b'b', b'y'], k));
        let events = feed_bytewise(&mut FrameReader::new(None), &wire);
        assert_eq!(
            events,
            vec![
                Event::Message {
                    binary: false,
                    head: b"hello world".to_vec(),
                    size: 11
                },
                Event::Close(Some(1000)),
            ]
        );
    }

    #[test]
    fn large_binary_is_capped_but_counted_and_empty_close_has_no_code() {
        let big = vec![7u8; 200_000];
        let mut wire = frame(true, false, 2, &big, None);
        wire.extend(frame(true, false, 8, &[], None));
        let events = FrameReader::new(None).push(&wire);
        let Event::Message { binary, head, size } = &events[0] else {
            panic!()
        };
        assert!(*binary && head.len() == MAX_WS_MSG && *size == 200_000);
        assert_eq!(events[1], Event::Close(None));
    }

    #[test]
    fn inflates_permessage_deflate_with_context_takeover() {
        // Two messages compressed with one shared context (the default).
        let mut c = Compress::new(Compression::default(), false);
        let mut wire = Vec::new();
        for text in [
            b"repeat repeat repeat".as_slice(),
            b"repeat repeat repeat again".as_slice(),
        ] {
            let mut out = Vec::with_capacity(256);
            c.compress_vec(text, &mut out, FlushCompress::Sync).unwrap();
            assert!(out.ends_with(&[0x00, 0x00, 0xff, 0xff]));
            out.truncate(out.len() - 4);
            wire.extend(frame(true, true, 1, &out, None));
        }
        let events = feed_bytewise(&mut FrameReader::new(Some(false)), &wire);
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[1],
            Event::Message {
                binary: false,
                head: b"repeat repeat repeat again".to_vec(),
                size: 26
            }
        );
    }

    #[test]
    fn negotiation_parsing() {
        assert_eq!(
            Deflate::negotiated(
                "permessage-deflate; server_no_context_takeover; client_max_window_bits=10"
            ),
            Some(Deflate {
                client_no_context_takeover: false,
                server_no_context_takeover: true
            })
        );
        assert_eq!(Deflate::negotiated("x-webkit-deflate-frame"), None);
    }
}
