//! A minimal D-Bus wire codec — only the pieces the Frida control protocol
//! needs (little-endian, direct connection, no auth, no Hello).
//!
//! Frida speaks GDBus over its socket: standard D-Bus messages, which here ride
//! on a WebSocket byte stream. This marshals the method calls Hizn makes and
//! parses the returns; it is not a general D-Bus implementation.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

/// A D-Bus value, limited to the types Frida's methods use.
#[derive(Debug, Clone)]
pub enum Value {
    Byte(u8),
    Bool(bool),
    U32(u32),
    I32(i32),
    Str(String),
    ObjectPath(String),
    Signature(String),
    /// Array of same-typed elements (element signature + items).
    Array(&'static str, Vec<Value>),
    Struct(Vec<Value>),
    /// A variant: the value's signature + the value.
    Variant(&'static str, Box<Value>),
    /// `a{sv}` — only empty is needed.
    EmptyDict,
}

/// Writes values little-endian with D-Bus alignment.
#[derive(Default)]
struct Marshaller {
    buf: Vec<u8>,
}

impl Marshaller {
    fn align(&mut self, n: usize) {
        while !self.buf.len().is_multiple_of(n) {
            self.buf.push(0);
        }
    }

    fn write(&mut self, v: &Value) {
        match v {
            Value::Byte(b) => self.buf.push(*b),
            Value::Bool(b) => {
                self.align(4);
                self.buf.extend_from_slice(&u32::from(*b).to_le_bytes());
            }
            Value::U32(n) => {
                self.align(4);
                self.buf.extend_from_slice(&n.to_le_bytes());
            }
            Value::I32(n) => {
                self.align(4);
                self.buf.extend_from_slice(&n.to_le_bytes());
            }
            Value::Str(s) | Value::ObjectPath(s) => {
                self.align(4);
                self.buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
                self.buf.extend_from_slice(s.as_bytes());
                self.buf.push(0);
            }
            Value::Signature(s) => {
                self.buf.push(s.len() as u8);
                self.buf.extend_from_slice(s.as_bytes());
                self.buf.push(0);
            }
            Value::Array(elem_sig, items) => {
                self.align(4);
                let len_pos = self.buf.len();
                self.buf.extend_from_slice(&[0u8; 4]);
                self.align(element_alignment(elem_sig));
                let content_start = self.buf.len();
                for item in items {
                    self.write(item);
                }
                let content_len = (self.buf.len() - content_start) as u32;
                self.buf[len_pos..len_pos + 4].copy_from_slice(&content_len.to_le_bytes());
            }
            Value::Struct(fields) => {
                self.align(8);
                for f in fields {
                    self.write(f);
                }
            }
            Value::Variant(sig, inner) => {
                self.write(&Value::Signature((*sig).to_owned()));
                self.write(inner);
            }
            Value::EmptyDict => {
                self.align(4);
                self.buf.extend_from_slice(&[0u8; 4]); // length 0
                self.align(8); // dict-entry alignment
            }
        }
    }
}

/// The alignment of a D-Bus type by its signature's first char.
fn element_alignment(sig: &str) -> usize {
    match sig.bytes().next() {
        Some(b'y' | b'g' | b'v') => 1,
        Some(b'b' | b'u' | b'i' | b's' | b'o' | b'a') => 4,
        Some(b'(' | b'{') => 8,
        _ => 1,
    }
}

const PROTOCOL_VERSION: u8 = 1;
const MSG_METHOD_CALL: u8 = 1;
pub const MSG_METHOD_RETURN: u8 = 2;
pub const MSG_ERROR: u8 = 3;

// Header field codes.
const PATH: u8 = 1;
const INTERFACE: u8 = 2;
const MEMBER: u8 = 3;
const DESTINATION: u8 = 6;
const SIGNATURE: u8 = 8;

/// Build a `method_call` message. `signature` is the body signature (empty for
/// no args); `args` the body values.
pub fn method_call(
    serial: u32,
    destination: &str,
    path: &str,
    interface: &str,
    member: &str,
    signature: &str,
    args: &[Value],
) -> Vec<u8> {
    let mut body = Marshaller::default();
    for a in args {
        body.write(a);
    }
    let body = body.buf;

    let field = |code: u8, sig: &'static str, v: Value| {
        Value::Struct(vec![Value::Byte(code), Value::Variant(sig, Box::new(v))])
    };
    let mut fields = vec![
        field(PATH, "o", Value::ObjectPath(path.to_owned())),
        field(DESTINATION, "s", Value::Str(destination.to_owned())),
        field(INTERFACE, "s", Value::Str(interface.to_owned())),
        field(MEMBER, "s", Value::Str(member.to_owned())),
    ];
    if !signature.is_empty() {
        fields.push(field(
            SIGNATURE,
            "g",
            Value::Signature(signature.to_owned()),
        ));
    }

    let mut m = Marshaller::default();
    m.buf.push(b'l');
    m.buf.push(MSG_METHOD_CALL);
    m.buf.push(0); // flags
    m.buf.push(PROTOCOL_VERSION);
    m.buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    m.buf.extend_from_slice(&serial.to_le_bytes());
    m.write(&Value::Array("(yv)", fields));
    m.align(8);
    m.buf.extend_from_slice(&body);
    m.buf
}

/// A parsed reply message.
pub struct Reply {
    pub msg_type: u8,
    pub reply_serial: u32,
    pub error_name: Option<String>,
    pub signature: String,
    body: Vec<u8>,
}

/// If `buf` begins with a complete message, return its total byte length.
pub fn message_length(buf: &[u8]) -> Option<usize> {
    if buf.len() < 16 || buf[0] != b'l' {
        return None;
    }
    let body_len = u32::from_le_bytes(buf[4..8].try_into().ok()?) as usize;
    let fields_len = u32::from_le_bytes(buf[12..16].try_into().ok()?) as usize;
    let header_len = pad8(16 + fields_len);
    Some(header_len + body_len)
}

fn pad8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

/// Parse one complete message (as framed by [`message_length`]).
pub fn parse(buf: &[u8]) -> Option<Reply> {
    let msg_type = buf[1];
    let body_len = u32::from_le_bytes(buf[4..8].try_into().ok()?) as usize;
    let fields_len = u32::from_le_bytes(buf[12..16].try_into().ok()?) as usize;

    // Header fields array starts at 16.
    let mut reply_serial = 0u32;
    let mut error_name = None;
    let mut signature = String::new();
    let mut p = 16usize;
    let end = 16 + fields_len;
    while p < end {
        p = align(p, 8); // dict-entry / struct alignment
        if p >= end {
            break;
        }
        let code = buf[p];
        p += 1;
        // variant: signature (g) then value
        let sig_len = *buf.get(p)? as usize;
        p += 1;
        let var_sig = std::str::from_utf8(buf.get(p..p + sig_len)?)
            .ok()?
            .to_owned();
        p += sig_len + 1; // + nul
        let (val, np) = read_simple(buf, p, &var_sig)?;
        p = np;
        match code {
            SIGNATURE => signature = val,
            5 => reply_serial = val.parse().unwrap_or(0), // REPLY_SERIAL (u)
            4 => error_name = Some(val),                  // ERROR_NAME (s)
            _ => {}
        }
    }

    let header_len = pad8(16 + fields_len);
    let body = buf.get(header_len..header_len + body_len)?.to_vec();
    Some(Reply {
        msg_type,
        reply_serial,
        error_name,
        signature,
        body,
    })
}

fn align(p: usize, n: usize) -> usize {
    p.div_ceil(n) * n
}

/// Read a header-field value as a string (object paths, strings, signatures are
/// all we store; uint32 returned as its decimal text for REPLY_SERIAL).
fn read_simple(buf: &[u8], p: usize, sig: &str) -> Option<(String, usize)> {
    match sig {
        "u" => {
            let p = align(p, 4);
            let n = u32::from_le_bytes(buf.get(p..p + 4)?.try_into().ok()?);
            Some((n.to_string(), p + 4))
        }
        "g" => {
            let len = *buf.get(p)? as usize;
            let s = std::str::from_utf8(buf.get(p + 1..p + 1 + len)?)
                .ok()?
                .to_owned();
            Some((s, p + 1 + len + 1))
        }
        "s" | "o" => {
            let p = align(p, 4);
            let len = u32::from_le_bytes(buf.get(p..p + 4)?.try_into().ok()?) as usize;
            let s = std::str::from_utf8(buf.get(p + 4..p + 4 + len)?)
                .ok()?
                .to_owned();
            Some((s, p + 4 + len + 1))
        }
        _ => None,
    }
}

impl Reply {
    /// Read a `u` from the start of the body (used for `(u)` returns — the
    /// struct has no padding at offset 0).
    pub fn body_u32(&self) -> Option<u32> {
        self.body
            .get(0..4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
    }

    /// Read the first string from the body (used for `(s)` returns).
    pub fn body_str(&self) -> Option<String> {
        let len = u32::from_le_bytes(self.body.get(0..4)?.try_into().ok()?) as usize;
        std::str::from_utf8(self.body.get(4..4 + len)?)
            .ok()
            .map(str::to_owned)
    }

    /// The error message string, if this is an error reply with a string body.
    pub fn error_message(&self) -> String {
        let name = self.error_name.clone().unwrap_or_else(|| "error".into());
        if self.signature.starts_with('s')
            && let Some(msg) = self.body_str()
        {
            format!("{name}: {msg}")
        } else {
            name
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marshals_a_simple_call_and_reparses_its_frame() {
        // Resume(pid=42): body signature "u", one u32.
        let msg = method_call(
            1,
            "re.frida.HostSession17",
            "/re/frida/HostSession",
            "re.frida.HostSession17",
            "Resume",
            "u",
            &[Value::U32(42)],
        );
        // The message framing is self-describing.
        assert_eq!(message_length(&msg), Some(msg.len()));
        assert_eq!(msg[0], b'l');
        assert_eq!(msg[1], MSG_METHOD_CALL);
    }

    #[test]
    fn string_and_struct_alignment() {
        let mut m = Marshaller::default();
        m.write(&Value::Byte(3));
        m.write(&Value::Struct(vec![Value::U32(7)])); // struct aligns to 8
        // byte at 0, struct padded to offset 8, u32 there.
        assert_eq!(m.buf.len(), 12);
        assert_eq!(&m.buf[8..12], &7u32.to_le_bytes());
    }
}
