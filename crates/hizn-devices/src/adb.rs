//! A thin ADB client: just enough of the ADB server protocol (TCP 5037) for
//! Hizn — device listing, shell, sync push/pull, reverse tunnels, and TCP
//! connect. This replaces `@devicefarmer/adbkit`.
//!
//! The protocol: each request is a 4-hex-digit length followed by the request
//! text; the server replies `OKAY` or `FAIL<len><reason>`. Host services
//! (`host:...`) answer on the same socket; a device service needs a
//! `host:transport:<serial>` switch on the connection first.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Where the local ADB server listens (override with `ANDROID_ADB_SERVER_PORT`).
fn server_addr() -> (String, u16) {
    let host = std::env::var("ANDROID_ADB_SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("ANDROID_ADB_SERVER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5037);
    (host, port)
}

#[derive(Debug)]
pub enum AdbError {
    /// The ADB server isn't reachable (not started).
    NoServer(io::Error),
    Io(io::Error),
    /// The server replied `FAIL` with this reason.
    Failed(String),
}

impl std::fmt::Display for AdbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoServer(_) => f.write_str(
                "could not reach the ADB server on this machine — is `adb` installed and running? (try `adb start-server`)",
            ),
            Self::Io(e) => write!(f, "{e}"),
            Self::Failed(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for AdbError {}

impl From<io::Error> for AdbError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

type Result<T> = std::result::Result<T, AdbError>;

/// One connection to the ADB server.
struct Conn {
    stream: TcpStream,
}

impl Conn {
    async fn open() -> Result<Self> {
        let (host, port) = server_addr();
        let stream = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(AdbError::NoServer)?;
        let _ = stream.set_nodelay(true);
        Ok(Self { stream })
    }

    /// Send a request and read the `OKAY`/`FAIL` status.
    async fn send(&mut self, request: &str) -> Result<()> {
        let framed = format!("{:04x}{request}", request.len());
        self.stream.write_all(framed.as_bytes()).await?;
        self.read_status().await
    }

    async fn read_status(&mut self) -> Result<()> {
        let mut status = [0u8; 4];
        self.stream.read_exact(&mut status).await?;
        match &status {
            b"OKAY" => Ok(()),
            b"FAIL" => Err(AdbError::Failed(self.read_message().await?)),
            other => Err(AdbError::Failed(format!(
                "unexpected ADB reply: {}",
                String::from_utf8_lossy(other)
            ))),
        }
    }

    /// Read a length-prefixed message (used for `FAIL` reasons and host replies).
    async fn read_message(&mut self) -> Result<String> {
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len).await?;
        let len = usize::from_str_radix(std::str::from_utf8(&len).unwrap_or("0"), 16).unwrap_or(0);
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    /// Read everything until the server closes the connection.
    async fn read_to_end(&mut self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.stream.read_to_end(&mut buf).await?;
        Ok(buf)
    }

    /// Switch this connection to a device's transport.
    async fn transport(&mut self, serial: &str) -> Result<()> {
        self.send(&format!("host:transport:{serial}")).await
    }
}

/// An attached device, as `host:devices-l` reports it.
#[derive(Debug, Clone)]
pub struct Listed {
    pub serial: String,
    /// `device`, `emulator`, `offline`, `unauthorized`, …
    pub state: String,
}

/// The ADB client. Cheap to clone; each call opens its own connection, as
/// adbkit does.
#[derive(Clone, Default)]
pub struct Adb {
    _private: (),
}

impl Adb {
    pub fn new() -> Self {
        Self::default()
    }

    /// `adb version` (the server's internal version number).
    pub async fn server_version(&self) -> Result<u32> {
        let mut conn = Conn::open().await?;
        conn.send("host:version").await?;
        let hex = conn.read_message().await?;
        Ok(u32::from_str_radix(hex.trim(), 16).unwrap_or(0))
    }

    /// Ensure the ADB server is running, starting it via the `adb` CLI if not.
    pub async fn ensure_server(&self) -> Result<()> {
        if self.server_version().await.is_ok() {
            return Ok(());
        }
        let _ = tokio::process::Command::new("adb")
            .arg("start-server")
            .output()
            .await;
        // Give it a moment to bind, then confirm.
        tokio::time::sleep(Duration::from_millis(300)).await;
        self.server_version().await.map(|_| ())
    }

    /// Attached devices and their states (`host:devices-l`).
    pub async fn list_devices(&self) -> Result<Vec<Listed>> {
        let mut conn = Conn::open().await?;
        conn.send("host:devices-l").await?;
        let text = conn.read_message().await?;
        Ok(text
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let serial = parts.next()?.to_owned();
                let state = parts.next().unwrap_or("unknown").to_owned();
                (!serial.is_empty()).then_some(Listed { serial, state })
            })
            .collect())
    }

    /// Connect to a device over TCP/IP (`host:connect:HOST:PORT`). Returns the
    /// server's response line.
    pub async fn connect(&self, host_port: &str) -> Result<String> {
        let mut conn = Conn::open().await?;
        conn.send(&format!("host:connect:{host_port}")).await?;
        conn.read_message().await
    }

    /// Run a shell command and return its combined output (shell v1: the raw
    /// byte stream until the device closes it).
    pub async fn shell(&self, serial: &str, command: &str) -> Result<String> {
        let mut conn = Conn::open().await?;
        conn.transport(serial).await?;
        conn.send(&format!("shell:{command}")).await?;
        let out = conn.read_to_end().await?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// Open a raw connection to a TCP port on the device (ADB `tcp:<port>`
    /// service). The returned stream is a direct pipe to the device port — used
    /// for the Frida control socket (frida-server on 27042).
    pub async fn open_tcp(&self, serial: &str, port: u16) -> Result<TcpStream> {
        let mut conn = Conn::open().await?;
        conn.transport(serial).await?;
        conn.send(&format!("tcp:{port}")).await?;
        Ok(conn.stream)
    }

    /// `getprop <prop>`, trimmed; `None` if empty.
    pub async fn getprop(&self, serial: &str, prop: &str) -> Result<Option<String>> {
        let out = self.shell(serial, &format!("getprop {prop}")).await?;
        let out = out.trim().to_owned();
        Ok((!out.is_empty()).then_some(out))
    }

    /// Open a reverse tunnel: the device's `tcp:remote` reaches the host's
    /// `tcp:local`.
    pub async fn reverse(&self, serial: &str, remote: u16, local: u16) -> Result<()> {
        let mut conn = Conn::open().await?;
        conn.transport(serial).await?;
        conn.send(&format!("reverse:forward:tcp:{remote};tcp:{local}"))
            .await?;
        // reverse replies with a second OKAY (or FAIL) after the first.
        conn.read_status().await
    }

    /// Remove a reverse tunnel.
    pub async fn remove_reverse(&self, serial: &str, remote: u16) -> Result<()> {
        let mut conn = Conn::open().await?;
        conn.transport(serial).await?;
        conn.send(&format!("reverse:killforward:tcp:{remote}"))
            .await?;
        conn.read_status().await
    }

    /// Push bytes to `remote_path` on the device via the sync protocol.
    pub async fn push_bytes(
        &self,
        serial: &str,
        data: &[u8],
        remote_path: &str,
        mode: u32,
    ) -> Result<()> {
        let mut conn = Conn::open().await?;
        conn.transport(serial).await?;
        conn.send("sync:").await?;
        sync::send(&mut conn.stream, data, remote_path, mode).await?;
        Ok(())
    }

    /// Pull a file off the device into memory via the sync protocol.
    pub async fn pull_bytes(&self, serial: &str, remote_path: &str) -> Result<Vec<u8>> {
        let mut conn = Conn::open().await?;
        conn.transport(serial).await?;
        conn.send("sync:").await?;
        sync::recv(&mut conn.stream, remote_path).await
    }
}

/// The ADB sync sub-protocol (little-endian framing), used for push/pull.
mod sync {
    use super::*;

    const MAX_CHUNK: usize = 64 * 1024;

    async fn write_le_u32(s: &mut TcpStream, v: u32) -> Result<()> {
        s.write_all(&v.to_le_bytes()).await?;
        Ok(())
    }

    async fn read_id(s: &mut TcpStream) -> Result<([u8; 4], u32)> {
        let mut id = [0u8; 4];
        s.read_exact(&mut id).await?;
        let mut len = [0u8; 4];
        s.read_exact(&mut len).await?;
        Ok((id, u32::from_le_bytes(len)))
    }

    /// SEND: `path,mode` header, then DATA chunks, then DONE(mtime).
    pub async fn send(s: &mut TcpStream, data: &[u8], path: &str, mode: u32) -> Result<()> {
        let header = format!("{path},{mode}");
        s.write_all(b"SEND").await?;
        write_le_u32(s, header.len() as u32).await?;
        s.write_all(header.as_bytes()).await?;

        for chunk in data.chunks(MAX_CHUNK) {
            s.write_all(b"DATA").await?;
            write_le_u32(s, chunk.len() as u32).await?;
            s.write_all(chunk).await?;
        }
        let mtime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        s.write_all(b"DONE").await?;
        write_le_u32(s, mtime).await?;

        let (id, len) = read_id(s).await?;
        match &id {
            b"OKAY" => Ok(()),
            b"FAIL" => {
                let mut buf = vec![0u8; len as usize];
                s.read_exact(&mut buf).await?;
                Err(AdbError::Failed(String::from_utf8_lossy(&buf).into_owned()))
            }
            other => Err(AdbError::Failed(format!(
                "unexpected sync reply: {}",
                String::from_utf8_lossy(other)
            ))),
        }
    }

    /// RECV: `path` header, then DATA chunks until DONE.
    pub async fn recv(s: &mut TcpStream, path: &str) -> Result<Vec<u8>> {
        s.write_all(b"RECV").await?;
        write_le_u32(s, path.len() as u32).await?;
        s.write_all(path.as_bytes()).await?;

        let mut out = Vec::new();
        loop {
            let (id, len) = read_id(s).await?;
            match &id {
                b"DATA" => {
                    let mut buf = vec![0u8; len as usize];
                    s.read_exact(&mut buf).await?;
                    out.extend_from_slice(&buf);
                }
                b"DONE" => return Ok(out),
                b"FAIL" => {
                    let mut buf = vec![0u8; len as usize];
                    s.read_exact(&mut buf).await?;
                    return Err(AdbError::Failed(String::from_utf8_lossy(&buf).into_owned()));
                }
                other => {
                    return Err(AdbError::Failed(format!(
                        "unexpected sync reply: {}",
                        String::from_utf8_lossy(other)
                    )));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_requests_with_a_hex_length() {
        // The wire form is "<4-hex-len><request>".
        assert_eq!(
            format!("{:04x}{}", "host:version".len(), "host:version"),
            "000chost:version"
        );
    }

    #[tokio::test]
    async fn talks_to_a_real_server_if_one_is_running() {
        // Not a failure when no ADB server / devices are present on the box;
        // this just exercises the path when they are.
        let adb = Adb::new();
        if let Ok(v) = adb.server_version().await {
            assert!(v > 0);
            let _ = adb.list_devices().await.unwrap();
        }
    }
}
