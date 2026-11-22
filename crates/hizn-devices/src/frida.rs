//! Frida support: provision `frida-server` on a device (download the right-ABI
//! build from GitHub, decompress, push, start as root). Mirrors the Node
//! `FridaService.provisionServer`.
//!
//! The injection half (CA + unpinning via the Frida control protocol) is the
//! Frida follow-up; provisioning is the piece that gets a working server onto
//! a rooted device.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::adb::{Adb, AdbError};
use crate::dbus::{self, Value};

/// On-device path where frida-server is staged and run.
const DEVICE_FRIDA_PATH: &str = "/data/local/tmp/frida-server";

/// frida-server's default control port on the device.
pub const FRIDA_DEFAULT_PORT: u16 = 27042;

/// Frida API versions this client speaks, newest first (as frida-js).
const API_VERSIONS: &[&str] = &["17", "16"];

/// Map an Android ABI (`ro.product.cpu.abi`) to a Frida download arch.
pub fn abi_to_frida_arch(abi: &str) -> &'static str {
    if abi.contains("arm64") {
        "arm64"
    } else if abi.contains("armeabi") || abi == "armeabi-v7a" {
        "arm"
    } else if abi == "x86_64" {
        "x86_64"
    } else {
        "x86"
    }
}

#[derive(Debug)]
pub enum FridaError {
    Adb(AdbError),
    Download(String),
    Decompress(String),
    Protocol(String),
}

impl std::fmt::Display for FridaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Adb(e) => write!(f, "{e}"),
            Self::Download(m) => write!(f, "Download failed: {m}"),
            Self::Decompress(m) => write!(f, "Decompress failed: {m}"),
            Self::Protocol(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for FridaError {}

impl From<AdbError> for FridaError {
    fn from(e: AdbError) -> Self {
        Self::Adb(e)
    }
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// What a provision run produced.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Provisioned {
    pub version: String,
    pub arch: String,
}

/// Download, push and start frida-server for `abi`'s architecture (requires
/// root to actually run). `version` is a release tag or "latest".
pub async fn provision_server(
    adb: &Adb,
    serial: &str,
    abi: &str,
    version: &str,
) -> Result<Provisioned, FridaError> {
    let arch = abi_to_frida_arch(abi);
    let client = reqwest::Client::builder()
        .user_agent("hizn")
        .build()
        .map_err(|e| FridaError::Download(e.to_string()))?;

    // 1. Resolve the release + find the android-<arch> asset.
    let api = if version.is_empty() || version == "latest" {
        "https://api.github.com/repos/frida/frida/releases/latest".to_owned()
    } else {
        format!("https://api.github.com/repos/frida/frida/releases/tags/{version}")
    };
    let release: Release = client
        .get(&api)
        .send()
        .await
        .map_err(|e| FridaError::Download(e.to_string()))?
        .error_for_status()
        .map_err(|e| FridaError::Download(e.to_string()))?
        .json()
        .await
        .map_err(|e| FridaError::Download(e.to_string()))?;

    let suffix = format!("-android-{arch}.xz");
    let asset = release
        .assets
        .iter()
        .find(|a| a.name.starts_with("frida-server-") && a.name.ends_with(&suffix))
        .ok_or_else(|| {
            FridaError::Download(format!(
                "no frida-server for android {arch} in {}",
                release.tag_name
            ))
        })?;

    // 2. Download the .xz and decompress it to the server binary.
    let xz = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .map_err(|e| FridaError::Download(e.to_string()))?
        .error_for_status()
        .map_err(|e| FridaError::Download(e.to_string()))?
        .bytes()
        .await
        .map_err(|e| FridaError::Download(e.to_string()))?;

    let binary = tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        lzma_rs::xz_decompress(&mut std::io::Cursor::new(&xz), &mut out).map(|_| out)
    })
    .await
    .map_err(|e| FridaError::Decompress(e.to_string()))?
    .map_err(|e| FridaError::Decompress(e.to_string()))?;

    // 3. Push, make executable, start detached as root (replacing any stale one).
    adb.push_bytes(serial, &binary, DEVICE_FRIDA_PATH, 0o755)
        .await?;
    adb.shell(serial, &format!("chmod 755 {DEVICE_FRIDA_PATH}"))
        .await?;
    adb.shell(serial, "su -c \"killall frida-server 2>/dev/null || true\"")
        .await?;
    adb.shell(
        serial,
        &format!("su -c \"nohup {DEVICE_FRIDA_PATH} >/dev/null 2>&1 &\""),
    )
    .await?;

    Ok(Provisioned {
        version: release.tag_name,
        arch: arch.to_owned(),
    })
}

// ---------------------------------------------------------------- injection

/// Options for a Frida injection.
pub struct InjectOptions {
    pub serial: String,
    /// The full payload (config prelude + the scripts/frida hooks), already built.
    pub payload: String,
    /// App id to spawn (true) or attach to (false).
    pub target: String,
    pub spawn: bool,
    pub frida_port: u16,
}

/// A live D-Bus connection to frida-server over the ADB tunnel.
struct FridaConn<S> {
    ws: tokio_tungstenite::WebSocketStream<S>,
    buf: Vec<u8>,
    serial: u32,
    version: &'static str,
}

impl<S: AsyncRead + AsyncWrite + Unpin> FridaConn<S> {
    async fn connect(stream: S) -> Result<Self, FridaError> {
        let req = "ws://127.0.0.1/ws"
            .into_client_request()
            .map_err(|e| FridaError::Protocol(e.to_string()))?;
        let (ws, _) = tokio_tungstenite::client_async(req, stream)
            .await
            .map_err(|e| FridaError::Protocol(format!("frida WebSocket handshake failed: {e}")))?;
        let mut conn = Self {
            ws,
            buf: Vec::new(),
            serial: 0,
            version: "17",
        };
        conn.version = conn.detect_version().await?;
        Ok(conn)
    }

    /// Introspect `/re/frida/HostSession` and pick the `re.frida.HostSessionNN`
    /// the server exposes.
    async fn detect_version(&mut self) -> Result<&'static str, FridaError> {
        let reply = self
            .call(
                "re.frida.HostSession",
                "/re/frida/HostSession",
                "org.freedesktop.DBus.Introspectable",
                "Introspect",
                "",
                &[],
            )
            .await?;
        let xml = reply.body_str().unwrap_or_default();
        for v in API_VERSIONS {
            if xml.contains(&format!("re.frida.HostSession{v}")) {
                return Ok(v);
            }
        }
        Err(FridaError::Protocol(
            "unsupported frida-server API version".into(),
        ))
    }

    fn host_dest(&self) -> String {
        format!("re.frida.HostSession{}", self.version)
    }
    fn agent_dest(&self) -> String {
        format!("re.frida.AgentSession{}", self.version)
    }

    async fn call(
        &mut self,
        dest: &str,
        path: &str,
        iface: &str,
        member: &str,
        sig: &str,
        args: &[Value],
    ) -> Result<dbus::Reply, FridaError> {
        self.serial += 1;
        let serial = self.serial;
        let msg = dbus::method_call(serial, dest, path, iface, member, sig, args);
        self.ws
            .send(Message::Binary(msg))
            .await
            .map_err(|e| FridaError::Protocol(e.to_string()))?;
        loop {
            while let Some(len) = dbus::message_length(&self.buf) {
                if self.buf.len() < len {
                    break;
                }
                let frame: Vec<u8> = self.buf.drain(..len).collect();
                if let Some(reply) = dbus::parse(&frame)
                    && reply.reply_serial == serial
                {
                    if reply.msg_type == dbus::MSG_ERROR {
                        return Err(FridaError::Protocol(reply.error_message()));
                    }
                    return Ok(reply);
                }
            }
            match self.ws.next().await {
                Some(Ok(Message::Binary(b))) => self.buf.extend_from_slice(&b),
                Some(Ok(Message::Close(_))) | None => {
                    return Err(FridaError::Protocol(
                        "frida-server closed the connection".into(),
                    ));
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(FridaError::Protocol(e.to_string())),
            }
        }
    }

    /// Spawn the app paused → pid.
    async fn spawn(&mut self, program: &str) -> Result<u32, FridaError> {
        // options struct (basbasbassia{sv}): no argv/envp/env, empty cwd, stdio 0.
        let options = Value::Struct(vec![
            Value::Bool(false),
            Value::Array("s", vec![]),
            Value::Bool(false),
            Value::Array("s", vec![]),
            Value::Bool(false),
            Value::Array("s", vec![]),
            Value::Str(String::new()),
            Value::Str(String::new()),
            Value::I32(0),
            Value::EmptyDict,
        ]);
        let dest = self.host_dest();
        let reply = self
            .call(
                &dest,
                "/re/frida/HostSession",
                &dest,
                "Spawn",
                "s(basbasbassia{sv})",
                &[Value::Str(program.to_owned()), options],
            )
            .await?;
        reply
            .body_u32()
            .ok_or_else(|| FridaError::Protocol("Spawn returned no pid".into()))
    }

    /// Attach to a pid → session id string.
    async fn attach(&mut self, pid: u32) -> Result<String, FridaError> {
        let dest = self.host_dest();
        let reply = self
            .call(
                &dest,
                "/re/frida/HostSession",
                &dest,
                "Attach",
                "ua{sv}",
                &[Value::U32(pid), Value::EmptyDict],
            )
            .await?;
        reply
            .body_str()
            .ok_or_else(|| FridaError::Protocol("Attach returned no session".into()))
    }

    async fn create_script(&mut self, session_id: &str, source: &str) -> Result<u32, FridaError> {
        let dest = self.agent_dest();
        let path = format!("/re/frida/AgentSession/{session_id}");
        let reply = self
            .call(
                &dest,
                &path,
                &dest,
                "CreateScript",
                "sa{sv}",
                &[Value::Str(source.to_owned()), Value::EmptyDict],
            )
            .await?;
        reply
            .body_u32()
            .ok_or_else(|| FridaError::Protocol("CreateScript returned no id".into()))
    }

    async fn load_script(&mut self, session_id: &str, script_id: u32) -> Result<(), FridaError> {
        let dest = self.agent_dest();
        let path = format!("/re/frida/AgentSession/{session_id}");
        self.call(
            &dest,
            &path,
            &dest,
            "LoadScript",
            "(u)",
            &[Value::Struct(vec![Value::U32(script_id)])],
        )
        .await?;
        Ok(())
    }

    async fn resume(&mut self, pid: u32) -> Result<(), FridaError> {
        let dest = self.host_dest();
        self.call(
            &dest,
            "/re/frida/HostSession",
            &dest,
            "Resume",
            "u",
            &[Value::U32(pid)],
        )
        .await?;
        Ok(())
    }
}

/// Live Frida sessions, keyed `serial:pid`. A session must stay connected or
/// its injected scripts unload, so each holds its connection task alive until
/// dropped.
#[derive(Clone, Default)]
pub struct FridaSessions {
    inner: Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
}

impl FridaSessions {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&self, serial: &str, pid: u32, task: tokio::task::JoinHandle<()>) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(format!("{serial}:{pid}"), task);
    }

    /// Drop a session (aborts its connection task, unloading the scripts).
    pub fn detach(&self, serial: &str, pid: u32) {
        if let Some(task) = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&format!("{serial}:{pid}"))
        {
            task.abort();
        }
    }
}

/// Inject the payload into the target app via frida-server (over the ADB
/// tunnel). Returns the target pid. The connection is kept alive in a
/// background task tracked by `sessions`.
pub async fn inject(
    adb: &Adb,
    sessions: &FridaSessions,
    opts: InjectOptions,
) -> Result<u32, FridaError> {
    let stream = adb.open_tcp(&opts.serial, opts.frida_port).await?;
    let mut conn = FridaConn::connect(stream).await?;

    let pid;
    if opts.spawn {
        pid = conn.spawn(&opts.target).await?;
        let session = conn.attach(pid).await?;
        let script = conn.create_script(&session, &opts.payload).await?;
        conn.load_script(&session, script).await?;
        conn.resume(pid).await?;
    } else {
        return Err(FridaError::Protocol(
            "attach-to-running is not supported yet".into(),
        ));
    }

    // Hold the connection open so the script stays loaded (reads and discards
    // any further frames until the session is detached).
    let task = tokio::spawn(async move {
        while let Some(Ok(msg)) = conn.ws.next().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
        }
    });
    sessions.insert(&opts.serial, pid, task);
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_mapping_matches_node() {
        assert_eq!(abi_to_frida_arch("arm64-v8a"), "arm64");
        assert_eq!(abi_to_frida_arch("armeabi-v7a"), "arm");
        assert_eq!(abi_to_frida_arch("x86_64"), "x86_64");
        assert_eq!(abi_to_frida_arch("x86"), "x86");
    }
}
