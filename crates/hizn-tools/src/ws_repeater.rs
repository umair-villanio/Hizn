//! WebSocket Repeater: open a live ws:// / wss:// connection to a target, fire
//! arbitrary frames at it by hand, and stream every frame (sent and received).
//! Mirrors the Node `WsRepeaterService`.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_tungstenite::Connector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

/// Cap each frame relayed to the UI.
const MAX_WS_FRAME: usize = 256 * 1024;
/// Guard against runaway session count.
const MAX_SESSIONS: usize = 32;

/// Events, broadcast by the server as `ws-repeater-open` / `-message` /
/// `-close` / `-error`. Each carries the session `id`.
#[derive(Debug, Clone)]
pub enum WsRepeaterEvent {
    Open(Value),
    Message(Value),
    Close(Value),
    Error(Value),
}

pub type WsRepeaterSink = Arc<dyn Fn(WsRepeaterEvent) + Send + Sync>;

enum Command {
    Send { data: String, is_binary: bool },
    Close,
}

struct Session {
    tx: mpsc::UnboundedSender<Command>,
}

type Sessions = Arc<Mutex<HashMap<String, Session>>>;

pub struct WsRepeater {
    sessions: Sessions,
    emit: WsRepeaterSink,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl WsRepeater {
    pub fn new(emit: WsRepeaterSink) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            emit,
        }
    }

    /// Open a session. Returns its id, or an error for a bad URL / too many
    /// sessions (the validation the Node route surfaced as a 400).
    pub fn open(
        &self,
        url: &str,
        headers: Option<&Value>,
        insecure: bool,
    ) -> Result<String, String> {
        let parsed = url::Url::parse(url).map_err(|_| format!("Invalid URL: {url}"))?;
        if parsed.scheme() != "ws" && parsed.scheme() != "wss" {
            return Err("URL must start with ws:// or wss://".into());
        }
        let mut sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        if sessions.len() >= MAX_SESSIONS {
            return Err("Too many open WebSocket sessions — close one first".into());
        }

        let id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = mpsc::unbounded_channel();
        sessions.insert(id.clone(), Session { tx });
        drop(sessions);

        let extra_headers = collect_headers(headers);
        let emit = self.emit.clone();
        let url = url.to_owned();
        let task_id = id.clone();
        let sessions = self.sessions.clone();
        tokio::spawn(run_session(
            task_id,
            url,
            extra_headers,
            insecure,
            rx,
            emit,
            sessions,
        ));

        Ok(id)
    }

    /// Send a frame on an open session. `is_binary` treats `data` as base64.
    pub fn send(&self, id: &str, data: String, is_binary: bool) -> Result<(), String> {
        let sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        let session = sessions
            .get(id)
            .ok_or_else(|| format!("No such WebSocket session: {id}"))?;
        session
            .tx
            .send(Command::Send { data, is_binary })
            .map_err(|_| "WebSocket is not open".to_owned())
    }

    /// Close a session (normal closure).
    pub fn close(&self, id: &str) {
        let sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(session) = sessions.get(id) {
            let _ = session.tx.send(Command::Close);
        }
    }
}

fn collect_headers(headers: Option<&Value>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(Value::Object(map)) = headers {
        for (k, v) in map {
            let lower = k.to_ascii_lowercase();
            // tungstenite sets these itself.
            if matches!(
                lower.as_str(),
                "connection" | "upgrade" | "sec-websocket-key" | "sec-websocket-version" | "host"
            ) {
                continue;
            }
            match v {
                Value::String(s) => out.push((k.clone(), s.clone())),
                Value::Array(list) => {
                    for item in list {
                        if let Some(s) = item.as_str() {
                            out.push((k.clone(), s.to_owned()));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out
}

fn insecure_tls() -> rustls::ClientConfig {
    #[derive(Debug)]
    struct NoVerify;
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports default versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth()
}

async fn run_session(
    id: String,
    url: String,
    headers: Vec<(String, String)>,
    insecure: bool,
    mut rx: mpsc::UnboundedReceiver<Command>,
    emit: WsRepeaterSink,
    sessions: Sessions,
) {
    let deregister = || {
        sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id);
    };
    let mut request = match url.as_str().into_client_request() {
        Ok(r) => r,
        Err(e) => {
            emit(WsRepeaterEvent::Error(
                json!({ "id": id, "message": e.to_string(), "at": now_ms() }),
            ));
            deregister();
            return;
        }
    };
    for (k, v) in headers {
        if let (Ok(name), Ok(value)) = (
            tokio_tungstenite::tungstenite::http::HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(&v),
        ) {
            request.headers_mut().append(name, value);
        }
    }

    let connector = insecure.then(|| Connector::Rustls(Arc::new(insecure_tls())));
    let connect =
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, connector).await;
    let ws = match connect {
        Ok((ws, _)) => ws,
        Err(e) => {
            emit(WsRepeaterEvent::Error(
                json!({ "id": id, "message": e.to_string(), "at": now_ms() }),
            ));
            deregister();
            return;
        }
    };
    emit(WsRepeaterEvent::Open(json!({ "id": id, "url": url })));

    let (mut sink, mut stream) = ws.split();
    loop {
        tokio::select! {
            cmd = rx.recv() => match cmd {
                Some(Command::Send { data, is_binary }) => {
                    let (msg, size) = if is_binary {
                        match B64.decode(data.as_bytes()) {
                            Ok(bytes) => { let n = bytes.len(); (Message::Binary(bytes), n) }
                            Err(e) => { emit(WsRepeaterEvent::Error(json!({ "id": id, "message": e.to_string(), "at": now_ms() }))); continue; }
                        }
                    } else {
                        (Message::Text(data.clone()), data.len())
                    };
                    match sink.send(msg).await {
                        Ok(()) => emit(WsRepeaterEvent::Message(json!({
                            "id": id, "dir": "outgoing", "text": data, "isBinary": is_binary, "size": size, "at": now_ms(),
                        }))),
                        Err(e) => emit(WsRepeaterEvent::Error(json!({ "id": id, "message": e.to_string(), "at": now_ms() }))),
                    }
                }
                Some(Command::Close) | None => {
                    use tokio_tungstenite::tungstenite::protocol::{frame::coding::CloseCode, CloseFrame};
                    let _ = sink.send(Message::Close(Some(CloseFrame { code: CloseCode::Normal, reason: "".into() }))).await;
                    // A client-initiated close fires a close event (code 1000),
                    // like the ws library's `close` handler.
                    emit(WsRepeaterEvent::Close(json!({ "id": id, "code": 1000, "reason": "", "at": now_ms() })));
                    break;
                }
            },
            frame = stream.next() => match frame {
                Some(Ok(Message::Text(text))) => emit(WsRepeaterEvent::Message(json!({
                    "id": id, "dir": "incoming",
                    "text": cap_text(text.as_bytes(), false), "isBinary": false, "size": text.len(), "at": now_ms(),
                }))),
                Some(Ok(Message::Binary(bytes))) => emit(WsRepeaterEvent::Message(json!({
                    "id": id, "dir": "incoming",
                    "text": cap_text(&bytes, true), "isBinary": true, "size": bytes.len(), "at": now_ms(),
                }))),
                Some(Ok(Message::Close(frame))) => {
                    let (code, reason) = frame.map(|f| (u16::from(f.code), f.reason.to_string())).unwrap_or((1005, String::new()));
                    emit(WsRepeaterEvent::Close(json!({ "id": id, "code": code, "reason": reason, "at": now_ms() })));
                    break;
                }
                Some(Ok(_)) => {} // ping/pong/frame — tungstenite auto-handles pings
                Some(Err(e)) => { emit(WsRepeaterEvent::Error(json!({ "id": id, "message": e.to_string(), "at": now_ms() }))); break; }
                None => break,
            },
        }
    }
    deregister();
}

/// Cap a frame to [`MAX_WS_FRAME`]: base64 for binary, UTF-8 (lossy) for text.
fn cap_text(bytes: &[u8], is_binary: bool) -> String {
    let slice = &bytes[..bytes.len().min(MAX_WS_FRAME)];
    if is_binary {
        B64.encode(slice)
    } else {
        String::from_utf8_lossy(slice).into_owned()
    }
}
