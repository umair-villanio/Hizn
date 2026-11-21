//! Shared server state and the WebSocket client hub.
//!
//! Everything the UI can observe lives behind one mutex. That mirrors the Node
//! server's single-threaded event loop: a store update and its broadcast (or a
//! new client's hello snapshot and its registration) can never interleave, so a
//! client never misses or double-receives an event around connect time.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::extract::ws::Utf8Bytes;
use hizn_devices::{Adb, Devices, Orchestrator};
use hizn_proxy::{CaError, CertAuthority, ProxyEngine, ProxyEvent, hizn_dir};
use indexmap::{IndexMap, IndexSet};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// Server-side flow log cap; the oldest flow is dropped past this.
pub const MAX_FLOWS: usize = 5000;
/// Per-flow cap on stored WebSocket frames (newest kept).
pub const MAX_WS_MESSAGES: usize = 2000;
/// Default proxy listen port.
pub const DEFAULT_PROXY_PORT: u16 = 8000;

/// Upstream proxy chaining (e.g. Burp Suite).
#[derive(Clone, Debug, Serialize)]
pub struct UpstreamConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        // Burp's default listener.
        Self {
            enabled: false,
            host: "127.0.0.1".into(),
            port: 8080,
        }
    }
}

/// Burp-style intercept switches as the engine reports them (raw JSON: a
/// switch posted as missing is absent, exactly as Node showed it).
pub type InterceptConfig = Map<String, Value>;

fn default_intercept() -> InterceptConfig {
    let mut m = Map::new();
    m.insert("enabled".into(), json!(false));
    m.insert("requests".into(), json!(true));
    m.insert("responses".into(), json!(false));
    m
}

/// `GET /status` and the `proxy-status` event payload.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatus {
    pub running: bool,
    pub port: u16,
    pub upstream: UpstreamConfig,
    pub intercept: InterceptConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_fingerprint: Option<String>,
}

/// All UI-observable state plus the connected WebSocket clients.
pub struct Hub {
    next_client: u64,
    clients: HashMap<u64, UnboundedSender<Utf8Bytes>>,

    pub running: bool,
    pub proxy_port: u16,
    /// The port this API + UI server listens on (for `/mcp/info`'s apiUrl).
    pub api_port: u16,
    pub upstream: UpstreamConfig,
    /// Mirrors of the engine's state, kept current from its events.
    pub intercept: InterceptConfig,
    pub scope: Value,
    pub ca_fingerprint: Option<String>,
    /// Serials hizn has actively routed (one-click connected), in insertion order.
    pub connected: IndexSet<String>,
    /// Server-side flow log so history survives UI reconnects (insertion order).
    pub flows: IndexMap<String, Value>,
    /// Currently-held intercept items, keyed by intercept id.
    pub pending: IndexMap<String, Value>,
}

impl Default for Hub {
    fn default() -> Self {
        Self {
            next_client: 0,
            clients: HashMap::new(),
            running: false,
            proxy_port: DEFAULT_PROXY_PORT,
            api_port: 4000,
            upstream: UpstreamConfig::default(),
            intercept: default_intercept(),
            scope: json!({ "enabled": false, "hosts": [] }),
            ca_fingerprint: None,
            connected: IndexSet::new(),
            flows: IndexMap::new(),
            pending: IndexMap::new(),
        }
    }
}

/// Borrowing view of the flow log, so a snapshot doesn't clone every flow.
#[derive(Serialize)]
struct FlowSnapshot<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    flows: Vec<&'a Value>,
}

impl Hub {
    pub fn status(&self) -> ProxyStatus {
        ProxyStatus {
            running: self.running,
            port: self.proxy_port,
            upstream: self.upstream.clone(),
            intercept: self.intercept.clone(),
            ca_fingerprint: self.ca_fingerprint.clone(),
        }
    }

    /// Broadcast the current connected-device list.
    pub fn broadcast_connections(&mut self) {
        let connected: Vec<String> = self.connected.iter().cloned().collect();
        self.broadcast(&json!({ "type": "connections", "connected": connected }));
    }

    /// Send one event to every open client, dropping clients that have gone away.
    pub fn broadcast(&mut self, msg: &impl Serialize) {
        let Ok(text) = serde_json::to_string(msg) else {
            return;
        };
        let text = Utf8Bytes::from(text);
        self.clients.retain(|_, tx| tx.send(text.clone()).is_ok());
    }

    /// Register a client. Its hello snapshot is queued before it can receive
    /// any broadcast, in the same effective order the Node server produces.
    pub fn add_client(&mut self) -> (u64, UnboundedReceiver<Utf8Bytes>) {
        let (tx, rx) = unbounded_channel();
        for msg in self.hello() {
            let _ = tx.send(msg);
        }
        let id = self.next_client;
        self.next_client += 1;
        self.clients.insert(id, tx);
        (id, rx)
    }

    pub fn remove_client(&mut self, id: u64) {
        self.clients.remove(&id);
    }

    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Node sends these synchronously on connect, except `proxy-status`, which
    /// resolves asynchronously and therefore arrives last.
    fn hello(&self) -> Vec<Utf8Bytes> {
        let mut out = Vec::with_capacity(5 + self.pending.len());
        let mut push = |s: serde_json::Result<String>| {
            if let Ok(s) = s {
                out.push(Utf8Bytes::from(s));
            }
        };
        push(serde_json::to_string(
            &json!({ "type": "intercept-config", "config": self.intercept }),
        ));
        push(serde_json::to_string(
            &json!({ "type": "connections", "connected": self.connected }),
        ));
        push(serde_json::to_string(
            &json!({ "type": "scope", "scope": self.scope }),
        ));
        push(serde_json::to_string(&FlowSnapshot {
            kind: "flow-snapshot",
            flows: self.flows.values().collect(),
        }));
        for item in self.pending.values() {
            push(serde_json::to_string(
                &json!({ "type": "intercept", "item": item }),
            ));
        }
        push(serde_json::to_string(
            &json!({ "type": "proxy-status", "status": self.status() }),
        ));
        out
    }

    /// Store a new flow (dropping the oldest past [`MAX_FLOWS`]) and stream it.
    pub fn add_flow(&mut self, flow: Value) {
        if let Some(id) = flow.get("id").and_then(Value::as_str) {
            self.flows.insert(id.to_owned(), flow.clone());
            if self.flows.len() > MAX_FLOWS {
                self.flows.shift_remove_index(0);
            }
        }
        self.broadcast(&json!({ "type": "flow", "flow": flow }));
    }

    /// Merge an update into its flow (`Object.assign`) and stream it.
    pub fn update_flow(&mut self, update: Value) {
        if let (Some(id), Value::Object(fields)) =
            (update.get("id").and_then(Value::as_str), &update)
            && let Some(Value::Object(existing)) = self.flows.get_mut(id)
        {
            for (k, v) in fields {
                existing.insert(k.clone(), v.clone());
            }
        }
        self.broadcast(&json!({ "type": "flow-update", "update": update }));
    }

    /// Store a WebSocket message on its flow (newest [`MAX_WS_MESSAGES`] kept)
    /// so history survives a UI reconnect, then stream it.
    pub fn add_ws_message(&mut self, msg: Value) {
        if let Some(id) = msg.get("id").and_then(Value::as_str)
            && let Some(Value::Object(flow)) = self.flows.get_mut(id)
        {
            let list = flow
                .entry("wsMessages")
                .or_insert_with(|| Value::Array(Vec::new()));
            if !list.is_array() {
                *list = Value::Array(Vec::new());
            }
            if let Value::Array(list) = list {
                list.push(msg.clone());
                if list.len() > MAX_WS_MESSAGES {
                    list.remove(0);
                }
            }
        }
        self.broadcast(&json!({ "type": "ws-message", "msg": msg }));
    }

    /// Mirror one engine event and pass it on to the UI, as the Node server's
    /// `wireProxyEvents` did.
    pub fn on_proxy_event(&mut self, event: ProxyEvent) {
        match event {
            ProxyEvent::Flow(flow) => self.add_flow(flow),
            ProxyEvent::FlowUpdate(update) => self.update_flow(update),
            ProxyEvent::WsMessage(msg) => self.add_ws_message(msg),
            ProxyEvent::Intercept(item) => {
                if let Some(id) = item.get("id").and_then(Value::as_str) {
                    self.pending.insert(id.to_owned(), item.clone());
                }
                self.broadcast(&json!({ "type": "intercept", "item": item }));
            }
            ProxyEvent::InterceptClosed(id) => {
                self.pending.shift_remove(&id);
                self.broadcast(&json!({ "type": "intercept-closed", "ref": { "id": id } }));
            }
            ProxyEvent::InterceptConfig(config) => {
                self.intercept = config;
                self.broadcast(&json!({ "type": "intercept-config", "config": self.intercept }));
            }
            ProxyEvent::Scope(scope) => {
                self.scope = scope;
                self.broadcast(&json!({ "type": "scope", "scope": self.scope }));
            }
        }
    }

    /// Replace the whole flow log (session import) and push it to everyone.
    pub fn replace_flows(&mut self, flows: Vec<Value>) -> usize {
        self.flows.clear();
        for flow in flows {
            // Same filter as Node: an object with a truthy `id`.
            let id = match flow.get("id") {
                Some(Value::String(s)) if !s.is_empty() => s.clone(),
                Some(Value::Number(n)) if n.as_f64() != Some(0.0) => n.to_string(),
                _ => continue,
            };
            self.flows.insert(id, flow);
        }
        let snapshot = FlowSnapshot {
            kind: "flow-snapshot",
            flows: self.flows.values().collect(),
        };
        if let Ok(text) = serde_json::to_string(&snapshot) {
            let text = Utf8Bytes::from(text);
            self.clients.retain(|_, tx| tx.send(text.clone()).is_ok());
        }
        self.flows.len()
    }
}

/// Cheap-to-clone handle to the shared state.
#[derive(Clone)]
pub struct AppState {
    hub: Arc<Mutex<Hub>>,
    /// The interception engine.
    pub proxy: Arc<ProxyEngine>,
    /// The root CA, loaded on first use (like Node's lazy `getCA()`).
    ca: Arc<Mutex<Option<Arc<CertAuthority>>>>,
    /// ADB + the one-click setup flow.
    pub orchestrator: Arc<Orchestrator>,
    /// Repeater (re-send a request).
    pub repeater: Arc<hizn_tools::Repeater>,
    /// Intruder (fuzz a request); streams over the WebSocket.
    pub intruder: Arc<hizn_tools::Intruder>,
    /// Intruder event sink → broadcast as intruder-start / row / done.
    pub intruder_sink: hizn_tools::IntruderSink,
    /// File-backed plugin store.
    pub plugins: Arc<crate::plugins::Plugins>,
    /// WebSocket Repeater (live frame replay).
    pub ws_repeater: Arc<hizn_tools::WsRepeater>,
    /// Desktop browser capture (Firefox).
    pub desktop: Arc<crate::desktop::Desktop>,
}

impl AppState {
    /// Mark a device connected (one-click routed) and broadcast `connections`.
    pub fn mark_connected(&self, serial: &str) {
        let mut hub = self.hub();
        hub.connected.insert(serial.to_owned());
        hub.broadcast_connections();
    }

    pub fn mark_disconnected(&self, serial: &str) {
        let mut hub = self.hub();
        hub.connected.shift_remove(serial);
        hub.broadcast_connections();
    }

    pub fn connected(&self) -> Vec<String> {
        self.hub().connected.iter().cloned().collect()
    }

    /// Broadcast a `setup-step` to every client (the orchestrator's step sink).
    pub fn broadcast_step(&self, step: &hizn_devices::SetupStep) {
        self.hub().broadcast(&hizn_devices::step_event(step));
    }

    /// Record the API server's listen port (for `/mcp/info`).
    pub fn set_api_port(&self, port: u16) {
        self.hub().api_port = port;
    }
}

/// Bridges the orchestrator to the proxy engine + CA (its `ProxyControl`).
pub struct ProxyBridge {
    pub proxy: Arc<ProxyEngine>,
    pub ca: Arc<Mutex<Option<Arc<CertAuthority>>>>,
    pub hub: Arc<Mutex<Hub>>,
}

impl hizn_devices::ProxyControl for ProxyBridge {
    fn start(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(u16, String), String>> + Send + '_>,
    > {
        Box::pin(async move {
            let port = self
                .hub
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .proxy_port;
            let ca = self.ca_arc().map_err(|e| e.to_string())?;
            self.proxy
                .start(port, ca)
                .await
                .map_err(|e| e.to_string())?;
            let upstream = self
                .hub
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .upstream
                .clone();
            {
                let mut hub = self.hub.lock().unwrap_or_else(|p| p.into_inner());
                hub.running = true;
                let status = hub.status();
                hub.broadcast(&json!({ "type": "proxy-status", "status": status }));
            }
            let detail = if upstream.enabled {
                format!(
                    "Listening :{port} → Burp {}:{}",
                    upstream.host, upstream.port
                )
            } else {
                format!("Listening :{port}")
            };
            Ok((port, detail))
        })
    }

    fn ca_pem(&self) -> Result<String, String> {
        self.ca_arc()
            .map(|ca| ca.cert_pem().to_owned())
            .map_err(|e| e.to_string())
    }

    fn port(&self) -> u16 {
        self.hub
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .proxy_port
    }
}

impl ProxyBridge {
    fn ca_arc(&self) -> Result<Arc<CertAuthority>, CaError> {
        let mut slot = self.ca.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ca) = slot.as_ref() {
            return Ok(ca.clone());
        }
        let dir = std::env::var_os("HIZN_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(hizn_dir);
        let ca = Arc::new(CertAuthority::load_or_create(&dir)?);
        self.hub
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .ca_fingerprint = Some(ca.fingerprint().to_owned());
        *slot = Some(ca.clone());
        Ok(ca)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        let hub = Arc::new(Mutex::new(Hub::default()));
        let events_hub = hub.clone();
        let proxy = Arc::new(ProxyEngine::new(Arc::new(move |event| {
            let mut hub = events_hub.lock().unwrap_or_else(|p| p.into_inner());
            hub.on_proxy_event(event);
        })));
        let orchestrator = Arc::new(Orchestrator::new(Devices::new(Adb::new())));
        let ws_hub = hub.clone();
        let ws_rep_sink: hizn_tools::WsRepeaterSink = Arc::new(move |event| {
            // Node spread the event into the message: `{ type, ...event }`.
            let (kind, mut value) = match event {
                hizn_tools::WsRepeaterEvent::Open(e) => ("ws-repeater-open", e),
                hizn_tools::WsRepeaterEvent::Message(e) => ("ws-repeater-message", e),
                hizn_tools::WsRepeaterEvent::Close(e) => ("ws-repeater-close", e),
                hizn_tools::WsRepeaterEvent::Error(e) => ("ws-repeater-error", e),
            };
            if let Value::Object(map) = &mut value {
                // Insert `type` first so it leads the object, as in Node.
                let mut out = serde_json::Map::new();
                out.insert("type".into(), json!(kind));
                out.append(map);
                value = Value::Object(out);
            }
            ws_hub
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .broadcast(&value);
        });
        let sink_hub = hub.clone();
        let intruder_sink: hizn_tools::IntruderSink = Arc::new(move |event| {
            let mut hub = sink_hub.lock().unwrap_or_else(|p| p.into_inner());
            let msg = match event {
                hizn_tools::IntruderEvent::Start(info) => {
                    json!({ "type": "intruder-start", "info": info })
                }
                hizn_tools::IntruderEvent::Row(row) => {
                    json!({ "type": "intruder-row", "row": row })
                }
                hizn_tools::IntruderEvent::Done(summary) => {
                    json!({ "type": "intruder-done", "summary": summary })
                }
            };
            hub.broadcast(&msg);
        });
        Self {
            hub,
            proxy,
            ca: Arc::new(Mutex::new(None)),
            orchestrator,
            repeater: Arc::new(hizn_tools::Repeater::new()),
            intruder: Arc::new(hizn_tools::Intruder::new()),
            intruder_sink,
            plugins: Arc::new(crate::plugins::Plugins::new(crate::plugins_dir())),
            ws_repeater: Arc::new(hizn_tools::WsRepeater::new(ws_rep_sink)),
            desktop: Arc::new(crate::desktop::Desktop::new()),
        }
    }

    /// A `ProxyControl` bridge for the orchestrator.
    pub fn proxy_bridge(&self) -> ProxyBridge {
        ProxyBridge {
            proxy: self.proxy.clone(),
            ca: self.ca.clone(),
            hub: self.hub.clone(),
        }
    }

    /// The CA from `~/.hizn` (created and persisted on first run). Loading it
    /// also makes `caFingerprint` appear in the status, as in Node.
    pub fn ca(&self) -> Result<Arc<CertAuthority>, CaError> {
        let mut slot = self.ca.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ca) = slot.as_ref() {
            return Ok(ca.clone());
        }
        let dir = std::env::var_os("HIZN_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(hizn_dir);
        let ca = Arc::new(CertAuthority::load_or_create(&dir)?);
        self.hub().ca_fingerprint = Some(ca.fingerprint().to_owned());
        *slot = Some(ca.clone());
        Ok(ca)
    }

    /// Lock the hub. Never hold the guard across an `.await`.
    pub fn hub(&self) -> MutexGuard<'_, Hub> {
        self.hub
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(rx: &mut UnboundedReceiver<Utf8Bytes>) -> Vec<Value> {
        let mut out = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            out.push(serde_json::from_str(msg.as_str()).unwrap());
        }
        out
    }

    #[test]
    fn status_matches_node_shape() {
        let status = serde_json::to_value(Hub::default().status()).unwrap();
        assert_eq!(
            status,
            json!({
                "running": false,
                "port": 8000,
                "upstream": { "enabled": false, "host": "127.0.0.1", "port": 8080 },
                "intercept": { "enabled": false, "requests": true, "responses": false },
            })
        );
        // Key order matches JSON.stringify of the Node object.
        let text = serde_json::to_string(&Hub::default().status()).unwrap();
        assert!(text.starts_with(r#"{"running":false,"port":8000,"upstream":"#));
    }

    #[test]
    fn hello_snapshot_order_matches_node() {
        let mut hub = Hub::default();
        hub.flows.insert("f1".into(), json!({ "id": "f1" }));
        hub.pending
            .insert("f1".into(), json!({ "id": "f1", "kind": "request" }));
        let (_, mut rx) = hub.add_client();
        let kinds: Vec<String> = drain(&mut rx)
            .iter()
            .map(|m| m["type"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            kinds,
            [
                "intercept-config",
                "connections",
                "scope",
                "flow-snapshot",
                "intercept",
                "proxy-status"
            ]
        );
    }

    #[test]
    fn broadcast_reaches_clients_and_drops_closed_ones() {
        let mut hub = Hub::default();
        let (_, mut a) = hub.add_client();
        let (_, b) = hub.add_client();
        drain(&mut a);
        drop(b);
        hub.broadcast(&json!({ "type": "flows-cleared" }));
        assert_eq!(drain(&mut a), vec![json!({ "type": "flows-cleared" })]);
        assert_eq!(hub.client_count(), 1);
    }
}
