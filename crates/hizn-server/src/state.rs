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
use hizn_proxy::{CaError, CertAuthority, ProxyEngine, ProxyEvent, hizn_dir};
use indexmap::{IndexMap, IndexSet};
use serde::Serialize;
use serde_json::{Value, json};
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

/// Burp-style interception switches.
#[derive(Clone, Debug, Serialize)]
pub struct InterceptConfig {
    pub enabled: bool,
    pub requests: bool,
    pub responses: bool,
}

impl Default for InterceptConfig {
    fn default() -> Self {
        // Responses are only held when explicitly asked for.
        Self {
            enabled: false,
            requests: true,
            responses: false,
        }
    }
}

/// Target scope: limit interception to specific hosts.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ScopeConfig {
    pub enabled: bool,
    pub hosts: Vec<String>,
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
    pub upstream: UpstreamConfig,
    pub intercept: InterceptConfig,
    pub scope: ScopeConfig,
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
            upstream: UpstreamConfig::default(),
            intercept: InterceptConfig::default(),
            scope: ScopeConfig::default(),
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
            match event {
                ProxyEvent::Flow(flow) => hub.add_flow(flow),
                ProxyEvent::FlowUpdate(update) => hub.update_flow(update),
            }
        })));
        Self {
            hub,
            proxy,
            ca: Arc::new(Mutex::new(None)),
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
