//! Hizn interception engine: an HTTP/HTTPS man-in-the-middle proxy that
//! decrypts TLS with the Hizn CA, forwards traffic (optionally through an
//! upstream proxy such as Burp), and reports every exchange as a flow.
//!
//! Flow events carry the same JSON the Node backend produced from mockttp, so
//! the UI and saved sessions work unchanged.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

pub mod ca;
mod capture;
mod forward;
pub mod headers;
mod io;
mod listener;
mod upstream;
mod ws;

use std::io as stdio;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

pub use ca::{CaError, CertAuthority, hizn_dir};
pub use capture::MAX_BODY_TEXT;
use upstream::{Clients, Route};

/// Something the UI should hear about.
#[derive(Debug, Clone)]
pub enum ProxyEvent {
    /// A new exchange (`type: 'flow'` payload).
    Flow(Value),
    /// More about an existing exchange (`type: 'flow-update'` payload).
    FlowUpdate(Value),
}

pub type EventSink = Arc<dyn Fn(ProxyEvent) + Send + Sync>;

/// Shared by every connection task.
pub(crate) struct Shared {
    events: EventSink,
    tls_client: Arc<rustls::ClientConfig>,
    route: RwLock<Route>,
    clients: RwLock<Arc<Clients>>,
    ca: RwLock<Option<Arc<CertAuthority>>>,
    listen_port: AtomicU16,
}

impl Shared {
    pub(crate) fn emit(&self, event: ProxyEvent) {
        (self.events)(event);
    }

    pub(crate) fn clients(&self) -> Arc<Clients> {
        self.clients
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub(crate) fn route(&self) -> Route {
        self.route.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub(crate) fn ca(&self) -> Option<Arc<CertAuthority>> {
        self.ca.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Would forwarding to `host:port` loop straight back into this proxy?
    pub(crate) fn is_self(&self, host: &str, port: u16) -> bool {
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        port == self.listen_port.load(Ordering::Relaxed)
            && matches!(
                host.as_str(),
                "localhost" | "127.0.0.1" | "::1" | "0.0.0.0" | "::"
            )
    }
}

struct Running {
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

/// Why the proxy couldn't start.
#[derive(Debug)]
pub enum StartError {
    /// The port is taken (message mirrors Node's `EADDRINUSE` text).
    AddrInUse(u16),
    Io(stdio::Error),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddrInUse(port) => {
                write!(f, "listen EADDRINUSE: address already in use :::{port}")
            }
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StartError {}

/// The proxy. Cheap to share; start/stop as often as needed.
pub struct ProxyEngine {
    shared: Arc<Shared>,
    running: Mutex<Option<Running>>,
    is_running: AtomicBool,
}

impl ProxyEngine {
    pub fn new(events: EventSink) -> Self {
        let tls_client = upstream::client_tls_config();
        let route = Route::default();
        let clients = Arc::new(Clients::new(&route, &tls_client));
        Self {
            shared: Arc::new(Shared {
                events,
                tls_client,
                route: RwLock::new(route),
                clients: RwLock::new(clients),
                ca: RwLock::new(None),
                listen_port: AtomicU16::new(0),
            }),
            running: Mutex::new(None),
            is_running: AtomicBool::new(false),
        }
    }

    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /// Listen on `port` on all interfaces (IPv6 + IPv4, like Node's default),
    /// intercepting TLS with `ca`. No-op if already running.
    pub async fn start(&self, port: u16, ca: Arc<CertAuthority>) -> Result<(), StartError> {
        let mut running = self.running.lock().await;
        if running.is_some() {
            return Ok(());
        }
        let listener = listener::bind(port).map_err(|e| {
            if e.kind() == stdio::ErrorKind::AddrInUse {
                StartError::AddrInUse(port)
            } else {
                StartError::Io(e)
            }
        })?;
        *self.shared.ca.write().unwrap_or_else(|p| p.into_inner()) = Some(ca);
        self.shared.listen_port.store(port, Ordering::Relaxed);
        let (shutdown, rx) = watch::channel(false);
        let task = tokio::spawn(listener::accept_loop(self.shared.clone(), listener, rx));
        *running = Some(Running { shutdown, task });
        self.is_running.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Stop listening and drop every open connection.
    pub async fn stop(&self) {
        let mut running = self.running.lock().await;
        if let Some(r) = running.take() {
            let _ = r.shutdown.send(true);
            r.task.abort();
            let _ = r.task.await;
        }
        self.is_running.store(false, Ordering::SeqCst);
    }

    /// Route all traffic through `upstream` (host, port), or directly with
    /// `None`. Takes effect for new requests immediately, while running.
    pub fn set_upstream(&self, upstream: Option<(String, u16)>) {
        let route = Route { upstream };
        let clients = Arc::new(Clients::new(&route, &self.shared.tls_client));
        *self.shared.route.write().unwrap_or_else(|p| p.into_inner()) = route;
        *self
            .shared
            .clients
            .write()
            .unwrap_or_else(|p| p.into_inner()) = clients;
    }
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
