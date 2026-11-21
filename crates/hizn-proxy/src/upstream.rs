//! Outbound side: reach origins directly, or through an upstream proxy such as
//! Burp Suite. Like mockttp's `proxyConfig`, every connection through the
//! upstream is an HTTP `CONNECT` tunnel — plain HTTP included.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::Uri;
use http_body_util::Full;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Where outbound connections go: straight to the origin, or via a proxy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Route {
    pub upstream: Option<(String, u16)>,
}

/// `host:port`, bracketing IPv6 literals.
pub fn authority_string(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Why an outbound connection failed, worded like the Node errors mockttp
/// reports (`connect ECONNREFUSED 127.0.0.1:443`, `getaddrinfo ENOTFOUND x`).
#[derive(Debug)]
pub(crate) enum ConnectError {
    Dns { host: String },
    Connect { addr: SocketAddr, source: io::Error },
    ProxyRefused { target: String, status_line: String },
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dns { host } => write!(f, "getaddrinfo ENOTFOUND {host}"),
            Self::Connect { addr, source } => {
                let code = match source.kind() {
                    io::ErrorKind::ConnectionRefused => "ECONNREFUSED",
                    io::ErrorKind::TimedOut => "ETIMEDOUT",
                    io::ErrorKind::ConnectionReset => "ECONNRESET",
                    io::ErrorKind::HostUnreachable => "EHOSTUNREACH",
                    io::ErrorKind::NetworkUnreachable => "ENETUNREACH",
                    io::ErrorKind::AddrNotAvailable => "EADDRNOTAVAIL",
                    _ => return write!(f, "connect {source} {}:{}", addr.ip(), addr.port()),
                };
                // Node prints IPv6 addresses without brackets.
                write!(f, "connect {code} {}:{}", addr.ip(), addr.port())
            }
            Self::ProxyRefused {
                target,
                status_line,
            } => {
                write!(
                    f,
                    "upstream proxy refused CONNECT to {target}: {status_line}"
                )
            }
        }
    }
}

impl std::error::Error for ConnectError {}

/// Resolve and connect, trying each address in turn (like Node).
async fn tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => addrs.collect(),
        Err(_) => Vec::new(),
    };
    if addrs.is_empty() {
        return Err(io::Error::other(ConnectError::Dns {
            host: host.to_owned(),
        }));
    }
    let mut last = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(source) => last = Some(ConnectError::Connect { addr, source }),
        }
    }
    Err(io::Error::other(
        last.expect("at least one address was tried"),
    ))
}

/// A byte stream to `host:port` — direct, or tunneled through the upstream
/// proxy with `CONNECT`.
pub async fn connect_tunnel(route: &Route, host: &str, port: u16) -> io::Result<TcpStream> {
    let Some((proxy_host, proxy_port)) = &route.upstream else {
        return tcp(host, port).await;
    };
    let mut stream = tcp(proxy_host, *proxy_port).await?;
    let target = authority_string(host, port);
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;

    // Read the proxy's response head byte by byte so nothing past it is consumed.
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream proxy closed the connection during CONNECT",
            ));
        }
        head.push(byte[0]);
        if head.len() > 16 * 1024 {
            return Err(io::Error::other(
                "upstream proxy sent an oversized CONNECT response",
            ));
        }
    }
    let status_line =
        String::from_utf8_lossy(head.split(|&b| b == b'\r').next().unwrap_or_default())
            .into_owned();
    let code = status_line.split_whitespace().nth(1).unwrap_or_default();
    if !code.starts_with('2') {
        return Err(io::Error::other(ConnectError::ProxyRefused {
            target,
            status_line,
        }));
    }
    Ok(stream)
}

/// Connector used by the HTTP clients; honours the current [`Route`].
#[derive(Clone)]
pub struct UpstreamConnector {
    route: Route,
}

impl tower_service::Service<Uri> for UpstreamConnector {
    type Response = UpStream;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<UpStream>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let route = self.route.clone();
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "request has no host"))?
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned();
            let tls = matches!(uri.scheme_str(), Some("https" | "wss"));
            let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
            Ok(UpStream {
                io: TokioIo::new(connect_tunnel(&route, &host, port).await?),
            })
        })
    }
}

/// An outbound TCP connection (direct, or a tunnel through the upstream).
pub struct UpStream {
    io: TokioIo<TcpStream>,
}

impl Connection for UpStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl hyper::rt::Read for UpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for UpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }
}

pub type HttpClient = Client<HttpsConnector<UpstreamConnector>, Full<Bytes>>;

/// Clients for one [`Route`]. Rebuilt when the route changes, so pooled
/// connections never outlive an upstream switch.
pub struct Clients {
    /// HTTP/1.1. Header names go out lowercase, as mockttp sends them.
    pub h1: HttpClient,
    /// HTTP/1.1 for WebSocket handshakes, which mockttp forwards with the
    /// client's original header case.
    pub h1_ws: HttpClient,
    /// For requests that arrived over HTTP/2: offers h2 and http/1.1 and
    /// uses whichever the origin picks (an h1-only origin still works).
    pub h2: HttpClient,
}

impl Clients {
    pub fn new(route: &Route, tls: &ClientConfig) -> Self {
        let connector = UpstreamConnector {
            route: route.clone(),
        };
        let h1_connector = || {
            HttpsConnectorBuilder::new()
                .with_tls_config(tls.clone())
                .https_or_http()
                .enable_http1()
                .wrap_connector(connector.clone())
        };
        let h2_or_h1 = HttpsConnectorBuilder::new()
            .with_tls_config(tls.clone())
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(connector.clone());
        Self {
            h1: Client::builder(TokioExecutor::new()).build(h1_connector()),
            h1_ws: Client::builder(TokioExecutor::new())
                .http1_preserve_header_case(true)
                .build(h1_connector()),
            h2: Client::builder(TokioExecutor::new()).build(h2_or_h1),
        }
    }
}

/// Trust store for origin certificates: Mozilla's roots, the OS store (so a
/// Burp CA trusted by Windows works when chaining), and any PEM files listed
/// in `HIZN_EXTRA_CA_CERTS` (path list, like `NODE_EXTRA_CA_CERTS`).
pub fn client_tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(paths) = std::env::var_os("HIZN_EXTRA_CA_CERTS") {
        for path in std::env::split_paths(&paths) {
            if let Ok(pem) = std::fs::read(&path) {
                for cert in CertificateDer::pem_slice_iter(&pem).flatten() {
                    let _ = roots.add(cert);
                }
            }
        }
    }
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    Arc::new(config)
}
