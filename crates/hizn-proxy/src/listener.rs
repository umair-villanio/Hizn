//! Accepting proxy clients: plain proxy requests, CONNECT tunnels, and TLS
//! interception inside them.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::LazyConfigAcceptor;

use crate::Shared;
use crate::forward::{self, Served, empty, text_response};
use crate::io::Prefixed;
use crate::upstream::connect_tunnel;
use crate::ws;

/// Bind `port` on all interfaces: dual-stack `[::]` when available (what
/// Node's `listen(port)` does), else `0.0.0.0`.
pub(crate) fn bind(port: u16) -> io::Result<TcpListener> {
    let v6 = (|| {
        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_only_v6(false)?;
        prepare(&socket)?;
        socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
        Ok::<_, io::Error>(socket)
    })();
    let socket = match v6 {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => return Err(e),
        Err(_) => {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            prepare(&socket)?;
            socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
            socket
        }
    };
    socket.listen(511)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

fn prepare(socket: &Socket) -> io::Result<()> {
    // Unix: allow quick restarts. Windows: SO_REUSEADDR would let another
    // process steal the port, so leave it off (as libuv does).
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    let _ = socket;
    Ok(())
}

/// Run `fut` until it finishes or the proxy is stopped.
pub(crate) async fn until_stopped<F: Future>(fut: F, mut stop: watch::Receiver<bool>) {
    tokio::select! {
        _ = fut => {}
        _ = stop.wait_for(|stopped| *stopped) => {}
    }
}

pub(crate) async fn accept_loop(
    shared: Arc<Shared>,
    listener: TcpListener,
    stop: watch::Receiver<bool>,
) {
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            // Transient (e.g. too many open files): back off briefly.
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        tokio::spawn(until_stopped(
            serve_proxy_client(shared.clone(), stream, stop.clone()),
            stop.clone(),
        ));
    }
}

/// One connection from a proxy client (device, browser, tool).
async fn serve_proxy_client(shared: Arc<Shared>, stream: TcpStream, stop: watch::Receiver<bool>) {
    let service = service_fn(move |req| proxy_request(shared.clone(), req, stop.clone()));
    // No automatic Date header: like mockttp, responses carry only what the
    // origin sent. Header case is kept for WebSocket handshakes.
    let _ = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .auto_date_header(false)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await;
}

/// `Err(Dropped)` makes hyper close the connection without a response.
async fn proxy_request(
    shared: Arc<Shared>,
    mut req: Request<Incoming>,
    stop: watch::Receiver<bool>,
) -> Served {
    if req.method() == Method::CONNECT {
        let Some(authority) = req.uri().authority().map(|a| a.as_str().to_owned()) else {
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "CONNECT needs host:port",
            ));
        };
        let on_upgrade = hyper::upgrade::on(&mut req);
        let tunnel_stop = stop.clone();
        tokio::spawn(until_stopped(
            async move {
                if let Ok(upgraded) = on_upgrade.await {
                    tunnel(shared, TokioIo::new(upgraded), authority, tunnel_stop).await;
                }
            },
            stop,
        ));
        return Ok(Response::new(empty()));
    }
    if ws::is_upgrade(&req) {
        return Ok(ws::passthrough(shared, req, "http", None, stop).await);
    }
    forward::forward(shared, req, "http", None).await
}

/// Inside a CONNECT tunnel: intercept TLS, serve plain HTTP, or (anything
/// else) relay the bytes untouched.
async fn tunnel<T>(shared: Arc<Shared>, mut io: T, authority: String, stop: watch::Receiver<bool>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut first = [0u8; 8];
    let n = match io.read(&mut first).await {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };
    let io = Prefixed::new(Bytes::copy_from_slice(&first[..n]), io);

    if first[0] == 0x16 {
        intercept_tls(shared, io, authority, stop).await;
    } else if first[0].is_ascii_uppercase() {
        serve_tunneled(shared, TokioIo::new(io), "http", authority, false, stop).await;
    } else {
        relay(shared, io, &authority).await;
    }
}

/// TLS interception: read the ClientHello, mint a leaf for the requested
/// name, and pick the protocol like mockttp's `http2: 'fallback'` — HTTP/1.1
/// whenever the client offers it, HTTP/2 only for h2-only clients.
async fn intercept_tls<T>(
    shared: Arc<Shared>,
    io: Prefixed<T>,
    authority: String,
    stop: watch::Receiver<bool>,
) where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(ca) = shared.ca() else { return };
    let Ok(start) = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io).await else {
        return;
    };
    let hello = start.client_hello();
    let offered: Vec<&[u8]> = hello.alpn().map(|it| it.collect()).unwrap_or_default();
    let alpn = if offered.is_empty() || offered.contains(&b"http/1.1".as_slice()) {
        if offered.is_empty() {
            vec![]
        } else {
            vec![b"http/1.1".to_vec()]
        }
    } else if offered.contains(&b"h2".as_slice()) {
        vec![b"h2".to_vec()]
    } else {
        vec![]
    };
    let connect_host = authority
        .parse::<http::uri::Authority>()
        .map(|a| a.host().to_owned())
        .unwrap_or_else(|_| authority.clone());
    let name = hello
        .server_name()
        .map(str::to_owned)
        .unwrap_or(connect_host);

    let Ok(config) = ca.server_config(&name, alpn) else {
        return;
    };
    // A client that doesn't trust the Hizn CA fails here; nothing to report.
    let Ok(tls) = start.into_stream(config).await else {
        return;
    };
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    serve_tunneled(shared, TokioIo::new(tls), "https", authority, h2, stop).await;
}

/// Serve HTTP that arrived inside a tunnel (decrypted, or plain).
async fn serve_tunneled<I>(
    shared: Arc<Shared>,
    io: I,
    scheme: &'static str,
    authority: String,
    h2: bool,
    stop: watch::Receiver<bool>,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let authority = Arc::new(authority);
    let service = service_fn(move |req: Request<Incoming>| {
        let shared = shared.clone();
        let authority = authority.clone();
        let stop = stop.clone();
        async move {
            if ws::is_upgrade(&req) {
                Ok(ws::passthrough(shared, req, scheme, Some(&authority), stop).await)
            } else {
                forward::forward(shared, req, scheme, Some(&authority)).await
            }
        }
    });
    if h2 {
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .auto_date_header(false)
            .serve_connection(io, service)
            .await;
    } else {
        let _ = hyper::server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .auto_date_header(false)
            .serve_connection(io, service)
            .with_upgrades()
            .await;
    }
}

/// Unknown protocol inside a tunnel: pass it through unchanged.
async fn relay<T>(shared: Arc<Shared>, mut io: T, authority: &str)
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let Ok(parsed) = authority.parse::<http::uri::Authority>() else {
        return;
    };
    let host = parsed.host().trim_start_matches('[').trim_end_matches(']');
    let port = parsed.port_u16().unwrap_or(443);
    if let Ok(mut server) = connect_tunnel(&shared.route(), host, port).await {
        let _ = tokio::io::copy_bidirectional(&mut io, &mut server).await;
    }
}
