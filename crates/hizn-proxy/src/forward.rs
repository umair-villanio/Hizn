//! Forward one HTTP exchange to its origin and report it as a flow.
//!
//! Event timing matches mockttp: `flow` once the request body has fully
//! arrived, `flow-update` once the response body has been fully delivered (or
//! `error: 'aborted'` if it never was).
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName};
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use serde_json::{Value, json};

use crate::capture::{CaptureBody, Captured, Outcome};
use crate::headers::node_headers;
use crate::{ProxyEvent, Shared, new_id, now_ms};

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type ResBody = UnsyncBoxBody<Bytes, BoxError>;

pub(crate) fn empty() -> ResBody {
    Empty::new()
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

pub(crate) fn text_response(status: StatusCode, text: impl Into<Bytes>) -> Response<ResBody> {
    let mut res = Response::new(
        Full::new(text.into())
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *res.status_mut() = status;
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    res
}

/// Where a request is going, worked out the way mockttp reports it.
pub(crate) struct Target {
    /// `host[:port]` used to connect (and for the upstream URI).
    pub authority: String,
    pub host_name: String,
    pub port: u16,
    /// The flow's `host`: the Host header as sent, else the authority.
    pub host_field: String,
    /// The flow's `path` (path + query).
    pub path: String,
    /// The flow's `url`.
    pub url: String,
}

impl Target {
    /// `scheme` is "http" or "https"; `fallback` is the CONNECT authority for
    /// requests that arrived inside a tunnel.
    pub fn resolve(
        parts: &http::request::Parts,
        scheme: &str,
        fallback: Option<&str>,
    ) -> Option<Self> {
        let host_header = parts
            .headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok());
        let authority = parts
            .uri
            .authority()
            .map(|a| a.as_str())
            .or(host_header)
            .or(fallback)?
            .to_owned();
        let default_port = if scheme == "https" { 443 } else { 80 };
        let parsed: http::uri::Authority = authority.parse().ok()?;
        let host_name = parsed
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = parsed.port_u16().unwrap_or(default_port);
        let path = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_owned())
            .unwrap_or_else(|| "/".into());

        // Absolute-form requests keep the URL exactly as sent; tunneled ones
        // are rebuilt from the Host header (or the CONNECT target).
        let url = if parts.uri.scheme().is_some() && parts.uri.authority().is_some() {
            parts.uri.to_string()
        } else {
            let shown = host_header.map(str::to_owned).unwrap_or_else(|| {
                if port == default_port {
                    parsed.host().to_owned()
                } else {
                    authority.clone()
                }
            });
            format!("{scheme}://{shown}{path}")
        };

        Some(Self {
            host_field: host_header
                .map(str::to_owned)
                .unwrap_or_else(|| authority.clone()),
            authority: crate::upstream::authority_string(&host_name, port),
            host_name,
            port,
            path,
            url,
        })
    }
}

/// Headers that belong to one hop only and must not be passed on.
const HOP_BY_HOP: &[&str] = &[
    "proxy-connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-authenticate",
];

fn strip_hop_by_hop(headers: &mut HeaderMap, h2: bool) {
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
    if h2 {
        // HTTP/2 forbids connection-specific headers.
        for name in [
            header::CONNECTION,
            header::TRANSFER_ENCODING,
            header::UPGRADE,
            HeaderName::from_static("te"),
        ] {
            headers.remove(name);
        }
    }
}

pub(crate) fn status_message(res: &http::response::Parts) -> String {
    res.extensions
        .get::<hyper::ext::ReasonPhrase>()
        .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned())
        .unwrap_or_else(|| res.status.canonical_reason().unwrap_or_default().to_owned())
}

/// Forward a normal (non-CONNECT, non-WebSocket) request.
pub(crate) async fn forward(
    shared: Arc<Shared>,
    req: Request<Incoming>,
    scheme: &'static str,
    fallback: Option<&str>,
) -> Response<ResBody> {
    let (mut parts, body) = req.into_parts();
    // mockttp never reports or forwards the client's proxy hint.
    parts.headers.remove("proxy-connection");
    let Some(target) = Target::resolve(&parts, scheme, fallback) else {
        return text_response(StatusCode::BAD_REQUEST, "Bad request: no target host");
    };
    // The client gave up while uploading: nothing to forward or report.
    let Ok(body) = body.collect().await.map(|c| c.to_bytes()) else {
        return text_response(StatusCode::BAD_REQUEST, "");
    };

    let id = new_id();
    let captured = Captured::from_bytes(&body);
    let h2 = parts.version == Version::HTTP_2;
    let request_headers = if h2 {
        // mockttp shows HTTP/2 pseudo-headers first.
        let mut h = serde_json::Map::new();
        h.insert(":path".into(), json!(target.path));
        h.insert(":method".into(), json!(parts.method.as_str()));
        h.insert(":authority".into(), json!(target.host_field));
        h.insert(":scheme".into(), json!(scheme));
        h.extend(node_headers(&parts.headers));
        h
    } else {
        node_headers(&parts.headers)
    };
    let mut flow = json!({
        "id": id,
        "method": parts.method.as_str(),
        "protocol": scheme,
        "host": target.host_field,
        "path": target.path,
        "url": target.url,
        "requestHeaders": request_headers,
        "requestBodySize": captured.size,
    });
    if let Some(text) = captured.text() {
        flow["requestBody"] = Value::String(text);
    }
    flow["startedAt"] = json!(now_ms());
    shared.emit(ProxyEvent::Flow(flow));

    // A request aimed at the proxy itself (not *through* it) would loop.
    if shared.is_self(&target.host_name, target.port) {
        return error_response(
            &shared,
            &id,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server error",
            format!(
                "Error: Passthrough loop detected. This probably means you're sending a request directly to a passthrough endpoint, which is forwarding it to the target URL, which is a passthrough endpoint, which is forwarding it to the target URL, which is a passthrough endpoint...\n\nYou should either explicitly mock a response for this URL ({}), or use the server as a proxy, instead of making requests to it directly.",
                target.url
            ),
        );
    }

    let is_head = parts.method == Method::HEAD;
    strip_hop_by_hop(&mut parts.headers, h2);
    parts.uri = match format!("{scheme}://{}{}", target.authority, target.path).parse() {
        Ok(uri) => uri,
        Err(_) => return text_response(StatusCode::BAD_REQUEST, "Bad request: invalid URL"),
    };
    // HTTP/1.1 on the request either way: the h2 client sends it over HTTP/2
    // when the origin negotiates h2, and over HTTP/1.1 otherwise.
    parts.version = Version::HTTP_11;
    // Drop the server-side extensions — in particular hyper's original-case
    // header map, which would make the client write `Host:` instead of the
    // lowercase `host:` mockttp sends.
    parts.extensions = http::Extensions::new();
    let upstream_req = Request::from_parts(parts, Full::new(body));

    let clients = shared.clients();
    let result = if h2 {
        clients.h2.request(upstream_req).await
    } else {
        clients.h1.request(upstream_req).await
    };

    match result {
        Ok(res) => respond(shared, id, res, is_head, h2),
        Err(e) => upstream_failed(&shared, &id, &e),
    }
}

/// Stream the origin's response back, reporting it when done.
fn respond(
    shared: Arc<Shared>,
    id: String,
    res: Response<Incoming>,
    is_head: bool,
    h2_client: bool,
) -> Response<ResBody> {
    let (mut parts, body) = res.into_parts();
    let status = parts.status;
    let update_head = if h2_client {
        // As sent to an HTTP/2 client: `:status` first, no connection-specific
        // headers, and no reason phrase (HTTP/2 has none).
        strip_hop_by_hop(&mut parts.headers, true);
        let mut headers = serde_json::Map::new();
        headers.insert(":status".into(), json!(status.as_u16().to_string()));
        headers.extend(node_headers(&parts.headers));
        json!({
            "id": id,
            "statusCode": status.as_u16(),
            "statusMessage": "",
            "responseHeaders": headers,
        })
    } else {
        json!({
            "id": id,
            "statusCode": status.as_u16(),
            "statusMessage": status_message(&parts),
            "responseHeaders": node_headers(&parts.headers),
        })
    };

    let report = move |outcome: Outcome| {
        let event = match outcome {
            Outcome::Complete(captured) => {
                let mut update = update_head;
                update["responseBodySize"] = json!(captured.size);
                if let Some(text) = captured.text() {
                    update["responseBody"] = Value::String(text);
                }
                update["completedAt"] = json!(now_ms());
                update
            }
            Outcome::Aborted => json!({ "id": id, "error": "aborted", "completedAt": now_ms() }),
        };
        shared.emit(ProxyEvent::FlowUpdate(event));
    };

    let bodyless = is_head
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED;
    if bodyless {
        report(Outcome::Complete(Captured::default()));
        return Response::from_parts(parts, empty());
    }
    let body = CaptureBody::new(body, report)
        .map_err(|e| Box::new(e) as BoxError)
        .boxed_unsync();
    Response::from_parts(parts, body)
}

/// The origin couldn't be reached: answer like mockttp does (a 502 whose body
/// is the Node-style error) and record it as the flow's response.
fn upstream_failed(
    shared: &Shared,
    id: &str,
    error: &hyper_util::client::legacy::Error,
) -> Response<ResBody> {
    error_response(
        shared,
        id,
        StatusCode::BAD_GATEWAY,
        "Error communicating with upstream server",
        node_error_text(error),
    )
}

/// mockttp's error reply: status line with a custom reason, no headers of its
/// own, the error text as the body, connection closed afterwards. Reported as
/// a normal response (`responseHeaders: {}`), as mockttp does.
pub(crate) fn error_response(
    shared: &Shared,
    id: &str,
    status: StatusCode,
    reason: &'static str,
    body: String,
) -> Response<ResBody> {
    shared.emit(ProxyEvent::FlowUpdate(json!({
        "id": id,
        "statusCode": status.as_u16(),
        "statusMessage": reason,
        "responseHeaders": {},
        "responseBodySize": body.len(),
        "responseBody": body,
        "completedAt": now_ms(),
    })));
    let mut res = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *res.status_mut() = status;
    res.headers_mut()
        .insert(header::CONNECTION, http::HeaderValue::from_static("close"));
    if let Ok(phrase) = hyper::ext::ReasonPhrase::try_from(reason.as_bytes()) {
        res.extensions_mut().insert(phrase);
    }
    res
}

/// The error as Node would print it (`err.toString()`).
pub(crate) fn node_error_text(error: &(dyn std::error::Error + 'static)) -> String {
    use crate::upstream::ConnectError;
    if let Some(c) = find::<ConnectError>(error) {
        return format!("Error: {c}");
    }
    if let Some(t) = find::<rustls::Error>(error) {
        return format!("Error: {}", tls_message(t));
    }
    format!("Error: {}", error_chain(error))
}

/// Find a `T` anywhere in an error chain. `io::Error::source()` skips its own
/// payload (and io errors nest), so payloads are searched explicitly.
fn find<'a, T: std::error::Error + 'static>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a T> {
    if let Some(t) = error.downcast_ref::<T>() {
        return Some(t);
    }
    if let Some(payload) = error
        .downcast_ref::<std::io::Error>()
        .and_then(|io| io.get_ref())
        && let Some(t) = find::<T>(payload)
    {
        return Some(t);
    }
    error.source().and_then(find::<T>)
}

/// Node/OpenSSL wording for the common certificate failures.
fn tls_message(e: &rustls::Error) -> String {
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(cert) => match cert {
            C::UnknownIssuer => "unable to get local issuer certificate".into(),
            C::NotValidForName | C::NotValidForNameContext { .. } => {
                "Hostname/IP does not match certificate's altnames".into()
            }
            C::Expired | C::ExpiredContext { .. } => "certificate has expired".into(),
            C::NotValidYet | C::NotValidYetContext { .. } => "certificate is not yet valid".into(),
            C::Revoked => "certificate revoked".into(),
            // webpki's name for a self-signed certificate presented as a leaf.
            other if format!("{other:?}").contains("CaUsedAsEndEntity") => {
                "self-signed certificate".into()
            }
            other => format!("{other:?}"),
        },
        other => other.to_string(),
    }
}

pub(crate) fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![error.to_string()];
    let mut source = error.source();
    while let Some(e) = source {
        let s = e.to_string();
        if !parts.contains(&s) {
            parts.push(s);
        }
        source = e.source();
    }
    parts.join(": ")
}
