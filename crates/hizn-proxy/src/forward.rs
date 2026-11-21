//! Forward one HTTP exchange to its origin and report it as a flow, applying
//! Match & Replace rules and Burp-style interception on the way.
//!
//! Event timing matches mockttp: `flow` (the request as received) once the
//! request body has fully arrived, `flow-update` (the response as sent) once
//! the response body has been delivered — or `error: 'aborted'` if it never
//! was, including when the user drops it.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use serde_json::{Map, Value, json};

use crate::capture::{CaptureBody, Captured, MAX_BODY_TEXT, Outcome};
use crate::headers::node_headers;
use crate::policy::Decision;
use crate::{ProxyEvent, Shared, codec, js, new_id, now_ms};

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type ResBody = UnsyncBoxBody<Bytes, BoxError>;

/// The user dropped the exchange: close the connection without a response
/// (returning this error from a hyper service does exactly that).
#[derive(Debug)]
pub(crate) struct Dropped;

impl std::fmt::Display for Dropped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("dropped by the user")
    }
}

impl std::error::Error for Dropped {}

pub(crate) type Served = Result<Response<ResBody>, Dropped>;

fn full(bytes: impl Into<Bytes>) -> ResBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn report_aborted(shared: &Shared, id: &str) {
    shared.emit(ProxyEvent::FlowUpdate(
        json!({ "id": id, "error": "aborted", "completedAt": now_ms() }),
    ));
}

/// Body as text the way mockttp's `body.getText()` gives it: decoded per
/// `Content-Encoding`, as UTF-8; empty if it can't be decoded.
fn body_text(raw: &[u8], encodings: &[String]) -> String {
    if encodings.is_empty() {
        return String::from_utf8_lossy(raw).into_owned();
    }
    codec::decode(raw, encodings)
        .map(|d| String::from_utf8_lossy(&d).into_owned())
        .unwrap_or_default()
}

/// Rewritten text back to bytes, re-encoded per the final `Content-Encoding`.
fn encode_text(text: &str, headers: &HeaderMap) -> Bytes {
    let encodings = codec::encodings(headers);
    if encodings.is_empty() {
        return Bytes::copy_from_slice(text.as_bytes());
    }
    codec::encode(text.as_bytes(), &encodings)
        .map(Bytes::from)
        .unwrap_or_else(|| Bytes::copy_from_slice(text.as_bytes()))
}

/// A headers object (from rules or the user's edit) as a header map. Names
/// go out lowercase; arrays become repeated headers; pseudo-headers and
/// unencodable values are skipped.
fn headers_from_object(obj: &Map<String, Value>) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in obj {
        if name.starts_with(':') {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(name.trim().as_bytes()) else {
            continue;
        };
        let values: Vec<String> = match value {
            Value::Array(list) => list.iter().map(js::string).collect(),
            other => vec![js::string(other)],
        };
        for v in values {
            if let Ok(v) = HeaderValue::from_str(&v) {
                out.append(name.clone(), v);
            }
        }
    }
    out
}

/// After changing headers or body, keep `content-length` truthful — updated in
/// place, or appended — unless the message is chunked (as mockttp does).
fn fix_content_length(headers: &mut HeaderMap, len: usize) {
    if !headers.contains_key(header::TRANSFER_ENCODING) {
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    }
}

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
) -> Served {
    let (mut parts, body) = req.into_parts();
    // mockttp never reports or forwards the client's proxy hint.
    parts.headers.remove("proxy-connection");
    let Some(target) = Target::resolve(&parts, scheme, fallback) else {
        return Ok(text_response(
            StatusCode::BAD_REQUEST,
            "Bad request: no target host",
        ));
    };
    // The client gave up while uploading: nothing to forward or report.
    let Ok(mut body) = body.collect().await.map(|c| c.to_bytes()) else {
        return Ok(text_response(StatusCode::BAD_REQUEST, ""));
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

    // A request aimed at the proxy itself (not *through* it) would loop.
    if shared.is_self(&target.host_name, target.port) {
        shared.emit(ProxyEvent::Flow(flow));
        return Ok(error_response(
            &shared,
            &id,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server error",
            format!(
                "Error: Passthrough loop detected. This probably means you're sending a request directly to a passthrough endpoint, which is forwarding it to the target URL, which is a passthrough endpoint, which is forwarding it to the target URL, which is a passthrough endpoint...\n\nYou should either explicitly mock a response for this URL ({}), or use the server as a proxy, instead of making requests to it directly.",
                target.url
            ),
        ));
    }

    // ---- Match & Replace, then (optionally) hold for the user ----
    let mut destination = format!("{scheme}://{}{}", target.authority, target.path);
    if let Some(edit) = before_request(&shared, &id, &parts, &body, &target, flow).await? {
        if let Some(url) = edit.url
            && let Ok(uri) = url.parse::<http::Uri>()
            && let (Some(s), Some(a)) = (uri.scheme_str(), uri.authority())
        {
            // A new destination; the Host header follows it, as in mockttp.
            if parts
                .headers
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                != Some(a.as_str())
                && let Ok(host) = HeaderValue::from_str(a.as_str())
            {
                parts.headers.insert(header::HOST, host);
            }
            let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
            let port = a.port_u16().unwrap_or(if s == "https" { 443 } else { 80 });
            let host = a.host().trim_start_matches('[').trim_end_matches(']');
            destination = format!(
                "{s}://{}{path}",
                crate::upstream::authority_string(host, port)
            );
        }
        if let Some(method) = edit.method {
            parts.method = method;
        }
        let replaced = edit.headers.is_some() || edit.body.is_some();
        if let Some(headers) = edit.headers {
            let host = parts.headers.get(header::HOST).cloned();
            parts.headers = headers_from_object(&headers);
            if !parts.headers.contains_key(header::HOST)
                && let Some(host) = host
            {
                parts.headers.insert(header::HOST, host);
            }
        }
        if let Some(text) = edit.body {
            body = encode_text(&text, &parts.headers);
        }
        if replaced {
            fix_content_length(&mut parts.headers, body.len());
        }
    }

    let is_head = parts.method == Method::HEAD;
    strip_hop_by_hop(&mut parts.headers, h2);
    parts.uri = match destination.parse() {
        Ok(uri) => uri,
        Err(_) => {
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "Bad request: invalid URL",
            ));
        }
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
        Ok(res) => {
            let (holding, rewrites) = {
                let mut policy = shared.policy();
                let holding = policy.holds_response(&id, &target.host_field);
                let rules = policy.rules_ref();
                let rewrites =
                    js::has_rule(rules, "response-header") || js::has_rule(rules, "response-body");
                (holding, rewrites)
            };
            if holding || rewrites {
                after_response(shared, id, res, holding, h2).await
            } else {
                Ok(respond(shared, id, res, is_head, h2))
            }
        }
        Err(e) => Ok(upstream_failed(&shared, &id, &e)),
    }
}

/// Changes to apply to a request before forwarding it.
struct RequestEdit {
    url: Option<String>,
    method: Option<Method>,
    headers: Option<Map<String, Value>>,
    body: Option<String>,
}

/// The Node backend's `onBeforeRequest`: Match & Replace first (so a held
/// request shows the rewritten message), then hold it if intercepting.
/// `Ok(None)` = forward untouched; `Err` = the user dropped it.
///
/// Also announces the `flow`: mockttp announced requests asynchronously, so a
/// held request's `intercept` event reached the UI *before* its `flow`.
async fn before_request(
    shared: &Shared,
    id: &str,
    parts: &http::request::Parts,
    body: &Bytes,
    target: &Target,
    flow: Value,
) -> Result<Option<RequestEdit>, Dropped> {
    let (holding, rules) = {
        let policy = shared.policy();
        (
            policy.holds_requests(&target.host_field),
            policy.rules_ref().to_vec(),
        )
    };
    if !holding {
        shared.emit(ProxyEvent::Flow(flow.clone()));
    }
    let body_rules = js::has_rule(&rules, "request-body");
    if !holding
        && !body_rules
        && !js::has_rule(&rules, "request-url")
        && !js::has_rule(&rules, "request-header")
    {
        return Ok(None);
    }

    // Rules see the whole decoded body (Node only looked at the first 512 KB,
    // and cut longer bodies to that size when a rule matched).
    let text = (holding || body_rules).then(|| body_text(body, &codec::encodings(&parts.headers)));

    let (url, url_changed) = js::apply_rules(&target.url, &rules, "request-url");
    let original_headers = node_headers(&parts.headers);
    let rewritten_headers = js::apply_header_rules(&original_headers, &rules, "request-header");
    let (body_text, body_changed) = match &text {
        Some(t) if body_rules => js::apply_rules(t, &rules, "request-body"),
        Some(t) => (t.clone(), false),
        None => (String::new(), false),
    };

    if !holding {
        return Ok(Some(RequestEdit {
            url: url_changed.then_some(url),
            method: None,
            headers: rewritten_headers,
            body: body_changed.then_some(body_text),
        }));
    }

    let headers = rewritten_headers.clone().unwrap_or(original_headers);
    let host = headers.get("host").cloned().unwrap_or_else(|| {
        json!(
            url.parse::<http::Uri>()
                .ok()
                .and_then(|u| u.authority().map(|a| a.to_string()))
                .unwrap_or_default()
        )
    });
    let (shown, truncated) = js::cap_utf16(&body_text, MAX_BODY_TEXT);
    let decision = shared
        .hold(
            json!({
                "id": id,
                "flowId": id,
                "kind": "request",
                "method": parts.method.as_str(),
                "url": url,
                "host": host,
                "path": target.path,
                "headers": headers,
                "body": shown,
                "bodyTruncated": truncated,
                "startedAt": now_ms(),
            }),
            Some(ProxyEvent::Flow(flow)),
        )
        .await;
    if decision.drop {
        report_aborted(shared, id);
        return Err(Dropped);
    }
    if decision.intercept_response {
        shared.policy().watch_response(id);
    }
    Ok(Some(RequestEdit {
        url: Decision::truthy_string(&decision.url).or(url_changed.then_some(url)),
        method: Decision::truthy_string(&decision.method)
            .and_then(|m| Method::from_bytes(m.as_bytes()).ok()),
        headers: decision.headers_object().cloned().or(rewritten_headers),
        body: decision.edited_body().or(body_changed.then_some(body_text)),
    }))
}

/// The Node backend's `onBeforeResponse`, for responses that are held or
/// rewritten: buffer, apply rules, hold if asked, send the result.
async fn after_response(
    shared: Arc<Shared>,
    id: String,
    res: Response<Incoming>,
    holding: bool,
    h2_client: bool,
) -> Served {
    let (mut parts, body) = res.into_parts();
    let Ok(raw) = body.collect().await.map(|c| c.to_bytes()) else {
        report_aborted(&shared, &id);
        return Err(Dropped);
    };
    let rules = shared.policy().rules();
    let body_rules = js::has_rule(&rules, "response-body");
    let original_headers = node_headers(&parts.headers);
    let rewritten_headers = js::apply_header_rules(&original_headers, &rules, "response-header");
    let text = (holding || body_rules).then(|| body_text(&raw, &codec::encodings(&parts.headers)));
    let (body_text, body_changed) = match &text {
        Some(t) if body_rules => js::apply_rules(t, &rules, "response-body"),
        Some(t) => (t.clone(), false),
        None => (String::new(), false),
    };

    let mut status_code = parts.status;
    let mut message = status_message(&parts);
    let (new_headers, new_body) = if holding {
        let (shown, truncated) = js::cap_utf16(&body_text, MAX_BODY_TEXT);
        let decision = shared
            .hold(
                json!({
                    "id": format!("{id}:res"),
                    "flowId": id,
                    "kind": "response",
                    "statusCode": status_code.as_u16(),
                    "statusMessage": message,
                    "headers": rewritten_headers.clone().unwrap_or(original_headers),
                    "body": shown,
                    "bodyTruncated": truncated,
                    "startedAt": now_ms(),
                }),
                None,
            )
            .await;
        if decision.drop {
            report_aborted(&shared, &id);
            return Err(Dropped);
        }
        let new_status = Decision::truthy_string(&decision.status_code)
            .and_then(|s| s.trim().parse::<u16>().ok())
            .and_then(|n| StatusCode::from_u16(n).ok());
        if let Some(new_status) = new_status.filter(|s| *s != status_code) {
            status_code = new_status;
            message = new_status.canonical_reason().unwrap_or_default().to_owned();
        }
        if let Some(m) = Decision::truthy_string(&decision.status_message) {
            message = m;
        }
        (
            decision.headers_object().cloned().or(rewritten_headers),
            decision.edited_body().or(body_changed.then_some(body_text)),
        )
    } else {
        (rewritten_headers, body_changed.then_some(body_text))
    };

    let replaced = new_headers.is_some() || new_body.is_some();
    if let Some(headers) = new_headers {
        parts.headers = headers_from_object(&headers);
    }
    let out = match new_body {
        Some(text) => encode_text(&text, &parts.headers),
        None => raw,
    };
    if replaced {
        fix_content_length(&mut parts.headers, out.len());
    }
    parts.status = status_code;
    parts.extensions.remove::<hyper::ext::ReasonPhrase>();
    if Some(message.as_str()) != status_code.canonical_reason()
        && let Ok(phrase) = hyper::ext::ReasonPhrase::try_from(message.as_bytes())
    {
        parts.extensions.insert(phrase);
    }

    let mut headers_json = node_headers(&parts.headers);
    let mut shown_message = message;
    if h2_client {
        strip_hop_by_hop(&mut parts.headers, true);
        let mut h = Map::new();
        h.insert(":status".into(), json!(status_code.as_u16().to_string()));
        h.extend(node_headers(&parts.headers));
        headers_json = h;
        shown_message = String::new();
    }
    let captured = Captured::from_bytes(&out);
    let mut update = json!({
        "id": id,
        "statusCode": status_code.as_u16(),
        "statusMessage": shown_message,
        "responseHeaders": headers_json,
        "responseBodySize": captured.size,
    });
    if let Some(text) = captured.text() {
        update["responseBody"] = Value::String(text);
    }
    update["completedAt"] = json!(now_ms());
    shared.emit(ProxyEvent::FlowUpdate(update));
    Ok(Response::from_parts(parts, full(out)))
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
