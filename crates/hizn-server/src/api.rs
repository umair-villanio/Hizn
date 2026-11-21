//! The REST surface: all 38 routes of the Node API, mounted under `/api`.
//!
//! Routes not ported yet answer `501` with a JSON `error` (which the UI's
//! `api()` helper shows as a banner), plus the route and the RUST-PORT.md phase
//! that ports it. As phases land, entries move from `PENDING` to `PORTED`.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use axum::extract::{FromRequest, Request, State};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodFilter, MethodRouter, get, post};
use axum::{Json, Router};
use indexmap::IndexMap;
use serde_json::{Value, json};

use hizn_proxy::Decision;

use crate::state::{AppState, ProxyStatus, UpstreamConfig};

/// Not-yet-ported routes: (method, path, phase).
pub const PENDING: &[(&str, &str, u8)] = &[
    ("POST", "/frida/provision", 4),
    ("GET", "/desktop/info", 5),
    ("POST", "/desktop/import-ca", 5),
    ("POST", "/desktop/firefox", 5),
    ("POST", "/repeater/ws/open", 5),
    ("POST", "/repeater/ws/send", 5),
    ("POST", "/repeater/ws/close", 5),
    ("POST", "/analyzer/scan", 5),
    ("GET", "/analyzer/packages", 5),
    ("POST", "/analyzer/scan-device", 5),
    ("GET", "/mcp/info", 5),
    ("GET", "/plugins", 5),
    ("POST", "/plugins", 5),
    ("POST", "/plugins/toggle", 5),
    ("DELETE", "/plugins/{origin}/{file}", 5),
];

/// Routes with a real implementation.
pub const PORTED: &[(&str, &str)] = &[
    ("GET", "/status"),
    ("GET", "/ca"),
    ("POST", "/proxy/start"),
    ("POST", "/proxy/stop"),
    ("POST", "/upstream"),
    ("GET", "/flows"),
    ("POST", "/flows/clear"),
    ("POST", "/flows/import"),
    ("GET", "/intercept"),
    ("POST", "/intercept/config"),
    ("POST", "/intercept/resolve"),
    ("GET", "/rules"),
    ("POST", "/rules"),
    ("GET", "/scope"),
    ("POST", "/scope"),
    ("GET", "/devices"),
    ("GET", "/connections"),
    ("POST", "/connect"),
    ("POST", "/disconnect"),
    ("POST", "/connect/genymotion"),
    ("POST", "/repeater/send"),
    ("POST", "/intruder/start"),
    ("POST", "/intruder/stop"),
];

pub fn router() -> Router<AppState> {
    let mut by_path: IndexMap<&'static str, MethodRouter<AppState>> = IndexMap::new();
    by_path.insert("/status", get(status));
    by_path.insert("/ca", get(ca));
    by_path.insert("/proxy/start", post(proxy_start));
    by_path.insert("/proxy/stop", post(proxy_stop));
    by_path.insert("/upstream", post(set_upstream));
    by_path.insert("/flows", get(flows));
    by_path.insert("/flows/clear", post(flows_clear));
    by_path.insert("/flows/import", post(flows_import));
    by_path.insert("/intercept", get(intercept));
    by_path.insert("/intercept/config", post(intercept_config));
    by_path.insert("/intercept/resolve", post(intercept_resolve));
    by_path.insert("/rules", get(rules).post(set_rules));
    by_path.insert("/scope", get(scope).post(set_scope));
    by_path.insert("/devices", get(devices));
    by_path.insert("/connections", get(connections));
    by_path.insert("/connect", post(connect));
    by_path.insert("/disconnect", post(disconnect));
    by_path.insert("/connect/genymotion", post(connect_genymotion));
    by_path.insert("/repeater/send", post(repeater_send));
    by_path.insert("/intruder/start", post(intruder_start));
    by_path.insert("/intruder/stop", post(intruder_stop));

    for &(method, path, phase) in PENDING {
        let filter = match method {
            "GET" => MethodFilter::GET,
            "POST" => MethodFilter::POST,
            "DELETE" => MethodFilter::DELETE,
            other => unreachable!("unexpected method {other}"),
        };
        let entry = by_path.entry(path).or_default();
        let current = std::mem::replace(entry, MethodRouter::new());
        *entry = current.on(
            filter,
            move || async move { not_ported(method, path, phase) },
        );
    }

    by_path
        .into_iter()
        .fold(Router::new(), |router, (path, methods)| {
            router.route(path, methods)
        })
}

// ---------------------------------------------------------------- handlers

async fn status(State(state): State<AppState>) -> Json<ProxyStatus> {
    let status = state.hub().status();
    Json(status)
}

async fn ca(State(state): State<AppState>) -> Response {
    match state.ca() {
        Ok(ca) => (
            [(CONTENT_TYPE, "application/x-pem-file; charset=utf-8")],
            ca.cert_pem().to_owned(),
        )
            .into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn proxy_start(State(state): State<AppState>, JsonBody(body): JsonBody) -> Response {
    if state.proxy.is_running() {
        let status = state.hub().status();
        return Json(status).into_response();
    }
    // `Number(req.body?.port) || current port`
    let port = match js_number(body.get("port")) {
        n if n.is_nan() || n == 0.0 => state.hub().proxy_port,
        n if n.fract() == 0.0 && (1.0..=65535.0).contains(&n) => n as u16,
        n => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("options.port should be >= 0 and < 65536. Received {n}."),
            );
        }
    };
    state.hub().proxy_port = port;
    let ca = match state.ca() {
        Ok(ca) => ca,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    if let Err(e) = state.proxy.start(port, ca).await {
        return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    let status = {
        let mut hub = state.hub();
        hub.running = true;
        let status = hub.status();
        hub.broadcast(&json!({ "type": "proxy-status", "status": status }));
        status
    };
    Json(status).into_response()
}

async fn proxy_stop(State(state): State<AppState>) -> Json<Value> {
    let was_running = state.proxy.is_running();
    state.proxy.stop().await;
    if was_running {
        let mut hub = state.hub();
        hub.running = false;
        let status = hub.status();
        hub.broadcast(&json!({ "type": "proxy-status", "status": status }));
    }
    Json(json!({ "ok": true }))
}

async fn set_upstream(
    State(state): State<AppState>,
    JsonBody(body): JsonBody,
) -> Json<UpstreamConfig> {
    let upstream = {
        let mut hub = state.hub();
        hub.upstream.enabled = js_truthy(body.get("enabled"));
        if let Some(Value::String(host)) = body.get("host") {
            hub.upstream.host = host.clone();
        }
        let port = js_number(body.get("port"));
        if port.fract() == 0.0 && (1.0..=65535.0).contains(&port) {
            hub.upstream.port = port as u16;
        }
        hub.upstream.clone()
    };
    state.proxy.set_upstream(
        upstream
            .enabled
            .then(|| (upstream.host.clone(), upstream.port)),
    );
    state
        .hub()
        .broadcast(&json!({ "type": "upstream", "upstream": upstream }));
    Json(upstream)
}

async fn flows(State(state): State<AppState>) -> Json<Value> {
    let flows: Vec<Value> = state.hub().flows.values().cloned().collect();
    Json(Value::Array(flows))
}

async fn flows_clear(State(state): State<AppState>) -> Json<Value> {
    let mut hub = state.hub();
    hub.flows.clear();
    hub.broadcast(&json!({ "type": "flows-cleared" }));
    Json(json!({ "ok": true }))
}

async fn flows_import(State(state): State<AppState>, JsonBody(body): JsonBody) -> Json<Value> {
    let incoming = match body.get("flows") {
        Some(Value::Array(list)) => list.clone(),
        _ => Vec::new(),
    };
    let count = state.hub().replace_flows(incoming);
    Json(json!({ "ok": true, "count": count }))
}

// --------------------------------------------- intercept / rules / scope

async fn intercept(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "config": state.proxy.intercept_config(),
        "pending": state.proxy.pending_intercepts(),
    }))
}

/// `setInterceptConfig({ enabled: req.body?.enabled, ... })`: a missing key
/// becomes `undefined`, an explicit `null` stays `null`.
async fn intercept_config(State(state): State<AppState>, JsonBody(body): JsonBody) -> Json<Value> {
    let field = |k: &str| body.get(k).cloned();
    let config =
        state
            .proxy
            .set_intercept_config(field("enabled"), field("requests"), field("responses"));
    Json(Value::Object(config))
}

async fn intercept_resolve(State(state): State<AppState>, JsonBody(body): JsonBody) -> Response {
    let id = body.get("id");
    if !hizn_proxy::js::truthy(id) {
        return error(StatusCode::BAD_REQUEST, "Missing id");
    }
    // Held items are keyed by string ids; anything else can't match.
    let found = match id {
        Some(Value::String(id)) => state
            .proxy
            .resolve_intercept(id, Decision::from_json(&body)),
        _ => false,
    };
    if !found {
        return error(
            StatusCode::NOT_FOUND,
            "No such held item (already resolved?)",
        );
    }
    Json(json!({ "ok": true })).into_response()
}

async fn rules(State(state): State<AppState>) -> Json<Value> {
    Json(Value::Array(state.proxy.rules()))
}

async fn set_rules(State(state): State<AppState>, JsonBody(body): JsonBody) -> Json<Value> {
    let rules = match body.get("rules") {
        Some(Value::Array(list)) => list.clone(),
        _ => Vec::new(),
    };
    Json(Value::Array(state.proxy.set_rules(rules)))
}

async fn scope(State(state): State<AppState>) -> Json<Value> {
    Json(state.proxy.scope().to_json())
}

async fn set_scope(State(state): State<AppState>, JsonBody(body): JsonBody) -> Json<Value> {
    Json(
        state
            .proxy
            .set_scope(body.get("enabled"), body.get("hosts"))
            .to_json(),
    )
}

// ----------------------------------------------------- repeater / intruder

async fn repeater_send(State(state): State<AppState>, JsonBody(body): JsonBody) -> Response {
    // `url` is required; an invalid shape is a 400, as Node's route threw.
    match serde_json::from_value::<hizn_tools::RepeaterRequest>(body) {
        Ok(req) => Json(state.repeater.send(req).await).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// Normalize payloads like Node: an array → `String(x)` each; a string → split
/// on `\n` with a trailing `\r` trimmed; anything else → empty.
fn norm_payloads(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(list)) => list.iter().map(hizn_proxy::js::string).collect(),
        Some(Value::String(s)) => s
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l).to_owned())
            .collect(),
        _ => Vec::new(),
    }
}

async fn intruder_start(State(state): State<AppState>, JsonBody(body): JsonBody) -> Response {
    if state.intruder.is_running() {
        return error(StatusCode::CONFLICT, "An attack is already running");
    }
    let template = hizn_tools::Template {
        method: body
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned),
        url: body
            .get("url")
            .map(hizn_proxy::js::string)
            .unwrap_or_default(),
        headers: body.get("headers").cloned(),
        body: body.get("body").and_then(Value::as_str).map(str::to_owned),
        insecure: js_truthy(body.get("insecure")),
    };
    let payloads = norm_payloads(body.get("payloads"));
    let attack = hizn_tools::AttackType::parse(body.get("attackType").and_then(Value::as_str));
    let positions = hizn_tools::count_positions(&template);
    if template.url.is_empty() {
        return error(StatusCode::BAD_REQUEST, "A URL is required");
    }
    if positions == 0 {
        return error(
            StatusCode::BAD_REQUEST,
            "No payload positions — wrap a value in § markers, e.g. §FUZZ§",
        );
    }
    if payloads.is_empty() {
        return error(StatusCode::BAD_REQUEST, "No payloads provided");
    }
    // Fire-and-forget: progress streams over the WebSocket.
    let url_encode = js_truthy(body.get("urlEncode"));
    let intruder = state.intruder.clone();
    let sink = state.intruder_sink.clone();
    tokio::spawn(async move {
        intruder
            .run(template, attack, payloads, url_encode, &sink)
            .await;
    });
    Json(json!({ "ok": true, "positions": positions, "attackType": attack.as_str() }))
        .into_response()
}

async fn intruder_stop(State(state): State<AppState>) -> Json<Value> {
    state.intruder.stop();
    Json(json!({ "ok": true }))
}

// ----------------------------------------------------- devices / one-click

async fn devices(State(state): State<AppState>) -> Response {
    match state.orchestrator.devices().list().await {
        Ok(list) => Json(list).into_response(),
        // Node surfaced ADB errors as a 500 from the route's throw.
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn connections(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "connected": state.connected() }))
}

/// The one-click button. Builds the orchestrator options from the body and
/// streams `setup-step` events as it runs.
async fn connect(State(state): State<AppState>, JsonBody(body): JsonBody) -> Response {
    let opts = hizn_devices::SetupOptions {
        serial: string_field(&body, "serial").unwrap_or_default(),
        frida_target: nonempty(&body, "fridaTarget"),
        host_ip: nonempty(&body, "hostIp"),
        emulator: false,
    };
    run_one_click(&state, opts).await
}

/// Find the Genymotion VM (optionally attaching one by IP first) and capture
/// all its traffic — system-wide proxy + system-store CA, no Frida.
async fn connect_genymotion(State(state): State<AppState>, JsonBody(body): JsonBody) -> Response {
    if let Some(ip) = nonempty(&body, "ip") {
        // May already be attached; ignore the result either way.
        let _ = state.orchestrator.devices().adb().connect(&ip).await;
    }
    let device = match state.orchestrator.devices().find_genymotion().await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return error(
                StatusCode::NOT_FOUND,
                "No Genymotion/emulator detected. Start the VM and make sure its ADB is enabled.",
            );
        }
        Err(e) => return error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let opts = hizn_devices::SetupOptions {
        serial: device.serial,
        frida_target: None,
        host_ip: nonempty(&body, "hostIp"),
        emulator: true,
    };
    run_one_click(&state, opts).await
}

async fn run_one_click(state: &AppState, opts: hizn_devices::SetupOptions) -> Response {
    let bridge = state.proxy_bridge();
    let step_state = state.clone();
    let sink: hizn_devices::StepSink = Box::new(move |step| step_state.broadcast_step(step));
    // Frida injection is not ported yet (Phase 4 follow-up); the step is skipped.
    let result = state
        .orchestrator
        .run_one_click(opts, &bridge, &sink, None)
        .await;
    match result {
        Ok(result) => {
            state.mark_connected(&result.device.serial);
            Json(result).into_response()
        }
        Err(e) => error(StatusCode::BAD_REQUEST, e),
    }
}

async fn disconnect(State(state): State<AppState>, JsonBody(body): JsonBody) -> Json<Value> {
    if let Some(serial) = string_field(&body, "serial") {
        let port = state.hub().proxy_port;
        state.orchestrator.disconnect(&serial, port).await;
        state.mark_disconnected(&serial);
    }
    Json(json!({ "ok": true }))
}

// ----------------------------------------------------------------- helpers

fn string_field(body: &Value, key: &str) -> Option<String> {
    body.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// `req.body?.x || undefined`: the value only when it's a non-empty string.
fn nonempty(body: &Value, key: &str) -> Option<String> {
    string_field(body, key).filter(|s| !s.is_empty())
}

/// Request JSON, read like Express's `express.json()`: parsed only for JSON
/// content types (anything else reads as no body), `400` on malformed JSON.
/// The limit is far above Express's 100 KB so large saved sessions import.
pub struct JsonBody(pub Value);

const MAX_JSON_BODY: usize = 600 * 1024 * 1024;

impl<S: Send + Sync> FromRequest<S> for JsonBody {
    type Rejection = Response;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Response> {
        let is_json = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.to_ascii_lowercase().contains("json"));
        let bytes = axum::body::to_bytes(req.into_body(), MAX_JSON_BODY)
            .await
            .map_err(|e| error(StatusCode::PAYLOAD_TOO_LARGE, e.to_string()))?;
        if !is_json || bytes.is_empty() {
            return Ok(Self(Value::Null));
        }
        serde_json::from_slice(&bytes)
            .map(Self)
            .map_err(|e| error(StatusCode::BAD_REQUEST, e.to_string()))
    }
}

/// JavaScript `Number(value)` for JSON input.
fn js_number(v: Option<&Value>) -> f64 {
    match v {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) if s.trim().is_empty() => 0.0,
        Some(Value::String(s)) => s.trim().parse().unwrap_or(f64::NAN),
        Some(_) => f64::NAN,
    }
}

/// JavaScript `!!value` for JSON input.
fn js_truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

fn not_ported(method: &str, path: &str, phase: u8) -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": format!(
                "{method} /api{path} is not available in the Rust backend yet (phase {phase} of the port)."
            ),
            "route": format!("{method} {path}"),
            "phase": phase,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn route_table_covers_the_whole_node_api() {
        let all: Vec<(&str, &str)> = PENDING
            .iter()
            .map(|&(m, p, _)| (m, p))
            .chain(PORTED.iter().copied())
            .collect();
        assert_eq!(all.len(), 38, "the Node API has 38 routes");
        let unique: HashSet<_> = all.iter().collect();
        assert_eq!(unique.len(), all.len(), "duplicate route in the table");
    }

    #[test]
    fn router_builds_without_conflicts() {
        let _ = router();
    }

    #[test]
    fn js_number_and_truthy_match_javascript() {
        assert!(js_number(None).is_nan());
        assert_eq!(js_number(Some(&json!("8001"))), 8001.0);
        assert_eq!(js_number(Some(&json!(""))), 0.0);
        assert!(js_number(Some(&json!("abc"))).is_nan());
        assert!(js_truthy(Some(&json!(1))));
        assert!(!js_truthy(Some(&json!(""))));
        assert!(!js_truthy(None));
        assert!(js_truthy(Some(&json!({}))));
    }
}
