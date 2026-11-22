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
pub const PENDING: &[(&str, &str, u8)] = &[];

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
    ("POST", "/frida/provision"),
    ("POST", "/repeater/send"),
    ("POST", "/intruder/start"),
    ("POST", "/intruder/stop"),
    ("POST", "/repeater/ws/open"),
    ("POST", "/repeater/ws/send"),
    ("POST", "/repeater/ws/close"),
    ("POST", "/analyzer/scan"),
    ("GET", "/analyzer/packages"),
    ("POST", "/analyzer/scan-device"),
    ("GET", "/desktop/info"),
    ("POST", "/desktop/import-ca"),
    ("POST", "/desktop/firefox"),
    ("GET", "/mcp/info"),
    ("GET", "/plugins"),
    ("POST", "/plugins"),
    ("POST", "/plugins/toggle"),
    ("DELETE", "/plugins/{origin}/{file}"),
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
    by_path.insert("/frida/provision", post(frida_provision));
    by_path.insert("/repeater/send", post(repeater_send));
    by_path.insert("/intruder/start", post(intruder_start));
    by_path.insert("/intruder/stop", post(intruder_stop));
    by_path.insert("/repeater/ws/open", post(ws_open));
    by_path.insert("/repeater/ws/send", post(ws_send));
    by_path.insert("/repeater/ws/close", post(ws_close));
    // The APK is POSTed as the raw body; lift the body limit to 600 MB.
    by_path.insert(
        "/analyzer/scan",
        post(analyzer_scan).layer(axum::extract::DefaultBodyLimit::max(600 * 1024 * 1024)),
    );
    by_path.insert("/analyzer/packages", get(analyzer_packages));
    by_path.insert("/analyzer/scan-device", post(analyzer_scan_device));
    by_path.insert("/desktop/info", get(desktop_info));
    by_path.insert("/desktop/import-ca", post(desktop_import_ca));
    by_path.insert("/desktop/firefox", post(desktop_firefox));
    by_path.insert("/mcp/info", get(mcp_info));
    by_path.insert("/plugins", get(plugins_list).post(plugins_install));
    by_path.insert("/plugins/toggle", post(plugins_toggle));
    by_path.insert(
        "/plugins/{origin}/{file}",
        axum::routing::delete(plugins_delete),
    );

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

// --------------------------------------------------------------- analyzer

async fn analyzer_scan(State(_state): State<AppState>, request: Request) -> Response {
    // The display name comes from the ?name= query.
    let name = request
        .uri()
        .query()
        .and_then(|q| form_urlencoded_get(q, "name"));
    let bytes = match axum::body::to_bytes(request.into_body(), 600 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => return error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    if bytes.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "Empty upload — POST the .apk as the raw request body.",
        );
    }
    // Analysis is CPU-bound binary parsing; keep it off the async executor.
    let report = tokio::task::spawn_blocking(move || {
        hizn_analyzer::analyze_to_json(&bytes, name.as_deref())
    })
    .await
    .unwrap_or_else(|_| json!({ "errors": ["analysis task failed"] }));
    Json(report).into_response()
}

async fn analyzer_packages(State(state): State<AppState>, request: Request) -> Response {
    let query = request.uri().query().unwrap_or("");
    let serial = form_urlencoded_get(query, "serial").unwrap_or_default();
    if serial.is_empty() {
        return error(StatusCode::BAD_REQUEST, "serial is required");
    }
    // `all=1` includes system packages (Node checked `all !== '1'` for the flag).
    let third_party_only = form_urlencoded_get(query, "all").as_deref() != Some("1");
    match state
        .orchestrator
        .devices()
        .list_installed_packages(&serial, third_party_only)
        .await
    {
        Ok(packages) => Json(json!({ "packages": packages })).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn analyzer_scan_device(State(state): State<AppState>, JsonBody(body): JsonBody) -> Response {
    let serial = string_field(&body, "serial").unwrap_or_default();
    let pkg = string_field(&body, "package").unwrap_or_default();
    if serial.is_empty() || pkg.is_empty() {
        return error(StatusCode::BAD_REQUEST, "serial and package are required");
    }
    let devices = state.orchestrator.devices();
    let paths = match devices.apk_paths(&serial, &pkg).await {
        Ok(p) if !p.is_empty() => p,
        Ok(_) => {
            return error(
                StatusCode::NOT_FOUND,
                format!("No APK path found for {pkg}"),
            );
        }
        Err(e) => return error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    // Prefer base.apk for split installs.
    let base = paths
        .iter()
        .find(|p| p.ends_with("base.apk"))
        .cloned()
        .unwrap_or_else(|| paths[0].clone());
    let bytes = match devices.adb().pull_bytes(&serial, &base).await {
        Ok(b) if !b.is_empty() => b,
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "Failed to pull the APK from the device",
            );
        }
    };
    let name = format!("{pkg}.apk");
    let report =
        tokio::task::spawn_blocking(move || hizn_analyzer::analyze_to_json(&bytes, Some(&name)))
            .await
            .unwrap_or_else(|_| json!({ "errors": ["analysis task failed"] }));
    Json(report).into_response()
}

/// First value of `key` in a `application/x-www-form-urlencoded` query string.
fn form_urlencoded_get(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

/// Minimal percent-decode (`+` → space) for query values.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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

async fn ws_open(State(state): State<AppState>, JsonBody(body): JsonBody) -> Response {
    let url = body
        .get("url")
        .map(hizn_proxy::js::string)
        .unwrap_or_default();
    match state
        .ws_repeater
        .open(&url, body.get("headers"), js_truthy(body.get("insecure")))
    {
        Ok(id) => Json(json!({ "ok": true, "id": id })).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e),
    }
}

async fn ws_send(State(state): State<AppState>, JsonBody(body): JsonBody) -> Response {
    let id = body
        .get("id")
        .map(hizn_proxy::js::string)
        .unwrap_or_default();
    let data = body
        .get("data")
        .map(hizn_proxy::js::string)
        .unwrap_or_default();
    match state
        .ws_repeater
        .send(&id, data, js_truthy(body.get("isBinary")))
    {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e),
    }
}

async fn ws_close(State(state): State<AppState>, JsonBody(body): JsonBody) -> Json<Value> {
    let id = body
        .get("id")
        .map(hizn_proxy::js::string)
        .unwrap_or_default();
    state.ws_repeater.close(&id);
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

/// Download + push + start frida-server for a device (rooted).
async fn frida_provision(State(state): State<AppState>, JsonBody(body): JsonBody) -> Response {
    let serial = string_field(&body, "serial").unwrap_or_default();
    let devices = state.orchestrator.devices();
    let device = match devices.list().await {
        Ok(list) => list.into_iter().find(|d| d.serial == serial),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let Some(device) = device else {
        return error(StatusCode::NOT_FOUND, "Device not found");
    };
    let Some(abi) = device.abi.as_deref() else {
        return error(StatusCode::BAD_REQUEST, "Unknown device ABI");
    };
    let version = string_field(&body, "version")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "latest".into());
    match hizn_devices::provision_server(devices.adb(), &serial, abi, &version).await {
        Ok(result) => Json(result).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
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

// --------------------------------------------------------------- desktop

async fn desktop_info(State(state): State<AppState>) -> Json<Value> {
    let proxy_port = state.hub().proxy_port;
    let desktop = state.desktop.clone();
    Json(
        tokio::task::spawn_blocking(move || desktop.info_full(proxy_port))
            .await
            .unwrap_or_else(|_| json!({})),
    )
}

async fn desktop_import_ca(State(state): State<AppState>) -> Response {
    let ca = match state.ca() {
        Ok(ca) => ca.cert_pem().to_owned(),
        Err(e) => return error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let desktop = state.desktop.clone();
    let result = tokio::task::spawn_blocking(move || desktop.auto_import_ca(&ca))
        .await
        .unwrap_or_else(|_| json!({ "imported": false }));
    Json(result).into_response()
}

async fn desktop_firefox(State(state): State<AppState>) -> Response {
    // Start the proxy first (like Node), so Firefox has something to hit.
    if !state.proxy.is_running() {
        let port = state.hub().proxy_port;
        match state.ca() {
            Ok(ca) => {
                if let Err(e) = state.proxy.start(port, ca).await {
                    return error(StatusCode::BAD_REQUEST, e.to_string());
                }
                let mut hub = state.hub();
                hub.running = true;
                let status = hub.status();
                hub.broadcast(&json!({ "type": "proxy-status", "status": status }));
            }
            Err(e) => return error(StatusCode::BAD_REQUEST, e.to_string()),
        }
    }
    let proxy_port = state.hub().proxy_port;
    let ca = match state.ca() {
        Ok(ca) => ca.cert_pem().to_owned(),
        Err(e) => return error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let desktop = state.desktop.clone();
    let result = tokio::task::spawn_blocking(move || desktop.launch_firefox(proxy_port, &ca))
        .await
        .unwrap_or_else(|_| Err("launch task failed".into()));
    match result {
        Ok(info) => Json(info).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e),
    }
}

// ----------------------------------------------------------- mcp / plugins

async fn mcp_info(State(state): State<AppState>) -> Json<Value> {
    // The MCP bridge binary (hizn-mcp) sits next to the running executable.
    let server_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(mcp_binary_name())))
        .unwrap_or_default();
    let port = state.hub().api_port;
    Json(json!({
        "serverPath": server_path.to_string_lossy(),
        "exists": server_path.is_file(),
        "apiUrl": format!("http://127.0.0.1:{port}"),
        "tools": {
            "readonly": ["hizn_status", "list_flows", "get_flow", "list_devices", "list_device_apps", "get_scope", "get_intercept", "scan_apk"],
            "active": ["start_proxy", "stop_proxy", "send_request", "start_intruder", "stop_intruder", "set_scope", "resolve_intercept"],
        },
    }))
}

fn mcp_binary_name() -> &'static str {
    if cfg!(windows) {
        "hizn-mcp.exe"
    } else {
        "hizn-mcp"
    }
}

async fn plugins_list(State(state): State<AppState>) -> Json<Value> {
    let plugins = state.plugins.clone();
    let (list, dirs) = tokio::task::spawn_blocking(move || (plugins.list(), plugins.dirs()))
        .await
        .unwrap_or_else(|_| (Vec::new(), json!({})));
    Json(json!({ "plugins": list, "dirs": dirs }))
}

async fn plugins_install(State(state): State<AppState>, JsonBody(body): JsonBody) -> Response {
    let name = string_field(&body, "name").unwrap_or_default();
    let source = string_field(&body, "source").unwrap_or_default();
    if name.is_empty() || source.is_empty() {
        return error(StatusCode::BAD_REQUEST, "name and source are required");
    }
    let desc = string_field(&body, "desc");
    let author = string_field(&body, "author");
    let plugins = state.plugins.clone();
    let result = tokio::task::spawn_blocking(move || {
        plugins.install(&name, desc.as_deref(), author.as_deref(), &source)
    })
    .await
    .unwrap_or_else(|_| Err("install task failed".into()));
    match result {
        Ok(info) => Json(info).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e),
    }
}

async fn plugins_toggle(State(state): State<AppState>, JsonBody(body): JsonBody) -> Json<Value> {
    if let Some(id) = string_field(&body, "id") {
        let enabled = js_truthy(body.get("enabled"));
        let plugins = state.plugins.clone();
        let _ = tokio::task::spawn_blocking(move || plugins.set_enabled(&id, enabled)).await;
    }
    Json(json!({ "ok": true }))
}

async fn plugins_delete(
    State(state): State<AppState>,
    path: axum::extract::Path<(String, String)>,
) -> Response {
    let axum::extract::Path((origin, file)) = path;
    let id = format!("{origin}/{file}");
    let plugins = state.plugins.clone();
    let result = tokio::task::spawn_blocking(move || plugins.remove(&id))
        .await
        .unwrap_or_else(|_| Err("delete task failed".into()));
    match result {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e),
    }
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
