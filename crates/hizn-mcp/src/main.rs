//! hizn-mcp — a Model Context Protocol (MCP) server for Hizn.
//!
//! Exposes Hizn's capabilities as MCP tools over newline-delimited JSON-RPC 2.0
//! on stdio, talking to Hizn's local REST API (so Hizn must be running). The
//! Rust port of the Node `mcp-server.ts`.
//!
//! Config (environment):
//!   HIZN_API_URL     base URL of the Hizn API (default http://127.0.0.1:4000)
//!   HIZN_MCP_ACTIVE  1/true/yes/on to also expose the state-changing tools
//!
//! stdout carries the protocol — logs go to stderr only.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::sync::OnceLock;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const SERVER_NAME: &str = "hizn";
const SERVER_VERSION: &str = "0.2.0";

fn api_base() -> &'static str {
    static B: OnceLock<String> = OnceLock::new();
    B.get_or_init(|| {
        std::env::var("HIZN_API_URL").unwrap_or_else(|_| "http://127.0.0.1:4000".into())
    })
}

fn active_on() -> bool {
    static A: OnceLock<bool> = OnceLock::new();
    *A.get_or_init(|| {
        let v = std::env::var("HIZN_MCP_ACTIVE")
            .unwrap_or_default()
            .to_lowercase();
        matches!(v.as_str(), "1" | "true" | "yes" | "on")
    })
}

fn log(msg: &str) {
    eprintln!("[hizn-mcp] {msg}");
}

fn client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("build http client")
    })
}

/// How to send an API request.
enum Payload {
    None,
    Json(Value),
    Raw { bytes: Vec<u8>, name: String },
}

/// Call the Hizn REST API at `/api<path>`.
async fn api(path: &str, payload: Payload) -> Result<Value, String> {
    let url = format!("{}/api{}", api_base().trim_end_matches('/'), path);
    let (method, builder) = match payload {
        Payload::None => (reqwest::Method::GET, client().get(&url)),
        Payload::Json(body) => (reqwest::Method::POST, client().post(&url).json(&body)),
        Payload::Raw { bytes, name } => {
            let sep = if url.contains('?') { "&" } else { "?" };
            let url = format!("{url}{sep}name={}", urlencode(&name));
            (
                reqwest::Method::POST,
                client()
                    .post(&url)
                    .header("Content-Type", "application/octet-stream")
                    .body(bytes),
            )
        }
    };
    let _ = method;
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("Cannot reach Hizn at {} — is it running? ({e})", api_base()))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    let data: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
    if status.as_u16() >= 400 {
        let msg = data
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
        return Err(msg);
    }
    Ok(data)
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

struct Tool {
    name: &'static str,
    description: &'static str,
    schema: fn() -> Value,
    active: bool,
}

/// `{ type: 'object', properties, required }`
fn obj(props: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": props, "required": required })
}

fn tools() -> &'static [Tool] {
    static T: OnceLock<Vec<Tool>> = OnceLock::new();
    T.get_or_init(|| {
        vec![
            Tool { name: "hizn_status", active: false,
                description: "Get Hizn proxy status (running, port, upstream, intercept config).",
                schema: || obj(json!({}), &[]) },
            Tool { name: "list_flows", active: false,
                description: "List captured HTTP flows (most recent last). Returns a compact summary.",
                schema: || obj(json!({ "limit": { "type": "number", "description": "Max flows to return (default 50)." }, "filter": { "type": "string", "description": "Case-insensitive substring over method/host/path." } }), &[]) },
            Tool { name: "get_flow", active: false,
                description: "Get one captured flow in full (headers + captured bodies) by its id.",
                schema: || obj(json!({ "id": { "type": "string", "description": "Flow id from list_flows." } }), &["id"]) },
            Tool { name: "list_devices", active: false,
                description: "List ADB devices Hizn can see, with model/root/emulator info.",
                schema: || obj(json!({}), &[]) },
            Tool { name: "get_scope", active: false,
                description: "Get the current target scope (interception is limited to these hosts).",
                schema: || obj(json!({}), &[]) },
            Tool { name: "get_intercept", active: false,
                description: "Get the interception config and any currently-held requests/responses.",
                schema: || obj(json!({}), &[]) },
            Tool { name: "list_device_apps", active: false,
                description: "List installed (third-party) app package names on a device.",
                schema: || obj(json!({ "serial": { "type": "string", "description": "Device serial from list_devices." } }), &["serial"]) },
            Tool { name: "scan_apk", active: false,
                description: "Static-scan an APK and return the report (permissions, exported components, signing certificate, manifest analysis, hardcoded secrets, URLs). Provide a local file \"path\", OR \"serial\" + \"package\" to pull it off a device.",
                schema: || obj(json!({ "path": { "type": "string", "description": "Local .apk file path." }, "serial": { "type": "string", "description": "Device serial (with package)." }, "package": { "type": "string", "description": "Installed package name to pull + scan." } }), &[]) },
            Tool { name: "start_proxy", active: true,
                description: "Start the interception proxy.",
                schema: || obj(json!({ "port": { "type": "number", "description": "Listener port (optional)." } }), &[]) },
            Tool { name: "stop_proxy", active: true,
                description: "Stop the interception proxy.",
                schema: || obj(json!({}), &[]) },
            Tool { name: "send_request", active: true,
                description: "Send an HTTP(S) request and return the raw response (like Repeater).",
                schema: || obj(json!({ "method": { "type": "string" }, "url": { "type": "string" }, "headers": { "type": "object", "description": "Header name→value map." }, "body": { "type": "string" }, "insecure": { "type": "boolean", "description": "Skip TLS verification." } }), &["url"]) },
            Tool { name: "start_intruder", active: true,
                description: "Launch an Intruder attack. Mark payload positions in url/headers/body with § markers. Results stream in Hizn; this returns the plan (poll Hizn UI for rows).",
                schema: || obj(json!({ "url": { "type": "string", "description": "Target URL, may contain §…§ positions." }, "method": { "type": "string" }, "headers": { "type": "object" }, "body": { "type": "string" }, "attackType": { "type": "string", "enum": ["sniper", "batteringram"] }, "payloads": { "type": "array", "items": { "type": "string" }, "description": "Payload list." }, "urlEncode": { "type": "boolean" }, "insecure": { "type": "boolean" } }), &["url", "payloads"]) },
            Tool { name: "stop_intruder", active: true,
                description: "Stop the running Intruder attack.",
                schema: || obj(json!({}), &[]) },
            Tool { name: "set_scope", active: true,
                description: "Set the target scope (limit interception to these hosts).",
                schema: || obj(json!({ "enabled": { "type": "boolean" }, "hosts": { "type": "array", "items": { "type": "string" }, "description": "Host patterns (substring or *wildcard)." } }), &["enabled"]) },
            Tool { name: "resolve_intercept", active: true,
                description: "Forward or drop a held request/response (optionally edited). Use get_intercept for the id.",
                schema: || obj(json!({ "id": { "type": "string" }, "action": { "type": "string", "enum": ["forward", "drop"] }, "headers": { "type": "object" }, "body": { "type": "string" }, "bodyEdited": { "type": "boolean" }, "method": { "type": "string" }, "url": { "type": "string" }, "statusCode": { "type": "number" }, "interceptResponse": { "type": "boolean" } }), &["id", "action"]) },
        ]
    })
}

fn available() -> impl Iterator<Item = &'static Tool> {
    tools().iter().filter(|t| active_on() || !t.active)
}

/// Dispatch a tool call to the REST API.
async fn call_tool(name: &str, args: &Value) -> Result<Value, String> {
    let a = |k: &str| args.get(k).cloned();
    match name {
        "hizn_status" => api("/status", Payload::None).await,
        "list_flows" => {
            let flows = api("/flows", Payload::None).await?;
            let filter = args.get("filter").and_then(Value::as_str).unwrap_or("").to_lowercase();
            let limit = args.get("limit").and_then(Value::as_f64).unwrap_or(50.0) as usize;
            let empty = Vec::new();
            let all = flows.as_array().unwrap_or(&empty);
            let mut rows: Vec<Value> = all
                .iter()
                .filter(|x| {
                    filter.is_empty() || {
                        let hay = format!(
                            "{} {} {}",
                            x.get("method").and_then(Value::as_str).unwrap_or(""),
                            x.get("host").and_then(Value::as_str).unwrap_or(""),
                            x.get("path").and_then(Value::as_str).unwrap_or("")
                        )
                        .to_lowercase();
                        hay.contains(&filter)
                    }
                })
                .map(|x| json!({ "id": x.get("id"), "method": x.get("method"), "status": x.get("statusCode"), "host": x.get("host"), "path": x.get("path"), "size": x.get("responseBodySize") }))
                .collect();
            if rows.len() > limit {
                rows = rows.split_off(rows.len() - limit);
            }
            Ok(json!({ "count": rows.len(), "flows": rows }))
        }
        "get_flow" => {
            let id = a("id");
            let flows = api("/flows", Payload::None).await?;
            flows
                .as_array()
                .and_then(|arr| arr.iter().find(|x| x.get("id") == id.as_ref()).cloned())
                .ok_or_else(|| format!("No flow with id {}", id.and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default()))
        }
        "list_devices" => api("/devices", Payload::None).await,
        "get_scope" => api("/scope", Payload::None).await,
        "get_intercept" => api("/intercept", Payload::None).await,
        "list_device_apps" => {
            let serial = args.get("serial").and_then(Value::as_str).unwrap_or("");
            api(&format!("/analyzer/packages?serial={}", urlencode(serial)), Payload::None).await
        }
        "scan_apk" => {
            let report = if let Some(path) = args.get("path").and_then(Value::as_str) {
                let bytes = tokio::fs::read(path).await.map_err(|e| e.to_string())?;
                let name = std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "upload.apk".into());
                api("/analyzer/scan", Payload::Raw { bytes, name }).await?
            } else if let (Some(serial), Some(pkg)) = (args.get("serial").and_then(Value::as_str), args.get("package").and_then(Value::as_str)) {
                api("/analyzer/scan-device", Payload::Json(json!({ "serial": serial, "package": pkg }))).await?
            } else {
                return Err("Provide \"path\", or \"serial\" + \"package\".".into());
            };
            // Trim the heaviest arrays, like the Node tool.
            let mut out = report.clone();
            if let Value::Object(map) = &mut out {
                let urls: Vec<Value> = report.get("urls").and_then(Value::as_array).map(|a| a.iter().take(60).cloned().collect()).unwrap_or_default();
                let comp_count = report.get("components").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
                map.insert("urls".into(), Value::Array(urls));
                map.remove("components");
                map.insert("componentsCount".into(), json!(comp_count));
            }
            Ok(out)
        }
        "start_proxy" => api("/proxy/start", Payload::Json(json!({ "port": a("port") }))).await,
        "stop_proxy" => api("/proxy/stop", Payload::Json(json!({}))).await,
        "send_request" => api("/repeater/send", Payload::Json(json!({ "method": a("method"), "url": a("url"), "headers": a("headers"), "body": a("body"), "insecure": a("insecure") }))).await,
        "start_intruder" => api("/intruder/start", Payload::Json(args.clone())).await,
        "stop_intruder" => api("/intruder/stop", Payload::Json(json!({}))).await,
        "set_scope" => api("/scope", Payload::Json(json!({ "enabled": a("enabled"), "hosts": a("hosts") }))).await,
        "resolve_intercept" => api("/intercept/resolve", Payload::Json(args.clone())).await,
        _ => Err(format!("Unknown tool: {name}")),
    }
}

async fn send(out: &mut (impl AsyncWriteExt + Unpin), msg: &Value) {
    let mut line = serde_json::to_string(msg).unwrap_or_default();
    line.push('\n');
    let _ = out.write_all(line.as_bytes()).await;
    let _ = out.flush().await;
}

async fn handle(msg: &Value, out: &mut (impl AsyncWriteExt + Unpin)) {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    if method == "notifications/initialized" || method == "notifications/cancelled" {
        return;
    }
    let reply = |result: Value| json!({ "jsonrpc": "2.0", "id": id, "result": result });

    match method {
        "initialize" => {
            let pv = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2024-11-05");
            send(
                out,
                &reply(json!({
                    "protocolVersion": pv,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
                })),
            )
            .await;
        }
        "ping" => send(out, &reply(json!({}))).await,
        "tools/list" => {
            let list: Vec<Value> = available()
                .map(|t| json!({ "name": t.name, "description": t.description, "inputSchema": (t.schema)() }))
                .collect();
            send(out, &reply(json!({ "tools": list }))).await;
        }
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let is_available = available().any(|t| t.name == name);
            if !is_available {
                let gated = tools().iter().any(|t| t.name == name && t.active);
                let text = if gated {
                    format!(
                        "Tool \"{name}\" is an active tool and is disabled. Start the server with HIZN_MCP_ACTIVE=1 to enable traffic-sending / state-changing tools."
                    )
                } else {
                    format!("Unknown tool: {name}")
                };
                send(
                    out,
                    &reply(
                        json!({ "content": [{ "type": "text", "text": text }], "isError": true }),
                    ),
                )
                .await;
                return;
            }
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            match call_tool(name, &args).await {
                Ok(result) => {
                    let mut text = match &result {
                        Value::String(s) => s.clone(),
                        other => serde_json::to_string_pretty(other).unwrap_or_default(),
                    };
                    text.truncate(100_000);
                    send(out, &reply(json!({ "content": [{ "type": "text", "text": text }] }))).await;
                }
                Err(e) => send(out, &reply(json!({ "content": [{ "type": "text", "text": format!("Error: {e}") }], "isError": true }))).await,
            }
        }
        _ => {
            if id.is_some() {
                send(out, &json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("Method not found: {method}") } })).await;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    log(&format!(
        "ready · API {} · {} tools · active={}",
        api_base(),
        available().count(),
        if active_on() { "on" } else { "off" }
    ));

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(msg) => handle(&msg, &mut out).await,
            Err(_) => log("bad JSON line"),
        }
    }
}
