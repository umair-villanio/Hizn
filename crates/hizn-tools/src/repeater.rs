//! Repeater: re-send one HTTP(S) request and return the raw response, like
//! Burp's Repeater. Nothing is auto-followed; headers and body go as given so
//! you can tamper freely. Mirrors the Node `RepeaterService`.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A request to replay. Deserialized straight from the route body, so unknown
/// fields are ignored and shapes match the Node `RepeaterRequest`.
#[derive(Debug, Clone, Deserialize)]
pub struct RepeaterRequest {
    #[serde(default)]
    pub method: Option<String>,
    pub url: String,
    #[serde(default)]
    pub headers: Option<Value>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default, rename = "timeoutMs")]
    pub timeout_ms: Option<u64>,
}

/// The response, matching the Node `RepeaterResponse` JSON (fields omitted when
/// absent).
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepeaterResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Sends replayed requests. One shared client per TLS-verification mode, built
/// lazily; redirects are never followed.
#[derive(Default)]
pub struct Repeater {
    secure: tokio::sync::OnceCell<reqwest::Client>,
    insecure: tokio::sync::OnceCell<reqwest::Client>,
}

impl Repeater {
    pub fn new() -> Self {
        Self::default()
    }

    async fn client(&self, insecure: bool) -> Result<&reqwest::Client, String> {
        let cell = if insecure {
            &self.insecure
        } else {
            &self.secure
        };
        cell.get_or_try_init(|| async move {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .danger_accept_invalid_certs(insecure)
                .danger_accept_invalid_hostnames(insecure)
                // Don't let reqwest add its own Accept-Encoding/decode — send and
                // report bytes as-is, like Node's raw http client.
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .no_zstd()
                .build()
        })
        .await
        .map_err(|e| e.to_string())
    }

    pub async fn send(&self, req: RepeaterRequest) -> RepeaterResponse {
        let started = Instant::now();
        let elapsed = |start: Instant| start.elapsed().as_millis() as u64;

        let Ok(url) = reqwest::Url::parse(&req.url) else {
            return RepeaterResponse {
                error: Some(format!("Invalid URL: {}", req.url)),
                ..Default::default()
            };
        };
        let method = match Method::from_bytes(
            req.method
                .as_deref()
                .unwrap_or("GET")
                .to_uppercase()
                .as_bytes(),
        ) {
            Ok(m) => m,
            Err(_) => {
                return RepeaterResponse {
                    error: Some("Invalid method".into()),
                    ..Default::default()
                };
            }
        };

        // Headers: drop content-length / connection (recomputed), keep the rest.
        let mut headers = HeaderMap::new();
        if let Some(Value::Object(map)) = &req.headers {
            for (name, value) in map {
                let lower = name.to_ascii_lowercase();
                if lower == "content-length" || lower == "connection" {
                    continue;
                }
                let Ok(hname) = HeaderName::from_bytes(name.as_bytes()) else {
                    continue;
                };
                for v in header_values(value) {
                    if let Ok(hv) = HeaderValue::from_str(&v) {
                        headers.append(hname.clone(), hv);
                    }
                }
            }
        }
        if !headers.contains_key(http::header::HOST)
            && let Some(host) = url.host_str()
        {
            let host_val = match url.port() {
                Some(p) => format!("{host}:{p}"),
                None => host.to_owned(),
            };
            if let Ok(hv) = HeaderValue::from_str(&host_val) {
                headers.insert(http::header::HOST, hv);
            }
        }

        let body = req.body.filter(|b| !b.is_empty()).map(|b| b.into_bytes());

        let client = match self.client(req.insecure).await {
            Ok(c) => c,
            Err(e) => {
                return RepeaterResponse {
                    error: Some(e),
                    duration_ms: Some(elapsed(started)),
                    ..Default::default()
                };
            }
        };
        let mut builder = client
            .request(method, url)
            .timeout(Duration::from_millis(req.timeout_ms.unwrap_or(20000)))
            .headers(headers);
        if let Some(body) = body {
            builder = builder.body(body);
        }

        match builder.send().await {
            Ok(res) => {
                let status = res.status();
                let status_message = status.canonical_reason().unwrap_or("").to_owned();
                let headers_json = response_headers(res.headers());
                match res.bytes().await {
                    Ok(bytes) => RepeaterResponse {
                        status_code: Some(status.as_u16()),
                        status_message: Some(status_message),
                        headers: Some(headers_json),
                        body: Some(String::from_utf8_lossy(&bytes).into_owned()),
                        body_size: Some(bytes.len() as u64),
                        duration_ms: Some(elapsed(started)),
                        error: None,
                    },
                    Err(e) => RepeaterResponse {
                        error: Some(node_error(&e)),
                        duration_ms: Some(elapsed(started)),
                        ..Default::default()
                    },
                }
            }
            Err(e) => RepeaterResponse {
                error: Some(node_error(&e)),
                duration_ms: Some(elapsed(started)),
                ..Default::default()
            },
        }
    }
}

/// A header value's text forms (an array becomes several).
fn header_values(v: &Value) -> Vec<String> {
    match v {
        Value::Array(list) => list
            .iter()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect(),
        Value::String(s) => vec![s.clone()],
        Value::Null => vec![],
        other => vec![other.to_string()],
    }
}

/// Response headers as Node's `res.headers`: lowercase keys, repeats combined
/// (except `set-cookie`, which stays an array).
fn response_headers(headers: &HeaderMap) -> Value {
    let mut out: Map<String, Value> = Map::new();
    for name in headers.keys() {
        let key = name.as_str().to_owned();
        let values: Vec<String> = headers
            .get_all(name)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect();
        let value = if key == "set-cookie" {
            Value::Array(values.into_iter().map(Value::String).collect())
        } else {
            Value::String(values.join(", "))
        };
        out.insert(key, value);
    }
    Value::Object(out)
}

/// A timeout reports like Node's; otherwise the message.
fn node_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "Request timed out".into()
    } else {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn response_headers_follow_node_rules() {
        let mut h = HeaderMap::new();
        h.append("Content-Type", HeaderValue::from_static("text/plain"));
        h.append("Set-Cookie", HeaderValue::from_static("a=1"));
        h.append("Set-Cookie", HeaderValue::from_static("b=2"));
        let v = response_headers(&h);
        assert_eq!(v["content-type"], json!("text/plain"));
        assert_eq!(v["set-cookie"], json!(["a=1", "b=2"]));
    }

    #[test]
    fn header_value_forms() {
        assert_eq!(header_values(&json!(["x", "y"])), vec!["x", "y"]);
        assert_eq!(header_values(&json!("z")), vec!["z"]);
        assert!(header_values(&json!(null)).is_empty());
    }
}
