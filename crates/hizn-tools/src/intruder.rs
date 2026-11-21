//! Intruder: automated request fuzzing, like Burp's Intruder. A template with
//! §…§ payload positions plus a payload list; one request per job through the
//! Repeater, a streamed row each. Mirrors the Node `IntruderService`.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::repeater::{Repeater, RepeaterRequest};

/// Hard ceiling on requests per attack.
const MAX_REQUESTS: usize = 5000;
/// Cap on the per-row response body kept for the detail view.
const MAX_ROW_BODY: usize = 256 * 1024;

#[derive(Debug, Clone, Deserialize)]
pub struct Template {
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub headers: Option<Value>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AttackType {
    Sniper,
    BatteringRam,
}

impl AttackType {
    pub fn parse(s: Option<&str>) -> Self {
        if s == Some("batteringram") {
            Self::BatteringRam
        } else {
            Self::Sniper
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sniper => "sniper",
            Self::BatteringRam => "batteringram",
        }
    }
}

/// Events emitted during an attack; the server broadcasts them as
/// `intruder-start` / `intruder-row` / `intruder-done`.
#[derive(Debug, Clone)]
pub enum IntruderEvent {
    Start(Value),
    Row(Value),
    Done(Value),
}

pub type IntruderSink = Arc<dyn Fn(IntruderEvent) + Send + Sync>;

/// Count §…§ positions across url, header values and body (non-greedy, as the
/// Node `MARKER` regex matches).
pub fn count_positions(t: &Template) -> usize {
    let mut n = count_markers(&t.url);
    if let Some(Value::Object(map)) = &t.headers {
        for v in map.values() {
            match v {
                Value::Array(list) => {
                    for x in list {
                        if let Some(s) = x.as_str() {
                            n += count_markers(s);
                        }
                    }
                }
                Value::String(s) => n += count_markers(s),
                _ => {}
            }
        }
    }
    if let Some(body) = &t.body {
        n += count_markers(body);
    }
    n
}

fn count_markers(s: &str) -> usize {
    markers(s).len()
}

/// Byte ranges of each `§…§` region (inclusive of the markers), non-greedy.
fn markers(s: &str) -> Vec<(usize, usize)> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\xc2' && i + 1 < bytes.len() && bytes[i + 1] == 0xa7 {
            // U+00A7 SECTION SIGN is 0xC2 0xA7 in UTF-8.
            if let Some(end) = find_section(bytes, i + 2) {
                out.push((i, end + 2));
                i = end + 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn find_section(bytes: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] == b'\xc2' && i + 1 < bytes.len() && bytes[i + 1] == 0xa7 {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Fill a string's markers: `pick(index, inner)` returns a replacement, or
/// `None` to keep the inner text (markers stripped).
fn fill(s: &str, idx: &mut usize, pick: &mut dyn FnMut(usize, &str) -> Option<String>) -> String {
    let ranges = markers(s);
    if ranges.is_empty() {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for (start, end) in ranges {
        out.push_str(&s[last..start]);
        let inner = &s[start + 2..end - 2];
        let replacement = pick(*idx, inner);
        *idx += 1;
        out.push_str(replacement.as_deref().unwrap_or(inner));
        last = end;
    }
    out.push_str(&s[last..]);
    out
}

/// Build a concrete request from the template, choosing each position.
fn build(t: &Template, mut pick: impl FnMut(usize, &str) -> Option<String>) -> RepeaterRequest {
    let mut idx = 0;
    let headers = t.headers.as_ref().and_then(Value::as_object).map(|map| {
        let mut out = Map::new();
        for (k, v) in map {
            let filled = match v {
                Value::Array(list) => Value::Array(
                    list.iter()
                        .map(|x| match x.as_str() {
                            Some(s) => Value::String(fill(s, &mut idx, &mut pick)),
                            None => x.clone(),
                        })
                        .collect(),
                ),
                Value::String(s) => Value::String(fill(s, &mut idx, &mut pick)),
                other => other.clone(),
            };
            out.insert(k.clone(), filled);
        }
        Value::Object(out)
    });
    let url = fill(&t.url, &mut idx, &mut pick);
    let body = t.body.as_ref().map(|b| fill(b, &mut idx, &mut pick));
    RepeaterRequest {
        method: t.method.clone(),
        url,
        headers,
        body,
        insecure: t.insecure,
        timeout_ms: None,
    }
}

fn url_encode(s: &str) -> String {
    // encodeURIComponent: keep A-Za-z0-9 and -_.!~*'()
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// Runs one attack at a time.
pub struct Intruder {
    repeater: Repeater,
    running: AtomicBool,
    cancel: AtomicBool,
}

impl Default for Intruder {
    fn default() -> Self {
        Self::new()
    }
}

impl Intruder {
    pub fn new() -> Self {
        Self {
            repeater: Repeater::new(),
            running: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Cancel the attack in flight.
    pub fn stop(&self) {
        if self.is_running() {
            self.cancel.store(true, Ordering::SeqCst);
        }
    }

    /// Run the attack, emitting start / row / done. Returns an error only for
    /// the up-front validation the route already did.
    pub async fn run(
        &self,
        template: Template,
        attack: AttackType,
        payloads: Vec<String>,
        url_encode_on: bool,
        emit: &IntruderSink,
    ) {
        let positions = count_positions(&template);
        // Expand into a flat job list: (position, payload).
        let mut jobs: Vec<(Option<usize>, String)> = Vec::new();
        match attack {
            AttackType::BatteringRam => {
                for p in &payloads {
                    jobs.push((None, p.clone()));
                }
            }
            AttackType::Sniper => {
                for pos in 0..positions {
                    for p in &payloads {
                        jobs.push((Some(pos), p.clone()));
                    }
                }
            }
        }
        let total = jobs.len().min(MAX_REQUESTS);

        self.running.store(true, Ordering::SeqCst);
        self.cancel.store(false, Ordering::SeqCst);
        emit(IntruderEvent::Start(json!({
            "total": total,
            "attackType": attack.as_str(),
            "positions": positions,
        })));

        let mut completed = 0;
        for (n, (position, payload)) in jobs.into_iter().take(total).enumerate() {
            if self.cancel.load(Ordering::SeqCst) {
                break;
            }
            let enc = |p: &str| {
                if url_encode_on {
                    url_encode(p)
                } else {
                    p.to_owned()
                }
            };
            let sent = build(&template, |i, _inner| match attack {
                AttackType::BatteringRam => Some(enc(&payload)),
                AttackType::Sniper => (Some(i) == position).then(|| enc(&payload)),
            });
            let sent_method = sent.method.clone().unwrap_or_else(|| "GET".into());
            let sent_url = sent.url.clone();
            let sent_headers = sent.headers.clone();
            let sent_body = sent.body.clone();

            let resp = self.repeater.send(sent).await;
            let body = resp.body.clone().unwrap_or_default();
            let truncated = body.len() > MAX_ROW_BODY;

            // The request object, with `headers`/`body` omitted when absent —
            // as Node's `undefined` fields serialize away.
            let mut request = Map::new();
            request.insert("method".into(), json!(sent_method));
            request.insert("url".into(), json!(sent_url));
            // Node's build() always returns a headers object (empty when none).
            request.insert("headers".into(), sent_headers.unwrap_or_else(|| json!({})));
            if let Some(body) = sent_body {
                request.insert("body".into(), json!(body));
            }
            let mut row = json!({
                "index": n,
                "payload": payload,
                "request": request,
            });
            let obj = row.as_object_mut().unwrap();
            if let Some(pos) = position {
                obj.insert("position".into(), json!(pos));
            }
            if let Some(sc) = resp.status_code {
                obj.insert("statusCode".into(), json!(sc));
            }
            if let Some(sm) = &resp.status_message {
                obj.insert("statusMessage".into(), json!(sm));
            }
            if let Some(sz) = resp.body_size {
                obj.insert("length".into(), json!(sz));
            }
            if let Some(d) = resp.duration_ms {
                obj.insert("durationMs".into(), json!(d));
            }
            if let Some(err) = &resp.error {
                obj.insert("error".into(), json!(err));
            } else {
                obj.insert(
                    "response".into(),
                    json!({
                        "statusCode": resp.status_code,
                        "statusMessage": resp.status_message,
                        "headers": resp.headers,
                        "body": if truncated { body[..MAX_ROW_BODY].to_owned() } else { body },
                        "truncated": truncated,
                    }),
                );
            }
            completed += 1;
            emit(IntruderEvent::Row(row));
        }

        let cancelled = self.cancel.load(Ordering::SeqCst);
        self.running.store(false, Ordering::SeqCst);
        self.cancel.store(false, Ordering::SeqCst);
        emit(IntruderEvent::Done(json!({
            "total": total,
            "completed": completed,
            "cancelled": cancelled,
        })));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tpl(url: &str, headers: Value, body: Option<&str>) -> Template {
        Template {
            method: None,
            url: url.into(),
            headers: Some(headers),
            body: body.map(str::to_owned),
            insecure: false,
        }
    }

    #[test]
    fn counts_positions_across_url_headers_body() {
        let t = tpl(
            "http://x/\u{a7}1\u{a7}?q=\u{a7}2\u{a7}",
            json!({ "x-a": "\u{a7}3\u{a7}", "x-b": ["\u{a7}4\u{a7}", "plain"] }),
            Some("body=\u{a7}5\u{a7}"),
        );
        assert_eq!(count_positions(&t), 5);
    }

    #[test]
    fn sniper_fills_one_position_keeps_others() {
        let t = tpl("http://x/\u{a7}A\u{a7}/\u{a7}B\u{a7}", json!({}), None);
        // position 0 → "P", others keep inner text (markers stripped)
        let req = build(&t, |i, _| (i == 0).then(|| "P".to_owned()));
        assert_eq!(req.url, "http://x/P/B");
    }

    #[test]
    fn battering_ram_fills_every_position() {
        let t = tpl("http://x/\u{a7}A\u{a7}/\u{a7}B\u{a7}", json!({}), None);
        let req = build(&t, |_, _| Some("Z".to_owned()));
        assert_eq!(req.url, "http://x/Z/Z");
    }

    #[test]
    fn url_encode_matches_encodeuricomponent() {
        assert_eq!(url_encode("a b/c?d=e&f"), "a%20b%2Fc%3Fd%3De%26f");
        assert_eq!(url_encode("keep-_.!~*'()"), "keep-_.!~*'()");
    }
}
