//! JavaScript semantics the Node backend's features depend on: truthiness,
//! `String(x)`, `str.replace(new RegExp(m, 'g'), r)` with `$`-substitutions,
//! `split`/`join`, and the header text round-trip used by Match & Replace.
//!
//! Rules arrive as arbitrary JSON from the UI (or the MCP bridge), so these
//! helpers work on `serde_json::Value` and reproduce what the JS code did with
//! the same input — including its quirks.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use fancy_regex::Regex;
use serde_json::{Map, Value};

/// `!!value`
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// `String(value)`
pub fn string(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => number(n),
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .map(|x| match x {
                Value::Null => String::new(),
                other => string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

fn number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    let f = n.as_f64().unwrap_or(f64::NAN);
    if f.fract() == 0.0 && f.abs() < 1e21 {
        format!("{f:.0}")
    } else {
        f.to_string()
    }
}

/// Compiled JS regexes, cached by source (rules re-run on every request).
fn compiled(pattern: &str) -> Option<Arc<Regex>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Arc<Regex>>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let mut cache = cache.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(hit) = cache.get(pattern) {
        return hit.clone();
    }
    if cache.len() > 512 {
        cache.clear();
    }
    let re = Regex::new(pattern).ok().map(Arc::new);
    cache.insert(pattern.to_owned(), re.clone());
    re
}

/// `input.replace(new RegExp(pattern, 'g'), replacement)`; an invalid pattern
/// leaves the input unchanged (the Node code caught the throw).
pub fn regex_replace_all(input: &str, pattern: &str, replacement: &str) -> String {
    let Some(re) = compiled(pattern) else {
        return input.to_owned();
    };
    let groups = re.captures_len().saturating_sub(1);
    let has_names = re.capture_names().any(|n| n.is_some());
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    for caps in re.captures_iter(input) {
        let Ok(caps) = caps else { break };
        let Some(m) = caps.get(0) else { continue };
        out.push_str(&input[last..m.start()]);
        substitute(
            &mut out,
            replacement,
            &caps,
            input,
            m.start(),
            m.end(),
            groups,
            has_names,
        );
        last = m.end();
    }
    out.push_str(&input[last..]);
    out
}

/// JS `GetSubstitution`: `$$ $& $` $' $n $nn $<name>`.
#[allow(clippy::too_many_arguments)]
fn substitute(
    out: &mut String,
    repl: &str,
    caps: &fancy_regex::Captures<'_, str>,
    input: &str,
    start: usize,
    end: usize,
    groups: usize,
    has_names: bool,
) {
    let bytes = repl.as_bytes();
    let mut i = 0;
    let mut literal_from = 0;
    let flush = |out: &mut String, from: usize, to: usize| out.push_str(&repl[from..to]);
    while i < bytes.len() {
        if bytes[i] != b'$' || i + 1 >= bytes.len() {
            i += 1;
            continue;
        }
        let next = bytes[i + 1];
        let (consumed, text): (usize, Option<String>) = match next {
            b'$' => (2, Some("$".into())),
            b'&' => (2, Some(input[start..end].to_owned())),
            b'`' => (2, Some(input[..start].to_owned())),
            b'\'' => (2, Some(input[end..].to_owned())),
            b'0'..=b'9' => {
                let d1 = (next - b'0') as usize;
                let two = bytes
                    .get(i + 2)
                    .filter(|c| c.is_ascii_digit())
                    .map(|c| d1 * 10 + (c - b'0') as usize);
                match two {
                    Some(nn) if (1..=groups).contains(&nn) => (
                        3,
                        Some(
                            caps.get(nn)
                                .map(|m| m.as_str().to_owned())
                                .unwrap_or_default(),
                        ),
                    ),
                    _ if (1..=groups).contains(&d1) => (
                        2,
                        Some(
                            caps.get(d1)
                                .map(|m| m.as_str().to_owned())
                                .unwrap_or_default(),
                        ),
                    ),
                    _ => (1, None),
                }
            }
            b'<' if has_names => match repl[i + 2..].find('>') {
                Some(close) => {
                    let name = &repl[i + 2..i + 2 + close];
                    let value = caps
                        .name(name)
                        .map(|m| m.as_str().to_owned())
                        .unwrap_or_default();
                    (close + 3, Some(value))
                }
                None => (1, None),
            },
            _ => (1, None),
        };
        match text {
            Some(text) => {
                flush(out, literal_from, i);
                out.push_str(&text);
                i += consumed;
                literal_from = i;
            }
            // Not a substitution: the `$` stays literal.
            None => i += consumed,
        }
    }
    flush(out, literal_from, bytes.len());
}

/// `input.split(sep).join(joiner)` (JS splits `""` into characters).
pub fn split_join(input: &str, sep: &str, joiner: &str) -> String {
    if sep.is_empty() {
        let chars: Vec<String> = input.chars().map(String::from).collect();
        return chars.join(joiner);
    }
    input.split(sep).collect::<Vec<_>>().join(joiner)
}

/// The Node backend's `doReplace(input, rule)`.
pub fn apply_rule(input: &str, rule: &Map<String, Value>) -> String {
    let pattern = rule
        .get("match")
        .map(string)
        .unwrap_or_else(|| "undefined".into());
    if rule.get("regex") == Some(&Value::Bool(false)) {
        // `.join(rule.replace)` — `undefined` joins with ","
        let joiner = match rule.get("replace") {
            None => ",".to_owned(),
            Some(v) => string(v),
        };
        return split_join(input, &pattern, &joiner);
    }
    // `.replace(re, rule.replace)` — `undefined` becomes the text "undefined"
    let replacement = match rule.get("replace") {
        None => "undefined".to_owned(),
        Some(v) => string(v),
    };
    regex_replace_all(input, &pattern, &replacement)
}

/// Run every enabled rule for `part`, in order. Returns the result and whether
/// anything changed.
pub fn apply_rules(input: &str, rules: &[Value], part: &str) -> (String, bool) {
    let mut text = input.to_owned();
    let mut changed = false;
    for rule in rules {
        let Some(rule) = rule.as_object() else {
            continue;
        };
        if !truthy(rule.get("enabled")) || rule.get("part").and_then(Value::as_str) != Some(part) {
            continue;
        }
        let next = apply_rule(&text, rule);
        if next != text {
            text = next;
            changed = true;
        }
    }
    (text, changed)
}

pub fn has_rule(rules: &[Value], part: &str) -> bool {
    rules
        .iter()
        .filter_map(Value::as_object)
        .any(|r| truthy(r.get("enabled")) && r.get("part").and_then(Value::as_str) == Some(part))
}

/// Headers object → `"name: value"` lines (arrays become repeated lines).
pub fn serialize_headers(headers: &Map<String, Value>) -> String {
    let mut lines = Vec::new();
    for (k, v) in headers {
        match v {
            Value::Array(values) => {
                for val in values {
                    lines.push(format!("{k}: {}", string(val)));
                }
            }
            other => lines.push(format!("{k}: {}", string(other))),
        }
    }
    lines.join("\n")
}

/// `"name: value"` lines → headers object (repeats become arrays).
pub fn parse_headers(text: &str) -> Map<String, Value> {
    let mut out = Map::new();
    for line in text.split('\n') {
        let Some(i) = line.find(':') else { continue };
        let key = line[..i].trim();
        let value = line[i + 1..].trim().to_owned();
        if key.is_empty() {
            continue;
        }
        match out.get_mut(key) {
            None => {
                out.insert(key.to_owned(), Value::String(value));
            }
            Some(Value::Array(list)) => list.push(Value::String(value)),
            Some(existing) => {
                let first = existing.take();
                *existing = Value::Array(vec![first, Value::String(value)]);
            }
        }
    }
    out
}

/// Run header rules over a headers object; `None` if nothing changed.
pub fn apply_header_rules(
    headers: &Map<String, Value>,
    rules: &[Value],
    part: &str,
) -> Option<Map<String, Value>> {
    let (text, changed) = apply_rules(&serialize_headers(headers), rules, part);
    changed.then(|| parse_headers(&text))
}

/// The Node backend's scope `hostMatches(host, pattern)`: a pattern with `*`
/// becomes an anchored regex (only `.` escaped, so other regex syntax still
/// applies); otherwise a substring test. Tried with and without the port.
pub fn host_matches(host: &str, pattern: &str) -> bool {
    let h = host.to_lowercase();
    let no_port = strip_port(&h);
    let p = pattern.to_lowercase();
    if p.contains('*') {
        let source = format!("^{}$", p.replace('.', "\\.").replace('*', ".*"));
        return compiled(&source).is_some_and(|re| {
            re.is_match(&h).unwrap_or(false) || re.is_match(no_port).unwrap_or(false)
        });
    }
    h.contains(&p) || no_port.contains(&p)
}

/// `host.replace(/:\d+$/, '')`
fn strip_port(host: &str) -> &str {
    match host.rfind(':') {
        Some(i) if i + 1 < host.len() && host[i + 1..].bytes().all(|b| b.is_ascii_digit()) => {
            &host[..i]
        }
        _ => host,
    }
}

/// UTF-16 length cap, as JS `str.length` / `str.slice(0, n)` count.
pub fn cap_utf16(text: &str, max_units: usize) -> (String, bool) {
    let mut units = 0;
    for (i, c) in text.char_indices() {
        units += c.len_utf16();
        if units > max_units {
            return (text[..i].to_owned(), true);
        }
    }
    (text.to_owned(), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn js_replacement_patterns_match_v8() {
        // Verified against the Node backend: '[parity|hello|hello parity|$||\n|$3]\n'
        assert_eq!(
            regex_replace_all(
                "hello parity\n",
                "(hello) (parity)",
                "[$2|$1|$&|$$|$`|$'|$3]"
            ),
            "[parity|hello|hello parity|$||\n|$3]\n"
        );
        assert_eq!(regex_replace_all("aaa", "a", "$0"), "$0$0$0");
        assert_eq!(regex_replace_all("ab", "(?<x>a)", "[$<x>]"), "[a]b");
        assert_eq!(regex_replace_all("abc", "", "-"), "-a-b-c-");
        assert_eq!(
            regex_replace_all("abc", "([", "x"),
            "abc",
            "invalid regex leaves input"
        );
    }

    #[test]
    fn literal_rules_and_undefined_replacements() {
        assert_eq!(
            apply_rule(
                "hello parity",
                &rule(json!({"match":"o","replace":"0","regex":false}))
            ),
            "hell0 parity"
        );
        assert_eq!(
            apply_rule("a-b", &rule(json!({"match":"-","regex":false}))),
            "a,b"
        );
        assert_eq!(
            apply_rule("a-b", &rule(json!({"match":"-"}))),
            "aundefinedb"
        );
        assert_eq!(
            apply_rule("x0y", &rule(json!({"match":0,"replace":null}))),
            "xnully"
        );
        assert_eq!(
            apply_rule("ab", &rule(json!({"match":"","replace":"+","regex":false}))),
            "a+b"
        );
    }

    #[test]
    fn header_rules_round_trip_like_node() {
        let headers = rule(json!({"host":"h","x-a":["1","2"]}));
        let rules = vec![
            json!({"enabled":true,"part":"request-header","match":"x-a: 2","replace":"x-b: 3"}),
        ];
        assert_eq!(
            Value::Object(apply_header_rules(&headers, &rules, "request-header").unwrap()),
            json!({"host":"h","x-a":"1","x-b":"3"})
        );
        assert!(apply_header_rules(&headers, &rules, "response-header").is_none());
    }

    #[test]
    fn scope_patterns() {
        assert!(host_matches("api.example.com:443", "*.example.com"));
        assert!(host_matches("Example.com:8443", "example.com"));
        assert!(host_matches("localhost:5000", "localhost"));
        assert!(!host_matches("127.0.0.1:5000", "localhost"));
        assert!(!host_matches("example.org", "*.example.com"));
        assert!(!host_matches("x", "*(")); // invalid → no match
    }

    #[test]
    fn js_string_and_truthiness() {
        assert_eq!(string(&json!(5)), "5");
        assert_eq!(string(&json!(1.5)), "1.5");
        assert_eq!(string(&json!(null)), "null");
        assert_eq!(string(&json!([1, null, "a"])), "1,,a");
        assert_eq!(string(&json!({})), "[object Object]");
        assert!(truthy(Some(&json!("yes"))) && !truthy(Some(&json!(0))) && !truthy(None));
    }

    #[test]
    fn utf16_cap() {
        assert_eq!(cap_utf16("abcd", 2), ("ab".into(), true));
        assert_eq!(cap_utf16("a😀b", 2), ("a".into(), true)); // the emoji is 2 units
        assert_eq!(cap_utf16("ab", 2), ("ab".into(), false));
    }
}
