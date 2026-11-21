//! Headers as the Node backend exposes them in flows: mockttp's
//! `rawHeadersToObject` — lowercase names in order of first appearance; a
//! repeated header becomes an array (any header, `set-cookie` included).
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use http::HeaderMap;
use serde_json::{Map, Value};

/// Header value as text. Non-UTF-8 bytes are read as Latin-1, like Node.
pub fn value_text(v: &http::HeaderValue) -> String {
    match v.to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => v.as_bytes().iter().map(|&b| b as char).collect(),
    }
}

pub fn node_headers(headers: &HeaderMap) -> Map<String, Value> {
    let mut out = Map::new();
    for (name, value) in headers {
        let value = value_text(value);
        match out.get_mut(name.as_str()) {
            Some(Value::Array(list)) => list.push(Value::String(value)),
            // `else if (existingValue)`: a non-empty first value turns into an array…
            Some(existing @ Value::String(_)) if existing.as_str() != Some("") => {
                let first = existing.take();
                *existing = Value::Array(vec![first, Value::String(value)]);
            }
            // …while a missing or empty one is simply replaced.
            _ => {
                out.insert(name.as_str().to_owned(), Value::String(value));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use serde_json::json;

    #[test]
    fn repeats_become_arrays_in_first_seen_order() {
        let mut h = HeaderMap::new();
        h.append("Content-Type", HeaderValue::from_static("text/plain"));
        h.append("Set-Cookie", HeaderValue::from_static("a=1"));
        h.append("X-Dup", HeaderValue::from_static("one"));
        h.append("Set-Cookie", HeaderValue::from_static("b=2"));
        h.append("X-Dup", HeaderValue::from_static("two"));
        h.append("Cookie", HeaderValue::from_static("c=3"));
        h.append("Cookie", HeaderValue::from_static("d=4"));
        h.append("X-Dup", HeaderValue::from_static("three"));
        let out = node_headers(&h);
        assert_eq!(
            Value::Object(out.clone()),
            json!({
                "content-type": "text/plain",
                "set-cookie": ["a=1", "b=2"],
                "x-dup": ["one", "two", "three"],
                "cookie": ["c=3", "d=4"],
            })
        );
        let keys: Vec<&String> = out.keys().collect();
        assert_eq!(keys, ["content-type", "set-cookie", "x-dup", "cookie"]);
    }

    #[test]
    fn single_values_stay_strings_and_empty_firsts_are_replaced() {
        let mut h = HeaderMap::new();
        h.append("set-cookie", HeaderValue::from_static("a=1"));
        h.append("x-empty", HeaderValue::from_static(""));
        h.append("x-empty", HeaderValue::from_static("later"));
        let out = node_headers(&h);
        assert_eq!(out["set-cookie"], json!("a=1"));
        assert_eq!(out["x-empty"], json!("later"));
    }
}
