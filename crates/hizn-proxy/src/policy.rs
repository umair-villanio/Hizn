//! Interception policy: Burp-style intercept switches and held items, Match &
//! Replace rules, and target scope — the state the Node `ProxyService` kept.
//!
//! Config values are kept as raw JSON because the Node code stored whatever it
//! was sent (`{...prev, ...config}`), so e.g. posting `{enabled: true}` alone
//! leaves `requests`/`responses` undefined — and the UI sees exactly that.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use tokio::sync::oneshot;

use crate::js;

/// What the user decided for a held request or response.
#[derive(Debug, Default, Clone)]
pub struct Decision {
    pub drop: bool,
    /// Replacement headers object (used when it's an object).
    pub headers: Option<Value>,
    pub body: Option<Value>,
    pub body_edited: bool,
    pub method: Option<Value>,
    pub url: Option<Value>,
    pub status_code: Option<Value>,
    pub status_message: Option<Value>,
    /// For a request: also hold this request's response.
    pub intercept_response: bool,
}

impl Decision {
    pub fn forward() -> Self {
        Self::default()
    }

    /// From a `POST /api/intercept/resolve` body.
    pub fn from_json(body: &Value) -> Self {
        let get = |k: &str| body.get(k).cloned();
        Self {
            drop: body.get("action").and_then(Value::as_str) == Some("drop"),
            headers: get("headers"),
            body: get("body"),
            body_edited: js::truthy(body.get("bodyEdited")),
            method: get("method"),
            url: get("url"),
            status_code: get("statusCode"),
            status_message: get("statusMessage"),
            intercept_response: js::truthy(body.get("interceptResponse")),
        }
    }

    /// The replacement headers, if given as an object (`if (decision.headers)`).
    pub fn headers_object(&self) -> Option<&Map<String, Value>> {
        self.headers
            .as_ref()
            .filter(|v| js::truthy(Some(v)))
            .and_then(Value::as_object)
    }

    /// The edited body text (`decision.body ?? ''`), when edited.
    pub fn edited_body(&self) -> Option<String> {
        self.body_edited.then(|| match &self.body {
            None | Some(Value::Null) => String::new(),
            Some(v) => js::string(v),
        })
    }

    pub fn truthy_string(v: &Option<Value>) -> Option<String> {
        v.as_ref().filter(|v| js::truthy(Some(v))).map(js::string)
    }
}

struct Pending {
    item: Value,
    tx: oneshot::Sender<Decision>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub enabled: bool,
    pub hosts: Vec<String>,
}

impl Scope {
    pub fn to_json(&self) -> Value {
        json!({ "enabled": self.enabled, "hosts": self.hosts })
    }
}

const CONFIG_KEYS: [&str; 3] = ["enabled", "requests", "responses"];

pub(crate) struct Policy {
    /// `enabled`, `requests`, `responses`; `None` = `undefined`. JS keeps an
    /// undefined key in place, so the JSON order never changes.
    intercept: [Option<Value>; 3],
    rules: Vec<Value>,
    scope: Scope,
    pending: IndexMap<String, Pending>,
    /// Flow ids whose response the user asked to hold (per-request).
    response_watch: HashSet<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            // Responses are only held when asked for, per request or globally.
            intercept: [Some(json!(false)), Some(json!(true)), Some(json!(false))],
            rules: Vec::new(),
            scope: Scope {
                enabled: false,
                hosts: Vec::new(),
            },
            pending: IndexMap::new(),
            response_watch: HashSet::new(),
        }
    }
}

/// Released holds to report after the lock is dropped.
pub(crate) type Released = Vec<String>;

impl Policy {
    pub fn intercept(&self) -> Map<String, Value> {
        CONFIG_KEYS
            .iter()
            .zip(&self.intercept)
            .filter_map(|(k, v)| v.clone().map(|v| ((*k).to_owned(), v)))
            .collect()
    }

    fn on(&self, key: &str) -> bool {
        let i = CONFIG_KEYS.iter().position(|k| *k == key).unwrap_or(0);
        js::truthy(self.intercept[i].as_ref())
    }

    pub fn holds_requests(&self, host: &str) -> bool {
        self.on("enabled") && self.on("requests") && self.in_scope(host)
    }

    /// A per-request watch bypasses scope; global response holding respects it.
    pub fn holds_response(&mut self, flow_id: &str, host: &str) -> bool {
        let watched = self.response_watch.remove(flow_id);
        watched || (self.on("enabled") && self.on("responses") && self.in_scope(host))
    }

    pub fn watch_response(&mut self, flow_id: &str) {
        self.response_watch.insert(flow_id.to_owned());
    }

    /// `{...prev, enabled, requests, responses}`: each key takes the posted
    /// value, `undefined` (missing) removing it. Kinds that are now off have
    /// their held items released, forwarded unchanged.
    pub fn set_intercept(
        &mut self,
        enabled: Option<Value>,
        requests: Option<Value>,
        responses: Option<Value>,
    ) -> (Map<String, Value>, Released) {
        self.intercept = [enabled, requests, responses];
        let off = |p: &Self, kind: &str| {
            !p.on("enabled")
                || (kind == "request" && !p.on("requests"))
                || (kind == "response" && !p.on("responses"))
        };
        let release: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, p)| off(self, p.item["kind"].as_str().unwrap_or("")))
            .map(|(id, _)| id.clone())
            .collect();
        let released = release
            .into_iter()
            .filter(|id| self.resolve(id, Decision::forward()))
            .collect();
        (self.intercept(), released)
    }

    pub fn hold(&mut self, item: Value) -> oneshot::Receiver<Decision> {
        let (tx, rx) = oneshot::channel();
        let id = item["id"].as_str().unwrap_or_default().to_owned();
        self.pending.insert(id, Pending { item, tx });
        rx
    }

    /// Hand a decision to a held item. False if there's no such item.
    pub fn resolve(&mut self, id: &str, decision: Decision) -> bool {
        match self.pending.shift_remove(id) {
            Some(p) => {
                // The client may have gone away meanwhile; that's fine.
                let _ = p.tx.send(decision);
                true
            }
            None => false,
        }
    }

    pub fn pending_items(&self) -> Vec<Value> {
        self.pending.values().map(|p| p.item.clone()).collect()
    }

    /// Forward everything held (proxy stopping), forgetting response watches.
    pub fn release_all(&mut self) -> Released {
        let ids: Vec<String> = self.pending.keys().cloned().collect();
        let released = ids
            .into_iter()
            .filter(|id| self.resolve(id, Decision::forward()))
            .collect();
        self.response_watch.clear();
        released
    }

    pub fn rules(&self) -> Vec<Value> {
        self.rules.clone()
    }

    /// Keep entries like Node's filter: `r && r.part && r.match != null`.
    pub fn set_rules(&mut self, rules: Vec<Value>) -> Vec<Value> {
        self.rules = rules
            .into_iter()
            .filter(|r| {
                js::truthy(Some(r))
                    && js::truthy(r.get("part"))
                    && !matches!(r.get("match"), None | Some(Value::Null))
            })
            .collect();
        self.rules.clone()
    }

    pub fn rules_ref(&self) -> &[Value] {
        &self.rules
    }

    pub fn scope(&self) -> Scope {
        self.scope.clone()
    }

    /// `enabled` only if a boolean; `hosts` only if an array (each `String()`-ed,
    /// trimmed, empties dropped).
    pub fn set_scope(&mut self, enabled: Option<&Value>, hosts: Option<&Value>) -> Scope {
        if let Some(Value::Bool(b)) = enabled {
            self.scope.enabled = *b;
        }
        if let Some(Value::Array(list)) = hosts {
            self.scope.hosts = list
                .iter()
                .map(|h| js::string(h).trim().to_owned())
                .filter(|h| !h.is_empty())
                .collect();
        }
        self.scope.clone()
    }

    pub fn in_scope(&self, host: &str) -> bool {
        !self.scope.enabled
            || self.scope.hosts.is_empty()
            || self.scope.hosts.iter().any(|p| js::host_matches(host, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_config_drops_missing_keys_like_node() {
        let mut p = Policy::default();
        let (cfg, _) = p.set_intercept(Some(json!(true)), None, None);
        assert_eq!(Value::Object(cfg), json!({ "enabled": true }));
        assert!(!p.holds_requests("x")); // requests is undefined → falsy
    }

    #[test]
    fn turning_off_releases_matching_holds() {
        let mut p = Policy::default();
        p.set_intercept(Some(json!(true)), Some(json!(true)), Some(json!(true)));
        let mut rx_req = p.hold(json!({ "id": "a", "kind": "request" }));
        let _rx_res = p.hold(json!({ "id": "b:res", "kind": "response" }));
        let (_, released) =
            p.set_intercept(Some(json!(true)), Some(json!(false)), Some(json!(true)));
        assert_eq!(released, ["a"]);
        assert!(!rx_req.try_recv().unwrap().drop);
        assert_eq!(p.pending_items().len(), 1);
    }

    #[test]
    fn rules_and_scope_filters_match_node() {
        let mut p = Policy::default();
        let kept = p.set_rules(vec![
            json!({ "part": "request-url", "match": "a" }),
            json!({ "match": "x" }),
            Value::Null,
            json!({ "part": "response-body", "match": null }),
            json!({ "part": "response-body", "match": 0, "extra": "kept" }),
        ]);
        assert_eq!(
            kept,
            vec![
                json!({ "part": "request-url", "match": "a" }),
                json!({ "part": "response-body", "match": 0, "extra": "kept" })
            ]
        );
        let s = p.set_scope(
            Some(&json!("yes")),
            Some(&json!([" a.com ", "", 5, null, "*.b.com"])),
        );
        assert_eq!(
            s.to_json(),
            json!({ "enabled": false, "hosts": ["a.com", "5", "null", "*.b.com"] })
        );
    }
}
