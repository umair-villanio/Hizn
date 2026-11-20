//! The REST surface: all 38 routes of the Node API, mounted under `/api`.
//!
//! Routes not ported yet answer `501` with a JSON `error` (which the UI's
//! `api()` helper shows as a banner), plus the route and the RUST-PORT.md phase
//! that ports it. As phases land, entries move from `PENDING` to real handlers.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{MethodFilter, MethodRouter, get};
use axum::{Json, Router};
use indexmap::IndexMap;
use serde_json::json;

use crate::state::{AppState, ProxyStatus};

/// Not-yet-ported routes: (method, path, phase).
pub const PENDING: &[(&str, &str, u8)] = &[
    ("GET", "/devices", 4),
    ("GET", "/ca", 2),
    ("POST", "/proxy/start", 2),
    ("POST", "/proxy/stop", 2),
    ("POST", "/upstream", 2),
    ("GET", "/intercept", 3),
    ("POST", "/intercept/config", 3),
    ("POST", "/intercept/resolve", 3),
    ("GET", "/connections", 4),
    ("POST", "/connect", 4),
    ("POST", "/disconnect", 4),
    ("POST", "/connect/genymotion", 4),
    ("POST", "/frida/provision", 4),
    ("GET", "/desktop/info", 5),
    ("POST", "/desktop/import-ca", 5),
    ("POST", "/desktop/firefox", 5),
    ("GET", "/rules", 3),
    ("POST", "/rules", 3),
    ("GET", "/flows", 2),
    ("POST", "/flows/clear", 2),
    ("POST", "/flows/import", 2),
    ("GET", "/scope", 3),
    ("POST", "/scope", 3),
    ("POST", "/intruder/start", 5),
    ("POST", "/intruder/stop", 5),
    ("POST", "/repeater/send", 5),
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
pub const PORTED: &[(&str, &str)] = &[("GET", "/status")];

pub fn router() -> Router<AppState> {
    let mut by_path: IndexMap<&'static str, MethodRouter<AppState>> = IndexMap::new();
    by_path.insert("/status", get(status));

    for &(method, path, phase) in PENDING {
        let filter = match method {
            "GET" => MethodFilter::GET,
            "POST" => MethodFilter::POST,
            "DELETE" => MethodFilter::DELETE,
            other => unreachable!("unexpected method {other}"),
        };
        let entry = by_path.entry(path).or_insert_with(MethodRouter::new);
        let current = std::mem::replace(entry, MethodRouter::new());
        *entry = current.on(filter, move || async move { not_ported(method, path, phase) });
    }

    by_path
        .into_iter()
        .fold(Router::new(), |router, (path, methods)| router.route(path, methods))
}

async fn status(State(state): State<AppState>) -> Json<ProxyStatus> {
    let status = state.hub().status();
    Json(status)
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
