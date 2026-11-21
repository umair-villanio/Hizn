//! Hizn backend: REST + WebSocket bridge between the backend services and the
//! (unchanged) web UI in `ui/`.
//!
//! The UI only uses relative `fetch('/api/…')` and `ws://${location.host}/ws`,
//! so serving it from this server is all it takes to run it unmodified.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

pub mod api;
pub mod plugins;
pub mod state;
pub mod ws;

use std::path::{Path, PathBuf};

use axum::Router;
use axum::routing::get;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

pub use state::AppState;

/// The shipped `plugins/` folder (sibling of `ui/`), for the contrib store.
pub fn plugins_dir() -> PathBuf {
    find_ui_dir()
        .and_then(|ui| ui.parent().map(|p| p.join("plugins")))
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins"))
}

/// Build the full app: `/api/*`, `/ws`, and the static UI.
pub fn app(state: AppState, ui_dir: &Path) -> Router {
    Router::new()
        .nest("/api", api::router())
        .route("/ws", get(ws::handler))
        .fallback_service(ServeDir::new(ui_dir))
        .with_state(state)
}

/// Serve on an already-bound listener until the process exits.
pub async fn serve(listener: TcpListener, state: AppState, ui_dir: &Path) -> std::io::Result<()> {
    if let Ok(addr) = listener.local_addr() {
        state.set_api_port(addr.port());
    }
    axum::serve(listener, app(state, ui_dir)).await
}

/// Locate the `ui/` folder (the one containing `index.html`).
///
/// `HIZN_UI_DIR` wins if set. Otherwise look in and above the working
/// directory and the executable's directory, then fall back to this repo's
/// `ui/` for `cargo run`.
pub fn find_ui_dir() -> Option<PathBuf> {
    let has_ui = |dir: &Path| dir.join("index.html").is_file();

    if let Some(dir) = std::env::var_os("HIZN_UI_DIR").map(PathBuf::from) {
        return has_ui(&dir).then_some(dir);
    }

    let mut roots = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd);
    }
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    {
        roots.push(exe_dir);
    }
    for root in roots {
        for dir in root.ancestors().take(5) {
            let ui = dir.join("ui");
            if has_ui(&ui) {
                return Some(ui);
            }
        }
    }

    let dev = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui");
    has_ui(&dev).then_some(dev)
}
