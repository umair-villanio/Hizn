//! `hizn` — headless entry point (the Rust equivalent of `npm start`).
//!
//! Starts the local API + UI server. Open the printed URL in a browser, or let
//! the desktop shell load it.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::process::exit;

use hizn_server::{AppState, find_ui_dir, serve};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    // Same rule as Node's `Number(process.env.DROIDMITM_PORT) || 4000`.
    let port = std::env::var("DROIDMITM_PORT")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|&p| p != 0)
        .unwrap_or(4000);

    let Some(ui_dir) = find_ui_dir() else {
        eprintln!("Fatal: could not find the ui/ folder (set HIZN_UI_DIR to its path).");
        exit(1);
    };

    let listener = match TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Fatal: could not listen on 127.0.0.1:{port}: {e}");
            exit(1);
        }
    };
    println!("hizn API + UI → http://127.0.0.1:{port}");

    if let Err(e) = serve(listener, AppState::new(), &ui_dir).await {
        eprintln!("Fatal: {e}");
        exit(1);
    }
}
