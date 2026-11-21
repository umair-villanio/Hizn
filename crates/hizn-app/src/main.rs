//! Hizn desktop app — the Tauri equivalent of `electron/main.js`.
//!
//! Boots the Rust API + UI server in-process on a free loopback port, then
//! opens a native window (system webview) pointed at it. No terminal, no
//! browser tab — just the app.
//!
//! The page gets no Tauri IPC at all. The shell actions it can't do itself
//! (show the auto-hidden menu bar with Alt, fullscreen with F11, zoom with
//! Ctrl+=/-/0) are requested by opening a `https://hizn.cmd/<action>` popup,
//! which the shell intercepts and cancels.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpListener as StdTcpListener;
use std::path::PathBuf;
use std::sync::Mutex;

use hizn_server::AppState;
use rfd::{FileDialog, MessageDialog, MessageLevel};
use tauri::menu::{Menu, MenuBuilder, MenuEvent, SubmenuBuilder};
use tauri::webview::{DownloadEvent, NewWindowResponse};
use tauri::window::Color;
use tauri::{AppHandle, Manager, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder, Wry};
use tauri_plugin_opener::OpenerExt;

const MAIN_WINDOW: &str = "main";
const REPO_URL: &str = "https://github.com/umair-villanio/Hizn";
/// Pseudo-host the injected shortcut script opens to ask for a shell action.
const CMD_HOST: &str = "hizn.cmd";

/// Chromium-style zoom level (factor = 1.2^level), shared by the menu and the
/// keyboard so they never disagree.
#[derive(Default)]
struct ZoomLevel(Mutex<f64>);

fn main() {
    tauri::Builder::default()
        // Single-instance lock: focus the existing window instead of opening a
        // second. Must be the first plugin registered.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(win) = app.get_webview_window(MAIN_WINDOW) {
                let _ = win.unminimize();
                let _ = win.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .manage(ZoomLevel::default())
        .setup(|app| {
            let handle = app.handle().clone();
            let url = match start_backend(&handle) {
                Ok(url) => url,
                Err(err) => {
                    MessageDialog::new()
                        .set_level(MessageLevel::Error)
                        .set_title("hizn failed to start")
                        .set_description(format!("The backend could not start:\n\n{err}"))
                        .show();
                    std::process::exit(1);
                }
            };
            let menu = build_menu(&handle)?;
            create_window(&handle, url, menu)?;
            Ok(())
        })
        .on_menu_event(on_menu_event)
        .run(tauri::generate_context!())
        .expect("error while running Hizn");
}

/// Boot the backend on a free loopback port. Returns the URL the window loads.
///
/// Binding port 0 directly (instead of probing for a free port and binding it
/// later, as the Electron shell did) leaves no window for another process to
/// grab the port in between.
fn start_backend(app: &AppHandle) -> Result<Url, String> {
    let ui_dir = ui_dir(app).ok_or("could not find the ui/ folder")?;
    let listener = StdTcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();

    tauri::async_runtime::spawn(async move {
        let result = match tokio::net::TcpListener::from_std(listener) {
            Ok(listener) => hizn_server::serve(listener, AppState::new(), &ui_dir).await,
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            eprintln!("hizn backend stopped: {e}");
        }
    });

    format!("http://127.0.0.1:{port}")
        .parse::<Url>()
        .map_err(|e| e.to_string())
}

/// The bundled `ui/` next to the app, or the repo's `ui/` when developing.
fn ui_dir(app: &AppHandle) -> Option<PathBuf> {
    if std::env::var_os("HIZN_UI_DIR").is_none()
        && let Some(dir) = app.path().resource_dir().ok().map(|d| d.join("ui"))
        && dir.join("index.html").is_file()
    {
        return Some(dir);
    }
    hizn_server::find_ui_dir()
}

fn create_window(app: &AppHandle, url: Url, menu: Menu<Wry>) -> tauri::Result<()> {
    let backend_origin = url.origin();
    let nav_app = app.clone();
    let popup_app = app.clone();

    let win = WebviewWindowBuilder::new(app, MAIN_WINDOW, WebviewUrl::External(url))
        .title("Hizn")
        .inner_size(1180.0, 820.0)
        .min_inner_size(900.0, 640.0)
        .background_color(Color(0x0e, 0x11, 0x16, 0xff))
        .menu(menu)
        .visible(false)
        .initialization_script(init_script())
        // Keep the app window on the backend; open anything else in the
        // user's browser.
        .on_navigation(move |target| {
            if target.origin() == backend_origin
                || matches!(target.scheme(), "about" | "data" | "blob")
            {
                return true;
            }
            open_external(&nav_app, target);
            false
        })
        .on_new_window(move |target, _features| {
            if target.host_str() == Some(CMD_HOST) {
                run_shell_command(&popup_app, target.path());
            } else {
                open_external(&popup_app, &target);
            }
            NewWindowResponse::Deny
        })
        // Exports (HAR, sessions, …) use <a download>; ask where to save, like
        // Electron does.
        .on_download(|webview, event| match event {
            DownloadEvent::Requested { destination, .. } => {
                let name = destination
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "download".into());
                let mut dialog = FileDialog::new().set_file_name(name);
                if let Some(dir) = destination.parent() {
                    dialog = dialog.set_directory(dir);
                }
                match dialog.set_parent(&webview.window()).save_file() {
                    Some(path) => {
                        *destination = path;
                        true
                    }
                    None => false,
                }
            }
            _ => true,
        })
        .build()?;

    // Electron's `autoHideMenuBar`: hidden until Alt is pressed.
    win.hide_menu()?;
    win.show()?;
    Ok(())
}

/// Injected into every page before its own scripts run.
fn init_script() -> String {
    let platform = match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        other => other,
    };
    format!(
        r#"(() => {{
  // Same read-only marker the Electron preload exposed as window.hizn.
  Object.defineProperty(window, 'hizn', {{
    value: Object.freeze({{
      desktop: true,
      platform: {platform:?},
      versions: Object.freeze({{ tauri: {tauri:?}, hizn: {hizn:?} }}),
    }}),
    enumerable: true,
  }});

  // Shell shortcuts: F11 = fullscreen, Ctrl+=/-/0 = zoom,
  // a lone Alt press = show/hide the menu bar.
  const ask = (action) => window.open('https://{host}/' + action);
  const zoomKeys = {{ '=': 'zoom-in', '+': 'zoom-in', '-': 'zoom-out', '0': 'zoom-reset' }};
  let altAlone = false;
  addEventListener('keydown', (e) => {{
    if (e.key === 'F11') {{ e.preventDefault(); ask('fullscreen'); }}
    else if ((e.ctrlKey || e.metaKey) && !e.altKey && zoomKeys[e.key]) {{
      e.preventDefault(); ask(zoomKeys[e.key]);
    }}
    if (e.key === 'Alt') {{ if (!e.repeat) altAlone = true; }} else altAlone = false;
  }}, true);
  addEventListener('keyup', (e) => {{
    if (e.key === 'Alt' && altAlone) ask('menu');
    altAlone = false;
  }}, true);
  addEventListener('mousedown', () => {{ altAlone = false; }}, true);
}})();"#,
        tauri = tauri::VERSION,
        hizn = env!("CARGO_PKG_VERSION"),
        host = CMD_HOST,
    )
}

fn run_shell_command(app: &AppHandle, path: &str) {
    let Some(win) = app.get_webview_window(MAIN_WINDOW) else {
        return;
    };
    match path.trim_matches('/') {
        "menu" => toggle_menu(&win),
        "fullscreen" => toggle_fullscreen(&win),
        "zoom-in" => zoom(app, &win, Some(0.5)),
        "zoom-out" => zoom(app, &win, Some(-0.5)),
        "zoom-reset" => zoom(app, &win, None),
        _ => {}
    }
}

/// Step the zoom level by `delta` (or reset it), Electron-style: level ±0.5,
/// factor 1.2^level, clamped to Chromium's 25%–500%.
fn zoom(app: &AppHandle, win: &WebviewWindow, delta: Option<f64>) {
    let state = app.state::<ZoomLevel>();
    let mut level = state.0.lock().unwrap_or_else(|p| p.into_inner());
    let next = match delta {
        Some(d) => *level + d,
        None => 0.0,
    };
    let factor = 1.2_f64.powf(next);
    if (0.25..=5.0).contains(&factor) {
        *level = next;
        let _ = win.set_zoom(factor);
    }
}

fn toggle_menu(win: &WebviewWindow) {
    let _ = match win.is_menu_visible() {
        Ok(true) => win.hide_menu(),
        _ => win.show_menu(),
    };
}

fn toggle_fullscreen(win: &WebviewWindow) {
    let full = win.is_fullscreen().unwrap_or(false);
    let _ = win.set_fullscreen(!full);
}

fn open_external(app: &AppHandle, url: &Url) {
    if matches!(url.scheme(), "http" | "https" | "mailto") {
        let _ = app.opener().open_url(url.as_str(), None::<&str>);
    }
}

/// Same menu as the Electron shell: File / Edit / View / Help.
///
/// The webview (reload, DevTools) and the injected script (zoom, fullscreen)
/// already handle the shortcuts, so these items only *show* them (text after
/// the tab) instead of registering a second accelerator that would fire twice.
fn build_menu(app: &AppHandle) -> tauri::Result<Menu<Wry>> {
    let file = SubmenuBuilder::new(app, "File").quit().build()?;
    let edit = SubmenuBuilder::new(app, "Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;
    let view = SubmenuBuilder::new(app, "View")
        .text("reload", "Reload\tCtrl+R")
        .text("devtools", "Toggle Developer Tools\tCtrl+Shift+I")
        .separator()
        .text("zoom-reset", "Actual Size\tCtrl+0")
        .text("zoom-in", "Zoom In\tCtrl+=")
        .text("zoom-out", "Zoom Out\tCtrl+-")
        .separator()
        .text("fullscreen", "Toggle Full Screen\tF11")
        .build()?;
    let help = SubmenuBuilder::new(app, "Help")
        .text("github", "Hizn on GitHub")
        .text("about", "About")
        .build()?;
    MenuBuilder::new(app)
        .items(&[&file, &edit, &view, &help])
        .build()
}

fn on_menu_event(app: &AppHandle, event: MenuEvent) {
    let Some(win) = app.get_webview_window(MAIN_WINDOW) else {
        return;
    };
    match event.id().as_ref() {
        "reload" => {
            let _ = win.reload();
        }
        "devtools" => {
            if win.is_devtools_open() {
                win.close_devtools();
            } else {
                win.open_devtools();
            }
        }
        "zoom-reset" => zoom(app, &win, None),
        "zoom-in" => zoom(app, &win, Some(0.5)),
        "zoom-out" => zoom(app, &win, Some(-0.5)),
        "fullscreen" => toggle_fullscreen(&win),
        "github" => {
            if let Ok(url) = REPO_URL.parse() {
                open_external(app, &url);
            }
        }
        "about" => {
            MessageDialog::new()
                .set_level(MessageLevel::Info)
                .set_title("About Hizn")
                .set_description(
                    "Hizn\n\nOne-click Android traffic interception with optional Burp chaining.\nAGPL-3.0-only.",
                )
                .set_parent(&win)
                .show();
        }
        _ => {}
    }
    // Like an auto-hidden menu bar: tuck it away again after use.
    let _ = win.hide_menu();
}
