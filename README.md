# Hizn

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable%20(MSVC)-orange.svg)](https://www.rust-lang.org)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#setup)

One-click traffic interception for **Android *and* desktop Firefox**, with optional Burp Suite chaining — a self-contained, Burp-style interception workbench. Point a phone (or a Firefox window) at your machine, decrypt its HTTPS, and watch — or mock, replay, and fuzz — the traffic. Flip one toggle to forward everything through Burp.

A **native Rust application** (Tauri desktop shell + a native backend): a single small binary, low RAM, no runtime to install.

> **Authorized testing only.** Use this on devices and apps you own or are explicitly permitted to test. You are responsible for complying with all applicable laws.

## Features

- **Live interception** — hold requests/responses, edit headers/body, Forward or Drop.
- **HTTP history** — every flow streamed live, with a request/response detail pane, Copy as cURL, and HAR export.
- **Repeater** — send any request to Repeater, edit, and re-fire with status + timing; boxes auto-size to content.
- **Intruder** — Burp-style fuzzing with `§markers§`, Sniper / Battering-ram attacks, payload types (numbers, brute-force, null) and processing; click any result row to inspect its full request/response.
- **Match & Replace** — auto-rewrite rules for request/response headers, body, and URL across all traffic.
- **Target scope** — limit interception to specific hosts, with an in-scope-only history filter.
- **Decoder** — base64 / URL / hex / HTML / JWT encode-decode with smart auto-detect.
- **Static APK analyzer** — drag-and-drop (or pull from a connected device over ADB) an `.apk` to extract version, permissions, hardcoded secrets/keys, certificate information + analysis, and manifest analysis — no external service, all local.
- **Plugins** — Burp-extension-style add-ons in plain JavaScript (no build step). *Message plugins* transform a single intercepted message; *extension plugins* are fully flexible — they add new tabs, inject buttons, hook live traffic, and call Hizn's API. See [`plugins/README.md`](plugins/README.md).
- **MCP integration** — exposes Hizn's API over the Model Context Protocol (stdio JSON-RPC) so external tooling can drive it programmatically; read-only by default, write tools gated behind an explicit toggle. See [`mcp/README.md`](mcp/README.md).
- **Desktop app** — native Tauri window, or headless/browser mode; dark/light theme.

## How it works

```
Android device
   │  global http_proxy  +  adb reverse  (set automatically over ADB)
   ▼
hizn proxy  ──(optional upstream)──►  Burp Suite  ──►  Internet
   │  native TLS engine + your root CA
   ▼
Web UI  ·  live flows, one-click connect, Burp toggle, CA download
```

- **Proxy engine:** a native MITM engine on [`hyper`](https://github.com/hyperium/hyper) + [`rustls`](https://github.com/rustls/rustls), with on-the-fly leaf certificates signed by your root CA ([`rcgen`](https://github.com/rustls/rcgen)) — TLS interception, mocking/rewriting, and upstream-proxy chaining.
- **Device automation:** a from-scratch ADB client (the ADB server protocol on TCP 5037) — detect device, push CA, set proxy, open reverse tunnels, pull APKs. Drives your own `adb` server; no bundled binary.
- **CA trust & unpinning:** a pure-Rust Frida control-protocol client (D-Bus framed over a WebSocket to `frida-server`) plus adapted [frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning) scripts (AGPL-3.0) — inject the CA and bypass certificate pinning on modern Android.

The static APK analyzer, MCP bridge, and Frida client are all native Rust with no external service and no extra runtime.

## Prerequisites

- **Rust** (stable) with the MSVC toolchain on Windows — see [`rust-toolchain.toml`](rust-toolchain.toml); `rustup` installs it automatically.
- **ADB** (`platform-tools`) on your `PATH`
- *(optional, pinning bypass)* **frida-server** on the device — or let One-Click Connect auto-provision it on a rooted device
- A device with **USB debugging** enabled, or a rooted emulator

## Setup

```bash
git clone https://github.com/umair-villanio/Hizn.git
cd Hizn
```

### Desktop app (recommended)

```bash
cargo run -p hizn-app        # native window; backend runs in-process
```

The backend (ADB, proxy, Frida) runs inside the app process and the window loads
the UI on a private loopback port — no terminal to watch, no browser tab. To
produce an installer:

```bash
cargo tauri build            # → target/release/bundle/  (NSIS .exe on Windows)
```

### Headless / browser (no desktop shell)

```bash
cargo run -p hizn-server     # starts the API + UI server
```

Then open the printed URL (default <http://127.0.0.1:4000>). Set `DROIDMITM_PORT`
to change the port. For an optimized build, add `--release`.

## Using it

1. Plug in the device (`adb devices` should list it) and hit **↻ Refresh**.
2. *(Optional)* enter a **Frida target** app id (e.g. `com.android.chrome`) to enable CA injection + unpinning for that app. On a rooted device, One-Click Connect will **auto-download and start frida-server** for the device's ABI if it isn't already running (or use the **Set up Frida** button on its own).
3. *(Optional)* tick **Forward all traffic to Burp** and set Burp's host/port, then **Apply upstream**. In Burp, listen on `127.0.0.1:8080` (Proxy → Options).
4. Press **⚡ One-Click Connect**. The setup panel shows each step: device check → proxy up → host IP → CA install → traffic routing → Frida inject.
5. Open an app on the device; flows stream into the table live.

### Desktop (Firefox)

Click **🦊 Launch Firefox & capture**. hizn starts the proxy and opens a
*dedicated* Firefox profile (`~/.hizn/firefox-profile`) already pointed at
it — your normal Firefox is untouched. **CA trust is automatic** when an NSS `certutil` is on your `PATH` — hizn
imports the CA straight into the profile's `cert9.db`, scoped to this profile
only (your normal Firefox and the OS trust store are never touched). If NSS
tools aren't installed, Firefox opens on the Certificates page for a one-time
import: **View Certificates → Authorities → Import** → pick `hizn-ca.pem`
(path shown in the card) → tick "Trust for websites". It persists, so you only
do it once.

> NSS `certutil` ships in the `nss`/`libnss3-tools` package (Linux),
> `brew install nss` (macOS), or Mozilla's NSS binary releases (Windows). It is
> **not** the same as Windows' `System32\certutil.exe`, which hizn ignores.

### CA trust, by device type

| Device | What happens |
|---|---|
| **Rooted / emulator** | CA is copied into the system trust store (`/system/etc/security/cacerts`, + APEX path on Android 14+). All apps trust it. |
| **Non-rooted** | CA is staged at `/sdcard/Download/hizn-ca.crt` for manual install (Settings → Security → Install certificate), **or** use a Frida target to inject it per-app. |

## APK analyzer

Open the **Analyzer** tab, then drag an `.apk` onto it or **pull an installed app**
from a connected device. Everything is parsed locally (ZIP, binary
`AndroidManifest.xml`, `resources.arsc`, and the APK signing block) — nothing is
uploaded. It reports:

- **App info** — package, versionName / versionCode, SDK targets.
- **Permissions** — every requested permission, dangerous ones flagged.
- **Secrets** — hardcoded API keys/tokens (Google, AWS, Firebase, Stripe, JWTs, …) scanned across code, resources, and string pools.
- **Certificate** — signer DN, validity, fingerprints, signature scheme (v1/v2/v3), with an analysis of weak/notable properties.
- **Manifest** — components, exported surfaces, and other notable manifest entries.

## Plugins & integration

- **`plugins/`** — drop-in JavaScript extensions. `jwt-decoder.js` and `sitemap.js` ship as samples; see [`plugins/README.md`](plugins/README.md) for the message- and extension-plugin APIs.
- **`mcp/`** — Model Context Protocol server exposing Hizn's REST API as tools over stdio; see [`mcp/README.md`](mcp/README.md) for registration and the tool table.

## Project layout

```
crates/
  hizn-proxy/       native MITM engine (hyper + rustls + rcgen): CA, TLS, Burp upstream, flow events
  hizn-devices/     ADB client + one-click orchestrator + Frida provisioning & injection
  hizn-tools/       Repeater, Intruder (§marker fuzzing), WebSocket Repeater
  hizn-analyzer/    static APK analysis (ZIP / AXML / arsc / signing block)
  hizn-server/      REST + WebSocket bridge to the UI; serves the static UI
  hizn-mcp/         Model Context Protocol bridge (stdio JSON-RPC)
  hizn-app/         Tauri desktop shell: boots the server + opens the window
scripts/frida/      adapted CA-injection + unpinning hook scripts (AGPL-3.0)
plugins/            drop-in JS plugins (message + extension)
ui/index.html       single-file web UI (no build step)
```

See [`RUST-PORT.md`](RUST-PORT.md) for the design notes and the port history.

## Roadmap

Done:

- ✅ Burp-style interception — hold, edit, Forward/Drop.
- ✅ Repeater, Intruder, Match & Replace, Target scope, Decoder.
- ✅ Static APK analyzer (secrets, permissions, certificate, manifest).
- ✅ Plugins — message + fully-flexible extension plugins (tabs, buttons, live hooks).
- ✅ MCP integration tab with copy-paste configs.
- ✅ Save/export — Copy as cURL, HAR export, server-side history + JSON sessions.
- ✅ Dark/light theme, auto-connect Genymotion, auto-provision frida-server, native desktop shell + installer.

Planned:

- **Server-side plugins** — a backend plugin host for inline traffic rewriting (today extension plugins run in the UI).
- **WebSocket interception** — pause/edit WS frames (today they pass through).
- **Companion Android app** — an "Activate" intent for one-tap device-side setup.

## Contributing

Issues and pull requests are welcome. Keep plugins self-contained (no npm deps,
no network calls) and target the `dev` branch. See [`plugins/README.md`](plugins/README.md)
for the plugin format.

## Credits

Hizn's Android/Frida interception approach builds on the open-source work of [HTTP Toolkit](https://httptoolkit.com) by Tim Perry (AGPL-3.0); see [`NOTICE.md`](NOTICE.md) for full attributions.

## License

AGPL-3.0-only. Includes adapted AGPL-3.0 scripts from httptoolkit/frida-interception-and-unpinning. If you distribute a modified build, you must share your source. See [`NOTICE.md`](NOTICE.md) for third-party attributions.
