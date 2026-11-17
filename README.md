# Hizn

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen.svg)](https://nodejs.org)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#setup)

One-click traffic interception for **Android *and* desktop Firefox**, with optional Burp Suite chaining — a self-contained, Burp-style interception workbench built on open components. Point a phone (or a Firefox window) at your machine, decrypt its HTTPS, and watch — or mock, replay, and fuzz — the traffic. Flip one toggle to forward everything through Burp.

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
- **Desktop app** — Electron shell (`npm run electron`) or headless/browser mode; dark/light theme.

## How it works

```
Android device
   │  global http_proxy  +  adb reverse  (set automatically over ADB)
   ▼
hizn proxy  ──(optional upstream)──►  Burp Suite  ──►  Internet
   │  mockttp engine + your root CA
   ▼
Web UI  ·  live flows, one-click connect, Burp toggle, CA download
```

- **Proxy engine:** [`mockttp`](https://github.com/httptoolkit/mockttp) — TLS interception, mocking/rewriting, and upstream-proxy chaining.
- **Device automation:** [`@devicefarmer/adbkit`](https://github.com/DeviceFarmer/adbkit) — detect device, push CA, set proxy, open reverse tunnels.
- **CA trust & unpinning:** [`frida-js`](https://github.com/httptoolkit/frida-js) + adapted [frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning) scripts (AGPL-3.0) — inject the CA and bypass certificate pinning on modern Android.

The static APK analyzer and MCP bridge use only Node's built-ins and existing dependencies — no extra runtime weight.

## Prerequisites

- **Node.js ≥ 20** (tested on 26)
- **ADB** (`platform-tools`) on your `PATH`
- *(optional, rooted-device CA install)* **OpenSSL** on your `PATH`
- *(optional, pinning bypass)* **frida-server** running on the device
- A device with **USB debugging** enabled, or a rooted emulator

## Setup

```bash
git clone https://github.com/umair-villanio/hizn.git
cd hizn
npm install
```

### Desktop app (recommended)

```bash
npm run electron     # builds the backend, then opens the desktop window
```

No terminal to watch, no browser tab — the backend (ADB, mockttp, Frida) runs
inside the Electron process and the window loads the UI on a private loopback
port. To produce an installer:

```bash
npm run dist         # → release/  (NSIS .exe on Windows, .dmg on macOS, AppImage on Linux)
```

### Headless / browser (no Electron)

```bash
npm run dev          # tsx watch — hot-reloads the backend
```

Then open the printed URL (default <http://127.0.0.1:4000>). For a production run:

```bash
npm run build
npm start
```

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
src/
  proxy/proxy-service.ts       mockttp engine, CA, Burp upstream, flow events
  devices/adb-service.ts       ADB: detect, proxy, push CA, reverse, frida tunnel, pull APKs
  frida/frida-service.ts       CA injection + unpinning payload + injection
  intruder/intruder-service.ts §marker fuzzing engine (Sniper / Battering-ram)
  analyzer/analyzer-service.ts static APK analysis (ZIP / AXML / arsc / signing block)
  mcp/mcp-server.ts            Model Context Protocol bridge (stdio JSON-RPC)
  orchestrator.ts              the one-click flow (ties it all together)
  api/server.ts                REST + WebSocket bridge to the UI
  index.ts                     entry point (headless server)
electron/main.js               desktop shell: boots the server + opens the window
electron/preload.js            exposes a read-only `window.hizn` marker
scripts/frida/                 adapted unpinning hook scripts (AGPL-3.0)
plugins/                       drop-in JS plugins (message + extension)
ui/index.html                  single-file web UI (no build step)
```

## Roadmap

Done:

- ✅ Burp-style interception — hold, edit, Forward/Drop.
- ✅ Repeater, Intruder, Match & Replace, Target scope, Decoder.
- ✅ Static APK analyzer (secrets, permissions, certificate, manifest).
- ✅ Plugins — message + fully-flexible extension plugins (tabs, buttons, live hooks).
- ✅ MCP integration tab with copy-paste configs.
- ✅ Save/export — Copy as cURL, HAR export, server-side history + JSON sessions.
- ✅ Dark/light theme, auto-connect Genymotion, auto-provision frida-server, Electron shell + installers.

Planned:

- **Server-side plugins** — a backend plugin host for inline traffic rewriting (today extension plugins run in the UI).
- **WebSocket interception** — pause/edit WS frames (today they pass through).
- **Companion Android app** — an "Activate" intent for one-tap device-side setup.

## Contributing

Issues and pull requests are welcome. Keep plugins self-contained (no npm deps,
no network calls) and target the `dev` branch. See [`plugins/README.md`](plugins/README.md)
for the plugin format.

## License

AGPL-3.0-only. Includes adapted AGPL-3.0 scripts from httptoolkit/frida-interception-and-unpinning. If you distribute a modified build, you must share your source. See [`NOTICE.md`](NOTICE.md) for third-party attributions.
