# Hizn

One-click traffic interception for **Android *and* desktop Firefox**, with optional Burp Suite chaining — built as an original tool on open components. Point a phone (or a Firefox window) at your machine, decrypt its HTTPS, and watch (or mock/rewrite) the traffic. Flip one toggle to forward everything through Burp.

> **Authorized testing only.** Use this on devices and apps you own or are explicitly permitted to test.

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

## Prerequisites

- **Node.js ≥ 20** (tested on 26)
- **ADB** (`platform-tools`) on your `PATH`
- *(optional, rooted-device CA install)* **OpenSSL** on your `PATH`
- *(optional, pinning bypass)* **frida-server** running on the device
- A device with **USB debugging** enabled, or a rooted emulator

## Setup

### Desktop app (recommended)

```bash
npm install
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

## Project layout

```
src/
  proxy/proxy-service.ts   mockttp engine, CA, Burp upstream, flow events
  devices/adb-service.ts   ADB: detect, proxy, push CA, reverse, frida tunnel
  frida/frida-service.ts   CA injection + unpinning payload + injection
  orchestrator.ts          the one-click flow (ties it all together)
  api/server.ts            REST + WebSocket bridge to the UI
  index.ts                 entry point (headless server)
electron/main.js           desktop shell: boots the server + opens the window
electron/preload.js        exposes a read-only `window.hizn` marker
scripts/frida/             adapted unpinning hook scripts (AGPL-3.0)
ui/index.html              single-file web UI (no build step)
```

## Roadmap / extension points

- ~~Burp-style interception~~ ✅ done — hold requests/responses, edit headers/body, Forward or Drop (Intercept card / header chip).
- ~~Plugins~~ ✅ done — Burp-extension-style tabs in the intercept panel; ships a JWT decoder, plus add custom `transform(ctx)` plugins.
- ~~Repeater~~ ✅ done — "→ Repeater" from HTTP history or a held request; edit and re-send, with status + timing.
- ~~Match & Replace~~ ✅ done — auto-rewrite rules (request/response headers, body, URL) applied to all traffic.
- ~~Connected-device status~~ ✅ done — live "connected" badge + one-click Disconnect.
- ~~Target scope~~ ✅ done — limit intercept to specific hosts; "in-scope only" history filter.
- ~~Save / export~~ ✅ done — request/response bodies in the detail pane; Copy as cURL; Export HTTP history as .har.
- ~~Server-side history + sessions~~ ✅ done — history survives UI reconnects; Save/Load a capture session as JSON.
- ~~Decoder~~ ✅ done — base64 / URL / hex / HTML / JWT encode-decode, with smart auto-detect.
- ~~Dark / light theme~~ ✅ done (header toggle, follows system by default).
- ~~Auto-connect Genymotion~~ ✅ done (detected VMs connect automatically).
- ~~Auto-provision frida-server~~ ✅ done (download + push + start by ABI).
- ~~Electron shell~~ ✅ done (`npm run electron`; `npm run dist` builds installers).
- **Server-side plugins** — today plugins run in the UI; add a backend plugin host for traffic rewriting.
- **WebSocket interception** — pause/edit WS frames (today they pass through).
- **Companion Android app** — an "Activate" intent for one-tap device-side setup.

## License

AGPL-3.0-only. Includes adapted AGPL-3.0 scripts from httptoolkit/frida-interception-and-unpinning. If you distribute a modified build, you must share your source.
