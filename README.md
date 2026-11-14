# droidmitm

One-click Android traffic interception, with upstream chaining into Burp Suite.

Open source (AGPL-3.0). Architecture derived from a study of HTTP Toolkit's
open-source implementation — see `NOTICE.md` for attribution and the
[RE notes](#how-http-toolkit-does-it) below.

## Architecture

```
┌──────────────┐     ┌─────────────────────────────────────┐     ┌──────┐
│ ui/ (later)  │────▶│ daemon (Node/TS)                     │────▶│ Burp │
│              │◀────│  src/proxy  : mockttp MITM (Apache)  │     │ :8080│
└──────────────┘ WS  │  src/devices: adbkit ADB pipeline    │     └──────┘
                     │  src/frida  : per-app injection      │         ▲
                     │  src/api    : REST + WS control      │   upstream chain
                     └─────────┬───────────────────────────┘  (proxyConfig)
                               │ adb / VpnService
                               ▼
                        Android device
```

- **MITM core**: `mockttp` (Apache-2.0) — CA generation, TLS interception, HTTP/1.1+2, WebSockets.
- **Burp chaining**: mockttp `proxyConfig` on the passthrough rules —
  `proxyUrl: 'http://127.0.0.1:8080'` + `additionalTrustedCAs` for Burp's CA.
- **Device pipeline** (Phase 2): adbkit — cert push, tmpfs `/system/etc/security/cacerts`
  overlay, `adb reverse` tunnels, companion-app ACTIVATE intent.
- **Frida pipeline** (Phase 3): `frida-js` — frida-server lifecycle, spawn-paused
  injection of proxy-override + unpinning scripts.
- **Companion app** (`android-app/`, Phase 4): Kotlin `VpnService` app for
  non-rooted whole-device capture.

## How HTTP Toolkit does it (RE notes)

Two paths, both ending at mockttp:

**ADB path** (`httptoolkit-server/src/interceptors/android/`)
1. `adbkit` device detection → `getRootCommand` probes for su/Magisk
2. Rooted: push CA to `/data/local/tmp`, then tmpfs-overlay it into
   `/system/etc/security/cacerts` (copy out → `mount -t tmpfs` → copy back + add
   → SELinux `chcon` → also bind-mount `/apex/com.android.conscrypt/cacerts`
   for Android 14+ per-app visibility). Plus CT-log-list injection (Android 16+)
   and Chrome `--ignore-certificate-errors-spki-list`.
3. Install companion APK (`tech.httptoolkit.android.v1`, fetched from GitHub releases)
4. `adb reverse` persistent tunnel (USB/emulator → host proxy)
5. Intent `tech.httptoolkit.android.ACTIVATE` with base64
   `{addresses, port, localTunnelPort, enableSocks, certFingerprint}` →
   app starts `VpnService` routing all traffic to the proxy

**Frida path** (`httptoolkit-server/src/interceptors/frida/` — rooted/emulator)
1. Push + launch `frida-server`, enumerate installed app targets
2. Spawn target app paused → probe reachable host IP → inject JS bundle
   (proxy override + cert unpinning + fallback + root-detection disable +
   Flutter unpinning + system-cert injection) → resume

## Roadmap

- [x] Phase 1 — daemon: mockttp core, CA, REST+WS API, Burp upstream toggle
- [ ] Phase 2 — Android one-click (rooted): ADB detect, cert inject, reverse
      tunnel, proxy routing
- [ ] Phase 3 — Frida per-app interception + unpinning bundle
- [ ] Phase 4 — `VpnService` companion app for non-rooted devices
      (study `httptoolkit/httptoolkit-android`, AGPL)
- [ ] Phase 5 — web UI (traffic list, device panel, Burp toggle)
- [ ] Phase 6+ — your new features

## Dev setup

```bash
npm install
npm run dev          # daemon on :13456
```

Requires Node >= 20 and `adb` on PATH (platform-tools).

```bash
# Start interception proxy, chained upstream into Burp:
curl -X POST http://127.0.0.1:13456/api/proxy/start \
  -H 'content-type: application/json' \
  -d '{"port":8000,"burpUrl":"http://127.0.0.1:8080","burpCaPath":"C:/path/to/burp-ca.der"}'

curl http://127.0.0.1:13456/api/status
curl http://127.0.0.1:13456/api/devices     # adb devices
curl http://127.0.0.1:13456/api/ca.pem -o ca.pem
```
