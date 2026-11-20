# Hizn — Rust port plan

Goal: replace the Node/TypeScript backend **and** the Electron shell with Rust
(Tauri), keeping the **same UI, same plugins, and same behavior** — for a
smaller, faster, lower-RAM app.

The Node app on `dev` stays untouched as the reference implementation until the
Rust version matches it feature-for-feature. This branch (`rust`) carries both
side by side during the port; the Node backend is removed only at cutover.

---

## Why this shape

The RAM cost of the current app is mostly **Electron's bundled Chromium**, not
the Node backend. So the port replaces both:

| | Today | After |
|---|---|---|
| Window / renderer | Electron (bundled Chromium) | Tauri 2 → OS webview (WebView2 on Windows) |
| Backend | Node + Express + ws + mockttp | Rust: axum + tokio + hudsucker |
| UI | `ui/index.html` | **`ui/index.html` — unchanged, byte for byte** |
| Plugins | JS in the webview | **unchanged** (they run in the webview, not the backend) |

The UI already talks to the backend only over relative `fetch('/api/…')` and
`ws://${location.host}/ws`, and never touches Electron APIs. The Rust app does
exactly what Electron does today: start the server on a free loopback port and
point a window at it. That is what keeps the UI and every plugin identical.

---

## Layout

```
Cargo.toml                    workspace
crates/
  hizn-server/                backend library + `hizn` headless binary (= npm start)
    src/lib.rs                router: /api, /ws, static UI
    src/state.rs              shared state + WebSocket client hub
    src/ws.rs                 /ws upgrade + hello snapshot
    src/api.rs                the 38-route REST table (+ 501 stubs for unported routes)
    src/main.rs               `hizn` binary
  hizn-app/                   (Phase 1) Tauri desktop shell — mirrors electron/main.js
  hizn-mcp/                   (Phase 5) stdio MCP bridge — mirrors src/mcp/mcp-server.ts
ui/  plugins/  scripts/frida/ shared, unchanged
src/  electron/               Node reference implementation (removed at cutover)
```

---

## Compatibility invariants (must hold, or it's a regression)

1. **Same CA.** Load `~/.hizn/ca-key.pem` + `ca-cert.pem` (RSA-2048, PKCS#8). Never
   mint a new one if these exist — devices and Firefox profiles that already trust
   Hizn must keep working with no re-import.
2. **Same API contract.** All 38 REST routes and 20 WebSocket event types, same
   paths, methods, JSON shapes, and status codes (see tables below).
3. **Same WS hello snapshot**, same effective order: `intercept-config`,
   `connections`, `scope`, `flow-snapshot`, held `intercept` items, `proxy-status`.
4. **Same files on disk:** `~/.hizn/plugins/`, `~/.hizn/plugins.json`,
   `~/.hizn/firefox-profile/`.
5. **Same defaults:** API port `DROIDMITM_PORT` (default 4000), proxy port 8000,
   upstream `127.0.0.1:8080`, intercept off / requests on / responses off, scope off.
6. **Same limits:** 5000 flows, 2000 WS frames per flow, 512 KiB intercept body,
   64 KiB per WS frame, 5000 intruder requests, 256 KiB intruder row body.
7. **Frida scripts reused as-is** from `scripts/frida/`.
8. **MCP tool names and arguments identical**, so existing client configs keep working.

---

## Crate choices

| Area | Node today | Rust | Notes |
|---|---|---|---|
| HTTP + WS server | express, ws | `axum`, `tokio`, `tower-http` | |
| MITM proxy | mockttp | `hudsucker` (hyper + rustls + rcgen) | main risk, see below |
| TLS crypto | Node OpenSSL | `rustls` + `ring` | needs a 64-bit C compiler to build |
| Leaf certs from CA | mockttp | `rcgen` | signs with the existing RSA CA |
| Upstream (Burp) chaining | mockttp | custom hyper connector (HTTP CONNECT) | hudsucker has no built-in upstream proxy |
| ADB | @devicefarmer/adbkit | ADB server protocol over TCP 5037 (`adb_client` or a thin own client) | same protocol adbkit speaks |
| Frida | frida-js (pure JS) | spike: pure-Rust D-Bus-over-WebSocket client (like frida-js) vs `frida` crate (native devkit) | decided in Phase 4 |
| Repeater / Intruder | Node http(s) | `reqwest` (rustls, invalid certs allowed) | |
| WS Repeater | ws | `tokio-tungstenite` | |
| APK analyzer | custom ZIP/AXML/arsc + node-forge | `zip` + ported AXML/arsc parsers + `x509-parser` | |
| MCP bridge | custom stdio JSON-RPC | `serde_json` + blocking HTTP client | separate small binary |
| Desktop shell | Electron | Tauri 2 | system webview |

---

## REST contract (38 routes)

| Route | Phase |
|---|---|
| `GET /status` | 0 (stopped-proxy state), full in 2 |
| `GET /ca`, `POST /proxy/start`, `POST /proxy/stop`, `POST /upstream` | 2 |
| `GET /flows`, `POST /flows/clear`, `POST /flows/import` | 2 |
| `GET /intercept`, `POST /intercept/config`, `POST /intercept/resolve` | 3 |
| `GET /rules`, `POST /rules` | 3 |
| `GET /scope`, `POST /scope` | 3 |
| `GET /devices`, `GET /connections`, `POST /connect`, `POST /disconnect`, `POST /connect/genymotion` | 4 |
| `POST /frida/provision` | 4 |
| `POST /repeater/send`, `POST /repeater/ws/open`, `POST /repeater/ws/send`, `POST /repeater/ws/close` | 5 |
| `POST /intruder/start`, `POST /intruder/stop` | 5 |
| `POST /analyzer/scan`, `GET /analyzer/packages`, `POST /analyzer/scan-device` | 5 |
| `GET /desktop/info`, `POST /desktop/import-ca`, `POST /desktop/firefox` | 5 |
| `GET /plugins`, `POST /plugins`, `POST /plugins/toggle`, `DELETE /plugins/:origin/:file` | 5 |
| `GET /mcp/info` | 5 |

Until a route is ported, the Rust server answers it with **`501` +
`{"error": "...", "route", "phase"}`**. The UI's `api()` helper surfaces
`error`, so an unported feature shows a clear message instead of breaking, and
the remaining gap is countable at any time.

## WebSocket events (20)

`proxy-status`, `flow`, `flow-update`, `flow-snapshot`, `flows-cleared`,
`ws-message`, `upstream`, `intercept`, `intercept-closed`, `intercept-config`,
`scope`, `connections`, `setup-step`, `intruder-start`, `intruder-row`,
`intruder-done`, `ws-repeater-open`, `ws-repeater-message`, `ws-repeater-close`,
`ws-repeater-error`.

---

## Phases

Each phase ends with its exit check passing **against the Node reference**
before the next one starts.

### Phase 0 — Foundations (code written; run blocked on toolchain)
- Cargo workspace; `hizn-server` crate; `hizn` headless binary.
- Serves the unchanged `ui/` and `/ws` with the hello snapshot in the same order.
- `GET /status` returns the stopped-proxy status in the exact Node shape.
- All other 37 routes registered as 501 stubs tagged with their phase.
- Unit tests: `/status` shape + key order, hello-snapshot order, broadcast fan-out,
  38-route table with no duplicates, router builds without conflicts.
- Status: `cargo check --all-targets` passes. Linking is blocked on this machine
  (see *Toolchain status*), so the binary and tests have not run yet.
- **Exit:** tests pass; the UI loads from the Rust server, the WebSocket connects
  and gets its snapshot, and status shows the proxy as stopped.

### Phase 1 — Toolchain + desktop shell
- Install the MSVC toolchain (VS 2022 Build Tools, C++ workload + Windows SDK),
  `rustup` target `x86_64-pc-windows-msvc`, pin it with `rust-toolchain.toml`.
- Re-run the Phase 0 exit check (first thing after the toolchain lands).
- `hizn-app` (Tauri 2), mirroring `electron/main.js`: free loopback port, 1180×820
  window (min 900×640), single instance, external links open in the browser,
  same menu (reload / devtools / zoom / about).
- Record a baseline: Electron idle RAM, startup time, install size.
- **Exit:** the desktop window shows the UI from the Rust backend.

### Phase 2 — Proxy core (largest phase)
- CA: load the existing `~/.hizn` CA; generate + persist only if missing.
  `GET /ca` serves the same PEM.
- HTTP + HTTPS MITM via hudsucker; per-host leaf certs cached.
- Flow capture: `flow` / `flow-update` with identical fields; flow store (cap 5000);
  `GET /flows`, clear, import.
- Upstream chaining to Burp (`POST /upstream`, `upstream` event).
- **Exit:** a parity harness sends the same traffic through the Node and Rust
  proxies (HTTP, HTTPS, chunked, gzip/br, large and binary bodies, redirects,
  and HTTP/2 to the same extent the Node reference negotiates it) and the
  captured flows match; Burp chaining works.

### Phase 3 — Proxy features
- Intercept: hold / edit / forward / drop for requests and responses, per-request
  "intercept response", held items in the hello snapshot.
- Match & Replace rules (all 5 parts, regex + literal).
- Target scope (substring + `*.wildcard`).
- WebSocket interception history (`ws-message`, frame caps).
- **Exit:** parity harness covers intercept edits, rules, and scope; manual
  intercept session matches Node behavior.

### Phase 4 — Devices + Frida
- ADB: device list, global proxy, CA push (rooted + APEX path, non-rooted staging),
  `adb reverse`, Genymotion auto-connect, connect/disconnect + `connections`.
- Orchestrator: one-click flow with the same `setup-step` sequence.
- Frida: spike both client options, pick one; provision frida-server by ABI;
  CA injection + unpinning with the unchanged `scripts/frida/` scripts.
- **Exit:** one-click connect on a real device captures HTTPS; unpinning works
  on a pinned app; Genymotion auto-connects.

### Phase 5 — Tools
- Repeater (HTTP) and WS Repeater.
- Intruder: Sniper / Battering-ram, all payload types + processing, streamed rows.
- APK analyzer: scan upload, device package list, pull + scan.
- Desktop: Firefox launch with the dedicated profile, NSS `certutil` import.
- Plugins API: list / add / toggle / delete, reusing `plugins.json`.
- `hizn-mcp` binary: same tools, same gating (`HIZN_MCP_ACTIVE`), `GET /mcp/info`
  points at it.
- **Exit:** analyzer reports match Node's on the reference APKs; intruder results
  match; MCP `tools/list` and tool calls match.

### Phase 6 — Hardening + sign-off
- Parity checklist complete: 38/38 routes, 20/20 events, zero 501s.
- Soak test (hours of real device traffic), memory-leak check.
- Measure against the Phase 1 baseline: idle RAM, RAM under load, startup,
  install size, proxy latency.
- Installer via the Tauri bundler.

### Phase 7 — Cutover
- Rust becomes the default build; the Node backend and Electron shell are removed
  from this branch (they remain in `dev` history).
- README updated; merged to `dev` once you approve.

---

## Verification strategy

- **Parity harness:** run the Node and Rust servers side by side on two ports,
  replay the same API calls and proxy traffic against local test targets, and diff
  the JSON responses, WS events, and captured flows. Differences fail the phase.
- **Real-world passes** at the end of Phases 2–5: an Android device, a Genymotion
  VM, and the Firefox flow.
- **Plugins:** the bundled `jwt-decoder.js` and `sitemap.js` are exercised in the
  Rust-served UI at each phase; they need no changes.

## Risks

| Risk | Mitigation |
|---|---|
| Proxy edge cases differ from mockttp (streaming, TLS quirks, HTTP/2, WS passthrough) | parity harness per case; fix before moving on |
| Upstream chaining isn't built into hudsucker | custom CONNECT connector, tested against Burp |
| Frida client in Rust | spike two options in Phase 4 before committing |
| Toolchain: machine has `windows-gnu` + 32-bit MinGW only | install MSVC Build Tools in Phase 1 (one-time) |
| Future server-side plugins (backend JS) | embed a small JS engine (QuickJS via `rquickjs`) so plugins stay JavaScript |

## Toolchain status

This machine has Rust 1.100 on `stable-x86_64-pc-windows-gnu`, and only a
**32-bit** MinGW (`C:\MinGW`, GCC 6.3). That's not enough to link current Windows
crates: `windows-sys` and `getrandom` use `raw-dylib`, which on the GNU target
needs a 64-bit `dlltool` *and* a 64-bit assembler (`as`). Rust bundles the
former but not the latter, and the 32-bit MinGW tools on `PATH` reject x86-64.
`cargo check` works (it skips that step); `cargo build` / `cargo test` do not.

The fix is the MSVC toolchain from Phase 1, which is also what Tauri, `ring`, and
the Windows SDK resource compiler need. Once it's installed:

```bash
rustup toolchain install stable-x86_64-pc-windows-msvc
cargo test -p hizn-server
```

## Running Phase 0

```bash
cargo run -p hizn-server            # → http://127.0.0.1:4000
DROIDMITM_PORT=4321 cargo run -p hizn-server
```

The server finds `ui/` automatically when run from the repo; set `HIZN_UI_DIR`
to override.
