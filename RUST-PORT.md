# Hizn — Rust port plan

Goal: replace the Node/TypeScript backend **and** the Electron shell with Rust
(Tauri), keeping the **same UI, same plugins, and same behavior** — for a
smaller, faster, lower-RAM app.

The Node app on `dev` stays untouched as the reference implementation until the
Rust version matches it feature-for-feature. This branch (`rust`) carries both
side by side during the port; the Node backend is removed only at cutover.

---

## Why this shape

Electron ships its own Chromium (~300 MB on disk) and runs the Node backend in
its main process. Tauri uses the Chromium that's already part of Windows
(WebView2), and the backend becomes native Rust. So the port replaces both.

What that buys, measured (see *Phase 1*): the install drops from ~300 MB to a
~10 MB exe, and the backend process drops from ~112 MB to ~6 MB private. The
UI itself still renders in Chromium either way (WebView2 *is* Chromium), so the
renderer and GPU processes cost about the same in both — total RAM goes down by
roughly a third, not by multiples.

| | Today | After |
|---|---|---|
| Window / renderer | Electron (bundled Chromium) | Tauri 2 → OS webview (WebView2 on Windows) |
| Backend | Node + Express + ws + mockttp | Rust: axum + tokio + own proxy engine (hyper + rustls) |
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
  hizn-proxy/                 (Phase 2) interception engine — replaces mockttp
    src/ca.rs                 load/create the ~/.hizn CA, mint per-host leaf certs
    src/listener.rs           proxy listener, CONNECT, TLS sniffing + interception
    src/forward.rs            forward one exchange, report it as a flow
    src/ws.rs                 WebSocket passthrough
    src/upstream.rs           origin connections, Burp chaining, trust store
    src/headers.rs            mockttp-style header objects for flows
    src/capture.rs            streaming body capture
  hizn-app/                   (Phase 1) Tauri desktop shell — mirrors electron/main.js
  hizn-mcp/                   (Phase 5) stdio MCP bridge — mirrors src/mcp/mcp-server.ts
tools/parity/                 Node-vs-Rust parity harness
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
| MITM proxy | mockttp | own engine on `hyper` + `hyper-util` + `tokio-rustls` (`crates/hizn-proxy`) | `hudsucker` was evaluated and rejected — see Phase 2 |
| TLS crypto | Node OpenSSL | `rustls` + `ring` | needs a 64-bit C compiler to build |
| Leaf certs from CA | mockttp | `rcgen` | signs with the existing RSA CA |
| Upstream (Burp) chaining | mockttp | custom connector: HTTP `CONNECT` tunnel for everything | same as mockttp |
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

### Phase 0 — Foundations ✅ verified
- Cargo workspace; `hizn-server` crate; `hizn` headless binary.
- Serves the unchanged `ui/` and `/ws` with the hello snapshot in the same order.
- `GET /status` returns the stopped-proxy status in the exact Node shape.
- All other 37 routes registered as 501 stubs tagged with their phase.
- Unit tests: `/status` shape + key order, hello-snapshot order, broadcast fan-out,
  38-route table with no duplicates, router builds without conflicts.
- **Exit:** tests pass; the UI loads from the Rust server, the WebSocket connects
  and gets its snapshot, and status shows the proxy as stopped.
- Result: 5/5 tests pass, clippy `-D warnings` clean, rustfmt clean. `GET /`
  serves `ui/index.html` byte for byte; `/api/status` matches the Node JSON;
  the browser gets the hello snapshot in Node's order and the header shows
  "Proxy stopped / Burp off / Intercept off". Release `hizn.exe` is 1.7 MB.

### Phase 1 — Toolchain + desktop shell ✅ verified
- MSVC toolchain installed and pinned (`rust-toolchain.toml`).
- `crates/hizn-app` (Tauri 2.12), mirroring `electron/main.js`:
  - backend on a free loopback port (binds port 0 directly — no probe-then-bind race);
  - 1180×820 window (min 900×640), `#0e1116` background, app icon from the UI logo;
  - single instance: a second launch focuses/restores the first and exits;
  - same `window.hizn` marker as the Electron preload (`desktop`, `platform`, `versions`);
  - **no Tauri IPC exposed to the page**; links off the backend open in the browser;
  - menu bar hidden like Electron's `autoHideMenuBar` — Alt shows it — with
    File / Edit / View / Help (reload, DevTools, zoom, fullscreen, GitHub, About);
  - keyboard: Ctrl+R/F5 reload and F12/Ctrl+Shift+I DevTools (webview built-ins),
    Ctrl+=/-/0 zoom with Electron's steps (level ±0.5, factor 1.2^level), F11 fullscreen;
  - exports (`<a download>`) open a native Save dialog, like Electron.
- Verified in the running window over the WebView2 debug port: UI and all 7 tabs
  load, hello snapshot in Node's order, `/api/status` correct, zoom steps
  1.25→1.37→1.50→1.25 (on a 125% display), F11 → 1536×864 fullscreen and back
  to the same window rect, second launch exits in ~150 ms and restores the
  window, HAR export opens "Save As" and cancel writes nothing.
- Baseline (idle, UI loaded, release builds, same machine):

  | | Tauri (`hizn-app`) | Electron (`Hizn` 0.2.0) |
  |---|---|---|
  | On disk | **9.5 MB** single exe | 299 MB folder (118 MB zip) |
  | Total private memory | **178 MB** (7 processes) | 255 MB (4 processes) |
  | Total working set | 389 MB | 426 MB |
  | Shell + backend process | **5.5 MB** private | 112 MB private (Node) |
  | UI renderer | 32 MB | 28 MB |
  | GPU process | 82 MB | 102 MB |

  The backend number is before the proxy engine exists (Node's includes
  mockttp); re-measure in Phase 6. A further ~80 MB could come from running the
  webview without GPU acceleration — to evaluate in Phase 6, not assumed.

### Phase 2 — Proxy core ✅ verified
- **Engine:** `crates/hizn-proxy`, written on hyper/rustls rather than `hudsucker`.
  hudsucker answers WebSocket upgrades with its own `101` *before* reaching the
  origin (losing subprotocol negotiation), sends WebSockets and non-intercepted
  tunnels around the upstream proxy, always offers HTTP/2, and can't drop a
  connection — each would have broken apps or Burp chaining.
- **CA:** loads the existing `~/.hizn` CA (verified: `/api/ca` byte-identical,
  fingerprint `c464136955c72e94` from both backends); per-host leaf certs
  (shared ECDSA key, cached), DNS or IP SANs.
- **TLS:** HTTP/1.1 whenever the client offers it, HTTP/2 only for h2-only
  clients (mockttp's `http2: 'fallback'`); an h2 client still reaches an
  HTTP/1.1-only origin.
- **Flows:** `flow` once the request body has arrived, `flow-update` when the
  response body has been delivered (`error: 'aborted'` if the client leaves);
  same fields, order, and header-object rules as mockttp (`rawHeadersToObject`);
  HTTP/2 flows carry the pseudo-headers and `:status`, with `statusMessage: ""`.
- **Errors:** unreachable origins answer `502 Error communicating with upstream
  server` with Node's error text (`Error: connect ECONNREFUSED 127.0.0.1:47199`,
  `Error: getaddrinfo ENOTFOUND …`) and are recorded as responses; a request
  aimed at the proxy itself gets mockttp's `500` loop message.
- **Upstream:** Burp chaining through `CONNECT` for HTTP and HTTPS alike; switching
  takes effect immediately while running.
- **Routes ported (8/38):** `/status`, `/ca`, `/proxy/start`, `/proxy/stop`,
  `/upstream`, `/flows`, `/flows/clear`, `/flows/import`.
- **Parity harness** (`tools/parity/proxy-parity.mjs`): runs both backends side
  by side and compares what the client got, what the origin got, and the
  flow. Phase 2 result: **45/45** — 36 identical, 9 with only the differences below.
  Covers HTTP, HTTPS (by name and IP), query strings, JSON and 1 MB uploads,
  chunked, gzip, brotli, a 2 MB binary body, UTF-8 and invalid bytes, 204,
  HEAD, redirects, repeated headers both ways, 404, plain HTTP inside CONNECT,
  refused / DNS / untrusted-TLS origins, client abort, loop, ws, wss, an
  h2-only client, Burp chaining (HTTP + HTTPS), and 17 REST/WebSocket API steps.
- Checked in the real UI: live history, request detail, Clear, header status.

**Differences from Node — intentional, each recorded in the harness:**

| | Node (mockttp) | Rust | Why |
|---|---|---|---|
| HTTPS to an IP address | client rejects the cert (no IP SAN) | works | improvement |
| Response delivery | whole response buffered before any byte is sent | streamed | improvement: SSE / long responses work. Phase 3 buffers only when a response is held or rewritten. |
| WebSocket `Sec-WebSocket-Protocol` | only the first offered value forwarded | header passed through unchanged | improvement |
| Error reply framing | no headers, close-delimited | `content-length`, then close | same status, reason and body |
| TLS failure text | OpenSSL wording | rustls mapped to Node's wording where known | e.g. `self-signed certificate` |
| HTTP/2 → HTTP/1.1 origin | adds `Connection: keep-alive` | omitted | a connection header breaks h2-capable origins |
| Loop request | an extra flow with no response | one flow | |
| CA on a fresh install | RSA-2048 | ECDSA P-256 | `ring` can't generate RSA keys; an existing RSA CA is always reused |
| Request JSON limit | 100 KB (large session imports fail) | 600 MB | fix |
| `POST /upstream` without host/port | sets them to `undefined` | keeps the previous values | the UI always sends both |
| Origin certificate trust | Node's bundled roots | Mozilla roots + Windows store (+ `HIZN_EXTRA_CA_CERTS`) | a Burp CA trusted by Windows works when chaining |

WebSocket frame history (`ws-message`, `wsMessages`, `wsCloseCode`) landed in
Phase 3.

Run the harness:

```bash
cargo build -p hizn-server
node tools/parity/proxy-parity.mjs --node ../droidmitm --rust target/debug/hizn.exe
```

### Phase 3 — Proxy features ✅ verified
- **Intercept** (`policy.rs`, `forward.rs`): hold / edit / forward / drop for
  requests and responses, per-request "intercept response", turning a kind off
  releases its held items, stopping releases everything, held items in the
  hello snapshot. Drop closes the connection with no reply, as mockttp does.
- **Edits** behave like mockttp: edited or rule-rewritten bodies are re-encoded
  per `Content-Encoding` (gzip / deflate / br / zstd, level 1 as mockttp uses);
  `content-length` updated in place or appended (not when chunked); a new URL
  host updates `Host`; flows show the request as received and the response as
  sent.
- **Match & Replace** (`js.rs`): the Node semantics, quirks included —
  `fancy-regex` for JS-style patterns (lookaround, backreferences), V8's `$`
  substitutions (`$1 $& $$ $\` $' $<name>`), literal split/join, header rules on
  the `"name: value"` text form, `String()` of non-string inputs, invalid
  patterns ignored.
- **Scope**: substring or `*` pattern (only `.` escaped, like Node), host with
  or without port; out-of-scope traffic is never held.
- **WebSocket history** (`wsframe.rs`): a passive streaming reader per
  direction — unmasking, fragments, control frames, permessage-deflate with
  the negotiated context takeover — reporting each message (text, size,
  64 KB cap) and the close code (1005 / 1006 when absent), without touching
  the forwarded bytes.
- **Responses are buffered only when held or rewritten**; otherwise they
  still stream.
- **Routes ported (15/38):** adds `/intercept`, `/intercept/config`,
  `/intercept/resolve`, `/rules` (GET/POST), `/scope` (GET/POST). Events:
  `intercept`, `intercept-closed`, `intercept-config`, `scope`, `ws-message`.
- **Parity harness: 73/73** (61 identical). Adds 13 Match & Replace cases,
  scope in / out, 6 intercept cases (forward, edit, drop, response edit,
  response drop, config-off release), the API quirks, compressed WebSockets
  through the real `ws` library (context takeover, binary, fragments,
  100 KB truncation, close 4001), and the live event stream of a whole
  intercept cycle — identical in content and order (`intercept` before
  `flow`, as mockttp's asynchronous announce made it).
- Checked in the real UI: switched Intercept on, edited the held request in the
  editor, Forward — the added header reached the origin.

**Further differences from Node:**

| | Node (mockttp) | Rust | Why |
|---|---|---|---|
| Rules on bodies over 512 KB | only the first 512 KB is searched; a match there cuts the body to 512 KB | the whole body | fix (data loss) |
| Re-compressed body bytes | Node zlib, level 1 | miniz, level 1 | different DEFLATE encoders pick different matches; the harness checks the *decompressed* content is identical |
| Header names a user types in an edit | sent with the typed case | sent lowercase | HTTP header names are case-insensitive |

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
| Proxy edge cases differ from mockttp (streaming, TLS quirks, HTTP/2, WS passthrough) | parity harness per case; fix before moving on (Phase 2: 45/45) |
| Upstream chaining | CONNECT connector; verified against a stand-in proxy — still to try with real Burp in Phase 4's device pass |
| Frida client in Rust | spike two options in Phase 4 before committing |
| Toolchain: machine has `windows-gnu` + 32-bit MinGW only | install MSVC Build Tools in Phase 1 (one-time) |
| Future server-side plugins (backend JS) | embed a small JS engine (QuickJS via `rquickjs`) so plugins stay JavaScript |

## Toolchain

Windows builds use the **MSVC** toolchain, pinned in `rust-toolchain.toml`.
Requirements: VS 2022 Build Tools with the "Desktop development with C++"
workload (MSVC + Windows SDK) and the WebView2 runtime (built into Windows 11).

The GNU toolchain doesn't work here: current `windows-sys` / `getrandom` use
`raw-dylib`, which on GNU needs a 64-bit `dlltool` and assembler, and a 32-bit
MinGW on `PATH` breaks it further.

## Running

```bash
cargo run -p hizn-app               # desktop app (native window)
cargo run -p hizn-server            # headless → http://127.0.0.1:4000
DROIDMITM_PORT=4321 cargo run -p hizn-server
```

Both find `ui/` automatically when run from the repo; set `HIZN_UI_DIR` to
override.
