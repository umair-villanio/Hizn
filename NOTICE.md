# Attribution

hizn is licensed under AGPL-3.0 (see LICENSE).

This project's design is derived from study of HTTP Toolkit
(https://github.com/httptoolkit), copyright Tim Perry / httptoolkit,
itself licensed AGPL-3.0. Components adapted with license notices preserved:

- httptoolkit/httptoolkit-server — Android ADB interception and Frida
  interception pipelines, studied for the one-click orchestration.
- httptoolkit/frida-interception-and-unpinning — the Android unpinning/proxy
  Frida scripts shipped under `scripts/frida/` (AGPL-3.0).
- httptoolkit/httptoolkit-android — VpnService companion-app approach, studied
  for the device-side setup design.

The backend is native Rust. The MITM proxy engine is built on hyper, rustls and
rcgen; TLS on rustls/webpki; the desktop shell on Tauri; WebSockets on
tokio-tungstenite; XZ decompression on lzma-rs. Each is used under its own
permissive (MIT/Apache-2.0) license; see `Cargo.toml` / `Cargo.lock` for the
full dependency set.
