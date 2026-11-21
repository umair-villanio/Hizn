//! The one-click flow: given a connected device, run the whole interception
//! setup and report each step. Mirrors the Node `Orchestrator`.
//!
//! The proxy itself lives in another crate, so the few things this needs from
//! it (start, CA PEM, port) come through the [`ProxyControl`] trait, which the
//! server implements.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use serde::Serialize;
use serde_json::{Value, json};

use crate::adb::AdbError;
use crate::devices::{CaInstall, DeviceInfo, Devices};

/// One line in the setup panel.
#[derive(Debug, Clone, Serialize)]
pub struct SetupStep {
    pub key: String,
    pub label: String,
    /// `pending` | `running` | `ok` | `warn` | `error`
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl SetupStep {
    fn running(key: &str, label: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
            status: "running".into(),
            detail: None,
        }
    }
    fn done(mut self, status: &str, detail: impl Into<String>) -> Self {
        self.status = status.into();
        self.detail = Some(detail.into());
        self
    }
}

/// The future [`ProxyControl::start`] returns: the proxy's port and a status
/// detail, or an error message.
pub type ProxyStartFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(u16, String), String>> + Send + 'a>>;

/// What the orchestrator needs from the proxy engine.
pub trait ProxyControl: Send + Sync {
    /// Start the proxy on its configured port (idempotent). Returns that port
    /// and a one-line status detail for the step.
    fn start(&self) -> ProxyStartFuture<'_>;
    /// The CA certificate PEM.
    fn ca_pem(&self) -> Result<String, String>;
    /// The proxy's listen port.
    fn port(&self) -> u16;
}

pub struct SetupOptions {
    pub serial: String,
    pub frida_target: Option<String>,
    pub host_ip: Option<String>,
    pub emulator: bool,
}

/// The `POST /api/connect` result JSON.
#[derive(Serialize)]
pub struct SetupResult {
    pub steps: Vec<SetupStep>,
    pub device: DeviceInfo,
    #[serde(rename = "hostIp")]
    pub host_ip: String,
    #[serde(rename = "caInstall")]
    pub ca_install: CaInstall,
    #[serde(rename = "proxyPort")]
    pub proxy_port: u16,
}

/// Emitted for every step (the server broadcasts it as `setup-step`).
pub type StepSink = Box<dyn Fn(&SetupStep) + Send + Sync>;

pub struct Orchestrator {
    devices: Devices,
}

impl Orchestrator {
    pub fn new(devices: Devices) -> Self {
        Self { devices }
    }

    pub fn devices(&self) -> &Devices {
        &self.devices
    }

    /// The LAN IP most likely reachable from the device, Node's preference order.
    pub fn detect_host_ip(&self) -> String {
        let addrs: Vec<String> = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .filter(|i| !i.is_loopback())
            .filter_map(|i| match i.addr.ip() {
                IpAddr::V4(v4) => Some(v4.to_string()),
                IpAddr::V6(_) => None,
            })
            .collect();
        let pick = |pred: &dyn Fn(&str) -> bool| addrs.iter().find(|ip| pred(ip)).cloned();
        pick(&|ip| ip.starts_with("192.168."))
            .or_else(|| pick(&|ip| ip.starts_with("10.")))
            .or_else(|| pick(&is_172_private))
            .or_else(|| addrs.first().cloned())
            .unwrap_or_else(|| "127.0.0.1".into())
    }

    /// Run the full one-click setup. `frida` runs the Frida step when a target
    /// is given (returns the step's status/detail and whether CA became
    /// Frida-provided); when `None`, the Frida step is skipped.
    pub async fn run_one_click(
        &self,
        opts: SetupOptions,
        proxy: &dyn ProxyControl,
        emit: &StepSink,
        frida: Option<&FridaRunner<'_>>,
    ) -> Result<SetupResult, String> {
        let mut steps = Vec::new();
        macro_rules! push {
            ($step:expr) => {{
                let s = $step;
                emit(&s);
                steps.push(s.clone());
                s
            }};
        }

        // 1. Device check.
        let dev_step = SetupStep::running("device", "Detect device");
        emit(&dev_step);
        let devices = self
            .devices
            .list()
            .await
            .map_err(|e: AdbError| e.to_string())?;
        let Some(device) = devices.into_iter().find(|d| d.serial == opts.serial) else {
            let s = dev_step.done("error", "Device not found");
            emit(&s);
            steps.push(s);
            return Err(format!("Device not found: {}", opts.serial));
        };
        let detail = format!(
            "{} · Android {} · {}",
            device.model.as_deref().unwrap_or(&device.serial),
            device.android_version.as_deref().unwrap_or("?"),
            if device.rooted { "rooted" } else { "non-root" }
        );
        steps.push({
            let s = dev_step.done("ok", detail);
            emit(&s);
            s
        });

        // 2. Proxy up.
        let proxy_step = SetupStep::running("proxy", "Start proxy engine");
        emit(&proxy_step);
        let (port, proxy_detail) = proxy.start().await?;
        steps.push({
            let s = proxy_step.done("ok", proxy_detail);
            emit(&s);
            s
        });

        // 3. Host IP.
        let host_ip = opts
            .host_ip
            .clone()
            .unwrap_or_else(|| self.detect_host_ip());
        push!(SetupStep::running("ip", "Resolve host address").done("ok", host_ip.clone()));

        let ca_pem = proxy.ca_pem()?;
        let mut ca_install = CaInstall::UserManual;

        // 4. CA install.
        let ca_step = SetupStep::running("ca", "Install CA certificate");
        emit(&ca_step);
        let ca_done = if device.rooted {
            match android_cert_hash(&ca_pem).await {
                Some(hash) => {
                    ca_install = self
                        .devices
                        .install_ca(&opts.serial, &ca_pem, &hash, true)
                        .await
                        .map_err(|e| e.to_string())?;
                    ca_step.done("ok", "Installed into system trust store")
                }
                None => {
                    self.devices
                        .install_ca(&opts.serial, &ca_pem, "0", false)
                        .await
                        .map_err(|e| e.to_string())?;
                    ca_step.done(
                        "warn",
                        "openssl missing — PEM staged at /sdcard/Download/hizn-ca.crt",
                    )
                }
            }
        } else {
            self.devices
                .install_ca(&opts.serial, &ca_pem, "0", false)
                .await
                .map_err(|e| e.to_string())?;
            ca_step.done(
                "warn",
                format!(
                    "Non-rooted (Android {}): cert staged at /sdcard/Download/hizn-ca.crt. Install via Settings → Security → Encryption & credentials → Install a certificate → CA. NOTE: apps ignore user CAs, so most HTTPS still won't decrypt — use an emulator, root, or Frida-gadget per app.",
                    device.android_version.as_deref().unwrap_or("7+")
                ),
            )
        };
        steps.push({
            emit(&ca_done);
            ca_done
        });

        // 5. Route device traffic. Default to 127.0.0.1 over an adb reverse
        // tunnel; only use the LAN IP when the caller supplied one.
        let route_step = SetupStep::running("route", "Route device traffic");
        emit(&route_step);
        let use_reverse = opts.host_ip.is_none();
        let proxy_host = if use_reverse {
            "127.0.0.1"
        } else {
            host_ip.as_str()
        };
        let route_done = match self
            .route(&opts.serial, proxy_host, port, use_reverse, &host_ip)
            .await
        {
            Ok(detail) => route_step.done("ok", detail),
            Err(e) => route_step.done("warn", format!("Could not set proxy automatically: {e}")),
        };
        steps.push({
            emit(&route_done);
            route_done
        });

        // 6. Frida (optional) — delegated to the server.
        if let (Some(target), Some(frida)) = (&opts.frida_target, frida) {
            let outcome = frida(FridaRequest {
                device: &device,
                serial: &opts.serial,
                target,
                ca_pem: &ca_pem,
                host_ip: &host_ip,
                port,
            })
            .await;
            for s in &outcome.steps {
                emit(s);
                steps.push(s.clone());
            }
            if outcome.ca_via_frida {
                ca_install = CaInstall::Frida;
            }
        }

        Ok(SetupResult {
            steps,
            device,
            host_ip,
            ca_install,
            proxy_port: port,
        })
    }

    async fn route(
        &self,
        serial: &str,
        proxy_host: &str,
        port: u16,
        use_reverse: bool,
        host_ip: &str,
    ) -> Result<String, AdbError> {
        self.devices.adb().reverse(serial, port, port).await?;
        self.devices
            .set_global_proxy(serial, proxy_host, port)
            .await?;
        Ok(if use_reverse {
            format!("global http_proxy = 127.0.0.1:{port} (adb reverse tunnel)")
        } else {
            format!("global http_proxy = {host_ip}:{port} (+adb reverse)")
        })
    }

    /// Undo device-side changes (proxy + reverse); the CA is left in place.
    pub async fn disconnect(&self, serial: &str, port: u16) {
        let _ = self.devices.clear_global_proxy(serial).await;
        let _ = self.devices.adb().remove_reverse(serial, port).await;
    }
}

/// Inputs the server's Frida step receives.
pub struct FridaRequest<'a> {
    pub device: &'a DeviceInfo,
    pub serial: &'a str,
    pub target: &'a str,
    pub ca_pem: &'a str,
    pub host_ip: &'a str,
    pub port: u16,
}

/// What the Frida step produced.
pub struct FridaOutcome {
    pub steps: Vec<SetupStep>,
    pub ca_via_frida: bool,
}

/// The future a [`FridaRunner`] returns.
pub type FridaFuture<'a> = Pin<Box<dyn Future<Output = FridaOutcome> + Send + 'a>>;

/// The server's Frida step: given a request, returns its steps.
pub type FridaRunner<'a> = dyn for<'r> Fn(FridaRequest<'r>) -> FridaFuture<'r> + Send + Sync + 'a;

fn is_172_private(ip: &str) -> bool {
    ip.strip_prefix("172.")
        .and_then(|rest| rest.split('.').next())
        .and_then(|o| o.parse::<u8>().ok())
        .is_some_and(|second| (16..=31).contains(&second))
}

/// Android's `subject_hash_old` for the CA, via the host `openssl`. `None` when
/// openssl isn't on PATH (so the caller falls back to manual install), exactly
/// as the Node orchestrator did.
async fn android_cert_hash(ca_pem: &str) -> Option<String> {
    let dir = std::env::temp_dir();
    let tmp = dir.join(format!("hizn-ca-{}.pem", crate::now_ms()));
    tokio::fs::write(&tmp, ca_pem).await.ok()?;
    let out = tokio::process::Command::new("openssl")
        .args([
            "x509",
            "-inform",
            "PEM",
            "-subject_hash_old",
            "-noout",
            "-in",
        ])
        .arg(&tmp)
        .output()
        .await;
    let _ = tokio::fs::remove_file(&tmp).await;
    let out = out.ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// A step payload for the `setup-step` broadcast.
pub fn step_event(step: &SetupStep) -> Value {
    json!({ "type": "setup-step", "step": step })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ip_preference_order() {
        assert!(is_172_private("172.16.0.1"));
        assert!(is_172_private("172.31.255.1"));
        assert!(!is_172_private("172.15.0.1"));
        assert!(!is_172_private("172.32.0.1"));
    }

    #[test]
    fn step_serializes_without_missing_detail() {
        let s = SetupStep::running("device", "Detect device");
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["status"], "running");
        assert!(v.get("detail").is_none());
    }
}
