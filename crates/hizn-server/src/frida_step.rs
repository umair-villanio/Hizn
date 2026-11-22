//! The server-side Frida step for the one-click flow: provision frida-server if
//! needed, build the CA + unpinning payload, and inject it. Mirrors the Frida
//! part of the Node `Orchestrator.runOneClick` and `FridaService`.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use hizn_devices::{FridaRequest, FridaSessions, SetupStep, provision_server};

/// The scripts, in the load order the upstream hooks expect.
const SCRIPT_FILES: &[&str] = &[
    "native-connect-hook.js",
    "native-tls-hook.js",
    "android/android-proxy-override.js",
    "android/android-system-certificate-injection.js",
    "android/android-certificate-unpinning.js",
    "android/android-certificate-unpinning-fallback.js",
];

/// Build the config prelude + all hook scripts into one injectable payload.
pub fn build_payload(
    ca_pem: &str,
    proxy_host: &str,
    proxy_port: u16,
    scripts_dir: &std::path::Path,
) -> String {
    let mut parts = vec![format!(
        "\n/* hizn runtime config — generated */\nconst CERT_PEM = `{}`;\nconst PROXY_HOST = {:?};\nconst PROXY_PORT = {proxy_port};\nconst DEBUG_MODE = false;\nconst IGNORED_NON_HTTP_PORTS = [];\nconst BLOCK_HTTP3 = true;\nconst PROXY_SUPPORTS_SOCKS5 = false;\n",
        ca_pem.trim(),
        proxy_host
    )];
    for file in SCRIPT_FILES {
        if let Ok(src) = std::fs::read_to_string(scripts_dir.join(file)) {
            parts.push(src);
        }
        // A missing script is skipped, so a partial install still runs.
    }
    parts.join("\n\n")
}

fn step(key: &str, label: impl Into<String>, status: &str, detail: impl Into<String>) -> SetupStep {
    SetupStep {
        key: key.into(),
        label: label.into(),
        status: status.into(),
        detail: Some(detail.into()),
    }
}

/// Run the Frida step: (optionally) provision frida-server, then inject the
/// payload into `req.target`. Returns the setup steps and whether the CA is now
/// delivered via Frida.
pub async fn run_frida_step(
    req: FridaRequest<'_>,
    adb: &hizn_devices::Adb,
    sessions: &FridaSessions,
    scripts_dir: &std::path::Path,
) -> (Vec<SetupStep>, bool) {
    let mut steps = Vec::new();
    let mut frida_ready = req.device.frida_running;

    // Provision frida-server if it's missing but we have root + an ABI.
    if !frida_ready
        && req.device.rooted
        && let Some(abi) = req.device.abi.as_deref()
    {
        match provision_server(adb, req.serial, abi, "latest").await {
            Ok(p) => {
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                // A re-check over ADB confirms it's actually listening.
                frida_ready = adb
                    .shell(req.serial, "ps -A 2>/dev/null | grep -i frida-server")
                    .await
                    .map(|o| o.to_lowercase().contains("frida-server"))
                    .unwrap_or(false);
                steps.push(step(
                    "frida-provision",
                    "Provision frida-server",
                    if frida_ready { "ok" } else { "warn" },
                    if frida_ready {
                        format!("frida-server {} ({}) running", p.version, p.arch)
                    } else {
                        format!(
                            "Pushed {} ({}) but it isn't listening yet",
                            p.version, p.arch
                        )
                    },
                ));
            }
            Err(e) => steps.push(step(
                "frida-provision",
                "Provision frida-server",
                "error",
                format!("Download/start failed: {e}"),
            )),
        }
    }

    let label = format!("Frida inject → {}", req.target);
    if !frida_ready {
        let detail = if req.device.rooted {
            "frida-server not listening — try again"
        } else {
            "Non-rooted: start frida-server/gadget manually, then retry"
        };
        steps.push(step("frida", label, "warn", detail));
        return (steps, false);
    }

    let payload = build_payload(req.ca_pem, req.host_ip, req.port, scripts_dir);
    let opts = hizn_devices::frida::InjectOptions {
        serial: req.serial.to_owned(),
        payload,
        target: req.target.to_owned(),
        spawn: true,
        frida_port: hizn_devices::frida::FRIDA_DEFAULT_PORT,
    };
    match hizn_devices::frida::inject(adb, sessions, opts).await {
        Ok(pid) => {
            steps.push(step(
                "frida",
                label,
                "ok",
                format!("Injected (pid {pid}) — CA + unpinning active"),
            ));
            (steps, true)
        }
        Err(e) => {
            steps.push(step("frida", label, "error", e.to_string()));
            (steps, false)
        }
    }
}
