//! Device description and device-side setup: the Rust equivalent of the Node
//! `AdbService` methods above the raw ADB protocol.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use crate::adb::{Adb, AdbError};

/// Enriched device info, matching the Node `DeviceInfo` JSON shape.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub serial: String,
    /// `device` | `emulator` | `offline` | …
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub android_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware: Option<String>,
    pub rooted: bool,
    pub frida_running: bool,
    pub is_emulator: bool,
    pub is_genymotion: bool,
}

impl DeviceInfo {
    fn base(serial: String, kind: String) -> Self {
        Self {
            serial,
            kind,
            model: None,
            android_version: None,
            sdk: None,
            abi: None,
            manufacturer: None,
            hardware: None,
            rooted: false,
            frida_running: false,
            is_emulator: false,
            is_genymotion: false,
        }
    }
}

pub struct Devices {
    adb: Adb,
}

impl Devices {
    pub fn new(adb: Adb) -> Self {
        Self { adb }
    }

    pub fn adb(&self) -> &Adb {
        &self.adb
    }

    /// Every attached device, enriched (`GET /api/devices`).
    pub async fn list(&self) -> Result<Vec<DeviceInfo>, AdbError> {
        let listed = self.adb.list_devices().await?;
        let mut out = Vec::with_capacity(listed.len());
        for d in listed {
            out.push(self.describe(&d.serial, &d.state).await);
        }
        Ok(out)
    }

    /// The Node `describe`: probe props and fingerprint emulators. Any probe
    /// error leaves the partially-filled record, as in Node.
    pub async fn describe(&self, serial: &str, kind: &str) -> DeviceInfo {
        let mut info = DeviceInfo::base(serial.to_owned(), kind.to_owned());
        if kind != "device" && kind != "emulator" {
            return info;
        }
        let prop =
            |p: &'static str| async move { self.adb.getprop(serial, p).await.ok().flatten() };

        info.model = prop("ro.product.model").await;
        info.android_version = prop("ro.build.version.release").await;
        info.sdk = prop("ro.build.version.sdk")
            .await
            .and_then(|s| s.trim().parse().ok());
        info.abi = prop("ro.product.cpu.abi").await;
        info.manufacturer = prop("ro.product.manufacturer").await;
        info.hardware = prop("ro.hardware").await;
        info.rooted = self.is_rooted(serial).await;
        info.frida_running = self.is_frida_running(serial).await;

        let hw = info.hardware.as_deref().unwrap_or("").to_lowercase();
        let mfr = info.manufacturer.as_deref().unwrap_or("").to_lowercase();
        let prod = prop("ro.product.name")
            .await
            .unwrap_or_default()
            .to_lowercase();
        info.is_genymotion = hw.contains("vbox")
            || mfr.contains("geny")
            || prod.contains("vbox")
            || prod.contains("genymotion");
        info.is_emulator = info.is_genymotion
            || kind == "emulator"
            || hw.contains("goldfish")
            || hw.contains("ranchu")
            || is_emulator_serial(serial);
        info
    }

    /// First Genymotion VM, else any emulator.
    pub async fn find_genymotion(&self) -> Result<Option<DeviceInfo>, AdbError> {
        let devices = self.list().await?;
        Ok(devices
            .iter()
            .find(|d| d.is_genymotion)
            .or_else(|| devices.iter().find(|d| d.is_emulator))
            .cloned())
    }

    pub async fn is_rooted(&self, serial: &str) -> bool {
        match self.adb.shell(serial, "su -c id 2>/dev/null || id").await {
            Ok(out) => out.contains("uid=0(root)"),
            Err(_) => false,
        }
    }

    pub async fn is_frida_running(&self, serial: &str) -> bool {
        match self
            .adb
            .shell(serial, "ps -A 2>/dev/null | grep -i frida")
            .await
        {
            Ok(out) => out.to_lowercase().contains("frida"),
            Err(_) => false,
        }
    }

    pub async fn set_global_proxy(
        &self,
        serial: &str,
        host: &str,
        port: u16,
    ) -> Result<(), AdbError> {
        self.adb
            .shell(
                serial,
                &format!("settings put global http_proxy {host}:{port}"),
            )
            .await
            .map(|_| ())
    }

    pub async fn clear_global_proxy(&self, serial: &str) -> Result<(), AdbError> {
        self.adb
            .shell(serial, "settings put global http_proxy :0")
            .await?;
        self.adb
            .shell(serial, "settings delete global http_proxy")
            .await?;
        Ok(())
    }

    /// Installed package names (`pm list packages`), third-party only by
    /// default, sorted.
    pub async fn list_installed_packages(
        &self,
        serial: &str,
        third_party_only: bool,
    ) -> Result<Vec<String>, AdbError> {
        let cmd = if third_party_only {
            "pm list packages -3"
        } else {
            "pm list packages"
        };
        let out = self.adb.shell(serial, cmd).await?;
        let mut pkgs: Vec<String> = out
            .lines()
            .map(|l| l.trim().trim_start_matches("package:").to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        pkgs.sort();
        Ok(pkgs)
    }

    /// On-device APK path(s) for a package (`pm path`), base + any splits.
    pub async fn apk_paths(&self, serial: &str, pkg: &str) -> Result<Vec<String>, AdbError> {
        if !pkg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        {
            return Err(AdbError::Failed("Invalid package name".into()));
        }
        let out = self.adb.shell(serial, &format!("pm path {pkg}")).await?;
        Ok(out
            .lines()
            .map(|l| l.trim().trim_start_matches("package:").to_owned())
            .filter(|l| !l.is_empty())
            .collect())
    }

    /// Install the CA: into the system trust store when rooted (plus the
    /// Android 14+ APEX path), otherwise staged on `/sdcard` for manual install.
    /// Returns which strategy was used.
    pub async fn install_ca(
        &self,
        serial: &str,
        ca_pem: &str,
        android_hash: &str,
        rooted: bool,
    ) -> Result<CaInstall, AdbError> {
        let tmp = "/data/local/tmp/hizn-ca.pem";
        self.adb
            .push_bytes(serial, ca_pem.as_bytes(), tmp, 0o644)
            .await?;

        if rooted {
            let target = format!("/system/etc/security/cacerts/{android_hash}.0");
            let script = [
                "su -c \"mount -o rw,remount /system 2>/dev/null || mount -o rw,remount /\"".to_owned(),
                format!("su -c \"cp {tmp} {target}\""),
                format!("su -c \"chmod 644 {target}\""),
                format!("su -c \"chown root:root {target}\""),
                format!("su -c \"cp {tmp} /apex/com.android.conscrypt/cacerts/{android_hash}.0 2>/dev/null || true\""),
            ]
            .join(" && ");
            self.adb.shell(serial, &script).await?;
            return Ok(CaInstall::System);
        }

        self.adb
            .push_bytes(
                serial,
                ca_pem.as_bytes(),
                "/sdcard/Download/hizn-ca.crt",
                0o644,
            )
            .await?;
        Ok(CaInstall::UserManual)
    }
}

/// Which CA-install strategy ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaInstall {
    System,
    UserManual,
    Frida,
}

/// A TCP serial (`1.2.3.4:5555`) or `emulator-NNNN`.
fn is_emulator_serial(serial: &str) -> bool {
    if let Some(n) = serial.strip_prefix("emulator-") {
        return !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit());
    }
    // host:port where host is a dotted IPv4.
    if let Some((host, port)) = serial.rsplit_once(':') {
        let ipv4 = host.split('.').count() == 4
            && host
                .split('.')
                .all(|o| !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit()));
        let port_ok = !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
        return ipv4 && port_ok;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn emulator_serials_match_node() {
        assert!(is_emulator_serial("emulator-5554"));
        assert!(is_emulator_serial("192.168.56.101:5555"));
        assert!(!is_emulator_serial("emulator-"));
        assert!(!is_emulator_serial("ABCD1234"));
        assert!(!is_emulator_serial("pixel.local:5555"));
    }

    #[test]
    fn device_info_serializes_in_node_shape() {
        let mut d = DeviceInfo::base("S1".into(), "device".into());
        d.model = Some("Pixel".into());
        d.sdk = Some(34);
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["type"], json!("device"));
        assert_eq!(v["model"], json!("Pixel"));
        assert_eq!(v["sdk"], json!(34));
        assert_eq!(v["fridaRunning"], json!(false));
        assert_eq!(v["isGenymotion"], json!(false));
        // Absent optionals are omitted, as in Node (undefined → not serialized).
        assert!(v.get("abi").is_none());
    }
}
