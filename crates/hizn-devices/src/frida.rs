//! Frida support: provision `frida-server` on a device (download the right-ABI
//! build from GitHub, decompress, push, start as root). Mirrors the Node
//! `FridaService.provisionServer`.
//!
//! The injection half (CA + unpinning via the Frida control protocol) is the
//! Frida follow-up; provisioning is the piece that gets a working server onto
//! a rooted device.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use serde::Deserialize;

use crate::adb::{Adb, AdbError};

/// On-device path where frida-server is staged and run.
const DEVICE_FRIDA_PATH: &str = "/data/local/tmp/frida-server";

/// Map an Android ABI (`ro.product.cpu.abi`) to a Frida download arch.
pub fn abi_to_frida_arch(abi: &str) -> &'static str {
    if abi.contains("arm64") {
        "arm64"
    } else if abi.contains("armeabi") || abi == "armeabi-v7a" {
        "arm"
    } else if abi == "x86_64" {
        "x86_64"
    } else {
        "x86"
    }
}

#[derive(Debug)]
pub enum FridaError {
    Adb(AdbError),
    Download(String),
    Decompress(String),
}

impl std::fmt::Display for FridaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Adb(e) => write!(f, "{e}"),
            Self::Download(m) => write!(f, "Download failed: {m}"),
            Self::Decompress(m) => write!(f, "Decompress failed: {m}"),
        }
    }
}

impl std::error::Error for FridaError {}

impl From<AdbError> for FridaError {
    fn from(e: AdbError) -> Self {
        Self::Adb(e)
    }
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// What a provision run produced.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Provisioned {
    pub version: String,
    pub arch: String,
}

/// Download, push and start frida-server for `abi`'s architecture (requires
/// root to actually run). `version` is a release tag or "latest".
pub async fn provision_server(
    adb: &Adb,
    serial: &str,
    abi: &str,
    version: &str,
) -> Result<Provisioned, FridaError> {
    let arch = abi_to_frida_arch(abi);
    let client = reqwest::Client::builder()
        .user_agent("hizn")
        .build()
        .map_err(|e| FridaError::Download(e.to_string()))?;

    // 1. Resolve the release + find the android-<arch> asset.
    let api = if version.is_empty() || version == "latest" {
        "https://api.github.com/repos/frida/frida/releases/latest".to_owned()
    } else {
        format!("https://api.github.com/repos/frida/frida/releases/tags/{version}")
    };
    let release: Release = client
        .get(&api)
        .send()
        .await
        .map_err(|e| FridaError::Download(e.to_string()))?
        .error_for_status()
        .map_err(|e| FridaError::Download(e.to_string()))?
        .json()
        .await
        .map_err(|e| FridaError::Download(e.to_string()))?;

    let suffix = format!("-android-{arch}.xz");
    let asset = release
        .assets
        .iter()
        .find(|a| a.name.starts_with("frida-server-") && a.name.ends_with(&suffix))
        .ok_or_else(|| {
            FridaError::Download(format!(
                "no frida-server for android {arch} in {}",
                release.tag_name
            ))
        })?;

    // 2. Download the .xz and decompress it to the server binary.
    let xz = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .map_err(|e| FridaError::Download(e.to_string()))?
        .error_for_status()
        .map_err(|e| FridaError::Download(e.to_string()))?
        .bytes()
        .await
        .map_err(|e| FridaError::Download(e.to_string()))?;

    let binary = tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        lzma_rs::xz_decompress(&mut std::io::Cursor::new(&xz), &mut out).map(|_| out)
    })
    .await
    .map_err(|e| FridaError::Decompress(e.to_string()))?
    .map_err(|e| FridaError::Decompress(e.to_string()))?;

    // 3. Push, make executable, start detached as root (replacing any stale one).
    adb.push_bytes(serial, &binary, DEVICE_FRIDA_PATH, 0o755)
        .await?;
    adb.shell(serial, &format!("chmod 755 {DEVICE_FRIDA_PATH}"))
        .await?;
    adb.shell(serial, "su -c \"killall frida-server 2>/dev/null || true\"")
        .await?;
    adb.shell(
        serial,
        &format!("su -c \"nohup {DEVICE_FRIDA_PATH} >/dev/null 2>&1 &\""),
    )
    .await?;

    Ok(Provisioned {
        version: release.tag_name,
        arch: arch.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_mapping_matches_node() {
        assert_eq!(abi_to_frida_arch("arm64-v8a"), "arm64");
        assert_eq!(abi_to_frida_arch("armeabi-v7a"), "arm");
        assert_eq!(abi_to_frida_arch("x86_64"), "x86_64");
        assert_eq!(abi_to_frida_arch("x86"), "x86");
    }
}
