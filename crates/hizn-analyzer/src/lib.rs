//! Hizn static APK analyzer: a light, MobSF-style SAST in pure Rust — ZIP
//! reader, binary AndroidManifest + resources.arsc decoders, signing
//! certificate parse + analysis, and a hardcoded-secret / endpoint scan.
//! Produces the same structured report the Node `AnalyzerService` did.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

mod axml;
mod cert;
pub mod report;
mod secrets;
mod zip;

use std::sync::OnceLock;

use regex::Regex;
use sha2::{Digest, Sha256};

use report::{
    AppInfo, Component, CustomPermission, FileInfo, Finding, Permission, Report, Severity,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn dangerous() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(READ_SMS|SEND_SMS|RECEIVE_SMS|READ_CONTACTS|WRITE_CONTACTS|RECORD_AUDIO|CAMERA|ACCESS_FINE_LOCATION|ACCESS_BACKGROUND_LOCATION|READ_CALL_LOG|WRITE_CALL_LOG|READ_PHONE_STATE|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES|READ_CALENDAR|BODY_SENSORS|GET_ACCOUNTS|CALL_PHONE|PROCESS_OUTGOING_CALLS|QUERY_ALL_PACKAGES)").expect("dangerous perms re"))
}
fn signature_like() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(MANAGE_EXTERNAL_STORAGE|BIND_ACCESSIBILITY_SERVICE|BIND_DEVICE_ADMIN|WRITE_SECURE_SETTINGS|INSTALL_PACKAGES|MOUNT_UNMOUNT_FILESYSTEMS)").expect("signature perms re"))
}

fn perm_severity(name: &str) -> (Severity, Option<String>) {
    if signature_like().is_match(name) {
        (Severity::High, Some("Powerful/abusable permission".into()))
    } else if dangerous().is_match(name) {
        (
            Severity::Medium,
            Some("Dangerous (runtime) permission".into()),
        )
    } else {
        (Severity::Info, None)
    }
}

/// Analyze an APK. Never panics; failures become `report.errors` entries, as in
/// Node. `file_name` is the display name shown in `file.name`.
pub fn analyze(apk: &[u8], file_name: Option<&str>) -> Report {
    let mut report = Report::new(FileInfo {
        name: file_name.map(str::to_owned),
        size_bytes: apk.len() as u64,
        sha256: hex(&Sha256::digest(apk)),
    });

    let zip = match zip::Zip::new(apk) {
        Ok(z) => z,
        Err(e) => {
            report.errors = Some(vec![e]);
            return report;
        }
    };

    let mut meta_data: Vec<(String, String)> = Vec::new();

    // ---- Manifest ----
    match zip.read("AndroidManifest.xml") {
        None => report.push_error("Manifest: AndroidManifest.xml not found".into()),
        Some(m_buf) => match axml::parse_axml(&m_buf) {
            Err(e) => report.push_error(format!("Manifest: {e}")),
            Ok(root) => analyze_manifest(&root, &mut report, &mut meta_data),
        },
    }

    // ---- Certificate (v1 META-INF, else v2/v3 signing block) ----
    analyze_certificate(&zip, apk, &mut report);

    // ---- Secrets / URLs ----
    secrets::scan_secrets(&zip, &mut report, &meta_data);

    report.tally();
    report
}

fn analyze_manifest(root: &axml::Node, report: &mut Report, meta_data: &mut Vec<(String, String)>) {
    let manifest = root.find_first("manifest");
    let application = root.find_first("application");

    let app_attr = |name: &str| manifest.and_then(|m| m.attr(name)).map(str::to_owned);
    report.app = AppInfo {
        package: app_attr("package"),
        version_name: app_attr("versionName"),
        version_code: app_attr("versionCode"),
        compile_sdk: app_attr("compileSdkVersion"),
        min_sdk: None,
        target_sdk: None,
    };
    let uses_sdk = root.find_first("uses-sdk");
    report.app.min_sdk = uses_sdk
        .and_then(|u| u.attr("minSdkVersion"))
        .map(str::to_owned)
        .or_else(|| app_attr("minSdkVersion"));
    report.app.target_sdk = uses_sdk
        .and_then(|u| u.attr("targetSdkVersion"))
        .map(str::to_owned)
        .or_else(|| app_attr("targetSdkVersion"));

    // Permissions, sorted by severity (stable).
    for p in root.find_all_vec("uses-permission") {
        if let Some(name) = p.attr("name") {
            let (severity, info) = perm_severity(name);
            report.permissions.push(Permission {
                name: name.to_owned(),
                severity,
                info,
            });
        }
    }
    report
        .permissions
        .sort_by_key(|p| std::cmp::Reverse(p.severity.rank()));
    for p in root.find_all_vec("permission") {
        if let Some(name) = p.attr("name") {
            report.custom_permissions.push(CustomPermission {
                name: name.to_owned(),
                protection_level: p.attr("protectionLevel").map(str::to_owned),
            });
        }
    }

    // Exported components.
    for kind in [
        "activity",
        "activity-alias",
        "service",
        "receiver",
        "provider",
    ] {
        for c in root.find_all_vec(kind) {
            let Some(name) = c.attr("name") else { continue };
            let has_intent_filter = c.children.iter().any(|x| x.name == "intent-filter");
            let exported = match c.attr("exported") {
                Some(v) => v == "true",
                None => has_intent_filter,
            };
            report.components.push(Component {
                kind: kind.to_owned(),
                name: name.to_owned(),
                exported,
                permission: c.attr("permission").map(str::to_owned),
                has_intent_filter,
            });
        }
    }

    // <meta-data> entries.
    for m in root.find_all_vec("meta-data") {
        let name = m.attr("name").unwrap_or("").to_owned();
        let value = m.attr("value").unwrap_or("").to_owned();
        if !name.is_empty() || !value.is_empty() {
            meta_data.push((name, value));
        }
    }

    // Manifest flags + findings.
    use serde_json::Value;
    let app_bool = |name: &str| application.and_then(|a| a.attr(name)).map(str::to_owned);
    let dbg = app_bool("debuggable").as_deref() == Some("true");
    let backup = app_bool("allowBackup");
    let cleartext = app_bool("usesCleartextTraffic");
    let nsc = app_bool("networkSecurityConfig");
    report
        .manifest_flags
        .insert("debuggable".into(), Value::Bool(dbg));
    report.manifest_flags.insert(
        "allowBackup".into(),
        Value::String(
            backup
                .clone()
                .unwrap_or_else(|| "(default: true ≤ API 30)".into()),
        ),
    );
    report.manifest_flags.insert(
        "usesCleartextTraffic".into(),
        Value::String(cleartext.clone().unwrap_or_else(|| "(default)".into())),
    );
    report.manifest_flags.insert(
        "networkSecurityConfig".into(),
        Value::String(
            nsc.clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "(none)".into()),
        ),
    );

    if dbg {
        report.add(
            Finding::new("Manifest", "App is debuggable", Severity::High)
                .detail("android:debuggable=\"true\" ships a debuggable build — do not release."),
        );
    }
    if backup.as_deref() != Some("false") {
        report.add(
            Finding::new("Manifest", "Backups allowed", Severity::Medium).detail(
                "android:allowBackup is not false — app data can be extracted via adb backup.",
            ),
        );
    }
    if cleartext.as_deref() == Some("true") {
        report.add(
            Finding::new("Manifest", "Cleartext traffic allowed", Severity::Medium)
                .detail("usesCleartextTraffic=\"true\" permits unencrypted HTTP."),
        );
    }
    if let Some(min_sdk) = report
        .app
        .min_sdk
        .as_deref()
        .and_then(|s| s.parse::<i64>().ok())
        && min_sdk != 0
        && min_sdk < 24
    {
        report.add(
            Finding::new(
                "Manifest",
                format!("Low minSdkVersion ({min_sdk})"),
                Severity::Low,
            )
            .detail("Pre-24 ignores user-added CAs and misses platform security hardening."),
        );
    }
    // Exported-without-permission findings (cap 40).
    let risky: Vec<(String, String)> = report
        .components
        .iter()
        .filter(|c| c.exported && c.permission.is_none() && c.has_intent_filter)
        .take(40)
        .map(|c| (c.kind.clone(), c.name.clone()))
        .collect();
    for (kind, name) in risky {
        report.add(
            Finding::new(
                "Manifest",
                format!("Exported {kind} without permission"),
                Severity::Medium,
            )
            .detail(name),
        );
    }
}

fn analyze_certificate(zip: &zip::Zip, apk: &[u8], report: &mut Report) {
    static SIG: OnceLock<Regex> = OnceLock::new();
    let sig_re =
        SIG.get_or_init(|| Regex::new(r"(?i)^META-INF/.*\.(RSA|DSA|EC)$").expect("sig re"));

    let mut cert_der: Option<Vec<u8>> = None;
    let mut scheme = "";
    if let Some(name) = zip.names().find(|n| sig_re.is_match(n))
        && let Some(sig) = zip.read(name)
    {
        cert_der = cert::pkcs7_first_cert_der(&sig);
        scheme = "v1 (JAR)";
    }
    if cert_der.is_none() {
        cert_der = cert::cert_from_signing_block(apk, zip.cd_offset);
        if cert_der.is_some() {
            scheme = "v2/v3 (APK Signing Block)";
        }
    }
    match cert_der {
        Some(der) => cert::analyze_cert_der(&der, scheme, report),
        None => report
            .push_error("Certificate: could not extract a signing certificate (v1/v2/v3).".into()),
    }
}

/// Analyze and return the report as JSON (the `/analyzer/scan` response).
pub fn analyze_to_json(apk: &[u8], file_name: Option<&str>) -> serde_json::Value {
    serde_json::to_value(analyze(apk, file_name))
        .unwrap_or_else(|_| serde_json::json!({ "errors": ["serialization failed"] }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_zip_reports_error() {
        let report = analyze(b"not an apk at all, too short even", Some("x.apk"));
        assert!(
            report
                .errors
                .as_ref()
                .is_some_and(|e| e[0].contains("end-of-central-directory"))
        );
        assert_eq!(report.file.name.as_deref(), Some("x.apk"));
    }
}
