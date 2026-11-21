//! Desktop browser capture (Firefox) — the Rust port of the Node
//! `DesktopService`. A stable `~/.hizn/firefox-profile` wired to the proxy,
//! with the CA auto-trusted in that profile's own NSS store when a real NSS
//! `certutil` is available.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_json::{Value, json};

fn hizn_home() -> PathBuf {
    std::env::var_os("HIZN_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(hizn_proxy::hizn_dir)
}

pub struct Desktop {
    profile_dir: PathBuf,
    ca_path: PathBuf,
}

impl Default for Desktop {
    fn default() -> Self {
        Self::new()
    }
}

impl Desktop {
    pub fn new() -> Self {
        let profile_dir = hizn_home().join("firefox-profile");
        let ca_path = profile_dir.join("hizn-ca.pem");
        Self {
            profile_dir,
            ca_path,
        }
    }

    /// Locate the Firefox binary, or `None`.
    pub fn detect_firefox(&self) -> Option<PathBuf> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if cfg!(windows) {
            let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
            let pf86 = std::env::var("ProgramFiles(x86)")
                .unwrap_or_else(|_| r"C:\Program Files (x86)".into());
            candidates.push(Path::new(&pf).join("Mozilla Firefox").join("firefox.exe"));
            candidates.push(Path::new(&pf86).join("Mozilla Firefox").join("firefox.exe"));
            if let Ok(local) = std::env::var("LOCALAPPDATA") {
                candidates.push(
                    Path::new(&local)
                        .join("Mozilla Firefox")
                        .join("firefox.exe"),
                );
            }
        } else if cfg!(target_os = "macos") {
            candidates.push("/Applications/Firefox.app/Contents/MacOS/firefox".into());
            if let Some(home) = std::env::var_os("HOME") {
                candidates
                    .push(Path::new(&home).join("Applications/Firefox.app/Contents/MacOS/firefox"));
            }
        } else {
            for p in [
                "/usr/bin/firefox",
                "/usr/local/bin/firefox",
                "/snap/bin/firefox",
                "/usr/bin/firefox-esr",
            ] {
                candidates.push(p.into());
            }
        }
        candidates.into_iter().find(|p| p.is_file())
    }

    pub fn info(&self, proxy_port: u16) -> Value {
        json!({
            "firefoxPath": self.detect_firefox().map(|p| p.to_string_lossy().into_owned()),
            "profileDir": self.profile_dir.to_string_lossy(),
            "caPath": self.ca_path.to_string_lossy(),
            "proxyPort": proxy_port,
        })
    }

    /// `GET /desktop/info` payload.
    pub fn info_full(&self, proxy_port: u16) -> Value {
        let mut info = self.info(proxy_port);
        if let Value::Object(map) = &mut info {
            map.insert(
                "firefoxFound".into(),
                json!(self.detect_firefox().is_some()),
            );
            map.insert("caImported".into(), json!(self.ca_imported()));
            map.insert(
                "certutilFound".into(),
                json!(self.find_nss_certutil().is_some()),
            );
        }
        info
    }

    /// Whether the profile's cert DB exists (a heuristic, as in Node).
    pub fn ca_imported(&self) -> bool {
        self.profile_dir.join("cert9.db").is_file()
    }

    /// Locate a real NSS `certutil` (not Windows' System32 one): run `-?` and
    /// look for cert-DB wording in the output.
    pub fn find_nss_certutil(&self) -> Option<PathBuf> {
        let names: &[&str] = if cfg!(windows) {
            &["certutil.exe"]
        } else {
            &["certutil"]
        };
        let is_system = |p: &Path| {
            let s = p.to_string_lossy().to_lowercase();
            s.contains("\\windows\\system32") || s.contains("\\windows\\syswow64")
        };
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                if is_system(&dir) {
                    continue;
                }
                for n in names {
                    candidates.push(dir.join(n));
                }
            }
        }
        if let Some(ff) = self.detect_firefox()
            && let Some(dir) = ff.parent()
        {
            candidates.push(dir.join("certutil.exe"));
        }
        for p in [
            r"C:\tools\nss\bin\certutil.exe",
            r"C:\ProgramData\chocolatey\lib\nss\tools\bin\certutil.exe",
            "/usr/bin/certutil",
            "/usr/local/bin/certutil",
            "/opt/homebrew/bin/certutil",
        ] {
            candidates.push(p.into());
        }

        for cand in candidates {
            if !cand.is_file() || is_system(&cand) {
                continue;
            }
            let out = std::process::Command::new(&cand).arg("-?").output();
            if let Ok(out) = out {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                )
                .to_lowercase();
                if text.contains("certdir")
                    || text.contains("certificate database")
                    || text.contains("nickname")
                {
                    return Some(cand);
                }
            }
        }
        None
    }

    fn write_profile(&self, proxy_port: u16, ca_pem: &str) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.profile_dir)?;
        std::fs::write(&self.ca_path, ca_pem)?;
        let prefs = format!(
            concat!(
                "// hizn Firefox interception profile — generated, safe to delete\n",
                "user_pref(\"network.proxy.type\", 1);\n",
                "user_pref(\"network.proxy.http\", \"127.0.0.1\");\n",
                "user_pref(\"network.proxy.http_port\", {port});\n",
                "user_pref(\"network.proxy.ssl\", \"127.0.0.1\");\n",
                "user_pref(\"network.proxy.ssl_port\", {port});\n",
                "user_pref(\"network.proxy.share_proxy_settings\", true);\n",
                "user_pref(\"network.proxy.socks_remote_dns\", true);\n",
                "user_pref(\"network.proxy.allow_hijacking_localhost\", true);\n",
                "user_pref(\"network.proxy.no_proxies_on\", \"\");\n",
                "user_pref(\"browser.shell.checkDefaultBrowser\", false);\n",
                "user_pref(\"datareporting.policy.dataSubmissionEnabled\", false);\n",
                "user_pref(\"datareporting.healthreport.uploadEnabled\", false);\n",
                "user_pref(\"trailhead.firstrun.didSeeAboutWelcome\", true);\n",
                "user_pref(\"browser.aboutwelcome.enabled\", false);\n",
                "user_pref(\"doh-rollout.disable-heuristics\", true);\n",
                "user_pref(\"network.trr.mode\", 5);\n",
            ),
            port = proxy_port
        );
        std::fs::write(self.profile_dir.join("user.js"), prefs)
    }

    /// Import the CA into this profile's NSS store (scoped). Reports why if no
    /// NSS certutil is available.
    pub fn auto_import_ca(&self, ca_pem: &str) -> Value {
        let Some(certutil) = self.find_nss_certutil() else {
            return json!({ "imported": false, "reason": "NSS certutil not found" });
        };
        if std::fs::create_dir_all(&self.profile_dir).is_err()
            || std::fs::write(&self.ca_path, ca_pem).is_err()
        {
            return json!({ "imported": false, "reason": "could not write the profile" });
        }
        let db = format!("sql:{}", self.profile_dir.to_string_lossy());
        let run = |args: &[&str]| {
            let _ = std::process::Command::new(&certutil).args(args).output();
        };
        if !self.profile_dir.join("cert9.db").is_file() {
            let pw = self.profile_dir.join(".nsspw");
            let _ = std::fs::write(&pw, "");
            run(&["-N", "-d", &db, "-f", &pw.to_string_lossy()]);
        }
        run(&["-D", "-n", "hizn CA", "-d", &db]);
        // The add must succeed for a real import.
        let added = std::process::Command::new(&certutil)
            .args([
                "-A",
                "-n",
                "hizn CA",
                "-t",
                "CT,c,c",
                "-i",
                &self.ca_path.to_string_lossy(),
                "-d",
                &db,
            ])
            .output();
        match added {
            Ok(out) if out.status.success() => json!({ "imported": true, "method": "certutil" }),
            _ => json!({ "imported": false, "reason": "certutil import failed" }),
        }
    }

    /// Launch Firefox on the interception profile. Errors if Firefox isn't
    /// found.
    pub fn launch_firefox(&self, proxy_port: u16, ca_pem: &str) -> Result<Value, String> {
        let Some(firefox) = self.detect_firefox() else {
            return Err(format!(
                "Firefox not found. Install it, or set the proxy manually (127.0.0.1:{proxy_port})."
            ));
        };
        self.write_profile(proxy_port, ca_pem)
            .map_err(|e| e.to_string())?;

        let imported = self.auto_import_ca(ca_pem);
        let ca_trusted = if imported.get("imported") == Some(&Value::Bool(true)) {
            "certutil"
        } else {
            "manual"
        };

        let mut args = vec![
            "-no-remote".to_owned(),
            "-new-instance".to_owned(),
            "-profile".to_owned(),
            self.profile_dir.to_string_lossy().into_owned(),
        ];
        if ca_trusted == "manual" {
            args.push("about:preferences#privacy".to_owned());
        }
        // Detached, so it outlives this request.
        std::process::Command::new(&firefox)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;

        let mut result = self.info(proxy_port);
        if let Value::Object(map) = &mut result {
            map.insert("launched".into(), json!(true));
            map.insert("caTrusted".into(), json!(ca_trusted));
            map.insert(
                "certutilFound".into(),
                json!(self.find_nss_certutil().is_some()),
            );
        }
        Ok(result)
    }
}
