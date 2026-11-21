//! Hardcoded-secret / endpoint scanner over DEX string pools, resources.arsc,
//! manifest meta-data, and text/native assets. Mirrors the Node `scanSecrets`.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::axml::parse_arsc;
use crate::report::{Report, Secret, Severity, WhereField};
use crate::zip::Zip;

struct Pattern {
    kind: &'static str,
    re: Regex,
    severity: Severity,
}

fn patterns() -> &'static [Pattern] {
    static P: OnceLock<Vec<Pattern>> = OnceLock::new();
    P.get_or_init(|| {
        let p = |kind: &'static str, re: &str, severity: Severity| Pattern {
            kind,
            re: Regex::new(re).expect("valid secret pattern"),
            severity,
        };
        vec![
            p("Google API key", r"AIza[0-9A-Za-z\-_]{35}", Severity::High),
            p("Firebase app id", r"1:[0-9]{6,}:android:[0-9a-f]{8,}", Severity::Low),
            p("Firebase URL", r"(?i)https?://[a-z0-9-]+\.firebaseio\.com", Severity::Medium),
            p("AWS access key", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b", Severity::High),
            p("AWS secret (heuristic)", r#"(?i)aws(.{0,20})?(secret|private).{0,20}['"][0-9a-zA-Z/+]{40}['"]"#, Severity::High),
            p("Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----", Severity::High),
            p("Google OAuth client", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", Severity::Low),
            p("Slack token", r"xox[baprs]-[0-9A-Za-z-]{10,48}", Severity::High),
            p("Slack webhook", r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+", Severity::High),
            p("Stripe key", r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}", Severity::High),
            p("Stripe publishable key", r"\bpk_(?:live|test)_[0-9a-zA-Z]{20,}", Severity::Low),
            p("GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}", Severity::High),
            p("Twilio SID", r"\bAC[0-9a-fA-F]{32}\b", Severity::Medium),
            p("SendGrid key", r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}", Severity::High),
            p("Mapbox token", r"\b(?:pk|sk)\.eyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+", Severity::Medium),
            p("Facebook access token", r"\bEAACEdEose0cBA[0-9A-Za-z]+", Severity::High),
            p("JWT", r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", Severity::Medium),
            p("Basic-auth URL", r#"https?://[^/\s:@"']{1,40}:[^/\s:@"']{1,40}@[A-Za-z0-9.-]+"#, Severity::High),
            p("Bearer token", r"[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}=*", Severity::Medium),
            p("Generic secret assignment", r#"(?i)(?:api[_-]?key|secret|passwd|password|token|auth[_-]?token|access[_-]?key|client[_-]?secret)['"\s:=]{1,6}['"][A-Za-z0-9\-_.=/+]{10,80}['"]"#, Severity::Low),
        ]
    })
}

fn url_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}"#).expect("url re")
    })
}
fn high_name() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)(api[_-]?key|apikey|client[_-]?secret|client[_-]?id|secret[_-]?key|access[_-]?key|private[_-]?key|consumer[_-]?(key|secret)|app[_-]?secret|\baws\b|s3[_-]|oauth[_-]?(token|key|secret)|google[_-]?api|google_app_id|gcm_default|fcm_|default_web_client|firebase[_-]|facebook_app|facebook_client|url_facebook|mapbox|sendgrid|twilio|stripe[_-]?(key|secret)|appsflyer|onesignal|mixpanel|braze|crashlytics[._-])").expect("high name re"))
}
fn is_file_path() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)(^res/|\.(xml|png|jpe?g|webp|gif|ttf|otf|json|mp3|ogg|ttc)$)")
            .expect("file path re")
    })
}
fn is_dotted_ident() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^[A-Za-z][A-Za-z0-9_$]*(\.[A-Za-z0-9_$]+)+$").expect("dotted ident re")
    })
}
fn name_high() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)(secret|private[_-]?key|access[_-]?key|\baws\b|client[_-]?secret|consumer[_-]?secret)").expect("name high re"))
}
fn url_strip() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"[).,'"\\]+$"#).expect("url strip re"))
}
fn url_ignore() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(w3\.org|android\.com/apk|schemas\.android|apache\.org/xml|purl\.org|ns\.adobe)",
        )
        .expect("url ignore re")
    })
}

fn name_severity(name: &str) -> Severity {
    if name_high().is_match(name) {
        Severity::High
    } else {
        Severity::Medium
    }
}

/// Collector carried through the scan.
struct Scan<'a> {
    report: &'a mut Report,
    urls: HashSet<String>,
    seen: HashSet<String>,
    budget: i64,
}

impl Scan<'_> {
    fn add_secret(&mut self, kind: &str, matched: &str, where_: &str, severity: Severity) {
        let m: String = matched.chars().take(120).collect();
        let key = format!("{kind}|{m}");
        if self.seen.contains(&key) {
            return;
        }
        self.seen.insert(key);
        if self.report.secrets.len() < 500 {
            self.report.secrets.push(Secret {
                kind: kind.to_owned(),
                matched: m,
                where_: WhereField(where_.to_owned()),
                severity,
            });
        }
    }

    fn scan_text(&mut self, text: &str, where_: &str) {
        if text.is_empty() {
            return;
        }
        for p in patterns() {
            for m in p.re.find_iter(text).take(60) {
                self.add_secret(p.kind, m.as_str(), where_, p.severity);
            }
        }
        for u in url_re().find_iter(text).take(800) {
            let url = url_strip().replace(u.as_str(), "").into_owned();
            if url.len() <= 180 && !url_ignore().is_match(&url) {
                self.urls.insert(url);
            }
        }
    }

    fn scan_named(&mut self, name: &str, value: &str, where_: &str) {
        if value.is_empty() {
            return;
        }
        let is_path = is_file_path().is_match(value);
        if !is_path {
            self.scan_text(value, &format!("{where_}:{name}"));
        }
        if name.is_empty() || is_path || is_dotted_ident().is_match(value) {
            return;
        }
        let v_len = value.chars().count();
        if high_name().is_match(name)
            && !value.chars().any(char::is_whitespace)
            && (4..=256).contains(&v_len)
            && !value.starts_with(['@', '#', '?'])
            && !value.eq_ignore_ascii_case("true")
            && !value.eq_ignore_ascii_case("false")
        {
            self.add_secret(
                &format!("Named: {name}"),
                value,
                where_,
                name_severity(name),
            );
        }
    }
}

/// Printable ASCII runs ≥ `min` (DEX string pools, native libs).
fn extract_ascii(buf: &[u8], min: usize) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let end = buf.len().min(80 * 1024 * 1024);
    for &c in &buf[..end] {
        if (0x20..0x7f).contains(&c) {
            cur.push(c);
        } else {
            if cur.len() >= min {
                out.push(String::from_utf8_lossy(&cur).into_owned());
            }
            cur.clear();
        }
    }
    if cur.len() >= min {
        out.push(String::from_utf8_lossy(&cur).into_owned());
    }
    out.join("\n")
}

/// Printable UTF-16LE runs (ASCII char followed by 0x00).
fn extract_utf16(buf: &[u8], min: usize) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let end = buf.len().saturating_sub(1).min(40 * 1024 * 1024);
    let mut i = 0;
    while i < end {
        let (c, hi) = (buf[i], buf[i + 1]);
        if hi == 0 && (0x20..0x7f).contains(&c) {
            cur.push(c);
        } else {
            if cur.len() >= min {
                out.push(String::from_utf8_lossy(&cur).into_owned());
            }
            cur.clear();
        }
        i += 2;
    }
    if cur.len() >= min {
        out.push(String::from_utf8_lossy(&cur).into_owned());
    }
    out.join("\n")
}

fn is_media(name: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)\.(png|jpe?g|webp|gif|bmp|ico|mp3|mp4|m4a|ogg|wav|ttf|otf|woff2?|eot)$")
            .expect("media re")
    })
    .is_match(name)
}

/// Scan the APK for secrets / URLs, filling `report.secrets` and `report.urls`.
pub fn scan_secrets(zip: &Zip, report: &mut Report, meta_data: &[(String, String)]) {
    let mut scan = Scan {
        report,
        urls: HashSet::new(),
        seen: HashSet::new(),
        budget: 150 * 1024 * 1024,
    };

    // 1. Manifest <meta-data>.
    for (name, value) in meta_data {
        scan.scan_named(name, value, "manifest");
    }

    // 2. Files: DEX string pools, resources.arsc, text/native assets.
    for (name, bytes) in zip.all() {
        if scan.budget <= 0 {
            break;
        }
        if is_media(name) {
            continue;
        }
        let Some(buf) = bytes else { continue };
        scan.budget -= buf.len() as i64;
        if name == "resources.arsc" {
            let arsc = parse_arsc(&buf);
            for s in &arsc.values {
                scan.scan_text(s, "resources.arsc");
            }
            for (k, v) in &arsc.named {
                scan.scan_named(k, v, "strings");
            }
        } else if name.to_lowercase().ends_with(".dex") {
            let text = extract_ascii(&buf, 6);
            scan.scan_text(&text, name);
        } else {
            let text = extract_ascii(&buf, 5);
            scan.scan_text(&text, name);
            let lower = name.to_lowercase();
            if lower.ends_with(".xml") || lower.ends_with(".arsc") || name.starts_with("res/") {
                let u16t = extract_utf16(&buf, 6);
                scan.scan_text(&u16t, name);
            }
        }
    }

    // Rank secrets by severity; collect sorted URLs (cap 500).
    let mut urls: Vec<String> = scan.urls.into_iter().collect();
    urls.sort();
    urls.truncate(500);
    report
        .secrets
        .sort_by_key(|s| std::cmp::Reverse(s.severity.rank()));
    report.urls = urls;
}
