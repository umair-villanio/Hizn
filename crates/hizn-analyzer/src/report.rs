//! Report types, serialized to the same JSON the Node `AnalyzerReport` produced.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
            Self::Info => 0,
        }
    }
    fn key(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub section: String,
    pub title: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Finding {
    pub fn new(section: &str, title: impl Into<String>, severity: Severity) -> Self {
        Self {
            section: section.into(),
            title: title.into(),
            severity,
            detail: None,
        }
    }
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Permission {
    pub name: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CustomPermission {
    pub name: String,
    #[serde(rename = "protectionLevel", skip_serializing_if = "Option::is_none")]
    pub protection_level: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Component {
    pub kind: String,
    pub name: String,
    pub exported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    #[serde(rename = "hasIntentFilter")]
    pub has_intent_filter: bool,
}

#[derive(Debug, Clone)]
pub struct Secret {
    pub kind: String,
    pub matched: String,
    pub where_: WhereField,
    pub severity: Severity,
}

/// Serializes as `where` (a Rust keyword, so stored as `where_`).
#[derive(Debug, Clone)]
pub struct WhereField(pub String);

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("Secret", 4)?;
        st.serialize_field("type", &self.kind)?;
        st.serialize_field("match", &self.matched)?;
        st.serialize_field("where", &self.where_.0)?;
        st.serialize_field("severity", &self.severity)?;
        st.end()
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AppInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(rename = "versionName", skip_serializing_if = "Option::is_none")]
    pub version_name: Option<String>,
    #[serde(rename = "versionCode", skip_serializing_if = "Option::is_none")]
    pub version_code: Option<String>,
    #[serde(rename = "minSdk", skip_serializing_if = "Option::is_none")]
    pub min_sdk: Option<String>,
    #[serde(rename = "targetSdk", skip_serializing_if = "Option::is_none")]
    pub target_sdk: Option<String>,
    #[serde(rename = "compileSdk", skip_serializing_if = "Option::is_none")]
    pub compile_sdk: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size_bits: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub file: FileInfo,
    pub app: AppInfo,
    pub permissions: Vec<Permission>,
    #[serde(rename = "customPermissions")]
    pub custom_permissions: Vec<CustomPermission>,
    pub components: Vec<Component>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertInfo>,
    #[serde(rename = "manifestFlags")]
    pub manifest_flags: serde_json::Map<String, serde_json::Value>,
    pub secrets: Vec<Secret>,
    pub urls: Vec<String>,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

impl Report {
    pub fn new(file: FileInfo) -> Self {
        Self {
            file,
            app: AppInfo::default(),
            permissions: Vec::new(),
            custom_permissions: Vec::new(),
            components: Vec::new(),
            certificate: None,
            manifest_flags: serde_json::Map::new(),
            secrets: Vec::new(),
            urls: Vec::new(),
            findings: Vec::new(),
            summary: Summary {
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
            },
            errors: None,
        }
    }

    pub fn add(&mut self, f: Finding) {
        self.findings.push(f);
    }

    pub fn push_error(&mut self, msg: String) {
        self.errors.get_or_insert_with(Vec::new).push(msg);
    }

    /// Tally findings + secrets into the severity summary (Node did this last).
    pub fn tally(&mut self) {
        let sevs: Vec<Severity> = self
            .findings
            .iter()
            .map(|f| f.severity)
            .chain(self.secrets.iter().map(|s| s.severity))
            .collect();
        for sev in sevs {
            self.bump(sev);
        }
    }

    fn bump(&mut self, sev: Severity) {
        match sev.key() {
            "high" => self.summary.high += 1,
            "medium" => self.summary.medium += 1,
            "low" => self.summary.low += 1,
            _ => self.summary.info += 1,
        }
    }
}
