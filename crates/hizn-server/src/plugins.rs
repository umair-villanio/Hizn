//! File-backed plugin store — the Rust port of the Node `PluginService`.
//!
//! Plugins are single `.js` files with `// @name` / `@description` / `@version`
//! / `@author` header comments. Two directories: `contrib` (shipped, read-only)
//! and `user` (`~/.hizn/plugins`, writable). Enabled state persists in
//! `~/.hizn/plugins.json`.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Map, Value, json};

#[derive(Debug, Clone, Serialize)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    pub desc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub origin: String,
    pub builtin: bool,
    pub enabled: bool,
    pub source: String,
}

pub struct Plugins {
    contrib_dir: PathBuf,
    user_dir: PathBuf,
    state_file: PathBuf,
}

/// `~/.hizn` (or `HIZN_HOME`), matching the proxy's CA directory.
fn hizn_home() -> PathBuf {
    std::env::var_os("HIZN_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(hizn_proxy::hizn_dir)
}

impl Plugins {
    /// `contrib_dir` is the shipped `plugins/` folder (next to `ui/`).
    pub fn new(contrib_dir: PathBuf) -> Self {
        let home = hizn_home();
        Self {
            contrib_dir,
            user_dir: home.join("plugins"),
            state_file: home.join("plugins.json"),
        }
    }

    pub fn dirs(&self) -> Value {
        json!({
            "contrib": self.contrib_dir.to_string_lossy(),
            "user": self.user_dir.to_string_lossy(),
        })
    }

    /// contrib then user (the Node order).
    pub fn list(&self) -> Vec<PluginInfo> {
        let enabled = self.enabled_map();
        let mut out = self.read_dir(&self.contrib_dir, "contrib", &enabled);
        out.extend(self.read_dir(&self.user_dir, "user", &enabled));
        out
    }

    fn read_dir(&self, dir: &Path, origin: &str, enabled: &Map<String, Value>) -> Vec<PluginInfo> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        // Sort file names for a stable order (readdir order is platform-defined;
        // Node's was insertion/FS order — a sorted list is deterministic and
        // close enough, and the UI sorts for display anyway).
        let mut files: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|f| f.to_ascii_lowercase().ends_with(".js"))
            .collect();
        files.sort();

        let mut out = Vec::new();
        for file in files {
            let Ok(source) = std::fs::read_to_string(dir.join(&file)) else {
                continue;
            };
            // Normalize CRLF → LF so the served source is the same regardless of
            // how git checked the file out.
            let source = source.replace("\r\n", "\n");
            let meta = parse_manifest(&source, &file);
            let id = format!("{origin}/{file}");
            let is_enabled = enabled.get(&id).and_then(Value::as_bool).unwrap_or(true);
            out.push(PluginInfo {
                id,
                name: meta.name,
                desc: meta.desc,
                version: meta.version,
                author: meta.author,
                origin: origin.to_owned(),
                builtin: origin == "contrib",
                enabled: is_enabled,
                source,
            });
        }
        out
    }

    fn enabled_map(&self) -> Map<String, Value> {
        std::fs::read_to_string(&self.state_file)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default()
    }

    fn write_enabled_map(&self, map: &Map<String, Value>) -> std::io::Result<()> {
        if let Some(parent) = self.state_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            &self.state_file,
            serde_json::to_string_pretty(map).unwrap_or_default(),
        )
    }

    /// Install a plugin into the user dir; `source` is the function body.
    pub fn install(
        &self,
        name: &str,
        desc: Option<&str>,
        author: Option<&str>,
        source: &str,
    ) -> Result<PluginInfo, String> {
        let slug = slugify(name);
        std::fs::create_dir_all(&self.user_dir).map_err(|e| e.to_string())?;

        let mut file = format!("{slug}.js");
        let mut i = 2;
        while self.user_dir.join(&file).exists() {
            file = format!("{slug}-{i}.js");
            i += 1;
        }

        let mut header = format!(
            "// @name        {name}\n// @description {}\n",
            desc.unwrap_or("")
        );
        if let Some(author) = author {
            header.push_str(&format!("// @author      {author}\n"));
        }
        header.push('\n');
        let contents = format!("{header}{}", source.trim_start());
        std::fs::write(self.user_dir.join(&file), &contents).map_err(|e| e.to_string())?;

        let meta = parse_manifest(&contents, &file);
        Ok(PluginInfo {
            id: format!("user/{file}"),
            name: meta.name,
            desc: meta.desc,
            version: meta.version,
            author: meta.author,
            origin: "user".into(),
            builtin: false,
            enabled: true,
            source: contents,
        })
    }

    /// Remove a user plugin (contrib is read-only).
    pub fn remove(&self, id: &str) -> Result<(), String> {
        let (origin, file) = id.split_once('/').unwrap_or(("", ""));
        if origin != "user"
            || file.is_empty()
            || file.contains("..")
            || file.contains('/')
            || file.contains('\\')
        {
            return Err("Only user-installed plugins can be removed".into());
        }
        std::fs::remove_file(self.user_dir.join(file)).map_err(|e| e.to_string())?;
        let mut map = self.enabled_map();
        map.remove(id);
        let _ = self.write_enabled_map(&map);
        Ok(())
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) {
        let mut map = self.enabled_map();
        map.insert(id.to_owned(), Value::Bool(enabled));
        let _ = self.write_enabled_map(&map);
    }
}

struct Manifest {
    name: String,
    desc: String,
    version: Option<String>,
    author: Option<String>,
}

/// Parse `// @field value` header comments (first 30 lines, stop at the first
/// non-matching line).
fn parse_manifest(source: &str, filename: &str) -> Manifest {
    let mut meta: BTreeMap<String, String> = BTreeMap::new();
    for line in source.split('\n').take(30) {
        match manifest_line(line) {
            Some((key, value)) => {
                meta.insert(key.to_ascii_lowercase(), value);
            }
            None => break,
        }
    }
    Manifest {
        name: meta
            .get("name")
            .cloned()
            .unwrap_or_else(|| strip_js(filename)),
        desc: meta
            .get("description")
            .or_else(|| meta.get("desc"))
            .cloned()
            .unwrap_or_default(),
        version: meta.get("version").cloned(),
        author: meta.get("author").cloned(),
    }
}

/// `^\s*//\s*@(\w+)\s+(.+?)\s*$`
fn manifest_line(line: &str) -> Option<(String, String)> {
    let rest = line.trim_start().strip_prefix("//")?.trim_start();
    let rest = rest.strip_prefix('@')?;
    let end = rest.find(|c: char| !c.is_alphanumeric() && c != '_')?;
    let key = &rest[..end];
    if key.is_empty() {
        return None;
    }
    let value = rest[end..].trim();
    if value.is_empty() {
        return None;
    }
    Some((key.to_owned(), value.to_owned()))
}

fn strip_js(filename: &str) -> String {
    filename
        .strip_suffix(".js")
        .or_else(|| filename.strip_suffix(".JS"))
        .unwrap_or(filename)
        .to_owned()
}

/// `name.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'') || 'plugin'`
fn slugify(name: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for c in name.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let slug = out.trim_matches('-').to_owned();
    if slug.is_empty() {
        "plugin".into()
    } else {
        slug
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_manifest_headers() {
        let src =
            "// @name  JWT Decoder\n// @description Decode JWTs\n// @version 1.0.0\nconst x = 1;";
        let m = parse_manifest(src, "jwt.js");
        assert_eq!(m.name, "JWT Decoder");
        assert_eq!(m.desc, "Decode JWTs");
        assert_eq!(m.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn manifest_stops_at_first_non_header() {
        let m = parse_manifest("const x = 1;\n// @name Late", "f.js");
        assert_eq!(m.name, "f"); // filename, headers stop at line 1
    }

    #[test]
    fn slugify_matches_node() {
        assert_eq!(slugify("My Cool Plugin!!"), "my-cool-plugin");
        assert_eq!(slugify("  --- "), "plugin");
        assert_eq!(slugify("a.b.c"), "a-b-c");
    }
}
