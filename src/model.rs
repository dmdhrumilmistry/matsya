//! Lock file data model (lockfileVersion 1, see docs/LOCKFILE.md).
//!
//! Every optional field is an `Option` that is skipped when absent, and
//! unknown fields are kept in `extra`, so reading and re-writing a lock never
//! changes fields this version does not know about (or the digests).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::platform::Platform;

pub const LOCKFILE_VERSION: i64 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Source {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Package {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// rpm only; an integer in practice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    /// `Some([])` means "not available from any repository" (apt).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub licenses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,

    // integrity
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sigmd5: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bottles: Option<BTreeMap<String, String>>,

    // apt
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub essential: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    // rpm
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installonly: Option<bool>,
    // apk
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world_entry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "virtual")]
    pub is_virtual: Option<bool>,
    // pacman
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packager: Option<String>,
    // brew
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outdated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub built_from_source: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other_kegs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_updates: Option<bool>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,

    /// Set while planning when the package was re-targeted to another arch.
    #[serde(skip)]
    pub cross_arch: bool,
}

impl Package {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Package { name: name.into(), version: version.into(), ..Default::default() }
    }
    pub fn arch(&self) -> &str {
        self.arch.as_deref().unwrap_or("")
    }
    pub fn reason(&self) -> &str {
        self.reason.as_deref().unwrap_or("")
    }
    pub fn is_manual(&self) -> bool {
        self.reason() == "manual"
    }
    pub fn kind(&self) -> &str {
        self.kind.as_deref().unwrap_or("")
    }
    pub fn flag(v: &Option<bool>) -> bool {
        v.unwrap_or(false)
    }
    pub fn epoch_str(&self) -> Option<String> {
        match &self.epoch {
            None | Some(Value::Null) => None,
            Some(Value::Number(n)) if n.as_i64() == Some(0) => None,
            Some(Value::String(s)) if s.is_empty() || s == "0" => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(v) => Some(v.to_string()),
        }
    }
    /// Version including epoch, for comparisons and display.
    pub fn full_version(&self) -> String {
        match self.epoch_str() {
            Some(e) => format!("{e}:{}", self.version),
            None => self.version.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Section {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taps: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreign_architectures: Option<Vec<String>>,
    #[serde(default)]
    pub packages: Vec<Package>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Section {
    pub fn repos(&self) -> &[Value] {
        self.repositories.as_deref().unwrap_or(&[])
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Environment {
    pub platform: Platform,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    #[serde(default)]
    pub managers: BTreeMap<String, Section>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Environment {
    pub fn captured_at(&self) -> &str {
        self.captured_at.as_deref().unwrap_or("")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Lockfile {
    pub lockfile_version: i64,
    #[serde(default)]
    pub generator: Value,
    #[serde(default)]
    pub environments: BTreeMap<String, Environment>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Default for Lockfile {
    fn default() -> Self {
        Lockfile {
            lockfile_version: LOCKFILE_VERSION,
            generator: generator(),
            environments: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }
}

pub fn generator() -> Value {
    serde_json::json!({"name": "matsya", "version": env!("CARGO_PKG_VERSION")})
}

/// Small accessors for the loosely-typed repository records.
pub fn vstr<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

pub fn vstrs(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}
