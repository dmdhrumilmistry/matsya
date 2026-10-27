//! Shared helpers for software installed outside the system package
//! manager (pip, npm, cargo, Go, gem, snap, flatpak, loose files, apps).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::model::Package;
use crate::plan::Plan;
use crate::util::{is_root, read_text_opt};

/// Where per-user software lives. Under `sudo`, that is the invoking
/// user's home rather than /root, so `sudo matsya lock` still records it.
pub fn user_home() -> Option<PathBuf> {
    if is_root() {
        if let Some(user) = std::env::var_os("SUDO_USER").filter(|u| !u.is_empty() && u != "root") {
            let user = user.to_string_lossy().into_owned();
            if let Some(home) = passwd_home(&user) {
                return Some(home);
            }
        }
    }
    std::env::var_os("HOME").map(PathBuf::from).filter(|h| !h.as_os_str().is_empty())
}

fn passwd_home(user: &str) -> Option<PathBuf> {
    read_text_opt("/etc/passwd")?.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 6 && f[0] == user).then(|| PathBuf::from(f[5]))
    })
}

/// Paths are recorded with the home directory as `~`, so locks from
/// different users and machines compare cleanly.
pub fn tilde(p: &Path) -> String {
    if let Some(home) = user_home() {
        if let Ok(rest) = p.strip_prefix(&home) {
            return if rest.as_os_str().is_empty() { "~".into() } else { format!("~/{}", rest.display()) };
        }
    }
    p.display().to_string()
}

pub fn untilde(s: &str) -> PathBuf {
    match (s.strip_prefix("~/"), user_home()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ if s == "~" => user_home().unwrap_or_default(),
        _ => PathBuf::from(s),
    }
}

/// Entries of `dir` whose names start with `prefix`, sorted.
pub fn entries_with_prefix(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|d| {
            d.flatten().filter(|e| e.file_name().to_string_lossy().starts_with(prefix)).map(|e| e.path()).collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

pub fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|d| d.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    System,
    User,
}

impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Scope::System => "system",
            Scope::User => "user",
        }
    }
    pub fn of(pkg: &Package) -> Scope {
        let k = pkg.kind();
        if k == "user" || k.ends_with("/user") || k == "pipx" {
            Scope::User
        } else {
            Scope::System
        }
    }
}

/// Can this run install software of the given scope? System-wide installs
/// need root (except in Termux, which has no root); per-user installs must
/// not run as root, or they would land in /root. Adds a warning when not.
pub fn scope_allowed(scope: Scope, what: &str, plan: &mut Plan) -> bool {
    let termux = crate::platform::termux_prefix().is_some();
    match scope {
        Scope::System if !is_root() && !termux => {
            plan.warnings.push(format!("skipping system-wide {what}: re-run with sudo to apply them"));
            false
        }
        Scope::User if is_root() => {
            plan.warnings.push(format!("skipping per-user {what}: re-run as your normal user to apply them"));
            false
        }
        _ => true,
    }
}

/// Group packages by their `kind` (scope/location label), keeping order.
pub fn by_kind<'a>(pkgs: impl Iterator<Item = &'a Package>) -> Vec<(String, Vec<&'a Package>)> {
    let mut order: Vec<String> = Vec::new();
    let mut map: HashMap<String, Vec<&Package>> = HashMap::new();
    for p in pkgs {
        let k = p.kind().to_string();
        if !map.contains_key(&k) {
            order.push(k.clone());
        }
        map.entry(k).or_default().push(p);
    }
    order.into_iter().map(|k| (k.clone(), map.remove(&k).unwrap_or_default())).collect()
}

pub fn extra_str<'a>(p: &'a Package, key: &str) -> Option<&'a str> {
    p.extra.get(key).and_then(|v| v.as_str())
}

/// Field names of `Package` itself; an extra field with one of these names
/// would shadow it and make the lock unreadable.
pub const RESERVED: &[&str] = &[
    "name",
    "version",
    "arch",
    "epoch",
    "kind",
    "reason",
    "dependencies",
    "repositories",
    "licenses",
    "source",
    "sha256",
    "size",
    "filename",
    "payloadDigest",
    "sigmd5",
    "checksum",
    "bottles",
    "held",
    "essential",
    "priority",
    "vendor",
    "installonly",
    "commit",
    "worldEntry",
    "virtual",
    "packager",
    "tap",
    "pinned",
    "outdated",
    "builtFromSource",
    "otherKegs",
    "url",
    "autoUpdates",
];

pub fn set_extra(p: &mut Package, key: &str, value: impl Into<serde_json::Value>) {
    debug_assert!(!RESERVED.contains(&key), "extra field {key:?} collides with a Package field");
    p.extra.insert(key.into(), value.into());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every built-in field must be in RESERVED, or the guard is useless.
    #[test]
    fn reserved_covers_every_package_field() {
        let full = serde_json::json!({
            "name": "n", "version": "v", "arch": "a", "epoch": 1, "kind": "k", "reason": "manual",
            "dependencies": ["d"], "repositories": ["r"], "licenses": ["l"], "source": {"name": "s"},
            "sha256": "x", "size": 1, "filename": "f", "payloadDigest": "p", "sigmd5": "m", "checksum": "c",
            "bottles": {"t": "h"}, "held": true, "essential": true, "priority": "p", "vendor": "v",
            "installonly": true, "commit": "c", "worldEntry": "w", "virtual": true, "packager": "p", "tap": "t",
            "pinned": true, "outdated": true, "builtFromSource": true, "otherKegs": ["k"], "url": "u", "autoUpdates": true
        });
        let p: Package = serde_json::from_value(full).unwrap();
        assert!(p.extra.is_empty(), "fields not known to Package: {:?}", p.extra.keys());
        let back = serde_json::to_value(&p).unwrap();
        for k in back.as_object().unwrap().keys() {
            assert!(RESERVED.contains(&k.as_str()), "{k} missing from RESERVED");
        }
    }

    #[test]
    fn tilde_roundtrip() {
        if let Some(home) = user_home() {
            let p = home.join(".local/lib/python3.12/site-packages");
            let t = tilde(&p);
            assert_eq!(t, "~/.local/lib/python3.12/site-packages");
            assert_eq!(untilde(&t), p);
        }
        assert_eq!(tilde(Path::new("/usr/local/lib")), "/usr/local/lib");
    }
}
