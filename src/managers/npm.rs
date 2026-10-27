//! Global npm packages (`npm install -g`), outside the system package
//! manager. Read from `<prefix>/lib/node_modules/*/package.json`, plus npm's
//! hidden lockfile (`node_modules/.package-lock.json`) for the nested
//! dependency tree and integrity hashes.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::eco::{by_kind, extra_str, scope_allowed, set_extra, subdirs, tilde, untilde, user_home, Scope};
use super::{Manager, Options, RootPolicy};
use crate::model::{Package, Section};
use crate::plan::{Plan, Step};
use crate::platform::Platform;
use crate::util::{has, read_text_opt, Result};

#[derive(Debug, Clone)]
pub struct Prefix {
    /// The npm prefix (node_modules lives in <prefix>/lib/node_modules).
    pub dir: PathBuf,
    pub scope: Scope,
}

impl Prefix {
    pub fn modules(&self) -> PathBuf {
        self.dir.join("lib/node_modules")
    }
}

pub fn prefixes() -> Vec<Prefix> {
    let mut out: Vec<Prefix> = Vec::new();
    let mut add = |dir: PathBuf, scope: Scope| {
        if dir.join("lib/node_modules").is_dir() && !out.iter().any(|p| p.dir == dir) {
            out.push(Prefix { dir, scope });
        }
    };
    for d in ["/usr/local", "/usr", "/opt/homebrew"] {
        add(PathBuf::from(d), Scope::System);
    }
    if let Some(p) = crate::platform::termux_prefix() {
        add(p, Scope::System);
    }
    if let Some(home) = user_home() {
        // A custom prefix from ~/.npmrc, then the usual per-user spots.
        if let Some(npmrc) = read_text_opt(home.join(".npmrc")) {
            for line in npmrc.lines() {
                if let Some(v) =
                    line.trim().strip_prefix("prefix").map(|r| r.trim_start()).and_then(|r| r.strip_prefix('='))
                {
                    let v = v.trim().trim_matches('"');
                    let p = if let Some(rest) = v.strip_prefix("~/") { home.join(rest) } else { PathBuf::from(v) };
                    add(p, Scope::User);
                }
            }
        }
        add(home.join(".npm-global"), Scope::User);
        add(home.join(".local"), Scope::User);
        for v in subdirs(&home.join(".nvm/versions/node")) {
            add(v, Scope::User);
        }
    }
    out
}

fn package_json(dir: &Path) -> Option<Value> {
    serde_json::from_str(&read_text_opt(dir.join("package.json"))?).ok()
}

fn license_of(pj: &Value) -> Option<String> {
    match pj.get("license") {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Object(o)) => o.get("type").and_then(Value::as_str).map(String::from),
        _ => None,
    }
}

/// "sha512-<base64>" -> hex, for SBOM hashes.
pub fn integrity_hex(integrity: &str) -> Option<(String, String)> {
    use base64::Engine;
    let (alg, b64) = integrity.split_whitespace().next()?.split_once('-')?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    Some((alg.to_ascii_uppercase(), crate::util::hex(&bytes)))
}

/// Packages of one prefix: top-level globals (manual) and, when npm's
/// hidden lockfile exists, their nested dependencies.
pub fn scan_prefix(prefix: &Prefix) -> Vec<Package> {
    let modules = prefix.modules();
    let kind = prefix.scope.label().to_string();
    let location = tilde(&prefix.dir);
    let mut pkgs = Vec::new();
    let mut tops: Vec<PathBuf> = Vec::new();
    for d in subdirs(&modules) {
        let name = d.file_name().unwrap_or_default().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        if name.starts_with('@') {
            tops.extend(subdirs(&d));
        } else {
            tops.push(d);
        }
    }
    let lock: Option<Value> =
        read_text_opt(modules.join(".package-lock.json")).and_then(|t| serde_json::from_str(&t).ok());
    let lock_entry =
        |rel: &str| lock.as_ref().and_then(|l| l.pointer(&format!("/packages/{}", rel.replace('/', "~1"))).cloned());
    for dir in tops {
        let Some(pj) = package_json(&dir) else { continue };
        let (Some(name), Some(version)) =
            (pj.get("name").and_then(Value::as_str), pj.get("version").and_then(Value::as_str))
        else {
            continue;
        };
        let rel = format!("node_modules/{name}");
        let mut p = Package::new(name, version);
        p.kind = Some(kind.clone());
        p.reason = Some("manual".into());
        if let Some(l) = license_of(&pj) {
            p.licenses = vec![l];
        }
        set_extra(&mut p, "location", location.clone());
        set_extra(&mut p, "path", name);
        if let Some(e) = lock_entry(&rel) {
            if let Some(i) = e.get("integrity").and_then(Value::as_str) {
                set_extra(&mut p, "integrity", i);
            }
        }
        // Nested dependencies recorded by npm under this package.
        let mut deps = BTreeSet::new();
        if let Some(packages) = lock.as_ref().and_then(|l| l.get("packages")).and_then(Value::as_object) {
            for (path, e) in packages {
                let Some(inner) = path.strip_prefix(&format!("{rel}/node_modules/")) else { continue };
                let dep_name = inner.rsplit("node_modules/").next().unwrap_or(inner).to_string();
                let Some(v) = e.get("version").and_then(Value::as_str) else { continue };
                let mut d = Package::new(dep_name, v);
                d.kind = Some(kind.clone());
                d.reason = Some("dependency".into());
                if let Some(l) = e.get("license").and_then(Value::as_str) {
                    d.licenses = vec![l.to_string()];
                }
                let dep_path = format!("{name}/node_modules/{inner}");
                set_extra(&mut d, "location", location.clone());
                set_extra(&mut d, "path", dep_path.clone());
                if let Some(i) = e.get("integrity").and_then(Value::as_str) {
                    set_extra(&mut d, "integrity", i);
                }
                if !inner.contains("/node_modules/") {
                    deps.insert(format!("{kind}:{location}:{dep_path}"));
                }
                pkgs.push(d);
            }
        }
        p.dependencies = deps.into_iter().collect();
        pkgs.push(p);
    }
    pkgs
}

pub fn scan() -> Vec<Package> {
    let mut pkgs: Vec<Package> = prefixes().iter().flat_map(scan_prefix).collect();
    pkgs.sort_by_key(key);
    pkgs.dedup_by_key(|p| key(p));
    pkgs
}

fn key(p: &Package) -> String {
    format!("{}:{}:{}", p.kind(), extra_str(p, "location").unwrap_or(""), extra_str(p, "path").unwrap_or(&p.name))
}

pub struct Npm;

impl Manager for Npm {
    fn name(&self) -> &'static str {
        "npm"
    }

    fn root_policy(&self) -> RootPolicy {
        RootPolicy::PerPackage
    }

    fn optional(&self) -> bool {
        true
    }

    fn available(&self) -> bool {
        !prefixes().is_empty() || has("npm")
    }

    fn key_of(&self, pkg: &Package, _plat: &Platform) -> String {
        key(pkg)
    }

    fn installed(&self, _plat: &Platform) -> Result<Vec<Package>> {
        Ok(scan())
    }

    fn capture(&self, _plat: &Platform, opts: &Options) -> Result<Section> {
        let mut pkgs = scan();
        if !opts.licenses {
            pkgs.iter_mut().for_each(|p| p.licenses.clear());
        }
        Ok(Section { tool: Some("npm (global node_modules)".into()), packages: pkgs, ..Default::default() })
    }

    fn plan(&self, section: &Section, _src: &Platform, _dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("npm");
        let installed = scan();
        let current: HashMap<String, &Package> = installed.iter().map(|p| (key(p), p)).collect();
        let mut n = 0;
        // Only top-level globals are installed; npm brings their dependencies.
        let tops = section.packages.iter().filter(|p| p.is_manual());
        let mut groups: Vec<(String, Vec<&Package>)> = Vec::new();
        for (_, pkgs) in by_kind(tops) {
            for p in pkgs {
                let loc = extra_str(p, "location").unwrap_or("").to_string();
                match groups.iter_mut().find(|(l, _)| *l == loc) {
                    Some(g) => g.1.push(p),
                    None => groups.push((loc, vec![p])),
                }
            }
        }
        for (loc, pkgs) in groups {
            let scope = Scope::of(pkgs[0]);
            let todo: Vec<&&Package> =
                pkgs.iter().filter(|p| current.get(&key(p)).map(|c| &c.version) != Some(&p.version)).collect();
            if todo.is_empty() || !scope_allowed(scope, &format!("npm globals in {loc}"), &mut plan) {
                continue;
            }
            let prefix = untilde(&loc);
            let npm = prefix.join("bin/npm");
            let npm = if npm.exists() { npm.to_string_lossy().into_owned() } else { "npm".into() };
            if npm == "npm" && !has("npm") {
                plan.unresolved.push(format!("{} npm package(s) in {loc} (npm is not installed)", todo.len()));
                continue;
            }
            let mut argv = vec![
                npm,
                "install".into(),
                "--global".into(),
                "--prefix".into(),
                prefix.to_string_lossy().into_owned(),
            ];
            let mut specs: Vec<String> = todo.iter().map(|p| format!("{}@{}", p.name, p.version)).collect();
            specs.sort();
            n += specs.len();
            let count = specs.len();
            argv.extend(specs);
            plan.add(Step::cmd(format!("install {count} npm global(s) into {loc}"), argv));
        }
        if opts.prune {
            let locked: BTreeSet<String> = section.packages.iter().map(key).collect();
            let extra: Vec<&Package> =
                installed.iter().filter(|p| p.is_manual() && !locked.contains(&key(p))).collect();
            for p in extra {
                let loc = extra_str(p, "location").unwrap_or("").to_string();
                if !scope_allowed(Scope::of(p), &format!("npm globals in {loc}"), &mut plan) {
                    continue;
                }
                let prefix = untilde(&loc).to_string_lossy().into_owned();
                plan.add(Step::cmd(
                    format!("remove npm global {} (not in the lock)", p.name),
                    ["npm", "uninstall", "--global", "--prefix", &prefix, &p.name],
                ));
            }
        }
        plan.summary = vec![("install".into(), n), ("unresolved".into(), plan.unresolved.len())];
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_a_global_prefix() {
        let root = std::env::temp_dir().join(format!("matsya-npm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let m = root.join("lib/node_modules");
        let w = |p: &str, c: &str| {
            let f = m.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, c).unwrap();
        };
        w("cowsay/package.json", r#"{"name": "cowsay", "version": "1.6.0", "license": "MIT"}"#);
        w("@scope/tool/package.json", r#"{"name": "@scope/tool", "version": "2.0.0", "license": {"type": "ISC"}}"#);
        w(
            ".package-lock.json",
            r#"{"packages": {
                "node_modules/cowsay": {"version": "1.6.0", "integrity": "sha512-AAAA"},
                "node_modules/cowsay/node_modules/get-stdin": {"version": "8.0.0", "license": "MIT", "integrity": "sha512-BBBB"},
                "node_modules/cowsay/node_modules/get-stdin/node_modules/deep": {"version": "1.0.0"}
            }}"#,
        );
        let pkgs = scan_prefix(&Prefix { dir: root.clone(), scope: Scope::System });
        let by = |n: &str| pkgs.iter().find(|p| p.name == n).unwrap().clone();
        let cow = by("cowsay");
        assert_eq!((cow.reason(), extra_str(&cow, "integrity")), ("manual", Some("sha512-AAAA")));
        assert_eq!(cow.dependencies.len(), 1); // only the direct child
        assert_eq!(by("@scope/tool").licenses, vec!["ISC"]);
        assert_eq!(by("get-stdin").reason(), "dependency");
        assert_eq!(by("deep").version, "1.0.0");
        assert!(integrity_hex("sha512-AAAA").unwrap().0 == "SHA512");
        let _ = std::fs::remove_dir_all(root);
    }
}
