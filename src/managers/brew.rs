//! Homebrew (macOS and Linux) backend.
//!
//! Homebrew has no repository of old versions, only the current formula
//! definition. What we can do:
//!
//! * record exact versions plus the bottle sha256 for that version
//!   (Homebrew reports the bottle of the platform it runs on; older releases
//!   report every platform, which is kept when present);
//! * reinstall the same version while it is still current;
//! * otherwise rebuild it with `brew extract` from homebrew-core's git
//!   history into a local tap (usually compiles from source).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::{json, Value};

use super::{Manager, Options};
use crate::bail;
use crate::model::{vstr, Package, Section};
use crate::plan::{Plan, Step};
use crate::platform::Platform;
use crate::util::{exec, has, is_root, run, run_ok, warn, Result};

pub const PIN_TAP: &str = "matsya/pins";
/// Tap used by the Python implementation for extracted versions.
const LEGACY_PIN_TAP: &str = "syslock/pins";
const OFFICIAL_TAPS: &[&str] = &["homebrew/core", "homebrew/cask"];

/// The version brew would install now: stable + _revision.
pub fn pkg_version(f: &Value) -> String {
    let stable = f.pointer("/versions/stable").and_then(Value::as_str).unwrap_or("");
    match f.get("revision").and_then(Value::as_i64).unwrap_or(0) {
        0 => stable.to_string(),
        r => format!("{stable}_{r}"),
    }
}

/// 1.2.3_1 -> 1.2.3 (drop the Homebrew revision suffix).
pub fn plain(version: &str) -> &str {
    version.rsplit_once('_').map(|(a, _)| a).unwrap_or(version)
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

/// `brew info --json=v2 --installed` -> lock entries.
pub fn parse_info(data: &Value) -> Vec<Package> {
    let mut pkgs = Vec::new();
    for f in data.get("formulae").and_then(Value::as_array).into_iter().flatten() {
        let inst = f.get("installed").and_then(Value::as_array).cloned().unwrap_or_default();
        if inst.is_empty() {
            continue;
        }
        // Several kegs can be installed; the linked one is what is in use.
        let linked = f.get("linked_keg").and_then(Value::as_str);
        let keg = inst
            .iter()
            .find(|i| i.get("version").and_then(Value::as_str) == linked)
            .unwrap_or(inst.last().expect("non-empty"));
        let version = s(keg, "version");
        let mut p = Package::new(s(f, "full_name"), version.clone());
        p.kind = Some("formula".into());
        p.tap = Some(Some(s(f, "tap")).filter(|t| !t.is_empty()).unwrap_or_else(|| "homebrew/core".into()));
        let on_request = keg.get("installed_on_request").and_then(Value::as_bool).unwrap_or(false);
        p.reason = Some(if on_request { "manual" } else { "dependency" }.into());
        if f.get("pinned").and_then(Value::as_bool).unwrap_or(false) {
            p.pinned = Some(true);
        }
        if let Some(l) = f.get("license").and_then(Value::as_str).filter(|l| !l.is_empty()) {
            p.licenses = vec![l.into()];
        }
        if !keg.get("poured_from_bottle").and_then(Value::as_bool).unwrap_or(false) {
            p.built_from_source = Some(true);
        }
        if inst.len() > 1 {
            let mut other: Vec<String> =
                inst.iter().filter(|i| !std::ptr::eq(*i, keg)).map(|i| s(i, "version")).collect();
            other.sort();
            p.other_kegs = other;
        }
        let deps: BTreeSet<String> = keg
            .get("runtime_dependencies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|d| s(d, "full_name"))
            .filter(|d| !d.is_empty())
            .collect();
        p.dependencies = deps.into_iter().collect();
        if version == pkg_version(f) {
            let bottles: BTreeMap<String, String> = f
                .pointer("/bottle/stable/files")
                .and_then(Value::as_object)
                .map(|files| {
                    files
                        .iter()
                        .filter_map(|(tag, v)| {
                            v.get("sha256").and_then(Value::as_str).map(|h| (tag.clone(), h.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            if !bottles.is_empty() {
                p.bottles = Some(bottles);
            }
        } else {
            // The formula has moved on; bottle hashes would describe another version.
            p.outdated = Some(true);
        }
        pkgs.push(p);
    }
    for c in data.get("casks").and_then(Value::as_array).into_iter().flatten() {
        let installed = s(c, "installed");
        if installed.is_empty() {
            continue;
        }
        let name = Some(s(c, "full_token")).filter(|t| !t.is_empty()).unwrap_or_else(|| s(c, "token"));
        let mut p = Package::new(name, installed.clone());
        p.kind = Some("cask".into());
        p.tap = Some(Some(s(c, "tap")).filter(|t| !t.is_empty()).unwrap_or_else(|| "homebrew/cask".into()));
        p.reason = Some("manual".into());
        let sha = s(c, "sha256");
        if installed == s(c, "version") && !sha.is_empty() && sha != "no_check" {
            p.sha256 = Some(sha);
            if !s(c, "url").is_empty() {
                p.url = Some(s(c, "url"));
            }
        }
        if c.get("auto_updates").and_then(Value::as_bool).unwrap_or(false) {
            // The app updates itself; the installed version can drift.
            p.auto_updates = Some(true);
        }
        pkgs.push(p);
    }
    pkgs.sort_by(|a, b| (a.kind(), &a.name).cmp(&(b.kind(), &b.name)));
    pkgs
}

/// macOS 15 aarch64 -> arm64_sequoia; Linux x86_64 -> x86_64_linux.
pub fn bottle_tag(plat: &Platform) -> String {
    let arm = plat.arch() == "aarch64";
    if plat.os() == "macos" {
        if arm {
            format!("arm64_{}", plat.codename())
        } else {
            plat.codename().to_string()
        }
    } else if arm {
        "arm64_linux".into()
    } else {
        "x86_64_linux".into()
    }
}

pub fn export_brewfile(section: &Section) -> String {
    let mut lines = Vec::new();
    for t in section.taps.iter().flatten() {
        let name = vstr(t, "name");
        if !OFFICIAL_TAPS.contains(&name) {
            let custom = t.get("customRemote").and_then(Value::as_bool).unwrap_or(false);
            lines.push(if custom {
                format!("tap \"{name}\", \"{}\"", vstr(t, "remote"))
            } else {
                format!("tap \"{name}\"")
            });
        }
    }
    for p in section.packages.iter().filter(|p| p.kind() == "formula" && p.is_manual()) {
        let pinned = if Package::flag(&p.pinned) { " (pinned)" } else { "" };
        lines.push(format!("brew \"{}\"  # {}{pinned}", p.name, p.version));
    }
    for p in section.packages.iter().filter(|p| p.kind() == "cask") {
        lines.push(format!("cask \"{}\"  # {}", p.name, p.version));
    }
    lines.join("\n") + "\n"
}

pub struct Brew;

impl Brew {
    fn info_installed(&self) -> Result<Value> {
        if is_root() {
            bail!("Homebrew refuses to run as root; run `matsya lock --managers brew` as your normal user");
        }
        let out = run(&["brew", "info", "--json=v2", "--installed"])?;
        Ok(if out.trim().is_empty() { json!({}) } else { serde_json::from_str(&out)? })
    }

    /// What brew would install right now for each name.
    fn current(&self, names: &[String], cask: bool) -> HashMap<String, (String, Vec<String>)> {
        let mut res = HashMap::new();
        if names.is_empty() {
            return res;
        }
        let flag = if cask { "--cask" } else { "--formula" };
        let query = |batch: &[String]| -> Option<Value> {
            let mut args = vec!["brew", "info", "--json=v2", flag];
            args.extend(batch.iter().map(String::as_str));
            let out = exec(&args).ok()?.stdout;
            serde_json::from_str(&out).ok()
        };
        // One unknown name fails the whole batch; fall back to one by one.
        let results: Vec<Value> = match query(names) {
            Some(v) => vec![v],
            None => names.iter().filter_map(|n| query(std::slice::from_ref(n))).collect(),
        };
        for d in results {
            for f in d.get("formulae").and_then(Value::as_array).into_iter().flatten() {
                let inst = f
                    .get("installed")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|i| s(i, "version"))
                    .collect();
                res.insert(s(f, "full_name"), (pkg_version(f), inst));
            }
            for c in d.get("casks").and_then(Value::as_array).into_iter().flatten() {
                let name = Some(s(c, "full_token")).filter(|t| !t.is_empty()).unwrap_or_else(|| s(c, "token"));
                let inst = Some(s(c, "installed")).filter(|x| !x.is_empty()).into_iter().collect();
                res.insert(name, (s(c, "version"), inst));
            }
        }
        res
    }
}

impl Manager for Brew {
    fn name(&self) -> &'static str {
        "brew"
    }

    fn available(&self) -> bool {
        has("brew")
    }

    fn key_of(&self, pkg: &Package, _plat: &Platform) -> String {
        if pkg.kind() == "cask" {
            return format!("cask:{}", pkg.name);
        }
        for tap in [PIN_TAP, LEGACY_PIN_TAP] {
            if let Some(rest) = pkg.name.strip_prefix(&format!("{tap}/")) {
                // matsya/pins/foo@1.2 is our `brew extract` of foo 1.2.
                return rest.rsplit_once('@').map(|(n, _)| n).unwrap_or(rest).to_string();
            }
        }
        pkg.name.clone()
    }

    fn installed(&self, _plat: &Platform) -> Result<Vec<Package>> {
        Ok(parse_info(&self.info_installed()?))
    }

    fn capture(&self, _plat: &Platform, opts: &Options) -> Result<Section> {
        let mut pkgs = parse_info(&self.info_installed()?);
        if !opts.licenses {
            for p in &mut pkgs {
                p.licenses.clear();
            }
        }
        let outdated: Vec<&str> = pkgs.iter().filter(|p| Package::flag(&p.outdated)).map(|p| p.name.as_str()).collect();
        if !outdated.is_empty() {
            warn(&format!(
                "{} Homebrew formula(e) are older than their current formula, so their bottle checksums are not recorded: {}",
                outdated.len(),
                outdated.iter().take(10).cloned().collect::<Vec<_>>().join(", ")
            ));
        }
        let mut taps = Vec::new();
        match serde_json::from_str::<Value>(&run_ok(&["brew", "tap-info", "--json", "--installed"])) {
            Ok(Value::Array(list)) => {
                for t in list {
                    let mut rec = json!({"name": s(&t, "name")});
                    if !s(&t, "remote").is_empty() {
                        rec["remote"] = json!(s(&t, "remote"));
                    }
                    if t.get("custom_remote").and_then(Value::as_bool).unwrap_or(false) {
                        rec["customRemote"] = json!(true);
                    }
                    let path = s(&t, "path");
                    if !path.is_empty() && std::path::Path::new(&path).join(".git").is_dir() {
                        let head = run_ok(&["git", "-C", &path, "rev-parse", "HEAD"]);
                        if !head.trim().is_empty() {
                            rec["commit"] = json!(head.trim());
                        }
                    }
                    taps.push(rec);
                }
            }
            _ => warn("could not read Homebrew taps"),
        }
        taps.sort_by(|a, b| vstr(a, "name").cmp(vstr(b, "name")));
        let version = run_ok(&["brew", "--version"]);
        Ok(Section {
            tool: Some(version.lines().next().unwrap_or("").to_string()),
            prefix: Some(run_ok(&["brew", "--prefix"]).trim().to_string()),
            taps: Some(taps),
            packages: pkgs,
            ..Default::default()
        })
    }

    fn prepare(&self, section: &Section, _src: &Platform, _dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("brew (prepare)");
        let have: BTreeSet<String> = if has("brew") {
            run_ok(&["brew", "tap"]).split_whitespace().map(String::from).collect()
        } else {
            BTreeSet::new()
        };
        for t in section.taps.iter().flatten() {
            let name = vstr(t, "name");
            if name.is_empty()
                || OFFICIAL_TAPS.contains(&name)
                || name == PIN_TAP
                || name == LEGACY_PIN_TAP
                || have.contains(name)
            {
                continue;
            }
            let mut argv = vec!["brew".to_string(), "tap".into(), name.into()];
            if t.get("customRemote").and_then(Value::as_bool).unwrap_or(false) && !vstr(t, "remote").is_empty() {
                argv.push(vstr(t, "remote").into());
            }
            plan.add(Step::cmd(format!("tap {name}"), argv));
        }
        if opts.refresh {
            plan.add(Step::cmd("refresh Homebrew metadata", ["brew", "update"]));
        }
        Ok(plan)
    }

    fn plan(&self, section: &Section, _src: &Platform, dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("brew");
        if is_root() {
            bail!("Homebrew refuses to run as root; apply the brew part as your normal user (matsya apply --managers brew)");
        }
        let pkgs = &section.packages;
        let formulae: Vec<&Package> = pkgs.iter().filter(|p| p.kind() == "formula" && p.is_manual()).collect();
        let casks: Vec<&Package> = pkgs.iter().filter(|p| p.kind() == "cask").collect();
        let cur_f = self.current(&formulae.iter().map(|p| p.name.clone()).collect::<Vec<_>>(), false);
        let cur_c = self.current(&casks.iter().map(|p| p.name.clone()).collect::<Vec<_>>(), true);
        let installed = self.installed(dst)?;
        let current: HashMap<String, &Package> = installed.iter().map(|p| (self.key_of(p, dst), p)).collect();

        let (mut install, mut extract, mut cask_install, mut pins) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for p in &formulae {
            let (name, ver) = (&p.name, &p.version);
            let cur = cur_f.get(name);
            let have = current.get(&self.key_of(p, dst));
            let extracted = have.is_some_and(|h| {
                h.name.starts_with(&format!("{PIN_TAP}/")) || h.name.starts_with(&format!("{LEGACY_PIN_TAP}/"))
            });
            // The formula name that ends up providing it (for pinning).
            let mut target: Option<String> = None;
            if let Some(h) = have.filter(|h| &h.version == ver || (extracted && plain(&h.version) == plain(ver))) {
                target = Some(h.name.clone());
            } else if cur.is_some_and(|c| c.1.contains(ver)) {
                target = Some(name.clone());
            } else if cur.is_some_and(|c| &c.0 == ver) {
                install.push(name.clone());
                target = Some(name.clone());
            } else if cur.is_some() && opts.snapshot {
                extract.push((name.clone(), ver.clone()));
                target = Some(format!("{PIN_TAP}/{}@{}", name.rsplit('/').next().unwrap_or(name), plain(ver)));
            } else if opts.best_effort {
                plan.warnings.push(format!("{name} {ver} unavailable; installing current version"));
                install.push(name.clone());
                target = Some(name.clone());
            } else {
                let why = if cur.is_none() { "formula not found" } else { "version is no longer current" };
                plan.unresolved.push(format!("{name}@{ver} ({why})"));
            }
            if let Some(t) = target {
                if Package::flag(&p.pinned) && !have.is_some_and(|h| Package::flag(&h.pinned)) {
                    pins.push(t);
                }
            }
        }
        for p in &casks {
            let (name, ver) = (&p.name, &p.version);
            match cur_c.get(name) {
                Some(c) if c.1.contains(ver) => {}
                Some(c) if &c.0 == ver || opts.best_effort => {
                    if &c.0 != ver {
                        plan.warnings
                            .push(format!("cask {name}: locked {ver}, installing {} (casks cannot be pinned)", c.0));
                    }
                    cask_install.push(name.clone());
                }
                _ => plan.unresolved.push(format!("cask {name}@{ver} (Homebrew cannot install old cask versions)")),
            }
        }
        install.sort();
        cask_install.sort();
        pins.sort();
        let n_install = install.len() + extract.len() + cask_install.len();
        if !install.is_empty() {
            let n = install.len();
            plan.add(Step::cmd(
                format!("install {n} formula(e)"),
                ["brew", "install", "--formula"].map(String::from).into_iter().chain(install),
            ));
        }
        if !extract.is_empty() {
            plan.warnings.push(
                "older formula versions are rebuilt from homebrew-core history with `brew extract`; this needs a full homebrew/core clone and usually compiles from source".into(),
            );
            plan.add(Step::cmd(
                "local tap for extracted versions",
                ["sh", "-c", &format!("brew tap | grep -qx {PIN_TAP} || brew tap-new --no-git {PIN_TAP}")],
            ));
            plan.add(
                Step::cmd(
                    "homebrew-core history is needed for brew extract",
                    ["sh", "-c", "brew tap | grep -qx homebrew/core || brew tap --force homebrew/core"],
                )
                .with_env("HOMEBREW_NO_INSTALL_FROM_API", "1"),
            );
            for (name, ver) in &extract {
                let short = name.rsplit('/').next().unwrap_or(name);
                plan.add(Step::cmd(
                    format!("recreate {name} {ver}"),
                    ["brew", "extract", "--force", &format!("--version={}", plain(ver)), name, PIN_TAP],
                ));
                plan.add(Step::cmd(
                    "",
                    ["brew".to_string(), "install".into(), format!("{PIN_TAP}/{short}@{}", plain(ver))],
                ));
            }
        }
        if !cask_install.is_empty() {
            let n = cask_install.len();
            plan.add(Step::cmd(
                format!("install {n} cask(s)"),
                ["brew", "install", "--cask"].map(String::from).into_iter().chain(cask_install),
            ));
        }
        if !pins.is_empty() {
            plan.add(Step::cmd("restore pins", ["brew".to_string(), "pin".into()].into_iter().chain(pins)));
        }
        if opts.prune {
            let locked: BTreeSet<String> = pkgs.iter().map(|p| self.key_of(p, dst)).collect();
            let extra: BTreeSet<String> = current
                .iter()
                .filter(|(k, p)| p.is_manual() && !locked.contains(*k))
                .map(|(_, p)| p.name.clone())
                .collect();
            if !extra.is_empty() {
                let n = extra.len();
                plan.add(Step::cmd(
                    format!("remove {n} package(s) not in the lock"),
                    ["brew".to_string(), "uninstall".into()].into_iter().chain(extra),
                ));
                plan.add(Step::cmd("remove orphaned dependencies", ["brew", "autoremove"]));
            }
        }
        let deps = pkgs.iter().filter(|p| p.kind() == "formula" && !p.is_manual()).count();
        if deps > 0 {
            plan.warnings.push(format!(
                "{deps} dependency formula(e) are installed at whatever version their dependants need; `matsya check` reports any drift afterwards"
            ));
        }
        plan.summary = vec![("install".into(), n_install), ("unresolved".into(), plan.unresolved.len())];
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkgs() -> Vec<Package> {
        let text =
            std::fs::read_to_string(format!("{}/tests/fixtures/brew-info.json", env!("CARGO_MANIFEST_DIR"))).unwrap();
        parse_info(&serde_json::from_str(&text).unwrap())
    }

    #[test]
    fn formulae() {
        let p = pkgs();
        let by = |n: &str| p.iter().find(|x| x.name == n).unwrap().clone();
        let jq = by("jq");
        assert_eq!(jq.reason(), "manual");
        assert!(jq.bottles.as_ref().unwrap().contains_key("arm64_sequoia"));
        assert_eq!(jq.dependencies, vec!["oniguruma"]);
        let onig = by("oniguruma");
        assert_eq!(onig.reason(), "dependency");
        assert_eq!(onig.other_kegs, vec!["6.9.8"]);
        let tool = by("acme/tools/mytool");
        assert_eq!(tool.outdated, Some(true));
        assert!(tool.bottles.is_none());
        assert_eq!(tool.built_from_source, Some(true));
        assert_eq!(tool.pinned, Some(true));
    }

    #[test]
    fn casks() {
        let p = pkgs();
        let casks: Vec<&Package> = p.iter().filter(|x| x.kind() == "cask").collect();
        assert_eq!(casks.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), vec!["firefox", "google-chrome"]);
        assert!(casks[0].sha256.is_some());
        assert!(casks[1].sha256.is_none()); // no_check
        assert_eq!(casks[1].auto_updates, Some(true));
    }

    #[test]
    fn tags_and_keys() {
        let mac = |arch: &str, code: &str| Platform {
            os: Some("macos".into()),
            arch: Some(arch.into()),
            codename: Some(code.into()),
            ..Default::default()
        };
        assert_eq!(bottle_tag(&mac("aarch64", "sequoia")), "arm64_sequoia");
        assert_eq!(bottle_tag(&mac("x86_64", "sonoma")), "sonoma");
        assert_eq!(
            bottle_tag(&Platform { os: Some("linux".into()), arch: Some("x86_64".into()), ..Default::default() }),
            "x86_64_linux"
        );
        let k = |n: &str, kind: &str| {
            let mut p = Package::new(n, "1");
            p.kind = Some(kind.into());
            Brew.key_of(&p, &Platform::default())
        };
        assert_eq!(k("matsya/pins/jq@1.7.1", "formula"), "jq");
        assert_eq!(k("syslock/pins/jq@1.7.1", "formula"), "jq");
        assert_eq!(k("matsya/pins/postgresql@16@16.4", "formula"), "postgresql@16");
        assert_eq!(k("python@3.12", "formula"), "python@3.12");
        assert_eq!(k("firefox", "cask"), "cask:firefox");
    }

    #[test]
    fn brewfile() {
        let sec = Section {
            taps: Some(vec![json!({"name": "acme/tools"}), json!({"name": "homebrew/core"})]),
            packages: pkgs(),
            ..Default::default()
        };
        let text = export_brewfile(&sec);
        assert!(text.contains("tap \"acme/tools\""));
        assert!(!text.contains("homebrew/core"));
        assert!(text.contains("brew \"jq\""));
        assert!(!text.contains("brew \"oniguruma\""));
        assert!(text.contains("cask \"firefox\""));
    }
}
