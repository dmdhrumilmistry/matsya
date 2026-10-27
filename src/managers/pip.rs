//! Python packages installed with pip (and pipx apps), outside the system
//! package manager. Read from `*.dist-info` directories:
//!
//! * `METADATA`: name, version, license, `Requires-Dist`
//! * `INSTALLER`: who installed it; distro-owned ones (`debian`, `rpm`, ...)
//!   are left to the system package manager section
//! * `REQUESTED`: present when the user asked for it (vs. a dependency)
//! * `direct_url.json`: VCS / URL / editable installs

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::eco::{by_kind, entries_with_prefix, extra_str, scope_allowed, set_extra, subdirs, tilde, user_home, Scope};
use super::{resolve_dependencies, Manager, Options, RootPolicy};
use crate::model::{Package, Section};
use crate::plan::{Plan, Step};
use crate::platform::Platform;
use crate::util::{has, read_text_opt, Result};

/// INSTALLER values written by distribution package builds.
const DISTRO_INSTALLERS: &[&str] = &["debian", "rpm", "dnf", "yum", "apk", "pacman", "conda", "spack", "nix", "brew"];

/// PEP 503 name normalisation.
pub fn normalize(name: &str) -> String {
    let mut out = String::new();
    let mut sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// A site-packages directory and what it belongs to.
#[derive(Debug, Clone)]
pub struct Site {
    pub dir: PathBuf,
    /// "python3.12"
    pub python: String,
    pub scope: Scope,
}

impl Site {
    pub fn kind(&self) -> String {
        format!("{}/{}", self.python, self.scope.label())
    }
}

/// All site-packages directories pip may have installed into.
pub fn sites() -> Vec<Site> {
    let mut out = Vec::new();
    let mut add = |dir: PathBuf, python: String, scope: Scope| {
        if dir.is_dir() && !out.iter().any(|s: &Site| s.dir == dir) {
            out.push(Site { dir, python, scope });
        }
    };
    let pys = |base: &Path| -> Vec<(PathBuf, String)> {
        entries_with_prefix(base, "python3.")
            .into_iter()
            .filter_map(|p| Some((p.clone(), p.file_name()?.to_string_lossy().into_owned())))
            .collect()
    };
    let mut system_bases = vec![
        PathBuf::from("/usr/local/lib"),
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/lib64"),
        PathBuf::from("/opt/homebrew/lib"),
    ];
    if let Some(p) = crate::platform::termux_prefix() {
        system_bases.push(p.join("lib"));
    }
    for base in system_bases {
        for (dir, py) in pys(&base) {
            for sub in ["site-packages", "dist-packages"] {
                add(dir.join(sub), py.clone(), Scope::System);
            }
        }
    }
    // python.org installers on macOS
    for v in entries_with_prefix(Path::new("/Library/Frameworks/Python.framework/Versions"), "3.") {
        let ver = v.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        add(v.join(format!("lib/python{ver}/site-packages")), format!("python{ver}"), Scope::System);
    }
    if let Some(home) = user_home() {
        for (dir, py) in pys(&home.join(".local/lib")) {
            add(dir.join("site-packages"), py, Scope::User);
        }
        for v in entries_with_prefix(&home.join("Library/Python"), "3.") {
            let ver = v.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            add(v.join("lib/python/site-packages"), format!("python{ver}"), Scope::User);
        }
    }
    out
}

/// The headers of a METADATA file (email-style, stops at the body).
pub fn parse_metadata(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = out.last_mut() {
                last.1.push('\n');
                last.1.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

/// Name of a `Requires-Dist` entry, or None when it only applies to an extra.
pub fn requirement_name(req: &str) -> Option<String> {
    let (spec, marker) = req.split_once(';').map(|(a, b)| (a, Some(b))).unwrap_or((req, None));
    if marker.is_some_and(|m| m.contains("extra")) {
        return None;
    }
    let name: String =
        spec.trim().chars().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')).collect();
    (!name.is_empty()).then(|| normalize(&name))
}

fn license_of(headers: &[(String, String)]) -> Option<String> {
    let get = |k: &str| headers.iter().find(|(h, _)| h.eq_ignore_ascii_case(k)).map(|(_, v)| v.clone());
    if let Some(l) = get("License-Expression").filter(|l| !l.is_empty()) {
        return Some(l);
    }
    if let Some(l) = get("License").map(|l| l.lines().next().unwrap_or("").trim().to_string()) {
        if !l.is_empty() && l.len() <= 80 && !l.eq_ignore_ascii_case("UNKNOWN") {
            return Some(l);
        }
    }
    headers
        .iter()
        .filter(|(h, _)| h == "Classifier")
        .find_map(|(_, v)| v.strip_prefix("License :: OSI Approved :: ").map(|l| l.to_string()))
}

/// One installed distribution from its dist-info directory, or None when a
/// distro package owns it.
pub fn read_dist_info(dir: &Path, kind: &str, location: &str) -> Option<(Package, Vec<String>)> {
    let installer = read_text_opt(dir.join("INSTALLER")).map(|s| s.trim().to_ascii_lowercase()).unwrap_or_default();
    if installer.is_empty() || DISTRO_INSTALLERS.contains(&installer.as_str()) {
        return None;
    }
    let headers = parse_metadata(&read_text_opt(dir.join("METADATA"))?);
    let get = |k: &str| headers.iter().find(|(h, _)| h.eq_ignore_ascii_case(k)).map(|(_, v)| v.clone());
    let mut p = Package::new(get("Name")?, get("Version")?);
    p.kind = Some(kind.into());
    p.reason = Some(if dir.join("REQUESTED").exists() { "manual" } else { "dependency" }.into());
    if let Some(l) = license_of(&headers) {
        p.licenses = vec![l];
    }
    set_extra(&mut p, "location", location);
    if installer != "pip" {
        set_extra(&mut p, "installer", installer);
    }
    if let Some(du) = read_text_opt(dir.join("direct_url.json")).and_then(|t| serde_json::from_str::<Value>(&t).ok()) {
        let url = du.get("url").and_then(Value::as_str).unwrap_or("").to_string();
        if du.pointer("/dir_info/editable").and_then(Value::as_bool) == Some(true) {
            set_extra(&mut p, "editable", true);
        }
        if let Some(vcs) = du.get("vcs_info") {
            let kind = vcs.get("vcs").and_then(Value::as_str).unwrap_or("git");
            let commit = vcs.get("commit_id").and_then(Value::as_str).unwrap_or("");
            set_extra(&mut p, "from", format!("{kind}+{url}@{commit}"));
        } else if !url.is_empty() && !url.starts_with("file:") {
            set_extra(&mut p, "from", url);
        }
        if let Some(sha) = du.pointer("/archive_info/hashes/sha256").and_then(Value::as_str) {
            p.sha256 = Some(sha.to_string());
        }
    }
    let deps = headers
        .iter()
        .filter(|(h, _)| h.eq_ignore_ascii_case("Requires-Dist"))
        .filter_map(|(_, v)| requirement_name(v))
        .collect();
    Some((p, deps))
}

/// pipx apps: one venv per app, described by pipx_metadata.json.
pub fn pipx_apps() -> Vec<Package> {
    let Some(home) = user_home() else { return vec![] };
    let mut out = Vec::new();
    for root in [home.join(".local/share/pipx/venvs"), home.join(".local/pipx/venvs")] {
        for venv in subdirs(&root) {
            let Some(meta) =
                read_text_opt(venv.join("pipx_metadata.json")).and_then(|t| serde_json::from_str::<Value>(&t).ok())
            else {
                continue;
            };
            let main = &meta["main_package"];
            let (Some(name), Some(ver)) =
                (main.get("package").and_then(Value::as_str), main.get("package_version").and_then(Value::as_str))
            else {
                continue;
            };
            let mut p = Package::new(name, ver);
            p.kind = Some("pipx".into());
            p.reason = Some("manual".into());
            set_extra(&mut p, "location", tilde(&venv));
            let spec = main.get("package_or_url").and_then(Value::as_str).unwrap_or("");
            if spec.contains("://") || spec.starts_with("git+") {
                set_extra(&mut p, "from", spec);
            }
            let injected: BTreeSet<String> = meta
                .get("injected_packages")
                .and_then(Value::as_object)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            if !injected.is_empty() {
                set_extra(&mut p, "injected", json!(injected));
            }
            out.push(p);
        }
    }
    out
}

pub fn scan() -> Vec<Package> {
    let mut pkgs: Vec<Package> = Vec::new();
    let mut keys = Vec::new();
    let mut requires: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    let mut by_name: HashMap<(String, String), String> = HashMap::new();
    for site in sites() {
        let kind = site.kind();
        let location = tilde(&site.dir);
        for d in entries_with_prefix(&site.dir, "") {
            if !d.to_string_lossy().ends_with(".dist-info") {
                continue;
            }
            let Some((p, deps)) = read_dist_info(&d, &kind, &location) else { continue };
            let key = key(&p);
            if keys.contains(&key) {
                continue;
            }
            by_name.insert((kind.clone(), normalize(&p.name)), key.clone());
            requires.insert(key.clone(), deps.into_iter().map(|d| vec![format!("{kind}:{d}")]).collect());
            keys.push(key);
            pkgs.push(p);
        }
    }
    // Dependencies resolve within the same interpreter and scope; a user
    // package may also depend on a system one of the same Python.
    let mut provides: HashMap<String, Vec<String>> = HashMap::new();
    for (k, p) in keys.iter().zip(&pkgs) {
        provides.entry(k.clone()).or_default().push(format!("{}:{}", p.kind(), normalize(&p.name)));
        if let Some(py) = p.kind().strip_suffix("/system") {
            provides.entry(k.clone()).or_default().push(format!("{py}/user:{}", normalize(&p.name)));
        }
    }
    resolve_dependencies(&mut pkgs, &keys, &requires, &provides);
    pkgs.extend(pipx_apps());
    pkgs.sort_by_key(key);
    pkgs
}

fn key(p: &Package) -> String {
    format!("{}:{}", p.kind(), normalize(&p.name))
}

pub struct Pip;

impl Manager for Pip {
    fn name(&self) -> &'static str {
        "pip"
    }

    fn root_policy(&self) -> RootPolicy {
        RootPolicy::PerPackage
    }

    fn optional(&self) -> bool {
        true
    }

    fn available(&self) -> bool {
        !sites().is_empty() || has("pipx")
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
        Ok(Section { tool: Some("pip (dist-info)".into()), packages: pkgs, ..Default::default() })
    }

    fn plan(&self, section: &Section, _src: &Platform, _dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("pip");
        let installed = scan();
        let current: HashMap<String, &Package> = installed.iter().map(|p| (key(p), p)).collect();
        let mut n = 0;
        for (kind, pkgs) in by_kind(section.packages.iter()) {
            let scope = Scope::of(pkgs[0]);
            let todo: Vec<&Package> = pkgs
                .iter()
                .copied()
                .filter(|p| !opts.roots_only || p.is_manual())
                .filter(|p| current.get(&key(p)).map(|c| &c.version) != Some(&p.version))
                .collect();
            if todo.is_empty() || !scope_allowed(scope, &format!("Python packages ({kind})"), &mut plan) {
                continue;
            }
            if kind == "pipx" {
                if !has("pipx") {
                    plan.unresolved.push("pipx apps (pipx is not installed)".into());
                    continue;
                }
                for p in todo {
                    let spec =
                        extra_str(p, "from").map(String::from).unwrap_or_else(|| format!("{}=={}", p.name, p.version));
                    plan.add(Step::cmd(
                        format!("pipx app {} {}", p.name, p.version),
                        ["pipx", "install", "--force", &spec],
                    ));
                    n += 1;
                }
                continue;
            }
            let python = kind.split('/').next().unwrap_or("python3").to_string();
            if !has(&python) {
                plan.unresolved.push(format!("{} package(s) for {python} ({python} is not installed)", todo.len()));
                continue;
            }
            let mut specs = Vec::new();
            for p in &todo {
                if p.extra.contains_key("editable") {
                    plan.warnings
                        .push(format!("{} is an editable install; reinstall it from its source checkout", p.name));
                    continue;
                }
                specs.push(match extra_str(p, "from") {
                    Some(src) => format!("{} @ {src}", p.name),
                    None => format!("{}=={}", p.name, p.version),
                });
            }
            if specs.is_empty() {
                continue;
            }
            specs.sort();
            let mut argv: Vec<String> =
                [python.as_str(), "-m", "pip", "install", "--no-input"].map(String::from).to_vec();
            if scope == Scope::User {
                argv.push("--user".into());
            }
            // PEP 668: pip refuses to touch a distro-managed Python without this.
            let ver = python.trim_start_matches("python");
            let managed = [
                format!("/usr/lib/python{ver}/EXTERNALLY-MANAGED"),
                format!("/usr/local/lib/python{ver}/EXTERNALLY-MANAGED"),
            ];
            if managed.iter().any(|m| Path::new(m).exists()) {
                argv.push("--break-system-packages".into());
            }
            n += specs.len();
            let count = specs.len();
            argv.extend(specs);
            plan.add(Step::cmd(format!("install {count} Python package(s) for {kind}"), argv));
        }
        if opts.prune {
            let locked: BTreeSet<String> = section.packages.iter().map(key).collect();
            for (kind, pkgs) in by_kind(installed.iter().filter(|p| p.is_manual() && !locked.contains(&key(p)))) {
                let scope = Scope::of(pkgs[0]);
                if kind == "pipx" || !scope_allowed(scope, &format!("Python packages ({kind})"), &mut plan) {
                    continue;
                }
                let python = kind.split('/').next().unwrap_or("python3").to_string();
                let mut argv: Vec<String> =
                    [python.as_str(), "-m", "pip", "uninstall", "-y"].map(String::from).to_vec();
                argv.extend(pkgs.iter().map(|p| p.name.clone()));
                plan.add(Step::cmd(format!("remove {} Python package(s) not in the lock", pkgs.len()), argv));
            }
        }
        plan.summary = vec![("install".into(), n), ("unresolved".into(), plan.unresolved.len())];
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dist(root: &Path, name: &str, files: &[(&str, &str)]) {
        let d = root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        for (f, c) in files {
            std::fs::write(d.join(f), c).unwrap();
        }
    }

    #[test]
    fn names_and_requirements() {
        assert_eq!(normalize("Foo_Bar.baz"), "foo-bar-baz");
        assert_eq!(requirement_name("requests (>=2.0)"), Some("requests".into()));
        assert_eq!(requirement_name("PySocks!=1.5.7,>=1.5.6; extra == 'socks'"), None);
        assert_eq!(requirement_name("idna<4,>=2.5"), Some("idna".into()));
        assert_eq!(requirement_name("typing_extensions; python_version < '3.11'"), Some("typing-extensions".into()));
    }

    #[test]
    fn reads_dist_info() {
        let root = std::env::temp_dir().join(format!("matsya-pip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        dist(&root, "requests-2.32.3.dist-info", &[
            ("INSTALLER", "pip\n"),
            ("REQUESTED", ""),
            ("METADATA", "Metadata-Version: 2.1\nName: requests\nVersion: 2.32.3\nLicense: Apache-2.0\nRequires-Dist: idna<4,>=2.5\nRequires-Dist: PySocks!=1.5.7; extra == \"socks\"\n\nbody text\n"),
        ]);
        dist(
            &root,
            "idna-3.7.dist-info",
            &[
                ("INSTALLER", "pip"),
                ("METADATA", "Name: idna\nVersion: 3.7\nClassifier: License :: OSI Approved :: BSD License\n"),
            ],
        );
        dist(
            &root,
            "attrs-25.4.0.dist-info",
            &[("INSTALLER", "debian"), ("METADATA", "Name: attrs\nVersion: 25.4.0\n")],
        );
        dist(
            &root,
            "tool-1.0.dist-info",
            &[
                ("INSTALLER", "uv"),
                ("METADATA", "Name: tool\nVersion: 1.0\n"),
                (
                    "direct_url.json",
                    r#"{"url": "https://github.com/acme/tool", "vcs_info": {"vcs": "git", "commit_id": "abc123"}}"#,
                ),
            ],
        );
        let (req, deps) = read_dist_info(&root.join("requests-2.32.3.dist-info"), "python3.12/user", "~/x").unwrap();
        assert_eq!((req.name.as_str(), req.version.as_str(), req.reason()), ("requests", "2.32.3", "manual"));
        assert_eq!(req.licenses, vec!["Apache-2.0"]);
        assert_eq!(deps, vec!["idna"]); // the extra-only dependency is skipped
        let (idna, _) = read_dist_info(&root.join("idna-3.7.dist-info"), "python3.12/user", "~/x").unwrap();
        assert_eq!((idna.reason(), idna.licenses[0].as_str()), ("dependency", "BSD License"));
        assert!(read_dist_info(&root.join("attrs-25.4.0.dist-info"), "k", "l").is_none()); // distro-owned
        let (tool, _) = read_dist_info(&root.join("tool-1.0.dist-info"), "k", "l").unwrap();
        assert_eq!(extra_str(&tool, "from"), Some("git+https://github.com/acme/tool@abc123"));
        assert_eq!(extra_str(&tool, "installer"), Some("uv"));
        let _ = std::fs::remove_dir_all(root);
    }
}
