//! Homebrew (macOS and Linux) backend, read straight from disk.
//!
//! Nothing here runs `brew` except `apply`, which has to install things.
//! The installed state comes from:
//!
//! * `Cellar/<name>/<version>/INSTALL_RECEIPT.json` (install reason, tap,
//!   runtime dependencies, bottle vs source build)
//! * `var/homebrew/linked` and `var/homebrew/pinned` (active keg, pins)
//! * `Caskroom/<token>/.metadata/INSTALL_RECEIPT.json` (casks)
//! * `Library/Taps/<user>/homebrew-<repo>/.git` (taps, remotes, commits)
//! * the API cache (`api/internal/packages.<tag>.jws.json` on Homebrew 5+,
//!   `api/formula.jws.json` before) for licenses, current versions and the
//!   bottle checksum.
//!
//! Homebrew keeps no repository of old versions. A version that is no
//! longer current is rebuilt with `brew extract` from homebrew-core's git
//! history into a local tap (usually compiles from source).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{Manager, Options};
use crate::bail;
use crate::model::{vstr, Package, Section};
use crate::plan::{Plan, Step};
use crate::platform::Platform;
use crate::util::{is_root, read_text_opt, warn, which, Result};

pub const PIN_TAP: &str = "matsya/pins";
/// Tap used by the Python implementation for extracted versions.
const LEGACY_PIN_TAP: &str = "syslock/pins";
const OFFICIAL_TAPS: &[&str] = &["homebrew/core", "homebrew/cask"];

/// 1.2.3_1 -> 1.2.3 (drop the Homebrew revision suffix).
pub fn plain(version: &str) -> &str {
    version.rsplit_once('_').map(|(a, _)| a).unwrap_or(version)
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

/// Where Homebrew lives on this machine.
#[derive(Debug, Clone)]
pub struct Layout {
    pub prefix: PathBuf,
    /// The git checkout of Homebrew itself (`brew --repo`).
    pub repo: PathBuf,
    pub cache: PathBuf,
}

impl Layout {
    pub fn detect() -> Option<Layout> {
        let prefix = std::env::var_os("HOMEBREW_PREFIX")
            .map(PathBuf::from)
            .or_else(|| {
                // The `brew` on PATH sits in <prefix>/bin.
                which("brew").and_then(|b| Path::new(&b).parent()?.parent().map(Path::to_path_buf))
            })
            .filter(|p| p.join("Cellar").is_dir())
            .or_else(|| {
                let mut c = vec![
                    PathBuf::from("/opt/homebrew"),
                    PathBuf::from("/usr/local"),
                    PathBuf::from("/home/linuxbrew/.linuxbrew"),
                ];
                if let Some(h) = std::env::var_os("HOME") {
                    c.push(Path::new(&h).join(".linuxbrew"));
                }
                c.into_iter().find(|p| p.join("Cellar").is_dir())
            })?;
        let repo = std::env::var_os("HOMEBREW_REPOSITORY").map(PathBuf::from).unwrap_or_else(|| {
            if prefix.join("Homebrew/.git").exists() {
                prefix.join("Homebrew")
            } else {
                prefix.clone()
            }
        });
        let cache = std::env::var_os("HOMEBREW_CACHE").map(PathBuf::from).unwrap_or_else(|| {
            let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
            if cfg!(target_os = "macos") {
                home.join("Library/Caches/Homebrew")
            } else {
                std::env::var_os("XDG_CACHE_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| home.join(".cache"))
                    .join("Homebrew")
            }
        });
        Some(Layout { prefix, repo, cache })
    }
}

/// What the API cache says about one formula or cask.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApiEntry {
    /// Version brew would install now (pkg_version: stable + _revision).
    pub version: String,
    pub license: Option<String>,
    /// bottle tag -> sha256
    pub bottles: BTreeMap<String, String>,
    pub sha256: Option<String>,
    pub url: Option<String>,
    pub auto_updates: bool,
}

#[derive(Debug, Default)]
pub struct Api {
    pub formulae: HashMap<String, ApiEntry>,
    pub casks: HashMap<String, ApiEntry>,
}

fn with_revision(stable: &str, rev: i64) -> String {
    if rev > 0 {
        format!("{stable}_{rev}")
    } else {
        stable.to_string()
    }
}

/// Parse the API cache. Homebrew 5+ ("internal" API) stores one compact
/// payload per bottle tag; older releases store the full formula JSON.
pub fn parse_api(payload: &Value, tag: &str) -> Api {
    let mut api = Api::default();
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(String::from);
    // Internal format: {"metadata": {"bottle_tag"}, "formulae": {name: {...}}, "casks": {...}}
    if let Some(formulae) = payload.get("formulae").and_then(Value::as_object) {
        let tag = payload.pointer("/metadata/bottle_tag").and_then(Value::as_str).unwrap_or(tag).to_string();
        for (name, f) in formulae {
            let mut e = ApiEntry {
                version: with_revision(
                    &s(f, "stable_version").unwrap_or_default(),
                    f.get("revision").and_then(Value::as_i64).unwrap_or(0),
                ),
                license: s(f, "license"),
                ..Default::default()
            };
            if let Some(sum) = s(f, "bottle_checksum") {
                e.bottles.insert(tag.clone(), sum);
            }
            api.formulae.insert(name.clone(), e);
        }
        for (token, c) in payload.get("casks").and_then(Value::as_object).into_iter().flatten() {
            api.casks.insert(token.clone(), cask_entry(c));
        }
        return api;
    }
    // Classic format: [{"name", "versions": {"stable"}, "revision", "bottle": {"stable": {"files"}}}]
    for f in payload.as_array().into_iter().flatten() {
        if let Some(token) = s(f, "token") {
            api.casks.insert(token, cask_entry(f));
            continue;
        }
        let Some(name) = s(f, "name") else { continue };
        let stable = f.pointer("/versions/stable").and_then(Value::as_str).unwrap_or("");
        let mut e = ApiEntry {
            version: with_revision(stable, f.get("revision").and_then(Value::as_i64).unwrap_or(0)),
            license: s(f, "license"),
            ..Default::default()
        };
        for (t, file) in f.pointer("/bottle/stable/files").and_then(Value::as_object).into_iter().flatten() {
            if let Some(sum) = s(file, "sha256") {
                e.bottles.insert(t.clone(), sum);
            }
        }
        api.formulae.insert(name, e);
    }
    api
}

fn cask_entry(c: &Value) -> ApiEntry {
    let url = c.get("url").and_then(Value::as_str).map(String::from).or_else(|| {
        c.get("url_args").and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str).map(String::from)
    });
    ApiEntry {
        version: c.get("version").and_then(Value::as_str).unwrap_or("").to_string(),
        sha256: c.get("sha256").and_then(Value::as_str).filter(|x| *x != "no_check").map(String::from),
        url,
        auto_updates: c.get("auto_updates").and_then(Value::as_bool).unwrap_or(false),
        ..Default::default()
    }
}

/// A JWS file wraps its JSON in a string "payload"; `.payload` files hold it raw.
fn read_payload(path: &Path) -> Option<Value> {
    if let Some(text) = read_text_opt(format!("{}.payload", path.display())) {
        if let Ok(v) = serde_json::from_str(&text) {
            return Some(v);
        }
    }
    let outer: Value = serde_json::from_str(&read_text_opt(path)?).ok()?;
    match outer.get("payload") {
        Some(Value::String(p)) => serde_json::from_str(p).ok(),
        _ => Some(outer),
    }
}

pub fn load_api(cache: &Path, tag: &str) -> Api {
    let internal = cache.join("api/internal");
    let mut candidates = vec![internal.join(format!("packages.{tag}.jws.json"))];
    // Any other platform's file still has versions and licenses.
    let mut others: Vec<PathBuf> = std::fs::read_dir(&internal)
        .map(|d| d.flatten().map(|e| e.path()).filter(|p| p.to_string_lossy().ends_with(".jws.json")).collect())
        .unwrap_or_default();
    others.sort();
    candidates.extend(others);
    for c in candidates {
        if let Some(v) = read_payload(&c) {
            return parse_api(&v, tag);
        }
    }
    let mut api = Api::default();
    for f in ["api/formula.jws.json", "api/cask.jws.json"] {
        if let Some(v) = read_payload(&cache.join(f)) {
            let part = parse_api(&v, tag);
            api.formulae.extend(part.formulae);
            api.casks.extend(part.casks);
        }
    }
    api
}

fn json_file(path: &Path) -> Option<Value> {
    serde_json::from_str(&read_text_opt(path)?).ok()
}

fn link_target(path: &Path) -> Option<String> {
    std::fs::read_link(path).ok()?.file_name().map(|s| s.to_string_lossy().into_owned())
}

fn sorted_dirs(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|d| d.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn file_name(p: &Path) -> String {
    p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Installed formulae and casks.
pub fn scan(layout: &Layout, api: &Api) -> Vec<Package> {
    let mut pkgs = Vec::new();
    for dir in sorted_dirs(&layout.prefix.join("Cellar")) {
        let name = file_name(&dir);
        let kegs: Vec<(String, Value)> = sorted_dirs(&dir)
            .into_iter()
            .filter_map(|k| Some((file_name(&k), json_file(&k.join("INSTALL_RECEIPT.json"))?)))
            .collect();
        let Some(last) = kegs.last() else { continue }; // no receipt: not a real keg
                                                        // Several kegs can be installed; the linked one is what is in use.
        let linked = link_target(&layout.prefix.join("var/homebrew/linked").join(&name))
            .or_else(|| link_target(&layout.prefix.join("opt").join(&name)));
        let (version, receipt) = kegs.iter().find(|(v, _)| Some(v) == linked.as_ref()).unwrap_or(last).clone();
        let tap = receipt
            .pointer("/source/tap")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .unwrap_or("homebrew/core")
            .to_string();
        let full = if tap == "homebrew/core" { name.clone() } else { format!("{tap}/{name}") };
        let mut p = Package::new(full, version.clone());
        p.kind = Some("formula".into());
        p.tap = Some(tap.clone());
        let on_request = receipt.get("installed_on_request").and_then(Value::as_bool).unwrap_or(false);
        p.reason = Some(if on_request { "manual" } else { "dependency" }.into());
        if layout.prefix.join("var/homebrew/pinned").join(&name).exists() {
            p.pinned = Some(true);
        }
        if !receipt.get("poured_from_bottle").and_then(Value::as_bool).unwrap_or(false) {
            p.built_from_source = Some(true);
        }
        if kegs.len() > 1 {
            p.other_kegs = kegs.iter().map(|k| k.0.clone()).filter(|v| *v != version).collect();
        }
        let deps: BTreeSet<String> = receipt
            .get("runtime_dependencies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|d| d.get("full_name").and_then(Value::as_str).map(String::from))
            .collect();
        p.dependencies = deps.into_iter().collect();
        let entry = api.formulae.get(&name).filter(|_| tap == "homebrew/core");
        let license = entry.and_then(|e| e.license.clone()).or_else(|| keg_sbom_license(&dir.join(&version), &name));
        if let Some(l) = license {
            p.licenses = vec![l];
        }
        match entry {
            Some(e) if e.version == version => {
                if !e.bottles.is_empty() {
                    p.bottles = Some(e.bottles.clone());
                }
            }
            // The formula has moved on; bottle hashes would describe another version.
            Some(_) => p.outdated = Some(true),
            None => {}
        }
        pkgs.push(p);
    }
    for dir in sorted_dirs(&layout.prefix.join("Caskroom")) {
        let token = file_name(&dir);
        let receipt = json_file(&dir.join(".metadata/INSTALL_RECEIPT.json"));
        let version = receipt
            .as_ref()
            .and_then(|r| r.pointer("/source/version").and_then(Value::as_str).map(String::from))
            .or_else(|| sorted_dirs(&dir).iter().map(|d| file_name(d)).rfind(|n| !n.starts_with('.')));
        let Some(version) = version else { continue };
        let tap = receipt
            .as_ref()
            .and_then(|r| r.pointer("/source/tap").and_then(Value::as_str))
            .unwrap_or("homebrew/cask")
            .to_string();
        let name = if tap == "homebrew/cask" { token.clone() } else { format!("{tap}/{token}") };
        let mut p = Package::new(name, version.clone());
        p.kind = Some("cask".into());
        p.tap = Some(tap);
        p.reason = Some("manual".into());
        if let Some(e) = api.casks.get(&token) {
            if e.version == version {
                p.sha256 = e.sha256.clone();
                p.url = e.url.clone().filter(|_| e.sha256.is_some());
            }
            if e.auto_updates {
                // The app updates itself; the installed version can drift.
                p.auto_updates = Some(true);
            }
        }
        pkgs.push(p);
    }
    pkgs.sort_by(|a, b| (a.kind(), &a.name).cmp(&(b.kind(), &b.name)));
    pkgs
}

/// License from the SPDX SBOM Homebrew writes into each keg.
fn keg_sbom_license(keg: &Path, name: &str) -> Option<String> {
    let sbom = json_file(&keg.join("sbom.spdx.json"))?;
    sbom.get("packages")?
        .as_array()?
        .iter()
        .find(|p| p.get("name").and_then(Value::as_str) == Some(name))
        .and_then(|p| p.get("licenseDeclared").and_then(Value::as_str))
        .filter(|l| *l != "NOASSERTION")
        .map(String::from)
}

/// Commit a git checkout is at, without git: HEAD -> ref -> loose or packed ref.
pub fn git_head(repo: &Path) -> Option<String> {
    let git = repo.join(".git");
    let head = read_text_opt(git.join("HEAD"))?.trim().to_string();
    let Some(r) = head.strip_prefix("ref: ") else { return Some(head) };
    if let Some(c) = read_text_opt(git.join(r)) {
        return Some(c.trim().to_string());
    }
    read_text_opt(git.join("packed-refs"))?.lines().find_map(|l| {
        let (sha, name) = l.split_once(' ')?;
        (name == r).then(|| sha.to_string())
    })
}

/// url of [remote "origin"] in .git/config.
pub fn git_remote(repo: &Path) -> Option<String> {
    let cfg = read_text_opt(repo.join(".git/config"))?;
    let mut in_origin = false;
    for l in cfg.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            in_origin = t == "[remote \"origin\"]";
        } else if in_origin {
            if let Some((k, v)) = t.split_once('=') {
                if k.trim() == "url" {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// "Homebrew 7.0.9": the tag at HEAD, else the newest tag.
pub fn homebrew_version(repo: &Path) -> String {
    let git = repo.join(".git");
    let mut tags: Vec<(String, String)> = Vec::new(); // (name, sha)
    for l in read_text_opt(git.join("packed-refs")).unwrap_or_default().lines() {
        if let Some((sha, name)) = l.split_once(' ') {
            if let Some(t) = name.strip_prefix("refs/tags/") {
                tags.push((t.to_string(), sha.to_string()));
            }
        }
    }
    for e in std::fs::read_dir(git.join("refs/tags")).into_iter().flatten().flatten() {
        if let Some(sha) = read_text_opt(e.path()) {
            tags.push((e.file_name().to_string_lossy().into_owned(), sha.trim().to_string()));
        }
    }
    let key =
        |t: &str| t.split(|c: char| !c.is_ascii_digit()).map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    tags.sort_by_key(|(t, _)| key(t));
    let head = git_head(repo);
    let at_head = tags.iter().rev().find(|(_, sha)| Some(sha) == head.as_ref()).map(|t| t.0.clone());
    match at_head.or_else(|| tags.last().map(|t| t.0.clone())) {
        Some(v) => format!("Homebrew {v}"),
        None => "Homebrew".into(),
    }
}

/// Installed taps: Library/Taps/<user>/homebrew-<repo>.
pub fn taps(repo: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    for user in sorted_dirs(&repo.join("Library/Taps")) {
        for dir in sorted_dirs(&user) {
            let (u, r) = (file_name(&user), file_name(&dir));
            let name = format!("{u}/{}", r.strip_prefix("homebrew-").unwrap_or(&r));
            let mut rec = json!({ "name": name });
            if let Some(remote) = git_remote(&dir) {
                let default = format!("https://github.com/{u}/{r}");
                if !remote.trim_end_matches(".git").eq_ignore_ascii_case(&default) {
                    rec["customRemote"] = json!(true);
                }
                rec["remote"] = json!(remote);
            }
            if let Some(head) = git_head(&dir) {
                rec["commit"] = json!(head);
            }
            out.push(rec);
        }
    }
    out
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

/// Does a formula definition exist in a (non-API) tap checkout?
fn tap_has_formula(layout: &Layout, full_name: &str) -> bool {
    let parts: Vec<&str> = full_name.split('/').collect();
    if parts.len() != 3 {
        return false;
    }
    let dir = layout.repo.join("Library/Taps").join(parts[0]).join(format!("homebrew-{}", parts[1]));
    let file = format!("{}.rb", parts[2]);
    fn walk(d: &Path, f: &str, depth: usize) -> bool {
        depth < 4
            && std::fs::read_dir(d).into_iter().flatten().flatten().any(|e| {
                let p = e.path();
                if p.is_dir() {
                    e.file_name() != ".git" && walk(&p, f, depth + 1)
                } else {
                    e.file_name().to_string_lossy() == f
                }
            })
    }
    walk(&dir, &file, 0)
}

fn is_extracted(name: &str) -> bool {
    name.starts_with(&format!("{PIN_TAP}/")) || name.starts_with(&format!("{LEGACY_PIN_TAP}/"))
}

pub struct Brew;

impl Brew {
    fn layout(&self) -> Result<Layout> {
        match Layout::detect() {
            Some(l) => Ok(l),
            None => bail!("Homebrew installation not found (set HOMEBREW_PREFIX)"),
        }
    }
}

impl Manager for Brew {
    fn name(&self) -> &'static str {
        "brew"
    }

    fn available(&self) -> bool {
        Layout::detect().is_some()
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

    fn installed(&self, plat: &Platform) -> Result<Vec<Package>> {
        let l = self.layout()?;
        Ok(scan(&l, &load_api(&l.cache, &bottle_tag(plat))))
    }

    fn capture(&self, plat: &Platform, opts: &Options) -> Result<Section> {
        let l = self.layout()?;
        let api = load_api(&l.cache, &bottle_tag(plat));
        if api.formulae.is_empty() {
            warn(
                "Homebrew API cache not found; licenses and bottle checksums are not recorded (run `brew update` once)",
            );
        }
        let mut pkgs = scan(&l, &api);
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
        Ok(Section {
            tool: Some(homebrew_version(&l.repo)),
            prefix: Some(l.prefix.to_string_lossy().into_owned()),
            taps: Some(taps(&l.repo)),
            packages: pkgs,
            ..Default::default()
        })
    }

    fn prepare(&self, section: &Section, _src: &Platform, _dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("brew (prepare)");
        let have: BTreeSet<String> = Layout::detect()
            .map(|l| taps(&l.repo).iter().map(|t| vstr(t, "name").to_string()).collect())
            .unwrap_or_default();
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
        let layout = self.layout()?;
        let api = load_api(&layout.cache, &bottle_tag(dst));
        let pkgs = &section.packages;
        let formulae: Vec<&Package> = pkgs.iter().filter(|p| p.kind() == "formula" && p.is_manual()).collect();
        let casks: Vec<&Package> = pkgs.iter().filter(|p| p.kind() == "cask").collect();
        let installed = scan(&layout, &api);
        let current: HashMap<String, &Package> = installed.iter().map(|p| (self.key_of(p, dst), p)).collect();
        let locked_taps: Vec<String> = section.taps.iter().flatten().map(|t| vstr(t, "name").to_string()).collect();

        let (mut install, mut extract, mut cask_install, mut pins) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for p in &formulae {
            let (name, ver) = (&p.name, &p.version);
            let have = current.get(&self.key_of(p, dst));
            let core = !name.contains('/');
            // Version brew would install now: from the API for core formulae;
            // unknown (but installable) for formulae from third-party taps.
            let available: Option<Option<String>> = if core {
                api.formulae.get(name.as_str()).map(|e| Some(e.version.clone()))
            } else if tap_has_formula(&layout, name) || locked_taps.iter().any(|t| name.starts_with(&format!("{t}/"))) {
                Some(None)
            } else {
                None
            };
            let mut target: Option<String> = None; // the formula name that ends up providing it
            if let Some(h) =
                have.filter(|h| &h.version == ver || (is_extracted(&h.name) && plain(&h.version) == plain(ver)))
            {
                target = Some(h.name.clone());
            } else {
                match &available {
                    Some(Some(v)) if v == ver => {
                        install.push(name.clone());
                        target = Some(name.clone());
                    }
                    Some(None) => {
                        plan.warnings.push(format!(
                            "{name}: third-party tap; installing its current version and checking it against {ver} afterwards"
                        ));
                        install.push(name.clone());
                        target = Some(name.clone());
                    }
                    Some(Some(_)) if opts.snapshot && core => {
                        extract.push((name.clone(), ver.clone()));
                        target = Some(format!("{PIN_TAP}/{name}@{}", plain(ver)));
                    }
                    Some(_) if opts.best_effort => {
                        plan.warnings.push(format!("{name} {ver} unavailable; installing current version"));
                        install.push(name.clone());
                        target = Some(name.clone());
                    }
                    _ => {
                        let why =
                            if available.is_none() { "formula not found" } else { "version is no longer current" };
                        plan.unresolved.push(format!("{name}@{ver} ({why})"));
                    }
                }
            }
            if let Some(t) = target {
                if Package::flag(&p.pinned) && !have.is_some_and(|h| Package::flag(&h.pinned)) {
                    pins.push(t);
                }
            }
        }
        for p in &casks {
            let (name, ver) = (&p.name, &p.version);
            if current.get(&self.key_of(p, dst)).is_some_and(|h| &h.version == ver) {
                continue;
            }
            let token = name.rsplit('/').next().unwrap_or(name);
            match api.casks.get(token) {
                Some(c) if &c.version == ver || opts.best_effort => {
                    if &c.version != ver {
                        plan.warnings.push(format!(
                            "cask {name}: locked {ver}, installing {} (casks cannot be pinned)",
                            c.version
                        ));
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
            let argv = ["brew", "install", "--formula"].map(String::from).into_iter().chain(install);
            plan.add(Step::cmd(format!("install {n} formula(e)"), argv));
        }
        if !extract.is_empty() {
            plan.warnings.push(
                "older formula versions are rebuilt from homebrew-core history with `brew extract`; this needs a full \
                 homebrew/core clone and usually compiles from source"
                    .into(),
            );
            let tap_new = format!("brew tap | grep -qx {PIN_TAP} || brew tap-new --no-git {PIN_TAP}");
            plan.add(Step::cmd("local tap for extracted versions", ["sh", "-c", &tap_new]));
            plan.add(
                Step::cmd(
                    "homebrew-core history is needed for brew extract",
                    ["sh", "-c", "brew tap | grep -qx homebrew/core || brew tap --force homebrew/core"],
                )
                .with_env("HOMEBREW_NO_INSTALL_FROM_API", "1"),
            );
            for (name, ver) in &extract {
                let v = format!("--version={}", plain(ver));
                plan.add(Step::cmd(
                    format!("recreate {name} {ver}"),
                    ["brew", "extract", "--force", &v, name, PIN_TAP],
                ));
                plan.add(Step::cmd(
                    "",
                    ["brew".to_string(), "install".into(), format!("{PIN_TAP}/{name}@{}", plain(ver))],
                ));
            }
        }
        if !cask_install.is_empty() {
            let n = cask_install.len();
            let argv = ["brew", "install", "--cask"].map(String::from).into_iter().chain(cask_install);
            plan.add(Step::cmd(format!("install {n} cask(s)"), argv));
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
                let argv = ["brew".to_string(), "uninstall".into()].into_iter().chain(extra);
                plan.add(Step::cmd(format!("remove {n} package(s) not in the lock"), argv));
                plan.add(Step::cmd("remove orphaned dependencies", ["brew", "autoremove"]));
            }
        }
        let deps = pkgs.iter().filter(|p| p.kind() == "formula" && !p.is_manual()).count();
        if deps > 0 {
            plan.warnings.push(format!(
                "{deps} dependency formula(e) are installed at whatever version their dependants need; `matsya check` \
                 reports any drift afterwards"
            ));
        }
        plan.summary = vec![("install".into(), n_install), ("unresolved".into(), plan.unresolved.len())];
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake Homebrew prefix shaped like Homebrew 7 on disk.
    fn fake_prefix(tag: &str) -> (PathBuf, Layout) {
        let root = std::env::temp_dir().join(format!("matsya-brew-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let p = root.join("prefix");
        let w = |path: &str, text: &str| {
            let f = p.join(path);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, text).unwrap();
        };
        w(
            "Cellar/jq/1.8.2/INSTALL_RECEIPT.json",
            r#"{"installed_on_request": true, "poured_from_bottle": true,
            "runtime_dependencies": [{"full_name": "oniguruma", "pkg_version": "6.9.10"}], "source": {"tap": "homebrew/core"}}"#,
        );
        w(
            "Cellar/oniguruma/6.9.8/INSTALL_RECEIPT.json",
            r#"{"installed_on_request": false, "poured_from_bottle": true, "source": {"tap": "homebrew/core"}}"#,
        );
        w(
            "Cellar/oniguruma/6.9.10/INSTALL_RECEIPT.json",
            r#"{"installed_on_request": false, "poured_from_bottle": true, "source": {"tap": "homebrew/core"}}"#,
        );
        w(
            "Cellar/mytool/1.9_1/INSTALL_RECEIPT.json",
            r#"{"installed_on_request": true, "poured_from_bottle": false, "source": {"tap": "acme/tools"}}"#,
        );
        w(
            "Cellar/mytool/1.9_1/sbom.spdx.json",
            r#"{"packages": [{"name": "mytool", "licenseDeclared": "Apache-2.0"}]}"#,
        );
        w("Cellar/broken/1.0/README", "no receipt");
        w(
            "Caskroom/firefox/.metadata/INSTALL_RECEIPT.json",
            r#"{"installed_on_request": true, "source": {"tap": "homebrew/cask", "version": "157.0.1"}}"#,
        );
        w("Caskroom/firefox/157.0.1/Firefox.app/x", "");
        w("Library/Taps/acme/homebrew-tools/.git/HEAD", "ref: refs/heads/main\n");
        w("Library/Taps/acme/homebrew-tools/.git/packed-refs", "# pack-refs\nabc123 refs/heads/main\n");
        w(
            "Library/Taps/acme/homebrew-tools/.git/config",
            "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://git.example.com/acme/homebrew-tools.git\n",
        );
        w("Library/Taps/acme/homebrew-tools/Formula/m/mytool.rb", "class Mytool < Formula; end");
        w(".git/HEAD", "ref: refs/heads/stable\n");
        w(".git/refs/heads/stable", "cafe\n");
        w(".git/packed-refs", "beef refs/tags/7.0.8\ncafe refs/tags/7.0.9\n");
        let cache = root.join("cache");
        let payload = json!({
            "metadata": {"bottle_tag": "arm64_tahoe"},
            "formulae": {
                "jq": {"stable_version": "1.8.2", "license": "MIT", "bottle_checksum": "aa"},
                "oniguruma": {"stable_version": "6.9.10", "license": "BSD-2-Clause", "bottle_checksum": "bb"},
                "aalib": {"stable_version": "1.4rc5", "revision": 2}
            },
            "casks": {"firefox": {"version": "157.0.1", "sha256": "ff", "url_args": ["https://example/ff.dmg"], "auto_updates": true}}
        });
        let jws = json!({"payload": payload.to_string(), "signatures": []});
        std::fs::create_dir_all(cache.join("api/internal")).unwrap();
        std::fs::write(cache.join("api/internal/packages.arm64_tahoe.jws.json"), jws.to_string()).unwrap();
        std::fs::create_dir_all(p.join("var/homebrew/linked")).unwrap();
        std::fs::create_dir_all(p.join("var/homebrew/pinned")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("../../../Cellar/oniguruma/6.9.10", p.join("var/homebrew/linked/oniguruma"))
                .unwrap();
            std::os::unix::fs::symlink("../../../Cellar/mytool/1.9_1", p.join("var/homebrew/pinned/mytool")).unwrap();
        }
        (root, Layout { prefix: p.clone(), repo: p, cache })
    }

    #[test]
    fn reads_homebrew_from_disk() {
        let (root, l) = fake_prefix("scan");
        let api = load_api(&l.cache, "arm64_tahoe");
        assert_eq!(api.formulae["aalib"].version, "1.4rc5_2");
        let pkgs = scan(&l, &api);
        let by = |n: &str| pkgs.iter().find(|p| p.name == n).unwrap().clone();
        let jq = by("jq");
        assert_eq!(jq.reason(), "manual");
        assert_eq!(jq.licenses, vec!["MIT"]);
        assert_eq!(jq.bottles.as_ref().unwrap()["arm64_tahoe"], "aa");
        assert_eq!(jq.dependencies, vec!["oniguruma"]);
        let onig = by("oniguruma");
        assert_eq!((onig.version.as_str(), onig.reason()), ("6.9.10", "dependency")); // linked keg wins
        assert_eq!(onig.other_kegs, vec!["6.9.8"]);
        let tool = by("acme/tools/mytool");
        assert_eq!(tool.tap.as_deref(), Some("acme/tools"));
        assert_eq!(tool.built_from_source, Some(true));
        assert_eq!(tool.licenses, vec!["Apache-2.0"]); // from the keg's SBOM
        if cfg!(unix) {
            assert_eq!(tool.pinned, Some(true));
        }
        assert!(!pkgs.iter().any(|p| p.name == "broken")); // no receipt, not a real keg
        let ff = by("firefox");
        assert_eq!((ff.kind(), ff.version.as_str(), ff.sha256.as_deref()), ("cask", "157.0.1", Some("ff")));
        assert_eq!(ff.auto_updates, Some(true));
        let t = taps(&l.repo);
        assert_eq!(t[0]["name"], "acme/tools");
        assert_eq!(t[0]["commit"], "abc123");
        assert_eq!(t[0]["customRemote"], true);
        assert_eq!(homebrew_version(&l.repo), "Homebrew 7.0.9");
        assert!(tap_has_formula(&l, "acme/tools/mytool"));
        assert!(!tap_has_formula(&l, "acme/tools/other"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn classic_api_format() {
        let payload = json!([{"name": "jq", "versions": {"stable": "1.7.1"}, "revision": 1, "license": "MIT",
            "bottle": {"stable": {"files": {"arm64_sonoma": {"sha256": "s1"}, "x86_64_linux": {"sha256": "s2"}}}}},
            {"token": "firefox", "version": "131.0", "sha256": "no_check", "url": "u"}]);
        let api = parse_api(&payload, "arm64_sonoma");
        assert_eq!(api.formulae["jq"].version, "1.7.1_1");
        assert_eq!(api.formulae["jq"].bottles.len(), 2);
        assert_eq!(api.casks["firefox"].sha256, None);
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
        let linux = Platform { os: Some("linux".into()), arch: Some("x86_64".into()), ..Default::default() };
        assert_eq!(bottle_tag(&linux), "x86_64_linux");
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
        let (root, l) = fake_prefix("brewfile");
        let sec = Section {
            taps: Some(vec![
                json!({"name": "acme/tools", "customRemote": true, "remote": "https://x"}),
                json!({"name": "homebrew/core"}),
            ]),
            packages: scan(&l, &load_api(&l.cache, "arm64_tahoe")),
            ..Default::default()
        };
        let text = export_brewfile(&sec);
        assert!(text.contains("tap \"acme/tools\", \"https://x\""));
        assert!(!text.contains("homebrew/core"));
        assert!(text.contains("brew \"jq\""));
        assert!(!text.contains("brew \"oniguruma\""));
        assert!(text.contains("cask \"firefox\""));
        let _ = std::fs::remove_dir_all(root);
    }
}
