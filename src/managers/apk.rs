//! Alpine Linux (apk-tools) backend.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::Path;

use serde_json::json;

use super::{resolve_dependencies, Manager, Options};
use crate::model::{vstr, Package, Section, Source};
use crate::plan::{Plan, Step, Write};
use crate::platform::Platform;
use crate::util::{read_text_opt, sha256_file, warn, Result};

const INSTALLED_DB: &[&str] = &["/lib/apk/db/installed", "/usr/lib/apk/db/installed"];
const WORLD: &str = "/etc/apk/world";
const REPOS: &str = "/etc/apk/repositories";
pub const PIN_GROUP: &str = ".matsya-pins";
/// Pin group created by the Python implementation (still recognised).
const LEGACY_PIN_GROUP: &str = ".syslock-pins";

/// 'so:libc.musl-x86_64.so.1' stays, 'busybox>=1.36' -> 'busybox',
/// 'curl@edge' -> 'curl', '!foo' -> '' (conflicts are not dependencies).
fn strip_dep(dep: &str) -> String {
    if dep.starts_with('!') {
        return String::new();
    }
    dep.split(|c| "<>=~@".contains(c)).next().unwrap_or("").to_string()
}

pub struct InstalledDb {
    pub pkgs: Vec<Package>,
    pub requires: HashMap<String, Vec<Vec<String>>>,
    pub provides: HashMap<String, Vec<String>>,
    /// Files owned by any package (to know whether a key file is ours).
    pub owned: HashSet<String>,
}

pub fn parse_installed(text: &str) -> InstalledDb {
    let mut db =
        InstalledDb { pkgs: vec![], requires: HashMap::new(), provides: HashMap::new(), owned: HashSet::new() };
    let mut cur: Option<Package> = None;
    let mut dir = String::new();
    for line in text.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            if let Some(p) = cur.take().filter(|p| !p.name.is_empty()) {
                db.pkgs.push(p);
            }
            dir.clear();
            continue;
        }
        let b = line.as_bytes();
        if b.len() < 2 || b[1] != b':' {
            continue;
        }
        let (k, v) = (b[0] as char, &line[2..]);
        let p = cur.get_or_insert_with(Package::default);
        match k {
            'P' => p.name = v.into(),
            'V' => p.version = v.into(),
            'A' => p.arch = Some(v.into()),
            'C' => p.checksum = Some(v.into()),
            'S' => p.size = v.parse().ok(),
            'L' if !v.is_empty() => p.licenses = vec![v.into()],
            'o' if v != p.name => p.source = Some(Source { name: v.into(), version: None }),
            'c' => p.commit = Some(v.into()),
            'D' => {
                db.requires.insert(
                    p.name.clone(),
                    v.split_whitespace().map(strip_dep).filter(|d| !d.is_empty()).map(|d| vec![d]).collect(),
                );
            }
            'p' => {
                db.provides
                    .insert(p.name.clone(), v.split_whitespace().map(strip_dep).filter(|d| !d.is_empty()).collect());
            }
            'F' => dir = v.into(),
            'R' => {
                db.owned.insert(if dir.is_empty() { format!("/{v}") } else { format!("/{dir}/{v}") });
            }
            _ => {}
        }
    }
    db
}

/// name -> raw world entry (keeps @tag / constraints).
pub fn parse_world(text: &str) -> BTreeMap<String, String> {
    text.split_whitespace().filter_map(|t| Some((strip_dep(t), t.to_string())).filter(|(n, _)| !n.is_empty())).collect()
}

/// (name, version) -> checksum from an APKINDEX file.
pub fn parse_apkindex(text: &str) -> HashMap<(String, String), String> {
    let mut res = HashMap::new();
    let mut cur: HashMap<char, &str> = HashMap::new();
    for line in text.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            if let (Some(p), Some(v)) = (cur.get(&'P'), cur.get(&'V')) {
                res.insert((p.to_string(), v.to_string()), cur.get(&'C').unwrap_or(&"").to_string());
            }
            cur.clear();
        } else if line.len() > 1 && line.as_bytes()[1] == b':' {
            cur.insert(line.as_bytes()[0] as char, &line[2..]);
        }
    }
    res
}

pub struct Apk;

/// What `apk --version` prints, from the installed database.
fn apk_tool_version(pkgs: &[Package]) -> String {
    let arch = read_text_opt("/etc/apk/arch").map(|s| s.trim().to_string()).unwrap_or_default();
    pkgs.iter()
        .find(|p| p.name == "apk-tools")
        .map(|p| format!("apk-tools {}, compiled for {}.", p.version, if arch.is_empty() { p.arch() } else { &arch }))
        .unwrap_or_default()
}

impl Apk {
    fn db_path(&self) -> Option<&'static str> {
        INSTALLED_DB.iter().copied().find(|p| Path::new(p).exists())
    }

    fn read(&self) -> InstalledDb {
        let mut db =
            self.db_path().and_then(read_text_opt).map(|t| parse_installed(&t)).unwrap_or_else(|| parse_installed(""));
        // Our own pin group is bookkeeping, not part of the locked state.
        db.pkgs.retain(|p| p.name != PIN_GROUP && p.name != LEGACY_PIN_GROUP);
        for p in &mut db.pkgs {
            if p.name.starts_with('.') {
                // `apk add --virtual .build-deps ...` creates a package that
                // exists in no repository; it is recreated from its deps.
                p.is_virtual = Some(true);
            }
        }
        db
    }

    fn world(&self) -> BTreeMap<String, String> {
        read_text_opt(WORLD).map(|t| parse_world(&t)).unwrap_or_default()
    }

    fn index(&self) -> Option<HashMap<(String, String), String>> {
        let mut files = Vec::new();
        for dir in ["/var/cache/apk", "/etc/apk/cache"] {
            if let Ok(d) = std::fs::read_dir(dir) {
                for e in d.flatten() {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if n.starts_with("APKINDEX.") && n.ends_with(".tar.gz") {
                        files.push(e.path());
                    }
                }
            }
        }
        if files.is_empty() {
            return None;
        }
        let mut res = HashMap::new();
        for f in files {
            let Ok(data) = std::fs::read(&f) else { continue };
            // APKINDEX.tar.gz is a concatenation of gzip streams (signature +
            // index); the capped reader decodes them as one tar stream.
            let Ok(reader) = crate::formats::capped_reader(data) else { continue };
            let mut ar = tar::Archive::new(reader);
            let Ok(entries) = ar.entries() else { continue };
            for mut e in entries.flatten() {
                if e.path().map(|p| p.to_string_lossy() == "APKINDEX").unwrap_or(false) {
                    let mut s = String::new();
                    if e.read_to_string(&mut s).is_ok() {
                        res.extend(parse_apkindex(&s));
                    }
                }
            }
        }
        Some(res)
    }
}

impl Manager for Apk {
    fn name(&self) -> &'static str {
        "apk"
    }

    fn available(&self) -> bool {
        self.db_path().is_some()
    }

    fn installed(&self, _plat: &Platform) -> Result<Vec<Package>> {
        let world = self.world();
        Ok(self
            .read()
            .pkgs
            .into_iter()
            .map(|mut p| {
                p.reason = Some(if world.contains_key(&p.name) { "manual" } else { "dependency" }.into());
                p
            })
            .collect())
    }

    fn capture(&self, _plat: &Platform, opts: &Options) -> Result<Section> {
        let mut db = self.read();
        let world = self.world();
        if world.is_empty() {
            warn("apk world file is empty or missing; no package is recorded as manually installed");
        }
        let keys: Vec<String> = db.pkgs.iter().map(|p| p.name.clone()).collect();
        resolve_dependencies(&mut db.pkgs, &keys, &db.requires, &db.provides);
        for p in &mut db.pkgs {
            p.reason = Some(if world.contains_key(&p.name) { "manual" } else { "dependency" }.into());
            if let Some(entry) = world.get(&p.name).filter(|e| **e != p.name) {
                p.world_entry = Some(entry.clone());
            }
            if !opts.licenses {
                p.licenses.clear();
            }
        }
        let mut repos = Vec::new();
        for line in read_text_opt(REPOS).unwrap_or_default().lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (tag, url) = if line.starts_with('@') {
                line.split_once(char::is_whitespace).unwrap_or((line, ""))
            } else {
                ("", line)
            };
            let mut r = json!({"id": line, "url": url.trim()});
            if !tag.is_empty() {
                r["tag"] = json!(tag);
            }
            repos.push(r);
        }
        let mut keys_out = Vec::new();
        let mut paths: Vec<String> = std::fs::read_dir("/etc/apk/keys")
            .map(|d| d.flatten().map(|e| e.path().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        paths.sort();
        for path in paths {
            let mut k = json!({"path": path, "sha256": sha256_file(&path)?});
            if !db.owned.contains(&path) && opts.embed_keys {
                use base64::Engine;
                k["data"] = json!(base64::engine::general_purpose::STANDARD.encode(std::fs::read(&path)?));
            }
            keys_out.push(k);
        }
        db.pkgs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Section {
            tool: Some(apk_tool_version(&db.pkgs)),
            repositories: Some(repos),
            keys: Some(keys_out),
            packages: db.pkgs,
            ..Default::default()
        })
    }

    fn prepare(&self, section: &Section, _src: &Platform, _dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("apk (prepare)");
        if opts.add_repos {
            let current: Vec<String> = read_text_opt(REPOS).unwrap_or_default().lines().map(String::from).collect();
            let have: HashSet<&str> = current.iter().map(|l| l.trim()).collect();
            let missing: Vec<String> = section
                .repos()
                .iter()
                .map(|r| vstr(r, "id").to_string())
                .filter(|id| !have.contains(id.as_str()))
                .collect();
            for k in section.keys.iter().flatten() {
                let path = vstr(k, "path");
                if !vstr(k, "data").is_empty() && !Path::new(path).exists() {
                    plan.add(Step::write(
                        format!("signing key {}", path.rsplit('/').next().unwrap_or(path)),
                        Write { path: path.into(), content: vstr(k, "data").into(), base64: true, mode: 0o644 },
                    ));
                }
            }
            if !missing.is_empty() {
                let content = current.iter().chain(missing.iter()).cloned().collect::<Vec<_>>().join("\n");
                plan.add(Step::write(
                    format!("add {} repositor(y/ies)", missing.len()),
                    Write { path: REPOS.into(), content, base64: false, mode: 0o644 },
                ));
            }
        }
        if opts.refresh {
            plan.add(Step::cmd("refresh package indexes", ["apk", "update"]));
        }
        Ok(plan)
    }

    fn plan(&self, section: &Section, _src: &Platform, dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("apk");
        let installed = self.installed(dst)?;
        let current: HashMap<&str, &Package> = installed.iter().map(|p| (p.name.as_str(), p)).collect();
        let index = self.index();
        let (mut roots, mut deps, mut virtuals) = (Vec::new(), Vec::new(), Vec::new());
        for p in &section.packages {
            let (name, ver) = (&p.name, &p.version);
            if !p.is_manual() && opts.roots_only {
                continue;
            }
            if Package::flag(&p.is_virtual) {
                if !current.contains_key(name.as_str()) {
                    virtuals.push(p);
                }
                continue;
            }
            let cur = current.get(name.as_str());
            if cur.map(|c| &c.version) == Some(ver) && (!p.is_manual() || cur.map(|c| c.is_manual()) == Some(true)) {
                continue;
            }
            let tag =
                p.world_entry.as_deref().and_then(|e| e.split_once('@')).map(|(_, t)| strip_dep(t)).unwrap_or_default();
            let mut spec = format!("{name}={ver}");
            if let Some(idx) = &index {
                if !idx.contains_key(&(name.clone(), ver.clone())) && cur.map(|c| &c.version) != Some(ver) {
                    // Alpine drops superseded versions and has no public archive.
                    if opts.best_effort {
                        plan.warnings
                            .push(format!("{spec} is no longer in the repositories; installing newest {name}"));
                        spec = name.clone();
                    } else {
                        plan.unresolved.push(format!("{spec} (Alpine keeps no archive of old versions)"));
                        continue;
                    }
                }
            }
            if !tag.is_empty() {
                // apk syntax is name[@tag][op version]
                spec = format!("{name}@{tag}{}", &spec[name.len()..]);
            }
            if p.is_manual() { &mut roots } else { &mut deps }.push(spec);
        }
        roots.sort();
        deps.sort();
        if !deps.is_empty() {
            // A virtual group pins dependencies without listing them in world
            // as if the user had asked for them.
            let n = deps.len();
            plan.add(Step::cmd(
                format!("pin {n} dependenc(y/ies) at locked versions"),
                ["apk", "add", "--virtual", PIN_GROUP].map(String::from).into_iter().chain(deps),
            ));
        }
        if !roots.is_empty() {
            let n = roots.len();
            plan.add(Step::cmd(
                format!("install {n} package(s) at locked versions"),
                ["apk".to_string(), "add".into()].into_iter().chain(roots),
            ));
        }
        for v in virtuals {
            plan.add(Step::cmd(
                format!("recreate virtual package {}", v.name),
                ["apk".to_string(), "add".into(), "--virtual".into(), v.name.clone()]
                    .into_iter()
                    .chain(v.dependencies.iter().cloned()),
            ));
        }
        if opts.prune {
            let locked: HashSet<&str> =
                section.packages.iter().filter(|p| p.is_manual()).map(|p| p.name.as_str()).collect();
            let extra: BTreeSet<String> = self
                .world()
                .into_keys()
                .filter(|n| !locked.contains(n.as_str()) && n != PIN_GROUP && n != LEGACY_PIN_GROUP)
                .collect();
            if !extra.is_empty() {
                let n = extra.len();
                plan.add(Step::cmd(
                    format!("remove {n} world entr(y/ies) not in the lock"),
                    ["apk".to_string(), "del".into()].into_iter().chain(extra),
                ));
            }
        }
        plan.warnings.push(
            "apk records '=version' pins in /etc/apk/world; `apk upgrade` keeps these versions until you run `matsya lock` again or relax the pins".into(),
        );
        let changed = section
            .packages
            .iter()
            .filter(|p| current.get(p.name.as_str()).map(|c| &c.version) != Some(&p.version))
            .count();
        plan.summary = vec![("install_or_change".into(), changed), ("unresolved".into(), plan.unresolved.len())];
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[test]
    fn installed_db() {
        let mut db = parse_installed(&fixture("apk-installed"));
        let names: Vec<&str> = db.pkgs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["musl", "busybox", "curl", "libcurl", "ca-certificates-bundle"]);
        assert!(db.owned.contains("/lib/ld-musl-x86_64.so.1"));
        assert!(db.owned.contains("/etc/apk/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"));
        let keys: Vec<String> = db.pkgs.iter().map(|p| p.name.clone()).collect();
        resolve_dependencies(&mut db.pkgs, &keys, &db.requires, &db.provides);
        let curl = db.pkgs.iter().find(|p| p.name == "curl").unwrap();
        assert_eq!(curl.dependencies, vec!["ca-certificates-bundle", "libcurl", "musl"]);
        assert_eq!(curl.checksum.as_deref(), Some("Q1xyz="));
    }

    #[test]
    fn world() {
        let w = parse_world(&fixture("apk-world"));
        assert_eq!(w.keys().cloned().collect::<Vec<_>>(), vec!["busybox", "curl", "jq"]);
        assert_eq!(w["jq"], "jq@edge");
    }

    #[test]
    fn index() {
        let idx = parse_apkindex(&fixture("APKINDEX"));
        assert!(idx.contains_key(&("curl".into(), "8.9.1-r0".into())));
        assert!(!idx.contains_key(&("busybox".into(), "1.36.1-r29".into())));
    }
}
