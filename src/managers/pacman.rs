//! Arch Linux and derivatives (pacman) backend.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::Path;

use serde_json::json;

use super::{resolve_dependencies, Manager, Options};
use crate::model::{Package, Section, Source};
use crate::plan::{Fetch, Plan, Step};
use crate::platform::Platform;
use crate::util::{read_text_opt, Result};

/// Every package Arch has ever shipped, by name.
const ALA: &str = "https://archive.archlinux.org/packages/{first}/{name}/{filename}";

/// %KEY%\nvalue\nvalue\n\n blocks used by local and sync databases.
pub fn parse_desc(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut res: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut key: Option<String> = None;
    for line in text.lines() {
        if line.len() > 2 && line.starts_with('%') && line.ends_with('%') {
            let k = line[1..line.len() - 1].to_string();
            res.insert(k.clone(), vec![]);
            key = Some(k);
        } else if line.is_empty() {
            key = None;
        } else if let Some(k) = &key {
            res.get_mut(k).expect("key").push(line.into());
        }
    }
    res
}

/// 'glibc>=2.38', 'sh: for scripts', 'libfoo.so=1-64' -> bare names
fn dep_name(d: &str) -> String {
    let d = d.split(':').next().unwrap_or("");
    d.split(|c| "<>=".contains(c)).next().unwrap_or("").trim().to_string()
}

pub fn package_from_desc(desc: &BTreeMap<String, Vec<String>>) -> (Package, Vec<Vec<String>>, Vec<String>) {
    let one = |k: &str| desc.get(k).and_then(|v| v.first()).cloned().unwrap_or_default();
    let mut p = Package::new(one("NAME"), one("VERSION"));
    p.arch = Some(one("ARCH"));
    if !one("BASE").is_empty() && one("BASE") != p.name {
        p.source = Some(Source { name: one("BASE"), version: None });
    }
    p.licenses = desc.get("LICENSE").cloned().unwrap_or_default();
    if !one("PACKAGER").is_empty() {
        p.packager = Some(one("PACKAGER"));
    }
    p.reason = Some(if one("REASON") == "1" { "dependency" } else { "manual" }.into());
    let list = |k: &str| {
        desc.get(k)
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|d| dep_name(d))
            .filter(|d| !d.is_empty())
            .collect::<Vec<_>>()
    };
    let requires = list("DEPENDS").into_iter().map(|d| vec![d]).collect();
    (p, requires, list("PROVIDES"))
}

#[derive(Debug, Clone, PartialEq)]
pub struct SyncEntry {
    pub filename: String,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub repository: String,
}

/// Decompress a sync database (gzip, zstd or plain tar).
fn db_reader(path: &str) -> Option<Box<dyn Read>> {
    let data = std::fs::read(path).ok()?;
    if data.starts_with(&[0x1f, 0x8b]) {
        Some(Box::new(flate2::read::MultiGzDecoder::new(std::io::Cursor::new(data))))
    } else if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let dec = ruzstd::decoding::StreamingDecoder::new(std::io::Cursor::new(data)).ok()?;
        Some(Box::new(dec))
    } else {
        Some(Box::new(std::io::Cursor::new(data)))
    }
}

/// (name, version) -> entry, from a sync .db file.
pub fn read_sync_db(path: &str, repo: &str) -> HashMap<(String, String), SyncEntry> {
    let mut res = HashMap::new();
    let Some(reader) = db_reader(path) else { return res };
    let mut ar = tar::Archive::new(reader);
    let Ok(entries) = ar.entries() else { return res };
    for mut e in entries.flatten() {
        let is_desc = e.path().map(|p| p.to_string_lossy().ends_with("/desc")).unwrap_or(false);
        if !is_desc {
            continue;
        }
        let mut s = String::new();
        if e.read_to_string(&mut s).is_err() {
            continue;
        }
        let d = parse_desc(&s);
        let one = |k: &str| d.get(k).and_then(|v| v.first()).cloned().unwrap_or_default();
        res.insert(
            (one("NAME"), one("VERSION")),
            SyncEntry {
                filename: one("FILENAME"),
                sha256: Some(one("SHA256SUM")).filter(|s| !s.is_empty()),
                size: one("CSIZE").parse().ok(),
                repository: repo.into(),
            },
        );
    }
    res
}

/// Installed packages with their raw requires and provides.
type LocalDb = (Vec<Package>, HashMap<String, Vec<Vec<String>>>, HashMap<String, Vec<String>>);

const PACMAN_CONF: &str = "/etc/pacman.conf";

/// The parts of pacman.conf matsya needs, as `pacman-conf` would report them.
#[derive(Debug, Default, PartialEq)]
pub struct PacmanConf {
    pub dbpath: String,
    /// Repositories in order, with expanded Server URLs.
    pub repos: Vec<(String, Vec<String>)>,
}

/// Parse pacman.conf; `include` reads files named by Include directives.
pub fn parse_pacman_conf(text: &str, include: &dyn Fn(&str) -> Option<String>) -> PacmanConf {
    let mut conf = PacmanConf { dbpath: "/var/lib/pacman".into(), repos: vec![] };
    let mut arch = std::env::consts::ARCH.to_string();
    // First pass: options (Architecture affects $arch in every repo).
    let mut section = String::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
        } else if section == "options" {
            if let Some((k, v)) = line.split_once('=') {
                match k.trim() {
                    "DBPath" => conf.dbpath = v.trim().trim_end_matches('/').to_string(),
                    "Architecture" => {
                        if let Some(a) = v.split_whitespace().find(|a| *a != "auto") {
                            arch = a.to_string();
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let servers_in = |body: &str, repo: &str| -> Vec<String> {
        body.lines()
            .filter_map(|l| {
                let l = l.split('#').next().unwrap_or("").trim();
                let (k, v) = l.split_once('=')?;
                (k.trim() == "Server").then(|| v.trim().replace("$repo", repo).replace("$arch", &arch))
            })
            .collect()
    };
    section.clear();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            if section != "options" {
                conf.repos.push((section.clone(), vec![]));
            }
            continue;
        }
        if section.is_empty() || section == "options" {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let found = match k.trim() {
            "Server" => servers_in(line, &section),
            "Include" => include(v.trim()).map(|t| servers_in(&t, &section)).unwrap_or_default(),
            _ => continue,
        };
        conf.repos.last_mut().expect("in a repo section").1.extend(found);
    }
    conf
}

pub struct Pacman;

impl Pacman {
    fn conf(&self) -> PacmanConf {
        let text = read_text_opt(PACMAN_CONF).unwrap_or_default();
        parse_pacman_conf(&text, &|p| read_text_opt(p))
    }

    fn dbpath(&self) -> String {
        self.conf().dbpath
    }

    fn local(&self) -> LocalDb {
        let (mut pkgs, mut req, mut prov) = (Vec::new(), HashMap::new(), HashMap::new());
        let mut dirs: Vec<_> = std::fs::read_dir(format!("{}/local", self.dbpath()))
            .map(|d| d.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        dirs.sort();
        for d in dirs {
            let Some(text) = read_text_opt(d.join("desc")) else { continue };
            let (p, r, pv) = package_from_desc(&parse_desc(&text));
            if !p.name.is_empty() {
                req.insert(p.name.clone(), r);
                prov.insert(p.name.clone(), pv);
                pkgs.push(p);
            }
        }
        (pkgs, req, prov)
    }

    fn sync(&self) -> HashMap<(String, String), SyncEntry> {
        let mut res = HashMap::new();
        let mut dbs: Vec<String> = std::fs::read_dir(format!("{}/sync", self.dbpath()))
            .map(|d| {
                d.flatten().map(|e| e.path().to_string_lossy().into_owned()).filter(|p| p.ends_with(".db")).collect()
            })
            .unwrap_or_default();
        dbs.sort();
        for db in dbs {
            let repo = Path::new(&db).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            for (k, v) in read_sync_db(&db, &repo) {
                res.entry(k).or_insert(v);
            }
        }
        res
    }
}

impl Manager for Pacman {
    fn name(&self) -> &'static str {
        "pacman"
    }

    fn available(&self) -> bool {
        Path::new(&self.dbpath()).join("local").is_dir()
    }

    fn installed(&self, _plat: &Platform) -> Result<Vec<Package>> {
        Ok(self.local().0)
    }

    fn capture(&self, _plat: &Platform, opts: &Options) -> Result<Section> {
        let (mut pkgs, req, prov) = self.local();
        let keys: Vec<String> = pkgs.iter().map(|p| p.name.clone()).collect();
        resolve_dependencies(&mut pkgs, &keys, &req, &prov);
        let sync = self.sync();
        for p in &mut pkgs {
            if let Some(hit) = sync.get(&(p.name.clone(), p.version.clone())) {
                p.repositories = Some(vec![hit.repository.clone()]);
                p.sha256 = hit.sha256.clone();
                p.size = hit.size;
                p.filename = Some(hit.filename.clone()).filter(|f| !f.is_empty());
            }
            if !opts.licenses {
                p.licenses.clear();
            }
        }
        let repos: Vec<_> = self
            .conf()
            .repos
            .into_iter()
            .map(|(name, servers)| json!({"id": name, "servers": servers.into_iter().take(3).collect::<Vec<_>>()}))
            .collect();
        let tool =
            pkgs.iter().find(|p| p.name == "pacman").map(|p| format!("pacman {}", p.version)).unwrap_or_default();
        Ok(Section { tool: Some(tool), repositories: Some(repos), packages: pkgs, ..Default::default() })
    }

    fn prepare(&self, _s: &Section, _src: &Platform, _dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("pacman (prepare)");
        if opts.refresh {
            plan.add(Step::cmd("refresh sync databases", ["pacman", "-Sy", "--noconfirm"]));
        }
        Ok(plan)
    }

    fn plan(&self, section: &Section, src: &Platform, dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("pacman");
        let pkgs: Vec<&Package> = section.packages.iter().filter(|p| !opts.roots_only || p.is_manual()).collect();
        let installed = self.installed(dst)?;
        let current: HashMap<&str, &Package> = installed.iter().map(|p| (p.name.as_str(), p)).collect();
        let sync = self.sync();
        let (mut repo_specs, mut files) = (Vec::new(), Vec::new());
        let mut touched: HashSet<&str> = HashSet::new();
        let cross = src.arch() != dst.arch();
        for p in &pkgs {
            let (name, ver) = (p.name.as_str(), &p.version);
            if current.get(name).map(|c| &c.version) == Some(ver) {
                continue;
            }
            touched.insert(name);
            if let Some(hit) = sync.get(&(name.to_string(), ver.clone())) {
                repo_specs.push(format!("{}/{name}", hit.repository));
                continue;
            }
            if let (true, "arch", Some(f), false) = (opts.snapshot, dst.distro(), &p.filename, cross) {
                let dest = format!("{}/pacman/{f}", opts.cache_dir);
                let url = ALA.replace("{first}", &name[..1]).replace("{name}", name).replace("{filename}", f);
                plan.add(Step::fetch(
                    format!("{name} {ver} is no longer current; fetching from the Arch Linux Archive"),
                    Fetch { urls: vec![url], dest: dest.clone(), sha256: p.sha256.clone(), rpm_payload: None },
                ));
                files.push(dest);
                continue;
            }
            if opts.best_effort {
                plan.warnings.push(format!("{name} {ver} unavailable; installing current {name}"));
                repo_specs.push(name.to_string());
            } else {
                let extra =
                    if dst.distro() != "arch" { " and the Arch Linux Archive only covers x86_64 Arch" } else { "" };
                plan.unresolved.push(format!("{name}={ver} (not in sync databases{extra})"));
            }
        }
        if !files.is_empty() {
            plan.warnings.push(
                "mixing archived and current packages is a partial upgrade; for a whole-system time travel point /etc/pacman.d/mirrorlist at \
                 https://archive.archlinux.org/repos/YYYY/MM/DD/$repo/os/$arch and run pacman -Syyuu"
                    .into(),
            );
        }
        repo_specs.sort();
        let n_install = repo_specs.len() + files.len();
        if !repo_specs.is_empty() {
            let n = repo_specs.len();
            plan.add(Step::cmd(
                format!("install {n} package(s) from sync databases"),
                ["pacman", "-S", "--needed", "--noconfirm"].map(String::from).into_iter().chain(repo_specs),
            ));
        }
        if !files.is_empty() {
            let n = files.len();
            plan.add(Step::cmd(
                format!("install {n} archived package(s)"),
                ["pacman", "-U", "--needed", "--noconfirm"].map(String::from).into_iter().chain(files),
            ));
        }
        let needs = |p: &Package, want: &str| {
            touched.contains(p.name.as_str()) || current.get(p.name.as_str()).map(|c| c.reason()) != Some(want)
        };
        let explicit: BTreeSet<String> =
            pkgs.iter().filter(|p| p.is_manual() && needs(p, "manual")).map(|p| p.name.clone()).collect();
        let deps: BTreeSet<String> =
            pkgs.iter().filter(|p| !p.is_manual() && needs(p, "dependency")).map(|p| p.name.clone()).collect();
        if !explicit.is_empty() {
            plan.add(Step::cmd(
                "restore explicit-install reasons",
                ["pacman".to_string(), "-D".into(), "--asexplicit".into()].into_iter().chain(explicit),
            ));
        }
        if !deps.is_empty() && !opts.roots_only {
            plan.add(Step::cmd(
                "restore dependency reasons",
                ["pacman".to_string(), "-D".into(), "--asdeps".into()].into_iter().chain(deps),
            ));
        }
        if opts.prune {
            let locked: HashSet<&str> = section.packages.iter().map(|p| p.name.as_str()).collect();
            let extra: BTreeSet<String> = current
                .keys()
                .filter(|n| !locked.contains(*n) && !["pacman", "glibc", "filesystem", "base"].contains(n))
                .map(|n| n.to_string())
                .collect();
            if !extra.is_empty() {
                let n = extra.len();
                plan.add(Step::cmd(
                    format!("remove {n} package(s) not in the lock"),
                    ["pacman".to_string(), "-Rn".into(), "--noconfirm".into()].into_iter().chain(extra),
                ));
            }
        }
        plan.summary = vec![("install".into(), n_install), ("unresolved".into(), plan.unresolved.len())];
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desc() {
        let text =
            std::fs::read_to_string(format!("{}/tests/fixtures/pacman-desc", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let (p, req, prov) = package_from_desc(&parse_desc(&text));
        assert_eq!(p.version, "1:8.10.1-1");
        assert_eq!(p.reason(), "dependency");
        assert_eq!(
            req.iter().map(|r| r[0].as_str()).collect::<Vec<_>>(),
            vec!["ca-certificates", "krb5", "libcurl.so", "glibc", "sh"]
        );
        assert_eq!(prov, vec!["libcurl.so"]);
    }

    #[test]
    fn pacman_conf() {
        let conf = "[options]\nArchitecture = auto x86_64\nDBPath = /srv/pacman/\n#[testing]\n[core]\nInclude = /etc/pacman.d/mirrorlist\n\n[custom]\nSigLevel = Optional\nServer = file:///repo/$repo/$arch # local\n";
        let mirrors = "[options]\n## comment\nServer = https://a.example/$repo/os/$arch\n#Server = https://disabled\nServer = https://b.example/$repo/os/$arch\n";
        let c = parse_pacman_conf(conf, &|p| (p == "/etc/pacman.d/mirrorlist").then(|| mirrors.to_string()));
        assert_eq!(c.dbpath, "/srv/pacman");
        assert_eq!(
            c.repos,
            vec![
                (
                    "core".to_string(),
                    vec!["https://a.example/core/os/x86_64".to_string(), "https://b.example/core/os/x86_64".into()]
                ),
                ("custom".to_string(), vec!["file:///repo/custom/x86_64".to_string()]),
            ]
        );
    }

    #[test]
    fn sync_db_gzip() {
        let desc = b"%FILENAME%\ncurl-1:8.10.1-1-x86_64.pkg.tar.zst\n\n%NAME%\ncurl\n\n%VERSION%\n1:8.10.1-1\n\n%CSIZE%\n123\n\n%SHA256SUM%\nabc\n\n";
        let dir = std::env::temp_dir().join(format!("matsya-pac-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("core.db");
        {
            let gz =
                flate2::write::GzEncoder::new(std::fs::File::create(&path).unwrap(), flate2::Compression::default());
            let mut b = tar::Builder::new(gz);
            let mut h = tar::Header::new_gnu();
            h.set_size(desc.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "curl-1:8.10.1-1/desc", &desc[..]).unwrap();
            b.into_inner().unwrap().finish().unwrap();
        }
        let db = read_sync_db(path.to_str().unwrap(), "core");
        let e = &db[&("curl".to_string(), "1:8.10.1-1".to_string())];
        assert_eq!(e.filename, "curl-1:8.10.1-1-x86_64.pkg.tar.zst");
        assert_eq!(e.sha256.as_deref(), Some("abc"));
        assert_eq!(e.size, Some(123));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
