//! Debian / Ubuntu (dpkg + apt) backend.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{by_key, resolve_dependencies, Manager, Options};
use crate::formats::read_text_decompressed;
use crate::model::{vstr, vstrs, Package, Section, Source};
use crate::plan::{Fetch, Plan, Step, Write};
use crate::platform::{sysroot, termux_prefix, Platform};
use crate::util::{
    compact_ts, parse_deb822, read_text, read_text_opt, rfc2822_to_iso, sha256_file, sha256_hex, warn, Result,
};

pub fn deb_arch(canonical: &str) -> String {
    match canonical {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "armv7" => "armhf",
        "armv6" => "armel",
        "i686" => "i386",
        "ppc64le" => "ppc64el",
        "loongarch64" => "loong64",
        other => other,
    }
    .to_string()
}

/// dpkg/apt live under the system root: "/" normally, $PREFIX on Termux.
pub fn dpkg_dir() -> PathBuf {
    sysroot().join("var/lib/dpkg")
}
fn apt_state() -> PathBuf {
    sysroot().join("var/lib/apt")
}
fn lists_dir() -> PathBuf {
    apt_state().join("lists")
}
fn apt_etc() -> PathBuf {
    sysroot().join("etc/apt")
}
fn doc_dir() -> PathBuf {
    match termux_prefix() {
        Some(p) => p.join("share/doc"),
        None => PathBuf::from("/usr/share/doc"),
    }
}

/// The architecture name dpkg uses on a platform. Termux spells them its
/// own way (aarch64, arm) instead of Debian's (arm64, armhf).
pub fn arch_name(plat: &Platform) -> String {
    if plat.distro() == "termux" {
        match plat.arch() {
            "armv7" => "arm".into(),
            other => other.into(),
        }
    } else {
        deb_arch(plat.arch())
    }
}

/// A dpkg package plus its raw relationship fields.
pub struct DpkgEntry {
    pub pkg: Package,
    pub requires: Vec<Vec<String>>,
    pub provides: Vec<String>,
}

/// Status stanzas from dpkg's database with the journal in `updates/`
/// applied on top, as dpkg-query does, so the state after an interrupted
/// dpkg run is read correctly.
pub fn read_status(dir: &Path) -> Result<Vec<BTreeMap<String, String>>> {
    let mut order: Vec<(String, String)> = Vec::new();
    let mut by_key: HashMap<(String, String), BTreeMap<String, String>> = HashMap::new();
    let mut add = |st: BTreeMap<String, String>| {
        let key = (st.get("Package").cloned().unwrap_or_default(), st.get("Architecture").cloned().unwrap_or_default());
        if key.0.is_empty() {
            return;
        }
        if by_key.insert(key.clone(), st).is_none() {
            order.push(key);
        }
    };
    for st in parse_deb822(&read_text(dir.join("status"))?) {
        add(st);
    }
    let mut updates: Vec<(u64, std::path::PathBuf)> = std::fs::read_dir(dir.join("updates"))
        .map(|d| d.flatten().filter_map(|e| Some((e.file_name().to_str()?.parse().ok()?, e.path()))).collect())
        .unwrap_or_default();
    updates.sort();
    for (_, path) in updates {
        for st in parse_deb822(&read_text(&path).unwrap_or_default()) {
            add(st);
        }
    }
    Ok(order.into_iter().filter_map(|k| by_key.remove(&k)).collect())
}

/// "install ok installed" -> "ii " (dpkg-query's db:Status-Abbrev).
pub fn status_abbrev(status: &str) -> String {
    let w: Vec<&str> = status.split_whitespace().collect();
    let want = match w.first().copied() {
        Some("install") => 'i',
        Some("hold") => 'h',
        Some("deinstall") => 'r',
        Some("purge") => 'p',
        _ => 'u',
    };
    let flag = if w.get(1) == Some(&"reinstreq") { 'R' } else { ' ' };
    let state = match w.get(2).copied() {
        Some("installed") => 'i',
        Some("config-files") => 'c',
        Some("half-installed") => 'H',
        Some("unpacked") => 'U',
        Some("half-configured") => 'F',
        Some("triggers-awaited") => 'W',
        Some("triggers-pending") => 't',
        _ => 'n',
    };
    format!("{want}{state}{flag}")
}

/// Installed packages from status stanzas, plus warnings about broken ones.
pub fn parse_status(stanzas: &[BTreeMap<String, String>]) -> (Vec<DpkgEntry>, Vec<String>) {
    let mut pkgs = Vec::new();
    let mut problems = Vec::new();
    for st in stanzas {
        let g = |k: &str| st.get(k).map(String::as_str).unwrap_or("");
        let (name, arch, version) = (g("Package"), g("Architecture"), g("Version"));
        let status = status_abbrev(g("Status"));
        let c: Vec<char> = status.chars().collect();
        if c[1] != 'i' {
            if "UFHWt".contains(c[1]) {
                problems.push(format!("{name}:{arch} is in a broken dpkg state ({}); it is not locked", status.trim()));
            }
            continue;
        }
        if c[2] == 'R' {
            problems.push(format!("{name}:{arch} needs reinstallation; locked anyway"));
        }
        let mut p = Package::new(name, version);
        p.arch = Some(arch.into());
        if c[0] == 'h' {
            p.held = Some(true);
        }
        if g("Essential") == "yes" {
            p.essential = Some(true);
        }
        if !g("Priority").is_empty() {
            p.priority = Some(g("Priority").into());
        }
        // "Source: glibc (2.36-9)" or "Source: glibc"; defaults are the binary's own.
        let src_field = g("Source");
        let (src, srcver) = match src_field.split_once(" (") {
            Some((n, v)) => (n.trim(), v.trim_end_matches(')').trim()),
            None if !src_field.is_empty() => (src_field.trim(), version),
            None => (name, version),
        };
        if src != name || srcver != version {
            p.source = Some(Source { name: src.into(), version: Some(srcver.into()) });
        }
        let rel: Vec<&str> = [g("Pre-Depends"), g("Depends")].into_iter().filter(|x| !x.is_empty()).collect();
        let requires = parse_relations(&rel.join(", "));
        let provides = parse_relations(g("Provides")).into_iter().map(|g| g[0].clone()).collect();
        pkgs.push(DpkgEntry { pkg: p, requires, provides });
    }
    (pkgs, problems)
}

/// Auto-installed (name, arch) pairs from apt's extended_states.
pub fn parse_extended_states(text: &str) -> HashSet<(String, String)> {
    parse_deb822(text)
        .into_iter()
        .filter(|st| st.get("Auto-Installed").map(String::as_str) == Some("1"))
        .filter_map(|st| Some((st.get("Package")?.clone(), st.get("Architecture").cloned().unwrap_or_default())))
        .collect()
}

/// dpkg's native architecture (the arch of dpkg itself) and the foreign
/// architectures enabled with `dpkg --add-architecture`.
pub fn dpkg_arches(dir: &Path, stanzas: Option<&[BTreeMap<String, String>]>) -> (Option<String>, Vec<String>) {
    let list: Vec<String> =
        read_text_opt(dir.join("arch")).unwrap_or_default().split_whitespace().map(String::from).collect();
    let from_status = |sts: &[BTreeMap<String, String>]| {
        sts.iter()
            .find(|s| {
                s.get("Package").map(String::as_str) == Some("dpkg")
                    && status_abbrev(s.get("Status").map(String::as_str).unwrap_or("")).as_bytes()[1] == b'i'
            })
            .and_then(|s| s.get("Architecture").cloned())
    };
    let native = match stanzas {
        Some(sts) => from_status(sts),
        None => read_status(dir).ok().and_then(|sts| from_status(&sts)),
    }
    .or_else(|| list.first().cloned());
    let mut foreign: Vec<String> = list.into_iter().filter(|a| Some(a) != native.as_ref()).collect();
    foreign.sort();
    foreign.dedup();
    (native, foreign)
}

/// "a (>= 1) | b:any, c [amd64], d <!nocheck>" -> [[a, b], [c], [d]]
pub fn parse_relations(text: &str) -> Vec<Vec<String>> {
    let strip = |s: &str| -> String {
        let mut out = String::new();
        // Drop "(>= 1)", "[amd64]" and "<!nocheck>"; only the matching
        // closer ends a group, so the '>' in "(>= 1)" is not a closer.
        let mut closer: Option<char> = None;
        for ch in s.chars() {
            match (closer, ch) {
                (None, '(') => closer = Some(')'),
                (None, '[') => closer = Some(']'),
                (None, '<') => closer = Some('>'),
                (None, c) => out.push(c),
                (Some(c), x) if c == x => closer = None,
                _ => {}
            }
        }
        out.trim().to_string()
    };
    text.split(',')
        .filter_map(|clause| {
            let alts: Vec<String> = clause
                .split('|')
                .map(strip)
                .filter(|a| !a.is_empty())
                .map(|a| a.split(':').next().unwrap_or("").to_string())
                .collect();
            if alts.is_empty() {
                None
            } else {
                Some(alts)
            }
        })
        .collect()
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct IndexHit {
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub filename: Option<String>,
}

pub type Triple = (String, String, String);

/// Pull integrity data for (name, arch, version) triples out of a Packages
/// index without materialising every stanza (indexes are large).
pub fn scan_packages_index(text: &str, wanted: &HashSet<Triple>) -> HashMap<Triple, IndexHit> {
    let mut found = HashMap::new();
    let mut cur: HashMap<&str, &str> = HashMap::new();
    let flush = |cur: &mut HashMap<&str, &str>, found: &mut HashMap<Triple, IndexHit>| {
        if cur.is_empty() {
            return;
        }
        let g = |k: &str| cur.get(k).copied().unwrap_or("").to_string();
        let key = (g("Package"), g("Architecture"), g("Version"));
        if wanted.contains(&key) && !found.contains_key(&key) {
            found.insert(
                key,
                IndexHit {
                    sha256: cur.get("SHA256").map(|s| s.to_string()),
                    size: cur.get("Size").and_then(|s| s.parse().ok()),
                    filename: cur.get("Filename").map(|s| s.to_string()),
                },
            );
        }
        cur.clear();
    };
    for line in text.lines() {
        if line.is_empty() {
            flush(&mut cur, &mut found);
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            if matches!(k, "Package" | "Architecture" | "Version" | "SHA256" | "Size" | "Filename") {
                cur.insert(k, v.trim());
            }
        }
    }
    flush(&mut cur, &mut found);
    found
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReleaseInfo {
    pub origin: String,
    pub label: String,
    pub suite: String,
    pub codename: String,
    pub version: String,
    /// ISO 8601 publication time.
    pub date: String,
}

/// The header of an (In)Release file, ignoring the PGP armor around it.
pub fn parse_release(text: &str) -> ReleaseInfo {
    let mut body = String::new();
    let mut lines = text.lines();
    if text.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
        for l in lines.by_ref() {
            if l.trim().is_empty() {
                break; // armor headers end at the first blank line
            }
        }
    }
    for l in lines {
        if l.starts_with("-----BEGIN PGP SIGNATURE-----") {
            break;
        }
        body.push_str(l);
        body.push('\n');
    }
    let st = parse_deb822(&body).into_iter().next().unwrap_or_default();
    let g = |k: &str| st.get(k).map(|v| v.lines().next().unwrap_or("").trim().to_string()).unwrap_or_default();
    ReleaseInfo {
        origin: g("Origin"),
        label: g("Label"),
        suite: g("Suite"),
        codename: g("Codename"),
        version: g("Version"),
        date: rfc2822_to_iso(&g("Date")).unwrap_or_default(),
    }
}

/// apt's URItoFileName: drop scheme and credentials, %-quote special
/// characters, turn '/' into '_'. This is how files in
/// /var/lib/apt/lists are named.
pub fn uri_to_filename(uri: &str) -> String {
    let rest = uri.split_once("://").map(|x| x.1).unwrap_or(uri);
    let rest = match rest.split_once('/') {
        Some((host, path)) => format!("{}/{path}", host.rsplit_once('@').map(|x| x.1).unwrap_or(host)),
        None => rest.rsplit_once('@').map(|x| x.1).unwrap_or(rest).to_string(),
    };
    let mut out = String::new();
    for b in rest.bytes() {
        let c = b as char;
        if b <= 0x20 || b >= 0x7f || "\\|{}[]<>\"^~_=!@#$%^&*".contains(c) {
            out.push_str(&format!("%{b:02x}"));
        } else if c == '/' {
            out.push('_');
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct SourceEntry {
    pub uri: String,
    pub suite: String,
    pub components: Vec<String>,
    pub signed_by: String,
    pub trusted: bool,
}

/// Parse one-line (.list) and deb822 (.sources) entries.
pub fn parse_sources(files: &[(String, String)]) -> Vec<SourceEntry> {
    let mut out = Vec::new();
    for (path, text) in files {
        if path.ends_with(".sources") {
            for st in parse_deb822(text) {
                let get = |k: &str| st.get(k).cloned().unwrap_or_default();
                if get("Enabled").eq_ignore_ascii_case("no") || !get("Types").split_whitespace().any(|t| t == "deb") {
                    continue;
                }
                for uri in get("URIs").split_whitespace() {
                    for suite in get("Suites").split_whitespace() {
                        out.push(SourceEntry {
                            uri: uri.trim_end_matches('/').into(),
                            suite: suite.into(),
                            components: get("Components").split_whitespace().map(String::from).collect(),
                            signed_by: get("Signed-By"),
                            trusted: get("Trusted").eq_ignore_ascii_case("yes"),
                        });
                    }
                }
            }
            continue;
        }
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            let Some(mut rest) = line.strip_prefix("deb ") else { continue };
            rest = rest.trim();
            let mut opts = HashMap::new();
            if let Some(r) = rest.strip_prefix('[') {
                let (o, after) = r.split_once(']').unwrap_or((r, ""));
                for kv in o.split_whitespace() {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    opts.insert(k.to_string(), v.to_string());
                }
                rest = after.trim();
            }
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            out.push(SourceEntry {
                uri: parts[0].trim_end_matches('/').into(),
                suite: parts[1].into(),
                components: parts[2..].iter().map(|s| s.to_string()).collect(),
                signed_by: opts.get("signed-by").cloned().unwrap_or_default(),
                trusted: opts.get("trusted").map(String::as_str) == Some("yes"),
            });
        }
    }
    out
}

/// Licenses from a machine-readable debian/copyright file.
pub fn dep5_licenses(text: &str) -> Vec<String> {
    if !text.starts_with("Format:") {
        return vec![];
    }
    let mut lic = BTreeSet::new();
    for st in parse_deb822(text) {
        if let (Some(v), true) = (st.get("License"), st.contains_key("Files")) {
            let first = v.split('\n').next().unwrap_or("").trim();
            if !first.is_empty() {
                lic.insert(first.to_string());
            }
        }
    }
    lic.into_iter().collect()
}

#[derive(Debug, Clone)]
struct Target {
    file: String,
    uri: String,
    suite: String,
    component: String,
    arch: String,
    release: ReleaseInfo,
}

pub struct Apt;

fn native_or_empty(arches: &[String]) -> String {
    arches.first().cloned().unwrap_or_default()
}

impl Apt {
    fn dpkg(&self) -> Result<(Vec<DpkgEntry>, Vec<String>)> {
        Ok(parse_status(&read_status(&dpkg_dir())?))
    }

    /// Auto-installed marks, or None when apt is absent (dpkg-only system).
    fn auto_marks(&self) -> Option<HashSet<(String, String)>> {
        match read_text_opt(apt_state().join("extended_states")) {
            Some(t) => Some(parse_extended_states(&t)),
            None if apt_state().is_dir() => Some(HashSet::new()),
            None => None,
        }
    }

    /// Package indexes apt has downloaded, derived from the configured
    /// sources and apt's own list file naming.
    fn index_targets(&self) -> Vec<Target> {
        let mut files = Vec::new();
        let mut paths = vec![apt_etc().join("sources.list").to_string_lossy().into_owned()];
        let mut extra: Vec<String> = std::fs::read_dir(apt_etc().join("sources.list.d"))
            .map(|d| d.flatten().map(|e| e.path().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        extra.retain(|p| p.ends_with(".list") || p.ends_with(".sources"));
        extra.sort();
        paths.extend(extra);
        for p in paths {
            if let Some(t) = read_text_opt(&p) {
                files.push((p, t));
            }
        }
        let (native, foreign) = dpkg_arches(&dpkg_dir(), None);
        let mut arches: Vec<String> = native.into_iter().collect();
        arches.extend(foreign);
        arches.push("all".into());
        let lists = lists_dir();
        let lists = lists.as_path();
        let find = |base: &str| -> Option<String> {
            let name = uri_to_filename(base);
            ["", ".lz4", ".gz", ".xz", ".zst"]
                .iter()
                .map(|ext| lists.join(format!("{name}{ext}")))
                .find(|p| p.is_file())
                .map(|p| p.to_string_lossy().into_owned())
        };
        let mut out: Vec<Target> = Vec::new();
        let mut seen = HashSet::new();
        for src in parse_sources(&files) {
            let flat = src.suite.ends_with('/');
            let dist = if flat {
                format!("{}/{}", src.uri, src.suite.trim_start_matches("./"))
            } else {
                format!("{}/dists/{}/", src.uri, src.suite)
            };
            let release = ["InRelease", "Release"]
                .iter()
                .find_map(|r| read_text_opt(lists.join(uri_to_filename(&format!("{dist}{r}")))))
                .map(|t| parse_release(&t))
                .unwrap_or_default();
            let mut candidates: Vec<(String, String, String)> = Vec::new();
            if flat {
                candidates.push((format!("{dist}Packages"), String::new(), native_or_empty(&arches)));
            } else {
                for comp in &src.components {
                    for arch in &arches {
                        candidates.push((format!("{dist}{comp}/binary-{arch}/Packages"), comp.clone(), arch.clone()));
                    }
                }
            }
            for (base, component, arch) in candidates {
                if let Some(file) = find(&base) {
                    if seen.insert(file.clone()) {
                        out.push(Target {
                            file,
                            uri: src.uri.clone(),
                            suite: src.suite.clone(),
                            component,
                            arch,
                            release: release.clone(),
                        });
                    }
                }
            }
        }
        out
    }

    fn cat_index(&self, path: &str) -> String {
        read_text_decompressed(path).unwrap_or_default()
    }

    /// (name, arch, version) -> (hit, indexes it was found in)
    fn scan(&self, wanted: &HashSet<Triple>, targets: &[Target]) -> HashMap<Triple, (IndexHit, Vec<usize>)> {
        let mut res: HashMap<Triple, (IndexHit, Vec<usize>)> = HashMap::new();
        if wanted.is_empty() {
            return res;
        }
        for (i, t) in targets.iter().enumerate() {
            for (k, hit) in scan_packages_index(&self.cat_index(&t.file), wanted) {
                res.entry(k).or_insert_with(|| (hit, vec![])).1.push(i);
            }
        }
        res
    }

    fn repo_records(&self, targets: &[Target], opts: &Options) -> (Vec<Value>, Vec<String>) {
        let mut files = Vec::new();
        let mut paths = vec![apt_etc().join("sources.list").to_string_lossy().into_owned()];
        let mut extra: Vec<String> = std::fs::read_dir(apt_etc().join("sources.list.d"))
            .map(|d| d.flatten().map(|e| e.path().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        extra.retain(|p| p.ends_with(".list") || p.ends_with(".sources"));
        extra.sort();
        paths.extend(extra);
        for p in paths {
            if let Some(t) = read_text_opt(&p) {
                files.push((p, t));
            }
        }
        let sources = parse_sources(&files);
        let mut repos: BTreeMap<String, Value> = BTreeMap::new();
        let mut ids = Vec::with_capacity(targets.len());
        for t in targets {
            let rel = &t.release;
            let rid = if !rel.origin.is_empty() {
                let suite = if rel.suite.is_empty() { &t.suite } else { &rel.suite };
                format!("{}:{suite}/{}", rel.origin, t.component)
            } else {
                let host = t.uri.split_once("://").map(|x| x.1).unwrap_or(&t.uri);
                format!("{host}:{}/{}", t.suite, t.component)
            };
            ids.push(rid.clone());
            if let Some(r) = repos.get_mut(&rid) {
                for (field, val) in [("architectures", &t.arch), ("uris", &t.uri)] {
                    let arr = r[field].as_array_mut().expect("array");
                    if !arr.iter().any(|x| x == val) {
                        arr.push(json!(val));
                    }
                }
                continue;
            }
            let mut r = json!({"id": rid, "uris": [t.uri], "suite": t.suite, "component": t.component, "architectures": [t.arch]});
            for (v, field) in
                [(&rel.origin, "origin"), (&rel.label, "label"), (&rel.codename, "codename"), (&rel.version, "version")]
            {
                if !v.is_empty() {
                    r[field] = json!(v);
                }
            }
            if !rel.date.is_empty() {
                // The archive's own publication time: the right snapshot to ask
                // for, independent of when (or with which clock) we ran.
                r["date"] = json!(rel.date);
            }
            if let Some(src) = sources.iter().find(|s| s.uri == t.uri && s.suite == t.suite) {
                if src.trusted {
                    r["trusted"] = json!(true);
                }
                if let Some(k) = keyring(&src.signed_by, opts) {
                    r["signedBy"] = k;
                }
            }
            repos.insert(rid, r);
        }
        let mut out: Vec<Value> = repos.into_values().collect();
        for r in &mut out {
            for f in ["architectures", "uris"] {
                let arr = r[f].as_array_mut().expect("array");
                arr.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
            }
        }
        (out, ids)
    }

    fn translate(&self, section: &Section, src: &Platform, dst: &Platform) -> Vec<Package> {
        let (s, d) = (arch_name(src), arch_name(dst));
        section
            .packages
            .iter()
            .map(|p| {
                let mut q = p.clone();
                if q.arch() == s && s != d {
                    q.arch = Some(d.clone());
                    q.cross_arch = true;
                }
                q
            })
            .collect()
    }

    /// Recreate missing third-party repositories. apt needs one entry per
    /// (URI, suite) with all components and a single Signed-By, otherwise
    /// it fails with "Conflicting values set for option Signed-By".
    pub fn add_repos(&self, plan: &mut Plan, section: &Section, configured: &HashSet<String>) {
        // (uri, suite) -> (components, signing key, repo ids)
        type Group = (Vec<String>, Value, Vec<String>);
        let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
        for r in section.repos() {
            let key = r.get("signedBy").cloned().unwrap_or(Value::Null);
            let uris = vstrs(r, "uris");
            if key.get("data").and_then(Value::as_str).is_none()
                || uris.is_empty()
                || uris.iter().any(|u| configured.contains(u))
            {
                continue;
            }
            let g = groups.entry((uris[0].clone(), vstr(r, "suite").into())).or_insert_with(|| (vec![], key, vec![]));
            let comp = vstr(r, "component");
            if !comp.is_empty() && !g.0.iter().any(|c| c == comp) {
                g.0.push(comp.into());
            }
            g.2.push(vstr(r, "id").into());
        }
        let mut written = HashSet::new();
        for ((uri, suite), (comps, key, ids)) in groups {
            let sha = vstr(&key, "sha256");
            let ext = if key.get("armored").and_then(Value::as_bool).unwrap_or(false) { ".asc" } else { ".gpg" };
            let kpath = apt_etc()
                .join(format!("keyrings/matsya-{}{ext}", &sha[..sha.len().min(16)]))
                .to_string_lossy()
                .into_owned();
            if written.insert(kpath.clone()) {
                plan.add(Step::write(
                    format!("keyring sha256 {sha}"),
                    Write { path: kpath.clone(), content: vstr(&key, "data").into(), base64: true, mode: 0o644 },
                ));
            }
            let host = uri.split_once("://").map(|x| x.1).unwrap_or(&uri);
            let safe: String = format!("{host}-{suite}")
                .to_ascii_lowercase()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect::<String>()
                .split('-')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("-");
            let mut content = format!("Types: deb\nURIs: {uri}\nSuites: {suite}\n");
            if !comps.is_empty() {
                content += &format!("Components: {}\n", comps.join(" "));
            }
            content += &format!("Signed-By: {kpath}\n");
            plan.add(Step::write(
                format!("add repository {}", ids.join(", ")),
                Write {
                    path: apt_etc()
                        .join(format!("sources.list.d/matsya-{safe}.sources"))
                        .to_string_lossy()
                        .into_owned(),
                    content,
                    base64: false,
                    mode: 0o644,
                },
            ));
        }
    }
}

fn reason(p: &Package, auto: &Option<HashSet<(String, String)>>, native: &str) -> String {
    let Some(auto) = auto else { return "manual".into() };
    // apt records Architecture: all packages under the native arch.
    let arch = if p.arch() == "all" { native } else { p.arch() };
    if auto.contains(&(p.name.clone(), arch.to_string())) || auto.contains(&(p.name.clone(), p.arch().to_string())) {
        "dependency".into()
    } else {
        "manual".into()
    }
}

/// The package whose file list contains `path` (dpkg -S).
fn dpkg_owner(path: &str) -> Option<String> {
    let dir = dpkg_dir().join("info");
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(pkg) = name.strip_suffix(".list") else { continue };
        if read_text_opt(e.path()).is_some_and(|t| t.lines().any(|l| l == path)) {
            return Some(pkg.split(':').next().unwrap_or(pkg).to_string());
        }
    }
    None
}

fn keyring(signed_by: &str, opts: &Options) -> Option<Value> {
    use base64::Engine;
    let b64 = |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);
    let s = signed_by.trim();
    if s.is_empty() {
        return None;
    }
    if s.starts_with("-----BEGIN") || s.contains('\n') {
        // deb822 allows the key inline; the lock becomes its source of truth.
        let mut v = json!({"inline": true, "armored": true, "sha256": sha256_hex(s.as_bytes())});
        if opts.embed_keys {
            v["data"] = json!(b64(s.as_bytes()));
        }
        return Some(v);
    }
    let path = s.split_whitespace().next().unwrap_or("");
    if !Path::new(path).is_file() {
        // Could be a fingerprint list; record it verbatim.
        return Some(json!({"fingerprints": s.split_whitespace().collect::<Vec<_>>()}));
    }
    let mut rec = json!({"path": path, "sha256": sha256_file(path).ok()?});
    if let Some(pkg) = dpkg_owner(path) {
        rec["package"] = json!(pkg);
    } else if opts.embed_keys {
        // Third-party key: embed it so another machine can trust the same repo.
        let raw = std::fs::read(path).ok()?;
        rec["armored"] = json!(String::from_utf8_lossy(&raw).trim_start().starts_with("-----BEGIN"));
        rec["data"] = json!(b64(&raw));
    }
    Some(rec)
}

fn licenses_for(name: &str) -> Vec<String> {
    read_text_opt(doc_dir().join(name).join("copyright")).map(|t| dep5_licenses(&t)).unwrap_or_default()
}

/// What `apt-get --version` / `dpkg --version` print, from the status db.
fn tool_version(stanzas: &[BTreeMap<String, String>], native: &str) -> String {
    let ver = |n: &str| {
        stanzas.iter().find(|s| s.get("Package").map(String::as_str) == Some(n)).and_then(|s| s.get("Version").cloned())
    };
    match (ver("apt"), ver("dpkg")) {
        (Some(v), _) => format!("apt {v} ({native})"),
        (None, Some(v)) => format!("Debian 'dpkg' package management program version {v} ({native})."),
        _ => String::new(),
    }
}

/// Snapshot URLs for a package, newest knowledge first: the repository's
/// publication time, then the capture time as a fallback.
pub fn snapshot_urls(p: &Package, repos: &HashMap<String, &Value>, captured_ts: &str) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    let Some(filename) = &p.filename else { return urls };
    for rid in p.repositories.iter().flatten() {
        let Some(r) = repos.get(rid) else { continue };
        let base = match vstr(r, "origin") {
            "Debian" => "https://snapshot.debian.org/archive/{archive}/{ts}/",
            "Ubuntu" => "https://snapshot.ubuntu.com/{archive}/{ts}/",
            _ => continue,
        };
        let mut stamps = vec![compact_ts(vstr(r, "date"))];
        stamps.push(captured_ts.to_string());
        stamps.retain(|s| !s.is_empty());
        stamps.dedup();
        for uri in vstrs(r, "uris") {
            let archive = uri.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string();
            let mut names = vec![archive.clone()];
            // Ubuntu mirrors carry ports under /ubuntu on some clouds.
            match archive.as_str() {
                "ubuntu" => names.push("ubuntu-ports".into()),
                "ubuntu-ports" => names.push("ubuntu".into()),
                _ => {}
            }
            for ts in &stamps {
                for n in &names {
                    let u = base.replace("{archive}", n).replace("{ts}", ts) + filename;
                    if !urls.contains(&u) {
                        urls.push(u);
                    }
                }
            }
        }
    }
    urls
}

impl Manager for Apt {
    fn name(&self) -> &'static str {
        "apt"
    }

    fn available(&self) -> bool {
        dpkg_dir().join("status").is_file()
    }

    fn key_of(&self, pkg: &Package, plat: &Platform) -> String {
        let native = arch_name(plat);
        let a = pkg.arch();
        if a == native || a == "all" || a.is_empty() {
            pkg.name.clone()
        } else {
            format!("{}:{a}", pkg.name)
        }
    }

    fn installed(&self, plat: &Platform) -> Result<Vec<Package>> {
        let (entries, _) = self.dpkg()?;
        let manual = self.auto_marks();
        let native = arch_name(plat);
        Ok(entries
            .into_iter()
            .map(|e| {
                let mut p = e.pkg;
                p.reason = Some(reason(&p, &manual, &native));
                p
            })
            .collect())
    }

    fn capture(&self, plat: &Platform, opts: &Options) -> Result<Section> {
        let stanzas = read_status(&dpkg_dir())?;
        let (entries, problems) = parse_status(&stanzas);
        for m in problems {
            warn(&m);
        }
        let manual = self.auto_marks();
        if manual.is_none() {
            warn("apt is not installed; every package is recorded as manually installed");
        }
        let native = arch_name(plat);
        let mut requires = HashMap::new();
        let mut provides = HashMap::new();
        let mut pkgs = Vec::new();
        let mut keys = Vec::new();
        for e in entries {
            let k = self.key_of(&e.pkg, plat);
            requires.insert(k.clone(), e.requires);
            provides.insert(k.clone(), e.provides);
            keys.push(k);
            pkgs.push(e.pkg);
        }
        resolve_dependencies(&mut pkgs, &keys, &requires, &provides);

        let targets = self.index_targets();
        let (repos, ids) = self.repo_records(&targets, opts);
        let wanted: HashSet<Triple> =
            pkgs.iter().map(|p| (p.name.clone(), p.arch().into(), p.version.clone())).collect();
        let found = self.scan(&wanted, &targets);
        let mut local = Vec::new();
        for p in &mut pkgs {
            p.reason = Some(reason(p, &manual, &native));
            match found.get(&(p.name.clone(), p.arch().into(), p.version.clone())) {
                Some((hit, idx)) => {
                    p.sha256 = hit.sha256.clone();
                    p.size = hit.size;
                    p.filename = hit.filename.clone();
                    let set: BTreeSet<String> = idx.iter().map(|i| ids[*i].clone()).collect();
                    p.repositories = Some(set.into_iter().collect());
                }
                None => {
                    p.repositories = Some(vec![]);
                    local.push(format!("{}={}", p.name, p.version));
                }
            }
            if opts.licenses {
                p.licenses = licenses_for(&p.name);
            }
        }
        if !local.is_empty() {
            let more = if local.len() > 10 { " ..." } else { "" };
            warn(&format!(
                "{} apt package(s) are not available from any configured repository (locally installed, removed upstream, \
                 or stale indexes - run apt-get update): {}{more}",
                local.len(),
                local.iter().take(10).cloned().collect::<Vec<_>>().join(", ")
            ));
        }
        if targets.is_empty() {
            warn("no apt package indexes found (was /var/lib/apt/lists cleaned?); run apt-get update before locking to record checksums");
        }
        pkgs.sort_by(|a, b| (&a.name, a.arch()).cmp(&(&b.name, b.arch())));
        Ok(Section {
            tool: Some(tool_version(&stanzas, &native)),
            repositories: Some(repos),
            foreign_architectures: Some(dpkg_arches(&dpkg_dir(), Some(&stanzas)).1),
            packages: pkgs,
            ..Default::default()
        })
    }

    fn prepare(&self, section: &Section, src: &Platform, dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("apt (prepare)");
        let native = arch_name(dst);
        let need: BTreeSet<String> = self
            .translate(section, src, dst)
            .iter()
            .map(|p| p.arch().to_string())
            .filter(|a| a != &native && a != "all" && !a.is_empty())
            .collect();
        let have: HashSet<String> = dpkg_arches(&dpkg_dir(), None).1.into_iter().collect();
        for a in need {
            if !have.contains(&a) {
                plan.add(Step::cmd(format!("enable multiarch for {a}"), ["dpkg", "--add-architecture", &a]));
            }
        }
        if opts.add_repos {
            let configured: HashSet<String> = self.index_targets().into_iter().map(|t| t.uri).collect();
            self.add_repos(&mut plan, section, &configured);
        }
        if opts.refresh || !plan.steps.is_empty() {
            plan.add(Step::cmd("refresh package indexes", ["apt-get", "update"]));
        }
        Ok(plan)
    }

    fn plan(&self, section: &Section, src: &Platform, dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("apt");
        let mut pkgs = self.translate(section, src, dst);
        if opts.roots_only {
            pkgs.retain(Package::is_manual);
        }
        let installed = self.installed(dst)?;
        let current = by_key(self, &installed, dst);
        let todo: Vec<&Package> =
            pkgs.iter().filter(|p| current.get(&self.key_of(p, dst)).map(|c| &c.version) != Some(&p.version)).collect();

        let targets = self.index_targets();
        let wanted: HashSet<Triple> =
            todo.iter().map(|p| (p.name.clone(), p.arch().into(), p.version.clone())).collect();
        let found = self.scan(&wanted, &targets);
        let repos: HashMap<String, &Value> = section.repos().iter().map(|r| (vstr(r, "id").to_string(), r)).collect();
        let ts = compact_ts(&opts.captured_at);
        let mut specs = Vec::new();
        for p in &todo {
            let (name, arch, ver) = (&p.name, p.arch(), &p.version);
            if found.contains_key(&(name.clone(), arch.into(), ver.clone())) {
                specs.push(format!("{name}:{arch}={ver}"));
                continue;
            }
            let urls = if opts.snapshot && p.sha256.is_some() && !p.cross_arch {
                snapshot_urls(p, &repos, &ts)
            } else {
                vec![]
            };
            if !urls.is_empty() {
                let base = p.filename.as_deref().unwrap_or("").rsplit('/').next().unwrap_or("").to_string();
                let dest = format!("{}/apt/{base}", opts.cache_dir);
                plan.add(Step::fetch(
                    format!("{name} {ver} is gone from the mirrors; fetching from snapshot"),
                    Fetch { urls, dest: dest.clone(), sha256: p.sha256.clone(), rpm_payload: None },
                ));
                specs.push(dest);
                continue;
            }
            let mut why = "not in any configured repository".to_string();
            if p.cross_arch {
                why += &format!(" for {arch} (lock was captured on another architecture)");
            }
            if opts.best_effort {
                plan.warnings.push(format!("{name} {ver} {why}; installing the newest available version instead"));
                specs.push(format!("{name}:{arch}"));
            } else {
                plan.unresolved.push(format!("{name}:{arch}={ver} ({why})"));
            }
        }
        if !specs.is_empty() {
            specs.sort();
            // One transaction: apt must see the whole closure to solve
            // downgrades and replacements consistently.
            let mut argv: Vec<String> = [
                "apt-get",
                "install",
                "-y",
                "--no-install-recommends",
                "--allow-downgrades",
                "--allow-change-held-packages",
                "-o",
                "Dpkg::Options::=--force-confold",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            argv.extend(specs.iter().cloned());
            plan.add(
                Step::cmd(format!("install {} package(s) at locked versions", specs.len()), argv)
                    .with_env("DEBIAN_FRONTEND", "noninteractive"),
            );
        }

        // Only touch marks that differ; anything installed now was marked
        // manual by apt-get, so it is compared against "not manual yet".
        let touched: HashSet<String> = todo.iter().map(|p| self.key_of(p, dst)).collect();
        let needs = |p: &Package, want: &str| {
            let k = self.key_of(p, dst);
            touched.contains(&k) || current.get(&k).map(|c| c.reason()) != Some(want)
        };
        let mut manual: Vec<String> =
            pkgs.iter().filter(|p| p.is_manual() && needs(p, "manual")).map(|p| self.key_of(p, dst)).collect();
        let mut auto: Vec<String> =
            pkgs.iter().filter(|p| !p.is_manual() && needs(p, "dependency")).map(|p| self.key_of(p, dst)).collect();
        manual.sort();
        auto.sort();
        if !manual.is_empty() {
            plan.add(Step::cmd(
                "restore manual-install marks",
                ["apt-mark".to_string(), "manual".into()].into_iter().chain(manual),
            ));
        }
        if !auto.is_empty() && !opts.roots_only {
            plan.add(Step::cmd(
                "restore automatic-install marks",
                ["apt-mark".to_string(), "auto".into()].into_iter().chain(auto),
            ));
        }
        let mut held: Vec<String> = pkgs
            .iter()
            .filter(|p| {
                Package::flag(&p.held) && !current.get(&self.key_of(p, dst)).is_some_and(|c| Package::flag(&c.held))
            })
            .map(|p| self.key_of(p, dst))
            .collect();
        held.sort();
        if !held.is_empty() {
            plan.add(Step::cmd("restore holds", ["apt-mark".to_string(), "hold".into()].into_iter().chain(held)));
        }
        if opts.prune {
            let locked: HashSet<String> =
                self.translate(section, src, dst).iter().map(|p| self.key_of(p, dst)).collect();
            let extra: Vec<String> = current
                .iter()
                .filter(|(k, p)| {
                    !locked.contains(*k) && !Package::flag(&p.essential) && p.priority.as_deref() != Some("required")
                })
                .map(|(k, _)| k.clone())
                .collect();
            if !extra.is_empty() {
                plan.add(
                    Step::cmd(
                        format!("remove {} package(s) not in the lock", extra.len()),
                        ["apt-get".to_string(), "purge".into(), "-y".into()].into_iter().chain(extra),
                    )
                    .with_env("DEBIAN_FRONTEND", "noninteractive"),
                );
            }
        }
        plan.summary = vec![
            ("install".into(), specs.len()),
            ("unchanged".into(), pkgs.len() - todo.len()),
            ("unresolved".into(), plan.unresolved.len()),
        ];
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    fn deb12() -> Platform {
        crate::platform::from_os_release("ID=debian\nVERSION_ID=12\n", "x86_64".into())
    }

    #[test]
    fn dpkg_states() {
        let (entries, problems) = parse_status(&parse_deb822(&fixture("dpkg-status")));
        let names: Vec<(String, String)> = entries.iter().map(|e| (e.pkg.name.clone(), e.pkg.arch().into())).collect();
        assert!(names.contains(&("libc6".into(), "i386".into())));
        assert!(!names.iter().any(|(n, _)| n == "oldpkg" || n == "halfpkg"));
        assert!(problems.iter().any(|p| p.contains("halfpkg")));
        let curl = entries.iter().find(|e| e.pkg.name == "curl").unwrap();
        assert_eq!(curl.pkg.held, Some(true));
        let bash = entries.iter().find(|e| e.pkg.name == "bash").unwrap();
        assert_eq!(bash.pkg.essential, Some(true));
        assert_eq!(bash.pkg.source, Some(Source { name: "bash".into(), version: Some("5.2.15-2".into()) }));
    }

    #[test]
    fn relations() {
        assert_eq!(
            parse_relations("a (>= 1) | b:any, c [amd64], d <!nocheck>"),
            vec![vec!["a".to_string(), "b".into()], vec!["c".into()], vec!["d".into()]]
        );
    }

    #[test]
    fn dependency_resolution() {
        let (entries, _) = parse_status(&parse_deb822(&fixture("dpkg-status")));
        let plat = deb12();
        let a = Apt;
        let keys: Vec<String> = entries.iter().map(|e| a.key_of(&e.pkg, &plat)).collect();
        let req = keys.iter().zip(&entries).map(|(k, e)| (k.clone(), e.requires.clone())).collect();
        let prov = keys.iter().zip(&entries).map(|(k, e)| (k.clone(), e.provides.clone())).collect();
        let mut pkgs: Vec<Package> = entries.into_iter().map(|e| e.pkg).collect();
        resolve_dependencies(&mut pkgs, &keys, &req, &prov);
        let libcurl = pkgs.iter().find(|p| p.name == "libcurl4").unwrap();
        assert!(libcurl.dependencies.contains(&"postfix".to_string())); // via Provides
        assert!(libcurl.dependencies.contains(&"libc6".to_string())); // libc6:any -> native
        assert!(!libcurl.dependencies.contains(&"libc6:i386".to_string()));
    }

    #[test]
    fn keys() {
        let p = |n: &str, a: &str| {
            let mut x = Package::new(n, "1");
            x.arch = Some(a.into());
            x
        };
        assert_eq!(Apt.key_of(&p("libc6", "i386"), &deb12()), "libc6:i386");
        assert_eq!(Apt.key_of(&p("libc6", "amd64"), &deb12()), "libc6");
        assert_eq!(Apt.key_of(&p("tzdata", "all"), &deb12()), "tzdata");
    }

    #[test]
    fn index_scan() {
        let wanted: HashSet<Triple> = [
            ("curl".to_string(), "amd64".to_string(), "7.88.1-10+deb12u5".to_string()),
            ("ca-certificates".into(), "all".into(), "20230311".into()),
            ("x".into(), "amd64".into(), "1".into()),
        ]
        .into_iter()
        .collect();
        let found = scan_packages_index(&fixture("Packages"), &wanted);
        assert_eq!(found.len(), 2);
        let c = &found[&("curl".to_string(), "amd64".to_string(), "7.88.1-10+deb12u5".to_string())];
        assert_eq!(c.size, Some(316176));
        assert!(c.sha256.as_deref().unwrap().starts_with("0f4c"));
    }

    #[test]
    fn termux_architecture_names() {
        let termux = |arch: &str| Platform {
            os: Some("android".into()),
            distro: Some("termux".into()),
            release: Some("rolling".into()),
            arch: Some(arch.into()),
            ..Default::default()
        };
        assert_eq!(arch_name(&termux("aarch64")), "aarch64");
        assert_eq!(arch_name(&termux("armv7")), "arm");
        assert_eq!(arch_name(&termux("x86_64")), "x86_64");
        assert_eq!(arch_name(&deb12()), "amd64");
        // Termux packages are keyed by bare name like Debian's native ones.
        let mut p = Package::new("jq", "1.7.1");
        p.arch = Some("aarch64".into());
        assert_eq!(Apt.key_of(&p, &termux("aarch64")), "jq");
        p.arch = Some("all".into());
        assert_eq!(Apt.key_of(&p, &termux("aarch64")), "jq");
        assert_eq!(crate::platform::normalize_arch("arm"), "armv7");
    }

    #[test]
    fn release_files() {
        let r = parse_release(&fixture("InRelease"));
        assert_eq!(
            (r.origin.as_str(), r.suite.as_str(), r.codename.as_str()),
            ("Debian", "stable-security", "bookworm-security")
        );
        assert_eq!(r.label, "Debian-Security");
        assert_eq!(r.date, "2024-10-26T10:00:00Z");
    }

    #[test]
    fn list_file_names() {
        assert_eq!(
            uri_to_filename("http://eu-west-2.ec2.archive.ubuntu.com/ubuntu/dists/resolute/main/binary-arm64/Packages"),
            "eu-west-2.ec2.archive.ubuntu.com_ubuntu_dists_resolute_main_binary-arm64_Packages"
        );
        assert_eq!(
            uri_to_filename("https://user:pw@example.com/a_b~c/dists/x/InRelease"),
            "example.com_a%5fb%7ec_dists_x_InRelease"
        );
        assert_eq!(uri_to_filename("http://host:8080/repo/./Packages"), "host:8080_repo_._Packages");
    }

    #[test]
    fn extended_states() {
        let auto = Some(parse_extended_states(&fixture("extended_states")));
        let mk = |n: &str, a: &str| {
            let mut p = Package::new(n, "1");
            p.arch = Some(a.into());
            p
        };
        assert_eq!(reason(&mk("libcurl4", "amd64"), &auto, "amd64"), "dependency");
        assert_eq!(reason(&mk("ca-certificates", "all"), &auto, "amd64"), "dependency"); // recorded under the native arch
        assert_eq!(reason(&mk("curl", "amd64"), &auto, "amd64"), "manual");
        assert_eq!(reason(&mk("curl", "amd64"), &None, "amd64"), "manual");
    }

    #[test]
    fn status_abbreviations() {
        assert_eq!(status_abbrev("install ok installed"), "ii ");
        assert_eq!(status_abbrev("hold ok installed"), "hi ");
        assert_eq!(status_abbrev("deinstall ok config-files"), "rc ");
        assert_eq!(status_abbrev("install reinstreq half-installed"), "iHR");
    }

    #[test]
    fn sources() {
        let e = parse_sources(&[
            ("/etc/apt/sources.list.d/debian.sources".into(), fixture("debian.sources")),
            ("/etc/apt/sources.list.d/docker.list".into(), fixture("docker.list")),
        ]);
        assert!(e.iter().any(|s| s.uri == "http://deb.debian.org/debian" && s.suite == "bookworm-updates"));
        assert!(!e.iter().any(|s| s.uri.contains("disabled") || s.uri.contains("example.com/src")));
        let docker = e.iter().find(|s| s.uri.contains("docker")).unwrap();
        assert_eq!(docker.signed_by, "/etc/apt/keyrings/docker.asc");
        let insecure = e.iter().find(|s| s.uri.contains("insecure")).unwrap();
        assert!(insecure.trusted);
        assert_eq!(insecure.suite, "./");
    }

    #[test]
    fn dep5() {
        assert_eq!(dep5_licenses(&fixture("copyright")), vec!["MIT", "curl"]);
        assert!(dep5_licenses("not machine readable").is_empty());
    }

    #[test]
    fn snapshots() {
        let mut p = Package::new("curl", "1");
        p.filename = Some("pool/main/c/curl/curl_1_amd64.deb".into());
        p.repositories = Some(vec!["Debian:stable-security/main".into()]);
        let r = json!({"origin": "Debian", "uris": ["http://deb.debian.org/debian-security"], "date": "2024-01-01T00:00:00Z"});
        let repos = HashMap::from([("Debian:stable-security/main".to_string(), &r)]);
        let urls = snapshot_urls(&p, &repos, "20240102T000000Z");
        assert_eq!(
            urls,
            vec![
                "https://snapshot.debian.org/archive/debian-security/20240101T000000Z/pool/main/c/curl/curl_1_amd64.deb",
                "https://snapshot.debian.org/archive/debian-security/20240102T000000Z/pool/main/c/curl/curl_1_amd64.deb",
            ]
        );
        let other = json!({"origin": "Docker", "uris": ["x"]});
        assert!(
            snapshot_urls(&p, &HashMap::from([("Debian:stable-security/main".to_string(), &other)]), "t").is_empty()
        );
    }

    #[test]
    fn add_repos_groups_components() {
        let key = json!({"sha256": "ab".repeat(32), "data": "a2V5", "armored": true});
        let sec = Section {
            repositories: Some(vec![
                json!({"id": "Docker:bookworm/stable", "uris": ["https://download.docker.com/linux/debian"], "suite": "bookworm", "component": "stable", "signedBy": key}),
                json!({"id": "Docker:bookworm/test", "uris": ["https://download.docker.com/linux/debian"], "suite": "bookworm", "component": "test", "signedBy": key}),
                json!({"id": "Debian:stable/main", "uris": ["http://deb.debian.org/debian"], "suite": "bookworm", "component": "main", "signedBy": {"sha256": "x", "package": "debian-archive-keyring"}}),
            ]),
            ..Default::default()
        };
        let mut plan = Plan::new("apt");
        Apt.add_repos(&mut plan, &sec, &HashSet::new());
        let writes: Vec<&Write> = plan.steps.iter().filter_map(|s| s.write.as_ref()).collect();
        assert_eq!(writes.len(), 2);
        let src = writes.iter().find(|w| w.path.ends_with(".sources")).unwrap();
        assert!(src.content.contains("Components: stable test"));
        assert_eq!(src.content.matches("Signed-By:").count(), 1);
    }
}
