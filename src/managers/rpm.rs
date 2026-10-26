//! RPM based distributions: Fedora, RHEL/CentOS/Rocky/Alma, Amazon Linux,
//! openSUSE/SLES. Inventory is read natively from the rpm database (sqlite,
//! ndb or BerkeleyDB) and the frontends' own state files; only `apply` runs
//! the frontend (dnf5, dnf, yum, zypper) to install packages.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{batches, by_key, resolve_dependencies, Manager, Options};
use crate::bail;
use crate::formats::rpmdb::{self, Header};
use crate::formats::sqlite;
use crate::model::{vstr, Package, Section, Source};
use crate::plan::{Fetch, Plan, Step, Write};
use crate::platform::Platform;
use crate::util::{has, package_manager_query, read_text_opt, split_lines, warn, Result};

const NOARCH: &str = "noarch";
/// Fedora's build system keeps every build ever shipped.
const KOJI: &str = "https://kojipkgs.fedoraproject.org/packages/{src}/{version}/{release}/{arch}/{name}-{version}-{release}.{arch}.rpm";

/// dnf's default installonlypkgs plus zypper's multiversion kernels.
const INSTALLONLY: &[&str] = &[
    "kernel",
    "kernel-core",
    "kernel-modules",
    "kernel-modules-core",
    "kernel-modules-extra",
    "kernel-modules-internal",
    "kernel-devel",
    "kernel-devel-matched",
    "kernel-uki-virt",
    "kernel-uek",
    "kernel-uek-core",
    "kernel-uek-modules",
    "kernel-default",
    "kernel-default-devel",
    "kernel-default-extra",
    "kernel-default-optional",
    "kernel-PAE",
    "kernel-rt",
    "kernel-rt-core",
    "installonlypkg",
];

fn none(s: &str) -> bool {
    s.is_empty() || s == "(none)"
}

/// A lock entry from an rpm header (None for gpg-pubkey pseudo packages).
pub fn package_from_header(h: &Header) -> Option<Package> {
    let name = h.string(rpmdb::NAME)?;
    if name == "gpg-pubkey" {
        return None; // imported signing keys masquerade as packages
    }
    let mut p = Package::new(
        name,
        format!("{}-{}", h.string(rpmdb::VERSION).unwrap_or(""), h.string(rpmdb::RELEASE).unwrap_or("")),
    );
    p.arch = Some(h.string(rpmdb::ARCH).unwrap_or("").into());
    if let Some(e) = h.int(rpmdb::EPOCH).filter(|e| *e != 0) {
        p.epoch = Some(json!(e));
    }
    let src = srpm_name(h.string(rpmdb::SOURCERPM).unwrap_or(""));
    if !src.is_empty() && src != name {
        p.source = Some(Source { name: src, version: None });
    }
    let opt = |v: Option<String>| v.filter(|x| !none(x));
    if let Some(l) = opt(h.string(rpmdb::LICENSE).map(String::from)) {
        p.licenses = vec![l];
    }
    p.payload_digest = opt(h.hex(rpmdb::PAYLOADDIGEST));
    p.sigmd5 = opt(h.hex(rpmdb::SIGMD5));
    p.vendor = opt(h.string(rpmdb::VENDOR).map(String::from));
    Some(p)
}

/// Flag packages that may be installed in several versions at once:
/// known install-only names, plus anything that actually is duplicated.
pub fn mark_installonly(pkgs: &mut [Package]) {
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    for p in pkgs.iter() {
        *seen.entry((p.name.clone(), p.arch().into())).or_default() += 1;
    }
    for p in pkgs.iter_mut() {
        if INSTALLONLY.contains(&p.name.as_str()) || seen[&(p.name.clone(), p.arch().to_string())] > 1 {
            p.installonly = Some(true);
        }
    }
}

/// bash-5.2.26-3.fc40.src.rpm -> bash
pub fn srpm_name(srpm: &str) -> String {
    if none(srpm) {
        return String::new();
    }
    let base = srpm.trim_end_matches(".src.rpm").trim_end_matches(".nosrc.rpm");
    let parts: Vec<&str> = base.rsplitn(3, '-').collect();
    if parts.len() == 3 {
        parts[2].to_string()
    } else {
        base.to_string()
    }
}

pub fn evr(p: &Package) -> String {
    p.full_version()
}

pub fn nevra(p: &Package) -> String {
    format!("{}-{}.{}", p.name, evr(p), p.arch())
}

/// /etc/yum.repos.d/*.repo and /etc/zypp/repos.d/*.repo (INI).
pub fn parse_repo_files(files: &[(String, String)]) -> Vec<Value> {
    let mut repos = Vec::new();
    for (path, text) in files {
        let mut sections: Vec<(String, BTreeMap<String, String>)> = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                sections.push((line[1..line.len() - 1].trim().to_string(), BTreeMap::new()));
            } else if let (Some((k, v)), Some(cur)) = (line.split_once('='), sections.last_mut()) {
                cur.1.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        let file = path.rsplit('/').next().unwrap_or(path);
        for (id, kv) in sections {
            let enabled = kv.get("enabled").map(|s| s.to_ascii_lowercase()).unwrap_or_else(|| "1".into());
            if ["0", "false", "no"].contains(&enabled.as_str()) {
                continue;
            }
            let mut r = json!({"id": id, "file": file});
            for k in ["name", "baseurl", "metalink", "mirrorlist", "gpgkey", "gpgcheck", "type"] {
                if let Some(v) = kv.get(k).filter(|v| !v.is_empty()) {
                    r[k] = json!(v.split_whitespace().collect::<Vec<_>>().join(" "));
                }
            }
            repos.push(r);
        }
    }
    repos.sort_by(|a, b| vstr(a, "id").cmp(vstr(b, "id")));
    repos
}

/// What the user asked for: dnf lists user-installed name.arch; zypper
/// lists what was pulled in automatically (inverted).
#[derive(Debug, Clone, Default)]
pub struct UserInstalled {
    pub names: HashSet<String>,
    pub inverted: bool,
}

pub fn reason(p: &Package, user: &Option<UserInstalled>) -> String {
    let Some(u) = user else { return "manual".into() };
    let is = |s: &str| u.names.contains(s);
    let manual = if u.inverted { !is(&p.name) } else { is(&format!("{}.{}", p.name, p.arch())) || is(&p.name) };
    if manual { "manual" } else { "dependency" }.into()
}

/// Reads under a filesystem root ("/" normally, a fixture in tests).
pub struct Rpm {
    root: PathBuf,
}

impl Default for Rpm {
    fn default() -> Self {
        Rpm { root: PathBuf::from("/") }
    }
}

/// Install reasons recorded by the frontends, keyed by "name.arch".
#[derive(Debug, Default)]
pub struct FrontendState {
    pub user: Option<UserInstalled>,
    /// name.arch -> repository the package came from
    pub repos: HashMap<String, String>,
}

impl Rpm {
    #[cfg(test)]
    pub fn at(root: &Path) -> Self {
        Rpm { root: root.to_path_buf() }
    }

    /// The installed frontend, found on PATH or in the standard system
    /// directories, so detection works with an empty PATH too.
    pub fn frontend(&self) -> Option<&'static str> {
        ["dnf5", "dnf", "yum", "zypper", "microdnf"].into_iter().find(|f| {
            has(f) || ["usr/bin", "bin", "usr/sbin", "sbin"].iter().any(|d| self.root.join(d).join(f).is_file())
        })
    }

    fn headers(&self) -> Result<Vec<Header>> {
        let Some(dir) = rpmdb::find(&self.root) else { bail!("no rpm database found") };
        rpmdb::read_all(&dir)
    }

    fn qa(&self, headers: &[Header]) -> Vec<Package> {
        let mut pkgs: Vec<Package> = headers.iter().filter_map(package_from_header).collect();
        mark_installonly(&mut pkgs);
        pkgs
    }

    /// What the user asked for and where packages came from, read from the
    /// state files of whichever frontend manages this system.
    pub fn frontend_state(&self) -> FrontendState {
        let r = |p: &str| self.root.join(p);
        // dnf5: TOML files under /usr/lib/sysimage/libdnf5.
        if let Some(text) = read_text_opt(r("usr/lib/sysimage/libdnf5/packages.toml")) {
            return dnf5_state(&text, read_text_opt(r("usr/lib/sysimage/libdnf5/nevras.toml")).as_deref());
        }
        // dnf4: the history database.
        if r("var/lib/dnf/history.sqlite").is_file() {
            if let Ok(st) = dnf4_state(&r("var/lib/dnf/history.sqlite")) {
                return st;
            }
        }
        // yum: one directory per package with small text files.
        if r("var/lib/yum/yumdb").is_dir() {
            return yumdb_state(&r("var/lib/yum/yumdb"));
        }
        // zypper: the list of automatically installed packages.
        if let Some(t) = read_text_opt(r("var/lib/zypp/AutoInstalled")) {
            let names =
                t.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from).collect();
            return FrontendState { user: Some(UserInstalled { names, inverted: true }), repos: HashMap::new() };
        }
        FrontendState::default()
    }

    fn deps(&self, pkgs: &mut [Package], headers: &[Header], plat: &Platform) {
        let keys: Vec<String> = pkgs.iter().map(|p| self.key_of(p, plat)).collect();
        let by_nevra: HashMap<String, String> = pkgs.iter().zip(&keys).map(|(p, k)| (nevra(p), k.clone())).collect();
        let mut requires: HashMap<String, Vec<Vec<String>>> = HashMap::new();
        let mut provides: HashMap<String, Vec<String>> = HashMap::new();
        let mut files: HashSet<&str> = HashSet::new();
        let pkg_of = |h: &Header| package_from_header(h).and_then(|p| by_nevra.get(&nevra(&p)).cloned());
        for h in headers {
            let Some(k) = pkg_of(h) else { continue };
            provides.entry(k.clone()).or_default().extend(h.strings(rpmdb::PROVIDENAME).iter().cloned());
            for r in h.strings(rpmdb::REQUIRENAME) {
                if !r.starts_with("rpmlib(") {
                    requires.entry(k.clone()).or_default().push(vec![r.clone()]);
                    if r.starts_with('/') {
                        files.insert(r);
                    }
                }
            }
        }
        // File requirements (/bin/sh) are satisfied by whoever owns the file.
        if !files.is_empty() {
            for h in headers {
                let Some(k) = pkg_of(h) else { continue };
                for f in h.files() {
                    if files.contains(f.as_str()) {
                        provides.entry(k.clone()).or_default().push(f);
                    }
                }
            }
        }
        resolve_dependencies(pkgs, &keys, &requires, &provides);
    }

    fn repo_files(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for dir in ["etc/yum.repos.d", "etc/zypp/repos.d", "etc/distro.repos.d"] {
            let mut v: Vec<String> = std::fs::read_dir(self.root.join(dir))
                .map(|d| {
                    d.filter_map(|e| e.ok())
                        .map(|e| e.path().to_string_lossy().into_owned())
                        .filter(|p| p.ends_with(".repo"))
                        .collect()
                })
                .unwrap_or_default();
            v.sort();
            for p in v {
                if let Some(t) = read_text_opt(&p) {
                    out.push((p, t));
                }
            }
        }
        out
    }

    fn translate(&self, section: &Section, src: &Platform, dst: &Platform) -> Vec<Package> {
        let (s, d) = (self.arch_of(src.arch()), self.arch_of(dst.arch()));
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

    fn arch_of(&self, canonical: &str) -> String {
        match canonical {
            "armv7" => "armv7hl".into(),
            other => other.into(),
        }
    }

    fn available_nevras(&self, fe: &str, nevras: &[String]) -> HashSet<String> {
        if !matches!(fe, "dnf5" | "dnf") || nevras.is_empty() {
            return nevras.iter().cloned().collect(); // cannot check cheaply; let the frontend decide
        }
        let mut avail = HashSet::new();
        for chunk in batches(nevras, 200) {
            let mut args = vec![fe, "-q", "repoquery", "--qf", "%{name}-%{evr}.%{arch}\\n"];
            args.extend(chunk.iter().map(String::as_str));
            // repoquery prints EVR without a zero epoch; normalise.
            avail.extend(split_lines(&package_manager_query(&args)).into_iter().map(|a| a.replace("-0:", "-")));
        }
        avail
    }
}

/// dnf5 state: packages.toml has reasons by "name.arch", nevras.toml the
/// repository of every installed NEVRA.
pub fn dnf5_state(packages: &str, nevras: Option<&str>) -> FrontendState {
    let mut st = FrontendState::default();
    if let Ok(v) = packages.parse::<toml::Table>() {
        let names = v
            .get("packages")
            .and_then(|p| p.as_table())
            .map(|t| {
                t.iter()
                    .filter(|(_, e)| matches!(e.get("reason").and_then(|r| r.as_str()), Some("User" | "Group")))
                    .map(|(k, _)| k.clone())
                    .collect::<HashSet<String>>()
            })
            .unwrap_or_default();
        st.user = Some(UserInstalled { names, inverted: false });
    }
    if let Some(Ok(v)) = nevras.map(|t| t.parse::<toml::Table>()) {
        for (nevra, e) in v.get("nevras").and_then(|n| n.as_table()).into_iter().flatten() {
            if let Some(repo) = e.get("from_repo").and_then(|r| r.as_str()) {
                st.repos.insert(na_of_nevra(nevra), repo.to_string());
            }
        }
    }
    st
}

/// "bash-0:5.2.26-3.fc40.x86_64" -> "bash.x86_64"
fn na_of_nevra(n: &str) -> String {
    let (rest, arch) = n.rsplit_once('.').unwrap_or((n, ""));
    let mut parts = rest.rsplitn(3, '-');
    let (_rel, _ver, name) = (parts.next(), parts.next(), parts.next().unwrap_or(rest));
    format!("{name}.{arch}")
}

/// dnf4 history.sqlite: the latest successful transaction item for each
/// name.arch carries its current reason (2 = user, 5 = group are manual).
pub fn dnf4_state(path: &Path) -> Result<FrontendState> {
    let db = sqlite::Db::open(path)?;
    let rpms: HashMap<i64, String> = db
        .table("rpm")?
        .into_iter()
        .map(|r| (r.int("item_id"), format!("{}.{}", r.str("name"), r.str("arch"))))
        .collect();
    let repos: HashMap<i64, String> =
        db.table("repo")?.into_iter().map(|r| (r.int("id"), r.str("repoid").to_string())).collect();
    // action: 1 install, 2 downgrade, 4 obsolete, 6 upgrade, 9 reinstall, 11 reason change;
    // 3/5/7/8/10 are the outgoing side of a transaction. state 1 = done.
    let mut latest: HashMap<String, (i64, i64, i64, String)> = HashMap::new();
    for r in db.table("trans_item")? {
        let (action, state) = (r.int("action"), r.int("state"));
        if state != 1 || ![1, 2, 4, 6, 9, 11].contains(&action) {
            continue;
        }
        let Some(na) = rpms.get(&r.int("item_id")) else { continue };
        let key = (r.int("trans_id"), r.rowid);
        let repo = if action == 11 { None } else { repos.get(&r.int("repo_id")).cloned() };
        let e = latest.entry(na.clone()).or_insert((0, 0, 0, String::new()));
        if key >= (e.0, e.1) {
            *e = (key.0, key.1, r.int("reason"), repo.unwrap_or_else(|| e.3.clone()));
        }
    }
    let names = latest.iter().filter(|(_, v)| v.2 == 2 || v.2 == 5).map(|(k, _)| k.clone()).collect();
    let repos = latest.into_iter().filter(|(_, v)| !v.3.is_empty()).map(|(k, v)| (k, v.3)).collect();
    Ok(FrontendState { user: Some(UserInstalled { names, inverted: false }), repos })
}

/// yum's yumdb: <letter>/<pkgid>-<name>-<version>-<release>-<arch>/{reason,from_repo}
pub fn yumdb_state(dir: &Path) -> FrontendState {
    let mut st = FrontendState { user: Some(UserInstalled::default()), repos: HashMap::new() };
    for letter in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        for e in std::fs::read_dir(letter.path()).into_iter().flatten().flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            // Drop the 40-hex pkgid, then split name-version-release-arch from the right.
            let rest = n.split_once('-').map(|x| x.1).unwrap_or(&n);
            let mut it = rest.rsplitn(4, '-');
            let (arch, _rel, _ver, name) = (it.next().unwrap_or(""), it.next(), it.next(), it.next().unwrap_or(""));
            let na = format!("{name}.{arch}");
            if read_text_opt(e.path().join("reason")).map(|r| r.trim() == "user").unwrap_or(false) {
                st.user.as_mut().expect("set").names.insert(na.clone());
            }
            if let Some(repo) = read_text_opt(e.path().join("from_repo")) {
                st.repos.insert(na, repo.trim().to_string());
            }
        }
    }
    st
}

/// rpmvercmp: compare version strings the way rpm does (alpha vs numeric
/// segments, '~' sorts before everything, '^' after the base version).
pub fn rpmvercmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    let sep = |c: u8| !c.is_ascii_alphanumeric() && c != b'~' && c != b'^';
    loop {
        while !a.is_empty() && sep(a[0]) {
            a = &a[1..];
        }
        while !b.is_empty() && sep(b[0]) {
            b = &b[1..];
        }
        match (a.first(), b.first()) {
            (Some(b'~'), Some(b'~')) => {
                a = &a[1..];
                b = &b[1..];
                continue;
            }
            (Some(b'~'), _) => return Less,
            (_, Some(b'~')) => return Greater,
            (Some(b'^'), Some(b'^')) => {
                a = &a[1..];
                b = &b[1..];
                continue;
            }
            (Some(b'^'), None) => return Greater,
            (None, Some(b'^')) => return Less,
            (Some(b'^'), _) => return Less,
            (_, Some(b'^')) => return Greater,
            (None, None) => return Equal,
            (None, _) => return Less,
            (_, None) => return Greater,
            _ => {}
        }
        let numeric = a[0].is_ascii_digit();
        let take = |s: &[u8]| {
            s.iter().take_while(|c| if numeric { c.is_ascii_digit() } else { c.is_ascii_alphabetic() }).count()
        };
        let (la, lb) = (take(a), take(b));
        if lb == 0 {
            return if numeric { Greater } else { Less }; // numeric beats alpha
        }
        let (sa, sb) = (&a[..la], &b[..lb]);
        let ord = if numeric {
            let trim = |s: &[u8]| -> Vec<u8> { s.iter().skip_while(|c| **c == b'0').copied().collect() };
            let (ta, tb) = (trim(sa), trim(sb));
            ta.len().cmp(&tb.len()).then(ta.cmp(&tb))
        } else {
            sa.cmp(sb)
        };
        if ord != Equal {
            return ord;
        }
        a = &a[la..];
        b = &b[lb..];
    }
}

/// Compare full EVRs: epoch, then version, then release.
pub fn evr_cmp(a: &Package, b: &Package) -> std::cmp::Ordering {
    let e = |p: &Package| p.epoch_str().and_then(|x| x.parse::<i64>().ok()).unwrap_or(0);
    let split = |p: &Package| -> (String, String) {
        p.version
            .rsplit_once('-')
            .map(|(v, r)| (v.to_string(), r.to_string()))
            .unwrap_or((p.version.clone(), String::new()))
    };
    let ((va, ra), (vb, rb)) = (split(a), split(b));
    e(a).cmp(&e(b)).then(rpmvercmp(&va, &vb)).then(rpmvercmp(&ra, &rb))
}

impl Manager for Rpm {
    fn name(&self) -> &'static str {
        "rpm"
    }

    /// Debian can have rpm installed as a tool; only claim the system if an
    /// RPM frontend is present too.
    fn available(&self) -> bool {
        rpmdb::find(&self.root).is_some() && self.frontend().is_some()
    }

    fn key_of(&self, pkg: &Package, plat: &Platform) -> String {
        let native = self.arch_of(plat.arch());
        let a = pkg.arch();
        let mut key =
            if a == native || a == NOARCH || a.is_empty() { pkg.name.clone() } else { format!("{}.{a}", pkg.name) };
        if Package::flag(&pkg.installonly) {
            // Several kernels live side by side; each version is its own entry.
            key += &format!("-{}", evr(pkg));
        }
        key
    }

    fn installed(&self, _plat: &Platform) -> Result<Vec<Package>> {
        let mut pkgs = self.qa(&self.headers()?);
        let user = self.frontend_state().user;
        for p in &mut pkgs {
            p.reason = Some(reason(p, &user));
        }
        Ok(pkgs)
    }

    fn capture(&self, plat: &Platform, opts: &Options) -> Result<Section> {
        let fe = self.frontend();
        let headers = self.headers()?;
        let mut pkgs = self.qa(&headers);
        let FrontendState { user, repos: from_repo } = self.frontend_state();
        if user.is_none() {
            warn(&format!(
                "{}: cannot tell user-installed from dependency packages; all are recorded as manual",
                fe.unwrap_or("rpm")
            ));
        }
        self.deps(&mut pkgs, &headers, plat);
        for p in &mut pkgs {
            p.reason = Some(reason(p, &user));
            // dnf5 reports an opaque hash for packages that came with the image.
            let opaque = |r: &str| r.len() == 32 && r.chars().all(|c| c.is_ascii_hexdigit());
            if let Some(r) = from_repo.get(&format!("{}.{}", p.name, p.arch())) {
                let r = r.trim_start_matches('@');
                if !r.is_empty() && !["System", "<unknown>", "(none)", "installed"].contains(&r) && !opaque(r) {
                    p.repositories = Some(vec![r.to_string()]);
                }
            }
            if !opts.licenses {
                p.licenses.clear();
            }
        }
        pkgs.sort_by(|a, b| (&a.name, a.arch(), a.full_version()).cmp(&(&b.name, b.arch(), b.full_version())));
        Ok(Section {
            tool: Some(format!(
                "{} / RPM version {}",
                fe.unwrap_or("None"),
                headers
                    .iter()
                    .find(|h| h.string(rpmdb::NAME) == Some("rpm"))
                    .and_then(|h| h.string(rpmdb::VERSION))
                    .unwrap_or("unknown")
            )),
            frontend: fe.map(String::from),
            repositories: Some(parse_repo_files(&self.repo_files())),
            packages: pkgs,
            ..Default::default()
        })
    }

    fn prepare(&self, section: &Section, _src: &Platform, _dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("rpm (prepare)");
        let fe = self.frontend();
        if opts.add_repos {
            let have: HashSet<String> =
                parse_repo_files(&self.repo_files()).iter().map(|r| vstr(r, "id").to_string()).collect();
            let dir = if fe == Some("zypper") { "/etc/zypp/repos.d" } else { "/etc/yum.repos.d" };
            for r in section.repos() {
                let id = vstr(r, "id");
                if id.is_empty() || have.contains(id) {
                    continue;
                }
                let mut lines = vec![format!("[{id}]"), "enabled=1".into()];
                for k in ["name", "baseurl", "metalink", "mirrorlist", "gpgkey", "gpgcheck", "type"] {
                    if !vstr(r, k).is_empty() {
                        lines.push(format!("{k}={}", vstr(r, k)));
                    }
                }
                plan.add(Step::write(
                    format!("add repository {id}"),
                    Write {
                        path: format!("{dir}/matsya-{id}.repo"),
                        content: lines.join("\n"),
                        base64: false,
                        mode: 0o644,
                    },
                ));
            }
        }
        if opts.refresh {
            match fe {
                Some("zypper") => {
                    plan.add(Step::cmd("refresh repositories", ["zypper", "--non-interactive", "refresh"]))
                }
                Some(f) => plan.add(Step::cmd("refresh repositories", [f, "-y", "makecache"])),
                None => {}
            }
        }
        Ok(plan)
    }

    fn plan(&self, section: &Section, src: &Platform, dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("rpm");
        let Some(fe) = self.frontend() else { bail!("no rpm frontend (dnf5/dnf/yum/zypper) found") };
        let mut pkgs = self.translate(section, src, dst);
        if opts.roots_only {
            pkgs.retain(Package::is_manual);
        }
        let installed = self.installed(dst)?;
        let current = by_key(self, &installed, dst);
        let todo: Vec<&Package> =
            pkgs.iter().filter(|p| current.get(&self.key_of(p, dst)).map(|c| evr(c)) != Some(evr(p))).collect();
        let available = self.available_nevras(fe, &todo.iter().map(|p| nevra(p)).collect::<Vec<_>>());
        let is_fedora = dst.distro() == "fedora";
        let (mut installs, mut downgrades, mut local) = (Vec::new(), Vec::new(), Vec::new());
        for p in &todo {
            let spec = nevra(p);
            if !available.contains(&spec) {
                if let (true, true, Some(digest), false) = (opts.snapshot, is_fedora, &p.payload_digest, p.cross_arch) {
                    let src = p.source.as_ref().map(|s| s.name.clone()).unwrap_or_else(|| p.name.clone());
                    let (ver, rel) = p.version.rsplit_once('-').unwrap_or((&p.version, ""));
                    let url = KOJI
                        .replace("{src}", &src)
                        .replace("{version}", ver)
                        .replace("{release}", rel)
                        .replace("{arch}", p.arch())
                        .replace("{name}", &p.name);
                    let dest = format!("{}/rpm/{}-{}.{}.rpm", opts.cache_dir, p.name, p.version, p.arch());
                    plan.add(Step::fetch(
                        format!("{spec} is gone from the mirrors; fetching from Koji"),
                        Fetch { urls: vec![url], dest: dest.clone(), sha256: None, rpm_payload: Some(digest.clone()) },
                    ));
                    local.push(dest);
                } else if opts.best_effort {
                    plan.warnings.push(format!("{spec} not available; installing newest {}", p.name));
                    installs.push(format!("{}.{}", p.name, p.arch()));
                } else {
                    plan.unresolved.push(format!("{spec} (not in any enabled repository)"));
                }
                continue;
            }
            // dnf and zypper move to an exact NEVRA in either direction; only
            // legacy yum needs an explicit downgrade, decided by rpm itself.
            match current.get(&self.key_of(p, dst)) {
                Some(cur) if fe == "yum" && evr_cmp(cur, p).is_gt() => downgrades.push(spec),
                _ => installs.push(spec),
            }
        }

        if fe == "zypper" {
            let mut z: Vec<String> = installs
                .iter()
                .map(|s| {
                    pkgs.iter()
                        .find(|p| &nevra(p) == s)
                        .map(|p| format!("{}.{}={}", p.name, p.arch(), evr(p)))
                        .unwrap_or(s.clone())
                })
                .collect();
            z.extend(local.iter().cloned());
            if !z.is_empty() {
                let mut argv: Vec<String> =
                    ["zypper", "--non-interactive", "install", "--oldpackage", "--force-resolution"]
                        .map(String::from)
                        .to_vec();
                let n = z.len();
                argv.extend(z);
                plan.add(Step::cmd(format!("install {n} package(s) at locked versions"), argv));
            }
        } else {
            if !installs.is_empty() || !local.is_empty() {
                let mut argv: Vec<String> = [fe, "-y", "install"].map(String::from).to_vec();
                // dnf can replace conflicting packages; legacy yum has no such option.
                if fe != "yum" {
                    argv.push("--allowerasing".into());
                }
                argv.extend(installs.iter().cloned());
                argv.extend(local.iter().cloned());
                plan.add(Step::cmd(
                    format!("install {} package(s) at locked versions", installs.len() + local.len()),
                    argv,
                ));
            }
            if !downgrades.is_empty() {
                let mut argv: Vec<String> = [fe, "-y", "downgrade"].map(String::from).to_vec();
                argv.extend(downgrades.iter().cloned());
                plan.add(Step::cmd(format!("downgrade {} package(s) to locked versions", downgrades.len()), argv));
            }
            if matches!(fe, "dnf5" | "dnf") {
                let touched: HashSet<String> = todo.iter().map(|p| nevra(p)).collect();
                let needs = |p: &Package, want: &str| {
                    touched.contains(&nevra(p)) || current.get(&self.key_of(p, dst)).map(|c| c.reason()) != Some(want)
                };
                let na = |p: &Package| format!("{}.{}", p.name, p.arch());
                let manual: BTreeSet<String> =
                    pkgs.iter().filter(|p| p.is_manual() && needs(p, "manual")).map(na).collect();
                let auto: BTreeSet<String> =
                    pkgs.iter().filter(|p| !p.is_manual() && needs(p, "dependency")).map(na).collect();
                let (user_cmd, dep_cmd) = if fe == "dnf5" {
                    (["mark", "user"], ["mark", "dependency"])
                } else {
                    (["mark", "install"], ["mark", "remove"])
                };
                if !manual.is_empty() {
                    let argv: Vec<String> =
                        [fe, "-y"].iter().chain(user_cmd.iter()).map(|s| s.to_string()).chain(manual).collect();
                    plan.add(Step::cmd("restore user-installed marks", argv));
                }
                if !auto.is_empty() && !opts.roots_only {
                    let argv: Vec<String> =
                        [fe, "-y"].iter().chain(dep_cmd.iter()).map(|s| s.to_string()).chain(auto).collect();
                    plan.add(Step::cmd("restore dependency marks", argv));
                }
            }
        }
        if opts.prune {
            let locked: HashSet<String> =
                self.translate(section, src, dst).iter().map(|p| self.key_of(p, dst)).collect();
            let protected = ["rpm", "dnf", "dnf5", "yum", "zypper", "systemd", "glibc", "filesystem", "setup"];
            // Never prune kernels: one of them is the running one.
            let extra: BTreeSet<String> = current
                .iter()
                .filter(|(k, p)| {
                    !locked.contains(*k) && !protected.contains(&p.name.as_str()) && !Package::flag(&p.installonly)
                })
                .map(|(_, p)| format!("{}.{}", p.name, p.arch()))
                .collect();
            if !extra.is_empty() {
                let base: Vec<&str> = if fe == "zypper" {
                    vec!["zypper", "--non-interactive", "remove"]
                } else {
                    vec![fe, "-y", "remove"]
                };
                let n = extra.len();
                plan.add(Step::cmd(
                    format!("remove {n} package(s) not in the lock"),
                    base.into_iter().map(String::from).chain(extra),
                ));
            }
        }
        plan.summary = vec![
            ("install".into(), installs.len() + local.len()),
            ("downgrade".into(), downgrades.len()),
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

    /// Build an rpm header blob: (tag, type, value bytes, count).
    fn header(entries: &[(u32, u32, Vec<u8>, u32)]) -> Vec<u8> {
        let (mut index, mut data) = (Vec::new(), Vec::new());
        for (tag, typ, val, count) in entries {
            index.extend_from_slice(&tag.to_be_bytes());
            index.extend_from_slice(&typ.to_be_bytes());
            index.extend_from_slice(&(data.len() as u32).to_be_bytes());
            index.extend_from_slice(&count.to_be_bytes());
            data.extend_from_slice(val);
        }
        let mut b = (entries.len() as u32).to_be_bytes().to_vec();
        b.extend_from_slice(&(data.len() as u32).to_be_bytes());
        b.extend(index);
        b.extend(data);
        b
    }
    fn s(v: &str) -> (Vec<u8>, u32) {
        (format!("{v}\0").into_bytes(), 1)
    }

    #[test]
    fn packages_from_headers() {
        let e = |tag, v: &str| {
            let (b, c) = s(v);
            (tag, 6, b, c)
        };
        let blob = header(&[
            e(rpmdb::NAME, "openssl-libs"),
            e(rpmdb::VERSION, "3.2.2"),
            e(rpmdb::RELEASE, "3.fc40"),
            (rpmdb::EPOCH, 4, 1u32.to_be_bytes().to_vec(), 1),
            e(rpmdb::ARCH, "x86_64"),
            e(rpmdb::SOURCERPM, "openssl-3.2.2-3.fc40.src.rpm"),
            e(rpmdb::LICENSE, "Apache-2.0"),
            (rpmdb::SIGMD5, 7, vec![0xca, 0xfe], 2),
            (rpmdb::PROVIDENAME, 8, b"libssl.so.3\0openssl-libs\0".to_vec(), 2),
        ]);
        let h = rpmdb::parse_header(&blob).unwrap();
        let p = package_from_header(&h).unwrap();
        assert_eq!(nevra(&p), "openssl-libs-1:3.2.2-3.fc40.x86_64");
        assert_eq!(p.source.as_ref().unwrap().name, "openssl");
        assert_eq!(p.sigmd5.as_deref(), Some("cafe"));
        assert!(p.payload_digest.is_none());
        assert_eq!(h.strings(rpmdb::PROVIDENAME), ["libssl.so.3", "openssl-libs"]);
        let key = header(&[e(rpmdb::NAME, "gpg-pubkey"), e(rpmdb::VERSION, "a15b79cc")]);
        assert!(package_from_header(&rpmdb::parse_header(&key).unwrap()).is_none());
    }

    #[test]
    fn version_comparison() {
        use std::cmp::Ordering::*;
        for (a, b, want) in [
            ("1.0", "1.0", Equal),
            ("1.10", "1.9", Greater),
            ("1.0~rc1", "1.0", Less),
            ("1.0^git1", "1.0", Greater),
            ("1.0a", "1.0", Greater),
            ("1.0", "1.0.1", Less),
            ("2.0", "10", Less),
            ("1.0.010", "1.0.9", Greater),
            ("a", "1", Less),
            ("5.2", "5.2", Equal),
        ] {
            assert_eq!(rpmvercmp(a, b), want, "{a} vs {b}");
        }
        let mk = |v: &str, e: i64| {
            let mut p = Package::new("x", v);
            if e > 0 {
                p.epoch = Some(json!(e));
            }
            p
        };
        // the review case: 1.0-2 must not count as newer than 1.0.1-1
        assert!(evr_cmp(&mk("1.0-2", 0), &mk("1.0.1-1", 0)).is_lt());
        assert!(evr_cmp(&mk("1.0-1", 1), &mk("9.0-1", 0)).is_gt());
    }

    #[test]
    fn dnf5_state_files() {
        let st = dnf5_state(&fixture("dnf5-packages.toml"), Some(&fixture("dnf5-nevras.toml")));
        let user = st.user.unwrap();
        assert!(user.names.contains("bash.aarch64"));
        assert!(!user.names.contains("alternatives.aarch64"));
        assert_eq!(st.repos["bash.aarch64"], "fedora");
        assert_eq!(st.repos["alternatives.aarch64"], "f6ae26d2709140ec8807dba8ce4e3091");
    }

    #[test]
    fn dnf4_history_with_wal() {
        let st =
            dnf4_state(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dnf-history.sqlite"))).unwrap();
        let user = st.user.unwrap().names;
        assert!(user.contains("bash.x86_64"));
        assert!(user.contains("jq.x86_64"));
        assert!(user.contains("oniguruma.x86_64")); // reason change to user wins
        assert!(!user.contains("tree.x86_64")); // failed transaction ignored
        assert_eq!(st.repos["jq.x86_64"], "appstream");
        assert_eq!(st.repos["oniguruma.x86_64"], "appstream"); // reason change keeps the install repo
        assert_eq!(st.repos["bash.x86_64"], "baseos");
    }

    #[test]
    fn srpm() {
        assert_eq!(srpm_name("python3.12-3.12.4-1.fc40.src.rpm"), "python3.12");
        assert_eq!(srpm_name("(none)"), "");
    }

    #[test]
    fn keys_and_installonly() {
        let r = Rpm::default();
        let plat = crate::platform::from_os_release("ID=fedora\nVERSION_ID=40\n", "x86_64".into());
        let mk = |n: &str, v: &str, a: &str| {
            let mut p = Package::new(n, v);
            p.arch = Some(a.into());
            p
        };
        assert_eq!(r.key_of(&mk("glibc", "1-1", "i686"), &plat), "glibc.i686");
        assert_eq!(r.key_of(&mk("tzdata", "1-1", "noarch"), &plat), "tzdata");
        let mut pkgs = vec![
            mk("kernel-core", "6.10.1-200.fc40", "x86_64"),
            mk("kernel-core", "6.11.2-300.fc40", "x86_64"),
            mk("bash", "5.2-1", "x86_64"),
            mk("dup", "1-1", "x86_64"),
            mk("dup", "2-1", "x86_64"),
        ];
        mark_installonly(&mut pkgs);
        let keys: HashSet<String> = pkgs.iter().map(|p| r.key_of(p, &plat)).collect();
        assert_eq!(keys.len(), 5);
        assert!(keys.contains("bash") && keys.contains("kernel-core-6.10.1-200.fc40"));
    }

    #[test]
    fn repo_files() {
        let repos = parse_repo_files(&[("/etc/yum.repos.d/fedora.repo".into(), fixture("fedora.repo"))]);
        let ids: Vec<&str> = repos.iter().map(|r| vstr(r, "id")).collect();
        assert_eq!(ids, vec!["docker-ce-stable", "fedora"]);
        assert!(repos[1].get("metalink").is_some());
    }

    #[test]
    fn reasons() {
        let mut p = Package::new("a", "1");
        p.arch = Some("x86_64".into());
        let dnf =
            |n: &[&str]| Some(UserInstalled { names: n.iter().map(|s| s.to_string()).collect(), inverted: false });
        let zyp = |n: &[&str]| Some(UserInstalled { names: n.iter().map(|s| s.to_string()).collect(), inverted: true });
        assert_eq!(reason(&p, &dnf(&["a.x86_64"])), "manual");
        assert_eq!(reason(&p, &dnf(&["b.x86_64"])), "dependency");
        assert_eq!(reason(&p, &zyp(&["a"])), "dependency");
        assert_eq!(reason(&p, &zyp(&["b"])), "manual");
        assert_eq!(reason(&p, &zyp(&[])), "manual"); // empty AutoInstalled
        assert_eq!(reason(&p, &None), "manual");
    }
}

#[cfg(test)]
mod real_db {
    use super::*;

    /// Prints frontend state for $MATSYA_ROOT; compared by hand against
    /// sqlite3/dnf during development.
    #[test]
    #[ignore]
    fn dump_frontend_state() {
        let root = std::env::var("MATSYA_ROOT").unwrap();
        let st = Rpm::at(Path::new(&root)).frontend_state();
        let mut u: Vec<String> = st.user.map(|u| u.names.into_iter().collect()).unwrap_or_default();
        u.sort();
        let mut r: Vec<String> = st.repos.iter().map(|(k, v)| format!("{k} {v}")).collect();
        r.sort();
        std::fs::write(format!("{root}/matsya-user.txt"), u.join("\n") + "\n").unwrap();
        std::fs::write(format!("{root}/matsya-repos.txt"), r.join("\n") + "\n").unwrap();
    }
}
