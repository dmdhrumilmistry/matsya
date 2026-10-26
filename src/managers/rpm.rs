//! RPM based distributions: Fedora, RHEL/CentOS/Rocky/Alma, Amazon Linux,
//! openSUSE/SLES. Inventory comes from rpm itself; installs go through
//! whichever frontend exists (dnf5, dnf, yum, zypper).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde_json::{json, Value};

use super::{batches, by_key, resolve_dependencies, Manager, Options};
use crate::bail;
use crate::model::{vstr, Package, Section, Source};
use crate::plan::{Fetch, Plan, Step, Write};
use crate::platform::Platform;
use crate::util::{has, read_text_opt, run, run_any, run_ok, split_lines, warn, Result};

const NOARCH: &str = "noarch";
/// Fedora's build system keeps every build ever shipped.
const KOJI: &str = "https://kojipkgs.fedoraproject.org/packages/{src}/{version}/{release}/{arch}/{name}-{version}-{release}.{arch}.rpm";
const QF_FIELDS: &[&str] =
    &["NAME", "EPOCHNUM", "VERSION", "RELEASE", "ARCH", "SOURCERPM", "LICENSE", "PAYLOADDIGEST", "SIGMD5", "VENDOR"];

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

pub fn parse_rpm_qa(out: &str) -> Vec<Package> {
    let mut pkgs = Vec::new();
    for line in out.lines() {
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() < QF_FIELDS.len() {
            continue;
        }
        let (name, epoch, ver, rel, arch, srpm, lic, payload, sigmd5, vendor) =
            (c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9]);
        if name == "gpg-pubkey" {
            continue; // imported signing keys masquerade as packages
        }
        let mut p = Package::new(name, format!("{ver}-{rel}"));
        p.arch = Some(arch.into());
        if !none(epoch) && epoch != "0" {
            p.epoch = Some(epoch.parse::<i64>().map(Value::from).unwrap_or_else(|_| json!(epoch)));
        }
        let src = srpm_name(srpm);
        if !src.is_empty() && src != name {
            p.source = Some(Source { name: src, version: None });
        }
        if !none(lic) {
            p.licenses = vec![lic.into()];
        }
        if !none(payload) {
            p.payload_digest = Some(payload.into());
        }
        if !none(sigmd5) {
            p.sigmd5 = Some(sigmd5.into());
        }
        if !none(vendor) {
            p.vendor = Some(vendor.into());
        }
        pkgs.push(p);
    }
    pkgs
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
#[derive(Debug, Clone)]
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

#[derive(Default)]
pub struct Rpm {
    tags: RefCell<Option<HashSet<String>>>,
}

impl Rpm {
    pub fn frontend(&self) -> Option<&'static str> {
        ["dnf5", "dnf", "yum", "zypper", "microdnf"].into_iter().find(|f| has(f))
    }

    fn tags(&self) -> HashSet<String> {
        self.tags
            .borrow_mut()
            .get_or_insert_with(|| run_ok(&["rpm", "--querytags"]).split_whitespace().map(String::from).collect())
            .clone()
    }

    /// RPM 6 renamed PAYLOADDIGEST to PAYLOADSHA256; RPM < 4.14 has neither.
    fn payload_tag(&self) -> Option<&'static str> {
        let t = self.tags();
        ["PAYLOADSHA256", "PAYLOADDIGEST"].into_iter().find(|x| t.contains(*x))
    }

    fn qa(&self) -> Result<Vec<Package>> {
        let payload = self.payload_tag();
        // An unknown tag makes rpm print an error yet exit 0 with no output.
        let fields: Vec<&str> =
            QF_FIELDS.iter().map(|f| if *f == "PAYLOADDIGEST" { payload.unwrap_or("NAME") } else { f }).collect();
        let qf = fields.iter().map(|f| format!("%{{{f}}}")).collect::<Vec<_>>().join("\\t") + "\\n";
        let mut pkgs = parse_rpm_qa(&run(&["rpm", "-qa", "--qf", &qf])?);
        if payload.is_none() {
            for p in &mut pkgs {
                p.payload_digest = None;
            }
        }
        mark_installonly(&mut pkgs);
        if pkgs.is_empty() && !run_ok(&["rpm", "-qa"]).trim().is_empty() {
            bail!(
                "rpm returned packages but none could be parsed; please report this with the output of `rpm --version`"
            );
        }
        Ok(pkgs)
    }

    fn user_installed(&self, fe: Option<&str>) -> Option<UserInstalled> {
        match fe {
            Some(f @ ("dnf5" | "dnf")) => {
                let names: HashSet<String> =
                    split_lines(&run_ok(&[f, "-q", "repoquery", "--userinstalled", "--qf", "%{name}.%{arch}\\n"]))
                        .into_iter()
                        .collect();
                (!names.is_empty()).then_some(UserInstalled { names, inverted: false })
            }
            Some("zypper") => read_text_opt("/var/lib/zypp/AutoInstalled").map(|t| UserInstalled {
                names: t
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from)
                    .collect(),
                inverted: true,
            }),
            _ => None,
        }
    }

    fn deps(&self, pkgs: &mut [Package], plat: &Platform) {
        let sep = '\x1f';
        let keys: Vec<String> = pkgs.iter().map(|p| self.key_of(p, plat)).collect();
        let by_na: HashMap<String, String> =
            pkgs.iter().zip(&keys).map(|(p, k)| (format!("{}.{}", p.name, p.arch()), k.clone())).collect();
        // %{=TAG} repeats a scalar inside an array iteration (required by RPM 6).
        let qf = format!("[%{{=NAME}}.%{{=ARCH}}{sep}P{sep}%{{PROVIDENAME}}\\n][%{{=NAME}}.%{{=ARCH}}{sep}R{sep}%{{REQUIRENAME}}\\n]");
        let mut requires: HashMap<String, Vec<Vec<String>>> = HashMap::new();
        let mut provides: HashMap<String, Vec<String>> = HashMap::new();
        let mut files: HashSet<String> = HashSet::new();
        for line in run_ok(&["rpm", "-qa", "--qf", &qf]).lines() {
            let parts: Vec<&str> = line.split(sep).collect();
            if parts.len() != 3 {
                continue;
            }
            let Some(k) = by_na.get(parts[0]) else { continue };
            if parts[1] == "P" {
                provides.entry(k.clone()).or_default().push(parts[2].into());
            } else if !parts[2].starts_with("rpmlib(") {
                requires.entry(k.clone()).or_default().push(vec![parts[2].into()]);
                if parts[2].starts_with('/') {
                    files.insert(parts[2].into());
                }
            }
        }
        // File requirements (/bin/sh) are satisfied by whoever owns the file.
        if !files.is_empty() {
            for line in
                run_ok(&["rpm", "-qa", "--qf", &format!("[%{{=NAME}}.%{{=ARCH}}{sep}%{{FILENAMES}}\\n]")]).lines()
            {
                if let Some((owner, path)) = line.split_once(sep) {
                    if let (true, Some(k)) = (files.contains(path), by_na.get(owner)) {
                        provides.entry(k.clone()).or_default().push(path.into());
                    }
                }
            }
        }
        resolve_dependencies(pkgs, &keys, &requires, &provides);
    }

    fn installed_repos(&self, fe: Option<&str>) -> HashMap<String, String> {
        let Some(f @ ("dnf5" | "dnf")) = fe else { return HashMap::new() };
        split_lines(&run_ok(&[f, "-q", "repoquery", "--installed", "--qf", "%{name}.%{arch}|%{from_repo}\\n"]))
            .into_iter()
            .filter_map(|l| {
                let (na, repo) = l.split_once('|')?;
                let opaque = repo.len() == 32 && repo.chars().all(|c| c.is_ascii_hexdigit());
                // dnf5 reports an opaque hash for packages that came with the image.
                (!repo.is_empty() && !["@System", "<unknown>", "(none)"].contains(&repo) && !opaque)
                    .then(|| (na.to_string(), repo.trim_start_matches('@').to_string()))
            })
            .collect()
    }

    fn repo_files() -> Vec<(String, String)> {
        let mut out = Vec::new();
        for dir in ["/etc/yum.repos.d", "/etc/zypp/repos.d", "/etc/distro.repos.d"] {
            let mut v: Vec<String> = std::fs::read_dir(dir)
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
            avail.extend(split_lines(&run_any(&args)).into_iter().map(|a| a.replace("-0:", "-")));
        }
        avail
    }
}

/// Compare two EVRs with rpm's own algorithm (via its embedded Lua).
fn rpm_vercmp(a: &str, b: &str) -> i32 {
    run_ok(&["rpm", "--eval", &format!("%{{lua: print(rpm.vercmp({a:?}, {b:?}))}}")]).trim().parse().unwrap_or(0)
}

impl Manager for Rpm {
    fn name(&self) -> &'static str {
        "rpm"
    }

    /// Debian can have rpm installed as a tool; only claim the system if an
    /// RPM frontend is present too.
    fn available(&self) -> bool {
        has("rpm") && self.frontend().is_some()
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
        let mut pkgs = self.qa()?;
        let user = self.user_installed(self.frontend());
        for p in &mut pkgs {
            p.reason = Some(reason(p, &user));
        }
        Ok(pkgs)
    }

    fn capture(&self, plat: &Platform, opts: &Options) -> Result<Section> {
        let fe = self.frontend();
        let mut pkgs = self.qa()?;
        let user = self.user_installed(fe);
        if user.is_none() {
            warn(&format!(
                "{}: cannot tell user-installed from dependency packages; all are recorded as manual",
                fe.unwrap_or("rpm")
            ));
        }
        self.deps(&mut pkgs, plat);
        let from_repo = self.installed_repos(fe);
        for p in &mut pkgs {
            p.reason = Some(reason(p, &user));
            if let Some(r) = from_repo.get(&format!("{}.{}", p.name, p.arch())) {
                p.repositories = Some(vec![r.clone()]);
            }
            if !opts.licenses {
                p.licenses.clear();
            }
        }
        pkgs.sort_by(|a, b| (&a.name, a.arch(), a.full_version()).cmp(&(&b.name, b.arch(), b.full_version())));
        Ok(Section {
            tool: Some(format!("{} / {}", fe.unwrap_or("None"), run_ok(&["rpm", "--version"]).trim())),
            frontend: fe.map(String::from),
            repositories: Some(parse_repo_files(&Self::repo_files())),
            packages: pkgs,
            ..Default::default()
        })
    }

    fn prepare(&self, section: &Section, _src: &Platform, _dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("rpm (prepare)");
        let fe = self.frontend();
        if opts.add_repos {
            let have: HashSet<String> =
                parse_repo_files(&Self::repo_files()).iter().map(|r| vstr(r, "id").to_string()).collect();
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
                    let tag = self.payload_tag().unwrap_or("PAYLOADDIGEST").to_string();
                    plan.add(Step::fetch(
                        format!("{spec} is gone from the mirrors; fetching from Koji"),
                        Fetch {
                            urls: vec![url],
                            dest: dest.clone(),
                            sha256: None,
                            rpm_payload: Some((tag, digest.clone())),
                        },
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
                Some(cur) if fe == "yum" && rpm_vercmp(&evr(cur), &evr(p)) > 0 => downgrades.push(spec),
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
                let mut argv: Vec<String> = [fe, "-y", "install", "--allowerasing"].map(String::from).to_vec();
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

    #[test]
    fn qa() {
        let pkgs = parse_rpm_qa(&fixture("rpm-qa.txt"));
        assert!(!pkgs.iter().any(|p| p.name == "gpg-pubkey"));
        let ossl = pkgs.iter().find(|p| p.name == "openssl-libs").unwrap();
        assert_eq!(ossl.epoch, Some(json!(1)));
        assert_eq!(nevra(ossl), "openssl-libs-1:3.2.2-3.fc40.x86_64");
        assert_eq!(ossl.source.as_ref().unwrap().name, "openssl");
        assert!(ossl.payload_digest.is_none());
        let bash = pkgs.iter().find(|p| p.name == "bash").unwrap();
        assert_eq!(nevra(bash), "bash-5.2.26-3.fc40.x86_64");
        assert!(bash.source.is_none());
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
