//! SBOM generation (CycloneDX 1.6 JSON and SPDX 2.3 JSON) from a lock.
//!
//! The SBOM is a pure function of the lock: the same lock always yields the
//! same bytes, and it can be produced on a machine that never had the
//! packages installed.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::{json, Value};

use crate::managers;
use crate::model::{Environment, Package};
use crate::platform::Platform;

/// A pragmatic subset of SPDX license ids seen in distro metadata. Anything
/// else becomes a named license (CycloneDX) or LicenseRef (SPDX).
const SPDX_IDS: &str = "0BSD AFL-2.1 AGPL-3.0-only AGPL-3.0-or-later Apache-1.1 Apache-2.0 Artistic-1.0 Artistic-1.0-Perl \
Artistic-2.0 BSD-1-Clause BSD-2-Clause BSD-3-Clause BSD-4-Clause BSL-1.0 CC-BY-3.0 CC-BY-4.0 CC-BY-SA-3.0 CC-BY-SA-4.0 CC0-1.0 \
CDDL-1.0 CDDL-1.1 CPL-1.0 curl EPL-1.0 EPL-2.0 EUPL-1.2 FSFAP FTL GFDL-1.1-or-later GFDL-1.2-or-later GFDL-1.3-only \
GFDL-1.3-or-later GPL-1.0-only GPL-1.0-or-later GPL-2.0-only GPL-2.0-or-later GPL-3.0-only GPL-3.0-or-later HPND ICU IJG IPA \
ISC LGPL-2.0-only LGPL-2.0-or-later LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0-only LGPL-3.0-or-later Libpng LPPL-1.3c MIT MIT-0 \
MPL-1.1 MPL-2.0 MS-PL NCSA OFL-1.1 OpenSSL PHP-3.01 PostgreSQL Python-2.0 Ruby Sleepycat TCL Unicode-3.0 Unicode-DFS-2016 \
Unlicense UPL-1.0 Vim W3C WTFPL X11 Zlib ZPL-2.1";

/// Legacy SPDX ids and distro spellings -> current ids (None: no SPDX id).
fn alias(tok: &str) -> Option<Option<&'static str>> {
    Some(match tok {
        "GPL-1" => Some("GPL-1.0-only"),
        "GPL-1+" | "GPL-1.0+" => Some("GPL-1.0-or-later"),
        "GPL-2" | "GPL-2.0" | "GPLv2" => Some("GPL-2.0-only"),
        "GPL-2+" | "GPL-2.0+" | "GPLv2+" => Some("GPL-2.0-or-later"),
        "GPL-3" | "GPL-3.0" | "GPLv3" => Some("GPL-3.0-only"),
        "GPL-3+" | "GPL-3.0+" | "GPLv3+" => Some("GPL-3.0-or-later"),
        "LGPL-2" => Some("LGPL-2.0-only"),
        "LGPL-2+" | "LGPL-2.0+" => Some("LGPL-2.0-or-later"),
        "LGPL-2.1" => Some("LGPL-2.1-only"),
        "LGPL-2.1+" => Some("LGPL-2.1-or-later"),
        "LGPL-3" => Some("LGPL-3.0-only"),
        "LGPL-3+" | "LGPL-3.0+" => Some("LGPL-3.0-or-later"),
        "Apache-2" | "Apache 2.0" | "ASL 2.0" => Some("Apache-2.0"),
        "Expat" => Some("MIT"),
        "BSD-3-clause" => Some("BSD-3-Clause"),
        "BSD-2-clause" => Some("BSD-2-Clause"),
        "BSD-4-clause" => Some("BSD-4-Clause"),
        "zlib" => Some("Zlib"),
        "PSF-2.0" => Some("Python-2.0"),
        "MPL-2" => Some("MPL-2.0"),
        "public-domain" | "custom" => None,
        _ => return None,
    })
}

/// -> (spdx id, None) or (None, unrecognised name)
fn map_token(tok: &str) -> (Option<String>, Option<String>) {
    let tok = tok.trim_matches(|c| c == '(' || c == ')' || c == ' ');
    if SPDX_IDS.split_whitespace().any(|x| x == tok) {
        return (Some(tok.into()), None);
    }
    match alias(tok) {
        Some(Some(id)) => (Some(id.into()), None),
        _ => (None, Some(tok.into())),
    }
}

fn pct(s: &str, safe: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || "-._~".contains(c) || safe.contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn purl(manager: &str, pkg: &Package, plat: &Platform) -> String {
    let distro = plat.distro();
    let mut ns = match distro {
        "rhel" => "redhat",
        "opensuse-leap" | "opensuse-tumbleweed" => "opensuse",
        "sles" => "suse",
        d => d,
    }
    .to_string();
    let release = plat.release();
    let distro_q =
        if !release.is_empty() && release != "rolling" { format!("{distro}-{release}") } else { distro.to_string() };
    let mut name = pkg.name.clone();
    let mut quals: Vec<(String, String)> = Vec::new();
    let arch = || ("arch".to_string(), pkg.arch().to_string());
    let typ = match manager {
        "apt" => {
            quals = vec![arch(), ("distro".into(), distro_q.clone())];
            if let Some(src) = &pkg.source {
                quals.push((
                    "upstream".into(),
                    format!("{}@{}", src.name, src.version.clone().unwrap_or_else(|| pkg.version.clone())),
                ));
            }
            "deb"
        }
        "rpm" => {
            quals = vec![arch(), ("distro".into(), distro_q.clone())];
            if let Some(e) = pkg.epoch_str() {
                quals.push(("epoch".into(), e));
            }
            "rpm"
        }
        "apk" => {
            quals = vec![arch(), ("distro".into(), distro_q.clone())];
            "apk"
        }
        "pacman" => {
            quals = vec![arch(), ("distro".into(), distro_q.clone())];
            "alpm"
        }
        "brew" => {
            let tap = pkg.tap.clone().unwrap_or_default();
            ns = if pkg.kind() == "cask" {
                if tap.is_empty() {
                    "homebrew/cask".into()
                } else {
                    tap
                }
            } else if tap.is_empty() || tap == "homebrew/core" {
                String::new()
            } else {
                tap
            };
            name = pkg.name.rsplit('/').next().unwrap_or(&pkg.name).to_ascii_lowercase();
            "brew"
        }
        // Software outside the system package manager: language ecosystems
        // have their own purl types, the rest is "generic".
        "pip" => {
            ns = String::new();
            name = crate::managers::pip::normalize(&pkg.name);
            "pypi"
        }
        "npm" => {
            ns = String::new();
            if let Some((scope, n)) = pkg.name.split_once('/').filter(|_| pkg.name.starts_with('@')) {
                ns = scope.to_string();
                name = n.to_string();
            }
            "npm"
        }
        "cargo" => {
            ns = String::new();
            "cargo"
        }
        "gem" => {
            ns = String::new();
            "gem"
        }
        "go" => {
            // pkg:golang/github.com/rakyll/hey@v0.1.4
            let (n, last) = pkg.name.rsplit_once('/').unwrap_or(("", &pkg.name));
            ns = n.to_string();
            name = last.to_string();
            "golang"
        }
        "snap" => {
            ns = "snap".into();
            if let Some(r) = pkg.extra.get("revision").and_then(|v| v.as_str()) {
                quals.push(("revision".into(), r.into()));
            }
            "generic"
        }
        "flatpak" => {
            ns = "flatpak".into();
            quals = vec![arch()];
            if let Some(c) = &pkg.checksum {
                quals.push(("commit".into(), c.clone()));
            }
            "generic"
        }
        "files" => {
            ns = String::new();
            name = pkg.name.rsplit('/').next().unwrap_or(&pkg.name).to_string();
            quals.push(("path".into(), pkg.name.clone()));
            "generic"
        }
        "apps" => {
            ns = "macos-app".into();
            if let Some(id) = pkg.extra.get("bundle_id").and_then(|v| v.as_str()) {
                quals.push(("bundle_id".into(), id.into()));
            }
            "generic"
        }
        _ => "generic",
    };
    let mut out = format!("pkg:{typ}/");
    if !ns.is_empty() {
        let segs: Vec<String> = ns
            .split('/')
            .map(|s| pct(&if typ == "brew" || typ == "npm" { s.to_ascii_lowercase() } else { s.to_string() }, ""))
            .collect();
        out += &(segs.join("/") + "/");
    }
    out += &format!("{}@{}", pct(&name, ""), pct(&pkg.version, ":"));
    quals.retain(|(_, v)| !v.is_empty());
    quals.sort();
    if !quals.is_empty() {
        out += &("?".to_string()
            + &quals
                .iter()
                .map(|(k, v)| format!("{k}={}", pct(v, if k == "path" { ":/" } else { ":" })))
                .collect::<Vec<_>>()
                .join("&"));
    }
    out
}

// ------------------------------------------------------------ licenses

#[derive(Debug, Clone, PartialEq)]
pub enum Lic {
    Leaf(String),
    Op(&'static str, Vec<Lic>),
}

fn join(op: &'static str, a: Option<Lic>, b: Option<Lic>) -> Option<Lic> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => {
            let mut kids = Vec::new();
            for x in [a, b] {
                match x {
                    Lic::Op(o, k) if o == op => kids.extend(k),
                    other => kids.push(other),
                }
            }
            Some(Lic::Op(op, kids))
        }
    }
}

/// Parse a license string into a tree. Precedence, loosest first:
/// ',' / ';' (DEP-5 lists, optionally followed by 'and'/'or'), OR (also
/// '/'), AND, parentheses. Words that are not operators form one name, so
/// 'GPL-3+ with Bison exception' is one leaf.
pub fn parse_license(item: &str) -> Option<Lic> {
    let mut toks: Vec<String> = Vec::new();
    let mut word = String::new();
    for c in item.chars() {
        if "(),;/".contains(c) || c.is_whitespace() {
            if !word.is_empty() {
                toks.push(std::mem::take(&mut word));
            }
            if !c.is_whitespace() {
                toks.push(c.to_string());
            }
        } else {
            word.push(c);
        }
    }
    if !word.is_empty() {
        toks.push(word);
    }
    struct P {
        t: Vec<String>,
        i: usize,
    }
    impl P {
        fn peek(&self) -> Option<&str> {
            self.t.get(self.i).map(String::as_str)
        }
        fn is_op(s: &str) -> Option<&'static str> {
            match s.to_ascii_lowercase().as_str() {
                "and" => Some("AND"),
                "or" => Some("OR"),
                _ => None,
            }
        }
        fn atom(&mut self) -> Option<Lic> {
            if self.peek() == Some("(") {
                self.i += 1;
                let inner = self.list();
                if self.peek() == Some(")") {
                    self.i += 1;
                }
                return inner;
            }
            let mut words = Vec::new();
            while let Some(t) = self.peek() {
                if "(),;/".contains(t) && t.len() == 1 || Self::is_op(t).is_some() {
                    break;
                }
                words.push(t.to_string());
                self.i += 1;
            }
            (!words.is_empty()).then(|| Lic::Leaf(words.join(" ")))
        }
        fn and_expr(&mut self) -> Option<Lic> {
            let mut left = self.atom();
            while self.peek().and_then(Self::is_op) == Some("AND") {
                self.i += 1;
                let right = self.atom();
                left = join("AND", left, right);
            }
            left
        }
        fn or_expr(&mut self) -> Option<Lic> {
            let mut left = self.and_expr();
            while self.peek().is_some_and(|t| t == "/" || Self::is_op(t) == Some("OR")) {
                self.i += 1;
                let right = self.and_expr();
                left = join("OR", left, right);
            }
            left
        }
        fn list(&mut self) -> Option<Lic> {
            let mut left = self.or_expr();
            while matches!(self.peek(), Some(",") | Some(";")) {
                self.i += 1;
                let mut op = "AND";
                if let Some(o) = self.peek().and_then(Self::is_op) {
                    op = o;
                    self.i += 1;
                }
                let right = self.or_expr();
                left = join(op, left, right);
            }
            left
        }
    }
    let mut p = P { t: toks, i: 0 };
    let mut tree = p.list();
    while p.i < p.t.len() {
        // stray ')' etc.: keep whatever follows, combined with AND
        p.i += 1;
        let rest = p.list();
        tree = join("AND", tree, rest);
    }
    tree
}

fn leaves(t: &Lic, out: &mut Vec<String>) {
    match t {
        Lic::Leaf(s) => out.push(s.clone()),
        Lic::Op(_, k) => k.iter().for_each(|x| leaves(x, out)),
    }
}

/// Split license strings into (spdx ids, unrecognised names).
pub fn license_ids(raw: &[String]) -> (Vec<String>, Vec<String>) {
    let (mut ids, mut names) = (BTreeSet::new(), BTreeSet::new());
    for item in raw {
        let mut l = Vec::new();
        if let Some(t) = parse_license(item) {
            leaves(&t, &mut l);
        }
        for tok in l {
            match map_token(&tok) {
                (Some(i), _) => {
                    ids.insert(i);
                }
                (_, Some(n)) => {
                    names.insert(n);
                }
                _ => {}
            }
        }
    }
    (ids.into_iter().collect(), names.into_iter().collect())
}

fn spdx_id(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out
}

fn render(t: &Lic, extracted: &mut BTreeMap<String, String>, parent: &str) -> String {
    match t {
        Lic::Leaf(s) => match map_token(s) {
            (Some(i), _) => i,
            (_, n) => {
                let n = n.unwrap_or_default();
                let id = format!("LicenseRef-{}", spdx_id(&n));
                extracted.insert(id.clone(), n);
                id
            }
        },
        Lic::Op(op, kids) => {
            let mut parts: Vec<String> = Vec::new();
            for k in kids {
                let r = render(k, extracted, op);
                if !parts.contains(&r) {
                    parts.push(r);
                }
            }
            let out = parts.join(&format!(" {op} "));
            if !parent.is_empty() && parent != *op && parts.len() > 1 {
                format!("({out})")
            } else {
                out
            }
        }
    }
}

/// SPDX expression preserving the grouping of the source metadata.
/// Separate entries (different files of one package) are combined with AND.
pub fn spdx_expression(raw: &[String], extracted: &mut BTreeMap<String, String>) -> String {
    let tree = raw.iter().filter_map(|i| parse_license(i)).fold(None, |acc, t| join("AND", acc, Some(t)));
    match tree {
        Some(t) => render(&t, extracted, ""),
        None => "NOASSERTION".into(),
    }
}

// ------------------------------------------------------------ documents

/// The best hash a lock entry has: (CycloneDX algorithm, hex value).
fn hashes(manager: &str, p: &Package, plat: &Platform) -> Option<(&'static str, String)> {
    if let Some(s) = &p.sha256 {
        return Some(("SHA-256", s.clone()));
    }
    if manager == "brew" {
        if let Some(b) = &p.bottles {
            if let Some(h) = b.get(&managers::brew::bottle_tag(plat)).or_else(|| b.get("all")) {
                return Some(("SHA-256", h.clone()));
            }
        }
    }
    if manager == "rpm" {
        if let Some(d) = p.payload_digest.as_ref().filter(|d| d.len() == 64) {
            return Some(("SHA-256", d.clone()));
        }
    }
    // npm's Subresource Integrity strings: "sha512-<base64>"
    if let Some((alg, hex)) = p.extra.get("integrity").and_then(|v| v.as_str()).and_then(managers::npm::integrity_hex) {
        match alg.as_str() {
            "SHA512" => return Some(("SHA-512", hex)),
            "SHA256" => return Some(("SHA-256", hex)),
            _ => {}
        }
    }
    None
}

/// CycloneDX component type for a lock entry.
fn component_type(manager: &str, p: &Package) -> &'static str {
    match (manager, p.kind()) {
        ("files", _) => "file",
        ("apps", _) | ("brew", "cask") | ("go", "binary") | ("cargo", _) | ("pip", "pipx") => "application",
        ("snap", "app") => "application",
        ("flatpak", k) if k.starts_with("app/") => "application",
        _ => "library",
    }
}

fn iter_pkgs(env: &Environment) -> impl Iterator<Item = (&String, &Package)> {
    env.managers.iter().flat_map(|(m, s)| s.packages.iter().map(move |p| (m, p)))
}

/// (manager, lock key) -> purl, used to wire dependencies.
fn refs(env: &Environment) -> HashMap<(String, String), String> {
    let mut res = HashMap::new();
    for (m, p) in iter_pkgs(env) {
        let key = managers::get(m).map(|mg| mg.key_of(p, &env.platform)).unwrap_or_else(|| p.name.clone());
        res.entry((m.clone(), key)).or_insert_with(|| purl(m, p, &env.platform));
    }
    res
}

pub fn cyclonedx(eid: &str, env: &Environment) -> Value {
    let plat = &env.platform;
    let refs = refs(env);
    let root = format!("matsya:env:{eid}");
    let mut components: BTreeMap<String, Value> = BTreeMap::new();
    let mut deps: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut roots = BTreeSet::new();
    for (m, p) in iter_pkgs(env) {
        let r = purl(m, p, plat);
        if components.contains_key(&r) {
            continue;
        }
        let mut c = json!({
            "type": component_type(m, p),
            "bom-ref": r, "name": p.name, "version": p.full_version(), "purl": r,
        });
        if let Some((alg, h)) = hashes(m, p, plat) {
            c["hashes"] = json!([{"alg": alg, "content": h}]);
        }
        let (ids, names) = license_ids(&p.licenses);
        let lic: Vec<Value> = ids
            .iter()
            .map(|i| json!({"license": {"id": i}}))
            .chain(names.iter().map(|n| json!({"license": {"name": n}})))
            .collect();
        if !lic.is_empty() {
            c["licenses"] = json!(lic);
        }
        let mut props = vec![("matsya:manager", m.clone()), ("matsya:reason", p.reason().to_string())];
        for (k, v) in [
            ("arch", p.arch.clone()),
            ("tap", p.tap.clone()),
            ("kind", p.kind.clone()),
            ("filename", p.filename.clone()),
        ] {
            if let Some(v) = v.filter(|v| !v.is_empty()) {
                props.push((
                    match k {
                        "arch" => "matsya:arch",
                        "tap" => "matsya:tap",
                        "kind" => "matsya:kind",
                        _ => "matsya:filename",
                    },
                    v,
                ));
            }
        }
        if let Some(r) = p.repositories.as_ref().filter(|r| !r.is_empty()) {
            props.push(("matsya:repositories", r.join(",")));
        }
        c["properties"] = json!(props
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| json!({"name": k, "value": v}))
            .collect::<Vec<_>>());
        if p.is_manual() {
            roots.insert(r.clone());
        }
        let d: BTreeSet<String> = p
            .dependencies
            .iter()
            .filter_map(|d| refs.get(&(m.clone(), d.clone())))
            .filter(|x| **x != r)
            .cloned()
            .collect();
        deps.insert(r.clone(), d.into_iter().collect());
        components.insert(r, c);
    }
    let mut dependencies = vec![json!({"ref": root, "dependsOn": roots.into_iter().collect::<Vec<_>>()})];
    dependencies.extend(deps.into_iter().map(|(r, d)| json!({"ref": r, "dependsOn": d})));
    let serial = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!("matsya:{eid}:{}", env.digest.clone().unwrap_or_default()).as_bytes(),
    );
    let props: Vec<Value> = [("arch", plat.arch()), ("release", plat.release()), ("codename", plat.codename())]
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| json!({"name": format!("matsya:{k}"), "value": v}))
        .collect();
    json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": format!("urn:uuid:{serial}"),
        "version": 1,
        "metadata": {
            "timestamp": env.captured_at,
            "tools": {"components": [{"type": "application", "name": "matsya", "version": env!("CARGO_PKG_VERSION"),
                "externalReferences": [{"type": "vcs", "url": "https://github.com/dmdhrumilmistry/matsya"}]}]},
            "component": {"type": "operating-system", "bom-ref": root, "name": plat.distro(),
                "version": if plat.version().is_empty() { plat.release() } else { plat.version() }, "properties": props},
            "properties": [{"name": "matsya:environment", "value": eid}, {"name": "matsya:lockDigest", "value": env.digest.clone().unwrap_or_default()}],
        },
        "components": components.into_values().collect::<Vec<_>>(),
        "dependencies": dependencies,
    })
}

pub fn spdx(eid: &str, env: &Environment) -> Value {
    let plat = &env.platform;
    let refs = refs(env);
    let os_id = "SPDXRef-OperatingSystem";
    let mut packages = vec![json!({
        "SPDXID": os_id, "name": plat.distro(), "versionInfo": if plat.version().is_empty() { plat.release() } else { plat.version() },
        "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "primaryPackagePurpose": "OPERATING-SYSTEM",
        "copyrightText": "NOASSERTION", "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
    })];
    let mut rels = vec![
        json!({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": os_id}),
    ];
    let mut extracted = BTreeMap::new();
    let mut id_of: HashMap<String, String> = HashMap::new();
    let mut used: HashMap<String, usize> = HashMap::new();
    for (m, p) in iter_pkgs(env) {
        let r = purl(m, p, plat);
        if id_of.contains_key(&r) {
            continue;
        }
        let base = spdx_id(&format!("SPDXRef-{m}-{}-{}", p.name, p.arch()));
        let n = used.entry(base.clone()).or_default();
        *n += 1;
        let sid = if *n == 1 { base } else { format!("{base}-{n}") };
        id_of.insert(r.clone(), sid.clone());
        let mut pk = json!({
            "SPDXID": sid, "name": p.name, "versionInfo": p.full_version(), "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false, "primaryPackagePurpose": match component_type(m, p) {
                "application" => "APPLICATION",
                "file" => "FILE",
                _ => "LIBRARY",
            },
            "copyrightText": "NOASSERTION", "licenseConcluded": "NOASSERTION",
            "licenseDeclared": spdx_expression(&p.licenses, &mut extracted),
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": r}],
        });
        if let Some((alg, h)) = hashes(m, p, plat) {
            pk["checksums"] = json!([{"algorithm": alg.replace('-', ""), "checksumValue": h}]);
        }
        packages.push(pk);
        rels.push(json!({"spdxElementId": os_id, "relationshipType": "CONTAINS", "relatedSpdxElement": sid}));
    }
    for (m, p) in iter_pkgs(env) {
        let sid = &id_of[&purl(m, p, plat)];
        for d in &p.dependencies {
            if let Some(t) = refs.get(&(m.clone(), d.clone())).and_then(|r| id_of.get(r)).filter(|t| *t != sid) {
                rels.push(json!({"spdxElementId": sid, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": t}));
            }
        }
    }
    let digest: String = env.digest.clone().unwrap_or_default().replace("sha256:", "").chars().take(32).collect();
    let mut doc = json!({
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": format!("matsya-{eid}"),
        "documentNamespace": format!("https://github.com/dmdhrumilmistry/matsya/spdx/{eid}-{digest}"),
        "creationInfo": {"created": env.captured_at, "creators": [format!("Tool: matsya-{}", env!("CARGO_PKG_VERSION"))]},
        "packages": packages, "relationships": rels,
    });
    if !extracted.is_empty() {
        doc["hasExtractedLicensingInfos"] = json!(extracted
            .iter()
            .map(|(k, v)| json!({"licenseId": k, "name": v, "extractedText": format!("License as declared by the package manager: {v}")}))
            .collect::<Vec<_>>());
    }
    doc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Source;

    fn plat(os_release: &str) -> Platform {
        crate::platform::from_os_release(os_release, "x86_64".into())
    }

    fn p(n: &str, v: &str, a: &str) -> Package {
        let mut x = Package::new(n, v);
        if !a.is_empty() {
            x.arch = Some(a.into());
        }
        x
    }

    #[test]
    fn purls() {
        let ubu = plat("ID=ubuntu\nVERSION_ID=24.04\n");
        assert_eq!(
            purl("apt", &p("dpkg", "1:1.22.6ubuntu6", "amd64"), &ubu),
            "pkg:deb/ubuntu/dpkg@1:1.22.6ubuntu6?arch=amd64&distro=ubuntu-24.04"
        );
        let mut cpp = p("libstdc++6", "14.2.0-4", "amd64");
        cpp.source = Some(Source { name: "gcc-14".into(), version: Some("14.2.0-4".into()) });
        assert_eq!(
            purl("apt", &cpp, &ubu),
            "pkg:deb/ubuntu/libstdc%2B%2B6@14.2.0-4?arch=amd64&distro=ubuntu-24.04&upstream=gcc-14%4014.2.0-4"
        );
        let mut ossl = p("openssl-libs", "3.2.2-3.fc40", "x86_64");
        ossl.epoch = Some(json!(1));
        assert_eq!(
            purl("rpm", &ossl, &plat("ID=fedora\nVERSION_ID=40\n")),
            "pkg:rpm/fedora/openssl-libs@3.2.2-3.fc40?arch=x86_64&distro=fedora-40&epoch=1"
        );
        assert_eq!(
            purl("rpm", &p("bash", "5.2-1.el9", "x86_64"), &plat("ID=rhel\nVERSION_ID=9.4\n")),
            "pkg:rpm/redhat/bash@5.2-1.el9?arch=x86_64&distro=rhel-9"
        );
        assert_eq!(
            purl("pacman", &p("curl", "1:8.10.1-1", "x86_64"), &plat("ID=arch\n")),
            "pkg:alpm/arch/curl@1:8.10.1-1?arch=x86_64&distro=arch"
        );
        assert_eq!(
            purl("apk", &p("musl", "1.2.5-r0", "x86_64"), &plat("ID=alpine\nVERSION_ID=3.20.1\n")),
            "pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=alpine-3.20"
        );
        let mac = Platform { distro: Some("macos".into()), ..Default::default() };
        let mut pg = p("postgresql@16", "16.4", "");
        pg.tap = Some("homebrew/core".into());
        assert_eq!(purl("brew", &pg, &mac), "pkg:brew/postgresql%4016@16.4");
        let mut t = p("Acme/Tools/mytool", "1.0", "");
        t.tap = Some("Acme/Tools".into());
        assert_eq!(purl("brew", &t, &mac), "pkg:brew/acme/tools/mytool@1.0");
        let mut ff = p("firefox", "131.0", "");
        ff.kind = Some("cask".into());
        ff.tap = Some("homebrew/cask".into());
        assert_eq!(purl("brew", &ff, &mac), "pkg:brew/homebrew/cask/firefox@131.0");
    }

    #[test]
    fn ecosystem_purls() {
        let any = Platform::default();
        let mk = |n: &str, v: &str| Package::new(n, v);
        assert_eq!(purl("pip", &mk("Foo_Bar", "1.0"), &any), "pkg:pypi/foo-bar@1.0");
        assert_eq!(purl("npm", &mk("@Angular/cli", "17.0.0"), &any), "pkg:npm/%40angular/cli@17.0.0");
        assert_eq!(purl("npm", &mk("cowsay", "1.6.0"), &any), "pkg:npm/cowsay@1.6.0");
        assert_eq!(purl("cargo", &mk("ripgrep", "14.1.0"), &any), "pkg:cargo/ripgrep@14.1.0");
        assert_eq!(purl("go", &mk("github.com/rakyll/hey", "v0.1.4"), &any), "pkg:golang/github.com/rakyll/hey@v0.1.4");
        assert_eq!(purl("gem", &mk("rails", "7.1.3"), &any), "pkg:gem/rails@7.1.3");
        assert_eq!(
            purl("files", &mk("/usr/local/bin/tool", "sha256:abcd"), &any),
            "pkg:generic/tool@sha256:abcd?path=/usr/local/bin/tool"
        );
        let mut snap = mk("jq", "1.5");
        snap.extra.insert("revision".into(), json!("6"));
        assert_eq!(purl("snap", &snap, &any), "pkg:generic/snap/jq@1.5?revision=6");
    }

    #[test]
    fn licenses() {
        let raw: Vec<String> = ["GPL-2+ and MIT", "Expat", "LicenseRef-Fedora-Public-Domain", "public-domain"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (ids, names) = license_ids(&raw);
        assert_eq!(ids, vec!["GPL-2.0-or-later", "MIT"]);
        assert_eq!(names, vec!["LicenseRef-Fedora-Public-Domain", "public-domain"]);
        let e = |v: &[&str]| {
            let mut ex = BTreeMap::new();
            spdx_expression(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>(), &mut ex)
        };
        assert_eq!(e(&["GPL-1+ or Artistic"]), "GPL-1.0-or-later OR LicenseRef-Artistic");
        assert_eq!(e(&["MIT", "GPL-2+ or BSD-3-clause"]), "MIT AND (GPL-2.0-or-later OR BSD-3-Clause)");
        assert_eq!(e(&[]), "NOASSERTION");
        assert_eq!(e(&["(MIT OR Apache-2.0) AND Unicode-DFS-2016"]), "(MIT OR Apache-2.0) AND Unicode-DFS-2016");
        assert_eq!(e(&["GPL-2+ or AFL-2.1, and Expat"]), "(GPL-2.0-or-later OR AFL-2.1) AND MIT");
        assert_eq!(e(&["GPL-3+ with Bison exception"]), "LicenseRef-GPL-3-with-Bison-exception");
        assert_eq!(e(&["MIT/X11"]), "MIT OR X11");
        assert_eq!(e(&["MIT) AND (BSD-3-Clause"]), "MIT AND BSD-3-Clause");
    }

    #[test]
    fn documents_are_consistent() {
        let lock =
            crate::lockfile::load(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/multi-machine.lock.json")).unwrap();
        for (eid, env) in &lock.environments {
            let c = cyclonedx(eid, env);
            let refs: BTreeSet<&str> =
                c["components"].as_array().unwrap().iter().map(|x| x["bom-ref"].as_str().unwrap()).collect();
            assert_eq!(refs.len(), c["components"].as_array().unwrap().len(), "{eid}: duplicate bom-refs");
            for d in c["dependencies"].as_array().unwrap().iter().skip(1) {
                for t in d["dependsOn"].as_array().unwrap() {
                    assert!(refs.contains(t.as_str().unwrap()), "{eid}: dangling {t}");
                }
            }
            assert_eq!(c, cyclonedx(eid, env), "deterministic");
            let s = spdx(eid, env);
            let ids: BTreeSet<&str> =
                s["packages"].as_array().unwrap().iter().map(|x| x["SPDXID"].as_str().unwrap()).collect();
            assert_eq!(ids.len(), s["packages"].as_array().unwrap().len());
            for r in s["relationships"].as_array().unwrap() {
                assert!(ids.contains(r["relatedSpdxElement"].as_str().unwrap()));
            }
            for id in &ids {
                assert!(id.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'), "{id}");
            }
        }
    }
}
