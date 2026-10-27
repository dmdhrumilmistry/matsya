//! Go programs installed with `go install`, read from the build information
//! the Go linker embeds in every binary (Go 1.18+): main package path,
//! module version and `h1:` checksum, plus every dependency module.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use super::eco::{extra_str, scope_allowed, set_extra, tilde, untilde, user_home, Scope};
use super::{Manager, Options, RootPolicy};
use crate::model::{Package, Section};
use crate::plan::{Plan, Step};
use crate::platform::Platform;
use crate::util::{has, Result};

const MAGIC: &[u8] = b"\xff Go buildinf:";
/// Go binaries above this size are not scanned (sanity limit).
const MAX_BINARY: u64 = 1 << 30;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Module {
    pub path: String,
    pub version: String,
    pub sum: String,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct BuildInfo {
    pub go_version: String,
    /// Main package path ("github.com/rakyll/hey").
    pub path: String,
    pub main: Module,
    pub deps: Vec<Module>,
}

fn uvarint(b: &[u8], mut i: usize) -> Option<(u64, usize)> {
    let mut x: u64 = 0;
    let mut shift = 0;
    loop {
        let byte = *b.get(i)?;
        i += 1;
        x |= ((byte & 0x7f) as u64) << shift;
        if byte < 0x80 {
            return Some((x, i));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

/// Parse the embedded build info of a Go binary (inline format, Go 1.18+).
pub fn parse_buildinfo(bin: &[u8]) -> Option<BuildInfo> {
    let off = bin.windows(MAGIC.len()).step_by(1).position(|w| w == MAGIC)?;
    let hdr = bin.get(off..off + 32)?;
    if hdr[15] & 2 == 0 {
        return None; // pre-1.18 pointer format: needs symbol tables; not supported
    }
    let (n, i) = uvarint(bin, off + 32)?;
    let go_version = String::from_utf8_lossy(bin.get(i..i + n as usize)?).into_owned();
    let (m, j) = uvarint(bin, i + n as usize)?;
    let mut modinfo = bin.get(j..j + m as usize)?;
    // modinfo is wrapped in 16-byte sentinels.
    if modinfo.len() >= 33 && modinfo[modinfo.len() - 17] == b'\n' {
        modinfo = &modinfo[16..modinfo.len() - 16];
    }
    let mut info = BuildInfo { go_version, ..Default::default() };
    for line in String::from_utf8_lossy(modinfo).lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let module = |f: &[&str]| Module {
            path: f.get(1).unwrap_or(&"").to_string(),
            version: f.get(2).unwrap_or(&"").to_string(),
            sum: f.get(3).unwrap_or(&"").to_string(),
        };
        match f.first().copied() {
            Some("path") => info.path = f.get(1).unwrap_or(&"").to_string(),
            Some("mod") => info.main = module(&f),
            Some("dep") => info.deps.push(module(&f)),
            // A replacement applies to the module listed just before it.
            Some("=>") => {
                if let Some(last) = info.deps.last_mut() {
                    *last = module(&f);
                }
            }
            _ => {}
        }
    }
    (!info.path.is_empty()).then_some(info)
}

pub fn bin_dirs() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    if let Some(b) = std::env::var_os("GOBIN").filter(|v| !v.is_empty()) {
        out.push(PathBuf::from(b));
    }
    if let Some(gp) = std::env::var_os("GOPATH") {
        if let Some(first) = std::env::split_paths(&gp).next() {
            out.push(first.join("bin"));
        }
    }
    if let Some(h) = user_home() {
        out.push(h.join("go/bin"));
    }
    out.dedup();
    out.into_iter().filter(|d| d.is_dir()).collect()
}

fn key(p: &Package) -> String {
    match p.kind() {
        "module" => format!("module:{}@{}", p.name, p.version),
        _ => format!("binary:{}", extra_str(p, "binary").unwrap_or(&p.name)),
    }
}

/// Binaries and their dependency modules from the given directories.
pub fn scan_dirs(dirs: &[PathBuf]) -> Vec<Package> {
    let mut out = Vec::new();
    let mut modules: BTreeMap<(String, String), Package> = BTreeMap::new();
    for dir in dirs {
        let mut files: Vec<PathBuf> =
            std::fs::read_dir(dir).map(|d| d.flatten().map(|e| e.path()).collect()).unwrap_or_default();
        files.sort();
        for f in files {
            let Ok(meta) = std::fs::metadata(&f) else { continue };
            if !meta.is_file() || meta.len() > MAX_BINARY {
                continue;
            }
            let Ok(bytes) = std::fs::read(&f) else { continue };
            let Some(info) = parse_buildinfo(&bytes) else { continue };
            let file = f.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let mut p = Package::new(info.path.clone(), info.main.version.clone());
            p.kind = Some("binary".into());
            p.reason = Some("manual".into());
            if !info.main.sum.is_empty() {
                p.checksum = Some(info.main.sum.clone());
            }
            set_extra(&mut p, "binary", file);
            set_extra(&mut p, "module", info.main.path.clone());
            set_extra(&mut p, "go", info.go_version.clone());
            set_extra(&mut p, "location", tilde(dir));
            let mut deps = BTreeSet::new();
            for m in &info.deps {
                let mut d = Package::new(m.path.clone(), m.version.clone());
                d.kind = Some("module".into());
                d.reason = Some("dependency".into());
                if !m.sum.is_empty() {
                    d.checksum = Some(m.sum.clone());
                }
                deps.insert(key(&d));
                modules.entry((m.path.clone(), m.version.clone())).or_insert(d);
            }
            p.dependencies = deps.into_iter().collect();
            out.push(p);
        }
    }
    out.extend(modules.into_values());
    out
}

pub struct Go;

impl Manager for Go {
    fn name(&self) -> &'static str {
        "go"
    }

    fn root_policy(&self) -> RootPolicy {
        RootPolicy::PerPackage
    }

    fn optional(&self) -> bool {
        true
    }

    /// Go programs live in the user's GOBIN.
    fn scope_of(&self, _pkg: &Package) -> super::eco::Scope {
        super::eco::Scope::User
    }

    fn available(&self) -> bool {
        !bin_dirs().is_empty() || has("go")
    }

    fn key_of(&self, pkg: &Package, _plat: &Platform) -> String {
        key(pkg)
    }

    fn installed(&self, _plat: &Platform) -> Result<Vec<Package>> {
        Ok(scan_dirs(&bin_dirs()))
    }

    fn capture(&self, _plat: &Platform, _opts: &Options) -> Result<Section> {
        Ok(Section {
            tool: Some("go (embedded build info)".into()),
            packages: scan_dirs(&bin_dirs()),
            ..Default::default()
        })
    }

    fn plan(&self, section: &Section, _src: &Platform, _dst: &Platform, _opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("go");
        let installed = scan_dirs(&bin_dirs());
        let current: HashMap<String, &Package> = installed.iter().map(|p| (key(p), p)).collect();
        let todo: Vec<&Package> = section
            .packages
            .iter()
            .filter(|p| p.kind() == "binary")
            .filter(|p| current.get(&key(p)).map(|c| &c.version) != Some(&p.version))
            .collect();
        let mut n = 0;
        if !todo.is_empty() && scope_allowed(Scope::User, "Go programs", &mut plan) {
            if !has("go") {
                plan.unresolved.push(format!("{} Go program(s) (the go toolchain is not installed)", todo.len()));
            } else {
                for p in todo {
                    if p.version.is_empty() || p.version == "(devel)" {
                        plan.unresolved.push(format!("{} (built from a local checkout, no module version)", p.name));
                        continue;
                    }
                    let gobin = untilde(extra_str(p, "location").unwrap_or("~/go/bin")).to_string_lossy().into_owned();
                    plan.add(
                        Step::cmd(
                            format!("go install {}@{}", p.name, p.version),
                            ["go".to_string(), "install".into(), format!("{}@{}", p.name, p.version)],
                        )
                        .with_env("GOBIN", &gobin),
                    );
                    n += 1;
                }
            }
        }
        plan.summary = vec![("install".into(), n), ("unresolved".into(), plan.unresolved.len())];
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the bytes the Go linker writes for buildinfo (inline format).
    fn fake_binary(version: &str, modinfo: &str) -> Vec<u8> {
        let mut b = vec![0u8; 100];
        b.extend_from_slice(MAGIC);
        b.push(8); // pointer size
        b.push(2); // flags: inline strings
        b.extend_from_slice(&[0u8; 16]);
        let push_str = |s: &[u8], b: &mut Vec<u8>| {
            let mut n = s.len() as u64;
            loop {
                let byte = (n & 0x7f) as u8;
                n >>= 7;
                if n == 0 {
                    b.push(byte);
                    break;
                }
                b.push(byte | 0x80);
            }
            b.extend_from_slice(s);
        };
        push_str(version.as_bytes(), &mut b);
        let mut wrapped = b"0123456789abcdef".to_vec();
        wrapped.extend_from_slice(modinfo.as_bytes());
        wrapped.extend_from_slice(b"fedcba9876543210");
        push_str(&wrapped, &mut b);
        b.extend_from_slice(&[0u8; 64]);
        b
    }

    #[test]
    fn parses_embedded_build_info() {
        let modinfo = "path\tgithub.com/rakyll/hey\nmod\tgithub.com/rakyll/hey\tv0.1.4\th1:main=\ndep\tgolang.org/x/net\tv0.0.1\th1:net=\n=>\tgolang.org/x/net\tv0.0.2\th1:repl=\ndep\tgolang.org/x/text\tv0.3.0\th1:text=\nbuild\t-compiler=gc\n";
        let bin = fake_binary("go1.22.4", modinfo);
        let info = parse_buildinfo(&bin).unwrap();
        assert_eq!(info.go_version, "go1.22.4");
        assert_eq!(info.path, "github.com/rakyll/hey");
        assert_eq!(
            info.main,
            Module { path: "github.com/rakyll/hey".into(), version: "v0.1.4".into(), sum: "h1:main=".into() }
        );
        assert_eq!(info.deps.len(), 2);
        assert_eq!(info.deps[0].version, "v0.0.2"); // replacement applied
        assert!(parse_buildinfo(b"not a go binary").is_none());

        let dir = std::env::temp_dir().join(format!("matsya-go-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hey"), &bin).unwrap();
        std::fs::write(dir.join("script.sh"), b"#!/bin/sh\n").unwrap();
        let pkgs = scan_dirs(std::slice::from_ref(&dir));
        assert_eq!(pkgs.len(), 3); // one binary + two modules
        let hey = pkgs.iter().find(|p| p.kind() == "binary").unwrap();
        assert_eq!((hey.version.as_str(), hey.checksum.as_deref()), ("v0.1.4", Some("h1:main=")));
        assert_eq!(hey.dependencies, vec!["module:golang.org/x/net@v0.0.2", "module:golang.org/x/text@v0.3.0"]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
