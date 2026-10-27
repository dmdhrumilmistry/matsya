//! Binaries installed with `cargo install`, recorded by cargo itself in
//! `$CARGO_HOME/.crates2.json` (or the older `.crates.toml`).

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use serde_json::{json, Value};

use super::eco::{extra_str, scope_allowed, set_extra, tilde, user_home, Scope};
use super::{Manager, Options, RootPolicy};
use crate::model::{Package, Section};
use crate::plan::{Plan, Step};
use crate::platform::Platform;
use crate::util::{has, read_text_opt, Result};

pub fn cargo_home() -> Option<PathBuf> {
    std::env::var_os("CARGO_HOME").map(PathBuf::from).or_else(|| user_home().map(|h| h.join(".cargo")))
}

/// "ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)"
pub fn parse_install_key(k: &str) -> Option<(String, String, String)> {
    let (head, src) = k.split_once(" (")?;
    let (name, ver) = head.split_once(' ')?;
    Some((name.to_string(), ver.to_string(), src.trim_end_matches(')').to_string()))
}

/// Installed crates from .crates2.json (v2) or .crates.toml (v1).
pub fn parse_crates(v2: Option<&str>, v1: Option<&str>, location: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut push = |key: &str, info: Option<&Value>, bins: Vec<String>| {
        let Some((name, ver, src)) = parse_install_key(key) else { return };
        let mut p = Package::new(name, ver);
        p.kind = Some("user".into());
        p.reason = Some("manual".into());
        set_extra(&mut p, "location", location);
        set_extra(&mut p, "from", src);
        if !bins.is_empty() {
            set_extra(&mut p, "bins", json!(bins));
        }
        if let Some(i) = info {
            let feats: Vec<String> = i
                .get("features")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|f| f.as_str().map(String::from)).collect())
                .unwrap_or_default();
            if !feats.is_empty() {
                set_extra(&mut p, "features", json!(feats));
            }
            for flag in ["all_features", "no_default_features"] {
                if i.get(flag).and_then(Value::as_bool) == Some(true) {
                    set_extra(&mut p, flag, true);
                }
            }
        }
        out.push(p);
    };
    if let Some(v) = v2.and_then(|t| serde_json::from_str::<Value>(t).ok()) {
        for (k, info) in v.get("installs").and_then(Value::as_object).into_iter().flatten() {
            let bins = info
                .get("bins")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|b| b.as_str().map(String::from)).collect())
                .unwrap_or_default();
            push(k, Some(info), bins);
        }
    } else if let Some(t) = v1.and_then(|t| t.parse::<toml::Table>().ok()) {
        for (k, bins) in t.get("v1").and_then(|v| v.as_table()).into_iter().flatten() {
            let bins = bins
                .as_array()
                .map(|a| a.iter().filter_map(|b| b.as_str().map(String::from)).collect())
                .unwrap_or_default();
            push(k, None, bins);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

pub fn scan() -> Vec<Package> {
    let Some(home) = cargo_home() else { return vec![] };
    parse_crates(
        read_text_opt(home.join(".crates2.json")).as_deref(),
        read_text_opt(home.join(".crates.toml")).as_deref(),
        &tilde(&home),
    )
}

/// cargo install arguments that reproduce an install from its source.
pub fn install_args(p: &Package) -> Option<Vec<String>> {
    let src = extra_str(p, "from").unwrap_or("");
    let mut a: Vec<String> = vec!["cargo".into(), "install".into(), "--locked".into(), "--force".into()];
    if src.starts_with("registry+") || src.starts_with("sparse+") || src.is_empty() {
        a.extend([p.name.clone(), "--version".into(), format!("={}", p.version)]);
    } else if let Some(rest) = src.strip_prefix("git+") {
        let (url, rev) = rest.split_once('#').unwrap_or((rest, ""));
        let url = url.split('?').next().unwrap_or(url);
        a.extend(["--git".into(), url.into()]);
        if !rev.is_empty() {
            a.extend(["--rev".into(), rev.into()]);
        }
        a.push(p.name.clone());
    } else {
        let path = src.strip_prefix("path+file://")?;
        if !std::path::Path::new(path).is_dir() {
            return None;
        }
        a.extend(["--path".into(), path.into()]);
    }
    if let Some(f) = p.extra.get("features").and_then(Value::as_array) {
        let list: Vec<&str> = f.iter().filter_map(Value::as_str).collect();
        if !list.is_empty() {
            a.extend(["--features".into(), list.join(",")]);
        }
    }
    if p.extra.contains_key("all_features") {
        a.push("--all-features".into());
    }
    if p.extra.contains_key("no_default_features") {
        a.push("--no-default-features".into());
    }
    Some(a)
}

pub struct Cargo;

impl Manager for Cargo {
    fn name(&self) -> &'static str {
        "cargo"
    }

    fn root_policy(&self) -> RootPolicy {
        RootPolicy::PerPackage
    }

    fn optional(&self) -> bool {
        true
    }

    fn available(&self) -> bool {
        cargo_home().is_some_and(|h| h.join(".crates2.json").is_file() || h.join(".crates.toml").is_file())
            || has("cargo")
    }

    fn installed(&self, _plat: &Platform) -> Result<Vec<Package>> {
        Ok(scan())
    }

    fn capture(&self, _plat: &Platform, _opts: &Options) -> Result<Section> {
        Ok(Section { tool: Some("cargo install (.crates2.json)".into()), packages: scan(), ..Default::default() })
    }

    fn plan(&self, section: &Section, _src: &Platform, _dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("cargo");
        let installed = scan();
        let current: HashMap<&str, &Package> = installed.iter().map(|p| (p.name.as_str(), p)).collect();
        let todo: Vec<&Package> = section
            .packages
            .iter()
            .filter(|p| current.get(p.name.as_str()).map(|c| &c.version) != Some(&p.version))
            .collect();
        let mut n = 0;
        if !todo.is_empty() && scope_allowed(Scope::User, "cargo installs", &mut plan) {
            if !has("cargo") {
                plan.unresolved.push(format!("{} cargo install(s) (cargo is not installed)", todo.len()));
            } else {
                for p in todo {
                    match install_args(p) {
                        Some(argv) => {
                            plan.add(Step::cmd(format!("cargo install {} {}", p.name, p.version), argv));
                            n += 1;
                        }
                        None => plan.unresolved.push(format!(
                            "{} {} (installed from {}, which is not available here)",
                            p.name,
                            p.version,
                            extra_str(p, "from").unwrap_or("?")
                        )),
                    }
                }
            }
        }
        if opts.prune {
            let locked: BTreeSet<&str> = section.packages.iter().map(|p| p.name.as_str()).collect();
            for p in installed.iter().filter(|p| !locked.contains(p.name.as_str())) {
                if scope_allowed(Scope::User, "cargo installs", &mut plan) {
                    plan.add(Step::cmd(
                        format!("remove {} (not in the lock)", p.name),
                        ["cargo", "uninstall", &p.name],
                    ));
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

    #[test]
    fn crates2_and_install_args() {
        let v2 = r#"{"installs": {
            "ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)": {"bins": ["rg"], "features": ["pcre2"], "all_features": false, "no_default_features": false},
            "tool 0.3.0 (git+https://github.com/acme/tool?branch=main#0123abc)": {"bins": ["tool"], "features": []},
            "local 0.1.0 (path+file:///nonexistent/local)": {"bins": ["local"]}
        }}"#;
        let pkgs = parse_crates(Some(v2), None, "~/.cargo");
        assert_eq!(pkgs.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["local", "ripgrep", "tool"]);
        let rg = &pkgs[1];
        assert_eq!(
            install_args(rg).unwrap(),
            vec!["cargo", "install", "--locked", "--force", "ripgrep", "--version", "=14.1.0", "--features", "pcre2"]
        );
        assert_eq!(
            install_args(&pkgs[2]).unwrap(),
            vec![
                "cargo",
                "install",
                "--locked",
                "--force",
                "--git",
                "https://github.com/acme/tool",
                "--rev",
                "0123abc",
                "tool"
            ]
        );
        assert!(install_args(&pkgs[0]).is_none()); // local path that does not exist here
        let v1 = "[v1]\n\"bat 0.24.0 (registry+https://github.com/rust-lang/crates.io-index)\" = [\"bat\"]\n";
        assert_eq!(parse_crates(None, Some(v1), "~/.cargo")[0].version, "0.24.0");
    }
}
