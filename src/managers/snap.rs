//! Snaps, read from `/snap/<name>/current` (the active revision) and its
//! `meta/snap.yaml`. The tracking channel comes from snapd's state file
//! when it is readable (root only).

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use serde_json::Value;

use super::eco::{extra_str, scope_allowed, set_extra, subdirs, Scope};
use super::{Manager, Options, RootPolicy};
use crate::model::{Package, Section};
use crate::plan::{Plan, Step};
use crate::platform::Platform;
use crate::util::{read_text_opt, Result};

const SNAP_ROOT: &str = "/snap";
const STATE: &str = "/var/lib/snapd/state.json";

/// Top-level `key: value` pairs of a simple YAML document.
pub fn yaml_top(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter(|l| !l.starts_with(' ') && !l.starts_with('\t') && !l.starts_with('#'))
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().trim_matches(|c| c == '"' || c == '\'').to_string()))
        .filter(|(_, v)| !v.is_empty())
        .collect()
}

pub fn scan_root(root: &Path, state: Option<&Value>) -> Vec<Package> {
    let mut out = Vec::new();
    for dir in subdirs(root) {
        let name = dir.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let Ok(rev) = std::fs::read_link(dir.join("current")) else { continue };
        let rev = rev.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let Some(meta) = read_text_opt(dir.join(&rev).join("meta/snap.yaml")).map(|t| yaml_top(&t)) else { continue };
        let mut p = Package::new(
            meta.get("name").cloned().unwrap_or(name.clone()),
            meta.get("version").cloned().unwrap_or_default(),
        );
        let typ = meta.get("type").cloned().unwrap_or_else(|| "app".into());
        // Bases, snapd and core come along with apps; apps are what users ask for.
        p.reason = Some(if typ == "app" { "manual" } else { "dependency" }.into());
        p.kind = Some(typ);
        set_extra(&mut p, "revision", rev);
        if let Some(c) = meta.get("confinement") {
            set_extra(&mut p, "confinement", c.clone());
        }
        if let Some(b) = meta.get("base") {
            set_extra(&mut p, "base", b.clone());
        }
        if let Some(ch) = state.and_then(|s| s.pointer(&format!("/data/snaps/{name}/channel"))).and_then(Value::as_str)
        {
            set_extra(&mut p, "channel", ch);
        }
        out.push(p);
    }
    let bases: BTreeSet<String> = out.iter().filter_map(|p| extra_str(p, "base").map(String::from)).collect();
    for p in &mut out {
        if let Some(b) = extra_str(p, "base").map(String::from) {
            if bases.contains(&b) && p.name != b {
                p.dependencies = vec![b];
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

pub fn scan() -> Vec<Package> {
    let state: Option<Value> = read_text_opt(STATE).and_then(|t| serde_json::from_str(&t).ok());
    scan_root(Path::new(SNAP_ROOT), state.as_ref())
}

pub struct Snap;

impl Manager for Snap {
    fn name(&self) -> &'static str {
        "snap"
    }

    fn root_policy(&self) -> RootPolicy {
        RootPolicy::PerPackage
    }

    fn optional(&self) -> bool {
        true
    }

    fn available(&self) -> bool {
        Path::new("/var/lib/snapd").is_dir() && Path::new(SNAP_ROOT).is_dir()
    }

    fn installed(&self, _plat: &Platform) -> Result<Vec<Package>> {
        Ok(scan())
    }

    fn capture(&self, _plat: &Platform, _opts: &Options) -> Result<Section> {
        Ok(Section { tool: Some("snapd (/snap)".into()), packages: scan(), ..Default::default() })
    }

    fn plan(&self, section: &Section, _src: &Platform, _dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("snap");
        let installed = scan();
        let current: HashMap<&str, &Package> = installed.iter().map(|p| (p.name.as_str(), p)).collect();
        let mut n = 0;
        let apps: Vec<&Package> = section.packages.iter().filter(|p| p.kind() == "app").collect();
        let todo: Vec<&Package> = apps
            .into_iter()
            .filter(|p| {
                current.get(p.name.as_str()).map(|c| extra_str(c, "revision")) != Some(extra_str(p, "revision"))
            })
            .collect();
        if !todo.is_empty() && scope_allowed(Scope::System, "snaps", &mut plan) {
            plan.warnings.push(
                "the Snap Store only serves revisions that are still published in a channel; older revisions need --best-effort"
                    .into(),
            );
            for p in todo {
                let rev = extra_str(p, "revision").unwrap_or("");
                let verb = if current.contains_key(p.name.as_str()) { "refresh" } else { "install" };
                let mut argv = vec!["snap".to_string(), verb.into(), p.name.clone()];
                if opts.best_effort {
                    argv.push(format!("--channel={}", extra_str(p, "channel").unwrap_or("stable")));
                } else {
                    argv.push(format!("--revision={rev}"));
                }
                if extra_str(p, "confinement") == Some("classic") {
                    argv.push("--classic".into());
                }
                plan.add(Step::cmd(format!("snap {} (revision {rev})", p.name), argv));
                n += 1;
            }
        }
        if opts.prune {
            let locked: BTreeSet<&str> = section.packages.iter().map(|p| p.name.as_str()).collect();
            for p in installed.iter().filter(|p| p.kind() == "app" && !locked.contains(p.name.as_str())) {
                if scope_allowed(Scope::System, "snaps", &mut plan) {
                    plan.add(Step::cmd(
                        format!("remove snap {} (not in the lock)", p.name),
                        ["snap", "remove", &p.name],
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
    fn reads_snaps() {
        let root = std::env::temp_dir().join(format!("matsya-snap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let w = |p: &str, c: &str| {
            let f = root.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, c).unwrap();
        };
        w(
            "jq/6/meta/snap.yaml",
            "name: jq\nversion: '1.5'\nbase: core22\nconfinement: strict\napps:\n  jq:\n    command: bin/jq\n",
        );
        w("core22/1380/meta/snap.yaml", "name: core22\nversion: \"20240111\"\ntype: base\n");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("6", root.join("jq/current")).unwrap();
            std::os::unix::fs::symlink("1380", root.join("core22/current")).unwrap();
            let state = serde_json::json!({"data": {"snaps": {"jq": {"channel": "latest/stable"}}}});
            let pkgs = scan_root(&root, Some(&state));
            assert_eq!(pkgs.len(), 2);
            let jq = pkgs.iter().find(|p| p.name == "jq").unwrap();
            assert_eq!((jq.version.as_str(), jq.kind(), jq.reason()), ("1.5", "app", "manual"));
            assert_eq!(extra_str(jq, "revision"), Some("6"));
            assert_eq!(extra_str(jq, "channel"), Some("latest/stable"));
            assert_eq!(jq.dependencies, vec!["core22"]);
            assert_eq!(pkgs.iter().find(|p| p.name == "core22").unwrap().reason(), "dependency");
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
