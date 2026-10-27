//! Flatpak apps and runtimes, read from the system (`/var/lib/flatpak`) and
//! per-user (`~/.local/share/flatpak`) installations:
//! `<install>/{app,runtime}/<id>/<arch>/<branch>/active` points at the
//! deployed commit, whose `deploy` file starts with the origin remote.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use super::eco::{extra_str, scope_allowed, set_extra, subdirs, user_home, Scope};
use super::{Manager, Options, RootPolicy};
use crate::model::{Package, Section};
use crate::plan::{Plan, Step};
use crate::platform::Platform;
use crate::util::{has, read_text_opt, Result};

pub fn installations() -> Vec<(PathBuf, Scope)> {
    let mut out = vec![(PathBuf::from("/var/lib/flatpak"), Scope::System)];
    if let Some(h) = user_home() {
        out.push((h.join(".local/share/flatpak"), Scope::User));
    }
    out.into_iter().filter(|(p, _)| p.join("repo").is_dir() || p.join("app").is_dir()).collect()
}

/// Latest `<release version="...">` from AppStream metainfo.
pub fn metainfo_version(xml: &str) -> Option<String> {
    let at = xml.find("<release ")?;
    let tag = &xml[at..at + xml[at..].find('>')?];
    let v = tag.find("version=")? + "version=".len();
    let q = tag[v..].chars().next()?;
    let rest = &tag[v + 1..];
    Some(rest[..rest.find(q)?].to_string())
}

/// The origin remote: the first NUL-terminated string of the `deploy` GVariant.
fn origin(deploy: &Path) -> Option<String> {
    let b = std::fs::read(deploy).ok()?;
    let end = b.iter().position(|c| *c == 0)?;
    let s = String::from_utf8_lossy(&b[..end]).into_owned();
    (!s.is_empty() && s.chars().all(|c| c.is_ascii_graphic())).then_some(s)
}

pub fn scan_installation(root: &Path, scope: Scope) -> Vec<Package> {
    let mut out = Vec::new();
    for (kind, reason) in [("app", "manual"), ("runtime", "dependency")] {
        for id_dir in subdirs(&root.join(kind)) {
            let id = id_dir.file_name().unwrap_or_default().to_string_lossy().into_owned();
            for arch_dir in subdirs(&id_dir) {
                let arch = arch_dir.file_name().unwrap_or_default().to_string_lossy().into_owned();
                for branch_dir in subdirs(&arch_dir) {
                    let branch = branch_dir.file_name().unwrap_or_default().to_string_lossy().into_owned();
                    let active = branch_dir.join("active");
                    let Ok(commit) = std::fs::read_link(&active) else { continue };
                    let commit = commit.file_name().unwrap_or_default().to_string_lossy().into_owned();
                    let version = ["metainfo", "appdata"]
                        .iter()
                        .find_map(|d| read_text_opt(active.join(format!("files/share/{d}/{id}.{d}.xml"))))
                        .and_then(|x| metainfo_version(&x))
                        .unwrap_or_else(|| branch.clone());
                    let mut p = Package::new(id.clone(), version);
                    p.arch = Some(arch.clone());
                    p.kind = Some(format!("{kind}/{}", scope.label()));
                    p.reason = Some(reason.into());
                    p.checksum = Some(commit);
                    set_extra(&mut p, "ref", format!("{kind}/{id}/{arch}/{branch}"));
                    if let Some(o) = origin(&active.join("deploy")) {
                        set_extra(&mut p, "origin", o);
                    }
                    // [Application] runtime=org.freedesktop.Platform/x86_64/23.08
                    if let Some(meta) = read_text_opt(active.join("metadata")) {
                        if let Some(rt) = meta.lines().find_map(|l| l.strip_prefix("runtime=")) {
                            set_extra(&mut p, "runtime", rt.trim());
                        }
                    }
                    out.push(p);
                }
            }
        }
    }
    // Apps depend on the runtime they declare.
    let refs: HashMap<String, String> = out
        .iter()
        .filter(|p| p.kind().starts_with("runtime"))
        .map(|p| (extra_str(p, "ref").unwrap_or("").trim_start_matches("runtime/").to_string(), key(p)))
        .collect();
    for p in &mut out {
        if let Some(k) = extra_str(p, "runtime").and_then(|rt| refs.get(rt)).cloned() {
            p.dependencies = vec![k];
        }
    }
    out
}

pub fn scan() -> Vec<Package> {
    let mut out: Vec<Package> = installations().into_iter().flat_map(|(p, s)| scan_installation(&p, s)).collect();
    out.sort_by_key(key);
    out
}

fn key(p: &Package) -> String {
    format!("{}:{}", p.kind(), extra_str(p, "ref").unwrap_or(&p.name))
}

pub struct Flatpak;

impl Manager for Flatpak {
    fn name(&self) -> &'static str {
        "flatpak"
    }

    fn root_policy(&self) -> RootPolicy {
        RootPolicy::PerPackage
    }

    fn optional(&self) -> bool {
        true
    }

    fn available(&self) -> bool {
        !installations().is_empty() || has("flatpak")
    }

    fn key_of(&self, pkg: &Package, _plat: &Platform) -> String {
        key(pkg)
    }

    fn installed(&self, _plat: &Platform) -> Result<Vec<Package>> {
        Ok(scan())
    }

    fn capture(&self, _plat: &Platform, _opts: &Options) -> Result<Section> {
        Ok(Section { tool: Some("flatpak (installations)".into()), packages: scan(), ..Default::default() })
    }

    fn plan(&self, section: &Section, _src: &Platform, _dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("flatpak");
        let installed = scan();
        let current: HashMap<String, &Package> = installed.iter().map(|p| (key(p), p)).collect();
        let mut n = 0;
        for p in section.packages.iter().filter(|p| p.kind().starts_with("app/")) {
            let have = current.get(&key(p));
            if have.and_then(|h| h.checksum.as_ref()) == p.checksum.as_ref() {
                continue;
            }
            let scope = Scope::of(p);
            if !scope_allowed(scope, "flatpaks", &mut plan) {
                continue;
            }
            if !has("flatpak") {
                plan.unresolved.push(format!("{} (flatpak is not installed)", p.name));
                continue;
            }
            let r = extra_str(p, "ref").unwrap_or(&p.name).to_string();
            let flag = if scope == Scope::User { "--user" } else { "--system" };
            if have.is_none() {
                let mut argv =
                    vec!["flatpak".to_string(), "install".into(), "-y".into(), "--noninteractive".into(), flag.into()];
                if let Some(o) = extra_str(p, "origin") {
                    argv.push(o.into());
                }
                argv.push(r.clone());
                plan.add(Step::cmd(format!("install {} ({})", p.name, p.version), argv));
            }
            // Pin the exact deployed commit (flatpak can downgrade to it).
            if let Some(c) = &p.checksum {
                plan.add(Step::cmd(
                    format!("pin {} to commit {}", p.name, &c[..c.len().min(12)]),
                    [
                        "flatpak".to_string(),
                        "update".into(),
                        "-y".into(),
                        "--noninteractive".into(),
                        flag.into(),
                        format!("--commit={c}"),
                        r,
                    ],
                ));
            }
            n += 1;
        }
        if opts.prune {
            let locked: BTreeSet<String> = section.packages.iter().map(key).collect();
            for p in installed.iter().filter(|p| p.kind().starts_with("app/") && !locked.contains(&key(p))) {
                let scope = Scope::of(p);
                if scope_allowed(scope, "flatpaks", &mut plan) {
                    let flag = if scope == Scope::User { "--user" } else { "--system" };
                    plan.add(Step::cmd(
                        format!("remove {} (not in the lock)", p.name),
                        [
                            "flatpak",
                            "uninstall",
                            "-y",
                            "--noninteractive",
                            flag,
                            extra_str(p, "ref").unwrap_or(&p.name),
                        ],
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
    fn reads_flatpaks() {
        assert_eq!(
            metainfo_version("<component><releases><release version=\"1.2.3\" date=\"2024-01-01\"/><release version='1.2.2'/></releases>").as_deref(),
            Some("1.2.3")
        );
        let root = std::env::temp_dir().join(format!("matsya-flatpak-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let app = root.join("app/org.gimp.GIMP/x86_64/stable/abc123def");
        let rt = root.join("runtime/org.gnome.Platform/x86_64/46/fff000");
        std::fs::create_dir_all(app.join("files/share/metainfo")).unwrap();
        std::fs::create_dir_all(&rt).unwrap();
        std::fs::write(app.join("files/share/metainfo/org.gimp.GIMP.metainfo.xml"), "<release version=\"2.10.38\"/>")
            .unwrap();
        std::fs::write(
            app.join("metadata"),
            "[Application]\nname=org.gimp.GIMP\nruntime=org.gnome.Platform/x86_64/46\n",
        )
        .unwrap();
        std::fs::write(app.join("deploy"), b"flathub\0\0\0binary-gvariant").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("abc123def", root.join("app/org.gimp.GIMP/x86_64/stable/active")).unwrap();
            std::os::unix::fs::symlink("fff000", root.join("runtime/org.gnome.Platform/x86_64/46/active")).unwrap();
            let pkgs = scan_installation(&root, Scope::System);
            let gimp = pkgs.iter().find(|p| p.name == "org.gimp.GIMP").unwrap();
            assert_eq!((gimp.version.as_str(), gimp.checksum.as_deref()), ("2.10.38", Some("abc123def")));
            assert_eq!(extra_str(gimp, "origin"), Some("flathub"));
            assert_eq!(extra_str(gimp, "ref"), Some("app/org.gimp.GIMP/x86_64/stable"));
            assert_eq!(gimp.dependencies, vec!["runtime/system:runtime/org.gnome.Platform/x86_64/46"]);
            let platform = pkgs.iter().find(|p| p.name == "org.gnome.Platform").unwrap();
            assert_eq!((platform.version.as_str(), platform.reason()), ("46", "dependency"));
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
