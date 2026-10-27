//! Ruby gems installed with `gem install`, read from the gemspecs RubyGems
//! writes to `<gem dir>/specifications/*.gemspec`. Ruby's own default gems
//! (`specifications/default`) and distro-owned gem directories are skipped.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use super::eco::{by_kind, entries_with_prefix, scope_allowed, set_extra, subdirs, tilde, user_home, Scope};
use super::{Manager, Options, RootPolicy};
use crate::model::{Package, Section};
use crate::plan::{Plan, Step};
use crate::platform::Platform;
use crate::util::{has, read_text_opt, Result};

/// Gem directories `gem install` writes to (not the distro's own).
pub fn gem_dirs() -> Vec<(PathBuf, Scope)> {
    let mut out = Vec::new();
    let versions = |base: PathBuf, scope: Scope, out: &mut Vec<(PathBuf, Scope)>| {
        for v in subdirs(&base) {
            if v.join("specifications").is_dir() {
                out.push((v, scope));
            }
        }
    };
    // Debian/Ubuntu `sudo gem install`, /usr/local rubies, Fedora's /usr/local share.
    versions(PathBuf::from("/var/lib/gems"), Scope::System, &mut out);
    versions(PathBuf::from("/usr/local/lib/ruby/gems"), Scope::System, &mut out);
    versions(PathBuf::from("/opt/homebrew/lib/ruby/gems"), Scope::System, &mut out);
    if Path::new("/usr/local/share/gems/specifications").is_dir() {
        out.push((PathBuf::from("/usr/local/share/gems"), Scope::System));
    }
    if let Some(p) = crate::platform::termux_prefix() {
        versions(p.join("lib/ruby/gems"), Scope::System, &mut out);
    }
    if let Some(home) = user_home() {
        versions(home.join(".local/share/gem/ruby"), Scope::User, &mut out);
        versions(home.join(".gem/ruby"), Scope::User, &mut out);
    }
    out
}

/// The first string literal after `field =` in a gemspec line.
fn quoted(line: &str) -> Option<String> {
    let start = line.find('"')? + 1;
    let end = line[start..].find('"')? + start;
    Some(line[start..end].to_string())
}

/// Name, version, licenses and runtime dependencies from a gemspec.
pub fn parse_gemspec(text: &str) -> Option<(String, String, Vec<String>, Vec<String>)> {
    let (mut name, mut version, mut licenses, mut deps) = (None, None, Vec::new(), Vec::new());
    for line in text.lines().map(str::trim) {
        if line.starts_with("s.name =") {
            name = quoted(line);
        } else if line.starts_with("s.version =") {
            version = quoted(line);
        } else if line.starts_with("s.licenses =") || line.starts_with("s.license =") {
            let mut rest = line;
            while let Some(s) = rest.find('"') {
                let after = &rest[s + 1..];
                let Some(e) = after.find('"') else { break };
                licenses.push(after[..e].to_string());
                rest = &after[e + 1..];
            }
        } else if line.starts_with("s.add_runtime_dependency") || line.starts_with("s.add_dependency") {
            // s.add_runtime_dependency(%q<rack>.freeze, [">= 2"])
            if let Some(s) = line.find("%q<") {
                if let Some(e) = line[s + 3..].find('>') {
                    deps.push(line[s + 3..s + 3 + e].to_string());
                }
            }
        }
    }
    Some((name?, version?, licenses, deps))
}

pub fn scan() -> Vec<Package> {
    let mut out = Vec::new();
    for (dir, scope) in gem_dirs() {
        let ruby = dir.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let kind = format!("ruby{ruby}/{}", scope.label());
        let location = tilde(&dir);
        for spec in entries_with_prefix(&dir.join("specifications"), "") {
            if !spec.to_string_lossy().ends_with(".gemspec") {
                continue;
            }
            let Some((name, version, licenses, deps)) = read_text_opt(&spec).and_then(|t| parse_gemspec(&t)) else {
                continue;
            };
            let mut p = Package::new(name, version);
            p.kind = Some(kind.clone());
            p.reason = Some("manual".into());
            p.licenses = licenses;
            p.dependencies =
                deps.into_iter().map(|d| format!("{kind}:{d}")).collect::<BTreeSet<_>>().into_iter().collect();
            set_extra(&mut p, "location", location.clone());
            out.push(p);
        }
    }
    // A gem required by another gem was most likely pulled in as a dependency.
    let required: BTreeSet<String> = out.iter().flat_map(|p| p.dependencies.clone()).collect();
    for p in &mut out {
        if required.contains(&key(p)) {
            p.reason = Some("dependency".into());
        }
    }
    out.sort_by_key(key);
    out
}

fn key(p: &Package) -> String {
    format!("{}:{}", p.kind(), p.name)
}

pub struct Gem;

impl Manager for Gem {
    fn name(&self) -> &'static str {
        "gem"
    }

    fn root_policy(&self) -> RootPolicy {
        RootPolicy::PerPackage
    }

    fn optional(&self) -> bool {
        true
    }

    fn available(&self) -> bool {
        !gem_dirs().is_empty() || has("gem")
    }

    fn key_of(&self, pkg: &Package, _plat: &Platform) -> String {
        key(pkg)
    }

    fn installed(&self, _plat: &Platform) -> Result<Vec<Package>> {
        Ok(scan())
    }

    fn capture(&self, _plat: &Platform, opts: &Options) -> Result<Section> {
        let mut pkgs = scan();
        if !opts.licenses {
            pkgs.iter_mut().for_each(|p| p.licenses.clear());
        }
        Ok(Section { tool: Some("rubygems (gemspecs)".into()), packages: pkgs, ..Default::default() })
    }

    fn plan(&self, section: &Section, _src: &Platform, _dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("gem");
        let installed = scan();
        let current: HashMap<String, Vec<&str>> = installed.iter().fold(HashMap::new(), |mut m, p| {
            m.entry(key(p)).or_default().push(p.version.as_str());
            m
        });
        let mut n = 0;
        for (kind, pkgs) in by_kind(section.packages.iter().filter(|p| !opts.roots_only || p.is_manual())) {
            let scope = Scope::of(pkgs[0]);
            let todo: Vec<&Package> = pkgs
                .into_iter()
                .filter(|p| !current.get(&key(p)).is_some_and(|v| v.contains(&p.version.as_str())))
                .collect();
            if todo.is_empty() || !scope_allowed(scope, &format!("Ruby gems ({kind})"), &mut plan) {
                continue;
            }
            if !has("gem") {
                plan.unresolved.push(format!("{} gem(s) for {kind} (gem is not installed)", todo.len()));
                continue;
            }
            for p in todo {
                let mut argv = vec![
                    "gem".to_string(),
                    "install".into(),
                    p.name.clone(),
                    "--version".into(),
                    p.version.clone(),
                    "--no-document".into(),
                ];
                if scope == Scope::User {
                    argv.push("--user-install".into());
                }
                plan.add(Step::cmd(format!("gem {} {}", p.name, p.version), argv));
                n += 1;
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
    fn gemspec_fields() {
        let text = r#"# -*- encoding: utf-8 -*-
Gem::Specification.new do |s|
  s.name = "rails".freeze
  s.version = "7.1.3".freeze
  s.licenses = ["MIT".freeze, "Ruby".freeze]
  s.add_runtime_dependency(%q<activesupport>.freeze, ["= 7.1.3".freeze])
  s.add_dependency(%q<rack>.freeze, [">= 2.2.4".freeze])
end
"#;
        let (n, v, l, d) = parse_gemspec(text).unwrap();
        assert_eq!((n.as_str(), v.as_str()), ("rails", "7.1.3"));
        assert_eq!(l, vec!["MIT", "Ruby"]);
        assert_eq!(d, vec!["activesupport", "rack"]);
        assert!(parse_gemspec("nothing here").is_none());
    }
}
