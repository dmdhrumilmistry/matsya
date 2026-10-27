//! Package manager backends.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::model::{Package, Section};
use crate::plan::Plan;
use crate::platform::Platform;
use crate::util::Result;

pub mod apk;
pub mod apps;
pub mod apt;
pub mod brew;
pub mod cargo;
pub mod eco;
pub mod files;
pub mod flatpak;
pub mod gem;
pub mod golang;
pub mod npm;
pub mod pacman;
pub mod pip;
pub mod rpm;
pub mod snap;

/// Knobs shared by capture and apply.
#[derive(Debug, Clone)]
pub struct Options {
    pub roots_only: bool,
    pub prune: bool,
    pub best_effort: bool,
    pub snapshot: bool,
    pub add_repos: bool,
    pub refresh: bool,
    pub cache_dir: String,
    pub licenses: bool,
    pub embed_keys: bool,
    /// capturedAt of the environment being applied (snapshot fallback).
    pub captured_at: String,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            roots_only: false,
            prune: false,
            best_effort: false,
            snapshot: true,
            add_repos: false,
            refresh: true,
            cache_dir: "/var/cache/matsya".into(),
            licenses: true,
            embed_keys: true,
            captured_at: String::new(),
        }
    }
}

/// Who may run a manager's `apply` steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootPolicy {
    /// System package managers: changes need root.
    Required,
    /// Homebrew: refuses to run as root.
    Forbidden,
    /// Decided per package: system-wide installs need root, per-user ones
    /// must not run as root (the plan skips whichever half does not fit).
    PerPackage,
}

pub trait Manager {
    fn name(&self) -> &'static str;
    fn root_policy(&self) -> RootPolicy {
        RootPolicy::Required
    }
    /// Sources outside the system package manager are only written to the
    /// lock when they actually have something installed.
    fn optional(&self) -> bool {
        false
    }
    /// Whether a package of a per-package source is installed system-wide
    /// or for one user (decides who may apply it).
    fn scope_of(&self, pkg: &Package) -> eco::Scope {
        eco::Scope::of(pkg)
    }
    fn available(&self) -> bool;
    /// The lock section for this manager.
    fn capture(&self, plat: &Platform, opts: &Options) -> Result<Section>;
    /// A cheap listing (name/version/arch/reason) for diff and apply.
    fn installed(&self, plat: &Platform) -> Result<Vec<Package>>;
    /// Steps that change what is *available* (repos, keys, index refresh);
    /// they run before `plan` so that it sees refreshed metadata.
    fn prepare(&self, _section: &Section, _src: &Platform, _dst: &Platform, _opts: &Options) -> Result<Plan> {
        Ok(Plan::new(&format!("{} (prepare)", self.name())))
    }
    fn plan(&self, section: &Section, src: &Platform, dst: &Platform, opts: &Options) -> Result<Plan>;
    /// Identity for diffing. Foreign-architecture packages get an arch
    /// suffix so they do not collide with native ones.
    fn key_of(&self, pkg: &Package, _plat: &Platform) -> String {
        pkg.name.clone()
    }
}

pub fn all() -> Vec<Box<dyn Manager>> {
    vec![
        Box::new(apt::Apt),
        Box::new(rpm::Rpm::default()),
        Box::new(apk::Apk),
        Box::new(pacman::Pacman),
        Box::new(brew::Brew),
        Box::new(pip::Pip),
        Box::new(npm::Npm),
        Box::new(cargo::Cargo),
        Box::new(golang::Go),
        Box::new(gem::Gem),
        Box::new(snap::Snap),
        Box::new(flatpak::Flatpak),
        Box::new(files::Files),
        Box::new(apps::Apps),
    ]
}

pub const NAMES: &[&str] =
    &["apt", "rpm", "apk", "pacman", "brew", "pip", "npm", "cargo", "go", "gem", "snap", "flatpak", "files", "apps"];

pub fn get(name: &str) -> Option<Box<dyn Manager>> {
    all().into_iter().find(|m| m.name() == name)
}

pub fn detect() -> Vec<Box<dyn Manager>> {
    all().into_iter().filter(|m| m.available()).collect()
}

/// Fill `dependencies` with keys of installed packages.
///
/// `requires`: key -> alternative groups; `provides`: key -> names it
/// satisfies (its own name is implied). The first installed alternative
/// of each group wins, preferring a satisfier built for the dependent's
/// architecture (libfoo:i386 -> libc6:i386), then arch-neutral ones.
pub fn resolve_dependencies(
    pkgs: &mut [Package],
    keys: &[String],
    requires: &HashMap<String, Vec<Vec<String>>>,
    provides: &HashMap<String, Vec<String>>,
) {
    let neutral = ["all", "noarch", "any", ""];
    let mut satisfiers: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut arch_of: HashMap<&str, &str> = HashMap::new();
    for (p, k) in pkgs.iter().zip(keys) {
        arch_of.insert(k, p.arch.as_deref().unwrap_or(""));
        satisfiers.entry(p.name.as_str()).or_default().push(k);
        for prov in provides.get(k).into_iter().flatten() {
            satisfiers.entry(prov.as_str()).or_default().push(k);
        }
    }
    let mut result: Vec<Vec<String>> = Vec::with_capacity(pkgs.len());
    for (p, k) in pkgs.iter().zip(keys) {
        let mine = p.arch.as_deref().unwrap_or("");
        let mut deps: BTreeSet<String> = BTreeSet::new();
        for group in requires.get(k).into_iter().flatten() {
            for alt in group {
                if let Some(cands) = satisfiers.get(alt.as_str()) {
                    let best = cands
                        .iter()
                        .min_by_key(|c| {
                            let a = arch_of.get(*c).copied().unwrap_or("");
                            (a != mine && !neutral.contains(&a), a != mine, **c != alt.as_str(), c.to_string())
                        })
                        .expect("non-empty");
                    deps.insert(best.to_string());
                    break;
                }
            }
        }
        deps.remove(k);
        result.push(deps.into_iter().collect());
    }
    for (p, d) in pkgs.iter_mut().zip(result) {
        p.dependencies = d;
    }
}

/// Avoid ARG_MAX on systems with thousands of packages.
pub fn batches(items: &[String], size: usize) -> impl Iterator<Item = &[String]> {
    items.chunks(size.max(1))
}

pub fn by_key<'a, M: Manager + ?Sized>(m: &M, pkgs: &'a [Package], plat: &Platform) -> BTreeMap<String, &'a Package> {
    pkgs.iter().map(|p| (m.key_of(p, plat), p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiarch_prefers_same_arch() {
        let mk = |n: &str, a: &str| {
            let mut p = Package::new(n, "1");
            p.arch = Some(a.into());
            p
        };
        let mut pkgs = vec![mk("libc6", "amd64"), mk("libc6", "i386"), mk("libfoo", "i386"), mk("bar", "amd64")];
        let keys: Vec<String> = ["libc6", "libc6:i386", "libfoo:i386", "bar"].iter().map(|s| s.to_string()).collect();
        let req = HashMap::from([
            ("libfoo:i386".to_string(), vec![vec!["libc6".to_string()]]),
            ("bar".to_string(), vec![vec!["libc6".to_string()]]),
        ]);
        resolve_dependencies(&mut pkgs, &keys, &req, &HashMap::new());
        assert_eq!(pkgs[2].dependencies, vec!["libc6:i386"]);
        assert_eq!(pkgs[3].dependencies, vec!["libc6"]);
    }
}
