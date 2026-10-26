//! Reading, writing, merging, validating lock files and choosing the
//! environment that matches this machine.

use std::path::Path;

use serde_json::Value;

use crate::bail;
use crate::model::{generator, Environment, Lockfile, LOCKFILE_VERSION};
use crate::platform::Platform;
use crate::util::{canonical_json, digest, read_text, Error, Result};

pub const DEFAULT_LOCKFILE: &str = "matsya.lock.json";
/// Lock files written before the project was renamed.
pub const LEGACY_LOCKFILE: &str = "syslock.lock.json";

/// The default lock path: matsya.lock.json, or the legacy name if only that exists.
pub fn default_path() -> String {
    if let Ok(p) = std::env::var("MATSYA_FILE") {
        return p;
    }
    if !Path::new(DEFAULT_LOCKFILE).exists() && Path::new(LEGACY_LOCKFILE).exists() {
        return LEGACY_LOCKFILE.into();
    }
    DEFAULT_LOCKFILE.into()
}

pub fn load(path: &str) -> Result<Lockfile> {
    if !Path::new(path).exists() {
        bail!("lock file not found: {path}");
    }
    let text = read_text(path)?;
    let value: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            let hint = if text.contains("<<<<<<<") {
                " (it contains git merge conflict markers; re-run `matsya lock` on each machine)"
            } else {
                ""
            };
            bail!("{path} is not valid JSON: {e}{hint}");
        }
    };
    let problems = validate(&value);
    if !problems.is_empty() {
        bail!("{path} is not a valid lock file:\n  {}", problems.join("\n  "));
    }
    serde_json::from_value(value).map_err(|e| Error(format!("{path}: {e}")))
}

pub fn load_or_empty(path: &str) -> Result<Lockfile> {
    if Path::new(path).exists() {
        load(path)
    } else {
        Ok(Lockfile::default())
    }
}

pub fn to_text(lock: &Lockfile) -> String {
    canonical_json(&serde_json::to_value(lock).expect("serialisable"))
}

/// Atomic write: a crash never leaves a half-written lock behind.
pub fn save(lock: &mut Lockfile, path: &str) -> Result<()> {
    lock.generator = generator();
    let text = to_text(lock);
    let target = Path::new(path);
    let dir = target.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".matsya-{}.tmp", std::process::id()));
    std::fs::write(&tmp, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(target).map(|m| m.permissions().mode() & 0o777).unwrap_or(0o644);
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    }
    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

pub fn env_digest(env: &Environment) -> String {
    let v = serde_json::json!({
        "platform": serde_json::to_value(&env.platform).expect("serialisable"),
        "managers": serde_json::to_value(&env.managers).expect("serialisable"),
    });
    digest(&v)
}

/// Insert or update one environment. Managers not captured this time (e.g.
/// brew missing in a CI container) are kept unless `replace` is set.
pub fn put_environment(lock: &mut Lockfile, eid: &str, mut env: Environment, replace: bool) {
    if let Some(old) = lock.environments.get(eid) {
        if !replace {
            let mut merged = old.managers.clone();
            merged.extend(env.managers);
            env.managers = merged;
        }
    }
    env.digest = Some(env_digest(&env));
    lock.environments.insert(eid.to_string(), env);
}

/// Environments whose content no longer matches their digest.
pub fn check_digests(lock: &Lockfile) -> Vec<String> {
    lock.environments
        .iter()
        .filter(|(_, e)| e.digest.as_deref().is_some_and(|d| d != env_digest(e)))
        .map(|(k, _)| k.clone())
        .collect()
}

/// Structural validation on the raw JSON, with readable messages.
pub fn validate(data: &Value) -> Vec<String> {
    let mut p = Vec::new();
    let Some(obj) = data.as_object() else {
        return vec!["top level must be an object".into()];
    };
    match obj.get("lockfileVersion").and_then(Value::as_i64) {
        None => p.push("lockfileVersion missing or not an integer".into()),
        Some(v) if v > LOCKFILE_VERSION => p.push(format!(
            "lockfileVersion {v} is newer than this matsya supports ({LOCKFILE_VERSION}); upgrade matsya"
        )),
        _ => {}
    }
    let Some(envs) = obj.get("environments").and_then(Value::as_object) else {
        p.push("environments must be an object".into());
        return p;
    };
    for (eid, env) in envs {
        let Some(env) = env.as_object() else {
            p.push(format!("{eid}: must be an object"));
            continue;
        };
        let plat = env.get("platform");
        let ok = plat.and_then(|x| x.get("arch")).and_then(Value::as_str).is_some_and(|s| !s.is_empty())
            && plat.and_then(|x| x.get("distro")).and_then(Value::as_str).is_some_and(|s| !s.is_empty());
        if !ok {
            p.push(format!("{eid}: platform.distro and platform.arch are required"));
        }
        let Some(mgrs) = env.get("managers").and_then(Value::as_object) else {
            p.push(format!("{eid}: managers must be an object"));
            continue;
        };
        for (mname, sec) in mgrs {
            let Some(pkgs) = sec.get("packages").and_then(Value::as_array) else {
                p.push(format!("{eid}/{mname}: packages must be a list"));
                continue;
            };
            let mut seen = std::collections::HashSet::new();
            for (i, pkg) in pkgs.iter().enumerate() {
                let name = pkg.get("name").and_then(Value::as_str).unwrap_or("");
                if name.is_empty() || pkg.get("version").and_then(Value::as_str).is_none() {
                    p.push(format!("{eid}/{mname}: package #{i} needs name and version"));
                    continue;
                }
                let s = |k: &str| pkg.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                let installonly = pkg.get("installonly").and_then(Value::as_bool).unwrap_or(false);
                let key =
                    (name.to_string(), s("arch"), s("kind"), if installonly { s("version") } else { String::new() });
                if !seen.insert(key) {
                    p.push(format!("{eid}/{mname}: duplicate package {name} ({})", s("arch")));
                }
            }
        }
    }
    p
}

/// Pick the environment to apply on this machine.
///
/// 1. `--env` wins.
/// 2. Exact id match (same distro, release, arch).
/// 3. Same distro + release on another arch (packages are re-targeted).
/// 4. Brew-only environments match on distro alone (Homebrew versions do
///    not depend on the macOS release).
/// 5. Same distro family, other release: only with --allow-cross-release.
pub fn select_environment(lock: &Lockfile, plat: &Platform, wanted: Option<&str>, allow_cross: bool) -> Result<String> {
    let envs = &lock.environments;
    if envs.is_empty() {
        bail!("the lock file has no environments; run `matsya lock` first");
    }
    let names = || envs.keys().cloned().collect::<Vec<_>>().join(", ");
    if let Some(w) = wanted {
        if !envs.contains_key(w) {
            bail!("environment {w:?} not in lock; available: {}", names());
        }
        return Ok(w.to_string());
    }
    let eid = plat.env_id();
    if envs.contains_key(&eid) {
        return Ok(eid);
    }
    let same_rel: Vec<&String> = envs
        .iter()
        .filter(|(_, e)| e.platform.distro() == plat.distro() && e.platform.release() == plat.release())
        .map(|(k, _)| k)
        .collect();
    if same_rel.len() == 1 {
        return Ok(same_rel[0].clone());
    }
    let mut brew_only: Vec<&String> = envs
        .iter()
        .filter(|(_, e)| {
            e.platform.distro() == plat.distro() && e.managers.len() == 1 && e.managers.contains_key("brew")
        })
        .map(|(k, _)| k)
        .collect();
    brew_only.sort_by_key(|k| (envs[*k].platform.arch() != plat.arch(), (*k).clone()));
    if let Some(k) = brew_only.first() {
        return Ok((*k).clone());
    }
    let fam: std::collections::HashSet<String> = plat.family().into_iter().collect();
    let mut near: Vec<&String> =
        envs.iter().filter(|(_, e)| e.platform.family().iter().any(|f| fam.contains(f))).map(|(k, _)| k).collect();
    if !near.is_empty() && allow_cross {
        near.sort_by_key(|k| {
            let p = &envs[*k].platform;
            (p.distro() != plat.distro(), p.arch() != plat.arch(), (*k).clone())
        });
        return Ok(near[0].clone());
    }
    let mut msg = format!("no environment in the lock matches this machine ({eid}); available: {}.", names());
    if !near.is_empty() {
        msg.push_str(" Pass --env to choose one, or --allow-cross-release to pick the closest match.");
    }
    Err(Error(msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Package, Section};
    use std::collections::BTreeMap;

    pub fn ubuntu() -> Platform {
        crate::platform::from_os_release(
            "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n",
            "x86_64".into(),
        )
    }

    fn sample() -> Lockfile {
        let mut lock = Lockfile::default();
        let mut sec = Section::default();
        let mut p = Package::new("curl", "8.5.0-2ubuntu10.1");
        p.arch = Some("amd64".into());
        p.reason = Some("manual".into());
        sec.packages.push(p);
        let env = Environment {
            platform: ubuntu(),
            managers: BTreeMap::from([("apt".to_string(), sec)]),
            ..Default::default()
        };
        put_environment(&mut lock, "ubuntu-24.04-x86_64", env, false);
        lock
    }

    #[test]
    fn digest_detects_edits() {
        let mut lock = sample();
        assert!(check_digests(&lock).is_empty());
        lock.environments.get_mut("ubuntu-24.04-x86_64").unwrap().managers.get_mut("apt").unwrap().packages[0]
            .version = "9".into();
        assert_eq!(check_digests(&lock), vec!["ubuntu-24.04-x86_64"]);
    }

    #[test]
    fn selection_rules() {
        let lock = sample();
        let u = ubuntu();
        assert_eq!(select_environment(&lock, &u, None, false).unwrap(), "ubuntu-24.04-x86_64");
        let mut arm = u.clone();
        arm.arch = Some("aarch64".into());
        assert_eq!(select_environment(&lock, &arm, None, false).unwrap(), "ubuntu-24.04-x86_64");
        let mut newer = u.clone();
        newer.release = Some("26.04".into());
        assert!(select_environment(&lock, &newer, None, false).unwrap_err().0.contains("allow-cross-release"));
        assert!(select_environment(&lock, &newer, None, true).is_ok());
        let deb = crate::platform::from_os_release("ID=debian\nVERSION_ID=12\n", "x86_64".into());
        assert!(select_environment(&lock, &deb, None, true).is_ok());
        let fed = crate::platform::from_os_release("ID=fedora\nVERSION_ID=40\n", "x86_64".into());
        assert!(select_environment(&lock, &fed, None, true).is_err());
    }

    #[test]
    fn validation() {
        assert!(validate(&serde_json::json!({"lockfileVersion": 99, "environments": {}}))[0].contains("newer"));
        let dup = serde_json::json!({"lockfileVersion": 1, "environments": {"e": {"platform": {"distro": "d", "arch": "a"},
            "managers": {"apt": {"packages": [{"name": "x", "version": "1"}, {"name": "x", "version": "2"}]}}}}});
        assert!(validate(&dup)[0].contains("duplicate"));
        let kernels = serde_json::json!({"lockfileVersion": 1, "environments": {"e": {"platform": {"distro": "d", "arch": "a"},
            "managers": {"rpm": {"packages": [{"name": "k", "version": "1", "installonly": true}, {"name": "k", "version": "2", "installonly": true}]}}}}});
        assert!(validate(&kernels).is_empty());
    }

    /// Locks written by the Python implementation must load with identical
    /// digests, so upgrading never invalidates committed lock files.
    #[test]
    fn python_written_examples_roundtrip() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/examples");
        for f in ["multi-machine.lock.json", "debian-12.lock.json"] {
            let path = format!("{dir}/{f}");
            let lock = load(&path).unwrap();
            assert!(check_digests(&lock).is_empty(), "{f}");
            let original: Value = serde_json::from_str(&read_text(&path).unwrap()).unwrap();
            let again = serde_json::to_value(&lock).unwrap();
            assert_eq!(original["environments"], again["environments"], "{f}");
        }
    }
}
