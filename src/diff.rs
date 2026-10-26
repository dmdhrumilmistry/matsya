//! Compare a locked environment with the live system or another lock.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::managers::Manager;
use crate::model::Package;
use crate::platform::Platform;

#[derive(Debug, Default, Serialize)]
pub struct Item {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct SectionDiff {
    pub missing: Vec<Item>,
    pub extra: Vec<Item>,
    pub changed: Vec<Item>,
    pub integrity: Vec<Item>,
    pub reason: Vec<Item>,
}

fn integrity_fields(p: &Package) -> [(&'static str, Option<&String>); 4] {
    [
        ("sha256", p.sha256.as_ref()),
        ("checksum", p.checksum.as_ref()),
        ("payloadDigest", p.payload_digest.as_ref()),
        ("sigmd5", p.sigmd5.as_ref()),
    ]
}

pub fn diff_sections(
    mgr: Option<&dyn Manager>,
    locked: &[Package],
    locked_plat: &Platform,
    current: &[Package],
    current_plat: &Platform,
) -> SectionDiff {
    let key = |p: &Package, plat: &Platform| mgr.map(|m| m.key_of(p, plat)).unwrap_or_else(|| p.name.clone());
    let a: BTreeMap<String, &Package> = locked.iter().map(|p| (key(p, locked_plat), p)).collect();
    let b: BTreeMap<String, &Package> = current.iter().map(|p| (key(p, current_plat), p)).collect();
    let mut d = SectionDiff::default();
    let item =
        |n: &str, l: Option<String>, c: Option<String>| Item { name: n.into(), locked: l, current: c, field: None };
    for (k, lp) in &a {
        let Some(cp) = b.get(k) else {
            d.missing.push(item(k, Some(lp.full_version()), None));
            continue;
        };
        if lp.full_version() != cp.full_version() {
            d.changed.push(item(k, Some(lp.full_version()), Some(cp.full_version())));
            continue;
        }
        for ((f, x), (_, y)) in integrity_fields(lp).into_iter().zip(integrity_fields(cp)) {
            if let (Some(x), Some(y)) = (x, y) {
                if x != y {
                    d.integrity.push(Item {
                        name: k.clone(),
                        locked: Some(x.clone()),
                        current: Some(y.clone()),
                        field: Some(f.into()),
                    });
                }
            }
        }
        if !lp.reason().is_empty() && !cp.reason().is_empty() && lp.reason() != cp.reason() {
            d.reason.push(item(k, Some(lp.reason().into()), Some(cp.reason().into())));
        }
    }
    for (k, cp) in &b {
        if !a.contains_key(k) {
            d.extra.push(item(k, None, Some(cp.full_version())));
        }
    }
    d
}

pub fn has_drift(result: &BTreeMap<String, SectionDiff>, ignore_extra: bool) -> bool {
    result.values().any(|s| {
        !s.missing.is_empty()
            || !s.changed.is_empty()
            || !s.integrity.is_empty()
            || (!ignore_extra && !s.extra.is_empty())
    })
}

pub fn render(result: &BTreeMap<String, SectionDiff>, limit: Option<usize>) -> String {
    let mut out = Vec::new();
    for (m, s) in result {
        let counts: Vec<String> = [
            ("missing", &s.missing),
            ("extra", &s.extra),
            ("changed", &s.changed),
            ("integrity", &s.integrity),
            ("reason", &s.reason),
        ]
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{} {k}", v.len()))
        .collect();
        out.push(format!("[{m}] {}", if counts.is_empty() { "no differences".to_string() } else { counts.join(", ") }));
        let mut rows = Vec::new();
        let v = |x: &Option<String>| x.clone().unwrap_or_default();
        rows.extend(s.missing.iter().map(|i| format!("  - {} {}  (locked, not installed)", i.name, v(&i.locked))));
        rows.extend(s.extra.iter().map(|i| format!("  + {} {}  (installed, not locked)", i.name, v(&i.current))));
        rows.extend(s.changed.iter().map(|i| format!("  ~ {} {} -> {}", i.name, v(&i.locked), v(&i.current))));
        rows.extend(
            s.integrity.iter().map(|i| {
                format!("  ! {} same version but {} differs (rebuilt or tampered package)", i.name, v(&i.field))
            }),
        );
        rows.extend(
            s.reason.iter().map(|i| format!("  * {} install reason {} -> {}", i.name, v(&i.locked), v(&i.current))),
        );
        if let Some(l) = limit {
            if rows.len() > l {
                let more = rows.len() - l;
                rows.truncate(l);
                rows.push(format!("  ... {more} more"));
            }
        }
        out.extend(rows);
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managers::apt::Apt;

    fn p(n: &str, v: &str, a: &str) -> Package {
        let mut x = Package::new(n, v);
        x.arch = Some(a.into());
        x
    }

    fn ubu(arch: &str) -> Platform {
        crate::platform::from_os_release("ID=ubuntu\nVERSION_ID=24.04\n", arch.into())
    }

    #[test]
    fn diff() {
        let mut locked =
            vec![p("curl", "8.5.0-2ubuntu10.1", "amd64"), p("libcurl4t64", "1", "amd64"), p("libc6", "2.39", "i386")];
        locked[1].sha256 = Some("c".repeat(64));
        let mut current =
            vec![p("curl", "8.5.0-2ubuntu10.2", "amd64"), p("libcurl4t64", "1", "amd64"), p("vim", "1", "amd64")];
        current[1].sha256 = Some("b".repeat(64));
        let r = diff_sections(Some(&Apt), &locked, &ubu("x86_64"), &current, &ubu("x86_64"));
        assert_eq!(r.changed[0].name, "curl");
        assert_eq!(r.missing[0].name, "libc6:i386");
        assert_eq!(r.extra[0].name, "vim");
        assert_eq!(r.integrity[0].name, "libcurl4t64");
        assert!(has_drift(&BTreeMap::from([("apt".to_string(), r)]), false));
    }

    #[test]
    fn cross_arch_matches_native() {
        let locked = vec![p("curl", "1", "amd64"), p("tzdata", "1", "all")];
        let current = vec![p("curl", "1", "arm64"), p("tzdata", "1", "all")];
        let r = diff_sections(Some(&Apt), &locked, &ubu("x86_64"), &current, &ubu("aarch64"));
        assert!(!has_drift(&BTreeMap::from([("apt".to_string(), r)]), false));
    }
}
