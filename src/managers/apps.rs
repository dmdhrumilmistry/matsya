//! macOS applications in /Applications and ~/Applications that were not
//! installed by Homebrew casks: vendor downloads and Mac App Store apps.
//! Read from each bundle's Info.plist (XML or binary). They cannot be
//! reinstalled automatically; `check` reports missing or changed ones.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::eco::{set_extra, subdirs, user_home};
use super::{Manager, Options, RootPolicy};
use crate::model::{Package, Section};
use crate::plan::Plan;
use crate::platform::Platform;
use crate::util::{read_text_opt, Result};

/// String values of the top-level dictionary of a binary plist (bplist00).
pub fn bplist_strings(b: &[u8]) -> Option<HashMap<String, String>> {
    if !b.starts_with(b"bplist00") || b.len() < 40 {
        return None;
    }
    let t = &b[b.len() - 32..];
    let (off_size, ref_size) = (t[6] as usize, t[7] as usize);
    let be = |s: &[u8]| s.iter().fold(0u64, |a, x| (a << 8) | *x as u64);
    let num = be(&t[8..16]) as usize;
    let top = be(&t[16..24]) as usize;
    let table = be(&t[24..32]) as usize;
    if off_size == 0 || ref_size == 0 || num > 1_000_000 {
        return None;
    }
    let offset =
        |i: usize| -> Option<usize> { Some(be(b.get(table + i * off_size..table + (i + 1) * off_size)?) as usize) };
    // Length of an object: inline nibble, or a following int object.
    let length = |o: usize| -> Option<(usize, usize)> {
        let info = (b.get(o)? & 0x0f) as usize;
        if info != 0x0f {
            return Some((info, o + 1));
        }
        let m = *b.get(o + 1)?;
        let n = 1usize << (m & 0x0f);
        Some((be(b.get(o + 2..o + 2 + n)?) as usize, o + 2 + n))
    };
    let string = |i: usize| -> Option<String> {
        let o = offset(i)?;
        let (len, start) = length(o)?;
        match b.get(o)? >> 4 {
            0x5 => Some(String::from_utf8_lossy(b.get(start..start + len)?).into_owned()),
            0x6 => {
                let u: Vec<u16> =
                    b.get(start..start + 2 * len)?.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                Some(String::from_utf16_lossy(&u))
            }
            _ => None,
        }
    };
    let o = offset(top)?;
    if b.get(o)? >> 4 != 0xd {
        return None;
    }
    let (count, start) = length(o)?;
    let r = |k: usize| be(&b[start + k * ref_size..start + (k + 1) * ref_size]) as usize;
    if start + 2 * count * ref_size > b.len() {
        return None;
    }
    let mut out = HashMap::new();
    for k in 0..count {
        if let (Some(key), Some(val)) = (string(r(k)), string(r(count + k))) {
            out.insert(key, val);
        }
    }
    Some(out)
}

/// String values of the top-level dictionary of an XML plist.
pub fn xml_plist_strings(x: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut rest = x;
    while let Some(k) = rest.find("<key>") {
        let after = &rest[k + 5..];
        let Some(ke) = after.find("</key>") else { break };
        let key = after[..ke].to_string();
        let tail = after[ke + 6..].trim_start();
        if let Some(v) = tail.strip_prefix("<string>") {
            if let Some(ve) = v.find("</string>") {
                out.entry(key).or_insert_with(|| v[..ve].to_string());
            }
        }
        rest = &after[ke..];
    }
    out
}

pub fn info_plist(app: &Path) -> Option<HashMap<String, String>> {
    let bytes = std::fs::read(app.join("Contents/Info.plist")).ok()?;
    bplist_strings(&bytes).or_else(|| Some(xml_plist_strings(&String::from_utf8_lossy(&bytes))))
}

/// .app bundle names installed by Homebrew casks (left to the brew section).
pub fn cask_apps() -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(layout) = super::brew::Layout::detect() else { return out };
    fn collect(v: &Value, out: &mut HashSet<String>) {
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    if k == "app" {
                        for a in x.as_array().into_iter().flatten() {
                            if let Some(s) = a.as_str() {
                                out.insert(s.rsplit('/').next().unwrap_or(s).to_string());
                            }
                        }
                    } else {
                        collect(x, out);
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|x| collect(x, out)),
            _ => {}
        }
    }
    for cask in subdirs(&layout.prefix.join("Caskroom")) {
        if let Some(r) = read_text_opt(cask.join(".metadata/INSTALL_RECEIPT.json"))
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        {
            collect(&r, &mut out);
        }
    }
    out
}

pub fn app_dirs() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("/Applications")];
    if let Some(h) = user_home() {
        v.push(h.join("Applications"));
    }
    v.into_iter().filter(|d| d.is_dir()).collect()
}

pub fn scan_in(dirs: &[PathBuf], casks: &HashSet<String>) -> Vec<Package> {
    let mut bundles = Vec::new();
    for d in dirs {
        for e in subdirs(d) {
            if e.extension().is_some_and(|x| x == "app") {
                bundles.push(e);
            } else {
                // One level of vendor folders (e.g. /Applications/Microsoft Office).
                bundles.extend(subdirs(&e).into_iter().filter(|x| x.extension().is_some_and(|x| x == "app")));
            }
        }
    }
    let mut out = Vec::new();
    for app in bundles {
        let file = app.file_name().unwrap_or_default().to_string_lossy().into_owned();
        if casks.contains(&file) {
            continue;
        }
        let Some(info) = info_plist(&app) else { continue };
        let id = info.get("CFBundleIdentifier").cloned().unwrap_or_default();
        if id.starts_with("com.apple.") {
            continue; // part of macOS
        }
        let version =
            info.get("CFBundleShortVersionString").or_else(|| info.get("CFBundleVersion")).cloned().unwrap_or_default();
        let mut p = Package::new(file.trim_end_matches(".app"), version);
        let store = app.join("Contents/_MASReceipt/receipt").exists();
        p.kind = Some(if store { "app-store" } else { "app" }.into());
        p.reason = Some("manual".into());
        set_extra(&mut p, "bundle_id", id);
        set_extra(&mut p, "path", app.display().to_string());
        if let Some(b) = info.get("CFBundleVersion") {
            set_extra(&mut p, "build", b.clone());
        }
        out.push(p);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

pub fn scan() -> Vec<Package> {
    if !cfg!(target_os = "macos") {
        return vec![];
    }
    scan_in(&app_dirs(), &cask_apps())
}

pub struct Apps;

impl Manager for Apps {
    fn name(&self) -> &'static str {
        "apps"
    }

    fn root_policy(&self) -> RootPolicy {
        RootPolicy::PerPackage
    }

    fn optional(&self) -> bool {
        true
    }

    fn available(&self) -> bool {
        cfg!(target_os = "macos") && !app_dirs().is_empty()
    }

    fn installed(&self, _plat: &Platform) -> Result<Vec<Package>> {
        Ok(scan())
    }

    fn capture(&self, _plat: &Platform, _opts: &Options) -> Result<Section> {
        Ok(Section { tool: Some("macOS applications".into()), packages: scan(), ..Default::default() })
    }

    fn plan(&self, section: &Section, _src: &Platform, _dst: &Platform, opts: &Options) -> Result<Plan> {
        let mut plan = Plan::new("apps");
        let current: HashMap<String, Package> = scan().into_iter().map(|p| (p.name.clone(), p)).collect();
        let mut problems = BTreeSet::new();
        for p in &section.packages {
            let src = if p.kind() == "app-store" { "the App Store" } else { "its vendor" };
            match current.get(&p.name) {
                None => problems.insert(format!("{} {} is missing; install it from {src}", p.name, p.version)),
                Some(c) if c.version != p.version => {
                    problems.insert(format!("{} is {} here, locked {}", p.name, c.version, p.version))
                }
                _ => false,
            };
        }
        if opts.best_effort {
            plan.warnings.extend(problems);
        } else {
            plan.unresolved.extend(problems);
        }
        plan.summary = vec![("checked".into(), section.packages.len()), ("unresolved".into(), plan.unresolved.len())];
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal binary plist: {"CFBundleIdentifier": "org.x", "CFBundleShortVersionString": "1.2"}
    fn bplist() -> Vec<u8> {
        let mut b = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        offsets.push(b.len());
        b.extend_from_slice(&[0xd2, 1, 2, 3, 4]); // dict, 2 entries: keys 1,2 values 3,4
        for s in ["CFBundleIdentifier", "CFBundleShortVersionString", "org.x", "1.2"] {
            offsets.push(b.len());
            if s.len() < 15 {
                b.push(0x50 | s.len() as u8);
            } else {
                b.extend_from_slice(&[0x5f, 0x10, s.len() as u8]);
            }
            b.extend_from_slice(s.as_bytes());
        }
        let table = b.len();
        for o in &offsets {
            b.push(*o as u8);
        }
        let mut trailer = vec![0u8; 6];
        trailer.push(1); // offset int size
        trailer.push(1); // object ref size
        trailer.extend_from_slice(&(offsets.len() as u64).to_be_bytes());
        trailer.extend_from_slice(&0u64.to_be_bytes());
        trailer.extend_from_slice(&(table as u64).to_be_bytes());
        b.extend(trailer);
        b
    }

    #[test]
    fn plists() {
        let m = bplist_strings(&bplist()).unwrap();
        assert_eq!(m["CFBundleIdentifier"], "org.x");
        assert_eq!(m["CFBundleShortVersionString"], "1.2");
        let x = xml_plist_strings("<dict><key>CFBundleIdentifier</key><string>org.y</string><key>LSMinimumSystemVersion</key>\n  <string>11.0</string><key>Flag</key><true/></dict>");
        assert_eq!(x["CFBundleIdentifier"], "org.y");
        assert_eq!(x["LSMinimumSystemVersion"], "11.0");
        assert!(!x.contains_key("Flag"));
    }

    #[test]
    fn scans_apps_and_skips_casks_and_apple() {
        let root = std::env::temp_dir().join(format!("matsya-apps-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mk = |name: &str, id: &str, ver: &str, store: bool| {
            let c = root.join(name).join("Contents");
            std::fs::create_dir_all(&c).unwrap();
            std::fs::write(c.join("Info.plist"), format!("<key>CFBundleIdentifier</key><string>{id}</string><key>CFBundleShortVersionString</key><string>{ver}</string>")).unwrap();
            if store {
                std::fs::create_dir_all(c.join("_MASReceipt")).unwrap();
                std::fs::write(c.join("_MASReceipt/receipt"), b"x").unwrap();
            }
        };
        mk("Slack.app", "com.tinyspeck.slackmacgap", "4.41.97", false);
        mk("Xcode.app", "com.apple.dt.Xcode", "16.0", true);
        mk("Things3.app", "com.culturedcode.ThingsMac", "3.21", true);
        mk("Firefox.app", "org.mozilla.firefox", "131.0", false);
        mk("Vendor/Tool.app", "com.vendor.tool", "1.0", false);
        let casks: HashSet<String> = ["Firefox.app".to_string()].into_iter().collect();
        let pkgs = scan_in(std::slice::from_ref(&root), &casks);
        let names: Vec<(&str, &str)> = pkgs.iter().map(|p| (p.name.as_str(), p.kind())).collect();
        assert_eq!(names, vec![("Slack", "app"), ("Things3", "app-store"), ("Tool", "app")]);
        let _ = std::fs::remove_dir_all(root);
    }
}
