//! Detect which OS/distribution/architecture we run on.
//!
//! The platform makes a lock portable: every snapshot is an "environment"
//! keyed by distro + release + architecture, so one lock file can hold a
//! laptop (macOS arm64), a CI runner (Ubuntu x86_64) and a Raspberry Pi
//! (Debian aarch64) side by side.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::util::{has, read_text_opt, run_ok};

/// Field presence is preserved exactly (Option) so that re-serialising a
/// lock written by another version never changes its digest.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Platform {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distro: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_like: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Platform {
    pub fn os(&self) -> &str {
        self.os.as_deref().unwrap_or("")
    }
    pub fn distro(&self) -> &str {
        self.distro.as_deref().unwrap_or("")
    }
    pub fn release(&self) -> &str {
        self.release.as_deref().unwrap_or("")
    }
    pub fn arch(&self) -> &str {
        self.arch.as_deref().unwrap_or("")
    }
    pub fn codename(&self) -> &str {
        self.codename.as_deref().unwrap_or("")
    }
    pub fn version(&self) -> &str {
        self.version.as_deref().unwrap_or("")
    }

    /// Distro plus everything it claims to be like, most specific first.
    pub fn family(&self) -> Vec<String> {
        let mut v = vec![self.distro().to_string()];
        v.extend(self.id_like.clone().unwrap_or_default());
        v
    }

    pub fn env_id(&self) -> String {
        let raw = format!("{}-{}-{}", self.distro(), self.release(), self.arch());
        raw.chars().map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect()
    }
}

/// Canonical architecture names. Every package manager has its own
/// spelling; locks store the canonical one and backends translate.
pub fn normalize_arch(arch: &str) -> String {
    let a = arch.trim().to_ascii_lowercase();
    let n = match a.as_str() {
        "x86_64" | "amd64" | "x64" => "x86_64",
        "aarch64" | "arm64" | "armv8" => "aarch64",
        "armv7l" | "armv7" | "armhf" | "armv7h" => "armv7",
        "armel" | "armv6l" | "armhf_v6" => "armv6",
        "i386" | "i486" | "i586" | "i686" | "x86" => "i686",
        "ppc64le" | "ppc64el" => "ppc64le",
        "loongarch64" | "loong64" => "loongarch64",
        "" => "unknown",
        other => other,
    };
    n.to_string()
}

const ROLLING: &[&str] =
    &["arch", "archarm", "manjaro", "endeavouros", "gentoo", "void", "opensuse-tumbleweed", "artix", "cachyos"];
/// Families whose mirrors keep only the latest minor release.
const MAJOR_ONLY: &[&str] = &["rhel", "centos", "rocky", "almalinux", "ol", "amzn", "fedora"];

pub fn macos_codename(major: &str) -> &'static str {
    match major {
        "27" => "golden_gate",
        "26" => "tahoe",
        "15" => "sequoia",
        "14" => "sonoma",
        "13" => "ventura",
        "12" => "monterey",
        "11" => "big_sur",
        _ => "",
    }
}

pub fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let mut v = v.trim().to_string();
            if v.len() >= 2 && (v.starts_with('"') && v.ends_with('"') || v.starts_with('\'') && v.ends_with('\'')) {
                v = v[1..v.len() - 1].to_string();
            }
            m.insert(k.trim().to_string(), v);
        }
    }
    m
}

fn release_for(distro: &str, osr: &BTreeMap<String, String>) -> String {
    let version = osr.get("VERSION_ID").cloned().unwrap_or_default();
    if ROLLING.contains(&distro) || distro.contains("tumbleweed") {
        return "rolling".into();
    }
    if distro == "alpine" {
        // 3.20.3 -> 3.20; edge reports things like 3.21_alpha20240923.
        if version.is_empty() || version.contains('_') {
            return "edge".into();
        }
        return version.split('.').take(2).collect::<Vec<_>>().join(".");
    }
    if distro == "debian" && version.is_empty() {
        return osr.get("VERSION_CODENAME").cloned().unwrap_or_else(|| "sid".into());
    }
    if MAJOR_ONLY.contains(&distro) && !version.is_empty() {
        return version.split('.').next().unwrap_or("").to_string();
    }
    if !version.is_empty() {
        return version;
    }
    osr.get("VERSION_CODENAME").filter(|s| !s.is_empty()).cloned().unwrap_or_else(|| "unknown".into())
}

pub fn from_os_release(text: &str, arch: String) -> Platform {
    let osr = parse_os_release(text);
    let mut distro = osr.get("ID").cloned().unwrap_or_else(|| "linux".into()).to_ascii_lowercase();
    if distro.starts_with("opensuse-tumbleweed") {
        distro = "opensuse-tumbleweed".into();
    }
    let id_like = osr
        .get("ID_LIKE")
        .map(|s| s.to_ascii_lowercase().split_whitespace().map(String::from).collect())
        .unwrap_or_default();
    Platform {
        os: Some("linux".into()),
        release: Some(release_for(&distro, &osr)),
        distro: Some(distro),
        id_like: Some(id_like),
        version: Some(osr.get("VERSION_ID").cloned().unwrap_or_default()),
        codename: Some(osr.get("VERSION_CODENAME").cloned().unwrap_or_default()),
        arch: Some(arch),
        extra: BTreeMap::new(),
    }
}

pub fn detect() -> Platform {
    if cfg!(target_os = "macos") {
        let version = run_ok(&["sw_vers", "-productVersion"]).trim().to_string();
        let version = if version.is_empty() { "unknown".to_string() } else { version };
        let major = version.split('.').next().unwrap_or("").to_string();
        let mut arch = normalize_arch(run_ok(&["uname", "-m"]).trim());
        // Rosetta: a translated shell reports x86_64 on Apple Silicon.
        if arch == "x86_64" && run_ok(&["sysctl", "-in", "sysctl.proc_translated"]).trim() == "1" {
            arch = "aarch64".into();
        }
        return Platform {
            os: Some("macos".into()),
            distro: Some("macos".into()),
            id_like: Some(vec![]),
            codename: Some(macos_codename(&major).into()),
            release: Some(major),
            version: Some(version),
            arch: Some(arch),
            extra: BTreeMap::new(),
        };
    }
    let text = ["/etc/os-release", "/usr/lib/os-release"].iter().find_map(read_text_opt).unwrap_or_default();
    from_os_release(&text, native_arch())
}

/// The architecture packages are built for. This differs from uname on
/// e.g. a 32-bit userland running on a 64-bit kernel.
pub fn native_arch() -> String {
    for args in [&["dpkg", "--print-architecture"][..], &["apk", "--print-arch"][..]] {
        if has(args[0]) {
            let out = run_ok(args);
            if !out.trim().is_empty() {
                return normalize_arch(out.trim());
            }
        }
    }
    normalize_arch(std::env::consts::ARCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_variants() {
        let cases = [
            ("ID=alpine\nVERSION_ID=3.20.3\n", "alpine", "3.20"),
            ("ID=alpine\nVERSION_ID=3.21_alpha20240923\n", "alpine", "edge"),
            ("ID=arch\nBUILD_ID=rolling\n", "arch", "rolling"),
            ("ID=debian\nVERSION_CODENAME=trixie\n", "debian", "trixie"),
            ("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n", "rocky", "9"),
            ("ID=\"opensuse-tumbleweed\"\nVERSION_ID=\"20241020\"\n", "opensuse-tumbleweed", "rolling"),
            ("ID=ubuntu\nVERSION_ID='24.04'\n", "ubuntu", "24.04"),
        ];
        for (text, d, r) in cases {
            let p = from_os_release(text, "x86_64".into());
            assert_eq!((p.distro(), p.release()), (d, r), "{text}");
        }
    }

    #[test]
    fn arches() {
        assert_eq!(normalize_arch("amd64"), "x86_64");
        assert_eq!(normalize_arch("arm64"), "aarch64");
        assert_eq!(normalize_arch("armhf"), "armv7");
        assert_eq!(normalize_arch("ppc64el"), "ppc64le");
    }
}
