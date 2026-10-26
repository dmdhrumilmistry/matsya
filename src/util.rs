//! Small helpers shared by every module: errors, logging, subprocesses,
//! hashing, deterministic JSON and time formatting.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;
use sha2::{Digest, Sha256};

pub static VERBOSE: AtomicBool = AtomicBool::new(false);

/// An error shown to the user as `matsya: error: ...` without a backtrace.
#[derive(Debug)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => { return Err($crate::util::Error(format!($($arg)*))) };
}

pub fn log(msg: &str) {
    eprintln!("matsya: {msg}");
}

pub fn warn(msg: &str) {
    eprintln!("matsya: warning: {msg}");
}

pub fn debug(msg: &str) {
    if VERBOSE.load(Ordering::Relaxed) {
        eprintln!("matsya[debug]: {msg}");
    }
}

pub fn which(cmd: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(cmd);
        if let Ok(meta) = std::fs::metadata(&p) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                    return Some(p.to_string_lossy().into_owned());
                }
            }
            #[cfg(not(unix))]
            if meta.is_file() {
                return Some(p.to_string_lossy().into_owned());
            }
        }
    }
    None
}

pub fn has(cmd: &str) -> bool {
    which(cmd).is_some()
}

/// Ask the system package manager a question during `apply` (e.g. which
/// exact versions its repositories offer) and return its stdout. This is the
/// only place matsya runs another program besides the install steps of an
/// apply plan; capture, check, diff and SBOM generation never do.
pub fn package_manager_query(args: &[&str]) -> String {
    debug(&format!("exec: {}", args.join(" ")));
    let mut c = Command::new(args[0]);
    c.args(&args[1..]).env("LC_ALL", "C").env("LANG", "C").stdin(Stdio::null()).stderr(Stdio::null());
    c.output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

pub fn read_text(path: impl AsRef<Path>) -> Result<String> {
    let bytes =
        std::fs::read(path.as_ref()).map_err(|e| Error(format!("cannot read {}: {e}", path.as_ref().display())))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn read_text_opt(path: impl AsRef<Path>) -> Option<String> {
    read_text(path).ok()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<String> {
    let mut f = std::fs::File::open(path.as_ref())?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Deterministic, human-diffable JSON: sorted keys (serde_json maps are
/// BTreeMaps), two-space indent, trailing newline.
pub fn canonical_json(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).expect("serialisable");
    s.push('\n');
    s
}

/// sha256 over the compact canonical form; stable across implementations.
pub fn digest(v: &Value) -> String {
    format!("sha256:{}", sha256_hex(serde_json::to_string(v).expect("serialisable").as_bytes()))
}

/// RFC822-style stanzas (dpkg status, apt Packages, deb822 sources).
/// Continuation lines are joined with newlines.
pub fn parse_deb822(text: &str) -> Vec<BTreeMap<String, String>> {
    let mut out = Vec::new();
    let mut cur: BTreeMap<String, String> = BTreeMap::new();
    let mut key: Option<String> = None;
    for line in text.lines() {
        if line.trim().is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            key = None;
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(k) = &key {
                if let Some(v) = cur.get_mut(k) {
                    v.push('\n');
                    v.push_str(line.trim());
                }
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_string();
            cur.insert(k.clone(), v.trim().to_string());
            key = Some(k);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

// ------------------------------------------------------------------ time

/// Days since 1970-01-01 -> (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn format_epoch(secs: i64) -> String {
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Capture timestamp. Honours SOURCE_DATE_EPOCH for reproducible output.
pub fn now_utc() -> String {
    if let Ok(v) = std::env::var("SOURCE_DATE_EPOCH") {
        if let Ok(n) = v.trim().parse::<i64>() {
            return format_epoch(n);
        }
    }
    let secs =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    format_epoch(secs)
}

/// "Sat, 25 Oct 2026 13:28:41 UTC" (Release files) -> ISO 8601 UTC.
pub fn rfc2822_to_iso(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    let parts = if parts.first().is_some_and(|p| p.ends_with(',')) { &parts[1..] } else { &parts[..] };
    if parts.len() < 4 {
        return None;
    }
    let day: u32 = parts[0].parse().ok()?;
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let mon = months.iter().position(|m| parts[1].eq_ignore_ascii_case(m))? as u32 + 1;
    let year: i64 = parts[2].parse().ok()?;
    let hms: Vec<i64> = parts[3].split(':').map(|x| x.parse().unwrap_or(0)).collect();
    if hms.len() < 2 {
        return None;
    }
    let mut secs =
        days_from_civil(year, mon, day) * 86_400 + hms[0] * 3600 + hms[1] * 60 + hms.get(2).copied().unwrap_or(0);
    if let Some(tz) = parts.get(4) {
        // +hhmm / -hhmm offsets; named zones are assumed to be UTC.
        if (tz.starts_with('+') || tz.starts_with('-')) && tz.len() == 5 {
            if let (Ok(h), Ok(m)) = (tz[1..3].parse::<i64>(), tz[3..5].parse::<i64>()) {
                let off = h * 3600 + m * 60;
                secs -= if tz.starts_with('+') { off } else { -off };
            }
        }
    }
    Some(format_epoch(secs))
}

/// 2026-10-26T08:30:00Z -> 20261026T083000Z (snapshot archive format).
pub fn compact_ts(iso: &str) -> String {
    let digits: String = iso.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 14 {
        return String::new();
    }
    format!("{}T{}Z", &digits[..8], &digits[8..14])
}

pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        extern "C" {
            fn geteuid() -> u32;
        }
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { geteuid() == 0 }
    }
    #[cfg(not(unix))]
    false
}

/// dnf4 and dnf5 disagree on whether --qf "\n" is interpreted.
pub fn split_lines(out: &str) -> Vec<String> {
    out.replace("\\n", "\n").lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_roundtrip() {
        assert_eq!(format_epoch(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_epoch(1_729_936_721), "2024-10-26T09:58:41Z");
        assert_eq!(rfc2822_to_iso("Sat, 25 Oct 2026 13:28:41 UTC").unwrap(), "2026-10-25T13:28:41Z");
        assert_eq!(rfc2822_to_iso("Sat, 25 Oct 2026 15:28:41 +0200").unwrap(), "2026-10-25T13:28:41Z");
        assert_eq!(compact_ts("2024-01-02T03:04:05Z"), "20240102T030405Z");
    }

    #[test]
    fn deb822() {
        let s = parse_deb822("A: 1\nB: x\n y\n\n# c\nA: 2\n");
        assert_eq!(s.len(), 2);
        assert_eq!(s[0]["B"], "x\ny");
    }
}
