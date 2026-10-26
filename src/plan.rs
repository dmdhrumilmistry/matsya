//! Apply plans: an ordered list of commands, verified downloads and file
//! writes that can be rendered as a shell script (dry run) or executed.

use std::collections::BTreeMap;
use std::path::Path;

use crate::bail;
use crate::util::{has, log, run_ok, sha256_file, Result};

#[derive(Debug, Clone, Default)]
pub struct Fetch {
    pub urls: Vec<String>,
    pub dest: String,
    pub sha256: Option<String>,
    /// For rpm: (header tag, expected value), e.g. ("PAYLOADSHA256", "...").
    pub rpm_payload: Option<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct Write {
    pub path: String,
    pub content: String,
    pub base64: bool,
    pub mode: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Step {
    pub comment: String,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub fetch: Option<Fetch>,
    pub write: Option<Write>,
}

impl Step {
    pub fn cmd<S: Into<String>>(comment: impl Into<String>, argv: impl IntoIterator<Item = S>) -> Self {
        Step { comment: comment.into(), argv: argv.into_iter().map(Into::into).collect(), ..Default::default() }
    }
    pub fn with_env(mut self, k: &str, v: &str) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }
    pub fn fetch(comment: impl Into<String>, f: Fetch) -> Self {
        Step { comment: comment.into(), fetch: Some(f), ..Default::default() }
    }
    pub fn write(comment: impl Into<String>, w: Write) -> Self {
        Step { comment: comment.into(), write: Some(w), ..Default::default() }
    }

    pub fn render(&self) -> String {
        let mut lines = Vec::new();
        if !self.comment.is_empty() {
            lines.push(format!("# {}", self.comment));
        }
        if let Some(f) = &self.fetch {
            let dest = sh_quote(&f.dest);
            let dir = Path::new(&f.dest).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
            lines.push(format!("mkdir -p {}", sh_quote(&dir)));
            lines.push(
                f.urls
                    .iter()
                    .map(|u| format!("curl -fsSL --retry 3 -o {dest} {}", sh_quote(u)))
                    .collect::<Vec<_>>()
                    .join(" || "),
            );
            if let Some(sha) = &f.sha256 {
                lines.push(format!("echo {} | sha256sum -c -", sh_quote(&format!("{sha}  {}", f.dest))));
            }
            if let Some((tag, want)) = &f.rpm_payload {
                lines.push(format!(
                    "test \"$(rpm -qp --nosignature --qf {} {dest})\" = {}",
                    sh_quote(&format!("%{{{tag}}}")),
                    sh_quote(want)
                ));
            }
        }
        if let Some(w) = &self.write {
            let dir = Path::new(&w.path).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
            lines.push(format!("mkdir -p {}", sh_quote(&dir)));
            let cmd = if w.base64 { "base64 -d >" } else { "cat >" };
            lines.push(format!("{cmd} {} <<'MATSYA_EOF'\n{}\nMATSYA_EOF", sh_quote(&w.path), w.content.trim_end()));
        }
        if !self.argv.is_empty() {
            let prefix: String = self.env.iter().map(|(k, v)| format!("{k}={} ", sh_quote(v))).collect();
            lines.push(prefix + &self.argv.iter().map(|a| sh_quote(a)).collect::<Vec<_>>().join(" "));
        }
        lines.join("\n")
    }

    pub fn execute(&self) -> Result<()> {
        if !self.comment.is_empty() {
            log(&self.comment);
        }
        if let Some(f) = &self.fetch {
            fetch_verified(f)?;
        }
        if let Some(w) = &self.write {
            if let Some(dir) = Path::new(&w.path).parent() {
                std::fs::create_dir_all(dir)?;
            }
            let bytes = if w.base64 {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(w.content.trim())
                    .map_err(|e| crate::util::Error(format!("bad base64 for {}: {e}", w.path)))?
            } else {
                format!("{}\n", w.content.trim_end()).into_bytes()
            };
            std::fs::write(&w.path, bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &w.path,
                    std::fs::Permissions::from_mode(if w.mode == 0 { 0o644 } else { w.mode }),
                )?;
            }
        }
        if !self.argv.is_empty() {
            log(&format!("running: {}", self.argv.iter().map(|a| sh_quote(a)).collect::<Vec<_>>().join(" ")));
            let status = std::process::Command::new(&self.argv[0])
                .args(&self.argv[1..])
                .envs(&self.env)
                .status()
                .map_err(|e| crate::util::Error(format!("cannot run {}: {e}", self.argv[0])))?;
            if !status.success() {
                bail!("step failed with exit code {}: {}", status.code().unwrap_or(-1), self.argv.join(" "));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct Plan {
    pub manager: String,
    pub steps: Vec<Step>,
    pub warnings: Vec<String>,
    pub unresolved: Vec<String>,
    pub summary: Vec<(String, usize)>,
}

impl Plan {
    pub fn new(manager: &str) -> Self {
        Plan { manager: manager.into(), ..Default::default() }
    }
    pub fn add(&mut self, s: Step) {
        self.steps.push(s);
    }
    pub fn render(&self) -> String {
        let mut out = vec![format!("# --- {} ---", self.manager)];
        out.extend(self.warnings.iter().map(|w| format!("# WARNING: {w}")));
        out.extend(self.unresolved.iter().map(|u| format!("# UNRESOLVED: {u}")));
        out.extend(self.steps.iter().map(Step::render));
        out.join("\n")
    }
    pub fn execute(&self) -> Result<()> {
        for s in &self.steps {
            s.execute()?;
        }
        Ok(())
    }
}

pub fn sh_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "@%+=:,./_-".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

/// Download with whatever the system already trusts (curl, wget or apt's
/// own helper, honouring its proxy settings) and refuse to keep the file
/// unless its digest matches the lock.
pub fn fetch_verified(f: &Fetch) -> Result<()> {
    if let Some(dir) = Path::new(&f.dest).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = format!("{}.part", f.dest);
    let mut errors = Vec::new();
    let mut ok = false;
    for url in &f.urls {
        log(&format!("downloading {url}"));
        let attempt: Vec<String> = if has("curl") {
            vec!["curl".into(), "-fsSL".into(), "--retry".into(), "3".into(), "-o".into(), tmp.clone(), url.clone()]
        } else if has("wget") {
            vec!["wget".into(), "-q".into(), "-O".into(), tmp.clone(), url.clone()]
        } else if Path::new("/usr/lib/apt/apt-helper").exists() {
            vec!["/usr/lib/apt/apt-helper".into(), "download-file".into(), url.clone(), tmp.clone()]
        } else {
            bail!("no downloader found (need curl, wget or apt-helper)");
        };
        let refs: Vec<&str> = attempt.iter().map(String::as_str).collect();
        match crate::util::exec(&refs) {
            Ok(o) if o.code == 0 && Path::new(&tmp).exists() => {
                ok = true;
                break;
            }
            Ok(o) => errors.push(format!("{url}: exit {} {}", o.code, o.stderr.trim())),
            Err(e) => errors.push(format!("{url}: {e}")),
        }
        let _ = std::fs::remove_file(&tmp);
    }
    if !ok {
        bail!("download failed:\n  {}", errors.join("\n  "));
    }
    if let Some(want) = &f.sha256 {
        let got = sha256_file(&tmp)?;
        if &got != want {
            let _ = std::fs::remove_file(&tmp);
            bail!("sha256 mismatch for {}: expected {want}, got {got}", f.urls[0]);
        }
    }
    if let Some((tag, want)) = &f.rpm_payload {
        let got = run_ok(&["rpm", "-qp", "--nosignature", "--qf", &format!("%{{{tag}}}"), &tmp]);
        if got.trim() != want {
            let _ = std::fs::remove_file(&tmp);
            bail!("rpm payload digest mismatch for {}", f.urls[0]);
        }
    }
    std::fs::rename(&tmp, &f.dest)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("apt-get"), "apt-get");
        assert_eq!(sh_quote("jq:arm64=1.7+dfsg-1"), "jq:arm64=1.7+dfsg-1");
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("it's"), "'it'\"'\"'s'");
        assert_eq!(sh_quote(""), "''");
    }

    #[test]
    fn verified_download_rejects_bad_hash() {
        let dir = std::env::temp_dir().join(format!("matsya-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        std::fs::write(&src, b"hello").unwrap();
        if !has("curl") {
            return;
        }
        let url = format!("file://{}", src.display());
        let dest = dir.join("out.bin").to_string_lossy().into_owned();
        let good = crate::util::sha256_hex(b"hello");
        fetch_verified(&Fetch { urls: vec![url.clone()], dest: dest.clone(), sha256: Some(good), rpm_payload: None })
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello");
        let bad = Fetch {
            urls: vec![url],
            dest: dir.join("bad.bin").to_string_lossy().into_owned(),
            sha256: Some("0".repeat(64)),
            rpm_payload: None,
        };
        assert!(fetch_verified(&bad).unwrap_err().0.contains("sha256 mismatch"));
        assert!(!Path::new(&bad.dest).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
