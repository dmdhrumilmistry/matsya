//! matsya: lock files and SBOMs for OS package managers.
//!
//! Named after Matsya, the fish avatar of Vishnu who carried the seeds of
//! all life safely through the great flood so the world could be rebuilt
//! exactly as it was. matsya records what a machine is made of and rebuilds
//! it, unchanged, somewhere else.

mod banner;
mod diff;
mod formats;
mod lockfile;
mod managers;
mod model;
mod plan;
mod platform;
mod sbom;
mod util;

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write as _};
use std::path::Path;
use std::sync::atomic::Ordering;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};

use crate::managers::{Manager, Options};
use crate::model::{Environment, Lockfile, Package};
use crate::util::{is_root, log, warn, Error, Result};

#[derive(Parser)]
#[command(
    name = "matsya",
    version,
    about = "Lock files and SBOMs for apt, rpm (dnf/yum/zypper), apk, pacman and Homebrew."
)]
struct Cli {
    /// Print executed commands
    #[arg(short, long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Args, Clone)]
struct FileArg {
    /// Lock file [default: matsya.lock.json, or syslock.lock.json if only that exists; env MATSYA_FILE]
    #[arg(short, long)]
    file: Option<String>,
    /// Comma separated subset of managers, e.g. apt,brew
    #[arg(short, long)]
    managers: Option<String>,
}

#[derive(Args, Clone)]
struct EnvArg {
    /// Environment id inside the lock (default: match this machine)
    #[arg(long)]
    env: Option<String>,
    /// If no environment matches exactly, use the closest one from the same distro family
    #[arg(long)]
    allow_cross_release: bool,
}

#[derive(Args, Clone)]
struct DiffArgs {
    #[command(flatten)]
    f: FileArg,
    #[command(flatten)]
    e: EnvArg,
    /// Compare with another lock file (LOCK[:ENV]) instead of the system
    #[arg(long, value_name = "LOCK[:ENV]")]
    against: Option<String>,
    /// Also compare checksums (slower, recaptures)
    #[arg(long)]
    integrity: bool,
    /// Packages installed but not locked are fine
    #[arg(long)]
    ignore_extra: bool,
    /// Only compare manually installed packages (pairs with apply --roots-only)
    #[arg(long)]
    roots_only: bool,
    #[arg(long)]
    json: bool,
    /// Do not truncate long lists
    #[arg(long)]
    all: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum SbomFormat {
    Cyclonedx,
    Spdx,
}

#[derive(Clone, Copy, ValueEnum)]
enum ExportFormat {
    List,
    Brewfile,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the detected platform and package managers
    Platform,
    /// Snapshot installed packages into the lock file
    Lock {
        #[command(flatten)]
        f: FileArg,
        /// Override the environment id (default: <distro>-<release>-<arch>)
        #[arg(long)]
        env_id: Option<String>,
        /// Drop managers not captured this run from the environment
        #[arg(long)]
        replace: bool,
        /// Do not record license metadata
        #[arg(long)]
        no_licenses: bool,
        /// Do not embed third-party repository keys
        #[arg(long)]
        no_embed_keys: bool,
        /// Print the lock instead of writing the file
        #[arg(long)]
        stdout: bool,
    },
    /// Generate an SBOM from the lock file
    Sbom {
        #[command(flatten)]
        f: FileArg,
        #[command(flatten)]
        e: EnvArg,
        #[arg(long, value_enum, default_value = "cyclonedx")]
        format: SbomFormat,
        /// Output file ('-' for stdout; a directory with --env all)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Show differences between the lock and this system
    Diff(DiffArgs),
    /// Exit 1 if the system drifted from the lock (for CI)
    Check(DiffArgs),
    /// Install the locked versions on this machine
    Apply {
        #[command(flatten)]
        f: FileArg,
        #[command(flatten)]
        e: EnvArg,
        /// Print the plan as a shell script, change nothing
        #[arg(short = 'n', long)]
        dry_run: bool,
        /// With --dry-run, write the script to this file
        #[arg(long)]
        script: Option<String>,
        /// Do not ask for confirmation
        #[arg(short, long)]
        yes: bool,
        /// Pin only manually installed packages; let the solver pick dependencies
        #[arg(long)]
        roots_only: bool,
        /// Remove packages that are not in the lock (never essential ones)
        #[arg(long)]
        prune: bool,
        /// Install the newest version when the locked one is gone
        #[arg(long)]
        best_effort: bool,
        /// Do not fall back to snapshot archives / Koji / Arch archive / brew extract
        #[arg(long)]
        no_snapshot: bool,
        /// Recreate third-party repositories and keys recorded in the lock
        #[arg(long)]
        add_repos: bool,
        /// Skip apt-get update / dnf makecache / ...
        #[arg(long)]
        no_refresh: bool,
        #[arg(long, env = "MATSYA_CACHE", default_value = "/var/cache/matsya")]
        cache_dir: String,
        /// Apply even if the lock digest does not match
        #[arg(long)]
        force: bool,
    },
    /// List environments stored in the lock file
    Envs {
        #[command(flatten)]
        f: FileArg,
    },
    /// Validate the lock file structure and digests
    Validate {
        #[command(flatten)]
        f: FileArg,
    },
    /// Export the lock as a Brewfile or a plain package list
    Export {
        #[command(flatten)]
        f: FileArg,
        #[command(flatten)]
        e: EnvArg,
        #[arg(long, value_enum, default_value = "list")]
        format: ExportFormat,
        #[arg(long)]
        roots_only: bool,
        #[arg(short, long)]
        output: Option<String>,
    },
}

fn file_of(f: &FileArg) -> String {
    f.file.clone().unwrap_or_else(lockfile::default_path)
}

fn managers_arg(v: &Option<String>) -> Result<Option<Vec<String>>> {
    let Some(v) = v else { return Ok(None) };
    let names: Vec<String> = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let unknown: Vec<&String> = names.iter().filter(|n| !managers::NAMES.contains(&n.as_str())).collect();
    if !unknown.is_empty() {
        crate::bail!(
            "unknown manager(s): {} (known: {})",
            unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
            managers::NAMES.join(", ")
        );
    }
    Ok(Some(names))
}

fn write_out(text: &str, path: Option<&str>) -> Result<()> {
    match path {
        None | Some("-") => {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(text.as_bytes());
        }
        Some(p) => {
            if let Some(d) = Path::new(p).parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(d)?;
            }
            std::fs::write(p, text)?;
            log(&format!("wrote {p}"));
        }
    }
    Ok(())
}

fn select(lock: &Lockfile, e: &EnvArg) -> Result<String> {
    lockfile::select_environment(lock, &platform::detect(), e.env.as_deref(), e.allow_cross_release)
}

// ---------------------------------------------------------------- commands

fn cmd_platform() -> Result<i32> {
    let plat = platform::detect();
    let mut v = serde_json::to_value(&plat)?;
    v["environment"] = serde_json::json!(plat.env_id());
    v["managers"] = serde_json::json!(managers::detect().iter().map(|m| m.name()).collect::<Vec<_>>());
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
fn cmd_lock(
    f: &FileArg,
    env_id: &Option<String>,
    replace: bool,
    no_licenses: bool,
    no_embed_keys: bool,
    stdout: bool,
) -> Result<i32> {
    let plat = platform::detect();
    let eid = env_id.clone().unwrap_or_else(|| plat.env_id());
    let wanted = managers_arg(&f.managers)?;
    let mgrs: Vec<Box<dyn Manager>> = managers::detect()
        .into_iter()
        .filter(|m| wanted.as_ref().map_or(true, |w| w.iter().any(|n| n == m.name())))
        .collect();
    if let Some(w) = &wanted {
        let missing: Vec<&String> = w.iter().filter(|n| !mgrs.iter().any(|m| m.name() == n.as_str())).collect();
        if !missing.is_empty() {
            crate::bail!(
                "requested manager(s) not available on this machine: {}",
                missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
    }
    if mgrs.is_empty() {
        crate::bail!("no supported package manager found (apt, rpm, apk, pacman, brew)");
    }
    let opts = Options { licenses: !no_licenses, embed_keys: !no_embed_keys, ..Default::default() };
    let mut sections = BTreeMap::new();
    for m in &mgrs {
        log(&format!("capturing {} ...", m.name()));
        match m.capture(&plat, &opts) {
            Ok(s) => {
                sections.insert(m.name().to_string(), s);
            }
            Err(e) if wanted.is_none() => warn(&format!("skipping {}: {e}", m.name())),
            Err(e) => return Err(e),
        }
    }
    if sections.is_empty() {
        crate::bail!("nothing captured");
    }
    let counts = sections.iter().map(|(k, v)| format!("{k}: {}", v.packages.len())).collect::<Vec<_>>().join(", ");
    let env =
        Environment { platform: plat, captured_at: Some(util::now_utc()), managers: sections, ..Default::default() };
    let path = file_of(f);
    let mut lock = if stdout { Lockfile::default() } else { lockfile::load_or_empty(&path)? };
    if let Some(old) = lock.environments.get(&eid) {
        if !replace {
            // Re-locking an unchanged system must not churn the file (git diffs).
            let mut merged = old.managers.clone();
            merged.extend(env.managers.clone());
            let candidate = Environment { managers: merged, ..env.clone() };
            if Some(lockfile::env_digest(&candidate)) == old.digest {
                log(&format!("{eid}: no changes"));
                if stdout {
                    print!("{}", lockfile::to_text(&lock));
                }
                return Ok(0);
            }
        }
    }
    lockfile::put_environment(&mut lock, &eid, env, replace);
    if stdout {
        lock.generator = model::generator();
        print!("{}", lockfile::to_text(&lock));
    } else {
        lockfile::save(&mut lock, &path)?;
        log(&format!("locked {eid} ({counts}) -> {path}"));
    }
    Ok(0)
}

fn cmd_envs(f: &FileArg) -> Result<i32> {
    let lock = lockfile::load(&file_of(f))?;
    let here = platform::detect().env_id();
    for (eid, env) in &lock.environments {
        let counts =
            env.managers.iter().map(|(k, v)| format!("{k}={}", v.packages.len())).collect::<Vec<_>>().join(", ");
        let mark = if *eid == here { "*" } else { " " };
        println!("{mark} {eid:32} {:22} {counts}", env.captured_at.as_deref().unwrap_or("?"));
    }
    Ok(0)
}

fn cmd_validate(f: &FileArg) -> Result<i32> {
    let path = file_of(f);
    let lock = lockfile::load(&path)?;
    let bad = lockfile::check_digests(&lock);
    if !bad.is_empty() {
        eprintln!("digest mismatch (edited by hand or corrupted): {}", bad.join(", "));
        return Ok(1);
    }
    println!("{path}: OK ({} environment(s))", lock.environments.len());
    Ok(0)
}

fn cmd_sbom(f: &FileArg, e: &EnvArg, format: SbomFormat, output: &Option<String>) -> Result<i32> {
    let lock = lockfile::load(&file_of(f))?;
    let envs = &lock.environments;
    let targets: Vec<String> = match e.env.as_deref() {
        Some("all") => envs.keys().cloned().collect(),
        Some(_) => vec![select(&lock, e)?],
        None if envs.len() == 1 => envs.keys().cloned().collect(),
        None => vec![select(&lock, e)?],
    };
    let ext = match format {
        SbomFormat::Cyclonedx => "cdx.json",
        SbomFormat::Spdx => "spdx.json",
    };
    // `--env all` and an existing directory both mean "one file per
    // environment in this directory", even if the lock has only one.
    let to_dir = e.env.as_deref() == Some("all") || output.as_deref().is_some_and(|o| Path::new(o).is_dir());
    for eid in &targets {
        let doc = match format {
            SbomFormat::Cyclonedx => sbom::cyclonedx(eid, &envs[eid]),
            SbomFormat::Spdx => sbom::spdx(eid, &envs[eid]),
        };
        let text = serde_json::to_string_pretty(&doc)? + "\n";
        let out = if to_dir || targets.len() > 1 {
            Some(format!("{}/{eid}.{ext}", output.as_deref().unwrap_or(".")))
        } else {
            output.clone()
        };
        write_out(&text, out.as_deref())?;
    }
    Ok(0)
}

fn current_sections(
    env: &Environment,
    plat: &platform::Platform,
    integrity: bool,
    only: &Option<Vec<String>>,
) -> Result<BTreeMap<String, Vec<Package>>> {
    let mut res = BTreeMap::new();
    for name in env.managers.keys() {
        if only.as_ref().is_some_and(|o| !o.contains(name)) {
            continue;
        }
        let pkgs = match managers::get(name).filter(|m| m.available()) {
            None => {
                warn(&format!("{name} is locked but not available here; every package will show as missing"));
                vec![]
            }
            Some(m) if integrity => {
                m.capture(plat, &Options { licenses: false, embed_keys: false, ..Default::default() })?.packages
            }
            Some(m) => m.installed(plat)?,
        };
        res.insert(name.clone(), pkgs);
    }
    Ok(res)
}

fn cmd_diff(a: &DiffArgs, check: bool) -> Result<i32> {
    let lock = lockfile::load(&file_of(&a.f))?;
    let eid = select(&lock, &a.e)?;
    let env = &lock.environments[&eid];
    let only = managers_arg(&a.f.managers)?;
    let (cur_plat, current) = if let Some(against) = &a.against {
        let (path, oenv) = against
            .split_once(':')
            .map(|(p, e)| (p.to_string(), Some(e.to_string())))
            .unwrap_or((against.clone(), None));
        let other = lockfile::load(&path)?;
        let oid = oenv.or_else(|| other.environments.contains_key(&eid).then(|| eid.clone()));
        let Some(o) = oid.as_ref().and_then(|id| other.environments.get(id)) else {
            crate::bail!(
                "pick an environment in {path} with {path}:<env>; available: {}",
                other.environments.keys().cloned().collect::<Vec<_>>().join(", ")
            );
        };
        (o.platform.clone(), o.managers.iter().map(|(k, v)| (k.clone(), v.packages.clone())).collect())
    } else {
        let p = platform::detect();
        let c = current_sections(env, &p, a.integrity, &only)?;
        (p, c)
    };
    let mut result = BTreeMap::new();
    for (name, sec) in &env.managers {
        if only.as_ref().is_some_and(|o| !o.contains(name)) {
            continue;
        }
        let locked: Vec<Package> = sec.packages.iter().filter(|p| !a.roots_only || p.is_manual()).cloned().collect();
        let mgr = managers::get(name);
        let mut d = diff::diff_sections(
            mgr.as_deref(),
            &locked,
            &env.platform,
            current.get(name).map(Vec::as_slice).unwrap_or(&[]),
            &cur_plat,
        );
        if a.roots_only {
            d.extra.clear(); // dependencies are not compared in this mode
        }
        result.insert(name.clone(), d);
    }
    if a.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("environment: {eid}");
        println!("{}", diff::render(&result, if a.all { None } else { Some(50) }));
    }
    if check {
        if diff::has_drift(&result, a.ignore_extra || a.roots_only) {
            log("drift detected");
            return Ok(1);
        }
        log("system matches the lock");
    }
    Ok(0)
}

fn confirm(yes: bool, text: &str) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    println!("{text}");
    if !std::io::stdin().is_terminal() {
        crate::bail!("refusing to change the system without a terminal; pass --yes or use --dry-run");
    }
    print!("Proceed? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

#[allow(clippy::too_many_arguments)]
fn cmd_apply(
    f: &FileArg,
    e: &EnvArg,
    dry_run: bool,
    script: &Option<String>,
    yes: bool,
    roots_only: bool,
    prune: bool,
    best_effort: bool,
    no_snapshot: bool,
    add_repos: bool,
    no_refresh: bool,
    cache_dir: &str,
    force: bool,
) -> Result<i32> {
    let lock = lockfile::load(&file_of(f))?;
    let plat = platform::detect();
    let eid = select(&lock, e)?;
    let env = &lock.environments[&eid];
    let src = &env.platform;
    let only = managers_arg(&f.managers)?;
    let opts = Options {
        roots_only,
        prune,
        best_effort,
        snapshot: !no_snapshot,
        add_repos,
        refresh: !no_refresh,
        cache_dir: match platform::termux_prefix() {
            Some(p) if cache_dir == "/var/cache/matsya" => p.join("var/cache/matsya").to_string_lossy().into_owned(),
            _ => cache_dir.into(),
        },
        captured_at: env.captured_at().into(),
        ..Default::default()
    };
    log(&format!("applying environment {eid} (captured {}) on {}", env.captured_at(), plat.env_id()));
    if src.arch() != plat.arch() {
        warn(&format!(
            "lock was captured on {}, this machine is {}: architecture-specific packages are re-targeted and their checksums cannot be verified",
            src.arch(), plat.arch()
        ));
    }
    if src.distro() != plat.distro() || src.release() != plat.release() {
        warn(&format!(
            "lock was captured on {} {}, this machine is {} {}: many exact versions will not exist",
            src.distro(),
            src.release(),
            plat.distro(),
            plat.release()
        ));
    }
    if env.digest.as_deref().is_some_and(|d| d != lockfile::env_digest(env)) {
        if !force {
            crate::bail!(
                "environment {eid} does not match its digest (edited or corrupted); use --force to apply anyway"
            );
        }
        warn("digest mismatch ignored because of --force");
    }
    let mut selected = Vec::new();
    for (name, section) in &env.managers {
        if only.as_ref().is_some_and(|o| !o.contains(name)) {
            continue;
        }
        let Some(m) = managers::get(name).filter(|m| m.available()) else {
            warn(&format!("skipping {name}: not available on this machine"));
            continue;
        };
        if name == "brew" && is_root() {
            warn("skipping brew: Homebrew must not run as root; run `matsya apply --managers brew` as your user");
            continue;
        }
        // Termux runs as the app's own user and owns $PREFIX: no root needed.
        if name != "brew" && !is_root() && !dry_run && plat.distro() != "termux" {
            crate::bail!("{name} changes need root; re-run with sudo (or use --dry-run to preview)");
        }
        selected.push((m, section));
    }
    if selected.is_empty() {
        crate::bail!("nothing to apply on this machine");
    }
    let mut out = vec![
        "#!/bin/sh".to_string(),
        format!("# matsya {} plan for {eid}", env!("CARGO_PKG_VERSION")),
        "set -eu".into(),
    ];
    for (m, section) in &selected {
        let prep = m.prepare(section, src, &plat, &opts)?;
        if dry_run {
            out.push(prep.render());
        } else if !prep.steps.is_empty() {
            if !confirm(yes, &prep.render())? {
                return Ok(1);
            }
            prep.execute()?;
        }
        let p = m.plan(section, src, &plat, &opts)?;
        out.push(p.render());
        for w in &p.warnings {
            warn(w);
        }
        if !p.unresolved.is_empty() && !best_effort && !dry_run {
            let list: Vec<String> = p.unresolved.iter().take(30).cloned().collect();
            crate::bail!(
                "{}: {} package(s) cannot be installed at the locked version:\n  {}\nUse --best-effort to install the closest available versions instead.",
                m.name(), p.unresolved.len(), list.join("\n  ")
            );
        }
        log(&format!(
            "{}: {}",
            m.name(),
            p.summary.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ")
        ));
        if !dry_run && !p.steps.is_empty() {
            if !confirm(yes, &p.render())? {
                return Ok(1);
            }
            p.execute()?;
        }
    }
    if dry_run {
        write_out(&(out.join("\n") + "\n"), script.as_deref())?;
        return Ok(0);
    }
    log("verifying ...");
    let args = DiffArgs {
        f: f.clone(),
        e: e.clone(),
        against: None,
        integrity: false,
        ignore_extra: !prune,
        // Dependencies were left to the solver, so only the roots must match.
        roots_only,
        json: false,
        all: false,
    };
    cmd_diff(&args, true)
}

fn cmd_export(f: &FileArg, e: &EnvArg, format: ExportFormat, roots_only: bool, output: &Option<String>) -> Result<i32> {
    let lock = lockfile::load(&file_of(f))?;
    let eid = select(&lock, e)?;
    let env = &lock.environments[&eid];
    let text = match format {
        ExportFormat::Brewfile => {
            let Some(sec) = env.managers.get("brew") else { crate::bail!("{eid} has no Homebrew section") };
            managers::brew::export_brewfile(sec)
        }
        ExportFormat::List => {
            let mut lines = Vec::new();
            for (m, sec) in &env.managers {
                for p in sec.packages.iter().filter(|p| !roots_only || p.is_manual()) {
                    lines.push(format!("{m}\t{}\t{}\t{}", p.name, p.full_version(), p.arch()));
                }
            }
            lines.join("\n") + "\n"
        }
    };
    write_out(&text, output.as_deref())?;
    Ok(0)
}

fn run(cli: Cli) -> Result<i32> {
    let Some(cmd) = &cli.cmd else {
        print!("{}", banner::welcome(banner::color_stdout()));
        return Ok(0);
    };
    match cmd {
        Cmd::Platform => cmd_platform(),
        Cmd::Lock { f, env_id, replace, no_licenses, no_embed_keys, stdout } => {
            cmd_lock(f, env_id, *replace, *no_licenses, *no_embed_keys, *stdout)
        }
        Cmd::Sbom { f, e, format, output } => cmd_sbom(f, e, *format, output),
        Cmd::Diff(a) => cmd_diff(a, false),
        Cmd::Check(a) => cmd_diff(a, true),
        Cmd::Apply {
            f,
            e,
            dry_run,
            script,
            yes,
            roots_only,
            prune,
            best_effort,
            no_snapshot,
            add_repos,
            no_refresh,
            cache_dir,
            force,
        } => cmd_apply(
            f,
            e,
            *dry_run,
            script,
            *yes,
            *roots_only,
            *prune,
            *best_effort,
            *no_snapshot,
            *add_repos,
            *no_refresh,
            cache_dir,
            *force,
        ),
        Cmd::Envs { f } => cmd_envs(f),
        Cmd::Validate { f } => cmd_validate(f),
        Cmd::Export { f, e, format, roots_only, output } => cmd_export(f, e, *format, *roots_only, output),
    }
}

fn main() {
    // The banner tops `--help`; clap strips its colors when stdout is not a
    // terminal or NO_COLOR is set.
    let matches = Cli::command().before_help(banner::render(true)).get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    util::VERBOSE.store(cli.verbose, Ordering::Relaxed);
    let code = match run(cli) {
        Ok(c) => c,
        Err(Error(msg)) => {
            eprintln!("matsya: error: {msg}");
            2
        }
    };
    std::process::exit(code);
}
