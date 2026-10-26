"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional

from . import __version__, lockfile, sbom, util
from . import platform as plat_mod
from .diff import diff_sections, has_drift, render
from .managers import ALL, detect
from .managers.base import Options, is_root
from .util import SyslockError, log, warn


def _managers_arg(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    names = [v.strip() for v in value.split(",") if v.strip()]
    unknown = [n for n in names if n not in ALL]
    if unknown:
        raise SyslockError(f"unknown manager(s): {', '.join(unknown)} (known: {', '.join(ALL)})")
    return names


def _write_out(text: str, path: Optional[str]) -> None:
    if not path or path == "-":
        sys.stdout.write(text)
        return
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    log(f"wrote {path}")


# ---------------------------------------------------------------- commands


def cmd_platform(args) -> int:
    plat = plat_mod.detect()
    print(json.dumps(dict(plat, environment=plat_mod.env_id(plat), managers=[m.name for m in detect()]), indent=2))
    return 0


def cmd_lock(args) -> int:
    plat = plat_mod.detect()
    eid = args.env_id or plat_mod.env_id(plat)
    wanted = _managers_arg(args.managers)
    mgrs = [m for m in detect() if wanted is None or m.name in wanted]
    if wanted:
        missing = sorted(set(wanted) - {m.name for m in mgrs})
        if missing:
            raise SyslockError(f"requested manager(s) not available on this machine: {', '.join(missing)}")
    if not mgrs:
        raise SyslockError("no supported package manager found (apt, rpm, apk, pacman, brew)")
    opts = Options(licenses=not args.no_licenses, embed_keys=not args.no_embed_keys)
    sections = {}
    for m in mgrs:
        log(f"capturing {m.name} ...")
        try:
            sections[m.name] = m.capture(plat, opts)
        except SyslockError as exc:
            if wanted:
                raise
            warn(f"skipping {m.name}: {exc}")
    if not sections:
        raise SyslockError("nothing captured")
    env = lockfile.strip_private({"platform": plat, "capturedAt": lockfile.now_utc(), "managers": sections})
    data = lockfile.load_or_empty(args.file) if not args.stdout else lockfile.empty()
    old = (data.get("environments") or {}).get(eid)  # type: ignore[union-attr]
    if old and not args.replace:
        # Re-locking an unchanged system must not churn the file (git diffs).
        merged_mgrs = dict(old.get("managers", {}))
        merged_mgrs.update(env["managers"])
        if lockfile.env_digest(dict(env, managers=merged_mgrs)) == old.get("digest"):
            log(f"{eid}: no changes")
            if args.stdout:
                sys.stdout.write(util.canonical_json(data))
            return 0
    lockfile.put_environment(data, eid, env, replace_managers=args.replace)
    if args.stdout:
        sys.stdout.write(util.canonical_json(data))
    else:
        lockfile.save(data, args.file)
        counts = ", ".join(f"{k}: {len(v['packages'])}" for k, v in sorted(sections.items()))
        log(f"locked {eid} ({counts}) -> {args.file}")
    return 0


def cmd_envs(args) -> int:
    data = lockfile.load(args.file)
    here = plat_mod.env_id(plat_mod.detect())
    for eid, env in sorted(data["environments"].items()):  # type: ignore[union-attr]
        counts = ", ".join(f"{k}={len(v.get('packages', []))}" for k, v in sorted(env["managers"].items()))
        mark = "*" if eid == here else " "
        print(f"{mark} {eid:32} {env.get('capturedAt', '?'):22} {counts}")
    return 0


def cmd_validate(args) -> int:
    data = lockfile.load(args.file)  # raises on structural problems
    bad = lockfile.check_digests(data)
    if bad:
        print(f"digest mismatch (edited by hand or corrupted): {', '.join(bad)}", file=sys.stderr)
        return 1
    print(f"{args.file}: OK ({len(data['environments'])} environment(s))")  # type: ignore[arg-type]
    return 0


def _select(args, data) -> str:
    plat = plat_mod.detect()
    return lockfile.select_environment(data, plat, args.env, getattr(args, "allow_cross_release", False))


def cmd_sbom(args) -> int:
    data = lockfile.load(args.file)
    envs: Dict[str, Dict[str, object]] = data["environments"]  # type: ignore[assignment]
    if args.env == "all":
        targets = sorted(envs)
    elif args.env:
        if args.env not in envs:
            raise SyslockError(f"environment {args.env!r} not in lock; available: {', '.join(sorted(envs))}")
        targets = [args.env]
    elif len(envs) == 1:
        targets = list(envs)
    else:
        targets = [_select(args, data)]
    gen = sbom.cyclonedx if args.format == "cyclonedx" else sbom.spdx
    ext = "cdx.json" if args.format == "cyclonedx" else "spdx.json"
    for eid in targets:
        doc = gen(eid, envs[eid])
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        out = args.output
        if len(targets) > 1:
            out = os.path.join(args.output or ".", f"{eid}.{ext}")
        _write_out(text, out)
    return 0


def _current_sections(env: Dict[str, object], plat, integrity: bool, only: Optional[List[str]]):
    res = {}
    for mname in env["managers"]:  # type: ignore[union-attr]
        if only and mname not in only:
            continue
        m = ALL.get(mname)
        if not m or not m.available():
            warn(f"{mname} is locked but not available here; every package will show as missing")
            res[mname] = []
            continue
        if integrity:
            res[mname] = m.capture(plat, Options(licenses=False, embed_keys=False))["packages"]
        else:
            res[mname] = m.installed(plat)
    return res


def cmd_diff(args, check: bool = False) -> int:
    data = lockfile.load(args.file)
    envs = data["environments"]
    eid = _select(args, data)
    env = envs[eid]  # type: ignore[index]
    only = _managers_arg(args.managers)
    if getattr(args, "against", None):
        other_path, _, other_env = args.against.partition(":")
        odata = lockfile.load(other_path)
        oenvs = odata["environments"]
        oid = other_env or (eid if eid in oenvs else None)  # type: ignore[operator]
        if not oid or oid not in oenvs:  # type: ignore[operator]
            raise SyslockError(f"pick an environment in {other_path} with {other_path}:<env>; "
                               f"available: {', '.join(sorted(oenvs))}")  # type: ignore[arg-type]
        other = oenvs[oid]  # type: ignore[index]
        cur_plat = other["platform"]
        current = {m: s.get("packages", []) for m, s in other["managers"].items()}
    else:
        cur_plat = plat_mod.detect()
        current = _current_sections(env, cur_plat, getattr(args, "integrity", False), only)
    result = {}
    for mname, sec in env["managers"].items():
        if only and mname not in only:
            continue
        result[mname] = diff_sections(mname, sec.get("packages", []), env["platform"],
                                      current.get(mname, []), cur_plat)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"environment: {eid}")
        print(render(result, limit=None if args.all else 50))
    drift = has_drift(result, ignore_extra=getattr(args, "ignore_extra", False))
    if check:
        if drift:
            log("drift detected")
            return 1
        log("system matches the lock")
    return 0


def cmd_apply(args) -> int:
    data = lockfile.load(args.file)
    plat = plat_mod.detect()
    eid = _select(args, data)
    env = data["environments"][eid]  # type: ignore[index]
    src_plat = env["platform"]
    only = _managers_arg(args.managers)
    opts = Options(roots_only=args.roots_only, prune=args.prune, best_effort=args.best_effort,
                   snapshot=not args.no_snapshot, add_repos=args.add_repos, refresh=not args.no_refresh,
                   cache_dir=args.cache_dir)

    log(f"applying environment {eid} (captured {env.get('capturedAt')}) on {plat_mod.env_id(plat)}")
    if src_plat.get("arch") != plat["arch"]:
        warn(f"lock was captured on {src_plat.get('arch')}, this machine is {plat['arch']}: "
             "architecture-specific packages are re-targeted and their checksums cannot be verified")
    if src_plat.get("distro") != plat["distro"] or src_plat.get("release") != plat["release"]:
        warn(f"lock was captured on {src_plat.get('distro')} {src_plat.get('release')}, this machine is "
             f"{plat['distro']} {plat['release']}: many exact versions will not exist")
    if lockfile.check_digests({"environments": {eid: env}}):
        if not args.force:
            raise SyslockError(f"environment {eid} does not match its digest (edited or corrupted); use --force to apply anyway")
        warn("digest mismatch ignored because of --force")

    selected = []
    for mname, section in sorted(env["managers"].items()):
        if only and mname not in only:
            continue
        m = ALL.get(mname)
        if not m or not m.available():
            warn(f"skipping {mname}: not available on this machine")
            continue
        if mname == "brew" and is_root() and not args.dry_run:
            warn("skipping brew: Homebrew must not run as root; run `syslock apply --managers brew` as your user")
            continue
        if mname != "brew" and not is_root() and not args.dry_run:
            raise SyslockError(f"{mname} changes need root; re-run with sudo (or use --dry-run to preview)")
        section = dict(section, _capturedAt=env.get("capturedAt", ""))
        selected.append((m, section))
    if not selected:
        raise SyslockError("nothing to apply on this machine")

    script = ["#!/bin/sh", f"# syslock {__version__} plan for {eid}", "set -eu"]
    for m, section in selected:
        prep = m.prepare(section, src_plat, plat, opts)
        if args.dry_run:
            script.append(prep.render())
        else:
            if prep.steps:
                if not _confirm(args, prep.render()):
                    return 1
            prep.execute()
        plan = m.plan(section, src_plat, plat, opts)
        script.append(plan.render())
        for w in plan.warnings:
            warn(w)
        if plan.unresolved and not args.best_effort and not args.dry_run:
            raise SyslockError(f"{m.name}: {len(plan.unresolved)} package(s) cannot be installed at the locked version:\n  "
                               + "\n  ".join(plan.unresolved[:30])
                               + "\nUse --best-effort to install the closest available versions instead.")
        log(f"{m.name}: " + ", ".join(f"{k}={v}" for k, v in plan.summary.items()))
        if not args.dry_run:
            if plan.steps and not _confirm(args, plan.render()):
                return 1
            plan.execute()
    if args.dry_run:
        _write_out("\n".join(script) + "\n", args.script)
        return 0
    log("verifying ...")
    args.json, args.all, args.ignore_extra, args.integrity = False, False, not args.prune, False
    return cmd_diff(args, check=True)


def _confirm(args, text: str) -> bool:
    if args.yes:
        return True
    print(text)
    if not sys.stdin.isatty():
        raise SyslockError("refusing to change the system without a terminal; pass --yes or use --dry-run")
    return input("Proceed? [y/N] ").strip().lower() in ("y", "yes")


def cmd_export(args) -> int:
    data = lockfile.load(args.file)
    eid = _select(args, data)
    env = data["environments"][eid]  # type: ignore[index]
    if args.format == "brewfile":
        if "brew" not in env["managers"]:
            raise SyslockError(f"{eid} has no Homebrew section")
        _write_out(ALL["brew"].export_brewfile(env["managers"]["brew"]), args.output)  # type: ignore[attr-defined]
        return 0
    # "list": name=version lines per manager, handy for review or Dockerfiles.
    lines = []
    for mname, sec in sorted(env["managers"].items()):
        for p in sec["packages"]:
            if args.roots_only and p.get("reason") != "manual":
                continue
            lines.append(f"{mname}\t{p['name']}\t{(str(p['epoch']) + ':') if p.get('epoch') else ''}{p['version']}\t{p.get('arch', '')}")
    _write_out("\n".join(lines) + "\n", args.output)
    return 0


# ------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="syslock", description="Lock files and SBOMs for apt, rpm, apk, pacman and Homebrew.")
    p.add_argument("--version", action="version", version=f"syslock {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="print executed commands")
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")
    sub.required = True

    def common(sp, env=True):
        sp.add_argument("-f", "--file", default=os.environ.get("SYSLOCK_FILE", lockfile.DEFAULT_LOCKFILE),
                        help="lock file (default: %(default)s, env SYSLOCK_FILE)")
        if env:
            sp.add_argument("--env", help="environment id inside the lock (default: match this machine)")
            sp.add_argument("--allow-cross-release", action="store_true",
                            help="if no environment matches exactly, use the closest one from the same distro family")
        sp.add_argument("-m", "--managers", help="comma separated subset, e.g. apt,brew")

    sp = sub.add_parser("platform", help="show the detected platform and package managers")
    sp.set_defaults(func=cmd_platform)

    sp = sub.add_parser("lock", help="snapshot installed packages into the lock file")
    common(sp, env=False)
    sp.add_argument("--env-id", help="override the environment id (default: <distro>-<release>-<arch>)")
    sp.add_argument("--replace", action="store_true", help="drop managers not captured this run from the environment")
    sp.add_argument("--no-licenses", action="store_true", help="do not record license metadata")
    sp.add_argument("--no-embed-keys", action="store_true", help="do not embed third-party repository keys")
    sp.add_argument("--stdout", action="store_true", help="print the lock instead of writing the file")
    sp.set_defaults(func=cmd_lock)

    sp = sub.add_parser("sbom", help="generate an SBOM from the lock file")
    common(sp)
    sp.add_argument("--format", choices=["cyclonedx", "spdx"], default="cyclonedx")
    sp.add_argument("-o", "--output", help="output file ('-' for stdout; a directory with --env all)")
    sp.set_defaults(func=cmd_sbom)

    sp = sub.add_parser("diff", help="show differences between the lock and this system")
    common(sp)
    sp.add_argument("--against", metavar="LOCK[:ENV]", help="compare with another lock file instead of the system")
    sp.add_argument("--integrity", action="store_true", help="also compare checksums (slower, recaptures)")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--all", action="store_true", help="do not truncate long lists")
    sp.set_defaults(func=cmd_diff)

    sp = sub.add_parser("check", help="exit 1 if the system drifted from the lock (for CI)")
    common(sp)
    sp.add_argument("--ignore-extra", action="store_true", help="packages installed but not locked are fine")
    sp.add_argument("--integrity", action="store_true", help="also compare checksums")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--all", action="store_true")
    sp.set_defaults(func=lambda a: cmd_diff(a, check=True))

    sp = sub.add_parser("apply", help="install the locked versions on this machine")
    common(sp)
    sp.add_argument("-n", "--dry-run", action="store_true", help="print the plan as a shell script, change nothing")
    sp.add_argument("--script", help="with --dry-run, write the script to this file")
    sp.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    sp.add_argument("--roots-only", action="store_true",
                    help="install only manually installed packages at their locked versions; let the solver pick dependencies")
    sp.add_argument("--prune", action="store_true", help="remove packages that are not in the lock (never essential ones)")
    sp.add_argument("--best-effort", action="store_true", help="install the newest version when the locked one is gone")
    sp.add_argument("--no-snapshot", action="store_true",
                    help="do not fall back to snapshot.debian.org / snapshot.ubuntu.com / Koji / Arch archive / brew extract")
    sp.add_argument("--add-repos", action="store_true", help="recreate third-party repositories and keys recorded in the lock")
    sp.add_argument("--no-refresh", action="store_true", help="skip apt-get update / dnf makecache / ...")
    sp.add_argument("--cache-dir", default=os.environ.get("SYSLOCK_CACHE", "/var/cache/syslock"))
    sp.add_argument("--force", action="store_true", help="apply even if the lock digest does not match")
    sp.set_defaults(func=cmd_apply)

    sp = sub.add_parser("envs", help="list environments stored in the lock file")
    common(sp, env=False)
    sp.set_defaults(func=cmd_envs)

    sp = sub.add_parser("validate", help="validate the lock file structure and digests")
    common(sp, env=False)
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("export", help="export the lock as a Brewfile or a plain package list")
    common(sp)
    sp.add_argument("--format", choices=["list", "brewfile"], default="list")
    sp.add_argument("--roots-only", action="store_true")
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_export)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    util.VERBOSE = args.verbose
    try:
        return int(args.func(args) or 0)
    except SyslockError as exc:
        print(f"syslock: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("syslock: interrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0
