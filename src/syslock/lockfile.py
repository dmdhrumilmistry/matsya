"""Reading, writing, merging and validating lock files.

Layout (lockfileVersion 1):

{
  "lockfileVersion": 1,
  "generator": {"name": "syslock", "version": "0.1.0"},
  "environments": {
    "<distro>-<release>-<arch>": {
      "platform": {...},            # what it was captured on
      "capturedAt": "...Z",         # also the snapshot.* timestamp
      "managers": {"apt": {...}, "brew": {...}},
      "digest": "sha256:..."        # over platform + managers
    }
  }
}
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import tempfile
from typing import Dict, List, Optional

from . import LOCKFILE_VERSION, __version__
from .util import SyslockError, canonical_json, digest

DEFAULT_LOCKFILE = "syslock.lock.json"


def now_utc() -> str:
    """Capture timestamp. Honours SOURCE_DATE_EPOCH for reproducible output."""
    sde = os.environ.get("SOURCE_DATE_EPOCH")
    if sde and sde.isdigit():
        t = _dt.datetime.fromtimestamp(int(sde), tz=_dt.timezone.utc)
    else:
        t = _dt.datetime.now(tz=_dt.timezone.utc)
    return t.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def empty() -> Dict[str, object]:
    return {
        "lockfileVersion": LOCKFILE_VERSION,
        "generator": {"name": "syslock", "version": __version__},
        "environments": {},
    }


def load(path: str) -> Dict[str, object]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise SyslockError(f"lock file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        hint = ""
        if "<<<<<<<" in open(path, encoding="utf-8", errors="replace").read():
            hint = " (it contains git merge conflict markers; re-run `syslock lock` on each machine)"
        raise SyslockError(f"{path} is not valid JSON: {exc}{hint}") from exc
    problems = validate(data)
    if problems:
        raise SyslockError(f"{path} is not a valid lock file:\n  " + "\n  ".join(problems))
    return data


def load_or_empty(path: str) -> Dict[str, object]:
    return load(path) if os.path.exists(path) else empty()


def save(data: Dict[str, object], path: str) -> None:
    """Atomic write: a crash never leaves a half-written lock behind."""
    data["generator"] = {"name": "syslock", "version": __version__}
    text = canonical_json(data)
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".syslock-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        if os.path.exists(path):
            os.chmod(tmp, os.stat(path).st_mode & 0o777)
        else:
            os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def env_digest(env: Dict[str, object]) -> str:
    return digest({"platform": env.get("platform"), "managers": env.get("managers")})


def put_environment(data: Dict[str, object], eid: str, env: Dict[str, object],
                    replace_managers: bool = False) -> None:
    """Insert or update one environment. By default managers that were not
    captured this time (e.g. brew not installed in a CI container) are kept
    from the previous lock instead of being silently dropped."""
    envs = data.setdefault("environments", {})
    assert isinstance(envs, dict)
    old = envs.get(eid)
    if old and not replace_managers:
        merged = dict(old.get("managers", {}))
        merged.update(env["managers"])  # type: ignore[arg-type]
        env = dict(env, managers=merged)
    env["digest"] = env_digest(env)
    envs[eid] = env


def strip_private(obj):
    """Drop keys starting with '_' (in-memory bookkeeping) and None values."""
    if isinstance(obj, dict):
        return {k: strip_private(v) for k, v in obj.items() if not k.startswith("_") and v is not None}
    if isinstance(obj, list):
        return [strip_private(v) for v in obj]
    return obj


def validate(data) -> List[str]:
    """Structural validation without a JSON-schema dependency."""
    p: List[str] = []
    if not isinstance(data, dict):
        return ["top level must be an object"]
    v = data.get("lockfileVersion")
    if not isinstance(v, int):
        p.append("lockfileVersion missing or not an integer")
    elif v > LOCKFILE_VERSION:
        p.append(f"lockfileVersion {v} is newer than this syslock supports ({LOCKFILE_VERSION}); upgrade syslock")
    envs = data.get("environments")
    if not isinstance(envs, dict):
        p.append("environments must be an object")
        return p
    for eid, env in envs.items():
        if not isinstance(env, dict):
            p.append(f"{eid}: must be an object")
            continue
        plat = env.get("platform")
        if not isinstance(plat, dict) or not plat.get("arch") or not plat.get("distro"):
            p.append(f"{eid}: platform.distro and platform.arch are required")
        mgrs = env.get("managers")
        if not isinstance(mgrs, dict):
            p.append(f"{eid}: managers must be an object")
            continue
        for mname, sec in mgrs.items():
            pkgs = sec.get("packages") if isinstance(sec, dict) else None
            if not isinstance(pkgs, list):
                p.append(f"{eid}/{mname}: packages must be a list")
                continue
            seen = set()
            for i, pkg in enumerate(pkgs):
                if not isinstance(pkg, dict) or not pkg.get("name") or "version" not in pkg:
                    p.append(f"{eid}/{mname}: package #{i} needs name and version")
                    continue
                k = (pkg["name"], pkg.get("arch", ""), pkg.get("kind", ""))
                if k in seen:
                    p.append(f"{eid}/{mname}: duplicate package {pkg['name']} ({pkg.get('arch', '')})")
                seen.add(k)
    return p


def check_digests(data: Dict[str, object]) -> List[str]:
    """Environments whose content does not match their recorded digest,
    i.e. the file was edited by hand or corrupted."""
    bad = []
    for eid, env in data.get("environments", {}).items():  # type: ignore[union-attr]
        if env.get("digest") and env["digest"] != env_digest(env):
            bad.append(eid)
    return bad


def select_environment(data: Dict[str, object], plat: Dict[str, object], wanted: Optional[str],
                       allow_cross: bool) -> str:
    """Pick the environment to apply on this machine.

    1. --env wins.
    2. Exact id match (same distro, release, arch).
    3. Same distro + release on another arch (packages are re-targeted).
    4. Same distro (or ID_LIKE family), other release - only with
       --allow-cross-release, because versions rarely exist across releases.
    """
    from .platform import env_id, family

    envs: Dict[str, Dict[str, object]] = data.get("environments", {})  # type: ignore[assignment]
    if not envs:
        raise SyslockError("the lock file has no environments; run `syslock lock` first")
    if wanted:
        if wanted not in envs:
            raise SyslockError(f"environment {wanted!r} not in lock; available: {', '.join(sorted(envs))}")
        return wanted
    eid = env_id(plat)
    if eid in envs:
        return eid
    same_rel = [k for k, e in envs.items()
                if e["platform"].get("distro") == plat["distro"] and e["platform"].get("release") == plat["release"]]  # type: ignore[index,union-attr]
    if len(same_rel) == 1:
        return same_rel[0]
    # Homebrew versions do not depend on the OS release (macOS 14 and 15
    # install the same formula versions), so brew-only environments match
    # on distro alone, preferring the same architecture.
    brew_only = sorted((k for k, e in envs.items()
                        if e["platform"].get("distro") == plat["distro"]  # type: ignore[union-attr]
                        and set(e.get("managers", {})) == {"brew"}),  # type: ignore[arg-type]
                       key=lambda k: envs[k]["platform"].get("arch") != plat["arch"])  # type: ignore[union-attr]
    if brew_only:
        return brew_only[0]
    fam = set(family(plat))
    near = sorted(k for k, e in envs.items()
                  if set(family(e["platform"])) & fam)  # type: ignore[arg-type]
    if near and allow_cross:
        # Prefer same distro and arch, then same distro.
        near.sort(key=lambda k: (envs[k]["platform"].get("distro") != plat["distro"],  # type: ignore[union-attr]
                                 envs[k]["platform"].get("arch") != plat["arch"]))  # type: ignore[union-attr]
        return near[0]
    msg = f"no environment in the lock matches this machine ({eid}); available: {', '.join(sorted(envs))}."
    if near:
        msg += " Pass --env to choose one, or --allow-cross-release to pick the closest match."
    raise SyslockError(msg)
