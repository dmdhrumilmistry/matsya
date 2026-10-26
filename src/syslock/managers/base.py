"""Common pieces for package manager backends."""

from __future__ import annotations

import os
import shlex
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ..util import SyslockError, log, run, sha256_file, warn


class Options:
    """Knobs shared by capture and apply. Kept as a plain object so the CLI
    and tests can construct it without argparse."""

    def __init__(self, **kw):
        self.roots_only: bool = kw.get("roots_only", False)
        self.prune: bool = kw.get("prune", False)
        self.best_effort: bool = kw.get("best_effort", False)
        self.snapshot: bool = kw.get("snapshot", True)
        self.add_repos: bool = kw.get("add_repos", False)
        self.refresh: bool = kw.get("refresh", True)
        self.cache_dir: str = kw.get("cache_dir", "/var/cache/syslock")
        self.licenses: bool = kw.get("licenses", True)
        self.embed_keys: bool = kw.get("embed_keys", True)


class Step:
    """One action in an apply plan: either a command or a verified download."""

    def __init__(self, argv: Optional[List[str]] = None, *, comment: str = "",
                 fetch: Optional[Dict[str, str]] = None,
                 write: Optional[Dict[str, str]] = None,
                 env: Optional[Dict[str, str]] = None):
        self.argv = argv
        self.comment = comment
        # {"url", "fallbacks"?, "dest", "sha256"} or {..., "check": "rpm-payload", "digest"}
        self.fetch = fetch
        self.write = write  # {"path", "content", "mode", "encoding"?: "base64"}
        self.env = env or {}

    def render(self) -> str:
        lines = []
        if self.comment:
            lines.append(f"# {self.comment}")
        if self.argv:
            prefix = "".join(f"{k}={shlex.quote(v)} " for k, v in sorted(self.env.items()))
            lines.append(prefix + " ".join(shlex.quote(a) for a in self.argv))
        if self.fetch:
            f = self.fetch
            dest = shlex.quote(f["dest"])
            lines.append(f"mkdir -p {shlex.quote(os.path.dirname(f['dest']))}")
            urls = [f["url"]] + list(f.get("fallbacks", []))
            lines.append(" || ".join(f"curl -fsSL --retry 3 -o {dest} {shlex.quote(u)}" for u in urls))
            if f.get("sha256"):
                lines.append(f"echo {shlex.quote(f['sha256'] + '  ' + f['dest'])} | sha256sum -c -")
            if f.get("check") == "rpm-payload":
                qf = shlex.quote("%{" + f.get("tag", "PAYLOADDIGEST") + "}")
                lines.append(f"test \"$(rpm -qp --nosignature --qf {qf} {dest})\" = {shlex.quote(f['digest'])}")
        if self.write:
            w = self.write
            lines.append(f"mkdir -p {shlex.quote(os.path.dirname(w['path']))}")
            if w.get("encoding") == "base64":
                lines.append(f"base64 -d > {shlex.quote(w['path'])} <<'SYSLOCK_EOF'\n{w['content'].strip()}\nSYSLOCK_EOF")
            else:
                lines.append(f"cat > {shlex.quote(w['path'])} <<'SYSLOCK_EOF'\n{w['content'].rstrip()}\nSYSLOCK_EOF")
        return "\n".join(lines)


class Plan:
    def __init__(self, manager: str):
        self.manager = manager
        self.steps: List[Step] = []
        self.warnings: List[str] = []
        self.unresolved: List[str] = []
        self.summary: Dict[str, int] = {}

    def add(self, step: Step) -> None:
        self.steps.append(step)

    def render(self) -> str:
        out = [f"# --- {self.manager} ---"]
        for w in self.warnings:
            out.append(f"# WARNING: {w}")
        for u in self.unresolved:
            out.append(f"# UNRESOLVED: {u}")
        for s in self.steps:
            out.append(s.render())
        return "\n".join(out)

    def execute(self) -> None:
        for step in self.steps:
            if step.comment:
                log(step.comment)
            if step.fetch:
                fetch_verified(step.fetch)
            if step.write:
                d = os.path.dirname(step.write["path"])
                os.makedirs(d, exist_ok=True)
                if step.write.get("encoding") == "base64":
                    import base64

                    with open(step.write["path"], "wb") as fh:
                        fh.write(base64.b64decode(step.write["content"]))
                else:
                    with open(step.write["path"], "w") as fh:
                        fh.write(step.write["content"].rstrip() + "\n")
                os.chmod(step.write["path"], int(step.write.get("mode", "644"), 8))
            if step.argv:
                env = dict(os.environ)
                env.update(step.env)
                import subprocess

                log("running: " + " ".join(shlex.quote(a) for a in step.argv))
                rc = subprocess.call(step.argv, env=env)
                if rc != 0:
                    raise SyslockError(f"step failed with exit code {rc}: {' '.join(step.argv)}")


def fetch_verified(f: Dict[str, str]) -> None:
    """Download a file and refuse to keep it unless its digest matches."""
    import urllib.request

    dest = f["dest"]
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp = dest + ".part"
    # Several mirrors may carry the file (e.g. ubuntu vs ubuntu-ports
    # snapshots); try them in order and keep the first that downloads.
    urls = [f["url"]] + list(f.get("fallbacks", []))
    errors = []
    for url in urls:
        log(f"downloading {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "syslock"})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as out:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
            break
        except Exception as exc:  # urllib raises a zoo of exception types
            errors.append(f"{url}: {exc}")
            if os.path.exists(tmp):
                os.unlink(tmp)
    else:
        raise SyslockError("download failed:\n  " + "\n  ".join(errors))
    if f.get("sha256"):
        got = sha256_file(tmp)
        if got != f["sha256"]:
            os.unlink(tmp)
            raise SyslockError(f"sha256 mismatch for {f['url']}: expected {f['sha256']}, got {got}")
    if f.get("check") == "rpm-payload":
        tag = f.get("tag", "PAYLOADDIGEST")
        got = run(["rpm", "-qp", "--nosignature", "--qf", "%{" + tag + "}", tmp], check=False).strip()
        if got != f["digest"]:
            os.unlink(tmp)
            raise SyslockError(f"rpm payload digest mismatch for {f['url']}")
    os.replace(tmp, dest)


class Manager:
    """Interface every backend implements."""

    name = "base"

    def available(self) -> bool:
        raise NotImplementedError

    def capture(self, plat: Dict[str, object], opts: Options) -> Dict[str, object]:
        """Return the lock section for this manager."""
        raise NotImplementedError

    def installed(self, plat: Dict[str, object]) -> List[Dict[str, object]]:
        """A cheap listing of installed packages (name/version/arch/reason),
        used by `diff`/`check` and by apply to compute what to change."""
        raise NotImplementedError

    def prepare(self, section: Dict[str, object], src_plat: Dict[str, object],
                dst_plat: Dict[str, object], opts: Options) -> Plan:
        """Steps that change what is *available* (repos, keys, index refresh).
        They run before plan() so that plan() sees the refreshed metadata."""
        return Plan(self.name)

    def plan(self, section: Dict[str, object], src_plat: Dict[str, object],
             dst_plat: Dict[str, object], opts: Options) -> Plan:
        raise NotImplementedError

    def key_of(self, pkg: Dict[str, object], plat: Dict[str, object]) -> str:
        """Identity of a package for diffing. Foreign-architecture packages
        (multiarch, multilib) get an arch suffix so they do not collide."""
        return str(pkg["name"])

    # Architecture names as this manager spells them.
    def arch_of(self, canonical: str) -> str:
        return canonical


def resolve_dependencies(
    pkgs: List[Dict[str, object]],
    requires: Dict[str, List[List[str]]],
    provides: Dict[str, Iterable[str]],
    key_of=lambda p: p["name"],
) -> None:
    """Fill pkg["dependencies"] with keys of installed packages.

    requires: key -> list of alternative groups (each a list of names).
    provides: key -> names that key satisfies (its own name is implied).
    The first installed alternative of every group wins, which mirrors how
    the package managers themselves pick satisfiers.
    """
    satisfiers: Dict[str, List[str]] = {}
    arch_of = {key_of(p): str(p.get("arch", "")) for p in pkgs}
    neutral = {"all", "noarch", "any", ""}
    for p in pkgs:
        k = key_of(p)
        satisfiers.setdefault(str(p["name"]), []).append(k)
        for prov in provides.get(k, ()):
            satisfiers.setdefault(prov, []).append(k)
    for p in pkgs:
        k = key_of(p)
        deps: Set[str] = set()
        for group in requires.get(k, []):
            for alt in group:
                cands = satisfiers.get(alt)
                if cands:
                    # Prefer a satisfier built for the dependent's architecture
                    # (libfoo:i386 -> libc6:i386), then arch-neutral ones.
                    mine = str(p.get("arch", ""))
                    deps.add(sorted(cands, key=lambda c: (arch_of.get(c) != mine and arch_of.get(c) not in neutral,
                                                          arch_of.get(c) != mine, c != alt, c))[0])
                    break
        deps.discard(k)
        if deps:
            p["dependencies"] = sorted(deps)


def split_lines(out: str) -> List[str]:
    # dnf4 and dnf5 disagree on whether --qf "\n" is interpreted.
    return [ln.strip() for ln in out.replace("\\n", "\n").splitlines() if ln.strip()]


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def batch_args(prefix: Sequence[str], items: Sequence[str], size: int = 200) -> List[List[str]]:
    """Avoid ARG_MAX on systems with thousands of packages."""
    return [list(prefix) + list(items[i : i + size]) for i in range(0, len(items), size)]


def compare_sets(locked: Dict[str, Dict[str, object]], current: Dict[str, Dict[str, object]]
                 ) -> Tuple[List[str], List[str], List[str]]:
    missing = sorted(k for k in locked if k not in current)
    extra = sorted(k for k in current if k not in locked)
    changed = sorted(k for k in locked if k in current and locked[k].get("version") != current[k].get("version"))
    return missing, extra, changed


def warn_once(seen: Set[str], msg: str) -> None:
    if msg not in seen:
        seen.add(msg)
        warn(msg)
