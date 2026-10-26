"""Alpine Linux (apk-tools) backend."""

from __future__ import annotations

import glob
import os
import re
import tarfile
from typing import Dict, List, Optional, Set, Tuple

from ..util import read_text, run, sha256_file, warn, which
from .base import Manager, Plan, Step, resolve_dependencies

APK_ARCH = {"armv6": "armhf", "i686": "x86"}
INSTALLED_DB = ["/lib/apk/db/installed", "/usr/lib/apk/db/installed"]
WORLD = "/etc/apk/world"
REPOS = "/etc/apk/repositories"
PIN_GROUP = ".syslock-pins"


def _strip_dep(dep: str) -> str:
    """'so:libc.musl-x86_64.so.1' stays, 'busybox>=1.36' -> 'busybox',
    'curl@edge' -> 'curl', '!foo' -> '' (conflicts are not dependencies)."""
    if dep.startswith("!"):
        return ""
    return re.split(r"[<>=~@]", dep, maxsplit=1)[0]


def parse_installed(text: str) -> Tuple[List[Dict[str, object]], Dict[str, List[List[str]]], Dict[str, List[str]], Set[str]]:
    """Parse the apk installed database. Returns packages, requires, provides
    and the set of files owned by any package."""
    pkgs: List[Dict[str, object]] = []
    requires: Dict[str, List[List[str]]] = {}
    provides: Dict[str, List[str]] = {}
    owned: Set[str] = set()
    cur: Dict[str, object] = {}
    cur_dir = ""

    def flush():
        if cur.get("name"):
            pkgs.append(dict(cur))

    for line in text.splitlines() + [""]:
        if not line:
            flush()
            cur = {}
            cur_dir = ""
            continue
        if len(line) < 2 or line[1] != ":":
            continue
        k, v = line[0], line[2:]
        if k == "P":
            cur["name"] = v
        elif k == "V":
            cur["version"] = v
        elif k == "A":
            cur["arch"] = v
        elif k == "C":
            cur["checksum"] = v
        elif k == "S" and v.isdigit():
            cur["size"] = int(v)
        elif k == "L" and v:
            cur["licenses"] = [v]
        elif k == "o" and v != cur.get("name"):
            cur["source"] = {"name": v}
        elif k == "c":
            cur["commit"] = v
        elif k == "D":
            requires[str(cur.get("name"))] = [[d] for d in (_strip_dep(x) for x in v.split()) if d]
        elif k == "p":
            provides[str(cur.get("name"))] = [_strip_dep(x) for x in v.split() if _strip_dep(x)]
        elif k == "F":
            cur_dir = v
        elif k == "R":
            owned.add("/" + (cur_dir + "/" if cur_dir else "") + v)
    return pkgs, requires, provides, owned


def parse_world(text: str) -> Dict[str, str]:
    """name -> raw world entry (keeps @tag / constraints for reference)."""
    res = {}
    for tok in text.split():
        name = _strip_dep(tok)
        if name:
            res[name] = tok
    return res


def parse_apkindex(text: str) -> Dict[Tuple[str, str], str]:
    """(name, version) -> checksum, from an APKINDEX file."""
    res = {}
    cur: Dict[str, str] = {}
    for line in text.splitlines() + [""]:
        if not line:
            if "P" in cur and "V" in cur:
                res[(cur["P"], cur["V"])] = cur.get("C", "")
            cur = {}
        elif len(line) > 1 and line[1] == ":":
            cur[line[0]] = line[2:]
    return res


class Apk(Manager):
    name = "apk"

    def available(self) -> bool:
        return bool(which("apk")) and self._db() is not None

    def arch_of(self, canonical: str) -> str:
        return APK_ARCH.get(canonical, canonical)

    def _db(self) -> Optional[str]:
        return next((p for p in INSTALLED_DB if os.path.exists(p)), None)

    def _read(self):
        db = self._db()
        pkgs, req, prov, owned = parse_installed(read_text(db)) if db else ([], {}, {}, set())
        # Our own pin group is bookkeeping, not part of the locked state.
        pkgs = [p for p in pkgs if p["name"] != PIN_GROUP]
        for p in pkgs:
            if str(p["name"]).startswith("."):
                # `apk add --virtual .build-deps ...` creates a package that
                # exists in no repository; it is recreated from its deps.
                p["virtual"] = True
        return pkgs, req, prov, owned

    def _world(self) -> Dict[str, str]:
        return parse_world(read_text(WORLD)) if os.path.exists(WORLD) else {}

    def installed(self, plat):
        pkgs, _, _, _ = self._read()
        world = self._world()
        for p in pkgs:
            p["reason"] = "manual" if p["name"] in world else "dependency"
        return pkgs

    def capture(self, plat, opts):
        pkgs, requires, provides, owned = self._read()
        world = self._world()
        if not world:
            warn("apk world file is empty or missing; no package is recorded as manually installed")
        resolve_dependencies(pkgs, requires, provides)
        for p in pkgs:
            p["reason"] = "manual" if p["name"] in world else "dependency"
            if world.get(str(p["name"]), p["name"]) != p["name"]:
                p["worldEntry"] = world[str(p["name"])]
            if not opts.licenses:
                p.pop("licenses", None)
        repos = []
        if os.path.exists(REPOS):
            for line in read_text(REPOS).splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    tag, url = (line.split(None, 1) if line.startswith("@") else ("", line))
                    r: Dict[str, object] = {"id": line, "url": url.strip()}
                    if tag:
                        r["tag"] = tag
                    repos.append(r)
        keys = []
        for path in sorted(glob.glob("/etc/apk/keys/*")):
            k: Dict[str, object] = {"path": path, "sha256": sha256_file(path)}
            if path not in owned and opts.embed_keys:
                import base64

                with open(path, "rb") as fh:
                    k["data"] = base64.b64encode(fh.read()).decode()
            keys.append(k)
        pkgs.sort(key=lambda p: str(p["name"]))
        return {"tool": run(["apk", "--version"], check=False).strip(), "repositories": repos,
                "keys": keys, "packages": pkgs}

    # ----------------------------------------------------------------- apply

    def prepare(self, section, src_plat, dst_plat, opts):
        plan = Plan("apk (prepare)")
        if opts.add_repos:
            current = read_text(REPOS).splitlines() if os.path.exists(REPOS) else []
            have = {ln.strip() for ln in current}
            missing = [str(r["id"]) for r in section.get("repositories", []) if str(r["id"]) not in have]
            for k in section.get("keys", []):
                if k.get("data") and not os.path.exists(str(k["path"])):
                    plan.add(Step(comment=f"signing key {os.path.basename(str(k['path']))}",
                                  write={"path": str(k["path"]), "content": str(k["data"]), "encoding": "base64"}))
            if missing:
                plan.add(Step(comment=f"add {len(missing)} repositor(y/ies)",
                              write={"path": REPOS, "content": "\n".join(current + missing)}))
        if opts.refresh:
            plan.add(Step(["apk", "update"], comment="refresh package indexes"))
        return plan

    def _index(self) -> Optional[Dict[Tuple[str, str], str]]:
        files = glob.glob("/var/cache/apk/APKINDEX.*.tar.gz") + glob.glob("/etc/apk/cache/APKINDEX.*.tar.gz")
        if not files:
            return None
        res: Dict[Tuple[str, str], str] = {}
        for f in files:
            try:
                with tarfile.open(f) as tf:
                    member = tf.extractfile("APKINDEX")
                    if member:
                        res.update(parse_apkindex(member.read().decode("utf-8", "replace")))
            except (tarfile.TarError, KeyError, OSError):
                continue
        return res

    def plan(self, section, src_plat, dst_plat, opts):
        plan = Plan("apk")
        pkgs = list(section.get("packages", []))
        current = {str(p["name"]): p for p in self.installed(dst_plat)}
        index = self._index()
        roots, deps, virtuals = [], [], []
        for p in pkgs:
            name, ver = str(p["name"]), str(p["version"])
            if p.get("reason") != "manual" and opts.roots_only:
                continue
            if p.get("virtual"):
                if name not in current:
                    virtuals.append(p)
                continue
            cur = current.get(name, {})
            if cur.get("version") == ver and (p.get("reason") != "manual" or cur.get("reason") == "manual"):
                continue
            spec = f"{name}={ver}"
            if index is not None and (name, ver) not in index and current.get(name, {}).get("version") != ver:
                # Alpine drops superseded versions and has no public archive.
                if opts.best_effort:
                    plan.warnings.append(f"{spec} is no longer in the repositories; installing newest {name}")
                    spec = name
                else:
                    plan.unresolved.append(f"{spec} (Alpine keeps no archive of old versions)")
                    continue
            tag = str(p.get("worldEntry", ""))
            if "@" in tag:
                spec += "@" + tag.split("@", 1)[1].split("=")[0]
            (roots if p.get("reason") == "manual" else deps).append(spec)
        if deps:
            # A virtual group pins dependencies without listing them in world
            # as if the user had asked for them.
            plan.add(Step(["apk", "add", "--virtual", PIN_GROUP] + sorted(deps),
                          comment=f"pin {len(deps)} dependenc(y/ies) at locked versions"))
        if roots:
            plan.add(Step(["apk", "add"] + sorted(roots), comment=f"install {len(roots)} package(s) at locked versions"))
        for v in virtuals:
            members = [str(d) for d in v.get("dependencies", [])]
            plan.add(Step(["apk", "add", "--virtual", str(v["name"])] + members,
                          comment=f"recreate virtual package {v['name']}"))
        if opts.prune:
            world = self._world()
            locked_roots = {str(p["name"]) for p in pkgs if p.get("reason") == "manual"}
            extra = sorted(n for n in world if n not in locked_roots and n != PIN_GROUP)
            if extra:
                plan.add(Step(["apk", "del"] + extra, comment=f"remove {len(extra)} world entr(y/ies) not in the lock"))
        plan.warnings.append("apk records '=version' pins in /etc/apk/world; `apk upgrade` will keep these "
                             "versions until you run `syslock lock` again or relax the pins")
        changed = sum(1 for p in pkgs if current.get(str(p["name"]), {}).get("version") != p["version"])
        plan.summary = {"install_or_change": changed, "unresolved": len(plan.unresolved)}
        return plan
