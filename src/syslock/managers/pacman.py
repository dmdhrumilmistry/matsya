"""Arch Linux and derivatives (pacman) backend."""

from __future__ import annotations

import glob
import io
import os
import re
import tarfile
from typing import Dict, List, Optional, Tuple

from ..util import read_text, run, which
from .base import Manager, Plan, Step, resolve_dependencies

# Every package Arch has ever shipped, by name.
ALA = "https://archive.archlinux.org/packages/{first}/{name}/{filename}"


def parse_desc(text: str) -> Dict[str, List[str]]:
    """%KEY%\\nvalue\\nvalue\\n\\n blocks used by local and sync databases."""
    res: Dict[str, List[str]] = {}
    key = None
    for line in text.splitlines():
        if line.startswith("%") and line.endswith("%") and len(line) > 2:
            key = line[1:-1]
            res[key] = []
        elif line and key:
            res[key].append(line)
        elif not line:
            key = None
    return res


def _dep_name(d: str) -> str:
    """'glibc>=2.38', 'sh: for scripts', 'libfoo.so=1-64' -> bare names"""
    d = d.split(":", 1)[0]
    return re.split(r"[<>=]", d, maxsplit=1)[0].strip()


def package_from_desc(desc: Dict[str, List[str]]) -> Tuple[Dict[str, object], List[List[str]], List[str]]:
    one = lambda k: (desc.get(k) or [""])[0]
    p: Dict[str, object] = {"name": one("NAME"), "version": one("VERSION"), "arch": one("ARCH")}
    if one("BASE") and one("BASE") != p["name"]:
        p["source"] = {"name": one("BASE")}
    if desc.get("LICENSE"):
        p["licenses"] = desc["LICENSE"]
    if one("PACKAGER"):
        p["packager"] = one("PACKAGER")
    p["reason"] = "dependency" if one("REASON") == "1" else "manual"
    requires = [[_dep_name(d)] for d in desc.get("DEPENDS", []) if _dep_name(d)]
    provides = [_dep_name(d) for d in desc.get("PROVIDES", []) if _dep_name(d)]
    return p, requires, provides


def read_sync_db(path: str) -> Dict[Tuple[str, str], Dict[str, object]]:
    """(name, version) -> {filename, sha256, size} from a sync .db file."""
    data = None
    try:
        tf = tarfile.open(path)
    except tarfile.TarError:
        # zstd-compressed databases need an external tool on older Pythons.
        if which("zstd"):
            import subprocess

            raw = subprocess.run(["zstd", "-dc", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
            data = io.BytesIO(raw)
            try:
                tf = tarfile.open(fileobj=data)
            except tarfile.TarError:
                return {}
        else:
            return {}
    res = {}
    with tf:
        for m in tf.getmembers():
            if not m.name.endswith("/desc"):
                continue
            f = tf.extractfile(m)
            if not f:
                continue
            d = parse_desc(f.read().decode("utf-8", "replace"))
            one = lambda k: (d.get(k) or [""])[0]
            entry: Dict[str, object] = {"filename": one("FILENAME")}
            if one("SHA256SUM"):
                entry["sha256"] = one("SHA256SUM")
            if one("CSIZE").isdigit():
                entry["size"] = int(one("CSIZE"))
            res[(one("NAME"), one("VERSION"))] = entry
    return res


class Pacman(Manager):
    name = "pacman"

    def available(self) -> bool:
        return bool(which("pacman"))

    def _dbpath(self) -> str:
        if which("pacman-conf"):
            out = run(["pacman-conf", "DBPath"], check=False).strip()
            if out:
                return out.rstrip("/")
        return "/var/lib/pacman"

    def _local(self):
        pkgs, requires, provides = [], {}, {}
        for desc_path in sorted(glob.glob(os.path.join(self._dbpath(), "local", "*", "desc"))):
            p, req, prov = package_from_desc(parse_desc(read_text(desc_path)))
            if p["name"]:
                pkgs.append(p)
                requires[str(p["name"])] = req
                provides[str(p["name"])] = prov
        return pkgs, requires, provides

    def _sync(self) -> Dict[Tuple[str, str], Dict[str, object]]:
        res: Dict[Tuple[str, str], Dict[str, object]] = {}
        for db in sorted(glob.glob(os.path.join(self._dbpath(), "sync", "*.db"))):
            repo = os.path.basename(db)[:-3]
            for k, v in read_sync_db(db).items():
                res.setdefault(k, dict(v, repository=repo))
        return res

    def installed(self, plat):
        return self._local()[0]

    def capture(self, plat, opts):
        pkgs, requires, provides = self._local()
        resolve_dependencies(pkgs, requires, provides)
        sync = self._sync()
        for p in pkgs:
            hit = sync.get((str(p["name"]), str(p["version"])))
            if hit:
                p["repositories"] = [hit["repository"]]
                for k in ("sha256", "size", "filename"):
                    if k in hit:
                        p[k] = hit[k]
            if not opts.licenses:
                p.pop("licenses", None)
        repos = []
        if which("pacman-conf"):
            for name in run(["pacman-conf", "--repo-list"], check=False).split():
                servers = run(["pacman-conf", "--repo", name, "Server"], check=False).split()
                repos.append({"id": name, "servers": servers[:3]})
        return {"tool": run(["pacman", "--version"], check=False).strip().splitlines()[-1:][0].strip()
                if which("pacman") else "", "repositories": repos, "packages": pkgs}

    def prepare(self, section, src_plat, dst_plat, opts):
        plan = Plan("pacman (prepare)")
        if opts.refresh:
            plan.add(Step(["pacman", "-Sy", "--noconfirm"], comment="refresh sync databases"))
        return plan

    def plan(self, section, src_plat, dst_plat, opts):
        plan = Plan("pacman")
        pkgs = [p for p in section.get("packages", []) if not opts.roots_only or p.get("reason") == "manual"]
        current = {str(p["name"]): p for p in self.installed(dst_plat)}
        sync = self._sync()
        repo_specs, files = [], []
        touched = set()
        cross_arch = src_plat.get("arch") != dst_plat.get("arch")
        for p in pkgs:
            name, ver = str(p["name"]), str(p["version"])
            if current.get(name, {}).get("version") == ver:
                continue
            touched.add(name)
            if (name, ver) in sync:
                repo_specs.append(f"{sync[(name, ver)]['repository']}/{name}")
                continue
            if opts.snapshot and dst_plat.get("distro") == "arch" and p.get("filename") and not cross_arch:
                dest = os.path.join(opts.cache_dir, "pacman", str(p["filename"]))
                plan.add(Step(comment=f"{name} {ver} is no longer current; fetching from the Arch Linux Archive",
                              fetch={"url": ALA.format(first=name[0], name=name, filename=p["filename"]),
                                     "dest": dest, "sha256": str(p.get("sha256", ""))}))
                files.append(dest)
                continue
            if opts.best_effort:
                plan.warnings.append(f"{name} {ver} unavailable; installing current {name}")
                repo_specs.append(name)
            else:
                plan.unresolved.append(f"{name}={ver} (not in sync databases"
                                       + (" and Arch Linux Archive only covers x86_64 Arch" if dst_plat.get("distro") != "arch" else "")
                                       + ")")
        if files:
            plan.warnings.append("mixing archived and current packages is a partial upgrade; for a whole-system "
                                 "time travel point /etc/pacman.d/mirrorlist at "
                                 "https://archive.archlinux.org/repos/YYYY/MM/DD/$repo/os/$arch and run pacman -Syyuu")
        if repo_specs:
            plan.add(Step(["pacman", "-S", "--needed", "--noconfirm"] + sorted(repo_specs),
                          comment=f"install {len(repo_specs)} package(s) from sync databases"))
        if files:
            plan.add(Step(["pacman", "-U", "--needed", "--noconfirm"] + files,
                          comment=f"install {len(files)} archived package(s)"))
        def needs(p, reason):
            return p["name"] in touched or current.get(str(p["name"]), {}).get("reason") != reason

        explicit = sorted(str(p["name"]) for p in pkgs if p.get("reason") == "manual" and needs(p, "manual"))
        deps = sorted(str(p["name"]) for p in pkgs if p.get("reason") != "manual" and needs(p, "dependency"))
        if explicit:
            plan.add(Step(["pacman", "-D", "--asexplicit"] + explicit, comment="restore explicit-install reasons"))
        if deps and not opts.roots_only:
            plan.add(Step(["pacman", "-D", "--asdeps"] + deps, comment="restore dependency reasons"))
        if opts.prune:
            locked = {str(p["name"]) for p in section.get("packages", [])}
            extra = sorted(n for n in current if n not in locked and n not in ("pacman", "glibc", "filesystem", "base"))
            if extra:
                plan.add(Step(["pacman", "-Rn", "--noconfirm"] + extra, comment=f"remove {len(extra)} package(s) not in the lock"))
        plan.summary = {"install": len(repo_specs) + len(files), "unresolved": len(plan.unresolved)}
        return plan
