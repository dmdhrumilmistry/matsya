"""RPM based distributions: Fedora, RHEL/CentOS/Rocky/Alma, Amazon Linux,
openSUSE/SLES. Inventory comes from rpm itself; installs go through
whichever frontend exists (dnf5, dnf, yum, zypper)."""

from __future__ import annotations

import configparser
import glob
import os
import re
from typing import Dict, List, Optional, Set, Tuple

from ..util import SyslockError, read_text, run, warn, which
from .base import Manager, Plan, Step, batch_args, resolve_dependencies, split_lines

RPM_ARCH = {"i686": "i686", "armv7": "armv7hl", "ppc64le": "ppc64le"}
NOARCH = "noarch"

# Fedora's build system keeps every build ever shipped.
KOJI = "https://kojipkgs.fedoraproject.org/packages/{src}/{version}/{release}/{arch}/{name}-{version}-{release}.{arch}.rpm"

_QF_FIELDS = ["NAME", "EPOCHNUM", "VERSION", "RELEASE", "ARCH", "SOURCERPM", "LICENSE", "PAYLOADDIGEST",
              "SIGMD5", "VENDOR"]


def parse_rpm_qa(out: str) -> List[Dict[str, object]]:
    pkgs = []
    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) < len(_QF_FIELDS):
            continue
        name, epoch, ver, rel, arch, srpm, lic, payload, sigmd5, vendor = cols[: len(_QF_FIELDS)]
        if name == "gpg-pubkey":
            # Imported signing keys masquerade as packages.
            continue
        p: Dict[str, object] = {"name": name, "version": f"{ver}-{rel}", "arch": arch}
        if epoch not in ("", "0", "(none)"):
            p["epoch"] = int(epoch) if epoch.isdigit() else epoch
        src = srpm_name(srpm)
        if src and src != name:
            p["source"] = {"name": src}
        if lic and lic != "(none)":
            p["licenses"] = [lic]
        if payload and payload != "(none)":
            p["payloadDigest"] = payload
        if sigmd5 and sigmd5 != "(none)":
            p["sigmd5"] = sigmd5
        if vendor and vendor != "(none)":
            p["vendor"] = vendor
        pkgs.append(p)
    return pkgs


def srpm_name(srpm: str) -> str:
    """bash-5.2.26-3.fc40.src.rpm -> bash"""
    if not srpm or srpm == "(none)":
        return ""
    base = re.sub(r"\.(no)?src\.rpm$", "", srpm)
    parts = base.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else base


def evr(p: Dict[str, object]) -> str:
    e = p.get("epoch")
    return f"{e}:{p['version']}" if e not in (None, 0, "0") else str(p["version"])


def nevra(p: Dict[str, object]) -> str:
    return f"{p['name']}-{evr(p)}.{p['arch']}"


def parse_repo_files(files: List[Tuple[str, str]]) -> List[Dict[str, object]]:
    """Parse /etc/yum.repos.d/*.repo and /etc/zypp/repos.d/*.repo (INI)."""
    repos = []
    for path, text in files:
        cp = configparser.RawConfigParser(strict=False)
        try:
            cp.read_string(text, source=path)
        except configparser.Error as exc:
            warn(f"cannot parse {path}: {exc}")
            continue
        for sect in cp.sections():
            get = lambda k: cp.get(sect, k, fallback="").strip()
            enabled = get("enabled") or "1"
            if enabled.lower() in ("0", "false", "no"):
                continue
            r: Dict[str, object] = {"id": sect, "file": os.path.basename(path)}
            for key, field in (("name", "name"), ("baseurl", "baseurl"), ("metalink", "metalink"),
                               ("mirrorlist", "mirrorlist"), ("gpgkey", "gpgkey"), ("gpgcheck", "gpgcheck"),
                               ("type", "type")):
                v = get(key)
                if v:
                    r[field] = " ".join(v.split())
            repos.append(r)
    return sorted(repos, key=lambda r: str(r["id"]))


class Rpm(Manager):
    name = "rpm"

    def available(self) -> bool:
        # Debian can have rpm installed as a tool; only claim the system if
        # an RPM frontend is present too.
        return bool(which("rpm")) and bool(self.frontend())

    def frontend(self) -> Optional[str]:
        for f in ("dnf5", "dnf", "yum", "zypper", "microdnf"):
            if which(f):
                return f
        return None

    def arch_of(self, canonical: str) -> str:
        return RPM_ARCH.get(canonical, canonical)

    def key_of(self, pkg, plat) -> str:
        native = self.arch_of(str(plat.get("arch")))
        if pkg.get("arch") in (native, NOARCH, ""):
            return str(pkg["name"])
        return f"{pkg['name']}.{pkg['arch']}"

    def _qa(self) -> List[Dict[str, object]]:
        qf = "\\t".join("%{" + f + "}" for f in _QF_FIELDS) + "\\n"
        return parse_rpm_qa(run(["rpm", "-qa", "--qf", qf]))

    def _user_installed(self, fe: Optional[str]) -> Optional[Set[str]]:
        """Names (name.arch) the user asked for, or None if unknown."""
        if fe in ("dnf5", "dnf"):
            out = run([fe, "-q", "repoquery", "--userinstalled", "--qf", "%{name}.%{arch}\\n"], check=False)
            names = set(split_lines(out))
            return names or None
        if fe == "zypper":
            path = "/var/lib/zypp/AutoInstalled"
            if os.path.exists(path):
                auto = {ln.strip() for ln in read_text(path).splitlines() if ln.strip() and not ln.startswith("#")}
                return {"!auto:" + a for a in auto}  # marker: inverted list
        return None

    def installed(self, plat):
        pkgs = self._qa()
        user = self._user_installed(self.frontend())
        for p in pkgs:
            p["reason"] = _reason(p, user)
        return pkgs

    def _deps(self, pkgs: List[Dict[str, object]], plat) -> None:
        sep = "\x1f"
        qf = f"[%{{NAME}}.%{{ARCH}}{sep}P{sep}%{{PROVIDENAME}}\\n][%{{NAME}}.%{{ARCH}}{sep}R{sep}%{{REQUIRENAME}}\\n]"
        out = run(["rpm", "-qa", "--qf", qf], check=False)
        by_na = {f"{p['name']}.{p['arch']}": self.key_of(p, plat) for p in pkgs}
        requires: Dict[str, List[List[str]]] = {}
        provides: Dict[str, Set[str]] = {}
        files: Set[str] = set()
        for line in out.splitlines():
            parts = line.split(sep)
            if len(parts) != 3 or parts[0] not in by_na:
                continue
            k = by_na[parts[0]]
            if parts[1] == "P":
                provides.setdefault(k, set()).add(parts[2])
            elif not parts[2].startswith("rpmlib("):
                requires.setdefault(k, []).append([parts[2]])
                if parts[2].startswith("/"):
                    files.add(parts[2])
        # File requirements (/bin/sh) are satisfied by whoever owns the file.
        # One pass over the file database; `rpm -qf` on many paths cannot be
        # matched back reliably when a file has several owners.
        if files:
            out = run(["rpm", "-qa", "--qf", f"[%{{NAME}}.%{{ARCH}}{sep}%{{FILENAMES}}\\n]"], check=False)
            for line in out.splitlines():
                owner, _, path = line.partition(sep)
                if path in files and owner in by_na:
                    provides.setdefault(by_na[owner], set()).add(path)
        resolve_dependencies(pkgs, requires, provides, key_of=lambda p: self.key_of(p, plat))  # type: ignore[arg-type]

    def _from_repo(self, fe: Optional[str]) -> Dict[str, str]:
        if fe not in ("dnf5", "dnf"):
            return {}
        out = run([fe, "-q", "repoquery", "--installed", "--qf", "%{name}.%{arch}|%{from_repo}\\n"], check=False)
        res = {}
        for line in split_lines(out):
            na, _, repo = line.partition("|")
            if repo and repo not in ("@System", "<unknown>", "(none)"):
                res[na] = repo.lstrip("@")
        return res

    def capture(self, plat, opts):
        fe = self.frontend()
        pkgs = self._qa()
        user = self._user_installed(fe)
        if user is None:
            warn(f"{fe or 'rpm'}: cannot tell user-installed from dependency packages; all are recorded as manual")
        self._deps(pkgs, plat)
        from_repo = self._from_repo(fe)
        for p in pkgs:
            p["reason"] = _reason(p, user)
            repo = from_repo.get(f"{p['name']}.{p['arch']}")
            if repo:
                p["repositories"] = [repo]
            if not opts.licenses:
                p.pop("licenses", None)
        files = []
        for pattern in ("/etc/yum.repos.d/*.repo", "/etc/zypp/repos.d/*.repo", "/etc/distro.repos.d/*.repo"):
            for path in sorted(glob.glob(pattern)):
                files.append((path, read_text(path)))
        pkgs.sort(key=lambda p: (str(p["name"]), str(p["arch"])))
        return {"tool": f"{fe} / " + run(["rpm", "--version"], check=False).strip(),
                "frontend": fe, "repositories": parse_repo_files(files), "packages": pkgs}

    # ----------------------------------------------------------------- apply

    def _translate(self, section, src_plat, dst_plat):
        src, dst = self.arch_of(str(src_plat["arch"])), self.arch_of(str(dst_plat["arch"]))
        out = []
        for p in section.get("packages", []):
            q = dict(p)
            if q.get("arch") == src and src != dst:
                q["arch"] = dst
                q["_crossArch"] = True
            out.append(q)
        return out

    def prepare(self, section, src_plat, dst_plat, opts):
        plan = Plan("rpm (prepare)")
        fe = self.frontend()
        if opts.add_repos:
            have = {str(r["id"]) for r in parse_repo_files(
                [(p, read_text(p)) for pat in ("/etc/yum.repos.d/*.repo", "/etc/zypp/repos.d/*.repo")
                 for p in sorted(glob.glob(pat))])}
            repodir = "/etc/zypp/repos.d" if fe == "zypper" else "/etc/yum.repos.d"
            for r in section.get("repositories", []):
                if r["id"] in have:
                    continue
                lines = [f"[{r['id']}]", "enabled=1"]
                for k in ("name", "baseurl", "metalink", "mirrorlist", "gpgkey", "gpgcheck", "type"):
                    if r.get(k):
                        lines.append(f"{k}={r[k]}")
                plan.add(Step(comment=f"add repository {r['id']}",
                              write={"path": f"{repodir}/syslock-{r['id']}.repo", "content": "\n".join(lines)}))
        if opts.refresh:
            if fe == "zypper":
                plan.add(Step(["zypper", "--non-interactive", "refresh"], comment="refresh repositories"))
            elif fe:
                plan.add(Step([fe, "-y", "makecache"], comment="refresh repositories"))
        return plan

    def _available(self, fe: str, nevras: List[str]) -> Set[str]:
        if fe not in ("dnf5", "dnf") or not nevras:
            return set(nevras)  # cannot check cheaply; let the frontend decide
        avail: Set[str] = set()
        for argv in batch_args([fe, "-q", "repoquery", "--qf", "%{name}-%{evr}.%{arch}\\n"], nevras):
            avail.update(split_lines(run(argv, check=False)))
        # repoquery prints EVR without a zero epoch; normalise both sides.
        return {re.sub(r"-0:", "-", a) for a in avail}

    def plan(self, section, src_plat, dst_plat, opts):
        plan = Plan("rpm")
        fe = self.frontend()
        if not fe:
            raise SyslockError("no rpm frontend (dnf5/dnf/yum/zypper) found")
        pkgs = self._translate(section, src_plat, dst_plat)
        if opts.roots_only:
            pkgs = [p for p in pkgs if p.get("reason") == "manual"]
        current = {self.key_of(p, dst_plat): p for p in self.installed(dst_plat)}

        installs, downgrades, local = [], [], []
        todo = [p for p in pkgs if evr(current.get(self.key_of(p, dst_plat), {"version": ""})) != evr(p)
                or self.key_of(p, dst_plat) not in current]
        available = self._available(fe, [nevra(p) for p in todo])
        is_fedora = str(dst_plat.get("distro")) == "fedora"
        for p in todo:
            spec = nevra(p)
            if spec not in available:
                src = (p.get("source") or {}).get("name") or p["name"]
                ver, rel = str(p["version"]).rsplit("-", 1)
                if opts.snapshot and is_fedora and p.get("payloadDigest") and not p.get("_crossArch"):
                    dest = os.path.join(opts.cache_dir, "rpm", f"{p['name']}-{p['version']}.{p['arch']}.rpm")
                    plan.add(Step(comment=f"{spec} is gone from the mirrors; fetching from Koji",
                                  fetch={"url": KOJI.format(src=src, version=ver, release=rel, arch=p["arch"], name=p["name"]),
                                         "dest": dest, "check": "rpm-payload", "digest": str(p["payloadDigest"])}))
                    local.append(dest)
                    continue
                if opts.best_effort:
                    plan.warnings.append(f"{spec} not available; installing newest {p['name']}")
                    installs.append(f"{p['name']}.{p['arch']}")
                else:
                    plan.unresolved.append(f"{spec} (not in any enabled repository)")
                continue
            cur = current.get(self.key_of(p, dst_plat))
            (downgrades if cur and _newer(cur, p) else installs).append(spec)

        if fe == "zypper":
            specs = [s for s in installs + downgrades]
            zspecs = [_zypper_spec(s, pkgs) for s in specs] + local
            if zspecs:
                plan.add(Step(["zypper", "--non-interactive", "install", "--oldpackage", "--force-resolution"] + zspecs,
                              comment=f"install {len(zspecs)} package(s) at locked versions"))
        else:
            y = [fe, "-y"]
            if installs or local:
                plan.add(Step(y + ["install", "--allowerasing"] + installs + local,
                              comment=f"install/upgrade {len(installs) + len(local)} package(s) at locked versions"))
            if downgrades:
                plan.add(Step(y + ["downgrade", "--allowerasing"] + downgrades,
                              comment=f"downgrade {len(downgrades)} package(s) to locked versions"))
            if fe in ("dnf5", "dnf"):
                touched = {nevra(p) for p in todo}

                def needs(p, reason):
                    cur = current.get(self.key_of(p, dst_plat), {}).get("reason")
                    return nevra(p) in touched or cur != reason

                manual = sorted(f"{p['name']}.{p['arch']}" for p in pkgs if p.get("reason") == "manual" and needs(p, "manual"))
                auto = sorted(f"{p['name']}.{p['arch']}" for p in pkgs if p.get("reason") != "manual" and needs(p, "dependency"))
                user_cmd, dep_cmd = (["mark", "user"], ["mark", "dependency"]) if fe == "dnf5" else (["mark", "install"], ["mark", "remove"])
                if manual:
                    plan.add(Step(y + user_cmd + manual, comment="restore user-installed marks"))
                if auto and not opts.roots_only:
                    plan.add(Step(y + dep_cmd + auto, comment="restore dependency marks"))

        if opts.prune:
            locked = {self.key_of(p, dst_plat) for p in self._translate(section, src_plat, dst_plat)}
            protected = {"rpm", "dnf", "dnf5", "yum", "zypper", "systemd", "glibc", "kernel", "kernel-core", "filesystem", "setup"}
            extra = sorted(f"{p['name']}.{p['arch']}" for k, p in current.items() if k not in locked and p["name"] not in protected)
            if extra:
                cmd = ["zypper", "--non-interactive", "remove"] if fe == "zypper" else [fe, "-y", "remove"]
                plan.add(Step(cmd + extra, comment=f"remove {len(extra)} package(s) not in the lock"))
        plan.summary = {"install": len(installs) + len(local), "downgrade": len(downgrades),
                        "unchanged": len(pkgs) - len(todo), "unresolved": len(plan.unresolved)}
        return plan


def _reason(p, user: Optional[Set[str]]) -> str:
    if user is None:
        return "manual"
    na = f"{p['name']}.{p['arch']}"
    if any(u.startswith("!auto:") for u in user):
        return "dependency" if ("!auto:" + str(p["name"])) in user else "manual"
    return "manual" if na in user or p["name"] in user else "dependency"


def _vercmp_key(s: str):
    """Rough rpmvercmp: split into numeric/alpha runs. Only used to decide
    between `install` and `downgrade`; the frontend does the real work."""
    return [(0, int(x)) if x.isdigit() else (1, x) for x in re.findall(r"\d+|[A-Za-z]+", s)]


def _newer(a, b) -> bool:
    ea, eb = int(a.get("epoch") or 0), int(b.get("epoch") or 0)
    if ea != eb:
        return ea > eb
    return _vercmp_key(str(a["version"])) > _vercmp_key(str(b["version"]))


def _zypper_spec(spec: str, pkgs) -> str:
    """dnf style NEVRA -> zypper 'name.arch=evr'."""
    for p in pkgs:
        if nevra(p) == spec:
            return f"{p['name']}.{p['arch']}={evr(p)}"
    return spec
