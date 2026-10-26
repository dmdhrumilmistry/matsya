"""Homebrew (macOS and Linux) backend.

Homebrew is the odd one out: there is no repository of old versions, only
the current formula definition. What we can do:

* record exact versions plus the bottle sha256 for that version (Homebrew
  reports the bottle of the platform it runs on; older releases report every
  platform, which is kept when present);
* reinstall the same version when it is still current;
* otherwise reconstruct it with `brew extract` from homebrew-core's git
  history into a local tap (usually builds from source).
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

from ..util import SyslockError, run, warn, which
from .base import Manager, Plan, Step, is_root

PIN_TAP = "syslock/pins"
OFFICIAL_TAPS = {"homebrew/core", "homebrew/cask"}


def pkg_version(f: Dict[str, object]) -> str:
    """The version brew would install now: stable + _revision."""
    stable = str((f.get("versions") or {}).get("stable") or "")  # type: ignore[union-attr]
    rev = int(f.get("revision") or 0)  # type: ignore[arg-type]
    return f"{stable}_{rev}" if rev else stable


def parse_info(data: Dict[str, object]) -> List[Dict[str, object]]:
    """Turn `brew info --json=v2 --installed` into lock entries."""
    pkgs: List[Dict[str, object]] = []
    for f in data.get("formulae", []) or []:  # type: ignore[union-attr]
        inst = f.get("installed") or []
        if not inst:
            continue
        # Several kegs can be installed; the linked one is what is in use.
        keg = next((i for i in inst if i.get("version") == f.get("linked_keg")), inst[-1])
        p: Dict[str, object] = {
            "name": f["full_name"],
            "kind": "formula",
            "version": keg["version"],
            "tap": f.get("tap") or "homebrew/core",
            "reason": "manual" if keg.get("installed_on_request") else "dependency",
        }
        if f.get("pinned"):
            p["pinned"] = True
        if f.get("license"):
            p["licenses"] = [f["license"]]
        if not keg.get("poured_from_bottle"):
            p["builtFromSource"] = True
        if len(inst) > 1:
            p["otherKegs"] = sorted(i["version"] for i in inst if i is not keg)
        deps = sorted({d["full_name"] for d in keg.get("runtime_dependencies") or []})
        if deps:
            p["dependencies"] = deps
        if keg["version"] == pkg_version(f):
            files = (((f.get("bottle") or {}).get("stable") or {}).get("files") or {})
            bottles = {tag: v["sha256"] for tag, v in files.items() if v.get("sha256")}
            if bottles:
                p["bottles"] = dict(sorted(bottles.items()))  # tag -> sha256
        else:
            # The formula has moved on; bottle hashes would describe another version.
            p["outdated"] = True
        pkgs.append(p)
    for c in data.get("casks", []) or []:  # type: ignore[union-attr]
        if not c.get("installed"):
            continue
        p = {
            "name": c.get("full_token") or c["token"],
            "kind": "cask",
            "version": c["installed"],
            "tap": c.get("tap") or "homebrew/cask",
            "reason": "manual",
        }
        if c.get("installed") == c.get("version") and c.get("sha256") and c.get("sha256") != "no_check":
            p["sha256"] = c["sha256"]
            if c.get("url"):
                p["url"] = c["url"]
        if c.get("auto_updates"):
            # The app updates itself; the installed version can drift
            # without brew noticing.
            p["autoUpdates"] = True
        pkgs.append(p)
    pkgs.sort(key=lambda p: (str(p["kind"]), str(p["name"])))
    return pkgs


def bottle_tag(plat: Dict[str, object]) -> str:
    """macos 15 aarch64 -> arm64_sequoia; linux x86_64 -> x86_64_linux"""
    arch = plat.get("arch")
    if plat.get("os") == "macos":
        name = str(plat.get("codename") or "")
        return f"arm64_{name}" if arch == "aarch64" else name
    return "arm64_linux" if arch == "aarch64" else "x86_64_linux"


class Brew(Manager):
    name = "brew"

    def available(self) -> bool:
        return bool(which("brew"))

    def key_of(self, pkg, plat) -> str:
        if pkg.get("kind") == "cask":
            return f"cask:{pkg['name']}"
        name = str(pkg["name"])
        if name.startswith(PIN_TAP + "/"):
            # syslock/pins/foo@1.2 is our `brew extract` of foo 1.2.
            name = name[len(PIN_TAP) + 1:].rsplit("@", 1)[0]
        return name

    def _info_installed(self) -> Dict[str, object]:
        if is_root():
            raise SyslockError("Homebrew refuses to run as root; run `syslock lock --managers brew` as your normal user")
        return json.loads(run(["brew", "info", "--json=v2", "--installed"]) or "{}")

    def installed(self, plat):
        return parse_info(self._info_installed())

    def capture(self, plat, opts):
        pkgs = parse_info(self._info_installed())
        if not opts.licenses:
            for p in pkgs:
                p.pop("licenses", None)
        outdated = [p["name"] for p in pkgs if p.get("outdated")]
        if outdated:
            warn(f"{len(outdated)} Homebrew formula(e) are older than their current formula, so their bottle "
                 f"checksums are not recorded: {', '.join(map(str, outdated[:10]))}")
        taps = []
        try:
            for t in json.loads(run(["brew", "tap-info", "--json", "--installed"]) or "[]"):
                rec: Dict[str, object] = {"name": t["name"]}
                if t.get("remote"):
                    rec["remote"] = t["remote"]
                if t.get("custom_remote"):
                    rec["customRemote"] = True
                if t.get("path") and os.path.isdir(os.path.join(t["path"], ".git")):
                    head = run(["git", "-C", t["path"], "rev-parse", "HEAD"], check=False).strip()
                    if head:
                        rec["commit"] = head
                taps.append(rec)
        except (ValueError, SyslockError) as exc:
            warn(f"could not read Homebrew taps: {exc}")
        version = run(["brew", "--version"], check=False).splitlines()
        return {"tool": version[0] if version else "", "prefix": run(["brew", "--prefix"], check=False).strip(),
                "taps": sorted(taps, key=lambda t: str(t["name"])), "packages": pkgs}

    # ----------------------------------------------------------------- apply

    def prepare(self, section, src_plat, dst_plat, opts):
        plan = Plan("brew (prepare)")
        have = set(run(["brew", "tap"], check=False).split()) if which("brew") else set()
        for t in section.get("taps", []):
            name = str(t["name"])
            if name in OFFICIAL_TAPS or name == PIN_TAP or name in have:
                continue
            argv = ["brew", "tap", name]
            if t.get("customRemote") and t.get("remote"):
                argv.append(str(t["remote"]))
            plan.add(Step(argv, comment=f"tap {name}"))
        if opts.refresh:
            plan.add(Step(["brew", "update"], comment="refresh Homebrew metadata"))
        return plan

    def _current(self, names: List[str], cask: bool) -> Dict[str, Dict[str, object]]:
        """What brew would install right now for each name."""
        if not names:
            return {}
        flag = "--cask" if cask else "--formula"
        res: Dict[str, Dict[str, object]] = {}

        def query(batch: List[str]) -> Optional[Dict[str, object]]:
            out = run(["brew", "info", "--json=v2", flag] + batch, check=False)
            try:
                return json.loads(out) if out.strip() else None
            except ValueError:
                return None

        data = query(names)
        batches = [data] if data else [query([n]) for n in names]  # one unknown name fails the batch
        for d in batches:
            if not d:
                continue
            for f in d.get("formulae", []) or []:
                res[f["full_name"]] = {"version": pkg_version(f), "installed": [i["version"] for i in f.get("installed") or []]}
            for c in d.get("casks", []) or []:
                res[c.get("full_token") or c["token"]] = {"version": c.get("version"), "installed": [c.get("installed")] if c.get("installed") else []}
        return res

    def plan(self, section, src_plat, dst_plat, opts):
        plan = Plan("brew")
        if is_root():
            raise SyslockError("Homebrew refuses to run as root; apply the brew part as your normal user "
                               "(syslock apply --managers brew)")
        pkgs = section.get("packages", [])
        formulae = [p for p in pkgs if p.get("kind") == "formula" and p.get("reason") == "manual"]
        casks = [p for p in pkgs if p.get("kind") == "cask"]
        cur_f = self._current([str(p["name"]) for p in formulae], cask=False)
        cur_c = self._current([str(p["name"]) for p in casks], cask=True)

        current = {self.key_of(p, dst_plat): p for p in self.installed(dst_plat)}
        install, extract, cask_install, pins = [], [], [], []
        for p in formulae:
            name, ver = str(p["name"]), str(p["version"])
            cur = cur_f.get(name)
            have = current.get(self.key_of(p, dst_plat))
            target = None  # the formula name that ends up providing it
            extracted = bool(have) and str(have["name"]).startswith(PIN_TAP + "/")
            if have and (str(have["version"]) == ver or (extracted and _plain(str(have["version"])) == _plain(ver))):
                target = str(have["name"])
            elif cur and ver in cur["installed"]:
                target = name
            elif cur and cur["version"] == ver:
                install.append(name)
                target = name
            elif cur and opts.snapshot:
                extract.append((name, ver))
                target = f"{PIN_TAP}/{name.rsplit('/', 1)[-1]}@{_plain(ver)}"
            elif opts.best_effort:
                plan.warnings.append(f"{name} {ver} unavailable; installing current version")
                install.append(name)
                target = name
            else:
                plan.unresolved.append(f"{name}@{ver} ({'formula not found' if not cur else 'version is no longer current'})")
            if p.get("pinned") and target and not (have and have.get("pinned")):
                pins.append(target)
        for p in casks:
            name, ver = str(p["name"]), str(p["version"])
            cur = cur_c.get(name)
            if cur and ver in cur["installed"]:
                continue
            if cur and (cur["version"] == ver or opts.best_effort):
                if cur["version"] != ver:
                    plan.warnings.append(f"cask {name}: locked {ver}, installing {cur['version']} (casks cannot be pinned)")
                cask_install.append(name)
            else:
                plan.unresolved.append(f"cask {name}@{ver} (Homebrew cannot install old cask versions)")

        if install:
            plan.add(Step(["brew", "install", "--formula"] + sorted(install), comment=f"install {len(install)} formula(e)"))
        if extract:
            plan.warnings.append("older formula versions are rebuilt from homebrew-core history with `brew extract`; "
                                 "this needs a full homebrew/core clone and usually compiles from source")
            plan.add(Step(["sh", "-c", f"brew tap | grep -qx {PIN_TAP} || brew tap-new --no-git {PIN_TAP}"],
                          comment="local tap for extracted versions"))
            plan.add(Step(["sh", "-c", "brew tap | grep -qx homebrew/core || brew tap --force homebrew/core"],
                          comment="homebrew-core history is needed for brew extract",
                          env={"HOMEBREW_NO_INSTALL_FROM_API": "1"}))
            for name, ver in extract:
                plain = _plain(ver)
                short = name.rsplit("/", 1)[-1]
                plan.add(Step(["brew", "extract", "--force", f"--version={plain}", name, PIN_TAP],
                              comment=f"recreate {name} {ver}"))
                plan.add(Step(["brew", "install", f"{PIN_TAP}/{short}@{plain}"]))
        if cask_install:
            plan.add(Step(["brew", "install", "--cask"] + sorted(cask_install), comment=f"install {len(cask_install)} cask(s)"))
        if pins:
            plan.add(Step(["brew", "pin"] + sorted(pins), comment="restore pins"))
        if opts.prune:
            locked = {self.key_of(p, dst_plat) for p in pkgs}
            extra = sorted(str(p["name"]) for k, p in current.items()
                           if p.get("reason") == "manual" and k not in locked)
            if extra:
                plan.add(Step(["brew", "uninstall"] + extra, comment=f"remove {len(extra)} package(s) not in the lock"))
                plan.add(Step(["brew", "autoremove"], comment="remove orphaned dependencies"))
        dep_note = [p for p in pkgs if p.get("kind") == "formula" and p.get("reason") != "manual"]
        if dep_note:
            plan.warnings.append(f"{len(dep_note)} dependency formula(e) are installed at whatever version their "
                                 "dependants need; `syslock check` reports any drift afterwards")
        plan.summary = {"install": len(install) + len(extract) + len(cask_install), "unresolved": len(plan.unresolved)}
        return plan

    def export_brewfile(self, section: Dict[str, object]) -> str:
        lines = []
        for t in section.get("taps", []):  # type: ignore[union-attr]
            if t["name"] not in OFFICIAL_TAPS:
                lines.append(f'tap "{t["name"]}"' + (f', "{t["remote"]}"' if t.get("customRemote") else ""))
        for p in section.get("packages", []):  # type: ignore[union-attr]
            if p.get("kind") == "formula" and p.get("reason") == "manual":
                lines.append(f'brew "{p["name"]}"  # {p["version"]}' + (" (pinned)" if p.get("pinned") else ""))
        for p in section.get("packages", []):  # type: ignore[union-attr]
            if p.get("kind") == "cask":
                lines.append(f'cask "{p["name"]}"  # {p["version"]}')
        return "\n".join(lines) + "\n"


def _plain(version: str) -> str:
    """1.2.3_1 -> 1.2.3 (drop the Homebrew revision suffix)."""
    return version.rsplit("_", 1)[0]
