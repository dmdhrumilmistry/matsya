"""Debian / Ubuntu (dpkg + apt) backend."""

from __future__ import annotations

import base64
import datetime as _dt
import glob
import os
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..util import SyslockError, parse_deb822, read_text, run, sha256_file, warn, which
from .base import Manager, Options, Plan, Step, resolve_dependencies

DEB_ARCH = {
    "x86_64": "amd64",
    "aarch64": "arm64",
    "armv7": "armhf",
    "armv6": "armel",
    "i686": "i386",
    "ppc64le": "ppc64el",
    "s390x": "s390x",
    "riscv64": "riscv64",
    "loongarch64": "loong64",
    "mips64el": "mips64el",
}

# Debian and Ubuntu keep every package ever published in a time-indexed
# archive. Pool paths are stable, so a Filename from the index plus the
# capture time is enough to fetch the exact .deb years later.
SNAPSHOT_BASES = {
    "Debian": "https://snapshot.debian.org/archive/{archive}/{ts}/",
    "Ubuntu": "https://snapshot.ubuntu.com/{archive}/{ts}/",
}

_DPKG_FIELDS = [
    "db:Status-Abbrev", "Package", "Architecture", "Version", "source:Package",
    "source:Version", "Essential", "Priority", "Pre-Depends", "Depends", "Provides",
]

_VERSION_CONSTRAINT = re.compile(r"\s*\(.*?\)|\s*\[.*?\]|\s*<.*?>")


def parse_dpkg_query(out: str) -> Tuple[List[Dict[str, object]], List[str]]:
    """Parse the tab separated output of our dpkg-query format.
    Returns (installed packages, warnings about broken packages)."""
    pkgs: List[Dict[str, object]] = []
    problems: List[str] = []
    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) < len(_DPKG_FIELDS):
            continue
        status, name, arch, version, src, srcver, essential, prio, predeps, deps, provides = cols[: len(_DPKG_FIELDS)]
        status = status.strip()
        if len(status) < 2:
            continue
        # Abbrev is desired/state/error: "ii", "hi", "rc", "iU", "iF", "iH" ...
        if status[1] != "i":
            if status[1] in "UFHWt":
                problems.append(f"{name}:{arch} is in a broken dpkg state ({status}); it is not locked")
            continue
        if len(status) > 2 and status[2] == "R":
            problems.append(f"{name}:{arch} needs reinstallation; locked anyway")
        p: Dict[str, object] = {"name": name, "version": version, "arch": arch}
        if status[0] == "h":
            p["held"] = True
        if essential == "yes":
            p["essential"] = True
        if prio:
            p["priority"] = prio
        if src and (src != name or srcver != version):
            p["source"] = {"name": src, "version": srcver or version}
        p["_requires"] = parse_relations(", ".join(x for x in (predeps, deps) if x))
        p["_provides"] = [g[0] for g in parse_relations(provides)]
        pkgs.append(p)
    return pkgs, problems


def parse_relations(text: str) -> List[List[str]]:
    """'a (>= 1) | b:any, c [amd64]' -> [['a', 'b'], ['c']]"""
    groups: List[List[str]] = []
    for clause in text.split(","):
        clause = clause.strip()
        if not clause:
            continue
        alts = []
        for alt in clause.split("|"):
            alt = _VERSION_CONSTRAINT.sub("", alt).strip()
            if not alt:
                continue
            alts.append(alt.split(":")[0])
        if alts:
            groups.append(alts)
    return groups


def scan_packages_index(text: str, wanted: Set[Tuple[str, str, str]]) -> Dict[Tuple[str, str, str], Dict[str, object]]:
    """Pull integrity data for (name, arch, version) triples out of an apt
    Packages index without materialising every stanza (indexes are large)."""
    found: Dict[Tuple[str, str, str], Dict[str, object]] = {}
    cur: Dict[str, str] = {}

    def flush() -> None:
        if not cur:
            return
        key = (cur.get("Package", ""), cur.get("Architecture", ""), cur.get("Version", ""))
        if key in wanted and key not in found:
            entry: Dict[str, object] = {}
            if "SHA256" in cur:
                entry["sha256"] = cur["SHA256"]
            if "Size" in cur and cur["Size"].isdigit():
                entry["size"] = int(cur["Size"])
            if "Filename" in cur:
                entry["filename"] = cur["Filename"]
            found[key] = entry

    for line in text.splitlines():
        if not line:
            flush()
            cur = {}
            continue
        if line[0] in " \t":
            continue
        k, _, v = line.partition(":")
        if k in ("Package", "Architecture", "Version", "SHA256", "Size", "Filename"):
            cur[k] = v.strip()
    flush()
    return found


def parse_policy(out: str) -> Dict[Tuple[str, str, str], Dict[str, str]]:
    """Map (uri, archive/suite, component) -> release attributes from
    `apt-cache policy` (o=Origin, l=Label, a=Suite, n=Codename, v=Version)."""
    res: Dict[Tuple[str, str, str], Dict[str, str]] = {}
    last_uri: Optional[str] = None
    for line in out.splitlines():
        s = line.strip()
        m = re.match(r"^-?\d+\s+(\S+)\s+(\S+)", s)
        if m and "://" in m.group(1):
            last_uri = m.group(1).rstrip("/")
            continue
        if s.startswith("release ") and last_uri:
            attrs = {}
            for part in s[len("release "):].split(","):
                k, _, v = part.partition("=")
                attrs[k.strip()] = v.strip()
            for suite in {attrs.get("a", ""), attrs.get("n", "")} - {""}:
                res[(last_uri, suite, attrs.get("c", ""))] = attrs
            last_uri = None
    return res


def parse_sources(files: Iterable[Tuple[str, str]]) -> List[Dict[str, object]]:
    """Parse one-line (.list) and deb822 (.sources) entries.
    files: (path, text). Returns entries with uri/suite/components/options."""
    entries: List[Dict[str, object]] = []
    for path, text in files:
        if path.endswith(".sources"):
            for st in parse_deb822(text):
                if st.get("Enabled", "yes").lower() == "no":
                    continue
                if "deb" not in st.get("Types", "").split():
                    continue
                signed = st.get("Signed-By", "")
                for uri in st.get("URIs", "").split():
                    for suite in st.get("Suites", "").split():
                        entries.append({
                            "uri": uri.rstrip("/"),
                            "suite": suite,
                            "components": st.get("Components", "").split(),
                            "signedBy": signed,
                            "trusted": st.get("Trusted", "").lower() == "yes",
                            "file": path,
                        })
            continue
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line.startswith("deb "):
                continue
            rest = line[4:].strip()
            opts: Dict[str, str] = {}
            if rest.startswith("["):
                optstr, _, rest = rest[1:].partition("]")
                for o in optstr.split():
                    k, _, v = o.partition("=")
                    opts[k] = v
            parts = rest.split()
            if len(parts) < 2:
                continue
            entries.append({
                "uri": parts[0].rstrip("/"),
                "suite": parts[1],
                "components": parts[2:],
                "signedBy": opts.get("signed-by", ""),
                "trusted": opts.get("trusted", "") == "yes",
                "file": path,
            })
    return entries


def dep5_licenses(text: str) -> List[str]:
    """Licenses from a machine-readable debian/copyright file."""
    if not text.startswith("Format:"):
        return []
    lic: Set[str] = set()
    for st in parse_deb822(text):
        v = st.get("License", "").split("\n", 1)[0].strip()
        if v and "Files" in st:
            lic.add(v)
    return sorted(lic)


class Apt(Manager):
    name = "apt"

    def available(self) -> bool:
        return bool(which("dpkg-query"))

    def arch_of(self, canonical: str) -> str:
        return DEB_ARCH.get(canonical, canonical)

    def key_of(self, pkg, plat) -> str:
        native = self.arch_of(str(plat.get("arch")))
        if pkg.get("arch") in (native, "all", ""):
            return str(pkg["name"])
        return f"{pkg['name']}:{pkg['arch']}"

    # ------------------------------------------------------------------ read

    def _dpkg(self) -> Tuple[List[Dict[str, object]], List[str]]:
        fmt = "\\t".join("${%s}" % f for f in _DPKG_FIELDS) + "\\n"
        return parse_dpkg_query(run(["dpkg-query", "-W", "-f", fmt]))

    def _manual(self) -> Optional[Set[str]]:
        if not which("apt-mark"):
            return None
        return set(run(["apt-mark", "showmanual"], check=False).split())

    def installed(self, plat):
        pkgs, _ = self._dpkg()
        manual = self._manual()
        native = self.arch_of(str(plat["arch"]))
        for p in pkgs:
            p.pop("_requires", None)
            p.pop("_provides", None)
            p["reason"] = _reason(p, manual, native)
        return pkgs

    def _index_targets(self) -> List[Dict[str, str]]:
        if not which("apt-get"):
            return []
        fmt = "$(FILENAME)\t$(REPO_URI)\t$(RELEASE)\t$(COMPONENT)\t$(ARCHITECTURE)\t$(CREATED_BY)"
        out = run(["apt-get", "indextargets", "--format", fmt], check=False)
        res = []
        for line in out.splitlines():
            cols = line.split("\t")
            if len(cols) != 6 or cols[5] != "Packages":
                continue
            if not os.path.exists(cols[0]):
                continue
            res.append({"file": cols[0], "uri": cols[1].rstrip("/"), "suite": cols[2],
                        "component": cols[3], "arch": cols[4]})
        return res

    def _cat_index(self, path: str) -> str:
        helper = "/usr/lib/apt/apt-helper"
        if os.path.exists(helper):
            return run([helper, "cat-file", path], check=False)
        return read_text(path)

    def _scan(self, wanted: Set[Tuple[str, str, str]], targets: List[Dict[str, str]]):
        """Returns {(name, arch, version): {"sha256", "size", "filename", "repos": [...]}}"""
        result: Dict[Tuple[str, str, str], Dict[str, object]] = {}
        for t in targets:
            hits = scan_packages_index(self._cat_index(t["file"]), wanted)
            for key, entry in hits.items():
                cur = result.setdefault(key, dict(entry, repos=[]))
                cur["repos"].append(t)  # type: ignore[union-attr]
        return result

    def _repo_records(self, targets: List[Dict[str, str]], opts: Options) -> Tuple[List[Dict[str, object]], Dict[int, str]]:
        policy = parse_policy(run(["apt-cache", "policy"], check=False)) if which("apt-cache") else {}
        files = []
        for p in ["/etc/apt/sources.list"] + sorted(glob.glob("/etc/apt/sources.list.d/*.list")) + \
                sorted(glob.glob("/etc/apt/sources.list.d/*.sources")):
            if os.path.isfile(p):
                files.append((p, read_text(p)))
        sources = parse_sources(files)
        repos: Dict[str, Dict[str, object]] = {}
        id_by_target: Dict[int, str] = {}
        for t in targets:
            rel = policy.get((t["uri"], t["suite"], t["component"]), {})
            origin = rel.get("o", "")
            if origin:
                rid = f"{origin}:{rel.get('a') or t['suite']}/{t['component']}"
            else:
                rid = f"{re.sub(r'^[a-z]+://', '', t['uri'])}:{t['suite']}/{t['component']}"
            id_by_target[id(t)] = rid
            if rid in repos:
                r = repos[rid]
                if t["arch"] not in r["architectures"]:  # type: ignore[operator]
                    r["architectures"].append(t["arch"])  # type: ignore[union-attr]
                if t["uri"] not in r["uris"]:  # type: ignore[operator]
                    r["uris"].append(t["uri"])  # type: ignore[union-attr]
                continue
            r: Dict[str, object] = {"id": rid, "uris": [t["uri"]], "suite": t["suite"],
                                    "component": t["component"], "architectures": [t["arch"]]}
            for k, field in (("o", "origin"), ("l", "label"), ("n", "codename"), ("v", "version")):
                if rel.get(k):
                    r[field] = rel[k]
            date = _release_date(t["file"], t["suite"])
            if date:
                # The archive's own publication time: the right snapshot to
                # ask for, independent of when (or with which clock) we ran.
                r["date"] = date
            src = next((s for s in sources if s["uri"] == t["uri"] and s["suite"] == t["suite"]), None)
            if src:
                if src["trusted"]:
                    r["trusted"] = True
                key = _keyring(str(src["signedBy"]), opts)
                if key:
                    r["signedBy"] = key
            repos[rid] = r
        for r in repos.values():
            r["architectures"] = sorted(r["architectures"])  # type: ignore[arg-type]
            r["uris"] = sorted(r["uris"])  # type: ignore[arg-type]
        return sorted(repos.values(), key=lambda r: str(r["id"])), id_by_target

    def capture(self, plat, opts):
        pkgs, problems = self._dpkg()
        for msg in problems:
            warn(msg)
        manual = self._manual()
        if manual is None:
            warn("apt-mark not found; every package is recorded as manually installed")
        native = self.arch_of(str(plat["arch"]))

        requires = {self.key_of(p, plat): p.pop("_requires") for p in pkgs}
        provides = {self.key_of(p, plat): p.pop("_provides") for p in pkgs}
        resolve_dependencies(pkgs, requires, provides, key_of=lambda p: self.key_of(p, plat))  # type: ignore[arg-type]

        targets = self._index_targets()
        repos, id_by_target = self._repo_records(targets, opts)
        wanted = {(str(p["name"]), str(p["arch"]), str(p["version"])) for p in pkgs}
        found = self._scan(wanted, targets)
        local = []
        for p in pkgs:
            p["reason"] = _reason(p, manual, native)
            hit = found.get((str(p["name"]), str(p["arch"]), str(p["version"])))
            if hit:
                for k in ("sha256", "size", "filename"):
                    if k in hit:
                        p[k] = hit[k]
                p["repositories"] = sorted({id_by_target[id(t)] for t in hit["repos"]})  # type: ignore[union-attr]
            else:
                p["repositories"] = []
                local.append(f"{p['name']}={p['version']}")
            if opts.licenses:
                lic = _licenses_for(str(p["name"]))
                if lic:
                    p["licenses"] = lic
        if local:
            warn(f"{len(local)} apt package(s) are not available from any configured repository "
                 f"(locally installed, removed upstream, or stale indexes - run apt-get update): "
                 + ", ".join(local[:10]) + (" ..." if len(local) > 10 else ""))
        if not targets:
            warn("no apt package indexes found (was /var/lib/apt/lists cleaned?); "
                 "run apt-get update before locking to record checksums")

        pkgs.sort(key=lambda p: (str(p["name"]), str(p["arch"])))
        return {
            "tool": _tool_version(),
            "repositories": repos,
            "foreignArchitectures": sorted(run(["dpkg", "--print-foreign-architectures"], check=False).split()),
            "packages": pkgs,
        }

    # ----------------------------------------------------------------- apply

    def _translate(self, section, src_plat, dst_plat) -> List[Dict[str, object]]:
        """Re-target packages at the destination's native architecture."""
        src_native = self.arch_of(str(src_plat["arch"]))
        dst_native = self.arch_of(str(dst_plat["arch"]))
        out = []
        for p in section.get("packages", []):
            q = dict(p)
            if q.get("arch") == src_native and src_native != dst_native:
                q["arch"] = dst_native
                q["_crossArch"] = True
            out.append(q)
        return out

    def prepare(self, section, src_plat, dst_plat, opts):
        plan = Plan("apt (prepare)")
        dst_native = self.arch_of(str(dst_plat["arch"]))
        pkgs = self._translate(section, src_plat, dst_plat)
        need_foreign = sorted({str(p["arch"]) for p in pkgs} - {dst_native, "all"})
        have_foreign = set(run(["dpkg", "--print-foreign-architectures"], check=False).split()) if which("dpkg") else set()
        for a in need_foreign:
            if a not in have_foreign:
                plan.add(Step(["dpkg", "--add-architecture", a], comment=f"enable multiarch for {a}"))
        if opts.add_repos:
            self._add_repos(plan, section)
        if opts.refresh or plan.steps:
            plan.add(Step(["apt-get", "update"], comment="refresh package indexes"))
        return plan

    def _add_repos(self, plan: Plan, section) -> None:
        """Recreate missing third-party repositories. apt needs one entry per
        (URI, suite) with all components and a single Signed-By, otherwise
        it fails with "Conflicting values set for option Signed-By"."""
        configured = {t["uri"] for t in self._index_targets()}
        groups: Dict[Tuple[str, str], Dict[str, object]] = {}
        for r in section.get("repositories", []):
            key = r.get("signedBy") or {}
            if not key.get("data") or not r.get("uris"):
                continue
            if any(u in configured for u in r["uris"]):
                continue
            g = groups.setdefault((r["uris"][0], r["suite"]), {"components": [], "key": key, "ids": []})
            if r["component"] and r["component"] not in g["components"]:
                g["components"].append(r["component"])  # type: ignore[union-attr]
            g["ids"].append(r["id"])  # type: ignore[union-attr]
        written: Set[str] = set()
        for (uri, suite), g in sorted(groups.items()):
            key: Dict[str, object] = g["key"]  # type: ignore[assignment]
            ext = ".asc" if key.get("armored") else ".gpg"
            kpath = f"/etc/apt/keyrings/syslock-{str(key['sha256'])[:16]}{ext}"
            if kpath not in written:
                written.add(kpath)
                plan.add(Step(comment=f"keyring sha256 {key['sha256']}",
                              write={"path": kpath, "content": str(key["data"]), "mode": "644", "encoding": "base64"}))
            safe = re.sub(r"[^A-Za-z0-9]+", "-", f"{re.sub(r'^[a-z]+://', '', uri)}-{suite}").strip("-").lower()
            comps = " ".join(g["components"])  # type: ignore[arg-type]
            content = f"Types: deb\nURIs: {uri}\nSuites: {suite}\n"
            content += f"Components: {comps}\n" if comps else ""
            content += f"Signed-By: {kpath}\n"
            plan.add(Step(comment="add repository " + ", ".join(g["ids"]),  # type: ignore[arg-type]
                          write={"path": f"/etc/apt/sources.list.d/syslock-{safe}.sources", "content": content}))

    def plan(self, section, src_plat, dst_plat, opts):
        plan = Plan("apt")
        pkgs = self._translate(section, src_plat, dst_plat)
        if opts.roots_only:
            pkgs = [p for p in pkgs if p.get("reason") == "manual"]
        current = {self.key_of(p, dst_plat): p for p in self.installed(dst_plat)}
        todo = [p for p in pkgs if current.get(self.key_of(p, dst_plat), {}).get("version") != p["version"]]

        targets = self._index_targets()
        found = self._scan({(str(p["name"]), str(p["arch"]), str(p["version"])) for p in todo}, targets)
        repos = {r["id"]: r for r in section.get("repositories", [])}
        ts = _snapshot_ts(str(section.get("_capturedAt", "")))
        specs: List[str] = []
        for p in todo:
            name, arch, ver = str(p["name"]), str(p["arch"]), str(p["version"])
            if (name, arch, ver) in found:
                specs.append(f"{name}:{arch}={ver}")
                continue
            urls = []
            if opts.snapshot and p.get("filename") and p.get("sha256") and not p.get("_crossArch"):
                urls = _snapshot_urls(p, repos, ts)
            if urls:
                dest = os.path.join(opts.cache_dir, "apt", os.path.basename(str(p["filename"])))
                plan.add(Step(comment=f"{name} {ver} is gone from the mirrors; fetching from snapshot",
                              fetch={"url": urls[0], "fallbacks": urls[1:], "dest": dest, "sha256": str(p["sha256"])}))
                specs.append(dest)
                continue
            why = "not in any configured repository"
            if p.get("_crossArch"):
                why += f" for {arch} (lock was captured on another architecture)"
            if opts.best_effort:
                plan.warnings.append(f"{name} {ver} {why}; installing the newest available version instead")
                specs.append(f"{name}:{arch}")
            else:
                plan.unresolved.append(f"{name}:{arch}={ver} ({why})")

        env = {"DEBIAN_FRONTEND": "noninteractive"}
        base = ["apt-get", "install", "-y", "--no-install-recommends", "--allow-downgrades",
                "--allow-change-held-packages", "-o", "Dpkg::Options::=--force-confold"]
        if specs:
            # One transaction: apt needs to see the whole closure at once to
            # solve downgrades and replacements consistently.
            plan.add(Step(base + sorted(specs), comment=f"install {len(specs)} package(s) at locked versions", env=env))

        # Only touch marks that differ; anything we just installed was marked
        # manual by apt-get, so it is compared against "not manual yet".
        installed_now = {self.key_of(p, dst_plat) for p in todo}

        def needs(p, reason):
            k = self.key_of(p, dst_plat)
            cur = current.get(k, {}).get("reason")
            return k in installed_now or cur != reason

        manual = sorted(self.key_of(p, dst_plat) for p in pkgs if p.get("reason") == "manual" and needs(p, "manual"))
        auto = sorted(self.key_of(p, dst_plat) for p in pkgs if p.get("reason") != "manual" and needs(p, "dependency"))
        if manual:
            plan.add(Step(["apt-mark", "manual"] + manual, comment="restore manual-install marks"))
        if auto and not opts.roots_only:
            plan.add(Step(["apt-mark", "auto"] + auto, comment="restore automatic-install marks"))
        held = sorted(self.key_of(p, dst_plat) for p in pkgs
                      if p.get("held") and not current.get(self.key_of(p, dst_plat), {}).get("held"))
        if held:
            plan.add(Step(["apt-mark", "hold"] + held, comment="restore holds"))

        if opts.prune:
            locked = {self.key_of(p, dst_plat) for p in self._translate(section, src_plat, dst_plat)}
            extra = sorted(k for k, p in current.items()
                           if k not in locked and not p.get("essential") and p.get("priority") != "required")
            if extra:
                plan.add(Step(["apt-get", "purge", "-y"] + extra, comment=f"remove {len(extra)} package(s) not in the lock", env=env))
        plan.summary = {"install": len(specs), "unchanged": len(pkgs) - len(todo), "unresolved": len(plan.unresolved)}
        return plan


def _reason(p, manual: Optional[Set[str]], native: str) -> str:
    if manual is None:
        return "manual"
    name = str(p["name"])
    if name in manual or (p.get("arch") not in (native, "all") and f"{name}:{p['arch']}" in manual):
        return "manual"
    return "dependency"


def _keyring(signed_by: str, opts: Options) -> Optional[Dict[str, object]]:
    signed_by = signed_by.strip()
    if not signed_by:
        return None
    if signed_by.startswith("-----BEGIN") or "\n" in signed_by:
        # deb822 allows the key inline; the lock is its own source of truth.
        data = signed_by.encode()
        import hashlib

        return {"inline": True, "armored": True, "sha256": hashlib.sha256(data).hexdigest(),
                "data": base64.b64encode(data).decode() if opts.embed_keys else None}
    path = signed_by.split()[0]
    if not os.path.isfile(path):
        # Could also be a fingerprint list; record it verbatim.
        return {"fingerprints": signed_by.split()}
    rec: Dict[str, object] = {"path": path, "sha256": sha256_file(path)}
    owned = run(["dpkg", "-S", path], check=False).strip() if which("dpkg") else ""
    if owned:
        rec["package"] = owned.split(":")[0]
    elif opts.embed_keys:
        # Third-party key: embed it so another machine can trust the same repo.
        with open(path, "rb") as fh:
            raw = fh.read()
        rec["armored"] = raw.lstrip().startswith(b"-----BEGIN")
        rec["data"] = base64.b64encode(raw).decode()
    return rec


_LICENSE_CACHE: Dict[str, List[str]] = {}


def _licenses_for(name: str) -> List[str]:
    if name not in _LICENSE_CACHE:
        path = f"/usr/share/doc/{name}/copyright"
        try:
            _LICENSE_CACHE[name] = dep5_licenses(read_text(path)) if os.path.isfile(path) else []
        except OSError:
            _LICENSE_CACHE[name] = []
    return _LICENSE_CACHE[name]


def _tool_version() -> str:
    out = run(["apt-get", "--version"], check=False) if which("apt-get") else run(["dpkg", "--version"], check=False)
    return out.splitlines()[0].strip() if out else ""


def _snapshot_ts(captured_at: str) -> str:
    """2026-10-26T08:30:00Z -> 20261026T083000Z"""
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", captured_at)
    return "".join(m.groups()[:3]) + "T" + "".join(m.groups()[3:]) + "Z" if m else ""


def _release_date(packages_file: str, suite: str) -> str:
    """Date field of the Release file next to a Packages index, as ISO 8601."""
    if "_dists_" not in packages_file:
        return ""  # flat repository
    base = packages_file[: packages_file.index("_dists_")] + "_dists_" + suite.replace("/", "_")
    for cand in (base + "_InRelease", base + "_Release"):
        if not os.path.exists(cand):
            continue
        for line in read_text(cand).splitlines():
            if line.startswith("Date:"):
                from email.utils import parsedate_to_datetime

                try:
                    d = parsedate_to_datetime(line[5:].strip())
                except (TypeError, ValueError):
                    return ""
                return d.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if line.startswith(("MD5Sum:", "SHA256:", "SHA1:")):
                break  # past the header (InRelease starts with a PGP armor header)
    return ""


def _snapshot_urls(p, repos, ts: str) -> List[str]:
    urls: List[str] = []
    for rid in p.get("repositories", []):
        r = repos.get(rid, {})
        tpl = SNAPSHOT_BASES.get(str(r.get("origin", "")))
        if not tpl:
            continue
        # Prefer the repository's publication time; the capture time is a
        # fallback (it may come from SOURCE_DATE_EPOCH or a merged lock).
        stamps = [x for x in dict.fromkeys([_snapshot_ts(str(r.get("date", ""))), ts]) if x]
        for uri in r.get("uris", []):
            archive = uri.rstrip("/").rsplit("/", 1)[-1]
            names = [archive]
            # Ubuntu mirrors carry ports under /ubuntu on some clouds.
            if archive == "ubuntu":
                names.append("ubuntu-ports")
            elif archive == "ubuntu-ports":
                names.append("ubuntu")
            for stamp in stamps:
                for n in names:
                    u = tpl.format(archive=n, ts=stamp) + str(p["filename"])
                    if u not in urls:
                        urls.append(u)
    return urls
