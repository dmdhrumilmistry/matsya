"""SBOM generation (CycloneDX 1.6 JSON and SPDX 2.3 JSON) from a lock file.

The SBOM is derived from the lock rather than from the live system, so it is
reproducible: the same lock always yields the same SBOM bytes, and the SBOM
can be produced on a machine that never had the packages installed.
"""

from __future__ import annotations

import re
import uuid
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

from . import __version__

# A pragmatic subset of SPDX license ids seen in distro metadata. Anything
# outside it is emitted as a named license (CycloneDX) or LicenseRef (SPDX)
# rather than guessed.
SPDX_IDS = set("""
0BSD AFL-2.1 AGPL-3.0-only AGPL-3.0-or-later Apache-1.1 Apache-2.0 Artistic-1.0 Artistic-1.0-Perl
Artistic-2.0 BSD-1-Clause BSD-2-Clause BSD-3-Clause BSD-4-Clause BSL-1.0 CC-BY-3.0 CC-BY-4.0
CC-BY-SA-3.0 CC-BY-SA-4.0 CC0-1.0 CDDL-1.0 CDDL-1.1 CPL-1.0 curl EPL-1.0 EPL-2.0 EUPL-1.2 FSFAP
FTL GFDL-1.1-or-later GFDL-1.2-or-later GFDL-1.3-only GFDL-1.3-or-later GPL-1.0-or-later
GPL-1.0-only GPL-2.0-only GPL-2.0-or-later GPL-3.0-only GPL-3.0-or-later HPND ICU IJG IPA ISC LGPL-2.0-only
LGPL-2.0-or-later LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0-only LGPL-3.0-or-later Libpng LPPL-1.3c
MIT MIT-0 MPL-1.1 MPL-2.0 MS-PL NCSA OFL-1.1 OpenSSL PHP-3.01 PostgreSQL Python-2.0 Ruby
Sleepycat TCL Unicode-3.0 Unicode-DFS-2016 Unlicense UPL-1.0 Vim W3C WTFPL X11 Zlib ZPL-2.1
""".split())

# Legacy SPDX ids and common distro spellings mapped to current ids.
LICENSE_ALIASES = {
    "GPL-1": "GPL-1.0-only", "GPL-1+": "GPL-1.0-or-later", "GPL-1.0+": "GPL-1.0-or-later",
    "GPL-2": "GPL-2.0-only", "GPL-2+": "GPL-2.0-or-later", "GPL-2.0": "GPL-2.0-only",
    "GPL-2.0+": "GPL-2.0-or-later", "GPLv2": "GPL-2.0-only", "GPLv2+": "GPL-2.0-or-later",
    "GPL-3": "GPL-3.0-only", "GPL-3+": "GPL-3.0-or-later", "GPL-3.0": "GPL-3.0-only",
    "GPL-3.0+": "GPL-3.0-or-later", "GPLv3": "GPL-3.0-only", "GPLv3+": "GPL-3.0-or-later",
    "LGPL-2": "LGPL-2.0-only", "LGPL-2+": "LGPL-2.0-or-later", "LGPL-2.1": "LGPL-2.1-only",
    "LGPL-2.1+": "LGPL-2.1-or-later", "LGPL-3": "LGPL-3.0-only", "LGPL-3+": "LGPL-3.0-or-later",
    "LGPL-3.0+": "LGPL-3.0-or-later", "LGPL-2.0+": "LGPL-2.0-or-later",
    "Apache-2": "Apache-2.0", "Apache 2.0": "Apache-2.0", "ASL 2.0": "Apache-2.0",
    "Expat": "MIT", "BSD-3-clause": "BSD-3-Clause", "BSD-2-clause": "BSD-2-Clause",
    "BSD-4-clause": "BSD-4-Clause", "zlib": "Zlib", "public-domain": None, "PSF-2.0": "Python-2.0",
    "MPL-2": "MPL-2.0", "custom": None,
}

PURL_NS = {"rhel": "redhat", "opensuse-leap": "opensuse", "opensuse-tumbleweed": "opensuse", "sles": "suse"}


def _q(s: str, safe: str = "") -> str:
    return quote(str(s), safe=safe)


def purl(manager: str, pkg: Dict[str, object], plat: Dict[str, object]) -> str:
    distro = str(plat.get("distro", ""))
    ns = PURL_NS.get(distro, distro)
    release = str(plat.get("release", ""))
    distro_q = f"{distro}-{release}" if release and release != "rolling" else distro
    name, ver = str(pkg["name"]), str(pkg["version"])
    quals: List[Tuple[str, str]] = []
    if manager == "apt":
        typ = "deb"
        quals = [("arch", str(pkg.get("arch", ""))), ("distro", distro_q)]
        src = pkg.get("source") or {}
        if src.get("name"):  # type: ignore[union-attr]
            quals.append(("upstream", f"{src['name']}@{src.get('version', ver)}"))  # type: ignore[index,union-attr]
    elif manager == "rpm":
        typ = "rpm"
        quals = [("arch", str(pkg.get("arch", ""))), ("distro", distro_q)]
        if pkg.get("epoch"):
            quals.append(("epoch", str(pkg["epoch"])))
    elif manager == "apk":
        typ = "apk"
        quals = [("arch", str(pkg.get("arch", ""))), ("distro", distro_q)]
    elif manager == "pacman":
        typ = "alpm"
        quals = [("arch", str(pkg.get("arch", ""))), ("distro", distro_q)]
    elif manager == "brew":
        typ = "brew"
        tap = str(pkg.get("tap") or "")
        short = name.rsplit("/", 1)[-1].lower()
        if pkg.get("kind") == "cask":
            ns = tap or "homebrew/cask"
        else:
            ns = "" if tap in ("", "homebrew/core") else tap
        name = short
    else:
        typ = "generic"
    path = f"pkg:{typ}/"
    if ns:
        path += "/".join(_q(seg.lower() if typ == "brew" else seg) for seg in ns.split("/")) + "/"
    path += _q(name) + "@" + _q(ver, safe=":")
    quals = sorted((k, v) for k, v in quals if v)
    if quals:
        path += "?" + "&".join(f"{k}={_q(v, safe=':')}" for k, v in quals)
    return path


def _map_token(tok: str) -> Tuple[Optional[str], Optional[str]]:
    """-> (spdx id, None) or (None, unrecognised name)"""
    tok = tok.strip("() ")
    if tok in SPDX_IDS:
        return tok, None
    if tok in LICENSE_ALIASES:
        return (LICENSE_ALIASES[tok], None) if LICENSE_ALIASES[tok] else (None, tok)
    return None, tok


_SPLIT = re.compile(r"\s+(AND|OR|and|or)\s+|\s*([,;/])\s*")


def _tokens(item: str) -> List[Tuple[str, str]]:
    """'GPL-2+ or Artistic, MIT' -> [('', 'GPL-2+'), ('OR', 'Artistic'), ('AND', 'MIT')]"""
    out: List[Tuple[str, str]] = []
    pos, op = 0, ""
    for m in _SPLIT.finditer(item):
        out.append((op, item[pos:m.start()]))
        op = (m.group(1) or "").upper() or ("OR" if m.group(2) == "/" else "AND")
        pos = m.end()
    out.append((op, item[pos:]))
    return [(o, t.strip("() ")) for o, t in out if t.strip("() ")]


def _license_ids(raw: List[str]) -> Tuple[List[str], List[str]]:
    """Split license strings into (spdx ids, unrecognised names)."""
    ids, names = [], []
    for item in raw:
        for _, tok in _tokens(item):
            i, n = _map_token(tok)
            if i:
                ids.append(i)
            if n:
                names.append(n)
    return sorted(set(ids)), sorted(set(names))


def _spdx_expression(raw: List[str], extracted: Dict[str, str]) -> str:
    """Build an SPDX expression that keeps OR choices from the metadata.
    Separate entries (different files of one package) are combined with AND."""
    parts = []
    for item in raw:
        terms = []
        for op, tok in _tokens(item):
            i, n = _map_token(tok)
            if n:
                i = "LicenseRef-" + _spdx_id(n)
                extracted[i] = n
            terms.append((op, i))
        if not terms:
            continue
        expr = terms[0][1]
        for op, t in terms[1:]:
            expr += f" {op} {t}"
        parts.append(f"({expr})" if len(terms) > 1 and len(raw) > 1 else expr)
    uniq = list(dict.fromkeys(parts))
    return " AND ".join(uniq) if uniq else "NOASSERTION"


def _hashes(manager: str, pkg: Dict[str, object], plat: Dict[str, object]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if pkg.get("sha256"):
        out.append(("SHA-256", str(pkg["sha256"])))
    if manager == "brew" and pkg.get("bottles"):
        from .managers.brew import bottle_tag

        bottles: Dict[str, str] = pkg["bottles"]  # type: ignore[assignment]
        sha = bottles.get(bottle_tag(plat)) or bottles.get("all")
        if sha:
            out.append(("SHA-256", sha))
    if manager == "rpm" and str(pkg.get("payloadDigest", "")).strip():
        d = str(pkg["payloadDigest"])
        if len(d) == 64:
            out.append(("SHA-256", d))
    return out


def _iter(env: Dict[str, object]):
    for mname, sec in sorted(env.get("managers", {}).items()):  # type: ignore[union-attr]
        for pkg in sec.get("packages", []):
            yield mname, pkg


def _refs(env: Dict[str, object]) -> Dict[Tuple[str, str], str]:
    """(manager, lock key) -> purl, used to wire dependencies."""
    from .managers import ALL

    plat = env["platform"]
    res = {}
    for mname, pkg in _iter(env):
        mgr = ALL.get(mname)
        key = mgr.key_of(pkg, plat) if mgr else str(pkg["name"])  # type: ignore[arg-type]
        res[(mname, key)] = purl(mname, pkg, plat)  # type: ignore[arg-type]
    return res


def cyclonedx(eid: str, env: Dict[str, object]) -> Dict[str, object]:
    plat: Dict[str, object] = env["platform"]  # type: ignore[assignment]
    refs = _refs(env)
    by_name: Dict[Tuple[str, str], str] = {}
    for (m, k), r in refs.items():
        by_name.setdefault((m, k), r)
    root_ref = f"syslock:env:{eid}"
    components, deps = [], []
    root_deps = []
    seen = set()
    for mname, pkg in _iter(env):
        ref = purl(mname, pkg, plat)
        if ref in seen:
            continue
        seen.add(ref)
        c: Dict[str, object] = {
            "type": "application" if pkg.get("kind") == "cask" else "library",
            "bom-ref": ref,
            "name": pkg["name"],
            "version": (f"{pkg['epoch']}:" if pkg.get("epoch") else "") + str(pkg["version"]),
            "purl": ref,
        }
        hashes = _hashes(mname, pkg, plat)
        if hashes:
            c["hashes"] = [{"alg": a, "content": h} for a, h in hashes[:1]]
        ids, names = _license_ids(list(pkg.get("licenses", [])))
        lic = [{"license": {"id": i}} for i in ids] + [{"license": {"name": n}} for n in names]
        if lic:
            c["licenses"] = lic
        props = [("syslock:manager", mname), ("syslock:reason", str(pkg.get("reason", "")))]
        for k in ("arch", "tap", "kind", "filename"):
            if pkg.get(k):
                props.append((f"syslock:{k}", str(pkg[k])))
        if pkg.get("repositories"):
            props.append(("syslock:repositories", ",".join(pkg["repositories"])))  # type: ignore[arg-type]
        c["properties"] = [{"name": k, "value": v} for k, v in props if v]
        components.append(c)
        if pkg.get("reason") == "manual":
            root_deps.append(ref)
        dep_refs = sorted({by_name[(mname, d)] for d in pkg.get("dependencies", []) if (mname, d) in by_name} - {ref})
        deps.append({"ref": ref, "dependsOn": dep_refs})
    deps.insert(0, {"ref": root_ref, "dependsOn": sorted(set(root_deps))})
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"syslock:{eid}:{env.get('digest', '')}")
    os_comp: Dict[str, object] = {
        "type": "operating-system",
        "bom-ref": root_ref,
        "name": str(plat.get("distro")),
        "version": str(plat.get("version") or plat.get("release")),
        "properties": [{"name": f"syslock:{k}", "value": str(plat[k])}
                       for k in ("arch", "release", "codename") if plat.get(k)],
    }
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": env.get("capturedAt"),
            "tools": {"components": [{"type": "application", "name": "syslock", "version": __version__,
                                      "externalReferences": [{"type": "vcs", "url": "https://github.com/dmdhrumilmistry/syslock"}]}]},
            "component": os_comp,
            "properties": [{"name": "syslock:environment", "value": eid},
                           {"name": "syslock:lockDigest", "value": str(env.get("digest", ""))}],
        },
        "components": sorted(components, key=lambda c: str(c["bom-ref"])),
        "dependencies": deps[:1] + sorted(deps[1:], key=lambda d: str(d["ref"])),
    }


def _spdx_id(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]+", "-", s)


def spdx(eid: str, env: Dict[str, object], namespace_base: Optional[str] = None) -> Dict[str, object]:
    plat: Dict[str, object] = env["platform"]  # type: ignore[assignment]
    refs = _refs(env)
    os_id = "SPDXRef-OperatingSystem"
    packages: List[Dict[str, object]] = [{
        "SPDXID": os_id,
        "name": str(plat.get("distro")),
        "versionInfo": str(plat.get("version") or plat.get("release")),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "primaryPackagePurpose": "OPERATING-SYSTEM",
        "copyrightText": "NOASSERTION",
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
    }]
    rels: List[Dict[str, str]] = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                                   "relatedSpdxElement": os_id}]
    extracted: Dict[str, str] = {}
    id_of: Dict[str, str] = {}
    used: Dict[str, int] = {}
    for mname, pkg in _iter(env):
        ref = purl(mname, pkg, plat)
        if ref in id_of:
            continue
        base = _spdx_id(f"SPDXRef-{mname}-{pkg['name']}-{pkg.get('arch', '')}")
        used[base] = used.get(base, 0) + 1
        sid = base if used[base] == 1 else f"{base}-{used[base]}"
        id_of[ref] = sid
        p: Dict[str, object] = {
            "SPDXID": sid,
            "name": str(pkg["name"]),
            "versionInfo": (f"{pkg['epoch']}:" if pkg.get("epoch") else "") + str(pkg["version"]),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "primaryPackagePurpose": "APPLICATION" if pkg.get("kind") == "cask" else "LIBRARY",
            "copyrightText": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": _spdx_expression(list(pkg.get("licenses", [])), extracted),
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": ref}],
        }
        hashes = _hashes(mname, pkg, plat)
        if hashes:
            p["checksums"] = [{"algorithm": "SHA256", "checksumValue": hashes[0][1]}]
        packages.append(p)
        rels.append({"spdxElementId": os_id, "relationshipType": "CONTAINS", "relatedSpdxElement": sid})
    for mname, pkg in _iter(env):
        sid = id_of[purl(mname, pkg, plat)]
        for d in pkg.get("dependencies", []):
            target = refs.get((mname, d))
            if target and id_of.get(target) and id_of[target] != sid:
                rels.append({"spdxElementId": sid, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": id_of[target]})
    base_ns = namespace_base or "https://github.com/dmdhrumilmistry/syslock/spdx"
    digest = str(env.get("digest", "")).replace("sha256:", "")[:32]
    doc: Dict[str, object] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"syslock-{eid}",
        "documentNamespace": f"{base_ns}/{eid}-{digest}",
        "creationInfo": {"created": env.get("capturedAt"), "creators": [f"Tool: syslock-{__version__}"]},
        "packages": packages,
        "relationships": rels,
    }
    if extracted:
        doc["hasExtractedLicensingInfos"] = [
            {"licenseId": k, "name": v, "extractedText": f"License as declared by the package manager: {v}"}
            for k, v in sorted(extracted.items())
        ]
    return doc
