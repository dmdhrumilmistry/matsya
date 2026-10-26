"""Compare a locked environment with the live system or with another lock."""

from __future__ import annotations

from typing import Dict, List, Optional

from .managers import ALL

INTEGRITY_FIELDS = ("sha256", "checksum", "payloadDigest", "sigmd5")


def _full_version(p: Dict[str, object]) -> str:
    return (f"{p['epoch']}:" if p.get("epoch") else "") + str(p.get("version"))


def diff_sections(manager: str, locked: List[Dict[str, object]], locked_plat: Dict[str, object],
                  current: List[Dict[str, object]], current_plat: Dict[str, object]) -> Dict[str, list]:
    mgr = ALL.get(manager)
    key = (lambda p, plat: mgr.key_of(p, plat)) if mgr else (lambda p, plat: str(p["name"]))
    a = {key(p, locked_plat): p for p in locked}
    b = {key(p, current_plat): p for p in current}
    res: Dict[str, list] = {"missing": [], "extra": [], "changed": [], "integrity": [], "reason": []}
    for k in sorted(a):
        if k not in b:
            res["missing"].append({"name": k, "locked": _full_version(a[k])})
            continue
        va, vb = _full_version(a[k]), _full_version(b[k])
        if va != vb:
            res["changed"].append({"name": k, "locked": va, "current": vb})
            continue
        for f in INTEGRITY_FIELDS:
            if a[k].get(f) and b[k].get(f) and a[k][f] != b[k][f]:
                res["integrity"].append({"name": k, "field": f, "locked": a[k][f], "current": b[k][f]})
        if a[k].get("reason") and b[k].get("reason") and a[k]["reason"] != b[k]["reason"]:
            res["reason"].append({"name": k, "locked": a[k]["reason"], "current": b[k]["reason"]})
    for k in sorted(b):
        if k not in a:
            res["extra"].append({"name": k, "current": _full_version(b[k])})
    return res


def has_drift(result: Dict[str, Dict[str, list]], ignore_extra: bool = False, ignore_reason: bool = True) -> bool:
    for sec in result.values():
        if sec.get("missing") or sec.get("changed") or sec.get("integrity"):
            return True
        if sec.get("extra") and not ignore_extra:
            return True
        if sec.get("reason") and not ignore_reason:
            return True
    return False


def render(result: Dict[str, Dict[str, list]], limit: Optional[int] = None) -> str:
    out = []
    for mname, sec in sorted(result.items()):
        counts = ", ".join(f"{len(v)} {k}" for k, v in sec.items() if v)
        out.append(f"[{mname}] " + (counts or "no differences"))
        rows = []
        for item in sec.get("missing", []):
            rows.append(f"  - {item['name']} {item['locked']}  (locked, not installed)")
        for item in sec.get("extra", []):
            rows.append(f"  + {item['name']} {item['current']}  (installed, not locked)")
        for item in sec.get("changed", []):
            rows.append(f"  ~ {item['name']} {item['locked']} -> {item['current']}")
        for item in sec.get("integrity", []):
            rows.append(f"  ! {item['name']} same version but {item['field']} differs (rebuilt or tampered package)")
        for item in sec.get("reason", []):
            rows.append(f"  * {item['name']} install reason {item['locked']} -> {item['current']}")
        if limit is not None and len(rows) > limit:
            rows = rows[:limit] + [f"  ... {len(rows) - limit} more"]
        out.extend(rows)
    return "\n".join(out)
