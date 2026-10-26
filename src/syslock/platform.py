"""Detect which OS/distribution/architecture we are running on.

The platform is what makes a lock file portable: every snapshot is stored as
an "environment" keyed by distro + release + architecture, so one lock file
can hold the same toolset for a laptop (macOS arm64), a CI runner
(Ubuntu x86_64) and a Raspberry Pi (Debian aarch64) side by side.
"""

from __future__ import annotations

import os
import platform as _platform
import re
from typing import Dict, List, Optional

from .util import read_text, run, which

# Canonical architecture names. Every package manager has its own spelling;
# lock files store the canonical one and managers translate on the way out.
_ARCH_ALIASES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "x64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "armv8": "aarch64",
    "armv7l": "armv7",
    "armv7": "armv7",
    "armhf": "armv7",
    "armv7h": "armv7",
    "armel": "armv6",
    "armv6l": "armv6",
    "armhf_v6": "armv6",
    "i386": "i686",
    "i486": "i686",
    "i586": "i686",
    "i686": "i686",
    "x86": "i686",
    "ppc64le": "ppc64le",
    "ppc64el": "ppc64le",
    "s390x": "s390x",
    "riscv64": "riscv64",
    "loongarch64": "loongarch64",
    "loong64": "loongarch64",
}

# Distros that do not have numbered releases.
_ROLLING = {"arch", "archarm", "manjaro", "endeavouros", "gentoo", "void",
            "opensuse-tumbleweed", "artix", "cachyos"}

# Families that only keep the latest minor release in their mirrors, so a
# lock is really tied to the major version.
_MAJOR_ONLY = {"rhel", "centos", "rocky", "almalinux", "ol", "amzn", "fedora"}

MACOS_CODENAMES = {
    "27": "golden_gate",
    "26": "tahoe",
    "15": "sequoia",
    "14": "sonoma",
    "13": "ventura",
    "12": "monterey",
    "11": "big_sur",
}


def normalize_arch(arch: str) -> str:
    a = (arch or "").strip().lower()
    return _ARCH_ALIASES.get(a, a or "unknown")


def parse_os_release(text: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        data[k.strip()] = v
    return data


def _release_for(distro: str, osr: Dict[str, str]) -> str:
    version = osr.get("VERSION_ID", "")
    if distro in _ROLLING or "tumbleweed" in distro:
        return "rolling"
    if distro == "alpine":
        # 3.20.3 -> 3.20 (repositories are per minor branch);
        # edge builds report things like 3.21_alpha20240923.
        if "_" in version or not version:
            return "edge"
        return ".".join(version.split(".")[:2])
    if distro == "debian" and not version:
        # testing/sid do not set VERSION_ID.
        return osr.get("VERSION_CODENAME") or "sid"
    if distro in _MAJOR_ONLY and version:
        return version.split(".")[0]
    return version or osr.get("VERSION_CODENAME") or "unknown"


def detect(os_release_path: Optional[str] = None) -> Dict[str, object]:
    """Return a dict describing the running platform."""
    system = _platform.system().lower()
    if system == "darwin":
        version = run(["sw_vers", "-productVersion"], check=False).strip() or "unknown"
        major = version.split(".")[0]
        arch = normalize_arch(_platform.machine())
        # Rosetta: a translated shell reports x86_64 on Apple Silicon.
        if arch == "x86_64" and run(["sysctl", "-in", "sysctl.proc_translated"], check=False).strip() == "1":
            arch = "aarch64"
        return {
            "os": "macos",
            "distro": "macos",
            "idLike": [],
            "release": major,
            "version": version,
            "codename": MACOS_CODENAMES.get(major, ""),
            "arch": arch,
        }

    path = os_release_path
    if path is None:
        for cand in ("/etc/os-release", "/usr/lib/os-release"):
            if os.path.exists(cand):
                path = cand
                break
    osr = parse_os_release(read_text(path)) if path and os.path.exists(path) else {}
    distro = osr.get("ID", system or "unknown").lower()
    if distro.startswith("opensuse-tumbleweed"):
        distro = "opensuse-tumbleweed"
    id_like: List[str] = [x for x in osr.get("ID_LIKE", "").lower().split() if x]
    return {
        "os": system or "unknown",
        "distro": distro,
        "idLike": id_like,
        "release": _release_for(distro, osr),
        "version": osr.get("VERSION_ID", ""),
        "codename": osr.get("VERSION_CODENAME", ""),
        "arch": native_arch(),
    }


def native_arch() -> str:
    """The architecture packages are built for. This differs from uname on
    e.g. a 32-bit userland running on a 64-bit kernel."""
    if which("dpkg"):
        out = run(["dpkg", "--print-architecture"], check=False).strip()
        if out:
            return normalize_arch(out)
    if which("apk"):
        out = run(["apk", "--print-arch"], check=False).strip()
        if out:
            return normalize_arch(out)
    return normalize_arch(_platform.machine())


def env_id(plat: Dict[str, object]) -> str:
    raw = f"{plat['distro']}-{plat['release']}-{plat['arch']}"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", raw)


def family(plat: Dict[str, object]) -> List[str]:
    """Distro plus everything it claims to be like, most specific first."""
    return [str(plat.get("distro", ""))] + list(plat.get("idLike", []) or [])  # type: ignore[arg-type]
