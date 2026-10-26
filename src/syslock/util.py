"""Small helpers shared by every module: subprocess, hashing, logging."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from typing import Dict, Iterable, Iterator, List, Optional, Sequence

# Package managers translate their output; force a stable, parseable locale.
_ENV = dict(os.environ, LC_ALL="C", LANG="C", LANGUAGE="C")
# Homebrew must never auto-update or nag while we are only reading state.
_ENV.update(
    HOMEBREW_NO_AUTO_UPDATE="1",
    HOMEBREW_NO_ANALYTICS="1",
    HOMEBREW_NO_ENV_HINTS="1",
    HOMEBREW_NO_INSTALL_CLEANUP="1",
)

VERBOSE = False


class SyslockError(Exception):
    """An error that should be shown to the user without a traceback."""


def log(msg: str) -> None:
    print(f"syslock: {msg}", file=sys.stderr)


def debug(msg: str) -> None:
    if VERBOSE:
        print(f"syslock[debug]: {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"syslock: warning: {msg}", file=sys.stderr)


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def run(
    args: Sequence[str],
    check: bool = True,
    input_text: Optional[str] = None,
    timeout: Optional[float] = 600,
) -> str:
    """Run a command and return stdout. Output is decoded leniently because
    package metadata is not guaranteed to be valid UTF-8."""
    debug("exec: " + " ".join(args))
    try:
        proc = subprocess.run(
            list(args),
            input=input_text.encode() if input_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_ENV,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise SyslockError(f"command not found: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SyslockError(f"command timed out: {' '.join(args)}") from exc
    out = proc.stdout.decode("utf-8", errors="replace")
    if check and proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise SyslockError(
            f"command failed ({proc.returncode}): {' '.join(args)}\n{err}"
        )
    return out


def read_text(path: str) -> str:
    with open(path, "rb") as fh:
        return fh.read().decode("utf-8", errors="replace")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(obj) -> str:
    """Deterministic JSON used for digests and for writing lock files, so
    that two runs over the same system produce byte-identical output."""
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def digest(obj) -> str:
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(data.encode("utf-8")).hexdigest()


def parse_deb822(text: str) -> Iterator[Dict[str, str]]:
    """Parse RFC822-style stanzas (dpkg status, apt Packages, deb822 sources).
    Continuation lines are joined with newlines; field names are kept as-is."""
    stanza: Dict[str, str] = {}
    key = None
    for line in text.splitlines():
        if not line.strip():
            if stanza:
                yield stanza
            stanza, key = {}, None
            continue
        if line.startswith("#"):
            continue
        if line[0] in " \t":
            if key is not None:
                stanza[key] += "\n" + line.strip()
            continue
        k, sep, v = line.partition(":")
        if not sep:
            continue
        key = k.strip()
        stanza[key] = v.strip()
    if stanza:
        yield stanza


def chunked(items: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]
