# syslock

**Lock files and SBOMs for OS package managers.** syslock snapshots the
exact packages on a machine (apt, dnf/yum/zypper, apk, pacman, Homebrew)
into a reviewable, portable `syslock.lock.json`. It can then:

* **replay** that state on another machine, fetching versions that have left
  the mirrors from the distro's archive and checking their hashes;
* **detect drift** (`syslock check` exits 1, useful in CI and cron);
* **generate SBOMs** (CycloneDX 1.6, SPDX 2.3) from the lock, deterministic
  and without access to the machine.

```
$ syslock lock
syslock: capturing apt ...
syslock: locked ubuntu-24.04-x86_64 (apt: 744) -> syslock.lock.json

$ syslock sbom -o sbom.cdx.json && syslock sbom --format spdx -o sbom.spdx.json

$ sudo syslock apply           # on another machine
$ syslock check                # later, in CI
[apt] 1 extra, 2 changed
  + cowsay 3.03+dfsg2-8build1  (installed, not locked)
  ~ jq 1.8.1-4ubuntu2 -> 1.8.1-4ubuntu1
```

Zero dependencies: Python 3.8+ standard library only, so it runs on the
systems it locks.

## Supported platforms

| Manager | Distros | Lock | Apply | Old-version fallback | CI-tested |
|---|---|---|---|---|---|
| apt / dpkg | Debian, Ubuntu, derivatives | ✓ | ✓ | snapshot.debian.org, snapshot.ubuntu.com (SHA-256 verified) | Debian 12, 13, Ubuntu 22.04, 24.04 |
| rpm + dnf5 / dnf / yum | Fedora, RHEL, Rocky, Alma, Amazon Linux | ✓ | ✓ | Fedora Koji (payload digest verified) | Fedora, Rocky 9 |
| rpm + zypper | openSUSE, SLES | ✓ | ✓ | none available | Tumbleweed |
| apk | Alpine, Wolfi | ✓ | ✓ | none available | Alpine latest |
| pacman | Arch, Manjaro, EndeavourOS | ✓ | ✓ | Arch Linux Archive (SHA-256 verified) | Arch latest |
| Homebrew | macOS, Linux | ✓ | ✓ | `brew extract` from homebrew-core history | macOS, Ubuntu |

## Install

```sh
pipx install git+https://github.com/dmdhrumilmistry/syslock
# or, with nothing but python3 on the box:
curl -fsSL https://github.com/dmdhrumilmistry/syslock/archive/refs/heads/main.tar.gz | tar xz
PYTHONPATH=syslock-main/src python3 -m syslock --help
```

## Usage

```sh
syslock platform                      # what syslock sees: distro, release, arch, managers
syslock lock                          # create/update this machine's environment in syslock.lock.json
syslock lock -m brew                  # only Homebrew (run as your user, not root)
syslock envs                          # list environments in the lock (* = this machine)
syslock validate                      # structure + digest check

syslock check                         # exit 1 on drift
syslock check --ignore-extra          # allow additional packages
syslock check --integrity             # also compare checksums (same version, different build)
syslock diff --against other.lock.json:debian-12-x86_64   # compare two machines

syslock apply --dry-run               # print the plan as a shell script
sudo syslock apply                    # do it (asks first; --yes for automation)
sudo syslock apply --prune            # also remove packages that aren't locked
sudo syslock apply --roots-only       # pin only what you asked for, let the solver choose deps
sudo syslock apply --add-repos        # recreate third-party repos/keys recorded in the lock
sudo syslock apply --best-effort      # newest version where the locked one is gone

syslock sbom [--format cyclonedx|spdx] [--env ID|all] [-o FILE|DIR]
syslock export --format brewfile      # Homebrew Bundle interop
syslock export --roots-only           # plain "manager name version arch" list
```

### One lock, many machines

Each machine gets its own **environment** keyed by
`<distro>-<release>-<arch>`, so a team can commit one file:

```
$ syslock envs
* ubuntu-24.04-x86_64     2026-10-26T08:38:26Z   apt=744
  debian-12-aarch64       2026-10-20T10:02:11Z   apt=391
  macos-15-aarch64        2026-10-25T17:40:03Z   brew=86
```

On `apply`, syslock picks the environment that matches the machine. A
different arch of the same release is allowed (packages are re-targeted). A
different release needs `--allow-cross-release`. You can always choose
explicitly with `--env`.

### In CI

```yaml
- run: sudo apt-get update && python3 -m pip install git+https://github.com/dmdhrumilmistry/syslock
- run: syslock check --ignore-extra          # fail the build if the base image drifted
- run: syslock sbom -o sbom.cdx.json         # attach to release / feed to Grype/Trivy
```

In a Dockerfile, run `syslock apply --yes` against a committed lock, then
`syslock check`, so rebuilding the image gives the same package set.

## How it works

* **Capture** reads each package manager's own database (`dpkg-query`,
  `rpm -qa`, `/lib/apk/db/installed`, pacman's local db, `brew info --json=v2`).
  It records version, arch, install reason, holds/pins, dependency edges,
  licenses and source package. Hashes come from the signed repo metadata
  (apt `Packages`, pacman sync dbs, Homebrew bottle hashes, rpm payload
  digests, apk checksums). Repositories are recorded
  with their signing keys.
* **Apply** asks the native manager for the exact versions in one
  transaction (`apt-get install name:arch=ver …`, `dnf install NEVRA`,
  `apk add name=ver`, `pacman -S` / `-U`, `brew install`). It then restores
  install reasons and holds. Anything the mirrors no longer have is fetched
  from the archive and hash-checked before install.
* **SBOM** is a pure function of the lock: purls (`pkg:deb`, `pkg:rpm`,
  `pkg:apk`, `pkg:alpm`, `pkg:brew`) with `distro=` qualifiers so scanners
  pick the right advisories, plus hashes, licenses (mapped to SPDX ids) and
  the full dependency graph.

## Examples

[`examples/`](examples) has real output from CI runs: a
[multi-machine lock](examples/multi-machine.lock.json) (Debian, Fedora,
Alpine, Arch, macOS Homebrew in one file) and the
[CycloneDX](examples/debian-12.cdx.json) and [SPDX](examples/debian-12.spdx.json)
SBOMs for the Debian environment.

## Docs

* [docs/DEEP_DIVE.md](docs/DEEP_DIVE.md): why OS lock files are hard, every alternative (package lists, pinning, snapshots, images, Nix/Guix/apko) with pros and cons, and when to use which.
* [docs/EDGE_CASES.md](docs/EDGE_CASES.md): epochs, multiarch, cross-arch and cross-release replay, vanished versions, local packages, held packages, virtual packages, root vs brew, and more.
* [docs/LOCKFILE.md](docs/LOCKFILE.md): the lock file format.

## Limitations

The honest version: Alpine, RHEL clones, openSUSE and Homebrew casks have
no public archive of old versions, so a lock can only be replayed while
those versions are still published. Install scripts still run, so locking
packages is not the same as locking files. Homebrew dependency versions
follow their formula. Details and workarounds are in
[docs/DEEP_DIVE.md](docs/DEEP_DIVE.md#2-the-approaches-with-pros-and-cons).

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

CI runs unit tests on Python 3.8 to 3.13, checks generated SBOMs against
the official CycloneDX and SPDX schemas, and for each of 9 distro images
runs a full cycle in containers: lock, introduce drift, `check` fails,
`apply --prune` repairs, then **restore from the lock on a fresh
container**. Homebrew is tested the same way on macOS and Linux.

New package managers implement `Manager` in `src/syslock/managers/base.py`
(`capture`, `installed`, `prepare`, `plan`, `key_of`).

## License

Apache-2.0
