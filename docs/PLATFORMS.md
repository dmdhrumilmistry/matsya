# Supported platforms

| Manager | Distros | Lock | Apply | Old versions come from | CI-tested on |
|---|---|:-:|:-:|---|---|
| **apt** / dpkg | Debian, Ubuntu, derivatives | yes | yes | snapshot.debian.org, snapshot.ubuntu.com (SHA-256) | Debian 12, 13, Ubuntu 22.04, 24.04, arm64 |
| **dnf5 / dnf / yum** | Fedora, RHEL, Rocky, Alma, Amazon Linux | yes | yes | Fedora Koji (payload digest) | Fedora, Rocky 8, 9, Amazon Linux 2, arm64 |
| **zypper** | openSUSE, SLES | yes | yes | no public archive | Tumbleweed |
| **apk** | Alpine, Wolfi | yes | yes | no public archive | Alpine, arm64 |
| **apt** in Termux | Android (Termux) | yes | yes | no public archive | termux-docker x86_64, aarch64 |
| **pacman** | Arch, Manjaro, EndeavourOS | yes | yes | Arch Linux Archive (SHA-256) | Arch |
| **Homebrew** | macOS, Linux | yes | yes | `brew extract` from homebrew-core history | macOS, Linux |

In the lock, rpm-based systems share one `rpm` section whatever the
frontend (dnf5, dnf, yum or zypper); the frontend is recorded alongside.

## How it is tested

Every CI run copies the static binary into each distro container and goes
through the full cycle:

1. `lock` the container.
2. Introduce drift.
3. `check` fails.
4. `apply --prune` repairs it.
5. Rebuild a **fresh container** from the lock.

Every run also does `lock`, `check` and `sbom` with an empty `PATH`, to
prove matsya needs nothing from the system.

## Architectures

Release binaries exist for Linux x86_64 and aarch64 (static musl), macOS
arm64 and x86_64, and Android aarch64, x86_64 and armv7 for Termux. See
[Installation](INSTALLATION.md).

Environment ids use a canonical architecture name (`x86_64`, `aarch64`,
`armv7`, `i686`, `ppc64le`, `s390x`, `riscv64`). A lock captured on one
architecture can be applied on another machine running the same release:
architecture-specific packages are re-targeted. See
[Edge cases](EDGE_CASES.md#portability-across-machines).

## How each manager is read

matsya never shells out to read package state. It parses the databases
directly:

- **apt**: `/var/lib/dpkg/status` plus its journal, and the apt list files
  for hashes and repositories.
- **rpm**: the rpmdb in any backend (SQLite including uncommitted WAL pages,
  NDB, BerkeleyDB), plus dnf5, dnf4, yum and zypper state for install
  reasons.
- **apk**: `/lib/apk/db/installed` and the world file.
- **pacman**: the local and sync databases.
- **Homebrew**: Cellar receipts and the API cache.

Only `apply` calls the system package manager, because installing is its
job. The [deep dive](DEEP_DIVE.md) explains the design in detail.
