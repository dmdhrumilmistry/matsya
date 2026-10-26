<p align="center">
  <img src="https://raw.githubusercontent.com/dmdhrumilmistry/matsya/main/assets/banner.svg" alt="matsya: lock files and SBOMs for OS package managers" width="100%">
</p>

<p align="center">
  <a href="https://github.com/dmdhrumilmistry/matsya/actions/workflows/ci.yml"><img src="https://github.com/dmdhrumilmistry/matsya/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/matsya"><img src="https://img.shields.io/crates/v/matsya?logo=rust&color=f7c044" alt="crates.io"></a>
  <a href="https://github.com/dmdhrumilmistry/matsya/releases/latest"><img src="https://img.shields.io/github/v/release/dmdhrumilmistry/matsya?color=7be0b5&label=release" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/runtime%20deps-none-0c6f80" alt="No runtime dependencies">
  <img src="https://img.shields.io/badge/SBOM-CycloneDX%201.6%20%C2%B7%20SPDX%202.3-0e3a64" alt="CycloneDX 1.6 and SPDX 2.3">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/dmdhrumilmistry/matsya?color=081a33" alt="License"></a>
</p>

<p align="center">
  <b>Record a machine. Rebuild it anywhere. Know exactly what is in it.</b><br>
  <a href="#-quick-start">Quick start</a> ·
  <a href="#-why-matsya">Why</a> ·
  <a href="#-supported-platforms">Platforms</a> ·
  <a href="#-commands">Commands</a> ·
  <a href="docs/DEEP_DIVE.md">Deep dive</a> ·
  <a href="docs/EDGE_CASES.md">Edge cases</a>
</p>

---

**matsya** snapshots the exact packages on a machine (apt, dnf, yum, zypper,
apk, pacman and Homebrew) into a reviewable, portable `matsya.lock.json`.
Then it can:

- 🔁 **replay** that state on another machine, pulling versions that have
  left the mirrors from the distro's archive and checking their hashes;
- 🚨 **detect drift**: `matsya check` exits 1, ready for CI and cron;
- 📦 **generate SBOMs** (CycloneDX 1.6 and SPDX 2.3) straight from the
  lock, byte-for-byte reproducible and without touching the machine.

It's a single ~3 MB static binary that **depends on nothing**. It reads the
dpkg, rpm, apk, pacman and Homebrew databases itself and has its own HTTPS
client. `lock`, `check`, `diff` and `sbom` work with an *empty* `PATH`. Only
`apply` calls the system package manager, because installing is its job.

<p align="center">
  <img src="https://raw.githubusercontent.com/dmdhrumilmistry/matsya/main/assets/cli.svg" alt="matsya welcome screen in a terminal" width="760">
</p>

## 🚀 Quick start

```sh
curl -fsSL https://raw.githubusercontent.com/dmdhrumilmistry/matsya/main/install.sh | sh
```

```console
$ matsya lock
matsya: capturing apt ...
matsya: locked ubuntu-24.04-x86_64 (apt: 744) -> matsya.lock.json

$ matsya sbom -o sbom.cdx.json                    # CycloneDX (or --format spdx)

$ sudo matsya apply                               # on another machine: same packages, same versions

$ matsya check                                    # later: has anything drifted?
environment: ubuntu-24.04-x86_64
[apt] 1 extra, 2 changed
  + cowsay 3.03+dfsg2-8build1  (installed, not locked)
  ~ jq 1.8.1-4ubuntu2 -> 1.8.1-4ubuntu1
matsya: drift detected
```

<details>
<summary><b>Other ways to install</b></summary>

```sh
cargo install matsya                              # from crates.io
cargo install --locked --git https://github.com/dmdhrumilmistry/matsya
```

The installer needs no root: it uses `sudo` or `doas` only if the target
directory isn't writable, and otherwise installs to `~/.local/bin`. In
**Termux** it installs the native Android build into `$PREFIX/bin`.

Release binaries (Linux x86_64/aarch64 as static musl builds, macOS arm64/x86_64,
Android aarch64/x86_64/armv7 for Termux)
come with SHA-256 files and GitHub build provenance attestations:

```sh
gh attestation verify matsya-x86_64-linux -R dmdhrumilmistry/matsya
```

In a container you can copy the binary in, run it, and delete it again.
Nothing it needs ends up in the image or in the lock.
</details>

## 💡 Why matsya

Language ecosystems have had lock files for years. The operating system
underneath usually has a hand-written `apt-get install` line and hope.

| | |
|---|---|
| **🔒 Real lock files** | Exact version, architecture, install reason, holds, dependency graph, repository and signing key for every package, plus the **SHA-256 from the signed repo metadata**. |
| **🌍 One file, many machines** | Your Mac, the CI runner and the Raspberry Pi live side by side as environments (`macos-15-aarch64`, `ubuntu-24.04-x86_64`, `debian-12-aarch64`). |
| **🕰️ Versions that disappeared still install** | Falls back to snapshot.debian.org, snapshot.ubuntu.com, Fedora Koji, the Arch Linux Archive or `brew extract`, and **verifies the hash** before installing. |
| **🧾 SBOMs you can reproduce** | purls with `distro=` qualifiers (so Grype, Trivy and OSV pick the right advisories), SPDX license expressions, hashes, the full dependency graph. Validated against the official schemas in CI. |
| **🔍 Reviewable** | Sorted, deterministic JSON. Re-locking an unchanged machine doesn't touch the file, so `git diff` shows exactly which packages moved. |
| **🪶 Zero dependencies** | One static binary. No Python, no `rpm`, no `sqlite3`, no `curl`. It even reads rpm's SQLite, NDB and BerkeleyDB databases (including uncommitted WAL pages) natively. |

### How it compares

| | Package list / Brewfile | Pinning (`apt-mark hold`, versionlock) | Syft / Trivy scan | Nix / Guix | **matsya** |
|---|:-:|:-:|:-:|:-:|:-:|
| Exact versions + hashes | ✗ | partial | ✓ | ✓ | **✓** |
| Rebuild on another machine | names only | ✗ | ✗ | ✓ | **✓** |
| Locks the distro packages you already use | ✓ | ✓ | ✓ | ✗ (own package set) | **✓** |
| Drift detection | ✗ | ✗ | diff by hand | ✓ | **✓** |
| SBOM | ✗ | ✗ | ✓ | via tools | **✓, from the lock** |
| macOS + Linux in one file | ✗ | ✗ | ✗ | ✓ | **✓** |

The [deep dive](docs/DEEP_DIVE.md) covers the trade-offs honestly,
including when Nix, snapshot mirrors or image digests are the better choice.

## 🖥️ Supported platforms

| Manager | Distros | Lock | Apply | Old versions come from | CI-tested on |
|---|---|:-:|:-:|---|---|
| **apt** / dpkg | Debian, Ubuntu, derivatives | ✓ | ✓ | snapshot.debian.org, snapshot.ubuntu.com (SHA-256) | Debian 12, 13 · Ubuntu 22.04, 24.04 · arm64 |
| **dnf5 / dnf / yum** | Fedora, RHEL, Rocky, Alma, Amazon Linux | ✓ | ✓ | Fedora Koji (payload digest) | Fedora · Rocky 8, 9 · Amazon Linux 2 · arm64 |
| **zypper** | openSUSE, SLES | ✓ | ✓ | no public archive | Tumbleweed |
| **apk** | Alpine, Wolfi | ✓ | ✓ | no public archive | Alpine · arm64 |
| **apt** in Termux | Android (Termux) | ✓ | ✓ | no public archive | termux-docker x86_64 · aarch64 |
| **pacman** | Arch, Manjaro, EndeavourOS | ✓ | ✓ | Arch Linux Archive (SHA-256) | Arch |
| **Homebrew** | macOS, Linux | ✓ | ✓ | `brew extract` from homebrew-core history | macOS · Linux |

Every CI run copies the static binary into each distro container and goes
through the full cycle: lock, introduce drift, `check` fails, `apply --prune`
repairs, then **rebuild a fresh container from the lock**. Every run also
does lock, check and sbom with an empty `PATH`.

## 🧭 Commands

```sh
matsya platform                     # distro, release, arch and package managers matsya sees
matsya lock                         # create/update this machine's environment in matsya.lock.json
matsya envs                         # environments in the lock (* = this machine)
matsya validate                     # structure + digest check

matsya check                        # exit 1 on drift   (--ignore-extra, --roots-only, --integrity)
matsya diff --against other.lock.json:debian-12-x86_64   # compare two machines

matsya apply --dry-run              # print the plan as a shell script
sudo matsya apply                   # do it (asks first; --yes for automation)
sudo matsya apply --prune           # also remove packages that aren't locked
sudo matsya apply --roots-only      # pin what you asked for, let the solver pick dependencies
sudo matsya apply --add-repos       # recreate third-party repos and keys recorded in the lock
sudo matsya apply --best-effort     # newest version where the locked one is gone

matsya sbom [--format cyclonedx|spdx] [--env ID|all] [-o FILE|DIR]
matsya export --format brewfile     # Homebrew Bundle interop
```

Colors appear only in a terminal. Pipes, CI logs and `NO_COLOR=1` get plain text.

### 🌍 One lock, many machines

```console
$ matsya envs
* ubuntu-24.04-x86_64     2026-10-26T08:38:26Z   apt=744
  debian-12-aarch64       2026-10-20T10:02:11Z   apt=391
  macos-15-aarch64        2026-10-25T17:40:03Z   brew=86
```

`apply` picks the environment that matches the machine. The same release on
another architecture works (packages are re-targeted). Another release needs
`--allow-cross-release`. `--env` always lets you choose.

### ⚙️ In CI and Dockerfiles

```yaml
- run: curl -fsSL https://raw.githubusercontent.com/dmdhrumilmistry/matsya/main/install.sh | sh
- run: matsya check --ignore-extra        # fail the build if the base image drifted
- run: matsya sbom -o sbom.cdx.json       # attach to the release, feed to Grype/Trivy
```

```dockerfile
ADD --chmod=755 https://github.com/dmdhrumilmistry/matsya/releases/latest/download/matsya-x86_64-linux /usr/local/bin/matsya
COPY matsya.lock.json .
RUN matsya apply --yes && matsya check && rm /usr/local/bin/matsya
```

## 🔬 How it works

- **Capture** reads each package manager's own database files:
  `/var/lib/dpkg/status` (plus its journal), the rpmdb in any backend, dnf5
  and dnf4 state, yumdb, `/lib/apk/db/installed`, pacman's local and sync
  databases, and Homebrew's Cellar receipts and API cache. Hashes come from
  signed repository metadata. Repositories are recorded with their signing
  keys.
- **Apply** asks the native manager for the exact versions in one
  transaction (`apt-get install name:arch=ver …`, `dnf install NEVRA`,
  `apk add name=ver`, `pacman -S`/`-U`, `brew install`), then restores
  install reasons and holds. Anything the mirrors dropped is downloaded from
  the archive and verified first.
- **SBOM** is a pure function of the lock: `pkg:deb`, `pkg:rpm`, `pkg:apk`,
  `pkg:alpm` and `pkg:brew` purls, SPDX license expressions that keep `AND`/`OR`
  grouping, hashes, and the dependency graph.

Real output lives in [`examples/`](examples): a
[multi-machine lock](examples/multi-machine.lock.json) (Debian, Fedora, Alpine,
Arch and macOS in one file) and its [CycloneDX](examples/debian-12.cdx.json)
and [SPDX](examples/debian-12.spdx.json) SBOMs.

## 🐟 Why "matsya"?

<img align="right" src="https://raw.githubusercontent.com/dmdhrumilmistry/matsya/main/assets/logo.svg" width="150" alt="matsya logo">

In the Matsya Purana, Vishnu takes the form of **Matsya**, a horned golden
fish, and warns the sage Manu of a great flood. Manu builds a boat and fills
it with the seeds of every plant, every kind of creature and the Vedas. He
ties it to Matsya's horn, the fish tows it safely through the deluge, and
afterwards the world is rebuilt from exactly what was saved.

That is the job: record everything a machine is made of, carry it safely,
and rebuild the same world somewhere else. The logo shows Matsya towing the
boat, and the cargo is packages.

## ⚖️ Limitations, honestly

- Alpine, RHEL clones, openSUSE and Homebrew casks keep **no public archive**
  of old versions, so a lock can only be replayed while those versions are
  still published. matsya says so up front instead of guessing.
- Install scripts still run, so locking packages isn't the same as locking
  files. Pair it with an image digest if you need bit-for-bit.
- Homebrew dependency versions follow their formula.
- Software installed outside a package manager (`/usr/local`, `curl | sh`,
  pip or npm globals, snaps) isn't captured.

More in [docs/DEEP_DIVE.md](docs/DEEP_DIVE.md) and [docs/EDGE_CASES.md](docs/EDGE_CASES.md).
The lock format is specified in [docs/LOCKFILE.md](docs/LOCKFILE.md).

## 🛠️ Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release --target x86_64-unknown-linux-musl    # needs musl-tools
```

New package managers implement the `Manager` trait in `src/managers/mod.rs`
(`capture`, `installed`, `prepare`, `plan`, `key_of`) and add a purl mapping
in `src/sbom.rs`. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md).

<details>
<summary><b>Migrating from syslock</b></summary>

matsya was first written in Python under the name *syslock*. The lock format
is unchanged and digests match byte for byte, so existing `syslock.lock.json`
files keep validating. If only `syslock.lock.json` exists in the current
directory it's used automatically.
</details>

## License

[Apache-2.0](LICENSE)
