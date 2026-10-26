# matsya

> In the Matsya Purana, Vishnu takes the form of **Matsya**, the fish, and
> warns Manu of the coming flood. Manu loads a boat with the seeds of every
> plant, every kind of creature and the Vedas; Matsya tows it safely through
> the deluge, and the world is rebuilt from exactly what was saved.

**Lock files and SBOMs for OS package managers.** matsya snapshots the
exact packages on a machine (apt, dnf/yum/zypper, apk, pacman, Homebrew)
into a reviewable, portable `matsya.lock.json`. It can then:

* **replay** that state on another machine, fetching versions that have left
  the mirrors from the distro's archive and checking their hashes;
* **detect drift** (`matsya check` exits 1, useful in CI and cron);
* **generate SBOMs** (CycloneDX 1.6, SPDX 2.3) from the lock, deterministic
  and without access to the machine.

```
$ matsya lock
matsya: capturing apt ...
matsya: locked ubuntu-24.04-x86_64 (apt: 744) -> matsya.lock.json

$ matsya sbom -o sbom.cdx.json && matsya sbom --format spdx -o sbom.spdx.json

$ sudo matsya apply           # on another machine
$ matsya check                # later, in CI
[apt] 1 extra, 2 changed
  + cowsay 3.03+dfsg2-8build1  (installed, not locked)
  ~ jq 1.8.1-4ubuntu2 -> 1.8.1-4ubuntu1
```

A single static binary (about 1.5 MB, no runtime, no libc dependency on
Linux), so it runs on minimal and distroless images without installing
anything that would end up in the lock itself.

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
# prebuilt static binary (Linux x86_64/aarch64, macOS arm64/x86_64), checksum verified
curl -fsSL https://raw.githubusercontent.com/dmdhrumilmistry/matsya/main/install.sh | sh

# or from source
cargo install --locked --git https://github.com/dmdhrumilmistry/matsya
```

Release binaries come with SHA-256 files and GitHub build provenance
attestations (`gh attestation verify matsya-x86_64-linux -R dmdhrumilmistry/matsya`).
In a container you can copy the binary in, run it, and delete it again.

## Usage

```sh
matsya platform                      # what matsya sees: distro, release, arch, managers
matsya lock                          # create/update this machine's environment in matsya.lock.json
matsya lock -m brew                  # only Homebrew (run as your user, not root)
matsya envs                          # list environments in the lock (* = this machine)
matsya validate                      # structure + digest check

matsya check                         # exit 1 on drift
matsya check --ignore-extra          # allow additional packages
matsya check --integrity             # also compare checksums (same version, different build)
matsya diff --against other.lock.json:debian-12-x86_64   # compare two machines

matsya apply --dry-run               # print the plan as a shell script
sudo matsya apply                    # do it (asks first; --yes for automation)
sudo matsya apply --prune            # also remove packages that aren't locked
sudo matsya apply --roots-only       # pin only what you asked for, let the solver choose deps
sudo matsya apply --add-repos        # recreate third-party repos/keys recorded in the lock
sudo matsya apply --best-effort      # newest version where the locked one is gone

matsya sbom [--format cyclonedx|spdx] [--env ID|all] [-o FILE|DIR]
matsya export --format brewfile      # Homebrew Bundle interop
matsya export --roots-only           # plain "manager name version arch" list
```

### One lock, many machines

Each machine gets its own **environment** keyed by
`<distro>-<release>-<arch>`, so a team can commit one file:

```
$ matsya envs
* ubuntu-24.04-x86_64     2026-10-26T08:38:26Z   apt=744
  debian-12-aarch64       2026-10-20T10:02:11Z   apt=391
  macos-15-aarch64        2026-10-25T17:40:03Z   brew=86
```

On `apply`, matsya picks the environment that matches the machine. A
different arch of the same release is allowed (packages are re-targeted). A
different release needs `--allow-cross-release`. You can always choose
explicitly with `--env`.

### In CI

```yaml
- run: curl -fsSL https://raw.githubusercontent.com/dmdhrumilmistry/matsya/main/install.sh | sh
- run: matsya check --ignore-extra          # fail the build if the base image drifted
- run: matsya sbom -o sbom.cdx.json         # attach to release / feed to Grype/Trivy
```

In a Dockerfile, run `matsya apply --yes` against a committed lock, then
`matsya check`, so rebuilding the image gives the same package set.

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
cargo test
cargo build --release --target x86_64-unknown-linux-musl   # static binary
```

CI runs `cargo fmt`, `clippy -D warnings` and the tests on Linux and macOS,
and checks generated SBOMs against the official CycloneDX and SPDX schemas.
For each of 9 distro images (plus Debian, Fedora and Alpine on aarch64) it
copies the static binary into a container and runs a full cycle: lock,
introduce drift, `check` fails, `apply --prune` repairs, then **restore
from the lock on a fresh container**. Homebrew is tested the same way on
macOS and Linux.

New package managers implement the `Manager` trait in
`src/managers/mod.rs` (`capture`, `installed`, `prepare`, `plan`,
`key_of`), plus a purl mapping in `src/sbom.rs`.

### Migrating from syslock

matsya was first written in Python under the name *syslock*. Lock files
are fully compatible: the format is unchanged and digests match byte for
byte, so existing `syslock.lock.json` files keep validating. If only
`syslock.lock.json` exists in the current directory it is used
automatically; rename it to `matsya.lock.json` when convenient.

## License

Apache-2.0
