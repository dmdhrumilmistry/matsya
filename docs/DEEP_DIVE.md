# Deep dive: lock files for OS package managers

Language package managers (npm, Cargo, Poetry, Go modules) all have lock
files. OS package managers mostly don't. This document covers why, what
options exist, what each one costs, and where syslock fits.

## 1. Why OS packages are hard to lock

A lock file only helps if three things are true:

1. **You can name an exact artifact.** That means a name, a version and an
   architecture, ideally plus a content hash.
2. **You can still get that artifact later.** The registry has to keep old
   versions.
3. **Installing it gives the same result.** Nothing else (other packages,
   scripts, config) changes the outcome.

npm and crates.io meet all three. Distribution repositories mostly don't:

| Property | npm / crates.io | apt (Debian/Ubuntu) | dnf (Fedora/RHEL) | apk (Alpine) | pacman (Arch) | Homebrew |
|---|---|---|---|---|---|---|
| Exact version naming | yes | yes (`name=epoch:ver-rev`) | yes (NEVRA) | yes (`name=ver-rN`) | yes | version visible, cannot be requested |
| Old versions stay in the main repo | yes, immutable | **no**, superseded versions are removed | **no**, only the latest update is kept | **no** | **no** | **no**, only the current formula exists |
| Public archive of old versions | n/a | **yes**: snapshot.debian.org, snapshot.ubuntu.com | Fedora: Koji. RHEL: no public archive | **none** | **yes**: Arch Linux Archive (x86_64) | git history of homebrew-core |
| Content hash in metadata | yes | SHA256 in `Packages` | payload digest in header | SHA1 control checksum | SHA256 in sync db | bottle SHA256 per platform |
| Signed metadata | npm provenance / sigstore | InRelease (GPG) | repomd (GPG) + rpm sigs | RSA-signed index | PGP signatures | git + HTTPS, bottles via GHCR |
| Install scripts | yes | maintainer scripts | scriptlets | install scripts | install hooks | post_install |

Two more problems come from the OS itself:

* **Version numbers are release-specific.** `curl 8.5.0-2ubuntu10.6` only
  exists for Ubuntu 24.04. A lock captured on 24.04 cannot just be replayed
  on 22.04 or Debian 12. Each distro release is effectively its own
  ecosystem.
* **Architecture changes artifacts.** The same version on amd64 and arm64 is
  a different `.deb` with a different hash. Only `Architecture: all` /
  `noarch` packages are byte-identical across machines.

## 2. The approaches, with pros and cons

### A. Package list (`dpkg --get-selections`, `rpm -qa`, `apk info`, `pacman -Qqe`, `brew bundle dump`)

Write down names, sometimes versions.

* **Pros:** trivial, every distro supports it, readable.
* **Cons:** this is a wishlist, not a lock. Versions are either missing or
  can't be honoured later because the mirror dropped them. No hashes, no
  repos, no dependency closure. `Brewfile` has no versions at all.

### B. Pin versions in the package manager (`apt-mark hold`, apt preferences, `dnf versionlock`, `/etc/apk/world` with `=ver`, `IgnorePkg`, `brew pin`)

* **Pros:** native. Stops upgrades on that one machine.
* **Cons:** stops change, doesn't reproduce anything. Lives in machine
  config rather than a portable file. Holding a library while its
  dependants move on causes dependency conflicts.

### C. Snapshot repositories / time travel (snapshot.debian.org, `apt --snapshot` on Ubuntu 24.04+, Arch Linux Archive by date, a Fedora compose, a private Pulp/Artifactory/Aptly mirror)

Point the whole system at the repository as it was at time T.

* **Pros:** consistent. Every package comes from the same moment, so the
  solver sees a coherent world. Strong for CI images.
* **Cons:** one timestamp for the whole system, so you cannot mix "frozen
  base" and "latest security fix" without overrides. You depend on the
  snapshot service being up and fast; snapshot.debian.org is famously
  rate-limited. Alpine and RHEL have no public equivalent.
  Third-party repos (Docker, NodeSource, GitHub CLI) are not covered.

### D. Image-based (Docker/OCI image digests, VM images, ostree / bootc)

Freeze the bytes of the whole filesystem.

* **Pros:** bit-for-bit reproducible at runtime. Easy rollback.
* **Cons:** opaque. You can't diff or review an image like a text file. It
  doesn't help a laptop or bare-metal host. The image still has to be built
  somehow, and that build is the unreproducible part.

### E. Functional package managers (Nix, Guix) and lock-native toolchains (apko/melange, `rpm-lockfile-prototype`, repro-env)

* **Pros:** real lock files with content hashes and full closures. Nix
  flakes and Guix channels pin the entire package set. apko builds Alpine
  and Wolfi images from a resolved lock. repro-env does Arch and Debian
  container lock files. rpm-lockfile-prototype resolves RPM lock files for
  Konflux builds.
* **Cons:** most mean switching how the system is built or what distro you
  run. They don't describe a Debian laptop or a Homebrew setup that already
  exists.

### F. Capture + replay with archive fallback (syslock)

Record the exact installed state of an existing machine, with hashes, repo
origins and install reasons, in a text lock file. Replay it elsewhere by
asking the native package manager for those exact versions. When the
normal mirror no longer has a version, fetch it from that distro's archive
and verify the recorded hash.

* **Pros:**
  * Works on systems you already have, with their native tools. No new distro, daemon or root-level agent.
  * The text format shows up in code review: `git diff` shows exactly which packages moved.
  * Hashes come from signed repo metadata, so a replay detects swapped or rebuilt artifacts.
  * One file holds several machines (laptop macOS arm64, CI Ubuntu x86_64, Pi Debian aarch64).
  * The SBOM is derived from the lock. It is deterministic, and you can produce it for a machine without logging into it.
  * Drift detection (`syslock check`) is cheap enough to run in CI or a cron job.
* **Cons and limits** (more in [EDGE_CASES.md](EDGE_CASES.md)):
  * Replay depends on archives. Debian/Ubuntu/Fedora/Arch are good. Alpine, RHEL clones and Homebrew casks have no archive, so old versions can fade away.
  * Install scripts still run, so file-level reproducibility isn't guaranteed (config files, generated caches, `postinst` side effects).
  * Cross-release replay (lock from 22.04 on 24.04) is mostly impossible by nature. syslock refuses unless you pass `--allow-cross-release --best-effort`.
  * Cross-architecture replay installs the same versions, but their hashes can't be checked (the lock only knows the source arch's hash).
  * Homebrew only gives you the current formula. Older versions get rebuilt via `brew extract` and usually compile from source. Dependency versions follow the formula and can't be pinned.
  * Mixing archived and current packages on Arch is a partial upgrade. syslock warns and points to date-based mirrors for a full time-travel.

## 3. Which approach when

| Goal | Best fit |
|---|---|
| Bit-identical production runtime | D (image digest) built from C or F |
| Review and audit what's installed on fleet hosts | F (+ SBOM) |
| Reproducible CI runners / dev containers | C or F; F if you also need third-party repos |
| Laptop setup across machines (macOS + Linux) | F (multi-environment lock + Brewfile export) |
| Hermetic builds from scratch | E (Nix/Guix/apko) |
| Freeze a box and stop upgrades | B |

They combine well. Run syslock inside a Dockerfile build to produce the
lock and SBOM, then ship the image by digest. Or lock the base image's
packages with syslock and pin the base image itself by digest.

## 4. SBOM considerations

* **Format.** CycloneDX 1.6 and SPDX 2.3 are both generated from the same
  data. CycloneDX carries the dependency graph and syslock properties
  (manager, install reason, repo). SPDX carries `DEPENDS_ON` / `CONTAINS`
  relationships and license expressions.
* **Identity.** Packages are identified by [purl](https://github.com/package-url/purl-spec):
  `pkg:deb`, `pkg:rpm`, `pkg:apk`, `pkg:alpm`, `pkg:brew`. Distro and
  release go in the `distro=` qualifier, because vulnerability scanners
  (Grype, Trivy, OSV) need them to choose the right advisory feed.
* **Hashes.** apt and pacman use the SHA-256 of the package file. rpm uses
  the payload SHA-256. Homebrew uses the bottle SHA-256 for the target
  platform. apk only has a SHA-1 control checksum, which is recorded in the
  lock and left out of the SBOM.
* **Licenses.** Distro license metadata is messy. Debian only has
  machine-readable `copyright` files for some packages, and RPM/pacman use
  a mix of SPDX and legacy names. syslock maps known identifiers and legacy
  aliases to SPDX ids, keeps `OR` choices, and records everything else as
  `LicenseRef-*` instead of guessing.
* **Lock vs live scan.** Scanners like Syft and Trivy read the filesystem.
  syslock reads the lock. The lock-based SBOM is reproducible and
  reviewable. A live scan also catches files the package manager doesn't
  know about (curl-pipe-bash installs, `/usr/local`, pip/npm globals).
  Use both if you need complete coverage.

## 5. Security model

* syslock trusts the package manager's own signature checks (apt
  InRelease, rpm GPG, apk RSA, pacman PGP). On top of that, when it
  downloads from an archive it checks the SHA-256 recorded at lock time
  (Fedora: the rpm payload digest). A mismatch aborts.
* Third-party repo keys can be embedded in the lock (base64). They are
  only installed on another machine with `--add-repos`, because adding a
  repo grants that vendor root on install. Review those entries the same
  way you'd review a new dependency.
* Each environment has a digest. `syslock validate` and `apply` refuse a
  hand-edited lock unless you pass `--force`. This catches mistakes, not
  attackers: anyone who can edit the file can recompute the digest. Sign
  the file (cosign, minisign, signed git commits) if you need
  authenticity.
* `apply` asks before changing anything unless you pass `--yes`, refuses
  without a TTY, and never removes `Essential`/`required` packages, even
  with `--prune`.
