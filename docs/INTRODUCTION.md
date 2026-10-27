# matsya

**Record a machine. Rebuild it anywhere. Know exactly what is in it.**

matsya snapshots the exact packages on a machine into a reviewable,
portable `matsya.lock.json`. It works with apt, dnf, yum, zypper, apk,
pacman, Homebrew and Termux.

With that lock file you can:

- **Replay** the same state on another machine. Versions that have left the
  mirrors are fetched from the distro's archive and their hashes are checked.
- **Detect drift.** `matsya check` exits 1 when a machine no longer matches,
  so it fits straight into CI and cron.
- **Generate SBOMs** in CycloneDX 1.6 and SPDX 2.3, straight from the lock.
  They are byte-for-byte reproducible and never touch the machine.

## Why it exists

Language ecosystems have had lock files for years. The operating system
underneath usually has a hand-written `apt-get install` line and hope.

matsya gives OS packages what npm and Cargo already have:

| | |
|---|---|
| **Real lock files** | Exact version, architecture, install reason, holds, dependency graph, repository and signing key for every package, plus the SHA-256 from the signed repo metadata. |
| **One file, many machines** | Your Mac, the CI runner and the Raspberry Pi live side by side as environments (`macos-15-aarch64`, `ubuntu-24.04-x86_64`, `debian-12-aarch64`). |
| **Vanished versions still install** | Falls back to snapshot.debian.org, snapshot.ubuntu.com, Fedora Koji, the Arch Linux Archive or `brew extract`, and verifies the hash before installing. |
| **Reproducible SBOMs** | purls with `distro=` qualifiers (so Grype, Trivy and OSV pick the right advisories), SPDX license expressions, hashes and the full dependency graph. |
| **Reviewable** | Sorted, deterministic JSON. Re-locking an unchanged machine doesn't touch the file, so `git diff` shows exactly which packages moved. |
| **Zero dependencies** | One ~3 MB static binary with its own database readers and HTTPS client. `lock`, `check`, `diff` and `sbom` work with an empty `PATH`. Only `apply` calls the system package manager. |

## How it compares

| | Package list / Brewfile | Pinning (`apt-mark hold`, versionlock) | Syft / Trivy scan | Nix / Guix | **matsya** |
|---|:-:|:-:|:-:|:-:|:-:|
| Exact versions + hashes | no | partial | yes | yes | **yes** |
| Rebuild on another machine | names only | no | no | yes | **yes** |
| Locks the distro packages you already use | yes | yes | yes | no (own package set) | **yes** |
| Drift detection | no | no | diff by hand | yes | **yes** |
| SBOM | no | no | yes | via tools | **yes, from the lock** |
| macOS + Linux in one file | no | no | no | yes | **yes** |

The [deep dive](DEEP_DIVE.md) covers the trade-offs honestly, including when
Nix, snapshot mirrors or image digests are the better choice.

## Limitations, honestly

- Alpine, RHEL clones, openSUSE and Homebrew casks keep **no public archive**
  of old versions. A lock can only be replayed while those versions are still
  published, and matsya says so up front instead of guessing.
- Install scripts still run, so locking packages isn't the same as locking
  files. Pair it with an image digest if you need bit-for-bit.
- Homebrew dependency versions follow their formula.

See [Edge cases](EDGE_CASES.md) for the details.

## Why the name?

In the Matsya Purana, Vishnu takes the form of **Matsya**, a horned golden
fish, and warns the sage Manu of a great flood. Manu fills a boat with the
seeds of every plant, every kind of creature and the Vedas, and ties it to
Matsya's horn. The fish tows it safely through the deluge, and afterwards the
world is rebuilt from exactly what was saved.

That is the job: record everything a machine is made of, carry it safely,
and rebuild the same world somewhere else.

## Where to next

- [Install matsya](INSTALLATION.md)
- [Lock, check and rebuild your first machine](QUICK_START.md)
- [Every command and flag](COMMANDS.md)
