# Edge cases and how matsya handles them

Each entry says what can go wrong and what matsya does about it. Covered
by tests = unit tests with fixtures in `tests/`. Covered by CI = real
containers in `.github/workflows/ci.yml`.

## Portability across machines

| Case | Handling |
|---|---|
| Same distro release, same arch | Exact match by environment id `<distro>-<release>-<arch>`. Full replay with hash checks. |
| Same release, different arch (amd64 lock on an arm64 box) | The environment is still chosen. Arch-specific packages are re-targeted to the native arch at the same version, and `all`/`noarch` stay as they are. The archive fallback is skipped for re-targeted packages because their hash can't be known. A warning is printed. |
| Different release of the same distro (22.04 lock on 24.04) | Refused by default. `--allow-cross-release` picks the closest environment from the same `ID`/`ID_LIKE` family. Add `--best-effort` to install the newest version where the exact one doesn't exist. |
| Derivative distros (Pop!_OS, Mint, Rocky vs Alma) | Matched through `ID_LIKE` only with `--allow-cross-release`. Versions usually differ, so expect `--best-effort`. |
| Several machines, one file | `environments` is a map. `matsya lock` only updates the current machine's entry. Use `matsya envs` to list them and `--env` to choose one. |
| macOS 14 lock on macOS 15 | Brew-only environments match on distro and arch and ignore the macOS release, because Homebrew versions don't depend on it. |
| macOS lock on Linux (or the reverse) for Homebrew | Choose it with `--env macos-15-aarch64`. Formula versions carry over. Bottle hashes are per platform (Homebrew reports the one it runs on), so on another platform Homebrew's own checksum verification applies instead of the lock's. Casks are skipped on Linux. |
| Rosetta shell on Apple Silicon | `sysctl.proc_translated` is checked so the platform reports `aarch64`, not `x86_64`. |
| 32-bit userland on a 64-bit kernel | The architecture comes from `dpkg --print-architecture` / `apk --print-arch`, not `uname -m`. |
| Lock file copied without its repos | Distro repos are assumed to exist on the target. Third-party repos and keys are embedded and recreated only with `--add-repos`. |

## Versions and naming

| Case | Handling |
|---|---|
| Epochs (`1:2.3-4`, rpm `EPOCHNUM`) | Kept verbatim for deb/pacman. Stored separately for rpm and put back into NEVRA (`name-1:ver-rel.arch`). purls: `epoch=` qualifier for rpm, `%3A`-safe version for deb. |
| `+`, `~` in versions (`1.0+dfsg~rc1`) | Kept verbatim. Percent-encoded in purls (`%2B`). |
| Multiarch (`libc6:amd64` + `libc6:i386`) | Keyed as `name:arch` for foreign archs. `apply` runs `dpkg --add-architecture` first if needed. |
| Multilib rpm (`glibc.x86_64` + `glibc.i686`) | Keyed as `name.arch` for non-native archs. |
| Several kernels installed at once (rpm install-only packages) | Marked `installonly` and keyed by version, so each kernel is its own entry. `--prune` never removes kernels. |
| Multiarch dependency edges (`libfoo:i386` → `libc6`) | Resolved to the satisfier of the same architecture (`libc6:i386`), then to arch-neutral ones. |
| Same name as formula and cask in Homebrew | Keyed separately (`cask:` prefix); the duplicate check includes `kind`. |
| Versioned formulae (`postgresql@16`) | The name is kept. `@` is percent-encoded in the purl as the purl spec requires. |
| Several kegs of one formula installed | The linked keg is recorded and the others are listed in `otherKegs`. |
| Formula from a third-party tap (`user/tap/foo`) | Full name kept, tap recorded with remote and commit. `apply` taps it first. |
| Binary NMU (Debian `+b1`, source version differs) | Source name and version recorded separately and exposed as `upstream=` in the purl. |
| `gpg-pubkey` pseudo-packages in rpm | Excluded. |
| Alpine virtual packages (`.build-deps`) | Marked `virtual` and recreated with `apk add --virtual` from their members. matsya's own pin group is ignored. |
| Alpine world entries with tags/constraints (`jq@edge`, `curl=8.9`) | The original entry is kept in `worldEntry`. Repository tags are re-applied on install using apk's `name@tag=version` syntax. |
| Older Homebrew version rebuilt with `brew extract` | Installed as `matsya/pins/foo@1.2`. `check`, re-applies and `--prune` treat it as `foo`, so it is not reinstalled or removed. Pins go on the formula that was actually installed. |

## System state

| Case | Handling |
|---|---|
| Half-installed / broken dpkg packages (`iU`, `iF`, `iH`) | Not locked. A warning names them. |
| Removed but config remains (`rc`) | Not locked. |
| Held packages | Recorded as `held`. Re-held after apply. `--allow-change-held-packages` is used so holds don't block replay. |
| Manual vs automatic install reasons | apt-mark, dnf `--userinstalled`, zypper `AutoInstalled`, apk world, pacman `%REASON%`, brew `installed_on_request`. Restored after apply, and only where they differ. Where the reason can't be read (yum, missing apt-mark), everything is marked manual and a warning is printed. |
| Locally installed `.deb`/`.rpm` (not from any repo) | `repositories: []` plus a warning at lock time. `apply` reports them as unresolved instead of guessing. |
| Stale or missing apt indexes (`rm -rf /var/lib/apt/lists` in Docker) | Warns that hashes can't be recorded. `apply` refreshes indexes by default. |
| Compressed apt indexes (`.lz4`, `.gz`) | Read through `apt-helper cat-file`, so any compression apt supports works. |
| zstd-compressed pacman sync dbs | gzip, zstd and plain tar databases are read natively. |
| Custom pacman `DBPath` | Read from `pacman-conf`. |
| Non-UTF-8 package metadata | Decoded with replacement; never crashes. |
| Minimal / distroless images without Python, curl or a shell toolchain | matsya is one static binary; archive downloads use curl, wget or apt's own `apt-helper`, whichever exists. |
| Localised tool output | Every command runs with `LC_ALL=C`. |
| Thousands of packages | Commands are batched to stay under `ARG_MAX`. Apt indexes are streamed rather than fully parsed. |
| Running as root with Homebrew present | Brew refuses root, so matsya skips brew under root and tells you to run `--managers brew` as your user. |
| Running `apply` without root | Refused for system managers. `--dry-run` works as any user. |
| `apply --roots-only` | The final verification and `check --roots-only` compare only manually installed packages, because dependencies were left to the solver. |
| zypper with an empty `AutoInstalled` file | Every package counts as user-installed (the file lists automatic ones). |
| No TTY (CI) | `apply` refuses to change anything unless `--yes` is given. |

## Repositories and archives

| Case | Handling |
|---|---|
| Version gone from the mirror (Debian/Ubuntu) | Download from `snapshot.debian.org` / `snapshot.ubuntu.com` using the pool path, verify SHA-256, then install the local file in the same apt transaction. The snapshot timestamp is the repository's own Release `Date` (recorded per repo), with the capture time as a fallback, so `SOURCE_DATE_EPOCH` or merged locks don't point at the wrong snapshot. |
| Third-party repo with several components (`stable test`) | `--add-repos` writes one `.sources` entry per URI and suite with all components and a single keyring, which apt requires. |
| Ubuntu ports vs main archive | Both snapshot archives are tried. |
| Version gone (Fedora) | Download from Koji. Verified by the rpm payload digest because Koji doesn't publish file hashes in the lock's terms. |
| Version gone (Arch) | Download from the Arch Linux Archive using the exact recorded filename and SHA-256. Warns about partial upgrades. |
| Version gone (Alpine, RHEL clones, openSUSE) | No public archive exists. Reported as unresolved, or the newest version is installed with `--best-effort`. |
| Version gone (Homebrew) | Recreated with `brew extract` into a local `matsya/pins` tap. Warns that this needs a homebrew-core clone and usually builds from source. |
| Old cask version | Can't be installed (Homebrew has no mechanism). Reported, or the newest is installed with `--best-effort`. |
| Third-party repo keys | Hashed always. The key bytes are embedded only when the keyring isn't owned by a distro package (`dpkg -S`, apk db ownership). `--no-embed-keys` disables embedding. |
| `trusted=yes` / unsigned repos | Flagged as `trusted: true` in the repository record so a reviewer sees it. |
| Inline `Signed-By` keys (deb822) | Hashed and embedded as armored data. |
| Same packages from several mirrors (cloud regional mirrors) | Repositories are identified by origin, suite and component (e.g. `Ubuntu:noble-updates/main`), not hostname, so locks from different regions agree. |
| Third-party repo that deletes old versions (e.g. vendor CLIs) | Shows up as "not available from any configured repository" at lock time, so you know before you need it. |

## Lock file integrity and collaboration

| Case | Handling |
|---|---|
| Re-locking an unchanged system | Byte-identical output; the file isn't rewritten (no git churn). |
| Lock produced at a fixed time for reproducible builds | `SOURCE_DATE_EPOCH` sets `capturedAt`. |
| Hand edits / corruption | Per-environment digest. `validate` fails and `apply` refuses without `--force`. |
| Git merge conflict markers in the lock | Detected with a specific hint (re-run `matsya lock` on each machine). |
| Lock from a newer matsya | `lockfileVersion` is checked and an upgrade is requested. |
| Partial capture (brew not installed in this container) | Existing manager sections in that environment are kept. `--replace` drops them. |
| Crash while writing | Writes go to a temp file followed by an atomic `rename`. |

## Known limitations (not handled)

* Packages installed outside a package manager (`/usr/local`, `curl | sh`,
  pip/npm/cargo globals, snaps, flatpaks, Mac App Store) are not captured.
* File-level drift inside packages (edited configs, deleted files) is not
  checked. Use `debsums`, `rpm -V`, `apk audit` or `pacman -Qkk` for that.
* Configuration of the package manager itself (apt preferences/pinning,
  dnf modules and streams, zypper patterns, Homebrew service state) is not
  replayed.
* RHEL subscription repos, Ubuntu Pro/ESM and other authenticated repos
  need credentials on the target; they are not stored in the lock.
* Gentoo, Void, NixOS, Solus and other package managers are not supported
  yet. The `Manager` interface in `src/managers/mod.rs` is the
  extension point.
