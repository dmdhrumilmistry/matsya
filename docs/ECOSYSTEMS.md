# Beyond the package manager

A machine is more than its distro packages. Command-line tools installed
with `pip`, `npm`, `cargo`, `go` or `gem`, snaps and flatpaks, binaries
dropped into `/usr/local/bin`, and apps copied into `/Applications` are part
of what makes it work. matsya records all of them in the same lock file,
next to the OS packages, as extra sections.

```console
$ matsya lock
matsya: locked ubuntu-24.04-x86_64 (apt: 785, cargo: 3, npm: 12, pip: 40, snap: 3, files: 2) -> matsya.lock.json
```

Like everything else in matsya, these are read **directly from disk**:
`lock`, `check`, `diff` and `sbom` never run `pip`, `npm` or any other tool.
A section is only written when something is actually installed through
that source.

## At a glance

| Source | What is recorded | Read from | `apply` can reinstall | SBOM purl |
|---|---|---|---|---|
| **pip** | Python packages installed with pip/uv, system-wide or `--user`, and pipx apps | `*.dist-info` in each site-packages directory | ✓ `python -m pip install name==ver` (and `pipx install`) | `pkg:pypi` |
| **npm** | Global packages (`npm install -g`) and their dependency tree | `<prefix>/lib/node_modules`, npm's hidden lockfile | ✓ `npm install -g name@ver` | `pkg:npm` |
| **cargo** | Programs from `cargo install` (crates.io, git or local path) | `~/.cargo/.crates2.json` | ✓ `cargo install --locked` with the same source and features | `pkg:cargo` |
| **go** | Programs from `go install` and every module they were built from | Build information embedded in the binaries | ✓ `go install path@version` | `pkg:golang` |
| **gem** | Ruby gems from `gem install` | `specifications/*.gemspec` | ✓ `gem install -v` | `pkg:gem` |
| **snap** | Snaps with their revision and channel | `/snap/<name>/current/meta/snap.yaml` | ✓ `snap install --revision` | `pkg:generic/snap/...` |
| **flatpak** | Apps and runtimes, system and per-user, pinned to the deployed commit | `/var/lib/flatpak`, `~/.local/share/flatpak` | ✓ `flatpak install` + `update --commit` | `pkg:generic/flatpak/...` |
| **files** | Executables in `/usr/local/bin`, `/usr/local/sbin`, `/opt/*/bin` that no package owns | The files themselves (SHA-256) | ✗ reported only | `pkg:generic/<name>` |
| **apps** | macOS apps in `/Applications` that are not Homebrew casks, including App Store apps | `Contents/Info.plist` | ✗ reported only | `pkg:generic/macos-app/...` |

Use the source names with `-m`, for example `matsya lock -m pip,npm` or
`matsya check -m files`.

## System-wide vs. per-user, and `sudo`

Most of these sources can install software for the whole machine or for one
user. matsya records which one it is (the `kind` field: `python3.12/system`,
`python3.12/user`, `pipx`, `system`, `user`, ...) and stores paths under the
home directory as `~/...`, so locks from different users and machines
compare cleanly.

- **Locking.** Under `sudo`, matsya reads per-user software from the home
  directory of the user who ran `sudo` (`SUDO_USER`), not from `/root`. So
  `sudo matsya lock` captures both halves in one go.
- **Applying.** System-wide installs need root and per-user installs must
  not run as root (they would land in `/root`). `apply` does the half it
  can and tells you about the other:

  ```console
  $ sudo matsya apply            # OS packages + system-wide pip/npm/gem/snap/flatpak
  matsya: warning: skipping per-user Python packages (python3.12/user): re-run as your normal user to apply them
  $ matsya apply -m pip,cargo,go # per-user installs, as yourself
  ```

  In Termux everything belongs to the app user, so a single run does it all.

## pip

Every `*.dist-info` directory in the system, Homebrew, python.org and user
site-packages directories is read:

- `METADATA` gives the name, version, license and `Requires-Dist`
  dependencies.
- `INSTALLER` says who installed it. Packages installed by the distro
  (`debian`, `rpm`, ...) belong to the OS package section and are skipped
  here, so nothing is counted twice.
- `REQUESTED` marks packages you asked for; everything else is recorded as a
  dependency.
- `direct_url.json` keeps VCS and URL installs (`git+https://...@<commit>`)
  so they are reinstalled from the same commit. Editable installs are
  recorded but not reinstalled: their source checkout is not portable.

pipx apps are recorded once per app, from `pipx_metadata.json`, and
reinstalled with `pipx install --force`.

On distributions that mark their Python as externally managed (PEP 668),
`apply` passes `--break-system-packages`. That only happens when the lock
already contains pip packages for that interpreter, which means they were
installed that way before.

## npm

Global packages are found in every npm prefix: `/usr/local`, `/usr`,
Homebrew, Termux, `~/.npm-global`, `~/.local`, a custom `prefix=` in
`~/.npmrc`, and every Node version managed by nvm. Each top-level package is
recorded as manual. npm's hidden lockfile (`node_modules/.package-lock.json`)
adds the full nested dependency tree with `sha512` integrity hashes, which
also end up in the SBOM.

`apply` installs the top-level packages with the npm of that prefix, at the
locked versions; npm brings their dependencies.

## cargo

`cargo install` records every install in `~/.cargo/.crates2.json` (or
`.crates.toml` on older Rust): crate, version, source, enabled features and
the binaries it put in `~/.cargo/bin`. `apply` reinstalls with
`cargo install --locked --force` from the same place:

| Installed from | Reinstalled with |
|---|---|
| crates.io | `cargo install name --version =1.2.3` |
| git | `cargo install --git <url> --rev <commit> name` |
| local path | `cargo install --path <dir>` (if the directory exists on the target) |

## Go

Every Go program built with Go 1.18 or later carries its build information:
main package, module version, `h1:` checksum, the Go version, and every
dependency module with its checksum. matsya reads it straight from the
binaries in `$GOBIN`, `$GOPATH/bin` and `~/go/bin`, without running
`go version -m`. The dependency modules are recorded too, so the SBOM lists
everything compiled into the program.

`apply` runs `go install path@version` into the same directory. Programs
built from a local checkout (version `(devel)`) are reported instead.

Go programs installed by hand into `/usr/local/bin` show up under **files**,
with their module and version filled in from the same build information.

## gem

Gems installed with `gem install` are read from their gemspecs in
`/var/lib/gems` (Debian/Ubuntu), `/usr/local/lib/ruby/gems`, Homebrew,
Termux and the per-user gem directories. Ruby's own default gems and gems
installed by the distro are skipped. A gem that another gem depends on is
recorded as a dependency. `apply` runs `gem install name --version` (with
`--user-install` for per-user gems).

## snap

For every snap under `/snap`, the active revision (`current`) and
`meta/snap.yaml` are read: version, type, confinement and base. When run as
root, the tracking channel is taken from snapd's state as well. Apps count as
manual, bases and snapd as dependencies.

`apply` installs or refreshes to the locked revision. The Snap Store only
serves revisions that are still published in a channel, so for older ones
use `--best-effort`, which follows the recorded channel instead.

## flatpak

Apps and runtimes are read from the system installation
(`/var/lib/flatpak`) and the per-user one (`~/.local/share/flatpak`). Each
entry records its ref (`app/org.gimp.GIMP/x86_64/stable`), the remote it
came from, the version from its AppStream metadata, and the **deployed
commit**, which works like a hash: `check` notices a different build of the
same version. Apps depend on the runtime they declare.

`apply` installs missing apps from their remote and pins every app to the
locked commit with `flatpak update --commit`.

## Unmanaged files

Executables in `/usr/local/bin`, `/usr/local/sbin`, `/opt/*/bin` (and
`$PREFIX/bin` in Termux) that no package manager owns are recorded with
their SHA-256 and size. Files owned by dpkg, rpm, apk or pacman, console
scripts installed by pip, RubyGems wrapper scripts and symlinks (Homebrew,
npm, alternatives) are left out. Go programs get their module and version.

These came from `make install`, a release tarball or `curl | sh`, so matsya
cannot reinstall them. `check` reports a missing or changed file, and
`apply` lists them as unresolved (or as warnings with `--best-effort`) so a
person can restore them.

## macOS apps

Apps in `/Applications` and `~/Applications` (and one level of vendor
folders) are read from their `Info.plist`, in XML or binary form: name,
bundle identifier, version and build. Apps installed by Homebrew casks are
left to the `brew` section and Apple's own apps are skipped. Apps with an
App Store receipt are marked `app-store`.

Like unmanaged files, they are reported rather than reinstalled: `check`
tells you which app is missing or at a different version, and from where to
get it.

## Not covered (yet)

- Software built and installed into home directories by hand.
- conda/mamba environments, virtualenvs inside projects, `uv tool`
  (pipx-like) installs and other language managers (Composer, NuGet, CPAN).
- Containers and VM images themselves.

Contributions are welcome: a new source implements the `Manager` trait in
`src/managers/` and a purl mapping in `src/sbom.rs`.
