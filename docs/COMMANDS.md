# Command reference

```text
matsya [-v] <COMMAND> [OPTIONS]
```

Running `matsya` with no command prints a welcome screen. `matsya --help`
and `matsya <COMMAND> --help` list the options below, and `matsya --version`
prints the version.

| Command | What it does |
|---|---|
| [`platform`](#platform) | Show the detected platform and package managers |
| [`lock`](#lock) | Snapshot installed packages into the lock file |
| [`envs`](#envs) | List environments stored in the lock file |
| [`validate`](#validate) | Validate the lock file structure and digests |
| [`check`](#check-and-diff) | Exit 1 if the system drifted from the lock (for CI) |
| [`diff`](#check-and-diff) | Show differences between the lock and this system |
| [`apply`](#apply) | Install the locked versions on this machine |
| [`sbom`](#sbom) | Generate an SBOM from the lock file |
| [`export`](#export) | Export the lock as a Brewfile or a plain package list |

## Shared options

These options appear on several commands and always mean the same thing.

| Option | Meaning |
|---|---|
| `-v`, `--verbose` | Print executed commands. Works with every command. |
| `-f`, `--file FILE` | Lock file to use. Default: `matsya.lock.json`, or `syslock.lock.json` if only that exists. The `MATSYA_FILE` environment variable sets it too. |
| `-m`, `--managers LIST` | Comma separated subset of managers, for example `apt,brew`. Known names: `apt`, `rpm`, `apk`, `pacman`, `brew`, and for software outside the system package manager `pip`, `npm`, `cargo`, `go`, `gem`, `snap`, `flatpak`, `files`, `apps` (see [Beyond the package manager](ECOSYSTEMS.md)). Used by `lock`, `check`, `diff` and `apply`. |
| `--env ID` | Environment id inside the lock. Default: the one matching this machine. |
| `--allow-cross-release` | If no environment matches exactly, use the closest one from the same distro family. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, or no drift. |
| `1` | Drift found (`check`, and the verification step after `apply`), a digest mismatch (`validate`), or you answered "no" at a confirmation prompt. |
| `2` | Error. The message starts with `matsya: error:`. |

## platform

```sh
matsya platform
```

Prints the detected distro, release, architecture, the environment id this
machine would use, and the package managers matsya found, as JSON. No
options.

## lock

```sh
matsya lock [-f FILE] [-m LIST] [--env-id ID] [--replace] [--no-licenses] [--no-embed-keys] [--stdout]
```

Captures the installed packages of every detected manager and writes them
into this machine's environment in the lock file. Other environments in the
file are left alone. If nothing changed, the file isn't rewritten.

| Option | Meaning |
|---|---|
| `--env-id ID` | Override the environment id. Default: `<distro>-<release>-<arch>`. |
| `--replace` | Drop managers not captured this run from the environment. By default, a manager you skipped (for example with `-m`) keeps its previous section. |
| `--no-licenses` | Do not record license metadata. |
| `--no-embed-keys` | Do not embed third-party repository keys. |
| `--stdout` | Print the lock instead of writing the file. |

With `-m`, a requested manager that isn't available is an error. Without
it, a manager that fails to capture is skipped with a warning.

## envs

```sh
matsya envs [-f FILE]
```

Lists the environments in the lock with their capture time and package
counts. `*` marks the one that matches this machine.

## validate

```sh
matsya validate [-f FILE]
```

Checks the lock's structure and recomputes each environment's digest.
Exits 1 if a digest doesn't match, which means the file was edited by hand
or corrupted.

## check and diff

```sh
matsya check [OPTIONS]
matsya diff  [OPTIONS]
```

Both compare the lock with the live system (or with another lock) and print
missing (`-`), extra (`+`) and changed (`~`) packages. `diff` always exits
0. `check` exits 1 on drift, which makes it the one to use in CI and cron.

| Option | Meaning |
|---|---|
| `-f`, `-m`, `--env`, `--allow-cross-release` | See [shared options](#shared-options). |
| `--against LOCK[:ENV]` | Compare with an environment in another lock file instead of the system. Without `:ENV`, the environment with the same id is used. |
| `--integrity` | Also compare checksums. Slower, because it recaptures. Catches rebuilt packages with the same version but a different hash. |
| `--ignore-extra` | Packages installed but not locked are fine (they don't count as drift). |
| `--roots-only` | Only compare manually installed packages. Pairs with `apply --roots-only`. |
| `--json` | Print the result as JSON. |
| `--all` | Do not truncate long lists (by default each list stops at 50 entries). |

```sh
matsya check --ignore-extra
matsya diff --against other.lock.json:debian-12-x86_64
```

## apply

```sh
sudo matsya apply [OPTIONS]
```

Installs the locked versions with the native package manager, in one
transaction per manager, then restores install reasons and holds. Versions
that left the mirrors are downloaded from the distro archive and verified
before installing. Afterwards it runs `check` to confirm the result.

`apply` shows each step and asks before changing anything. Without a
terminal it refuses unless you pass `--yes`.

| Option | Meaning |
|---|---|
| `-f`, `-m`, `--env`, `--allow-cross-release` | See [shared options](#shared-options). |
| `-n`, `--dry-run` | Print the plan as a shell script and change nothing. |
| `--script FILE` | With `--dry-run`, write the script to this file. |
| `-y`, `--yes` | Do not ask for confirmation. |
| `--roots-only` | Pin only manually installed packages and let the solver pick dependencies. |
| `--prune` | Remove packages that are not in the lock (never essential ones, never kernels). |
| `--best-effort` | Install the newest version when the locked one is gone. Without it, unresolvable packages stop the run. |
| `--no-snapshot` | Do not fall back to snapshot archives, Koji, the Arch Linux Archive or `brew extract`. |
| `--add-repos` | Recreate third-party repositories and keys recorded in the lock. |
| `--no-refresh` | Skip `apt-get update`, `dnf makecache` and friends. |
| `--cache-dir DIR` | Download cache. Default `/var/cache/matsya` (in Termux, `$PREFIX/var/cache/matsya`). Also set by `MATSYA_CACHE`. |
| `--force` | Apply even if the environment's digest does not match. |

Root and Homebrew:

- System managers need root, so run `apply` with `sudo` (not needed for
  `--dry-run`, or in Termux, which owns its own prefix).
- Homebrew must not run as root. When run as root, matsya skips the brew
  section; apply it separately as your user with `matsya apply --managers brew`.

```sh
matsya apply --dry-run --script plan.sh   # review first
sudo matsya apply --yes --prune           # make the machine match exactly
```

## sbom

```sh
matsya sbom [-f FILE] [--env ID|all] [--format cyclonedx|spdx] [-o FILE|DIR]
```

Generates an SBOM from the lock file alone, without looking at the machine.

| Option | Meaning |
|---|---|
| `--format` | `cyclonedx` (default, CycloneDX 1.6) or `spdx` (SPDX 2.3). |
| `-o`, `--output` | Output file. `-` or no value means stdout. |
| `--env ID` | Which environment. With a single environment in the lock it's used automatically. |
| `--env all` | One SBOM per environment, written to the `-o` directory (default: the current directory) as `<env>.cdx.json` or `<env>.spdx.json`. |
| `--allow-cross-release` | See [shared options](#shared-options). |

If `-o` points to an existing directory, the file is written there as
`<env>.cdx.json` or `<env>.spdx.json`.

## export

```sh
matsya export [-f FILE] [--env ID] [--format list|brewfile] [--roots-only] [-o FILE]
```

| Option | Meaning |
|---|---|
| `--format list` | Default. One line per package: manager, name, version and architecture, separated by tabs. |
| `--format brewfile` | A Homebrew Bundle `Brewfile` from the environment's Homebrew section. |
| `--roots-only` | Only manually installed packages. |
| `-o`, `--output` | Write to a file instead of stdout. |

## Environment variables

| Variable | Effect |
|---|---|
| `MATSYA_FILE` | Default lock file path (same as `-f`). |
| `MATSYA_CACHE` | Default `apply --cache-dir`. |
| `NO_COLOR` | Disable colors. Colors only appear in a terminal anyway; pipes and CI logs get plain text. |
