# Quick start

Four commands cover the whole life of a machine: **lock**, **sbom**,
**check** and **apply**.

## 1. Lock this machine

```console
$ matsya lock
matsya: capturing apt ...
matsya: locked ubuntu-24.04-x86_64 (apt: 744) -> matsya.lock.json
```

matsya reads the package databases directly and writes a sorted,
deterministic `matsya.lock.json`. Commit it to git. Running `matsya lock`
again on an unchanged machine leaves the file untouched.

## 2. Generate an SBOM

```sh
matsya sbom -o sbom.cdx.json                    # CycloneDX 1.6
matsya sbom --format spdx -o sbom.spdx.json     # SPDX 2.3
```

The SBOM is built from the lock alone, so it never touches the machine and
is reproducible byte for byte.

## 3. Detect drift

```console
$ matsya check
environment: ubuntu-24.04-x86_64
[apt] 1 extra, 2 changed
  + cowsay 3.03+dfsg2-8build1  (installed, not locked)
  ~ jq 1.8.1-4ubuntu2 -> 1.8.1-4ubuntu1
matsya: drift detected
```

`check` exits 1 on drift and 0 when the system matches. Add
`--ignore-extra` if extra packages are fine.

## 4. Rebuild on another machine

Copy `matsya.lock.json` to the other machine and preview first:

```sh
matsya apply --dry-run          # prints the plan as a shell script
sudo matsya apply               # installs the exact locked versions
```

`apply` installs everything in one transaction with the native package
manager, restores install reasons and holds, and then runs `check` to
verify the result.

## One lock, many machines

A lock file holds one **environment** per machine type:

```console
$ matsya envs
* ubuntu-24.04-x86_64     2026-10-26T08:38:26Z   apt=744
  debian-12-aarch64       2026-10-20T10:02:11Z   apt=391
  macos-15-aarch64        2026-10-25T17:40:03Z   brew=86
```

The `*` marks the environment that matches this machine.

- `matsya lock` only updates the current machine's environment.
- `apply` picks the matching environment automatically.
- The same release on another architecture works: packages are re-targeted.
- Another release of the distro needs `--allow-cross-release`.
- `--env ID` always lets you choose.

## Next steps

- [Command reference](COMMANDS.md) for every flag.
- [CI and Dockerfile recipes](CI.md) to automate it.
- [Edge cases](EDGE_CASES.md) to see what happens in tricky situations.
