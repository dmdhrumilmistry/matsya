# Installation

matsya is a single static binary. Pick whichever method suits you.

## Install script (recommended)

```sh
curl -fsSL https://raw.githubusercontent.com/dmdhrumilmistry/matsya/main/install.sh | sh
```

The script detects your OS and architecture, downloads the matching
[release binary](https://github.com/dmdhrumilmistry/matsya/releases/latest)
and its `.sha256` file, and refuses to install if the checksum doesn't
match. It works with either `curl` or `wget`.

### Where it installs, and when it asks for root

Root is never required. The script picks the target directory like this:

1. `BIN_DIR`, if you set it.
2. In Termux, `$PREFIX/bin`.
3. Otherwise `/usr/local/bin`.

If that directory isn't writable, it uses `sudo` or `doas` just for the
final `mv`. If neither is available (and you didn't set `BIN_DIR`), it
installs to `~/.local/bin` instead and tells you to add it to your `PATH`
if needed.

### Options

| Variable | Effect |
|---|---|
| `MATSYA_VERSION=v0.2.2` | Install a specific release instead of the latest. |
| `BIN_DIR=/some/dir` | Install into this directory. |

```sh
curl -fsSL https://raw.githubusercontent.com/dmdhrumilmistry/matsya/main/install.sh | BIN_DIR="$HOME/bin" sh
```

### Termux (Android)

The same command works inside Termux. The script notices Termux, downloads
the native Android build (`aarch64`, `x86_64` or `armv7`) and installs it
into `$PREFIX/bin`. No root is involved.

## Cargo

```sh
cargo install matsya                                             # from crates.io
cargo install --locked --git https://github.com/dmdhrumilmistry/matsya   # latest main
```

## Release binaries

Every [release](https://github.com/dmdhrumilmistry/matsya/releases) ships
these binaries, each with a `.sha256` file:

| Asset | Platform |
|---|---|
| `matsya-x86_64-linux` | Linux x86_64 (static musl build) |
| `matsya-aarch64-linux` | Linux aarch64 (static musl build) |
| `matsya-aarch64-macos` | macOS on Apple Silicon |
| `matsya-x86_64-macos` | macOS on Intel |
| `matsya-aarch64-android` | Termux on 64-bit ARM phones |
| `matsya-x86_64-android` | Termux on x86_64 (emulators, Chromebooks) |
| `matsya-armv7-android` | Termux on 32-bit ARM |

```sh
curl -fsSLO https://github.com/dmdhrumilmistry/matsya/releases/latest/download/matsya-x86_64-linux
curl -fsSLO https://github.com/dmdhrumilmistry/matsya/releases/latest/download/matsya-x86_64-linux.sha256
sha256sum -c matsya-x86_64-linux.sha256
chmod +x matsya-x86_64-linux && sudo mv matsya-x86_64-linux /usr/local/bin/matsya
```

### Verify build provenance

Release binaries are built in GitHub Actions and carry a
[build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations).
With the GitHub CLI you can prove a binary came from this repository's
release workflow:

```sh
gh attestation verify matsya-x86_64-linux -R dmdhrumilmistry/matsya
```

## In a container

You can copy the binary into a container, run it, and delete it again.
Nothing it needs ends up in the image or in the lock. See
[CI and Dockerfile recipes](CI.md).

## Check that it works

```console
$ matsya --version
$ matsya platform        # what matsya detects on this machine
```

Running `matsya` with no arguments prints a short welcome screen.
Continue with the [quick start](QUICK_START.md).
