#!/bin/sh
# Install the latest matsya release binary.
#
#   curl -fsSL https://raw.githubusercontent.com/dmdhrumilmistry/matsya/main/install.sh | sh
#
# Environment:
#   MATSYA_VERSION=v0.2.2   install a specific release (default: latest)
#   BIN_DIR=/some/dir       where to put the binary
#
# Works on Linux (x86_64, aarch64), macOS (arm64, x86_64) and Termux on
# Android (aarch64, x86_64, armv7). Root is never required: if the target
# directory is not writable and neither sudo nor doas is available, it
# installs to ~/.local/bin instead.
set -eu

REPO=dmdhrumilmistry/matsya

say() { printf '%s\n' "matsya-install: $*"; }
die() { printf '%s\n' "matsya-install: error: $*" >&2; exit 1; }

# --- platform -------------------------------------------------------------
termux=false
case "${PREFIX:-}" in *com.termux*) termux=true ;; esac
[ -n "${TERMUX_VERSION:-}" ] && termux=true

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) die "unsupported OS: $(uname -s)" ;;
esac
$termux && os=android

case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  armv7l | armv8l | armv7*) arch=armv7 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
if [ "$arch" = armv7 ] && [ "$os" != android ]; then
  die "32-bit ARM builds are only published for Termux"
fi
asset="matsya-$arch-$os"

# --- where to install -------------------------------------------------------
if [ -n "${BIN_DIR:-}" ]; then
  dir="$BIN_DIR"
elif $termux; then
  dir="$PREFIX/bin"
else
  dir=/usr/local/bin
fi

elevate=""
if [ -d "$dir" ] && [ -w "$dir" ]; then
  :
elif [ ! -e "$dir" ] && mkdir -p "$dir" 2>/dev/null; then
  :
elif [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  elevate=sudo
elif [ "$(id -u)" -ne 0 ] && command -v doas >/dev/null 2>&1; then
  elevate=doas
elif [ -z "${BIN_DIR:-}" ]; then
  dir="$HOME/.local/bin"
  mkdir -p "$dir"
  say "$dir is used because /usr/local/bin is not writable and sudo/doas are not available"
else
  die "$dir is not writable (and sudo/doas are not available)"
fi

# --- download and verify ----------------------------------------------------
if [ -n "${MATSYA_VERSION:-}" ]; then
  base="https://github.com/$REPO/releases/download/$MATSYA_VERSION"
else
  base="https://github.com/$REPO/releases/latest/download"
fi

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    die "need curl or wget to download"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    die "need sha256sum or shasum to verify the download"
  fi
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/matsya.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $asset"
fetch "$base/$asset" "$tmp/matsya" || die "download failed: $base/$asset"
fetch "$base/$asset.sha256" "$tmp/matsya.sha256" || die "download failed: $base/$asset.sha256"
want="$(cut -d' ' -f1 <"$tmp/matsya.sha256")"
got="$(sha256 "$tmp/matsya")"
[ "$want" = "$got" ] || die "checksum mismatch for $asset (expected $want, got $got)"
chmod +x "$tmp/matsya"

# --- install ------------------------------------------------------------------
$elevate mkdir -p "$dir"
$elevate mv "$tmp/matsya" "$dir/matsya"
say "installed $("$dir/matsya" --version) to $dir/matsya"

case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "add $dir to your PATH, e.g.: export PATH=\"$dir:\$PATH\"" ;;
esac
