#!/bin/sh
# Install the latest matsya release binary.
#   curl -fsSL https://raw.githubusercontent.com/dmdhrumilmistry/matsya/main/install.sh | sh
# Set MATSYA_VERSION=v0.2.0 to pin a version, BIN_DIR to choose where it goes.
set -eu
REPO=dmdhrumilmistry/matsya
case "$(uname -s)" in Linux) os=linux ;; Darwin) os=macos ;; *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=x86_64 ;; aarch64|arm64) arch=aarch64 ;; *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;; esac
asset="matsya-$arch-$os"
if [ -n "${MATSYA_VERSION:-}" ]; then base="https://github.com/$REPO/releases/download/$MATSYA_VERSION"; else base="https://github.com/$REPO/releases/latest/download"; fi
dir="${BIN_DIR:-/usr/local/bin}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fetch() { if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$2" "$1"; else wget -qO "$2" "$1"; fi; }
fetch "$base/$asset" "$tmp/matsya"
fetch "$base/$asset.sha256" "$tmp/matsya.sha256"
want="$(cut -d' ' -f1 < "$tmp/matsya.sha256")"
if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$tmp/matsya" | cut -d' ' -f1)"; else got="$(shasum -a 256 "$tmp/matsya" | cut -d' ' -f1)"; fi
[ "$want" = "$got" ] || { echo "checksum mismatch for $asset" >&2; exit 1; }
chmod +x "$tmp/matsya"
if [ -w "$dir" ]; then mv "$tmp/matsya" "$dir/matsya"; else sudo mv "$tmp/matsya" "$dir/matsya"; fi
echo "installed $("$dir/matsya" --version) to $dir/matsya"
