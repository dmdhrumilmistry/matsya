#!/bin/sh
# Runs inside a distro container with the static matsya binary mounted at
# /src/bin/matsya. Nothing else is installed for matsya itself, so the
# locked system is exactly what the test put there.
#
# Phase "capture" builds a system, locks it and exercises drift detection
# and repair. Phase "restore" starts from a fresh container and rebuilds
# the same system from the lock: "use the lock on another device".
set -eu
PHASE="$1"
LOCK="$2"
M=/src/bin/matsya

if command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v zypper >/dev/null 2>&1; then PM=zypper
elif command -v dnf >/dev/null 2>&1; then PM=dnf
elif command -v yum >/dev/null 2>&1; then PM=yum
elif command -v apk >/dev/null 2>&1; then PM=apk
elif command -v pacman >/dev/null 2>&1; then PM=pacman
else echo "unknown package manager"; exit 1; fi

pm_install() {
  case $PM in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" ;;
    dnf) dnf install -y "$@" ;;
    yum) yum install -y "$@" ;;
    zypper) zypper --non-interactive install "$@" ;;
    apk) apk add "$@" ;;
    pacman) pacman -S --noconfirm --needed "$@" ;;
  esac
}
pm_remove() {
  case $PM in
    apt) DEBIAN_FRONTEND=noninteractive apt-get purge -y "$@" ;;
    dnf) dnf remove -y "$@" ;;
    yum) yum remove -y "$@" ;;
    zypper) zypper --non-interactive remove "$@" ;;
    apk) apk del "$@" ;;
    pacman) pacman -R --noconfirm "$@" ;;
  esac
}
refresh() {
  case $PM in
    apt) apt-get update -q ;;
    dnf) dnf -y makecache ;;
    yum) yum -y makecache ;;
    zypper) zypper --non-interactive refresh ;;
    apk) apk update ;;
    pacman) pacman -Sy --noconfirm ;;
  esac
}
expect_fail() {
  if "$@"; then echo "expected failure: $*"; exit 1; fi
}
same_file() {
  [ "$(sha256sum < "$1")" = "$(sha256sum < "$2")" ]
}

refresh
$M platform

if [ "$PHASE" = capture ]; then
  pm_install tree jq
  $M lock -f "$LOCK"
  $M validate -f "$LOCK"
  $M check -f "$LOCK"
  # Locking an unchanged system must not rewrite the file.
  cp "$LOCK" /tmp/before.json
  $M lock -f "$LOCK"
  same_file "$LOCK" /tmp/before.json
  $M sbom -f "$LOCK" -o "${LOCK%.lock.json}.cdx.json"
  $M sbom -f "$LOCK" --format spdx -o "${LOCK%.lock.json}.spdx.json"

  echo "== drift: remove a locked package, add an unlocked one"
  pm_remove tree
  pm_install nano
  expect_fail $M check -f "$LOCK"
  $M apply -f "$LOCK" --dry-run --no-refresh
  $M apply -f "$LOCK" --yes --prune --no-refresh
  $M check -f "$LOCK"
else
  echo "== fresh machine: rebuild from the lock"
  expect_fail $M check -f "$LOCK"
  $M apply -f "$LOCK" --yes
  $M check -f "$LOCK"
  command -v tree
  command -v jq
fi
echo "== $PHASE OK"
