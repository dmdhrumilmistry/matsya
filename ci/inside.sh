#!/bin/sh
# Runs inside a distro container. Phase "capture" builds a system, locks it
# and exercises drift detection + repair. Phase "restore" starts from a
# fresh container and rebuilds the same system from the lock, which is the
# "use the lock on another device" scenario.
set -eu
PHASE="$1"
LOCK="$2"
cd /src
export PYTHONPATH=/src/src

if command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v zypper >/dev/null 2>&1; then PM=zypper
elif command -v dnf >/dev/null 2>&1; then PM=dnf
elif command -v apk >/dev/null 2>&1; then PM=apk
elif command -v pacman >/dev/null 2>&1; then PM=pacman
else echo "unknown package manager"; exit 1; fi

pm_install() {
  case $PM in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" ;;
    dnf) dnf install -y "$@" ;;
    zypper) zypper --non-interactive install "$@" ;;
    apk) apk add "$@" ;;
    pacman) pacman -S --noconfirm --needed "$@" ;;
  esac
}
pm_remove() {
  case $PM in
    apt) DEBIAN_FRONTEND=noninteractive apt-get purge -y "$@" ;;
    dnf) dnf remove -y "$@" ;;
    zypper) zypper --non-interactive remove "$@" ;;
    apk) apk del "$@" ;;
    pacman) pacman -R --noconfirm "$@" ;;
  esac
}
bootstrap() {
  case $PM in
    apt) apt-get update -q ;;
    dnf) dnf -y makecache ;;
    zypper) zypper --non-interactive refresh ;;
    apk) apk update ;;
    pacman) pacman -Sy --noconfirm ;;
  esac
  if [ $PM = pacman ]; then pm_install python; else pm_install python3; fi
}
expect_fail() {
  if "$@"; then echo "expected failure: $*"; exit 1; fi
}
S="python3 -m syslock"

bootstrap
$S platform

if [ "$PHASE" = capture ]; then
  pm_install tree jq
  $S lock -f "$LOCK"
  $S validate -f "$LOCK"
  $S check -f "$LOCK"
  # Locking an unchanged system must not rewrite the file.
  cp "$LOCK" /tmp/before.json
  $S lock -f "$LOCK"
  python3 -c "import sys; sys.exit(open(sys.argv[1],'rb').read() != open(sys.argv[2],'rb').read())" "$LOCK" /tmp/before.json
  $S sbom -f "$LOCK" -o "${LOCK%.lock.json}.cdx.json"
  $S sbom -f "$LOCK" --format spdx -o "${LOCK%.lock.json}.spdx.json"

  echo "== drift: remove a locked package, add an unlocked one"
  pm_remove tree
  pm_install nano
  expect_fail $S check -f "$LOCK"
  $S apply -f "$LOCK" --dry-run --no-refresh
  $S apply -f "$LOCK" --yes --prune --no-refresh
  $S check -f "$LOCK"
else
  echo "== fresh machine: rebuild from the lock"
  expect_fail $S check -f "$LOCK"
  $S apply -f "$LOCK" --yes
  $S check -f "$LOCK"
  command -v tree
  command -v jq
fi
echo "== $PHASE OK"
