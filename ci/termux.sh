#!/data/data/com.termux/files/usr/bin/sh
# Runs inside termux/termux-docker as the Termux user, with the Android build
# of matsya at /src/bin/matsya. Same cycle as ci/inside.sh: lock, drift,
# repair; then rebuild a fresh container from the lock.
set -eu
PHASE="$1"
LOCK="$2"
M="$HOME/matsya"
cp /src/bin/matsya "$M"
chmod +x "$M"

expect_fail() {
  if "$@"; then echo "expected failure: $*"; exit 1; fi
}

apt-get update -q
"$M" platform

if [ "$PHASE" = capture ]; then
  apt-get install -y tree jq
  "$M" lock -f "$LOCK"
  "$M" validate -f "$LOCK"
  "$M" check -f "$LOCK"
  echo "== no external tools: empty PATH"
  env -i HOME="$HOME" PATH=/nonexistent "$M" check -f "$LOCK"
  "$M" sbom -f "$LOCK" -o "${LOCK%.lock.json}.cdx.json"
  "$M" sbom -f "$LOCK" --format spdx -o "${LOCK%.lock.json}.spdx.json"

  echo "== drift: remove a locked package, add an unlocked one"
  apt-get remove -y tree
  apt-get install -y nano
  expect_fail "$M" check -f "$LOCK"
  "$M" apply -f "$LOCK" --dry-run --no-refresh
  "$M" apply -f "$LOCK" --yes --prune --no-refresh
  "$M" check -f "$LOCK"
else
  echo "== fresh Termux: rebuild from the lock"
  expect_fail "$M" check -f "$LOCK"
  "$M" apply -f "$LOCK" --yes
  "$M" check -f "$LOCK"
  command -v tree
  command -v jq
fi
echo "== termux $PHASE OK"
