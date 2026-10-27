#!/bin/sh
# Software outside the system package manager, in a Debian container:
# system-wide pip/npm/gem installs and a hand-placed /usr/local/bin file,
# plus per-user pip, cargo and go installs for the user "dev".
#   capture: install, lock (as root with SUDO_USER=dev), drift, repair
#   restore: fresh container, rebuild from the lock (root, then dev)
set -eu
PHASE="$1"
LOCK="$2"
M=/src/bin/matsya
export DEBIAN_FRONTEND=noninteractive

expect_fail() {
  if "$@"; then echo "expected failure: $*"; exit 1; fi
}
as_dev() {
  su dev -c "export PATH=\$HOME/.cargo/bin:\$HOME/go/bin:\$HOME/.local/bin:/usr/local/go/bin:\$PATH; $*"
}

apt-get update -q
apt-get install -y -q --no-install-recommends python3-pip npm ruby golang-go cargo ca-certificates git >/dev/null
useradd -m dev
cp -r /src/ci/fixtures/hello-crate /home/dev/hello-crate && chown -R dev /home/dev/hello-crate
# A hand-installed tool (the kind `make install` leaves behind).
printf '#!/bin/sh\necho hi\n' > /usr/local/bin/hello-tool
chmod +x /usr/local/bin/hello-tool

if [ "$PHASE" = capture ]; then
  pip install -q --break-system-packages 'six==1.16.0'
  npm install -g --silent 'is-number@7.0.0'
  gem install rake -v 13.2.1 --no-document
  as_dev "pip install -q --user --break-system-packages 'idna==3.7'"
  as_dev "cargo install --quiet --path /home/dev/hello-crate"
  as_dev "go install github.com/rakyll/hey@v0.1.4"

  SUDO_USER=dev $M lock -f "$LOCK"
  echo "== sections:"; grep -o '"\(pip\|npm\|gem\|cargo\|go\|files\)": {' "$LOCK" | sort
  SUDO_USER=dev $M check -f "$LOCK"
  $M sbom -f "$LOCK" -o "${LOCK%.lock.json}.cdx.json"
  for p in pkg:pypi/six@1.16.0 pkg:pypi/idna@3.7 pkg:npm/is-number@7.0.0 pkg:gem/rake@13.2.1 \
           pkg:cargo/matsya-ci-hello@0.1.0 pkg:golang/github.com/rakyll/hey@v0.1.4 "pkg:generic/hello-tool@"; do
    grep -q "\"$p" "${LOCK%.lock.json}.cdx.json" || { echo "SBOM is missing $p"; exit 1; }
  done

  echo "== drift: remove system pip/npm/gem packages"
  pip uninstall -y -q --break-system-packages six
  npm uninstall -g --silent is-number
  gem uninstall -x -I rake -v 13.2.1 || true  # Debian also ships a vendor rake
  expect_fail env SUDO_USER=dev $M check -f "$LOCK"
  SUDO_USER=dev $M apply -f "$LOCK" --yes --no-refresh -m pip,npm,gem,files
  SUDO_USER=dev $M check -f "$LOCK"
else
  echo "== fresh machine: rebuild from the lock"
  expect_fail env SUDO_USER=dev $M check -f "$LOCK"
  # System-wide parts as root, per-user parts as the user.
  SUDO_USER=dev $M apply -f "$LOCK" --yes --no-refresh -m pip,npm,gem,files
  as_dev "$M apply -f $LOCK --yes --no-refresh -m pip,cargo,go"
  SUDO_USER=dev $M check -f "$LOCK"
  as_dev "matsya-ci-hello && command -v hey"
fi
echo "== ecosystems $PHASE OK"
