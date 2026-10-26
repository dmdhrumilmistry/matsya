# Contributing

* matsya ships as one static binary and must not depend on other
  programs: `lock`, `check`, `diff`, `sbom` and `validate` read package
  databases directly (dpkg status, rpmdb sqlite/ndb/BerkeleyDB, apk and
  pacman databases, Homebrew's Cellar and API cache) and download with a
  built-in HTTPS client. Only `apply` runs the system package manager,
  because installing is its job. CI enforces this by running
  lock/check/sbom with an empty `PATH`.
* Building the static Linux binary needs `musl-gcc` (`apt install
  musl-tools`) because the TLS library compiles a little C/assembly.
* Before sending a change: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.
* Parser changes need a fixture in `tests/fixtures/` taken from real tool
  output (trim it, and keep the odd cases).
* The lock format is a contract (docs/LOCKFILE.md): new fields must be
  optional and old lock files must keep their digests. The
  `python_written_examples_roundtrip` test guards this.
* Behaviour changes in `apply` should be exercised in `ci/inside.sh`, which
  runs in real containers for every supported distro.
* A new package manager implements the `Manager` trait in
  `src/managers/`, is registered in `managers::all()`, and gets a purl
  mapping in `src/sbom.rs`.
* If you add an edge case, document it in `docs/EDGE_CASES.md`.
