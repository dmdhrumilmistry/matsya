# Contributing

* matsya ships as one static binary. Keep dependencies pure Rust (no C
  libraries, no TLS stack: downloads go through the system's curl/wget/
  apt-helper and are verified by matsya).
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
