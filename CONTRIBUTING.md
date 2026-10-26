# Contributing

* Zero runtime dependencies, Python 3.8+. Please keep it that way. syslock
  has to run on minimal systems.
* Run the tests: `PYTHONPATH=src python3 -m unittest discover -s tests -v`.
* Parser changes need a fixture in `tests/fixtures/` taken from real tool
  output (trim it, and keep the odd cases).
* Behaviour changes in `apply` should be exercised in `ci/inside.sh`, which
  runs in real containers for every supported distro.
* A new package manager is a `Manager` subclass in `src/syslock/managers/`
  implementing `available`, `capture`, `installed`, `prepare`, `plan` and
  `key_of`, registered in `managers/__init__.py`, plus a purl mapping in
  `sbom.py`.
* If you add an edge case, document it in `docs/EDGE_CASES.md`.
