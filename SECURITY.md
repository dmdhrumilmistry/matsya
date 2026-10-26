# Security policy

Please report vulnerabilities privately via
[GitHub security advisories](https://github.com/dmdhrumilmistry/matsya/security/advisories/new)
rather than public issues.

matsya runs package managers as root during `apply`. In scope:

* a lock file that makes `apply` run unintended commands or write outside
  the paths described in the plan;
* bypasses of hash verification for archive downloads;
* repositories or keys being added without `--add-repos`.

The lock digest detects accidental edits, not malicious ones. Treat lock
files from untrusted sources like any other code you'd run as root:
review `matsya apply --dry-run` output first, and sign lock files if you
distribute them.
