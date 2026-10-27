# CI and Dockerfile recipes

matsya is one static binary with no runtime dependencies, so it drops into
any pipeline or image. `lock`, `check`, `diff` and `sbom` even work with an
empty `PATH`.

## GitHub Actions

Fail the build when the runner or base image drifts, and publish an SBOM:

```yaml
- run: curl -fsSL https://raw.githubusercontent.com/dmdhrumilmistry/matsya/main/install.sh | sh
- run: matsya check --ignore-extra        # fail the build if the base image drifted
- run: matsya sbom -o sbom.cdx.json       # attach to the release, feed to Grype/Trivy
```

`check` exits 1 on drift and 2 on errors, so the step fails in both cases.

### Machine-readable output

```sh
matsya check --json > drift.json     # still exits 1 on drift
```

### One SBOM per environment

If one lock describes several machines, write an SBOM for each:

```sh
mkdir -p sboms
matsya sbom --env all -o sboms                  # sboms/<env>.cdx.json
matsya sbom --env all --format spdx -o sboms    # sboms/<env>.spdx.json
```

### Compare two machines

```sh
matsya diff --against production.lock.json:ubuntu-24.04-x86_64
```

## Dockerfile

Copy the binary in, apply the lock, verify, and remove the binary again.
Nothing it needs ends up in the image.

```dockerfile
ADD --chmod=755 https://github.com/dmdhrumilmistry/matsya/releases/latest/download/matsya-x86_64-linux /usr/local/bin/matsya
COPY matsya.lock.json .
RUN matsya apply --yes && matsya check && rm /usr/local/bin/matsya
```

Use `matsya-aarch64-linux` for arm64 images. Pin a release by replacing
`latest/download` with `download/<tag>`.

### Lock an existing image

```sh
chmod +x matsya-x86_64-linux
docker run --rm -v "$PWD:/work" -w /work \
  -v "$PWD/matsya-x86_64-linux:/usr/local/bin/matsya:ro" \
  debian:12 matsya lock
```

The lock is written to the mounted directory. Run it against each image
you care about and they all end up in one file as separate environments.

## Review before you apply

Treat lock files like code you run as root. Preview the plan, keep it as an
artifact, then apply:

```sh
matsya apply --dry-run --script plan.sh
sudo matsya apply --yes
```

## Scheduled drift checks

A cron entry that reports when a server drifts (cron mails the output to the job owner):

```cron
0 6 * * * cd /etc/matsya && matsya check --ignore-extra || echo "drift on $(hostname)"
```

## Tips

- Commit `matsya.lock.json`. Re-locking an unchanged machine doesn't touch
  it, so `git diff` shows exactly which packages moved.
- Use `--roots-only` on both `apply` and `check` when you only care about
  the packages you asked for, not their dependencies.
- `matsya validate` in CI catches hand-edited or corrupted lock files.
