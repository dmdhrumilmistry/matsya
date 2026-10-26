# Lock file format (lockfileVersion 1)

`syslock.lock.json` is UTF-8 JSON with sorted keys and two-space
indentation, ending in a newline. Package lists are sorted, so the same
system always produces the same bytes and `git diff` stays readable.

```jsonc
{
  "lockfileVersion": 1,
  "generator": { "name": "syslock", "version": "0.1.0" },
  "environments": {
    "ubuntu-24.04-x86_64": {
      "platform": {
        "os": "linux", "distro": "ubuntu", "idLike": ["debian"],
        "release": "24.04", "version": "24.04", "codename": "noble", "arch": "x86_64"
      },
      "capturedAt": "2026-10-26T08:38:26Z",   // also the snapshot archive timestamp
      "digest": "sha256:…",                  // over platform + managers
      "managers": {
        "apt": { … },
        "brew": { … }
      }
    }
  }
}
```

* **Environment id**: `<distro>-<release>-<arch>`. `release` is normalised:
  Alpine `3.20` (minor branch) or `edge`; RHEL family, Fedora and macOS the
  major version; rolling distros `rolling`; Debian testing/sid the codename.
* **arch** is canonical (`x86_64`, `aarch64`, `armv7`, `i686`, `ppc64le`,
  `s390x`, `riscv64`). Each package keeps its manager's own spelling
  (`amd64`, `noarch`, `any`, …).
* **digest**: SHA-256 of the canonical JSON of `{platform, managers}`.

## Common package fields

| Field | Meaning |
|---|---|
| `name` | Package name (brew: full name incl. tap; cask token) |
| `version` | Exact version as the manager prints it (rpm: `version-release`; deb/pacman include epoch) |
| `epoch` | rpm only, when non-zero |
| `arch` | Manager-native architecture |
| `reason` | `manual` (user asked for it) or `dependency` |
| `dependencies` | Keys of installed packages this one depends on (resolved through Provides/alternatives) |
| `repositories` | Repository ids the exact version was available from at capture time; `[]` means local / no longer published |
| `licenses` | License strings as declared by the package metadata |
| `source` | `{name, version?}` of the source package when it differs |

## Per-manager fields

**apt**: `sha256`, `size`, `filename` (pool path, used for snapshot
fallback), `held`, `essential`, `priority`. Section: `repositories[]`
(`id` = `Origin:suite/component`, `uris`, `architectures`, `origin`,
`label`, `codename`, `signedBy {path, sha256, package?, data?, armored?}`,
`trusted`), `foreignArchitectures`.

**rpm**: `payloadDigest`, `sigmd5`, `vendor`. Section: `frontend`,
`repositories[]` from `.repo` files (`baseurl`, `metalink`,
`mirrorlist`, `gpgkey`, …).

**apk**: `checksum` (`Q1…` control checksum), `commit` (aports git
commit), `worldEntry` (original world constraint/tag), `virtual`. Section:
`repositories[]` (`url`, `tag`), `keys[] {path, sha256, data?}`.

**pacman**: `sha256`, `size`, `filename`, `packager`. Section:
`repositories[] {id, servers}`.

**brew**: `kind` (`formula`/`cask`), `tap`, `bottles {tag: sha256}` (only
when the installed version is the formula's current version), `pinned`,
`outdated`, `builtFromSource`, `otherKegs`; casks: `sha256`, `url`,
`autoUpdates`. Section: `taps[] {name, remote, customRemote, commit}`,
`prefix`.

## Compatibility rules

* Readers must reject a `lockfileVersion` greater than they understand.
* Unknown fields must be preserved or ignored, never treated as errors.
  New optional fields don't bump the version.
* Fields starting with `_` are internal and never written.
