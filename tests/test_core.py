"""Lock file handling, environment selection, diff and SBOM output."""

import copy
import json
import os
import tempfile
import unittest

from syslock import lockfile, platform, sbom
from syslock.diff import diff_sections, has_drift
from syslock.util import SyslockError

UBU = {"os": "linux", "distro": "ubuntu", "idLike": ["debian"], "release": "24.04", "version": "24.04",
       "codename": "noble", "arch": "x86_64"}


def sample_lock():
    data = lockfile.empty()
    env = {
        "platform": UBU,
        "capturedAt": "2024-06-01T00:00:00Z",
        "managers": {"apt": {"packages": [
            {"name": "curl", "version": "8.5.0-2ubuntu10.1", "arch": "amd64", "reason": "manual",
             "dependencies": ["libcurl4t64"], "sha256": "a" * 64, "licenses": ["curl", "GPL-2+"],
             "source": {"name": "curl", "version": "8.5.0-2ubuntu10.1"}},
            {"name": "libcurl4t64", "version": "8.5.0-2ubuntu10.1", "arch": "amd64", "reason": "dependency"},
            {"name": "libc6", "version": "2.39-0ubuntu8", "arch": "i386", "reason": "dependency"},
            {"name": "dpkg", "version": "1:1.22.6ubuntu6", "arch": "amd64", "reason": "dependency"},
        ]}},
    }
    lockfile.put_environment(data, platform.env_id(UBU), env)
    return data


class LockfileTests(unittest.TestCase):
    def test_roundtrip_and_digest(self):
        data = sample_lock()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.lock.json")
            lockfile.save(data, path)
            first = open(path).read()
            loaded = lockfile.load(path)
            lockfile.save(loaded, path)
            self.assertEqual(first, open(path).read())  # deterministic bytes
            self.assertEqual(lockfile.check_digests(loaded), [])
            loaded["environments"]["ubuntu-24.04-x86_64"]["managers"]["apt"]["packages"][0]["version"] = "9"
            self.assertEqual(lockfile.check_digests(loaded), ["ubuntu-24.04-x86_64"])

    def test_rejects_future_version_and_conflicts(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.json")
            with open(p, "w") as fh:
                json.dump({"lockfileVersion": 99, "environments": {}}, fh)
            with self.assertRaisesRegex(SyslockError, "newer than this syslock"):
                lockfile.load(p)
            with open(p, "w") as fh:
                fh.write('{\n<<<<<<< HEAD\n"a": 1\n=======\n')
            with self.assertRaisesRegex(SyslockError, "merge conflict"):
                lockfile.load(p)

    def test_duplicates_detected(self):
        data = sample_lock()
        pk = data["environments"]["ubuntu-24.04-x86_64"]["managers"]["apt"]["packages"]
        pk.append(dict(pk[0]))
        self.assertTrue(any("duplicate" in m for m in lockfile.validate(data)))

    def test_merge_keeps_other_managers(self):
        data = sample_lock()
        eid = "ubuntu-24.04-x86_64"
        lockfile.put_environment(data, eid, {"platform": UBU, "capturedAt": "x", "managers": {"brew": {"packages": []}}})
        self.assertEqual(set(data["environments"][eid]["managers"]), {"apt", "brew"})
        lockfile.put_environment(data, eid, {"platform": UBU, "capturedAt": "x", "managers": {"brew": {"packages": []}}},
                                 replace_managers=True)
        self.assertEqual(set(data["environments"][eid]["managers"]), {"brew"})

    def test_source_date_epoch(self):
        os.environ["SOURCE_DATE_EPOCH"] = "0"
        try:
            self.assertEqual(lockfile.now_utc(), "1970-01-01T00:00:00Z")
        finally:
            del os.environ["SOURCE_DATE_EPOCH"]

    def test_strip_private(self):
        self.assertEqual(lockfile.strip_private({"a": 1, "_b": 2, "c": None, "d": [{"_e": 1, "f": 2}]}),
                         {"a": 1, "d": [{"f": 2}]})


class SelectTests(unittest.TestCase):
    def test_selection_rules(self):
        data = sample_lock()
        self.assertEqual(lockfile.select_environment(data, UBU, None, False), "ubuntu-24.04-x86_64")
        arm = dict(UBU, arch="aarch64")
        self.assertEqual(lockfile.select_environment(data, arm, None, False), "ubuntu-24.04-x86_64")  # same release, other arch
        newer = dict(UBU, release="26.04")
        with self.assertRaisesRegex(SyslockError, "allow-cross-release"):
            lockfile.select_environment(data, newer, None, False)
        self.assertEqual(lockfile.select_environment(data, newer, None, True), "ubuntu-24.04-x86_64")
        debian = {"distro": "debian", "idLike": [], "release": "12", "arch": "x86_64"}
        self.assertEqual(lockfile.select_environment(data, debian, None, True), "ubuntu-24.04-x86_64")  # ID_LIKE family
        fedora = {"distro": "fedora", "idLike": [], "release": "40", "arch": "x86_64"}
        with self.assertRaises(SyslockError):
            lockfile.select_environment(data, fedora, None, True)
        with self.assertRaises(SyslockError):
            lockfile.select_environment(data, UBU, "nope", False)

    def test_brew_only_ignores_macos_release(self):
        data = lockfile.empty()
        mac15 = {"os": "macos", "distro": "macos", "idLike": [], "release": "15", "arch": "aarch64"}
        lockfile.put_environment(data, "macos-15-aarch64", {"platform": mac15, "managers": {"brew": {"packages": []}}})
        self.assertEqual(lockfile.select_environment(data, dict(mac15, release="26"), None, False), "macos-15-aarch64")


class PlatformTests(unittest.TestCase):
    def test_os_release_variants(self):
        cases = {
            'ID=alpine\nVERSION_ID=3.20.3\n': ("alpine", "3.20"),
            'ID=alpine\nVERSION_ID=3.21_alpha20240923\n': ("alpine", "edge"),
            'ID=arch\nBUILD_ID=rolling\n': ("arch", "rolling"),
            'ID=debian\nVERSION_CODENAME=trixie\n': ("debian", "trixie"),
            'ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.4"\n': ("rocky", "9"),
            'ID="opensuse-tumbleweed"\nVERSION_ID="20241020"\n': ("opensuse-tumbleweed", "rolling"),
            "ID=ubuntu\nVERSION_ID='24.04'\n": ("ubuntu", "24.04"),
        }
        for text, (distro, release) in cases.items():
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(text)
            try:
                plat = platform.detect(fh.name)
            finally:
                os.unlink(fh.name)
            if plat["os"] != "linux":
                self.skipTest("os-release parsing is only used on Linux")
            self.assertEqual((plat["distro"], plat["release"]), (distro, release), text)

    def test_arch_normalisation(self):
        self.assertEqual(platform.normalize_arch("amd64"), "x86_64")
        self.assertEqual(platform.normalize_arch("arm64"), "aarch64")
        self.assertEqual(platform.normalize_arch("armhf"), "armv7")
        self.assertEqual(platform.normalize_arch("ppc64el"), "ppc64le")


class DiffTests(unittest.TestCase):
    def test_diff(self):
        locked = sample_lock()["environments"]["ubuntu-24.04-x86_64"]["managers"]["apt"]["packages"]
        current = copy.deepcopy(locked)
        current[0]["version"] = "8.5.0-2ubuntu10.2"
        current[1]["sha256"] = "b" * 64
        locked = copy.deepcopy(locked)
        locked[1]["sha256"] = "c" * 64
        current.append({"name": "vim", "version": "1", "arch": "amd64"})
        del current[2]
        r = diff_sections("apt", locked, UBU, current, UBU)
        self.assertEqual([x["name"] for x in r["changed"]], ["curl"])
        self.assertEqual([x["name"] for x in r["missing"]], ["libc6:i386"])
        self.assertEqual([x["name"] for x in r["extra"]], ["vim"])
        self.assertEqual([x["name"] for x in r["integrity"]], ["libcurl4t64"])
        self.assertTrue(has_drift({"apt": r}))

    def test_cross_arch_diff_matches_native_packages(self):
        locked = sample_lock()["environments"]["ubuntu-24.04-x86_64"]["managers"]["apt"]["packages"]
        arm = dict(UBU, arch="aarch64")
        current = [dict(p, arch="arm64") if p["arch"] == "amd64" else p for p in copy.deepcopy(locked)]
        r = diff_sections("apt", locked, UBU, current, arm)
        self.assertFalse(has_drift({"apt": r}))


class SbomTests(unittest.TestCase):
    def test_purls(self):
        p = {"name": "dpkg", "version": "1:1.22.6ubuntu6", "arch": "amd64"}
        self.assertEqual(sbom.purl("apt", p, UBU), "pkg:deb/ubuntu/dpkg@1:1.22.6ubuntu6?arch=amd64&distro=ubuntu-24.04")
        p = {"name": "libstdc++6", "version": "14.2.0-4", "arch": "amd64", "source": {"name": "gcc-14", "version": "14.2.0-4"}}
        self.assertEqual(sbom.purl("apt", p, UBU),
                         "pkg:deb/ubuntu/libstdc%2B%2B6@14.2.0-4?arch=amd64&distro=ubuntu-24.04&upstream=gcc-14%4014.2.0-4")
        fed = {"distro": "fedora", "release": "40"}
        self.assertEqual(sbom.purl("rpm", {"name": "openssl-libs", "version": "3.2.2-3.fc40", "arch": "x86_64", "epoch": 1}, fed),
                         "pkg:rpm/fedora/openssl-libs@3.2.2-3.fc40?arch=x86_64&distro=fedora-40&epoch=1")
        self.assertEqual(sbom.purl("rpm", {"name": "bash", "version": "5.2-1.el9", "arch": "x86_64"}, {"distro": "rhel", "release": "9"}),
                         "pkg:rpm/redhat/bash@5.2-1.el9?arch=x86_64&distro=rhel-9")
        arch = {"distro": "arch", "release": "rolling"}
        self.assertEqual(sbom.purl("pacman", {"name": "curl", "version": "1:8.10.1-1", "arch": "x86_64"}, arch),
                         "pkg:alpm/arch/curl@1:8.10.1-1?arch=x86_64&distro=arch")
        alp = {"distro": "alpine", "release": "3.20"}
        self.assertEqual(sbom.purl("apk", {"name": "musl", "version": "1.2.5-r0", "arch": "x86_64"}, alp),
                         "pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=alpine-3.20")
        mac = {"distro": "macos"}
        self.assertEqual(sbom.purl("brew", {"name": "postgresql@16", "version": "16.4", "tap": "homebrew/core"}, mac),
                         "pkg:brew/postgresql%4016@16.4")
        self.assertEqual(sbom.purl("brew", {"name": "Acme/Tools/mytool", "version": "1.0", "tap": "Acme/Tools"}, mac),
                         "pkg:brew/acme/tools/mytool@1.0")
        self.assertEqual(sbom.purl("brew", {"name": "firefox", "version": "131.0", "kind": "cask", "tap": "homebrew/cask"}, mac),
                         "pkg:brew/homebrew/cask/firefox@131.0")

    def test_licenses(self):
        ids, names = sbom._license_ids(["GPL-2+ and MIT", "Expat", "LicenseRef-Fedora-Public-Domain", "public-domain"])
        self.assertEqual(ids, ["GPL-2.0-or-later", "MIT"])
        self.assertEqual(names, ["LicenseRef-Fedora-Public-Domain", "public-domain"])

    def test_cyclonedx_structure(self):
        data = sample_lock()
        env = data["environments"]["ubuntu-24.04-x86_64"]
        doc = sbom.cyclonedx("ubuntu-24.04-x86_64", env)
        self.assertEqual(doc["specVersion"], "1.6")
        refs = {c["bom-ref"] for c in doc["components"]}
        self.assertEqual(len(refs), 4)
        for d in doc["dependencies"]:
            for t in d["dependsOn"]:
                self.assertIn(t, refs)
        curl = next(c for c in doc["components"] if c["name"] == "curl")
        self.assertEqual(curl["hashes"], [{"alg": "SHA-256", "content": "a" * 64}])
        self.assertEqual(doc, sbom.cyclonedx("ubuntu-24.04-x86_64", env))  # deterministic
        self.assertEqual(doc["dependencies"][0]["dependsOn"], [curl["bom-ref"]])  # roots hang off the OS

    def test_spdx_structure(self):
        env = sample_lock()["environments"]["ubuntu-24.04-x86_64"]
        doc = sbom.spdx("ubuntu-24.04-x86_64", env)
        ids = {p["SPDXID"] for p in doc["packages"]}
        self.assertEqual(len(ids), len(doc["packages"]))
        for r in doc["relationships"]:
            self.assertTrue(r["spdxElementId"] in ids or r["spdxElementId"] == "SPDXRef-DOCUMENT")
            self.assertIn(r["relatedSpdxElement"], ids)
        curl = next(p for p in doc["packages"] if p["name"] == "curl")
        self.assertEqual(curl["licenseDeclared"], "curl AND GPL-2.0-or-later")

    def test_spdx_expression_keeps_choices(self):
        ex = {}
        self.assertEqual(sbom._spdx_expression(["GPL-1+ or Artistic"], ex), "GPL-1.0-or-later OR LicenseRef-Artistic")
        self.assertEqual(ex, {"LicenseRef-Artistic": "Artistic"})
        self.assertEqual(sbom._spdx_expression(["MIT", "GPL-2+ or BSD-3-clause"], {}), "MIT AND (GPL-2.0-or-later OR BSD-3-Clause)")
        self.assertEqual(sbom._spdx_expression([], {}), "NOASSERTION")
        # grouping survives: AND binds tighter than OR in SPDX
        self.assertEqual(sbom._spdx_expression(["(MIT OR Apache-2.0) AND Unicode-DFS-2016"], {}),
                         "(MIT OR Apache-2.0) AND Unicode-DFS-2016")
        # DEP-5: the comma is the loosest operator and may carry its own and/or
        ex = {}
        self.assertEqual(sbom._spdx_expression(["GPL-2+ or AFL-2.1, and Expat"], ex),
                         "(GPL-2.0-or-later OR AFL-2.1) AND MIT")
        self.assertEqual(sbom._spdx_expression(["GPL-3+ with Bison exception"], ex), "LicenseRef-GPL-3-with-Bison-exception")
        self.assertEqual(sbom._spdx_expression(["MIT/X11"], {}), "MIT OR X11")
        self.assertEqual(sbom._spdx_expression(["MIT) AND (BSD-3-Clause"], {}), "MIT AND BSD-3-Clause")


class SchemaValidationTests(unittest.TestCase):
    """Run only where the optional validators are installed (CI)."""

    def test_cyclonedx_schema(self):
        try:
            from cyclonedx.schema import SchemaVersion
            from cyclonedx.validation.json import JsonStrictValidator
        except ImportError:
            self.skipTest("cyclonedx-python-lib not installed")
        env = sample_lock()["environments"]["ubuntu-24.04-x86_64"]
        doc = sbom.cyclonedx("ubuntu-24.04-x86_64", env)
        doc.pop("$schema")
        err = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(doc))
        self.assertIsNone(err, err)

    def test_spdx_schema(self):
        try:
            from spdx_tools.spdx.parser.parse_anything import parse_file
            from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
        except ImportError:
            self.skipTest("spdx-tools not installed")
        env = sample_lock()["environments"]["ubuntu-24.04-x86_64"]
        with tempfile.NamedTemporaryFile("w", suffix=".spdx.json", delete=False) as fh:
            json.dump(sbom.spdx("ubuntu-24.04-x86_64", env), fh)
        try:
            msgs = validate_full_spdx_document(parse_file(fh.name))
        finally:
            os.unlink(fh.name)
        self.assertEqual([m.validation_message for m in msgs], [])


if __name__ == "__main__":
    unittest.main()
