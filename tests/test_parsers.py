"""Parser tests against captured/handwritten fixtures, so every backend is
covered even on a machine that only has one package manager."""

import io
import json
import os
import tarfile
import tempfile
import unittest

from syslock.managers import apk, apt, brew, pacman, rpm
from syslock.managers.base import resolve_dependencies

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


DEB12 = {"os": "linux", "distro": "debian", "release": "12", "arch": "x86_64", "idLike": []}


class AptTests(unittest.TestCase):
    def test_dpkg_states(self):
        pkgs, problems = apt.parse_dpkg_query(fixture("dpkg-query.txt"))
        names = [(p["name"], p["arch"]) for p in pkgs]
        self.assertIn(("libc6", "i386"), names)  # multiarch kept separately
        self.assertNotIn("oldpkg", [n for n, _ in names])  # rc = removed, config files only
        self.assertNotIn("halfpkg", [n for n, _ in names])  # broken state is reported, not locked
        self.assertTrue(any("halfpkg" in p for p in problems))
        curl = next(p for p in pkgs if p["name"] == "curl")
        self.assertTrue(curl["held"])
        bash = next(p for p in pkgs if p["name"] == "bash")
        self.assertTrue(bash["essential"])
        self.assertEqual(bash["source"], {"name": "bash", "version": "5.2.15-2"})  # binNMU: source version differs

    def test_relations(self):
        self.assertEqual(apt.parse_relations("a (>= 1) | b:any, c [amd64], d <!nocheck>"),
                         [["a", "b"], ["c"], ["d"]])

    def test_dependency_resolution_with_alternatives_and_provides(self):
        pkgs, _ = apt.parse_dpkg_query(fixture("dpkg-query.txt"))
        a = apt.Apt()
        req = {a.key_of(p, DEB12): p.pop("_requires") for p in pkgs}
        prov = {a.key_of(p, DEB12): p.pop("_provides") for p in pkgs}
        resolve_dependencies(pkgs, req, prov, key_of=lambda p: a.key_of(p, DEB12))
        libcurl = next(p for p in pkgs if p["name"] == "libcurl4")
        # "mail-transport-agent | default-mta" is satisfied by postfix via Provides
        self.assertIn("postfix", libcurl["dependencies"])
        # libc6:any resolves to the native libc6, not libc6:i386
        self.assertIn("libc6", libcurl["dependencies"])
        self.assertNotIn("libc6:i386", libcurl["dependencies"])

    def test_foreign_arch_key(self):
        a = apt.Apt()
        self.assertEqual(a.key_of({"name": "libc6", "arch": "i386"}, DEB12), "libc6:i386")
        self.assertEqual(a.key_of({"name": "libc6", "arch": "amd64"}, DEB12), "libc6")
        self.assertEqual(a.key_of({"name": "tzdata", "arch": "all"}, DEB12), "tzdata")

    def test_packages_index_scan(self):
        wanted = {("curl", "amd64", "7.88.1-10+deb12u5"), ("ca-certificates", "all", "20230311"), ("x", "amd64", "1")}
        found = apt.scan_packages_index(fixture("Packages"), wanted)
        self.assertEqual(set(found), wanted - {("x", "amd64", "1")})
        self.assertEqual(found[("curl", "amd64", "7.88.1-10+deb12u5")]["size"], 316176)
        self.assertTrue(found[("curl", "amd64", "7.88.1-10+deb12u5")]["sha256"].startswith("0f4c"))

    def test_policy(self):
        pol = apt.parse_policy(fixture("apt-policy.txt"))
        rel = pol[("http://deb.debian.org/debian-security", "bookworm-security", "main")]
        self.assertEqual(rel["o"], "Debian")
        # Lookup by suite alias also works
        self.assertIn(("http://deb.debian.org/debian", "stable", "main"), pol)
        self.assertEqual(pol[("https://download.docker.com/linux/debian", "bookworm", "stable")]["o"], "Docker")

    def test_sources(self):
        entries = apt.parse_sources([("/etc/apt/sources.list.d/debian.sources", fixture("debian.sources")),
                                     ("/etc/apt/sources.list.d/docker.list", fixture("docker.list"))])
        uris = [(e["uri"], e["suite"]) for e in entries]
        self.assertIn(("http://deb.debian.org/debian", "bookworm-updates"), uris)
        self.assertNotIn(("http://example.com/disabled", "x"), uris)
        self.assertNotIn(("http://example.com/src", "bookworm"), uris)  # deb-src ignored
        docker = next(e for e in entries if "docker" in e["uri"])
        self.assertEqual(docker["signedBy"], "/etc/apt/keyrings/docker.asc")
        insecure = next(e for e in entries if "insecure" in e["uri"])
        self.assertTrue(insecure["trusted"])
        self.assertEqual(insecure["suite"], "./")  # flat repository

    def test_dep5(self):
        self.assertEqual(apt.dep5_licenses(fixture("copyright")), ["MIT", "curl"])
        self.assertEqual(apt.dep5_licenses("not machine readable"), [])

    def test_snapshot_urls(self):
        p = {"filename": "pool/main/c/curl/curl_1_amd64.deb", "repositories": ["Debian:stable-security/main"]}
        repos = {"Debian:stable-security/main": {"origin": "Debian", "uris": ["http://deb.debian.org/debian-security"]}}
        urls = apt._snapshot_urls(p, repos, "20240101T000000Z")
        self.assertEqual(urls, ["https://snapshot.debian.org/archive/debian-security/20240101T000000Z/pool/main/c/curl/curl_1_amd64.deb"])
        self.assertEqual(apt._snapshot_ts("2024-01-02T03:04:05Z"), "20240102T030405Z")
        self.assertEqual(apt._snapshot_urls(p, {"Debian:stable-security/main": {"origin": "Docker", "uris": ["x"]}}, "t"), [])


class RpmTests(unittest.TestCase):
    def test_qa(self):
        pkgs = rpm.parse_rpm_qa(fixture("rpm-qa.txt"))
        names = [p["name"] for p in pkgs]
        self.assertNotIn("gpg-pubkey", names)
        ossl = next(p for p in pkgs if p["name"] == "openssl-libs")
        self.assertEqual(ossl["epoch"], 1)
        self.assertEqual(rpm.nevra(ossl), "openssl-libs-1:3.2.2-3.fc40.x86_64")
        self.assertEqual(ossl["source"], {"name": "openssl"})
        self.assertNotIn("payloadDigest", ossl)  # (none) is dropped
        bash = next(p for p in pkgs if p["name"] == "bash")
        self.assertEqual(rpm.nevra(bash), "bash-5.2.26-3.fc40.x86_64")
        self.assertNotIn("source", bash)

    def test_srpm(self):
        self.assertEqual(rpm.srpm_name("python3.12-3.12.4-1.fc40.src.rpm"), "python3.12")
        self.assertEqual(rpm.srpm_name("(none)"), "")

    def test_multilib_key(self):
        r = rpm.Rpm()
        plat = {"arch": "x86_64"}
        self.assertEqual(r.key_of({"name": "glibc", "arch": "i686"}, plat), "glibc.i686")
        self.assertEqual(r.key_of({"name": "tzdata", "arch": "noarch"}, plat), "tzdata")

    def test_repo_files(self):
        repos = rpm.parse_repo_files([("/etc/yum.repos.d/fedora.repo", fixture("fedora.repo"))])
        ids = [r["id"] for r in repos]
        self.assertEqual(ids, ["docker-ce-stable", "fedora"])  # disabled one skipped, sorted
        self.assertIn("metalink", repos[1])

    def test_newer(self):
        self.assertTrue(rpm._newer({"version": "1.10-1"}, {"version": "1.9-1"}))
        self.assertTrue(rpm._newer({"version": "1.0-1", "epoch": 1}, {"version": "9.0-1"}))
        self.assertFalse(rpm._newer({"version": "1.0-1"}, {"version": "1.0-2"}))

    def test_user_installed_parsing(self):
        self.assertEqual(rpm._reason({"name": "a", "arch": "x86_64"}, {"a.x86_64"}), "manual")
        self.assertEqual(rpm._reason({"name": "b", "arch": "x86_64"}, {"a.x86_64"}), "dependency")
        self.assertEqual(rpm._reason({"name": "b", "arch": "x86_64"}, {"!auto:b"}), "dependency")
        self.assertEqual(rpm._reason({"name": "c", "arch": "x86_64"}, {"!auto:b"}), "manual")
        self.assertEqual(rpm._reason({"name": "c", "arch": "x86_64"}, None), "manual")


class ApkTests(unittest.TestCase):
    def test_installed_db(self):
        pkgs, req, prov, owned = apk.parse_installed(fixture("apk-installed"))
        self.assertEqual([p["name"] for p in pkgs], ["musl", "busybox", "curl", "libcurl", "ca-certificates-bundle"])
        self.assertIn("/lib/ld-musl-x86_64.so.1", owned)
        self.assertIn("/etc/apk/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub", owned)
        resolve_dependencies(pkgs, req, prov)
        curl = next(p for p in pkgs if p["name"] == "curl")
        self.assertEqual(curl["dependencies"], ["ca-certificates-bundle", "libcurl", "musl"])  # so: names resolved, !conflict ignored
        self.assertEqual(curl["checksum"], "Q1xyz=")

    def test_world(self):
        w = apk.parse_world(fixture("apk-world"))
        self.assertEqual(set(w), {"busybox", "curl", "jq"})
        self.assertEqual(w["jq"], "jq@edge")

    def test_index(self):
        idx = apk.parse_apkindex(fixture("APKINDEX"))
        self.assertIn(("curl", "8.9.1-r0"), idx)
        self.assertNotIn(("busybox", "1.36.1-r29"), idx)


class PacmanTests(unittest.TestCase):
    def test_desc(self):
        p, req, prov = pacman.package_from_desc(pacman.parse_desc(fixture("pacman-desc")))
        self.assertEqual(p["version"], "1:8.10.1-1")
        self.assertEqual(p["reason"], "dependency")
        self.assertEqual([r[0] for r in req], ["ca-certificates", "krb5", "libcurl.so", "glibc", "sh"])
        self.assertEqual(prov, ["libcurl.so"])

    def test_sync_db(self):
        desc = b"%FILENAME%\ncurl-1:8.10.1-1-x86_64.pkg.tar.zst\n\n%NAME%\ncurl\n\n%VERSION%\n1:8.10.1-1\n\n%CSIZE%\n123\n\n%SHA256SUM%\nabc\n\n"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "core.db")
            with tarfile.open(path, "w:gz") as tf:
                info = tarfile.TarInfo("curl-1:8.10.1-1/desc")
                info.size = len(desc)
                tf.addfile(info, io.BytesIO(desc))
            db = pacman.read_sync_db(path)
        self.assertEqual(db[("curl", "1:8.10.1-1")], {"filename": "curl-1:8.10.1-1-x86_64.pkg.tar.zst", "sha256": "abc", "size": 123})


class BrewTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(fixture("brew-info.json"))
        self.pkgs = brew.parse_info(self.data)

    def test_formulae(self):
        by = {p["name"]: p for p in self.pkgs}
        jq = by["jq"]
        self.assertEqual(jq["reason"], "manual")
        self.assertIn("arm64_sequoia", jq["bottles"])  # every platform's bottle hash
        self.assertEqual(jq["dependencies"], ["oniguruma"])
        onig = by["oniguruma"]
        self.assertEqual(onig["reason"], "dependency")
        self.assertEqual(onig["otherKegs"], ["6.9.8"])  # several kegs, linked one wins
        tool = by["acme/tools/mytool"]
        self.assertTrue(tool["outdated"])  # 1.9_1 installed, formula is 2.0_1
        self.assertNotIn("bottles", tool)
        self.assertTrue(tool["builtFromSource"])
        self.assertTrue(tool["pinned"])

    def test_casks(self):
        casks = {p["name"]: p for p in self.pkgs if p["kind"] == "cask"}
        self.assertEqual(set(casks), {"firefox", "google-chrome"})
        self.assertIn("sha256", casks["firefox"])
        self.assertNotIn("sha256", casks["google-chrome"])  # no_check
        self.assertTrue(casks["google-chrome"]["autoUpdates"])

    def test_bottle_tag(self):
        self.assertEqual(brew.bottle_tag({"os": "macos", "codename": "sequoia", "arch": "aarch64"}), "arm64_sequoia")
        self.assertEqual(brew.bottle_tag({"os": "macos", "codename": "sonoma", "arch": "x86_64"}), "sonoma")
        self.assertEqual(brew.bottle_tag({"os": "linux", "arch": "x86_64"}), "x86_64_linux")

    def test_brewfile(self):
        text = brew.Brew().export_brewfile({"taps": [{"name": "acme/tools"}, {"name": "homebrew/core"}], "packages": self.pkgs})
        self.assertIn('tap "acme/tools"', text)
        self.assertNotIn("homebrew/core", text)
        self.assertIn('brew "jq"', text)
        self.assertNotIn('brew "oniguruma"', text)
        self.assertIn('cask "firefox"', text)


if __name__ == "__main__":
    unittest.main()
