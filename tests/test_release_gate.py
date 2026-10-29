"""The release content gate refuses every way source has leaked or could leak.

Each case builds a real artifact (tar, zip, .deb, binary) in a temp folder and
runs the same check_release the CI build, the publish job, the site deploy and
the live audit run. 2026-10-29: the Windows zip shipped 429 .py files and the
server tarball decompilable .pyc; the desktop binaries carried /home/<user>.
"""

import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import gate  # noqa: E402

ELF = b"\x7fELF" + b"\x00" * 60 + b"native code"
SERVER = "argus-server-linux-x86_64.tar.gz"


def tar_bytes(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data, mode in members:
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode = len(data), mode
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def ar_bytes(members):
    out = b"!<arch>\n"
    for name, data in members:
        out += f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode() + data
        if len(data) % 2:
            out += b"\n"
    return out


GOOD_SERVER = [
    ("argus-server/bin/argus-server", ELF, 0o755),
    ("argus-server/bin/argus/web/static/dashboard.html", b"<html></html>", 0o644),
    ("argus-server/bin/argus/web/static/app.js", b"console.log(1)", 0o644),
    ("argus-server/units/argus.service", b"[Service]\n", 0o644),
    ("argus-server/install.sh", b"#!/bin/sh\nset -eu\n", 0o755),
    ("argus-server/VERSION", b"2026.11.01\n", 0o644),
]


class GateCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.policy = gate.load_policy()

    def tearDown(self):
        self.tmp.cleanup()

    def publish(self, files, manifest=True):
        for name, data in files.items():
            (self.dir / name).write_bytes(data)
        if manifest:
            listed = {n: {"bytes": len(d), "sha256": hashlib.sha256(d).hexdigest()} for n, d in files.items()}
            (self.dir / "manifest.json").write_text(json.dumps({"version": "t", "files": listed}))
            (self.dir / "SHA256SUMS").write_text("".join(f"{v['sha256']}  {k}\n" for k, v in listed.items()))

    def problems(self, previous=None):
        return gate.check_release(self.dir, self.policy, previous)[0]

    def assertRefused(self, needle):
        found = self.problems()
        self.assertTrue(any(needle in p for p in found), f"expected {needle!r} in {found}")


class Passes(GateCase):
    def test_binary_only_server_release_passes(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER)})
        self.assertEqual(self.problems(), [])

    def test_desktop_deb_passes(self):
        data = tar_bytes([("./usr/bin/argus-desktop", ELF, 0o755),
                          ("./usr/share/applications/argus-desktop.desktop", b"[Desktop Entry]\n", 0o644)])
        ctrl = tar_bytes([("./control", b"Package: argus-desktop\n", 0o644)])
        deb = ar_bytes([("debian-binary", b"2.0\n"), ("control.tar.gz", ctrl), ("data.tar.gz", data)])
        self.publish({"argus-desktop_2026.11.01_amd64.deb": deb})
        self.assertEqual(self.problems(), [])


class RefusesSource(GateCase):
    def test_python_source_in_server_tarball(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER + [("argus-server/bin/argus-server.py", b"print(1)", 0o644)])})
        self.assertRefused("argus-server.py: denied file type")

    def test_bytecode_even_when_renamed(self):
        pyc = bytes.fromhex("cb0d0d0a") + b"\x00" * 12 + b"\xe3code"
        self.publish({SERVER: tar_bytes(GOOD_SERVER + [("argus-server/bin/argus/intel/data/x.json", pyc, 0o644)])})
        self.assertRefused("x.json: Python bytecode")

    def test_python_source_disguised_as_asset(self):
        src = b"#!/usr/bin/env python3\nimport os\n"
        self.publish({SERVER: tar_bytes(GOOD_SERVER + [("argus-server/bin/argus/web/static/a.txt", src, 0o644)])})
        self.assertRefused("a.txt: Python source")

    def test_zip_appended_to_binary_with_source(self):
        z = io.BytesIO()
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("argus/core/main.pyc", b"x")
        self.publish({"argus-desktop-windows-x64.exe": b"MZ" + b"\x00" * 100 + z.getvalue()})
        self.assertRefused("embedded archive member argus/core/main.pyc")

    def test_unlisted_file_in_allowed_folder(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER + [("argus-server/bin/helper", ELF, 0o644)])})
        self.assertRefused("helper: not in the allow list")

    def test_tests_and_docs_folders(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER + [
            ("argus-server/bin/argus/web/static/tests/a.js", b"1", 0o644),
            ("argus-server/bin/argus/web/static/docs/a.html", b"1", 0o644)])})
        self.assertRefused("tests/a.js: denied folder")
        self.assertRefused("docs/a.html: denied folder")

    def test_source_map(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER + [
            ("argus-server/bin/argus/web/static/b.js", b"x//# sourceMappingURL=b.js.map", 0o644)])})
        self.assertRefused("b.js: contains source-map")


class RefusesLeaks(GateCase):
    def test_build_machine_home_path_in_binary(self):
        self.publish({"argus-desktop-windows-x64.exe": b"MZ..../home/chris/.cargo/registry/src/x.rs"})
        self.assertRefused("contains home-path")

    def test_windows_home_path(self):
        self.publish({"argus-desktop-windows-x64.exe": b"MZ..C:\\Users\\runneradmin\\.cargo\\x"})
        self.assertRefused("contains windows-home-path")

    def test_private_key_and_token(self):
        key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"
        tok = b"token=ghp_" + b"a" * 36
        self.publish({SERVER: tar_bytes(GOOD_SERVER + [("argus-server/bin/argus/intel/data/k.json", key + tok, 0o644)])})
        self.assertRefused("contains private-key")
        self.assertRefused("contains github-token")


class RefusesStructure(GateCase):
    def test_unknown_download(self):
        self.publish({"argus-windows-x64.zip": b"PK\x05\x06" + b"\x00" * 18})
        self.assertRefused("no policy rule")

    def test_symlink_member(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, data, mode in GOOD_SERVER:
                ti = tarfile.TarInfo(name)
                ti.size, ti.mode = len(data), mode
                tf.addfile(ti, io.BytesIO(data))
            link = tarfile.TarInfo("argus-server/bin/argus/web/static/x.js")
            link.type, link.linkname = tarfile.SYMTYPE, "/etc/shadow"
            tf.addfile(link)
        self.publish({SERVER: buf.getvalue()})
        self.assertRefused("link is not allowed")

    def test_parent_path(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER + [("argus-server/../evil.html", b"x", 0o644)])})
        self.assertRefused("absolute or parent path")

    def test_unlisted_executable(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER + [("argus-server/bin/argus/web/static/run.js", b"1", 0o755)])})
        self.assertRefused("executable but not listed")

    def test_manifest_mismatch_and_missing(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER)})
        (self.dir / SERVER).write_bytes(tar_bytes(GOOD_SERVER[:-1]))
        self.assertRefused("size or SHA-256 differs")
        (self.dir / "manifest.json").unlink()
        self.assertRefused("manifest.json is missing")

    def test_unreadable_container_fails_closed(self):
        self.publish({SERVER: b"not a tarball"})
        self.assertRefused("cannot be opened for checking")

    def test_folder_in_release(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER)})
        (self.dir / "app").mkdir()
        self.assertRefused("folders are not published")

    def test_file_count_jump(self):
        many = GOOD_SERVER + [(f"argus-server/bin/argus/web/static/p{i}.js", b"1", 0o644) for i in range(20)]
        self.publish({SERVER: tar_bytes(many)})
        prev = self.dir.parent / f"{self.dir.name}-prev.json"
        prev.write_text(json.dumps({"member_counts": {SERVER: len(GOOD_SERVER)}}))
        try:
            found = self.problems(prev)
        finally:
            prev.unlink()
        self.assertTrue(any("up from 6" in p for p in found), found)


class PolicyShape(unittest.TestCase):
    def test_policy_never_allows_source_suffixes(self):
        policy = gate.load_policy()
        for rule in policy["artifacts"]:
            for pat in rule["allow"]:
                for suffix in (".py", ".pyc", ".ps1", ".cs", ".rs", ".map", ".ts"):
                    # A trailing wildcard would admit any type; only versioned
                    # shared libraries (lib.so.3) may end in one.
                    open_ended = pat.endswith("*") and not pat.endswith(".so.*")
                    self.assertFalse(pat.endswith(suffix) or open_ended, f"{rule['name']} allows {pat}")

    def test_glob_semantics(self):
        self.assertTrue(gate.glob_match("a/b/c/x.js", "a/**/*.js"))
        self.assertTrue(gate.glob_match("a/x.js", "a/**/*.js"))
        self.assertFalse(gate.glob_match("a/b/x.js", "a/*.js"))


if __name__ == "__main__":
    unittest.main()
