"""ARGUS-1 is proprietary, says so everywhere, and ships every notice it owes.

2026-11-02: the product's own Rust runtime declared MIT, no release carried a
licence, the SBOM had no licence data, and the server binary bundled GNU
Readline (GPL-3.0). These tests hold the fixes.
"""

import io
import json
import re
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import build_desktop  # noqa: E402
import build_server  # noqa: E402
import gate  # noqa: E402
import notices  # noqa: E402

from tests.test_release_gate import GOOD_SERVER, SERVER, GateCase, ar_bytes, tar_bytes  # noqa: E402

LICENCE = ROOT / "LICENSE.txt"
PROPRIETARY = "LicenseRef-Archymedes-Proprietary"


class TheLicence(unittest.TestCase):
    def test_licence_names_the_product_licensor_and_says_proprietary(self):
        text = LICENCE.read_text()
        for needle in ("ARGUS-1 END USER LICENCE AGREEMENT", "Archymedes, Inc.", PROPRIETARY,
                       "proprietary", "not open-source software", "THIRD-PARTY-NOTICES.txt"):
            self.assertIn(needle, text)
        self.assertNotIn("source code in this repository", text)

    def test_a_licence_without_the_draft_header_has_no_placeholders(self):
        text = LICENCE.read_text()
        placeholders = re.findall(r"\[[A-Z][A-Z /]+:", text)
        if not text.startswith("DRAFT"):
            self.assertEqual(placeholders, [], "a final licence must have every placeholder filled")
        else:
            self.assertIn("being\nincorporated", text)

    def test_expiry_never_disables_core_functions(self):
        self.assertIn("does not disable the Software's core", " ".join(LICENCE.read_text().split()))


class OwnManifests(unittest.TestCase):
    def test_own_rust_crates_are_proprietary_and_unpublishable(self):
        for f in ("rust-runtime/Cargo.toml", "desktop/Cargo.toml"):
            text = (ROOT / f).read_text()
            self.assertIn(f'license = "{PROPRIETARY}"', text, f)
            self.assertIn("publish = false", text, f)
            self.assertNotRegex(text, r'license = "(MIT|Apache|GPL|BSD)', f)

    def test_own_packages_are_private_and_unlicensed(self):
        for f in ("desktop/ui/package.json", "hosted/mesh-cloudflare/package.json",
                  "hosted/notify-cloudflare/package.json"):
            pkg = json.loads((ROOT / f).read_text())
            self.assertTrue(pkg.get("private"), f)
            self.assertEqual(pkg.get("license"), "UNLICENSED", f)


class Notices(unittest.TestCase):
    def setUp(self):
        self.snap = notices.load()
        self.rows = notices.entries(self.snap)

    def test_committed_notices_are_current(self):
        self.assertEqual((ROOT / "THIRD-PARTY-NOTICES.txt").read_text(), notices.render(),
                         "run python3 release/notices.py render")

    def test_every_component_has_a_permitted_licence(self):
        self.assertEqual([(s, n, v) for s, n, v, lic, _c, _src in self.rows if not lic], [])
        for _s, name, _v, lic, _c, _src in self.rows:
            self.assertFalse(notices.FORBIDDEN.search(lic), name)

    def test_every_locked_crate_is_listed(self):
        lock = (ROOT / "desktop" / "Cargo.lock").read_text()
        locked = set(re.findall(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', lock))
        listed = {(c["name"], c["version"]) for c in self.snap["cargo"]}
        own = {("jarvis-desktop", v) for n, v in locked if n == "jarvis-desktop"}
        self.assertEqual(sorted(locked - listed - own), [])

    def test_every_pinned_runtime_package_is_listed(self):
        pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", (ROOT / "release/requirements-runtime.txt").read_text(), re.M)
        listed = {(c["name"].lower(), c["version"]) for c in self.snap["python"]}
        self.assertEqual([p for p in pins if (p[0].lower(), p[1]) not in listed], [])

    def test_mpl_components_say_where_their_source_is(self):
        for _s, name, _v, lic, _c, src in self.rows:
            if "MPL" in lic:
                self.assertTrue(src.startswith("https://"), name)

    def test_every_chosen_licence_has_its_text(self):
        for part in {p for *_x, lic, _c, _src in self.rows for p in lic.split(" AND ")}:
            self.assertTrue((notices.TEXTS / f"{part}.txt").exists(), part)

    def test_choose_takes_a_permitted_alternative_and_refuses_copyleft(self):
        self.assertEqual(notices.choose("MIT OR Apache-2.0 OR LGPL-2.1-or-later"), "MIT")
        self.assertEqual(notices.choose("Apache-2.0 WITH LLVM-exception OR MIT"), "Apache-2.0")
        self.assertEqual(notices.choose("Apache-2.0/MIT"), "Apache-2.0")
        self.assertIsNone(notices.choose("GPL-3.0-only"))
        self.assertIsNone(notices.choose("AGPL-3.0"))
        self.assertIsNone(notices.choose("LGPL-2.1"))


class GateRefusesCopyleft(GateCase):
    def test_readline_in_the_server_tarball_is_refused(self):
        for member in ("argus-server/bin/libreadline.so.7", "argus-server/bin/readline.so",
                       "argus-server/bin/readline.cpython-312-x86_64-linux-gnu.so"):
            with self.subTest(member):
                for p in self.dir.iterdir():
                    p.unlink()
                self.publish({SERVER: tar_bytes(GOOD_SERVER + [(member, b"\x7fELF lib", 0o755)])})
                self.assertRefused("copyleft library")

    def test_permissive_libraries_still_pass(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER + [("argus-server/bin/libssl.so.1.1", b"\x7fELF", 0o755),
                                                       ("argus-server/bin/libffi.so.6", b"\x7fELF", 0o755)])})
        self.assertEqual(self.problems(), [])

    def test_licence_files_are_allowed_in_every_package_and_beside_them(self):
        lic = [("argus-server/LICENSE.txt", b"EULA", 0o644), ("argus-server/THIRD-PARTY-NOTICES.txt", b"n", 0o644)]
        data = tar_bytes([("./usr/bin/argus-desktop", b"\x7fELF", 0o755),
                          ("./usr/share/doc/argus-desktop/LICENSE.txt", b"EULA", 0o644),
                          ("./usr/share/doc/argus-desktop/THIRD-PARTY-NOTICES.txt", b"n", 0o644)])
        deb = ar_bytes([("debian-binary", b"2.0\n"),
                        ("control.tar.gz", tar_bytes([("./control", b"Package: argus-desktop\n", 0o644)])),
                        ("data.tar.gz", data)])
        self.publish({SERVER: tar_bytes(GOOD_SERVER + lic), "argus-desktop_2026.11.02_amd64.deb": deb})
        (self.dir / "LICENSE.txt").write_text("EULA")
        (self.dir / "THIRD-PARTY-NOTICES.txt").write_text("notices")
        self.assertEqual(self.problems(), [])

    def test_any_other_text_file_beside_the_artifacts_is_still_refused(self):
        self.publish({SERVER: tar_bytes(GOOD_SERVER)})
        (self.dir / "NOTES.txt").write_text("x")
        self.assertTrue(self.problems())


class BuildsShipTheLicence(unittest.TestCase):
    def test_server_package_contains_licence_and_notices(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "argus-server").write_bytes(b"\x7fELF")
            names = {n: data for n, data, _m in build_server.entries(Path(d), "t", "c")}
        self.assertEqual(names["LICENSE.txt"], LICENCE.read_bytes())
        self.assertEqual(names["THIRD-PARTY-NOTICES.txt"], (ROOT / "THIRD-PARTY-NOTICES.txt").read_bytes())

    def test_server_build_excludes_gnu_readline(self):
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            raise SystemExit("stop after capturing the command")
        # data_files() refuses a tree without the dashboard (it must ship); stub it here.
        with tempfile.TemporaryDirectory() as d, mock.patch.object(build_server.subprocess, "run", fake_run), \
                mock.patch.object(build_server, "data_files", lambda *a, **k: []):
            (Path(d) / "argus").mkdir()
            with self.assertRaises(SystemExit):
                build_server.nuitka(Path(d), Path(d) / "work", 1)
        cmd = seen["cmd"]
        for flag in ("--nofollow-import-to=readline", "--nofollow-import-to=rlcompleter",
                     "--noinclude-dlls=libreadline.so*"):
            self.assertIn(flag, cmd)

    def test_desktop_deb_contains_licence_and_notices(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "desktop"
            (src / "icons").mkdir(parents=True)
            for icon in ("32x32.png", "128x128.png", "128x128@2x.png"):
                (src / "icons" / icon).write_bytes(b"png")
            exe = Path(d) / "argus-desktop"
            exe.write_bytes(b"\x7fELF")
            out = Path(d) / "out"
            out.mkdir()
            deb = build_desktop.linux_deb(src, exe, out, "2026.11.02")
            raw = (out / Path(deb).name).read_bytes()
            data_at = raw.index(b"data.tar")
            payload = raw[raw.index(b"`\n", data_at) + 2:]
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as tf:
                names = [m.name.lstrip("./") for m in tf.getmembers()]
        self.assertIn("usr/share/doc/argus-desktop/LICENSE.txt", names)
        self.assertIn("usr/share/doc/argus-desktop/THIRD-PARTY-NOTICES.txt", names)


class ReleaseFolder(unittest.TestCase):
    def test_licence_files_are_known_release_files(self):
        self.assertTrue({"LICENSE.txt", "THIRD-PARTY-NOTICES.txt"} <= gate.META)

    def test_sbom_carries_licences_and_names_argus_proprietary(self):
        import assemble
        bom = assemble.sbom("t", "c")
        self.assertEqual(bom["metadata"]["component"]["licenses"][0]["license"]["id"], PROPRIETARY)
        missing = [c["name"] for c in bom["components"] if "licenses" not in c and c["purl"].startswith("pkg:cargo/")]
        self.assertEqual(missing, [c for c in missing if c == "jarvis-desktop"])
        runtime = {c["name"] for c in bom["components"] if c["name"] in ("cryptography", "cffi", "pycparser")}
        self.assertTrue(all("licenses" in c for c in bom["components"] if c["name"] in runtime))


if __name__ == "__main__":
    unittest.main()
