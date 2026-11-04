"""Package data ships the same whatever Python builds it (ported from the
windows-installer branch): on 3.12 `glob("dir/**")` returns no files, and the
2026.11.03-0 release shipped no dashboard file because of it."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import build_server  # noqa: E402


class DataFilesTest(unittest.TestCase):
    """The package data that ships must not depend on the Python version that builds it."""

    def make_tree(self):
        tree = Path(tempfile.mkdtemp(prefix="argus-data-"))
        static = tree / "argus" / "web" / "static"
        (static / "vendor" / "leaflet").mkdir(parents=True)
        (static / "index.html").write_text("<html></html>")
        (static / "vendor" / "leaflet" / "leaflet.js").write_text(
            "var L = {};\nL.x = 1;\n//# sourceMappingURL=leaflet-src.js.map\n")
        (tree / "argus" / "web" / "styles").mkdir(parents=True)
        (tree / "argus" / "web" / "styles" / "shell.css").write_text("a{}")
        return tree

    def test_nested_static_files_are_included_not_just_directories(self):
        tree = self.make_tree()
        rels = {rel for _src, rel in build_server.data_files(tree, Path(tempfile.mkdtemp()))}
        self.assertIn("argus/web/static/index.html", rels)
        self.assertIn("argus/web/static/vendor/leaflet/leaflet.js", rels)
        self.assertIn("argus/web/styles/shell.css", rels)

    def test_a_source_map_comment_is_removed_from_a_copy_not_the_source(self):
        tree = self.make_tree()
        clean = Path(tempfile.mkdtemp())
        got = dict((rel, src) for src, rel in build_server.data_files(tree, clean))
        shipped = got["argus/web/static/vendor/leaflet/leaflet.js"].read_bytes()
        self.assertNotIn(b"sourceMappingURL", shipped)
        self.assertIn(b"L.x = 1;", shipped, "only the comment goes, never the code")
        original = (tree / "argus/web/static/vendor/leaflet/leaflet.js").read_bytes()
        self.assertIn(b"sourceMappingURL", original)

    def test_the_real_dashboard_files_are_all_found_and_none_carry_a_source_map(self):
        import rename
        tree = Path(tempfile.mkdtemp(prefix="argus-export-"))
        rename.export(ROOT, "HEAD", tree)   # the same renamed export the build compiles
        pairs = build_server.data_files(tree, Path(tempfile.mkdtemp()))
        rels = [rel for _s, rel in pairs]
        self.assertGreater(len([r for r in rels if r.startswith("argus/web/static/")]), 10)
        self.assertIn("argus/web/static/vendor/leaflet/leaflet.js", rels)
        for src, rel in pairs:
            self.assertNotIn(b"sourceMappingURL=", Path(src).read_bytes(), rel)


class ShippedDataIsAllowed(unittest.TestCase):
    """Every data file the builds ship must be allowed, path by path, in each
    artifact that carries the engine: run 41744195602 found world-50m.json
    refused only after a 10-minute compile, once dashboard files began to ship."""

    PREFIXES = {
        "argus-server-linux-x86_64.tar.gz": "argus-server/bin/",
        "argus-server_*_amd64.deb": "usr/share/argus-server/bin/",
        "argus-instinct-windows-x64.zip": "ARGUS-INSTINCT/engine/",
        "ARGUS-INSTINCT-Setup-windows-x64.exe": "engine/",
    }

    def test_every_shipped_data_file_is_allowed_and_not_denied(self):
        import gate
        import rename
        tree = Path(tempfile.mkdtemp(prefix="argus-export-"))
        rename.export(ROOT, "HEAD", tree)
        rels = [rel for _s, rel in build_server.data_files(tree, Path(tempfile.mkdtemp()))]
        policy = gate.load_policy()
        rules = {r["name"]: r for r in policy["artifacts"]}
        for name, prefix in self.PREFIXES.items():
            for rel in rels:
                path = prefix + rel
                with self.subTest(artifact=name, file=rel):
                    self.assertIsNone(gate.denied_path(path, policy))
                    self.assertTrue(any(gate.glob_match(path, p) for p in rules[name]["allow"]),
                                    f"{path} is not in the allow list of {name}")


if __name__ == "__main__":
    unittest.main()
