"""The Windows installer build: embedded payloads, staging refusals, policy proposals."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import build_windows  # noqa: E402
import gate  # noqa: E402

WIN = ROOT / "jarvis" / "platform" / "win"


class PayloadEmbeddingTest(unittest.TestCase):
    def test_every_payload_round_trips_byte_for_byte(self):
        ns = {}
        exec(compile(build_windows.payloads_module(WIN), "win_payloads", "exec"), ns)
        files = sorted(WIN.glob("*.ps1"))
        self.assertGreater(len(files), 30)
        self.assertEqual(sorted(ns["PAYLOADS"]), [f.name for f in files])
        for f in files:
            with open(f, encoding="utf-8", errors="replace", newline="") as fh:
                self.assertEqual(ns["PAYLOADS"][f.name], fh.read(), f.name)

    def test_the_loader_reads_the_generated_module(self):
        import types

        from jarvis.core import paths
        mod = types.ModuleType("jarvis.core.win_payloads")
        exec(build_windows.payloads_module(WIN), mod.__dict__)
        with mock.patch.dict(sys.modules, {"jarvis.core.win_payloads": mod}), \
                mock.patch.object(paths, "win_script", side_effect=AssertionError("must not read a file")):
            self.assertIn("Get-", paths.load_win_script("posture.ps1"))


class VersionTest(unittest.TestCase):
    def test_product_version_has_four_numbers(self):
        self.assertEqual(build_windows.product_version("2026.11.03"), "2026.11.3.0")
        self.assertEqual(build_windows.product_version("2026.10.30-2"), "2026.10.30.2")
        self.assertEqual(build_windows.product_version("1.2"), "1.2.0.0")


class StagingTest(unittest.TestCase):
    def folder(self, files):
        d = Path(tempfile.mkdtemp(prefix="argus-stage-test-"))
        for name, data in files.items():
            (d / name).parent.mkdir(parents=True, exist_ok=True)
            (d / name).write_bytes(data)
        return d

    def test_a_complete_folder_may_become_an_installer(self):
        d = self.folder({"argus.exe": b"MZ", "argus-desktop.exe": b"MZ", "python312.dll": b"MZ"})
        self.assertEqual(build_windows.stage_problems(d), [])

    def test_missing_daemon_or_app_is_refused(self):
        d = self.folder({"argus-desktop.exe": b"MZ"})
        self.assertIn("argus.exe is missing", build_windows.stage_problems(d))
        d = self.folder({"argus.exe": b"MZ"})
        self.assertIn("argus-desktop.exe is missing", build_windows.stage_problems(d))

    def test_source_bytecode_and_scripts_are_refused(self):
        d = self.folder({"argus.exe": b"MZ", "argus-desktop.exe": b"MZ",
                         "argus/core/x.py": b"", "a.pyc": b"", "scripts/run.ps1": b"", "k.pem": b""})
        text = " ".join(build_windows.stage_problems(d))
        for name in ("x.py", "a.pyc", "run.ps1", "k.pem"):
            self.assertIn(name, text)

    def test_stage_folder_exits_instead_of_building_a_bad_installer(self):
        dist = self.folder({"argus.exe": b"MZ", "leak.py": b"print(1)"})
        exe = self.folder({"app.exe": b"MZ"}) / "app.exe"
        with self.assertRaises(SystemExit):
            build_windows.stage_folder(dist, exe, Path(tempfile.mkdtemp()) / "stage")


class PolicyProposalTest(unittest.TestCase):
    PROPOSAL = ROOT / "release" / "proposals" / "windows-installer.json"

    def test_the_committed_policy_has_no_windows_installer_rule_yet(self):
        # Changing policy.json is a two-person review. This fails loudly if a rule
        # appears there without the proposal being retired on purpose.
        self.assertIsNone(gate.rule_for("Argus-Setup.exe", gate.load_policy()))

    def test_the_proposal_adds_one_rule_and_changes_nothing_else(self):
        base = gate.load_policy()
        with_prop = gate.load_policy(proposals=[self.PROPOSAL])
        self.assertEqual(gate.rule_for("Argus-Setup.exe", with_prop)["kind"], "nsis")
        self.assertEqual(len(with_prop["artifacts"]), len(base["artifacts"]) + 1)
        for key in ("deny_suffixes", "deny_path_parts", "deny_bytecode_magic", "max_file_count_growth"):
            self.assertEqual(with_prop[key], base[key], key)
        self.assertEqual(with_prop["_markers"][0][0], base["_markers"][0][0])

    def test_the_proposal_never_allows_source_or_scripts(self):
        rule = json.loads(self.PROPOSAL.read_text())["artifacts"][0]
        for pat in rule["allow"]:
            self.assertFalse(pat.endswith(gate_suffixes()), pat)

    def test_a_proposal_cannot_touch_the_deny_lists_or_replace_a_rule(self):
        tmp = Path(tempfile.mkdtemp())
        loosen = tmp / "loosen.json"
        loosen.write_text(json.dumps({"deny_suffixes": [], "artifacts": []}))
        with self.assertRaises(ValueError):
            gate.load_policy(proposals=[loosen])
        replace = tmp / "replace.json"
        replace.write_text(json.dumps({"artifacts": [{"name": "argus-server-linux-x86_64.tar.gz", "kind": "tar", "allow": ["**"]}]}))
        with self.assertRaises(ValueError):
            gate.load_policy(proposals=[replace])


def gate_suffixes():
    return tuple(gate.load_policy()["deny_suffixes"])


if __name__ == "__main__":
    unittest.main()


class WindowsRequirementsTest(unittest.TestCase):
    @staticmethod
    def pins(*names):
        import re
        out = {}
        for name in names:
            for line in (ROOT / "release" / name).read_text().splitlines():
                m = re.match(r"^([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.]*)", line)
                if m:
                    out[m[1].lower()] = m[2]
        return out

    def test_windows_pins_match_the_linux_pins_version_for_version(self):
        self.assertEqual(self.pins("requirements-windows.txt"),
                         self.pins("requirements-build.txt", "requirements-runtime.txt"))

    def test_every_windows_pin_carries_a_hash(self):
        text = (ROOT / "release" / "requirements-windows.txt").read_text()
        lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        self.assertTrue(lines)
        self.assertTrue(all("--hash=sha256:" in ln for ln in lines), lines)


class InternalInputsTest(unittest.TestCase):
    def test_the_client_only_desktop_exe_is_never_published(self):
        import assemble
        self.assertIn("argus-desktop-windows-x64.exe", assemble.INTERNAL_INPUTS)
        self.assertNotIn("Argus-Setup.exe", assemble.INTERNAL_INPUTS)
