"""Policy proposals under review: what they may change, and what must still be refused."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import build_windows  # noqa: E402
import gate  # noqa: E402

PROPOSALS = ROOT / "release" / "proposals"
MARKERS = PROPOSALS / "windows-markers.json"

# Paths we must never ship, and paths that belong to other projects' pipelines.
OUR_RUNNER = r"D:\a\Argus-1\Argus-1\release\build_windows.py"
OUR_SELF_HOSTED = r"C:\actions-runner\_work\Argus-1\x"
PYTHON_CI = r"D:\a\1\b\bin\amd64\python312.pdb"
MICROSOFT_CI = r"C:\A\_work\1\s\vcruntime.pdb"
PYCA_CI = r"D:\a\cryptography\cryptography\src\rust"
PYCA_HOME = "C:\\Users\\runneradmin\\.cargo\\registry\\"
A_PERSON = "C:\\Users\\jane\\Desktop\\x\\"


def hits(policy, marker_id, text):
    rx = dict(policy["_markers"])[marker_id]
    return bool(rx.search(text.encode()))


class MarkerProposalTest(unittest.TestCase):
    def setUp(self):
        self.base = gate.load_policy()
        self.narrow = gate.load_policy(proposals=[MARKERS])

    def test_the_committed_policy_refuses_everything_here(self):
        for text in (OUR_RUNNER, PYTHON_CI, MICROSOFT_CI, PYCA_CI):
            self.assertTrue(hits(self.base, "windows-build-path", text), text)
        self.assertTrue(hits(self.base, "windows-home-path", PYCA_HOME))

    def test_the_narrowed_marker_still_refuses_our_own_paths(self):
        for text in (OUR_RUNNER, OUR_SELF_HOSTED):
            self.assertTrue(hits(self.narrow, "windows-build-path", text), text)

    def test_the_narrowed_marker_lets_other_projects_pipelines_through(self):
        for text in (PYTHON_CI, MICROSOFT_CI, PYCA_CI):
            self.assertFalse(hits(self.narrow, "windows-build-path", text), text)
        # The home-folder marker is NOT loosened: a runner home folder stays a leak.
        self.assertTrue(hits(self.narrow, "windows-home-path", PYCA_HOME))

    def test_the_proposal_pins_exactly_one_file_by_digest(self):
        ex = self.narrow["marker_exemptions"]
        self.assertEqual([(e["member"], e["marker"]) for e in ex],
                         [("cryptography/hazmat/bindings/_rust.pyd", "windows-home-path")])
        self.assertRegex(ex[0]["sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(ex[0]["reason"])

    def test_a_real_persons_home_folder_is_still_refused(self):
        self.assertTrue(hits(self.narrow, "windows-home-path", A_PERSON))

    def test_nothing_else_in_the_policy_changed(self):
        for key in ("deny_suffixes", "deny_path_parts", "deny_bytecode_magic", "max_file_count_growth"):
            self.assertEqual(self.narrow[key], self.base[key], key)
        changed = [a["id"] for a, b in zip(self.narrow["deny_markers"], self.base["deny_markers"]) if a != b]
        self.assertEqual(sorted(changed), ["windows-build-path"])
        self.assertTrue(any("REPLACES marker windows-build-path" in p for p in self.narrow["_proposals"]))

    def test_a_proposal_cannot_add_or_invent_a_marker_or_touch_the_lists(self):
        tmp = Path(tempfile.mkdtemp())
        invent = tmp / "invent.json"
        invent.write_text(json.dumps({"deny_markers": [{"id": "no-such-marker", "regex": "x"}]}))
        with self.assertRaises(ValueError):
            gate.load_policy(proposals=[invent])
        lists = tmp / "lists.json"
        lists.write_text(json.dumps({"deny_suffixes": []}))
        with self.assertRaises(ValueError):
            gate.load_policy(proposals=[lists])


class StrictScanTest(unittest.TestCase):
    """What is ours is always scanned with the committed policy, never a proposal."""

    def stage(self, files):
        d = Path(tempfile.mkdtemp(prefix="argus-strict-"))
        for name, data in files.items():
            (d / name).parent.mkdir(parents=True, exist_ok=True)
            (d / name).write_bytes(data)
        return d

    def test_which_files_are_ours(self):
        for rel in ("argus.exe", "argus-desktop.exe", "argus/web/static/app.js"):
            self.assertTrue(build_windows.is_ours(rel), rel)
        for rel in ("python312.dll", "_ssl.pyd", "libcrypto-3.dll", "cryptography/hazmat/_rust.pyd"):
            self.assertFalse(build_windows.is_ours(rel), rel)

    def test_a_leak_of_our_runner_home_folder_in_our_program_is_caught(self):
        stage = self.stage({"argus.exe": b"MZ" + PYCA_HOME.encode() + b"leak", "python312.dll": b"MZ"})
        self.assertTrue(build_windows.strict_problems(stage))

    def test_the_vendors_path_in_a_third_party_binary_is_not_our_problem(self):
        stage = self.stage({"argus.exe": b"MZ clean", "python312.dll": b"MZ" + PYTHON_CI.encode(),
                            "cryptography/_rust.pyd": b"MZ" + PYCA_HOME.encode()})
        self.assertEqual(build_windows.strict_problems(stage), [])

    def test_a_vendors_path_inside_our_own_program_is_still_caught(self):
        stage = self.stage({"argus.exe": b"MZ" + PYTHON_CI.encode()})
        self.assertTrue(build_windows.strict_problems(stage))


if __name__ == "__main__":
    unittest.main()


class ExemptionTest(unittest.TestCase):
    """A digest-pinned exemption covers one vendor binary and nothing near it."""

    MEMBER = "cryptography/hazmat/bindings/_rust.pyd"
    BYTES = b"MZ vendor binary " + PYCA_HOME.encode() + b" end"

    def policy(self, data=None):
        import hashlib
        pol = gate.load_policy()
        pol["marker_exemptions"] = [{"member": self.MEMBER, "marker": "windows-home-path",
                                     "sha256": hashlib.sha256(data or self.BYTES).hexdigest(), "reason": "test"}]
        return pol

    def test_without_an_exemption_the_vendor_file_is_refused(self):
        problems = gate.scan_bytes("Argus-Setup.exe:" + self.MEMBER, self.BYTES, gate.load_policy())
        self.assertTrue(any("windows-home-path" in p for p in problems))

    def test_the_exact_bytes_at_the_named_member_pass(self):
        label = "Argus-Setup.exe:" + self.MEMBER
        self.assertEqual(gate.scan_bytes(label, self.BYTES, self.policy()), [])

    def test_changed_bytes_are_refused_again(self):
        label = "Argus-Setup.exe:" + self.MEMBER
        self.assertTrue(gate.scan_bytes(label, self.BYTES + b"x", self.policy()))

    def test_the_same_bytes_under_another_name_are_refused(self):
        self.assertTrue(gate.scan_bytes("Argus-Setup.exe:argus.exe", self.BYTES, self.policy()))

    def test_it_exempts_only_the_named_marker(self):
        data = self.BYTES + OUR_RUNNER.encode()
        import hashlib
        pol = self.policy(data)
        pol["marker_exemptions"][0]["sha256"] = hashlib.sha256(data).hexdigest()
        problems = gate.scan_bytes("Argus-Setup.exe:" + self.MEMBER, data, pol)
        self.assertTrue(any("windows-build-path" in p for p in problems), problems)
        self.assertFalse(any("windows-home-path" in p for p in problems), problems)

    def test_a_proposal_may_carry_exemptions_and_records_them(self):
        tmp = Path(tempfile.mkdtemp()) / "ex.json"
        tmp.write_text(json.dumps({"marker_exemptions": [
            {"member": self.MEMBER, "marker": "windows-home-path", "sha256": "0" * 64}]}))
        pol = gate.load_policy(proposals=[tmp])
        self.assertEqual(len(pol["marker_exemptions"]), 1)
        self.assertTrue(any("exempts windows-home-path" in p for p in pol["_proposals"]))
