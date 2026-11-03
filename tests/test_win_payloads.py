"""PowerShell payloads compiled into a release build are read instead of files."""

import sys
import types
import unittest
from unittest import mock

from jarvis.core import paths


class EmbeddedPayloadTest(unittest.TestCase):
    def test_an_embedded_payload_wins_and_is_byte_exact(self):
        text = "Write-Output 'a'\r\nWrite-Output 'b'\r\n"
        mod = types.ModuleType("jarvis.core.win_payloads")
        mod.PAYLOADS = {"x.ps1": text}
        with mock.patch.dict(sys.modules, {"jarvis.core.win_payloads": mod}):
            self.assertEqual(paths.load_win_script("x.ps1"), text)

    def test_a_missing_payload_still_throws_explicitly(self):
        mod = types.ModuleType("jarvis.core.win_payloads")
        mod.PAYLOADS = {}
        with mock.patch.dict(sys.modules, {"jarvis.core.win_payloads": mod}):
            self.assertIn("is not part of this edition", paths.load_win_script("nope.ps1"))

    def test_a_source_checkout_reads_the_file(self):
        sys.modules.pop("jarvis.core.win_payloads", None)
        text = paths.load_win_script("posture.ps1")
        self.assertNotIn("is not part of this edition", text)
        self.assertGreater(len(text), 100)


if __name__ == "__main__":
    unittest.main()
