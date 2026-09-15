import unittest
from unittest import mock

from jarvis.collectors.telemetry import sysmon


class WindowsSysmonImpactTests(unittest.TestCase):
    def audit(self, events):
        data = {"events": events, "complete": True, "readFailed": False}
        with mock.patch.object(sysmon, "status", return_value={"installed": True,
                                                               "readable": True}), \
             mock.patch.object(sysmon, "_fetch", return_value=data):
            return sysmon.audit()

    def test_shadow_copy_deletion_is_critical_impact(self):
        findings = self.audit([{
            "id": 1, "image": r"C:\Windows\System32\vssadmin.exe",
            "cmdline": "vssadmin.exe delete shadows /all /quiet",
            "time": "2026-09-15T10:00:00Z", "hashes": "",
        }])
        hit = [f for f in findings if f["category"] == "impact"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "critical")

    def test_tool_name_without_destructive_arguments_is_not_ransomware(self):
        findings = self.audit([{
            "id": 1, "image": r"C:\Windows\System32\vssadmin.exe",
            "cmdline": "vssadmin.exe list shadows", "hashes": "",
        }])
        self.assertEqual([f for f in findings if f["category"] == "impact"], [])

    def test_unsigned_adjacent_dll_in_user_directory_is_sideload_signal(self):
        findings = self.audit([{
            "id": 7, "image": r"C:\Users\u\Downloads\host.exe",
            "loaded": r"C:\Users\u\Downloads\version.dll",
            "signed": "false", "time": "2026-09-15T10:00:00Z",
        }])
        hit = [f for f in findings if "side-loading" in f["title"]]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "high")

    def test_unsigned_system_dll_is_not_called_sideloading(self):
        findings = self.audit([{
            "id": 7, "image": r"C:\Windows\System32\host.exe",
            "loaded": r"C:\Windows\System32\version.dll",
            "signed": "false", "time": "2026-09-15T10:00:00Z",
        }])
        self.assertEqual([f for f in findings if "side-loading" in f["title"]], [])


if __name__ == "__main__":
    unittest.main()
