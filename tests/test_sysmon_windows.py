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


class ThreadVerdictTests(unittest.TestCase):
    """Real Sysmon event 8 shapes recorded on this machine, 2026-09-16/17."""

    def v(self, *a):
        from jarvis.collectors.telemetry import sysmon
        return sysmon.thread_verdict(*a)

    def test_kernel_start_address_is_routine(self):
        self.assertIsNone(self.v(r"C:\Windows\System32\dwm.exe", "", "-", "-", "0xFFFFF80749AED220"))
        self.assertIsNone(self.v("", "", "-", "-", "0xFFFFF8043EA61070"))

    def test_console_ctrl_delivery_is_routine(self):
        self.assertIsNone(self.v("", r"C:\x\ollama.exe", r"C:\WINDOWS\System32\KERNELBASE.dll",
                                 "CtrlRoutine", "0x00007FFDB7876400"))

    def test_electron_child_thread_in_its_own_image_is_low(self):
        exe = r"C:\Users\c\AppData\Local\Programs\VSCodium\VSCodium.exe"
        self.assertEqual(self.v(exe, exe, exe, "-", "0x00007FF6CFEBACC0")[0], "low")

    def test_real_injection_shapes_stay_loud(self):
        self.assertEqual(self.v(r"C:\t\evil.exe", r"C:\x\notepad.exe", "-", "-",
                                "0x000001A2B3C40000")[0], "critical")
        self.assertEqual(self.v(r"C:\t\evil.exe", r"C:\x\notepad.exe",
                                r"C:\WINDOWS\System32\KERNEL32.DLL", "LoadLibraryW",
                                "0x00007FFD00001000")[0], "critical")


class RememberTests(unittest.TestCase):
    def test_run_state_is_reported_once_not_remembered(self):
        import os
        import tempfile

        from jarvis.core.store import Store
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "t.db"))
            try:
                partial = sysmon._finding("visibility", "high", "Sysmon event coverage is partial", "x", "c")
                hit = sysmon._finding("injection", "critical", "evil.exe created a thread inside notepad.exe", "d", "w")
                first = sysmon._remember(store, [partial, hit], 24)
                later = sysmon._remember(store, [], 24)
            finally:
                store.close()
        self.assertIn("Sysmon event coverage is partial", [f["title"] for f in first])
        self.assertEqual([f["title"] for f in later], ["evil.exe created a thread inside notepad.exe"])
