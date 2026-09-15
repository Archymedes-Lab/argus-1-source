import os
import unittest

from jarvis.collectors.persistence import trusted_tasks
from jarvis.core import paths


class TrustedScheduledTaskTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "currentUser": r"WORKSTATION\chris",
            "localAppData": r"C:\Users\chris\AppData\Local",
        }

    def _ide_task(self):
        return {
            "name": "WSL IDE Keepalive",
            "path": "\\",
            "user": r"WORKSTATION\chris",
            "logonType": "S4U",
            "runLevel": "Limited",
            "actions": [{
                "execute": "powershell.exe",
                "arguments": (
                    '-NoProfile -NonInteractive -WindowStyle Hidden '
                    '-ExecutionPolicy Bypass -File '
                    '"C:\\Users\\chris\\AppData\\Local\\WSLKeepalive\\'
                    'wsl-ide-keepalive-supervisor.ps1"'),
                "targetHash": trusted_tasks.TRUSTED_IDE_TASKS[
                    "wsl ide keepalive"]["hash"],
            }],
        }

    def test_exact_reviewed_task_is_verified(self):
        ok, detail = trusted_tasks.verified_maintenance_task(
            self._ide_task(), self.data)
        self.assertTrue(ok, detail)

    def test_trusted_name_does_not_override_changed_script(self):
        task = self._ide_task()
        task["actions"][0]["targetHash"] = "0" * 64
        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)
        self.assertFalse(ok)
        self.assertIn("fingerprint", detail)

    def test_trusted_name_does_not_override_extra_arguments(self):
        task = self._ide_task()
        task["actions"][0]["arguments"] += " -EncodedCommand Z" * 20
        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)
        self.assertFalse(ok)
        self.assertIn("arguments", detail)

    def test_principal_must_be_limited_current_user(self):
        task = self._ide_task()
        task["runLevel"] = "Highest"
        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)
        self.assertFalse(ok)
        self.assertIn("limited", detail)

    def test_headless_conhost_wrapper_is_verified(self):
        task = self._ide_task()
        action = task["actions"][0]
        action["execute"] = r"C:\Windows\System32\conhost.exe"
        action["arguments"] = (r'--headless "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" '
                               + action["arguments"])
        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)
        self.assertTrue(ok, detail)

    def test_headless_conhost_cannot_wrap_other_programs(self):
        task = self._ide_task()
        action = task["actions"][0]
        action["execute"] = r"C:\Windows\System32\conhost.exe"
        action["arguments"] = r'--headless C:\Users\chris\evil.exe ' + action["arguments"]
        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)
        self.assertFalse(ok)
        task["actions"][0]["execute"] = r"C:\Users\chris\conhost.exe"
        action["arguments"] = (r'--headless "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" '
                               + self._ide_task()["actions"][0]["arguments"])
        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)
        self.assertFalse(ok)

    def test_wake_task_uses_the_actual_checkout_path(self):
        root = str(paths.REPO_ROOT)
        task = {
            "name": "jarvis wake watchdog",
            "path": "\\",
            "user": r"WORKSTATION\chris",
            "logonType": "Interactive",
            "runLevel": "Limited",
            "actions": [{
                "execute": "powershell.exe",
                "arguments": (
                    '-NoProfile -NonInteractive -WindowStyle Hidden '
                    '-ExecutionPolicy Bypass -File '
                    '"C:\\Users\\chris\\AppData\\Local\\WSLKeepalive\\'
                    'wake-jarvis.ps1" -Distro "Ubuntu" '
                    f'-RepoRoot "{root}" -RecoverInterop true'),
                "targetHash": trusted_tasks.normalized_text_hash(
                    os.path.join(root, "wake-jarvis.ps1")),
            }],
        }

        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)

        self.assertTrue(ok, detail)


if __name__ == "__main__":
    unittest.main()


class SystemdAliasTests(unittest.TestCase):
    def test_alias_into_a_packaged_unit_is_inventory_but_other_links_stay_medium(self):
        import os
        import tempfile
        from unittest import mock

        from jarvis.collectors.persistence import control
        with tempfile.TemporaryDirectory() as root:
            packaged, etc = os.path.join(root, "pkg") + "/", os.path.join(root, "etc")
            os.makedirs(packaged); os.makedirs(etc)
            open(os.path.join(packaged, "rsyslog.service"), "w").close()
            open(os.path.join(root, "evil.service"), "w").close()
            os.symlink(os.path.join(packaged, "rsyslog.service"), os.path.join(etc, "syslog.service"))
            os.symlink(os.path.join(root, "evil.service"), os.path.join(etc, "evil.service"))
            units = sorted(os.path.join(etc, n) for n in os.listdir(etc))

            def fake_glob(pattern):
                return units if pattern == "/etc/systemd/system/*.service" else []

            with mock.patch.object(control, "PACKAGED_UNIT_DIRS", (packaged,)), \
                 mock.patch.object(control.glob, "glob", side_effect=fake_glob), \
                 mock.patch.object(control, "_run", return_value=""):
                out = {f["where"]: f for f in control.audit_linux()
                       if "systemd" in f["title"] and f["where"] in units}
        self.assertEqual(out[units[1]]["severity"], "low")       # syslog -> packaged
        self.assertEqual(out[units[0]]["severity"], "medium")    # evil -> elsewhere
        self.assertEqual(out[units[0]]["title"], "custom systemd service")
