"""Boot findings keep a stable identity across scans.

Regression test: "task ran at boot" used to carry the observation timestamp
in `where`, which alert identity uses raw — so every 6-hour scan minted new
finding ids, confirmations expired after one interval, and the score
oscillated on unchanged facts. The task name is now the location; the run
time lives in the detail where clock times are stripped from identity.
"""

import unittest
from unittest import mock

from jarvis.collectors.persistence import startup
from jarvis.response import acknowledge


def _sample(when):
    return {
        "bootTime": "2026-09-20T10:00:00",
        "taskRuns": [{"task": "\\JARVIS connectivity guard",
                      "cmd": "powershell.exe -File x.ps1",
                      "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                      "time": when}],
        "autostart": [],
        "crashes": [],
    }


def _ran(stdout):
    return [f for f in stdout if f.get("title") == "task ran at boot"]


class BootIdentityTests(unittest.TestCase):
    def _run(self, when):
        with mock.patch.object(startup, "ps_json", return_value=_sample(when)):
            return startup.audit()

    def test_location_is_the_task_name_not_the_timestamp(self):
        (finding,) = _ran(self._run("2026-09-20T14:46:47"))
        self.assertEqual(finding["where"], "\\JARVIS connectivity guard")
        self.assertIn("2026-09-20 14:46:47", finding["detail"])

    def test_identity_survives_a_rescan_with_a_new_timestamp(self):
        (first,) = _ran(self._run("2026-09-20T14:46:47"))
        (second,) = _ran(self._run("2026-09-20T20:46:47"))
        self.assertEqual(acknowledge.finding_id(first, "boot"),
                         acknowledge.finding_id(second, "boot"))

    def test_distinct_tasks_keep_distinct_identities(self):
        with mock.patch.object(startup, "ps_json", return_value={
                "bootTime": "2026-09-20T10:00:00",
                "taskRuns": [
                    {"task": "\\A", "cmd": "", "path": "",
                     "time": "2026-09-20T14:00:00"},
                    {"task": "\\B", "cmd": "", "path": "",
                     "time": "2026-09-20T14:00:00"},
                ],
                "autostart": [], "crashes": []}):
            findings = _ran(startup.audit())
        ids = {acknowledge.finding_id(f, "boot") for f in findings}
        self.assertEqual(len(ids), 2)


if __name__ == "__main__":
    unittest.main()
