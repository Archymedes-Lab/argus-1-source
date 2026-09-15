import importlib
import os
import sqlite3
import tempfile
import time
import unittest

from jarvis.collectors.host import inputwatch
from jarvis.core.store import Store
from jarvis.core.util import now


class TypingWindowTests(unittest.TestCase):
    def test_punctuation_concentration_is_detected_without_key_content(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, "jarvis.db"))
            try:
                store.db.execute(
                    "INSERT INTO input_typing_windows "
                    "(ts,real_keys,real_key_gaps,equals_keys) VALUES(?,?,?,?)",
                    (now(), 40, 39, 22),
                )
                findings = inputwatch._typing_findings(store, None)
                finding = next(f for f in findings if "equals/plus" in f["title"])
                self.assertEqual(finding["severity"], "low")
                columns = {row[1] for row in store.db.execute(
                    "PRAGMA table_info(input_typing_windows)")}
                self.assertNotIn("key", columns)
                self.assertNotIn("text", columns)
                self.assertNotIn("character", columns)
            finally:
                store.close()

    def test_digit_concentration_is_detected_without_key_content(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, "jarvis.db"))
            try:
                store.db.execute(
                    "INSERT INTO input_typing_windows "
                    "(ts,real_keys,real_key_gaps,digit_keys) VALUES(?,?,?,?)",
                    (now(), 40, 39, 22),
                )
                findings = inputwatch._typing_findings(store, None)
                finding = next(f for f in findings if "digit" in f["title"])
                self.assertEqual(finding["severity"], "low")
            finally:
                store.close()

    def test_existing_typing_table_gets_new_punctuation_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "old.db")
            db = sqlite3.connect(path)
            db.execute(
                "CREATE TABLE input_typing_windows ("
                "ts INTEGER PRIMARY KEY, real_keys INTEGER NOT NULL DEFAULT 0, "
                "injected_keys INTEGER NOT NULL DEFAULT 0, "
                "real_key_gaps INTEGER NOT NULL DEFAULT 0, "
                "real_key_sub20 INTEGER NOT NULL DEFAULT 0, "
                "real_key_sub8 INTEGER NOT NULL DEFAULT 0, "
                "cad_run_max INTEGER NOT NULL DEFAULT 0)"
            )
            db.commit()
            db.close()

            store = Store(path)
            try:
                columns = {row[1] for row in store.db.execute(
                    "PRAGMA table_info(input_typing_windows)")}
                self.assertTrue(
                    {"equals_keys", "slash_keys", "period_keys", "digit_keys"}
                    <= columns)
            finally:
                store.close()


class DesktopSessionTests(unittest.TestCase):
    """A hook outside the desktop session heartbeats forever and sees nothing."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "jarvis.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_heartbeat_session_is_recorded(self):
        from unittest import mock

        ingest = importlib.import_module("jarvis.collectors.host.inputwatch.ingest")
        out = os.path.join(self.tmp.name, "input.jsonl")
        with open(out, "w") as fh:
            fh.write('{"ts": 1, "kind": "heartbeat", "pid": 7, "session": 0, "desktop": 2, '
                     '"counters": {}, "window": {}}\n')
        with mock.patch.object(ingest, "_paths", return_value=("C:\\x", out)):
            ingest.ingest(self.store)
        self.assertEqual(self.store.get_meta("input_hook_session"), "0:2")

    def test_only_a_real_mismatch_counts_as_outside(self):
        supervise = importlib.import_module("jarvis.collectors.host.inputwatch.supervise")
        for value, expected in (("0:2", (0, 2)), ("2:2", None), ("0:-1", None), ("", None)):
            with self.subTest(value=value):
                self.store.set_meta("input_hook_session", value)
                self.assertEqual(supervise._outside_desktop(self.store), expected)

    def test_healthy_looking_hook_outside_the_desktop_is_restarted(self):
        from unittest import mock

        supervise = importlib.import_module("jarvis.collectors.host.inputwatch.supervise")
        self.store.set_meta("input_hook_session", "0:2")
        with mock.patch.object(supervise, "_verify_pin", return_value=[]), \
             mock.patch.object(supervise, "ingest"), \
             mock.patch.object(supervise, "liveness", return_value=("fresh", 0)), \
             mock.patch.object(supervise, "_stop_all") as stop_all, \
             mock.patch.object(supervise, "start", return_value="") as start:
            _pids, findings = supervise.supervise(self.store)
        stop_all.assert_called_once()
        start.assert_called_once()
        titles = [f["title"] for f in findings]
        self.assertIn("the input hook was running outside the desktop session", titles)
        self.assertNotIn("the injected-input monitor is healthy", titles)

    def _start_with(self, task_reply, desktop=""):
        from unittest import mock

        helper = importlib.import_module("jarvis.collectors.host.inputwatch.helper")
        paths = ("C:\\Jarvis\\input.jsonl", os.path.join(self.tmp.name, "input.jsonl"))
        with mock.patch.object(helper, "helper_count", return_value=0), \
             mock.patch.object(helper, "_paths", return_value=paths), \
             mock.patch.object(helper, "_stage_helper",
                               return_value=("C:\\Jarvis\\inputhook.ps1", paths[0], "")), \
             mock.patch.object(helper.collect_windows, "available", return_value=True), \
             mock.patch.object(helper.collect_windows, "desktop_interop", return_value=desktop), \
             mock.patch.object(helper, "ps_json", return_value=task_reply) as task, \
             mock.patch.object(helper, "subprocess") as sub:
            return helper.start(), task, sub

    def test_the_scheduled_task_is_the_normal_way_the_hook_starts(self):
        err, task, sub = self._start_with({"registered": True, "started": True})
        self.assertEqual(err, "")
        sub.run.assert_not_called()          # no direct WSL launch needed
        script = task.call_args.args[0]
        for required in ("JARVIS input hook", "-LogonType Interactive", "-RunLevel Limited",
                         "-MultipleInstances IgnoreNew", "-RestartCount 3",
                         "conhost.exe", "--headless", "Start-ScheduledTask"):
            self.assertIn(required, script)

    def test_a_refused_task_falls_back_to_a_desktop_launch(self):
        err, _task, sub = self._start_with({"error": "Access is denied"},
                                           desktop="/run/WSL/3309_interop")
        self.assertEqual(err, "")
        self.assertEqual(sub.run.call_args.kwargs["env"]["WSL_INTEROP"], "/run/WSL/3309_interop")

    def test_no_task_and_no_desktop_connection_is_reported_not_guessed(self):
        err, _task, sub = self._start_with({"error": "Access is denied"}, desktop="")
        self.assertIn("Access is denied", err)
        self.assertIn("desktop", err)
        sub.run.assert_not_called()

    def test_the_task_definition_is_one_jarvis_verifies_as_its_own(self):
        from jarvis.collectors.persistence import trusted_tasks
        helper = importlib.import_module("jarvis.collectors.host.inputwatch.helper")
        local = r"C:\Users\chris\AppData\Local"
        arguments = helper.task_arguments(local + r"\Jarvis\inputhook.ps1",
                                          local + r"\Jarvis\input.jsonl")
        task = {"name": helper.TASK_NAME, "runLevel": "Limited", "user": "DESKTOP\\chris",
                "logonType": "Interactive",
                "actions": [{"execute": r"C:\Windows\System32\conhost.exe",
                             "arguments": '--headless "C:\\Windows\\System32\\WindowsPowerShell'
                                          '\\v1.0\\powershell.exe" ' + arguments,
                             "targetHash": trusted_tasks.normalized_text_hash(
                                 str(trusted_tasks.win_script("inputhook.ps1")))}]}
        data = {"currentUser": "DESKTOP\\chris", "localAppData": local}
        self.assertEqual(trusted_tasks.verified_maintenance_task(task, data)[0], True)

        tampered = {**task, "actions": [{**task["actions"][0], "targetHash": "0" * 64}]}
        ok, why = trusted_tasks.verified_maintenance_task(tampered, data)
        self.assertFalse(ok)
        self.assertIn("fingerprint", why)

    def test_start_never_launches_beside_an_existing_or_uncountable_helper(self):
        from unittest import mock

        helper = importlib.import_module("jarvis.collectors.host.inputwatch.helper")
        for count, expected in ((1, "already running"), (-1, "possible duplicate")):
            with self.subTest(count=count), \
                 mock.patch.object(helper, "helper_count", return_value=count), \
                 mock.patch.object(helper.collect_windows, "desktop_interop") as desktop, \
                 mock.patch.object(helper.subprocess, "run") as run:
                self.assertIn(expected, helper.start())
                desktop.assert_not_called()
                run.assert_not_called()

    def test_stop_all_also_targets_heartbeat_pids_it_cannot_see_by_command_line(self):
        from unittest import mock

        helper = importlib.import_module("jarvis.collectors.host.inputwatch.helper")
        with mock.patch.object(helper.collect_windows, "run_in_every_session") as run, \
             mock.patch.object(helper, "_paths", return_value=("C:\\x", os.path.join(self.tmp.name, "input.jsonl"))):
            helper._stop_all(pids=["13544", "7560", "1; Stop-Computer", ""])
        script = run.call_args.args[0]
        self.assertIn("@(13544,7560)", script)
        self.assertNotIn("Stop-Computer", script)
        self.assertIn("ProcessName -eq 'powershell'", script)

    def test_duplicate_reconciliation_stops_the_pids_that_wrote_heartbeats(self):
        from unittest import mock

        supervise = importlib.import_module("jarvis.collectors.host.inputwatch.supervise")
        self.store.set_meta("input_hook_dupe_pids", f"{int(time.time())}:13544,7560")
        with mock.patch.object(supervise, "_verify_pin", return_value=[]), \
             mock.patch.object(supervise, "ingest"), \
             mock.patch.object(supervise, "_stop_all") as stop_all, \
             mock.patch.object(supervise, "start", return_value=""):
            supervise.supervise(self.store)
        stop_all.assert_called_once_with(pids=["13544", "7560"])

    def test_cleanup_runs_through_every_live_socket(self):
        import subprocess
        from unittest import mock

        from jarvis.platform import windows
        with mock.patch.object(windows, "_PS", "powershell.exe"), \
             mock.patch.object(windows, "interop_sockets", return_value=["/run/WSL/2_interop", "/run/WSL/3309_interop"]), \
             mock.patch.object(windows.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            self.assertEqual(windows.run_in_every_session("Stop-Process -Id 1"), 2)
        self.assertEqual([c.kwargs["env"]["WSL_INTEROP"] for c in run.call_args_list],
                         ["/run/WSL/2_interop", "/run/WSL/3309_interop"])

    def test_desktop_interop_picks_the_socket_that_lands_on_the_desktop(self):
        import stat
        import subprocess
        from unittest import mock

        from jarvis.platform import windows
        replies = {"/run/WSL/531_interop": "0:2\n", "/run/WSL/3309_interop": "2:2\n"}

        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, replies[kwargs["env"]["WSL_INTEROP"]], "")

        with mock.patch.object(windows, "_PS", "powershell.exe"), \
             mock.patch.object(windows.os, "listdir", return_value=["531_interop", "3309_interop"]), \
             mock.patch.object(windows.os.path, "getmtime", side_effect=lambda p: 2 if "531" in p else 1), \
             mock.patch.object(windows.os.path, "islink", return_value=False), \
             mock.patch.object(windows.os, "stat", return_value=mock.Mock(st_mode=stat.S_IFSOCK)), \
             mock.patch.object(windows.subprocess, "run", side_effect=fake_run):
            self.assertEqual(windows.desktop_interop(), "/run/WSL/3309_interop")


if __name__ == "__main__":
    unittest.main()
