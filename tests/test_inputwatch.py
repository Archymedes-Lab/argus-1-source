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

    def test_start_refuses_when_no_connection_reaches_the_desktop(self):
        from unittest import mock

        helper = importlib.import_module("jarvis.collectors.host.inputwatch.helper")
        with mock.patch.object(helper, "helper_count", return_value=0), \
             mock.patch.object(helper, "_lock_path", return_value=os.path.join(self.tmp.name, "l")), \
             mock.patch.object(helper.collect_windows, "available", return_value=True), \
             mock.patch.object(helper.collect_windows, "desktop_interop", return_value=""), \
             mock.patch.object(helper.subprocess, "run") as run:
            err = helper.start()
        self.assertIn("desktop session", err)
        run.assert_not_called()

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
        with mock.patch.object(helper, "ps_json") as ps, \
             mock.patch.object(helper, "_paths", return_value=("C:\\x", os.path.join(self.tmp.name, "input.jsonl"))):
            helper._stop_all(pids=["13544", "7560", "1; Stop-Computer", ""])
        script = ps.call_args.args[0]
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
