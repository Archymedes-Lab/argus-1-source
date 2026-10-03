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

    def lsass(self, granted):
        findings = self.audit([{
            "id": 10, "image": r"C:\x\tool.exe",
            "target": r"C:\Windows\System32\lsass.exe",
            "granted": granted, "time": "2026-09-15T10:00:00Z",
        }])
        return [f for f in findings if f["category"] == "credential access"]

    def test_lsass_access_severity_follows_granted_rights(self):
        # Query-only rights cannot read memory but can open the token.
        for granted in ("0x1000", "0x400", "0x101400"):
            hit = self.lsass(granted)
            self.assertEqual([(f["severity"], f["title"]) for f in hit],
                             [("medium", "tool.exe queried LSASS")], granted)
        for granted, severity in (("0x1010", "critical"), ("0x1410", "critical"),
                                  ("0x1fffff", "critical"), ("0x1040", "high"),
                                  ("0x1080", "high"), ("0x1800", "high"),
                                  ("", "high"), ("junk", "high"), ("0x0", "high")):
            hit = self.lsass(granted)
            self.assertEqual([(f["severity"], f["title"]) for f in hit],
                             [(severity, "tool.exe opened LSASS memory")], granted)

    def test_stored_query_only_lsass_rows_are_rejudged_and_migrated(self):
        import tempfile
        from pathlib import Path

        from jarvis.core.store import Store
        from jarvis.core.util import now
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(str(Path(tmp) / "j.db"))
            try:
                old = "granted access 0x{} — 2026-09-22 19:20:33. This is the detection"
                for tool, mask in (("hp.exe", "1000"), ("dump.exe", "1010")):
                    store.db.execute(
                        "INSERT INTO sysmon_hits(ts,category,severity,title,detail,where_) "
                        "VALUES(?,?,?,?,?,?)",
                        (now(), "credential access", "critical" if mask == "1010" else "high",
                         f"{tool} opened LSASS memory", old.format(mask), tool))
                store.commit()
                out = {f["where"]: f for f in sysmon._remember(store, [], 24)}
                self.assertEqual((out["hp.exe"]["severity"], out["hp.exe"]["title"]),
                                 ("medium", "hp.exe queried LSASS"))
                self.assertEqual((out["dump.exe"]["severity"], out["dump.exe"]["title"]),
                                 ("critical", "dump.exe opened LSASS memory"))
                titles = [r["title"] for r in store.db.execute(
                    "SELECT title FROM sysmon_hits ORDER BY title")]
                self.assertEqual(titles, ["dump.exe opened LSASS memory",
                                          "hp.exe queried LSASS"])
            finally:
                store.close()

    DROP = ("Events dropped from driver queue:  ProcessCreate:98 RegistryEvent:52195. "
            "DriverQueueSize: 50000, 1 bytes.")

    def drops(self, events):
        return {f["title"]: f["severity"] for f in self.audit(events)
                if f["category"] == "telemetry loss"}

    def test_drop_reported_with_the_service_start_is_the_boot_backlog(self):
        start = {"id": 4, "state": "Started", "time": "2026-09-23T05:19:45.403Z"}
        drop = {"id": 255, "description": self.DROP, "time": "2026-09-23T05:19:45.407Z"}
        for events in ([start, drop], [drop, start]):
            self.assertEqual(self.drops(events),
                             {sysmon.BOOT_DROP_TITLE: "medium"})

    def test_drop_while_running_stays_high(self):
        start = {"id": 4, "state": "Started", "time": "2026-09-23T05:19:45Z"}
        late = {"id": 255, "description": self.DROP, "time": "2026-09-23T06:00:00Z"}
        self.assertEqual(self.drops([start, late]),
                         {"Sysmon dropped events before logging them": "high"})

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


class CtrlRoutineAddressTests(unittest.TestCase):
    CTRL = "0x00007FFB2EBF6400"

    def test_address_proof_is_limited_to_the_same_burst(self):
        rows = [(r"C:\Windows\System32\csrss.exe", "target.exe",
                 "2026-09-23T09:48:50Z", "KERNELBASE.dll", "CtrlRoutine", self.CTRL)]
        known = sysmon._ctrl_routine_addresses(rows)
        self.assertTrue(sysmon._near_ctrl_routine(
            self.CTRL, "2026-09-23T09:48:46Z", known))
        self.assertFalse(sysmon._near_ctrl_routine(
            self.CTRL, "2026-09-22T09:48:46Z", known))
        self.assertFalse(sysmon._near_ctrl_routine(
            self.CTRL, "2026-09-23T09:49:22Z", known))

    def test_unresolved_csrss_start_at_a_known_ctrlroutine_address_is_routine(self):
        v = sysmon.thread_verdict(r"C:\Windows\System32\csrss.exe", r"C:\x\llama-server.exe",
                                  "-", "-", self.CTRL, {int(self.CTRL, 16)})
        self.assertIsNone(v)

    def test_unknown_address_or_other_source_stays_critical(self):
        for image, addr in ((r"C:\Windows\System32\csrss.exe", "0x00007FFB2EBF6500"),
                            (r"C:\t\evil.exe", self.CTRL)):
            v = sysmon.thread_verdict(image, r"C:\x\llama-server.exe", "-", "-", addr,
                                      {int(self.CTRL, 16)})
            self.assertEqual(v[0], "critical", image)


class InjectionReplayTests(unittest.TestCase):
    def test_rule_change_replays_full_native_window_before_clearing_stored_hit(self):
        import tempfile
        from pathlib import Path

        from jarvis.core.store import Store

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(str(Path(tmp) / "j.db"))
            self.addCleanup(store.close)
            store.set_meta("sysmon_thread_rules", "start-module-v1")
            store.db.execute(
                "INSERT INTO sysmon_hits(ts,category,severity,title,detail,where_) "
                "VALUES(strftime('%s','now'),'injection','critical',?,?,?)",
                ("csrss.exe created a thread inside llama-server.exe", "old verdict",
                 r"C:\Windows\System32\csrss.exe"))
            store.db.execute(
                "INSERT INTO sysmon_hits(ts,category,severity,title,detail,where_) "
                "VALUES(strftime('%s','now'),'injection','critical',?,?,?)",
                ("unmatched injection", "underlying event unavailable", "unknown.exe"))
            store.commit()
            address = "0x00007FFB2EBF6400"
            events = [
                {"id": 8, "seq": i + 1,
                 "image": r"C:\Windows\System32\csrss.exe",
                 "target": rf"C:\x\routine{i}.exe", "time": "2026-09-23T09:48:46Z",
                 "start_module": r"C:\Windows\System32\KERNELBASE.dll",
                 "start_function": "CtrlRoutine", "start_address": address}
                for i in range(40)
            ]
            # The previously critical event is after the ordinary 40-event
            # display cap. The complete replay still has to rejudge it.
            events.append({"id": 8, "seq": 41,
                           "image": r"C:\Windows\System32\csrss.exe",
                           "target": r"C:\x\llama-server.exe",
                           "time": "2026-09-23T09:48:46Z", "start_module": "",
                           "start_function": "", "start_address": address})
            ordinary = ({"events": [], "complete": True, "rareComplete": True}, 42)
            replay = ({"events": events, "complete": True, "rareComplete": True}, 42)
            with mock.patch.object(sysmon, "_native", side_effect=[ordinary, replay]) as read:
                out = sysmon.audit(store, incremental=True)
            self.assertIsNone(read.call_args_list[0].kwargs["since"])
            self.assertIsNotNone(read.call_args_list[1].kwargs["since"])
            self.assertEqual(read.call_args_list[1].kwargs["event_ids"], {8})
            self.assertNotIn("csrss.exe created a thread inside llama-server.exe",
                             [f["title"] for f in out])
            self.assertIn("unmatched injection", [f["title"] for f in out])
            self.assertEqual(store.get_meta("sysmon_thread_rules"), sysmon.THREAD_RULES)

    def test_incomplete_replay_preserves_prior_critical(self):
        import tempfile
        from pathlib import Path

        from jarvis.core.store import Store

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(str(Path(tmp) / "j.db"))
            self.addCleanup(store.close)
            store.set_meta("sysmon_thread_rules", "start-module-v1")
            store.db.execute(
                "INSERT INTO sysmon_hits(ts,category,severity,title,detail,where_) "
                "VALUES(strftime('%s','now'),'injection','critical',?,?,?)",
                ("critical injection", "old verdict", "source.exe"))
            store.commit()
            ordinary = ({"events": [], "complete": True, "rareComplete": True}, 42)
            replay = ({"events": [], "complete": False, "rareComplete": False}, 42)
            with mock.patch.object(sysmon, "_native", side_effect=[ordinary, replay]):
                out = sysmon.audit(store, incremental=True)
            self.assertIn("critical injection", [f["title"] for f in out])
            self.assertEqual(store.get_meta("sysmon_thread_rules"), "start-module-v1")


class BrokerLsassTests(unittest.TestCase):
    def test_only_a_reviewed_broker_script_is_recognised(self):
        import sqlite3
        from unittest import mock

        from jarvis.platform import broker

        class Log:
            def __init__(self, cmd):
                self.db = sqlite3.connect(":memory:")
                self.db.execute("CREATE TABLE processes(guid TEXT, cmdline TEXT)")
                self.db.execute("INSERT INTO processes VALUES('g', ?)", (cmd,))

            def close(self):
                pass

        ok = ('"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile '
              '-File C:\\ProgramData\\Jarvis\\Broker\\inputaudit.ps1 ')
        for cmd, drift, want in ((ok, [], "inputaudit.ps1"),
                                 (ok, ["inputaudit.ps1"], ""),
                                 (ok.replace("ProgramData", "Users\\x"), [], ""),
                                 (ok.replace("inputaudit", "evil"), [], "")):
            with mock.patch.object(sysmon, "EventLog", return_value=Log(cmd)), \
                 mock.patch.object(broker, "drifted", return_value=drift):
                self.assertEqual(sysmon._broker_script("g"), want, cmd)
