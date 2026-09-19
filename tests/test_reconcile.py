import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jarvis.collectors.telemetry import reconcile
from jarvis.core import event
from jarvis.core.eventlog import EventLog
from jarvis.platform.native.normalize import SYSMON


def iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat().replace("+00:00", "Z")


class ProcessReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "eventlog"
        self.log = EventLog(self.root, writer=True)
        self.addCleanup(self.log.close)
        self.now = time.time()

    def ev(self, record, pid, guid, started, action="start"):
        return event.make(
            host="WINBOX", sensor="sensor", device="device", boot="boot-7",
            channel=SYSMON, generation="generation", record=record,
            source="sysmon", source_event=1 if action == "start" else 5,
            time=iso(started), received=iso(self.now), category="process",
            action=action, process={"pid": pid, "guid": guid, "image": r"C:\x\worker.exe"})

    def commit(self, events, *, created=None, continuous=None, status="complete", gap=None):
        created = self.now if created is None else created
        continuous = self.now - 300 if continuous is None else continuous
        self.log.append(events, {
            "sensor": "sensor", "channel": SYSMON, "sequence": 1,
            "generation": "generation", "status": status, "gap": gap,
            "created_at": iso(created), "continuous_since": iso(continuous),
            "host": "WINBOX", "device": "device", "boot": "boot-7",
        })

    def snapshot(self, pid=42, started=None, observed=None):
        return [{"host": "win", "pid": pid, "name": "worker.exe",
                 "exe": r"C:\x\worker.exe", "started": iso(started or self.now - 60),
                 "observed_at": iso(observed or self.now)}]

    def test_snapshot_process_without_start_event_is_visibility_evidence(self):
        self.commit([self.ev(1, 7, "{other}", self.now - 80)])
        findings = reconcile.processes(self.snapshot(), self.now, self.root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "temporal-process-start-missing")
        self.assertIn("boot-7:42", findings[0]["subject_id"])

    def test_exact_instance_match_is_consistent(self):
        started = self.now - 60
        self.commit([self.ev(1, 42, "{worker}", started)])
        self.assertEqual(reconcile.processes(self.snapshot(started=started), self.now, self.root), [])

    def test_pid_reuse_does_not_match_a_different_execution(self):
        self.commit([self.ev(1, 42, "{old}", self.now - 180)])
        findings = reconcile.processes(self.snapshot(started=self.now - 60), self.now, self.root)
        self.assertEqual(findings[0]["rule_id"], "temporal-process-start-missing")

    def test_recorded_exit_conflicts_with_live_exact_instance(self):
        started = self.now - 90
        self.commit([self.ev(1, 42, "{worker}", started),
                     self.ev(2, 42, "{worker}", self.now - 30, action="exit")])
        findings = reconcile.processes(self.snapshot(started=started), self.now, self.root)
        self.assertEqual(findings[0]["rule_id"], "temporal-process-exit-conflict")

    def test_exit_after_snapshot_does_not_create_a_race_false_positive(self):
        started = self.now - 90
        snapshot_at = self.now - 30
        self.commit([self.ev(1, 42, "{worker}", started),
                     self.ev(2, 42, "{worker}", self.now - 20, action="exit")])
        self.assertEqual(reconcile.processes(
            self.snapshot(started=started, observed=snapshot_at), self.now, self.root), [])

    def test_process_before_continuous_coverage_is_unknown(self):
        self.commit([self.ev(1, 7, "{other}", self.now - 20)],
                    continuous=self.now - 30)
        self.assertEqual(reconcile.processes(
            self.snapshot(started=self.now - 60), self.now, self.root), [])

    def test_stale_or_gapped_stream_cannot_contradict_snapshot(self):
        self.commit([self.ev(1, 7, "{other}", self.now - 400)], created=self.now - 400)
        self.assertEqual(reconcile.processes(self.snapshot(), self.now, self.root), [])


if __name__ == "__main__":
    unittest.main()
