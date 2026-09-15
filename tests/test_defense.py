import os
import tempfile
import unittest
from unittest import mock

from jarvis.core.store import Store
from jarvis.response import defense, questions
from jarvis.response.actions import base, quarantine, suspend


def dropped(path, sev="high"):
    return {"category": "dropped file", "severity": sev, "host": "wsl",
            "title": "a file named in threat intelligence exists here", "where": path,
            "detail": "listed as an attacker-created path"}


class QuarantineActionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.qroot = tempfile.TemporaryDirectory()
        self.patch = mock.patch.object(quarantine, "QUARANTINE_DIR",
                                       os.path.join(self.qroot.name, "q"))
        self.patch.start()
        self.action = quarantine.QuarantineFile()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()
        self.qroot.cleanup()

    def _file(self, name="payload.sh", body="#!/bin/sh\necho evil\n"):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w") as fh:
            fh.write(body)
        return p

    def test_matches_only_a_real_non_system_file(self):
        p = self._file()
        self.assertEqual(self.action.match(dropped(p), "hunt"), {"path": p})
        self.assertIsNone(self.action.match(dropped("/usr/bin/python3"), "hunt"))
        self.assertIsNone(self.action.match(dropped(p + ".gone"), "hunt"))
        self.assertIsNone(self.action.match({**dropped(p), "host": "win"}, "hunt"))

    def test_apply_moves_and_undo_restores_the_bytes(self):
        p = self._file(body="payload-body")
        ok, record, detail = self.action.apply({"path": p}, None)
        self.assertTrue(ok, detail)
        self.assertFalse(os.path.exists(p))
        self.assertTrue(os.path.isfile(record["stored"]))
        self.assertTrue(os.path.exists(p + ".jarvis-quarantined"))
        ok, detail = self.action.undo({"path": p}, record)
        self.assertTrue(ok, detail)
        with open(p) as fh:
            self.assertEqual(fh.read(), "payload-body")
        self.assertFalse(os.path.exists(p + ".jarvis-quarantined"))

    def test_undo_never_overwrites_a_file_that_returned(self):
        p = self._file()
        ok, record, _ = self.action.apply({"path": p}, None)
        self.assertTrue(ok)
        with open(p, "w") as fh:
            fh.write("something new")
        ok, detail = self.action.undo({"path": p}, record)
        self.assertFalse(ok)
        self.assertIn("exists again", detail)


class SuspendActionTests(unittest.TestCase):
    def _state(self, pid, want, tries=50):
        import time
        for _ in range(tries):
            with open(f"/proc/{pid}/stat") as fh:
                st = fh.read().rsplit(")", 1)[1].split()[0]
            if st == want:
                return st
            time.sleep(0.01)
        return st

    def test_never_matches_a_protected_process(self):
        action = suspend.SuspendProcess()
        with mock.patch.object(suspend, "_alive", return_value=True), \
             mock.patch.object(suspend, "_name", return_value="systemd"):
            self.assertIsNone(action.match({"host": "wsl", "pid": 1234}, "sysmon_linux"))

    def test_apply_and_undo_pause_resume_a_real_process(self):
        import signal
        import subprocess
        proc = subprocess.Popen(["sleep", "30"])
        try:
            action = suspend.SuspendProcess()
            target = action.match({"host": "wsl", "pid": proc.pid}, "sysmon_linux")
            self.assertIsNotNone(target)
            ok, record, _ = action.apply(target, None)
            self.assertTrue(ok)
            self.assertEqual(self._state(proc.pid, want="T"), "T")  # stopped
            ok, _ = action.undo(target, record)
            self.assertTrue(ok)
            self.assertIn(self._state(proc.pid, want="S"), ("S", "R"))
        finally:
            proc.send_signal(signal.SIGCONT)
            proc.kill()
            proc.wait()


class LadderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.qroot = tempfile.TemporaryDirectory()
        self.qpatch = mock.patch.object(quarantine, "QUARANTINE_DIR",
                                        os.path.join(self.qroot.name, "q"))
        self.qpatch.start()
        self.file = os.path.join(self.tmp.name, "drop.sh")
        with open(self.file, "w") as fh:
            fh.write("evil")

    def tearDown(self):
        self.qpatch.stop()
        self.store.close()
        self.tmp.cleanup()
        self.qroot.cleanup()

    def test_off_by_default_proposes_never_acts(self):
        rung, action, _ = defense.decide(dropped(self.file), "hunt", {}, {})
        self.assertEqual(rung, defense.PROPOSE)
        self.assertEqual(action.id, "quarantine_file")
        defense.process(self.store, {}, "hunt", [dropped(self.file)])
        self.assertTrue(os.path.exists(self.file))            # untouched
        self.assertEqual(len(defense.pending(self.store)), 1)

    def test_enabled_and_high_severity_acts_and_is_undoable(self):
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        rung, action, _ = defense.decide(dropped(self.file), "hunt", conf, {})
        self.assertEqual(rung, defense.AUTO)
        out = defense.process(self.store, conf, "hunt", [dropped(self.file)])
        self.assertFalse(os.path.exists(self.file))           # quarantined
        eid = out[0]["defense"]["id"]
        self.assertEqual(out[0]["defense"]["status"], "applied")
        ok, _ = defense.undo(self.store, eid)
        self.assertTrue(ok)
        self.assertTrue(os.path.exists(self.file))            # restored

    def test_enabling_does_not_lower_the_bar_for_a_medium(self):
        conf = {"autonomous_defense": True, "auto_quarantine": True}
        rung, _, _ = defense.decide(dropped(self.file, "medium"), "hunt", conf, {})
        self.assertEqual(rung, defense.PROPOSE)

    def test_approve_runs_a_proposal_and_records_it(self):
        defense.process(self.store, {}, "hunt", [dropped(self.file)])
        eid = next(iter(defense.pending(self.store)))
        ok, detail = defense.approve(self.store, eid)
        self.assertTrue(ok, detail)
        self.assertFalse(os.path.exists(self.file))
        self.assertIn(eid, defense.applied(self.store))

    def test_an_acknowledged_finding_is_left_alone(self):
        from jarvis.response import acknowledge
        f = dropped(self.file)
        acknowledge.acknowledge(self.store, f, "hunt", "mine")
        rung, _, _ = defense.decide(f, "hunt", {"autonomous_defense": True,
                                                "auto_quarantine": True},
                                    acknowledge.load(self.store))
        self.assertEqual(rung, defense.WATCH)


class QuestionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _account(self):
        return {"category": "accounts", "severity": "high", "host": "win",
                "title": "account hidden from the sign-in screen: Weird",
                "where": "Winlogon", "detail": "hidden"}

    def test_a_confirm_finding_becomes_a_specific_question(self):
        self.store.save_snapshot("backdoor", [self._account()])
        qs = questions.build(self.store, self.store.get_snapshots(), {})
        self.assertEqual(len(qs), 1)
        self.assertIn("Weird", qs[0]["prompt"])
        self.assertIn("Did you", qs[0]["prompt"])

    def test_yes_acknowledges_and_no_longer_asks(self):
        self.store.save_snapshot("backdoor", [self._account()])
        qid = questions.build(self.store, self.store.get_snapshots(), {})[0]["id"]
        ok, msg = questions.answer(self.store, qid, "yes")
        self.assertTrue(ok)
        self.assertIn("expected", msg)
        self.assertEqual(questions.build(self.store, self.store.get_snapshots(), {}), [])

    def test_no_flags_and_records_the_answer(self):
        self.store.save_snapshot("backdoor", [self._account()])
        qid = questions.build(self.store, self.store.get_snapshots(), {})[0]["id"]
        with mock.patch.object(defense, "approve", return_value=(True, "blocked")):
            ok, msg = questions.answer(self.store, qid, "no")
        self.assertTrue(ok)

    def test_an_unknown_answer_is_rejected(self):
        self.store.save_snapshot("backdoor", [self._account()])
        qid = questions.build(self.store, self.store.get_snapshots(), {})[0]["id"]
        ok, _ = questions.answer(self.store, qid, "maybe")
        self.assertFalse(ok)


class TriageIntegrationTests(unittest.TestCase):
    def test_an_applied_action_reads_as_jarvis_handled_with_undo(self):
        from jarvis.response.reporting import triage
        f = {**dropped("/tmp/x"), "defense": {"rung": "auto", "status": "applied",
             "detail": "quarantined", "undo": "jarvis defend undo ab12"}}
        r = triage.classify(f, "hunt")
        self.assertEqual(r["owner"], triage.JARVIS)
        self.assertEqual(r["command"], "jarvis defend undo ab12")

    def test_a_proposal_reads_as_your_approval_with_the_command(self):
        from jarvis.response.reporting import triage
        f = {**dropped("/tmp/x"), "defense": {"rung": "propose", "preview": "Move it.",
             "approve": "jarvis defend approve ab12"}}
        r = triage.classify(f, "hunt")
        self.assertEqual(r["owner"], triage.YOU_DO)
        self.assertEqual(r["command"], "jarvis defend approve ab12")


class RegistryTests(unittest.TestCase):
    def test_every_auto_action_is_reversible(self):
        for a in base.registry().values():
            if a.autonomy == base.AUTO:
                self.assertTrue(a.reversible, a.id)


if __name__ == "__main__":
    unittest.main()
