"""Lane fairness: no job can monopolise a lane, and lateness is real.

Measured fault (2026-10-10, release 677b2a83b901): the Windows reviver
re-forced a capped sysmon every ~30 s. Each run took about 57 s on the single
main worker, and the forced floor times criticality 4 beat every starving
collector. sysmon ran back to back for 7 hours while 36 collectors went STALE.
See docs/architecture/LANE-FAIRNESS-AND-OUTAGE-RECORD.md.
"""

import unittest
from unittest import mock

from jarvis.service import scheduler as sched_mod
from jarvis.service.schedule import JOBS
from jarvis.service.scheduler import BULK, FAST, STARVING, Scheduler

# Measured durations (s) from the live dashboard on 2026-10-10; others ~5 s.
DURATIONS = {"sysmon": 57.0, "evidence": 314.0, "hidden": 32.5, "netwatch": 24.7,
             "internet": 21.2, "world": 49.7, "toolchain": 23.6, "rust_mirror": 27.2,
             "firewall": 15.3, "intrusion": 16.8, "spy": 13.4, "implant": 11.5,
             "resources": 11.3, "control": 10.5, "audio": 9.9, "boot": 83.6}


def _no_pressure():
    return mock.patch("jarvis.core.governor.live_pressure", return_value=(False, ""))


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


class ForceTests(unittest.TestCase):
    def setUp(self):
        self.s = Scheduler(":memory:", ("wsl", "win"))
        self.s.cold_start_pending.clear()

    def test_repeated_force_requests_collapse_into_one(self):
        for _ in range(10):
            self.assertTrue(self.s.force("sysmon"))
        self.assertEqual(self.s.forced, ["sysmon"])

    def test_unknown_job_is_refused(self):
        self.assertFalse(self.s.force("nope"))
        self.assertEqual(self.s.forced, [])

    def test_owner_force_of_an_idle_job_runs_at_once(self):
        now = 1_000_000.0
        self.s.next_run = {n: now + 9e5 for n in JOBS}
        self.s.evidence_ts = {n: now - 10 for n in JOBS}
        self.s.force("firewall")
        with _no_pressure(), mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertEqual(self.s._due("main"), "firewall")
        self.assertEqual(self.s.forced, [])

    def test_reforced_job_that_just_ran_waits_but_is_not_dropped(self):
        now = 1_000_000.0
        self.s.next_run = {n: now + 9e5 for n in JOBS}
        self.s.evidence_ts = {n: now - 10 for n in JOBS}
        self.s.last_attempt["sysmon"] = now - 5
        self.s.force("sysmon")
        with _no_pressure(), mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertIsNone(self.s._due("main"))
        self.assertEqual(self.s.forced, ["sysmon"])
        later = now + sched_mod.FORCE_COOLDOWN_S + 1
        with _no_pressure(), mock.patch.object(sched_mod.time, "time", return_value=later):
            self.assertEqual(self.s._due("main"), "sysmon")


class LatenessTests(unittest.TestCase):
    def setUp(self):
        self.s = Scheduler(":memory:", ("wsl", "win"))
        self.s.cold_start_pending.clear()

    def test_restart_does_not_hide_real_staleness(self):
        # After a restart next_run is "now" for every job; six hours of real
        # staleness must still count as six hours.
        now = 1_000_000.0
        self.s.evidence_ts = {"spy": now - 6 * 3600}
        self.assertGreaterEqual(self.s.lateness("spy", now), 6 * 3600 / JOBS["spy"][0])

    def test_no_evidence_at_all_is_long_overdue(self):
        self.s.evidence_ts = {}
        self.assertGreaterEqual(self.s.lateness("audio", 1_000_000.0), STARVING)

    def test_an_attempt_resets_lateness_even_when_it_failed(self):
        now = 1_000_000.0
        self.s.evidence_ts = {"sysmon": now - 7 * 3600}
        self.s.last_attempt["sysmon"] = now - 1
        self.assertLess(self.s.lateness("sysmon", now), 0.01)

    def test_starving_collector_beats_a_forced_critical_one(self):
        now = 1_000_000.0
        self.s.next_run = {n: now - 1 for n in JOBS}
        self.s.evidence_ts = {n: now - 10 for n in JOBS}
        self.s.evidence_ts["audio"] = now - 5600        # 18.7x its 300 s cadence
        self.s.evidence_ts["sysmon"] = now - 700
        self.s.reliability.health["sysmon"].consecutive_failures = 3
        self.s.force("sysmon")
        with _no_pressure(), mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertEqual(self.s._due("main"), "audio")

    def test_governor_defers_by_real_lateness(self):
        from jarvis.core import governor
        governed = sorted(n for n in governor.GOVERNED_JOBS if n in JOBS
                          and n not in FAST and n not in BULK)
        self.assertTrue(governed)
        name = governed[0]
        now = 1_000_000.0
        self.s.next_run = {n: now + 9e5 for n in JOBS}
        self.s.next_run[name] = now - 1
        pressured = mock.patch("jarvis.core.governor.live_pressure",
                               return_value=(True, "CPU 93%"))
        self.s.evidence_ts = {n: now for n in JOBS}
        self.s.evidence_ts[name] = now - 1.5 * JOBS[name][0]
        with pressured, mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertIsNone(self.s._due("main"))       # 1.5x late: deferred
        self.s.evidence_ts[name] = now - 4 * JOBS[name][0]
        with pressured, mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertEqual(self.s._due("main"), name)  # 4x late: runs


class BulkLaneTests(unittest.TestCase):
    def test_evidence_runs_only_in_the_bulk_lane(self):
        s = Scheduler(":memory:", ("wsl", "win"))
        s.cold_start_pending.clear()
        now = 1_000_000.0
        s.next_run = {n: now + 9e5 for n in JOBS}
        s.next_run["evidence"] = now - 1
        with _no_pressure(), mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertIsNone(s._due("main"))
            self.assertIsNone(s._due("fast"))
            self.assertEqual(s._due("bulk"), "evidence")

    def test_lane_liveness_includes_the_bulk_lane(self):
        s = Scheduler(":memory:", ("wsl",))
        s.bulk_thread = mock.Mock(is_alive=mock.Mock(return_value=False))
        self.assertFalse(s.fast_alive())


class MonopolyReplayTests(unittest.TestCase):
    """Replay the measured fault in virtual time: a reviver re-forces sysmon
    every 30 s, each sysmon run takes 57 s, and every collector starts stale
    after a restart."""

    def _replay(self, hours=3.0, force_every=30.0):
        s = Scheduler(":memory:", ("wsl", "win"))
        s.cold_start_pending.clear()
        clock = Clock(1_000_000.0)
        start = clock.t
        main = [n for n in JOBS if n not in FAST and n not in BULK]
        s.next_run = {n: start for n in JOBS}
        s.evidence_ts = {n: start - 6 * 3600 for n in JOBS}   # 6 h stale at restart
        runs = {n: [] for n in main}
        worst = {n: 0.0 for n in main}
        next_force = start
        with _no_pressure(), mock.patch.object(sched_mod.time, "time", clock):
            while clock.t < start + hours * 3600:
                while next_force <= clock.t:
                    s.force("sysmon")
                    next_force += force_every
                name = s._due("main")
                if name is None:
                    clock.t += 1.0
                    continue
                clock.t += DURATIONS.get(name, 5.0)
                s.last_attempt[name] = clock.t
                s.evidence_ts[name] = clock.t
                s.next_run[name] = clock.t + JOBS[name][0]
                runs[name].append(clock.t)
                if clock.t > start + 3600:         # after the catch-up hour
                    for n in main:
                        worst[n] = max(worst[n], s.lateness(n, clock.t))
        return s, runs, worst, start

    def test_every_main_collector_catches_up_within_the_first_hour(self):
        _s, runs, _worst, start = self._replay()
        missing = [n for n, r in runs.items() if not r or r[0] > start + 3600]
        self.assertEqual(missing, [], f"never caught up: {missing}")

    def test_sysmon_cannot_hold_the_lane(self):
        _s, runs, _worst, start = self._replay()
        busy = len(runs["sysmon"]) * DURATIONS["sysmon"]
        self.assertLess(busy / (3 * 3600), 0.25,
                        f"sysmon held {busy / (3 * 3600):.0%} of the main lane")

    def test_staleness_stays_bounded_after_catch_up(self):
        _s, _runs, worst, _start = self._replay()
        over = {n: round(v, 2) for n, v in worst.items() if v >= 3.0}
        self.assertEqual(over, {}, f"collectors past 3x their cadence: {over}")


class OutageHookTests(unittest.TestCase):
    def test_supervise_reports_transitions_to_the_recorder(self):
        s = Scheduler(":memory:", ("wsl",))
        s.outages = mock.Mock()
        snaps = {"hidden": {"ts": 1.0, "error": "", "findings": []}}
        s.supervise_once(snaps)
        s.outages.observe.assert_called_once()
        args = s.outages.observe.call_args[0]
        self.assertIs(args[1], snaps)

    def test_a_failing_recorder_never_breaks_supervision(self):
        import time
        s = Scheduler(":memory:", ("wsl",))
        s.outages = mock.Mock(observe=mock.Mock(side_effect=RuntimeError("disk")))
        snaps = {"hidden": {"ts": time.time() - 340.0, "error": "", "findings": []}}
        self.assertIn("hidden", s.supervise_once(snaps))


if __name__ == "__main__":
    unittest.main()
