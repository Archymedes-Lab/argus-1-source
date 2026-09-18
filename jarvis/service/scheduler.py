"""The always-on loop: run the audits one at a time, each on its own interval.

The collectors have wildly different costs. Reading /proc takes 20ms; a
PowerShell audit takes 15-60s because crossing the WSL interop boundary and
spinning up powershell.exe dominates everything else. So jobs run on their own
intervals, and never concurrently -- a single worker thread runs them one at a
time, because two simultaneous powershell.exe launches are slower than running
them back to back and would fight over the same interop pipe.

One exception: the jobs that prove JARVIS is watching at all run in a lane of
their own. They are cheap (a socket stat, a heartbeat read, a /proc walk plus
one short process listing), and behind a single queue they starved: on
2026-09-17 `intrusion` (48s) then `secrets` (192s) held the worker, `bridge`
and `scan` aged past their health limits, and the Windows monitor mailed
"monitoring unavailable" about a daemon that was perfectly alive. A long audit
must never be able to make JARVIS look dead.
"""

import threading
import time
import traceback

from jarvis.core import collection, incidents
from jarvis.core.store import Store
from jarvis.response import alert, defense, remediation
from jarvis.response.reporting import notifications
from jarvis.service import sdnotify
from jarvis.service.jobs import run_job
from jarvis.service.schedule import JOBS

# The priority lane: short jobs that health and the watchdogs judge freshness
# by. Each must stay well under a few seconds, or it starves its own lane.
FAST = ("bridge", "input_hook", "scan")


class Scheduler(threading.Thread):
    """Runs the audits forever, one at a time, each on its own interval."""

    daemon = True

    def __init__(self, db_path, hosts):
        super().__init__(name="jarvis-scheduler")
        self.db_path = db_path
        self.hosts = hosts
        # Give every cold-start job a real deadline. Using 0 here makes every
        # job that has not run yet appear decades more overdue than a recurring
        # short-interval job. The result is a full, multi-minute cold-start
        # sweep before scan/bridge/input_hook get their second turn.
        first_deadline = time.time()
        self.next_run = {name: first_deadline for name in JOBS}
        # Coverage judges persisted timestamps. On restart those timestamps are
        # necessarily from the previous process until each collector gets its
        # first turn; running coverage halfway through that cold-start sweep
        # sends a burst of false "stale" pages for perfectly healthy jobs later
        # in the dict. Hold the automatic coverage pass until every other job
        # has attempted once. A manually forced pass still runs immediately.
        self.cold_start_pending = set(JOBS) - {"coverage", "report"}
        self.forced = []
        self.current = None
        # Bumped at the top of every loop iteration. The systemd watchdog pings
        # only while this keeps advancing, so a wedged scheduler — alive process,
        # frozen snapshots — gets the service restarted instead of going
        # unnoticed. It is deliberately not touched mid-job: the longest job
        # (~106s) must not look like a hang, but a multi-minute stall must.
        self.heartbeat = time.time()
        self.fast_heartbeat = time.time()
        self.fast_current = None
        self.fast_thread = None
        self.started_at = time.time()
        self.lock = threading.Lock()

    def force(self, name):
        if name in JOBS:
            with self.lock:
                self.forced.append(name)
            return True
        return False

    def _due(self, lane=None):
        """The job to run next. `lane` is "fast", "main", or None for either."""
        member = (lambda n: True) if lane is None else (
            (lambda n: n in FAST) if lane == "fast" else (lambda n: n not in FAST))
        with self.lock:
            for i, name in enumerate(self.forced):
                if member(name):
                    return self.forced.pop(i)
        now = time.time()
        most_overdue, score = None, None
        for name, t in self.next_run.items():
            if not member(name):
                continue
            if name in ("coverage", "report") and self.cold_start_pending:
                continue
            if t > now:
                continue
            # Compare lateness as a fraction of each job's own cadence. An
            # absolute oldest-deadline policy starves the one-minute watchdogs
            # behind every not-yet-run hourly collector after a restart or a
            # long suspend. Relative lateness keeps all cadences represented;
            # stable dict order remains the tie-breaker on the first pass.
            overdue = (now - t) / max(1, JOBS[name][0])
            if score is None or overdue > score:
                most_overdue, score = name, overdue
        return most_overdue

    def run(self):
        self.fast_thread = threading.Thread(target=self._lane, args=("fast",),
                                            name="jarvis-fast-lane", daemon=True)
        self.fast_thread.start()
        self._lane("main")

    def fast_alive(self):
        return self.fast_thread is None or self.fast_thread.is_alive()

    def _lane(self, lane):
        store = Store(self.db_path)
        beat = "heartbeat" if lane == "main" else "fast_heartbeat"
        running = "current" if lane == "main" else "fast_current"
        try:
            while True:
                setattr(self, beat, time.time())
                name = self._due(lane)
                if name is None:
                    time.sleep(1)
                    continue
                setattr(self, running, name)
                try:
                    findings, err = self.run_once(store, name)
                finally:
                    setattr(self, running, None)
                    self.next_run[name] = time.time() + JOBS[name][0]
                    self.cold_start_pending.discard(name)
                # Page out anything that warrants it — especially a collector
                # that has stopped recording. Guarded so a mail failure can
                # never take down the scheduler.
                try:
                    notifications.deliver(store, name, findings, error=err)
                except Exception:
                    pass
        finally:
            store.close()

    def run_once(self, store, name):
        """Collect -> durable observation -> bounded response -> presentation.

        Response failure must not erase successfully collected evidence. A
        journal failure inhibits response and is visible in the job snapshot.
        Collectors with their own internal maintenance are not sandboxed by
        this pipeline; the privileged broker remains a separate migration.
        """
        started = time.time()
        findings, err, status = [], "", "unavailable"
        try:
            with collection.observe() as observation:
                findings = list(run_job(name, self.hosts, self.db_path) or [])
            err, status = observation.error, observation.status
        except Exception:
            err = traceback.format_exc()[-800:]

        try:
            receipt = store.record_observation(name, findings, coverage=status, error=err)
        except Exception:
            err = (err + "; defender journal failed; response inhibited: " +
                   traceback.format_exc()[-500:]).strip("; ")
        else:
            try:
                conf = alert.load_conf()
                # An explicit visibility finding can mean incomplete coverage
                # even when a legacy collector did not raise an exception.
                if receipt["coverage"] != "complete" and not err:
                    err = "collector coverage incomplete"
                findings, err = remediation.process(
                    store, conf, name, findings, err,
                    lambda: run_job(name, self.hosts, self.db_path))
                findings = defense.process(store, conf, name, findings,
                                           coverage=incidents.coverage_status(
                                               findings, err, receipt["coverage"]))
            except Exception:
                err = (err + "; response failed: " + traceback.format_exc()[-500:]).strip("; ")
        store.save_snapshot(name, findings, max(0.0, time.time() - started), err)
        return findings, err


def watchdog_loop(scheduler):
    """Feed the systemd hardware-style watchdog, but only while healthy.

    Healthy == the scheduler thread is alive and has looped within
    STALL_LIMIT seconds. If it has wedged or died we simply stop pinging;
    systemd then hits WatchdogSec, kills the process and starts it clean.
    A monitor that quietly stops monitoring is the exact failure this whole
    module exists to prevent, so the watchdog treats "no progress" as death.
    """
    usec = sdnotify.watchdog_usec()
    if not usec:
        return
    interval = max(5.0, usec / 1_000_000 / 3)
    # A job may honestly run for minutes — `intel` does networked LLM calls —
    # so the bar for "wedged" is deliberately high. Killing a healthy daemon
    # mid-refresh would make this hardening an outage of its own. The
    # out-of-daemon selfcheck timer is the fast detector; this is the backstop.
    stall_limit = max(600.0, usec / 1_000_000 * 0.8)
    while True:
        time.sleep(interval)
        alive = scheduler.is_alive() and scheduler.fast_alive()
        # The fast lane's jobs take seconds, so a minute without a loop is a hang.
        progressed = ((time.time() - scheduler.heartbeat) < stall_limit and
                      (time.time() - scheduler.fast_heartbeat) < 300)
        if alive and progressed:
            sdnotify.watchdog()
        # else: withhold the ping and let systemd restart us.
