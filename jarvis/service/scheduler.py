"""The always-on loop: run the audits one at a time, each on its own interval.

The collectors have wildly different costs. Reading /proc takes 20ms; a
PowerShell audit takes 15-60s because crossing the WSL interop boundary and
spinning up powershell.exe dominates everything else. So jobs run on their own
intervals, and never concurrently -- a single worker thread runs them one at a
time, because two simultaneous powershell.exe launches are slower than running
them back to back and would fight over the same interop pipe.
"""

import threading
import time
import traceback

from jarvis.core import collection
from jarvis.core.store import Store
from jarvis.response import alert, remediation
from jarvis.response.reporting import notifications
from jarvis.service import sdnotify
from jarvis.service.jobs import run_job
from jarvis.service.schedule import JOBS


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
        self.started_at = time.time()
        self.lock = threading.Lock()

    def force(self, name):
        if name in JOBS:
            with self.lock:
                self.forced.append(name)
            return True
        return False

    def _due(self):
        with self.lock:
            if self.forced:
                return self.forced.pop(0)
        now = time.time()
        most_overdue, score = None, None
        for name, t in self.next_run.items():
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
        store = Store(self.db_path)
        try:
            while True:
                self.heartbeat = time.time()
                name = self._due()
                if name is None:
                    time.sleep(1)
                    continue
                self.current = name
                started = time.time()
                findings, err = [], ""
                try:
                    with collection.observe() as observation:
                        findings = run_job(name, self.hosts, self.db_path)
                    err = observation.error
                    findings, err = remediation.process(
                        store, alert.load_conf(), name, findings, err,
                        lambda: run_job(name, self.hosts, self.db_path))
                    store.save_snapshot(name, findings, max(0.0, time.time() - started), err)
                except Exception:
                    # One broken collector must never stop the other six.
                    err = traceback.format_exc()[-800:]
                    store.save_snapshot(name, [], max(0.0, time.time() - started), err)
                finally:
                    self.current = None
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
        alive = scheduler.is_alive()
        progressed = (time.time() - scheduler.heartbeat) < stall_limit
        if alive and progressed:
            sdnotify.watchdog()
        # else: withhold the ping and let systemd restart us.
