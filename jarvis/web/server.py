"""The always-on half: a scheduler that keeps auditing, and a local dashboard.

Design constraints that shaped this:

  * The collectors have wildly different costs. Reading /proc takes 20ms; a
    PowerShell audit takes 15-60s because crossing the WSL interop boundary and
    spinning up powershell.exe dominates everything else. So jobs run on their
    own intervals, and never concurrently -- a single worker thread runs them
    one at a time, because two simultaneous powershell.exe launches are slower
    than running them back to back and would fight over the same interop pipe.

  * The page must never wait for a scan. Every request is served from the last
    stored snapshot, so the dashboard is instant even while a 60-second Windows
    audit is running behind it.

  * Nothing binds beyond localhost. A dashboard listing your firewall gaps and
    running processes is exactly what an attacker would like to read, so the
    listener is 127.0.0.1 and there is no option to change that to 0.0.0.0.
"""

import json
import os
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from jarvis.response import alert
from jarvis.collectors.telemetry import auditd, sysmon, sysmon_linux
from jarvis.collectors.persistence import backdoor, control, implant, startup
from jarvis.collectors.identity import bruteforce, impersonation, secrets
from jarvis.collectors.host import (controlwatch, inputwatch, posture, pixel, spyware,
                                    toolchain)
from jarvis.service import deadman, sdnotify, selfcheck
from jarvis.intel import feeds, hunt, research as intel
from jarvis.collectors.network import (firewall, internetwatch, netwatch, sniffing,
                                       webshell)
from jarvis.collectors.process import hidden, memscan, monitor, resourcewatch
from jarvis.core import retention
from jarvis.response import ledger as ledger_mod
from jarvis.collectors.persistence import asep as asep_mod
from jarvis.service import coverage as coverage_mod
from jarvis.collectors.process import evasion as evasion_mod
from jarvis.collectors.host import intrusion as intrusion_mod
from jarvis.core.paths import STATIC_DIR
from jarvis.core.store import DEFAULT_DB, Store
from jarvis.core.util import now
from jarvis.core import collection

PAGE = str(STATIC_DIR / "dashboard.html")

# name -> (interval seconds, label, callable(hosts) -> list[finding])
# Intervals have to fit through one worker. The scheduler runs jobs strictly
# one at a time on purpose — two concurrent powershell.exe launches are slower
# than running them back to back and fight over the same interop pipe — so the
# sum of (duration / interval) across every job is a duty cycle that must stay
# well under 1. Adding the intel and forensics collectors pushed it over, and
# the symptom was exactly what coverage.py is built to catch: short-interval
# checks silently starving behind a four-minute firewall audit and serving
# hour-old snapshots that still looked current.
#
# Measured on this machine, not estimated. The expensive collectors are the
# ones that cross the WSL interop boundary and ask Windows for a lot: the cost
# is the query, not the interop — a bare powershell.exe round trip is 0.5s.
#
#   hidden 14s   netwatch 10s   implant 15s   posture 14s   intrusion 106s
#   firewall 18s   control 16s   spy 22s   memscan 90s   feeds 90s
#   sysmon 1.5s (incremental; 23s before)   scan 2.2s   secrets 60s
#   toolchain 17s (bounded $HOME walk + one stat pass per extension)
#   coverage/hunt/gaps under 0.5s — they only touch SQLite
#
# Sysmon earned its short interval by reading only what happened since the
# last run instead of re-reading a day of log every time.
JOBS = {
    "scan":     (60,    "Processes & network"),
    # Early in the dict so that on a cold start these two watchdogs run before
    # the long Windows audits, not after them. Both healthy paths are
    # local-only (well under a second), so their position costs nothing.
    #
    # "bridge" is a standalone, fast copy of coverage.py's Windows-bridge
    # check: available() only stats a socket, so at 45s it can page within a
    # minute of the interop link dying instead of waiting for the 10-minute
    # coverage cycle. Its finding is classed as an outage, so it mails
    # immediately regardless of alert_min_severity.
    "bridge":   (45,    "Windows bridge reachability"),
    "input_hook":(45,   "Input monitor watchdog"),
    # The other half of the mutual supervision loop. jarvis-selfcheck.timer
    # restarts this daemon when it dies; this re-arms that timer when it stops.
    # Without it the timer is a single point of failure that nothing watches,
    # and a stopped timer looks exactly like a healthy one from in here.
    "watchdogs":(120,   "Watchdog mutual supervision"),
    "resources":(300,   "Resource pressure"),
    "internet": (120,   "Internet apps & incoming traffic"),
    "controls": (300,   "Brightness & control devices"),
    "deep_hidden": (86400, "Deep process cross-view scan"),
    "hidden":   (300,   "Hidden processes"),
    "firewall": (2400,  "Firewall & inbound"),
    "control":  (1800,  "Control surfaces"),
    "asep":     (3600,  "Autostart points"),
    "spy":      (5400,  "Spyware & capabilities"),
    "pixel":    (3600,  "Screen capture & tracking pixels"),
    "identity": (900,   "Who is acting on this machine"),
    "intrusion":(5400,  "Intrusion artifacts"),
    "evasion":  (1200,  "Evasion & kernel integrity"),
    "coverage": (600,   "Self-audit & blind spots"),
    "boot":     (21600, "Startup analysis"),
    # Local and cheap: compare what intel knows against what is on the box.
    "hunt":     (1800,  "Threat-intel indicator hunt"),
    "gaps":     (21600, "Detection coverage vs current intel"),
    # Networked and metered. One topic per run, so the corpus rotates itself
    # and the daily budget guard in intel.py is what actually bounds spend.
    "intel":    (18000, "Threat-intelligence refresh"),
    # Runs after the equally frequent intel refresh in declaration-order ties,
    # so a report can describe the newest research rather than the prior wave.
    "report":   (300, "Daily advisory & change digests"),
    # Free, unauthenticated and high volume. Each feed has its own publisher
    # cadence; this job just asks which are due.
    "feeds":    (3600,  "Bulk indicator feeds"),
    "implant":  (3600,  "Interception & boundary bypass"),
    # Short interval on purpose: the value is a continuous record, and a drop
    # that happened between two samples is a drop that cannot be investigated.
    "netwatch": (300,   "Network & wireless state"),
    "posture":  (7200,  "Windows security posture"),
    "backdoor": (3600,  "Backdoors & access grants"),
    # The developer trust surface: MCP servers, agent hooks, editor extensions,
    # git hooks and .pth files. Local filesystem only — no interop — but it
    # walks $HOME for repositories and stats every installed extension, so it
    # sits with the hourly collectors rather than the fast ones.
    "toolchain":(3600,  "Developer toolchain trust"),
    # Reads only the alert ledger and the snapshot timestamps, so it costs
    # nothing. Frequent enough that a recurrence is noticed the same day.
    "ledger":   (1800,  "Unresolved & recurring alerts"),
    # Cheap: the helper does the watching, this only drains its output file
    # and runs the injected-event audit. The short-interval "input_hook"
    # watchdog (declared above) is what keeps the helper itself alive.
    "input":    (300,   "Synthetic input"),
    # Walks every readable process's address space; expensive, so it runs
    # rarely and its cost is accounted for in the duty cycle above.
    "memscan":  (7200,  "Memory & instruction level"),
    # Walks the home directory; slow, and secrets do not appear by the minute.
    "secrets":  (43200, "Plaintext credentials"),
    # Counts failed-auth records in the OS logs; one PowerShell call + a log
    # read, so it is cheap enough to run hourly.
    "bruteforce":(3600, "Brute force & auth failures"),
    # Local packet-capture state on both sides.
    "sniffing": (1800,  "Packet capture"),
    # Walks web-server document roots; slow, and web shells do not appear by
    # the minute.
    "webshell": (21600, "Web shells"),
    # Is the Linux syscall-interception layer present and recording?
    "auditd":   (7200,  "Syscall interception posture"),
    # eBPF syscall interception on Linux — reads incrementally, like sysmon.
    "sysmon_linux":(600, "Sysmon for Linux (eBPF)"),
    # The interception layer. Frequent, because its value is catching things
    # that start and exit between the sampling passes.
    "sysmon":   (600,   "Sysmon telemetry"),
}


def _run_job(name, hosts):
    """Run one audit and return its findings in the common shape."""
    if name == "scan":
        # The process scan is stateful (it maintains the baseline), so it needs
        # its own store handle inside the worker thread.
        store = Store(_run_job.db_path)
        try:
            res = monitor.scan(store, hosts=hosts)
            out = []
            for f in res["findings"]:
                remotes = ", ".join(
                    f"{r['ip']}:{r['port']}" for r in f["remotes"][:3]
                    if r["scope"] == "public")
                out.append({
                    "category": "process", "severity": f["severity"],
                    "host": f["host"],
                    "title": f"{f['name']} [pid {f['pid']}]"
                             + (" — NEW" if f["unknown"] else ""),
                    "detail": (f["cmdline"] or "")[:160]
                              + (f"  →  {remotes}" if remotes else ""),
                    "where": f["exe"] or f.get("script") or "",
                })
            for p in res["new_public_peers"]:
                out.append({
                    "category": "peer", "severity": "medium",
                    "host": p["proc"]["host"],
                    "title": "new external peer",
                    "detail": f"{p['ip']}:{p['port']} ← {p['proc']['name']}",
                    "where": p["proc"].get("exe") or "",
                })
            return out
        finally:
            store.close()

    if name == "hidden":
        return hidden.audit(hosts=hosts)[0]
    if name == "deep_hidden":
        return hidden.audit(hosts=hosts, deep=True)[0]
    if name == "controls":
        store = Store(_run_job.db_path)
        try:
            return controlwatch.audit(store, hosts=hosts)
        finally:
            store.close()
    if name == "internet":
        store = Store(_run_job.db_path)
        try:
            return internetwatch.audit(store, hosts=hosts)
        finally:
            store.close()
    if name == "resources":
        store = Store(_run_job.db_path)
        try:
            return resourcewatch.audit(store, hosts=hosts)
        finally:
            store.close()
    if name == "firewall":
        return firewall.audit(hosts=hosts)
    if name == "control":
        return control.audit(hosts=hosts)
    if name == "asep":
        return asep_mod.sort_findings(asep_mod.audit())
    if name == "spy":
        return spyware.sort_findings(spyware.audit())
    if name == "intrusion":
        return intrusion_mod.sort_findings(intrusion_mod.audit())
    if name == "pixel":
        return pixel.audit(hosts=hosts)
    if name == "identity":
        store = Store(_run_job.db_path)
        try:
            return impersonation.audit(store, hosts=hosts)
        finally:
            store.close()
    if name == "evasion":
        return evasion_mod.sort_findings(evasion_mod.audit())
    if name == "bridge":
        return coverage_mod.bridge_status()
    if name == "watchdogs":
        # Both halves of the supervision loop: the systemd timer that restarts
        # this daemon, and the Windows task that reports it missing when WSL
        # itself is down.
        from jarvis.service import connectivity
        out = deadman.audit() + connectivity.audit()
        active, enabled_state = selfcheck.timer_state()
        if not active:
            return out + [{
                "category": "daemon", "severity": "high", "host": "wsl",
                "title": "the out-of-daemon watchdog is not installed",
                "detail": "jarvis-selfcheck.timer is absent, so nothing outside "
                          "this process can restart it if it dies — and a dead "
                          "daemon cannot report its own death. Install with "
                          "`./install.sh --seal`.",
                "where": "jarvis-selfcheck.timer"}]
        err = selfcheck.ensure_timer()
        if err:
            return out + [{
                "category": "daemon", "severity": "high", "host": "wsl",
                "title": "the out-of-daemon watchdog has stopped",
                "detail": f"jarvis-selfcheck.timer is {active}/{enabled_state} "
                          f"and could not be re-armed: {err}",
                "where": "jarvis-selfcheck.timer"}]
        if active != "active" or enabled_state != "enabled":
            # ensure_timer() fixed it. Say so — a watchdog that keeps needing
            # to be restarted is a finding, not a routine success.
            return out + [{
                "category": "daemon", "severity": "medium", "host": "wsl",
                "title": "the out-of-daemon watchdog had stopped and was re-armed",
                "detail": f"jarvis-selfcheck.timer was {active}/{enabled_state}; "
                          f"it is running again. Repeated occurrences mean "
                          f"something is stopping it.",
                "where": "jarvis-selfcheck.timer"}]
        return out + [{
            "category": "daemon", "severity": "ok", "host": "wsl",
            "title": "watchdogs supervise each other",
            "detail": f"jarvis-selfcheck.timer {active}/{enabled_state} — it "
                      f"restarts this daemon, this daemon re-arms it",
            "where": "jarvis-selfcheck.timer"}]
    if name == "coverage":
        return coverage_mod.sort_findings(
            coverage_mod.audit(db_path=_run_job.db_path, hosts=hosts))
    if name == "report":
        store = Store(_run_job.db_path)
        try:
            from jarvis.reporting.cadence import run as report_due
            return report_due(store, JOBS)
        finally:
            store.close()
    if name == "boot":
        return startup.sort_findings(startup.audit())
    if name == "implant":
        return implant.audit(hosts=hosts)
    if name == "posture":
        return posture.audit(hosts=hosts)
    if name == "backdoor":
        return backdoor.audit(hosts=hosts)
    if name == "ledger":
        store = Store(_run_job.db_path)
        try:
            # A row is only "stale" relative to whether its own collector has
            # run since; the snapshot table is where that is recorded.
            snaps = store.get_snapshots()
            job_ts = {k: int(v.get("ts") or 0) for k, v in snaps.items()
                      if not v.get("error")}
            return ledger_mod.audit(store, job_ts=job_ts)
        finally:
            store.close()
    if name == "toolchain":
        store = Store(_run_job.db_path)
        try:
            return toolchain.audit(store, hosts=hosts)
        finally:
            store.close()
    if name == "memscan":
        return memscan.audit(hosts=hosts)
    if name == "secrets":
        return secrets.audit()
    if name == "bruteforce":
        return bruteforce.audit(hosts=hosts)
    if name == "sniffing":
        return sniffing.audit(hosts=hosts)
    if name == "webshell":
        return webshell.audit(hosts=hosts)
    if name == "auditd":
        return auditd.audit(hosts=hosts)
    if name == "sysmon_linux":
        store = Store(_run_job.db_path)
        try:
            return sysmon_linux.audit(store=store, hosts=hosts, incremental=True)
        finally:
            store.close()
    if name == "sysmon":
        store = Store(_run_job.db_path)
        try:
            # Incremental: each run reads only what happened since the
            # last one, instead of re-reading a day of log every ten minutes.
            return sysmon.audit(store=store, hosts=hosts, incremental=True)
        finally:
            store.close()
    if name in ("input", "input_hook"):
        store = Store(_run_job.db_path)
        try:
            # The Windows-side hook does not survive a reboot or a WSL restart
            # and nothing outside this loop respawns it, so supervise() keeps
            # it up — cheaply on the healthy path, with backoff and flap
            # detection when it is not. "input_hook" is the short-interval
            # watchdog; "input" additionally runs the full injected-event audit.
            pids, findings = inputwatch.supervise(store, deep=(name == "input"))
            if name == "input":
                findings += inputwatch.audit(store, pids=pids, supervised=True)
            return findings
        finally:
            store.close()
    if name == "netwatch":
        store = Store(_run_job.db_path)
        try:
            netwatch.record(store)
            return netwatch.audit(store)
        finally:
            store.close()

    if name == "feeds":
        store = Store(_run_job.db_path)
        try:
            results = feeds.refresh(store)
            results.append(feeds.refresh_attack(store))
            out = []
            for r in results:
                if r.get("error"):
                    out.append({"category": "feed", "severity": "medium",
                                "host": "wsl",
                                "title": f"{r['name']} feed failed",
                                "detail": r["error"], "where": ""})
            kept = sum(r.get("kept", 0) for r in results if not r.get("error"))
            if kept:
                out.append({"category": "feed", "severity": "low", "host": "wsl",
                            "title": f"{kept} indicators refreshed",
                            "detail": ", ".join(
                                r["name"] for r in results
                                if r.get("kept")), "where": ""})
            feeds.prune(store)
            # Retire-then-remove: prune() marks feed entries retired, and
            # retention deletes the ones that have stayed retired. Without
            # this second step the indicators table only ever grows.
            removed = sum(r["rows"] for r in retention.apply(store))
            if removed:
                out.append({"category": "feed", "severity": "low",
                            "host": "wsl",
                            "title": f"{removed} aged rows removed",
                            "detail": "database retention policy; run "
                                      "`jarvis retention` to see what it keeps",
                            "where": ""})
            return out
        finally:
            store.close()

    if name in ("hunt", "gaps", "intel"):
        store = Store(_run_job.db_path)
        try:
            if name == "hunt":
                return hunt.sort_findings(hunt.hunt(store, hosts=hosts))
            if name == "gaps":
                return hunt.gaps(store)[0]
            try:
                options = intel.daemon_options(store)
                stats = intel.refresh(store, **options)
            except intel.BudgetExceeded as exc:
                # Not a failure: the brake worked. Say so quietly and keep the
                # previous findings on the dashboard.
                return [{"category": "intel", "severity": "low",
                         "host": "wsl", "title": "intel refresh paused",
                         "detail": str(exc), "where": ""}]
            out = []
            if stats["errors"]:
                out.append({
                    "category": "intel", "severity": "medium", "host": "wsl",
                    "title": "intel refresh had errors",
                    "detail": "; ".join(stats["errors"])[:400], "where": ""})
            out.append({
                "category": "intel", "severity": "low", "host": "wsl",
                "title": f"refreshed {', '.join(stats['topics'])}",
                "detail": f"{stats['docs']} documents, {stats['kept']} indicators "
                          f"kept of {stats['seen']} candidates, "
                          f"${stats['cost']:.3f}",
                "where": ""})
            return out
        finally:
            store.close()
    raise ValueError(name)


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
        _run_job.db_path = db_path

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
                        findings = _run_job(name, self.hosts)
                    err = observation.error
                    from jarvis.response import remediation
                    findings, err = remediation.process(
                        store, alert.load_conf(), name, findings, err,
                        lambda: _run_job(name, self.hosts))
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
                    alert.dispatch(store, name, findings, error=err)
                except Exception:
                    pass
        finally:
            store.close()


def _watchdog_loop(scheduler):
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


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def _intel_state(store):
    """Knowledge-base health, so the page shows what the hunt is hunting with.

    A hunt that finds nothing is only reassuring if the thing doing the hunting
    is current. Showing the indicator count, the age of each feed and the last
    refresh makes "no findings" mean something.
    """
    try:
        kinds = {r["kind"]: r["n"] for r in store.db.execute(
            "SELECT kind, COUNT(*) n FROM indicators WHERE status='active' "
            "GROUP BY kind ORDER BY n DESC")}
        feeds_rows = [dict(r) for r in store.db.execute(
            "SELECT name,last_run,rows,kept,error FROM feed_runs ORDER BY name")]
        hits = [dict(r) for r in store.db.execute(
            "SELECT ts,kind,value,host,severity,evidence FROM hunt_hits "
            "ORDER BY ts DESC LIMIT 20")]
        docs = store.db.execute(
            "SELECT COUNT(*) FROM intel_docs").fetchone()[0]
        today = time.strftime("%Y%m%d")
        return {
            "total": sum(kinds.values()),
            "kinds": kinds,
            "docs": docs,
            "feeds": feeds_rows,
            "hits": hits,
            "last_refresh": int(store.get_meta("intel_last_refresh", 0) or 0),
            "last_hunt": int(store.get_meta("hunt_last_run", 0) or 0),
            "spend_today": float(store.get_meta(f"intel_spend_{today}", 0) or 0),
            "spend_total": float(store.get_meta("intel_spend_total", 0) or 0),
        }
    except Exception:
        return {"total": 0, "kinds": {}, "docs": 0, "feeds": [], "hits": [],
                "last_refresh": 0, "last_hunt": 0,
                "spend_today": 0.0, "spend_total": 0.0}


def build_state(db_path, scheduler):
    store = Store(db_path)
    try:
        snaps = store.get_snapshots()
        jobs, all_findings, all_checks = [], [], []
        for name, (interval, label) in JOBS.items():
            s = snaps.get(name)
            counts, ok_count = {}, 0
            if s:
                for f in s["findings"]:
                    sev = f.get("severity")
                    if sev == "ok":
                        # "Checked and found clean" is a result, not an absence
                        # of one. Without it the page cannot distinguish a check
                        # that passed from a check that never ran.
                        ok_count += 1
                        all_checks.append({**f, "job": name})
                    elif sev:
                        counts[sev] = counts.get(sev, 0) + 1
                        all_findings.append({**f, "job": name})
            jobs.append({
                "name": name, "label": label, "interval": interval,
                "ts": s["ts"] if s else 0,
                "duration": round(s["duration"], 1) if s else 0,
                "error": (s["error"] or "")[:400] if s else "",
                "counts": counts, "ok": ok_count,
                "stale": bool(s and s["ts"]
                              and (time.time() - s["ts"]) > max(interval * 2,
                                                                interval + 300)),
                "running": scheduler.current == name,
                "next": int(scheduler.next_run.get(name, 0) - time.time()),
            })

        all_findings.sort(key=lambda f: (SEV_ORDER.get(f.get("severity"), 9),
                                         f.get("job", "")))
        worst = all_findings[0]["severity"] if all_findings else "ok"
        totals = {}
        for f in all_findings:
            totals[f["severity"]] = totals.get(f["severity"], 0) + 1

        all_checks.sort(key=lambda f: (f.get("job", ""), f.get("title", "")))

        by_host = {}
        for f in all_findings:
            h = f.get("host") or "?"
            by_host.setdefault(h, {})
            by_host[h][f["severity"]] = by_host[h].get(f["severity"], 0) + 1

        by_category = {}
        for f in all_findings:
            c = f.get("category") or "other"
            by_category[c] = by_category.get(c, 0) + 1

        def _count(sql):
            try:
                return store.db.execute(sql).fetchone()[0]
            except Exception:
                return 0

        return {
            "now": now(),
            "worst": worst,
            "totals": totals,
            "by_host": by_host,
            "by_category": by_category,
            "jobs": jobs,
            "findings": all_findings[:1000],
            "findings_total": len(all_findings),
            "checks": all_checks,
            "history": store.get_history(24),
            "internet": internetwatch.latest(store),
            "peers": [dict(r) for r in store.list_peers(scope="public", limit=60)],
            "events": [dict(r) for r in store.list_events(limit=40)],
            "stats": {
                "procs": _count("SELECT COUNT(*) FROM procs"),
                "approved": _count("SELECT COUNT(*) FROM procs WHERE approved=1"),
                "peers": _count("SELECT COUNT(*) FROM peers"),
                "peers_public": _count(
                    "SELECT COUNT(*) FROM peers WHERE scope='public'"),
                "events": _count("SELECT COUNT(*) FROM events"),
            },
            "intel": _intel_state(store),
            "baseline_at": store.get_meta("baseline_at"),
            "db": db_path,
        }
    finally:
        store.close()


# Binding to 127.0.0.1 is NOT sufficient on its own. A malicious page you visit
# can point a hostname it controls at 127.0.0.1 (DNS rebinding); the browser then
# treats that hostname as same-origin with this server and can read every
# response — which for this tool means handing over a complete map of the
# machine's firewall gaps, running processes and external peers. The defence is
# to check the Host header and serve only names we expect.
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}


class Handler(BaseHTTPRequestHandler):
    server_version = "JARVIS"
    db_path = DEFAULT_DB
    scheduler = None

    def log_message(self, *a):
        pass  # the dashboard polls constantly; access logs would be noise

    def _host_ok(self):
        host = (self.headers.get("Host") or "").strip()
        # Strip the port; ports are not part of the rebinding decision.
        if host.startswith("["):                      # bracketed IPv6 literal
            name = host[: host.index("]") + 1] if "]" in host else host
        else:
            name = host.rsplit(":", 1)[0] if ":" in host else host
        return name.lower() in ALLOWED_HOSTS

    def _same_origin(self):
        """Reject cross-site calls. Browsers that send Sec-Fetch-Site make this
        exact; for anything older we fall back to checking Origin."""
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None:
            return site in ("same-origin", "none")
        origin = self.headers.get("Origin")
        if not origin:
            return True  # curl and friends send no Origin at all
        return any(origin == f"http://{h}:{self.server.server_address[1]}"
                   for h in ("localhost", "127.0.0.1"))

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # The page is entirely self-contained; forbid anything external.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, json.dumps({"error": "bad host"}))
        if not self._same_origin():
            return self._send(403, json.dumps({"error": "cross-site request"}))
        url = urlparse(self.path)
        if url.path == "/api/run":
            job = (parse_qs(url.query).get("job") or [""])[0]
            ok = self.scheduler.force(job)
            return self._send(200 if ok else 404, json.dumps({"queued": ok}))
        return self._send(404, json.dumps({"error": "not found"}))

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, "forbidden: unexpected Host header\n"
                                   "reach this dashboard as http://localhost:PORT",
                              "text/plain")
        url = urlparse(self.path)
        if url.path in ("/", "/index.html"):
            try:
                with open(PAGE, "r", encoding="utf-8", errors="replace") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                return self._send(500, "dashboard.html missing", "text/plain")

        if url.path == "/api/state":
            return self._send(200, json.dumps(
                build_state(self.db_path, self.scheduler), default=str))

        if url.path in ("/api/health", "/api/live"):
            from jarvis.service.protection import health
            state = health(self.db_path, self.scheduler)
            ok = state['live'] if url.path == '/api/live' else state['healthy']
            return self._send(200 if ok else 503, json.dumps(state))

        # /api/run is a state-changing action, so it is POST-only: a cross-site
        # page cannot force one without a preflight it will not survive.
        if url.path == "/api/run":
            return self._send(405, json.dumps({"error": "use POST"}))

        return self._send(404, json.dumps({"error": "not found"}))


def serve(db_path=DEFAULT_DB, port=8787, hosts=("wsl", "win")):
    scheduler = Scheduler(db_path, hosts)
    scheduler.start()

    # Tell systemd we are up, then keep the watchdog fed for as long as the
    # scheduler is actually making progress. Both are no-ops when not run under
    # a systemd unit that asked for them.
    sdnotify.ready()
    sdnotify.status(f"scheduling {len(JOBS)} jobs")
    wd = threading.Thread(target=_watchdog_loop, args=(scheduler,),
                          name="jarvis-watchdog", daemon=True)
    wd.start()

    Handler.db_path = db_path
    Handler.scheduler = scheduler
    # Localhost only, deliberately and without an override.
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    # flush=True so journalctl shows these immediately under systemd, where
    # stdout is a pipe and would otherwise stay buffered indefinitely.
    print(f"JARVIS dashboard  \u2192  http://127.0.0.1:{port}", flush=True)
    print(f"  watching {'+'.join(hosts)};  database {db_path}", flush=True)
    print("  jobs: " + ", ".join(f"{n} every {v[0]}s" for n, v in JOBS.items()),
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
