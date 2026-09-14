"""Run one scheduled audit by name and return its findings in the common shape.

Most collectors already return findings; the ones that do not (the process scan,
feeds, intel) are adapted here, so the scheduler only ever sees one shape.

Each job is a small function registered in RUNNERS under its schedule name.
Jobs that touch the database open their own store: they run inside the
scheduler's worker thread, and a sqlite handle must not cross threads.
"""

from contextlib import contextmanager

from jarvis.collectors.host import (controlwatch, inputwatch, pixel, posture,
                                    spyware, toolchain)
from jarvis.collectors.host import intrusion as intrusion_mod
from jarvis.collectors.identity import bruteforce, impersonation, secrets
from jarvis.collectors.network import (firewall, internetwatch, netwatch,
                                       sniffing, webshell)
from jarvis.collectors.persistence import backdoor, control, implant, startup
from jarvis.collectors.persistence import asep as asep_mod
from jarvis.collectors.process import hidden, memscan, monitor, resourcewatch
from jarvis.collectors.process import evasion as evasion_mod
from jarvis.collectors.telemetry import auditd, sysmon, sysmon_linux
from jarvis.core import retention
from jarvis.core.store import Store
from jarvis.intel import feeds, hunt
from jarvis.intel import research as intel
from jarvis.reporting.cadence import run as report_due
from jarvis.response import ledger as ledger_mod
from jarvis.service import connectivity, deadman, selfcheck
from jarvis.service import coverage as coverage_mod
from jarvis.service.schedule import JOBS


@contextmanager
def _store(db_path):
    store = Store(db_path)
    try:
        yield store
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Jobs that adapt a collector's own result shape
# ---------------------------------------------------------------------------

def _scan(hosts, db_path):
    # The process scan is stateful (it maintains the baseline), so it needs
    # its own store handle inside the worker thread.
    with _store(db_path) as store:
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


def _watchdogs(hosts, db_path):
    # Both halves of the supervision loop: the systemd timer that restarts
    # this daemon, and the Windows task that reports it missing when WSL
    # itself is down.
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


def _report(hosts, db_path):
    with _store(db_path) as store:
        return report_due(store, JOBS)


def _ledger(hosts, db_path):
    with _store(db_path) as store:
        # A row is only "stale" relative to whether its own collector has
        # run since; the snapshot table is where that is recorded.
        snaps = store.get_snapshots()
        job_ts = {k: int(v.get("ts") or 0) for k, v in snaps.items()
                  if not v.get("error")}
        return ledger_mod.audit(store, job_ts=job_ts)


def _input(deep):
    def run(hosts, db_path):
        with _store(db_path) as store:
            # The Windows-side hook does not survive a reboot or a WSL restart
            # and nothing outside this loop respawns it, so supervise() keeps
            # it up — cheaply on the healthy path, with backoff and flap
            # detection when it is not. "input_hook" is the short-interval
            # watchdog; "input" additionally runs the full injected-event audit.
            pids, findings = inputwatch.supervise(store, deep=deep)
            if deep:
                findings += inputwatch.audit(store, pids=pids, supervised=True)
            return findings
    return run


def _netwatch(hosts, db_path):
    with _store(db_path) as store:
        netwatch.record(store)
        return netwatch.audit(store)


def _feeds(hosts, db_path):
    with _store(db_path) as store:
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


def _intel(hosts, db_path):
    with _store(db_path) as store:
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


def _hunt(hosts, db_path):
    with _store(db_path) as store:
        return hunt.sort_findings(hunt.hunt(store, hosts=hosts))


def _gaps(hosts, db_path):
    with _store(db_path) as store:
        return hunt.gaps(store)[0]


# ---------------------------------------------------------------------------
# Jobs that call a collector directly
# ---------------------------------------------------------------------------

def _with_store(audit, **kwargs):
    """A job whose collector takes (store, hosts=...)."""
    def run(hosts, db_path):
        with _store(db_path) as store:
            return audit(store, hosts=hosts, **kwargs)
    return run


def _hosts_only(audit):
    """A job whose collector takes only hosts=..."""
    return lambda hosts, db_path: audit(hosts=hosts)


def _sorted(module):
    """A job whose collector takes no arguments and ships its own ordering."""
    return lambda hosts, db_path: module.sort_findings(module.audit())


RUNNERS = {
    "scan": _scan,
    "bridge": lambda hosts, db_path: coverage_mod.bridge_status(),
    "input_hook": _input(deep=False),
    "watchdogs": _watchdogs,
    "resources": _with_store(resourcewatch.audit),
    "internet": _with_store(internetwatch.audit),
    "controls": _with_store(controlwatch.audit),
    "deep_hidden": lambda hosts, db_path: hidden.audit(hosts=hosts, deep=True)[0],
    "hidden": lambda hosts, db_path: hidden.audit(hosts=hosts)[0],
    "firewall": _hosts_only(firewall.audit),
    "control": _hosts_only(control.audit),
    "asep": _sorted(asep_mod),
    "spy": _sorted(spyware),
    "pixel": _hosts_only(pixel.audit),
    "identity": _with_store(impersonation.audit),
    "intrusion": _sorted(intrusion_mod),
    "evasion": _sorted(evasion_mod),
    "coverage": lambda hosts, db_path: coverage_mod.sort_findings(
        coverage_mod.audit(db_path=db_path, hosts=hosts)),
    "boot": _sorted(startup),
    "hunt": _hunt,
    "gaps": _gaps,
    "intel": _intel,
    "report": _report,
    "feeds": _feeds,
    "implant": _hosts_only(implant.audit),
    "netwatch": _netwatch,
    "posture": _hosts_only(posture.audit),
    "backdoor": _hosts_only(backdoor.audit),
    "toolchain": _with_store(toolchain.audit),
    "ledger": _ledger,
    "input": _input(deep=True),
    "memscan": _hosts_only(memscan.audit),
    "secrets": lambda hosts, db_path: secrets.audit(),
    "bruteforce": _hosts_only(bruteforce.audit),
    "sniffing": _hosts_only(sniffing.audit),
    "webshell": _hosts_only(webshell.audit),
    "auditd": _hosts_only(auditd.audit),
    # Incremental: each run reads only what happened since the last one,
    # instead of re-reading a day of log every ten minutes.
    "sysmon_linux": _with_store(sysmon_linux.audit, incremental=True),
    "sysmon": _with_store(sysmon.audit, incremental=True),
}


def run_job(name, hosts, db_path):
    """Run one audit and return its findings in the common shape."""
    runner = RUNNERS.get(name)
    if runner is None:
        raise ValueError(name)
    return runner(hosts, db_path)
