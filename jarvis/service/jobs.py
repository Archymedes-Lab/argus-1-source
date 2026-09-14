"""Run one scheduled audit by name and return its findings in the common shape.

Most collectors already return findings; the ones that do not (the process scan,
feeds, intel) are adapted here, so the scheduler only ever sees one shape.
"""

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
from jarvis.response import ledger as ledger_mod
from jarvis.service import deadman, selfcheck
from jarvis.service import coverage as coverage_mod
from jarvis.service.schedule import JOBS


def run_job(name, hosts, db_path):
    """Run one audit and return its findings in the common shape."""
    if name == "scan":
        # The process scan is stateful (it maintains the baseline), so it needs
        # its own store handle inside the worker thread.
        store = Store(db_path)
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
        store = Store(db_path)
        try:
            return controlwatch.audit(store, hosts=hosts)
        finally:
            store.close()
    if name == "internet":
        store = Store(db_path)
        try:
            return internetwatch.audit(store, hosts=hosts)
        finally:
            store.close()
    if name == "resources":
        store = Store(db_path)
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
        store = Store(db_path)
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
            coverage_mod.audit(db_path=db_path, hosts=hosts))
    if name == "report":
        store = Store(db_path)
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
        store = Store(db_path)
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
        store = Store(db_path)
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
        store = Store(db_path)
        try:
            return sysmon_linux.audit(store=store, hosts=hosts, incremental=True)
        finally:
            store.close()
    if name == "sysmon":
        store = Store(db_path)
        try:
            # Incremental: each run reads only what happened since the
            # last one, instead of re-reading a day of log every ten minutes.
            return sysmon.audit(store=store, hosts=hosts, incremental=True)
        finally:
            store.close()
    if name in ("input", "input_hook"):
        store = Store(db_path)
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
        store = Store(db_path)
        try:
            netwatch.record(store)
            return netwatch.audit(store)
        finally:
            store.close()

    if name == "feeds":
        store = Store(db_path)
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
        store = Store(db_path)
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
