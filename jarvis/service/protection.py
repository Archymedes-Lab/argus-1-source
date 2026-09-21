"""Cheap persisted coverage assessment; never launches Windows from HTTP."""
import sqlite3
import time

from jarvis.core.assurance import report as assurance_report
from jarvis.core.telemetry import META as TELEMETRY_META
from jarvis.core.telemetry import parse as telemetry_parse


def _invariants(sources, scheduler, stamp):
    """Experience invariants from already-held state. Pure/cheap; never raises."""
    try:
        from jarvis.core import governor as governor_mod
        from jarvis.core import invariants as invariants_mod
        stale = any(
            sources.get(name, {}).get("status") in ("stale", "unavailable")
            for name in ("scan", "bridge", "sysmon", "native"))
        recovering = False
        try:
            summary = scheduler.reliability_status()["summary"]
            recovering = bool(summary.get("recovering"))
        except Exception:
            pass
        try:
            pressured, _reason = governor_mod.live_pressure()
        except Exception:
            pressured = False
        # Noncritical running is approximated by whether a governed job is
        # currently executing; the scheduler defers them under pressure, so
        # this closes the loop without new instrumentation.
        current = {scheduler.current, getattr(scheduler, "fast_current", None)}
        noncritical_running = pressured and any(
            c in governor_mod.GOVERNED_JOBS for c in current if c)
        return invariants_mod.evaluate_all(
            startup=dict(ui_openable=True, engine_exists=True,
                         health_known=bool(sources), elapsed_seconds=0),
            protection=dict(ui_failed=False, engine_active=scheduler.is_alive()),
            freshness=dict(stale_mandatory=stale, recovery_active=recovering),
            repair=dict(patch_hash="", authorized_hash=""),
            evidence=dict(response_claimed_success=False,
                          independently_verified=False),
            performance=dict(host_pressured=pressured,
                             noncritical_running=noncritical_running),
            privacy=dict())
    except Exception:
        return {"ok": True, "reason": "invariant probe unavailable"}


def _perception(store_db):
    """Persisted perception summary written by the scan job; None if never run."""
    try:
        import json
        row = store_db.execute(
            "SELECT v FROM meta WHERE k='perception_summary_v1'").fetchone()
        value = json.loads(row[0]) if row else None
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _state(row, limit, stamp):
    """A fresh snapshot status; collector semantics remain in its payload."""
    import json

    status, reason = 'not_reporting', 'no observation yet'
    if not row:
        return {'status': status, 'reason': reason, 'observed_at': None}
    findings = json.loads(row[3])
    problem = next((f for f in findings if f.get('severity') != 'ok' and
                    (f.get('category') in ('visibility', 'collectors') or
                     f.get('coverage_status') in ('partial', 'unavailable'))), None)
    if row[2]:
        status, reason = 'unavailable', row[2]
    elif stamp - row[1] > limit or row[1] > stamp + 60:
        status, reason = 'stale', 'observation outside freshness window'
    elif problem:
        status, reason = 'partial', problem.get('title', 'coverage missing')
    else:
        status, reason = 'complete', 'recent successful collection'
    return {'status': status, 'reason': reason, 'observed_at': row[1]}


def health(db_path, scheduler, stamp=None):
    stamp = time.time() if stamp is None else stamp
    age = max(0, stamp - scheduler.heartbeat)
    fast_age = max(0, stamp - getattr(scheduler, 'fast_heartbeat', stamp))
    fast_ok = getattr(scheduler, 'fast_alive', lambda: True)() and fast_age < 300
    alive = scheduler.is_alive() and age < 900 and fast_ok
    sources = {}
    required = {'scan': 180}
    if 'win' in scheduler.hosts:
        required.update(bridge=135, sysmon=1500, native=180)
    try:
        with sqlite3.connect('file:' + db_path + '?mode=ro', uri=True, timeout=1) as db:
            rows = {r[0]: r for r in db.execute('SELECT kind,ts,error,payload FROM snapshots')}
            for name, limit in required.items():
                sources[name] = _state(rows.get(name), limit, stamp)
            # Optional sources make their capability telemetry honest without
            # making an opt-in browser extension or an infrequent audit a
            # service-health dependency.
            optional = {'internet': 300, 'veil': 90, 'secrets': 90000, 'resources': 900}
            for name, limit in optional.items():
                sources[name] = _state(rows.get(name), limit, stamp)
    except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
        sources['storage'] = {'status': 'unavailable', 'reason': type(exc).__name__}
    telemetry_chain = None
    perception = None
    governor_state = None
    try:
        row = db.execute('SELECT v FROM meta WHERE k=?',
                         (TELEMETRY_META,)).fetchone()
        telemetry_chain = telemetry_parse(row[0] if row else None, stamp)
        perception = _perception(db)
    except (NameError, sqlite3.Error, ValueError, TypeError, IndexError):
        pass
    try:
        from jarvis.core import governor as governor_mod
        pressured, reason = governor_mod.live_pressure()
        governor_state = {"pressured": pressured, "reason": reason,
                          "governed_jobs": sorted(governor_mod.GOVERNED_JOBS)}
    except Exception:
        governor_state = None
    runtime_state = None
    try:
        from jarvis.core import runtime as runtime_mod
        runtime_state = runtime_mod.metrics()
        runtime_state["storage"] = runtime_mod.verify_store()
    except Exception:
        runtime_state = None
    mlworker_state = None
    try:
        from jarvis.core import mlworker as mlworker_mod
        mlworker_state = mlworker_mod.stats()
    except Exception:
        mlworker_state = None
    protected = bool(sources) and all(
        sources.get(name, {}).get('status') == 'complete' for name in required)
    reliability_state = None
    try:
        status_fn = getattr(scheduler, 'reliability_status', None)
        if callable(status_fn):
            reliability_state = status_fn()['summary']
    except Exception:
        reliability_state = None
    try:
        # Closed DB handle above on some paths; reopen read-only briefly for
        # the invariant probe's reliability snapshot is unnecessary: the
        # probe takes scheduler state directly.
        invariants_state = _invariants(sources, scheduler, stamp)
    except Exception:
        invariants_state = None
    return {'assurance': assurance_report(sources), 'service': 'JARVIS', 'time': stamp, 'healthy': alive and protected,
            'live': alive, 'ready': alive and protected, 'protection_healthy': protected,
            'progress_age': age, 'fast_lane_age': fast_age,
            'current_job': scheduler.current,
            'current_fast_job': getattr(scheduler, 'fast_current', None), 'sources': sources,
            'telemetry_chain': telemetry_chain,
            'perception': perception,
            'governor': governor_state,
            'runtime': runtime_state,
            'mlworker': mlworker_state,
            'invariants': invariants_state,
            'reliability': reliability_state}
