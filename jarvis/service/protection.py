"""Cheap persisted coverage assessment; never launches Windows from HTTP."""
import sqlite3
import time

from jarvis.core.assurance import report as assurance_report
from jarvis.core.telemetry import META as TELEMETRY_META
from jarvis.core.telemetry import parse as telemetry_parse


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
    try:
        row = db.execute('SELECT v FROM meta WHERE k=?',
                         (TELEMETRY_META,)).fetchone()
        telemetry_chain = telemetry_parse(row[0] if row else None, stamp)
    except (sqlite3.Error, ValueError, TypeError, IndexError):
        pass
    protected = bool(sources) and all(
        sources.get(name, {}).get('status') == 'complete' for name in required)
    reliability_state = None
    try:
        status_fn = getattr(scheduler, 'reliability_status', None)
        if callable(status_fn):
            reliability_state = status_fn()['summary']
    except Exception:
        reliability_state = None
    return {'assurance': assurance_report(sources), 'service': 'JARVIS', 'time': stamp, 'healthy': alive and protected,
            'live': alive, 'ready': alive and protected, 'protection_healthy': protected,
            'progress_age': age, 'fast_lane_age': fast_age,
            'current_job': scheduler.current,
            'current_fast_job': getattr(scheduler, 'fast_current', None), 'sources': sources,
            'telemetry_chain': telemetry_chain,
            'reliability': reliability_state}
