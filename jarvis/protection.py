"""Cheap persisted coverage assessment; never launches Windows from HTTP."""
import sqlite3
import time


def health(db_path, scheduler, stamp=None):
    stamp = time.time() if stamp is None else stamp
    age = max(0, stamp - scheduler.heartbeat)
    alive = scheduler.is_alive() and age < 900
    sources = {}
    required = {'scan': 180}
    if 'win' in scheduler.hosts:
        required.update(bridge=135, sysmon=1500)
    try:
        with sqlite3.connect('file:' + db_path + '?mode=ro', uri=True, timeout=1) as db:
            import json
            rows = {r[0]: r for r in db.execute('SELECT kind,ts,error,payload FROM snapshots')}
            for name, limit in required.items():
                row = rows.get(name)
                status, reason = 'unavailable', 'no observation yet'
                if row:
                    findings = json.loads(row[3])
                    problem = next((f for f in findings if f.get('severity') != 'ok' and
                                    (f.get('category') in ('visibility', 'collectors') or
                                     f.get('coverage_status') in ('partial', 'unavailable'))), None)
                    if row[2]:
                        status, reason = 'unavailable', row[2]
                    elif stamp - row[1] > limit or row[1] > stamp + 60:
                        status, reason = 'stale', 'observation outside freshness window'
                    elif problem:
                        status, reason = 'unavailable', problem.get('title', 'coverage missing')
                    else:
                        status, reason = 'complete', 'recent successful collection'
                sources[name] = {'status': status, 'reason': reason,
                                 'observed_at': row[1] if row else None}
    except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
        sources['storage'] = {'status': 'unavailable', 'reason': type(exc).__name__}
    protected = bool(sources) and all(s['status'] == 'complete' for s in sources.values())
    return {'service': 'JARVIS', 'time': stamp, 'healthy': alive and protected,
            'live': alive, 'ready': alive and protected, 'protection_healthy': protected,
            'progress_age': age, 'current_job': scheduler.current, 'sources': sources}
