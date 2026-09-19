"""Reconcile point-in-time process state with the native temporal history.

The event stream and snapshots fail differently. Sysmon can miss records when
its log wraps or its sensor is stopped; a snapshot can miss a process that
starts and exits between scans. Comparing them turns those blind spots into
evidence about JARVIS's own perception.

This module is deliberately conservative. It only judges Windows process
instances with an exact creation time, after the stream's last continuous
coverage boundary, and only when a fresh complete Sysmon cursor has already
advanced past that creation. Processes that predate coverage or are still in
the ingestion settling window are unknown, not discrepancies.
"""

from datetime import datetime, timezone

from jarvis.core.eventlog import DEFAULT_ROOT, EventLog, LogError
from jarvis.platform.native.normalize import SYSMON

FRESH_SECONDS = 180
SETTLE_SECONDS = 10
START_TOLERANCE_SECONDS = 2


def _stamp(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (ValueError, OverflowError):
        return None


def _same_start(left, right):
    a, b = _stamp(left), _stamp(right)
    return a is not None and b is not None and abs(a - b) <= START_TOLERANCE_SECONDS


def _cursor(log, observed_at):
    candidates = [c for c in log.cursors.values()
                  if c.get("channel") == SYSMON and c.get("status") == "complete"
                  and not c.get("gap") and c.get("host")]
    if not candidates:
        return None
    cursor = max(candidates, key=lambda c: float(c.get("at") or 0))
    created = _stamp(cursor.get("created_at"))
    continuous = _stamp(cursor.get("continuous_since"))
    if created is None or continuous is None:
        return None
    # A stale stream cannot contradict a current snapshot. The native health
    # collector owns the outage finding; avoiding a second one here also keeps
    # existing incidents unobserved rather than spuriously replaced.
    if observed_at - created > FRESH_SECONDS or created - observed_at > FRESH_SECONDS:
        return None
    return cursor, created, continuous


def processes(snapshot, observed_at, root=DEFAULT_ROOT):
    """Return visibility findings for snapshot/event-state contradictions."""
    observed_at = _stamp(observed_at)
    if observed_at is None:
        return []
    try:
        with EventLog(root) as log:
            stream = _cursor(log, observed_at)
            if stream is None:
                return []
            cursor, cursor_at, continuous_since = stream
            findings = []
            for proc in snapshot:
                if proc.get("host") != "win" or not proc.get("pid"):
                    continue
                started = _stamp(proc.get("started"))
                snapshot_at = _stamp(proc.get("observed_at")) or observed_at
                if started is None or started < continuous_since:
                    continue
                # The committed native cursor must be newer than the start by
                # enough for Event Log publication and ingestion to settle.
                if started > cursor_at - SETTLE_SECONDS:
                    continue
                rows = log.process_instances(cursor["host"], proc["pid"])
                instance = next((r for r in rows if _same_start(r.get("started"), proc["started"])), None)
                subject = (f"{cursor.get('device') or cursor['host']}:"
                           f"{cursor.get('boot') or 'unknown'}:{proc['pid']}:{proc['started']}")
                if instance is None:
                    findings.append({
                        "category": "visibility", "severity": "high", "host": "win",
                        "rule_id": "temporal-process-start-missing", "subject_id": subject,
                        "title": f"{proc.get('name') or 'process'} exists without a start event",
                        "detail": ("The current process snapshot contains this exact execution, but the "
                                   "continuous native Sysmon stream has no matching ProcessGuid start. "
                                   "This can indicate an event-log gap, excluded telemetry, sensor "
                                   "tampering, or a process hidden from the event path."),
                        "where": proc.get("exe") or f"pid {proc['pid']}",
                    })
                    continue
                ended = _stamp(instance.get("ended"))
                if ended is not None and ended <= snapshot_at - SETTLE_SECONDS:
                    findings.append({
                        "category": "visibility", "severity": "high", "host": "win",
                        "rule_id": "temporal-process-exit-conflict", "subject_id": subject,
                        "title": f"{proc.get('name') or 'process'} exists after its recorded exit",
                        "detail": ("The snapshot still contains this exact process instance after the "
                                   "temporal stream recorded its termination. The snapshot or event "
                                   "state is inconsistent and must not be treated as verified reality."),
                        "where": proc.get("exe") or f"pid {proc['pid']}",
                    })
            return findings
    except (LogError, OSError):
        return []
