"""The data behind the /coverage view: what JARVIS defends, and how it is running.

One read-only summary joining three things that already exist: the ATT&CK
coverage map (attackmap, measured by probes), the collectors with their real
freshness and open findings, and what the scheduler is running right now.

Nothing here is computed to look better than the sources. A technique's level
is attackmap's, a collector's state is the score's own freshness rule, and a
collector with no stored snapshot is "missing", never quiet.

Uptime is read from the collector receipts (defender_runs). A collector is up
while its newest complete receipt is no older than the score's own staleness
limit; partial and unavailable runs do not keep it up. Time before a collector's
first receipt is unknown and left out, never counted as up or down.
"""
import re
import time

from jarvis.core.store import Store
from jarvis.response.reporting import score
from jarvis.response.reporting.commands import JOB_COMMANDS
from jarvis.service import attackmap
from jarvis.service.schedule import JOBS

SEVERITIES = ("critical", "high", "medium", "low")
BUCKETS, BUCKET_S, WEEK_S, CACHE_S = 24, 3600, 7 * 86400, 30
_uptime_cache = {}
# attackmap's free-text source names that are not job or command names.
ALIASES = {"detect": ("scan",), "monitor": ("internet",), "peers": ("scan",),
           "startup": ("boot",), "sysmon_linux": ("sysmon_linux",)}


def _jobs_for(word):
    """Jobs behind one source word of a COVERAGE entry ('hidden', 'asep', ...)."""
    word = word.strip().lower().replace("-", "_")
    if word in JOBS:
        return (word,)
    if word in ALIASES:
        return ALIASES[word]
    return tuple(sorted(job for job, command in JOB_COMMANDS.items()
                        if command.split()[0].replace("-", "_") == word and job in JOBS))


def sources(tid, evidence):
    """Collectors that feed a technique: the probe's jobs, else the mapped ones."""
    if tid in attackmap.PROBES:
        return [j for j in attackmap.PROBES[tid][1] if j in JOBS]
    head = re.split(r"\s[—-]\s", evidence or "", maxsplit=1)[0]
    found = []
    for word in head.split("/"):
        for job in _jobs_for(word):
            if job not in found:
                found.append(job)
    return found


def _grace(interval):
    """How long a complete receipt keeps a collector up: score.freshness's limit."""
    return max(interval * 2, interval + 300)


def _overlap(segments, lo, hi):
    return sum(max(0.0, min(b, hi) - max(a, lo)) for a, b in segments)


def _fresh_segments(times, grace, now):
    """Spans a collector had fresh evidence: each receipt holds until the next one."""
    out = []
    for i, t in enumerate(times):
        end = times[i + 1] if i + 1 < len(times) else now
        out.append((t, min(t + grace, end, now)))
    return out


def _longest_gap(segments, lo, hi):
    gap, cursor = 0.0, lo
    for a, b in segments:
        if b <= lo or a >= hi:
            continue
        gap = max(gap, max(a, lo) - cursor)
        cursor = max(cursor, min(b, hi))
    return max(gap, hi - cursor)


def _collector_uptime(times, first, grace, now, runs):
    day = now - BUCKETS * BUCKET_S
    segs = _fresh_segments(times, grace, now)
    known24 = max(0.0, now - max(day, first))
    known7 = max(0.0, now - max(now - WEEK_S, first))
    if not known24:
        return None
    buckets = []
    for k in range(BUCKETS):
        lo = day + k * BUCKET_S
        hi = lo + BUCKET_S
        known = max(0.0, hi - max(lo, first))
        buckets.append(round(_overlap(segs, lo, hi) / known, 4) if known else None)
    fresh24 = _overlap(segs, day, now)
    return {"pct24": round(fresh24 / known24, 4),
            "pct7d": round(_overlap(segs, now - WEEK_S, now) / known7, 4) if known7 else None,
            "buckets": buckets, "observed_s": int(known24), "fresh_s": int(fresh24),
            "longest_gap_s": int(_longest_gap(segs, max(day, first), now)),
            "runs24": runs}


def _technique_uptime(jobs, segs, now):
    """Share of the last 24 h in which at least one feeding collector had fresh evidence."""
    have = [segs[j] for j in jobs if j in segs]
    if not have:
        return None
    day = now - BUCKETS * BUCKET_S
    known = now - max(day, min(first for _s, first in have))
    if known <= 0:
        return None
    spans = sorted((max(a, day), min(b, now)) for s, _f in have for a, b in s if b > day and a < now)
    fresh, edge = 0.0, day
    for a, b in spans:
        a = max(a, edge)
        if b > a:
            fresh += b - a
            edge = b
    return round(min(1.0, fresh / known), 4)


def uptime(store, now):
    """Per-collector and fleet uptime from the stored receipts."""
    per, fleet, _segs = _collect(store, now)
    return per, fleet


def _collect(store, now):
    """Receipts to uptime: per collector, fleet, and the fresh spans themselves."""
    start = now - WEEK_S - max(_grace(i) for i, _ in JOBS.values())
    firsts = dict(store.db.execute("SELECT job, MIN(observed_at) FROM defender_runs GROUP BY job"))
    times = {}
    for job, ts in store.db.execute(
            "SELECT job, observed_at FROM defender_runs WHERE coverage='complete' "
            "AND observed_at>=? ORDER BY job, observed_at", (start,)):
        times.setdefault(job, []).append(ts)
    runs = {}
    for job, coverage, n in store.db.execute(
            "SELECT job, coverage, COUNT(*) FROM defender_runs WHERE observed_at>=? GROUP BY job, coverage",
            (now - BUCKETS * BUCKET_S,)):
        runs.setdefault(job, dict.fromkeys(("complete", "partial", "unavailable"), 0))[coverage] = n
    per, segs = {}, {}
    for job, (interval, _label) in JOBS.items():
        if job in firsts:
            segs[job] = (_fresh_segments(times.get(job, []), _grace(interval), now), firsts[job])
            per[job] = _collector_uptime(times.get(job, []), firsts[job], _grace(interval), now,
                                         runs.get(job, dict.fromkeys(("complete", "partial", "unavailable"), 0)))
    tracked = [u for u in per.values() if u]
    fleet = None
    if tracked:
        fleet_buckets = []
        for k in range(BUCKETS):
            known = [u["buckets"][k] for u in tracked if u["buckets"][k] is not None]
            fleet_buckets.append(round(sum(known) / len(known), 4) if known else None)
        observed = sum(u["observed_s"] for u in tracked)
        fleet = {"pct24": round(sum(u["fresh_s"] for u in tracked) / observed, 4),
                 "buckets": fleet_buckets, "tracked": len(tracked), "of": len(JOBS),
                 "partial_history": sum(1 for u in tracked if u["observed_s"] < BUCKETS * BUCKET_S - 60)}
    return per, fleet, segs


def build(db_path, scheduler=None, now=None):
    now = time.time() if now is None else now
    store = Store(db_path)
    try:
        snaps = store.get_snapshots()
        attack = attackmap.latest(store)
        verified = score.last_verified(store)
        cached = _uptime_cache.get(db_path)
        if cached and abs(now - cached[0]) < CACHE_S:
            per_uptime, fleet, segs = cached[1]
        else:
            per_uptime, fleet, segs = _collect(store, now)
            _uptime_cache[db_path] = (now, (per_uptime, fleet, segs))
    finally:
        store.close()
    running = []
    if scheduler is not None:
        try:
            running = list(scheduler.wake_phase().get("current") or [])
        except Exception:
            running = []

    techniques, feeds = [], {}
    for row in (attack or {}).get("techniques", []):
        jobs = [] if row["level"] == "blind" else sources(row["tid"], row.get("evidence"))
        for job in jobs:
            feeds.setdefault(job, []).append(row["tid"])
        techniques.append({"tid": row["tid"], "name": row["name"], "tactics": row["tactics"],
                           "level": row["level"], "evidence": row.get("evidence") or "",
                           "sources": jobs, "uptime": _technique_uptime(jobs, segs, now)})

    collectors = []
    for job, (interval, label) in JOBS.items():
        snap = snaps.get(job)
        counts = dict.fromkeys(SEVERITIES, 0)
        for finding in (snap or {}).get("findings") or []:
            if isinstance(finding, dict) and finding.get("severity") in counts:
                counts[finding["severity"]] += 1
        ts = (snap or {}).get("ts")
        collectors.append({
            "job": job, "label": label, "interval": interval,
            "area": score.AREA_OF.get(job, "Unscored"),
            "state": score.freshness(snap, interval, now),
            "ts": int(ts) if ts else None,
            "findings": counts, "running": job in running, "uptime": per_uptime.get(job),
            "techniques": sorted(feeds.get(job, []))})
    return {
        "at": int(now),
        "map_at": (attack or {}).get("at"),
        "totals": (attack or {}).get("totals") or {},
        "tactics": (attack or {}).get("tactics") or {},
        "techniques": techniques,
        "collectors": collectors,
        "running": running,
        "uptime": fleet,
        "score": ({"score": verified.get("score"), "grade": verified.get("grade"),
                   "at": verified.get("at")} if verified else None),
    }
