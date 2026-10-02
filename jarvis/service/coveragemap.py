"""The data behind the /coverage view: what JARVIS defends, and how it is running.

One read-only summary joining three things that already exist: the ATT&CK
coverage map (attackmap, measured by probes), the collectors with their real
freshness and open findings, and what the scheduler is running right now.

Nothing here is computed to look better than the sources. A technique's level
is attackmap's, a collector's state is the score's own freshness rule, and a
collector with no stored snapshot is "missing", never quiet.
"""
import re
import time

from jarvis.core.store import Store
from jarvis.response.reporting import score
from jarvis.response.reporting.commands import JOB_COMMANDS
from jarvis.service import attackmap
from jarvis.service.schedule import JOBS

SEVERITIES = ("critical", "high", "medium", "low")
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


def build(db_path, scheduler=None, now=None):
    now = time.time() if now is None else now
    store = Store(db_path)
    try:
        snaps = store.get_snapshots()
        attack = attackmap.latest(store)
        verified = score.last_verified(store)
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
                           "sources": jobs})

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
            "findings": counts, "running": job in running,
            "techniques": sorted(feeds.get(job, []))})
    return {
        "at": int(now),
        "map_at": (attack or {}).get("at"),
        "totals": (attack or {}).get("totals") or {},
        "tactics": (attack or {}).get("tactics") or {},
        "techniques": techniques,
        "collectors": collectors,
        "running": running,
        "score": ({"score": verified.get("score"), "grade": verified.get("grade"),
                   "at": verified.get("at")} if verified else None),
    }
