"""How safe is this machine right now, as one number and a bar to fill.

The findings list answers "what is wrong". This answers "how far is this system
from secure", so progress is visible: fixing a high finding moves the bar, and
so does getting a blind collector reporting again.

Three rules keep the number honest:

  * It is built from what the collectors last observed, grouped into
    protection areas by the job that observed it. Nothing is guessed.
  * Blindness is not safety. An area whose collectors are failing, stale or
    have never run is shown as unverified and does not count as healthy, and
    the overall score is pulled down in proportion to how much of the machine
    is currently unobserved.
  * Inventory is not risk. Low-severity findings (every scheduled task, every
    installed extension) do not lower the score, per-process and per-peer
    churn is left out exactly as alerting leaves it out, and medium findings
    from one collector stop counting past a small cap, so a noisy rule cannot
    bury everything else.
"""

import json
import time

from jarvis.response import acknowledge, alert

# Protection areas, in display order, and the jobs whose findings describe them.
# Jobs absent here do not describe the machine's safety and are not scored:
# gaps (jarvis's own detection coverage), intel/feeds (knowledge-base upkeep),
# ledger (a record of past alerts, already counted where they came from),
# report (email cadence), resources and controls (performance and devices).
AREAS = (
    ("Active threats", ("hunt", "sysmon", "sysmon_linux", "memscan", "hidden",
                        "deep_hidden", "evasion", "intrusion", "webshell",
                        "input", "input_hook", "scan")),
    ("OS hardening", ("posture", "firewall", "implant", "auditd")),
    ("Persistence & access", ("control", "asep", "boot", "backdoor",
                              "identity", "bruteforce")),
    ("Data & privacy", ("secrets", "spy", "pixel", "sniffing", "geo")),
    ("Network", ("internet", "netwatch")),
    ("Developer toolchain", ("toolchain",)),
    ("Monitoring", ("coverage", "bridge", "watchdogs", "native", "arena")),
)
UNSCORED = ("gaps", "intel", "feeds", "ledger", "report", "resources", "controls",
            "attackmap")
AREA_OF = {job: area for area, jobs in AREAS for job in jobs}

WEIGHT = {"critical": 20, "high": 8, "medium": 2, "low": 0, "ok": 0}
MEDIUM_CAP = 5     # mediums counted per job
K = 16             # penalty at which an area reads 50%: two highs, or 8 mediums

HISTORY_META = "security_score_history"
HISTORY_KEEP = 400

GRADES = ((90, "secure"), (75, "good"), (50, "needs work"), (0, "at risk"))


def grade(score):
    for floor, label in GRADES:
        if score >= floor:
            return label
    return GRADES[-1][1]


def freshness(snap, interval, now):
    if not snap or not snap.get("ts"):
        return "missing"
    if snap.get("error"):
        return "failing"
    if now - int(snap["ts"]) > max(interval * 2, interval + 300):
        return "stale"
    return "current"


def _scored(findings, job="", acks=None, now=None):
    """Findings that describe risk. Per-process and per-peer churn (and meta
    categories) are the same ones alerting never pages on: they change by the
    minute and would make the bar jitter rather than track progress. Findings
    you have acknowledged as expected are left out while the acknowledgement
    holds."""
    return [f for f in findings or () if isinstance(f, dict)
            and f.get("category") not in alert.NOPAGE_CATEGORIES
            and not (acks and acknowledge.is_acknowledged(acks, f, job, now))]


def _job_penalty(findings):
    counts = {}
    for f in findings:
        sev = f.get("severity")
        counts[sev] = counts.get(sev, 0) + 1
    return (WEIGHT["critical"] * counts.get("critical", 0)
            + WEIGHT["high"] * counts.get("high", 0)
            + WEIGHT["medium"] * min(counts.get("medium", 0), MEDIUM_CAP)), counts


def _area_score(penalty):
    return round(100 * K / (K + penalty))


def compute(snapshots, jobs, now=None, acks=None):
    """Score from stored snapshots. `jobs` is the schedule: name -> (interval, label).
    `acks` is acknowledge.load(store): findings you confirmed as expected."""
    now = int(time.time() if now is None else now)
    areas, next_steps = [], []
    observed_jobs = scored_jobs = acknowledged = 0
    for area, members in AREAS:
        penalty, counts, blind = 0, {}, []
        present = [j for j in members if j in jobs]
        for job in present:
            snap = snapshots.get(job)
            state = freshness(snap, jobs[job][0], now)
            scored_jobs += 1
            if state != "current":
                blind.append({"job": job, "state": state})
                continue
            observed_jobs += 1
            kept = _scored(snap.get("findings"), job, acks, now)
            acknowledged += len(_scored(snap.get("findings"))) - len(kept)
            p, c = _job_penalty(kept)
            penalty += p
            for sev, n in c.items():
                if sev in WEIGHT and sev != "ok":
                    counts[sev] = counts.get(sev, 0) + n
            for f in kept:
                w = WEIGHT.get(f.get("severity"), 0)
                if w:
                    next_steps.append({"area": area, "job": job, "weight": w,
                                       "severity": f.get("severity"),
                                       "title": f.get("title", ""),
                                       "where": f.get("where", "")})
        observed = len(present) - len(blind)
        areas.append({
            "name": area,
            "score": _area_score(penalty) if observed else None,
            "open": counts,
            "jobs": len(present),
            "observed": observed,
            "blind": blind,
        })
    scored = [a["score"] for a in areas if a["score"] is not None]
    coverage = observed_jobs / scored_jobs if scored_jobs else 0.0
    base = sum(scored) / len(scored) if scored else 0.0
    # A machine that is half unobserved cannot score better than half-way
    # between its observed score and zero.
    score = round(base * (0.5 + 0.5 * coverage)) if scored else 0
    next_steps.sort(key=lambda s: (-s["weight"], s["area"], s["title"]))
    return {
        "score": score,
        "grade": grade(score),
        "coverage": round(coverage * 100),
        "areas": areas,
        "next_steps": next_steps[:8],
        "acknowledged": acknowledged,
        "at": now,
    }


def bar(score, width=20):
    """[##########----------] as text, for email bodies and terminals."""
    score = max(0, min(100, int(score)))
    filled = round(width * score / 100)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def record(store, jobs, now=None):
    """Compute, and append to the stored history (one point per call)."""
    result = compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    history = history_of(store)
    history.append([result["at"], result["score"]])
    store.set_meta(HISTORY_META, json.dumps(history[-HISTORY_KEEP:]))
    store.set_meta("security_score_latest", json.dumps(result))
    return result


def history_of(store):
    try:
        value = json.loads(store.get_meta(HISTORY_META, "[]") or "[]")
        return [p for p in value if isinstance(p, list) and len(p) == 2]
    except (TypeError, ValueError):
        return []


def change_within(store, seconds, now=None):
    """Score change across the recorded points of the last `seconds`, oldest to
    newest. This is what the dashboard's sparkline shows, so speech and screen
    agree; None with fewer than two points."""
    now = int(time.time() if now is None else now)
    recent = [p for p in history_of(store) if p[0] >= now - seconds]
    return recent[-1][1] - recent[0][1] if len(recent) > 1 else None


def latest(store):
    """The last recorded score, or None if the report job has not run yet."""
    try:
        value = json.loads(store.get_meta("security_score_latest", "") or "null")
        return value if isinstance(value, dict) and "score" in value else None
    except (TypeError, ValueError):
        return None


def change_since(store, seconds, now=None):
    """Score change against the recorded point closest to `seconds` ago."""
    now = int(time.time() if now is None else now)
    history = history_of(store)
    if len(history) < 2:
        return None
    target = now - seconds
    past = min(history[:-1], key=lambda p: abs(p[0] - target))
    if abs(past[0] - target) > 3 * 3600:
        return None     # no point near enough to that moment to compare with
    return history[-1][1] - past[1]



def summary_lines(result, delta=None):
    """Plain-text block for emails: the overall bar, then one bar per area."""
    trend = "" if delta is None else (
        f"  ({'+' if delta > 0 else ''}{delta} in 24h)" if delta else "  (no change in 24h)")
    lines = [f"SECURITY HEALTH {bar(result['score'])} {result['score']}% — "
             f"{result['grade']}{trend}",
             f"  monitoring coverage {result['coverage']}%"]
    for a in result["areas"]:
        if a["score"] is None:
            lines.append(f"  {a['name']:<22} unverified — no current data")
        else:
            opened = ", ".join(f"{n} {s}" for s, n in sorted(
                a["open"].items(), key=lambda kv: WEIGHT.get(kv[0], 0), reverse=True)
                if WEIGHT.get(s, 0))
            note = f"  {opened}" if opened else ""
            blind = f"  ({len(a['blind'])} collector(s) not reporting)" if a["blind"] else ""
            lines.append(f"  {a['name']:<22} {bar(a['score'], 10)} {a['score']:>3}%{note}{blind}")
    if result["next_steps"]:
        lines.append("  biggest gains:")
        for s in result["next_steps"][:3]:
            lines.append(f"    fix {s['severity']}: {s['title']} ({s['job']})")
    return lines
