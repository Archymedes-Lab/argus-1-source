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

import html as html_mod
import json
import time

from jarvis.response import alert

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
    ("Data & privacy", ("secrets", "spy", "pixel", "sniffing")),
    ("Network", ("internet", "netwatch")),
    ("Developer toolchain", ("toolchain",)),
    ("Monitoring", ("coverage", "bridge", "watchdogs")),
)
UNSCORED = ("gaps", "intel", "feeds", "ledger", "report", "resources", "controls")
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


def _freshness(snap, interval, now):
    if not snap or not snap.get("ts"):
        return "missing"
    if snap.get("error"):
        return "failing"
    if now - int(snap["ts"]) > max(interval * 2, interval + 300):
        return "stale"
    return "current"


def _scored(findings):
    """Findings that describe risk. Per-process and per-peer churn (and meta
    categories) are the same ones alerting never pages on: they change by the
    minute and would make the bar jitter rather than track progress."""
    return [f for f in findings or () if isinstance(f, dict)
            and f.get("category") not in alert.NOPAGE_CATEGORIES]


def _job_penalty(findings):
    counts = {}
    for f in _scored(findings):
        sev = f.get("severity")
        counts[sev] = counts.get(sev, 0) + 1
    return (WEIGHT["critical"] * counts.get("critical", 0)
            + WEIGHT["high"] * counts.get("high", 0)
            + WEIGHT["medium"] * min(counts.get("medium", 0), MEDIUM_CAP)), counts


def _area_score(penalty):
    return round(100 * K / (K + penalty))


def compute(snapshots, jobs, now=None):
    """Score from stored snapshots. `jobs` is the schedule: name -> (interval, label)."""
    now = int(time.time() if now is None else now)
    areas, next_steps = [], []
    observed_jobs = scored_jobs = 0
    for area, members in AREAS:
        penalty, counts, blind = 0, {}, []
        present = [j for j in members if j in jobs]
        for job in present:
            snap = snapshots.get(job)
            state = _freshness(snap, jobs[job][0], now)
            scored_jobs += 1
            if state != "current":
                blind.append({"job": job, "state": state})
                continue
            observed_jobs += 1
            p, c = _job_penalty(snap.get("findings"))
            penalty += p
            for sev, n in c.items():
                if sev in WEIGHT and sev != "ok":
                    counts[sev] = counts.get(sev, 0) + n
            for f in _scored(snap.get("findings")):
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
        "at": now,
    }


def bar(score, width=20):
    """[##########----------] as text, for email bodies and terminals."""
    score = max(0, min(100, int(score)))
    filled = round(width * score / 100)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def record(store, jobs, now=None):
    """Compute, and append to the stored history (one point per call)."""
    result = compute(store.get_snapshots(), jobs, now)
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


def health_email(store, conf, now=None):
    """The short daily security-health email: the bar and what would raise it."""
    result = latest(store)
    if result is None:
        return "no security score recorded yet"
    delta = change_since(store, 86400, now)
    lines = ["JARVIS SECURITY HEALTH", ""] + summary_lines(result, delta) + [
        "", "Details and every finding: the local JARVIS dashboard."]
    body = html_block(result, lambda v: html_mod.escape(str(v or "")), delta)
    steps = "".join(
        f"<li>{html_mod.escape(s['severity'])}: {html_mod.escape(s['title'])} "
        f"<small>({html_mod.escape(s['job'])})</small></li>"
        for s in result["next_steps"][:5])
    page = ("<!doctype html><html><body style='margin:0;background:#f2f4f7;"
            "font-family:Segoe UI,Arial,sans-serif;color:#101828'>"
            "<div style='max-width:640px;margin:auto;background:#fff;padding:24px 28px'>"
            f"{body}"
            + (f"<h3 style='margin:18px 0 6px'>Biggest gains</h3><ol>{steps}</ol>" if steps else "")
            + "<p style='color:#57606a;font-size:12px'>Details and every finding are on "
              "the local JARVIS dashboard.</p></div></body></html>")
    trend = "" if not delta else f" ({'+' if delta > 0 else ''}{delta})"
    subject = f"[JARVIS] security health {result['score']}% — {result['grade']}{trend}"
    return alert.send_email(conf, subject, "\n".join(lines) + "\n", html=page)


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


def html_block(result, esc, delta=None):
    """The same content as summary_lines, as inline-styled HTML for email."""
    def colour(score):
        if score is None:
            return "#7d8590"
        return "#1a7f37" if score >= 75 else "#9a6700" if score >= 50 else "#cf222e"

    def meter(score, height):
        pct = 0 if score is None else max(0, min(100, int(score)))
        return (f"<div style='background:#e6e9ed;border-radius:6px;height:{height}px;"
                f"overflow:hidden'><div style='width:{pct}%;height:{height}px;"
                f"background:{colour(score)}'></div></div>")

    trend = "" if delta is None else (
        f" · {'+' if delta > 0 else ''}{delta} in 24h" if delta else " · no change in 24h")
    rows = []
    for a in result["areas"]:
        label = "unverified" if a["score"] is None else f"{a['score']}%"
        rows.append(
            f"<tr><td style='padding:3px 10px 3px 0;white-space:nowrap'>{esc(a['name'])}</td>"
            f"<td style='width:60%'>{meter(a['score'], 8)}</td>"
            f"<td style='padding-left:10px;white-space:nowrap'>{esc(label)}</td></tr>")
    return (
        f"<div style='margin:6px 0 4px;font-size:13px;letter-spacing:1px'>SECURITY HEALTH</div>"
        f"<div style='font-size:28px;font-weight:700;color:{colour(result['score'])}'>"
        f"{result['score']}% <span style='font-size:14px;font-weight:400;color:#57606a'>"
        f"{esc(result['grade'])} · coverage {result['coverage']}%{esc(trend)}</span></div>"
        f"{meter(result['score'], 14)}"
        f"<table style='width:100%;margin-top:10px;font-size:13px'>{''.join(rows)}</table>")
