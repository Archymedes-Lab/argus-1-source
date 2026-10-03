"""Metadata-only Windows Core Audio route and session snapshot.

The sensor samples every five minutes. It cannot exclude shorter transitions,
actual sound, or WASAPI loopback capture; those remain explicit blind spots.

Each pass also reads the scalar peak meter of the active render endpoints for a
short bounded burst, to flag beep-like transients: a rise from silence that
falls back to silence within 1.5 s, inside the window. Only amplitude is seen,
never tone, content or audibility, and the burst covers a small slice of each
interval, so an absent beep is never evidence that none played.
"""
import json
import time

from jarvis.core import collection
from jarvis.core.paths import load_win_script
from jarvis.platform.windows import ps_json

PS_AUDIO = load_win_script("audio_state.ps1")
_STATE_KEY = "audiowatch_latest_v1"
_MAX_ENDPOINTS = 64
_MAX_SESSIONS = 256
_MAX_EVENTS = 32
_BURST_MAX_MS = 15000
_INTERVAL_S = 300
_ROLES = {(flow, role) for flow in ("render", "capture")
          for role in ("console", "multimedia", "communications")}


def _finding(severity, title, detail, category="audio"):
    return {"host": "win", "severity": severity, "title": title,
            "detail": detail, "category": category,
            "where": "Windows Core Audio"}


def _valid(data):
    if not isinstance(data, dict) or any(
            not isinstance(data.get(key), list)
            for key in ("endpoints", "defaults", "sessions", "errors")):
        return False
    if (len(data["endpoints"]) > _MAX_ENDPOINTS
            or len(data["sessions"]) > _MAX_SESSIONS
            or len(data["defaults"]) != 6
            or len(data["errors"]) > 16):
        return False
    endpoints = data["endpoints"]
    defaults = data["defaults"]
    sessions = data["sessions"]
    if any(not isinstance(row, dict) or not isinstance(row.get("id"), str)
           or not 0 < len(row["id"]) <= 512
           or row.get("flow") not in ("render", "capture")
           or row.get("state") not in (1, 2, 4, 8)
           for row in endpoints):
        return False
    if len({row["id"] for row in endpoints}) != len(endpoints):
        return False
    if ({(row.get("flow"), row.get("role")) for row in defaults} != _ROLES
            or any(not isinstance(row.get("id"), (str, type(None)))
                   or isinstance(row.get("id"), str) and row["id"] not in
                   {endpoint["id"] for endpoint in endpoints}
                   for row in defaults)):
        return False
    ids = {row["id"] for row in endpoints}
    if not _valid_burst(data.get("burst"), ids):
        return False
    if any(not isinstance(row, dict) or row.get("endpoint") not in ids
           or row.get("flow") not in ("render", "capture")
           or row.get("state") not in (0, 1, 2)
           or not isinstance(row.get("pid"), int)
           or not 0 <= row["pid"] <= 0xffffffff
           or not isinstance(row.get("identityKnown"), bool)
           or not isinstance(row.get("singleProcess"), bool)
           or row.get("identityKnown") and not row.get("singleProcess")
           for row in sessions):
        return False
    return all(isinstance(error, str) and len(error) <= 160
               for error in data["errors"])


def _num(value, low, high):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and low <= value <= high)


def _valid_burst(burst, endpoint_ids):
    """The peak-meter burst is required: a helper without it is not a clean
    snapshot, so beep visibility cannot silently disappear."""
    if not isinstance(burst, dict):
        return False
    if not (_num(burst.get("durationMs"), 1, _BURST_MAX_MS)
            and _num(burst.get("elapsedMs"), 0, _BURST_MAX_MS * 2)
            and _num(burst.get("samples"), 0, 1_000_000)
            and _num(burst.get("endpointsSampled"), 0, 64)
            and _num(burst.get("sustained"), 0, 1_000_000)
            and isinstance(burst.get("truncated"), bool)
            and isinstance(burst.get("errors"), list)
            and len(burst["errors"]) <= 16
            and all(isinstance(e, str) and len(e) <= 160 for e in burst["errors"])
            and isinstance(burst.get("events"), list)
            and len(burst["events"]) <= _MAX_EVENTS):
        return False
    window = burst["durationMs"] * 2
    for row in burst["events"]:
        if (not isinstance(row, dict) or row.get("endpoint") not in endpoint_ids
                or not _num(row.get("startMs"), 0, window)
                or not _num(row.get("durationMs"), 1, 1500 + 200)
                or not _num(row.get("peak"), 0.0, 1.0)
                or not _num(row.get("pid"), 0, 0xffffffff)
                or not isinstance(row.get("identityKnown"), bool)
                or not isinstance(row.get("systemSounds"), bool)
                or row["identityKnown"] and not (
                    row["pid"] and isinstance(row.get("processStart"), str)
                    and row["processStart"])):
            return False
    return True


def _burst_findings(burst):
    findings = []
    groups = {}
    for row in burst["events"]:
        who = ("system sounds" if row["systemSounds"] else
               (row["pid"], row["processStart"]) if row["identityKnown"] else None)
        groups.setdefault((row["endpoint"], who), []).append(row)
    for (endpoint, who), rows in sorted(groups.items(), key=lambda kv: str(kv[0])):
        if who == "system sounds":
            actor = "system sounds session"
        elif who:
            actor = f"process {who[0]} started {who[1]}"
        else:
            actor = "no exact process identity"
        low = min(r["durationMs"] for r in rows)
        high = max(r["durationMs"] for r in rows)
        findings.append(_finding(
            "low", "short audio burst (beep-like)",
            f"endpoint {endpoint}: {len(rows)} burst(s) of {low}-{high} ms, "
            f"peak up to {max(r['peak'] for r in rows):.3f}; {actor}. Amplitude "
            "only: tone, content and audibility are not verified"))
    if burst["sustained"]:
        findings.append(_finding(
            "low", "continuous audio output during the burst window",
            f"{burst['sustained']} stretch(es) of sound spanned the window edge or "
            "lasted over 1.5 s, so they were not classified as beeps"))
    return findings


def _routes(data):
    return {(row["flow"], row["role"]): row.get("id")
            for row in data.get("defaults", [])}


def _active(data):
    # A bare PID is never an identity. Ignore ambiguous shared/system sessions
    # and exited processes for transition attribution.
    return {(row["endpoint"], row["pid"], row["processStart"])
            for row in data.get("sessions", [])
            if row.get("flow") == "render" and row.get("state") == 1
            and row.get("identityKnown") and row.get("singleProcess")
            and isinstance(row.get("processStart"), str)
            and row["processStart"]}


def compare(current, previous):
    findings = []
    if previous.get("schema") == 1:
        before, after = _routes(previous), _routes(current)
        for flow, role in sorted(_ROLES):
            old, new = before.get((flow, role)), after.get((flow, role))
            if old != new:
                findings.append(_finding(
                    "medium" if flow == "capture" else "low",
                    "default audio route changed",
                    f"{flow}/{role}: {old or 'none'} -> {new or 'none'}; "
                    "source is not attributed and this is a sampled change"))
        for endpoint, pid, started in sorted(_active(current) - _active(previous)):
            findings.append(_finding(
                "low", "audio render session became active",
                f"endpoint {endpoint}; process {pid} started {started}; "
                "an active session does not prove audible output"))
    active = sum(row.get("state") == 1 and row.get("flow") == "render"
                 for row in current.get("sessions", []))
    unknown = sum(row.get("state") == 1 and not row.get("identityKnown")
                  for row in current.get("sessions", []))
    burst = current["burst"]
    findings.extend(_burst_findings(burst))
    share = 100.0 * burst["elapsedMs"] / (_INTERVAL_S * 1000)
    findings.append(_finding(
        "low", "audio route and session inventory",
        f"{len(current['endpoints'])} endpoints, {active} active render "
        f"session(s), {unknown} active session(s) without exact process "
        "identity; five-minute snapshot, no stream-content or loopback "
        f"capture detection. Beep sampler: {burst['samples']} peak samples on "
        f"{burst['endpointsSampled']} endpoint(s) over {burst['elapsedMs']} ms "
        f"(about {share:.1f}% of the interval); a beep outside that window is "
        "not seen"))
    return findings


def audit(store, hosts=("wsl", "win")):
    if "win" not in hosts:
        collection.failed("audio", "Windows collection disabled")
        return [_finding("medium", "Windows audio routes are not monitored",
                         "Windows collection is disabled", "visibility")]
    data = ps_json(PS_AUDIO, timeout=45)
    if not _valid(data):
        collection.failed("audio", "metadata probe returned no valid snapshot")
        return [_finding("medium", "audio route visibility unavailable",
                         "Core Audio returned no complete, valid snapshot; "
                         "previous evidence is retained", "visibility")]
    burst = data["burst"]
    meter_errors = sorted(set(burst["errors"]))[:4]
    if burst["truncated"]:
        meter_errors.append("beep event budget exhausted")
    if not burst["endpointsSampled"] or burst["elapsedMs"] < burst["durationMs"] // 2:
        meter_errors.append("peak meter burst did not cover its window")
    if data.get("errors") or data.get("truncated"):
        reasons = sorted(set(data["errors"]))[:4]
        if data.get("truncated"):
            reasons.append("endpoint or session budget exhausted")
        collection.failed("audio", "; ".join(reasons))
        return [_finding("medium", "audio route visibility incomplete",
                         "; ".join(reasons) + "; previous evidence is retained",
                         "visibility")]
    try:
        previous = json.loads(store.get_meta(_STATE_KEY, "{}")) or {}
    except (ValueError, TypeError):
        previous = {}
    findings = compare(data, previous)
    store.set_meta(_STATE_KEY, json.dumps(dict(data, schema=1, ts=time.time())))
    if meter_errors:
        # Routes and sessions are valid and kept; only beep visibility is partial.
        collection.failed("audio", "; ".join(meter_errors))
        findings.append(_finding(
            "medium", "audio beep detection incomplete",
            "; ".join(meter_errors) + "; route evidence is current, beep "
            "visibility for this pass is partial", "visibility"))
        return findings
    collection.succeeded("audio")
    return findings
