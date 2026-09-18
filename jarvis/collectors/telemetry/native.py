"""Native sensor delivery: drain the spool into the event log, and say what it cost.

The ingestion itself is `jarvis.platform.native.ingest`. This job is the part
that reports: whether the sensor exists and is alive, which channels it cannot
read, whether any delivery was lost or refused, and whether recorded history
still verifies. A detector reading the event log inherits every one of these
limits, so they are findings, not log lines.
"""

import json
import time

from jarvis.core import collection
from jarvis.core.eventlog import DEFAULT_ROOT, EventLog, LogError
from jarvis.core.finding import win_finding as _finding
from jarvis.platform.native import ingest

SENSOR = "native sensor"
INSTALL = "windows-sensor\\install.ps1 -Install (elevated PowerShell)"
# Gaps are events: they happened once, in one run. Keep re-reporting them for
# a week so a lost stretch of history is not visible for a single minute.
GAP_META = "native_gaps"
GAP_KEEP = 7 * 86400
VERIFY_META = "eventlog_verified_at"
VERIFY_EVERY = 86400

CHANNEL_FIX = {
    "Microsoft-Windows-TaskScheduler/Operational":
        "wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true",
}


def _gaps(store, fresh):
    now = time.time()
    try:
        kept = json.loads(store.get_meta(GAP_META, "[]") or "[]")
    except ValueError:
        kept = []
    kept = [g for g in kept if now - g.get("at", 0) < GAP_KEEP]
    kept += [{"at": now, "channel": ch, "gap": gap} for ch, gap in fresh]
    kept = kept[-50:]
    store.set_meta(GAP_META, json.dumps(kept))
    store.commit()
    return kept


def audit(store, hosts=("win",), spool=None, root=None):
    if "win" not in hosts:
        return []
    spool = spool or ingest.SPOOL
    try:
        log = EventLog(root or DEFAULT_ROOT, writer=True)
    except LogError as exc:
        collection.failed(SENSOR, str(exc))
        return [_finding("visibility", "medium", "Event log is busy or unavailable", str(exc),
                         str(root or DEFAULT_ROOT))]
    try:
        report = ingest.run(log=log, spool=spool)
        out = []
        if not report["installed"]:
            collection.failed(SENSOR, "not installed")
            return [_finding(
                "visibility", "medium", "The native Windows sensor is not installed",
                "Windows telemetry reaches JARVIS only through PowerShell queries over "
                "the WSL bridge: capped, sampled by time window, and blind whenever WSL "
                "is down. The sensor is a Windows service that records every Sysmon and "
                "Defender record in order, with losses reported rather than hidden. "
                f"Install it with {INSTALL}.", str(spool))]
        out += _health(report.get("health"))
        fresh_gaps = []
        for ch in report["channels"]:
            name = ch["channel"] or ch["directory"]
            if ch["error"]:
                collection.failed(SENSOR, f"{name}: delivery stopped")
                out.append(_finding(
                    "visibility", "high", f"Sensor delivery stopped for {_short(name)}",
                    f"{ch['error']}. Nothing after this batch is ingested until it is "
                    f"resolved — the cursor holds rather than skipping evidence.", name))
            for gap in ch["gaps"]:
                fresh_gaps.append((name, gap))
            if ch["ack_error"]:
                out.append(_finding(
                    "visibility", "low", "The sensor spool cannot be acknowledged",
                    f"{ch['ack_error']}. The sensor keeps every batch until it is "
                    f"acknowledged and stops collecting at capacity. Re-run {INSTALL} "
                    f"to grant this account write access to the acks folder.", str(spool)))
                break
        for g in _gaps(store, fresh_gaps):
            out.append(_finding(
                "telemetry loss", "medium", f"Records missing from {_short(g['channel'])}",
                f"{g['gap']} (recorded {time.strftime('%Y-%m-%d %H:%M', time.localtime(g['at']))}). "
                f"Events that were never read cannot be analysed; a log that wraps "
                f"faster than it is read needs a larger maximum size.", g["channel"]))
        out += _verify(store, log)
        if not any(f["severity"] in ("high", "critical") for f in out if f["category"] == "visibility"):
            collection.succeeded(SENSOR)
        stats = report.get("log") or log.stats()
        pruned = (f"; {stats['pruned']} older segments removed by the space budget"
                  if stats["pruned"] else "")
        out.append(_finding(
            "telemetry", "ok", f"Native sensor delivered {report['events']} events this run",
            f"The event log holds events 1–{stats['last_seq']} in {stats['segments']} sealed "
            f"segments ({stats['sealed_bytes'] // 1024 // 1024} MiB) plus "
            f"{stats['unsealed_events']} unsealed{pruned}.", str(log.root)))
        return out
    finally:
        log.close()


def _short(channel):
    return channel.replace("Microsoft-Windows-", "").replace("/Operational", "")


def _health(health):
    if health is None:
        collection.failed(SENSOR, "no health file")
        return [_finding("visibility", "high", "The native sensor has never reported health",
                         "The spool exists but health.json does not: the service is "
                         "installed and not running, or cannot write its spool.", "health.json")]
    if health.get("status") == "unreadable":
        collection.failed(SENSOR, "health unreadable")
        return [_finding("visibility", "high", "The native sensor's health file is unreadable",
                         health.get("reason", ""), "health.json")]
    out = []
    age = health.get("age")
    if age is None or age > ingest.HEALTH_STALE:
        collection.failed(SENSOR, "health stale")
        mins = "an unknown time" if age is None else f"{int(age // 60)} minutes"
        out.append(_finding(
            "visibility", "high", "The native sensor has stopped reporting",
            f"Its last health report is {mins} old; it writes one every few seconds "
            f"while running. Check the JarvisNativeSensor service.", "JarvisNativeSensor"))
    if health.get("status") == "unavailable":
        out.append(_finding("visibility", "high", "The native sensor failed its last pass",
                            str(health.get("reason", ""))[:300], "JarvisNativeSensor"))
    for channel, state in (health.get("channels") or {}).items():
        if isinstance(state, dict) and state.get("status") == "unavailable":
            reason = str(state.get("reason", ""))
            fix = CHANNEL_FIX.get(channel)
            out.append(_finding(
                "visibility", "medium", f"The sensor cannot read {_short(channel)}",
                reason + (f". Enable it (elevated): {fix}" if fix and "disabled" in reason else ""),
                channel))
    used, cap = health.get("spool_bytes"), health.get("spool_capacity")
    if used and cap and used >= 0.75 * cap:
        out.append(_finding(
            "visibility", "high" if used >= cap else "medium", "The sensor spool is nearly full",
            f"{used // 1024 // 1024} of {cap // 1024 // 1024} MiB. At capacity the sensor "
            f"stops collecting rather than delete evidence.", "spool"))
    if health.get("compaction_error"):
        out.append(_finding("visibility", "low", "The sensor could not reclaim spool space",
                            str(health["compaction_error"])[:300], "spool"))
    return out


def _verify(store, log):
    """Re-verify the whole chain daily; history damage is the loudest finding here."""
    last = float(store.get_meta(VERIFY_META, 0) or 0)
    if time.time() - last < VERIFY_EVERY:
        return []
    result = log.verify()
    store.set_meta(VERIFY_META, time.time())
    store.commit()
    if result["ok"]:
        return []
    return [_finding(
        "tampering", "critical", "Recorded event history does not verify",
        "; ".join(result["problems"][:5]) + ". Segments were changed, removed or "
        "reordered outside retention. Preserve the event log directory before "
        "anything else writes to it.", str(log.root))]
