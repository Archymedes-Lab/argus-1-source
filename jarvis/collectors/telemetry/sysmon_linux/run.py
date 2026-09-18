"""The audit: rules over new events, remembered hits, and capture-health checks."""

from jarvis.core import egress as egress_baseline
from jarvis.core.finding import finding as _finding
from jarvis.core.util import now

from .journal import CHANNEL, _event_utc, _parse, _raw, state
from .rules import (
    DOWNLOAD_RUN,
    LOG_DELETE_SUFFIX,
    LOG_DELETE_TITLE,
    PERSIST_WRITE_TITLE,
    RAW_ACCESS_TITLE,
    RAW_LEGACY_SUFFIX,
    RAW_UNRESOLVED_TITLE,
    _expected_log_maintenance,
    _expected_persistence,
    _rules,
    _without_quoted_heredocs,
)

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


# A remembered finding is shown for at most `hours` (24h by default); keeping a
# few days of it behind that covers a daemon that was down over a weekend
# without letting a since-tuned false positive resurface for a month.
REMEMBER_DAYS = 3


# The oldest event still in the journal may legitimately be a few minutes newer
# than where the last pass stopped; more than this means journald discarded
# events before they were read.
GAP_TOLERANCE = 300


# Don't judge the capture scope on a near-idle window that simply had no
# network or file activity to record.
COVERAGE_FLOOR = 200


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))


def _remember(store, findings, hours):
    ts = now()
    for f in findings:
        if f["severity"] == "ok":
            continue
        store.db.execute(
            """INSERT INTO sysmon_hits(ts,category,severity,title,detail,where_)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(category,title,where_) DO UPDATE SET
                   ts=excluded.ts, severity=excluded.severity,
                   detail=excluded.detail""",
            (ts, f["category"], f["severity"], f["title"][:300],
             f["detail"][:600], f["where"][:400]))

    # Correct old rendered claims while retaining their original observation
    # time. Never drop an unresolved device as benign or erase a real path.
    for row in store.db.execute(
            "SELECT * FROM sysmon_hits WHERE category='sysmon-linux' "
            "AND title=?", (RAW_ACCESS_TITLE,)).fetchall():
        detail = row["detail"] or ""
        if not detail.endswith(RAW_LEGACY_SUFFIX) or " opened " not in detail:
            continue
        actor, device = detail[:-len(RAW_LEGACY_SUFFIX)].split(" opened ", 1)
        if device.startswith("/") and device != "/":
            continue
        store.db.execute(
            """INSERT INTO sysmon_hits(ts,category,severity,title,detail,where_)
               VALUES(?,?,?,?,?,?) ON CONFLICT(category,title,where_)
               DO UPDATE SET ts=excluded.ts, detail=excluded.detail,
                   severity=excluded.severity WHERE excluded.ts > sysmon_hits.ts""",
            (row["ts"], "sysmon-linux", "medium", RAW_UNRESOLVED_TITLE,
             f"{actor}: legacy Sysmon Event 9 reported device {device!r}; "
             "target is unresolved; raw disk access is not established; "
             "original event time and process GUID were not retained",
             row["where_"]))
        store.db.execute("DELETE FROM sysmon_hits WHERE id=?", (row["id"],))

    # A hit created before an exemption was widened would otherwise remain
    # visible for the whole reminder window.  Re-evaluate this detector's
    # stored rows against the current rules and drop the ones now recognized
    # as expected maintenance.
    for row in store.db.execute(
            "SELECT id, title, detail FROM sysmon_hits "
            "WHERE category='sysmon-linux' AND title IN (?,?)",
            (LOG_DELETE_TITLE, PERSIST_WRITE_TITLE)).fetchall():
        detail = row["detail"] or ""
        stale = False
        if row["title"] == LOG_DELETE_TITLE and detail.endswith(LOG_DELETE_SUFFIX) \
                and " deleted " in detail:
            actor, target = detail[:-len(LOG_DELETE_SUFFIX)].split(" deleted ", 1)
            stale = _expected_log_maintenance(actor, target)
        elif row["title"] == PERSIST_WRITE_TITLE and " created/modified " in detail:
            actor, target = detail.split(" created/modified ", 1)
            stale = _expected_persistence(actor, target)
        if stale:
            store.db.execute("DELETE FROM sysmon_hits WHERE id=?", (row["id"],))

    for row in store.db.execute(
            "SELECT id, detail FROM sysmon_hits WHERE category='sysmon-linux' "
            "AND title='download-and-run in a command line'").fetchall():
        command = (row["detail"] or "").split(": ", 1)[-1]
        if not DOWNLOAD_RUN.search(_without_quoted_heredocs(command)):
            store.db.execute("DELETE FROM sysmon_hits WHERE id=?", (row["id"],))

    # A program you have since confirmed stops being reported at once.
    for row in store.db.execute(
            "SELECT id, title FROM sysmon_hits WHERE category='sysmon-linux' AND title LIKE ?",
            (egress_baseline.TITLE + " %",)).fetchall():
        program = egress_baseline.program_of(row["title"])
        if program and egress_baseline.decision(store, "wsl", program) == egress_baseline.EXPECTED:
            store.db.execute("DELETE FROM sysmon_hits WHERE id=?", (row["id"],))

    # Per-address egress rows came from the parent-name bug in rules.py and
    # are superseded by one finding per program.
    store.db.execute("DELETE FROM sysmon_hits WHERE category='sysmon-linux' "
                     "AND title LIKE 'outbound connection to %'")
    store.db.execute("DELETE FROM sysmon_hits WHERE ts < ? AND category='sysmon-linux'",
                     (ts - REMEMBER_DAYS * 86400,))
    store.commit()
    since = ts - hours * 3600
    keep = [f for f in findings if f["severity"] == "ok"]
    for r in store.db.execute(
            "SELECT * FROM sysmon_hits WHERE ts >= ? AND category='sysmon-linux' "
            "ORDER BY ts DESC", (since,)):
        keep.append(_finding(r["category"], r["severity"], r["title"],
                             r["detail"], r["where_"]))
    return keep


def _health(events, since, incremental):
    """Two things that make the stream itself untrustworthy: journald throwing
    events away before they are read, and a config that records process events
    only so half the rules never have anything to match."""
    out = []
    ids = {e.get("id") for e in events}

    if incremental and events:
        stamps = [t for t in (_event_utc(e) for e in events) if t]
        gap = min(stamps) - since if stamps else 0
        if gap > GAP_TOLERANCE:
            out.append(_finding(
                "sysmon-linux", "medium",
                "Sysmon journal rotated past the last read position",
                f"the oldest sysmon event still in the journal is ~{int(gap // 60)} "
                f"min newer than where the last pass stopped — journald is "
                f"discarding events before they are consumed, so that window was "
                f"never inspected. Install the systemd/journald-sysmon.conf "
                f"drop-in for more retention, or shorten the sysmon_linux poll "
                f"interval.", CHANNEL))

    if len(events) >= COVERAGE_FLOOR and 1 in ids and not ({3, 10, 11, 23, 26} & ids):
        out.append(_finding(
            "sysmon-linux", "medium", "Sysmon is capturing process events only",
            "no NetworkConnect, ProcessAccess or FileCreate/Delete events in this "
            "window, so the egress-correlation, memory-read and persistence-write "
            "rules have nothing to act on. Load the fuller policy bundled with "
            "JARVIS: `sudo sysmon -c \"$(pwd)/sysmon/config.xml\"`.", CHANNEL))
    return out


def audit(store=None, hours=24, hosts=("wsl", "win"), incremental=False):
    if "wsl" not in hosts:
        return []
    installed, running = state()
    if not installed:
        return [_finding(
            "sysmon-linux", "medium", "no eBPF syscall interception on Linux",
            "Sysmon for Linux is not installed. auditd cannot run on this "
            "kernel, so this is the way to make the runtime-behaviour "
            "techniques observable — see the module header for the install",
            "sysmonforlinux")]
    if not running:
        return [_finding(
            "sysmon-linux", "high", "Sysmon for Linux is installed but stopped",
            "the eBPF probes are not attached, so nothing between two sampling "
            "passes is captured. `sudo sysmon -accepteula -i` then "
            "`sudo systemctl enable --now sysmon`", "systemctl")]

    if incremental and store is not None:
        last = int(store.get_meta("sysmon_linux_last", 0) or 0)
        since = last or (now() - 1800)
        store.set_meta("sysmon_linux_last", now())
    else:
        since = now() - hours * 3600

    events = _parse(_raw(since))
    out = _rules(events, store=store) + _health(events, since, incremental)
    if store is not None:
        out = _remember(store, out, hours)
    out.append(_finding(
        "telemetry", "ok",
        f"Sysmon for Linux delivered {len(events)} events since the last pass",
        "eBPF interception active — runtime-behaviour techniques are being "
        "recorded", CHANNEL))
    return sort_findings(out)
