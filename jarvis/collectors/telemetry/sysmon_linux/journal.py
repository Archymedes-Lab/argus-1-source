"""Reading Sysmon for Linux events out of the journal and parsing them."""

import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

CHANNEL = "journal:sysmon"


def _run(args, timeout=20):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return r.stdout, r.returncode
    except (OSError, subprocess.SubprocessError):
        return "", 1


def state():
    """(installed, running)."""
    installed = bool(shutil.which("sysmon")) or os.path.exists("/opt/sysmon/sysmon")
    active_out, _ = _run(["systemctl", "is-active", "sysmon"])
    return installed, active_out.strip() == "active"


def active():
    installed, running = state()
    return installed and running


JOURNAL_TIMEOUT_S = 40
SYSLOG = "/var/log/syslog"
# Syslog is read only when the journal returned nothing for the window, as a
# duplicate source; it is not time-filtered, so only its tail can hold events the
# journal does not. Reading all of it each pass (rsyslog copies reached 9 GB on
# one host) is unbounded; the tail is enough.
SYSLOG_CAP = 8 * 1024 * 1024     # bytes read from the end of syslog, at most


def _syslog(path=SYSLOG, cap=SYSLOG_CAP):
    """(sysmon lines from the last `cap` bytes of syslog, capped?) or (None, False) without one."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - cap))
            data = fh.read(cap)
    except OSError:
        return None, False
    lines = data.decode("utf-8", errors="replace").splitlines()
    if size > cap and lines:
        lines = lines[1:]            # the first line is cut mid-way
    return "\n".join(ln for ln in lines if "sysmon" in ln.lower()), size > cap


def read_since(since_ts, run=subprocess.run, syslog=_syslog):
    """(text, ok, why): the sysmon journal text since `since_ts`, journal first then syslog.

    ok is False when nothing could be read for that window (journalctl timed out
    or failed and there is no syslog): the caller must not move its cursor past
    it (evidence continuity). why says what happened, or names a capped read."""
    try:
        r = run(["journalctl", "-t", "sysmon", "-o", "cat", "--no-pager", "--since", f"@{int(since_ts)}"],
                capture_output=True, text=True, errors="replace", timeout=JOURNAL_TIMEOUT_S)
        out, rc, failure = r.stdout, r.returncode, f"journalctl failed (exit {r.returncode})"
    except subprocess.TimeoutExpired:
        return None, False, f"journalctl did not answer within {JOURNAL_TIMEOUT_S} s"
    except OSError:
        out, rc, failure = "", None, "journalctl is not available"
    except subprocess.SubprocessError as exc:
        return None, False, f"journalctl could not run ({type(exc).__name__})"
    if rc == 0 and out.strip():
        return out, True, ""
    text, capped = syslog()
    if text is None:
        return ("", True, "") if rc == 0 else (None, False, failure)
    return text, True, (f"syslog read limited to its last {SYSLOG_CAP // (1024 * 1024)} MB" if capped else "")


def _raw(since_ts):
    """All sysmon journal text since `since_ts` ("" when nothing could be read)."""
    return read_since(since_ts)[0] or ""


_TYPE_ID = {
    "processcreate": 1, "process create": 1,
    "networkconnect": 3, "network connection": 3, "networkconnection": 3,
    "processterminate": 5, "process terminated": 5, "processterminated": 5,
    "rawaccessread": 9, "raw access read": 9,
    "processaccess": 10, "process accessed": 10,
    "filecreate": 11, "file created": 11,
    "sysmonconfigstatechanged": 16, "configchange": 16,
    "filedelete": 23, "file delete": 23, "filedeletedetected": 26,
}


def _parse(text):
    """List of {id, ...fields}. Handles the XML form and the key/value form."""
    events = []

    for m in re.finditer(r"<Event\b.*?</Event>", text, re.S):
        blob = re.sub(r'\sxmlns(:\w+)?="[^"]*"', "", m.group(0))
        try:
            root = ET.fromstring(blob)
        except ET.ParseError:
            continue
        sysd, data = root.find("System"), root.find("EventData")
        ev = {"id": int((sysd.findtext("EventID") or 0)) if sysd is not None
              else 0}
        # UtcTime in EventData is the process/event timestamp reported by
        # Sysmon. It can lag journal ingestion substantially while Sysmon is
        # draining its own queue, so retain TimeCreated separately for journal
        # continuity checks.
        created = sysd.find("TimeCreated") if sysd is not None else None
        if created is not None and created.get("SystemTime"):
            ev["SystemTime"] = created.get("SystemTime")
        for d in (list(data) if data is not None else []):
            if d.get("Name"):
                ev[d.get("Name")] = (d.text or "").strip()
        if ev["id"]:
            events.append(ev)
    if events:
        return events

    # Key/value block form: a "TypeName:" header line then "  Key: Value" lines,
    # blocks separated by blank lines.
    cur = None
    for line in text.splitlines():
        s = line.strip()
        if not s:
            if cur and cur.get("id"):
                events.append(cur)
            cur = None
            continue
        head = re.match(r"^([A-Za-z][A-Za-z ]+):$", s)
        if head and cur is None:
            cur = {"id": _TYPE_ID.get(head.group(1).strip().lower(), 0)}
            continue
        kv = re.match(r"^([A-Za-z][\w ]*):\s*(.*)$", s)
        if kv and cur is not None:
            cur[kv.group(1).replace(" ", "")] = kv.group(2).strip()
    if cur and cur.get("id"):
        events.append(cur)
    return events


def _clean(v):
    v = (v or "").strip()
    return "" if v in ("-", "<unknown process>", "<unknown>", "") else v


def _base(path):
    path = _clean(path)
    return os.path.basename(path.split()[0]) if path else ""


def _event_utc(e):
    """Journal event time, falling back to the payload time for text records."""
    value = e.get("SystemTime") or e.get("UtcTime") or ""
    try:
        if "T" in value:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        return (datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
                .replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None
