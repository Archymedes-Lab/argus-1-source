"""Parsing Sysmon for Linux records (XML or key/value text) into dicts.

Pure text handling, no I/O: shared by the Sysmon collector and by any other
collector that reads Sysmon lineage (collectors may not import each other).
"""

import re
import xml.etree.ElementTree as ET

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


def parse(text):
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
