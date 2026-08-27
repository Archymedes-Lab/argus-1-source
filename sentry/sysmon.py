"""Sysmon: the interception layer this design could not otherwise have.

Every other collector here samples state on an interval, and `coverage.py`
reports the consequence honestly: anything that starts and exits between two
passes is never seen. That ceiling is why `T1003` — OS credential dumping, the
most-raised technique in the entire intelligence corpus — was marked
unclosable. Catching a process opening LSASS requires being told when it
happens, not asking afterwards whether it did.

Sysmon is a kernel driver that does exactly that, writing to an event log this
module reads. It changes what sentry is capable of rather than adding another
thing to poll:

  event 10  a process opened another process's memory — the LSASS case is
            credential theft, and the access mask says whether it was a read
  event 8   a thread created inside another process
  event 25  process image tampering: hollowing and herpaderping
  event 7   an image loaded that is unsigned or signed by nobody expected
  event 22  every DNS query, by process
  event 1   every process start, with a SHA-256 and its parent

The last two matter beyond their own findings. A DNS query is a name to check
against the 53,000 domains the intel corpus holds, and a process start carries
a hash to check against 252,000 sample digests — so Sysmon turns the knowledge
base from something matched against *current* state into something matched
against everything that has happened since the last pass.

Reading the channel needs membership in `Event Log Readers` or elevation. When
that is missing the module says so and says how to fix it, because a log that
cannot be read produces exactly the same silence as a machine with nothing
wrong.
"""

import json

from .control import _aslist, _ps_json
from .util import iso, now

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CAT_ORDER = {"credential access": 0, "injection": 1, "tampering": 2,
             "intel match": 3, "telemetry": 4, "visibility": 5}

CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Access masks that include reading another process's memory. 0x0010 is
# PROCESS_VM_READ and 0x0400 is PROCESS_QUERY_INFORMATION; the classic
# credential-dumping combination is 0x1010 or 0x1410.
VM_READ = 0x0010

# Processes that legitimately open LSASS. Windows' own protection stack and
# a few management agents do this by design.
LSASS_EXPECTED = {
    "msmpeng.exe", "mssense.exe", "sensecncproxy.exe", "wmiprvse.exe",
    "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe", "services.exe",
    "taskmgr.exe", "procexp64.exe", "procexp.exe", "perfmon.exe",
    "securityhealthservice.exe", "mpcmdrun.exe", "vgk.exe", "vgc.exe",
}


# Windows creates threads across its own processes as normal operation — the
# desktop compositor into the client-server subsystem, the crash handler into
# whatever crashed. Reporting those as injection is the CreateRemoteThread
# equivalent of flagging every browser sandbox hook.
SYSTEM_INJECTORS = {
    "dwm.exe", "csrss.exe", "wininit.exe", "services.exe", "smss.exe",
    "lsass.exe", "svchost.exe", "werfault.exe", "werfaultsecure.exe",
    "explorer.exe", "audiodg.exe", "taskmgr.exe", "system", "ntoskrnl.exe",
    "sihost.exe", "runtimebroker.exe", "dllhost.exe", "conhost.exe",
    "searchindexer.exe", "wmiprvse.exe", "msmpeng.exe", "mssense.exe",
}


def _finding(category, severity, title, detail, where="", host="win"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def _ps(script, timeout=240):
    return _ps_json(
        script + "\n$json = [pscustomobject]$o | ConvertTo-Json -Depth 6 -Compress\n"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))",
        timeout=timeout)


def status():
    """Is Sysmon installed, and can this account actually read its log?"""
    d = _ps(r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
$svc = Get-CimInstance Win32_Service -Filter "Name='Sysmon64' or Name='Sysmon'"
$o.installed = [bool]$svc
$o.state = [string]$svc.State
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational'
$o.channel = [bool](Test-Path $k)
$o.enabled = [string](Get-ItemProperty $k).Enabled
# The only honest test of readability is a read.
$probe = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -EA SilentlyContinue
$o.readable = [bool]$probe
$o.reader = [bool]((whoami /groups) -match 'Event Log Readers')
""", timeout=180)
    return d or {}


def _fetch(hours=24, max_events=3000):
    """Pull the event types worth reasoning about, already reduced to fields."""
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
$since = (Get-Date).AddHours(-__HOURS__)
$ev = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        Id=1,3,7,8,10,22,25
        StartTime=$since } -MaxEvents __MAX__ -EA SilentlyContinue

$rows = foreach ($e in $ev) {
  $d = @{}
  foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
  [pscustomobject]@{
    id      = $e.Id
    time    = $e.TimeCreated.ToString('o')
    # ProcessAccess (10) and CreateRemoteThread (8) name the actor
    # SourceImage, not Image — reading the wrong field left every injection
    # finding with a blank process name.
    image   = [string]$(if ($d['SourceImage']) { $d['SourceImage'] } else { $d['Image'] })
    target  = [string]$d['TargetImage']
    granted = [string]$d['GrantedAccess']
    parent  = [string]$d['ParentImage']
    hashes  = [string]$d['Hashes']
    query   = [string]$d['QueryName']
    loaded  = [string]$d['ImageLoaded']
    signed  = [string]$d['Signed']
    sigstat = [string]$d['SignatureStatus']
    dest    = [string]$d['DestinationIp']
    dport   = [string]$d['DestinationPort']
    cmdline = [string]$d['CommandLine']
    type    = [string]$d['Type']
  }
}
$o.events = @($rows)
$o.count = @($rows).Count
""".replace("__HOURS__", str(int(hours))).replace("__MAX__", str(int(max_events)))
    return _ps(script, timeout=420) or {}


def _sha256_of(hashes):
    """Sysmon packs hashes as 'SHA1=..,MD5=..,SHA256=..,IMPHASH=..'."""
    for part in (hashes or "").split(","):
        k, _, v = part.partition("=")
        if k.strip().upper() == "SHA256":
            return v.strip().lower()
    return ""


def _base(path):
    """Basename of a Sysmon image path, or "" when Sysmon could not resolve it.

    Sysmon writes the literal string `<unknown process>` rather than leaving
    the field empty, so testing for emptiness silently never fires.
    """
    p = (path or "").strip()
    if not p or p.startswith("<"):
        return ""
    return p.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def audit(store=None, hours=24, hosts=("win",)):
    if "win" not in hosts:
        return []

    st = status()
    if not st:
        return [_finding("visibility", "medium", "Sysmon status unavailable",
                         "powershell.exe returned no data")]
    if not st.get("installed"):
        return [_finding(
            "visibility", "medium", "Sysmon is not installed",
            "without an interception layer, anything that starts and exits "
            "between two sampling passes is invisible — which is why "
            "credential dumping cannot be detected by polling",
            "Sysmon64.exe -i")]
    if not st.get("readable"):
        return [_finding(
            "visibility", "high",
            "Sysmon is running but its log cannot be read by this account",
            "the driver is recording and nothing here can see it, which "
            "produces the same silence as a clean machine. Add this account to "
            "the Event Log Readers group (one-time, needs admin): "
            "net localgroup \"Event Log Readers\" %USERNAME% /add — then log "
            "out and back in. Running sentry elevated also works.",
            CHANNEL)]

    data = _fetch(hours=hours)
    events = _aslist(data.get("events"))
    out = []

    lsass_hits, remote_threads, tampering = [], [], []
    unsigned, dns_names, proc_hashes = {}, {}, {}

    for e in events:
        eid = int(e.get("id") or 0)
        image = e.get("image") or ""
        base = _base(image)

        if eid == 10:
            if _base(e.get("target")) != "lsass.exe":
                continue
            if base in LSASS_EXPECTED:
                continue
            try:
                mask = int(str(e.get("granted") or "0"), 16)
            except ValueError:
                mask = 0
            lsass_hits.append((image, e.get("granted"), e.get("time"),
                               bool(mask & VM_READ)))
        elif eid == 8:
            remote_threads.append((image, e.get("target"), e.get("time")))
        elif eid == 25:
            tampering.append((image, e.get("type"), e.get("time")))
        elif eid == 7:
            if str(e.get("signed") or "").lower() == "false":
                unsigned.setdefault(_base(e.get("loaded")), [0, image])
                unsigned[_base(e.get("loaded"))][0] += 1
        elif eid == 22:
            q = (e.get("query") or "").lower().rstrip(".")
            if q:
                dns_names.setdefault(q, set()).add(base)
        elif eid == 1:
            h = _sha256_of(e.get("hashes"))
            if h:
                proc_hashes.setdefault(h, (image, e.get("time")))

    # -- credential access -------------------------------------------------
    for image, granted, when, read in lsass_hits:
        out.append(_finding(
            "credential access", "critical" if read else "high",
            f"{_base(image)} opened LSASS memory",
            f"granted access {granted}"
            + (" including PROCESS_VM_READ, which is what reading credentials "
               "out of LSASS requires" if read else "")
            + f" — {iso_of(when)}. This is the detection that polling cannot "
              f"make, and the technique current intel raises more than any "
              f"other.", image))

    # -- injection ---------------------------------------------------------
    routine = 0
    for image, target, when in remote_threads[:40]:
        src, dst = _base(image), _base(target)
        if src in SYSTEM_INJECTORS and dst in SYSTEM_INJECTORS:
            routine += 1
            continue
        out.append(_finding(
            "injection", "medium" if not src else "high",
            f"{src or '<unknown process>'} created a thread inside {dst}",
            f"{iso_of(when)} — a thread starting in another process's address "
            f"space is code executing where it was not loaded"
            + ("; Sysmon could not resolve the source image, which usually "
               "means the kernel" if not src else ""), image))
    if routine:
        out.append(_finding(
            "injection", "ok",
            f"{routine} remote threads between Windows system processes",
            "the compositor, subsystem and crash handler create threads in "
            "each other as normal operation", "SYSTEM_INJECTORS"))

    for image, kind, when in tampering[:20]:
        out.append(_finding(
            "tampering", "critical",
            f"process image tampering by {_base(image)}",
            f"{kind or 'image replaced'} at {iso_of(when)} — the process on "
            f"disk is not the code that is running, which is hollowing",
            image))

    for name, (count, loader) in sorted(
            unsigned.items(), key=lambda kv: -kv[1][0])[:10]:
        out.append(_finding(
            "tampering", "medium", f"unsigned image loaded: {name}",
            f"loaded {count}×, most recently by {_base(loader)} — an unsigned "
            f"module runs with the full trust of whatever loaded it", loader))

    # -- correlation with the intelligence corpus --------------------------
    if store is not None:
        out += _correlate(store, dns_names, proc_hashes)

    out.append(_finding(
        "telemetry", "ok",
        f"Sysmon delivered {len(events)} events in the last {hours}h",
        f"{len(dns_names)} distinct DNS names and {len(proc_hashes)} process "
        f"hashes were checked against the indicator corpus; "
        f"{len(lsass_hits)} unexpected LSASS opens, "
        f"{len(remote_threads)} remote threads", CHANNEL))
    return sort_findings(out)


def iso_of(t):
    """Sysmon timestamps arrive as ISO strings already; keep them readable."""
    return (t or "")[:19].replace("T", " ")


def _correlate(store, dns_names, proc_hashes):
    """Match observed names and hashes against stored indicators.

    This is the payoff of having both halves: the corpus stops being a thing
    checked against current state and becomes a thing checked against
    everything that happened while nobody was looking.
    """
    out = []
    for name, procs in dns_names.items():
        parts = name.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            hit = store.db.execute(
                "SELECT context, source_url, malware, source FROM indicators "
                "WHERE kind='domain' AND norm=? AND status='active'",
                (parent,)).fetchone()
            if hit:
                label = hit["malware"] or hit["context"] or "listed in threat intelligence"
                out.append(_finding(
                    "intel match", "critical",
                    f"a process resolved a known attacker domain: {name}",
                    f"queried by {', '.join(sorted(procs))} — {label} "
                    f"(via {hit['source']})", hit["source_url"]))
                break

    for digest, (image, when) in proc_hashes.items():
        hit = store.db.execute(
            "SELECT context, source_url, malware, source FROM indicators "
            "WHERE kind='sha256' AND norm=? AND status='active'",
            (digest,)).fetchone()
        if hit:
            label = hit["malware"] or hit["context"] or "listed in threat intelligence"
            out.append(_finding(
                "intel match", "critical",
                f"a process matching a known sample ran: {_base(image)}",
                f"SHA-256 {digest} at {iso_of(when)} — {label} "
                f"(via {hit['source']})", image))
    return out


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9), x["title"]))
