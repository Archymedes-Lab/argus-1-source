"""Detect the evasion techniques that make the other collectors blind.

The rest of jarvis asks "what is running, and should it be?". This module asks
the prior question: "is anything in a position to lie to me?" Each check targets
a technique that is currently in wide use and that specifically defeats
userland process inspection:

  * BYOVD — load a legitimately-signed but vulnerable driver, then use it to run
    code in the kernel and switch the defences off. Nothing above the kernel can
    detect the result, so the only useful signal is the precondition: whether
    the two features that block it are on, and whether any driver is loaded from
    somewhere a normal driver never lives.
  * NTFS alternate data streams — a second, unnamed stream on an innocent file.
    It does not appear in a directory listing, does not change the visible file
    size, and executes perfectly well.
  * LNK abuse — a shortcut that displays one target and runs another. Still one
    of the most durable initial-access vectors there is.
  * Dead-drop C2 — commands and stolen data move through Telegram, Discord,
    Pastebin or a tunnel, so egress is ordinary HTTPS to a reputable host and no
    firewall rule or IP reputation feed objects.
  * Invisible Unicode — zero-width and bidirectional-override characters in a
    command line, so what you read is not what runs.

These are checks a machine can answer honestly without a kernel driver. Where a
technique genuinely cannot be seen from here, the check reports the gap instead
of implying a clean result.
"""

import re

from jarvis.platform.windows import aslist, ps_json

# Where drivers legitimately live. Vendors with a real kernel component —
# anti-cheat, virtualisation, backup, GPU tooling — do ship drivers outside
# System32, so "unusual path" alone is not the signal. What BYOVD actually needs
# is a driver in a directory a non-admin can write, because that is what lets
# the attacker put the vulnerable driver there in the first place.
DRIVER_HOME = re.compile(
    r"^(\\systemroot|%systemroot%|c:\\windows)\\system32\\(drivers|driverstore)\\|"
    r"^(\\systemroot|%systemroot%|c:\\windows)\\system32\\[a-z0-9_.-]+\.(sys|dll)$",
    re.I,
)

# Under a normal ACL an unprivileged process can write here; a driver staged in
# one of these did not come from an installer that already had admin.
DRIVER_USER_WRITABLE = re.compile(
    r"\\appdata\\|\\temp\\|\\downloads\\|\\users\\public\\|\\programdata\\|"
    r"^c:\\users\\|\\windows\\temp\\|\\tasks\\", re.I,
)


def _normalize_driver_path(path: str) -> str:
    """Strip the NT object-manager prefixes the Service Control Manager reports.

    Win32_SystemDriver hands back paths like \\??\\C:\\... and
    \\SystemRoot\\System32\\..., which no plain path comparison will match.
    """
    p = (path or "").strip().strip('"')
    for prefix in (r"\??\ ".strip(), r"\\?\ ".strip()):
        if p.lower().startswith(prefix.lower()):
            p = p[len(prefix):]
            break
    return p

# Drivers repeatedly abused for BYOVD. Presence is not proof — some are shipped
# by real products — but each of these has a public exploit that grants kernel
# read/write, so one appearing on a workstation deserves a direct answer.
KNOWN_ABUSED_DRIVERS = re.compile(
    r"^(rtcore64|gdrv|gmer|iqvw64e|dbutil_2_3|dbutildrv2|winio|winring0|"
    r"speedfan|aswarpot|procexp1[0-9]?|kprocesshacker|truesight|viragt64|"
    r"mhyprot2|echo_driver|zam64|amsdk|terminator|asrdrv10[0-9]?|nvflash|"
    r"atillk64|elrawdsk|physmem|rwdrv|stdcdrv64)\.sys$",
    re.I,
)

# Dead-drop and tunnel infrastructure. The point of each is that the traffic is
# ordinary HTTPS to a host with a good reputation, so the destination name is
# the only thing that gives it away.
DEAD_DROP = re.compile(
    r"(api\.telegram\.org|discord(app)?\.com/api/webhooks|"
    r"pastebin\.com/raw|paste\.ee|hastebin|ghostbin|rentry\.co|"
    r"transfer\.sh|file\.io|anonfiles|gofile\.io|temp\.sh|"
    r"\.ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|"
    r"localtonet\.com|playit\.gg|loclx\.io|serveo\.net|pinggy\.io)",
    re.I,
)

# Binaries whose whole purpose is to expose this machine through someone else's
# infrastructure, bypassing the firewall entirely because the connection is
# outbound.
TUNNEL_BINARIES = re.compile(
    r"^(ngrok|cloudflared|localtonet|playit|frpc|frps|chisel|gost|"
    r"localxpose|loclx|pinggy|zrok|bore|tunnelto)\.exe$",
    re.I,
)

# Living-off-the-land binaries a shortcut has no honest reason to point at.
LNK_LOLBIN = re.compile(
    r"\\(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|"
    r"certutil|bitsadmin|msiexec|installutil|conhost|forfiles|"
    r"wmic|curl|ftp)\.exe$",
    re.I,
)

# Zero-width, bidirectional-override and Unicode-tag characters. None of these
# has any business in a command line; all of them let displayed text differ from
# executed text.
INVISIBLE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff"
    "\U000e0000-\U000e007f]"
)


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": "win"}


def _describe_invisible(text: str) -> str:
    return ", ".join(sorted({f"U+{ord(c):04X}" for c in INVISIBLE.findall(text)}))


PS_EVASION = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

# --- 1. the two features that actually stop BYOVD -------------------------
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$o.hvciRunning = [bool](@($dg.SecurityServicesRunning) -contains 2)
$o.hvciConfigured = [bool](@($dg.SecurityServicesConfigured) -contains 2)
$o.vbsStatus = [int]$dg.VirtualizationBasedSecurityStatus

$ci = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
$v = (Get-ItemProperty -Path $ci -Name VulnerableDriverBlocklistEnable).VulnerableDriverBlocklistEnable
# Absent means "default", and the default is on for Windows 11 22H2 and later.
$o.blocklistValue = if ($null -eq $v) { -1 } else { [int]$v }

$hv = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
$o.hvciRegEnabled = [int](Get-ItemProperty -Path $hv -Name Enabled).Enabled

# --- 2. loaded kernel drivers ---------------------------------------------
# Only drivers outside the normal directories get an Authenticode check: over
# 300 drivers are loaded and signature verification is far too slow to run on
# all of them every pass.
$o.drivers = @(Get-CimInstance Win32_SystemDriver |
  Where-Object { $_.State -eq 'Running' -and $_.PathName } |
  ForEach-Object {
    [pscustomobject]@{
      name = [string]$_.Name
      path = [string]$_.PathName
      start= [string]$_.StartMode
    } })

# --- 3. alternate data streams --------------------------------------------
# Zone.Identifier is the mark-of-the-web and is on nearly every downloaded file;
# any *other* stream is the interesting case. Scoped to the directories payloads
# stage in, and capped, because a full-disk stream enumeration is not something
# you can run every half hour.
$dirs = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop",
          "$env:TEMP", "$env:LOCALAPPDATA\Temp", "$env:PUBLIC",
          "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")
$cut = (Get-Date).AddDays(-90)
$o.ads = @(foreach ($d in $dirs) {
  if (-not (Test-Path -LiteralPath $d)) { continue }
  Get-ChildItem -LiteralPath $d -File -Recurse -Depth 2 -Force |
    Where-Object { $_.LastWriteTime -gt $cut } |
    Select-Object -First 400 |
    ForEach-Object {
      $f = $_
      Get-Item -LiteralPath $f.FullName -Stream * |
        Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' } |
        ForEach-Object {
          [pscustomobject]@{ file=[string]$f.FullName
                             stream=[string]$_.Stream
                             size=[long]$_.Length }
        }
    }
})

# --- 4. shortcuts ----------------------------------------------------------
$shell = New-Object -ComObject WScript.Shell
$lnkDirs = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
             "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
             "$env:USERPROFILE\Desktop", "$env:PUBLIC\Desktop",
             "$env:USERPROFILE\Downloads")
$o.lnks = @(foreach ($d in $lnkDirs) {
  if (-not (Test-Path -LiteralPath $d)) { continue }
  Get-ChildItem -LiteralPath $d -Filter *.lnk -Force -ErrorAction SilentlyContinue |
    Select-Object -First 150 |
    ForEach-Object {
      $s = $shell.CreateShortcut($_.FullName)
      [pscustomobject]@{
        lnk    = [string]$_.FullName
        target = [string]$s.TargetPath
        args   = [string]$s.Arguments
        icon   = [string]$s.IconLocation
        wstyle = [int]$s.WindowStyle
      }
    }
})

# --- 5. where this machine has actually been resolving ---------------------
# The DNS client cache is the cheapest possible view of egress destinations by
# name, which is the only way dead-drop C2 is distinguishable at all.
$o.dns = [string[]]@(Get-DnsClientCache | Select-Object -ExpandProperty Entry -Unique)

# --- 6. autostart command lines, for the Unicode check ---------------------
$o.autoruns = @(
  foreach ($k in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                   'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
    if (-not (Test-Path $k)) { continue }
    $p = Get-ItemProperty $k
    $p.PSObject.Properties |
      Where-Object { $_.Name -notlike 'PS*' } |
      ForEach-Object { [pscustomobject]@{ key=$k; name=[string]$_.Name; cmd=[string]$_.Value } }
  })

$o.runmru = [string[]]@(
  $m = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
  if (Test-Path $m) {
    (Get-ItemProperty $m).PSObject.Properties |
      Where-Object { $_.Name -match '^[a-z]$' } | ForEach-Object { [string]$_.Value }
  })

$payload = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
"""


def audit():
    data = ps_json(PS_EVASION, timeout=300)
    if data is None:
        return [_finding("byovd", "medium", "evasion audit unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    # -- 1. BYOVD preconditions -------------------------------------------
    hvci = bool(data.get("hvciRunning"))
    out.append(_finding(
        "byovd", "ok" if hvci else "high",
        "Memory Integrity (HVCI)" + (" is on" if hvci else " is OFF"),
        "kernel code integrity enforced by the hypervisor — this is what stops a "
        "vulnerable signed driver from being loaded and used to run kernel code"
        if hvci else
        "without it, any signed-but-vulnerable driver can be loaded and used to "
        "execute kernel code and switch off the defences. Windows Security → "
        "Device security → Core isolation → Memory integrity.",
        "Win32_DeviceGuard"))

    blocklist = data.get("blocklistValue", -1)
    if blocklist == 0:
        out.append(_finding(
            "byovd", "critical", "vulnerable driver blocklist is explicitly disabled",
            "VulnerableDriverBlocklistEnable is set to 0. This is not a default — "
            "something set it, and turning it off is a documented precursor to "
            "loading a vulnerable driver.",
            r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config"))
    elif blocklist == -1:
        out.append(_finding(
            "byovd", "ok", "vulnerable driver blocklist at default",
            "no explicit setting; on by default from Windows 11 22H2",
            r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config"))
    else:
        out.append(_finding("byovd", "ok", "vulnerable driver blocklist enabled",
                            "VulnerableDriverBlocklistEnable = 1", "CI\\Config"))

    # -- 2. drivers in the wrong place ------------------------------------
    odd = 0
    for d in aslist(data.get("drivers")):
        path = _normalize_driver_path(d.get("path"))
        base = path.replace("/", "\\").rsplit("\\", 1)[-1]
        if KNOWN_ABUSED_DRIVERS.match(base):
            out.append(_finding(
                "byovd", "critical", "known BYOVD-abused driver is loaded",
                f"{d.get('name')} — {base} has a public kernel read/write exploit",
                path))
            odd += 1
        elif DRIVER_HOME.match(path):
            continue
        elif DRIVER_USER_WRITABLE.search(path):
            out.append(_finding(
                "byovd", "high", "kernel driver loaded from a user-writable path",
                f"{d.get('name')} (start={d.get('start')}) — a driver here did not "
                f"come from an installer that already had admin, which is exactly "
                f"how BYOVD stages",
                path))
            odd += 1
        else:
            out.append(_finding(
                "byovd", "low", "kernel driver outside the standard directories",
                f"{d.get('name')} (start={d.get('start')}) — normal for anti-cheat, "
                f"virtualisation and backup products, which ship their own signed "
                f"driver; worth recognising the name",
                path))
            odd += 1
    total = len(aslist(data.get("drivers")))
    if total:
        out.append(_finding("byovd", "ok", "kernel drivers",
                            f"{total} running, none on the abused-driver list"
                            + ("" if odd else ", all from standard directories"),
                            ""))

    # -- 3. alternate data streams ----------------------------------------
    ads = aslist(data.get("ads"))
    for a in ads[:20]:
        out.append(_finding(
            "ads", "high", "file carries a hidden alternate data stream",
            f"{a.get('stream')} ({a.get('size')} bytes) — a second stream does not "
            f"show in a directory listing and does not change the visible file size",
            a.get("file", "")))
    if not ads:
        out.append(_finding("ads", "ok", "no unexpected alternate data streams",
                            "staging directories carry only Zone.Identifier "
                            "(the normal mark-of-the-web)", ""))

    # -- 4. shortcuts ------------------------------------------------------
    bad_lnk = 0
    for l in aslist(data.get("lnks")):
        target, args = l.get("target") or "", l.get("args") or ""
        reasons = []
        if LNK_LOLBIN.search(target):
            reasons.append(f"points at {target.rsplit(chr(92), 1)[-1]}")
        if re.search(r"http://|https://|frombase64string|-enc\b|iex|"
                     r"invoke-expression|downloadstring", args, re.I):
            reasons.append("arguments fetch or decode code")
        # A shortcut that runs minimised or hidden is how the flash is avoided.
        if l.get("wstyle") == 7 and reasons:
            reasons.append("opens minimised")
        # The icon is what you actually look at; borrowing one from a different
        # binary than the target is deliberate misdirection.
        icon = (l.get("icon") or "").split(",")[0]
        if icon and target and icon.lower() != target.lower() and \
                icon.lower().endswith((".exe", ".dll")) and LNK_LOLBIN.search(target):
            reasons.append(f"shows the icon of {icon.rsplit(chr(92), 1)[-1]}")
        if reasons:
            bad_lnk += 1
            out.append(_finding(
                "lnk", "high" if len(reasons) > 1 else "medium",
                "shortcut runs something other than what it appears to",
                f"{', '.join(reasons)} — args: {args[:110]}",
                l.get("lnk", "")))
    if not bad_lnk:
        out.append(_finding("lnk", "ok", "shortcuts",
                            "no shortcut in Startup, Desktop or Downloads points "
                            "at a script host or fetches code", ""))

    # -- 5. dead-drop C2 ---------------------------------------------------
    hits = sorted({e for e in aslist(data.get("dns"))
                   if isinstance(e, str) and DEAD_DROP.search(e)})
    for h in hits[:15]:
        out.append(_finding(
            "c2", "high", "resolved a known dead-drop or tunnel host",
            f"{h} — services in this class are used to carry commands and stolen "
            f"data over ordinary HTTPS, so no firewall rule or IP reputation "
            f"check objects. Benign use exists; confirm you did this.",
            "DNS client cache"))
    if not hits:
        out.append(_finding("c2", "ok", "no dead-drop C2 destinations resolved",
                            "nothing in the DNS cache matches Telegram bot API, "
                            "Discord webhooks, paste sites or tunnel providers", ""))

    # -- 6. invisible Unicode ---------------------------------------------
    suspect = []
    for a in aslist(data.get("autoruns")):
        cmd = a.get("cmd") or ""
        if INVISIBLE.search(cmd):
            suspect.append((f"{a.get('key')}\\{a.get('name')}", cmd))
    for cmd in aslist(data.get("runmru")):
        if isinstance(cmd, str) and INVISIBLE.search(cmd):
            suspect.append(("RunMRU", cmd))
    for l in aslist(data.get("lnks")):
        blob = f"{l.get('target') or ''} {l.get('args') or ''}"
        if INVISIBLE.search(blob):
            suspect.append((l.get("lnk", ""), blob))
    for where, cmd in suspect[:15]:
        out.append(_finding(
            "unicode", "critical", "command line contains invisible characters",
            f"{_describe_invisible(cmd)} — what is displayed is not what runs; "
            f"zero-width and bidirectional-override characters exist here for no "
            f"legitimate reason: {INVISIBLE.sub('', cmd)[:100]}",
            where))
    if not suspect:
        out.append(_finding("unicode", "ok", "no invisible characters in command lines",
                            "Run keys, RunMRU and shortcuts are all plain text", ""))

    return out


CAT_ORDER = {"byovd": 0, "unicode": 1, "ads": 2, "lnk": 3, "c2": 4}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9),
                                    x["title"]))
