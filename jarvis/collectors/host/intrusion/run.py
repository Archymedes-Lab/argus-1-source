"""The intrusion audit: one PowerShell sample, turned into findings."""

import re

from jarvis.platform.windows import aslist, ps_json

from .bits import _bits_is_vendor
from .common import _finding
from .history import _history_findings


# Command shapes that show up in ClickFix lures and in pasted-payload attacks.
PASTE_ATTACK = re.compile(
    r"powershell|pwsh|cmd(\.exe)?\s*/c|mshta|curl|wget|iwr|invoke-webrequest|"
    r"invoke-expression|\biex\b|bitsadmin|certutil|msiexec\s+/i\s+http|"
    r"regsvr32|rundll32|conhost|forfiles|\bftp\b|base64|frombase64string|"
    r"\.hta\b|\bwscript\b|\bcscript\b|http://|https://|\\\\[^\\]+\\",
    re.I,
)


# Browser credential and session stores. Anything but the browser reading these
# is worth knowing about.
CRED_STORES = re.compile(
    r"\\(Login Data|Cookies|Web Data|Local State|key4\.db|logins\.json|"
    r"cookies\.sqlite|places\.sqlite)$", re.I)


BROWSER_PROC = re.compile(r"^(chrome|msedge|firefox|opera|brave|vivaldi|"
                          r"chromium|thorium)\.exe$", re.I)


# Extension permissions that allow reading every page, including session tokens.
BROAD_PERMS = re.compile(r"<all_urls>|\*://\*/\*|http://\*/\*|https://\*/\*|"
                         r"webRequest|cookies|debugger|nativeMessaging|proxy",
                         re.I)


PS_INTRUSION = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

# --- 1. ClickFix: everything ever typed into the Win+R Run dialog ----------
$mru = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
$o.runmru = @()
if (Test-Path $mru) {
  $p = Get-ItemProperty $mru
  $o.runmru = @($p.PSObject.Properties |
    Where-Object { $_.Name -match '^[a-z]$' } |
    ForEach-Object { [pscustomobject]@{ slot=$_.Name; cmd=[string]$_.Value } })
  $o.runmruOrder = [string]$p.MRUList
}

# --- 2. PowerShell console history (what was actually typed) --------------
$hist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
$o.psHistory = @()
if (Test-Path $hist) {
  $o.psHistoryPath = $hist
  # [string[]] is load-bearing: Get-Content attaches PSPath/PSDrive/PSProvider
  # note properties to every line it returns, and ConvertTo-Json -Depth serialises
  # that entire provider graph once per line. Left as-is this one field produced
  # ~700MB of JSON and took three minutes.
  $o.psHistory = [string[]]@(Get-Content $hist -Tail 300 |
                             Where-Object { $_.Trim() })
}

# --- 3. Defender's own detection history ----------------------------------
$o.threats = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending |
  Select-Object -First 40 | ForEach-Object {
    $t = $_
    [pscustomobject]@{
      time     = if ($t.InitialDetectionTime) { $t.InitialDetectionTime.ToString('o') } else { '' }
      action   = [string]$t.ActionSuccess
      status   = [string]$t.ThreatStatusID
      resources= [string]($t.Resources -join ' | ')
      id       = [string]$t.ThreatID
    } })
# IsActive and "does the file still exist" are the two facts that decide whether
# a Get-MpThreat entry is a live problem or a historical record. Defender keeps
# naming a threat long after the file behind it is gone, so without these every
# past detection reads as an ongoing compromise forever.
$o.threatNames = @(Get-MpThreat | Select-Object -First 40 |
  ForEach-Object {
    $res = @($_.Resources)
    $files = @($res | Where-Object { $_ -like 'file:_*' } |
                      ForEach-Object { $_.Substring(6) })
    [pscustomobject]@{
      name      = [string]$_.ThreatName
      severity  = [string]$_.SeverityID
      resources = [string]($res -join ' | ')
      active    = [bool]$_.IsActive
      # $null when the threat names no file at all (registry/memory detections),
      # which must not be mistaken for "the file is gone".
      onDisk    = if ($files.Count -eq 0) { $null }
                  else { [bool](@($files | Where-Object { Test-Path -LiteralPath $_ }).Count) }
    } })

# --- 4. Browser extensions -------------------------------------------------
$ext = New-Object System.Collections.ArrayList
$chromiumRoots = @(
  @{n='Chrome'; p="$env:LOCALAPPDATA\Google\Chrome\User Data"},
  @{n='Edge';   p="$env:LOCALAPPDATA\Microsoft\Edge\User Data"},
  @{n='Brave';  p="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"},
  @{n='Opera';  p="$env:APPDATA\Opera Software\Opera Stable"}
)
foreach ($b in $chromiumRoots) {
  if (-not (Test-Path $b.p)) { continue }
  Get-ChildItem "$($b.p)\*\Extensions\*\*\manifest.json" -ErrorAction SilentlyContinue |
    ForEach-Object {
      # -Encoding UTF8 matters: PowerShell 5.1 reads as ANSI by default and
      # mangles any non-ASCII character in an extension's name.
      $m = Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
      [void]$ext.Add([pscustomobject]@{
        browser = $b.n
        id      = $_.Directory.Parent.Name
        name    = [string]$m.name
        version = [string]$m.version
        perms   = [string](@($m.permissions) + @($m.host_permissions) -join ',')
        updateUrl = [string]$m.update_url
        location  = 'profile'
        installed = $_.LastWriteTime.ToString('o')
      }) }
}
# Firefox keeps its inventory in one JSON file per profile. Its `location` field
# separates add-ons *you* installed ("app-profile") from the ones Mozilla ships
# with the browser ("app-builtin", "app-system-defaults") -- the built-ins have
# no update URL by design, so without this they all look sideloaded.
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\*\extensions.json" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $j = Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    $j.addons | Where-Object { $_.type -eq 'extension' -and $_.active } | ForEach-Object {
      [void]$ext.Add([pscustomobject]@{
        browser='Firefox'; id=[string]$_.id
        name=[string]$_.defaultLocale.name; version=[string]$_.version
        perms=[string](@($_.userPermissions.permissions) + @($_.userPermissions.origins) -join ',')
        updateUrl=[string]$_.updateURL
        location=[string]$_.location
        signed=[string]$_.signedState
        installed=if($_.installDate){([DateTimeOffset]::FromUnixTimeMilliseconds($_.installDate)).ToString('o')}else{''}
      }) } }
$o.extensions = @($ext)

# --- 5. Recently written executables in staging directories ---------------
$cut = (Get-Date).AddDays(-14)
$o.recentExe = @(Get-ChildItem -File -ErrorAction SilentlyContinue -Path @(
    "$env:TEMP", "$env:USERPROFILE\Downloads", "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp", "$env:PUBLIC") -Recurse -Depth 2 -Include `
    *.exe,*.dll,*.scr,*.ps1,*.bat,*.cmd,*.vbs,*.hta,*.js,*.jar |
  Where-Object { $_.LastWriteTime -gt $cut -and
                 $_.FullName -notmatch '\\(Mozilla|Firefox|Google\\Chrome|Microsoft\\Edge)\\' -and
                 $_.Name -notmatch '^(prefs|user|handlers|search|extension-preferences)\.js$' } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 250 |
  ForEach-Object {
    $s = Get-AuthenticodeSignature -LiteralPath $_.FullName
    $h = Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName -ErrorAction SilentlyContinue
    [pscustomobject]@{ path=$_.FullName; size=$_.Length
                       written=$_.LastWriteTime.ToString('o')
                       sig=[string]$s.Status
                       signer=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''}
                       sha256=[string]$h.Hash } })

# --- 6. Who has the browser credential stores open ------------------------
$o.credAccess = @()
try {
  $stores = Get-ChildItem -File -ErrorAction SilentlyContinue -Path @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Login Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Login Data",
    "$env:APPDATA\Mozilla\Firefox\Profiles\*\logins.json") |
    ForEach-Object { [pscustomobject]@{ path=$_.FullName
                                        written=$_.LastWriteTime.ToString('o') } }
  $o.credAccess = @($stores)
} catch {}

# --- 7. BITS transfer jobs (T1197) --------------------------------------
# A queued BITS job survives reboots and logoffs and downloads with the
# System service's network identity, which is why droppers and C2 use it.
# -AllUsers needs elevation. Unelevated it throws Access Denied, and the
# original code caught that and left the list empty -- so an unelevated daemon
# reported no BITS jobs at all rather than reporting that it could not see them,
# which is the exact "a clean report and no report look identical" failure this
# codebase treats as worse than a finding. Fall back to this user's own jobs and
# say which view was obtained.
$o.bits = @()
$o.bitsScope = 'none'
function Get-BitsJobs($all) {
  $jobs = if ($all) { Get-BitsTransfer -AllUsers -ErrorAction Stop }
          else { Get-BitsTransfer -ErrorAction Stop }
  @($jobs | ForEach-Object {
    [pscustomobject]@{
      name  = [string]$_.DisplayName
      state = [string]$_.JobState
      owner = [string]$_.OwnerAccount
      url   = [string](@($_.FileList | ForEach-Object { $_.RemoteName }) -join ' ; ')
      local = [string](@($_.FileList | ForEach-Object { $_.LocalName }) -join ' ; ')
    } })
}
try {
  $o.bits = Get-BitsJobs $true
  $o.bitsScope = 'all'
} catch {
  try {
    $o.bits = Get-BitsJobs $false
    $o.bitsScope = 'user'
  } catch { $o.bitsScope = 'none' }
}

$json = [pscustomobject]$o | ConvertTo-Json -Depth 6 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""


# Extensions that ship with the browser or are installed by Windows itself.
STOCK_EXT = re.compile(r"^(Chrome Web Store Payments|Google Docs Offline|"
                       r"Microsoft Defender Browser Protection|"
                       r"Edge relevant text changes|Web Store|"
                       r"Chrome PDF Viewer|Firefox Screenshots)$", re.I)


def audit():
    data = ps_json(PS_INTRUSION, timeout=300)
    if data is None:
        return [_finding("clickfix", "medium", "intrusion audit unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    # -- 1. ClickFix ------------------------------------------------------
    runmru = aslist(data.get("runmru"))
    for r in runmru:
        cmd = (r.get("cmd") or "").rstrip("\\1")
        if not cmd:
            continue
        if PASTE_ATTACK.search(cmd):
            out.append(_finding(
                "clickfix", "critical",
                "a command was typed or pasted into the Win+R Run dialog",
                cmd[:150],
                "RunMRU — this is the artefact ClickFix leaves. If you did not "
                "type this yourself, treat the machine as compromised."))
        else:
            out.append(_finding("clickfix", "low", "Run dialog history",
                                cmd[:100], "RunMRU"))
    if not runmru:
        out.append(_finding("clickfix", "ok", "Run dialog history is empty",
                            "nothing has been typed into Win+R", "RunMRU"))

    # -- 2. PowerShell history --------------------------------------------
    out.extend(_history_findings(data))

    # -- 3. Defender's own findings ---------------------------------------
    # Grade on what is still true, not on the fact that Defender once said the
    # name. A threat Defender still calls active is critical; an inactive one
    # whose file is still sitting on disk is a live risk waiting to be run
    # again; an inactive one whose file is gone is history, and reporting it
    # forever trains you to ignore the category.
    for t in aslist(data.get("threatNames")):
        active, on_disk = t.get("active"), t.get("onDisk")
        if active:
            sev, note = "critical", "still active"
        elif on_disk:
            sev, note = "high", "not active, but the file is still on disk"
        elif on_disk is None:
            sev, note = "medium", "not active; names no file to verify"
        else:
            sev, note = "low", "not active, file no longer on disk — historical"
        out.append(_finding("av", sev, "Defender detected a threat",
                            f"{t.get('name')} — {note}",
                            (t.get("resources") or "")[:110] or "Get-MpThreat"))
    # Defender logs one detection per scan, so the same file appears repeatedly.
    # Collapse by resource and keep the worst outcome and latest time.
    detections = {}
    for d in aslist(data.get("threats")):
        key = (d.get("resources") or "")[:200]
        clean = str(d.get("action")).lower() == "true"
        e = detections.setdefault(key, {"n": 0, "clean": True, "last": ""})
        e["n"] += 1
        e["clean"] = e["clean"] and clean
        e["last"] = max(e["last"], d.get("time") or "")
    for res, e in sorted(detections.items(), key=lambda kv: kv[1]["last"],
                         reverse=True)[:10]:
        out.append(_finding(
            "av", "low" if e["clean"] else "critical",
            "Defender detection" + ("" if e["clean"] else " NOT remediated"),
            f"{res[:110]}" + (f"  (×{e['n']})" if e["n"] > 1 else ""),
            e["last"].replace("T", " ")[:19]))

    # -- 4. browser extensions --------------------------------------------
    exts = aslist(data.get("extensions"))
    for e in exts:
        name = e.get("name") or e.get("id") or "?"
        if name.startswith("__MSG_") or STOCK_EXT.match(name):
            continue
        # Browser-shipped add-ons are not "sideloaded" in any meaningful sense.
        location = (e.get("location") or "").lower()
        if location.startswith("app-") and location != "app-profile":
            continue
        # Mozilla ships several add-ons under its own IDs; they carry no update
        # URL because the browser updates them.
        if re.search(r"@mozilla\.(org|com)$", e.get("id") or "", re.I):
            continue
        perms = e.get("perms") or ""
        sideloaded = not (e.get("updateUrl") or "")
        broad = BROAD_PERMS.search(perms)
        if broad and sideloaded:
            sev, why = "critical", "broad permissions and no update URL (sideloaded)"
        elif sideloaded:
            sev, why = "high", "no update URL — installed outside the store"
        elif broad:
            sev, why = "low", "can read every page you visit"
        else:
            continue
        out.append(_finding("extension", sev, f"{e.get('browser')} extension",
                            f"{name} v{e.get('version')} — {why}",
                            f"{e.get('id')}  perms: {perms[:90]}"))
    out.append(_finding("extension", "ok", "browser extensions",
                        f"{len(exts)} installed across all browsers", ""))

    # -- 5. staged executables --------------------------------------------
    recent_code = aslist(data.get("recentExe"))[:250]
    for f in recent_code:
        path, sig = f.get("path") or "", f.get("sig") or ""
        in_temp = re.search(r"\\temp\\|\\public\\", path, re.I)
        if sig == "Valid":
            continue
        if in_temp or sig in ("HashMismatch", "NotTrusted"):
            sev = "high"
        else:
            sev = "low"
        out.append(_finding(
            "staging", sev, "recently written unsigned executable",
            f"{path.split(chr(92))[-1]} — {sig}, "
            f"{(f.get('written') or '').replace('T', ' ')[:19]}, "
            f"SHA-256 {(f.get('sha256') or 'unavailable')[:64]}", path))
    valid_code = sum(1 for f in recent_code if f.get("sig") == "Valid")
    out.append(_finding(
        "staging", "ok", "recent downloaded and staged software inventoried",
        f"{len(recent_code)} executable/script files checked from the last 14 "
        f"days; {valid_code} have a valid Authenticode signature; every "
        f"non-valid item is listed separately with its SHA-256",
        "Downloads, Temp, AppData and Public"))

    # -- 6. BITS transfer jobs (T1197) ----------------------------------
    bits = aslist(data.get("bits"))
    for j in bits:
        name = j.get("name") or "(unnamed)"
        url = j.get("url") or ""
        if _bits_is_vendor(name, url):
            continue
        http = re.search(r"https?://", url, re.I)
        suspended = (j.get("state") or "").lower() in ("suspended", "queued",
                                                       "transient_error")
        if http and suspended:
            sev, why = "high", ("a suspended job with an HTTP source is how a "
                                "dropper stages a download to run later")
        elif http:
            sev, why = "medium", "downloads over HTTP under the service identity"
        else:
            sev, why = "low", "a BITS job outside the known updaters"
        out.append(_finding(
            "staging", sev, f"BITS transfer job: {name}",
            f"{why} — state {j.get('state')}, owner {j.get('owner') or '?'}, "
            f"url {url[:120] or '—'}", "Get-BitsTransfer"))
    scope = str(data.get("bitsScope") or "none")
    if scope == "none":
        out.append(_finding(
            "staging", "medium", "BITS transfer jobs are not readable",
            "neither the all-users nor the per-user query returned — queued "
            "BITS jobs are a reboot-surviving download channel and none of "
            "them are visible from here, which is not the same as there being "
            "none", "Get-BitsTransfer"))
    elif bits and not any(f["title"].startswith("BITS") for f in out):
        out.append(_finding(
            "staging", "ok", "BITS jobs",
            f"{len(bits)} queued, all served by known updater hosts"
            + ("" if scope == "all" else
               " — this account's jobs only; -AllUsers needs elevation, so "
               "jobs owned by other users or by SYSTEM are not in this view"),
            "Get-BitsTransfer"))
    elif not bits and scope == "user":
        out.append(_finding(
            "staging", "low", "no BITS jobs for this account",
            "the all-users view needs elevation and was refused, so a job "
            "owned by SYSTEM or another user would not appear here",
            "Get-BitsTransfer"))

    return out
