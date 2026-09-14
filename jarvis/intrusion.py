"""Artifacts of how machines actually get compromised right now.

The other modules look for things that are *running* or *installed*. This one
looks for evidence of the initial access itself, because current intrusions are
increasingly things that happen once and leave no persistent process behind:

  ClickFix          A fake CAPTCHA page copies a command to the clipboard and
                    tells you to press Win+R and paste it. It is reportedly the
                    single largest initial-access technique in circulation, and
                    it leaves a perfect fingerprint: Windows records everything
                    typed into the Run dialog in the RunMRU registry key.

  Infostealers      Modern stealers run once, harvest browser cookies, session
                    tokens and saved passwords, and exit. Behavioural rules that
                    watch for persistence miss them entirely, because there is
                    no persistence. What they leave behind is access to the
                    browser credential stores and, often, a malicious extension.

  Session theft     Stolen cookies and OAuth tokens are replayed directly, so
                    the password and the second factor never come into it. A
                    browser extension with broad host permissions is one of the
                    cheapest ways to keep harvesting them.

It also reads Defender's own detection history, which is the cheapest possible
question to ask and the one most often skipped: has the antivirus already found
something and been ignored?
"""

import re
from urllib.parse import urlsplit

from .collect_windows import aslist, ps_json

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


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": "win"}


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

# BITS job names Windows Update and vendor updaters use.
_BITS_BENIGN = re.compile(
    r"windows ?update|wuauclt|delivery optimization|msedge|edgeupdate|"
    r"google update|gupdate|dropbox|onedrive|office|teams|adobe|mozilla",
    re.I)

# Hosts those updaters actually fetch from. The name alone is not enough in
# either direction, and matching it against the whole URL was worse than
# useless: `https://evil.example/?ref=onedrive` contains "onedrive" and was
# therefore exempt, while OneDrive's own real job — DisplayName
# `PreSignInSettingsConfigJSON`, url `https://g.live.com/odclientsettings/ProdV2`
# — contains none of these words anywhere and was reported HIGH. So the host is
# what gets matched, parsed out of the URL rather than searched for inside it: a
# dropper can name its job anything, but it still has to serve the payload from
# somewhere, and that somewhere is never one of these.
_BITS_VENDOR_HOST = re.compile(
    r"(^|\.)("
    r"(g|go|api)\.live\.com|"
    r"(officecdn|officeclient|download|update|dl\.delivery\.mp|"
    r"[a-z0-9-]*\.?windowsupdate|au\.download\.windowsupdate)\.microsoft\.com|"
    r"[a-z0-9-]+\.windowsupdate\.com|"
    r"[a-z0-9-]*\.?dl\.delivery\.mp\.microsoft\.com|"
    r"onedrive\.live\.com|oneclient\.sfx\.ms|"
    r"dl\.google\.com|update\.googleapis\.com|"
    r"download\.mozilla\.org|[a-z0-9-]+\.cdn\.mozilla\.net|"
    r"ardownload[0-9]*\.adobe\.com|"
    r"client-update\.dropbox\.com|edgedl\.me\.gvt1\.com"
    r")$", re.I)


def _bits_hosts(url):
    """Every host named in a BITS job's file list, lowercased."""
    return [m.group(1).lower()
            for m in re.finditer(r"https?://([^/\s;:]+)", url or "", re.I)]


def _bits_is_vendor(name, url):
    """True when this job is a known updater doing its normal work.

    Requires the *hosts* to check out whenever there are any. A job with no URL
    at all falls back to the name, because there is then nothing to fetch and
    nothing to stage.
    """
    hosts = _bits_hosts(url)
    if hosts:
        return all(_BITS_VENDOR_HOST.search(h) for h in hosts)
    return bool(_BITS_BENIGN.search(name or ""))

SUSPICIOUS_HISTORY = re.compile(
    r"\b(irm|invoke-restmethod|iwr|invoke-webrequest|curl|wget)\b[^|;\n]*\|\s*(iex|invoke-expression)\b|"
    r"frombase64string|-enc(odedcommand)?\s+[A-Za-z0-9+/=]{30,}|"
    r"downloadstring|downloadfile|"
    r"set-mppreference\s+-disable|add-mppreference\s+-exclusionpath|"
    r"disable-windowsoptionalfeature|"
    r"new-object\s+system\.net\.webclient|"
    r"bypass\s+-\w*\s*(file|command)|start-process\s+-verb\s+runas",
    re.I,
)

# Exact hostname matching: the missing-d MAS lookalike has a documented
# malware-download record (https://urlhaus.abuse.ch/url/3740911/).
# A history entry records a command, not successful payload execution.
HISTORY_MALWARE_HOSTS = frozenset({"get.activate.win"})


def _history_malware_hosts(line):
    hosts = set()
    for url in re.findall(r"https?://[^\s\"'`<>|)]+", line, re.I):
        try:
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if host in HISTORY_MALWARE_HOSTS:
            hosts.add(host)
    return hosts

# Download-and-execute is also how half of developer tooling installs itself, so
# shape alone cannot separate `iex (irm chocolatey.org/install.ps1)` from a
# ClickFix payload. What does separate them is where the code comes from: an
# HTTPS URL on a known vendor's own domain. A lure has to host its payload
# somewhere, and it is never here.
VENDOR_INSTALL = re.compile(
    r"https://([a-z0-9-]+\.)*("
    r"chocolatey\.org|community\.chocolatey\.org|"
    r"astral\.sh|ollama\.com|rustup\.rs|sh\.rustup\.rs|"
    r"get\.scoop\.sh|scoop\.sh|nodejs\.org|python\.org|"
    r"aka\.ms|microsoft\.com|windows\.net|"
    r"githubusercontent\.com/(docker|nvm-sh|Homebrew|oven-sh|pyenv)/|"
    r"deb\.nodesource\.com|get\.docker\.com|starship\.rs|deno\.land|bun\.sh"
    r")/",
    re.I,
)

# A vendor domain only excuses the URL. If the same line also turns off a
# defence or hides itself, the origin is beside the point.
NEVER_BENIGN = re.compile(
    r"set-mppreference\s+-disable|add-mppreference\s+-exclusionpath|"
    r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{30,}|frombase64string|"
    r"-w(indowstyle)?\s+hidden|disable-windowsoptionalfeature",
    re.I,
)


def _history_severity(line: str) -> str:
    if _history_malware_hosts(line):
        return "critical"
    if NEVER_BENIGN.search(line):
        return "high"
    if VENDOR_INSTALL.search(line):
        return "low"
    return "high"


def _history_findings(data):
    hist = aslist(data.get("psHistory"))
    out = []
    for h in hist:
        if not isinstance(h, str) or not SUSPICIOUS_HISTORY.search(h):
            continue
        hosts = _history_malware_hosts(h)
        sev = _history_severity(h)
        if hosts:
            title = "PowerShell history references a known malware host: " + ", ".join(sorted(hosts))
            detail = h[:300] + " — recorded command; successful download/execution is not established"
        else:
            title = ("download-and-execute from a known vendor domain"
                     if sev == "low" else "suspicious PowerShell command in history")
            detail = h[:150]
        out.append(_finding("clickfix", sev, title, detail,
                            data.get("psHistoryPath", "")))
    # Inspect every collected line before presenting results; old high/critical
    # commands must not disappear behind a list of benign installer entries.
    if hist and not out:
        out.append(_finding("clickfix", "ok", "PowerShell history clean",
                            f"{len(hist)} recent commands, none matching known "
                            "download-and-execute or defence-tampering shapes", ""))
    return out


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


CAT_ORDER = {"av": 0, "clickfix": 1, "extension": 2, "staging": 3}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def sort_findings(f):
    return sorted(f, key=lambda x: (CAT_ORDER.get(x["category"], 9),
                                    SEV_ORDER.get(x["severity"], 9), x["title"]))
