"""Explain what ran at boot — specifically, windows that flash open and close.

A console window that appears for a fraction of a second and vanishes is a
process with a console attached that exited immediately: `cmd.exe /c ...`,
`wscript`, `cscript`, a `.bat` file, or PowerShell without `-WindowStyle Hidden`.
Interval sampling will never catch one reliably, so this module does not try.
It reconstructs the event after the fact from three records that persist:

  1. Task Scheduler's operational log, event 129, which names the task and the
     process it launched, with a timestamp
  2. the autostart inventory, filtered to entries that would *show a window* —
     these are the candidates, whether or not they ran this boot
  3. the Windows Error Reporting and Application logs, which catch the ones
     that flashed because they crashed

Cross-referencing 1 against 2 usually names the culprit outright.
"""

import re

from .control import _aslist, _ps_json

# Things that get a console window unless explicitly hidden.
CONSOLE_HOST = re.compile(
    r"\bcmd(\.exe)?\b|\bpowershell(\.exe)?\b|\bpwsh(\.exe)?\b|\bwscript(\.exe)?\b|"
    r"\bcscript(\.exe)?\b|\bmshta(\.exe)?\b|\bconhost(\.exe)?\b|"
    r"\.bat\b|\.cmd\b|\.vbs\b|\.js\b|\.ps1\b|\bcurl(\.exe)?\b|\brobocopy\b|\bschtasks\b",
    re.I,
)
HIDDEN_FLAG = re.compile(r"-w(indowstyle)?\s+hidden|/b\b|CreateNoWindow", re.I)

# Directories an unprivileged process can write to. Applied to the *executed
# image*, never to the whole command line: a path that appears as an argument is
# data the command reads or deletes, not code it runs.
USER_WRITABLE = re.compile(
    r"\\appdata\\|\\temp\\|\\users\\public\\|\\downloads\\|\\programdata\\|"
    r"\\windows\\tasks\\", re.I,
)

# `cmd.exe /c del ...` / `rmdir ...` and nothing else. An updater writes one of
# these to RunOnce so the old version is removed on the next logon, when the
# files are no longer locked. It runs once, deletes itself from the key, and
# cannot execute anything: `del` takes no code path. It still flashes a console,
# which is worth naming, but it is not a persistence mechanism.
DELETE_ONLY = re.compile(
    r"^\s*(\"[^\"]*cmd(\.exe)?\"|\S*cmd(\.exe)?)\s+(/\w+\s+)*(del|rmdir|rd)\b", re.I)

# Anything that lets one command become another. A `del` with a `&&` after it is
# not a deletion, it is a launcher, so the RunOnce downgrade must not apply.
CHAINING = re.compile(r"[&|<>^]")

# Extensions that make a path on a command line *code* rather than data.
CODE_PATH = re.compile(
    r"(?:\"([^\"]+?\.(?:exe|com|scr|dll|cmd|bat|ps1|vbs|vbe|js|jse|wsf|msi|hta))\"|"
    r"([^\s\"]+\.(?:exe|com|scr|dll|cmd|bat|ps1|vbs|vbe|js|jse|wsf|msi|hta)))\b", re.I)


def _code_paths(it):
    """Every path on the entry that will be executed, not merely referenced.

    The launched image plus any script it is handed. `cmd.exe /c foo.cmd` runs
    System32\\cmd.exe, but the thing that decides what happens is foo.cmd, so
    grading on the image alone would miss a script staged in AppData.
    """
    paths = []
    exe = it.get("exe") or ""
    if exe:
        paths.append(exe)
    for quoted, bare in CODE_PATH.findall(it.get("cmd") or ""):
        paths.append(quoted or bare)
    return paths


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": "win"}


PS_BOOT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$o.bootTime = $boot.ToString('o')

# --- what Task Scheduler launched since boot (129 = created task process) ---
$o.taskRuns = @(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=129,100,200;
        StartTime=$boot } -MaxEvents 200 |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      time = $_.TimeCreated.ToString('o')
      id   = $_.Id
      task = [string]$d['TaskName']
      path = [string]$d['Path']
      cmd  = [string]$d['ActionName']
    } })

# --- every autostart entry, with enough detail to tell if it shows a window ---
# The executed image is captured separately from the full command line. What an
# entry is allowed to run is decided by that image, not by any path that happens
# to appear later on the line -- `cmd.exe /c del "<appdata path>"` executes
# System32\cmd.exe and merely names a file to delete, which is a very different
# thing from launching something out of AppData.
$items = New-Object System.Collections.ArrayList
function Resolve-Exe([string]$cmd) {
  if (-not $cmd) { return '' }
  $c = $cmd.Trim()
  if ($c -match '^\s*"([^"]+)"') { $exe = $matches[1] }
  else { $exe = ($c -split '\s+')[0] }
  $exe = [Environment]::ExpandEnvironmentVariables($exe)
  if ($exe -and -not [IO.Path]::IsPathRooted($exe)) {
    $w = Get-Command $exe -CommandType Application -ErrorAction SilentlyContinue |
         Select-Object -First 1
    if ($w) { $exe = $w.Source }
  }
  return $exe
}
$sigCache = @{}
function Get-Sig([string]$exe) {
  if (-not $exe) { return 'unknown|' }
  if ($sigCache.ContainsKey($exe)) { return $sigCache[$exe] }
  $r = 'unknown|'
  if (Test-Path -LiteralPath $exe -PathType Leaf) {
    $s = Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction SilentlyContinue
    if ($s) {
      $subj = ''
      if ($s.SignerCertificate) {
        $subj = ($s.SignerCertificate.Subject -replace '^CN=', '') -replace ',.*$', ''
      }
      $r = "$($s.Status)|$subj"
    }
  } else { $r = 'missing|' }
  $sigCache[$exe] = $r
  return $r
}
foreach ($k in @(
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')) {
  $p = Get-ItemProperty -Path $k
  if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
    ForEach-Object { [void]$items.Add([pscustomobject]@{
      kind='run-key'; name=$_.Name; cmd=[string]$_.Value; where=$k
      exe=(Resolve-Exe ([string]$_.Value)) }) } }
}
Get-ChildItem -File -Path @(
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") |
  ForEach-Object { [void]$items.Add([pscustomobject]@{
    kind='startup-folder'; name=$_.Name; cmd=$_.FullName; where=$_.DirectoryName
    exe=$_.FullName }) }
Get-ScheduledTask | Where-Object {
    $_.State -ne 'Disabled' -and
    ($_.Triggers | Where-Object { $_.CimClass.CimClassName -match 'Boot|Logon' }) } |
  ForEach-Object {
    $t = $_
    $a = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
    $x = ($t.Actions | ForEach-Object { $_.Execute } | Where-Object { $_ } |
          Select-Object -First 1)
    [void]$items.Add([pscustomobject]@{
      kind='boot-task'; name=$t.TaskName; cmd=$a; where=$t.TaskPath
      exe=(Resolve-Exe ([string]$x)) }) }
foreach ($it in $items) {
  $parts = (Get-Sig ([string]$it.exe)) -split '\|', 2
  Add-Member -InputObject $it -NotePropertyName sig    -NotePropertyValue $parts[0]
  Add-Member -InputObject $it -NotePropertyName signer -NotePropertyValue $parts[1]
}
$o.autostart = @($items)

# --- things that crashed or errored around boot, another cause of a flash ---
$o.crashes = @(Get-WinEvent -FilterHashtable @{
        LogName='Application'; Level=1,2; StartTime=$boot } -MaxEvents 60 |
  ForEach-Object { [pscustomobject]@{
      time=$_.TimeCreated.ToString('o'); src=[string]$_.ProviderName
      msg=(($_.Message -replace "`r`n",' ') -replace '\s+',' ') } })

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""



def _flash_severity(it):
    """Grade a window-showing autostart entry by what it can execute.

    The question is not "does an AppData path appear on this line" — an updater
    naming its own old version directory for deletion trips that, and it is the
    single largest source of false HIGHs. The question is which paths the entry
    actually *runs*, and whether any of them is one an attacker could replace.
    """
    cmd = it.get("cmd") or ""
    sig = (it.get("sig") or "unknown").lower()
    where = (it.get("where") or "").lower()

    # A one-shot deletion queued by an installer: flashes, but runs no code.
    # Only when nothing on the line can chain a second command onto it.
    if "runonce" in where and DELETE_ONLY.search(cmd) and not CHAINING.search(cmd):
        return "low"

    # Something it executes sits where a non-admin can overwrite it. Whatever
    # that file is today, anything that can write there picks what runs next.
    if any(USER_WRITABLE.search(p) for p in _code_paths(it)):
        return "high"

    # A missing image is a pre-authorised slot: create that file and it runs.
    if sig == "missing":
        return "high"

    # Protected location, validly signed — a vendor component. It still shows a
    # window, which is the finding, but that is not a HIGH.
    if sig == "valid":
        return "low"

    return "medium"


def _flash_note(it):
    """One clause explaining why an entry is graded the way it is."""
    sig = (it.get("sig") or "unknown").lower()
    signer = it.get("signer") or ""
    where = (it.get("where") or "").lower()
    cmd = it.get("cmd") or ""

    if "runonce" in where and DELETE_ONLY.search(cmd) and not CHAINING.search(cmd):
        return "  [RunOnce deletion — runs once then removes itself; executes no code]"
    hot = [p for p in _code_paths(it) if USER_WRITABLE.search(p)]
    if hot:
        return f"  [executes from a user-writable path: {hot[0]}]"
    if sig == "missing":
        return "  [the launched image does not exist]"
    if sig == "valid" and signer:
        return f"  [signed: {signer}]"
    if sig == "notsigned":
        return "  [unsigned]"
    return ""


def audit():
    data = _ps_json(PS_BOOT, timeout=240)
    if data is None:
        return [_finding("boot", "medium", "startup analysis unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []
    boot = data.get("bootTime") or "?"
    out.append(_finding("boot", "ok", "last boot", boot.replace("T", " ")[:19], ""))

    # -- autostart entries that would visibly flash ------------------------
    flashers = []
    for it in _aslist(data.get("autostart")):
        cmd = it.get("cmd") or ""
        if CONSOLE_HOST.search(cmd) and not HIDDEN_FLAG.search(cmd):
            flashers.append(it)

    for it in flashers:
        cmd = it.get("cmd") or ""
        out.append(_finding(
            "flash", _flash_severity(it),
            f"autostart shows a console window ({it.get('kind')})",
            f"{it.get('name')} → {cmd[:110]}{_flash_note(it)}", it.get("where") or ""))

    if not flashers:
        out.append(_finding("flash", "ok", "no window-showing autostart entries",
                            "nothing in Run keys, the startup folder or boot-triggered "
                            "tasks launches a visible console host", ""))

    # -- what actually ran this boot ---------------------------------------
    runs = [r for r in _aslist(data.get("taskRuns")) if r.get("task")]
    seen = {}
    for r in runs:
        seen.setdefault(r.get("task"), r)
    for task, r in list(seen.items())[:40]:
        blob = f"{task} {r.get('cmd') or ''} {r.get('path') or ''}"
        ms = task.startswith("\\Microsoft\\")
        sev = "low" if ms else "medium"
        if CONSOLE_HOST.search(blob) and not ms:
            sev = "high"
        out.append(_finding("ran", sev, "task ran at boot",
                            f"{task}" + (f" → {r.get('path')}" if r.get("path") else ""),
                            (r.get("time") or "").replace("T", " ")[:19]))

    if not runs:
        out.append(_finding("ran", "medium", "task history unavailable",
                            "the Task Scheduler operational log is empty or not "
                            "readable — enable it in Task Scheduler → View → "
                            "Show All Tasks History to capture the next boot",
                            "Microsoft-Windows-TaskScheduler/Operational"))

    for c in _aslist(data.get("crashes"))[:15]:
        out.append(_finding("ran", "low", "error logged since boot",
                            f"{c.get('src')}: {(c.get('msg') or '')[:100]}",
                            (c.get("time") or "").replace("T", " ")[:19]))

    return out


CAT_ORDER = {"flash": 0, "ran": 1, "boot": 2}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def sort_findings(f):
    return sorted(f, key=lambda x: (CAT_ORDER.get(x["category"], 9),
                                    SEV_ORDER.get(x["severity"], 9), x["title"]))
