# Who is watching the mouse and keyboard? Elevated broker job.
#
# Windows records, in the Microsoft-Windows-Win32k provider's AuditApiCalls
# keyword (0x400), each call that registers an input watcher:
#   1002  SetWindowsHookEx         FilterType 13 keyboard-LL, 14 mouse-LL, ...
#   1001  RegisterRawInputDevices  UsagePage/Usage/Flags (0x100 = background sink)
#   1000  SetWinEventHook          focus and window-event watchers
#   1003  GetAsyncKeyState         written at a key event for a process that
#         polled at >= 1 call/ms since the previous key event (kernel gate);
#         fields PID, MsSinceLastKeyEvent, BackgroundCallCount
# Measured on this machine (build 26200): 1002 and 1001 fire under 0x400 and
# name the calling process (2026-09-23). 1003 fires only when keyword 0x1000
# is enabled as well (2026-10-21: 0x400 alone and 0x1000 alone gave none at
# 14 calls/ms; 0x1400 gave 102 in 45 s, all attributed by EventData.PID).
#
# A registration is logged once, when it happens, so this job keeps a trace
# session running between broker runs ("JarvisInputAudit", real-time to a file
# in this admin-only folder). It is the broker's one stateful job: it starts
# JARVIS's own ETW session and keeps an inventory here, and changes no system
# setting. The session does not survive a reboot, so anything that registered
# between boot and the first run after it is unseen; that gap is reported.
#
# Each run: stop the session (flushing its file), start a fresh one, parse the
# old file, merge it into the inventory, drop watchers whose process has
# exited (after reporting them once), and print the inventory as base64 JSON. It keeps process ids, image
# paths, signer status, hook types and counts. Never key codes, window titles
# or command lines.

$ErrorActionPreference = 'Stop'
$Name = 'JarvisInputAudit'
$Dir = Join-Path $env:ProgramData 'Jarvis\Broker\inputaudit'
$Etl = Join-Path $Dir 'session.etl'
$Old = Join-Path $Dir 'session.prev.etl'
$Inv = Join-Path $Dir 'inventory.json'
$MaxRows = 400
$Keyword = '0x1400'
$CapMB = 128          # about 52 MB per 15 min was measured; logging stops at the cap, which the output reports
$WantIds = "*[System[(EventID=1000 or EventID=1001 or EventID=1002 or EventID=1003)]]"
New-Item -ItemType Directory -Force $Dir | Out-Null

function Unix([datetime]$t) { [DateTimeOffset]::new($t.ToUniversalTime()).ToUnixTimeSeconds() }
function Running { & logman.exe query $Name -ets *> $null; return $LASTEXITCODE -eq 0 }
function Start-Session {
    # 0x1400: AuditApiCalls (0x400) plus the 0x1000 bit that 1003 (key-state
    # polling) is gated on. Measured 2026-10-21: 0x400 alone and 0x1000 alone
    # each gave no 1003 at 14 calls/ms; together, 102 events in 45 s, all
    # attributed. 0x1000 adds about 450 other Win32k events a second, so the
    # file is capped and parsed with an event-id filter (0.8 s for 20k events
    # against 23 s unfiltered).
    & logman.exe start $Name -p Microsoft-Windows-Win32k $Keyword 0x5 -o $Etl -bs 64 -nb 4 16 -max $CapMB -ets | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "logman start failed ($LASTEXITCODE)" }
}

$boot = Unix (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$state = $null
if (Test-Path $Inv) { try { $state = Get-Content $Inv -Raw | ConvertFrom-Json } catch { $state = $null } }
if (-not $state -or [int64]$state.boot -ne $boot) {
    # A new boot: every process in the old inventory is gone.
    $state = [pscustomobject]@{ boot = $boot; session_started = 0; runs = 0; rows = @() }
}

$gapMs = $null
$fresh = $false
if (Running) {
    $t0 = Get-Date
    & logman.exe stop $Name -ets | Out-Null
    Remove-Item $Old -ErrorAction SilentlyContinue
    if (Test-Path $Etl) { Move-Item $Etl $Old }
    Start-Session
    $gapMs = [int]((Get-Date) - $t0).TotalMilliseconds
} else {
    Remove-Item $Etl -ErrorAction SilentlyContinue
    Start-Session
    $fresh = $true
    if (-not [int64]$state.session_started) { $state.session_started = Unix (Get-Date) }
}

# --- identify a process as it was when it registered ----------------------
$procCache = @{}
function Identify([int]$procId, [datetime]$when) {
    $key = "$procId|$(Unix $when)"
    if ($procCache.ContainsKey($key)) { return $procCache[$key] }
    $id = [ordered]@{ path = ''; start = 0; via = 'unresolved' }
    $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
    # A live process with this id that started after the event is a reuse
    # of the id, not the registrant.
    if ($p -and $p.StartTime -le $when.AddSeconds(1)) {
        $id.path = [string]$p.Path; $id.start = Unix $p.StartTime; $id.via = 'live'
    } else {
        try {
            $xp = "*[System[EventID=1]] and *[EventData[Data[@Name='ProcessId']='$procId']]"
            foreach ($e in (Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath $xp -MaxEvents 8 -ErrorAction Stop)) {
                if ($e.TimeCreated -le $when.AddSeconds(1)) {
                    $x = [xml]$e.ToXml()
                    $img = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' }).'#text'
                    $id.path = [string]$img; $id.start = Unix $e.TimeCreated; $id.via = 'sysmon'
                    break
                }
            }
        } catch { }
    }
    $procCache[$key] = $id
    return $id
}

$sigCache = @{}
function Signer([string]$path) {
    if (-not $path) { return @{ status = 'unknown'; signer = '' } }
    if (-not $sigCache.ContainsKey($path)) {
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $path
            $cn = if ($s.SignerCertificate) { ($s.SignerCertificate.Subject -replace '^.*?CN=("?)([^,"]+)\1.*$', '$2') } else { '' }
            $sigCache[$path] = @{ status = [string]$s.Status; signer = $cn }
        } catch { $sigCache[$path] = @{ status = 'unreadable'; signer = '' } }
    }
    return $sigCache[$path]
}

function Signed32([string]$v) {
    $n = [int64]0
    if (-not [int64]::TryParse($v, [ref]$n)) { return $null }
    if ($n -gt 2147483647) { $n -= 4294967296 }
    return [int]$n
}

# --- parse the closed session file -----------------------------------------
$rows = @{}
foreach ($r in @($state.rows)) { if ($r) { $rows[[string]$r.key] = $r } }
$parsed = 0; $failed = 0; $seen1003 = 0
$touched = @{}
$etlBytes = 0; $capped = $false
if (Test-Path $Old) {
    $etlBytes = (Get-Item $Old).Length
    $capped = $etlBytes -ge ($CapMB * 1MB)
    $events = @()
    try { $events = @(Get-WinEvent -Path $Old -Oldest -FilterXPath $WantIds -ErrorAction Stop) } catch {
        if ($_.Exception.Message -notmatch 'No events') { $failed++ } }
    foreach ($e in $events) {
        try {
            $parsed++
            $d = @{}
            foreach ($f in @(([xml]$e.ToXml()).Event.EventData.Data)) { if ($f) { $d[[string]$f.Name] = [string]$f.'#text' } }
            $kind = $null; $type = ''; $extra = @{}
            $procId = [int]$e.ProcessId
            switch ($e.Id) {
                1002 {
                    $kind = 'hook'; $type = [string](Signed32 $d['FilterType'])
                    $extra.lib = [string]$d['pstrLib']
                    if ($d['ReturnValue'] -eq '0') { $extra.failed = $true }
                }
                1001 {
                    $kind = 'rawinput'
                    $flags = Signed32 $d['Flags']
                    $type = "$($d['UsagePage'])/$($d['Usage'])/$flags"
                    $extra.visible_windows = Signed32 $d['cVisWindows']
                }
                1000 { $kind = 'winevent'; $type = 'any' }
                1003 {
                    # Written by the kernel at a key event, for a process that called
                    # the key-state API at >= 1 call/ms since the previous key event.
                    # The polling process is EventData.PID, not the header pid.
                    $seen1003++; $kind = 'poll'; $type = 'getasynckeystate'
                    if ($d['PID']) { $procId = [int]$d['PID'] }
                    $extra.calls = Signed32 $d['BackgroundCallCount']
                    $extra.ms = Signed32 $d['MsSinceLastKeyEvent']
                }
            }
            if (-not $kind) { continue }
            $who = Identify $procId $e.TimeCreated
            $key = "$kind|$type|$($who.path.ToLower())|$procId|$($who.start)"
            $t = Unix $e.TimeCreated
            $touched[$key] = $true
            if ($rows.ContainsKey($key)) {
                $row = $rows[$key]
                $row.count = [int]$row.count + 1
                $row.last = $t
                if ($null -ne $extra.calls -and $extra.calls -gt [int]$row.calls) { $row.calls = $extra.calls; $row.ms = $extra.ms }
            } else {
                if ($rows.Count -ge $MaxRows) { continue }
                $sig = Signer $who.path
                $row = [pscustomobject]@{
                    key = $key; kind = $kind; type = $type; pid = $procId
                    start = $who.start; path = $who.path; via = $who.via
                    sig = $sig.status; signer = $sig.signer
                    first = $t; last = $t; count = 1
                    lib = [string]$extra.lib; failed = [bool]$extra.failed
                    visible_windows = $extra.visible_windows
                    calls = $extra.calls; ms = $extra.ms }
                $rows[$key] = $row
            }
        } catch { $failed++ }
    }
    Remove-Item $Old -ErrorAction SilentlyContinue
}

# --- keep only watchers whose process is still the same process -----------
$alive = @{}
foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
    try { $alive[[int]$p.Id] = Unix $p.StartTime } catch { $alive[[int]$p.Id] = -1 }
}
$kept = @(); $ended = 0
$unresolved = @(); $gone = @()
foreach ($row in $rows.Values) {
    if (-not [int64]$row.start) {
        # Never identified, so a later process reusing the id cannot be told
        # apart from it: report it in the run that saw it, never carry it.
        if ($touched.ContainsKey($row.key)) { $unresolved += $row }
        continue
    }
    $s = $alive[[int]$row.pid]
    $same = ($null -ne $s) -and (($s -eq -1) -or ([math]::Abs($s - [int64]$row.start) -le 2))
    if ($same) { $kept += $row } else {
        $ended++
        # Seen this run but already gone: a watcher that ran briefly between
        # two runs must still be reported once, or it would never be seen.
        if ($touched.ContainsKey($row.key)) {
            $row | Add-Member -NotePropertyName exited -NotePropertyValue $true -Force
            $gone += $row
        }
    }
}

$state.rows = $kept
$state.runs = [int]$state.runs + 1
$state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$Inv.new" -Encoding UTF8
Move-Item -LiteralPath "$Inv.new" -Destination $Inv -Force

$o = [ordered]@{
    version = 1; boot = $boot; session_started = [int64]$state.session_started
    fresh_session = $fresh; rotate_gap_ms = $gapMs; runs = $state.runs
    parsed = $parsed; parse_failures = $failed; polling_events = $seen1003
    keyword = $Keyword; polling_logged = ($Keyword -eq '0x1400')
    etl_bytes = $etlBytes; etl_capped = $capped
    ended = $ended
    watchers = @(@($kept) + @($unresolved) + @($gone) | Where-Object { $_ })
    winevent_watchers = @($kept | Where-Object { $_.kind -eq 'winevent' }).Count
}
$json = $o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
