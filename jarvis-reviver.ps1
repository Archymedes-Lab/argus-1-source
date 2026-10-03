# Instant revival: the watchdog that checks every few seconds.
#
# jarvis-wake-watchdog.ps1 runs every five minutes and jarvis-health-monitor.ps1 every minute.
# Both are too slow to *fix* anything quickly, and the health monitor only tells you.
# This is one long-lived loop that asks JARVIS how it is every $Interval
# seconds and repairs the smallest thing that explains the answer:
#
#   * JARVIS answers but a required protection source is stale or unavailable
#       -> queue that collector now through /api/run. No restart: the daemon
#          is alive, and killing it would open a bigger gap than the one seen.
#   * JARVIS does not answer, or answers that its scheduler has stalled
#       -> distro stopped:        start it (systemd brings jarvis.service up)
#       -> unit not active:       restart jarvis.service
#       -> unit active but silent or stalled for $HungAfter seconds: restart it
#
# Every restart is budgeted: at least $RestartGap seconds apart and at most
# $RestartBudget in 15 minutes. Past that the loop stops acting, says so in its
# state file, and leaves the fault to a human and the health monitor's email. A
# reviver that restart-loops a sick daemon is an outage of its own.
#
#   .\jarvis-reviver.ps1                 run the loop (what the task does)
#   .\jarvis-reviver.ps1 -Once           one check, then exit
#   .\jarvis-reviver.ps1 -Once -DryRun   one check, log what it would do
#   .\jarvis-reviver.ps1 -Install        register the task and start it now
#   .\jarvis-reviver.ps1 -Remove         stop and unregister it
#
# Maintenance: while a file named "pause" exists next to the state file
# (%LOCALAPPDATA%\Jarvis\Reviver\pause), it keeps checking but repairs nothing,
# so a deliberate `systemctl stop jarvis` is not undone five seconds later.
# The file's first line may be a Unix time at which the pause ends by itself.

param(
    [switch]$Install,
    [switch]$Remove,
    [switch]$Once,
    [switch]$DryRun,
    [string]$Distro = 'Ubuntu',
    [string]$TaskName = 'jarvis reviver',
    [string]$RepoRoot = '',
    [string]$HealthUrl = 'http://127.0.0.1:8787/api/health',
    [int]$Interval = 5,
    [int]$HungAfter = 90,
    [int]$RestartGap = 60,
    [int]$RestartBudget = 3,
    [int]$MaxSeconds = 0,          # testing: leave the loop after this long
    [string]$StateRoot = (Join-Path $env:LOCALAPPDATA 'Jarvis\Reviver')
)

$ErrorActionPreference = 'Continue'
$self = $MyInvocation.MyCommand.Path
$log = Join-Path $StateRoot 'revive.log'
$statePath = Join-Path $StateRoot 'state.json'
$base = $HealthUrl -replace '/api/health$', ''

function Say($m) {
    $line = "{0} {1}{2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $(if ($DryRun) { '[dry-run] ' } else { '' }), $m
    Write-Host $line
    try {
        Add-Content -LiteralPath $log -Value $line
        if ((Get-Item -LiteralPath $log).Length -gt 1MB) {
            (Get-Content -LiteralPath $log -Tail 2000) | Set-Content -LiteralPath $log
        }
    } catch { }
}

function Save-State($s) {
    try {
        $tmp = $statePath + '.new'
        $s | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $statePath -Force
    } catch { }
}

function Now { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }

# --- install / remove --------------------------------------------------------
if ($Install -or $Remove) {
    [void](New-Item -ItemType Directory -Path $StateRoot -Force)
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if ($Remove) { Say "removed task '$TaskName'"; return }

    # Run from a local copy: a script on the \\wsl share is unreadable exactly
    # when WSL is down, which is when this has to run.
    $script = Join-Path $StateRoot 'jarvis-reviver.ps1'
    if ($self -ne $script) { Copy-Item -LiteralPath $self -Destination $script -Force }
    $argline = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
               $script + '" -Distro "' + $Distro + '"'
    if ($RepoRoot) { $argline += ' -RepoRoot "' + $RepoRoot + '"' }
    # conhost --headless: -WindowStyle Hidden alone still flashes a console window.
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\conhost.exe" `
        -Argument ('--headless "' + "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" + '" ' + $argline)
    # The loop is meant to run forever. The repeating trigger is its resurrection:
    # while it runs, IgnoreNew drops each trigger; if it has died, the next one
    # (at most five minutes away) starts it again.
    $triggers = @((New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME),
                  (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
                     -RepetitionInterval (New-TimeSpan -Minutes 5) `
                     -RepetitionDuration (New-TimeSpan -Days 3650)))
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
    # ExecutionTimeLimit of zero means no limit; a finite one would kill the loop.
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal `
        -Settings $settings -Description 'Checks JARVIS every few seconds and revives what has stopped' | Out-Null
    $check = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $check) { Say "FAILED to register task '$TaskName'"; exit 1 }
    Start-ScheduledTask -TaskName $TaskName
    Say "registered and started task '$TaskName' (checks every ${Interval}s)"
    return
}

# --- probes ------------------------------------------------------------------
function Get-Health {
    # Raw HttpWebRequest with the proxy off: the same reason as the health monitor --
    # Invoke-RestMethod can block past its timeout in a hidden task session.
    try {
        $req = [Net.HttpWebRequest]::Create($HealthUrl)
        $req.Proxy = $null; $req.Timeout = 4000; $req.ReadWriteTimeout = 4000; $req.KeepAlive = $false
        $resp = $req.GetResponse()
    } catch [Net.WebException] {
        $resp = $_.Exception.Response
        if (-not $resp) { return @{ answered = $false } }
    } catch { return @{ answered = $false } }
    try {
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        try { $h = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
    } catch { return @{ answered = $false } } finally { $resp.Dispose() }
    if ($h.service -ne 'JARVIS') { return @{ answered = $false } }
    return @{ answered = $true; live = ($h.live -eq $true); healthy = ($h.healthy -eq $true); body = $h }
}

function Invoke-Run([string]$job) {
    if ($DryRun) { return $true }
    try {
        $req = [Net.HttpWebRequest]::Create("$base/api/run?job=$([uri]::EscapeDataString($job))")
        $req.Proxy = $null; $req.Timeout = 4000; $req.Method = 'POST'; $req.ContentLength = 0
        $req.GetResponse().Dispose()
        return $true
    } catch { return $false }
}

# wsl.exe can hang when the VM is wedged, so every call into the distro runs
# with a wall-clock ceiling.
function Invoke-Wsl([string[]]$WslArgs, [int]$Seconds = 20) {
    $j = Start-Job -ScriptBlock {
        param($a)
        $prev = [Console]::OutputEncoding
        try { [Console]::OutputEncoding = [Text.Encoding]::Unicode; (& wsl.exe @a 2>$null) -join "`n" }
        finally { [Console]::OutputEncoding = $prev }
    } -ArgumentList (, $WslArgs)
    if (Wait-Job $j -Timeout $Seconds) {
        $out = Receive-Job $j; Remove-Job $j -Force -ErrorAction SilentlyContinue
        return @{ ok = $true; out = "$out" }
    }
    Stop-Job $j -ErrorAction SilentlyContinue; Remove-Job $j -Force -ErrorAction SilentlyContinue
    return @{ ok = $false; out = '' }
}

function Test-DistroRunning {
    $r = Invoke-Wsl @('-l', '--running') 15
    if (-not $r.ok) { return $null }
    return ($r.out -replace "`0", '') -match [regex]::Escape($Distro)
}

function Get-UnitState {
    # Not the UTF-16 listing: systemctl's own output is UTF-8, so read it plainly.
    $j = Start-Job -ScriptBlock { param($d) (& wsl.exe -d $d --exec systemctl is-active jarvis.service 2>$null) -join "`n" } -ArgumentList $Distro
    if (Wait-Job $j -Timeout 20) {
        $out = "$(Receive-Job $j)"; Remove-Job $j -Force -ErrorAction SilentlyContinue
        $lines = @(@($out -split "`n") | ForEach-Object { "$_".Trim() } | Where-Object { $_ -ne '' })
        if ($lines.Count -eq 0) { return '' }
        return ([string]$lines[-1]).ToLower()
    }
    Stop-Job $j -ErrorAction SilentlyContinue; Remove-Job $j -Force -ErrorAction SilentlyContinue
    return ''
}

# --- the loop ----------------------------------------------------------------
[void](New-Item -ItemType Directory -Path $StateRoot -Force)
$mutex = New-Object Threading.Mutex($false, 'Local\JarvisReviver')
if (-not $Once) {
    try { $owned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owned = $true }
    if (-not $owned) { return }   # another reviver is already watching
}

$st = @{ healthy = $null; firstFailure = 0; lastAction = ''; lastActionAt = 0; lastResult = '';
         restarts = @(); gaveUp = $false; kicked = @{}; gapSince = 0; startedAt = (Now); pid = $PID }
if (Test-Path -LiteralPath $statePath) {
    try {
        $old = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $st.restarts = @($old.restarts | Where-Object { $_ -gt (Now) - 900 })
    } catch { }
}
$lastSync = 0

function Act([string]$what, [scriptblock]$do) {
    $st.lastAction = $what; $st.lastActionAt = (Now)
    Say $what
    if (-not $DryRun) { & $do }
}

function Restart-Allowed {
    $now = Now
    $st.restarts = @($st.restarts | Where-Object { $_ -gt $now - 900 })
    if ($st.restarts.Count -ge $RestartBudget) {
        if (-not $st.gaveUp) {
            $st.gaveUp = $true
            Say "restart budget spent ($RestartBudget in 15 min) -- not restarting again; needs a human"
        }
        return $false
    }
    if ($st.restarts.Count -and $now - ($st.restarts | Measure-Object -Maximum).Maximum -lt $RestartGap) { return $false }
    return $true
}

function Restart-Jarvis([string]$why) {
    if (-not (Restart-Allowed)) { return }
    $st.restarts = @($st.restarts) + (Now)
    Act "restarting jarvis.service: $why" {
        [void](Invoke-Wsl @('-d', $Distro, '--exec', 'bash', '-lc',
            'systemctl restart jarvis.service 2>/dev/null || sudo -n systemctl restart jarvis.service') 45)
    }
}

function Test-Paused {
    $f = Join-Path $StateRoot 'pause'
    if (-not (Test-Path -LiteralPath $f)) { return $false }
    $until = 0
    try { $until = [long]((Get-Content -LiteralPath $f -TotalCount 1) -as [long]) } catch { }
    if ($until -and (Now) -ge $until) {
        Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue
        Say "maintenance pause expired -- reviving again"
        return $false
    }
    return $true
}

while ($true) {
    $now = Now
    $h = Get-Health
    $st.checkedAt = $now
    $paused = Test-Paused
    if ($paused -ne [bool]$st.paused) { Say $(if ($paused) { 'paused for maintenance -- checking only' } else { 'maintenance pause lifted' }) }
    $st.paused = $paused

    if ($h.answered -and $h.live) {
        if ($h.healthy) {
            if ($st.healthy -eq $false) {
                $down = $now - [long]$st.firstFailure
                Say "JARVIS healthy again after ${down}s$(if ($st.lastAction) { " (last action: $($st.lastAction))" })"
                $st.lastResult = "recovered after ${down}s"
            }
            $st.healthy = $true; $st.firstFailure = 0; $st.gaveUp = $false; $st.gapSince = 0
        } else {
            # Alive, but a required source is stale or blind: run it now.
            if ($st.healthy -ne $false) { $st.firstFailure = $now }
            $st.healthy = $false
            foreach ($p in $(if ($paused) { @() } else { $h.body.sources.PSObject.Properties })) {
                if ($p.Value.status -eq 'complete' -or $p.Name -eq 'storage') { continue }
                $last = [long]($st.kicked[$p.Name])
                if ($now - $last -lt 30) { continue }
                $st.kicked[$p.Name] = $now
                $ok = Invoke-Run $p.Name
                $st.lastAction = "queued $($p.Name) ($($p.Value.status): $($p.Value.reason))"
                $st.lastActionAt = $now
                Say "$($st.lastAction)$(if (-not $ok) { ' -- request failed' })"
            }
        }
    } else {
        if ($st.healthy -ne $false) { $st.firstFailure = $now; Say "JARVIS not answering$(if ($h.answered) { ' (scheduler stalled)' })" }
        $st.healthy = $false
        $age = $now - [long]$st.firstFailure
        $settling = ($now - [long]$st.lastActionAt) -lt 45   # give the last fix time to land
        if ($age -ge 10 -and -not $settling -and -not $st.gaveUp -and -not $paused) {
            $running = Test-DistroRunning
            if ($running -eq $false) {
                Act "distro '$Distro' is not running -- starting it" {
                    [void](Invoke-Wsl @('-d', $Distro, '--exec', '/bin/true') 60)
                }
            } elseif ($running) {
                $unit = Get-UnitState
                if ($unit -in @('activating', 'reloading', 'deactivating')) {
                    # systemd is already mid-restart; racing it helps nobody.
                } elseif ($unit -ne '' -and $unit -ne 'active') {
                    Restart-Jarvis "unit is '$unit'"
                } elseif ($unit -eq 'active' -and $age -ge $HungAfter) {
                    Restart-Jarvis "active but $(if ($h.answered) { 'stalled' } else { 'silent' }) for ${age}s"
                }
            }
        }
    }

    # Keep the deployed copy in step with the checkout, as the wake watchdog does.
    if ($RepoRoot -and -not $Once -and $now - $lastSync -ge 600) {
        $lastSync = $now
        try {
            $rel = ($RepoRoot -replace '/', '\').TrimEnd('\')
            $unc = "\\wsl.localhost\$Distro$rel\jarvis-reviver.ps1"
            $repoTxt = Get-Content -LiteralPath $unc -Raw -ErrorAction Stop
            $mine = Get-Content -LiteralPath $self -Raw -ErrorAction Stop
            $norm = { param($s) ($s -replace "`r`n", "`n").TrimEnd() }
            if ($repoTxt.Length -gt 2000 -and $repoTxt -match 'Instant revival' -and
                (& $norm $repoTxt) -ne (& $norm $mine)) {
                Set-Content -LiteralPath $self -Value $repoTxt -NoNewline -Encoding UTF8
                Say "updated from repo -- handing over to the new copy"
                Save-State $st
                $mutex.ReleaseMutex()
                Start-Process -FilePath "$env:SystemRoot\System32\conhost.exe" -ArgumentList (
                    '--headless "' + "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" +
                    '" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $self +
                    '" -Distro "' + $Distro + '" -RepoRoot "' + $RepoRoot + '"')
                return
            }
        } catch { }
    }

    Save-State $st
    if ($Once -or ($MaxSeconds -and $now - [long]$st.startedAt -ge $MaxSeconds)) { return }
    Start-Sleep -Seconds $Interval
}
