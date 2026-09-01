# The outermost watchdog: the one that runs when WSL is not.
#
# Everything else that keeps sentry alive lives *inside* the distro --
# systemd's Restart=always, the sd_notify watchdog, sentry-selfcheck.timer.
# All of it is gone the moment the WSL utility VM stops, and nothing inside a
# stopped VM can start it again. The existing "WSL sentry 24x7" task only fires
# AtLogOn, so a mid-session `wsl --shutdown`, an idle teardown or a VM crash
# leaves the machine unmonitored until the next Windows login.
#
# This script closes that. Registered as a scheduled task repeating every five
# minutes, it:
#   1. starts the distro if it is not running,
#   2. restarts sentry.service if the distro is up but the unit is not,
#   3. writes one line per run so a repeating failure is visible afterwards.
#
# It is deliberately dumb and side-effect-light. It does not parse findings or
# send mail -- sentry does that better from the inside, and a watchdog that can
# itself fail in interesting ways is not a watchdog.
#
#   .\wake-sentry.ps1            one check now
#   .\wake-sentry.ps1 -Install   register the repeating task (no elevation)
#   .\wake-sentry.ps1 -Remove    unregister it

param(
    [switch]$Install,
    [switch]$Remove,
    [string]$Distro = 'Ubuntu',
    [string]$TaskName = 'sentry wake watchdog'
)

$ErrorActionPreference = 'Continue'
$logDir = Join-Path $env:LOCALAPPDATA 'WSLKeepalive'
$log    = Join-Path $logDir 'sentry-wake.log'
$self   = $MyInvocation.MyCommand.Path

function Say($m) {
    $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
    Write-Host $line
    try {
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        Add-Content -Path $log -Value $line
        # Keep the log from growing without bound; this runs every 5 minutes.
        if ((Get-Item $log).Length -gt 1MB) {
            (Get-Content $log -Tail 2000) | Set-Content $log
        }
    } catch { }
}

# --- install / remove ------------------------------------------------------
if ($Install -or $Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if ($Remove) { Say "removed task '$TaskName'"; return }

    # RunLevel Limited is load-bearing: asking for Highest makes registration
    # itself require an elevated shell and fails with 0x80070005. Starting WSL
    # and restarting a unit inside it need no admin rights.
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass ' +
        '-File "' + $self + '" -Distro "' + $Distro + '"')

    # Two triggers: at logon, and every five minutes forever afterwards.
    $atLogon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    # RepetitionDuration wants a finite, in-range value. Both idioms for
    # "forever" are rejected by Task Scheduler with 0x80041318: MaxValue
    # serialises to P99999999DT23H59M59S and Zero to PT0S, and this build
    # accepts neither. Ten years is finite, valid, and long enough that the
    # distinction stops mattering.
    $repeat  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
                 -RepetitionInterval (New-TimeSpan -Minutes 5) `
                 -RepetitionDuration (New-TimeSpan -Days 3650)

    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME `
                   -LogonType Interactive -RunLevel Limited
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                   -DontStopIfGoingOnBatteries -StartWhenAvailable `
                   -MultipleInstances IgnoreNew `
                   -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

    Register-ScheduledTask -TaskName $TaskName -Action $action `
        -Trigger @($atLogon, $repeat) -Principal $principal -Settings $settings `
        -Description 'Starts WSL and sentry.service if either has stopped' | Out-Null

    # Verify rather than assume. $ErrorActionPreference is Continue, so a failed
    # registration would otherwise be followed by a cheerful success message --
    # and a watchdog you believe is installed but is not is worse than none.
    $check = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $check) {
        Say "FAILED to register task '$TaskName'"
        exit 1
    }
    Say "registered task '$TaskName' [$($check.State)] (at logon + every 5 min)"
    return
}

# --- one check -------------------------------------------------------------
# `wsl -l --running` is the cheap way to ask whether the VM is up. It does not
# start the distro as a side effect, which matters: a probe that starts what it
# is measuring can never report a problem.
#
# wsl.exe writes its listing as UTF-16LE. Read with the default console
# encoding it comes back as "U b u n t u" -- every character separated by the
# decoded NUL half of each code unit -- so a plain -match on the distro name
# silently never matches. That failure mode is worse than useless here: the
# watchdog would conclude WSL was down on every single run, try to start an
# already-running distro forever, and never reach the sentry.service check
# below. Force the encoding for the call and restore it afterwards.
function Get-RunningDistros {
    $prev = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        return ((& wsl.exe -l --running) -join ' ')
    } finally {
        [Console]::OutputEncoding = $prev
    }
}

$running = Get-RunningDistros
if ($running -notmatch [regex]::Escape($Distro)) {
    Say "distro '$Distro' is NOT running -- starting it"
    & wsl.exe -d $Distro --exec /bin/true 2>&1 | Out-Null
    Start-Sleep -Seconds 10
    $running = Get-RunningDistros
    if ($running -notmatch [regex]::Escape($Distro)) {
        Say "FAILED to start '$Distro'"
        exit 1
    }
    Say "'$Distro' started; systemd will bring sentry.service up"
}

# The distro is up. Is the unit?
$state = (& wsl.exe -d $Distro --exec systemctl is-active sentry.service 2>&1) -join ''
$state = $state.Trim()
if ($state -eq 'active') {
    exit 0
}

Say "sentry.service is '$state' -- restarting"
& wsl.exe -d $Distro --exec bash -lc 'systemctl restart sentry.service 2>/dev/null || sudo -n systemctl restart sentry.service' 2>&1 | Out-Null
Start-Sleep -Seconds 5
$state2 = ((& wsl.exe -d $Distro --exec systemctl is-active sentry.service 2>&1) -join '').Trim()
if ($state2 -eq 'active') { Say "sentry.service is active again" }
else { Say "sentry.service still '$state2' after restart -- needs a human"; exit 1 }
