# Windows-side quickstart: the one layer that keeps JARVIS alive when WSL is not.
#
#   powershell -ExecutionPolicy Bypass -File .\quickstart.ps1
#       start the distro if needed, register the wake watchdog task (fires at
#       logon and every 5 min), and verify the dashboard answers
#
#   .\quickstart.ps1 -Distro Ubuntu -Port 8787     override the defaults
#   .\quickstart.ps1 -Remove                        unregister the wake task
#
# No elevation required. Firewall logging and browser hardening are a separate,
# elevated step: .\scripts\harden\secure-internet.ps1 -Firewall  /  -Browsers
[CmdletBinding()]
param(
    [string]$Distro = 'Ubuntu',
    [int]$Port = 8787,
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
function Say($m) { Write-Host "  $m" }

$wake = Join-Path $here 'wake-jarvis.ps1'
if (-not (Test-Path -LiteralPath $wake)) { throw "wake-jarvis.ps1 not found next to this script ($here)" }

if ($Remove) {
    $revive = Join-Path $here 'revive-jarvis.ps1'
    if (Test-Path -LiteralPath $revive) { & $revive -Remove }
    & $wake -Remove -Distro $Distro
    return
}

Write-Host "`n1/3  Distro" -ForegroundColor Cyan
$running = (& wsl.exe -l --running) -join ' '
if ($running -notmatch [regex]::Escape($Distro)) {
    Say "'$Distro' is not running - starting it"
    & wsl.exe -d $Distro --exec /bin/true | Out-Null
}
$active = (& wsl.exe -d $Distro --exec systemctl is-active jarvis.service 2>$null | Out-String).Trim()
Say "jarvis.service: $active"
if ($active -ne 'active') {
    Say "asking systemd to start it"
    & wsl.exe -d $Distro --exec bash -lc 'systemctl restart jarvis.service 2>/dev/null || sudo -n systemctl restart jarvis.service' | Out-Null
}

Write-Host "`n2/3  Wake watchdog (scheduled task)" -ForegroundColor Cyan
# -RepoRoot lets each run reconcile the staged copy against this checkout, so a
# later `git pull` reaches the task without re-installing.
$repoRoot = (& wsl.exe -d $Distro --exec wslpath -a $here 2>$null | Out-String).Trim()
if (-not $repoRoot) { $repoRoot = $here }
& $wake -Install -Distro $Distro -RepoRoot $repoRoot
# The instant reviver: checks every few seconds and revives what has stopped.
$revive = Join-Path $here 'revive-jarvis.ps1'
if (Test-Path -LiteralPath $revive) { & $revive -Install -Distro $Distro -RepoRoot $repoRoot }

Write-Host "`n3/3  Dashboard" -ForegroundColor Cyan
$ok = $false
foreach ($i in 1..20) {
    try {
        $null = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://127.0.0.1:$Port/api/state"
        $ok = $true; break
    } catch { Start-Sleep -Seconds 1 }
}
if ($ok) { Say "up: http://127.0.0.1:$Port" }
else     { Say "dashboard not answering on :$Port yet - check 'journalctl -u jarvis.service' inside WSL" }

Write-Host @"

  dashboard:  http://127.0.0.1:$Port   (open the "ops & setup" tab)
  hardening:  .\scripts\harden\secure-internet.ps1 -Firewall   (elevated)
              .\scripts\harden\secure-internet.ps1 -Browsers
  remove:     .\quickstart.ps1 -Remove
"@
