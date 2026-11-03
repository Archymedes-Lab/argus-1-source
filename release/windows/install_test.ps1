# Install, run, observe and remove the Windows edition on a clean Windows host
# (the windows-2025 runner: no WSL distribution, no previous install).
#
#   powershell -File release/windows/install_test.ps1 -Setup <ARGUS-INSTINCT-Setup-windows-x64.exe>
#
# Every check prints PASS or FAIL; the script exits 1 on any FAIL. What it shows:
#   1. the Setup installs per user and exits 0 only once the service answers;
#   2. the service is the registered per-user task, healthy and live;
#   3. the engine adapts to this host: the Linux-only checks are listed as not
#      applicable here, never as failing or healthy;
#   4. a positive control: a harmless autostart entry planted in the current
#      user's Run key is found by the compiled startup audit, and is gone from
#      it once removed (absent before, present while planted, absent after);
#   5. the uninstaller removes the task, the program, the uninstall entry and
#      the desktop app's token; the user's history is kept and reported.

param([Parameter(Mandatory = $true)][string]$Setup)

$ErrorActionPreference = 'Stop'
$script:failed = 0
function Check([bool]$ok, [string]$what) {
    if ($ok) { Write-Host "PASS  $what" } else { Write-Host "FAIL  $what"; $script:failed++ }
}

$product = 'ARGUS-INSTINCT'
$install = Join-Path $env:LOCALAPPDATA "Programs\$product"
$engine = Join-Path $install 'engine\argus-instinct.exe'
$task = 'argus native service'
$uninstKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$product"
$appDir = Join-Path $env:APPDATA 'local.argus.desktop'
$probeName = 'ArgusInstallProbe'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

function Health([int]$port) {
    try {
        $req = [Net.HttpWebRequest]::Create("http://127.0.0.1:$port/api/health")
        $req.Proxy = $null; $req.Timeout = 5000
        try { $resp = $req.GetResponse() } catch [Net.WebException] { $resp = $_.Exception.Response }
        if (-not $resp) { return $null }
        $r = New-Object IO.StreamReader($resp.GetResponseStream())
        try { return ($r.ReadToEnd() | ConvertFrom-Json) } finally { $r.Dispose(); $resp.Dispose() }
    } catch { return $null }
}

function Boot-Findings {
    $out = & $engine boot --json 2>$null | Out-String
    $start = $out.IndexOf('[')
    if ($start -lt 0) { return @() }
    try { return @($out.Substring($start) | ConvertFrom-Json) } catch { return @() }
}

function Probe-Seen {
    return [bool](@(Boot-Findings | Where-Object { "$($_.detail)" -like "*$probeName*" }).Count)
}

Write-Host "== host"
$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
$distros = if ($wsl) { (& wsl.exe --list --quiet 2>$null | Out-String).Trim() } else { '' }
Write-Host "Windows $([Environment]::OSVersion.Version); WSL distributions: $(if ($distros) { $distros } else { 'none' })"
Check (-not (Test-Path -LiteralPath $install)) 'no previous install'

Write-Host "== install (silent)"
$p = Start-Process -FilePath $Setup -ArgumentList '/S' -Wait -PassThru
Check ($p.ExitCode -eq 0) "Setup /S exit code 0 (was $($p.ExitCode))"
Check (Test-Path -LiteralPath $engine) 'engine installed per user'
Check (Test-Path -LiteralPath (Join-Path $install 'argus-desktop.exe')) 'desktop app installed'
Check (Test-Path -LiteralPath $uninstKey) 'uninstall entry for the current user'
# -Include is ignored with -LiteralPath: filter on the extension itself.
$scripts = @(Get-ChildItem -LiteralPath $install -Recurse -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Extension -in '.py', '.pyc', '.ps1', '.cs' })
Check ($scripts.Count -eq 0) "no source or script files in the program folder ($($scripts.Count))"
$scripts | Select-Object -First 10 | ForEach-Object { Write-Host "      $($_.FullName)" }
$lnk = Join-Path ([Environment]::GetFolderPath('Programs')) "$product.lnk"
Check (Test-Path -LiteralPath $lnk) 'Start menu entry'

$setupLog = Join-Path $install 'install.log'
if (Test-Path -LiteralPath $setupLog) { Write-Host "-- the Setup's install step:"; Get-Content -LiteralPath $setupLog | Out-Host }
Write-Host "== service"
$t = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
$state = Join-Path $env:LOCALAPPDATA 'Argus\NativeService'
if (-not $t) {
    # Diagnose before judging: what the Setup's own step would have printed.
    Write-Host "-- no task after Setup: running the install step by hand"
    $out = & $engine native install 2>&1 | Out-String
    Write-Host $out
    Write-Host "-- native install exit code: $LASTEXITCODE"
    foreach ($f in 'service.log', 'daemon.err.log', 'daemon.out.log') {
        $pth = Join-Path $state $f
        if (Test-Path -LiteralPath $pth) { Write-Host "-- $f"; Get-Content -LiteralPath $pth -Tail 40 | Out-Host }
    }
    Check $false 'the Setup registered the service by itself'
    $t = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
}
Check ([bool]$t) "scheduled task '$task' registered"
if ($t) { Check ($t.Principal.RunLevel -eq 'Limited') 'task runs without elevation' }
$port = 8787
$portFile = Join-Path $appDir 'port'
if (Test-Path -LiteralPath $portFile) { $port = [int](Get-Content -LiteralPath $portFile -TotalCount 1) }
$h = Health $port
Check ($h -and $h.service -eq 'ARGUS') "health answers as ARGUS on port $port"
Check ($h -and $h.live -eq $true) 'scheduler live'
Check (Test-Path -LiteralPath (Join-Path $appDir 'client.token')) 'desktop app paired (token written)'

Write-Host "== adapts to this host"
$status = & $engine native status --all 2>&1 | Out-String
Write-Host $status
Check ($status -match 'not here\s+auditd\b') 'Linux-only audit listed as not applicable here'
Check ($status -match 'daemon process: pid') 'supervisor sees the daemon it started'
$welcome = & $engine welcome 2>&1 | Out-String
Write-Host $welcome
Check ($welcome -match 'for Windows') "first-run statement chosen for native Windows"

Write-Host "== positive control: a planted autostart entry"
# A brand-new profile can lack the Run key itself.
if (-not (Test-Path -LiteralPath $runKey)) { New-Item -Path $runKey -Force | Out-Null }
Remove-ItemProperty -Path $runKey -Name $probeName -ErrorAction SilentlyContinue
Check (-not (Probe-Seen)) 'absent before planting (negative control)'
New-ItemProperty -Path $runKey -Name $probeName -Value 'cmd.exe /c exit' -PropertyType String -Force | Out-Null
try {
    Check (Probe-Seen) 'found by the compiled startup audit while planted'
} finally {
    Remove-ItemProperty -Path $runKey -Name $probeName -ErrorAction SilentlyContinue
}
Check (-not (Probe-Seen)) 'gone once removed'

Write-Host "== uninstall (silent)"
$u = Start-Process -FilePath (Join-Path $install 'Uninstall.exe') -ArgumentList '/S', "_?=$install" -Wait -PassThru
Check ($u.ExitCode -eq 0) "uninstaller exit code 0 (was $($u.ExitCode))"
Remove-Item -LiteralPath (Join-Path $install 'Uninstall.exe') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $install -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5
Check (-not (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)) 'task removed'
Check (-not (Test-Path -LiteralPath $engine)) 'program removed'
Check (-not (Test-Path -LiteralPath $uninstKey)) 'uninstall entry removed'
Check (-not (Test-Path -LiteralPath (Join-Path $appDir 'client.token'))) 'desktop token removed'
Check (-not (Health $port)) 'nothing answers on the port any more'
Check (-not (Test-Path -LiteralPath $lnk)) 'Start menu entry removed'
$kept = Join-Path $env:USERPROFILE '.argus'
Write-Host "history kept at $kept : $(Test-Path -LiteralPath $kept)"

if ($script:failed) { Write-Host "$($script:failed) check(s) failed"; exit 1 }
Write-Host 'all checks passed'
