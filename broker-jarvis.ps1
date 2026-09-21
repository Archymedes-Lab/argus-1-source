# Elevated collector broker: the read-only checks that need administrator.
#
# Five collectors are half-blind without elevation: posture (BitLocker, TPM,
# Defender exclusions, optional features), memscan (157 of 280 processes could
# not be opened), internet (the firewall traffic log is admin-only), and the
# active Sysmon policy, and bounded Sysmon boot-pressure evidence. A UAC
# prompt per run is not a schedule, so this registers one task that runs with
# the user's elevated token and writes each collector's normal output where
# JARVIS can read it.
#
# The trap to avoid: a task running as administrator must never execute a file
# the unelevated user can modify, or any malware running as that user inherits
# administrator through it. So everything the task runs is copied into
# C:\ProgramData\Jarvis\Broker, whose ACL grants write only to Administrators
# and SYSTEM (Users may read). Nothing is ever re-read from WSL or LocalAppData
# at run time, and there is no self-update: a changed script needs -Install
# again, which needs a new UAC consent. JARVIS fingerprints the staged copies
# against the checkout and reports drift.
#
# The scripts run are the collectors' own: they read state and print base64
# JSON. The broker adds no remediation and runs nothing else.
#
#   .\broker-jarvis.ps1 -Install -Source <folder with the .ps1 collectors>
#       (from an elevated shell, or via Start-Process -Verb RunAs)
#   .\broker-jarvis.ps1 -Run       what the task executes
#   .\broker-jarvis.ps1 -Remove

param(
    [switch]$Install,
    [switch]$Run,
    [switch]$Remove,
    [string]$Source = '',
    # Opt-in at install: log allowed connections too (Windows logs neither
    # allowed nor, by default, dropped traffic). Changes firewall settings.
    [switch]$EnableFirewallLogging,
    [string]$TaskName = 'jarvis elevated broker'
)

$ErrorActionPreference = 'Stop'
$Root = Join-Path $env:ProgramData 'Jarvis\Broker'
$Out = Join-Path $Root 'out'
$Jobs = [ordered]@{
    posture  = @{ script = 'posture.ps1';       timeout = 400 }
    memscan  = @{ script = 'memscan.ps1';       timeout = 600 }
    internet = @{ script = 'internetwatch.ps1'; timeout = 120 }
    sysmon_policy = @{ script = 'sysmon_policy.ps1'; timeout = 30 }
    sysmon_pressure = @{ script = 'sysmon_pressure.ps1'; timeout = 120 }
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Lock-Folder([string]$path) {
    # SYSTEM and Administrators: full. Users: read and execute. No inheritance
    # from ProgramData, whose default ACL lets Users create files.
    & icacls.exe $path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' `
        '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $path ($LASTEXITCODE)" }
}

if ($Remove) {
    if (-not (Test-Admin)) { throw 'run -Remove from an elevated shell' }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "removed '$TaskName' and $Root"
    return
}

if ($Install) {
    if (-not (Test-Admin)) { throw 'run -Install from an elevated shell' }
    if (-not $Source -or -not (Test-Path -LiteralPath $Source)) { throw "-Source folder not found: $Source" }
    New-Item -ItemType Directory -Path $Out -Force | Out-Null
    Lock-Folder $Root
    Copy-Item -LiteralPath $MyInvocation.MyCommand.Path -Destination (Join-Path $Root 'broker-jarvis.ps1') -Force
    foreach ($job in $Jobs.Values) {
        Copy-Item -LiteralPath (Join-Path $Source $job.script) -Destination (Join-Path $Root $job.script) -Force
    }
    # The installing user's elevated token, so per-user state (HKCU, the
    # user's own Defender view) matches what the unelevated collectors see.
    $user = (Get-CimInstance Win32_ComputerSystem).UserName
    if (-not $user) { $user = "$env:USERDOMAIN\$env:USERNAME" }
    $script = Join-Path $Root 'broker-jarvis.ps1'
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\conhost.exe" -Argument (
        '--headless "' + "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" +
        '" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $script + '" -Run')
    $triggers = @((New-ScheduledTaskTrigger -AtLogOn -User $user),
                  (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
                     -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 3650)))
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal `
        -Settings $settings -Description 'JARVIS read-only collectors that need administrator' -Force | Out-Null
    if ($EnableFirewallLogging) {
        Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384
        Write-Output 'firewall logging: allowed and blocked connections are now logged'
    }
    Start-ScheduledTask -TaskName $TaskName
    Write-Output "installed '$TaskName' (every 15 min, elevated) with scripts in $Root"
    return
}

if ($Run) {
    New-Item -ItemType Directory -Path $Out -Force | Out-Null
    $status = [ordered]@{ started = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); admin = (Test-Admin); jobs = [ordered]@{} }
    foreach ($name in $Jobs.Keys) {
        $job = $Jobs[$name]
        $t0 = Get-Date
        $tmp = Join-Path $Out "$name.b64.new"
        $err = Join-Path $Out "$name.err"
        try {
            $p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
                -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Root $job.script)) `
                -RedirectStandardOutput $tmp -RedirectStandardError $err -WindowStyle Hidden -PassThru
            if (-not $p.WaitForExit($job.timeout * 1000)) {
                $p.Kill(); throw "timed out after $($job.timeout)s"
            }
            $body = (Get-Content -LiteralPath $tmp -Raw -ErrorAction SilentlyContinue)
            if (-not $body -or -not $body.Trim()) { throw 'produced no output' }
            Move-Item -LiteralPath $tmp -Destination (Join-Path $Out "$name.b64") -Force
            $status.jobs[$name] = @{ ok = $true; ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds();
                                     secs = [int]((Get-Date) - $t0).TotalSeconds; error = '' }
        } catch {
            $status.jobs[$name] = @{ ok = $false; ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds();
                                     secs = [int]((Get-Date) - $t0).TotalSeconds; error = [string]$_.Exception.Message }
        } finally {
            Remove-Item -LiteralPath $tmp, $err -ErrorAction SilentlyContinue
        }
    }
    $status.finished = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $status | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Out 'status.json.new') -Encoding UTF8
    Move-Item -LiteralPath (Join-Path $Out 'status.json.new') -Destination (Join-Path $Out 'status.json') -Force
    return
}

Write-Output 'use -Install, -Run or -Remove'
