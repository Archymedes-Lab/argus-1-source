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
# JSON. The one writer is vault.ps1, which only appends copies of JARVIS's own
# sealed history into C:\ProgramData\Jarvis\Vault (Administrators/SYSTEM
# write, owner read) and never overwrites or deletes. The one stateful job is
# inputaudit.ps1: it keeps JARVIS's own Win32k audit trace session running
# (observation only; it changes no system setting and ends at reboot) and an
# inventory under this folder. hp_firmware_audit.ps1 loads HP's signed CMSL
# module from Program Files only after checking every file's signer and that
# only SYSTEM, Administrators or TrustedInstaller can change it; it reads the
# HP Sure Start audit log and changes nothing. The broker adds no remediation
# and runs nothing else.
#
#   .\jarvis-elevated-broker.ps1 -Install -Source <folder with the .ps1 collectors>
#       (from an elevated shell, or via Start-Process -Verb RunAs)
#   .\jarvis-elevated-broker.ps1 -Run       what the task executes
#   .\jarvis-elevated-broker.ps1 -Remove

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
# Paths come from the operating system, never from environment variables: an
# elevated process started with the user's token inherits the user's own
# environment (HKCU\Environment), so %ProgramData%, %SystemRoot%, %TEMP% and
# %PSModulePath% are whatever the unelevated user set them to.
$Sys32 = [Environment]::SystemDirectory
$WinDir = Split-Path -Parent $Sys32
$ProgramDataDir = Join-Path ([IO.Path]::GetPathRoot($Sys32)) 'ProgramData'
$PowerShellExe = Join-Path $Sys32 'WindowsPowerShell\v1.0\powershell.exe'
# Module autoloading searches PSModulePath, whose first entry is normally the
# user's Documents folder; only the administrator-only folders remain.
$env:PSModulePath = (Join-Path $Sys32 'WindowsPowerShell\v1.0\Modules') + ';' +
    (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WindowsPowerShell\Modules')
$env:ProgramData = $ProgramDataDir
$env:ALLUSERSPROFILE = $ProgramDataDir
$env:SystemRoot = $WinDir
$env:windir = $WinDir
$JarvisDir = Join-Path $ProgramDataDir 'Jarvis'
$Root = Join-Path $JarvisDir 'Broker'
$Out = Join-Path $Root 'out'
$Tmp = Join-Path $Root 'tmp'
$BrokerCopy = Join-Path $Root 'jarvis-elevated-broker.ps1'
# Owners allowed for anything the elevated task runs or reads: SYSTEM,
# Administrators and TrustedInstaller.
$TrustedOwners = @('S-1-5-18', 'S-1-5-32-544',
                   'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$Jobs = [ordered]@{
    posture  = @{ script = 'posture.ps1';       timeout = 400 }
    memscan  = @{ script = 'memscan.ps1';       timeout = 600 }
    internet = @{ script = 'internetwatch.ps1'; timeout = 120 }
    sysmon_policy = @{ script = 'sysmon_policy.ps1'; timeout = 30 }
    sysmon_pressure = @{ script = 'sysmon_pressure.ps1'; timeout = 120 }
    vault    = @{ script = 'vault.ps1';          timeout = 120 }
    # Scanning the trace costs 0.7-1.7 s per MB whatever the reader (measured
    # 2026-10-27: Get-WinEvent and EventLogReader both 24 s on 34 MB; 70 MB
    # under load passed 120 s and every run failed). The trace is capped at
    # 128 MB, so 400 s covers the worst case measured.
    inputaudit = @{ script = 'inputaudit.ps1';   timeout = 400 }
    fwaudit  = @{ script = 'hp_firmware_audit.ps1'; timeout = 120 }
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Lock-Folder([string]$path) {
    # SYSTEM and Administrators: full. Users: read and execute. Owner
    # Administrators. The whole DACL is replaced, not merged: a folder someone
    # created before the install (ProgramData lets Users create folders, and
    # the creator owns them) keeps neither its owner nor any extra entry.
    $sid = { param($v) New-Object Security.Principal.SecurityIdentifier($v) }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner((& $sid 'S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($grant in @(@('S-1-5-18', 'FullControl'), @('S-1-5-32-544', 'FullControl'),
                         @('S-1-5-32-545', 'ReadAndExecute'))) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (& $sid $grant[0]), [Security.AccessControl.FileSystemRights]$grant[1], $inherit,
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)))
    }
    [IO.Directory]::SetAccessControl($path, $acl)
}

function Find-Untrusted([string]$path, [switch]$Recurse) {
    # The first entry that is a link or is owned by anyone but SYSTEM,
    # Administrators or TrustedInstaller; $null when there is none. Links are
    # reported, never followed.
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return "$path is a link" }
    $owner = (Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($TrustedOwners -notcontains $owner) { return "$path is owned by $owner" }
    if ($Recurse -and $item.PSIsContainer) {
        foreach ($child in @(Get-ChildItem -LiteralPath $path -Force)) {
            $why = Find-Untrusted $child.FullName -Recurse
            if ($why) { return $why }
        }
    }
    return $null
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
    if (-not (Test-Path -LiteralPath $JarvisDir)) { New-Item -ItemType Directory -Path $JarvisDir | Out-Null }
    if ((Get-Item -LiteralPath $JarvisDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "refusing: $JarvisDir is a link"
    }
    Lock-Folder $JarvisDir
    # A broker folder holding anything an unelevated account created or owns
    # is set aside (kept as evidence, never run) and a fresh one is made.
    $why = Find-Untrusted $Root -Recurse
    if ($why) {
        $aside = "$Root.untrusted-" + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
        Move-Item -LiteralPath $Root -Destination $aside
        Write-Output "set aside $aside ($why)"
    }
    if (-not (Test-Path -LiteralPath $Root)) { New-Item -ItemType Directory -Path $Root | Out-Null }
    Lock-Folder $Root
    New-Item -ItemType Directory -Path $Out -Force | Out-Null
    New-Item -ItemType Directory -Path $Tmp -Force | Out-Null
    Copy-Item -LiteralPath $MyInvocation.MyCommand.Path -Destination $BrokerCopy -Force
    foreach ($job in $Jobs.Values) {
        Copy-Item -LiteralPath (Join-Path $Source $job.script) -Destination (Join-Path $Root $job.script) -Force
    }
    # The installing user's elevated token, so per-user state (HKCU, the
    # user's own Defender view) matches what the unelevated collectors see.
    $user = (Get-CimInstance Win32_ComputerSystem).UserName
    if (-not $user) { $user = "$env:USERDOMAIN\$env:USERNAME" }
    $action = New-ScheduledTaskAction -Execute (Join-Path $Sys32 'conhost.exe') -Argument (
        '--headless "' + $PowerShellExe +
        '" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $BrokerCopy + '" -Run')
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
    # Only the protected copy runs jobs, and only while its folders are still
    # owned by administrators: a copy elsewhere, or a folder that changed
    # hands, runs nothing.
    if (-not [string]::Equals([IO.Path]::GetFullPath($PSCommandPath), $BrokerCopy,
                              [StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to run from $PSCommandPath; only $BrokerCopy runs jobs"
    }
    foreach ($dir in @($JarvisDir, $Root)) {
        $why = Find-Untrusted $dir
        if ($why) { throw "refusing to run: $why" }
    }
    New-Item -ItemType Directory -Path $Out -Force | Out-Null
    New-Item -ItemType Directory -Path $Tmp -Force | Out-Null
    # Collectors that compile C# (Add-Type) write and load files in TEMP; the
    # user's TEMP would let the unelevated user swap the compiled code.
    $env:TEMP = $Tmp
    $env:TMP = $Tmp
    $status = [ordered]@{ started = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); admin = (Test-Admin); jobs = [ordered]@{} }
    foreach ($name in $Jobs.Keys) {
        $job = $Jobs[$name]
        $t0 = Get-Date
        $tmp = Join-Path $Out "$name.b64.new"
        $err = Join-Path $Out "$name.err"
        try {
            $p = Start-Process -FilePath $PowerShellExe `
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
