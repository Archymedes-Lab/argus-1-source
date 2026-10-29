# Installs the JARVIS native sensor as a Windows service. Run elevated.
#
#   .\install.ps1 -Install [-User <account JARVIS runs as>] [-EnableTaskLog] [-SysmonLogMB 256]
#   .\install.ps1 -Remove  [-PurgeSpool]
#
# Trust layout, so that nothing the unelevated user can modify ever runs as the
# service:
#   C:\Program Files\Jarvis\Sensor   the executable, compiled here from the
#                                    checkout at install time. Administrators
#                                    and SYSTEM write; everyone else reads.
#   C:\ProgramData\Jarvis\Sensor     the spool. The service writes; the user
#                                    reads (WSL ingests from /mnt/c).
#   ...\Sensor\acks                  the one place the user may write: the
#                                    acknowledgements that let the sensor
#                                    reclaim batches JARVIS has committed.
# The service runs as its own virtual account (NT SERVICE\JarvisNativeSensor),
# not LocalSystem, and reads event channels through Event Log Readers.
# A changed JarvisSensor.cs does nothing until -Install is run again.

param(
    [switch]$Install,
    [switch]$Remove,
    [string]$User = "$env:USERDOMAIN\$env:USERNAME",
    # Scheduled-task persistence is invisible while this channel is disabled,
    # which is the Windows default.
    [switch]$EnableTaskLog,
    # Sysmon's log wraps at 64 MB by default; records it overwrites before the
    # sensor reads them are lost (and reported as a gap). 0 leaves it alone.
    [int]$SysmonLogMB = 0,
    [switch]$PurgeSpool
)

$ErrorActionPreference = 'Stop'
# Locations from the operating system, not environment variables, which an
# elevated shell inherits from the (unelevated) user's own environment.
$Sys32 = [Environment]::SystemDirectory
$WinDir = Split-Path -Parent $Sys32
$ProgramFilesDir = [Environment]::GetFolderPath('ProgramFiles')
$ProgramDataDir = Join-Path ([IO.Path]::GetPathRoot($Sys32)) 'ProgramData'
$Name = 'JarvisNativeSensor'
$Account = "NT SERVICE\$Name"
$Bin = Join-Path $ProgramFilesDir 'Jarvis\Sensor'
$Exe = Join-Path $Bin 'JarvisSensor.exe'
$Spool = Join-Path $ProgramDataDir 'Jarvis\Sensor'
$Acks = Join-Path $Spool 'acks'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Grant-Folder([string]$path, [string[]]$grants) {
    # No inheritance from the parent: ProgramData lets Users create files.
    # Owner Administrators: a folder the user created before the install
    # would otherwise stay theirs, and an owner can rewrite the ACL.
    & (Join-Path $Sys32 'icacls.exe') $path /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /setowner failed on $path ($LASTEXITCODE)" }
    & (Join-Path $Sys32 'icacls.exe') $path /inheritance:r /grant:r @grants | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $path ($LASTEXITCODE)" }
}

# Defender's ASR rule "Block executable files from running unless they meet a
# prevalence, age, or trusted list criterion" blocks a freshly built, unsigned,
# low-prevalence binary from starting — the Service Control Manager reports it
# as "Access is denied". Signing does not help: the rule uses Microsoft's cloud
# reputation, not the local trusted-publisher store. So scope a single ASR-only
# exclusion to this one binary. It is far narrower than an antivirus exclusion —
# the file is still fully scanned for malware — and the binary sits in an
# administrator-only-write folder, so nothing unprivileged can abuse the path.
$AsrPrevalenceRule = '01443614-CD74-433A-B99E-2ECDC07BFC25'

function Add-AsrExclusion([string]$path) {
    try {
        $current = @((Get-MpPreference).AttackSurfaceReductionOnlyExclusions)
        if ($current -notcontains $path) {
            Add-MpPreference -AttackSurfaceReductionOnlyExclusions $path
            Write-Host "Added a scoped ASR-only exclusion for $path (malware scanning unaffected)."
        }
    } catch { Write-Warning "Could not add the ASR exclusion: $($_.Exception.Message)" }
}

function Remove-AsrExclusion([string]$path) {
    try { Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $path -ErrorAction SilentlyContinue } catch {}
}

function New-AdminOnlyDirectory([string]$prefix) {
    # A fresh folder under %SystemRoot%\Temp, created with its ACL in one call
    # (SYSTEM and Administrators only, nothing inherited). The user's %TEMP%
    # is writable by the unelevated user, who could edit a policy file there
    # between its writing and secedit applying it.
    $sid = { param($v) New-Object Security.Principal.SecurityIdentifier($v) }
    $sec = New-Object Security.AccessControl.DirectorySecurity
    $sec.SetOwner((& $sid 'S-1-5-32-544'))
    $sec.SetAccessRuleProtection($true, $false)
    foreach ($s in @('S-1-5-18', 'S-1-5-32-544')) {
        $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((& $sid $s),
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)))
    }
    $path = Join-Path (Join-Path $WinDir 'Temp') ($prefix + [guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $path) { throw "refusing: $path already exists" }
    [void][IO.Directory]::CreateDirectory($path, $sec)
    return $path
}

function Grant-LogonAsService([string]$sid) {
    # A virtual service account needs SeServiceLogonRight or the service fails
    # to start with "Access is denied". sc.exe does not reliably grant it, so
    # add it through the local security policy. SIDs in a secedit INF are
    # written with a leading '*'.
    $tmp = New-AdminOnlyDirectory 'jarvis-secedit-'
    try {
        $inf = Join-Path $tmp 'export.inf'
        $db  = Join-Path $tmp 'secedit.sdb'
        & (Join-Path $Sys32 'secedit.exe') /export /cfg $inf /areas USER_RIGHTS | Out-Null
        $content = Get-Content -LiteralPath $inf
        $line = $content | Where-Object { $_ -match '^SeServiceLogonRight' }
        if ($line -and $line -match [regex]::Escape($sid)) { return }   # already granted
        if ($line) {
            $content = $content -replace '^(SeServiceLogonRight\s*=\s*.*)$', "`$1,*$sid"
        } else {
            $content = $content -replace '(\[Privilege Rights\])', "`$1`r`nSeServiceLogonRight = *$sid"
        }
        Set-Content -LiteralPath $inf -Value $content -Encoding Unicode
        & (Join-Path $Sys32 'secedit.exe') /configure /db $db /cfg $inf /areas USER_RIGHTS | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit could not grant the logon right ($LASTEXITCODE)" }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Stop-Sensor {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
        Stop-Service -Name $Name -Force
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    return $svc
}

if (-not (Test-Admin)) { throw 'Run this from an elevated PowerShell.' }
if ($Install -eq $Remove) { throw 'Choose exactly one of -Install or -Remove.' }

if ($Remove) {
    if (Stop-Sensor) { & (Join-Path $Sys32 'sc.exe') delete $Name | Out-Null }
    Remove-AsrExclusion $Exe
    Remove-Item -LiteralPath $Bin -Recurse -Force -ErrorAction SilentlyContinue
    if ($PurgeSpool) { Remove-Item -LiteralPath $Spool -Recurse -Force -ErrorAction SilentlyContinue }
    else { Write-Host "Spool kept as evidence: $Spool (-PurgeSpool removes it)" }
    return
}

$source = Join-Path $PSScriptRoot 'JarvisSensor.cs'
$compiler = Join-Path $WinDir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '64-bit .NET Framework compiler is unavailable' }

$existing = Stop-Sensor
New-Item -ItemType Directory -Force -Path $Bin | Out-Null
# The service runs as the virtual account NT SERVICE\JarvisNativeSensor, which
# is not a member of Users, so it needs its own read+execute on the binary
# folder or the service fails to start with "Access is denied". The virtual
# account's SID is derived from the name and grantable before the service
# exists. Users keep RX so `jarvis sensor status` can stat the exe.
Grant-Folder $Bin @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F',
                    "${Account}:(OI)(CI)RX", '*S-1-5-32-545:(OI)(CI)RX')
# Exclude the target path before compiling, so the ASR prevalence rule blocks
# neither csc.exe creating the binary nor the service starting it.
Add-AsrExclusion $Exe
# Compile from a copy in the protected folder, so the file compiled is the
# file that was checked, not one swapped in the checkout mid-install.
$staged = Join-Path $Bin 'JarvisSensor.cs'
Copy-Item -LiteralPath $source -Destination $staged -Force
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /r:System.ServiceProcess.dll `
    /r:System.Web.Extensions.dll /out:$Exe $staged
if ($LASTEXITCODE -ne 0) { throw 'Native sensor compilation failed' }

if (-not $existing) {
    New-Service -Name $Name -BinaryPathName "`"$Exe`"" -DisplayName 'JARVIS native sensor' `
        -Description 'Records Sysmon, Defender and Task Scheduler events for JARVIS.' `
        -StartupType Automatic | Out-Null
}
# password= "" is required for a virtual account, or the change half-applies.
& (Join-Path $Sys32 'sc.exe') config $Name obj= $Account password= "" | Out-Null
& (Join-Path $Sys32 'sc.exe') sidtype $Name unrestricted | Out-Null
$sid = (New-Object System.Security.Principal.NTAccount($Account)).Translate(
    [System.Security.Principal.SecurityIdentifier]).Value
Grant-LogonAsService $sid
& (Join-Path $Sys32 'sc.exe') failure $Name reset= 86400 actions= restart/5000/restart/5000/restart/60000 | Out-Null
$readers = Get-LocalGroupMember -SID 'S-1-5-32-573' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq $Account }
if (-not $readers) { Add-LocalGroupMember -SID 'S-1-5-32-573' -Member $Account }

New-Item -ItemType Directory -Force -Path $Acks | Out-Null
Grant-Folder $Spool @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "${Account}:(OI)(CI)M",
                 "${User}:(OI)(CI)RX")
Grant-Folder $Acks @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "${Account}:(OI)(CI)RX",
                "${User}:(OI)(CI)M")

if ($EnableTaskLog) {
    & (Join-Path $Sys32 'wevtutil.exe') sl 'Microsoft-Windows-TaskScheduler/Operational' /e:true
}
if ($SysmonLogMB -gt 0) {
    & (Join-Path $Sys32 'wevtutil.exe') sl 'Microsoft-Windows-Sysmon/Operational' /ms:$([int64]$SysmonLogMB * 1MB)
}

try {
    Start-Service -Name $Name
} catch {
    Write-Warning "Start-Service failed: $($_.Exception.Message)"
    Write-Host '--- most recent Service Control Manager entry ---'
    Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'} `
        -MaxEvents 20 -EA SilentlyContinue |
        Where-Object { $_.Message -match 'JarvisNativeSensor|JARVIS native sensor' } |
        Select-Object -First 1 | Format-List TimeCreated, Id, Message
    Write-Host 'If this says the binary was blocked, Windows Security (ASR/SmartScreen) '
    Write-Host 'is preventing an unsigned service exe. Re-run once you have reviewed it; '
    Write-Host 'the service and ACLs are already in place.'
    throw
}
$health = Join-Path $Spool 'health.json'
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $health)) { Start-Sleep 2 }
if (Test-Path -LiteralPath $health) { Get-Content -LiteralPath $health }
else { Write-Warning 'The service started but has not written health.json yet.' }
Get-FileHash -LiteralPath $Exe -Algorithm SHA256
