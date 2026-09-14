
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

# --- 1. the two features that actually stop BYOVD -------------------------
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$o.hvciRunning = [bool](@($dg.SecurityServicesRunning) -contains 2)
$o.hvciConfigured = [bool](@($dg.SecurityServicesConfigured) -contains 2)
$o.vbsStatus = [int]$dg.VirtualizationBasedSecurityStatus

$ci = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
$v = (Get-ItemProperty -Path $ci -Name VulnerableDriverBlocklistEnable).VulnerableDriverBlocklistEnable
# Absent means "default", and the default is on for Windows 11 22H2 and later.
$o.blocklistValue = if ($null -eq $v) { -1 } else { [int]$v }

$hv = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
$o.hvciRegEnabled = [int](Get-ItemProperty -Path $hv -Name Enabled).Enabled

# --- 2. loaded kernel drivers ---------------------------------------------
# Only drivers outside the normal directories get an Authenticode check: over
# 300 drivers are loaded and signature verification is far too slow to run on
# all of them every pass.
$o.drivers = @(Get-CimInstance Win32_SystemDriver |
  Where-Object { $_.State -eq 'Running' -and $_.PathName } |
  ForEach-Object {
    [pscustomobject]@{
      name = [string]$_.Name
      path = [string]$_.PathName
      start= [string]$_.StartMode
    } })

# --- 3. alternate data streams --------------------------------------------
# Zone.Identifier is the mark-of-the-web and is on nearly every downloaded file;
# any *other* stream is the interesting case. Scoped to the directories payloads
# stage in, and capped, because a full-disk stream enumeration is not something
# you can run every half hour.
$dirs = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop",
          "$env:TEMP", "$env:LOCALAPPDATA\Temp", "$env:PUBLIC",
          "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")
$cut = (Get-Date).AddDays(-90)
$o.ads = @(foreach ($d in $dirs) {
  if (-not (Test-Path -LiteralPath $d)) { continue }
  Get-ChildItem -LiteralPath $d -File -Recurse -Depth 2 -Force |
    Where-Object { $_.LastWriteTime -gt $cut } |
    Select-Object -First 400 |
    ForEach-Object {
      $f = $_
      Get-Item -LiteralPath $f.FullName -Stream * |
        Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' } |
        ForEach-Object {
          [pscustomobject]@{ file=[string]$f.FullName
                             stream=[string]$_.Stream
                             size=[long]$_.Length }
        }
    }
})

# --- 4. shortcuts ----------------------------------------------------------
$shell = New-Object -ComObject WScript.Shell
$lnkDirs = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
             "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
             "$env:USERPROFILE\Desktop", "$env:PUBLIC\Desktop",
             "$env:USERPROFILE\Downloads")
$o.lnks = @(foreach ($d in $lnkDirs) {
  if (-not (Test-Path -LiteralPath $d)) { continue }
  Get-ChildItem -LiteralPath $d -Filter *.lnk -Force -ErrorAction SilentlyContinue |
    Select-Object -First 150 |
    ForEach-Object {
      $s = $shell.CreateShortcut($_.FullName)
      [pscustomobject]@{
        lnk    = [string]$_.FullName
        target = [string]$s.TargetPath
        args   = [string]$s.Arguments
        icon   = [string]$s.IconLocation
        wstyle = [int]$s.WindowStyle
      }
    }
})

# --- 5. where this machine has actually been resolving ---------------------
# The DNS client cache is the cheapest possible view of egress destinations by
# name, which is the only way dead-drop C2 is distinguishable at all.
$o.dns = [string[]]@(Get-DnsClientCache | Select-Object -ExpandProperty Entry -Unique)

# --- 6. autostart command lines, for the Unicode check ---------------------
$o.autoruns = @(
  foreach ($k in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                   'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
    if (-not (Test-Path $k)) { continue }
    $p = Get-ItemProperty $k
    $p.PSObject.Properties |
      Where-Object { $_.Name -notlike 'PS*' } |
      ForEach-Object { [pscustomobject]@{ key=$k; name=[string]$_.Name; cmd=[string]$_.Value } }
  })

$o.runmru = [string[]]@(
  $m = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
  if (Test-Path $m) {
    (Get-ItemProperty $m).PSObject.Properties |
      Where-Object { $_.Name -match '^[a-z]$' } | ForEach-Object { [string]$_.Value }
  })

$payload = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
