
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$o.authkeys = @()
foreach ($p in @("$env:ProgramData\ssh\administrators_authorized_keys") +
                @(Get-ChildItem C:\Users -Directory |
                  ForEach-Object { Join-Path $_.FullName '.ssh\authorized_keys' })) {
  if (Test-Path $p) {
    $o.authkeys += [pscustomobject]@{ path=$p; body=(Get-Content $p -Raw) }
  }
}

# Accessibility backdoor: a debugger on sethc/utilman gives a SYSTEM shell
# from the logon screen without any credential.
$o.ifeo = @('sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe',
            'displayswitch.exe','atbroker.exe') | ForEach-Object {
  $k = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$_"
  $d = (Get-ItemProperty -Path $k -Name Debugger).Debugger
  if ($d) { [pscustomobject]@{ exe=$_; debugger=[string]$d } }
}

# Accounts hidden from the sign-in screen.
$o.hidden = @()
$ul = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
if (Test-Path $ul) {
  (Get-Item $ul).Property | ForEach-Object {
    $o.hidden += [pscustomobject]@{ name=$_; val=[int](Get-ItemProperty $ul $_).$_ }
  }
}

$o.sshsvc = [string](Get-Service sshd).Status
$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
