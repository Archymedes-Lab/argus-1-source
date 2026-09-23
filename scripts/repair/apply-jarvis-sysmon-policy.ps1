#Requires -RunAsAdministrator
<#
Applies the JARVIS Windows Sysmon baseline only after explicit operator consent.

The original active XML was not recoverable.  The script preserves Sysmon's
readable configuration export and the policy being applied, but it cannot claim
a byte-for-byte rollback to the unknown source.  It therefore requires a
separate explicit acknowledgement before changing the running service.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$PolicyPath,
    [switch]$AcknowledgeNoExactRollback
)

$ErrorActionPreference = 'Stop'
$sysmon = Join-Path $env:WINDIR 'Sysmon64.exe'
if (-not $AcknowledgeNoExactRollback) {
    throw 'Refusing to apply: the original XML is unavailable. Re-run only after reviewing the policy with -AcknowledgeNoExactRollback.'
}
if (-not (Test-Path -LiteralPath $sysmon -PathType Leaf)) { throw "Sysmon executable not found: $sysmon" }
if (-not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) { throw "Policy not found: $PolicyPath" }

try {
    $xml = New-Object System.Xml.XmlDocument
    $xml.PreserveWhitespace = $true
    $xml.Load((Resolve-Path -LiteralPath $PolicyPath))
    $node = $xml.SelectSingleNode('/Sysmon/EventFiltering/ProcessCreate[@onmatch="exclude"]')
    if ($null -eq $node -or $node.HasChildNodes) {
        throw 'Policy must use an empty ProcessCreate exclude rule to preserve complete start evidence.'
    }
} catch {
    throw "Policy preflight failed: $($_.Exception.Message)"
}

$root = Join-Path $env:ProgramData 'Jarvis\SysmonPolicy'
$backup = Join-Path $root ('backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $backup -Force | Out-Null
& $sysmon -c 2>&1 | Set-Content -LiteralPath (Join-Path $backup 'active-policy-export.txt') -Encoding UTF8
Copy-Item -LiteralPath $PolicyPath -Destination (Join-Path $backup 'applied-policy.xml') -Force
Get-FileHash -Algorithm SHA256 -LiteralPath $PolicyPath |
    Select-Object Algorithm,Hash,Path | ConvertTo-Json -Compress |
    Set-Content -LiteralPath (Join-Path $backup 'applied-policy-sha256.json') -Encoding UTF8

if (-not $PSCmdlet.ShouldProcess($sysmon, 'replace Sysmon configuration')) { return }
& $sysmon -c $PolicyPath
if ($LASTEXITCODE -ne 0) { throw "Sysmon rejected the policy ($LASTEXITCODE); prior configuration remains inspectable in $backup" }

$after = (& $sysmon -c 2>&1 | Out-String)
$processCreate = [regex]::Match(
    $after,
    '(?ms)^\s*-\s*ProcessCreate\s+onmatch:\s*exclude.*?(?=^\s*-\s*[A-Za-z][A-Za-z0-9]*\s+onmatch:|\z)'
)
if (-not $processCreate.Success -or $processCreate.Value -match '(?im)\bfilter:\s*') {
    throw "Applied policy could not be verified from Sysmon export; inspect $backup immediately."
}
Write-Output "Applied and verified JARVIS Sysmon policy. Evidence backup: $backup"
