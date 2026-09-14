# Fixed operation: disable local inbound allow rules for missing executables.
# No elevation prompts, arbitrary commands, deletion, or policy-store edits.
$ErrorActionPreference = 'Stop'
$result = @{ ok = $false; changed = 0 }
try {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator permission is unavailable'
    }
    $targets = @(
        foreach ($rule in @(Get-NetFirewallRule -PolicyStore ActiveStore)) {
            if ($rule.Enabled -ne 'True' -or $rule.Direction -ne 'Inbound' -or
                $rule.Action -ne 'Allow' -or $rule.PolicyStoreSourceType -ne 'Local') { continue }
            $apps = @($rule | Get-NetFirewallApplicationFilter)
            if ($apps.Count -ne 1) { continue }
            $program = [Environment]::ExpandEnvironmentVariables([string]$apps[0].Program)
            if ($program -notmatch '^[A-Za-z]:\\.+\.exe$') { continue }
            # Check the parent too: an inaccessible/unmounted directory is not absence.
            $parent = Split-Path -Parent $program
            if (-not (Test-Path -LiteralPath $parent -PathType Container)) { continue }
            if (Test-Path -LiteralPath $program) { continue }
            [pscustomobject]@{ Name = $rule.Name; Program = $program; Enabled = $rule.Enabled }
        }
    )
    if ($targets.Count) {
        $dir = Join-Path $env:LOCALAPPDATA 'Jarvis\repairs'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $backup = Join-Path $dir ('orphan-firewall-' + [guid]::NewGuid().ToString() + '.clixml')
        $targets | Export-Clixml -LiteralPath $backup
        foreach ($target in $targets) {
            if (Test-Path -LiteralPath $target.Program) { throw 'Program reappeared' }
            Disable-NetFirewallRule -PolicyStore PersistentStore -Name $target.Name | Out-Null
            $live = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $target.Name)
            if (-not $live.Count -or @($live | Where-Object Enabled -ne 'False').Count) {
                throw 'Rule disable could not be verified'
            }
            $result.changed++
        }
    }
    $result.ok = $true
} catch { $result.ok = $false }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Compress)))
