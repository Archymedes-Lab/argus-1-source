<#
.SYNOPSIS
Collect the process table with command lines (needed for AI agent identification).

.DESCRIPTION
Runs on Windows only. Uses Get-CimInstance to enumerate processes and their
command lines. No execution of payloads, no network, no credential access.

.NOTES
Returns JSON on stdout. Designed to be called by the agent_guardian collector
via subprocess from a daemon, so no console UI. Exit code 0 on success.
#>
[CmdletBinding()]
param(
    [string]$Mode = "list"
)

$ErrorActionPreference = "Stop"

try {
    $procs = Get-CimInstance Win32_Process -ErrorAction Stop |
        Select-Object ProcessName, ExecutablePath, CommandLine, ProcessId, ParentProcessId, User, Description

    $out = @()
    foreach ($p in $procs) {
        $out += @{
            pid        = [int]$p.ProcessId
            exe        = if ($p.ExecutablePath) { $p.ExecutablePath } else { $p.ProcessName }
            name       = $p.ProcessName
            cmdline    = if ($p.CommandLine) { $p.CommandLine } else { "" }
            ppid       = [int]$p.ParentProcessId
            user       = if ($p.User) { $p.User } else { "" }
            description= if ($p.Description) { $p.Description } else { "" }
        }
    }

    Write-Host (ConvertTo-Json -InputObject @{
        processes = $out
        ts        = (Get-Date -Format "o")
    })
    exit 0
} catch {
    Write-Host (ConvertTo-Json -InputObject @{
        processes = @()
        error     = $_.Exception.Message
        ts        = (Get-Date -Format "o")
    })
    exit 1
}
