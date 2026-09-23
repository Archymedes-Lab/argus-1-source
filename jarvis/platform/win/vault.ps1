# Append-only evidence vault, run by the elevated JARVIS broker.
#
# The unprivileged daemon stages copies of its sealed event-log segments, the
# chain file and timestamp anchors in %LOCALAPPDATA%\Jarvis\VaultInbox. The
# inbox is untrusted: anything running as the user can write there. This job
# moves staged files into C:\ProgramData\Jarvis\Vault, which only
# Administrators and SYSTEM can modify and only the owning user can read,
# under one rule: the vault only grows.
#
#   * The vaulted chain.jsonl must be a byte-for-byte prefix of the staged
#     one. Anything else means the live history was rewritten (or the inbox
#     forged); the staged chain is kept as divergence evidence and the vault
#     is left untouched.
#   * A file already in the vault is never overwritten or deleted. A staged
#     copy that differs from it is reported, not applied.
#   * A chain line is appended only after its segment is in the vault, or
#     the stager marked it as removed by retention before it was vaulted.
#
# The vault does not verify segment payload hashes itself (.NET Framework's
# GZipStream stops at the first gzip member); the daemon verifies vaulted
# copies read-only and reports any that fail. Output: base64 JSON, counts only.

$ErrorActionPreference = 'Stop'
$Vault = Join-Path $env:ProgramData 'Jarvis\Vault'
$Inbox = Join-Path $env:LOCALAPPDATA 'Jarvis\VaultInbox'
$MaxBytes = 20GB
$BudgetSeconds = 90
$AnchorPattern = '^[0-9a-f]{64}(\.[a-z0-9]+)*\.(json|ots)$'

$result = [ordered]@{
  ok = $false
  vaulted_segments = 0
  head_segment = 0
  head_hash = ''
  new_segments = 0
  unvaulted_segments = 0
  new_anchors = 0
  anchor_conflicts = 0
  diverged = $false
  divergence = ''
  pending = ''
  bytes = 0
  full = $false
  truncated = $false
  error = ''
}

function Lock-Folder([string]$path) {
  # SYSTEM and Administrators: full. The owning user (whose elevated token
  # runs the broker): read, so the daemon can verify. No other account: the
  # history holds command lines. No inherited ProgramData ACEs.
  $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  & icacls.exe $path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' `
      "*${owner}:(OI)(CI)RX" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls failed on $path ($LASTEXITCODE)" }
}

function Get-Sha256([byte[]]$bytes, [int]$count) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return [BitConverter]::ToString($sha.ComputeHash($bytes, 0, $count)).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function Get-FileSha256([string]$path) {
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
}

function Add-Bytes([string]$path, [byte[]]$bytes) {
  $fs = New-Object IO.FileStream($path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
  try { $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
}

function Install-Copy([string]$source, [string]$target) {
  $temp = "$target.partial"
  if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
  Copy-Item -LiteralPath $source -Destination $temp
  # Move fails rather than replacing: a file already in the vault stays.
  [IO.File]::Move($temp, $target)
  (Get-Item -LiteralPath $target).IsReadOnly = $true
}

try {
  $clock = [Diagnostics.Stopwatch]::StartNew()
  $segDir = Join-Path $Vault 'eventlog\segments'
  foreach ($dir in @($Vault, $segDir, (Join-Path $Vault 'anchors'), (Join-Path $Vault 'divergence'))) {
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  }
  Lock-Folder $Vault
  $chainPath = Join-Path $Vault 'eventlog\chain.jsonl'
  $digestPath = Join-Path $Vault 'eventlog\segments.sha256'
  $unvaultedPath = Join-Path $Vault 'eventlog\unvaulted.txt'
  # Assigned inside the branches: an if-expression would unroll the byte
  # arrays (an empty one becomes $null).
  [byte[]]$vaulted = New-Object byte[] 0
  if (Test-Path -LiteralPath $chainPath) { $vaulted = [IO.File]::ReadAllBytes($chainPath) }
  $inboxChain = Join-Path $Inbox 'eventlog\chain.jsonl'
  $staged = $null
  if (Test-Path -LiteralPath $inboxChain) { [byte[]]$staged = [IO.File]::ReadAllBytes($inboxChain) }

  if ($null -ne $staged) {
    $prefix = $staged.Length -ge $vaulted.Length -and
              (Get-Sha256 $staged $vaulted.Length) -eq (Get-Sha256 $vaulted $vaulted.Length)
    if (-not $prefix) {
      $result.diverged = $true
      $result.divergence = 'staged chain does not extend the vaulted chain'
      $evidence = Join-Path $Vault ('divergence\chain-' + (Get-Sha256 $staged $staged.Length) + '.jsonl')
      if (-not (Test-Path -LiteralPath $evidence)) {
        [IO.File]::WriteAllBytes($evidence, $staged)
        (Get-Item -LiteralPath $evidence).IsReadOnly = $true
      }
    } else {
      $size = [int64](Get-ChildItem -LiteralPath $Vault -Recurse -File | Measure-Object Length -Sum).Sum
      $offset = $vaulted.Length
      while ($offset -lt $staged.Length) {
        $end = [Array]::IndexOf($staged, [byte]10, $offset)
        if ($end -lt 0) { break }                     # torn tail: wait for the stager
        $lineBytes = New-Object byte[] ($end - $offset + 1)
        [Array]::Copy($staged, $offset, $lineBytes, 0, $lineBytes.Length)
        $header = [Text.Encoding]::UTF8.GetString($lineBytes) | ConvertFrom-Json
        $name = '{0:D12}.jseg' -f [int64]$header.segment
        $source = Join-Path $Inbox "eventlog\segments\$name"
        $target = Join-Path $segDir $name
        if (Test-Path -LiteralPath $target) {
          if ((Test-Path -LiteralPath $source) -and (Get-FileSha256 $source) -ne (Get-FileSha256 $target)) {
            $result.diverged = $true
            $result.divergence = "staged $name differs from its vaulted copy"
            break
          }
        } elseif (Test-Path -LiteralPath $source) {
          if ($size + (Get-Item -LiteralPath $source).Length -ge $MaxBytes) { $result.full = $true; break }
          Install-Copy $source $target
          $size += (Get-Item -LiteralPath $target).Length
          Add-Bytes $digestPath ([Text.Encoding]::ASCII.GetBytes("$name $(Get-FileSha256 $target)`n"))
          $result.new_segments++
        } elseif (Test-Path -LiteralPath "$source.pruned") {
          Add-Bytes $unvaultedPath ([Text.Encoding]::ASCII.GetBytes("$name removed by retention before it was vaulted`n"))
          $result.unvaulted_segments++
        } else {
          $result.pending = "waiting for staged $name"
          break
        }
        Add-Bytes $chainPath $lineBytes
        $offset = $end + 1
        if ($clock.Elapsed.TotalSeconds -ge $BudgetSeconds) { $result.truncated = $true; break }
      }
    }
  }

  $anchorInbox = Join-Path $Inbox 'anchors'
  if (Test-Path -LiteralPath $anchorInbox) {
    foreach ($file in Get-ChildItem -LiteralPath $anchorInbox -File) {
      if ($file.Name -notmatch $AnchorPattern) { continue }
      $target = Join-Path $Vault "anchors\$($file.Name)"
      if (Test-Path -LiteralPath $target) {
        if ((Get-FileSha256 $file.FullName) -ne (Get-FileSha256 $target)) { $result.anchor_conflicts++ }
      } else {
        Install-Copy $file.FullName $target
        $result.new_anchors++
      }
    }
  }

  if (Test-Path -LiteralPath $chainPath) {
    $lines = @([IO.File]::ReadAllLines($chainPath) | Where-Object { $_ })
    $result.vaulted_segments = $lines.Count
    if ($lines.Count) {
      $head = $lines[-1] | ConvertFrom-Json
      $result.head_segment = [int64]$head.segment
      $result.head_hash = [string]$head.hash
    }
  }
  $result.bytes = [int64](Get-ChildItem -LiteralPath $Vault -Recurse -File | Measure-Object Length -Sum).Sum
  $result.full = $result.full -or $result.bytes -ge $MaxBytes
  $result.ok = $true
} catch {
  $result.error = [string]$_.Exception.Message
}

$json = $result | ConvertTo-Json -Depth 4 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
