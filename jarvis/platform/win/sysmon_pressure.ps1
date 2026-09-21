# Read-only Sysmon pressure evidence for the elevated JARVIS broker.
# Returns aggregate counts only: no registry values, command lines, or raw events.

$ErrorActionPreference = 'Stop'
$result = [ordered]@{
  ok = $false
  boot = ''
  retained_registry_events = 0
  by_rule = @()
  by_image = @()
  drops = @()
  truncated = $false
  error = ''
}

try {
  $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
  $result.boot = $boot.ToUniversalTime().ToString('o')
  $events = @(Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 12,13,14,255
    StartTime = $boot
  } -MaxEvents 50000 -ErrorAction Stop)
  $result.truncated = $events.Count -eq 50000
  $rules = @{}
  $images = @{}
  foreach ($event in $events) {
    if ($event.Id -eq 255) {
      $counts = [ordered]@{}
      foreach ($match in [regex]::Matches([string]$event.Message,
          '([A-Za-z][A-Za-z0-9]+):(\d+)')) {
        if ($match.Groups[1].Value -ne 'DriverQueueSize') {
          $counts[$match.Groups[1].Value] = [int64]$match.Groups[2].Value
        }
      }
      $queue = [regex]::Match([string]$event.Message, 'DriverQueueSize:\s*(\d+)')
      $result.drops += [ordered]@{
        at = $event.TimeCreated.ToUniversalTime().ToString('o')
        counts = $counts
        driver_queue_size = if ($queue.Success) { [int64]$queue.Groups[1].Value } else { $null }
      }
      continue
    }
    $result.retained_registry_events++
    $xml = [xml]$event.ToXml()
    $fields = @{}
    foreach ($data in $xml.Event.EventData.Data) {
      $fields[[string]$data.Name] = [string]$data.'#text'
    }
    $rule = if ($fields.RuleName) { $fields.RuleName } else { '(none)' }
    $image = if ($fields.Image) { [IO.Path]::GetFileName($fields.Image) } else { '(unknown)' }
    $rules[$rule] = 1 + [int64]($rules[$rule])
    $images[$image] = 1 + [int64]($images[$image])
  }
  $result.by_rule = @($rules.GetEnumerator() | Sort-Object Value -Descending |
    Select-Object -First 20 | ForEach-Object {
      [ordered]@{ name = [string]$_.Key; count = [int64]$_.Value }
    })
  $result.by_image = @($images.GetEnumerator() | Sort-Object Value -Descending |
    Select-Object -First 20 | ForEach-Object {
      [ordered]@{ name = [string]$_.Key; count = [int64]$_.Value }
    })
  $result.ok = $true
} catch {
  $result.error = [string]$_.Exception.Message
}

$json = $result | ConvertTo-Json -Depth 7 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
