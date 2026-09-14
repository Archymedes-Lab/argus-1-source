
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$o.adapters = @(Get-NetAdapter | ForEach-Object {
  [pscustomobject]@{ name=[string]$_.Name; status=[string]$_.Status
                     mac=[string]$_.MacAddress; type=[string]$_.MediaType
                     up=[bool]($_.Status -eq 'Up') }})

# netsh is the only place BSSID, channel, authentication and cipher are all
# exposed together, so it is parsed as text rather than reinvented.
$o.wlan = [string](netsh wlan show interfaces 2>$null | Out-String)

$o.ipcfg = @(Get-NetIPConfiguration | ForEach-Object {
  [pscustomobject]@{
    iface=[string]$_.InterfaceAlias
    ipv4=[string]($_.IPv4Address.IPAddress -join ',')
    gw=[string]($_.IPv4DefaultGateway.NextHop -join ',')
    dns=[string](($_.DNSServer | Where-Object {$_.AddressFamily -eq 2}).ServerAddresses -join ',')
  }})

$o.neighbors = @(Get-NetNeighbor -AddressFamily IPv4 |
  Where-Object { $_.State -in 'Reachable','Stale','Permanent' } |
  ForEach-Object { [pscustomobject]@{ ip=[string]$_.IPAddress
                                      mac=[string]$_.LinkLayerAddress }})

# Windows' own record of every wireless transition. Read incrementally — only
# what has appeared since the last fetch — which makes it cheap enough to take
# on every sample instead of every half hour.
#
# No event-ID filter. The previous version kept a hand-picked subset and capped
# at 300 events, and in a twelve-hour window that silently dropped most of the
# record: ten disconnects and seven failed connects had been reduced to two
# entries. A monitor whose whole purpose is a complete timeline cannot decide
# in advance which transitions matter.
$o.wlanlog = @(Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'
    StartTime=__SINCE__} -MaxEvents 4000 -EA SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ id=$_.Id
                                      time=$_.TimeCreated.ToString('o')
                                      msg=($_.Message -replace "`r`n",' ') }})

# The profile service sees every adapter, wired included, so a link that drops
# outside the wireless stack still lands in the timeline.
$o.netprofile = @(Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-NetworkProfile/Operational'
    StartTime=__SINCE__} -MaxEvents 1000 -EA SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ id=$_.Id
                                      time=$_.TimeCreated.ToString('o')
                                      msg=($_.Message -replace "`r`n",' ') }})

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
