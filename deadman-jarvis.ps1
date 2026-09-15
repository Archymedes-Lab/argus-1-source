# Independent Windows monitor: all runtime files live in LocalAppData.
param([switch]$Install, [switch]$ProbeOnly, [switch]$TestNotification,
      [string]$StateRoot = (Join-Path $env:LOCALAPPDATA 'Jarvis\Deadman'))
$ErrorActionPreference='Stop'
$taskName='JARVIS independent health monitor'
$appId='JARVIS.Monitor'

function Save-State($state) {
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $StateRoot 'state.json.new') -Encoding UTF8
    Move-Item -LiteralPath (Join-Path $StateRoot 'state.json.new') -Destination (Join-Path $StateRoot 'state.json') -Force
}
function Show-JarvisToast([string]$title,[string]$body) {
    [void][Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
    [void][Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
    $xml=New-Object Windows.Data.Xml.Dom.XmlDocument
    $t=[Security.SecurityElement]::Escape($title);$b=[Security.SecurityElement]::Escape($body)
    $xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>")
    $toast=[Windows.UI.Notifications.ToastNotification]::new($xml)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
}
function Send-JarvisMail([string]$title,[string]$body) {
    # Raw HttpWebRequest for the same reason as the health probe below:
    # Invoke-RestMethod can block on proxy and first-run state under Task
    # Scheduler. TLS 1.2 is required by the mail API and is not guaranteed to
    # be enabled for Windows PowerShell 5.1 by default.
    [Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $cfg=Get-Content -LiteralPath (Join-Path $StateRoot 'mail.json') -Raw | ConvertFrom-Json
    $secure=ConvertTo-SecureString $cfg.key
    $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $key=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        $json=@{from=$cfg.from;to=@($cfg.to);subject=$title;text=$body}|ConvertTo-Json -Compress
        $bytes=[Text.Encoding]::UTF8.GetBytes($json)
        $req=[Net.HttpWebRequest]::Create('https://api.resend.com/emails')
        $req.Method='POST'; $req.Proxy=$null; $req.Timeout=20000; $req.ReadWriteTimeout=20000
        $req.ContentType='application/json'; $req.Headers['Authorization']='Bearer '+$key
        $stream=$req.GetRequestStream()
        try {$stream.Write($bytes,0,$bytes.Length)} finally {$stream.Dispose()}
        $req.GetResponse().Dispose()
    } finally {[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr);$key=$null}
}
function Get-MailFailure($err) {
    # Why delivery failed, without anything from the request or the key: the
    # HTTP status when the API answered, otherwise the network failure kind.
    $e=$err.Exception
    while ($e.InnerException -and -not ($e -is [Net.WebException])) {$e=$e.InnerException}
    if ($e -is [Net.WebException]) {
        if ($e.Response) {return 'mail API answered HTTP '+[int]$e.Response.StatusCode}
        return 'network: '+$e.Status
    }
    return $e.GetType().Name
}
function Get-JarvisHealth {
    # Raw HttpWebRequest, not Invoke-RestMethod. Under Task Scheduler the
    # cmdlet consults the system proxy and Internet Explorer first-run state,
    # and in a hidden non-interactive session that can block past any
    # -TimeoutSec, leaving the task stuck 'Running'. With MultipleInstances
    # IgnoreNew every later trigger is then refused (0x800710E0) and the
    # dead-man's switch silently stops checking -- the exact failure it exists
    # to catch. Proxy is disabled explicitly: this call never leaves the host.
    try {
        $req=[Net.HttpWebRequest]::Create('http://127.0.0.1:8787/api/health')
        $req.Proxy=$null; $req.Timeout=8000; $req.ReadWriteTimeout=8000
        $req.Method='GET'; $req.KeepAlive=$false
        $resp=$req.GetResponse()
        try {
            $reader=New-Object IO.StreamReader($resp.GetResponseStream())
            try {$h=$reader.ReadToEnd()|ConvertFrom-Json} finally {$reader.Dispose()}
        } finally {$resp.Dispose()}
        $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ($h.service -ne 'JARVIS' -or $h.healthy -ne $true -or $h.protection_healthy -ne $true -or
            $null -eq $h.time -or [math]::Abs($now-[double]$h.time) -gt 120 -or
            $null -eq $h.progress_age -or [double]$h.progress_age -ge 900) {
            return @{healthy=$false;reason='JARVIS reports stale or invalid scheduler health'}
        }
        return @{healthy=$true;reason='scheduler progress and required protection coverage verified';progress_age=$h.progress_age}
    } catch [Net.WebException] {
        # 503 can mean lost coverage while the scheduler is still alive.
        $r=$_.Exception.Response
        if ($r -and [int]$r.StatusCode -eq 503) {
            try {
                $reader=New-Object IO.StreamReader($r.GetResponseStream())
                try {$h=$reader.ReadToEnd()|ConvertFrom-Json} finally {$reader.Dispose();$r.Dispose()}
                if ($h.live -eq $true) {
                    return @{healthy=$false;reason='JARVIS is running but required protection coverage is unavailable'}
                }
            } catch {}
            return @{healthy=$false;reason='JARVIS reports unavailable service or protection coverage'}
        }
        return @{healthy=$false;reason='JARVIS local health endpoint is unreachable'}
    } catch {return @{healthy=$false;reason='JARVIS health probe failed: '+$_.Exception.GetType().Name}}
}

if ($Install) {
    [void](New-Item -ItemType Directory -Path $StateRoot -Force)
    $registry="HKCU:\Software\Classes\AppUserModelId\$appId"
    [void](New-Item -Path $registry -Force)
    [void](New-ItemProperty -Path $registry -Name DisplayName -Value 'JARVIS' -PropertyType String -Force)
    [void](New-ItemProperty -Path $registry -Name ShowInSettings -Value 1 -PropertyType DWord -Force)
    $script=Join-Path $StateRoot 'deadman-jarvis.ps1'
    if ($MyInvocation.MyCommand.Path -ne $script) {Copy-Item -LiteralPath $MyInvocation.MyCommand.Path -Destination $script -Force}
    # conhost --headless: -WindowStyle Hidden alone still flashes a console window each run.
    $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\conhost.exe" -Argument ('--headless "'+"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"+'" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$script+'"')
    $triggers=@((New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)))
    $principal=New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
    # The limit must exceed the one-minute repeat, not equal it. At PT1M a
    # run that is merely slow -- PowerShell start-up plus a WinRT load on a
    # loaded machine -- is killed at the boundary and every run records
    # SCHED_S_TASK_TERMINATED (0x41306), which hides a genuine failure
    # behind a result code that is always the same. IgnoreNew already stops
    # slow runs from piling up.
    $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    [void](Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force)
    Write-Output 'Independent Windows monitor installed. Credentials must be staged separately with DPAPI.'
    return
}
if ($ProbeOnly) {Get-JarvisHealth | ConvertTo-Json -Compress;return}
if ($TestNotification) {
    Show-JarvisToast 'JARVIS notification test' 'The independent Windows notification path is working. This is a test.'
    Write-Output 'Test toast submitted to Windows.';return
}

[void](New-Item -ItemType Directory -Path $StateRoot -Force)
$state=@{failures=0;firstFailure=0;emailLevel=-1;toastLevel=-1;lastMailAttempt=0;lastToastAttempt=0;lastHealthy=0}
$saved=Join-Path $StateRoot 'state.json'
if (Test-Path -LiteralPath $saved) {
    try {
        $old=Get-Content -LiteralPath $saved -Raw | ConvertFrom-Json
        foreach ($p in $old.PSObject.Properties) {$state[$p.Name]=$p.Value}
    } catch {$state.stateError='Previous state was unreadable; outage confirmation restarted'}
}
$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$health=Get-JarvisHealth
$state.checkedAt=$now;$state.healthy=$health.healthy;$state.reason=$health.reason
if ($health.healthy) {
    $state.lastHealthy=$now
    if ($state.emailLevel -ge 0 -or $state.toastLevel -ge 0) {
        if ($state.toastLevel -ge 0) {
            try {Show-JarvisToast 'JARVIS recovered' 'The independent Windows monitor verified scheduler progress.';$state.toastLevel=-1}
            catch {$state.toastError=$_.Exception.Message}
        }
        if ($state.emailLevel -ge 0 -and $now-$state.lastMailAttempt -ge 300) {
            $state.lastMailAttempt=$now
            try {Send-JarvisMail '[JARVIS] monitor recovered' 'The independent Windows monitor verified that JARVIS is reachable and its scheduler is progressing.';$state.emailLevel=-1;$state.mailError=''}
            catch {$state.mailError='Recovery email failed ('+(Get-MailFailure $_)+'); queued for retry'}
        }
    } elseif ($state.mailError -and $now-[long]$state.lastMailAttempt -ge 3600) {
        # An outage mail that failed leaves emailLevel at -1, so nothing above
        # would ever retry and the error would stay stale. Only a delivered
        # message proves the path again; retry at most hourly while healthy.
        $state.lastMailAttempt=$now
        try {Send-JarvisMail '[JARVIS] alert email path restored' 'The independent Windows monitor failed to send an earlier email. Delivery is working again and JARVIS is healthy.';$state.mailError=''}
        catch {$state.mailError='Email delivery still failing ('+(Get-MailFailure $_)+'); retrying hourly. No credential data logged.'}
    }
    $state.failures=0;$state.firstFailure=0
} else {
    if (-not $state.firstFailure) {$state.firstFailure=$now}
    $state.failures=[int]$state.failures+1
    $age=$now-[long]$state.firstFailure
    if ($state.failures -ge 2 -and $age -ge 60) {
        $level=0
        foreach ($threshold in @(3600,21600,86400)) {if ($age -ge $threshold) {$level++}}
        $title='[JARVIS] monitoring unavailable'
        $body="The independent Windows monitor cannot verify JARVIS. Failure duration: $([int]($age/60)) minutes. $($health.reason). Open Ubuntu and run: jarvis selfcheck. Escalation level: $level."
        if ($level -gt $state.toastLevel -and $now-$state.lastToastAttempt -ge 300) {
            $state.lastToastAttempt=$now
            try {Show-JarvisToast 'JARVIS monitoring unavailable' $body;$state.toastLevel=$level;$state.toastError=''}
            catch {$state.toastError=$_.Exception.Message}
        }
        if ($level -gt $state.emailLevel -and $now-$state.lastMailAttempt -ge 300) {
            $state.lastMailAttempt=$now
            try {Send-JarvisMail $title $body;$state.emailLevel=$level;$state.mailError=''}
            catch {$state.mailError='Outage email failed ('+(Get-MailFailure $_)+'); queued for retry. No credential data logged.'}
        }
    }
}
Save-State $state
