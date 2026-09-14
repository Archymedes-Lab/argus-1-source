"""Reading the posture sample from Windows, unelevated or through one UAC prompt."""

import os
import subprocess

from jarvis.platform import windows as collect_windows
from jarvis.platform.windows import ps_json

PS_POSTURE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$o.defender = Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,
  IoavProtectionEnabled, AntispywareEnabled, BehaviorMonitorEnabled,
  OnAccessProtectionEnabled, TamperProtectionSource, IsTamperProtected,
  AntivirusSignatureAge, AntispywareSignatureAge, AMServiceEnabled,
  NISEnabled, QuickScanAge, FullScanAge, AMRunningMode

$o.mppref = Get-MpPreference | Select-Object MAPSReporting, SubmitSamplesConsent,
  PUAProtection, EnableControlledFolderAccess, EnableNetworkProtection,
  DisableRealtimeMonitoring, ExclusionPath, ExclusionProcess,
  AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions,
  ScanAvgCPULoadFactor

$o.license = @(Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey is not null" |
  Where-Object { $_.ApplicationId -eq '55c92734-d682-4d71-983e-d6ec3f16059f' } |
  ForEach-Object { [pscustomobject]@{ name=[string]$_.Name
                                      status=[int]$_.LicenseStatus
                                      desc=[string]$_.Description
                                      grace=[int]$_.GracePeriodRemaining }})

$o.secureboot = try { [bool](Confirm-SecureBootUEFI) } catch { $null }
$o.tpm = Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, ManagedAuthLevel

$dg = Get-CimInstance -ClassName Win32_DeviceGuard `
      -Namespace root\Microsoft\Windows\DeviceGuard
$o.deviceguard = [pscustomobject]@{
  vbs=[int]$dg.VirtualizationBasedSecurityStatus
  running=@($dg.SecurityServicesRunning)
  configured=@($dg.SecurityServicesConfigured)
}

$o.bitlocker = @(Get-BitLockerVolume | ForEach-Object {
  [pscustomobject]@{ mount=[string]$_.MountPoint
                     status=[string]$_.ProtectionStatus
                     method=[string]$_.EncryptionMethod
                     pct=[int]$_.EncryptionPercentage }})

function RVal($p,$n){ (Get-ItemProperty -Path $p -Name $n).$n }
$sys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
$o.uac = [pscustomobject]@{
  enabled=RVal $sys 'EnableLUA'
  consent=RVal $sys 'ConsentPromptBehaviorAdmin'
  securedesktop=RVal $sys 'PromptOnSecureDesktop'
}
$o.lsa = [pscustomobject]@{
  runasppl=RVal 'HKLM:\System\CurrentControlSet\Control\Lsa' 'RunAsPPL'
  restrictanon=RVal 'HKLM:\System\CurrentControlSet\Control\Lsa' 'RestrictAnonymous'
}
$o.smartscreen = [string](RVal 'HKLM:\Software\Policies\Microsoft\Windows\System' 'EnableSmartScreen')
$o.smartscreen_shell = [string](RVal 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled')

$o.smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
$o.smbsign = Get-SmbClientConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
$o.rdp = [pscustomobject]@{
  denied=RVal 'HKLM:\System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
  nla=RVal 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
}
$o.winrm = (Get-Service WinRM).Status

$o.pslog = [pscustomobject]@{
  scriptblock=RVal 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
  module=RVal 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
  transcript=RVal 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
}

$o.consolehost = [pscustomobject]@{
  console=[string](RVal 'HKCU:\Console\%%Startup' 'DelegationConsole')
  terminal=[string](RVal 'HKCU:\Console\%%Startup' 'DelegationTerminal')
}

$o.autologon = [pscustomobject]@{
  user=[string](RVal 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultUserName')
  auto=[string](RVal 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon')
  pwd=[string](RVal 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword')
}

$o.admins = @(Get-LocalGroupMember -Group 'Administrators' |
  ForEach-Object { [pscustomobject]@{ name=[string]$_.Name
                                      source=[string]$_.PrincipalSource }})
$o.users = @(Get-LocalUser | ForEach-Object {
  [pscustomobject]@{ name=[string]$_.Name; enabled=[bool]$_.Enabled
                     pwdreq=[bool]$_.PasswordRequired
                     lastpwd=[string]$_.PasswordLastSet }})

$o.updates = [pscustomobject]@{
  lastsearch=[string](New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate
  lastinstall=[string](New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate
}
$o.hotfix = @(Get-HotFix | Sort-Object InstalledOn -Descending |
  Select-Object -First 3 | ForEach-Object {
    [pscustomobject]@{ id=[string]$_.HotFixID
                       on=[string]$_.InstalledOn }})

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""


def _win_temp():
    r"""%LOCALAPPDATA%\Temp as both a Windows path and a WSL path."""
    out = ps_json(
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{t=$env:TEMP})))", timeout=60)
    win = (out or {}).get("t") or r"C:\Windows\Temp"
    p = win.replace("\\", "/")
    wsl = "/mnt/" + p[0].lower() + p[2:] if len(p) > 2 and p[1] == ":" else "/tmp"
    return win, wsl


def elevated_data(timeout=300):
    """Re-run the collector through a UAC prompt.

    Several of the most important checks — BitLocker, TPM, Defender's exclusion
    list, optional features — return nothing at all without elevation, and
    "nothing" is indistinguishable from "clean" unless something asks properly.
    There is no way to elevate from inside WSL without a consent prompt, so
    this writes the same script to disk, asks Windows to run it as
    administrator, and reads the result back.

    Returns (data, error). The prompt is user-visible and cancellable; a
    cancelled prompt is an error, not an empty result.
    """
    if not collect_windows.available():
        return None, "the Windows interop bridge is not available"
    win_tmp, wsl_tmp = _win_temp()
    script_wsl = os.path.join(wsl_tmp, "jarvis_posture.ps1")
    out_wsl = os.path.join(wsl_tmp, "jarvis_posture.b64")
    script_win = win_tmp + r"\jarvis_posture.ps1"
    out_win = win_tmp + r"\jarvis_posture.b64"

    for stale in (out_wsl,):
        try:
            os.unlink(stale)
        except OSError:
            pass
    try:
        # UTF-8 with BOM so PowerShell reads the file in the right encoding.
        with open(script_wsl, "w", encoding="utf-8-sig") as fh:
            fh.write(PS_POSTURE.replace(
                "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))",
                "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)) "
                "| Set-Content -Path '" + out_win + "' -Encoding ascii"))
    except OSError as exc:
        return None, f"could not stage the elevated script: {exc}"

    launcher = (
        "$p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru "
        "-WindowStyle Hidden -ArgumentList "
        "'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',"
        "'-File','" + script_win + "'; exit $p.ExitCode")
    try:
        subprocess.run([collect_windows._PS, "-NoProfile", "-NonInteractive",
                        "-Command", launcher],
                       capture_output=True, timeout=timeout, cwd="/")
    except subprocess.TimeoutExpired:
        return None, "timed out waiting for the elevation prompt"
    except OSError as exc:
        return None, f"could not launch an elevated shell: {exc}"

    try:
        with open(out_wsl, errors="replace") as fh:
            blob = fh.read().strip().replace("\r", "").replace("\n", "")
    except OSError:
        return None, ("no elevated result was produced — the UAC prompt was "
                      "most likely declined or dismissed")
    if not blob:
        return None, "the elevated run produced an empty result"
    try:
        import base64
        import json as _json
        return _json.loads(base64.b64decode(blob).decode("utf-8", "replace")), ""
    except Exception as exc:
        return None, f"could not decode the elevated result: {exc}"
    finally:
        for f in (script_wsl, out_wsl):
            try:
                os.unlink(f)
            except OSError:
                pass
