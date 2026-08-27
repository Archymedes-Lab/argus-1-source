"""Windows security posture: what is on, what is off, and what it should be.

Every other module asks whether something bad is present. This one asks whether
the defenses that would have stopped it are switched on — and says what to set
when they are not, because "SmartScreen is off" is only useful if you also know
what to turn on.

On activation, since it is the question everyone asks: **an unactivated Windows
is not an insecure Windows.** Activation gates personalisation, not security.
Defender still runs, Windows Update still delivers security patches, and the
firewall still works. What actually carries risk is the method used to activate
— a script piped from the internet into an elevated shell is a total-trust
event regardless of what it does afterwards. So this module reports the
activation *state* as information, and treats the activation *method* as the
thing worth thinking about.

Each finding names the setting to change rather than just the problem. The
severities reflect exploitability on a personal workstation, not a domain
controller: Memory Integrity being off is common and worth fixing; Tamper
Protection being off means malware can switch Defender off silently, which is
worse than it sounds.
"""

import os
import subprocess

from . import collect_windows
from .control import _aslist, _ps_json

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CAT_ORDER = {"malware defense": 0, "platform integrity": 1, "data at rest": 2,
             "account & access": 3, "attack surface": 4, "visibility": 5,
             "licensing": 6}


def _finding(category, severity, title, detail, fix="", host="win"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail + (f"  →  {fix}" if fix else ""),
            "where": fix, "host": host}


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

# The five ASR rules that matter most on a workstation that runs Office and a
# browser, by GUID. There are more; these are the ones whose absence shows up
# in real intrusion reports.
ASR_KEY = {
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a":
        "block Office apps creating child processes",
    "3b576869-a4ec-4529-8536-b80a7769e899":
        "block Office apps creating executable content",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc":
        "block obfuscated scripts",
    "d3e037e1-3eb8-44c8-a917-57927947596d":
        "block JS/VBS launching downloaded content",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2":
        "block credential theft from LSASS",
    "01443614-cd74-433a-b99e-2ecdc07bfc25":
        "block executables unless they meet prevalence/age criteria",
    "56a863a9-875e-4185-98a7-b882c64b5ce5":
        "block abuse of vulnerable signed drivers",
}


def _truthy(v):
    """Registry booleans are not always 1.

    RunAsPPL is 2 when LSA protection is enabled with a UEFI lock, which is the
    *stronger* setting — reading only "1" as true reported a hardened machine
    as unprotected.
    """
    t = str(v).strip().lower()
    if t in ("true", "yes", "on"):
        return True
    try:
        return int(t) > 0
    except (TypeError, ValueError):
        return False


def _unreadable(v):
    """PowerShell returns a human sentence instead of data when not elevated."""
    if v is None:
        return True
    t = str(v)
    return ("must be an administrator" in t.lower()
            or "access is denied" in t.lower()
            or t.strip() in ("", "N/A"))


def _win_temp():
    r"""%LOCALAPPDATA%\Temp as both a Windows path and a WSL path."""
    out = _ps_json(
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
    script_wsl = os.path.join(wsl_tmp, "sentry_posture.ps1")
    out_wsl = os.path.join(wsl_tmp, "sentry_posture.b64")
    script_win = win_tmp + r"\sentry_posture.ps1"
    out_win = win_tmp + r"\sentry_posture.b64"

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
        with open(out_wsl) as fh:
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


def audit(hosts=("win",), elevate=False):
    if "win" not in hosts:
        return []
    elev_err = ""
    d = None
    if elevate:
        d, elev_err = elevated_data()
    if d is None:
        d = _ps_json(PS_POSTURE, timeout=400)
    if not d:
        return [_finding("visibility", "medium", "posture audit unavailable",
                         "powershell.exe returned no data")]
    out = []
    if elevate and elev_err:
        out.append(_finding(
            "visibility", "medium", "elevated audit did not run",
            f"{elev_err} — falling back to the unelevated result, so the "
            f"checks that need administrator remain unread"))

    # ── malware defense ───────────────────────────────────────────────────
    dfn = d.get("defender") or {}
    pref = d.get("mppref") or {}
    mode = str(dfn.get("AMRunningMode") or "")
    if not dfn:
        out.append(_finding("malware defense", "high",
                            "Defender status could not be read",
                            "another product may have replaced it"))
    else:
        if not dfn.get("RealTimeProtectionEnabled"):
            out.append(_finding(
                "malware defense", "critical", "real-time protection is off",
                "nothing is scanning files as they are written",
                "Set-MpPreference -DisableRealtimeMonitoring $false"))
        if not dfn.get("IsTamperProtected"):
            out.append(_finding(
                "malware defense", "high", "Tamper Protection is off",
                "without it, code running as admin can silently disable "
                "Defender — which is the first thing most intrusions do",
                "Windows Security > Virus & threat protection > "
                "Manage settings > Tamper Protection ON"))
        age = dfn.get("AntivirusSignatureAge")
        if isinstance(age, int) and age > 3:
            out.append(_finding(
                "malware defense", "high" if age > 14 else "medium",
                f"malware signatures are {age} days old",
                "signature updates ship several times a day",
                "Update-MpSignature"))
        if not dfn.get("BehaviorMonitorEnabled"):
            out.append(_finding(
                "malware defense", "high", "behaviour monitoring is off",
                "signature-only detection misses anything novel",
                "Set-MpPreference -DisableBehaviorMonitoring $false"))
        if mode and mode.lower() not in ("normal", "0"):
            out.append(_finding(
                "malware defense", "medium",
                f"Defender is running in {mode} mode",
                "passive mode means it is not the primary protection"))

    if str(pref.get("PUAProtection")) not in ("1", "True"):
        out.append(_finding(
            "malware defense", "medium",
            "potentially-unwanted-application blocking is not enabled",
            "Defender has already flagged two PUA bundlers on this machine",
            "Set-MpPreference -PUAProtection Enabled"))
    if str(pref.get("EnableNetworkProtection")) not in ("1", "True"):
        out.append(_finding(
            "malware defense", "medium", "Network Protection is not enabled",
            "blocks outbound connections to known-malicious hosts at the OS level",
            "Set-MpPreference -EnableNetworkProtection Enabled"))
    if str(pref.get("EnableControlledFolderAccess")) not in ("1", "True"):
        out.append(_finding(
            "malware defense", "low", "Controlled Folder Access is off",
            "this is the anti-ransomware guard on Documents and similar folders",
            "Set-MpPreference -EnableControlledFolderAccess Enabled"))

    excl = _aslist(pref.get("ExclusionPath")) + _aslist(pref.get("ExclusionProcess"))
    real_excl = [e for e in excl if not _unreadable(e)]
    if excl and not real_excl:
        out.append(_finding(
            "visibility", "medium", "Defender exclusions are not readable",
            "listing exclusions needs an elevated shell — an excluded path is "
            "invisible to scanning, so this is worth checking by hand",
            "run `sentry posture` from an elevated PowerShell"))
    for e in real_excl:
        out.append(_finding(
            "malware defense", "high", f"Defender exclusion: {e}",
            "an excluded path is not scanned at all; malware that finds an "
            "exclusion list will use it"))

    ids = [str(x).lower() for x in _aslist(pref.get("AttackSurfaceReductionRules_Ids"))]
    actions = _aslist(pref.get("AttackSurfaceReductionRules_Actions"))
    enabled = {i for i, a in zip(ids, actions) if str(a) == "1"}
    missing = [(g, n) for g, n in ASR_KEY.items() if g not in enabled]
    if missing:
        out.append(_finding(
            "attack surface", "medium",
            f"{len(missing)} of {len(ASR_KEY)} key ASR rules are not enforcing",
            "; ".join(n for _, n in missing[:4])
            + ("; …" if len(missing) > 4 else ""),
            "Add-MpPreference -AttackSurfaceReductionRules_Ids <guid> "
            "-AttackSurfaceReductionRules_Actions Enabled"))

    # ── platform integrity ────────────────────────────────────────────────
    sb = d.get("secureboot")
    if sb is False:
        out.append(_finding(
            "platform integrity", "high", "Secure Boot is off",
            "the boot chain is not verified, which is what a bootkit needs",
            "enable Secure Boot in UEFI firmware settings"))
    elif sb is None:
        out.append(_finding("platform integrity", "low",
                            "Secure Boot state could not be read",
                            "usually means a legacy/BIOS boot"))

    tpm = d.get("tpm") or {}
    if tpm.get("TpmPresent") is None:
        out.append(_finding(
            "visibility", "low", "TPM state is not readable",
            "Get-Tpm needs an elevated shell — this is not the same as the "
            "TPM being absent, and the difference matters for BitLocker",
            "run elevated to confirm"))
    elif not tpm.get("TpmPresent"):
        out.append(_finding("platform integrity", "medium", "no TPM present",
                            "BitLocker and Credential Guard both rely on it"))
    elif not tpm.get("TpmReady"):
        out.append(_finding("platform integrity", "medium", "the TPM is not ready",
                            "present but not initialised"))

    dg = d.get("deviceguard") or {}
    running = {str(x) for x in _aslist(dg.get("running"))}
    if str(dg.get("vbs")) not in ("2",):
        out.append(_finding(
            "platform integrity", "medium",
            "virtualisation-based security is not running",
            "VBS underpins Memory Integrity and Credential Guard",
            "Windows Security > Device security > Core isolation"))
    if "2" not in running:
        out.append(_finding(
            "platform integrity", "medium", "Memory Integrity (HVCI) is off",
            "HVCI is what stops an unsigned or vulnerable driver loading into "
            "the kernel — the BYOVD technique this machine's own audits look for",
            "Windows Security > Device security > Core isolation > "
            "Memory integrity ON"))
    if "1" not in running:
        out.append(_finding(
            "account & access", "medium", "Credential Guard is not running",
            "without it, credentials in LSASS can be read by admin-level code",
            "Core isolation, or the Device Guard policy"))

    if not _truthy((d.get("lsa") or {}).get("runasppl")):
        out.append(_finding(
            "account & access", "medium", "LSA protection (RunAsPPL) is off",
            "LSA runs unprotected, so tools like mimikatz can open it",
            r"reg add HKLM\System\CurrentControlSet\Control\Lsa "
            r"/v RunAsPPL /t REG_DWORD /d 1"))

    # ── data at rest ──────────────────────────────────────────────────────
    vols = _aslist(d.get("bitlocker"))
    if not vols:
        out.append(_finding(
            "visibility", "medium", "BitLocker status is not readable",
            "Get-BitLockerVolume needs elevation. Unreadable is not the same "
            "as unencrypted — but if this drive is not encrypted, anyone with "
            "physical access can read the .env secrets and credential-vault "
            "files in your project directories",
            "run elevated, or check Settings > Privacy & security > "
            "Device encryption"))
    for v in vols:
        if v.get("mount", "").upper().startswith("C") and \
                str(v.get("status")).lower() not in ("on", "1"):
            out.append(_finding(
                "data at rest", "high",
                f"the system drive {v.get('mount')} is not encrypted",
                "anyone with physical access can read this disk from another "
                "machine — including the .env secrets and credential vault "
                "in your project directories",
                "manage-bde -on C: (or Settings > Device encryption)"))

    # ── account & access ──────────────────────────────────────────────────
    uac = d.get("uac") or {}
    if uac.get("enabled") is not None and not _truthy(uac.get("enabled")):
        out.append(_finding("account & access", "critical", "UAC is disabled",
                            "every process runs elevated without a prompt",
                            "set EnableLUA to 1 and reboot"))
    elif str(uac.get("consent")) == "0":
        out.append(_finding(
            "account & access", "high", "UAC never prompts for elevation",
            "ConsentPromptBehaviorAdmin=0 elevates silently",
            "set ConsentPromptBehaviorAdmin to 2 (prompt on secure desktop)"))

    al = d.get("autologon") or {}
    if _truthy(al.get("auto")):
        detail = "this machine logs in without a password"
        if al.get("pwd"):
            detail += " and the password is stored in the registry in cleartext"
        out.append(_finding("account & access", "high",
                            "automatic logon is enabled", detail,
                            "remove AutoAdminLogon and DefaultPassword"))

    for u in _aslist(d.get("users")):
        # PasswordRequired is False for any account backed by a Microsoft
        # account or signing in with a PIN, which is the normal case on a
        # personal Windows 11 machine — it does not mean there is no password.
        if u.get("enabled") and not u.get("pwdreq") and not u.get("lastpwd"):
            out.append(_finding(
                "account & access", "low",
                f"account '{u.get('name')}' has no local password set",
                "normal for a Microsoft-account or PIN login; a real finding "
                "only if this is a local-only account"))
    admins = [a.get("name", "") for a in _aslist(d.get("admins"))]
    if len(admins) > 3:
        out.append(_finding(
            "account & access", "low",
            f"{len(admins)} accounts are local administrators",
            ", ".join(a.split("\\")[-1] for a in admins[:6])))

    # ── attack surface ────────────────────────────────────────────────────
    if d.get("smb1") is None:
        out.append(_finding(
            "visibility", "low", "SMBv1 feature state is not readable",
            "needs elevation to query optional features"))
    elif str(d.get("smb1")).lower() == "enabled":
        out.append(_finding(
            "attack surface", "critical", "SMBv1 is installed",
            "the protocol WannaCry and NotPetya spread over; nothing needs it",
            "Disable-WindowsOptionalFeature -Online "
            "-FeatureName SMB1Protocol"))
    rdp = d.get("rdp") or {}
    if rdp.get("denied") is not None and str(rdp.get("denied")) == "0":
        sev = "high" if str(rdp.get("nla")) != "1" else "medium"
        out.append(_finding(
            "attack surface", sev, "Remote Desktop is enabled",
            "inbound RDP is one of the most attacked services on the internet"
            + ("; network-level authentication is also off" if sev == "high" else ""),
            "disable RDP, or require NLA and never expose it directly"))
    # ServiceControllerStatus: 1 = Stopped, 4 = Running.
    if str(d.get("winrm")).lower() in ("running", "4"):
        out.append(_finding(
            "attack surface", "medium", "WinRM is running",
            "remote PowerShell is a lateral-movement path",
            "Stop-Service WinRM; Set-Service WinRM -StartupType Disabled"))
    ss = str(d.get("smartscreen_shell") or d.get("smartscreen") or "")
    if ss.lower() in ("off", "0"):
        out.append(_finding(
            "attack surface", "medium", "SmartScreen is off",
            "downloaded executables are not reputation-checked",
            "Windows Security > App & browser control > "
            "Reputation-based protection"))

    # ── visibility ────────────────────────────────────────────────────────
    ps = d.get("pslog") or {}
    if not _truthy(ps.get("scriptblock")):
        out.append(_finding(
            "visibility", "medium", "PowerShell script block logging is off",
            "this is the single most useful log for reconstructing what an "
            "attacker ran — and this machine has already had a remote script "
            "piped into an elevated shell",
            r"reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell"
            r"\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1"))
    if not _truthy(ps.get("transcript")):
        out.append(_finding(
            "visibility", "low", "PowerShell transcription is off",
            "transcripts record command output, not just the commands",
            "enable Transcription policy with an output directory"))

    upd = d.get("updates") or {}
    hot = _aslist(d.get("hotfix"))
    if hot:
        out.append(_finding(
            "visibility", "ok",
            f"most recent update {hot[0].get('id')} on {hot[0].get('on', '')[:10]}",
            f"last successful search {str(upd.get('lastsearch') or '?')[:19]}"))
    else:
        out.append(_finding("visibility", "medium",
                            "no installed updates could be listed",
                            "update history is unreadable"))

    # ── licensing ─────────────────────────────────────────────────────────
    for lic in _aslist(d.get("license")):
        status = lic.get("status")
        name = (lic.get("name") or "Windows")[:60]
        if status == 1:
            out.append(_finding(
                "licensing", "ok", f"Windows is activated ({name})",
                "activation state does not affect security posture either way"))
        else:
            states = {0: "unlicensed", 2: "in grace period",
                      3: "additional grace", 4: "non-genuine grace",
                      5: "notification mode", 6: "extended grace"}
            out.append(_finding(
                "licensing", "low",
                f"Windows is not activated ({states.get(status, status)})",
                "this does not reduce security: Defender, Windows Update and "
                "the firewall all keep working unactivated. What matters is "
                "how activation is attempted — a script piped from the web "
                "into an elevated shell is a full-trust event, and this "
                "machine's PowerShell history shows exactly that"))
    return sort_findings(out)


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9), x["title"]))
