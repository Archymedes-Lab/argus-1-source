# Windows commands: make spyware hard to run here (2026-10-21)

Every value below was read from this machine on 2026-10-21 (build 26200.9711, 25H2,
13th-gen Core i5 with CET). Order follows the ORION prioritisation in
[SPYWARE-DEFENSE-2026-10-21](../architecture/SPYWARE-DEFENSE-2026-10-21.md) §3b, with the
JARVIS-side items that need a release marked as such. Nothing here is automatic: run each
block yourself, read the verification line, and keep the rollback.

**Applied 2026-10-21 17:04** by one elevated run of `scripts/harden/harden-antispyware.ps1`
(receipt and the previous values in `%LOCALAPPDATA%\Jarvis\Hardening`; `-Undo` restores them):
blocks 3, 4, 5 (user-mode part), 6, 7 and 9 below, 21 of 22 steps verified by readback. The
one failure was harmless: the PowerShell 2.0 feature does not exist on this build. Defender
exclusions read back empty (the earlier "1 of each" was the unelevated "N/A" placeholder).
Still yours: block 1 (Smart App Control, Windows Security app), block 5's kernel stack
protection (`-KernelCET`, reboot), block 8 (microphone and camera consent), block 10, and the
JARVIS release in block 11.

Rules of the road:

- **Elevated** means an elevated PowerShell (Win+X, Terminal (Admin)). **User** means your
  normal PowerShell. Do not pipe a remote script into either.
- Every change is reversible with the rollback shown. Reboot only where stated.
- After each block, JARVIS should report the new value within one posture cycle (2 h) or
  after `jarvis run posture`. A command that succeeded is not proof; the readback is.
- Nothing here can stop a kernel driver, a hardware keylogger or an administrator. See §5 of
  the defense document for what stays inherent.

## 0. Take a restore point and snapshot current state (elevated, 2 min)

```powershell
Enable-ComputerRestore -Drive "C:\"
Checkpoint-Computer -Description "pre-spyware-hardening-2026-10-21" -RestorePointType MODIFY_SETTINGS
$snap = "$env:LOCALAPPDATA\Jarvis\Hardening\snapshot-$(Get-Date -Format yyyyMMdd-HHmm)"
New-Item -ItemType Directory -Force -Path $snap | Out-Null
Get-MpPreference | ConvertTo-Json -Depth 4 | Set-Content "$snap\mppreference.json"
Get-ProcessMitigation -System | Out-String | Set-Content "$snap\process-mitigation.txt"
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "$snap\policies-system.reg" /y
reg export "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "$snap\deviceguard.reg" /y
reg export "HKLM\SOFTWARE\Policies\Microsoft\Edge" "$snap\edge-policies.reg" /y 2>$null
reg export "HKLM\SOFTWARE\Policies\Google\Chrome" "$snap\chrome-policies.reg" /y 2>$null
"snapshot in $snap"
```

Rollback for everything in this file starts from that folder.

## 1. Smart App Control (Windows Security app, 5 min, no reboot)

Live: `VerifiedAndReputablePolicyState = 0` (off). SAC blocks unsigned, unknown binaries, the
carrier for nearly every commodity stealer. Since the April 2026 update it can be turned on
without reinstalling; it starts in evaluation mode and only enforces if it judges your
workload compatible. It has no supported command: open the setting.

```powershell
Start-Process "windowsdefender://appbrowser"
# App & browser control > Smart App Control settings > On (or Evaluation)
```

Verify (user):

```powershell
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy").VerifiedAndReputablePolicyState
# 2 = evaluation, 1 = on, 0 = off
```

Know before you flip it: unsigned binaries you built yourself and unsigned developer tools
stop running under "On". Try evaluation first for a week. If the toggle is greyed out,
October's KB5127648 is the known cause; install the fix Microsoft shipped for it before
retrying. Rollback: the same page, Off (one-way on older builds; reversible on this one).

## 2. Administrator Protection: not on this machine yet (read, do not run)

Live: `TypeOfAdminApprovalMode = 1` (classic UAC). ORION gave this measure the highest
leverage and P(first), and it is the one that would stop malware running as you from silently
using your admin token. Microsoft's documentation (read 2026-10-21, page dated 2026-10-13)
rules it out here for now:

- "When not to enable this feature: ... For devices that require Hyper-V." WSL 2, which runs
  JARVIS, is a Hyper-V virtual machine.
- "If you are using development tools or environments like Windows Subsystem for Linux (WSL)
  ... you will need to reinstall and configure the distro in the elevated profile separately."
  The elevated broker, reviver and health monitor run elevated and read this WSL distro; under
  profile separation they would see an empty profile.
- Settings do not carry across the unelevated and elevated profiles; network drives are not
  reachable from elevated apps; a September fix (KB5124010) is still needed for RDP and
  Edge-extension issues.

Revisit when Microsoft lifts the Hyper-V restriction or when JARVIS's elevated tasks no longer
depend on the user profile. The commands, for that day (elevated, reboot):

```powershell
# secpol.msc > Local Policies > Security Options > "User Account Control: Configure type of Admin Approval Mode"
#   = "Admin Approval Mode with Administrator protection", or:
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v TypeOfAdminApprovalMode /t REG_DWORD /d 2 /f
Restart-Computer
# rollback: value 1 and reboot. Elevation events: Microsoft-Windows-LUA 15031 (approved) / 15032 (denied).
```

## 3. Attack Surface Reduction: finish the set (elevated, 5 min, no reboot)

Live: 10 of 19 rules configured, 7 block and 3 audit; 9 unset. Audit mode logs what a rule
would have blocked (event 1122) without blocking, which is the safe way to add the rest.

Step 1, move the three audit rules to block. They concern Office and Adobe child processes
and Win32 API calls from macros; on a developer laptop they almost never fire.

```powershell
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84,92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B,BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled,Enabled,Enabled
```

Step 2, add the nine unset rules in audit mode. The two that matter most against spyware are
WMI event-subscription persistence and copied or impersonated system tools.

```powershell
$audit = @(
  'E6DB77E5-3DF2-4CF1-B95A-636979351E5B',  # persistence through WMI event subscription
  'C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB',  # use of copied or impersonated system tools
  'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4',  # untrusted/unsigned processes from USB
  '33DDEDF1-C6E0-47CB-833E-DE6133960387',  # rebooting into Safe Mode
  'C1DB55AB-C21A-4637-BB3F-A12568109D35',  # advanced ransomware protection
  '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C',  # Adobe Reader child processes
  '26190899-1602-49E8-8B27-EB1D0A1CE869',  # Office communication app child processes
  'D1E49AAC-8F56-4280-B9BA-993A6D77406C',  # process creation from PsExec and WMI  (audit: may touch dev tooling)
  'A8F5898E-1DC8-49A9-9878-85004B8A61E6'   # webshell creation (server rule, harmless here)
)
Add-MpPreference -AttackSurfaceReductionRules_Ids $audit -AttackSurfaceReductionRules_Actions ($audit | ForEach-Object { 'AuditMode' })
```

Verify:

```powershell
$p = Get-MpPreference; for ($i=0; $i -lt $p.AttackSurfaceReductionRules_Ids.Count; $i++) { "{0}  {1}" -f $p.AttackSurfaceReductionRules_Ids[$i], @{0='off';1='block';2='audit';6='warn'}[[int]$p.AttackSurfaceReductionRules_Actions[$i]] }
# expect 19 rows, 10 block, 9 audit
```

After two weeks, read the audit hits and promote the quiet ones to `Enabled`:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1122} -MaxEvents 500 | Group-Object { $_.Properties[3].Value } | Sort-Object Count -Descending | Select-Object Count,Name
```

Rollback: `Remove-MpPreference -AttackSurfaceReductionRules_Ids <id>` for any rule, or
`Set-MpPreference -AttackSurfaceReductionRules_Ids <id> -AttackSurfaceReductionRules_Actions AuditMode`.

## 4. Defender settings that are still at default (elevated, 2 min)

Live: cloud block level 0 (default), Controlled Folder Access in audit (2), and one path,
one process and one extension exclusion that only an administrator can read.

```powershell
Set-MpPreference -CloudBlockLevel High -CloudExtendedTimeout 50
Set-MpPreference -DisableRemovableDriveScanning $false -ScanAvgCPULoadFactor 30
# read the exclusions; remove any you did not create (spyware adds exclusions for itself)
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension
# Remove-MpPreference -ExclusionPath '<path>'   /  -ExclusionProcess '<name>'  /  -ExclusionExtension '<ext>'
```

Leave Controlled Folder Access in audit; read what it would have blocked before enforcing:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1124} -MaxEvents 200 | Select-Object TimeCreated, @{n='app';e={$_.Properties[7].Value}} | Group-Object app | Sort-Object Count -Descending
# when the list is only apps you trust: Set-MpPreference -EnableControlledFolderAccess Enabled
```

Verify: `Get-MpPreference | Select-Object CloudBlockLevel, CloudExtendedTimeout, EnableControlledFolderAccess`.
Rollback: `Set-MpPreference -CloudBlockLevel Default -CloudExtendedTimeout 0`.

## 5. Exploit mitigations and stack protection (elevated, reboot for the kernel part)

Live: DEP, SEHOP and CFG system defaults NOTSET; ASLR on; user shadow stacks OFF; kernel
shadow stacks unset. The CPU (i5-1335U) supports CET, so both shadow-stack settings apply.

```powershell
Set-ProcessMitigation -System -Enable DEP,SEHOP,CFG
# optional, stricter: user-mode hardware stack protection for every process that opts in
Set-ProcessMitigation -System -Enable UserShadowStack
# kernel-mode hardware-enforced stack protection (Core isolation), takes effect after reboot
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks" /v Locked /t REG_DWORD /d 0 /f
Restart-Computer
```

Verify after reboot:

```powershell
Get-ProcessMitigation -System | Select-Object -ExpandProperty DEP; Get-ProcessMitigation -System | Select-Object -ExpandProperty UserShadowStack
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks").Enabled   # 1
# Windows Security > Device security > Core isolation should show "Kernel-mode Hardware-enforced Stack Protection: On"
```

If a driver is incompatible, Windows refuses to enable the kernel setting and says which
driver; update or remove that driver first. Rollback: `Set-ProcessMitigation -System -Disable UserShadowStack`
and the registry value back to `0`, reboot.

## 6. Close the script and autorun droppers (elevated, 2 min, no reboot)

ClickFix and most stealer droppers arrive as `.js`, `.vbs`, `.wsf` or `.hta` and as
"invoice.pdf.exe" with the extension hidden. None of these affect PowerShell or your IDE.

```powershell
# Windows Script Host off (cscript/wscript refuse .vbs/.js/.wsf)
reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f
# AutoRun off for every drive type
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
# PowerShell 2.0 engine (bypasses script block logging and AMSI) off
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
# PowerShell module logging beside the existing script block logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f
# command line in Security 4688 (second source beside Sysmon 1)
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

As your user, show file extensions:

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f; Stop-Process -Name explorer -Force
```

Verify: `cscript //nologo` should print "Windows Script Host access is disabled on this machine";
`Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root` reads Disabled.
Rollback: `Enabled` back to `1`, `NoDriveTypeAutoRun` to `145`, `Enable-WindowsOptionalFeature` for v2.

## 7. Browsers: close the cookie-theft doors you control (elevated, 2 min)

Live: no Edge or Chrome policies set. Chrome is installed under Program Files, Edge 155 is
present. Stealers drive the browser through its remote-debugging port or a headless
instance; a policy makes those launches fail, and JARVIS already alerts on the flag.

```powershell
foreach ($k in 'HKLM\SOFTWARE\Policies\Google\Chrome','HKLM\SOFTWARE\Policies\Microsoft\Edge') {
  reg add $k /v RemoteDebuggingAllowed /t REG_DWORD /d 0 /f
  reg add $k /v BackgroundModeEnabled /t REG_DWORD /d 0 /f        # no browser process lingering after close
}
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v SafeBrowsingProtectionLevel /t REG_DWORD /d 2 /f   # enhanced protection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v SmartScreenEnabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v SmartScreenPuaEnabled /t REG_DWORD /d 1 /f
```

Optional, if you keep passwords in a password manager rather than the browser: set
`PasswordManagerEnabled` to `0` in both keys, so there is no `Login Data` to steal.

Verify: open `chrome://policy` and `edge://policy`, press Reload policies, confirm
`RemoteDebuggingAllowed = false`. Rollback: `reg delete <key> /v RemoteDebuggingAllowed /f`.

## 8. Microphone, camera and screen capture (your user account, 1 min)

Live: microphone, camera and programmatic screen capture are Allow for every app. The
JARVIS seal does the same writes with a recorded rollback; prefer it once released.

```powershell
# from WSL, once the privacy release is deployed:  jarvis privacy seal     (undo: jarvis privacy unseal)
# raw equivalent today, per capability: Deny for packaged apps (Value) and desktop apps (NonPackaged):
foreach ($cap in 'microphone','webcam','graphicsCaptureProgrammatic') {
  $k = "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$cap"
  reg add $k /v Value /t REG_SZ /d Deny /f
  reg add "$k\NonPackaged" /v Value /t REG_SZ /d Deny /f
}
```

What this does and does not do: it closes the user-mode consent gate (Teams, Zoom and
screenshot tools lose the device until you set Allow again). Kernel streaming, drivers and
`BitBlt` screen grabs are not gated by it; a hardware kill switch is stronger. Rollback:
the same commands with `Allow`, or Settings > Privacy & security > Microphone / Camera /
Screenshots and screen recording.

## 9. Network and identity leftovers (elevated, 2 min)

Live: inbound is Block on all profiles with 157 enabled allow rules; WinRM stopped; RDP
denied; Remote Registry disabled; NetBIOS default; LLMNR default.

```powershell
# LLMNR and NetBIOS name resolution off (credential-relay surface)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} | Out-Null
# built-in Administrator stays disabled; your account is the only admin
Get-LocalUser Administrator | Select-Object Name,Enabled        # expect False
# review inbound allow rules that are not Microsoft's: anything you do not recognise, disable (JARVIS records orphan rules; this is the live list)
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object { $_.Owner -eq $null -and $_.DisplayName -notmatch '^(Core Networking|Microsoft|Windows|Delivery|Cast|mDNS|Wi-Fi|Hyper-V|Remote Desktop|File and Printer|Network Discovery|AllJoyn|Wireless)' } | Select-Object DisplayName,Profile,Program | Sort-Object DisplayName
# Disable-NetFirewallRule -DisplayName '<name>'
```

Rollback: `EnableMulticast` to `1`, `TcpipNetbiosOptions=0`, `Enable-NetFirewallRule`.

## 10. Disk and boot (elevated, check first)

```powershell
manage-bde -status C:                      # Protection On expected; if Off: Enable-BitLocker -MountPoint C: -TpmProtector -UsedSpaceOnly -SkipHardwareTest, then back up the recovery key
Confirm-SecureBootUEFI                     # True
Get-WindowsOptionalFeature -Online -FeatureName Recall | Select-Object State   # Disabled or absent is what you want
```

Secure Boot's revocation list has been failing to update since boot 182 (dbx error
0x80071149); that needs Windows Update or a firmware update, not a command here.

## 11. JARVIS-side items that need a release first (WSL, your decision)

These close the detection gaps ORION ranked first and fifth, and they ship as narrow
releases per [DEPLOY](DEPLOY.md), not as owner commands:

1. Sysmon policy: image loads for browser and user-writable folders, registry writes to
   Defender, CLSID, LSA and AMSI keys, process access to browser processes from non-browser
   images. Volume is replayed first; then you apply it with
   `scripts\repair\apply-jarvis-sysmon-policy.ps1 -PolicyPath <xml> -ExpectedSha256 <hash>`
   (elevated; it backs up and auto-restores on a failed readback). Apply only after the
   matching release, or the evidence job reports the running policy as drifted.
2. The polling-keylogger probe: `scripts\tools\probe-win32k-polling.ps1` (elevated, type
   during the 45 s window). If 1003 fires, the per-process finding ships in the same release.
3. Then the pending items already verified: native sensor stage, `jarvis broker install`
   after the release carrying the reflective-image check, privacy collector and seal.

## 11a. Status at 18:35 the same day

- Release `20261021T152300Z-0f19614d3cd7` is live (input-watcher and posture changes),
  the broker was reinstalled, and the input job accepted the new inventory.
- `jarvis privacy seal` was applied: microphone and camera read Deny in both consent
  values. Teams, Zoom and the camera app lose the devices until `jarvis privacy unseal`.
  The collector that watches the seal is in stage `privacy-seal-20261021`; until that is
  deployed, a reopened value goes unnoticed. Deploy:

  ```
  sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --source /home/chris/.cache/jarvis-release-staging/privacy-seal-20261021 --checkout /home/chris/jarvis --expect-base sha256:0f19614d3cd7ef79d32bfa52c9ac1858b0501c2e0e9c65ce02f3a3c49367905e --skip-tests
  ```
- 18:50: the polling probe settled it. Under keyword 0x400 (what the broker traced) Windows
  logs no 1003 even at 14 calls/ms; under 0x1400 it logged 102 events in 45 s, every one
  attributed to the control by `EventData.PID`. Stage `antispyware-20261021-r4` moves the
  broker trace to 0x1400 with a 128 MB cap and an event-id filtered read (validated: exact
  counts, 0.8 s when nothing matches), scores the privacy job and gives it a command. Deploy,
  then `jarvis broker install`:

  ```
  sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --source /home/chris/.cache/jarvis-release-staging/antispyware-20261021-r4 --checkout /home/chris/jarvis --expect-base sha256:90a885994a9da24d5cac3239b088af70a205f3a5abd2cad89a2c79fc8d0164fd --skip-tests
  jarvis broker install
  ```
- Still open: Smart App Control (reads 0), kernel stack protection (`-KernelCET`, reboot),
  the native sensor stage (files already copied to `C:\Users\Public\jarvis-native-position`,
  run `.\install.ps1 -Install` there elevated), timesyncd, and the ASR audit review in two weeks.

## 12. Read it back (user, after everything)

```powershell
wsl -d Ubuntu -- bash -lc 'cd ~/jarvis && jarvis run posture && jarvis run evasion && jarvis status'
```

JARVIS's posture, memory-defense and tamper sections must show every value above as read
from the machine. A finding that disappears without a new observation is a bug, not a fix.
