"""Windows: capability use (microphone, camera, location), unsigned or oddly signed
autostarts, known monitoring software, and input and audio control devices."""

import datetime
import re

from jarvis.platform.windows import aslist, ps_json

from .common import INPUT_VENDORS, STALKERWARE, _finding
from .keyboard import _keyboard_findings


PS_SPY = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

# --- 1. Who used the microphone / camera / location, and when -------------
$caps = New-Object System.Collections.ArrayList
foreach ($hive in @('HKCU:','HKLM:')) {
  $base = "$hive\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
  # Every capability Windows keeps a ledger for, not a hand-picked three.
  # Screen capture (graphicsCapture*), notification reading and app diagnostics
  # are exactly what surveillance software wants and were previously unread.
  if (-not (Test-Path $base)) { continue }
  foreach ($capKey in (Get-ChildItem $base)) {
    $cap = $capKey.PSChildName
    $capPath = $capKey.PSPath
    foreach ($k in (Get-ChildItem $capPath)) {
      # Desktop (non-Store) apps are nested one level deeper under NonPackaged,
      # with their path encoded using '#' in place of the separators.
      $leaves = if ($k.PSChildName -eq 'NonPackaged') { Get-ChildItem $k.PSPath } else { @($k) }
      foreach ($l in $leaves) {
        $v = Get-ItemProperty $l.PSPath
        if ($null -eq $v.LastUsedTimeStart) { continue }
        $st = [int64]$v.LastUsedTimeStart
        $sp = [int64]$v.LastUsedTimeStop
        [void]$caps.Add([pscustomobject]@{
          cap   = $cap
          hive  = $hive
          app   = ($l.PSChildName -replace '#','\')
          start = if ($st -gt 0) { [DateTime]::FromFileTime($st).ToString('o') } else { '' }
          stop  = if ($sp -gt 0) { [DateTime]::FromFileTime($sp).ToString('o') } else { '' }
          inUse = ($st -gt 0 -and $sp -eq 0)
        })
      }
    }
  }
}
$o.caps = @($caps)

# --- 2. Every autostart binary, with its Authenticode signature -----------
$paths = New-Object System.Collections.ArrayList
$shell = New-Object -ComObject WScript.Shell
function Add-Path([string]$cmd) {
  if (-not $cmd) { return }
  $c = $cmd.Trim()
  # Pull the executable out of a command line, quoted or not.
  if ($c.StartsWith('"')) { $p = ($c -split '"')[1] }
  else { $m = [regex]::Match($c, '^(.*?\.(exe|dll|scr|com|bat|cmd|vbs|ps1|lnk))\b',
                             'IgnoreCase'); $p = if ($m.Success) { $m.Groups[1].Value } else { $c } }
  if (-not $p) { return }
  # A shortcut carries no signature of its own; follow it to the real binary.
  if ($p -like '*.lnk' -and (Test-Path -LiteralPath $p)) {
    $t = $shell.CreateShortcut($p).TargetPath
    if ($t) { $p = $t }
  }
  if (Test-Path -LiteralPath $p -PathType Leaf) { [void]$paths.Add($p) }
}

foreach ($k in @(
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')) {
  $p = Get-ItemProperty -Path $k
  if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
            ForEach-Object { Add-Path ([string]$_.Value) } }
}
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' } |
  ForEach-Object { Add-Path $_.PathName }
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' } |
  ForEach-Object { $_.Actions | ForEach-Object { Add-Path $_.Execute } }
Get-ChildItem -File -Path @(
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") |
  ForEach-Object { Add-Path $_.FullName }

$o.sigs = @($paths | Select-Object -Unique | ForEach-Object {
  $s = Get-AuthenticodeSignature -LiteralPath $_
  $f = Get-Item -LiteralPath $_
  [pscustomobject]@{
    path    = $_
    status  = [string]$s.Status
    signer  = if ($s.SignerCertificate) { [string]$s.SignerCertificate.Subject } else { '' }
    written = $f.LastWriteTime.ToString('o')
  }
})

# --- 3. Input devices able to send volume/media commands ------------------
$o.hid = @(Get-CimInstance Win32_PnPEntity |
  Where-Object { $_.Name -match 'Consumer Control|HID Keyboard|Multimedia|Audio Control' -and
                 $_.Status -eq 'OK' } |
  Select-Object -First 25 @{n='name';e={$_.Name}}, @{n='id';e={$_.DeviceID}},
                          @{n='mfr';e={$_.Manufacturer}})

$o.audio = @(Get-CimInstance Win32_SoundDevice |
  Select-Object @{n='name';e={$_.Name}}, @{n='status';e={$_.Status}})

# --- 4. Software with a global input hook or accessibility control --------
# UIAccess / accessibility apps can drive the desktop; so can anything holding
# a low-level keyboard hook. Enumerating the modules is native work, so we look
# at the practical proxy: running processes from known input-automation tools.
$o.procs = @(Get-Process | ForEach-Object {
  [pscustomobject]@{ pid=$_.Id; name=$_.ProcessName; path=$_.Path;
                     title=$_.MainWindowTitle } })

# --- 5. Keyboard stack integrity -------------------------------------------
# A software keylogger that wants every keystroke regardless of which window has
# focus has two durable options, and both are visible from here.
#
#   * A keyboard class filter driver. It sits in the driver stack above
#     kbdclass and sees scancodes before any application does. The stack is
#     declared in one registry value, and on a healthy machine that value is
#     exactly 'kbdclass'.
#   * A Scancode Map. It remaps keys in the kernel. It has legitimate uses
#     (swapping Caps Lock), but it is also how a key can be made to do something
#     other than what is printed on it, and an unexpected one is worth seeing.
$kb = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}'
$ms = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E96F-E325-11CE-BFC1-08002BE10318}'
$o.kbdUpperFilters = [string[]]@((Get-ItemProperty $kb).UpperFilters)
$o.kbdLowerFilters = [string[]]@((Get-ItemProperty $kb).LowerFilters)
$o.mouUpperFilters = [string[]]@((Get-ItemProperty $ms).UpperFilters)
$sc = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layout').'Scancode Map'
$o.scancodeMap = if ($sc) { [BitConverter]::ToString($sc) } else { '' }

# Physically present keyboards. A hardware keylogger that sits between a USB
# keyboard and the port has to enumerate as a keyboard itself to pass keystrokes
# through, so an unaccounted-for entry here is the artifact it cannot avoid.
$o.keyboards = @(Get-PnpDevice -Class Keyboard |
  Select-Object @{n='name';e={[string]$_.FriendlyName}},
                @{n='id';e={[string]$_.InstanceId}},
                @{n='status';e={[string]$_.Status}})

# Every USB device this machine has ever enumerated, so a keyboard that was
# attached once and removed still shows up.
$o.usbHistory = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' |
  ForEach-Object {
    $vid = $_.PSChildName
    $desc = @(Get-ChildItem $_.PSPath | ForEach-Object {
                (Get-ItemProperty $_.PSPath).DeviceDesc }) -replace '^@.*;',''
    [pscustomobject]@{ id=[string]$vid; desc=[string]($desc -join '; ') } })

# The accessibility binaries run as SYSTEM from the logon screen, before anyone
# signs in. An IFEO debugger on one of them is a keyboard-reachable backdoor.
$o.ifeoAccessibility = @(
  foreach ($f in 'sethc.exe','utilman.exe','osk.exe','narrator.exe','magnify.exe','atbroker.exe') {
    $d = (Get-ItemProperty ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\' + $f)).Debugger
    if ($d) { [pscustomobject]@{ file=$f; debugger=[string]$d } }
  })

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""


BAD_SIG = {"NotSigned", "HashMismatch", "NotTrusted", "UnknownError"}


TRUSTED_SIGNERS = re.compile(
    r"Microsoft (Corporation|Windows)|CN=Microsoft|Google LLC|Mozilla Corporation|"
    r"Intel Corporation|NVIDIA|Advanced Micro Devices|Realtek|Logitech|"
    r"Valve Corp|Riot Games|Proton AG|Dropbox|Adobe|Apple Inc|Cisco|"
    r"Discord|Spotify|Oracle|Citrix|VMware|Lenovo|Dell|HP Inc|ASUSTeK",
    re.I,
)


# What each capability actually exposes, which is what should decide how loudly
# it is reported. Windows tracks all of these identically; they are very far
# from equally sensitive.
SURVEILLANCE_CAPS = {
    "microphone", "webcam", "graphicsCaptureProgrammatic",
    "graphicsCaptureWithoutBorder", "userNotificationListener",
    "appDiagnostics", "humanInterfaceDevice", "gazeInput",
    "broadFileSystemAccess",
}


ROUTINE_CAPS = {
    "cellularData", "wifiData", "wiFiDirect", "radios", "bluetooth",
    "bluetoothSync", "musicLibrary", "picturesLibrary", "videosLibrary",
    "documentsLibrary", "usb", "serialCommunication", "sensors.custom",
    "activity", "userDataTasks", "systemAIModels",
}


CAP_TIER = ({c: "surveillance" for c in SURVEILLANCE_CAPS}
            | {c: "routine" for c in ROUTINE_CAPS})


# Windows' internal names do not say what the capability lets an app do.
CAP_LABEL = {
    "graphicsCaptureProgrammatic": "SCREEN CAPTURE (programmatic)",
    "graphicsCaptureWithoutBorder": "SCREEN CAPTURE (no capture border shown)",
    "userNotificationListener": "READS ALL YOUR NOTIFICATIONS",
    "appDiagnostics": "READS OTHER PROCESSES' DIAGNOSTIC INFO",
    "humanInterfaceDevice": "DIRECT HID ACCESS",
    "gazeInput": "EYE TRACKING",
    "broadFileSystemAccess": "YOUR ENTIRE FILE SYSTEM",
    "microphone": "MICROPHONE",
    "webcam": "CAMERA",
    "location": "location",
    "phoneCallHistory": "call history",
    "userAccountInformation": "your account details",
}


def _recent(iso_ts, hours=24):
    """True when an ISO-8601 timestamp is within the last `hours`."""
    if not iso_ts:
        return False
    try:
        t = datetime.datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00"))
    except ValueError:
        return False
    if t.tzinfo is None:
        t = t.astimezone()
    delta = datetime.datetime.now(datetime.timezone.utc) - t.astimezone(
        datetime.timezone.utc)
    return datetime.timedelta(0) <= delta <= datetime.timedelta(hours=hours)


def audit_windows(now_iso=None):
    data = ps_json(PS_SPY, timeout=180)
    if data is None:
        return [_finding("access", "medium", "spyware audit unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    # -- 1. capability ledger ---------------------------------------------
    # Most recent first: "what touched the mic last" is the question being asked.
    caps = sorted(aslist(data.get("caps")),
                  key=lambda c: c.get("start") or "", reverse=True)
    routine = {}
    for c in caps:
        app = c.get("app") or "?"
        cap = c.get("cap") or "?"
        pretty = app.split("\\")[-1] if "\\" in app else app
        when = (c.get("start") or "").replace("T", " ")[:19]
        tier = CAP_TIER.get(cap, "personal")

        # Reading every capability means reading a lot of uninteresting ones.
        # Wi-Fi and cellular data access is how apps check connectivity; listing
        # sixteen of those individually buries the one that used the camera.
        if tier == "routine":
            routine.setdefault(cap, []).append(pretty)
            continue

        if c.get("inUse"):
            out.append(_finding(
                "access", "high" if tier == "surveillance" else "medium",
                f"{CAP_LABEL.get(cap, cap)} IN USE right now",
                f"{pretty} — since {when}", app))
        else:
            if STALKERWARE.search(app):
                sev = "high"
            elif tier == "surveillance" and _recent(c.get("start"), hours=24):
                sev = "medium"
            else:
                sev = "low"
            out.append(_finding(
                "access", sev, f"{CAP_LABEL.get(cap, cap)} used",
                f"{pretty} — last used {when}",
                f"{app}  until {(c.get('stop') or '').replace('T', ' ')[:19]}"))

    for cap, apps in sorted(routine.items()):
        out.append(_finding(
            "access", "low", f"{CAP_LABEL.get(cap, cap)} used",
            f"{len(apps)} app(s): {', '.join(sorted(set(apps))[:6])}"
            + (" …" if len(set(apps)) > 6 else ""),
            "CapabilityAccessManager"))

    if not caps:
        out.append(_finding("access", "low", "no capability history",
                            "no app has recorded use of any tracked capability "
                            "(or the consent store is not readable from here)",
                            "CapabilityAccessManager"))
    else:
        watched = sorted({c.get("cap") for c in caps} & set(SURVEILLANCE_CAPS))
        out.append(_finding(
            "access", "ok", "capability ledger read",
            f"{len(caps)} recorded uses across {len({c.get('cap') for c in caps})} "
            f"capabilities; surveillance-relevant ones present: "
            f"{', '.join(watched) or 'none'}",
            "CapabilityAccessManager"))

    # -- 2. autostart signatures ------------------------------------------
    for s in aslist(data.get("sigs")):
        path, status = s.get("path", ""), s.get("status", "")
        signer = s.get("signer") or ""
        name = path.split("\\")[-1]
        if STALKERWARE.search(path):
            out.append(_finding("spyware", "critical",
                                "autostart matches known monitoring software",
                                name, path))
            continue
        if status in BAD_SIG:
            # Unsigned in Program Files is sloppy vendor practice; unsigned in a
            # directory you can write to without prompting is the shape that
            # matters, because anything on the machine could have put it there.
            in_user_space = re.search(
                r"\\appdata\\|\\temp\\|\\users\\public\\|\\downloads\\", path, re.I)
            out.append(_finding(
                "signing", "critical" if in_user_space else "medium",
                f"autostart binary is unsigned ({status})",
                f"{name} — no verified publisher"
                + (", running from a user-writable directory" if in_user_space else ""),
                path))
        elif status == "Valid" and signer and not TRUSTED_SIGNERS.search(signer):
            cn = re.search(r"CN=([^,]+)", signer)
            out.append(_finding("signing", "low",
                                "autostart signed by an unfamiliar publisher",
                                f"{name} — {cn.group(1) if cn else signer[:60]}", path))

    # -- 3. input / audio control -----------------------------------------
    # Windows creates one consumer-control node per HID collection, so a single
    # keyboard or headset shows up several times. Collapse them, and report the
    # count -- a device with a stuck or oversensitive volume control is by far
    # the most common cause of volume changing on its own.
    hid = aslist(data.get("hid"))
    grouped = {}
    for h in hid:
        key = (h.get("name") or "", h.get("mfr") or "")
        grouped.setdefault(key, []).append(h.get("id", ""))
    for (nm, mfr), ids in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        n = len(ids)
        out.append(_finding(
            "input", "low", "device can send volume/media commands",
            f"{nm}" + (f"  [{mfr}]" if mfr else "")
            + (f"  ×{n} endpoints" if n > 1 else ""),
            "; ".join(ids[:4])))
    if hid:
        out.append(_finding(
            "input", "low", "volume changing on its own",
            f"{len(grouped)} distinct device(s) here can send volume commands — "
            f"unplug them one at a time to rule out a stuck media key before "
            f"suspecting software", "physical-first triage"))

    procs = aslist(data.get("procs"))
    for p in procs:
        blob = f"{p.get('name')} {p.get('path') or ''}"
        if STALKERWARE.search(blob):
            out.append(_finding("spyware", "critical", "monitoring software running",
                                f"{p.get('name')} [pid {p.get('pid')}]",
                                p.get("path") or ""))
        elif INPUT_VENDORS.search(blob):
            out.append(_finding("input", "low", "input/media control software running",
                                f"{p.get('name')} [pid {p.get('pid')}]",
                                p.get("path") or ""))

    for a in aslist(data.get("audio")):
        if a.get("status") not in ("OK", None):
            out.append(_finding("input", "medium", "audio device not healthy",
                                f"{a.get('name')} — {a.get('status')}", ""))

    out.extend(_keyboard_findings(data))
    return out
