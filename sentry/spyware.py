"""Look for commodity spyware, stalkerware and unwanted monitoring.

The sophisticated end of this problem needs a kernel driver. The unsophisticated
end — which is most of it — leaves obvious traces, and those are what this
module reads:

  * Windows records which application used the microphone, camera or location
    and exactly when, in the CapabilityAccessManager consent store. Nothing that
    records you through the normal APIs escapes this ledger.
  * Monitoring tools have to survive reboot, so they appear in autostart. Almost
    none of them are signed by a recognizable vendor. Checking the Authenticode
    signature of every autostart binary is a very high-signal, cheap test.
  * Anything that can change your volume or type for you is either an HID device
    sending consumer-control codes, or software with an input hook. Both are
    enumerable.
"""

import datetime
import os
import re

from .control import _ps_json, _aslist

# Names used by consumer monitoring, parental-control and stalkerware products.
# Matching one is a prompt to look, not a verdict.
STALKERWARE = re.compile(
    r"actualspy|ardamax|blurspy|cocospy|couplevow|cerberus|clevguard|"
    r"eyezy|flexispy|flexible?spy|hoverwatch|ikeymonitor|iwantspy|"
    r"kidsguard|kidlogger|mobistealth|mspy|minspy|neatspy|netbull|"
    r"pcpandora|perfectkeylogger|refog|realtime-?spy|revealer|spyagent|"
    r"spyera|spyhuman|spyic|spyier|spytech|spyzie|snoopza|"
    r"teensafe|thetruthspy|umobix|webwatcher|wolfeye|xnspy|"
    r"keylog|keystroke|screenshot.?monitor|employee.?monitor|"
    r"activtrak|hubstaff|teramind|veriato|interguard|workpuls|"
    r"desktime|timedoctor|controlio",
    re.I,
)

# Vendor software that legitimately drives volume and media keys. Present so the
# audit can say "this is probably your keyboard" instead of leaving you guessing.
INPUT_VENDORS = re.compile(
    r"logi|logitech|lghub|icue|corsair|razer|synapse|steelseries|"
    r"nahimic|sonic ?studio|realtek|dolby|armoury|asus|msi|alienware|"
    r"gamebar|xbox|elgato|streamdeck|touchportal|autohotkey|powertoys",
    re.I,
)

CAPABILITIES = ("microphone", "webcam", "location")


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": "win"}


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


def audit(now_iso=None, hosts=("wsl", "win")):
    """Run the spyware audit for the requested hosts.

    Split per host deliberately: the WSL display/audio checks need no PowerShell,
    so a broken interop bridge must not take them down with it.
    """
    out = []
    if "win" in hosts:
        out.extend(audit_windows(now_iso))
    if "wsl" in hosts:
        out.extend(audit_linux())
    return out


def audit_windows(now_iso=None):
    data = _ps_json(PS_SPY, timeout=180)
    if data is None:
        return [_finding("access", "medium", "spyware audit unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    # -- 1. capability ledger ---------------------------------------------
    # Most recent first: "what touched the mic last" is the question being asked.
    caps = sorted(_aslist(data.get("caps")),
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
    for s in _aslist(data.get("sigs")):
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
    hid = _aslist(data.get("hid"))
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

    procs = _aslist(data.get("procs"))
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

    for a in _aslist(data.get("audio")):
        if a.get("status") not in ("OK", None):
            out.append(_finding("input", "medium", "audio device not healthy",
                                f"{a.get('name')} — {a.get('status')}", ""))

    out.extend(_keyboard_findings(data))
    return out


# The driver stack for these two classes, on a machine nobody has inserted
# anything into. Anything else in the list is a filter driver seeing input
# before the applications do.
STOCK_KBD_FILTERS = {"kbdclass"}
STOCK_MOU_FILTERS = {"mouclass"}

# Filter drivers that legitimately ship with laptop vendor and peripheral
# software. They still see every keystroke, so they are reported — just not as
# though they were a discovery.
KNOWN_FILTERS = re.compile(
    r"^(synTP|ETDFilter|ApplePS2|LenovoRd|HpqKbFiltr|SynRMIHID|"
    r"CtrlPad|Elan|AlpsAlpine|VirtualBox|vmusbmouse|vmmouse|kbfiltr)",
    re.I,
)

# Input devices that are part of a laptop rather than something attached to it.
INTERNAL_BUS = re.compile(r"^(ACPI\\|HID\\CONVERTEDDEVICE|HID\\INTC|"
                          r"HID\\ELAN|ROOT\\|BUTTONCONVERTER\\)", re.I)


def _keyboard_findings(data):
    """Answer 'is anything sitting between the keys and the applications?'"""
    out = []

    # -- 1. filter drivers -------------------------------------------------
    for label, key, stock in (("keyboard", "kbdUpperFilters", STOCK_KBD_FILTERS),
                              ("mouse", "mouUpperFilters", STOCK_MOU_FILTERS)):
        filters = [f for f in _aslist(data.get(key)) if isinstance(f, str) and f]
        extra = [f for f in filters if f.lower() not in stock]
        for f in extra:
            known = KNOWN_FILTERS.match(f)
            out.append(_finding(
                "input", "low" if known else "critical",
                f"extra {label} filter driver in the input stack",
                f"{f} — a class filter driver sees every "
                f"{'keystroke' if label == 'keyboard' else 'movement and click'} "
                f"before any application does"
                + (", and this one belongs to known vendor input software"
                   if known else
                   ". Nothing but the stock driver should be here."),
                f"{label} class UpperFilters"))
        if not extra:
            out.append(_finding(
                "input", "ok", f"{label} driver stack is stock",
                f"UpperFilters = {', '.join(filters) or '(empty)'} — nothing is "
                f"layered above the class driver", f"{label} class UpperFilters"))

    lower = [f for f in _aslist(data.get("kbdLowerFilters")) if isinstance(f, str) and f]
    if lower:
        out.append(_finding(
            "input", "critical", "keyboard lower filter driver present",
            f"{', '.join(lower)} — sits below the class driver, closer to the "
            f"hardware than anything else in the stack. This position is almost "
            f"never legitimately occupied.", "keyboard class LowerFilters"))

    # -- 2. scancode remapping ---------------------------------------------
    sc = data.get("scancodeMap") or ""
    if sc:
        out.append(_finding(
            "input", "medium", "a kernel-level key remap is installed",
            f"Scancode Map is set ({len(sc.split('-'))} bytes). Legitimate if you "
            f"remapped a key yourself; otherwise a key does something other than "
            f"what is printed on it.",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layout"))
    else:
        out.append(_finding("input", "ok", "no kernel key remapping",
                            "Scancode Map is not set", "Keyboard Layout"))

    # -- 3. what is physically plugged in ----------------------------------
    kbs = _aslist(data.get("keyboards"))
    external = [k for k in kbs if not INTERNAL_BUS.match(k.get("id") or "")]
    for k in external:
        out.append(_finding(
            "input", "medium", "external keyboard device present",
            f"{k.get('name')} — an inline hardware keylogger must enumerate as a "
            f"keyboard to pass keystrokes through, so confirm you recognise this",
            k.get("id", "")))
    if kbs and not external:
        out.append(_finding(
            "input", "ok", "all keyboard devices are internal",
            f"{len(kbs)} keyboard device(s), all on internal buses (ACPI / "
            f"embedded HID) — nothing attached from outside", ""))

    # A hardware keylogger has to enumerate to work. Anything that ever did is
    # still recorded, so this covers devices attached once and taken away.
    usb_kb = [u for u in _aslist(data.get("usbHistory"))
              if re.search(r"keyboard|keypad", u.get("desc") or "", re.I)]
    for u in usb_kb:
        out.append(_finding(
            "input", "high", "a USB keyboard was attached at some point",
            f"{u.get('desc')} ({u.get('id')}) — present in the USB enumeration "
            f"history even if it is not connected now", "USB enum history"))
    if not usb_kb:
        out.append(_finding(
            "input", "ok", "no USB keyboard has ever been attached",
            f"{len(_aslist(data.get('usbHistory')))} USB devices in this "
            f"machine's history, none of them a keyboard or keypad",
            "USB enum history"))

    # -- 4. accessibility backdoor -----------------------------------------
    for h in _aslist(data.get("ifeoAccessibility")):
        out.append(_finding(
            "input", "critical", "accessibility binary is hijacked",
            f"{h.get('file')} → {h.get('debugger')} — these run as SYSTEM from "
            f"the logon screen, so this is a backdoor reachable from the keyboard "
            f"before anyone signs in",
            "Image File Execution Options"))

    return out


# ---------------------------------------------------------------------------
# WSL side: WSLg wires a Linux process straight into a display and audio server
# ---------------------------------------------------------------------------
#
# This is the part of the machine that has no consent ledger at all. WSLg gives
# every process in the distro an X11 display, a Wayland socket and a PulseAudio
# server, and X11 in particular has no isolation between clients: any process
# that can open the display can screenshot the entire desktop and read the
# keyboard, with no prompt and nothing recorded anywhere. Windows asks before an
# app uses the microphone; nothing asks here.

_SOCKET_FD = re.compile(r"^socket:\[(\d+)\]$")


def _unix_socket_map():
    """inode -> unix socket path, from /proc/net/unix."""
    out = {}
    try:
        with open("/proc/net/unix") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 8 and parts[6].isdigit():
                    out[int(parts[6])] = parts[7]
    except (OSError, ValueError, StopIteration):
        pass
    return out


# Which server a socket path belongs to, and what connecting to it grants.
DISPLAY_SOCKETS = (
    (re.compile(r"/tmp/\.X11-unix/X\d+"), "X11 display",
     "X11 has no isolation between clients: any connected process can capture "
     "the whole screen and read every keystroke sent to any window"),
    (re.compile(r"wayland-\d+"), "Wayland display",
     "Wayland isolates clients from each other, so this is normal for a GUI app"),
    (re.compile(r"PulseServer|/pulse/native"), "PulseAudio server",
     "a connected client can record from the microphone"),
)


def audit_linux():
    """Who inside WSL is wired into the display and audio servers."""
    out = []

    def _f(sev, title, detail, where=""):
        return {"category": "access", "severity": sev, "title": title,
                "detail": detail, "where": where, "host": "wsl"}

    if not os.path.isdir("/mnt/wslg"):
        return [_f("ok", "no WSLg display stack",
                   "this distro has no GUI, audio or screen-capture surface", "")]

    inodes = _unix_socket_map()
    clients = {}          # (kind, note) -> [ "name [pid]" ]
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/comm") as fh:
                name = fh.read().strip()
        except OSError:
            continue
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            continue
        seen = set()
        for fd in fds:
            try:
                target = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            m = _SOCKET_FD.match(target)
            if not m:
                continue
            path = inodes.get(int(m.group(1)), "")
            if not path:
                continue
            for pattern, kind, note in DISPLAY_SOCKETS:
                if pattern.search(path) and kind not in seen:
                    seen.add(kind)
                    clients.setdefault((kind, note), []).append(f"{name} [{pid}]")

    for (kind, note), procs in sorted(clients.items()):
        sev = "medium" if kind.startswith("X11") else "low"
        out.append(_f(sev, f"connected to the {kind}",
                      f"{len(procs)} process(es): {', '.join(sorted(set(procs))[:8])}"
                      + (" …" if len(set(procs)) > 8 else "")
                      + f" — {note}",
                      kind))
    if not clients:
        out.append(_f("ok", "nothing inside WSL is connected to a display or audio server",
                      "WSLg is present but no process holds an X11, Wayland or "
                      "PulseAudio connection", "/mnt/wslg"))

    # X11 exposure is a property of the display being reachable at all, not of
    # anyone currently using it.
    if os.path.exists("/tmp/.X11-unix/X0"):
        out.append(_f(
            "low", "an X11 display is reachable from every process in this distro",
            "Any process here can connect to :0 and, because X11 grants every "
            "client access to every other client's input and to the framebuffer, "
            "screenshot the desktop and log keystrokes without a prompt and "
            "without leaving a record. Windows' capability ledger does not cover "
            "this. Prefer Wayland-native apps; unset DISPLAY for anything that "
            "does not need a GUI.",
            "/tmp/.X11-unix/X0"))

    snd = [d for d in (os.listdir("/dev/snd") if os.path.isdir("/dev/snd") else [])
           if d.startswith(("pcm", "control"))]
    if snd:
        out.append(_f("low", "ALSA capture devices present in WSL",
                      f"{', '.join(sorted(snd)[:6])}", "/dev/snd"))

    cams = [d for d in os.listdir("/dev") if d.startswith("video")] \
        if os.path.isdir("/dev") else []
    if cams:
        out.append(_f("medium", "camera device present in WSL",
                      f"{', '.join(sorted(cams))} — a process here can read the "
                      f"camera directly, outside Windows' capability ledger", "/dev"))

    return out


CAT_ORDER = {"spyware": 0, "access": 1, "input": 2, "signing": 3}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def sort_findings(findings):
    return sorted(findings, key=lambda f: (CAT_ORDER.get(f["category"], 9),
                                           SEV_ORDER.get(f["severity"], 9),
                                           f["title"]))
