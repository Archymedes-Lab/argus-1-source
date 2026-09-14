"""Audit the ways something can take or keep control of the machine.

Process monitoring answers "what is running right now". This module answers the
harder question: "what has arranged to run later, what can drive this machine
from outside, and has anything turned off the defenses?"

Three categories:
  persistence -- autostart hooks that survive reboot (tasks, services, cron,
                 registry Run keys, shell rc files, authorized_keys)
  remote      -- anything that grants interactive control from elsewhere
                 (RDP, WinRM, SSH, VNC/TeamViewer/AnyDesk-class agents)
  defense     -- the state of the controls themselves (Defender, tamper
                 protection, firewall, audit logging), because an attacker's
                 first move is usually to disable them
"""

import base64
import glob
import hashlib
import json
import os
import re
import subprocess

from . import collect_windows
from . import collection
from .paths import REPO_ROOT
from .util import short

# Commercial remote-control agents. Presence is not proof of compromise -- it is
# proof that someone can drive this machine, which is what you asked to see.
REMOTE_AGENTS = re.compile(
    r"teamviewer|anydesk|rustdesk|ultravnc|tightvnc|realvnc|vncserver|x11vnc|"
    r"screenconnect|connectwise|logmein|gotoassist|splashtop|supremo|ammyy|"
    r"radmin|dwservice|dwagent|atera|ninjarmm|ninjaone|syncro|kaseya|"
    r"chrome remote desktop|remotepc|zoho assist|action1|pulseway|"
    r"quickassist|mstsc|psexec|paexec|meshagent|tacticalrmm",
    re.I,
)

# PowerShell's -EncodedCommand, as a real flag rather than any string containing
# "enc" (Proton's "ms-encodedlaunch:" URI matched a looser pattern).
OBFUSCATED = re.compile(
    r"(?:^|[\s\"'])[-/]e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{30,}|"
    r"FromBase64String|"
    r"powershell[^\n]*\s[-/]w(?:indowstyle)?\s+hidden",
    re.I,
)


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True,
                           errors="replace")
        return r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": ""}


# ---------------------------------------------------------------------------
# Linux / WSL side
# ---------------------------------------------------------------------------

SHELL_RC = ["~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc",
            "~/.bash_login", "~/.config/autostart"]


def audit_linux():
    out = []

    # -- persistence: cron -------------------------------------------------
    crontab = _run(["crontab", "-l"])
    for line in crontab.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(_finding("persistence", "medium", "user cron job",
                                short(line, 100), "crontab -l"))

    for path in glob.glob("/etc/cron.d/*") + ["/etc/crontab"]:
        try:
            with open(path, errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("SHELL") \
                            and not line.startswith("PATH") and not line.startswith("MAILTO"):
                        out.append(_finding("persistence", "low", "system cron entry",
                                            short(line, 100), path))
        except OSError:
            pass

    # -- persistence: systemd ---------------------------------------------
    units = _run(["systemctl", "list-unit-files", "--state=enabled", "--no-pager",
                  "--no-legend"])
    for line in units.splitlines():
        unit = line.split()[0] if line.split() else ""
        if unit and not unit.startswith(("systemd-", "dbus", "getty", "network",
                                         "ssh.socket", "cron")):
            out.append(_finding("persistence", "low", "enabled systemd unit", unit,
                                "systemctl"))

    for pattern in ("/etc/systemd/system/*.service", os.path.expanduser(
            "~/.config/systemd/user/*.service")):
        for path in glob.glob(pattern):
            out.append(_finding("persistence", "medium", "custom systemd service",
                                os.path.basename(path), path))

    # -- persistence: shell startup + rc hooks -----------------------------
    for rc in SHELL_RC:
        path = os.path.expanduser(rc)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    s = line.strip()
                    if re.search(r"(curl|wget)\s+[^|]*\|\s*(ba)?sh|nc\s+-e|"
                                 r"base64\s+-d|/dev/tcp/", s):
                        out.append(_finding("persistence", "critical",
                                            "shell rc runs remote code",
                                            short(s, 100), f"{path}:{n}"))
        except OSError:
            pass

    # -- persistence: preload hijack ---------------------------------------
    if os.path.exists("/etc/ld.so.preload"):
        try:
            with open("/etc/ld.so.preload", errors="replace") as fh:
                body = fh.read().strip()
        except OSError:
            body = "<unreadable>"
        if body:
            out.append(_finding("persistence", "critical",
                                "global library preload set", body,
                                "/etc/ld.so.preload"))

    # -- remote: SSH trust -------------------------------------------------
    for path in glob.glob(os.path.expanduser("~/.ssh/authorized_keys")) + \
            glob.glob("/home/*/.ssh/authorized_keys") + \
            glob.glob("/root/.ssh/authorized_keys"):
        try:
            with open(path, errors="replace") as fh:
                keys = [l for l in fh if l.strip() and not l.startswith("#")]
        except OSError:
            continue
        for k in keys:
            comment = k.strip().split()[-1] if len(k.split()) > 2 else "(no comment)"
            out.append(_finding("remote", "high", "SSH key can log in as this user",
                                comment, path))

    # -- remote: listening services ---------------------------------------
    ss = _run(["ss", "-tulnp"])
    for line in ss.splitlines()[1:]:
        f = line.split()
        if len(f) < 5:
            continue
        local = f[4]
        if local.startswith(("0.0.0.0", "*", "[::]", ":::")):
            proc = f[6] if len(f) > 6 else ""
            sev = "high" if REMOTE_AGENTS.search(line) else "medium"
            out.append(_finding("remote", sev, "listening on all interfaces",
                                f"{local} {short(proc, 60)}", "ss -tulnp"))

    # -- privilege: sudoers drop-ins --------------------------------------
    for path in glob.glob("/etc/sudoers.d/*"):
        try:
            with open(path, errors="replace") as fh:
                body = fh.read()
        except OSError:
            continue
        if "NOPASSWD" in body:
            out.append(_finding("defense", "high", "passwordless sudo rule",
                                short(body.strip().replace("\n", " "), 90), path))

    # -- defense: WSL is not the security boundary -------------------------
    if os.path.exists("/mnt/c/Windows"):
        out.append(_finding("defense", "low", "Windows drive mounted in WSL",
                            "processes in WSL can read and write the Windows "
                            "filesystem at /mnt/c", "/mnt/c"))

    for f in out:
        f["host"] = "wsl"
    return out


# ---------------------------------------------------------------------------
# Windows side
# ---------------------------------------------------------------------------

PS_CONTROL = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
$o.currentUser = "$env:USERDOMAIN\$env:USERNAME"
$o.localAppData = $env:LOCALAPPDATA

function Get-NormalizedTextHash([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $text = [IO.File]::ReadAllText($Path).Replace("`r`n", "`n").TrimEnd()
        $bytes = [Text.Encoding]::UTF8.GetBytes($text)
        $sha = [Security.Cryptography.SHA256]::Create()
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } catch { return $null }
}

# --- persistence: scheduled tasks not shipped by Microsoft
$o.tasks = @(Get-ScheduledTask | Where-Object {
    $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*'
} | ForEach-Object {
    $task = $_
    $principal = $task.Principal
    $actions = @($task.Actions | ForEach-Object {
        $target = $null
        if ($_.Arguments -match '(?i)(?:^|\s)-File\s+(?:"([^"]+)"|([^\s]+))') {
            $target = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
        }
        [pscustomobject]@{
            execute=$_.Execute
            arguments=$_.Arguments
            target=$target
            targetHash=(Get-NormalizedTextHash $target)
        }
    })
    [pscustomobject]@{
        name=$task.TaskName
        path=$task.TaskPath
        author=$task.Author
        user=$principal.UserId
        logonType=[string]$principal.LogonType
        runLevel=[string]$principal.RunLevel
        actions=$actions
    }
})

# --- persistence: Run / RunOnce registry keys
$runKeys = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$o.runkeys = @(foreach ($k in $runKeys) {
    $p = Get-ItemProperty -Path $k
    if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
        ForEach-Object { [pscustomobject]@{ key=$k; name=$_.Name; value=[string]$_.Value } } }
})

# --- persistence: startup folders
$o.startup = @(Get-ChildItem -Path @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") -File |
    ForEach-Object { [pscustomobject]@{ name=$_.Name; path=$_.FullName } })

# --- persistence: auto-start services outside system32
$o.services = @(Get-CimInstance Win32_Service |
    Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -and
                   $_.PathName -notlike '*\System32\*' } |
    ForEach-Object { [pscustomobject]@{ name=$_.Name; disp=$_.DisplayName;
                                        path=$_.PathName; state=$_.State } })

# --- persistence: WMI event subscriptions (a quiet, classic foothold)
$o.wmi = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
    ForEach-Object { [pscustomobject]@{ filter=[string]$_.Filter; consumer=[string]$_.Consumer } })

# --- remote: inbound control channels
$rdpDeny = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
$winrm   = (Get-Service WinRM).Status
$sshd    = (Get-Service sshd).Status
$o.remote = [pscustomobject]@{
    rdpEnabled = ($rdpDeny -eq 0)
    winrm      = [string]$winrm
    sshd       = [string]$sshd
    sessions   = @(query user 2>$null)
}

# --- remote: interactive logon sessions other than the console
$o.logons = @(Get-CimInstance Win32_LogonSession |
    Where-Object { $_.LogonType -in 3,10 } |
    Select-Object -First 20 LogonId, LogonType, StartTime)

# --- defense: Defender + tamper protection
$mp = Get-MpComputerStatus
$pref = Get-MpPreference
$o.defender = [pscustomobject]@{
    present          = [bool]$mp
    realtime         = $mp.RealTimeProtectionEnabled
    tamperProtection = $mp.IsTamperProtected
    antivirus        = $mp.AntivirusEnabled
    sigAgeDays       = $mp.AntivirusSignatureAge
    exclusionPaths   = @($pref.ExclusionPath)
    exclusionProcs   = @($pref.ExclusionProcess)
}

# --- defense: firewall profile state
$o.firewall = @(Get-NetFirewallProfile |
    ForEach-Object { [pscustomobject]@{ name=$_.Name; enabled=$_.Enabled } })

# --- defense: inbound Allow rules opened for specific programs
$o.fwrules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
    Where-Object { $_.Group -eq $null -or $_.Group -eq '' } |
    Select-Object -First 40 DisplayName, Profile)

# --- privilege: who is a local administrator
$o.admins = @((Get-LocalGroupMember -Group 'Administrators').Name)

# --- privilege: UAC posture
$o.uac = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA).EnableLUA

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""


def _ps_json(script, timeout=120):
    """Run a PowerShell script and decode its base64 JSON payload.

    Retries once after forcing interop re-resolution: the socket named in
    WSL_INTEROP can go stale between calls when the session that created it
    ends, and the only symptom is empty output.
    """
    if not collect_windows.available():
        collection.failed('windows', 'interop unavailable')
        return None

    for attempt in (1, 2):
        try:
            r = subprocess.run(
                [collect_windows._PS, "-NoProfile", "-NonInteractive",
                 "-Command", script],
                capture_output=True, timeout=timeout, cwd="/",
            )
        except (OSError, subprocess.TimeoutExpired):
            collection.failed('windows', 'PowerShell failed or timed out')
            return None

        blob = (r.stdout.decode("ascii", "ignore")
                .strip().replace("\r", "").replace("\n", ""))
        if blob:
            try:
                value = json.loads(base64.b64decode(blob).decode("utf-8", "replace"))
                if value is None:
                    collection.failed('windows', 'PowerShell returned null')
                else:
                    collection.succeeded('windows')
                return value
            except Exception:
                collection.failed('windows', 'invalid PowerShell payload')
                return None

        if attempt == 1:
            # No output at all: most likely a dead interop socket. Drop the
            # cached value so ensure_interop() picks a fresh one, and retry.
            os.environ.pop("WSL_INTEROP", None)
            if not collect_windows.ensure_interop():
                collection.failed('windows', 'interop retry unavailable')
                return None
    collection.failed('windows', 'PowerShell returned no payload')
    return None


def _aslist(v):
    """PowerShell collapses single-element arrays; normalize back to a list."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


_TRUSTED_IDE_TASKS = {
    "wsl ide keepalive": {
        "script": "wsl-ide-keepalive-supervisor.ps1",
        "hash": "45c0e95c0bb388c7091d0ce2d3b83e6e692ac954791fcfb6ab1039fd5e6011d5",
        "logon": "s4u",
    },
    "wsl ide keepalive watchdog": {
        "script": "wsl-ide-keepalive-watchdog.ps1",
        "hash": "1e69a376ceec44355343684861239f55e2f3b3955ed684a51ef2cf3929ab6207",
        "logon": "s4u",
    },
}


def _normalized_text_hash(path):
    """Hash reviewed script text independent of Windows newline/EOF style."""
    try:
        with open(path, encoding="utf-8-sig", errors="strict", newline="") as fh:
            text = fh.read().replace("\r\n", "\n").rstrip()
    except (OSError, UnicodeError):
        return ""
    return hashlib.sha256(text.encode()).hexdigest()


def _task_action_text(task):
    return " ; ".join(
        " ".join(filter(None, (a.get("execute"), a.get("arguments"))))
        for a in _aslist(task.get("actions")) if isinstance(a, dict)
    )


def _verified_maintenance_task(task, data):
    """Verify reviewed local watchdogs without trusting their names alone.

    All fields are required: one PowerShell action, exact arguments, limited
    principal, current Windows user, expected LocalAppData path, and the
    reviewed script fingerprint.  A renamed or modified script therefore
    remains a critical persistence finding.
    """
    name = (task.get("name") or "").casefold()
    if name not in _TRUSTED_IDE_TASKS and name not in ("jarvis wake watchdog", "jarvis independent health monitor", "jarvis connectivity guard"):
        return False, "not a known maintenance task"

    actions = _aslist(task.get("actions"))
    if len(actions) != 1 or not isinstance(actions[0], dict):
        return False, "expected exactly one action"
    action = actions[0]
    execute = (action.get("execute") or "").replace("/", "\\").casefold()
    arguments = action.get("arguments") or ""
    if re.fullmatch(r"(?:%systemroot%|c:\\windows)\\system32\\conhost\.exe", execute):
        # conhost --headless is the only launch path that never shows a window;
        # accept it solely as a wrapper around System32 Windows PowerShell.
        wrapped = re.match(
            r"--headless\s+\"?(?:%SystemRoot%|C:\\Windows)\\System32\\WindowsPowerShell"
            r"\\v1\.0\\powershell\.exe\"?\s+(.*)$", arguments, re.I | re.S)
        if not wrapped:
            return False, "headless console host does not wrap Windows PowerShell"
        arguments = wrapped.group(1)
    elif execute.rsplit("\\", 1)[-1] not in ("powershell.exe", "powershell"):
        return False, "action is not Windows PowerShell"
    if (task.get("runLevel") or "").casefold() != "limited":
        return False, "principal is not limited"

    actual_user = (task.get("user") or "").casefold().rsplit("\\", 1)[-1]
    current_user = (data.get("currentUser") or "").casefold().rsplit("\\", 1)[-1]
    if not actual_user or actual_user != current_user:
        return False, "principal is not the current Windows user"

    local = (data.get("localAppData") or "").rstrip("\\/")
    repo_root = str(REPO_ROOT)
    if name == "jarvis connectivity guard":
        spec = {"script":"connectivity-jarvis.ps1", "logon":"interactive",
                "hash":_normalized_text_hash(os.path.join(repo_root, "connectivity-jarvis.ps1"))}
        expected_args = (
            rf'^-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass '
            rf'-File "{re.escape(local)}\\Jarvis\\Connectivity\\connectivity-jarvis\.ps1" '
            rf'-StateRoot "{re.escape(local)}\\Jarvis\\Connectivity"$')
    elif name == "jarvis independent health monitor":
        spec = {"script":"deadman-jarvis.ps1", "logon":"interactive",
                "hash":_normalized_text_hash(os.path.join(repo_root,"deadman-jarvis.ps1"))}
        expected_args = (
            rf'^-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass '
            rf'-File "{re.escape(local)}\\Jarvis\\Deadman\\deadman-jarvis\.ps1"$')
    elif name == "jarvis wake watchdog":
        spec = {
            "script": "wake-jarvis.ps1",
            "hash": _normalized_text_hash(os.path.join(
                repo_root, "wake-jarvis.ps1")),
            "logon": "interactive",
        }
        expected_args = (
            rf'^-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass '
            rf'-File "{re.escape(local)}\\WSLKeepalive\\wake-jarvis\.ps1" '
            rf'-Distro "Ubuntu" -RepoRoot "{re.escape(repo_root)}" '
            rf'-RecoverInterop true$'
        )
    else:
        spec = _TRUSTED_IDE_TASKS[name]
        expected_args = (
            rf'^-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass '
            rf'-File "{re.escape(local)}\\WSLKeepalive\\{re.escape(spec["script"])}"$'
        )

    if (task.get("logonType") or "").casefold() != spec["logon"]:
        return False, f'logon type is not {spec["logon"]}'
    if not re.fullmatch(expected_args, arguments, re.I):
        return False, "arguments differ from the reviewed definition"
    if not spec["hash"] or (action.get("targetHash") or "").casefold() != spec["hash"]:
        return False, "script fingerprint differs from the reviewed version"
    return True, "exact task definition and script fingerprint verified"


def audit_windows():
    data = _ps_json(PS_CONTROL)
    if data is None:
        return [_finding("defense", "medium", "Windows audit unavailable",
                         "powershell.exe did not return data; some checks need an "
                         "elevated shell", "interop")]
    out = []

    for t in _aslist(data.get("tasks")):
        action = _task_action_text(t)
        trusted, trust_detail = _verified_maintenance_task(t, data)
        if trusted:
            out.append(_finding("persistence", "low", "verified scheduled task",
                                f"{t.get('name')} — {trust_detail}",
                                (t.get("path") or "") + str(t.get("name"))))
            continue
        sev = "high" if REMOTE_AGENTS.search(action + (t.get("name") or "")) else "low"
        if OBFUSCATED.search(action):
            sev = "critical"
        if (t.get("name") or "").casefold() in (
                "jarvis wake watchdog", "jarvis independent health monitor", "wsl ide keepalive",
                "wsl ide keepalive watchdog"):
            sev = "critical"
            action = f"{action} [verification failed: {trust_detail}]"
        out.append(_finding("persistence", sev, "scheduled task",
                            f"{t.get('name')} → {short(action, 90)}",
                            (t.get("path") or "") + str(t.get("name"))))

    for k in _aslist(data.get("runkeys")):
        val = k.get("value") or ""
        sev = "high" if REMOTE_AGENTS.search(val) else "medium"
        if OBFUSCATED.search(val) or re.search(r"\\temp\\|\\downloads\\", val, re.I):
            sev = "critical"
        out.append(_finding("persistence", sev, "autostart registry entry",
                            f"{k.get('name')} = {short(val, 90)}", k.get("key", "")))

    for s in _aslist(data.get("startup")):
        out.append(_finding("persistence", "medium", "startup folder item",
                            s.get("name", ""), s.get("path", "")))

    for s in _aslist(data.get("services")):
        path = s.get("path") or ""
        sev = "high" if REMOTE_AGENTS.search(path + (s.get("disp") or "")) else "low"
        if re.search(r"\\temp\\|\\users\\public\\|\\appdata\\", path, re.I):
            sev = "critical"
        out.append(_finding("persistence", sev, "auto-start service",
                            f"{s.get('disp') or s.get('name')} [{s.get('state')}] "
                            f"{short(path, 80)}", s.get("name", "")))

    for w in _aslist(data.get("wmi")):
        pair = f"{w.get('filter')} {w.get('consumer')}"
        # Windows ships one of these out of the box; the rest deserve alarm.
        stock = "SCM Event Log" in pair
        out.append(_finding("persistence", "low" if stock else "critical",
                            "WMI event subscription"
                            + (" (Windows built-in)" if stock else ""),
                            f"{short(str(w.get('filter')), 60)} → "
                            f"{short(str(w.get('consumer')), 60)}",
                            "root\\subscription"))

    remote = data.get("remote") or {}
    if remote.get("rdpEnabled"):
        out.append(_finding("remote", "high", "Remote Desktop is enabled",
                            "inbound RDP can drive this machine interactively",
                            "Terminal Server\\fDenyTSConnections"))
    if (remote.get("winrm") or "") == "Running":
        out.append(_finding("remote", "high", "WinRM service running",
                            "accepts remote PowerShell", "Service: WinRM"))
    if (remote.get("sshd") or "") == "Running":
        out.append(_finding("remote", "high", "OpenSSH server running",
                            "accepts inbound SSH", "Service: sshd"))
    for line in _aslist(remote.get("sessions")):
        if isinstance(line, str) and line.strip() and "USERNAME" not in line:
            out.append(_finding("remote", "medium", "logon session",
                                short(line.strip(), 90), "query user"))

    d = data.get("defender") or {}
    if d.get("present"):
        if d.get("realtime") is False:
            out.append(_finding("defense", "critical",
                                "Defender real-time protection is OFF",
                                "live scanning disabled", "Get-MpComputerStatus"))
        if d.get("tamperProtection") is False:
            out.append(_finding("defense", "high", "Tamper Protection is OFF",
                                "Defender settings can be changed by software",
                                "Get-MpComputerStatus"))
        if d.get("antivirus") is False:
            out.append(_finding("defense", "critical", "Defender antivirus disabled",
                                "", "Get-MpComputerStatus"))
        age = d.get("sigAgeDays")
        if isinstance(age, int) and age > 7:
            out.append(_finding("defense", "medium", "Defender signatures stale",
                                f"{age} days old", "Get-MpComputerStatus"))
        denied = False
        for kind, key in (("path", "exclusionPaths"), ("process", "exclusionProcs")):
            for p in _aslist(d.get(key)):
                if not p:
                    continue
                if str(p).startswith("N/A"):
                    denied = True  # non-admin shell: value is a refusal, not a path
                    continue
                out.append(_finding("defense", "high",
                                    f"Defender scan exclusion ({kind})",
                                    str(p), "Get-MpPreference"))
        if denied:
            out.append(_finding("defense", "medium", "Defender exclusions not readable",
                                "run this audit from an elevated PowerShell to see "
                                "which paths are excluded from scanning",
                                "Get-MpPreference"))
    else:
        out.append(_finding("defense", "medium", "Defender status unreadable",
                            "run the audit from an elevated shell for defense checks",
                            "Get-MpComputerStatus"))

    for fw in _aslist(data.get("firewall")):
        if fw.get("enabled") in (False, 0, "False"):
            out.append(_finding("defense", "critical",
                                f"firewall disabled on {fw.get('name')} profile",
                                "inbound traffic unfiltered", "Get-NetFirewallProfile"))

    for r in _aslist(data.get("fwrules")):
        out.append(_finding("remote", "low", "inbound firewall allow rule",
                            short(str(r.get("DisplayName")), 80),
                            str(r.get("Profile"))))

    for a in _aslist(data.get("admins")):
        out.append(_finding("defense", "low", "local administrator", str(a),
                            "Administrators group"))

    if data.get("uac") == 0:
        out.append(_finding("defense", "critical", "UAC is disabled",
                            "elevation prompts are off", "EnableLUA"))

    for f in out:
        f["host"] = "win"
    return out


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CAT_ORDER = {"defense": 0, "remote": 1, "persistence": 2}


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        out += audit_linux()
    if "win" in hosts:
        out += audit_windows()
    # Group by category first so each section prints once, worst item at the top.
    out.sort(key=lambda f: (CAT_ORDER.get(f["category"], 9),
                            SEV_ORDER.get(f["severity"], 9), f["title"]))
    return out
