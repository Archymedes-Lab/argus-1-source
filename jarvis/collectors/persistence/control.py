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

import glob
import os
import re
import subprocess

from jarvis.collectors.signatures import REMOTE_AGENTS
from jarvis.core.paths import load_win_script
from jarvis.core.util import short
from jarvis.platform.windows import aslist, ps_json

from .trusted_tasks import verified_maintenance_task

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

PS_CONTROL = load_win_script("control.ps1")




def _task_action_text(task):
    return " ; ".join(
        " ".join(filter(None, (a.get("execute"), a.get("arguments"))))
        for a in aslist(task.get("actions")) if isinstance(a, dict)
    )


def audit_windows():
    data = ps_json(PS_CONTROL)
    if data is None:
        return [_finding("defense", "medium", "Windows audit unavailable",
                         "powershell.exe did not return data; some checks need an "
                         "elevated shell", "interop")]
    out = []

    for t in aslist(data.get("tasks")):
        action = _task_action_text(t)
        trusted, trust_detail = verified_maintenance_task(t, data)
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

    for k in aslist(data.get("runkeys")):
        val = k.get("value") or ""
        sev = "high" if REMOTE_AGENTS.search(val) else "medium"
        if OBFUSCATED.search(val) or re.search(r"\\temp\\|\\downloads\\", val, re.I):
            sev = "critical"
        out.append(_finding("persistence", sev, "autostart registry entry",
                            f"{k.get('name')} = {short(val, 90)}", k.get("key", "")))

    for s in aslist(data.get("startup")):
        out.append(_finding("persistence", "medium", "startup folder item",
                            s.get("name", ""), s.get("path", "")))

    for s in aslist(data.get("services")):
        path = s.get("path") or ""
        sev = "high" if REMOTE_AGENTS.search(path + (s.get("disp") or "")) else "low"
        if re.search(r"\\temp\\|\\users\\public\\|\\appdata\\", path, re.I):
            sev = "critical"
        out.append(_finding("persistence", sev, "auto-start service",
                            f"{s.get('disp') or s.get('name')} [{s.get('state')}] "
                            f"{short(path, 80)}", s.get("name", "")))

    for w in aslist(data.get("wmi")):
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
    for line in aslist(remote.get("sessions")):
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
            for p in aslist(d.get(key)):
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

    for fw in aslist(data.get("firewall")):
        if fw.get("enabled") in (False, 0, "False"):
            out.append(_finding("defense", "critical",
                                f"firewall disabled on {fw.get('name')} profile",
                                "inbound traffic unfiltered", "Get-NetFirewallProfile"))

    for r in aslist(data.get("fwrules")):
        out.append(_finding("remote", "low", "inbound firewall allow rule",
                            short(str(r.get("DisplayName")), 80),
                            str(r.get("Profile"))))

    for a in aslist(data.get("admins")):
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
