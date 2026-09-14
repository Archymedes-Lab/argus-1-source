"""Backdoors: the ways back in that survive a reboot and a password change.

A backdoor is not malware. It is usually a line in a config file, a key in a
file the owner never reads, or an account that looks like it belongs. Nothing
here is a signature match — every check reads a mechanism that grants access
and asks whether what it grants is what you intended.

The vectors are the ones current research keeps naming: SSH authorised keys and
sshd_config, systemd *user* services (which need no root at all), XDG autostart
entries, appended shell profiles, sudoers NOPASSWD grants, setuid binaries no
package owns, and second UID-0 accounts.

Most findings here need a human to confirm, because the tool cannot know which
SSH key is yours. So each one shows the actual evidence — the key comment, the
sudoers line, the appended command — rather than only naming the file.
"""

import glob
import os
import pwd
import re
import stat

from jarvis.core.util import dpkg_owns
from jarvis.platform.windows import aslist, ps_json
from jarvis.core.finding import finding as _finding

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CAT_ORDER = {"remote access": 0, "privilege": 1, "persistence": 2,
             "accounts": 3}

# Commands that fetch and run, or open a shell to somewhere. In a profile or a
# cron entry these are how a foothold re-establishes itself on every login.
PAYLOAD_RE = re.compile(
    r"(curl|wget)\s[^|;&]*\|\s*(ba|z|d|k)?sh"          # download and pipe
    r"|nc\s+(-[a-z]*e|.*-e\s)"                          # netcat with -e
    r"|bash\s+-i\s*>&\s*/dev/tcp"                       # bash reverse shell
    r"|/dev/tcp/\d"                                     # raw tcp redirect
    r"|python3?\s+-c\s+.{0,40}(socket|pty)"             # python reverse shell
    r"|base64\s+-d\s*\|\s*(ba)?sh"                      # decode and run
    r"|socat\s+.*exec"
    r"|\bncat\b.*--exec",
    re.I)


def _read(path, limit=200000):
    try:
        with open(path, errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


_dpkg_owns = dpkg_owns

# jarvis's own units, installed by install.sh. A monitor that reports itself as
# a backdoor trains you to skim the section where a real one would appear.
_SELF_UNITS = ("jarvis.service", "jarvis-selfcheck.service",
               "jarvis-selfcheck.timer")


def _is_self(unit_name, execs):
    """True for jarvis's own systemd units — matched on name AND command.

    Both have to agree. Matching on the filename alone would let anything
    named jarvis.service through, which is a cheap way to hide in the one
    place this audit has been told not to look.
    """
    if unit_name not in _SELF_UNITS:
        return False
    if not execs:
        return unit_name.endswith(".timer")     # timers carry no Exec line
    return all(re.search(r"-m\s+jarvis\b", e) for e in execs)


def _home_dirs():
    out = []
    try:
        for p in pwd.getpwall():
            if p.pw_dir and os.path.isdir(p.pw_dir) and (
                    p.pw_uid >= 1000 or p.pw_uid == 0):
                out.append((p.pw_name, p.pw_dir, p.pw_uid))
    except Exception:
        pass
    return out


# ── SSH ───────────────────────────────────────────────────────────────────

def check_ssh():
    out = []
    for user, home, _uid in _home_dirs():
        ak = os.path.join(home, ".ssh", "authorized_keys")
        body = _read(ak)
        if not body.strip():
            continue
        keys = [l.strip() for l in body.splitlines()
                if l.strip() and not l.startswith("#")]
        for k in keys:
            parts = k.split()
            comment = parts[2] if len(parts) > 2 else "(no comment)"
            fp = parts[1][:24] + "…" if len(parts) > 1 else "?"
            forced = "command=" in k or "no-pty" in k
            out.append(_finding(
                "remote access", "high",
                f"SSH key authorised for {user}: {comment}",
                f"anyone holding the matching private key can log in as {user} "
                f"without a password"
                + (" — this entry also forces a command" if forced else "")
                + f"  [{fp}]", ak))
        # A key file writable by others is a way to add a key later.
        try:
            mode = os.stat(ak).st_mode
            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                out.append(_finding(
                    "remote access", "critical",
                    f"authorized_keys for {user} is writable by others",
                    f"mode {oct(mode & 0o777)} — anyone on this system can "
                    f"add their own key", ak))
        except OSError:
            pass

    cfg = _read("/etc/ssh/sshd_config")
    extra = ""
    for inc in glob.glob("/etc/ssh/sshd_config.d/*.conf"):
        extra += "\n" + _read(inc)
    full = cfg + extra
    risky = {
        "permitrootlogin": (re.compile(r"^\s*PermitRootLogin\s+(yes|without-password|prohibit-password)",
                                       re.I | re.M),
                            "high", "root can log in over SSH"),
        "authorizedkeyscommand": (re.compile(r"^\s*AuthorizedKeysCommand\s+(\S+)", re.I | re.M),
                                  "high",
                                  "authorised keys come from a command's output — "
                                  "whoever controls that program controls who may log in"),
        "permittunnel": (re.compile(r"^\s*PermitTunnel\s+(yes|point-to-point|ethernet)", re.I | re.M),
                         "medium", "SSH may build a network tunnel into this host"),
        "gatewayports": (re.compile(r"^\s*GatewayPorts\s+(yes|clientspecified)", re.I | re.M),
                         "medium", "forwarded ports are reachable from off-host"),
        "permitemptypasswords": (re.compile(r"^\s*PermitEmptyPasswords\s+yes", re.I | re.M),
                                 "critical", "accounts with empty passwords may log in"),
    }
    for _name, (rx, sev, why) in risky.items():
        m = rx.search(full)
        if m:
            out.append(_finding(
                "remote access", sev,
                f"sshd_config: {m.group(0).strip()}", why, "/etc/ssh/sshd_config"))
    return out


# ── privilege ─────────────────────────────────────────────────────────────

def check_privilege():
    out = []
    files = ["/etc/sudoers"] + sorted(glob.glob("/etc/sudoers.d/*"))
    for f in files:
        for line in _read(f).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "NOPASSWD" in line.upper():
                sev = "high" if re.search(r"ALL\s*$", line) else "medium"
                out.append(_finding(
                    "privilege", sev, f"passwordless sudo: {line[:90]}",
                    "this grant does not re-prompt, so anything running as "
                    "that user can become root silently", f))

    # setuid binaries no package owns
    roots = ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin",
             "/usr/local/sbin", "/opt", "/home", "/tmp", "/var/tmp")
    checked = 0
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if checked > 40000:
                break
            if dirpath.count("/") - root.count("/") > 3:
                dirnames[:] = []
            for fn in filenames:
                checked += 1
                full = os.path.join(dirpath, fn)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode) or not (st.st_mode & (stat.S_ISUID | stat.S_ISGID)):
                    continue
                if _dpkg_owns(full):
                    continue
                which = "setuid" if st.st_mode & stat.S_ISUID else "setgid"
                out.append(_finding(
                    "privilege", "critical",
                    f"{which} binary no package owns: {fn}",
                    f"runs as {'root' if st.st_uid == 0 else 'uid ' + str(st.st_uid)} "
                    f"regardless of who executes it — a classic way to keep root "
                    f"after losing it", full))
    return out


# ── accounts ──────────────────────────────────────────────────────────────

def check_accounts():
    out = []
    try:
        entries = list(pwd.getpwall())
    except Exception:
        return out
    for p in entries:
        if p.pw_uid == 0 and p.pw_name != "root":
            out.append(_finding(
                "accounts", "critical",
                f"second account with uid 0: {p.pw_name}",
                "a uid-0 account is root under another name", "/etc/passwd"))
    shadow = _read("/etc/shadow")
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) > 1 and parts[1] == "":
            out.append(_finding(
                "accounts", "critical",
                f"account '{parts[0]}' has an empty password",
                "it can be logged into with no credential at all", "/etc/shadow"))
    return out


# ── persistence ───────────────────────────────────────────────────────────

PROFILE_FILES = (".bashrc", ".bash_profile", ".profile", ".zshrc",
                 ".zprofile", ".bash_login", ".bash_logout")


def check_persistence():
    out = []
    # shell profiles
    targets = ["/etc/profile"] + sorted(glob.glob("/etc/profile.d/*.sh"))
    for user, home, _uid in _home_dirs():
        targets += [os.path.join(home, f) for f in PROFILE_FILES]
    for f in targets:
        body = _read(f)
        if not body:
            continue
        for i, line in enumerate(body.splitlines(), 1):
            if PAYLOAD_RE.search(line):
                out.append(_finding(
                    "persistence", "critical",
                    f"shell profile runs a payload: {os.path.basename(f)}:{i}",
                    f"{line.strip()[:150]} — this executes on every login",
                    f))

    # systemd user services need no root and are easy to miss
    for user, home, _uid in _home_dirs():
        d = os.path.join(home, ".config", "systemd", "user")
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith((".service", ".timer")):
                continue
            full = os.path.join(d, fn)
            body = _read(full)
            execs = re.findall(r"^\s*Exec\w*\s*=\s*(.+)$", body, re.M)
            # Do not report ourselves. jarvis's own units are installed by
            # install.sh and are the reason this audit runs at all; flagging
            # them as persistence teaches you to skim past this section, which
            # is exactly how a real unit slips through.
            if _is_self(fn, execs):
                continue
            out.append(_finding(
                "persistence", "high",
                f"systemd user unit for {user}: {fn}",
                (execs[0][:130] if execs else "no Exec line")
                + " — user units start at login and need no root", full))

    # XDG autostart
    xdg = ["/etc/xdg/autostart"]
    for user, home, _uid in _home_dirs():
        xdg.append(os.path.join(home, ".config", "autostart"))
    for d in xdg:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".desktop"):
                continue
            full = os.path.join(d, fn)
            if _dpkg_owns(full):
                continue
            body = _read(full)
            m = re.search(r"^\s*Exec\s*=\s*(.+)$", body, re.M)
            out.append(_finding(
                "persistence", "medium",
                f"autostart entry no package owns: {fn}",
                (m.group(1)[:130] if m else "no Exec line"), full))

    # cron
    cron_files = sorted(glob.glob("/etc/cron.d/*")) + ["/etc/crontab"]
    cron_files += sorted(glob.glob("/var/spool/cron/crontabs/*"))
    for f in cron_files:
        body = _read(f)
        if not body:
            continue
        owned = _dpkg_owns(f)
        for i, line in enumerate(body.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if PAYLOAD_RE.search(line):
                out.append(_finding(
                    "persistence", "critical",
                    f"cron entry runs a payload: {os.path.basename(f)}:{i}",
                    line[:150], f))
            elif not owned and f.startswith("/etc/cron.d/"):
                out.append(_finding(
                    "persistence", "medium",
                    f"cron file no package owns: {os.path.basename(f)}",
                    line[:150], f))
    return out


# ── Windows ───────────────────────────────────────────────────────────────

PS_BACKDOOR = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$o.authkeys = @()
foreach ($p in @("$env:ProgramData\ssh\administrators_authorized_keys") +
                @(Get-ChildItem C:\Users -Directory |
                  ForEach-Object { Join-Path $_.FullName '.ssh\authorized_keys' })) {
  if (Test-Path $p) {
    $o.authkeys += [pscustomobject]@{ path=$p; body=(Get-Content $p -Raw) }
  }
}

# Accessibility backdoor: a debugger on sethc/utilman gives a SYSTEM shell
# from the logon screen without any credential.
$o.ifeo = @('sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe',
            'displayswitch.exe','atbroker.exe') | ForEach-Object {
  $k = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$_"
  $d = (Get-ItemProperty -Path $k -Name Debugger).Debugger
  if ($d) { [pscustomobject]@{ exe=$_; debugger=[string]$d } }
}

# Accounts hidden from the sign-in screen.
$o.hidden = @()
$ul = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
if (Test-Path $ul) {
  (Get-Item $ul).Property | ForEach-Object {
    $o.hidden += [pscustomobject]@{ name=$_; val=[int](Get-ItemProperty $ul $_).$_ }
  }
}

$o.sshsvc = [string](Get-Service sshd).Status
$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""


def check_windows():
    d = ps_json(PS_BACKDOOR, timeout=180)
    if not d:
        return []
    out = []
    for ak in aslist(d.get("authkeys")):
        for line in (ak.get("body") or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            comment = parts[2] if len(parts) > 2 else "(no comment)"
            out.append(_finding(
                "remote access", "high",
                f"Windows SSH key authorised: {comment}",
                "grants passwordless SSH into this machine",
                ak.get("path", ""), "win"))
    for i in aslist(d.get("ifeo")):
        out.append(_finding(
            "remote access", "critical",
            f"accessibility backdoor on {i.get('exe')}",
            f"debugger = {i.get('debugger')} — this yields a SYSTEM shell from "
            f"the logon screen with no credential",
            "IFEO", "win"))
    for h in aslist(d.get("hidden")):
        if h.get("val") == 0:
            out.append(_finding(
                "accounts", "high",
                f"account hidden from the sign-in screen: {h.get('name')}",
                "SpecialAccounts\\UserList hides it from view but not from use",
                "Winlogon", "win"))
    if str(d.get("sshsvc")).lower() in ("running", "4"):
        out.append(_finding(
            "remote access", "medium", "the Windows OpenSSH server is running",
            "inbound SSH is listening on this machine", "sshd", "win"))
    return out


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        for fn in (check_ssh, check_privilege, check_accounts, check_persistence):
            try:
                out += fn()
            except Exception as exc:
                out.append(_finding("persistence", "medium",
                                    f"{fn.__name__} failed", str(exc)))
    if "win" in hosts:
        try:
            out += check_windows()
        except Exception as exc:
            out.append(_finding("remote access", "medium",
                                "windows backdoor audit failed", str(exc), "", "win"))
    return sort_findings(out)


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9), x["title"]))
