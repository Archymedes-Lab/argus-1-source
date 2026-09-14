"""Password guessing, seen from the artefacts it leaves in the auth logs.

Brute force (T1110) is one of the most-cited techniques in the intel corpus and
one of the few runtime behaviours that *does* leave a durable host artefact: a
pile of failed-authentication records. Every OS keeps them.

  Linux   sshd and PAM write "Failed password", "authentication failure" and
          "Invalid user" lines to the journal or /var/log/auth.log. btmp
          (read by `lastb`) records failed logins too, when it is readable.

  Windows the Security log records event 4625 for every failed logon and 4740
          for an account lockout — but only if logon auditing is enabled, so
          "no events" is reported as "cannot tell", not "clean".

This is a counting exercise, not interception: a spike of failures from one
source, a spread of failures across many usernames (spraying), or any lockout
is the signal. It cannot see a slow, low-volume guess that stays under the
threshold, and it says so.
"""

import re
import subprocess

from jarvis.core.finding import finding as _finding
from jarvis.platform import windows as collect_windows
from jarvis.platform.windows import ps_json

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

WINDOW_H = 24
SPIKE_ONE_SOURCE = 20      # failures from a single source in the window
SPRAY_USERS = 10           # distinct usernames targeted from one source
TOTAL_ELEVATED = 40        # total failures in the window worth a medium

_LINUX_FAIL = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
    r"|authentication failure;.*?(?:user=(?P<user2>\S+))?.*?rhost=(?P<ip2>\S+)"
    r"|Invalid user (?P<user3>\S+) from (?P<ip3>\S+)")


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))


# ── Linux ───────────────────────────────────────────────────────────────────

def _linux_lines():
    """Recent auth lines, from the journal if present, else the flat logs."""
    since = f"{WINDOW_H} hours ago"
    try:
        r = subprocess.run(
            ["journalctl", "--since", since, "--no-pager", "-q",
             "SYSLOG_FACILITY=10", "-o", "cat"],
            capture_output=True, text=True,
            errors="replace", timeout=30)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        pass
    lines = []
    for p in ("/var/log/auth.log", "/var/log/auth.log.1",
              "/var/log/secure", "/var/log/secure.1"):
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                lines += fh.read().splitlines()[-20000:]
        except OSError:
            continue
    return lines


def _linux():
    out = []
    lines = _linux_lines()
    if not lines:
        out.append(_finding(
            "bruteforce", "low", "no readable auth log on the Linux side",
            "neither the journal nor /var/log/auth.log could be read, so "
            "failed-login volume here is unknown — run as root to see it",
            "journalctl / auth.log"))
        return out

    by_ip = {}          # ip -> [count, {users}]
    sudo_fail = 0
    for ln in lines:
        if "pam_unix(sudo:auth): authentication failure" in ln:
            sudo_fail += 1
        m = _LINUX_FAIL.search(ln)
        if not m:
            continue
        ip = m.group("ip") or m.group("ip2") or m.group("ip3") or "?"
        user = m.group("user") or m.group("user2") or m.group("user3") or "?"
        rec = by_ip.setdefault(ip, [0, set()])
        rec[0] += 1
        rec[1].add(user)

    total = sum(v[0] for v in by_ip.values())
    for ip, (n, users) in sorted(by_ip.items(), key=lambda x: -x[1][0])[:8]:
        if n >= SPIKE_ONE_SOURCE or len(users) >= SPRAY_USERS:
            spray = (f", spread across {len(users)} usernames"
                     if len(users) >= SPRAY_USERS else "")
            out.append(_finding(
                "bruteforce", "high",
                f"{n} failed SSH/PAM logins from {ip} in {WINDOW_H}h{spray}",
                f"sample users: {', '.join(sorted(users)[:6])}. A sustained "
                f"guess against this host — confirm the source is yours or "
                f"block it", "auth log"))

    if not out and total >= TOTAL_ELEVATED:
        out.append(_finding(
            "bruteforce", "medium",
            f"{total} failed logins on the Linux side in {WINDOW_H}h",
            "below the single-source spike threshold but above background — "
            "worth knowing which host and account", "auth log"))

    if sudo_fail >= 5:
        out.append(_finding(
            "bruteforce", "medium",
            f"{sudo_fail} failed sudo authentications in {WINDOW_H}h",
            "repeated wrong passwords at sudo — a local user, or something "
            "trying to escalate", "auth log"))

    if not out:
        out.append(_finding(
            "bruteforce", "ok", "no failed-login spike on the Linux side",
            f"{total} failed attempts in {WINDOW_H}h, none concentrated on one "
            f"source", "auth log"))
    return out


# ── Windows ─────────────────────────────────────────────────────────────────

_WIN_PS = r"""
$since = (Get-Date).AddDays(-1)
$out = @{ auditing = 1; total = 0; top = @(); lockouts = 0 }
try {
  $ev = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$since} `
        -MaxEvents 5000 -ErrorAction Stop
  $out.total = $ev.Count
  $out.top = $ev | ForEach-Object {
      $x = [xml]$_.ToXml()
      $d = @{}
      $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
      [pscustomobject]@{ user = $d['TargetUserName']; ip = $d['IpAddress'] }
    } | Group-Object { "$($_.user)|$($_.ip)" } |
    Sort-Object Count -Descending | Select-Object -First 6 |
    ForEach-Object { @{ key = $_.Name; n = $_.Count } }
} catch {
  $m = "$($_.Exception.Message)"
  if ($m -match 'No events were found') { $out.auditing = 1 }
  elseif ($m -match 'Unauthorized|access is denied|not authorized') { $out.auditing = -1 }
  else { $out.auditing = 0 }
}
try {
  $out.lockouts = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4740;StartTime=(Get-Date).AddDays(-7)} `
    -MaxEvents 200 -ErrorAction Stop).Count
} catch { }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $out -Depth 5)))
"""


def _windows():
    out = []
    if not collect_windows.available():
        return out
    d = ps_json(_WIN_PS, timeout=120)
    if not d:
        return [_finding(
            "bruteforce", "low", "could not read the Windows Security log",
            "the 4625 query returned nothing — the log may be inaccessible "
            "from here", "Security log", host="win")]

    auditing = int(d.get("auditing") or 0)
    if auditing == -1:
        out.append(_finding(
            "bruteforce", "low", "cannot read the Windows Security log",
            "the 4625 query was denied — reading it needs Administrator or "
            "'Event Log Readers' membership, so failed-logon volume on the "
            "Windows side is unknown from here", "Security log", host="win"))
        return out
    if auditing == 0:
        out.append(_finding(
            "bruteforce", "medium", "failed-logon auditing looks disabled",
            "the 4625 query returned no events and no error, which usually "
            "means 'Audit logon events' is off — a brute force against this "
            "machine would leave no trace. Enable it in the local security "
            "policy", "auditpol", host="win"))
        return out

    total = int(d.get("total") or 0)
    top = d.get("top") or []
    if isinstance(top, dict):
        top = [top]
    for row in top:
        n = int(row.get("n") or 0)
        key = (row.get("key") or "?|?").split("|", 1)
        user, ip = (key + ["?"])[:2]
        if n >= SPIKE_ONE_SOURCE:
            out.append(_finding(
                "bruteforce", "high",
                f"{n} failed Windows logons for {user or '(blank)'} "
                f"from {ip or 'local'} in 24h",
                "a concentrated logon-guessing attempt — confirm the source",
                "Security log 4625", host="win"))

    if int(d.get("lockouts") or 0):
        out.append(_finding(
            "bruteforce", "high",
            f"{d['lockouts']} account lockout(s) in the last 7 days",
            "an account hit the lockout threshold — either a real attack or a "
            "stale credential hammering the domain", "Security log 4740",
            host="win"))

    if not out and total >= TOTAL_ELEVATED:
        out.append(_finding(
            "bruteforce", "medium",
            f"{total} failed Windows logons in 24h",
            "elevated but not concentrated on one source", "Security log 4625",
            host="win"))
    if not out:
        out.append(_finding(
            "bruteforce", "ok", "no failed-logon spike on the Windows side",
            f"{total} failed logons in 24h, none concentrated", "Security log",
            host="win"))
    return out


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        out += _linux()
    if "win" in hosts:
        out += _windows()
    return sort_findings(out)
