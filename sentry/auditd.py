"""Linux syscall interception — the piece whose absence is `gaps`' whole
"NOT OBSERVABLE" list.

Everything else on the Linux side of sentry samples state on an interval, so
anything that starts and finishes between two passes is never seen: a process
that runs `id`, opens a socket, reads a file and exits leaves nothing to find
later. auditd is the kernel's answer — it records the syscalls as they happen.
Windows has Sysmon for this; Linux has auditd and nothing here was checking
whether it is even installed.

This module reports the posture (installed, running, rules loaded) and, when it
is actually recording, a light read of the notable recent activity. It is not a
log analytics engine — it answers "is the interception layer present and doing
something", which is the question `gaps` needs answered before it can say
whether 200-odd techniques are covered or merely unobservable.
"""

import shutil
import subprocess

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

# Rule keys that common rulesets (Neo23x0/auditd, CIS) attach to high-signal
# events. A hit on one of these in the recent window is worth surfacing.
NOTABLE_KEYS = ("susp_activity", "sbin_susp", "shell_profiles", "T1055",
                "T1059", "T1071", "sshd_config", "sudoers", "cron",
                "pam", "passwd_changes", "power_abuse", "recon",
                "code_injection", "web_shells")


def _finding(category, severity, title, detail, where="", host="wsl"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))


def _run(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr), r.returncode
    except (OSError, subprocess.SubprocessError):
        return "", 1


def state():
    """(installed, running, rule_count) or "denied".

    `auditctl` needs root even to read status, so a non-root run cannot tell
    running-with-rules from stopped. That is reported as "denied", not guessed.
    """
    if not shutil.which("auditctl"):
        return False, False, 0
    out, rc = _run(["auditctl", "-s"])
    if "must be root" in out.lower() or "operation not permitted" in out.lower():
        return "denied"
    running = False
    for line in out.splitlines():
        if line.startswith("enabled"):
            running = line.split()[-1] in ("1", "2")
        if line.startswith("pid") and line.split()[-1] not in ("0", ""):
            running = True
    rules_out, _ = _run(["auditctl", "-l"])
    rc_rules = 0 if rules_out.strip().lower().startswith("no rules") \
        else len([r for r in rules_out.splitlines() if r.strip()])
    return True, running, rc_rules


def active():
    st = state()
    if st == "denied" or not isinstance(st, tuple):
        return False
    installed, running, rules = st
    return installed and running and rules > 0


def _recent_notable():
    if not shutil.which("ausearch"):
        return []
    hits = []
    for key in NOTABLE_KEYS:
        out, rc = _run(["ausearch", "-k", key, "-ts", "recent", "-i"],
                       timeout=20)
        if rc == 0 and out.strip() and "no matches" not in out.lower():
            n = out.count("----") or out.count("type=")
            hits.append((key, n))
    return hits


def audit(hosts=("wsl", "win")):
    if "wsl" not in hosts:
        return []
    st = state()

    if st == "denied":
        return [_finding(
            "auditd", "low",
            "auditd is installed but its state cannot be read without root",
            "run `sudo sentry auditd`, or `sudo systemctl status auditd` and "
            "`sudo auditctl -l`, to confirm it is running with a ruleset",
            "auditctl")]

    installed, running, rules = st

    if not installed:
        return [_finding(
            "auditd", "medium",
            "no syscall interception on the Linux side",
            "auditd is not installed, so every runtime-behaviour technique — "
            "process/file/network discovery, execution, staging, exfil — is "
            "unobservable here rather than merely unseen. `sudo apt install "
            "auditd` (or dnf) and load a ruleset closes most of that gap",
            "auditctl")]

    out = []
    if not running:
        out.append(_finding(
            "auditd", "high", "auditd is installed but not running",
            "the kernel is not recording syscalls — nothing between two "
            "sampling passes is captured. `systemctl enable --now auditd`",
            "systemctl"))
        return out

    if rules == 0:
        out.append(_finding(
            "auditd", "medium", "auditd is running with no rules loaded",
            "a running auditd with an empty ruleset records almost nothing. "
            "Load a ruleset — Neo23x0/auditd or the CIS set — and the "
            "runtime-behaviour techniques become observable", "auditctl -l"))
        return out

    out.append(_finding(
        "auditd", "ok", "syscall interception is active",
        f"auditd running with {rules} rules loaded — runtime-behaviour "
        f"techniques are being recorded", "auditctl"))

    for key, n in _recent_notable():
        out.append(_finding(
            "auditd", "high" if key.startswith("T1") or "susp" in key
            else "medium",
            f"auditd rule '{key}' fired {n} time(s) recently",
            "a ruleset key that tags high-signal activity matched in the "
            "recent window — run `ausearch -k " + key + " -ts recent -i`",
            "ausearch"))
    return sort_findings(out)
