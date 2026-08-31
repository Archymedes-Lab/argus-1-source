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

import os
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


def _rules_on_disk():
    """Non-comment lines across /etc/audit/rules.d and audit.rules."""
    import glob
    n = 0
    for path in glob.glob("/etc/audit/rules.d/*.rules") + ["/etc/audit/audit.rules"]:
        try:
            with open(path) as fh:
                n += sum(1 for ln in fh
                         if ln.strip() and not ln.lstrip().startswith("#"))
        except OSError:
            continue
    return n


def state():
    """(installed, running, rule_count, how).

    `auditctl` needs root even to read status. When it is denied, fall back to
    signals a normal user can see — `systemctl is-active auditd`, the rule
    files on disk, whether the audit log is being written — and mark `how` as
    "fallback" so the caller can caveat.
    """
    if not shutil.which("auditctl"):
        return False, False, 0, "none"
    out, rc = _run(["auditctl", "-s"])
    denied = ("must be root" in out.lower()
              or "operation not permitted" in out.lower())
    if not denied and rc == 0 and out.strip():
        running = False
        for line in out.splitlines():
            if line.startswith("enabled"):
                running = line.split()[-1] in ("1", "2")
            if line.startswith("pid") and line.split()[-1] not in ("0", ""):
                running = True
        rules_out, _ = _run(["auditctl", "-l"])
        rc_rules = 0 if rules_out.strip().lower().startswith("no rules") \
            else len([r for r in rules_out.splitlines() if r.strip()])
        return True, running, rc_rules, "auditctl"

    active_out, _ = _run(["systemctl", "is-active", "auditd"])
    running = active_out.strip() == "active"
    rules = _rules_on_disk()
    try:
        if os.path.getsize("/var/log/audit/audit.log") > 0:
            rules = rules or 1
    except OSError:
        pass
    return True, running, rules, "fallback"


def active():
    installed, running, rules, _how = state()
    return installed and running and rules > 0


def _is_wsl():
    try:
        with open("/proc/sys/kernel/osrelease") as fh:
            return "microsoft" in fh.read().lower()
    except OSError:
        return False


def _service_failed():
    out, _ = _run(["systemctl", "is-failed", "auditd"])
    return out.strip() == "failed"


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
    installed, running, rules, how = state()
    caveat = ("" if how == "auditctl"
              else " (read without root — `sudo sentry auditd` confirms)")

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
        if _is_wsl() and _service_failed():
            return [_finding(
                "auditd", "medium",
                "auditd cannot run on this WSL2 kernel",
                "the service fails at start with 'audit_set_pid: Operation not "
                "permitted' — Microsoft's WSL2 kernel rejects the audit daemon "
                "over the netlink socket, and no userland change fixes it. "
                "Syscall interception here needs eBPF tooling (Sysmon for "
                "Linux; BTF is present). `sudo systemctl disable --now auditd` "
                "to stop the restart loop", "auditd.service")]
        out.append(_finding(
            "auditd", "high", f"auditd is installed but not running{caveat}",
            "the kernel is not recording syscalls — nothing between two "
            "sampling passes is captured. `sudo systemctl enable --now auditd`",
            "systemctl"))
        return out

    if rules == 0:
        out.append(_finding(
            "auditd", "medium", f"auditd is running with no rules loaded{caveat}",
            "a running auditd with an empty ruleset records almost nothing. "
            "Drop a ruleset into /etc/audit/rules.d/ — Neo23x0/auditd or the "
            "CIS set — then `sudo augenrules --load`", "auditctl -l"))
        return out

    out.append(_finding(
        "auditd", "ok", f"syscall interception is active{caveat}",
        f"auditd running with {rules} rule(s) — runtime-behaviour techniques "
        f"are being recorded", "auditctl"))

    for key, n in _recent_notable():
        out.append(_finding(
            "auditd", "high" if key.startswith("T1") or "susp" in key
            else "medium",
            f"auditd rule '{key}' fired {n} time(s) recently",
            "a ruleset key that tags high-signal activity matched in the "
            "recent window — run `ausearch -k " + key + " -ts recent -i`",
            "ausearch"))
    return sort_findings(out)
