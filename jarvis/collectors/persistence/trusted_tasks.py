"""Scheduled tasks jarvis itself installs, verified so their names buy no trust.

The control audit reports every scheduled task that can run code. A handful are
jarvis's own watchdogs and the reviewed IDE keepalive tasks; these are accepted
only when the whole definition matches: one PowerShell action with exact
arguments, a limited principal, the current Windows user, the expected
LocalAppData path, and the reviewed script fingerprint. A renamed or modified
script therefore stays a critical persistence finding.
"""

import hashlib
import os
import re

from jarvis.core.paths import REPO_ROOT, win_script
from jarvis.platform.windows import aslist

TRUSTED_IDE_TASKS = {
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


def normalized_text_hash(path):
    """Hash reviewed script text independent of Windows newline/EOF style."""
    try:
        with open(path, encoding="utf-8-sig", errors="strict", newline="") as fh:
            text = fh.read().replace("\r\n", "\n").rstrip()
    except (OSError, UnicodeError):
        return ""
    return hashlib.sha256(text.encode()).hexdigest()


def verified_maintenance_task(task, data):
    """Verify reviewed local watchdogs without trusting their names alone.

    All fields are required: one PowerShell action, exact arguments, limited
    principal, current Windows user, expected LocalAppData path, and the
    reviewed script fingerprint.  A renamed or modified script therefore
    remains a critical persistence finding.
    """
    name = (task.get("name") or "").casefold()
    if name not in TRUSTED_IDE_TASKS and name not in (
            "jarvis wake watchdog", "jarvis independent health monitor",
            "jarvis connectivity guard", "jarvis input hook"):
        return False, "not a known maintenance task"

    actions = aslist(task.get("actions"))
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
                "hash":normalized_text_hash(os.path.join(repo_root, "connectivity-jarvis.ps1"))}
        expected_args = (
            rf'^-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass '
            rf'-File "{re.escape(local)}\\Jarvis\\Connectivity\\connectivity-jarvis\.ps1" '
            rf'-StateRoot "{re.escape(local)}\\Jarvis\\Connectivity"$')
    elif name == "jarvis independent health monitor":
        spec = {"script":"deadman-jarvis.ps1", "logon":"interactive",
                "hash":normalized_text_hash(os.path.join(repo_root,"deadman-jarvis.ps1"))}
        expected_args = (
            rf'^-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass '
            rf'-File "{re.escape(local)}\\Jarvis\\Deadman\\deadman-jarvis\.ps1"$')
    elif name == "jarvis input hook":
        # Registered by inputwatch.helper so the keystroke monitor keeps
        # running in the desktop session; the staged script is fingerprinted
        # against the copy in this checkout.
        spec = {"script": "inputhook.ps1", "logon": "interactive",
                "hash": normalized_text_hash(str(win_script("inputhook.ps1")))}
        expected_args = (
            rf'^-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass '
            rf'-File "{re.escape(local)}\\Jarvis\\inputhook\.ps1" '
            rf'-OutFile "{re.escape(local)}\\Jarvis\\input\.jsonl"$')
    elif name == "jarvis wake watchdog":
        spec = {
            "script": "wake-jarvis.ps1",
            "hash": normalized_text_hash(os.path.join(
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
        spec = TRUSTED_IDE_TASKS[name]
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
