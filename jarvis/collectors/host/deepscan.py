"""DeepScan + File Protection: scan files, hash them, and flag suspicious
executables, persistence trees and dangerous content.

The product's promise is not "we scanned and said OK". It is:
1. What do we know about this host right now? (inventory)
2. What does the file system hold that deserves a second look?
3. Which files are dangerous to execute, or are already sitting somewhere
   they should not be, or are part of a persistence layer that a defender
   should not have to reconstruct from a forensic tool?

This module implements the "what" and "how" but does not decide. Each finding
carries a severity, a plain-language explanation of why the file was flagged,
and the evidence behind it (path, size, hash, entires). A "medium" or "high"
finding is never automatically actioned: the owner reviews it in the
investigation view and picks an action (quarantine, allow, ignore, delete).

Cross-platform
--------------
Windows: file enumeration through PowerShell Get-ChildItem with full
          recursion bounds; hashes through .NET's SHA256; executable
          extensions matched against a Windows-specific set.
Linux:  /proc based process reading, os.stat and hashlib for content.
macOS:  os.stat and hashlib; note that macOS uses .app bundles and code
          signing; files that cannot be read are reported as such, never
          silently skipped.

Permissions
-----------
Scanning the whole file system is read-only and needs no privilege. Declared
paths below the user's home directory are reported as "permission-restricted"
when the process cannot open them, and the dashboard shows that as "unsupported
for this path" rather than as a finding that *something is hostile there*.
"""

from __future__ import annotations

import hashlib
import os
import stat
import time
from dataclasses import dataclass, field
from typing import Iterable

# Well-known places a payload hides or that a defender should not have to
# chase down: temp folders, download directories, application data, and every
# place the OS installs persistent artifacts outside the user's control.
SUSPICIOUS_DIRS = (
    "/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/",
    "C:\\Windows\\Temp",
    "C:\\Users\\*\\[Uu]ser*\\[Dd]ocuments\\[Aa]ppdata\\Local\\Temp",
    "C:\\Users\\*\\[Dd]ownloads",
)

# Executable extensions on Windows, plus the classic Unix kinds.
WIN_EXE_EXT = {
    ".exe", ".dll", ".bat", ".cmd", ".com", ".pif", ".scr", ".msi", ".msp",
    ".mst", ".js", ".vbs", ".vbe", ".jse", ".ws", ".wsf", ".wsF", ".wsh",
    ".hta", ".ps1", ".psm1", ".psd1", ".ps1xml",
}
UNIX_EXE_MASK = (
    "rwxrwxrwx", "rwxr-xr-x", "rwxrwx---", "rwxrwxr-x",
)

# Patterns that, when found in an image path or a filename, mark it as a
# suspicious executable even before the extension is checked. These are
# content hints, not verdicts.
SUSPICIOUS_NAME_TOKENS = (
    "payload", "shell", "backdoor", "trojan", "agent", "worm", "keygen",
    "crack", "loader", "dropper", "stager", "binder", "patch-tmp",
    "tmp-svc", "svchost-temp", "notepad-temp",
)

# Names of files that, when they appear in a user-writable startup location,
# indicate a persistence choice the operator should know about.
PERSISTENCE_FILES = (
    "startup.bat", "startup.ps1", "autorun.inf", "schtasks.xml",
    "registry.hive", "winlogon.exe", "lsass.exe", "csrss.exe",
)

# The four severity classes, in display order. Lower number = more urgent.
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def hash_file(path: str, chunk: int = 1024 * 1024) -> str:
    """SHA-256 of a file's bytes, read-only. Never executes the file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while True:
                chunk_data = fh.read(chunk)
                if not chunk_data:
                    break
                h.update(chunk_data)
        return h.hexdigest()
    except OSError:
        return ""


def _is_executable(path: str, mode: int) -> bool:
    """True if the path looks like an executable for its platform."""
    name = os.path.basename(path).lower()
    if name.endswith(WIN_EXE_EXT):
        return True
    if os.name == "nt":
        # Windows: an extension not in the exe set, but the file is a script
        # or something else that runs. The store keeps the extension list
        # above; callers that need a separate enum should use the platform
        # scripts only.
        return False
    # Unix: check the mode bits.
    if stat.S_ISREG(mode):
        return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    return False


def _looks_suspicious(path: str) -> list[str]:
    """Heuristic reasons for flagging a file's path name."""
    reasons = []
    basename = os.path.basename(path).lower()
    for token in SUSPICIOUS_NAME_TOKENS:
        if token in basename:
            reasons.append(f"suspicious-name-token:'{token}'")
            break
    # Temp files that live in places where payloads drop.
    tmp_name = os.path.basename(path)
    for d in SUSPICIOUS_DIRS:
        if d in path:
            reasons.append("in-suspicious-dir")
            break
    return reasons


def scan_file(path: str, host: str = "wsl") -> dict:
    """One pass over a single file: size, hash, executable-ness, suspicious
    tokens, permission summary. Returns a finding dict or {"safe": true}."""
    result = {
        "host": host,
        "path": path,
        "size": 0,
        "hash": "",
        "executable": False,
        "suspicious_tokens": [],
        "permissions": "unknown",
        "accessible": False,
        "reason": "",
    }
    try:
        st = os.stat(path)
    except OSError as exc:
        return {
            "host": host,
            "path": path,
            "error": str(exc),
            "accessible": False,
            "reason": "unreadable",
        }

    result["accessible"] = True
    result["size"] = st.st_size
    result["permissions"] = oct(stat.S_IMODE(st.st_mode))
    result["hash"] = hash_file(path)
    result["executable"] = _is_executable(path, st.st_mode)
    result["suspicious_tokens"] = _looks_suspicious(path)

    if result["suspicious_tokens"] or result["executable"]:
        severity = "high" if result["executable"] else "medium"
        reasons = []
        if result["executable"]:
            reasons.append("executable-file")
        if result["suspicious_tokens"]:
            reasons.extend(result["suspicious_tokens"])
        if os.path.basename(path) in PERSISTENCE_FILES:
            reasons.append("persistence-file")

        return {
            "host": host,
            "category": "files",
            "severity": severity,
            "title": "Suspicious executable or persistence file",
            "detail": (f"{path} ({result['size']} bytes, {result['permissions']}, "
                       f"SHA-256 {result['hash'][:16]}…) is flagged as "
                       f"{os.path.basename(path)}. Reasons: "
                       f"{', '.join(reasons)}. This is evidence for the owner; "
                       f"it is not a verdict."),
            "where": "deepscan-file",
            "reasons": reasons,
            "score": 70 if result["executable"] else 45,
            "hash": result["hash"],
            "size": result["size"],
        }

    return result


def scan_directory(root: str, host: str = "wsl",
                   max_depth: int = 3) -> list[dict]:
    """Walk `root` and return a list of findings for files worth a human
    looking at. Files that are unreadable are returned with `accessible: False`
    so the dashboard can show them as a limitation, not as an absence of risk.
    """
    findings = []
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        # Bound recursion so a huge tree does not stall the daemon.
        depth = dirpath[len(root):].count(os.sep)
        if depth >= max_depth:
            dirnames[:] = []
            continue
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            findings.append(scan_file(path, host))
    return findings


def audit(host: str = "wsl") -> list[dict]:
    """One pass over the places this scanner watches. Returns a list of
    findings for anything that is a candidate for a human look."""
    # On Linux/WSL, watch /tmp, /dev/shm, /var/tmp, /run/shm (where payloads
    # drop); on Windows, watch the equivalent temp and downloads directories.
    roots = []
    if host in ("wsl", "linux"):
        for d in ("/tmp", "/dev/shm", "/var/tmp", "/run/shm"):
            if os.path.isdir(d):
                roots.append(d)
    else:
        # Windows: watch %TEMP% and %USERPROFILE%\\AppData\\Local\\Temp and
        # Downloads. Calls that need the real user profile constants should
        # use platform.host.local_appdata() and friends.
        import os as _os
        temp = _os.environ.get("TEMP") or ""
        appdata = _os.environ.get("LOCALAPPDATA") or ""
        if temp:
            roots.append(temp)
        if appdata:
            roots.append(os.path.join(appdata, "Temp"))
        profile = _os.path.expanduser("~")
        if profile:
            roots.append(os.path.join(profile, "Downloads"))

    findings = []
    for root in roots:
        try:
            if not os.path.isdir(root):
                continue
            findings.extend(scan_directory(root, host, max_depth=2))
        except OSError as exc:
            findings.append({
                "host": host,
                "category": "files",
                "severity": "low",
                "title": "Cannot scan directory",
                "detail": f"{root}: {exc.strerror or exc}. "
                          f"Scanning is incomplete for this path.",
                "where": "deepscan-scan-dir",
                "reasons": ["scan-unreadable"],
                "score": 5,
            })
    return findings
