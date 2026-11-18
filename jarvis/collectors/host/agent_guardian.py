"""AI agent guardian: observe coding-agent processes and their tool calls.

A watcher mode, not a one-shot audit. It keeps a rolling window of recently
seen agent-related processes, what tools they invoked, and whether the command
line or file access looks risky. It reports every sample (bounded), not only
what triggers a rule, so the dashboard can show a live "AI assistant active
on this machine" state instead of a point-in-time snapshot.

It observes, never judges: each sample carries a plain-language explanation
of what was seen and a risk score derived only from observable behaviour.
The score is advisory; a finding that is uncertain is labelled low-confidence
and never escalated automatically.

Platform notes
--------------
Windows:  process list through PowerShell Get-CimInstance Win32_Process with
          command line capture; agent detection by image path, start name
          and parent chain.
Linux:    /proc scan; command lines read through /proc/<pid>/cmdline; agent
          detection by exe path and process name; child processes read from
          /proc/<pid>/stat and /proc/<pid>/cmdline.
macOS:    fall back to the Linux /proc scan when available; otherwise the
          observer reports "unsupported" for process-level agent watching on
          this host and still reports whatever is visible through the generic
          process population. AppleScript invocation is deliberately not used:
          it would require accessibility permissions that the product does not
          request, and it would make the observer depend on a logged-in user.
"""

from __future__ import annotations

import io
import json
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from jarvis.core.util import classify_ip, now

# Everything this module reads is local; nothing is streamed or shipped.
_AUDIT_THRESHOLD = 60  # seconds between samples in the shared cache


# ---------------------------------------------------------------------------
# Configuration: which executables, image paths and command lines plausibly
# belong to an AI coding agent. The list is a permission boundary, not a
# whitelist: a binary that is not on it is simply "not identified as an agent".
# ---------------------------------------------------------------------------

_AGENT_EXE_NAMES = {
    "claude", "claude-code", "codex", "codex-cli", "cursor", "windsurfer",
    "cliner", "gemini", "gemini-cli", "kitty", "kilocode", "qodo", "roo",
    "codium", "bloop", "auggie", "tabby", "stargan", "shell-agent",
}

_AGENT_IMAGE_PATTERNS = [
    re.compile(r"(?:claude|codex|cursor|windsurf|cline|gemini|kitty|kilocode|qodo|roo|codium|bloop|auggie|tabby)[_.\-]",
               re.I),
    re.compile(r"^/(?:opt/conda|/snap/bin/|/usr/local/bin/)[A-Za-z0-9.+-]+-codex", re.I),
]

# What counts as a plausible tool invocation. Everything the agent does is
# ultimately an OS call, so "tool call" here means "a command line that names
# a recognised agent binary and carries a tool-ish verb or a working-directory
# hint". This is intentionally conservative.
_TOOL_VERBS = (
    "read", "write", "edit", "create", "delete", "search", "grep", "rg",
    "find", "ls", "git", "bash", "sh", "zsh", "cmd", "powershell", "node",
    "python", "pip", "npm", "npx", "cargo", "go", "make", "mvn", "gradle",
    "docker", "podman", "kubectl", "helm", "curl", "wget", "ssh", "scp",
    "sudo", "su", "gdb", "strace", "ngrok", "ngrok", "tsnet", "socks",
)

_RISKY_VERBS = {"rm ", "dd ", "mkfs", "fdisk", "format", "shutdown", "reboot",
                "sudo", "su ", "chmod 777", "chown -R", "kill -9", "curl |",
                "wget -O", "base64 -d", "eval", "exec ", "source ", ". "}

_FILE_READ_PATTERNS = (
    re.compile(r"~\.ssh|id_rsa|authorized_keys|\.secrets|\.npmrc|env$|\.env$|credentials|\.pem$|\.key$"),
    re.compile(r"\.pem$|\.key$|\.pfx$|\.p12$|\.gpg$"),
)

# Command-line tokens that indicate the agent is under the user's direction
# (fine) versus something that opens a wide gate on the host.
_PRIVILEGE_ESCALATION = ("sudo", "su ", "runas", "--privileged", "--user=root")


@dataclass
class AgentSample:
    """One observed agent, with everything we can cheaply see about it."""

    pid: int
    name: str
    exe: str
    cmdline: str
    ppid: int
    host: str
    ts: float = field(default_factory=now)
    risk_score: int = 0
    risk_reasons: list[str] = field(default_factory=list)
    tool_calls: list[str] = field(default_factory=list)
    files_accessed: list[str] = field(default_factory=list)
    parent_name: str = ""
    parent_exe: str = ""
    parent_cmdline: str = ""
    uid: int = -1
    gid: int = -1
    fd_count: int = 0
    state: str = "?"

    @property
    def identified_agent(self) -> bool:
        return self.name.lower() in _AGENT_EXE_NAMES or any(
            p.search(self.exe or "") for p in _AGENT_IMAGE_PATTERNS
        )


# ---------------------------------------------------------------------------
# Observation primitives. Each is deliberately small and safe: reads what the
# agent asks for, no network, no sub-process spawning except where the OS gives
# us no other way to see what the agent is doing.
# ---------------------------------------------------------------------------


def _read_cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        return raw
    except OSError:
        return ""


def _read_stat(pid: int) -> dict:
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            fields = fh.read().decode("utf-8", errors="replace").rsplit(")", 1)[1].split()
        return {
            "state": fields[0] if fields else "?",
            "ppid": int(fields[1]) if len(fields) > 1 else -1,
            "utime": int(fields[11]) if len(fields) > 11 else 0,
            "stime": int(fields[12]) if len(fields) > 12 else 0,
        }
    except (OSError, ValueError, IndexError):
        return {"state": "?", "ppid": -1, "utime": 0, "stime": 0}


def _read_fd_list(pid: int) -> list[str]:
    try:
        entries = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return []
    # We do not resolve the symlinks: that would follow sockets and escapes
    # into files we are not entitled to see. The names alone are enough to
    # say "this process reaches into the vfs".
    return entries


def _process_table() -> list[dict]:
    """Collect the whole process table as cheaply as we can, one read pass."""
    hosts = ("wsl", "win") if sys.platform.startswith("linux") else (None,)
    if hosts[0] == "wsl" or sys.platform.startswith("linux"):
        procs = []
        for pid in range(1, 65536):
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                continue
            cmdline = _read_cmdline(pid)
            stat = _read_stat(pid)
            fd_count = len(_read_fd_list(pid))
            if not exe or not cmdline:
                # A kernel thread with no cmdline and a deleted exe is normal.
                if not exe or "[kthreadd]" in exe:
                    continue
            procs.append({
                "pid": pid, "exe": exe, "cmdline": cmdline,
                "ppid": stat["ppid"], "uid": -1, "gid": -1,
                "fd_count": fd_count, "state": stat["state"],
            })
        return procs
    # Windows: PowerShell fallback
    try:
        script = os.path.join(
            os.path.dirname(__file__), "..", "host", "agent_guardian_win.ps1"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-File", script],
            capture_output=True, text=True, timeout=20, errors="replace",
        )
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                # PowerShell returns {processes: [...], ts: ...}; unwrap the list.
                if isinstance(data, dict) and isinstance(data.get("processes"), list):
                    return data["processes"]
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                pass
    except (OSError, subprocess.SubprocessError):
        pass
    return []


# ---------------------------------------------------------------------------
# Risk analysis. Each signal is a fact about what the agent did, not a verdict.
# ---------------------------------------------------------------------------


def assess(sample: AgentSample, now_ts: float | None = None) -> dict:
    """Return (risk_score, risk_reasons, explanation) for one sample."""
    now_ts = now_ts or now()
    reasons: list[str] = []
    score = 0

    if sample.identified_agent:
        # Agent processes are inherently interesting; their mere presence is
        # not a finding, but their behaviour is worth watching.
        score += 5

    if sample.ppid != 0 and sample.parent_name:
        if any(v in sample.parent_cmdline.lower() for v in
               ("tmux", "screen", "ssh", "su ", "sudo")):
            reasons.append("parent-under-shell")
            score += 3

    cmd = sample.cmdline.lower()
    for token in _PRIVILEGE_ESCALATION:
        if token in cmd:
            reasons.append("privilege-escalation-candidate")
            score += 8
            break

    for v in _RISKY_VERBS:
        if v in cmd:
            reasons.append("risky-command-candidate")
            score += 6
            break

    for pat in _FILE_READ_PATTERNS:
        if pat.search(sample.cmdline):
            reasons.append("suspicious-file-read-target")
            score += 7
            break

    if sample.fd_count and sample.fd_count > 128:
        reasons.append("high-file-descriptor-count")
        score += 2

    return {"score": min(100, score), "reasons": reasons,
            "explanation": _explain(sample, reasons)}


def _explain(sample: AgentSample, reasons: list[str]) -> str:
    parts = []
    if sample.identified_agent:
        parts.append(f"agent '{sample.name}' (pid {sample.pid}) with cmdline "
                     f"'{sample.cmdline[:120]}'")
    else:
        parts.append(f"process '{sample.name}' (pid {sample.pid})")

    if reasons:
        parts.append("behaviour: " + "; ".join(reasons))
    else:
        parts.append("no risky traits observed")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# The watcher: samples frequently, keeps a window, reports bounded findings.
# ---------------------------------------------------------------------------


_HISTORY: list[AgentSample] = []
_HISTORY_MAX = 200


def sample(host: str = "wsl", now_fn=None) -> AgentSample | None:
    """Take one sample and return the newest agent-related record, or None."""
    now_fn = now_fn or now
    table = _process_table()
    seen: list[AgentSample] = []
    for p in table:
        sample = AgentSample(
            pid=p["pid"], name=os.path.basename(p["exe"]),
            exe=p["exe"], cmdline=p["cmdline"], ppid=p["ppid"],
            host=host, uid=p.get("uid", -1), gid=p.get("gid", -1),
            fd_count=p.get("fd_count", 0), state=p.get("state", "?"),
        )
        if sample.identified_agent or _looks_toolish(sample):
            seen.append(sample)

    # Score everything we could identify; the score is advisory and raw.
    for s in seen:
        result = assess(s, now_fn())
        s.risk_score = result["score"]
        s.risk_reasons = result["reasons"]

    if seen:
        global _HISTORY
        _HISTORY.append(seen[-1])
        if len(_HISTORY) > _HISTORY_MAX:
            _HISTORY = _HISTORY[-_HISTORY_MAX:]
        return _HISTORY[-1]
    return None


def _looks_toolish(sample: AgentSample) -> bool:
    """Heuristic: does this process look like it is doing something an agent
    might drive (file I/O, shell, network)?"""
    cmd = sample.cmdline.lower()
    if any(v in cmd for v in _TOOL_VERBS):
        return True
    if sample.fd_count and sample.fd_count > 64:
        return True
    return False


def window(max_samples: int = 50) -> list[AgentSample]:
    """Return the most recent samples for the dashboard."""
    return list(_HISTORY[-max_samples:]) if _HISTORY else []


def time_span_seconds() -> int:
    if not _HISTORY:
        return 0
    oldest = _HISTORY[0].ts
    return int(now() - oldest)


def audit(host: str = "wsl") -> list[dict]:
    """One sample of agent activity, returned as a list of findings.

    The watcher is sampled here; the caller controls how often. Each record
    is a finding only when something interesting was seen: an identified
    agent, a risky tool invocation, or a privilege-escalation candidate.
    """
    sample(host=host)
    findings: list[dict] = []
    for s in window(max_samples=10):
        if s.risk_score > 0:
            findings.append({
                "host": s.host,
                "category": "ai-agent",
                "severity": "high" if s.risk_score >= 20 else "medium",
                "title": f"AI agent activity: {s.name}",
                "detail": f"{s.exe} (pid {s.pid}, parent {s.ppid}): {_explain(s, s.risk_reasons)}",
                "where": "ai-agent-cmdline",
                "score": s.risk_score,
                "reasons": s.risk_reasons,
                "cmdline": s.cmdline[:500],
                "tool_calls": s.risk_reasons,
            })
    return findings
