"""Collect Windows processes and TCP connections through WSL interop.

Everything happens in one powershell.exe invocation because crossing the interop
boundary costs ~1s; doing it per-process would make scanning unusable. The
payload comes back base64-encoded so console codepage quirks can't corrupt it.
"""

import base64
import json
import os
import re
import shutil
import stat
import subprocess

from jarvis.core import collection
from jarvis.core.paths import load_win_script
from jarvis.core.util import fingerprint

HOST = "win"

PS_SCRIPT = load_win_script("process_snapshot.ps1")

# Hosts that run someone else's code; the argument is the real identity.
SCRIPT_HOSTS = re.compile(
    r"^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|python[\d.]*|node|"
    r"ruby|perl|php|java|javaw|wsl|bash)\.exe$",
    re.I,
)
SCRIPT_EXT = re.compile(r"\.(ps1|psm1|bat|cmd|vbs|js|jse|wsf|py|rb|pl|php|jar|hta)\b", re.I)

_PS = None


def ensure_interop() -> bool:
    """Make sure WSL_INTEROP points at a live socket.

    Launching a Windows binary from WSL goes through a per-session Unix socket
    named in $WSL_INTEROP. A systemd *user service* inherits no such variable —
    and a value inherited from a login shell goes stale the moment that session
    ends. Either way the daemon silently loses every Windows collector while
    looking perfectly healthy, so we resolve a working socket ourselves instead
    of trusting the environment.
    """
    current = os.environ.get("WSL_INTEROP")
    if current and os.path.exists(current):
        return True

    try:
        candidates = [
            os.path.join("/run/WSL", n)
            for n in os.listdir("/run/WSL")
            if n.endswith("_interop")
        ]
    except OSError:
        return False

    # Newest socket first: it belongs to the most recent session, which is the
    # one most likely to still be attached to a running Windows side.
    for path in sorted(candidates, key=lambda p: os.stat(p).st_mtime, reverse=True):
        try:
            if stat.S_ISSOCK(os.stat(path).st_mode):
                os.environ["WSL_INTEROP"] = path
                return True
        except OSError:
            continue
    return False


# Where powershell.exe lives when PATH cannot help. A login shell gets the
# Windows directories appended to PATH by WSL; a systemd service does not, so
# shutil.which() finds nothing there and every Windows collector goes quiet.
FALLBACK_PS = [
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe",
    "/mnt/c/Program Files/PowerShell/7/pwsh.exe",
]


def find_powershell() -> str:
    found = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if found:
        return found
    for path in FALLBACK_PS:
        if os.path.exists(path):
            return path
    return ""


def available() -> bool:
    """True when the Windows side is reachable from here."""
    global _PS
    if not _PS:
        _PS = find_powershell()
    # A cached binary path and a surviving socket do not prove the Windows
    # filesystem survived a suspend. Recheck before declaring the bridge up.
    return bool(_PS) and os.path.isfile(_PS) and ensure_interop()


_SESSION_PROBE = ("\"$((Get-Process -Id $PID).SessionId):"
                  "$((Get-Process explorer -EA SilentlyContinue | Select-Object -First 1).SessionId)\"")


def interop_sockets():
    """Live interop sockets, newest first. Each reaches its own Windows session."""
    try:
        paths = [os.path.join("/run/WSL", n) for n in os.listdir("/run/WSL")
                 if n.endswith("_interop")]
        live = [p for p in paths
                if not os.path.islink(p) and stat.S_ISSOCK(os.stat(p).st_mode)]
        return sorted(live, key=os.path.getmtime, reverse=True)
    except OSError:
        return []


def _run_via(sock, script, timeout):
    try:
        return subprocess.run([_PS or find_powershell(), "-NoProfile", "-NonInteractive",
                               "-Command", script],
                              capture_output=True, text=True, errors="replace",
                              timeout=timeout, cwd="/", env={**os.environ, "WSL_INTEROP": sock})
    except (OSError, subprocess.SubprocessError):
        return None


def desktop_interop() -> str:
    """An interop socket whose Windows processes land on the user's desktop.

    Each socket belongs to the wsl.exe that created it, and a Windows process
    launched through it inherits that launcher's session. When WSL was started
    by a background task, its sockets reach session 0, which has no desktop or
    keyboard. Anything that has to see the user's input or windows — a
    low-level keyboard hook above all — is blind there while looking perfectly
    alive. So each socket is asked where it lands, and only one reaching the
    session Explorer runs in is returned. "" when none does (no WSL terminal is
    open on the desktop).
    """
    if not (_PS or find_powershell()):
        return ""
    for sock in interop_sockets():
        r = _run_via(sock, _SESSION_PROBE, 30)
        own, _, desktop = (r.stdout.strip() if r else "").partition(":")
        if own.isdigit() and own == desktop and own != "0":
            return sock
    return ""


def run_in_every_session(script, timeout=60):
    """Run an idempotent PowerShell command once through every interop socket.

    Windows refuses to terminate a process in another logon session: a stop
    issued from the desktop is denied for a session-0 helper and succeeds from
    session 0. Cleanup that must reach every session therefore runs from each.
    Returns how many runs completed.
    """
    if not (_PS or find_powershell()):
        return 0
    return sum(1 for sock in interop_sockets() if _run_via(sock, script, timeout))


def _split_args(cmd: str):
    """Tokenize a Windows command line, honoring double quotes."""
    return [t.strip('"') for t in re.findall(r'"[^"]*"|\S+', cmd or "")]


def _script_target(cmd: str, exe_base: str) -> str:
    if not SCRIPT_HOSTS.match(exe_base):
        return ""
    for arg in _split_args(cmd)[1:]:
        if arg.startswith(("-", "/")):
            continue
        if SCRIPT_EXT.search(arg):
            return arg
    return ""


def collect(timeout: int = 45):
    """Return a list of process records for the Windows side (empty if unreachable)."""
    if not available():
        collection.failed('windows-processes', 'interop unavailable')
        return []
    try:
        res = subprocess.run(
            [_PS, "-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT],
            capture_output=True,
            timeout=timeout,
            cwd="/",  # avoids the UNC-path warning when cwd is a Linux dir
        )
    except (subprocess.TimeoutExpired, OSError):
        collection.failed('windows-processes', 'query failed or timed out')
        return []

    blob = res.stdout.decode("ascii", "ignore").strip().replace("\r", "").replace("\n", "")
    if not blob:
        collection.failed('windows-processes', 'query returned no payload')
        return []
    try:
        data = json.loads(base64.b64decode(blob).decode("utf-8", "replace"))
    except Exception:
        collection.failed('windows-processes', 'invalid payload')
        return []

    if not isinstance(data, dict) or not data.get('procs'):
        collection.failed('windows-processes', 'no process observations')
        return []
    collection.succeeded('windows-processes')

    by_pid = {}
    for c in data.get("conns") or []:
        # Windows reports pid 0 for connections it declines to attribute; that
        # is not the System Idle Process actually talking to the internet.
        pid = c.get("pid")
        by_pid.setdefault(0 if pid in (0, None) else pid, []).append({
            "proto": c.get("proto", "tcp"),
            "local_ip": c.get("lip", ""),
            "local_port": c.get("lport", 0),
            "remote_ip": c.get("rip", ""),
            "remote_port": c.get("rport", 0),
            "state": c.get("state", ""),
        })

    procs = []
    for p in data.get("procs") or []:
        pid = p.get("pid")
        exe = p.get("exe") or ""
        name = p.get("name") or ""
        cmd = p.get("cmd") or name
        if pid == 0:
            name = "(unattributed)"
        exe_base = os.path.basename(exe.replace("\\", "/")) or name
        script = _script_target(cmd, exe_base)
        ident_exe = script if script else exe

        procs.append({
            "host": HOST,
            "pid": pid,
            "ppid": p.get("ppid", 0),
            "name": name,
            "exe": exe,
            "script": script,
            "cmdline": cmd,
            "user": "",  # per-process owner lookup is too slow to do on every scan
            "rss_bytes": int(p.get("rss") or 0),
            "cpu_seconds": float(p.get("cpu") or 0),
            "logical_cpus": int(data.get("logical_cpus") or 0),
            "conns": by_pid.get(pid, []),
            "fp": fingerprint(HOST, ident_exe or name, cmd, ""),
        })

    return procs


def ps_json(script, timeout=120):
    """Run a PowerShell script and decode its base64 JSON payload.

    Retries once after forcing interop re-resolution: the socket named in
    WSL_INTEROP can go stale between calls when the session that created it
    ends, and the only symptom is empty output.
    """
    if not available():
        collection.failed('windows', 'interop unavailable')
        return None

    for attempt in (1, 2):
        try:
            r = subprocess.run(
                [_PS, "-NoProfile", "-NonInteractive",
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
            if not ensure_interop():
                collection.failed('windows', 'interop retry unavailable')
                return None
    collection.failed('windows', 'PowerShell returned no payload')
    return None


def aslist(v):
    """PowerShell collapses single-element arrays; normalize back to a list."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]
