"""Staging, starting and stopping the Windows input helper, and the
paths and pids that describe it."""

import os
import subprocess
from jarvis.platform import windows as collect_windows
from jarvis.platform.windows import ps_json
from jarvis.core.util import now
from .common import HOOK_PS1


_PATHS_CACHE = None


def _paths():
    """Where the helper writes, in both Windows and WSL spelling.

    `$env:LOCALAPPDATA` is fixed for the life of the machine, so the resolved
    answer is cached: the short-interval watchdog calls this every pass and a
    powershell.exe round trip each time would defeat the point of a local-only
    health check. A run that only reaches the fallback is not cached, so a
    transient interop failure does not pin us to C:\\Windows\\Temp.
    """
    global _PATHS_CACHE
    if _PATHS_CACHE:
        return _PATHS_CACHE
    out = ps_json(
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{t=$env:LOCALAPPDATA})))", timeout=60)
    base = (out or {}).get("t")
    resolved = bool(base)
    base = base or r"C:\Windows\Temp"
    p = base.replace("\\", "/")
    wsl = "/mnt/" + p[0].lower() + p[2:] if len(p) > 2 and p[1] == ":" else "/tmp"
    wsl_dir = os.path.join(wsl, "Jarvis")
    try:
        os.makedirs(wsl_dir, exist_ok=True)
    except OSError:
        pass
    pair = (base + r"\Jarvis\input.jsonl", os.path.join(wsl_dir, "input.jsonl"))
    if resolved:
        _PATHS_CACHE = pair
    return pair


def _stage_helper():
    """Copy the hook script somewhere powershell.exe can actually reach."""
    win_out, wsl_out = _paths()
    wsl_dir = os.path.dirname(wsl_out)
    dest = os.path.join(wsl_dir, "inputhook.ps1")
    try:
        with open(HOOK_PS1, encoding="utf-8", errors="replace") as src, \
                open(dest, "w", encoding="utf-8-sig") as dst:
            dst.write(src.read())
    except OSError as exc:
        return None, None, f"could not stage the hook helper: {exc}"
    return win_out.rsplit("\\", 1)[0] + r"\inputhook.ps1", win_out, ""


def _pid_path():
    _win, wsl_out = _paths()
    return os.path.splitext(wsl_out)[0] + ".pid"


def running():
    """PIDs of the helper on the Windows side, if it is alive.

    Reads a pid file the helper writes rather than searching command lines.
    Searching was subtly wrong: the query's own command line contains the
    script name, so the querying shell matched itself, `running()` was always
    true, and `start()` short-circuited on "already running" without ever
    launching anything.
    """
    try:
        with open(_pid_path(), errors="replace") as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        return []
    d = ps_json(
        "$ok = 0; try { $p = Get-Process -Id %d -ErrorAction Stop; "
        "if ($p.ProcessName -eq 'powershell') { $ok = 1 } } catch { };"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{ok=$ok})))" % pid, timeout=90)
    return [pid] if (d or {}).get("ok") else []


def _lock_path():
    _win, wsl_out = _paths()
    return os.path.splitext(wsl_out)[0] + ".starting"


def start():
    """Launch the hook helper, hidden and detached. Returns "" on success.

    Guarded by a short-lived lock file. `running()` reads the pid file, which
    the helper does not write until its hook is installed a few seconds in, so
    two supervise cycles racing through that window would each launch a helper
    — which is exactly the duplicate-process condition the watchdog then flags.
    """
    if running():
        return "already running"
    try:
        age = now() - os.path.getmtime(_lock_path())
        if age < 45:
            return "a start is already in progress"
    except OSError:
        pass
    if not collect_windows.available():
        return "the Windows interop bridge is not available"
    script_win, win_out, err = _stage_helper()
    if err:
        return err
    try:
        with open(_lock_path(), "w") as fh:
            fh.write(str(now()))
    except OSError:
        pass
    cmd = ("Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "
           "'-NoProfile','-ExecutionPolicy','Bypass','-File','"
           + script_win + "','-OutFile','" + win_out + "'")
    try:
        subprocess.run([collect_windows._PS, "-NoProfile", "-NonInteractive",
                        "-Command", cmd], capture_output=True, timeout=90, cwd="/")
    except (OSError, subprocess.SubprocessError) as exc:
        return f"could not start the helper: {exc}"
    return ""


def ensure():
    """Best-effort "make sure it is up" for callers without a Store handle."""
    pids = running()
    if pids:
        return pids
    start()
    return running()


def stop():
    pids = running()
    if not pids:
        return "not running"
    ps_json("Stop-Process -Id " + ",".join(str(p) for p in pids)
             + " -Force; [Convert]::ToBase64String([Text.Encoding]::UTF8"
               ".GetBytes((ConvertTo-Json @{ok=1})))", timeout=90)
    for p in (_pid_path(), _alive_path()):
        try:
            os.remove(p)
        except OSError:
            pass
    return ""  # note: under the daemon, the watchdog will start it again


def _stop_all():
    """Kill every hook helper, not just the one in the pid file.

    A race in `start()` (now locked) could once leave two helpers writing to
    the same file and double-counting. Reconciliation is: stop them all, clear
    the state files, and let the caller start exactly one.
    """
    ps_json(
        "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | "
        "Where-Object { $_.CommandLine -like '*inputhook.ps1*' -and "
        "$_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id "
        "$_.ProcessId -Force -EA SilentlyContinue };"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{ok=1})))", timeout=90)
    for p in (_pid_path(), _alive_path(), _lock_path()):
        try:
            os.remove(p)
        except OSError:
            pass


def _staged_matches_source():
    """True if the copy powershell.exe will read is identical (BOM aside) to
    the in-repo helper — a staged file rewritten under us aborts the restart."""
    _win, wsl_out = _paths()
    staged = os.path.join(os.path.dirname(wsl_out), "inputhook.ps1")
    try:
        with open(HOOK_PS1, "rb") as a, open(staged, "rb") as b:
            return a.read().decode("utf-8-sig") == b.read().decode("utf-8-sig")
    except (OSError, UnicodeError):
        return False


def _alive_path():
    _win, wsl_out = _paths()
    return os.path.splitext(wsl_out)[0] + ".alive"


def _alive_mtime():
    try:
        return os.path.getmtime(_alive_path())
    except OSError:
        return None


def _pidfile_pid():
    try:
        return int(open(_pid_path(), errors="replace").read().strip())
    except (OSError, ValueError):
        return None
