"""Windows-specific agent guardian: enumerates processes through PowerShell."""

import json
import os
import subprocess

from jarvis.platform import windows as collect_windows

# PowerShell can enumerate the whole process table in a second. That is the
# fastest reliable way to get command lines on Windows, where /proc does not
# exist. We capture the command line but we do not execute anything.


def collect():
    """Return a list of dicts: pid, exe, cmdline, ppid."""
    try:
        script = os.path.join(
            os.path.dirname(__file__), "agent_guardian_win.ps1"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-File", script],
            capture_output=True, text=True, timeout=20, errors="replace",
        )
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                return data.get("processes", [])
            except json.JSONDecodeError:
                pass
    except (OSError, subprocess.SubprocessError):
        pass
    return collect_windows.collect()
