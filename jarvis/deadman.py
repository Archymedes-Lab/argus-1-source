"""Does the independent Windows monitor still check on us?

`deadman-jarvis.ps1` runs as a Windows scheduled task and is the only layer
that can tell you JARVIS is gone when WSL itself is down — nothing inside a
stopped distro can send that mail. That makes its own silence the most
dangerous silence available: a task stuck in `Running` refuses every later
trigger under MultipleInstances=IgnoreNew, and Task Scheduler still shows the
task as present and Ready afterwards.

So the supervision runs both ways. The Windows task verifies that JARVIS's
scheduler is progressing; this checks that the Windows task is still writing
its state file. Each side is the only thing positioned to notice the other's
failure.
"""

import json
import os
import time

# Written by the monitor on every run, via write-then-rename.
STATE = ("/mnt/c/Users/%s/AppData/Local/Jarvis/Deadman/state.json"
         % os.environ.get("WSL_USER", "chris"))

# The task repeats every minute. Three missed runs is a real stall rather than
# one slow probe on a loaded machine.
STALE_AFTER = 300


def _finding(severity, title, detail, where=STATE):
    return {"category": "daemon", "severity": severity, "title": title,
            "detail": detail, "where": where, "host": "win"}


def read_state(path=STATE):
    try:
        # errors="replace": a truncated or partially written state file must
        # degrade to "unreadable", never take the collector down with it.
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def audit(path=STATE, now=None):
    """Findings about the Windows-side monitor's own liveness."""
    now = int(time.time() if now is None else now)
    if not os.path.exists(path):
        return [_finding(
            "medium", "the independent Windows monitor has never run",
            "no state file at %s. Install it with "
            "`powershell.exe -File deadman-jarvis.ps1 -Install` — without it, "
            "nothing reports an outage while WSL is stopped." % path, path)]

    state = read_state(path)
    if state is None:
        return [_finding(
            "medium", "the independent Windows monitor's state is unreadable",
            "%s exists but could not be parsed; its liveness cannot be "
            "confirmed" % path, path)]

    checked = int(state.get("checkedAt") or 0)
    age = now - checked
    if not checked:
        return [_finding(
            "medium", "the independent Windows monitor has not recorded a check",
            "its state file carries no check timestamp", path)]

    if age > STALE_AFTER:
        return [_finding(
            "high", "the independent Windows monitor has stopped checking",
            "its last check was %dm ago (stale after %dm). A scheduled task "
            "stuck in 'Running' refuses every later trigger and still reports "
            "Ready, so this is the failure that hides itself. Clear it with "
            "`Stop-ScheduledTask -TaskName 'JARVIS independent health monitor'`."
            % (age // 60, STALE_AFTER // 60), path)]

    out = []
    if not state.get("healthy", True):
        out.append(_finding(
            "medium", "the independent Windows monitor reports JARVIS unhealthy",
            "%s (as of %dm ago)" % (state.get("reason") or "no reason recorded",
                                    age // 60), path))
    for field, label in (("mailError", "email"), ("toastError", "toast")):
        if state.get(field):
            out.append(_finding(
                "medium", "the Windows monitor's %s path is failing" % label,
                "%s. Outage notification would not reach you by %s."
                % (state[field], label), path))
    if not out:
        out.append(_finding(
            "ok", "the independent Windows monitor is checking on JARVIS",
            "last check %ds ago; it verified %s"
            % (age, state.get("reason") or "JARVIS health"), path))
    return out
