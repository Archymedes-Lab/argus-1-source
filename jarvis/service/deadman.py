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
        detail = ("%s exists but could not be parsed; its liveness cannot be "
                  "confirmed" % path)
        try:
            from jarvis.platform import mounts as _mounts
            if _mounts.under_windows_drive(path) \
                    and _mounts.windows_drive() == _mounts.STALE:
                detail = ("%s cannot be read because %s; the monitor itself "
                          "may be fine — the drive is the patient"
                          % (path, _mounts.stale_detail()))
        except Exception:
            pass
        return [_finding(
            "medium", "the independent Windows monitor's state is unreadable",
            detail, path)]

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


# ── the instant reviver ─────────────────────────────────────────────────────
#
# `revive-jarvis.ps1` is the Windows loop that re-runs a stale protection
# source or restarts a dead daemon within seconds. Like the monitor above, its
# own silence hides itself, so this reads its state file the same way.

REVIVER_STATE = ("/mnt/c/Users/%s/AppData/Local/Jarvis/Reviver/state.json"
                 % os.environ.get("WSL_USER", "chris"))

# It writes every five seconds; a minute of silence is a dead loop. The task's
# five-minute trigger restarts it, so this only fires when that failed too.
REVIVER_STALE_AFTER = 60


def audit_reviver(path=REVIVER_STATE, now=None):
    """Findings about the instant reviver's own liveness and posture."""
    now = int(time.time() if now is None else now)
    if not os.path.exists(path):
        return [_finding(
            "medium", "the instant reviver is not installed",
            "nothing revives JARVIS within seconds; an outage waits for the "
            "five-minute wake task. Install with `powershell.exe -File "
            "revive-jarvis.ps1 -Install`.", path)]
    state = read_state(path)
    if state is None:
        detail = "%s could not be parsed" % path
        try:
            from jarvis.platform import mounts as _mounts
            if _mounts.under_windows_drive(path) \
                    and _mounts.windows_drive() == _mounts.STALE:
                detail = ("%s cannot be read because %s"
                          % (path, _mounts.stale_detail()))
        except Exception:
            pass
        return [_finding("medium", "the instant reviver's state is unreadable",
                         detail, path)]
    # max(0, …): the Windows and WSL clocks drift a few seconds apart.
    age = max(0, now - int(state.get("checkedAt") or 0))
    if age > REVIVER_STALE_AFTER:
        return [_finding(
            "high", "the instant reviver has stopped",
            "its last check was %ds ago. Its task restarts it within five "
            "minutes; if this persists, run `Start-ScheduledTask -TaskName "
            "'jarvis reviver'` in PowerShell." % age, path)]
    if state.get("gaveUp"):
        return [_finding(
            "high", "the instant reviver has used its restart budget",
            "it restarted JARVIS repeatedly without recovery and has stopped "
            "restarting. Last action: %s." % (state.get("lastAction") or "none"), path)]
    if state.get("paused"):
        return [_finding(
            "medium", "the instant reviver is paused for maintenance",
            "it checks but repairs nothing while the pause file exists "
            "(%s)." % os.path.join(os.path.dirname(path), "pause"), path)]
    detail = "checking every few seconds; last check %ds ago" % age
    if state.get("lastResult"):
        detail += "; last recovery: %s" % state["lastResult"]
    return [_finding("ok", "the instant reviver is watching JARVIS", detail, path)]


# ── the elevated broker ─────────────────────────────────────────────────────

def audit_broker(now=None):
    """Is the elevated collector broker installed, current and running?"""
    from jarvis.platform import broker
    now = int(time.time() if now is None else now)
    where = broker.ROOT
    if not broker.installed():
        return [_finding(
            "medium", "the elevated collector broker is not installed",
            "posture, memscan, the firewall traffic log and Sysmon policy "
            "inspection run unelevated or remain unreadable and "
            "report what administrator would see as unreadable. Install with "
            "`jarvis broker install` (one UAC prompt).", where)]
    drift = broker.drifted()
    if drift:
        return [_finding(
            "medium", "the elevated broker's scripts differ from this checkout",
            "staged copies of %s are not the reviewed versions, so their results "
            "are not used. Re-run `jarvis broker install` to restage them."
            % ", ".join(drift), where)]
    st = broker.status() or {}
    age = now - int(st.get("finished") or 0)
    if age > broker.MAX_AGE:
        return [_finding(
            "high", "the elevated broker has stopped running",
            "its last completed run was %dm ago; collectors have fallen back to "
            "unelevated results" % (age // 60), where)]
    failed = {k: v.get("error") for k, v in (st.get("jobs") or {}).items() if not v.get("ok")}
    if failed:
        return [_finding("medium", "an elevated broker job is failing",
                         "; ".join(f"{k}: {v}" for k, v in failed.items()), where)]
    if not st.get("admin"):
        return [_finding("high", "the elevated broker is running without administrator",
                         "its task is not using an elevated token, so its results "
                         "are no better than the unelevated collectors'", where)]
    return [_finding("ok", "the elevated broker is feeding privileged read-only evidence",
                     "last run %dm ago, all jobs succeeded" % (age // 60), where)]
