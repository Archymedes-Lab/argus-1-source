"""The watchdog outside the daemon.

Everything else that reports an outage runs *inside* `sentry serve`. That
covers a collector going quiet, the Windows bridge dropping, the input hook
dying — but not the one failure that silences all of them at once: the daemon
itself being gone. A dead process cannot mail you about being dead.

So this module is deliberately small, has no state of its own beyond two meta
keys, and is meant to be run from a systemd timer that is independent of
sentry.service:

    sentry selfcheck            report only  (safe, unprivileged)
    sentry selfcheck --restart  also restart the unit if it is not running
    sentry selfcheck --quiet    exit status only, for the timer

Health is judged on evidence, not on systemd's opinion alone:

  * the unit is active, AND
  * the newest snapshot in the database is fresher than STALE_AFTER.

The second clause is the important one. `systemctl is-active` reports "active"
for a process that is running and doing nothing at all, which is exactly the
wedged-scheduler case. A snapshot timestamp only advances when a job actually
completed and wrote a result.

Mail goes out through the same Resend transport as everything else, with its
own re-send interval so a timer running every few minutes cannot flood an
inbox while the machine is genuinely broken.
"""

import json
import subprocess
import time

from . import alert
from .store import DEFAULT_DB, Store
from .util import iso, now

UNIT = "sentry.service"

# The scheduler runs jobs one at a time and the longest measured job is ~106s,
# so a gap of a couple of minutes is normal. Five is not.
STALE_AFTER = 300

# Do not re-mail the same unhealthy verdict more often than this. Short on
# purpose: an unmonitored machine should keep nagging.
RENOTIFY_AFTER = 900

# Never declare the daemon dead on one reading. A check can lose a race with a
# restart, a systemctl call can time out under load, sqlite can be locked mid
# write. Re-check this many times, spaced RECHECK_DELAY apart, and only call it
# down if every single attempt agrees.
ATTEMPTS = 4
RECHECK_DELAY = 6

# How many times to try bringing the unit back before giving up on this pass.
RESTART_ATTEMPTS = 3
RESTART_SETTLE = 8

_M_LAST_ALERT = "selfcheck_last_alert"
_M_LAST_STATE = "selfcheck_last_state"


def _run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)


def _systemctl(*args, user=False, privileged=False):
    """Run systemctl, escalating to a passwordless sudo only when required.

    Reads never need privilege. A restart of a *system* unit does, and this
    runs unprivileged from a user timer on purpose — a monitor should not need
    to be root to keep itself alive. install.sh drops a sudoers rule that
    permits exactly two verbs on exactly this unit and nothing else; without
    it the read path still works and the restart simply reports that it could
    not act, which is itself worth mailing about.
    """
    base = ["systemctl"] + (["--user"] if user else []) + list(args)
    rc, out, err = _run(base)
    if rc == 0 or user or not privileged:
        return rc, out, err
    blocked = ("access denied" in err.lower() or "authentication" in err.lower()
               or "interactive authentication required" in err.lower())
    if not blocked:
        return rc, out, err
    return _run(["sudo", "-n"] + base)


def unit_state():
    """(scope, ActiveState) for whichever manager owns the unit, or ("", "")."""
    for scope, user in (("system", False), ("user", True)):
        rc, out, _ = _systemctl("show", UNIT, "-p", "ActiveState",
                                "--value", user=user)
        if rc == 0 and out:
            return scope, out
    return "", ""


def uptime_s():
    """Seconds the unit has been active, or None if that cannot be read.

    Snapshots are legitimately stale for the first few seconds after a start,
    so "how long has it been up" is the difference between a daemon that is
    booting and one that is wedged.
    """
    scope, _ = unit_state()
    if not scope:
        return None
    rc, out, _ = _systemctl("show", UNIT, "-p", "ActiveEnterTimestampMonotonic",
                            "--value", user=(scope == "user"))
    try:
        started_us = int(out)
        if started_us <= 0:
            return None
        with open("/proc/uptime") as fh:
            boot_s = float(fh.read().split()[0])
        return max(0.0, boot_s - started_us / 1_000_000)
    except (ValueError, OSError, IndexError):
        return None


def newest_snapshot(db_path=DEFAULT_DB):
    """(kind, ts) of the most recently written snapshot, or ("", 0)."""
    store = Store(db_path)
    try:
        row = store.db.execute(
            "SELECT kind, ts FROM snapshots ORDER BY ts DESC LIMIT 1").fetchone()
        return (row["kind"], int(row["ts"])) if row else ("", 0)
    except Exception:
        return "", 0
    finally:
        store.close()


def check(db_path=DEFAULT_DB):
    """Return a verdict dict. Never raises."""
    scope, state = unit_state()
    kind, ts = newest_snapshot(db_path)
    age = now() - ts if ts else None

    up = uptime_s() if state == "active" else None
    starting = up is not None and up < STALE_AFTER

    problems = []
    if not scope:
        problems.append(f"{UNIT} is not installed under either systemd manager")
    elif state != "active":
        problems.append(f"{UNIT} is {state or 'unknown'} ({scope} manager)")

    # Only judge snapshot freshness once the daemon has been up long enough to
    # have produced one. Otherwise every restart would immediately re-page.
    if not starting:
        if ts == 0:
            problems.append("the database holds no collector snapshots at all")
        elif age is not None and age > STALE_AFTER:
            problems.append(
                f"the newest snapshot is {age}s old ({kind}, written "
                f"{iso(ts)}) — the scheduler has written nothing for over "
                f"{STALE_AFTER}s, so it is wedged or dead even though the "
                f"process is up")

    return {
        "healthy": not problems,
        "scope": scope,
        "active_state": state,
        "uptime": int(up) if up is not None else None,
        "starting": starting,
        "newest_kind": kind,
        "newest_ts": ts,
        "age": age,
        "problems": problems,
    }


def confirm_unhealthy(db_path=DEFAULT_DB, attempts=ATTEMPTS):
    """Check repeatedly; return the verdict only once every attempt agrees.

    A single reading is not evidence. The daemon may be mid-restart, systemctl
    may have timed out behind a loaded bus, the database may have been locked
    for the instant we looked. Any single healthy reading wins immediately —
    we are trying to avoid crying wolf, not to build a case for the prosecution.
    """
    verdict = check(db_path)
    for _ in range(max(1, attempts) - 1):
        if verdict["healthy"]:
            return verdict
        time.sleep(RECHECK_DELAY)
        verdict = check(db_path)
    return verdict


def restart(attempts=RESTART_ATTEMPTS, db_path=DEFAULT_DB):
    """Bring the unit back, trying more than once. Returns "" on success.

    `systemctl restart` can fail transiently — the bus is busy, a previous stop
    is still settling, the start limit was hit. Each of those is worth another
    go, and a `reset-failed` in between clears the one case systemd will
    otherwise refuse to retry on its own.
    """
    scope, _ = unit_state()
    if not scope:
        return f"{UNIT} is not installed under either systemd manager"
    user = (scope == "user")
    last = ""
    for i in range(max(1, attempts)):
        if i:
            # Clears start-limit-hit, which makes systemd refuse to start a
            # unit that has restarted too often — exactly the state that must
            # never leave this machine unmonitored.
            _systemctl("reset-failed", UNIT, user=user, privileged=True)
            time.sleep(RESTART_SETTLE)
        rc, _, err = _systemctl("restart", UNIT, user=user, privileged=True)
        if rc == 0:
            time.sleep(RESTART_SETTLE)
            if check(db_path)["active_state"] == "active":
                return ""
            last = "restart reported success but the unit is not active"
        else:
            last = err or f"systemctl restart returned {rc}"
    return f"{last} (after {attempts} attempts)"


def _notify(db_path, verdict, restart_err=None, restarted=False):
    """Mail the verdict, at most once per RENOTIFY_AFTER while it persists.

    A recovery is always mailed once, so "sentry is back" is never inferred
    from silence — the same rule the in-daemon alerts follow.
    """
    conf = alert.load_conf()
    if not alert.enabled(conf):
        return "alerts are not configured"

    store = Store(db_path)
    try:
        last_state = store.get_meta(_M_LAST_STATE, "") or ""
        last_alert = int(store.get_meta(_M_LAST_ALERT, 0) or 0)
        state = "healthy" if verdict["healthy"] else "down"

        if verdict["healthy"]:
            if last_state != "down":
                store.set_meta(_M_LAST_STATE, state)
                return ""
            body = (f"sentry is running again.\n\n"
                    f"newest snapshot: {verdict['newest_kind']} "
                    f"{iso(verdict['newest_ts'])} ({verdict['age']}s ago)\n"
                    f"unit: {UNIT} {verdict['active_state']} "
                    f"({verdict['scope']} manager)\n")
            err = alert.send_email(conf, "[sentry] the monitor is back up", body)
            if not err:
                alert._record_send(store)
                store.set_meta(_M_LAST_STATE, state)
                store.set_meta(_M_LAST_ALERT, 0)
            return err

        if last_state == "down" and now() - last_alert < RENOTIFY_AFTER:
            return ""      # already paged recently; do not flood

        lines = ["sentry is NOT monitoring this machine.", ""]
        lines += [f"  - {p}" for p in verdict["problems"]]
        lines += ["", f"unit:  {UNIT} {verdict['active_state'] or '?'} "
                      f"({verdict['scope'] or 'not installed'})"]
        if verdict["newest_ts"]:
            lines.append(f"last snapshot: {verdict['newest_kind']} at "
                         f"{iso(verdict['newest_ts'])}")
        if restarted:
            lines += ["", "A restart was attempted automatically."
                          if not restart_err
                          else f"Automatic restart FAILED: {restart_err}"]
        lines += ["", "This message was sent by `sentry selfcheck`, which runs "
                      "outside the daemon precisely so a dead daemon still "
                      "reaches you."]
        err = alert.send_email(
            conf, "[sentry] the monitor is DOWN — nothing is being watched",
            "\n".join(lines) + "\n")
        if not err:
            alert._record_send(store)
            store.set_meta(_M_LAST_STATE, state)
            store.set_meta(_M_LAST_ALERT, now())
        return err
    except Exception as exc:
        return str(exc)
    finally:
        store.close()


def run(db_path=DEFAULT_DB, do_restart=False, notify=True, attempts=ATTEMPTS):
    """One full pass: confirm, optionally restart, optionally mail.

    Order matters. We confirm before acting so a restart is never triggered by
    a single bad reading, and we mail *after* the restart attempt so the alert
    can say whether recovery worked — an alert that says "down, and I could not
    bring it back" needs a human; one that says "down, restarted, healthy" does
    not.
    """
    verdict = confirm_unhealthy(db_path, attempts)
    restarted, restart_err = False, ""

    if not verdict["healthy"] and do_restart:
        restarted = True
        restart_err = restart(db_path=db_path)
        after = check(db_path)
        verdict["after_restart"] = after
        if after["healthy"]:
            # It is back. Say so rather than paging as if it were still down.
            verdict = dict(after, recovered_by_restart=True)

    mail_err = ""
    if notify:
        mail_err = _notify(db_path, verdict, restart_err, restarted) or ""

    verdict["restarted"] = restarted
    verdict["restart_error"] = restart_err
    verdict["mail_error"] = mail_err
    return verdict
