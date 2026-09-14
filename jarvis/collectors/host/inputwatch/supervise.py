"""Is the helper alive, unmodified and actually producing data?"""

import json
import os
from jarvis.platform import windows as collect_windows
from jarvis.platform.windows import ps_json
from jarvis.core.util import iso, now
from jarvis.core.finding import win_finding as _finding

from .common import HOOK_PS1, READ_CAP, _M_DUPES, _M_OVERSIZE, _mget_int, _sha256
from .helper import _alive_mtime, _alive_path, _paths, _pid_path, _pidfile_pid, _staged_matches_source, _stop_all, running, start, stop
from .ingest import ingest
from .analysis import _latency_findings, _typing_findings, sort_findings



MISS_LIMIT = 2         # watchdog passes with nothing moving before "down"

START_GRACE = 120      # a fresh helper's pulse may not have propagated yet

BACKOFF_BASE = 20

BACKOFF_CAP = 600

FLAP_WINDOW = 6 * 3600

FLAP_N = 4

GIVEUP_FAILS = 8

_M_FAILS = "input_hook_fails"          # consecutive failed supervise cycles

_M_LASTTRY = "input_hook_last_try"     # ts of the last (re)start attempt

_M_RESTARTS = "input_hook_restarts"    # json list of recent restart ts

_M_OKSINCE = "input_hook_ok_since"     # ts we last became healthy

_M_SRCSHA = "input_hook_src_sha256"    # content pin of the trusted helper

_M_PROBE = "input_hook_probe"          # json snapshot for change-based liveness


def _newest_beat(store):
    row = store.db.execute("SELECT MAX(ts) t FROM input_beats").fetchone()
    return int(row["t"]) if row and row["t"] else 0


def _restart_log(store):
    try:
        return [int(x) for x in json.loads(store.get_meta(_M_RESTARTS, "[]")
                                           or "[]")]
    except (ValueError, TypeError):
        return []


def liveness(store):
    """Is the helper alive — decided by *change*, not by any absolute clock.

    Every timestamp available from WSL (a heartbeat's embedded ts, a DrvFs
    file mtime) rides the Windows clock, so a skew there defeats any "is this
    recent?" test. What cannot be faked by a skew is motion: between two
    watchdog passes a live helper always advances its 10 s `.alive` pulse, its
    output file, or its newest heartbeat. Nothing advancing across N passes is
    death.

    Returns (state, misses) where state is "fresh", "stale" or "new" (first
    observation — no prior snapshot to compare against).
    """
    snap = {"alive": _alive_mtime(),
            "size": _jsonl_size(store),
            "beat": _newest_beat(store)}
    try:
        prev = json.loads(store.get_meta(_M_PROBE, "") or "{}")
    except ValueError:
        prev = {}
    if not prev:
        snap["misses"] = 0
        store.set_meta(_M_PROBE, json.dumps(snap))
        return "new", 0
    moved = (snap["alive"] != prev.get("alive")
             or (snap["size"] >= 0 and snap["size"] != prev.get("size"))
             or snap["beat"] != prev.get("beat"))
    misses = 0 if moved else int(prev.get("misses", 0)) + 1
    snap["misses"] = misses
    store.set_meta(_M_PROBE, json.dumps(snap))
    return ("fresh" if moved else "stale"), misses


def _verify_pin(store):
    """Surface a change to the trusted helper source.

    Not a verdict — a legitimate `git pull` and tampering look identical from
    here — but the code that gets launched changing without notice is worth
    seeing, and an unreadable source means we cannot restart from known-good.
    """
    cur = _sha256(HOOK_PS1)
    if not cur:
        return [_finding(
            "input", "high",
            "the input-hook helper script is missing or unreadable",
            f"{HOOK_PS1} could not be hashed — the monitor cannot be restarted "
            f"from a known-good copy", HOOK_PS1)]
    old = store.get_meta(_M_SRCSHA, "")
    if old != cur:
        store.set_meta(_M_SRCSHA, cur)
    if old and old != cur:
        return [_finding(
            "input", "medium",
            "the input-hook helper script changed on disk",
            f"sha256 {old[:12]} → {cur[:12]}. If you did not just update "
            f"JARVIS, treat an unannounced change to a security monitor as "
            f"tampering", HOOK_PS1)]
    return []


def _jsonl_size(store):
    try:
        _w, wsl_out = _paths()
        return os.path.getsize(wsl_out)
    except OSError:
        return -1


def _helper_count():
    """How many hook helpers are actually running. >1 is unexpected.

    Excludes this query's own shell — its command line contains the script
    name too, which is the trap the pid-file approach in `running()` was
    written to avoid.
    """
    d = ps_json(
        "$n = @(Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\""
        " | Where-Object { $_.CommandLine -like '*inputhook.ps1*' -and "
        "$_.ProcessId -ne $PID }).Count;"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{n=$n})))", timeout=60)
    try:
        return int((d or {}).get("n"))
    except (TypeError, ValueError):
        return -1


def _dupes(store):
    """(age_seconds, "pid,pid") if ingest saw >1 helper recently, else None."""
    v = store.get_meta(_M_DUPES, "")
    if not v or ":" not in v:
        return None
    ts, pids = v.split(":", 1)
    try:
        age = now() - int(ts)
    except ValueError:
        return None
    return (age, pids) if age < 180 else None


def _flap_finding(store):
    recent = [t for t in _restart_log(store) if now() - t < FLAP_WINDOW]
    if len(recent) < FLAP_N:
        return []
    hrs = max(1, (now() - min(recent)) // 3600)
    return [_finding(
        "input", "high",
        f"the injected-input monitor has restarted {len(recent)} times in {hrs}h",
        "a security monitor that keeps dying is itself the finding — something "
        "may be calling Stop-Process on it, or it is crashing on this host. "
        "Note what holds focus when it dies", "input_beats")]


def supervise(store, deep=False):
    """Keep the hook alive; make repeated failure loud. Returns (pids, findings).

    Healthy path is cheap: drain the helper's output, see a fresh heartbeat,
    return — no powershell.exe. Only a stale or absent heartbeat escalates to
    the interop-crossing probe and a backed-off restart.

    `deep` adds the one health check that does cross the interop boundary on a
    healthy host — the LowLevelHooksTimeout registry read — so the frequent
    watchdog can leave it to the slower full audit.
    """
    out = _verify_pin(store)
    ingest(store)
    if store.get_meta(_M_OVERSIZE):
        store.set_meta(_M_OVERSIZE, "")
        out.append(_finding(
            "input", "high",
            "the input hook's output file blew past its size cap",
            f"over {READ_CAP // (1024 * 1024)} MiB of helper output in one "
            f"interval — it is writing without bound, and the overflow was "
            f"dropped rather than loaded", "input.jsonl"))

    last_try = _mget_int(store, _M_LASTTRY)
    fails = _mget_int(store, _M_FAILS)

    # Two helpers writing the same file. Reconcile before anything else: stop
    # every hook, start exactly one.
    dup = _dupes(store)
    if dup:
        store.set_meta(_M_DUPES, "")
        _stop_all()
        store.set_meta(_M_LASTTRY, now())
        store.set_meta(_M_PROBE, "")
        err = start()
        store.set_meta(_M_FAILS, 0 if not err else fails + 1)
        out.append(_finding(
            "input", "high" if err else "medium",
            "duplicate input-hook helpers were running",
            f"heartbeats from pids {dup[1]} in one interval — they double-count "
            f"and corrupt the totals. Stopped all and started one"
            + (f"; restart failed: {err}" if err else ""), "inputwatch"))
        return [], sort_findings(out + _flap_finding(store))

    state, misses = liveness(store)

    # "new" means no prior snapshot to diff against. Normally that earns one
    # grace pass — but if nothing is even on disk (no pid file, no pulse file,
    # empty output) there is nothing to wait for, so treat it as down.
    present = (os.path.exists(_pid_path()) or os.path.exists(_alive_path())
               or _jsonl_size(store) > 0)
    if state == "new" and not present:
        state, misses = "stale", MISS_LIMIT

    if state in ("fresh", "new"):
        # Alive. Reset the failure counter and re-emit any flap finding.
        if fails:
            store.set_meta(_M_FAILS, 0)
        if not _mget_int(store, _M_OKSINCE):
            store.set_meta(_M_OKSINCE, now())
        out += _flap_finding(store)
        latest = store.db.execute(
            "SELECT * FROM input_beats ORDER BY ts DESC LIMIT 1").fetchone()
        out += _latency_findings(store, latest, probe_registry=deep)
        out += _typing_findings(store, latest)
        pid = _pidfile_pid()
        embedded = _newest_beat(store)
        seen = f", last heartbeat stamped {iso(embedded)}" if embedded else ""
        out.append(_finding(
            "input", "ok", "the injected-input monitor is healthy",
            f"pid {pid or '?'} — pulse, output file or heartbeat advanced since "
            f"the last check{seen}", "inputwatch"))
        return ([pid] if pid else []), sort_findings(out)

    if last_try and now() - last_try < START_GRACE:
        out.append(_finding(
            "input", "low", "the injected-input monitor is starting",
            f"launched {now() - last_try}s ago; waiting for its first pulse",
            "inputwatch"))
        return [], sort_findings(out)

    if misses < MISS_LIMIT:
        out.append(_finding(
            "input", "medium",
            "the injected-input monitor has gone quiet",
            f"nothing has advanced for {misses} watchdog pass(es) — pulse, "
            f"output file and heartbeat all frozen. One more and it is cycled",
            "inputwatch"))
        return [], sort_findings(out + _flap_finding(store))

    # Frozen for MISS_LIMIT passes. Confirm across the interop boundary.
    alive = bool(running())
    pid = _pidfile_pid()
    helpers = _helper_count()
    if helpers > 1:
        _stop_all()
        alive = False
        out.append(_finding(
            "input", "medium", f"{helpers} input-hook helpers were running",
            "more than one hook writing the same file — stopped all, starting "
            "one", "inputwatch"))
    elif alive:
        # Process up but everything frozen — the hook was removed or the loop
        # is wedged. Same remedy either way.
        out.append(_finding(
            "input", "high",
            "the input hook is running but has stopped watching",
            f"pid {pid} is alive, yet its pulse, output file and heartbeat have "
            f"all been frozen for {misses} passes — the low-level hook was "
            f"removed or the message loop is stuck. Cycling it", "inputwatch"))
        stop()
        alive = False

    if not collect_windows.available():
        out.append(_finding(
            "input", "medium",
            "the injected-input monitor is down and cannot be restarted",
            "the Windows interop bridge is unavailable — environmental, not "
            "necessarily tampering; will retry", "inputwatch"))
        return [], sort_findings(out)

    delay = min(BACKOFF_BASE * (2 ** fails), BACKOFF_CAP)
    if last_try and now() - last_try < delay:
        out.append(_finding(
            "input", "high" if fails >= FLAP_N else "medium",
            "the injected-input monitor is down",
            f"restart backed off — {fails} consecutive failures, next attempt "
            f"in {delay - (now() - last_try)}s", "inputwatch"))
        return [], sort_findings(out + _flap_finding(store))

    store.set_meta(_M_LASTTRY, now())
    store.set_meta(_M_PROBE, "")          # next liveness() starts a clean baseline
    err = start()
    if not err and not _staged_matches_source():
        stop()
        err = "the staged helper does not match its trusted source"

    if err:
        n = fails + 1
        store.set_meta(_M_FAILS, n)
        sev = ("critical" if n >= GIVEUP_FAILS else
               "high" if n >= FLAP_N else "medium")
        out.append(_finding(
            "input", sev, "could not restart the injected-input monitor",
            f"{err} — {n} consecutive failures", "inputwatch"))
        return [], sort_findings(out + _flap_finding(store))

    log = [t for t in _restart_log(store) if now() - t < 86400] + [now()]
    store.set_meta(_M_RESTARTS, json.dumps(log[-64:]))
    store.set_meta(_M_FAILS, 0)
    store.set_meta(_M_OKSINCE, 0)
    out.append(_finding(
        "input", "medium",
        "the injected-input monitor was down and has been restarted",
        "synthetic-input recording had stopped; a fresh hook is starting up",
        "inputwatch"))
    return [], sort_findings(out + _flap_finding(store))
