"""Draining the helper's output into the store."""

import json
import os

from jarvis.core.util import now

from .common import _M_DUPES, _M_OVERSIZE, _M_SESSION, READ_CAP
from .helper import _paths

_BEAT_COLS = ("real_keys", "injected_keys", "real_clicks", "injected_clicks",
              "real_moves", "injected_moves", "injected_keyups",
              "injected_move_bursts", "real_key_gaps", "real_key_sub20",
              "real_key_sub8", "cad_run_max", "lat_avg_ms", "lat_max_ms",
              "lat_over50", "lat_samples")

_BEAT_SQL = ("INSERT OR REPLACE INTO input_beats (ts," + ",".join(_BEAT_COLS)
             + ") VALUES (" + ",".join("?" * (len(_BEAT_COLS) + 1)) + ")")

_WINDOW_COLS = ("real_keys", "injected_keys", "real_key_gaps",
                "real_key_sub20", "real_key_sub8", "cad_run_max",
                "equals_keys", "slash_keys", "period_keys", "digit_keys")

_WINDOW_SQL = ("INSERT OR REPLACE INTO input_typing_windows (ts,"
               + ",".join(_WINDOW_COLS) + ") VALUES ("
               + ",".join("?" * (len(_WINDOW_COLS) + 1)) + ")")


def _clean(value):
    """JSON text safe for SQLite.

    A VK_PACKET emoji arrives as two events, each carrying half of a surrogate
    pair. json.loads keeps the lone half, and SQLite's UTF-8 encoder rejects it,
    so a lone surrogate is spelled out as U+XXXX instead of failing the drain.
    """
    if isinstance(value, str):
        return "".join(f"U+{ord(c):04X}" if 0xD800 <= ord(c) <= 0xDFFF else c
                       for c in value)
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    return value


def ingest(store):
    """Fold new helper output into the database, then truncate the file.

    The read is capped: a helper writing without bound is a fault, and past the
    cap that fact is recorded rather than loaded into memory. Heartbeats from
    more than one PID in a drain flag a duplicate helper.
    """
    _win_out, wsl_out = _paths()
    if not os.path.exists(wsl_out):
        return 0
    try:
        size = os.path.getsize(wsl_out)
        with open(wsl_out, "r+", encoding="utf-8", errors="replace") as fh:
            body = fh.read(READ_CAP)
            fh.seek(0)
            fh.truncate()
    except OSError:
        return 0
    if size > READ_CAP:
        store.set_meta(_M_OVERSIZE, now())

    beats, windows, events, beat_pids = [], [], [], set()
    bursts = []
    session = None
    controls = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("kind") == "heartbeat":
            c = rec.get("counters") or {}
            ts = int(rec.get("ts") or now())
            beats.append((ts,)
                         + tuple(int(c.get(k) or 0) for k in _BEAT_COLS))
            window = rec.get("window") or {}
            if window:
                windows.append((ts,) + tuple(
                    int(window.get(k) or 0) for k in _WINDOW_COLS))
            if rec.get("pid"):
                beat_pids.add(int(rec["pid"]))
            if "session" in rec:
                session = f"{int(rec['session'])}:{int(rec.get('desktop', -1))}"
        elif rec.get("kind") in ("control-key", "control-state"):
            # Control activations are kept in full, with their own timestamp:
            # they carry no text, and the whole point is being able to say
            # which control moved, when, and whether a key explains it.
            kind = str(rec.get("kind"))
            if kind == "control-state":
                detail = "%s -> %s%s" % (
                    rec.get("from"), rec.get("to"),
                    "  muted" if rec.get("muted") else "")
                keyed = int(rec.get("keyed", -1))
                gap = int(rec.get("key_gap_ms", -1))
            else:
                detail = str(rec.get("class") or "")[:40]
                keyed, gap = -1, -1
            controls.append((
                int(rec.get("ts") or now()), kind[:16],
                str(rec.get("control") or rec.get("class") or "")[:32],
                detail[:120], int(rec.get("injected") or 0),
                int(rec.get("lower_il") or 0), keyed, gap,
                str(rec.get("fg") or "")[:64]))
        elif rec.get("kind") == "inject-burst":
            rec = _clean(rec)
            bursts.append((str(rec.get("burst") or "")[:40],
                           int(rec.get("ts") or now()),
                           json.dumps(rec, ensure_ascii=False)[:200_000]))
        else:
            # Injected keys carry a full forensic record (vk, scan, character,
            # flags, extra info, ms time); older helper output and the real
            # punctuation/digit timestamps do not, and keep an empty one.
            forensic = "ms" in rec
            rec = _clean(rec)
            events.append(
                (int(rec.get("ts") or now()), str(rec.get("kind") or "key")[:16],
                 int(rec.get("lower_il") or 0), str(rec.get("class") or "")[:24],
                 str(rec.get("fg") or "")[:64], int(rec.get("ms") or 0),
                 str(rec.get("burst") or "")[:40],
                 json.dumps(rec, ensure_ascii=False)[:4000] if forensic else ""))
    if controls:
        store.db.executemany(
            "INSERT INTO control_events(ts,kind,control,detail,injected,"
            "lower_il,keyed,key_gap_ms,fg) VALUES(?,?,?,?,?,?,?,?,?)", controls)
    if beats:
        store.db.executemany(_BEAT_SQL, beats)
    if windows:
        store.db.executemany(_WINDOW_SQL, windows)
    if events:
        store.db.executemany(
            "INSERT INTO input_events(ts,kind,lower_il,class,fg,ms,burst,record) "
            "VALUES(?,?,?,?,?,?,?,?)", events)
    if bursts:
        store.db.executemany(
            "INSERT OR REPLACE INTO input_bursts(burst,ts,record) VALUES(?,?,?)",
            bursts)
    if session is not None:
        store.set_meta(_M_SESSION, session)
    # Heartbeats from more than one PID in a single drain means two helpers are
    # writing to the same file and double-counting. Cheap and local — no
    # interop — so the healthy path can check it too.
    if len(beat_pids) > 1:
        store.set_meta(_M_DUPES,
                       f"{now()}:{','.join(str(p) for p in sorted(beat_pids))}")
    if beats or windows or events or bursts:
        # Minute windows give a useful 90-day baseline at only ~130k rows.
        # Raw cumulative beats and injected-event detail need much less history;
        # bounding all three keeps the SQLite file small indefinitely.
        stamp = now()
        store.db.execute("DELETE FROM input_typing_windows WHERE ts < ?",
                         (stamp - 90 * 86400,))
        store.db.execute("DELETE FROM input_beats WHERE ts < ?",
                         (stamp - 7 * 86400,))
        store.db.execute("DELETE FROM input_events WHERE ts < ?",
                         (stamp - 30 * 86400,))
        store.db.execute("DELETE FROM input_bursts WHERE ts < ?",
                         (stamp - 30 * 86400,))
        store.commit()
    return len(events)
