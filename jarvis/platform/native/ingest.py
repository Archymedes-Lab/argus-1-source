"""Drain the native sensor's spool into the event log, in order, exactly once.

The sensor (`windows-sensor/JarvisSensor.cs`) runs as a Windows service with
no dependency on WSL. It resumes each channel from the last record ID it
published, and publishes immutable, sequence-numbered batch files. This module is the
other half of that contract:

  * batches are taken strictly in sequence per (sensor, channel); a missing
    or out-of-order batch stops that channel with the cursor unchanged, so a
    hole in delivery is an error that stays visible, never a silent skip
  * a batch is committed to the event log together with its cursor (one
    fsync'd write), so a crash replays at most the batch in flight and the
    replay is recognised by sequence number and digest
  * a changed log generation (the channel was cleared or recreated) is
    accepted only when the sensor recorded the gap; records the log
    overwrote before the sensor read them arrive as a recorded gap too
  * only after the commit is the batch acknowledged back to the sensor, which
    may then reclaim spool space; nothing here deletes the sensor's files

Every record is normalized and kept, including records no detector reads.
"""

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from jarvis.core import event as event_mod
from jarvis.core.eventlog import EventLog

from . import normalize
from .store import MAX_BATCH_BYTES, BatchError, validate

SPOOL = Path(os.environ.get("JARVIS_SENSOR_SPOOL", "/mnt/c/ProgramData/Jarvis/Sensor"))

# Per run: 400 batches is up to 200,000 records, a few minutes of a busy
# backlog. The rest waits for the next run with the cursor where it stopped.
MAX_BATCHES = 400
# The sensor writes health every pass (2s) — minutes of silence means it
# stopped, or cannot write, whatever its last health file claimed.
HEALTH_STALE = 300


def read_health(spool=SPOOL):
    try:
        with open(Path(spool) / "health.json", "rb") as fh:
            health = json.loads(fh.read(1024 * 1024).decode("utf-8-sig"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        return {"status": "unreadable", "reason": str(exc)[:200]}
    health["age"] = _age(health.get("time"))
    return health


def _age(stamp):
    try:
        t = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return time.time() - t.timestamp()


def _batches(directory):
    """(sequence, path) for published batch files, oldest first."""
    out = []
    for p in directory.glob("*.json"):
        stem = p.stem
        if len(stem) == 20 and stem.isdigit():
            out.append((int(stem), p))
    return sorted(out)


def _write_ack(spool, dirname, batch, digest):
    acks = Path(spool) / "acks"
    try:
        acks.mkdir(exist_ok=True)
        path = acks / f"{dirname}.json"
        tmp = acks / f"{dirname}.{os.getpid()}.tmp"
        with open(tmp, "w") as fh:
            json.dump({"sensor_id": batch["sensor_id"], "channel": batch["channel"],
                       "through_sequence": batch["sequence"], "digest": digest,
                       "acknowledged_at": datetime.now(timezone.utc).isoformat()}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return None
    except OSError as exc:
        # The install grants this account write access to acks/ only. Without
        # it the sensor keeps everything and stops at its capacity, which is
        # the safe failure — so report it rather than treat it as fatal.
        return f"acknowledgement not written: {exc.strerror or exc}"


def _event(record, batch):
    try:
        return normalize.normalize(record, batch)
    except (normalize.NormalizeError, ValueError, KeyError) as exc:
        # A record that cannot be understood is still evidence that something
        # was logged. Keep it raw rather than block the channel on it forever.
        return event_mod.make(
            host=batch["host_id"], sensor=batch["sensor_id"], device=batch.get("device_id"),
            boot=batch.get("boot_id"), channel=batch["channel"],
            generation=batch["generation"], record=record["record_id"],
            source=normalize.SOURCES.get(batch["channel"], "windows-eventlog"),
            source_event=record["event_id"], time=record["time"], received=record["time"],
            batch=batch["sequence"], category="unknown",
            action=f"event_{record['event_id']}",
            attrs={"_normalize_error": str(exc)[:200]}, raw=record["xml"])


def ingest_channel(log, spool, directory, budget):
    """Ingest one channel directory. Returns its accounting dict."""
    result = {"directory": directory.name, "batches": 0, "events": 0, "gaps": [],
              "error": None, "channel": None, "last_sequence": None, "status": None,
              "ack_error": None, "backlog": 0, "duplicates": 0}
    last_batch = last_digest = None
    files = _batches(directory)
    for i, (seq, path) in enumerate(files):
        if result["batches"] >= budget:
            result["backlog"] = len(files) - i
            break
        try:
            with open(path, "rb") as fh:
                raw = fh.read(MAX_BATCH_BYTES + 1)
            if len(raw) > MAX_BATCH_BYTES:
                raise BatchError("batch exceeds size limit")
            batch = validate(json.loads(raw))
        except (OSError, ValueError) as exc:
            result["error"] = f"{path.name}: {exc}"[:300]
            break
        if batch["sequence"] != seq:
            result["error"] = f"{path.name}: file name and sequence disagree"
            break
        result["channel"] = batch["channel"]
        digest = hashlib.sha256(raw).hexdigest()
        cursor = log.cursor(batch["sensor_id"], batch["channel"])
        done = cursor["sequence"] if cursor else 0
        if seq < done:
            continue                       # committed earlier, awaiting reclamation
        if seq == done:
            if cursor.get("digest") != digest:
                result["error"] = (f"{path.name}: batch {seq} was replaced after it was "
                                   f"ingested — spool content changed under a committed cursor")
                break
            last_batch, last_digest = batch, digest
            continue
        gap = batch.get("gap")
        if seq != done + 1:
            if cursor is not None:
                result["error"] = (f"{path.name}: batch {done + 1} is missing; "
                                   f"cursor held at {done}")
                break
            # Nothing ingested for this channel yet and the spool starts later:
            # the earlier batches are gone. Say so in the history itself.
            gap = f"first ingested batch is {seq}; batches 1-{seq - 1} were never received"
        if cursor and batch["generation"] != cursor["generation"] and not batch.get("gap"):
            result["error"] = f"{path.name}: log generation changed without a gap record"
            break
        # Record IDs only grow within a log generation, so one at or below the
        # highest already committed is a redelivery, not a new observation.
        seen = (cursor.get("record_through") or 0) if cursor and \
            batch["generation"] == cursor["generation"] else 0
        fresh = [r for r in batch["events"] if r["record_id"] > seen]
        result["duplicates"] += len(batch["events"]) - len(fresh)
        events = [_event(r, batch) for r in fresh]
        event_times = [e.get("time") for e in events if e.get("time")]
        if gap:
            # A gap breaks the claim that the state reducer has seen every
            # transition. Later complete batches must not erase that boundary:
            # snapshot reconciliation is safe only for instances born after it.
            continuous_since = batch["created_at"]
        elif cursor and cursor.get("continuous_since"):
            continuous_since = cursor["continuous_since"]
        else:
            # The first native pass drains the retained Event Log from its
            # oldest record, so its oldest source time is the beginning of the
            # interval this stream can honestly claim to reconstruct.
            continuous_since = min(event_times) if event_times else batch["created_at"]
        log.append(events, {
            "sensor": batch["sensor_id"], "channel": batch["channel"], "sequence": seq,
            "generation": batch["generation"], "status": batch["status"], "gap": gap,
            "digest": digest, "created_at": batch["created_at"], "events": len(events),
            "host": batch["host_id"], "device": batch.get("device_id"),
            "boot": batch.get("boot_id"),
            "continuous_since": continuous_since,
            "record_through": max([seen] + [r["record_id"] for r in fresh]),
        })
        if gap:
            result["gaps"].append(gap)
        result["batches"] += 1
        result["events"] += len(events)
        last_batch, last_digest = batch, digest
    if last_batch is not None:
        result["last_sequence"] = last_batch["sequence"]
        result["status"] = last_batch["status"]
        result["ack_error"] = _write_ack(spool, directory.name, last_batch, last_digest)
    return result


def run(log=None, spool=SPOOL, max_batches=MAX_BATCHES):
    """One ingestion pass over every channel in the spool."""
    spool = Path(spool)
    report = {"spool": str(spool), "installed": spool.is_dir(), "health": None,
              "channels": [], "batches": 0, "events": 0, "sealed": None, "pruned": []}
    if not report["installed"]:
        return report
    report["health"] = read_health(spool)
    own = log is None
    log = log or EventLog(writer=True)
    try:
        dirs = sorted(p for p in spool.iterdir()
                      if p.is_dir() and len(p.name) == 16
                      and all(c in "0123456789abcdef" for c in p.name))
        for directory in dirs:
            share = max(1, (max_batches - report["batches"]) // max(1, len(dirs)))
            ch = ingest_channel(log, spool, directory, share)
            report["channels"].append(ch)
            report["batches"] += ch["batches"]
            report["events"] += ch["events"]
        header = log.seal()
        report["sealed"] = header["segment"] if header else None
        report["pruned"] = log.prune()
        report["log"] = log.stats()
    finally:
        if own:
            log.close()
    return report
