"""Replay retained Windows history through the real Sysmon detector.

Read-only: the event log is opened as a reader and the detector is given rows
directly, so no finding is stored and no cursor moves. Run it before a new
technique rule is counted, to see what it would have reported on this machine:

    nice -n 10 python3 -m scripts.dev.replay_techniques [last N events]
"""
import collections
import sys
import time

from jarvis.collectors.telemetry import sysmon
from jarvis.core.eventlog import EventLog

EVENTS = (1, 3, 13, 22)
CHUNK = 20000


def main(last=None):
    log = EventLog()
    after = max(0, log.last_seq - last) if last else 0
    hits, example, seen, chunk, started = collections.Counter(), {}, 0, [], time.time()

    def flush():
        for f in sysmon.audit(events=sysmon.rows_from_events(chunk)):
            if f.get("techniques"):
                key = (f["severity"], f["title"])
                hits[key] += 1
                example.setdefault(key, f["detail"][:170])
        chunk.clear()

    for ev in log.iter_events(after=after):
        if ev.get("source") != "sysmon" or int(ev.get("source_event") or 0) not in EVENTS:
            continue
        chunk.append(ev)
        seen += 1
        if len(chunk) >= CHUNK:
            flush()
    flush()
    print(f"{seen} events replayed in {time.time() - started:.0f}s")
    for key, n in hits.most_common():
        print(n, key, "|", example[key])
    return hits


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else None)
