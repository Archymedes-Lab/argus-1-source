"""Read the temporal event log: what happened, in order, and what caused what."""

import json

from jarvis.core.eventlog import DEFAULT_ROOT, EventLog, LogError
from jarvis.platform.native import ingest


def _line(ev):
    p, t = ev.get("process") or {}, ev.get("target") or {}
    who = (p.get("image") or "").replace("/", "\\").rsplit("\\", 1)[-1] or "-"
    what = (t.get("query") or t.get("path") or t.get("image") or t.get("key")
            or t.get("name") or (f"{t.get('ip')}:{t.get('port')}" if t.get("ip") else "")
            or (p.get("cmdline") or "")[:100])
    return (f"#{ev['seq']:<8} {(ev.get('time') or '')[:23]:23}  "
            f"{ev['category']}.{ev['action']:<16} {who:<24} {what}")


def _open(root):
    try:
        return EventLog(root)
    except (LogError, OSError) as exc:
        print(f"event log unavailable: {exc}")
        return None


def cmd_timeline(args, store):
    action = args.action
    if action == "ingest":
        try:
            log = EventLog(args.log or DEFAULT_ROOT, writer=True)
        except LogError as exc:
            print(f"{exc} (the daemon's native job ingests every minute)")
            return 1
        with log:
            result = ingest.run(log=log, spool=args.spool or ingest.SPOOL)
        print(json.dumps(result, indent=2, default=str) if args.json else
              f"{result['events']} events from {result['batches']} batches"
              + ("" if result["installed"] else " — no sensor spool at " + result["spool"]))
        return 1 if any(c["error"] for c in result["channels"]) else 0
    log = _open(args.log or DEFAULT_ROOT)
    if log is None:
        return 1
    with log:
        if action == "status":
            stats = log.stats()
            stats["health"] = ingest.read_health(args.spool or ingest.SPOOL)
            if args.json:
                print(json.dumps(stats, indent=2, default=str))
                return 0
            print(f"event log {stats['root']}: events 1–{stats['last_seq']}, "
                  f"{stats['segments']} sealed segments ({stats['sealed_bytes'] // 1048576} MiB), "
                  f"{stats['unsealed_events']} unsealed, {stats['pruned']} pruned")
            for c in stats["cursors"]:
                print(f"  {c['channel']}: batch {c['sequence']} ({c['status']}), "
                      f"through event #{c['through_seq']}" + (f" — gap: {c['gap']}" if c.get("gap") else ""))
            h = stats["health"]
            print("  sensor: " + ("not installed" if h is None else
                                  f"health {int(h['age'] or 0)}s old, boot {h.get('boot_id')}"))
            if log.db is not None:
                print("  most frequent:")
                for r in log.counts()[:12]:
                    print(f"    {r['n']:>8}  {r['category']}.{r['action']} (source {r['source_event']})")
            return 0
        if action == "verify":
            anchor = json.loads(args.anchor) if args.anchor else None
            result = log.verify(anchor=anchor)
            print(json.dumps(result, indent=2))
            if result["ok"]:
                print("Chain intact. Keep this head somewhere this machine cannot write "
                      "(a phone note, another device) and pass it back with --anchor.")
            return 0 if result["ok"] else 2
        if action == "search":
            kind, value = next(((k, getattr(args, k)) for k in ("sha256", "dns", "ip", "image")
                                if getattr(args, k)), (None, None))
            if not kind:
                print("give one of --sha256, --dns, --ip, --image")
                return 1
            row = log.sighting(kind, value)
            if not row:
                print(f"never recorded: {kind} {value}")
                return 0
            print(f"{kind} {value}: {row['count']}× between {row['first_time']} and {row['last_time']}")
            shown = 0
            needle = row["value"]
            for ev in log.iter_events(after=row["first_seq"] - 1, until=row["last_seq"]):
                text = json.dumps([ev.get("process"), ev.get("target")]).lower()
                if needle.lower() in text:
                    print("  " + _line(ev))
                    shown += 1
                    if shown >= args.limit:
                        print(f"  … limited to {args.limit}")
                        break
            return 0
        if action == "tree":
            ancestry = log.ancestry(args.guid)
            for depth, p in enumerate(reversed(ancestry)):
                name = p.get("image") or ("(not recorded)" if p.get("unrecorded") else "?")
                print("  " * depth + f"{name}  pid {p.get('pid')}  {p.get('started') or ''}  {p['guid']}")
            for child in log.children(args.guid, args.limit):
                print("  " * len(ancestry) + f"└ {child.get('image')}  pid {child.get('pid')}  "
                      f"{child.get('started') or ''}  {child['guid']}")
            return 0
        if action == "show":
            for ev in log.iter_events(after=args.seq - 1, until=args.seq):
                if not args.raw:
                    ev = {k: v for k, v in ev.items() if k != "raw"}
                print(json.dumps(ev, indent=2))
                return 0
            print("no such event (or its segment was pruned)")
            return 1
        if action == "tail":
            start = max(0, log.last_seq - args.limit * (20 if args.category else 1))
            rows = [ev for ev in log.iter_events(after=start)
                    if not args.category or ev["category"] == args.category]
            for ev in rows[-args.limit:]:
                print(json.dumps(ev) if args.json else _line(ev))
            return 0
    return 1


def add_parser(sub):
    p = sub.add_parser("timeline", help="the recorded event history: search, lineage, integrity")
    p.add_argument("action", choices=["status", "ingest", "verify", "search", "tree", "show", "tail"])
    p.add_argument("guid", nargs="?", help="tree: a process GUID")
    p.add_argument("--sha256"); p.add_argument("--dns"); p.add_argument("--ip")
    p.add_argument("--image", help="full image path")
    p.add_argument("--seq", type=int, help="show: event sequence number")
    p.add_argument("--category", help="tail: only this category")
    p.add_argument("--limit", type=int, default=40)
    p.add_argument("--raw", action="store_true", help="show: include the source record")
    p.add_argument("--anchor", help="verify: a previously exported head, as JSON")
    p.add_argument("--spool", help="sensor spool directory (default: ProgramData)")
    p.add_argument("--log", help="event log directory, e.g. a preserved copy (default: ~/.jarvis/eventlog)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_timeline)
