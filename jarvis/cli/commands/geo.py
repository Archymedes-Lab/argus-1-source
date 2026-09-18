"""`jarvis geo` — device location, geofencing, and the GeoSecurity view.

    jarvis geo status                 location, confidence, zones, anomalies
    jarvis geo locate                 take one native fix now (needs consent)
    jarvis geo zone add HOME LAT LON [--radius M]
    jarvis geo zone list
    jarvis geo zone rm NAME

Trusted zones are user-asserted ground truth. Raw coordinates are never kept as
history; JARVIS never infers a position from your IP.
"""

import json

from jarvis.collectors.host import geo as geo_collector
from jarvis.service import geosecurity


def cmd_geo(args, store):
    action = args.action
    if action == "zone":
        if args.zone_action == "add":
            if args.name is None or args.lat is None or args.lon is None:
                print("usage: jarvis geo zone add NAME LAT LON [--radius M]")
                return 1
            zones = geosecurity.add_zone(store, args.name, args.lat, args.lon,
                                         args.radius or 200)
            print(f"trusted zone '{args.name}' set ({len(zones)} total)")
            return 0
        if args.zone_action == "rm":
            geosecurity.remove_zone(store, args.name)
            print(f"removed zone '{args.name}'")
            return 0
        zones = geosecurity.get_zones(store)
        if args.json:
            print(json.dumps(zones, indent=2))
        elif not zones:
            print("no trusted zones set — add one with: jarvis geo zone add HOME LAT LON")
        else:
            for z in zones:
                print(f"  {z['name']:12} {z['lat']:.5f}, {z['lon']:.5f}  r={z['radius_m']}m")
        return 0

    if action == "locate":
        fix = geo_collector.locate()
        print(json.dumps(fix, indent=2) if args.json else
              f"{fix.get('status')}: " + (f"{fix.get('lat'):.5f}, {fix.get('lon'):.5f} "
              f"(~{int(fix.get('accuracy_m') or 0)} m via {fix.get('source')})"
              if fix.get("status") == "ok" else fix.get("reason", "")))
        return 0 if fix.get("status") == "ok" else 1

    # status
    payload = geosecurity.state(store)
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
        return 0
    loc = payload["location"]
    conf = payload["confidence"]
    print(f"location: {loc.get('status')}"
          + (f" — {loc.get('zone')} (~{int(loc.get('accuracy_m') or 0)} m)"
             if loc.get("status") == "ok" else f" — {loc.get('reason', '')}"))
    print(f"confidence: {int(conf['score'] * 100)}%  "
          + ", ".join(f"{s['name']} {s['weight']}" for s in conf["signals"]))
    print(f"trusted zones: {len(payload['zones'])}  "
          + ", ".join(z["name"] for z in payload["zones"]))
    for d in payload["devices"]:
        print(f"  device {d['name']}: {d['trust']}"
              + (f", in {d['zone']}" if d.get("zone") else ""))
    for a in payload["anomalies"]:
        print(f"  [{a['severity']}] {a['kind']}: {a['detail']}")
    print(f"imagery: {payload['imagery']['provider']} "
          f"({payload['imagery']['cadence']}). Open the globe at http://localhost:8787/geo")
    return 0


def add_parser(sub):
    p = sub.add_parser("geo", help="device location, geofencing and the GeoSecurity globe")
    p.add_argument("action", nargs="?", default="status", choices=["status", "locate", "zone"])
    p.add_argument("zone_action", nargs="?", choices=["add", "list", "rm"], default="list")
    p.add_argument("name", nargs="?", help="zone name (e.g. HOME)")
    p.add_argument("lat", nargs="?", type=float, help="zone latitude")
    p.add_argument("lon", nargs="?", type=float, help="zone longitude")
    p.add_argument("--radius", type=int, help="zone radius in metres (default 200)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_geo)
    return p
