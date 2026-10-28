"""Linux server commands (docs/architecture/ARGUS-SERVER.md).

    netflow     what the packet sensor saw, judged          (reads the daemon store)
    logins      successful SSH logins, new networks and keys
    sshwatch    sshd policy, authorised and host keys, live SSH tunnels
    opshealth   failed services, expiring TLS certificates, OOM kills, crashes
    pkgverify   packaged-file integrity of intruder targets
    services    the declared services file, and what listens now
    netstate    write the firewall snapshot      (argus-netstate unit; no store)
    netsensor   run the packet sensor            (argus-netsensor unit; no store)
"""

import json
import sys


def _print(findings, as_json):
    if as_json:
        print(json.dumps(findings, indent=2))
        return
    if not findings:
        print("nothing to report")
        return
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(findings, key=lambda f: (order.get(f["severity"], 9), f["title"])):
        print(f"  {f['severity']:<8} {f['title']}")
        if f.get("detail"):
            print(f"           {f['detail']}")


def cmd_netflow(args, store):
    from jarvis.collectors.network import netflow
    _print(netflow.audit(store), args.json)


def cmd_logins(args, store):
    from jarvis.collectors.identity import logins
    _print(logins.audit(store), args.json)


def cmd_sshwatch(args, store):
    from jarvis.collectors.identity import sshwatch
    _print(sshwatch.audit(store), args.json)


def cmd_opshealth(args, store):
    from jarvis.collectors.host import opshealth
    _print(opshealth.audit(store), args.json)


def cmd_pkgverify(args, store):
    from jarvis.collectors.persistence import pkgverify
    _print(pkgverify.audit(), args.json)


def cmd_services(args, store):
    from jarvis.collectors.network import exposure
    from jarvis.platform.linux import socket_table
    declared, path, problems = exposure.load_declared()
    listening = exposure.exposed_listeners(socket_table(fresh=True))
    if args.suggest:
        # A starting point for /etc/argus/services.conf, for the owner to edit.
        # Every line is commented out: declaring whatever listens now could
        # declare a backdoor that is already here. The owner uncomments.
        print("# Services this server is meant to expose: port/proto [source networks ...]")
        print("# e.g.  22/tcp   443/tcp   5432/tcp 10.0.0.0/8")
        print("# Below is what listens beyond loopback now. Uncomment only what this server")
        print("# exists to serve; until a line is uncommented nothing counts as declared.")
        for (port, proto), addrs in sorted(listening.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            print(f"# {port}/{proto}    # bound to {', '.join(addrs[:3])}")
        return
    print(f"declared: {path or 'no file (' + exposure.DECLARED_PATHS[0] + ')'}")
    for (port, proto), nets in sorted((declared or {}).items()):
        print(f"  {port}/{proto}  " + (", ".join(str(n) for n in nets) or "from anywhere"))
    for problem in problems:
        print(f"  unreadable {problem}")
    print("listening beyond loopback:")
    for (port, proto), addrs in sorted(listening.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        mark = "declared" if exposure.is_declared(declared, port, proto) else "NOT DECLARED"
        print(f"  {port}/{proto:<4} {mark:<13} {', '.join(addrs[:3])}")


def cmd_netstate(args, store):
    from jarvis.platform.netsensor import netstate
    sys.exit(netstate.main())


def cmd_netsensor(args, store):
    from jarvis.platform.netsensor import capture
    sys.exit(capture.main())


def add_parser(sub):
    for name, fn, text in (("netflow", cmd_netflow, "incoming packets the sensor saw, judged"),
                           ("logins", cmd_logins, "successful SSH logins: new networks, new keys, guesses that worked"),
                           ("sshwatch", cmd_sshwatch,
                            "SSH server policy, every authorised key, host keys and live tunnels"),
                           ("opshealth", cmd_opshealth,
                            "failed services, expiring TLS certificates, OOM kills, crashes"),
                           ("pkgverify", cmd_pkgverify, "changed files in the packages intruders replace")):
        p = sub.add_parser(name, help=text)
        p.add_argument("--json", action="store_true")
        p.set_defaults(fn=fn)
    p = sub.add_parser("services", help="declared services and what listens now")
    p.add_argument("--suggest", action="store_true",
                   help="print a services.conf starting point from current listeners")
    p.set_defaults(fn=cmd_services, no_store=True)
    p = sub.add_parser("netstate", help="write the firewall snapshot (run by argus-netstate)")
    p.set_defaults(fn=cmd_netstate, no_store=True)
    p = sub.add_parser("netsensor", help="run the packet sensor (run by argus-netsensor)")
    p.set_defaults(fn=cmd_netsensor, no_store=True)
