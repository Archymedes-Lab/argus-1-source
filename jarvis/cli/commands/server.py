"""Linux server commands (docs/architecture/ARGUS-SERVER.md).

    netflow     what the packet sensor saw, judged          (reads the daemon store)
    logins      successful SSH logins, new networks and keys
    sshwatch    sshd policy, authorised and host keys, live SSH tunnels
    opshealth   failed services, expiring TLS certificates, OOM kills, crashes
    bootchain   boot-chain persistence (GRUB, initramfs hooks, kernel images), kernel attack surface
    keyreaders  who reads the keyboard, raw HID or uinput; hidden staging files
    defender    Friday Defender reviews of your codebases: enable (asks), disable, status, run
    pkgverify   packaged-file integrity of intruder targets
    appcode     every codebase: vulnerable dependencies, risky code, secrets  [PATH ...]
    services    the declared services file, and what listens now
    review      one report of a window of stored observation, with its blind spots  [--days N]
    netstate    write the firewall snapshot      (argus-netstate unit; no store)
    netsensor   run the packet sensor            (argus-netsensor unit; no store)
"""

import json
import os
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


def cmd_bootchain(args, store):
    from jarvis.collectors.host import bootchain
    _print(bootchain.audit(store), args.json)


def cmd_keyreaders(args, store):
    from jarvis.collectors.host import keyreaders
    _print(keyreaders.audit(store), args.json)


def cmd_defender(args, store):
    """Owner consent for Friday Defender reviews (collectors/host/fridaydefender.py).

    Only this command, run by a person in a terminal, can grant consent or
    install Friday; the daemon can only read or withdraw it."""
    import shutil
    import subprocess
    import time

    from jarvis.collectors.host import fridaydefender as fd
    if args.action == "status":
        c = fd.load_consent()
        print(f"friday:  {fd.find_friday() or 'not installed'}")
        print(f"consent: {'granted ' + time.strftime('%Y-%m-%d', time.gmtime(c['granted_at'])) if c else 'none'}")
        if c:
            print(f"folders: {', '.join(c['roots']) if c.get('roots') else 'every codebase appcode found'}")
            print(f"budget:  {c.get('budget')} per review, one codebase at a time, each at most weekly")
            print(f"model:   agreed {c.get('provider')}/{c.get('model')}; Friday now {'/'.join(map(str, fd.friday_provider()))}")
        for f in fd.feed_findings(time.time()):
            print(f"feed:    {f['title']}")
        return
    if args.action == "disable":
        fd.revoke("disabled by the owner")
        print("Friday Defender reviews are off.")
        return
    if args.action == "run":
        _print(fd.audit(store), args.json)
        return
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        sys.exit("jarvis defender enable asks you to confirm, so it needs a terminal")
    friday = fd.find_friday()
    roots = [os.path.abspath(r) for r in (args.folders or [])]
    print("Friday Defender reviews\n")
    print("  What happens: once a week per codebase, while the machine is idle, Argus runs your Friday")
    print("  install in defender mode on one codebase. Friday reads the code and reports vulnerabilities;")
    print("  it is not allowed to change anything, and Argus checks the folder is untouched afterwards.")
    provider, model = fd.friday_provider()
    print(f"  Where your code goes: {provider or 'Friday default'} / {model or 'its default model'}"
          " (the provider set in Friday; changing it pauses reviews until you confirm again).")
    print(f"  Folders: {', '.join(roots) if roots else 'every codebase the appcode scan found'}")
    print(f"  Budget: {args.budget} per review. Findings are advice (at most medium), never acted on.")
    if not friday:
        print(f"\n  Friday is not installed. Enabling installs it with: {' '.join(fd.INSTALL)}")
    if input("\nAllow this? [y/N] ").strip().lower() not in ("y", "yes"):
        print("Nothing changed.")
        return
    if not friday:
        if not shutil.which("npm"):
            sys.exit("npm is not installed, so Friday cannot be installed here; install Node.js first")
        if subprocess.run(fd.INSTALL, check=False).returncode or not fd.find_friday():
            sys.exit("Friday did not install; consent not recorded")
    provider, model = fd.friday_provider()
    fd.write_consent({"v": 1, "granted_at": time.time(), "granted_by": "owner (interactive terminal)",
                      "roots": roots or None, "budget": args.budget, "provider": provider, "model": model,
                      "revoked": False})
    print("Enabled. `jarvis defender status` shows the state; `jarvis defender disable` turns it off.")


def cmd_pkgverify(args, store):
    from jarvis.collectors.persistence import pkgverify
    _print(pkgverify.audit(), args.json)


def cmd_appcode(args, store):
    from jarvis.collectors import appcode
    if args.paths:
        missing = [p for p in args.paths if not os.path.isdir(p)]
        if missing:
            sys.exit(f"not a folder: {', '.join(missing)}")
        findings = appcode.audit(store, roots=[os.path.abspath(p) for p in args.paths],
                                 web_roots=[], extra_roots=[], exclude=[], write_inventory=False)
    else:
        findings = appcode.audit(store)
    _print(findings, args.json)


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


def cmd_review(args, store):
    """Read-only report over the daemon's stored observation (jarvis/response/review.py)."""
    from jarvis.core import statedir
    from jarvis.core.store import DEFAULT_DB
    from jarvis.response import review
    refusal = statedir.cli_refusal(args.db, DEFAULT_DB, sys.argv[1:])
    if refusal:
        print(refusal, file=sys.stderr)
        return 2
    try:
        report = review.build(args.db, days=args.days)
    except review.ReviewError as exc:
        print(f"no review: {exc}", file=sys.stderr)
        return 2
    text = (json.dumps(report, indent=2) + "\n") if args.json else review.render(report)
    if not args.out:
        sys.stdout.write(text)
        return 0
    try:
        review.write_private(args.out, text)
    except FileExistsError:
        print(f"not written: {args.out} already exists (choose a new name)", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"not written: {exc.strerror or type(exc).__name__}", file=sys.stderr)
        return 2
    print(f"review written to {args.out} (readable by this account only)")
    return 0


def add_parser(sub):
    for name, fn, text in (("netflow", cmd_netflow, "incoming packets the sensor saw, judged"),
                           ("logins", cmd_logins, "successful SSH logins: new networks, new keys, guesses that worked"),
                           ("sshwatch", cmd_sshwatch,
                            "SSH server policy, every authorised key, host keys and live tunnels"),
                           ("opshealth", cmd_opshealth,
                            "failed services, expiring TLS certificates, OOM kills, crashes"),
                           ("bootchain", cmd_bootchain,
                            "boot-chain persistence and kernel attack surface"),
                           ("keyreaders", cmd_keyreaders,
                            "who reads the keyboard, raw HID or uinput; hidden staging files"),
                           ("pkgverify", cmd_pkgverify, "changed files in the packages intruders replace")):
        p = sub.add_parser(name, help=text)
        p.add_argument("--json", action="store_true")
        p.set_defaults(fn=fn)
    p = sub.add_parser("appcode", help="every codebase on this server: vulnerable or malicious "
                       "dependencies, risky code, credentials, writable code, web-root leaks")
    p.add_argument("paths", nargs="*", help="scan only these folders (default: the whole server)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_appcode)
    p = sub.add_parser("defender", help="Friday Defender reviews of your codebases (needs your consent)")
    p.add_argument("action", choices=("enable", "disable", "status", "run"))
    p.add_argument("folders", nargs="*", help="enable: only these folders (default: every codebase found)")
    p.add_argument("--budget", default="0.50", help="enable: spending cap per review")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_defender)
    p = sub.add_parser("services", help="declared services and what listens now")
    p.add_argument("--suggest", action="store_true",
                   help="print a services.conf starting point from current listeners")
    p.set_defaults(fn=cmd_services, no_store=True)
    p = sub.add_parser("review", help="observed server review: one report of the last days of "
                       "stored observation, with what it could not see (read-only)")
    p.add_argument("--days", type=int, default=7, help="window in days, 1 to 31 (default 7)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--out", help="write the report to this new file, owner-only")
    p.set_defaults(fn=cmd_review, no_store=True)
    p = sub.add_parser("netstate", help="write the firewall snapshot (run by argus-netstate)")
    p.set_defaults(fn=cmd_netstate, no_store=True)
    p = sub.add_parser("netsensor", help="run the packet sensor (run by argus-netsensor)")
    p.set_defaults(fn=cmd_netsensor, no_store=True)
