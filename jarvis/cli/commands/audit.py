"""Subcommands that run a collector and report findings."""

import json

from ... import (asep, auditd, pixel, sniffing, webshell, backdoor, bruteforce, control, coverage, firewall, hidden, evasion, hunt, implant, intel, intrusion, inputwatch, memscan, monitor, netwatch, posture, secrets, spyware, startup, sysmon, sysmon_linux, toolchain)
from ...util import iso, short
from ..output import (color, _tty, _hosts, _print_finding, _report,
                      _simple_cmd)


def cmd_scan(args, store):
    if not store.get_meta("baseline_at"):
        print(color("No baseline yet — everything will look new. "
                    "Run `jarvis baseline` first.\n", "medium", _tty()))
    res = monitor.scan(store, hosts=_hosts(args), enrich=args.enrich)

    if args.json:
        print(json.dumps(res, default=str, indent=2))
        return

    print(monitor.summarize(res))
    findings = res["findings"]
    if args.severity:
        keep = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.severity]
        findings = [f for f in findings if monitor.SEV_ORDER[f["severity"]] <= keep]

    if not findings:
        print(color("  no drift, no suspicious traits.", "ok", _tty()))
    for f in findings[: args.limit]:
        _print_finding(f)

    if res["new_public_peers"]:
        print(f"\n{color('New external peers', 'bold', _tty())} "
              f"({len(res['new_public_peers'])} first-time public IPs):")
        for p in res["new_public_peers"][: args.limit]:
            proc = p["proc"]
            rd = f"  {p.get('rdns')}" if p.get("rdns") else ""
            print(f"  {p['ip']}:{p['port']}  ←  {proc['name']} "
                  f"[{proc['host']}/{proc['pid']}]{rd}")

    if len(findings) > args.limit:
        print(f"\n  … {len(findings) - args.limit} more (use --limit)")


def cmd_investigate(args, store):
    """Everything at once, for when you think something is actually wrong."""
    t = _tty()
    hosts = _hosts(args)
    sections = [
        ("HIDDEN PROCESSES", lambda: hidden.audit(hosts=hosts, deep=args.deep)[0]),
        ("STARTUP", startup.audit),
        ("SPYWARE & CAPABILITY USE", lambda: spyware.sort_findings(spyware.audit())),
        ("INTRUSION ARTIFACTS", lambda: intrusion.sort_findings(intrusion.audit())),
        ("EVASION & KERNEL INTEGRITY", lambda: evasion.sort_findings(evasion.audit())),
        ("AUTOSTART EXTENSIBILITY", lambda: asep.sort_findings(asep.audit())),
        ("FIREWALL & INBOUND", lambda: firewall.audit(hosts=hosts)),
        ("CONTROL SURFACES", lambda: control.audit(hosts=hosts)),
        ("INTERCEPTION & BOUNDARY BYPASS", lambda: implant.audit(hosts=hosts)),
        ("NETWORK & WIRELESS", lambda: netwatch.audit(store)),
        ("SECURITY POSTURE", lambda: posture.audit(hosts=hosts)),
        ("BACKDOORS & ACCESS GRANTS", lambda: backdoor.audit(hosts=hosts)),
        ("DEVELOPER TOOLCHAIN TRUST", lambda: toolchain.audit(store, hosts=hosts)),
        ("SYNTHETIC INPUT", lambda: inputwatch.audit(store)),
        ("MEMORY & INSTRUCTION LEVEL", lambda: memscan.audit(hosts=hosts)),
        ("PLAINTEXT CREDENTIALS", lambda: secrets.audit()),
        ("SCREEN CAPTURE & TRACKING PIXELS", lambda: pixel.audit(hosts=hosts)),
        ("SYSMON TELEMETRY", lambda: sysmon.audit(store=store, hosts=hosts)),
        ("THREAT-INTEL MATCHES", lambda: hunt.sort_findings(
            hunt.hunt(store, hosts=hosts))),
    ]
    worst = {}
    for title, fn in sections:
        print(f"\n{color('━' * 72, 'dim', t)}")
        print(color(title, "bold", t))
        print(color("━" * 72, "dim", t))
        try:
            findings = fn()
        except Exception as exc:  # one failing collector must not kill the report
            print(color(f"  section failed: {exc}", "medium", t))
            continue
        for f in findings:
            f.setdefault("category", "")
        counts = _report(findings, verbose=args.verbose,
                         severity=args.severity or "medium")
        for k, v in counts.items():
            worst[k] = worst.get(k, 0) + v

    print(f"\n{color('━' * 72, 'dim', t)}")
    tally = "  ".join(f"{k}={worst[k]}" for k in
                      ("critical", "high", "medium", "low") if k in worst)
    print(f"{color('TOTAL', 'bold', t)}   {tally or 'nothing at medium or above'}")


def cmd_hidden(args, store):
    print(f"Cross-view process scan on {'+'.join(_hosts(args))} — comparing "
          f"independent enumerations…\n")
    findings, _ = hidden.audit(hosts=_hosts(args), deep=args.deep)
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    for f in findings:
        f.setdefault("category", "")
    counts = _report(findings, verbose=True, severity=args.severity,
                     sev_order=hidden.SEV_ORDER, show_ok=True,
                     empty="every view agrees — no processes hiding")
    if not any(k in counts for k in ("critical", "high")):
        print(color("  all process views agree.", "ok", _tty()))


def cmd_spy(args, store):
    print("Auditing for monitoring software, capability use and input control…\n")
    findings = spyware.sort_findings(spyware.audit())
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            empty="no monitoring software or capability abuse found")


def cmd_boot(args, store):
    if getattr(args, 'trace', False) or getattr(args, 'watch_seconds', None):
        from ... import flash
        argv = ['--watch-seconds', str(args.watch_seconds)] if args.watch_seconds else []
        return flash.main(argv)
    print("Reconstructing what ran at startup…\n")
    findings = startup.sort_findings(startup.audit())
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=startup.SEV_ORDER, show_ok=True,
            empty="nothing notable at boot")


def cmd_firewall(args, store):
    print(f"Auditing firewall posture and inbound connections on "
          f"{'+'.join(_hosts(args))}…\n")
    findings = firewall.audit(hosts=_hosts(args))
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=firewall.SEV_ORDER, show_ok=args.verbose,
            empty="no inbound exposure found")


def cmd_intrusion(args, store):
    print("Looking for intrusion artifacts — pasted commands, stealers, "
          "extensions…\n")
    findings = intrusion.sort_findings(intrusion.audit())
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=intrusion.SEV_ORDER, show_ok=True,
            empty="no intrusion artifacts found")


def cmd_coverage(args, store):
    print("Auditing the monitor itself — what is blind, stale or not running…\n")
    findings = coverage.sort_findings(coverage.audit(db_path=store.path))
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=coverage.SEV_ORDER, show_ok=True,
            empty="coverage is complete")


def cmd_evasion(args, store):
    print("Checking kernel integrity, hidden streams, shortcuts and dead-drop "
          "egress…\n")
    findings = evasion.sort_findings(evasion.audit())
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=evasion.SEV_ORDER, show_ok=True,
            empty="no evasion artifacts found")


def cmd_asep(args, store):
    print("Auditing autostart extensibility points…\n")
    findings = asep.sort_findings(asep.audit())
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=asep.SEV_ORDER, show_ok=True,
            empty="no autostart abuse found")


def cmd_implant(args, store):
    """Interception, boundary bypass and trust subversion."""
    print("Auditing interception, network-boundary bypass and trust "
          "subversion…\n")
    findings = implant.audit(hosts=_hosts(args))
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=implant.SEV_ORDER, show_ok=True,
            empty="no interception or boundary-bypass artifacts found")


def cmd_sysmon(args, store):
    """Kernel-level telemetry: LSASS access, injection, tampering."""
    print("Reading Sysmon telemetry…\n")
    findings = sysmon.audit(store=store, hours=args.hours, hosts=_hosts(args))
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=sysmon.SEV_ORDER, show_ok=True,
            empty="Sysmon reported nothing of interest")


def cmd_secrets(args, store):
    """Credentials sitting in plaintext on this disk."""
    roots = args.path or None
    where = (", ".join(roots) if roots
             else "all of $HOME" if args.deep
             else "config directories, documents and git checkouts")
    print(f"Scanning for credentials in plaintext ({where})…\n")
    findings = secrets.audit(roots=roots, deep=args.deep)
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=secrets.SEV_ORDER, show_ok=True,
            empty="no plaintext credentials found")


def cmd_memscan(args, store):
    """Executable memory with no file behind it, and patched syscall stubs."""
    print("Scanning process memory for unbacked code and hooked stubs…\n")
    findings = memscan.audit(hosts=_hosts(args))
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=memscan.SEV_ORDER, show_ok=True,
            empty="no unbacked executable memory or patched stubs found")


def cmd_inputwatch(args, store):
    """Synthetic keystrokes and clicks — input no hardware produced."""
    t = _tty()
    if args.start:
        err = inputwatch.start()
        print(color(f"  {err}", "medium", t) if err
              else "  injected-input monitor started")
        if err and err != "already running":
            return 1
    if args.stop:
        err = inputwatch.stop()
        print(f"  {err or 'injected-input monitor stopped'}")
        return
    findings = inputwatch.audit(store, hours=args.hours)
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=inputwatch.SEV_ORDER, show_ok=True,
            empty="no synthetic input recorded")


def cmd_backdoor(args, store):
    """Ways back in: keys, grants, units, profiles, accounts."""
    print("Auditing remote-access grants, privilege grants and login "
          "persistence…\n")
    findings = backdoor.audit(hosts=_hosts(args))
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=backdoor.SEV_ORDER, show_ok=True,
            empty="no backdoor mechanisms found")


def cmd_toolchain(args, store):
    """MCP servers, agent hooks, extensions, git hooks, package sources."""
    print("Auditing the developer trust surface — what runs because you "
          "opened an editor, a repo or a shell…\n")
    findings = toolchain.audit(store, hosts=_hosts(args))
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=toolchain.SEV_ORDER, show_ok=True,
            empty="nothing in the developer toolchain executes on its own")


def cmd_posture(args, store):
    """Windows security posture: what is on, off, and what to set."""
    print("Auditing Windows security posture…\n")
    if args.elevate:
        print(color("  a UAC prompt will appear on the Windows desktop — "
                    "accept it to read BitLocker, TPM and Defender exclusions",
                    "dim", _tty()))
    findings = posture.audit(hosts=_hosts(args), elevate=args.elevate)
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=posture.SEV_ORDER, show_ok=True,
            empty="posture could not be read")


def cmd_netwatch(args, store):
    """Sample network state, then report what the history shows."""
    t = _tty()
    if args.timeline:
        rows = netwatch.timeline(store, hours=args.hours)
        if not rows:
            print("no network events recorded yet")
            return
        for r in rows:
            sev = r["severity"]
            print(f"{iso(r['ts'])}  {color(sev.upper()[:4].ljust(4), sev, t)}  "
                  f"{r['kind']:22} {short(r['detail'], 76)}")
        return
    if not args.no_sample:
        events = netwatch.record(store)
        for e in events:
            print(color(f"  {e['severity']}: {e['detail']}", e["severity"], t))
    findings = netwatch.audit(store, hours=args.hours)
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=netwatch.SEV_ORDER, show_ok=True,
            empty="no network changes recorded")


def cmd_sysmon_linux(args, store):
    """eBPF syscall events from Sysmon for Linux."""
    findings = sysmon_linux.audit(store=store, hosts=_hosts(args),
                                  incremental=False)
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=sysmon_linux.SEV_ORDER, show_ok=True,
            empty="no Sysmon-for-Linux events in the window")


def cmd_bruteforce(args, store):
    """Failed-authentication volume across both sides."""
    findings = bruteforce.audit(hosts=_hosts(args))
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=bruteforce.SEV_ORDER, show_ok=True,
            empty="no failed-auth records to analyse")


def cmd_hunt(args, store):
    """Check every stored indicator against this machine."""
    t = _tty()
    info = intel.summary(store)
    if not info["total"]:
        print("no indicators yet — run `jarvis intel` first")
        return
    print(f"Hunting {info['total']} indicators from {info['docs']} writeups "
          f"across {'+'.join(_hosts(args))}…\n")
    findings = hunt.sort_findings(hunt.hunt(store, hosts=_hosts(args)))
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            empty="no indicator matched anything on this machine")


def cmd_gaps(args, store):
    """What current intel talks about that no collector checks."""
    t = _tty()
    findings, covered, closeable = hunt.gaps(store, min_docs=args.min_docs)
    if args.json:
        print(json.dumps({"gaps": findings,
                          "covered": [{"id": c[0], "docs": c[1], "by": c[2]}
                                      for c in covered]}, indent=2))
        return
    total = len(covered) + len(closeable)
    if not total:
        print("no ATT&CK techniques in the knowledge base yet — run `jarvis intel`")
        return
    pct = 100.0 * len(covered) / total
    print(f"of the techniques in current intel that leave host artifacts, "
          f"{len(covered)} of {total} are covered ({pct:.0f}%)\n")
    _report(findings, verbose=args.verbose, severity=args.severity,
            empty="every technique in current intel is covered")
    if args.verbose and covered:
        print(color("\n  already covered:", "dim", t))
        for tid, n, where in covered[:40]:
            print(color(f"    {tid:11} ×{n:<3} {where}", "dim", t))


# Collectors whose output needs no shaping beyond the standard report.
cmd_sniffing = _simple_cmd(sniffing, "no packet-capture state to report")
cmd_webshell = _simple_cmd(webshell, "no web server to audit")
cmd_auditd = _simple_cmd(auditd, "syscall-interception posture unavailable")
