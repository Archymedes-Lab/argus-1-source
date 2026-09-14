"""Terminal rendering shared by every subcommand."""

import json
import sys

from .. import (detect, fixit)
from ..util import short

C = {
    "critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m",
    "low": "\033[90m", "ok": "\033[32m", "dim": "\033[90m", "bold": "\033[1m",
    "reset": "\033[0m",
}


def color(text, key, on=True):
    return f"{C[key]}{text}{C['reset']}" if on and key in C else text


def _tty():
    return sys.stdout.isatty()


def _hosts(args):
    if args.host == "all":
        return ("wsl", "win")
    return (args.host,)


SECTION = {
    # module category -> heading shown above that group
    "spyware": "MONITORING SOFTWARE — things built to watch you",
    "access": "DEVICE & ACCOUNT ACCESS — mic, camera, logons",
    "input": "INPUT & AUDIO CONTROL — what can move your volume or type for you",
    "signing": "AUTOSTART CODE SIGNING — who vouches for what starts with Windows",
    "av": "ANTIVIRUS — what Defender already found",
    "clickfix": "PASTED COMMANDS — the Run dialog and PowerShell history",
    "extension": "BROWSER EXTENSIONS — what can read your sessions",
    "staging": "STAGED FILES — recent unsigned executables",
    "loader": "LOADER ABUSE — code injected into other processes",
    "collectors": "COLLECTOR HEALTH — is every check actually running?",
    "daemon": "CONTINUITY — is the monitor running, and will it survive a reboot?",
    "visibility": "BLIND SPOTS — what this system currently cannot see",
    "limits": "BY DESIGN — what this approach can never see",
    "byovd": "KERNEL INTEGRITY — vulnerable drivers and what blocks them",
    "ads": "ALTERNATE DATA STREAMS — files hidden inside other files",
    "lnk": "SHORTCUTS — what they show versus what they run",
    "c2": "DEAD-DROP C2 — commands and exfil over reputable services",
    "unicode": "INVISIBLE CHARACTERS — displayed text that is not executed text",
    "logon": "LOGON CHAIN",
    "com": "COM REGISTRATIONS",
    "privileged": "PRIVILEGED PLUMBING — code loaded by system services",
    "masquerade": "MASQUERADING & PARENTAGE",
    "history": "EXECUTION HISTORY",
    "flash": "WINDOW FLASHES — autostart entries that show a console window",
    "ran": "WHAT ACTUALLY RAN THIS BOOT",
    "boot": "BOOT",
    "inbound": "INBOUND CONNECTIONS — traffic initiated from outside",
    "rules": "FIREWALL RULES",
    "posture": "FIREWALL POSTURE",
    "impersonation": "IDENTITY — who is acting on this machine",
    "screen": "SCREEN CAPTURE — what can read your display",
    "tracking-mail": "MAIL TRACKING PIXELS — what reports that you read it",
    "tracking-web": "WEB BEACONS — browser anti-tracking posture",
}


def _print_finding(f):
    t = _tty()
    sev = f["severity"]
    tag = color(f" {sev.upper():8} ", sev, t)
    flag = "NEW" if f["unknown"] else "   "
    print(f"\n{tag} {flag} {color(f['name'], 'bold', t)} "
          f"[{f['host']}/{f['pid']}] {color(f['user'] or '-', 'dim', t)}")
    print(f"          exe   {short(f['exe'] or f.get('script') or '-', 96)}")
    print(f"          cmd   {short(f['cmdline'], 96)}")
    if f["reasons"]:
        print(f"          why   {detect.explain(f['reasons'])}")
    for r in f["remotes"][:6]:
        rd = f"  ({r['rdns']})" if r.get("rdns") else ""
        mark = color("→ PUBLIC", "high", t) if r["scope"] == "public" else "→"
        print(f"          net   {mark} {r['ip']}:{r['port']} "
              f"{r['proto']}/{r['state']}{rd}")
    print(f"          fp    {f['fp']}")


def _report(findings, verbose=False, severity=None, sev_order=None,
            show_ok=False, empty="nothing found"):
    """Shared renderer for the audit-style commands."""
    t = _tty()
    sev_order = sev_order or {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
    if severity:
        findings = [f for f in findings
                    if sev_order.get(f["severity"], 9) <= sev_order[severity]]
    if not show_ok and not verbose:
        findings = [f for f in findings if f["severity"] != "ok"]

    counts, last = {}, None
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        cat = f.get("category", "")
        if cat != last:
            heading = SECTION.get(cat, cat.upper())
            if heading:
                print(f"\n{color(heading, 'bold', t)}")
            last = cat
        sev = f["severity"]
        tag = (color("  ok  ", "ok", t) if sev == "ok"
               else color(f" {sev[:4].upper():4} ", sev, t))
        host = f.get("host", "")
        print(f"  {tag} [{host}] {f['title']}: {f['detail']}")
        where = f.get("where") or f.get("evidence") or ""
        if verbose and where:
            print(f"          {color(where, 'dim', t)}")
        fix = fixit.suggest(f)
        if fix:
            print(f"          {color('fix: ' + fix, 'ok', t)}")

    if not findings:
        print(color(f"  {empty}", "ok", t))
    tally = "  ".join(f"{k}={counts[k]}" for k in
                      ("critical", "high", "medium", "low") if k in counts)
    print(f"\n{len([f for f in findings if f['severity'] != 'ok'])} findings   "
          f"{tally or 'none'}")
    return counts


def _simple_cmd(mod, empty):
    def run(args, store):
        findings = mod.audit(hosts=_hosts(args))
        if args.json:
            print(json.dumps(findings, indent=2))
            return
        _report(findings, verbose=args.verbose, severity=args.severity,
                sev_order=mod.SEV_ORDER, show_ok=True, empty=empty)
    return run

