"""`jarvis pixel` — screen-capture exposure and tracking-pixel posture."""

from . import run


def cmd_pixel(args, store):
    from ..cli.output import selected_hosts, render_findings
    findings = run.audit(hosts=selected_hosts(args))
    render_findings(findings, verbose=args.verbose,
            severity=args.severity or "medium")
    return 0


def add_parser(sub):
    p = sub.add_parser(
        "pixel",
        help="screen-capture exposure, mail tracking pixels and browser "
             "beacon protection")
    p.add_argument("--severity",
                   choices=["critical", "high", "medium", "low"])
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_pixel)
    return p
