"""`jarvis impersonation` — is someone else acting, or something acting as you?"""

from . import run


def cmd_impersonation(args, store):
    from jarvis.cli.output import selected_hosts, render_findings
    render_findings(run.audit(store, hosts=selected_hosts(args)), verbose=args.verbose,
            severity=args.severity or "medium")
    return 0


def add_parser(sub):
    p = sub.add_parser(
        "impersonation",
        help="logon sessions, remote desktop, assistive automation and "
             "credentials that let something act as you")
    p.add_argument("--severity",
                   choices=["critical", "high", "medium", "low"])
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_impersonation)
    return p
