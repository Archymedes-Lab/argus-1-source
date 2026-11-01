"""`jarvis welcome <profile>`: the first-run statement for one edition's audience.

Read-only and store-less: it renders jarvis/core/audience.py from the in-memory
coverage register, so it runs before the daemon has any state and never opens
the protected database. `--json` gives the same statement to other interfaces
(desktop app, dashboard) so they never write their own coverage claims.
"""

import json
import sys

from jarvis.core import audience


def cmd_welcome(args, store):
    statement = audience.first_run(args.profile)
    if args.json:
        json.dump(statement, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(audience.render(statement))
    return 0


def add_parser(sub):
    p = sub.add_parser("welcome",
                       help="first-run: what this edition looks at, its limits, how to remove it")
    p.add_argument("profile", choices=sorted(audience.PROFILES),
                   help="the edition's audience")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_welcome, no_store=True)
