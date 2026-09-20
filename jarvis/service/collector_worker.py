"""Process boundary for collectors that touch failure-prone kernel bridges.

This module is intentionally not a general command runner. The parent passes a
fixed collector name and ordinary data arguments; only collectors explicitly
listed here may execute. stdout is one JSON result so the scheduler can commit
the same observation receipt it would have produced in-process.
"""

import json
import sys
import traceback

from jarvis.core import collection
from jarvis.service.jobs import run_job

ALLOWED = {"native"}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 3 or argv[0] not in ALLOWED:
        return 2
    name, db_path, *hosts = argv
    findings, error, status = [], "", "unavailable"
    try:
        with collection.observe() as observation:
            findings = list(run_job(name, tuple(hosts), db_path) or [])
        error, status = observation.error, observation.status
    except Exception:
        error = traceback.format_exc()[-800:]
    sys.stdout.write(json.dumps({"findings": findings, "error": error,
                                 "status": status}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
