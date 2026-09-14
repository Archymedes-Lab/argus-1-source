"""Is something typing or clicking for you?

Split by stage, and by what each stage depends on: `helper` stages and
runs the Windows input hook, `ingest` drains its output into the store,
`analysis` turns that telemetry into findings, and `supervise` decides
whether the helper is alive and unmodified. Dependencies run one way
through that list, so no two modules import each other.

The package re-exports the flat module's surface, internal helpers
included, so existing callers keep working unchanged.
"""

from .analysis import (SEV_ORDER, _cadence_findings, _latency_findings,
                       _typing_findings, audit, sort_findings)
from .common import HOOK_PS1, _finding, _mget_int, _sha256
from .helper import (_alive_mtime, _alive_path, _paths, _pid_path,
                     _pidfile_pid, _staged_matches_source, _stop_all,
                     ensure, running, start, stop)
from .ingest import ingest
from .supervise import (_dupes, _flap_finding, _helper_count, _jsonl_size,
                        _verify_pin, liveness, supervise)

__all__ = ["SEV_ORDER", "audit", "sort_findings", "ingest", "liveness",
           "supervise", "start", "stop", "ensure", "running", "HOOK_PS1"]
