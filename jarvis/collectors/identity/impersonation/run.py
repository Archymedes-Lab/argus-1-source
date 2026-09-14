"""Running the identity audit, correlated with what the input hook saw."""

from jarvis.core.util import now

from . import rules
from .collect import sample

# How far back to count real input when deciding whether anything typed while
# the workstation was locked. The lock state is a point-in-time reading, so a
# wide window would attribute old, legitimate input to the current lock.
LOCK_WINDOW = 300


def _real_input_since(store, seconds=LOCK_WINDOW):
    """(keys, clicks) of un-flagged input in the recent beats."""
    if store is None:
        return 0, 0, "the last sample"
    try:
        rows = store.db.execute(
            "SELECT real_keys, real_clicks FROM input_beats WHERE ts >= ?",
            (now() - seconds,)).fetchall()
    except Exception:
        return 0, 0, "the last sample"
    keys = sum(int(r["real_keys"] or 0) for r in rows)
    clicks = sum(int(r["real_clicks"] or 0) for r in rows)
    return keys, clicks, "the last %d minutes" % (seconds // 60)


def audit(store=None, hosts=("wsl", "win")):
    if "win" not in hosts:
        return []
    keys, clicks, label = _real_input_since(store)
    data = sample()
    out = rules.audit_data(data, keys, clicks, label)
    return sort_findings(out)


def sort_findings(findings):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
    return sorted(findings, key=lambda f: (order.get(f["severity"], 9),
                                           f["title"]))
