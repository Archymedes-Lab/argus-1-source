"""The posture audit: one sample, every section, sorted."""

from jarvis.platform.windows import ps_json

from .collect import PS_POSTURE, elevated_data
from .common import _finding, sort_findings
from .sections import SECTIONS


def audit(hosts=("win",), elevate=False):
    if "win" not in hosts:
        return []
    elev_err = ""
    d = None
    if elevate:
        d, elev_err = elevated_data()
    if d is None:
        d = ps_json(PS_POSTURE, timeout=400)
    if not d:
        return [_finding("visibility", "medium", "posture audit unavailable",
                         "powershell.exe returned no data")]
    out = []
    if elevate and elev_err:
        out.append(_finding(
            "visibility", "medium", "elevated audit did not run",
            f"{elev_err} — falling back to the unelevated result, so the "
            f"checks that need administrator remain unread"))

    for section in SECTIONS:
        out.extend(section(d))
    return sort_findings(out)
