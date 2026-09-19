"""Deterministic analysis for the opt-in JARVIS Veil browser sensor.

The sensor deliberately cannot submit page text, typed characters, pointer
coordinates, screenshots, cookies, URL paths/query strings, request bodies, or
browser identifiers.  This module accepts only bounded counters and origins;
external pages and extension messages are untrusted evidence, not authority.
"""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from jarvis.core.finding import finding

MAX_ORIGINS = 16
MAX_COUNTER = 10_000
INTERACTION = {"mousemove", "pointermove", "scroll", "input", "keydown"}
FINGERPRINT_SURFACES = {
    "canvas", "webgl", "webgpu", "audio", "fonts", "screen", "hardware",
    "media_devices", "performance", "opfs",
}
TRACKING_PARAMS = {
    "fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid", "_ga",
    "_gl", "igshid", "vero_id", "yclid",
}


def _origin(value):
    if not isinstance(value, str) or len(value) > 255:
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    return f"{parsed.scheme}://{parsed.hostname.lower()}" + (
        f":{port}" if port else "")


def _counts(value, allowed):
    if not isinstance(value, dict):
        return {}
    out = {}
    for key, count in value.items():
        if key in allowed and isinstance(count, int) and 0 <= count <= MAX_COUNTER:
            out[key] = count
    return out


def validate_report(report):
    """Return a minimal, normalized report or ``None`` if it is malformed.

    No coercion is used for counts: accepting strings or floats makes a hostile
    page able to create ambiguous evidence.  Origins are reduced before storage.
    """
    if not isinstance(report, dict):
        return None
    top = _origin(report.get("top_origin"))
    if top is None:
        return None
    origins = report.get("egress_origins")
    if not isinstance(origins, list) or len(origins) > MAX_ORIGINS:
        return None
    egress = sorted({_origin(value) for value in origins if _origin(value)})
    if len(egress) > MAX_ORIGINS:
        return None
    listeners = _counts(report.get("listeners"), INTERACTION)
    surfaces = _counts(report.get("surfaces"), FINGERPRINT_SURFACES)
    transports = _counts(report.get("transports"), {"fetch", "xhr", "beacon"})
    if not (listeners or surfaces or transports):
        return None
    return {"top_origin": top, "egress_origins": egress,
            "listeners": listeners, "surfaces": surfaces,
            "transports": transports}


def classify(report):
    """Classify aggregate behavior; this function never performs blocking.

    The browser sensor is evidence-only in this release.  A count by itself is
    not malicious: elevated findings require a combination plus cross-origin
    export.  That keeps ordinary interactive sites from being labelled trackers.
    """
    report = validate_report(report)
    if report is None:
        return []
    top = report["top_origin"]
    third_party = [o for o in report["egress_origins"] if o != top]
    exported = bool(third_party and sum(report["transports"].values()))
    interaction = {name for name, n in report["listeners"].items() if n}
    surfaces = {name for name, n in report["surfaces"].items() if n}
    out = []
    if exported and len(interaction & INTERACTION) >= 4:
        out.append(finding(
            "privacy-veil", "high", "behavioral interaction tracking detected",
            "aggregate listener observation: " + ", ".join(sorted(interaction))
            + "; cross-origin network export via "
            + ", ".join(sorted(k for k, v in report["transports"].items() if v))
            + ". JARVIS retained no typed text, timing series, or pointer coordinates.",
            top, host="browser"))
    elif exported and {"input", "keydown"} & interaction:
        out.append(finding(
            "privacy-veil", "medium", "keyboard interaction data may be exported",
            "keyboard/input listeners and cross-origin network activity were observed; "
            "this is metadata-only evidence, not proof of keystroke capture.", top,
            host="browser"))
    if exported and len(surfaces) >= 4:
        out.append(finding(
            "privacy-veil", "medium", "fingerprinting surface aggregation detected",
            "%d high-entropy surfaces (%s) were observed before cross-origin export. "
            "This is a behavioral indicator, not a compromise verdict."
            % (len(surfaces), ", ".join(sorted(surfaces))), top, host="browser"))
    elif exported and "opfs" in surfaces and "performance" in surfaces:
        out.append(finding(
            "privacy-veil", "low", "storage timing surface used before network export",
            "OPFS and performance APIs were both observed with cross-origin export; "
            "review in a hardened browser mode if this is unexpected.", top, host="browser"))
    return out


def clean_link(url):
    """Remove common decoration without changing a link's destination path."""
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return url
    kept = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if not (key.lower().startswith("utm_") or key.lower() in TRACKING_PARAMS)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                       urlencode(kept, doseq=True), parsed.fragment))
