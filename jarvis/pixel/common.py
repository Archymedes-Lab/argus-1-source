"""Shared shape for the tracking and capture checks."""

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def finding(category, severity, title, detail, where="", host="win"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def sort_findings(findings):
    return sorted(findings, key=lambda f: (SEV_ORDER.get(f["severity"], 9),
                                           f["category"], f["title"]))


def aslist(value):
    """PowerShell emits a bare object for one result and an array for many."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
