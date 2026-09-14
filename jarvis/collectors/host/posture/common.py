"""Finding shape and ordering for the posture audit."""


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


CAT_ORDER = {"malware defense": 0, "platform integrity": 1, "data at rest": 2,
             "account & access": 3, "attack surface": 4, "visibility": 5,
             "licensing": 6, "operations": 7}


def _finding(category, severity, title, detail, fix="", host="win"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail + (f"  →  {fix}" if fix else ""),
            "where": fix, "host": host}


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9), x["title"]))
