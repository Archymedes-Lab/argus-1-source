"""The common finding shape every collector returns.

Key order matters only to humans reading raw JSON, but it is kept stable here so
snapshots, the dashboard and stored payloads read the same everywhere.
Identity for alerting is derived from category, title and where (see
response.alert.finding_key), so those three must stay stable for a given
condition.
"""


def finding(category, severity, title, detail, where="", host="wsl"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def win_finding(category, severity, title, detail, where="", host="win"):
    """The same shape for collectors whose findings are about Windows by default."""
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}
