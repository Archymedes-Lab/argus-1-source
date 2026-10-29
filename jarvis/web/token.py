"""Per-start API token for the state-changing routes.

`jarvis serve` writes a fresh random token to a 0600 file when it starts; the
dashboard receives it as a SameSite cookie on the page load, and the CLI reads
the file. Every POST route that changes state (run, answer, fix, geo) requires
it as the `X-JARVIS-Token` header or the `jarvis_token` cookie.

What this closes: DNS-rebound pages, other local accounts, and any client that
cannot read the token file. What it does not close on its own: a process
running as the same account as the daemon can read the file, and under WSL
mirrored networking a Windows process of that account can read it through
\\\\wsl.localhost. The token is complete only once the daemon runs as its own
user (PROTECTION-REVIEW-2026-10-21 F2); until then it is a gate, not a wall.
"""

import os
import secrets

TOKEN_PATH = os.path.expanduser("~/.jarvis/api.token")
HEADER = "X-JARVIS-Token"
COOKIE = "jarvis_token"
_TOKEN = None


def issue(path=TOKEN_PATH):
    """Write a new token (0600) and keep it in memory for this process."""
    global _TOKEN
    value = secrets.token_hex(32)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, value.encode())
    finally:
        os.close(fd)
    os.replace(tmp, path)
    _TOKEN = value
    return value


def current():
    """The token this process issued, or None (tests, or serve not started)."""
    return _TOKEN


def read(path=TOKEN_PATH):
    """A client's view: the token file, or "" when there is none."""
    try:
        with open(path, encoding="ascii", errors="ignore") as fh:
            return fh.read().strip()[:128]
    except OSError:
        return ""


def presented(headers):
    """The token a request carries, from the header or the cookie, or ""."""
    value = (headers.get(HEADER) or "").strip()
    if value:
        return value
    for part in (headers.get("Cookie") or "").split(";"):
        name, _, val = part.strip().partition("=")
        if name == COOKIE:
            return val.strip()
    return ""


def accepts(headers):
    """True when no token is in force (not serving) or the request carries it."""
    if _TOKEN is None:
        return True
    return secrets.compare_digest(presented(headers), _TOKEN)


def cookie_header():
    """Set-Cookie value for the dashboard page, or None when not serving."""
    if _TOKEN is None:
        return None
    return f"{COOKIE}={_TOKEN}; Path=/; SameSite=Strict"
