"""Per-start API token for the state-changing routes.

`jarvis serve` writes a fresh random token to a 0600 file when it starts; the
dashboard receives it as a SameSite cookie on the page load, and the CLI reads
the file. Every POST route that changes state (run, answer, fix, geo) requires
it as the `X-JARVIS-Token` header or the `jarvis_token` cookie.

What this closes: DNS-rebound pages, cross-site pages, and any client that can
neither read the token file nor load the dashboard page as an allowed peer.

The dashboard page hands the token to whoever loads it, so the page load is
itself gated: on Linux the connecting socket's owner is looked up in
/proc/net/tcp{,6} and the cookie is issued only to this account or root (both
can read the file anyway). A peer whose owner cannot be seen there -- a Windows
process reaching the daemon through WSL mirrored networking -- still receives
it; that is the residual exposure until the daemon runs as its own user
(PROTECTION-REVIEW-2026-10-21 F2). Until then the token is a gate, not a wall:
a process of the same account can read the file, and from Windows through
\\\\wsl.localhost.

With no token issued (serve() not started) every state-changing request is
refused: the gate fails closed.
"""

import os
import secrets
import socket
import tempfile

TOKEN_PATH = os.path.expanduser("~/.jarvis/api.token")
HEADER = "X-JARVIS-Token"
COOKIE = "jarvis_token"
_TOKEN = None


def issue(path=TOKEN_PATH):
    """Write a new token (0600) and keep it in memory for this process.

    The file is created fresh with O_EXCL under a random name (tempfile.mkstemp:
    mode 0600, never through a link, never reusing a file someone left behind
    with a looser mode), flushed, then renamed over the old one. The token is
    therefore never readable by another account, not even for an instant.
    """
    global _TOKEN
    value = secrets.token_hex(32)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".api.token.", dir=directory)
    try:
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            data = value.encode()
            while data:
                data = data[os.write(fd, data):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
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
    """True only when a token is in force and the request carries exactly it.

    Fails closed: with no token issued nothing state-changing is accepted. The
    comparison is constant time over bytes, so a non-ASCII header value is a
    plain mismatch rather than an exception.
    """
    if _TOKEN is None:
        return False
    given = presented(headers).encode("utf-8", "replace")
    return secrets.compare_digest(given, _TOKEN.encode("ascii"))


def cookie_header():
    """Set-Cookie value for the dashboard page, or None when not serving.

    HttpOnly: no page script reads it (the browser attaches it), so injected
    script cannot copy it out. SameSite=Strict: no cross-site request carries it.
    """
    if _TOKEN is None:
        return None
    return f"{COOKIE}={_TOKEN}; Path=/; HttpOnly; SameSite=Strict"


# ---- who may receive the token with the dashboard page ------------------------

PROC_NET = ("/proc/net/tcp", "/proc/net/tcp6")
_PROC_ROWS_MAX = 65_536          # bounded scan of the socket tables


def _decode(hexaddr):
    """('127.0.0.1', 8787) from a /proc/net/tcp{,6} "ADDR:PORT" field, or None."""
    try:
        addr, port = hexaddr.split(":")
        raw = bytes.fromhex(addr)
        if len(raw) == 4:
            return socket.inet_ntop(socket.AF_INET, raw[::-1]), int(port, 16)
        if len(raw) == 16:
            # Four 32-bit words, each in host (little-endian) order.
            raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
            if raw[:12] == b"\0" * 10 + b"\xff\xff":      # v4-mapped
                return socket.inet_ntop(socket.AF_INET, raw[12:]), int(port, 16)
            return socket.inet_ntop(socket.AF_INET6, raw), int(port, 16)
    except (ValueError, OSError):
        pass
    return None


def peer_uid(client, server, tables=PROC_NET):
    """The uid owning the client end of a loopback TCP connection, or None.

    `client` and `server` are (host, port) as the server sees them. The client's
    socket is the row whose local address is `client` and whose remote address
    is `server`. None when no such row exists (Windows peers under WSL mirrored
    networking, non-Linux hosts) or the tables cannot be read.
    """
    want_local = (str(client[0]), int(client[1]))
    want_remote = (str(server[0]), int(server[1]))
    for table in tables:
        try:
            with open(table, encoding="ascii", errors="replace") as fh:
                next(fh, None)                      # header line
                for n, line in enumerate(fh):
                    if n >= _PROC_ROWS_MAX:
                        break
                    fields = line.split()
                    if len(fields) < 8:
                        continue
                    if (_decode(fields[1]) == want_local
                            and _decode(fields[2]) == want_remote):
                        try:
                            return int(fields[7])
                        except ValueError:
                            return None
        except OSError:
            continue
    return None


def may_receive(uid):
    """Whether a peer owned by `uid` may be handed the token with the page.

    This account and root may (both can read the token file anyway). Any other
    attributed account may not. An unattributable peer (None) keeps today's
    behaviour -- see the module docstring for that residual exposure.
    """
    if uid is None:
        return True
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    return uid == 0 or uid == euid
