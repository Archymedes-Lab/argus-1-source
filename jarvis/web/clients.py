"""Paired API clients: per-client, revocable tokens for programs that are not
the dashboard page (the desktop app, the CLI, Windows supervisors, Prometheus).

Why: the dashboard page can only hand its per-start token to a peer whose
socket owner is identified (web/token.py). A client the daemon cannot identify
-- a Windows program reaching WSL, a scraper -- is paired explicitly instead:
the owner runs `jarvis desktop pair` where the daemon's store is writable, gives
the printed token to that one program, and can list or revoke it later.

Storage: only SHA-256 digests are kept, in the store's meta table. A token is
`jc1_<id>_<secret>`: the id locates the record, the 256-bit secret is compared
in constant time against the stored digest. A revoked record is kept (with the
time and the name) so the list stays an audit trail, and it never matches.
"""

import hashlib
import json
import re
import secrets
import time

META_KEY = "api_clients"
PREFIX = "jc1_"
MAX_ACTIVE = 32
MAX_RECORDS = 256
_TOKEN_RE = re.compile(r"^jc1_([0-9a-f]{12})_([A-Za-z0-9_-]{43})$")
_NAME_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,40}$")


def _digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _load(store):
    try:
        value = json.loads(store.get_meta(META_KEY, "[]") or "[]")
    except (TypeError, ValueError):
        return []
    return [r for r in value if isinstance(r, dict) and isinstance(r.get("id"), str)] \
        if isinstance(value, list) else []


def _save(store, records):
    store.set_meta(META_KEY, json.dumps(records[-MAX_RECORDS:], sort_keys=True))


def looks_like(token):
    """True when the text has the shape of a client token (not that it is valid)."""
    return isinstance(token, str) and bool(_TOKEN_RE.match(token))


def pair(store, name, now=None):
    """Create one client. Returns (id, token); the token is shown only here."""
    name = (name or "").strip()
    if not _NAME_RE.match(name):
        raise ValueError("name: 1-40 letters, digits, space, dot, dash or underscore")
    records = _load(store)
    active = [r for r in records if not r.get("revoked_at")]
    if len(active) >= MAX_ACTIVE:
        raise ValueError(f"{MAX_ACTIVE} clients are already paired; revoke one first")
    cid = secrets.token_hex(6)
    while any(r["id"] == cid for r in records):
        cid = secrets.token_hex(6)
    token = f"{PREFIX}{cid}_{secrets.token_urlsafe(32)}"
    records.append({"id": cid, "name": name, "sha256": _digest(token),
                    "created_at": int(now if now is not None else time.time()),
                    "revoked_at": None})
    _save(store, records)
    return cid, token


def listing(store):
    """Every record without its digest: id, name, created_at, revoked_at."""
    return [{k: r.get(k) for k in ("id", "name", "created_at", "revoked_at")}
            for r in _load(store)]


def revoke(store, cid, now=None):
    """Revoke one client by id. True when an active client was revoked."""
    records = _load(store)
    for r in records:
        if r["id"] == cid and not r.get("revoked_at"):
            r["revoked_at"] = int(now if now is not None else time.time())
            _save(store, records)
            return True
    return False


def verify(store, token):
    """The id of the active client this token belongs to, or None.

    Malformed, unknown, revoked and forged tokens are all just None; the
    digest comparison is constant time.
    """
    if not isinstance(token, str):
        return None
    m = _TOKEN_RE.match(token)
    if not m:
        return None
    want = _digest(token)
    for r in _load(store):
        if r["id"] == m.group(1) and not r.get("revoked_at"):
            # Bytes, not str: compare_digest raises TypeError on non-ASCII text (FZ-09).
            if secrets.compare_digest(str(r.get("sha256") or "").encode("utf-8", "replace"), want.encode()):
                return r["id"]
            return None
    return None
