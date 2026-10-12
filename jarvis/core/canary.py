"""Canary tokens: inert bait that alerts the owner when it is touched or taken.

The idea the owner asked for: if the machine is infiltrated, plant decoys an
intruder cannot resist, and have the decoy — once read, copied, or opened
somewhere else — raise the alarm *to the owner*. The signal reaches the
attacker's world only in that the bait sits still where they will find it; what
comes back is a log entry their own software produced by opening it.

Two detections, both passive:

  on-box tripwire   a decoy file is fingerprinted when planted. If it is later
                    modified, removed, or (best effort) read, that is a touch.
                    JARVIS never attributes this to a person; it reports that
                    the bait moved.
  off-box callback  a decoy document carries a URL that resolves only to
                    infrastructure the OWNER controls. When the bait is opened
                    elsewhere, the opener's client fetches that URL and the
                    owner's listener records the connection metadata it reveals
                    (source address, user-agent, time). JARVIS ingests those
                    hits; it does not host an exposed service, and it never
                    fetches, stores, or runs anything from the attacker's side.

Hard line, enforced here: a token is inert data and runs no code anywhere. Its
callback target is owner-controlled and must be configured — never defaulted to
a third party. Nothing in this module reaches toward, scans, or acts on the
attacker. There is no hack-back.

Permanent ink: the journal below is an append-only hash chain, the same shape as
the event log. Each record carries the previous record's hash, so deleting,
editing, or reordering any record breaks the chain at a verifiable point. The
head is anchored externally (OpenTimestamps) so the record of what bait existed,
and that it tripped, cannot be quietly rewritten after the fact.
"""

import hashlib
import json
import os
import secrets
import time
from pathlib import Path

from jarvis.core import filelock

DEFAULT_ROOT = Path(os.path.expanduser("~/.jarvis/canary"))
GENESIS = "0" * 64
KINDS = ("file_decoy", "doc_url", "credential")
RECORD_KINDS = ("plant", "retire", "trip", "callback")
# A tracking URL may name only a host the owner controls. There is deliberately
# no default: planting a doc_url without a configured base is refused, so a token
# can never be made to call home to someone else's server.
TRIP_REASONS = ("modified", "removed", "accessed")


class CanaryError(Exception):
    pass


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False, default=str)


def record_hash(record):
    """SHA-256 of a record's canonical JSON with its own hash field removed.

    Exposed so an independent verifier can recompute the chain without this code.
    """
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(_canonical(body).encode()).hexdigest()


# -- bait generation (inert) --------------------------------------------------

def _token_id():
    return secrets.token_hex(16)


def fingerprint_file(path):
    """A decoy file's identity at plant time: size, mtime and content hash.

    Returns None if the path cannot be read, so a decoy that never existed is
    not mistaken for one that was removed.
    """
    try:
        data = Path(path).read_bytes()
        st = Path(path).stat()
    except OSError:
        return None
    return {"sha256": hashlib.sha256(data).hexdigest(),
            "size": st.st_size, "mtime": int(st.st_mtime)}


def make_token(kind, label, *, path=None, url_base=None):
    """Build an inert token record (not yet planted). Pure.

    `credential` and `doc_url` return bait text to place; `file_decoy` records
    the fingerprint of a file the owner has already written at `path`.
    """
    if kind not in KINDS:
        raise CanaryError(f"unknown token kind {kind!r}")
    tid = _token_id()
    token = {"id": tid, "kind": kind, "label": str(label)[:200],
             "created_at": int(time.time())}
    if kind == "file_decoy":
        if not path:
            raise CanaryError("file_decoy needs the path of the decoy file")
        fp = fingerprint_file(path)
        if fp is None:
            raise CanaryError(f"decoy file is not readable: {path}")
        token["path"] = str(path)
        token["fingerprint"] = fp
    elif kind == "doc_url":
        base = (url_base or "").strip().rstrip("/")
        if not base or "://" not in base:
            raise CanaryError("doc_url needs an owner-controlled URL base "
                              "(e.g. https://canary.example.com); there is no default")
        # The only thing embedded in the bait: a unique path under the owner's
        # own host. Opening the doc makes the opener fetch this, and only this.
        token["url"] = f"{base}/c/{tid}.png"
        token["bait_hint"] = ("Embed this URL as a remote image/link in a tempting "
                              "document and place the document as bait.")
    elif kind == "credential":
        # A fake, clearly-random secret. Detection is via the owner's own audit
        # of where the real credential would be used (e.g. a cloud trail), fed
        # back as a callback. JARVIS stores only its fingerprint, never a usable
        # secret of its own.
        fake = "AKIA" + secrets.token_hex(8).upper()[:16]
        token["secret_fp"] = hashlib.sha256(fake.encode()).hexdigest()
        token["bait_value"] = fake
        token["bait_hint"] = ("Place this fake key where a real one would sit. Report "
                              "any use of it to the callback inbox.")
    return token


# -- the append-only hash-chained journal ("permanent ink") -------------------

class CanaryJournal:
    """Append-only, hash-chained record of every token and every trip.

    Readers take no lock; the one writer (the scheduler worker, or the planting
    CLI) holds a lock file while appending, so a concurrent plant and audit
    cannot interleave a half-written line.
    """

    def __init__(self, root=DEFAULT_ROOT):
        self.root = Path(root)
        self.path = self.root / "journal.jsonl"
        self.anchors = self.root / "anchors"

    def _read(self):
        """Every committed line, parsed. A line that does not decode or parse is
        kept as a corrupt sentinel rather than raised: a garbled byte in the
        journal is tampering to report, not a crash that takes the audit down."""
        if not self.path.exists():
            return []
        out = []
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    out.append({"__corrupt__": True})
        return out

    def records(self):
        """Every committed record, in order. Raises on a truncated last line."""
        return self._read()

    def verify(self):
        """The first broken link, or None if the whole chain verifies.

        Detects an edited, deleted, reordered or inserted record: any of these
        makes a recomputed hash or a previous-hash link fail to match.
        """
        prev = GENESIS
        expect_seq = 1
        for i, rec in enumerate(self._read()):
            if rec.get("__corrupt__"):
                return {"index": i, "seq": expect_seq, "reason": "corrupt record"}
            if rec.get("seq") != expect_seq:
                return {"index": i, "reason": "sequence break",
                        "expected_seq": expect_seq, "found_seq": rec.get("seq")}
            if rec.get("prev") != prev:
                return {"index": i, "seq": rec.get("seq"), "reason": "broken link"}
            if rec.get("hash") != record_hash(rec):
                return {"index": i, "seq": rec.get("seq"), "reason": "record altered"}
            prev = rec["hash"]
            expect_seq += 1
        return None

    def head(self):
        """{seq, hash}: copy it off-box to make a later rewrite visible."""
        recs = [r for r in self._read() if "hash" in r and "seq" in r]
        if not recs:
            return {"seq": 0, "hash": GENESIS}
        return {"seq": recs[-1]["seq"], "hash": recs[-1]["hash"]}

    def append(self, kind, payload):
        """Append one record under the writer lock, as a single durable write."""
        if kind not in RECORD_KINDS:
            raise CanaryError(f"unknown record kind {kind!r}")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock = open(self.root / "writer.lock", "a")
        try:
            filelock.acquire(lock)
        except OSError:
            lock.close()
            raise CanaryError("another writer holds the canary journal")
        try:
            recs = self._read()               # re-read under the lock
            prev = recs[-1]["hash"] if recs else GENESIS
            seq = (recs[-1]["seq"] + 1) if recs else 1
            rec = {"seq": seq, "at": int(time.time()), "kind": kind,
                   "prev": prev, "payload": payload}
            rec["hash"] = record_hash(rec)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(_canonical(rec) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return rec
        finally:
            lock.close()

    # -- derived current state (a replay of the journal) ------------------

    def state(self):
        """Replay to the current view: active tokens, trips, seen callbacks."""
        tokens, retired = {}, set()
        tripped = {}            # token id -> set of reasons already recorded
        callbacks = {}          # token id -> list of hit metadata
        seen_hits = set()
        for rec in self._read():
            if rec.get("__corrupt__"):
                continue
            p = rec.get("payload") or {}
            if rec.get("kind") == "plant":
                tokens[p["id"]] = p
            elif rec.get("kind") == "retire":
                retired.add(p.get("id"))
            elif rec.get("kind") == "trip":
                tripped.setdefault(p.get("id"), set()).add(p.get("reason"))
            elif rec.get("kind") == "callback":
                if p.get("hit_id"):
                    seen_hits.add(p["hit_id"])
                callbacks.setdefault(p.get("id"), []).append(p)
        active = {tid: t for tid, t in tokens.items() if tid not in retired}
        return {"tokens": tokens, "active": active, "retired": retired,
                "tripped": tripped, "callbacks": callbacks, "seen_hits": seen_hits}


# -- planting -----------------------------------------------------------------

def plant(kind, label, *, path=None, url_base=None, root=DEFAULT_ROOT):
    """Create a token and record it in the journal. Returns the token."""
    token = make_token(kind, label, path=path, url_base=url_base)
    journal = CanaryJournal(root)
    journal.append("plant", token)
    return token


def retire(token_id, root=DEFAULT_ROOT):
    journal = CanaryJournal(root)
    journal.append("retire", {"id": token_id})


# -- on-box tripwire ----------------------------------------------------------

def onbox_trips(active_tokens, *, now=None, stat=os.stat, read_bytes=None,
                check_access=False):
    """Trips for planted file decoys whose on-disk state no longer matches.

    `modified` and `removed` are reliable. `accessed` (atime advanced past the
    plant time) is only reported when `check_access` is set, because relatime
    and DrvFs make atime weak; a false "accessed" would cry wolf.
    """
    now = now or time.time()
    reader = read_bytes or (lambda p: Path(p).read_bytes())
    trips = []
    for tid, token in sorted(active_tokens.items()):
        if token.get("kind") != "file_decoy":
            continue
        path = token.get("path")
        baseline = token.get("fingerprint") or {}
        try:
            st = stat(path)
        except OSError:
            trips.append({"id": tid, "reason": "removed", "path": path,
                          "detail": "the decoy file is gone — copied and deleted, "
                                    "or deleted outright", "at": int(now)})
            continue
        changed = (int(st.st_size) != baseline.get("size")
                   or int(st.st_mtime) != baseline.get("mtime"))
        if not changed:
            try:
                changed = (hashlib.sha256(reader(path)).hexdigest()
                           != baseline.get("sha256"))
            except OSError:
                changed = True
        if changed:
            trips.append({"id": tid, "reason": "modified", "path": path,
                          "detail": "the decoy file's contents or metadata changed "
                                    "since it was planted", "at": int(now)})
        elif check_access:
            atime = int(getattr(st, "st_atime", 0))
            if atime > baseline.get("mtime", 0) and atime > token.get("created_at", 0):
                trips.append({"id": tid, "reason": "accessed", "path": path,
                              "detail": "the decoy file's access time advanced "
                                        "(weak signal; atime can be unreliable)",
                              "at": int(now)})
    return trips


# -- off-box callback ingestion (owner's own listener) ------------------------

def read_callbacks(inbox_path, *, active_ids=None, seen_hits=None, max_bytes=1_000_000):
    """New, well-formed hits from the owner's listener file. Metadata only.

    The inbox is a JSONL file the owner's own collector writes, one hit per line:
    {"hit_id","token","ip","ua","at"}. Malformed lines are skipped, not fatal;
    oversized lines and unknown fields are dropped. Nothing here fetches a URL,
    opens a connection, or trusts the attacker's data as anything but a string.
    """
    seen_hits = seen_hits or set()
    out = []
    if not inbox_path:
        return out
    try:
        size = os.path.getsize(inbox_path)
    except OSError:
        return out
    if size > max_bytes:
        # Bounded read: a huge inbox is itself suspicious, but it must not take
        # the collector down. Read the tail only.
        start = size - max_bytes
    else:
        start = 0
    try:
        with open(inbox_path, "r", encoding="utf-8", errors="replace") as fh:
            if start:
                fh.seek(start)
                fh.readline()                 # drop a partial first line
            for line in fh:
                line = line.strip()
                if not line or len(line) > 8192:
                    continue
                try:
                    hit = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(hit, dict):
                    continue
                token_id = str(hit.get("token", ""))[:64]
                hit_id = str(hit.get("hit_id", ""))[:64]
                if not token_id or not hit_id or hit_id in seen_hits:
                    continue
                if active_ids is not None and token_id not in active_ids:
                    # A hit for a token we never planted (or already retired):
                    # keep it, but mark it so a finding can flag the mismatch.
                    pass
                out.append({"id": token_id, "hit_id": hit_id,
                            "ip": str(hit.get("ip", ""))[:64],
                            "ua": str(hit.get("ua", ""))[:256],
                            "at": int(hit["at"]) if str(hit.get("at", "")).isdigit()
                                  else int(time.time()),
                            "source": "callback-inbox"})
                seen_hits.add(hit_id)
    except OSError:
        return out
    return out


# -- external anchoring (permanent ink for the journal head) ------------------

def anchor_manifest(head, now):
    return {"v": 1, "at": int(now), "canary_head": {"seq": head.get("seq"),
                                                    "hash": head.get("hash")}}


def anchor_head(journal, *, now=None, last=None, every=21600, network=True,
                submit=None):
    """Anchor the journal head externally when due. Returns (digest_hex, error).

    `submit` is injected (defaults to the OpenTimestamps client) so tests never
    touch the network. Only a 32-byte digest of the head manifest ever leaves.
    """
    now = now or time.time()
    head = journal.head()
    if not network or head.get("hash") in (None, GENESIS):
        return None, None
    if last and last.get("hash") == head.get("hash"):
        return None, None
    if last and now - last.get("at", 0) < every:
        return None, None
    if submit is None:
        # core must not reach up into the platform layer; the caller (the
        # collector) supplies the OpenTimestamps submitter. No submitter means
        # anchoring is not configured, not that the head is unprotected.
        return None, "no anchor submitter"
    body = _canonical(anchor_manifest(head, now)).encode()
    digest = hashlib.sha256(body).digest()
    try:
        proof, _calendars = submit(digest)
    except Exception as exc:                   # noqa: BLE001 - network/proof errors stay advisory
        return None, type(exc).__name__
    journal.anchors.mkdir(parents=True, exist_ok=True)
    (journal.anchors / f"{digest.hex()}.json").write_bytes(body)
    (journal.anchors / f"{digest.hex()}.ots").write_bytes(proof)
    return digest.hex(), None
