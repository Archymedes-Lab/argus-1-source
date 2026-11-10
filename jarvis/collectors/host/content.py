"""File content checked against community rules, where dropped files land.

Process and registry rules judge what was typed. They say nothing about a web
shell saved into a web root, a tool unpacked into /tmp, or a script waiting in a
startup folder. This collector reads files in a short list of such places and
checks their bytes against compiled community rules (core/patterns.py: a strict
subset of YARA evaluated by literal search; no engine, no regular expressions).

Invariants
  1. Read-only and private: files are opened read-only without following links;
     content is matched in memory and never stored, logged or shown. A finding
     carries the path, size, SHA-256 and the rule.
  2. Bounded: files per pass, bytes per file, bytes per pass and seconds per pass
     are capped, newest files first; a pass that hit a cap says so.
  3. No lost visibility: a match stays reported while the file is unchanged; a
     rule file that does not validate is reported, never read as "no rules".
  4. Content is not authority: severity is capped below critical, findings carry
     the community-rule mark (never acted on automatically) and name the author.

Limits, stated: only the listed folders, to a fixed depth; only complete files up to
MAX_FILE_BYTES; files the account cannot read are not checked; a file
that changes between two passes is seen at the next pass only; packed or encrypted
content may evade the literal subset; rules below the confidence bar and
rules needing a YARA engine are not used (yara_compile.py counts them).
"""

import glob
import hashlib
import json
import os
import stat
import time

from jarvis.collectors import webroots
from jarvis.core import collection, patterns
from jarvis.core.finding import finding as _finding

META = "content_scan_v1"
MAX_FILES = 3000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 96 * 1024 * 1024
MAX_SECONDS = 45.0
MAX_DEPTH = 4
MAX_REMEMBERED = 20000
MAX_ENTRIES = 12000
MIN_SIZE = 16
WHERE = "file content"
# Places files are dropped into or served from. Globs are expanded at run time.
LINUX_ROOTS = ("/tmp", "/var/tmp", "/dev/shm", "/home/*/Downloads", "/root/Downloads")
WINDOWS_ROOTS = ("/mnt/c/Users/*/Downloads", "/mnt/c/Users/*/AppData/Local/Temp",
                 "/mnt/c/Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
                 "/mnt/c/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup")
SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".cache", "site-packages"})


def roots(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        out += list(LINUX_ROOTS) + list(webroots.COMMON_ROOTS) + sorted(webroots.roots_from_config())
    if "win" in hosts:
        out += list(WINDOWS_ROOTS)
    found = []
    for pattern in out:
        for path in sorted(glob.glob(pattern)) if any(c in pattern for c in "*?[") else [pattern]:
            if path not in found and os.path.isdir(path) and not os.path.islink(path):
                found.append(path)
    return found


def identity(st):
    return [st.st_dev, st.st_ino, st.st_ctime_ns, st.st_mtime_ns, st.st_size]


def open_safe(path, directory=False):
    """Anchor every component to an opened, non-link directory descriptor."""
    parts = os.path.abspath(path).split(os.sep)
    fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(parts):
            if not part:
                continue
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(parts) - 1 or directory:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def candidates(root_dirs, limit=MAX_ENTRIES, clock=time.monotonic, started=None):
    """Bound discovery, including directories and nonregular entries.

    Return candidates, whether discovery stopped early, and unreadable directories.
    Sort the discovered subset only; coverage beyond it remains unknown.
    """
    started = clock() if started is None else started
    out, pending, visited, unread = [], list(root_dirs), 0, 0
    while pending:
        path = pending.pop()
        if visited >= limit or clock() - started >= MAX_SECONDS:
            return sorted(out, reverse=True), True, unread
        visited += 1
        try:
            fd = open_safe(path, directory=True)
        except OSError:
            unread += 1
            continue
        try:
            with os.scandir(fd) as entries:
                for entry in entries:
                    if visited >= limit or clock() - started >= MAX_SECONDS:
                        return sorted(out, reverse=True), True, unread
                    visited += 1
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        unread += 1
                        continue
                    child = os.path.join(path, entry.name)
                    if stat.S_ISDIR(st.st_mode) and entry.name not in SKIP_DIRS:
                        depth = min((os.path.relpath(child, r).count(os.sep)
                                     for r in root_dirs if child.startswith(r.rstrip(os.sep) + os.sep)),
                                    default=MAX_DEPTH)
                        if depth < MAX_DEPTH:
                            pending.append(child)
                    elif stat.S_ISREG(st.st_mode) and st.st_size >= MIN_SIZE:
                        out.append((st.st_mtime_ns, st.st_size, child, identity(st)))
        except OSError:
            unread += 1
        finally:
            os.close(fd)
    return sorted(out, reverse=True), False, unread


def read_start(path, limit=MAX_FILE_BYTES, expected=None):
    """Read a stable regular file without traversing links; races return unknown."""
    try:
        fd = open_safe(path)
    except OSError:
        return None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or (expected is not None and identity(before) != expected):
            return None
        chunks, left = [], limit
        while left > 0:
            chunk = os.read(fd, min(left, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        if identity(os.fstat(fd)) != identity(before):
            return None
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def _load(store):
    try:
        seen = json.loads(store.get_meta(META, "") or "{}")
    except (TypeError, ValueError):
        seen = {}
    return seen if isinstance(seen, dict) else {}


def _describe(path, entry, by_id):
    """A finding for one file from its remembered matches, or None if no rule is left."""
    hits = [by_id[r] for r in entry.get("rules", ()) if r in by_id]
    if not hits:
        return None
    worst = "high" if any(r.severity == "high" for r in hits) else "medium"
    first = max(hits, key=lambda r: r.score)
    more = f" It also matches {len(hits) - 1} more rule(s)." if len(hits) > 1 else ""
    f = _finding(
        "file content", worst, f"{first.title[:140]} (community rule)",
        f"{path} ({entry.get('size', '?')} bytes, SHA-256 {entry.get('sha', '?')}) matches a community rule "
        f"for known malicious or attack-tool content.{more} The file's content is not shown. Whether it "
        f"belongs there is for you to confirm. {patterns.attribution(first)}.", path)
    f["origin"] = "yara"
    return f


def audit(store, hosts=("wsl", "win"), root_dirs=None, clock=time.monotonic):
    rules, _source, error = patterns.load()
    if error:
        collection.failed("content", error[:160])
        f = _finding("visibility", "medium", "File-content rules could not be loaded",
                     f"{error}. No file content was checked this pass. Reinstalling the program restores "
                     "the rule file.", WHERE)
        return [f]
    if not rules:
        collection.failed("content", "file-content rule set is missing or empty")
        return [_finding("visibility", "medium", "File-content rules are missing",
                         "No file content was checked. Restore the shipped rule data.", WHERE)]
    generation = hashlib.sha256(json.dumps([
        (r.id, r.title, r.author, r.score, r.strings, r.condition)
        for r in rules], sort_keys=True, default=repr).encode()).hexdigest()
    by_id = {r.id: r for r in rules}
    seen = _load(store)
    started = clock()
    scan_roots = roots(hosts) if root_dirs is None else root_dirs
    if not scan_roots:
        collection.failed("content", "no accessible file-content scan roots")
        return [_finding("visibility", "low", "No file-content scan folders were accessible",
                         "No content was checked; configured drop folders were absent or inaccessible.", WHERE)]
    files, discovery_cut, unread = candidates(scan_roots,
                                             clock=clock, started=started)
    out, fresh, read_bytes, checked, left, oversized = [], {}, 0, 0, 0, 0
    for index, (mtime_ns, size, path, ident) in enumerate(files):
        if checked >= MAX_FILES or read_bytes >= MAX_TOTAL_BYTES or clock() - started >= MAX_SECONDS:
            left = len(files) - index
            break
        known = seen.get(path)
        if isinstance(known, dict) and known.get("identity") == ident and known.get("generation") == generation:
            fresh[path] = known
            continue
        if size > MAX_FILE_BYTES:
            oversized += 1
            continue
        if size > MAX_TOTAL_BYTES - read_bytes:
            left = len(files) - index
            break
        data = read_start(path, limit=size + 1, expected=ident)
        if data is None or len(data) != size:
            unread += 1
            continue
        checked += 1
        read_bytes += len(data)
        hits = patterns.match(rules, data, size)
        entry = {"m": mtime_ns, "size": size, "identity": ident, "generation": generation}
        if hits:
            entry["rules"] = [r.id for r in hits][:8]
            entry["sha"] = hashlib.sha256(data).hexdigest()
        fresh[path] = entry
    # Retain prior matches when discovery or refresh could not reach them.
    discovered = {row[2] for row in files}
    for path, entry in seen.items():
        if (path not in fresh and isinstance(entry, dict) and entry.get("rules")
                and (discovery_cut or path in discovered)):
            fresh[path] = dict(entry, stale=True)
    for path, entry in fresh.items():
        if entry.get("rules"):
            f = _describe(path, entry, by_id)
            if f:
                if entry.get("stale"):
                    f["detail"] += " Previous match; this pass could not refresh its evidence."
                out.append(f)
    if left or discovery_cut or oversized or unread:
        out.append(_finding(
            "visibility", "low", "File-content check did not finish this pass",
            f"Discovery incomplete: {discovery_cut}; deferred files: {left}; oversized files: {oversized}; "
            f"unreadable or changed entries: {unread}. Limits: {MAX_ENTRIES} discovered entries, "
            f"{MAX_FILES} reads, {MAX_TOTAL_BYTES} bytes and {int(MAX_SECONDS)} seconds. "
            "Only complete stable files up to the per-file limit are evaluated. "
            "Coverage outside the discovered subset remains unknown.", WHERE))
    if len(fresh) > MAX_REMEMBERED:
        keep = sorted(fresh.items(), key=lambda kv: (bool(kv[1].get("rules")), kv[1].get("m", 0)), reverse=True)
        fresh = dict(keep[:MAX_REMEMBERED])
    store.set_meta(META, json.dumps(fresh, sort_keys=True))
    if left or discovery_cut or oversized or unread:
        collection.failed("content", "file-content coverage incomplete; see visibility finding")
    else:
        collection.succeeded("content")
    return out
