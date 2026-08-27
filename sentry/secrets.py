"""Credentials sitting in plaintext on this disk.

This closes `T1552` (unsecured credentials), which current intel raises in
twenty-one separate writeups. It matters more here than the technique ranking
suggests: this machine's own posture audit confirmed the system drive is **not
encrypted**, so every secret found by this module is readable by anyone who can
take the disk out, and by any process running as this user.

The rule that shapes everything below: **a scanner that finds secrets must not
become a place where secrets are kept.** Nothing here stores, logs or prints a
credential. A finding carries the file, the line, what kind of credential it
looks like, and a truncated SHA-256 fingerprint — enough to identify the same
secret across two files or confirm you rotated it, useless to anyone who reads
the report. That is the same reasoning that keeps key values out of
`inputwatch`, and it is the reason no `--show` flag exists.

Three kinds of finding, in descending order of how much they should worry you:

  reachable   a credential in a file other users or the world can read
  tracked     a credential in a file git is tracking, or in a repo with a
              remote — the disk is one thing, a push is another
  present     a credential in plaintext, correctly permissioned

High-entropy strings are checked for entropy rather than pattern alone, because
a config key called `api_key = "changeme"` is not a leak and `AKIA...` is.
"""

import hashlib
import math
import os
import re
import stat
import subprocess

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CAT_ORDER = {"reachable": 0, "tracked": 1, "present": 2, "visibility": 3}

# Directories that hold other people's code, build output, or caches. Scanning
# them finds thousands of test fixtures and no real secrets.
SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", "dist", "build", "target", ".next", ".nuxt", ".cache",
    ".gradle", ".m2", ".cargo", ".rustup", ".npm", ".pnpm-store", ".yarn",
    "vendor", "site-packages", ".tox", ".terraform", "Pods", ".idea",
    ".vscode-server", ".cursor-server", ".antigravity-server", "snap",
    ".local/share/Trash", "AppData", "Windows", "Program Files",
}

# Path fragments that mean "this file is a cache, a vendored dependency, or
# someone else's source". The first live run drowned six real credentials —
# an OAuth token, a Cursor auth file, a project .env — under hundreds of hits
# inside WebKit caches and package stores. A scanner nobody reads because it
# cries wolf is worse than no scanner.
SKIP_PATH_PARTS = (
    "webkitcache", "/cache/", "gpucache", "code cache", "blob_storage",
    "indexeddb", "service worker", "local storage", "session storage",
    "/pkg/mod/", "/pnpm/store/", "/share/uv/", "-server/bin/", "/.git/",
    "/dist/", "/coverage/", "/.next/", "/testdata/", "/fixtures/",
    "/node_modules/", "/site-packages/", "/.trash/", "/logs/",
    # AI tool working state: conversation caches, file-history snapshots and
    # plugin sources. These mirror content that already exists elsewhere, so
    # reporting them doubles every finding and points at a path the user
    # cannot act on.
    "/.claude/file-history/", "/.claude/todos/", "/.claude/projects/",
    "/.codex/.tmp/", "/.codex/sessions/", "/.cursor/projects/",
    "/.gemini/tmp/", "/.antigravity", "/.aider", "/.continue/sessions/",
)

# Files whose entire purpose is to show the *shape* of a credential.
EXAMPLE_FILES = re.compile(
    r"(\.env\.(example|sample|template|dist)$|\.example$|\.sample$|"
    r"(^|/)(example|sample|template)[._-]|_test\.|\.test\.|\.spec\.)", re.I)

SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf",
    ".zip", ".gz", ".tar", ".xz", ".7z", ".rar", ".jar", ".war",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav", ".ttf", ".woff",
    ".woff2", ".eot", ".so", ".dll", ".dylib", ".exe", ".bin", ".o",
    ".pyc", ".pyo", ".class", ".wasm", ".db", ".sqlite", ".sqlite3",
    ".lock", ".map", ".min.js", ".pack",
}

# (name, regex, severity floor). Ordered most-specific first: a match on a
# vendor-prefixed token is a fact, while a generic assignment is a guess.
PATTERNS = [
    ("AWS access key id", re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), "critical"),
    ("GitHub token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b"), "critical"),
    ("GitHub fine-grained token", re.compile(r"\b(github_pat_[A-Za-z0-9_]{50,})\b"), "critical"),
    ("Slack token", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b"), "critical"),
    ("Stripe live key", re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b"), "critical"),
    ("Anthropic API key", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"), "critical"),
    ("OpenAI API key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b"), "critical"),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), "high"),
    ("npm token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), "critical"),
    ("SendGrid key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), "critical"),
    ("Twilio key", re.compile(r"\b(SK[0-9a-fA-F]{32})\b"), "high"),
    ("private key block", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----)"), "critical"),
    ("JSON web token", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"), "high"),
    ("database URL with password",
     re.compile(r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]{4,}@[^\s/]+)"), "critical"),
    ("Convex deploy key", re.compile(r"\b(prod:[a-z0-9\-]+\|[A-Za-z0-9+/=]{24,})\b"), "critical"),
    # The keyword has to be allowed *inside* a longer identifier: `\bsecret\b`
    # never matches SECRET_TOKEN, because underscore is a word character, and
    # SCREAMING_SNAKE_CASE is exactly how environment files name these.
    ("generic secret assignment",
     re.compile(r"(?i)[A-Za-z0-9_\-]{0,40}?(?:api[_\-]?key|secret|token|passwd|"
                r"password|access[_\-]?key|client[_\-]?secret|auth[_\-]?token|"
                r"private[_\-]?key|credential|[_\-]key)[A-Za-z0-9_\-]{0,40}\s*[:=]\s*"
                r"[\"']?([A-Za-z0-9_\-+/=\.]{16,})[\"']?"), "medium"),
]

# Values that match the generic pattern but say nothing.
PLACEHOLDER = re.compile(
    r"^(?:changeme|placeholder|your[_\-]?\w*|example\w*|xxx+|<[^>]*>|\.{3,}|"
    r"null|none|undefined|true|false|test|dummy|sample|redacted|secret|"
    r"password|token|abcdef\w*|0+|1234\w*|process\.env\.\w+|\$\{?\w+\}?)$",
    re.I)

# Files whose whole purpose is holding a credential. Their existence is not the
# finding; their permissions and whether git can see them are.
CREDENTIAL_FILES = (
    ".npmrc", ".git-credentials", ".pypirc", ".netrc",
    ".aws/credentials", ".config/gh/hosts.yml", ".docker/config.json",
    ".kube/config", ".config/gcloud/credentials.db",
)


def _finding(category, severity, title, detail, where="", host="wsl"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def _entropy(s):
    """Shannon entropy per character. Real keys are near-random; words are not."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def fingerprint(secret):
    """A stable, non-reversible id for a credential.

    Enough to notice the same key in two files, or to confirm a rotation
    happened. Not enough to be a leak in its own right — which matters,
    because this report is itself written to disk.
    """
    return hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:12]


def _mask(secret):
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * 8}{secret[-2:]}"


def _looks_real(name, value):
    if PLACEHOLDER.match(value.strip()):
        return False
    if name == "generic secret assignment":
        # Only trust the generic pattern when the value looks random.
        if len(value) < 20 or _entropy(value) < 3.6:
            return False
        if re.match(r"^[A-Za-z]+$", value):      # a word, however long
            return False
    return True


def _other_humans():
    """Real login accounts other than this one.

    "Readable by other accounts" is only a finding if other accounts exist.
    WSL's default umask writes 0644, so on a single-user machine that
    condition is true for essentially every file — the first run escalated
    200 findings to critical on exactly this mistake. Where nobody else can
    log in, permissions are not the control that matters; the unencrypted
    disk is.
    """
    import pwd
    me = os.getuid()
    try:
        return [p.pw_name for p in pwd.getpwall()
                if p.pw_uid >= 1000 and p.pw_uid != me
                and p.pw_shell and "nologin" not in p.pw_shell
                and "false" not in p.pw_shell]
    except Exception:
        return []


def _world_readable(path):
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IRGRP | stat.S_IROTH))


# Two git subprocesses per finding is fine for ten findings and unusable for a
# few hundred — the first full run had not finished after ten minutes. The
# remote lookup is per repository, not per file, so it is cached.
_repo_cache = {}


def _repo_of(directory):
    """(repo_root, origin_url) for a directory, or (None, "")."""
    if directory in _repo_cache:
        return _repo_cache[directory]
    try:
        r = subprocess.run(["git", "-C", directory, "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True, timeout=8)
        if r.returncode != 0:
            result = (None, "")
        else:
            root = r.stdout.strip()
            rem = subprocess.run(["git", "-C", root, "remote", "get-url", "origin"],
                                 capture_output=True, text=True, timeout=8)
            result = (root, rem.stdout.strip() if rem.returncode == 0 else "")
    except (OSError, subprocess.SubprocessError):
        result = (None, "")
    _repo_cache[directory] = result
    return result


def _git_tracked(path):
    """Is this file tracked by git, and does its repo have a remote?"""
    d = os.path.dirname(path) or "."
    root, remote = _repo_of(d)
    if not root:
        return False, ""
    try:
        r = subprocess.run(["git", "-C", root, "ls-files", "--error-unmatch",
                            "--", path], capture_output=True, text=True, timeout=8)
        return (r.returncode == 0), remote
    except (OSError, subprocess.SubprocessError):
        return False, ""


def scan_file(path, max_bytes=2 * 1024 * 1024):
    """Return [(kind, secret, lineno, severity)] without keeping any of it."""
    out = []
    try:
        if os.path.getsize(path) > max_bytes:
            return out
        with open(path, "r", errors="strict") as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError, ValueError):
        return out          # binary or unreadable: not our business

    for lineno, line in enumerate(text.splitlines(), 1):
        # Long lines are minified bundles and base64 blobs — no human puts a
        # credential there, and they are exactly where an unbounded regex goes
        # quadratic. The first full scan never finished; this cap is why it now
        # takes seconds.
        if len(line) > 800:
            continue
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "*", "<!--")) and "BEGIN" not in line:
            continue
        for name, rx, sev in PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            value = m.group(1)
            if not _looks_real(name, value):
                continue
            out.append((name, value, lineno, sev))
            break               # one finding per line is enough
    return out


def walk(roots, max_files=60000):
    seen = 0
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames
                           if d not in SKIP_DIRS and not d.startswith(".cache")]
            low_dir = dirpath.lower()
            if any(part in low_dir for part in SKIP_PATH_PARTS):
                dirnames[:] = []
                continue
            for fn in filenames:
                seen += 1
                if seen > max_files:
                    return
                ext = os.path.splitext(fn)[1].lower()
                if ext in SKIP_EXT:
                    continue
                yield os.path.join(dirpath, fn)


def default_roots():
    """Where credentials actually live.

    Scanning all of $HOME sounds thorough and is mostly theatre: the first
    attempt spent fifteen minutes inside dependency trees and package caches
    without finishing, and the real findings it had already surfaced were all
    in config directories and project checkouts. So the default is the places
    a credential is plausibly stored — tool config, documents, and the top
    level of each git repository — and `--deep` is there for the rare case
    where the whole tree really is wanted.
    """
    home = os.path.expanduser("~")
    roots = []
    for rel in (".config", ".aws", ".azure", ".docker", ".kube", ".gemini",
                ".fly", ".ssh", ".gnupg", ".claude", ".codex", ".cursor",
                ".convex", ".nova", ".vscode", "Documents", "Desktop",
                "Downloads"):
        p = os.path.join(home, rel)
        if os.path.isdir(p):
            roots.append(p)

    # Git checkouts near the top of home: that is where .env files live.
    try:
        for name in sorted(os.listdir(home)):
            p = os.path.join(home, name)
            if not os.path.isdir(p) or name in SKIP_DIRS:
                continue
            if os.path.isdir(os.path.join(p, ".git")):
                roots.append(p)
    except OSError:
        pass
    return roots


# Files that are worth reading individually even though scanning their parent
# directory would be far too broad.
LOOSE_FILES = (".bash_history", ".zsh_history", ".npmrc", ".netrc",
               ".pypirc", ".git-credentials", ".env", ".env.local",
               ".my.cnf", ".pgpass", ".rediscli_history", ".psql_history")


def audit(roots=None, hosts=("wsl",), deep=False):
    home = os.path.expanduser("~")
    if roots:
        roots = list(roots)
    elif deep:
        roots = [home]
    else:
        roots = default_roots()
    out = []
    found = {}          # fingerprint -> list of (path, kind, line)
    scanned = 0

    targets = list(walk(roots))
    if not deep:
        for rel in LOOSE_FILES:
            p = os.path.join(home, rel)
            if os.path.isfile(p):
                targets.append(p)

    others = _other_humans()

    for path in targets:
        scanned += 1
        if EXAMPLE_FILES.search(os.path.basename(path)):
            continue        # a file that exists to show the shape of a secret
        for kind, secret, lineno, sev in scan_file(path):
            fp = fingerprint(secret)
            found.setdefault(fp, {"kind": kind, "sev": sev,
                                  "mask": _mask(secret), "hits": []})
            found[fp]["hits"].append((path, lineno))

    for fp, info in found.items():
        paths = info["hits"]
        first_path, first_line = paths[0]
        reachable = [p for p, _ in paths if _world_readable(p)]
        tracked = []
        for p, _ in paths:
            is_tracked, remote = _git_tracked(p)
            if is_tracked:
                tracked.append((p, remote))

        sev = info["sev"]
        cat = "present"
        extra = ""
        if tracked:
            cat = "tracked"
            sev = "critical"
            remote = next((r for _, r in tracked if r), "")
            extra = (f"  git is tracking this file"
                     + (f" and its remote is {remote}" if remote else "")
                     + " — the credential is one push from being published")
        elif reachable and others:
            cat = "reachable"
            sev = "critical" if sev in ("critical", "high") else "high"
            extra = ("  the file is readable by other accounts on this system ("
                     + ", ".join(others[:3]) + ")")

        where = f"{first_path}:{first_line}"
        more = (f" (+{len(paths) - 1} more location"
                f"{'s' if len(paths) > 2 else ''})" if len(paths) > 1 else "")
        out.append(_finding(
            cat, sev, f"{info['kind']} in plaintext{more}",
            f"{info['mask']}  fingerprint {fp} — this disk is not encrypted, so "
            f"anyone with physical access can read it.{extra}",
            where))

    for rel in CREDENTIAL_FILES:
        p = os.path.join(home, rel)
        if not os.path.exists(p):
            continue
        if _world_readable(p):
            try:
                mode = oct(os.stat(p).st_mode & 0o777)
            except OSError:
                mode = "?"
            out.append(_finding(
                "reachable", "high",
                f"credential file is readable by others: {rel}",
                f"mode {mode} — this file exists to hold a credential, so its "
                f"permissions are the only thing protecting it",
                p))

    out.append(_finding(
        "visibility", "ok", f"scanned {scanned} files for credentials",
        f"{len(found)} distinct secret{'s' if len(found) != 1 else ''} found. "
        f"Values are never stored or printed — only a masked preview and a "
        f"truncated fingerprint, so this report is not itself a leak.",
        ", ".join(roots)))
    return sort_findings(out)


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9), x["title"]))
