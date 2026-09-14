"""Constants shared by more than one part of toolchain."""

import hashlib
import json
import os
import re

from jarvis.core.finding import finding as _finding

MAX_REPOS = 200

PAYLOAD_RE = re.compile(
    r"(curl|wget|iwr|invoke-webrequest)\b[^|;&]*\|\s*(ba|z|d|k)?sh"
    r"|base64\s+(-d|--decode)[^|]*\|\s*(ba)?sh"
    r"|python3?\s+-c\s+.{0,60}(socket|pty|urlopen|b64decode)"
    r"|(powershell|pwsh)(\.exe)?\b[^|;&]*\s-(enc|e|ec|encodedcommand)\b"
    r"|/dev/tcp/\d"
    r"|\beval\s*\("
    r"|\bnc\b\s+(-[a-z]*e|.*-e\s)",
    re.I)


def _read(path, limit=400000):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _json(path):
    """Parse a config file, tolerating the JSONC that editors actually write.

    VS Code and its forks accept comments and trailing commas in their own
    config files, so a strict parser silently reports "no MCP servers here" for
    a file that has several. Silently reporting nothing is the one outcome this
    whole module exists to prevent, so strip what the editors strip.
    """
    raw = _read(path)
    if not raw.strip():
        return None
    for attempt in (raw, _strip_jsonc(raw)):
        try:
            return json.loads(attempt)
        except (ValueError, TypeError):
            continue
    return None


def _strip_jsonc(raw):
    out, i, n = [], 0, len(raw)
    in_str = esc = False
    while i < n:
        c = raw[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
        elif c == "/" and i + 1 < n and raw[i + 1] == "/":
            while i < n and raw[i] != "\n":
                i += 1
            continue
        elif c == "/" and i + 1 < n and raw[i + 1] == "*":
            i = raw.find("*/", i + 2)
            if i < 0:
                break
            i += 2
            continue
        else:
            out.append(c)
        i += 1
    # Trailing commas, once the strings are known not to contain them.
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _hash(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _home():
    return os.path.expanduser("~")


def _short(path):
    home = _home()
    return "~" + path[len(home):] if path.startswith(home) else path


def _baseline(store, key):
    if store is None:
        return None
    try:
        return json.loads(store.get_meta(key, "") or "{}")
    except (ValueError, TypeError):
        return {}


def _save_baseline(store, key, data):
    if store is None:
        return
    try:
        store.set_meta(key, json.dumps(data))
    except Exception:
        pass


def _diff(store, meta_key, seen, category, noun, why, changed_sev="critical"):
    """Added / changed / removed against the stored baseline."""
    prev = _baseline(store, meta_key)
    out = []
    if prev is None:
        return out                     # no store: inventory only, no history
    if not prev:
        _save_baseline(store, meta_key, seen)
        if seen:
            out.append(_finding(
                category, "ok", f"{noun} baseline established",
                f"{len(seen)} recorded; from the next run onwards an addition "
                f"or a change to any of them is reported",
                "baseline"))
        return out

    added = [k for k in seen if k not in prev]
    changed = [k for k in seen if k in prev and prev[k] != seen[k]]
    removed = [k for k in prev if k not in seen]

    for k in changed:
        out.append(_finding(
            category, changed_sev, f"{noun} changed: {k}",
            f"the definition is not the one recorded on the previous run. {why}",
            k.split("::")[0]))
    for k in added:
        out.append(_finding(
            category, "high", f"new {noun}: {k}",
            "this appeared since the last run. If you did not add it, "
            "something else did — and it runs with your identity.",
            k.split("::")[0]))
    for k in removed:
        out.append(_finding(
            category, "low", f"{noun} removed: {k}",
            "no longer present; recorded so the inventory stays honest",
            k.split("::")[0]))
    _save_baseline(store, meta_key, seen)
    return out


SKIP_DIRS = {
    "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", "dist",
    "build", "target", ".next", ".nuxt", ".cache", ".gradle", ".m2", ".cargo",
    ".rustup", ".npm", ".pnpm-store", ".yarn", "vendor", "site-packages",
    ".tox", ".terraform", "Pods", "snap", "AppData", ".local",
    ".vscode-server", ".cursor-server", ".antigravity-server",
    ".windsurf-server", "Windows", "Program Files", "go",
}
_repo_cache = {}


def reset_cache():
    """Drop the per-run repository cache. Called at the top of every audit()."""
    _repo_cache.clear()


def repos(root=None, max_depth=4, limit=MAX_REPOS):
    """Git working trees under $HOME, breadth-first and bounded.

    Bounded twice on purpose. Depth stops the walk before it descends into a
    checkout of someone else's monorepo, and the count stops it before a
    machine with a thousand clones turns an hourly collector into a disk-bound
    one. Both limits are visible in the output when they bite, because a check
    that quietly stopped looking is indistinguishable from a check that looked
    and found nothing.
    """
    root = root or _home()
    key = (root, max_depth, limit)
    if key in _repo_cache:
        return _repo_cache[key]
    found, queue = [], [(root, 0)]
    truncated = False
    while queue:
        path, depth = queue.pop(0)
        if len(found) >= limit:
            truncated = True
            break
        try:
            entries = list(os.scandir(path))
        except OSError:
            continue
        names = {e.name for e in entries}
        is_repo = ".git" in names
        if is_repo:
            found.append(path)
            # Do not descend into a repo looking for more repos: submodules and
            # vendored checkouts belong to the parent's trust decision. The one
            # exception is the starting directory, because a $HOME kept under
            # git — an ordinary dotfiles setup — would otherwise end the walk
            # on its first step and leave every project below it unaudited.
            if depth > 0:
                continue
        if depth >= max_depth:
            continue
        for e in entries:
            try:
                if not e.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if e.name in SKIP_DIRS or (e.name.startswith(".") and
                                       e.name not in (".config",)):
                continue
            queue.append((e.path, depth + 1))
    _repo_cache[key] = (found, truncated)
    return found, truncated
