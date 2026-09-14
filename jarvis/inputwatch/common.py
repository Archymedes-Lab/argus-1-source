"""Constants shared by more than one part of inputwatch."""

import hashlib
import os


HEARTBEAT_S = 60

# The helper ships in jarvis/win/. This module sits one level deeper, in
# jarvis/inputwatch/, so the package root is the *parent* of this directory.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HOOK_PS1 = os.path.join(_PKG_ROOT, "win", "inputhook.ps1")

READ_CAP = 8 * 1024 * 1024   # bytes of helper output read per pass; a runaway

_M_DUPES = "input_hook_dupe_pids"       # "<local ts>:<pid,pid>" seen this drain

_M_OVERSIZE = "input_hook_oversized_at"  # local ts the output file blew READ_CAP


def _finding(category, severity, title, detail, where="", host="win"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def _sha256(path):
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return ""


def _mget_int(store, key, default=0):
    try:
        return int(store.get_meta(key, default) or default)
    except (TypeError, ValueError):
        return default
