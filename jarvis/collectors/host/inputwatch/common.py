"""Constants shared by more than one part of inputwatch."""

import hashlib

from jarvis.core.paths import win_script

HEARTBEAT_S = 60

HOOK_PS1 = str(win_script("inputhook.ps1"))

READ_CAP = 8 * 1024 * 1024   # bytes of helper output read per pass; a runaway

_M_DUPES = "input_hook_dupe_pids"       # "<local ts>:<pid,pid>" seen this drain

_M_OVERSIZE = "input_hook_oversized_at"  # local ts the output file blew READ_CAP

_M_SESSION = "input_hook_session"   # "<helper session>:<desktop session>" from the newest beat


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
