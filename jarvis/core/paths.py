"""Every on-disk location jarvis ships or reads relative to its own code.

Paths built from a module's `__file__` hard-code how deep that module sits, and
break silently when it moves: splitting inputwatch into a package once pointed
the input hook at a directory that did not exist, and nothing noticed but the
supervisor. Resolving them here, from one fixed anchor, means a module can move
without its data files moving out from under it.
"""

import os
from pathlib import Path

# abspath, not resolve(): the Windows task check compares against the path the
# repo was installed from, symlinks included.
PACKAGE_DIR = Path(os.path.abspath(__file__)).parent.parent   # jarvis/core/ -> jarvis/
REPO_ROOT = PACKAGE_DIR.parent

# A root-owned release (scripts/deploy_root_runtime.py) carries RELEASE.json
# naming the editable checkout it belongs to. Code runs from the release;
# anything that must act on that checkout (fix drafting, Windows tasks and the
# selfcheck unit installed from it) uses SOURCE_ROOT.
#
# "checkout" is preferred over "source": a narrow release is built from a
# temporary clone, and treating that clone as the checkout made JARVIS's own
# watchdog tasks (installed with -RepoRoot <checkout>) fail verification and
# read as critical persistence (2026-09-24, /tmp/jarvis-netwatch-narrow-*).
RELEASE_MANIFEST = REPO_ROOT / "RELEASE.json"


def _source_root():
    try:
        import json
        with open(RELEASE_MANIFEST, encoding="utf-8", errors="replace") as fh:
            manifest = json.load(fh)
        for key in ("checkout", "source"):
            value = manifest.get(key)
            if isinstance(value, str) and os.path.isabs(value):
                return Path(value)
    except (OSError, ValueError, AttributeError):
        pass
    return REPO_ROOT


SOURCE_ROOT = _source_root()

# PowerShell payloads run through the Windows bridge.
WIN_SCRIPTS_DIR = PACKAGE_DIR / "platform" / "win"
# The dashboard page and its assets.
STATIC_DIR = PACKAGE_DIR / "web" / "static"


def win_script(name):
    """Path of a bundled PowerShell payload."""
    return WIN_SCRIPTS_DIR / name


def load_win_script(name):
    """Text of a bundled PowerShell payload, byte for byte.

    newline="" disables newline translation, so the script reaches PowerShell
    (and any str.replace templating) exactly as it is stored. Payloads load at
    import time, so a damaged byte is replaced rather than raised: one broken
    script then shows up as that collector's "unavailable" finding instead of
    stopping the daemon and every other collector with it.
    """
    with open(win_script(name), encoding="utf-8", errors="replace", newline="") as fh:
        return fh.read()


def repo_file(name):
    """Path of an operator script shipped at the repository level."""
    return REPO_ROOT / name
