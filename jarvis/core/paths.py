"""Every on-disk location jarvis ships or reads relative to its own code.

Paths built from a module's `__file__` hard-code how deep that module sits, and
break silently when it moves: splitting inputwatch into a package once pointed
the input hook at a directory that did not exist, and nothing noticed but the
supervisor. Resolving them here, from one fixed anchor, means a module can move
without its data files moving out from under it.
"""

import os
import sys
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
# The owner's settings file. response/alert.py reads it for delivery; lower
# layers that need one setting read it here instead of importing upward.
CONFIG_PATH = os.path.expanduser("~/.jarvis/config.json")


def self_executable():
    """The program file to start when Argus runs a copy of itself (`-m module`).

    `sys.executable` is wrong in a compiled Windows build: Nuitka's standalone
    mode reports a python.exe in the install folder that does not exist, so
    every collector worker failed with FileNotFoundError and its job showed as
    broken (found 2026-11-03 by running the compiled program; Linux reports
    the binary correctly). When `sys.executable` does not exist, ask Windows
    for the path of the running program.
    """
    exe = sys.executable
    if exe and os.path.exists(exe):
        return exe
    if sys.platform.startswith("win"):
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(32768)
            if ctypes.windll.kernel32.GetModuleFileNameW(None, buf, len(buf)) and os.path.exists(buf.value):
                return buf.value
        except (AttributeError, OSError):
            pass
    return exe


def win_script(name):
    """Path of a bundled PowerShell payload."""
    return WIN_SCRIPTS_DIR / name


def _embedded_payloads():
    """The payloads compiled into a release build, or {} in a source checkout.

    A release ships no .ps1 files (the content policy forbids them), so the
    build generates jarvis/core/win_payloads.py holding each payload's text and
    compiles it into the program. Looked up lazily so a source tree, which has
    no such module, reads the files as before.
    """
    try:
        from jarvis.core import win_payloads
    except ImportError:
        return {}
    return getattr(win_payloads, "PAYLOADS", {})


def load_win_script(name):
    """Text of a bundled PowerShell payload, byte for byte.

    newline="" disables newline translation, so the script reaches PowerShell
    (and any str.replace templating) exactly as it is stored. Payloads load at
    import time, so a damaged byte is replaced rather than raised: one broken
    script then shows up as that collector's "unavailable" finding instead of
    stopping the daemon and every other collector with it.
    """
    embedded = _embedded_payloads().get(name)
    if embedded is not None:
        return embedded
    try:
        with open(win_script(name), encoding="utf-8", errors="replace", newline="") as fh:
            return fh.read()
    except FileNotFoundError:
        # The Linux server edition ships no Windows payloads. A payload that
        # throws keeps the absence explicit: a collector that ever ran it would
        # report itself unavailable, never an empty clean result.
        return f'throw "{name} is not part of this edition"\n'


def repo_file(name):
    """Path of an operator script shipped at the repository level."""
    return REPO_ROOT / name
