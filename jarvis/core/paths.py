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

# PowerShell payloads run through the Windows bridge.
WIN_SCRIPTS_DIR = PACKAGE_DIR / "platform" / "win"
# The dashboard page and its assets.
STATIC_DIR = PACKAGE_DIR / "web" / "static"


def win_script(name):
    """Path of a bundled PowerShell payload."""
    return WIN_SCRIPTS_DIR / name


def repo_file(name):
    """Path of an operator script shipped at the repository level."""
    return REPO_ROOT / name
