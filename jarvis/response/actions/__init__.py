"""Reversible actions JARVIS can take against a threat, and the ladder base.

Importing the package registers every action, so decision code can just call
`base.registry()`.
"""

from . import block_network, disable_autostart, quarantine, suspend  # noqa: F401  (registration)
from .base import APPROVE, AUTO, Action, get, register, registry

__all__ = ["Action", "AUTO", "APPROVE", "register", "registry", "get"]
