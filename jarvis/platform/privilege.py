"""Least-privilege Linux visibility: the capabilities JARVIS reads with.

The daemon runs as the user. Seeing other accounts' processes needs more than
that, but not root: the systemd drop-in systemd/capabilities.conf grants only

  CAP_SYS_PTRACE       /proc/<pid>/{fd,maps,environ,exe} of other accounts
  CAP_DAC_READ_SEARCH  root-only files such as /sys/kernel/tracing
  CAP_SYSLOG           kernel addresses in /proc/kallsyms and /proc/modules

Listing eBPF objects needs CAP_SYS_ADMIN and reading netfilter rules needs
CAP_NET_ADMIN. Both are close to full root, so they are deliberately not
requested, and coverage reports that as a stated limit.

systemd delivers the grant as ambient capabilities, which every exec'd child
would inherit. `drop_ambient()` clears them once, before any thread starts,
so the daemon's own threads keep reading while nothing it launches (model
tooling, tests, PowerShell, sudo) gains a capability from it.
"""

import ctypes
import os

CAPS = {"CAP_DAC_READ_SEARCH": 2, "CAP_SYS_PTRACE": 19, "CAP_SYSLOG": 34}
NOT_REQUESTED = ("CAP_SYS_ADMIN (eBPF enumeration)", "CAP_NET_ADMIN (netfilter rules)")

PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4


def effective(status_path="/proc/thread-self/status"):
    """This thread's effective capability mask, or 0 when unreadable."""
    try:
        with open(status_path, errors="replace") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    return int(line.split()[1], 16)
    except (OSError, ValueError, IndexError):
        pass
    return 0


def missing(mask=None):
    """Names of the visibility capabilities this thread does not hold."""
    if os.geteuid() == 0:
        return []
    mask = effective() if mask is None else mask
    return [name for name, bit in CAPS.items() if not mask >> bit & 1]


def can_read_other_processes(mask=None):
    return "CAP_SYS_PTRACE" not in missing(mask)


def drop_ambient():
    """Stop exec'd children inheriting the grant. True when the ambient set
    is empty afterwards (including when there was nothing to clear)."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    except (OSError, AttributeError):
        pass
    try:
        with open("/proc/thread-self/status", errors="replace") as fh:
            for line in fh:
                if line.startswith("CapAmb:"):
                    return int(line.split()[1], 16) == 0
    except (OSError, ValueError, IndexError):
        pass
    return False
