"""Sockets and listeners with no visible owning process."""

import errno
import os

from jarvis.platform.linux import socket_table

from .common import PROC


def orphan_sockets():
    """Socket inodes bound to a connection that no visible process holds an fd
    for. Under-privileged scans see plenty of these (you cannot read another
    user's fd table), so this is only reported when we are root."""
    table = socket_table()
    claimed = set()
    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        fddir = f"{PROC}/{entry}/fd"
        try:
            for fd in os.listdir(fddir):
                try:
                    target = os.readlink(f"{fddir}/{fd}")
                except OSError:
                    continue
                if target.startswith("socket:["):
                    claimed.add(int(target[8:-1]))
        except OSError:
            continue

    orphans = []
    for inode, conn in table.items():
        if inode in claimed or inode == 0:
            continue
        if conn["state"] in ("TIME_WAIT", "CLOSE"):
            continue  # kernel-owned leftovers, no process behind them
        orphans.append(conn)
    return orphans


def hidden_listeners(limit=10000):
    """Ports the kernel says are taken but /proc/net does not admit to.

    A rootkit that filters /proc/net/tcp still cannot make the kernel hand out a
    port that is genuinely bound. Asking to bind it and being refused with
    EADDRINUSE is only a discrepancy: TIME_WAIT sockets and connections created
    during the sweep can also reserve ports. Retain inode-zero rows and recheck.
    """
    import socket as _s

    visible = _visible_tcp_ports()
    if visible is None:
        raise RuntimeError('TCP socket tables unreadable; hidden listener check unavailable')
    found = []
    for port in range(1, limit + 1):
        if port in visible:
            continue
        sock = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        try:
            # No SO_REUSEADDR: we want an honest answer about the port.
            sock.bind(("0.0.0.0", port))
        except PermissionError:
            continue  # privileged port and we are not root; inconclusive
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                found.append(port)
            continue
        finally:
            sock.close()
    # Refresh after probing: the scan and socket table are not atomic.
    refreshed = _visible_tcp_ports()
    if refreshed is None:
        raise RuntimeError('TCP socket tables unreadable during listener recheck')
    confirmed = []
    for port in found:
        if port in refreshed:
            continue
        with _s.socket(_s.AF_INET, _s.SOCK_STREAM) as sock:
            try:
                sock.bind(('0.0.0.0', port))
            except OSError as exc:
                if exc.errno == errno.EADDRINUSE:
                    confirmed.append(port)
    return confirmed


def _visible_tcp_ports():
    # An inode-keyed dictionary collapses TIME_WAIT rows (all inode 0),
    # manufacturing hidden-port findings. Read every row instead.
    ports = set()
    for name in ('tcp', 'tcp6'):
        try:
            with open(f'{PROC}/net/{name}', errors="replace") as handle:
                for line in list(handle)[1:]:
                    fields = line.split()
                    if len(fields) >= 2:
                        ports.add(int(fields[1].rsplit(':', 1)[1], 16))
        except FileNotFoundError:
            if name == 'tcp6':
                continue
            return None
        except (OSError, ValueError, IndexError):
            return None
    return ports


def _socket_table_safe():
    try:
        return socket_table()
    except Exception:
        return {}
