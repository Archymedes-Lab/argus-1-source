"""Independent views of the process list, so one can be lied to and
disagree with the others."""

import ctypes
import ctypes.util
import errno
import os
import re
import struct
from .common import DEFAULT_SWEEP, PROC, _read


SYS_getdents64 = {"x86_64": 217, "aarch64": 61, "armv7l": 217, "i686": 220}

_SCHED_ROW = re.compile(r"^\s*[RS>]?\s+(\S+)\s+(\d+)\s+\d")


def view_readdir():
    try:
        return {int(e) for e in os.listdir(PROC) if e.isdigit()}
    except OSError:
        return set()


def view_getdents():
    """List /proc through the syscall directly, so an LD_PRELOAD hook on
    readdir cannot filter the result."""
    nr = SYS_getdents64.get(os.uname().machine)
    if nr is None:
        return None  # unknown ABI; caller treats None as "view unavailable"
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    except OSError:
        return None

    fd = os.open(PROC, os.O_RDONLY | os.O_DIRECTORY)
    pids = set()
    buf = ctypes.create_string_buffer(65536)
    try:
        while True:
            n = libc.syscall(nr, ctypes.c_int(fd), buf, ctypes.c_uint(len(buf)))
            if n <= 0:
                break
            off = 0
            raw = buf.raw
            while off < n:
                # struct linux_dirent64 { u64 d_ino; s64 d_off; u16 d_reclen;
                #                         u8 d_type; char d_name[]; }
                reclen = struct.unpack_from("H", raw, off + 16)[0]
                if reclen == 0:
                    break
                name = raw[off + 19 : off + reclen].split(b"\x00", 1)[0]
                if name.isdigit():
                    pids.add(int(name))
                off += reclen
    except OSError:
        return None
    finally:
        os.close(fd)
    return pids


def view_stat_sweep(limit=DEFAULT_SWEEP):
    """A pid whose directory entry is filtered from listings usually still
    resolves when you stat the path directly."""
    found = set()
    for pid in range(1, limit + 1):
        try:
            os.stat(f"{PROC}/{pid}")
        except OSError as e:
            if e.errno in (errno.ENOENT, errno.ESRCH, errno.EACCES, errno.EPERM):
                continue
            continue
        found.add(pid)
    return found


def view_kill_probe(limit=DEFAULT_SWEEP):
    """Ask the kernel whether a pid exists by trying to signal it.

    Every view above this one goes through procfs, so a rootkit that filters
    procfs defeats all of them at once. kill(pid, 0) delivers nothing but
    resolves the pid through the kernel's pid hash table instead, which is a
    different structure reached by a different path. ESRCH means no such
    process; success or EPERM both mean it is there.
    """
    found = set()
    for pid in range(1, limit + 1):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        except PermissionError:
            found.add(pid)          # exists, owned by someone else
            continue
        except OSError:
            continue
        found.add(pid)
    return found


def view_sched_debug():
    """Read pids out of /proc/sched_debug.

    The scheduler prints every task on every runqueue. It is generated from the
    runqueues rather than from the procfs directory tree, so a rootkit that
    hides a /proc/<pid> entry has to remember to scrub this too, and most do
    not. Returns None when the kernel was built without CONFIG_SCHED_DEBUG,
    which is a missing view rather than a clean one.
    """
    text = _read(f"{PROC}/sched_debug")
    if not text.strip():
        return None
    pids = set()
    for line in text.splitlines():
        m = _SCHED_ROW.match(line)
        if m:
            try:
                pids.add(int(m.group(2)))
            except ValueError:
                continue
    return pids or None


def pid_max():
    try:
        with open(f"{PROC}/sys/kernel/pid_max", errors="replace") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return DEFAULT_SWEEP


def _describe(pid):
    """Whatever we can learn about a pid the listings did not want to show."""
    info = {"pid": pid, "name": "?", "exe": "", "cmdline": "", "ppid": 0,
            "uid": "?", "tgid": pid}
    try:
        with open(f"{PROC}/{pid}/status", errors="replace") as fh:
            for line in fh:
                if line.startswith("Name:"):
                    info["name"] = line.split("\t", 1)[-1].strip()
                elif line.startswith("PPid:"):
                    info["ppid"] = int(line.split()[1])
                elif line.startswith("Uid:"):
                    info["uid"] = line.split()[1]
                elif line.startswith("Tgid:"):
                    info["tgid"] = int(line.split()[1])
    except OSError:
        pass
    try:
        info["exe"] = os.readlink(f"{PROC}/{pid}/exe")
    except OSError:
        pass
    try:
        with open(f"{PROC}/{pid}/cmdline", "rb") as fh:
            info["cmdline"] = " ".join(
                a.decode("utf-8", "replace") for a in fh.read().split(b"\x00") if a
            )
    except OSError:
        pass
    return info


def _alive(pid):
    try:
        os.stat(f"{PROC}/{pid}")
        return True
    except OSError:
        return False


def is_thread(pid):
    """/proc/<tid> stats successfully for every thread, but readdir only lists
    thread-group leaders. A thread showing up in the stat sweep and not in the
    listing is how Linux is supposed to work, not something hiding."""
    try:
        with open(f"{PROC}/{pid}/status", errors="replace") as fh:
            for line in fh:
                if line.startswith("Tgid:"):
                    return int(line.split()[1]) != pid
    except OSError:
        pass
    return False
