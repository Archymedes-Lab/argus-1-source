"""Find processes that are hiding.

Every process list you can ask for comes from *some* API, and anything with
enough privilege can lie to that API. So no single enumeration is trusted here.
Instead we collect several views that reach the kernel by different routes and
diff them against each other. A process that appears in one view and not another
is either a race (it started or exited mid-scan) or something actively hiding —
and re-verification tells those two apart.

Linux views:
  readdir   -- os.listdir("/proc"), which goes through libc; an LD_PRELOAD
               rootkit hooks this one
  getdents  -- the raw getdents64 syscall via ctypes, bypassing libc entirely
  stat      -- directly stat()ing /proc/<pid> for each pid in a range, which
               works even when the directory entry is filtered out of listings
  sockets   -- socket inodes in /proc/net/* that no visible process claims

Windows views:
  wmi       -- Win32_Process (the CIM/WMI provider)
  api       -- Get-Process (toolhelp/NtQuerySystemInformation)
  tasklist  -- tasklist.exe (a third code path again)
  netstat   -- pids owning TCP connections
Userland hooks routinely patch one of these and miss the others.
"""

import ctypes
import ctypes.util
import errno
import os
import re
import struct
import subprocess
import time

from . import collect_windows
from .control import _ps_json

PROC = "/proc"

# stat() sweep bound. Linux allows pids up to 4194304, but sweeping that many is
# slow and pointless -- hidden processes launched at boot or by a service land
# in the low range. --deep raises this to the real pid_max.
DEFAULT_SWEEP = 65536


def _finding(severity, title, detail, evidence=""):
    return {"severity": severity, "title": title, "detail": detail,
            "evidence": evidence, "host": ""}


# ---------------------------------------------------------------------------
# Linux view 1: libc readdir
# ---------------------------------------------------------------------------

def view_readdir():
    try:
        return {int(e) for e in os.listdir(PROC) if e.isdigit()}
    except OSError:
        return set()


# ---------------------------------------------------------------------------
# Linux view 2: raw getdents64 syscall, bypassing libc
# ---------------------------------------------------------------------------

SYS_getdents64 = {"x86_64": 217, "aarch64": 61, "armv7l": 217, "i686": 220}


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


# ---------------------------------------------------------------------------
# Linux view 3: direct stat() sweep
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Linux view 4: the signal path — no filesystem involved at all
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Linux view 5: the scheduler's own task list
# ---------------------------------------------------------------------------

# Task rows look like:  " R          systemd     1      6462.573889   ..."
_SCHED_ROW = re.compile(r"^\s*[RS>]?\s+(\S+)\s+(\d+)\s+\d")


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
        with open(f"{PROC}/sys/kernel/pid_max") as fh:
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


# ---------------------------------------------------------------------------
# Linux view 4: sockets with no owner
# ---------------------------------------------------------------------------

def orphan_sockets():
    """Socket inodes bound to a connection that no visible process holds an fd
    for. Under-privileged scans see plenty of these (you cannot read another
    user's fd table), so this is only reported when we are root."""
    from .collect_linux import _socket_table

    table = _socket_table()
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


# ---------------------------------------------------------------------------
# Linux view 5: bind() probing for hidden listeners
# ---------------------------------------------------------------------------

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
            with open(f'{PROC}/net/{name}') as handle:
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
    from .collect_linux import _socket_table
    try:
        return _socket_table()
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Linux view 6: kernel modules, eBPF and function hooking
# ---------------------------------------------------------------------------

def hidden_modules():
    """Modules the kernel has loaded but /proc/modules omits.

    A classic LKM rootkit unlinks itself from the module list, but the sysfs
    directory it created on load usually survives the trick.
    """
    listed = set()
    for line in _read("/proc/modules").splitlines():
        if line.split():
            listed.add(line.split()[0])

    hidden = []
    try:
        for name in os.listdir("/sys/module"):
            # Built-in modules have no initstate; only genuinely loaded ones do.
            state = _read(f"/sys/module/{name}/initstate").strip()
            if state == "live" and name not in listed:
                hidden.append(name)
    except OSError:
        pass
    return hidden


def bpf_programs():
    """Loaded eBPF programs and the processes holding eBPF file descriptors.

    eBPF is now the preferred way to build a Linux rootkit: it loads on any
    modern kernel without matching kernel headers, and it can filter what other
    tools see. Legitimate users exist (systemd, docker, observability agents),
    so this is inventory to review, not an accusation.
    """
    progs, holders = [], []

    out = _run_capture(["bpftool", "--json", "prog", "list"])
    if out:
        try:
            import json as _json
            for p in _json.loads(out):
                progs.append({
                    "id": p.get("id"), "type": p.get("type"),
                    "name": p.get("name") or "(unnamed)",
                    "tag": p.get("tag", ""), "pids": p.get("pids", []),
                })
        except Exception:
            pass

    # Even without bpftool, a process holding a bpf fd is visible in its fd table.
    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        fddir = f"{PROC}/{entry}/fd"
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue
        kinds = set()
        for fd in fds:
            try:
                target = os.readlink(f"{fddir}/{fd}")
            except OSError:
                continue
            if "bpf-prog" in target or "bpf-map" in target or "bpf_link" in target:
                kinds.add(target.split(":")[-1].strip("[]"))
        if kinds:
            holders.append({"pid": int(entry), "name": _describe(int(entry))["name"],
                            "kinds": sorted(kinds)})
    return progs, holders


# Names that eBPF rootkits give their pinned maps. A hiding rootkit has to keep
# the list of what it is hiding somewhere, and a pinned map is the usual place —
# which means the map can be read back to recover exactly what was concealed.
BPF_HIDE_MAPS = re.compile(r"hidden_(pids?|names?|inodes?|files?|ports?)|"
                           r"(pid|name|inode|port)s?_to_hide|hide_(pid|list|map)",
                           re.I)


def bpf_hidden_pins():
    """Walk /sys/fs/bpf looking for pinned objects that exist to hide things.

    This is the rare check that can do better than 'something is wrong': if a
    map named hidden_pids is present, its contents are the answer.
    """
    out, names = [], []
    root = "/sys/fs/bpf"
    if not os.path.isdir(root):
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        for n in list(dirnames) + list(filenames):
            names.append(os.path.join(dirpath, n))
    for path in names:
        base = os.path.basename(path)
        if BPF_HIDE_MAPS.search(base):
            out.append(_finding(
                "critical", "eBPF object pinned under a concealment name",
                f"{base} — an eBPF map by this name exists to hold the list of "
                f"pids, filenames or ports being hidden from you. Read it with "
                f"`sudo bpftool map dump pinned {path}` to recover what was "
                f"concealed.",
                path))
    if names and not out:
        out.append(_finding("ok", "pinned eBPF objects",
                            f"{len(names)} pinned under /sys/fs/bpf, none named "
                            f"for concealment", root))
    elif not names:
        out.append(_finding("ok", "no pinned eBPF objects",
                            "/sys/fs/bpf is empty", root))
    return out


def io_uring_state():
    """io_uring is the current way to act without making syscalls.

    It can read and write files, open sockets and spawn processes through a
    shared ring buffer, so a tool that watches syscalls sees nothing at all —
    this is the blind spot the 'Curing' proof-of-concept rootkit was written to
    demonstrate. Nothing here is evidence of compromise on its own; it is
    exposure, plus the list of who is currently using it.
    """
    out = []
    disabled = _read(f"{PROC}/sys/kernel/io_uring_disabled").strip()

    users = []
    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        fddir = f"{PROC}/{entry}/fd"
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue
        for fd in fds:
            try:
                if "io_uring" in os.readlink(f"{fddir}/{fd}"):
                    users.append(int(entry))
                    break
            except OSError:
                continue

    for pid in users:
        info = _describe(pid)
        out.append(_finding(
            "medium", "process is using io_uring",
            f"pid {pid} ({info['name']}) holds an io_uring ring — its file, "
            f"socket and process operations do not appear as syscalls. Legitimate "
            f"for databases, proxies and modern runtimes; confirm you know this one.",
            info["cmdline"] or info["exe"] or ""))

    if disabled == "0":
        out.append(_finding(
            "low", "io_uring is available to every process",
            "io_uring_disabled=0. Setting it to 2 disables io_uring entirely and "
            "closes the syscall-monitoring blind spot, at the cost of breaking "
            "software that genuinely uses it.",
            f"{PROC}/sys/kernel/io_uring_disabled"))
    elif disabled == "2":
        out.append(_finding("ok", "io_uring is disabled kernel-wide",
                            "io_uring_disabled=2 — the syscall-bypass path is shut",
                            f"{PROC}/sys/kernel/io_uring_disabled"))
    elif disabled:
        out.append(_finding("ok", "io_uring is restricted",
                            f"io_uring_disabled={disabled}",
                            f"{PROC}/sys/kernel/io_uring_disabled"))
    if not users:
        out.append(_finding("ok", "no process is using io_uring",
                            "no open io_uring ring in any visible process", ""))
    return out


def ftrace_hooks():
    """Kernel functions currently hooked via ftrace — how many rootkits patch
    syscalls without touching the syscall table itself."""
    for path in ("/sys/kernel/tracing/enabled_functions",
                 "/sys/kernel/debug/tracing/enabled_functions"):
        body = _read(path).strip()
        if body:
            return [l.split()[0] for l in body.splitlines() if l.strip()][:40]
    return []


def _run_capture(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired):
        return ""


# ---------------------------------------------------------------------------
# Linux view 7: injected and fileless code in live processes
# ---------------------------------------------------------------------------

def injected_processes():
    """Processes running code with no honest file behind it.

    Three shapes worth catching:
      LD_PRELOAD in a live environment  -- userland hooking of that process
      an executable mapping marked (deleted) -- the file was unlinked after load
      a memfd: executable mapping -- fileless execution, never touched the disk
    """
    hits = []
    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        pid = int(entry)
        reasons = []

        environ = _read(f"{PROC}/{pid}/environ", binary=True)
        if b"LD_PRELOAD=" in environ:
            val = ""
            for part in environ.split(b"\x00"):
                if part.startswith(b"LD_PRELOAD="):
                    val = part.decode("utf-8", "replace")[11:]
            if val:
                reasons.append(("LD_PRELOAD set", val))

        maps = _read(f"{PROC}/{pid}/maps")
        for line in maps.splitlines():
            if len(line.split()) < 6:
                continue
            perms, path = line.split()[1], line.split(None, 5)[5]
            if "x" not in perms:
                continue
            if path.endswith("(deleted)"):
                reasons.append(("executable mapping was deleted from disk", path))
                break
            if path.startswith("/memfd:"):
                reasons.append(("fileless executable mapping (memfd)", path))
                break

        if reasons:
            info = _describe(pid)
            hits.append({"pid": pid, "name": info["name"],
                         "cmdline": info["cmdline"] or info["exe"],
                         "reasons": reasons})
    return hits


def _read(path, binary=False):
    try:
        if binary:
            with open(path, "rb") as fh:
                return fh.read()
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except (OSError, PermissionError):
        return b"" if binary else ""


# ---------------------------------------------------------------------------
# Linux: /proc overmount hiding
# ---------------------------------------------------------------------------

def proc_overmounts():
    """A bind-mount over /proc/<pid> makes a process unreadable without any
    code injection at all."""
    hits = []
    try:
        with open("/proc/self/mountinfo", errors="replace") as fh:
            for line in fh:
                f = line.split()
                if len(f) > 4 and re.match(r"^/proc/\d+", f[4]):
                    hits.append(f[4])
    except OSError:
        pass
    return hits


def audit_linux(deep=False):
    out = []
    sweep_limit = pid_max() if deep else min(DEFAULT_SWEEP, pid_max())

    readdir = view_readdir()
    getdents = view_getdents()
    swept = view_stat_sweep(sweep_limit)
    signalled = view_kill_probe(sweep_limit)
    sched = view_sched_debug()

    # Anything the sweep can stat but the listing omitted. Re-verify, because a
    # process that simply exited between the two passes looks identical here.
    suspects = sorted(swept - readdir)
    confirmed = []
    if suspects:
        time.sleep(0.35)
        fresh = view_readdir()
        for pid in suspects:
            if _alive(pid) and pid not in fresh and not is_thread(pid):
                confirmed.append(pid)

    for pid in confirmed:
        info = _describe(pid)
        out.append(_finding(
            "critical", "process hidden from /proc listing",
            f"pid {pid} ({info['name']}) resolves by direct stat() but is absent "
            f"from readdir — {info['cmdline'] or info['exe'] or 'no cmdline'}",
            f"uid={info['uid']} ppid={info['ppid']} exe={info['exe'] or '?'}",
        ))

    if getdents is None:
        out.append(_finding("low", "syscall view unavailable",
                            "could not call getdents64 directly on this ABI; "
                            "libc-hook detection was skipped", os.uname().machine))
    else:
        # libc says fewer pids than the kernel does -> something is hooking libc.
        hooked = sorted(getdents - readdir)
        for pid in hooked:
            if _alive(pid) and not is_thread(pid):
                info = _describe(pid)
                out.append(_finding(
                    "critical", "process hidden from libc but visible to the kernel",
                    f"pid {pid} ({info['name']}) appears in raw getdents64 output "
                    f"but not through libc readdir — this is the signature of an "
                    f"LD_PRELOAD rootkit",
                    info["cmdline"] or info["exe"],
                ))

    # -- the signal path vs procfs ----------------------------------------
    # Everything above reaches the kernel through procfs, so one rootkit that
    # filters procfs defeats all of them together. kill(pid, 0) resolves through
    # the pid hash table instead, and a pid that answers a signal while having no
    # /proc entry at all is hidden below the filesystem layer.
    ghosts = sorted(signalled - readdir - swept)
    if ghosts:
        time.sleep(0.35)
        fresh_read, fresh_sig = view_readdir(), view_kill_probe(sweep_limit)
        for pid in ghosts:
            if pid in fresh_sig and pid not in fresh_read and not is_thread(pid):
                info = _describe(pid)
                out.append(_finding(
                    "critical", "pid answers signals but has no /proc entry",
                    f"pid {pid} accepts kill(pid, 0) while procfs denies it "
                    f"exists — procfs is being filtered below the point every "
                    f"other view reads from",
                    f"name={info['name'] or '?'} exe={info['exe'] or '?'}"))
    else:
        out.append(_finding("ok", "signal view agrees with /proc",
                            f"{len(signalled)} pids answer kill(pid, 0), all of "
                            f"them present in procfs", f"1–{sweep_limit}"))

    # -- the scheduler's view ---------------------------------------------
    if sched is None:
        out.append(_finding(
            "low", "scheduler view unavailable",
            "/proc/sched_debug is absent — this kernel was built without "
            "CONFIG_SCHED_DEBUG, so the runqueue cross-check was skipped",
            f"{PROC}/sched_debug"))
    else:
        missing = sorted(p for p in sched - readdir if _alive(p) and not is_thread(p))
        for pid in missing:
            info = _describe(pid)
            out.append(_finding(
                "critical", "process on a runqueue but absent from /proc",
                f"pid {pid} ({info['name']}) is scheduled by the kernel yet does "
                f"not appear in the process listing",
                info["cmdline"] or info["exe"] or ""))
        if not missing:
            out.append(_finding("ok", "scheduler view agrees with /proc",
                                f"{len(sched)} scheduled tasks, all visible",
                                f"{PROC}/sched_debug"))

    for path in proc_overmounts():
        out.append(_finding("critical", "/proc entry is bind-mounted over",
                            f"{path} is masked by a mount, hiding that process",
                            "/proc/self/mountinfo"))

    out.extend(bpf_hidden_pins())
    out.extend(io_uring_state())

    # -- hidden listeners --------------------------------------------------
    port_limit = 65535 if deep else 10000
    for port in hidden_listeners(port_limit):
        out.append(_finding(
            "high", "TCP port reservation discrepancy needs investigation",
            f"tcp/{port} refuses a bind with EADDRINUSE, yet nothing in "
            f"/proc/net claims it after a refresh; a race or hidden socket remains possible, not confirmed concealment",
            f"bind probe 1–{port_limit}"))

    # -- kernel modules ----------------------------------------------------
    for mod in hidden_modules():
        out.append(_finding(
            "critical", "kernel module hidden from /proc/modules",
            f"{mod} is live in sysfs but unlisted — the signature of an LKM "
            f"rootkit unlinking itself", f"/sys/module/{mod}"))

    # -- eBPF --------------------------------------------------------------
    progs, holders = bpf_programs()
    for p in progs:
        risky = (p.get("type") or "") in (
            "kprobe", "tracepoint", "raw_tracepoint", "lsm", "fentry", "fexit")
        out.append(_finding(
            "medium" if risky else "low", "eBPF program loaded",
            f"{p['name']} [{p.get('type')}] id={p.get('id')}"
            + (f" pids={[x.get('pid') for x in p['pids']]}" if p.get("pids") else ""),
            "bpftool prog list"))
    for h in holders:
        out.append(_finding("low", "process holds eBPF handles",
                            f"{h['name']} [pid {h['pid']}] — {', '.join(h['kinds'])}",
                            f"/proc/{h['pid']}/fd"))

    hooks = ftrace_hooks()
    if hooks:
        out.append(_finding(
            "high", "kernel functions are hooked via ftrace",
            f"{len(hooks)} hooked: {', '.join(hooks[:6])}"
            + ("…" if len(hooks) > 6 else ""),
            "/sys/kernel/tracing/enabled_functions"))

    # -- injected / fileless code -----------------------------------------
    for hit in injected_processes():
        worst = max(("fileless" in r[0]) * 2 + ("deleted" in r[0]) for r in hit["reasons"])
        out.append(_finding(
            "critical" if worst else "high",
            hit["reasons"][0][0],
            f"{hit['name']} [pid {hit['pid']}] — {hit['reasons'][0][1][:80]}",
            hit["cmdline"][:120]))

    if os.geteuid() == 0:
        for conn in orphan_sockets():
            out.append(_finding(
                "high", "network connection with no owning process",
                f"{conn['proto']} {conn['local_ip']}:{conn['local_port']} → "
                f"{conn['remote_ip']}:{conn['remote_port']} ({conn['state']}) "
                f"is not claimed by any visible process",
                "/proc/net + fd sweep",
            ))

    out.append(_finding("ok", "cross-view scan complete",
                        f"{len(readdir)} pids via readdir, "
                        f"{len(getdents) if getdents is not None else '—'} via getdents64, "
                        f"{len(swept)} via stat sweep (1–{sweep_limit})",
                        ""))
    for f in out:
        f["host"] = "wsl"
    return out


# ---------------------------------------------------------------------------
# Windows cross-view
# ---------------------------------------------------------------------------

PS_HIDDEN = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$o.wmi      = @(Get-CimInstance Win32_Process | ForEach-Object {
                  [pscustomobject]@{ pid=$_.ProcessId; name=$_.Name; path=$_.ExecutablePath } })
$o.api      = @(Get-Process | ForEach-Object {
                  [pscustomobject]@{ pid=$_.Id; name=$_.ProcessName; path=$_.Path;
                                     title=$_.MainWindowTitle } })
$o.tasklist = @((tasklist /fo csv /nh 2>$null) -split "`n" | Where-Object { $_ -match '^"' } |
                  ForEach-Object { $p = $_ -split '","'
                                   [pscustomobject]@{ name=$p[0].Trim('"'); pid=[int]($p[1]) } })
$o.netpids  = @((Get-NetTCPConnection).OwningProcess | Sort-Object -Unique)

# --- view 5: OpenProcess sweep, i.e. the PspCidTable ----------------------
# The classic way to hide a process on Windows is DKOM: unlink its EPROCESS
# from ActiveProcessLinks, which is the list every enumeration API above walks.
# The handle table (PspCidTable) is a *separate* kernel structure, and unlinking
# from one does not unlink from the other -- so a pid that opens successfully
# while appearing in none of the enumerations is the signature of that attack.
# The loop lives in C# because 16k P/Invoke calls from PowerShell would take
# minutes; Windows pids are always multiples of four, so only those are tried.
Add-Type -ErrorAction SilentlyContinue -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class PidSweep {
  const uint STILL_ACTIVE = 259;
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GetExitCodeProcess(IntPtr h, out uint code);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool QueryFullProcessImageName(IntPtr h, uint flags, StringBuilder buf, ref uint size);

  // A pid that opens is NOT necessarily a running process. When a process
  // exits, its kernel object -- and therefore its pid -- stays valid for as
  // long as anything still holds a handle to it, so OpenProcess keeps
  // succeeding on something that is already gone. Reporting those as concealed
  // processes produced ~27 false positives on an ordinary desktop. The exit
  // code is what separates the two: a live process has none yet.
  // 0 = nothing there. 1 = confirmed running. 2 = something is there but it
  // will not let us look, so we cannot tell running from already-exited.
  // Keeping 2 separate matters: ERROR_ACCESS_DENIED is returned both by
  // protected processes and by pids we have no way to qualify, and treating it
  // as proof of a concealed process is guesswork dressed up as a critical alert.
  public static int Probe(int pid) {
    IntPtr h = OpenProcess(0x1000, false, (uint)pid);
    if (h == IntPtr.Zero) {
      return Marshal.GetLastWin32Error() == 5 ? 2 : 0;
    }
    uint code;
    bool got = GetExitCodeProcess(h, out code);
    CloseHandle(h);
    if (!got) return 2;
    return code == STILL_ACTIVE ? 1 : 0;
  }

  public static bool Alive(int pid) { return Probe(pid) == 1; }

  // A concealed process still has a backing image; a dead object has none, so
  // this doubles as a second confirmation and names the binary in the report.
  public static string Image(int pid) {
    IntPtr h = OpenProcess(0x1000, false, (uint)pid);
    if (h == IntPtr.Zero) return "";
    var sb = new StringBuilder(1024); uint n = 1024;
    string s = QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString() : "";
    CloseHandle(h);
    return s;
  }

  public static int[] Live(int max) {
    var found = new List<int>();
    for (uint pid = 4; pid <= (uint)max; pid += 4) {
      if (Probe((int)pid) == 1) found.Add((int)pid);
    }
    return found.ToArray();
  }
  public static int[] Opaque(int max) {
    var found = new List<int>();
    for (uint pid = 4; pid <= (uint)max; pid += 4) {
      if (Probe((int)pid) == 2) found.Add((int)pid);
    }
    return found.ToArray();
  }
}
'@

# A sweep of 16k pids takes long enough that processes start and exit while it
# runs, and either one looks exactly like a concealed process. So the sweep is
# bracketed by two enumerations and only pids missing from BOTH survive, then
# each survivor is re-opened and re-checked against a third, fresh listing. What
# is left is a pid that was continuously openable and continuously absent, which
# no amount of ordinary process churn can produce.
$before = @{}
@(Get-CimInstance Win32_Process | ForEach-Object { $_.ProcessId }) +
  @(Get-Process | ForEach-Object { $_.Id }) | ForEach-Object { $before[[int]$_] = $true }

$sweep = @()
try { $sweep = [int[]][PidSweep]::Live(65535) } catch { $sweep = @() }

$after = @{}
@(Get-CimInstance Win32_Process | ForEach-Object { $_.ProcessId }) +
  @(Get-Process | ForEach-Object { $_.Id }) | ForEach-Object { $after[[int]$_] = $true }

$cand = @($sweep | Where-Object { -not $before.ContainsKey($_) -and -not $after.ContainsKey($_) })

Start-Sleep -Milliseconds 400
$third = @{}
@(Get-CimInstance Win32_Process | ForEach-Object { $_.ProcessId }) +
  @(Get-Process | ForEach-Object { $_.Id }) +
  @((tasklist /fo csv /nh 2>$null) -split "`n" | Where-Object { $_ -match '^"' } |
      ForEach-Object { [int](($_ -split '","')[1]) }) |
  ForEach-Object { $third[[int]$_] = $true }

$o.openable = @($cand |
    Where-Object { -not $third.ContainsKey($_) -and [PidSweep]::Alive($_) } |
    ForEach-Object { [pscustomobject]@{ pid=[int]$_; image=[string][PidSweep]::Image($_) } })
$o.openableTotal = @($sweep).Count
# Pids that exist in some form but refuse inspection. Reported as a gap in
# coverage, not as a detection.
$opaque = @()
try { $opaque = [int[]][PidSweep]::Opaque(65535) } catch { $opaque = @() }
$o.opaque = @($opaque | Where-Object { -not $third.ContainsKey($_) })

# --- view 6: the thread list ----------------------------------------------
# Threads are tracked separately from processes. A process unlinked from the
# process list still has threads, and they still name their owning process.
$o.threadOwners = @((Get-CimInstance Win32_Thread |
                     Select-Object -ExpandProperty ProcessHandle) |
                    Sort-Object -Unique | ForEach-Object { [int]$_ })

# --- view 7: the performance subsystem ------------------------------------
# Perfmon reads process data through a different provider chain again.
$o.perfpids = @()
try {
  $o.perfpids = @((Get-Counter '\Process(*)\ID Process' -ErrorAction Stop).CounterSamples |
                  ForEach-Object { [int]$_.CookedValue } | Where-Object { $_ -gt 0 } |
                  Sort-Object -Unique)
} catch { $o.perfpids = @() }

# --- view 8: what the service controller thinks is running ----------------
$o.svcpids = @(Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -gt 0 } |
               ForEach-Object { [int]$_.ProcessId } | Sort-Object -Unique)

# --- verification pass ------------------------------------------------------
# Views 6-8 are each a single snapshot taken at a slightly different instant
# from the enumerations they are compared against, so a process that starts or
# exits in between shows up as concealed. Every candidate is therefore re-tested
# against one final, fresh listing and re-probed for life; only a pid that is
# still running and still absent survives. Without this the scan reports a
# couple of phantom criticals per run, which is worse than reporting nothing.
$verify = @{}
@(Get-CimInstance Win32_Process | ForEach-Object { $_.ProcessId }) +
  @(Get-Process | ForEach-Object { $_.Id }) +
  @((tasklist /fo csv /nh 2>$null) -split "`n" | Where-Object { $_ -match '^"' } |
      ForEach-Object { [int](($_ -split '","')[1]) }) |
  ForEach-Object { $verify[[int]$_] = $true }

function Confirm-Ghosts($pids) {
  @($pids | Where-Object {
      $_ -gt 4 -and -not $verify.ContainsKey($_) -and [PidSweep]::Probe($_) -eq 1 } |
    ForEach-Object { [pscustomobject]@{ pid=[int]$_; image=[string][PidSweep]::Image($_) } })
}
$o.ghostThreads = Confirm-Ghosts $o.threadOwners
$o.ghostPerf    = Confirm-Ghosts $o.perfpids
$o.ghostSvc     = Confirm-Ghosts $o.svcpids

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""


def _aslist(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def audit_windows():
    data = _ps_json(PS_HIDDEN, timeout=120)
    if data is None:
        return [_finding("medium", "Windows cross-view unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    wmi = {p["pid"]: p for p in _aslist(data.get("wmi")) if p.get("pid") is not None}
    api = {p["pid"]: p for p in _aslist(data.get("api")) if p.get("pid") is not None}
    tl = {p["pid"]: p for p in _aslist(data.get("tasklist")) if p.get("pid") is not None}
    netpids = {p for p in _aslist(data.get("netpids")) if isinstance(p, int) and p > 4}

    def label(pid):
        for src in (wmi, api, tl):
            if pid in src:
                return src[pid].get("name") or "?"
        return "unknown"

    # WMI and the process API disagreeing is the classic userland-hook tell.
    for pid in sorted(set(wmi) - set(api) - {0, 4}):
        out.append(_finding("high", "process visible to WMI but not to the process API",
                            f"pid {pid} ({label(pid)}) — {wmi[pid].get('path') or 'no path'}",
                            "Win32_Process vs Get-Process"))
    for pid in sorted(set(api) - set(wmi) - {0, 4}):
        out.append(_finding("high", "process visible to the process API but not to WMI",
                            f"pid {pid} ({label(pid)}) — WMI provider may be tampered with",
                            "Get-Process vs Win32_Process"))
    for pid in sorted((set(wmi) | set(api)) - set(tl) - {0, 4}):
        out.append(_finding("medium", "process missing from tasklist",
                            f"pid {pid} ({label(pid)})", "tasklist.exe"))

    for pid in sorted(netpids - set(wmi) - set(api) - set(tl)):
        out.append(_finding("critical", "network connection owned by an invisible process",
                            f"pid {pid} holds an open TCP connection but appears in no "
                            f"process listing",
                            "Get-NetTCPConnection vs process views"))

    # -- the DKOM cross-view ----------------------------------------------
    # Everything above walks ActiveProcessLinks, one kernel list. These three
    # reach process objects by other routes, so a pid they can see while the
    # enumerations cannot is the signature of a process unlinked from that list.
    enumerated = set(wmi) | set(api) | set(tl)
    threads = {p for p in _aslist(data.get("threadOwners")) if isinstance(p, int)}
    perf = {p for p in _aslist(data.get("perfpids")) if isinstance(p, int)}
    svc = {p for p in _aslist(data.get("svcpids")) if isinstance(p, int)}

    # pid 0 and 4 are the System process and have no ordinary listing entry.
    IGNORE = {0, 4}

    # The handle-table suspects are already triple-verified inside PowerShell
    # (see PS_HIDDEN), so anything still here survived two bracketing
    # enumerations, a third fresh listing and a re-opened handle.
    for s in _aslist(data.get("openable")):
        pid = s.get("pid") if isinstance(s, dict) else None
        if pid is None or pid in IGNORE:
            continue
        image = (s.get("image") or "").strip()
        out.append(_finding(
            "critical", "process visible only to the handle table",
            f"pid {pid} ({image or 'no image name'}) is running — not merely a "
            f"handle held open on a dead object — yet appears in no enumeration. "
            f"The handle table (PspCidTable) still holds it, which is what "
            f"unlinking an EPROCESS from ActiveProcessLinks (DKOM) leaves behind",
            image or "OpenProcess vs WMI/Get-Process/tasklist"))

    opaque = {p for p in _aslist(data.get("opaque")) if isinstance(p, int)} - IGNORE
    if opaque:
        out.append(_finding(
            "low", "some pids could not be qualified",
            f"{len(opaque)} pid(s) return ERROR_ACCESS_DENIED to a limited-info "
            f"open, so this scan cannot tell a protected process from an already "
            f"exited one and does not guess: {', '.join(str(p) for p in sorted(opaque)[:10])}"
            + (" …" if len(opaque) > 10 else "")
            + ". Running the audit elevated resolves them.",
            "OpenProcess"))

    for src_name, src, ghost_key, note in (
        ("the thread list", threads, "ghostThreads",
         "owns running threads while appearing in no process listing"),
        ("the performance counters", perf, "ghostPerf",
         "is reported by the performance subsystem but by no enumeration API"),
        ("the service controller", svc, "ghostSvc",
         "is registered as a running service's process but appears in no listing"),
    ):
        if not src:
            out.append(_finding("low", f"{src_name} view unavailable",
                                "this cross-check was skipped", "Windows"))
            continue
        # Already re-verified against a fourth enumeration inside PowerShell.
        ghosts = [g for g in _aslist(data.get(ghost_key))
                  if isinstance(g, dict) and g.get("pid") not in IGNORE]
        for g in ghosts:
            image = (g.get("image") or "").strip()
            out.append(_finding(
                "critical", f"process visible only to {src_name}",
                f"pid {g.get('pid')} ({image or 'no image name'}) {note}, and is "
                f"still running when re-checked",
                image or f"{src_name} vs WMI/Get-Process/tasklist"))
        if not ghosts:
            out.append(_finding("ok", f"{src_name} agrees with the process listings",
                                f"{len(src)} pids, none of them concealed", ""))

    out.append(_finding("ok", "cross-view scan complete",
                        f"{len(wmi)} via WMI, {len(api)} via process API, "
                        f"{len(tl)} via tasklist, "
                        f"{data.get('openableTotal', 0)} via OpenProcess sweep, "
                        f"{len(threads)} via threads, {len(perf)} via perf counters",
                        ""))
    for f in out:
        f["host"] = "win"
    return out, data


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def audit(hosts=("wsl", "win"), deep=False):
    out, extra = [], {}
    if "wsl" in hosts:
        out += audit_linux(deep=deep)
    if "win" in hosts:
        res = audit_windows()
        if isinstance(res, tuple):
            out += res[0]
            extra = res[1]
        else:
            out += res
    out.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["title"]))
    return out, extra
