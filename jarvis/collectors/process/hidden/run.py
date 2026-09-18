"""Correlating every view into findings."""

import os
import time

from .common import DEFAULT_SWEEP, PROC, _finding

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
from .kernel import (
    bpf_hidden_pins,
    bpf_programs,
    ftrace_hooks,
    hidden_modules,
    injected_processes,
    io_uring_state,
    proc_overmounts,
)
from .sockets import hidden_listeners, orphan_sockets
from .views import (
    _alive,
    _describe,
    is_thread,
    pid_max,
    view_getdents,
    view_kill_probe,
    view_readdir,
    view_sched_debug,
    view_stat_sweep,
)
from .windows import audit_windows

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def confirmed_ghosts(ghosts, fresh_read, fresh_sig):
    """Pids that answer signals, are not listed in /proc, and are not threads.

    Measured 2026-09-17: a lone critical for a pid that, re-probed, was one of
    ~260 ordinary threads. is_thread() answers False when the status read
    fails, and a thread that exits between the probe and that read fails it.
    So the pid must still answer a signal after the thread test: a vanished
    thread does not, a hidden process does.
    """
    return [pid for pid in ghosts
            if pid in fresh_sig and pid not in fresh_read and not is_thread(pid)
            and _still_alive(pid) and not is_thread(pid)]


def _still_alive(pid):
    """Does `pid` still answer kill(pid, 0)? EPERM counts: it exists."""
    try:
        os.kill(pid, 0)
    except PermissionError:
        return True
    except OSError:
        return False
    return True


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
        # Sequential views race with process creation. Require the discrepancy
        # to survive fresh views in both directions before raising a finding.
        hooked = sorted(getdents - readdir)
        if hooked:
            fresh_raw = view_getdents()
            fresh_libc = view_readdir()
            hooked = [pid for pid in hooked if fresh_raw is not None
                      and pid in fresh_raw and pid not in fresh_libc]
        for pid in hooked:
            if _alive(pid) and not is_thread(pid):
                info = _describe(pid)
                out.append(_finding(
                    "critical", "process hidden from libc but visible to the kernel",
                    f"pid {pid} ({info['name']}) appears in raw getdents64 output "
                    f"but not through repeated libc listings. This persistent "
                    f"cross-view discrepancy needs investigation; it is not proof of a rootkit.",
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
        confirmed = confirmed_ghosts(ghosts, fresh_read, fresh_sig)
        if not confirmed:
            out.append(_finding("ok", "signal view agrees with /proc",
                                f"{len(ghosts)} unlisted pids answered kill(pid, 0); every "
                                f"one re-checked as a thread or had exited", f"1–{sweep_limit}"))
        for pid in confirmed:
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
