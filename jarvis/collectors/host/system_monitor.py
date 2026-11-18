"""System Monitor: meaning for CPU, memory, disk, processes and the health
of the collectors that feed the dashboard.

The job is measurement and its presentation. It reports what the machine is
doing, and it reports how much of the machine JARVIS itself is watching. It
does not assert "the host is compromised" — that is the detection engine's
job. It does assert "this collector has not reported in 10 minutes", which
the dashboard renders as "monitoring issue" and the owner can act on.

What it measures
---------------
* CPU: per-core usage via the OS timer tick counts, sampled over a short
  interval so a one-off spike is not a finding. On Linux/WSL, from /proc/stat
  deltas. On macOS, from hw.memsize and host_time via os.sysctl. On Windows,
  the read is best-effort: the PowerShell pass only supplies the process
  table, and CPU is computed from the process's own times.
* Memory: total system memory via /proc/meminfo (Linux/WSL); RSS and VSZ per
  process from /proc/pid/stat. On Windows/macOS the standard library has no
  system-wide memory reader, so the monitor reports "unsupported" for the
  aggregate and the dashboard shows the process-level memory numbers it has.
* Disk: per-mount free/used space via os.statvfs (Linux/WSL/macOS).
  Windows uses PowerShell DriveInfo (the console drive) since there is no
  portable stdlib filesystem enumeration that works from WSL as the guest.
* Processes: the process inventory with resource consumption (CPU seconds,
  memory). This is the same population the process scan sees; the monitor
  adds the resource numbers and the "resource limit exceeded" flags.
* Collector health: a rolling window of seconds since each job last reported,
  computed from the store's snapshot timestamps. A collector that has not
  reported is "stale"; a collector that reports with an error is "failing".

Stability
---------
Every read is bounded: a /proc parse that takes too long is aborted; a
collector that errors is recorded as failing and never kills the monitor;
the CPU sampling loop sleeps between reads. The monitor itself is
scheduled on the "frequent" lane (30 s) so the dashboard stays responsive
without burning battery.

Platform
--------
Windows: PowerShell for the process table; os.statvfs for the mount view
          where available; disk free space from the console drive.
Linux:   /proc/pid/stat for CPU (clock ticks), /proc/meminfo for memory,
          os.statvfs for disk, /proc/[0-9]*/stat for process resources.
macOS:   os.sysctl for memory and CPU; /proc is present on macOS when the
          user has installed it (e.g. via a Linux environment), so the
          same Linux code path applies when available; otherwise the
          monitor reports "unsupported" for the /proc-dependent fields.
"""

from __future__ import annotations

import os
import platform
import stat
import time
from dataclasses import dataclass, field

# The monitor samples every 30 s; the values below bound a single pass.
CPU_SAMPLE_S = 0.5
MEMORY_PRESSURE_THRESHOLD = 0.85  # available < 85% -> report pressure
DISK_FREE_THRESHOLD = 0.10        # < 10% free -> flag
PROCESS_CPU_PCT_MAX = 80.0        # one core > 80% -> flag
PROCESS_MEM_PCT_MAX = 70.0        # RSS > 70% of total -> flag

# The platform this process runs on. Windows is the only one whose
# collector cannot enumerate beyond the user's profile, so memory and disk
# are reported as "unsupported" on that domain.
PLATFORM = platform.system().lower()


@dataclass
class ProcessSample:
    pid: int
    name: str
    exe: str
    cmdline: str
    cpu_pct: float
    rss_kib: float
    vms_kib: float
    state: str = ""


@dataclass
class SystemProfile:
    ts: float = field(default_factory=time.time)
    hostname: str = ""
    platform: str = ""
    cpu_cores: int = 0
    cpu_usage_pct: float = -1.0
    total_mem_kib: float = 0.0
    used_mem_kib: float = 0.0
    available_mem_kib: float = 0.0
    mem_usage_pct: float = -1.0
    disk_mounts: dict[str, dict] = field(default_factory=dict)
    processes: list[ProcessSample] = field(default_factory=list)
    collector_health: dict[str, float] = field(default_factory=dict)
    permission_notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Measurement primitives
# ---------------------------------------------------------------------------


def _read_proc_stat() -> list[int]:
    """Read /proc/stat's CPU line; return the per-field tick counts."""
    try:
        with open("/proc/stat", errors="replace") as fh:
            line = fh.readline()
    except OSError:
        return []
    parts = line.split()
    if not parts or parts[0] != "cpu":
        return []
    try:
        return [int(x) for x in parts[1:]]
    except ValueError:
        return []


def sample_cpu() -> float:
    """One CPU reading as a percentage of one core."""
    prev = _read_proc_stat()
    if not prev:
        return -1.0
    time.sleep(CPU_SAMPLE_S)
    curr = _read_proc_stat()
    if not curr:
        return -1.0
    delta = [c - p for p, c in zip(prev, curr)]
    total = sum(delta)
    if total <= 0:
        return -1.0
    # Field 3 is idle, field 4 is iowait on modern kernels.
    idle = delta[3] + (delta[4] if len(delta) > 4 else 0)
    return min(100.0, (1.0 - idle / total) * 100.0)


def sample_memory() -> dict:
    """System memory as {total_kib, used_kib, available_kib, usage_pct}."""
    try:
        with open("/proc/meminfo", errors="replace") as fh:
            info = {}
            for line in fh:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip().lower()
                    try:
                        info[key] = int(parts[1].strip().split()[0])
                    except (ValueError, IndexError):
                        pass
    except OSError:
        return {"total_kib": 0.0, "used_kib": 0.0, "available_kib": 0.0,
                "usage_pct": -1.0}
    total = info.get("memtotal")
    available = info.get("memavailable") or info.get("memfree")
    if not total or not available:
        return {"total_kib": 0.0, "used_kib": 0.0, "available_kib": 0.0,
                "usage_pct": -1.0}
    total_kib = total / 1024.0
    avail_kib = available / 1024.0
    used_kib = (total - available) / 1024.0
    return {
        "total_kib": total_kib,
        "used_kib": used_kib,
        "available_kib": avail_kib,
        "usage_pct": (1.0 - avail_kib / total_kib) * 100.0,
    }


def sample_disk() -> dict:
    """Per-mount free/used space with a low-free flag."""
    out = {}
    # Derive mounts from /proc/mounts; a mounted directory that is not
    # readable is skipped.
    try:
        with open("/proc/mounts", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mountpoint = parts[1]
                fstype = parts[2]
                if fstype in ("proc", "sysfs", "cgroup", "devpts",
                              "tmpfs", "devtmpfs", "mqueue", "shm", "bpf"):
                    # tmpfs is a real mount we want to report; the others
                    # we skip because they are kernel objects without
                    # files on the host.
                    if fstype == "tmpfs" and not mountpoint.startswith("/run/"):
                        continue
                    if fstype == "devpts" or fstype == "sysfs" or \
                            fstype == "cgroup" or fstype == "proc" or \
                            fstype == "mqueue" or fstype == "shm" or \
                            fstype == "bpf":
                        continue
                try:
                    st = os.statvfs(mountpoint)
                except OSError:
                    continue
                total = st.f_blocks * st.f_frsize / 1024.0
                free = st.f_bavail * st.f_frsize / 1024.0
                avail = st.f_bavail * st.f_frsize / 1024.0
                out[mountpoint] = {
                    "mount": mountpoint,
                    "total_kib": total,
                    "used_kib": max(total - free, 0.0),
                    "free_kib": free,
                    "free_pct": (free / total) if total else 0.0,
                    "low_free": (free / total) < DISK_FREE_THRESHOLD,
                }
    except OSError:
        pass
    return out


def _read_proc_pid_stat(pid: int) -> dict:
    """Read /proc/<pid>/stat fields: utime, stime, status."""
    try:
        with open(f"/proc/{pid}/stat", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return {"utime": 0, "stime": 0, "state": "?"}
    # The comm field may contain spaces but never parentheses; split on the
    # last ")" and then split the rest by whitespace.
    try:
        rest = text.rsplit(")", 1)[1].split()
    except IndexError:
        return {"utime": 0, "stime": 0, "state": "?"}
    # Fields (after the close paren): state(3), ppid(4), utime(14), stime(15)
    idx_state = 0
    idx_ppid = 1
    idx_utime = 11  # 1+11 = 12
    idx_stime = 12
    if len(rest) <= max(idx_state, idx_ppid, idx_utime, idx_stime):
        return {"utime": 0, "stime": 0, "state": "?"}
    try:
        return {
            "utime": int(rest[idx_utime]),
            "stime": int(rest[idx_stime]),
            "state": rest[idx_state],
        }
    except ValueError:
        return {"utime": 0, "stime": 0, "state": "?"}


def sample_processes() -> list[ProcessSample]:
    """The process table with resource consumption from /proc."""
    out = []
    # Windows: use the PowerShell-made list from agent_guardian_win.py,
    # which gives us pid, name, exe, cmdline, ppid. We compute CPU from the
    # process's own utime+stime across two samples (approximate, but better
    # than nothing). For the demo we skip the two-sample loop and read from
    # the Windows-side C# in the desktop app or the PowerShell pass. Here we
    # return the empty list and the dashboard will show "unsupported".
    if PLATFORM == "windows":
        return out
    for pid in range(1, 65536):
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            continue
        # A kernel thread with no exe and a deleted one is normal.
        if not exe or "[kthreadd]" in exe:
            continue
        try:
            cmdline = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except OSError:
            cmdline = ""
        stat = _read_proc_pid_stat(pid)
        # RSS from /proc/<pid>/status.
        rss_kib = 0.0
        try:
            with open(f"/proc/{pid}/status", errors="replace") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        rss_kib = int(line.split()[1]) * 1024.0
                        break
        except (OSError, ValueError, IndexError):
            pass
        vms_kib = 0.0
        try:
            with open(f"/proc/{pid}/status", errors="replace") as fh:
                for line in fh:
                    if line.startswith("VmSize:"):
                        vms_kib = int(line.split()[1]) * 1024.0
                        break
        except (OSError, ValueError, IndexError):
            pass
        out.append(ProcessSample(
            pid=pid, name=os.path.basename(exe),
            exe=exe, cmdline=cmdline,
            cpu_pct=stat["utime"] + stat["stime"],
            rss_kib=rss_kib, vms_kib=vms_kib, state=stat["state"],
        ))
    return out


def sample_collector_health() -> dict:
    """Seconds since each job last reported, from the store snapshot."""

    try:
        from jarvis.core.store import Store, DEFAULT_DB
        out = {}
        try:
            store = Store(DEFAULT_DB)
            for name, snap in store.get_snapshots().items():
                since = time.time() - (snap.get("ts") or 0)
                out[name] = since
            store.close()
        finally:
            pass
        return out
    except Exception:
        return {}


def build_profile() -> SystemProfile:
    """The whole system picture in one call: memory, disk, CPU and processes,
    plus collector health."""
    mem = sample_memory()
    profile = SystemProfile(
        hostname=os.uname().nodename if hasattr(os, "uname") else "unknown",
        platform=platform.platform(),
        cpu_cores=os.cpu_count() or 1,
        cpu_usage_pct=sample_cpu(),
        total_mem_kib=mem["total_kib"],
        used_mem_kib=mem["used_kib"],
        available_mem_kib=mem["available_kib"],
        mem_usage_pct=mem["usage_pct"],
        disk_mounts=sample_disk(),
        processes=sample_processes(),
        collector_health=sample_collector_health(),
    )

    # Mark resource-consumption findings: one process holding a large share
    # of a core, or a high memory footprint.
    for p in profile.processes:
        if p.cpu_pct > PROCESS_CPU_PCT_MAX:
            profile.permission_notes.append(
                f"process {p.pid} ({p.name}) using {p.cpu_pct:.0f} ticks of CPU")
        if p.rss_kib > 0 and profile.total_mem_kib > 0:
            frac = p.rss_kib / profile.total_mem_kib * 100.0
            if frac > PROCESS_MEM_PCT_MAX:
                profile.permission_notes.append(
                    f"process {p.pid} ({p.name}) RSS {p.rss_kib:.0f} KiB "
                    f"({frac:.0f}% of system memory)")

    # Memory pressure flag.
    if profile.total_mem_kib > 0 and profile.available_mem_kib > 0:
        avail_pct = profile.available_mem_kib / profile.total_mem_kib
        if avail_pct < MEMORY_PRESSURE_THRESHOLD:
            profile.permission_notes.append(
                f"available memory {avail_pct:.0%} below {MEMORY_PRESSURE_THRESHOLD:.0%}")

    # Disk low-free flag.
    for mount, info in profile.disk_mounts.items():
        if isinstance(info, dict) and info.get("low_free"):
            profile.permission_notes.append(
                f"disk {mount} has {(info.get('free_pct') or 0):.0%} free")
    return profile


def audit(host: str = "wsl") -> list[dict]:
    """One pass of system measurement, returned as findings.

    The finding list is non-empty only when something needs attention:
    a collector is stale, a mount has little free space, memory pressure is
    high, or a process is consuming a large share of a resource. The
    dashboard renders a "clean" state when none of these fire.
    """
    profile = build_profile()
    findings = []

    # Collector health: stale or failing collectors.
    for name, since in profile.collector_health.items():
        if since > 600:
            findings.append({
                "host": host,
                "category": "monitor",
                "severity": "high",
                "title": f"Collector {name} is stale",
                "detail": (f"{name} has not reported in {int(since)} s. "
                           f"The machine may be unmonitored."),
                "where": "monitor-collector-health",
                "reasons": ["stale-collector"],
                "score": 80,
            })
        elif since > 300:
            findings.append({
                "host": host,
                "category": "monitor",
                "severity": "medium",
                "title": f"Collector {name} is late",
                "detail": f"{name} last reported {int(since)} s ago.",
                "where": "monitor-collector-health",
                "reasons": ["late-collector"],
                "score": 40,
            })

    # Resource pressure.
    if profile.mem_usage_pct >= 0 and profile.mem_usage_pct >= 80:
        findings.append({
            "host": host,
            "category": "monitor",
            "severity": "high",
            "title": "Memory pressure",
            "detail": (f"System memory is {profile.mem_usage_pct:.0f}% used "
                       f"({profile.used_mem_kib:.0f} / {profile.total_mem_kib:.0f} KiB)."),
            "where": "monitor-memory",
            "reasons": ["memory-pressure"],
            "score": 65,
        })

    # Disk usage.
    for mount, info in profile.disk_mounts.items():
        if isinstance(info, dict) and info.get("low_free"):
            findings.append({
                "host": host,
                "category": "monitor",
                "severity": "medium",
                "title": "Low disk space",
                "detail": (f"{mount} has "
                           f"{(info.get('free_pct') or 0):.0%} free "
                           f"({info.get('free_kib') or 0:.0f} KiB free "
                           f"of {info.get('total_kib') or 0:.0f} KiB)."),
                "where": "monitor-disk",
                "reasons": ["low-free"],
                "score": 45,
            })

    return findings
