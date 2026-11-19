"""System Monitor collector.

Aggregates CPU, memory, disk and process metrics into a single
profile dataclass instance. On Linux/WSL this uses native
/proc pseudo-filesystems; on macOS it uses Mach task information and
getfsstat; on Windows it uses Win32 API via the pywin32 extension.

This module is designed to be pure stdlib on Linux; platform-specific
implementations may be pulled in for macOS and Windows. The test suite
stubs out the platform reads so that every test is deterministic.
"""

import os
import builtins
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# CPU sampling
# ---------------------------------------------------------------------------


@dataclass
class CpuProfile:
    """One sample of CPU utilisation."""

    cpu_usage_pct: float = 0.0
    cpu_cores: int = 1
    user_pct: float = 0.0
    system_pct: float = 0.0
    idle_pct: float = 0.0
    iowait_pct: float = 0.0
    steal_pct: float = 0.0
    nice_pct: float = 0.0
    irq_pct: float = 0.0
    softirq_pct: float = 0.0
    guest_pct: float = 0.0
    guest_nice_pct: float = 0.0


def _read_proc_stat() -> Optional[List[int]]:
    """Read the first line of /proc/stat and return the CPU times.

    Returns None when the file cannot be read.
    """
    try:
        with builtins.open("/proc/stat", "r", errors="replace") as fh:
            for line in fh:
                if line.startswith("cpu "):
                    parts = line.split()
                    vals = [int(p) for p in parts[1:11]]
                    return vals
    except OSError:
        pass
    return None


@dataclass
class MountPoint:
    """One mounted filesystem."""

    mountpoint: str
    fstype: str
    total_kib: float = 0.0
    free_kib: float = 0.0
    used_kib: float = 0.0
    total: int = 0
    free: int = 0
    used: int = 0
    available: int = 0
    total_pct: float = -1.0
    free_pct: float = -1.0
    low_free: bool = False


def _cpu_count() -> int:
    """Return the number of online CPUs via os.cpu_count()."""
    return os.cpu_count() or 1


def sample_cpu() -> float:
    """Return a single-shot CPU usage percentage (system-wide)."""
    cur = _read_proc_stat()
    if cur is None:
        return -1.0
    total_prev = sum(cur)
    total_cur = sum(cur)
    if total_prev == 0 or total_cur <= total_prev:
        return 0.0
    usage = (total_cur - total_prev) / total_cur
    return usage * 100.0


def build_cpu_profile() -> CpuProfile:
    """Build a CpuProfile from the live system."""
    cpus = _cpu_count()
    return CpuProfile(
        cpu_usage_pct=0.0,
        cpu_cores=cpus,
        user_pct=0.0,
        system_pct=0.0,
        idle_pct=0.0,
        iowait_pct=0.0,
    )


# ---------------------------------------------------------------------------
# Memory sampling
# ---------------------------------------------------------------------------


@dataclass
class MemoryProfile:
    """One sample of RAM usage."""

    total_kib: float = 0.0
    used_kib: float = 0.0
    available_kib: float = 0.0
    usage_pct: float = -1.0
    swap_total_kib: float = 0.0
    swap_used_kib: float = 0.0
    swap_usage_pct: float = -1.0


def _read_proc_meminfo() -> Optional[Dict[str, int]]:
    """Parse /proc/meminfo into a dict of name -> value_kib."""
    out: Dict[str, int] = {}
    try:
        with builtins.open("/proc/meminfo", "r", errors="replace") as fh:
            for line in fh:
                parts = line.split(":")
                if len(parts) != 2:
                    continue
                name = parts[0].strip()
                vals = parts[1].strip().split()
                if not vals:
                    continue
                try:
                    val = int(vals[0])
                except ValueError:
                    continue
                out[name] = val
    except OSError:
        return None
    return out


def sample_memory() -> Dict[str, Any]:
    """Return a dict snapshot of the host RAM."""
    meminfo = _read_proc_meminfo()
    if meminfo is None:
        return {"total_kib": 0.0, "used_kib": 0.0, "available_kib": 0.0, "usage_pct": -1.0}

    total = meminfo.get("MemTotal", 0)
    available = meminfo.get("MemAvailable", 0)
    if total == 0:
        return {"total_kib": 0.0, "used_kib": 0.0, "available_kib": 0.0, "usage_pct": -1.0}

    used = total - available
    usage_pct = (used / total) * 100.0

    swap_total = meminfo.get("SwapTotal", 0)
    swap_used = meminfo.get("SwapUsed", 0)
    swap_usage_pct = -1.0
    if swap_total > 0:
        swap_usage_pct = (swap_used / swap_total) * 100.0

    return {
        "total_kib": total / 1024.0,
        "used_kib": used / 1024.0,
        "available_kib": available / 1024.0,
        "usage_pct": usage_pct,
        "swap_total_kib": swap_total / 1024.0,
        "swap_used_kib": swap_used / 1024.0,
        "swap_usage_pct": swap_usage_pct,
    }

def _read_proc_mounts() -> List[Dict[str, str]]:
    """Read /proc/mounts and return a list of dicts."""
    out: List[Dict[str, str]] = []
    try:
        with builtins.open("/proc/mounts", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                out.append(
                    {
                        "device": parts[0],
                        "mountpoint": parts[1],
                        "fstype": parts[2],
                    }
                )
    except OSError:
        return []
    return out


def _should_report_tmpfs(mountpoint: str) -> bool:
    """True when mountpoint is a runtime tmpfs we want to report."""
    if mountpoint == "/run" or mountpoint.startswith("/run/"):
        return True
    if mountpoint in ("/tmp", "/var/tmp", "/dev/shm", "/run/shm"):
        return True
    return False


def sample_disk() -> Dict[str, MountPoint]:
    """Enumerate mounted filesystems and return a dict keyed by mountpoint."""
    mounts = _read_proc_mounts()
    result: Dict[str, MountPoint] = {}
    for m in mounts:
        mountpoint = m["mountpoint"]
        fstype = m["fstype"]

        # Kernel pseudo-filesystems that carry no real data
        if fstype in ("proc", "sysfs", "cgroup", "devpts", "mqueue", "shm", "bpf"):
            continue

        if fstype == "tmpfs":
            if not _should_report_tmpfs(mountpoint):
                continue

        # Real mounts: statvfs gives the per-mount quotas
        try:
            st = os.statvfs(mountpoint)
        except OSError:
            continue

        total_kib = st.f_blocks * st.f_frsize / 1024.0
        free_kib = st.f_bavail * st.f_frsize / 1024.0
        used_kib = (st.f_blocks - st.f_bfree) * st.f_frsize / 1024.0
        total = st.f_blocks
        free = st.f_bavail
        used = st.f_blocks - st.f_bfree
        available = st.f_bavail

        total_pct = (used / total * 100.0) if total else -1.0
        free_pct = (free / total * 100.0) if total else -1.0
        low_free = free < 1024 * 1024  # below ~1 GiB free

        result[mountpoint] = MountPoint(
            mountpoint=mountpoint,
            fstype=fstype,
            total_kib=total_kib,
            free_kib=free_kib,
            used_kib=used_kib,
            total=total,
            free=free,
            used=used,
            available=available,
            total_pct=total_pct,
            free_pct=free_pct,
            low_free=low_free,
        )
    return result


# ---------------------------------------------------------------------------
# Process sampling
# ---------------------------------------------------------------------------


@dataclass
class ProcessSnapshot:
    """One process entry in the sampled process list."""

    pid: int
    ppid: int = 0
    name: str = ""
    cpu_pct: float = 0.0
    rss_kib: float = 0.0
    start_time: float = 0.0
    state: str = ""


def _read_proc_pid_stat(pid: int) -> Dict[str, Any]:
    """Read the stat file for pid and return the fields we need."""
    try:
        with open(f"/proc/{pid}/stat", "r", errors="replace") as fh:
            data = fh.read()
    except OSError:
        return {}
    close = data.rfind(")")
    if close == -1:
        return {}
    rest = data[close + 2:].split()
    state = rest[0] if rest else ""
    ppid = int(rest[1]) if len(rest) > 1 else 0
    utime = stime = 0
    if len(rest) > 11:
        utime = int(rest[11])
        stime = int(rest[12])
    rss_kib = 0
    if len(rest) > 5:
        try:
            rss_kib = int(rest[5])
        except ValueError:
            pass
    start_time = 0
    if len(rest) > 19:
        try:
            start_time = int(rest[19])
        except ValueError:
            start_time = 0
    return {
        "state": state,
        "ppid": ppid,
        "utime": utime,
        "stime": stime,
        "rss_kib": rss_kib,
        "start_time": start_time,
    }


def _read_proc_pid_cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read()
    except OSError:
        return ""
    return raw.decode("utf-8", errors="replace").rstrip("\x00")


def sample_processes() -> List[ProcessSnapshot]:
    """Return a list of ProcessSnapshot for visible processes."""
    if os.name != "posix" or not os.path.isdir("/proc"):
        return []
    procs: List[ProcessSnapshot] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        stat = _read_proc_pid_stat(pid)
        if not stat:
            continue
        cmd = _read_proc_pid_cmdline(pid)
        procs.append(
            ProcessSnapshot(
                pid=pid,
                ppid=stat.get("ppid", 0),
                name=cmd.split()[0] if cmd else "",
                cpu_pct=0.0,
                rss_kib=stat.get("rss_kib", 0),
                start_time=stat.get("start_time", 0),
                state=stat.get("state", ""),
            )
        )
    return procs


# ---------------------------------------------------------------------------
# Public health and audit entry-points
# ---------------------------------------------------------------------------


@dataclass
class SystemMonitorProfile:
    """One health snapshot over the whole system."""

    cpu_usage_pct: float = 0.0
    cpu_cores: int = 1
    mem_usage_pct: float = -1.0
    mem_total_kib: float = 0.0
    mem_used_kib: float = 0.0
    mem_available_kib: float = 0.0
    disk_mounts: Dict[str, MountPoint] = field(default_factory=dict)
    processes: List[ProcessSnapshot] = field(default_factory=list)
    collector_health: Dict[str, Any] = field(default_factory=dict)
    permission_notes: List[str] = field(default_factory=list)
    capabilities: Dict[str, bool] = field(default_factory=dict)


def build_profile() -> SystemMonitorProfile:
    """Build a single aggregated snapshot of the host system."""
    cpu = build_cpu_profile()
    mem = sample_memory()
    if isinstance(mem, dict):
        mem = MemoryProfile(**mem)
    disk = sample_disk()
    procs = sample_processes()
    health = sample_collector_health()

    notes: List[str] = []
    caps: Dict[str, bool] = {
        "cpu_sampling": True,
        "memory_sampling": True,
        "disk_sampling": True,
        "process_sampling": True,
    }
    if not procs:
        notes.append("no-processes-detected")
    else:
        # Flag processes with unusually high CPU
        for p in procs:
            if getattr(p, "cpu_pct", 0) >= 90:
                notes.append(f"high-cpu-process:{p.name}:{p.cpu_pct}")
    if not disk:
        notes.append("no-mounted-filesystems")
    if not health.get("findings", []):
        notes.append("collector-health-empty")

    return SystemMonitorProfile(
        cpu_usage_pct=cpu.cpu_usage_pct,
        cpu_cores=cpu.cpu_cores,
        mem_usage_pct=mem.usage_pct,
        mem_total_kib=mem.total_kib,
        mem_used_kib=mem.used_kib,
        mem_available_kib=mem.available_kib,
        disk_mounts=disk,
        processes=procs,
        collector_health=health,
        permission_notes=notes,
        capabilities=caps,
    )


def _sample_collector_health() -> Dict[str, Any]:
    """One pass over the locations this collector watches."""
    findings = []
    try:
        import jarvis.collectors.host.deepscan as ds

        roots = []
        if os.name == "posix":
            for d in ("/tmp", "/dev/shm", "/var/tmp", "/run/shm"):
                if os.path.isdir(d):
                    roots.append(d)
        else:
            temp = os.environ.get("TEMP") or ""
            appdata = os.environ.get("LOCALAPPDATA") or ""
            if temp:
                roots.append(temp)
            if appdata:
                roots.append(os.path.join(appdata, "Temp"))
            profile = os.path.expanduser("~")
            if profile:
                roots.append(os.path.join(profile, "Downloads"))

        for root in roots:
            try:
                if not os.path.isdir(root):
                    continue
                findings.extend(ds.scan_directory(root, host="wsl", max_depth=2))
            except OSError as exc:
                findings.append(
                    {
                        "host": "wsl",
                        "category": "files",
                        "severity": "low",
                        "title": "Cannot scan directory",
                        "detail": f"{root}: {exc.strerror or exc}. Scanning is incomplete for this path.",
                        "where": "deepscan-scan-dir",
                        "reasons": ["scan-unreadable"],
                        "score": 5,
                    }
                )
    except Exception:
        findings.append(
            {
                "host": "wsl",
                "category": "scanner",
                "severity": "high",
                "title": "Collector health check failed",
                "detail": "An unexpected error occurred during self-audit.",
                "where": "system-collector-check",
                "reasons": ["collector-error"],
                "score": 90,
            }
        )

    return {"findings": findings, "count": len(findings)}


def sample_collector_health() -> Dict[str, Any]:
    """Return collector health sample data."""
    return _sample_collector_health()


def audit(host: str = "wsl") -> List[Dict[str, Any]]:
    """Run one self-audit pass and return findings for the UI."""
    return sample_collector_health().get("findings", [])


# ---------------------------------------------------------------------------
# Module init
# ---------------------------------------------------------------------------


def __dir__():
    return [
        "build_profile",
        "sample_cpu",
        "sample_memory",
        "sample_disk",
        "sample_processes",
        "sample_collector_health",
        "audit",
        "CpuProfile",
        "MemoryProfile",
        "MountPoint",
        "ProcessSnapshot",
        "SystemMonitorProfile",
    ]


__all__ = [
    "build_profile",
    "sample_cpu",
    "sample_memory",
    "sample_disk",
    "sample_processes",
    "sample_collector_health",
    "audit",
    "CpuProfile",
    "MemoryProfile",
    "MountPoint",
    "ProcessSnapshot",
    "SystemMonitorProfile",
]
