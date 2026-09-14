"""Sustained process consumption and whole-system capacity pressure."""

import json
import math
import os
import shutil
import time

from . import monitor

_META = "resourcewatch_sample_v1"


def _finding(severity, title, detail, where="", host="wsl"):
    return {"category": "resource", "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def _memory_pressure():
    try:
        values = {}
        with open("/proc/meminfo", errors="replace") as fh:
            for line in fh:
                name, value = line.split(":", 1)
                values[name] = int(value.split()[0]) * 1024
        return values["MemTotal"], values["MemAvailable"]
    except (OSError, ValueError, KeyError, IndexError):
        return 0, 0


def audit(store, hosts=("wsl", "win")):
    """Compare cumulative CPU counters with the prior five-minute sample."""
    sampled_at = time.time()
    processes = monitor.collect_all(hosts=hosts, with_sockets=False)
    try:
        previous = json.loads(store.get_meta(_META, "{}") or "{}")
    except (TypeError, ValueError):
        previous = {}
    if not isinstance(previous, dict):
        previous = {}
    elapsed = sampled_at - float(previous.get("ts", sampled_at))
    cpu_count = max(1, os.cpu_count() or 1)
    old = previous.get("processes", {}) if isinstance(previous, dict) else {}
    current = {}
    findings = []
    cpu_gaps = set()

    for proc in processes:
        # Windows PID 0 is the idle-time counter. Its socket attribution label
        # must not turn unused CPU capacity into a resource-pressure alert.
        if proc.get("pid") in (None, 0, "0"):
            continue
        host = proc.get("host") or "wsl"
        key = f"{proc.get('host')}:{proc.get('pid')}:{proc.get('fp')}"
        cpu_seconds = max(0.0, float(proc.get("cpu_seconds") or 0))
        rss = max(0, int(proc.get("rss_bytes") or 0))
        current[key] = {"cpu": cpu_seconds}
        prior = old.get(key) if isinstance(old, dict) else None
        # WSL can have fewer virtual CPUs than the Windows host. Never divide
        # Windows CPU counters by the Linux VM's processor count.
        capacity = proc.get("logical_cpus", 0) if host == "win" else cpu_count
        cpu_pct = None
        if not capacity:
            cpu_gaps.add(host)
        elif prior is not None and elapsed > 0:
            delta = cpu_seconds - float(prior.get("cpu", 0))
            measured = delta / elapsed / capacity * 100
            if math.isfinite(measured) and 0 <= measured <= 100:
                cpu_pct = measured
            else:
                # Counter resets, PID reuse, or clock discontinuities cannot
                # establish sustained consumption. Rebaseline, don't clamp an
                # impossible measurement into a HIGH process alert.
                cpu_gaps.add(host)
        elif prior is not None:
            cpu_gaps.add(host)
        severe = rss >= 4 * 1024**3 or (cpu_pct is not None and cpu_pct >= 50)
        notable = rss >= 1536 * 1024**2 or (cpu_pct is not None and cpu_pct >= 20)
        if severe or notable:
            cpu_detail = (f"{cpu_pct:.1f}% of total CPU over the last {_duration(elapsed)}"
                          if cpu_pct is not None else "CPU usage unavailable for this sample")
            findings.append(_finding(
                "high" if severe else "medium", "resource-intensive process",
                f"{proc.get('name') or '?'} [pid {proc.get('pid')}] uses "
                f"{rss / 1024**3:.1f} GiB resident memory and {cpu_detail}",
                proc.get("exe") or "", proc.get("host") or "wsl"))

    for host in sorted(cpu_gaps):
        findings.append(_finding(
            "medium", "process CPU measurement unavailable",
            "Missing host CPU capacity or inconsistent counters/timestamps; "
            "affected samples were rebaselined, memory checks remain active", host=host))

    total, available = _memory_pressure()
    if total:
        pct = available / total * 100
        if pct < 10:
            findings.append(_finding(
                "high" if pct < 5 else "medium", "system memory pressure",
                f"only {available / 1024**3:.1f} GiB ({pct:.1f}%) remains available",
                "/proc/meminfo"))

    for path in ("/", "/mnt/c"):
        if not os.path.exists(path):
            continue
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            continue
        used = (usage.total - usage.free) / usage.total * 100 if usage.total else 0
        if used >= 85:
            findings.append(_finding(
                "high" if used >= 95 else "medium", "disk capacity pressure",
                f"{path} is {used:.1f}% full; low free space can stop logs, "
                "updates, quarantine, and collector snapshots", path))

    store.set_meta(_META, json.dumps({"ts": sampled_at, "processes": current}))
    findings.sort(key=lambda f: ({"high": 0, "medium": 1}.get(f["severity"], 9),
                                 f["title"], f["detail"]))
    if not findings:
        findings.append(_finding(
            "ok", "system resource headroom is healthy",
            f"{len(processes)} processes sampled; no sustained CPU, memory, or "
            "disk pressure crossed the reporting threshold"))
    return findings[:20]


def _duration(seconds):
    return f"{int(seconds)}s" if seconds < 120 else f"{int(seconds // 60)}m"
