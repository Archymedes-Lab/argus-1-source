"""Sustained process consumption and whole-system capacity pressure."""

import json
import math
import os
import shutil
import time

from . import monitor

_META = "resourcewatch_sample_v1"
PROFILE_META = "resource_profile_v1"


def _owner(proc):
    """Stable resource bucket; classification only, never a threat verdict."""
    name = str(proc.get("name") or "").lower()
    text = " ".join(str(proc.get(k) or "") for k in ("name", "exe", "cmdline")).lower()
    if "ollama" in text:
        return "ollama"
    if name in ("chrome.exe", "msedge.exe", "brave.exe", "chromium", "chrome"):
        return "browser"
    if "jarvis.service.collector_worker" in text:
        return "collector workers"
    if "-m jarvis" in text or "/home/chris/jarvis" in text:
        return "jarvis engine"
    if "powershell" in name and "jarvis" in text:
        return "collector interop"
    return "other"


def _database_profile(store):
    result = {"bytes": 0, "tables": []}
    try:
        result["bytes"] = os.path.getsize(store.path)
    except OSError:
        pass
    try:
        rows = store.db.execute(
            "SELECT name, SUM(pgsize) AS bytes FROM dbstat "
            "GROUP BY name ORDER BY bytes DESC LIMIT 8").fetchall()
        result["tables"] = [{"name": row[0], "bytes": int(row[1] or 0)}
                            for row in rows]
    except Exception:
        pass
    return result


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
    owners = {}

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
        owner = _owner(proc)
        bucket = owners.setdefault(owner, {"rss_bytes": 0, "cpu_pct": 0.0,
                                           "processes": 0})
        bucket["rss_bytes"] += rss
        bucket["processes"] += 1
        if cpu_pct is not None:
            bucket["cpu_pct"] += cpu_pct
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
    store.set_meta(PROFILE_META, json.dumps({
        "at": sampled_at,
        "owners": dict(sorted(owners.items(),
                              key=lambda item: item[1]["rss_bytes"], reverse=True)),
        "database": _database_profile(store),
        "attribution": _attribution(owners),
        "governor": _governor_advice(owners, processes),
    }))
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


def _attribution(owners):
    """JARVIS self-cost shares; always sums to ~1 so the UI can render it.

    RAM-first and cheap: shares of already-measured owner buckets, never a
    new scan. Tells which part of JARVIS costs what instead of one number.
    """
    try:
        from jarvis.core import governor as governor_mod
        cpu = {k: float(v.get("cpu_pct") or 0.0) for k, v in owners.items()}
        rss = {k: int(v.get("rss_bytes") or 0) for k, v in owners.items()}
        return governor_mod.attribution(cpu, rss)
    except Exception:
        return {}


def _governor_advice(owners, processes):
    """Advisory-only governor input snapshot; enforcement lives elsewhere."""
    try:
        from jarvis.core import governor as governor_mod
        jarvis_rss = sum(int(v.get("rss_bytes") or 0)
                         for k, v in owners.items() if "jarvis" in k or "collector" in k)
        total_rss = sum(int(v.get("rss_bytes") or 0) for v in owners.values()) or 1
        jarvis_cpu = sum(float(v.get("cpu_pct") or 0.0)
                         for k, v in owners.items() if "jarvis" in k or "collector" in k)
        decision = governor_mod.decide(cpu_pct=jarvis_cpu,
                                       memory_pressure=False,
                                       disk_pressure=False,
                                       queue_depth=0, telemetry_backlog=0)
        return {"jarvis_cpu_pct": round(jarvis_cpu, 2),
                "jarvis_rss_share": round(jarvis_rss / total_rss, 4),
                "processes": len(processes),
                "decision": decision["reason"],
                "pause": decision["pause"]}
    except Exception:
        return {}
