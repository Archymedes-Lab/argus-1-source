"""JARVIS Runtime bridge: hot-path prototype in Rust, intelligence in Python.

Phase 4: the Python engine calls the optional binary for live metrics,
governance, and durable append/verification of an independent Rust segment
store. The established Python event log remains authoritative; there is no
unsafe claim that two separately committed stores form one atomic journal.
Python also owns policies, incidents, reasoning and models.

The binary is optional: when absent (dev checkout, unbuilt tree) every
helper falls back to the pure-Python path and reports
`{"runtime": "python"}` so no caller can mistake the fallback for the
measured Rust path.
"""

from __future__ import annotations

import json
import math
import os
import subprocess
from pathlib import Path

_RUNTIME_CANDIDATES = (
    Path(__file__).resolve().parents[2] / "rust-runtime" / "target" / "release" / "jarvis-runtime",
    Path(__file__).resolve().parents[2] / "rust-runtime" / "target" / "debug" / "jarvis-runtime",
)
DEFAULT_STORE = Path(os.path.expanduser("~/.jarvis/rust-eventlog"))


def binary():
    for path in _RUNTIME_CANDIDATES:
        try:
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
        except OSError:
            continue
    return None


def available():
    return binary() is not None


def _invoke(*args):
    """Run one bounded CLI probe and return (stdout, failure_kind)."""
    path = binary()
    if path is None:
        return None, "binary_absent"
    try:
        out = subprocess.run(
            [path, *args], capture_output=True, text=True, errors="replace",
            timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return None, "execution_failed"
    if out.returncode != 0:
        return None, "nonzero_exit"
    stdout = out.stdout or ""
    if len(stdout) > 64 * 1024:
        return None, "oversized_output"
    return stdout, None


def metrics():
    """Live host-pressure metrics. Prefers the Rust probe; falls back pure."""
    stdout, rust_error = _invoke("metrics")
    if stdout is not None:
        try:
            data = json.loads(stdout)
            cpu = data.get("cpu_pct")
            mem = data.get("mem_available_pct")
            reason = data.get("reason")
            valid_numbers = (
                isinstance(cpu, (int, float)) and not isinstance(cpu, bool)
                and math.isfinite(cpu) and cpu >= 0
                and isinstance(mem, (int, float)) and not isinstance(mem, bool)
                and math.isfinite(mem) and 0 <= mem <= 100
            )
            if (isinstance(data, dict)
                    and type(data.get("pressured")) is bool
                    and isinstance(reason, str) and reason
                    and valid_numbers):
                return {"runtime": "rust", "cpu_pct": cpu,
                        "mem_available_pct": mem,
                        "pressured": data["pressured"], "reason": reason}
            rust_error = "invalid_output"
        except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
            rust_error = "invalid_output"
    try:
        from jarvis.core import governor as governor_mod
        pressured, reason = governor_mod.live_pressure()
        return {"runtime": "python", "pressured": pressured,
                "reason": reason, "rust_status": rust_error}
    except Exception:
        return {"runtime": "python", "pressured": False,
                "reason": "metrics unavailable; all tiers permitted",
                "rust_status": rust_error}


def should_defer(job_name, pressured):
    """Governance decision; identical contract in Rust and Python."""
    stdout, rust_error = _invoke(
        "defer", str(job_name), "true" if pressured else "false")
    if stdout is not None:
        value = stdout.strip().lower()
        if value in ("true", "false"):
            return {"runtime": "rust", "defer": value == "true"}
        rust_error = "invalid_output"
    try:
        from jarvis.core import governor as governor_mod
        return {"runtime": "python",
                "defer": governor_mod.should_defer(job_name, pressured),
                "rust_status": rust_error}
    except Exception:
        return {"runtime": "python", "defer": False,
                "rust_status": rust_error}


def persist(events, root=None):
    """Durably append canonical events to the verified Rust segment store."""
    path = binary()
    if path is None:
        return {"ok": False, "runtime": "python", "error": "binary_absent"}
    events = list(events)
    if len(events) > 20_000 or any(not isinstance(event, dict)
                                   for event in events):
        return {"ok": False, "runtime": "rust", "error": "invalid_events"}
    try:
        body = "".join(json.dumps(event, separators=(",", ":")) + "\n"
                       for event in events)
    except (TypeError, ValueError):
        return {"ok": False, "runtime": "rust", "error": "invalid_events"}
    store = Path(root or DEFAULT_STORE)
    try:
        out = subprocess.run(
            [path, "ingest", str(store)], input=body, capture_output=True,
            text=True, errors="replace", timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return {"ok": False, "runtime": "rust", "error": "execution_failed"}
    if out.returncode != 0 or len(out.stdout or "") > 1024 * 1024:
        return {"ok": False, "runtime": "rust", "error": "ingest_failed"}
    try:
        rows = [json.loads(line) for line in (out.stdout or "").splitlines()]
    except (TypeError, ValueError):
        return {"ok": False, "runtime": "rust", "error": "invalid_output"}
    if len(rows) != len(events) + 1 \
            or any(row.get("ok") is not True for row in rows) \
            or rows[-1].get("persisted") is not True:
        return {"ok": False, "runtime": "rust", "error": "invalid_output"}
    return {"runtime": "rust", **rows[-1], "events": len(events),
            "root": str(store)}


def verify_store(root=None):
    """Verify every durable Rust segment and return its measured chain head."""
    path = binary()
    if path is None:
        return {"ok": False, "runtime": "python", "error": "binary_absent"}
    store = Path(root or DEFAULT_STORE)
    if not store.is_dir():
        return {"ok": False, "runtime": "rust", "error": "store_absent",
                "root": str(store)}
    try:
        out = subprocess.run(
            [path, "verify", str(store)], capture_output=True, text=True,
            errors="replace", timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return {"ok": False, "runtime": "rust", "error": "execution_failed"}
    if out.returncode != 0 or len(out.stdout or "") > 64 * 1024:
        return {"ok": False, "runtime": "rust", "error": "verify_failed"}
    try:
        result = json.loads(out.stdout)
    except (TypeError, ValueError):
        return {"ok": False, "runtime": "rust", "error": "invalid_output"}
    if (not isinstance(result, dict) or result.get("ok") is not True
            or not isinstance(result.get("segments"), int)
            or not isinstance(result.get("last_seq"), int)):
        return {"ok": False, "runtime": "rust", "error": "invalid_output"}
    return {"runtime": "rust", **result, "root": str(store)}
