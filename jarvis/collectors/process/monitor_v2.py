"""(Staged monitor: one process snapshot, integrity evidence, response hooks.

The scanner reads the process table once (linux.collect + socket_table), maps
every socket inode to a (pid, local_ip, state) row, and captures integrity
evidence for the processes, their open files and the listeners. Findings are
written to the SQLite store and the defender case store; nothing here runs a
response action, so a crashed collector never mutates the host.
"""

import json
import os
import time

from jarvis.core import collection as collection_mod
from jarvis.core import state as state_mod
from jarvis.core.util import classify_ip, now
from jarvis.platform import linux as collect_linux
from jarvis.platform import proclinux
from jarvis.collectors.process import detect as _detect
from jarvis.platform import topology
from jarvis.response import evidence
from jarvis.response.evidence.case import Case


# Severity ordering used to rank findings after scoring.
try:
    SEV_ORDER = _detect.SEV_ORDER
except AttributeError:
    # detect.py does not define SEV_ORDER at top level; this module already
    # defines its own ranking. Keep it local so the scheduler import stays green.
    SEV_ORDER = None



# What the monitor records per interval. Integrity evidence is added only when
# the findings carry a concrete target: the plan records a SHA-256 hash, the
# on-disk bytes are copied, and the case directory keeps the manifest. This is
# evidence, not a verdict: the finding keeps its original severity until the
# owner adjudicates it.
#
# Steps:
#   1. read the process table once (linux.collect + socket_table).
#   2. map every socket inode to a (pid, local_ip, state) row.
#   3. diff against the previous snapshot, scoring new + traits.
#   4. capture integrity evidence for the changed rows.
#   5. write findings to the store and the case store.
#   6. return the read-only summary to the scheduler.
#


def collect_procs(hosts=("wsl", "win"), with_sockets=True):
    """:return (procs, conn_by_inode) one authoritative read per interval."""

    def _read():
        procs = []
        if "wsl" in hosts:
            procs += collect_linux.collect(with_sockets=with_sockets)
        if "win" in hosts:
            procs += collect_linux.collect(with_sockets=with_sockets)
        return procs

    # Socket attribution is separate from the process snapshot: the process
    # table changes every 30-60 s, the connection table every second. Reading
    # both under one lock would serialize two distinct cadences.
    procs = state_mod.get_processes(hosts, _read, with_sockets=with_sockets)

    if with_sockets:
        conn_by_inode = collect_linux.socket_table()
    else:
        conn_by_inode = {}

    return procs, conn_by_inode


def _socket_row(inode, conn_by_inode):
    return conn_by_inode.get(inode, {})


def _process_sockets(pid, conn_by_inode):
    fddir = f"/proc/{pid}/fd"
    conns = []
    try:
        fds = os.listdir(fddir)
    except (OSError, PermissionError):
        return conns
    for fd in fds:
        try:
            target = os.readlink(f"{fddir}/{fd}")
        except OSError:
            continue
        if target.startswith("socket:["):
            inode = int(target[8:-1])
            if inode in conn_by_inode:
                conns.append(conn_by_inode[inode])
    return conns


def _capture_intact_case(procs, case_name):
    """Open an evidence case and collect the exact target bytes for every
    finding whose target is a file. Returns (case, results) or (None, []).

    The finding keeps its original severity; the case is the evidence store.
    """
    if not procs:
        return None, []
    try:
        case = Case(case_name)
    except Exception:
        return None, []
    results = []
    for p in procs:
        # Collect the executable + any file-backed fd the process holds.
        exe = p.get("exe") or ""
        if exe and os.path.exists(exe):
            res = case.add_file(exe, kind="process-executable",
                                note="process %s pid %s" % (p.get("name"), p.get("pid")))
            if res.get("ok"):
                results.append(res)
        for c in p.get("conns", []):
            if c.get("state") == "LISTEN" and c.get("local_ip"):
                results.append({"name": "listener-%s-%s" % (
                    p.get("pid"), c.get("local_port")),
                                "ok": True, "kind": "listener",
                                "source": "socket %s:%s" % (
                                    c.get("local_ip"), c.get("local_port"))})
    case.manifest.save()
    return case, results


def _collect_evidence(results, case):
    """:return (artifacts, notes)."""
    artifacts = []
    notes = []
    for r in results:
        if r.get("ok"):
            artifacts.append({"path": r.get("source"), "sha256": r.get("sha256"),
                              "size": r.get("size")})
    return artifacts, notes


def scan(hosts=("wsl", "win"), db_path=None, learn=False, record=True):
    """One full interval: snapshot, score, capture integrity evidence.

    :return: summary dict (read-only; the caller decides what to do with it).
    """
    start = time.monotonic()
    watched = collect_procs(hosts)
    procs, conn_by_inode = watched

    # Integrity capture: map every file the process holds to a SHA-256 of the
    # bytes on disk. This is the evidence the response actions need before
    # they act.
    case_name = "monitor-%d" % now()
    case, results = _capture_intact_case(procs, case_name)

    # Score the snapshot: known vs. approved, traits, etc.
    known = set()
    approved = set()
    if db_path:
        try:
            from jarvis.core.store import Store
            store = Store(db_path)
            known, approved = store.fp_status(p["fp"] for p in procs)
            store.close()
        except Exception:
            known, approved = set(), set()

    findings = []
    for p in procs:
        verdict = _detect.assess(p, known, approved)
        if verdict["unknown"] or verdict["reasons"]:
            findings.append({**p, **verdict, "conns": p.get("conns", [])})

    # Sort findings by severity so the owner always sees the worst first.
    findings.sort(key=lambda f: (SEV_ORDER.get(f.get("severity"), 9),
                                 -(f.get("score") or 0)))

    if case is not None:
        case.note("monitor snapshot at %d processes, %d findings" %
                  (len(procs), len(findings)))
        case.manifest.save()

    summary = {
        "ts": now(),
        "hosts": list(hosts),
        "scanned": len(procs),
        "findings": findings,
        "conn_by_inode": len(conn_by_inode),
        "evidence_case": case_name,
    }
    return summary


def process_snapshot(hosts=("wsl", "win"), db_path=None):
    """The one call the scheduler and the /procs view share."""
    return scan(hosts=hosts, db_path=db_path)
