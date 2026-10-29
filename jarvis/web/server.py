"""The local dashboard: served from the last stored snapshot, never from a scan.

Design constraints that shaped this:

  * The page must never wait for a scan. Every request is served from the last
    stored snapshot, so the dashboard is instant even while a 60-second Windows
    audit is running behind it.

  * Nothing binds beyond localhost. A dashboard listing your firewall gaps and
    running processes is exactly what an attacker would like to read, so the
    listener is 127.0.0.1 and there is no option to change that to 0.0.0.0.
"""

import hashlib
import json
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from jarvis.collectors.network import internetwatch
from jarvis.core import incidents, mechanisms
from jarvis.core.paths import SOURCE_ROOT, STATIC_DIR
from jarvis.core.store import DEFAULT_DB, Store
from jarvis.core.util import now
from jarvis.platform import procfeed
from jarvis.response import (
    acknowledge,
    advisor,
    alert,
    assistant,
    protocols,
    questions,
    remediation,
)
from jarvis.response.reporting import score, voice
from jarvis.service import attackmap, detectorhealth, sdnotify
from jarvis.service import posture as posture_mod
from jarvis.service import reliability as reliability_mod
from jarvis.service.protection import health
from jarvis.service.schedule import JOBS, NOT_APPLICABLE
from jarvis.service.scheduler import Scheduler, reliability_watchdog_loop, watchdog_loop
from jarvis.web import procview, stream
from jarvis.web import token as api_token

PAGE = str(STATIC_DIR / "dashboard.html")
GEO_PAGE = str(STATIC_DIR / "geo.html")
# The /coverage view and its two scripts, served from this origin only. The
# vendored three.js build is pinned: a file that no longer matches is refused,
# so a modified engine cannot run inside the dashboard's origin.
COVERAGE_ASSETS = {
    "/coverage": ("coverage.html", "text/html; charset=utf-8", None),
    "/static/coverage.js": ("coverage.js", "text/javascript; charset=utf-8", None),
    "/static/vendor/three.module.min.js": (
        "vendor/three.module.min.js", "text/javascript; charset=utf-8",
        "08fd7545d13d2c7fb65ab691530a802dafefd638596501854f267d0fb13c39e7"),
    # The /world view: same engine, same policy. Its map data is generated from
    # pinned Natural Earth files (scripts/tools/build_world_assets.py).
    "/world": ("world.html", "text/html; charset=utf-8", None),
    "/static/world.js": ("world.js", "text/javascript; charset=utf-8", None),
    # The /procs view: every process on both domains, live, read-only.
    "/procs": ("procs.html", "text/html; charset=utf-8", None),
    "/static/procs.js": ("procs.js", "text/javascript; charset=utf-8", None),
    "/static/procs-model.js": ("procs-model.js", "text/javascript; charset=utf-8", None),
    "/static/procs-state.js": ("procs-state.js", "text/javascript; charset=utf-8", None),
    "/static/procs-scene.js": ("procs-scene.js", "text/javascript; charset=utf-8", None),
    "/static/procs-layout.js": ("procs-layout.js", "text/javascript; charset=utf-8", None),
    "/static/vendor/world-50m.json": (
        "vendor/world-50m.json", "application/json",
        "bd89e13c5073e3fba5dbe16ca9231a1d7d7de5844961f426e9d35d95b4ec4a28"),
    # The dashboard's typeface: Inter 4.1 variable (SIL Open Font License 1.1,
    # vendor/InterVariable-LICENSE.txt), from the rsms/inter v4.1 release.
    "/static/vendor/InterVariable.woff2": (
        "vendor/InterVariable.woff2", "font/woff2",
        "693b77d4f32ee9b8bfc995589b5fad5e99adf2832738661f5402f9978429a8e3"),
}


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
_PERF_LOCK = threading.Lock()
_PERF_SAMPLE = {"at": 0.0, "ticks": 0, "write_bytes": 0}


def _performance_state(jobs, scheduler):
    """Cheap live daemon cost plus the schedule's measured duty cycle."""
    contributors = []
    for job in jobs:
        interval = max(1.0, float(job.get("interval") or 0))
        duration = max(0.0, float(job.get("duration") or 0))
        share = duration / interval * 100.0
        if duration:
            contributors.append({"name": job.get("name", ""),
                                 "label": job.get("label", ""),
                                 "duration": round(duration, 1),
                                 "duty_pct": round(share, 1)})
    contributors.sort(key=lambda row: row["duty_pct"], reverse=True)

    cpu_pct = None
    write_mib_s = None
    rss_bytes = 0
    service_bytes = 0
    stamp = time.monotonic()
    try:
        with open("/proc/self/stat", errors="replace") as fh:
            fields = fh.read().split(") ", 1)[1].split()
        ticks = int(fields[11]) + int(fields[12])
        hz = os.sysconf("SC_CLK_TCK")
        with open("/proc/self/statm", errors="replace") as fh:
            pages = int(fh.read().split()[1])
        rss_bytes = pages * os.sysconf("SC_PAGE_SIZE")
        with open("/proc/self/cgroup", errors="replace") as fh:
            cgroup = next((line.split(":", 2)[2].strip() for line in fh
                           if line.startswith("0::")), "")
        if cgroup and ".." not in cgroup.split("/"):
            with open("/sys/fs/cgroup" + cgroup + "/memory.current",
                      errors="replace") as fh:
                service_bytes = max(0, int(fh.read().strip()))
        with open("/proc/self/io", errors="replace") as fh:
            io_values = {k.rstrip(":"): int(v) for k, v in
                         (line.split(None, 1) for line in fh) if v.strip().isdigit()}
        writes = io_values.get("write_bytes", 0)
        with _PERF_LOCK:
            before_at = _PERF_SAMPLE["at"]
            before_ticks = _PERF_SAMPLE["ticks"]
            before_writes = _PERF_SAMPLE["write_bytes"]
            _PERF_SAMPLE.update(at=stamp, ticks=ticks, write_bytes=writes)
        elapsed = stamp - before_at
        if before_at and elapsed > 0 and ticks >= before_ticks:
            cpu_pct = (ticks - before_ticks) / hz / elapsed / max(1, os.cpu_count() or 1) * 100
            if writes >= before_writes:
                write_mib_s = (writes - before_writes) / elapsed / 1024 / 1024
    except (OSError, ValueError, IndexError):
        pass
    return {"cpu_pct": None if cpu_pct is None else round(cpu_pct, 1),
            "write_mib_s": None if write_mib_s is None else round(write_mib_s, 3),
            "rss_mib": round(rss_bytes / 1024 / 1024, 1),
            "service_memory_mib": round((service_bytes or rss_bytes) / 1024 / 1024, 1),
            "scheduled_duty_pct": round(sum(x["duty_pct"] for x in contributors), 1),
            "top": contributors[:6],
            "running": [n for n in (getattr(scheduler, "current", None),
                                      getattr(scheduler, "fast_current", None),
                                      getattr(scheduler, "bulk_current", None)) if n]}


def _intel_state(store):
    """Knowledge-base health, so the page shows what the hunt is hunting with.

    A hunt that finds nothing is only reassuring if the thing doing the hunting
    is current. Showing the indicator count, the age of each feed and the last
    refresh makes "no findings" mean something.
    """
    try:
        kinds = {r["kind"]: r["n"] for r in store.db.execute(
            "SELECT kind, COUNT(*) n FROM indicators WHERE status='active' "
            "GROUP BY kind ORDER BY n DESC")}
        feeds_rows = [dict(r) for r in store.db.execute(
            "SELECT name,last_run,rows,kept,error FROM feed_runs ORDER BY name")]
        hits = [dict(r) for r in store.db.execute(
            "SELECT ts,kind,value,host,severity,evidence FROM hunt_hits "
            "ORDER BY ts DESC LIMIT 20")]
        docs = store.db.execute(
            "SELECT COUNT(*) FROM intel_docs").fetchone()[0]
        today = time.strftime("%Y%m%d")
        return {
            "total": sum(kinds.values()),
            "kinds": kinds,
            "docs": docs,
            "feeds": feeds_rows,
            "hits": hits,
            "last_refresh": int(store.get_meta("intel_last_refresh", 0) or 0),
            "last_hunt": int(store.get_meta("hunt_last_run", 0) or 0),
            "spend_today": float(store.get_meta(f"intel_spend_{today}", 0) or 0),
            "spend_total": float(store.get_meta("intel_spend_total", 0) or 0),
        }
    except Exception:
        return {"total": 0, "kinds": {}, "docs": 0, "feeds": [], "hits": [],
                "last_refresh": 0, "last_hunt": 0,
                "spend_today": 0.0, "spend_total": 0.0}


def _meta_object(store, key):
    try:
        value = json.loads(store.get_meta(key, "{}") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _continuity_state(store, snaps, scheduler, findings):
    """Continuity systems for the dashboard: invariants, governor,
    perception, activity. Read-only, cheap, never raises.

    Sources are rebuilt from the already-loaded snapshots with the same
    freshness budgets the health endpoint uses, so both pages judge from
    one rulebook. Activity correlates a bounded slice of the findings the
    page already holds — no new scans, no new queries.
    """
    try:
        from jarvis.core import activity as activity_mod
        from jarvis.core import governor as governor_mod
        from jarvis.service import protection as protection_mod
        stamp = time.time()
        required, optional = mechanisms.health_sources(windows="win" in scheduler.hosts)
        sources = {}
        for name, limit in {**required, **optional}.items():
            snap = snaps.get(name)
            row = (name, snap["ts"], snap["error"],
                   json.dumps(snap["findings"])) if snap else None
            sources[name] = protection_mod._state(row, limit, stamp)
        invariants = protection_mod._invariants(sources, scheduler, stamp)
        pressured, reason = governor_mod.live_pressure()
        perception = _meta_object(store, "perception_summary_v1") or None
        chains = activity_mod.correlate(findings[:300], now=stamp)[:30]
        activity = [{**c, "members": c["members"][:6],
                     "member_overflow": max(0, len(c["members"]) - 6)}
                    for c in chains]
        return {"invariants": invariants,
                "governor": {"pressured": pressured, "reason": reason},
                "perception": perception, "activity": activity}
    except Exception:
        return {"invariants": None, "governor": None, "perception": None,
                "activity": []}


def build_state(db_path, scheduler):
    store = Store(db_path)
    try:
        snaps = store.get_snapshots()
        jobs, all_findings, all_checks = [], [], []
        for name, (interval, label) in JOBS.items():
            s = snaps.get(name)
            counts, ok_count = {}, 0
            if s:
                for f in s["findings"]:
                    sev = f.get("severity")
                    if sev == "ok":
                        # "Checked and found clean" is a result, not an absence
                        # of one. Without it the page cannot distinguish a check
                        # that passed from a check that never ran.
                        ok_count += 1
                        all_checks.append({**f, "job": name})
                    elif sev:
                        counts[sev] = counts.get(sev, 0) + 1
                        all_findings.append({**f, "job": name, "id": acknowledge.finding_id(f, name)})
            jobs.append({
                "name": name, "label": label, "interval": interval,
                "ts": s["ts"] if s else 0,
                "duration": round(s["duration"], 1) if s else 0,
                "error": (s["error"] or "")[:400] if s else "",
                "counts": counts, "ok": ok_count,
                "stale": bool(s and s["ts"]
                              and (time.time() - s["ts"]) > max(interval * 2,
                                                                interval + 300)),
                # Freshness budget (FRESH/LATE/DEGRADED/STALE) recovers before
                # the hard stale threshold above loses coverage. Unknown age
                # is STALE: no result is no result, never clean.
                "freshness": reliability_mod.classify(
                    (time.time() - s["ts"]) if s and s["ts"] else -1, interval),
                "running": name in (scheduler.current, getattr(scheduler, "fast_current", None),
                                    getattr(scheduler, "bulk_current", None)),
                "next": int(scheduler.next_run.get(name, 0) - time.time()),
            })

        all_findings.sort(key=lambda f: (SEV_ORDER.get(f.get("severity"), 9),
                                         f.get("job", "")))
        worst = all_findings[0]["severity"] if all_findings else "ok"
        totals = {}
        for f in all_findings:
            totals[f["severity"]] = totals.get(f["severity"], 0) + 1

        all_checks.sort(key=lambda f: (f.get("job", ""), f.get("title", "")))

        by_host = {}
        for f in all_findings:
            h = f.get("host") or "?"
            by_host.setdefault(h, {})
            by_host[h][f["severity"]] = by_host[h].get(f["severity"], 0) + 1

        by_category = {}
        for f in all_findings:
            c = f.get("category") or "other"
            by_category[c] = by_category.get(c, 0) + 1

        def _count(sql):
            try:
                return store.db.execute(sql).fetchone()[0]
            except Exception:
                return 0

        return {
            "now": now(),
            "worst": worst,
            "totals": totals,
            "by_host": by_host,
            "by_category": by_category,
            "jobs": jobs,
            "findings": all_findings[:1000],
            "findings_total": len(all_findings),
            "checks": all_checks,
            "history": store.get_history(24),
            "internet": internetwatch.latest(store),
            "peers": [dict(r) for r in store.list_peers(scope="public", limit=60)],
            "events": [dict(r) for r in store.list_events(limit=40)],
            "stats": {
                "procs": _count("SELECT COUNT(*) FROM procs"),
                "approved": _count("SELECT COUNT(*) FROM procs WHERE approved=1"),
                "peers": _count("SELECT COUNT(*) FROM peers"),
                "peers_public": _count(
                    "SELECT COUNT(*) FROM peers WHERE scope='public'"),
                "events": _count("SELECT COUNT(*) FROM events"),
            },
            "intel": _intel_state(store),
            # Live from the same snapshots the page shows; the trend comes
            # from the history the report job records every five minutes.
            "security": {**score.stable(store, JOBS, acks=acknowledge.load(store),
                                        live=score.compute(snaps, JOBS,
                                                           acks=acknowledge.load(store)),
                                        snapshots=snaps, phase=_wake_phase(scheduler)),
                         "history": score.history_of(store)[-300:]},
            "posture": posture_mod.build(
                snaps, JOBS, acks=acknowledge.load(store),
                sustained_samples=score.sustained_history_of(store),
                repair_state=remediation.audit(store)),
            "questions": questions.build(store, snaps, alert.load_conf())[:12],
            "attack": attackmap.latest(store),
            "baseline_at": store.get_meta("baseline_at"),
            "db": db_path,
            "reliability": _reliability_state(scheduler, snaps),
            "detector_health": _detector_health(store, scheduler, snaps),
            "assistant": _assistant_state(store),
            "performance": {**_performance_state(jobs, scheduler),
                            "subsystems": _meta_object(store, "resource_profile_v1"),
                            "accelerator": _meta_object(store, "accelerator_probe_v2")
                            or _meta_object(store, "accelerator_probe_v1")},
            "continuity": _continuity_state(store, snaps, scheduler, all_findings),
            "fix": _fix_state(db_path),
        }
    finally:
        store.close()


def _wake_phase(scheduler):
    """The scheduler's re-verification phase for the score. Never raises."""
    try:
        fn = getattr(scheduler, "wake_phase", None)
        return fn() if callable(fn) else {}
    except Exception:
        return {}


def _assistant_state(store):
    """Recent assistant activity, open proposals and what ARGUS-1 has changed. Never raises."""
    try:
        return {"audit": advisor.audit_log(store)[-25:],
                "pending": advisor.pending_proposals(store, JOBS),
                "changes": advisor.changes_summary(store)}
    except Exception:
        return {"audit": [], "pending": [], "changes": None}


def _detector_health(store, scheduler, snaps):
    """Per-detector health for the dashboard panel. Never raises."""
    try:
        status_fn = getattr(scheduler, "reliability_status", None)
        statuses = status_fn(snapshots=snaps).get("statuses", {}) if callable(status_fn) else {}
        rep = detectorhealth.report(JOBS, snaps, statuses, NOT_APPLICABLE)
        detectorhealth.record_transitions(store, rep)
        return rep
    except Exception:
        return {"detectors": [], "counts": {}, "total": 0, "attention": [],
                "summary": "Detector health is unavailable right now."}


def _reliability_state(scheduler, snaps):
    """Collector reliability plane for the dashboard. Never raises."""
    try:
        status_fn = getattr(scheduler, "reliability_status", None)
        if callable(status_fn):
            status = status_fn(snapshots=snaps)
            return {**status["summary"], "resume": status.get("resume") or {},
                    "outages": status.get("outages") or {}}
    except Exception:
        pass
    return {"levels": {}, "stale_collectors": [], "recovering": [],
            "violations": [], "expired_leases": []}


def _fix_state(db_path):
    """Open self-fix proposals waiting on the operator. Never raises."""
    try:
        from jarvis.response import report as agent_report
        from jarvis.response import selffix
        store = Store(db_path)
        try:
            return [{"report": agent_report.fix_report(e), "id": e["id"], "title": e.get("title", ""),
                     "status": e.get("status", ""), "problem": e.get("problem", ""),
                     "created_at": e.get("created_at", 0),
                     "generation_state": e.get("generation_state", ""),
                     "generation_error": e.get("generation_error", ""),
                     "patch_chars": len(e.get("patch_draft", "")),
                     "directive_objective": (e.get("directive") or {}).get("objective", ""),
                     "jev": ((e.get("jev") or {}).get("proposal") or {}).get("answers", {}),
                     "jev_validation": ((e.get("jev_validation") or e.get("jev") or {}).get("validation") or {}).get("answers", {}),
                     "last_event": (e.get("decision_history") or [{}])[-1]}
                    for e in selffix.list_open(store)]
        finally:
            store.close()
    except Exception:
        return []


_FIX_DRAFT_LOCK = threading.Lock()
_FIX_DRAFTS = set()


def _start_fix_draft(db_path, pid):
    """Start one bounded drafting worker without blocking dashboard health."""
    with _FIX_DRAFT_LOCK:
        if pid in _FIX_DRAFTS:
            return False
        _FIX_DRAFTS.add(pid)

    def run():
        from jarvis.response import fixdraft
        store = Store(db_path)
        try:
            try:
                fixdraft.generate(store, pid, repo=str(SOURCE_ROOT))
            except Exception as exc:
                fixdraft.record_failure(
                    store, pid, f"unexpected drafting failure: {type(exc).__name__}: {exc}")
        finally:
            store.close()
            with _FIX_DRAFT_LOCK:
                _FIX_DRAFTS.discard(pid)

    threading.Thread(target=run, name=f"jarvis-fix-{pid}", daemon=True).start()
    return True


# Binding to 127.0.0.1 is NOT sufficient on its own. A malicious page you visit
# can point a hostname it controls at 127.0.0.1 (DNS rebinding); the browser then
# treats that hostname as same-origin with this server and can read every
# response — which for this tool means handing over a complete map of the
# machine's firewall gaps, running processes and external peers. The defence is
# to check the Host header and serve only names we expect.
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}


class Handler(BaseHTTPRequestHandler):
    server_version = "JARVIS"
    db_path = DEFAULT_DB
    scheduler = None
    hub = None          # stream.Hub, shared by every /api/pulse and /api/stream client
    cover_hub = None    # stream.Hub for the /coverage page's live state

    def log_message(self, *a):
        pass  # the dashboard polls constantly; access logs would be noise

    def _host_ok(self):
        host = (self.headers.get("Host") or "").strip()
        # Strip the port; ports are not part of the rebinding decision.
        if host.startswith("["):                      # bracketed IPv6 literal
            name = host[: host.index("]") + 1] if "]" in host else host
        else:
            name = host.rsplit(":", 1)[0] if ":" in host else host
        return name.lower() in ALLOWED_HOSTS

    def _runner(self):
        """Queue one audit for the assistant, or None when no scheduler is attached."""
        scheduler = getattr(self, "scheduler", None)
        return scheduler.force if scheduler is not None else None

    def _same_origin(self):
        """Reject cross-site calls. Browsers that send Sec-Fetch-Site make this
        exact; for anything older we fall back to checking Origin."""
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None:
            return site in ("same-origin", "none")
        origin = self.headers.get("Origin")
        if not origin:
            return True  # curl and friends send no Origin at all
        return any(origin == f"http://{h}:{self.server.server_address[1]}"
                   for h in ("localhost", "127.0.0.1"))

    def _json_body(self, limit):
        """The request's JSON object, or None when it is missing, oversized or malformed."""
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            return None
        if length <= 0 or length > limit:
            return None
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except ValueError:
            return None
        return payload if isinstance(payload, dict) else None

    # The dashboard is self-contained and forbids anything external, except that
    # it may frame its own GeoSecurity page.
    CSP_STRICT = ("default-src 'none'; style-src 'unsafe-inline'; "
                  "script-src 'unsafe-inline'; connect-src 'self'; frame-src 'self'; "
                  "font-src 'self'; img-src data:")
    # The GeoSecurity globe is inherently external: the Cesium engine and the
    # satellite tiles come from named third parties, place-name lookup from
    # OpenStreetMap, and the 2D street map from OSM and Esri tiles. This
    # relaxation is scoped to the /geo page alone and names the exact
    # origins; every other route keeps the strict policy above.
    CSP_GEO = (
        "default-src 'none'; "
        "script-src 'unsafe-inline' 'wasm-unsafe-eval' https://cdn.jsdelivr.net; "
        "style-src 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: blob: https://gibs.earthdata.nasa.gov https://cdn.jsdelivr.net "
        "https://server.arcgisonline.com https://tiles.maps.eox.at "
        "https://tile.openstreetmap.org; "
        "connect-src 'self' blob: https://gibs.earthdata.nasa.gov "
        "https://cdn.jsdelivr.net https://nominatim.openstreetmap.org "
        "https://server.arcgisonline.com https://tiles.maps.eox.at "
        "https://tile.openstreetmap.org; "
        "worker-src blob: https://cdn.jsdelivr.net; child-src blob:; font-src data:")

    # /coverage runs no inline script and loads nothing from another origin.
    CSP_COVERAGE = ("default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
                    "connect-src 'self'; img-src data:")

    def _coverage_asset(self, path):
        name, ctype, digest = COVERAGE_ASSETS[path]
        try:
            with open(STATIC_DIR / name, "rb") as fh:
                body = fh.read()
        except OSError:
            return self._send(500, f"{name} missing", "text/plain")
        if digest and hashlib.sha256(body).hexdigest() != digest:
            return self._send(500, f"{name} does not match its pinned hash", "text/plain")
        return self._send(200, body, ctype, csp=self.CSP_COVERAGE)

    def _send(self, code, body, ctype="application/json", csp=None, cookie=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", csp or self.CSP_STRICT)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # The client closed the connection (a dashboard poll replaced by
            # the next one). Nothing to deliver, and nothing to log.
            self.close_connection = True

    def _hub(self):
        if Handler.hub is None:
            Handler.hub = stream.Hub(self.db_path, self.scheduler)
        return Handler.hub

    def _cover_hub(self):
        """One shared live state for every open /coverage page, rebuilt at most
        twice a second however many are listening, with its own bounded slots."""
        hub = Handler.cover_hub
        if hub is None or hub.db_path != self.db_path or hub.scheduler is not self.scheduler:
            from jarvis.service import coveragemap
            hub = Handler.cover_hub = stream.Hub(
                self.db_path, self.scheduler, period=coveragemap.LIVE_PERIOD_S,
                max_streams=coveragemap.LIVE_STREAMS, builder=coveragemap.live)
        return hub

    def _stream(self, hub=None, beat=None):
        """Server-Sent Events of the live pulse (see web/stream.py). `beat` is
        the interval of a visible heartbeat, for pages that show liveness."""
        # Checked before a slot is taken: a cross-site page cannot read the
        # stream, but without this it could still hold every slot open.
        if not self._same_origin():
            return self._send(403, json.dumps({"error": "cross-site"}))
        hub = hub or self._hub()
        if not hub.acquire():
            return self._send(503, json.dumps({"error": "too many live streams; poll /api/pulse"}))
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", self.CSP_STRICT)
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

            def write(chunk):
                self.wfile.write(chunk)
                self.wfile.flush()

            try:
                options = {"keepalive": beat, "beat": True} if beat else {}
                stream.run_stream(hub, write,
                                  gone=lambda: stream.peer_closed(self.connection), **options)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass  # the client left; nothing to deliver
        finally:
            hub.release()
            self.close_connection = True

    def _procs_stream(self):
        """Server-Sent Events of the live process table (web/procview.py). The
        feed behind it runs only while at least one of these is open."""
        if not self._same_origin():
            return self._send(403, json.dumps({"error": "cross-site"}))
        if not procview.acquire_slot():
            return self._send(503, json.dumps({"error": "too many process views open"}))
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", self.CSP_STRICT)
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

            def write(chunk):
                self.wfile.write(chunk)
                self.wfile.flush()

            try:
                from jarvis.web import procidentity
                feed = procfeed.shared(identity=procidentity.shared(self.db_path))
                procview.run(feed, write,
                             gone=lambda: stream.peer_closed(self.connection))
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass  # the viewer left
        finally:
            procview.release_slot()
            self.close_connection = True

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, json.dumps({"error": "bad host"}))
        url = urlparse(self.path)
        # Browser extensions are deliberately not same-origin with the dashboard.
        # This one write-only route is instead paired with a high-entropy token,
        # has a tiny schema, returns no observations, and stores only aggregate
        # metadata.  Keep it before the dashboard's same-origin gate.
        if url.path == "/api/veil/events":
            from jarvis.collectors.host.veil import classify, validate_report
            from jarvis.core.veil import TOKEN_KEY
            payload = self._json_body(8192)
            token = self.headers.get("X-JARVIS-Veil-Token", "")
            store = Store(self.db_path)
            try:
                expected = store.get_meta(TOKEN_KEY) or ""
                if not expected or not secrets.compare_digest(token, expected):
                    return self._send(403, json.dumps({"error": "not paired"}))
                report = validate_report(payload)
                if report is None:
                    return self._send(400, json.dumps({"error": "invalid metadata-only report"}))
                findings = classify(report)
                # A benign aggregate report is still a durable coverage receipt.
                store.record_observation("veil", findings, coverage="complete")
                # The dashboard and local incident history need the same
                # bounded metadata-only result.  This route intentionally does
                # not send email or trigger containment from browser content.
                store.save_snapshot("veil", findings)
                return self._send(202, json.dumps({"accepted": True, "findings": len(findings)}))
            finally:
                store.close()
        if not self._same_origin():
            return self._send(403, json.dumps({"error": "cross-site request"}))
        # Every state-changing route needs the per-start token (header or the
        # dashboard's cookie). See jarvis/web/token.py for what this does and
        # does not close.
        if not api_token.accepts(self.headers):
            return self._send(403, json.dumps({"error": "missing or wrong API token"}))
        if url.path == "/api/run":
            job = (parse_qs(url.query).get("job") or [""])[0]
            ok = self.scheduler.force(job)
            return self._send(200 if ok else 404, json.dumps({"queued": ok}))
        if url.path == "/api/ask":
            payload = self._json_body(16_384)
            if payload is None:
                return self._send(400, json.dumps({"error": "invalid request"}))
            question = str(payload.get("question") or "")[:4000]
            offer = payload.get("offer") if isinstance(payload.get("offer"), dict) else None
            store = Store(self.db_path)
            try:
                result = assistant.answer(store, question, jobs=JOBS, offer=offer,
                                          runner=self._runner())
            finally:
                store.close()
            return self._send(200, json.dumps(result))
        if url.path == "/api/assistant/action":
            # The assistant's only door to doing anything. advisor validates the
            # action against its capability table; changes need propose+approve.
            payload = self._json_body(4096)
            if payload is None:
                return self._send(400, json.dumps({"error": "invalid request"}))
            store = Store(self.db_path)
            try:
                result = advisor.handle_action(
                    store, JOBS, str(payload.get("op") or "")[:12], payload.get("action"),
                    payload.get("target"), str(payload.get("token") or "")[:64],
                    runner=self._runner(), conf=alert.load_conf())
            finally:
                store.close()
            return self._send(200, json.dumps(result))
        if url.path == "/api/score-coach":
            # Deterministic: the score's real projection, no model, no waiting.
            store = Store(self.db_path)
            try:
                answer = assistant.score_coach(store, JOBS)
                now_score = None
                try:
                    state = protocols.evaluate(store, JOBS)
                    now_score = state[0]["score_now"] if state else None
                except Exception:
                    pass
            finally:
                store.close()
            return self._send(200, json.dumps({"answer": answer, "source": "coach",
                                               "score": now_score}))
        if url.path == "/api/voice":
            # POST, not GET: a model call costs seconds of CPU, so a cross-site
            # page must not be able to trigger one with an <img> tag.
            payload = self._json_body(1024) or {}
            try:
                live = max(0, min(99, int(payload.get("live_alerts") or 0)))
            except (TypeError, ValueError):
                live = 0
            store = Store(self.db_path)
            try:
                facts = assistant.spoken_facts(store, JOBS, live_alerts=live)
            finally:
                store.close()
            line, by_model = voice.spoken_opener(alert.load_conf(), facts)
            return self._send(200, json.dumps({"line": line, "by_model": by_model}))
        if url.path == "/api/brief":
            payload = self._json_body(4096)
            if payload is None:
                return self._send(400, json.dumps({"error": "invalid request"}))
            store = Store(self.db_path)
            try:
                ok, message = protocols.answer(store, str(payload.get("protocol") or "")[:40],
                                               str(payload.get("choice") or "")[:8])
                follow = assistant.greeting(store, JOBS)
            finally:
                store.close()
            return self._send(200 if ok else 400, json.dumps(
                {"ok": ok, "message": message, "pending": follow["pending"]}))
        if url.path == "/api/geo/here":
            from jarvis.service import geosecurity
            payload = self._json_body(2048)
            if payload is None:
                return self._send(400, json.dumps({"error": "invalid request"}))
            store = Store(self.db_path)
            try:
                if payload.get("clear"):
                    geosecurity.clear_here(store)
                    return self._send(200, json.dumps({"ok": True, "cleared": True}))
                try:
                    lat, lon = float(payload["lat"]), float(payload["lon"])
                except (KeyError, TypeError, ValueError):
                    return self._send(400, json.dumps({"error": "lat and lon required"}))
                try:
                    geosecurity.set_here(store, lat, lon, str(payload.get("label") or "")[:80])
                except ValueError as exc:
                    return self._send(400, json.dumps({"error": str(exc)}))
                return self._send(200, json.dumps({"ok": True}))
            finally:
                store.close()
        if url.path == "/api/geo/zone":
            # Same trust model as /api/geo/here: localhost + same-origin POST
            # from you editing your own trusted zones on the /geo page.
            from jarvis.service import geosecurity
            payload = self._json_body(2048)
            if payload is None:
                return self._send(400, json.dumps({"error": "invalid request"}))
            store = Store(self.db_path)
            try:
                if payload.get("remove"):
                    geosecurity.remove_zone(store, str(payload["remove"])[:80])
                    return self._send(200, json.dumps({"ok": True, "removed": True}))
                name = str(payload.get("name") or "").strip()[:80]
                if not name:
                    return self._send(400, json.dumps({"error": "zone name required"}))
                if "lat" not in payload or "lon" not in payload:
                    # In-place edit of radius/address/kind; nothing moves.
                    radius = payload.get("radius_m")
                    if radius is not None:
                        try:
                            radius = int(radius)
                        except (TypeError, ValueError):
                            return self._send(400, json.dumps(
                                {"error": "radius_m must be a number"}))
                    try:
                        zones = geosecurity.update_zone(
                            store, name, radius_m=radius,
                            address=payload.get("address"),
                            kind=payload.get("kind"))
                    except (TypeError, ValueError) as exc:
                        return self._send(400, json.dumps({"error": str(exc)}))
                    return self._send(200, json.dumps({"ok": True, "zones": len(zones)}))
                try:
                    lat, lon = float(payload["lat"]), float(payload["lon"])
                except (KeyError, TypeError, ValueError):
                    return self._send(400, json.dumps({"error": "lat and lon required"}))
                try:
                    radius = int(payload.get("radius_m", 200))
                except (TypeError, ValueError):
                    return self._send(400, json.dumps({"error": "radius_m must be a number"}))
                try:
                    zones = geosecurity.add_zone(
                        store, name, lat, lon, radius,
                        address=str(payload.get("address") or "")[:200],
                        kind=str(payload.get("kind") or "")[:20])
                except ValueError as exc:
                    return self._send(400, json.dumps({"error": str(exc)}))
                return self._send(200, json.dumps({"ok": True, "zones": len(zones)}))
            finally:
                store.close()

        if url.path == "/api/answer":
            payload = self._json_body(4096)
            if payload is None:
                return self._send(400, json.dumps({"error": "invalid request"}))
            qid = str(payload.get("id") or "")[:32]
            choice = str(payload.get("choice") or "")[:16]
            store = Store(self.db_path)
            try:
                ok, message = questions.answer(store, qid, choice)
            finally:
                store.close()
            return self._send(200 if ok else 400,
                              json.dumps({"ok": ok, "message": message}))
        if url.path in ("/api/fix/approve", "/api/fix/authorize",
                        "/api/fix/retry", "/api/fix/reject"):
            # Same trust model as /api/answer above: localhost + same-origin
            # POST from you clicking a button. This records intent only —
            # applying stays a terminal command (`jarvis fix apply <id>`),
            # and email replies can never reach this path.
            from jarvis.response import selffix
            payload = self._json_body(4096)
            if payload is None:
                return self._send(400, json.dumps({"error": "invalid request"}))
            pid = str(payload.get("id") or "")[:16]
            if not re.match(r"^fx-[0-9a-f]{8}$", pid):
                return self._send(400, json.dumps({"error": "unknown proposal"}))
            store = Store(self.db_path)
            try:
                if url.path.endswith("approve"):
                    ok, message = selffix.approve(store, pid, by="dashboard")
                elif url.path.endswith("authorize"):
                    ok, message = selffix.authorize_apply(store, pid, by="dashboard")
                elif url.path.endswith("retry"):
                    entry = selffix.get(store, pid)
                    ok = bool(entry and entry.get("status") == "draft_failed")
                    message = (f"draft retry queued for {pid}" if ok else
                               f"{pid} is not awaiting a draft retry")
                else:
                    ok, message = selffix.reject(
                        store, pid, str(payload.get("reason") or "")[:300],
                        by="dashboard")
            finally:
                store.close()
            if ok and (url.path.endswith("approve") or url.path.endswith("retry")):
                _start_fix_draft(self.db_path, pid)
            return self._send(200 if ok else 400,
                              json.dumps({"ok": ok, "message": message}))
        return self._send(404, json.dumps({"error": "not found"}))

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, "forbidden: unexpected Host header\n"
                                   "reach this dashboard as http://localhost:PORT",
                              "text/plain")
        url = urlparse(self.path)
        if url.path in ("/", "/index.html"):
            try:
                with open(PAGE, "r", encoding="utf-8", errors="replace") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8",
                                      cookie=api_token.cookie_header())
            except OSError:
                return self._send(500, "dashboard.html missing", "text/plain")

        if url.path == "/api/greeting":
            store = Store(self.db_path)
            try:
                return self._send(200, json.dumps(assistant.greeting(store, JOBS)))
            finally:
                store.close()

        if url.path == "/api/state":
            return self._send(200, json.dumps(
                build_state(self.db_path, self.scheduler), default=str))

        if url.path == "/api/pulse":
            return self._send(200, json.dumps(self._hub().latest(), default=str))

        if url.path == "/api/stream":
            return self._stream()

        if url.path in ("/api/posture", "/api/posture/path-to-100"):
            from jarvis.service import posture
            store = Store(self.db_path)
            try:
                payload = posture.build(
                    store.get_snapshots(), JOBS,
                    acks=acknowledge.load(store),
                    sustained_samples=score.sustained_history_of(store),
                    repair_state=remediation.audit(store))
            finally:
                store.close()
            return self._send(200, json.dumps(payload))

        if url.path == "/api/defender":
            params = parse_qs(url.query)
            try:
                limit = max(1, min(500, int((params.get("limit") or ["100"])[0])))
            except ValueError:
                return self._send(400, json.dumps({"error": "limit must be an integer"}))
            store = Store(self.db_path)
            try:
                incident_id = (params.get("id") or [""])[0]
                result = (incidents.detail(store.db, incident_id, limit) if incident_id
                          else incidents.overview(store.db, limit))
            finally:
                store.close()
            if result is None:
                return self._send(404, json.dumps({"error": "unknown incident"}))
            return self._send(200, json.dumps(result))

        if url.path in COVERAGE_ASSETS:
            return self._coverage_asset(url.path)

        if url.path == "/api/coverage/live":
            return self._send(200, json.dumps(self._cover_hub().latest(), default=str))

        if url.path == "/api/coverage/stream":
            from jarvis.service import coveragemap
            return self._stream(self._cover_hub(), beat=coveragemap.LIVE_BEAT_S)

        if url.path == "/api/procs/stream":
            return self._procs_stream()

        if url.path == "/api/procs/baseline":
            # Names this machine has seen before, for the /procs change lens.
            # Metadata only and cached (web/procbaseline.py).
            if not self._same_origin():
                return self._send(403, json.dumps({"error": "cross-site"}))
            from jarvis.web import procbaseline
            return self._send(200, json.dumps(procbaseline.shared.get(self.db_path)))

        if url.path == "/api/coverage":
            from jarvis.service import coveragemap
            return self._send(200, json.dumps(
                coveragemap.build(self.db_path, self.scheduler), default=str))

        if url.path == "/geo":
            try:
                with open(GEO_PAGE, "r", encoding="utf-8", errors="replace") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8",
                                      csp=self.CSP_GEO)
            except OSError:
                return self._send(500, "geo.html missing", "text/plain")

        if url.path == "/api/geo":
            from jarvis.service import geosecurity
            # The geo payload needs only hot findings and liveness, not the
            # full dashboard state: build_state() serializes every finding,
            # score and intel feed (measured 0.6–3 s for a 2 KB response).
            # Snapshots + geo fusion answer the same question in ~5 ms.
            hstate = health(self.db_path, self.scheduler)
            store = Store(self.db_path)
            try:
                try:
                    snaps = store.get_snapshots()
                except Exception:
                    snaps = {}
                recent = [f for s in snaps.values()
                          for f in (s.get("findings") or [])
                          if isinstance(f, dict)
                          and f.get("severity") in ("critical", "high")]
                payload = geosecurity.state(store, health_state=hstate, recent_findings=recent)
            finally:
                store.close()
            return self._send(200, json.dumps(payload, default=str))

        if url.path == "/api/world":
            from jarvis.collectors.host import geo
            from jarvis.intel import worldwatch
            # Stored reports plus distances worked out here. The device position
            # is read locally and returned only to this loopback page.
            store = Store(self.db_path)
            try:
                payload = worldwatch.state(
                    store, location=geo.effective(store, geo.current(store)),
                    trusted=geo.get_zones(store))
            finally:
                store.close()
            return self._send(200, json.dumps(payload, default=str))

        if url.path == "/api/arena":
            from jarvis.lab import regression
            reg = regression.Regression()
            try:
                summary = reg.summary()
                summary["scenarios_detail"] = [
                    {"id": r["id"], "title": r["title"], "safety": r["safety"],
                     "source": r["source"], "techniques": json.loads(r["techniques"] or "[]"),
                     "last": (lambda x: {"score": x["score"], "ok": bool(x["ok"]),
                                         "at": x["at"]} if x else None)(reg.latest(r["id"]))}
                    for r in reg.scenarios()]
            finally:
                reg.close()
            return self._send(200, json.dumps(summary, default=str))

        if url.path == "/metrics":
            from jarvis.web import metrics
            try:
                return self._send(200, metrics.cached(self.db_path, self.scheduler),
                                  metrics.CONTENT_TYPE)
            except metrics.Unavailable as exc:
                return self._send(503, f"store unavailable: {exc}\n", "text/plain")

        if url.path in ("/api/health", "/api/live"):
            state = health(self.db_path, self.scheduler)
            ok = state['live'] if url.path == '/api/live' else state['healthy']
            return self._send(200 if ok else 503, json.dumps(state))

        # /api/run is a state-changing action, so it is POST-only: a cross-site
        # page cannot force one without a preflight it will not survive.
        if url.path == "/api/run":
            return self._send(405, json.dumps({"error": "use POST"}))

        return self._send(404, json.dumps({"error": "not found"}))


def serve(db_path=DEFAULT_DB, port=8787, hosts=("wsl", "win")):
    # Before any thread exists: keep the visibility capabilities for our own
    # reads, never for the programs we launch. See platform/privilege.py.
    from jarvis.platform import privilege
    privilege.drop_ambient()
    scheduler = Scheduler(db_path, hosts)
    scheduler.start()
    # Execution identities (docs/architecture/EVIDENCE-FABRIC.md): issued only
    # when this sealed daemon can read the root-owned key. Never raises.
    from jarvis.platform.provenance import authority
    print(f"provenance authority: {authority.start()}", flush=True)

    # Tell systemd we are up, then keep the watchdog fed for as long as the
    # scheduler is actually making progress. Both are no-ops when not run under
    # a systemd unit that asked for them.
    sdnotify.ready()
    sdnotify.status(f"scheduling {len(JOBS)} jobs")
    wd = threading.Thread(target=watchdog_loop, args=(scheduler,),
                          name="jarvis-watchdog", daemon=True)
    wd.start()
    # Collector reliability plane: independent health loop that queues LATE
    # collectors and expires dead leases, so staleness is recovered before
    # the score loses coverage.
    rel = threading.Thread(target=reliability_watchdog_loop, args=(scheduler,),
                           name="jarvis-reliability", daemon=True)
    rel.start()

    Handler.db_path = db_path
    Handler.scheduler = scheduler
    api_token.issue()               # fresh per start; 0600 beside the store
    Handler.hub = stream.Hub(db_path, scheduler)
    Handler.cover_hub = None        # built on first use, for this database and scheduler
    # Localhost only, deliberately and without an override.
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    # flush=True so journalctl shows these immediately under systemd, where
    # stdout is a pipe and would otherwise stay buffered indefinitely.
    print(f"JARVIS dashboard  \u2192  http://127.0.0.1:{port}", flush=True)
    print(f"  watching {'+'.join(hosts)};  database {db_path}", flush=True)
    print("  jobs: " + ", ".join(f"{n} every {v[0]}s" for n, v in JOBS.items()),
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
