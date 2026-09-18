"""The local dashboard: served from the last stored snapshot, never from a scan.

Design constraints that shaped this:

  * The page must never wait for a scan. Every request is served from the last
    stored snapshot, so the dashboard is instant even while a 60-second Windows
    audit is running behind it.

  * Nothing binds beyond localhost. A dashboard listing your firewall gaps and
    running processes is exactly what an attacker would like to read, so the
    listener is 127.0.0.1 and there is no option to change that to 0.0.0.0.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from jarvis.collectors.network import internetwatch
from jarvis.core import incidents
from jarvis.core.paths import STATIC_DIR
from jarvis.core.store import DEFAULT_DB, Store
from jarvis.core.util import now
from jarvis.response import acknowledge, alert, assistant, protocols, questions
from jarvis.response.reporting import score, voice
from jarvis.service import attackmap, sdnotify
from jarvis.service.protection import health
from jarvis.service.schedule import JOBS
from jarvis.service.scheduler import Scheduler, watchdog_loop

PAGE = str(STATIC_DIR / "dashboard.html")
GEO_PAGE = str(STATIC_DIR / "geo.html")


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


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
                        all_findings.append({**f, "job": name})
            jobs.append({
                "name": name, "label": label, "interval": interval,
                "ts": s["ts"] if s else 0,
                "duration": round(s["duration"], 1) if s else 0,
                "error": (s["error"] or "")[:400] if s else "",
                "counts": counts, "ok": ok_count,
                "stale": bool(s and s["ts"]
                              and (time.time() - s["ts"]) > max(interval * 2,
                                                                interval + 300)),
                "running": name in (scheduler.current, getattr(scheduler, "fast_current", None)),
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
            "security": {**score.compute(snaps, JOBS, acks=acknowledge.load(store)),
                         "history": score.history_of(store)[-300:]},
            "questions": questions.build(store, snaps, alert.load_conf())[:12],
            "attack": attackmap.latest(store),
            "baseline_at": store.get_meta("baseline_at"),
            "db": db_path,
        }
    finally:
        store.close()


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

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # The page is entirely self-contained; forbid anything external.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, json.dumps({"error": "bad host"}))
        if not self._same_origin():
            return self._send(403, json.dumps({"error": "cross-site request"}))
        url = urlparse(self.path)
        if url.path == "/api/run":
            job = (parse_qs(url.query).get("job") or [""])[0]
            ok = self.scheduler.force(job)
            return self._send(200 if ok else 404, json.dumps({"queued": ok}))
        if url.path == "/api/ask":
            payload = self._json_body(16_384)
            if payload is None:
                return self._send(400, json.dumps({"error": "invalid request"}))
            question = str(payload.get("question") or "")[:4000]
            store = Store(self.db_path)
            try:
                result = assistant.answer(store, question, jobs=JOBS)
            finally:
                store.close()
            return self._send(200, json.dumps(result))
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
                    return self._send(200, fh.read(), "text/html; charset=utf-8")
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

        if url.path == "/geo":
            try:
                with open(GEO_PAGE, "r", encoding="utf-8", errors="replace") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                return self._send(500, "geo.html missing", "text/plain")

        if url.path == "/api/geo":
            from jarvis.service import geosecurity
            state = build_state(self.db_path, self.scheduler)
            hstate = health(self.db_path, self.scheduler)
            recent = [f for f in state.get("findings", [])
                      if f.get("severity") in ("critical", "high")]
            store = Store(self.db_path)
            try:
                payload = geosecurity.state(store, health_state=hstate, recent_findings=recent)
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
    scheduler = Scheduler(db_path, hosts)
    scheduler.start()

    # Tell systemd we are up, then keep the watchdog fed for as long as the
    # scheduler is actually making progress. Both are no-ops when not run under
    # a systemd unit that asked for them.
    sdnotify.ready()
    sdnotify.status(f"scheduling {len(JOBS)} jobs")
    wd = threading.Thread(target=watchdog_loop, args=(scheduler,),
                          name="jarvis-watchdog", daemon=True)
    wd.start()

    Handler.db_path = db_path
    Handler.scheduler = scheduler
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
