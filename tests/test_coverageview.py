import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

from jarvis.core.paths import STATIC_DIR
from jarvis.core.store import Store
from jarvis.service import attackmap, coveragemap
from jarvis.service.schedule import JOBS
from jarvis.web import server


class SourcesTests(unittest.TestCase):
    def test_probe_jobs_win_over_free_text(self):
        self.assertEqual(coveragemap.sources("T1055", "anything — else"), ["sysmon", "memscan"])

    def test_mapped_words_resolve_to_real_jobs_only(self):
        self.assertEqual(coveragemap.sources("T1547", "control / startup — boot and logon autostart"),
                         ["control", "boot"])
        self.assertEqual(coveragemap.sources("T1027", "detect — obfuscated command lines"), ["scan"])
        self.assertEqual(coveragemap.sources("T9999", "nonsense / words — nothing"), [])
        for job in coveragemap.sources("T1014", "hidden / evasion — rootkit detection"):
            self.assertIn(job, JOBS)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = os.path.join(self.tmp.name, "t.db")
        store = Store(self.db)
        store.set_meta(attackmap.META, json.dumps({
            "at": 100, "totals": {"validated": 1, "claimed": 1, "blind": 1, "regressed": 0, "total": 3},
            "tactics": {"execution": {"validated": 1, "claimed": 1, "blind": 1, "regressed": 0, "total": 3}},
            "techniques": [
                {"tid": "T1059", "name": "Interpreter", "tactics": ["execution"], "level": "validated",
                 "evidence": "encoded command; live via scan"},
                {"tid": "T1204", "name": "User Execution", "tactics": ["execution"], "level": "claimed",
                 "evidence": "intrusion — user execution artefacts"},
                {"tid": "T1106", "name": "Native API", "tactics": ["execution"], "level": "blind",
                 "evidence": "hidden — must never be linked while blind"}]}))
        store.save_snapshot("scan", [{"severity": "high", "title": "x"}, {"severity": "low", "title": "y"},
                                     {"severity": "bogus", "title": "z"}])
        store.commit()
        store.close()

    def test_levels_sources_and_collector_state_come_from_the_stored_evidence(self):
        data = coveragemap.build(self.db)
        by_tid = {t["tid"]: t for t in data["techniques"]}
        self.assertEqual(by_tid["T1059"]["sources"], ["scan"])
        self.assertEqual(by_tid["T1204"]["sources"], ["intrusion"])
        self.assertEqual(by_tid["T1106"]["sources"], [])          # blind is never drawn as fed
        by_job = {c["job"]: c for c in data["collectors"]}
        self.assertEqual(set(by_job), set(JOBS))
        self.assertEqual(by_job["scan"]["state"], "current")
        self.assertEqual(by_job["scan"]["findings"], {"critical": 0, "high": 1, "medium": 0, "low": 1})
        self.assertEqual(by_job["scan"]["techniques"], ["T1059"])
        self.assertEqual(by_job["hidden"]["state"], "missing")    # no snapshot is not a clean collector
        self.assertEqual(by_job["hidden"]["techniques"], [])
        self.assertEqual(data["totals"]["total"], 3)
        self.assertEqual(data["running"], [])

    def test_stale_collector_is_reported_stale_and_running_comes_from_the_scheduler(self):
        scheduler = mock.Mock()
        scheduler.wake_phase.return_value = {"current": ["scan"]}
        later = time.time() + JOBS["scan"][0] * 10 + 600
        data = coveragemap.build(self.db, scheduler, now=later)
        scan = next(c for c in data["collectors"] if c["job"] == "scan")
        self.assertEqual(scan["state"], "stale")
        self.assertTrue(scan["running"])

    def test_unmeasured_map_and_broken_scheduler_are_empty_not_errors(self):
        empty = os.path.join(self.tmp.name, "empty.db")
        Store(empty).close()
        scheduler = mock.Mock()
        scheduler.wake_phase.side_effect = RuntimeError("down")
        data = coveragemap.build(empty, scheduler)
        self.assertEqual((data["techniques"], data["totals"], data["running"]), ([], {}, []))
        self.assertTrue(all(c["state"] == "missing" for c in data["collectors"]))


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db = os.path.join(self.tmp.name, "t.db")
        Store(db).close()
        handler = type("H", (server.Handler,), {"db_path": db, "scheduler": None,
                                                "log_message": lambda *a: None})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.base = f"http://localhost:{self.httpd.server_address[1]}"

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=10) as res:
                return res.status, dict(res.headers), res.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def test_page_scripts_and_api_are_served_same_origin_only(self):
        for path in server.COVERAGE_ASSETS:
            status, headers, body = self.get(path)
            self.assertEqual(status, 200, path)
            csp = headers["Content-Security-Policy"]
            self.assertIn("script-src 'self'", csp)
            self.assertNotIn("https:", csp)
            self.assertNotIn("script-src 'unsafe-inline'", csp)
            self.assertTrue(body)
        status, _headers, body = self.get("/api/coverage")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["collectors"]), len(JOBS))

    def test_page_loads_no_inline_or_foreign_script(self):
        _status, _headers, body = self.get("/coverage")
        page = body.decode()
        self.assertEqual(page.count("<script"), 1)
        self.assertIn('<script type="module" src="/static/coverage.js"></script>', page)
        self.assertNotIn("http://", page)
        self.assertNotIn("https://", page)

    def test_vendored_engine_matches_its_pin_and_a_modified_one_is_refused(self):
        name, _ctype, digest = server.COVERAGE_ASSETS["/static/vendor/three.module.min.js"]
        with open(STATIC_DIR / name, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), digest)
        tampered = dict(server.COVERAGE_ASSETS)
        tampered["/static/vendor/three.module.min.js"] = (name, _ctype, "0" * 64)
        with mock.patch.object(server, "COVERAGE_ASSETS", tampered):
            status, _headers, body = self.get("/static/vendor/three.module.min.js")
        self.assertEqual(status, 500)
        self.assertIn(b"pinned hash", body)

    def test_unknown_static_path_is_not_served(self):
        self.assertEqual(self.get("/static/../server.py")[0], 404)
        self.assertEqual(self.get("/static/dashboard.html")[0], 404)


if __name__ == "__main__":
    unittest.main()
