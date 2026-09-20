import json
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import Mock

from jarvis.collectors.host import geo
from jarvis.core.store import Store
from jarvis.service import geosecurity
from jarvis.web.server import Handler


class _FakeScheduler:
    """Minimal scheduler surface health() needs; no jobs ever run."""
    hosts = ("wsl",)
    current = None
    fast_current = None
    heartbeat = time.time()
    fast_heartbeat = time.time()

    def is_alive(self):
        return True

    def fast_alive(self):
        return True


class ZoneTests(unittest.TestCase):
    def test_classify_picks_the_nearest_containing_zone(self):
        zones = [{"name": "HOME", "lat": -1.9500, "lon": 30.0600, "radius_m": 200},
                 {"name": "OFFICE", "lat": -1.9536, "lon": 30.0605, "radius_m": 150}]
        self.assertEqual(geo.classify(-1.9501, 30.0601, zones), "HOME")
        self.assertEqual(geo.classify(0.0, 0.0, zones), "outside")

    def test_haversine_is_metres(self):
        # ~111 km per degree of latitude.
        self.assertAlmostEqual(geo.haversine_m(0, 0, 1, 0) / 1000, 111.19, delta=1)

    def test_exact_zone_center_is_inside(self):
        zones = [{"name": "HOME", "lat": -1.9441, "lon": 30.0619, "radius_m": 300}]
        self.assertEqual(geo.classify(-1.9441, 30.0619, zones), "HOME")

    def test_zone_boundary_is_metre_exact(self):
        zones = [{"name": "HOME", "lat": -1.9441, "lon": 30.0619, "radius_m": 300}]
        m_per_deg = 111195.0  # consistent with haversine_is_metres above
        self.assertEqual(geo.classify(-1.9441 + 299 / m_per_deg, 30.0619, zones), "HOME")
        self.assertEqual(geo.classify(-1.9441 + 301 / m_per_deg, 30.0619, zones), "outside")

    def test_reported_pin_is_outside_home(self):
        # 2026-09-20 live case: user-set pin ~728 m from HOME center,
        # radius 300 m — "outside" is correct, not a stale cache.
        zones = [{"name": "HOME", "lat": -1.9441, "lon": 30.0619, "radius_m": 300}]
        self.assertEqual(geo.classify(-1.9506, 30.0611, zones), "outside")


class StoreZoneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(str(Path(self.tmp.name) / "j.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_add_list_remove_zone(self):
        geosecurity.add_zone(self.store, "HOME", -1.95, 30.06, 300)
        self.assertEqual(geosecurity.get_zones(self.store)[0]["name"], "HOME")
        geosecurity.remove_zone(self.store, "HOME")
        self.assertEqual(geosecurity.get_zones(self.store), [])

    def test_bad_coordinates_rejected(self):
        with self.assertRaises(ValueError):
            geosecurity.add_zone(self.store, "X", 200, 0)


class FusionTests(unittest.TestCase):
    def test_denied_location_is_zero_confidence(self):
        f = geosecurity.fusion(None, {"status": "denied"})
        self.assertEqual(f["score"], 0.0)

    def test_tight_fix_in_zone_beats_a_loose_one(self):
        tight = geosecurity.fusion(None, {"status": "ok", "accuracy_m": 20,
                                          "zone": "HOME", "ts": 9e9})
        loose = geosecurity.fusion(None, {"status": "ok", "accuracy_m": 9000,
                                          "zone": "outside", "ts": 9e9})
        self.assertGreater(tight["score"], loose["score"])
        self.assertGreaterEqual(tight["score"], 0.9)


class StateAndAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(str(Path(self.tmp.name) / "j.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_denied_audit_reports_and_never_stores_coordinates(self):
        with mock.patch.object(geo, "locate", return_value={"status": "denied",
                                                            "reason": "off"}):
            findings = geo.audit(self.store, hosts=("win",))
        self.assertEqual(findings[0]["category"], "geo")
        self.assertIn("cannot verify", findings[0]["title"])
        current = geo.current(self.store)
        self.assertEqual(current["status"], "denied")
        self.assertNotIn("lat", current)         # no coordinates persisted

    def test_ok_audit_classifies_zone_and_keeps_only_current(self):
        geosecurity.add_zone(self.store, "HOME", -1.95, 30.06, 500)
        fix = {"status": "ok", "lat": -1.9501, "lon": 30.0601, "accuracy_m": 30,
               "source": "windows-gnss"}
        with mock.patch.object(geo, "locate", return_value=fix):
            geo.audit(self.store, hosts=("win",))
        self.assertEqual(geo.current(self.store)["zone"], "HOME")

    def test_state_marks_a_geo_blind_anomaly_when_denied(self):
        with mock.patch.object(geo, "locate", return_value={"status": "denied"}):
            geo.audit(self.store, hosts=("win",))
        state = geosecurity.state(self.store, health_state={"healthy": True})
        kinds = [a["kind"] for a in state["anomalies"]]
        self.assertIn("geo_blind", kinds)
        self.assertEqual(state["devices"][0]["trust"], "trusted")
        self.assertEqual(state["imagery"]["provider"], "NASA GIBS")
        # VIIRS, not MODIS: MODIS's narrower swath leaves black no-data
        # wedges over this region (verified against live GIBS tiles).
        self.assertEqual(state["imagery"]["layer"],
                         "VIIRS_NOAA20_CorrectedReflectance_TrueColor")

    def test_user_set_location_takes_over_when_native_denied(self):
        geosecurity.add_zone(self.store, "HOME", -1.9441, 30.0619, 500)
        with mock.patch.object(geo, "locate", return_value={"status": "denied"}):
            geo.audit(self.store, hosts=("win",))
        geosecurity.set_here(self.store, -1.9441, 30.0619, "Norrsken Kigali")
        state = geosecurity.state(self.store, health_state={"healthy": True})
        loc = state["location"]
        self.assertEqual(loc["status"], "ok")
        self.assertEqual(loc["source"], "user-set")
        self.assertEqual(loc["label"], "Norrsken Kigali")
        self.assertEqual(loc["zone"], "HOME")
        self.assertNotIn("geo_blind", [a["kind"] for a in state["anomalies"]])
        self.assertGreater(state["confidence"]["score"], 0)
        self.assertEqual(state["imagery"]["center"]["source"], "user-set")

    def test_native_fix_overrides_a_user_set_location(self):
        geosecurity.set_here(self.store, 0.0, 0.0, "somewhere")
        fix = {"status": "ok", "lat": -1.95, "lon": 30.06, "accuracy_m": 25,
               "source": "windows-gnss"}
        with mock.patch.object(geo, "locate", return_value=fix):
            geo.audit(self.store, hosts=("win",))
        loc = geosecurity.state(self.store)["location"]
        self.assertEqual(loc["source"], "windows-gnss")

    def test_clearing_a_set_location_restores_geo_blind(self):
        with mock.patch.object(geo, "locate", return_value={"status": "denied"}):
            geo.audit(self.store, hosts=("win",))
        geosecurity.set_here(self.store, 10, 10, "x")
        geosecurity.clear_here(self.store)
        state = geosecurity.state(self.store)
        self.assertEqual(state["location"]["status"], "denied")
        self.assertIn("geo_blind", [a["kind"] for a in state["anomalies"]])

    def test_user_set_audit_is_ok_not_a_blind_finding(self):
        geosecurity.set_here(self.store, -1.94, 30.06, "Norrsken Kigali")
        with mock.patch.object(geo, "locate", return_value={"status": "denied"}):
            findings = geo.audit(self.store, hosts=("win",))
        self.assertEqual(findings[0]["severity"], "ok")
        self.assertIn("Norrsken Kigali", findings[0]["title"])

    def test_outside_zone_with_active_threat_is_flagged(self):
        geosecurity.add_zone(self.store, "HOME", -1.95, 30.06, 100)
        fix = {"status": "ok", "lat": 10.0, "lon": 10.0, "accuracy_m": 20,
               "source": "windows-gnss"}
        with mock.patch.object(geo, "locate", return_value=fix):
            geo.audit(self.store, hosts=("win",))
        state = geosecurity.state(self.store, recent_findings=[{"severity": "critical"}])
        self.assertIn("outside_zone_with_activity", [a["kind"] for a in state["anomalies"]])

    def test_outside_anomaly_states_measured_distance_not_proof(self):
        geosecurity.add_zone(self.store, "HOME", -1.9441, 30.0619, 300)
        fix = {"status": "ok", "lat": -1.9506, "lon": 30.0611, "accuracy_m": 25,
               "source": "windows-gnss"}
        with mock.patch.object(geo, "locate", return_value=fix):
            geo.audit(self.store, hosts=("win",))
        state = geosecurity.state(self.store, recent_findings=[{"severity": "high"}])
        det = [a["detail"] for a in state["anomalies"]
               if a["kind"] == "outside_zone_with_activity"][0]
        self.assertIn("728 m from HOME", det)
        self.assertIn("300 m", det)
        self.assertIn("not proof of compromise", det)

    def test_imagery_carries_date_and_fallback(self):
        state = geosecurity.state(self.store)
        img = state["imagery"]
        self.assertRegex(img["date"], r"^\d{4}-\d{2}-\d{2}$")
        self.assertEqual(img["base"]["layer"], "BlueMarble_NextGeneration")
        self.assertEqual(img["detail"]["layer"], "World_Imagery")
        self.assertLessEqual(img["detail"]["min_level"], 14)
        self.assertGreaterEqual(img["detail"]["max_level"], 19)
        self.assertEqual(img["mid"]["layer"], "s2cloudless-2020")
        self.assertEqual((img["mid"]["min_level"], img["mid"]["max_level"]), (8, 13))
        self.assertLessEqual(img["max_level"], 7)


class GeoCSPTests(unittest.TestCase):
    """The /geo globe needs WASM + workers + CDN assets; nothing else does.

    Regression cover for the starfield-only failure: Cesium rendered its
    canvas, marker and sky but the CSP blocked the globe pipeline
    (WebAssembly, Workers/createGeometry.js, CDN images). The exception
    stays scoped to the /geo page; the strict policy is unchanged.
    """

    def _served_csp(self, path):
        handler = Handler.__new__(Handler)
        handler.headers = {"Host": "localhost:8787"}
        handler._send = Mock()
        handler.path = path
        old, Handler.scheduler = Handler.scheduler, _FakeScheduler()
        try:
            handler.do_GET()
        finally:
            Handler.scheduler = old
        self.assertEqual(handler._send.call_args.args[0], 200)
        _, kwargs = handler._send.call_args
        return kwargs.get("csp") or Handler.CSP_STRICT

    def test_geo_page_permits_the_cesium_pipeline(self):
        csp = self._served_csp("/geo")
        self.assertIn("'wasm-unsafe-eval'", csp)
        self.assertTrue(re.search(r"worker-src[^;]*blob:", csp),
                        f"worker-src must keep blob: in {csp}")
        self.assertTrue(re.search(r"worker-src[^;]*https://cdn\.jsdelivr\.net", csp),
                        f"worker-src must allow the Cesium CDN in {csp}")
        self.assertTrue(re.search(r"img-src[^;]*https://cdn\.jsdelivr\.net", csp),
                        f"img-src must allow Cesium assets in {csp}")
        self.assertTrue(re.search(r"img-src[^;]*server\.arcgisonline\.com", csp),
                        f"img-src must allow detail tiles in {csp}")
        self.assertTrue(re.search(r"img-src[^;]*tiles\.maps\.eox\.at", csp),
                        f"img-src must allow mid-band tiles in {csp}")

    def test_geo_page_never_gets_full_unsafe_eval(self):
        csp = self._served_csp("/geo")
        # "'wasm-unsafe-eval'" contains "unsafe-eval" as a substring, so
        # match the standalone token only.
        self.assertNotRegex(csp, r"['\s]unsafe-eval['\s;]")

    def test_dashboard_keeps_the_strict_policy(self):
        csp = self._served_csp("/")
        self.assertNotIn("'wasm-unsafe-eval'", csp)
        self.assertNotIn("cdn.jsdelivr.net", csp)
        self.assertNotIn("arcgisonline", csp)
        self.assertNotIn("maps.eox.at", csp)

    def test_global_detail_providers_use_layer_not_provider_minimums(self):
        """Global z8/z14 provider minimums make Cesium enumerate huge roots."""
        html = (Path(__file__).parents[1] / "jarvis/web/static/geo.html").read_text()
        self.assertNotIn("minimumLevel: img.mid.min_level", html)
        self.assertNotIn("minimumLevel: img.detail.min_level", html)
        self.assertIn("minimumTerrainLevel: img.mid.min_level", html)
        self.assertIn("minimumTerrainLevel: img.detail.min_level", html)
        self.assertIn("viewer.imageryLayers.add(midLayer)", html)
        self.assertIn("viewer.imageryLayers.add(detailLayer)", html)


class GeoRouteTests(unittest.TestCase):
    """`/api/geo` must stay cheap: snapshots + fusion, never build_state().

    Regression cover for the 0.6–3 s geo poll: the route built the entire
    dashboard state (every finding, score, intel feed) to extract hot
    findings for a 2 KB response.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "route.db")
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self._old_sched, Handler.scheduler = Handler.scheduler, _FakeScheduler()
        self.addCleanup(setattr, Handler, "scheduler", self._old_sched)

    def _get_geo(self):
        handler = Handler.__new__(Handler)
        handler.db_path = self.path
        handler.headers = {"Host": "localhost:8787"}
        handler._send = Mock()
        handler.path = "/api/geo"
        handler.do_GET()
        args, _ = handler._send.call_args
        self.assertEqual(args[0], 200)
        return json.loads(args[1])

    def test_skips_full_dashboard_state(self):
        import jarvis.web.server as server_mod
        with mock.patch.object(server_mod, "build_state") as full:
            payload = self._get_geo()
        full.assert_not_called()
        self.assertIn("location", payload)
        self.assertIn("imagery", payload)

    def test_hot_findings_reach_anomalies_without_build_state(self):
        geosecurity.add_zone(self.store, "HOME", -1.9441, 30.0619, 300)
        geosecurity.set_here(self.store, -1.9506, 30.0611, "probe")
        self.store.save_snapshot("intrusion", [{
            "severity": "critical", "title": "probe", "category": "test"}])
        payload = self._get_geo()
        kinds = [a["kind"] for a in payload["anomalies"]]
        self.assertIn("outside_zone_with_activity", kinds)


if __name__ == "__main__":
    unittest.main()
