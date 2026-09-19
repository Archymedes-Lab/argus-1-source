import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.collectors.host import geo
from jarvis.core.store import Store
from jarvis.service import geosecurity


class ZoneTests(unittest.TestCase):
    def test_classify_picks_the_nearest_containing_zone(self):
        zones = [{"name": "HOME", "lat": -1.9500, "lon": 30.0600, "radius_m": 200},
                 {"name": "OFFICE", "lat": -1.9536, "lon": 30.0605, "radius_m": 150}]
        self.assertEqual(geo.classify(-1.9501, 30.0601, zones), "HOME")
        self.assertEqual(geo.classify(0.0, 0.0, zones), "outside")

    def test_haversine_is_metres(self):
        # ~111 km per degree of latitude.
        self.assertAlmostEqual(geo.haversine_m(0, 0, 1, 0) / 1000, 111.19, delta=1)


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


if __name__ == "__main__":
    unittest.main()
