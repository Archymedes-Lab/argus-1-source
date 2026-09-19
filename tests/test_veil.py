import unittest
import io
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock

from jarvis.cli.commands.veil import TOKEN_KEY
from jarvis.collectors.host.veil.analysis import classify, clean_link, validate_report
from jarvis.core import incidents
from jarvis.core.store import Store
from jarvis.web.server import Handler


def report(**overrides):
    base = {
        "top_origin": "https://shop.example/path?private=no",
        "egress_origins": ["https://tracker.example/a?user=private"],
        "listeners": {"mousemove": 1, "pointermove": 1, "scroll": 1, "input": 1},
        "surfaces": {}, "transports": {"beacon": 1},
    }
    base.update(overrides)
    return base


class VeilContractTests(unittest.TestCase):
    def test_behavioral_combination_with_export_is_high_without_raw_input(self):
        findings = classify(report())
        hit = next(f for f in findings if "behavioral interaction" in f["title"])
        self.assertEqual(hit["severity"], "high")
        self.assertNotIn("private", hit["where"])
        self.assertNotIn("(391,", hit["detail"])

    def test_interaction_listeners_without_export_are_not_a_tracking_finding(self):
        self.assertEqual(classify(report(egress_origins=[], transports={})), [])

    def test_entropy_requires_aggregation_and_export(self):
        findings = classify(report(listeners={}, surfaces={
            "canvas": 1, "webgl": 1, "webgpu": 1, "audio": 1,
        }, transports={"fetch": 1}))
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("fingerprinting", findings[0]["title"])

    def test_rejects_paths_bad_schemes_and_unbounded_payloads(self):
        normalized = validate_report(report())
        self.assertEqual(normalized["top_origin"], "https://shop.example")
        self.assertEqual(normalized["egress_origins"], ["https://tracker.example"])
        self.assertIsNone(validate_report(report(top_origin="file:///private")))
        self.assertIsNone(validate_report(report(egress_origins=["https://x.example"] * 17)))

    def test_link_cleaning_preserves_destination_and_non_tracking_parameters(self):
        self.assertEqual(clean_link("https://example.test/a?utm_source=x&keep=y&fbclid=z"),
                         "https://example.test/a?keep=y")

    def test_extension_source_never_mentions_raw_input_collection(self):
        with open("browser-sensor/content.js", encoding="utf-8") as fh:
            source = fh.read().lower()
        self.assertNotIn("formdata", source)
        self.assertNotIn("key value", source)


class VeilIntakeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "state.db")
        store = Store(self.path)
        store.set_meta(TOKEN_KEY, "paired-secret")
        store.close()

    def _post(self, token):
        payload = json.dumps(report()).encode()
        handler = Handler.__new__(Handler)
        handler.db_path = self.path
        handler.path = "/api/veil/events"
        handler.headers = {"Host": "localhost:8787", "Content-Length": str(len(payload)),
                           "X-JARVIS-Veil-Token": token}
        handler.rfile = io.BytesIO(payload)
        handler._send = Mock()
        handler.do_POST()
        return handler._send.call_args.args

    def test_token_paired_extension_report_is_durable_before_acknowledgement(self):
        status, body = self._post("paired-secret")
        self.assertEqual(status, 202)
        self.assertTrue(json.loads(body)["accepted"])
        store = Store(self.path)
        try:
            self.assertEqual(incidents.overview(store.db)["counts"]["active"], 1)
        finally:
            store.close()

    def test_unpaired_caller_cannot_write_privacy_observations(self):
        status, _ = self._post("wrong")
        self.assertEqual(status, 403)
        store = Store(self.path)
        try:
            self.assertEqual(incidents.overview(store.db)["total"], 0)
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
