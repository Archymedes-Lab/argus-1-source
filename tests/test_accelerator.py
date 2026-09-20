import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jarvis.collectors.host import accelerator
from jarvis.core.store import Store


class AcceleratorProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(str(Path(self.tmp.name) / "state.db"))
        self.addCleanup(self.store.close)

    def test_probe_is_read_only_persisted_and_hourly_cached(self):
        data = {
            "gpus": [{"name": "Intel(R) UHD Graphics", "driver": "1.2"}],
            "openvino": {"installed": True, "devices": ["CPU", "GPU"], "error": ""},
            "ollama": {"reachable": True, "models": []},
            "processes": [{"name": "ollama", "rss_bytes": 123}],
        }
        with patch.object(accelerator, "ps_json", return_value=data) as probe:
            first = accelerator.audit(self.store, hosts=("win",), now=1000)
            second = accelerator.audit(self.store, hosts=("win",), now=1001)
        probe.assert_called_once()
        self.assertEqual(first[0]["severity"], "ok")
        self.assertIn("available", first[0]["title"])
        self.assertEqual(second[0]["title"], first[0]["title"])
        saved = json.loads(self.store.get_meta(accelerator.META))
        self.assertEqual(saved["gpus"][0]["name"], "Intel(R) UHD Graphics")

    def test_missing_openvino_is_inventory_not_false_gpu_claim(self):
        data = {"gpus": [{"name": "Intel UHD"}],
                "openvino": {"installed": False, "devices": []},
                "ollama": {"reachable": False, "models": []}, "processes": []}
        with patch.object(accelerator, "ps_json", return_value=data):
            result = accelerator.audit(self.store, hosts=("win",), now=1000)
        self.assertEqual(result[0]["title"], "GPU inference capability inventoried")
        self.assertIn("installed=False", result[0]["detail"])

    def test_no_windows_host_does_not_probe(self):
        with patch.object(accelerator, "ps_json") as probe:
            self.assertEqual(accelerator.audit(self.store, hosts=("wsl",), now=1000), [])
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
