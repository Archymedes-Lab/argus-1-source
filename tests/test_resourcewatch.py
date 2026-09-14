import json
import os
import tempfile
import unittest
from unittest.mock import patch

from jarvis.collectors.process import resourcewatch
from jarvis.core.store import Store


class ResourceWatchTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tempdir.name, "jarvis.db"))

    def tearDown(self):
        self.store.close()
        self.tempdir.cleanup()

    def test_sustained_cpu_is_calculated_from_two_samples(self):
        key = "wsl:42:fp"
        self.store.set_meta(resourcewatch._META, json.dumps({
            "ts": 700.0, "processes": {key: {"cpu": 100.0}}
        }))
        proc = {"host": "wsl", "pid": 42, "fp": "fp", "name": "worker",
                "exe": "/opt/worker", "rss_bytes": 100, "cpu_seconds": 400.0}
        with patch("jarvis.collectors.process.resourcewatch.time.time", return_value=1000.0), \
             patch("jarvis.collectors.process.resourcewatch.monitor.collect_all", return_value=[proc]), \
             patch("jarvis.collectors.process.resourcewatch.os.cpu_count", return_value=4), \
             patch("jarvis.collectors.process.resourcewatch._memory_pressure", return_value=(100, 100)), \
             patch("jarvis.collectors.process.resourcewatch.os.path.exists", return_value=False):
            findings = resourcewatch.audit(self.store, hosts=("wsl",))

        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("25.0%", findings[0]["detail"])
        self.assertNotIn("command", findings[0]["detail"])

    def sample(self, proc, previous_cpu=100.0, previous_ts=700.0):
        key = f"{proc['host']}:{proc['pid']}:fp"
        self.store.set_meta(resourcewatch._META, json.dumps({
            'ts': previous_ts, 'processes': {key: {'cpu': previous_cpu}}}))
        with patch('jarvis.collectors.process.resourcewatch.time.time', return_value=1000.0), \
             patch('jarvis.collectors.process.resourcewatch.monitor.collect_all', return_value=[proc]), \
             patch('jarvis.collectors.process.resourcewatch.os.cpu_count', return_value=4), \
             patch('jarvis.collectors.process.resourcewatch._memory_pressure', return_value=(100, 100)), \
             patch('jarvis.collectors.process.resourcewatch.os.path.exists', return_value=False):
            return resourcewatch.audit(self.store)

    def windows_process(self, **changes):
        return dict({'host': 'win', 'pid': 42, 'fp': 'fp', 'name': 'worker',
                     'exe': '', 'rss_bytes': 100, 'cpu_seconds': 2020.0,
                     'logical_cpus': 16}, **changes)

    def test_idle_counter_is_not_consumption_or_a_saved_baseline(self):
        findings = self.sample(self.windows_process(pid=0, name='(unattributed)',
                                                    cpu_seconds=100000.0))
        self.assertEqual(findings[0]['severity'], 'ok')
        self.assertEqual(json.loads(self.store.get_meta(resourcewatch._META))['processes'], {})

    def test_windows_uses_host_capacity_not_wsl_capacity(self):
        findings = self.sample(self.windows_process())
        self.assertEqual(findings[0]['severity'], 'medium')
        self.assertIn('40.0% of total CPU', findings[0]['detail'])

    def test_real_windows_high_cpu_still_alerts(self):
        findings = self.sample(self.windows_process(cpu_seconds=2980.0))
        self.assertEqual(findings[0]['severity'], 'high')
        self.assertIn('60.0%', findings[0]['detail'])

    def test_impossible_counter_or_clock_jump_is_visibility_not_pressure(self):
        for cpu, timestamp in ((10000, 700), (1, 700), (2020, 1100)):
            with self.subTest(cpu=cpu, timestamp=timestamp):
                findings = self.sample(self.windows_process(cpu_seconds=cpu), previous_ts=timestamp)
                self.assertEqual([f['title'] for f in findings],
                                 ['process CPU measurement unavailable'])

    def test_missing_windows_capacity_preserves_high_memory_alert(self):
        findings = self.sample(self.windows_process(logical_cpus=0, rss_bytes=5 * 1024**3))
        self.assertEqual(findings[0]['severity'], 'high')
        self.assertIn('CPU usage unavailable', findings[0]['detail'])
        self.assertTrue(any(f['title'] == 'process CPU measurement unavailable' for f in findings))


if __name__ == "__main__":
    unittest.main()
