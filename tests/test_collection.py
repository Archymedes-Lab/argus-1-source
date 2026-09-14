import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from jarvis import collect_windows, collection, control, sysmon
from jarvis.protection import health
from jarvis.store import Store


class CollectionTests(unittest.TestCase):
    def test_nested_contexts_do_not_leak(self):
        with collection.observe() as outer:
            collection.succeeded('linux')
            with collection.observe() as inner:
                collection.failed('win', 'down')
            self.assertEqual(inner.status, 'unavailable')
            self.assertEqual(outer.status, 'complete')

    def test_bridge_failure_is_explicit_even_when_helper_returns_none(self):
        with collection.observe() as observation, patch.object(control.collect_windows, 'available', return_value=False):
            self.assertIsNone(collect_windows.ps_json('unused'))
        self.assertEqual(observation.status, 'unavailable')

    def test_failed_sysmon_query_preserves_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(str(Path(directory)/'test.db'))
            store.set_meta('sysmon_last_run', 50)
            with patch.object(sysmon, 'status', return_value={'installed': True, 'readable': True}), patch.object(sysmon, '_fetch', return_value={}):
                with collection.observe() as observation:
                    result = sysmon.audit(store, incremental=True)
            self.assertEqual(int(store.get_meta('sysmon_last_run')), 50)
            self.assertEqual(observation.status, 'unavailable')
            self.assertEqual(result[0]['severity'], 'high')
            store.close()


class ProtectionHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name)/'state.db')
        self.store = Store(self.path)
        self.scheduler = SimpleNamespace(heartbeat=1000, current=None, hosts=('win',), is_alive=lambda: True)

    def tearDown(self):
        self.store.close(); self.temp.cleanup()

    def record(self, kind, findings=None, error=''):
        with patch('jarvis.store.now', return_value=1000):
            self.store.save_snapshot(kind, findings or [], error=error)

    def test_live_is_not_protected_when_windows_is_blind(self):
        self.record('scan'); self.record('bridge', error='Windows unavailable'); self.record('sysmon')
        result = health(self.path, self.scheduler, 1010)
        self.assertTrue(result['live']); self.assertFalse(result['healthy'])

    def test_visibility_finding_blocks_false_green(self):
        self.record('scan'); self.record('bridge'); self.record('sysmon', [{'category':'visibility','severity':'high','title':'unreadable'}])
        self.assertFalse(health(self.path, self.scheduler, 1010)['protection_healthy'])

    def test_stale_and_missing_observations_are_not_healthy(self):
        self.assertFalse(health(self.path, self.scheduler, 1010)['healthy'])
        for kind in ('scan','bridge','sysmon'): self.record(kind)
        self.assertTrue(health(self.path, self.scheduler, 1010)['healthy'])
        self.assertFalse(health(self.path, self.scheduler, 1500)['healthy'])
