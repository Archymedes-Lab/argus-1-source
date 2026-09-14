import os
import tempfile
import unittest
from unittest.mock import patch

from jarvis.core.store import Store
from jarvis.response import alert
from jarvis.service import selfcheck


class SelfcheckNotificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, 'state.db')
        self.clock = patch.object(selfcheck, 'now', return_value=1000000)
        self.now = self.clock.start()
        self.conf = patch.object(alert, 'load_conf', return_value={})
        self.conf.start()
        self.enabled = patch.object(alert, 'enabled', return_value=True)
        self.enabled.start()
        self.sender = patch.object(alert, 'send_email', return_value='')
        self.send = self.sender.start()
        self.verdict = dict(healthy=False, problems=['stalled'], newest_kind='test',
                            newest_ts=999999, age=1, active_state='active', scope='system')

    def tearDown(self):
        self.sender.stop(); self.enabled.stop(); self.conf.stop(); self.clock.stop()
        self.tmp.cleanup()

    def notify(self, healthy=False):
        return selfcheck._notify(self.path, {**self.verdict, 'healthy': healthy})

    def test_persistent_outage_has_finite_escalation(self):
        self.notify(); self.notify()
        self.assertEqual(self.send.call_count, 1)
        for step in (3600, 18000, 64800):
            self.now.return_value += step
            self.notify(); self.notify()
        self.assertEqual(self.send.call_count, 4)
        self.now.return_value += 86400 * 30
        self.notify()
        self.assertEqual(self.send.call_count, 4)

    def test_undelivered_outage_recovery_resets_clock(self):
        self.send.return_value = 'unavailable'
        self.notify()
        self.now.return_value += 86400
        self.notify(healthy=True)
        self.send.return_value = ''
        self.notify()
        store = Store(self.path)
        try:
            self.assertEqual(int(store.get_meta('selfcheck_first_down')), self.now.return_value)
            self.assertEqual(int(store.get_meta('selfcheck_escalation')), 0)
        finally:
            store.close()

    def test_failed_recovery_retries_without_flooding(self):
        self.notify()
        self.send.return_value = 'unavailable'
        self.notify(healthy=True)
        self.notify(healthy=True)
        self.assertEqual(self.send.call_count, 2)
        self.now.return_value += 300
        self.send.return_value = ''
        self.notify(healthy=True); self.notify(healthy=True)
        self.assertEqual(self.send.call_count, 3)
        self.notify()
        self.assertEqual(self.send.call_count, 4)
