import json
import os
import tempfile
import unittest
from unittest.mock import patch
from jarvis.response import alert
from jarvis.core.store import Store
from jarvis.reporting import notifications as n, cadence

CONF = {'resend_api_key':'test','alert_to':'owner@example.test','alert_from':'jarvis@example.test',
        'alert_digest_interval':3600}


class NotificationsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=os.path.join(self.tmp.name,'test.db')
        self.store=Store(self.path)
        self.clock=patch('time.time',return_value=1000000); self.now=self.clock.start()
        self.sender=patch.object(alert,'send_email',return_value='');self.send=self.sender.start()
        self.f={'category':'intrusion','severity':'high','title':'unknown script','detail':'check','where':'file'}

    def tearDown(self):
        self.sender.stop();self.clock.stop();self.store.close();self.tmp.cleanup()

    def observe(self,job='intrusion',findings=None,error=''):
        n.dispatch(self.store,CONF,job,[self.f] if findings is None else findings,error)

    def test_multiple_jobs_coalesce_and_survive_restart(self):
        self.observe();self.observe()
        f={**self.f,'title':'other script'}
        self.observe('other',[f]);self.observe('other',[f])
        self.send.assert_not_called()
        self.store.close();self.store=Store(self.path)
        self.now.return_value+=3601
        n.flush(self.store,CONF)
        self.send.assert_called_once()
        self.assertIn('2 update(s)',self.send.call_args.args[1])
        self.assertEqual(json.loads(self.store.get_meta(n.QUEUE)),{})

    def test_no_still_repeat_and_each_age_tier_sends_once(self):
        self.f['severity']='critical';self.observe()
        self.assertEqual(self.send.call_count,1)
        self.now.return_value+=3601;self.observe()
        self.assertEqual(self.send.call_count,2)
        self.assertIn('ESCALATED',self.send.call_args.args[2])
        self.now.return_value+=100;self.observe()
        self.assertEqual(self.send.call_count,2)
        self.now.return_value+=100000;self.observe();self.observe()
        self.assertEqual(self.send.call_count,3)
        self.now.return_value+=86400*30;self.observe()
        self.assertEqual(self.send.call_count,3)

    def test_critical_worsening_bypasses_digest(self):
        self.observe();self.observe()
        self.f={**self.f,'severity':'critical'};self.observe()
        self.send.assert_called_once()
        self.assertIn('[CRITICAL]',self.send.call_args.args[2])

    def test_failed_initial_send_retries_without_acknowledging(self):
        self.f['severity']='critical';self.send.return_value='offline';self.observe()
        st=json.loads(self.store.get_meta(alert._M_STATE))[alert._key(self.f)]
        self.assertEqual(st['last_sent'],0)
        self.assertTrue(json.loads(self.store.get_meta(n.QUEUE)))
        self.send.return_value='';self.now.return_value+=301;self.observe()
        self.assertEqual(self.send.call_count,2)
        self.assertFalse(json.loads(self.store.get_meta(n.QUEUE)))

    def test_cap_keeps_pending_and_quick_disappearance_is_not_mailed(self):
        self.observe();self.observe()
        self.store.set_meta(alert._M_SENTLOG,json.dumps([1000000]*12))
        self.now.return_value+=3600;n.flush(self.store,CONF)
        self.send.assert_not_called()
        self.assertTrue(json.loads(self.store.get_meta(n.QUEUE)))
        self.observe(findings=[])
        self.assertFalse(json.loads(self.store.get_meta(n.QUEUE)))
        self.send.assert_not_called()

    def test_failure_cannot_resolve_previous_security_findings(self):
        self.f['severity']='critical';self.observe()
        self.observe(findings=[],error='collector failed')
        state=json.loads(self.store.get_meta(alert._M_STATE))
        self.assertIn(alert._key(self.f),state)
        self.assertEqual(self.store.ledger_rows()[0]['cleared_at'],0)

    def test_unrelated_job_does_not_clear_and_recovery_survives_mail_failure(self):
        self.f['severity']='critical';self.observe()
        self.observe(job='other',findings=[])
        self.assertIn(alert._key(self.f),json.loads(self.store.get_meta(alert._M_STATE)))
        n.dispatch(self.store, {**CONF, 'alert_on_clear': True}, 'intrusion', [])
        self.now.return_value+=3601;self.send.return_value='offline'
        n.flush(self.store,{**CONF, 'alert_on_clear': True})
        self.assertTrue(json.loads(self.store.get_meta(n.QUEUE)))
        self.assertNotEqual(self.store.ledger_rows()[0]['cleared_at'],0)

    def test_clear_is_silent_by_default_and_not_claimed_as_remediation(self):
        self.f['severity']='critical';self.observe()
        self.observe(findings=[])
        self.now.return_value+=3601;n.flush(self.store,CONF)
        self.send.assert_called_once()
        self.assertFalse(json.loads(self.store.get_meta(n.QUEUE)))

    def test_failed_repair_is_queued_on_first_observation_with_reason(self):
        self.f['remediation']={'status':'failed','reason':'Repair lacks permission.'}
        self.observe()
        self.now.return_value+=3601;n.flush(self.store,CONF)
        self.send.assert_called_once()
        self.assertIn('Repair lacks permission.', self.send.call_args.args[2])

    def test_outage_bypasses_ordinary_cap(self):
        self.store.set_meta(alert._M_SENTLOG,json.dumps([1000000]*12))
        self.observe(findings=[{'category':'daemon','severity':'high','title':'JARVIS is down'}])
        self.send.assert_called_once()

    def test_daily_is_once_per_local_day_not_every_poll(self):
        now=1000000;conf={'report_hour':0}
        self.assertTrue(cadence.daily_due(self.store,conf,now))
        self.store.set_meta('report_daily_last_ok',now)
        self.assertFalse(cadence.daily_due(self.store,conf,now+100))
        self.assertTrue(cadence.daily_due(self.store,conf,now+86400))
