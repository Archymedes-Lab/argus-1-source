"""Argus licence keys (jarvis/licensing/licence.py): no secret, offline status, bounded grace.

The Archymedes licence service (pay.archymedes.xyz) is replaced by a fake opener that records every request, so these tests also show
exactly what leaves the machine.
"""

import io
import json
import os
import stat
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from jarvis.cli import parser as cli
from jarvis.core.store import Store
from jarvis.licensing import licence
from jarvis.response import review

KEY = 'ARGUS-SERVER-1C285B2D-6CE6-4BC7-B8BE-ADB6A7E304DA'
NOW = 1_800_000_000.0


class FakeService:
    def __init__(self, validate=None, activate=None, error=None):
        self.requests = []
        self.validate = validate or {'status': 'granted', 'expires_at': '2027-01-01T00:00:00.000Z',
                                     'product': 'Argus Server', 'benefit': 'argus-server'}
        self.activate = activate or {'id': 'act-1', 'key': KEY, 'label': 'srv1'}
        self.error = error

    def __call__(self, req, timeout=None):
        self.requests.append((req.full_url, req.get_method(), dict(req.header_items()),
                              json.loads(req.data)))
        if self.error:
            raise self.error
        body = self.activate if req.full_url.endswith('/activate') else self.validate
        return io.BytesIO(json.dumps(body).encode())


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, licence.FILENAME)

    def tearDown(self):
        self.tmp.cleanup()


class Keys(Base):
    def test_only_argus_key_formats_are_accepted(self):
        self.assertEqual(licence.normalise(KEY.lower()), KEY)
        for bad in ('', 'hello', 'ARGUS-SERVER-123', 'MYAPP-1C285B2D-6CE6-4BC7-B8BE-ADB6A7E304DA',
                    KEY + 'X', 'ARGUS-SERVER-1C285B2D-6CE6-4BC7-B8BE-ADB6A7E304DA; rm -rf /',
                    # retired kinds (Server Review, Watch): the service no longer issues them
                    KEY.replace('SERVER', 'REVIEW'), KEY.replace('SERVER', 'WATCH')):
            with self.subTest(bad=bad), self.assertRaises(licence.LicenceError):
                licence.normalise(bad)

    def test_product_comes_from_the_prefix(self):
        self.assertEqual(licence.product_of(KEY), 'Argus Server')
        self.assertEqual(licence.product_of(KEY.replace('SERVER', 'DESKTOP')), 'Argus Desktop')


class Activation(Base):
    def test_activate_sends_no_secret_only_the_key(self):
        fake = FakeService()
        rec = licence.activate(self.path, KEY, label='srv1', now=NOW, opener=fake)
        self.assertEqual(rec['status'], 'granted')
        self.assertEqual(rec['benefit'], 'argus-server')
        self.assertEqual([u.rsplit('/', 1)[1] for u, *_ in fake.requests], ['activate', 'validate'])
        for url, method, headers, body in fake.requests:
            self.assertTrue(url.startswith('https://pay.archymedes.xyz/licence/'))
            self.assertEqual(method, 'POST')
            self.assertNotIn('Authorization', headers)
            self.assertEqual(body['key'], KEY)
        self.assertEqual(fake.requests[0][3], {'key': KEY, 'label': 'srv1'})
        self.assertEqual(fake.requests[1][3], {'key': KEY, 'activation_id': 'act-1'})

    def test_checkout_links_are_the_archymedes_pay_service(self):
        self.assertEqual(licence.SERVER_CHECKOUT, 'https://pay.archymedes.xyz/buy/argus-server')
        self.assertEqual(licence.DESKTOP_CHECKOUT, 'https://pay.archymedes.xyz/buy/argus-desktop')

    def test_a_key_active_on_another_machine_says_so(self):
        err = urllib.error.HTTPError('u', 409, 'conflict', {}, None)
        with self.assertRaises(licence.LicenceError) as cm:
            licence.activate(self.path, KEY, label='srv2', now=NOW, opener=FakeService(error=err))
        self.assertIn('another machine', str(cm.exception))
        self.assertIn('Archymedes licence service', str(cm.exception))
        self.assertFalse(os.path.exists(self.path))

    def test_stored_file_is_owner_only_and_holds_no_more_than_needed(self):
        licence.activate(self.path, KEY, label='srv1', now=NOW, opener=FakeService())
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        with open(self.path) as fh:
            self.assertEqual(set(json.load(fh)), {'key', 'product', 'activation_id', 'status',
                                                  'expires_at', 'benefit', 'checked_at'})

    def test_a_refused_key_is_not_stored(self):
        err = urllib.error.HTTPError('u', 404, 'nf', {}, None)
        with self.assertRaises(licence.LicenceError):
            licence.activate(self.path, KEY, now=NOW, opener=FakeService(error=err))
        self.assertFalse(os.path.exists(self.path))

    def test_a_non_granted_answer_is_refused(self):
        with self.assertRaises(licence.LicenceError):
            licence.activate(self.path, KEY, now=NOW, opener=FakeService(validate={'status': 'revoked'}))
        self.assertFalse(os.path.exists(self.path))


class Status(Base):
    def install(self, **validate):
        licence.activate(self.path, KEY, now=NOW, opener=FakeService(validate={
            'status': 'granted', 'expires_at': None, **validate}))

    def test_status_is_offline(self):
        self.install()
        with mock.patch('urllib.request.urlopen', side_effect=AssertionError('network')):
            self.assertTrue(licence.status(self.path, now=NOW + 60)['licensed'])

    def test_no_file_is_not_licensed(self):
        self.assertFalse(licence.status(self.path, now=NOW)['licensed'])

    def test_grace_ends_after_seven_days_without_a_check(self):
        self.install()
        self.assertTrue(licence.status(self.path, now=NOW + 6 * 86400)['licensed'])
        st = licence.status(self.path, now=NOW + 8 * 86400)
        self.assertFalse(st['licensed'])
        self.assertIn('refresh', st['reason'])

    def test_expiry_beats_grace(self):
        self.install(expires_at='2027-01-15T00:00:00Z')   # NOW is 2027-01-15T08:00Z
        self.assertFalse(licence.status(self.path, now=NOW)['licensed'])

    def test_a_key_for_another_product_does_not_unlock_the_review(self):
        licence.activate(self.path, KEY.replace('SERVER', 'DESKTOP'), now=NOW, opener=FakeService(
            validate={'status': 'granted', 'expires_at': None}))
        self.assertFalse(licence.status(self.path, now=NOW)['licensed'])

    def test_refresh_refusal_revokes_but_no_answer_keeps_the_grant(self):
        self.install()
        with self.assertRaises(licence.LicenceError):
            licence.refresh(self.path, now=NOW + 60, opener=FakeService(error=OSError('down')))
        self.assertTrue(licence.status(self.path, now=NOW + 120)['licensed'])
        with self.assertRaises(licence.LicenceError):
            licence.refresh(self.path, now=NOW + 60, opener=FakeService(
                error=urllib.error.HTTPError('u', 404, 'nf', {}, None)))
        self.assertFalse(licence.status(self.path, now=NOW + 120)['licensed'])

    def test_refresh_that_answers_revoked_or_expired_ends_the_grant_at_once(self):
        for answer in ('revoked', 'expired'):
            with self.subTest(answer=answer):
                self.install()
                with self.assertRaises(licence.LicenceError):
                    licence.refresh(self.path, now=NOW + 60, opener=FakeService(
                        validate={'status': answer, 'expires_at': None}))
                st = licence.status(self.path, now=NOW + 120)
                self.assertFalse(st['licensed'])
                self.assertEqual(st['status'], answer)

    def test_messages_name_the_archymedes_service_not_polar(self):
        self.install()
        self.assertIn('Archymedes licence service', licence.status(self.path, now=NOW + 60)['reason'])
        with self.assertRaises(licence.LicenceError) as cm:
            licence.refresh(self.path, now=NOW + 60, opener=FakeService(error=OSError('down')))
        self.assertNotIn('Polar', str(cm.exception))


class ReviewPreview(Base):
    def setUp(self):
        super().setUp()
        self.db = os.path.join(self.tmp.name, 'jarvis.db')
        Store(self.db).close()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(['--db', self.db, 'review', *argv])
        return code, out.getvalue(), err.getvalue()

    def test_unlicensed_review_is_a_preview_with_the_buy_link(self):
        code, out, err = self.run_cli()
        self.assertEqual(code or 0, 0)
        self.assertIn('(preview)', out)
        self.assertIn(licence.SERVER_CHECKOUT, out)
        self.assertIn('preview only', err)

    def test_preview_keeps_states_counts_and_blind_spots_but_no_findings(self):
        rv = {'sections': [{'job': 'x', 'finding_count': 3, 'findings': [{'title': 't'}], 'truncated': 0}]}
        pv = review.preview(rv, 'https://buy')
        self.assertEqual(pv['sections'][0]['findings'], [])
        self.assertEqual(pv['sections'][0]['finding_count'], 3)
        self.assertEqual(rv['sections'][0]['findings'], [{'title': 't'}], 'input is not modified')

    def test_licensed_review_is_full(self):
        licence.activate(licence.path_for(self.db), KEY, opener=FakeService(
            validate={'status': 'granted', 'expires_at': None}))
        code, out, _err = self.run_cli()
        self.assertEqual(code or 0, 0)
        self.assertNotIn('(preview)', out)


if __name__ == '__main__':
    unittest.main()
