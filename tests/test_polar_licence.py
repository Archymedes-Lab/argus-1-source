"""Argus licence keys from Polar (jarvis/licensing/polar.py): no secret, offline status, bounded grace.

Polar is replaced by a fake opener that records every request, so these tests also show
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
from jarvis.licensing import polar
from jarvis.response import review

KEY = 'ARGUS-REVIEW-1C285B2D-6CE6-4BC7-B8BE-ADB6A7E304DA'
NOW = 1_800_000_000.0


class FakePolar:
    def __init__(self, validate=None, activate=None, error=None):
        self.requests = []
        self.validate = validate or {'status': 'granted', 'expires_at': '2027-01-01T00:00:00Z',
                                     'benefit_id': 'b-1'}
        self.activate = activate or {'id': 'act-1'}
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
        self.path = os.path.join(self.tmp.name, polar.FILENAME)

    def tearDown(self):
        self.tmp.cleanup()


class Keys(Base):
    def test_only_argus_key_formats_are_accepted(self):
        self.assertEqual(polar.normalise(KEY.lower()), KEY)
        for bad in ('', 'hello', 'ARGUS-REVIEW-123', 'MYAPP-1C285B2D-6CE6-4BC7-B8BE-ADB6A7E304DA',
                    KEY + 'X', 'ARGUS-REVIEW-1C285B2D-6CE6-4BC7-B8BE-ADB6A7E304DA; rm -rf /'):
            with self.subTest(bad=bad), self.assertRaises(polar.LicenceError):
                polar.normalise(bad)

    def test_product_comes_from_the_prefix(self):
        self.assertEqual(polar.product_of(KEY), 'Argus Server Review')
        self.assertEqual(polar.product_of(KEY.replace('REVIEW', 'WATCH')), 'Argus Watch')


class Activation(Base):
    def test_activate_sends_no_secret_only_key_and_public_org(self):
        fake = FakePolar()
        rec = polar.activate(self.path, KEY, label='srv1', now=NOW, opener=fake)
        self.assertEqual(rec['status'], 'granted')
        self.assertEqual([u.rsplit('/', 1)[1] for u, *_ in fake.requests], ['activate', 'validate'])
        for url, method, headers, body in fake.requests:
            self.assertTrue(url.startswith('https://api.polar.sh/v1/customer-portal/license-keys/'))
            self.assertEqual(method, 'POST')
            self.assertNotIn('Authorization', headers)
            self.assertEqual(body['organization_id'], polar.ORGANIZATION_ID)
            self.assertEqual(body['key'], KEY)
        self.assertEqual(fake.requests[1][3]['activation_id'], 'act-1')

    def test_stored_file_is_owner_only_and_holds_no_more_than_needed(self):
        polar.activate(self.path, KEY, label='srv1', now=NOW, opener=FakePolar())
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        with open(self.path) as fh:
            self.assertEqual(set(json.load(fh)), {'key', 'product', 'activation_id', 'status',
                                                  'expires_at', 'benefit_id', 'checked_at'})

    def test_a_refused_key_is_not_stored(self):
        err = urllib.error.HTTPError('u', 404, 'nf', {}, None)
        with self.assertRaises(polar.LicenceError):
            polar.activate(self.path, KEY, now=NOW, opener=FakePolar(error=err))
        self.assertFalse(os.path.exists(self.path))

    def test_a_non_granted_answer_is_refused(self):
        with self.assertRaises(polar.LicenceError):
            polar.activate(self.path, KEY, now=NOW, opener=FakePolar(validate={'status': 'revoked'}))
        self.assertFalse(os.path.exists(self.path))


class Status(Base):
    def install(self, **validate):
        polar.activate(self.path, KEY, now=NOW, opener=FakePolar(validate={
            'status': 'granted', 'expires_at': None, **validate}))

    def test_status_is_offline(self):
        self.install()
        with mock.patch('urllib.request.urlopen', side_effect=AssertionError('network')):
            self.assertTrue(polar.status(self.path, now=NOW + 60)['licensed'])

    def test_no_file_is_not_licensed(self):
        self.assertFalse(polar.status(self.path, now=NOW)['licensed'])

    def test_grace_ends_after_seven_days_without_a_check(self):
        self.install()
        self.assertTrue(polar.status(self.path, now=NOW + 6 * 86400)['licensed'])
        st = polar.status(self.path, now=NOW + 8 * 86400)
        self.assertFalse(st['licensed'])
        self.assertIn('refresh', st['reason'])

    def test_expiry_beats_grace(self):
        self.install(expires_at='2027-01-15T00:00:00Z')   # NOW is 2027-01-15T08:00Z
        self.assertFalse(polar.status(self.path, now=NOW)['licensed'])

    def test_a_key_for_another_product_does_not_unlock_the_review(self):
        polar.activate(self.path, KEY.replace('REVIEW', 'WATCH'), now=NOW, opener=FakePolar(
            validate={'status': 'granted', 'expires_at': None}))
        self.assertFalse(polar.status(self.path, now=NOW)['licensed'])

    def test_refresh_refusal_revokes_but_no_answer_keeps_the_grant(self):
        self.install()
        with self.assertRaises(polar.LicenceError):
            polar.refresh(self.path, now=NOW + 60, opener=FakePolar(error=OSError('down')))
        self.assertTrue(polar.status(self.path, now=NOW + 120)['licensed'])
        with self.assertRaises(polar.LicenceError):
            polar.refresh(self.path, now=NOW + 60, opener=FakePolar(
                error=urllib.error.HTTPError('u', 404, 'nf', {}, None)))
        self.assertFalse(polar.status(self.path, now=NOW + 120)['licensed'])


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
        self.assertIn(polar.REVIEW_CHECKOUT, out)
        self.assertIn('preview only', err)

    def test_preview_keeps_states_counts_and_blind_spots_but_no_findings(self):
        rv = {'sections': [{'job': 'x', 'finding_count': 3, 'findings': [{'title': 't'}], 'truncated': 0}]}
        pv = review.preview(rv, 'https://buy')
        self.assertEqual(pv['sections'][0]['findings'], [])
        self.assertEqual(pv['sections'][0]['finding_count'], 3)
        self.assertEqual(rv['sections'][0]['findings'], [{'title': 't'}], 'input is not modified')

    def test_licensed_review_is_full(self):
        polar.activate(polar.path_for(self.db), KEY, opener=FakePolar(
            validate={'status': 'granted', 'expires_at': None}))
        code, out, _err = self.run_cli()
        self.assertEqual(code or 0, 0)
        self.assertNotIn('(preview)', out)


if __name__ == '__main__':
    unittest.main()
