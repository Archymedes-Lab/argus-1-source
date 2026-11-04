"""Argus licence keys sold through Stripe, checked against the Archymedes licence service.

Decided 2026-11-04: Polar is dropped; Argus is sold through Stripe Checkout with Stripe
Managed Payments (Stripe is the merchant of record). The buyer pays at
https://pay.archymedes.xyz/buy/<offer>; the Archymedes licence service (the
hosted/licence-cloudflare Worker at pay.archymedes.xyz) issues an ARGUS-...-<UUID> key. This
module activates the key for this machine and validates it at
https://pay.archymedes.xyz/licence/{activate,validate} with the key alone. No seller secret
or API token ever reaches a customer machine.

Rules (tests/test_licence.py):
- Licence state only unlocks premium content (the full review report). Detection,
  collectors, alerts, evidence and on-demand checks never consult it
  (tests/test_licence_never_gates_core.py).
- Network: HTTPS POST to LICENCE_API only, and only from activate/refresh, which the owner
  runs on purpose. Reading the status is offline.
- A key is accepted only in Argus's own formats; the stored file is owner-only and is
  written atomically. Nothing is stored except the key, the activation id, the service's
  answer (status, expiry, benefit) and when it was checked.
- Offline grace: a granted key stays valid offline for GRACE_DAYS after the last
  successful check, never past its own expiry. A refused, revoked or expired key is not
  licensed.
"""

import json
import os
import re
import socket
import tempfile
import time
import urllib.error
import urllib.request

SERVICE = 'Archymedes licence service'
PAY_ORIGIN = 'https://pay.archymedes.xyz'
LICENCE_API = f'{PAY_ORIGIN}/licence'
REVIEW_CHECKOUT = f'{PAY_ORIGIN}/buy/argus-review'
WATCH_CHECKOUT = f'{PAY_ORIGIN}/buy/argus-watch'
DESKTOP_CHECKOUT = f'{PAY_ORIGIN}/buy/argus-desktop'   # sellable only after the free beta
PRODUCTS = {'REVIEW': 'Argus Server Review', 'WATCH': 'Argus Watch', 'DESKTOP': 'Argus Desktop'}
KEY_RE = re.compile(r'^ARGUS-(REVIEW|WATCH|DESKTOP)-[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$')
GRACE_DAYS = 7
TIMEOUT = 15
FILENAME = 'licence.json'
REFUSED = (400, 403, 404, 422)


class LicenceError(Exception):
    """The key could not be activated or checked; the message is safe to show."""


def normalise(key):
    """The key in Argus's format, upper-case, or LicenceError."""
    k = str(key or '').strip().upper()
    if not KEY_RE.match(k):
        raise LicenceError('that is not an Argus licence key (it starts with ARGUS-REVIEW-, '
                           'ARGUS-WATCH- or ARGUS-DESKTOP-)')
    return k


def product_of(key):
    return PRODUCTS[KEY_RE.match(key).group(1)]


def path_for(db_path):
    return os.path.join(os.path.dirname(os.path.abspath(db_path)), FILENAME)


def _post(endpoint, body, opener=None):
    req = urllib.request.Request(f'{LICENCE_API}/{endpoint}', data=json.dumps(body).encode(),
                                 method='POST', headers={'content-type': 'application/json',
                                                         'accept': 'application/json',
                                                         'user-agent': 'argus-licence/2'})
    try:
        with (opener or urllib.request.urlopen)(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read(65536) or b'{}')
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            raise LicenceError(f'the {SERVICE} says this key is already activated on another '
                               'machine; one key covers one machine') from None
        if exc.code in REFUSED:
            raise LicenceError(f'the {SERVICE} does not recognise this key for this machine '
                               f'(HTTP {exc.code}); check the key in your receipt email') from None
        raise LicenceError(f'the {SERVICE} answered HTTP {exc.code}; try again later') from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise LicenceError(f'the {SERVICE} could not be reached ({type(exc).__name__}); '
                           'the stored licence, if any, is unchanged') from None


def load(path):
    try:
        with open(path, encoding='utf-8') as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def save(path, data):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix='.licence-', dir=d)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=1)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _expiry(ts):
    if not ts:
        return None
    try:
        return time.mktime(time.strptime(str(ts)[:19], '%Y-%m-%dT%H:%M:%S')) - time.timezone
    except ValueError:
        return None


def _record(key, activation_id, answer, now):
    if answer.get('status') != 'granted':
        raise LicenceError(f'the {SERVICE} says this key is {answer.get("status") or "not valid"}')
    return {'key': key, 'product': product_of(key), 'activation_id': activation_id,
            'status': 'granted', 'expires_at': answer.get('expires_at'),
            'benefit': answer.get('benefit'), 'checked_at': now}


def activate(path, key, label=None, now=None, opener=None):
    """Activate `key` for this machine, validate it, store it. Returns the record."""
    key = normalise(key)
    now = time.time() if now is None else now
    host = (label or socket.gethostname())[:60]
    act = _post('activate', {'key': key, 'label': host}, opener)
    activation_id = act.get('id')
    if not activation_id:
        raise LicenceError(f'the {SERVICE} did not return an activation for this key')
    rec = _record(key, activation_id, _post('validate', {'key': key, 'activation_id': activation_id},
                                            opener), now)
    save(path, rec)
    return rec


def refresh(path, now=None, opener=None):
    """Re-check the stored key. A refusal, revocation or expiry removes the grant; no answer keeps it."""
    rec = load(path)
    if not rec or not rec.get('key'):
        raise LicenceError('no licence is installed on this machine')
    now = time.time() if now is None else now
    try:
        answer = _post('validate', {'key': rec['key'], 'activation_id': rec.get('activation_id')}, opener)
    except LicenceError as exc:
        if 'does not recognise' in str(exc):
            rec.update(status='refused', checked_at=now)
            save(path, rec)
        raise
    if answer.get('status') != 'granted':
        # Revoked (refund, cancelled subscription) or expired: stop the grant now, not after the grace.
        rec.update(status=str(answer.get('status') or 'refused')[:20], checked_at=now)
        save(path, rec)
    new = _record(rec['key'], rec.get('activation_id'), answer, now)
    save(path, new)
    return new


def status(path, product='Argus Server Review', now=None):
    """Offline: {'licensed': bool, 'reason': str, ...} for `product`. Never touches the network."""
    now = time.time() if now is None else now
    rec = load(path)
    if not rec:
        return {'licensed': False, 'reason': 'no licence installed'}
    out = {k: rec.get(k) for k in ('product', 'expires_at', 'checked_at', 'status')}
    out['key_hint'] = str(rec.get('key', ''))[-4:]
    if rec.get('product') != product:
        return {**out, 'licensed': False, 'reason': f'the installed key is for {rec.get("product")}'}
    if rec.get('status') != 'granted':
        return {**out, 'licensed': False,
                'reason': f'the {SERVICE} did not grant this key at the last check'}
    exp = _expiry(rec.get('expires_at'))
    if exp is not None and now > exp:
        return {**out, 'licensed': False, 'reason': 'the key has expired'}
    checked = float(rec.get('checked_at') or 0)
    if now - checked > GRACE_DAYS * 86400:
        return {**out, 'licensed': False,
                'reason': f'not checked with the {SERVICE} for over {GRACE_DAYS} days '
                          '(run `argus licence refresh`)'}
    return {**out, 'licensed': True, 'reason': f'granted by the {SERVICE}'}
