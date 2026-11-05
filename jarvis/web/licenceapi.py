"""The licence screen's API for the desktop app and the dashboard (GET/POST /api/licence...).

Thin wrapper over jarvis/licensing/licence.py. Premium content only: nothing here is consulted
by detection, collectors, alerts or evidence (tests/test_licence_never_gates_core.py), and an
unlicensed answer is an ordinary 200 with licensed=false, never a payment-required status.
"""

import threading
import time

from jarvis.licensing import licence

_renew_lock = threading.Lock()
_last_renew_try = [0.0]
RENEW_CHECK_EVERY = 3600


def _links():
    return {'buy_server': licence.SERVER_CHECKOUT, 'buy_desktop': licence.DESKTOP_CHECKOUT,
            'manage': licence.MANAGE_URL, 'recover': licence.RECOVER_URL}


def _maybe_renew_in_background(path):
    """While Argus runs: at most hourly, renew in a thread if the lease is in its last 7 days."""
    now = time.time()
    with _renew_lock:
        if now - _last_renew_try[0] < RENEW_CHECK_EVERY:
            return
        _last_renew_try[0] = now
    threading.Thread(target=licence.maybe_renew, args=(path,), daemon=True, name='licence-renew').start()


def state(db_path):
    path = licence.path_for(db_path)
    _maybe_renew_in_background(path)
    st = licence.status(path)
    pending = (licence.load(path) or {}).get('claim')
    out = {k: v for k, v in st.items() if k != 'activation_id'}
    out['purchase_waiting'] = bool(pending and pending.get('expires', 0) > time.time())
    return {**out, 'links': _links()}


def action(db_path, name, payload):
    """(HTTP status, body) for POST /api/licence/<name>."""
    path = licence.path_for(db_path)
    payload = payload if isinstance(payload, dict) else {}
    try:
        if name == 'activate':
            licence.activate(path, str(payload.get('key') or '')[:200])
        elif name == 'deactivate':
            licence.deactivate(path)
        elif name == 'refresh':
            licence.refresh(path)
        elif name == 'upgrade':
            plan = payload.get('plan') if payload.get('plan') in ('server', 'desktop') else 'desktop'
            claim = licence.claim_start(path)
            return 200, {'ok': True, 'open': claim['buy'][plan], 'interval': claim.get('interval', 5)}
        elif name == 'poll':
            done = licence.claim_poll(path) == 'active'
            return 200, {'ok': True, 'active': done, **({'state': state(db_path)} if done else {})}
        else:
            return 404, {'ok': False, 'error': 'unknown licence action'}
    except licence.LicenceError as exc:
        return 200, {'ok': False, 'code': exc.code, 'error': str(exc), 'state': state(db_path)}
    return 200, {'ok': True, 'state': state(db_path)}
