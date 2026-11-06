"""ARGUS-INSTINCT licence ($15 a month or $79 a year): Stripe Checkout, a local licence record, an optional gate.

Everything here is standard library. The Stripe secret key never reaches the
browser; the dashboard only asks this module for a Checkout URL and for the
licence state. Configuration comes from the environment or from
`~/.jarvis/billing.env` (KEY=value lines), so nothing secret lives in the repo:

    STRIPE_SECRET_KEY       sk_test_... or sk_live_...        (required to sell)
    STRIPE_PRICE_ID         price_...  the yearly recurring price (optional; when
                            unset an inline $79/year price is used)
    STRIPE_PRICE_ID_MONTHLY price_...  the monthly recurring price (optional; when
                            unset an inline $15/month price is used)
    STRIPE_WEBHOOK_SECRET   whsec_...  (optional; verifies /api/billing/webhook)

A licence is written when Stripe says the Checkout Session is paid, either
because the browser came back with its session id (`confirm`) or because a
signed webhook arrived (`handle_webhook`). Both paths ask Stripe, or verify
Stripe's signature, before trusting anything.
"""

import hashlib
import hmac
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.stripe.com/v1"
ENV_PATH = os.path.expanduser("~/.jarvis/billing.env")
META_KEY = "billing.license"
PLANS = {"month": 15, "year": 79}                  # US dollars per billing interval
PRICE_USD = PLANS["year"]                          # the yearly price, kept for older callers
TERMS = {"month": 32 * 86400, "year": 366 * 86400}  # one interval plus a day or two of grace
TERM_SECONDS = TERMS["year"]
DEFAULT_PLAN = "year"
WEBHOOK_TOLERANCE = 300
_SESSION_ID = re.compile(r"^cs_(test|live)_[A-Za-z0-9]{10,200}$")
_KEYS = ("STRIPE_SECRET_KEY", "STRIPE_PRICE_ID", "STRIPE_PRICE_ID_MONTHLY",
         "STRIPE_WEBHOOK_SECRET")


def plan_of(value):
    """'month' or 'year'; anything else (including nothing) is the yearly plan."""
    value = str(value or "").strip().lower()
    return value if value in PLANS else DEFAULT_PLAN


def _file_env(path=ENV_PATH):
    out = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    out[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def setting(name):
    return (os.environ.get(name) or _file_env().get(name) or "").strip()


def configured():
    return setting("STRIPE_SECRET_KEY").startswith(("sk_test_", "sk_live_", "rk_test_", "rk_live_"))


def _stripe(method, path, form=None, timeout=20):
    """-> (json | None, error text). Talks to api.stripe.com over HTTPS only."""
    key = setting("STRIPE_SECRET_KEY")
    if not key:
        return None, "Stripe is not configured on this computer."
    data = urllib.parse.urlencode(form).encode() if form else None
    req = urllib.request.Request(API + path, data=data, method=method, headers={
        "Authorization": "Bearer " + key,
        "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace")), ""
    except urllib.error.HTTPError as exc:
        try:
            message = json.loads(exc.read().decode("utf-8", "replace"))["error"]["message"]
        except (ValueError, KeyError, TypeError):
            message = f"Stripe answered {exc.code}."
        return None, str(message)[:300]
    except (urllib.error.URLError, OSError, ValueError):
        return None, "Could not reach Stripe. Check the internet connection and try again."


def _load(store):
    try:
        record = json.loads(store.get_meta(META_KEY) or "")
    except (TypeError, ValueError):
        return None
    return record if isinstance(record, dict) else None


def status(store, now=None):
    now = int(time.time() if now is None else now)
    record = _load(store)
    active = bool(record) and int(record.get("expires") or 0) > now
    return {
        "licensed": active,
        "expires": int(record["expires"]) if active else None,
        "email": (record or {}).get("email") if active else None,
        "can_purchase": configured(),
        # Protection never depends on payment (tests/test_licence_never_gates_core.py): no
        # build asks for a licence before a check runs. Kept so older screens read a value.
        "required": False,
        "price_usd": PRICE_USD,
        "interval": "year",
        "plans": dict(PLANS),
        "plan": plan_of((record or {}).get("plan")) if active else None,
    }



def checkout(origin, plan=DEFAULT_PLAN):
    """-> {url} to send the browser to, or {error}. `origin` is this dashboard's address.
    `plan` is 'month' ($15) or 'year' ($79)."""
    plan = plan_of(plan)
    if not configured():
        return {"error": "Payments are not set up on this computer yet. Add STRIPE_SECRET_KEY "
                         "to ~/.jarvis/billing.env (see docs/BILLING.md)."}
    form = {
        "mode": "subscription",
        "success_url": origin + "/?session_id={CHECKOUT_SESSION_ID}#pricing",
        "cancel_url": origin + "/#pricing",
        "allow_promotion_codes": "true",
        "line_items[0][quantity]": "1",
        "metadata[plan]": plan,
        "subscription_data[metadata][plan]": plan,
    }
    price = setting("STRIPE_PRICE_ID_MONTHLY" if plan == "month" else "STRIPE_PRICE_ID")
    if price:
        form["line_items[0][price]"] = price
    else:
        form.update({
            "line_items[0][price_data][currency]": "usd",
            "line_items[0][price_data][unit_amount]": str(PLANS[plan] * 100),
            "line_items[0][price_data][recurring][interval]": plan,
            "line_items[0][price_data][product_data][name]": "ARGUS-INSTINCT %s licence" % (
                "monthly" if plan == "month" else "yearly"),
        })
    session, error = _stripe("POST", "/checkout/sessions", form)
    if not session or not session.get("url"):
        return {"error": error or "Stripe did not return a checkout page."}
    return {"url": session["url"]}


def _grant(store, session, now):
    details = session.get("customer_details") or {}
    plan = plan_of((session.get("metadata") or {}).get("plan"))
    store.set_meta(META_KEY, json.dumps({
        "session": session.get("id"), "customer": session.get("customer"),
        "subscription": session.get("subscription"), "plan": plan,
        "email": details.get("email") or session.get("customer_email"),
        "activated": now, "expires": now + TERMS[plan]}))


def confirm(store, session_id, now=None):
    """Activate after Stripe Checkout sends the browser back. Stripe is asked, not the URL."""
    now = int(time.time() if now is None else now)
    if not _SESSION_ID.match(session_id or ""):
        return {"ok": False, "error": "That is not a Stripe session."}
    session, error = _stripe("GET", "/checkout/sessions/" + session_id)
    if not session:
        return {"ok": False, "error": error}
    if session.get("payment_status") not in ("paid", "no_payment_required"):
        return {"ok": False, "error": "Stripe has not marked this payment as paid yet."}
    _grant(store, session, now)
    return {"ok": True, **status(store, now)}


def _signature_ok(payload, header, secret, now):
    parts = dict(p.split("=", 1) for p in (header or "").split(",") if "=" in p)
    stamp = parts.get("t", "")
    if not stamp.isdigit() or abs(now - int(stamp)) > WEBHOOK_TOLERANCE:
        return False
    expected = hmac.new(secret.encode(), stamp.encode() + b"." + payload,
                        hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, v) for k, v in
               (p.split("=", 1) for p in (header or "").split(",") if "=" in p) if k == "v1")


def handle_webhook(store, payload, header, now=None):
    """-> (http status, body). Needs STRIPE_WEBHOOK_SECRET; unsigned events are refused."""
    now = int(time.time() if now is None else now)
    secret = setting("STRIPE_WEBHOOK_SECRET")
    if not secret:
        return 503, {"error": "webhook secret not configured"}
    if not _signature_ok(payload, header, secret, now):
        return 400, {"error": "bad signature"}
    try:
        event = json.loads(payload.decode("utf-8", "replace"))
        kind, obj = event["type"], event["data"]["object"]
    except (ValueError, KeyError, TypeError):
        return 400, {"error": "bad event"}
    if kind == "checkout.session.completed" and obj.get("payment_status") in ("paid", "no_payment_required"):
        _grant(store, obj, now)
    elif kind == "invoice.paid" and _load(store):
        record = _load(store)
        record["expires"] = now + TERMS[plan_of(record.get("plan"))]
        store.set_meta(META_KEY, json.dumps(record))
    elif kind == "customer.subscription.deleted" and _load(store):
        record = _load(store)
        record["expires"] = now
        store.set_meta(META_KEY, json.dumps(record))
    return 200, {"received": True}
