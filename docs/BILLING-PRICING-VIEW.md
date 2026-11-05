> **The licence lock (`ARGUS_REQUIRE_LICENSE`, HTTP 402) was removed in the merge:** protection never depends on payment (`tests/test_licence_never_gates_core.py`). Billing status and checkout remain; the lines below that describe the lock are historical.
>
> Kept alongside the newer licensing design. This describes the daemon-side Stripe billing (Pricing view, `/api/billing`). The signed-lease licensing service is in `docs/BILLING.md` and `docs/LICENSING-ARCHITECTURE.md`. Which of the two stays is an owner decision.

# Licence and Stripe payments

ARGUS-INSTINCT is sold as a **$79 per year** subscription through Stripe Checkout.
The code is `jarvis/web/billing.py`; the page is **Pricing** in the dashboard.
Standard library only, no Stripe SDK.

## Set up (once, on the machine that sells or tests)

Create `~/.jarvis/billing.env` (on Windows `C:\Users\<you>\.jarvis\billing.env`).
Environment variables of the same names also work. Never commit this file.

```
STRIPE_SECRET_KEY=sk_test_...        # Dashboard > Developers > API keys
STRIPE_PRICE_ID=price_...            # optional: a yearly recurring $79 Price
STRIPE_WEBHOOK_SECRET=whsec_...      # optional, see below
ARGUS_REQUIRE_LICENSE (REMOVED)=0              # 1 = lock the assistant and checks until licensed
```

- Without `STRIPE_PRICE_ID` an inline `$79 / year` price is created per checkout.
  For production, create a Product with a yearly $79 Price in Stripe and set the id,
  so coupons, tax and reporting work from the Stripe dashboard.
- Use `sk_test_` keys and card `4242 4242 4242 4242` until you go live.

## How it works

1. **Subscribe** calls `POST /api/billing/checkout`; the server creates a Checkout
   Session (mode `subscription`) and the browser is sent to Stripe's hosted page.
2. Stripe returns to `/?session_id=cs_...#pricing`. The page posts the id to
   `POST /api/billing/confirm`; the server **asks Stripe** for the session and only
   writes the licence when `payment_status` is `paid`. The URL alone proves nothing.
3. The licence is stored in the local database (meta key `billing.license`) and lasts
   a year plus a day.
4. Optional webhook `POST /api/billing/webhook` (verified with `STRIPE_WEBHOOK_SECRET`)
   activates on `checkout.session.completed`, extends on `invoice.paid` and ends the
   licence on `customer.subscription.deleted`. For local testing:
   `stripe listen --forward-to localhost:8787/api/billing/webhook`.

## Enforcement

`ARGUS_REQUIRE_LICENSE (REMOVED)=1` makes `/api/ask`, `/api/run` and `/api/assistant/action`
answer `402` without a licence, and the dashboard shows a banner. It is off by default
so development builds stay usable. Turn it on for release builds.

This is a **local** check: someone with the source can bypass it. It stops casual
use, not a determined user. Server-side licence keys would be the next step.

## Notes

- ARGUS-INSTINCT otherwise talks only to loopback. The only outbound calls added are
  HTTPS requests to `api.stripe.com`, made by the server, and only for billing.
- The secret key is read server-side and never sent to the browser.
