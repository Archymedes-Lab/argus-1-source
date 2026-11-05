# Stripe hand-off (for Chris)

Everything on the JARVIS side is built and tested; what is left is the Stripe account
and keys. No secret is in the repository and none is needed to run the app: until a key
exists, the Pricing screen says payments are not switched on yet.

## What exists

| Piece | Where |
|---|---|
| Checkout, confirm, webhook, licence record | `jarvis/web/billing.py` (standard library only) |
| HTTP routes `/api/billing/status`, `/checkout`, `/confirm`, `/webhook` | `jarvis/web/server.py` |
| Pricing screen (Simple and Expert wording) | `desktop/ui/src/views/Pricing.svelte` |
| App commands `billing_status`, `billing_checkout` | `desktop/src/api.rs` |
| Background on the flow | `docs/BILLING.md` |

The app opens only `https://checkout.stripe.com/...` addresses in the browser (checked in
`is_checkout_url`, with tests). The card is entered on Stripe's page; JARVIS never sees it.

## What Chris needs to do

1. In Stripe (test mode first) create a Product with a **yearly recurring $79 Price** and a **monthly recurring $15 Price**. Copy both `price_...` ids.
2. Create `C:\Users\<user>\.jarvis\billing.env` (never commit it):
   ```
   STRIPE_SECRET_KEY=sk_test_...
   STRIPE_PRICE_ID=price_...            # the yearly $79 Price
   STRIPE_PRICE_ID_MONTHLY=price_...    # the monthly $15 Price
   STRIPE_WEBHOOK_SECRET=whsec_...
   ARGUS_REQUIRE_LICENSE=0
   ```
   Without the price ids, inline $79/year and $15/month prices are created per checkout (fine for testing, not for tax or coupons).
3. Webhook endpoint `POST /api/billing/webhook` on the daemon. Locally:
   `stripe listen --forward-to localhost:8787/api/billing/webhook`
   Events used: `checkout.session.completed`, `invoice.paid`, `customer.subscription.deleted`.
4. Restart the JARVIS service so it reads the file.

## How to test

- Open **Pricing** in the app, press **Subscribe**, pay with card `4242 4242 4242 4242`.
- Stripe returns the browser to the daemon's dashboard, which confirms the session with Stripe and writes the licence.
  The app, which is watching, then shows **Licensed**. If it does not update, press "I have paid, check now".
- Cancel the subscription in Stripe: the webhook ends the licence.

## Before going live

- Swap `sk_test_` for `sk_live_` and re-create the webhook for the live endpoint.
- Set `ARGUS_REQUIRE_LICENSE=1` on release builds only. The check is local and stops casual use, not a determined user.
- Decide the public return URL: the success address is built from the daemon's own address (`127.0.0.1:<port>`),
  so the paying browser must be on the same computer as the daemon.
- The webhook needs a reachable address; for a desktop product that normally means polling/confirm only, or a small hosted relay (`hosted/` has Cloudflare examples).
