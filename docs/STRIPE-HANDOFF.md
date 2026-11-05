# Stripe hand-off: deploying pay.archymedes.xyz

Everything below is done by the owner, on the seller machine. Nothing here has been run.
The Worker is `hosted/licence-cloudflare` (Cloudflare Worker + D1). Pinned Stripe API
version: **`2026-10-28.endive`** (`src/stripe.ts`); Managed Payments needs
`2025-03-31.basil` or later.

## 0. Stripe account (Dashboard)

1. Turn on Managed Payments: Dashboard → Settings → Managed Payments.
2. Run archymedes-gtm `scripts/stripe-setup.ts`, which creates the two products (tax code
   `txcd_10103101`, eligible for Managed Payments) and prices with these lookup keys:
   `argus_server_usd_5000_year` ($50 / year per server) and `argus_desktop_usd_7900_year`
   ($79 / year). The Worker never creates prices. With `--retire` it also deactivates the
   retired Server Review and Watch prices, if they were ever created.
3. Configure the customer billing portal (Settings → Billing → Customer portal) so
   `POST /licence/portal` can open it.
4. Create a **restricted key** (`rk_live_…`) with: `checkout_session_write`,
   `checkout_session_read`, `plan_read` (prices), `subscription_read`, `customer_portal_write`.
   That is every Stripe call the Worker makes (archymedes-gtm `docs/stripe-restricted-keys.md`).

## 1. D1 database

```sh
cd hosted/licence-cloudflare
bun install
npx wrangler d1 create argus-licence          # paste the printed database_id into wrangler.jsonc
npx wrangler d1 execute argus-licence --remote --file=schema.sql
```

## 2. Secrets (never in a file)

```sh
npx wrangler secret put STRIPE_SECRET_KEY      # rk_live_… or sk_live_…
npx wrangler secret put STRIPE_WEBHOOK_SECRET  # whsec_… from step 4
npx wrangler secret put RESEND_API_KEY         # optional: emails the key after payment
```

Vars in `wrangler.jsonc`: `SITE_ORIGIN=https://www.archymedes.xyz`, `MANAGED_PAYMENTS="1"`
(`"0"` falls back to `automatic_tax[enabled]=true`), `MAIL_FROM` (a verified Resend sender on archymedes.xyz).

## 3. Deploy and custom domain

```sh
bun test && npx tsc --noEmit
npx wrangler deploy
```

`wrangler.jsonc` routes the custom domain `pay.archymedes.xyz` (the archymedes.xyz zone
must be on the same Cloudflare account). Check: `curl https://pay.archymedes.xyz/health`
→ `{"ok":true,"stripe":true,"managed_payments":true}`.

## 4. Webhook endpoint

Dashboard → Developers → Webhooks → Add endpoint, or:

```sh
stripe webhook_endpoints create \
  --url https://pay.archymedes.xyz/stripe/webhook \
  --api-version 2026-10-28.endive \
  -d "enabled_events[]=checkout.session.completed" \
  -d "enabled_events[]=checkout.session.async_payment_succeeded" \
  -d "enabled_events[]=invoice.paid" \
  -d "enabled_events[]=customer.subscription.deleted" \
  -d "enabled_events[]=charge.refunded"
```

Put its signing secret into `STRIPE_WEBHOOK_SECRET` (step 2). Orion's webhook on the same
account is separate; this endpoint ignores anything without `metadata.app=argus`.

## 5. Test mode first

Repeat steps 1–4 with `sk_test_`/`rk_test_` and a test webhook, then buy with card
`4242 4242 4242 4242`: `/buy/argus-server` → thanks page shows the key →
`argus licence activate <key>` → `argus review` is the full report. Cancel the subscription
in the Dashboard → `argus licence refresh` reports the key revoked. In a sandbox Stripe sends
no receipt email automatically (Dashboard → payment → Send receipt to preview).

## Customer support notes

- Receipts and invoices come from Link (Stripe) automatically; buyers manage subscriptions
  at https://link.com or through the billing-portal link (`POST /licence/portal`).
- One key covers one machine. To move a key, delete its row in `activations` for that key
  (`wrangler d1 execute argus-licence --remote --command "DELETE FROM activations WHERE key = '…'"`).
- Logs never contain full keys or emails (only the last 4 characters of a key).
