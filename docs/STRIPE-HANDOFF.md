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

## 1. D1 database (and migration)

```sh
cd hosted/licence-cloudflare
bun install
npx wrangler d1 create argus-licence          # paste the printed database_id into wrangler.jsonc
npx wrangler d1 execute argus-licence --remote --file=schema.sql
```

`schema.sql` is idempotent and never drops anything; run it again after every update. The licence
tables are `licences_v2`, `activations_v2`, `claims`, `magic_links`, `manage_sessions`, `releases`,
`nonces`, `throttle`, `audit` and `processed_events`.

**Migration from the first payments schema.** The first version stored keys in plain text in tables
`licences` and `activations`. It was never deployed (pay.archymedes.xyz had no DNS record and
`wrangler.jsonc` still had `REPLACE_WITH_D1_ID`), so no `ARGUS-SERVER-<UUID>` key was ever issued and the
client no longer accepts that format. If a test database has those tables, check they are empty and drop
them:

```sh
npx wrangler d1 execute argus-licence --remote --command "SELECT COUNT(*) FROM licences"
npx wrangler d1 execute argus-licence --remote --command "DROP TABLE IF EXISTS activations; DROP TABLE IF EXISTS licences"
```

## 2. Signing keys and secrets (never in a file in the repo)

**Licence signing key (Ed25519).** Run once per environment (test and live get different keys):

```sh
bun scripts/licence-keygen.ts --kid 2026-11-a          # live
bun scripts/licence-keygen.ts --kid 2026-11-test --out ~/.config/archymedes/test   # test Worker
```

It writes the private key to `~/.config/archymedes/argus-licence-<kid>.secret` (mode 0600, outside the
repo; back it up in your password manager), adds the public key to `jarvis/licensing/trust.py`, and prints
the command below. Commit `trust.py` and ship that Argus release **before** the Worker signs with the new
kid: a build that does not know a kid refuses its certificates (it says "update Argus"). A test kid in a
release build is harmless (it only verifies test certificates) but remove it before a public release.

```sh
npx wrangler secret put LICENCE_SIGNING_KEY < ~/.config/archymedes/argus-licence-2026-11-a.secret
openssl rand -base64 48 | tr -d '\n' | npx wrangler secret put KEY_PEPPER   # once; keep a copy in the password manager
npx wrangler secret put STRIPE_SECRET_KEY      # rk_live_… or sk_live_…
npx wrangler secret put STRIPE_WEBHOOK_SECRET  # whsec_… from step 4
npx wrangler secret put RESEND_API_KEY         # emails keys, sign-in links and recoveries
```

`KEY_PEPPER` keys the HMACs for key hashes and email hashes and derives the keys themselves (so they can be
re-sent without being stored). **Never change it on a live database:** every existing key would stop
matching. Treat it like the signing key: if it leaks, keys can be computed from Checkout Session ids.

**Rotating the signing key:** make a new kid with the script, ship the release with both kids in
`trust.py`, `wrangler secret put LICENCE_SIGNING_KEY` with the new one, wait 30 days (the longest lease),
then remove the old kid from `trust.py` in a later release.

Vars in `wrangler.jsonc`: `SITE_ORIGIN=https://www.archymedes.xyz`, `PAY_ORIGIN=https://pay.archymedes.xyz`
(links in emails and pages), `SUPPORT_EMAIL`, `MANAGED_PAYMENTS="1"` (`"0"` falls back to
`automatic_tax[enabled]=true`), `MAIL_FROM` (a verified Resend sender on archymedes.xyz). Rate limits
(`RL_BUY`, `RL_LICENCE`, `RL_EMAIL`) are Workers rate-limiting bindings, per IP.

## 3. Deploy and custom domain

```sh
bun test && npx tsc --noEmit
npx wrangler deploy
```

`wrangler.jsonc` routes the custom domain `pay.archymedes.xyz` (the archymedes.xyz zone
must be on the same Cloudflare account). Check: `curl https://pay.archymedes.xyz/health`
→ `{"ok":true,"stripe":true,"managed_payments":true,"signing":true,"pepper":true}`.

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

Repeat steps 1–4 with `sk_test_`/`rk_test_`, a test signing kid and a test webhook, then buy with card
`4242 4242 4242 4242`: `/buy/argus-server` → the thank-you page at `/thanks` shows the key →
`argus licence activate <key>` → `argus review` is the full report. Then: `argus licence buy desktop` on
another machine (activates by itself), `/manage` with the purchase email (release a machine, resend the
key), `/recover`. Cancel the subscription in the Dashboard → `argus licence refresh` reports it cancelled.
In a sandbox Stripe sends no receipt email automatically (Dashboard → payment → Send receipt to preview).

**Local run without Stripe** (what was used to test this): put test values in `.dev.vars` (gitignored)
including `PAY_ORIGIN=http://127.0.0.1:9477` and `DEV_FAKE_UPSTREAM=http://127.0.0.1:<port of a fake
Stripe>`, then `npx wrangler dev --ip 127.0.0.1 --port 9477 --local-upstream 127.0.0.1:9477
--upstream-protocol http` (without the last two flags wrangler rewrites the browser's Origin header to
pay.archymedes.xyz and the manage forms are refused), and point the client at it with
`ARGUS_LICENCE_API=http://127.0.0.1:9477`. `DEV_FAKE_UPSTREAM` is ignored unless the Worker itself is on
127.0.0.1.

## Support runbooks

Customers can do most of this themselves at `https://pay.archymedes.xyz/manage` (release a machine, resend
the key, billing) and `/recover` (lost key). The database holds no keys or emails, so support looks rows
up by hash with `scripts/support.ts` (needs `KEY_PEPPER` in the environment; it prints SQL and connects to
nothing). Run its SQL with `npx wrangler d1 execute argus-licence --remote --command "<sql>"`.

- **Find a licence:** `KEY_PEPPER=… bun scripts/support.ts key ARGUS-SRV-…` or `… email someone@example.com`.
  Then `SELECT id, label, created_at, released_at FROM activations_v2 WHERE licence_id = 'lic_…'`.
- **Move a licence** (the customer is over the 3-releases-in-30-days limit, or lost the old machine):
  `UPDATE activations_v2 SET released_at = unixepoch(), released_by = 'support' WHERE id = 'act_…'`, then
  `INSERT INTO audit (at, licence_id, action, actor) VALUES (unixepoch(), 'lic_…', 'released', 'support')`.
  Support releases do not count toward the limit. The customer then activates on the new machine.
- **Machine fingerprint changed** (Windows or Linux reinstalled, VM cloned, WSL interop turned off): the old
  activation cannot renew from the new install. The customer releases it at `/manage` (or support does, as
  above) and activates again. Reinstalling only Argus on the same machine needs nothing: the seat follows.
- **Resend a key:** ask the customer to use `/recover` (it goes to the purchase email only). Support cannot
  see keys; `support.ts reissue` is for leaked keys.
- **Leaked key:** `KEY_PEPPER=… bun scripts/support.ts reissue cs_… <current key_gen> server|desktop` prints a
  new key and the SQL that retires the old one. Send the new key to the purchase email; release strangers'
  activations as above.
- **Revoke** (chargeback or abuse outside Stripe's events): `UPDATE licences_v2 SET status = 'revoked',
  revoked_at = unixepoch(), updated_at = unixepoch() WHERE id = 'lic_…'`. Renewals and content stop at once;
  the machine is no longer licensed when its lease ends (at most 30 days) or at its next renewal. Refunds and
  cancellations in Stripe do this automatically (`customer.subscription.deleted`).
- Receipts and invoices come from Link (Stripe); buyers manage subscriptions at https://link.com or through
  "Billing and invoices" on `/manage`.
- Logs never contain keys, emails or IPs (at most the last 4 characters of a key).
