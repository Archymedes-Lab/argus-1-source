# Licence and payments (Stripe, Managed Payments)

Decided 2026-11-04: Polar is dropped. Argus is sold through Stripe Checkout with
**Stripe Managed Payments**, so Stripe is the merchant of record: it takes the card,
calculates and remits sales tax / VAT, handles fraud and disputes, and sends receipts and
invoices through Link. Checkout and licences are served by one Cloudflare Worker,
`hosted/licence-cloudflare`, at **https://pay.archymedes.xyz** (the "Archymedes licence
service"). Deploying it: `docs/STRIPE-HANDOFF.md`.

| Offer (`/buy/…`) | Stripe Price lookup key | Mode | Licence valid | Key prefix |
|---|---|---|---|---|
| `argus-review` (Argus Server Review, $149) | `argus_review_usd_14900_once` | payment | 30 days from purchase | `ARGUS-REVIEW-` |
| `argus-watch` (Argus Watch, $9/month) | `argus_watch_usd_900_month` | subscription | current period end + 3 days, extended on every paid invoice | `ARGUS-WATCH-` |
| `argus-desktop` (Argus Desktop, $79/year) | `argus_desktop_usd_7900_year` | subscription | as Watch | `ARGUS-DESKTOP-` |

Argus Desktop is **free during the beta**: `/buy/argus-desktop` shows a "free during the
beta" page until the Worker var `ARGUS_DESKTOP_OPEN` is `"1"`.

Prices and products are created by a separate setup script (with an eligible Managed
Payments `tax_code` on every product); the Worker only looks prices up by lookup key.

## How a purchase becomes a licence

1. The buyer follows `https://pay.archymedes.xyz/buy/argus-review` (optionally with `ref`,
   `utm_*` and `lang`). The Worker creates a Checkout Session with
   `managed_payments[enabled]=true` and `metadata[app]=argus` and redirects to Stripe.
2. After payment Stripe returns the buyer to
   `https://www.archymedes.xyz/<lang>/solutions/argus/thanks/?session_id=cs_…`; that page
   calls `GET https://pay.archymedes.xyz/api/session/cs_…` and shows the key.
3. Stripe also calls `POST /stripe/webhook` (`checkout.session.completed`); the Worker
   issues the same key (one key per Checkout Session, however many times it is asked) and,
   when `RESEND_API_KEY` is set, emails it once with the next steps.
4. On the server: `argus licence activate ARGUS-REVIEW-…`.
   `jarvis/licensing/licence.py` calls `POST /licence/activate` `{key, label}` (label = host
   name) and `POST /licence/validate` `{key, activation_id}`. **No API token or seller secret
   is on any customer machine.** One key covers one machine: activating again with the same
   name returns the same activation; another name is refused (HTTP 409).
5. The answer is stored owner-only beside the store (`licence.json`, written atomically).
   Status is read offline; a granted key stays valid for 7 days after the last good check
   (`argus licence refresh`), never past its expiry. A key the service refuses, revokes or
   reports expired is not licensed from that check on.

Revocation: a full refund (`charge.refunded`) of a one-time purchase, or a cancelled
subscription (`customer.subscription.deleted`), marks the key revoked; the next refresh on
the machine ends the grant.

Managing a purchase: `POST /licence/portal {key}` returns a Stripe billing-portal link for
the key's customer. Managed Payments buyers can also manage subscriptions, receipts and
support at **https://link.com** with the email they paid with.

## What a licence never does

A licence never gates protection: collectors, detection, alerts, evidence, the assistant and
on-demand checks run the same with no licence, an expired one or a forged one
(`tests/test_licence_never_gates_core.py`). There is no lock switch and no HTTP 402
anywhere. A licence unlocks premium content only (today: the full server review report).

## Shared Stripe account

Orion sells from the same Stripe account and has its own webhook endpoint. The Argus Worker
acts only on objects carrying `metadata.app=argus` (or a subscription / payment it issued a
key for) and answers every other event with 200 and no change.
