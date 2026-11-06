// pay.archymedes.xyz: Stripe Checkout for Argus and the Archymedes licence service.
// docs/LICENSING-ARCHITECTURE.md, docs/BILLING.md, docs/STRIPE-HANDOFF.md. Stripe is the merchant of record.
//
// Rules:
// - Prices are looked up by lookup_key; this worker never creates products or prices.
// - A licence is created once per Checkout Session (same session, same licence and key), only for a session
//   Stripe says is complete and paid, and only for metadata.app=argus. Orion shares the Stripe account and has
//   its own webhook: an event whose metadata.app names another app is ignored before anything else.
// - Customer machines call /licence/* with the key or a device signature: no secret leaves this worker.
// - Keys, emails, machine ids and IPs are never stored or logged (D1 holds HMACs; see schema.sql).
// - Certificates are Ed25519 JWS (src/cert.ts); the app verifies them offline with embedded public keys.
import { contentRoute, issue, keyEmail, keyOf, bindClaim, CLAIM_ID, licenceRoute, type Claim } from "./licence";
import { manage, manageHome, recover, link, thanks } from "./manage";
import { idOf, invoiceMetadata, invoicePeriodEnd, invoiceSubscription, stripe, StripeError, subscriptionQuantity, verifyStripeSignature } from "./stripe";
import { sha256Hex } from "./keys";
import { audit, type Deps, type Env, fail, json, limited, managed, type Offer, OFFERS, payOrigin, pricingUrl, REVEAL_WINDOW,
         sec, SECURITY_HEADERS, siteOrigin, SUBSCRIPTION_GRACE, type Licence } from "./env";
import { sendMail, simplePage } from "./web";

export type { Env, Deps } from "./env";
export { OFFERS } from "./env";

const LANGS = new Set(["en", "zh", "ja", "ko", "de"]);
const REF = /^[A-Za-z0-9_-]{1,64}$/;
const SESSION_ID = /^cs_(test|live)_[A-Za-z0-9]+$/;
const UTM = ["utm_source", "utm_medium", "utm_campaign", "utm_content"] as const;
const MAX_WEBHOOK = 1024 * 1024;
const PRICE_TTL_MS = 10 * 60 * 1000;

/** a***@example.com */
export function maskEmail(email: unknown): string | null {
  if (typeof email !== "string") return null;
  const at = email.lastIndexOf("@");
  if (at < 1) return null;
  return `${email[0]}***${email.slice(at)}`;
}

/** Attribution text safe for Stripe metadata: printable, no markup, at most 100 characters. */
export function cleanUtm(v: string | null): string | null {
  if (!v) return null;
  const s = v.replace(/[^A-Za-z0-9 ._~:/@+-]/g, "").trim().slice(0, 100);
  return s || null;
}

// ---------------------------------------------------------------------------------------------
// Prices (by lookup key, cached)
// ---------------------------------------------------------------------------------------------
const priceCache = new Map<string, { id: string; at: number }>();
export const clearPriceCache = () => priceCache.clear();

async function priceId(env: Env, deps: Deps, lookup: string): Promise<string> {
  const hit = priceCache.get(lookup);
  if (hit && deps.now() - hit.at < PRICE_TTL_MS) return hit.id;
  const q = new URLSearchParams({ "lookup_keys[0]": lookup, active: "true", limit: "1" });
  const list = await stripe<{ data?: { id?: string }[] }>(deps.fetch, env.STRIPE_SECRET_KEY, "GET", "/prices", q);
  const id = list.data?.[0]?.id;
  if (!id) throw new StripeError(404, "price_not_found");
  priceCache.set(lookup, { id, at: deps.now() });
  return id;
}

// ---------------------------------------------------------------------------------------------
// GET /buy/:offer[?claim=clm_…]
// ---------------------------------------------------------------------------------------------
export function checkoutForm(env: Env, offerId: string, offer: Offer, price: string, url: URL): URLSearchParams {
  const lang = LANGS.has(url.searchParams.get("lang") || "") ? url.searchParams.get("lang")! : "en";
  const ref = url.searchParams.get("ref");
  const claim = url.searchParams.get("claim");
  const meta: [string, string][] = [["app", "argus"], ["offer", offerId]];
  if (ref && REF.test(ref)) meta.push(["ref", ref]);
  for (const k of UTM) { const v = cleanUtm(url.searchParams.get(k)); if (v) meta.push([k, v]); }
  const f = new URLSearchParams();
  f.set("mode", offer.mode);
  f.set("line_items[0][price]", price);
  // A fleet offer opens with ?servers=N or ?computers=N (default 1) and the buyer can change it on the Stripe page.
  const asked = Number.parseInt(url.searchParams.get("servers") || url.searchParams.get("computers") || "1", 10);
  const qty = offer.fleet && Number.isFinite(asked) ? Math.min(Math.max(asked, 1), offer.fleet.max) : 1;
  f.set("line_items[0][quantity]", String(qty));
  if (offer.fleet) {
    f.set("line_items[0][adjustable_quantity][enabled]", "true");
    f.set("line_items[0][adjustable_quantity][minimum]", "1");
    f.set("line_items[0][adjustable_quantity][maximum]", String(offer.fleet.max));
  }
  f.set("allow_promotion_codes", "true");
  if (managed(env)) f.set("managed_payments[enabled]", "true");
  else f.set("automatic_tax[enabled]", "true");
  if (ref && REF.test(ref)) f.set("client_reference_id", ref);
  f.set("locale", lang);
  const nested = offer.mode === "payment" ? "payment_intent_data" : "subscription_data";
  for (const [k, v] of meta) {
    f.set(`metadata[${k}]`, v);
    f.set(`${nested}[metadata][${k}]`, v);
  }
  // The device claim from "Upgrade" in Argus: only on the session, so the webhook can activate that device.
  if (claim && CLAIM_ID.test(claim)) f.set("metadata[claim]", claim);
  f.set("success_url", `${payOrigin(env)}/thanks?session_id={CHECKOUT_SESSION_ID}&lang=${lang}`);
  f.set("cancel_url", pricingUrl(env, lang));
  return f;
}

async function buy(req: Request, env: Env, deps: Deps, offerId: string, url: URL): Promise<Response> {
  const lang = LANGS.has(url.searchParams.get("lang") || "") ? url.searchParams.get("lang")! : "en";
  const offer = OFFERS[offerId];
  if (!offer) return simplePage(404, "Not found", "There is no Argus offer at this address.", pricingUrl(env, lang), "See Argus pricing");
  if (await limited(env.RL_BUY, req)) return simplePage(429, "Please wait a moment", "Too many checkout attempts from this network. Try again in a minute.", pricingUrl(env, lang), "Back to pricing");
  try {
    const price = await priceId(env, deps, offer.lookup);
    const session = await stripe<{ url?: string }>(deps.fetch, env.STRIPE_SECRET_KEY, "POST", "/checkout/sessions",
                                                   checkoutForm(env, offerId, offer, price, url));
    if (!session.url) throw new StripeError(502, "no_url");
    return new Response(null, { status: 303, headers: { Location: session.url, ...SECURITY_HEADERS } });
  } catch (err) {
    console.log(`buy ${offerId}: ${err instanceof StripeError ? err.message : "error"}`);
    return simplePage(502, "Checkout is not available right now",
                      "The payment page could not be opened. Nothing was charged. Please try again in a few minutes.",
                      pricingUrl(env, lang), "Back to pricing");
  }
}

// ---------------------------------------------------------------------------------------------
// Licence creation from a paid session (webhook, thank-you page, /api/session)
// ---------------------------------------------------------------------------------------------
const paid = (s: any) => s?.status === "complete" && (s?.payment_status === "paid" || s?.payment_status === "no_payment_required");
const ours = (meta: any) => meta?.app === "argus";
/** Another app on the shared Stripe account (e.g. "orion"): never ours, whatever else matches. */
const foreign = (meta: any) => typeof meta?.app === "string" && meta.app !== "argus";
/** The metadata an event's object carries, for every event type this worker handles. */
const eventMeta = (type: string, obj: any) => (type === "invoice.paid" ? invoiceMetadata(obj) : obj?.metadata);

async function bindSessionClaim(env: Env, deps: Deps, session: any, lic: Licence): Promise<void> {
  const claimId = typeof session.metadata?.claim === "string" ? session.metadata.claim : "";
  if (!CLAIM_ID.test(claimId)) return;
  const claim = await env.DB.prepare("SELECT * FROM claims WHERE id_hash = ?").bind(await sha256Hex(claimId)).first<Claim>();
  if (claim && !claim.licence_id) await bindClaim(env, deps, claim, lic, "stripe");
}

async function mailKey(env: Env, deps: Deps, lic: Licence, email: unknown): Promise<void> {
  if (!env.RESEND_API_KEY || typeof email !== "string" || !email.includes("@")) return;
  const claim = await env.DB.prepare("UPDATE licences_v2 SET emailed_at = ? WHERE id = ? AND emailed_at IS NULL").bind(sec(deps), lic.id).run();
  if (!claim.meta?.changes) return;  // already sent
  const m = keyEmail(env, lic, await keyOf(env, lic));
  if (!(await sendMail(env, deps, email, m.subject, m.text))) {
    // Release the claim so Stripe's retry of this event sends it.
    await env.DB.prepare("UPDATE licences_v2 SET emailed_at = NULL WHERE id = ?").bind(lic.id).run();
    throw new Error("key email failed");
  }
}

// ---------------------------------------------------------------------------------------------
// GET /api/session/:id (for the marketing site's own thank-you page; same reveal window as /thanks)
// ---------------------------------------------------------------------------------------------
function cors(env: Env) {
  return { "Access-Control-Allow-Origin": siteOrigin(env), "Access-Control-Allow-Methods": "GET, OPTIONS",
           "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Max-Age": "600", Vary: "Origin" };
}

async function sessionStatus(env: Env, deps: Deps, id: string): Promise<Response> {
  const h = cors(env);
  if (!SESSION_ID.test(id)) return fail(400, "bad_request", "not a Checkout Session id", {}, h);
  let session: any;
  try {
    session = await stripe(deps.fetch, env.STRIPE_SECRET_KEY, "GET", `/checkout/sessions/${id}`,
                           new URLSearchParams({ "expand[0]": "subscription" }));
  } catch (err) {
    if (err instanceof StripeError && err.status === 404) return fail(404, "not_found", "not found", {}, h);
    return fail(502, "stripe_unavailable", "the payment service is not answering; try again shortly", {}, h);
  }
  if (!ours(session?.metadata) || !OFFERS[session.metadata.offer]) return fail(404, "not_found", "not found", {}, h);
  if (!paid(session)) return json({ status: session.status === "expired" ? "unpaid" : "pending" }, 200, h);
  const { lic } = await issue(env, deps, session);
  await bindSessionClaim(env, deps, session, lic);
  const created = typeof session.created === "number" ? session.created : lic.created_at;
  const reveal = sec(deps) - created <= REVEAL_WINDOW;
  return json({ status: "paid", offer: lic.offer, key: reveal ? await keyOf(env, lic) : null, key_hint: `…${lic.key_last4}`,
                email_hint: maskEmail(session.customer_details?.email) }, 200, h);
}

// ---------------------------------------------------------------------------------------------
// POST /stripe/webhook
// ---------------------------------------------------------------------------------------------
async function webhook(req: Request, env: Env, deps: Deps): Promise<Response> {
  const len = Number(req.headers.get("Content-Length") || "0");
  if (len > MAX_WEBHOOK) return fail(413, "too_large", "too large");
  const raw = await req.text();
  if (raw.length > MAX_WEBHOOK) return fail(413, "too_large", "too large");
  if (!(await verifyStripeSignature(env.STRIPE_WEBHOOK_SECRET, raw, req.headers.get("Stripe-Signature"), deps.now())))
    return fail(400, "bad_signature", "bad signature");
  let event: any;
  try { event = JSON.parse(raw); } catch { return fail(400, "bad_json", "bad json"); }
  if (typeof event?.id !== "string" || typeof event?.type !== "string") return fail(400, "not_an_event", "not an event");
  const seen = await env.DB.prepare("SELECT id FROM processed_events WHERE id = ?").bind(event.id).first();
  if (seen) return json({ received: true, duplicate: true });
  const obj = event.data?.object ?? {};
  const handled = await handleEvent(env, deps, event.type, obj);
  if (handled === "ignored") return json({ received: true, ignored: true });
  await env.DB.prepare("INSERT OR IGNORE INTO processed_events (id, type, processed_at) VALUES (?, ?, ?)")
    .bind(event.id, event.type, sec(deps)).run();
  console.log(`event ${event.type} ${event.id}: ${handled}`);
  return json({ received: true });
}

async function revoke(env: Env, deps: Deps, column: "subscription" | "payment_intent", value: string): Promise<boolean> {
  const lic = await env.DB.prepare(`SELECT id FROM licences_v2 WHERE ${column} = ?`).bind(value).first<{ id: string }>();
  if (!lic) return false;
  const now = sec(deps);
  await env.DB.prepare(`UPDATE licences_v2 SET status = 'revoked', revoked_at = COALESCE(revoked_at, ?), updated_at = ? WHERE ${column} = ?`)
    .bind(now, now, value).run();
  await audit(env, deps, lic.id, "revoked", "stripe");
  return true;
}

async function handleEvent(env: Env, deps: Deps, type: string, obj: any): Promise<string> {
  if (foreign(eventMeta(type, obj))) return "ignored";
  const now = sec(deps);
  switch (type) {
    case "checkout.session.completed":
    case "checkout.session.async_payment_succeeded": {
      if (!ours(obj.metadata) || !OFFERS[obj.metadata?.offer]) return "ignored";
      if (!paid(obj)) return "awaiting payment";
      const { lic } = await issue(env, deps, obj);
      await bindSessionClaim(env, deps, obj, lic);
      await mailKey(env, deps, lic, obj.customer_details?.email);
      return "issued";
    }
    case "invoice.paid": {
      const subId = invoiceSubscription(obj);
      if (!subId) return "ignored";
      const lic = await env.DB.prepare("SELECT id FROM licences_v2 WHERE subscription = ?").bind(subId).first<{ id: string }>();
      if (!lic) return ours(invoiceMetadata(obj)) ? "no licence yet" : "ignored";
      const end = invoicePeriodEnd(obj);
      if (end == null) return "no period";
      // Never shortens: a late or replayed older invoice cannot pull lic_exp back.
      await env.DB.prepare("UPDATE licences_v2 SET lic_exp = MAX(COALESCE(lic_exp, 0), ?), updated_at = ? WHERE id = ?")
        .bind(end + SUBSCRIPTION_GRACE, now, lic.id).run();
      await audit(env, deps, lic.id, "extended", "stripe");
      return "extended";
    }
    case "customer.subscription.updated": {
      // A fleet licence follows the subscription quantity (servers added or removed in the billing portal).
      const subId = idOf(obj);
      const lic = subId ? await env.DB.prepare("SELECT id, offer, seats FROM licences_v2 WHERE subscription = ?").bind(subId).first<{ id: string; offer: string; seats: number }>() : null;
      if (!lic) return ours(obj.metadata) ? "no licence yet" : "ignored";
      if (!OFFERS[lic.offer]?.fleet) return "not a fleet";
      const qty = subscriptionQuantity(obj);
      if (qty == null || qty === lic.seats) return "unchanged";
      await env.DB.prepare("UPDATE licences_v2 SET seats = ?, updated_at = ? WHERE id = ?").bind(qty, now, lic.id).run();
      await audit(env, deps, lic.id, `seats ${lic.seats}->${qty}`, "stripe");
      return "seats";
    }
    case "customer.subscription.deleted": {
      const subId = idOf(obj);
      if (subId && (await revoke(env, deps, "subscription", subId))) return "revoked";
      return ours(obj.metadata) ? "no licence" : "ignored";
    }
    case "charge.refunded": {
      // One-time purchases are matched by payment intent. Both current plans are subscriptions: under Managed
      // Payments a refund comes with the subscription's cancellation, and customer.subscription.deleted revokes.
      const pi = idOf(obj.payment_intent);
      const full = obj.refunded === true || (typeof obj.amount === "number" && obj.amount_refunded >= obj.amount);
      const lic = pi ? await env.DB.prepare("SELECT id FROM licences_v2 WHERE payment_intent = ?").bind(pi).first() : null;
      if (!lic) return ours(obj.metadata) ? "no licence" : "ignored";
      if (!full) return "partial refund";
      await revoke(env, deps, "payment_intent", pi!);
      return "revoked";
    }
    default:
      return "ignored";
  }
}

// ---------------------------------------------------------------------------------------------
export async function handle(req: Request, env: Env, deps: Deps): Promise<Response> {
  const url = new URL(req.url);
  const p = url.pathname.replace(/\/+$/, "") || "/";
  try {
    if (p === "/health" && req.method === "GET")
      return json({ ok: true, stripe: /^(sk|rk)_(test|live)_/.test(env.STRIPE_SECRET_KEY || ""), managed_payments: managed(env),
                    signing: !!env.LICENCE_SIGNING_KEY, pepper: (env.KEY_PEPPER || "").length >= 32 });
    let m = p.match(/^\/buy\/([a-z-]{1,40})$/);
    if (m && req.method === "GET") return await buy(req, env, deps, m[1], url);
    m = p.match(/^\/api\/session\/([^/]{1,300})$/);
    if (m) {
      if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(env) });
      if (req.method === "GET") return await sessionStatus(env, deps, decodeURIComponent(m[1]));
    }
    if (p === "/stripe/webhook" && req.method === "POST") return await webhook(req, env, deps);
    // Machine-facing JSON API. No CORS headers: no browser page needs to call it.
    m = p.match(/^\/licence\/(activate|renew|release|claim|claim\/poll|portal)$/);
    if (m && req.method === "POST") return await licenceRoute(req, env, deps, m[1] === "claim/poll" ? "poll" : m[1]);
    m = p.match(/^\/content\/([a-z0-9-]{1,40})$/);
    if (m && req.method === "POST") return await contentRoute(req, env, deps, m[1]);
    // People-facing pages.
    if (p === "/thanks" && req.method === "GET") {
      if (await limited(env.RL_LICENCE, req, "pages:")) return simplePage(429, "Please wait a moment", "Too many requests. Try again in a minute.");
      return await thanks(env, deps, url);
    }
    if (p === "/recover" && (req.method === "GET" || req.method === "POST")) return await recover(req, env, deps);
    if (p === "/link" && (req.method === "GET" || req.method === "POST")) return await link(req, env, deps);
    if (p === "/manage/home" && req.method === "GET") return await manageHome(req, env, deps, url);
    if (p === "/manage" || p.startsWith("/manage/")) {
      if (await limited(env.RL_LICENCE, req, "pages:")) return simplePage(429, "Please wait a moment", "Too many requests. Try again in a minute.");
      return await manage(req, env, deps, p, url);
    }
    if (p === "/") return Response.redirect(`${siteOrigin(env)}/en/solutions/argus/`, 302);
    return fail(404, "not_found", "not found");
  } catch (err) {
    console.log(`error on ${p}: ${err instanceof StripeError ? err.message : (err as Error)?.name || "error"}`);
    return fail(500, "server_error", "something went wrong; nothing was changed, try again");
  }
}

/**
 * Local end-to-end runs only: with PAY_ORIGIN on loopback and DEV_FAKE_UPSTREAM set (in .dev.vars), Stripe and
 * Resend calls go to a fake upstream instead. Ignored unless the worker itself is on 127.0.0.1, so a deployed
 * worker can never be pointed elsewhere by a stray variable.
 */
export function upstream(env: Env & { DEV_FAKE_UPSTREAM?: string }): (u: string, i?: RequestInit) => Promise<Response> {
  const fake = env.DEV_FAKE_UPSTREAM;
  if (!fake || !/^http:\/\/127\.0\.0\.1:\d+$/.test(fake) || !/^http:\/\/127\.0\.0\.1:\d+$/.test(payOrigin(env)))
    return (u, i) => fetch(u, i);
  return (u, i) => fetch(u.replace(/^https:\/\/api\.(stripe|resend)\.com/, fake), i);
}

export default {
  fetch(req: Request, env: Env): Promise<Response> {
    return handle(req, env, { fetch: upstream(env), now: () => Date.now() });
  },
};
