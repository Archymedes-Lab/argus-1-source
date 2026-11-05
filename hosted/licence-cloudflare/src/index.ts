// pay.archymedes.xyz: Stripe Checkout for Argus and the Archymedes licence service.
// docs/BILLING.md and docs/STRIPE-HANDOFF.md. Stripe is the merchant of record (Managed Payments).
//
// Rules:
// - Prices are looked up by lookup_key; this worker never creates products or prices.
// - A licence key is issued once per Checkout Session (same session, same key), only for a
//   session Stripe says is complete and paid, and only for sessions with metadata.app=argus.
//   Orion shares the Stripe account and has its own webhook: an event whose metadata.app names another
//   app ("orion") is ignored before anything else, and so is any event that is not ours.
// - Customer machines call /licence/* with the key alone: no secret leaves this worker.
// - Full keys and email addresses are never logged, and emails are never stored.
import { idOf, invoiceMetadata, invoicePeriodEnd, invoiceSubscription, periodEnd, stripe, StripeError,
         verifyStripeSignature, type Fetch } from "./stripe";

export interface Env {
  DB: D1Database;
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  RESEND_API_KEY?: string;
  SITE_ORIGIN: string;
  MANAGED_PAYMENTS?: string;
  MAIL_FROM?: string;
  RL_BUY?: RateLimit;
  RL_LICENCE?: RateLimit;
}

export interface Deps { fetch: Fetch; now: () => number /* ms */ }

type Mode = "payment" | "subscription";
type Offer = { lookup: string; mode: Mode; kind: "SERVER" | "DESKTOP"; product: string; days?: number };

// Owner decision 2026-11-04 (archymedes-gtm docs/PRICE-BOOK.md, catalog/stripe.ts): two yearly plans only.
// Lookup keys are the price book's; scripts/stripe-setup.ts there creates the prices. Server Review ($149),
// Watch ($9/month) and the free desktop beta are retired and no longer sold here.
export const OFFERS: Record<string, Offer> = {
  "argus-server": { lookup: "argus_server_usd_5000_year", mode: "subscription", kind: "SERVER", product: "Argus Server" },
  "argus-desktop": { lookup: "argus_desktop_usd_7900_year", mode: "subscription", kind: "DESKTOP", product: "Argus Desktop" },
};
const SUBSCRIPTION_GRACE = 3 * 86400;
const LANGS = new Set(["en", "zh", "ja", "ko", "de"]);
const REF = /^[A-Za-z0-9_-]{1,64}$/;
const SESSION_ID = /^cs_(test|live)_[A-Za-z0-9]+$/;
const KEY = /^ARGUS-(SERVER|DESKTOP)-[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/;
const UTM = ["utm_source", "utm_medium", "utm_campaign", "utm_content"] as const;
const MAX_WEBHOOK = 1024 * 1024;
const MAX_JSON = 4096;
const PRICE_TTL_MS = 10 * 60 * 1000;

const SECURITY_HEADERS: Record<string, string> = {
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
};

const json = (data: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...SECURITY_HEADERS, ...extra } });
const fail = (status: number, error: string, extra: Record<string, string> = {}) => json({ error }, status, extra);

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
function page(status: number, title: string, text: string, link: string, linkText: string) {
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<title>${esc(title)}</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 16px;color:#111;background:#fff}` +
    `a{color:#0b57d0}</style></head><body><h1>${esc(title)}</h1><p>${esc(text)}</p><p><a href="${esc(link)}">${esc(linkText)}</a></p></body></html>`;
  return new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8", ...SECURITY_HEADERS,
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" } });
}

const managed = (env: Env) => env.MANAGED_PAYMENTS !== "0";
const origin = (env: Env) => (env.SITE_ORIGIN || "https://www.archymedes.xyz").replace(/\/+$/, "");
const pricingUrl = (env: Env, lang = "en") => `${origin(env)}/${lang}/solutions/argus/#pricing`;
const sec = (d: Deps) => Math.floor(d.now() / 1000);
const iso = (s: number | null) => (s == null ? null : new Date(s * 1000).toISOString());
const hint = (key: string) => `…${key.slice(-4)}`;

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

async function limited(rl: RateLimit | undefined, req: Request): Promise<boolean> {
  if (!rl) return false;
  try {
    const { success } = await rl.limit({ key: req.headers.get("CF-Connecting-IP") || "unknown" });
    return !success;
  } catch { return false; }
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
// GET /buy/:offer
// ---------------------------------------------------------------------------------------------
export function checkoutForm(env: Env, offerId: string, offer: Offer, price: string, url: URL): URLSearchParams {
  const lang = LANGS.has(url.searchParams.get("lang") || "") ? url.searchParams.get("lang")! : "en";
  const ref = url.searchParams.get("ref");
  const meta: [string, string][] = [["app", "argus"], ["offer", offerId]];
  if (ref && REF.test(ref)) meta.push(["ref", ref]);
  for (const k of UTM) { const v = cleanUtm(url.searchParams.get(k)); if (v) meta.push([k, v]); }
  const f = new URLSearchParams();
  f.set("mode", offer.mode);
  f.set("line_items[0][price]", price);
  f.set("line_items[0][quantity]", "1");
  if (managed(env)) f.set("managed_payments[enabled]", "true");
  else f.set("automatic_tax[enabled]", "true");
  if (ref && REF.test(ref)) f.set("client_reference_id", ref);
  f.set("locale", lang);
  const nested = offer.mode === "payment" ? "payment_intent_data" : "subscription_data";
  for (const [k, v] of meta) {
    f.set(`metadata[${k}]`, v);
    f.set(`${nested}[metadata][${k}]`, v);
  }
  f.set("success_url", `${origin(env)}/${lang}/solutions/argus/thanks/?session_id={CHECKOUT_SESSION_ID}`);
  f.set("cancel_url", pricingUrl(env, lang));
  return f;
}

async function buy(req: Request, env: Env, deps: Deps, offerId: string, url: URL): Promise<Response> {
  const lang = LANGS.has(url.searchParams.get("lang") || "") ? url.searchParams.get("lang")! : "en";
  const offer = OFFERS[offerId];
  if (!offer) return page(404, "Not found", "There is no Argus offer at this address.", pricingUrl(env, lang), "See Argus pricing");
  if (await limited(env.RL_BUY, req)) return page(429, "Please wait a moment", "Too many checkout attempts from this network. Try again in a minute.", pricingUrl(env, lang), "Back to pricing");
  try {
    const price = await priceId(env, deps, offer.lookup);
    const session = await stripe<{ url?: string }>(deps.fetch, env.STRIPE_SECRET_KEY, "POST", "/checkout/sessions",
                                                   checkoutForm(env, offerId, offer, price, url));
    if (!session.url) throw new StripeError(502, "no_url");
    return new Response(null, { status: 303, headers: { Location: session.url, ...SECURITY_HEADERS } });
  } catch (err) {
    console.log(`buy ${offerId}: ${err instanceof StripeError ? err.message : "error"}`);
    return page(502, "Checkout is not available right now",
                "The payment page could not be opened. Nothing was charged. Please try again in a few minutes.",
                pricingUrl(env, lang), "Back to pricing");
  }
}

// ---------------------------------------------------------------------------------------------
// Licences
// ---------------------------------------------------------------------------------------------
type Row = { key: string; session_id: string; offer: string; status: "active" | "revoked"; expires_at: number | null;
             customer: string | null; subscription: string | null; payment_intent: string | null; emailed_at: number | null };

const paid = (s: any) => s?.status === "complete" && (s?.payment_status === "paid" || s?.payment_status === "no_payment_required");
const ours = (meta: any) => meta?.app === "argus";
/** Another app on the shared Stripe account (e.g. "orion"): never ours, whatever else matches. */
const foreign = (meta: any) => typeof meta?.app === "string" && meta.app !== "argus";
/** The metadata an event's object carries, for every event type this worker handles. */
const eventMeta = (type: string, obj: any) => (type === "invoice.paid" ? invoiceMetadata(obj) : obj?.metadata);

/** The licence for a paid Argus Checkout Session, created on first call; the same row afterwards. */
export async function issue(env: Env, deps: Deps, session: any): Promise<Row> {
  const existing = await env.DB.prepare("SELECT * FROM licences WHERE session_id = ?").bind(session.id).first<Row>();
  if (existing) return existing;
  const offerId = String(session.metadata?.offer || "");
  const offer = OFFERS[offerId];
  if (!offer) throw new Error("session has no known offer");
  const now = sec(deps);
  let expires: number | null;
  const subId = idOf(session.subscription);
  if (offer.mode === "payment") {
    expires = (typeof session.created === "number" ? session.created : now) + (offer.days ?? 30) * 86400;
  } else {
    const sub = typeof session.subscription === "object" && session.subscription
      ? session.subscription
      : await stripe(deps.fetch, env.STRIPE_SECRET_KEY, "GET", `/subscriptions/${encodeURIComponent(subId || "")}`);
    const end = periodEnd(sub);
    if (end == null) throw new Error("subscription has no period end");
    expires = end + SUBSCRIPTION_GRACE;
  }
  const key = `ARGUS-${offer.kind}-${crypto.randomUUID().toUpperCase()}`;
  const ref = typeof session.metadata?.ref === "string" && REF.test(session.metadata.ref) ? session.metadata.ref : null;
  await env.DB.prepare(
    `INSERT OR IGNORE INTO licences (key, session_id, offer, status, expires_at, customer, subscription, payment_intent,
       livemode, ref, created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(key, session.id, offerId, expires, idOf(session.customer), subId, idOf(session.payment_intent),
          session.livemode ? 1 : 0, ref, now, now).run();
  // A concurrent call may have won the insert; the session's row is the answer either way.
  const row = await env.DB.prepare("SELECT * FROM licences WHERE session_id = ?").bind(session.id).first<Row>();
  if (!row) throw new Error("licence was not stored");
  console.log(`issued ${offerId} ${hint(row.key)}`);
  return row;
}

async function mailKey(env: Env, deps: Deps, row: Row, email: unknown): Promise<void> {
  if (!env.RESEND_API_KEY || typeof email !== "string" || !email.includes("@")) return;
  const claim = await env.DB.prepare("UPDATE licences SET emailed_at = ? WHERE key = ? AND emailed_at IS NULL")
    .bind(sec(deps), row.key).run();
  if (!claim.meta?.changes) return;  // already sent
  const offer = OFFERS[row.offer];
  const server = offer.kind === "SERVER";
  const text = [
    `Thank you for buying ${offer.product}.`, "",
    `Your licence key: ${row.key}`, "",
    "Next steps:",
    server ? `1. On the server, run: argus licence activate ${row.key}` : "1. In Argus Desktop, open Pricing and paste the key.",
    "2. The licence renews with the yearly subscription; run `argus licence refresh` to re-check it.",
    "", `Manage billing: ${origin(env)}/en/solutions/argus/ (or at link.com with the email you paid with).`,
    "Receipts and invoices come from Stripe (Link), the merchant of record.", "", "Archymedes",
  ].join("\n");
  try {
    const res = await deps.fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: env.MAIL_FROM || "Archymedes <licences@archymedes.xyz>", to: [email],
                             subject: `Your ${offer.product} licence key`, text }),
    });
    if (!res.ok) throw new Error(`resend ${res.status}`);
  } catch (err) {
    // Release the claim so Stripe's retry of this event sends it.
    await env.DB.prepare("UPDATE licences SET emailed_at = NULL WHERE key = ?").bind(row.key).run();
    throw err;
  }
}

// ---------------------------------------------------------------------------------------------
// GET /api/session/:id
// ---------------------------------------------------------------------------------------------
function cors(env: Env) {
  return { "Access-Control-Allow-Origin": origin(env), "Access-Control-Allow-Methods": "GET, OPTIONS",
           "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Max-Age": "600", Vary: "Origin" };
}

async function sessionStatus(env: Env, deps: Deps, id: string): Promise<Response> {
  const h = cors(env);
  if (!SESSION_ID.test(id)) return fail(400, "not a Checkout Session id", h);
  let session: any;
  try {
    session = await stripe(deps.fetch, env.STRIPE_SECRET_KEY, "GET", `/checkout/sessions/${id}`,
                           new URLSearchParams({ "expand[0]": "subscription" }));
  } catch (err) {
    if (err instanceof StripeError && err.status === 404) return fail(404, "not found", h);
    return fail(502, "the payment service is not answering; try again shortly", h);
  }
  if (!ours(session?.metadata) || !OFFERS[session.metadata.offer]) return fail(404, "not found", h);
  if (!paid(session)) return json({ status: session.status === "expired" ? "unpaid" : "pending" }, 200, h);
  const row = await issue(env, deps, session);
  return json({ status: "paid", offer: row.offer, key: row.key, email_hint: maskEmail(session.customer_details?.email) }, 200, h);
}

// ---------------------------------------------------------------------------------------------
// POST /stripe/webhook
// ---------------------------------------------------------------------------------------------
async function webhook(req: Request, env: Env, deps: Deps): Promise<Response> {
  const len = Number(req.headers.get("Content-Length") || "0");
  if (len > MAX_WEBHOOK) return fail(413, "too large");
  const raw = await req.text();
  if (raw.length > MAX_WEBHOOK) return fail(413, "too large");
  if (!(await verifyStripeSignature(env.STRIPE_WEBHOOK_SECRET, raw, req.headers.get("Stripe-Signature"), deps.now())))
    return fail(400, "bad signature");
  let event: any;
  try { event = JSON.parse(raw); } catch { return fail(400, "bad json"); }
  if (typeof event?.id !== "string" || typeof event?.type !== "string") return fail(400, "not an event");
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

async function handleEvent(env: Env, deps: Deps, type: string, obj: any): Promise<string> {
  if (foreign(eventMeta(type, obj))) return "ignored";
  const now = sec(deps);
  switch (type) {
    case "checkout.session.completed":
    case "checkout.session.async_payment_succeeded": {
      if (!ours(obj.metadata) || !OFFERS[obj.metadata?.offer]) return "ignored";
      if (!paid(obj)) return "awaiting payment";
      const row = await issue(env, deps, obj);
      await mailKey(env, deps, row, obj.customer_details?.email);
      return "issued";
    }
    case "invoice.paid": {
      const subId = invoiceSubscription(obj);
      if (!subId) return "ignored";
      const row = await env.DB.prepare("SELECT * FROM licences WHERE subscription = ?").bind(subId).first<Row>();
      if (!row) return ours(invoiceMetadata(obj)) ? "no licence yet" : "ignored";
      const end = invoicePeriodEnd(obj);
      if (end == null) return "no period";
      await env.DB.prepare("UPDATE licences SET expires_at = MAX(COALESCE(expires_at, 0), ?), updated_at = ? WHERE key = ?")
        .bind(end + SUBSCRIPTION_GRACE, now, row.key).run();
      return "extended";
    }
    case "customer.subscription.deleted": {
      const subId = idOf(obj);
      const row = subId ? await env.DB.prepare("SELECT key FROM licences WHERE subscription = ?").bind(subId).first() : null;
      if (!row) return ours(obj.metadata) ? "no licence" : "ignored";
      await env.DB.prepare("UPDATE licences SET status = 'revoked', updated_at = ? WHERE subscription = ?").bind(now, subId).run();
      return "revoked";
    }
    case "charge.refunded": {
      const pi = idOf(obj.payment_intent);
      const row = pi ? await env.DB.prepare("SELECT key FROM licences WHERE payment_intent = ?").bind(pi).first() : null;
      if (!row) return ours(obj.metadata) ? "no licence" : "ignored";
      const full = obj.refunded === true || (typeof obj.amount === "number" && obj.amount_refunded >= obj.amount);
      if (!full) return "partial refund";
      await env.DB.prepare("UPDATE licences SET status = 'revoked', updated_at = ? WHERE payment_intent = ?").bind(now, pi).run();
      return "revoked";
    }
    default:
      return "ignored";
  }
}

// ---------------------------------------------------------------------------------------------
// /licence/*
// ---------------------------------------------------------------------------------------------
async function readJson(req: Request): Promise<any> {
  const raw = await req.text();
  if (raw.length > MAX_JSON) return undefined;
  try { const v = JSON.parse(raw); return v && typeof v === "object" ? v : undefined; } catch { return undefined; }
}
const normKey = (k: unknown) => (typeof k === "string" ? k.trim().toUpperCase() : "");

async function licence(req: Request, env: Env, deps: Deps, action: string): Promise<Response> {
  if (await limited(env.RL_LICENCE, req)) return fail(429, "too many requests; try again in a minute");
  const body = await readJson(req);
  if (!body) return fail(400, "send a JSON object");
  const key = normKey(body.key);
  if (!KEY.test(key)) return fail(400, "that is not an Argus licence key");
  const row = await env.DB.prepare("SELECT * FROM licences WHERE key = ?").bind(key).first<Row>();
  if (!row) return fail(404, "unknown licence key");

  if (action === "activate") {
    const label = typeof body.label === "string" && body.label.trim() ? body.label.trim().slice(0, 60) : "unnamed";
    let act = await env.DB.prepare("SELECT id, label FROM activations WHERE key = ?").bind(key).first<{ id: string; label: string }>();
    if (!act) {
      await env.DB.prepare("INSERT OR IGNORE INTO activations (id, key, label, created_at) VALUES (?, ?, ?, ?)")
        .bind(crypto.randomUUID(), key, label, sec(deps)).run();
      act = await env.DB.prepare("SELECT id, label FROM activations WHERE key = ?").bind(key).first<{ id: string; label: string }>();
    }
    if (!act) return fail(500, "activation was not stored");
    if (act.label !== label)
      return fail(409, "this key is already activated on another machine; one key covers one machine. " +
                       "Activate it with the same name there, or reply to your receipt email to move it.");
    return json({ id: act.id, key, label: act.label });
  }

  if (action === "validate") {
    const act = await env.DB.prepare("SELECT id FROM activations WHERE key = ?").bind(key).first<{ id: string }>();
    if (!act || act.id !== body.activation_id) return fail(404, "this key is not activated with that activation id");
    await env.DB.prepare("UPDATE activations SET last_validated_at = ? WHERE id = ?").bind(sec(deps), act.id).run();
    const st = row.status === "revoked" ? "revoked" : row.expires_at != null && sec(deps) > row.expires_at ? "expired" : "granted";
    return json({ status: st, expires_at: iso(row.expires_at), product: OFFERS[row.offer]?.product ?? row.offer, benefit: row.offer });
  }

  if (action === "portal") {
    if (!row.customer) return fail(404, "no billing account is linked to this key; manage the purchase at https://link.com");
    try {
      const s = await stripe<{ url?: string }>(deps.fetch, env.STRIPE_SECRET_KEY, "POST", "/billing_portal/sessions",
        new URLSearchParams({ customer: row.customer, return_url: `${origin(env)}/en/solutions/argus/` }));
      if (!s.url) throw new StripeError(502, "no_url");
      return json({ url: s.url });
    } catch {
      return fail(502, "the billing portal is not available right now; you can also manage the purchase at https://link.com");
    }
  }
  return fail(404, "not found");
}

// ---------------------------------------------------------------------------------------------
export async function handle(req: Request, env: Env, deps: Deps): Promise<Response> {
  const url = new URL(req.url);
  const p = url.pathname.replace(/\/+$/, "") || "/";
  try {
    if (p === "/health" && req.method === "GET")
      return json({ ok: true, stripe: /^(sk|rk)_(test|live)_/.test(env.STRIPE_SECRET_KEY || ""), managed_payments: managed(env) });
    let m = p.match(/^\/buy\/([a-z-]{1,40})$/);
    if (m && req.method === "GET") return await buy(req, env, deps, m[1], url);
    m = p.match(/^\/api\/session\/([^/]{1,300})$/);
    if (m) {
      if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(env) });
      if (req.method === "GET") return await sessionStatus(env, deps, decodeURIComponent(m[1]));
    }
    if (p === "/stripe/webhook" && req.method === "POST") return await webhook(req, env, deps);
    m = p.match(/^\/licence\/(activate|validate|portal)$/);
    if (m && req.method === "POST") return await licence(req, env, deps, m[1]);
    if (p === "/") return Response.redirect(`${origin(env)}/en/solutions/argus/`, 302);
    return fail(404, "not found");
  } catch (err) {
    console.log(`error on ${p}: ${err instanceof StripeError ? err.message : (err as Error)?.name || "error"}`);
    return fail(500, "something went wrong; nothing was changed, try again");
  }
}

export default {
  fetch(req: Request, env: Env): Promise<Response> {
    return handle(req, env, { fetch: (u, i) => fetch(u, i), now: () => Date.now() });
  },
};
