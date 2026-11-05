import { beforeEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { clearPriceCache, handle, maskEmail, type Deps, type Env } from "../src/index";
import { hmacHex, STRIPE_VERSION, verifyStripeSignature } from "../src/stripe";

// Synthetic values only: no live key, no live endpoint is ever contacted.
const WHSEC = "whsec_test_synthetic";
const NOW_MS = Date.UTC(2026, 10, 4, 12, 0, 0);
const NOW = Math.floor(NOW_MS / 1000);
const YEAR_END = NOW + 365 * 86400;
const FORBIDDEN = ["automatic_tax", "tax_id_collection", "payment_method_types", "payment_method_configuration",
  "excluded_payment_method_types", "customer_update", "invoice_creation", "shipping_address_collection", "shipping_options",
  "payment_intent_data[statement_descriptor", "payment_intent_data[receipt_email]", "payment_intent_data[shipping]",
  "subscription_data[invoice_settings]", "subscription_data[default_tax_rates]", "adaptive_pricing"];

function fakeD1() {
  const db = new Database(":memory:");
  db.exec(readFileSync(new URL("../schema.sql", import.meta.url), "utf8"));
  const prepare = (sql: string) => {
    let args: any[] = [];
    const stmt = {
      bind(...a: any[]) { args = a.map((v) => (v === undefined ? null : v)); return stmt; },
      async first() { return (db.query(sql).get(...args) as any) ?? null; },
      async all() { return { results: db.query(sql).all(...args) }; },
      async run() { const r = db.query(sql).run(...args); return { meta: { changes: r.changes } }; },
    };
    return stmt;
  };
  return { db, d1: { prepare } as unknown as D1Database };
}

type Call = { url: string; method: string; headers: Record<string, string>; body: string };

class FakeStripe {
  calls: Call[] = [];
  sessions = new Map<string, any>();
  subscriptions = new Map<string, any>();
  failCheckout = false;
  resendOk = true;
  fetch = async (url: string, init: RequestInit = {}) => {
    const call = { url, method: init.method || "GET", headers: init.headers as Record<string, string>, body: String(init.body ?? "") };
    this.calls.push(call);
    const u = new URL(url);
    const ok = (b: unknown) => new Response(JSON.stringify(b), { status: 200 });
    if (u.host === "api.resend.com") return new Response("{}", { status: this.resendOk ? 200 : 500 });
    if (u.pathname === "/v1/prices") return ok({ data: [{ id: `price_for_${u.searchParams.get("lookup_keys[0]")}` }] });
    if (u.pathname === "/v1/checkout/sessions" && call.method === "POST") {
      if (this.failCheckout)
        return new Response(JSON.stringify({ error: { code: "x", message: "customer jane@example.com is blocked" } }), { status: 400 });
      return ok({ id: "cs_test_new", url: "https://checkout.stripe.com/c/pay/cs_test_new" });
    }
    let m = u.pathname.match(/^\/v1\/checkout\/sessions\/(.+)$/);
    if (m) return this.sessions.has(m[1]) ? ok(this.sessions.get(m[1])) : new Response("{}", { status: 404 });
    m = u.pathname.match(/^\/v1\/subscriptions\/(.+)$/);
    if (m) return ok(this.subscriptions.get(m[1]));
    if (u.pathname === "/v1/billing_portal/sessions") return ok({ url: "https://billing.stripe.com/p/session/test_1" });
    return new Response("{}", { status: 404 });
  };
  stripeCalls(path: string) { return this.calls.filter((c) => new URL(c.url).pathname === path); }
}

let stripe: FakeStripe, store: ReturnType<typeof fakeD1>, env: Env, deps: Deps;
beforeEach(() => {
  clearPriceCache();
  stripe = new FakeStripe();
  store = fakeD1();
  env = { DB: store.d1, STRIPE_SECRET_KEY: "sk_test_synthetic", STRIPE_WEBHOOK_SECRET: WHSEC, SITE_ORIGIN: "https://www.archymedes.xyz",
          MANAGED_PAYMENTS: "1", MAIL_FROM: "Archymedes <licences@archymedes.xyz>" };
  deps = { fetch: stripe.fetch, now: () => NOW_MS };
  stripe.subscriptions.set("sub_s", { id: "sub_s", items: { data: [{ current_period_end: YEAR_END }] }, metadata: { app: "argus" } });
});

const call = (path: string, init?: RequestInit) => handle(new Request(`https://pay.archymedes.xyz${path}`, init), env, deps);
const post = (path: string, body: unknown) => call(path, { method: "POST", body: JSON.stringify(body), headers: { "Content-Type": "application/json" } });

async function signed(event: unknown, secret = WHSEC, t = NOW) {
  const raw = JSON.stringify(event);
  return call("/stripe/webhook", { method: "POST", body: raw, headers: { "Stripe-Signature": `t=${t},v1=${await hmacHex(secret, `${t}.${raw}`)}` } });
}

const serverSession = (over: any = {}) => ({
  id: "cs_test_server1", object: "checkout.session", status: "complete", payment_status: "paid", mode: "subscription",
  created: NOW - 60, livemode: false, customer: "cus_1", payment_intent: null, subscription: "sub_s",
  customer_details: { email: "alice@example.com" }, metadata: { app: "argus", offer: "argus-server", ref: "hn" }, ...over,
});
const desktopSession = (over: any = {}) => ({
  id: "cs_test_desk1", object: "checkout.session", status: "complete", payment_status: "paid", mode: "subscription",
  created: NOW - 60, livemode: false, customer: "cus_2", payment_intent: null, subscription: "sub_1",
  customer_details: { email: "bob@example.com" }, metadata: { app: "argus", offer: "argus-desktop" }, ...over,
});
const event = (id: string, type: string, object: any) => ({ id, type, data: { object } });
const licences = () => store.db.query("SELECT * FROM licences").all() as any[];

describe("GET /buy", () => {
  test("creates a Managed Payments subscription session with metadata and none of the forbidden params", async () => {
    const res = await call("/buy/argus-server?ref=hn_launch&utm_source=hacker<news>&utm_campaign=" + "x".repeat(150) + "&lang=ja");
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("https://checkout.stripe.com/c/pay/cs_test_new");
    const [c] = stripe.stripeCalls("/v1/checkout/sessions");
    expect(c.headers["Stripe-Version"]).toBe(STRIPE_VERSION);
    expect(STRIPE_VERSION).toBe("2026-10-28.endive");
    const f = new URLSearchParams(c.body);
    expect(f.get("managed_payments[enabled]")).toBe("true");
    expect(f.get("mode")).toBe("subscription");
    expect(f.get("line_items[0][price]")).toBe("price_for_argus_server_usd_5000_year");
    expect(f.get("line_items[0][quantity]")).toBe("1");
    expect(f.get("client_reference_id")).toBe("hn_launch");
    for (const prefix of ["metadata", "subscription_data[metadata]"]) {
      expect(f.get(`${prefix}[app]`)).toBe("argus");
      expect(f.get(`${prefix}[offer]`)).toBe("argus-server");
      expect(f.get(`${prefix}[ref]`)).toBe("hn_launch");
      expect(f.get(`${prefix}[utm_source]`)).toBe("hackernews");
      expect(f.get(`${prefix}[utm_campaign]`)!.length).toBe(100);
    }
    expect([...f.keys()].some((k) => k.startsWith("payment_intent_data"))).toBe(false);
    expect(f.get("success_url")).toBe("https://www.archymedes.xyz/ja/solutions/argus/thanks/?session_id={CHECKOUT_SESSION_ID}");
    expect(f.get("cancel_url")).toBe("https://www.archymedes.xyz/ja/solutions/argus/#pricing");
    for (const k of f.keys()) for (const bad of FORBIDDEN) expect(k.startsWith(bad)).toBe(false);
  });

  test("desktop is on sale ($79/year); bad ref and lang are dropped", async () => {
    await call("/buy/argus-desktop?ref=bad%20ref!&lang=fr");
    const f = new URLSearchParams(stripe.stripeCalls("/v1/checkout/sessions")[0].body);
    expect(f.get("mode")).toBe("subscription");
    expect(f.get("line_items[0][price]")).toBe("price_for_argus_desktop_usd_7900_year");
    expect(f.get("subscription_data[metadata][offer]")).toBe("argus-desktop");
    expect(f.get("subscription_data[metadata][app]")).toBe("argus");
    expect(f.get("client_reference_id")).toBeNull();
    expect(f.get("metadata[ref]")).toBeNull();
    expect(f.get("success_url")).toStartWith("https://www.archymedes.xyz/en/");
    for (const k of f.keys()) for (const bad of FORBIDDEN) expect(k.startsWith(bad)).toBe(false);
  });

  test("MANAGED_PAYMENTS=0 uses automatic_tax instead", async () => {
    env.MANAGED_PAYMENTS = "0";
    await call("/buy/argus-server");
    const f = new URLSearchParams(stripe.stripeCalls("/v1/checkout/sessions")[0].body);
    expect(f.get("automatic_tax[enabled]")).toBe("true");
    expect(f.get("managed_payments[enabled]")).toBeNull();
  });

  test("price lookups are cached", async () => {
    await call("/buy/argus-server"); await call("/buy/argus-server");
    expect(stripe.stripeCalls("/v1/prices").length).toBe(1);
  });

  test("retired offers (Server Review, Watch) and unknown offers are 404 and never reach Stripe", async () => {
    for (const id of ["argus-review", "argus-watch", "argus-nothing"]) expect((await call(`/buy/${id}`)).status).toBe(404);
    expect(stripe.calls.length).toBe(0);
  });

  test("a Stripe failure shows a plain page without Stripe's message", async () => {
    stripe.failCheckout = true;
    const res = await call("/buy/argus-server");
    expect(res.status).toBe(502);
    const html = await res.text();
    expect(html).toContain("#pricing");
    expect(html).not.toContain("jane@example.com");
  });
});

describe("webhook signature", () => {
  test("rejects a wrong secret, a stale timestamp, a missing header; accepts any matching v1", async () => {
    const ev = event("evt_1", "checkout.session.completed", serverSession());
    expect((await signed(ev, "whsec_other")).status).toBe(400);
    expect((await signed(ev, WHSEC, NOW - 301)).status).toBe(400);
    expect((await call("/stripe/webhook", { method: "POST", body: JSON.stringify(ev) })).status).toBe(400);
    expect(licences().length).toBe(0);
    const raw = JSON.stringify(ev);
    const good = await hmacHex(WHSEC, `${NOW}.${raw}`);
    expect(await verifyStripeSignature(WHSEC, raw, `t=${NOW},v1=${"0".repeat(64)},v1=${good}`, NOW_MS)).toBe(true);
    expect(await verifyStripeSignature(WHSEC, raw + " ", `t=${NOW},v1=${good}`, NOW_MS)).toBe(false);
    expect((await signed(ev)).status).toBe(200);
    expect(licences().length).toBe(1);
  });
});

describe("webhook events", () => {
  test("events of another app (Orion) are ignored and not recorded", async () => {
    const orion = serverSession({ id: "cs_test_orion", metadata: { app: "orion", offer: "argus-server" } });
    const res = await signed(event("evt_o1", "checkout.session.completed", orion));
    expect(res.status).toBe(200);
    expect((await res.json() as any).ignored).toBe(true);
    await signed(event("evt_o2", "customer.subscription.deleted", { id: "sub_orion", object: "subscription", metadata: { app: "orion" } }));
    await signed(event("evt_o3", "charge.refunded", { id: "ch_o", payment_intent: "pi_orion", refunded: true, amount: 100, amount_refunded: 100 }));
    await signed(event("evt_o4", "invoice.paid", { id: "in_o", parent: { subscription_details: { subscription: "sub_orion", metadata: { app: "orion" } } } }));
    expect(licences().length).toBe(0);
    expect(store.db.query("SELECT count(*) AS n FROM processed_events").get()).toEqual({ n: 0 });
    expect(stripe.calls.length).toBe(0);
  });

  test("an Orion-tagged event never touches an Argus licence, even on a matching subscription id", async () => {
    await signed(event("evt_1", "checkout.session.completed", serverSession()));
    const r1 = await signed(event("evt_o1", "customer.subscription.deleted", { id: "sub_s", object: "subscription", metadata: { app: "orion" } }));
    expect((await r1.json() as any).ignored).toBe(true);
    const r2 = await signed(event("evt_o2", "invoice.paid", { id: "in_o", parent: { subscription_details: { subscription: "sub_s", metadata: { app: "orion" } } },
      lines: { data: [{ period: { end: YEAR_END + 999 * 86400 } }] } }));
    expect((await r2.json() as any).ignored).toBe(true);
    const [row] = licences();
    expect(row.status).toBe("active");
    expect(row.expires_at).toBe(YEAR_END + 3 * 86400);
  });

  test("key issuance is idempotent across the webhook, its retries and the thanks page", async () => {
    env.RESEND_API_KEY = "re_synthetic";
    const s = serverSession();
    stripe.sessions.set(s.id, s);
    await signed(event("evt_1", "checkout.session.completed", s));
    await signed(event("evt_1", "checkout.session.completed", s));                  // retry, same event
    await signed(event("evt_2", "checkout.session.async_payment_succeeded", s));   // another event, same session
    const res = await call(`/api/session/${s.id}`, { headers: { Origin: "https://www.archymedes.xyz" } });
    const body = await res.json() as any;
    const rows = licences();
    expect(rows.length).toBe(1);
    expect(rows[0].key).toMatch(/^ARGUS-SERVER-[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/);
    expect(rows[0].expires_at).toBe(YEAR_END + 3 * 86400);
    expect(rows[0].subscription).toBe("sub_s");
    expect(body).toEqual({ status: "paid", offer: "argus-server", key: rows[0].key, email_hint: "a***@example.com" });
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("https://www.archymedes.xyz");
    expect(stripe.calls.filter((c) => c.url.startsWith("https://api.resend.com")).length).toBe(1);
    expect(JSON.stringify(rows[0])).not.toContain("alice@example.com");
  });

  test("an unpaid async session waits; the thanks page says pending", async () => {
    const s = serverSession({ payment_status: "unpaid" });
    stripe.sessions.set(s.id, s);
    await signed(event("evt_1", "checkout.session.completed", s));
    expect(licences().length).toBe(0);
    expect(await (await call(`/api/session/${s.id}`)).json() as any).toEqual({ status: "pending" });
    stripe.sessions.set("cs_test_gone", serverSession({ id: "cs_test_gone", status: "expired", payment_status: "unpaid" }));
    expect(await (await call("/api/session/cs_test_gone")).json() as any).toEqual({ status: "unpaid" });
    expect((await call("/api/session/not_a_session")).status).toBe(400);
    stripe.sessions.set("cs_test_orion", serverSession({ id: "cs_test_orion", metadata: { app: "orion" } }));
    expect((await call("/api/session/cs_test_orion")).status).toBe(404);
  });

  test("invoice.paid extends a subscription key to period end + 3 days; deletion revokes", async () => {
    const s = desktopSession();
    const firstEnd = NOW + 30 * 86400;
    stripe.subscriptions.set("sub_1", { id: "sub_1", items: { data: [{ current_period_end: firstEnd }] }, metadata: { app: "argus" } });
    await signed(event("evt_1", "checkout.session.completed", s));
    let [row] = licences();
    expect(row.key).toStartWith("ARGUS-DESKTOP-");
    expect(row.expires_at).toBe(firstEnd + 3 * 86400);
    const nextEnd = firstEnd + 31 * 86400;
    await signed(event("evt_2", "invoice.paid", { id: "in_2", object: "invoice",
      parent: { subscription_details: { subscription: "sub_1", metadata: { app: "argus" } } },
      lines: { data: [{ period: { start: firstEnd, end: nextEnd } }] } }));
    [row] = licences();
    expect(row.expires_at).toBe(nextEnd + 3 * 86400);
    await signed(event("evt_3", "customer.subscription.deleted", { id: "sub_1", object: "subscription", metadata: { app: "argus" } }));
    expect(licences()[0].status).toBe("revoked");
  });

  test("a refund with no one-time licence is a no-op; cancelling the subscription revokes the key", async () => {
    // Both plans are subscriptions: a refund under Managed Payments comes with the subscription's
    // cancellation, and customer.subscription.deleted is what revokes the key.
    await signed(event("evt_1", "checkout.session.completed", serverSession()));
    await signed(event("evt_2", "charge.refunded", { id: "ch_1", payment_intent: "pi_x", refunded: true, amount: 5000, amount_refunded: 5000, metadata: { app: "argus" } }));
    expect(licences()[0].status).toBe("active");
    await signed(event("evt_3", "customer.subscription.deleted", { id: "sub_s", object: "subscription", metadata: { app: "argus" } }));
    expect(licences()[0].status).toBe("revoked");
    const key = licences()[0].key;
    const act = await (await post("/licence/activate", { key, label: "srv1" })).json() as any;
    const v = await (await post("/licence/validate", { key, activation_id: act.id })).json() as any;
    expect(v.status).toBe("revoked");
  });
});

describe("licence service", () => {
  async function installServer() {
    await signed(event("evt_1", "checkout.session.completed", serverSession()));
    return licences()[0].key as string;
  }

  test("one activation per key: same label returns the same id, another label is 409", async () => {
    const key = await installServer();
    const a = await post("/licence/activate", { key: key.toLowerCase(), label: "srv1" });
    expect(a.status).toBe(200);
    const first = await a.json() as any;
    expect(first.key).toBe(key);
    expect(first.label).toBe("srv1");
    const again = await (await post("/licence/activate", { key, label: "srv1" })).json() as any;
    expect(again.id).toBe(first.id);
    const other = await post("/licence/activate", { key, label: "srv2" });
    expect(other.status).toBe(409);
    expect((await other.json() as any).error).toContain("already activated on another machine");
  });

  test("validate grants, then expires; unknown keys and wrong activations are 404", async () => {
    const key = await installServer();
    const { id } = await (await post("/licence/activate", { key, label: "srv1" })).json() as any;
    const v = await (await post("/licence/validate", { key, activation_id: id })).json() as any;
    expect(v).toEqual({ status: "granted", expires_at: new Date((YEAR_END + 3 * 86400) * 1000).toISOString(),
                        product: "Argus Server", benefit: "argus-server" });
    expect((await post("/licence/validate", { key, activation_id: "nope" })).status).toBe(404);
    const unknown = "ARGUS-SERVER-1C285B2D-6CE6-4BC7-B8BE-ADB6A7E304DA";
    expect((await post("/licence/validate", { key: unknown, activation_id: id })).status).toBe(404);
    expect((await post("/licence/activate", { key: unknown, label: "x" })).status).toBe(404);
    expect((await post("/licence/validate", { key: "hello" })).status).toBe(400);
    // Retired kinds are not Argus keys any more.
    expect((await post("/licence/validate", { key: "ARGUS-REVIEW-1C285B2D-6CE6-4BC7-B8BE-ADB6A7E304DA" })).status).toBe(400);
    deps.now = () => NOW_MS + 369 * 86400 * 1000;
    expect((await (await post("/licence/validate", { key, activation_id: id })).json() as any).status).toBe("expired");
  });

  test("portal opens a Stripe billing portal session for the key's customer", async () => {
    const key = await installServer();
    const res = await post("/licence/portal", { key });
    expect(await res.json() as any).toEqual({ url: "https://billing.stripe.com/p/session/test_1" });
    const f = new URLSearchParams(stripe.stripeCalls("/v1/billing_portal/sessions")[0].body);
    expect(f.get("customer")).toBe("cus_1");
    expect(f.get("return_url")).toBe("https://www.archymedes.xyz/en/solutions/argus/");
  });

  test("health reports configuration without secrets", async () => {
    const body = await (await call("/health")).json() as any;
    expect(body).toEqual({ ok: true, stripe: true, managed_payments: true });
    expect(JSON.stringify(body)).not.toContain("sk_test");
  });

  test("emails are masked", () => {
    expect(maskEmail("alice@example.com")).toBe("a***@example.com");
    expect(maskEmail("nope")).toBeNull();
  });
});
