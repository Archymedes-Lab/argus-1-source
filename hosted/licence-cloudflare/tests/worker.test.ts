import { beforeEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { clearPriceCache, handle, maskEmail, stripeMode, type Deps, type Env } from "../src/index";
import { hmacHex, STRIPE_VERSION, verifyStripeSignature } from "../src/stripe";
import { b64url, decodeJws, signedMessage, unb64url } from "../src/cert";
import { ALPHABET, checkChar, deriveKey, formatKey, parseKey } from "../src/keys";

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
const PEPPER = "pepper-synthetic-0123456789abcdef0123456789";
const signing = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
const SIGNING_SECRET = `test-k1.${b64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", signing.privateKey) as ArrayBuffer))}`;
beforeEach(() => {
  clearPriceCache();
  stripe = new FakeStripe();
  store = fakeD1();
  env = { DB: store.d1, STRIPE_SECRET_KEY: "sk_test_synthetic", STRIPE_WEBHOOK_SECRET: WHSEC, SITE_ORIGIN: "https://www.archymedes.xyz",
          MANAGED_PAYMENTS: "1", MAIL_FROM: "Archymedes <licences@archymedes.xyz>", PAY_ORIGIN: "https://pay.archymedes.xyz",
          KEY_PEPPER: PEPPER, LICENCE_SIGNING_KEY: SIGNING_SECRET, RESEND_API_KEY: "re_synthetic" };
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
const licences = () => store.db.query("SELECT * FROM licences_v2").all() as any[];

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
    expect(f.get("line_items[0][price]")).toBe("price_for_argus_server_fleet_usd_year_v1");
    expect(f.get("line_items[0][quantity]")).toBe("1");
    expect(f.get("line_items[0][adjustable_quantity][enabled]")).toBe("true");
    expect(f.get("line_items[0][adjustable_quantity][minimum]")).toBe("1");
    expect(f.get("line_items[0][adjustable_quantity][maximum]")).toBe("1000");
    expect(f.get("allow_promotion_codes")).toBe("true");
    expect(f.get("client_reference_id")).toBe("hn_launch");
    for (const prefix of ["metadata", "subscription_data[metadata]"]) {
      expect(f.get(`${prefix}[app]`)).toBe("argus");
      expect(f.get(`${prefix}[offer]`)).toBe("argus-server");
      expect(f.get(`${prefix}[ref]`)).toBe("hn_launch");
      expect(f.get(`${prefix}[utm_source]`)).toBe("hackernews");
      expect(f.get(`${prefix}[utm_campaign]`)!.length).toBe(100);
    }
    expect([...f.keys()].some((k) => k.startsWith("payment_intent_data"))).toBe(false);
    expect(f.get("success_url")).toBe("https://pay.archymedes.xyz/thanks?session_id={CHECKOUT_SESSION_ID}&lang=ja");
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
    expect(f.get("success_url")).toEndWith("&lang=en");
    for (const k of f.keys()) for (const bad of FORBIDDEN) expect(k.startsWith(bad)).toBe(false);
  });

  test("fleet: ?servers=N opens checkout at N, clamped to 1..1000; desktop teams 1..100 with ?computers=N", async () => {
    for (const [q, want] of [["25", "25"], ["0", "1"], ["5000", "1000"], ["abc", "1"]]) {
      stripe.calls = [];
      await call(`/buy/argus-server?servers=${q}`);
      expect(new URLSearchParams(stripe.stripeCalls("/v1/checkout/sessions")[0].body).get("line_items[0][quantity]")).toBe(want);
    }
    for (const [path, want] of [["/buy/argus-desktop?computers=30", "30"], ["/buy/argus-desktop-monthly?computers=500", "100"], ["/buy/argus-desktop", "1"]]) {
      stripe.calls = [];
      await call(path);
      const f = new URLSearchParams(stripe.stripeCalls("/v1/checkout/sessions")[0].body);
      expect(f.get("line_items[0][quantity]")).toBe(want);
      expect(f.get("line_items[0][adjustable_quantity][maximum]")).toBe("100");
      expect(f.get("allow_promotion_codes")).toBe("true");
    }
  });

  test("desktop monthly is on sale ($15/month)", async () => {
    const res = await call("/buy/argus-desktop-monthly");
    expect(res.status).toBe(303);
    const f = new URLSearchParams(stripe.stripeCalls("/v1/checkout/sessions")[0].body);
    expect(f.get("line_items[0][price]")).toBe("price_for_argus_desktop_usd_1500_month");
    expect(f.get("subscription_data[metadata][offer]")).toBe("argus-desktop-monthly");
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

const mails = () => stripe.calls.filter((c) => c.url.startsWith("https://api.resend.com")).map((c) => JSON.parse(c.body));
const ORIGIN = { Origin: "https://pay.archymedes.xyz" };
const form = (path: string, fields: Record<string, string>, headers: Record<string, string> = {}) =>
  call(path, { method: "POST", body: new URLSearchParams(fields).toString(),
               headers: { "Content-Type": "application/x-www-form-urlencoded", ...ORIGIN, ...headers } });

/** A simulated Argus install: its own device key and machine fingerprint. */
class Device {
  keys!: CryptoKeyPair; dpk = ""; dev: string; label: string;
  constructor(label: string, dev?: string) { this.label = label; this.dev = dev ?? ""; }
  async init() {
    if (!this.dev) this.dev = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(this.label)))]
      .map((b) => b.toString(16).padStart(2, "0")).join("");
    this.keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    this.dpk = b64url(new Uint8Array(await crypto.subtle.exportKey("raw", this.keys.publicKey) as ArrayBuffer));
    return this;
  }
  async signed(action: string, subject: string, over: Record<string, unknown> = {}) {
    const nonce = b64url(crypto.getRandomValues(new Uint8Array(18)));
    const ts = Math.floor(deps.now() / 1000);
    const sig = b64url(await crypto.subtle.sign("Ed25519", this.keys.privateKey, new TextEncoder().encode(signedMessage(action, subject, nonce, ts))));
    return { nonce, ts, sig, ...over };
  }
  activate(key: string) { return post("/licence/activate", { key, dev: this.dev, dpk: this.dpk, label: this.label }); }
  async renew(act: string, over: Record<string, unknown> = {}) { return post("/licence/renew", { act, ...(await this.signed("renew", act)), ...over }); }
  async release(act: string) { return post("/licence/release", { act, ...(await this.signed("release", act)) }); }
}
const device = (label: string, dev?: string) => new Device(label, dev).init();

async function verifyCert(jws: string) {
  const [h, p, s] = jws.split(".");
  const pub = await crypto.subtle.exportKey("raw", signing.publicKey);
  const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify("Ed25519", key, unb64url(s)!, new TextEncoder().encode(`${h}.${p}`));
}

async function buyServer(over: any = {}) {
  const s = serverSession(over);
  stripe.sessions.set(s.id, s);
  await signed(event(`evt_${s.id}`, "checkout.session.completed", s));
  return { session: s, key: await deriveKey(PEPPER, s.id, 0, "SERVER") };
}

describe("licence keys", () => {
  test("format: ARGUS-SRV/DSK, five groups of five Crockford symbols, last one a Luhn mod 32 check", async () => {
    const key = await deriveKey(PEPPER, "cs_test_x", 0, "SERVER");
    expect(key).toMatch(/^ARGUS-SRV-([0-9A-HJKMNP-TV-Z]{5}-){4}[0-9A-HJKMNP-TV-Z]{5}$/);
    expect(await deriveKey(PEPPER, "cs_test_x", 0, "SERVER")).toBe(key);          // deterministic
    expect(await deriveKey(PEPPER, "cs_test_x", 1, "SERVER")).not.toBe(key);      // a re-issue is a new key
    expect((await deriveKey(PEPPER, "cs_test_x", 0, "DESKTOP")).startsWith("ARGUS-DSK-")).toBe(true);
  });

  test("accepted case- and space-insensitively, without dashes or prefix; O, I and L read as 0 and 1", async () => {
    const key = formatKey("SERVER", "0123456789ABCDEFGHJKMNPQ");
    const parsed = parseKey(key);
    expect(parsed).toEqual({ ok: true, key, kind: "SERVER" });
    expect(parseKey(` ${key.toLowerCase().replace(/-/g, " ")} `)).toEqual(parsed);
    expect(parseKey(key.replace("ARGUS-", ""))).toEqual(parsed);
    expect(parseKey(key.replace(/0/g, "O").replace(/1/g, "l"))).toEqual(parsed);
  });

  test("every single mistyped character is caught by the check character", () => {
    const key = formatKey("DESKTOP", "Z9Y8X7W6V5T4S3R2Q1P0NMKJ");
    const body = key.slice(10).replace(/-/g, "");
    for (let i = 0; i < body.length; i++) for (const c of ALPHABET) {
      if (c === body[i]) continue;
      const typo = body.slice(0, i) + c + body.slice(i + 1);
      expect(parseKey(`ARGUS-DSK-${typo}`)).toEqual({ ok: false, reason: "check" });
    }
    expect(parseKey("ARGUS-SERVER-1C285B2D-6CE6-4BC7-B8BE-ADB6A7E304DA")).toEqual({ ok: false, reason: "format" });
    expect(parseKey(key.replace("DSK", "SRV"))).toEqual({ ok: false, reason: "check" });
    expect(parseKey("hello")).toEqual({ ok: false, reason: "format" });
  });

  test("shared vectors with the Python client (jarvis/licensing/keys.py)", () => {
    const v = JSON.parse(readFileSync(new URL("../../../tests/fixtures/licence/vectors.json", import.meta.url), "utf8"));
    for (const [body, check] of v.check) expect(checkChar(body)).toBe(check);
    for (const [input, canon] of v.parse) expect(parseKey(input)).toMatchObject(canon ? { ok: true, key: canon } : { ok: false });
  });
});

describe("issuing", () => {
  test("one licence per session across webhook retries and the thank-you page; D1 holds no key and no email", async () => {
    const { session, key } = await buyServer();
    await signed(event("evt_retry", "checkout.session.async_payment_succeeded", session));
    const res = await call(`/api/session/${session.id}`, { headers: { Origin: "https://www.archymedes.xyz" } });
    const body = await res.json() as any;
    const rows = licences();
    expect(rows.length).toBe(1);
    expect(body).toEqual({ status: "paid", offer: "argus-server", key, key_hint: `…${key.slice(-4)}`, email_hint: "a***@example.com" });
    expect(rows[0]).toMatchObject({ plan: "server", seats: 1, lic_exp: YEAR_END + 3 * 86400, key_last4: key.slice(-4), subscription: "sub_s" });
    const dump = JSON.stringify(store.db.query("SELECT * FROM licences_v2").all()) + JSON.stringify(store.db.query("SELECT * FROM audit").all());
    expect(dump).not.toContain(key);
    expect(dump).not.toContain(key.replace(/-/g, ""));
    expect(dump).not.toContain("alice@example.com");
    expect(rows[0].email_hash).toMatch(/^[0-9a-f]{64}$/);
    const sent = mails();
    expect(sent.length).toBe(1);
    expect(sent[0].to).toEqual(["alice@example.com"]);
    expect(sent[0].text).toContain(key);
    expect(sent[0].text).toContain("https://pay.archymedes.xyz/manage");
  });

  test("a failed key email is released for Stripe's retry", async () => {
    stripe.resendOk = false;
    const s = serverSession();
    const res = await signed(event("evt_1", "checkout.session.completed", s));
    expect(res.status).toBe(500);
    expect(licences()[0].emailed_at).toBeNull();
    stripe.resendOk = true;
    expect((await signed(event("evt_1", "checkout.session.completed", s))).status).toBe(200);
    expect(licences()[0].emailed_at).not.toBeNull();
  });

  test("fleet: seats = subscription quantity at purchase, then follow customer.subscription.updated", async () => {
    stripe.subscriptions.set("sub_s", { id: "sub_s", items: { data: [{ quantity: 12, current_period_end: YEAR_END }] }, metadata: { app: "argus" } });
    expect((await signed(event("evt_f1", "checkout.session.completed", serverSession()))).status).toBe(200);
    expect(licences()[0].seats).toBe(12);
    const updated = (q: number) => ({ id: "sub_s", object: "subscription", metadata: { app: "argus", offer: "argus-server" },
                                      items: { data: [{ quantity: q, current_period_end: YEAR_END }] } });
    await signed(event("evt_f2", "customer.subscription.updated", updated(40)));
    expect(licences()[0].seats).toBe(40);
    await signed(event("evt_f3", "customer.subscription.updated", updated(40)));
    await signed(event("evt_f4", "customer.subscription.updated", updated(5)));
    expect(licences()[0].seats).toBe(5);
    const audits = store.db.query("SELECT action FROM audit WHERE action LIKE 'seats%' ORDER BY rowid").all() as any[];
    expect(audits.map((a) => a.action)).toEqual(["seats 12->40", "seats 40->5"]);
  });

  test("a desktop team licence: 30 computers at purchase, 9 after the team shrinks", async () => {
    stripe.subscriptions.set("sub_1", { id: "sub_1", items: { data: [{ quantity: 30, current_period_end: YEAR_END }] }, metadata: { app: "argus" } });
    await signed(event("evt_d1", "checkout.session.completed", desktopSession()));
    expect(licences()[0].seats).toBe(30);
    await signed(event("evt_d2", "customer.subscription.updated",
      { id: "sub_1", metadata: { app: "argus", offer: "argus-desktop" }, items: { data: [{ quantity: 9 }] } }));
    expect(licences()[0].seats).toBe(9);
  });

  test("events of another app (Orion) are ignored and recorded nowhere", async () => {
    const orion = serverSession({ id: "cs_test_orion", metadata: { app: "orion", offer: "argus-server" } });
    expect((await (await signed(event("evt_o1", "checkout.session.completed", orion))).json() as any).ignored).toBe(true);
    await signed(event("evt_o2", "customer.subscription.deleted", { id: "sub_orion", metadata: { app: "orion" } }));
    await signed(event("evt_o4", "invoice.paid", { id: "in_o", parent: { subscription_details: { subscription: "sub_orion", metadata: { app: "orion" } } } }));
    expect(licences().length).toBe(0);
    expect(store.db.query("SELECT count(*) AS n FROM processed_events").get()).toEqual({ n: 0 });
  });

  test("webhook signature: wrong secret, stale timestamp, missing header refused", async () => {
    const ev = event("evt_1", "checkout.session.completed", serverSession());
    expect((await signed(ev, "whsec_other")).status).toBe(400);
    expect((await signed(ev, WHSEC, NOW - 301)).status).toBe(400);
    expect((await call("/stripe/webhook", { method: "POST", body: JSON.stringify(ev) })).status).toBe(400);
    const raw = JSON.stringify(ev);
    expect(await verifyStripeSignature(WHSEC, raw, `t=${NOW},v1=${"0".repeat(64)},v1=${await hmacHex(WHSEC, `${NOW}.${raw}`)}`, NOW_MS)).toBe(true);
    expect(licences().length).toBe(0);
  });
});

describe("activation and certificates", () => {
  test("activate returns an EdDSA JWS with exactly the architecture's claims", async () => {
    const { key } = await buyServer();
    const d = await device("srv1");
    const res = await d.activate(key.toLowerCase().replace(/-/g, " "));
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(await verifyCert(body.certificate)).toBe(true);
    const { header, claims } = decodeJws(body.certificate)!;
    expect(header).toEqual({ alg: "EdDSA", kid: "test-k1", typ: "argus-licence+jwt" });
    expect(Object.keys(claims).sort()).toEqual(["act", "aud", "dev", "dpk", "exp", "iat", "iss", "kid", "lic_exp", "plan", "renew_after", "seats", "sub"]);
    expect(claims).toMatchObject({ iss: "pay.archymedes.xyz", aud: "argus", kid: "test-k1", plan: "server", seats: 1, dev: d.dev, dpk: d.dpk,
                                   iat: NOW, exp: NOW + 30 * 86400, lic_exp: YEAR_END + 3 * 86400, renew_after: NOW + 23 * 86400 });
    expect(claims.sub).toBe(licences()[0].id);
    expect(body.certificate).not.toContain(key);
  });

  test("the lease never runs past the licence's own end", async () => {
    stripe.subscriptions.set("sub_s", { id: "sub_s", items: { data: [{ current_period_end: NOW + 5 * 86400 }] } });
    const { key } = await buyServer();
    const { claims } = decodeJws((await (await (await device("a")).activate(key)).json() as any).certificate)!;
    expect(claims.exp).toBe(NOW + 8 * 86400);
    expect(claims.renew_after).toBe(NOW + 1 * 86400);
  });

  test("same device again: same activation, fresh certificate; another machine: 409 seat_taken with the manage URL", async () => {
    const { key } = await buyServer();
    const a = await device("srv1");
    const first = await (await a.activate(key)).json() as any;
    deps.now = () => NOW_MS + 60_000;
    const again = await (await a.activate(key)).json() as any;
    expect(again.activation_id).toBe(first.activation_id);
    expect(decodeJws(again.certificate)!.claims.iat).toBe(NOW + 60);
    const b = await device("srv2");
    const res = await b.activate(key);
    expect(res.status).toBe(409);
    const body = await res.json() as any;
    expect(body.code).toBe("seat_taken");
    expect(body.manage_url).toBe("https://pay.archymedes.xyz/manage");
    expect(body.machines).toEqual([{ label: "srv1", since: new Date(NOW_MS).toISOString() }]);
    expect(body.error).toContain("argus licence deactivate");
  });

  test("Argus reinstalled on the same machine (new device key, same fingerprint) takes its own seat back", async () => {
    const { key } = await buyServer();
    const a = await device("srv1");
    await a.activate(key);
    const reinstalled = await device("srv1", a.dev);
    expect((await reinstalled.activate(key)).status).toBe(200);
    expect(store.db.query("SELECT COUNT(*) AS n FROM releases").get()).toEqual({ n: 0 });
    expect((await (await device("srv2")).activate(key)).status).toBe(409);
  });

  test("typos, wrong formats and unknown keys get distinct answers", async () => {
    const { key } = await buyServer();
    const d = await device("x");
    const typo = key.slice(0, -2) + (key.at(-2) === "0" ? "1" : "0") + key.at(-1);
    expect((await (await d.activate(typo)).json() as any).code).toBe("bad_check");
    expect((await (await d.activate("ARGUS-SERVER-1C285B2D-6CE6-4BC7-B8BE-ADB6A7E304DA")).json() as any).code).toBe("bad_key");
    const other = await deriveKey(PEPPER, "cs_test_never", 0, "SERVER");
    const res = await d.activate(other);
    expect(res.status).toBe(404);
    expect((await res.json() as any).code).toBe("unknown_key");
    expect((await post("/licence/activate", { key, dev: "nothex", dpk: d.dpk })).status).toBe(400);
  });

  test("a revoked or expired licence cannot be activated", async () => {
    const { key } = await buyServer();
    await signed(event("evt_del", "customer.subscription.deleted", { id: "sub_s", metadata: { app: "argus" } }));
    const res = await (await device("a")).activate(key);
    expect(res.status).toBe(403);
    expect((await res.json() as any).code).toBe("revoked");
  });
});

describe("renewal and release (device-signed)", () => {
  async function activated() {
    const { key } = await buyServer();
    const d = await device("srv1");
    const { activation_id } = await (await d.activate(key)).json() as any;
    return { key, d, act: activation_id as string };
  }

  test("renew returns a new lease; invoice.paid extends lic_exp first", async () => {
    const { d, act } = await activated();
    const nextEnd = YEAR_END + 365 * 86400;
    await signed(event("evt_inv", "invoice.paid", { id: "in_2", parent: { subscription_details: { subscription: "sub_s", metadata: { app: "argus" } } },
      lines: { data: [{ period: { start: YEAR_END, end: nextEnd } }] } }));
    // An older invoice replayed later never shortens it.
    await signed(event("evt_old", "invoice.paid", { id: "in_1", parent: { subscription_details: { subscription: "sub_s", metadata: { app: "argus" } } },
      lines: { data: [{ period: { end: NOW } }] } }));
    deps.now = () => NOW_MS + 25 * 86400_000;
    const res = await d.renew(act);
    expect(res.status).toBe(200);
    const { claims } = decodeJws((await res.json() as any).certificate)!;
    expect(claims.lic_exp).toBe(nextEnd + 3 * 86400);
    expect(claims.exp).toBe(NOW + 55 * 86400);
  });

  test("refused: another device's signature, a replayed nonce, a stale timestamp, a wrong action", async () => {
    const { d, act } = await activated();
    const thief = await device("thief");
    expect(await (await post("/licence/renew", { act, ...(await thief.signed("renew", act)) })).json() as any).toMatchObject({ code: "bad_signature" });
    const once = await d.signed("renew", act);
    expect((await post("/licence/renew", { act, ...once })).status).toBe(200);
    expect(await (await post("/licence/renew", { act, ...once })).json() as any).toMatchObject({ code: "replay" });
    const stale = await d.signed("renew", act);
    deps.now = () => NOW_MS + 301_000;
    expect(await (await post("/licence/renew", { act, ...stale })).json() as any).toMatchObject({ code: "clock" });
    expect(await (await post("/licence/renew", { act, ...(await d.signed("release", act)) })).json() as any).toMatchObject({ code: "bad_signature" });
  });

  test("a revoked licence fails at the next renewal", async () => {
    const { d, act } = await activated();
    await signed(event("evt_del", "customer.subscription.deleted", { id: "sub_s", metadata: { app: "argus" } }));
    const res = await d.renew(act);
    expect(res.status).toBe(403);
    expect((await res.json() as any).code).toBe("revoked");
    expect(licences()[0].revoked_at).toBe(NOW);
  });

  test("release frees the seat; the released machine can no longer renew; 3 releases per 30 days", async () => {
    const { key, d, act } = await activated();
    expect(await (await d.release(act)).json() as any).toEqual({ released: true, already: false });
    expect(await (await d.renew(act)).json() as any).toMatchObject({ code: "not_activated" });
    expect(await (await d.release(act)).json() as any).toEqual({ released: true, already: true });
    let current = d;
    for (let i = 0; i < 2; i++) {
      const next = await device(`m${i}`);
      const r = await (await next.activate(key)).json() as any;
      expect(r.activation_id).toBeTruthy();
      expect(await (await next.release(r.activation_id)).json() as any).toMatchObject({ released: true });
      current = next;
    }
    const last = await device("last");
    const { activation_id } = await (await last.activate(key)).json() as any;
    const res = await last.release(activation_id);
    expect(res.status).toBe(429);
    const body = await res.json() as any;
    expect(body.code).toBe("release_limit");
    expect(body.error).toContain("support@archymedes.xyz");
    deps.now = () => NOW_MS + 31 * 86400_000;
    expect((await last.release(activation_id)).status).toBe(200);
    expect(current).toBeTruthy();
  });
});

describe("buy from inside Argus (claim)", () => {
  test("claim → checkout carries metadata[claim] → webhook seats that device → only that device can collect", async () => {
    const d = await device("laptop");
    const c = await (await post("/licence/claim", { dev: d.dev, dpk: d.dpk, label: "laptop" })).json() as any;
    expect(c.claim_id).toMatch(/^clm_[0-9A-Z]{32}$/);
    expect(c.user_code).toMatch(/^[0-9A-Z]{4}-[0-9A-Z]{4}$/);
    expect(c.buy.desktop).toBe(`https://pay.archymedes.xyz/buy/argus-desktop?claim=${c.claim_id}`);
    const poll = async (who: Device) => post("/licence/claim/poll", { claim_id: c.claim_id, ...(await who.signed("poll", c.claim_id)) });
    expect((await poll(d)).status).toBe(202);

    await call(`/buy/argus-desktop?claim=${c.claim_id}`);
    const f = new URLSearchParams(stripe.stripeCalls("/v1/checkout/sessions")[0].body);
    expect(f.get("metadata[claim]")).toBe(c.claim_id);
    expect(f.get("subscription_data[metadata][claim]")).toBeNull();

    const s = desktopSession({ metadata: { app: "argus", offer: "argus-desktop", claim: c.claim_id } });
    stripe.subscriptions.set("sub_1", { id: "sub_1", items: { data: [{ current_period_end: YEAR_END }] } });
    await signed(event("evt_1", "checkout.session.completed", s));
    expect(await (await poll(await device("thief"))).json()).toMatchObject({ code: "bad_signature" });
    const res = await poll(d);
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.status).toBe("active");
    expect(body.key).toBe(await deriveKey(PEPPER, s.id, 0, "DESKTOP"));
    expect(decodeJws(body.certificate)!.claims).toMatchObject({ plan: "desktop", dpk: d.dpk, dev: d.dev });
    expect(store.db.query("SELECT COUNT(*) AS n FROM claims WHERE id_hash = ?").get(c.claim_id)).toEqual({ n: 0 }); // stored hashed
  });

  test("an unbound claim expires after 30 minutes", async () => {
    const d = await device("x");
    const c = await (await post("/licence/claim", { dev: d.dev, dpk: d.dpk })).json() as any;
    deps.now = () => NOW_MS + 31 * 60_000;
    const res = await post("/licence/claim/poll", { claim_id: c.claim_id, ...(await d.signed("poll", c.claim_id)) });
    expect(res.status).toBe(410);
  });
});

describe("server-gated content", () => {
  test("a live activation with a device signature gets a signed pack; nothing else does", async () => {
    const { key } = await buyServer();
    const d = await device("srv1");
    const { activation_id: act } = await (await d.activate(key)).json() as any;
    const res = await post("/content/sample", { act, ...(await d.signed("content", `sample:${act}`)) });
    expect(res.status).toBe(200);
    const { pack } = await res.json() as any;
    expect(await verifyCert(pack)).toBe(true);
    expect(decodeJws(pack)).toMatchObject({ header: { typ: "argus-pack+jwt" }, claims: { pack: "sample", act, version: 1 } });
    expect((await post("/content/sample", { act, ...(await d.signed("content", `other:${act}`)) })).status).toBe(401);
    expect((await post("/content/nope", { act })).status).toBe(404);
    await signed(event("evt_del", "customer.subscription.deleted", { id: "sub_s", metadata: { app: "argus" } }));
    expect((await post("/content/sample", { act, ...(await d.signed("content", `sample:${act}`)) })).status).toBe(403);
  });
});

describe("thank-you page", () => {
  test("shows the key with Copy and Open in Argus on the day of purchase; afterwards only points to email", async () => {
    const s = serverSession();
    stripe.sessions.set(s.id, s);
    const res = await call(`/thanks?session_id=${s.id}`);
    const html = await res.text();
    const key = await deriveKey(PEPPER, s.id, 0, "SERVER");
    expect(html).toContain(key);
    expect(html).toContain("Copy key");
    expect(html).toContain(`argus://activate?key=${encodeURIComponent(key)}`);
    expect(html).toContain(`argus licence activate ${key}`);
    expect(html).not.toContain("alice@example.com");
    expect(res.headers.get("Content-Security-Policy")).toContain("script-src 'nonce-");
    deps.now = () => NOW_MS + 25 * 3600_000;
    const later = await (await call(`/thanks?session_id=${s.id}`)).text();
    expect(later).not.toContain(key);
    expect(later).toContain("/recover");
  });

  test("pending payments refresh; other apps' sessions are not shown", async () => {
    stripe.sessions.set("cs_test_p", serverSession({ id: "cs_test_p", payment_status: "unpaid" }));
    expect(await (await call("/thanks?session_id=cs_test_p")).text()).toContain('http-equiv="refresh"');
    stripe.sessions.set("cs_test_o", serverSession({ id: "cs_test_o", metadata: { app: "orion" } }));
    expect((await call("/thanks?session_id=cs_test_o")).status).toBe(404);
  });
});

describe("manage and recover", () => {
  const linkIn = (text: string) => text.match(/https:\/\/pay\.archymedes\.xyz\/manage\/open\?t=([A-Za-z0-9_-]+)/)?.[1];
  async function signIn(): Promise<{ cookie: string; csrf: string }> {
    await form("/manage/link", { email: "Alice@Example.com" });
    const t = linkIn(mails().at(-1).text)!;
    const open = await form("/manage/open", { t });
    expect(open.status).toBe(303);
    const cookie = open.headers.get("Set-Cookie")!.split(";")[0];
    const home = await (await call("/manage/home", { headers: { Cookie: cookie } })).text();
    return { cookie, csrf: home.match(/name="csrf" value="([^"]+)"/)![1] };
  }

  test("/manage and /recover answer the same whether or not the email bought anything", async () => {
    await buyServer();
    const before = mails().length;
    const a = await (await form("/manage/link", { email: "alice@example.com" })).text();
    const b = await (await form("/manage/link", { email: "nobody@example.com" })).text();
    expect(a.replace(/nonce-[^']+|nonce="[^"]+"/g, "")).toBe(b.replace(/nonce-[^']+|nonce="[^"]+"/g, ""));
    expect(mails().length).toBe(before + 1);
    const r1 = await (await form("/recover", { email: "alice@example.com" })).text();
    const r2 = await (await form("/recover", { email: "nobody@example.com" })).text();
    expect(r1.replace(/nonce-[^']+|nonce="[^"]+"/g, "")).toBe(r2.replace(/nonce-[^']+|nonce="[^"]+"/g, ""));
    expect(mails().at(-1).text).toContain(await deriveKey(PEPPER, "cs_test_server1", 0, "SERVER"));
  });

  test("per-email throttle: 3 mails an hour, same answer after", async () => {
    await buyServer();
    const before = mails().length;
    for (let i = 0; i < 5; i++) expect((await form("/recover", { email: "alice@example.com" })).status).toBe(200);
    expect(mails().length).toBe(before + 3);
  });

  test("magic links: single use, 15 minutes, opening needs a click (POST), and the token never reaches D1", async () => {
    await buyServer();
    await form("/manage/link", { email: "alice@example.com" });
    const t = linkIn(mails().at(-1).text)!;
    expect(JSON.stringify(store.db.query("SELECT * FROM magic_links").all())).not.toContain(t);
    const getPage = await (await call(`/manage/open?t=${t}`)).text();
    expect(getPage).toContain('method="post"');
    expect(store.db.query("SELECT used_at FROM magic_links").get()).toEqual({ used_at: null });
    expect((await form("/manage/open", { t })).status).toBe(303);
    expect((await form("/manage/open", { t })).status).toBe(410);
    await form("/manage/link", { email: "alice@example.com" });
    const t2 = linkIn(mails().at(-1).text)!;
    deps.now = () => NOW_MS + 16 * 60_000;
    expect((await form("/manage/open", { t: t2 })).status).toBe(410);
  });

  test("the manage page lists machines, releases one, re-sends the key and opens billing; CSRF and Origin are checked", async () => {
    const { key } = await buyServer();
    const d = await device("web-01");
    const { activation_id } = await (await d.activate(key)).json() as any;
    const { cookie, csrf } = await signIn();
    const home = await (await call("/manage/home", { headers: { Cookie: cookie } })).text();
    expect(home).toContain("web-01");
    expect(home).toContain(`…${key.slice(-4)}`);
    expect(home).not.toContain(key);
    expect(cookie.startsWith("__Host-argus_manage=")).toBe(true);
    expect((await form("/manage/release", { csrf: "wrong", activation_id }, { Cookie: cookie })).status).toBe(403);
    expect((await form("/manage/release", { csrf, activation_id }, { Cookie: cookie, Origin: "https://evil.example" })).status).toBe(403);
    expect((await form("/manage/release", { csrf, activation_id }, { Cookie: cookie, Origin: "null", "Sec-Fetch-Site": "cross-site" })).status).toBe(403);
    const rel = await form("/manage/release", { csrf, activation_id }, { Cookie: cookie });
    expect(rel.headers.get("Location")).toBe("/manage/home?m=released");
    expect((await (await device("web-02")).activate(key)).status).toBe(200);
    const lic = licences()[0];
    const n = mails().length;
    await form("/manage/resend", { csrf, licence_id: lic.id }, { Cookie: cookie });
    expect(mails().length).toBe(n + 1);
    expect(mails().at(-1).to).toEqual(["Alice@Example.com"]);
    expect(mails().at(-1).text).toContain(key);
    const portal = await form("/manage/portal", { csrf, licence_id: lic.id }, { Cookie: cookie });
    expect(portal.headers.get("Location")).toBe("https://billing.stripe.com/p/session/test_1");
    expect(new URLSearchParams(stripe.stripeCalls("/v1/billing_portal/sessions")[0].body).get("customer")).toBe("cus_1");
    expect(JSON.stringify(store.db.query("SELECT * FROM manage_sessions").all())).not.toContain("alice");
  });

  test("argus licence login: a claim is approved on /link after signing in", async () => {
    const { key } = await buyServer();
    const d = await device("headless");
    const c = await (await post("/licence/claim", { dev: d.dev, dpk: d.dpk, label: "headless" })).json() as any;
    expect((await call("/link")).headers.get("Location")).toBe("/manage?next=link");
    const { cookie, csrf } = await signIn();
    const lic = licences()[0];
    const res = await form("/link", { csrf, code: c.user_code.toLowerCase(), licence_id: lic.id }, { Cookie: cookie });
    expect(await res.text()).toContain("is activated");
    const poll = await post("/licence/claim/poll", { claim_id: c.claim_id, ...(await d.signed("poll", c.claim_id)) });
    expect((await poll.json() as any).key).toBe(key);
  });
});

describe("misc", () => {
  test("browsers that send Origin: null are accepted only with Sec-Fetch-Site: same-origin", async () => {
    await buyServer();
    const n = mails().length;
    expect((await form("/manage/link", { email: "alice@example.com" }, { Origin: "null", "Sec-Fetch-Site": "same-origin" })).status).toBe(200);
    expect(mails().length).toBe(n + 1);
    expect((await form("/recover", { email: "alice@example.com" }, { Origin: "null" })).status).toBe(403);
  });

  test("the fake-upstream redirect only works for a worker on loopback", async () => {
    const { upstream } = await import("../src/index");
    const seen: string[] = [];
    const orig = globalThis.fetch;
    globalThis.fetch = (async (u: string) => { seen.push(String(u)); return new Response("{}"); }) as any;
    try {
      await upstream({ ...env, PAY_ORIGIN: "https://pay.archymedes.xyz", DEV_FAKE_UPSTREAM: "http://127.0.0.1:9" } as any)("https://api.stripe.com/v1/prices");
      await upstream({ ...env, PAY_ORIGIN: "http://127.0.0.1:9477", DEV_FAKE_UPSTREAM: "http://127.0.0.1:9" } as any)("https://api.stripe.com/v1/prices");
    } finally { globalThis.fetch = orig; }
    expect(seen).toEqual(["https://api.stripe.com/v1/prices", "http://127.0.0.1:9/v1/prices"]);
  });

  test("portal by key; health reports configuration without secrets; emails are masked", async () => {
    const { key } = await buyServer();
    expect(await (await post("/licence/portal", { key })).json() as any).toEqual({ url: "https://billing.stripe.com/p/session/test_1" });
    const body = await (await call("/health")).json() as any;
    expect(body).toEqual({ ok: true, stripe: true, stripe_mode: "test", managed_payments: true, signing: true, pepper: true });
    expect(JSON.stringify(body)).not.toContain("sk_test");
    // The mode is read from the key's prefix only; nothing of the key is echoed.
    expect(stripeMode({ STRIPE_SECRET_KEY: "rk_live_" + "s".repeat(24) })).toBe("live");
    expect(stripeMode({ STRIPE_SECRET_KEY: "sk_test_x" })).toBe("test");
    for (const k of ["", "pk_live_x", "live", "sk_livex"]) expect(stripeMode({ STRIPE_SECRET_KEY: k })).toBe("none");
    expect(maskEmail("alice@example.com")).toBe("a***@example.com");
  });

  test("the licence API sends no CORS headers and refuses oversized or non-object bodies", async () => {
    const res = await post("/licence/activate", [1, 2]);
    expect(res.status).toBe(400);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect((await post("/licence/activate", { key: "x".repeat(5000) })).status).toBe(400);
  });
});
