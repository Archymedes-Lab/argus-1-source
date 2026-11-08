// The web dashboard and the app buy the same way: through the hosted licence claim flow at
// pay.archymedes.xyz, at the prices in prices.ts. No seller payment key or local checkout route.
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { ROUTES } from "./api";
import { PAY_ORIGIN, validLicencePage } from "./licence";

const src = (rel: string) => readFileSync(new URL(rel, import.meta.url), "utf8");
const CLAIM = "clm_0123456789ABCDEFGHJKMNPQRSTVWXYZ";

test("in a browser, licence state and purchases go to the daemon's licence routes", () => {
  expect(ROUTES.licence_state({})).toEqual({ method: "GET", path: "/api/licence" });
  expect(ROUTES.licence_action({ action: "upgrade", plan: "desktop-monthly" }))
    .toEqual({ method: "POST", path: "/api/licence/upgrade", body: { key: "", plan: "desktop-monthly" } });
  expect(ROUTES.licence_action({ action: "poll" }).path).toBe("/api/licence/poll");
  // a crafted action stays inside /api/licence/
  expect(ROUTES.licence_action({ action: "../billing/checkout" }).path).toBe("/api/licence/..%2Fbilling%2Fcheckout");
});

test("no browser route reaches a local Stripe checkout", () => {
  for (const [cmd, route] of Object.entries(ROUTES)) {
    const r = route({ action: "upgrade", job: "x", page: "x", decision: "approve" });
    expect(`${cmd} ${r.path}`).not.toMatch(/billing|stripe|checkout/i);
  }
  const api = src("./api.ts");
  expect(api).not.toMatch(/billing|checkout\.stripe\.com|session_id/i);
});

test("only Archymedes licence pages open, the same list as the app", () => {
  for (const ok of ["manage", "recover", "buy/argus-server", "buy/argus-desktop", "buy/argus-desktop-monthly",
                    `buy/argus-desktop?claim=${CLAIM}`, `buy/argus-desktop-monthly?claim=${CLAIM}`, `buy/argus-server?claim=${CLAIM}`]) {
    expect(validLicencePage(`${PAY_ORIGIN}/${ok}`)).toBe(true);
  }
  for (const bad of ["https://checkout.stripe.com/c/pay/cs_live_abc", "http://pay.archymedes.xyz/manage",
                     "https://pay.archymedes.xyz.evil/manage", "https://pay.archymedes.xyz/buy/argus-server?claim=clm_short",
                     `https://pay.archymedes.xyz/buy/argus-server?claim=${CLAIM}&x=1`, "https://pay.archymedes.xyz/",
                     `https://pay.archymedes.xyz/buy/argus-watch?claim=${CLAIM}`, "javascript:alert(1)", ""]) {
    expect(validLicencePage(bad)).toBe(false);
  }
  // The Rust allow-list says the same.
  const rust = src("../../../src/api.rs");
  expect(rust).toContain('const BASE: &str = "https://pay.archymedes.xyz/";');
  expect(rust).not.toMatch(/checkout\.stripe\.com|\/api\/billing/);
});

test("the Pricing view buys through the claim flow at the price-book prices", () => {
  const view = src("../views/Pricing.svelte");
  expect(view).toContain('api.licenceAction("upgrade"');
  expect(view).toContain("api.openLicencePage(");
  expect(view).toContain('from "../lib/prices"');
  expect(view).not.toMatch(/\$\d/);            // no amount written outside prices.ts
  expect(view).not.toMatch(/billing(Status|Checkout|Confirm)/);
});
