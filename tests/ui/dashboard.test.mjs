// UI tests: the new Continuity and Activity cards render honest state.
//
// These run the page's own functions (not copies) against stubbed DOM:
// a violated invariant must read VIOLATED, attacker-controlled text must
// be escaped, and the static contract (ids + render wiring) must hold.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./harness.mjs";

const { html, page } = loadPage("jarvis/web/static/dashboard.html",
  ["continuityHTML", "activityHTML", "esc"]);

describe("continuity card", () => {
  it("reports absence instead of a false green", () => {
    assert.match(page.continuityHTML(null), /not reporting/);
  });

  it("marks violated invariants VIOLATED with their reason", () => {
    const out = page.continuityHTML({
      invariants: { ok: false,
        freshness: { ok: false, reason: "stale with no recovery" },
        privacy: { ok: true, reason: "local" } },
      governor: { pressured: false, reason: "nominal" },
      perception: null,
    });
    assert.match(out, /VIOLATED/);
    assert.match(out, /stale with no recovery/);
    assert.match(out, /holding/);
  });

  it("shows governor deferral and perception counts", () => {
    const out = page.continuityHTML({
      invariants: { ok: true },
      governor: { pressured: true, reason: "CPU 88%" },
      perception: { verified: 41, unreconciled: 2, unknown: 7,
                    windows_processes: 50 },
    });
    assert.match(out, /deferring noncritical/);
    assert.match(out, /41 verified/);
  });

  it("escapes attacker-controlled text", () => {
    const out = page.continuityHTML({
      invariants: { ok: false,
        privacy: { ok: false, reason: '<img src=x onerror="1">' } },
      governor: {}, perception: null,
    });
    assert.doesNotMatch(out, /<img/);
    assert.match(out, /&lt;img/);
  });
});

describe("activity card", () => {
  it("stays quiet with no stories instead of inventing them", () => {
    assert.match(page.activityHTML([]), /no correlated activity/);
  });

  it("renders one story per chain with severity and provenance", () => {
    const out = page.activityHTML([{
      headline: "2 related observations across network, sysmon: evil",
      worst_severity: "high", count: 2, jobs: ["network", "sysmon"],
      host: "win", causal: false, last: 1700000000, member_overflow: 0,
    }]);
    assert.match(out, /evil/);
    assert.match(out, /causality unverified/);
    assert.match(out, /pill high/);
  });

  it("marks explicit causal edges and overflow honestly", () => {
    const out = page.activityHTML([{
      headline: "chain", worst_severity: "critical", count: 9,
      jobs: ["sysmon"], host: "win", causal: true, last: null,
      member_overflow: 3,
    }]);
    assert.match(out, /causal edge/);
    assert.match(out, /\+3 more/);
  });
});

describe("static wiring contract", () => {
  for (const id of ["continuity", "contcnt", "activity", "actcnt",
                    "continuitycard", "activitycard"]) {
    it(`dashboard contains #${id}`, () => {
      assert.ok(html.includes(`id="${id}"`), `missing #${id}`);
    });
  }
  it("render() mounts both cards", () => {
    assert.ok(html.includes("renderContinuity(s)"));
    assert.ok(html.includes("renderActivity(s)"));
  });
});
