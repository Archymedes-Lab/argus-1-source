import { describe, expect, test } from "bun:test";
import {
  ago, collectorSummary, distinct, every, filterFindings, groupQuestions, isReminder, problemCounts,
  jobHealth, matches, scoreTone, sevRank, severityCounts, type Finding,
} from "./model";

const F = (severity: string, title: string, extra: Partial<Finding> = {}): Finding =>
  ({ severity, title, job: "scan", host: "win", ...extra });

describe("findings", () => {
  const list = [F("low", "inbound firewall allow rule", { detail: "Firefox", job: "control" }),
                F("critical", "privileged container", { host: "wsl", job: "containers" }),
                F("high", "task ran at boot", { job: "boot" })];

  test("severity order, critical first, unknown last", () => {
    expect(sevRank("critical")).toBe(0);
    expect(sevRank("ok")).toBe(9);
    expect(filterFindings(list, {}).map((f) => f.severity)).toEqual(["critical", "high", "low"]);
  });

  test("search matches every word across title, detail, collector and host", () => {
    expect(filterFindings(list, { query: "firewall firefox" }).length).toBe(1);
    expect(filterFindings(list, { query: "containers wsl" })[0].title).toBe("privileged container");
    expect(filterFindings(list, { query: "  " }).length).toBe(3);
    expect(matches(list[0], "FIREWALL")).toBe(true);
    expect(filterFindings(list, { query: "nothing-like-this" })).toEqual([]);
  });

  test("filters combine", () => {
    expect(filterFindings(list, { severity: "high", host: "win" }).length).toBe(1);
    expect(filterFindings(list, { severity: "high", host: "wsl" }).length).toBe(0);
    expect(filterFindings(list, { job: "control" })[0].severity).toBe("low");
  });

  test("counts and distinct rows", () => {
    expect(severityCounts(list)).toEqual({ critical: 1, high: 1, medium: 0, low: 1 });
    const dup = [F("critical", "a"), F("critical", "a"), F("critical", "b")];
    expect(distinct(dup, 5).map((d) => [d.title, d.count])).toEqual([["a", 2], ["b", 1]]);
    expect(distinct(dup, 1).length).toBe(1);
  });
});

test("the same question asked three times is one group", () => {
  const g = groupQuestions([{ id: "1", prompt: "p" }, { id: "2", prompt: "p" }, { id: "3", prompt: "q" }]);
  expect(g.map((x) => [x.prompt, x.ids.length])).toEqual([["p", 2], ["q", 1]]);
});

test("collector health", () => {
  expect(jobHealth({ name: "a", label: "A", running: true, error: "x" })).toBe("running");
  expect(jobHealth({ name: "a", label: "A", error: "boom", ts: 1 })).toBe("error");
  expect(jobHealth({ name: "a", label: "A" })).toBe("never");
  expect(jobHealth({ name: "a", label: "A", ts: 1, stale: true })).toBe("stale");
  expect(jobHealth({ name: "a", label: "A", ts: 1 })).toBe("ok");
  expect(collectorSummary([{ name: "a", label: "A", ts: 1 }, { name: "b", label: "B" }, { name: "c", label: "C", error: "e", ts: 1 }]))
    .toEqual({ total: 3, ok: 1, stale: 1, error: 1 });
});

test("time and tone formatting", () => {
  expect(ago(null)).toBe("never");
  expect(ago(100, 130)).toBe("30s ago");
  expect(ago(0 + 1, 7201)).toBe("2h ago");
  expect(every(45)).toBe("45s");
  expect(every(900)).toBe("15 min");
  expect(every(86400)).toBe("1 d");
  expect(scoreTone(90)).toBe("green");
  expect(scoreTone(60)).toBe("amber");
  expect(scoreTone(10)).toBe("red");
  expect(scoreTone(null)).toBe("gray");
});

describe("reminders are not new problems", () => {
  // The reminder engine (job "ledger") re-raises an unresolved or returning
  // finding at the original's severity so its emails escalate; on screen it is
  // the same problem again, not another one (2026-10-30: 39 critical, 14 real).
  const list = [
    F("critical", "driver loaded from a writable path", { job: "drivers" }),
    F("critical", "unresolved for 6d: driver loaded from a writable path", { job: "ledger" }),
    F("critical", "a resolved alert has come back: scheduled task", { job: "ledger" }),
    F("high", "old browser", { job: "patches" }),
  ];

  test("problem counts leave reminders out; reminders are counted on their own", () => {
    expect(problemCounts(list)).toEqual({ critical: 1, high: 1, medium: 0, low: 0 });
    expect(list.filter(isReminder).length).toBe(2);
    expect(severityCounts(list).critical).toBe(3);   // the full list is unchanged
  });
});

import { noteText } from "./model";
test("a JSON-wrapped model note shows its text, never braces", () => {
  expect(noteText('{"security": "This may indicate a scheduled task."}')).toBe("This may indicate a scheduled task.");
  expect(noteText("  plain note ")).toBe("plain note");
  expect(noteText("{not json")).toBe("{not json");
  expect(noteText('{"n": 3}')).toBe('{"n": 3}');
  expect(noteText(undefined)).toBe("");
});
