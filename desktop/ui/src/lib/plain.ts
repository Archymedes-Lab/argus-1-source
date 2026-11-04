// Plain-language wording for the Simple mode. The category guidance is the
// dashboard's own (lib/guide.json, generated from jarvis/web/static/dashboard.html),
// so both interfaces tell the same story. General background, never a verdict.
import guide from "./guide.json";
import type { Finding } from "./model";

const G = guide as Record<string, string[]>;
const SEVERITY_WHY: Record<string, string> = {
  critical: "If it is real, it can seriously harm this computer or your data.",
  high: "Worth looking at soon.",
  medium: "Worth a look, rarely urgent.",
  low: "For your information.",
};

export interface Plain { means: string; why: string; next: string }

export function plainFinding(f: Finding): Plain {
  const g = G[f.category ?? ""];
  if (g) return { means: g[0], why: g[1], next: g[2] };
  return {
    means: "ARGUS-INSTINCT noticed something it wants you to know about.",
    why: SEVERITY_WHY[f.severity] ?? "ARGUS-INSTINCT has not rated this.",
    next: "Open it and decide whether you expect this on your computer.",
  };
}

export interface Headline { tone: "ok" | "warn" | "bad" | "unknown"; title: string; body: string; vars: Record<string, number>; partial?: string }

export const PARTIAL = "Some of ARGUS-INSTINCT's checks are not reporting right now, so this picture may be incomplete.";

/** One calm sentence about the whole computer, from the numbers the daemon reports.
 *  `title` and `body` are English keys with {n} placeholders; the view translates them. */
export function headline(score: number | null | undefined, critical: number, high: number, notReporting: number): Headline {
  if (score === null || score === undefined) {
    return { tone: "unknown", title: "ARGUS-INSTINCT is still getting a look at your computer", body: "Check back in a minute.", vars: {} };
  }
  const partial = notReporting ? PARTIAL : undefined;
  if (critical) {
    return { tone: "bad", title: critical === 1 ? "1 thing needs your attention" : "{n} things need your attention",
      body: "Start with the most urgent one below. This is not proof that something is wrong, only that it is worth a look.", vars: { n: critical }, partial };
  }
  if (high) {
    return { tone: "warn", title: "Nothing urgent, but a few things are worth a look",
      body: high === 1 ? "1 item could use your attention when you have a minute." : "{n} items could use your attention when you have a minute.", vars: { n: high }, partial };
  }
  return { tone: "ok", title: "Your computer looks fine", body: "Nothing needs you right now.", vars: {}, partial };
}

/** A friendly opener for the time of day. */
export function greeting(now = new Date()): string {
  const h = now.getHours();
  return h < 5 ? "Still up?" : h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
}
