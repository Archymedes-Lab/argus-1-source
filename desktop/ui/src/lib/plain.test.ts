import { expect, test } from "bun:test";
import { headline, plainFinding } from "./plain";

test("headline never says fine when something is critical, and admits partial coverage", () => {
  expect(headline(90, 0, 0, 0).tone).toBe("ok");
  expect(headline(90, 0, 0, 3).partial).toContain("incomplete");
  expect(headline(90, 0, 0, 0).partial).toBeUndefined();
  // Each part is a whole key, so every language translates it (a joined string never matched).
  expect(headline(10, 2, 0, 3).body.startsWith(" ")).toBe(false);
  expect(headline(10, 2, 5, 0).vars.n).toBe(2);
  expect(headline(10, 2, 5, 0).tone).toBe("bad");
  expect(headline(50, 0, 4, 0).tone).toBe("warn");
  expect(headline(undefined, 0, 0, 0).tone).toBe("unknown");
});

test("plain wording uses the dashboard guide, and falls back without inventing a verdict", () => {
  const known = plainFinding({ severity: "high", title: "x", job: "j", category: "persistence" });
  expect(known.means.length).toBeGreaterThan(10);
  const other = plainFinding({ severity: "critical", title: "x", job: "j", category: "nope" });
  expect(other.why).toContain("seriously harm");
  expect(other.means).not.toMatch(/malware|compromised/i);
});
