import { describe, expect, test } from "bun:test";
import { brand, brandDeep } from "./brand";

describe("brand", () => {
  test("product prose reads ARGUS-1", () => {
    expect(brand("JARVIS is up")).toBe("ARGUS-1 is up");
    expect(brand("JARVIS's view of JARVIS")).toBe("ARGUS-1's view of ARGUS-1");
  });
  test("real Windows objects, commands, paths and variables keep their spelling", () => {
    for (const s of ["JARVIS input hook", "JARVIS independent health monitor",
                     "JARVIS connectivity guard", "JARVIS native sensor",
                     "JARVIS JarvisSensorDefender collector", "jarvis.service", "jarvis fix apply 3",
                     "C:\\ProgramData\\Jarvis\\Broker", "JARVIS_DESKTOP_PORT"])
      expect(brand(s)).toBe(s);
  });
  test("deep: values only, keys and non-strings untouched", () => {
    const v = { JARVIS: "JARVIS score", n: 3, ok: true, list: ["JARVIS", null], id: "a1" };
    expect(brandDeep(v)).toEqual({ JARVIS: "ARGUS-1 score", n: 3, ok: true, list: ["ARGUS-1", null], id: "a1" });
  });
  test("idempotent: branding twice changes nothing (no ARGUS-1-1)", () => {
    for (const s of ["JARVIS is up", "ARGUS-1 is up", "JARVIS input hook", "x JARVIS-1 y"])
      expect(brand(brand(s))).toBe(brand(s));
    expect(brand("ARGUS-1 is up")).toBe("ARGUS-1 is up");
  });
  test("null and undefined are empty, never 'null'", () => {
    expect(brand(null)).toBe("");
    expect(brand(undefined)).toBe("");
  });
});
