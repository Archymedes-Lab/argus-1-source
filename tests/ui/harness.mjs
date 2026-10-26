// Shared harness: evaluate a page's inline scripts with browser globals
// stubbed, then expose named functions for UI unit tests.
//
// Top-level side effects (tick/refresh/setInterval) run against stubs: fetch
// never settles, timers are dropped, and every DOM node is an absorbing
// proxy. Tests then exercise the pure view functions for real.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

function makeEl() {
  const el = { dataset: {}, style: {}, children: [] };
  return new Proxy(el, {
    get(t, p) {
      if (p in t) return t[p];
      return (...args) => makeEl();
    },
    set(t, p, v) { t[p] = v; return true; },
  });
}

export function loadPage(relPath, exportNames) {
  const html = readFileSync(join(ROOT, relPath), "utf8");
  const scripts = [...html.matchAll(/<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/g)]
    .map((m) => m[1]).filter((s) => s.trim());
  globalThis.document = {
    getElementById: () => makeEl(),
    addEventListener: () => {},
    createElement: () => makeEl(),
    querySelector: () => makeEl(),
    querySelectorAll: () => [],
    documentElement: makeEl(),
  };
  globalThis.window = globalThis;
  globalThis.localStorage = { getItem: () => null, setItem: () => {} };
  globalThis.fetch = () => new Promise(() => {});
  globalThis.setInterval = () => 0;
  globalThis.clearInterval = () => {};
  globalThis.setTimeout = () => 0;
  globalThis.clearTimeout = () => {};
  const names = exportNames.join(",");
  // Indirect eval keeps "use strict" scripts scoped; re-export explicitly.
  (0, eval)(scripts.join("\n;\n") + `\n;globalThis.__page = {${names}};`);
  return { html, page: globalThis.__page };
}
