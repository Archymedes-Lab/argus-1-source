// brand:begin -- the same rule as jarvis/web/static/dashboard.html; tests/test_ui_brand.py keeps the copies equal.
// The product is ARGUS-1. Server text can still say JARVIS (finding titles keep their
// identity for acknowledgements and history), so it is re-branded at display time.
// Real Windows objects keep their spelling so they can be found in Task Scheduler
// and Services; lowercase commands (jarvis ..., jarvis.service) are never touched.
// Idempotent: a name already followed by -1 is left alone.
const BRAND = "ARGUS-1";
const BRAND_KEEP = /^ (input hook|independent health monitor|connectivity guard|native sensor|Jarvis)/;
export const brand = (s: unknown): string => String(s ?? "").replace(/\bJARVIS\b(?!-1)/g,
  (m, i, all) => (BRAND_KEEP.test(all.slice(i + m.length)) ? m : BRAND));
// brand:end
