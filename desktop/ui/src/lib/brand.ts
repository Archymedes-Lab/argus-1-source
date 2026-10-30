// The product is ARGUS-1. Daemon text can still say JARVIS (finding titles keep
// their identity for acknowledgements and history), so string values are
// re-branded once, where replies enter the interface. Object keys, ids, job
// names, lowercase commands (jarvis ..., jarvis.service), capitalised paths
// (C:\ProgramData\Jarvis) and real Windows object names are left as they are.
// The same rule runs in the web pages (jarvis/web/static, between brand:begin
// and brand:end); tests/test_ui_brand.py keeps the two in step.
export const BRAND = "ARGUS-1";
const BRAND_KEEP = /^ (input hook|independent health monitor|connectivity guard|native sensor|Jarvis)/;

export const brand = (s: unknown): string =>
  // Idempotent: never brand a name already followed by -1 (see the web copy).
  String(s ?? "").replace(/\bJARVIS\b(?!-1)/g, (m, i: number, all: string) =>
    BRAND_KEEP.test(all.slice(i + m.length)) ? m : BRAND);

/** Every string value in a reply, branded; structure and keys unchanged. */
export function brandDeep<T>(value: T): T {
  if (typeof value === "string") return brand(value) as T;
  if (Array.isArray(value)) return value.map(brandDeep) as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = brandDeep(v);
    return out as T;
  }
  return value;
}
