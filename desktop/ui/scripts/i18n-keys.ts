// Lists every English string the interface asks tr() to translate.
// Used by the locale test and to produce a worklist for translators.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) { if (n !== "locales") walk(p, out); }
    else if (/\.(svelte|ts)$/.test(n) && !/\.test\.ts$/.test(n)) out.push(p);
  }
  return out;
}

export function collectKeys(root = "src"): string[] {
  const keys = new Set<string>();
  const re = /\btr\(\s*"((?:\\.|[^"\\])*)"/g;
  for (const f of walk(root)) {
    const text = readFileSync(f, "utf8");
    for (const m of text.matchAll(re)) keys.add(JSON.parse(`"${m[1]}"`));
  }
  // Strings that reach tr() through a variable.
  const extra = [
    "Automatic", "Light", "Dark", "15 minutes", "1 hour", "4 hours", "24 hours",
    "Critical", "High", "Medium", "Low", "Ok", "never",
    "Good morning", "Good afternoon", "Good evening", "Still up?",
    "ARGUS-INSTINCT is still getting a look at your computer", "Check back in a minute.",
    "1 thing needs your attention", "{n} things need your attention",
    "Start with the most urgent one below. This is not proof that something is wrong, only that it is worth a look.",
    "Nothing urgent, but a few things are worth a look",
    "1 item could use your attention when you have a minute.", "{n} items could use your attention when you have a minute.",
    "Your computer looks fine", "Nothing needs you right now.",
    "Some of ARGUS-INSTINCT's checks are not reporting right now, so this picture may be incomplete.",
  ];
  for (const k of extra) keys.add(k);
  return [...keys].sort();
}

if (import.meta.main) console.log(JSON.stringify(collectKeys(), null, 1));
