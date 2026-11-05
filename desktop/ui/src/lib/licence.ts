// Licence key checking in the interface: the same format and Luhn mod 32 check character as
// jarvis/licensing/keys.py and hosted/licence-cloudflare/src/keys.ts, so a typo is caught as it is
// typed, before anything is sent. The daemon checks again; this is feedback only.
export const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PLANS: Record<string, "server" | "desktop"> = { SRV: "server", DSK: "desktop" };

export function checkChar(s: string): string {
  let factor = 2, sum = 0;
  for (let i = s.length - 1; i >= 0; i--) {
    let add = factor * ALPHABET.indexOf(s[i]);
    factor = factor === 2 ? 1 : 2;
    sum += Math.floor(add / 32) + (add % 32);
  }
  return ALPHABET[(32 - (sum % 32)) % 32];
}

export type KeyCheck =
  | { state: "empty" }
  | { state: "typing"; message: string }
  | { state: "bad"; message: string }
  | { state: "ok"; key: string; plan: "server" | "desktop" };

/** Feedback for what is in the paste box. */
export function checkKey(input: string): KeyCheck {
  let text = input.trim();
  if (text.toLowerCase().startsWith("argus://")) {
    try { text = new URL(text).searchParams.get("key") || ""; } catch { text = ""; }
  }
  let s = text.toUpperCase().replace(/[\s\-_]/g, "");
  if (!s) return { state: "empty" };
  if (s.startsWith("ARGUS")) s = s.slice(5);
  const code = s.slice(0, 3);
  if (s.length >= 3 && !PLANS[code]) return { state: "bad", message: "An Argus key starts with ARGUS-SRV- or ARGUS-DSK-." };
  const body = s.slice(3).replace(/O/g, "0").replace(/[IL]/g, "1");
  const badChar = [...body].find((c) => !ALPHABET.includes(c));
  if (badChar) return { state: "bad", message: `“${badChar}” is not used in Argus keys. Check the key in your email.` };
  if (body.length < 25) return { state: "typing", message: `${25 - body.length} more characters` };
  if (body.length > 25) return { state: "bad", message: "This is longer than an Argus key. Paste just the key." };
  if (checkChar(code + body.slice(0, 24)) !== body[24])
    return { state: "bad", message: "One character is wrong (the check character does not match). Compare it with your email." };
  const groups = (body.match(/.{5}/g) || []).join("-");
  return { state: "ok", key: `ARGUS-${code}-${groups}`, plan: PLANS[code] };
}

export const PRODUCT = { server: "Argus Server", desktop: "Argus Desktop" } as const;
