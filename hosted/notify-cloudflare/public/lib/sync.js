// Fetch each paired server's sealed inbox, keep only what verifies against that
// server's pinned key and decrypts with this phone's key, acknowledge, return the new ones.
import { openEnvelope, signRequest, unb64u } from "./protocol.js";
import { messages, servers } from "./store.js";

const enc = new TextEncoder();
const now = () => Date.now() / 1000;

export async function signedFetch(server, method, path, body) {
  const bytes = body === undefined ? new Uint8Array() : enc.encode(JSON.stringify(body));
  const headers = await signRequest(server.keys.sigPriv, server.keys.sigPub, method, path, bytes, now());
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : bytes, cache: "no-store" });
  if (!res.ok) {
    let error = `HTTP ${res.status}`;
    try { error = (await res.json()).error || error; } catch {}
    throw new Error(error);
  }
  return res.json();
}

export async function syncAll() {
  const fresh = [];
  let dropped = 0;
  for (const server of await servers.all()) {
    let envelopes;
    try {
      envelopes = await signedFetch(server, "GET", `/v1/device/${server.dev}/inbox?mb=${server.mb}`);
    } catch (err) {
      server.lastError = String(err.message || err);
      await servers.put(server);
      continue;
    }
    const ids = [];
    for (const env of envelopes) {
      ids.push(env.id);
      if (env.mb !== server.mb || env.dev !== server.dev || (await messages.get(env.id))) continue;
      try {
        const p = await openEnvelope(env, server.keys.encPriv, unb64u(server.s_sig));
        const m = { id: env.id, mb: server.mb, label: server.label, kind: p.kind, title: String(p.title || ""),
          body: String(p.body || ""), severity: String(p.severity || "info"), host: String(p.host || ""),
          at: Number(p.at) || env.sent, read: false };
        await messages.put(m);
        fresh.push(m);
      } catch {
        dropped += 1;          // not signed by this server, or not for this phone: never shown
      }
    }
    if (ids.length) {
      try { await signedFetch(server, "POST", `/v1/device/${server.dev}/ack?mb=${server.mb}`, { ids }); } catch {}
    }
    server.lastSync = Math.floor(now());
    server.lastError = "";
    await servers.put(server);
  }
  await messages.prune();
  return { fresh, dropped };
}
