// Argus on the phone: inbox, servers, pairing, settings. Alert text is untrusted data
// from a server: it is only ever placed with textContent, never parsed as HTML.
import { b64u, generateDevice, keyId, normalizeCode, sas, supported, unb64u, validCode } from "./lib/protocol.js";
import { messages, servers, settings } from "./lib/store.js";
import { CATEGORIES, signedFetch, syncAll } from "./lib/sync.js";

const view = document.getElementById("view");
const status = document.getElementById("status");

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return el;
}

const ago = (t) => {
  const s = Math.max(0, Date.now() / 1000 - t);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(t * 1000).toLocaleDateString();
};
const sevClass = (s) => `sev sev-${["critical", "high", "medium", "low", "ok"].includes(s) ? s : "info"}`;

function show(...nodes) {
  view.replaceChildren(...nodes);
  view.focus({ preventScroll: true });
  const tab = location.hash.startsWith("#/servers") || location.hash.startsWith("#/add") ? "servers"
    : location.hash.startsWith("#/settings") ? "settings" : "inbox";
  for (const a of document.querySelectorAll(".tabs a")) a.toggleAttribute("aria-current", a.dataset.tab === tab);
}

// --- inbox -----------------------------------------------------------------------
let inflight = null;

async function inbox() {
  // Opening the inbox checks for new alerts first: push only wakes the service
  // worker, and a phone without push still gets its alerts.
  await sync();
  const [list, paired] = [await messages.all(), await servers.all()];
  if (!paired.length) {
    return show(h("section", { class: "empty" },
      h("h1", {}, "No servers yet"),
      h("p", {}, "Pair a server running Argus to receive its alerts here, end-to-end encrypted."),
      h("a", { class: "button", href: "#/add" }, "Add a server")));
  }
  if (!list.length) {
    return show(h("section", { class: "empty" }, h("h1", {}, "All quiet"),
      h("p", {}, `${paired.length} server${paired.length > 1 ? "s" : ""} paired. New alerts appear here.`),
      h("button", { class: "button ghost", onclick: refresh }, "Check now")));
  }
  // Filter by category; the choice is kept in the hash so Back keeps it.
  const want = new URLSearchParams(location.hash.split("?")[1] || "").get("c");
  const present = Object.keys(CATEGORIES).filter((c) => list.some((m) => (m.category || "system") === c));
  const shown = want ? list.filter((m) => (m.category || "system") === want) : list;
  const chip = (c, text) => h("a", { class: `chip ${(c || "") === (want || "") ? "on" : ""}`,
    href: c ? `#/?c=${c}` : "#/", "aria-current": (c || "") === (want || "") ? "true" : false }, text);
  show(h("nav", { class: "chips", "aria-label": "Filter by kind" },
      chip("", `All ${list.length}`),
      present.map((c) => chip(c, `${CATEGORIES[c]} ${list.filter((m) => (m.category || "system") === c).length}`))),
    h("ul", { class: "list" }, shown.map((m) =>
    h("li", {}, h("a", { class: `row ${m.read ? "" : "unread"}`, href: `#/m/${m.id}` },
      h("span", { class: sevClass(m.severity) }, m.severity),
      h("span", { class: "row-main" }, h("span", { class: "row-title" }, m.title),
        h("span", { class: "row-meta" }, `${CATEGORIES[m.category] || CATEGORIES.system} · ${m.label || m.host} · ${ago(m.at)}`)))))));
}

async function message(id) {
  const m = await messages.get(id);
  if (!m) return show(h("p", { class: "pad" }, "This alert is no longer on this phone."), h("a", { class: "button ghost", href: "#/" }, "Back"));
  if (!m.read) { m.read = true; await messages.put(m); }
  show(h("article", { class: "detail" },
    h("a", { class: "back", href: "#/" }, "‹ Alerts"),
    h("span", { class: sevClass(m.severity) }, m.severity),
    h("span", { class: "kindtag" }, CATEGORIES[m.category] || CATEGORIES.system),
    h("h1", {}, m.title),
    h("p", { class: "row-meta" }, `${m.label || m.host} · ${new Date(m.at * 1000).toLocaleString()}`),
    h("pre", { class: "body" }, m.body),
    h("button", { class: "button ghost danger", onclick: async () => { await messages.remove(id); location.hash = "#/"; } }, "Delete from this phone")));
}

// --- servers -------------------------------------------------------------------------
async function serverList() {
  const list = await servers.all();
  const pending = await settings.get(PENDING, null);
  show(h("section", { class: "pad" },
    h("h1", {}, "Servers"),
    pending && Date.now() < pending.deadline ? h("p", { class: "card" }, `Pairing with ${pending.server.label} is in progress. `,
      h("a", { href: "#/pending" }, "Continue")) : null,
    list.length ? h("ul", { class: "list" }, list.map((s) => h("li", { class: "server" },
      h("div", {}, h("strong", {}, s.label), h("span", { class: "row-meta" },
        s.lastError ? `Problem: ${s.lastError}` : s.lastSync ? `Checked ${ago(s.lastSync)}` : `Paired ${ago(s.pairedAt)}`)),
      h("button", { class: "button ghost danger small", onclick: () => removeServer(s) }, "Remove"))))
      : h("p", {}, "No server is paired with this phone."),
    h("a", { class: "button", href: "#/add" }, "Add a server")));
}

async function removeServer(s) {
  if (!confirm(`Stop receiving alerts from ${s.label} on this phone?`)) return;
  try { await signedFetch(s, "DELETE", `/v1/mailbox/${s.mb}/devices/${s.dev}`); } catch {}
  await messages.removeServer(s.mb);
  await servers.remove(s.mb);
  serverList();
}

// --- pairing -------------------------------------------------------------------------
async function addServer() {
  if (!(await supported())) {
    return show(h("section", { class: "pad" }, h("h1", {}, "Update your browser"),
      h("p", {}, "This browser lacks the encryption Argus uses (X25519 and Ed25519). Use a current Safari, Chrome or Firefox.")));
  }
  const code = h("input", { id: "code", inputmode: "text", autocapitalize: "characters", autocomplete: "off",
    spellcheck: "false", maxlength: "11", placeholder: "XXXXX-XXXXX", "aria-describedby": "code-help", required: true });
  code.addEventListener("input", () => {
    const n = normalizeCode(code.value).slice(0, 10);
    code.value = n.length > 5 ? `${n.slice(0, 5)}-${n.slice(5)}` : n;
  });
  const name = h("input", { id: "name", maxlength: "40", value: defaultName() });
  const error = h("p", { class: "error", role: "alert" });
  const form = h("form", { class: "pad stack", onsubmit: async (e) => {
    e.preventDefault();
    error.textContent = "";
    const c = normalizeCode(code.value);
    if (!validCode(c)) { error.textContent = "The code has 10 letters and digits, as your server shows it."; return; }
    form.querySelector("button").disabled = true;
    try { await pair(c, name.value.trim() || "Phone"); }
    catch (err) { error.textContent = String(err.message || err); form.querySelector("button").disabled = false; }
  } },
    h("h1", {}, "Add a server"),
    h("p", { id: "code-help" }, "On the server, run ", h("code", {}, "argus notify pair"), " and type the code it shows."),
    h("label", { for: "code" }, "Pairing code"), code,
    h("label", { for: "name" }, "Name for this phone"), name,
    error,
    h("button", { class: "button", type: "submit" }, "Continue"));
  show(form);
  code.focus();
}

function defaultName() {
  const ua = navigator.userAgent;
  return /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android phone" : "Browser";
}

const PENDING = "pendingPairing";

async function pair(code, name) {
  const offerRes = await fetch(`/v1/pair/${code}`, { cache: "no-store" });
  if (!offerRes.ok) throw new Error("That code is unknown or has expired. Run the pairing again on the server.");
  const offer = await offerRes.json();
  const sSig = unb64u(offer.s_sig), sEnc = unb64u(offer.s_enc);
  // The mailbox id is the hash of the server's key: the relay cannot substitute another.
  if ((await keyId(sSig)) !== offer.mb || sEnc.length !== 32) throw new Error("The relay returned an offer that does not check out.");
  const keys = await generateDevice();
  const server = { mb: offer.mb, label: String(offer.label || "server").slice(0, 40), s_sig: offer.s_sig, s_enc: offer.s_enc,
    dev: keys.dev, keys, pairedAt: Math.floor(Date.now() / 1000), name };
  const push = await subscription().catch(() => null);
  // Keep the pairing (with this phone's keys) before claiming: a reload or a
  // switch to another app mid-pairing used to lose the keys, and the server
  // then "paired" a phone that could never read anything.
  const pending = { code, server, push, deadline: Date.now() + 10 * 60_000 };
  await settings.set(PENDING, pending);
  try {
    await signedFetch(server, "POST", `/v1/pair/${code}/claim`,
      { dev: keys.dev, d_sig: b64u(keys.sigPub), d_enc: b64u(keys.encPub), name, push });
  } catch (err) {
    await settings.set(PENDING, null);
    throw err;
  }
  return awaitConfirmation(pending);
}

async function awaitConfirmation(pending) {
  const { code, server, push, deadline } = pending;
  const digits = await sas(unb64u(server.s_sig), unb64u(server.s_enc), server.keys.sigPub, server.keys.encPub);
  const waiting = h("p", { class: "row-meta" }, "Waiting for the server…");
  show(h("section", { class: "pad stack center" },
    h("h1", {}, "Compare this code"),
    h("p", {}, `On ${server.label}, answer yes only if it shows exactly:`),
    h("p", { class: "sas", "aria-label": digits.split("").join(" ") }, `${digits.slice(0, 3)} ${digits.slice(3)}`),
    h("p", { class: "fine" }, "If the codes differ, answer no on the server: someone may be interfering."),
    waiting,
    h("button", { class: "button ghost small", onclick: async () => { await settings.set(PENDING, null); location.hash = "#/servers"; } }, "Cancel")));
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 2500));
    if ((await settings.get(PENDING, null))?.code !== code) return;        // cancelled elsewhere
    const st = await fetch(`/v1/pair/${code}/status?dev=${server.dev}`, { cache: "no-store" }).then((r) => r.json()).catch(() => ({}));
    if (st.active) {
      await servers.put(server);
      await settings.set(PENDING, null);
      if (push) await signedFetch(server, "PUT", `/v1/device/${server.dev}/push?mb=${server.mb}`, push).catch(() => {});
      await syncAll();
      return show(h("section", { class: "pad stack center" }, h("h1", {}, "Paired"),
        h("p", {}, `Alerts from ${server.label} now arrive on this phone.`),
        push ? h("a", { class: "button", href: "#/" }, "See alerts")
          : h("button", { class: "button", onclick: enableNotifications }, "Turn on notifications")));
    }
  }
  await settings.set(PENDING, null);
  throw new Error("The server did not confirm within 10 minutes. Nothing was paired.");
}

// A pairing interrupted by a reload resumes where it was, with the same keys.
async function resumePending() {
  const pending = await settings.get(PENDING, null);
  if (!pending) return false;
  if (Date.now() >= pending.deadline || !pending.server?.keys) { await settings.set(PENDING, null); return false; }
  try { await awaitConfirmation(pending); }
  catch (err) { show(h("section", { class: "pad stack" }, h("p", { class: "error", role: "alert" }, String(err.message || err)),
    h("a", { class: "button", href: "#/add" }, "Try again"))); }
  return true;
}

// --- notifications -------------------------------------------------------------------
async function registration() {
  if (!("serviceWorker" in navigator)) return null;
  return navigator.serviceWorker.ready;
}

async function subscription() {
  if (!("PushManager" in window) || Notification.permission !== "granted") return null;
  const reg = await registration();
  const existing = await reg.pushManager.getSubscription();
  if (existing) return existing.toJSON();
  const { key } = await fetch("/v1/vapid").then((r) => r.json());
  return (await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: unb64u(key) })).toJSON();
}

async function enableNotifications() {
  if (!("Notification" in window) || !("PushManager" in window)) {
    status.textContent = isIos() && !standalone() ? "Add Argus to your Home Screen first." : "Notifications are not available in this browser.";
    return;
  }
  if ((await Notification.requestPermission()) !== "granted") { status.textContent = "Notifications are off."; return; }
  const sub = await subscription();
  for (const s of await servers.all()) await signedFetch(s, "PUT", `/v1/device/${s.dev}/push?mb=${s.mb}`, sub).catch(() => {});
  status.textContent = "Notifications on.";
  route();
}

const isIos = () => /iPhone|iPad|iPod/.test(navigator.userAgent);
const standalone = () => matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;

async function settingsView() {
  const detail = await settings.get("lockscreenDetail", false);
  const perm = "Notification" in window ? Notification.permission : "unavailable";
  const toggle = h("input", { type: "checkbox", id: "detail", checked: detail,
    onchange: (e) => settings.set("lockscreenDetail", e.target.checked) });
  show(h("section", { class: "pad stack" },
    h("h1", {}, "Settings"),
    h("div", { class: "card" }, h("strong", {}, "Notifications"),
      h("p", { class: "row-meta" }, perm === "granted" ? "On for this phone." : perm === "denied"
        ? "Blocked in the browser's site settings." : "Off."),
      perm !== "granted" && perm !== "denied" ? h("button", { class: "button", onclick: enableNotifications }, "Turn on notifications") : null,
      isIos() && !standalone() ? h("p", { class: "fine" }, "On iPhone, add Argus to the Home Screen (Share › Add to Home Screen) to receive notifications.") : null),
    await categoryCard(),
    h("div", { class: "card" }, h("label", { class: "switch", for: "detail" }, toggle,
      h("span", {}, h("strong", {}, "Show alert titles on the lock screen"),
        h("span", { class: "row-meta" }, "Off: the lock screen shows only the severity and the server; the text stays inside the app.")))),
    h("div", { class: "card" }, h("strong", {}, "Privacy"),
      h("p", { class: "row-meta" }, "Alerts are encrypted on your server for this phone only. The relay and the push services see sizes and times, never the text. There is no account."))));
}

// Which kinds of news buzz the phone. Everything still reaches the inbox, and a
// security threat always notifies: it is the reason this app exists.
async function categoryCard() {
  const muted = new Set(await settings.get("mutedCategories", []));
  const rows = Object.entries(CATEGORIES).filter(([c]) => c !== "test").map(([c, text]) => {
    const locked = c === "threat";
    const box = h("input", { type: "checkbox", id: `cat-${c}`, checked: locked || !muted.has(c), disabled: locked,
      onchange: async (e) => {
        const now = new Set(await settings.get("mutedCategories", []));
        if (e.target.checked) now.delete(c); else now.add(c);
        await settings.set("mutedCategories", [...now]);
      } });
    return h("label", { class: "switch", for: `cat-${c}` }, box,
      h("span", {}, h("strong", {}, text), locked ? h("span", { class: "row-meta" }, "Always on.") : null));
  });
  return h("div", { class: "card" }, h("strong", {}, "Notify me about"),
    h("p", { class: "row-meta" }, "Turned-off kinds still arrive in the inbox, without a notification."), rows);
}

// --- routing -------------------------------------------------------------------------
async function route() {
  const hash = location.hash || "#/";
  if (hash.startsWith("#/m/")) return message(decodeURIComponent(hash.slice(4)));
  if (hash === "#/servers") return serverList();
  if (hash === "#/add") return addServer();
  if (hash === "#/pending") return (await resumePending()) || addServer();
  if (hash === "#/settings") return settingsView();
  return inbox();         // "#/" and "#/?c=<category>"
}

// One check at a time; callers arriving meanwhile share it.
function sync() {
  inflight = inflight || runSync().finally(() => { inflight = null; });
  return inflight;
}

async function runSync() {
  status.textContent = "Checking…";
  try {
    const { fresh, dropped } = await syncAll();
    const problems = (await servers.all()).filter((s) => s.lastError);
    status.textContent = problems.length ? `${problems[0].label}: ${problems[0].lastError}`
      : dropped ? `${dropped} message${dropped > 1 ? "s" : ""} failed verification and were dropped`
      : fresh.length ? `${fresh.length} new` : "";
  } catch (err) {
    status.textContent = `Could not check: ${err.message || err}`;
  }
}

async function refresh() {
  route();          // the inbox syncs as it renders
}

addEventListener("hashchange", route);
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") refresh(); });
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js", { type: "module", scope: "/" }).catch(() => {
    status.textContent = "Background notifications are not supported in this browser.";
  });
}
// First paint: an interrupted pairing takes precedence over the inbox.
(async () => { if (!(location.hash && location.hash !== "#/") && (await resumePending())) return; route(); })();
