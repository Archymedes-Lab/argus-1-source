// Application state. The daemon owns the truth; this holds the last copy the
// shell fetched and refreshes it when the pulse stream says something changed.
import { api, onDaemon } from "./api";

export type View = "overview" | "findings" | "collectors" | "review" | "assistant" | "pricing" | "settings";
export type Mode = "simple" | "expert";
export type Theme = "auto" | "light" | "dark";

const THEME_KEY = "jarvis.theme";
const MODE_KEY = "jarvis.mode";
const LANG_KEY = "jarvis.lang";
const LANG_CODES = ["en", "fr", "de", "es", "zh", "ja", "ko", "pt", "hi", "ru", "ar"];
const RTL = ["ar"];

/** Language and reading direction go on <html>, so the whole page follows. */
function applyLang() {
  document.documentElement.setAttribute("lang", app.lang);
  document.documentElement.setAttribute("dir", RTL.includes(app.lang) ? "rtl" : "ltr");
}
const MIN_GAP_MS = 4000;       // pulses can arrive in bursts; one refetch covers them
const FALLBACK_MS = 60000;     // if the stream is quiet, still refresh once a minute

export const app = $state({
  data: null as any,
  loading: false,
  error: "",
  daemon: "connecting" as "connecting" | "live" | "down",
  updatedAt: 0,
  view: "overview" as View,
  query: "",
  severity: null as string | null,
  host: "",
  job: "",
  selected: null as any,
  palette: false,
  theme: readTheme(),
  mode: readMode(),
  lang: readLang(),
  toasts: [] as { id: number; text: string; tone: "ok" | "bad" | "info" }[],
});

function readTheme(): Theme {
  try { const t = localStorage.getItem(THEME_KEY); return t === "light" || t === "dark" ? t : "auto"; }
  catch { return "auto"; }
}

function readLang(): string {
  try {
    const saved = localStorage.getItem(LANG_KEY);
    if (saved && LANG_CODES.includes(saved)) return saved;
    // First run: follow the system language when it is one we have.
    const sys = (navigator.language || "en").slice(0, 2).toLowerCase();
    return LANG_CODES.includes(sys) ? sys : "en";
  } catch { return "en"; }
}

export function setLang(code: string) {
  if (!LANG_CODES.includes(code)) return;
  app.lang = code;
  try { localStorage.setItem(LANG_KEY, code); } catch { /* per-viewer convenience only */ }
  applyLang();
}

function readMode(): Mode {
  try { return localStorage.getItem(MODE_KEY) === "expert" ? "expert" : "simple"; }
  catch { return "simple"; }
}

export function applyMode() {
  document.documentElement.setAttribute("data-mode", app.mode);
}

export function setMode(m: Mode) {
  app.mode = m;
  applyMode();
  try { localStorage.setItem(MODE_KEY, m); } catch { /* per-viewer convenience only */ }
}

export function setTheme(t: Theme) {
  app.theme = t;
  try { localStorage.setItem(THEME_KEY, t); } catch { /* per-viewer convenience only */ }
  applyTheme();
}

export function applyTheme() {
  const root = document.documentElement;
  if (app.theme === "auto") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", app.theme);
}

let inFlight = false, last = 0, queued = 0 as any;

export async function refresh() {
  if (inFlight) return;
  inFlight = true; app.loading = true; last = Date.now();
  try {
    app.data = await api.state();
    app.error = ""; app.daemon = "live"; app.updatedAt = Date.now();
  } catch (e) {
    app.error = String((e as Error)?.message ?? e);
    app.daemon = "down";
  } finally {
    inFlight = false; app.loading = false;
  }
}

function schedule() {
  const wait = Math.max(0, MIN_GAP_MS - (Date.now() - last));
  clearTimeout(queued);
  queued = setTimeout(refresh, wait);
}

export async function start() {
  applyLang();
  applyTheme();
  applyMode();
  await refresh();
  await onDaemon(() => schedule(), () => { app.daemon = "down"; });
  setInterval(() => { if (Date.now() - last > FALLBACK_MS) refresh(); }, 10000);
}

let toastId = 0;
export function toast(text: string, tone: "ok" | "bad" | "info" = "info") {
  const id = ++toastId;
  app.toasts = [...app.toasts.slice(-2), { id, text, tone }];
  setTimeout(() => { app.toasts = app.toasts.filter((t) => t.id !== id); }, 6000);
}

export function go(view: View, filters: Partial<{ severity: string | null; query: string; host: string; job: string }> = {}) {
  app.view = view;
  if ("severity" in filters) app.severity = filters.severity ?? null;
  if ("query" in filters) app.query = filters.query ?? "";
  if ("host" in filters) app.host = filters.host ?? "";
  if ("job" in filters) app.job = filters.job ?? "";
  app.selected = null;
}
