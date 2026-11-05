// Application state. The daemon owns the truth; this holds the last copy the
// shell fetched and refreshes it when the pulse stream says something changed.
import { api, onDaemon } from "./api";

export type View = "overview" | "findings" | "collectors" | "review" | "assistant" | "licence" | "settings";
export type Theme = "auto" | "light" | "dark";

const THEME_KEY = "jarvis.theme";
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
  toasts: [] as { id: number; text: string; tone: "ok" | "bad" | "info" }[],
});

function readTheme(): Theme {
  try { const t = localStorage.getItem(THEME_KEY); return t === "light" || t === "dark" ? t : "auto"; }
  catch { return "auto"; }
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
  applyTheme();
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
