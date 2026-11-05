// The only way the interface reaches the daemon: typed Tauri commands
// (desktop/src/api.rs). The page has no network permission of its own.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { brandDeep } from "./brand";

export const inApp = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (inApp) return brandDeep(await invoke<T>(cmd, args));
  if (import.meta.env.DEV) return brandDeep(await preview<T>(cmd));
  throw new Error("This interface runs inside the ARGUS-1 app.");
}

// Development preview in a plain browser: read-only, from a saved state file.
async function preview<T>(cmd: string): Promise<T> {
  if (cmd === "licence_state") {
    const r = await fetch("/__fixture/licence.json");
    if (!r.ok) throw new Error("No licence preview fixture.");
    return (await r.json()) as T;
  }
  if (cmd === "daemon_state") {
    const r = await fetch("/__fixture/state.json");
    if (!r.ok) throw new Error("No preview fixture (set JARVIS_UI_FIXTURE).");
    return (await r.json()) as T;
  }
  throw new Error("Preview mode: actions are disabled.");
}

export type Reply = { ok?: boolean; message?: string; answer?: string; source?: string; queued?: boolean };

export const api = {
  state: () => call<any>("daemon_state"),
  runCollector: (job: string) => call<Reply>("run_collector", { job }),
  answer: (id: string, choice: "yes" | "no") => call<Reply>("answer_question", { id, choice }),
  ask: (question: string) => call<Reply>("ask_jarvis", { question }),
  scoreCoach: () => call<Reply>("score_coach"),
  decideFix: (id: string, decision: "approve" | "retry" | "reject", reason?: string) =>
    call<Reply>("decide_fix", { id, decision, reason }),
  licence: () => call<LicenceState>("licence_state"),
  licenceAction: (action: "activate" | "deactivate" | "refresh" | "upgrade" | "poll", key?: string, plan?: "server" | "desktop") =>
    call<LicenceReply>("licence_action", { action, key, plan }),
  openLicencePage: (url: string) => call<void>("open_licence_page", { url }),
};

export type LicenceState = {
  licensed: boolean; reason: string; product?: string; plan?: "server" | "desktop"; label?: string; key_hint?: string;
  expires_at?: number | null; lease_until?: number; renew_after?: number; auto_renew?: boolean; renew_error?: string | null;
  needs_key?: boolean; needs_check?: boolean; purchase_waiting?: boolean;
  links: { buy_server: string; buy_desktop: string; manage: string; recover: string };
};
export type LicenceReply = { ok: boolean; code?: string; error?: string; open?: string; active?: boolean; state?: LicenceState };

/** Pulses from the shell's stream thread; `down` when the daemon is unreachable. */
export async function onDaemon(pulse: (p: unknown) => void, down: () => void): Promise<UnlistenFn> {
  if (!inApp) return () => {};
  const a = await listen("pulse", (e) => pulse(brandDeep(e.payload)));
  const b = await listen("daemon-down", () => down());
  return () => { a(); b(); };
}
