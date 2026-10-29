// The only way the interface reaches JARVIS: typed Tauri commands
// (desktop/src/api.rs). The page has no network permission of its own.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export const inApp = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (inApp) return invoke<T>(cmd, args);
  if (import.meta.env.DEV) return preview<T>(cmd);
  throw new Error("This interface runs inside the ARGUS-1 app.");
}

// Development preview in a plain browser: read-only, from a saved state file.
async function preview<T>(cmd: string): Promise<T> {
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
};

/** Pulses from the shell's stream thread; `down` when the daemon is unreachable. */
export async function onDaemon(pulse: (p: unknown) => void, down: () => void): Promise<UnlistenFn> {
  if (!inApp) return () => {};
  const a = await listen("pulse", (e) => pulse(e.payload));
  const b = await listen("daemon-down", () => down());
  return () => { a(); b(); };
}
