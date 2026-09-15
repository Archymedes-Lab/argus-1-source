# JARVIS as a desktop app: architecture

Status: proposal, 2026-09-16. Nothing here is built yet.

The goal: JARVIS always open on the desktop, telling you what it sees as it
sees it, with everything the CLI and dashboard can do.

## The rule that shapes everything

**The app is a client, never the monitor.** `jarvis serve` keeps collecting,
responding and emailing whether or not a window is open, and closing the app
must never blind the machine. Anything the app alone can do is a feature that
disappears the moment you quit it — so the app renders state, and the daemon
owns it.

That also decides where work happens: no collector, no rule and no response
action moves into the UI process.

## What "always open" needs, beyond the current page

The dashboard already exists as a local web page served by the daemon. A
desktop shell adds only the things a browser tab cannot do:

| capability | why it needs a shell |
|---|---|
| Tray icon with the live score and worst finding | a tab cannot live in the tray |
| Native notifications for criticals and outages | browser notifications need a focused origin and are easy to lose |
| Start with the session, single instance, restore last view | a tab does not survive a reboot |
| Global hotkey ("what changed?") | needs an OS-level hook |
| Window that cannot be navigated away | the shell pins one origin |

## The shell: Tauri (decided 2026-09-16)

**Tauri 2** (Rust shell, uses the system WebView2 on Windows).
A ~5 MB binary, one process tree, no bundled browser, and a small dependency
set — which matters for a tool whose own audits flag unsigned binaries,
unexpected autostart entries and supply-chain risk. JARVIS shipping hundreds
of npm packages to display its own findings is the kind of thing JARVIS
reports on.

**Electron** was the alternative, and would have been a reasonable choice for
its richer native API surface and familiar toolchain. If it is ever picked up
instead, these are the terms:

- a bundled Chromium per install (~150 MB) and a large npm dependency tree —
  pin with a lockfile, vendor it, and review updates like any other supply
  chain;
- `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, and the
  page's existing CSP kept as-is: the renderer shows a local page and needs no
  Node;
- no auto-updater phoning home — JARVIS updates by `git pull` like the rest;
- ASAR integrity on, so the app's own files are fingerprinted the way JARVIS
  fingerprints its scheduled-task scripts.

Either way the UI is the same web app, so the choice stays reversible. A
stopgap costing almost nothing until the shell exists: install the existing
dashboard as a PWA (Edge "Install this site as an app"), which already gives a
window, a taskbar entry and autostart, and answers some of the shell-shaped
questions before one is written.

## Live insight instead of polling

The page polls `/api/state` every 5 seconds today. For an always-open window
that is both wasteful and slow to tell you something urgent. Add one endpoint:

- **`GET /api/stream`** — Server-Sent Events from the daemon: score changes,
  new findings above a threshold, collector state changes, defense-ledger
  entries, protocol state. SSE over the existing `http.server`, no new
  dependency, and the app falls back to polling when the stream drops.
- The app keeps a local cache so a restart redraws instantly, exactly as the
  page does from SQLite today.

## What the app shows

1. **The greeting**, as the dashboard chat now opens: blind collectors first,
   score and trend, what needs you, today's protocol and its question.
2. **Protocols** as a checklist: steps, the Yes/No question, `brief check`
   as a button, and progress toward the projected score.
3. **Findings** with the existing triage grouping (you act / you confirm /
   JARVIS handles), filters and evidence.
4. **Ask JARVIS** — the same read-only assistant, with the local model for
   open questions.
5. **Defense ledger** — what JARVIS did and the undo for each.
6. **Tray**: score, worst open finding, "run all", "open dashboard".

## The mutation boundary stays where it is

The app may: ask, acknowledge with a reason, answer protocol questions, run a
collector, approve or undo a *proposed* action — each one an explicit click
that calls the existing local API, which keeps its host and same-origin checks.

The app may not: change config, run arbitrary commands, or act on model output.
As with messaging, text from the local model has no route to any of these.

## Packaging and trust

- Built from this checkout, unsigned to begin with — and therefore visible to
  JARVIS's own "recently written unsigned executable" rule, which is the
  correct outcome for a binary you built yourself. Sign it when convenient.
- Autostart via a scheduled task registered the way `JARVIS input hook` is, so
  the control audit verifies it by definition and fingerprint instead of
  trusting a name.
- The window binds nothing: it talks to `127.0.0.1:8787`, which stays
  loopback-only.

## Phases

1. **Stopgap:** install the dashboard as a PWA, add the tray-shaped needs to
   the list of what is actually missing.
2. **Stream:** `/api/stream` plus an SSE client in the page — the biggest
   single improvement, and it benefits the browser too.
3. **Shell:** the Tauri window, tray, notifications, autostart and
   single instance.
4. **Native touches:** global hotkey, jump list / quick actions, per-finding
   deep links.

## Open questions

- Windows only, or the WSL side too (a Linux build would need a separate
  shell)?
- Should the app show the keystroke-monitor state as a tray colour, given it
  is the one component that can be blind while everything else looks fine?
