# Native defender implementation checkpoint

Started 2026-09-13. Existing deployment remains in place during migration.

## In progress

- Explicit per-job collection status so a bridge failure cannot clear incidents.
- Separate liveness and protection health.
- Independent Windows Event Log sensor with durable local spool and replay checkpoints.
- Validating importer with atomic events/cursor persistence and duplicate protection.

## Done: terminal flashes (2026-09-13)

Root cause: `HKCU\Console\%%Startup` had no delegation values ("Let Windows
decide"), so Windows 11 hosted every console launch in Windows Terminal
(`OpenConsole.exe -Embedding`, `CASCADIA_HOSTING_WINDOW_CLASS`), which ignores
`-WindowStyle Hidden`. `fix-console-host.ps1` sets Windows Console Host for
this user (backup + `-Revert`); applied live. Posture audit now flags a
regression.

That removed the Windows Terminal windows, but a 3-minute re-observation
still recorded 6 `ConsoleWindowClass` powershell SHOW events (the two
one-minute monitors): conhost shows the window before hiding it. Real fix:
launch through `conhost.exe --headless`. The three installers now register
that form, and `control.py` verification accepts it only when it wraps
System32 Windows PowerShell with the reviewed arguments. `apply-headless-monitors.ps1`
rewraps the existing tasks in place (triggers/principal unchanged). Applied
live 2026-09-13 ~19:05 UTC. Verified 19:06–19:12 UTC (6 min, uncapped): zero
console/terminal windows; all three tasks kept running (last runs 21:09–21:11
local, dead-man state.json rewritten 21:11:46). Caveat: conhost returns
exit code 0, so Task Scheduler's LastTaskResult no longer reflects script
failures (nothing in JARVIS reads it). Do not pass `-SyncScripts` until
jarvis.service runs this checkout: the new dead-man requires
`protection_healthy`, which the running service does not send yet.

## Required before calling this deployed

Compile and exercise the Windows sensor; validate crash/replay and malformed input;
install under an administrator-owned path with a restricted service identity;
verify live native events reach storage while WSL is unavailable; preserve old
monitoring until native coverage is verified. Do not count source code or a
successful build as a running production sensor.

## Remaining architecture

Incident lifecycle and response broker, signed distribution, independent evidence
destination, prevention-policy rollout, and restore exercises remain subsequent
stages. See JARVIS-DEFENDER-ARCHITECTURE-2026-09-13.md for acceptance criteria.
