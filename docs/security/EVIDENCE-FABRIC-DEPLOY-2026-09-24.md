# Evidence Fabric deployment, 2026-09-24 (measured)

Four sealed releases were deployed by the owner on 2026-09-24, verified on live results as set out
in `docs/guides/DEPLOY.md`. Every number below is a fresh post-restart snapshot or a stored score.

| Time (EEST) | Release | Content |
|---|---|---|
| 22:21 | `20260924T192154Z-bd5e28bd` | Lane A (provenance, managed persistence, release controller) + Lane B (observation, epochs, topology) |
| 23:13 | `20260924T201343Z-c642fa37de4a` | `/init` ancestry may end at pid 1; exe identity recorded at collection; provenance key provisioned |
| 23:29 | `20260924T202958Z-868793e24be7` | Lane A: provenance key/state paths restored |
| 23:32 | `20260924T203201Z-6599e03cda78` | Lane B: epoch clock-step rule fitted to measured WSL clock discipline |

Service after each switch: active, 0 restarts; `/api/health` healthy, ready, protection_healthy.
`provenance authority: issuing` since 23:29 (key `ca55075b2a190264`).

## Findings, before and after

- **scan**: 16 mediums at 21:30 (WSL `/init` SessionLeader/Relay, udev, sd-pam, python scripts)
  down to 0 name-mismatch mediums. What remains: `powershell.exe` via `/init` (interop, flagged by
  design until the interop broker exists) and agent-shell highs (`bash`/`python3` piping into an
  interpreter). A privileged dry run found the `/init` chain bug (PPid of WSL's init-systemd is 1
  under systemd=true). The first live readback found the udev-worker race, which failed closed.
- **hidden / deep_hidden**: 4 → 2 mediums each. `10.255.255.254:53` tcp/udp are low, with WSL's
  declaration as proof. `udp/323` stays medium; its owner is in the WSL VM root and cannot be seen.
- **control (Persistence)**: the two watchdog-task criticals and the selfcheck medium cleared.
  Persistence went 22 → 67 (23:13).
- **Epoch ledger**: before the fix, a false clock-step on nearly every sample (19 epochs in 70 min).
  Measured cause: CLOCK_MONOTONIC runs ~10% fast on this VM, and hv timesync steps the wall clock
  back ~2.95 s every ~30 s. After the 23:32 fix: one `release` epoch, then two consecutive
  5-minute samples (23:37:52, 23:43:04) in the same epoch.

Overall score: 60 (22:17) → 67 (23:13) → 66 (23:52). Active threats 15 → 17. Remaining highs: sysmon_linux, input, intrusion, agent shells.

## Changes not caused by these releases (reviewed)

- **boot, +1 medium (Persistence 67 → 62)**: one 22:15 run of the JARVIS input hook task is
  recorded twice. The `\JARVIS input hook` record is lowered by the control verification. The
  `NT TASK\JARVIS input hook → taskhostw.exe` record is not, because `apply_verified_tasks` matches
  the task path only. `startup.py` is unchanged in these releases. This is a matching gap to fix,
  with a test, and not by name alone: the `NT TASK\<name>` account must map to exactly one
  verified task path.
- **deep_hidden, +3 mediums**: Windows processes (`curl.exe`, `conhost.exe`, `powershell.exe`) that
  were missing from `tasklist` during the sweep. The Windows view is unchanged in these releases,
  and these are short-lived interop processes. Not reclassified.
- **watchdogs, transient medium 23:34–23:47**: `inputaudit` produced no output after the restarts.
  The broker output refreshed at 23:48 and the finding cleared at 23:49.

## Open

Epochs are not yet consumed by Sysmon/native reconciliation. The WSL interop broker (item 6) is
not built. The `NT TASK\` boot alias gap above. Watch the epoch ledger across the next standby:
a resume must open exactly one epoch.
