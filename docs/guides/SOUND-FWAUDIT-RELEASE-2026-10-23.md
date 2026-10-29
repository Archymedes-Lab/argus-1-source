# Release closure-20261023-r6-sound-fwaudit (2026-10-23)

A continuous sound listener in the input hook that names who made each beep,
and a reader for the HP firmware (Sure Start) security audit log. The stage
**supersedes `closure-20261023-r5-sound-fwaudit` and `closure-20261022-r4`**: it
is r4 plus this change on the same live base, so deploy only r6. r5 is left in
place and must not be deployed: it lacks the Beep() caller lookup.

Prompted by a beep the owner heard at about 14:37 with Windows running. JARVIS
had no record of it, because the audio collector meters output for only 8 s in
every 5 minutes. A positive control the same day identified the sound: a
`Beep()` tone (the owner recognised `[console]::Beep(800, 300)`), which plays
through the shared *system sounds* session. It was not a firmware beep.

## What it adds

**Continuous sound listener** (`jarvis/platform/win/inputhook.ps1`, section
"continuous sound listener").
- Every 25 ms it reads the scalar peak meter of every app session on every
  active output device, plus each device's own meter.
- A sound episode starts when the level rises from silence and ends after 2 s of
  silence. An episode with 1.5 s or less of sound is a beep.
- Each episode names the session that played it: pid, process name and start
  time, or *system sounds*. Sound that no session explains is recorded at device
  level, with no owner.
- **Beep() callers are named.** Measured: `Beep()` opens `\Device\Beep`, holds
  it while the tone plays, then closes it. The Windows sound service (`taskhostw`)
  holds its own handle permanently and plays the tone through the system-sounds
  session. So at the onset of a system-sounds sound, a worker thread snapshots the
  handle table (34–38 ms, at most once a second) and names the process that has
  just opened the device. Holders already present in a quiet baseline, or present
  for 10 s or more, are reported separately, never as the caller.
- **Console bells name their owner.** A bell is played by the console host
  (`conhost`/OpenConsole) in its own session. The program that printed it is the
  host's parent, which is accepted only if it started before the host.
- Episodes go to the new `sound_events` table, with caller and console columns
  added by migration on an existing table. The listener's and the lookup's
  counters ride the hook heartbeat (`sound_listener_v1` meta).
- The `audio` job reports beeps from the last 24 h, grouped by source. It raises
  a medium visibility finding while the listener is not reporting.

**HP firmware audit log** (job `fwaudit`, every 30 min, unscored).
- The elevated broker runs `hp_firmware_audit.ps1`, which reads the log through
  HP CMSL `Get-HPFirmwareAuditLog`.
- Warning and critical records are reported, grouped by event. Runtime intrusion,
  DMA, Sure Admin and Tamper Lock sources are raised to high.
- Records new since the last read are marked as new.

## Invariants (and the tests that hold them)

| Invariant | Held by |
|---|---|
| Privacy: amplitude only. No stream is opened, no buffer read, no capture (microphone) device touched | `test_meters_output_devices_only_and_never_opens_a_stream` |
| Bounded: 25 ms poll, ≤16 devices, ≤32 sessions per device, 30 lines/min, 256-line queue, 64 lines per drain tick, 30-day retention | `test_bounded_poll_queue_and_rate`, `test_retention_is_bounded` |
| A listener that fails never takes the hook down | `test_compile_failure_does_not_stop_the_hook` |
| Liveness: a dead, wedged or missing listener is reported, never read as silence | `ListenerHealthTests` (stale beat, stopped thread, wedged sampler, compile failure, old hook) |
| Output from the user-writable spool is type- and range-checked; bad lines are dropped whole | `test_malformed_lines_are_dropped_not_half_stored` |
| No owner is invented: system-sounds and device-level beeps name no program | `test_beeps_grouped_by_source_with_honest_attribution` |
| The caller lookup only duplicates handles with Beep's exact access, compares one name and keeps only the match; it never terminates, reads or writes another process; at most once a second, off the metering thread, and a stuck lookup reads as `wedged` | `test_beep_lookup_is_bounded_and_names_only_the_beep_device`, `test_lookup_health_and_unexpected_holders_from_the_heartbeat` |
| A caller is named only from evidence: `found` needs a pid; no new holder means "not Beep()"; new handles it cannot inspect mean "an elevated caller is not ruled out" | `CallerTests` |
| A database created by r5 gains the caller columns | `test_a_table_from_before_the_caller_columns_is_migrated` |
| memscan still recognises the hook's in-memory assemblies | `test_own_assembly_register_counts_the_listener` |
| The elevated reader loads nothing the unelevated user can change: modules from Program Files by full path, `PSModulePath` pinned first, every file writable and owned only by SYSTEM, Administrators or TrustedInstaller, every code file signed by HP Inc. or Microsoft, checked before any import | `ReaderScriptRules` |
| The reader is read-only (only `Get-HPFirmwareAuditLog` is called) | `test_read_only` |
| Missing CMSL, a refused integrity check, malformed output and a missing broker are each reported, never clean | `CollectorTests` |

## Design choice

For naming `Beep()` callers, a handle-table snapshot from the unelevated hook was
chosen over a kernel file-open trace, which needs an administrator session. Jev
(advisory) agreed at 0.94. It split the main remaining weakness between elevated
callers (0.49) and short tones (0.38); the short-tone limit was then measured
(above).

The listener has three candidate homes:
- a thread in the resident input hook (chosen);
- a new scheduled-task helper;
- a longer burst in the 5-minute collector (60 s would be 20% coverage).

The hook already runs all the time in the desktop session, with a writer, a
heartbeat and a watchdog. So the thread needs no new task, no new privilege and
no new supervisor, and it gets full coverage.

Metering per session is required, not optional. Measured on 2026-10-23, a
whole-device meter never went quiet while Firefox played, and it caught none of
three test sounds. The per-session listener caught all three while Firefox kept
playing.

Jev (advisory only) agreed:
- in-hook listener 0.98;
- hardened CMSL reader 1.0;
- the residual risk of HP's native DLL running elevated should be stated (0.93);
- the top validation gap is a real positive control (0.79), which was done.

Reconsider if:
- the hook's measured CPU rises materially (now 0.83% of one core and 2.3 MB);
- `Beep()` callers need naming, which needs an ETW or API trace;
- HP ships unsigned files in CMSL, which this reader would refuse.

## Measured before staging

Caller attribution, isolated from the live hook:
- `Beep()` from separate processes named the right pid for 6 of 6 tones of 120 ms
  or more, 2 of 2 at 80 ms, and 1 of 4 under 80 ms. All tones were still
  recorded as beeps.
- Console bells named the program that printed them.
- An Asterisk .wav correctly had no `Beep()` caller.
- End to end, the hook's own code, the real ingest and the real findings produced
  `beep-like sound from powershell (Beep() call)` and
  `beep-like sound from powershell (console bell)`.
- The only permanent holder of the Beep device here is `taskhostw` (the sound
  service). About 730 handles of elevated processes cannot be inspected from the
  unelevated hook, with 8–12 new ones appearing per lookup from normal churn.

Listener:

- Positive control, isolated from the live hook: an Asterisk .wav, `Beep(800,300)`,
  and `Beep(600,200)` from another process. All three were recorded as system-sounds
  beeps while Firefox played on the same device. Durations read short (159 ms for a
  300 ms tone), so they are approximate.
- The hook's exact listener section was run against a stub writer with a real
  message loop. The beep line went through the drain timer, and the heartbeat
  carried the counters.
- Cost over 60 s: 0.50 s CPU (0.83% of one core), +2.3 MB private memory,
  12,663 samples.
- Reader, unelevated, run with `-File`: it returns "not elevated", and the collector
  accepts that output. Its ACL and signature checks pass Microsoft's signed modules
  in Program Files and refuse the user's Documents folder. On this machine, files an
  elevated session creates are owned by Administrators.
- **Never run elevated or with CMSL installed.** No firmware record has been read yet.

## Baseline (2026-10-23 15:37:52, live 20261022T205204Z-414291d535bb)

- Score 42.
- `audio`: 2 low (`continuous audio output during the burst window`,
  `audio route and session inventory`).
- `input_hook`: 1 low, 2 ok.
- `input`: 1 medium (`the volume changed with no key press behind it`), 2 low, 7 ok.
- `fwaudit`: no snapshot.
- `sound_listener_v1`: absent.

## Expected after deploy

1. **Daemon restart only.**
   - `audio` gains a **medium** `continuous sound listener not reporting`, because
     the running hook predates the listener. The inventory says "only the burst
     sampler".
   - A new `fwaudit` snapshot appears with one **low** `HP firmware audit log is not
     read`, because the broker has no reader yet.
   - Both jobs are unscored, so the score should not move from them.
2. **After the hook restart** (owner step 1 below):
   - `sound_listener_v1` appears, with state `running`;
   - the medium disappears and the inventory says "continuous listener is live";
   - any beep within 24 h shows as a low `beep-like sound from …`, naming the
     `Beep()` caller or the console's owner where measured;
   - a medium `Beep() caller lookup not working` appears only if the lookup stops;
   - a low `a process keeps the Beep device open` appears only for a permanent
     holder other than `taskhostw`.
3. **After CMSL and the broker reinstall** (owner steps 2–3):
   - `fwaudit` reports `HP firmware audit log read` (ok), plus a finding for each
     warning or critical record.
   - Or, if HP's files fail the check, a medium `HP firmware module failed JARVIS's
     integrity check` that names the files.
   - All r4 expectations still apply (storage collector, brightness, gaps, Sysmon
     baseline).

## Also fixed in this stage (r4 shipped them failing)

The full suite in the r4 stage failed on its own storage collector:
- `storage` was scheduled but neither scored nor declared unscored;
- it had no command mapping;
- `docker system df` output was decoded strictly, so one non-UTF-8 byte raised
  instead of being replaced.

This stage declares `storage` unscored with the `status` command, as the
checkout's mechanism registry already does, and adds `errors="replace"`. The
assurance test's pinned counts move by exactly the new `firmware_audit_log`
entry (unverified 8 → 9, not validated 28 → 29).

Still failing in the staged tree, and equally in the untouched r4 stage, so not
caused by this change:
- `test_input_watchers.BrokerWiringTests`, which reads `jarvis-elevated-broker.ps1`.
  Release trees carry the legacy `broker-jarvis.ps1` until the supervisor rename
  is re-registered.
- `test_stream` (one HTTP bound check).
- `test_ui` (Node dashboard suite).

## Recommended before deploying: prove the firmware reader by hand

The elevated reader has never run against HP's real module. A bounded Jev
review rated that the gap most in need of its own check (0.82), and rated the
evidence for handing the release over without it at 0.10 (advisory only). It
can be closed before the deploy, without JARVIS.

1. In an elevated PowerShell: `Install-Module PowerShellGet -Scope AllUsers -Force -AllowClobber`, then in a new elevated PowerShell `Install-Module HPCMSL -Scope AllUsers -AcceptLicense` (PowerShell 5.1 ships PowerShellGet 1.0.0.1, which lacks -AcceptLicense; HP.Firmware is not published alone; HPCMSL installs HP.Firmware, HP.Utility and HP.Private as separate module folders).
2. In the same elevated shell, run the reader from the checkout and decode its output:

   ```
   $b = powershell -NoProfile -ExecutionPolicy Bypass -File \\wsl.localhost\Ubuntu\home\chris\jarvis\jarvis\platform\win\hp_firmware_audit.ps1
   [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)) | ConvertFrom-Json | Format-List
   ```

   The distribution name in the path may differ; `wsl -l` shows it.
3. Expect `available : True` and the records. If `reason` starts with `refused`,
   `problems` names each file that failed the ownership or signature check.
   Send that output back before deploying.

## Deploy

```
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
  --source ~/.cache/jarvis-release-staging/closure-20261023-r6-sound-fwaudit \
  --checkout /home/chris/jarvis \
  --expect-base sha256:414291d535bb44aedfa16d063d39c05b4362d6a467a4bfa78c840357129724f4 \
  --skip-tests
```

`--checkout` must be `/home/chris/jarvis`, not the overlay that the stage
builder printed. Rollback: `sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --rollback`.

## Owner steps after the deploy

1. **Restart the hook** from a desktop WSL terminal, so the listener starts:
   `jarvis inputwatch --stop && jarvis inputwatch --start`
2. **Install HP CMSL for all users** (elevated PowerShell): `Install-Module PowerShellGet -Scope AllUsers -Force -AllowClobber`, then in a new elevated PowerShell `Install-Module HPCMSL -Scope AllUsers -AcceptLicense` (PowerShell 5.1 ships PowerShellGet 1.0.0.1, which lacks -AcceptLicense; HP.Firmware is not published alone; HPCMSL installs HP.Firmware, HP.Utility and HP.Private as separate module folders).
   It must be *AllUsers*: a CurrentUser install lands in Documents, and the reader
   refuses it by design.
3. **Restage the broker** (one UAC prompt): `jarvis broker install`.
4. Optional, to see the log at once: in an elevated PowerShell,
   `Get-HPFirmwareAuditLog | Select -Last 20`.

## Acceptance (per docs/guides/DEPLOY.md)

1. Read the release path, check `systemctl show jarvis.service -p ActiveState -p NRestarts`,
   and confirm `/api/health` is `ready`.
2. The journal has no tracebacks.
3. `audio`, `fwaudit` and `input_hook` all have fresh snapshots.
4. Each change matches "Expected after deploy" above, finding by finding.
5. Play a beep, for example `[console]::Beep(800,300)` in PowerShell. Within the
   next audio pass, a `beep-like sound from powershell (Beep() call)` finding
   should carry its time and that PowerShell's pid.

## Blind spots that remain

- A `Beep()` caller is not named when it is elevated or protected (the unelevated
  hook cannot inspect its handles; the finding says an elevated caller is not
  ruled out), or when its tone is under about 80 ms.
- Windows event sounds and PlaySound calls share the system-sounds session, so
  their program is not named.
- A process that keeps the Beep device open is reported, but its own `Beep()`
  calls are not attributed.
- Sounds shorter than one 25 ms poll are missed.
- The first sound of a new app session is missed when it is shorter than the
  250 ms rescan and another app is already playing.
- Audio played at zero session volume is missed.
- Firmware and embedded-controller beeps never reach Windows audio.
- HP's native DLL runs as administrator inside the broker job. The signature and
  ACL checks bound who can change it, not what it does.
- The firmware clock zone is unknown.
- Only events the firmware journals are visible: no fan, thermal or battery chimes.
