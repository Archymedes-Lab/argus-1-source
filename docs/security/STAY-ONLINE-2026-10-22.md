# Why JARVIS kept stopping, and what was done (2026-10-22)

Owner request: "it still stops a few times a day; make sure it stays online" and
"strengthen the daemon as well". This records the measured causes, the daemon
changes made, how they were verified, and the actions only the owner can take.

Clocks: Windows logs are UTC+2, WSL is UTC+3. Times below are WSL unless marked.

## Measured causes (score history gaps, reviver log, Windows event logs, cgroup counters)

Score history (`history` table, one row per 5 s while the daemon runs) over the last
7 days has 21 gaps longer than 20 minutes. Matched against the Windows System log and
the Hyper-V worker log, they fall into five classes:

| Class | Evidence | Count (10-19..10-22) | Who can fix |
| --- | --- | --- | --- |
| Laptop asleep (user sleep, Modern Standby) | Kernel-Power 42/107/506/507 bracket every gap; VM shut down "by the guest" 2 s after sleep | most daytime gaps (e.g. 14:27-15:12 and 15:44-16:30 today) | owner (power settings); nothing inside the VM runs |
| Windows hard reset | Kernel-Power 41 + EventLog 6008 "previous shutdown was unexpected" | 7 in 4 days (10-19 09:59, 10:10, 15:57; 10-20 12:30, 18:38; 10-21 20:41; 10-22 16:01 Win time) | owner: hardware/firmware/battery; JARVIS cannot prevent |
| Reviver restarted a daemon that was alive | `revive.log`: "active but stalled for N s" right after each resume / cold start; the installed `revive-jarvis.ps1` is the 2026-09-17 copy without StartGrace | 1-3 per day (10-14..10-22) | daemon fix below + owner re-registration of the reviver |
| Windows interop registration flushed | `/proc/sys/fs/binfmt_misc` lost `WSLInterop` at 17:24 when two privileged containers running their own systemd (`argus-u1`, `argus-t3`, `privileged=true`, host cgroupns) booted; every PowerShell collector then failed with "PowerShell failed or timed out" while `bridge` still read "up" | 1 today; silent class until now | daemon fix below (self-heals); owner can restore the entry |
| Memory ceiling | `jarvis.service` cgroup at 1.47 GiB of MemoryHigh 1.5 GiB, `memory.events high` rising ~20/min, 0.95 GiB of it page cache of the 0.77 GiB database | continuous | owner: raise MemoryHigh (unit drop-in) |

Why the journal could not show this: systemd-timesyncd and Hyper-V time sync step the
clock every 32 s ("Time jumped backwards, rotating": 52 rotations in 45 minutes), so
the journal holds about 50 minutes. The daemon's own records and the Windows logs
were used instead.

## Daemon changes (checkout, uncommitted; backport staged for the live release)

Invariants written before editing: evidence continuity (a flushed interop must stay
visible as a finding, never masked); sensor freshness (collection must continue
through the flush); bounded resource use (one extra `stat` per spawn, one cgroup read
per 5-minute sample); recovery (nothing new needs root; failures fall back to the old
behaviour); explicit authority (no new automatic action).

1. `jarvis/platform/windows.py`: `interop_binfmt_registered()`, `interop_launcher()`,
   `interop_mode()`, `spawn()`. When the kernel's `WSLInterop` entry is missing and
   `/init` is executable, every Windows program is started as `/init <exe> ...`
   (the interpreter the entry names). A flush between the check and the exec raises
   ENOEXEC and is retried once through `/init`. All PowerShell launch sites use it
   (`ps_json`, `collect`, `_run_via`, posture elevation, input-hook direct start).
2. `jarvis/service/coverage.py` `bridge_status()`: adds a medium finding "the WSL
   interop registration was removed from binfmt_misc" (critical when `/init` is not
   executable either). Worded outside `alert.py`'s outage markers so it informs
   without paging; the ok finding stays.
3. `jarvis/service/scheduler.py` + `protection.py`: lanes stamp `CLOCK_MONOTONIC`
   twins of their heartbeats; `/api/health` `progress_age`/`fast_lane_age` and the
   systemd watchdog feeder read monotonic ages. The monotonic clock stops with the
   frozen VM, so a resume no longer reads as a 15-minute stall; a real stall while
   awake is judged on the unchanged thresholds (900 s main, 300 s fast).
4. `jarvis/collectors/process/resourcewatch.py`: `service_cgroup()` reads the unit's
   `memory.current/high/max/events/stat/pressure`; `_cgroup_findings()` reports
   "JARVIS is being throttled at its memory ceiling" (medium) when usage is at or
   above 90% of MemoryHigh and at least 60 throttle events accrued since the last
   sample, and "OOM-killed" (high) on an `oom_kill` increase. First sample records only.

Tests: `tests/test_daemon_resilience.py` (20 checks: direct vs `/init`, disabled and
late entry names, ENOEXEC retry and its non-recursion, `ps_json` through the fallback,
bridge finding does not classify as an outage, standby vs real stall on health, fakes
without monotonic twins, cgroup first-sample/brush/ceiling/OOM/no-limit, audit survives
an unreadable cgroup).

Verification: checkout suite 2457 tests, 7 not passing, all reproduced on the tree without this change (jarvis.argus import/layer checks from other uncommitted work, two tests that execute PowerShell and need the flushed binfmt entry, one timing test that fails 1 in 4 under load either way). Backport overlay suite 2042 tests; the 4 remaining failures are identical on an unpatched copy of the live release. `scripts/dev/static_gate.sh --quick` (ruff,
mypy) pass. Live path: with the entry missing on this VM, `ps_json` and `collect()`
through the launcher returned a payload and 314 Windows processes; `service_cgroup()`
read the live unit (1.44 GiB current, 1.5 GiB high, 7965 high events).

Jev advisory (metadata only, 4 questions, jev-1.14.0): "fallback masks a real failure"
0.25, "monotonic liveness misses a real stall" 0.08, "ceiling threshold plausible"
0.73, top validation gap: observe a real standby/resume (0.76). Advisory only; the
tests and live reads above are the evidence.

## Second cause found after the first deploy: the daily history verification

After release 2dac3942 was deployed (19:16) and the memory drop-in applied (19:18), every
PowerShell collector recovered within a minute, but `native` stayed "unavailable: collector
exceeded its 45s process deadline". Cause: `native.audit` re-verifies the whole event
history once a day (`eventlog_verified_at` older than 24 h). At 1.5 GiB / 2006 segments the
verification takes 75 s on this machine (measured read-only, result ok), so the 45 s worker
deadline killed it on every run, the completion stamp was never written, and the next run
tried again. The reviver log shows the same pattern on 2026-10-21 (218 lines, 16:00-18:00
Windows time) and today from 18:20: a daily hour-plus of protection "unavailable".

Fix (checkout + backport stage `stay-online-20261022-r3`; r2 was superseded before deploy
because bulk jobs must live in a PowerShell-free module): the verification is its own
daily bulk-lane job `history_verify` (module `jarvis/collectors/telemetry/history_verify.py`) (300 s budget per `reliability._execution_timeout`;
governor-deferrable; Monitoring score area). It stamps the attempt before reading, so a
run cut off by its budget is reported as a medium finding and not retried for an hour; a
completed run stamps `eventlog_verified_at`; chain damage stays a critical tampering
finding. The ingestion collector no longer verifies and reports a medium visibility
finding when the last verification is older than 48 h. Tests: `HistoryVerifyTests` (5).

## Owner actions, in order

1. Restore the interop entry now (until the release is deployed, every PowerShell
   collector is down):
   `sudo systemctl restart systemd-binfmt`
   and avoid running privileged containers with systemd inside while JARVIS matters,
   or add a guard that re-registers (see below).
2. Deploy the staged backport `~/.cache/jarvis-release-staging/stay-online-20261022-r1`
   (base `sha256:0d307253d24d…`; baseline docs/guides/baselines/stay-online-baseline-2026-10-22.json):
   ```
   sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
     --source ~/.cache/jarvis-release-staging/stay-online-20261022-r1 \
     --checkout /home/chris/jarvis \
     --expect-base sha256:0d307253d24d25d531895848fe3bf64b69c26ff4a51c950afcf4ed4f66ccc36b --skip-tests
   ```
   (`--checkout /home/chris/jarvis`, not the scratch overlay the stage record names,
   or the watchdog tasks read critical); then read back `/api/health`
   (`healthy`, `ready`), a fresh `bridge` snapshot with no binfmt finding once the
   entry is back, and `resources` after two samples.
3. Raise the memory ceiling (`sudo systemctl edit jarvis.service`):
   `[Service]` / `MemoryHigh=2560M` / `MemoryMax=3G`, then `daemon-reload` and restart.
   Measured need: 0.45 GiB process memory + 0.95 GiB database cache + headroom.
4. Stop the clock fight so the journal keeps history:
   `sudo systemctl disable --now systemd-timesyncd` (Hyper-V keeps the guest clock).
5. Re-register the Windows reviver and health monitor from the renamed scripts
   (docs/guides/WINDOWS-SUPERVISOR-NAMES.md). The installed reviver predates
   StartGrace and kick back-off; the installed health monitor toasts "unavailable"
   for degraded coverage.
6. Optional guard for the interop entry (root): a one-minute timer running
   `test -e /proc/sys/fs/binfmt_misc/WSLInterop || systemctl restart systemd-binfmt`.
7. Deploy `stay-online-20261022-r3` the same way (base is the r1 release 2dac3942…),
   then force `history_verify` once with the API token and expect an "ok" snapshot within
   about 90 s and `native` complete on its next run:
   ```
   T=$(cat ~/.jarvis/api.token); curl -s -X POST -H "X-JARVIS-Token: $T" "http://127.0.0.1:8787/api/run?job=history_verify"
   ```
8. Hardware: 7 unexpected shutdowns in 4 days (`powercfg /batteryreport`, firmware).

## What would cause reconsideration

If a real stall while awake goes unnoticed (health `live` true with no snapshot
progress for more than 15 minutes), the monotonic design is wrong, not the thresholds.
If the cgroup finding fires while `memory.pressure full avg60` stays near zero for a
day, raise `CGROUP_THROTTLE_EVENTS`.

## Release r4: r3 plus the redesigned dashboard (2026-10-22 evening)

Stage `~/.cache/jarvis-release-staging/stay-online-ui-20261022-r4`, base the live r1 release
`sha256:2dac3942680a…`. It supersedes r3 (same files plus `jarvis/web/static/dashboard.html`).

```
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
  --source ~/.cache/jarvis-release-staging/stay-online-ui-20261022-r4 \
  --checkout /home/chris/jarvis \
  --expect-base sha256:2dac3942680acda4339c93f87fb552baac4a42936ca56de92a60307f8746d538 \
  --skip-tests
```

Dashboard changes (owner list of 2026-10-22): Swiss/Apple design system (one stylesheet,
system type, 8-point grid, Apple system colours), Auto/Light/Dark switch remembered per
browser, a Priorities row (critical, high, needs your decision, collectors reporting), a
red alert banner for criticals and live alerts, browser desktop notifications for new
criticals (opt-in "Notify me"; the daemon's Windows toasts are unchanged and independent),
search results shown directly under the search box across findings, verified-clean checks
and collectors (Enter jumps to the list), a section bar, and Monitoring / Assistant / More
as collapsible sections.

Readback after deploy: open http://127.0.0.1:8787, switch Light/Dark, type in the search box
(the results panel must appear), press Notify me and allow, then confirm the priorities
counts match `/api/state`; history_verify and native as in the r3 readback.

## Release r5: the dashboard design system (2026-10-22 night)

Stage `~/.cache/jarvis-release-staging/ui-design-system-20261022-r5`, base the live release
`sha256:b43045cd63c8…` (r4, deployed 21:40).

```
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
  --source ~/.cache/jarvis-release-staging/ui-design-system-20261022-r5 \
  --checkout /home/chris/jarvis \
  --expect-base sha256:b43045cd63c88a39fe6843b5485dc465c84c826bd7df7fed966f275aa61f9bfc \
  --skip-tests
```

- Design system: Tailwind CSS v4.3.3 source `jarvis/web/styles/dashboard.css` (tokens in
  `@theme`, components in `@layer components`, a `dark` custom variant on `data-theme`),
  compiled by `scripts/dev/build_ui.sh` into the page's `<style id="ui">`. The standalone CLI
  is verified against the release `sha256sums.txt` and kept in `~/.cache/jarvis-ui-tools`;
  nothing of Tailwind ships. `source(none)` stops utility generation from the page (the
  utilities `ring` and `static` would restyle existing classes).
- Type: Inter 4.1 variable (SIL OFL 1.1) vendored at `static/vendor/InterVariable.woff2`,
  served from a pinned SHA-256 like three.js; SF Pro on Apple devices; optical sizing on.
  Content policy gains `font-src 'self'` and `img-src data:` (the search icon).
- Palette: Apple system colours for light and dark; dark surfaces separate by tone only.
- Checked in a Linux headless Chromium (Playwright, user cache; Windows policy blocks
  headless Chrome and Edge here) at 1440 px dark and light and at 390 px, with live data.
- Tests: `tests/test_dashboard_ui.py` (inlined system present, no other origin, font pinned
  and licensed and allowed by policy, no decorative inline styles, scripts parse).

## Daemon incidents after r4 (21:40 to 22:20)

- 21:40 to 22:10: the r4 daemon grew to 2.9 GB peak (cgroup 2.68 GB at MemoryHigh 2560M),
  stopped completing jobs at 22:03 and stopped answering HTTP. At 21:55 it had held 1.06 GB.
  The new history_verify job ran 21:57 to 21:59 but is not the cause: a bounded read-only
  verify of 100 segments peaked at 41 MB. The process is not inspectable from the user
  account (ambient capabilities), so the allocation is not yet attributed. Restarted at
  22:10:44 from outside systemd (NRestarts 0).
- 22:10 to 22:19: memory stayed near 500 MB, but the installed Sep-17 reviver restarted the
  daemon at 22:19:24 for "active but stalled for 148s" during its cold start. VM load was
  about 20 on 4 vCPUs (Go race-test builds, gopls, three Claude sessions, test containers);
  CPU pressure 37% and I/O pressure 34% over five minutes.
- A recorder samples the service's memory and job completions every 20 s until about 22:51:
  scratchpad `memtrace.log` of this session. Owner action #5 (re-register the reviver with
  StartGrace) stops the cold-start restarts.
