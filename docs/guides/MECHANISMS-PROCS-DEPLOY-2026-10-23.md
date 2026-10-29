# Deploying stage mechanisms-procs-20261023-r1

This release adds two things:

- **Mechanism registry.** Every collector is declared once in `jarvis/core/mechanisms.py`, and the
  old per-job tables are now derived from it (see `docs/architecture/MECHANISMS.md`).
- **Process map.** The live `/procs` view of every process on Windows and in the WSL guest.

It is stacked on the other session's stage `closure-20261023-r6-sound-fwaudit` (storage governor,
sound listener and firmware audit). **Deploy r6 first.** This stage's `--expect-base` is r6's
release id, so it refuses to deploy until r6 is live.

## Order and commands

1. Deploy r6 and verify it according to its own notes. Use `--checkout /home/chris/jarvis`, not
   the overlay path in r6's stage record (see DEPLOY.md, "Always keep `--checkout`").

   ```
   sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
     --source /home/chris/.cache/jarvis-release-staging/closure-20261023-r6-sound-fwaudit \
     --checkout /home/chris/jarvis \
     --expect-base sha256:414291d535bb44aedfa16d063d39c05b4362d6a467a4bfa78c840357129724f4 \
     --skip-tests
   ```

   Afterwards, `readlink -f /opt/jarvis/current` should end in `-d13dc7206da4`. That is the id this
   stage predicted from r6's files, using the deploy's own packing rules. The same method
   reproduced the current live id exactly.

2. Deploy this stage:

   ```
   sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
     --source /home/chris/.cache/jarvis-release-staging/mechanisms-procs-20261023-r1 \
     --checkout /home/chris/jarvis \
     --expect-base sha256:d13dc7206da480531ba34d7bd87040a6a165c4fc1f1ef0621a154567890c7e0c \
     --skip-tests
   ```

   Expected new release id: `sha256:0534b538cd16…`, so the directory ends in `-0534b538cd16`.

Rollback for either step: `sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --rollback`.

## What changes, finding by finding

The baseline was taken 2026-10-23 16:30 EEST on release `414291d535bb`: healthy, ready,
protection healthy, assurance 12, security score 51, 52 collectors current and 1 failing
(memscan, unelevated). It is stored in `docs/guides/baselines/mechanisms-procs-baseline-2026-10-23.json`.
r6 was deployed at 16:34 and verified by 16:47: all 55 collectors refreshed, healthy, 0 restarts.
At that point `audio`, `fwaudit` and `memscan` were failing, each for an owner action listed in r6's guide.
The file's `r6_live` section is the baseline this stage is compared against.

Expected, measured on the stage against r6 (every table compared value for value):

- **Schedule and scoring: no change.** Job order, intervals and labels, lanes, governed set, score
  areas and their order, the unscored list, dependency roots, budgets, CLI commands and runners
  are identical to r6, with one exception. No finding should appear, disappear or change
  severity because of this release.
- **The one exception: `fwaudit` run timeout drops from 180 s to 60 s.** Its owner declared it:
  the job only reads the broker's output file, with a measured cost of about 0.1 s.
- **New route `/procs`** and its stream `/api/procs/stream`, plus a "Processes ↗" link in the
  dashboard nav. Nothing runs until the page is opened. While it is open, one PowerShell helper
  runs (about 2.6% of one core) and stops 15 s after the page closes.
- **Assurance register:** one new `unverified` entry (`live_process_view`). JARVIS's own assurance
  score may fall by about a point. That is a more honest register, not a regression.

## Verify on real results

1. `readlink -f /opt/jarvis/current` ends in `-0534b538cd16`. Run
   `systemctl show jarvis.service -p ActiveState -p NRestarts`, and check that `/api/health`
   reports healthy, ready and protection_healthy.
2. `journalctl -u jarvis.service --since "<deploy time>"` shows no tracebacks.
3. Every collector reaches a fresh snapshot after the restart. Compare `/api/coverage` with the
   baseline file, job by job: same states (memscan stays failing until the broker is
   reinstalled), and no finding missing without an explanation.
4. Open `http://localhost:8787/procs`. Both domains should read "live · <1 s", with Windows
   showing "Sysmon starts subscribed". Close the tab, wait 20 s, then run the check below in
   Windows PowerShell. It must print 0.

   ```
   @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
     ? { $_.ProcessId -ne $PID -and $_.CommandLine -like '*JarvisProcFeed*' }).Count
   ```

5. Read the score back over several collector intervals.

Roll back if any collector this release touched goes stale or errors, if findings move without
the explanation above, or if the helper outlives its page.

## Addendum 2026-10-24: the change lens (checkout only, not in this stage)

Owner request: make anything that changes visible in the 3D map. Built in the checkout on top of
this stage's process view; it ships in the release after `mechanisms-procs-20261023-r1`.

| File | What |
| --- | --- |
| `jarvis/web/procbaseline.py` | Per-host name baseline from the scan collector's `procs` table: first seen, last seen, sightings, approval. Names only; cached 300 s, one rebuild at a time; unreadable is reported, never "all new". |
| `jarvis/web/server.py` | `GET /api/procs/baseline` (same-origin) and the `/static/procs-model.js` asset. |
| `jarvis/web/static/procs-model.js` | Pure lens rules: unknown, new, recent, known, approved; missing and back; which events reach the change list. |
| `jarvis/web/static/procs.js`, `procs.html` | Never-seen processes red, enlarged, labelled and pulsing; new-today amber; "Show only what changed" dims the rest; a Changes list; watched processes flagged missing and back; baseline line on the hover card. |
| `tests/test_procbaseline.py` | Ten checks: grouping, no path, command line or user leaks, unreadable baseline, cache, route, and the page rules run in Node. |

Normalisation: names are lower-cased and a trailing `(digits)` becomes `(#)`, because WSL's
`Relay(<pid>)` processes would otherwise each read as new (4 false markers before, 0 after; the Linux
baseline folds from 873 to 435 names). Linux names are the kernel's 15-character `comm`.

Verified 2026-10-24 on a scratch server with the real feed: 297 to 308 Windows and 106 to 119 Linux
processes; a never-seen probe (`jarvis-lens-probe`, a renamed `sleep`) shown 1.6 s after it started
and its exit 1.2 s after it ended. The missing rule was tested by unit tests only (it watches
Defender, Sysmon, the JARVIS sensor and core Windows processes, which are not stopped for a test).

Limits: a renamed binary that takes a familiar name reads as known; missing detection runs only while
the page is open. Jev (advisory): name lens useful 0.87, missing rule balance 0.64, next layer image
identity (path and signer or hash against the baseline, server side) at 1.0.
