# Coverage depth, three more techniques, and the extension-baseline fix: release record (2026-10-04)

Stage: `~/.cache/jarvis-release-staging/20261004T143600Z-on-4cc6288f6dd0`
Base: live release `20261004T002941Z-4cc6288f6dd0` (`sha256:4cc6288f6dd0…`).
Commit: `5945293`. Baseline: `docs/guides/baselines/coverage-depth-baseline-2026-10-04.json`
(taken 17:44 EEST: healthy, score 57, map 89 validated / 25 claimed / 72 blind of 186).

## What the release contains

Twelve changed files and one added, all identical to the live release before this round:

- `jarvis/collectors/telemetry/techniques.py`: rules for T1566, T1189, T1563, T1484, T1207 and
  T1606; six registry-write rules (`REG_RULES`); `ways()`; a parent-rule finding now quotes the
  command instead of one letter.
- `jarvis/collectors/telemetry/sysmon.py`: registry events (Sysmon 13) are run through the
  registry rules, and a real run records which key families the machine logs
  (`sysmon_registry_recorded_v1`).
- `jarvis/collectors/host/inputwatch/analysis.py`: the injected-input rule moved into
  `injected_findings(store, since)`. Same queries, same findings.
- `jarvis/service/attackmap.py`: probes for T1674 and T1495; every rule for a technique is
  replayed; a technique with two kinds of proof needs both; `ways` on each row; T1550, T1207,
  T1606, T1189, T1563 and T1484 held at claimed with the reason.
- `jarvis/service/coveragemap.py`, `jarvis/web/static/coverage.js`: the count of proven
  procedures, shown only in a technique's detail text.
- `jarvis/intel/gaps.py`: T1674 and T1495 mapped.
- `jarvis/collectors/host/toolchain/common.py`, `extensions.py`: the baseline fix below.
- `tests/test_techniques.py`, `tests/test_coverageview.py`, `tests/test_toolchain.py`,
  `scripts/dev/replay_techniques.py`.

Not in the release: `jarvis/core/assurance.py`, the native-hosts work, and the world-watch work
another session has in progress in the checkout.

## The extension-baseline bug

Measured 2026-10-04: the security score fell from 56 to 46 because 23 editor extensions were
reported as new (high). Their directories are dated February to May. After standby the Windows
drive was not answering for one run; the inventory recorded the smaller set as its baseline and
reported the rest as removed (low), then reported all of them as new on the next run. The false
findings cleared by themselves an hour later (score 57), and would return after any standby.

Invariants the fix keeps, each with a test in `tests/test_toolchain.py`:

1. A source that could not be read is not an uninstall: what was recorded under it is kept.
2. Its return is not an install: nothing is reported as new on its account.
3. A real install or version change during the outage is still reported when it returns.
4. A real removal from a readable directory is still reported.
5. The gap is stated, never silent: low for one or two runs, medium from the third in a row.
6. A first run that cannot read everything records no baseline.

Designs compared: keep what was recorded (chosen); skip the whole comparison on an incomplete
run (loses the readable directories too); tombstones with a grace period (more state, and a
real reinstall inside the window would be hidden); unchanged. Jev put 1.0 on the chosen one,
0.32 on "an install during the outage could go unreported" (invariant 3 tests exactly that; what
stays unseen is something installed and removed again while the drive was dark), and was split
0.47 low / 0.51 medium on severity, which is why it escalates. It would be reconsidered if a
directory can fail to list while answering `stat` without an error.

Checked on the real directories with a scratch store: baseline, clean second run, a simulated
dark run reporting "23 not re-read", and a clean run after it.

## Validation before staging

- Full suite inside the staged tree: 1,868 tests, OK.
- 121 probes fire inside the staged tree, both precision probes pass, 109 look-alikes are quiet.
- 752,569 retained Windows events replayed through `sysmon.audit`: the new rules report nothing
  after two false positives (Defender's service path, an installer's RunOnce) were removed.
- Projection from a copy of live data, in the staged tree: 91 validated, 31 claimed, 64 blind.
- Jev was asked three times; each answer and what it changed is in the plan's status section.

## Expected changes

1. Map: **91 validated, 31 claimed, 64 blind, 0 regressed of 186**. T1674, T1495 and T1566 become
   validated. T1189, T1563, T1484, T1207 and T1606 go from blind to claimed. T1550 goes from
   validated to claimed. No other technique changes level.
2. `/api/coverage` rows carry `ways`; the detail text of a validated technique says how many
   ways it is proven. The headline and the panes look the same.
3. `gaps` (193 findings at baseline) loses the entries that name the newly mapped techniques.
   Measured in the current list: T1207, T1484, T1484.002 and T1606, so 189 is expected. The
   other new techniques are not in the list today. Nothing is added.
4. `sysmon`: no new finding expected from this machine's ordinary activity. After the first run
   that sees a firewall-rule or service registry write, the meta key
   `sysmon_registry_recorded_v1` exists and names those key families.
5. `toolchain`: unchanged on a healthy run (1 medium, 5 low, ok). After the next standby there is
   at most one low "extension inventory incomplete" line and no "new extension" burst.
6. `input`, `preos` and every other collector: unchanged. Security score: unchanged (57), apart
   from findings that are already moving by themselves.

Roll back if the service does not come back `ready`, if any technique outside item 1 changes
level, if anything reads `regressed`, or if `sysmon` or `toolchain` report a high or critical
finding that the baseline does not have and that is not a real event.

## Deploy

```
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --source /home/chris/.cache/jarvis-release-staging/20261004T143600Z-on-4cc6288f6dd0 --checkout /home/chris/jarvis --expect-base sha256:4cc6288f6dd0e9551e730b8075c3943c908d06341b235e5112304db32e1f2029 --skip-tests
```

## Outcome

To be filled in from the live readback.
