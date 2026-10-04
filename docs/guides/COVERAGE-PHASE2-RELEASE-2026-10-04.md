# Coverage, phase 2: release record (2026-10-04)

Stage: `~/.cache/jarvis-release-staging/20261003T223154Z-on-5343e88b5230`
Base: `sha256:5343e88b5230…` (live release `20261003T214117Z-5343e88b5230`)
Baseline: `docs/guides/baselines/coverage-phase2-baseline-2026-10-04.json`

## What the release contains

The live sealed release plus fourteen reviewed files: the rule table and the two event
detectors, the coverage map and gap list, five collectors that gained a parameter for
already-collected evidence (`firewall`, `bruteforce`, `implant`, `evasion`,
`toolchain/packaging`), the coverage page script, two test files and the plan.

Not included: the native-host seam, `jarvis/core/assurance.py`, and every other undeployed
change. T1620 stays claimed because its classifier module is not in the live release.

## Expected changes

1. **Coverage map** after a forced `attackmap` run: 72 to 90 validated, 33 to 24 claimed, 81 to 72
   blind of 186, no `regressed`. Newly validated: T1056, T1068, T1102, T1110, T1133, T1185,
   T1187, T1190, T1195, T1200, T1203, T1204, T1542 stays, T1556, T1557, T1568, T1649, T1689.
   T1078 stays claimed with its reason. T1497 and T1571 go from claimed to blind.
2. **`firewall`, `bruteforce`, `implant`, `evasion`, `toolchain`**: identical findings. The only
   code change in each is a parameter that is unused in normal runs.
3. **`sysmon`, `sysmon_linux`**: no finding disappears. The two discovery-burst findings from the
   positive controls remain until they age out. New findings only from the new rules, for real
   events; replay of 687,887 retained events predicts none.
4. **`gaps`**: entries for T1187, T1568, T1203, T1190, T1068, T1649 and their sub-techniques go;
   entries for T1497 and T1571 appear. Nothing else changes.
5. **`attackmap` snapshot**: no `no longer lists` finding (the T1562 mapping is removed).
6. **Score**: unchanged by this release.

Roll back if the service does not come back `ready`, if any touched collector errors, goes
stale or changes its findings outside the items above, or if the map reports a regression.

## Outcome (measured 2026-10-04, 01:42 to 01:50 EEST)

Deployed by the owner as release `20261003T224213Z-e42b88bd6f8c`.

| Check | Baseline | After deploy |
|---|---|---|
| Service | healthy, ready | active, 0 restarts, healthy, ready, no traceback |
| Security score | 58 | 58 |
| Coverage map | 72 validated, 33 claimed, 81 blind of 186 | 89 validated, 25 claimed, 72 blind, 0 regressed |
| `firewall`, `bruteforce`, `implant`, `evasion`, `toolchain`, `sysmon` | 3, 1, 2, 1, 6, 6 findings | identical |
| `sysmon_linux` | 15 | 15: one high aged out of its 24 h window (24.5 h old), one fresh medium for a real raw-access event |
| `gaps` | 195 | 207 |

The map reads 89 validated, not the 90 written above: the expectation counted T1620, whose probe
is not registered in this release. Seventeen techniques moved to validated, T1078 stayed claimed,
T1497 and T1571 went from claimed to blind, nothing left validated.

One expectation was wrong. Removing the retired T1562 mapping made the gap list report T1562 and
seven of its sub-techniques as uncovered, because intelligence documents still cite the old id.
Eight coverage-gap findings appeared that item 4 did not predict. `gaps` is unscored, so the
score did not move, but the list was less accurate. Fixed in the next release: a retired id is
treated as covered through its mapped successors (`gaps.SUPERSEDED`), and a test keeps the gap
list and the coverage map in step.

Live positive control: seven read-only discovery commands under one `cmd.exe` were reported by
the Windows detector as one medium `discovery burst under cmd.exe` on its next run.
