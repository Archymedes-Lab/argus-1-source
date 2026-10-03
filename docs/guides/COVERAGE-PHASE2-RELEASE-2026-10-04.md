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

## Outcome

To be filled in from the live readback.
