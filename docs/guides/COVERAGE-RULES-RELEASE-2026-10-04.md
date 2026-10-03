# Coverage rules and live coverage view: release record (2026-10-04)

Stage: `~/.cache/jarvis-release-staging/20261003T213600Z-on-83060e4ed3b4`
Base: `sha256:83060e4ed3b4…` (live release `20261002T093627Z-83060e4ed3b4`)
Checkout commit: see `git log` on branch `native-hosts`.
Baseline: `docs/guides/baselines/coverage-rules-baseline-2026-10-04.json`

## What the release contains

The live sealed release plus twelve reviewed files:

- `jarvis/collectors/telemetry/techniques.py` (new), `sysmon.py`, `sysmon_linux/rules.py`:
  process-creation technique rules inside the two event detectors.
- `jarvis/service/attackmap.py`, `jarvis/intel/gaps.py`, `jarvis/intel/feeds.py`: probes built
  from the rule table, probes for detectors that were unmapped, retired techniques not counted.
- `jarvis/service/coveragemap.py`, `jarvis/web/static/coverage.html`, `coverage.js`: collector
  uptime on the /coverage view (built earlier, never deployed) and technique levels that follow
  the collectors' state now.
- `tests/test_techniques.py`, `tests/test_coverageview.py`, `docs/architecture/COVERAGE-PLAN.md`.

Deliberately not included: the native-host seam, `jarvis/core/assurance.py` (its checkout copy
describes features this release does not carry), and every other undeployed change.
The in-memory image probe (T1620) is absent here because its classifier module is not in the
live release; T1620 stays claimed.

## Expected changes, to compare the readback against

1. **Coverage map** after a forced `attackmap` run: validated rises from 11 to about 72, claimed
   to about 33, no `regressed`. Total stays 186 until the `feeds` job reloads the catalogue
   (monthly), then drops to 176. Each new validated technique names `sysmon` or `sysmon_linux`.
2. **`sysmon` and `sysmon_linux` snapshots**: no finding disappears. New findings are possible
   only in category `technique` (Windows) or titles ending `(T….)` (Linux), and only for real
   process starts since the last cursor. Replay of retained history predicts none to a handful.
3. **`gaps`**: fewer "nothing checks this technique" entries, only for technique ids now in the
   rule table. This is the one place findings may legitimately disappear.
4. **Score**: no change expected from this release by itself. Any gain must trace to item 3;
   a gain with coverage lost is a regression.
5. **/coverage**: `uptime` present in `/api/coverage`; technique rows carry levels consistent
   with the collectors' current state; totals equal the count of tiles per level.

Roll back if the service does not come back `ready`, if `sysmon` or `sysmon_linux` errors or goes
stale, if any existing finding disappears outside item 3, or if the map reports a regression.

## Outcome

To be filled in from the live readback.
