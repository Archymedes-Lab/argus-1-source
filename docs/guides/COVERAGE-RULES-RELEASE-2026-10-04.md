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

## Outcome (measured 2026-10-04, 00:41 to 00:50 EEST)

Deployed by the owner as release `20261003T214117Z-5343e88b5230` (`sha256:5343e88b5230…`).

| Check | Baseline (00:37) | After deploy |
|---|---|---|
| Service | active, healthy, ready | active, 0 restarts, healthy, ready, protection healthy; no traceback in the journal |
| Security score | 58 | 58, every area unchanged |
| Coverage map | 11 validated, 34 claimed, 141 blind of 186 | 72 validated, 33 claimed, 81 blind of 186, 0 regressed |
| `sysmon` findings | 5 | 5, none new, none gone, no error |
| `sysmon_linux` findings | 16 | 16, none new, none gone, no error |
| `gaps` findings | 222 | 195: 27 gone, every one a technique id now in the rule table |
| Collectors current | 50 of 50 | 50 of 50 |

Level moves: 39 blind to validated, 22 claimed to validated, 21 blind to claimed. Nothing left
validated. The total stays 186 until the `feeds` job reloads the catalogue.

Live positive control (00:49): seven read-only discovery commands were run from one shell. The
next `sysmon_linux` run reported one medium finding, `discovery burst under bash`, naming exactly
those seven techniques. This is the first rule from the table seen firing on a real event. No
Windows rule has fired on a live event yet.

The /coverage page was rendered in headless Edge in both readings and compared with
`/api/coverage`: 39%, 72 of 186, 72 / 33 / 81, the thirteen per-tactic counts, score 58% with its
age, and 50 of 50 collectors current all matched.

Collector uptime read 31.3% for the last 24 h. That is real, not a display fault: the `scan`
collector has no receipts at all for about 18 consecutive hours of that window, then resumes.
The WSL guest was not running the collectors for that time.

Known cosmetic fault: two tactic labels on the shell overlap at some camera angles.
