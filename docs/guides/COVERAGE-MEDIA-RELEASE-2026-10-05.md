# Removable media and the blind-side round: release record (2026-10-05)

Stage: `~/.cache/jarvis-release-staging/20261005T145150Z-on-677b2a83b901`
Base: live release `20261004T200640Z-677b2a83b901` (`sha256:677b2a83b901…`).
Baseline: `docs/guides/baselines/coverage-media-baseline-2026-10-05.json`
(taken 17:34 EEST: healthy, ready, protection healthy; score 53; map 91 validated / 31 claimed /
64 blind of 186).

This release carries two rounds. The blind-side round of 2026-10-04 (commit `0e504f1`) was
staged as `20261004T161550Z-on-db35acdbd196` and never deployed; the world-watch release
replaced its base. That stage can no longer be deployed (`--expect-base` refuses it) and is
superseded by this one.

## What the release contains

Eight changed files. The live copy of each is identical to commit `5945293`, the last coverage
release, so nothing from another line of work is carried or dropped.

- `jarvis/collectors/telemetry/techniques.py`: the blind-side rules, and the drive rules
  (`drive_letter`, `volume_kind`, `copy_drives`, `off_disk`).
- `jarvis/collectors/telemetry/sysmon.py`: network events through the unusual-port rule; process
  starts through the drive rules; the drive inventory (`_read_volumes`, kept in
  `windows_volumes_v1`), read only when a process names a drive not known to be internal.
- `jarvis/collectors/network/sniffing.py`: a data seam for the raw-socket finding.
- `jarvis/service/attackmap.py`: probes and held reasons for both rounds.
- `jarvis/intel/gaps.py`: T1205, T1571, T1091, T1025 and T1052 mapped.
- `scripts/dev/replay_techniques.py`, `tests/test_techniques.py`, `tests/test_coverageview.py`.

Not in the release: `jarvis/core/assurance.py`, the advisory scripts, the native-hosts work.

## Checked before staging

- Full suite in the checkout: 2,163 tests, OK. Lint clean on the changed files.
- In the staged tree: `tests.test_techniques` and `tests.test_coverageview` (85 tests) OK; all
  142 probes fire; both false-positive guards hold.
- Projection in the staged tree against a copy of the live catalogue and snapshots: 100 / 43 / 43,
  and no technique moves other than the 21 listed below.
- Replay of 842,563 retained Windows events: the drive rules report nothing.
- The real inventory read, once, through the collector's function: `C: Fixed, NVMe`, 3 s.

## Expected on the live system

1. Map: **100 validated, 43 claimed, 43 blind, 0 regressed of 186**.
   Blind to validated: T1005, T1020, T1029, T1039, T1095, T1119, T1132, T1499, T1573.
   Blind to claimed: T1025, T1030, T1052, T1072, T1074, T1080, T1091, T1205, T1491, T1497,
   T1571, T1678. No other technique changes level.
2. `gaps`: 192 rows at baseline. These leave: T1095, T1132, T1132.002, T1205, T1497 and its four
   sub-techniques, T1571, T1573, T1573.001 (12 rows). Nothing is added by this release; the
   count also moves by itself as intelligence arrives.
3. `sysmon`: the same findings as the baseline (2 medium: "powershell.exe queried LSASS",
   "Sysmon lost events while starting at boot"; 4 low). No finding ending in (T1091), (T1025),
   (T1052) or (T1571), and no "drive types could not be read". After its first run the store
   has `windows_volumes_v1` naming `C` as `Fixed`, `NVMe`; that one run takes about 3 s longer.
4. `sysmon_linux`: unchanged apart from real events (2 high, 21 medium, 1 low at baseline).
5. `sniffing`: unchanged (2 ok).
6. Security score: unchanged (53) apart from findings already moving by themselves. Twelve
   techniques leave "blind" without becoming "validated"; that is the intended reading.

Roll back if the service does not come back `ready`, if anything reads `regressed`, if a
technique outside item 1 changes level, or if `sysmon` reports a drive finding or a high or
critical finding the baseline does not have and that is not a real event.

## Deploy

```
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --source /home/chris/.cache/jarvis-release-staging/20261005T145150Z-on-677b2a83b901 --checkout /home/chris/jarvis --expect-base sha256:677b2a83b901b3d93174d21ed4139fed589158e2bb54bc632a7d32fc429ce438 --skip-tests
```

## Positive control, when convenient

Attach a USB stick and run any program from it, or `robocopy` a folder to it. Within one
Sysmon run (ten minutes) the Sysmon findings should show "program run from a removable drive
(T1091)" (medium) or "files copied to a removable drive (T1052)" (low). The finding stays for a
day and lowers the score slightly for that day. Until that has been seen, the three techniques
stay claimed.

## Outcome

Not deployed yet.
