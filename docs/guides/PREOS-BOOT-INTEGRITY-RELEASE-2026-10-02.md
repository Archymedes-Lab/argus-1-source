# Release handoff: pre-OS boot integrity (`preos`)

Adds one collector that compares what ran before Windows with an owner-pinned baseline.

Stage: `/home/chris/.cache/jarvis-release-staging/20261002-preos-boot-integrity`
Overlay: `/home/chris/.cache/jarvis-release-overlay-preos-20261002`
Base: live release `99173c01c1da`. 16 files differ: 5 added, 11 changed. Unrelated checkout edits are not staged.

## What it reads (unelevated, read-only)

- The TPM measured-boot logs Windows keeps per boot (`C:\Windows\Logs\MeasuredBoot`), read as local files and replayed: firmware code and settings, option ROM code, boot applications, Secure Boot variables and signing authorities.
- Windows' own pre-attestation verdict (`PcrsMatchTcgLog`), required before a log is trusted.
- One bounded PowerShell probe (about 3 s): firmware version, Secure Boot and revocation-list servicing state, TPM health, virtualization-based security, and boot-manager events (boot options, boot-menu wait time, boot-entry count, unclean shutdowns, hardware errors).

## Invariants

- **Authority.** Nothing is changed. The baseline never advances by itself; `jarvis preos --accept-baseline` is the only way, and it is an owner action.
- **Evidence continuity.** On first run the oldest retained cold boot is pinned, so every retained boot is compared immediately. A drift stays reported until accepted.
- **Fail closed.** An unparsed log, no log for the current boot, a missing attestation verdict or a failed probe gives a noncomplete receipt and a visibility finding, never a clean result. A failed probe on first run pins no baseline.
- **Bounded.** 64 logs, 4 MiB per log, 20,000 events per log, 40 events per event id, 90 s probe timeout, 30-minute cadence.
- **Privacy.** Digests, counters, versions and boot option flags only.
- **No overclaim.** A drift is a difference to explain. Firmware and Windows updates change these values legitimately, and the findings say so.

## Why this design

Alternatives were an elevated collector (UEFI variables, boot configuration, EFI partition) and a kernel or firmware agent. The unelevated replay needs no new privilege, costs about 3 s per half hour, and already covers the measured chain. Reconsider the elevated read if a boot-order or EFI-partition change must be seen directly; that fits the existing elevated broker.

## Measured 2026-10-02 from the checkout

- 26 retained logs (boots 130-140) parsed; 11 cold boots identical in PCR 0-7; no option ROM code; 6 boot applications per boot.
- Windows attestation verdict: Attestable, PCRs match the log.
- Findings: Secure Boot revocation list update error `0x80071149` (medium); 27 unclean-shutdown records against 19 cold boots (low).
- Checkout suite 1,967 passed. Exact-stage suite 1,771 passed. Ruff clean on the new files.
- Jev advisory: called (Choice, Noul, Choice over an engineering summary); unavailable, `HTTPError`. It had no effect on the work.

## Not covered

Firmware that falsifies its own measurements; a boot of other media (seen only as a counter gap or an unclean shutdown); firmware setup and boot-device menus; the POST beep itself; UEFI variable contents, boot order and the EFI partition. Drift detection has no positive control on real hardware, only synthetic logs. Findings are unscored until soaked.

## Expected changes after the switch

- A new `preos` job with a fresh snapshot: the two findings above plus the inventory line.
- `preos` is unscored, so the score should not move because of it.
- ATT&CK map: T1542 Pre-OS Boot moves from blind to claimed (not validated).
- Assurance counts: partial 18 to 19 by documented accounting.

## Switch

```bash
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
  --source /home/chris/.cache/jarvis-release-staging/20261002-preos-boot-integrity \
  --checkout /home/chris/jarvis \
  --expect-base sha256:99173c01c1dabb98e09225eba0bc3c0672e7aeb3c7eff2ea3cb98f8b7aea3679 \
  --skip-tests
```

Rollback: `sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --rollback`.
Acceptance follows [the deploy guide](DEPLOY.md).

## Superseding stage: pre-OS boot integrity plus the coverage view

A later stage contains everything above plus the `/coverage` page. Deploy this one instead; the
two stages share a base, so only one of them can be switched in.

Stage: `/home/chris/.cache/jarvis-release-staging/20261002-preos-and-coverage-view`
Overlay: `/home/chris/.cache/jarvis-release-overlay-preos-coverage-20261002`

Added for the view: `jarvis/service/coveragemap.py`, `jarvis/web/static/coverage.html`,
`jarvis/web/static/coverage.js`, `jarvis/web/static/vendor/three.module.min.js` (three.js 0.170.0,
MIT, sha256 `08fd7545…c39e7`, pinned in `server.py`), `tests/test_coverageview.py`; `server.py`
gains three routes and `/api/coverage`.

Invariants of the view: read-only; no inline or third-party script (`script-src 'self'`); the
vendored engine is refused if it no longer matches its pin; levels, collector states and run
times are the stored ones, with a missing snapshot shown as missing; a failed fetch shows a
"not live" banner.

Exact-stage suite: 1,780 tests, 1 failure, `test_server.SchedulerLaneTests.
test_fast_lane_stays_fresh_while_the_main_lane_is_busy`. It is a timing test with a 3 s deadline
that also fails about 1 run in 6 on the unmodified live release (`scheduler.py` is identical in
the stage), so it is a flake that predates this change, not a regression. It was not weakened.

```bash
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
  --source /home/chris/.cache/jarvis-release-staging/20261002-preos-and-coverage-view \
  --checkout /home/chris/jarvis \
  --expect-base sha256:99173c01c1dabb98e09225eba0bc3c0672e7aeb3c7eff2ea3cb98f8b7aea3679 \
  --skip-tests
```
