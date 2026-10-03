# Release handoff: audio (with beep detection), containers, .NET posture

The live release (387802244eed) has no `audio`, `containers` or `dotnet` collectors, so
`/api/run` for them returns `queued: false` and the coverage audit reports them as never run.
This stage adds them to the live sealed release and nothing else.

Stage: `/home/chris/.cache/jarvis-release-staging/20261001-audio-containers-dotnet-r2`
Overlay (source of the reviewed files): `/home/chris/.cache/jarvis-release-overlay-audio-20261001`
Baseline: `docs/guides/baselines/audio-containers-dotnet-baseline-2026-10-01.json`

Only 20 files differ from the live release: the three collectors, two PowerShell helpers, their
tests, wiring (jobs, schedule, CLI, score areas, assurance) and two review documents. The
checkout's unrelated edits (supervisor renames, `memory_advice`, `procs --live`, cursor-speed and
execution-intelligence assurance text) are deliberately **not** staged.

## Invariants

- **Privacy.** The audio helper opens no stream and reads no buffer. The only signal-level input
  is the scalar `IAudioMeterInformation` peak (0..1). Tone, content and audibility are never seen.
- **Bounded.** 8 s burst, 20 ms steps, at most 16 endpoints, 32 events, 45 s process timeout.
- **Honest coverage.** The inventory finding states samples, endpoints, elapsed ms and the share of
  the 300 s interval (about 2.7%). Absence of a beep finding is never evidence that none played.
- **Fail closed.** A snapshot without a valid `burst`, or with an event for an unknown endpoint,
  an out-of-range peak or duration, or an identity claim without a PID and start time, is not a clean
  snapshot and the previous evidence is kept. A meter failure keeps the route evidence but marks the
  collection incomplete with a medium visibility finding.
- **No false classification.** Sound already playing at either window edge, or longer than 1.5 s, is
  counted as sustained and never reported as a beep. A shared or system-sounds session is never
  reported as a process.

## Why this design

Alternatives: (1) loopback capture and spectral analysis, which would identify tones but reads
audio content and is refused on privacy grounds; (2) a resident sampler in the native sensor, which
would cover the whole interval but adds a service, an install and an admin step; (3) a bounded burst
in the existing five-minute job, chosen as the simplest design that adds beep visibility without new
privilege. Reconsider (2) if beeps outside the burst must be caught reliably.

## Measured before the release (2026-10-01, from the checkout through the Windows bridge)

- Idle pass: 273 peak samples on 1 endpoint over 8022 ms, no beep reported.
- One deliberate 250 ms test tone during a pass: 1 beep-like burst of 115 ms, peak 0.500, attributed
  to the system-sounds session, not to a process.
- `jarvis containers`: 11 of 11 inspected. `jarvis dotnet`: no CLR hijack variables, Defender's AMSI
  provider present.
- Exact-stage full suite: 1,750 tests passed (500 s). The first stage run found 4 errors from a missing `cmd_audio` import in the staged `parser.py`; fixed and restaged as `-r2`. Jev advisory review was not run for this release; the deterministic gates above stand alone.

## Not covered

Pre-OS events (BIOS/POST beep codes, boot-menu beeps, firmware or bootkit tampering) are invisible
to this collector: they happen before Windows and WSL load. That needs a separate boot-integrity
collector built on measured-boot evidence.

## Expected changes after the switch

- `audio`, `containers` and `dotnet` produce their first snapshots. `audio` and `containers` are
  unscored; `dotnet` joins "Persistence & access".
- Expected findings: audio inventory (low, with the sampler line), container inventory complete
  (11/11, no elevated host access), and `dotnet` clean.
- The coverage CRIT findings about these three collectors disappear. This is explained by the
  collectors now existing, not by lost visibility.
- Legacy assurance counts move by documented accounting (partial 16 to 18, unverified 2 to 3).

## Switch

```bash
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
  --source /home/chris/.cache/jarvis-release-staging/20261001-audio-containers-dotnet-r2 \
  --checkout /home/chris/jarvis \
  --expect-base sha256:387802244eedca0a26fd2157386af587a3fcea739f674b16268a8b55ba5b3d17 \
  --skip-tests
```

Rollback: `sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --rollback`.
Acceptance follows [the deploy guide](DEPLOY.md): release identity, active with 0 restarts, health
ready, fresh snapshots for the three jobs after the restart, findings compared with the baseline,
and the score read back over several collector intervals.

## Outcome (2026-10-02, after the owner's switch)

- Live release `99173c01c1da`, `jarvis.service` active since 00:06:33 EEST with 0 restarts. `/api/health` reported healthy, ready and protection_healthy. No traceback or error lines in the journal over the 20 minutes after the restart.
- `/api/run` for `audio`, `containers` and `dotnet` returned `queued: true` (it was `false` before the release), and each produced a fresh snapshot within seconds.
- `audio`: inventory with 46 endpoints and 1 active render session, plus a "continuous audio output" note because sound was already playing at the window edge. That is by design, not a beep. No beep-like burst was seen, as expected for a quiet moment.
- `containers`: 11 of 11 inspected, none elevated. `dotnet`: no CLR hijack variables, Defender's AMSI provider present.
- Coverage: the three CRIT "never produced a result" findings are gone, explained by the collectors now existing. The score read 54% before and 58% afterwards, with coverage at 100%.
- Still to do per the deploy guide: read the score back over several collector intervals, and check that the next scheduled `audio` runs keep `collection` complete.
