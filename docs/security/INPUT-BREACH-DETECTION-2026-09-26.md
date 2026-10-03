# Input monitor and breach-detection design review — 2026-09-26

## Measured state

At the live readback around 15:00 EEST, `input_hook` and `input` had fresh,
error-free receipts. The Windows input task was running, the helper and desktop
were both in session 4, the restart failure count was zero, and aggregate
heartbeat counters advanced from 1,682 to 1,684 real keys with no injected
keys in that interval. This proves the hook observed physical input during
that interval. It does not prove uninterrupted collection or that every way
to read input is visible.

One high injected-key finding came from 2026-09-25 16:48:39 in Windows
Terminal: virtual key 0, scan 0, injection flag `0x10`. It predates the
owner's current period keypress and has no identified sender. Keep the raw
event and the high finding until independently explained. The period keypress
itself is ordinary physical activity, not evidence of a breach.

Defender reported real-time, behavior, and on-access protection enabled. Its
listed threats were inactive, but that is not a clean-host verdict. JARVIS
had no current critical finding; the high `staging` findings included current
hash matches for the reviewed isolated-sensor scripts. The live trace began
well after boot, leaving early hook registrations unseen. Sysmon also reports
a prior boot ProcessCreate loss. These are material coverage limits.

## Invariants

- Keep evidence, sensor identity, sequence, cursor and gap records through a
  crash, suspend, restart, update, and rollback. Never turn absence of an event
  into a clean verdict.
- Require fresh per-channel receipts and a demonstrated observation path before
  calling a sensor functional. A process heartbeat alone proves liveness only.
- Retain only bounded metadata and aggregate physical-input counts; do not
  store ordinary typed characters, key sequences, passwords, or private text.
- Keep CPU, memory, spool capacity, retry and restart budgets bounded. No
  automated response gains authority from an input finding or model output.
- A replacement must preserve the old executable, service definitions, spool,
  acknowledgements, ACLs, and a tested rollback path.

## Designs compared

| Design | Coverage and failure behavior | Cost and decision |
| --- | --- | --- |
| Restart the existing desktop hook more often | Recovers crashes, but a live message loop can retain its heartbeat after Windows silently removes a low-level hook; polling and early-boot watchers remain invisible | Cheap interim layer only |
| Periodic antivirus or filesystem scans | Finds some known artifacts, but cannot establish input-hook continuity or catch every live action | Keep as an independent sensor, not a replacement |
| Independent native Windows channels plus cross-sensor reconciliation | Separates input, Sysmon, Defender, task, process and network failures; per-channel sequence and freshness receipts expose each blind spot | Selected design; requires staged installation and live validation |

Microsoft documents that Windows may silently remove a timed-out low-level
keyboard hook without telling its application, and recommends raw input for
many monitoring cases. Thus the current 10-second pulse cannot by itself
attest hook installation. The proposed input channel should compare
contentless counts from two independent paths during real activity: the
existing injection-flag hook and a raw-input counter in the interactive
session. Agreement establishes activity for that interval only. Disagreement,
no independent input while the desktop is active, session mismatch, cursor
gap, or stale receipts must report `unknown` or `degraded`, never clean.
Raw-input registration and hook registration need boot-start capture with
event identity and a durable cursor. Polling, direct driver access, firmware,
sensor tampering and pre-capture activity remain explicit blind spots.

Correlate process lineage, signed image identity, task/service changes,
Defender detections, Sysmon process/network/file events and input watcher
registrations by boot and event time. Preserve source disagreement and make
the underlying event accessible for investigation. No single score or model
judgment is a compromise verdict.

The project Jev client reviewed only the architecture descriptions and
aggregate status. Its Choice selected independent sensors (1.0 concentration)
and its Noul probability that a fresh hook heartbeat proves complete breach
visibility was 0.04. This advice did not authorize installation or establish
correctness; the Windows API behavior and measured receipts drive the choice.

## Acceptance gates

1. Isolated tests: blocked hook reader, crash, hook timeout, wrong session,
   stale/forged heartbeat, raw-input disagreement, duplicate publisher,
   cursor rewind, interrupted write, retry exhaustion and rollback.
2. Protected Windows cutover: preserve and read back previous binary, task,
   ACL and spool; validate one publisher per channel, service identity,
   first sequence continuity, heartbeat, independent observation and rollback.
3. Awake soak: 15 minutes with all channels fresh and no unexplained gaps;
   then 24 hours including sleep/resume and reboot, with measured CPU,
   memory, disk, latency and battery impact. Compare with the prior
   577 complete, 155 partial and 3 unavailable native receipts per day.
4. Breach assessment: independently investigate the older injected-key sender,
   early-boot watcher gap, Sysmon drop and any current threat finding. A clean
   Defender status or no new alert cannot close these gaps.

References: [Microsoft low-level keyboard hook behavior](https://learn.microsoft.com/en-us/windows/win32/winmsg/lowlevelkeyboardproc),
[Microsoft raw input overview](https://learn.microsoft.com/en-us/windows/win32/inputdev/about-raw-input),
[Microsoft Defender status cmdlet](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus).
