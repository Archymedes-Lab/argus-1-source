# Change-level observability audit — 2026-09-28

## Decision

The proposed architecture is a target, not the current machine state. At the
start of this audit the Linux service ran sealed release
`20260925T140154Z-959cff948858`; it now runs
`20260928T191033Z-541be197118e`, which adds the bounded change query only.
`/api/health` reported healthy after the switch, but this does not measure
change-level coverage. The checkout contains new pure execution models and an
event vocabulary; the installed release predates those models. No kernel driver binary, CLR event
stream, memory-protection transition source, instruction sampler, PMU trace,
or Intel PT trace was demonstrated. Millisecond transitions between scans can
therefore be missed.

Read-only aggregate query of the installed event-log index found 97 sealed
segments through sequence 669605. Its cumulative category counts included
161331 process starts, 149243 network connects, 33767 registry value sets,
33556 file creates and 748 driver loads. It had **zero indexed `thread`,
`memory`, `service`, `device` or `account` category rows** at audit time.
These are historical index counts, not fresh per-channel receipts or proof
that every source transition was captured.

The reviewed Sysmon baseline itself is intentionally selective: process
termination covers selected paths, network connections exclude local/private
destinations, file creation and registry collection target selected security
locations, and image-load collection is not enabled. This bounds the driver
queue after a measured earlier overflow, but it also makes "every connection,
file, registry value or module" an unsupported claim. Broadening a rule needs
an event-volume measurement and a no-loss soak before it can be accepted.

## Invariants before integration

1. **Evidence continuity:** preserve source channel, generation, record ID,
   boot identity, global ingest sequence, and explicit gaps. A snapshot cannot
   fill an event-stream hole retroactively.
2. **Freshness and identity:** compare observations from the same process
   instance and coherent time window. PID alone is insufficient; a stale or
   interrupted stream yields unknown, not verified or suspicious.
3. **Privacy and authority:** local metadata is sufficient for routine
   correlation; no typed text, secret values, command lines, or private file
   contents in remote review. A transition is evidence, not maliciousness or
   permission to respond.
4. **Bounded cost:** every stream and buffer needs a measured drop count,
   capacity, retention budget, and retry behavior. Deep capture remains
   explicit, narrow and recoverable.
5. **Recovery and rollback:** validate interruption, replay, log clear, boot
   switch, cursor reset, and release rollback before promoting a capability
   from source-tested to live.

## Measured implementation boundary

| Plane | Current evidence | Status |
| --- | --- | --- |
| Windows Event Logs | Native C# reader is configured for Sysmon, Defender and Task Scheduler; Python ingest normalizes supported events and retains unknown records | Existing live channel family; exact per-event coverage still requires fresh receipts and policy readback |
| Process and persistence | Sysmon event history, snapshots and collectors exist | Partial; no demonstrated all-process, all-boot continuity |
| Thread lifecycle and per-thread CPU | Canonical type and pure projection exist | No live continuous source demonstrated |
| Image and assembly loads | Sysmon and sampled in-memory assembly scan exist in source | Sampled scan can miss load/free between passes; CLR load trace absent |
| Memory permissions and RW→RX chain | Pure delta and chain helpers | No live protection-change stream demonstrated |
| Network/file/registry | Some Sysmon transitions and snapshot collectors exist | Subject to active policy, retention, source drops and attribution gaps |
| Cross-view reconciliation | Pure Python and Rust verdicts; tests | No live scheduled multi-view invocation found |
| Global change ledger, visibility score, sensor suppression | Pure helpers; new checkout-only bounded read query over the existing durable event log | No scheduled product path or new independent durable ledger demonstrated |
| Deep execution and hardware | Plans/contracts only | No L3/L4 scheduled sampling, kernel binary, PMU or processor trace demonstrated |
| .NET method-level visibility | Pure IL/native range resolver and sampled assembly inspection | No live CLR EventPipe/ETW method map demonstrated |

## Design choice and next acceptance gate

Three options were compared: declare pure models live; build a kernel driver
first; or wire one supported Windows event channel end to end with source
identity, gap accounting and live readback. The last option is the simplest
credible next step. It uses existing supported OS facilities, preserves
privacy and rollback, and exposes real drop rates before adding expensive
planes. Reconsider a signed driver only when a measured, important transition
cannot be covered by supported user-mode mechanisms and its cost and safety
case is established.

The next implementation must name one transition and prove: source emission,
fresh per-channel receipt, exact cursor/replay behavior across interruption,
identity-safe normalization, durable event query, coherent snapshot
reconciliation, measured latency and drop count under load, and a live
post-release readback. It must also pass the full test suite inside the exact
release stage. The current checkout's prior combined stage failed its suite
and must not be deployed as acceptance evidence.

This audit corrected two pure-model interpretation bugs: an exit plus current
activity no longer becomes a verified live process, and gapped coverage no
longer produces a high cross-view mismatch. The RW→write→RX→thread helper now
requires ordered events and exact permissions. These corrections are
source-tested only. They do not increase live sensor coverage.

## Bounded change query added in checkout

`jarvis timeline changes --seconds 120 --scan-limit 5000 --json` reads the
committed canonical event log and returns counts by event type, sequence
bounds, source-cursor ages and gaps, timestamp anomalies and a permanent
`partial` coverage label. It includes unknown provider events in the count
without revealing raw XML, paths, queries or command lines. It scans at most
20,000 recent records. Time filtering uses the source event wall clock:
the installed sensor does not record its read time separately. The checkout
now adds an optional `read_time` field to future native batches, validates
its timezone, and retains a marker distinguishing sensor read time from the
legacy event-time fallback. The query reports read-delay evidence only for
records with that measured field. A clock step or backlog therefore limits
temporal precision; a quiet answer is only
"no matching observed records," never "nothing changed."

Before deployment, read-only host-path validation of the checkout command
over a 120-second window returned 117 committed records through sequence
674287 and recent indexed Sysmon, Defender and Task Scheduler cursor commits.
The query does not independently verify source health or log integrity and
does not upgrade the broader execution-intelligence capability to live.

A narrow private stage at
`/home/chris/.cache/jarvis-release-staging/20260928T185915Z-on-959cff948858`
contains only the query module, timeline command change and its test over the
same sealed base. Its exact staged tree passed 1,531 Python tests and was
switched to release `20260928T191033Z-541be197118e` by the owner with
`--expect-base` and `--skip-tests`. This deploy does not add sensor sources.

The Windows sensor source change is **not in that stage**. The Windows host
refused to run the unsigned `build.ps1` under its execution policy; no policy
setting was changed. A direct invocation of the platform C# compiler with
the script's exact compile options produced a temporary binary with SHA-256
`c897e5651b1de7600c7b738ad4de151ba8b924584ebde2d8391b5d81a733ab70`.
Windows then denied execution of that binary for a one-pass, temporary-spool
read of its Event Logs. No sensor binary was installed or service changed;
the temporary audit spool was removed. Python validation of the optional
field and legacy fallback passed, but real read-time receipts remain
unverified. The Windows execution denial needs an approved installation or
test path, not a policy bypass.

An unattended Linux release attempt stopped before a switch because `sudo -n`
required the owner's password. The owner then ran the guarded command in
their own administrator session. The predeploy baseline is preserved at
`/tmp/jarvis-change-query-baseline-20260928.json` with hashed finding keys;
the guarded deploy command named the expected sealed base and tested stage.

Post-switch readback: `/opt/jarvis/current` resolves to the new release,
`jarvis.service` is active with zero restarts, and `/api/health` reported
healthy, ready and protection healthy. Fresh native, scan, Sysmon and
coverage snapshots had no job errors; the event log advanced 1,479 global
sequences from the baseline with no missing retained ranges. The live query
counted 396 source-time records in 120 seconds with three recent cursor
commits and `coverage: partial`. Two later installed-query runs completed in
0.81 and 1.04 seconds. The owner's first invocation was interrupted; the
second completed, and two subsequent bounded runs also completed. Journal
review since the restart showed no traceback or error lines. Scan added new
process and peer observations; no previous non-OK scan finding disappeared
in the first comparison. The service entered the new release at Unix time
1790622634; later readback showed scan, bridge, Sysmon, native, internet and
resource collection timestamps after that restart. Reliability counts
fluctuated during postdeploy observation. A later health read showed `bridge`
and `input_hook` stale and recovering even while the top-level health flag
remained true and the native chain reported a fresh, gap-free pass. Their
recovery and sustained health remain unverified. This is acceptance of the
narrow query release, not evidence of complete observation or a sustained
soak.

A later live request returned HTTP 503 while the service stayed active with
zero restarts. The next request returned HTTP 200, but the health payload had
`invariants.performance.ok = false`: the governor measured about 404–412%
host CPU and reported noncritical work still running under pressure. A native
collector was also marked stale and recovering at the last read. Concurrent
Playwright Chromium processes and the JARVIS Rust ingest worker were among
the largest CPU consumers at that moment; this observation does not establish
that the new query caused the pressure. A healthy top-level flag cannot erase
the failed performance invariant. The release has not passed an awake/idle
soak or this pressure case.

The full checkout regression suite after these changes passed 1,701 tests
through the permitted host path. The staged suite's 1,531-test result covers
only its three-file overlay; it does not validate the later sensor read-time
change or the rest of the dirty checkout as a deployable release.
