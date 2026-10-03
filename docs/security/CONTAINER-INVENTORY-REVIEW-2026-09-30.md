# Container inventory release review

## Invariants before editing

- Read-only local Docker inventory; never create, start, stop, execute in, or modify containers. Findings describe exposure, not compromise or authority to respond.
- Failed, malformed, interrupted, capped, or incomplete reads remain unavailable or partial. Preserve successful observations and name missing coverage; never label them complete.
- Bound each subprocess output and duration and the total audit duration. No automatic retries; exhaustion remains visible.
- Inspect only required metadata, excluding environment values, labels, command lines and credentials. Do not persist raw Docker responses or diagnostics.
- Preserve unrelated checkout changes and the sealed running release. Stage only reviewed deltas over the measured live base; keep rollback and compare fresh receipts against a written baseline.
- Container IDs select observations; missing inspection structures cannot establish clean configuration. Inventory remains a non-atomic snapshot with races explicitly degraded.
- Assurance remains unverified until isolated positive and negative controls and the actual service path have been measured. Fresh telemetry cannot upgrade validation claims.

## Design comparison

Per-container read-only inspection was selected over a persistent Docker event consumer or a privileged agent. It fits the current scheduler, requires no new daemon or permission, and keeps failures attributable to individual containers. A single unbounded inspect batch risks excessive output and loss of all results on one failure. Bounded per-container reads preserve earlier results, with a 60-second audit budget, 20-second command budget, 1 MiB output limit and 500-entry inventory cap. At 900-second cadence, one exhausted audit consumes at most 6.7 percent wall duty time; this is a configured bound, not measured CPU cost. Reconsider event-driven collection when fleet size or measured scan cost makes snapshot sampling inadequate.

No adversarial containers are launched on the protected host. Configuration fixtures establish rule behavior only. Container risk, identity integrity supplied by Docker, remote or alternate rootless engines, transient containers between scans and containment remain limitations.

## Validation and release

Focused collector and assurance validation: 61 tests passed in the restricted environment, with one Docker integration skip. Includes interruption cleanup and context restoration, real subprocess termination on timeout, output exhaustion, expired-budget refusal, redacted failures, malformed/identity-mismatched inspect data, partial/unavailable/truncated receipts, CLI dispatch, scheduler dispatch, coverage missing/stale/error paths, socket mount renaming, capability prefixes and assurance non-promotion. Compilation and `git diff --check` passed. Ruff is not installed.

Host read-only measurement at Unix time 1790785288: complete inspection of 11/11 containers, 12 ok findings and no exposure findings; elapsed 0.79 seconds, peak RSS 28,780 KiB, user CPU 0.35 seconds, system CPU 0.35 seconds. This is one inventory sample, not an adversarial detection or sustained-service measurement.

Jev was called through the project credential loader over the host network with one Choice design comparison and one Noul question about validation gaps, using only engineering metadata. The request failed with HTTPError. No model advice was available; deterministic invariants and tests remain authoritative. No retry or credential disclosure. Question definitions and engineering state are retained in `scripts/reviews/container_inventory_advisory.py`. Question semantics follow the [TypeSafe primitive contract](https://docs.typesafe.ai/primitives.md).

Live baseline: release db8fb2bdb4b2; system service active, MainPID 323570, zero restarts; healthy, ready and protection_healthy all true, assurance 17. A later baseline at Unix time 1790785540 recorded legacy protection score 54 and coverage 100 percent, with the same healthy booleans and assurance 17. Job receipts and finding hashes are saved locally in `/home/chris/jarvis/.container-release-overlay-20260930/validation/container-release-baseline.json`. Complete host checkout suite passed: 1,890 tests in 323.703 seconds. An earlier run caught the missing reporting command map entry; that wiring was fixed and the suite rerun. Exact-stage validation passed: 1,709 tests in 277.894 seconds, and 61 focused tests including the real Docker path. Stage hash audit found 13 reviewed files (9 changed, 4 added), zero unexpected changes. The stage is `/home/chris/.cache/jarvis-release-staging/20260930-containers-on-db8fb2bdb4b2`; administrator command and acceptance steps are in [the handoff](../guides/CONTAINER-RELEASE-2026-09-30.md). The documented administrator path was checked with `sudo -n true`, which reports a password required; no service switch attempted. Deployment acceptance requires fresh scheduled-job observations and health compared with the recorded baseline. This document will be updated with measured results.

## Expected changes before any cutover

The new `containers` job runs every 900 seconds and reports a complete receipt only when every listed container is inspected without truncation. Docker unavailable remains unavailable; failed inspect, exhausted budgets, and truncation remain explicit and noncomplete. CLI `jarvis --host wsl containers --json` and the investigation section expose the same inventory. Existing coverage automatically names missing, stale and failed container receipts through the shared schedule table. Container inventory is explicitly outside the legacy protection score; assurance adds one unverified entry, so the legacy assurance denominator may reduce 17 to 16 even with identical source states. This expected accounting change is not evidence of lost protection or a compromise verdict. Existing findings must persist except ordinary fresh-state changes with a recorded explanation.

Rollback remains the current sealed db8fb2bdb4b2 release until an authorized administrator switches the stage. The deploy uses the running sealed script, `--expect-base`, `--checkout /home/chris/jarvis`, and the owner-directed `--skip-tests`. Fresh affected-job receipt, baseline comparison, journal and service health are mandatory after cutover; periodic and interruption behavior still need sustained observation.
