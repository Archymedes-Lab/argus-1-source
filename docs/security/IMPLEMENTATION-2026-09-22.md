# Implementation record — 2026-09-22: Rust evidence mirror, Sysmon pressure, Sysmon evidence

## Rust evidence mirror

- `rust-runtime` builds (`cargo build --release`); 18 Rust tests, clippy clean.
  `rust-runtime/target/` is ignored.
- Mirrored events carry the authoritative Python `seq` as `source_seq`. The Rust
  store rejects any `source_seq` that does not advance, and `verify` reports the
  newest one, so the durable store is its own mirror cursor.
- `ingest` is all-or-nothing and runs under one writer lock with one full
  verification. Budgeted `prune` keeps the newest segment and the complete header
  chain, which stays link-verified. It makes the marker durable before deleting
  payloads, and it rejects a marker that covers the newest segment.
- `jarvis/collectors/telemetry/mirror.py` + scheduler job `rust_mirror` (1200s,
  governed): batches ≤ 20,000 events / 24 MiB, store budget 128 MiB. Findings:
  - **low:** binary absent
  - **medium:** retention gap, or mirror not advancing
  - **high tampering:** store fails verification
  - **high tampering:** store cursor behind the recorded cursor, which pauses the
    mirror and writes nothing
- `/api/health` reports the job's recorded summary and never verifies the store
  in the request path.
- Measured: 5,000 real events persist in 2.0s (1.8 MB compressed). Four live
  catch-up batches took 3.6–7.1s. The live daemon (restarted at 23:07 by another
  session) ran the job, and the store verified at 36,404 events with contiguous
  `source_seq`.

## Sysmon pressure probe

The broker killed the probe at 120s every run. `Get-WinEvent` rendered every event's
message: it took 230s for 14,609 events, while `ToXml` parsing took only 0.3s per 1,000. The probe now
uses `EventLogReader` with positional properties, a 90s budget, and the same
aggregate-only output. It measured 4.3s wall time unelevated for 15,021 registry
events plus one drop record. After `jarvis broker install` on 2026-09-23 the
elevated broker ran it in 2s over 34,002 registry events, not truncated. The only
drop record this boot is still the 12:48:51Z overflow under the previous policy.

## Sysmon evidence

- The elevated broker export shows config hash
  `DDAD44B2933C95030CB7F2A073D5AAE8A5704463B9087258F59D595AEAE58EDA`, which equals
  the SHA-256 of `windows-sysmon/jarvis-windows-baseline.xml`. ProcessCreate is
  `exclude` with no filters.
- `C:\ProgramData\Jarvis\SysmonPolicy\backup-20260922-143734` is empty. No export
  of the pre-change policy was preserved.
- Boot 94 logged one driver-queue overflow at 12:48:51Z, 46s after boot and under
  the previous policy: 82 ProcessCreate and 64,784 RegistryEvent records dropped,
  queue 50,000. There has been no overflow since the new policy. Whether the new
  baseline prevents boot-time overflow is unmeasured until a reboot.
- The earlier all-`unknown` perception and stale `controls` were ingestion
  catch-up after a daemon restart. Later samples showed 230 verified, 0
  unreconciled and 67 unknown processes, with all 45 collectors FRESH.

## Validation

- Full suite: 1,082 tests passed, 0 skipped.
- Ruff is clean on the changed files.
- Jev (advisory, metadata only) was run twice:
  - Before the fixes: scope 0.83, more-permissive-action 0.05, review priority
    store integrity at 0.82 confidence. That prompted the cursor-regression,
    newest-segment marker and interrupted-prune fixes.
  - After the fixes: claims 0.40, blind spots 0.62. That prompted stating in the
    register that the regression pause is live only after the next restart.
