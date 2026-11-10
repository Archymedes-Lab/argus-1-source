# Benchmark continuation plan (2026-11-10)

Purpose: complete the interrupted detection work without mistaking text replay for
live protection or treating community content as authority.

## Invariants before edits

- Privacy: inspect local bytes read-only; retain metadata and findings, never content.
  Reject symlinks in every path component and special files, including replacement races.
- Identity/freshness: cache verdicts only for the same device, inode, ctime, mtime,
  size and rule generation. Unreadable, changed and unvisited evidence stays unknown;
  prior positive findings survive an interrupted pass.
- Bounds: discovery as well as reading has entry, byte and elapsed-time limits.
  Never evaluate negative conditions against a partial file as if it were complete.
  Report omitted, oversized and inaccessible evidence explicitly.
- Authority: every community finding remains advisory after storage round trips.
- Recovery: benchmark actions run only on disposable infrastructure; attempt cleanup
  only for attempted actions, even on partial failure; report failed undo and collector
  failures, and return failure for incomplete measurements.
- Evidence: preserve the pinned replay corpus and report reproducible counts. No
  promotion to deployed, live-tested or containment-validated without measured evidence.

## Designs compared

Keep prefix scans with three-valued condition evaluation, or skip oversized files.
Choose skipping: simpler exact semantics, lower CPU/memory cost, explicit visibility
loss. Reconsider if measured dropped-file sizes justify streaming or a maintained engine.
Keep pathname-only opens, or anchor each component with O_NOFOLLOW directory descriptors.
Choose descriptors: prevents ancestor-link traversal and bounds descriptor lifetime.
Keep metadata cache, or hash every file every pass. Choose identity plus change-time and
rule-generation cache: bounds recurring disk reads; a privileged metadata-forging adversary
remains outside this cache's trust boundary. Discovery remains capped and explicitly
incomplete rather than claiming all files were enumerated or guaranteeing eventual coverage.

## Work and acceptance

1. Audit scanner, compiler, script-block collector and benchmark gates; fix directly.
2. Add adversarial regression checks for path races, cache replacement, rule changes,
   partial reads, discovery exhaustion, interruption and cleanup failures.
3. Register the content collector conservatively and refresh the benchmark document.
4. Run focused tests, complete scratch-HOME suite, static and ASES gates, pinned replay,
   and a bounded metadata-only Jev review. Record failures and limitations.
5. Commit and open a reviewable PR; merge only with required CI green. Run real attacker
   actions solely in the disposable CI workflow after safety review, never on this host.

## Audit fixes and measured checkpoints

- Fixed ancestor-link traversal, replacement/rule-generation cache invalidation,
  partial-file absence evaluation, discovery exhaustion, missing rule/root visibility,
  stale-positive continuity and oversized-file handling.
- Removed PowerShell's process-id-based ten-minute allowance; partial blocks stay
  explicit gaps and do not participate in absence-based matching.
- Compiler now refuses files containing global gates, rejects malformed token tails,
  accepts explicit approved licence labels and verifies the clean input commit.
  This yields 215 rules rather than the interrupted 326-rule build. Updated both
  the licence source snapshot and its generated notices, plus the assurance sample.
- Scanner runs in the governed isolated bulk lane and has its own CLI entry point.
- Live runner now requires network isolation, uses an explicit observation allowlist,
  unique per-run markers, whole-action process-group termination on timeout,
  attempted-action cleanup and explicit failed-cleanup/incomplete-measurement status.
- Pinned replay: 707/1745 matches, Windows 642, Linux 65, benign 0/24, no crashes;
  hash and floor passed. This is replay evidence only.
- Real service dispatch smoke test (`run_job('content', ...)`) on a scratch dropped
  fixture with the shipped rules: one attributed finding, 2.897 s including imports;
  persisted snapshot retains the community marker. This is not a throughput or soak
  measurement and does not promote the capability.
- Jev called through the project client on host networking, fixed metadata only:
  Choice skip-large probability 0.89 (concentration 0.83); Choice live execution as
  validation priority 0.74 (concentration 0.61); Noul production detection established
  by replay 0.03. Advice reinforces the conservative design, changes no authority.
