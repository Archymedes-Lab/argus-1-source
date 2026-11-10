# UI and detection integration plan, 2026-11-10

Owner request: integrate the two-room desktop redesign, inspect latest branches,
close measured detection gaps, and verify production and disposable Windows paths.

## Invariants before changes

- Keep unrelated dirty owner checkout intact; integrate in isolated worktrees.
- Preserve finding evidence, identity, timestamps, cursors and sources. UI changes
  cannot alter counting, authority, scores or collector health.
- Never infer directory ACL protection from a Windows path prefix. Missing ACL
  evidence cannot justify lower severity. Remote-access and user-writable rules
  retain their existing severity.
- Do not skip executable package trees to reduce cost or findings. Package source
  remains visible; bad signatures and native payloads retain their severity.
- Protected replay stays local and read-only. Jev receives aggregate engineering
  metadata only, never private findings, command lines, scripts or credentials.
- Failures and staleness remain visible. Do not resolve the three owner policy
  questions merely to improve score; require replay and independent controls.
- Windows fixtures run only on disposable hosted machines with checked cleanup.
  Production activation uses sealed source, expected base, baseline and rollback.

## Designs compared

Blindly merging the whole UI branch would also take unreviewed detector and daemon
changes. Cherry-picking visual files alone would leave requested backend work
unresolved. Select full branch integration with explicit backend review and repairs,
preserving the author's commits. Verify UI build, type checks, tests and browser
walk; a mock bridge does not prove a real Tauri window.

For orphaned firewall rules, prefix-only downgrades lack ACL proof. Adding ACL
collection increases scope and cost. Retain previous severity until measured ACL
evidence exists. For staging, retain bounded-depth package enumeration and
deduplicate overlapping roots; never silently prune executable npm directories.

## Execution

1. Fetch all remotes; classify unmerged branches, superseded patches and independent
   work. Do not blindly merge old experiments.
2. Integrate UI and licence/state changes in isolation. Repair assumptions and add
   independent failure controls. Run metadata-only Jev design and implementation review.
3. Read live state/coverage locally; report aggregate alert shapes. Retain unresolved
   policy questions where representative replay or corroboration is unavailable.
4. Run regression/static/ASES gates, UI build/types/tests/browser checks. Merge only
   reviewed exact heads after required CI passes.
5. Preserve Linux/Windows campaign evidence; prepare a narrow sealed-base release.
   Native desktop and live service acceptance remain independent gates.

Translations still require native review. A restart does not verify protection.

## Review findings and baseline

The incoming branch is not UI-only: its latest tip also includes licence retries,
Defender explanations, staging enumeration, indicator counting, and two severity
changes. Review found three repairs needed before integration:

- Prefix-only firewall protection is unproved (Windows Temp and delegated ACLs are
  counterexamples). Revert that downgrade; preserve rule evidence and severity.
- Pruning global npm contents silently removes native payload visibility. Restore
  bounded-depth traversal, deduplicate roots, include .node/.mjs/.cjs types.
- The global indicator cache keys by Store identity, but every request creates a
  new Store. It cannot reuse results and retains a closed connection. Keep the
  covering-index query without the cache, with committed-write and error recovery
  tests. This trades at most one indexed count per request for fresh counts and no
  cross-store retention. Reconsider only after measured indexed-query bottlenecks.

Package-source severity uses normalized Windows paths: traversal out of
node_modules cannot inherit its lower severity. NotSigned is not useful evidence
against library source alone; bad signatures and executable/native payloads retain
severity. Source remains listed and can still be malicious; low is not a safe verdict.

Live owner API baseline: 45 critical, 207 high, 235 medium, 645 low. The response
includes only 1,000 of 1,132 findings: ten high collector-health findings, one stock
WMI subscription at low. No complete second-machine replay is available, so these
are aggregate shape observations, not a false-positive rate. Coverage reports
5 validated, 141 claimed, 33 blind, zero regressed. memscan currently reports
incomplete coverage. Health remains explicit and no score policy is changed.

Media Play/Pause handling has already changed on main: inputwatch separates 0xB3
nonprintable controls from typed characters and reports media-only bursts at medium;
software injection is retained as evidence, not equated to malicious intent. WMI
and AppData critical thresholds and collector-health counting remain owner decisions;
no suppression or exclusion was introduced to make the dashboard look healthier.

## Advisory review

Jev 1.14.0 was called with fixed engineering metadata only (no protected evidence).
Choice favored retaining firewall severity (probability 0.98, concentration 0.97).
Noul for changing/suppressing findings from the current evidence: 0.07; for claiming
five Windows detections from initial delivery evidence: 0.07. Advice supports the
conservative repairs; deterministic tests and measured execution remain authoritative.
UI build passed, svelte-check had zero errors/warnings, 72 Bun tests passed.

Native signing follow-up: owner identifies the warning as SmartScreen unknown
publisher. Added a public-trust signing plan and corrected the outdated EV claim.
No policy bypass or security exclusion was applied. Read-only Windows diagnostic
was unavailable from this shell, so local event counts remain unverified.

The combined tree now includes the measured-gap branch for final regression.
Browser navigation checks target stable Coverage view identity with the same
navigation assertions. Full unittest discovery uses a private scratch HOME.
