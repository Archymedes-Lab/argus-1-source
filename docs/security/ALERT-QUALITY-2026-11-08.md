# Alert quality: double counting, blocklist-only criticals, coverage gaps as findings

Date: 2026-11-08. Closes QC-ARGUS-1-2026-10-27 blocker 3. The owner approved fixing all
three on 2026-11-08. Under the score-integrity rule, each one is argued below as a
detector bug, with a replay.

## Invariants

1. **One problem, one finding.** A ledger note must not restate a finding that its own
   collector still lists at that finding's severity.
2. **No lost visibility.** Every problem the ledger knows about stays visible at full
   severity whenever its original is *not* listed. That covers a failing collector, a
   title that drifted, and callers that pass no snapshots. Stale rows stay medium. A lone
   blocklist hit stays listed. Coverage gaps move to another view; none are dropped.
3. **The ageing signal survives.** The original finding carries how long it has been
   open, whether it is past its deadline and whether it came back after being cleared.
4. **No blocklist-only critical.** An address listing becomes critical only when a
   second, independent signal backs it up. Shared provider infrastructure is never
   critical.
5. **Bounded fan-out.** A process gets one finding with a count, not one per listed peer.
   That includes flagged-network (Spamhaus DROP) hits. Below `PEER_SINGLE_THRESHOLD` (5)
   peers, each peer keeps its own finding, so a real C2 contact is not folded away.
6. **Category honesty.** Coverage gaps are about Argus, not the machine. They stay out of
   the machine's findings list, its severity totals, the live pulse, the
   `jarvis_findings_open` metric and autopilot investigations. They never moved the
   score, and they still don't.
7. **Bounded automatic intervention.** The opt-in `auto_block_ip` acts only on a
   corroborated critical.

## 1. Double counting (ledger)

**Detector bug.** `ledger.audit` turned every overdue outstanding row and every
recurring row into a new finding at the original's severity (`unresolved for 16d:
OpenAI API key in plaintext`, critical), even when the `secrets` collector was still
listing that same finding. The ledger is unscored, but `/api/state` (findings, totals,
worst), the pulse's urgent list, metrics and autopilot all counted the problem twice.
The desktop app had already worked around this (`isReminder`). The replay below shows 30
weighted restatements.

**Fix.** `audit(..., snapshots=)` checks each recurring or overdue row against its own
job's current snapshot, matching on the same dedupe key (`alert.finding_key`) and the same
clearing domain.
- **Original listed:** the ledger emits a **low** note with `restates=<key>`.
- **Original not listed:** this covers a failing snapshot, a key mismatch and a missing
  `snapshots` argument. The note keeps the **full severity** and gets `orphan=true`.
- **Stale rows:** unchanged (medium, "unverified since it was reported").

`jobs._ledger` passes the snapshots it already reads. `ledger.annotate()` adds a `ledger`
field to the original in `/api/state`, containing state (overdue or recurring), age,
deadline, sends, clears, reopens and worst severity. The desktop app shows it as an
"Open for 16d" or "Came back" tag. `isReminder` now treats an orphan note as a problem.
Older daemons send no flag, so their notes stay reminders, as before.

**Designs compared.**
- **(A) Annotate the original and attach the note (chosen).**
- **(B) Keep ledger severities and deduplicate only in UI counts.** Every other consumer
  (pulse, metrics, autopilot, email briefings) would still double count, and each would
  need its own copy of the rule.
- **(C) Drop overdue notes altogether.** This loses visibility for originals that are no
  longer listed.

Reconsider (A) if `finding_key` changes in a way that splits one problem across keys.
That would make orphans appear, which is safe but noisy.

**Replay.** Recorded live store, read-only copy, run through `ledger.audit`:

| | critical | high | medium | low | weighted notes restating a listed finding | orphans at full severity |
|---|---|---|---|---|---|---|
| before (org/main 4e50d1d) | 17 | 22 | 1 | 0 | **30** | n/a |
| after | 0 | 9 | 1 | 30 | **0** | 10 |

- **Annotations:** after the fix, 30 originals carry a `ledger` annotation (25 overdue, 5
  recurring).
- **The 10 orphans:** 9 high and 1 medium. Examples are "unresolved for 49d: svchost.exe
  exists without a start event" and "a resolved alert has come back: collector 'evasion'
  did not complete observation". They keep their severity because nothing else lists
  them.
- **The 4 former recurring criticals:** these were scheduled tasks whose `worst_sev` was
  critical. Their originals are listed at their current severity, and the annotation
  carries `worst_severity`.

## 2. Blocklist-only critical (hunt)

**State on org/main before this change.** Part of this was already fixed on 2026-10-30:
- Attack-source reputation feeds (blocklist.de, CINS, Binary Defense, IPsum) were already
  medium.
- Peers were already collapsed per process above 5.
- Cloudflare and GitHub shared addresses were already rejected at match time. That is why
  the Quasar RAT listing of 188.114.97.3 (Cloudflare), still critical on the older
  deployed release, does not appear in the replay.

The remaining defect was that any single high-confidence ThreatFox, Feodo, URLhaus or Exa
listing made a contacted address critical. A torrent client (btweb.exe, 320 listed peers)
and an unattributed group each produced a critical. Each flagged network was also its own
high finding, so btweb produced 7 extra highs.

**Detector bug.** "Known attacker" was asserted on one list's word. The ThreatFox
entries in question are mostly VPN exit and residential addresses reached by a
peer-to-peer client.

**Fix** (`hunt.grade_ip_hit`, pure). Feed type decides the starting severity, and a
second signal can raise it:

| Hit | Severity | Title wording |
|---|---|---|
| Reputation feed | medium | "reported attack source" |
| Google / Google Cloud published range (`SHARED_PROVIDER_IPV4`) | medium | detail says the listing may concern another tenant |
| C2 feed, lower confidence | medium | |
| C2 feed, high confidence, alone | **high** | "listed command-and-control", detail says "one list only, no second signal" |
| C2 feed, high confidence, plus an independent signal | **critical** | "known attacker", detail names the corroborating signal |

The independent signals are:
- the process image runs from a temp or download folder;
- the process's cached digest matches a malware sample;
- beacon-shaped repeated contact: at least 3 samples over at least 1 h, from a process with
  no more than 5 listed peers, so a swarm member that recurs does not count;
- the address is also inside a Spamhaus DROP network (a second provider).

Other changes:
- **Collapse:** DROP range hits fold into the per-process collapse. The collapsed title
  counts distinct addresses and corroborated ones: "btweb.exe contacted 289 listed IPs (0
  corroborated)". Its detail gives the counts per severity, the worst address and the
  reason.
- **rDNS domain hits:** in `hunt`, these follow the same lone-signal rule (high).

**Designs compared.**
- **(A) Grade per hit with explicit corroborating signals (chosen).**
- **(B) Require two feeds to list the address.** Not possible with the current store:
  `indicators` is unique per (kind, norm) and keeps only the first source.
- **(C) Allowlist P2P processes.** That hides a real implant hiding in a P2P process, and
  depends on the process name, which an attacker controls.

Reconsider when feed ingest keeps the listed port, because a port match is a strong
second signal. The port is currently dropped by `feeds._host`.

**Replay.** Recorded peers (48,478 public) and their matched indicators, run through
`hunt.check_peers`:

| | critical | high | medium | findings |
|---|---|---|---|---|
| before (org/main 4e50d1d) | 2 | 7 | 5 | 14 |
| after | **0** | 2 | 5 | 7 |

- **btweb.exe:** went from 1 critical plus 7 flagged-network highs to 1 high. It reached
  289 distinct addresses: 27 graded high, 262 medium, none corroborated.
- **Google addresses:** 142.251.38.238 (1e100.net) and 142.251.37.78/142.251.10.101 stay
  medium, as on org/main, and their detail now names the shared provider.
- **35.190.43.134 (Google Cloud):** medium, inside the firefox.exe group.
- **Nothing hidden:** every address is still listed and can still be blocked with
  `jarvis defend`.

**Behaviour change to note:** the opt-in `auto_block_ip` now auto-blocks only corroborated
criticals. A lone C2 listing becomes an approval proposal. This is deliberate, per
invariant 7.

## 3. Coverage gaps shown as findings (gaps)

**State on org/main.** The `gaps` job was already unscored (area `None`, category in
`NOPAGE_CATEGORIES`). Removing every gap finding leaves the score identical (replay
below; also `test_they_never_moved_the_score`), so the "security score" part of the QC
note was already fixed. The defect that remained was categorical. `/api/state` listed
"T1001 Data Obfuscation" and similar gaps as high findings about the machine, inside
`findings`, `totals`, `worst` and `by_category`. The pulse urgent list, the
`jarvis_findings_open` metric, `assistant._current` and autopilot investigations
(`current_findings`) also picked them up.

**Fix.**
- **Predicate:** `alert.is_coverage_gap(f)` returns true for the categories "coverage gap",
  "not observable" and "not applicable", which only `gaps` emits.
- **Where they leave:** the findings list, totals, pulse, metrics, the assistant's current
  list and autopilot all skip them.
- **Where they now live:** `/api/coverage` gains `intel_gaps` (every gap with tid, name,
  kind, priority and detail, plus freshness). `/api/state` keeps
  `coverage_gaps: {total, by_priority}`. The desktop Coverage view lists them under
  "Detection gaps". `isCoverageGap` also keeps an older daemon's copy out of the desktop
  problem counts.
- **No change needed:** the classic web dashboard already treated `job === "gaps"` as
  noise.

**Replay.** The recorded `gaps` snapshot holds 6 high, 5 medium and 185 low:

| | in the findings list | in `/api/coverage intel_gaps` | score |
|---|---|---|---|
| before | 196 (6 high, 5 medium, 185 low) | absent | 25 |
| after | 0 | 196 | 25 |

## Combined effect on the findings list (recorded store)

| | critical | high | medium | low |
|---|---|---|---|---|
| before | 43 | 135 | 196 | 672 |
| after | 24 | 111 | 191 | 517 |

The score stays 25 in both runs. In the recorded snapshot the "Active threats" area is
already 0 because one of its collectors was blind, so the hunt change (2 criticals → 0,
57 → 52 highs in that area) does not move it at this moment. Once that area is observed
in full, the change lowers its penalty by 80 points. That comes from a proven detector
fix, not from lost visibility.

Reproduce:

```
python3 scripts/dev/replay_alert_quality.py extract ~/.jarvis/jarvis.db $SCRATCH   # mode=ro
git archive <base> jarvis | tar -x -C $BASE
(cd $BASE && PYTHONPATH=$BASE python3 <repo>/scripts/dev/replay_alert_quality.py replay $SCRATCH)
PYTHONPATH=. python3 scripts/dev/replay_alert_quality.py replay $SCRATCH
```

The extracted data is private. Keep it in a scratch directory.

## Tests

- **New:** `tests/test_alert_quality_20261108.py`. The ledger cases cover:
  - the original listed (one problem; a low note plus an annotation on the original);
  - a recurring row;
  - the original no longer listed (orphan at full severity);
  - a failing collector;
  - a different job;
  - no snapshots;
  - a stale row (stays medium);
  - a cleared row and a not-yet-overdue row;
  - the real `jobs._ledger` path.

  It also covers the grading table, the range-and-address collapse, and coverage gaps
  across `build_state`, `/api/coverage`, autopilot, score invariance, pulse and metrics.
- **Updated:** `tests/test_hunt_peer_severity.py`, which adds the lone C2 = high case,
  each corroborating signal = critical, a short repeat, a P2P swarm member, shared
  provider = medium, and the collapsed count. `tests/test_protection_gaps.py` was also
  updated.
- **Desktop:** `model.test.ts` covers orphan counting and coverage gaps excluded from
  problem counts, and `locales.test.ts` covers four new strings in 10 languages.

## Jev advisory (metadata only, host network)

One bounded request with counts and policy descriptions only (no paths, addresses or
content):

| question | result | effect on the work |
|---|---|---|
| choice: ledger design A/B/C | A, confidence 0.98 | kept A |
| noul: lone C2 capped at high makes the owner miss a real C2 | 0.33 | kept high (still a threat-area alert), not medium |
| noul: corroborating signals too narrow for a real implant to reach critical | **0.80** | added beacon-shaped repeated contact as a fourth signal and recorded the port gap below |
| noul: moving gaps to the coverage view loses information the owner needs | 0.13 | kept the move, with counts left in `/api/state` |

Jev is advisory only. Correctness rests on the tests and the replay above.

## Left open

- **Listed port not kept:** feed ingest drops the port of a ThreatFox `ip:port` entry, so
  "listed port matches the contacted port" cannot be a signal yet.
- **Coarse beacon signal:** `peers.seen_count` and first/last seen measure repetition, not
  periodicity.
- **Shared-provider list covers Google only:** Microsoft, AWS and Akamai should be added
  from their own published range files, not from memory.
- **Sysmon DNS matches** (`warninglist.match_domain` severity) are outside this change and
  can still be critical on one list.
- **Title-based keys reset:** retitled hunt findings ("listed command-and-control",
  "(N corroborated)") get new dedupe keys. Existing ledger rows and acknowledgements on
  the old titles clear once and new ones open.
- **Compiled web UI not rebuilt:** `jarvis/web/ui` predates several desktop source
  changes, including this one. Rebuild it with `scripts/dev/build_web_ui.py` at release.
- **Not deployed:** nothing is deployed. Live readback after an owner deploy should show
  zero `ledger` notes with `restates` at a weighted severity, no critical `c2 match`
  without a named signal, and no `coverage gap` in `/api/state` findings.
