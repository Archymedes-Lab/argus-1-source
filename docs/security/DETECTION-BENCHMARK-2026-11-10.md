# Does it catch attacks? First independent detection benchmark (2026-11-10)

## Latest continuation measurement

Reverified on the pinned corpus on 2026-11-10:

| Same text-replay corpus | Any finding |
|---|---:|
| Built-in baseline | 392 / 1,745 (22.5%) |
| Community process/registry rules | 620 / 1,745 (35.5%) |
| Plus registry-family watch | 693 / 1,745 (39.7%) |
| Plus PowerShell script-block matching | **707 / 1,745 (40.5%)** |
| Windows, latest | 642 / 1,322 (48.6%) |
| Linux, latest | 65 / 423 (15.4%) |
| Benign commands flagged, latest | 0 / 24 |

Latest run: no detector crashes; the pinned-index hash and detection floor pass.
The registry layer observes writes rather than snapshotting registry state; writes
outside the Sysmon policy remain unseen. Script blocks are read only if Windows
already records them. Logging is never enabled automatically because it records
private script contents. Neither collector is deployed by this work.

This remains command-text replay, with script-block rule matching added to the
PowerShell test text. It does not measure telemetry delivery, actual block assembly,
detection latency, end-to-end attacks or the benign population false-positive rate.
The following earlier sections are historical snapshots, including superseded counts.

Content scanning now ships a strict **215-rule** literal-only signature-base subset
(commit de3c7252c22b3376352b5a68defa46459a12a693), without executing rule code.
The interrupted 326-rule build used a licence substring check; explicit approved
DRL-1.1 labels reduce that set to 215. The scanner rejects ancestor symlinks and
unstable reads, invalidates cached verdicts on identity or rule-generation change,
bounds discovery and reads, and reports incomplete coverage. It skips oversized
files entirely: absence predicates must not inspect a prefix as a complete file.
Prior positive evidence that cannot be refreshed remains visibly stale. It runs
in the governed isolated bulk lane, unscored; `jarvis content` audits the same path.
Only Linux/WSL is supported, including accessible Windows mount roots from WSL.
This is file scanning, not a memory scanner or full YARA engine. The scanner does
not increase the command-text replay count. The earlier 6,001-file/222 MB noise
measurement is historical, not independently revalidated for this final tree.

The audit also removed the PowerShell reader's ten-minute process-id exemption:
only complete exact own-script hashes are excluded. Incomplete/truncated blocks
are reported as gaps and not evaluated. Nested blocks now receive ordinary rule
judgment. The 120-second polling interval still loses evidence when the log wraps
in about 30 seconds; this work does not enlarge logs or close that runtime gap.

Real-execution work is a manually dispatched disposable-runner workflow with an
explicit observation-only collector allowlist, an isolated network namespace,
per-action cleanup, failure reporting and retained artifacts. It is not a replay
replacement: 16 local Linux scenarios do not represent the 1,745-test corpus.
No live-execution result is claimed until a workflow run produces evidence.

Plan and invariants: [BENCHMARK-CONTINUATION-PLAN.md](BENCHMARK-CONTINUATION-PLAN.md).
Jev advisory (jev-1.14.0, fixed metadata only): Choice favored skipping oversized
files (probability 0.89; concentration/confidence 0.83), prioritized real execution
(probability 0.74; concentration 0.61); Noul probability that replay establishes
production detection was 0.03. Advice supports the conservative design and next
validation priority; it changes no gate, severity or authorization.

Still open: exact own-launch suppression for process-start community rules,
broader false-positive measurement, reliable script-log retention, memory-content
scanning, a maintained full rule engine if justified, signed rule-pack distribution,
and measured live execution on both Windows and Linux.

---

Until today every technique rule was tested against a sample written with the rule. This
is the first measurement against a library written by someone else: Atomic Red Team
(redcanaryco, MIT), `atomics/Indexes/index.yaml` as of 2026-11-10
(sha256 `afa92a2c9b95b77d6ff0a318ae8000d9df04fc63101f87a7ac9fc6feb1fdf6f6`).

Under [MAXIMUM-ASSURANCE](MAXIMUM-ASSURANCE.md) this is a measurement of one detection
layer on replayed text. It promotes no capability and is not a protection claim.

## Method

`scripts/security/atomic_bench.py`. Nothing is executed. Each test's command (default
arguments filled in) becomes the process starts it would produce if run as written, plus
the registry value writes of `reg add` and `Set-ItemProperty` lines. Those go through the
real entry points: `sysmon.audit(events=...)` for Windows and the Sysmon for Linux rule
pass. A test counts as caught when any finding results.

Re-run: `python3 -m scripts.security.atomic_bench INDEX.yaml` (PyYAML, development only).

## Result

| | Tests | Any finding | High or critical | Right technique named |
|---|---|---|---|---|
| All | 1,745 | 398 (22.8%) | 329 (18.9%) | 165 (9.5%) |
| Windows | 1,322 | 337 (25.5%) | 287 (21.7%) | 141 (10.7%) |
| Linux | 423 | 61 (14.4%) | 42 (9.9%) | 24 (5.7%) |

- Techniques with a runnable test: 316. At least one test caught: 155. Every test caught:
  31. None caught: 161.
- Benign control: 24 ordinary commands (12 per platform) raised no finding. Small; the
  real false-positive measure remains the replay of recorded history
  (`scripts/dev/replay_techniques.py`).
- No detector crashed on any of the 1,745 inputs.
- Weakest tactics: persistence 10.9%, discovery 19.4% (single discovery commands are
  listed, by design, only as a burst), stealth 19.5%. Strongest: lateral movement 41.7%,
  credential access 32.5%.
- Most-missed techniques (missed/total): T1112 modify registry 88/92, T1685 55/71, T1105
  ingress tool transfer 27/37, T1552.001 credentials in files 25/31, T1082 25/37, T1087.002
  22/25, T1548.002 UAC bypass 21/28, T1547.001 run keys 19/21, T1059.001 PowerShell 17/21,
  T1218.011 rundll32 15/16.
- Registry: 221 tests write a value; the 18 registry rules caught 11.
- Findings from the older detectors (for example "attempted to disable Windows recovery")
  carry no technique id, which is why "right technique" trails "any finding".

## What this does and does not show

It is an **upper bound for the command-line and registry rule layer**, and does not establish a bound
for the complete product:

- Generous to Argus: 758 of the tests are PowerShell. They were modelled as
  `powershell.exe -Command <text>`. Typed into a running session they produce no process
  start, and Argus does not read PowerShell script-block logging (event 4104) or AMSI, so
  on a real machine most of those 189 catches would not happen.
- Unfair to Argus: collectors that do not read process starts were not exercised:
  persistence state diffs (`asep`, `startup`, tasks), memory scanning, cross-view process
  checks, network and DNS, posture, canaries, drift baselines. A run-key test missed here
  may well be reported by `asep` minutes later.
- Not measured at all: whether the telemetry arrives. Sysmon dropped tens of thousands of
  events per boot on the development machine (BLIND-SPOTS-2026-10-22 S12).

The honest reading: against commodity techniques run exactly as published, the rule layer
sees about one in four. An attacker who changes anything sees less.

## Is there a better way? Yes, in five parts

1. **Stop hand-writing the signature floor.** 186 process rules and 18 registry rules
   written by one team cannot keep up. The community maintains thousands of rules in an
   open format (Sigma) for exactly these Sysmon events. Build a small evaluator for the
   subset of that format the event rows support, and ship converted rules through the
   signed rule-pack channel that already exists (`core/rulepack.py`). The rule licence must
   be checked and recorded in `core/thirdparty.py` before any rule ships.
2. **Read what PowerShell actually ran.** Ingest script-block logging (4104) through the
   existing event-log reader. It is the single largest blind area in this benchmark.
3. **Judge behaviour and state, not spelling.** This is already the adopted strategy
   (DETECTION-CONTENT.md): invariants, cross-views, learned drift, canaries. The benchmark
   shows why. The registry family is the clearest case: watch the security-relevant key
   families by state (policy, Defender, LSA, run keys, services) and report any change,
   instead of 18 patterns for specific values.
4. **Scan content with a maintained engine.** A file and memory pattern scanner with
   community malware-family rules covers what command lines never show (packed tools,
   in-memory loaders). Licence to be checked as in 1.
5. **Make this number a gate.** Run the benchmark in CI and refuse a release whose rate
   falls. Then replace replayed text with real execution in the disposable VM lab so that
   every collector and the telemetry path are measured, per technique, and only those
   results promote a register entry.

Kernel-level telemetry (a signed driver on Windows, eBPF on Linux) would close more, and
is out of reach until the project can sign a Windows driver; it should not be promised.

## What would change this assessment

A real-execution run in the VM lab (it measures all collectors); a Sigma-subset evaluator
re-measured on this same index; or recorded-history replay showing that broader rules
raise false findings on ordinary machines.

---

## Update, later on 2026-11-10: community rules built (item 1) and the gate (item 5, first half)

**Harness correction.** The first run modelled every first word of a command as a program
and placed bare program names under `C:\Tools`. Both inflated or distorted matches. A
bare name is now placed where Windows finds it and only something that can be a program
is a process start. Re-measured, the built-in rules catch 392 of 1,745 (22.5%).

**Community rules.** 1,116 Sigma rules (SigmaHQ commit `d7c9da10`, Detection Rule License
1.1) are compiled ahead of time into literal field tests (`scripts/security/sigma_compile.py`
→ `jarvis/intel/data/sigma_rules.json`, evaluated by `jarvis/core/sigma.py`). 439 rules
were left out because they cannot be evaluated exactly here (experimental status, fields
Argus does not record, regular expressions); none is approximated.

| Same 1,745 tests | Built-in rules | With community rules |
|---|---|---|
| Any finding | 392 (22.5%) | **997 (57.1%)** |
| Windows (1,322) | 331 (25.0%) | 772 (58.4%) |
| Linux (423) | 61 (14.4%) | 225 (53.2%) |
| Techniques with at least one test caught (of 316) | 145 | 252 |
| Benign control commands flagged (of 24) | 0 | 0 |

**False alarms, measured on real history.** Read-only replay of 18 hours of the
development host (27,252 process starts, 938 registry writes): 28 rules matched 11,578
times, nearly all on the monitor's own scheduled PowerShell audits. Reporting raw matches
would bury a person. Cost: 0.37 ms per distinct event with the candidate index (2.8 ms
without), 24 s of rule time for the whole replay before the per-pass cache.

**Designs compared for that noise** (`collectors/telemetry/community.py`):

| Design | Verdict |
|---|---|
| Learn (rule, program, parent) shapes for the first 7 days, list them as a standing low finding until a person reviews them, alert only on new shapes afterwards (built) | Works on every install today; on the replay 38 shapes learned, no alert afterwards. An attacker with the same shape as a learned one is not reported by this layer |
| Exclude exactly the monitor's own launches (a ledger of what it started) | The right fix for the monitor's own noise; needs a change to the command runner and measurement of how Sysmon records those command lines. **Next build** |
| Exempt by the monitor's name | Rejected: an allowance an attacker can claim by naming a file |
| Shadow mode only | No protection gain |
| Report every match | 38 standing medium and high findings on this host from the monitor itself |

Jev (jev-1.14.0, metadata only, `scripts/reviews/community_rules_advisory.py`), advisory:
own-launch ledger first 0.59, learning 0.31; add the ledger later 0.76; a learning week on
its own acceptable 0.22; top validation gap more hosts 0.43, imitation of a learned shape
0.41. **Effect on the work:** learned shapes were made a standing finding that stays until
reviewed (`jarvis rules`, `jarvis rules reviewed`, `jarvis rules forget KEY`) instead of
being reported once, and the ledger is recorded as the next build. Jev did not favour the
design that shipped; the deterministic evidence for shipping it is the replay above and
the tests, and its limit is stated in the register.

**Why not through the signed rule-pack channel yet.** No signer is pinned
(`rulepack.PINNED_SIGNERS` is empty, so no pack can become active) and a pack is capped at
256 KiB and 500 regular-expression rules; the compiled file is 741 KB of a different form.
The rules ship as reviewed data inside the signed release. Extending the pack format to
carry this form is a follow-up.

**The gate.** `scripts/security/atomic_floor.json` records the measured counts for the
pinned index. CI fetches that index by commit, checks its hash, and fails when fewer tests
are caught, when a benign command raises a finding, or when a detector crashes.

**Still open from the five-part list:** PowerShell script-block ingestion (2), registry
family state watch (3), content scanner beyond the operator-installed YARA path (4), real
execution in the VM lab (5, second half), and the own-launch ledger above.

### Correction after the full test suite (same day)

The existing rule-table tests caught three problems in the first cut, all fixed before merge:

1. **Medium-level rules flag single ordinary commands** (one `whoami`), which this product
   reports only as a burst. Only high and critical rules are used now: **582 rules**
   (435 Windows process, 118 registry, 29 Linux). The benchmark with them is
   **620 of 1,745 (35.5%)**: Windows 555 (42.0%), Linux 65 (15.4%); built-in alone 392
   (22.5%). The 57.1% above needed the medium rules and is not what ships. On the real-history
   replay the trimmed set fires 12 rules 2,436 times (the monitor's own PowerShell), 12
   shapes are learned and no alert follows. The floor file records 620.
2. **A community finding quoted the command line**, which can carry a password. Community
   findings never quote it now.
3. **Stored findings lose their `origin` key**, and the automatic-response gate read only
   that key, so a stored rule-content finding of high severity could have been treated as
   built-in. The title now carries the mark and the gate reads either
   (`core.finding.content_origin`). This also closes the same latent gap for signed
   rule-pack findings.

A replay runs the built-in rules only unless it asks for community rules, so the coverage
map's probes and benign look-alike controls keep measuring the built-in table. Community
rules hit 7 of those 195 curated look-alikes (for example `powershell -ep bypass -file
build.ps1`), which is the kind of activity the per-install learning exists for.
