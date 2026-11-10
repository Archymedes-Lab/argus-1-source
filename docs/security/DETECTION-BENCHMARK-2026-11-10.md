# Does it catch attacks? First independent detection benchmark (2026-11-10)

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

It is an **upper bound for the command-line and registry rule layer**, and a lower bound
for the product:

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
