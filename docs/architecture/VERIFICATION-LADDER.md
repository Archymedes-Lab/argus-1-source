# Verification ladder (2026-10-21)

The owner asked for JARVIS to become static-analysis based, with levels of formal
verification. This records the ladder, what each rung proves and does not prove, what was
built today with its measurements, and the order for the rest. The
[Maximum Assurance directive](../security/MAXIMUM-ASSURANCE.md) still governs: a proof about
a model is evidence about the model, never a compromise verdict about the machine.

## Invariants the ladder guards

Written before the code, from the existing design documents:

| Id | Invariant | Where it was prose | Rung |
| --- | --- | --- | --- |
| V1 | Score is in 0..100; a blind area reads 0; losing a collector never raises the score | score-integrity, SCORE-STABILITY-REVIEW | L1 |
| V2 | Adding a finding never raises the score; the same fact twice counts once | score.py docstrings | L1 |
| V3 | Stale or incomplete observations never count as evidence and are listed as degraded | SPYWARE-REASONING #1 | L1 |
| V4 | Adding positive evidence never lowers a verdict | SPYWARE-REASONING #5 | L1 |
| V5 | A valid signature never raises an input watcher's severity; exit never launders it; JARVIS's own supervised hook never counts | watchers.py docstring | L1 |
| V6 | Under a declared privacy seal, any reopen, policy override or use is reported high by the next collection; an intact seal never alarms; nothing is reported without a seal | PRIVACY-SEAL | L2 |
| V7 | A release staged on a base that is no longer live is refused; rollback restores the previous release | DEPLOY, EVIDENCE-FABRIC P1/P5 | L2 |
| V8 | A due fast-lane job never waits behind a main-lane job; protection jobs are in the fast lane | LANE-FAIRNESS | L2 (abstract) |
| V9 | Every collector is declared once with a complete contract (scored or unscored with a reason, budgets below interval, no governed tier 0 or fast-lane job, lane duty under 0.8); every mechanism primitive names existing code and tests | MECHANISMS | L1 (declarations; files where tests/ ships) |

## The rungs

**L0, static analysis (built).** `scripts/dev/static_gate.sh`.
ruff now selects pyflakes, syntax, import order, bugbear and pylint-error classes
(`pyproject.toml`). Fixing the gate found two real defects: a closure capturing an `except`
target after the clause ends (`fixdraft.py`, would have raised NameError on the failure path)
and a duplicated entry in a vetting set. mypy runs on the pure packages (`core/reasoning`,
`core/execution`, `response/reporting`, `verify`) with transitive imports followed silently, so
the typed set grows package by package. Six type errors were fixed on the way. Both gates
read clean at the end of the day.

**L1, property checks (built).** `jarvis/verify/props.py`, `tests/test_verify_props.py`.
Standard library only: a seeded generator, a fixed number of cases, replayable by seed and
index, no shrinking (cases are kept small by construction instead). Jev put "adequate first
rung rather than a reason to add Hypothesis" at 0.84. Ten properties over V1 to V5, 150
cases each. The first run **falsified an over-claim**: points in the reasoning engine are not
monotone, because a capture capability explained by the subject's own publisher turns its
autostart and network companions into "part of being that product", so the chain points drop
while the verdict rises. The documented invariant is about the verdict; the property now
states exactly that, and points-monotonicity only for non-capture evidence.

**L2, exhaustive model checking (built).** `jarvis/verify/mc.py`, `jarvis/verify/models/`.
A breadth-first explicit-state checker: every reachable state, every invariant, shortest
counterexample path, bound reported rather than hidden, optional deadlock freedom.
Self-tests plant a violation and check the path. Three models:

| Model | Drives real code? | States | Transitions | Result |
| --- | --- | --- | --- | --- |
| privacy seal lifecycle (V6) | yes: `privacyseal._seal_findings` | 71 | 283 | exhausted, no violation |
| release switch (V7) | yes: `deploy_root_runtime.check_expected_base`, `release.release_id` | 57 | 152 | exhausted, no violation |
| scheduler lanes (V8) | no: policy model; membership asserted against `scheduler.FAST` | 98 | 165 | exhausted, no violation |

A planted-bug test weakens the seal detector (ignores a reopened desktop value) and the
checker produces the counterexample `seal, reopen_desktop, collect`. Jev rated driving the
checker through the real pure functions as the stronger evidence at 0.82, and the abstract
lane model as adding meaningful assurance at only 0.64, which is honest: it pins the shape
of the claim, not the code.

**L3, model-checked specifications (not built).** TLA+ or Alloy for the real scheduler
selection (lateness, starvation, forced cooldown, governor deferral), the broker handshake,
and the evidence hash chain with its cursor commit points. Java is present on this machine,
so TLC can run locally; the specs would live beside the models with the same invariants.
Jev's pick for the next rung was the scheduler model (0.43, low concentration).

**L4, refinement proofs (not built).** Dafny or Lean for the pieces where a bug is a safety
bug: response-ladder gating (auto versus propose), the severity lattice, the hash chain. The
Python stays the tested twin of the verified artefact.

**L5, boundary contracts (partly in place).** The PowerShell and ETW parsers cannot be
proven; they get schema validation on output (`_valid` in each collector) and measured
positive controls. Today's polling-keylogger probe is the pattern: the claim "1003 is
visible" is held only by a measurement, re-runnable by anyone.

## What the ladder does not say

A clean L0 gate is not type safety for the whole tree; only the listed packages are typed.
A property that passes 150 seeded cases has not been proven; it has survived a search. An
exhausted model proves the model, within its abstractions, each listed in the model's
docstring: one capability, bounded uses, discrete ticks, no filesystem, no lock. None of it
observes the live machine; the register in `assurance.py` keeps that distinction.

## How to run

```
scripts/dev/static_gate.sh            # ruff, mypy, L1 and L2 tests
scripts/dev/static_gate.sh --quick    # ruff and mypy only
python3 -m unittest tests.test_verify_models -v
```

## Order for the rest

1. Widen `TYPED` in the gate script one package at a time, fixing as it goes (Jev 0.25).
2. Scheduler model against the real `_due` with injected clock, reliability and governor, in
   the in-tree checker first; promote to TLA+ when the state space outgrows it (Jev 0.43).
3. Response ladder model: every action's auto-eligibility across severity, coverage and flag
   combinations, exhaustively (Jev 0.15).
4. Hash chain and cursor commit model (Jev 0.11).

## 2026-10-22: the ladder ships inside the product

Owner request: static analysis and formal verification in Argus (the public build of
JARVIS) by default. What changed:

- **The property catalogue lives in the package** (`jarvis/verify/properties.py`, eleven
  properties over V1 to V5, 150 cases each). `tests/test_verify_props.py` now runs that
  catalogue; the catalogue is the single definition.
- **A runner and command**: `python -m jarvis.verify [--json PATH] [--cases N]` runs every
  property and exhaustively checks the three models over the installed files, prints a
  report and exits 1 on any failure. Standard library only, 0.3 s on this machine
  (11/11 properties, 1650 cases; 3/3 models, 226 states).
- **A daily `verify` job** (`jarvis/service/verifyjob.py`, bulk lane, governor-deferrable,
  Monitoring area) repeats the run and records it in the store (`code_verification_v1`).
  A failure is a *high visibility* finding about JARVIS itself ("Installed code violates
  a verified invariant"), never a verdict about the machine. The job loads
  `jarvis.verify` at run time because that package sits above every layer it exercises
  (`tests/test_layers.py`).
- **Argus build gate** (`~/archymedes-site/scripts/argus/build.py`): every build runs ruff
  and mypy (the same selection as `scripts/dev/static_gate.sh`) and `python -m argus.verify`
  over the renamed tree, refuses to package on failure, and records the results under
  `verification` in `manifest.json`. `--skip-verify` packages anyway and records the
  failure; `--worktree` builds the working copy as a tree object without a commit.
- **Install-time gate**: the Windows and Linux installers run `python -m argus.verify` over
  the files they just installed and refuse (Linux: keep the previous install) when it
  fails; the report is kept beside the program. `-SkipVerify` / `--skip-verify` override.

What a pass means: this copy keeps the eleven stated properties on the generated cases and
no reachable state of the three models breaks its invariant. It says nothing about
inputs or states the catalogue leaves out, and nothing about the machine being monitored.
Still not built: L3 (TLA+/Alloy specifications) and L4 (refinement proofs).
