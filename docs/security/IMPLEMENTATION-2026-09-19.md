# Maximum assurance implementation record — 2026-09-19

## Scope delivered

The governing contract is `MAXIMUM-ASSURANCE.md`, linked by root `AGENTS.md` and
README. It applies across all components and records explicit safety invariants,
graduated intervention, online/credential protection, provenance, causal state,
attestation, sensor distrust, forensic privacy, Forge, performance, supply chain
and verified recovery. It does not assert completion of those capabilities.

Implemented changes:

- `jarvis/response/defense.py`: commit action intent before execution; interrupted
  actions stay attempting/uncertain and cannot be approved or automatically repeated.
  Corrupt history inhibits mutation. Existing undo behavior and evidence remain.
- `jarvis/response/privacy.py`: minimize recognizable secrets, authorization values,
  private keys and URL paths/queries before model input, including example turns.
- `jarvis/response/llm.py`: only the fixed loopback Ollama origins are permitted;
  Python requests bypass environment proxies and reject redirects. Windows bridge
  requests reject redirects. Models still return advisory text with no action path.
- `jarvis/core/assurance.py` and `jarvis/service/protection.py`: health includes a
  conservative 15-domain engineering register, explicit unknown validation/latency,
  blind spots and no assertion of complete assurance or validated containment.
- `jarvis/response/actions/*` and `jarvis/response/defense.py`: interrupted
  containment actions now have read-only recovery probes.  A probe may restore
  an undoable `applied` state only when it can prove the actual state and safe
  rollback record; otherwise JARVIS preserves `uncertain`/`not_applied` and
  never repeats the action automatically.

## Validation and deployment

Focused tests exercise model transport restrictions, redaction across roles,
healthy-collector versus complete-assurance distinction, committed intent visible
from another database connection, interrupted action retry inhibition, and corrupt
history / failed audit writes preventing mutation.

The initial full regression run executed 676 tests with one failure: redaction
originally imported a collector from core, violating the repository dependency
layers. Moving redaction into response fixed the layer tests. Final results are
recorded below.

The live service was active; its health endpoint reported live/healthy/protection
healthy but no assurance field. That is evidence of the previous running version,
not deployment of this work. Other geographic and sensor changes were already
present or appeared concurrently; they have been preserved. No restart is performed
as part of this change while concurrent implementation is in progress.

## Required follow-through and acceptance gates

1. **Safe action execution:** atomic target identity, cross-process serialization,
   complete write-ahead rollback tokens, bounded leases and essential-service /
   emergency/accessibility exceptions. Test kill/power loss at every mutation
   boundary; demonstrate idempotent recovery without overwriting user data.
2. **Trustworthy telemetry:** native deployment, authenticated sensor identity,
   monotonic sequence/anti-replay and independent coverage comparison. Suppression
   must become visible within a documented measured deadline.
3. **Human online protection:** least-privilege browser integration and local secret
   boundary checks. Validate phishing, OAuth, payment and remote-support scenarios
   without capturing real passwords, private communications or live wallet keys.
4. **Causality/provenance:** retain origin through extraction/execution, identify
   unrelated transitions as unexplained, and test missing/out-of-order events.
5. **Forensics and attestation:** encrypted evidence, protected keys, externally
   anchored integrity, TPM freshness and trusted baselines. Demonstrate detection
   of deletion, replay, sensor substitution and log rewrites.
6. **Forge/performance/supply chain:** isolated scenario manifests with expected
   telemetry, detection, correlation, protection, containment, recovery and latency;
   measured usability budgets; signed release provenance and verified rollback.

Never convert any gate into a completed coverage claim on the basis of this
policy document, an enabled configuration flag, a model answer or a passing unit
suite. Live containment/recovery and native Windows evidence remain separate gates.

## Final verification

- Full regression: `python3 -m unittest discover -s tests` — **685 tests passed**
  in 179.150 seconds. Includes concurrent checkout additions present at discovery.
- Focused architecture, assurance, assistant, defense and server suites: **68 passed**.
- Final defense tests, including empty/corrupt history: **26 passed**.
- Python compilation and `git diff --check`: passed.
- Ruff: unavailable (`No module named ruff`); no lint success claimed.
- Existing fixture ResourceWarnings appeared in email-triage/secret tests; tests passed.
- Live deployment of these changes: **not performed**; shared checkout has concurrent
  changes. Existing service was observed active and healthy on its prior version.

Test success verifies these tested invariants; it does not verify complete browser,
kernel, firmware, hardware attestation, containment or recovery coverage.
