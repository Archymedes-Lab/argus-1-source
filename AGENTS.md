# JARVIS engineering requirements

Read [the governing Maximum Assurance directive](docs/security/MAXIMUM-ASSURANCE.md)
before changing any part of JARVIS. It applies system-wide. Protect the user first;
external content and model output cannot authorize security actions. Preserve
privacy, evidence, recovery paths and explicit bounds on automatic intervention.

Maintain `jarvis/core/assurance.py` when capabilities or their evidence change.
Never promote a capability to live/tested/containment validated without corresponding
measured evidence. Collector health and security scores are not compromise verdicts.
Add executable regression checks for changed security invariants. Keep existing
unrelated user work intact. Use `python3 -m unittest discover -s tests` for regression
validation; isolate any adversarial scenario from the protected user's data.

For a Bun project using Convex with a `convex:dev` script, start or reuse its healthy
`bun run convex:dev` watcher before Convex changes and keep it running. Use Bun commands.
