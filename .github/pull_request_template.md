## What and why
<!-- One or two sentences. Link the issue if there is one. -->

## Invariants (AGENTS.md; delete for docs-only)
<!-- What must stay true: evidence, privacy, bounded resources, recovery, rollback, authority. -->

## Proof
- [ ] `python3 scripts/dev/fasttest.py` (or the pre-push hook) green locally
- [ ] Failure paths tested, not only the happy path
- [ ] `jarvis/core/assurance.py` updated if a capability or its evidence changed
- [ ] Live/runtime check, or "not live-verified" stated plainly below

## Not done / blind spots
<!-- What this does not cover; what the other cofounder should look at first. -->
