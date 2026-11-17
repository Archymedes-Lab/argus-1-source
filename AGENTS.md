# Source-preview engineering requirements

Read docs/security/MAXIMUM-ASSURANCE.md and the public normative portions of
docs/security/ARCHYMEDES-SECURITY-STANDARD.md before edits. Preserve privacy,
evidence continuity, sensor freshness, identity/cursors, resource bounds,
recovery, rollback and explicit action authority. Record invariants and credible
alternatives before non-trivial changes. Add success and refusal regression cases.

Use `python3 -m unittest discover -s tests` and `scripts/dev/static_gate.sh`.
Use scratch HOME and synthetic fixtures. Do not run adversarial scenarios on a
protected workstation, deploy services, install a privileged broker or change
Windows policy without the machine user's explicit authorization.

Use the project Jev client for bounded metadata-only advisory review of nontrivial
changes when available. Credentials come only from its approved local loader;
never print, copy, commit or send credentials or private evidence to a model.
Jev cannot authorize actions, override policy, certify protection or replace
runtime measurements and deterministic validation. Keep unavailable/uncertain
results explicit. Never change the assurance register without corresponding evidence.

Use Bun commands for Bun projects. If future Convex work supplies `convex:dev`,
start or reuse its healthy watcher before making Convex-backed changes.

This is an unmerged source preview. Do not claim upstream merge, release signing,
installed-app validation or protection based on this publication. Do not bypass
upstream required checks or automatically synchronize private files here.
