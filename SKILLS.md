# JARVIS agent skills

## Default: TypeSafe/Jev advisory review

For every non-trivial coding task, load and follow
`.agents/skills/typesafe-ai/SKILL.md`. Use `jarvis.response.jev` as the project
client. This is the default workflow, not an optional enhancement.

1. Establish deterministic security, privacy, evidence and rollback constraints.
2. Ask Jev one narrow typed question over the minimum metadata required.
3. Keep credentials, source, patches, command lines, raw telemetry, private content
   and protected-user data local.
4. Treat the result as advisory. Unavailable or uncertain output fails safely and
   cannot grant authority.
5. Implement and verify with focused tests, the full suite, relevant lint/build
   checks and direct runtime evidence.

Jev may rank, route or identify ambiguity. It may never approve, authorize, execute,
deploy, remediate, suppress evidence, alter a security score, weaken a test, or
override `docs/security/MAXIMUM-ASSURANCE.md`. The API key is read only from
`TYPESAFE_API_KEY` or the owner-only `~/.jarvis/typesafe.env`; it must never enter
the repository or model state.
