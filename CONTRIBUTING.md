# Contributing to the source preview

This is an unmerged review snapshot, not the protected upstream main branch.
Propose narrowly scoped changes through pull requests. Explain the user outcome,
invariants, success and failure cases and remaining blind spots. Use synthetic
fixtures and preserve third-party notices. Report vulnerabilities privately via
[SECURITY.md](SECURITY.md), not public issues or attachments.

Contributions use PolyForm-Noncommercial-1.0.0 and retain author copyright.
Include a Developer Certificate of Origin 1.1 sign-off using `git commit -s`
with an address you are willing to publish. DCO certifies provenance; it does
not grant separate commercial relicensing rights. Before merging externally
copyrighted contributions, maintainers need a reviewed grant or existing license
supporting the intended commercial offering, including documentation, rules and
assets. See [the rights policy](docs/commercial/CONTRIBUTOR-RIGHTS.md).
Until that grant exists, do not merge the contribution. No executed CLA or
copyright assignment is assumed.

Use Python unit tests, the static gate and Bun commands for Bun projects.
Run tests with an isolated scratch HOME and synthetic data. Preserve source
freshness, identity, evidence continuity, privacy, resource bounds and recovery.
Keep AI review metadata-only and advisory. Do not send keys, source patches or
private security evidence to remote models. The project Jev client reports
unavailable when no credential is configured; do not weaken tests to get a result.

The included CI definition has read-only permissions, hosted runners, pinned actions and no
production secrets. Maintainers review untrusted workflow changes before
approving fork execution. Required check success does not grant merge or release
authority. No release/publish workflow or automatic private-to-public mirror is
included. Contributions to this preview do not merge themselves into upstream.

GitHub Actions is disabled in the public preview. Enabling any automation needs
a separate review; this publication does not enable it or claim CI success.
