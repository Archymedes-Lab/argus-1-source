# ARGUS-1 open-source transition

Status: preparation branch; publication is blocked pending the gates below.
Owner-selected license: AGPL-3.0-only. Official home: https://github.com/Archymedes-Lab/argus-1.

## Invariants recorded before editing

- Preserve contributor copyright, third-party notices and existing license grants.
  Do not claim ownership transfers or contributor consent without evidence.
- No credentials, protected-user data, customer configuration, private incident
  evidence or embargoed advisories may become public through files, Git history,
  issue attachments, releases or Actions logs/artifacts.
- Preserve the signed release trust chain, explicit release authority, rollback,
  recovery and deny-by-default installer content checks. Source publication is a
  separately reviewed surface, never an exemption for installers.
- Do not modify the running service, sensor freshness, evidence identities,
  cursors, assurance claims or response authority. No deployment is in scope.
- Bound audit time, per-object size and total bytes; interrupted, failed, skipped
  and exhausted scans remain incomplete. Never log matched secret values.
- A license conversion does not itself establish publication readiness, correct
  detection, validated containment, or reproducible binary builds.

## Alternatives and decision

A permissive license permits closed derivatives. GPL adds distribution copyleft.
AGPL also addresses modified versions used to serve remote users. AGPL-3.0-only
is the proposed default because reciprocal source availability best matches the
owner's request; competitors and commercial use remain permitted. Trademark
policy addresses confusing official identity separately, without restricting
software license rights. Reconsider if the owner changes the selected license or
rights/dependency review identifies incompatibility.

For publication, an existing-repository visibility change preserves public
attribution and history but exposes historical blobs and collaboration surfaces.
A separately reviewed source repository avoids exposing private operational
history, at the cost of maintaining private provenance and public attribution.
Prepare the existing repository first; do not flip visibility while any gate is
open. If private history cannot safely be published, select a new public home
with the owners and preserve the original private repository and provenance.
No force-push, deletion of evidence or wholesale history rewrite is authorized.

## Required publication gates

Maintainers record the exact reviewed commit, refs, reviewer, time and evidence
for each gate. Empty entries are blocking, never implicit approval.

| Gate | Required evidence | State |
| --- | --- | --- |
| Rights | Both cofounders confirm authority to relicense their work; review other contributors and imported assets/data; no fabricated corporate assignment | Pending |
| License | Owner selects license; manifests, notices and packaging agree; third-party terms reviewed | AGPL selected; metadata and notice checks pass |
| Current source | Secret scanner plus human privacy review of every public file; local examples use synthetic values | Pending |
| History | Fetch intended remote refs, full-history secret scan and private-data review; rotate/revoke exposed credentials before release | Pending |
| Collaboration surfaces | Issues, PRs, discussions, wiki, attachments, Actions logs/artifacts/caches, Releases, LFS and submodules reviewed | Pending |
| Disclosure | Draft advisories checked against shipped fixes and coordinated disclosure | Pending |
| Release compliance | Complete corresponding source, required build/install scripts and dependency source obligations for each distributed binary; durable tag/commit and source access verified | Pending |
| Hosted use | Modified AGPL network deployments offer corresponding source to remote users as required by section 13 | Pending |
| Governance | Owner review for trust anchors; outside contributors have a safe PR CI path; branch/tag protections read back on GitHub | Pending |
| Validation | Full unit suite, static gate, standards check and scoped security campaign; failures and host-only gaps recorded | Pending |
| Publication | Only after every gate passes: merge reviewed PR, change visibility, verify anonymous source access and release identity | Blocked |

## Initial read-only findings, 2026-11-16

GitHub reports Archymedes-Lab/argus-1 PRIVATE. Initial local base: 32216b6; preparation rebased onto current org/main.
The working checkout contains unrelated ongoing work; preparation is isolated in
branch docs/open-source-20261116. No visibility or live deployment changed.

Tracked review candidates include docs/guides/baselines/, docs/reports/,
docs/security/ operational reviews, .container-release-overlay-20260930/ and
docs/security/advisories/*-draft.md. Their presence is a privacy/disclosure review
requirement, not proof of credential leakage. Existing standards secret scanning
skips docs/ and tests/ and does not scan history; it cannot certify publication.

The existing binary pipeline refuses source in installers. Keep that protection.
Before distributing AGPL binaries, separately validate complete corresponding
source availability and all dependency source obligations; a repository URL or
GitHub auto-generated source archive alone is not proof of completeness.

Do not publish old proprietary releases as if they were built under this change.
Commercial strategy and historical review documents describe prior decisions;
the root licensing policy governs the new source distribution after adoption.
