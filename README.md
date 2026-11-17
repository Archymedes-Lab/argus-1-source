# ARGUS-1 — source preview

**Unmerged, unreleased source preview.** This repository publishes a reviewed
selection from proposed upstream PR #51 at commit
`bbea895096685700cf9753931ef67caea63c7dde`. The upstream merge is still blocked
by required checks. This preview does not represent an approved merge, signed
binary release, deployment or verified protection of any machine.

ARGUS monitors processes, persistence, configuration and security evidence on
Linux and Windows/WSL. The source includes the Python engine, desktop interface,
native sensor code, hosted-service code, synthetic tests and build tooling.
GitHub Actions is disabled for this review repository; its CI definition is
source for inspection, not an active release or approval gate. Some upstream
pipeline tests reference withheld internal inputs and are not claimed to pass
in this selected preview.
See [PUBLICATION.md](PUBLICATION.md) for the source boundary and validation.

## License and commercial use

Project-owned material uses **PolyForm-Noncommercial-1.0.0**. This is
source-available, not open source. Read [LICENSE.txt](LICENSE.txt),
[LICENSING.md](LICENSING.md) and [COMMERCIAL.md](COMMERCIAL.md). The standard
terms permit the listed government and nonprofit institution uses; other
commercial purposes require separate permission from the authorized rights
holders. Earlier AGPL grants remain valid. Third-party components retain their
own licenses and notices in [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt).

## Inspect and test

Use Python 3.12+ in a disposable development environment. A help-only smoke is:

```bash
python3 -m jarvis --help
```

The core uses the Python standard library; optional features have additional
requirements. Development requirements are pinned in `release/` and
`scripts/security/`. Use Bun for the desktop UI and Workers. Hosted deployment
configuration and production credentials are intentionally absent; configure
your own resources before attempting any deployment.

```bash
python3 -m unittest tests.test_licensing tests.test_public_contributor_ci
scripts/dev/static_gate.sh
```

Installation scripts can install services or request elevation. Review them
before use; do not run privileged or adversarial scenarios on personal data.
The [Maximum Assurance directive](docs/security/MAXIMUM-ASSURANCE.md) and
[verification ladder](docs/architecture/VERIFICATION-LADDER.md) distinguish
implemented behavior, tested invariants and remaining limits. Collector health
and scores are not compromise verdicts or security guarantees.

## Contribute

Use [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md) and
[SECURITY.md](SECURITY.md). Vulnerabilities, private logs and customer evidence
belong outside public issues. Public-source contributions do not grant release
keys or deployment access. Official identity follows [TRADEMARKS.md](TRADEMARKS.md).
