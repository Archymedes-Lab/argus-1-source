# Branch audit, 2026-11-10

All three configured GitHub remotes fetched. Counts are patches not present on main
(git cherry); patch differences alone do not establish missing functionality.

| Branch | Unique patches | Disposition |
|---|---:|---|
| `org/desktop-senses-and-updates` | 1 | Older variant; main contains later senses/update work |
| `org/feat/close-measured-detection-gaps` | 3 | Active measured-gap PR #38; reviewed and tested separately |
| `org/feat/ui-two-rooms-redesign` | 5 | Integrated here, with review repairs and provenance preserved |
| `org/feature/plain-language-pricing-geo-world` | 3 | Superseded by newer main browser pairing, including monotonic expiry and Unicode digest guards; do not regress |
| `org/fix/licence-retry-and-faster-state` | 2 | Already included by UI branch merge ancestry |
| `origin/Intern/Evan/Contributions` | 7 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `origin/defensibility/licensing` | 9 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `origin/easy-install` | 6 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `origin/feat/polar-desktop` | 1 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `origin/jarvis-mobile` | 1 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `origin/mobile-backend` | 4 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `argus1/checkout/main-20261103` | 1 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `argus1/ci/cut-minutes` | 1 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `argus1/feat/commercial-licence` | 1 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `argus1/feat/osquery-crossview` | 1 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `argus1/feature/normal-pro` | 1 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `argus1/feature/ollama-install` | 1 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `argus1/feature/screen-guard` | 1 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `argus1/fuzz/early-20261104` | 1 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `argus1/native-hosts` | 3 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `argus1/release-test/fast-path` | 2 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `argus1/release-test/windows-installer` | 1 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |
| `argus1/wip/checkout-20261103` | 1 | Historical or independent feature experiment; inventoried, not approved as part of this UI/detection release |

Also inspected all local heads by commit date. The owner working tree contains
uncommitted desktop/updater/release changes; these are preserved and cannot be
claimed as integrated or release-tested. No untracked file was silently added.

The plain-language branch would roll back main security hardening if its files
were copied wholesale: one-time browser-link expiry uses wall time there, while
main uses monotonic time; digest comparison there lacks the Unicode-safe guard.
Ancestry, not copying old file versions, preserves the newer protections.
