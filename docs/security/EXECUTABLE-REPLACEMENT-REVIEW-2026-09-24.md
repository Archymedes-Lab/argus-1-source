# Deleted executable reconciliation, 2026-09-24

The live process scan reports one high deleted executable mapping for Sysmon.
The hidden-process collector already checks whether a deleted mapping was
replaced by byte-identical installed code; the process scanner does not. The
unprivileged host account cannot read either executable, so equality on this
host is unverified. No current finding may be cleared from that fact alone.

## Invariants before editing

- Preserve the original `/proc` executable path and the scan evidence. A
  matching replacement can change a *derived* verdict only.
- Deleted, unreadable, missing, changed, oversized, or racing files remain
  suspicious. A path or process name alone never establishes trust.
- Bind the comparison to the same PID instance and the same on-disk file
  throughout the read. A PID reuse or file replacement fails closed.
- Bound bytes and candidate count per scan, with no hash or file content in
  findings, telemetry, Jev state, or logs.
- Other process traits retain their severities. A byte match for the main
  executable does not validate its arguments, libraries, mapped code, or origin.
- Compare the installed runtime hash, fresh process scan, and live score after
  an authorized narrow release. A test or advisory judgment is not live proof.

## Designs considered

1. Exempt the known Sysmon path: cheap, but path identity can be spoofed and
   bypasses evidence.
2. Leave the process and hidden collectors divergent: no implementation cost,
   but contradictory findings consume review time.
3. Share a bounded byte-and-identity verifier between collectors, and carry
   only a verified boolean into process scoring: selected. Unknown results
   preserve the high finding.

The shared comparison should be attempted only for a small number of deleted
executables per process pass. Its resource cost is two bounded file reads per
candidate; all other processes incur no hash work. Reconsider if this adds
material latency or if a platform-specific identity check is needed.

Jev's metadata-only Choice favored the shared verifier (confidence 1.0). Its
Noul probability for keeping the finding when verification fails was 0.79.
These are advisory and do not authorize lowering any live finding.

## Implementation and validation

`jarvis/platform/executable_identity.py` checks two bounded byte digests,
the process start time and executable link before and after, and the installed
file's inode, size, and modification metadata before and after. It rejects a
symlink at the installed path, non-regular files, unreadable files, and files
over 16 MiB. The Linux process collector checks at most four deleted main
executables per pass (at most 128 MiB read in total); unchecked cases retain
the deleted-binary trait. The hidden-process collector now calls the same
verifier. The process record carries one boolean; the raw `/proc` path remains.

Focused host tests cover identical reinstall, changed and removed files,
process identity change, installed-file swap during hashing, size limit,
scoring fallback, and candidate exhaustion. The existing hidden-attribution
suite also passed (18 cases). Ruff passed on all changed files. The final
staged-source full suite passed 1,341 tests on the real host after the last
race test; the earlier checkout suite passed 1,340 before that test was added.

Jev's implementation review selected fresh privileged runtime proof as the
largest remaining validation gap (Choice confidence 0.93); its Noul for the
failure fallback was 0.89. The unprivileged host cannot read either Sysmon
binary, so the live score effect is unknown until a sealed release is switched
by an authorized administrator and a fresh scan is measured.

The combined owner-controlled release stage is
`/tmp/jarvis-netwatch-narrow-20260924`, commit
`8c28d311bd58e91f56c0a0fd468a0b84d842ddad`. An unprivileged build with
the sealed packer added the verifier and two regression files, changed six
runtime files (including a conservative assurance-register update), removed
none, and reported a clean source. The stage also contains the prior tested
network-switch correction. No root-owned release has been switched.

## Live release readback and size correction

The owner switched the staged release. `/opt/jarvis/current` now points to
`20260924T151932Z-8c28d311`; its verifier hash matches the staged source and
`jarvis.service` is active with zero restarts. Fresh scored coverage is 100%,
but the hidden collector still reports Sysmon PID 455's deleted main mapping
as critical. The owner performed a privileged read-only check: SHA-256 of
`/proc/455/exe` and `/opt/sysmon/sysmon` both equal
`3e25a035fdff4b3136371cdea9714411c2a29ff37de2844ddfa3395967509931`.
Both files measure 31,693,824 bytes, exceeding the verifier's 16 MiB ceiling.
Matching bytes support an unchanged reinstall; they do not certify all of
Sysmon's libraries, configuration or current behavior.

The next narrow candidate raises the per-file limit to 32 MiB and cuts
process-scan attempts from four to two: at most 128 MiB read per pass. The
hidden collector also limits attempts to two and caches repeated mappings.
Missing, changed, racing, or over-budget files continue to report deleted
mapping evidence. Jev's metadata-only Choice favored the raised limit with
the reduced attempt count (confidence 0.88) and selected fresh runtime
verification as the required next gate (confidence 1.0). This is advisory;
focused tests and live collector evidence govern classification.

The candidate is isolated at `/tmp/jarvis-sysmon-size-narrow-20260924`, clean
commit `f3fc9ee`. The focused host suites passed 27 tests and the staged-source
full suite passed 1,343 tests. A disposable build from the sealed packer
changed exactly three runtime files and two regression files; it added and
removed none. The administrator release switch and fresh service scans remain
necessary before claiming that the critical finding has resolved.

### Installed readback

The owner switched `/opt/jarvis/current` to sealed release
`20260924T154835Z-f3fc9ee1`. The manifest records the clean `f3fc9ee1`
source and exactly the five reviewed changes; the three installed runtime
file hashes match the manifest. `jarvis.service` is active with zero restarts,
and `/api/health` reports live, healthy, ready and protection healthy.

The first post-release `hidden` snapshot and the explicitly queued
post-release `deep_hidden` snapshot both classify Sysmon PID 455's deleted
main mapping as an identical replacement at low severity. Neither has a
critical deleted mapping. Their result verifies the specific bounded
comparison in the protected service; it does not prove Sysmon's full runtime
integrity. Scored collector coverage is 100% at this readback.
