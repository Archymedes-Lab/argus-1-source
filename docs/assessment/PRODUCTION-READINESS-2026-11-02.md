# ARGUS-1 production-readiness assessment (2026-11-02)

Scope: the product line `argus1/main` at `5fe1588` (local `main` in `~/jarvis` is 68 commits
behind it and was not assessed), the shipped release `v2026.10.30-2`, the public site, CI.
Method: three independent read-only reviews (security; architecture and code quality;
operations, release and UX), my own measurements, web research on fleet agents, and
real-container probes. Every claim below was checked against code or a measurement; the two
High security findings were re-verified by hand.

## Verdict

**Production-ready for a supervised, founder-installed Linux server review. Not ready for
self-serve general availability, and not ready for many-computer deployment.** The engineering
core is unusually disciplined; what is missing is mostly the layer that lets a stranger install,
upgrade, trust and run it on a machine its developer has never seen.

| Area | Grade | Why |
|---|---|---|
| Engineering discipline (tests, registers, gates) | A- | 3,738 tests; registry, capability register and release gate are test-enforced; mutation checks catch breaks |
| Release integrity | B+ | CI-only, digest-pinned, hash-locked, signed (signature verified live); one releaser key, no build provenance attestation, installer does not verify signatures itself |
| Security of the local API and privileges | B | Credential on every route, loopback only, Host check, strict CSP, SYSTEM broker with ACL checks; per-user installs let same-user malware ack its own findings |
| Evidence integrity | B | Event log refuses to move past lost data; one Linux Sysmon cursor bug (fixed today); history stops for good at 2 GiB |
| Robustness | C+ | 69 of 72 collectors share threads (one hang stalls a lane); ad-hoc schema migrations, no integrity check or repair |
| Portability / many computers | D (before today) → C | Three host kinds only; macOS misread as Linux; owner paths in the release; phase 1 of the target architecture built today |
| Operability | B- | Health, metrics, alert channels, dead-man, good docs; documented Prometheus scrape gets 403; failed upgrade leaves the server unwatched |
| Supportability and legal | D | No security.txt, changelog or support contact; licence/EULA work exists on branches, not on main |
| Windows end-user product | D | No protection edition ships; desktop app is unsigned (SmartScreen, Smart App Control) |

## Measured facts

- Code: `jarvis/` 92,001 Python lines in 443 files; tests 46,653 lines, 246 files, 3,738 test
  methods; release 1,900; desktop 2,949; rust-runtime 1,521; hosted 1,742.
- Registry: 72 collectors, 3 isolated; capability register 54 entries (25 partial, 29
  unverified, 0 live-tested or containment-validated).
- Runtime dependencies: 3 (cryptography 50.0.2, cffi 2.1.1, pycparser 3.11), hash-pinned;
  OSV: no known advisories (queried 2026-11-02).
- CI on `main`: green after a re-run on 2026-11-02 (python, desktop-ui); billing is fixed.
- Release `v2026.10.30-2`: site manifest, GitHub assets and SHA256SUMS agree; signature
  verifies against the published key; tarball downloads (HTTP 200).
- Static gate green on the product line; full suite on this branch: see the commit message.
- Host stability on the development machine: Windows restarted uncleanly 3 times on
  2026-11-02 (Kernel-Power 41), once during a VM test; this limits what can be soaked here.

## Strengths worth keeping

- One collector registry (`core/mechanisms.py`) with golden and conformance tests; one
  capability register (`core/assurance.py`) that cannot claim live validation without evidence.
- Clean layering: `core` and `platform` import nothing above them.
- Evidence-first event log: fsync, integrity walk, index rebuild, refuses to move a cursor past
  lost data; WAL, `synchronous=FULL` store.
- Bounded scheduler: leases, last-known-good snapshots, real deadlines for isolated jobs.
- Local API: 127.0.0.1 only, credential on every route including `/metrics`, constant-time
  compare, Host allowlist, HttpOnly SameSite=Strict cookie only to a same-uid peer, strict CSP.
- Windows broker: runs as SYSTEM with a rebuilt environment, admin-only script folder with
  owner/ACL/reparse checks before each run.
- Server unit: own account, three capabilities, `ProtectSystem=strict`, watchdog, memory cap.
- Release pipeline: SHA-pinned actions, `--require-hashes`, pinned manylinux image, content
  gate (no source, no bytecode, no home paths, no keys), install-and-purge test, manual signing
  with type-to-confirm, rollback workflow, SBOM, documented key-loss procedure.
- Honest product copy: "what it is not", scores are not verdicts, unknown is never clean.

## Findings, ranked

### Blockers for general availability

1. **Same-user malware can silence findings on per-user installs** (High). `POST /api/answer`
   acknowledges any finding, criticals included (`response/questions.py:124,155`), and acks are
   dropped from alerts (`response/reporting/notifications.py:147`). The per-user install and the
   desktop keep the token where any same-user process can read it. The server edition is not
   affected (token owned by the `argus` account, 0600). Fix: per-user installs move to the
   service-account model; acknowledging a critical needs an out-of-band confirmation.
2. **Linux Sysmon window skipped on a timed-out read** (High, **fixed today**). The cursor
   moved before the read (`sysmon_linux/run.py:208`); a 40 s journalctl timeout lost that
   window, and the syslog fallback read the whole file unbounded.
3. **Product not separated from the developer's machine** (High for many computers). A WSL
   drop-in naming one Windows account shipped inside the signed server release
   (`bin/systemd/service-user.conf`; not installed by any installer). **Fixed today**: the gate
   now refuses WSL-mounted Windows homes (it found exactly that one file) and the file is left
   out. Remaining: owner sudoers, watchdogs and repair scripts in the product tree; register
   evidence text describes one host.
4. **Hung collector stalls its lane** (High for unattended servers). Only 3 of 72 collectors
   run in a killable child; a lease detects a hung thread but cannot stop it.
5. **Failed upgrade leaves the server unwatched** (Medium-High). `install.sh` stops the
   service before verifying and, on a failed verification, restores the binary and exits
   without restarting; `VERSION` is already overwritten.
6. **Installer does not verify the signature itself** (Medium). It tells the user to; the
   self-verification it runs is executed by the binary being verified.
7. **No supportability basics on main** (Medium): security.txt (404), changelog, support
   contact, licence/EULA and third-party notices (on branches, not merged).

### Important, not blocking a supervised launch

8. Finding details leave the machine unredacted in email, webhook and ntfy alerts
   (`response/reporting/emails.py:33`); only model input is redacted.
9. Event history halts permanently at 2 GiB with no archive path; operators are not told.
10. Schema migrations are add-column-if-missing; no `user_version`, no `integrity_check`, no
    repair path for a corrupt store that also holds response authority.
11. Documented Prometheus scrape config has no credential and will get 403.
12. Desktop pairing docs name `local.jarvis.desktop`; the build renames it to `local.argus.desktop`.
13. No connection limit on the local HTTP server; one local process can exhaust threads.
14. Phone relay serves its own PWA code: whoever controls the Worker can ship code that reads
    the phone's keys (E2E protects against a passive relay only).
15. Typing covers ~2% of functions; mypy checks five packages. 214 functions with
    cyclomatic complexity > 20 (`telemetry/sysmon.py:628` audit: 280).
16. One releaser key; no Sigstore/SLSA provenance; host-bound tests are a laptop-signed attestation.
17. Source installs need Python 3.10+ (RHEL 9 ships 3.9) and `pyproject.toml` declares no
    `requires-python`; the native build is unaffected.

## Built today toward many-computer deployment (branch `feat/host-facts`)

Target architecture and phases: `docs/architecture/AGNOSTIC-DEPLOYMENT.md`. Phase 1:
- `jarvis/platform/facts.py`: measured host facts (file reads only, 64 KB cap, unknown stays unknown).
- `Collector.requires` + `REQUIREMENTS` in the registry; `schedule.applicable(facts=)` lists
  unmet collectors as "not on this host: needs …". Requirements name the observed thing, never
  the sensor (tested). Seven collectors declare requirements.
- macOS is reported unsupported and `serve` refuses to start there (it used to run as "linux").
- Release gate rule for Windows homes seen through a WSL mount; owner drop-in out of the server
  release; account name out of the shipped capabilities comment.
- Linux Sysmon cursor moves only after a good read; failed passes are reported and re-read;
  syslog fallback capped at 8 MB.
- Evidence: 16 fixture tests, cursor and journal tests, gate tests, mutation checks (every
  deliberate break caught); the development host's schedule is unchanged; real Debian 12,
  Rocky 9 and Alpine container filesystems probed and classified correctly.
- Register: `host_applicability` added as `unverified` (no real non-WSL host yet).
- Jev (advisory): facts-first architecture 0.72; top remaining gap "fixture-only" 0.54; merge
  before real-host runs 0.38. The container probes answer part of that; real VM and VPS runs
  remain before promotion.

## Road to production

| Step | Closes | Size |
|---|---|---|
| Merge `feat/host-facts`, `feat/pmf-ready`, licence branch; cut a signed release | 2, 3 (part), 7 (part) | days |
| VM matrix T1/T2 on a stable host (harness on `feat/vm-matrix`) | install/upgrade/removal evidence | 1 day machine time |
| Installer: verify signature and digest itself; never leave a server unwatched on failure | 5, 6 | days |
| Critical acks need out-of-band confirmation; per-user installs move to a service account | 1 | 1-2 weeks |
| Phase 2: all external-read collectors in deadline-bounded children; Layout per install mode; owner files out of the product tree | 3, 4 | 2-3 weeks |
| Store: `user_version` migrations, integrity check and repair; event-log archive and sizing docs | 9, 10 | 1-2 weeks |
| Redact alert details by default; connection limit; docs fixes (metrics, pairing id) | 8, 11-13 | days |
| security.txt, changelog, support contact, second releaser key, build provenance | 7, 16 | days |
| Phase 3: TUF-style signed metadata for binary and rule packs, health-gated updater | many-computer updates | 3-4 weeks |
| Phase 4 (optional): enrolment, per-device keys, ringed policy and content, fleet views | fleet | 6+ weeks |

## Not verified

The shipped binary's full contents (licences, leftover names); the C# sensors and Tauri app
internals; byte-reproducibility of builds; runtime alert delivery and heartbeat on a real
server; behaviour of a real hung in-thread collector; store growth rates; macOS anything; the
Windows installer, broker and quickstart paths end to end.
