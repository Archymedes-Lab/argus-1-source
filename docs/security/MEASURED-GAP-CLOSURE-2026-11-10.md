# Closing measured gaps (2026-11-10)

Baseline: the unchanged disposable Linux campaign applied 16 state scenarios and
reported 11 marker-linked findings, 10 high/critical. Cases 07 (profile), 12 (PHP),
13 (root cron), 15 (history symlink), 16 (rc.local) remained unreported. The public
text replay is separately 707/1745; neither number is a general protection claim.

## Invariants before implementation

- Read-only local observation; never execute files to classify them. No protected
  host attack execution. Attack cases remain unchanged and run only on disposable VMs.
- File bytes and command arguments remain in memory only. Emit metadata, locations,
  hashes and fixed explanations; never source lines or history contents.
- Anchor file reads to non-link directory descriptors, reject replacements and
  incomplete reads. Time, entry, byte and per-file caps report unknown coverage.
- Recognize literal startup invocations in staging directories, not a mention of
  a path in an argument, comment or quoted example. Missing sources are not alerts;
  failed reads remain explicit gaps. History checks inspect links, never history text.
- Findings derived from external file content remain advisory after persistence.
  A copied filename, rule text or model answer cannot authorize a response.
- Preserve existing evidence and unrelated dirty work. A narrow release starts at
  the running sealed manifest, overlays only reviewed files, validates dependencies,
  records expected finding changes and retains an expect-base guard and rollback.
- Windows validation requires an ephemeral hosted Windows machine, an empty scratch
  profile/store, explicit protected-host refusal, local controlled actions, bounded
  collection, fresh real records, verified cleanup and no publication of script text.

## Designs and chosen scope

Startup: extending malware keyword lists would leave simple literal persistence
unseen; inventorying every unowned profile would flag ordinary user customization.
Choose a bounded command-position parser for direct staging-path invocation plus
metadata-only history-sink checks and executable rc.local inspection. Indirection,
framework loaders and uncommon shell grammars remain stated limits.

PHP: the current webshell audit requires a listening server, while the benchmark
places a dormant artifact. Add a bounded built-in direct request-to-execution probe
to the existing drop-folder content collector. Ignore comments and quoted examples;
retain the community literal subset. A full language/dataflow engine is future work.

Reuse one safe file reader for both new observations and content scanning. Keep the
existing reader API so its ancestor-link, identity-race and budget regressions remain
applicable. Do not change response authority or require model inference at runtime.

## Work and acceptance

1. Build the five-gap observations with benign controls and failure-path regressions.
2. Run the unchanged Linux campaign and preserve its report, including any misses.
3. Build and execute a bounded Windows campaign on a disposable hosted runner; separate
   observed state, actual log delivery and unmeasured sources. No owner-host attacks.
4. Run focused regressions, full isolated suite, static and ASES gates, pinned replay,
   real service dispatch, resource measurements and a metadata-only Jev review.
5. Merge only with CI green. Stage a narrow release from the live sealed source and
   write a baseline, expected deltas and rollback. Activate only through the permitted
   administrator path, then verify fresh affected snapshots and service health.

## Initial live readback

The live service is active with zero restarts on sealed release
20261105T160315Z-e8c21be52587. No changes were made. Authenticated API readback and
administrator availability are checked separately; a restart is not deployment.

## File-evidence privacy and authority audit

The existing persistence check could quote complete cron/profile/Exec lines,
including credentials, before the new metadata-only finding was folded away.
Remove those source/argument fields for these startup reports. Mark file evidence
in a durable title and recognize legacy stored startup/webshell titles so a stored
finding cannot acquire response authority. File-content evidence is capped below
critical; no automatic response is granted. Record these expected title/severity
changes in the deployment baseline rather than claiming a score gain as protection.

## Windows test design

Use only a GitHub-hosted Windows VM, refusing existing JARVIS data/installations.
Install the Microsoft-signed Sysmon tool only in that disposable VM, from a pinned
zip SHA-256 with Authenticode publisher validation; never replace an existing
sensor. Enable 4104 logging only there, record previous settings, and restore them.
Keep source text and event payloads out of artifacts. Network blocks for the test
interpreter and command shells are read back from active policy before actions;
agent/artifact transport stays outside these programs. No Defender exclusions,
ASR bypass, memory dumping, credential reads or unknown-code execution.

Controlled actions: unique Run value, unique IFEO debugger key, inert logon task,
inert auto-service registration, and a script-file LSASS process-id query (metadata
only). Verify the action's state, new real Sysmon records, a 4104 record associated
with the fixture's file path, detections through real job dispatch, and per-object
cleanup. OS prevention stays explicit rather than relaxing policy. This validates
these Windows paths, not all Windows techniques or the native spool/broker service.

References: Microsoft Sysmon documentation (v15.22, 2026-09-10),
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon ; runner image
https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md .

## Measured results, reviewed source 899f43b

Workflow 42897555336 completed on disposable Linux and Windows runners. Reports
are preserved under `docs/security/evidence/` with source/run/scope metadata.

- Linux: 16/16 unchanged fixtures caught; 11 high/critical; no collector, execution
  or cleanup errors. This closes the five measured gaps for these exact cases.
- Windows: 5/5 inert state fixtures applied and removed; **1/5** marker-linked
  detection (IFEO), zero collector/cleanup errors. Real Sysmon registry/process
  events and the fixture's PowerShell 4104 block arrived. This proves delivery,
  not five detections. Inert Run/task/service commands and process-id discovery
  are not inherently malicious; do not add noisy detectors to inflate this count.
- Full owner-host isolated unittest discovery: 5,007 tests passed, 17 skipped.
  Static gate and ASES passed before the Windows-only additions; repeat final gates.

Production remains the November 5 sealed source and is not deployed. Baseline live
readiness is false (`memscan`: incomplete coverage); no health improvement claimed.
No passwordless administrator deployment route was available. Stage and verify a
narrow sealed-base release before requesting the final local authenticated activation.

Initial Windows report investigation: the job list omitted `control`, the actual
Run/task/service collector. Add it and rerun identical fixtures; preserve the
initial 1/5 report as harness evidence. No detector rule/severity is changed.

## Integration correction, 2026-11-11: file evidence keeps its severity

The file-evidence change above also lowered existing detections from critical to
high: a fetch-and-run or reverse-shell line in a login profile or cron file, and a
web-shell score of four or more. That is not a proven detector bug, and making a
detection cheaper is an owner decision under the score-integrity rule
(ALERT-QUALITY-2026-11-08). It was reverted before merge: `file_finding` marks the
evidence (durable title mark, no automatic response, source and arguments withheld)
and leaves severity as the detector gave it. The privacy fix and the authority fix
stand. Titles of these findings gained the ` (file evidence)` mark, so
acknowledgements made against the old titles no longer apply and the findings show
again at full severity until confirmed: the score can only fall from this.

Still for the owner: whether these should cost less than critical.

## Second live lists, 2026-11-11

Both campaigns were extended with attack-shaped, harmless, reversible cases and run on
disposable GitHub-hosted runners.

**Linux** (`live_bench.py`, cases 17-29): the first run caught 20 of 29. Nine actions no
collector reported (PAM `pam_exec` line, `cap_setuid` file capability, udev `RUN` rule,
system `bash.bashrc` line, `LD_PRELOAD` in `/etc/environment`, update-motd script, new
sudo-group member, emptied `auth.log`, APT hook) are closed by the new `linuxguard`
collector (PR #41): per-install baseline drift plus invariants. Run 43085086326:
**29 of 29**, no collector failures.

**Windows** (`windows_bench.py`, cases 06-18, and collectors intrusion, implant, firewall,
scan, evasion and winblocks added to the run): the first run caught 14 of 18. Two of the
three misses were findings that cut their evidence: the Winlogon detail at 100 characters
lost the added program, and the COM detail at 80 lost the library's name. Both now name
the evidence in full. The third was the harness (shared file names without the case id).
Run 43094456700: **17 of 18**; the one miss is case 05, the deliberately inert process-id
query. Case 19 (inbound firewall rule) could not be created on the hosted runner and was
removed.

A mid-branch Linux run exposed a regression of mine: an unguarded `import grp` broke every
job on native Windows (0 of 5). Fixed with a regression test.

What this does not show: one runner image per platform; harmless stand-ins, not real
malware; nothing about the owner's machine, which still runs the 5 November release.
