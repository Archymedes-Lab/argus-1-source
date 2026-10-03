# Attack-surface coverage plan

Status 2026-10-02: 11 validated, 34 claimed, 141 blind of 186 ATT&CK techniques (Windows and
Linux, parent techniques only). This plan raises the validated share. It follows the score-integrity
rule: a number moves only through a real detector, a proven measurement bug, or an explicit owner
decision. A technique is never promoted without a probe that makes the real detector fire.

## Status 2026-10-03: Phase 0 item 1 and Phase 3 A built, not deployed

Projected from a copy of the live catalogue and collector freshness: **73 validated, 32 claimed,
71 blind of 176** (41%). The live map does not change until the release is deployed and read back.

What landed:

- **Phase 0, item 1.** `feeds._attack` skips deprecated techniques and removes rows a full
  catalogue load no longer refreshes (never on a truncated load). 186 to 176.
- **Phase 3 A.** `jarvis/collectors/telemetry/techniques.py`: about 120 rules, each keyed on the
  image of the process that ran the tool plus its own arguments, wired into `sysmon.audit` and
  `sysmon_linux._rules`. The coverage map builds one probe per technique from the rule table and
  replays it through those two functions (`sysmon.audit(events=...)` is the new replay entry; it
  cannot write to the store).
- **Already detected, never mapped.** Probes for LSASS memory access (T1003), recovery destruction
  (T1490), DLL side-loading (T1574), raw device opens (T1006), measured-boot drift (T1542) and
  file-less images in memory (T1620).

Decisions that differ from the plan below:

- **Discovery bursts stay claimed.** The plan counted the 23 burst-only discovery techniques as
  validated. A single discovery command is deliberately silent, so the technique by itself is not
  caught; they are shown as claimed with that reason. Their probes still run, so a broken burst
  rule is reported as a regression.
- **Phase 1 was done through process rules**, not by mapping the posture collectors: T1685, T1686,
  T1688, T1690, T1496, T1611, T1037 and T1529 are validated by the command that does it. The
  collectors' own state checks are still unprobed.

Noise measured before scoring, as this plan requires: 256,397 Windows and 35,583 Linux retained
process starts replayed read-only. First pass: 1,281 Windows hits, almost all JARVIS's own
collectors (an inline script naming `root\subscription`, `cmdkey /list` from the identity
collector). After keying rules on creation verbs and dropping the `cmdkey` rule: under ten
findings, all real owner actions (sensor install, a task created by `schtasks`, a power-setting
change), and no discovery burst.

Still open from this plan: Phase 0 item 2 (a test that fails when a `COVERAGE` key such as T1562
is absent from the catalogue) and the `partial` level for sub-techniques; the remaining claimed
techniques of Phase 2 (T1056, T1078, T1110, T1133, T1204, T1497, T1556, T1557, T1571); Phase 3
B to F; and Arena emulation for any of it.

## Status 2026-10-04: Phase 2 and part of Phase 3 built

Live after the first release: 72 validated, 33 claimed, 81 blind of 186. This round projects
**90 validated, 24 claimed, 62 blind of 176** (51%) once deployed and the catalogue reloads.

- **Phase 2, proven through the collector's own rules.** Probes hand a synthetic payload to the
  real function (`data=`, `lines=`, `dirs=`, `home=` parameters; the same code runs either way):
  T1204 pasted-command lures, T1056 keyboard hooks, T1557 gateway and resolver changes, T1689
  Wi-Fi encryption downgrade, T1110 login-guess spikes, T1133 remote desktop logons, T1556 rogue
  PAM modules, T1068 exploitable drivers, T1102 dead-drop hosts, T1185 browser remote debugging,
  T1195 package-registry redirection, T1200 new option ROM code.
- **Phase 2, claims removed.** T1497 and T1571 had no rule a probe could fire; they are blind.
  The retired T1562 mapping is gone, and the map now reports any mapping to a technique the
  catalogue no longer lists (Phase 0 item 2, done at run time rather than as a unit test, since
  tests have no catalogue).
- **Held at claimed although the probe fires.** T1078: every successful remote logon is
  reported, but a stolen credential looks the same as the owner's. The 23 burst-only discovery
  techniques, as before. Both are listed in `attackmap.HELD` with the reason shown on the tile.
- **Phase 3 A additions.** Rules keyed on the parent process: a document application starting a
  script host (T1203), a server process starting a shell (T1190), the print spooler or LSASS
  starting one (T1068). These report the after-effect of an exploit, never the exploit, and say
  so. Certificate export (T1649).
- **Phase 3 C, first two.** Outbound file-share connection to a public address (T1187) and one
  process resolving 15 or more non-existent names in ten minutes (T1568), both from Sysmon
  events already ingested.

Noise, measured before scoring: 687,887 retained process, network and DNS events replayed through
`sysmon.audit` itself. The new rules produced nothing; the only findings were real owner actions.
No outbound public SMB exists in 294,236 network events, and no process reached the
non-existent-name threshold.

Live positive controls on the deployed rules: a seven-command discovery burst on Linux and one
on Windows were each reported within a minute.

A probe is registered only where its detector exists (`attackmap._optional`), so a narrow release
that lacks a module keeps that technique's mapped level instead of reporting a regression.
A contract test ties the fields the probes build to the fields the collection scripts emit.

Still open: `partial` level for sub-techniques; T1674 input injection (the detector exists, no
probe yet); Phase 3 B file canaries, the rest of C, D, E and F; Arena emulation.

## Rules for every phase

- **No claim without a probe.** New mappings land together with a probe in
  `jarvis/service/attackmap.py`, so they enter as validated or not at all.
- **A probe proves the rule, not the sensor.** Sensor liveness stays judged by collector freshness.
  Arena scenarios (`jarvis/lab/`) add end-to-end proof for the highest-value techniques.
- **Unobservable is said, not hidden.** Techniques this machine cannot observe are listed with a
  reason and stay in the denominator unless the owner removes them.
- **Each phase ships as a narrow release** with a written baseline and a live readback.

## Phase 0: make the measurement correct

Two defects were found on 2026-10-02. Both are measurement bugs, not coverage.

1. `jarvis/intel/feeds.py` drops revoked techniques but keeps deprecated ones. Ten deprecated
   techniques sit in the denominator as blind: T1026, T1034, T1043, T1051, T1061, T1062, T1064,
   T1108, T1153, T1175. Fix: skip `x_mitre_deprecated`. Denominator 186 to about 176.
2. ATT&CK split T1562 (Impair Defenses) into T1685 to T1690. The catalogue no longer has T1562,
   so the existing claim counts for nothing and the successors read blind. Fix: a test that fails
   when a `COVERAGE` key is absent from the catalogue, then remap each successor on its own
   evidence.

Also decide how sub-technique coverage counts. Today T1003, T1555 and T1195 read blind although
T1003.001, T1555.003 and T1195.001 are mapped. Proposal: a `partial` level, shown separately and
never added to validated.

## Phase 1: map what existing collectors already detect

Candidates, each to be confirmed against the collector's code and given a probe:

| Technique | Existing collector |
|---|---|
| T1685 Disable or Modify Tools | control, posture |
| T1686 Disable or Modify System Firewall | firewall |
| T1688 Safe Mode Boot, T1689 Downgrade Attack | posture, preos (boot options) |
| T1690 Prevent Command History Logging | evasion |
| T1496 Resource Hijacking | resources |
| T1611 Escape to Host | containers |
| T1669 Wi-Fi Networks | netwatch |
| T1200 Hardware Additions | controls, preos (option ROM code) |
| T1037 Boot or Logon Initialization Scripts | startup, asep |
| T1529 System Shutdown/Reboot | preos (unclean shutdowns) |

Expected: 8 to 11 techniques from blind to validated.

## Phase 2: prove the 34 claimed techniques

12 probes exist. Write one for each remaining claimed technique, calling the real detector
with synthetic evidence. A probe that cannot be made to fire is a finding: the claim is removed.
Expected: most of 34 from claimed to validated. This is the largest honest gain for the least new code.

## Phase 3: new detection, grouped by data source

Ordered by techniques closed per unit of work. Sources A and B reuse event streams JARVIS already
ingests (Sysmon, native sensor, Sysmon for Linux).

**A. Command-line and process rules on existing streams (about 45 techniques)**
- Discovery burst: many discovery commands from one process tree in a short window, one sequence
  rule. T1007, T1012, T1016, T1018, T1033, T1046, T1049, T1057, T1069, T1083, T1087, T1120, T1124,
  T1135, T1201, T1217, T1482, T1615, T1652, T1654, T1673, T1680. Single commands stay silent;
  the burst is the signal.
- Proxy execution: T1047, T1127, T1202, T1216, T1220, T1569, T1559, T1129.
- Impact preparation: T1490 (shadow-copy and recovery deletion), T1489, T1485, T1531, T1561, T1222.
- Credential tooling: T1003, T1558, T1649, T1134, T1550.
- Collection and staging: T1560, T1074, T1119, T1140, T1005.

**B. File-system canaries (impact)**
Decoy files in user folders, watched for mass rename, rewrite or deletion: T1486, T1485, T1565,
T1491. This closes most of the impact tactic, which is at zero today.

**C. Network egress baselines (exfiltration and command-and-control)**
Per-process upload volume and destination baselines from netwatch: T1041, T1048, T1567, T1020,
T1029, T1030, T1011. DNS behaviour: T1568, T1572, T1071. Protocol shape: T1095, T1102, T1008,
T1104. Volume: T1498, T1499.

**D. Removable media and hardware**
Device arrival and volume mount events: T1091, T1052, T1025, T1092, T1200.

**E. Identity and credentials**
T1555, T1539, T1606, T1621, T1111, T1187 (outbound authentication to untrusted hosts), T1185.

**F. Initial access**
Download provenance (mark-of-the-web lineage from browser to execution): T1566, T1189, T1204.
Exposed services: T1190, T1210. Supply chain: T1195.

## Phase 4: techniques this machine cannot observe

For the owner to rule on, one by one. Proposed reasons:

- No domain: T1207, T1482, T1484, T1615.
- Happens off the machine or to the person: T1657, T1667, T1684, T1534, T1199.
- Content of encrypted traffic: T1001, T1132, T1573, T1665. Only metadata is visible without
  decrypting traffic, which JARVIS does not do.
- Exploitation itself (only its effects are visible): T1068, T1203, T1211, T1212, T1687.

These stay blind and listed with their reason unless the owner removes them from the denominator.

## Expected numbers

| After | Validated | Claimed | Blind | Of |
|---|---|---|---|---|
| Today | 11 | 34 | 141 | 186 |
| Phase 0 | 11 | 34 | about 131 | about 176 |
| Phases 1 and 2 | about 50 | under 5 | about 121 | about 176 |
| Phase 3 A and B | about 95 | under 5 | about 76 | about 176 |
| Phase 3 C to F | about 130 | under 5 | about 40 | about 176 |

The figures after Phase 0 are estimates. A realistic ceiling is about 75% validated; the rest is
Phase 4. The assurance register moves separately: a capability leaves `partial` only with a
deployed receipt, a positive control and a soak.

## What would change this plan

- A probe in Phase 2 that cannot fire: the detector is fixed before any new work.
- Rule noise in Phase 3 A on this machine's own developer activity: the burst thresholds are
  measured against a week of real events before the rules are scored.
- Resource cost: every new job states its measured CPU and time before it is scheduled.
