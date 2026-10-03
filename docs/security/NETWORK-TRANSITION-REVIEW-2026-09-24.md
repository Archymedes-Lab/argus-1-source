# Network transition review, 2026-09-24

The current host score fell from the user's observed 74 to 66 with 100% scored
coverage. Network is 50 because `netwatch` scored two high events: a DNS change
and a gateway MAC change. The read-only sample and timeline audit shows both
events occurred at the same instant as a move from one identified Wi-Fi network
to a different SSID, BSSID, IP range and gateway. The latest samples remain on
the new network. This establishes a cross-network comparison in the collector;
it does not establish whether either network is trustworthy.

## Invariants before implementation

- Keep every original `net_events` row and timestamp; do not delete or rewrite
  the historical high events.
- A DNS or gateway MAC change while the same identified Wi-Fi network remains
  connected must retain its high investigation finding.
- Unknown SSID, missing paired samples, contradictory timestamps and incomplete
  identity must retain the original severity and state uncertainty.
- A transition between two known different SSIDs may be explained as a network
  switch, with the original event still visible in the timeline and a derived
  lower-priority audit finding that cites the sample pair.
- No automatic DNS, gateway, firewall or Wi-Fi configuration change follows
  from the classification. Preserve recovery and operator choice.
- A score change is not proof of safety. Verify the deployed collector, fresh
  `netwatch` snapshot, current network state and whole-host score separately.

## Design comparison

1. Keep all cross-network changes high: simplest but compares unrelated
   networks and obscures real same-network changes.
2. Rewrite historical high rows: lowers the score but destroys the original
   observation and weakens auditability.
3. Keep raw events, gate new high transitions on stable network identity, and
   derive context-aware audit findings from the paired samples: selected for
   evidence continuity, correct scope and bounded database cost.

Reconsider the selected design if a legitimate network switch can be mistaken
for a stable same-network transition, or if paired samples become unavailable.
The fallback remains the original high finding, not a clean verdict.

Jev's metadata-only Choice favored derived verdicts over rewriting history or
retaining all cross-network highs (probability 1.0, concentration confidence
1.0). Its Noul for retaining same-SSID changes high was 0.74. The implementation
review prioritized sample identity collision (Choice probability 0.91,
confidence 0.87); its missing-evidence fallback Noul was 0.94. These are
advisory signals. Executable cases check distinct networks, same-network DNS
and gateway changes, preserved historical high rows, missing paired samples,
missing BSSID and same-timestamp events on another interface.

A read-only audit against the host database with the candidate code derived
low network-switch findings from the two historical high events without
changing either raw row. This is a projection, not the live score. The live
release, fresh collector run, score and network state must be verified after
an authorized narrow deployment.

At the latest readback, `/opt/jarvis/current` still pointed to sealed release
`20260924T064933Z-a5544c87-dirty`. Its `netwatch/run.py` hash differed from
the candidate checkout file. The latest live score was 64 with 100% scored coverage;
the candidate has not been deployed.

The fresh network findings include one high alert for a previously unseen
access point on the **same** Wi-Fi name. That alert remains high: shared SSID,
WPA3 association, and nearby network settings do not independently establish
that the access point is authorized. Three medium connectivity-drop findings
also remain. Only the two historical DNS and gateway highs from the identified
cross-network switch are contextualized by the candidate read-only audit. With
all other areas fixed, Network would project from 35 to about 53 and the whole
score from 64 to about 67. This is an arithmetic projection, not live evidence.

## Narrow release prepared, not switched

`/tmp/jarvis-netwatch-narrow-20260924` is an owner-controlled Git stage based on
the running sealed release. Every base file was checked against `RELEASE.json`
before copying. The network-only commit
`6a84c892122cc9731cf249079d974ecd5263c944` changes only
`jarvis/collectors/network/netwatch/record.py` and `run.py`, and adds
`tests/test_netwatch_switch.py`. A later commit in the same stage adds the
[deleted-executable reconciliation](EXECUTABLE-REPLACEMENT-REVIEW-2026-09-24.md),
so the current staged diff is larger. The ignored Rust runtime binary is
present; the release packer includes it explicitly. The stage has a clean Git
status.

The focused network-switch tests passed (7). The full staged suite passed on
the real host as the checkout owner (1,334 tests), and Ruff passed on the three
reviewed files. A sandbox run of the same full suite had three read-only cache
errors and five ownership-sensitive assertion failures; the host rerun resolved
all eight. The live database was opened in SQLite read-only mode for the
candidate audit, which left the unfamiliar access point high and did not edit
the raw events.

The sealed release packer built an unprivileged network-only trial release
under `/tmp/jarvis-netwatch-builds-20260924`. Its manifest comparison against
the running release reported exactly one added test, two changed runtime
files, and no removals; `dirty` was false. A second trial build for the
combined stage is recorded in the linked review. The owner-only stage and
tarball remain under `/tmp`. This validates packaging, not the root-owned
switch or runtime.

The Jev advisory on this latest decision selected finishing the narrow release
gate (Choice confidence 1.0), and favored keeping the unvalidated access point
high (Noul yes probability 0.91). Deterministic tests and read-only host evidence,
not this judgment, establish the release gate and the remaining alert.

The host sudo allowlist permits only fixed repair commands and a service
restart without a password; it does not permit switching a root-owned release.
A restart of the current release would not install these files. An authorized
administrator must review the exact staged diff, use the release mechanism with
this explicit source and rollback ready, and then verify the new release hash,
fresh collector receipt, service health, and score. The failed direct deploy
from the dirty checkout must not be retried.

## Current route toward 80

The latest live read measured 64 with 100% scored coverage: Active threats 20,
OS hardening 80, Persistence & access 62, Data & privacy 50, Network 35,
Developer toolchain 100, Monitoring 100. The unfamiliar access point and
connectivity drops account for the remaining network penalty. The narrow
network correction alone projects only about 67, and no deployment or later change in
findings can be assumed.

The remaining gap is real protection work. A filename-only review found the
Secrets collector's generic findings mainly in project `.env` files and a
configuration file; no secret values were printed or sent to Jev. Migrating
those credentials requires compatibility checks for each app, rotation where
exposure is established, and fresh scans. The two hidden Codex sandbox Windows
accounts are enabled and non-administrative, so they cannot be dismissed as
disabled leftovers. The running Linux Sysmon mapping still appears deleted to
the process scanner and needs privileged hash/readback or a validated service
restart before changing that finding. Historical PowerShell and Sysmon events
remain evidence. None of these findings should be suppressed to reach a number.
