# Implementation record — 2026-09-23: lasting Sysmon fix, evidence vault, public anchors

## Sysmon: why the log overflowed, and the fix

Replaying boot 94 (35,859 registry events since 12:15Z) showed that 97% came
from operations that change no security state:

| Events | Operation | Key |
|---|---|---|
| 24,929 | CreateKey (opening an existing key) | `Services\Tcpip\Parameters` (every networked app) |
| ~6,900 | SetValue | `Services\bam\State\UserSettings` (launch stamps; ProcessCreate already records launches) |
| ~370 | SetValue | `W32Time\SecureTimeLimits`, `SharedAccess\Epoch`, `VSS\Diag` |

`windows-sysmon/jarvis-windows-baseline.xml` now puts registry rules in two
`RuleGroup`s. The exclude group has five `Rule groupRelation="and"` clauses. Each
one pairs a single operation (CreateKey or SetValue) with a single key.
DeleteKey, DeleteValue, RenameKey and every other value change stay recorded,
including DNS `NameServer`, `ImagePath`/`ServiceDll`, Run keys and NtpServer.
Replaying the same boot through the new rules: **37,062 → 1,927 events (−95%)**.
All 180 DeleteKey and 115 DeleteValue events are kept.

The log itself (256 MB, circular) holds about 4.7 days. It only loses data if
ingestion stops for longer than that.

**Applying it (one UAC prompt):** `python3 -m jarvis broker sysmon-baseline`.
The installer (`scripts/repair/apply-jarvis-sysmon-policy.ps1`):

- refuses any policy whose SHA-256 differs from the checkout's
- `reg export`s the Sysmon driver and service keys into
  `C:\ProgramData\Jarvis\Vault\sysmon\backup-<UTC>\` before changing anything,
  and refuses if the export lacks the `Rules` value
- applies the policy, then requires three things: the running config hash
  equals the policy hash, ProcessCreate is unfiltered, and the registry
  exclusions are present
- restores the backup automatically if any of those checks fail
- supports manual rollback: `apply-jarvis-sysmon-policy.ps1 -Rollback <backup folder>`

The rollback path (reg import plus a service restart) has not been exercised on
this machine yet.

**Lasting:** the new `evidence` job compares the running config hash with the
baseline file's SHA-256 every 15 minutes. It raises **high** "Sysmon is not
running the reviewed baseline" until the new baseline is applied, and again if
anything later replaces the rules.

## Evidence that cannot be quietly rewritten

The event log lives in a directory this account can rewrite. Two independent
witnesses now check it.

**Administrator-only vault.** The daemon stages copies of sealed segments, the
chain file and anchor records in `%LOCALAPPDATA%\Jarvis\VaultInbox`. That folder
is untrusted and owner-readable. The broker's new `vault` job
(`jarvis/platform/win/vault.ps1`, staged in the admin-only broker folder) copies
them into `C:\ProgramData\Jarvis\Vault` under these rules:

- The ACL gives full control to SYSTEM and Administrators and read access to the
  owner, with no inheritance (measured on the live machine).
- The vaulted `chain.jsonl` must be a byte-for-byte prefix of the staged chain.
  Otherwise the vault is left untouched and the conflicting chain is kept under
  `divergence\`.
- Files are installed with a move that cannot overwrite and are marked
  read-only. Nothing is ever deleted.
- A chain line is appended only after its segment is in the vault. A segment
  claimed as "pruned before vaulting" is accepted only if the live log's own
  retention record confirms it.

Measured live: the first elevated run vaulted all 36 segments (62 MB) in 1s, and
the daemon re-verified every header link and payload hash.

**Public anchors (OpenTimestamps).** At most every 6h, and only when the chain
head has moved, the job writes a manifest of the event-log head, the vault head
and the Sysmon config hash. It submits only the manifest's 32-byte SHA-256 to
four public calendars and needs at least two to accept. Proofs are upgraded to
Bitcoin attestations after about 2h. Each Bitcoin attestation's Merkle root is
checked against the block header from `blockstream.info`. Outbound connections
go only to fixed allowlisted origins, with no proxy and no redirects, and URLs
found inside proof files are never followed. The first live proof was accepted by all four
calendars, and the official client (`ots info`) confirms it covers the
manifest's hash.

**What each witness catches:**

| Attack | Result |
|---|---|
| Malware as the user rewrites or truncates the event log | **critical**: live history differs from the vault, or no longer contains an anchored head |
| Malware as the user forges the inbox | vault refuses the chain; **critical** divergence |
| Administrator alters the vault | vault verification fails, or the vault disagrees with anchors whose Bitcoin proofs exist |
| Administrator rewrites everything and deletes every anchor record | not detectable locally. Keep copies of `~/.jarvis/anchors/*.ots` and `*.json` somewhere else (email, USB) and check them with `ots verify` |

**Remaining limits:**
- Events newer than the last anchor (up to 6h) are protected only by the vault.
- The vault is local and unencrypted.
- The 20 GB vault budget stops vaulting rather than deleting anything.

## Validation

- `tests/test_evidence_custody.py` (17 tests, offline): staging and vaulting,
  a rewritten live history, an altered vault payload, a forged pruned claim,
  vault-job divergence, Sysmon drift, anchor timing, a rewrite after anchoring,
  an edited anchor record, Bitcoin block mismatch, calendar quorum, the upgrade
  allowlist, malformed proofs, and vault-script invariants.
- `tests/test_windows_sysmon_policy.py`: rule-group structure; exclusions limited
  to CreateKey/SetValue AND a `\Services\` key; security keys never excluded;
  installer ordering (refuse, then back up, then apply) and automatic restore.
- `vault.ps1` was exercised unelevated on real segments with the ACL step stubbed:
  first run, idle run, missing segment, pruned marker, forged segment and forged
  chain. This caught a PowerShell array-unrolling bug that broke the first run.

## Email: scheduled briefings instead of an alert stream

**Measured cause:** 9 emails between 06:02 and 06:56. They were collector
outage notices ("collector 'native' is failing" was sent 8 times) caused by
daemon restarts, plus critical reminders sent again at 1h, 6h and 24h.

**New rules** (`response/reporting/notifications.py`, `cadence.py`):

- **Collector outages:** page only after lasting 15 minutes
  (`OUTAGE_CONFIRM_S`). Restart-length blips are never mailed.
- **Interrupts:** go out immediately only for a critical finding, or a high from
  an *Active threats* detector, that is NEW, WORSENED or REOPENED, or for a
  confirmed outage. Age reminders never interrupt.
- **Everything else:** held for scheduled **briefings** at the report hour and
  18:00 (`briefing_hours`). A slot missed by more than 3h is skipped rather than
  sent stale.
- **Health email:** the morning briefing carries the health panel, so the
  separate daily health email is off while briefings are on.
- **Opting out:** setting `briefings: false`, or a fixed
  `alert_digest_interval`, restores the rolling digest.

**The briefing** (`emails.briefing`):

- a condition code from counts: RED for an open critical, AMBER for items for
  you, otherwise GREEN
- one **mission of the day**: an open critical first, then the next protocol
- changes since the last briefing, with reminders labelled "open Nd"
- what JARVIS is watching on its own
- wins (resolved items, score gains)
- evidence custody: vault, anchors, Sysmon baseline
- the score panel

**The voice** (`voice.py`):

- **Styles:** six delivery styles (butler, mission control, sidekick, field
  report, forecast, workshop). The style is stable for a day, never repeats the
  previous one, and interrupts use only the serious styles.
- **Memory:** the last 20 openers are remembered. A line that overlaps one of
  them (≥45% of words, or the same first three words) is rejected, and one
  other style is tried.
- **Fallbacks:** 19 fallback lines, with recent ones skipped.
- **Checks:** every earlier grounding check still applies. Two new rules were
  added from measured llama3.2:3b output: gloom ("a sombre morning … a
  worrying state of affairs", "only going to get more serious by the hour") is
  rejected, and "N new" must equal the new count ("nine new matters" when one
  was new).

**Measured dry runs** on live data with llama3.2:3b: a briefing takes 25–40s to
build, and about 1 in 3 model openers pass the checks. The rest use the
rotating fallback pool, so there are no repeats either way.

**Jev (advisory):** goal fit 0.85. It flagged a 0.38 chance that a deserving
threat would wait for a briefing. That led to new *Active threats* highs also
interrupting.
