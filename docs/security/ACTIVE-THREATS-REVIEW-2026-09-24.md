# Active threats evidence review, 2026-09-24

## 2026-09-25: injected media control counted twice

Three injected key-down rows at distinct timestamps carry VK 0xB3, scan zero,
and no printable character. Three `control-key` rows at exactly those times
carry `media-play-pause`, the same injection and integrity flags, and the same
foreground. Microsoft defines VK 0xB3 as the Play/Pause key. JARVIS currently
reports a high injected-*character* finding as well as a high injected control
finding for these three presses. The two views are evidence of one action.

Invariant: preserve both raw streams and the high control finding. The key-view
finding becomes low duplicate inventory only when every member has a recognized
non-printable control VK and a matching control row at the same second, with
matching foreground and integrity flags. Any unmatched, malformed, printable,
lower-integrity, or truncated group keeps its original severity. This adds one
bounded read of at most 50 event timestamps; it changes no sensor, authority,
recovery path, or response rule. A sealed-release rollback restores the former
classification if the live readback disagrees.

Alternatives: keep double charging, lower all media keys, or reconcile exact
pairs. Jev Choice selected exact pairing (confidence 1.0; Noul 0.84 that the
described rows are one event). Tests and fresh service evidence are the gate.

The remaining control finding also needs proportionate severity. A group made
only of injected Play/Pause presses without a lower-integrity origin is medium:
the actor is unknown, but no text, credential, system-setting, or launch action
is in evidence. Any other injected control in the group or any lower-integrity
press keeps the existing high. This rule uses the recorded control class and
integrity flag, never the focused app name or a presumed agent. Jev Choice
selected medium for that exact group (confidence 1.0); its Noul gave 0.11 yes
probability that a blanket downgrade of all controls would preserve detection.

The live Active threats area measured 13 with 100% scored collector coverage.
Nine high findings were counted. Four were recently written unsigned artifacts
in the Windows temporary directory; two of those were created during the
2026-09-24 JARVIS sensor uptime investigation.

`JarvisSensorUptimeReview.exe` was compiled by this investigation from
`windows-sensor/JarvisSensor.cs` into the Windows user Temp directory for a
build check. It was not installed as a service. A read-only Windows check found
it present, 15,360 bytes, unsigned, SHA-256
`CC651301779C4C5F33A3391B606704422026A8F07E0931E85E262FA7AF921CFE`.
The compiler returned success. This receipt identifies only that exact file;
another file under the same name must not inherit the verdict.

`JarvisSensorTimeoutRetry.exe` was also compiled by this investigation. The
Windows host denied reading its hash and signature and denied executing it.
Its exact bytes are unverified, so its high finding remains. The older unsigned
probe scripts, PowerShell history findings, deleted Sysmon mapping, ProtonDrive
RWX memory, and prior Linux event findings remain unresolved by this review.

No score claim follows from deleting or moving a file alone. A fresh intrusion
audit and score readback are required after any cleanup. Deleted-binary and
event-history evidence must remain visible.

The exact hash-matched `JarvisSensorUptimeReview.exe` was confirmed not running
and removed from Windows Temp. A subsequent service-run intrusion audit was
current and error-free; it no longer reported that file. The live Active
threats area rose from 13 to 15 with seven counted high findings, while the
whole-host score remained 73 after rounding. This is evidence of one reviewed
staging exposure removed, not proof the other findings are benign.

A subsequent hidden-process scan showed three different unowned TCP connection
findings and the prior loopback connection had disappeared; the live Active
threats value then measured 12 with ten counted highs. One new connection had a
non-loopback peer, so the findings cannot be dismissed as loopback traffic.
The collector used a socket table cached for up to five seconds followed by a
live process-fd sweep. The candidate fix in `hidden/sockets.py` checks the same
inode and connection fields in two fresh, uncached socket/fd views. Persistent
or inconclusive discrepancies remain high. This code is not installed in the
running service, and no score increase is attributed to it until deployed and
verified against fresh host evidence.

The candidate passed 12 focused socket-attribution checks, six package-layer
checks, and the full 1,321-test Python suite on the host. Jev's metadata-only
Choice favored two fresh views, while its Noul invariant answer was uncertain;
the executable tests remain the authority. A later live readback still measured
Active threats 12, overall host score 73, 100% scored collector coverage and a
healthy service. Three unowned-connection highs remained in the running release.
The checkout contains unrelated work, so the candidate should be released from
an isolated copy of the current sealed release with only the two changed
production files and its regression tests, then freshly rechecked and rolled
back if service health or attribution regresses. Administrator access is needed
to switch the root-owned release.

## Post-release verification

The owner deployed sealed release `20260924T062756Z-a5544c87-dirty` and
restarted `jarvis.service`. The `current` symlink points to that release, and
the installed `hidden/sockets.py` and `platform/linux.py` hashes exactly match
the tested checkout. systemd reported the service active, running, with zero
restarts; `/api/health` reported healthy, ready and protection healthy.

Fresh `hidden` and `deep_hidden` runs completed without errors and without
the three earlier unowned-connection highs. The scored Active threats area
subsequently measured 14, up from the pre-refresh 12, with seven counted highs
instead of ten; overall host score remained 73 and scored coverage 100%.
These are fresh observation and attribution results, not proof that any
underlying threat was remediated. The remaining highs require separate review.

## Fresh investigation after the narrow release switch

The owner switched sealed release `20260924T151932Z-8c28d311`; the daemon is
active with zero restarts and reports healthy, ready and protection healthy.
The latest scored host state during this investigation is 60 with 100% scored
coverage; Active threats is 16. The lower overall score also includes two
new critical findings in Persistence & access, which need their own review.

The Active threats score contains one critical deleted Sysmon mapping, four
high historical findings (one rotated log deletion, one JARVIS trial runtime
executed from a temporary release build, and two PowerShell history entries
from policy repair), and medium findings across hidden, input, memscan,
Sysmon and Sysmon Linux. The PowerShell records establish command history,
not execution; the old log event lacks its prior boot's lineage. No historical
event has been deleted or reclassified for the score.

The owner checked the running Sysmon PID 455 executable and installed file
with privileged SHA-256; both were identical. Both measure 31,693,824 bytes.
The deployed identical-replacement verifier refuses files above 16 MiB,
which explains the current critical classification without excusing future
unreadable or changed binaries. A narrow 32 MiB, two-attempt candidate and
regression tests are under review in
`/tmp/jarvis-sysmon-size-narrow-20260924`. A fresh hidden/process scan under
the deployed service is required to verify its effect. Jev's metadata-only
Choice selected the bounded size fix for investigation; its Noul probability
that the historical metadata suffices for benign reclassification was 0.05.

The staged-source full suite passed 1,343 tests. Its runtime verification
executed the trial Rust binary from the temporary release path, producing a
new high world-writable-execution record. A later `deep_hidden` pass also
reported one loopback connection without a visible owner. At the next live
readback, Active threats was 14, overall host score 58 and scored coverage
100%. The unowned connection needs a fresh pass or independent attribution;
neither it nor the historical execution record was erased for score recovery.

## Post-release result

The owner installed sealed release `20260924T154835Z-f3fc9ee1`; systemd
reported `jarvis.service` active with zero restarts. Both post-release hidden
collectors then classified Sysmon's byte-identical replacement as low. The
critical Active threats finding is no longer present in either fresh snapshot.
The fresh score readback was overall 58, Active threats 16 and scored coverage
100%. Other areas had worsened independently, including Persistence & access
22 and Monitoring 89, so the overall number did not rise with the Sysmon
correction. Two separate hidden passes still report unowned loopback
connections to local port 8787 at high severity. Their different ephemeral
ports and absence of a visible fd owner require investigation; they have not
been reclassified on the basis of loopback scope alone.

A read-only Windows `Get-NetTCPConnection` query for port 8787 returned no
matching established entry during its sample. A controlled local TCP client
was correctly recognized by an unprivileged fd sweep, but that sweep also
had 159 permission-denied fd reads, so it cannot establish ownership for
the separate live unknown sockets. No Windows or process owner was inferred
from these checks. The loopback discrepancy remains high pending attribution
from a sufficiently privileged, time-correlated view.

The later live readback measured overall host score 60, Active threats 16,
Monitoring 100 and scored coverage 100%; neither fresh hidden collector had
an Active threats critical. Jev's metadata-only Choice prioritized a
time-correlated socket-inode and process-fd inventory in the service's
capability context (confidence 0.78). Its Noul favored keeping the unknown
peer connection high pending independent ownership evidence (yes probability
0.77). These are advisory; current deterministic policy and fresh evidence
remain authoritative.
