# Critical acknowledgements and the fail-safe upgrade (2026-11-10)

Two findings of `docs/assessment/PRODUCTION-READINESS-2026-11-02.md` are addressed in
source: blocker 1 (a local program can silence findings) and finding 5 (a failed upgrade
leaves the server unwatched). Neither is deployed. Both register entries
(`critical_ack_confirmation`, `upgrade_failsafe`) are `unverified`.

## 1. A critical finding cannot be acknowledged through the local API

**Invariants** (tests: `tests/test_critical_confirmation.py`)

1. `acknowledge` refuses a critical finding unless the caller names a confirmation made
   outside the API. Refusal is the default; every caller must opt in.
2. A stored acknowledgement of a critical finding without that record does not apply.
   The finding keeps its severity for the score, alerts and questions (no lost visibility).
3. A "yes" on a critical finding through `questions.answer`, which is what `/api/answer`
   calls, changes no state: no acknowledgement, no recorded answer, no egress decision.
4. The terminal confirmation reads nothing unless both streams are terminals, and accepts
   only the exact finding id.
5. Lower severities and "no" answers behave as before.

**Designs compared**

| Design | Verdict |
|---|---|
| A. Typed confirmation at a terminal (chosen) | Works today on every install; a real boundary where the store belongs to a service account (server edition), a higher bar elsewhere |
| B. Signed approval from a paired phone with a passkey | The right anchor for per-user installs. The machinery exists for defense proposals only and no real phone is paired, so nothing could be measured |
| C. Allow it and notify every channel | Detects, does not prevent; no channel is measured as delivering |
| D. Wait for the service account | Leaves the server edition's API path open in the meantime |

Reconsider A when a real phone is paired (then add B as a second confirmer) or if typed
confirmation proves too heavy for people with many critical findings.

**Effect on existing installs.** Critical findings acknowledged before this change return
to full severity until confirmed again at a terminal. The score can only fall.
`jarvis ack list` marks each such entry "NOT APPLYING" with the command to run.

**Stated limits.** Where the daemon runs as the protected account, a program running as
that account can write the store directly, or allocate a pseudo-terminal. No notice is
sent when a critical finding is acknowledged. The dashboard and desktop app show the
refusal text; they do not yet replace the yes button (question entries now carry
`confirm: "terminal"` for that).

## 2. The server installer never leaves a watched server unwatched

**Invariants** (tests: `tests/test_server_install_failsafe.py`, which runs the shipped
script against a scratch root with recording stand-ins for the system tools)

1. A new copy that fails its own verification is not installed, and a running Argus is
   never stopped for it.
2. After the switch, any failure before the new version answers its health check puts the
   previous program, version file and unit back, starts it again if it was running, and
   exits non-zero.
3. A previous version that does not start again is reported as an unwatched server,
   never as recovered.
4. A good upgrade leaves the new version running and no leftovers.

**Designs compared**

| Design | Verdict |
|---|---|
| Verify in a root-owned staging directory, switch, health-gate, roll back (chosen) | No new moving parts; the old program is the fallback |
| Two versioned directories with a `current` link | Cleaner switch, but changes the unit, the launcher's ownership rule and the uninstall path in one release |
| Leave a non-answering new version in place | Simpler; an unattended server can sit unwatched until someone looks |

Reconsider if a real slow start (more than 60 seconds) causes a false rollback on a
healthy upgrade; the previous version keeps watching in that case.

**Stated limits.** Not yet run as root on a real systemd host or through the `.deb`.
Self-verification is executed by the copy being verified, so it detects damage, not a
deliberately altered download. The installer does not check the download signature
itself. Settings files and network-sensor units are not rolled back.

## Checks

- Negative controls: eight deliberate breaks (stop before verify, rollback disabled,
  health gate removed, unwatched reported as recovered, gate removed in three places,
  terminal check removed) each failed at least one test.
- Jev (jev-1.14.0, metadata only, `scripts/reviews/critical_ack_upgrade_failsafe_advisory.py`),
  advisory: terminal gate as the step to take now 0.89; resetting earlier critical
  acknowledgements acceptable 0.59 (uncertain, so the list now says which entries
  stopped applying); next gap is the same-user store write 0.95; rolling back on a
  failed health check is safer 0.88; top installer gap is a real-host run 0.57, then the
  installer checking the signature itself 0.43.
