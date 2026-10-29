# Is JARVIS protecting this computer? Review of 2026-10-21 (evening)

Every statement below was measured on the live machine between 21:00 and 22:15 local, after
the day's three releases (input audit, privacy seal, polling keyword), the hardening run and
the native sensor install. "Faille" entries are ranked by what an attacker gains, not by
score weight. The [Maximum Assurance directive](MAXIMUM-ASSURANCE.md) applies: this is an
engineering review of the guard, not a verdict that the machine is clean or compromised.

## Verdict in one paragraph

JARVIS sees a great deal and sees it fresh: 51 collectors, all fresh, native Sysmon ingestion
working for the first time in weeks, the Win32k input trace attributed, the privacy seal
watched. It does not, today, **tell you** when something is wrong, and it cannot **stop**
anything on Windows. It runs as you, so anything running as you can stop it, blind it or
rewrite its memory of events before the vault copies them. Those three gaps, not detection
coverage, are what decide whether it protects you.

## Failles, ranked

### F1. No alert channel reaches you (critical)

- `config.json` has no mail key and no recipient; the Windows dead-man's `mail.json` has been
  renamed `.paused` since 2026-09-29; the dead-man's last state says
  "Outage email failed (ItemNotFoundException); queued for retry".
- The only working channel is a desktop toast from the dead-man, which fires only for a JARVIS
  outage, and the dashboard, which you must open.
- Consequence: 251 critical findings exist right now and nothing has paged you about any of
  them. Detection without delivery is a log.
- Fix: put a working recipient and key back (or a channel that needs no third party: the
  dead-man toast path already exists; extend it to critical findings), and make the "no
  channel configured" state itself a critical finding that never clears.

### F2. JARVIS runs as the user it protects (critical)

- `systemctl show jarvis.service`: `User=chris`, `ProtectSystem=no`, `ProtectHome=no`,
  `NoNewPrivileges=no`. The release code is root-owned and read-only (good), but the daemon,
  its store (`~/.jarvis/jarvis.db`, 0600, owner chris, 766 MB), its config and the TypeSafe
  key are all writable by the same account that malware would run as.
- Every Windows supervisor task (reviver, health monitor, dead-man, input hook, broker) runs
  as `chris`; a process as `chris` can disable them with one `schtasks` call. Only the native
  sensor service and the Sysmon service are outside that account.
- Consequence: user-level malware can stop the daemon, stop what would restart it, and edit
  or delete findings and acknowledgements in the store before the next vault copy. The hash
  chain makes rewriting detectable later, not preventable.
- Fix (in order): run the daemon as a dedicated `jarvis` user with the store owned by it;
  `ProtectSystem=strict`, `ProtectHome=read-only` with explicit read paths; register the
  reviver and dead-man as SYSTEM tasks (one elevated step); have the health monitor report a
  disabled JARVIS task as critical through the toast path.

### F3. The control API accepts state changes from any local process, including Windows (high)

- `POST /api/run`, `/api/fix/approve`, `/api/fix/authorize`, `/api/geo/zone`, acknowledgement
  routes: no token, no origin check. From PowerShell on Windows, `http://127.0.0.1:8787/api/live`
  answered 200: mirrored networking exposes the loopback API to every Windows process of the
  user.
- Consequence: a Windows process can force jobs, approve a drafted fix, acknowledge findings
  so they count as low, or move the geofence.
- Fix: a per-boot random token in a 0600 file read by the CLI and the dashboard, required on
  every state-changing route; refuse requests whose peer is not the WSL loopback (the WSL
  guard work already measured that a Windows-originated connection arrives as 127.0.0.1, so
  the token is the gate, not the address).

### F4. A BitTorrent client is listening on the public profile and drowns the alert channel (high)

- `btweb.exe` (BitTorrent Web, installed under AppData\Roaming, an ad-supported bundle) listens
  on `0.0.0.0:6881` and three high ports, with an inbound allow rule on the **Public** firewall
  profile.
- Its peer connections match abuse lists, producing **232 of the 251 criticals** ("contacted a
  known attacker IP", one per peer) and 232 pending block proposals.
- Consequence: real criticals are 19 lines in 251; nobody reads that. And the inbound rule is
  a door on every network you join.
- Fix: your call on the client. JARVIS side: collapse per-process peer matches into one
  finding per process per day with a count, rate the inbound Public rule as the finding it
  is, and never propose 232 individual firewall rules.

### F5. Sysmon still drops events at every boot (high)

- Boot 2026-10-21 18:41Z: the driver queue overflowed and dropped 39,612 registry events,
  1,403 process-access, 149 image-load, 99 process-create, 74 file-create, 27 pipe events.
  The native sensor records the 99 lost process creations as a coverage gap.
- Cause known since 2026-10-11: the registry include set is too broad at boot; the revised
  baseline that removes 95% of that volume is in the checkout and has never been applied.
- Consequence: the first minute after boot, the window where persistence fires, is partly
  blind. Boot persistence is exactly what spyware uses.
- Fix: apply the revised Sysmon baseline (one elevated command, backup and auto-restore
  built in), then confirm on the next boot that event 255 does not appear.

### F6. No response on Windows (high)

- The response ladder has no Windows kill or suspend. Quarantine and suspend are Linux-only;
  `block_network` adds a firewall rule only for a critical hunt match with a flag that is off
  (`auto_block_ip: false`); `auto_disable_autostart: false`.
- Consequence: when JARVIS does see a keylogger, it proposes; it does not stop the capture.
- Fix: a reversible, evidence-first Windows suspend (`NtSuspendProcess` via PowerShell) behind
  the same propose-then-approve ladder, auto only for the unsigned-global-keyboard-hook shape
  with coverage complete. This was rung 7 in the ORION prioritisation.

### F7. C: is 98% full (medium, rising)

- 14 GB free on a 475 GB disk. Sysmon, the sensor spool (173 MB now, 512 MB cap), the broker
  trace (new 128 MB cap) and the vault all live on C:. A full disk silently stops evidence.
- Fix: compact the WSL image (owner action from the blind-spots register); JARVIS should
  report free space under 5% as high.

### F8. The guard's own tasks read as critical to itself (medium, attention cost)

- Three of today's criticals are JARVIS's own scheduled tasks (`jarvis elevated broker`,
  `JarvisCursorSpeed`, `WSL IDE Keepalive`) after the broker reinstall changed their
  fingerprints. `INSTALL.json` records the right checkout, so this is fingerprint drift the
  install step should re-declare, not a bug in the detector.
- Fix: `jarvis broker install` and the supervisor installers re-declare their own task
  fingerprints in the same step.

### F9. Clock still fights (medium)

- `systemd-timesyncd` is enabled and active; the WSL clock steps back about every 30 s
  (measured 2026-09-30). Wall-clock windows in detectors are unreliable until the owner
  disables it (one `sudo` command in the pending-actions guide).

### F10. Known, accepted or inherent

- 45 plaintext credentials in your files (secrets collector): JARVIS reports, you rotate.
- Smart App Control unavailable (unactivated Windows); Administrator Protection excluded
  (Hyper-V/WSL). Compensations: ASR 10 block / 9 audit, cloud block High, WSH off.
- Kernel-mode, firmware, hardware keyloggers, `BitBlt` screen capture, clipboard listeners,
  hotkey loggers: no user-mode sensor sees them (SPYWARE-DEFENSE §5).
- The privacy seal is on; a real capture attempt has not yet been tried against it.
- The WSL boundary: any Windows process of the user is root inside this distro by design.

## Code-level failles (audit of JARVIS's own attack surface, verified against the source)

Everything an attacker running as `chris` could do to the guard itself. Verified lines are
cited; the daemon's `AmbientCapabilities` (dac_read_search, sys_ptrace, syslog) stop ptrace
into it but nothing else below.

| # | Faille | Evidence | Mitigation today | Sev |
| --- | --- | --- | --- | --- |
| C1 | `/api/answer` "yes" acknowledges a finding for 90 days and marks egress EXPECTED with no expiry; "no" proposes **and approves** a containment action with no human gate | `questions.py:124-169`, `acknowledge.py:29` | only `daemon` and `collectors` categories are unacknowledgeable (`acknowledge.py:30`); tamper and visibility findings can be acked | H |
| C2 | No authentication on state-changing routes; `_same_origin` passes any client without an Origin header | `server.py:428-438`, routes `:588-764` | Host allow-list; loopback bind (Windows reaches it anyway) | H |
| C3 | The store (`~/.jarvis/jarvis.db`): acks, alert state, defense ledger, egress decisions, baselines are plain rows writable by the user; no HMAC, no chain | `store.py:12`, live 0600 chris | hash chain and vault cover the event log only | C |
| C4 | `config.json` trusted without integrity: `alert_to`, `alert_min_severity`, `resend_api_key`, `autonomous_defense`, `auto_*` all user-writable; `JARVIS_RESEND_KEY` env overrides | `alert.py:90-100`, `defense.py:70-75` | owner-only mode check proves only that chris owns it | H |
| C5 | Supervisors run as the user; liveness judged from user-writable `state.json`; both trust whatever JSON answers on `:8787/api/health`, so kill the daemon and squat the port inside the 5 s restart window and the guard reads healthy while the real daemon crash-loops | `jarvis-health-monitor.ps1:92-106`, `reviver.ps1:306-313`, `supervisors.py:28-36` | none | H |
| C6 | `SIGSTOP` freezes the daemon for up to `WatchdogSec=900` | `systemd/hardening.conf` | systemd restart after 15 min | M |
| C7 | Elevated `vault.ps1` copies from the user-writable `VaultInbox` without rejecting reparse points and appends any chain that extends the vaulted prefix without checking `prev` links or segment hashes | `vault.ps1:76-98,114-143` | admin-only vault ACL | M-H |
| C8 | Sensor acks are user-writable, so a forged ack can force early deletion of batches (under spool pressure); batches themselves cannot be forged | `install.ps1:168`, `JarvisSensor.cs:386-415` | ingest sequence/digest checks make the gap visible, evidence gone | M |
| C9 | Release integrity is ownership-only and checked at start; `RELEASE.json` hashes never re-verified at runtime | `jarvis-release.py:22-66`, `privilege.py:81-113` | root-owned tree | M |
| C10 | ~35-minute window to rewrite the live chain before seal + evidence job + broker vault it; anchors every 6 h from a user-writable staging dir | `eventlog.py:32-38`, `evidence.py:44-45,251-271` | vault detects later rewrites | H |
| C11 | `chris` is in `sudo` and **`docker`** (root without a password), and any Windows process is root in the distro via `wsl -u root` | `id chris` | documented in WSL-ATTACK-SURFACE | C |
| C12 | `jarvis evidence scan` prepends `~/.jarvis/tools` to `sys.path`; a root-hijack if ever run under sudo with the user's HOME | `evidence/scan.py:21-22` | CLI only | L |

The audit's own priority order, which I agree with: (1) a dedicated `jarvis` uid with state in
`/var/lib/jarvis` and config in `/etc/jarvis`, which closes C3, C4, C6, C9's writer and the
socket squat; (2) the health monitor in a SYSTEM context with authenticated health replies
(C5); (3) a working mail key plus an external heartbeat that pages when check-ins **stop**
(F1); (4) acks and egress decisions behind an out-of-band gate, tamper findings never
acknowledgeable, "no" answers only ever *propose* (C1); (5) `vault.ps1` reparse-point refusal
and in-script chain verification (C7); (6) remove `chris` from `docker` (C11).

Note on F3 above: an API token alone fixes little while the daemon, its store and its config
are the user's; it is worth doing, but after (1).

## Sealing work done the same night (stage `protection-20261021-r9`)

Built, tested (focused suites pass on the stage; full suites reported in the session) and
staged on the live base; the owner deploys with the usual command. What each faille got:

| Faille | In the release | Still the owner's |
| --- | --- | --- |
| F1 | desktop toast for new/worsened criticals and outages, mail or no mail (`jarvis/response/toast.py`, 6 per hour, 6 h repeat, stdin-only payload); a critical, unacknowledgeable "no alert channel can reach you" finding in the watchdogs job | a Resend key, sender and recipient in `config.json`; unpause the Windows dead-man's `mail.json` |
| F2 | `systemd/service-user.conf` + `scripts/repair/install-service-user.sh`: dedicated `jarvis` user, state in `/var/lib/jarvis`, config in `/etc/jarvis` (root-owned), `ProtectSystem=strict`, preflight that refuses to switch unless PowerShell interop works for the new user, one-command rollback | run it (`sudo … --preflight` first); Windows-side supervisors as SYSTEM is a separate design (toast and DPAPI mail do not survive a SYSTEM context) |
| F3 | per-start API token (0600 file, `X-JARVIS-Token` header or SameSite cookie set by the dashboard page) on every state-changing route; CLI sends it | nothing; complete only once F2 moves the file out of the user's reach |
| C1 | answering "no" now only proposes; approval is `jarvis defend approve`; tamper, tampering and visibility findings can no longer be acknowledged | — |
| F4 | peer matches collapse to one finding per process once a process has more than five listed peers (232 criticals become 1; a process with a few contacts keeps one finding each, after Jev put "could hide a real C2 contact" at 0.52) | `scripts/harden/close-exposures.ps1` (elevated) disables BitTorrent Web's inbound rules; uninstalling the client is your call |
| F5 | the revised Sysmon baseline ships in the release so the evidence job expects it | after deploy: `close-exposures.ps1 -PolicyPath <release baseline> -ExpectedSha256 85a52fe6e4d0bfaafe93467beea04acfead944eb1e698e7944761354740bcab8`, then one reboot to prove event 255 is gone |
| F6 | `suspend_windows_process` (Jev advisory rated the approval-only gate "needs more" at 0.36 and named a live positive control as the first remaining gap at 0.71; it ships dormant until you approve a proposal, and no automatic rung exists): approval-only, identity-checked (pid + image + start time) NtSuspendProcess for an unsigned global keyboard watcher, exact resume on undo, never auto | approve one when it is ever proposed; an isolated positive control before any automatic rung |

## What is working, measured

| Capability | Evidence tonight |
| --- | --- |
| Collector freshness | 51 FRESH, 0 stale, reviver recovered the 25-minute churn around the installs |
| Native Sysmon ingestion | complete, 15,019 events in one pass, channel at sequence 140,387 |
| Input watchers | hooks and sinks attributed; polling (1003) proven loggable at 0x1400; r4 ships it |
| Privacy seal | mic and camera Deny, collector fresh, breach would read high within 5 min |
| OS hardening | 19 ASR rules, DEP/SEHOP/CFG, script host off, browser debugging refused |
| Release integrity | root-owned sealed release, expect-base refusal model-checked today |
| Evidence | hash-chained log, admin-only vault, anchors (vault cadence limits F2) |

## Order of work

1. F1 alert channel (your key or the toast extension), same day.
2. F3 API token: small change, closes the Windows-side control path.
3. F4 decide on BitTorrent Web; collapse peer findings either way.
4. F5 apply the revised Sysmon baseline; reboot once to prove it.
5. F2 service user and SYSTEM supervisors (C3, C4, C5, C6): the structural fix, one planned
   maintenance window with a rollback.
6. C1 answer-route authority and C7 vault hardening: small, deterministic, testable.
7. F6 Windows suspend action.
