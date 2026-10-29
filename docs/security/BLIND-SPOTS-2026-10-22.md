# Blind-spot register, 2026-10-22 (evening)

Every row was read from the live machine, the live store (`~/.jarvis/jarvis.db`),
the installed release (`/opt/jarvis/current`, release `2dac3942680a`, deployed
19:16) or the assurance register in `jarvis/core/assurance.py` on 2026-10-22.
Nothing here is a compromise verdict. A blind spot is a place where silence
must not be read as "clean".

Classes used below:

- **Inherent**: no software on this host can close it. Recorded so nobody
  mistakes silence for coverage.
- **Platform**: Windows, WSL or the firmware withholds the telemetry; closable
  only by a different privilege, a kernel component, or a Microsoft change.
- **Built, not live**: code exists in the checkout and is tested, but the
  running release does not contain it, or it is not scheduled, or it needs an
  elevated install the owner has not done.
- **Owner**: needs an owner decision or elevation.
- **Design**: a limit of how JARVIS is built (sampling, user-mode, same user).

## 1. Sensor-level blind spots (what no collector can see)

| # | Blind spot | Class | Evidence today |
|---|---|---|---|
| S1 | Kernel-mode anything: a rootkit or a malicious driver can lie to every userland view at once | Inherent (no kernel component) | coverage finding "no kernel component"; cross-view checks make lying visible, not impossible |
| S2 | 22 Protected Process Light processes, plus 166 processes this pass that could not be opened, are outside the memory scan | Platform / Owner | memscan: "166 processes could not be opened… 182 were scanned"; broker memscan staged copy differs from the reviewed one, so its elevated results are discarded (`watchdogs`) |
| S3 | Firmware, SMM, anything below the first measured boot stage; BIOS setup, boot menus, POST beep; UEFI variable contents, boot order, BCD, EFI partition | Inherent / Owner (elevation) | preos register; dbx update failing 0x80071149 since boot 182 |
| S4 | Polling keyloggers (`GetAsyncKeyState`) are invisible until the broker traces keyword 0x1400; watchers registered before the broker's trace starts each boot are unseen; the trace does not survive reboot | Built, not live (stage r4) + Platform | assurance input_surveillance; broker inputaudit last run timed out after 120 s (`input` finding) so the current watcher list is unknown |
| S5 | `RegisterHotKey` and DirectInput capture (no OS telemetry). `SetWinEventHook` holders are now reported as a low inventory naming unsigned ones (checkout 2026-10-23, in stage r3) | Platform / Built, not live | SPYWARE-DEFENSE §1 and §3a; `watchers.py` |
| S6 | Desktop-app screen capture (`BitBlt`, `PrintWindow`, DXGI duplication) and clipboard listeners | Inherent (Windows gates none of them) | consent ledger covers packaged apps only |
| S7 | Kernel-streaming audio/camera capture, drivers and administrators bypass the user-mode consent seal; WSL has no consent store | Inherent | privacy seal register |
| S8 | External monitor (S22i-30) has no WMI brightness provider; physical OSD buttons, KVM, monitor firmware emit nothing | Inherent | controls snapshot: one brightness instance (internal LGD0725) |
| S9 | Wi-Fi SSID/BSSID/cipher denied to the collector; evil-twin and downgrade detection cannot run | Owner (machine-wide location is Deny in HKLM; privacy trade) | netwatch medium finding |
| S10 | The WSL DNS tunnel listener (10.255.255.254:53) and loopback udp/323 are held by the VM root outside the distro | Inherent | hidden/deep_hidden findings |
| S11 | `/proc/sched_debug` and performance-counter cross-views absent in this kernel; auditd blocked by the WSL2 kernel (EPERM on the audit netlink) | Platform | hidden, auditd findings |
| S12 | Sysmon drops events at every boot: 41,383 queued before the service started last boot (39,612 registry) | Owner (apply the revised baseline, then reboot to measure) | sysmon medium "lost events while starting at boot"; evidence high "Sysmon is not running the reviewed baseline" (running 72a1d0…, baseline 85a52f…) |
| S13 | Sysmon log (256 MB) wrapped past the native cursor on 2026-10-21, Task Scheduler (10 MB) on 2026-10-18; journald rotated ~5 min past the last read this pass | Owner: step 7 of CLOSURE-COMMANDS (wevtutil sizes, journald drop-in) | native "Records missing", sysmon_linux "journal rotated" |
| S14 | Baseline now records unsigned ImageLoad, browser ProcessAccess and the Defender/CLSID/LSA/AMSI/Autologger families (checkout 2026-10-22, in stage); not applied to the running Sysmon until the owner runs `jarvis broker sysmon-baseline`. Still absent on purpose: ClipboardChange (24, stores clipboard text), RawAccessRead (9), loopback NetworkConnect | Owner (apply) | tests/test_windows_sysmon_policy.py |
| S15 | Sysmon 6, 11, 17/18, 19–21 now have detectors (checkout 2026-10-23, in stage r3): unsigned or staged driver loads critical, Startup-folder and drivers-folder drops high, attack-tool pipes high/critical, WMI subscriptions critical. WMI field names are from the schema and no live WMI record has been seen, so T1546 stays claimed until one is replayed | Built, not live | `sysmon.py`, tests/test_sysmon_windows.py; Jev: pipe-name certainty 0.33 (wording softened), WMI field risk 0.80 (kept claimed) |
| S16 | Kernel minimal processes (Registry, Memory Compression, vmmem) have no start event; Windows interop (`/init`-backed .exe) and container execution domains are not modelled in the state graph | Platform / Design | temporal_correlation, system_state_graph registers |
| S17 | Browser: first-party or CNAME-cloaked trackers, server-side recorders, page-forgeable main-world probe; no synchronous credential/payment/OAuth interception | Design | browser_privacy_veil, online_guardian registers |
| S18 | Defender exclusions unreadable without elevation | Owner | control medium finding |
| S19 | Beacon timing: no interval model for C2; remote-control tooling is matched by name only | Design | spyware table rows "Egress", "Remote control" |
| S20 | 41 ATT&CK techniques have no collector at all, 44 are mapped without a live proof (see §6) | Design | attack map meta `attack_coverage_v1` |

## 2. Timing blind spots (what is seen too late or not at all because of cadence)

| # | Blind spot | Class | Evidence |
|---|---|---|---|
| T1 | Every sampling collector misses a change undone inside its interval: 5 min for controls, privacy, wsl, canary; 2 min for sockets; 90 min for `spy`; 10 min for technique rules on drives | Design | coverage "sampling, not interception" |
| T2 | Audio beep burst covers ~2.7 % of each 5-minute interval | Design | audio register |
| T3 | Memory scan samples: an image loaded and freed between scans is missed; byte-array loaders that erase the PE header are invisible | Design | dotnet register |
| T4 | Nothing is recorded while Windows is off, asleep, or while the WSL VM is frozen by Modern Standby; the daemon itself stopped 7 times in 4 days from hard resets | Platform | STAY-ONLINE-2026-10-22 |
| T5 | Up to ~35 min before the live event chain is sealed and vaulted, and up to 6 h between anchors: a rewrite inside that window is only tamper-evident later, and only while an anchor record survives | Design | forensic_storage, recovery registers |
| T6 | Windows and WSL clocks disagree (WSL steps back ~2.5 s every 30 s; UTC+2 vs UTC+3 offsets); detectors that compare wall-clock windows are not yet monotonic-based | Platform / Design | sensor_integrity register |

## 3. Attribution blind spots (seen, but not who)

| # | Blind spot | Evidence |
|---|---|---|
| A1 | Brightness and volume changes are recorded with timing and foreground only; no API names the actor (the brightness hotkey is ACPI, Windows dims on its own) | controls, control_events (brightness sampler added today, not live) |
| A2 | Who called `SendInput` is never identified; the hook names candidates, not the sender | input_surveillance register |
| A3 | Input stalls are symptoms and never attributed to a process; a hook installed before JARVIS's runs after it and its delay is invisible | input_hook "latency" finding text |
| A4 | Consent-store (mic/camera/capture) switches have no writer in Sysmon on this host | privacy register |
| A5 | A root process launched from Windows (`wsl -u root`) is indistinguishable on the Linux side from the thousands docker produces; a Windows-origin API call arrives as 127.0.0.1 | wsl_trust_boundary register, measured 2026-10-21 |
| A6 | Agent actors are self-declared; execution identities are not provisioned; Windows-side processes are not attributed in the component model | component_isolation register |
| A7 | Location is user-declared (Norrsken Kigali), no native fix | geo finding |

## 4. Self-protection and delivery blind spots (JARVIS watching itself)

| # | Blind spot | Class | Evidence |
|---|---|---|---|
| P1 | **No alert channel can reach you**: email not configured in the live config, the Windows monitor's mail path fails hourly (ItemNotFoundException); a toast exists in the checkout only | Owner | watchdogs critical "no alert channel can reach you" |
| P2 | The daemon, supervisors, store, config and acks run as or are writable by the user it protects; a same-user process (including any Windows process via WSL) can edit `config.json`, acknowledge findings or squat the port during the 5 s restart window | Owner (dedicated `jarvis` uid staged, not installed) | PROTECTION-REVIEW C2–C5, C11 |
| P3 | State-changing API routes are unauthenticated from Windows (token gate is in the checkout) | Built, not live | C2 |
| P4 | Release integrity is checked at start only; RELEASE.json hashes are never re-verified at runtime; `SIGSTOP` freezes the daemon for up to 15 min unseen | Design | C6, C9 |
| P5 | Elevated vault copies from a user-writable inbox without rejecting reparse points or checking chain links; sensor acks are user-writable | Design | C7, C8 |
| P6 | The elevated broker's staged memscan script differs from the reviewed copy, so elevated memory results are discarded; the broker's inputaudit timed out | Owner (`jarvis broker install` after a release) | watchdogs, input findings |
| P7 | No response exists on Windows (no kill or suspend; `suspend_windows_process` dormant in the checkout); quarantine and suspend are Linux-only; no containment has ever been validated | Built, not live / Design | F6, spyware table "Respond" |
| P8 | The reviver can restart a live daemon after resume (installed `revive-jarvis.ps1` is the 2026-09-17 copy); health monitor still on the legacy layout | Owner (re-register supervisors) | STAY-ONLINE, blind-spots 2026-10-21 |
| P9 | Memory ceiling: raised today to 2.5 GiB high / 3 GiB max; the daily whole-chain verify (75 s on 1.5 GiB) exceeded the 45 s worker deadline | fixed in checkout, measured today | STAY-ONLINE §second cause |
| P10 | `chris` is in `sudo` and `docker` (passwordless root); privileged containers running their own systemd flushed the WSL interop registration once today | Owner | C11, STAY-ONLINE table |
| P11 | C: at 97.5 % (read 22:40): a full disk took swap offline on 2026-10-11 and stalled JARVIS; disk pressure is a repeatable outage cause | Owner | blind-spots 2026-10-21 |

## 5. Built but not live (the checkout is ahead of the release)

Measured: 128 files differ between `/opt/jarvis/current/jarvis` and the checkout,
48 of them exist only in the checkout. The release schedule has no `wsl`,
`canary` or `tamper` job; the checkout schedules `wsl` and `canary` every 5 min.

| Capability | Where it stops |
|---|---|
| WSL trust-boundary checkpoint (`wslguard`) | not in the release schedule; no accepted baseline |
| Canary tokens and tamper-evident canary journal | not scheduled live; nothing planted |
| Windows tamper audit (`tamper.py`, `tamper.ps1`) | checkout only |
| Privacy seal | collector live and sealed; a real capture attempt against the seal has never been run |
| Reflective-image check in memscan (`assemblies.py`) | checkout only; the Win32k 0x1400 polling trace and the 128 MB ETL cap (stage r4) are in the live release since 2026-10-21 but the broker still runs the older staged scripts until `jarvis broker install` |
| Brightness change events in the input hook | added today; needs a release and a hook restart |
| API token on state-changing routes, desktop toast, "no alert channel" finding, peer-finding collapse, Windows suspend action, revised Sysmon baseline | stage r9 is in the live release since 2026-10-21 (release 0d3072…); the baseline is reviewed but not applied to Sysmon |
| Dedicated `jarvis` service user, SYSTEM supervisors | staged scripts; owner install |
| Gaps-job ATT&CK revocation handling, outage-mail pause, consent-store writer rule | checkout |
| Native isolated channel services and Windows monitor | built 2026-09; never installed, rebooted or soaked |
| Spyware reasoning engine, positive-control lab | on demand only; Windows lab blocked on Windows Sandbox not being installed |

## 6. ATT&CK techniques with no collector (41, live attack map)

T1001 Data Obfuscation; T1008 Fallback Channels; T1011 Exfiltration Over Other
Network Medium; T1026 Multiband Communication; T1034 Path Interception; T1041
Exfiltration Over C2 Channel; T1043 Commonly Used Port (revoked upstream); T1051
Shared Webroot; T1061 Graphical User Interface (revoked); T1062 Hypervisor;
T1064 Scripting (revoked); T1092 Communication Through Removable Media; T1104
Multi-Stage Channels; T1106 Native API; T1108 Redundant Access (revoked); T1111
Multi-Factor Authentication Interception; T1129 Shared Modules; T1153 Source;
T1175 COM and DCOM (revoked, split); T1199 Trusted Relationship; T1210
Exploitation of Remote Services; T1211 Exploitation for Stealth; T1212
Exploitation for Credential Access; T1213 Data from Information Repositories;
T1221 Template Injection; T1480 Execution Guardrails; T1486 Data Encrypted for
Impact; T1498 Network Denial of Service; T1534 Internal Spearphishing; T1554
Compromise Host Software Binary; T1559 Inter-Process Communication; T1565 Data
Manipulation; T1621 MFA Request Generation; T1622 Debugger Evasion; T1657
Financial Theft; T1659 Content Injection; T1665 Hide Infrastructure; T1667 Email
Bombing; T1668 Exclusive Control; T1669 Wi-Fi Networks; T1684 Social Engineering.

Of these, the ones a host sensor could reasonably close are T1106 (Native API:
needs ETW or a kernel view), T1129/T1554 (image-load and file-hash drift: ImageLoad
in the Sysmon baseline plus a signed-binary inventory), T1559 (named pipes: detector added 2026-10-23, validated by replay once deployed), T1486/T1565 (mass file
rewrites: FileCreate rate and entropy), T1041/T1011 (needs a per-process egress
volume model), T1622 (debugger checks are an in-process matter; only a memory
scan heuristic applies). The rest are cloud, network-infrastructure or
human-factor techniques outside a single-host monitor.

44 further techniques are "claimed": mapped to a rule that has never been seen
to fire on a live event (mostly discovery commands, removable media, reflective
loading, traffic signaling). See the attack map for the list.

## 7. What is explicitly *not* a blind spot today (measured)

- 51 collectors fresh; none stale beyond its cadence except the hourly ones at
  78–88 min (secrets, posture, intel, spy, memscan, gaps) which are inside their
  retry window.
- The input hook is in session 1, the same session as Explorer, and sampled
  20,078 events with human cadence; it is not deaf.
- Native sensor delivered events this run; the event log holds 8.6 M events in
  2,017 sealed segments.
- Containers: 9 running at 22:40, none named `argus-*`; the snapshot of the
  running set found no privileged container, no host namespace and no Docker
  socket mount.

## 8. Order of closure (highest value per owner-minute first)

1. Alert channel (P1): set `resend_api_key`, `alert_from`, `alert_to`, or
   deploy the toast stage. Until then every finding below is unseen unless you
   open the dashboard.
2. Cut and deploy one release at a commit boundary that carries stage r4
   (polling trace, reflective check) and r9 (API token, toast, suspend, Sysmon
   baseline) plus today's hook sampler; then `jarvis broker install`, re-register
   supervisors, restart the hook, apply the revised Sysmon policy, reboot once
   and read back the boot-drop count (S12, S4, P3, P6, P8).
3. Dedicated `jarvis` uid and SYSTEM supervisors (P2).
4. Sysmon policy additions: ImageLoad, ProcessAccess on browsers and JARVIS,
   Defender/COM/LSA/AMSI registry keys (S14, S15). ClipboardChange is a privacy
   decision; leave it off unless you want clipboard text archived.
5. Free C: and compact the WSL image (P11); larger Sysmon log and journald
   drop-in (S13).
6. Decide on machine-wide location (S9) and on planting canaries (§5).

Inherent rows (S1, S3, S6, S7, S8, S10) stay inherent; the only honest
mitigation is to record them and never present the dashboard as complete.
