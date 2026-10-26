# Fending off spyware: measured state and plan (2026-10-21)

Scope: a single-owner Windows 11 25H2 laptop (build 26200.9711) with WSL, protected by
JARVIS user-mode sensors (ETW, Sysmon, registry, `/proc`), no kernel driver. The governing
[Maximum Assurance directive](../security/MAXIMUM-ASSURANCE.md) applies: nothing here claims
complete coverage, silence is never proof, and external advice cannot authorize an action.

"Fully guarded" is not reachable from user mode: a kernel driver, a hardware keylogger, an
administrator or firmware sit below every sensor JARVIS has. The honest goal is
**(1) prevent** what the OS lets us lock, **(2) see** every user-mode spyware stage the OS
exposes, **(3) corroborate** across independent views so one blinded sensor is not a blinded
machine, and **(4) alert the owner** with evidence and a recovery path. This document records
what is live, what is built but not deployed, what is missing, and the order to close it.

## 1. What spyware on this laptop must do, and what JARVIS sees today

| Stage | Mechanism (user mode) | JARVIS today | Status |
| --- | --- | --- | --- |
| Capture keys | `SetWindowsHookEx` WH_KEYBOARD_LL (13) | Win32k ETW 1002 via elevated broker (`inputaudit.ps1`), per-process, signed/unsigned | live, positive control 2026-09-23 |
| Capture keys | `RegisterRawInputDevices` RIDEV_INPUTSINK | Win32k ETW 1001, keyboard sink reported high | live, positive control 2026-09-23 |
| Capture keys | `GetAsyncKeyState` polling | Win32k ETW 1003 counted, reported **low** as "unexpected" | **mis-measured** (section 2) |
| Capture keys | `RegisterHotKey` (Hotkeyz class) | nothing | gap, no OS telemetry |
| Capture keys | DirectInput | nothing specific | gap |
| Capture screen | packaged-app `Windows.Graphics.Capture` | consent-store ledger for both graphicsCapture capabilities (`spy` 90 min, `controls` 5 min live; `privacy` in checkout); `pixel` posture hourly | live |
| Capture screen | desktop-app `BitBlt`/`PrintWindow`/DXGI duplication | nothing; Windows gates none of these | gap, no OS telemetry |
| Capture mic/camera | consent-store ledger (`LastUsedTimeStart`), audio session enumeration | `spy` + `controls` ledger live; `audio` sessions live; `privacy` posture and owner seal in checkout | live; seal built, never applied |
| Capture clipboard | `AddClipboardFormatListener`, `SetClipboardViewer`, polling | nothing; no OS telemetry | gap |
| Steal browser secrets | copy `Login Data`/`Cookies` by command line | techniques rule + intrusion credentials rule on command lines | live |
| Steal browser secrets | read browser network-service memory (ChromeKatz), COM `IElevator` decrypt, debugger attach | Sysmon ProcessAccess watches only `lsass`/`lsaiso`; no rule for browser targets or the elevation CLSID | **gap, ranked first** (section 3) |
| Steal browser secrets | `--remote-debugging-port` | internetwatch high, attackmap T1185 | live |
| Dump credentials | LSASS access | Sysmon 10 on lsass/lsaiso; RunAsPPL + CredGuard on | live |
| Inject | Sysmon 8/10/25, memscan unbacked executable memory, hooked Nt* stubs; reflective PE check | 8/10/25 live; reflective check in checkout only; **no ImageLoad (7) in the baseline although `sysmon.py` has a type-7 detector** | partial |
| Persist | Run keys, tasks, services, WMI, startup folder | Sysmon baseline (registry, FileCreate on Tasks/Startup), controlwatch, provenance | live |
| Hide | process cross-view contradictions (WMI/API/Sysmon/native) | hidden-process collector + `jarvis reason spyware` | live / on demand |
| Egress | external connections per process, beacon timing | internetwatch, spy_evidence external connections; no beacon-interval model | partial |
| Remote control | RMM / remote-desktop tools | REMOTE_AGENTS names in `firewall` and `control` jobs, `pixel` REMOTE_TOOLS, RDP/WinRM/sshd state, type 3/10 logons | partial, name-based |
| Respond | kill, suspend, quarantine, block | `block_network` (Windows firewall), `disable_autostart` (Windows), `quarantine` and `suspend` (**Linux only**); no Windows process kill or suspend exists; no containment validated | partial |
| Disable defenses | Defender exclusions, ASR audit mode, Sysmon config drift, tamper | posture, Sysmon config hash vs baseline, `tamper.py` | live / checkout |

Prevention layer, read live today: RunAsPPL 1, Credential Guard and HVCI running, tamper
protection on, 7 ASR rules block and 3 audit, **Smart App Control off**
(`VerifiedAndReputablePolicyState` 0), DEP/SEHOP/CFG at default, user and kernel shadow
stacks off, firewall logging on all profiles.

## 2. The polling-keylogger blind spot is probably a probe artifact

The register says polling loggers are invisible because 1003 was absent under a positive
control on 2026-09-23. The reverse-engineered Win32k source
(`repnz/etw-providers-docs`, `NtUserGetAsyncKeyState.c`) shows the kernel evaluates the
anomaly **only when a key event arrives**, and writes 1003 only for processes with
`BackgroundCallCount / MsSinceLastKeyEvent >= 1`, i.e. at least one call per millisecond
since the previous key event. The September control made about 10,000 calls in 90 s,
roughly 0.1 calls/ms, an order of magnitude under the gate. A real polling keylogger
scans all 256 virtual keys every few milliseconds, which is tens of calls per millisecond.
Velociraptor's `Windows.Detection.Keylogger` artifact and Elastic Defend both consume 1003 on
current builds (thresholds: `MsSinceLastKeyEvent > 100`, `BackgroundCallCount > 400`).

Jev (metadata-only, advisory) put "probe artifact rather than OS property" at 0.71.

Re-measure before changing any claim: `scripts/tools/probe-win32k-polling.ps1` (elevated,
owner present and typing). It polls every virtual key in a tight loop, discards every value,
and reports each 1003 row and whether the control pid was attributed. If it fires:

- raise the `inputaudit` polling finding from low "unexpected" to a per-process finding with
  the pid, rate and signer, same shape as hook/sink rows (`watchers.py`), with the
  Velociraptor thresholds as the first calibration and Explorer/known IMEs excluded by
  verified path and signature, never by name;
- rewrite the `input_surveillance` blind spot in `assurance.py` and the memory note.

If it does not fire, record the measured rate so nobody repeats this.

## 3. Gaps ranked, with the evidence each closes

Jev (metadata-only, `choice` over eight gap labels) ranked the browser-memory-read gap first
at 0.81, Smart App Control second at 0.15, and said "measure volume before deploying" (0.33
for deploy-without-measurement) on the ProcessAccess rule. Advisory only; the order below
is mine and is justified by the measurements.

1. **Browser secret theft through memory or COM (T1539/T1555.003).** Every 2025-2026
   stealer family bypasses Chrome/Edge app-bound encryption by reading the
   `--utility-sub-type=network.mojom.NetworkService` child's memory, calling the elevation
   service COM object (`{708860E0-F641-4611-8895-7D867DD3675B}`), attaching as a debugger,
   or launching the browser with a debugging port. JARVIS sees only the last one.
   Build: (a) Sysmon `ProcessAccess` include for `TargetImage` ending in `\msedge.exe`,
   `\chrome.exe`, `\firefox.exe` with `SourceImage` excluding the same browser image,
   `GrantedAccess` containing VM_READ (0x10) or ALL_ACCESS; (b) a technique rule for
   "browser process ended, `elevation_service.exe` started within 1 s, then a non-browser
   caller"; (c) an unsigned image loaded from the browser's Application folder, which
   needs an `ImageLoad` include for that folder (none exists today); (d) a loopback
   connection to a browser-owned port from a non-browser process (internetwatch samples
   sockets every two minutes; Sysmon 3 excludes loopback).
   Measure Sysmon 10 volume for 24 h in the replay harness (`scripts/dev/replay_techniques.py`)
   before applying; boot-time registry overflow is a known risk on this host.
2. **Polling keylogger re-measurement** (section 2). Cheapest possible fix if the probe fires.
3. **Smart App Control** is off. On 25H2 after the April 2026 update it can be enabled
   without reinstalling, and it blocks unsigned, unknown binaries, which is the carrier for
   almost every commodity stealer. Cost: unsigned developer tools and self-built binaries
   stop running; October's KB5127648 greyed the toggle on some devices. Jev was undecided
   (0.49). Owner decision; JARVIS should at least **report SAC state in posture** (not read
   today) so a silent failure is visible.
4. **Capability Access Manager history.** Windows 11 keeps a per-app SQLite history
   (`C:\ProgramData\Microsoft\Windows\CapabilityAccessManager\`, about a month) beyond the
   registry snapshot the `privacy` collector reads. Reading it through the elevated broker
   closes the "reopen-and-reclose inside one five-minute interval" blind spot for mic,
   camera and packaged screen capture.
5. **Remote-access tool chains.** Current reporting is by process name. Add: two remote
   agents installed within hours, an installer that creates an inbound firewall rule,
   `.scr` execution outside `System32`, and PowerShell spawned by an RMM agent, each from
   Sysmon 1/13 and the firewall log already collected.
6. **Beacon timing.** Per-process periodic outbound connections to one destination with low
   jitter, from the existing connection samples; no new sensor.
7. **Hotkey keyloggers, Win32 screen capture, clipboard listeners.** No OS telemetry.
   Options are an undocumented-kernel-table read (Elastic's `gphkHashTable` approach, needs a
   driver), or honest "inherent" entries plus indirect signals: an unsigned process holding a
   message-only hidden window with a message loop and no visible windows (window trace),
   periodic image-sized writes to a staging directory, and the existing
   `jarvis reason spyware` chain rule (capture + persist + egress).

## 3a. Code-level gaps the inventory found that no document states

Verified in the checkout today (branch `native-hosts`):

| Gap | Evidence | Consequence |
| --- | --- | --- |
| Sysmon baseline has no `ImageLoad` element | `grep -c ImageLoad` on the baseline returns 0; `sysmon.py:703` handles event 7 | unsigned DLL and side-load rules never fire; the MEMORY-DEFENSE claim of image-load rules is wrong |
| No `ClipboardChange` (24) or `RawAccessRead` (9) | baseline | clipboard and raw-disk reads unlogged (24 would store clipboard text in Sysmon's archive, so adding it is a privacy decision, not a free win) |
| Registry includes lack Defender, CLSID/COM, LSA, AMSI and Autologger keys | baseline lines 89-99 list only Run, RunOnce, Services, Winlogon, IFEO, Policies\Explorer\Run, App Paths, ConsentStore | `tamper.py` writer attribution for Defender exclusions is always "unknown"; COM hijack is seen only by the hourly `asep` poll |
| Sysmon 10 watches `lsass`/`lsaiso` only | baseline lines 53-56 | browser, password-manager and JARVIS-process memory reads are unlogged |
| Sysmon 3 excludes loopback | 24 private-range excludes | a non-browser client on a browser debugging port is visible only to the two-minute socket sampler |
| Win32k 1000 `SetWinEventHook` counted, never reported | `inputaudit.ps1` counts, `watchers.py` drops kind `winevent` | UIA/WinEvent-based screen readers and window scrapers are invisible even when Windows logs them |
| Sysmon 6, 11, 17, 19-21 logged but no detector | agent sweep of `sysmon.py` | driver loads, startup-folder drops, named pipes and WMI subscriptions reach the event log with attention priority only |
| Spyware reasoning engine on demand only | SPYWARE-REASONING.md:3 | the chain rule (capture + persist + egress) never runs unattended |
| `docs/security/WIN32K-INPUT-AUDIT` cited, missing | SPYWARE-REASONING.md:221 | the 2026-09-23 measurement lives only in the memory note and in `C:\ProgramData\Jarvis\Probe` |

Each baseline change needs a replayed volume measurement first: boot 94 overflowed the Sysmon
driver queue under a broader registry policy, and the current policy still queued 78,883
events before the service started.

## 3b. ORION prioritisation (2026-10-21, second pass)

The owner asked for the plan to be run through ORION's new prioritisation engine
(`~/orion/src/decision-engine/prioritize.ts`): Jev rates each option on seven dimensions
(impact, urgency, reach, confidence, effort, leverage, reversibility) as a belief over five
levels, each question asked twice with the levels reversed; deterministic code turns the
beliefs into Eisenhower, Impact/Effort, RICE, ICE, WSJF and Leverage matrices, a Borda
consensus, Kendall's W for agreement, and an exact WSJF lottery for P(first). State sent was
metadata only (the measured facts in section 1, no host names or paths). Script:
scratchpad `orion_prioritize.ts`, run with Bun from the ORION checkout.

| Consensus | Measure | Eisenhower | Matrix | P(first) | WSJF | Leverage |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Sysmon image-load + Defender/COM/LSA/AMSI registry rules | do now | quick win | 0.16 | 8.5 | 3.4 |
| 2 | Smart App Control on | do now | quick win | 0.16 | 8.2 | 3.3 |
| 3 | Administrator Protection on | delegate | fill-in | **0.25** | **9.9** | **3.6** |
| 4 | ASR: 3 audit rules to block, 9 unset rules added | do now | quick win | 0.12 | 7.6 | 2.8 |
| 5 | Browser-memory / COM cookie-theft rules | do now | quick win | 0.05 | 6.5 | 2.8 |
| 6 | DEP/SEHOP/CFG + shadow stacks | delegate | fill-in | 0.12 | 7.8 | 2.5 |
| 7 | Windows suspend/kill response action | do now | quick win | 0.04 | 5.7 | 2.4 |
| 8 | Privacy seal + Capability Access Manager history | delegate | fill-in | 0.05 | 5.9 | 2.0 |
| 9 | RMM chain + beacon-timing rules | do now | quick win | 0.02 | 4.9 | 1.9 |
| 10 | Polling-keylogger re-measurement | drop | fill-in | 0.04 | 6.0 | 1.9 |

Agreement across the five frameworks: W = 0.73. Every option is a two-way door.

How this changed the plan:

- The OS-level **prevention** measures (SAC, Administrator Protection, ASR, mitigations) moved
  ahead of most detection work. They are hours of owner time, reversible, and they remove the
  carrier (unsigned unknown binaries, standing admin tokens, script droppers) rather than
  detecting one technique. They are now the first block of the command file.
- **Sysmon policy extension** ranks first on consensus, but it remains gated by a replayed
  volume measurement (boot 94 overflow); it ships as a JARVIS release, not an owner command.
- **Administrator Protection** has the highest P(first) and leverage, but ORION filed it under
  "delegate" (lower impact belief), and Microsoft's documentation (2026-10-13) says not to
  enable it on devices that require Hyper-V and that WSL must be reinstalled inside the
  elevated profile. JARVIS runs in WSL 2 and its elevated tasks read this distro, so the
  measure is recorded in the command file as "not yet", with the commands kept for the day
  the restriction lifts. ORION's state did not contain that constraint; the engine cannot know
  it, which is why its output stays advisory.
- The **polling probe** dropped to last: it is a measurement, not protection, and ORION's
  impact belief for it is low. It stays in the plan because it corrects a false register
  claim cheaply, not because it reduces risk.
- Jev's single-question pick of browser-memory rules as "first" (section 3) and ORION's
  consensus disagree; both are advisory. The deterministic facts that decide are: SAC off,
  nine ASR rules unset, no ImageLoad in the policy. Those are closed in that order.

Commands: [SPYWARE-HARDENING-COMMANDS-2026-10-21](../guides/SPYWARE-HARDENING-COMMANDS-2026-10-21.md).

### Applied the same day

- Windows, elevated, one UAC prompt (`scripts/harden/harden-antispyware.ps1`, receipt in
  `%LOCALAPPDATA%\Jarvis\Hardening`): ASR now 19 rules (10 block, 9 audit), Defender cloud
  block High, DEP/SEHOP/CFG system-wide, Windows Script Host and AutoRun off, module logging
  and 4688 command lines on, Chrome and Edge remote debugging refused by policy, LLMNR and
  NetBIOS off. Posture's "ASR rules are not enforcing" finding cleared on the next run.
- Checkout (source-tested, 1 release pending): 1003 polling rows classified like hooks with
  the kernel's measured call rate, WinEvent hook holders listed at low/ok, an unattributed
  polling count reported medium, posture reads Smart App Control. Jev advisory on the
  implementation (metadata-only): proportionate 0.72, WinEvent level 0.81, unreadable-as-gap
  0.93; the first validation gap to close is the owner polling probe (0.94).
- Not done, by design: a stored sudo password. The fixed-operation deploy helper that would
  replace it was written but its installation is the owner's (see the command file).

## 4. Already built, needs the owner (in order)

Verified live today, commands in [PENDING-OWNER-ACTIONS-2026-10-21](../guides/PENDING-OWNER-ACTIONS-2026-10-21.md):
install the native sensor stage; release then `jarvis broker install` (reflective-image
check); deploy the `privacy` collector and the ConsentStore Sysmon rule, then
`jarvis privacy seal` and a real capture attempt as the acceptance test; turn the three
audit-only ASR rules to block; enable user and kernel shadow stacks.

## 5. Inherent, recorded so silence is not mistaken for coverage

Kernel-mode or driver-based loggers (BYOVD), hardware keyloggers, firmware, administrators
and PPL processes, `GetAsyncKeyState` below 1 call/ms between key events (by kernel design),
hotkey and DirectInput capture, Win32 screen capture, clipboard readers, and anything that
happens inside an interval of a sampling collector. Windows 11 26H2's built-in Sysmon does
not change the event set.

## Sources consulted

Elastic Security Labs: "Protecting your devices from information theft" (ETW keylogger
detection), "Detecting hotkey-based keyloggers", "Katz and Mouse Game" (ABE bypass
telemetry); Velociraptor `Windows.Detection.Keylogger`; `repnz/etw-providers-docs`
Win32k reverse engineering; Microsoft Security blog on RMM-tool phishing (2026-09) and
Lumma Stealer; MITRE DET0509/DET0037; Microsoft Learn on Smart App Control, Sysmon in
Windows, Administrator Protection and `Windows.Graphics.Capture`; Capability Access
Manager forensics write-ups.
