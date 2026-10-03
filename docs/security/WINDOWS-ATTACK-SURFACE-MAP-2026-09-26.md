# Windows attack surface map for JARVIS

Research and source review, 2026-09-26. This is a coverage specification, not a
claim that every attack is detectable or that the current installation is healthy.
Windows edition, hardware, installed software, user roles, and connected services
change the actual surface. A local administrator or compromised kernel can falsify
host observations. Each row needs a per-machine inventory, a sensor receipt,
freshness/loss accounting, and a safe validation before it earns a coverage claim.

## Boundary and evidence contract

For every monitored transition, retain: boot/epoch, sensor identity, sequence or
record ID, event and observation times, user/session, process instance (not PID
alone), object/endpoint identity, source health, causality if known, and evidence
integrity. Preserve `unknown` when attribution or a sensor is missing. Track
collection permission, OS support, log configuration, volume, lost records, latency,
and retention. A snapshot proves state at one time; it cannot prove that a short
action did not occur between samples. Monitoring must not record speech, media,
keystroke contents, documents, or secret values merely to fill a coverage gap.

This checkout already contains broad but partial Windows monitoring: Sysmon,
Defender and Task Scheduler native channels; Windows PowerShell collectors for
posture, identity, network, persistence, devices, capabilities, input, and other
areas; plus a resident input/audio-control sampler. These are source-observed
capabilities. The native sensor's isolated service design is explicitly **not
installed or live validated** in its own README. The live host and its current
Windows policies were not checked for this research. The machine-readable
`jarvis/core/assurance.py` register is the authority for existing claims.

## Surface inventory and JARVIS gaps

`Partial` means relevant code exists, not complete or live coverage. `Gap` means
this review did not find a dedicated, validated observation path. The proposed
signals are design targets, not instructions to enable high-volume auditing.

| Windows boundary | Attacker opportunity and user impact | Current source evidence | Next observation / validation target |
|---|---|---|---|
| Firmware, UEFI, boot, TPM, recovery | Bootkit, altered boot policy, recovery-key exposure, rollback of security state | Partial posture/boot inventory | Secure Boot and measured-boot state across boots, TPM quote with trusted baseline if attestation is claimed, BitLocker protector/recovery changes, firmware update provenance; treat inventory alone as no attestation. |
| Kernel, drivers, hypervisor, hardware security | Vulnerable/signed-driver abuse, VBS/HVCI disablement, kernel sensor evasion | Sysmon driver events, evasion/posture checks: partial | Effective App Control/driver blocklist/VBS/HVCI state, driver load and identity, boot-time lost-event accounting, independent comparisons; kernel compromise remains a fundamental blind spot. |
| Windows services and privileged components | Service hijack, DLL search/order abuse, token escalation, COM/RPC abuse | Persistence, backdoor, hidden-process and process collectors: partial | Service/config/binary/ACL transitions, protected-process and privilege transitions, service-to-image identity, selected COM registrations and RPC exposure. |
| Process, memory, script, execution | Malicious binaries, PowerShell/WMI/script chains, injection, LOLBins, unsigned code | Sysmon/process/memory/implant collectors: partial | ProcessGuid lineage and actual loaded image, process access/injection where available, script-block/AMSI health, App Control/ASR decisions and exclusions, signed-policy provenance. |
| Persistence and tasking | Run keys, scheduled tasks, WMI subscription, IFEO, browser/Office add-ins, services | Autostart/ASEP/task/registry monitoring: partial | Full ASEP delta inventory with owner/ACL and execution proof, WMI consumer/filter/binding, management-policy changes and task-event delivery gaps. |
| Local identity and sessions | Password spraying, remote logon, admin-group changes, token/session theft | Identity and brute-force collectors: partial | Complete Security-channel policy/receipt, logon type and session graph, group/privilege changes, remote session creation, Windows Hello/credential guard effective state. |
| Secrets and trust stores | DPAPI, browser credentials/cookies, tokens, certificates, SSH keys, wallet data | Secret and credential collectors: partial | Access to protected stores by process identity, certificate/private-key/trust-root changes, DPAPI policy/use metadata where supported; no secret contents. |
| Files, folders, volumes, backup | Ransomware, tampering, data theft, shadow-copy/backup destruction | Sysmon file events and host scans: partial | Protected-path mutation/rename/delete, origin of downloads and archive extraction, backup/shadow-copy transitions, removable-media writes, recoverability test. |
| Network and name resolution | Inbound access, C2, tunneling, proxy/VPN/DNS manipulation, lateral movement | Netwatch, firewall, internet, sniffing, Sysmon: partial | Per-interface/routes/DNS/proxy/firewall rule transitions, attributed sockets and DNS, VPN/remote-tunnel state, Wi-Fi roam and WSL/Hyper-V boundaries; account for encrypted traffic. |
| Browser, mail, document, and social entry | Phishing, malicious downloads, extension abuse, OAuth grants, fraudulent prompts | Optional browser Veil and web collectors: partial and browser validation unproven | Consented browser integration with download→file→execution provenance, extension and permission changes, safe point-of-action warnings; no page-content surveillance by default. |
| Audio **output** and routing | Unexpected playback, deceptive prompts, inaudible/remote sink, Bluetooth or RDP redirection, output stream capture | Endpoint inventory plus default-output volume/mute and per-app level sampler: partial | All render endpoints and defaults per role/session, route changes, active sessions by endpoint and process instance, Bluetooth/RDP/virtual endpoint origin; see audio contract below. |
| Audio **capture** | Microphone surveillance or capture of system playback via WASAPI loopback | Capture-device and capability ledger inventory: partial | Mic-use provenance and stream/session transitions where supported; explicitly test WASAPI loopback, which can capture render output without a hardware recording device. No raw samples. |
| Video, display, input, clipboard | Camera/screen capture, fake input, accessibility abuse, clipboard exfiltration, remote display | Controlwatch, pixel, input hook, Win32k trace: partial | App-to-device/desktop provenance, screen-capture and remote-display transitions, clipboard access metadata only if a reliable supported sensor exists; physical OSD/KVM remain outside host visibility. |
| USB, Bluetooth, printers, radios | Rogue HID, storage exfiltration, nearby pairing, printer/phone egress | PnP/device and some USB history: partial | Arrival/removal plus actual class/function, stable device identity, pairing and trust changes, mount/volume identity and attributed transfer; avoid treating a new device as malicious by itself. |
| Windows Update, software supply chain | Malicious update/installer, rollback, package-store poisoning | Toolchain/signature/posture checks: partial | Update policy/source/history, installer origin and signature, package/service version transitions, App Control decisions, installed artifact against publisher provenance. |
| WSL, Hyper-V, containers, RDP/remote desktops | Cross-OS execution, shared mounts, virtual NICs, remote device/audio redirection | WSL/Linux collectors and topology work: partial | Explicit Windows↔WSL process/file/socket edges, VM/container inventory, shared-mount and port-forward exposure, RDP session/device redirection; cross-boundary owner can remain unknown. |
| Accounts and cloud control plane | Entra/Microsoft account session takeover, OAuth consent, sync/backup abuse | Local identity/browser signals only: gap for full cloud plane | Provider-backed sign-in, consent, token, device and audit receipts only with authorized integrations; a local endpoint cannot infer full cloud account state. |
| JARVIS and security sensors | Sensor stop, log clear/overflow, exclusion change, forged telemetry, repair loop | Native delivery and assurance checks: partial | Independent sensor integrity, channel-specific freshness/loss, effective Defender/ASR policy, protected storage, restart/rollback proof; losing visibility must be reported as loss. |

Microsoft's [Sysmon event reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events),
[advanced audit policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings),
[attack surface reduction overview](https://learn.microsoft.com/en-us/defender-endpoint/overview-attack-surface-reduction),
[application/driver control](https://learn.microsoft.com/en-us/windows/security/book/application-security-application-and-driver-control),
[device control](https://learn.microsoft.com/en-gb/defender-endpoint/device-control-overview),
and [hardware root of trust](https://learn.microsoft.com/en-us/windows/security/book/hardware-security-hardware-root-of-trust)
define the Windows mechanisms behind these rows. Availability and event detail
vary by edition, version, configuration, privilege, and hardware.

## Audio output: the first new sensor design

### Implementation invariants, recorded before editing

- Preserve the existing endpoint, microphone, input, and event evidence; a
  failed Core Audio query cannot overwrite the last clean route baseline.
- Missing endpoints, failed enumeration, ambiguous session PID, and a stale
  sample remain `unknown` or visibility debt, never evidence of no playback.
- Keep endpoint and process identity separate from mutable names and bare PIDs;
  no audio samples, speech, private media, or credentials enter storage.
- Bound each pass by a fixed endpoint/session count and timeout; report
  truncation, errors, and retry exhaustion rather than silently dropping rows.
- Never switch or mute a user's audio endpoint automatically. Preserve the
  existing release and rollback path; score credit requires live evidence.

For the first implementation, a dedicated Core Audio snapshot in the existing
five-minute controls job is the simplest verifiable design. It can enumerate
**all** endpoints and route roles, and reconcile sessions with the prior clean
snapshot without adding a second resident Windows process. Its measured cost
and false-positive rate determine whether a later callback-based desktop
helper is justified. A callback helper would see shorter transitions, but
adds a new lifecycle, spool, identity and recovery path. The snapshot cannot
observe a short session or route change that begins and ends between passes;
that remains an explicit gap until event delivery is implemented and tested.

**Threats to distinguish.** (1) An application raises volume or starts playback
without an expected user action; (2) a call or private media is routed to a new
Bluetooth, HDMI, virtual, or remote-session endpoint; (3) another process
captures the system output mix; (4) a driver or endpoint change removes audio
or substitutes a device. Ordinary call software, media apps, headset controls,
accessibility tools, and user device switching are common benign explanations.

**Present observations.** `controlwatch.ps1` inventories present audio render
and capture devices every five minutes. `inputhook.ps1` samples the default
render endpoint's volume/mute each second and its per-app session volume every
two seconds. It associates changes with recently observed media keys, but the
code itself says a key or change source cannot always be attributed. The
capability ledger tracks microphone use. None of these proves that sound played,
which physical/remote device received it, or which process changed the default.

**Proposed minimum metadata-only sensor.** In the interactive Windows session,
use Core Audio device notifications for endpoint arrival/removal/state/default
changes; enumerate render and capture endpoints and the console/multimedia/
communications roles; watch session create/state/volume events on **each**
endpoint and periodically reconcile to recover missed callbacks. Record stable
endpoint ID, flow/role, device kind/transport when available, session instance,
process creation identity, state transition, timestamp, and sensor loss. Verify
that PID reuse, shared/system sessions, exclusive-mode streams, RDP audio
devices, Bluetooth reconnect, and applications selecting a non-default endpoint
are reported honestly. An active session is evidence of a stream/session, not
proof of audible content or malicious intent. Windows documents Core Audio
[device events](https://learn.microsoft.com/en-us/windows/win32/coreaudio/device-events),
[audio sessions](https://learn.microsoft.com/en-us/windows/win32/coreaudio/audio-sessions),
[volume callbacks](https://learn.microsoft.com/en-us/windows/win32/coreaudio/volume-controls),
and [stream routing](https://learn.microsoft.com/en-us/windows/win32/coreaudio/stream-routing).

**Separate loopback-capture proof.** WASAPI can capture a render device's
system mix without a hardware loopback device, including audio from other
sessions. Endpoint inventory and the microphone ledger cannot establish that
it was absent. Research a supported, measured observation of loopback stream
creation or another defensible detector; until a positive control and negative
control succeed on the actual Windows build, label this `unobserved`.
[Microsoft's WASAPI loopback documentation](https://learn.microsoft.com/en-us/windows/win32/coreaudio/loopback-recording)
also notes remote-desktop audio devices are session-specific. Do not record
audio buffers, infer speech, or claim universal loopback detection from process
names or a disabled “Stereo Mix” device.

**Acceptance gate.** In an isolated test account, exercise normal playback,
non-default playback, default-role change, Bluetooth and RDP redirection if
available, user and software volume changes, a consented WASAPI loopback
positive control, endpoint removal, sensor restart, missed callback, stale
receipt, and log/buffer exhaustion. Measure detection latency, CPU, memory,
disk writes, event loss, and false alerts. JARVIS should warn on a corroborated
unexpected route or surveillance-relevant transition; no automatic audio
blocking, muting, or device disablement without a tested safety/recovery path.

## Implementation order

1. **Visibility contract:** measure the live installation, Windows edition,
   active policies, native channel health, and per-row `observed / partial /
   unavailable / untested` state. Do not add score credit from this document.
2. **Audio and device path:** implement the metadata-only endpoint/session
   sensor with loss/restart handling and validate the controls above. Keep
   loopback capture as an explicit blind spot until a real positive control
   proves a detector.
3. **High-consequence transitions:** effective security-policy/exclusion,
   privileged identity/session, driver/boot, backup destruction, and
   cross-Windows/WSL boundaries. Prefer the Windows event channels and narrow
   reconciliation over broad continuous polling.
4. **Human-facing entry and egress:** consented browser/download provenance,
   external-device transfer, account/OAuth integrations, and remote sessions.
   Require actual provider/browser evidence for any protection claim.

The selected approach is incremental event collection plus bounded snapshot
reconciliation: events preserve short transitions, while snapshots expose
missed-event disagreement. A snapshots-only design misses short-lived actions;
an events-only design cannot explain a channel that was disabled, overflowed,
or started late. Reconsider the sensor split if measured event volume, service
availability, battery cost, or Windows API reliability fails the stated budget.
