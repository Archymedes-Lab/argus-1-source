# Blind-spot register, measured 2026-10-21

Every entry below was read from the live machine or the live JARVIS store on
2026-10-21. "Remediated" means code in this checkout fixes it (not yet
deployed). "Owner" means it needs your decision or elevation. "Inherent"
means no software on this host can close it; it is recorded so nobody
mistakes silence for coverage.

## Remediated in this checkout

| Blind spot | Evidence | Fix |
|---|---|---|
| Gaps job reports retired ATT&CK ids (T1043, T1064) and cloud-only techniques (T1578 IaaS) as high coverage gaps | 186 gap findings, 8 high, several on ids MITRE revoked or scoped to IaaS | `jarvis/intel/gaps.py`: revoked ids judged under their successor; techniques scoped outside Windows/Linux reported low as "not applicable" |
| Outage email reported as a failing path | `mail.json` was deliberately paused on 2026-09-29 (`mail.json.paused-…bak`); the monitor fails on the missing file every hour | `jarvis/service/supervisors.py` reports a pause as low with its date; the monitor script treats a missing `mail.json` as a pause |
| Consent-store writes have no writer | Sysmon policy records no `ConsentStore` keys, so a reopened privacy seal is unattributed | Baseline records the Allow/Deny switch (per-use stamps excluded); a detector rule reports a switch to Allow with the writing process (owner must re-apply the policy) |
| Capture sessions unreported; access posture unaudited | earlier today | `privacy` collector, `jarvis privacy seal`, audio capture findings |
| OS-wide memory mitigations unaudited | earlier today | posture memory defense section |

## Owner decisions or elevation

| Blind spot | Evidence | What closes it |
|---|---|---|
| Native sensor cannot read Sysmon (timeouts) | `native` partial every pass; installed sensor source still the 2026-09-18 build | install stage `native-position-20261012` (see PENDING-OWNER-ACTIONS) |
| Sysmon loses events at boot | 78,883 queued before the service started, 76,922 of them registry; the active policy is the JARVIS baseline | review why registry volume is that high at boot with `Sysmon64 -c` elevated; the driver starts before the service and queues everything |
| Reflective-image check unreleased | live release and broker run the older memscan script | release, then `jarvis broker install` |
| Health monitor still on the legacy layout | `Deadman` folder only, no `HealthMonitor` | re-register supervisors after a release |
| Disk nearly full | C: at 97.7%; the WSL disk image is 252 GB with 209 GB used inside (projects 6–13 GB each, `~/.cache` 29 GB) | free space inside WSL, then compact the image: `wsl --shutdown` and `Optimize-VHD` or `wsl --manage Ubuntu --set-sparse true` |
| Wi-Fi SSID/BSSID invisible | Windows denies SSID to the collector; machine-wide location is Deny in HKLM | allowing location machine-wide trades privacy for evil-twin detection; your call |
| 45 plaintext credentials in your files | secrets collector, 8 critical | rotate or move to a credential store; JARVIS only reports |
| Secure Boot revocation list failed to update | dbx error 0x80071149 since boot 182 | Windows Update or firmware update |
| Threat-intel feed stopped | Exa HTTP 402 credits exceeded | billing |
| Seven ASR rules audit-only or unset; shadow stacks off | posture | each finding carries its command |
| Unverified privacy seal | never applied live | `jarvis privacy seal` then try to record |

## Inherent, recorded

- 22 Protected Process Light processes are outside the memory scan.
- auditd cannot run in this WSL kernel; the owner of loopback udp/323 is
  outside the distro.
- GetAsyncKeyState polling keyloggers emit no ETW event on this build.
- Kernel-streaming capture, drivers and administrators bypass the consent
  gate; hardware kill switches are stronger.
- A five-minute sampler misses a change that is undone within its interval.
- Pre-OS beeps and firmware activity are only visible after the fact through
  measured-boot logs.

## Still unmeasured after this pass

- The `WSL IDE Keepalive` task reads critical in the checkout's control audit;
  the reason text is truncated in the finding. Compare the installed script
  with its declared fingerprint (`jarvis provenance persistence`) before
  trusting or removing it.
- No exploit, injection or capture attempt has been run against this host to
  show any mitigation or seal stopping it.
