# ARGUS-1 threat coverage against the research literature — 2026-10-27

Owner direction: make sure ARGUS-1 protects against the attacks in the papers
(docs/research/SPYWARE-READING-LIST-2026-10-27.md), thoroughly and precisely.

**Method.** Four read-only audits, one per threat family. For each technique
each audit read the detection logic (not the collector names), checked whether
it is in the running release (`2852f6956c80`), and looked for proof: live runs
in `defender_runs`, recorded hits, positive controls in `jarvis/core/assurance.py`,
and the blind-spot registers. The claims below that drive fixes were then
re-verified directly (marked ✔).

**Verdicts.**

| Verdict | Meaning |
| --- | --- |
| PROVEN | A positive control or a real live hit is on record |
| UNPROVEN | The logic exists and runs, but nothing has shown it fires |
| PARTIAL | It covers part of the technique; what it misses is named |
| GAP | No detection |
| SILENT FAIL | The sensor is broken but the run still records itself as complete. This is the worst case, because it looks like a clean machine |

## Delivery: nothing reaches you off-box ✔

The `watchdogs` audit has a critical active: "no alert channel can reach you".
- `~/.jarvis/config.json` has no email keys. Email was paused on 10-24, and the last alert went out on 10-24 at 16:19.
- The Windows health monitor's `mail.json` was renamed to `.bak` the same day. Its state shows `mailError: ItemNotFound`.

Every detection below therefore reaches only the dashboard and a toast that your own session can mute. **This is the first thing to fix, and it needs you:** restore the email config, or use the Argus phone relay.

## Coverage matrix

### Spyware, stalkerware and input or sensor surveillance (Chatterjee, Freed, Roundy, Ortolani, Munir, Scalabrino)

| Technique | Verdict | Evidence and what is missed |
| --- | --- | --- |
| Keyboard hooks and raw-input sinks | PROVEN, then SILENT FAIL ✔ | Win32k audit trace via the broker, with a positive control on 09-23. The broker's `inputaudit` timed out at 120 s on 59–70 MB traces, yet every `input` run was recorded complete with a *low* note. **Fixed in the checkout.** Still missed: a signed program in a user folder holding a global keyboard hook is rated low; polling slower than 1 call/ms; hooks registered before the trace started |
| Key-state polling | PARTIAL | Seen only at 1 call/ms or faster |
| Screen capture | PARTIAL | Packaged apps are caught through the consent ledger and capture-capable package checks. GAP for desktop BitBlt, PrintWindow and DXGI capture |
| Clipboard listeners | GAP | Command-line rules only (Get-Clipboard, xclip). Windows has no telemetry for clipboard listeners. A clipboard canary is the realistic fix |
| Microphone and camera | UNPROVEN | Consent ledger, audio sessions and the privacy seal. Camera has no live session sensor. Stereo Mix loopback capture is not attributed to a process |
| Dual-use monitoring and remote-access tools | PARTIAL | Name matching only; a renamed binary or a validly signed tool lands at low. The capability-chain reasoner exists but is not scheduled |
| Browser surveillance | PARTIAL | Sideloaded extensions; cookie theft by command line. The browser sensor (replay and keystroke listeners) has never reported. Infostealers that read cookies from memory or the file directly are not seen. Extension changes are not compared run to run |
| Account-level abuse (shared accounts, synced devices, location sharing) | GAP | The most common route in the stalkerware literature. Location use by script hosts is rated low |

### Rootkits, persistence and boot (GhostBuster, Copilot, Landauer, Zaidenberg, BlackLotus, SmmPack)

| Technique | Verdict | Evidence and what is missed |
| --- | --- | --- |
| Hidden processes, Linux | UNPROVEN | Four independent views plus /proc overmount checks; no positive control |
| Hidden processes, Windows | PARTIAL | The OpenProcess sweep runs unelevated (156 of 306 opened). Access-denied pids are reported only as low |
| Hidden files and registry | GAP | No cross-view outside /proc |
| Vulnerable or malicious drivers (BYOVD) | PARTIAL | Name regex, signature check and Sysmon driver-load rule. A renamed, validly signed vulnerable driver passes all of them. Missing: hash matching against Microsoft's blocklist and LOLDrivers |
| eBPF rootkits | SILENT FAIL ✔ | `bpftool` is absent, so the inventory was empty with no finding. **Fixed in the checkout:** the kallsyms tag inventory against a baseline (45 programs, 24 tags live) |
| Kernel modules | UNPROVEN | Hidden-module check only; no load events and no taint check |
| UEFI, Secure Boot, BlackLotus | PARTIAL | The TCG-log replay is live. Two defects: (1) drift findings are keyed by title, so a new bootkit merges into a finding that has been open for 33 boots; (2) `UEFICA2023Status` is collected but never evaluated. The dbx update is failing on this machine (0x80071149) |
| SMM and firmware | GAP (largely inherent) | `fwaudit` has been unavailable every run (the broker's copy differs) |
| Windows persistence | PARTIAL | Run keys, startup folders, non-Microsoft tasks, WMI, IFEO, LSA and Winlogon are covered. Missed: tasks under `\Microsoft\`, tasks with stripped security descriptors, ServiceDll in System32, AppCertDlls, BootExecute, Winsock LSP (claimed in a docstring but never read) |
| Linux persistence | PARTIAL | Missed: udev rules, `.timer` units and drop-ins, generators, `/etc/pam.d`, `ld.so.conf.d`, `/etc/environment`, `at` jobs |

### Evasion, C2 and exfiltration (Survivalism, Karantzas, HookChain, Mutate-to-Bypass, Ransomware 3.0, Baywatch, EarlyCrow)

| Technique | Verdict | Evidence and what is missed |
| --- | --- | --- |
| LOLBins, Windows | PARTIAL | Event-1 rules for mshta, regsvr32, rundll32, certutil, bitsadmin, wmic and msbuild. **No encoded-command or download-cradle PowerShell rule on the event stream.** Matching is on the image name only, so a renamed LOLBin defeats every rule (`OriginalFileName` is not used) |
| LOLBins, Linux | PROVEN | `DOWNLOAD_RUN` fired live today |
| DLL side-loading | PARTIAL | Fires live, but only on unsigned DLLs. A signed but untrusted DLL, or search-order hijack outside the host's own folder, is missed |
| Telemetry tampering (registry and logs) | PROVEN | Defender, Sysmon and log-clearing events and rules |
| Sysmon service stopped | SILENT FAIL ✔ | The state was read but never judged, and never queried on the native path. **Fixed in the checkout** |
| ETW or AMSI patched in memory, ntdll unhooking | GAP | memscan checks Nt* stubs only |
| Injection outside lsass and browsers | PARTIAL | Remote-thread creation is PROVEN. Process-access events are recorded only for lsass and browsers, and JIT hosts are excused |
| C2 beaconing | GAP | No timing model. No raw-IP (no prior DNS) check. No DNS-tunnel entropy check on endpoint events |
| Discord and Pastebin dead drops | SILENT FAIL | The patterns need URL paths, but the DNS cache holds hostnames only |
| Exfiltration by volume | GAP | No per-process byte counts |
| Malware calling an LLM at runtime | GAP | Loopback traffic to the local model is excluded from Sysmon. No check for unexpected processes resolving LLM API domains |
| Cross-stage correlation | PARTIAL | Discovery and DGA bursts only; the reasoner is not scheduled |

### The monitor itself, triage and intelligence (EvilEDR, NoDoze, Arp, Citizen Lab)

| Item | Verdict | Evidence and what is missed |
| --- | --- | --- |
| Local API | VULNERABLE ✔ | `GET /` hands the write token to any local caller; requests with no Origin pass; GETs need no token. Same-user malware can read location and incidents, and can silence findings for 90 days via `/api/answer` (EvilEDR-style). The fix drafter runs with auto-accept permissions (latent: not on the service's PATH) |
| Automatic response | SAFE today | Only exact-hash quarantine is automatic. `auto_block_ip` is off, which is good, because every blocklist IP is rated "high" (Google would be blocked). The quarantine marker follows symlinks |
| Evidence integrity | PROVEN for the event log | Vault, anchors and Bitcoin confirmation. `jarvis.db` (acknowledgements, ledger) is plain rows the same user can edit |
| Threat-intel freshness | SILENT FAIL ✔ | URLhaus, ThreatFox and MalwareBazaar have returned 410 since 10-21; abuse.ch has required an Auth-Key since 2025-06-30. **Fixed in the checkout:** the run reports partial until a fetch succeeds, and Auth-Key support is added. It needs your free key |
| Mercenary-spyware indicators | GAP | No Amnesty MVT, Citizen Lab or STIX feeds |
| Alert triage | PARTIAL | `ledger` double-counts (21 criticals). `gaps` items appear as threats. Blocklist-only IPs are critical. No NoDoze-style rarity scoring, although `procbaseline`, `egress_baseline` and Tranco exist |

## Plan, in order

1. **Delivery (you):** restore an alert channel.
2. **Silent failures, done in the checkout and tested:** keyboard-hook audit coverage, threat-feed staleness and Auth-Key, the eBPF kallsyms inventory, and Sysmon service state. Remaining: the `inputaudit` parse speed (interop is degraded right now, so it can't be measured), and the dead-drop patterns.
3. **High-risk detections on sensors that already exist:**
   - PowerShell cradle and encoded-command rules, plus `OriginalFileName` matching, on Sysmon event 1;
   - per-digest boot drift and `UEFICA2023Status`;
   - driver hash matching (LOLDrivers and Microsoft's blocklist);
   - beaconing and raw-IP egress from events 3 and 22;
   - LLM API domains contacted by unexpected processes;
   - the missing persistence locations.
4. **API hardening:** a token file with owner-only permissions; tokens on GETs; no token from `GET /`; Origin required; a shorter or CLI-confirmed `/api/answer`; the desktop app updated to match.
5. **Alert quality (your sign-off under score-integrity):** ledger dedupe, `gaps` moved off findings, single-feed IPs capped at medium.
6. **Deeper sensors:** ETW and AMSI prologue checks, process-access widening (measure volume first), clipboard canary, account-activity collector, MVT and Citizen Lab indicator feeds, an elevated Windows cross-view.

Every fix ships with a positive control (it fires on the technique) and a
negative control (it stays quiet on the look-alike), and is accepted on live
readback, not on tests alone.
