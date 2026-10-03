# Process audit — 2026-09-30

Scope: every process on Windows (284) and WSL (92), from independent read-only views
taken by hand in addition to the collectors' own six-view reconciliation. Nothing was
executed, killed or changed. Absence of findings is not proof of absence of compromise
(see MAXIMUM-ASSURANCE.md); this records what was checked and what stayed unresolved.

## Method

- Windows: `Win32_Process` with parent links, Authenticode status for every readable image,
  service binary paths (`Win32_Service`) for processes whose path Windows hides from a
  limited token, `Get-AppxPackage` signature state for Store apps, TCP owners cross-checked
  against the process list. Public knowledge (web search) for names that were not obvious.
- Linux: `/proc` name/exe/parent/uid/cgroup, listeners, `docker inspect` for privilege,
  socket and mount exposure, Sysmon-for-Linux's own journal.

## Result

No hidden process, orphaned socket owner, impersonating name, duplicated singleton
(csrss ×2 is one per session), or unsigned image outside a known vendor path was found.

| Observation | Verdict | Evidence |
|---|---|---|
| 10 Windows images `NotSigned` | Store (MSIX) apps: `SignatureKind=Store, Status=Ok`. Riot crash handler: unsigned Crashpad build by design; SHA-256 D224446B… matches a public sample of Riot's file | `Get-AppxPackage`; public reports |
| 28 processes with no readable path | All resolved through the service binary, signed Microsoft/vendor (HP, Intel, Realtek, Epson, Proton, Anthropic, OpenAI) or a parent that is one | service `PathName`, parent chain |
| PresentMonService (no service entry) | Child of `IntelGraphicsSoftware.Service`; same file exists in the Intel package, signature Valid | package listing |
| JarvisSensor.exe unsigned | Own component; already a known assurance gap (no signed release) | assurance register |
| "System Idle Process" connections | 31 `TimeWait` sockets Windows attributes to PID 0. Fixed in the checkout (`(unattributed)`), not yet released | `Get-NetTCPConnection` |
| `qemu-system-x86_64.exe` "QDoor" hunt hit | Name-only match. Google-signed Android SDK emulator 36.6.11, AVDs Pixel_6 and Resizable_Experimental present, not running | signature, package.xml |
| `JarvisCursorSpeed` critical persistence | Owner-approved JARVIS task; installed script is byte-identical to `windows-sensor/cursor-speed.ps1` (A7C61FB8…). The sealed release cannot verify it yet, so it reads critical until a release carries the script and provenance registration | sha256 both sides |
| Docker `aios-*` stack incl. `cloudflared` | Owner's project (`~/angel-intelligence-os/deploy`). No privileged container, no docker.sock mount, no host PID/network, no host binds beyond the HAProxy config | `docker inspect` |
| `rm /var/log//dmesg.4.gz` high | `dmesg.service` runs `savelog -c 5` every boot. The exemption compares wall-clock windows and fails while the clock steps (below) | unit file, `savelog` |
| Sysmon pid 426 executable "deleted" | Sysmon's install copy under `/opt/sysmon` was replaced after the service started; same pattern as EXECUTABLE-REPLACEMENT-REVIEW-2026-09-24. Unprivileged host cannot hash it. Owner check: `sudo sha256sum /proc/426/exe /opt/sysmon/sysmon /usr/bin/sysmon` | not verifiable here |

## Unresolved (kept explicit)

1. **`clang-18` → 5.148.170.168:443** (Nine Internet Solutions AG, Zürich; first flagged in
   `sysmon_linux`). The originating event is no longer in the journal and the finding
   carries no pid, time or GUID, so the process cannot be identified. No `clang` is running.
   Treat as unknown, not benign. Detector gap: findings should carry event time and
   ProcessGuid.
2. **The WSL wall clock steps backward.** Measured with `jarvis timeline clock --watch 65`:
   two −2.47 s steps in 65 s (≈ every 30 s); journald logged 85 "Time jumped backwards"
   rotations in one hour. Effects: journald rotates on each step (why earlier Sysmon events
   are gone), cross-source ordering is unreliable, and wall-clock exemptions miss. The kernel
   uses Hyper-V implicit time sync (`hv_utils.timesync_implicit=1`) while `systemd-timesyncd`
   is also active; the cause is not established without root. Owner diagnostics:
   `sudo journalctl -k | grep -i -E 'hv_utils|clocksource'`, then test with
   `sudo systemctl stop systemd-timesyncd` and re-run the probe. `wsl --shutdown` restarts the
   VM (stops the Docker stack and open sessions) and is the usual remedy after host standby.
3. Windows listens on 445/139/135/7680/5040 on all interfaces (Windows defaults, incl.
   Delivery Optimization on 7680). Not changed; firewall profile scope was not re-verified here.
4. Secrets findings (plaintext credential files flagged critical/medium) and 5.6 GiB
   `vmmemWSL` were left to their own collectors.
