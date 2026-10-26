# Pending owner actions, verified 2026-10-21

Each item was checked against the live machine on 2026-10-21, not taken from
notes. Items marked done need nothing.

## Done (verified)

- `scripts/harden/secure-internet.ps1 -Firewall` (elevated) and `-Browsers`:
  backups exist under `%LOCALAPPDATA%\Jarvis\InternetProtection`, and all three
  firewall profiles log allowed and blocked traffic.
- LSA protection (RunAsPPL=1, boot flag 1), Credential Guard and Memory
  Integrity are running. Tamper protection, PUA blocking and Network
  Protection are on. Seven key ASR rules block.

## Still pending, in order

1. **Install the sensor stage** (elevated PowerShell). The installed sensor is
   still the 2026-09-18 source (its hash equals the stage's `legacy` copy), and
   the live `native` collector reports "The sensor cannot read Sysmon:
   timeout" every pass. The stage changes the read path only.

   ```powershell
   Copy-Item -Recurse \\wsl.localhost\Ubuntu\home\chris\.cache\jarvis-release-staging\native-position-20261012 C:\Users\Public\jarvis-native-position
   cd C:\Users\Public\jarvis-native-position
   Get-FileHash JarvisSensor.cs -Algorithm SHA256   # expect a27f4141f1051a72bb8d0eee5a7dc66eb525aa0051698eb2d1252bb6208437ed
   .\install.ps1 -Install
   ```
   Accept only on 30 minutes or more of `native` reading complete. Rollback
   is in the stage README.

2. **Stop the WSL clock fight** (WSL shell, needs sudo), then optionally
   `w32tm /resync` in an elevated Windows prompt, and `wsl --shutdown` at a
   convenient moment so the new `.wslconfig` loads. timesyncd was still
   enabled and active on 2026-10-21.

   ```bash
   sudo systemctl disable --now systemd-timesyncd
   ```

3. **Release, then reinstall the elevated broker.** The checkout's memory
   scan script carries the reflective-image check (a whole PE image in memory
   that no file backs). The live release and the broker both still run the
   older script. Order matters: the daemon refuses broker results from a
   script that differs from its own copy, so `jarvis broker install` (one UAC
   prompt) must follow a deployed release containing the matching Python and
   script, or the memory scan goes blind until the release lands.

4. **Re-register the Windows supervisors** under their new names after they
   ship in a release: `jarvis-reviver.ps1 -Install` and
   `jarvis-health-monitor.ps1 -Install` (elevated).

5. **Optional, your account, no elevation:** `jarvis privacy seal` closes
   microphone and camera access until `jarvis privacy unseal`.

6. **Optional memory hardening** (elevated), each reported by the memory
   defense posture section with its command: pin DEP system-wide, enable user
   shadow stacks if the CPU supports CET, turn on kernel-mode hardware-enforced
   stack protection in Core isolation, and move the three audit-only ASR rules
   to block after checking their workflow impact.

7. **WSL boundary (added later on 2026-10-21, see
   `docs/architecture/WSL-ATTACK-SURFACE.md`).** Measured: any Windows
   process of your account gets root inside the distro with
   `wsl.exe -u root` and no prompt; nothing inside the distro can stop that,
   so the deliverable is to see every crossing. After the release that
   carries the `wsl` job and the new Sysmon rules:
   - `jarvis timeline wsl-boundary`, and if the state reads as yours,
     `jarvis timeline wsl-boundary --accept` (your account, no elevation).
     Drift findings start after that; a change you make reports every five
     minutes until you re-accept.
   - Apply the Sysmon policy through the elevated installer so the `Lxss`
     registration keys, the WSL policy key, `.wslconfig` and writes over the
     `\\wsl.localhost` share are recorded with their writing process.
   - Your own `wsl --shutdown` will show as a high "WSL shut down from
     Windows" finding; acknowledge it with `jarvis ack`.
   - Decide on the loopback API: a Windows process of your account can call
     the dashboard's state-changing routes (acknowledge, approve-intent,
     run a job). Acknowledgements stay visible as low findings; a token or
     peer gate would be readable by the same account through the share, so
     it was not built. Say if you want it anyway.
