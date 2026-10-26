# Fix release 2026-10-23: Defender driver false positive, corrected HP install steps

Stage: `~/.cache/jarvis-release-staging/20261023T173708Z-on-0534b538cd16`. It is staged on the live
release `0534b538cd16`, with four reviewed files changed. The predicted new release id is
`sha256:94423eb462e2…`.

```
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
  --source /home/chris/.cache/jarvis-release-staging/20261023T173708Z-on-0534b538cd16 \
  --checkout /home/chris/jarvis \
  --expect-base sha256:0534b538cd160b49405c6ced57ffa6532c53499e884f300194f9eeaa013faabd \
  --skip-tests
```

## What changes

- **`sysmon`.** r6's new driver-load rule treated every path under ProgramData as user-writable,
  so it reported Defender's own drivers (`ksld.sys`, `WdNisDrv.sys`) as critical. Measured on
  2026-10-23:
  - `BUILTIN\Users` has read and execute only on
    `C:\ProgramData\Microsoft\Windows Defender\Platform\…\Drivers`.
  - Both drivers are signed by "Microsoft Windows", and the signatures are Valid.

  A validly signed driver in that one folder is no longer counted as staged. These cases stay
  critical:
  - a driver in that folder whose signature fails;
  - an unsigned driver anywhere;
  - a look-alike folder.

  Test: `test_defender_platform_drivers_are_not_staged_unless_their_signature_fails`. It fails
  when the exemption is removed.
- **`fwaudit`.** The setup text now gives the steps that work on Windows PowerShell 5.1:
  1. Update PowerShellGet.
  2. In a new elevated PowerShell, run `Install-Module HPCMSL -Scope AllUsers -AcceptLicense`.
  3. Run `jarvis broker install`.

  The PowerShell Gallery has no standalone HP.Firmware, and PowerShellGet 1.0.0.1 lacks
  `-AcceptLicense`.

## Baseline and readback

The baseline is in `docs/guides/baselines/defender-driver-fix-baseline-2026-10-23.json`.

After the deploy, once `sysmon` has produced a fresh snapshot:

- The two `driver loaded that is unsigned or from a writable path` criticals for
  `ksld.sys` and `wdnisdrv.sys` are gone.
- Every other `sysmon` finding remains, unless new events explain the change.
- `fwaudit` keeps its one low finding, now with the new instructions.
- No other collector changes.
