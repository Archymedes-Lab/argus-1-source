# Argus Windows edition: full automatic install (2026-10-22)

Owner request: a Windows-only install that contains every feature and proceeds
automatically. Built in `~/archymedes-site/scripts/argus/windows/`.

## What the installer does now

1. Copies Argus and its own Python to `%LOCALAPPDATA%\Programs\Argus`.
2. Verifies the copy with the shipped property and model checks; refuses on failure
   (`-SkipVerify` overrides). Report: `verification.json`.
3. Registers the daemon's scheduled task (`quickstart.ps1 -Native`).
4. One UAC prompt installs the elevated parts from a script it writes: the native event
   sensor service (`windows-sensor\install.ps1 -Install`, compiled inside Program Files),
   the elevated broker task (`argus-elevated-broker.ps1 -Install`, staged into
   ProgramData) and the Sysmon baseline (when a Sysmon service exists, with the policy's
   SHA-256 pinned). Each step's failure is caught and reported; transcript in
   `install-elevated.log`. `-NoElevated` skips this part.
5. Checks what is running (daemon task, dashboard health, sensor service, broker task) and
   prints it. `-Unattended` suppresses pauses and exits 1 on any problem, 0 when everything
   is running.

`Uninstall-Argus.ps1` removes the sensor service and broker task with one UAC prompt
(`-KeepElevated` leaves them).

## Validation state

- The two PowerShell scripts parse (PowerShell 5.1 parser) and the builder packages them.
- Not exercised end to end: this machine runs the live WSL JARVIS install, and the sensor
  and broker installers would displace its sensor service, broker task and Sysmon policy.
  The native Windows mode itself is still `native_host_portability: unverified` in
  `jarvis/core/assurance.py`.
- Owner validation before publishing: install `argus-windows-x64.zip` with
  `-Unattended` on a clean Windows 10/11 VM, read the final check block and
  `install-elevated.log`, open the dashboard, run `argus sensor status` and
  `argus broker status`, then uninstall and confirm no `argus` task or service remains.

## Build and verification results (2026-10-22, working tree 9d83d1a478de+)

- `build.py --worktree`: ruff ok, mypy ok, `argus.verify` 11/11 properties and 3/3 models on
  the full exported tree; packages written to the session scratchpad (not copied into
  `public/downloads/argus`, which publishes through the site's GitHub Actions on push).
- The Windows zip's own verifier, run from an isolated temp folder with its embedded
  Python 3.12.10 through interop: PASSED, 11/11 properties, 2/2 applicable models
  (the release-switch model reads "not applicable: deploy_root_runtime.py is not part of
  this copy", which is correct for a packaged edition).
- The Linux tarball's verifier in a network-less, unprivileged container (Python 3.13):
  PASSED with the same record.

To rebuild into the site: `python3 scripts/argus/build.py --worktree` (or `--ref <commit>`
once the JARVIS changes are committed), then commit `public/downloads/argus`.
