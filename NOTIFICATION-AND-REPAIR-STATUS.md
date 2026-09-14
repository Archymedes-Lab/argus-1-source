# JARVIS notification and repair continuation

Updated 10 September 2026.

Implemented and running:

- `jarvis/reporting/notifications.py`: persistent change queue; hourly ordinary
  digest; immediate critical/outage changes; finite age escalation; retry without
  acknowledging undelivered findings; collector-owned resolution.
- `jarvis/reporting/cadence.py`: daily advisory eligibility at 09:00 host-local
  time by default; 5-minute scheduling checks replace the 5-hour mail interval.
- `/api/health`: JARVIS identity, scheduler thread liveness, heartbeat age; 503 for
  stalled/dead scheduler. The Windows monitor rejects stale response timestamps.
- Root-owned `/usr/local/sbin/jarvis-repair`, with exact-command sudo permission
  for `status`, `monitor`, `telemetry`, `journal`, `mount`, and `all`.
  No arbitrary root shell grant. `jarvis repair status` is the CLI entry point.
- Watchdog verifier now expects the corrected `-RecoverInterop true` spelling;
  script hash, principal, path, and other arguments are still verified.

Installed and verified 10 September:

- `deadman-jarvis.ps1` is registered, running every minute, and writing state.
- Mail credential staged as a DPAPI blob (588 hex chars, not the raw key);
  ACL is SYSTEM / Administrators / chris only. The script decrypts it in
  process and never logs it.
- Toast path verified with `-TestNotification`.
- Two defects found and fixed during verification:
  * `ExecutionTimeLimit` was `PT1M`, equal to the repeat interval, so slow runs
    were killed at the boundary and every run recorded 0x41306. Now `PT5M`.
  * The probe used `Invoke-RestMethod`, which consults the system proxy and IE
    first-run state; under Task Scheduler it blocked past its own timeout and
    left the task stuck `Running`. With `MultipleInstances IgnoreNew` every
    later trigger was refused (0x800710E0) and the monitor silently stopped
    checking for 11 minutes while Task Scheduler still reported it Ready.
    Replaced with a raw `HttpWebRequest` (proxy disabled, hard timeouts).
    A 503 is now distinguished from an unreachable endpoint.
- `jarvis/deadman.py`: JARVIS now audits the Windows monitor's own freshness
  from the `watchdogs` job, so a stuck task is reported instead of hiding.
  Both halves of the loop now supervise each other.

Superseded — previously ready but not installed:

- `deadman-jarvis.ps1`: Windows-native one-minute task, two failed probes before
  an outage, toast/email notifications, one-time 1h/6h/24h escalation, recovery,
  retryable delivery, and durable state under `%LOCALAPPDATA%\Jarvis\Deadman`.
- Mail credential is designed to be encrypted with DPAPI for the Windows user.
  Installation must stage only the existing recipient/sender and encrypted key;
  never print or log the raw credential.
- Automatic approval review rejected the staging tool call on 10 September,
  stating that persistent task registration, credential storage, and future mail
  require explicit trusted user permission. An approval question is pending.
  Do not work around the rejection or claim the Windows task is already active.

Security assessment running separately:

- `review-alerts-elevated.ps1` was approved by Windows UAC and launched.
- Results under `%LOCALAPPDATA%\Jarvis\Evidence\alert-review-20260910-112349-c9821116155f43e5b72fefa2be587d99`.
- Exclusions: none. Real-time, behavior, IOAV, and script scanning enabled.
- Flagged JavaScript custom scan: exit 0; Defender explicitly reports no threats.
- Signature update reported an error. The full scan started with installed
  definitions; inspect `status.json` and `defender-after.json` for completion.
- A clean result does not prove that the historical activation-domain command
  failed. Keep that uncertainty separate from the likely application artifact.

Validation so far: 284 Python tests passed; PowerShell syntax passed; Windows
health probe accepted healthy and rejected stalled/incorrect-service fixtures;
root ownership/modes and sudo status execution verified; live health endpoint
returned healthy after service restart. Further tests and deployment verification
are still in progress. Existing unrelated work is present throughout this checkout;
do not revert it or blanket-commit it as part of these changes.
