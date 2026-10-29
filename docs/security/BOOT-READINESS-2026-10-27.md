# Continuous monitoring and boot readiness — 2026-10-27

Owner request: "fix it not monitoring continuously; at boot it should already be
100% operational". This records what was measured, what was changed, what is
still unproven, and the owner steps in order.

## What was measured (14 days to 2026-10-27, Windows time UTC+2)

Sources: `defender_runs` receipts, the Windows System log (Kernel-Power 41/42,
Kernel-General 12/13, EventLog 6008, Power-Troubleshooter 1 with its own
SleepTime/WakeTime), the wake watchdog and keepalive logs, and the Sysmon
pressure probe. Analysis scripts were bounded and read-only.

| Measure | Value |
| --- | --- |
| Windows awake | 106.6 h of 336 h |
| Unexpected hard resets (Kernel-Power 41) | 37 |
| JARVIS blind while Windows awake, best sensor (`bridge`) | 6.5 h, 52 episodes (93.9% coverage) |
| Boot or wake to first complete `scan` | usually 1–2 min; outliers 25–118 min |
| Pre-logon gap | JARVIS starts at logon; 10-16 18:31 boot waited 87 min |
| Pre-reboot evidence still counted fresh | 66 min after the 10:05 boot: `posture`, `memscan`, `spy` |
| Sysmon at boot 187 (08:05Z) | queue of 50000 overflowed in 36 s: 102 ProcessCreate, 73388 RegistryEvent dropped |
| Wake watchdog misreads | ~30 restart attempts on `error code: wsl/service/0x8007274c` |

Gaps while Windows is asleep or crashed are not JARVIS defects: a frozen or
powered-off VM cannot observe (see `collector-staleness`). The native sensor
and Sysmon are Windows services started at boot, so pre-logon events are
recorded and ingested when JARVIS starts (native completed 14 s after daemon
start today); what waits for logon is analysis and alerting.

`scan` "partial" on 10-25/26 was not blindness: it reported Windows processes
with no Sysmon start event, which is the boot-time Sysmon drop above.

## Changes (checkout; nothing deployed by this work)

1. **Boot currency** (`jarvis/core/mechanisms.py` `boot_scoped`,
   `jarvis/service/scheduler.py`). Sixteen collectors whose evidence describes
   state a reboot activates or resets are declared boot-scoped. A result older
   than the guest boot (`/proc/stat` btime; the VM boots after Windows, so
   this also bounds the Windows boot) counts as at least one cadence late.
   `reliability.boot` in `/api/health` reports `pending`, `failed`, `ready`
   and `ready_after_s` (boot to the last boot audit's post-boot result),
   derived only from persisted snapshots so a daemon restart gives the same
   answer. It is deliberately not folded into `ready`: a 503 there raises the
   user-facing "unavailable" alert (2026-10-12 root cause).
2. **Supervisor unit-state parsing** (`jarvis-wake-watchdog.ps1`,
   `jarvis-reviver.ps1`). Only the eight states `systemctl is-active` prints
   count; anything else, including WSL's own error text, is unknown and the
   unit is left alone.
3. **Sysmon baseline** (`windows-sysmon/jarvis-windows-baseline.xml`). The
   bare `\CurrentControlSet\Services\` include (93% of retained registry
   volume) is replaced by 28 persistence and tamper value names, service key
   deletion, and whole firewall, port-proxy, Sysmon, EventLog and JARVIS
   sensor subtrees. Also records `Control\SecurityProviders\WDigest\`, which
   the T1003 rule read but no baseline ever recorded (found by the new
   sample-coverage test). 7-day replay: 46582 retained events → 30%.
4. **Start at boot**: an owner-run elevated step below; no code.

### Design choices

| Choice | Selected | Rejected and why |
| --- | --- | --- |
| Pre-boot evidence priority | due now (floor 1.0) | never-ran 99: puts ~8 min of serial boot audits ahead of tier-0 `sysmon`; age only: the measured defect |
| Readiness signal | separate `reliability.boot` | gating `ready`: turns boot catch-up into "unavailable" toasts |
| Boot reference | guest btime, local read | Windows LastBootUpTime: a PowerShell call per start, and the guest boot is never earlier |
| Sysmon volume | value-anchored Services rule | bigger driver queue: no supported knob; dropping the Services family: loses service persistence |
| Start at boot | boot trigger on the existing S4U keepalive task | a new task: two supervisors racing for one distro; auto-logon: weakens the machine |

Reconsider if: a boot audit's own cost delays `sysmon` (measure `ready_after_s`
against sysmon freshness), the anchored policy still overflows at boot, or
S4U cannot start WSL before logon.

### Verification so far

- `tests/test_boot_readiness.py` (22): floor only for boot-scoped pre-boot
  evidence; the sweep prefix up to `sysmon` is identical with and without
  the floor; boot audits precede long-cadence non-boot jobs; governed audits
  still yield under pressure; readiness pending / failed / ready / unknown;
  malformed snapshots; restart stability; unreadable or malformed btime;
  real `reliability_status` path from a store.
- `tests/windows/supervisors.Tests.ps1` in Windows PowerShell 5.1: the parser
  is loaded from both real scripts; WSL timeout text, trailing errors and
  banners are unknown.
- `tests/test_windows_sysmon_policy.py`: a Sysmon RegistryEvent evaluator
  (`sysmon_policy.registry_recorded`) proves every `techniques.REG_RULES`
  positive sample and 24 service persistence/tamper keys are recorded and
  measured noise is not.
- Jev advisory (jev-1.14.0, metadata only, `scripts/reviews/boot_readiness_advisory.py`):
  floor `due_now` 0.94; separate readiness 0.77; Services anchoring keeps
  signal 0.57 (uncertain — prompted adding service-wrapper `Application`,
  `AppParameters`, `AppDirectory`); biggest risk pre-logon WSL 0.77; real
  reboot still required 0.93. Advisory only; it authorised nothing.

### Not proven

- No change has run across a real reboot. Boot readiness, the Sysmon
  overflow and pre-logon start are all unmeasured until the readback below.
- Dropped boot events cannot be attributed, so the replay predicts but does
  not show that the anchored policy stays under the queue.
- Whether WSL starts under S4U before any interactive logon on this host is
  unknown; 10-16 suggests the existing 5-minute S4U watchdog did not achieve it.
- The 37 hard resets are outside JARVIS and remain the largest source of
  lost time.

## Owner steps, in order

Baseline recorded before any step: `~/.cache/jarvis-logs/baseline-boot-readiness-20261027.json`.

### 1. Deploy the narrow release (sudo)

Stage `boot-brand-20261027-r1` (built by
`~/.cache/jarvis-release-staging/boot-brand-20261027-r1.build.py`) also carries
the ARGUS-1 display name for the web pages. It contains the live release plus
the scheduler, Sysmon policy and evaluator, the Sysmon baseline, the six web UI
files and their tests, with exact-anchor overlays of `mechanisms.py` and
`assurance.py` on the live copies.

```
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
  --source /home/chris/.cache/jarvis-release-staging/20261027T101318Z-on-01606b5b1d07 \
  --checkout /home/chris/jarvis \
  --expect-base sha256:01606b5b1d07fa78446e5a996e015391dd834be99d1dff3c3fea689ac144bc00 \
  --skip-tests
```

`procs-identity-20261024-r3` is staged on the same base and also changes
`mechanisms.py` and `assurance.py`. Whichever deploys second is refused by
`--expect-base`; restage it on the new base (for this one, run the build
script again; it asserts every anchor).

Readback (DEPLOY.md): new release id, `NRestarts=0`, health ready, no
tracebacks; `/api/health` → `reliability.boot` present with `known: true`;
force `posture`, `memscan`, `spy` if they are still pending and see them leave
`pending`. Rollback: `--rollback`.

### 2. Re-register the supervisors (no elevation)

From a WSL terminal on the desktop: `./install.sh` (stages and registers
`jarvis-wake-watchdog.ps1` and `jarvis-reviver.ps1` on the new layout).
Readback: force `control` and see both tasks verified on the new layout; the
next `wsl/service` timeout in `jarvis-wake.log` reads "could not read
jarvis.service state" instead of "restarting".

### 3. Apply the Sysmon baseline (one UAC prompt), after step 1

`jarvis broker sysmon-baseline` — vault backup, verification, automatic
rollback. Readback: `perception.sysmon_process_create_policy.config_hash`
equals `sha256sum windows-sysmon/jarvis-windows-baseline.xml`, and no
"not running the reviewed baseline" finding.

### 4. Start at Windows boot (elevated PowerShell)

```powershell
$n = 'WSL IDE Keepalive'
$bak = "$env:LOCALAPPDATA\WSLKeepalive\$n.before-boot-trigger.xml"
Export-ScheduledTask -TaskName $n | Set-Content -LiteralPath $bak -Encoding Unicode
$t = Get-ScheduledTask -TaskName $n
$t.Triggers += New-ScheduledTaskTrigger -AtStartup
Set-ScheduledTask -InputObject $t
Get-ScheduledTask -TaskName $n | Select-Object -Expand Triggers | Format-Table
Get-ScheduledTask -TaskName $n | Select-Object -Expand Principal | Format-List UserId, LogonType, RunLevel
```

The principal must still read `LogonType S4U`. Rollback:
`Register-ScheduledTask -TaskName $n -Xml (Get-Content -Raw $bak) -Force`.
JARVIS may report the changed task definition; that is correct, acknowledge it.

### 5. Reboot test (the acceptance gate)

Reboot, wait at the sign-in screen for 5 minutes, then sign in. From WSL:

- `systemctl show jarvis.service -p ActiveEnterTimestamp` against the Windows
  boot (`journalctl -b` first line, Windows = WSL − 1 h): started before
  sign-in means pre-logon start works.
- `/api/health` → `reliability.boot.ready_after_s` (boot → all 16 boot audits
  verified); compare with the baseline (3 of 16 still pre-boot at 66 min).
- `perception.sysmon_pressure.drops` for this boot: none, or fewer than the
  102 ProcessCreate / 73388 RegistryEvent of boot 187.

Record the results here. If pre-logon start fails, roll back step 4.
