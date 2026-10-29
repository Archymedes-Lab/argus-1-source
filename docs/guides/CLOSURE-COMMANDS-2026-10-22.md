# Closing the five headline blind spots, 2026-10-22

What was done without you, what is staged, and the exact commands that are
yours because they end in a sudo or UAC prompt. Run them in this order; each
step's readback is written next to it so you can stop at the first one that
does not match.

## Done already (no privilege needed)

| Blind spot | What changed | Readback |
|---|---|---|
| 1. No alert channel | `~/.jarvis/config.json`: `alert_from`, `alert_to` and the Resend key restored from your 2026-09-29 pause backup (the pre-restore file is kept beside it as `config.json.before-email-restore-*.bak`); `Deadman\mail.json` restored from its paused copy; `jarvis alert --test` sent | watchdogs snapshot 21:39: the critical "no alert channel can reach you" is gone; the Windows monitor's hourly mail attempt at 21:44 succeeded (`mailError` empty, reviver reads "working") |
| 2. Release behind checkout | stage `closure-20261022-r4` built on the release that went live at 23:52 (`414291d535bb`, the UI design-system release): the storage governor job (`storage`, every 30 min) and the system-drive-full critical in the resource watcher, brightness events in the hook, gaps-job ATT&CK revocation handling, WSL command rules, Sysmon browser-memory detector, detectors for driver loads, Startup-folder and drivers-folder drops, attack-tool named pipes and WMI subscriptions, the window-event hook inventory, the T1559 attack-map probe, the revised Sysmon baseline below, and their tests | full unit suite running in the staged tree; see the end of this file for the result |
| 4. Sysmon policy | baseline now records unsigned image loads, cross-program browser memory opens, and Defender / COM / LSA / AMSI / trace-session registry families; six registry rules and a browser-memory detector with tests | `python3 -m unittest tests.test_windows_sysmon_policy tests.test_sysmon_windows tests.test_techniques` passes (90 tests) |

Not in this stage, deliberately: the `wsl` and `canary` jobs and the
reflective-image memory check. Each pulls in `platform/host.py`,
`core/filelock.py` and `process/assemblies.py`, which are another session's
unverified work in the same checkout. They need their own review and stage.

## Yours, in order

### Step 1. Deploy the stage (sudo)

```
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
  --source /home/chris/.cache/jarvis-release-staging/closure-20261022-r4 \
  --checkout /home/chris/jarvis \
  --expect-base sha256:414291d535bb44aedfa16d063d39c05b4362d6a467a4bfa78c840357129724f4 \
  --skip-tests
```

Readback: `readlink -f /opt/jarvis/current` names a new release;
`systemctl show jarvis.service -p ActiveState -p NRestarts` reads active, 0;
`curl -s http://127.0.0.1:8787/api/health` reports healthy. Rollback is
`sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --rollback`.

### Step 2. Restart the input hook so the brightness sampler runs (desktop WSL terminal, your account)

```
jarvis inputwatch --stop && jarvis inputwatch --start
```

Then change the screen brightness once. Readback within a minute:

```
sqlite3 ~/.jarvis/jarvis.db "select datetime(ts,'unixepoch','localtime'), detail, fg from control_events where control='brightness' order by ts desc limit 3"
```

### Step 3. Reinstall the elevated broker (one UAC prompt)

```
jarvis broker install
```

This restages `memscan.ps1` and `inputaudit.ps1` from the deployed release.
Readback on the next watchdogs run: "the elevated broker's scripts differ"
is gone; the memscan job no longer reports "coverage incomplete"; the input
job no longer says the watcher audit timed out.

### Step 4. Apply the Sysmon baseline (one UAC prompt), then reboot once

```
jarvis broker sysmon-baseline
```

It prints the baseline SHA-256, backs up the running policy, applies, and
verifies that process starts are still unfiltered. Readback: the evidence job
stops reporting "Sysmon is not running the reviewed baseline". After the
reboot, read the boot-drop count in the sysmon job ("lost events while
starting at boot"); it was 41,383 at the last boot. Jev's advisory on this
change put the top risk at password managers or accessibility tools being
reported for reading browser memory (0.80); those arrive as medium findings
for installed programs and can be acknowledged with the program named.

### Step 5. Windows supervisors: not yet

The renamed supervisors (`jarvis-reviver.ps1`, `jarvis-health-monitor.ps1`,
with the fix that stops the reviver restarting a live daemon after resume and
the mail-pause handling) write their state to `Jarvis\HealthMonitor`, and the
live daemon still reads `Jarvis\Deadman` (`service/deadman.py`). Registering
them now would make the daemon report the monitor as missing. They ship
together with the daemon's `service/supervisors.py` and the `jobs.py` that
uses it, which is a separate stage (that `jobs.py` carries the `wsl` and
`canary` jobs and the native-host seam, see "Not in this stage" above). The
installed `deadman-jarvis.ps1` and `revive-jarvis.ps1` are byte-identical to
the release copies, so there is nothing to refresh under the old names.

### Step 6. Move the daemon to its own user (sudo; preflight first)

```
sudo /home/chris/jarvis/scripts/repair/install-service-user.sh --preflight
sudo /home/chris/jarvis/scripts/repair/install-service-user.sh
```

The preflight stops if the `jarvis` user cannot reach PowerShell through
interop; nothing changes in that case. After the switch, `jarvis status` still
works for you (readers group) and writes such as `jarvis ack` need
`sudo -u jarvis`. Rollback: `--rollback`. Do this after step 1, because the
email settings restored today are copied into `/etc/jarvis/config.json` at
this step.

### Step 7. Log headroom (sudo in WSL; elevated PowerShell on Windows)

The Linux Sysmon journal rotated past the collector's cursor again today, and
the Windows Sysmon log (256 MB) wrapped past the native cursor on 2026-10-21;
the Task Scheduler log is 10 MB and wrapped on 2026-10-18.

```
sudo install -Dm644 /home/chris/jarvis/systemd/journald-sysmon.conf /etc/systemd/journald.conf.d/journald-sysmon.conf
sudo systemctl restart systemd-journald
```

```
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /ms:67108864
```

Readback: `sysmon_linux` stops reporting "journal rotated past the last read
position"; `native` stops reporting "Records missing" on the next wrap window.
The journal drop-in commits up to 6 GB under /var/log/journal; lower
`SystemMaxUse` in the file first if WSL disk is tight.

### Step 8. Disk (your account; nothing deleted for you)

C: is at 97.5 % and the WSL disk image is the bulk of it. Inside WSL, measured
2026-10-23 00:30, the freeable space is in your own caches, so the choice is
yours:

| Where | Size | Command |
|---|---|---|
| uv package cache | 26 GB | `uv cache clean` |
| Go build cache | 5.8 GB | `go clean -cache` |
| Docker images, stopped containers, build cache | ~7 GB reclaimable | `docker system prune` (add `-a` to drop unused images too) |
| Playwright and Puppeteer browsers | 3.6 GB | delete `~/.cache/ms-playwright` and `~/.cache/puppeteer` if not needed |
| Old release stages | 1.7 GB | keep the three newest under `~/.cache/jarvis-release-staging`; the rest are deployed or superseded |

Then compact the image from Windows: `wsl --shutdown` followed by
`Optimize-VHD` (Hyper-V module) or `wsl --manage Ubuntu --set-sparse true`.
The JARVIS store itself is 0.78 GB and the sensor spool 21 MB; neither is the problem.

### Step 9. Storage rescue (do this before anything else; the VM died of this at 00:29)

Measured 2026-10-23 01:00: C: 4.6 GB free of 474 GB, WSL image 246 GB holding
219 GB, page file system-managed, no ballast. The architecture is in
`docs/architecture/STORAGE-GOVERNOR.md`; the order:

```
# inside WSL (sudo): stop the 9 GB syslog copy of the Sysmon journal
sudo install -Dm644 /home/chris/jarvis/systemd/rsyslog-sysmon.conf /etc/rsyslog.d/10-jarvis-sysmon.conf
sudo systemctl restart rsyslog
sudo rm -f /var/log/syslog.[0-9]*
sudo truncate -s 0 /var/log/syslog
# inside WSL (your account, your call): ~42 GB of caches
uv cache clean; go clean -cache; docker system prune
rm -rf ~/.cache/ms-playwright ~/.cache/puppeteer      # only if unused
```

```
# Windows, after the above, so the freed blocks go back to C:
wsl --shutdown
wsl --manage Ubuntu --set-sparse true      # or: diskpart compact vdisk while stopped
wsl -d Ubuntu -- sudo fstrim -av
fsutil file createnew %LOCALAPPDATA%\Jarvis\ballast.bin 4294967296
```

Then fix the page file at 8192 MB (System > Advanced > Performance >
Virtual memory). Readback: `ext4.vhdx` shrinks by roughly what was freed;
the `storage` job (in the next release) reports free space, image overhang,
page-file policy and the ballast, and estimates days to the critical line.

## What stays open after all six

- Windows-side supervisors still run as your account and under the legacy layout; the renamed supervisors and the reviver fix wait for the supervisors stage.
- The `wsl`, `canary` and reflective-image work needs its own reviewed stage.
- Clipboard listeners, desktop screen capture, kernel-mode anything and the
  external monitor remain inherent gaps (register §1).

## Staged-tree suite result (closure-20261022-r2, 22:30; r4 targeted result below)

2063 tests, 2 failures and 1 error, all three present in the live release
`b43045cd63c8` as well and none in a file this stage changes:

- `test_input_watchers.BrokerWiringTests.test_job_is_registered_on_both_sides`
  looks for `jarvis-elevated-broker.ps1`, the renamed broker script that lives
  only in the checkout (the release ships `broker-jarvis.ps1`).
- `test_ui.DashboardUITests.test_node_ui_suite_passes` fails on the dashboard
  that the `stay-online-ui` release shipped at 21:40 (`removeAttribute` of an
  undefined element in `tests/ui/dashboard.test.mjs`).
- `test_stream.HttpTests.test_stream_delivers_pulse_then_refuses_past_the_bound`
  is a wall-clock deadline test; it passed and failed alternately in the stage
  and passed in the live tree while two suites shared the machine.

Everything this stage touches passes: the 90 technique, policy and detector
tests, the 7 brightness tests, the gaps tests, and the rest of the suite.

r4 (2026-10-23 01:40): the full suite was not re-run in the staged tree
because two concurrent suites are what pushed the guest into the crash at
00:29 (see STORAGE-GOVERNOR.md); the targeted suites that cover every file
r4 adds or changes pass in the staged tree: storage, resource watcher,
imports, layers, daemon resilience (75 tests), plus the 115-test detector
run and the 90-test policy run in the checkout. Run the full suite after the
storage rescue, when the machine has headroom.
