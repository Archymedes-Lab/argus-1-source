# Deploy: /procs lens, identity, real-time sync and start history (2026-10-24)

One release. `closure-20261023-r6-sound-fwaudit` (release `d13dc720`) and
`mechanisms-procs-20261023-r1` (`0534b538`) were already deployed on 2026-10-23, and `94423eb4` then `01606b5b`
(HP firmware audit) are live on top of them, so this is the only deploy.

| | |
| --- | --- |
| Stage | `~/.cache/jarvis-release-staging/procs-identity-20261024-r3` (652 files) |
| Base (must be live) | `sha256:01606b5b1d07fa78446e5a996e015391dd834be99d1dff3c3fea689ac144bc00` |
| Predicted release | `sha256:e100a872fd0c0d0ade8fea7ad0c8a32afaa240e0d9db2ddde70001cdbe944c21` |
| Built by | `~/.cache/jarvis-release-staging/procs-identity-20261024-r3.build.py` |
| Contents | 12 added files and 9 changed (only this work's hunks in `server.py`, `assurance.py`, `mechanisms.py`) |
| Suite on the stage tree | 2250 tests; 2 failures that fail identically on the live release's source (`test_input_watchers` broker wiring, `test_ui` node harness) |
| Superseded | r1 (a layering test failed; never deployed); r2 (deployed 23:39 EEST and rolled back: the differences were a Windows sleep between baseline and deploy, not the release; then `01606b5b`, another session's HP firmware-audit release, became live, so r3 is the same work on it) |

What it changes is written in the readback script's header and in
`MECHANISMS-PROCS-DEPLOY-2026-10-24-identity.md`. In short: new `/procs` page modules and baseline
route; the process feed with identity, helper handoff and Linux Sysmon starts; `sysmon_linux` also
records the start history. No other collector's code changes.

## Commands

```bash
R=~/.cache/jarvis-release-staging/procs-identity-20261024-r3
B=~/jarvis/docs/guides/baselines/procs-identity-baseline-2026-10-24.json

# 1. Fresh baseline right before the deploy (score, every job, every finding)
python3 $R.readback.py capture $B

# 2. Deploy (refuses unless 01606b5b is live; keeps the previous release for rollback)
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
  --source $R --checkout /home/chris/jarvis \
  --expect-base sha256:01606b5b1d07fa78446e5a996e015391dd834be99d1dff3c3fea689ac144bc00 \
  --skip-tests

# 3. Service and journal
readlink -f /opt/jarvis/current
systemctl show jarvis.service -p ActiveState -p NRestarts
journalctl -u jarvis.service --since "-10 min" --no-pager | grep -E "Traceback|Error" | head

# 4. Let sysmon_linux run once on the new code (every 10 min), or force it
curl -s -X POST "http://127.0.0.1:8787/api/run?job=sysmon_linux"

# 5. Readback against the baseline (exit 1 = hard failure: roll back)
python3 $R.readback.py compare $B

# 6. Look at it: open http://127.0.0.1:8787/procs in the Windows browser

# Roll back if step 5 reports a hard failure or a finding disappears without explanation
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py --rollback
```

Run step 5 again after 30 minutes (several collector intervals), and once more the next day: the
Linux start history answers only "unknown" for its first day, so the first-run rule's real volume
(how many "First time this program has started here" lines a normal day produces) can only be
measured then.

## Before you run step 1

* The laptop must stay awake and on power from step 1 to step 5. A sleep in between makes the
  Windows-side findings differ for reasons unrelated to the release (that is what happened to r2).
  The readback now warns when Windows slept or the baseline is older than 15 minutes.
* `readlink -f /opt/jarvis/current` must end in `01606b5b1d07`; the deploy refuses otherwise.
* `/api/run` needs the API token, so step 4 answers "missing or wrong API token" from a shell; just
  wait for the 10-minute `sysmon_linux` pass instead.
