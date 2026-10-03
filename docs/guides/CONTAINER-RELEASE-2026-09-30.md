# Container inventory release handoff

Source implementation and checkout validation are complete. The live service remains on db8fb2bdb4b2. The new private stage contains exactly 13 reviewed files (9 modified base files and 4 additions), with every other file hash matching the sealed live manifest. No unrelated checkout changes were staged.

Review: [container inventory invariants and evidence](../security/CONTAINER-INVENTORY-REVIEW-2026-09-30.md).

Stage: `/home/chris/.cache/jarvis-release-staging/20260930-containers-on-db8fb2bdb4b2`.

The stage record names the private review overlay as its source. For deployment, explicitly retain the actual installation checkout below; this is the path managed Windows tasks use.

## Administrator command after stage validation

```bash
sudo python3 -I /opt/jarvis/current/scripts/deploy_root_runtime.py \
  --source /home/chris/.cache/jarvis-release-staging/20260930-containers-on-db8fb2bdb4b2 \
  --checkout /home/chris/jarvis \
  --expect-base sha256:db8fb2bdb4b2b972c82804257c9fbd646ba10222231eeafeae0e7aaa19f118f5 \
  --skip-tests
```

The administrator path currently requires a password (`sudo -n true` failed). No cutover was attempted. Preserve the previous release and the written baseline in `/home/chris/jarvis/.container-release-overlay-20260930/validation/container-release-baseline.json`.

## Acceptance after cutover

Follow [the deploy guide](DEPLOY.md): confirm the new release identity, active service, restart count, healthy/ready/protection_healthy and absence of journal errors; obtain a fresh scheduled containers receipt after restart (use the local dashboard Run control if forcing is needed); require 11/11 inspections only if the fleet has not changed, and explain each change against a fresh inventory. Readback must show complete observation and an unverified assurance capability. Docker errors, inspection races or configured bounds must show noncomplete observation. Compare all existing affected health and findings against the saved baseline. Legacy assurance may change from 17 to 16 through the additional unverified denominator; this is documented accounting, not evidence of improved or reduced protection. Recheck across collector intervals. Roll back with the sealed deploy script's `--rollback` if acceptance fails.

## Validation status

Checkout: 1,890 tests passed. Focused current-source checks: 61 tests passed with one restricted-environment Docker skip. Exact-stage full suite: 1,709 tests passed in 277.894 seconds; all 61 focused stage checks also passed, including the live Docker path. Stage hash audit: 13 reviewed files, zero unexpected changes. Jev Choice/Noul review: unavailable (HTTPError); deterministic gates preserved. Read-only host inventory: 11/11 containers, 0.79 seconds, 28,780 KiB peak RSS. No isolated malicious-container or sustained-service validation. Ruff unavailable.
