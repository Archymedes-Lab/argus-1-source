# Release handoff for Chris, 2026-11-10

Branch: `feat/ui-two-rooms-redesign` (already contains current `main` and the two licence-fix
commits). Procedure is [RELEASING.md](RELEASING.md) and [FAST-RELEASE.md](FAST-RELEASE.md);
this page only says what is special about this branch. Nothing has been tagged, signed or
published. Releasing needs your releaser key and your machine, so it is yours to run.

## What is in it

1. **Desktop UI redesign** (two rooms: Simple and Expert; plain words in Simple).
   See `docs/ux/REDESIGN-2026-11-10.md`.
2. **Alert-quality round 2** (fewer false alarms, nothing hidden).
   See `docs/security/ALERT-QUALITY-2026-11-10.md`.
   - `intrusion/run.py`: unsigned `.js/.mjs/.cjs` under `node_modules` is low, still listed.
   - `network/firewall.py`: an orphaned rule under `Program Files`/`Windows` is medium, not high.
3. **Simple wording** for `staging` and `rules`, in `guide.json`, `plainalert.py`,
   `dashboard.js` and ten locales.

## Before you release: decisions and checks that are yours

1. **Approve the two severity changes** (score-integrity rule). Argument, designs and replay are
   in the alert-quality doc. If you disagree, revert `4dc0af8` only; the UI does not depend on it.
2. **Six test modules fail** in the full suite (`fasttest.py --all` under WSL2, 302 of 308 pass):
   `test_api_clients`, `test_notify_qr`, `test_containers`, `test_memory_assemblies`,
   `test_score`, `test_server`. They fail the same way on the commit before this work. The clear
   one: `containers` has a runner (`jobs.RUNNERS`) and a score area but is missing from
   `schedule.JOBS` (`test_server`, `test_score`). Run the suite on your host and fix or explain each; do not
   release with the gate red. The suite was not rerun in full after merging `main` on 2026-11-10;
   the targeted tests and `standard_check` pass.
3. **Translations** of the new Simple-mode sentences (and the 25 from the redesign) were
   written by Claude, not read by native speakers. Ship, or have them read first.
4. **Not run for real:** the redesign was only walked in a browser against mock data, never in
   the real desktop window or against a live daemon. Run the browser check and open the real
   app once (below).
5. After pulling: `cd desktop/ui && bun install` (main added a local `deepmerge` patch that a
   test checks).

## Release steps (Windows, Linux, WSL, server)

One release builds all of them; there is no separate WSL or server release.

| Target | Download | Proven by |
|---|---|---|
| Windows | `ARGUS-INSTINCT-Setup-windows-x64.exe`, `argus-desktop-windows-x64.exe`, `argus-instinct-windows-x64.zip` | install-run-remove test on a clean Windows host, native desktop test harness |
| Linux desktop | `argus-desktop_<v>_amd64.deb` | desktop build for Linux |
| Linux server | `argus-server-linux-x86_64.tar.gz`, `argus-server_<v>_amd64.deb` | install-run-remove on a systemd host |
| WSL | the Windows Setup plus the host-bound tests | your host attestation (step 3) |

1. Merge the pull request to `main` after required CI (either cofounder may merge).
2. `git switch main && git pull && (cd desktop/ui && bun install)`
3. **Host attestation on your WSL2 host**, then commit both files and push `main`:
   `python3 release/host_attest.py make`, then sign `release/host-attestation.json` with your
   releaser key (`ssh-keygen -Y sign`, see `release/host_attest.py`).
4. Desktop browser check (a release touching `desktop/` requires it):
   `cd desktop/ui && bun run build`, then
   `uv run --with playwright==1.55.0 python3 scripts/dev/desktop_ui_check.py` (must exit 0).
   Also open the real desktop app once and look at Home, Checks, Settings, in Simple and Expert.
5. **Dry run** on the standing branch so the compiler cache is warm (remote is `org` in your
   checkout): `git push --force org main:refs/heads/release-test/sharded-check-20261106`.
   Push once and wait; a newer push cancels the run. It must go fully green: builds, Windows
   install tests, server install tests, native Windows desktop harness (check the test count,
   not only that it compiled), assembly and the content gate.
6. `python3 release/promote.py suggest`, then push the tag it prints (`vYYYY.MM.DD[-N]`).
   The tag run produces an **unsigned draft**; nothing is public.
7. Read the change report and file counts, then sign and publish:
   `python3 release/sign.py <tag>` (needs `7z`), then publish as in RELEASING.md
   (`bash release/publish_dry_run.sh RUN_ID` signs and **publishes**; use it only when ready).
8. Confirm the live readback passes and the site serves the new version. Rollback is
   publishing an earlier tag (`publish.yml` with `rollback: true`).

## Known limits to expect

- Windows desktop binaries are not Authenticode-signed, so SmartScreen will warn.
- The Windows **server** edition is not published yet (RELEASING.md, "Other limits").
- Findings were replayed on one machine's stored data, not on a second clean machine.
