# Credential exposure classification — 2026-09-25

The running release reports 26 medium secret findings at 100% scored coverage.
Read-only path and mode inspection found local project `.env` files and five
application-managed login stores, all regular owner-only files (`0600`). No
free-standing credential file outside a project or application store was
identified. This is an inventory conclusion about the scanned files, not proof
that the credentials remain private everywhere or that their providers are safe.

## Invariants before the change

1. Preserve every matched value's fingerprint, location and line in the local
   evidence; never print or send a value to Jev, logs or telemetry.
2. A protected project environment file is advisory inventory only when it is
   regular, owned by this user, has no group/other bits, is inside a project
   checkout (not the home directory), is not tracked and is explicitly ignored
   by Git. A local software directory with no functioning Git repository may
   use a stricter structural proof: the env file sits at the top of a direct
   home-directory project with a package/dependency manifest, and `.git` is
   absent or empty. Once version control is initialized, explicit Git-ignore
   proof becomes mandatory. A broken nonempty `.git` or command failure never
   takes this fallback. A failure to prove any part keeps the original severity.
3. An exact application credential store is advisory inventory only when it
   has the same owner and mode proof, no other login account, and no copy in
   another location. A store name alone proves nothing.
4. A tracked copy stays critical; a reachable copy stays high/critical; a loose,
   symlinked, non-project or unrecognized copy remains actionable. Repeated
   matching values are assessed across *all* locations.
5. Classification does not delete, rotate or move credentials. Deletion of a
   software login file can log the user out and does not revoke a provider key.
   No deletion command is issued unless an actual orphan is identified.
6. Scanning remains bounded; Git queries have timeouts and failure leaves the
   original finding. A fresh service receipt and score readback are required.

The alternatives were scoring every private development credential as a medium,
lowering by `.env` filename alone, and lowering only with owner/mode and
version-control or local software structure proof.
The last preserves real exposure detection and matches normal local development.
Jev Choice favored it with concentration 0.99 and assigned 0.07 yes probability
that an application CLI login file should be deleted merely for being outside a
project. These judgments are advisory; tests and live evidence decide.

Cloudflare's [Wrangler documentation](https://developers.cloudflare.com/workers/wrangler/commands/general/)
identifies `~/.config/.wrangler/config/default.toml` as its normal OAuth token
store and documents `wrangler logout` for deliberate sign-out. The file is not
an orphan merely because it sits outside a project checkout. App-owned stores
and protected project files are still readable by code running as the same user;
that residual risk belongs in the advisory detail and in execution isolation.

## Deploy baseline (before), 2026-09-24T22:59:47Z

Live `/api/state`, `secrets` job: 25 "generic secret assignment in plaintext"
findings at medium (some grouped as "+N more locations"), plus 4 named-store
findings at medium (Anthropic/Claude Code, GitHub CLI, Cursor, archymedes),
plus 1 AWS access key finding already at low. Staged in
`~/.cache/jarvis-release-staging/20260924T225925Z-on-39dbdf2bd1e1` alongside
the network/firewall change reviewed the same day
([NETWORK-ROAM-FIREWALL-REVIEW-2026-09-25.md](NETWORK-ROAM-FIREWALL-REVIEW-2026-09-25.md)).

Expected after deploy, finding by finding: the ~21 project-`.env`/local-app
findings that pass the private-and-ignored (or local-app) proof drop to low
with the "private project environment file" or "credential store" wording;
the named-store findings (GitHub CLI, Cursor, Wrangler, archymedes, Claude
Code) drop to low with "credential store" wording; any finding that instead
keeps medium/high must be explained by a failed ownership/mode/Git-ignore/
tracked-elsewhere check, not by a lowered scan. A read-only replay against
this exact host's files projected `{'medium': 5, 'low': 22, 'ok': 1}`
pre-deploy; the live post-deploy readback is the actual acceptance gate, not
this projection.

## Deploy result (after), 2026-09-25T00:32:02Z

Release `sha256:d4d38844f40475cf0c05f52ccb7346d2628c5ed127aa5994123b87cce64cf77c`
switched in, `jarvis.service` restarted with 0 further restarts, `/api/health`
reports `healthy`/`live`/`ready`/`protection_healthy`. A forced fresh `secrets`
run (`POST /api/run?job=secrets`) reports 24 low, 0 medium/high — every one of
the prior 26 medium findings is present with a lower severity and an explicit
reason (Wrangler's store, a named credential store, or "a private project
environment file"); none disappeared. Security score moved 70 → 72; Data &
privacy 50 → 73. This is a live readback, not a projection, and every change
is individually explained — no lost visibility.
