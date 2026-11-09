# Working on JARVIS / ARGUS-INSTINCT

Two cofounders, several AI agents (Claude Code, Codex), one private repository
(`Archymedes-Lab/argus-1`), and a CI budget that stops at $0. The rules below are
the smallest set that keeps that combination fast and safe. The engineering
rules themselves are in [AGENTS.md](AGENTS.md); this page is how we work together.

## Where we work

The product is **ARGUS-INSTINCT** (JARVIS is the engine's internal name). Work happens in these repositories:

| Repository | What it is | Run / test |
|---|---|---|
| [Archymedes-Lab/argus-1](https://github.com/Archymedes-Lab/argus-1) (this one, remote `org`) | All product code: the JARVIS/Argus engine, desktop app, installers, licence and phone Workers, release pipeline | `scripts/dev/bootstrap.sh`, `scripts/dev/fasttest.py` |
| [Archymedes-Lab/argusinstinct](https://github.com/Archymedes-Lab/argusinstinct) | The product site argusinstinct.xyz (Vite + three.js, Cloudflare Worker assets) | `cd web && bun install && bun run dev` |
| [Archymedes-Lab/archymedes-gtm](https://github.com/Archymedes-Lab/archymedes-gtm) | Price book (`catalog/stripe.ts`), go-to-market | prices here first, then the desktop app and the licence Worker |
| chrisnkuno/archymedes-site | archymedes.xyz and the download pages a release publishes to | touched by `release/publish_dry_run.sh` |

Do not push product work to `chrisnkuno/Argus-1` (`argus1`, the older private copy), `chrisnkuno/JARVIS`
(`origin`, retired 2026-10-26) or the public `jarvis-origin`.

## First day (about 15 minutes)

```bash
git clone https://github.com/Archymedes-Lab/argus-1.git ~/jarvis && cd ~/jarvis
git remote rename origin org            # the tooling and the docs call the shared home `org`
scripts/dev/bootstrap.sh                # checks tools and access, enables the pre-push hook, runs the fast tests
```

`bootstrap.sh --check` changes nothing; without it, the only change is this
repository's `core.hooksPath`. It never installs a service or reads a secret.
To also *run* JARVIS on your own machine, see "Using it" in the
[README](README.md#cofounders-start-here).

## Two people, many agents

| Rule | Why |
|---|---|
| **`main` only moves by pull request.** Branch from `org/main`: `feat/…`, `fix/…`, `docs/…`; `release-test/…` for a release build; `integrate/…` to combine branches. | One history both of us and every agent can trust. |
| **Green CI merges itself; no review needed** for ordinary code. The author merges when CI is green. | Waiting on the other person for every change would halve our speed. |
| **Either cofounder may merge when required CI is green**, including trust-anchor changes. [CODEOWNERS](.github/CODEOWNERS) routes review requests; approval from the other cofounder is optional (owner decision 2026-11-09). | Both cofounders can ship; PR history, required checks and ASES DEV-12's independent review requirements remain in force. |
| **One agent, one worktree, one branch.** `git worktree add ~/.cache/wt/<branch> -b <branch> org/main`. Never two agents in one checkout. | 2026-09-24: two agents in one checkout half-applied each other's edits. |
| **Small PRs, merged the same day.** Stack them if needed; rebase or merge `org/main` before asking for review. | Long-lived branches are where our merges went wrong (the 68-vs-3 commit fork of 2026-11-02). |
| **Say what is not done.** The PR template's last section is mandatory. | A claim without measured evidence is the one thing AGENTS.md forbids. |

### Saving CI minutes

CI runs on every push (not on pull requests too, which doubled it). So:
- The **pre-push hook** runs the quick static gate and the tests whose inputs
  changed (`scripts/dev/fasttest.py`, scratch HOME, usually seconds). A push that fails
  there would only have failed in CI. Skip once with `git push --no-verify` for docs.
- Push when a piece is done, not every commit. A newer push to the same branch cancels the older run.
- `python3 scripts/dev/fasttest.py --all` before asking for review on a large change.

### Who owns what (the default reviewer and first responder, not a gate)

| Area | First owner |
|---|---|
| Installers, recovery, uninstall, phone approvals, Windows supervisor tests | soniAineza4 |
| Collectors, detection rules, evidence, the live JARVIS machine, licence Worker, Stripe | chrisnkuno |
| Releases | either releaser: any one of us signs ([RELEASING.md](docs/guides/RELEASING.md)) |

Edit the table by PR when it changes.

## Secrets and accounts: each of us has our own

Never share a key by chat or put one in the repository. Each person holds:
- a **GitHub account with 2FA** (an org admin);
- an **Argus release signing key**, generated on and never leaving their own
  machine ([RELEASER-KEYS.md](docs/guides/RELEASER-KEYS.md));
- their own **TypeSafe/Jev key** in `~/.jarvis/typesafe.env` (optional; without it
  Jev reports unavailable and work continues, AGENTS.md);
- an **Argus licence** for their own computers (a complimentary grant;
  `docs/STRIPE-HANDOFF.md`, "Complimentary licences").

Production secrets (Stripe, `KEY_PEPPER`, `LICENCE_SIGNING_KEY`, Cloudflare,
Vercel) live in the shared password manager and in the services themselves, nowhere else.

## The owner's machine is not a template

Parts of AGENTS.md and many guides describe one live machine (`/opt/jarvis`,
its sealed releases, its Windows tasks). On any other machine an agent must not
run deploy, broker install, `wsl --shutdown`, or Windows hardening steps; it
works in the checkout and tests with a scratch HOME. AGENTS.md, "Which machine".

## When CI is unavailable

If the org's Actions budget is spent, CI and therefore merges to `main` stop.
That is deliberate: do not merge around it. An admin may set the `main` ruleset to
"Evaluate" for an urgent fix only after recording it in
`docs/security/exceptions.md` (owner, expiry) and running `fasttest.py --all` and
`static_gate.sh` locally; set it back the same day.
