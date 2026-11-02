<!-- Copied unchanged from ~/.cache/gstack-review/ARCHYMEDES-MARKET-READINESS-2026-11-01.md on 2026-11-02. A snapshot of 2026-11-01: later work (PMF-2026-11.md, RELEASE-PLAN-2026-11.md, LICENSING-STRATEGY.md) supersedes parts of it. -->

# Archymedes market readiness, reviewed with gstack (2026-11-01)

The review was read-only. Nothing was installed, committed, pushed, deployed or sent. Every verdict
cites a file, a commit, a public page or a measurement taken today. Anything that could not be
checked is marked **unverified**.

---

## 1. gstack: source, skills, and how they were applied

**Repository.** https://github.com/garrytan/gstack. I confirmed it is the official one through the
GitHub API: owner `garrytan` (Garry Tan, company "Y Combinator"), `fork: false`, MIT licence, about
138.6K stars. Search results also surface lookalike forks (`zsh/gstack`, `ldt/gstack`, `hua/gstack`,
`mcgluut/gstack`, `dmurai/gstack`); none of them was used.

**Pinned commit.** `1ea86923a86129d1f32828b36acfe6f91f17c8e6` (VERSION 1.92.37.0, 2026-11-01T17:35Z,
"review briefs check template slots before pasting reviewer text").

It was cloned with `--depth 1` into `~/.cache/gstack-src/repo`. The clone was read only: no setup,
no install, no scripts, no binaries, and the working tree is still clean.

**What the repo ships.** The repo description says "23 opinionated tools". The tree at this commit
holds more:
- 62 top-level skills plus the root router `SKILL.md`
- 4 OpenClaw variants: ceo-review, investigate, office-hours, retro
- 1 browser-skill, `hackernews-frontpage`
- 1 Capy host skill

| Group | Skills (purpose taken from each SKILL.md `description`) |
| --- | --- |
| Product / strategy | `office-hours` (YC office hours: startup diagnostic with six forcing questions, or builder mode), `plan-ceo-review` (CEO/founder-mode plan review, 4 scope modes, 11 review sections), `autoplan` (runs the CEO, design, eng and DX reviews in sequence), `spec` (vague intent to an executable spec), `retro` (weekly engineering retro) |
| Engineering review | `plan-eng-review` (eng-manager plan review), `review` (PR diff review), `investigate` (root-cause debugging), `health` (code quality dashboard), `test-audit` (low-value tests), `deslop-shared-libs`, `modernize` (stale PRs), `verify` (build loop until green), `codex` (second opinion from the Codex CLI), `eval-plan` (pre-registered paid evals) |
| Security | `cso` (security audit: "evidence before assurance"), `careful` / `guard` / `freeze` / `unfreeze` (destructive-command and edit-scope guardrails) |
| QA | `qa` (test, fix, verify with a 0–100 health score), `qa-only` (report only), `benchmark` (web performance), `canary` (post-deploy monitoring), iOS: `ios-qa`, `ios-fix`, `ios-design-review`, `ios-clean`, `ios-sync` |
| Design / DX | `plan-design-review`, `design-review` (A–F design score plus an AI-slop score), `design-consultation`, `design-shotgun`, `design-html`, `design-motion`, `diagram`, `plan-devex-review`, `devex-review` (DX scorecard, time-to-hello-world) |
| Release | `ship` (preflight, distribution-pipeline check, version, changelog, PR), `land-and-deploy`, `setup-deploy`, `landing-report`, `document-release`, `document-generate`, `make-pdf` |
| Browser / ops | `browse`, `scrape`, `skillify`, `open-gstack-browser`, `setup-browser-cookies`, `pair-agent`, `connect-chrome`, `ubicloud`, `captain` (multi-agent controller) |
| Meta | `context-save` / `context-restore`, `learn`, `plan-tune`, `write-skill`, `benchmark-models`, `gstack-upgrade`, `setup-gbrain` / `sync-gbrain` |

**Skills applied, and how.** Each was followed manually from its SKILL.md. Its helper binaries,
telemetry and brain write-backs were not run.

| Skill | Why it bears on market readiness | How it was applied here |
| --- | --- | --- |
| `office-hours` (Phase 2A startup diagnostic, Phase 3 premise challenge, Phase 4 alternatives) | It tests demand, the status quo, a named user and the narrowest wedge. Those decide whether anything is ready for a market. | The six forcing questions (`office-hours/sections/phase-2a-startup-diagnostic.md`) were answered from evidence, not from the founder; they are interactive and could not be asked. Routing: Argus is "pre-product" (Q1–Q3); Friday "has users?" (Q2, Q4, Q5). The unanswered ones are listed for the owner in §5. |
| `plan-ceo-review` (Prime Directives, Step 0A–0C, Sections 1–10, strategy-only depth) | Premise, do-nothing cost, the 12-month ideal, "dashboards, alerts and runbooks are launch scope", rollback, security. | Strategy-only depth across the portfolio (§3, §4). Mode recommended per product: SCOPE REDUCTION for the company. |
| `cso` (Phase 12 evidence rubric, Phase 13 report labels) | ARGUS-1 is a security product. | `cso` requires its trusted installed launcher; without it, its own rule says report **not assessed**. Its evidence rubric (severity, confidence and evidence kept apart; "unknown is not unreachable") was applied to the existing QC and assurance evidence. No new security audit was run. |
| `qa-only` (Health Score rubric: Links, Functional, Content) | Can a stranger actually get and use what is advertised? | No gstack browser, so no visual, console or accessibility scoring. Equivalent done: crawled 303 unique links from 6 public pages with curl, and checked the documented download commands. Scores are **provisional, partial coverage**. |
| `ship` (Step 2 "Distribution Pipeline Check") | "Users cannot download this artifact" is a ship blocker in gstack. | Checked release pipelines, CI state and the public download path for each artifact. |
| `devex-review` (TTHW, the 0–10 DX rubric) | Friday is a developer tool. | Applied to Friday's install and CI evidence only. No live time-to-hello-world measurement: running a coding agent needs a provider key and costs money. |
| `plan-eng-review` | Engineering readiness. | Folded into the CEO Section 9 rollout review through CI and release evidence. Its interactive scope gate was not run. |

Not applied: `design-review` and `qa` need the gstack/Aside browser binary, which would have to be
installed, so there is **no design score**. `land-and-deploy`, `canary` and `ship` beyond Step 2
write or deploy. The iOS skills have no iOS target.

---

## 2. Portfolio map

| # | Product / repo | What it is | Audience | Kind | State (evidence) |
| --- | --- | --- | --- | --- | --- |
| 1 | **ARGUS-1** (`~/jarvis`, private `chrisnkuno/Argus-1`) | Local security monitor for Windows PCs and Linux servers: evidence-first findings, response ladder, blind-spot reporting | Developers and small teams whose machines run AI agents; small-server operators | **Product (flagship by owner direction)** | Signed release `v2026.10.30-2` exists on GitHub (10 assets incl. SBOM and signature). Public site manifest is empty (`/downloads/argus/manifest.json` = `{"version":"","files":{}}`). 53 capabilities in the register, 0 live/tested. |
| 2 | **Friday CLI** (`~/archymedes-cli`, public `chrisnkuno/archymedes-cli`) | Open-source (Apache-2.0) terminal coding agent; Go engine; 10 providers, Claude/Codex subscriptions, `/undo`, budget caps | Developers | **Product (shipped)** | npm `@archymedes/friday@3.12.6` (2026-10-30); 1,022 downloads 2026-09-30→10-29, 851 in the last week. The old name `archymedes-cli@3.7.0` is still live (765/month). GitHub: 0 stars, 0 forks. |
| 3 | Archymedes Desktop | Agent workspace with snapshotted diffs | Developers | Product (in development) | Site label "In development". Not inspected further. |
| 4 | Archymedes Cloud + `archymedes-billing`, `-routing-intelligence`, `-operations`, `-premium-packs` (private); `-protocol`, `-role-packs`, `-defender` (public) | Prepaid multi-model balance with per-call caps and routing receipts | Developers and teams | Product (pre-launch) plus platform repos | Cloud: 11 commits, last push 2026-09-14. Billing: 3 commits (09-01). Premium-packs: empty (size 0). Role-packs and defender: 1 commit each (09-01). `docs/PLATFORM_STATUS.md` hosted-beta gates are unmet. **Dormant.** |
| 5 | **Orion** (`~/orion`, private `chrisnkuno/orion`) | Consumer decision app: LLM structures the choice, a deterministic engine decides | Individuals making personal and business decisions | Product | Deployed at `orion-web-psi.vercel.app` (HTTP 200 today). Site says "Launching soon". Pricing (Pro $4.99/mo, pass $4.99) has status `founder` in the claim register. Market research done 2026-10-27. |
| 6 | NPC Reliability Layer (`~/archymedes-gaming`, local only, no remote) | Middleware for grounded, bounded NPC memory and behaviour | Game studios (Japan/Korea partner briefs in gtm) | **R&D prototype** | 10 commits; 95 tests; ablation benchmark; proprietary LICENSE draft and provisional patent draft today (`3d68425`). No studio user. |
| 7 | `archymedes-site` (private) | Marketing site, docs, Argus downloads host | Public | Infrastructure for products | Live at www.archymedes.xyz; 0 broken links of 303. Production deploys depend on GitHub Actions, which are blocked by billing. |
| 8 | `archymedes-gtm` (Archymedes-Lab, private) | Offers and Stripe checkout, attribution, claim guard, outreach engine | Internal | **Internal tooling** | DB: `payments=0`, `contacts=0`, `touches=1`, `optins=0`. Metrics last collected 2026-10-08. |
| 9 | Scout (`~/sales`, Archymedes-Lab/scout) | Finds places and people for Argus (Exa + Orion + cdm) | Internal | **Internal tooling** | 1,163 places and 128 leads judged; 14 `reach_now`, 5 `reply_public`. Latest report (2026-10-29) used the **mock** judge and fixture rows ("Acme", HN item 777). None of the leads reached gtm (`contacts=0`). |
| 10 | Sage (`~/sage`, Archymedes-Lab/sage) | Internal fundraising CRM and claim guard | Internal | **Internal tooling** | Deployed on Vercel and Convex behind a team password. |
| 11 | Capital Radar (`~/archymedes-inv`) | Funder ranking via Orion | Internal | **Internal tooling** | Base list "not live-verified" (README). |
| 12 | thriving-argus-1 | Team cyber knowledge site | Internal | Internal | Vercel preview behind protection (memory note). |
| 13 | `archymedes-legacy` (`circuit-agent`, archived) | Predecessor of Friday | — | **Abandoned (correctly)** | `DEPRECATED.md`; repo archived; npm packages deprecated. |

---

## 3. Per-product verdicts (gstack style)

Severity uses the gstack qa rubric:
- **Critical:** data loss, security or privacy exposure, or the core unusable for all users.
- **High:** a core task blocked with no workaround.
- **Medium / Low:** friction.

### 3.1 ARGUS-1: **NOT READY** for the general market

The QC verdict, *"Not yet ready for general users"* (`docs/security/QC-ARGUS-1-2026-10-27.md:9`),
still holds. A narrow path exists: a founder-installed, design-partner pilot on Linux servers
(§4).

**Evidence**
- **Assurance register** (`jarvis/core/assurance.py`, parsed today): 53 capabilities, **25 partial,
  28 unverified, 0 live/tested or containment-validated**. HEAD has 52; the checkout adds one.
  - The brief said 54. The measured count is 53.
  - Under the Maximum Assurance directive ("No claim without evidence",
    `docs/security/MAXIMUM-ASSURANCE.md:146`), no protection effectiveness may be marketed.
- **Never installed on another machine.**
  - QC blocker 2.
  - `native_host_portability` is *unverified*: "Never installed or run on a machine without WSL…
    Plain Linux is source-tested only" (assurance.py:34).
  - Every server capability (`server_exposure_audit`, `server_ops_health`, `server_ssh_watch`,
    `off_box_heartbeat`, `patch_cve_awareness`, `alert_channels`) says "Never run on a real server"
    or "No live delivery … measured".
- **Public distribution is broken.**
  - www.archymedes.xyz/en/solutions/argus/ says, for all three editions, "A new Windows release is
    on its way" / "A native Linux release is on its way" / "The desktop app returns with the next
    signed release".
  - The product menu still reads **"Download · Windows and Linux"**.
  - The docs (`/en/docs/argus/`) tell users to
    `curl -fsSLO https://www.archymedes.xyz/downloads/argus/argus-server-linux-x86_64.tar.gz`,
    which returns **404** today. `SHA256SUMS` returns 404 too, and the manifest is empty.
- **The signed release never reached the site.**
  - `v2026.10.30-2` is published on GitHub (2026-10-30T22:26Z).
  - The publish workflow failed (folder bug, fixed in PR #13).
  - Since then **GitHub Actions has been refused for billing**: "recent account payments have
    failed or your spending limit needs to be increased" on Argus-1 CI; the last 5 runs failed for
    that reason.
- **QC blockers status**
  1. Single install/update/uninstall: still open; no uninstall for the main product.
  2. Clean-machine validation: open.
  3. Alert quality: **partly fixed on main** (PR #12, merged 2026-10-30T23:08Z: blocklist hits now
     medium, reminders not double-counted). That is **after** the signed release, so not shipped.
     The web dashboard still double-counts (#12 "Not covered").
  4. Local API token handed to same-user processes: open on main per the QC. A
     `sec/privileged-paths` branch exists but is unmerged (memory `release-pipeline-and-hardening`).
- **Windows-specific.**
  - Unsigned exe is blocked by the ASR prevalence rule on the owner's own PC (memory
    `argus-1-rename-qc`): no code-signing certificate.
  - WSL dependency.
  - A two-hook fight between the Argus and JARVIS input hooks; the owner decided on "one install
    per machine" on 2026-10-31.
- **Security history.**
  - Source shipped in downloads 2026-10-22..29, then withdrawn (memory
    `release-pipeline-and-hardening`).
  - Draft advisories ARGUS-2026-001..003 are unpublished.
- **Strengths, real and measured.**
  - CI-only signed binary pipeline with a deny-by-default content gate.
  - VM harness 16/16 on the server edition (memory `sshwatch-and-server-binary`).
  - QEMU lab: 5 of 6 Linux positive controls detected (assurance.py:17).
  - Honest product page ("Not a replacement for enterprise endpoint security"; admin and kernel
    compromise can falsify local tools).

**Blockers, ranked**
1. **Critical:** No working download or install path for any edition, and the site advertises one.
   Root causes: Actions billing failure, release #10 waiting on an owner merge, the publish path
   unverified end to end.
2. **Critical (security product):** 0 of 53 capabilities live-tested. No install outside the dev
   machine, no real server run, no Windows clean-machine run.
3. **Critical:** Local API write token available to any same-user process (QC blocker 4, `cso`
   class: privilege boundary). The fix is on an unmerged branch.
4. **High:** No uninstall or update path. Three separate Linux install paths (QC blocker 1).
5. **High:** Alert noise. The fix is on main but unreleased; the web dashboard still double-counts.
6. **High:** Windows needs code signing; unsigned installers are blocked by common ASR policy.
7. **Medium:** Internal names (`jarvis` CLI, tasks), "Ubuntu" hardcoded, no Python check in
   `install.sh` (QC Major/Minor).
8. **Medium:** EULA in the repo (`LICENSE`, commit `c4a463c` today) is marked "DRAFT — have counsel
   review" and names "Archymedes, Inc.". The Sage dossier says a US entity is planned with the
   round, not existing (`sage/engine/src/dossier.ts:48,54`).

### 3.2 Friday CLI: **READY WITH CONDITIONS**

It is ready as a free open-source tool, which it already is. It is **not ready** as a paid product,
because there is nothing to pay for until Cloud ships.

**Evidence**
- **Shipped.**
  - npm `@archymedes/friday` 3.12.6, repo field correct, maintainer `chrisnk1`.
  - Apache-2.0 with NOTICE.
  - `docs/RELEASE_ASSESSMENT.md` documents pty journeys, recovery tests and a 3-OS package CI.
- **CI is red.**
  - None of the last 30 "CLI release checks" runs succeeded.
  - The latest (2026-10-30T23:16Z) failed `package (windows-latest)` and `package (macos-latest)`.
  - Windows failures include `TestUndoPutsBackChangedDeletedAndCreatedFilesAndLeavesStagingAlone`,
    `TestDirMatchesTheAgentsSettingsDirectory` and
    `TestAWritableBackgroundChildWorksOnItsOwnBranch`.
  - `/undo` is a headline claim (`archymedes-gtm/catalog/claims.ts` `cli.undo`, "verified").
  - Three npm releases went out in 4 days (3.12.2 → 3.12.6) while Windows and macOS were red.
- **Demand signal is weak and unmeasured.**
  - 851 npm downloads in the week to 10-29. The claim guard itself says "npm downloads are package
    events, not users" (claims.ts `traction.users`).
  - The dossier: "downloads followed launches, from 4,088 in the peak week to 265 by late
    September" (`sage/engine/src/playbook.ts:190`).
  - No telemetry, so there are no active users to cite. 0 GitHub stars.
- **Naming confusion.**
  - Product "Friday", repo `archymedes-cli`, two live npm packages (`archymedes-cli@3.7.0`, not
    deprecated, and `@archymedes/friday`), binary `friday`, site "Archymedes CLI".
  - The gtm claim `cli.npm` still says "npm install -g archymedes-cli".
- **Market.** It is a crowded category (Claude Code, Codex, many others). The README's differentiator
  is "an inspectable coding workspace". By `office-hours` Q2 the status quo is the incumbents'
  free CLIs, and no switching evidence exists.

**Blockers, ranked**
1. **High:** Windows and macOS package tests failing, including `/undo` on Windows, while releasing.
   gstack `ship` treats a red verification gate as a stop.
2. **High** (for a paid market only): no paid path. Cloud is not generally available, and billing
   is dormant.
3. **Medium:** Two npm names and three product names. Deprecate `archymedes-cli` toward
   `@archymedes/friday`, or the reverse.
4. **Medium:** No usage measurement (the opt-in telemetry is still to build, gtm `cli-free` offer).
5. **Medium:** Dirty working tree, 30 files (`git status`). Another agent may be active; not
   touched.

### 3.3 Archymedes Desktop: **NOT READY**

Labelled "In development" on the site. Not inspected beyond that, so no further claim.

### 3.4 Archymedes Cloud (and billing, routing, operations, premium-packs): **NOT READY**

- `archymedes-cli/docs/PLATFORM_STATUS.md` sets the hosted-beta gates: concurrent ledger
  correctness, webhook replay protection, refunds and chargebacks, exactly-once job outcomes,
  invoice reconciliation, backup restore, worker recovery, and export/deletion/refund behaviour.
  No evidence shows any of them met.
- Activity has stopped:
  - billing: 3 commits, last 2026-09-01
  - premium-packs: empty
  - cloud: last push 2026-09-14
- The site shows "Pre-launch" with a prepaid balance but no prices.
- Money handling is the highest-risk surface; gstack CEO Section 3 makes payment data its own
  threat model. **Recommendation: freeze**, and remove it from the public product list or label it
  "research".

### 3.5 Orion: **READY WITH CONDITIONS**

Ready for a free public beta; **not ready** for paid.

- **Evidence.**
  - Deployed and answering: `orion-web-psi.vercel.app` returns 200.
  - Honesty rules are documented (README "Honesty rule"; neutral outcomes render a tie).
  - 51 test files.
  - Accounts use scrypt with a one-time recovery code. There is no email service, so a lost code
    means a lost account (README:229-230).
  - Market research of 272 documents (`research/2026-10-27-market/`).
- **Conditions.**
  - Pricing is unconfirmed: status `founder`, not `verified`, in claims.ts:42. Checkout is
    **unverified**.
  - No email recovery.
  - The site says "Launching soon" while the app is live.
  - 6 uncommitted files.
- **Positioning.** Consumer decision-making is crowded with general chatbots. The research's own
  numbers say people already use ChatGPT and Claude for this (status quo = free general assistants).
  **Strategic risk:** it targets a different buyer from Argus and Friday and splits focus.

### 3.6 NPC Reliability Layer (gaming): **NOT READY**, and research, not a product

- 95 tests and an ablation benchmark with an independent oracle (README).
- No customer, no integration with a real engine (`src/core/world.ts` is a "stand-in for the studio
  engine").
- Today's work is legal (licence and patent drafts for counsel).
- Treat it as IP and research. Do not launch.

### 3.7 Internal tooling (gtm, Scout, Sage, Capital Radar, thriving-argus-1)

These are not market products. The gstack lens: **built, but not used for selling.**
- `payments=0`, `contacts=0` in gtm.
- Scout's 14 `reach_now` leads were never handed off.
- Scout's latest report ran on the mock judge.
- GTM metrics are stale since 2026-10-08.

Under gstack's "Interest is not demand" / "Watch, don't demo", the tooling is ahead of the selling.

### 3.8 Public site (www.archymedes.xyz): **READY WITH CONDITIONS**

**Provisional QA, links and content only:**
- Links: 303 unique links from 6 pages, **0 broken** (Links 100).
- **Content and functional findings:**
  - Argus "Download" label with no downloads, and docs commands that 404 (**Critical** under the
    qa rubric: the core task is blocked).
  - Inconsistent Argus status: "Launching soon" in the Orion page nav, "Download · Windows and
    Linux" on the home page menu.
  - No `/pricing`, `/contact`, `/privacy`, `/terms` or `/security` pages (all 404) and no company
    contact anywhere (WebFetch of /en/solutions/). A privacy policy matters for a security product.
  - Structured data `sameAs` points to `github.com/chrisnkuno/archymedes`, which is 404.
  - Positioning leads with "AI Lab in Rwanda & Africa" (home `<title>`) and a long geographic
    keyword list, rather than with a product.
- No visual, console, accessibility or performance score: needs the gstack browser (not installed).

---

## 4. Company-level view (gstack CEO and office-hours lens)

### The diagnosis, through the six forcing questions, answered from evidence

| Q | Evidence | Position |
| --- | --- | --- |
| Q1 Demand reality | $0 revenue, 0 paying customers, no outside capital as of 20 Oct (`sage/engine/src/dossier.ts:36`). gtm `payments=0`. No one is on record as upset if a product disappeared. | **No demand evidence yet.** Downloads are not demand. |
| Q2 Status quo | Argus: Defender, free EDR trials, osquery/Wazuh for servers, or "nothing". Friday: Claude Code and Codex. Orion: ChatGPT. | Status quo is strong and free for Friday and Orion. For Argus, "nothing" is common among small teams, which may mean low pain (gstack red flag) **or** an unserved niche. Unproven. |
| Q3 Desperate specificity | Scout leads name segments ("developers hit by an agent doing something unsafe"). The published report holds fixture rows only. No named human with a quote is on record. | **Not met.** You can't email a category. |
| Q4 Narrowest wedge | The dossier already names it: "one-week safety audits", Rung 1 = "3 paid audits, 25+ Argus seats" (dossier.ts:42; playbook.ts:207). gtm offer `jarvis-founding` $89/yr. | **The best answer in the company.** A founder-delivered paid audit does not need a self-serve installer. |
| Q5 Observation | No stranger has installed Argus (QC blocker 2). Nobody has been watched using Friday. | **Not met.** Assignment #1. |
| Q6 Future-fit | "Agents and servers run code with your credentials" (Argus page). More agents running on dev machines raises the stakes of local compromise. | Plausible and specific. This is the strongest thesis in the portfolio. |

### Premise challenge (CEO 0A)
- **Real problem:** distribution and proof, not features.
  - The register has 53 capabilities, and new ones are still being added (wslmanifest, licensing,
    Screen Guard).
  - Meanwhile there is no working download and no first paying user.
  - Do-nothing cost: each week adds untested surface to a product whose own rule forbids claiming
    it.
- **The 12-month ideal** (dossier rungs): 3 paid audits and 25 seats → $50K collected → $150K ARR.
  Today's plan of 5 public products plus a lab plus gaming does not move toward Rung 1. That rung
  needs one product a stranger can install and one sales motion actually run.
- **Mode recommendation: SCOPE REDUCTION** (CEO 0E: more than 15 moving parts, overlapping
  categories).

### Focus: the one or two products to take to market first

**First: ARGUS-1, Linux server edition, sold as a founder-delivered "agent-machine safety audit"**
(design-partner pilot, Rung 1). It is not sold as self-serve protection.

Why this wins (gstack "narrow beats wide", "smallest version someone pays for this week"):
- **Most finished release path.** The Nuitka native binary, signed SHA256SUMS and a CI content gate
  exist, and the VM harness passes 16/16.
- **Avoids the Windows blockers:** code signing, ASR, WSL, the hook fight.
- **Day-one value without protection claims.** Failed units, TLS expiry, SSH key drift, pending
  CVEs with KEV, and exposure are *operational findings*, not compromise verdicts. That is
  consistent with the assurance register and the directive.
- **Validation comes with the sales motion.** A human-delivered audit tolerates install friction,
  and each install is the clean-machine run QC blocker 2 needs.
- **The owner has named Argus the core** (memory `argus-1-rename-qc`), and the dossier's Rung 1 is
  already defined around audits and seats.

Conditions before the first paid audit:
1. Fix Actions billing.
2. Publish a signed release to the site, or retract the "Download" label.
3. One clean install each on Ubuntu 24.04 and Debian 12 VMs, with idle RAM measured.
4. Merge the local-API token fix.
5. Ship the alert-quality fix (#12) in a release.
6. Produce a written audit report template that states blind spots.

**Second: Friday, as free top-of-funnel and credibility, not as a revenue product.**
- Fix Windows and macOS CI (the `/undo` failure first).
- Unify the npm name.
- Add opt-in usage telemetry so "users" can be measured.
- Scout already lists "Argus prompt inside Friday" as a channel. It fits: Friday users run agents,
  which is Argus's ICP.

**Defer:**
- Orion: keep it live as a free beta; no paid launch, no outbound.
- Cloud, billing and routing: freeze.
- Desktop: freeze until Argus Rung 1.
- Gaming: IP and research only.
- Internal tools: stop building them; use gtm and Scout as they are.

### Positioning
- **Current:** "An open AI lab in Rwanda building instruments for accountable AI" with five products
  across developers, consumers and security.
- **gstack lens:** "Growth rate is not a vision" and "the user's words beat the founder's pitch".
  There are no user words yet. Lead with one sharp sentence the Argus page already contains:
  *"Agents and servers run code with your credentials. Argus watches the machine… and tells you
  what it cannot see."*
- **Honest differentiator:** it reports blind spots and never says "fixed" without evidence. The
  moat notes agree: the measured evidence record is the moat (memory `product-moat-strategy`).
- Keep the lab and Rwanda story as the *company* identity, not the product headline.

### Gaps the CEO and product lens surfaces
1. **No customer contact loop.** No pricing, contact, privacy or terms pages. The gtm checkout is
   not exercised. 14 qualified leads have not been contacted.
2. **Launch scope missing.** Per CEO Prime Directive 5, "dashboards, alerts and runbooks are launch
   scope":
   - Argus `alert_channels` and `off_box_heartbeat` are unverified.
   - There is no support channel.
   - There is no runbook for "user's install failed".
3. **Single point of failure:** the GitHub account's billing gates CI, release and site deploy for
   every product.
4. **Merge authority:** release-critical PRs (#10 signing) wait for the owner, because the agent
   classifier blocks agent merges. That is a reasonable control, but the queue is long: #8, #9, #10,
   #11, #14, #15 are open.
5. **Legal readiness:**
   - EULA is a draft.
   - Entity named "Archymedes, Inc." with no US entity per the dossier.
   - Cap table and IP assignment are "week-one fixes" (dossier.ts:54).
   - Patent draft unfiled.
6. **Rollback posture** (CEO Section 9): Argus has a signed-release path but no uninstall. A
   customer cannot roll back cleanly.

### Launch sequencing (proposed)
1. **Week 0, owner unblockers.**
   - Fix GitHub billing.
   - Merge #10.
   - Publish a signed release, including #12 and the token fix, through `publish.yml`.
   - Correct the site labels until downloads resolve.
2. **Week 1, clean-machine proof.**
   - Linux server install in disposable VMs and on one real, owner-controlled VPS.
   - Measure footprint.
   - Record results in `assurance.py` only where measured.
3. **Weeks 1–2, demand test.**
   - Contact the 14 `reach_now` leads through gtm's approval queue, with claim lint.
   - Offer the paid one-week audit (price is the owner's call).
   - Watch at least 3 installs without helping (office-hours Q5).
4. **Weeks 2–4.** Deliver the audits and collect the user's words. Rewrite the Argus page in their
   words. Decide on the Windows edition only after Rung 1 evidence and a code-signing certificate.
5. **In parallel, low effort.** Fix Friday CI and the npm naming; add opt-in telemetry; keep Orion
   as a free beta.

What would change this recommendation:
- Friday shows paid demand (someone asks to pay, or a team pilot at $1,000 closes).
- Argus clean-server installs fail repeatedly.
- Audits find no pain ("nothing" is the status quo and nobody cares).

---

## 5. Decisions only the owner can make
1. **Fix the GitHub billing failure.** It blocks all Actions: Argus-1 CI, release publish, and site
   deploys.
2. **Merge or decline** Argus-1 #10 (release signing). Decide whether to cut a new signed release
   that includes #12 (alert quality) and the local-API token fix before anything goes public.
3. **Focus.** Confirm or reject: Argus Linux-server audits first, Friday as funnel, the rest
   frozen. Decide what the public site lists and how (remove or relabel Cloud, Desktop, Orion,
   gaming).
4. **Score-integrity sign-off** on alert-quality changes (QC blocker 3 requires it).
5. **Clean-machine validation resources.** Enable Windows Sandbox or a VM; provide or approve a real
   test VPS.
6. **Code-signing certificate** for Windows (cost and identity verification).
7. **Pricing and offer.** $89/yr founding licence vs a paid audit (the dossier mentions one-week
   audits; amount for the owner). Jev's price picks were low-confidence (gtm README). Choose a
   payment processor (Stripe in gtm vs Polar in the dossier).
8. **Outreach approval.** Approve contacting the 14 Scout `reach_now` leads through gtm, and the
   message.
9. **Legal.**
   - Entity: the EULA says "Archymedes, Inc."
   - Counsel review of the EULA.
   - Privacy policy and terms for the site.
   - IP assignment and cap table.
   - Whether to file the gaming patent.
10. **npm naming.** Which of `archymedes-cli` and `@archymedes/friday` is canonical; deprecate the
    other.
11. **Telemetry.** Whether Friday and Argus get opt-in usage data (the dossier says "no telemetry
    today"). Without it, no user numbers can ever be claimed.
12. **Repo access.** Collaborator access and exposure decisions on Argus-1 and JARVIS (memory
    `product-moat-strategy`: "Never change collaborator access without the owner").
13. **The office-hours questions** this review could not ask:
    - Who is the one named person who would be upset if Argus disappeared?
    - What did they say, in their words?
    - Have you watched a stranger install it?

---

## Method notes and limits
- **Not done:**
  - gstack `qa` / `design-review` / `browse` (need the gstack browser binary, i.e. an install).
  - `cso` (needs its trusted launcher; per its own rule, **not assessed**).
  - The interactive AskUserQuestion gates of `office-hours` and `plan-ceo-review` (the owner was not
    available, so answers came from evidence).
  - No test suites run, because the host is fragile; CI records were used instead.
  - No live Friday time-to-hello-world (needs a paid provider).
  - Desktop app not inspected.
- **Jev:** not called. AGENTS.md makes Jev optional for read-only investigation, and no code was
  changed.
- **Unverified:**
  - Orion checkout and payments.
  - Whether npm downloads are humans or mirrors.
  - The state of `sec/*` branches beyond memory notes.
  - Whether QC blocker 4 is fixed anywhere merged.
- **Sources:**
  - gstack repo at `1ea8692`.
  - Local repos at their current HEADs:
    - archymedes-cli `19290c7`
    - site `15d2c06`
    - gtm `300d55e`
    - inv `6bfcdaa`
    - gaming `3d68425`
    - sales `0b3584d`
    - orion `b186cc9`
    - sage `450aaef`
    - jarvis branch `defensibility/licensing`
  - `gh` read-only on `chrisnkuno/*`.
  - Public pages fetched 2026-11-01.
  - npm registry and downloads API.
  - Web search (public terms only):
    [augmentcode](https://www.augmentcode.com/learn/garry-tan-open-sources-gstack-claude-code),
    [moltchat wiki](https://moltchat-agent-commons.onrender.com/wiki/garrytan%2Fgstack_(Garry_Tan's_Claude_Code_skill_suite)).
