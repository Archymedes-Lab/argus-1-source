# ARGUS-1 commercial release plan (2026-11)

Status: plan and one built slice, committed locally on `feat/commercial-release`.
Nothing here is published, posted, sent, tagged or deployed. Every product claim
below is bounded by `jarvis/core/assurance.py` (54 capabilities: 25 `partial`,
29 `unverified`, none live-tested) and by `docs/security/QC-ARGUS-1-2026-10-27.md`
(verdict: not yet ready for general users; 4 blockers).

## Phase 1: audience evidence (Scout, stored data only)

Source: `~/sales/data/scout.db`, read-only, 2026-11-01. Stored data: 1,163 places,
128 leads, 1,291 Orion judgments, 1,287 Jev tier calls, 198 Exa searches (all on
2026-10-29, logged spend $1.39), 2 cdm channel decisions. **No refresh was run**
(the stored data is enough to choose a first launch target; spend this phase: $0).
`data/reports/report-2026-10-29.md` holds fixture rows (Acme, maconly.dev) and was
not used; the live cdm decision is `channel_decisions` row 2 (judge jev-1.13.0).

Counting rules: a place counts once per audience theme it was tagged with (places
can carry several themes). "Paying/free" is Jev's tier call per place or lead
(`tiers`); most places are `unclear` (769 of 1,159 tiered). "Engage/prepare" is
Orion's move. Lead "reach_now/reply_public" is Orion's move; Scout sends nothing.

| # | Launch audience | Scout themes / segments | Places (paying / free tier) | Orion engage / prepare | Leads (tier) |
|---|---|---|---|---|---|
| A | Windows + WSL developers running AI coding agents | `windows_wsl`, `ai_agents`; leads `wsl`, `agent_incident` | wsl 112 (9 / 49); ai_agents 181 (12 / 50) | wsl 45 / 17; ai_agents 166 / 1 | wsl 10 (1 paying, 1 free, 8 none); agent_incident 10 (1 paying, 2 free, 7 none; 2 reply_public) |
| B | Linux server admins and self-hosters | `selfhosted`, `sysadmin`; leads `linux_servers` | selfhosted 156 (10 / 72); sysadmin 152 (13 / 12) | 87 / 18; 104 / 13 | linux_servers 9 (4 free, 5 none; 1 reply_public) |
| C | Software agencies and small dev teams (buyers of seats) | `agencies`; leads `agencies`, `prospects`, `platform_teams` | agencies 134 (67 / 9) | 49 / 22 | agencies 10 (10 paying); prospects 20 (20 paying, 14 reach_now, 14 with a published email); platform_teams 9 (5 paying) |
| D | MSPs / IT providers for software firms (partners, resale) | place type `partner`; leads `msp` | partner 82 (81 / 0) | (see type) | msp 10 (4 paying, 6 none) |
| E | Compliance-driven startups and fintech engineering | `fintech`; leads `security_review`, `fintech` | fintech 147 (27 / 9) | 44 / 22 | security_review 10 (1 paying, 9 none); fintech 10 (5 paying, 5 none) |
| F | Security-minded individuals, infosec, supply-chain-aware maintainers | `infosec`, `devsec`, `supply_chain`; leads `maintainers`, `supply_chain` | infosec 151 (16 / 13); devsec 149 (15 / 28); supply_chain 110 (10 / 10) | 105 / 9; 116 / 6; 54 / 8 | maintainers 10 (4 free, 6 none); supply_chain 10 (10 none) |
| G | Launch sites, directories, marketplaces (channels, not an audience) | place types `directory` 100, `platform` 35, `marketplace` 6 | directory (14 / 23); platform (2 / 9); marketplace (0 / 2) | cdm row 2: commit Show HN, innovation Product Hunt | n/a |

Not an audience: `learners` (10 leads, all tier `none`).

### Per audience: where, needs, objections (from Scout records)

**A. Windows/WSL agent developers (mostly free).** Places with the most search hits:
IndieStack (92 hits, free), "27 Best Software Development Subreddits" (40), UBEL
marketplace (18), WindowsForum.com windows-development tag (8), Developer Toolkit |
Cursor & Claude Code Community (9, free), Collabnix (9), Handrail (6, free).
Needs, in the leads' own words: WSL "is not a security sandbox for running untrusted
code" (WSL security model page); "Containing the Blast Radius: Hardening WSL2 for AI
Coding Agents"; "An AI Agent Just Deleted a C: Drive"; "do not ask the agent what it
did" (incident-response guide); a Claude Code rm -rf home-directory bug report
(reply_public). Objections visible in the same results: free single-purpose tools
already exist (agent-blast-radius, nono sandbox, Stacktrace destructive-action rule,
AgentDFIR); Scout's hard rule excludes macOS-only users.

**B. Linux servers and self-hosters (mostly free, large).** r/selfhosted (861,000
members, free), r/homelab (1,100,000, free), r/SelfHosted Chat (49 hits), Self-Host
Talk (19), selfhosted forum (12), Self-Host Weekly newsletter (10), ServeTheHome
Forums (8), r/sysadmin (2), Self-Hosted podcast, Unraid community apps (3).
Needs: "How to log what your AI agent does on your own server"; observe-only exec/
file/net auditing (logira); the audit log must survive a root compromise
(shadowai-watch: "an attacker with root can rewrite it"). Objections: free eBPF
tools (logira, md-sentry); a same-machine record is not durable evidence.
(Outside Scout, `argus-server-readiness` research 2026-10-25 adds: heavy, noisy and
cloud-gated tools get abandoned; small teams want "host went silent" alerts.)

**C. Agencies and small dev teams (paying).** 10/10 agency leads are paying tier
(NerdHeadz, Octave, Ajackus, STX Next, Makeitfuture, LOW/CODE, Revex, CV Infotech,
Invatechs, Digital Applied), all `nurture`; 20 paying prospects (Seedlight, Softly
Tech, Bitnoise, MaxDev, Iterus, MyWebdesign.cz, WF Tech, hkdev.cz, Celaeno, TC Dev,
mFox, Cyber-Solutions Software, Agentify, Select Interactive: reach_now; CodeLinks,
Wise Pelican, GetWidget, Rippling, Neon, Ramp: nurture). Places: The Fastlane
Entrepreneur forum (90,000, paying), Digital Agency Owners Podcast (paying), Hacker
News (39 hits). Needs: they ship client code with Claude Code/Cursor/Copilot, some
"for regulated industries" (STX Next); platform teams "built the governance
infrastructure first". Objections: per-seat cost, mixed Mac fleets, no fleet view.

**D. MSPs (paying partners).** Stack2 (dev-agency IT), IT Launch Solutions,
CyberDuo, Jones IT (paying); OAC, Synaxa, goCloudOffice, Bayport, Triton, Alpiba.
Needs: "Mac, Windows and Linux developers supported", "the SOC 2 questionnaire
answered", EDR and patching already bundled. Objection: they resell an EDR already.

**E. Compliance / fintech.** Leads are guides, not buyers: "Your SOC2 Auditor Will
Ask About AI Code Security", "SOC 2 control set for agentic teams" (only paying one).
Need: an audit trail of AI tool use. Objection: Argus maps to no SOC 2 control today.

**F. Security-minded individuals.** Security Stack Exchange (25 hits), Simply Cyber
Discord (13), DevSecOps Community (15), CyberAgents Exchange (12), NewsBites, Bad
Dependencies and Adventures of Alice & Bob podcasts. Needs: post-compromise of a
developer laptop ("My laptop was compromised through the rust supply chain attack
... I'm revoking everything"). Objection: credibility; every claim must be evidenced.

**G. Channels.** cdm row 2 (Jev): commit Show HN (time 45%), innovation Product Hunt
(13%), DevHunt 13%, baseline (HN + founder email to agencies) 18%, Friday prompt 11%.
App stores: Scout holds **no** records for winget, Microsoft Store, Snap, Flathub,
Homebrew or Docker Hub (Unraid community apps only). That is an evidence gap, not a
negative signal; a later bounded Scout run should cover it before choosing a store.

## Phase 2: platform x audience matrix

What exists on `argus1/main` (5fe1588) today: Linux server binary (Nuitka, `.tar.gz`
and `.deb`), Tauri desktop app (Windows `.exe`, Linux `.deb`), the daemon's web
dashboard (`jarvis/web/static`: dashboard, coverage, procs, geo, world, pair), the
`server` CLI group (netflow, logins, sshwatch, opshealth, bootchain, keyreaders,
appcode, ...), and the phone relay PWA. Latest release `v2026.10.30-2` (published on
GitHub; the site publish is blocked by Actions billing).

QC blocker state on main, checked 2026-11-01:

| QC blocker (2026-10-27) | State on main | Source |
|---|---|---|
| 1 One install/update/uninstall path per platform | Open. CI builds one artifact per platform; update and uninstall paths for Windows desktop are not exercised end to end | `release/`, memory `argus-verified-installs` |
| 2 Never installed on another machine | Open for Windows (unsigned exe, no clean-VM run; native Windows `unverified` in the register). Server: VM harness 16/16 on 10-29, no real server install | `native_host_portability` = unverified; memory `sshwatch-and-server-binary` |
| 3 Alert quality | Partly fixed: reputation-list hits now medium, not critical (0988256); five false alarms removed (ee56c43). No fix found on main for ledger double counting of secrets or for `gaps` shown as machine findings | `git log` on main |
| 4 Local API reachable by same-user malware | Fixed in code: every `/api/*` route needs a credential, paired per-client tokens (d196a87). Not verified live on a clean install | d196a87 |

| Launch target | Edition / packaging | Channel (Scout) | Interface the audience needs | Tier | Must be true before launch |
|---|---|---|---|---|---|
| **B. Linux server admins and self-hosters** | Server: `argus-server` `.deb` and `.tar.gz` (Nuitka, binary only) | Show HN (cdm commit), r/selfhosted, r/homelab, Self-Host Weekly, Self-Hosted podcast, ServeTheHome; disclosed posts by hand only | **Terminal first-run / onboarding** (what is watched, what is not, how to remove it), the existing `server` CLI, phone notifications via the relay; web dashboard only over an SSH tunnel | Free per server | Clean install, upgrade and uninstall on Ubuntu 24.04 and Debian 12 VMs with measured idle RAM/CPU; deadman heartbeat explained at first run (opt-in today); site publish unblocked (billing); first-run text bounded by the register |
| **A. Windows + WSL agent developers** | Desktop: `Argus-Setup` (Tauri `.exe`) plus the WSL/Linux engine | DevHunt, IndieStack, Developer Toolkit (Cursor & Claude Code), WindowsForum, Product Hunt (cdm innovation) | **Guided desktop app** with a first-run that names coverage limits; in-app and phone notifications | Free per machine | Code signing (SmartScreen and ASR prevalence block unsigned exes); clean Windows VM install, update, uninstall; WSL distro discovery (not "Ubuntu"); one UAC story; QC blocker 3 remainder (ledger double count, `gaps` as findings) with owner sign-off per score integrity |
| **C. Agencies and small dev teams** | Team: several desktops/servers under one owner | Founder-led email via archymedes-gtm (owner approves each), Hacker News, Fastlane forum, Digital Agency Owners Podcast | **Web dashboard for the team lead plus a read-only status/report page for a manager or client**; per-machine health kept separate from any verdict | Paid (per machine or seat; owner sets price) | Everything in A and B, plus a fleet view (not built), licensing/billing (not built), support terms, and an evidence export whose wording matches the register |
| D. MSPs / IT providers | Team edition, resold | Partner pages (82 places, 81 paying tier) | Same as C, multi-tenant | Paid, partner margin | C shipped and run with at least one direct team; Mac support question answered (Argus has none) |
| E. Compliance / fintech | Team edition + report | Guides and content, not communities | Read-only report page | Paid | A control mapping Argus can evidence; today none exists, so no compliance claim |
| F. Security-minded individuals | Desktop or server | Security Stack Exchange, Simply Cyber Discord, DevSecOps Community (no promotion), podcasts | Same as A/B, plus the public evidence record (positive controls) | Free | The first positive control (`sensorprobe`, branch `feat/positive-control`) measured end to end, so claims rest on data |

Order of fit: B and A are mostly free audiences (selfhosted 72 free vs 10 paying
places; wsl 49 vs 9) and drive adoption and evidence; C is the paying audience
(agencies 67 paying vs 9 free; 10/10 agency leads and 20/20 prospects paying) but
needs a fleet view and billing that do not exist. No interface text for any target
may claim complete protection or a capability's live status: none is live-tested.

## Phase 3: choice (CDM over Jev, then Jev narrow questions)

Both ran live outside the sandbox on 2026-11-01. Advisory only.

**CDM** (`scripts/dev/decide.py judge`, design mode, judge jev-1.13.0; spec kept in the
session scratchpad, metadata only). Six strategies; JARVIS's hard constraints plus
three added here: `overclaim` (state protection beyond the register), `gate_loosen`
(readable proprietary content or a looser content gate), `outreach` (contact anyone
without owner approval per message).

| Strategy | Status | Mean | CVaR | P(best) | Vetoed by |
|---|---|---|---|---|---|
| `single` (baseline: ship current release unchanged) | clear | 0.424 | 0.274 | 0.935 | |
| `server_first` (server edition + terminal first-run from the register) | verify | 0.382 | 0.123 | 0.000 | |
| `audience_profiles` (one profile setting; copy from the register; server first) | verify | 0.382 | 0.123 | 0.000 | |
| `design_partners` (private paid beta first) | reject | 0.382 | 0.123 | 0.000 | evidence |
| `team_first` (paid fleet dashboard + manager report) | reject | 0.348 | 0.093 | 0.024 | overclaim, privacy |
| `desktop_first` (Windows app to WSL developers) | verify | 0.337 | 0.108 | 0.042 | |

Commit `single`; innovation none; explore none; EVPI 0.0. As in the moat run, the
identical 0.382/0.123 scores across three candidates look degenerate: CDM separates
the baseline from the rest but not the alternatives from each other. "Commit the
baseline" means no alternative is reliably better *yet*, with no measured evidence.

**Jev narrow questions** (`scripts/reviews/commercial_release_advisory.py`, jev-1.14.0,
aggregate counts only):

| Question | Type | Answer |
|---|---|---|
| Ship current release unchanged to general users while QC says not ready? | Noul | 0.06 (no) |
| Which edition should lead? | Choice | server 0.71, none-yet 0.21, team 0.07, desktop 0.01 |
| Server-only first-run vs shared audience profiles (server first)? | Choice | profiles 0.49, server-only 0.35, neither 0.16 (low concentration 0.24) |
| Does a first-run that lists what is not watched build more trust than it costs? | Noul | 0.59 (weak yes) |
| What must the server edition prove first? | Choice | clean install/upgrade/uninstall 0.72, positive control 0.19 |
| Whom to charge first? | Choice | agency seats 0.82, nobody yet 0.16 |

**Decision (deterministic, recorded here):** CDM's commit and Jev's 0.06 disagree:
the baseline is the *safest* artifact set, but its generic copy is what QC and Jev
reject for general users. The chosen strategy keeps the baseline artifacts and
release gate exactly as they are and adds only the cheapest tailoring both cleared
candidates share: **audience profiles, server profile first, with every line of
first-run text derived from the assurance register.** The checks CDM attached to
`server_first`/`audience_profiles` (overclaim, gate_loosen, evidence, recovery,
unbounded, outreach, authority) become the slice's tests. `team_first` stays vetoed;
charging agencies (Jev 0.82) waits for a fleet view and billing that do not exist.
Reconsider if a clean-VM install shows the server edition is not installable (then
the profile is moot and `design_partners`-style validation comes first), or if a
later Scout run on app stores changes the channel picture.

## Phase 4: what was built (audience profiles, server first)

`argus welcome server|desktop [--json]` prints the first-run statement for an edition's
audience: what it is built to look at, each capability's register status in plain
words, the first clause of its recorded limit, fixed facts (heartbeat off until
configured, where alerts go), the scores-are-not-verdicts note, next commands, and
how to remove it together with what is not validated about removal. `--json` gives
the same statement to the desktop app and dashboard so they never write their own
coverage claims (they do not consume it yet).

Files: `jarvis/core/audience.py` (profiles, mapping, guards), `jarvis/cli/commands/welcome.py`,
`jarvis/cli/parser.py` (registration), `tests/test_audience.py` (18 tests),
`release/server/install.sh` and `release/server/README.txt` (one hint line each, both
already allowed by `release/policy.json`), `scripts/reviews/commercial_release_advisory.py`.

Invariants written before the code, each with a test:

| Invariant | Test |
|---|---|
| Status word is a fixed map of register status (`partial`, `unverified` only) | `test_status_words_follow_the_register` |
| A stronger or unknown status, or a capability missing from the register, is "not provided", never watched | `test_a_promoted_status_is_counted_but_never_given_a_stronger_word`, `test_a_capability_missing_from_the_register_is_not_provided` |
| The live-tested count is computed from the register, never written | `test_live_count_is_counted_not_written` |
| No overclaim phrase in any line; no outcome promise in hand-written labels or facts | `test_no_profile_overclaims`, `test_render_refuses_an_overclaiming_line`, `test_handwritten_text_promises_no_outcome` |
| Limits show only the first clause (later clauses can name evasions), no source paths, bounded length and lines | `test_limits_show_the_first_clause_and_no_source_paths`, `test_empty_and_long_limits_are_bounded`, `test_render_is_bounded_in_lines` |
| Scores are not verdicts; removal states what is unvalidated | `test_scores_and_removal_are_stated_honestly` |
| Read-only, store-less, offline; no state-changing option | `test_cli_is_read_only_storeless_and_offline`, `test_cli_takes_no_option_that_changes_state` |
| Unknown profiles (including `team`) refused, CLI exit 2 | `test_unknown_profiles_are_refused`, `test_cli_refuses_an_unknown_profile` |
| Shipped hints name a real command | `test_shipped_hints_name_a_real_command` |
| Output follows a changed register (no cached copy) | `test_output_follows_a_changed_register_without_caching` |

Negative controls: adding a `live` status word, disabling the render guard, and
dropping `no_store` each made exactly one test fail; all restored.

Release content gate: no new shipped file kinds; the module is compiled into the
native server binary like every other module; `release/policy.json` is unchanged;
`tests.test_release_gate` and `tests.test_release_publish_workflow` pass.

Jev review of the slice (`commercial_release_advisory.py review`, jev-1.14.0):

| Question | Answer | Effect |
|---|---|---|
| First clause of each limit honest enough? | 0.58 | Kept; full limits stay in the register and `/api/health` |
| Unknown or stronger status listed as not provided is the right fail-safe? | 0.91 | Kept |
| Phrase list plus register words enough to stop overclaiming? | 0.26 | Acted on: added an outcome-verb guard on hand-written text and a test; heading changed to "built to look at" |
| Most important gap before shipping | native_build 0.48, desktop_consumer 0.24, user_test 0.18, register_wording 0.10 | Recorded as the first R1 gate below |

Known copy issues (register wording, not changed here because the register is the
source of truth and its owner should reword it): "Measured on this WSL Ubuntu 24.04
only" reads as the user's machine; "Not soaked" is jargon.

## Phase 5: launch blockers per platform and release sequence

| Platform | Blockers before a public release | Owner? |
|---|---|---|
| Linux server (R1) | Actions billing blocks publishing; clean install, upgrade and uninstall of the native build on fresh Ubuntu 24.04 and Debian 12 VMs, including `argus welcome server` from the binary (Jev top gap); measured idle CPU and memory; remaining QC blocker 3 items (ledger double counting, `gaps` as findings) need a score-integrity decision | billing, blocker-3 sign-off, publish |
| Windows + WSL desktop (R2) | Code signing (SmartScreen and ASR prevalence block the unsigned exe); clean Windows VM install, update, uninstall; WSL distro discovery instead of "Ubuntu"; one elevation story; desktop app shows the `welcome desktop --json` statement; native Windows mode stays labelled unverified | certificate purchase, VM enablement |
| Team edition (R3, paid) | Fleet view, licensing and billing, read-only manager report page, support terms; CDM vetoed leading with it (overclaim, privacy), so it is re-judged once R1/R2 have measured evidence | pricing, all outreach |
| App stores (winget, Microsoft Store, Snap, Docker Hub, Unraid) | No Scout evidence yet; one bounded Scout run (about 20 queries, roughly $0.15 at the logged $0.007 per search) before choosing | approve the run |

Sequence:

1. **R1 server (free).** Merge this slice after review; owner fixes billing; VM readback of
   install/upgrade/uninstall and `argus welcome server` from the native build; publish
   through `publish.yml` only. Channel per Scout cdm row 2: Show HN, then r/selfhosted and
   Self-Host Weekly, posted by a person with disclosure; nothing from Scout or this branch.
2. **Evidence record.** The `sensorprobe` positive control (`feat/positive-control`) measured
   end to end. When the register promotes a capability with evidence, the first-run text
   changes by itself, and only after a reviewed status word is added.
3. **R2 desktop (free).** After signing and a clean Windows VM run; the desktop first-run reads
   `welcome desktop --json`. Channels: DevHunt, Product Hunt (cdm innovation).
4. **R3 team (paid).** Fleet view and billing first; then the 14 Scout `reach_now` prospects
   through archymedes-gtm, each message approved by the owner.

Decisions for the owner: pricing (Jev favours charging agency seats first, 0.82, but the
fleet view and billing do not exist; free per server and per desktop is assumed here);
confirm server first (Jev 0.71); billing; code-signing certificate; score-integrity
sign-off on QC blocker 3; the bounded app-store Scout run; every publication and every
message.

## Reconciliation with the gstack market-readiness review (2026-11-01)

Source: `~/.cache/gstack-review/ARCHYMEDES-MARKET-READINESS-2026-11-01.md` (read-only
review). It recommends: ARGUS-1 Linux server edition first, sold as a founder-delivered
one-week "agent-machine safety audit" (design-partner pilot); Friday CLI as free entry;
Orion as a free beta; freeze Cloud, Desktop and gaming.

**Agreements.** Server edition first (this plan's R1; Jev 0.71). Desktop waits for a
signing certificate and a clean Windows run (this plan's R2, consistent with "freeze
Desktop until Rung 1"). No team/fleet product build now (CDM vetoed `team_first`;
the review freezes billing). Public copy may not claim protection; the honest
differentiator is the blind-spot record (moat note agrees). Owner unblockers: Actions
billing, #10, publish through `publish.yml`, clean Ubuntu 24.04 / Debian 12 installs
with idle RAM measured.

**Adopted from the review (changes to Phase 2 and Phase 5).**
- *First paid offer.* This plan had the server edition free and charging deferred to a
  team edition needing a fleet view and billing. The review's founder-delivered audit
  removes that dependency: a service needs no in-product billing or fleet view, and
  Scout's paying audience (agencies: 67 paying vs 9 free places; 10/10 agency leads and
  20/20 prospects tier `paying`) can buy it. This matches Jev's `charge_first`
  (agency seats 0.82) better than this plan did. Revised R1: free server binary **plus**
  a paid founder-delivered audit to agencies and small teams; price is the owner's.
- *Audit report template.* The review's condition 6 ("a written audit report template
  that states blind spots") is what `argus welcome server --json` already produces in
  structured form: what was looked at, each register status, first-clause limit, the
  scores-are-not-verdicts note. The template should embed that statement rather than
  restate coverage by hand.
- *Observation.* Add "watch at least three installs without helping" to R1.
- *Site.* Add to R1 blockers: the site's "Download" label and docs commands 404 today
  (review §3.1); relabel until a signed release resolves.
- *Launch scope.* No support channel and no "install failed" runbook (review §4): R1 blockers.

**Disagreements, with evidence.**

| Review says | Measured here | Evidence |
|---|---|---|
| Register holds 53 capabilities ("the brief said 54") | 54 (25 partial, 29 unverified) on both the signed tag `v2026.10.30-2` (1af9b7d) and `argus1/main` (5fe1588) | The review parsed `~/jarvis` on branch `defensibility/licensing`, a different line. Both counts are right for their refs; the release and main hold 54 |
| QC blocker 4 (API token) open; fix on an unmerged `sec/privileged-paths` branch | Narrowed, and **shipped**: d196a87 (every `/api/*` route needs a credential; daemon runs as its own account; paired per-client tokens) is an ancestor of `v2026.10.30-2` and of main | `git merge-base --is-ancestor d196a87 v2026.10.30-2` = yes. Not closed: `web/token.py may_receive` still hands the page token to a configured owner UID, so same-user malware gets it when an owner account is configured. Unverified on a clean install |
| Alert-noise fix #12 is unreleased | Agree: 0988256 is not in `v2026.10.30-2`; ee56c43 (five other false alarms) is | ancestry check |
| Contact the 14 `reach_now` leads in weeks 1–2 | Defer until R1's clean installs and a working download exist; the review itself lists both as conditions before the first paid audit. Every message stays owner-approved via archymedes-gtm | review §4 conditions 1–3 |
| Friday as free funnel | Out of this plan's scope (Argus only); no disagreement. Scout's cdm row 2 already gives "Argus prompt inside Friday" 11% of time | `channel_decisions` row 2 |

**CDM choice after reconciliation.** Not re-run: no paid calls beyond those already
reported, and CDM's spec had no "audit service" option, so its `commit single` neither
supports nor refutes the audit. The deterministic choice stands (audience profiles,
server first; artifacts and gate unchanged) and now also serves the audit offer. A
re-run with `server_audit` as a candidate is the right next CDM call when the owner
approves it.

**Revised sequence.**
1. **R0 owner unblockers:** billing, #10, a signed release containing #12 and this slice,
   site labels corrected.
2. **R1 server:** clean VM installs (Ubuntu 24.04, Debian 12) and one owner-controlled VPS,
   footprint measured, `argus welcome server` read back from the native binary, three
   unassisted installs watched, support runbook; then a paid founder-delivered audit to
   agencies and small teams (owner sets price and approves every message).
3. **Evidence record:** `sensorprobe` positive control; register promoted only on measurement.
4. **R2 desktop** only after Rung 1 evidence and a signing certificate.
5. **R3 team edition** re-judged by CDM once audits produce user evidence.
