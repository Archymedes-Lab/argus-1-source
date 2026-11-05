# ARGUS-1 licensing strategy and payment pipeline (2026-11)

Status: **strategy and a prepared pipeline; nothing deployed, priced, sent or published.**
Chosen with CDM over Jev on 2026-11-02 (advisory), after the PMF bet in `PMF-2026-11.md`:
free server edition (CDM commit) plus a paid one-week observed server review for small agencies
(CDM explore).

## The rule (unchanged, now tested)

**Core protection never depends on licence or payment state.** Detection, evidence, alerts,
collectors and on-demand checks run the same with no licence, an expired one or a forged one
(`docs/LICENSING.md` on `defensibility/licensing`). New regression test:
`tests/test_licence_never_gates_core.py`.

## What exists today (two designs, both undeployed)

| Design | Where | What it sells | Enforcement | State |
|---|---|---|---|---|
| A. Local yearly licence | `main` (bb6795b): `jarvis/web/billing.py`, `docs/BILLING.md` | $79/year; `ARGUS_REQUIRE_LICENSE=1` answers 402 on `/api/ask`, `/api/run`, `/api/assistant/action` ("turn it on for release builds") | local flag | not in `argus1/main` or any release |
| B. Signed tokens + rule packs | `defensibility/licensing` (a6370af, 1e9e65b): `jarvis/licensing/`, `hosted/licence-cloudflare/` | premium = signed rule-pack updates only | Ed25519 offline check; the Worker checks the token before serving packs | diverged from `argus1/main` (9 ahead, 57 behind); Worker not deployed; token delivery not built |
| C. Orion | `src/billing/*`, `server/billing.ts` | deeper analysis per decision | server-signed licence | live code, billing off in production |

## CDM (decide.py, jev-1.13.0, JARVIS engineering dimensions; spec metadata-only)

Morphology: sold × payment × issuance × delivery × enforcement × revocation. Record (used):
design A and Orion's design. Extra hard constraints: `core_gate` (detection, alerts, evidence or
on-demand checks depend on licence or payment), `overclaim`, `gate_loosen`.

| Option | Status | ν | Λ | Vetoed by | Raw value |
|---|---|---|---|---|---|
| `keep_both` (baseline: keep both designs as they are, undeployed; invoice reviews by hand) | clear, **commit** | 0 | 0 | — | 0.58 |
| `service_first` (software free and unlicensed; reviews by payment link or invoice; tokens wait for a paid software feature) | verify, **explore** | 0.852 | **0.422** | — | 0.56 |
| `support_only` (no licence ever; reviews + support contracts) | verify | 0.919 | 0.404 | — | 0.52 |
| `review_bundle` (a review includes a one-year rule-pack token from the offline tool) | verify | 0.748 | 0.401 | — (overclaim 0.60) | 0.47 |
| `tokens_polar` (design B now) | verify | 0.705 | 0.358 | — (overclaim 0.68, authority 0.54) | 0.44 |
| `local_gate` (design A with the flag on) | **reject** | 0.11 | 0.256 | **core_gate 0.885, evidence 0.715** | 0.56 |

As in the PMF runs, cdm's mechanism-feasibility gate rejects every six-function option outright;
the second run routes feasibility to a prototype test (`reject_above` 0.999) with the safety
vetoes unchanged at 0.70. `local_gate` stays vetoed in both runs.

## Jev narrow questions (`scripts/reviews/pmf_advisory.py licensing`, jev-1.14.0)

| Question | Answer |
|---|---|
| Will a small agency pay for the review by invoice or payment link, with no software licence? | 0.57 |
| Which pipeline piece first? | **payment links 0.59**, engagement ledger 0.34, token delivery 0.01 |
| Keep the flag that locks the assistant and on-demand checks out of release builds permanently? | **0.82 yes** |
| When to put signed tokens in front of customers? | paid-feature buyer 0.35 ≈ after three reviews 0.33 (conc. 0.13: no real preference) |

## Decision

1. **Now: service-first.** The server edition is free and carries no licence. The review is the
   only thing sold. It is a service, so its "entitlement" is the engagement itself.
2. **Never: design A's lock flag in a release.** CDM veto (core_gate, evidence) and Jev 0.82. If the
   dashboard checkout ships at all, it may only unlock premium content, never `/api/run`,
   collectors, alerts or evidence. The new test enforces this on this branch.
3. **Later: design B (tokens + signed rule packs)**, unchanged, when either a buyer asks to pay for
   a software feature or three reviews have been paid (Jev could not separate the two). Token
   delivery (a portal or `argus license install` from an email) is the missing piece then.
4. **Orion keeps its design C**; it is consistent with the rule (depth only, free core).

## The pipeline (prepared, not live)

```
 apply (gtm /o/argus-server-review)          prepared: archymedes-gtm feat/server-review-offer
   │  claim-linted offer; unpriced = apply-only; a forged pay intent becomes an application
   ▼
 scoping call (owner)  ── owner approves every message (gtm approval queue)
   │
   ▼
 price set (owner) ──► gtm offer gets priceCents ──► Stripe Checkout deposit
   │                        (or a payment link / invoice by hand while there is no entity)
   ▼
 gate: clean install/upgrade/removal measured on fresh VMs  (Jev 0.20 against skipping)
   ▼
 install with the client ─► one week ─► `argus review --days 7 --out review.txt`
   ▼
 walkthrough ─► balance paid ─► record evidence (TTHW, footprint, client's words; no client data)
   ▼
 refund / abuse: the founder stops the service; nothing to revoke (no software entitlement)
```

What would make us reconsider: a buyer asks to pay for software rather than the service (go to
design B); three reviews paid (re-run CDM with measured outcomes reported to the programme); or
no agency pays after about 15 approaches (Jev 0.48), in which case revisit the bet, not the
licence.

## Owner decisions

Price per server and deposit (Jev band 200–500 USD); entity and payment processor (Stripe in
gtm, Polar in design B); retire or pause the gtm `jarvis-founding` $89/yr offer (Windows+WSL,
old name, Python setup: it predates this bet); keep design A out of releases; when to merge
`defensibility/licensing`.
