# Network roam classifier and firewall reachability review — 2026-09-25

Continuing the route toward 90 described in
[the 2026-09-24 network transition review](NETWORK-TRANSITION-REVIEW-2026-09-24.md):
Network was 35, then a narrow correction projected ~53. The live host now reports
Network 73 with 100% scored coverage (security score 70 overall; Active threats 19,
OS hardening 80, Persistence & access 67, Data & privacy 50, Developer toolchain 100,
Monitoring 100 — read from the running `/api/state`, not the candidate checkout).
This document covers two further, still-uncommitted changes on top of that: a
same-network "coherent unverified roam" classifier and a Windows Firewall
reachability check (`jarvis/platform/firewall_state.py`) that only lowers an
otherwise-exposed listener when every profile provably blocks it.

## Invariants before implementation

1. Never rewrite or delete a raw `net_events` row; only derived audit findings may
   be lowered, and only while citing the original.
2. `coherent_unverified_roam` may lower `ap-unknown`/`ap-repeat-unverified` from
   high to **medium**, never to low/ok — it establishes recent stable context, not
   AP ownership. It requires: same iface, same SSID, a fresh pair (≤900s), both
   samples `connected`, matching auth **and** cipher within an explicit WPA2/WPA3
   allow-list, and byte-identical gateway, gateway MAC and DNS.
3. Any missing pair, missing BSSID, stale timestamp, or single mismatched field
   keeps the original severity — uncertainty must not lower a finding.
4. `firewall_state.blocked()` may report a listener unreachable only when **all
   three** profiles (Domain/Private/Public) are enabled, default to block, and
   either ignore allow rules entirely or have no enabled inbound allow rule
   matching protocol, port and program. Unparseable rule fields (RPC keywords,
   ranges) and any unreadable/missing profile state count as still exposed.
5. No automatic firewall, DNS, gateway or Wi-Fi change follows from either
   classifier. Both are read-only reclassification of existing findings.
6. A remote-access agent's permissive inbound rule (`REMOTE_AGENTS`) stays
   critical even when "block all incoming connections" is active — the agent is
   installed and one toggle away, so the rule is not treated as inactive.

## Design comparison

For the roam classifier: keep all cross-BSSID changes high (simplest, but
indistinguishable from the already-solved cross-network case and keeps noise);
mark the AP as trusted/known after N sightings (rejected — a replayed SSID/BSSID
pair would pass this automatically, which is the exact failure the original
`ap-repeat-unverified` design exists to avoid); or downgrade only to medium under
the strict same-topology test above, leaving the raw high event intact — selected,
matching the same evidence-continuity approach already used for the identified
network-switch case.

For firewall reachability: trust the active profile only (rejected — joining
another network silently changes which profile is active, and a rule enabled on
an inactive profile would go unaudited); parse and trust rule scope exactly
(rejected — RPC/dynamic port and remote-address scope are not fully resolvable
from `Get-NetFirewallRule` metadata alone, so a confident "safe" there would be a
false negative risk); or require all three profiles to independently prove
blocking, with any unparseable or missing state treated as exposed — selected.

Reconsider the roam classifier if an active on-path relay attack becomes a
credible threat in this environment (see below); reconsider the firewall check
if `Get-NetFirewallRule` scope resolution becomes reliable enough to stop
treating RPC/keyword rules as always-open.

## Jev advisory (bounded, metadata-only, host-network path)

Two independent questions, no file contents or credentials sent:

- **Noul, on-path relay gap**: "Does downgrading `ap-unknown` to medium create a
  real detection gap for an active on-path relay (evil-twin MITM) that matches
  gateway MAC and DNS by relaying rather than by coincidence?" → **0.6** (mild
  lean yes). This is a genuine, previously-implicit blind spot, not a false
  positive: an attacker capable of actively relaying all traffic could reproduce
  gateway MAC and DNS while presenting a new BSSID, satisfying the coherence
  test. The design already bounds the consequence — the raw high event is
  preserved unmodified in the timeline, and the derived finding only ever falls
  to medium, never low/ok, so an operator working from raw events still sees the
  original high. This blind spot is recorded in code (`coherent_unverified_roam`'s
  docstring: "never AP ownership") and is repeated here rather than left implicit.
- **Choice, firewall check conservatism**: "appropriately_conservative" at
  confidence 0.97 (probabilities: appropriately_conservative 0.98,
  too_conservative 0.01, not_conservative_enough 0.01).

These are advisory signals, not verdicts; the executable tests below and the live
read are what actually establish behavior.

## Verification performed

- Full suite: `python3 -m unittest discover -s tests` — **1521 tests, OK**, run on
  the real host (not the restricted sandbox, which hung on a live call during an
  earlier attempt in-session — consistent with the sandbox-network caveat in
  `docs/security/MAXIMUM-ASSURANCE.md`).
- `ruff check` on every changed file in this area — all checks passed.
- `tests/test_netwatch_switch.py` covers the roam classifier directly: fresh vs.
  stale pairs, auth/cipher downgrade, gateway/DNS mismatch, missing BSSID, and the
  ARP-gap corroboration window and its bound (`MAC_CONFIRM_LIMIT`).
- `tests/test_firewall_state.py` covers `blocked()`/`rule_inactive()`: block-all
  toggle, a matching allow rule on any one profile, RPC/keyword treated as open,
  disabled profile or default-allow treated as open, and unreadable/empty state
  proving nothing.
- Live read of `/api/state` on the running daemon confirms Network is currently
  73/100 under the **deployed** code (which does not yet include this session's
  roam/firewall change) — this establishes the baseline these changes build on,
  not the effect of the change itself.

## Deploy baseline (before), 2026-09-24T22:59:47Z

Live `/api/state`: security score 70 (Network 73). `netwatch` job: 1 medium
("ap unknown during coherent unverified roam ×4" — the same-SSID/different-BSSID
case this session's stricter WPA2/WPA3+gateway/DNS match refines further), 2
medium drops (net-profile-disconnected ×3, wlan-disconnected), 9 low findings
(network-switched, dns/gateway-changed-during-switch, wlan chatter). `firewall`
job: 1 medium ("service installed recently"), 17 low (7 "service installed
recently", 10 "permissive inbound rule" — the exact findings `firewall_state`
is meant to reclassify once a listener is provably unreachable). No
`internetwatch` findings were open at this snapshot to compare against.

Staged in `~/.cache/jarvis-release-staging/20260924T225925Z-on-39dbdf2bd1e1`
alongside the secrets classification reviewed the same day
([SECRET-EXPOSURE-REVIEW-2026-09-25.md](SECRET-EXPOSURE-REVIEW-2026-09-25.md)).

Expected after deploy, finding by finding: the "ap unknown during coherent
unverified roam" finding may re-title or count differently only if the pair no
longer matches the stricter auth/cipher allow-list check added this session —
it must never disappear or drop below medium on its own. Any `internetwatch`
"application listening beyond loopback" medium that Windows Firewall provably
blocks on every profile should appear as low with a "not reachable from the
network" detail; nothing should silently vanish. A permissive-inbound-rule
finding should drop to low only when every firewall profile ignores allow
rules (a distinct condition from a listener being blocked), and never for a
`REMOTE_AGENTS`-matched rule (AnyDesk etc.), which stays at its original
severity regardless.

## Not yet done

This code is uncommitted and not deployed. Per the standing deploy constraint, it
must go out only as a narrow release built from the running sealed source with an
explicit administrator switch and rollback ready — not a retry of the direct
`deploy_root_runtime.py` invocation from a dirty checkout, and not a service
restart alone. Live effect on the Network score, a fresh `netwatch`/firewall
collector receipt, and the on-path relay blind spot's real-world likelihood on
this host remain unverified until that release is authorized, switched, and read
back.

A separate, still-blocked change (adding an AtStartup/SYSTEM scheduled task so
the injected-input Win32k audit trace starts before user logon instead of at
the next logon or 15-minute broker tick) is not part of this release. The edit
to `broker-jarvis.ps1` was refused by the permission system as new,
unauthorized boot persistence and needs the owner's explicit sign-off before
it is written, let alone staged.

## Owner-acceptance policy and network pin — deployed 2026-09-25T00:14:17Z

Owner decisions this session: an acknowledged finding is charged as low in the
security score (reversing b5a8f39; it stays listed as `accepted` posture debt and
still blocks the `no_weighted_findings` readiness gate); Norrsken Guests and
Norrsken Members are confirmed networks; the two Codex sandbox accounts are
disabled; WSLg is turned off (`guiApplications=false`, pending `wsl --shutdown`).

Release `sha256:16b53e695072c0ea4ecdbea0bfb8b2b771f7ce695128b14b3a5d32e44aceaefd`
also narrows the ClickFix history rule to `Bypass -Command` (a `-File` target is a
file already on disk; JARVIS's own repair scripts were the two highs). Tests:
1531 pass. `jarvis netwatch --confirm-network` pins exact recorded BSSIDs plus
the single gateway MAC; only AP-change findings are lowered, and a drop beside an
identified network switch or a pinned roam is no longer called suspicious (a
burst still is). Jev advisory: pin Noul 0.63; acceptance weakness Choice was
diffuse (stale acceptance 0.45, score misread 0.35, confidence 0.27).

Live readback after forced runs of intrusion, netwatch, backdoor and internet:
score 72 → 89 at 100% coverage. Active threats 17 → 36, OS hardening 80 → 100,
Persistence 67 → 100, Data & privacy 73 → 89, Network 67 → 100. 21 acknowledged
findings are live, 13 of them recorded in earlier sessions under the old
no-score-effect rule. Remaining: the injected VK_0x00 keystroke (high, not
accepted), X11 (clears after `wsl --shutdown`), 12 Active-threats mediums. Not
done: starting the input-audit trace at boot (broker-jarvis.ps1).
