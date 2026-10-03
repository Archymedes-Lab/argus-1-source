# Protection-score stability review, 2026-09-24

The latest live score is 64 with 100% scored coverage. The service reports
healthy, live, ready, and protection-healthy; its installed source still
differs from the staged collector corrections. These flags establish daemon
health, not that the remaining findings are safe.

The stored score series shows 74 to 66 when two high network changes were
recorded across an identified Wi-Fi switch, then 66 to 63 as a new access
point on the same SSID and three medium drop findings appeared. A one-point
63/64 movement followed a medium persistence finding changing. A much older
10-point reading followed sleep and recovered through 58, 69, 70, and 73;
the code now has a bounded wake re-verification hold, but that older episode
must not be presented as proof of the current release's wake behavior.

## Stability invariants

- The score follows fresh, complete collector evidence. A new unverified
  access point remains visible even if the score becomes less steady.
- Raw network and process events stay preserved; a derived verdict may explain
  them only with exact evidence and a conservative fallback.
- Missing or stale sensors cannot be treated as clean. Any wake hold is
  bounded and exposes its verification phase and live underlying score.
- Acknowledging a finding does not erase its protection-health debt.
- A stable number is useful only when it reflects stable protection. Verify
  fresh snapshots and the deployed code after each repair.

## Options and decision

1. Smooth or hold all score changes: visually steady, but hides new risk.
2. Acknowledge findings to flatten the score: preserves some queue history,
   but misrepresents unresolved protection debt.
3. Correct identified cross-network comparisons, reconcile deleted executable
   evidence, and investigate transient collector findings at their source:
   selected. The remaining access-point alert stays high until independent
   trust evidence exists.

Jev's metadata-only Choice selected source-level evidence fixes (confidence
1.0); its Noul favored keeping the unfamiliar access point visible despite
score movement (yes probability 0.90). This is advisory. The network and
process regression tests, release manifest diff, fresh collector receipts,
and live score are the decision gates.

The staged release at `/tmp/jarvis-netwatch-narrow-20260924` is the immediate
stability work. After an authorized administrator switch, read back the
installed manifest, wait for fresh `netwatch` and `scan` snapshots, compare
their findings with the original events, and observe the score over several
collector intervals. A claimed recovery to 70 or 80 needs measured protection
changes beyond these two corrections; the remaining high access-point and
historical threat findings are not safe to discard for a target number.
