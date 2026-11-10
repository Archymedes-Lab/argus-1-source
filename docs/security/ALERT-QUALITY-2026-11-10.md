# Alert quality, round 2: package source in Temp, stale firewall rules, plain wording

Integration review: the prefix-only firewall downgrade below was rejected and
removed. Directory names do not prove ACL protection (Windows Temp, traversal,
delegated permissions). Orphaned rules retain their previous severity until ACL
evidence exists. The package-source change remains, with normalized-path traversal
controls; it is not a claim that package code is harmless. See
[the integration plan](UI-INTEGRATION-PLAN-2026-11-10.md) for current evidence.

Date: 2026-11-10. Follows [ALERT-QUALITY-2026-11-08](ALERT-QUALITY-2026-11-08.md). Needs owner
review before release (detector severity changes fall under the score-integrity rule).
Each change below is argued as a detector bug with a replay.

## Where the noise actually came from

A read-only look at one real store (a developer machine, last written 2026-11-03: 226 high,
19 critical findings). Two detectors produced 193 of the 226 highs. They are general rules
about Windows and npm, not about this machine.

| Detector | Finding | high before | cause |
|---|---|---|---|
| `host/intrusion/run.py` | recently written unsigned executable | 124 | unsigned `.js` library files from an `npm install` under `%TEMP%` |
| `network/firewall.py` | permissive inbound rule | 69 | 41 rules left behind for programs that were removed or updated (Edge WebView mDNS, one set per old version) |

The remaining highs are real signals or already covered by earlier rounds (secrets in plain
text, a camera in use, firmware measurement change, coverage health).

## Invariants

1. **No lost visibility.** Both changes lower severity only. Every finding stays listed with
   the same title, path and detail.
2. **Only the proven-harmless shape is lowered.** Anything that is not exactly that shape keeps
   its old severity (tests below).
3. **A second signal still raises it.** A bad signature, a native add-on, an executable, a
   user-writable path or a remote-access group is unchanged.

## 1. Package source under Temp (intrusion)

**Detector bug.** "NotSigned" is meaningless for library source: nobody Authenticode-signs
`.js` files, so every unpacked npm package looks like an unsigned program. One `npm install`
in a scratch folder under Temp wrote 122 of them.

**Fix.** `PACKAGE_SOURCE`: a `.js`, `.mjs` or `.cjs` file under a `\node_modules\` folder with
signature `NotSigned` is **low**. Not lowered: `.node` add-ons, `.exe`/`.dll`, `HashMismatch`,
`NotTrusted`, and any script outside `node_modules` (a loose `dash.js` in Temp stays high).

**Designs compared.** (A) lower package source only (chosen). (B) lower every `.js` in Temp:
a dropped script is a real staging technique (T1059.007), so no. (C) skip `node_modules`
entirely: loses visibility of a poisoned package, so no.
Reconsider (A) if a package manager other than npm-style unpacking needs the same treatment.

## 2. Stale firewall rule for a protected path

**Detector bug.** A rule for a program that no longer exists, plus "any remote address", was
counted as two risks and became **high**. When the program's folder is administrator-only
(`Program Files`, `Windows`), no user-level process can plant a program there, so the rule
admits nothing a user could abuse. It is clean-up, not exposure.

**Fix.** `PROTECTED_PATH`: an orphaned rule under `Program Files`, `Program Files (x86)`,
`Windows` (or their `%ProgramFiles%` / `%SystemRoot%` forms) no longer counts toward the
"more than one risk" rule, so with only "any remote address" it is **medium**. Unchanged: an
orphaned rule in a user-writable or any other folder, and any rule in a remote-access group.

## Replay (recorded store, read-only, nothing written)

The 69 firewall rules and 126 staged files that were high before:

| | high | medium | low |
|---|---|---|---|
| staged files, before | 124 | 0 | 2 |
| staged files, after | 2 | 0 | 124 |
| firewall rules (the 69 highs), before | 69 | 0 | 0 |
| firewall rules (the 69 highs), after | 31 | 38 | 0 |

The two staging highs left are loose scripts (`dash.js`, `split-package.js`) in Temp, which
is correct. The 31 firewall highs left are user-writable paths, remote-access groups or
"any program" rules.

## Tests

- `tests/test_scan_races.py::PackageSourceTests`: package source is low and listed; add-ons,
  executables, bad signatures and loose scripts stay high.
- `tests/test_firewall_state.py::StaleRuleTests`: protected-path orphan is medium and listed;
  user-folder orphan, other-folder orphan and remote-access group stay high.
- Both new test classes fail on the code before the change.

## Plain wording (Simple mode)

The Simple-mode sentences for `staging` and `rules` were reworded for a reader of about
twelve ("the computer cannot tell who made it", "a rule that lets other devices talk to one
of its programs"). Changed together: `guide.json`, `plainalert.py`, `dashboard.js` and the ten
locale files. **The ten translations were written by Claude and have not been read by native
speakers.**

## Not changed, for the owner

These need a decision, not a bug fix. In the same store they are small (8 of 226 highs):

- Argus's own health ("collector 'x' is failing", "detection regressed") still counts in the
  machine's high totals. Invariant 6 of the 11-08 work treats coverage gaps as about Argus;
  collector health may deserve the same, with the banner and Checks view as its home.
- WMI event subscriptions and auto-start entries under `AppData` are critical on one signal.
- Media keys (VK 0xB3) count as injected input.

## Blind spots

Replayed on stored findings of one machine, not on a second clean machine and not on a live
daemon. Rule 2's `exists is False` depends on the PowerShell probe reporting a path correctly.
