# "Your administrator caused Windows Security to block this action"

Measured on the owner's machine, 2026-11-11, from the Defender event log (read-only).

## What is blocking

Almost every block comes from one attack surface reduction rule, **01443614**: *block
executable files unless they meet a prevalence, age or trusted-list criterion*. It stops any
program Microsoft's cloud has not seen often or for long. Argus's Windows programs are new,
unsigned and installed per user, so the rule blocks them.

| Last nine days | Blocks |
|---|---|
| Argus installer in Downloads | 63 |
| Installed desktop program (`AppData\Local\Programs\Argus`) | 4 |
| Test and probe builds | 9 |
| Windows' own services reaching for sign-in secrets (rule 9e6c4e1f, harmless) | 41 |

**Most installer blocks were caused by Argus itself.** Its intrusion audit opens every new
program in Downloads to hash it and check its signature, about every 90 minutes and on each
manual run. Windows refuses the open and records each refusal as a blocked action
(the records name the audit's own PowerShell payload as the parent). The installer was never
run by those records.

## What changed in Argus

- **The intrusion audit opens a refused file once.** It remembers the file (path, size, write
  time), lists it as "recently written program Windows blocks", and does not open it again
  until it changes. Measured live: the first pass caused one block record, the second none.
- **A new collector explains blocks** (`winblocks`, every 10 minutes, read-only). Each block
  becomes a plain finding: which rule, which program, how often, and what an administrator can
  do. A block of an Argus program by a person or another program is **high** (part of the
  protection did not run). Argus's own file checks are told apart and reported low. Windows'
  own routine blocks are low. Attack-like blocks keep their weight.
- **Argus no longer tells people to enable this rule as a key rule**, and the fix helper no
  longer enables it. It stays listed as advice, with its side effect named.

Argus never unblocks, excludes or changes Windows Security settings by itself.

## What removes the blocks (owner actions)

1. **Lasting fix: sign the Windows programs** with Authenticode and install them machine-wide
   (`Program Files`). See [the publisher-trust plan](WINDOWS-PUBLISHER-TRUST-2026-11-10.md).
   Signing alone does not exempt a file from this rule, but a signed, widely seen publisher
   builds the reputation the rule checks.
2. **Now, on this machine: allow exact files only** (elevated PowerShell). Allow the installed
   program, not a folder ordinary programs can write:

   ```
   Add-MpPreference -AttackSurfaceReductionOnlyExclusions "$env:LOCALAPPDATA\Programs\Argus\desktop\argus-desktop.exe"
   ```

   This exclusion applies to every ASR rule, not just this one (per-rule exclusions need Group
   Policy or Intune). An excluded path is a path malware can use if it can write it, which is
   why a single file and not the folder.
3. **Or keep the rule and live with it:** delete old installers from Downloads; run the
   installer once with the rule in audit mode, then set it back to block.
4. **Not recommended:** turning the rule off. It also stops real threats that arrive as new
   programs.

## Limits

The collector reads blocks still in the log from the last 24 hours. It does not judge whether
a block was right, and it does not remove the cause: until the programs are signed or the exact
files are allowed, a machine with this rule enabled keeps blocking them.

Sources: Microsoft Learn, [ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference),
[ASR FAQ](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-faq),
[Configure ASR rules and exclusions](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure).
