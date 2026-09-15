# Autonomous defense

JARVIS can take reversible action against a threat on its own, but only within
strict limits and only when you turn it on. The default posture is **propose,
never act**.

## The response ladder

For every finding, `jarvis/response/defense.py` chooses one rung:

- **AUTO** — a reversible containment action fits, the finding is critical or
  high, and you enabled that action. JARVIS captures evidence, acts, and tells
  you what it did with an undo command.
- **PROPOSE** — an action fits but it is not enabled (or the finding is only
  medium). It waits for `jarvis defend approve <id>`.
- **ASK** — no action fits, but only you can judge it: it becomes a question
  (`jarvis answer <id> yes|no`).
- **WATCH** — nothing to do.

Everything AUTO does is reversible and recorded in the defense ledger, so any
action can be undone with `jarvis defend undo <id>`.

## Actions

| action | host | what it does | undo |
|---|---|---|---|
| `quarantine_file` | wsl | move a dropped file into a locked store, leave a marker | move it back |
| `block_address` | win | Windows Firewall outbound block to a flagged IP | remove the rule |
| `suspend_process` | wsl | SIGSTOP a suspicious process (memory kept for a dump) | SIGCONT |

Killing, deleting and disabling accounts are **approval-only** and are added as
proposals, never run automatically.

## Turning it on

Off by default. In `~/.jarvis/config.json`:

```json
{
  "autonomous_defense": true,
  "auto_quarantine": true,
  "auto_block_ip": false,
  "auto_suspend": false
}
```

`autonomous_defense` is the master switch; each action also needs its own flag.
Enable one at a time and watch `jarvis defend` to see how it behaves on your
machine before enabling more.

## Commands

```
jarvis defend            what JARVIS did, and what is waiting for you
jarvis defend actions    the actions and whether each is auto or propose-only
jarvis defend approve <id>
jarvis defend undo <id>
jarvis answer            open questions
jarvis answer <id> yes   confirm as expected (acknowledges it)
jarvis answer <id> no    escalate / contain it
```
