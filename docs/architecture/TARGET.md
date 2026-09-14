# Jarvis architecture: target and migration plan

## Layout

```
jarvis/
  core/         store, util, collection, retention, paths
  platform/     linux (/proc), windows (interop + the one PowerShell runner),
                win/*.ps1 payloads, native/ (Windows sensor spool ingest)
  collectors/
    process/      monitor, detect, hidden/, memscan, evasion, resourcewatch
    telemetry/    sysmon, sysmon_linux, auditd
    persistence/  asep, startup, flash, control, implant, backdoor
    network/      firewall, netwatch, internetwatch, sniffing, webshell
    identity/     bruteforce, secrets, impersonation/
    host/         posture, spyware, inputwatch/, intrusion, toolchain/,
                  controlwatch, pixel/
  intel/        feeds, research (was intel.py), hunt, gaps, vet
  response/     alert, remediation, repair, fixit, ledger, evidence/
  reporting/    cadence, commands, diff, notifications
  service/      schedule (job table), jobs (dispatch), scheduler, coverage,
                selfcheck, deadman, connectivity, protection, sdnotify
  web/          server (HTTP handler + dashboard state), static/
  cli/          parser, output, commands/
scripts/        install/, windows/, repair/, harden/
deploy/         systemd/, sysmon/
docs/           architecture/, guides/, reports/
```

Kept at the top level: `install.sh`, `quickstart.sh`, `quickstart.ps1`,
`jarvis.sh`, `README.md`, and `QUICKSTART.md`. These are the documented entry
points.

## Dependency rules (enforced by `tests/test_layers.py`)

Rank: `core` 0 < `platform` 1 < `collectors` 2 < `intel` 3 < `response` 4 <
`reporting` 5 < `service` 6 < `web` 7 < `cli` 8.

1. A module may import only from its own rank or lower.
2. A collector domain doesn't import another collector domain. Exceptions
   that need design work are listed explicitly in the test and must shrink,
   never grow.
3. No leading-underscore name is imported across a top-level package
   boundary. Package-internal helpers (`toolchain/common._finding`) are
   package-private and allowed.
4. Import cycles are not allowed. Function-local imports are allowed only
   with a comment saying why (startup cost or optional dependency), never to
   hide a cycle.

Refinement from the prompt: the prompt banned *all* cross-module underscore
imports. The map shows about 110 of the 157 are package-internal helpers in
already-cohesive subpackages. Renaming those would be churn without a
boundary gain, so rule 3 is scoped to package boundaries.

## Migration steps (one kind of change per commit)

| # | Kind | Step | Risk | Verification |
|---|---|---|---|---|
| 1 | extract | `core/paths.py`: one place for package, repo, win/ and static paths | path regressions | test_imports data-file test, snapshot |
| 2 | extract | Promote the PowerShell runner and `aslist` to public names in the Windows platform module, `collect_linux` helpers, `cli.output` helpers, and `alert.finding_key`, then update callers and test patches | patch targets drift | full suite |
| 3 | move | `git mv` into the layout above and rewrite imports, test patches, and `-m` references mechanically | missed reference | compileall, test_imports walks every module, string snapshot identical |
| 4 | extract | Split `server.py` into `service/schedule`, `service/jobs`, `service/scheduler`, and `web/server`, which breaks the coverage↔server cycle | scheduler behavior | test_server/test_watchdog, snapshot |
| 5 | extract | Break alert↔notifications (inject `dispatch`) and replace hunt's `__import__` | alert delivery | test_alert, test_reporting |
| 6 | test | `tests/test_layers.py` enforcing the rules with an explicit exception list | none | itself |
| 7 | move | Root scripts to `scripts/`, units to `deploy/`, and docs to `docs/`, with every reference updated (including control.py task hashes and dashboard links) | installer paths | grep for stale names, test_control, test_watchdog |
| 8 | tooling | `pyproject.toml` (ruff config, optional; no runtime deps) | none | none |
| 9 | perf | Profile the local collectors and batch or cache only where measured | detection drift | before/after numbers, snapshot |

Follow-ups that are out of scope for mechanical restructuring go in
`FOLLOWUPS.md`.
