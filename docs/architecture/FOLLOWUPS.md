# Follow-ups found during the restructure

## Resolved (2026-09-14, second pass)

| Item | Outcome |
|---|---|
| `gaps` descriptions for T1090 / T1176 | T1090 now credits `firewall / implant`. T1176 already named both collectors, and `T1176.001` keeps the browser-extension wording. |
| `sysmon_linux.py` (684 lines) | Package: `journal`, `harness`, `rules`, `run`. 124,491 captured journal events give identical rule findings (6,086) before and after. |
| `spyware.py` (664) | Package: `common`, `windows`, `keyboard`, `linux`, `run`. A captured Windows sample gives identical findings (33). |
| `posture.py` (584, one 307-line `audit`) | Seven section functions, then a package: `common`, `collect`, `sections`, `run`. A real sample plus two synthetic edge cases give identical results. |
| `intrusion.py` (556) | Package: `common`, `bits`, `history`, `run`. A captured sample gives identical findings (17). |
| `control.py` (572) | Trusted scheduled-task verification moved to `persistence/trusted_tasks.py` (467 lines left). |
| `core/vet.py` (556) | The 24 deny-lists and patterns moved to `core/vet_lists.py`, and `vet.py` keeps the validators (286). |
| Import ordering | ruff `I` enabled with `jarvis` as first-party, and 88 import blocks sorted. |
| `idx_ind_kind` possibly redundant | Not redundant. `EXPLAIN QUERY PLAN` shows the hunt's hot `kind=? AND status='active'` query and the gaps query use it. It stays. |

## Still open

- **Transient alert during the first move (2026-09-14, about 22:20).** Kept as
  a lesson, not a task: restart `jarvis.service` after any commit that moves
  files, since the daemon runs from this checkout.
- **About 90 package-internal underscore imports** remain (`toolchain/common`,
  `inputwatch/common|helper`, `hidden/common|views`, and the new packages'
  `common` modules). The layer rules allow them. Promote one if its package
  grows a second consumer.
- **Embedded PowerShell payloads** still live as Python strings (`PS_SPY`,
  `PS_INTRUSION`, `PS_POSTURE`, `PS_CONTROL`, …). Moving them to
  `platform/win/*.ps1` would shorten the collectors, but some are templated
  with `str.replace`, so each needs a byte-identical check of the loaded text.
- **Modules near the size cap** with no obvious seam yet: `collectors/identity/
  secrets.py` (518), `intel/research.py` (516), `collectors/network/netwatch.py`
  (493).
- **`intrusion/run.py` defines `CRED_STORES` and `BROWSER_PROC`**, but no
  Python code reads them. Check whether they were meant to feed the
  PowerShell payload before deleting them.
