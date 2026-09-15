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

## Resolved (2026-09-15, third pass)

| Item | Outcome |
|---|---|
| Embedded PowerShell payloads | 21 payloads moved to `platform/win/*.ps1` and load via `core.paths.load_win_script()` with newline translation off. Every loaded payload is byte-identical to the old string constant. `.gitattributes` pins LF, and tests check each file exists and that the templated placeholders survive. |
| `secrets.py` (518) | Package: `patterns`, `exposure`, `run`. A home-directory scan gives the same 50 credential findings. |
| `research.py` (516) | Package: `extraction`, `client`, `run`. The search request, `summary()`, and a synthetic ingest (16 candidates, 8 kept) are identical. |
| `netwatch.py` (493) | Package: `sample`, `record`, `run`. The audit over the live timeline is identical (14 findings). |

## Still open

- **`CRED_STORES` / `BROWSER_PROC` and the "credential stores" coverage
  claim.** Both patterns date from the initial commit and have never been
  read. PowerShell section 6 of `intrusion.ps1` collects `credAccess` (store
  paths and last-write times), which nothing reads either. Meanwhile
  `intel/gaps.py` lists T1555.003 as covered by intrusion. The intended check
  ("who has the browser credential stores open") was never built, so the
  coverage claim is currently false. Decide: build a real check, or remove the
  dead code and the claim.
- **Transient alert during the first move (2026-09-14, about 22:20).** Kept as
  a lesson, not a task: restart `jarvis.service` after any commit that moves
  files.
- **About 90 package-internal underscore imports** remain. The layer rules
  allow them.
