# Assistant, detector health and the beginner UI: assurance record

Date: 2026-10-29. Branch `ui-redesign` (based on `native-hosts` `9e904be`).
Register entries: `guided_assistant`, `detector_health`, `plain_language_overview` in
`jarvis/core/assurance.py`. All three are **partial**: implemented and exercised on one
Windows machine, not validated, with no `last_validation` date and no containment claim.
This record is an engineering account of what was measured, not a security verdict.

## What each capability does

**Guided assistant** (`jarvis/response/advisor.py`, `assistant.py`, `llm.py`)

- A capability registry is the only source of what the assistant may do. A model reply is
  text; it is never passed to the action handler.
- A deterministic keyword/regex router answers common questions from stored findings and the
  score engine. It works with the local model offline. An unrecognised question gets one
  clarifying question, not a guess and not an error.
- The only state-changing action is *queue one extra read-only audit*. It needs a proposal, a
  single-use approval token (10-minute expiry) and an explicit approval. Each step is audited
  in the store. "Queued" is never reported as success: recovery is reported only when a later
  stored result is newer than the approval and has no error.
- Secret-shaped text is masked before it is displayed or sent to the model.

**Detector health** (`jarvis/service/detectorhealth.py`)

- States: healthy, late, stale, failing, never ran, malformed, permission-restricted, missing
  dependency, unsupported, not applicable. Coverage is verified, partial or blind. Only a
  fresh, error-free, well-formed result is healthy.
- Recovery is confirmed only by a result newer than the last failure. Transitions are kept in
  a bounded history with their timestamps and error text.
- Only phrases naming a missing program or module ("command not found", "no module named",
  "not installed", ...) are classed as a missing dependency. A bare "not found" or "no such
  file" stays a failure and keeps its error visible.

**Plain-language Overview and shell** (`jarvis/web/static/dashboard.html`, `styles/shell.css`)

- Status wording cannot read as healthy while any check is not reporting. Counts keep
  suspicious activity, confirmed settings, monitoring problems, unverified checks and
  user-accepted findings apart. Nothing is labelled a confirmed attack.
- Plain-language guidance is general category background and is labelled as such. The
  original evidence stays under "Technical details".

## What was verified, and how

| Claim | Evidence |
|---|---|
| Assistant, detector health, shell logic | `tests/test_advisor.py` (51), `tests/test_detectorhealth.py` (28), `tests/test_dashboard_shell.py` (41); the page's pure helpers run in Node |
| Propose, cancel, approve, reuse, forged token | Unit tests and a live daemon over HTTP |
| Approval expiry | Unit tests, plus one live run: proposal approved after 605 s was refused, nothing changed (daemon restarted in between; the proposal is stored) |
| Queued is not recovered | Live: verify immediately after approval returned "Not confirmed"; "Recovered" appeared only after a real newer result |
| Navigation, themes, drawer, focus, 7 suggested questions | Headless Chrome via the DevTools protocol against a running daemon: 53 checks, no console errors |
| Secret masking | Node tests with run-time-assembled fixtures; the rendered page was scanned for secret-shaped strings |

## What was not validated

- **Ollama.** It was not installed, not running and nothing listened on port 11434, so no real
  model was ever contacted. The stopped, model-missing, refused and inference-failed
  diagnoses were tested with simulated errors only. One real mis-diagnosis (a stopped service
  reported as "refused", because the Windows PowerShell bridge reports connection failures
  as error objects) was found against the live "Ollama absent" case and fixed; the
  missing-model and inference-failed paths have not met a real Ollama.
- **Jev review.** Not run. `AGENTS.md` requires it for non-trivial changes; it needs an API
  key (`~/.jarvis/typesafe.env` or `TYPESAFE_API_KEY`, neither present) and one authorized
  host-network run of the Jev client to `api.typesafe.ai`. Jev is advisory and cannot
  substitute for the tests above. Pending until the owner provides the key and approves the
  run; no metadata has been sent anywhere.
- **Other platforms.** Everything ran on one Windows machine. The Linux, macOS and
  dual-domain cases are simulated through `schedule.applicable`, not run.
- **Browsers.** One engine (Chrome, headless).
- **Intent routing** is keyword based. Unusual phrasings fall back to a clarifying question.
- **Error classification** in detector health is keyword based (see above).
- **Secret masking** is best-effort. Unrecognised secrets and ordinary private prose remain a
  blind spot.

## Findings seen on the development machine

While testing, the daemon's own audits reported critical-severity items on the development
computer (a WMI event subscription and a scheduled task, among others). They were **not
investigated and are not a verdict**: they may be expected software, and nothing was
disabled, deleted or remediated. They need review in the owner's own instance with the
evidence in hand and the owner's explicit approval before any action.

## Build, lint and type checks

| Check | Command | Status |
|---|---|---|
| Unit tests | `python -m unittest discover -s tests` | The whole run hangs in `tests/test_appcode.py` (`Audit.test_end_to_end`, a filesystem scan) on this machine, on the untouched baseline as well. Run per module instead (see below) |
| Lint | `python -m ruff check .` (the project's `uvx ruff check`, same tool; `uvx` is not installed here) | 12 pre-existing findings, identical on the base; none added by this branch |
| Type check | none configured | `pyproject.toml` configures ruff only; no type checker is part of the project |
| UI scripts | `node --test tests/ui/*.test.mjs` | 32 of 32 |
| CSS build | `scripts/dev/build_ui.sh` (`--check` to verify) | Needs the Tailwind v4.3.3 standalone CLI (Linux x64) |

**Why the build needs a download.** Tailwind is not vendored, to keep the product free of
npm and runtime dependencies. `build_ui.sh` fetches the standalone CLI once, verifies it
against the release `sha256sums.txt`, and caches it in `~/.cache/jarvis-ui-tools`. It is a
Linux binary, so run the script from WSL or Linux; the Windows Python splice step needs
`PYTHONUTF8=1`. The binary was not cached on this machine (Windows or WSL), and no download
was made.

**How the stylesheet stays honest without it.** `build_ui.sh` appends
`jarvis/web/styles/shell.css` verbatim after the Tailwind output. Checked offline:

- The Tailwind-generated part of the page's stylesheet is byte-identical to the base's, and
  `dashboard.css` (its source) is unchanged.
- The appended tail equals `shell.css` (`tests/test_dashboard_shell.py` enforces this).
- The script's own splice step, run in `--check` mode on the unchanged Tailwind output,
  reproduces the committed page exactly (exit 0), and exits 1 with "out of date" when
  `shell.css` is changed without rebuilding (negative control).

What remains unverified until a normal build is run: that the Tailwind CLI, run on the
unchanged source, produces the same bytes as the committed block. Do this before release:
`scripts/dev/build_ui.sh --check`, then `scripts/dev/build_ui.sh` if it reports a difference.

**Per-module test runs** avoid the `test_appcode` hang: run each `tests/test_*.py` module in
its own process with a timeout and compare against the base. Baseline failures (about 72
modules on Windows, mostly Linux-only behaviour and file-lock cleanup) are pre-existing and
were left alone. Two existing test files were edited on this branch, and both edits are
narrow: `tests/ui/harness.mjs` gained browser stubs (`addEventListener`, `matchMedia`,
`location`, `document.body`, `classList`) so a passing suite keeps passing now that the page
wires its router at load, and `tests/test_dashboard_ui.py` now writes its temp file as UTF-8,
which turned `test_page_scripts_parse` (a baseline failure on Windows) green.
