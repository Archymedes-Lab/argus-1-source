"""`jarvis fix` — human-in-the-loop self-fix: JARVIS asks, you decide.

    jarvis fix                    proposals waiting on you
    jarvis fix list [--all]       open proposals (or every recent one)
    jarvis fix show <id>          full proposal: problem, evidence, patch draft
    jarvis fix propose --title T --problem P
                                  file a proposal yourself
    jarvis fix draft <id>         ask Ollama for advisory notes and opencode
                                  for a patch draft (stored, never applied)
    jarvis fix approve <id>       approve (records intent; changes nothing)
    jarvis fix reject <id>        reject with an optional reason
    jarvis fix apply <id>         apply the approved patch, test-gated, reverting
                                  on failure
    jarvis fix email <id>         re-send the proposal email (rate-limited)
    jarvis fix check              run the daemon-side scan now and mail anything new

Only this command — run by you at a terminal — may invoke opencode or apply
a patch. The scheduler never calls anything here. Approval by email reply is
impossible by construction: no inbound mail path exists, and `approve` takes
only an explicit proposal id from your shell (or the equivalent click on the
local dashboard, which is the same explicit act through the same-origin gate).
"""

import re
import shutil
import subprocess
import time

from jarvis.core.util import iso
from jarvis.response import alert, selffix

from ..output import color, is_tty

PID_RE = re.compile(r"^fx-[0-9a-f]{8}$")

# `git apply` first, tests after. The default is the same suite AGENTS.md
# requires for any change; callers (and tests) may pass a smaller command.
DEFAULT_TEST_CMD = ["python3", "-m", "unittest", "discover", "-s", "tests"]

OPCODE_TIMEOUT = 300
APPLY_TIMEOUT = 900


def _valid_pid(pid):
    return bool(pid and PID_RE.match(pid))


def _print_proposal(entry, full=False):
    t = is_tty()
    print(color(f"{entry['id']}  [{entry['status']}]  {entry.get('title', '')}",
                "bold", t))
    print(f"  problem: {entry.get('problem', '')}")
    for line in entry.get("evidence", []):
        print(f"  evidence: {line}")
    if entry.get("suggested"):
        print(f"  next: {entry['suggested']}")
    if full:
        print(f"  risk: {entry.get('risk', '')}")
        print(f"  rollback: {entry.get('rollback', '')}")
        print(f"  verify: {', '.join(entry.get('verify', []))}")
        if entry.get("model_notes"):
            print("  --- unverified local-model notes (advisory only) ---")
            print("  " + entry["model_notes"].replace("\n", "\n  ")[:2000])
        if entry.get("patch_draft"):
            print("  --- patch draft (not applied) ---")
            print("  " + entry["patch_draft"].replace("\n", "\n  ")[:4000])
        if entry.get("apply_log"):
            print("  --- apply log ---")
            print("  " + entry["apply_log"].replace("\n", "\n  ")[-2000:])
    print(f"  created {iso(entry.get('created_at', 0))}"
          + (f" · emailed {iso(entry['emailed_at'])}" if entry.get("emailed_at") else ""))


def cmd_fix(args, store):
    action = args.action
    if action in (None, "list"):
        entries = list(selffix.list_open(store)) if not args.all else \
            sorted(selffix._load(store).values(), key=lambda e: e.get("created_at", 0),
                   reverse=True)[:20]
        if not entries:
            print("no fix proposals waiting on you.")
            return 0
        for entry in entries:
            _print_proposal(entry)
            print(f"    decide: jarvis fix approve {entry['id']}  |  "
                  f"jarvis fix reject {entry['id']}  |  jarvis fix show {entry['id']}")
        return 0

    if action == "show":
        if not _valid_pid(args.id):
            print(f"no proposal {args.id}")
            return 1
        entry = selffix.get(store, args.id)
        if entry is None:
            print(f"no proposal {args.id}")
            return 1
        _print_proposal(entry, full=True)
        return 0

    if action == "propose":
        if not args.title or not args.problem:
            print("give both --title and --problem")
            return 1
        entry, created = selffix.propose(
            store, f"manual-{int(time.time())}", args.title, args.problem,
            evidence=[args.evidence] if args.evidence else [],
            suggested=args.suggested)
        print(f"{'proposed' if created else 'already open'} {entry['id']}: {entry['title']}")
        return 0

    if action == "approve":
        if not _valid_pid(args.id):
            print(f"no proposal {args.id}")
            return 1
        ok, message = selffix.approve(store, args.id)
        print(message)
        return 0 if ok else 1

    if action == "reject":
        if not _valid_pid(args.id):
            print(f"no proposal {args.id}")
            return 1
        ok, message = selffix.reject(store, args.id, args.reason)
        print(message)
        return 0 if ok else 1

    if action == "draft":
        return _draft(args, store)

    if action == "apply":
        return _apply(args, store)

    if action == "email":
        if not _valid_pid(args.id):
            print(f"no proposal {args.id}")
            return 1
        err = selffix.send_email_for(store, alert.load_conf(), args.id)
        print(f"not sent: {err}" if err else f"sent proposal {args.id}")
        return 0 if not err else 1

    if action == "check":
        from jarvis.service.schedule import JOBS
        result = selffix.maintain(store.path, store.get_snapshots(), JOBS)
        print(f"scan complete: created {result['created'] or 'nothing'}; "
              f"mailed {result['mailed'] or 'nothing'}")
        return 0

    print(f"unknown fix action {action}")
    return 1


def _draft(args, store):
    """Human-invoked drafting help. Stores text, changes nothing.

    May consult the local Ollama model for advisory notes (redacted, labelled
    unverified) and may run `opencode run` WITHOUT --auto so its permission
    rules stay deny-by-default. The prompt instructs diff-only output; any
    working-tree change opencode makes anyway is reported, not hidden, and
    `apply` refuses a dirty tree until you deal with it.
    """
    if not _valid_pid(args.id):
        print(f"no proposal {args.id}")
        return 1
    entry = selffix.get(store, args.id)
    if entry is None:
        print(f"no proposal {args.id}")
        return 1
    if entry.get("status") not in ("proposed", "approved"):
        print(f"{args.id} is {entry.get('status')}; draft only open proposals")
        return 1

    if args.with_model:
        notes = _model_notes(entry)
        if notes:
            proposals = selffix._load(store)
            proposals[args.id]["model_notes"] = notes[:2000]
            proposals[args.id]["updated_at"] = int(time.time())
            selffix._save(store, proposals)
            print("saved unverified local-model notes (advisory only).")
        else:
            print("local model unavailable — continuing without notes.")

    if not shutil.which("opencode"):
        print("opencode not found on PATH — patch draft skipped.")
        return 0
    before = _git_status()
    if before is None:
        print("not in a git checkout — patch draft skipped.")
        return 0
    prompt = (
        "You are helping maintain the JARVIS monitor (this repository). "
        "Do NOT modify any files. Study the problem below and output ONLY a "
        "unified diff (git-compatible, `diff --git` format) that fixes it, "
        "followed by nothing else. If you cannot fix it with a diff, output "
        "the single line: NO-DIFF-POSSIBLE.\n\n"
        f"Problem: {entry.get('problem', '')}\n"
        f"Evidence: {'; '.join(entry.get('evidence', []))}\n"
        f"Suggested: {entry.get('suggested', '')}\n")
    try:
        proc = subprocess.run(
            ["opencode", "run", prompt], capture_output=True, text=True,
            errors="replace", timeout=OPCODE_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"opencode failed to run: {exc}")
        return 1
    out = (proc.stdout or "").strip()[:selffix.MAX_PATCH_CHARS]
    if not out or "NO-DIFF-POSSIBLE" in out:
        print("opencode produced no usable diff.")
        return 1
    proposals = selffix._load(store)
    proposals[args.id]["patch_draft"] = out
    proposals[args.id]["updated_at"] = int(time.time())
    selffix._save(store, proposals)
    after = _git_status()
    print(f"saved patch draft ({len(out)} chars) — NOT applied.")
    if after != before:
        print("warning: opencode modified the working tree during drafting:")
        for line in (after or "").splitlines()[:20]:
            print(f"  {line}")
        print("`jarvis fix apply` will refuse until the tree is clean again "
              "(`git status`, review, `git checkout -- <file>`).")
    print(f"review with: jarvis fix show {args.id}")
    return 0


def _model_notes(entry):
    """Advisory text from the loopback model. Never a command, never trusted."""
    from jarvis.response import llm
    conf = alert.load_conf()
    text, err = llm.chat(
        conf,
        "You are a terse maintenance assistant. Suggest investigation steps only. "
        "Never output secrets, never output shell commands that delete or modify data.",
        f"JARVIS proposal: {entry.get('title', '')}. Problem: {entry.get('problem', '')}. "
        f"Evidence: {'; '.join(entry.get('evidence', []))}",
        num_predict=110, temperature=0.2, timeout=120, wait=10.0)
    if err or not text:
        return ""
    return "UNVERIFIED MODEL NOTES (do not act without review): " + text[:1500]


def _git_status():
    try:
        proc = subprocess.run(["git", "status", "--porcelain"],
                              capture_output=True, text=True, errors="replace",
                              timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _apply(args, store, test_cmd=None):
    """Apply an approved patch: snapshot, patch, test, revert on failure.

    Preconditions (all must hold or nothing happens): proposal approved,
    patch draft present, inside a git checkout, tree clean. On test failure
    every touched file is restored and new files removed, and the proposal is
    marked failed with the log tail.
    """
    pid = args.id
    if not _valid_pid(pid):
        print(f"no proposal {pid}")
        return 1
    entry = selffix.get(store, pid)
    if entry is None:
        print(f"no proposal {pid}")
        return 1
    if entry.get("status") != "approved":
        print(f"{pid} is {entry.get('status')}: approve it first "
              f"(`jarvis fix approve {pid}`)")
        return 1
    patch = entry.get("patch_draft", "")
    if not patch.strip():
        print(f"{pid} has no patch draft yet (`jarvis fix draft {pid}`)")
        return 1
    if not shutil.which("git"):
        print("git not found — cannot apply safely.")
        return 1
    before = _git_status()
    if before is None:
        print("not in a git checkout — refusing to apply.")
        return 1
    if before.strip():
        print("working tree is dirty — commit or stash first; refusing to apply.")
        return 1
    base = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                          capture_output=True, text=True, errors="replace",
                          timeout=30)
    base_commit = base.stdout.strip() if base.returncode == 0 else ""
    check = subprocess.run(["git", "apply", "--check", "-"], input=patch,
                           capture_output=True, text=True, errors="replace",
                           timeout=60)
    if check.returncode != 0:
        print(f"patch does not apply cleanly:\n{check.stderr.strip()[:1000]}")
        return 1
    applied = subprocess.run(["git", "apply", "-"], input=patch,
                             capture_output=True, text=True, errors="replace",
                             timeout=60)
    if applied.returncode != 0:
        print(f"git apply failed:\n{applied.stderr.strip()[:1000]}")
        return 1
    touched = _touched_files(before)
    cmd = test_cmd or (args.test_cmd.split() if getattr(args, "test_cmd", "") else None) \
        or DEFAULT_TEST_CMD
    print(f"patch applied at {base_commit or '?'}; running: {' '.join(cmd)}")
    try:
        test = subprocess.run(cmd, capture_output=True, text=True,
                              errors="replace", timeout=APPLY_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        _revert(before)
        _record(store, pid, "failed", f"test runner failed to start: {exc}")
        print(f"could not run tests ({exc}) — patch reverted.")
        return 1
    log_tail = ((test.stdout or "") + "\n" + (test.stderr or "")).strip()[-3000:]
    if test.returncode != 0:
        _revert(before)
        _record(store, pid, "failed",
                f"tests failed at {base_commit}; patch reverted.\n{log_tail}")
        print("tests FAILED — patch reverted, proposal marked failed.")
        print(log_tail[-1500:])
        return 1
    _record(store, pid, "applied",
            f"applied at {base_commit}; tests passed.\n{log_tail}")
    print(f"applied {pid} at {base_commit or '?'} — tests passed.")
    print(f"touched: {', '.join(touched) or 'none tracked'}")
    return 0


def _touched_files(before):
    after = _git_status() or ""
    return [line for line in after.splitlines()
            if line.strip() and line not in (before or "").splitlines()][:50]


def _revert(before):
    """Restore the pre-apply tree: checkout tracked mods, delete new files."""
    before_lines = set((before or "").splitlines())
    after = _git_status() or ""
    new_paths, tracked = [], []
    for line in after.splitlines():
        status, _, path = line[:2], line[2:3], line[3:].strip()
        if not path:
            continue
        if status.strip() == "??" and line not in before_lines:
            new_paths.append(path.split(" -> ")[-1])
        else:
            tracked.append(path.split(" -> ")[-1])
    if tracked:
        subprocess.run(["git", "checkout", "--", *tracked],
                       capture_output=True, timeout=60)
    import os
    for path in new_paths:
        try:
            if os.path.isfile(path) and os.path.exists(path):
                os.unlink(path)
        except OSError:
            pass


def _record(store, pid, status, log):
    proposals = selffix._load(store)
    entry = proposals.get(pid)
    if entry is None:
        return
    entry["status"] = status
    entry["updated_at"] = int(time.time())
    entry["apply_log"] = log[:4000]
    selffix._save(store, proposals)


def add_parser(sub):
    p = sub.add_parser("fix", help="self-fix proposals: JARVIS asks, you decide")
    p.add_argument("action", nargs="?", default=None,
                   choices=["list", "show", "propose", "draft", "approve",
                            "reject", "apply", "email", "check"],
                   help="what to do (default: list open proposals)")
    p.add_argument("id", nargs="?", help="proposal id (fx-…)")
    p.add_argument("--all", action="store_true", help="with list: include decided")
    p.add_argument("--title", default="", help="with propose: short title")
    p.add_argument("--problem", default="", help="with propose: the problem")
    p.add_argument("--evidence", default="", help="with propose: one evidence line")
    p.add_argument("--suggested", default="", help="with propose: suggested next step")
    p.add_argument("--reason", default="", help="with reject: why not")
    p.add_argument("--with-model", action="store_true",
                   help="with draft: also ask the local Ollama model for advisory notes")
    p.add_argument("--test-cmd", default="",
                   help="with apply: override test command (space-separated)")
    p.set_defaults(fn=cmd_fix)
    return p
