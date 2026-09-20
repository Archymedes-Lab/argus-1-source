"""Human-in-the-loop self-fix proposals: JARVIS asks, you decide.

The daemon may *propose* and *mail*, never *change*. Every function in this
module is daemon-safe by construction:

  * no subprocess, no shell, no model calls, no network except the existing
    user-configured Resend email transport;
  * proposals are deterministic text built from snapshots and the schedule;
  * approval, drafting and applying live only in `jarvis/cli/commands/fix.py`,
    which runs when you run it — never from the scheduler.

Lifecycle of one proposal:

    proposed -> approved -> applied -> (verified by the next collector runs)
       |          |
       |          +-> rejected
       +-> expired (no decision within 14 days)

Email is notify-only. There is deliberately no code path from an email reply
to an approval: replies do nothing, and the mail says so. Approval is the
explicit terminal command `jarvis fix approve <id>`, and applying is a second
explicit command `jarvis fix apply <id>` after you have reviewed the patch.

Rate limits keep a flapping collector from becoming inbox spam: one open
proposal per problem key, a 6h cooldown after a decision, one email per
proposal, and at most 3 proposal emails per 24h.
"""

import json
import time
import uuid

from jarvis.response import alert

META = "selffix_proposals_v1"
MAIL_LOG_META = "selffix_mail_log_v1"

# Same hard-stale threshold the coverage self-audit and the score use: a
# result older than this is history, not status.
STALE_SLACK = 300

# Problem keys the daemon is allowed to raise. Anything else must come from
# `jarvis fix propose`, i.e. from you.
DAEMON_KEYS = ("stale-collectors", "failing-collectors")

OPEN = "proposed"
DECIDED = ("approved", "rejected", "applied", "failed", "expired")

COOLDOWN_S = 6 * 3600
EXPIRY_S = 14 * 86400
MAX_OPEN = 10
MAX_STORED = 25
MAX_PATCH_CHARS = 20000
MAX_EVIDENCE_LINES = 12

EMAILS_PER_DAY = 3


def _now(now=None):
    return int(time.time() if now is None else now)


def _load(store):
    try:
        value = json.loads(store.get_meta(META, "{}") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _save(store, proposals):
    items = sorted(proposals.items(), key=lambda kv: kv[1].get("created_at", 0))
    while len(items) > MAX_STORED:
        _, entry = items[0]
        if entry.get("status") == OPEN and len(items) <= MAX_OPEN:
            break
        items.pop(0)
    store.set_meta(META, json.dumps(dict(items)))


def _mail_log(store):
    try:
        log = json.loads(store.get_meta(MAIL_LOG_META, "[]") or "[]")
        return [int(t) for t in log if isinstance(t, int)]
    except (TypeError, ValueError):
        return []


def _prune(store, proposals, now):
    """Expire undecided proposals older than 14 days. Returns ids expired."""
    expired = []
    for pid, entry in proposals.items():
        if entry.get("status") == OPEN and now - int(entry.get("created_at", 0)) > EXPIRY_S:
            entry["status"] = "expired"
            entry["updated_at"] = now
            expired.append(pid)
    return expired


def propose(store, key, title, problem, evidence=(), suggested="",
            risk="", rollback="", verify=(), now=None):
    """Record a proposal. Returns (proposal, created).

    An identical open proposal suppresses duplicates: the second call returns
    the existing record with created=False and sends no new email.
    """
    now = _now(now)
    proposals = _load(store)
    _prune(store, proposals, now)
    for pid, entry in proposals.items():
        if entry.get("key") == key and entry.get("status") in (OPEN, "approved"):
            return entry, False
    for pid, entry in proposals.items():
        if entry.get("key") == key and entry.get("status") in DECIDED \
                and now - int(entry.get("updated_at", 0)) < COOLDOWN_S:
            return entry, False
    if sum(1 for e in proposals.values() if e.get("status") == OPEN) >= MAX_OPEN:
        return {}, False
    pid = "fx-" + uuid.uuid4().hex[:8]
    entry = {
        "id": pid,
        "key": key,
        "title": str(title)[:200],
        "problem": str(problem)[:2000],
        "evidence": [str(line)[:300] for line in list(evidence)[:MAX_EVIDENCE_LINES]],
        "suggested": str(suggested)[:2000],
        "risk": str(risk)[:1000] or "Unknown until drafted — review the patch before approving.",
        "rollback": str(rollback)[:1000] or "git revert of the applied patch; full test suite re-run.",
        "verify": [str(v)[:200] for v in list(verify)[:6]] or
                  ["python3 -m unittest discover -s tests"],
        "status": OPEN,
        "created_at": now,
        "updated_at": now,
        "emailed_at": 0,
        "patch_draft": "",
        "model_notes": "",
        "apply_log": "",
        "base_commit": "",
    }
    proposals[pid] = entry
    _save(store, proposals)
    return entry, True


def get(store, pid):
    return _load(store).get(pid or "")


def list_open(store):
    return sorted(
        (e for e in _load(store).values() if e.get("status") in (OPEN, "approved")),
        key=lambda e: e.get("created_at", 0))


def approve(store, pid, by="operator", now=None):
    """Human approval. Records intent only — it never touches the tree."""
    now = _now(now)
    proposals = _load(store)
    entry = proposals.get(pid or "")
    if entry is None:
        return False, f"no proposal {pid}"
    if entry.get("status") != OPEN:
        return False, f"{pid} is {entry.get('status')}, not awaiting approval"
    entry["status"] = "approved"
    entry["updated_at"] = now
    entry["approved_by"] = str(by)[:80]
    _save(store, proposals)
    has_patch = bool(entry.get("patch_draft"))
    nxt = (f"review it with: jarvis fix show {pid}" if not has_patch
           else f"apply it with: jarvis fix apply {pid}  (runs the test suite first)")
    return True, f"approved {pid}: {entry.get('title')} — {nxt}"


def reject(store, pid, reason="", by="operator", now=None):
    now = _now(now)
    proposals = _load(store)
    entry = proposals.get(pid or "")
    if entry is None:
        return False, f"no proposal {pid}"
    if entry.get("status") not in (OPEN, "approved"):
        return False, f"{pid} is already {entry.get('status')}"
    entry["status"] = "rejected"
    entry["updated_at"] = now
    entry["decision"] = f"{by}: {(reason or 'no reason given')[:300]}"
    _save(store, proposals)
    return True, f"rejected {pid} — it will not be raised again for 6h"


def _stale_threshold(interval):
    return max(interval * 2, interval + STALE_SLACK)


def scan(store, snapshots, schedule, now=None):
    """Deterministic daemon-side check. No subprocess, no model, no network.

    Groups all stale collectors into one proposal and all failing collectors
    into another, so five symptoms of one dead bridge become one question,
    not five emails.
    """
    now = _now(now)
    snapshots = snapshots or {}
    if not any((s or {}).get("ts") for s in snapshots.values()):
        return []  # cold start: nothing observed yet, nothing to propose
    stale, failing = [], []
    for name, entry in (schedule or {}).items():
        if name in ("coverage", "report"):
            continue
        try:
            interval = int(entry[0])
        except (TypeError, ValueError, IndexError):
            continue
        snap = snapshots.get(name) or {}
        ts = snap.get("ts") or 0
        if snap.get("error"):
            failing.append(name)
        elif ts and now - int(ts) > _stale_threshold(interval):
            stale.append(name)
        elif not ts:
            stale.append(f"{name} (never reported)")
    created = []
    if stale:
        names = ", ".join(sorted(stale)[:MAX_EVIDENCE_LINES])
        proposal, made = propose(
            store, "stale-collectors",
            f"{len(stale)} collector(s) reading history, not status",
            "Collectors aged past their hard-stale threshold while the "
            "reliability watchdog kept re-queueing them. The score already "
            "treats these areas as unverified.",
            evidence=[f"stale: {names}"],
            suggested="Investigate why these collectors cannot complete "
                      "(bridge, sensor, or schedule overload), then draft a "
                      f"targeted fix with: jarvis fix draft <id>",
            risk="No change is made by this proposal itself. Any future patch "
                 "is reviewed and test-gated before it lands.",
            rollback="No change to roll back until a patch is applied.",
            now=now)
        if made:
            created.append(proposal)
    if failing:
        names = ", ".join(sorted(failing)[:MAX_EVIDENCE_LINES])
        proposal, made = propose(
            store, "failing-collectors",
            f"{len(failing)} collector(s) reporting errors",
            "Collectors whose latest run recorded an error instead of "
            "evidence. Their subject areas are uncovered until they succeed.",
            evidence=[f"failing: {names}"],
            suggested="Read the recorded errors with `jarvis coverage -v`, "
                      f"then draft a targeted fix with: jarvis fix draft <id>",
            risk="No change is made by this proposal itself.",
            rollback="No change to roll back until a patch is applied.",
            now=now)
        if made:
            created.append(proposal)
    return created


def email_text(proposal):
    """Deterministic mail body. States plainly that replies do nothing."""
    lines = [
        "JARVIS needs a decision from you before it changes anything.",
        "",
        f"Proposal {proposal['id']}: {proposal.get('title', '')}",
        "",
        f"Problem: {proposal.get('problem', '')}",
    ]
    if proposal.get("evidence"):
        lines.append("Evidence:")
        lines += [f"  - {line}" for line in proposal["evidence"]]
    if proposal.get("suggested"):
        lines.append(f"Suggested next step: {proposal['suggested']}")
    lines += [
        f"Risk: {proposal.get('risk', '')}",
        f"Rollback: {proposal.get('rollback', '')}",
        f"Verification: {', '.join(proposal.get('verify', []))}",
        "",
        "Nothing has been changed. Nothing will change until you approve AND "
        "apply it at a terminal:",
        f"  jarvis fix show {proposal['id']}",
        f"  jarvis fix approve {proposal['id']}",
        f"  jarvis fix apply {proposal['id']}",
        "",
        "You can also review and approve from the local dashboard "
        "(http://localhost:8787/#fix — same machine only); the approve "
        "button there is equivalent to the terminal command.",
        "",
        "Replying to this email does nothing — approval only counts from the "
        "terminal command above. Model-generated notes, if any, are labelled "
        "as unverified and never authorize action.",
    ]
    return "\n".join(lines) + "\n"


def send_email_for(store, conf, pid, now=None):
    """Mail one proposal, rate-limited. Returns '' on success else an error."""
    now = _now(now)
    if not alert.enabled(conf):
        return "alerts are not configured"
    proposals = _load(store)
    entry = proposals.get(pid or "")
    if entry is None:
        return f"no proposal {pid}"
    if entry.get("status") != OPEN:
        return f"{pid} is {entry.get('status')}, not awaiting approval"
    if entry.get("emailed_at"):
        return f"{pid} was already mailed"
    log = [t for t in _mail_log(store) if now - t < 86400]
    if len(log) >= EMAILS_PER_DAY:
        return f"daily proposal-email budget spent ({EMAILS_PER_DAY}/day)"
    subject = f"[JARVIS] fix proposal {entry['id']}: {entry.get('title', '')}"[:200]
    err = alert.send_email(conf, subject, email_text(entry))
    if err:
        return err
    alert.record_send(store)
    entry["emailed_at"] = now
    entry["updated_at"] = now
    _save(store, proposals)
    log.append(now)
    store.set_meta(MAIL_LOG_META, json.dumps(log[-50:]))
    return ""


def maintain(db_path, snapshots=None, schedule=None, now=None):
    """One daemon pass: scan for problems, mail new proposals. Never raises.

    This is the only entry point the scheduler calls. It performs no
    subprocess, model, or network activity beyond the rate-limited proposal
    email through the user's own configured Resend transport.
    """
    try:
        from jarvis.core.store import Store
        if schedule is None:
            # The response layer cannot depend upward on service scheduling.
            # Daemon and CLI callers own that policy and pass their registry.
            return {"created": [], "mailed": []}
        now = _now(now)
        store = Store(db_path)
        try:
            if snapshots is None:
                snapshots = store.get_snapshots()
            created = scan(store, snapshots, schedule, now=now)
            conf = alert.load_conf()
            mailed = []
            for proposal in created:
                if not send_email_for(store, conf, proposal["id"], now=now):
                    mailed.append(proposal["id"])
            return {"created": [p["id"] for p in created], "mailed": mailed}
        finally:
            store.close()
    except Exception:
        return {"created": [], "mailed": []}
