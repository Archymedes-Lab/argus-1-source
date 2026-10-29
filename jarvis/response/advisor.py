"""Guided, evidence-bound security advice that works with no language model.

Invariants this module keeps:
  * Every claim comes from stored snapshots, the scoring engine or the triage
    rules. Nothing is "checked" unless the code here read that state, and a
    check that read stored results says so rather than claiming a fresh run.
  * What ARGUS can do is the CAPABILITIES table and nothing else. The router
    and any model text can only *name* a capability; handle_action validates
    the name, target and availability before anything runs.
  * A capability that changes anything (here: queueing one read-only audit)
    needs an explicit proposal, an approval token, and is audited. Success is
    only reported after a later fresh, error-free result, never on queueing.
  * No capability here changes security settings, deletes files, stops
    processes or edits firewall rules. Those are listed as unavailable.
  * Text shown to the user passes through privacy.redact.
"""

import json
import re
import secrets
import time
from dataclasses import dataclass

from jarvis.response import acknowledge, alert, llm
from jarvis.response.privacy import redact
from jarvis.response.reporting import score, triage

CHECK, PREPARE, GUIDE, UNAVAILABLE = "check_now", "prepare", "guide", "unavailable"
PROPOSAL_TTL_S = 600
_PENDING_KEY, _AUDIT_KEY = "assistant_pending", "assistant_audit"
_AUDIT_MAX, _PENDING_MAX = 200, 20
_FID = re.compile(r"^[0-9a-f]{8}$")


@dataclass(frozen=True)
class Capability:
    id: str
    title: str
    purpose: str
    mode: str                  # CHECK, PREPARE (needs approval), GUIDE, UNAVAILABLE
    read_only: bool
    platforms: tuple = ("any",)
    needs_runner: bool = False  # needs a live scheduler to queue work
    permissions: str = "none beyond reading ARGUS's own stored results"
    risks: str = "none"
    rollback: str = "not needed"
    verify: str = ""
    alternative: str = ""


CAPABILITIES = {c.id: c for c in (
    Capability("explain_finding", "Explain this alert", "Describe one current finding in plain language.",
               CHECK, True, verify="Reads the stored finding; nothing to verify."),
    Capability("check_monitor", "Check this problem",
               "Read a monitor's stored last result: age, error, and likely cause.",
               CHECK, True, verify="Reports the stored result's timestamp; it does not re-run the monitor.",
               alternative="Use the dashboard's run button to re-run it."),
    Capability("next_priority", "Show the next priority", "Rank current findings and name the first.",
               CHECK, True),
    Capability("score_plan", "How to raise my score",
               "Split confirmed weaknesses from missing monitoring using the scoring engine.",
               CHECK, True),
    Capability("check_model", "Check local AI", "List local models to see whether the local AI is usable.",
               CHECK, True, verify="Reports what the local endpoint answered just now."),
    Capability("show_fix_steps", "Show me how to fix it",
               "Show the manual steps ARGUS's triage rules give for a finding.",
               GUIDE, True, alternative="ARGUS never runs these steps for you."),
    Capability("verify_finding", "Verify the fix",
               "Check whether a finding is gone from a result newer than when you started.",
               CHECK, True, verify="Requires a monitor result newer than the request."),
    Capability("rerun_monitor", "Re-run this monitor",
               "Queue one extra run of a read-only audit so its stored result is refreshed.",
               PREPARE, False, needs_runner=True,
               permissions="your approval; the scheduler must be running",
               risks="uses some CPU for the length of one audit; changes no setting and no file",
               rollback="not needed; the audit only reads state",
               verify="A stored result newer than the approval with no error.",
               alternative="Press the monitor's run button on the dashboard."),
    Capability("verify_monitor", "Verify the monitor", "Confirm a re-run produced a fresh, valid result.",
               CHECK, True, verify="Compares the stored result's time with the approval time."),
    Capability("system_repair", "Apply a system repair",
               "Change firewall rules, disable security tools, delete files or stop processes.",
               UNAVAILABLE, False,
               alternative="ARGUS shows manual steps; you apply them, then it verifies."),
)}


# ---------------------------------------------------------------- helpers

def _clean(text, limit=220):
    text = " ".join(redact(str(text or "")).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _jobs_label(jobs, job):
    entry = jobs.get(job)
    label = entry[1] if isinstance(entry, (tuple, list)) and len(entry) > 1 else ""
    return _clean(label or job, 60)


def _sev_why(sev):
    return {"critical": "ARGUS rates this critical: it describes something that can seriously harm "
                        "the computer or your data if it is real.",
            "high": "ARGUS rates this high: it deserves attention soon.",
            "medium": "ARGUS rates this medium: worth reviewing, rarely urgent.",
            "low": "ARGUS rates this low: informational."}.get(sev, "ARGUS has not rated this finding.")


def _findings(store, levels=("critical", "high", "medium"), now=None):
    snaps = store.get_snapshots()
    seen, out = set(), []
    for finding, job in triage.current(snaps, levels=levels, acks=acknowledge.load(store), now=now):
        key = (job, finding.get("title"))
        if key not in seen:
            seen.add(key)
            out.append((finding, job))
    out.sort(key=lambda fj: (alert.SEV_RANK.get(fj[0].get("severity"), 9), fj[1]))
    return out


def _blind(result):
    return [b for area in result["areas"] for b in area["blind"]]


_STATE_WORDS = {"missing": "has never reported a result",
                "failing": "its last run failed",
                "stale": "has not reported recently"}


def _cause(error):
    """(plain cause, is_assumption) from a stored error string."""
    e = (error or "").lower()
    if any(k in e for k in ("permission", "access is denied", "denied", "not permitted", "eperm")):
        return "It looks like a permissions problem: the monitor was not allowed to read something it needs.", True
    if any(k in e for k in ("not found", "no such file", "not recognized", "cannot find", "missing module")):
        return "It looks like a required program or file is missing on this computer.", True
    if "timed out" in e or "timeout" in e:
        return "It looks like the monitor took too long to finish and was stopped.", True
    if "not supported" in e or "unsupported" in e:
        return "It looks like this monitor is not supported on this computer.", True
    return "", False


def _section(kind, text):
    return {"kind": kind, "text": text}


def reply(sections, actions=(), offer=None, suggestions=(), extra=None):
    """Uniform response. `sections` kinds: say, verified, recommend, assumption."""
    out = {"answer": "\n\n".join(s["text"] for s in sections), "sections": list(sections),
           "source": "builtin", "actions": list(actions), "offer": offer,
           "suggestions": list(suggestions)}
    out.update(extra or {})
    return out


def _act(action_id, target=None, label=None):
    cap = CAPABILITIES[action_id]
    return {"action": action_id, "label": label or cap.title, "target": target or {}}


# ------------------------------------------------------------- model status

def model_summary(conf=None):
    """Interface-facing model status from the last attempt; makes no network call."""
    state = llm.last_state()
    if state == "unknown":
        return {"state": "unknown", "label": "Local AI has not been checked yet. Basic assistance is working."}
    model = llm.model_name(conf or {})
    return {"state": state, "label": llm.DIAGNOSES.get(state, state).format(model=model)}


# -------------------------------------------------------------- suggestions

def suggestions(store, jobs, now=None):
    out = []
    try:
        result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    except Exception:
        return ["What can you do?", "Am I safe?"]
    if _blind(result):
        out.append("Why is a monitor not working?")
    if _findings(store, now=now):
        out.append("What should I do first?")
    out += ["How do I raise my score?", "Am I safe?"]
    return out[:4]


# ------------------------------------------------------------------ intents

_GREET = re.compile(r"^(hi|hey|hello|yo|hiya|howdy|good (morning|afternoon|evening))\b[\s!.,]*"
                    r"(argus|jarvis|there)?[\s!.?]*$")
_YES = re.compile(r"^(yes|yeah|yep|yup|sure|ok|okay|please|please do|go ahead|do it|y)\b[\s!.]*$")
_NO = re.compile(r"^(no|nope|nah|not now|cancel|stop|never mind|nevermind|n)\b[\s!.]*$")


def classify_intent(q):
    """Deterministic intent for a normalised lowercase question, or None."""
    if _GREET.match(q):
        return "greeting"
    if _YES.match(q):
        return "yes"
    if _NO.match(q):
        return "no"
    has = lambda *ps: any(p in q for p in ps)
    if has("hacked", "compromised", "infected", "am i safe", "is my computer safe", "am i secure",
           "got a virus", "have a virus", "being attacked", "is my computer ok", "is my computer okay",
           "is my system ok", "is my system okay", "is my pc ok", "is everything ok"):
        return "safe"
    if has("explain this finding", "explain this warning", "explain this alert",
           "why is argus", "why am i seeing", "showing this warning", "showing me this"):
        return "warning"
    if has("score mean", "score means", "meaning of my score", "what is the score"):
        return "score_meaning"
    if has("like i'm not technical", "like im not technical", "not technical", "plain english",
           "simple terms", "in simple", "eli5", "explain simply"):
        return "plain"
    if has("what can you do", "what are you able", "what do you do", "your capabilities",
           "can you help", "what can i ask") or q in ("help", "help me", "?"):
        return "capabilities"
    if has("can you fix", "fix it", "fix this", "fix that", "repair it", "can you repair", "fix my"):
        return "fix"
    if re.search(r"(monitor|collector|detector|sensor|watcher|check)s?\b.*(not working|stopped|broken|"
                 r"down|offline|fail|blind|why|not reporting)|(not working|stopped|broken|why|which).*"
                 r"(monitor|collector|detector|sensor|check)s?\b", q):
        return "monitor"
    if has("what does this warning", "what does this alert", "what does that warning",
           "what does this mean", "what does it mean", "what is this warning", "this warning",
           "this alert"):
        return "warning"
    if has("what should i do first", "do first", "most important", "biggest problem", "top priority",
           "what first", "next priority", "attention first", "needs my attention", "safely do next",
           "do next", "what can i safely"):
        return "first"
    if re.search(r"(raise|improve|increase|boost|better|higher|up).{0,20}score|score.{0,20}"
                 r"(better|higher|improve|low|bad)", q):
        return "score"
    if has("retry the model", "retry model", "check the model", "check local ai", "check ollama"):
        return "model"
    return None


def greeting(store, jobs, now=None):
    return reply([_section("say", "Hey! I'm ARGUS, your computer security assistant. I can help you "
                                  "understand your security status, explain alerts, improve your "
                                  "protection, and guide you through fixing problems. What would you "
                                  "like help with?")],
                 suggestions=suggestions(store, jobs, now))


def safe(store, jobs, now=None):
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    serious = _findings(store, ("critical", "high"), now)
    blind = _blind(result)
    secs = []
    if serious:
        top = serious[0][0]
        secs.append(_section("verified", f"ARGUS currently has {len(serious)} serious finding"
                             f"{'s' if len(serious) != 1 else ''}. The most important is "
                             f"“{_clean(top.get('title'), 120)}”. A finding is evidence to review, not "
                             "proof that someone has broken in."))
        offer = {"action": "next_priority", "target": {}}
        q = "Would you like me to walk you through that one first?"
    else:
        secs.append(_section("verified", f"ARGUS has no critical or high-severity findings in the current "
                             f"results of the monitors that are reporting (coverage {result['coverage']}%)."))
        offer, q = None, ""
    if blind:
        secs.append(_section("verified", f"{len(blind)} monitor{'s are' if len(blind) != 1 else ' is'} not "
                             "reporting, so ARGUS may be missing activity there. That is a gap in visibility, "
                             "not evidence of an attack."))
        if offer is None:
            offer = {"action": "check_monitor", "target": {"job": blind[0]["job"]}}
            q = "Would you like me to check why one of them stopped?"
    secs.append(_section("assumption", "No tool can prove a computer is completely clean, and ARGUS "
                         "can only report what its monitors have seen. " + q))
    return reply(secs, _offer_buttons(offer), offer)


def _offer_buttons(offer):
    return [_act(offer["action"], offer["target"])] if offer else []


def first(store, jobs, now=None):
    items = _findings(store, now=now)
    if items:
        finding, job = items[0]
        return _finding_walkthrough(store, finding, job, len(items), now)
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    blind = _blind(result)
    if blind:
        return monitor(store, jobs, now)
    return reply([_section("verified", "Nothing in ARGUS's current results needs your attention. I'll "
                                       "keep watching.")], suggestions=suggestions(store, jobs, now))


def _finding_walkthrough(store, finding, job, total, now):
    c = triage.classify(finding, job)
    sev = finding.get("severity", "?")
    secs = [_section("verified", f"[{sev.upper()}] {_clean(finding.get('title'), 140)} "
                                 f"(found by {_clean(job, 40)}). {_clean(finding.get('detail'))}"),
            _section("verified", _sev_why(sev))]
    if c.get("action"):
        secs.append(_section("recommend", f"ARGUS recommends: {_clean(c['action'], 240)}"))
    acts = [_act("explain_finding", {"id": c["id"]})]
    if c.get("command"):
        acts.append(_act("show_fix_steps", {"id": c["id"], "job": job}))
        secs.append(_section("say", "I can show you the steps. ARGUS does not make this change for you; "
                                    "you apply it, then I verify the result. Want the steps?"))
        offer = {"action": "show_fix_steps", "target": {"id": c["id"], "job": job}}
    else:
        secs.append(_section("say", "Want me to explain it in more detail?"))
        offer = {"action": "explain_finding", "target": {"id": c["id"]}}
    if total > 1:
        acts.append(_act("next_priority", label="Show the next priority"))
    return reply(secs, acts, offer)


def monitor(store, jobs, now=None):
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    blind = _blind(result)
    if not blind:
        return reply([_section("verified", "All of ARGUS's monitors have reported recently. None of them "
                                           "looks stopped right now.")])
    b = blind[0]
    name = _jobs_label(jobs, b["job"])
    more = f" ({len(blind) - 1} more are also not reporting.)" if len(blind) > 1 else ""
    secs = [_section("verified", f"The “{name}” monitor {_STATE_WORDS.get(b['state'], 'is not reporting')}."
                                 f"{more} This does not mean your computer has been attacked, but ARGUS "
                                 "may be missing some activity."),
            _section("say", "Would you like me to check why it stopped working? I'll only read its stored "
                            "result and recent error. I won't run or change anything.")]
    offer = {"action": "check_monitor", "target": {"job": b["job"]}}
    return reply(secs, _offer_buttons(offer), offer)


def capabilities(runner_available):
    groups = {CHECK: [], PREPARE: [], GUIDE: [], UNAVAILABLE: []}
    for cap in CAPABILITIES.values():
        ok, _ = availability(cap, runner_available)
        groups[cap.mode if ok else UNAVAILABLE].append(cap)
    def names(items):
        return ", ".join(c.title.lower() for c in items) or "nothing right now"
    secs = [_section("verified", "Here is what I can actually do:"),
            _section("verified", f"I can check now (read-only): {names(groups[CHECK])}."),
            _section("verified", f"I can prepare for your approval: {names(groups[PREPARE])}."),
            _section("verified", f"I can guide you through manually: {names(groups[GUIDE])}."),
            _section("verified", "Not available: changing firewall rules, disabling security tools, "
                                 "deleting files or stopping processes. I will never do those on my own."
                                 )]
    return reply(secs)


def availability(cap, runner_available):
    if cap.mode == UNAVAILABLE:
        return False, "ARGUS does not change system settings from chat."
    if cap.needs_runner and not runner_available:
        return False, "The ARGUS service is not running, so it cannot queue the audit."
    return True, ""


def plain(store, jobs, now=None):
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    serious = len(_findings(store, ("critical", "high"), now))
    blind = len(_blind(result))
    secs = [_section("say", "Think of ARGUS as a set of smoke detectors for your computer."),
            _section("verified", f"Right now {serious} thing{'s' if serious != 1 else ''} ARGUS rates as "
                                 f"serious {'need' if serious != 1 else 'needs'} a look, and {blind} "
                                 f"detector{'s are' if blind != 1 else ' is'} not reporting. Your score is "
                                 f"{result['score']}%."),
            _section("say", "Ask “what should I do first?” and I'll explain the most important item "
                            "step by step.")]
    return reply(secs, [_act("next_priority")], {"action": "next_priority", "target": {}})


def fix(store, jobs, runner_available, now=None):
    items = _findings(store, now=now)
    if items:
        finding, job = items[0]
        c = triage.classify(finding, job)
        secs = [_section("verified", "I can't change your system settings, firewall or files from chat, "
                                     "and I won't pretend to. For the top finding, "
                                     f"“{_clean(finding.get('title'), 120)}”, here is what I can do:")]
        if c.get("command"):
            secs.append(_section("say", "I can show you the exact manual steps, then verify the result "
                                        "after you apply them."))
            offer = {"action": "show_fix_steps", "target": {"id": c["id"], "job": job}}
            return reply(secs, _offer_buttons(offer), offer)
        secs.append(_section("say", "ARGUS has no specific steps for this one yet. I can explain what it "
                                    "found so you can decide."))
        offer = {"action": "explain_finding", "target": {"id": c["id"]}}
        return reply(secs, _offer_buttons(offer), offer)
    return monitor(store, jobs, now)


def score_advice(store, jobs, now=None):
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    # Same-title findings (e.g. two WMI subscriptions) are one line with a
    # count, so the top three are three different problems, not one repeated.
    grouped = {}
    for step in result.get("next_steps", []):
        key = (step["severity"], step["title"])
        grouped.setdefault(key, dict(step, count=0))["count"] += 1
    steps = list(grouped.values())[:3]
    blind = _blind(result)
    secs = [_section("say", "I can help you improve your security score. Your score is "
                            f"{result['score']}% ({result['grade']}) with {result['coverage']}% monitoring "
                            "coverage. I'll start with the biggest verified weaknesses.")]
    offer = None
    if steps:
        lines = [f"{i}. {s['severity'].upper()}: {_clean(s['title'], 120)}"
                 + (f" ({s['count']} found)" if s["count"] > 1 else "")
                 for i, s in enumerate(steps, 1)]
        secs.append(_section("verified", "Confirmed weaknesses, biggest first:\n" + "\n".join(lines)))
        top = next(((f, j) for f, j in _findings(store, now=now)
                    if f.get("title") == steps[0]["title"]), None)
        if top:
            offer = {"action": "show_fix_steps" if triage.classify(*top).get("command")
                     else "explain_finding",
                     "target": {"id": triage.classify(*top)["id"], "job": top[1]}}
    else:
        secs.append(_section("verified", "ARGUS has no confirmed weaknesses lowering the score right now."))
    if blind:
        secs.append(_section("verified", f"{len(blind)} monitor{'s are' if len(blind) != 1 else ' is'} not "
                             "reporting. That lowers coverage, not proof of infection; restoring "
                             "them only raises the score if their results come back clean."))
        if offer is None:
            offer = {"action": "check_monitor", "target": {"job": blind[0]["job"]}}
    secs.append(_section("say", "I will not hide, downgrade or suppress anything to raise the number. "
                                "The score changes only when a fresh check confirms the underlying issue "
                                "is fixed. Want me to start with the first one?"))
    return reply(secs, _offer_buttons(offer), offer)


def score_meaning(store, jobs, now=None):
    """What the number means, in the engine's own terms (see reporting/score.py)."""
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    blind = _blind(result)
    secs = [_section("verified", f"Your security score is {result['score']}% ({result['grade']}), with "
                                 f"{result['coverage']}% of ARGUS-1's monitoring coverage reporting."),
            _section("say", "How it works: each protection area loses points for its open findings, "
                            "more for critical and high ones. Low-severity items are inventory and do not "
                            "lower it."),
            _section("say", "A check that is failing, stale or has never run is not counted as safe. It "
                            "is shown as unverified and pulls the score down in proportion to how much "
                            "of the computer is unobserved.")]
    if blind:
        secs.append(_section("verified", f"Right now {len(blind)} check{'s are' if len(blind) != 1 else ' is'} "
                                         "not reporting, so part of this score reflects missing "
                                         "visibility rather than known problems."))
    secs.append(_section("assumption", "A low score is not proof of an attack, and a high score is not "
                                       "proof of safety. The score only reflects what ARGUS-1 could check."))
    offer = {"action": "score_plan", "target": {}}
    secs.append(_section("say", "Want me to show what would raise it?"))
    return reply(secs, [_act("score_plan", label="How do I raise my score?")], offer)


def clarify(store, jobs, model_note=True, now=None):
    secs = [_section("say", "I'm not sure I understood that, and I don't want to guess about your "
                            "security. Are you asking about your overall status, a specific warning, "
                            "or how to improve your score?")]
    return reply(secs, suggestions=suggestions(store, jobs, now))


# ------------------------------------------------------------ action handlers

def _snapshot(store, job):
    return store.get_snapshots().get(job)


def _fmt(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "never"


def _check_monitor(store, jobs, target, runner_available, now):
    job = target.get("job")
    snap = _snapshot(store, job)
    name = _jobs_label(jobs, job)
    secs = [_section("verified", "I read the stored result of its last run. I did not run it again.")]
    if not snap or not snap.get("ts"):
        secs.append(_section("verified", f"The “{name}” monitor has no stored result: it has never "
                                         "completed on this computer."))
    else:
        age = int((now or time.time()) - int(snap["ts"]))
        interval = jobs[job][0]
        state = ("failing" if snap.get("error") else
                 "stale" if age > max(interval * 2, interval + 300) else "current")
        secs.append(_section("verified", f"Last result: {_fmt(snap['ts'])} ({age // 60} min ago; it is "
                                         f"expected about every {max(1, interval // 60)} min). "
                                         f"Status: {state}."))
        if snap.get("error"):
            secs.append(_section("verified", f"Recorded error: {_clean(snap['error'], 200)}"))
            cause, guess = _cause(snap["error"])
            if cause:
                secs.append(_section("assumption", cause))
    actions = []
    cap = CAPABILITIES["rerun_monitor"]
    if availability(cap, runner_available)[0]:
        secs.append(_section("say", "I can re-run it once with your approval. Want me to prepare that?"))
        actions.append(_act("rerun_monitor", {"job": job}))
        offer = {"action": "rerun_monitor", "target": {"job": job}}
    else:
        secs.append(_section("say", "The ARGUS service isn't running, so I can't re-run it from here. "
                                    "Start the service or press the monitor's run button."))
        offer = None
    return reply(secs, actions, offer)


def _explain_finding(store, target):
    hit = acknowledge.resolve(store.get_snapshots(), target.get("id", ""))
    if not hit:
        return reply([_section("verified", "That finding is no longer in the current results.")])
    finding, job = hit
    c = triage.classify(finding, job)
    secs = [_section("verified", f"[{finding.get('severity', '?').upper()}] "
                                 f"{_clean(finding.get('title'), 140)} (found by {_clean(job, 40)})"),
            _section("verified", _clean(finding.get("detail") or "No detail was recorded.", 400)
                     + f" Observed at: {_clean(finding.get('where') or 'unspecified', 160)}."),
            _section("verified", _sev_why(finding.get("severity"))),
            _section("assumption", "This is evidence to review. It is not proof that your computer is "
                                   "compromised.")]
    acts = [_act("show_fix_steps", {"id": c["id"], "job": job})] if c.get("command") else []
    return reply(secs, acts, {"action": "show_fix_steps", "target": {"id": c["id"], "job": job}}
                 if acts else None)


def _show_fix_steps(store, target, now):
    hit = acknowledge.resolve(store.get_snapshots(), target.get("id", ""))
    if not hit:
        return reply([_section("verified", "That finding is no longer in the current results.")])
    finding, job = hit
    c = triage.classify(finding, job)
    if not c.get("command"):
        return reply([_section("verified", "ARGUS has no specific steps for this finding.")])
    secs = [_section("recommend", f"{_clean(c.get('action') or 'Suggested step', 240)}"),
            _section("recommend", f"Command: {_clean(c['command'], 300)}"),
            _section("say", "ARGUS will not run this for you. Side effects depend on the command, so read "
                            "it first. When you've done it, press “Verify the fix” and I'll check a "
                            "fresh result.")]
    since = int(now or time.time())
    return reply(secs, [_act("verify_finding", {"id": c["id"], "job": job, "since": since})])


def _verify_finding(store, jobs, target, now):
    job, fid, since = target.get("job"), target.get("id"), int(target.get("since") or 0)
    snap = _snapshot(store, job)
    if not snap or not snap.get("ts") or int(snap["ts"]) <= since or snap.get("error"):
        why = ("has not produced a result since you started" if snap and not snap.get("error") else
               "has no valid result")
        return reply([_section("verified", f"I can't confirm it yet: the “{_jobs_label(jobs, job)}” monitor "
                                           f"{why}. A fix only counts once a fresh check confirms it.")],
                     [_act("rerun_monitor", {"job": job})] if job in jobs else [])
    still = any(isinstance(f, dict) and acknowledge.finding_id(f, job) == fid
                for f in snap.get("findings") or [])
    if still:
        return reply([_section("verified", f"Checked at {_fmt(snap['ts'])}: the finding is still present, "
                                           "so it is not fixed yet.")])
    return reply([_section("verified", f"Verified: a result from {_fmt(snap['ts'])} (after your "
                                       "request) no longer contains this finding.")])


def _verify_monitor(store, jobs, target):
    job, since = target.get("job"), int(target.get("since") or 0)
    snap = _snapshot(store, job)
    name = _jobs_label(jobs, job)
    if not snap or not snap.get("ts") or int(snap["ts"]) <= since:
        return reply([_section("verified", f"Not confirmed: the “{name}” monitor has not stored a new "
                                           "result since you approved the re-run. It may still be queued. "
                                           "Ask me to verify again shortly.")],
                     [_act("verify_monitor", {"job": job, "since": since})])
    if snap.get("error"):
        cause, _ = _cause(snap["error"])
        secs = [_section("verified", f"The monitor ran at {_fmt(snap['ts'])} but failed: "
                                     f"{_clean(snap['error'], 200)}")]
        if cause:
            secs.append(_section("assumption", cause))
        return reply(secs)
    return reply([_section("verified", f"Recovered: the “{name}” monitor stored a fresh, error-free result "
                                       f"at {_fmt(snap['ts'])}.")])


def _check_model(conf):
    llm.reset_backoff()
    d = llm.diagnose(conf or {})
    return reply([_section("verified", d["label"])],
                 extra={"model": {"state": d["state"], "label": d["label"]}})


# ------------------------------------------------------------ audit/approval

def _load(store, key, default):
    try:
        value = json.loads(store.get_meta(key, "") or "")
        return value if isinstance(value, type(default)) else default
    except ValueError:
        return default


def audit_log(store):
    return _load(store, _AUDIT_KEY, [])


def _audit(store, op, action, target, outcome, detail="", now=None):
    log = audit_log(store)
    entry = {"ts": int(now or time.time()), "op": op, "action": action, "target": target,
             "outcome": outcome, "detail": _clean(detail, 200)}
    last = log[-1] if log else None
    # Polling "verify" while a re-run is still queued would otherwise fill the
    # trail with identical rows. Repeats of the same read-only result collapse
    # into one entry (latest time, repeat count); every state change is kept.
    if (op == "run" and last and last.get("op") == "run" and last.get("action") == action
            and last.get("target") == target and last.get("outcome") == outcome):
        entry["repeats"] = int(last.get("repeats", 1)) + 1
        entry["first_ts"] = last.get("first_ts", last["ts"])
        log.pop()
    log.append(entry)
    store.set_meta(_AUDIT_KEY, json.dumps(log[-_AUDIT_MAX:]))


def _valid_target(cap, target, jobs):
    if not isinstance(target, dict):
        return None
    out = {}
    if "job" in target:
        if target["job"] not in jobs:
            return None
        out["job"] = target["job"]
    if "id" in target:
        if not _FID.match(str(target["id"])):
            return None
        out["id"] = str(target["id"])
    for k in ("since",):
        if k in target:
            try:
                out[k] = int(target[k])
            except (TypeError, ValueError):
                return None
    needs_job = cap.id in ("check_monitor", "rerun_monitor", "verify_monitor", "verify_finding")
    needs_id = cap.id in ("explain_finding", "show_fix_steps", "verify_finding")
    if (needs_job and "job" not in out) or (needs_id and "id" not in out):
        return None
    return out


def _refuse(store, op, action, target, why, now):
    _audit(store, op, action, target if isinstance(target, dict) else {}, "denied", why, now)
    return reply([_section("verified", why)], extra={"ok": False, "state": "denied"})


def handle_action(store, jobs, op, action=None, target=None, token=None, runner=None, conf=None,
                  now=None):
    """The only entry point that can cause anything to happen. -> reply dict.

    `runner(job) -> bool` queues one audit; it is injected by the service layer
    and is None when no scheduler is running.
    """
    now = int(now or time.time())
    runner_available = runner is not None
    if op in ("approve", "cancel"):
        return _resolve_proposal(store, jobs, op, token, runner, now)
    cap = CAPABILITIES.get(str(action))
    if cap is None:
        return _refuse(store, op, str(action)[:40], {}, "That is not an action ARGUS supports.", now)
    ok, why = availability(cap, runner_available)
    if not ok:
        return _refuse(store, op, cap.id, {}, why, now)
    clean = _valid_target(cap, target or {}, jobs)
    if clean is None:
        return _refuse(store, op, cap.id, {}, "That request did not name a valid target.", now)
    if op == "propose":
        if cap.mode != PREPARE:
            return _refuse(store, op, cap.id, clean, "That action does not need approval.", now)
        return _propose(store, jobs, cap, clean, now)
    if op != "run" or cap.mode == PREPARE:
        return _refuse(store, op, cap.id, clean,
                       "That action changes something, so it must be proposed and approved first.", now)
    handlers = {
        "explain_finding": lambda: _explain_finding(store, clean),
        "check_monitor": lambda: _check_monitor(store, jobs, clean, runner_available, now),
        "next_priority": lambda: first(store, jobs, now),
        "score_plan": lambda: score_advice(store, jobs, now),
        "check_model": lambda: _check_model(conf),
        "show_fix_steps": lambda: _show_fix_steps(store, clean, now),
        "verify_finding": lambda: _verify_finding(store, jobs, clean, now),
        "verify_monitor": lambda: _verify_monitor(store, jobs, clean),
    }
    result = handlers[cap.id]()
    if cap.id in ("verify_finding", "verify_monitor"):
        _audit(store, op, cap.id, clean, "verified" if result["answer"].startswith(
            ("Verified", "Recovered", "Checked")) and "still present" not in result["answer"]
            else "not_verified", result["answer"], now)
    result.update(ok=True, state="done")
    return result


def _propose(store, jobs, cap, target, now):
    pending = {t: p for t, p in _load(store, _PENDING_KEY, {}).items() if p.get("expires", 0) > now}
    token = secrets.token_urlsafe(9)
    pending[token] = {"action": cap.id, "target": target, "expires": now + PROPOSAL_TTL_S}
    for old in sorted(pending, key=lambda t: pending[t]["expires"])[:-_PENDING_MAX]:
        del pending[old]
    store.set_meta(_PENDING_KEY, json.dumps(pending))
    _audit(store, "propose", cap.id, target, "proposed", "", now)
    name = _jobs_label(jobs, target["job"])
    secs = [_section("recommend", f"Proposed: {cap.purpose} Monitor: “{name}”."),
            _section("verified", f"Needs: {cap.permissions}. Risk: {cap.risks}. Rollback: {cap.rollback}. "
                                 f"I will verify by: {cap.verify}"),
            _section("say", "Nothing has happened yet. Do you approve?")]
    return reply(secs, [{"action": "approve", "label": "Approve", "target": {}, "token": token},
                        {"action": "cancel", "label": "Cancel", "target": {}, "token": token}],
                 extra={"ok": True, "state": "proposed", "token": token})


def _resolve_proposal(store, jobs, op, token, runner, now):
    pending = _load(store, _PENDING_KEY, {})
    prop = pending.pop(str(token), None)
    store.set_meta(_PENDING_KEY, json.dumps(pending))
    if not prop or prop.get("expires", 0) <= now:
        return _refuse(store, op, "", {}, "That proposal has expired or was already used. Nothing was "
                                          "changed.", now)
    cap, target = CAPABILITIES.get(prop["action"]), prop["target"]
    if op == "cancel":
        _audit(store, "cancel", prop["action"], target, "cancelled", "", now)
        return reply([_section("verified", "Cancelled. Nothing was changed.")],
                     extra={"ok": True, "state": "cancelled"})
    ok, why = availability(cap, runner is not None)
    if not ok:
        return _refuse(store, op, cap.id, target, why + " Nothing was changed.", now)
    try:
        queued = bool(runner(target["job"]))
    except Exception:
        queued = False
    if not queued:
        _audit(store, "approve", cap.id, target, "failed", "runner refused", now)
        return reply([_section("verified", "I could not queue the re-run, so nothing happened.")],
                     extra={"ok": False, "state": "failed"})
    _audit(store, "approve", cap.id, target, "queued", "", now)
    return reply([_section("verified", "Approved and queued. It has not finished yet, so I can't tell you "
                                       "whether it worked."),
                  _section("say", "ARGUS runs audits one at a time, so this may wait behind others, "
                                  "sometimes several minutes. Ask me to verify later and I'll check "
                                  "for a fresh result.")],
                 [_act("verify_monitor", {"job": target["job"], "since": now})],
                 extra={"ok": True, "state": "queued"})


# ------------------------------------------------------------------ routing

def route(store, jobs, q, offer=None, runner_available=False, now=None, conf=None):
    """Answer a normalised question deterministically, or None if not understood."""
    intent = classify_intent(q)
    if intent is None:
        return None
    if intent == "greeting":
        return greeting(store, jobs, now)
    if intent in ("yes", "no"):
        if intent == "no":
            return reply([_section("say", "No problem. Ask me anything else whenever you like.")],
                         suggestions=suggestions(store, jobs, now))
        if not isinstance(offer, dict):
            return reply([_section("say", "Happy to help. What would you like me to do?")],
                         suggestions=suggestions(store, jobs, now))
        action, target = offer.get("action"), offer.get("target")
        cap = CAPABILITIES.get(str(action))
        if cap is None:
            return None
        # "yes" is consent to the offered step only; a change still gets its
        # own proposal and approval.
        return {"_run": True, "op": "propose" if cap.mode == PREPARE else "run",
                "action": action, "target": target}
    return {"score_meaning": lambda: score_meaning(store, jobs, now),
            "safe": lambda: safe(store, jobs, now), "plain": lambda: plain(store, jobs, now),
            "capabilities": lambda: capabilities(runner_available), "monitor": lambda: monitor(store, jobs, now),
            "fix": lambda: fix(store, jobs, runner_available, now), "first": lambda: first(store, jobs, now),
            "warning": lambda: first(store, jobs, now), "score": lambda: score_advice(store, jobs, now),
            "model": lambda: _check_model(conf)}[intent]()
