"""The emails JARVIS sends, as a plain-text part and an HTML part.

Every message answers the same question first — what needs you, and what is
JARVIS already handling — before it says anything else. The grouping comes
from triage.py; the HTML comes from email_ui.py; the plain-text part carries
the same structure for clients that do not render HTML.
"""

import time

from jarvis.response import acknowledge, alert, protocols

from . import email_ui as ui
from . import score, triage, voice

RULE = "─" * 58


# ── plain text ────────────────────────────────────────────────────────────

def _text_health(result, delta):
    return score.summary_lines(result, delta)


def _text_group(owner, entries, limit=25):
    if not entries:
        return []
    lines = ["", RULE, f"{triage.LABEL[owner].upper()} ({len(entries)})",
             f"  {triage.BLURB[owner]}", RULE]
    for n, (f, job, t, tag) in enumerate(entries[:limit], 1):
        lines.append(f"{n}. [{(f.get('severity') or '?').upper()}]"
                     + (f" {tag}:" if tag else "") + f" {f.get('title', '')}")
        if f.get("detail"):
            lines.append(f"   {f['detail'][:300]}")
        lines.append(f"   → {t['action']}")
        if t.get("command"):
            lines.append(f"   $ {t['command']}")
        if owner == triage.YOU_CONFIRM and t.get("id"):
            lines.append(f"   if this was you: jarvis ack {t['id']} --reason \"…\"")
        meta = " · ".join(x for x in (job, f.get("host"), f.get("where")) if x)
        if meta:
            lines.append(f"   ({meta})")
    if len(entries) > limit:
        lines.append(f"   … and {len(entries) - limit} more on the dashboard")
    return lines


def _grouped(entries):
    """entries: [(finding, job, tag)] -> {owner: [(finding, job, triage, tag)]}"""
    out = {owner: [] for owner in triage.ORDER}
    for f, job, tag in entries:
        t = triage.classify(f, job)
        out[t["owner"]].append((f, job, t, tag))
    for owner in out:
        out[owner].sort(key=lambda e: alert.SEV_RANK.get(e[0].get("severity"), 9))
    return out


def _counts(grouped):
    return {owner: len(items) for owner, items in grouped.items()}


def _needs_you(counts):
    return counts.get(triage.YOU_DO, 0) + counts.get(triage.YOU_CONFIRM, 0)


# ── change digest / priority changes ──────────────────────────────────────

def digest(ordered, urgent, health, delta, now, conf=None):
    """ordered: [(key, queue item)] -> (subject, text, html)."""
    active = [(item["finding"], item["job"], item["tag"]) for _key, item in ordered
              if item["tag"] != "RESOLVED"]
    resolved = [item for _key, item in ordered if item["tag"] == "RESOLVED"]
    grouped = _grouped(active)
    counts = _counts(grouped)

    kind = "priority changes" if urgent else "change digest"
    need = _needs_you(counts)
    headline = (f"{need} need{'s' if need == 1 else ''} you" if need
                else "nothing needs you")
    subject = f"[JARVIS] {kind}: {len(ordered)} update(s) — {headline}"
    line, by_model = voice.opener(conf, voice.facts_for(
        "change digest", counts, urgent, health, delta, len(resolved),
        [f.get("title") for f, _job, _tag in active]),
        time.strftime("%Y-%m-%d", time.localtime(now)))

    text = ["JARVIS PRIORITY CHANGES" if urgent else "JARVIS CHANGE DIGEST",
            f"{need} need you · {counts[triage.JARVIS]} handled by JARVIS"
            + (f" · {len(resolved)} no longer observed" if resolved else ""), "", line, ""]
    if health:
        text += _text_health(health, delta)
    for owner in triage.ORDER:
        text += _text_group(owner, grouped[owner])
    if resolved:
        text += ["", RULE, f"NO LONGER OBSERVED ({len(resolved)})",
                 "  Absent from the latest collector result; this alone does not prove "
                 "remediation.", RULE]
        text += [f"- {item['finding'].get('title', '')} ({item['job']})" for item in resolved]
    text += ["", "Unchanged findings stay on the dashboard and in the daily advisory; "
                 "they do not generate repeat emails."]

    for owner in triage.ORDER:
        for f, job, t, tag in grouped[owner]:
            item = next(i for _k, i in ordered if i["finding"] is f)
            if tag == "ESCALATED":
                hours = (now - item["first"]) // 3600
                grouped[owner][grouped[owner].index((f, job, t, tag))] = (
                    f, job, t, f"escalated · {hours}h open")

    inner = ui.header("JARVIS · " + ("priority changes" if urgent else "change digest"),
                      headline[0].upper() + headline[1:],
                      time.strftime("%A %d %B, %H:%M", time.localtime(now)))
    inner += ui.voice(line, by_model)
    inner += ui.section(ui.owner_summary(counts), "px-5 pt-5 pb-1")
    for owner in triage.ORDER:
        inner += ui.owner_section(owner, grouped[owner])
    if resolved:
        rows = "".join(
            f'<div {ui.tw("text-sm text-slate-700 py-1")}>&#10003; {ui.esc(i["finding"].get("title"))} '
            f'<span {ui.tw("text-slate-400")}>({ui.esc(i["job"])})</span></div>' for i in resolved)
        inner += ui.section(ui.heading("No longer observed",
                                       "Absent from the latest result; that alone does not prove a fix.")
                            + f'<div {ui.tw("mt-2")}>{rows}</div>')
    if health:
        inner += ui.section(ui.health_panel(health, delta), "px-6 py-5 bg-slate-50")
    inner += ui.footer("Unchanged findings stay on the dashboard and in the daily advisory; "
                       "they do not generate repeat emails. Credential values are never included.")
    html = ui.document(subject, line, inner)
    return subject, "\n".join(text) + "\n", html


# ── daily security health ─────────────────────────────────────────────────

def health(result, delta, snapshots, now, store=None, conf=None, protocol_state=()):
    """-> (subject, text, html) for the once-a-day health email.

    `protocol_state` is protocols.evaluate(): today's protocol is carried in
    full, steps included, because mail is where you read it."""
    # The daily email is a to-do list, not an inventory: critical and high only,
    # one entry per distinct finding. Mediums are counted, not listed.
    acks = acknowledge.load(store) if store is not None else {}
    seen, top = set(), []
    for f, job in triage.current(snapshots, levels=("critical", "high"), acks=acks, now=now):
        key = (job, f.get("title"))
        if key not in seen:
            seen.add(key)
            top.append((f, job, ""))
    lower = len(triage.current(snapshots, levels=("medium",), acks=acks, now=now))
    grouped = _grouped(top)
    counts = _counts(grouped)
    need = _needs_you(counts)
    trend = "" if not delta else f" ({'+' if delta > 0 else ''}{delta})"
    subject = (f"[JARVIS] security health {result['score']}% — {result['grade']}{trend} · "
               f"{need} need you")
    line, by_model = voice.opener(conf, voice.facts_for(
        "daily security health", counts, False, result, delta,
        top=[f.get("title") for f, _job, _tag in top]),
        time.strftime("%Y-%m-%d", time.localtime(now)))

    text = ["JARVIS SECURITY HEALTH",
            f"{need} need you · {counts[triage.JARVIS]} handled by JARVIS", "", line, ""]
    text += _text_health(result, delta)
    for owner in triage.ORDER:
        text += _text_group(owner, grouped[owner], limit=10)
    briefing = protocols.pick_next(protocol_state)
    brief_lines = protocols.email_lines(briefing, protocol_state) if briefing else []
    if brief_lines:
        text += ["", RULE, "TODAY'S PROTOCOL", RULE, *brief_lines]
    text += ["", f"Plus {lower} medium-severity findings on the dashboard.",
             "Every finding and its history: the local JARVIS dashboard."]

    inner = ui.header("JARVIS · daily security health",
                      f"Your system is {result['score']}% of the way to secure",
                      time.strftime("%A %d %B", time.localtime(now)))
    inner += ui.voice(line, by_model)
    inner += ui.section(ui.health_panel(result, delta))
    inner += ui.section(ui.owner_summary(counts, result.get("acknowledged", 0)), "px-5 pt-1 pb-1")
    for owner in triage.ORDER:
        inner += ui.owner_section(owner, grouped[owner], limit=8, show_detail=False)
    if brief_lines:
        inner += ui.briefing(brief_lines)
    if lower:
        inner += ui.section(f'<div {ui.tw("text-sm text-slate-500")}>Plus {lower} medium-severity '
                            f'findings, listed on the dashboard rather than here.</div>', "px-6 pb-5")
    inner += ui.footer("Fixing items under “Needs you — action” raises the score the most. "
                       "Every finding and its history: the local JARVIS dashboard. "
                       "Set health_email_enabled to false to stop this email.")
    return subject, "\n".join(text) + "\n", ui.document(subject, line, inner)


def health_email(store, conf, now=None, jobs=None):
    """Send the daily health email. Returns an error string, or "" on success."""
    result = score.latest(store)
    if result is None:
        return "no security score recorded yet"
    now = int(time.time() if now is None else now)
    state = protocols.evaluate(store, jobs, now) if jobs else ()
    subject, text, html = health(result, score.change_since(store, 86400, now),
                                 store.get_snapshots(), now, store, conf, state)
    return alert.send_email(conf, subject, text, html=html)


# ── the action plan: everything that needs your hands ─────────────────────

def action_plan(result, protocol_state, snapshots, now, store=None, conf=None, delta=None):
    """-> (subject, text, html, personalized) for the on-request action plan email.

    Every open protocol in the order it has to happen, each with its full
    hand-written steps, then the other critical and high findings only you can
    act on. The local model writes the opening note and one line per task on
    why it matters; each is checked before use, and the steps are never its.
    `personalized` counts the lines the model wrote that passed.
    """
    tasks = [i for i in protocol_state
             if i["state"] in (protocols.READY, protocols.WAITING, protocols.BLOCKED)]
    acks = acknowledge.load(store) if store is not None else {}
    others, seen = [], set()
    for f, job in triage.current(snapshots, levels=("critical", "high"), acks=acks, now=now):
        if (job, f.get("title")) in seen or any(i["protocol"].fixes(job, f) for i in tasks):
            continue
        seen.add((job, f.get("title")))
        others.append((f, job, ""))
    others = _grouped(others)[triage.YOU_DO]

    total = len(tasks) + len(others)
    subject = f"[JARVIS] your action plan — {total} thing{'s' if total != 1 else ''} need your hands"
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    line, by_model = voice.opener(conf, voice.facts_for(
        "action plan", {triage.YOU_DO: total}, False, result, delta,
        top=[i["protocol"].title for i in tasks]), day)
    personalized = int(by_model)

    text = ["JARVIS ACTION PLAN", f"{len(tasks)} protocol(s) in order, then "
            f"{len(others)} other matter(s) for your hands", "", line, ""]
    inner = ui.header("JARVIS · action plan", "What needs your hands, in order",
                      time.strftime("%A %d %B", time.localtime(now)))
    inner += ui.voice(line, by_model)

    for n, item in enumerate(tasks, 1):
        note, note_by_model = voice.task_note(conf, item)
        personalized += int(note_by_model)
        lines = protocols.email_lines(item)
        lines[0] = f"Task {n} · {lines[0]}"
        lines[1] = note
        text += [RULE, lines[0], (f"[local model] {note}" if note_by_model else note),
                 *lines[2:], ""]
        inner += ui.briefing(lines, model_note=note_by_model)

    if others:
        text += _text_group(triage.YOU_DO, others, limit=15)
        inner += ui.owner_section(triage.YOU_DO, others, limit=15)

    footer = ("The steps are written by hand; only the italic notes marked \u201clocal model\u201d "
              "come from the model. After each task, run jarvis brief check <task> — a task counts as done "
              "only when a fresh scan agrees.")
    text += ["", footer]
    inner += ui.footer(footer)
    return subject, "\n".join(text) + "\n", ui.document(subject, line, inner), personalized


def action_plan_email(store, conf, jobs, now=None):
    """Build and send the action plan. -> (error or "", subject, personalized lines)."""
    now = int(time.time() if now is None else now)
    result = score.latest(store) or score.compute(store.get_snapshots(), jobs, now,
                                                  acknowledge.load(store))
    subject, text, html, personalized = action_plan(
        result, protocols.evaluate(store, jobs, now), store.get_snapshots(), now, store, conf,
        score.change_since(store, 86400, now))
    return alert.send_email(conf, subject, text, html=html), subject, personalized
