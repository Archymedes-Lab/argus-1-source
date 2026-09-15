"""`jarvis defend` and `jarvis answer` — the autonomous-response controls.

    jarvis defend                 what JARVIS did, and what is waiting for you
    jarvis defend approve <id>    run a proposed containment action now
    jarvis defend undo <id>       reverse an action JARVIS took
    jarvis defend actions         the actions available and whether they are on
    jarvis answer <id> yes|no     answer a proactive question

Turning automatic response on is a config change (autonomous_defense plus the
per-action flags in ~/.jarvis/config.json); this command never edits config,
so nothing starts acting on its own without an explicit edit.
"""


from jarvis.core.util import iso
from jarvis.response import alert, defense, questions
from jarvis.response.actions import base

from ..output import color, is_tty


def cmd_defend(store, args):
    t = is_tty()
    sub = args.action_arg

    if sub == "approve":
        ok, detail = defense.approve(store, args.id)
        print(("approved: " if ok else "not approved: ") + detail)
        return 0 if ok else 1
    if sub == "undo":
        ok, detail = defense.undo(store, args.id)
        print(("undone: " if ok else "could not undo: ") + detail)
        return 0 if ok else 1
    if sub == "actions":
        conf = alert.load_conf()
        on = conf.get("autonomous_defense", False) is True
        print(f"autonomous response: {'ON' if on else 'OFF'} "
              f"(set autonomous_defense in ~/.jarvis/config.json)")
        for a in base.registry().values():
            enabled = on and a.enable_flag and conf.get(a.enable_flag, False) is True
            mark = color("auto", "ok", t) if enabled else "propose-only"
            print(f"  {a.id:18} [{a.host}] {a.title} — {mark}"
                  + (f"  (enable: {a.enable_flag}=true)" if a.enable_flag else ""))
        return 0

    ledger = defense.load(store)
    applied = {k: v for k, v in ledger.items() if v.get("status") == "applied"}
    proposed = {k: v for k, v in ledger.items() if v.get("status") == "proposed"}

    if proposed:
        print(color("\nWAITING FOR YOU — proposed containment", "bold", t))
        for eid, e in sorted(proposed.items(), key=lambda kv: kv[1].get("at", 0), reverse=True):
            print(f"  {eid}  {e['title']}")
            print(f"        {e.get('preview', '')}")
            print(f"        approve: jarvis defend approve {eid}")
    if applied:
        print(color("\nJARVIS ACTED — reversible, undo any of these", "bold", t))
        for eid, e in sorted(applied.items(), key=lambda kv: kv[1].get("at", 0), reverse=True):
            print(f"  {eid}  {e['title']} — {e.get('detail', '')}  ({iso(e.get('at', 0))})")
            print(f"        undo: jarvis defend undo {eid}")
    if not proposed and not applied:
        print("no automatic actions taken and nothing waiting.")
        print("see what is available with: jarvis defend actions")
    return 0


def cmd_answer(store, args):
    if not args.qid:
        open_q = questions.build(store, store.get_snapshots(), alert.load_conf())
        if not open_q:
            print("no open questions.")
            return 0
        print(color(f"{len(open_q)} question(s) for you"
                    + (f"; showing the top {min(15, len(open_q))}" if len(open_q) > 15 else "")
                    + ":\n", "bold", is_tty()))
        for q in open_q[:15]:
            print(f"  {q['id']}  [{(q['severity'] or '').upper()}] {q['prompt']}")
            print(f"        yes → {q['yes']}")
            print(f"        no  → {q['no']}")
            print(f"        {q['answer_cmd']}\n")
        return 0
    ok, message = questions.answer(store, args.qid, args.choice)
    print(message)
    return 0 if ok else 1


def add_parser(sub):
    p = sub.add_parser("defend", help="autonomous response: what JARVIS did and what awaits you")
    p.add_argument("action_arg", nargs="?", choices=["approve", "undo", "actions"],
                   help="approve or undo an action, or list available actions")
    p.add_argument("id", nargs="?", help="the action id (for approve/undo)")
    p.set_defaults(fn=lambda args, store: cmd_defend(store, args))

    a = sub.add_parser("answer", help="answer a proactive question (jarvis answer <id> yes|no)")
    a.add_argument("qid", nargs="?", help="the question id")
    a.add_argument("choice", nargs="?", default="", help="yes or no")
    a.set_defaults(fn=lambda args, store: cmd_answer(store, args))
    return p


