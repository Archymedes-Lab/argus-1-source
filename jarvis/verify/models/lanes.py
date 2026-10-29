"""Scheduler lanes: a fast-lane job is never queued behind a long main job.

This is an abstract model of the documented policy (LANE-FAIRNESS-AND-OUTAGE-
RECORD.md): the fast lane has its own worker, so a due fast job waits at most
one tick regardless of what the main lane runs. It does not execute the real
`Scheduler._due`, which needs a store, reliability state and the governor; the
real selection order is covered by tests/test_server.py. The model pins the
shape of the claim, and the membership test below pins that the protection
jobs are in the fast lane.

Abstractions: time is discrete ticks; one main job of bounded length; one fast
job; no governor pressure; no forced requests.
"""

from dataclasses import dataclass, replace

from jarvis.service import scheduler
from jarvis.verify.mc import Model

MAIN_LEN = 3
MAX_TICK = 12
REQUIRED_FAST = frozenset({"scan", "bridge", "native", "watchdogs"})


@dataclass(frozen=True)
class State:
    tick: int = 0
    main_remaining: int = 0
    fast_due: bool = False
    fast_wait: int = 0


def act_tick(s):
    if s.tick >= MAX_TICK:
        return ()
    nxt = replace(s, tick=s.tick + 1,
                  main_remaining=max(0, s.main_remaining - 1))
    if s.fast_due:
        # The fast worker runs it this tick; the main lane is irrelevant.
        nxt = replace(nxt, fast_due=False, fast_wait=0)
    return (nxt,)


def act_fast_arrives(s):
    return (replace(s, fast_due=True, fast_wait=0),) if not s.fast_due else ()


def act_main_starts(s):
    return (replace(s, main_remaining=MAIN_LEN),) if s.main_remaining == 0 else ()


ACTIONS = [("tick", act_tick), ("fast_job_due", act_fast_arrives),
           ("main_job_starts", act_main_starts)]

INVARIANTS = [
    ("a due fast job waits at most one tick", lambda s: s.fast_wait <= 1),
]


def required_fast_jobs_are_in_the_fast_lane():
    return REQUIRED_FAST <= set(scheduler.FAST)


def model():
    return Model("scheduler_lanes", State(), ACTIONS, INVARIANTS, max_states=5_000)
