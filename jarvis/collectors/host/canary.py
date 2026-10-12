"""The canary job: watch planted bait and report when it is touched or taken.

Every pass: verify the tamper-evident journal, check planted decoys against
their plant-time fingerprints, ingest any callback hits the owner's listener
recorded, anchor the journal head externally when due, and turn the current
state into findings. Planting is owner-driven (`jarvis.core.canary.plant`); this
job never creates bait, never touches the attacker, and never clears a trip on
its own — a trip, once recorded, stays reported until the owner retires the
token.
"""

import json

from jarvis.core import canary as canary_mod
from jarvis.core.finding import finding

META = "canary_v1"


def _summary(store):
    try:
        state = json.loads(store.get_meta(META) or "null")
    except (TypeError, ValueError):
        return None
    return state if isinstance(state, dict) else None


def findings_from_state(state, chain_broken):
    """Findings for the current canary state. Pure, for direct testing."""
    out = []
    if chain_broken is not None:
        out.append(finding(
            "tampering", "critical", "Canary journal was tampered with",
            f"The append-only record of planted bait no longer verifies "
            f"({chain_broken.get('reason')} at sequence "
            f"{chain_broken.get('seq', chain_broken.get('index'))}). Someone with "
            "local access edited, deleted or reordered it. Compare against the "
            "off-box copy and the last external anchor before anything else writes "
            "here.", "canary journal"))
        # The chain cannot be trusted to enumerate tokens, so stop here.
        return out

    active = state.get("active", {})
    tripped = state.get("tripped", {})
    callbacks = state.get("callbacks", {})

    # Off-box callbacks are the strongest signal: the bait left this machine and
    # was opened elsewhere. That is exfiltration, whoever did it.
    for tid, hits in sorted(callbacks.items()):
        token = state.get("tokens", {}).get(tid, {})
        label = token.get("label", tid)
        last = hits[-1]
        registry_note = ("" if tid in active else
                         " (not in the active registry — planted long ago, or the "
                         "registry was trimmed)")
        ip = last.get("ip") or "unknown address"
        ua = last.get("ua") or "unknown"
        out.append(finding(
            "tampering", "critical",
            f"Canary bait was opened off this machine: {label}",
            f"{len(hits)} callback hit(s) for token {tid}{registry_note}. Most "
            f"recent: from {ip}, user-agent {ua}. The bait was taken from this "
            "machine and opened elsewhere — treat anything it sat alongside as "
            "exfiltrated.", f"token {tid}"))

    # On-box trips: the decoy was modified or removed here.
    for tid, reasons in sorted(tripped.items()):
        token = state.get("tokens", {}).get(tid, {})
        label = token.get("label", tid)
        where = token.get("path") or f"token {tid}"
        removed = "removed" in reasons
        verb = "taken" if removed else "touched"
        what = ("is gone (copied then deleted, or deleted)" if removed
                else "changed since it was planted")
        out.append(finding(
            "tampering", "high",
            f"Canary decoy was {verb}: {label}",
            f"The planted decoy {where} {what}. JARVIS does not write to planted "
            "decoys, so this was something else on the machine.", where))

    # Posture: how much bait is watching, so an empty registry is visible rather
    # than looking like silence meaning safety.
    if active:
        out.append(finding(
            "visibility", "ok", f"{len(active)} canary token(s) armed",
            "Planted bait is being watched for tampering and off-box callbacks.",
            "canary journal"))
    else:
        out.append(finding(
            "visibility", "low", "No canary tokens are planted",
            "No bait is in place, so a quiet intruder leaves no canary signal. "
            "Plant decoys with `jarvis.core.canary.plant(...)`.", "canary journal"))
    return out


def audit(store, hosts=None, root=canary_mod.DEFAULT_ROOT, conf=None, now=None,
          network=True, submit=None):
    import time

    now = now or time.time()
    # Config is handed down from the service layer (jobs.py); this collector does
    # not import `response`. An empty conf means "no inbox, no anchor configured".
    conf = conf or {}
    journal = canary_mod.CanaryJournal(root)

    broken = journal.verify()
    if broken is not None:
        # Do not append to a chain that no longer verifies: that would extend a
        # record an intruder has already broken. Report and stop writing.
        state = journal.state()
        store.set_meta(META, json.dumps({"at": int(now), "chain_ok": False,
                                        "broken": broken,
                                        "active": len(state.get("active", {}))},
                                       sort_keys=True))
        store.commit()
        return findings_from_state(state, broken)

    state = journal.state()

    appended = False

    # 1. on-box tripwire: record a trip once per (token, reason) transition.
    already = state.get("tripped", {})
    for trip in canary_mod.onbox_trips(state.get("active", {}), now=now,
                                       check_access=bool(conf.get("check_access"))):
        if trip["reason"] not in already.get(trip["id"], set()):
            journal.append("trip", trip)
            appended = True

    # 2. off-box callbacks from the owner's own listener inbox.
    for hit in canary_mod.read_callbacks(
            conf.get("callback_inbox"),
            active_ids=set(state.get("tokens", {})),
            seen_hits=set(state.get("seen_hits", set()))):
        journal.append("callback", hit)
        appended = True

    # Re-derive after any appends so the findings reflect this pass.
    if appended:
        state = journal.state()

    # 3. anchor the head externally when due (32-byte digest only). The
    # OpenTimestamps submitter comes from the platform layer, which this
    # collector may import; core stays platform-independent.
    want_anchor = network and conf.get("anchor", True) is not False
    if submit is None and want_anchor:
        from jarvis.platform import timestamps
        submit = timestamps.submit
    last_anchor = (_summary(store) or {}).get("last_anchor")
    digest, anchor_err = canary_mod.anchor_head(
        journal, now=now, last=last_anchor,
        every=int(conf.get("anchor_every", 21600)),
        network=want_anchor, submit=submit)

    head = journal.head()
    summary = {"at": int(now), "chain_ok": True, "head": head,
               "active": len(state.get("active", {})),
               "tripped": sorted(state.get("tripped", {})),
               "callbacks": sorted(state.get("callbacks", {})),
               "anchor_error": anchor_err}
    if digest:
        summary["last_anchor"] = {"hash": head["hash"], "at": int(now),
                                  "digest": digest}
    elif last_anchor:
        summary["last_anchor"] = last_anchor
    store.set_meta(META, json.dumps(summary, sort_keys=True))
    store.commit()
    return findings_from_state(state, None)
