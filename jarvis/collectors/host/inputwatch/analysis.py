"""Turning input telemetry into findings about synthetic input."""

import statistics
from jarvis.platform.windows import ps_json
from jarvis.core.util import iso, now
from .common import _finding
from .helper import running
from .ingest import ingest



SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

BENIGN_INJECTORS = {
    "1password", "bitwarden", "keepass", "keepassxc", "lastpass", "dashlane",
    "autohotkey", "ahk", "osk", "tabtip", "magnify", "narrator",
    "mstsc", "rdpclip", "teamviewer", "anydesk", "rustdesk", "vncviewer",
    "synergy", "barrier", "deskflow", "sharemouse", "logioptionsplus",
    "logitech", "razer", "steam", "vmware", "virtualbox",
    "parsec", "moonlight", "sunshine", "obs64", "obs32",
}


def audit(store, hours=24, pids=None, supervised=False):
    out = []
    ingest(store)
    since = now() - hours * 3600
    # Control activations are recorded whether or not the hook is supervised:
    # they are their own record, not part of the liveness narrative.
    out.extend(_control_findings(store, hours))
    out.extend(_punct_findings(store, hours))
    out.extend(_digit_findings(store, hours))

    beat = store.db.execute(
        "SELECT * FROM input_beats ORDER BY ts DESC LIMIT 1").fetchone()

    # When the supervisor has already run it owns the liveness and latency
    # narrative; audit adds only what it alone produces — the injected-event
    # breakdown below.
    if not supervised:
        if pids is None:
            pids = running()
        if not pids:
            out.append(_finding(
                "input", "medium", "the injected-input monitor is not running",
                "synthetic keystrokes are only visible from inside a live hook, "
                "so nothing is being recorded — this is not a clean result",
                "jarvis inputwatch --start"))
        elif beat and now() - beat["ts"] > 300:
            out.append(_finding(
                "input", "high", "the input hook has stopped reporting",
                f"the helper is alive but its last heartbeat was "
                f"{iso(beat['ts'])} — a hook that was removed looks exactly "
                f"like a quiet keyboard", "inputwatch"))
        else:
            totals = (f"{beat['real_keys']} real keystrokes / "
                      f"{beat['injected_keys']} injected "
                      f"(+{beat['injected_keyups']} injected key-ups), "
                      f"{beat['real_moves']} real cursor moves / "
                      f"{beat['injected_moves']} injected in "
                      f"{beat['injected_move_bursts']} bursts"
                      if beat else "no counts yet")
            out.append(_finding(
                "input", "ok", "the injected-input monitor is running",
                f"pid {pids[0]} — {totals}", "inputwatch"))
        out += _latency_findings(store, beat)
        out += _typing_findings(store, beat)

    rows = store.db.execute(
        """SELECT fg, kind, class, lower_il, COUNT(*) n,
                  MIN(ts) first, MAX(ts) last
             FROM input_events WHERE ts>=?
            GROUP BY fg, kind, class, lower_il
            ORDER BY COUNT(*) DESC""", (since,)).fetchall()
    for r in rows:
        fg = (r["fg"] or "").lower()
        benign = any(b in fg for b in BENIGN_INJECTORS)
        if r["kind"] == "click" and benign:
            continue
        sev = ("low" if benign else
               "critical" if r["lower_il"] else
               "high" if r["kind"] == "key" else "medium")
        why = ("this program injects input as part of its normal job"
               if benign else
               "injected from a lower integrity level — the shape of one "
               "process driving another's window" if r["lower_il"] else
               "no hardware produced this event")
        out.append(_finding(
            "input", sev,
            f"{r['n']} injected {r['class'] or r['kind']}"
            f"{'s' if r['n'] > 1 else ''} while "
            f"{r['fg'] or 'an unknown window'} had focus",
            f"{why} — first {iso(r['first'])}, last {iso(r['last'])}",
            "input_events"))
    return sort_findings(out)


def _latency_findings(store, beat, probe_registry=True):
    """Is anything making the cursor and keyboard feel slow?

    Every low-level hook sits in a chain and delays each event until it
    returns. That is the mechanism behind "the cursor is slower than it used
    to be" — a keylogger, a screen recorder or an overlay doing work on the
    input thread shows up here as milliseconds.

    Windows drops a hook that exceeds `LowLevelHooksTimeout` (default 300ms),
    so software that wants to keep a slow hook alive has a reason to raise
    that value. An unexplained increase is worth seeing. That check reads the
    registry over the interop boundary, so `probe_registry=False` lets the
    frequent watchdog skip it and leave it to the full audit.
    """
    out = []
    if not beat or not beat["lat_samples"]:
        return out

    avg, mx = beat["lat_avg_ms"], beat["lat_max_ms"]
    over = beat["lat_over50"]
    pct = (100.0 * over / beat["lat_samples"]) if beat["lat_samples"] else 0

    if avg >= 30 or pct >= 10:
        sev = "high" if (avg >= 60 or pct >= 25) else "medium"
        out.append(_finding(
            "input", sev, f"input events are arriving {avg} ms late on average",
            f"peak {mx} ms; {over} of {beat['lat_samples']} events "
            f"({pct:.0f}%) took over 50 ms to reach this hook. Every low-level "
            f"hook in the chain delays input until it returns, so this is what "
            f"a keylogger, screen recorder or overlay feels like. Note that "
            f"JARVIS's own hook is in that chain and contributes part of it — "
            f"stop it with `jarvis inputwatch --stop` and see whether the "
            f"figure follows.", "input_beats"))
    else:
        out.append(_finding(
            "input", "ok", f"input latency is {avg} ms average, {mx} ms peak",
            f"{beat['lat_samples']} events sampled — nothing in the hook chain "
            f"is adding perceptible delay", "input_beats"))

    if not probe_registry:
        return out

    d = ps_json(
        "$v = (Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' "
        "-Name LowLevelHooksTimeout -EA SilentlyContinue).LowLevelHooksTimeout;"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{t=$v})))", timeout=60)
    t = (d or {}).get("t")
    if t and int(t) > 300:
        out.append(_finding(
            "input", "high", f"LowLevelHooksTimeout has been raised to {t} ms",
            "Windows removes a low-level hook that takes longer than this to "
            "return. Raising it above the 300 ms default keeps slow hooks "
            "alive — which is something a keylogger benefits from and normal "
            "software rarely needs",
            r"HKCU\Control Panel\Desktop"))
    return out


def _cadence_findings(beat):
    """Real keystrokes arriving faster or more evenly than a person can type.

    Hardware-level injection — a malicious HID filter driver, a BadUSB device,
    an IOCTL straight to kbdclass — sets no injected flag; the events are
    identical to human typing. Timing is the only tell it leaves: nobody holds
    a sub-8 ms inter-key cadence, or a long run of gaps all within 2 ms of each
    other. Key auto-repeat is already excluded on the helper side.
    """
    if not beat:
        return []
    gaps = beat["real_key_gaps"] or 0
    if gaps < 30:                       # too little typing to characterise
        return []
    sub8, sub20 = beat["real_key_sub8"] or 0, beat["real_key_sub20"] or 0
    run = beat["cad_run_max"] or 0
    p8, p20 = 100.0 * sub8 / gaps, 100.0 * sub20 / gaps

    if p8 >= 5 or run >= 40:
        extra = (f", and a run of {run} consecutive gaps stayed within 2 ms of "
                 f"each other" if run >= 20 else "")
        return [_finding(
            "input", "high",
            "real keystrokes are arriving faster than a human types",
            f"{sub8} of {gaps} inter-key gaps ({p8:.0f}%) were under 8 ms{extra}. "
            f"Driver- or hardware-level injection carries no injected flag — "
            f"cadence like this is the only signal it leaves.", "input_beats")]
    if p20 >= 25 or run >= 20:
        extra = f"; longest even run {run}" if run >= 10 else ""
        return [_finding(
            "input", "medium",
            "real keystrokes show a machine-like cadence",
            f"{sub20} of {gaps} gaps ({p20:.0f}%) were under 20 ms{extra} — fast "
            f"automation, a very fast typist, or a stuck repeat. Worth a look at "
            f"what had focus.", "input_beats")]
    return [_finding(
        "input", "ok", "keystroke cadence looks human",
        f"{gaps} inter-key gaps sampled, {p20:.0f}% under 20 ms, longest even "
        f"run {run}", "input_beats")]


def _typing_findings(store, beat):
    """Rolling, contentless typing anomalies from one-minute aggregates.

    This deliberately cannot answer "what was typed". It can answer whether a
    minute was implausibly dense, machine-fast, or dominated by the three key
    families the operator asked to watch (=, / and .).
    """
    rows = store.db.execute(
        "SELECT * FROM input_typing_windows WHERE ts >= ? ORDER BY ts DESC",
        (now() - 300,)).fetchall()
    if not rows:
        return _cadence_findings(beat)

    total = lambda key: sum(int(r[key] or 0) for r in rows)
    keys = total("real_keys")
    gaps = total("real_key_gaps")
    sub20 = total("real_key_sub20")
    sub8 = total("real_key_sub8")
    run = max((int(r["cad_run_max"] or 0) for r in rows), default=0)
    summary = {"real_key_gaps": gaps, "real_key_sub20": sub20,
               "real_key_sub8": sub8, "cad_run_max": run}
    out = _cadence_findings(summary) if gaps >= 30 else []

    labels = (("equals/plus", "equals_keys"),
              ("slash/question", "slash_keys"),
              ("period/greater-than", "period_keys"),
              ("digit", "digit_keys"))
    for label, column in labels:
        count = total(column)
        share = 100.0 * count / keys if keys else 0.0
        # Coding naturally uses punctuation, and PINs/OTP entry use digits, so
        # concentration alone is a low signal. It becomes medium only alongside
        # machine-fast cadence.
        if count >= 20 and share >= 35:
            machine_like = (sub8 >= 5 or run >= 20)
            out.append(_finding(
                "input", "medium" if machine_like else "low",
                f"typing is unusually concentrated on the {label} key",
                f"{count} of {keys} real key-down events ({share:.0f}%) in the "
                f"last five minutes used this physical key family"
                + (" alongside machine-like timing" if machine_like else
                   " — often benign, but retained as an anomaly signal"),
                "input_typing_windows"))

    latest = int(rows[0]["real_keys"] or 0)
    baseline = [int(r[0]) for r in store.db.execute(
        "SELECT real_keys FROM input_typing_windows "
        "WHERE ts < ? AND ts >= ? AND real_keys > 0 ORDER BY ts DESC LIMIT 5000",
        (rows[0]["ts"], now() - 90 * 86400)).fetchall()]
    if len(baseline) >= 30:
        median = statistics.median(baseline)
        mad = statistics.median(abs(n - median) for n in baseline)
        threshold = max(600, median + 8 * max(mad, 5))
        if latest > threshold:
            out.append(_finding(
                "input", "medium", "typing volume spiked above its baseline",
                f"{latest} key-down events in one minute versus a median of "
                f"{median:.0f} across {len(baseline)} active baseline minutes; "
                "content was not recorded", "input_typing_windows"))
    return out



# A control that moved with no key behind it is the one shape that separates
# "you pressed the volume key" from "something drove the machine as you". It is
# not proof of compromise: a media app, a headset dock, a meeting client and
# Windows itself all move the master level legitimately. It is proof that the
# change did not come from the keyboard in front of you, which is the fact the
# keyboard hook alone can never establish.
CONTROL_WINDOW = 24 * 3600


def _control_findings(store, hours=24):
    since = now() - min(hours, 168) * 3600
    try:
        rows = store.db.execute(
            "SELECT * FROM control_events WHERE ts >= ? ORDER BY ts DESC",
            (since,)).fetchall()
    except Exception:
        return []
    if not rows:
        return [_finding("input", "ok", "no control activations recorded",
                         "no volume, media or launch control moved in the last "
                         "%dh" % hours, "control_events")]

    out = []
    keys = [r for r in rows if r["kind"] == "control-key"]
    states = [r for r in rows if r["kind"] == "control-state"]
    injected = [r for r in keys if r["injected"]]
    unkeyed = [r for r in states if r["keyed"] == 0]

    if injected:
        first = injected[0]
        out.append(_finding(
            "input", "high", "a control key was injected by software",
            "%d injected control activation(s) in %dh; most recent %s at %s"
            "%s. A synthesised media key is software pressing it for you."
            % (len(injected), hours, first["control"], iso(first["ts"]),
               " (from a lower-integrity process)" if first["lower_il"] else ""),
            "control_events"))

    if unkeyed:
        first = unkeyed[0]
        out.append(_finding(
            "input", "medium",
            "the volume changed with no key press behind it",
            "%d unkeyed change(s) in %dh; most recent %s at %s, foreground %s. "
            "Media apps, headsets and Windows itself do this legitimately — but "
            "so does anything driving this machine as if it were you."
            % (len(unkeyed), hours, first["detail"], iso(first["ts"]),
               first["fg"] or "unknown"),
            "control_events"))

    keyed = [r for r in states if r["keyed"] == 1]
    out.append(_finding(
        "input", "ok", "control activations are being logged",
        "%d control key press(es) and %d state change(s) in %dh — %d matched a "
        "key press, %d did not" % (len(keys), len(states), hours, len(keyed),
                                   len(unkeyed)),
        "control_events"))
    return out


# Punctuation key-downs are timestamped individually so a key that appears
# without being pressed can be located in time and attributed to a window.
# A phantom key is only diagnosable if you know exactly when it happened.
def _punct_findings(store, hours=24):
    since = now() - min(hours, 168) * 3600
    try:
        rows = store.db.execute(
            "SELECT ts, kind, class, fg FROM input_events "
            "WHERE ts >= ? AND (kind = 'punct-key' OR class IN "
            "('period-greater','slash-question','equals-plus')) "
            "ORDER BY ts DESC LIMIT 200", (since,)).fetchall()
    except Exception:
        return []
    if not rows:
        return []
    injected = [r for r in rows if r["kind"] != "punct-key"]
    if injected:
        first = injected[0]
        return [_finding(
            "input", "critical", "a punctuation key was injected by software",
            "%d injected punctuation key(s); most recent %s at %s in %s. "
            "Nothing pressed it — it was synthesised."
            % (len(injected), first["class"], iso(first["ts"]),
               first["fg"] or "an unknown window"), "input_events")]
    first = rows[0]
    return [_finding(
        "input", "ok", "punctuation key presses are timestamped",
        "%d real punctuation key press(es) in %dh, none injected; most recent "
        "%s at %s in %s" % (len(rows), hours, first["class"], iso(first["ts"]),
                            first["fg"] or "an unknown window"),
        "input_events")]


# Digits 0-9 (top row and numpad) are timestamped the same way as punctuation:
# enough to say "digit-3 at 22:36 in WindowsTerminal", not enough to rebuild
# surrounding text. Injected digit presses keep the critical path.
def _digit_findings(store, hours=24):
    since = now() - min(hours, 168) * 3600
    try:
        rows = store.db.execute(
            "SELECT ts, kind, class, fg FROM input_events "
            "WHERE ts >= ? AND (kind = 'digit-key' OR class LIKE 'digit-_') "
            "ORDER BY ts DESC LIMIT 200", (since,)).fetchall()
    except Exception:
        return []
    if not rows:
        return []
    injected = [r for r in rows if r["kind"] != "digit-key"]
    if injected:
        first = injected[0]
        return [_finding(
            "input", "critical", "a digit key was injected by software",
            "%d injected digit key(s); most recent %s at %s in %s. "
            "Nothing pressed it — it was synthesised."
            % (len(injected), first["class"], iso(first["ts"]),
               first["fg"] or "an unknown window"), "input_events")]
    first = rows[0]
    return [_finding(
        "input", "ok", "digit key presses are timestamped",
        "%d real digit key press(es) in %dh, none injected; most recent "
        "%s at %s in %s" % (len(rows), hours, first["class"], iso(first["ts"]),
                            first["fg"] or "an unknown window"),
        "input_events")]


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))
