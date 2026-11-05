"""Everyday words for every notification the daemon sends.

The owner asked that every alert (email, phone, webhook, ntfy, syslog, desktop
toast) be understandable by anyone: what happened and what, if anything, to do,
in plain words, with the exact facts kept beside it ("What it saw: <title>").
The desktop app's pop-ups say the same thing from the same sentences
(desktop/src/watch.rs, desktop/ui/src/lib/guide.json).

Invariants (tests/test_plainalert.py):
  * A fact is never removed or softened: the finding's own title, where it was
    seen and its severity stay in every message.
  * A plain sentence never claims a confirmed compromise, and never claims the
    computer is safe.
  * Deterministic: no model writes any of this.
  * GUIDE is a copy of the interface's guide (the daemon package does not ship
    desktop/ui); a test keeps it identical to guide.json and to the dashboard.
"""

from __future__ import annotations

from jarvis.response import categories

PRODUCT = "ARGUS-INSTINCT"
PREFIX = f"[{PRODUCT}]"
# The phone shows at most this much of a title on the lock screen
# (notify/channel.py LOCK_SCREEN_TITLE); subjects are built to fit it.
SUBJECT_LIMIT = 90

# Words a person who is not an engineer would not follow. The human-facing
# part of every message is tested against this list.
JARGON = ("daemon", "collector", "telemetry", "blind", "finding", "unobserved",
          "jarvis serve", "`", "observation", "digest", "interrupt", "snapshot",
          "stale", "remediation", "triage")

# [what it is, why it matters, what to do] per finding category: a copy of
# desktop/ui/src/lib/guide.json (itself the dashboard's GUIDE).
GUIDE = {
    "data at rest": (
        "A file appears to contain a credential, such as an API key or password.",
        "If it is a real, active credential and the file can be read by others, it could be misused.",
        "Review the affected file and decide whether the credential is real. If it is, revoke or rotate it using the service's own process.",
    ),
    "persistence": (
        "Something is set up to start automatically or run on a trigger, such as a scheduled task or a WMI subscription.",
        "Legitimate software does this, but so can malware that wants to survive a restart.",
        "Check whether you recognise the item and the program it runs. If you do not, investigate before removing anything.",
    ),
    "staging": (
        "A new, unsigned program was recently written to a place where programs are often dropped.",
        "Installers and developer tools do this too, but unexpected unsigned programs are a common way malware arrives.",
        "Check whether you installed or built something just before this appeared.",
    ),
    "rules": (
        "A firewall rule allows connections in a permissive way.",
        "Broad rules can let other computers reach programs on this one.",
        "Review who the rule allows and whether the program needs it.",
    ),
    "remote": (
        "A rule or setting allows connections into this computer.",
        "Remote access you did not set up could let someone else in.",
        "Confirm you expect this remote access.",
    ),
    "access": (
        "An app is using or can use a sensitive device such as the camera or microphone.",
        "That is normal during a call, but unexpected if you are not using it.",
        "Check which app it is and whether you started it.",
    ),
    "internet": (
        "A program is listening for connections beyond this computer, or traffic monitoring is limited.",
        "Programs reachable from the network are a way in if they have flaws.",
        "Check whether you want this program reachable from other devices.",
    ),
    "impersonation": (
        "Credentials stored on this computer could be used to sign in as you.",
        "Anyone who can run programs as you could use them.",
        "Review which stored sign-ins you still need.",
    ),
    "accounts": (
        "An account is hidden from the sign-in screen or looks unusual.",
        "Hidden accounts are sometimes used to keep access, though some are created by software on purpose.",
        "Identify what created the account before changing anything.",
    ),
    "interception": (
        "A trusted root certificate that is not a standard one was found.",
        "A trusted certificate can let its owner read protected web traffic.",
        "Check that the certificate belongs to software you installed on purpose.",
    ),
    "injected code": (
        "A program has executable memory that is not backed by a file on disk.",
        "Some software does this legitimately; malware uses it to hide.",
        "See whether the program is one you know and run.",
    ),
    "clickfix": (
        "The Run dialog history shows commands that may have been pasted from a website.",
        "Fake 'fix it' pages trick people into running commands themselves.",
        "Check whether you ran these commands on purpose.",
    ),
    "av": (
        "Windows Defender reported a detection.",
        "Defender has already flagged this item, so it deserves a look.",
        "Open Windows Security to see what it found and what it did.",
    ),
    "posture": (
        "A Windows protection setting is off or could not be read.",
        "Protections that are off leave less between you and an attack.",
        "Open the details to see which setting and whether you want it on.",
    ),
    "malware defense": (
        "A malware protection feature is not enabled.",
        "That feature would otherwise help block threats.",
        "Decide whether you want it enabled.",
    ),
    "defense": (
        "A Windows Defender setting could not be read.",
        "ARGUS-INSTINCT cannot confirm protection it cannot read.",
        "Open the details to see which setting.",
    ),
    "mitigations": (
        "A program runs without a hardening feature that limits what attackers can do.",
        "This makes that program easier to exploit if it has a flaw.",
        "Usually informational; keep the program updated.",
    ),
    "screen": (
        "An app may capture the screen without showing a capture border.",
        "Screen capture can reveal anything on your display.",
        "Check whether you use a screen-sharing or recording app.",
    ),
    "extension": (
        "A browser extension is installed.",
        "Extensions can read pages you visit, so each one is trusted with that.",
        "Keep only extensions you recognise.",
    ),
    "daemon": (
        "ARGUS-INSTINCT's own monitor or one of its services is not running as expected.",
        "While it is not running, ARGUS-INSTINCT cannot watch that area.",
        "Open Monitoring to see the reason and the steps to restore it.",
    ),
    "collectors": (
        "One of ARGUS-INSTINCT's checks could not complete.",
        "ARGUS-INSTINCT cannot currently confirm the security of that area.",
        "Open Monitoring to see the reason.",
    ),
    "visibility": (
        "ARGUS-INSTINCT has limited visibility into part of this computer.",
        "It cannot report on what it cannot see.",
        "Open Monitoring to see what is limited and why.",
    ),
}

# When the category has no guide entry: the kind of news decides the sentence.
FALLBACK = {
    "threat": (f"{PRODUCT} noticed activity on this computer that could be an attack, or could be "
               "something you or your software did.",
               "Look at what it saw and decide whether you expect it. Do not delete anything "
               "based on this alone."),
    "exposure": (f"{PRODUCT} found a setting or gap that could make this computer easier to attack.",
                 "Look at what it saw and decide whether to change it."),
    "updates": ("Software on this computer has an update that is not installed yet.",
                "Install it when you can."),
    "monitoring": (GUIDE["collectors"][0], GUIDE["collectors"][2]),
    "system": (GUIDE["daemon"][0], GUIDE["daemon"][2]),
    "test": ("This is a test message you asked for.", "Nothing to do."),
}

# Short forms for the desktop toast, whose body holds 160 characters.
SHORT = {
    "threat": "This could be an attack, or something you did.",
    "exposure": "A setting or gap could make this computer easier to attack.",
    "updates": "An update is waiting to be installed.",
    "monitoring": "A check stopped working, so part of this computer is not being watched.",
    "system": f"Part of {PRODUCT} is not working as expected.",
    "test": "This is a test.",
}


def _outage(finding):
    from jarvis.response import alert
    return alert.is_outage(finding)


def kind(finding, job=""):
    """The kind of news one finding is (response/categories.py), with a check that
    stopped working always filed as such."""
    f = finding or {}
    if _outage(f) and f.get("category") != "daemon":
        return "monitoring"
    return categories.of_finding(f, job)


# Finding categories that are the same kind of thing as a guide entry.
ALIASES = {"present": "data at rest"}


def guide(finding, job=""):
    """(what it is, what to do) for one finding, in everyday words."""
    cat = str((finding or {}).get("category") or "")
    g = GUIDE.get(ALIASES.get(cat, cat))
    if g:
        return g[0], g[2]
    return FALLBACK[kind(finding, job)]


def headline(finding, job="", tag=None):
    """A few words saying how much this needs you: the start of a subject."""
    f = finding or {}
    if tag == "RESOLVED":
        return "No longer seen"
    k = kind(f, job)
    if k == "monitoring":
        return "A check stopped working" if _outage(f) else "Something is not being checked"
    if k == "system":
        return f"Part of {PRODUCT} stopped working"
    if k == "updates":
        return "An update is waiting"
    sev = f.get("severity")
    if sev == "critical":
        return "Please look at this now"
    if sev == "high":
        return "Worth a look soon"
    return "Worth a look"


def title_of(finding):
    return " ".join(str((finding or {}).get("title") or "something it could not name").split())


def facts(finding):
    """The exact facts, unchanged: what it saw, where, how serious."""
    f = finding or {}
    out = [f"What it saw: {title_of(f)}"]
    if f.get("where"):
        out.append(f"Where: {f['where']}")
    if f.get("severity"):
        out.append(f"How serious: {f['severity']}")
    return out


def lead(finding, job="", tag=None):
    """Lines for one item: the plain sentence, then the facts."""
    if tag == "RESOLVED":
        return [f"{headline(finding, job, tag)}. That alone does not prove it was fixed.",
                *facts(finding)]
    means, todo = guide(finding, job)
    return [f"{headline(finding, job, tag)}. {means} {todo}", *facts(finding)]


def clip(text, limit):
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:max(0, limit - 1)].rstrip() + "…"


def subject(items, need=None, limit=SUBJECT_LIMIT):
    """One subject for [(finding, job, tag)], worst first: what it is, the title
    of the first thing seen and, with several, how many need you. Fits the
    lock-screen limit."""
    items = list(items)
    if not items:
        return f"{PREFIX} Nothing needs you right now"
    active = [i for i in items if i[2] != "RESOLVED"] or items
    f, job, tag = active[0]
    more = ""
    if len(items) > 1:
        more = f" (and {len(items) - 1} more" + (f", {need} need you)" if need is not None else ")")
    head = f"{PREFIX} {headline(f, job, tag)}: "
    # Branded first: delivery renames JARVIS, and the limit holds for what is sent.
    from jarvis.core import brand
    return head + clip(brand.brand(title_of(f)), limit - len(head) - len(more)) + more


def jargon(text):
    """The jargon words present in `text` (empty when it is plain)."""
    low = (text or "").lower()
    return [w for w in JARGON if w in low]
