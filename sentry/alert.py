"""Outbound alerts by email, through Resend.

Everything else in sentry stays on the machine. This is the one component that
reaches the network on its own, and only when you have put a Resend API key and
a recipient in ~/.sentry/config.json — with neither, it is inert. It exists so
that "sentry stopped recording" reaches you when you are not looking at the
dashboard.

Config, all under ~/.sentry/config.json (kept 0600), or the noted env var:

    resend_api_key      "re_..."            (or $SENTRY_RESEND_KEY)
    alert_to            "you@example.com"   or ["a@x.com", "b@y.com"]
    alert_from          "sentry@yourdomain.com"   a Resend-verified sender
    alert_min_severity  "high"              critical | high | medium
    alert_resend_after  21600               seconds a still-firing alert waits
                                            before it pages again
    alert_on_clear      true                also send when an alert clears
    alert_hourly_cap    12                  hard ceiling on emails per hour

Dedupe: every finding has a stable key — category | title | where. An alert for
a key is sent once, then not again until alert_resend_after has passed while it
kept firing, or until it clears and returns. So a flapping input monitor pages
you when it goes down, again if it is still down alert_resend_after later, and
once when it recovers — not on every 45-second watchdog tick.
"""

import json
import os
import ssl
import time
import urllib.error
import urllib.request

CONFIG_PATH = os.path.expanduser("~/.sentry/config.json")
API_URL = "https://api.resend.com/emails"

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def _int(v, default):
    """int() with a default for None / "" / junk — but 0 is kept as 0."""
    if v is None or v == "":
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

# Substrings that mark a finding as "sentry itself is not watching something".
# These page regardless of alert_min_severity, because a monitoring gap is the
# one class of finding whose whole point is that nothing else will tell you.
_OUTAGE_MARKERS = (
    "not running", "not recording", "is down", "was down", "stopped reporting",
    "has stopped", "cannot be restarted", "could not restart", "keeps dying",
    "has restarted", "is stale", "has never produced", "is failing",
    "heartbeat is overdue", "hook has stopped", "interop bridge",
)
_OUTAGE_CATEGORIES = ("input", "collectors", "daemon")

_M_STATE = "alert_state"       # json: {key: {first, last_sent, count, sev}}
_M_SENTLOG = "alert_sent_log"  # json: [ts, ...] emails actually sent, last hour


# ── config ──────────────────────────────────────────────────────────────────

def load_conf():
    conf = {}
    try:
        with open(CONFIG_PATH) as fh:
            conf = json.load(fh) or {}
    except (OSError, ValueError):
        conf = {}
    env = os.environ.get("SENTRY_RESEND_KEY", "").strip()
    if env:
        conf["resend_api_key"] = env
    return conf


def recipients(conf):
    to = conf.get("alert_to") or []
    if isinstance(to, str):
        to = [x.strip() for x in to.replace(";", ",").split(",")]
    return [x for x in to if x]


def enabled(conf):
    return bool((conf.get("resend_api_key") or "").strip()
                and (conf.get("alert_from") or "").strip()
                and recipients(conf))


def status(store):
    """A dict for `sentry alert` to print — never includes the key itself."""
    conf = load_conf()
    try:
        state = json.loads(store.get_meta(_M_STATE, "{}") or "{}")
    except ValueError:
        state = {}
    return {
        "enabled": enabled(conf),
        "have_key": bool((conf.get("resend_api_key") or "").strip()),
        "from": conf.get("alert_from", ""),
        "to": recipients(conf),
        "min_severity": conf.get("alert_min_severity", "high"),
        "resend_after": _int(conf.get("alert_resend_after"), 21600),
        "on_clear": conf.get("alert_on_clear", True) is not False,
        "hourly_cap": _int(conf.get("alert_hourly_cap"), 12),
        "active": sorted(state.keys()),
        "sent_last_hour": len(_recent_sends(store)),
    }


# ── transport ───────────────────────────────────────────────────────────────

def send_email(conf, subject, text):
    """POST one email to Resend. Returns "" on success, else an error string.

    The API key goes only in the Authorization header of this one request to
    api.resend.com, over TLS with verification on. It is never logged.
    """
    key = (conf.get("resend_api_key") or "").strip()
    payload = json.dumps({
        "from": conf["alert_from"],
        "to": recipients(conf),
        "subject": subject[:200],
        "text": text,
    }).encode()
    req = urllib.request.Request(API_URL, data=payload, method="POST")
    req.add_header("Authorization", f"Bearer {key}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    # api.resend.com sits behind Cloudflare, which blocks the default
    # "Python-urllib/x.y" agent with a 403 (error 1010). Any real UA is fine.
    req.add_header("User-Agent", "sentry-monitor/1.0 (+https://github.com)")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            if resp.status in (200, 201):
                return ""
            return f"Resend returned HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read().decode()).get("message", "")
        except Exception:
            pass
        return f"Resend HTTP {exc.code}: {detail or exc.reason}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return f"could not reach Resend: {exc}"


def test(store):
    conf = load_conf()
    if not enabled(conf):
        return "alerts are not configured — set resend_api_key, alert_from and " \
               "alert_to in " + CONFIG_PATH
    err = send_email(conf, "[sentry] test alert",
                     "This is a test from `sentry alert --test`.\n"
                     "If you got this, outage alerts will reach you too.\n")
    if not err:
        _record_send(store)
    return err


# ── dispatch ────────────────────────────────────────────────────────────────

def _key(f):
    return f"{f.get('category', '')}|{f.get('title', '')}|{f.get('where', '')}"


# The full input audit and its watchdog cover the same ground; either may clear
# an alert the other raised. Every other job clears only its own.
_DOMAIN = {"input": "input", "input_hook": "input"}


def _same_domain(a, b):
    return _DOMAIN.get(a, a) == _DOMAIN.get(b, b)


def _is_outage(f):
    if f.get("category") not in _OUTAGE_CATEGORIES:
        return False
    if SEV_RANK.get(f.get("severity"), 9) > SEV_RANK["medium"]:
        return False
    blob = (f.get("title", "") + " " + f.get("detail", "")).lower()
    return any(m in blob for m in _OUTAGE_MARKERS)


def _recent_sends(store):
    try:
        log = [int(x) for x in json.loads(store.get_meta(_M_SENTLOG, "[]") or "[]")]
    except (ValueError, TypeError):
        log = []
    cutoff = int(time.time()) - 3600
    return [t for t in log if t >= cutoff]


def _record_send(store):
    log = _recent_sends(store)
    log.append(int(time.time()))
    store.set_meta(_M_SENTLOG, json.dumps(log[-100:]))


def dispatch(store, job, findings, error=""):
    """Called by the scheduler after every job. Sends at most one email.

    Never raises: an alerting path that can crash the monitor is worse than one
    that occasionally misses. The caller still wraps this in its own guard.
    """
    try:
        conf = load_conf()
        if not enabled(conf):
            return
        _dispatch(store, conf, job, list(findings or []), error)
    except Exception:
        pass


def _dispatch(store, conf, job, findings, error):
    now = int(time.time())
    min_rank = SEV_RANK.get(conf.get("alert_min_severity", "high"), 1)
    resend_after = _int(conf.get("alert_resend_after"), 21600)
    on_clear = conf.get("alert_on_clear", True) is not False
    cap = _int(conf.get("alert_hourly_cap"), 12)

    if error:
        findings = findings + [{
            "category": "collectors", "severity": "high",
            "title": f"collector '{job}' crashed",
            "detail": error.strip().splitlines()[-1][:200] if error.strip()
                      else "unknown error",
            "where": "sentry serve", "host": "wsl"}]

    # Which findings from THIS job would page.
    pageable = {}
    for f in findings:
        rank = SEV_RANK.get(f.get("severity"), 9)
        if rank <= min_rank or _is_outage(f):
            pageable[_key(f)] = f

    try:
        state = json.loads(store.get_meta(_M_STATE, "{}") or "{}")
    except ValueError:
        state = {}

    to_send, cleared = [], []

    for k, f in pageable.items():
        st = state.get(k)
        if st is None:
            state[k] = {"first": now, "last_sent": now, "count": 1,
                        "sev": f.get("severity", "high"), "job": job}
            to_send.append(("NEW", f))
        elif now - int(st.get("last_sent", 0)) >= resend_after:
            st["last_sent"] = now
            st["count"] = int(st.get("count", 1)) + 1
            st["sev"] = f.get("severity", st.get("sev", "high"))
            st["job"] = job
            to_send.append(("STILL", f))

    # An alert clears only when the job that raised it (or one covering the
    # same ground) runs and no longer reports it — so an unrelated job cannot
    # "resolve" it just by staying silent about it.
    for k in list(state.keys()):
        if k in pageable:
            continue
        if _same_domain(state[k].get("job", ""), job):
            if on_clear:
                cleared.append(k)
            state.pop(k, None)

    if not to_send and not cleared:
        store.set_meta(_M_STATE, json.dumps(state))
        return

    if len(_recent_sends(store)) >= cap:
        # Keep the state we just advanced (so resend timing stays honest) but
        # do not add to the flood. The next email will note the gap.
        store.set_meta(_M_STATE, json.dumps(state))
        store.set_meta("alert_capped_at", now)
        return

    lines = []
    worst = "low"
    for tag, f in sorted(to_send, key=lambda x: SEV_RANK.get(
            x[1].get("severity"), 9)):
        sev = f.get("severity", "?")
        if SEV_RANK.get(sev, 9) < SEV_RANK.get(worst, 9):
            worst = sev
        lines.append(f"[{sev.upper()}] {tag}: {f.get('title', '')}\n"
                     f"    {f.get('detail', '')}\n"
                     f"    where: {f.get('where', '') or '—'}  (job: {job})")
    for k in cleared:
        lines.append(f"[CLEARED] {k.split('|', 1)[1].replace('|', ' — ')}")

    if to_send:
        subject = f"[sentry] {len(to_send)} alert(s), worst {worst.upper()}: " \
                  f"{to_send[0][1].get('title', '')}"
    else:
        subject = f"[sentry] {len(cleared)} alert(s) cleared"

    body = "\n\n".join(lines)
    if store.get_meta("alert_capped_at"):
        body += "\n\n(some earlier alerts were suppressed by the hourly cap)"
        store.set_meta("alert_capped_at", "")

    err = send_email(conf, subject, body + "\n")
    if err:
        # Could not send. Roll back last_sent on the STILL items so we retry
        # promptly rather than waiting a full resend_after.
        for tag, f in to_send:
            if tag == "STILL":
                k = _key(f)
                if k in state:
                    state[k]["last_sent"] = 0
        store.set_meta(_M_STATE, json.dumps(state))
        store.set_meta("alert_last_error", f"{now}: {err}"[:300])
        return

    _record_send(store)
    store.set_meta(_M_STATE, json.dumps(state))
    store.set_meta("alert_last_ok", now)
    store.set_meta("alert_last_error", "")
