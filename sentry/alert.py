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
    alert_outage_resend_after  900          the same, for outages — much
                                            shorter, and it widens per repeat
                                            up to an hour
    alert_on_clear      true                also send when an alert clears
    alert_hourly_cap    12                  ceiling on ordinary emails per
                                            hour; 0 or negative means no
                                            ceiling. It never applies to
                                            outages, which have their own far
                                            higher ceiling.
    alert_send_attempts 5                   transport retries per email

Dedupe: every finding has a stable key — category | title | where. An alert for
a key is sent once, then not again until alert_resend_after has passed while it
kept firing, or until it clears and returns. So a flapping input monitor pages
you when it goes down, again if it is still down alert_resend_after later, and
once when it recovers — not on every 45-second watchdog tick.
"""

import json
import os
import random
import re
import ssl
import time
import urllib.error
import urllib.request

CONFIG_PATH = os.path.expanduser("~/.sentry/config.json")
API_URL = "https://api.resend.com/emails"

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

# Transport retries. One outage mail is worth several attempts: the network
# path this alert travels is frequently the same one that just broke.
SEND_ATTEMPTS = 5
SEND_BACKOFF_BASE = 2.0
SEND_BACKOFF_CAP = 30.0

# Outages re-page far more often than ordinary findings. "The monitor is not
# watching" is not information you want delivered once and then filed; every
# hour it stays down is another hour of nothing being recorded.
OUTAGE_RESEND = 900          # 15 minutes, overridable per config

# An hour of an unfixed outage should escalate, not fade. Repeat intervals grow
# only up to this, so a long outage keeps pinging rather than going quiet.
OUTAGE_RESEND_CAP = 3600

# The hourly ceiling that applies to outage mail. Deliberately far above the
# ordinary cap: the ordinary cap protects an inbox from a flapping collector,
# but nothing may be allowed to suppress "the monitor is not watching". This
# only exists so a genuine runaway cannot burn a Resend quota to zero.
OUTAGE_HOURLY_CAP = 60


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
        "outage_resend_after": max(60, _int(
            conf.get("alert_outage_resend_after"), OUTAGE_RESEND)),
        "on_clear": conf.get("alert_on_clear", True) is not False,
        "hourly_cap": max(0, _int(conf.get("alert_hourly_cap"), 12)),
        "outage_hourly_cap": OUTAGE_HOURLY_CAP,
        "send_attempts": max(1, _int(conf.get("alert_send_attempts"),
                                     SEND_ATTEMPTS)),
        "active": sorted(state.keys()),
        "outages": sorted(k for k, v in state.items() if v.get("outage")),
        "sent_last_hour": len(_recent_sends(store)),
        "last_ok": int(store.get_meta("alert_last_ok", 0) or 0),
        "last_error": store.get_meta("alert_last_error", "") or "",
        "capped_at": int(store.get_meta("alert_capped_at", 0) or 0),
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
    ctx = ssl.create_default_context()
    attempts = max(1, _int(conf.get("alert_send_attempts"), SEND_ATTEMPTS))
    last = "no attempt was made"

    for i in range(attempts):
        if i:
            # Full jitter on an exponential backoff. Sentry's outage mail and a
            # transient DNS or TLS failure must not become a tight retry loop
            # against api.resend.com — that is how a key gets rate-limited
            # exactly when it is needed.
            time.sleep(min(SEND_BACKOFF_CAP,
                           SEND_BACKOFF_BASE * (2 ** (i - 1)))
                       * (0.5 + random.random() / 2))
        req = urllib.request.Request(API_URL, data=payload, method="POST")
        req.add_header("Authorization", f"Bearer {key}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        # api.resend.com sits behind Cloudflare, which blocks the default
        # "Python-urllib/x.y" agent with a 403 (error 1010). Any real UA is fine.
        req.add_header("User-Agent", "sentry-monitor/1.0 (+https://github.com)")
        try:
            with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
                if resp.status in (200, 201):
                    return ""
                last = f"Resend returned HTTP {resp.status}"
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = json.loads(exc.read().decode()).get("message", "")
            except Exception:
                pass
            last = f"Resend HTTP {exc.code}: {detail or exc.reason}"
            # 4xx other than 408/429 is a permanent problem with the request
            # itself — a bad key, an unverified sender. Retrying cannot fix it
            # and only burns the rate limit.
            if 400 <= exc.code < 500 and exc.code not in (408, 429):
                return last
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last = f"could not reach Resend: {exc}"

    return f"{last} (after {attempts} attempts)"


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

# Categories whose findings are inherently per-PID / per-connection churn. They
# belong on the dashboard, not in an inbox — a genuinely dangerous process
# still pages through sysmon / hunt / intrusion with a stable title.
_NOPAGE_CATEGORIES = {"process", "peer"}

# Volatile tokens that must not be part of a dedupe key, or every occurrence is
# a "new" alert: pids, the NEW marker, repeat counts, long hex/base64 blobs,
# and the timestamped names in Claude Code's shell snapshots.
_VOLATILE = re.compile(
    r"\[pid \d+\]|\bpid[= ]\d+|—\s*NEW\b|\(×\d+\)|\bsnapshot-\w+-\d+[-\w]*|"
    r"\b[0-9a-f]{16,}\b|\b\d{10,}\b")


def _key(f):
    title = _VOLATILE.sub("", f.get("title", "")).strip(" -—|")
    return f"{f.get('category', '')}|{title}|{f.get('where', '')}"


# The full input audit and its watchdog cover the same ground; either may clear
# an alert the other raised. Every other job clears only its own.
#
# "bridge" and "coverage" both emit the identical Windows-bridge finding, so
# they share a dedupe key and never double-mail — but they are deliberately NOT
# given a shared domain: coverage raises other alerts of its own, and the
# bridge job (which reports nothing but the bridge) would then clear them all.
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


def _resend_interval(st, outage_resend, resend_after):
    """How long this alert waits before paging again.

    Ordinary findings use alert_resend_after. Outages start at outage_resend
    and widen with each repeat up to OUTAGE_RESEND_CAP — so a monitor that has
    been down for a minute pages quickly, one that has been down all afternoon
    still pages hourly, and neither turns into a per-scan flood.
    """
    if not st.get("outage"):
        return resend_after
    count = max(1, int(st.get("count", 1)))
    return int(min(OUTAGE_RESEND_CAP, outage_resend * count))


def _dispatch(store, conf, job, findings, error):
    now = int(time.time())
    min_rank = SEV_RANK.get(conf.get("alert_min_severity", "high"), 1)
    resend_after = _int(conf.get("alert_resend_after"), 21600)
    outage_resend = max(60, _int(conf.get("alert_outage_resend_after"),
                                 OUTAGE_RESEND))
    on_clear = conf.get("alert_on_clear", True) is not False
    # 0 or negative means "no ceiling". It used to mean "cap at zero", which
    # silently suppressed every alert for as long as it was set — a monitoring
    # tool must fail toward telling you, never toward silence.
    cap = _int(conf.get("alert_hourly_cap"), 12)
    if cap <= 0:
        cap = 0        # falsy => unlimited, checked explicitly below

    if error:
        findings = findings + [{
            "category": "collectors", "severity": "high",
            "title": f"collector '{job}' crashed",
            "detail": error.strip().splitlines()[-1][:200] if error.strip()
                      else "unknown error",
            "where": "sentry serve", "host": "wsl"}]

    # Which findings from THIS job would page.
    pageable, outage_keys = {}, set()
    for f in findings:
        if f.get("category") in _NOPAGE_CATEGORIES and not _is_outage(f):
            continue
        rank = SEV_RANK.get(f.get("severity"), 9)
        if rank <= min_rank or _is_outage(f):
            k = _key(f)
            pageable[k] = f
            if _is_outage(f):
                outage_keys.add(k)

    try:
        state = json.loads(store.get_meta(_M_STATE, "{}") or "{}")
    except ValueError:
        state = {}

    to_send, cleared = [], []

    for k, f in pageable.items():
        st = state.get(k)
        outage = k in outage_keys
        if st is None:
            # Persistence gate: a finding must survive one interval before it
            # pages, so a one-scan blip (a short-lived process, a transient
            # error) never reaches the inbox. Outages skip the gate — "the
            # monitor is down" is time-sensitive.
            if outage:
                state[k] = {"first": now, "last_sent": now, "count": 1,
                            "sev": f.get("severity", "high"), "job": job,
                            "outage": True}
                to_send.append(("NEW", f))
            else:
                state[k] = {"first": now, "pending": now, "count": 0,
                            "sev": f.get("severity", "high"), "job": job}
            continue
        if outage:
            st["outage"] = True
        if st.get("pending"):
            st.pop("pending", None)
            st["last_sent"] = now
            st["count"] = 1
            state[k] = st
            to_send.append(("NEW", f))
        elif now - int(st.get("last_sent", 0)) >= _resend_interval(
                st, outage_resend, resend_after):
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

    # The hourly cap exists to stop a flapping collector from filling an inbox.
    # It must never be able to silence an outage: "nothing is being monitored"
    # is the one message whose whole purpose is to arrive. Outages get their own
    # much higher ceiling, and only a true runaway trips it.
    has_outage = any(_key(f) in outage_keys for _, f in to_send)
    limit = OUTAGE_HOURLY_CAP if has_outage else cap
    if limit and len(_recent_sends(store)) >= limit:
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
