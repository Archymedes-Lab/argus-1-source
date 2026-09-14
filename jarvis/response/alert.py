"""Outbound alerts by email, through Resend.

Everything else in jarvis stays on the machine. This is the one component that
reaches the network on its own, and only when you have put a Resend API key and
a recipient in ~/.jarvis/config.json — with neither, it is inert. It exists so
that "jarvis stopped recording" reaches you when you are not looking at the
dashboard.

Config, all under ~/.jarvis/config.json (kept 0600), or the noted env var:

    resend_api_key      "re_..."            (or $JARVIS_RESEND_KEY)
    alert_to            "you@example.com"   or ["a@x.com", "b@y.com"]
    alert_from          "JARVIS <jarvis@yourdomain.com>"  a verified sender
    alert_min_severity  "high"              critical | high | medium
    alert_digest_interval 3600             group ordinary changes for an hour
    alert_on_clear      true                include recoveries in the digest
    alert_hourly_cap    12                  transport ceiling; unsent work stays queued
    report_hour         9                   daily advisory, host local time
    alert_send_attempts 5                   transport retries per email

Critical findings and monitoring outages send immediately. Other findings
must survive a second observation and are grouped into an hourly change digest.
Unchanged findings escalate once per age threshold, never via periodic STILL
mail. Notification state and pending delivery survive process restarts.
"""

import json
import os
import random
import re
import ssl
import time
import urllib.error
import urllib.request

CONFIG_PATH = os.path.expanduser("~/.jarvis/config.json")
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


def parse_int(v, default):
    """int() with a default for None / "" / junk — but 0 is kept as 0."""
    if v is None or v == "":
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

# Substrings that mark a finding as "jarvis itself is not watching something".
# These page regardless of alert_min_severity, because a monitoring gap is the
# one class of finding whose whole point is that nothing else will tell you.
_OUTAGE_MARKERS = (
    "not running", "not recording", "is down", "was down", "stopped reporting",
    "has stopped", "cannot be restarted", "could not restart", "keeps dying",
    "has restarted", "is stale", "has never produced", "is failing",
    "heartbeat is overdue", "hook has stopped", "interop bridge",
)
_OUTAGE_CATEGORIES = ("input", "collectors", "daemon")

STATE_META = "alert_state"       # json: {key: {first, last_sent, count, sev}}
SENT_LOG_META = "alert_sent_log"  # json: [ts, ...] emails actually sent, last hour


# ── config ──────────────────────────────────────────────────────────────────

def load_conf():
    conf = {}
    try:
        with open(CONFIG_PATH, errors="replace") as fh:
            conf = json.load(fh) or {}
    except (OSError, ValueError):
        conf = {}
    env = os.environ.get("JARVIS_RESEND_KEY", "").strip()
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


def branded_sender(conf):
    """Keep the configured verified address while presenting the JARVIS name."""
    sender = (conf.get("alert_from") or "").strip()
    match = re.search(r"<([^<>]+)>", sender)
    address = match.group(1).strip() if match else sender
    return f"JARVIS <{address}>"


def status(store):
    """A dict for `jarvis alert` to print — never includes the key itself."""
    conf = load_conf()
    try:
        state = json.loads(store.get_meta(STATE_META, "{}") or "{}")
    except ValueError:
        state = {}
    return {
        "enabled": enabled(conf),
        "have_key": bool((conf.get("resend_api_key") or "").strip()),
        "from": conf.get("alert_from", ""),
        "to": recipients(conf),
        "min_severity": conf.get("alert_min_severity", "high"),
        "digest_interval": max(60, parse_int(conf.get("alert_digest_interval"), 3600)),
        "resend_after": 0,
        "outage_resend_after": max(60, parse_int(
            conf.get("alert_outage_resend_after"), OUTAGE_RESEND)),
        "on_clear": conf.get("alert_on_clear", True) is not False,
        "hourly_cap": max(0, parse_int(conf.get("alert_hourly_cap"), 12)),
        "outage_hourly_cap": OUTAGE_HOURLY_CAP,
        "send_attempts": max(1, parse_int(conf.get("alert_send_attempts"),
                                     SEND_ATTEMPTS)),
        "active": sorted(state.keys()),
        "outages": sorted(k for k, v in state.items() if v.get("outage")),
        "sent_last_hour": len(recent_sends(store)),
        "last_ok": int(store.get_meta("alert_last_ok", 0) or 0),
        "report_last_ok": int(store.get_meta(REPORT_OK_META, 0) or 0),
        "report_last_error": store.get_meta(REPORT_ERROR_META, "") or "",
        "advisory_model": conf.get("advisory_model", "") or "",
        "advisory_ai": bool((os.environ.get("JARVIS_OPENAI_KEY", "").strip() or
                             (conf.get("openai_api_key") or "").strip()) and
                            (conf.get("advisory_model") or "").strip()),
        "last_error": store.get_meta("alert_last_error", "") or "",
        "capped_at": int(store.get_meta("alert_capped_at", 0) or 0),
    }


# ── transport ───────────────────────────────────────────────────────────────

def send_email(conf, subject, text, html=None):
    """POST one email to Resend. Returns "" on success, else an error string.

    The API key goes only in the Authorization header of this one request to
    api.resend.com, over TLS with verification on. It is never logged.
    """
    key = (conf.get("resend_api_key") or "").strip()
    message = {
        "from": branded_sender(conf),
        "to": recipients(conf),
        "subject": subject[:200],
        "text": text,
    }
    if html:
        message["html"] = html
    payload = json.dumps(message).encode()
    ctx = ssl.create_default_context()
    attempts = max(1, parse_int(conf.get("alert_send_attempts"), SEND_ATTEMPTS))
    last = "no attempt was made"

    for i in range(attempts):
        if i:
            # Full jitter on an exponential backoff. JARVIS's outage mail and a
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
        req.add_header("User-Agent", "jarvis-monitor/1.0 (+https://github.com)")
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
    err = send_email(conf, "[JARVIS] test alert",
                     "This is a test from JARVIS (`jarvis alert --test`).\n"
                     "If you got this, outage alerts will reach you too.\n")
    if not err:
        record_send(store)
    return err


# ── periodic whole-system advisory (store keys; the report itself is
#    response/reporting/advisory.py) ─────────────────────────────────────────

REPORT_OK_META = "advisory_report_last_ok"
REPORT_ERROR_META = "advisory_report_last_error"


# ── dispatch ────────────────────────────────────────────────────────────────

# Categories whose findings are inherently per-PID / per-connection churn. They
# belong on the dashboard, not in an inbox — a genuinely dangerous process
# still pages through sysmon / hunt / intrusion with a stable title.
# "ledger" is here for a structural reason, not a preference one. Its findings
# are *about* alerts that were already emailed. If they paged, an unresolved
# HIGH would generate a ledger HIGH, which would be mailed, which would be
# recorded in the ledger as another unresolved alert, which would page. The
# backlog belongs in the advisory report and on the dashboard, where it is read
# deliberately rather than pushed.
NOPAGE_CATEGORIES = {"process", "peer", "coverage gap", "not observable",
                      "ledger"}

# Volatile tokens that must not be part of a dedupe key, or every occurrence is
# a "new" alert: pids, the NEW marker, repeat counts, long hex/base64 blobs,
# and the timestamped names in Claude Code's shell snapshots.
_VOLATILE = re.compile(
    r"\[pid \d+\]|\bpid[= ]\d+|—\s*NEW\b|\(×\d+\)|\bsnapshot-\w+-\d+[-\w]*|"
    r"\b[0-9a-f]{16,}\b|\b\d{10,}\b")


def finding_key(f):
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


def same_domain(a, b):
    return _DOMAIN.get(a, a) == _DOMAIN.get(b, b)


def is_outage(f):
    if f.get("category") not in _OUTAGE_CATEGORIES:
        return False
    if SEV_RANK.get(f.get("severity"), 9) > SEV_RANK["medium"]:
        return False
    blob = (f.get("title", "") + " " + f.get("detail", "")).lower()
    return any(m in blob for m in _OUTAGE_MARKERS)


def recent_sends(store):
    try:
        log = [int(x) for x in json.loads(store.get_meta(SENT_LOG_META, "[]") or "[]")]
    except (ValueError, TypeError):
        log = []
    cutoff = int(time.time()) - 3600
    return [t for t in log if t >= cutoff]


def record_send(store):
    log = recent_sends(store)
    log.append(int(time.time()))
    store.set_meta(SENT_LOG_META, json.dumps(log[-100:]))
