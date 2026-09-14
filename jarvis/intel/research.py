"""Threat intelligence acquisition: turn published security research into
candidate indicators this machine can actually check.

The pipeline is deliberately one-directional and lossy:

    Exa search  ->  structured extraction  ->  vet.py  ->  indicators table
                                                  |
                                            most things die here

What survives is never authoritative. An indicator is a reason to go and look
at something, evaluated against the live system by hunt.py. Nothing fetched is
executed, and nothing fetched can clear an existing finding — see vet.py for
why that invariant is the whole design.

Two things dominate output quality, in this order:

  1. **Which sources are searched.** An early test run without a source
     allowlist returned a 2007 academic paper on registry forensics as the top
     hit for a Linux rootkit query. The allowlist below is the single highest
     leverage knob in this file.
  2. **What the extraction is told to refuse.** Language models fill empty
     fields with plausible filler: `evil.com`, `192.168.1.100`, and the SHA-256
     of the empty string all arrived from one real article. The prompt spends
     most of its length on refusal rules for that reason.
"""

import json
import os
import stat
import time
import urllib.error
import urllib.request

from jarvis.core import vet
from jarvis.core.util import now
from jarvis.intel.corpus import CORPUS, SOURCES

API_URL = "https://api.exa.ai/search"
CONFIG_PATH = os.path.expanduser("~/.jarvis/config.json")

# ── The extraction prompt ─────────────────────────────────────────────────
#
# Every rule here exists because its absence produced a specific bad result in
# testing. Notably: naming the target platform in the prompt caused the model
# to echo "Windows 11 workstation with WSL2" back as extracted data, so the
# prompt now says nothing about the machine it defends.
EXTRACTION_PROMPT = """\
You are extracting host-based detection content from a security research \
article for an automated defensive agent. The output is machine-consumed. \
Precision matters far more than recall: a wrong indicator causes a false alarm \
on a production workstation, while a missing one costs nothing.

COPY, DO NOT COMPOSE. Every value must appear verbatim in the article. Do not \
infer, generalise, normalise, complete, or reconstruct any value. If you are \
recalling it from knowledge of this malware family rather than reading it in \
this text, omit it.

OMIT ANY VALUE THAT IS NOT A REAL OBSERVED ARTEFACT. Specifically omit: \
redacted or partially redacted values, anything containing angle brackets or \
ellipses, illustrative examples such as evil.com or example.com, RFC1918 and \
loopback addresses used in lab writeups, and digests of empty or placeholder \
input. An empty array is a correct and expected answer. Never fill a field to \
avoid leaving it empty.

SEPARATE ATTACKER ARTEFACTS FROM ABUSED LEGITIMATE ONES. A path, process, or \
key only belongs in an attacker_* field if the article says the attacker \
created, dropped, or controls it. If the article describes the attacker abusing \
software that is legitimately present on a normal system - a debugger, a shell, \
a signed system binary, a package manager - put its name in abused_legitimate \
and nowhere else. This distinction is critical: the consuming system treats \
attacker_* values as things that should not exist on a clean machine.

REFANG defanged notation: evil[.]com becomes evil.com, hxxp becomes http.

EXCLUDE the publishing vendor's own domains, cited reference links, social \
media links, and any infrastructure belonging to the researchers.

PREFER SPECIFICITY. A full absolute path is worth more than a bare filename. A \
full registry path is worth more than a hive name. If only a vague reference \
exists, omit it rather than guessing the rest.

If the article is not primary threat research containing concrete artefacts - \
if it is a product announcement, an opinion piece, a conference recap, or a \
listing page - set is_threat_research to false and leave every array empty.\
"""

EXTRACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "is_threat_research": {
            "type": "boolean",
            "description": "True only for primary research containing concrete artefacts.",
        },
        "threat_name": {
            "type": "string",
            "description": "Malware family, tool, or campaign name as written. Empty if unnamed.",
        },
        "platforms": {
            "type": "array", "items": {"type": "string"},
            "description": "Operating systems the article says are affected.",
        },
        "attack_technique_ids": {
            "type": "array", "items": {"type": "string"},
            "description": "MITRE ATT&CK technique IDs stated in the article, e.g. T1053.005.",
        },
        "attacker_file_paths": {
            "type": "array", "items": {"type": "string"},
            "description": "Absolute paths the attacker created or dropped.",
        },
        "attacker_process_names": {
            "type": "array", "items": {"type": "string"},
            "description": "Names of attacker-controlled binaries or services.",
        },
        "registry_keys": {
            "type": "array", "items": {"type": "string"},
            "description": "Full registry paths the attacker created or modified.",
        },
        "domains": {
            "type": "array", "items": {"type": "string"},
            "description": "Attacker-controlled domains, refanged.",
        },
        "ipv4": {
            "type": "array", "items": {"type": "string"},
            "description": "Attacker-controlled IPv4 addresses, refanged.",
        },
        "sha256": {
            "type": "array", "items": {"type": "string"},
            "description": "SHA-256 digests of attacker samples. Omit other hash lengths.",
        },
        "cves": {
            "type": "array", "items": {"type": "string"},
            "description": "CVE identifiers the article says were exploited.",
        },
        "abused_legitimate": {
            "type": "array", "items": {"type": "string"},
            "description": "Legitimate software the attacker abused rather than installed.",
        },
        "persistence_mechanisms": {
            "type": "array", "items": {"type": "string"},
            "description": "One short phrase per mechanism describing how it survives reboot.",
        },
        "detection_guidance": {
            "type": "array", "items": {"type": "string"},
            "description": "Concrete, checkable detection advice. One idea per string.",
        },
    },
    "required": ["is_threat_research"],
}

# Which schema field feeds which indicator kind in the store.
FIELD_KINDS = {
    "attacker_file_paths": "path",
    "attacker_process_names": "process",
    "registry_keys": "regkey",
    "domains": "domain",
    "ipv4": "ipv4",
    "sha256": "sha256",
    "attack_technique_ids": "attack",
    "cves": "cve",
}


class IntelError(RuntimeError):
    pass


class BudgetExceeded(IntelError):
    pass


# A metered API on a 24/7 timer is a standing invitation to a surprise bill, so
# spend is capped per day and the cap is enforced before each query rather than
# reported after the fact.
DEFAULT_DAILY_BUDGET = 0.50


def _today():
    return time.strftime("%Y%m%d")


def daily_budget():
    try:
        with open(CONFIG_PATH, errors="replace") as fh:
            return float(json.load(fh).get("daily_budget", DEFAULT_DAILY_BUDGET))
    except (OSError, ValueError, TypeError):
        return DEFAULT_DAILY_BUDGET


def spent_today(store):
    return float(store.get_meta(f"intel_spend_{_today()}", 0) or 0)


def _charge(store, amount):
    key = f"intel_spend_{_today()}"
    store.set_meta(key, round(spent_today(store) + float(amount or 0), 4))


# ── credentials ───────────────────────────────────────────────────────────

def load_key():
    """API key from the environment, else from a 0600 file outside the repo.

    The repository is public. The key never goes in a tracked file, and the
    config lives beside the database in ~/.jarvis rather than in the checkout.
    """
    env = os.environ.get("JARVIS_EXA_KEY", "").strip()
    if env:
        return env
    try:
        with open(CONFIG_PATH, errors="replace") as fh:
            return (json.load(fh).get("exa_api_key") or "").strip()
    except (OSError, ValueError):
        return ""


def save_key(key):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    cfg = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, errors="replace") as fh:
                cfg = json.load(fh)
        except ValueError:
            cfg = {}
    cfg["exa_api_key"] = key.strip()
    fd = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(cfg, fh, indent=2)
    os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
    return CONFIG_PATH


# ── transport ─────────────────────────────────────────────────────────────

def _post(payload, key, timeout=90):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        API_URL, data=body, method="POST",
        headers={"x-api-key": key, "Content-Type": "application/json",
                 "User-Agent": "jarvis-intel/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise IntelError(f"HTTP {exc.code}: {detail}") from None
    except urllib.error.URLError as exc:
        raise IntelError(f"network error: {exc.reason}") from None
    except (TimeoutError, OSError) as exc:
        raise IntelError(f"request failed: {exc}") from None


def search(query, key, num_results=6, days=365, domains=None):
    """One Exa search with structured extraction attached to every result."""
    start = time.strftime(
        "%Y-%m-%dT00:00:00.000Z", time.gmtime(time.time() - days * 86400))
    payload = {
        "query": query,
        "type": "auto",
        "numResults": max(1, min(int(num_results), 25)),
        "startPublishedDate": start,
        "includeDomains": domains if domains is not None else SOURCES,
        "contents": {
            "summary": {"query": EXTRACTION_PROMPT, "schema": EXTRACTION_SCHEMA},
        },
    }
    return _post(payload, key)


# ── ingestion ─────────────────────────────────────────────────────────────

def _parse_summary(raw):
    """Extraction comes back as a JSON string. Anything else is discarded."""
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def _as_list(value):
    """Fields come back as null, a string, or a list depending on the article."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str) and v.strip()]
    return []


def ingest_result(store, result, topic, query, stats):
    """Vet one article's extraction and fold the survivors into the store."""
    url = (result.get("url") or "").strip()
    if not url:
        return 0
    data = _parse_summary(result.get("summary"))
    if not data:
        stats["unparsed"] += 1
        return 0
    if not data.get("is_threat_research"):
        stats["not_research"] += 1
        return 0

    ts = now()
    threat = (data.get("threat_name") or "").strip()[:120]
    context_bits = _as_list(data.get("persistence_mechanisms"))[:2]
    context = (threat + (" — " if threat and context_bits else "")
               + "; ".join(context_bits))[:400]

    kept = 0
    for field, kind in FIELD_KINDS.items():
        for raw in _as_list(data.get(field))[:60]:
            k = kind
            # A ".so"/".ko" named as a process is really a file to hunt for,
            # not a process to match — reroute rather than discard it.
            if kind == "process" and raw.strip().lower().endswith(
                    (".so", ".ko", ".dll", ".dylib")):
                k = "filename"
            norm, why = vet.vet(k, raw)
            stats["seen"] += 1
            if not norm:
                stats["rejected"] += 1
                stats["reasons"][why] = stats["reasons"].get(why, 0) + 1
                continue
            # ATT&CK ids and CVEs describe technique, not attacker
            # infrastructure, so they are always safe to keep at high
            # confidence. Everything else starts as a lead, not a verdict.
            conf = "high" if k in ("attack", "cve", "sha256") else "medium"
            store.db.execute(
                """INSERT INTO indicators(kind,value,norm,confidence,topic,
                                          context,source_url,first_seen,last_seen)
                   VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(kind,norm) DO UPDATE SET
                       last_seen=excluded.last_seen,
                       doc_count=indicators.doc_count+1""",
                (k, raw[:512], norm, conf, topic, context, url, ts, ts),
            )
            kept += 1
            stats["kept"] += 1

    store.db.execute(
        """INSERT INTO intel_docs(url,title,published,topic,query,fetched_at,
                                  text_len,n_indicators)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(url) DO UPDATE SET
               fetched_at=excluded.fetched_at,
               n_indicators=excluded.n_indicators""",
        (url, (result.get("title") or "")[:300],
         (result.get("publishedDate") or "")[:32], topic, query[:300],
         ts, len(result.get("text") or ""), kept),
    )
    stats["docs"] += 1
    return kept


def refresh(store, topics=None, per_query=6, days=365, key=None, on_progress=None):
    """Run part of the corpus and ingest what comes back.

    Defaults to a single topic per call so the daemon spreads cost over time
    rather than spending the whole corpus in one burst.
    """
    key = key or load_key()
    if not key:
        raise IntelError(
            "no Exa API key configured — run: jarvis intel --set-key <key>")

    budget = daily_budget()
    already = spent_today(store)
    if already >= budget:
        raise BudgetExceeded(
            f"daily API budget reached (${already:.3f} of ${budget:.2f}) — "
            f"raise `daily_budget` in {CONFIG_PATH} or wait for tomorrow")

    names = list(topics) if topics else [_next_topic(store)]
    stats = {"seen": 0, "kept": 0, "rejected": 0, "docs": 0, "unparsed": 0,
             "not_research": 0, "queries": 0, "errors": [], "cost": 0.0,
             "reasons": {}, "topics": names}

    for topic in names:
        for query in CORPUS.get(topic, []):
            if on_progress:
                on_progress(topic, query)
            if spent_today(store) >= budget:
                stats["errors"].append(
                    f"stopped early: daily budget ${budget:.2f} reached")
                break
            try:
                res = search(query, key, num_results=per_query, days=days)
            except IntelError as exc:
                stats["errors"].append(f"{topic}: {exc}")
                continue
            stats["queries"] += 1
            cost = float((res.get("costDollars") or {}).get("total") or 0.0)
            stats["cost"] += cost
            _charge(store, cost)
            for result in res.get("results", []):
                ingest_result(store, result, topic, query, stats)
            store.commit()
        store.set_meta(f"intel_topic_{topic}", now())

    store.set_meta("intel_last_refresh", now())
    store.set_meta("intel_spend_total",
                   round(float(store.get_meta("intel_spend_total", 0) or 0)
                         + stats["cost"], 4))
    store.commit()
    return stats


def daemon_options(store):
    """Bounded Exa breadth for unattended refreshes.

    The daily dollar brake remains authoritative. These knobs let a user buy
    broader/fresher intelligence without changing code or allowing an
    unbounded scheduled search.
    """
    try:
        with open(CONFIG_PATH, errors="replace") as fh:
            conf = json.load(fh) or {}
    except (OSError, ValueError):
        conf = {}
    try:
        topic_count = max(1, min(int(conf.get("intel_topics_per_run", 2)), 6))
    except (TypeError, ValueError):
        topic_count = 2
    try:
        results = max(1, min(int(conf.get("intel_results_per_query", 6)), 25))
    except (TypeError, ValueError):
        results = 6
    try:
        days = max(7, min(int(conf.get("intel_lookback_days", 365)), 1825))
    except (TypeError, ValueError):
        days = 365
    ages = []
    for topic in CORPUS:
        last = int(store.get_meta(f"intel_topic_{topic}", 0) or 0)
        ages.append((last, topic))
    ages.sort()
    return {
        "topics": [topic for _last, topic in ages[:topic_count]],
        "per_query": results,
        "days": days,
    }


def _next_topic(store):
    """Least recently refreshed topic, so the corpus rotates on its own."""
    ages = []
    for topic in CORPUS:
        last = int(store.get_meta(f"intel_topic_{topic}", 0) or 0)
        ages.append((last, topic))
    ages.sort()
    return ages[0][1]


def revet(store):
    """Re-judge every stored indicator against the current rules.

    The gate gets tighter as bad extractions are found. Without this, the first
    poisoned batch stays live forever and the knowledge base is only ever as
    good as the rules on the day it was fetched.
    """
    stats = {"checked": 0, "dropped": 0, "moved": 0, "reasons": {}}
    rows = store.db.execute(
        "SELECT id, kind, value, norm, status FROM indicators").fetchall()
    for r in rows:
        stats["checked"] += 1
        kind = r["kind"]
        raw = r["value"]
        if kind == "process" and raw.strip().lower().endswith(
                (".so", ".ko", ".dll", ".dylib")):
            kind = "filename"
        norm, why = vet.vet(kind, raw)
        if not norm:
            if r["status"] != "rejected":
                store.db.execute(
                    "UPDATE indicators SET status='rejected' WHERE id=?", (r["id"],))
                stats["dropped"] += 1
                stats["reasons"][why] = stats["reasons"].get(why, 0) + 1
            continue
        if kind != r["kind"] or norm != r["norm"]:
            # Moving a row can collide with an existing one; drop it if so.
            try:
                store.db.execute(
                    "UPDATE indicators SET kind=?, norm=?, status='active' WHERE id=?",
                    (kind, norm, r["id"]))
                stats["moved"] += 1
            except Exception:
                store.db.execute("DELETE FROM indicators WHERE id=?", (r["id"],))
        elif r["status"] == "rejected":
            store.db.execute(
                "UPDATE indicators SET status='active' WHERE id=?", (r["id"],))
    store.commit()
    return stats


def summary(store):
    """What the knowledge base currently holds."""
    rows = store.db.execute(
        "SELECT kind, COUNT(*) n FROM indicators WHERE status='active' "
        "GROUP BY kind ORDER BY n DESC").fetchall()
    docs = store.db.execute("SELECT COUNT(*) n FROM intel_docs").fetchone()["n"]
    return {
        "docs": docs,
        "by_kind": {r["kind"]: r["n"] for r in rows},
        "total": sum(r["n"] for r in rows),
        "last_refresh": int(store.get_meta("intel_last_refresh", 0) or 0),
        "spend": float(store.get_meta("intel_spend_total", 0) or 0),
        "spend_today": spent_today(store),
        "budget": daily_budget(),
    }
