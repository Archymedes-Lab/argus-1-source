"""Evaluate stored indicators against what is actually on this machine.

intel.py answers "what is being used against machines like this one?".
This module answers the only question that matters: "is any of it here?"

Every check is a comparison against state jarvis already collects — the process
baseline, the peer table, the filesystem — so a hunt costs almost nothing and
can run often. Indicators are compared as opaque data: never executed, never
interpolated into a shell, never used to build a command.

False positives are the failure mode that kills a tool like this, so matching
is exact and a second local check runs before anything is reported:

  * a path that exists is only reported if the package manager does not own it
  * a process name must match exactly, not as a substring
  * a hash match is reported at critical because a 256-bit collision is not a
    false positive

The ATT&CK side is different in kind. Technique IDs cannot be "found" on a
host, so instead they are compared against what jarvis's own collectors check,
turning current intel into a gap list for the tool itself. coverage.py asks
whether jarvis is running; gaps() asks whether it is looking at the right
things.
"""

import ipaddress
import os
import subprocess

from . import vet
from .detect import TRUSTED_PATHS
from .store import Store
from .util import dpkg_owns, now

# Which jarvis audit covers which ATT&CK technique. Parent technique ids cover
# their sub-techniques unless a sub-technique is listed on its own.
COVERAGE = {
    "T1014":     "hidden / evasion — rootkit detection",
    "T1055":     "hidden — process injection artefacts",
    "T1027":     "detect — obfuscated/encoded command lines",
    "T1036":     "detect — masquerading (name vs executable)",
    "T1053":     "control — scheduled tasks and cron",
    "T1543":     "control — service and systemd unit creation",
    "T1547":     "control / startup — boot and logon autostart",
    "T1546":     "asep — event-triggered execution",
    "T1574":     "asep — hijacked execution flow",
    "T1562":     "control — impaired defenses",
    "T1564":     "evasion — hidden files, streams and artefacts",
    "T1070":     "evasion — indicator removal and log tampering",
    "T1056":     "spy — input capture",
    "T1113":     "spy — screen capture",
    "T1123":     "spy — audio capture",
    "T1125":     "spy — video capture",
    "T1021":     "firewall — remote services and inbound access",
    "T1571":     "firewall / peers — non-standard ports",
    "T1090":     "firewall — proxy and tunnelling",
    "T1071":     "monitor — application layer C2 egress",
    "T1059":     "detect — command and scripting interpreter",
    "T1105":     "detect — ingress tool transfer (download-and-run)",
    "T1204":     "intrusion — user execution artefacts",
    "T1219":     "control — remote access software",
    "T1218":     "detect / asep — signed binary proxy execution",
    "T1620":     "hidden — in-memory / reflective loading",
    "T1497":     "hidden — sandbox and analysis evasion",
    "T1082":     "scan — system information discovery",
    # Closed by the modules added alongside the intel engine.
    "T1556":     "implant / backdoor — PAM stack and auth configuration",
    "T1553":     "implant — root certificate trust store",
    "T1557":     "netwatch — gateway MAC and DNS changes",
    "T1090":     "implant — proxy, PAC and portproxy",
    "T1548":     "backdoor — sudo, setuid and elevation grants",
    "T1098":     "backdoor / posture — account and group inventory",
    "T1136":     "backdoor — new and hidden accounts",
    "T1078":     "backdoor / posture — account inventory",
    "T1133":     "backdoor / firewall — external remote services",
    "T1176":     "intrusion — browser extension artefacts",
    "T1518":     "posture — installed defenses and their state",
    "T1600":     "implant — cryptographic trust weakening",
    "T1595":     "netwatch — wireless association history",
    # Added with the bruteforce collector and by wiring existing modules to the
    # techniques they already answer.
    "T1110":     "bruteforce — failed-auth spikes and account lockouts",
    "T1552":     "secrets — plaintext credentials on disk (files, history, config)",
    "T1539":     "intrusion — browser session and cookie theft artefacts",
    "T1555.003": "intrusion — browser credential stores",
    "T1003.001": "sysmon — LSASS process-access events (Windows, needs Sysmon)",
    "T1040":     "sniffing — promiscuous NICs, raw sockets, capture drivers/tools",
    "T1197":     "intrusion — BITS transfer jobs outside the known updaters",
    "T1505.003": "webshell — dispatcher-shaped scripts in web document roots",
    "T1112":     "asep / control / posture — autostart and security-relevant "
                 "registry surface",
    # Added with the toolchain collector: the developer trust surface, where
    # execution comes from a config file rather than from a service or a key.
    "T1176":     "toolchain / intrusion — software extensions",
    "T1176.001": "intrusion — browser extension artefacts",
    "T1176.002": "toolchain — IDE/editor extension inventory, version drift and "
                 "post-install modification",
    "T1195.001": "toolchain — package registry and index redirection "
                 "(~/.npmrc, pip.conf)",
    "T1546.016": "toolchain — executable .pth lines that run on every Python "
                 "interpreter start",
    "T1059.006": "toolchain / sysmon_linux — Python execution, including "
                 "site-triggered startup code",
}

# Techniques worth naming explicitly as uncovered when intel raises them, with
# the reason they are hard rather than merely missing.
KNOWN_BLIND = {
    "T1555": "credential stores beyond browsers — Windows Credential Manager "
             "and OS keyrings are not read",
    # Narrowed by the toolchain collector, not closed: registry redirection,
    # editor-extension drift and repo-supplied agent/MCP/git hooks are checked,
    # but the contents of an installed package are still taken on trust.
    "T1195": "supply chain compromise — package *sources* and developer-tool "
             "configuration are audited by `toolchain`, but installed package "
             "contents are not verified against their publisher",
    "T1554": "compromised host binary — no integrity baseline for system files",
    "T1505": "server software component — no web/server module auditing",
    "T1567": "exfiltration to web service — egress is seen but not classified",
    "T1611": "container escape — no container runtime auditing",
    "T1610": "malicious container deployment — no container runtime auditing",
    "T1003": "credential dumping beyond LSASS memory (SAM, LSA secrets, NTDS, "
             "DCSync) — sysmon covers LSASS access; the rest needs "
             "registry/file/replication auditing",
}


def _finding(category, severity, title, detail, where="", host="wsl"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def _win_to_wsl(path):
    """C:\\Users\\x -> /mnt/c/Users/x so Windows paths are checkable from here."""
    p = path.replace("\\", "/")
    if len(p) > 2 and p[1] == ":" and p[2] == "/":
        return "/mnt/" + p[0].lower() + p[2:]
    return None


_dpkg_owns = dpkg_owns


def _sha256(path, cap=256 * 1024 * 1024):
    import hashlib
    try:
        if os.path.getsize(path) > cap:
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, ValueError):
        return ""


def _hash_cached(store, path):
    """Hash a file, reusing the stored digest while size and mtime are unchanged."""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    row = store.db.execute(
        "SELECT sha256,size,mtime FROM file_hashes WHERE path=?", (path,)
    ).fetchone()
    if row and row["size"] == st.st_size and row["mtime"] == int(st.st_mtime):
        return row["sha256"]
    digest = _sha256(path)
    if digest:
        store.db.execute(
            """INSERT INTO file_hashes(path,sha256,size,mtime,hashed_at)
               VALUES(?,?,?,?,?)
               ON CONFLICT(path) DO UPDATE SET
                   sha256=excluded.sha256, size=excluded.size,
                   mtime=excluded.mtime, hashed_at=excluded.hashed_at""",
            (path, digest, st.st_size, int(st.st_mtime), now()))
    return digest


def _active(store, kind):
    return store.db.execute(
        "SELECT norm, value, source_url, context, doc_count FROM indicators "
        "WHERE kind=? AND status='active'", (kind,)).fetchall()


# ── the checks ────────────────────────────────────────────────────────────

def check_peers(store):
    """Do any recorded network peers match attacker infrastructure?

    Written as indexed joins rather than by loading indicators into Python.
    At a few thousand records the difference is invisible; at half a million it
    is the difference between a hunt that runs every half hour and one that
    reads a hundred megabytes into memory to answer a question SQLite can
    answer from an index.
    """
    out = []

    # Addresses: one join, served entirely from the (kind, norm) unique index.
    for r in store.db.execute(
            """SELECT p.remote_ip ip, p.remote_port port, p.host host,
                      pr.name pname, i.context ctx, i.source_url src,
                      i.malware fam, i.source feed, i.confidence confidence
                 FROM peers p
                 JOIN indicators i
                   ON i.kind='ipv4' AND i.norm = p.remote_ip
                      AND i.status='active'
                LEFT JOIN procs pr ON pr.fp = p.fp
                WHERE p.scope='public'"""):
        # Re-vet at match time as well as ingestion time. The corpus is
        # persistent, so a newly learned shared-infrastructure exclusion must
        # take effect immediately rather than waiting for a manual re-vet.
        if not vet.vet_ipv4(r["ip"])[0]:
            continue
        label = r["fam"] or r["ctx"] or "listed in threat intelligence"
        severity = "critical" if r["confidence"] == "high" else "medium"
        qualifier = "known attacker" if severity == "critical" else "threat-intelligence"
        out.append(_finding(
            "c2 match", severity,
            f"contacted a {qualifier} IP: {r['ip']}",
            f"{r['pname'] or 'unknown process'} → {r['ip']}:{r['port']} — "
            f"{label} (via {r['feed']})", r["src"], r["host"]))

    # Domains: exact reverse-DNS match, then parent domains. Only the distinct
    # rdns values are walked, and each parent is a single index probe, so this
    # stays a few thousand lookups no matter how large the indicator set is.
    rdns_rows = store.db.execute(
        "SELECT DISTINCT rdns FROM peers WHERE scope='public' AND rdns != ''"
    ).fetchall()
    matched = {}
    for row in rdns_rows:
        host = (row["rdns"] or "").lower().rstrip(".")
        parts = host.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if not vet.vet_domain(parent)[0]:
                continue
            hit = store.db.execute(
                "SELECT context, source_url, malware, source, confidence FROM indicators "
                "WHERE kind='domain' AND norm=? AND status='active'",
                (parent,)).fetchone()
            if hit:
                matched[host] = (parent, hit)
                break
    for host, (parent, hit) in matched.items():
        severity = "critical" if hit["confidence"] == "high" else "medium"
        qualifier = "known attacker" if severity == "critical" else "threat-intelligence"
        for p in store.db.execute(
                """SELECT p.remote_ip ip, p.remote_port port, p.host host,
                          pr.name pname FROM peers p
                     LEFT JOIN procs pr ON pr.fp = p.fp
                    WHERE p.scope='public' AND lower(p.rdns) LIKE ?""",
                (host + "%",)):
            label = hit["malware"] or hit["context"] or "listed in threat intelligence"
            out.append(_finding(
                "c2 match", severity,
                f"contacted a {qualifier} domain: {parent}",
                f"{p['pname'] or 'unknown process'} → {host} "
                f"({p['ip']}:{p['port']}) — {label} (via {hit['source']})",
                hit["source_url"], p["host"]))

    # Ranges cannot be indexed by value, so they are bucketed by first octet.
    # A peer then only has to be tested against the handful of networks that
    # could possibly contain it instead of all of them.
    buckets = {}
    for r in _active(store, "cidr"):
        try:
            net = ipaddress.ip_network(r["norm"])
        except ValueError:
            continue
        if net.version != 4:
            continue
        first = int(str(net.network_address).split(".")[0])
        buckets.setdefault(first, []).append((net, r))
    if buckets:
        for p in store.db.execute(
                """SELECT p.remote_ip ip, p.remote_port port, p.host host,
                          pr.name pname FROM peers p
                     LEFT JOIN procs pr ON pr.fp = p.fp
                    WHERE p.scope='public'"""):
            try:
                addr = ipaddress.ip_address(p["ip"])
            except ValueError:
                continue
            if addr.version != 4:
                continue
            for net, hit in buckets.get(int(str(addr).split(".")[0]), ()):
                if addr in net:
                    out.append(_finding(
                        "c2 match", "high",
                        f"contacted a host in a flagged network: {net}",
                        f"{p['pname'] or 'unknown process'} → "
                        f"{p['ip']}:{p['port']} — "
                        f"{hit['context'] or 'listed range'}",
                        hit["source_url"], p["host"]))
                    break
    return out


# Directories under C:\Windows that any user or service can write to. A
# Microsoft-signed binary sitting in one of these is still a drop — attackers
# bring signed hosts along to sideload from — so a signature does not clear it.
_WIN_WRITABLE = ("c:/windows/temp/", "c:/windows/tasks/", "c:/windows/tracing/",
                 "c:/windows/debug/", "c:/windows/registration/crmlog/",
                 "c:/windows/system32/spool/", "c:/windows/system32/tasks/")


# Files every Debian/Ubuntu system has but dpkg does not register (created by
# maintainer scripts or the installer). Detection writeups name them as the
# thing an attacker modifies, which says nothing about whether they exist.
_STOCK_UNREGISTERED = frozenset((
    "/etc/profile", "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/etc/fstab",
    "/etc/sudoers", "/etc/crontab", "/etc/environment", "/etc/ld.so.cache",
    "/etc/machine-id", "/etc/shells", "/etc/os-release"))


def _win_norm(path):
    p = path.replace("\\", "/")
    while "//" in p:
        p = p.replace("//", "/")
    return p.lower()


def _microsoft_signed(paths):
    """Subset of Windows paths carrying a valid Microsoft Authenticode signature.

    Writeups name stock binaries (rundll32, dllhost, explorer) that malware
    abuses, and the feed records them as attacker paths. The file existing is
    then meaningless. Paths come from feeds, so they travel as base64 JSON and
    are never interpolated into the script.
    """
    if not paths:
        return set()
    import base64
    import json
    from .collect_windows import ps_json
    blob = base64.b64encode(json.dumps(sorted(paths)).encode()).decode()
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{blob}'))"
        "|ConvertFrom-Json;"
        "$ok=@(foreach($x in $p){$s=Get-AuthenticodeSignature -LiteralPath $x;"
        "if($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match "
        "'O=Microsoft Corporation'){$x}});"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json -InputObject $ok -Compress)))")
    result = ps_json(script, timeout=60)
    if isinstance(result, str):
        result = [result]
    return set(result) if isinstance(result, list) else set()


def check_paths(store):
    """Does any attacker-dropped path actually exist here?"""
    out = []
    stock = {}      # windows path -> finding args, pending a signature check
    for r in _active(store, "path"):
        raw = r["norm"]
        candidates = []
        if raw.startswith("/"):
            candidates.append(("wsl", raw))
        win = _win_to_wsl(raw)
        if win:
            candidates.append(("win", win))
        for host, path in candidates:
            try:
                if not os.path.lexists(path):
                    continue
                if os.path.isdir(path) or not (
                        os.path.isfile(path) or os.path.islink(path)):
                    continue        # sockets, fifos and devices are not payloads
            except (OSError, ValueError):
                continue
            if host == "wsl" and path in _STOCK_UNREGISTERED:
                continue        # exists on every system; tampering is audited elsewhere
            if host == "wsl" and _dpkg_owns(path):
                continue        # a package owns it: present by design
            finding = _finding(
                "dropped file", "high",
                f"a file named in threat intelligence exists here: {raw}",
                (r["context"] or "listed as an attacker-created path")
                + " — verify before deleting; the name may simply collide",
                r["source_url"], host)
            norm = _win_norm(raw)
            if (host == "win" and norm.startswith("c:/windows/")
                    and not norm.startswith(_WIN_WRITABLE)):
                stock.setdefault(raw.replace("\\\\", "\\"), []).append(finding)
            else:
                out.append(finding)
    signed = _microsoft_signed(set(stock))
    for path, findings in stock.items():
        if path not in signed:
            out.extend(findings)    # unsigned or unverifiable: still report
    return out


def check_processes(store):
    """Has anything with an attacker-associated name ever run here?

    This is the weakest indicator class by a wide margin. A writeup naming a
    binary the attacker abused puts that name in the feed, and if the name
    belongs to real software the match is meaningless. The first live run
    produced 1500 findings for `wslhost.exe` on exactly this mistake.

    So a name match alone is not evidence. It is only reported when the binary
    is somewhere a legitimate copy would not be — the same reasoning the path
    check applies with dpkg, and the reason severity here is capped below the
    hash and infrastructure checks.
    """
    out = []
    names = {r["norm"]: r for r in _active(store, "process")}
    if not names:
        return out
    for row in store.db.execute(
            "SELECT name, exe, host, cmdline, last_seen FROM procs"):
        name = (row["name"] or "").lower()
        stem = name.rsplit(".", 1)[0] if "." in name else name
        hit = names.get(name) or names.get(stem)
        if not hit:
            continue
        exe = (row["exe"] or "").lower().replace("\\", "/")
        if exe.startswith(TRUSTED_PATHS):
            continue        # the real binary, in the place it belongs
        sev = "high" if exe else "medium"
        out.append(_finding(
            "named process", sev,
            f"a process matching a known malware name ran: {row['name']}",
            (hit["context"] or "name listed in threat intelligence")
            + f" — {(row['cmdline'] or '')[:110]}",
            hit["source_url"] or (row["exe"] or ""), row["host"]))
    return out


def check_hashes(store, limit=1500):
    """Hash the executables jarvis has seen and compare against sample digests."""
    out = []
    have = store.db.execute(
        "SELECT 1 FROM indicators WHERE kind='sha256' AND status='active' "
        "LIMIT 1").fetchone()
    if not have:
        return out
    seen = set()
    rows = store.db.execute(
        "SELECT DISTINCT exe, host FROM procs WHERE exe LIKE '/%' "
        "ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
    for row in rows:
        path = row["exe"]
        if not path or path in seen:
            continue
        seen.add(path)
        digest = _hash_cached(store, path)
        if not digest:
            continue
        hit = store.db.execute(
            "SELECT context, source_url, malware, source FROM indicators "
            "WHERE kind='sha256' AND norm=? AND status='active'",
            (digest,)).fetchone()
        if hit:
            label = hit["malware"] or hit["context"] or "listed in threat intelligence"
            out.append(_finding(
                "sample match", "critical",
                f"a file here matches a known malware sample: {os.path.basename(path)}",
                f"SHA-256 {digest} — {label} (via {hit['source']})",
                path, row["host"]))
    store.commit()
    return out


# Where a payload named only by filename has to live in order to work. A PAM
# backdoor must be on the PAM module path; a preloaded object must be findable
# by the loader; a rootkit module must be under the module tree. Hunting only
# these keeps the check bounded and cheap — a whole-filesystem sweep for
# attacker filenames would be both slow and a false-positive machine.
FILENAME_DIRS = (
    "/lib/security", "/usr/lib/security", "/lib/x86_64-linux-gnu/security",
    "/usr/lib/x86_64-linux-gnu/security", "/usr/local/lib", "/usr/local/bin",
    "/etc", "/etc/systemd/system", "/lib/systemd/system", "/etc/cron.d",
    "/tmp", "/var/tmp", "/dev/shm", "/run", "/opt", "/usr/lib/modules",
)


def check_filenames(store, max_entries=40000):
    """Look for attacker-named files in the places such payloads must live."""
    out = []
    names = {r["norm"]: r for r in _active(store, "filename")}
    if not names:
        return out

    scanned = 0
    for root in FILENAME_DIRS:
        if not os.path.isdir(root):
            continue
        # /lib/modules is deep and huge; everything else is one level.
        depth_cap = 3 if "modules" in root else 1
        base_depth = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if dirpath.rstrip("/").count("/") - base_depth >= depth_cap:
                dirnames[:] = []
            for fn in filenames:
                scanned += 1
                if scanned > max_entries:
                    return out
                hit = names.get(fn.lower())
                if not hit:
                    continue
                full = os.path.join(dirpath, fn)
                if _dpkg_owns(full):
                    continue
                out.append(_finding(
                    "dropped file", "high",
                    f"a file named in threat intelligence is present: {fn}",
                    (hit["context"] or "filename listed in threat intelligence")
                    + " — no package owns this file",
                    full, "wsl"))
    return out


def _aggregate(findings):
    """Collapse repeats of one indicator into a single counted finding.

    The same C2 address seen by nineteen browser tabs is one fact, not
    nineteen. Reporting it nineteen times buries whatever else the hunt found.
    """
    groups = {}
    for f in findings:
        key = (f["category"], f["title"], f["host"])
        if key in groups:
            groups[key]["_n"] += 1
        else:
            groups[key] = {**f, "_n": 1}
    out = []
    for g in groups.values():
        n = g.pop("_n")
        if n > 1:
            g["detail"] = f"{g['detail']}  [seen {n}×]"
        out.append(g)
    return out


def hunt(store, hosts=("wsl", "win")):
    """Run every indicator check and record the hits."""
    findings = []
    for fn in (check_peers, check_paths, check_filenames, check_processes,
               check_hashes):
        try:
            findings += fn(store)
        except Exception as exc:      # one broken check must not hide the rest
            findings.append(_finding(
                "hunt", "medium", f"{fn.__name__} failed", str(exc)))
    findings = [f for f in findings if f["host"] in hosts or f["host"] == "wsl"]
    findings = _aggregate(findings)

    ts = now()
    for f in findings:
        if f["category"] == "hunt":
            continue
        store.db.execute(
            """INSERT INTO hunt_hits(ts,kind,value,host,severity,evidence,source_url)
               VALUES(?,?,?,?,?,?,?)""",
            (ts, f["category"], f["title"][:300], f["host"], f["severity"],
             f["detail"][:600], f["where"][:400]))
    store.set_meta("hunt_last_run", ts)
    store.commit()
    return findings


# Tactics whose techniques are defined by runtime behaviour rather than by
# anything left on disk. A monitor that samples state on an interval cannot
# see them at all — that is the sampling blind spot coverage.py already
# reports, not a missing collector. Listing them as work to do would bury the
# gaps that could actually be closed.
BEHAVIOURAL_TACTICS = {
    "discovery", "collection", "execution", "impact", "exfiltration",
    "lateral-movement", "privilege-escalation", "reconnaissance",
    "resource-development", "initial-access",
}

_INTERCEPT = None


def _intercept_active():
    """(active, name) — is a syscall-interception layer recording on this box?

    auditd or Sysmon for Linux (eBPF). When one is, the behavioural bucket is
    covered rather than merely unobservable. Probed once per process.
    """
    global _INTERCEPT
    if _INTERCEPT is None:
        _INTERCEPT = (False, "")
        for name in ("auditd", "sysmon_linux"):
            try:
                mod = __import__(f"jarvis.{name}", fromlist=[name])
                if mod.active():
                    _INTERCEPT = (True, "auditd" if name == "auditd"
                                  else "Sysmon for Linux")
                    break
            except Exception:
                continue
    return _INTERCEPT


def gaps(store, min_docs=1):
    """Techniques current intel is talking about, against what jarvis checks.

    Three outcomes, and the distinction is the whole point of the report:

      * covered      — a collector already looks for this
      * closeable    — leaves host artefacts, nothing looks for them yet
      * behavioural  — needs syscall interception; no collector here can help

    Only the middle group is a work queue.
    """
    rows = store.db.execute(
        "SELECT norm, doc_count, context, source_url FROM indicators "
        "WHERE kind='attack' AND status='active' AND doc_count>=? "
        "ORDER BY doc_count DESC", (min_docs,)).fetchall()

    cat = {r["tid"]: (r["name"], r["tactics"]) for r in
           store.db.execute("SELECT tid,name,tactics FROM attack_techniques")}

    covered, closeable, behavioural = [], [], []
    for r in rows:
        tid, n = r["norm"], r["doc_count"]
        parent = tid.split(".")[0]
        where = COVERAGE.get(tid) or COVERAGE.get(parent)
        if where:
            covered.append((tid, n, where))
            continue
        name, tactics = cat.get(tid) or cat.get(parent) or ("", "")
        why = (KNOWN_BLIND.get(tid) or KNOWN_BLIND.get(parent)
               or "no collector checks this")
        if not name:
            behavioural.append((tid, n, "deprecated or unrecognised "
                                        "technique id", ""))
            continue
        tset = {t for t in (tactics or "").split(",") if t}
        if tset and tset <= BEHAVIOURAL_TACTICS:
            intercept_on, intercept_name = _intercept_active()
            if intercept_on:
                covered.append((tid, n,
                                f"{intercept_name} — syscall interception active"))
            else:
                behavioural.append((tid, n, "runtime behaviour — needs syscall "
                                            "interception (auditd/Sysmon)", name))
        else:
            closeable.append((tid, n, why, name))

    out = []
    for tid, n, why, name in closeable:
        # Weight by how many separate writeups raised it: a technique three
        # independent teams wrote about this year is a better use of an
        # afternoon than one mentioned once.
        sev = "high" if n >= 5 else "medium" if n >= 2 else "low"
        out.append(_finding(
            "coverage gap", sev, f"{tid} {name}".strip(),
            f"{why} — mentioned in {n} intelligence document{'s' if n > 1 else ''}; "
            "this is a detection coverage gap, not observed activity on this host"))
    for tid, n, why, name in behavioural:
        out.append(_finding(
            "not observable", "low", f"{tid} {name}".strip(),
            f"{why} — mentioned in {n} intelligence document{'s' if n > 1 else ''}; "
            "this is a visibility limitation, not observed activity on this host"))
    return out, covered, closeable


def sort_findings(findings):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    cat = {"c2 match": 0, "sample match": 1, "dropped file": 2,
           "named process": 3, "coverage gap": 4, "hunt": 5}
    return sorted(findings, key=lambda f: (order.get(f["severity"], 9),
                                           cat.get(f["category"], 9), f["title"]))
