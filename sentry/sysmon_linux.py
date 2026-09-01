"""Sysmon for Linux — the eBPF syscall interception WSL2 forces us to.

auditd cannot run on the WSL2 kernel: it rejects the audit daemon over the
netlink socket regardless of privilege. Microsoft's Sysmon for Linux does the
same job through eBPF instead — it hooks execve, connect, ptrace, raw disk
reads and file create/delete, and writes Windows-Sysmon-schema events to the
journal. This reads them incrementally and applies rules adapted to Linux
paths and shapes, the same way `sysmon.py` does for the Windows side.

Install (Ubuntu):

    curl -sSL https://packages.microsoft.com/keys/microsoft.asc \\
      | sudo tee /etc/apt/trusted.gpg.d/microsoft.asc >/dev/null
    echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/$(lsb_release -rs)/prod \\
      $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/microsoft-prod.list
    sudo apt update && sudo apt install -y sysmonforlinux
    sudo sysmon -accepteula -i        # default config; pass a file to tighten

Events land in the journal under the `sysmon` identifier. The daemon reads them
as `chris`, so `chris` must be in the `systemd-journal` or `adm` group (usually
already true on Ubuntu); the module falls back to /var/log/syslog otherwise.
"""

import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from .util import now

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CHANNEL = "journal:sysmon"

WORLD_WRITABLE = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/", "/var/lib/php/")
# Unambiguous web servers only. node/java/python host servers too but also host
# most other things, so a shell under those is not on its own a signal.
WEB_PARENTS = ("nginx", "httpd", "apache2", "php-fpm", "php-cgi", "php",
               "caddy", "lighttpd", "tomcat", "gunicorn", "uwsgi")
SHELLS = ("sh", "bash", "dash", "zsh", "ksh", "ash", "busybox")
RECON_BINS = {"whoami", "id", "uname", "hostname", "hostnamectl", "ifconfig",
              "netstat", "arp", "route", "w", "who", "last", "lastlog",
              "crontab", "lsmod", "nmap", "showmount", "rpcinfo"}
REVSHELL_BINS = {"nc", "ncat", "netcat", "socat", "telnet"}
PERSIST_PATHS = re.compile(
    r"/\.ssh/authorized_keys$|/etc/cron|/var/spool/cron|"
    r"/etc/systemd/system/|/\.config/systemd/user/|/etc/init\.d/|"
    r"/etc/ld\.so\.preload$|/etc/sudoers|/\.bashrc$|/\.bash_profile$|"
    r"/\.profile$|/etc/profile\.d/|/etc/rc\.local$")
# What makes this dangerous is fetched content reaching an interpreter, not the
# mere presence of curl. The old second alternative was `sh -c .* (curl|...)`,
# where `.*` matched a fetch used for anything at all -- an ordinary
# `bash -c '... curl -s https://api/health ...'` tripped it every time. Each
# alternative below now requires the download and the execution to be joined.
DOWNLOAD_RUN = re.compile(
    # fetch piped straight into an interpreter
    r"(curl|wget|fetch)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b|"
    # fetch inside a substitution that is then evaluated
    r"\b(eval|exec|source)\b[^\n]{0,30}\$\(\s*(curl|wget|fetch)\b|"
    # base64 payload decoded into a shell
    r"base64\s+(-d|--decode)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b|"
    # a shell reaching for a raw TCP socket
    r"\b(ba)?sh\b\s+-c\b[^\n]*/dev/tcp/|"
    # python one-liner opening a socket or exec'ing fetched code
    r"python[0-9.]*\s+-c\s+[^\n]{0,80}\b(socket|exec)\b",
    re.I)

# Package-manager layouts under a world-writable root. A JS or Python project
# checked out in /tmp runs binaries out of its own dependency tree constantly;
# that is a dev habit, not a dropper. Still reported -- node_modules is a fine
# place to hide a payload -- but one severity lower, so the genuinely odd case
# of an unparented binary in /tmp stays visible above the noise.
DEV_PKG_PATH = re.compile(
    r"/(node_modules|site-packages|\.venv|venv|\.pnpm|\.cargo|vendor)/")
DEV_PARENTS = ("node", "npm", "npx", "pnpm", "yarn", "bun", "deno", "tsx",
               "python", "python3", "pip", "pip3", "cargo", "go", "make")


def _finding(category, severity, title, detail, where="", host="wsl"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))


# ── posture ─────────────────────────────────────────────────────────────────

def _run(args, timeout=20):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.returncode
    except (OSError, subprocess.SubprocessError):
        return "", 1


def state():
    """(installed, running)."""
    installed = bool(shutil.which("sysmon")) or os.path.exists("/opt/sysmon/sysmon")
    active_out, _ = _run(["systemctl", "is-active", "sysmon"])
    return installed, active_out.strip() == "active"


def active():
    installed, running = state()
    return installed and running


# ── reading events ─────────────────────────────────────────────────────────

def _raw(since_ts):
    """All sysmon journal text since `since_ts`, journal first then syslog."""
    out, rc = _run(["journalctl", "-t", "sysmon", "-o", "cat", "--no-pager",
                    "--since", f"@{int(since_ts)}"], timeout=40)
    if rc == 0 and out.strip():
        return out
    try:
        with open("/var/log/syslog", encoding="utf-8", errors="replace") as fh:
            return "\n".join(ln for ln in fh if "sysmon" in ln.lower())
    except OSError:
        return ""


_TYPE_ID = {
    "processcreate": 1, "process create": 1,
    "networkconnect": 3, "network connection": 3, "networkconnection": 3,
    "processterminate": 5, "process terminated": 5, "processterminated": 5,
    "rawaccessread": 9, "raw access read": 9,
    "processaccess": 10, "process accessed": 10,
    "filecreate": 11, "file created": 11,
    "sysmonconfigstatechanged": 16, "configchange": 16,
    "filedelete": 23, "file delete": 23, "filedeletedetected": 26,
}


def _parse(text):
    """List of {id, ...fields}. Handles the XML form and the key/value form."""
    events = []

    for m in re.finditer(r"<Event\b.*?</Event>", text, re.S):
        blob = re.sub(r'\sxmlns(:\w+)?="[^"]*"', "", m.group(0))
        try:
            root = ET.fromstring(blob)
        except ET.ParseError:
            continue
        sysd, data = root.find("System"), root.find("EventData")
        ev = {"id": int((sysd.findtext("EventID") or 0)) if sysd is not None
              else 0}
        for d in (list(data) if data is not None else []):
            if d.get("Name"):
                ev[d.get("Name")] = (d.text or "").strip()
        if ev["id"]:
            events.append(ev)
    if events:
        return events

    # Key/value block form: a "TypeName:" header line then "  Key: Value" lines,
    # blocks separated by blank lines.
    cur = None
    for line in text.splitlines():
        s = line.strip()
        if not s:
            if cur and cur.get("id"):
                events.append(cur)
            cur = None
            continue
        head = re.match(r"^([A-Za-z][A-Za-z ]+):$", s)
        if head and cur is None:
            cur = {"id": _TYPE_ID.get(head.group(1).strip().lower(), 0)}
            continue
        kv = re.match(r"^([A-Za-z][\w ]*):\s*(.*)$", s)
        if kv and cur is not None:
            cur[kv.group(1).replace(" ", "")] = kv.group(2).strip()
    if cur and cur.get("id"):
        events.append(cur)
    return events


def _clean(v):
    v = (v or "").strip()
    return "" if v in ("-", "<unknown process>", "<unknown>", "") else v


def _base(path):
    path = _clean(path)
    return os.path.basename(path.split()[0]) if path else ""


def _is_public_ip(ip):
    if not ip:
        return False
    if ":" in ip:   # IPv6
        return not ip.lower().startswith(("fe80", "::1", "fc", "fd", "::"))
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a in (10, 127, 0) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return False
    if a == 169 and b == 254:
        return False
    return True


# ── rules ──────────────────────────────────────────────────────────────────

def _is_sentry(e):
    """sentry shells out to ps/ss/ip/journalctl constantly — do not report
    its own activity as reconnaissance or unexplained egress."""
    blob = (str(e.get("ParentCommandLine", "")) + " "
            + str(e.get("CommandLine", "")) + " "
            + str(e.get("ParentImage", ""))).lower()
    return "sentry" in blob or "-m sentry" in blob


def _rules(events, store=None):
    out = []
    recon = {}
    dns_names, dests = set(), set()

    for e in events:
        eid = e.get("id")
        img = _clean(e.get("Image") or e.get("SourceImage"))
        cmd = _clean(e.get("CommandLine"))
        parent = _clean(e.get("ParentImage"))
        base, pbase = _base(img), _base(parent)
        mine = _is_sentry(e)

        if eid == 1:
            # Only the executable's own path counts — a world-writable path in
            # an argument (runc/containerd pass plenty) is not execution from
            # there.
            if img and img.startswith(WORLD_WRITABLE):
                dev = bool(DEV_PKG_PATH.search(img)) and pbase in DEV_PARENTS
                out.append(_finding(
                    "sysmon-linux", "medium" if dev else "high",
                    "process executed from a world-writable directory",
                    f"{img}  «{cmd[:120]}»  parent {pbase or '?'}"
                    + ("  — dependency-tree binary run by its own package "
                       "manager, which is normal for a project under /tmp"
                       if dev else ""), CHANNEL))
            if DOWNLOAD_RUN.search(cmd):
                out.append(_finding(
                    "sysmon-linux", "high", "download-and-run in a command line",
                    f"{pbase or base}: {cmd[:160]}", CHANNEL))
            if pbase in WEB_PARENTS and base in SHELLS:
                out.append(_finding(
                    "sysmon-linux", "critical",
                    f"the web server ({pbase}) spawned a shell",
                    f"{img}  «{cmd[:140]}» — the classic post-exploitation "
                    f"step after a web shell or an RCE", CHANNEL))
            if base in REVSHELL_BINS and re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b|"
                                                   r"-e\b|/dev/tcp", cmd):
                out.append(_finding(
                    "sysmon-linux", "high",
                    f"{base} invoked with a connect-back argument",
                    cmd[:160], CHANNEL))
            if base in RECON_BINS and not mine:
                recon.setdefault(pbase or "?", set()).add(base)

        elif eid == 3:
            dst = e.get("DestinationIp") or ""
            host = e.get("DestinationHostname") or ""
            port = e.get("DestinationPort") or "?"
            if host:
                dns_names.add(host.lower())
            if dst:
                dests.add(dst)
            if _is_public_ip(dst) and not mine and pbase not in (
                    "firefox", "chrome", "chromium", "curl", "wget", "apt",
                    "apt-get", "snap", "snapd", "packagekitd", "systemd",
                    "NetworkManager", "dockerd", "containerd", "git", "gh",
                    "ssh", "sshd", "code", "node", "python3", "bun"):
                out.append(_finding(
                    "sysmon-linux", "medium",
                    f"outbound connection to {dst}:{port}",
                    f"from {base or '?'} ({host or 'no rDNS'}) — confirm this "
                    f"egress is expected", CHANNEL))

        elif eid == 10:
            tgt = e.get("TargetImage") or ""
            ga = (e.get("GrantedAccess") or "").lower()
            if "ptrace" in ga or "/proc/" in tgt or tgt:
                out.append(_finding(
                    "sysmon-linux", "high",
                    "a process read another process's memory",
                    f"{base or '?'} → {_base(tgt) or tgt or '?'} "
                    f"(access {ga or '?'}) — the Linux shape of credential "
                    f"dumping and injection", CHANNEL))

        elif eid == 11:
            tgt = e.get("TargetFilename") or ""
            if PERSIST_PATHS.search(tgt):
                out.append(_finding(
                    "sysmon-linux", "high",
                    "write to a persistence or trust location",
                    f"{base or '?'} created/modified {tgt}", CHANNEL))

        elif eid in (23, 26):
            tgt = e.get("TargetFilename") or ""
            if tgt.startswith("/var/log/") or "/.bash_history" in tgt:
                out.append(_finding(
                    "sysmon-linux", "high", "a log or history file was deleted",
                    f"{base or '?'} deleted {tgt} — indicator removal", CHANNEL))

        elif eid == 9:
            out.append(_finding(
                "sysmon-linux", "high", "raw device read",
                f"{base or '?'} opened {e.get('Device') or 'a block device'} "
                f"for raw access — disk imaging or filesystem-bypass read",
                CHANNEL))

    # Container and build tooling legitimately runs a lot of these.
    build_parents = {"runc", "containerd", "containerd-shim", "dockerd",
                     "docker", "buildkitd", "bun", "node", "npm", "yarn",
                     "make", "cmake", "cargo", "go", "bazel", "ansible-playbook"}
    for pbase, bins in recon.items():
        # An unresolved parent means unattributable — and that bucket is
        # dominated by short-lived system and monitoring processes.
        if pbase and pbase != "?" and pbase not in build_parents and len(bins) >= 5:
            out.append(_finding(
                "sysmon-linux", "medium",
                f"host reconnaissance burst under {pbase}",
                f"{', '.join(sorted(bins))} from one parent in a short window — "
                f"enumeration a sampling monitor would never have caught",
                CHANNEL))

    if store is not None and (dns_names or dests):
        out += _correlate(store, dns_names, dests)
    return out


def _correlate(store, dns_names, dests):
    """Check observed names/IPs against the indicator corpus."""
    out = []
    values = list(dns_names) + list(dests)
    if not values:
        return out
    qmarks = ",".join("?" * len(values))
    try:
        rows = store.db.execute(
            f"SELECT value, kind, malware, source FROM indicators "
            f"WHERE status='active' AND (norm IN ({qmarks}) OR value IN ({qmarks}))",
            values + values).fetchall()
    except Exception:
        return out
    for r in rows:
        out.append(_finding(
            "sysmon-linux", "critical",
            f"a process contacted a known-bad indicator: {r['value']}",
            f"{r['kind']} — {r['malware'] or 'flagged'} (via {r['source']})",
            "threat-intel"))
    return out


# ── entry point ────────────────────────────────────────────────────────────

def _remember(store, findings, hours):
    ts = now()
    for f in findings:
        if f["severity"] == "ok":
            continue
        store.db.execute(
            """INSERT INTO sysmon_hits(ts,category,severity,title,detail,where_)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(category,title,where_) DO UPDATE SET
                   ts=excluded.ts, severity=excluded.severity,
                   detail=excluded.detail""",
            (ts, f["category"], f["severity"], f["title"][:300],
             f["detail"][:600], f["where"][:400]))
    store.db.execute("DELETE FROM sysmon_hits WHERE ts < ? AND category='sysmon-linux'",
                     (ts - 30 * 86400,))
    store.commit()
    since = ts - hours * 3600
    keep = [f for f in findings if f["severity"] == "ok"]
    for r in store.db.execute(
            "SELECT * FROM sysmon_hits WHERE ts >= ? AND category='sysmon-linux' "
            "ORDER BY ts DESC", (since,)):
        keep.append(_finding(r["category"], r["severity"], r["title"],
                             r["detail"], r["where_"]))
    return keep


def audit(store=None, hours=24, hosts=("wsl", "win"), incremental=False):
    if "wsl" not in hosts:
        return []
    installed, running = state()
    if not installed:
        return [_finding(
            "sysmon-linux", "medium", "no eBPF syscall interception on Linux",
            "Sysmon for Linux is not installed. auditd cannot run on this "
            "kernel, so this is the way to make the runtime-behaviour "
            "techniques observable — see the module header for the install",
            "sysmonforlinux")]
    if not running:
        return [_finding(
            "sysmon-linux", "high", "Sysmon for Linux is installed but stopped",
            "the eBPF probes are not attached, so nothing between two sampling "
            "passes is captured. `sudo sysmon -accepteula -i` then "
            "`sudo systemctl enable --now sysmon`", "systemctl")]

    if incremental and store is not None:
        last = int(store.get_meta("sysmon_linux_last", 0) or 0)
        since = last or (now() - 1800)
        store.set_meta("sysmon_linux_last", now())
    else:
        since = now() - hours * 3600

    events = _parse(_raw(since))
    out = _rules(events, store=store)
    if store is not None:
        out = _remember(store, out, hours)
    out.append(_finding(
        "telemetry", "ok",
        f"Sysmon for Linux delivered {len(events)} events since the last pass",
        "eBPF interception active — runtime-behaviour techniques are being "
        "recorded", CHANNEL))
    return sort_findings(out)
