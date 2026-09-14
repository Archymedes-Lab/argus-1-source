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

The default config records process events only. A tightened policy that also
captures the NetworkConnect, ProcessAccess and persistence-path FileCreate /
FileDelete events the rules below need — without the volume an unfiltered
FileCreate would add — ships in this repo at `sysmon/config.xml`:

    sudo sysmon -accepteula -i <repo>/sysmon/config.xml   # first install
    sudo sysmon -c          <repo>/sysmon/config.xml       # update in place

`audit()` reports it as a finding if those event types never show up.

Events land in the journal under the `sysmon` identifier. The daemon reads them
as `chris`, so `chris` must be in the `systemd-journal` or `adm` group (usually
already true on Ubuntu); the module falls back to /var/log/syslog otherwise.
"""

import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from jarvis.core.util import now
from jarvis.core.finding import finding as _finding

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CHANNEL = "journal:sysmon"

# A remembered finding is shown for at most `hours` (24h by default); keeping a
# few days of it behind that covers a daemon that was down over a weekend
# without letting a since-tuned false positive resurface for a month.
REMEMBER_DAYS = 3
# The oldest event still in the journal may legitimately be a few minutes newer
# than where the last pass stopped; more than this means journald discarded
# events before they were read.
GAP_TOLERANCE = 300
# Don't judge the capture scope on a near-idle window that simply had no
# network or file activity to record.
COVERAGE_FLOOR = 200

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
# snapd rewrites its own revision-pinned units under /etc/systemd/system on
# every refresh, through an atomic temp file whose name ends in `~`. The
# directory is a genuine persistence location, so the exemption is scoped to
# snapd touching a `snap-*` / `snap.*` unit name and nothing else — a unit
# with any other name, or any other writer, still surfaces.
SNAP_UNIT = re.compile(
    r"/etc/systemd/system/snap[-.][^/]+\.(mount|service|timer|socket|slice)"
    r"(\.[A-Za-z0-9_]+~)?$")
# The numbered-generation ladder a log rotator leaves behind: `dmesg.0`,
# `syslog.7.gz`, `apt/history.log.3.xz`. savelog/logrotate hand the previous
# generation to a compressor, which deletes the source once it is packed.
ROTATED_LOG = re.compile(r"^/var/log/.+\.\d+(\.(gz|xz|bz2|zst|Z))?$")
LOG_ROTATORS = {"gzip", "bzip2", "xz", "zstd", "lzma", "compress",
                "savelog", "logrotate"}
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
    r"/(node_modules|site-packages|\.venv|venv|\.pnpm|\.cargo|vendor|"
    r"go-build\d+/b\d+)/")
DEV_PARENTS = ("node", "npm", "npx", "pnpm", "yarn", "bun", "deno", "tsx",
               "python", "python3", "pip", "pip3", "cargo", "go", "make")

LOG_DELETE_TITLE = "a log or history file was deleted"
LOG_DELETE_SUFFIX = " — indicator removal"
PERSIST_WRITE_TITLE = "write to a persistence or trust location"
RAW_ACCESS_TITLE = "raw device read"  # retain existing alert identity
RAW_UNRESOLVED_TITLE = "Sysmon raw-access event has an unresolved device"
RAW_LEGACY_SUFFIX = " for raw access — disk imaging or filesystem-bypass read"


# Claude Code and similar agent harnesses run every command through a fixed
# wrapper: `bash -c 'source <shell-snapshot.sh> ... && eval '<the real
# command>' < /dev/null && pwd -P >| /tmp/claude-<id>-cwd'`. The scaffolding —
# sourcing the snapshot, a builtin-unalias block, the cwd write — is not what
# ran, and matching the content rules against it produced a download-and-run
# false positive whenever the real command was ordinary. Pull the real command
# back out before those rules look at it.
# The wrapper is not one fixed shape. A single-line command ends
# `' < /dev/null && pwd -P >| /tmp/claude-<id>-cwd`; a multi-line one (a
# heredoc, say) has no `< /dev/null` at all and ends at `' && pwd -P >|`.
# Matching only the first shape left roughly a third of harness events falling
# through to raw content matching — measured at 9 of 26 on this machine — and a
# rule that then reads the scaffolding is a rule that reports the scaffolding.
# So accept either terminator, and take the last one on the line rather than
# the first, because the real command may legitimately contain either string.
_HARNESS_MARK = "shell-snapshots/"
_HARNESS_WRAP = re.compile(
    r"shell-snapshots/\S+\.sh\b.*?&&\s*eval\s+'(?P<real>.*)'"
    r"(?:\s*<\s*/dev/null|\s*&&\s*pwd\s+-P\s*>\|)",
    re.S)

# The pieces of scaffolding themselves, for the case where the payload cannot be
# isolated — a truncated journal line, or a wrapper revision not seen yet.
# Stripping them is strictly better than giving up in either direction: the real
# command is still content-matched, and the scaffolding cannot be reported as if
# it were the command.
_HARNESS_PARTS = (
    re.compile(r"^/bin/bash\s+-c\s+", re.S),
    re.compile(r"source\s+\S*shell-snapshots/\S+\.sh\s*2>/dev/null\s*\|\|\s*true"),
    re.compile(r"shopt\s+-u\s+extglob\s*2>/dev/null\s*\|\|\s*true"),
    re.compile(r"\{[^{}]*\\builtin\s+un(alias|set)[^{}]*\}\s*>/dev/null\s*2>&1"
               r"\s*\|\|\s*true", re.S),
    re.compile(r"&&\s*pwd\s+-P\s*>\|\s*/tmp/claude-\S+-cwd\s*$"),
    re.compile(r"<\s*/dev/null\s*$"),
    re.compile(r"^\s*(&&\s*)+"),
)


# The bash escape for an apostrophe inside a single-quoted string.
_SQ_ESCAPE = chr(39) + chr(34) + chr(39) + chr(34) + chr(39)


def _payload(cmd):
    """The command the harness was asked to run, without the harness's own noise.

    Returns the original string unchanged for anything that is not a harness
    invocation, so non-agent command lines are unaffected.
    """
    cmd = cmd or ""
    if _HARNESS_MARK not in cmd:
        return cmd
    m = _HARNESS_WRAP.search(cmd)
    if m:
        real = m.group("real")
    else:
        real = cmd
        for part in _HARNESS_PARTS:
            real = part.sub("", real).strip()
        real = re.sub(r"^eval\s+'", "", real).strip()
    # bash single-quote escaping: an apostrophe inside a '…' string is written
    # as '"'"'. Left in place it splits words and hides what actually ran.
    return real.replace(_SQ_ESCAPE, chr(39)).strip()


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))


# ── posture ─────────────────────────────────────────────────────────────────

def _run(args, timeout=20):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
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
        # UtcTime in EventData is the process/event timestamp reported by
        # Sysmon. It can lag journal ingestion substantially while Sysmon is
        # draining its own queue, so retain TimeCreated separately for journal
        # continuity checks.
        created = sysd.find("TimeCreated") if sysd is not None else None
        if created is not None and created.get("SystemTime"):
            ev["SystemTime"] = created.get("SystemTime")
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


def _expected_log_maintenance(actor, target):
    """True only for a logging daemon or the rotation tooling acting on files
    it owns.

    Two exact shapes, nothing wider — broadly trusting anything that touches
    /var/log would be an easy indicator-removal blind spot:

      * journald unlinking one of its own archived journal segments, and
      * a compressor (invoked by savelog/logrotate) removing the previous
        numbered generation of a log once it has been packed — e.g. `gzip`
        deleting `/var/log/dmesg.0`.

    A bare `rm /var/log/auth.log`, or a compressor deleting a name that is not
    a numbered generation, still surfaces as indicator removal.
    """
    path = os.path.normpath(target or "")
    if (actor == "systemd-journald"
            and path.startswith("/var/log/journal/")
            and path.endswith((".journal", ".journal~"))):
        return True
    return actor in LOG_ROTATORS and bool(ROTATED_LOG.match(path))


def _expected_persistence(actor, target):
    """True only for snapd rewriting one of its own revision-pinned units.

    snapd regenerates `/etc/systemd/system/snap-<name>-<rev>.mount` (and the
    matching temp file ending in `~`) on every snap install or refresh. No
    other writer, and no other unit name, is exempt.
    """
    return actor == "snapd" and bool(
        SNAP_UNIT.search(os.path.normpath(target or "")))


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

def _is_jarvis(e):
    """jarvis shells out to ps/ss/ip/journalctl constantly — do not report
    its own activity as reconnaissance or unexplained egress."""
    blob = (str(e.get("ParentCommandLine", "")) + " "
            + str(e.get("CommandLine", "")) + " "
            + str(e.get("ParentImage", ""))).lower()
    return "jarvis" in blob or "-m jarvis" in blob


def _rules(events, store=None):
    out = []
    recon = {}
    dns_names, dests = set(), set()
    # A PID can be reused. Only a matching Sysmon ProcessGuid can supply the
    # command line for an event that doesn't contain one of its own.
    processes = {e["ProcessGuid"]: e for e in events
                 if e.get("id") == 1 and _clean(e.get("ProcessGuid"))
                 and e["ProcessGuid"] != "{00000000-0000-0000-0000-000000000000}"}

    for e in events:
        eid = e.get("id")
        img = _clean(e.get("Image") or e.get("SourceImage"))
        cmd = _clean(e.get("CommandLine"))
        # The command the operator actually ran, with any agent-harness wrapper
        # stripped — this is what the content rules should judge.
        pcmd = _payload(cmd)
        parent = _clean(e.get("ParentImage"))
        base, pbase = _base(img), _base(parent)
        mine = _is_jarvis(e)

        if eid == 1:
            # Only the executable's own path counts — a world-writable path in
            # an argument (runc/containerd pass plenty) is not execution from
            # there.
            if img and img.startswith(WORLD_WRITABLE):
                # A binary sitting inside a checked-out dependency tree
                # (node_modules, site-packages, …) that a project under /tmp
                # runs against itself is a dev habit, not a dropper — whether
                # or not Sysmon managed to resolve the parent this time. HIGH is
                # for an executable in a world-writable dir that is *not*
                # transparently part of a package tree.
                dev = bool(DEV_PKG_PATH.search(img)) and (
                    pbase in DEV_PARENTS or not pbase)
                out.append(_finding(
                    "sysmon-linux", "medium" if dev else "high",
                    "process executed from a world-writable directory",
                    f"{img}  «{cmd[:120]}»  parent {pbase or '?'}"
                    + ("  — dependency-tree binary run by its own package "
                       "manager, which is normal for a project under /tmp"
                       if dev else ""), CHANNEL))
            if DOWNLOAD_RUN.search(pcmd):
                out.append(_finding(
                    "sysmon-linux", "high", "download-and-run in a command line",
                    f"{pbase or base}: {pcmd[:160]}", CHANNEL))
            if pbase in WEB_PARENTS and base in SHELLS:
                out.append(_finding(
                    "sysmon-linux", "critical",
                    f"the web server ({pbase}) spawned a shell",
                    f"{img}  «{cmd[:140]}» — the classic post-exploitation "
                    f"step after a web shell or an RCE", CHANNEL))
            if base in REVSHELL_BINS and re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b|"
                                                   r"-e\b|/dev/tcp", pcmd):
                out.append(_finding(
                    "sysmon-linux", "high",
                    f"{base} invoked with a connect-back argument",
                    pcmd[:160], CHANNEL))
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
            if PERSIST_PATHS.search(tgt) and not _expected_persistence(base, tgt):
                out.append(_finding(
                    "sysmon-linux", "high", PERSIST_WRITE_TITLE,
                    f"{base or '?'} created/modified {tgt}", CHANNEL))

        elif eid in (23, 26):
            tgt = e.get("TargetFilename") or ""
            if ((tgt.startswith("/var/log/") or "/.bash_history" in tgt)
                    and not _expected_log_maintenance(base, tgt)):
                out.append(_finding(
                    "sysmon-linux", "high", LOG_DELETE_TITLE,
                    f"{base or '?'} deleted {tgt}{LOG_DELETE_SUFFIX}", CHANNEL))

        elif eid == 9:
            device = _clean(e.get("Device"))
            proc = processes.get(e.get("ProcessGuid"), {})
            context = _clean(proc.get("CommandLine")) if proc.get("Image") == img else ""
            # Linux Event 9 originates in processFileOpen (Sysmon 1.5.2),
            # which tests S_IFBLK but doesn't establish a read or disk imaging.
            # Missing/relative device names are retained as an uncertainty,
            # never silently trusted or promoted to a confirmed disk read.
            resolved = device.startswith("/") and device != "/"
            out.append(_finding(
                "sysmon-linux", "high" if resolved else "medium",
                RAW_ACCESS_TITLE if resolved else RAW_UNRESOLVED_TITLE,
                f"{img or '?'}: Sysmon Event 9 reports device {device or '<missing>'!r}; "
                + ("block-device open requires investigation; read/write direction "
                   "and disk imaging are not established"
                   if resolved else "target is unresolved; raw disk access is not established")
                + f"; PID {e.get('ProcessId') or '?'}; event time {e.get('UtcTime') or '?'}"
                + (f"; command {context[:180]}" if context else ""),
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

    # Correct old rendered claims while retaining their original observation
    # time. Never drop an unresolved device as benign or erase a real path.
    for row in store.db.execute(
            "SELECT * FROM sysmon_hits WHERE category='sysmon-linux' "
            "AND title=?", (RAW_ACCESS_TITLE,)).fetchall():
        detail = row["detail"] or ""
        if not detail.endswith(RAW_LEGACY_SUFFIX) or " opened " not in detail:
            continue
        actor, device = detail[:-len(RAW_LEGACY_SUFFIX)].split(" opened ", 1)
        if device.startswith("/") and device != "/":
            continue
        store.db.execute(
            """INSERT INTO sysmon_hits(ts,category,severity,title,detail,where_)
               VALUES(?,?,?,?,?,?) ON CONFLICT(category,title,where_)
               DO UPDATE SET ts=excluded.ts, detail=excluded.detail,
                   severity=excluded.severity WHERE excluded.ts > sysmon_hits.ts""",
            (row["ts"], "sysmon-linux", "medium", RAW_UNRESOLVED_TITLE,
             f"{actor}: legacy Sysmon Event 9 reported device {device!r}; "
             "target is unresolved; raw disk access is not established; "
             "original event time and process GUID were not retained",
             row["where_"]))
        store.db.execute("DELETE FROM sysmon_hits WHERE id=?", (row["id"],))

    # A hit created before an exemption was widened would otherwise remain
    # visible for the whole reminder window.  Re-evaluate this detector's
    # stored rows against the current rules and drop the ones now recognized
    # as expected maintenance.
    for row in store.db.execute(
            "SELECT id, title, detail FROM sysmon_hits "
            "WHERE category='sysmon-linux' AND title IN (?,?)",
            (LOG_DELETE_TITLE, PERSIST_WRITE_TITLE)).fetchall():
        detail = row["detail"] or ""
        stale = False
        if row["title"] == LOG_DELETE_TITLE and detail.endswith(LOG_DELETE_SUFFIX) \
                and " deleted " in detail:
            actor, target = detail[:-len(LOG_DELETE_SUFFIX)].split(" deleted ", 1)
            stale = _expected_log_maintenance(actor, target)
        elif row["title"] == PERSIST_WRITE_TITLE and " created/modified " in detail:
            actor, target = detail.split(" created/modified ", 1)
            stale = _expected_persistence(actor, target)
        if stale:
            store.db.execute("DELETE FROM sysmon_hits WHERE id=?", (row["id"],))

    store.db.execute("DELETE FROM sysmon_hits WHERE ts < ? AND category='sysmon-linux'",
                     (ts - REMEMBER_DAYS * 86400,))
    store.commit()
    since = ts - hours * 3600
    keep = [f for f in findings if f["severity"] == "ok"]
    for r in store.db.execute(
            "SELECT * FROM sysmon_hits WHERE ts >= ? AND category='sysmon-linux' "
            "ORDER BY ts DESC", (since,)):
        keep.append(_finding(r["category"], r["severity"], r["title"],
                             r["detail"], r["where_"]))
    return keep


def _event_utc(e):
    """Journal event time, falling back to the payload time for text records."""
    value = e.get("SystemTime") or e.get("UtcTime") or ""
    try:
        if "T" in value:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        return (datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
                .replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


def _health(events, since, incremental):
    """Two things that make the stream itself untrustworthy: journald throwing
    events away before they are read, and a config that records process events
    only so half the rules never have anything to match."""
    out = []
    ids = {e.get("id") for e in events}

    if incremental and events:
        stamps = [t for t in (_event_utc(e) for e in events) if t]
        gap = min(stamps) - since if stamps else 0
        if gap > GAP_TOLERANCE:
            out.append(_finding(
                "sysmon-linux", "medium",
                "Sysmon journal rotated past the last read position",
                f"the oldest sysmon event still in the journal is ~{int(gap // 60)} "
                f"min newer than where the last pass stopped — journald is "
                f"discarding events before they are consumed, so that window was "
                f"never inspected. Install the systemd/journald-sysmon.conf "
                f"drop-in for more retention, or shorten the sysmon_linux poll "
                f"interval.", CHANNEL))

    if len(events) >= COVERAGE_FLOOR and 1 in ids and not ({3, 10, 11, 23, 26} & ids):
        out.append(_finding(
            "sysmon-linux", "medium", "Sysmon is capturing process events only",
            "no NetworkConnect, ProcessAccess or FileCreate/Delete events in this "
            "window, so the egress-correlation, memory-read and persistence-write "
            "rules have nothing to act on. Load the fuller policy bundled with "
            "JARVIS: `sudo sysmon -c \"$(pwd)/sysmon/config.xml\"`.", CHANNEL))
    return out


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
    out = _rules(events, store=store) + _health(events, since, incremental)
    if store is not None:
        out = _remember(store, out, hours)
    out.append(_finding(
        "telemetry", "ok",
        f"Sysmon for Linux delivered {len(events)} events since the last pass",
        "eBPF interception active — runtime-behaviour techniques are being "
        "recorded", CHANNEL))
    return sort_findings(out)
