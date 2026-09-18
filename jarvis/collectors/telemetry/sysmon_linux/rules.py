"""Linux-shaped detection rules over parsed Sysmon events."""

import os
import re

from jarvis.core import egress as egress_baseline
from jarvis.core import vet, warninglist
from jarvis.core.finding import finding as _finding

from .harness import _payload
from .journal import CHANNEL, _base, _clean

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


EGRESS_TITLE = egress_baseline.TITLE


EXPECTED_EGRESS = {
    "firefox", "chrome", "chromium", "curl", "wget", "apt", "apt-get", "http",
    "https", "snap", "snapd", "packagekitd", "systemd", "systemd-resolved",
    "NetworkManager", "dockerd", "containerd", "git", "git-remote-http", "gh",
    "ssh", "sshd", "code", "node", "python3", "bun", "npm", "pip", "pip3", "uv",
}


LOG_DELETE_SUFFIX = " — indicator removal"


PERSIST_WRITE_TITLE = "write to a persistence or trust location"


RAW_ACCESS_TITLE = "raw device read"  # retain existing alert identity


RAW_UNRESOLVED_TITLE = "Sysmon raw-access event has an unresolved device"


RAW_LEGACY_SUFFIX = " for raw access — disk imaging or filesystem-bypass read"


ROTATION_PARENT = re.compile(r"(^|[/\s])(savelog|logrotate)(\s|$)")


# A heredoc whose delimiter is quoted (<<'EOF', <<"EOF", <<\EOF) is written
# verbatim: no expansion, no substitution, nothing runs. Measured 2026-09-17:
# `cat > approvals.test.ts <<'EOF'` with test source mentioning `curl | sh`
# raised "download-and-run". Unquoted heredocs are left in place — `$(curl …)`
# inside one does execute.
def _without_quoted_heredocs(cmd):
    out, pos = [], 0
    for m in re.finditer(r"<<-?\s*(?:'([^']+)'|\"([^\"]+)\"|\\(\w+))[^\n]*\n", cmd or ""):
        if m.start() < pos:
            continue
        tag = m.group(1) or m.group(2) or m.group(3)
        end = re.compile(r"^\s*" + re.escape(tag) + r"\s*$", re.M).search(cmd, m.end())
        out.append(cmd[pos:m.end()])
        pos = end.end() if end else len(cmd)
    out.append((cmd or "")[pos:])
    return "".join(out)


def _expected_log_maintenance(actor, target, parent_cmdline=""):
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
    if actor == "rm":
        # savelog deletes the oldest generation with a plain `rm -f`; Ubuntu's
        # dmesg.service runs `savelog -c 5 /var/log/dmesg` at every boot.
        # Measured: `rm deleted /var/log/dmesg.4.gz` raised a high each WSL
        # start. Only rm's own process record naming savelog or logrotate as
        # its parent exempts it; an rm Sysmon cannot parent stays high.
        return bool(ROTATED_LOG.match(path)) and bool(ROTATION_PARENT.search(parent_cmdline or ""))
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


def _is_jarvis(e):
    """jarvis shells out to ps/ss/ip/journalctl constantly — do not report
    its own activity as reconnaissance or unexplained egress."""
    blob = (str(e.get("ParentCommandLine", "")) + " "
            + str(e.get("CommandLine", "")) + " "
            + str(e.get("ParentImage", ""))).lower()
    return "jarvis" in blob or "-m jarvis" in blob


def _rules(events, store=None):
    out = []
    recon, egress = {}, {}
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
            if DOWNLOAD_RUN.search(_without_quoted_heredocs(pcmd)):
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
            # Event 3 names the connecting process in Image and carries no
            # parent, so the list is checked against `base`. It was checked
            # against the (always empty) parent, which turned every public
            # connection from node, curl or gh into its own medium finding —
            # 209 of them in three days.
            if _is_public_ip(dst) and not mine and base not in EXPECTED_EGRESS:
                egress.setdefault(base or "", {}).setdefault(f"{dst}:{port}", host)

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
            creator = processes.get(e.get("ProcessGuid"), {})
            if ((tgt.startswith("/var/log/") or "/.bash_history" in tgt)
                    and not _expected_log_maintenance(
                        base, tgt, _clean(creator.get("ParentCommandLine")))):
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

    # One finding per program, not per address: the question is whether this
    # program should talk to the internet at all.
    for base, peers in sorted(egress.items()):
        sample = ", ".join(f"{d}" + (f" ({h})" if h and h != "-" else "")
                           for d, h in list(peers.items())[:4])
        verdict = egress_baseline.decision(store, "wsl", base) if (store is not None and base) else ""
        if base and verdict == egress_baseline.EXPECTED:
            continue            # you confirmed this program reaches the internet
        if base and verdict == egress_baseline.UNEXPECTED:
            out.append(_finding(
                "sysmon-linux", "high", f"{EGRESS_TITLE} {base}",
                f"{len(peers)} public destination(s): {sample} — you marked this "
                f"program as not expected to reach the internet", CHANNEL))
        elif base:
            out.append(_finding(
                "sysmon-linux", "medium", f"{EGRESS_TITLE} {base}",
                f"{len(peers)} public destination(s): {sample} — confirm this "
                f"program is expected to reach the internet", CHANNEL))
        else:
            out.append(_finding(
                "sysmon-linux", "low", f"{EGRESS_TITLE} an unresolved process",
                f"{len(peers)} public destination(s): {sample} — Sysmon could not "
                f"name the process, so this is a visibility gap, not a detection",
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
            f"SELECT value, kind, malware, source, confidence FROM indicators "
            f"WHERE status='active' AND (norm IN ({qmarks}) OR value IN ({qmarks}))",
            values + values).fetchall()
    except Exception:
        return out
    for r in rows:
        # The same gates the Windows matcher uses: vetting, popularity, and
        # the indicator's own confidence. This matched exactly, unvetted, and
        # made every hit critical — a writeup's brand name included.
        value = r["value"]
        severity = "critical" if r["confidence"] == "high" else "medium"
        if r["kind"] == "domain":
            if not vet.vet_domain(value)[0]:
                continue
            worth = warninglist.judge_domain(store, value.lower(), value.lower(), r["source"])
            if worth == "none":
                continue
            if worth == "weak":
                severity = "low"
        elif r["kind"] == "ipv4" and not vet.vet_ipv4(value)[0]:
            continue
        out.append(_finding(
            "sysmon-linux", severity,
            f"a process contacted a known-bad indicator: {value}",
            f"{r['kind']} — {r['malware'] or 'flagged'} (via {r['source']})",
            "threat-intel"))
    return out
