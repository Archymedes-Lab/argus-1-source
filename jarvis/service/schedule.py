"""Which audits the daemon runs, and how often.

Pure data, so the scheduler, the coverage self-audit, the report cadence and the
dashboard can all read the one table without importing each other.

ALL_JOBS is every audit JARVIS has. JOBS is the part of it that applies to the
machine this process runs on (platform/host.py): a native Windows install has
no Linux domain to audit, a plain Linux one no Windows domain. A job outside
JOBS is never scheduled, never expected and never scored - it is listed in
NOT_APPLICABLE with the reason, so the absence is stated rather than silent.
"""

from jarvis.platform import host

# name -> (interval seconds, label, callable(hosts) -> list[finding])
# Intervals have to fit through one worker. The scheduler runs jobs strictly
# one at a time on purpose — two concurrent powershell.exe launches are slower
# than running them back to back and fight over the same interop pipe — so the
# sum of (duration / interval) across every job is a duty cycle that must stay
# well under 1. Adding the intel and forensics collectors pushed it over, and
# the symptom was exactly what coverage.py is built to catch: short-interval
# checks silently starving behind a four-minute firewall audit and serving
# hour-old snapshots that still looked current.
#
# Measured on this machine, not estimated. The expensive collectors are the
# ones that cross the WSL interop boundary and ask Windows for a lot: the cost
# is the query, not the interop — a bare powershell.exe round trip is 0.5s.
#
#   hidden 14s   netwatch 10s   implant 15s   posture 14s   intrusion 106s
#   firewall 18s   control 16s   spy 22s   memscan 90s   feeds 90s
#   sysmon 1.5s (incremental; 23s before)   scan 2.2s   secrets 60s
#   toolchain 17s (bounded $HOME walk + one stat pass per extension)
#   coverage/hunt/gaps under 0.5s — they only touch SQLite
#
# Sysmon earned its short interval by reading only what happened since the
# last run instead of re-reading a day of log every time.
ALL_JOBS = {
    "scan":     (60,    "Processes & network"),
    # Early in the dict so that on a cold start these two watchdogs run before
    # the long Windows audits, not after them. Both healthy paths are
    # local-only (well under a second), so their position costs nothing.
    #
    # "bridge" is a standalone, fast copy of coverage.py's Windows-bridge
    # check: available() only stats a socket, so at 45s it can page within a
    # minute of the interop link dying instead of waiting for the 10-minute
    # coverage cycle. Its finding is classed as an outage, so it mails
    # immediately regardless of alert_min_severity.
    "bridge":   (45,    "Windows bridge reachability"),
    "input_hook":(45,   "Input monitor watchdog"),
    # Drains the native Windows sensor's spool into the event log. Local file
    # reads only — no PowerShell — and ahead of sysmon, which reads its output.
    "native":   (60,    "Native sensor ingestion"),
    # The other half of the mutual supervision loop. jarvis-selfcheck.timer
    # restarts this daemon when it dies; this re-arms that timer when it stops.
    # Without it the timer is a single point of failure that nothing watches,
    # and a stopped timer looks exactly like a healthy one from in here.
    "watchdogs":(120,   "Watchdog mutual supervision"),
    "resources":(300,   "Resource pressure"),
    "internet": (120,   "Internet apps & incoming traffic"),
    "controls": (300,   "Brightness & control devices"),
    "audio":    (300,   "Audio endpoints & routes"),
    # Replays the TPM measured-boot logs (local file reads) and one bounded
    # event-log query, about 3 s. Boots are rare; a baseline drift persists.
    "preos":    (1800,  "Pre-OS boot integrity"),
    "deep_hidden": (86400, "Deep process cross-view scan"),
    "hidden":   (300,   "Hidden processes"),
    "firewall": (2400,  "Firewall & inbound"),
    "control":  (1800,  "Control surfaces"),
    # One registry/environment read, about 1s: CLR profiler, startup-hook,
    # AppDomainManager and runtime-ETW settings, and the AMSI providers.
    "dotnet":   (1800,  ".NET runtime hijack points"),
    "asep":     (3600,  "Autostart points"),
    "spy":      (5400,  "Spyware & capabilities"),
    "pixel":    (3600,  "Screen capture & tracking pixels"),
    "identity": (900,   "Who is acting on this machine"),
    "intrusion":(5400,  "Intrusion artifacts"),
    "evasion":  (1200,  "Evasion & kernel integrity"),
    "coverage": (600,   "Self-audit & blind spots"),
    "boot":     (21600, "Startup analysis"),
    # Local and cheap: compare what intel knows against what is on the box.
    "hunt":     (1800,  "Threat-intel indicator hunt"),
    "gaps":     (21600, "Detection coverage vs current intel"),
    # Networked and metered. One topic per run, so the corpus rotates itself
    # and the daily budget guard in intel.py is what actually bounds spend.
    "intel":    (18000, "Threat-intelligence refresh"),
    # Runs after the equally frequent intel refresh in declaration-order ties,
    # so a report can describe the newest research rather than the prior wave.
    "report":   (300, "Daily advisory & change digests"),
    # Free, unauthenticated and high volume. Each feed has its own publisher
    # cadence; this job just asks which are due.
    "feeds":    (3600,  "Bulk indicator feeds"),
    "implant":  (3600,  "Interception & boundary bypass"),
    # Short interval on purpose: the value is a continuous record, and a drop
    # that happened between two samples is a drop that cannot be investigated.
    "netwatch": (300,   "Network & wireless state"),
    "posture":  (7200,  "Windows security posture"),
    "backdoor": (3600,  "Backdoors & access grants"),
    # The developer trust surface: MCP servers, agent hooks, editor extensions,
    # git hooks and .pth files. Local filesystem only — no interop — but it
    # walks $HOME for repositories and stats every installed extension, so it
    # sits with the hourly collectors rather than the fast ones.
    "toolchain":(3600,  "Developer toolchain trust"),
    # Reads only the alert ledger and the snapshot timestamps, so it costs
    # nothing. Frequent enough that a recurrence is noticed the same day.
    "ledger":   (1800,  "Unresolved & recurring alerts"),
    # Cheap: the helper does the watching, this only drains its output file
    # and runs the injected-event audit. The short-interval "input_hook"
    # watchdog (declared above) is what keeps the helper itself alive.
    "input":    (300,   "Synthetic input"),
    # Walks every readable process's address space; expensive, so it runs
    # rarely and its cost is accounted for in the duty cycle above.
    "memscan":  (7200,  "Memory & instruction level"),
    # Walks the home directory; slow, and secrets do not appear by the minute.
    "secrets":  (43200, "Plaintext credentials"),
    # Counts failed-auth records in the OS logs; one PowerShell call + a log
    # read, so it is cheap enough to run hourly.
    "bruteforce":(3600, "Brute force & auth failures"),
    # Local packet-capture state on both sides.
    "sniffing": (1800,  "Packet capture"),
    # Walks web-server document roots; slow, and web shells do not appear by
    # the minute.
    "webshell": (21600, "Web shells"),
    # Is the Linux syscall-interception layer present and recording?
    "auditd":   (7200,  "Syscall interception posture"),
    # eBPF syscall interception on Linux — reads incrementally, like sysmon.
    "sysmon_linux":(600, "Sysmon for Linux (eBPF)"),
    # The interception layer. Frequent, because its value is catching things
    # that start and exit between the sampling passes.
    "sysmon":   (600,   "Sysmon telemetry"),
    # ATT&CK coverage, validated by probing the real detectors (attackmap.py).
    "attackmap": (21600, "ATT&CK coverage map"),
    # JARVIS Arena: run the synthetic validation suite against the real
    # detectors and flag any regression. Local-only and cheap (no PowerShell).
    "arena":    (3600,  "Adversarial self-validation"),
    # Device location & geofencing. One registry read when location is off;
    # one native-locator call when the user has consented.
    "geo":      (900,   "Device location & geofencing"),
    # Conflict reports from public newsroom feeds and GDELT, for the /world
    # view. Context only: unscored, deferrable, and the same requests whoever
    # and wherever the owner is.
    "world":    (900,   "World conflict reports"),
    # Docker container inventory: privilege flags, namespace sharing, socket
    # and sensitive-mount exposure. `docker inspect` per container, read-only.
    "containers": (900, "Container privilege and exposure inventory"),
    # Is the local Ollama endpoint actually there? One loopback GET (or one
    # bridge round trip), never a generation, never the model lock — so it is
    # cheap enough for its own cadence and a dead model becomes a known state.
    "model":    (1800,  "Local model availability"),
    # Copies the authoritative event history into the independent Rust
    # store. Each run re-verifies the whole retained store (O(store), about
    # 20s at its 128 MiB budget), so it is governed and runs rarely; the
    # 1200s interval also gives it a 120s reliability budget.
    "rust_mirror": (1200, "Independent evidence mirror"),
    # Stages sealed history for the broker's administrator-only vault,
    # verifies the vault against the live log, checks the running Sysmon
    # rules against the baseline, and timestamps chain heads publicly
    # (a 32-byte digest at most every 6h). Incremental: new vaulted segments
    # are hashed each run, every vaulted payload once a day.
    "evidence": (900,   "Evidence vault & anchors"),
}

# Audits of one execution domain only. Everything else either observes both
# domains (and narrows itself to the `hosts` it is given) or describes JARVIS
# itself. A collector belongs here only when it has nothing to observe without
# that domain - never because it is failing.
WINDOWS_ONLY = frozenset({
    "bridge", "input_hook", "input", "native", "internet", "controls", "audio",
    "preos", "dotnet", "asep", "evasion", "intrusion", "boot", "posture",
    "memscan", "sysmon", "geo",
})
LINUX_ONLY = frozenset({"auditd", "sysmon_linux", "containers"})


def applicable(windows, linux, jobs=None):
    """(schedule, {job: reason}) for a machine with these execution domains."""
    jobs = ALL_JOBS if jobs is None else jobs
    keep, absent = {}, {}
    for name, spec in jobs.items():
        if name in WINDOWS_ONLY and not windows:
            absent[name] = "this machine has no Windows domain to observe"
        elif name in LINUX_ONLY and not linux:
            absent[name] = "this machine has no Linux domain to observe"
        else:
            keep[name] = spec
    return keep, absent


JOBS, NOT_APPLICABLE = applicable(host.has_windows(), host.has_linux())
