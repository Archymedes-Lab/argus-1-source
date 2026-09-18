"""Which audits the daemon runs, and how often.

Pure data, so the scheduler, the coverage self-audit, the report cadence and the
dashboard can all read the one table without importing each other.
"""

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
JOBS = {
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
    "deep_hidden": (86400, "Deep process cross-view scan"),
    "hidden":   (300,   "Hidden processes"),
    "firewall": (2400,  "Firewall & inbound"),
    "control":  (1800,  "Control surfaces"),
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
}
