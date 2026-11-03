"""Which collectors need the administrator sensor, and what to say when it is absent.

The Windows release without the elevated parts (the Sysmon-fed native sensor
and the read-only broker) runs everything that needs no administrator rights.
It must not read as full coverage: each job below uses the broker's results
(`jarvis.platform.broker.result`) or the native sensor's spool, so without
them it is unavailable or limited, and says so in the same words everywhere.

The list is derived from the code, not from memory: a job is here because its
collector module calls `broker.result` or reads the native sensor. Adding the
elevated components in a later native release needs no change here: once
`broker.installed()` is true, `absent()` is false and nothing is reported.
"""

NEEDS_ADMIN_SENSOR = "Needs administrator sensor"

# job -> "unavailable": produces nothing without the sensor;
#        "limited": still checks what an unprivileged account can see.
ADMIN_SENSOR_JOBS = {
    "native": "unavailable",     # telemetry/native.py: the sensor's own spool
    "sysmon": "unavailable",     # telemetry/sysmon.py: Sysmon event feed
    "evidence": "unavailable",   # telemetry/evidence.py: the broker's vault
    "fwaudit": "unavailable",    # host/firmwareaudit.py: broker only
    "internet": "limited",       # network/internetwatch.py
    "control": "limited",        # persistence/control.py
    "memscan": "limited",        # process/memscan.py
    "posture": "limited",        # host/posture/run.py
    "input": "limited",          # host/inputwatch/watchers.py (Win32k trace)
    "input_hook": "limited",
}


def absent():
    """True on Windows when the elevated broker is not installed."""
    import sys

    if not sys.platform.startswith("win"):
        return False
    from jarvis.platform import broker
    try:
        return not broker.installed()
    except OSError:
        return True


def blind_entries(labels, already=(), is_absent=None):
    """Pulse `blind` entries for the jobs the missing sensor affects.

    `labels` maps job -> display label; jobs already reported blind for
    another reason are left as they are (their own reason is more specific).
    """
    if not (absent() if is_absent is None else is_absent):
        return []
    seen = set(already)
    return [{"job": job, "label": labels.get(job, job), "reason": NEEDS_ADMIN_SENSOR, "level": level,
             "freshness": "UNAVAILABLE", "error": False}
            for job, level in ADMIN_SENSOR_JOBS.items() if job in labels and job not in seen]
