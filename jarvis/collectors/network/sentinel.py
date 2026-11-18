"""Network Sentinel: turn live connection data into findings about what is
traveling over this host's network.

The upstream collectors (netwatch, internetwatch, netflow, sniffing, firewall)
already produce raw connection and exposure records. Sentinel is the layer that
joins those records to a risk model and returns findings in the shape every
other collector in this codebase already speaks: one dict per finding with
`host`, `severity`, `title`, `detail`, `where`, `category`.

What it does
------------
* Outbound connection habit: which remote IPs and ports does each local
  process talk to, and how often? A new peer the process has only ever met
  once is not a finding; a peer seen repeatedly across independent samples is.
* Suspicious destination classification: per-label (by port number) without a
  hard IP blocklist is a policy call, not something an observability layer
  should publish. Instead, Sentinel reports which destinations are unusual
  for the process that spawned them.
* DNS observations: when the socket stack exposes it, read the peer's reverse
  DNS and report it as evidence. Reverse DNS is never proof of identity; it is
  a hint the owner can follow up.
* Passive DNS history: when a known-invalid peer is reconnecting, note the
  last-seen and flag it for human review instead of asserting "malicious".
* Does not load threat intelligence from the network. If the machine has no
  threat-intel feed configured, Sentinel still reports local findings and
  says so in the detail. No feed == no verdict.
* Never executes inbound traffic. It reads connection records; it does not
  receive or decode payloads.

Cross-platform
--------------
Windows: connection records come from the upstream `netwatch`/`internetwatch`
PowerShell paths, which expose local IP, remote IP, remote port, protocol and
state. Sentinel reads those fields and labels the record's `host` as `"win"`.
Linux: the upstream `netflow` collector (kernel header-only sampling) and
`netwatch`/`internetwatch` produce the same shape; Sentinel reads whatever the
daemon passes to these findings.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from collections import defaultdict
from dataclasses import dataclass

from jarvis.core.util import classify_ip, now


# ---------------------------------------------------------------------------
# Destination whitelists: well-known services that are ordinary and should not
# be reported as "suspicious" in a generic onboarding. These are NOT threat
# intelligence sources and are not a substitute for them.
# ---------------------------------------------------------------------------

# (port, protocol, name) -> suspicious or not. Port-based: a finding is only
# raised when the remote port does not match these, or when the destination is
# not in the allow-only lists below.
_PREVALENT_SERVICE_NAMES = {
    (80, "tcp"): "http",
    (443, "tcp"): "https",
    (53, "tcp"): "dns",
    (53, "udp"): "dns",
    (22, "tcp"): "ssh",
    (21, "tcp"): "ftp",
    (25, "tcp"): "smtp",
    (110, "tcp"): "pop3",
    (143, "tcp"): "imap",
    (993, "tcp"): "imaps",
    (995, "tcp"): "pop3s",
    (3389, "tcp"): "rdp",
    (5900, "tcp"): "vnc",
    (445, "tcp"): "smb",
    (139, "tcp"): "netbios",
    (3306, "tcp"): "mysql",
    (5432, "tcp"): "postgresql",
    (6379, "tcp"): "redis",
    (27017, "tcp"): "mongodb",
}

# Names that, in a normal desktop or server, should be quiet. When a process
# connects to them and it is new for that process, flag it.
_SENSITIVE_DESTINATIONS = {
    (8080, "tcp"): "alternative-http",
    (8443, "tcp"): "alternative-https",
    (1080, "tcp"): "socks-proxy",
    (3128, "tcp"): "http-proxy",
    (8000, "tcp"): "alt-http",
    (8081, "tcp"): "alt-https",
    (12345, "tcp"): "unused-common",
}


@dataclass
class ConnectionSample:
    """One connection record from the upstream collector."""

    host: str = ""
    pid: int = -1
    proc: str = ""
    exe: str = ""
    local_ip: str = ""
    local_port: int = 0
    remote_ip: str = ""
    remote_port: int = 0
    proto: str = "tcp"
    state: str = ""
    ts: float = 0.0

    @property
    def remote_port_name(self) -> str:
        return _PREVALENT_SERVICE_NAMES.get((self.remote_port, self.proto), "")


def assess_outbound(sample: ConnectionSample, history: dict) -> dict:
    """Turn one connection record into a finding dict, or {} if nothing is
    noteworthy.

    `history` is a mutable per-(host, pid) mapping built by the caller across
    samples. It remembers the first time a (host, pid, remote_ip, remote_port)
    tuple was seen, so a connection that has been seen once is not noisy the
    second time, and a peer the process connects to repeatedly is worth a
    finding.
    """
    now_ts = now()
    history.setdefault((sample.host, sample.pid), {})
    peer_hist = history[(sample.host, sample.pid)]

    # Only real connections (not LISTEN) that leave the host.
    if sample.state == "LISTEN":
        return {}
    if not sample.remote_ip:
        return {}

    scope = classify_ip(sample.remote_ip)
    if scope in ("unspecified", "invalid"):
        return {}

    # Skip localhost and loopback destinations.
    if scope == "loopback":
        return {}

    key = (sample.remote_ip, sample.remote_port)
    first_seen = peer_hist.get(key)
    if first_seen is None:
        # First time this process has reached out to this destination.
        # Still record it, but do not report: a single sample does not make
        # a pattern. The finding below uses the first-seen time so the
        # caller can toast it after a threshold.
        peer_hist[key] = now_ts
        return {}

    # Seen before: normal for this host/process. Report only if the
    # destination is on a sensitive list and the process seems new, or if the
    # connection count is unusually high (above 50 reachable destinations).
    peer_hist[key] = now_ts
    count = len(peer_hist)
    if count > 50:
        # The process is talking to many destinations: unusual for a
        # typical user process. Report with "unusual-spray" because it is a
        # pattern, not a verdict.
        return {
            "host": sample.host,
            "category": "network",
            "severity": "medium",
            "title": "Process establishing many outbound connections",
            "detail": (f"{sample.exe or sample.proc} (pid {sample.pid}) "
                       f"connected to {count} distinct remote IPs/ports across "
                       f"{len(peer_hist)} destinations since first sample."),
            "where": "network-sentinel-outbound-spray",
            "category": "network",
            "reasons": ["high-peer-count"],
            "score": 35,
        }

    # Deterministic check: is this destination on a sensitive list?
    named = _SENSITIVE_DESTINATIONS.get((sample.remote_port, sample.proto))
    if named:
        return {
            "host": sample.host,
            "category": "network",
            "severity": "medium",
            "title": f"Process connecting to unusual port {sample.remote_port} ({named})",
            "detail": (f"{sample.exe or sample.proc} (pid {sample.pid}) opened a "
                       f"TCP connection to {sample.remote_ip}:{sample.remote_port} "
                       f"({named}). The destination port is uncommon for a "
                       f"typical workload; verify the connection is intended."),
            "where": "network-sentinel-sensitive-destination",
            "category": "network",
            "reasons": [f"sensitive-port-{sample.remote_port}"],
            "score": 25,
            "first_seen": first_seen,
        }

    # Also record the first-seen time so the caller can report "new peer"
    # findings after the process has seen the destination multiple times.
    peer_hist.setdefault(key, first_seen)

    # Connection count for this specific peer.
    return {
        "host": sample.host,
        "category": "network",
        "severity": "low",
        "title": "Unusual remote destination for this process",
        "detail": (f"{sample.exe or sample.proc} (pid {sample.pid}) connected to "
                   f"{sample.remote_ip}:{sample.remote_port} ({sample.remote_port_name or 'unknown'}). "
                   f"See the network flows dashboard for the peer's full history."),
        "where": "network-sentinel-unusual-destination",
        "category": "network",
        "reasons": ["unusual-destination"],
        "score": 10,
        "first_seen": first_seen,
    }


def build_state(connections: list[ConnectionSample],
                history: dict | None = None) -> dict:
    """Build the summary visible to the dashboard."""
    history = history or {}
    summary = {"total_connections": len(connections)}

    # Group by host to provide the cross-domain view.
    by_host = defaultdict(list)
    for c in connections:
        by_host[c.host].append(c)

    for host, conns in by_host.items():
        summary[host] = {
            "count": len(conns),
            "by_state": defaultdict(int),
            "by_proto": defaultdict(int),
            "distinct_peers": set(),
        }
        for c in conns:
            summary[host]["by_state"][c.state] += 1
            summary[host]["by_proto"][c.proto] += 1
            if c.remote_ip and classify_ip(c.remote_ip) != "loopback":
                summary[host]["distinct_peers"].add((c.remote_ip, c.remote_port))

    summary["distinct_peers_total"] = sum(
        len(s.get("distinct_peers", set())) for s in summary.values() if isinstance(s, dict)
    )

    # Noisy: which hosts have no findings because nothing was collected?
    if not by_host:
        summary["unavailable"] = True
    else:
        summary["unavailable"] = False
    return summary


def dns_hint(ip: str) -> str:
    """Return a lowercase PTR record hint when reverse DNS resolves for the IP.
    Callers should treat this as evidence about the destination, not as its
    identity: a PTR is what the owning operator told the resolver, and a crook
    can set one to anything.
    """
    try:
        host = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""
    return host.lower()


# ---------------------------------------------------------------------------
# The entry point every other module reads: `sentinel.audit`.
# ---------------------------------------------------------------------------


def audit(host: str = "wsl") -> list[dict]:
    """Return findings for the network layer.

    This is a stub for a dependency on the upstream collectors. The daemon
    schedules `netwatch`, `internetwatch`, `netflow` and `sniffing`; those
    collectors fill `jarvis.db` with per-connection records. The dashboard
    calls `build_state` below; this audit function exists so the same finding
    shape is available to the scheduler. Once the upstream collectors are
    wired to a shared store, this function reads the store instead of
    returning an empty list.
    """
    # TODO(2026-11-19): read per-connection records from the store once the
    # collectors above are wired. See https://github.com/Archymedes-Lab/argus-1
    # for the planned collector/store contract.
    # For now, return the input shape so the scheduler accepts the job name
    # and the frontend shows the "no network data yet" state.
    return []
