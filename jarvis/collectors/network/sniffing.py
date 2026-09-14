"""Packet capture on this host — the local half of T1040 Network Sniffing.

An attacker who wants to read traffic they are not a party to has to do one of
a few visible things: put an interface in promiscuous mode, open an
AF_PACKET / raw socket, or load a capture driver. None of that is traffic
analysis — it is all local state, so a sampling monitor can see it.

  Linux    IFF_PROMISC on an interface, and any process holding a packet
           socket. Bridges and container veth pairs run promiscuous by design,
           so those are noted, not alarmed; a physical NIC in promiscuous mode
           with no capture tool to explain it is the finding.

  Windows  the Npcap / WinPcap driver being present at all (it is not there on
           a stock machine), plus any running capture tool — Wireshark,
           dumpcap, tshark, windump, NetworkMiner, Fiddler, mitmproxy.

It cannot see a capture that a driver-level implant does entirely in kernel
without a userland socket, and it says as much.
"""

import glob
import os
import re
import subprocess

from jarvis.core.finding import finding as _finding
from jarvis.core.paths import load_win_script
from jarvis.platform import windows as collect_windows
from jarvis.platform.windows import aslist, ps_json

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

IFF_PROMISC = 0x100
CAPTURE_TOOLS = ("tcpdump", "tshark", "dumpcap", "wireshark", "windump",
                 "netsniff-ng", "ettercap", "bettercap", "mitmproxy",
                 "mitmdump", "ngrep", "tcpflow", "netcat-capture")
# Interface name prefixes that are promiscuous as part of normal operation.
BENIGN_IFACE = ("br-", "docker", "veth", "virbr", "vnet", "lxc", "cni",
                "flannel", "cali", "tap", "tun", "kube")


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))


# ── Linux ───────────────────────────────────────────────────────────────────

def _capture_procs_linux():
    procs = []
    for p in glob.glob("/proc/[0-9]*"):
        try:
            with open(f"{p}/comm", errors="replace") as fh:
                comm = fh.read().strip()
        except OSError:
            continue
        if comm in CAPTURE_TOOLS:
            procs.append((os.path.basename(p), comm))
    return procs


def _packet_sockets():
    """Processes holding an AF_PACKET socket, via `ss`."""
    try:
        r = subprocess.run(["ss", "-0", "-p", "-a", "-H"],
                           capture_output=True, text=True,
                           errors="replace", timeout=15)
    except (OSError, subprocess.SubprocessError):
        return []
    holders = []
    for line in r.stdout.splitlines():
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        if m:
            holders.append((m.group(2), m.group(1)))
    return holders


def _promisc_ifaces():
    out = []
    for path in glob.glob("/sys/class/net/*/flags"):
        iface = path.split("/")[-2]
        try:
            flags = int(open(path, errors="replace").read().strip(), 16)
        except (OSError, ValueError):
            continue
        if flags & IFF_PROMISC:
            out.append(iface)
    return out


def _linux():
    out = []
    tools = _capture_procs_linux()
    sockets = [(pid, name) for pid, name in _packet_sockets()
               if name not in ("systemd-networkd", "NetworkManager", "dhclient",
                               "dhcpcd", "wpa_supplicant", "avahi-daemon")]
    promisc = _promisc_ifaces()
    phys_promisc = [i for i in promisc
                    if not any(i.startswith(b) for b in BENIGN_IFACE)
                    and i != "lo"]

    for pid, comm in tools:
        out.append(_finding(
            "sniffing", "high", f"a packet-capture tool is running: {comm}",
            f"pid {pid}. Confirm this is a capture you started",
            f"/proc/{pid}"))

    for pid, name in sockets:
        if any(t[0] == pid for t in tools):
            continue
        out.append(_finding(
            "sniffing", "high",
            f"{name} (pid {pid}) is holding a raw packet socket",
            "an AF_PACKET socket reads frames off the wire directly — normal "
            "for a sniffer, unexpected for anything else", f"/proc/{pid}"))

    for iface in phys_promisc:
        explained = bool(tools or sockets)
        out.append(_finding(
            "sniffing", "medium" if explained else "high",
            f"{iface} is in promiscuous mode",
            ("a capture tool above explains it" if explained else
             "no capture process on this host explains a physical NIC "
             "reading every frame on the segment"), f"/sys/class/net/{iface}"))

    benign_promisc = [i for i in promisc if i not in phys_promisc and i != "lo"]
    if not out:
        note = (f"; {', '.join(benign_promisc)} promiscuous by design (bridge/"
                f"container)" if benign_promisc else "")
        out.append(_finding(
            "sniffing", "ok", "no packet capture on the Linux side",
            f"no capture tool, no unexplained raw socket, no physical NIC in "
            f"promiscuous mode{note}", "ip link / ss"))
    return out


# ── Windows ─────────────────────────────────────────────────────────────────

_WIN_PS = load_win_script("sniffing.ps1")


def _windows():
    if not collect_windows.available():
        return []
    d = ps_json(_WIN_PS, timeout=120)
    if not d:
        return []
    out = []
    for drv in aslist(d.get("drivers")):
        name = (drv or {}).get("name", "?")
        status = (drv or {}).get("status", "?")
        if name == "pktmon":
            continue  # built-in, only interesting when actively tracing
        out.append(_finding(
            "sniffing", "medium" if status != "Running" else "high",
            f"a packet-capture driver is installed: {name} ({status})",
            "Npcap/WinPcap is not present on a stock machine — something "
            "installed it to capture traffic. Fine if that was you",
            "services", host="win"))
    for t in aslist(d.get("tools")):
        out.append(_finding(
            "sniffing", "high",
            f"a capture tool is running: {(t or {}).get('name', '?')}",
            f"pid {(t or {}).get('id', '?')} — confirm this capture is yours",
            "processes", host="win"))
    for name in aslist(d.get("promisc")):
        out.append(_finding(
            "sniffing", "high", f"adapter {name} is in promiscuous mode",
            "an adapter reading every frame on the segment", "netadapter",
            host="win"))
    if not out:
        out.append(_finding(
            "sniffing", "ok", "no packet capture on the Windows side",
            "no Npcap/WinPcap driver, no capture tool running, no adapter in "
            "promiscuous mode", "services / processes", host="win"))
    return out


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        out += _linux()
    if "win" in hosts:
        out += _windows()
    return sort_findings(out)
