"""Container intelligence: what each running container can reach on the host.

Read-only. Nothing here starts, stops, execs into, or reconfigures a
container; it only inspects what Docker already reports. Docker absent or
not running is `unavailable`, never "no containers" — a stopped daemon must
not read as a clean fleet. Every check names the exact field it read, so a
finding can be verified by hand against `docker inspect`.

This is source-tested only: it has not been measured against a scenario
where a genuinely malicious container was present, so it is not registered
as a validated detection capability (see assurance.py).
"""

import ipaddress
import json
import os
import selectors
import subprocess
import time
from contextvars import ContextVar

from jarvis.core import collection
from jarvis.core.finding import finding as _finding

TIMEOUT_S = 20
MAX_CONTAINERS = 500
MAX_OUTPUT_BYTES = 1 << 20
AUDIT_TIMEOUT_S = 60
_deadline = ContextVar("container_deadline", default=None)
DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]
INSPECT_FORMAT = (
    '{"Id":{{json .Id}},"Name":{{json .Name}},'
    '"Config":{"Image":{{json .Config.Image}}},'
    '"HostConfig":{"Privileged":{{json .HostConfig.Privileged}},'
    '"PidMode":{{json .HostConfig.PidMode}},'
    '"NetworkMode":{{json .HostConfig.NetworkMode}},'
    '"IpcMode":{{json .HostConfig.IpcMode}},'
    '"CapAdd":{{json .HostConfig.CapAdd}}},'
    '"Mounts":{{json .Mounts}},'
    '"NetworkSettings":{"Ports":{{json .NetworkSettings.Ports}}}}'
)
# Real container-breakout primitives, not general hardening advice.
DANGEROUS_CAPS = frozenset({
    "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT",
    "NET_ADMIN", "NET_RAW", "DAC_READ_SEARCH", "DAC_OVERRIDE", "BPF",
    "PERFMON", "ALL",
})
# Host paths whose read-write exposure inside a container is a host compromise
# primitive regardless of the container's own privilege flags.
SENSITIVE_HOST_PATHS = ("/", "/etc", "/root", "/boot", "/var/run/docker.sock",
                        "/run/docker.sock", "/proc", "/sys", "/home")
DOCKER_SOCK_NAMES = ("/var/run/docker.sock", "/run/docker.sock")


def _run(args):
    """Bound output and wall time; never expose raw daemon diagnostics."""
    deadline = min(_deadline.get() or float("inf"), time.monotonic() + TIMEOUT_S)
    if time.monotonic() >= deadline:
        return None, "audit time budget exhausted"
    try:
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            try:
                data = bytearray()
                with selectors.DefaultSelector() as selector:
                    selector.register(proc.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            return None, "command time budget exhausted"
                        if not selector.select(remaining):
                            return None, "command time budget exhausted"
                        chunk = os.read(proc.stdout.fileno(), 65536)
                        if not chunk:
                            break
                        if len(data) + len(chunk) > MAX_OUTPUT_BYTES:
                            return None, "command output limit exceeded"
                        data.extend(chunk)
                code = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
                if code:
                    return None, f"docker command failed (exit {code})"
                return data.decode("utf-8", "replace"), None
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
    except (OSError, subprocess.SubprocessError) as exc:
        return None, type(exc).__name__


def daemon_state():
    """(available, detail). False with a reason when Docker cannot be inspected."""
    out, err = _run([*DOCKER, "version", "--format", "{{.Server.Version}}"])
    if out is None:
        return False, err or "docker unavailable"
    return True, out.strip()


def list_containers():
    """[{id, name}] for every container Docker reports, running or not."""
    out, err = _run([*DOCKER, "ps", "-a", "--format", "{{.ID}}\t{{.Names}}"])
    if out is None:
        return None, err
    rows = []
    for line in out.splitlines():
        cid, _, name = line.partition("\t")
        if cid.strip():
            rows.append({"id": cid.strip(), "name": name.strip() or cid.strip()})
    return rows[:MAX_CONTAINERS], ("container inventory limit exceeded"
                                   if len(rows) > MAX_CONTAINERS else None)


def inspect(container_id):
    """Parsed `docker inspect` for one container, or None on any failure."""
    out, _err = _run([*DOCKER, "inspect", "--format", INSPECT_FORMAT, container_id])
    if out is None:
        return None
    try:
        cfg = json.loads(out)
    except ValueError:
        return None
    if not isinstance(cfg, dict) or not str(cfg.get("Id") or "").startswith(container_id):
        return None
    host = cfg.get("HostConfig")
    config = cfg.get("Config")
    net = cfg.get("NetworkSettings")
    mounts = cfg.get("Mounts")
    if (not isinstance(host, dict) or not isinstance(config, dict)
            or not isinstance(net, dict) or not isinstance(mounts, list)
            or not isinstance(host.get("Privileged"), bool)
            or any(not isinstance(host.get(k), str) for k in ("PidMode", "NetworkMode", "IpcMode"))
            or not isinstance(config.get("Image"), str)
            or not isinstance(cfg.get("Name"), str)):
        return None
    caps = host.get("CapAdd")
    ports = net.get("Ports")
    if ("CapAdd" not in host or "Ports" not in net
            or caps is not None and (not isinstance(caps, list) or any(not isinstance(c, str) for c in caps))
            or not isinstance(ports, (dict, type(None)))
            or any(not isinstance(m, dict) or not isinstance(m.get("RW"), bool)
                   or any(not isinstance(m.get(k), str) for k in ("Source", "Destination"))
                   for m in mounts)):
        return None
    for bindings in (ports or {}).values():
        if bindings is not None and (not isinstance(bindings, list)
                or any(not isinstance(b, dict)
                       or any(not isinstance(b.get(k), str) for k in ("HostIp", "HostPort"))
                       for b in bindings)):
            return None
    return cfg


def _mounts(cfg):
    return cfg.get("Mounts") or []


def _sensitive_mount(mount):
    src = str(mount.get("Source") or "")
    return mount.get("RW") and any(
        src == p or src.rstrip("/") == p.rstrip("/") for p in SENSITIVE_HOST_PATHS)


def _docker_sock_mounted(cfg):
    for m in _mounts(cfg):
        dst = str(m.get("Destination") or "")
        if dst in DOCKER_SOCK_NAMES or m.get("Source") in DOCKER_SOCK_NAMES:
            return True
    return False


def _dangerous_caps(cfg):
    host = cfg.get("HostConfig") or {}
    add = {str(c).upper().removeprefix("CAP_") for c in (host.get("CapAdd") or [])}
    return sorted(add & DANGEROUS_CAPS)


def _published_public(cfg):
    """Ports bound to a non-loopback host address, not just container-internal."""
    net = cfg.get("NetworkSettings") or {}
    out = []
    for container_port, bindings in (net.get("Ports") or {}).items():
        for b in bindings or []:
            # Docker's own semantics: an empty/absent HostIp binds all interfaces
            # (equivalent to 0.0.0.0), not localhost. Defaulting it to loopback
            # would hide the common case of a genuinely exposed port.
            host_ip = str(b.get("HostIp") or "") or "0.0.0.0"
            try:
                is_loopback = ipaddress.ip_address(host_ip).is_loopback
            except ValueError:
                is_loopback = False
            if not is_loopback:
                out.append(f"{host_ip}:{b.get('HostPort')}->{container_port}")
    return out


def assess(cfg):
    """One container's raw inspect data -> findings. Pure."""
    host = cfg.get("HostConfig") or {}
    name = str((cfg.get("Name") or "")).lstrip("/") or cfg.get("Id", "")[:12]
    image = str(cfg.get("Config", {}).get("Image") or "unknown")
    where = f"{name} ({image})"
    out = []

    if host.get("Privileged"):
        out.append(_finding("containers", "critical", "privileged container",
                            f"{where} runs with HostConfig.Privileged=true: full device and "
                            f"kernel-capability access, equivalent to root on the host", where))
    if host.get("PidMode") == "host":
        out.append(_finding("containers", "high", "container shares the host PID namespace",
                            f"{where} has HostConfig.PidMode=host: it can see and signal "
                            f"every host process", where))
    if host.get("NetworkMode") == "host":
        out.append(_finding("containers", "medium", "container shares the host network namespace",
                            f"{where} has HostConfig.NetworkMode=host: no network isolation "
                            f"from the host", where))
    if host.get("IpcMode") == "host":
        out.append(_finding("containers", "medium", "container shares the host IPC namespace",
                            f"{where} has HostConfig.IpcMode=host", where))
    if _docker_sock_mounted(cfg):
        out.append(_finding("containers", "critical", "the Docker socket is mounted inside a container",
                            f"{where} can mount /var/run/docker.sock: this is equivalent to "
                            f"unrestricted root on the host by design of the Docker API, "
                            f"regardless of this container's own privilege flags", where))
    for m in _mounts(cfg):
        if _sensitive_mount(m):
            out.append(_finding("containers", "critical", "sensitive host path mounted read-write",
                                f"{where} mounts host path {m.get('Source')} read-write at "
                                f"{m.get('Destination')}", where))
    caps = _dangerous_caps(cfg)
    if caps:
        out.append(_finding("containers", "high", "container was granted extra kernel capabilities",
                            f"{where} HostConfig.CapAdd includes {', '.join(caps)}", where))
    for pub in _published_public(cfg):
        out.append(_finding("containers", "low", "container port reachable beyond loopback",
                            f"{where} publishes {pub}; confirm this is intended to be reachable "
                            f"from outside this host", where))
    if not out:
        out.append(_finding("containers", "ok", "no elevated host access found",
                            f"{where}: not privileged, no host namespaces, no Docker socket, "
                            f"no sensitive host mounts, no added dangerous capabilities", where))
    return out


def _audit(hosts):
    if "wsl" not in hosts:
        return []
    available, detail = daemon_state()
    if not available:
        collection.failed("containers", detail)
        return [_finding("containers", "low", "Docker is not available for inspection",
                         f"{detail}. Container risk on this host is unknown, not clean.",
                         "docker")]
    rows, err = list_containers()
    if rows is None:
        collection.failed("containers", err or "docker ps failed")
        return [_finding("containers", "low", "container list unavailable", str(err), "docker ps")]
    out = []
    inspected, unreadable = 0, []
    for row in rows:
        cfg = inspect(row["id"])
        if cfg is None:
            unreadable.append(row["name"])
            continue
        inspected += 1
        out.extend(assess(cfg))
    if err:
        collection.failed("containers", err)
        out.append(_finding("containers", "low", "container inventory truncated",
                            err, "docker ps"))
    if unreadable:
        collection.failed("containers", "some inspections unavailable")
        out.append(_finding(
            "containers", "low", "some containers could not be inspected",
            f"{len(unreadable)} container(s) returned no inspect data: "
            + ", ".join(unreadable[:10]) + (" ..." if len(unreadable) > 10 else ""),
            "docker inspect"))
    if inspected or not rows:
        collection.succeeded("containers")
    complete = not unreadable and not err
    out.append(_finding("containers", "ok" if complete else "low",
                        "container inventory complete" if complete else "container inventory incomplete",
                        f"{inspected} of {len(rows)} container(s) inspected", "docker ps"))
    return out


def audit(store=None, hosts=("wsl",)):
    token = _deadline.set(time.monotonic() + AUDIT_TIMEOUT_S)
    try:
        return _audit(hosts)
    finally:
        _deadline.reset(token)
