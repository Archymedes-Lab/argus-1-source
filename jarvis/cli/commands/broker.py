"""`jarvis broker` — the elevated collector broker.

    jarvis broker status     installed, current, last run, per-job result
    jarvis broker install    stage scripts and register the task (one UAC prompt)
    jarvis broker install --firewall-logging
                             also log allowed and blocked firewall connections
    jarvis broker remove     unregister and delete (one UAC prompt)
    jarvis broker sysmon-baseline
                             apply windows-sysmon/jarvis-windows-baseline.xml
                             with an exact registry backup in the vault,
                             verification and automatic rollback (one UAC prompt)
"""

import base64
import hashlib
import subprocess
import time
from pathlib import Path

from jarvis.core.paths import REPO_ROOT, WIN_SCRIPTS_DIR
from jarvis.platform import broker, elevation, host
from jarvis.platform import windows as win


def _winpath(path):
    return host.windows_name(path)


def _ps_args(script):
    """PowerShell argv immune to WSL/Windows command-line quote rewriting.

    Progress is silenced: over a pipe PowerShell serialises it as CLIXML
    ("Preparing modules for first use") into stderr, which reached the user."""
    script = "$ProgressPreference='SilentlyContinue';" + script
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return [win._PS, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]


STAGE_TRIES = 3
STAGE_TIMEOUT_S = 60


def _clean(text):
    """PowerShell output without CLIXML serialisation noise."""
    return "\n".join(line for line in (text or "").splitlines()
                     if not line.startswith(("#< CLIXML", "<Objs "))).strip()


def _make_stage(prefix):
    """A fresh folder under the Windows user's TEMP: (path, "") or ("", why).

    Retried: right after a daemon restart or a task registration the interop
    bridge can refuse one call (2026-10-27: "could not create a staging
    folder", fine seconds later), and the real error used to be discarded."""
    script = (f"$d=Join-Path $env:TEMP ('{prefix}-'+[guid]::NewGuid());"
              "New-Item -ItemType Directory $d | Out-Null; $d")
    why = ""
    for attempt in range(STAGE_TRIES):
        if attempt:
            time.sleep(3 * attempt)
        try:
            r = subprocess.run(_ps_args(script), capture_output=True, text=True,
                               errors="replace", cwd="/", timeout=STAGE_TIMEOUT_S)
        except (OSError, subprocess.SubprocessError) as exc:
            why = f"{type(exc).__name__}: {exc}"
            continue
        stage = r.stdout.strip().splitlines()[-1].strip() if r.stdout.strip() else ""
        if r.returncode == 0 and stage:
            return stage, ""
        why = _clean(r.stderr)[-400:] or f"PowerShell exited {r.returncode} with no output"
    return "", f"could not create a staging folder on Windows after {STAGE_TRIES} tries: {why}"


def _elevated_files(files, entry, args, timeout=240, prefix="jarvis-elevated"):
    """Stage `files` ({name: path}) in a fresh local folder and run `entry`
    elevated through one UAC prompt. Returns (exit code, output).

    Never run from the \\\\wsl share, and never from the stage either: the
    elevated shell copies each file into Program Files and matches it against
    the SHA-256 taken here before the prompt (platform/elevation.py), so a
    file the user swaps in between runs nothing. "{trusted}" in `args` names
    that checked folder.
    """
    if not win.available():
        return 1, "the Windows interop bridge is not available"
    hashes = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in files.items()}
    stage, why = _make_stage(prefix)
    if not stage:
        return 1, why
    copy = ";".join(f"Copy-Item -LiteralPath {elevation.literal(_winpath(path))} "
                    f"-Destination {elevation.literal(stage + chr(92) + name)}"
                    for name, path in files.items())
    script = f"{copy}; " + elevation.launcher(
        elevation.inline_command(stage, hashes, entry, args),
        after=f"Remove-Item -LiteralPath {elevation.literal(stage)} -Recurse -Force;")
    try:
        r = subprocess.run(_ps_args(script),
                           capture_output=True, text=True, errors="replace", timeout=timeout, cwd="/")
    except subprocess.TimeoutExpired:
        return 1, "timed out waiting for the UAC prompt"
    return r.returncode, _clean(r.stdout + "\n" + r.stderr)


def _sysmon_baseline():
    from jarvis.collectors.telemetry import sysmon_policy
    policy = REPO_ROOT / sysmon_policy.BASELINE
    installer = REPO_ROOT / "scripts" / "repair" / "apply-jarvis-sysmon-policy.ps1"
    digest = hashlib.sha256(policy.read_bytes()).hexdigest()
    print(f"baseline SHA-256 {digest}")
    print("approve the UAC prompt on the Windows desktop…")
    code, out = _elevated_files(
        {"apply.ps1": installer, "baseline.xml": policy}, "apply.ps1",
        ["-PolicyPath", "{trusted}\\baseline.xml", "-ExpectedSha256", digest])
    if out:
        print(out)
    # Success is what the elevated broker next reads back, not the exit code.
    print("applied; the evidence job confirms the running hash on its next run"
          if code == 0 else "did not complete — nothing is changed unless the script reported it")
    return 0 if code == 0 else 1


def _elevated(args, timeout=240):
    """Run jarvis-elevated-broker.ps1 with `args` through a UAC prompt, from a local copy.

    An elevated shell executing a file the user can edit is the hole the
    broker is built to avoid, even for the instant of installation: the broker
    and its job scripts run only from the checked copy (_elevated_files), and
    the broker installs its jobs from that copy (-Source).
    """
    names = [broker.BROKER_SCRIPT] + list(broker.SCRIPTS.values())
    files = {n: (REPO_ROOT if n == broker.BROKER_SCRIPT else WIN_SCRIPTS_DIR) / n for n in names}
    return _elevated_files(files, broker.BROKER_SCRIPT, [*args, "-Source", "{trusted}"],
                           timeout=timeout, prefix="jarvis-broker")


def cmd_broker(args, store=None):
    if args.action == "status":
        if not broker.installed():
            print("not installed — run `jarvis broker install`")
            return 1
        drift = broker.drifted()
        print("scripts:", "match this checkout" if not drift else "DIFFER: " + ", ".join(drift))
        st = broker.status() or {}
        if not st:
            print("no run recorded yet")
            return 1
        print(f"admin token: {st.get('admin')}; last run finished "
              f"{int((time.time() - (st.get('finished') or 0)) / 60)}m ago")
        for name, job in (st.get("jobs") or {}).items():
            print(f"  {name:9} {'ok' if job.get('ok') else 'FAILED'} {job.get('secs')}s {job.get('error') or ''}")
        return 0
    if args.action == "sysmon-baseline":
        return _sysmon_baseline()
    if args.action == "install":
        extra = ["-Install"] + (["-EnableFirewallLogging"] if args.firewall_logging else [])
        print("approve the UAC prompt on the Windows desktop…")
        code, out = _elevated(extra)
    else:
        print("approve the UAC prompt on the Windows desktop…")
        code, out = _elevated(["-Remove"])
    if out:
        print(out)
    if args.action == "install":
        # An older installation does not make a failed restage successful.
        # The elevated command must complete and every staged script must
        # match this checkout before we say "done".
        ok = code == 0 and broker.installed() and not broker.drifted()
    else:
        ok = code == 0 and not broker.installed()
    print("done" if ok else "did not complete — the prompt may have been declined")
    return 0 if ok else 1


def add_parser(sub):
    p = sub.add_parser("broker", help="elevated read-only collectors (posture, memscan, firewall log)")
    p.add_argument("action", nargs="?", default="status", choices=["status", "install", "remove",
                                                               "sysmon-baseline"])
    p.add_argument("--firewall-logging", action="store_true",
                   help="on install, also log allowed and blocked firewall connections")
    p.set_defaults(fn=cmd_broker)
    return p
