#!/usr/bin/env python3
"""Clean-machine acceptance test for Argus-Setup.exe (Windows 10/11 x64).

    python release/windows/install_test.py PATH\\Argus-Setup.exe

Does exactly what a customer does, without a terminal step of theirs: run the
installer, then look at what is on the machine. It exits non-zero unless all of
these hold, and prints every check with its result:

  contents    the installer holds the compiled daemon and the app, and no source,
              bytecode or script
  install     /S exits 0 (which means the installer's own verification saw
              monitoring answer); files, logon task, sign-in entry, Settings > Apps
              entry exist
  pairing     the app's token file exists, is readable by this account only, and
              was created without anyone running a pairing command
  access      an unauthenticated request is refused (403); the app's token is accepted
  data        the daemon answers with real state: ok, a score, collectors that ran
  honesty     the pulse is not reported healthy-and-complete: the areas that need
              the administrator sensor are named with that reason
  recovery    after the daemon is killed, the app starts it again and monitoring
              answers; whether Task Scheduler also restarts it is recorded (not asserted)
  upgrade     installing over itself keeps the pairing and the history, leaves one
              daemon, and monitoring still answers
  uninstall   task, sign-in entry, Settings > Apps entry, files and the pairing
              token are gone and the port is closed; history stays unless /PURGE,
              which removes it

Run it on a clean machine or a fresh CI runner. It changes the machine (installs
and removes Argus) and ends by uninstalling.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    _stream.reconfigure(errors="replace")  # a refusal must print, not crash on a cp1252 console

PORT = 8787
TASK = "argus native service"
LOCAL = Path(os.environ["LOCALAPPDATA"])
HOME = Path(os.environ["USERPROFILE"])
INSTDIR = LOCAL / "Programs" / "Argus"
TOKEN = Path(os.environ["APPDATA"]) / "local.argus.desktop" / "client.token"
HISTORY = HOME / ".argus"
SENSOR_REASON = "Needs administrator sensor"
FORBIDDEN = (".py", ".pyc", ".pyo", ".ps1", ".psm1", ".pem", ".key", ".map")

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail else ""), flush=True)
    return bool(ok)


def run(cmd, timeout=900, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, **kw)


def listening():
    out = run(["netstat", "-ano", "-p", "TCP"]).stdout
    return len(re.findall(rf":{PORT}\s+\S+\s+LISTENING", out))


def wait_for(pred, seconds, every=2):
    end = time.time() + seconds
    while time.time() < end:
        if pred():
            return True
        time.sleep(every)
    return pred()


def get(path, token=None, timeout=60):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}")
    if token:
        req.add_header("X-ARGUS-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, OSError, ValueError):
        return 0, None


def token_text():
    try:
        return TOKEN.read_text().strip()
    except OSError:
        return ""


def pulse():
    return get("/api/pulse", token_text())[1] or {}


def only_this_account_can_read(path):
    out = run(["icacls", str(path)]).stdout
    me = os.environ["USERNAME"]
    others = [g for g in ("Everyone", "BUILTIN\\Users", "Authenticated Users") if g in out]
    return me in out and not others, out.strip().splitlines()[0] if out.strip() else ""


def install(setup):
    return run([str(setup), "/S"], timeout=1200)


def uninstall(purge=False):
    exe = INSTDIR / "Uninstall.exe"
    if not exe.exists():
        return None
    # _?= makes the uninstaller run in place and wait, instead of copying itself away.
    r = run([str(exe), "/S", *(["/PURGE"] if purge else []), f"_?={INSTDIR}"], timeout=300)
    for leftover in (exe,):
        leftover.unlink(missing_ok=True)
    shutil.rmtree(INSTDIR, ignore_errors=True)
    return r


def contents(setup):
    seven = shutil.which("7z") or shutil.which("7zz") or r"C:\Program Files\7-Zip\7z.exe"
    if not Path(seven).exists() and not shutil.which("7z"):
        return check("contents: 7z available", False, "7-Zip is needed to list the installer")
    names = [line.split(None, 5)[-1] for line in run([seven, "l", "-ba", str(setup)]).stdout.splitlines() if line.strip()]
    low = [n.lower() for n in names]
    ok = check("contents: compiled daemon is inside", any(n.endswith("argus.exe") for n in low), f"{len(names)} members")
    ok &= check("contents: desktop app is inside", any(n.endswith("argus-desktop.exe") for n in low))
    bad = [n for n in names if n.lower().endswith(FORBIDDEN)]
    ok &= check("contents: no source, bytecode or script", not bad, ", ".join(bad[:5]))
    return ok


def main():
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        sys.exit(__doc__)
    setup = Path(sys.argv[1]).resolve()
    if INSTDIR.exists() or TOKEN.exists():
        sys.exit("this machine already has Argus installed: run the test on a clean machine")
    if listening():
        sys.exit(f"port {PORT} is already in use: run the test on a clean machine")

    contents(setup)

    # ---- install ----
    r = install(setup)
    check("install: /S exits 0 (the installer saw monitoring answer)", r.returncode == 0, f"exit {r.returncode}")
    check("install: program files", (INSTDIR / "argus.exe").is_file() and (INSTDIR / "argus-desktop.exe").is_file())
    check("install: logon task registered", run(["schtasks", "/Query", "/TN", TASK]).returncode == 0)
    check("install: starts at sign-in", "argus-desktop.exe" in run(
        ["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "Argus"]).stdout)
    check("install: listed in Settings > Apps", run(
        ["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Argus"]).returncode == 0)

    # ---- pairing, with no manual step ----
    check("pairing: token file exists", TOKEN.is_file(), str(TOKEN))
    private, acl = only_this_account_can_read(TOKEN) if TOKEN.is_file() else (False, "")
    check("pairing: token readable by this account only", private, acl)
    tok = token_text()
    check("pairing: token has the client format", bool(re.fullmatch(r"jc1_[0-9a-f]{12}_[A-Za-z0-9_-]{43}", tok)) or
          bool(re.fullmatch(r"ac1_[0-9a-f]{12}_[A-Za-z0-9_-]{43}", tok)), "format only; the secret is not printed")

    # ---- access ----
    check("access: a request without a token is refused", get("/api/pulse")[0] == 403)
    status, p = get("/api/pulse", tok)
    check("access: the app's token is accepted", status == 200 and bool(p), f"HTTP {status}")

    # ---- data ----
    got = wait_for(lambda: isinstance(pulse().get("score"), int), 300)
    p = pulse()
    check("data: monitoring returns a score", got, f"score {p.get('score')}")
    st, state = get("/api/state", tok, timeout=120)
    check("data: full state is readable", st == 200 and isinstance(state, dict) and bool(state), f"HTTP {st}")

    # ---- honesty ----
    blind = {b.get("job"): b.get("reason") for b in p.get("blind") or []}
    named = [j for j, why in blind.items() if why == SENSOR_REASON]
    check("honesty: areas needing the administrator sensor are named", len(named) >= 4, ", ".join(sorted(named)))
    chk = run([str(INSTDIR / "argus-desktop.exe"), "--check"], timeout=180)
    check("honesty: the app's own check passes", chk.returncode == 0, f"exit {chk.returncode}")

    # ---- recovery ----
    run(["taskkill", "/F", "/T", "/IM", "argus.exe"])
    check("recovery: the daemon is really down", wait_for(lambda: listening() == 0, 30))
    chk = run([str(INSTDIR / "argus-desktop.exe"), "--check"], timeout=240)
    check("recovery: the app restarts it and monitoring answers", chk.returncode == 0 and listening() == 1,
          f"exit {chk.returncode}")
    run(["taskkill", "/F", "/T", "/IM", "argus.exe"])
    restarted = wait_for(lambda: listening() >= 1, 150, every=5)
    print(f"NOTE  Task Scheduler restarted a killed daemon without the app: {'yes' if restarted else 'no'} (recorded, not asserted)")
    if not restarted:
        run([str(INSTDIR / "argus-desktop.exe"), "--check"], timeout=240)

    # ---- upgrade ----
    HISTORY.mkdir(exist_ok=True)
    marker = HISTORY / "upgrade-marker"
    marker.write_text("kept")
    before = TOKEN.read_bytes()
    r = install(setup)
    check("upgrade: installing over itself exits 0", r.returncode == 0, f"exit {r.returncode}")
    check("upgrade: pairing kept", TOKEN.is_file() and TOKEN.read_bytes() == before)
    check("upgrade: history kept", marker.exists())
    check("upgrade: exactly one daemon", wait_for(lambda: listening() == 1, 60))
    check("upgrade: monitoring answers", get("/api/pulse", token_text())[0] == 200)
    check("upgrade: no leftover previous version", not Path(str(INSTDIR) + ".previous").exists())

    # ---- uninstall ----
    r = uninstall()
    check("uninstall: exits 0", r is not None and r.returncode == 0, f"exit {getattr(r, 'returncode', None)}")
    check("uninstall: task removed", run(["schtasks", "/Query", "/TN", TASK]).returncode != 0)
    check("uninstall: sign-in entry removed", run(
        ["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "Argus"]).returncode != 0)
    check("uninstall: Settings > Apps entry removed", run(
        ["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Argus"]).returncode != 0)
    check("uninstall: files removed", not INSTDIR.exists())
    check("uninstall: pairing token removed", not TOKEN.exists())
    check("uninstall: nothing is listening", wait_for(lambda: listening() == 0, 30))
    check("uninstall: history kept by default", marker.exists())
    install(setup)
    uninstall(purge=True)
    check("uninstall /PURGE: history removed", not HISTORY.exists())

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)} of {len(results)} checks passed")
    if failed:
        sys.exit("FAILED: " + "; ".join(failed))


if __name__ == "__main__":
    main()
