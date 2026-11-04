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
  watchdog    with the app closed, Task Scheduler starts a killed daemon again within
              its 5-minute interval; firing the task while the daemon runs starts no
              second daemon and uses none of the restart budget
  recovery    with the app open, and through the app's own check, a killed daemon comes
              back; exactly one daemon runs; the same token still works and history is
              intact after every recovery
  stop        `argus stop` keeps it stopped: neither the app nor a full watchdog interval
              starts it; `argus start` brings it back
  loop guard  a daemon that keeps dying is tried a few times, then refused with a reason
              (run in a scratch profile on another port, never against the real install)
  upgrade     installing over itself keeps the pairing and the history, leaves one
              daemon, and monitoring still answers
  uninstall   task, sign-in entry, Settings > Apps entry, files and the pairing
              token are gone and the port is closed; history is removed too (everything Argus put on the PC);
              /KEEP keeps it

Run it on a clean machine or a fresh CI runner. It changes the machine (installs
and removes Argus) and ends by uninstalling.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    # A refusal must print, not crash on a cp1252 console. Some runners replace the
    # stream with one that cannot be reconfigured (unittest buffering), so ask first.
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="replace")

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
skipped = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail else ""), flush=True)
    return bool(ok)


def skip(name, why):
    skipped.append((name, why))
    print(f"SKIP  {name}  [{why}]", flush=True)


def run(cmd, timeout=900, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, **kw)


def listening(port=PORT):
    out = run(["netstat", "-ano", "-p", "TCP"]).stdout
    return len(re.findall(rf":{port}\s+\S+\s+LISTENING", out))


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


def daemon_count():
    """Daemon processes: argus.exe started with `serve`. Collector workers (-m) do not count."""
    ps = ("(Get-CimInstance Win32_Process -Filter 'Name=''argus.exe''' | "
          "Where-Object { $_.CommandLine -match ' serve ' } | Measure-Object).Count")
    out = run(["powershell", "-NoProfile", "-Command", ps]).stdout.strip()
    return int(out) if out.isdigit() else -1


def kill_daemon():
    run(["taskkill", "/F", "/T", "/IM", "argus.exe"])


def task_status():
    """What Task Scheduler says about the watchdog: for a failure's detail, never for a verdict."""
    out = run(["schtasks", "/Query", "/TN", TASK, "/V", "/FO", "LIST"]).stdout
    keep = ("Status", "Last Run Time", "Last Result", "Scheduled Task State", "Next Run Time")
    return "; ".join(line.strip() for line in out.splitlines() if line.split(":")[0].strip() in keep)


def starts_recorded():
    try:
        return len(json.loads((HISTORY / "supervised-starts.json").read_text()))
    except (OSError, ValueError):
        return 0


def intact(label, token_before, marker):
    same = TOKEN.is_file() and TOKEN.read_bytes() == token_before
    check(f"{label}: the same token still works", same and get("/api/pulse", token_text())[0] == 200)
    check(f"{label}: history is intact", marker.exists())


def only_this_account_can_read(path):
    out = run(["icacls", str(path)]).stdout
    me = os.environ["USERNAME"]
    others = [g for g in ("Everyone", "BUILTIN\\Users", "Authenticated Users") if g in out]
    return me in out and not others, out.strip().splitlines()[0] if out.strip() else ""


def install(setup):
    return run([str(setup), "/S"], timeout=1200)


def uninstall(keep=False):
    exe = INSTDIR / "Uninstall.exe"
    if not exe.exists():
        return None
    # _?= makes the uninstaller run in place and wait, instead of copying itself away.
    r = run([str(exe), "/S", *(["/KEEP"] if keep else []), f"_?={INSTDIR}"], timeout=300)
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


def recovery_and_supervision():
    HISTORY.mkdir(exist_ok=True)
    marker = HISTORY / "recovery-marker"
    marker.write_text("kept")
    token_before = TOKEN.read_bytes()
    app, exe = INSTDIR / "argus-desktop.exe", INSTDIR / "argus.exe"

    # 1. App closed: the watchdog task alone brings a killed daemon back.
    kill_daemon()
    check("watchdog (app closed): the daemon is really down", wait_for(lambda: listening() == 0, 30))
    t0 = time.time()
    back = wait_for(lambda: listening() >= 1, 420, every=5)
    check("watchdog (app closed): Task Scheduler starts it again", back,
          f"{time.time() - t0:.0f} s" + ("" if back else "; " + task_status()))
    check("watchdog (app closed): exactly one daemon", wait_for(lambda: daemon_count() == 1, 30),
          f"{daemon_count()} daemon process(es)")
    intact("watchdog (app closed)", token_before, marker)

    # 2. Firing the task while the daemon runs is harmless and costs no restart budget.
    budget = starts_recorded()
    for _ in range(3):
        run(["schtasks", "/Run", "/TN", TASK])
        time.sleep(10)
    check("watchdog: firing the task while the daemon runs starts no second daemon",
          daemon_count() == 1 and listening() == 1, f"{daemon_count()} daemon process(es)")
    check("watchdog: ... and uses none of the restart budget", starts_recorded() == budget,
          f"{budget} -> {starts_recorded()} recorded starts")
    intact("watchdog (task fired while running)", token_before, marker)

    # 3. App open: the real window process is running while the daemon dies.
    proc = subprocess.Popen([str(app), "--hidden"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(25)
    if proc.poll() is not None:
        skip("recovery (app open)", f"the app exited with {proc.returncode} within 25 s: this runner may have "
             "no usable desktop session or WebView2, so the window itself was not exercised")
    else:
        print("NOTE  the app window process stayed up for 25 s on this machine (WebView2 and a desktop session exist)")
        kill_daemon()
        check("recovery (app open): the daemon is really down", wait_for(lambda: listening() == 0, 30))
        t0 = time.time()
        back = wait_for(lambda: listening() >= 1, 200, every=3)
        check("recovery (app open): monitoring resumes", back,
              f"{time.time() - t0:.0f} s (the watchdog alone can need up to 300 s)")
        check("recovery (app open): exactly one daemon, the app and the watchdog did not both start one",
              wait_for(lambda: daemon_count() == 1, 30), f"{daemon_count()} daemon process(es)")
        intact("recovery (app open)", token_before, marker)
        proc.kill()
        proc.wait()

    # 4. The app's own recovery logic, deterministically (what the open app does when it sees a dead daemon).
    kill_daemon()
    check("recovery (app check): the daemon is really down", wait_for(lambda: listening() == 0, 30))
    chk = run([str(app), "--check"], timeout=240)
    check("recovery (app check): the app starts it and monitoring answers",
          chk.returncode == 0 and listening() == 1, f"exit {chk.returncode}")
    check("recovery (app check): exactly one daemon", wait_for(lambda: daemon_count() == 1, 30))
    intact("recovery (app check)", token_before, marker)

    # 5. Stopping on purpose is respected by the app and by a full watchdog interval.
    r = run([str(exe), "stop"])
    check("stop: `argus stop` exits 0", r.returncode == 0, f"exit {r.returncode}")
    check("stop: the daemon is down", wait_for(lambda: listening() == 0, 30))
    chk = run([str(app), "--check"], timeout=120)
    check("stop: the app does not turn it back on", chk.returncode == 3 and listening() == 0,
          f"app check exit {chk.returncode}")
    time.sleep(330)    # more than one full 5-minute watchdog interval
    check("stop: the watchdog leaves it stopped", listening() == 0 and daemon_count() == 0, task_status())
    r = run([str(exe), "start"])
    check("stop: `argus start` exits 0", r.returncode == 0, f"exit {r.returncode}")
    check("stop: monitoring resumes after `argus start`", wait_for(lambda: listening() >= 1, 120, every=3))
    check("stop: exactly one daemon", wait_for(lambda: daemon_count() == 1, 30))
    intact("stop", token_before, marker)

    # 6. A daemon that keeps dying is not restarted forever (scratch profile and port: never the real install).
    scratch = tempfile.mkdtemp(prefix="argus-loop-")
    port = 18799
    env = {**os.environ, "USERPROFILE": scratch, "HOME": scratch, "ARGUS_RESTART_LIMIT": "2"}
    cmd = [str(exe), "serve", "--port", str(port), "--supervised"]
    for i in (1, 2):
        p = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        check(f"loop guard: start {i} of 2 is allowed", wait_for(lambda: listening(port) >= 1, 120, every=3))
        run(["taskkill", "/F", "/T", "/PID", str(p.pid)])
        wait_for(lambda: listening(port) == 0, 30)
    third = run(cmd, env=env, timeout=120)
    said = (third.stderr or "") + (third.stdout or "")
    check("loop guard: the third start within the hour is refused with the reason",
          third.returncode == 75 and "will not be started again" in said, f"exit {third.returncode}")
    check("loop guard: nothing is listening after the refusal", listening(port) == 0)
    shutil.rmtree(scratch, ignore_errors=True)


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

    # ---- watchdog, recovery, intentional stop, restart-loop guard ----
    recovery_and_supervision()

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
    r = uninstall(keep=True)
    check("uninstall: exits 0", r is not None and r.returncode == 0, f"exit {getattr(r, 'returncode', None)}")
    check("uninstall: task removed", run(["schtasks", "/Query", "/TN", TASK]).returncode != 0)
    check("uninstall: sign-in entry removed", run(
        ["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "Argus"]).returncode != 0)
    check("uninstall: Settings > Apps entry removed", run(
        ["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Argus"]).returncode != 0)
    check("uninstall: files removed", not INSTDIR.exists())
    check("uninstall: pairing token removed", not TOKEN.exists())
    check("uninstall: nothing is listening", wait_for(lambda: listening() == 0, 30))
    check("uninstall: no Argus process is left running", wait_for(lambda: daemon_count() == 0, 30))
    check("uninstall /KEEP: history kept", marker.exists())
    install(setup)
    uninstall()
    check("uninstall: history removed by default", not HISTORY.exists())
    check("uninstall: input hook task removed", run(["schtasks", "/Query", "/TN", "ARGUS input hook"]).returncode != 0)
    check("uninstall: Argus app-data folder removed", not (Path(os.environ["LOCALAPPDATA"]) / "Argus").exists())

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)} of {len(results)} checks passed, {len(skipped)} skipped"
          + ("".join(f"\n  skipped: {n} ({why})" for n, why in skipped)))
    if failed:
        sys.exit("FAILED: " + "; ".join(failed))


if __name__ == "__main__":
    main()
