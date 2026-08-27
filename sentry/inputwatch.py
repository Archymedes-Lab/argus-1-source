"""Synthetic input: keystrokes and clicks that no human produced.

Windows tags every keyboard and mouse event that did not originate from real
hardware. `LLKHF_INJECTED` is set on anything delivered through `SendInput` or
`keybd_event`, and `LLKHF_LOWER_IL_INJECTED` additionally marks input injected
by a process at a lower integrity level than the window receiving it — which is
the shape of one program driving another's UI.

That flag is only visible from inside a low-level hook, so this module manages a
small Windows-side helper that installs one. Three things about that are worth
stating plainly, because all three are real costs:

**It is an agent.** Everything else here is agentless — it samples state and
exits. This runs resident on the Windows side, and if it dies the record stops.
The heartbeat exists so that a dead hook and a quiet keyboard are
distinguishable, because otherwise "no injected input" would be
indistinguishable from "not watching".

**It deliberately does not record what you type.** A low-level keyboard hook
sees every keystroke, and one that stored key values would be a keylogger
writing passwords to a SQLite file on a disk this machine's own posture audit
has confirmed is unencrypted. So real keystrokes are counted and nothing more;
injected events record only a coarse key class, the flags, and which window had
focus. Enough to say "something typed Enter into your terminal at 03:14", not
enough to reconstruct a sentence.

**Injected does not mean malicious.** Password-manager auto-type, AutoHotkey,
on-screen keyboards, accessibility tools, remote desktop, screen sharing and
some IDE features all inject legitimately. The flag also says nothing about
*which* process injected — only that the event was synthetic. The foreground
window is recorded as a weak correlate. So this reports evidence with the
context needed to judge it, and does not pretend to a verdict.
"""

import json
import os
import subprocess

from . import collect_windows
from .control import _ps_json
from .util import iso, now

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

HOOK_PS1 = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "win", "inputhook.ps1")

# Software that injects input as its normal job. Seeing these in the foreground
# alongside injected events is an explanation, not a finding.
BENIGN_INJECTORS = {
    "1password", "bitwarden", "keepass", "keepassxc", "lastpass", "dashlane",
    "autohotkey", "ahk", "osk", "tabtip", "magnify", "narrator",
    "mstsc", "rdpclip", "teamviewer", "anydesk", "rustdesk", "vncviewer",
    "synergy", "barrier", "deskflow", "sharemouse", "logioptionsplus",
    "logitech", "razer", "steam", "vmware", "virtualbox",
    "parsec", "moonlight", "sunshine", "obs64", "obs32",
}


def _finding(category, severity, title, detail, where="", host="win"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def _paths():
    """Where the helper writes, in both Windows and WSL spelling."""
    out = _ps_json(
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{t=$env:LOCALAPPDATA})))", timeout=60)
    base = (out or {}).get("t") or r"C:\Windows\Temp"
    p = base.replace("\\", "/")
    wsl = "/mnt/" + p[0].lower() + p[2:] if len(p) > 2 and p[1] == ":" else "/tmp"
    wsl_dir = os.path.join(wsl, "Sentry")
    try:
        os.makedirs(wsl_dir, exist_ok=True)
    except OSError:
        pass
    return base + r"\Sentry\input.jsonl", os.path.join(wsl_dir, "input.jsonl")


def _stage_helper():
    """Copy the hook script somewhere powershell.exe can actually reach."""
    win_out, wsl_out = _paths()
    wsl_dir = os.path.dirname(wsl_out)
    dest = os.path.join(wsl_dir, "inputhook.ps1")
    try:
        with open(HOOK_PS1, encoding="utf-8") as src, \
                open(dest, "w", encoding="utf-8-sig") as dst:
            dst.write(src.read())
    except OSError as exc:
        return None, None, f"could not stage the hook helper: {exc}"
    return win_out.rsplit("\\", 1)[0] + r"\inputhook.ps1", win_out, ""


def _pid_path():
    _win, wsl_out = _paths()
    return os.path.splitext(wsl_out)[0] + ".pid"


def running():
    """PIDs of the helper on the Windows side, if it is alive.

    Reads a pid file the helper writes rather than searching command lines.
    Searching was subtly wrong: the query's own command line contains the
    script name, so the querying shell matched itself, `running()` was always
    true, and `start()` short-circuited on "already running" without ever
    launching anything.
    """
    try:
        with open(_pid_path()) as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        return []
    d = _ps_json(
        "$ok = 0; try { $p = Get-Process -Id %d -ErrorAction Stop; "
        "if ($p.ProcessName -eq 'powershell') { $ok = 1 } } catch { };"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{ok=$ok})))" % pid, timeout=90)
    return [pid] if (d or {}).get("ok") else []


def start():
    """Launch the hook helper, hidden and detached. Returns "" on success."""
    if running():
        return "already running"
    if not collect_windows.available():
        return "the Windows interop bridge is not available"
    script_win, win_out, err = _stage_helper()
    if err:
        return err
    cmd = ("Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "
           "'-NoProfile','-ExecutionPolicy','Bypass','-File','"
           + script_win + "','-OutFile','" + win_out + "'")
    try:
        subprocess.run([collect_windows._PS, "-NoProfile", "-NonInteractive",
                        "-Command", cmd], capture_output=True, timeout=90, cwd="/")
    except (OSError, subprocess.SubprocessError) as exc:
        return f"could not start the helper: {exc}"
    return ""


def stop():
    pids = running()
    if not pids:
        return "not running"
    _ps_json("Stop-Process -Id " + ",".join(str(p) for p in pids)
             + " -Force; [Convert]::ToBase64String([Text.Encoding]::UTF8"
               ".GetBytes((ConvertTo-Json @{ok=1})))", timeout=90)
    return ""


def ingest(store):
    """Fold new helper output into the database, then truncate the file."""
    _win_out, wsl_out = _paths()
    if not os.path.exists(wsl_out):
        return 0
    try:
        with open(wsl_out, "r+", encoding="utf-8", errors="replace") as fh:
            body = fh.read()
            fh.seek(0)
            fh.truncate()
    except OSError:
        return 0

    n = 0
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("kind") == "heartbeat":
            c = rec.get("counters") or {}
            store.db.execute(
                """INSERT OR REPLACE INTO input_beats
                   (ts,real_keys,injected_keys,real_clicks,injected_clicks,
                    real_moves,injected_moves,lat_avg_ms,lat_max_ms,
                    lat_over50,lat_samples)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (int(rec.get("ts") or now()), int(c.get("real_keys") or 0),
                 int(c.get("injected_keys") or 0), int(c.get("real_clicks") or 0),
                 int(c.get("injected_clicks") or 0), int(c.get("real_moves") or 0),
                 int(c.get("injected_moves") or 0), int(c.get("lat_avg_ms") or 0),
                 int(c.get("lat_max_ms") or 0), int(c.get("lat_over50") or 0),
                 int(c.get("lat_samples") or 0)))
            continue
        store.db.execute(
            """INSERT INTO input_events(ts,kind,lower_il,class,fg)
               VALUES(?,?,?,?,?)""",
            (int(rec.get("ts") or now()), str(rec.get("kind") or "key")[:16],
             int(rec.get("lower_il") or 0), str(rec.get("class") or "")[:24],
             str(rec.get("fg") or "")[:64]))
        n += 1
    store.commit()
    return n


def audit(store, hours=24):
    out = []
    ingest(store)
    since = now() - hours * 3600

    pids = running()
    beat = store.db.execute(
        "SELECT * FROM input_beats ORDER BY ts DESC LIMIT 1").fetchone()
    if not pids:
        out.append(_finding(
            "input", "medium", "the injected-input monitor is not running",
            "synthetic keystrokes are only visible from inside a live hook, so "
            "nothing is being recorded — this is not a clean result",
            "sentry inputwatch --start"))
    elif beat and now() - beat["ts"] > 300:
        out.append(_finding(
            "input", "high", "the input hook has stopped reporting",
            f"the helper is alive but its last heartbeat was {iso(beat['ts'])} — "
            f"a hook that was removed looks exactly like a quiet keyboard",
            "inputwatch"))
    else:
        totals = (f"{beat['real_keys']} real keystrokes / "
                  f"{beat['injected_keys']} injected, "
                  f"{beat['real_moves']} real cursor moves / "
                  f"{beat['injected_moves']} injected" if beat else "no counts yet")
        out.append(_finding(
            "input", "ok", "the injected-input monitor is running",
            f"pid {pids[0]} — {totals}", "inputwatch"))

    out += _latency_findings(store, beat)

    rows = store.db.execute(
        """SELECT fg, kind, class, lower_il, COUNT(*) n,
                  MIN(ts) first, MAX(ts) last
             FROM input_events WHERE ts>=?
            GROUP BY fg, kind, class, lower_il
            ORDER BY COUNT(*) DESC""", (since,)).fetchall()
    for r in rows:
        fg = (r["fg"] or "").lower()
        benign = any(b in fg for b in BENIGN_INJECTORS)
        if r["kind"] == "click" and benign:
            continue
        sev = ("low" if benign else
               "critical" if r["lower_il"] else
               "high" if r["kind"] == "key" else "medium")
        why = ("this program injects input as part of its normal job"
               if benign else
               "injected from a lower integrity level — the shape of one "
               "process driving another's window" if r["lower_il"] else
               "no hardware produced this event")
        out.append(_finding(
            "input", sev,
            f"{r['n']} injected {r['class'] or r['kind']}"
            f"{'s' if r['n'] > 1 else ''} while "
            f"{r['fg'] or 'an unknown window'} had focus",
            f"{why} — first {iso(r['first'])}, last {iso(r['last'])}",
            "input_events"))
    return sort_findings(out)


def _latency_findings(store, beat):
    """Is anything making the cursor and keyboard feel slow?

    Every low-level hook sits in a chain and delays each event until it
    returns. That is the mechanism behind "the cursor is slower than it used
    to be" — a keylogger, a screen recorder or an overlay doing work on the
    input thread shows up here as milliseconds.

    Windows drops a hook that exceeds `LowLevelHooksTimeout` (default 300ms),
    so software that wants to keep a slow hook alive has a reason to raise
    that value. An unexplained increase is worth seeing.
    """
    out = []
    if not beat or not beat["lat_samples"]:
        return out

    avg, mx = beat["lat_avg_ms"], beat["lat_max_ms"]
    over = beat["lat_over50"]
    pct = (100.0 * over / beat["lat_samples"]) if beat["lat_samples"] else 0

    if avg >= 30 or pct >= 10:
        sev = "high" if (avg >= 60 or pct >= 25) else "medium"
        out.append(_finding(
            "input", sev, f"input events are arriving {avg} ms late on average",
            f"peak {mx} ms; {over} of {beat['lat_samples']} events "
            f"({pct:.0f}%) took over 50 ms to reach this hook. Every low-level "
            f"hook in the chain delays input until it returns, so this is what "
            f"a keylogger, screen recorder or overlay feels like. Note that "
            f"sentry's own hook is in that chain and contributes part of it — "
            f"stop it with `sentry inputwatch --stop` and see whether the "
            f"figure follows.", "input_beats"))
    else:
        out.append(_finding(
            "input", "ok", f"input latency is {avg} ms average, {mx} ms peak",
            f"{beat['lat_samples']} events sampled — nothing in the hook chain "
            f"is adding perceptible delay", "input_beats"))

    d = _ps_json(
        "$v = (Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' "
        "-Name LowLevelHooksTimeout -EA SilentlyContinue).LowLevelHooksTimeout;"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{t=$v})))", timeout=60)
    t = (d or {}).get("t")
    if t and int(t) > 300:
        out.append(_finding(
            "input", "high", f"LowLevelHooksTimeout has been raised to {t} ms",
            "Windows removes a low-level hook that takes longer than this to "
            "return. Raising it above the 300 ms default keeps slow hooks "
            "alive — which is something a keylogger benefits from and normal "
            "software rarely needs",
            r"HKCU\Control Panel\Desktop"))
    return out


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))
