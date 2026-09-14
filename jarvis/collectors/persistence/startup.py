"""Explain what ran at boot — specifically, windows that flash open and close.

A console window that appears for a fraction of a second and vanishes is a
process with a console attached that exited immediately: `cmd.exe /c ...`,
`wscript`, `cscript`, a `.bat` file, or PowerShell without `-WindowStyle Hidden`.
Interval sampling will never catch one reliably, so this module does not try.
It reconstructs the event after the fact from three records that persist:

  1. Task Scheduler's operational log, event 129, which names the task and the
     process it launched, with a timestamp
  2. the autostart inventory, filtered to entries that would *show a window* —
     these are the candidates, whether or not they ran this boot
  3. the Windows Error Reporting and Application logs, which catch the ones
     that flashed because they crashed

Cross-referencing 1 against 2 usually names the culprit outright.
"""

import re

from jarvis.core.paths import load_win_script
from jarvis.platform.windows import aslist, ps_json

# Things that get a console window unless explicitly hidden.
CONSOLE_HOST = re.compile(
    r"\bcmd(\.exe)?\b|\bpowershell(\.exe)?\b|\bpwsh(\.exe)?\b|\bwscript(\.exe)?\b|"
    r"\bcscript(\.exe)?\b|\bmshta(\.exe)?\b|\bconhost(\.exe)?\b|"
    r"\.bat\b|\.cmd\b|\.vbs\b|\.js\b|\.ps1\b|\bcurl(\.exe)?\b|\brobocopy\b|\bschtasks\b",
    re.I,
)
HIDDEN_FLAG = re.compile(r"-w(indowstyle)?\s+hidden|/b\b|CreateNoWindow", re.I)

# Directories an unprivileged process can write to. Applied to the *executed
# image*, never to the whole command line: a path that appears as an argument is
# data the command reads or deletes, not code it runs.
USER_WRITABLE = re.compile(
    r"\\appdata\\|\\temp\\|\\users\\public\\|\\downloads\\|\\programdata\\|"
    r"\\windows\\tasks\\", re.I,
)

# `cmd.exe /c del ...` / `rmdir ...` and nothing else. An updater writes one of
# these to RunOnce so the old version is removed on the next logon, when the
# files are no longer locked. It runs once, deletes itself from the key, and
# cannot execute anything: `del` takes no code path. It still flashes a console,
# which is worth naming, but it is not a persistence mechanism.
DELETE_ONLY = re.compile(
    r"^\s*(\"[^\"]*cmd(\.exe)?\"|\S*cmd(\.exe)?)\s+(/\w+\s+)*(del|rmdir|rd)\b", re.I)

# Anything that lets one command become another. A `del` with a `&&` after it is
# not a deletion, it is a launcher, so the RunOnce downgrade must not apply.
CHAINING = re.compile(r"[&|<>^]")

# Extensions that make a path on a command line *code* rather than data.
CODE_PATH = re.compile(
    r"(?:\"([^\"]+?\.(?:exe|com|scr|dll|cmd|bat|ps1|vbs|vbe|js|jse|wsf|msi|hta))\"|"
    r"([^\s\"]+\.(?:exe|com|scr|dll|cmd|bat|ps1|vbs|vbe|js|jse|wsf|msi|hta)))\b", re.I)


def _code_paths(it):
    """Every path on the entry that will be executed, not merely referenced.

    The launched image plus any script it is handed. `cmd.exe /c foo.cmd` runs
    System32\\cmd.exe, but the thing that decides what happens is foo.cmd, so
    grading on the image alone would miss a script staged in AppData.
    """
    paths = []
    exe = it.get("exe") or ""
    if exe:
        paths.append(exe)
    for quoted, bare in CODE_PATH.findall(it.get("cmd") or ""):
        paths.append(quoted or bare)
    return paths


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": "win"}


PS_BOOT = load_win_script("startup.ps1")



def _flash_severity(it):
    """Grade a window-showing autostart entry by what it can execute.

    The question is not "does an AppData path appear on this line" — an updater
    naming its own old version directory for deletion trips that, and it is the
    single largest source of false HIGHs. The question is which paths the entry
    actually *runs*, and whether any of them is one an attacker could replace.
    """
    cmd = it.get("cmd") or ""
    sig = (it.get("sig") or "unknown").lower()
    where = (it.get("where") or "").lower()

    # A one-shot deletion queued by an installer: flashes, but runs no code.
    # Only when nothing on the line can chain a second command onto it.
    if "runonce" in where and DELETE_ONLY.search(cmd) and not CHAINING.search(cmd):
        return "low"

    # Something it executes sits where a non-admin can overwrite it. Whatever
    # that file is today, anything that can write there picks what runs next.
    if any(USER_WRITABLE.search(p) for p in _code_paths(it)):
        return "high"

    # A missing image is a pre-authorised slot: create that file and it runs.
    if sig == "missing":
        return "high"

    # Protected location, validly signed — a vendor component. It still shows a
    # window, which is the finding, but that is not a HIGH.
    if sig == "valid":
        return "low"

    return "medium"


def _flash_note(it):
    """One clause explaining why an entry is graded the way it is."""
    sig = (it.get("sig") or "unknown").lower()
    signer = it.get("signer") or ""
    where = (it.get("where") or "").lower()
    cmd = it.get("cmd") or ""

    if "runonce" in where and DELETE_ONLY.search(cmd) and not CHAINING.search(cmd):
        return "  [RunOnce deletion — runs once then removes itself; executes no code]"
    hot = [p for p in _code_paths(it) if USER_WRITABLE.search(p)]
    if hot:
        return f"  [executes from a user-writable path: {hot[0]}]"
    if sig == "missing":
        return "  [the launched image does not exist]"
    if sig == "valid" and signer:
        return f"  [signed: {signer}]"
    if sig == "notsigned":
        return "  [unsigned]"
    return ""


def audit():
    data = ps_json(PS_BOOT, timeout=240)
    if data is None:
        return [_finding("boot", "medium", "startup analysis unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []
    boot = data.get("bootTime") or "?"
    out.append(_finding("boot", "ok", "last boot", boot.replace("T", " ")[:19], ""))

    # -- autostart entries that would visibly flash ------------------------
    flashers = []
    for it in aslist(data.get("autostart")):
        cmd = it.get("cmd") or ""
        if CONSOLE_HOST.search(cmd) and not HIDDEN_FLAG.search(cmd):
            flashers.append(it)

    for it in flashers:
        cmd = it.get("cmd") or ""
        out.append(_finding(
            "flash", _flash_severity(it),
            f"autostart shows a console window ({it.get('kind')})",
            f"{it.get('name')} → {cmd[:110]}{_flash_note(it)}", it.get("where") or ""))

    if not flashers:
        out.append(_finding("flash", "ok", "no window-showing autostart entries",
                            "nothing in Run keys, the startup folder or boot-triggered "
                            "tasks launches a visible console host", ""))

    # -- what actually ran this boot ---------------------------------------
    runs = [r for r in aslist(data.get("taskRuns")) if r.get("task")]
    seen = {}
    for r in runs:
        seen.setdefault(r.get("task"), r)
    for task, r in list(seen.items())[:40]:
        blob = f"{task} {r.get('cmd') or ''} {r.get('path') or ''}"
        ms = task.startswith("\\Microsoft\\")
        sev = "low" if ms else "medium"
        if CONSOLE_HOST.search(blob) and not ms:
            sev = "high"
        out.append(_finding("ran", sev, "task ran at boot",
                            f"{task}" + (f" → {r.get('path')}" if r.get("path") else ""),
                            (r.get("time") or "").replace("T", " ")[:19]))

    if not runs:
        out.append(_finding("ran", "medium", "task history unavailable",
                            "the Task Scheduler operational log is empty or not "
                            "readable — enable it in Task Scheduler → View → "
                            "Show All Tasks History to capture the next boot",
                            "Microsoft-Windows-TaskScheduler/Operational"))

    for c in aslist(data.get("crashes"))[:15]:
        out.append(_finding("ran", "low", "error logged since boot",
                            f"{c.get('src')}: {(c.get('msg') or '')[:100]}",
                            (c.get("time") or "").replace("T", " ")[:19]))

    return out


CAT_ORDER = {"flash": 0, "ran": 1, "boot": 2}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def sort_findings(f):
    return sorted(f, key=lambda x: (CAT_ORDER.get(x["category"], 9),
                                    SEV_ORDER.get(x["severity"], 9), x["title"]))
