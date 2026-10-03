"""Reading the posture sample from Windows, unelevated or through one UAC prompt."""

import os
import subprocess

from jarvis.core.paths import load_win_script
from jarvis.platform import host
from jarvis.platform import windows as collect_windows
from jarvis.platform.windows import ps_json

PS_POSTURE = load_win_script("posture.ps1")


def _win_temp():
    r"""%LOCALAPPDATA%\Temp as both a Windows path and a WSL path."""
    out = ps_json(
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{t=$env:TEMP})))", timeout=60)
    win = (out or {}).get("t") or r"C:\Windows\Temp"
    p = win.replace("\\", "/")
    wsl = host.local_path(win) if len(p) > 2 and p[1] == ":" else "/tmp"
    return win, wsl


def elevated_data(timeout=300):
    """Re-run the collector through a UAC prompt.

    Several of the most important checks — BitLocker, TPM, Defender's exclusion
    list, optional features — return nothing at all without elevation, and
    "nothing" is indistinguishable from "clean" unless something asks properly.
    There is no way to elevate from inside WSL without a consent prompt, so
    this writes the same script to disk, asks Windows to run it as
    administrator, and reads the result back.

    Returns (data, error). The prompt is user-visible and cancellable; a
    cancelled prompt is an error, not an empty result.
    """
    if not collect_windows.available():
        return None, "the Windows interop bridge is not available"
    win_tmp, wsl_tmp = _win_temp()
    script_wsl = os.path.join(wsl_tmp, "jarvis_posture.ps1")
    out_wsl = os.path.join(wsl_tmp, "jarvis_posture.b64")
    script_win = win_tmp + r"\jarvis_posture.ps1"
    out_win = win_tmp + r"\jarvis_posture.b64"

    for stale in (out_wsl,):
        try:
            os.unlink(stale)
        except OSError:
            pass
    try:
        # UTF-8 with BOM so PowerShell reads the file in the right encoding.
        with open(script_wsl, "w", encoding="utf-8-sig") as fh:
            fh.write(PS_POSTURE.replace(
                "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))",
                "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)) "
                "| Set-Content -Path '" + out_win + "' -Encoding ascii"))
    except OSError as exc:
        return None, f"could not stage the elevated script: {exc}"

    launcher = (
        "$p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru "
        "-WindowStyle Hidden -ArgumentList "
        "'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',"
        "'-File','" + script_win + "'; exit $p.ExitCode")
    try:
        subprocess.run([collect_windows._PS, "-NoProfile", "-NonInteractive",
                        "-Command", launcher],
                       capture_output=True, timeout=timeout,
                       cwd=host.subprocess_cwd(), **host.spawn_options())
    except subprocess.TimeoutExpired:
        return None, "timed out waiting for the elevation prompt"
    except OSError as exc:
        return None, f"could not launch an elevated shell: {exc}"

    try:
        with open(out_wsl, errors="replace") as fh:
            blob = fh.read().strip().replace("\r", "").replace("\n", "")
    except OSError:
        return None, ("no elevated result was produced — the UAC prompt was "
                      "most likely declined or dismissed")
    if not blob:
        return None, "the elevated run produced an empty result"
    try:
        import base64
        import json as _json
        return _json.loads(base64.b64decode(blob).decode("utf-8", "replace")), ""
    except Exception as exc:
        return None, f"could not decode the elevated result: {exc}"
    finally:
        for f in (script_wsl, out_wsl):
            try:
                os.unlink(f)
            except OSError:
                pass
