#!/usr/bin/env python3
"""Build Argus-Setup.exe: the one Windows download (desktop app + monitoring program).

    python release/build_windows.py --version V --out DIR --desktop DIR [--ref HEAD] [--jobs 4]

Runs in CI on windows-2025 (.github/workflows/release.yml, job windows-installer).
No Python, bytecode or PowerShell file ships (release/policy.json denies them):

  1. export the commit and rename jarvis -> argus (release/rename.py);
  2. embed the 41 PowerShell collector payloads into a generated module
     (argus/core/win_payloads.py), so the compiled program needs no .ps1;
  3. compile the package and release/launcher.py with Nuitka into a standalone
     argus.exe plus its libraries (the CLI and the daemon are the same program);
  4. smoke-test the compiled program: it starts, refuses arbitrary `-m` modules,
     and passes its own shipped verification;
  5. stage argus.exe + libraries + argus-desktop.exe (built by build_desktop.py)
     and REFUSE the build if the staged folder holds anything the policy denies
     or lacks anything the installer needs;
  6. makensis release/windows/Argus-Setup.nsi -> Argus-Setup.exe;
  7. run the content gate over it.

Elevated Windows sensors (the Sysmon-fed service and the read-only broker) are
PowerShell and are not part of this edition. Collectors that need them report
themselves as unavailable; the app says which and why.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    # A refusal must print, not crash on a cp1252 console. Some runners replace the
    # stream with one that cannot be reconfigured (unittest buffering), so ask first.
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="replace")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_server  # noqa: E402  (DATA_KEEP, REPO_DATA)
import gate  # noqa: E402
import rename  # noqa: E402

NSI = HERE / "windows" / "Argus-Setup.nsi"
INSTALLER = "Argus-Setup.exe"
DESKTOP_EXE = "argus-desktop-windows-x64.exe"
# What the staged folder must hold, and what it must never hold.
REQUIRED = ("argus.exe", "argus-desktop.exe")
FORBIDDEN_SUFFIXES = tuple(gate.load_policy()["deny_suffixes"])


# ---- pure steps (unit-tested in tests/test_release_windows.py) ---------------

def payloads_module(win_dir):
    """Source of argus/core/win_payloads.py: every .ps1 of platform/win, byte for byte.

    Read the way paths.load_win_script reads (UTF-8, errors replaced, newlines
    untouched) so the embedded text is exactly what the file loader returned.
    """
    lines = ['"""Generated at build time: the PowerShell payloads, compiled into the program."""', "",
             "PAYLOADS = {"]
    for f in sorted(Path(win_dir).glob("*.ps1")):
        with open(f, encoding="utf-8", errors="replace", newline="") as fh:
            lines.append(f"    {f.name!r}: {fh.read()!r},")
    lines.append("}")
    return "\n".join(lines) + "\n"


def product_version(version):
    """VIProductVersion wants a.b.c.d: a date a.b.c, or a.b.c.d with a revision."""
    nums = [int(p) for p in version.replace("-", ".").split(".") if p.isdigit()][:4]
    return ".".join(str(n) for n in nums + [0] * (4 - len(nums)))


def stage_problems(stage):
    """Why this staged folder must not become an installer ([] when it may)."""
    stage = Path(stage)
    problems = [f"{name} is missing" for name in REQUIRED if not (stage / name).is_file()]
    for f in sorted(stage.rglob("*")):
        rel = f.relative_to(stage).as_posix()
        if f.is_symlink():
            problems.append(f"{rel} is a symlink")
        elif f.is_file() and rel.lower().endswith(FORBIDDEN_SUFFIXES):
            problems.append(f"{rel} is a file type the release policy denies")
    return problems


def is_ours(rel):
    """Our own program and data, as opposed to the third-party runtime beside them
    (the Python and OpenSSL DLLs, extension modules, the cryptography package)."""
    rel = rel.replace("\\", "/")
    return rel in ("argus.exe", "argus-desktop.exe") or rel.startswith("argus/")


def strict_problems(stage):
    """Everything that is ours must pass the committed policy's ORIGINAL markers.

    A reviewed policy may narrow the Windows path markers so third-party runtime
    binaries that carry their maintainers' CI paths are not refused. That must
    not also hide a leak of our own build machine's paths, so our files are
    always scanned with the committed policy, never with a proposal.
    """
    policy = gate.load_policy()
    out = []
    for f in sorted(Path(stage).rglob("*")):
        rel = f.relative_to(stage).as_posix()
        if f.is_file() and not f.is_symlink() and is_ours(rel):
            out += gate.scan_bytes(f"{rel} (ours, committed policy)", f.read_bytes(), policy)
    return out


def stage_folder(dist, desktop_exe, stage):
    stage = Path(stage)
    shutil.copytree(dist, stage)
    shutil.copyfile(desktop_exe, stage / "argus-desktop.exe")
    problems = stage_problems(stage) + strict_problems(stage)
    if problems:
        sys.exit("refusing to build the installer:\n  " + "\n  ".join(problems))
    return stage


SOURCE_MAP_COMMENT = re.compile(rb"\r?\n?[ \t]*(?://|/\*)[#@] sourceMappingURL=[^\r\n]*")


def data_files(tree, clean_dir):
    """[(source path, path inside the program)] for the package data that ships.

    Globbed so it is the same on every Python: `Path.glob("dir/**")` returns only
    directories up to Python 3.12 and files as well from 3.13, so build_server.py's
    loop shipped no web/static file at all from a 3.12 build (the published Linux
    server has none), while a local 3.13 build shipped them. A pattern ending in
    /** is every file below the directory.

    Vendored web libraries end with a `sourceMappingURL` comment that points at a
    map we do not ship. The release policy denies that marker, so the comment (not
    the code) is removed from a copy; the build refuses to go on if it survives.
    """
    pkg = Path(tree) / "argus"
    out = []
    for pattern in build_server.DATA_KEEP:
        if pattern.endswith("/**"):
            found = sorted(p for p in (pkg / pattern[:-3]).rglob("*") if p.is_file())
        else:
            found = sorted(p for p in pkg.glob(pattern) if p.is_file())
        for f in found:
            rel = f.relative_to(tree).as_posix()
            data = f.read_bytes()
            if f.suffix in (".js", ".css") and b"sourceMappingURL=" in data:
                data = SOURCE_MAP_COMMENT.sub(b"", data)
                if b"sourceMappingURL=" in data:
                    sys.exit(f"{rel}: a sourceMappingURL reference remains after cleaning")
                f = Path(clean_dir) / rel
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_bytes(data)
            out.append((f, rel))
    return out


# ---- build steps (need Windows, Nuitka, MSVC, makensis) ----------------------

def nuitka(tree, work, jobs):
    cmd = [sys.executable, "-m", "nuitka", "--standalone", "--assume-yes-for-downloads", "--msvc=latest",
           f"--output-dir={work}", "--output-filename=argus.exe",
           "--include-package=argus", "--include-package=cryptography",
           "--python-flag=isolated", "--python-flag=safe_path",
           "--file-reference-choice=runtime", "--lto=no", f"--jobs={jobs}",
           # Console when started from a terminal (argus status), none when the
           # logon task or the app starts it: no window flashes at sign-in.
           "--windows-console-mode=attach",
           f"--report={work}/nuitka-report.xml", "--remove-output",
           "--no-deployment-flag=self-execution",
           "--include-module=_json", "--include-module=_bisect"]
    for src, rel in data_files(tree, work / "data-clean"):
        cmd.append(f"--include-data-files={src}={rel}")
    cmd.append(str(tree / "release" / "launcher.py"))
    print("$ " + " ".join(cmd[:12]) + " ...", flush=True)
    subprocess.run(cmd, cwd=tree, check=True)
    dist = work / "launcher.dist"
    if not (dist / "argus.exe").is_file():
        sys.exit(f"Nuitka produced no {dist}\\argus.exe")
    return dist


def smoke(dist):
    """The compiled program starts, refuses arbitrary -m modules, passes its own checks."""
    home = tempfile.mkdtemp(prefix="argus-smoke-")
    env = {**os.environ, "USERPROFILE": home, "HOME": home}
    exe = str(dist / "argus.exe")
    r = subprocess.run([exe, "--help"], capture_output=True, text=True, env=env, timeout=180)
    if r.returncode != 0:
        sys.exit(f"argus.exe --help failed:\n{r.stdout}{r.stderr}")
    r = subprocess.run([exe, "-m", "os"], capture_output=True, text=True, env=env, timeout=60)
    if r.returncode != 2:
        sys.exit("argus.exe ran an arbitrary -m module")
    report = Path(home) / "verification.json"
    r = subprocess.run([exe, "-m", "argus.verify", "--json", str(report)], capture_output=True,
                       text=True, env=env, timeout=900)
    if r.returncode != 0:
        sys.exit(f"the compiled program fails its own verification:\n{(r.stdout + r.stderr)[-3000:]}")
    return json.loads(report.read_text())


def makensis(stage, out, version, icon):
    exe = shutil.which("makensis") or r"C:\Program Files (x86)\NSIS\makensis.exe"
    if not Path(exe).exists() and not shutil.which("makensis"):
        sys.exit("makensis not found (CI installs it; locally: https://nsis.sourceforge.io)")
    defines = [f"-DVERSION={version}", f"-DPRODUCT_VERSION={product_version(version)}",
               f"-DSRC={stage}", f"-DOUTFILE={out / INSTALLER}"]
    if icon and Path(icon).is_file():
        defines.append(f"-DICON={icon}")
    r = subprocess.run([exe, "-V2", "-NOCD", *defines, str(NSI)], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"makensis failed:\n{r.stdout}{r.stderr}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--desktop", required=True, help=f"folder holding {DESKTOP_EXE} (build_desktop.py --platform windows)")
    ap.add_argument("--ref", default="HEAD")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--proposal", action="append", default=[], help="dry run only: a policy proposal under review (release/proposals/)")
    ap.add_argument("--work", help="build folder (default: a temporary one)")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    desktop_exe = Path(args.desktop) / DESKTOP_EXE
    if not desktop_exe.is_file():
        sys.exit(f"{desktop_exe} is missing: build the desktop app first")
    repo = HERE.parent
    with tempfile.TemporaryDirectory(prefix="argus-win-") as tmp:
        work = Path(args.work or tmp)
        tree = work / "tree"
        shutil.rmtree(tree, ignore_errors=True)
        commit = rename.export(repo, args.ref, tree)
        print(f"exported {commit} as Argus", flush=True)
        (tree / "argus" / "core" / "win_payloads.py").write_text(
            payloads_module(tree / "argus" / "platform" / "win"), encoding="utf-8")
        dist = nuitka(tree, work / "nuitka", args.jobs)
        shutil.copy(work / "nuitka" / "nuitka-report.xml", out / "nuitka-windows-report.xml")
        verification = smoke(dist)
        print(f"compiled program passes its own verification: {verification.get('ok', verification)!s:.200}")
        stage = stage_folder(dist, desktop_exe, work / "stage")
        makensis(stage, out, args.version, repo / "desktop" / "icons" / "icon.ico")
    data = (out / INSTALLER).read_bytes()
    record = {"edition": "windows-installer", "version": args.version, "commit": commit,
              "files": {INSTALLER: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}}}
    (out / "windows-installer-build.json").write_text(json.dumps(record, indent=2) + "\n")
    policy = gate.load_policy(proposals=args.proposal)
    for line in policy["_proposals"]:
        print("PROPOSAL ACTIVE (dry run only): " + line)
    problems = gate.check_artifact(out / INSTALLER, gate.rule_for(INSTALLER, policy), policy)[0]
    for p in problems:
        print("REFUSED  " + p)
    if problems:
        hint = "" if args.proposal else (" The committed policy has no rule for the Windows installer yet: "
                                         "release/proposals/windows-installer.json needs review first.")
        sys.exit(f"{INSTALLER} fails the content gate ({len(problems)} problems).{hint}")
    print(f"{INSTALLER} passes the content gate")


if __name__ == "__main__":
    main()
