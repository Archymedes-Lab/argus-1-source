#!/usr/bin/env python3
"""Build the Argus desktop client (Tauri) for one platform, in CI.

    python3 release/build_desktop.py --platform linux|windows --version V --out DIR [--ref HEAD]

Exports the commit's desktop/ folder renamed to Argus (release/rename.py),
builds the interface with Bun from the locked install, compiles the Rust
program with --locked and every build path remapped (no home directory,
registry or toolchain path of the build machine survives in the binary), and
writes:

    linux     argus-desktop_<version>_amd64.deb
    windows   argus-desktop-windows-x64.exe

The result must pass the content gate (release/gate.py) before this exits 0.
"""

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_server  # noqa: E402  (tar/ar helpers, fixed timestamps)
import gate  # noqa: E402
import rename  # noqa: E402

LINUX_DEPENDS = "libwebkit2gtk-4.1-0, libgtk-3-0, libayatana-appindicator3-1"


def run(cmd, cwd, env=None):
    print("$ " + " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, check=True, env=env)


def remap_flags(src):
    """--remap-path-prefix for every path the build machine could leak."""
    home = Path.home()
    cargo = Path(os.environ.get("CARGO_HOME", home / ".cargo"))
    rustup = Path(os.environ.get("RUSTUP_HOME", home / ".rustup"))
    pairs = [(src, "/build"), (cargo, "/cargo"), (rustup, "/rustup"), (home, "/h")]
    if os.environ.get("CARGO_TARGET_DIR"):
        pairs.insert(0, (Path(os.environ["CARGO_TARGET_DIR"]), "/target"))
    return " ".join(f"--remap-path-prefix={p}=/{n.lstrip('/')}" for p, n in pairs)


def build(tree, platform):
    src = tree / "desktop"
    ui = src / "ui"
    run(["bun", "install", "--frozen-lockfile"], ui)
    run(["bun", "run", "build"], ui)
    if not (ui / "dist" / "index.html").exists():
        sys.exit("the interface build produced no dist/index.html")
    env = {**os.environ, "RUSTFLAGS": remap_flags(src),
           "CARGO_PROFILE_RELEASE_DEBUG": "0", "CARGO_PROFILE_RELEASE_STRIP": "symbols"}
    run(["cargo", "build", "--release", "--locked", "--features", "custom-protocol"], src, env)
    # CARGO_TARGET_DIR (CI: a cached folder) keeps compiled dependencies between
    # dry runs; cargo rebuilds whatever its fingerprints say changed.
    target = Path(os.environ.get("CARGO_TARGET_DIR") or src / "target")
    exe = target / "release" / ("argus-desktop.exe" if platform == "windows" else "argus-desktop")
    if not exe.is_file():
        sys.exit(f"{exe} is missing")
    return src, exe


def linux_deb(src, exe, out, version):
    ver = version.replace("-", ".")
    name = f"argus-desktop_{ver}_amd64.deb"
    # The application menu entry: the same name as the window, tray and the
    # Windows Start menu shortcut (desktop/src/startmenu.rs).
    entry = ("[Desktop Entry]\nType=Application\nName=ARGUS-INSTINCT\nGenericName=Security monitor\n"
             "Comment=Argus security monitor: window, tray and notifications for the local daemon\n"
             "Exec=argus-desktop\nIcon=argus-desktop\nCategories=System;Monitor;Security;\n"
             "StartupWMClass=argus-desktop\nTerminal=false\n").encode()
    files = [("usr/bin/argus-desktop", exe.read_bytes(), 0o755),
             ("usr/share/applications/argus-desktop.desktop", entry, 0o644),
             ("usr/share/icons/hicolor/32x32/apps/argus-desktop.png", (src / "icons/32x32.png").read_bytes(), 0o644),
             ("usr/share/icons/hicolor/128x128/apps/argus-desktop.png", (src / "icons/128x128.png").read_bytes(), 0o644),
             ("usr/share/icons/hicolor/256x256/apps/argus-desktop.png",
              (src / "icons/128x128@2x.png").read_bytes(), 0o644)]
    size = sum(len(d) for _, d, _ in files)
    control = (
        f"Package: argus-desktop\nVersion: {ver}\nArchitecture: amd64\n"
        f"Maintainer: {build_server.DEB_MAINTAINER}\nInstalled-Size: {size // 1024 + 1}\n"
        f"Depends: {LINUX_DEPENDS}\nSection: admin\nPriority: optional\n"
        "Homepage: https://www.archymedes.xyz/en/solutions/argus/\n"
        "Description: Argus desktop client\n"
        " Window, tray and notifications for an Argus daemon on 127.0.0.1. To watch a\n"
        " server, forward its port first: ssh -N -L 8787:127.0.0.1:8787 your-server\n").encode()
    ctrl = io.BytesIO()
    with tarfile.open(fileobj=ctrl, mode="w", format=tarfile.GNU_FORMAT) as tar:
        build_server._tar_add(tar, "control", control, 0o644)
    (out / name).write_bytes(build_server.ar_archive([
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", build_server._gzip(ctrl.getvalue())),
        ("data.tar.gz", build_server._gzip(build_server._tar(files, "")))]))
    return name


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--platform", choices=("linux", "windows"), required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--ref", default="HEAD")
    ap.add_argument("--work", help="build folder (default: a temporary one). A fixed folder keeps "
                                   "the compiler flags, which name it, the same between builds")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="argus-desktop-") as tmp:
        tree = Path(args.work or tmp)
        if args.work:
            shutil.rmtree(tree, ignore_errors=True)
            tree.mkdir(parents=True)
        commit = rename.export(HERE.parent, args.ref, tree, paths=("desktop",))
        src, exe = build(tree, args.platform)
        if args.platform == "linux":
            name = linux_deb(src, exe, out, args.version)
        else:
            name = "argus-desktop-windows-x64.exe"
            shutil.copyfile(exe, out / name)
    data = (out / name).read_bytes()
    (out / f"desktop-{args.platform}-build.json").write_text(json.dumps(
        {"edition": f"desktop-{args.platform}", "version": args.version, "commit": commit,
         "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}}}, indent=2) + "\n")
    policy = gate.load_policy()
    problems = gate.check_artifact(out / name, gate.rule_for(name, policy), policy)[0]
    for p in problems:
        print("REFUSED  " + p)
    if problems:
        sys.exit(f"{name} fails the content gate ({len(problems)} problems)")
    print(f"{name} passes the content gate")


if __name__ == "__main__":
    main()
