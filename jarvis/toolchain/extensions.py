"""Editor and browser extensions."""

import os
import time
from .common import _diff, _finding, _hash, _json, _short
from .mcp import _windows_profiles


_M_EXT = "toolchain_ext"

EXT_ROOTS = (
    "~/.vscode-server/extensions", "~/.vscode-server-insiders/extensions",
    "~/.cursor-server/extensions", "~/.antigravity-server/extensions",
    "~/.windsurf-server/extensions", "~/.vscode/extensions",
    "~/.cursor/extensions",
)


def _extension_dirs(hosts):
    out = []
    if "wsl" in hosts:
        for root in EXT_ROOTS:
            path = os.path.expanduser(root)
            if os.path.isdir(path):
                out.append((path, "wsl"))
    if "win" in hosts:
        for udir in _windows_profiles():
            for rel in (".vscode/extensions", ".cursor/extensions",
                        ".vscode-insiders/extensions",
                        ".windsurf/extensions", ".antigravity/extensions"):
                path = os.path.join(udir, rel.replace("/", os.sep))
                if os.path.isdir(path):
                    out.append((path, "win"))
    return out


def check_extensions(store=None, hosts=("wsl", "win")):
    """Inventory every installed extension, and report what moved since last run.

    An extension is unsandboxed Node running inside the editor's process with
    the developer's tokens, SSH agent and filesystem. There is no permission
    model to audit, so the only questions worth asking are which ones are here
    and which ones are not the ones that were here before — a backdoored
    release arrives as a version bump on something already trusted.
    """
    out, seen = [], {}
    roots = _extension_dirs(hosts)
    if not roots:
        return [_finding(
            "editor", "ok", "no editor extensions installed",
            "no VS Code, Cursor, Windsurf or Antigravity extension directory "
            "exists for this account", "extensions")]

    startup_active, modified = [], []
    versions = {}
    total = 0
    for root, host in roots:
        try:
            entries = sorted(os.scandir(root), key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            if not e.name or e.name.startswith(".") or not e.is_dir():
                continue
            manifest = os.path.join(e.path, "package.json")
            doc = _json(manifest)
            if not isinstance(doc, dict):
                continue
            total += 1
            pub = doc.get("publisher") or "?"
            name = doc.get("name") or e.name
            ver = doc.get("version") or "?"
            ident = f"{host}:{os.path.basename(os.path.dirname(root))}:{pub}.{name}"
            versions.setdefault(ident, set()).add(str(ver))

            events = doc.get("activationEvents") or []
            if isinstance(events, list) and any(
                    str(x) in ("*", "onStartupFinished") for x in events):
                startup_active.append((ident, ver, host))

            mtime = _modified_after_install(e.path, manifest)
            if mtime:
                modified.append((ident, mtime, e.path, host))

    for ident, mtime, path, host in modified:
        out.append(_finding(
            "editor", "high", f"extension modified after installation: {ident}",
            f"files under the extension directory are newer than its manifest "
            f"(most recent {time.strftime('%Y-%m-%d %H:%M', time.localtime(mtime))}). "
            f"Extensions are written once at install and not touched again, so "
            f"an in-place edit means either a patch applied outside the "
            f"marketplace or code added to a package you already trust.",
            _short(path), host))

    for ident, vers in versions.items():
        seen[ident] = _hash(",".join(sorted(vers)))

    by_host = {}
    for ident, ver, host in startup_active:
        by_host.setdefault(host, []).append(f"{ident} {ver}")
    for host, listed in by_host.items():
        out.append(_finding(
            "editor", "low",
            f"{len(listed)} extension(s) activate on every startup",
            f"these run before you open a file and regardless of project type: "
            f"{', '.join(sorted(set(listed))[:10])}. Normal for many "
            f"extensions; listed because it is the activation mode "
            f"credential-harvesting extensions use.",
            "activationEvents", host))

    out.extend(_diff(store, _M_EXT, seen, "editor", "extension",
                     "an extension updating is routine, so this is not by "
                     "itself an incident — but a version change on something "
                     "already installed is exactly how a backdoored release "
                     "arrives, the package being trusted already and only its "
                     "contents being new. Confirm the update was one you or "
                     "the marketplace initiated.",
                     changed_sev="high"))
    if total and not any(f["severity"] in ("critical", "high") for f in out):
        out.append(_finding(
            "editor", "ok", f"{total} editor extensions inventoried",
            f"across {len(roots)} extension directories; contents match the "
            f"recorded baseline", "extensions"))
    return out


def _modified_after_install(ext_dir, manifest, slack=3600, limit=400):
    """Newest mtime under the extension that post-dates its own manifest."""
    try:
        base = os.stat(manifest).st_mtime
    except OSError:
        return 0
    newest, count = 0, 0
    for dirpath, dirnames, filenames in os.walk(ext_dir):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git")]
        for fn in filenames:
            if not fn.endswith((".js", ".cjs", ".mjs", ".json", ".node",
                                ".ts", ".sh", ".py")):
                continue
            count += 1
            if count > limit:
                return newest if newest > base + slack else 0
            try:
                m = os.stat(os.path.join(dirpath, fn)).st_mtime
            except OSError:
                continue
            newest = max(newest, m)
    return newest if newest > base + slack else 0
