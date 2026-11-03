#!/usr/bin/env python3
"""The release content gate: nothing leaves unless policy.json allows it.

    python3 release/gate.py DIR [--previous MANIFEST] [--report FILE]

DIR is a release folder: the published artifacts plus manifest.json,
SHA256SUMS and the signature files. The gate exits non-zero, listing every
problem, unless all of these hold:

  * every file in DIR is a known release file or matches exactly one artifact
    rule (an unknown download is refused, not ignored);
  * every member of every artifact (zip, tar, .deb, NSIS installer) matches
    that rule's allow list and none has a denied suffix or path part
    (source, tests, docs, source maps, keys, lock files);
  * no member is a symlink, hard link, device or absolute/parent path, and only
    the listed members are executable;
  * no file's bytes (binaries included) contain a denied marker: a
    build-machine home path, a private key, a token, a source map reference;
  * no file starts with Python bytecode magic, and no zip archive is hidden
    inside a binary with a denied member (the PyInstaller pattern);
  * manifest.json lists exactly the artifacts, with matching sizes and
    SHA-256, and SHA256SUMS agrees with it;
  * the file count of each artifact grew by no more than the policy allows over
    the previous release (an unexplained jump is how a whole tree slips in).

It runs three times per release (after the CI build, before publishing, and in
the site's deploy job over what is about to go live) and on the owner's
machine against the live site (release/audit.py). Standard library only, so
every one of those places runs the same code.
"""

import argparse
import fnmatch
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY = HERE / "policy.json"
# Release metadata that sits next to the artifacts; checked, not unpacked.
META = {"manifest.json", "SHA256SUMS", "SHA256SUMS.txt", "SHA256SUMS.sig", "allowed_signers",
        "release-report.json", "release-report.md", "sbom.cdx.json"}
SIGS = re.compile(r"^SHA256SUMS\.[A-Za-z0-9_-]+\.sig$")  # one signature per releaser
MAX_MEMBER = 512 * 1024 * 1024
CHUNK = 8 * 1024 * 1024
OVERLAP = 4096


def load_policy(path=POLICY, proposals=()):
    """The policy at `path`. `proposals` are changes under review (release/proposals/),
    loaded only by dry runs (release-test/* branches) and never by a tagged build:

      * `artifacts`: new artifact rules (a name that already has a rule is refused);
      * `deny_markers`: a replacement regex for a marker that already exists, by id
        (a marker cannot be added or removed this way).

    Nothing else can be touched: not the suffix, folder or bytecode lists, and not
    the other markers. Each active proposal is recorded in policy["_proposals"] so
    the caller can print it."""
    policy = json.loads(Path(path).read_text())
    policy["_proposals"] = []
    for prop in proposals:
        extra = json.loads(Path(prop).read_text())
        stray = sorted(k for k in extra if k not in ("artifacts", "deny_markers", "marker_exemptions")
                       and not k.startswith("_"))
        if stray:
            raise ValueError(f"{prop}: a proposal may only add artifact rules, replace named markers or add "
                             f"marker exemptions, not {', '.join(stray)}")
        known = {r["name"] for r in policy["artifacts"]}
        for rule in extra.get("artifacts", []):
            if rule["name"] in known:
                raise ValueError(f"{prop}: {rule['name']} already has a rule; a proposal cannot replace it")
            policy["artifacts"].append(rule)
            policy["_proposals"].append(f"{Path(prop).name}: adds artifact rule {rule['name']}")
        for ex in extra.get("marker_exemptions", []):
            policy.setdefault("marker_exemptions", []).append(ex)
            policy["_proposals"].append(f"{Path(prop).name}: exempts {ex['marker']} in {ex['member']} (sha256 pinned)")
        by_id = {m["id"]: i for i, m in enumerate(policy["deny_markers"])}
        for marker in extra.get("deny_markers", []):
            if marker["id"] not in by_id:
                raise ValueError(f"{prop}: marker {marker['id']} does not exist; a proposal cannot add one")
            policy["deny_markers"][by_id[marker["id"]]] = {**policy["deny_markers"][by_id[marker["id"]]], **marker}
            policy["_proposals"].append(f"{Path(prop).name}: REPLACES marker {marker['id']}")
    policy["_markers"] = [(m["id"], re.compile(m["regex"].encode())) for m in policy["deny_markers"]
                          if m["id"] != "python-source-header"]
    policy["_magic"] = [bytes.fromhex(h) for h in policy["deny_bytecode_magic"]]
    return policy


def glob_match(path, pattern):
    """fnmatch where * stays inside one path segment and ** spans segments."""
    rx = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            rx += "(?:[^/]+/)*"
            i += 3
        elif pattern[i] == "*":
            rx += "[^/]*"
            i += 1
        else:
            rx += re.escape(pattern[i])
            i += 1
    return re.fullmatch(rx, path) is not None


def rule_for(name, policy):
    hits = [r for r in policy["artifacts"] if fnmatch.fnmatchcase(name, r["name"])]
    return hits[0] if len(hits) == 1 else None


class Member:
    __slots__ = ("path", "data", "mode", "kind")

    def __init__(self, path, data, mode=0o644, kind="file"):
        self.path, self.data, self.mode, self.kind = path, data, mode, kind


def _norm(name):
    name = name.replace("\\", "/")
    while name.startswith("./"):
        name = name[2:]
    return name


def _tar_members(data):
    out = []
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for ti in tf.getmembers():
            path = _norm(ti.name)
            if ti.isdir():
                out.append(Member(path.rstrip("/"), b"", ti.mode, "dir"))
            elif ti.isfile():
                if ti.size > MAX_MEMBER:
                    out.append(Member(path, b"", ti.mode, "oversize"))
                    continue
                out.append(Member(path, tf.extractfile(ti).read(), ti.mode, "file"))
            else:
                out.append(Member(path, b"", ti.mode, "link" if (ti.issym() or ti.islnk()) else "special"))
    return out


def _zip_members(data):
    out = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for zi in zf.infolist():
            path = _norm(zi.filename)
            mode = (zi.external_attr >> 16) & 0o777777
            if zi.is_dir():
                out.append(Member(path.rstrip("/"), b"", mode, "dir"))
            elif (mode & 0o170000) == 0o120000:
                out.append(Member(path, b"", mode, "link"))
            elif zi.file_size > MAX_MEMBER:
                out.append(Member(path, b"", mode, "oversize"))
            else:
                out.append(Member(path, zf.read(zi), mode or 0o644, "file"))
    return out


def _ar_members(data):
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    pos, out = 8, {}
    while pos + 60 <= len(data):
        header = data[pos:pos + 60]
        name = header[:16].decode().strip().rstrip("/")
        size = int(header[48:58].decode().strip())
        out[name] = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size % 2)
    return out


def _deb_members(data):
    ar = _ar_members(data)
    out = []
    for name, blob in ar.items():
        if name == "debian-binary":
            continue
        if name.startswith("control.tar"):
            prefix = "DEBIAN/"
        elif name.startswith("data.tar"):
            prefix = ""
        else:
            out.append(Member(name, blob, 0o644, "unknown-ar-member"))
            continue
        if name.endswith((".xz", ".zst")):
            blob = _decompress(name, blob)
        for m in _tar_members(blob):
            if prefix and m.path in ("", "."):
                continue
            m.path = prefix + m.path if prefix else m.path
            out.append(m)
    return out


def _decompress(name, blob):
    if name.endswith(".xz"):
        import lzma
        return lzma.decompress(blob)
    tool = shutil.which("zstd")
    if not tool:
        raise ValueError("zstd member and no zstd tool to open it")
    return subprocess.run([tool, "-dc"], input=blob, capture_output=True, check=True).stdout


def _nsis_members(path):
    tool = shutil.which("7z") or shutil.which("7zz")
    if not tool:
        raise ValueError("an NSIS installer cannot be opened without 7z, so it cannot be checked")
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([tool, "x", "-y", f"-o{tmp}", str(path)], capture_output=True, check=True)
        out = []
        for p in sorted(Path(tmp).rglob("*")):
            rel = p.relative_to(tmp).as_posix()
            if p.is_symlink():
                out.append(Member(rel, b"", 0o777, "link"))
            elif p.is_dir():
                out.append(Member(rel, b"", 0o755, "dir"))
            else:
                out.append(Member(rel, p.read_bytes(), 0o644, "file"))
        return out


def members_of(path, kind):
    data = path.read_bytes()
    if kind == "tar":
        return _tar_members(data)
    if kind == "zip":
        return _zip_members(data)
    if kind == "deb":
        return _deb_members(data)
    if kind == "nsis":
        return _nsis_members(path)
    if kind == "binary":
        return [Member(path.name, data, 0o755, "file")]
    raise ValueError(f"unknown artifact kind {kind!r}")


def exempt(label, marker_id, data, policy):
    """True when this exact file is exempted from this marker.

    An exemption names a member path, one marker and the SHA-256 of the file's
    bytes. It applies to those bytes only: another file with the same marker, or
    the same file after any change, is refused as usual. They exist for a vendor's
    signed binary that carries the vendor's own build path and cannot be altered.
    """
    for ex in policy.get("marker_exemptions", ()):
        member = ex["member"]
        if ex["marker"] == marker_id and (label == member or label.endswith(":" + member)
                                          or label.endswith("/" + member)):
            if hashlib.sha256(data).hexdigest() == ex["sha256"]:
                return True
    return False


def scan_bytes(label, data, policy):
    """Problems found in one file's bytes, whatever the file is."""
    problems = []
    for magic in policy["_magic"]:
        if data.startswith(magic):
            problems.append(f"{label}: Python bytecode")
    if data.startswith((b"#!/usr/bin/env python", b"#!/usr/bin/python", b"# -*- coding")):
        problems.append(f"{label}: Python source")
    seen = set()
    for start in range(0, max(len(data), 1), CHUNK):
        window = data[max(0, start - OVERLAP):start + CHUNK]
        for mid, rx in policy["_markers"]:
            m = rx.search(window) if mid not in seen else None
            if m:
                seen.add(mid)
                if exempt(label, mid, data, policy):
                    continue
                problems.append(f"{label}: contains {mid} ({evidence(mid, m.group(0))})")
    # A zip appended to or embedded in a binary (PyInstaller, a self-extractor).
    if b"PK\x01\x02" in data and not data.startswith(b"PK\x03\x04"):
        problems += [f"{label}: embedded archive member {n}" for n in embedded_zip_names(data)
                     if denied_path(n, policy)]
    return problems


def evidence(marker_id, found):
    """What matched, safe to print in a public CI log: a path is shown up to its
    user name; a key or token never, only its kind, length and first characters."""
    if marker_id.endswith("path") or marker_id == "source-map":
        text = found[:80].decode("ascii", "replace")
        return repr("".join(c if c.isprintable() else "?" for c in text))
    head = found.split(b"-----", 2)[1] if marker_id == "private-key" and b"-----" in found else found[:4]
    return f"{head.decode('ascii', 'replace')}... {len(found)} bytes, redacted"


def embedded_zip_names(data):
    """File names from every zip central-directory header found in the bytes."""
    names, pos = [], data.find(b"PK\x01\x02")
    while pos != -1 and pos + 46 <= len(data):
        n_len = int.from_bytes(data[pos + 28:pos + 30], "little")
        name = data[pos + 46:pos + 46 + n_len].decode("utf-8", "replace")
        if name:
            names.append(_norm(name))
        pos = data.find(b"PK\x01\x02", pos + 4)
    return names


def denied_path(path, policy):
    low = path.lower()
    if any(low.endswith(s) for s in policy["deny_suffixes"]):
        return "denied file type"
    parts = path.split("/")
    if any(p in policy["deny_path_parts"] for p in parts[:-1]):
        return "denied folder"
    return None


def check_artifact(path, rule, policy):
    problems, count = [], 0
    try:
        members = members_of(path, rule["kind"])
    except Exception as exc:  # noqa: BLE001 - any unreadable container fails closed
        return [f"{path.name}: cannot be opened for checking ({type(exc).__name__}: {exc})"], 0
    if rule["kind"] == "binary":
        return scan_bytes(path.name, members[0].data, policy), 1
    for m in members:
        label = f"{path.name}:{m.path}"
        if m.path.startswith("/") or ".." in m.path.split("/"):
            problems.append(f"{label}: absolute or parent path")
            continue
        if m.kind == "dir":
            continue
        if m.kind != "file":
            problems.append(f"{label}: {m.kind} is not allowed")
            continue
        count += 1
        why = denied_path(m.path, policy)
        if why:
            problems.append(f"{label}: {why}")
        elif not any(glob_match(m.path, pat) for pat in rule["allow"]):
            problems.append(f"{label}: not in the allow list")
        if m.mode & 0o111 and m.path not in rule.get("executables", []) \
                and not m.path.endswith((".so",)) and ".so." not in m.path:
            problems.append(f"{label}: executable but not listed as one")
        problems += scan_bytes(label, m.data, policy)
    return problems, count


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def check_release(folder, policy, previous=None):
    folder = Path(folder)
    problems, counts = [], {}
    files = sorted(p for p in folder.iterdir() if p.is_file())
    artifacts = []
    for p in files:
        if p.name in META or SIGS.match(p.name):
            continue
        rule = rule_for(p.name, policy)
        if rule is None:
            problems.append(f"{p.name}: no policy rule (or more than one) allows this download")
            continue
        artifacts.append(p.name)
        found, counts[p.name] = check_artifact(p, rule, policy)
        problems += found
    for d in (p for p in folder.iterdir() if p.is_dir()):
        problems.append(f"{d.name}/: folders are not published")
    manifest_path = folder / "manifest.json"
    if not manifest_path.exists():
        problems.append("manifest.json is missing")
    else:
        manifest = json.loads(manifest_path.read_text())
        listed = manifest.get("files") or {}
        if sorted(listed) != sorted(artifacts):
            problems.append(f"manifest lists {sorted(listed)} but the folder holds {sorted(artifacts)}")
        for name in set(listed) & set(artifacts):
            p = folder / name
            if listed[name].get("bytes") != p.stat().st_size or listed[name].get("sha256") != sha256(p):
                problems.append(f"{name}: size or SHA-256 differs from the manifest")
        sums = "".join(f"{listed[k]['sha256']}  {k}\n" for k in listed)
        for s in ("SHA256SUMS", "SHA256SUMS.txt"):
            if (folder / s).exists() and (folder / s).read_text() != sums:
                problems.append(f"{s} does not match the manifest")
        if not (folder / "SHA256SUMS").exists():
            problems.append("SHA256SUMS is missing")
    if previous:
        prev = json.loads(Path(previous).read_text()).get("member_counts") or {}
        growth = policy["max_file_count_growth"]
        for name, n in counts.items():
            key = re.sub(r"_\d[\w.]*?_", "_*_", name)
            before = prev.get(key) or prev.get(name)
            if before and n > before * (1 + growth):
                problems.append(f"{name}: {n} files, up from {before} in the previous release "
                                f"(more than {growth:.0%}); explain it in the policy or the build")
    return problems, counts


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("folder")
    ap.add_argument("--policy", default=str(POLICY))
    ap.add_argument("--previous", help="the previous release's manifest.json (member counts)")
    ap.add_argument("--report", help="write a JSON report here")
    args = ap.parse_args()
    policy = load_policy(args.policy)
    problems, counts = check_release(args.folder, policy, args.previous)
    report = {"ok": not problems, "policy_sha256": sha256(args.policy), "member_counts": counts,
              "problems": problems}
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    for p in problems:
        print("REFUSED  " + p)
    print(f"gate: {'PASSED' if not problems else 'FAILED'} "
          f"({len(counts)} artifacts, {sum(counts.values())} files, {len(problems)} problems)")
    sys.exit(0 if not problems else 1)


if __name__ == "__main__":
    main()
