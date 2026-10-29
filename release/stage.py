#!/usr/bin/env python3
"""Hand build outputs between CI jobs through a temporary draft release.

    python3 release/stage.py create   --name staging-<run id> --sha <commit>
    python3 release/stage.py upload   --name staging-<run id> FILE...
    python3 release/stage.py download --name staging-<run id> --dir DIR
    python3 release/stage.py delete   --name staging-<run id>

GitHub's Actions artifacts count toward the account's storage quota (500 MB on
the free plan), which other repositories' builds fill; release files do not.
So release.yml stages every build in a draft, prerelease release named
staging-<run id> in this private repository, assembles the real draft from it
and deletes it at the end of the run, whatever the outcome. A staging draft
creates no tag and is never published: publish.yml acts only on a published
release, and publish.py refuses anything without a pinned releaser's signature.

Standard library only, so the same helper runs in the manylinux container, on
the Windows runner and on Ubuntu. GITHUB_TOKEN and GITHUB_REPOSITORY come from
the workflow; the token is sent only to api.github.com and uploads.github.com.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://api.github.com"
UPLOADS = "https://uploads.github.com"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # An asset download redirects to signed storage; the token must not follow it.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _headers(extra=None):
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        sys.exit("GITHUB_TOKEN is not set")
    h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
         "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "argus-release-stage"}
    h.update(extra or {})
    return h


def call(method, url, body=None, headers=None, raw=False, attempts=4):
    data = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
    for attempt in range(attempts):
        req = urllib.request.Request(url, data=data, method=method, headers=_headers(headers))
        try:
            with urllib.request.urlopen(req, timeout=600) as r:
                payload = r.read()
                return payload if raw else (json.loads(payload) if payload else None)
        except urllib.error.HTTPError as exc:
            if exc.code in (500, 502, 503, 504) and attempt + 1 < attempts:
                time.sleep(5 * (attempt + 1))
                continue
            raise SystemExit(f"{method} {url.split('?')[0]}: HTTP {exc.code} {exc.read()[:300]!r}") from None
        except urllib.error.URLError as exc:
            if attempt + 1 < attempts:
                time.sleep(5 * (attempt + 1))
                continue
            raise SystemExit(f"{method} {url.split('?')[0]}: {exc.reason}") from None
    return None


def repo():
    r = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in r:
        sys.exit("GITHUB_REPOSITORY is not set")
    return r


def find(name):
    """The staging release named `name` (drafts are listed only to writers), or None."""
    page = 1
    while True:
        rels = call("GET", f"{API}/repos/{repo()}/releases?per_page=100&page={page}") or []
        for rel in rels:
            if rel.get("name") == name and rel.get("draft"):
                return rel
        if len(rels) < 100:
            return None
        page += 1


def create(name, sha):
    rel = find(name)
    if rel:
        print(f"staging release {name} exists ({rel['id']})")
        return rel
    rel = call("POST", f"{API}/repos/{repo()}/releases",
               {"tag_name": name, "target_commitish": sha, "name": name, "draft": True, "prerelease": True,
                "body": "Temporary CI staging for one release build run. Deleted at the end of the run; "
                        "never published."})
    print(f"created staging release {name} ({rel['id']})")
    return rel


def upload(name, files):
    rel = find(name)
    if not rel:
        sys.exit(f"no staging release {name}")
    existing = {a["name"]: a["id"] for a in rel.get("assets", [])}
    for f in map(Path, files):
        if f.name in existing:
            call("DELETE", f"{API}/repos/{repo()}/releases/assets/{existing[f.name]}")
        url = f"{UPLOADS}/repos/{repo()}/releases/{rel['id']}/assets?name={urllib.parse.quote(f.name)}"
        call("POST", url, f.read_bytes(), {"Content-Type": "application/octet-stream"})
        print(f"staged {f.name} ({f.stat().st_size / 1e6:.1f} MB)")


def download(name, dest):
    rel = find(name)
    if not rel:
        sys.exit(f"no staging release {name}")
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(_NoRedirect)
    for asset in rel.get("assets", []):
        req = urllib.request.Request(f"{API}/repos/{repo()}/releases/assets/{asset['id']}",
                                     headers=_headers({"Accept": "application/octet-stream"}))
        try:
            with opener.open(req, timeout=600) as r:
                data = r.read()
        except urllib.error.HTTPError as exc:
            if exc.code not in (301, 302, 307, 308):
                raise SystemExit(f"{asset['name']}: HTTP {exc.code}") from None
            # Signed storage URL: fetched without the token.
            loc = exc.headers["Location"]
            with urllib.request.urlopen(urllib.request.Request(loc, headers={"User-Agent": "argus-release-stage"}),
                                        timeout=600) as r:
                data = r.read()
        if len(data) != asset["size"]:
            sys.exit(f"{asset['name']}: got {len(data)} bytes, expected {asset['size']}")
        (dest / asset["name"]).write_bytes(data)
        print(f"fetched {asset['name']} ({len(data) / 1e6:.1f} MB)")


def delete(name):
    rel = find(name)
    if not rel:
        print(f"no staging release {name}: nothing to delete")
        return
    if not rel.get("draft") or not name.startswith("staging-"):
        sys.exit(f"refusing to delete {name}: not a staging draft")
    call("DELETE", f"{API}/repos/{repo()}/releases/{rel['id']}")
    print(f"deleted staging release {name}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("action", choices=("create", "upload", "download", "delete"))
    ap.add_argument("--name", required=True)
    ap.add_argument("--sha")
    ap.add_argument("--dir")
    ap.add_argument("files", nargs="*")
    args = ap.parse_args()
    if not args.name.startswith("staging-"):
        sys.exit("staging releases are named staging-<run id>")
    if args.action == "create":
        create(args.name, args.sha or os.environ.get("GITHUB_SHA"))
    elif args.action == "upload":
        upload(args.name, args.files)
    elif args.action == "download":
        download(args.name, args.dir)
    else:
        delete(args.name)


if __name__ == "__main__":
    main()
