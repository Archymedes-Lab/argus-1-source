# Releasing Argus

This is the only way Argus reaches the public. It exists because on 2026-10-29
the Windows download was found to contain the whole Python codebase, the Linux
download decompilable bytecode, and both desktop binaries the build machine's
home path. Every rule below closes one of those gaps or the way they happened
(a laptop build from a working tree, a gate that checked for one known
problem instead of allowing only known-good content).

## The rules

1. **Binaries only.** A download may contain only what `release/policy.json`
   allows, file by file: native programs, shared libraries, web assets, data,
   service units and the installer scripts. Source of any language, Python
   bytecode, tests, docs, source maps, lock files, keys and build-machine paths
   are refused. The policy is deny-by-default: a new kind of file fails until
   someone adds it to the policy on purpose.
2. **Built by CI from a tag on `main`, never on a laptop.** The release
   workflow builds on clean GitHub runners from the tagged commit only. The
   server edition is compiled to a native program with Nuitka inside a pinned
   `manylinux_2_28` image; build tools are pinned by version and SHA-256 and at
   least two weeks old; actions are pinned by commit SHA.
3. **Checked at every hop by the same code.** `release/gate.py` (content) and
   `release/check.py` (content + signature) run after the build, before
   signing, before publishing, in the site's deploy job, on the live site after
   publishing, and on the owner's machine every 30 minutes.
4. **Signed by a releaser.** Any one person listed in
   `release/allowed_signers` *and* pinned by an admin in the
   `ARGUS_RELEASE_SIGNERS` variable signs `SHA256SUMS` with their own offline,
   passphrase-protected key. No signature, no publish.
5. **Read back.** Publishing ends only when the live site serves the new
   version and every file verifies. A failure says so loudly and points here.
6. **Reversible.** Every signed release stays in GitHub Releases (Argus-1,
   private). Rolling back is publishing an earlier tag again.

## Version order

A tag is `vYYYY.MM.DD`, or `vYYYY.MM.DD-N` for the Nth release that day (no suffix is the
first). A dry run (below) is versioned `YYYY.MM.DD-<run number>`, so a later dry run is always
newer; the 2026-11-03 dry runs carry `-0`, which sorts before that day's first tag. Order is by that rule, not by string: `2026.10.31-10` is newer than `2026.10.31-9`.
`release/publish.py` reads the version the site serves now (the site checkout's
`public/downloads/argus/manifest.json`) and **refuses** a candidate that is equal, older, or
not a valid tag version (for example the dotted `2026.10.29.1`), before the site is touched.
Releases made before tagging (`2026.10.30`) still order correctly as the live side. A deliberate
rollback is the only way back: `publish.yml` with `rollback: true`. Tests: `tests/test_release_version.py`.

## Host-bound tests

A few tests (see `docs/guides/HOST-TESTS.md`) only pass on a WSL2 host, so CI lists them as NOT RUN.
Before tagging, on that host: commit, `python3 release/host_attest.py make`, sign
`release/host-attestation.json` with your releaser key, commit both files. `release.yml` refuses a
tag whose attestation is missing, unsigned by a pinned releaser, incomplete, or older than a code change.

## Releaser keys

Adding a second releaser, a lost or compromised key, revocation and rotation:
`docs/guides/RELEASER-KEYS.md`.

## Publishing a dry run (the current method)

Owner decision 2026-11-03: a green dry run is published straight to the site,
without a tag, draft or `publish.yml`. The checks are the same: the content
gate, `SHA256SUMS`, the releaser's signature against the pinned keys, the
version order, the site copy's own check and the live read-back.

1. Push the commit to a `release-test/*` branch of Argus-1. The **Release
   build** workflow runs every stage (builds, both install tests, assembly and
   gate) and hands the assembled release folder over as the `release-out`
   artifact, kept 7 days. A newer push to the same branch cancels the run in
   progress. About 15-20 minutes with warm caches.
2. When the run is green, on the releaser's machine (it needs `gh`, `7z`,
   `bun`, the Vercel CLI linked to the site, and the release key):

   ```sh
   bash release/publish_dry_run.sh <run id>
   ```

   It checks the run is green, downloads `release-out`, gates every file again
   (the Setup opened with 7z) and checks `SHA256SUMS`, signs it (the
   passphrase is asked again on a typo, up to 5 times), lays the downloads out
   in a fresh worktree of the site's `master` (`release/publish.py`, which
   refuses a version not newer than the live one), commits and pushes, deploys
   to production with the Vercel CLI and reads the live site back.

   If it stops after signing, run the same command again: it resumes at the
   site without downloading or asking for the passphrase, provided the folder
   still matches its signature.

The site commit is made with the site checkout's own git identity: it must be
an account Vercel can match to Git (your GitHub email), or Vercel blocks the
production deployment ("couldn't find a Git account for the commit author").

Paths can be overridden: `ARGUS_PUBLISH_DIR` (working folder, default
`~/.cache/argus-instinct-publish`), `ARGUS_SITE_REPO` (default
`~/archymedes-site`), `ARGUS_RELEASE_KEY`, `ARGUS_7Z_DIR`.

What a dry run does not have that a tag does: the commit need not be on
`main`, the host-bound tests' signed attestation is not checked, and the
builds use the compiler caches kept between dry runs (a tag builds cold). The
manifest records the run and the commit either way.

## Making a release

Anyone with write access to Argus-1 who is a releaser:

```sh
git switch main && git pull                      # the commit must be on main
git tag -a v2026.11.01 -m "Argus 2026.11.01"     # vYYYY.MM.DD, -2 for a second one that day (-s if you sign git tags)
git push origin v2026.11.01
```

The **Release build** workflow then runs (about an hour): static gate and
unit suite, native server build, the native Windows engine
(`release/build_windows.py`, PowerShell payloads compiled in), desktop builds
for Linux and Windows, the Windows Setup made from the engine and the desktop
app (`release/build_setup.py`), a real install-run-remove test of both server
packages on a systemd host and of the Setup on a clean Windows host without
WSL (`release/windows/install_test.ps1`, with a planted-autostart positive
control), assembly (manifest, `SHA256SUMS`, a report of what changed since the
last release, an SBOM) and the content gate. It ends with a **draft** release.
Nothing is public.

The downloads are: `argus-server-linux-x86_64.tar.gz`, `argus-server_<v>_amd64.deb`,
`argus-desktop_<v>_amd64.deb`, `argus-desktop-windows-x64.exe`,
`argus-instinct-windows-x64.zip` and `ARGUS-INSTINCT-Setup-windows-x64.exe`
(docs/architecture/WINDOWS-EDITION.md says who downloads which). The gate opens
the Setup with 7-Zip, so `release/sign.py` and `release/check.py` need `7z` on
the releaser's machine (`sudo apt install 7zip`); without it the Setup is
refused, never passed.

Sign it on your own machine:

```sh
python3 release/sign.py v2026.11.01
```

It downloads the draft, runs the gate again, shows every artifact with its size
and file count and the change report, asks you to type the version, signs with
your key (ssh-keygen asks for its passphrase) and uploads `SHA256SUMS.sig`.
Read the report before typing the version: a file count that jumped, or an
artifact you did not expect, is a reason to stop.

Publish:

```sh
gh release edit v2026.11.01 --draft=false -R chrisnkuno/Argus-1
```

The **Publish release** workflow checks the signature against the pinned keys,
commits exactly the release files to the site, the site's deploy job checks
them again, and the workflow reads the live site back. Watch it to the end:
`gh run watch -R chrisnkuno/Argus-1`.

## Rolling back

```sh
gh workflow run publish.yml -R chrisnkuno/Argus-1 -f tag=v2026.10.31
```

This republishes an earlier signed release through the same checks. To take
the downloads offline entirely, remove `public/downloads/argus/*` except an
empty `manifest.json` (`{"version": "", "files": {}}`) in the site repository;
the download page then shows each edition as coming soon.

## Adding a releaser

The new releaser, on their own machine:

```sh
mkdir -p -m 700 ~/.config/argus-release
ssh-keygen -t ed25519 -C <github-login>@argus-release -f ~/.config/argus-release/signing_key
#   use a real passphrase; back the private key up offline; never copy it anywhere else
ssh-keygen -lf ~/.config/argus-release/signing_key.pub      # the SHA256:... fingerprint
```

They open a pull request adding one line to `release/allowed_signers`:

```
<github-login> namespaces="argus-release" ssh-ed25519 AAAA...
```

An admin compares the fingerprint with the one the releaser reads out over a
second channel (call, in person), merges, then appends it to the
`ARGUS_RELEASE_SIGNERS` variable in **both** Argus-1 and archymedes-site
(Settings → Secrets and variables → Actions → Variables), for example
`chrisnkuno=SHA256:ko2T... soniaineza=SHA256:...`, and to
`~/.config/argus-release/trusted_signers` on the owner's machine. Removing a
releaser is the reverse; do it the same day a key may be lost.

## What protects what

| Threat | Stopped by |
|---|---|
| source, bytecode, tests or docs in a download | policy allow-list, checked six times |
| build-machine paths, keys or tokens in a binary | byte scan of every file, binaries included |
| an uncommitted or local build shipped | CI builds only from a tag on `main`; publish takes only GitHub Release assets |
| a tampered file between CI and the site | `SHA256SUMS` signed by a releaser; verified before and after publishing |
| a compromised dependency version | pins by version and SHA-256, two-week minimum age |
| a broken install | install-run-remove test on a real systemd host before the draft exists |
| a bad release live | live readback, the owner's 30-minute audit, one-command rollback |

## Known limits (free GitHub plan)

The repositories are private on GitHub's free plan, which cannot protect
branches, tags or workflow files. Anyone with write access could therefore
edit a workflow to skip a check, or use the site's `VERCEL_TOKEN` secret from
a workflow of their own. The signature check is in the workflows too, so on
this plan it guards against mistakes and outside attackers, not against a
collaborator acting in bad faith. What a collaborator cannot change is the
owner's live audit (`release/audit.py`, run on the owner's machine with
fingerprints pinned in the owner's own file): it would report an unsigned or
non-conforming download within 30 minutes. Moving to GitHub Team would let
rulesets protect `main`, `v*` tags and `.github/`, require a review, and keep
deploy secrets behind an approval.

Other limits: a native program can still be reverse-engineered with effort
(it stops casual reading, not a determined analyst; never put secrets in
code). The Windows server edition is not published until it is native too
(its PowerShell payloads must ship as text, which needs Authenticode signing,
and its C# sensor must be prebuilt). The desktop binaries are not
Authenticode-signed yet, so Windows SmartScreen warns.
