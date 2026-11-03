# Proposal for review: third-party build paths in the Windows runtime

**Status: not applied.** `release/policy.json` is unchanged. This needs the same
two-person review as any policy change.

## What happened

CI dry run #3 (run 41714844470) built `Argus-Setup.exe`, and the content gate
opened it with 7z and refused 23 members for markers. Every one is a
**third-party runtime binary carrying its maintainers' own build paths**. None
is in `argus.exe`, in our compiled modules, or in the desktop app (checked
locally with the gate's own markers against the Nuitka output and the desktop build).

| marker | matched | binaries | whose path it is |
|---|---|---|---|
| `windows-build-path` | `D:\a\1\` | `python3*.dll`, `_ssl.pyd`, `_socket.pyd`, `_ctypes.pyd`, `_sqlite3.pyd`, `_hashlib.pyd`, `_lzma.pyd`, `_bz2.pyd`, `_decimal.pyd`, `_elementtree.pyd`, `_uuid.pyd`, `_wmi.pyd`, `pyexpat.pyd`, `select.pyd`, `unicodedata.pyd`, `sqlite3.dll`, `libcrypto-3.dll`, `libssl-3.dll` | Python project's release pipeline (PDB path in the PE debug directory) |
| `windows-build-path` | `C:\A\_work\`, `D:\a\_work\` | `libcrypto-3.dll`, `libssl-3.dll`, `vcruntime140.dll`, `vcruntime140_1.dll` | OpenSSL / Microsoft build agents |
| `windows-build-path` | `D:\a\cryptography\` | `cryptography/hazmat/bindings/_rust.pyd` | PyCA's CI |
| `windows-home-path` | `C:\Users\runneradmin\` | `cryptography/hazmat/bindings/_rust.pyd` | PyCA's CI runner account |

These cannot be removed without breaking the vendors' signatures (python.org
and Microsoft binaries are Authenticode-signed), and any standard Windows
Python runtime carries them.

## Why the marker matches

`windows-build-path` is `[A-Z]:\\a\\<name>\\` and `[A-Z]:\\actions-runner\\`. It
was written to catch **our** CI (`D:\a\Argus-1\Argus-1\`), but GitHub Actions
uses `D:\a\` for everyone, so it also matches other projects' pipelines. The
Linux policy already makes the opposite choice for the same situation: its
markers name our own paths (`/github/workspace/`, `/__w/`, `/tmp/argus-*`), and
maintainers' paths (`/github/home/`, `/opt/_internal/`) are deliberately not
markers (commit 8678015, "third-party libraries keep their maintainers' build paths").

## Options

**A. Narrow the Windows markers to our own paths (recommended).**
`windows-build-path`: match `[A-Z]:\\a\\Argus-1\\` and `[A-Z]:\\actions-runner\\`
(still catches anything built from this repository on a runner), and
`windows-home-path` gains `runneradmin` as a placeholder name (a shared CI
service account, not a person). This mirrors the Linux decision, keeps every
other marker, and adds no new allowed file type.
Risk: the narrower regex would not catch a different repository's runner path
in *our* code. Mitigation: our code is compiled from this repository only, and
the home-folder and key markers still apply to every byte.

**B. Exempt named files** (e.g. `*.pyd`, `*.dll` from the pinned runtime) from the
build-path marker only, by digest. More precise, more upkeep (each runtime update
changes digests).

**C. Rewrite the binaries to remove the paths.** Not recommended: it invalidates
the vendors' signatures and makes the runtime unverifiable.

**D. Do not ship a Windows installer** until a runtime without these strings exists.

Whichever is chosen, a test should pin it: a fixture binary containing our
runner path must still be refused.
