# Fuzz findings, 2026-11-04 (first pass)

Branch `fuzz/early-20261104`, based on 57087c4. Harness: `tests/fuzz/` (see its README),
run with `python3 -m tests.fuzz.run --budget-seconds N`. Regression tests:
`tests/test_fuzz_findings.py` (one test per finding id; open findings are
`expectedFailure` or `skip`, so the gap stays visible and nothing existing was weakened).

All inputs were synthetic (seeds built from the formats in `tests/` fixtures). Nothing
read `~/.jarvis`, `~/.argus` or `/var/log`, contacted the daemon, ran PowerShell or used
elevation; each target ran in a child process with `HOME`/`TMPDIR` in a fresh temp dir.
The one external tool used was `dpkg-deb -c` (read-only listing) on a synthetic .deb in a
temp dir, to confirm FZ-02.

## Findings

| id | target | kind | severity (guess) | status |
|----|--------|------|------------------|--------|
| FZ-01 | release/gate.py `_ar_members` | hang | medium | fixed + test |
| FZ-02 | release/gate.py `_ar_members` / `_deb_members` | blind spot | medium | fixed + test |
| FZ-03 | collectors/identity/logins.py `FAILED` | misattribution | medium | fixed + test |
| FZ-04 | collectors/identity/logins.py `read_journal` | forged evidence | high | **open** (expectedFailure) |
| FZ-05 | release/versioning.py `TAG`/`LEGACY` | grammar bypass | low | fixed + test |
| FZ-06 | collectors/telemetry/sysmon_linux/journal.py `_parse` | crash + quadratic hang | medium | fixed + tests |
| FZ-07 | collectors/identity/sshwatch.py `parse_sshd_config` | crash | low-medium | fixed + tests |
| FZ-08 | collectors/host/updates.py `parse_winget` | silent drop | low-medium | fixed + tests |
| FZ-09 | web/clients.py `verify` | crash | low | fixed + test |
| FZ-10 | collectors/host/updates.py `parse_brew` | crash | low | fixed + test |
| FZ-11 | release/gate.py `scan_bytes` (nested archives) | blind spot | medium | **open** (expectedFailure) |
| FZ-12 | release/gate.py `check_artifact` kind `binary` | blind spot | medium | **open** (expectedFailure) |
| FZ-13 | release/gate.py `denied_path` | blind spot | low-medium | **open** (expectedFailure) |
| FZ-14 | release/gate.py `_tar_members`/`_zip_members` | unbounded memory | low-medium | **open** (skip) |
| FZ-15 | collectors/identity/logins.py `read_journal` | crash | low | fixed + test |

### FZ-01: negative ar member size loops for ever (gate)
- Reproducer: `b"!<arch>\n" + b"d" + b"-60       " * 6` given to `gate._ar_members` (any `*.deb` artifact).
- Observed: `int("-60")` is accepted as the member size; `pos += 60 + size` does not advance, so
  the loop never ends. Found by the fuzzer in under a second (3 s per-input deadline hit).
- Why it matters: the gate runs in CI, before publishing, in the site deploy and in the owner's
  `release/audit.py` against the live site. A crafted .deb on the site hangs the audit instead of
  failing it (no verdict is a missing verdict).
- Fix: sizes below 0 or past the end of the archive raise `ValueError`, which `check_artifact`
  already turns into a refusal ("cannot be opened for checking").

### FZ-02: a second `data.tar` hides the first (gate vs dpkg)
- Reproducer: ar with `debian-binary`, `control.tar.xz`, `data.tar.xz` (holding
  `usr/share/argus-server/src/secret.py`), then a second clean `data.tar.xz`.
- Observed: `_ar_members` stores members in a dict, so the second `data.tar.xz` overwrote the
  first and the gate checked only the clean one. `dpkg-deb -c` on the same file lists
  `./usr/lib/argus/src/secret.py` from the **first** one (measured). The gate approved bytes
  other than the ones dpkg installs.
- Fix: a repeated ar member name is refused.

### FZ-03: client-chosen user name moves a failed login to any address (logins)
- Reproducer: `Invalid user bob from 203.0.113.9 from 198.51.100.7 port 4242` (user name
  `bob from 203.0.113.9`; sshd logs names as sent, spaces included, up to 100 chars).
- Observed: `FAILED` took the first ` from <x>`: the failure was charged to 203.0.113.9.
- Why: an unauthenticated network client can frame any address (e.g. the owner's own network)
  so that the owner's next successful login reads "a password guesser logged in", and can fill
  the 5000-address failure table with forged sources that crowd out real ones.
  `bruteforce._LINUX_FAIL` had already been fixed for this; `logins` had not.
- Fix: anchored to sshd's own trailing ` from IP port N[ ssh2][: TYPE FP][ [preauth]]`.

### FZ-04 (open): `logins` accepts sshd lines written by any local account
- Reproducer: a journal record `{"_UID": "1000", "MESSAGE": "Accepted publickey for chris from
  203.0.113.50 port 1 ssh2: ED25519 SHA256:evil"}` (what `logger -t sshd ...` produces).
- Observed: `read_journal` filters with `-t sshd` (SYSLOG_IDENTIFIER, client-chosen) and never
  checks `_UID`, so the line is a record. The same weakness was measured for `-t sysmon` on
  2026-11-01 and fixed there (`TRUSTED_MATCH`) and in `bruteforce._journal_messages`.
- Why: any local process can forge root logins (false criticals) and, worse, pre-train the
  per-account baseline with an attacker's network and key so the real login later raises no
  `new_key`/`new_net` alert.
- Not fixed here: dropping non-root lines changes what counts as evidence; it should copy
  bruteforce's design (count and show untrusted lines, never use them) and be reviewed.

### FZ-05: tag versions with a trailing newline or non-ASCII digits (versioning)
- Reproducer: `candidate_key("v2026.10.31\n")`, `candidate_key("v2026.11.0٤")`.
- Observed: accepted (`$` matches before a final newline; `\d` matches any Unicode digit).
- Fix: `re.ASCII` and `\Z`.

### FZ-06: Linux Sysmon parse crash and quadratic scan (sysmon_linux)
- Reproducers: `<Event><System><EventID>1x</EventID></System></Event>` raises `ValueError`
  and loses every event in the text; `"<Event " * 8000` (56 KB) took 7.1 s, quadratic, so the
  8 MB syslog tail would take hours.
- Why: when `journalctl` fails or times out (40 s, which this loaded laptop does), `read_since`
  falls back to the syslog tail, whose lines any account can write with `logger "sysmon ..."`.
  One line then blinded or stalled Linux Sysmon for as long as it stayed in the tail.
- Fix: a non-numeric EventID skips that record; spans are found in linear time with the same
  results as the old pattern (tested against it).
- Still open (noted, not a test): the syslog fallback itself carries no trusted origin, so
  forged XML events there are still parsed as Sysmon events.

### FZ-07: `Subsystem` with no command crashes the SSH audit (sshwatch)
- Reproducer: sshd_config `Subsystem sftp` (then any `Subsystem x /cmd`, or nothing).
- Observed: stored as a plain tuple; the next `Subsystem` line (`setdefault` on a tuple) or
  `policy_findings` (`.items()`) raised `AttributeError`, losing every SSH finding. Also
  `Include /etc/ssh/a\x00b.d/*.conf` raised `ValueError` from glob.
- Severity: config is root-owned and sshd refuses such a file, so low-medium (a broken config is
  exactly when the audit should still report).
- Fix: recorded as a parse problem; NUL patterns become a problem, not a crash.

### FZ-08: a program's display name hides later winget updates (updates)
- Reproducer: a `winget upgrade` row whose name is `The following game` (or contains
  `cannot be determined` / `require explicit targeting`).
- Observed: footer detection matched anywhere in the line and stopped parsing: every later
  update was silently dropped. Installed programs (user-scope included) choose their own names.
- Fix: footer phrases only end the table on a line that does not end in a source column. Real
  footers are still honoured (tested).

### FZ-09: damaged client digest crashes `verify` (web/clients)
- Reproducer: stored record `"sha256": "ȶ"`; `compare_digest` on non-ASCII `str` raises
  `TypeError`. The store is the daemon's own, so low. Fix: compare bytes.

### FZ-10: `brew outdated` JSON that is not an object (updates)
- Reproducer: `1`, `[]`, `null`; also `installed_versions: 3`. `AttributeError`/`TypeError`.
- Fix: non-object JSON returns `None` (shown as "brew outdated did not run"); odd fields coerced.

### FZ-11 (open): denied files inside a nested archive pass the gate
- Reproducer: zip artifact with allowed member `app/lib/bundle.zip` containing `src/secret.py`
  (deflated, with a `/home/...` build path in it). Also `.tar.gz` inside the zip. Gate: no problem.
- Why: `scan_bytes` skips the embedded-zip check when the bytes start with `PK\x03\x04`, and
  compressed contents hide the marker regexes. Source, tests or build paths can ship inside any
  nested archive (wheel, nupkg, bundled zip).
- Not fixed: scanning nested archives could newly refuse legitimate bundled runtimes in the
  Windows zip; needs a build-side check of what the current artifacts contain.

### FZ-12 (open): a `binary` artifact that is really a zip is not opened
- Reproducer: `argus-desktop-windows-x64.exe` whose bytes are a zip of `src/secret.py`: passes.
- Same root cause as FZ-11 (`not data.startswith(b"PK\x03\x04")`).

### FZ-13 (open): denied names compared case-sensitively
- Reproducers: `app/Docs/readme.txt`, `app/SRC/x.dll`, `app/Tests/a.dll`, `app/x.PY.`
  (Windows strips the trailing dot, giving `x.py`). The Windows zip extracts on a
  case-insensitive file system.
- Not fixed: may newly refuse current members; check the live artifacts first.

### FZ-14 (open): archive members are all held in memory
- Measured: a 65 KB `.tar.gz` of 8 zero-filled members made `_tar_members` hold 64 MiB (+48 MiB
  max RSS). There is a 512 MiB per-member cap but no aggregate one, so a small download on a
  compromised site can exhaust memory on the owner's machine during `audit.py`.
- Fix direction: stream members (scan, then drop) and set a total-bytes budget that refuses.

### FZ-15: odd journal JSON lines lose the whole login read (logins)
- Reproducers: a line `0` or `null`; `MESSAGE` byte array with 900 or a string element;
  `__REALTIME_TIMESTAMP` of 400 digits (`OverflowError`). journalctl does not emit these, so low.
- Fix: such a line is skipped or coerced; the rest of the read is kept.

### FZ-16: a huge numeric EventID loses the Sysmon read (sysmon_linux), fixed 2026-11-06

Found by a 120 s run (seed 20261106) on the release integration tree. FZ-06 accepted any
ASCII digit string as an EventID; one longer than Python's 4300-digit int conversion limit
passed `isdigit()` and `int()` raised `ValueError`, losing every event in the window. The
syslog fallback is writable by any account. Fix: event ids longer than five digits are
treated like a non-numeric one (that record only); regression
`test_fz16_huge_numeric_event_id_skips_that_record_only`. The parser now lives in
`jarvis/platform/sysmon_records.py`.

## Targets fuzzed with no finding

Budget: three passes, 8 s, 15 s and 15 s per target (21 targets, about 13 minutes of CPU), run
serially at `nice 10`. Executions per target in the last pass ranged from 1.1 k (sshd_config,
temp files per input) to 433 k.

| target | what | result |
|--------|------|--------|
| gate.zip | `_zip_members` | no hang; exceptions fail closed |
| gate.scan_bytes | markers + embedded zip walk on arbitrary bytes | no crash, no slow input |
| bruteforce.attribution | the anchored `_LINUX_FAIL` (control for FZ-03) | holds |
| bruteforce.journal | `_journal_messages` + `_linux` | no crash |
| native.parse | Windows event XML (`normalize.parse`) | only `NormalizeError`; expat refuses entity bombs |
| sshwatch.keys | `parse_key_line`, `fingerprint`, `rsa_bits`, `client_tunnels` | no crash |
| updates.parsers | apt, snap, winget, choco parsers | no crash |
| web.json_body | `Handler._json_body` (pre-auth on `/api/veil/events`) | dict or None; 4096-deep nesting parses (no RecursionError on 3.12) |
| web.client_token | `clients.verify`/`looks_like` | accepts only the issued token (`\n`-suffixed token rejected) |
| web.request_token | `token.accepts`/`candidates` over Cookie, Authorization, header | accepts iff exact token |

Not covered this pass: `release/signers.py` (shells out to ssh-keygen per input; too costly
here), NSIS via 7z (no 7z on this machine), the Rust and PowerShell code, the phone relay (JS),
`sysmon.py` Windows rows (input is our own normalised events), appcode lockfile parsers.

## Next targets (most promising)
1. FZ-04 fix plus the same `_UID`/unit check for every other `journalctl -t` reader (grep `-t`).
2. Gate: nested archives and streaming with a total budget (FZ-11..14) — needs a look at the
   real Windows zip contents first.
3. `jarvis/collectors/appcode/lockfiles.py` (parses untrusted repositories, XML + JSON + TOML).
4. `jarvis/intel/distrovuln.py` / `worldwatch.py` (network-fed XML/JSON).
5. The syslog fallback in sysmon_linux (forged events, see FZ-06).
6. `release/signers.py` `parse_allowed` alone (pure), and a differential against `ssh-keygen`.
