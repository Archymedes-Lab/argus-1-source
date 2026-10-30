# ARGUS-2026-001 (DRAFT): local web API and API token hardening

**Status:** DRAFT, not published. Prepared 2026-10-30 after an internal review of
the local dashboard and API (`jarvis/web/server.py`, `jarvis/web/token.py`,
`jarvis/web/static/`). The review followed a week in which the product source was
accidentally public, so we assume others may have read the same code.

**Fixed in:** the first signed release after 2026-10-30.

**Exposure:** the dashboard listens on `127.0.0.1` only, with no option to bind
elsewhere. Nothing here can be reached from the network. Every issue needs code
already running on the same computer (another local account, a compromised
service account, or a web page open in the owner's browser) and none gives
code execution. The worst case is that someone else on the machine records
decisions in the owner's name (approving a fix investigation, answering a
question, changing trusted locations) or stops the dashboard from responding.

## Affected versions

These versions were checked from the release trees:

| Version | Affected by |
|---|---|
| 2026.10.22 (9d83d1a478de) | 0, 2, 5 (extension pairing check only), 7, 8, 9, 10, 11, 12 |
| 2026.10.25 (9d83d1a478de+35419628e380) | 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 |
| 2026.10.29 (9d79f9e9e99e+85a786299464) | 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 |
| 2026.10.30 (7a8301068e6f) | 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 |

Item 9 concerns the workstation (WSL) install. The server edition already runs
as its own `argus` account.

## Weaknesses fixed

**0. No credential on state-changing requests (2026.10.22 only). Medium.**
CWE-306. Requests that change state were accepted from any local client that
sent no `Origin` header. Cause: there was no API token yet. Already fixed in
2026.10.25, which added a per-start token. It is listed here so that owners of
2026.10.22 upgrade.

**1. The token was given to every local account that loaded the page. Medium.**
CWE-306, CWE-200. The dashboard page sets the API token as a cookie for whoever
requests it. Because the page itself needs no credential, any local account
could obtain the token and then make state-changing calls. Fix: on Linux the
server now finds the owner of the connecting socket (`/proc/net/tcp`). It
withholds the cookie from any account other than the daemon's own and root,
both of which can already read the token file, and from the owner account the
service-account install names. A client whose owner cannot be determined (for
example a Windows process reaching the daemon across WSL networking) no longer
receives the cookie either. Such clients pair explicitly instead (see 10).

**2. Stalled connections were never closed. Medium.** CWE-400. The HTTP
handler had no socket timeout. A local client that opened connections and then
sent nothing, or announced a body it never sent, held one daemon thread per
connection indefinitely. The daemon that runs the security checks could be
exhausted this way. Fix: every connection now has a 30-second socket timeout.
Live update streams are unaffected; this was measured with a stream held open
for 30 s under a 1 s timeout.

**3. The token file could inherit a loose mode or follow a planted link. Low.**
CWE-377, CWE-59. The token was written to a fixed temporary name opened without
`O_EXCL`. If a file with that name already existed with a looser mode (for
example `0644`), it kept that mode, and the token file renamed into place had it
too. A symbolic link at that name was followed. Fix: the temporary file is now
created fresh and exclusively with a random name and mode `0600`, synced, then
renamed. It is removed if anything fails.

**4. The token check failed open when no token had been issued. Low.** CWE-636.
If the request handler ever ran without the token having been issued, every
state-changing request was accepted. Fix: with no token, nothing state-changing
is accepted.

**5. A non-ASCII token header raised an error instead of failing. Low.**
CWE-755. The constant-time comparison was done on text, which raises an
exception for non-ASCII input. The request still failed, but through an
unhandled error. The pairing-token check for the browser extension had the same
problem. Fix: both comparisons are now constant time over bytes, so the input is
simply a mismatch.

**6. The token cookie was readable by page script. Low.** CWE-1004. The cookie
lacked `HttpOnly`. Fix: `HttpOnly` added. No page script reads the cookie.

**7. Pages could be framed by other sites. Low.** CWE-1021. No
`frame-ancestors` directive was sent. Fix: every policy now carries
`frame-ancestors 'self'`, and every response also sends
`X-Frame-Options: SAMEORIGIN` and `X-Content-Type-Options: nosniff`.

**8. Server values were placed inside inline event-handler JavaScript. Low.**
CWE-79. Question ids, job names and fix ids were HTML-escaped and then inserted
into `onclick="...('…')"` strings. The browser decodes HTML entities in an
event-handler attribute before running it, so the escaping does not protect
that position. With today's server-generated id formats this was not reachable.
Separately, a collector state on the coverage page reached a `class` attribute
without escaping. Fix: these values now travel in `data-*` attributes through
the page's single delegated click handler, and the collector state is escaped.

**9. The daemon ran as the account it protects. Medium.** CWE-250, CWE-732.
Anything running as the owner could do the following:
- read the API token file;
- rewrite the store, acknowledgements and alert settings;
- stop the daemon.

On WSL, a Windows program could read the token file through `\\wsl.localhost`.

Fix: the documented default install now runs the daemon as the system account
`jarvis` (`./install.sh --service-account`, docs/guides/SERVICE-ACCOUNT.md):
- its state is `/var/lib/jarvis/.jarvis`;
- the directory is 0700 and every file 0600, all owned by `jarvis`;
- the daemon refuses to start while that directory is open to other accounts;
- the self-check also moves to the `jarvis` account;
- CLI commands that would read the owner's stale `~/.jarvis` refuse and print
  the `sudo jarvis-svc` form instead.

The earlier migration script is fixed as well. It put the store where the code
never looked for it, set an environment variable that nothing read, and shared
the store with a readers group. **Requires an owner deploy and switch-over.**

**10. Read-only routes served the full security state without a credential.
Medium.** CWE-306, CWE-200. Every local process could read the following:
- findings;
- processes;
- network peers;
- location;
- the live streams;
- `/metrics`.

Fix: every `/api/*` route, every live stream and `/metrics` now needs a
credential: the per-start token, or a paired client token. Exceptions:
- `/api/health` and `/api/live` stay open, but without a credential they return
  liveness fields only;
- HTML pages and static assets stay open.

Paired clients are listed and revoked with `jarvis desktop clients` and
`jarvis desktop revoke`. Only a SHA-256 digest of each client token is stored,
and a revoked token is refused.

Each kind of client authenticates as follows:
- **desktop app:** reads its token from an owner-only file in its config folder;
- **browsers that cannot be identified:** pair once on `/pair`, which sets an
  HttpOnly, SameSite=Strict cookie;
- **Prometheus:** sends `Authorization: Bearer`;
- **in-repo callers:** the CLI, quickstart, the Windows supervisors and the UI
  check send a paired token.

**11. The dashboard allowed inline script. Low.** CWE-79 (defence in depth).
`script-src 'unsafe-inline'` meant that any markup injection would run code in
the API's origin. Fix:
- all inline scripts moved to same-origin files;
- the 46 inline event handlers moved to delegated listeners;
- every page's policy is now `script-src 'self'`, with `object-src 'none'` and
  `base-uri 'none'`.

`style-src 'unsafe-inline'` remains: the compiled stylesheet is inline and
templates set CSS variables. All data reaching style attributes is escaped.

**12. The GeoSecurity page loaded unpinned remote code. Low.** CWE-829. Cesium
was loaded from a CDN by version range (`@1.121`) and Leaflet by version, both
without integrity hashes, into the API's origin.

Fix:
- **Leaflet 1.9.4:** vendored and hash-pinned.
- **Cesium:** about 11.7 MB, above the 10 MB vendoring bar, so it stays on the
  CDN. It is pinned to exactly 1.121.1 with SRI hashes and `crossorigin`, and
  the page's policy allows only that exact versioned directory. *Residual:*
  Cesium's own workers and assets cannot carry SRI.

## What was checked and found sound

- Binding is fixed at `127.0.0.1`.
- The `Host` header is checked against an allow-list, which prevents DNS
  rebinding.
- State-changing routes require `POST` with `Sec-Fetch-Site` or `Origin`
  same-origin.
- No CORS headers are sent.
- The cookie is `SameSite=Strict`.
- Request bodies are size-capped, and malformed JSON is rejected.
- The token never appears in a URL, a log line or an error message.
- Other dashboard data is escaped before rendering.

## Known remaining exposure (not fixed by this advisory)

- **Cesium workers and assets** come from the pinned CDN directory without SRI,
  so a compromise of that CDN path could still run code on `/geo`.
- **`style-src 'unsafe-inline'`** remains on every page.
- **Until the owner switches to the service account (item 9)**, any process of
  the owner's account can still read the token file, and with it the API.
- **Unidentified clients must pair.** Any client whose account cannot be
  identified, including the owner's Windows browser and desktop app, must pair
  before it sees data. This is intended, but it is a visible change.

## Recommended action

Install the first signed release after 2026-10-30, then:
1. switch to the service account (docs/guides/SERVICE-ACCOUNT.md);
2. pair the desktop app, browsers, supervisors and any scraper.

Until then, do not run unfamiliar software on the machine that runs the daemon.
