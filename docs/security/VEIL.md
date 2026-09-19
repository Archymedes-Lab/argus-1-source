# JARVIS Veil

Status: implemented as an **opt-in, evidence-only foundation** on 2026-09-19.
It is not a claim of installed browser coverage, effective browser blocking, or
protection from every fingerprinting technique. Its status is deliberately
registered as partial in `jarvis/core/assurance.py`.

Veil protects against silent behavioral profiling without becoming an input
logger. The browser-side sensor observes a fixed, bounded set of counters:

- interaction listener registrations (`mousemove`, `pointermove`, `scroll`,
  `input`, `keydown`);
- high-entropy surface use (`canvas`, graphics, audio, media-device, OPFS);
- transport method counts (`fetch`, XHR, `sendBeacon`); and
- top-level and egress **origins only**.

It never intentionally reads or sends page text, form values, typed characters,
keystroke timings, pointer coordinates, screenshots, cookies, resource paths,
query strings, request bodies, or browser/device identifiers. Browser reports
are untrusted evidence. A script may produce misleading counters, so no report
can authorize a response; JARVIS stores a durable observation before any later
policy work.

## Detection policy

Veil only raises an interaction finding when four or more interaction listener
types coincide with cross-origin network export. It treats a single listener as
ordinary website behavior. It flags fingerprinting only when four distinct
high-entropy surfaces coincide with cross-origin export. These are privacy-risk
indicators, never compromise verdicts.

`clean_link()` removes common URL-decoration parameters for an integration to
use; this release does not rewrite browser navigation automatically.

## Pairing and operation

1. Run `jarvis veil pair` against the database used by the local dashboard.
2. Load `browser-sensor/` as an unpacked Chromium-compatible extension and
   paste the printed token into its options page.
3. Keep the dashboard on its loopback-only default (`127.0.0.1:8787`).

The extension posts a maximum 8 KiB aggregate report to a write-only endpoint.
The endpoint requires an exact Host header plus a constant-time checked pairing
token, has no CORS grant, returns no browsing evidence, and does not queue data
when JARVIS is unavailable. Re-pair to rotate the token. The token is sensitive:
do not put it in a support bundle or screenshot.

## Explicit limitations and next safe increments

This source tree does not demonstrate that an extension is installed, that its
main-world hook cannot be bypassed, or that a browser's native anti-fingerprinting
features are effective. It does not yet inventory extension permissions/deltas,
resolve CNAME cloaking, inspect redirect chains, proxy email content, or block
third-party requests. Browser enforcement must use a separately tested browser
integration with narrow per-site exceptions, tested rollback, and user-visible
explanations; HTTPS interception/MITM is out of scope.

Forge scenarios in this first increment are pure unit-level synthetic reports.
They verify the privacy invariants and classifier thresholds, but do not validate
browser containment or a live browser's telemetry.
