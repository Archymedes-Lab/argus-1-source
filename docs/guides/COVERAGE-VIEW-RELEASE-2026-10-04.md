# Coverage view: live feed and glass redesign, release record (2026-10-04)

Stage: `~/.cache/jarvis-release-staging/20261004T002224Z-on-e42b88bd6f8c`
Base: live release `20261003T224213Z-e42b88bd6f8c` (`sha256:e42b88bd6f8c…`).
Baseline: `docs/guides/baselines/coverage-view-baseline-2026-10-04.json`.

## What the release contains

- `jarvis/service/coveragemap.py`: `live()`, a 2 kB state built in about 2 ms through a read-only
  connection (the full summary is 72 kB and 15 ms, and opens the store's write path).
- `jarvis/web/server.py`, `jarvis/web/stream.py` (new to the live release): `/api/coverage/live`
  and `/api/coverage/stream`. The stream is bounded to 4 connections and 30 minutes each, refuses
  cross-site requests before taking a slot, and sends a visible heartbeat every 5 s. Shipping
  `server.py` also brings the already-written `/api/pulse` and `/api/stream` endpoints live.
- `jarvis/web/static/coverage.js`, `coverage.html`: the redesigned view.
- `jarvis/intel/gaps.py`: the T1562 fix described in the phase 2 record.
- Tests: `tests/test_coverageview.py`, `tests/test_stream.py`, `tests/test_techniques.py`.

## Design, and how Jev guided it

`scripts/reviews/coverage_view_design.py` put ten candidate design moves and ten things already
drawn to Jev, three questions each (does it help a glance read, could it mislead about protection
or activity, is it refined or a gimmick), and ranked them in code. Jev advises; the rules below
are the project's.

| Guidance | What was done |
|---|---|
| Random flicker between neurons to look alive: appeal 0.01, misleading 0.88 | Not built |
| Dendrite stubs, rotating core rings, swirling motes, drifting and breathing panes, sheen: appeal 0.09 to 0.39, misleading 0.66 to 0.84 | All removed. Nothing moves by itself except the camera's slow turn |
| Freeze and drain colour when not live: the one clear keep (misleading 0.32) | Kept; the panels grey out too |
| Axons faint until used: appeal 0.90 | Built |
| Technique id etched on each pane: the only candidate that helped a glance read without failing the misleading test | Built |
| Default reading: stay on what is proven (0.65) rather than alternate (0.04) | Default changed; alternating is still one click away |
| Theme: follow the system (0.64) | Kept |
| Colouring a firing by its result, an activity strip, an overdue ring, a distinct style for held claims: misleading above 0.5 | Not built on this ranking |

Kept against the ranking, with the reason: bloom (appeal 0.86; it is a static property of the
picture and stops with everything else when the view is not live), the signal from the core when
the scheduler starts a job (it is a real event), and the one-time fly-in on first load.

The misleading score ran high for nearly everything asked, so 0.5 was used as a strict bar for
new work, not as a measurement.

## Expected changes

1. `/api/coverage/live` answers with a state for all 50 collectors; `/api/coverage/stream`
   delivers a `pulse` on connect and a `beat` every 5 s when nothing changes; a fifth concurrent
   stream is refused with 503.
2. `/coverage` shows the same numbers as `/api/coverage` in both themes, a `live` badge, and
   technique ids on panes. A collector run reaches the page within about a second.
3. `gaps`: the eight T1562 findings disappear, and entries for T1068, T1102, T1185, T1187, T1195,
   T1200, T1568 and T1689 and their sub-techniques disappear. Nothing else changes.
4. Every other collector and the security score: unchanged. No collector code is in this release.
5. Load: with one page open the daemon does one 2 ms read twice a second instead of a 15 ms
   store open every four seconds.

Roll back if the service does not come back `ready`, if health degrades with a page open, or if
any finding outside item 3 changes.

## Incident during development (03:05 to 03:08 EEST)

The live daemon stopped answering and the Windows reviver restarted it twice, at 03:05:56 and
03:07:21 (its log, on the Windows clock, reads 02:05 and 02:07). From about 02:46 it had been
intermittently slow, with `native` reported stale. Machine load average reached 33.

What I was running at the time: a development server whose stand-in scheduler asked the live
daemon for the full coverage summary twice a second for about forty minutes, headless browser
captures, and the full unit suite. Other sessions and a headless Chromium not started by this
work were also running. The daemon recovered by itself after the second restart and has been
healthy since; no release was involved. The development server now caches the summary for 20 s
and asks the daemon nothing else, and the suite is no longer run alongside captures.

The reviver has used two of its three restarts in fifteen minutes; that budget frees up by
itself as the entries age out.

## Outcome

Read back 2026-10-04 after the owner deployed (release `20261004T002941Z-4cc6288f6dd0`).

| Expectation | Measured |
|---|---|
| release active, daemon healthy | yes |
| gap list loses the 16 superseded and newly mapped entries, gains none | 207 to 191; exactly T1102, T1102.003, T1187, T1562 and 7 sub-techniques, T1568 and 3 sub-techniques, T1689 gone; nothing new |
| `/api/coverage/live` small and fast | 2,137 bytes, 2 to 5 ms, 50 collectors |
| stream delivers pulses and beats | 1 pulse and 2 beats in 13 s |
| map unchanged | 89 validated, 25 claimed, 72 blind of 186 |
| page renders from the live daemon | captured with headless Edge: panes, labels, neurons, live badge, 50 of 50 current |

Right after the machine woke (WSL started 15:56:33) the page showed 27 current, 19 failing and
4 stale collectors and 83 validated; it returned to 50 current and 89 validated as the
collectors caught up. That is the view telling the truth about a monitor that was catching up.

The security score read 56 at the first readback and 46 later the same afternoon. The drop was
not this release: 23 editor extensions installed between February and May were reported as new
(a baseline bug in the extension inventory after standby, fixed in the next release), plus one
real Wi-Fi key-exchange failure event.
