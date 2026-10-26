# /procs identity and real-time sync (2026-10-24)

Owner request: build the next layer of the process map (which binary is behind each name), keep
refining and organising it, and make it truly real-time. Checkout only; it ships in the release after
`mechanisms-procs-20261023-r1` together with the change lens (see that guide's addendum).

## What the map now shows

| Colour | Meaning |
| --- | --- |
| Red | Unfamiliar: a name never seen on this machine, a familiar name running from a place it has never run from, a core Windows process (lsass, csrss, svchost…) outside `C:\Windows`, or an image running from memory only |
| Amber | New today: a name first seen today, a binary whose hash was first seen today (an update), a Linux file replaced since its process started, or a short-lived run from a temporary folder |
| Purple ring | A start Sysmon recorded that no 500 ms look caught (now on Linux too) |

The hover card says where the image runs from (Windows folder, Program Files, your user folders, a
temporary folder…), whether that path is familiar, and on Windows whether the binary has been seen
before. Paths and hashes never reach the page: the daemon judges and sends three words.

## Design

| Piece | File | Notes |
| --- | --- | --- |
| Image paths, no handles | `jarvis/platform/win/procfeed.ps1` | `SystemProcessIdInformation` by pid, once per new process; Sysmon starts now carry `Hashes` (SHA-256). No command line is read. |
| Linux side | `jarvis/platform/proclinux.py` | `/proc` reader moved here; `exe_path`; `StartFollower` (`journalctl -f -t sysmon`) for Sysmon for Linux starts. |
| Feed | `jarvis/platform/procfeed.py` | Identity worker (fast verdicts first, slow hash lookups after, cached); `i` frames; helper handoff before the 30-minute lifetime; Linux `ev` frames; paths and hashes stripped from every frame. |
| Judge | `jarvis/web/procidentity.py` | Place classes, version folding, path verdict against `Store.procs`, hash verdict against the event log index (read-only). |
| Page | `static/procs.js` + `procs-model.js` (rules) + `procs-state.js` (table, Node-testable) + `procs-scene.js` (three.js) | Was one 700-line file. |

Designs compared (Jev advisory, metadata only): daemon-side verdict words (chosen, 1.0) against sending
paths to the browser (breaks the metadata-only invariant) and hashing images through the Windows
share (redundant with Sysmon's hash, heavy I/O).

## Rules that keep it honest

* Unknown stays unknown: no path, no baseline, or a protected process whose path the scan never
  recorded reads "unknown", never "same" and never "moved".
* No slow fading for core names: the `SYSTEM_ONLY` list must run from the system place; a Windows
  name established in the system place needs your approval to run from a user-writable place.
* Short-lived starts are judged by place only. The first live run showed why: Docker health checks
  start ~4 processes a second, and the once-a-minute scan has never recorded those names, so "never
  seen" flooded the change list. Now: red only for memory-only images or a system name from a temp or
  user folder; amber for a temp folder or a never-seen binary; otherwise counted, not listed.
* Repeated identical change lines within 10 minutes become one line with a count.
* A Sysmon start for a pid that exited within the last minute is not a ghost (Sysmon for Linux can
  deliver a start after the exit).
* A start during a gap (stream reconnect, helper handoff) is still listed: a resynchronising snapshot
  treats processes created after the last live moment as births.

## Measured on this machine (2026-10-24)

* 315 Windows and 113 Linux processes judged: 0 false alarms; 3 amber, all true (Task Manager and
  Ollama binaries first seen today). Windows: 301 same path, 16 unknown (protected processes).
* Judge: 5 ms for 315 verdicts from a ~2 s baseline load; a cold event-log hash lookup is 0.1-0.3 s
  (a pid is reused ~100 times in five weeks), so lookups run after the verdicts and are cached.
* Controls (all in WSL, nothing written to Windows): a copy of `/usr/bin/sleep` run from `/tmp`
  shown red 0.35 s after it started; a 0.1 s run of it listed 0.13 s after it ended; a Windows
  `cmd /c exit` counted 2.4 s after launch through interop.
* Continuity: three real helper generations in 75 s (renewal shortened to 30 s for the test), the
  Windows source live throughout, at most 0.60 s between Windows frames.
* Cost: helper 7.7 ms CPU per second steady with path lookups; identity settled 4 s after the page
  opened (22 s cold).
* Tests: `tests/test_procfeed.py` (34), `tests/test_procidentity.py` (15), `tests/test_procs_page.py`
  (18, page rules run in Node), `tests/test_procbaseline.py` (7).

## Limits

* No code-signing verdict; Linux has no hash history.
* The daemon runs unprivileged: 22 of ~100 Linux executable paths are readable, so most long-running
  root processes read unknown (those started while the map is open get their path from Sysmon).
* The Linux start history starts empty at deploy and says only "unknown" for its first day; it is
  written by the 10-minute sysmon_linux pass, so a program first started minutes ago reads new.
* A masquerade under a non-core name in a place that is not user-writable becomes established after a
  day.

## Start history (added later on 2026-10-24)

Jev's pick for the next gap (0.64): judge short-lived programs by whether that exact program has
started here before, not by place alone.

* Windows: the event log already indexes the first sighting of every started image path and hash
  (`sightings`, kinds `image` and `sha256`, since 2026-09-17): 789 images.
* Linux: `jarvis/collectors/telemetry/sysmon_linux/history.py` adds a `start_images` table (one row per
  image path and SHA-256: name, first and last sighting, count; at most 50,000 rows, least recently
  seen dropped first), written by the incremental `sysmon_linux` pass from the events it already
  parses. Metadata only. A failed write is a low finding; the audit's own findings are unaffected.
  Measured on a real 10-minute window: 4,877 starts became 114 rows in 79 ms (the pass already spends
  ~9 s reading and parsing the journal).
* `Judge.judge_start` gives a start no table row showed: path `same` if that image first started more
  than a day ago, `new` if never or only today, `unknown` while the history is younger than a day;
  `moved` (a familiar name from a user-writable place) still wins. Linux hashes are now judged
  against the same history.
* Page rule for such starts: red for memory-only or `moved` from a temp or user folder; amber for a
  first run here, for a temp folder unless the program has run from there before, or for a
  never-seen binary; otherwise counted only.
* Checked against the real event log: `cmd.exe` and `conhost.exe` same; an invented Temp program new;
  `svchost.exe` from Temp moved. Tests: `tests/test_start_history.py` (10).
