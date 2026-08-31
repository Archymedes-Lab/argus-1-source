# sentry

Monitors what runs on this machine — both the WSL2 Linux side and the Windows
host — and audits the ways something could take or keep control of it.

Pure Python 3 standard library. No dependencies, no agent, and no network calls
unless you ask for one — `--enrich`, the `intel` feeds, or email alerts once you
have put a Resend key in the config.

## Start here

```bash
cd ~/sentry
./install.sh --service   # run it 24/7, dashboard at http://127.0.0.1:8787
sentry investigate       # or a one-off report in the terminal
```

## The dashboard

`sentry serve` runs a scheduler and a local web page. It is plain
`http.server` + SQLite + one self-contained HTML file — no framework, no build
step, no CDN, and no dependency beyond the Python standard library. For a
security tool that is the point: every dependency is code you have to trust, and
this one is meant to tell you when something untrustworthy is running.

Three things shaped the design:

- **Collectors have wildly different costs.** Reading `/proc` takes 20ms; a
  PowerShell audit takes 10–60s because crossing the WSL interop boundary
  dominates everything else. So each job runs on its own interval — processes
  every 60s, firewall every 15min, spyware and autostart hourly.
- **Jobs never run concurrently.** A single worker runs them one at a time; two
  simultaneous `powershell.exe` launches are slower than running them back to
  back and fight over the same interop pipe.
- **The page never waits for a scan.** Every request is served from the last
  stored snapshot, so the dashboard is instant even mid-audit, and a restart
  redraws immediately from SQLite instead of showing a blank page.

The listener binds `127.0.0.1` with no option to change it. A page listing your
firewall gaps and running processes is exactly what an attacker would like to
read.

### Running 24/7

`./install.sh --service` installs a systemd **user** service with
`Restart=always`. Two WSL-specific gotchas that the installer calls out:

1. **Linger.** Without it, systemd tears down your user manager when your last
   shell exits — closing your terminal would stop the daemon.
   ```bash
   sudo loginctl enable-linger $USER
   ```
2. **WSL itself.** WSL only runs while Windows keeps it running. Run
   `./install.sh --windows` for the one-time PowerShell command that registers a
   hidden logon task to start WSL; systemd and linger take it from there.

## The commands

| command | question it answers |
|---|---|
| `scan` | What is running right now, and is any of it new? |
| `hidden` | Is anything hiding from the normal process listings? |
| `boot` | What ran at startup — including windows that flash open and close? |
| `spy` | Is anything monitoring me? Who used the mic/camera, and when? |
| `firewall` | Who can reach in, and who actually did? |
| `control` | What could take control of this machine, and are the defenses on? |
| `asep` | What else can auto-start code — beyond Run keys? |
| `investigate` | All of the above, in one report. |
| `intrusion` | How would this machine have been broken into — and was it? |
| `evasion` | Is anything in a position to lie to the checks above? |
| `coverage` | Is this system itself running, current, and not blind? |
| `intel` | What is being used against machines like this one, right now? |
| `feeds` | Bulk indicator feeds — hundreds of thousands of live records, free. |
| `hunt` | Is any of it actually here? |
| `gaps` | What is current attacker tradecraft that nothing here checks? |
| `implant` | Can anything read my traffic, or reach past the firewall? |
| `backdoor` | What grants a way back in — keys, sudo, units, accounts? |
| `posture` | Are the defenses that would have stopped this switched on? |
| `netwatch` | What has the network been doing, and did anything tamper with it? |
| `inputwatch` | Did anything type or move the cursor that was not a human? |
| `sysmon` | What happened between two sampling passes? |
| `secrets` | Which credentials are sitting in plaintext on this disk? |
| `serve` | Run everything continuously behind a local dashboard. |
| `alert` | Email me when a collector stops recording or something critical fires. |

```bash
sentry baseline          # learn the current state as known-good (do this once)
sentry scan              # what drifted, what looks wrong, who it talks to
sentry scan --enrich     # ...and reverse-DNS the public IPs
sentry watch -i 120      # keep scanning, print only medium-and-worse
sentry hidden            # cross-view scan (--deep sweeps the full pid range)
sentry boot              # reconstruct startup from the event logs
sentry spy               # monitoring software, capability use, input devices
sentry evasion           # kernel integrity, hidden streams, shortcuts, dead drops
sentry firewall          # posture, inbound rules, inbound connections, logons
sentry control -v        # persistence / remote access / defenses
sentry peers --scope public   # every external IP seen, and which process reached it
sentry events --since 24      # alert history
sentry procs --approved 0     # fingerprints not yet approved
sentry approve <fp> --note "my build script"
sentry status

sentry intel --set-key <exa-key>   # once
sentry intel                      # refresh the least-recently-updated topic
sentry intel --all                # refresh the whole corpus
sentry intel --show               # what the knowledge base holds
sentry intel --revet              # re-judge stored indicators after a rules change
sentry hunt                       # match every indicator against this machine
sentry gaps -v                    # techniques in current intel that nothing checks
```

Add `--host wsl` or `--host win` to either side alone; the default is both.
Every audit command takes `--severity`, `-v` and `--json`.

## Finding hidden processes

No single process list is trusted, because anything with enough privilege can
lie to the API behind it. `sentry hidden` collects several enumerations that
reach the kernel by different routes and diffs them:

*Linux* — libc `readdir`, the raw `getdents64` syscall via ctypes (which an
`LD_PRELOAD` rootkit cannot filter), a direct `stat()` sweep of the pid range,
and socket inodes that no visible process claims. It also checks for bind-mounts
over `/proc/<pid>`, which hide a process with no code injection at all.

Two of these views do not go through procfs at all, which matters because a
single rootkit that filters procfs defeats every view that does:

- **The signal path.** `kill(pid, 0)` delivers nothing but resolves the pid
  through the kernel's pid hash table. A pid that accepts a signal while having
  no `/proc` entry is hidden below the filesystem layer.
- **The scheduler.** `/proc/sched_debug` is generated from the runqueues rather
  than the process tree, so a task can be scheduled and still be missing from
  the listing. (Absent on kernels built without `CONFIG_SCHED_DEBUG` — including
  WSL's — in which case the missing view is reported rather than passed.)

It also looks for the machinery itself: **pinned eBPF maps named for
concealment** (`hidden_pids`, `hidden_names`, `hidden_inodes`), which is where a
modern eBPF rootkit keeps the list of what it is hiding — so the finding tells
you to `bpftool map dump` it and recover exactly what was concealed — and
**io_uring**, which performs file, socket and process operations through a
shared ring buffer instead of syscalls, making it invisible to syscall-based
tooling. Processes holding a ring are listed, and whether the kernel permits it
at all is reported.

Beyond process listings it looks for the machinery hiding them:

- **Bind probing.** A rootkit that filters `/proc/net/tcp` still cannot make the
  kernel hand out a port that is genuinely bound. Asking to bind each port and
  being refused `EADDRINUSE` while no visible socket claims it means something
  is listening that does not want to be seen.
- **Kernel modules.** A classic LKM rootkit unlinks itself from `/proc/modules`,
  but the `/sys/module/<name>` directory it created on load usually survives.
- **eBPF.** This is now the preferred way to build a Linux rootkit — it loads on
  any modern kernel without matching headers and can filter what other tools
  see. Loaded programs and the processes holding eBPF file descriptors are
  inventoried; tracing-class program types are called out. Legitimate users
  exist (systemd, Docker, observability agents), so this is a list to review.
- **ftrace hooks.** How many rootkits patch syscalls without ever touching the
  syscall table.
- **Injected and fileless code.** `LD_PRELOAD` in a live process environment, an
  executable mapping marked `(deleted)`, or a `memfd:` executable mapping —
  code running with no honest file behind it.

*Windows* — `Win32_Process` (WMI), `Get-Process` (the process API), `tasklist`,
and the pids owning TCP connections. Userland hooks routinely patch one of these
and miss the others. But all four walk the same kernel list —
`ActiveProcessLinks` — so all four fall to one DKOM unlink. Four more views
reach process objects by other routes:

- **The handle table.** `OpenProcess` resolves through `PspCidTable`, a
  different structure entirely. Unlinking an `EPROCESS` from
  `ActiveProcessLinks` does not remove it from here, so a pid that opens while
  appearing in no enumeration is the signature of that attack. The sweep runs in
  C# because 16k P/Invoke calls from PowerShell would take minutes.
- **The thread list**, **the performance counters**, and **the service
  controller** — each reached through its own provider chain.

Two things make this usable rather than noisy, and both were found by running
it:

1. **A pid that opens is not necessarily a running process.** When a process
   exits, its kernel object — and its pid — stay valid for as long as anything
   holds a handle to it, so `OpenProcess` keeps succeeding on something already
   gone. Checking `GetExitCodeProcess` for `STILL_ACTIVE` removes ~27 phantom
   detections on an ordinary desktop.
2. **`ERROR_ACCESS_DENIED` is not proof of existence.** It is returned both by
   protected processes and by pids that cannot be qualified at all. Those are
   reported as a *gap in coverage* — with the advice to re-run elevated — rather
   than as critical findings, because guessing there is guesswork dressed up as
   an alert.

Every candidate from every view is then re-tested against a fresh enumeration
and re-probed for life, so a process that merely started or exited mid-scan is
never called a rootkit. `sentry asep` adds **masquerade detection** (a `svchost.exe`
outside System32 is not svchost) and **parentage analysis** (Office or a browser
spawning a script host, WMI spawning a shell, `lsass` having children at all).

Disagreement between views is re-verified before it is reported, so a process
that merely started or exited mid-scan is not called a rootkit. Threads are
excluded: `/proc/<tid>` stats fine for every thread while `readdir` lists only
thread-group leaders, and treating that as hiding produces nothing but noise.

## Knowing what to look for

Every other check in this repo encodes what was worth looking for on the day it
was written. Attacker tradecraft moves; a static detector quietly ages into a
detector of last year's problems. `intel` keeps a knowledge base of current
published research, `hunt` compares it against this machine, and `gaps` reports
what current tradecraft nothing here can see.

The knowledge comes from Exa's search API, restricted to a list of publishers
that do primary host-based research. Each result is passed back through the
same API with a JSON schema attached, so what returns is structured artefacts —
paths, hashes, domains, registry keys, ATT&CK technique ids — rather than
article text to parse. The API key lives in `~/.sentry/config.json` at mode
0600, never in the repository.

### Why none of it is trusted

This is the only part of sentry that takes input from the internet, and it does
so in a security tool whose entire value is being right about what is running.
Two things are wrong with the input by construction: the articles are written by
strangers, and the extraction is done by a language model that fills empty
fields with plausible filler.

That is not hypothetical. One real article in testing produced `evil.com`,
`192.168.1.100`, `gdb`, `strace`, a bare `/tmp/`, and two "SHA-256" values that
turned out to be the digests of the empty string. Every one of those is
syntactically perfect. Loaded straight into a detector on a developer's
workstation, that single article would have flagged the debugger on every use
and pinned a permanent alert on a directory that is supposed to contain files.

So `vet.py` sits between the feed and the database, and it is deliberately the
dumbest code in the project — no network, no model, no learning. It drops
digests of empty input, non-public addresses, reserved example domains, kernel
symbols filed as process names, stock PAM modules, path fragments like `/proc`
that exist on every machine, and anything holding a redaction marker. On the
first real corpus run it rejected roughly a quarter of all candidates.

Two invariants hold no matter what the feed says:

- **Intel may only ever add suspicion.** Nothing fetched can approve a process,
  clear a finding, or lower a severity. The worst a poisoned feed can achieve is
  wasting your attention; it can never create a blind spot.
- **Nothing fetched is ever executed.** Indicators are compared as data — never
  interpolated into a shell, never used to build a command.

When the rules get tighter, `sentry intel --revet` re-judges everything already
stored, so the knowledge base is never stuck at the quality of the rules that
were in force the day it was fetched.

### Turning knowledge into a check

`hunt` only compares against state sentry already collects, so it is cheap
enough to run every half hour:

| indicator | checked against | severity on match |
|---|---|---|
| SHA-256 | digests of executables in the baseline, cached by size and mtime | critical |
| domain / IPv4 | the recorded peer table, including reverse DNS | critical |
| absolute path | the filesystem, skipping anything a package owns | high |
| filename | only the directories such a payload must live in to work | high |
| process name | exact matches in the process baseline | high |

Two second-guards keep the false-positive rate down: a path that `dpkg` owns is
never reported, because a package putting a file where it belongs is not an
intrusion, and a directory is never reported as a dropped file.

The filename check exists because the best indicator from the first real run —
`pam_security.so`, a PAM backdoor named in six separate writeups — arrived with
no path at all. Hunting bare filenames across a whole filesystem would be slow
and noisy, so it looks only where such a payload has to be to function: the PAM
module paths, the loader paths, the systemd unit directories, the world-writable
drops.

### Gaps: pointing the tool at its own blind spots

ATT&CK technique ids cannot be "found" on a host, so they are used differently.
`gaps` compares the techniques current research is discussing against the
techniques sentry's collectors actually cover, and reports the difference,
weighted by how many independent writeups raised each one. A technique three
teams wrote about this year is a better use of an afternoon than one mentioned
once.

This is the counterpart to `coverage`. `coverage` asks whether sentry is
running; `gaps` asks whether it is looking at the right things — and answers
with a work queue rather than a warning.

### Cost

Searches are metered. One topic refresh is roughly five cents; the full corpus
is under forty. The daemon refreshes one topic at a time on a six-hour timer, so
the corpus rotates itself over about two days. A daily budget, default `$0.50`
and settable as `daily_budget` in `~/.sentry/config.json`, is enforced before
each query rather than reported after it — a metered API on a 24/7 timer is
otherwise a standing invitation to a surprise bill.


## Volume: the bulk feeds

Search buys *tradecraft* — the path a rootkit drops, the unit file it installs.
It is a poor way to buy *coverage*: a writeup names a handful of hashes, and
paying a metered API per document to accumulate tens of thousands of them costs
real money for data that is already published free.

So `feeds` carries the volume and `intel` carries the narrative:

| | source | gives |
|---|---|---|
| `intel` | Exa over ~60 research publishers | paths, filenames, techniques, persistence |
| `feeds` | 15 public feeds, no authentication | hashes, domains, addresses, ranges, CVEs |

The feeds are abuse.ch (ThreatFox, MalwareBazaar, URLhaus, Feodo), CISA KEV,
Spamhaus DROP, OpenPhish, Emerging Threats, blocklist.de, CINS, Binary Defense,
IPsum, and the MITRE ATT&CK catalogue. Together they hold **just under 400,000
live indicators**, refreshed on each publisher's own cadence — ThreatFox and
URLhaus update continuously, CISA KEV when exploitation starts.

Feed data is better than an extraction from prose: curated, attributed,
confirmed malicious. It still goes through the same `vet.py` gate, because a
feed can carry a private address or a defanged placeholder too, and because the
"intel may only add suspicion" invariant has to hold for every source without
exception.

Everything ages. `feeds --prune` retires feed indicators no publisher has
listed for 90 days, because C2 infrastructure is rented and recycled and an
address that fell off every list three months ago is more likely to be someone
else's server now. Writeup-derived indicators are never pruned: a sample's hash
is true forever.

### Staying fast at that size

Holding 400,000 records is easy. Querying them on a 30-minute timer without the
machine noticing is the part that needed design.

The first version loaded every indicator into Python dictionaries and compared
in a loop. At sixteen thousand records that was invisible; at four hundred
thousand it would have read a hundred megabytes into memory to answer a
question SQLite can answer from an index. `hunt` is now written as indexed
joins against the `(kind, norm)` unique index, with three consequences:

- addresses match in a single join
- reverse-DNS names walk only their own parent domains — a handful of index
  probes each, regardless of how many domains are stored
- file hashes probe the index per file rather than loading every digest

Network ranges are the exception, because a CIDR cannot be indexed by value, so
they are bucketed by first octet and a peer is only tested against the handful
of networks that could contain it.

The database runs in WAL mode so the dashboard reads while feeds write. Bulk
inserts go in 20,000-row chunks.

The result is that a hunt across 397,000 indicators takes **0.4 seconds** —
the same as it took across 16,000.

## Interception, boundary bypass, and trust

`implant` looks for what a *targeted* implant does that commodity malware
usually does not bother with: the quiet changes that let an operator read
traffic and reach in past the firewall.

- **interception** — a root certificate the operator controls, a proxy or PAC
  URL, a rewritten hosts file, a DNS override. None of these are malware. All
  of them make TLS readable.
- **boundary** — `netsh interface portproxy` forwards traffic straight through
  the host **with no firewall rule to show for it**, which is why the firewall
  audit cannot see it. Filtering-platform callouts sit below the firewall UI
  entirely.
- **trust** — an unsigned driver, a PAM module no package owns, a preloaded
  object. These do not hide the implant; they make the system vouch for it.

Worth saying plainly: true Pegasus indicators are iOS and Android artefacts and
nothing here can find them — that is a phone forensics job for Amnesty's MVT.
What this finds is the desktop equivalent class, and it reports mechanism
rather than attribution.

## Backdoors

`backdoor` reads the mechanisms that grant access and asks whether what they
grant is what you intended: SSH authorised keys and `sshd_config`, systemd
**user** services (which need no root at all), XDG autostart entries, appended
shell profiles, `NOPASSWD` sudo grants, setuid binaries no package owns, second
UID-0 accounts, and — on Windows — OpenSSH authorised keys, accounts hidden
from the sign-in screen, and a debugger set on `sethc.exe` or `utilman.exe`,
which yields a SYSTEM shell from the logon screen with no credential.

Most of these need a human to confirm, because the tool cannot know which SSH
key is yours. So each finding shows the actual evidence — the key comment, the
sudoers line, the appended command — not just the filename.

## Posture: what should be switched on

`posture` asks whether the defenses that would have stopped an intrusion are
enabled, and names the setting to change when they are not.

It covers Defender (real-time, tamper protection, PUA, network protection,
signature age, exclusions), ASR rules, Secure Boot, TPM, VBS and Memory
Integrity, Credential Guard, LSA protection, BitLocker, UAC, autologon, local
administrators, SMBv1, RDP, WinRM, SmartScreen, and PowerShell logging.

Four of those — BitLocker, TPM, Defender's exclusion list and optional features
— return nothing at all without administrator rights, and *nothing* is
indistinguishable from *clean* unless something asks properly. `--elevate`
re-runs the same collector behind a UAC prompt and reads them for real. It
matters: on this machine the unelevated run reported Secure Boot and BitLocker
as "could not be read", and the elevated run showed Secure Boot **off** and the
system drive **unencrypted**. A cancelled prompt is reported as an error, never
as an empty result.

**On activation**, since it is the question everyone asks: an unactivated
Windows is not an insecure Windows. Activation gates personalisation, not
security — Defender still runs, Windows Update still delivers security patches,
the firewall still works. What carries risk is the *method*: a script piped
from the internet into an elevated shell is a total-trust event regardless of
what it does afterwards. So activation state is reported as information, and
the activation method is treated as the thing worth thinking about.

## Network history

`netwatch` samples network state every two minutes and keeps every sample, not
just the interesting ones. The useful network questions are all about the past
— when did the link drop, did the adapter go down on its own, has this network
always been on this hardware — and none of them can be answered by looking now.
Storage is a few hundred bytes a minute; the alternative is discovering that
the one moment you needed is the one you did not keep.

What the transitions mean:

| transition | reading |
|---|---|
| adapter disabled | nothing disables a working adapter by accident |
| link lost | ordinary alone — the point is what else happened at that moment |
| same SSID, new BSSID | roaming, unless the BSSID is one never seen before |
| encryption weakened | a network that was WPA3 yesterday is not the same network |
| gateway MAC changed | traffic now leaves through different hardware — ARP spoofing |

It also folds in Windows' own WLAN log, so the history predates the monitor.

One caveat the audit reports on itself: `netsh` needs Location permission to
reveal SSID, BSSID and cipher. Without it, evil-twin and downgrade detection
cannot run — adapter state, gateway MAC, DNS and the connect/disconnect log
still do. The audit says so rather than reporting a clean result it could not
actually check.


## Input that no human produced

Windows tags every keyboard and mouse event that did not come from real
hardware. `LLKHF_INJECTED` marks anything delivered through `SendInput` or
`keybd_event`; `LLKHF_LOWER_IL_INJECTED` additionally marks input injected by a
process at a lower integrity level than the window receiving it, which is the
shape of one program driving another's UI. Those flags are visible only from
inside a low-level hook, so `inputwatch` manages a small resident helper that
installs one.

Three costs, all real, all worth stating before you turn it on.

**It is an agent.** Everything else here samples state and exits. This runs
resident, and if it dies the record stops — so it emits a heartbeat, because
otherwise "no injected input" and "not watching" look identical.

**It does not record what you type.** A low-level keyboard hook sees every
keystroke, and one that stored key values would be a keylogger writing your
passwords to a SQLite file — on a disk this project's own posture audit
confirmed is unencrypted. Real keystrokes are counted and nothing else.
Injected events store a coarse class (`enter`, `character`, `navigation`), the
flags, and the focused window. Enough to say *something typed Enter into your
terminal at 03:14*; not enough to reconstruct a sentence.

**Injected does not mean malicious.** Password-manager auto-type, AutoHotkey,
on-screen keyboards, RDP, screen sharing and some IDE features all inject
legitimately, and the flag says nothing about *which* process did it — the
foreground window is only a weak correlate. This reports evidence with the
context to judge it, not a verdict.

### Why the cursor feels slow

Every low-level hook sits in a chain, and each one delays every event until it
returns. That is the mechanism behind "the mouse is slower than it used to be":
a keylogger, screen recorder or overlay doing work on the input thread shows up
as milliseconds on every movement.

So the hook measures it rather than guessing — the delta between when Windows
generated an event and when this hook received it, reported as average, peak,
and the share of events over 50 ms. Sentry's own hook is in that chain and
contributes part of the figure, which is why the finding says so and tells you
to stop it and re-measure.

It also reads `LowLevelHooksTimeout`. Windows silently removes a hook that
takes longer than that to return, default 300 ms, so software wanting to keep a
slow hook alive has a motive to raise it. An unexplained increase is a finding.

### Keeping the hook up

The helper is Windows-side and does not survive a reboot, a WSL restart or
being killed — and anything that wants to drive this machine unseen has a
direct motive to kill it. So the daemon runs an `input_hook` watchdog every
45 seconds:

- **Liveness is the heartbeat, not the PID.** A hung hook still has a PID and a
  forged pid file still names one. Past 90 s without a heartbeat the watchdog
  crosses the interop boundary once to tell "process gone" (restart now) from
  "process alive, drain delayed by a slow collector" (wait); past ~210 s an
  alive-but-silent helper is treated as a removed hook and cycled.
- **Restarts back off exponentially** (20 s to 10 min) keyed to consecutive
  failures, so a crash loop cannot become a `powershell.exe` spawn loop.
- **Repeated failure is itself a finding.** More than four restarts in six
  hours is reported `high`: a security monitor that keeps dying is a detection,
  not an operational annoyance. Eight consecutive failed restarts is `critical`.
- **The helper script is content-pinned.** A change to the trusted source is
  surfaced; a staged copy that does not match it aborts the restart rather than
  launching something unexpected.

The healthy path is local-only — drain the output file, check the heartbeat
age — so running it every 45 s costs about 25 ms and no interop round trip.

## Alerts: being told when it stops

The dashboard is only useful when you are looking at it. `sentry alert` adds an
outbound path for the findings that matter when you are not — a collector that
crashed, a monitor that stopped recording, anything `critical`.

It is off until you configure it, and it is the one component besides `intel`
that reaches the network on its own. It sends through [Resend](https://resend.com)
over HTTPS, standard library only. Put this in `~/.sentry/config.json` (kept
`0600`):

```json
{
  "resend_api_key": "re_...",
  "alert_from": "sentry@yourdomain.com",
  "alert_to": "you@example.com",
  "alert_min_severity": "high",
  "alert_resend_after": 21600,
  "alert_on_clear": true,
  "alert_hourly_cap": 12
}
```

`alert_from` must be a sender Resend has verified for your domain; `alert_to`
takes a string or a list. The key may also come from `$SENTRY_RESEND_KEY`, and
it is only ever sent in the `Authorization` header of the one request to
`api.resend.com` — never logged, never in the body.

Every finding has a stable key, so an alert pages you once when it fires, again
after `alert_resend_after` if it is *still* firing, and once when it clears —
not on every 45-second watchdog tick. Findings that mean "sentry itself is not
watching something" page regardless of `alert_min_severity`, because a
monitoring gap is the one class of finding whose whole point is that nothing
else will tell you. `alert_hourly_cap` is a hard ceiling; anything past it is
suppressed and noted in the next mail.

```bash
sentry alert            # show configuration and any active alerts
sentry alert --test     # send a test message to the configured recipients
```

**On screen scraping**: the modern capture APIs go through the capability
access manager and `spy` already reports them, including whether a capture
border was shown. Legacy GDI scraping — `BitBlt` against the screen DC — leaves
no such record and a sampling monitor cannot see it. That is a genuine blind
spot rather than a covered one, and it is listed as such rather than papered
over.

## Sysmon: the ceiling this design otherwise has

`coverage` reports its own limit honestly: *sampling, not interception —
anything that starts and exits between two passes is never seen.* That is why
`T1003` (OS credential dumping), the most-raised technique in the whole
intelligence corpus, was marked unclosable. Catching a process opening LSASS
means being told when it happens, not asking afterwards.

Sysmon is a kernel driver that does exactly that. With it installed, `sysmon`
reads process access (event 10), remote threads (8), image tampering (25),
unsigned image loads (7), DNS queries (22) and process starts with hashes (1).

The last two are worth more than their own findings. A DNS query is a name to
check against the 53,000 domains in the corpus, and a process start carries a
SHA-256 to check against 252,000 sample digests — so the knowledge base stops
being something matched against *current* state and becomes something matched
against everything that happened while nobody was looking.

Reading the channel needs membership in `Event Log Readers`, or elevation.
When that is missing the module says so and says how to fix it, because a log
that cannot be read produces exactly the same silence as a machine with nothing
wrong. That distinction is the whole reason `coverage.py` exists.

## Detecting how machines actually get broken into now

`sentry intrusion` targets current initial-access tradecraft rather than
classic malware, because the modern shape is a thing that runs **once** and
leaves no persistent process for a behavioural rule to catch:

- **ClickFix.** A fake CAPTCHA copies a command to your clipboard and tells you
  to press Win+R and paste it — reportedly the largest single initial-access
  technique in circulation. It leaves a perfect fingerprint: Windows records
  everything typed into the Run dialog in `RunMRU`. That key is read and every
  entry matched against download-and-execute shapes.
- **Infostealers.** They harvest browser cookies, session tokens and saved
  passwords, then exit. Detection here is the residue: PowerShell console
  history, recently written unsigned executables in staging directories, and
  browser extensions.
- **Session theft.** Stolen cookies are replayed directly, so the password and
  the second factor never come into it. Extensions are inventoried and rated on
  whether they can read every page and whether they came from outside the store.
- **Defender's own history.** The cheapest question to ask and the one most
  often skipped: has the antivirus already found something and been ignored?
  Detections that were *not* remediated are raised to critical.

## Checking whether anything can lie to the other checks

Every collector above reads the machine from userland, so each one is only as
honest as the layer beneath it. `sentry evasion` asks the prior question — is
anything in a position to lie? — by targeting the techniques that specifically
defeat userland inspection:

- **BYOVD (bring your own vulnerable driver).** Load a genuinely signed but
  vulnerable driver, exploit it to run code in the kernel, and switch the
  defences off from underneath. Nothing above the kernel can see the result, so
  the useful signal is the *precondition*: whether Memory Integrity (HVCI) and
  the vulnerable-driver blocklist are on, and whether any loaded driver sits
  somewhere it shouldn't. Severity follows **writability**, not novelty — real
  vendors (anti-cheat, virtualisation, backup) do ship drivers outside
  `System32\drivers`, but a driver under `AppData` or `Temp` did not arrive
  through an installer that already had admin, and that is how BYOVD stages.
  Drivers with public kernel read/write exploits are named outright.
- **NTFS alternate data streams.** A second stream on an ordinary file doesn't
  appear in a directory listing, doesn't change the visible file size, and runs
  perfectly well. Staging directories are enumerated for any stream that isn't
  `Zone.Identifier` — the mark-of-the-web, which is on nearly every download and
  is the reason a naive ADS check is all false positives.
- **LNK abuse.** A shortcut that displays one thing and runs another remains one
  of the most durable initial-access vectors there is. Shortcuts in Startup,
  Desktop and Downloads are checked for a script-host target, arguments that
  fetch or decode code, and an icon borrowed from a binary other than the
  target.
- **Dead-drop C2.** Commands and stolen data increasingly move through Telegram,
  Discord webhooks, paste sites and tunnel providers, so egress is ordinary
  HTTPS to a reputable host and neither a firewall rule nor an IP reputation
  feed objects. The DNS client cache is the cheapest honest view of destinations
  *by name*, which is the only level at which this is visible at all.
- **Invisible Unicode.** Zero-width and bidirectional-override characters in a
  command line make displayed text differ from executed text. Run keys, RunMRU
  and shortcut arguments are checked; there is no legitimate reason for these
  characters to appear in any of them.

## Auditing the monitor itself

`sentry coverage` answers the question that decides what every other module's
silence is worth: *can this system currently see?*

The failure it exists to prevent has already happened here once. The daemon ran
for hours reporting every Windows collector as healthy while the interop socket
was dead — each job had a timestamp, each timestamp looked recent, and every one
of them was a stale snapshot being re-read. **A clean report and no report look
identical unless something is specifically checking.** So:

- a collector that has never produced a result is reported as *missing*, not
  clean;
- a result older than twice its own interval is *stale*, and stale is a failure;
- a check that could not run says so where its result would have been;
- degraded coverage names what specifically is invisible because of it — not
  "running unprivileged" but *which* checks that costs.

It also verifies the continuity chain end to end (service active, enabled,
linger on) and restates the limits that no amount of work here removes: this
samples rather than intercepts, it has no kernel component, and WSL is not a
security boundary.

## Screen, microphone and camera

Windows keeps a consent ledger for far more than the microphone and camera, and
the entries that matter most for surveillance were the ones nobody reads:
`graphicsCaptureProgrammatic` and `graphicsCaptureWithoutBorder` (screen
capture, the second without the recording border being shown),
`userNotificationListener` (reads every notification you receive),
`appDiagnostics` (reads other processes' state), `humanInterfaceDevice` and
`gazeInput`. Every capability Windows tracks is now read, each one with the
timestamps of every app that used it and whether it is in use *right now*.

Reading all of them means reading a lot of uninteresting ones — sixteen apps
check Wi-Fi state — so capabilities are tiered by what they actually expose.
Surveillance-relevant ones are reported per app and escalate if used in the last
24 hours; routine ones collapse to a single counted line, so the camera entry is
never buried under connectivity checks.

**The WSL side has no consent ledger at all**, and this is the gap WSLg opens:
every process in the distro gets an X11 display, a Wayland socket and a
PulseAudio server. X11 has no isolation between clients — anything that can open
`:0` can screenshot the whole desktop and read every keystroke sent to any
window, with no prompt and no record anywhere. So processes are mapped to the
display and audio sockets they hold open (via `/proc/net/unix` inode matching),
and the exposure itself is reported whether or not anyone is currently using it.

## Security of the dashboard itself

Binding to `127.0.0.1` is **not** sufficient on its own. A page you visit can
point a hostname it controls at `127.0.0.1` (DNS rebinding); the browser then
treats it as same-origin with the dashboard and can read every response — which
for this tool is a complete map of the machine's firewall gaps, processes and
external peers. So:

- the `Host` header is validated against an allowlist, which is what actually
  defeats rebinding;
- `/api/run` is POST-only and rejects cross-site requests via `Sec-Fetch-Site`;
- a strict CSP forbids the page from loading anything external.

## Finding commodity spyware

The sophisticated end of this needs a kernel driver to catch. The unsophisticated
end — which is most of it — leaves traces that `sentry spy` reads directly:

- **The capability ledger.** Windows records which application used the
  microphone, camera or location and exactly when, in
  `CapabilityAccessManager\ConsentStore`. Anything recording you through the
  normal APIs appears here, with timestamps.
- **Autostart signatures.** Monitoring tools must survive reboot, and almost
  none are signed by a recognizable publisher. Every autostart binary gets an
  Authenticode check; unsigned *and* in a user-writable directory is the shape
  that matters. Shortcuts are followed to their target first, since a `.lnk`
  carries no signature of its own.
- **Input devices.** Anything that can change your volume or type for you is
  either an HID consumer-control device or software holding an input hook. Both
  are enumerated, deduplicated per physical device.
- **The keyboard stack itself.** A keylogger that wants every keystroke
  regardless of focus has a small number of durable options, and each leaves an
  artifact: a **class filter driver** layered above `kbdclass` (which sees
  scancodes before any application does — the stock value is exactly
  `kbdclass`, so anything else is a discovery), a **lower** filter driver
  (closer to the hardware than anything else in the stack, and almost never
  legitimately occupied), a kernel **Scancode Map**, or an **IFEO debugger on an
  accessibility binary** like `sethc.exe`, which runs as SYSTEM from the logon
  screen before anyone signs in. Hardware is covered from the other side: an
  inline USB keylogger has to enumerate as a keyboard in order to pass
  keystrokes through, so both the currently-present keyboards and the machine's
  full USB enumeration history are checked — the latter catches a device that
  was attached once and taken away.

`sentry asep` covers the persistence surface past Run keys, which is where
anything trying to stay quiet actually lives: `AppInit_DLLs` and Image File
Execution Options debuggers (which inject into *other* processes rather than
starting one of their own), the Winlogon chain, Active Setup, per-user COM
hijacks, LSA packages, print monitors, netsh helpers, time providers, Explorer
extensions, the screensaver, and the `sethc.exe` / `utilman.exe` accessibility
backdoor that runs as SYSTEM from the logon screen before anyone signs in. It
also reads **UserAssist**, Windows' own record of which GUI programs were
launched and how often.

The rule throughout is to flag the **path, not the presence**. Every one of
these extension points is populated on a healthy machine — per-user COM
registrations are how OneDrive and Teams work. What matters is a registration
whose target sits in a world-writable directory, points at a scripting host, or
doesn't exist at all (an empty slot anything could fill).

## Why windows flash open and close at startup

A console window that appears for a fraction of a second is a process with a
console attached that exited immediately — `cmd.exe /c`, `wscript`, a `.bat`, or
PowerShell without `-WindowStyle Hidden`. Interval sampling will never reliably
catch one, so `sentry boot` does not try. It reconstructs the event afterwards
from Task Scheduler's operational log, the autostart inventory filtered to
entries that *would* show a window, and the Application log. Cross-referencing
those usually names the culprit outright.

If the task-history log is empty, enable it once in Task Scheduler → View →
Show All Tasks History, and the next boot will be fully reconstructable.

## How it decides something is unauthorized

Two independent signals combine into one severity, which is what keeps a
baseline system from either screaming at every software update or going quiet
when something hides behind an approved name:

1. **Drift** — the process fingerprint (executable + normalized command line +
   user) is not in the approved baseline. A new invocation of `/usr/bin/tail`
   is logged quietly; a new binary running out of a home or temp directory is
   not.
2. **Traits** — what the process looks like regardless of the baseline:
   encoded command lines, `curl | sh` pipelines, execution from world-writable
   directories, a deleted executable still running, a name that doesn't match
   its binary, listening on all interfaces, egress to public IPs.

A trait on an approved process still gets flagged.

## What it does not do

- It is **not** a kernel-level EDR. It samples on an interval, so a process
  that starts and exits between passes is missed. For gap-free Linux execution
  logging, pair it with `auditd`.
- Without an **elevated PowerShell**, Windows Defender exclusions and some
  service details are unreadable — the audit tells you when this happens rather
  than reporting a clean result it can't actually see.
- WSL is not a security boundary. Anything in WSL can read and write `/mnt/c`,
  and the Windows side can see into WSL. Treat findings on either host as
  findings about one machine.
- Presence of a remote-access agent (TeamViewer, AnyDesk, RMM tooling) is
  reported because it grants control — not because it is necessarily malicious.

## Files

| path | purpose |
|---|---|
| `sentry/collect_linux.py` | `/proc` walker: processes, fds, socket inode → connection |
| `sentry/collect_windows.py` | one-shot PowerShell collector over WSL interop |
| `sentry/detect.py` | trait rules, scoring, severity |
| `sentry/hidden.py` | cross-view enumeration, hidden-process detection |
| `sentry/spyware.py` | capability ledger, autostart signatures, input devices |
| `sentry/startup.py` | boot reconstruction, window-flash attribution |
| `sentry/firewall.py` | firewall posture, inbound rules and connections, logons |
| `sentry/asep.py` | autostart extensibility points, masquerade + parentage |
| `sentry/evasion.py` | kernel integrity, ADS, LNK abuse, dead-drop C2, Unicode |
| `sentry/coverage.py` | self-audit: collector health, blind spots, continuity |
| `sentry/control.py` | persistence / remote-access / defense audit |
| `sentry/monitor.py` | scan orchestration |
| `sentry/server.py` | scheduler + localhost dashboard server |
| `sentry/static/dashboard.html` | the dashboard, self-contained |
| `sentry/store.py` | SQLite baseline, peers, events |
| `sentry/cli.py` | command-line interface |

State lives in `~/.sentry/sentry.db`.
