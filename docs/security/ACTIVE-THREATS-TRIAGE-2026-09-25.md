# Active threats triage — 2026-09-25

At 2026-09-24 21:35 UTC the running sealed release reported host score 66,
100% scored collector coverage, and Active threats 17. The `input` receipt had
two highs and one medium. This is a measured starting point, not a verdict that
the host is compromised or clean.

## Confirmed duplicate and proportionate classification

The three `VK_0xB3` injected key rows at 2026-09-24 21:22–21:23 local each
have an empty character, scan zero, and a same-second `media-play-pause`
control row with matching foreground and integrity. Microsoft defines VK 0xB3
as Play/Pause. The collector had charged the key and control views as separate
high findings. A read-only replay of the new code over the production database
yielded low duplicate inventory, medium unknown-sender media control, and the
pre-existing medium unkeyed volume finding. No raw event was changed.

Release `sha256:0c993d9a592342106adaf379a40985a86cd844ba96ef6a99c7915fd910be1c4d`
was installed from the narrow reviewed stage with `--skip-tests` after 1,505
local unit tests, 45 focused tests, Ruff and `git diff --check` passed. On the
running service, `/api/health` reported healthy, ready and protection healthy;
fresh `input` and `netwatch` receipts reported no errors. The measured score
moved from 66 to 67 at 100% scored coverage, with Active threats from 17 to 21.
The fresh `input` receipt has two mediums and three lows, rather than two highs.
This is post-switch evidence, not a claim of sustained health. Jev favored exact event
pairing (Choice confidence 1.0), medium for this media-only case (Choice 1.0),
and named the unidentified sender as the remaining blind spot. These are
advisory judgments; the row pairing, regression cases, and live readback govern.

## High findings that remain unresolved

| Collector | Evidence and present conclusion | Proof needed before lowering |
| --- | --- | --- |
| `intrusion` (two highs) | PowerShell history contains two JARVIS Sysmon policy-repair command shapes. History proves text was entered, not which script bytes ran or whether the repair completed. | Correlate exact command line and process identity with protected policy-repair receipt, actual script hash, and effective Sysmon readback. Preserve the history. |
| `sysmon_linux` | A log/history deletion names `dmesg.4.gz`; the prior boot's source proof has rolled out of the memory-only journal. | Durable, independent maintenance provenance for that event. Do not infer innocence from the missing record. |
| `sysmon_linux` | Execution came from a world-writable `/tmp` build path. The exact artifact and source directory are gone. | An event-time signed test execution identity and artifact hash. Current path name or later source code is insufficient. Future controlled builds must use private workspaces. |

The network collector still reports an unfamiliar same-SSID access point as
high. Repeated SSID/BSSID sightings are not proof of AP ownership; the deployed
collector keeps them as observations without silently learning trust. A
separate change under review uses recent WPA3/cipher, gateway and DNS agreement
to classify a coherent roam as medium while preserving unknown AP ownership;
it is not yet deployed. An operator-reviewed independent AP identity is still
needed to call a BSSID verified.

Other current Active-threat mediums include WSL VM-root listener ownership
that this distro cannot see, executable-memory and mitigation posture,
outbound connections with no verified process-to-destination provenance, and
Sysmon startup/raw-access visibility gaps. They require sensor or artifact
proof, not acknowledgements or score-weight changes.

With Active threats at 17 and Network at 53, even making the other five areas
100 would produce only `(17 + 53 + 500) / 7 = 81.4`. Reaching 90 requires
those highs to expire from their documented live window or be resolved by
independent evidence, as well as real reductions in privacy and persistence
debt. A score increase from stale collectors or suppressed history would fail
the Maximum Assurance directive.
