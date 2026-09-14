# Computer control monitoring

JARVIS observes selected control surfaces. It does not observe every control or
prove the absence of intrusion. A fresh collector timestamp is not proof that
all of its subchecks succeeded; review visibility findings as well.

| Surface | Observation | Remaining gap |
| --- | --- | --- |
| Brightness and display | Windows brightness provider and display driver state every 5 minutes | Physical button source, rapid changes, external monitor OSD and unsupported displays |
| Keyboard, mouse, HID | Device inventory; existing injected-input hook and watchdog | Firmware-origin input and secure-desktop attribution are not established |
| Camera, audio, Bluetooth | Device presence/status inventory; separate capability checks | No content recording or complete attribution of every device control change |
| Remote control | Existing control, backdoor, firewall and startup collectors | Protected Windows processes require additional privileges |
| App traffic | TCP/UDP endpoint samples every 2 minutes; bounded history | Short-lived traffic and packet payloads; UDP direction unknown |
| Windows firewall | Profile/rule checks and bounded log-tail summaries | Allowed logging must be enabled and log readable to record successful connections |
| Browsers and apps | Unsafe launch flags and selected browser registry policies | Effective policy UI, every extension action, and app-internal controls are not fully covered |
| Process concealment | Daily deep PID/API/socket cross-view sweep | Kernel compromise can falsify userland views; inaccessible processes remain unqualified |
| Firmware and physical controls | No comprehensive sensor | BIOS/UEFI, monitor firmware, physical buttons, and devices outside OS telemetry |

## Brightness verification

The first service-side sample on this run reported 100% and active=True.
This confirms a readable brightness provider, not that the brightness key works.
Identify the affected key/slider/button and compare samples before and after
using it. Brightness changes are low-severity observations, never intrusion
claims by themselves.

## Deep scan interpretation

The first deep sweep found a detector defect: inode-keyed socket data collapsed
TIME_WAIT rows (inode zero), manufacturing hidden-port alerts. The corrected
scanner retains all TCP rows, refreshes the table, and repeats failed binds.
Any remaining discrepancy is an investigation lead, not proven concealment.

Windows Temp contains two distinct unsigned-file leads in the earlier snapshot
(one JavaScript bundle and a Nova installer); duplicate findings are not four
distinct files. An executable-memory heuristic and a raw-device event with an
unspecified target likewise require corroboration. No file was executed,
deleted, uploaded, or declared safe on the basis of its name.

Windows brightness provider reference:
[Microsoft WmiMonitorBrightness](https://learn.microsoft.com/en-us/windows/win32/wmicoreprov/wmimonitorbrightness).
