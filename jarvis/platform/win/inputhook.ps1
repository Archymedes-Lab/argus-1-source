# Injected-keystroke monitor.
#
# Windows tags every keyboard and mouse event that did not come from real
# hardware. A low-level hook is the only place that tag is visible, so this
# installs one and watches for it.
#
# It deliberately does NOT record what was typed. A hook that logs arbitrary
# key values is a keylogger, and writing one to an unencrypted disk would be a
# worse problem than the one it detects. Only injected events are recorded in
# full (coarse class only), plus a short allowlist of real key families the
# operator asked to timestamp: =/+, /?, ./ >, and digits 0-9. Everything else
# is counted without identity.
param(
    [Parameter(Mandatory = $true)][string]$OutFile,
    [int]$HeartbeatSeconds = 60
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms

$src = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class JarvisInputHook
{
    // Flags on KBDLLHOOKSTRUCT / MSLLHOOKSTRUCT.
    const uint LLKHF_INJECTED           = 0x10;
    const uint LLKHF_LOWER_IL_INJECTED  = 0x02;

    const int WH_KEYBOARD_LL = 13;
    const int WH_MOUSE_LL    = 14;

    [StructLayout(LayoutKind.Sequential)]
    struct KBDLLHOOKSTRUCT {
        public uint vkCode; public uint scanCode; public uint flags;
        public uint time; public IntPtr dwExtraInfo;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct MSLLHOOKSTRUCT {
        public int x; public int y; public uint mouseData; public uint flags;
        public uint time; public IntPtr dwExtraInfo;
    }

    delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr SetWindowsHookEx(int id, HookProc fn, IntPtr mod, uint tid);
    [DllImport("user32.dll")]
    static extern IntPtr CallNextHookEx(IntPtr hk, int nCode, IntPtr wp, IntPtr lp);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string name);
    [DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);

    static IntPtr _kb, _ms;
    static HookProc _kbProc, _msProc;      // kept alive; a collected delegate crashes the hook
    static string _out;
    static readonly object _lock = new object();

    public static long RealKeys, InjectedKeys, RealClicks, InjectedClicks;
    public static long RealMoves, InjectedMoves;

    // Reset once per heartbeat and persisted as a single aggregate row. These
    // counters retain every typing event statistically without retaining a key
    // code or character, which keeps anomaly baselines useful and passwords
    // unrecoverable.
    public static long WindowRealKeys, WindowInjectedKeys;
    public static long WindowRealKeyGaps, WindowRealKeySub20, WindowRealKeySub8;
    public static long WindowCadRunMax;
    public static long WindowEqualsKeys, WindowSlashKeys, WindowPeriodKeys;
    public static long WindowDigitKeys;

    // Injected key-up events, and the count of distinct injected cursor-move
    // bursts (a run of injected moves with no >400 ms gap). Key-down alone
    // missed the release half of a synthetic keystroke; the burst count makes
    // a short reposition-and-click visible instead of being lost between the
    // every-250th-move samples.
    public static long InjectedKeyUps, InjectedMoveBursts;

    // Real-keystroke cadence. Hardware-level injection — a malicious HID
    // filter driver, a BadUSB device, an IOCTL straight to kbdclass — arrives
    // with no injected flag set and is otherwise identical to a person typing.
    // Timing is the only tell: humans do not hold a sub-8 ms inter-key gap, or
    // a long run of gaps all within 2 ms of each other.
    public static long RealKeyGaps, RealKeySub20, RealKeySub8, CadRunMax;
    static uint _lastRealKeyTick, _lastInjMoveTick, _lastVk;
    static long _lastGap = -1, _cadRun;

    // Input latency. Every low-level hook sits in a chain, and each one delays
    // every event until it returns. A cursor that feels slower than it used to
    // is the symptom a slow hook produces, so the delay is measured rather
    // than guessed: d.time is when the event was generated, GetTickCount is
    // now, and the difference is how long it spent traversing the chain ahead
    // of us. This hook is itself in that chain, so it measures its own cost
    // too — which is the honest thing for it to do.
    public static long LatSamples, LatTotalMs, LatMaxMs, LatOver50;

    [DllImport("kernel32.dll")]
    static extern uint GetTickCount();

    static void Latency(uint eventTime)
    {
        long d = (long)(GetTickCount() - eventTime);
        if (d < 0 || d > 10000) return;        // tick wrap or a stale event
        LatSamples++;
        LatTotalMs += d;
        if (d > LatMaxMs) LatMaxMs = d;
        if (d > 50) LatOver50++;
    }

    // A coarse bucket, recorded only for injected events. Enough to tell an
    // injected Enter from an injected character without ever reconstructing
    // what was typed.
    // Volume, media and launch keys. These carry no text -- knowing that the
    // volume-down key was pressed reveals nothing about what was typed -- so
    // unlike ordinary keystrokes they are recorded in full, injected or not.
    // That is the point: a control activation the user did not perform is only
    // visible if the real ones are logged too.
    public static string ControlClass(uint vk)
    {
        switch (vk) {
            case 0xAD: return "volume-mute";
            case 0xAE: return "volume-down";
            case 0xAF: return "volume-up";
            case 0xB0: return "media-next";
            case 0xB1: return "media-prev";
            case 0xB2: return "media-stop";
            case 0xB3: return "media-play-pause";
            case 0xB4: return "launch-mail";
            case 0xB5: return "launch-media-select";
            case 0xB6: return "launch-app1";
            case 0xB7: return "launch-app2";
            case 0xA6: return "browser-back";
            case 0xA7: return "browser-forward";
            case 0xA8: return "browser-refresh";
            case 0xA9: return "browser-stop";
            case 0xAA: return "browser-search";
            case 0xAB: return "browser-favorites";
            case 0xAC: return "browser-home";
            default:   return "";
        }
    }

    // Counted separately so a control activation is never lost inside the
    // aggregate keystroke totals.
    public static long ControlKeys, ControlKeysInjected;
    static uint _lastCtrlTick;

    // Milliseconds since the last control key of any kind, capped. The volume
    // sampler uses this to decide whether a level change had a key behind it.
    public static long MsSinceControlKey()
    {
        if (_lastCtrlTick == 0) return 999999;
        long d = (long)unchecked((uint)Environment.TickCount - _lastCtrlTick);
        return d < 0 ? 999999 : d;
    }

    static string KeyClass(uint vk)
    {
        if (vk == 0xBB) return "equals-plus";       // = / + physical key
        if (vk == 0xBF || vk == 0x6F) return "slash-question";
        if (vk == 0xBE || vk == 0x6E) return "period-greater";
        // Top-row and numpad digits. Named individually so a phantom "3"
        // can be located; not a general character log.
        if (vk >= 0x30 && vk <= 0x39) return "digit-" + (vk - 0x30);
        if (vk >= 0x60 && vk <= 0x69) return "digit-" + (vk - 0x60);
        if (vk >= 0x70 && vk <= 0x87) return "function";
        if (vk == 0x0D) return "enter";
        if (vk == 0x09) return "tab";
        if (vk == 0x1B) return "escape";
        if (vk == 0x08) return "backspace";
        if (vk >= 0x21 && vk <= 0x28) return "navigation";
        if (vk == 0x5B || vk == 0x5C) return "windows-key";
        if (vk >= 0x10 && vk <= 0x12) return "modifier";
        if (vk == 0x11 || vk == 0xA2 || vk == 0xA3) return "control";
        return "character";
    }

    static bool IsDigitClass(string cls)
    {
        return cls.Length == 7 && cls.StartsWith("digit-")
            && cls[6] >= '0' && cls[6] <= '9';
    }

    public static string Foreground()
    {
        try {
            uint pid;
            GetWindowThreadProcessId(GetForegroundWindow(), out pid);
            if (pid == 0) return "";
            return Process.GetProcessById((int)pid).ProcessName + ":" + pid;
        } catch { return ""; }
    }

    // Timing analysis for genuine (un-flagged) keystrokes. See the cadence
    // counters above for why this is the only signal for driver-level input.
    static void Cadence(uint eventTime, uint vk)
    {
        if (vk == 0xBB) WindowEqualsKeys++;
        if (vk == 0xBF || vk == 0x6F) WindowSlashKeys++;
        if (vk == 0xBE || vk == 0x6E) WindowPeriodKeys++;
        if ((vk >= 0x30 && vk <= 0x39) || (vk >= 0x60 && vk <= 0x69))
            WindowDigitKeys++;
        if (_lastRealKeyTick != 0) {
            long gap = (long)(eventTime - _lastRealKeyTick);
            // Key auto-repeat (a held key) is regular and fast but benign, so
            // it is counted as a gap but kept out of the "too fast" and
            // "robotically even" tallies.
            bool repeat = (vk == _lastVk && gap >= 0 && gap < 60);
            if (gap >= 0 && gap < 5000) {
                RealKeyGaps++;
                WindowRealKeyGaps++;
                if (!repeat && gap < 20) RealKeySub20++;
                if (!repeat && gap < 8)  RealKeySub8++;
                if (!repeat && gap < 20) WindowRealKeySub20++;
                if (!repeat && gap < 8)  WindowRealKeySub8++;
                if (!repeat && _lastGap >= 0 && gap < 120
                        && Math.Abs(gap - _lastGap) <= 2) {
                    _cadRun++;
                    if (_cadRun > CadRunMax) CadRunMax = _cadRun;
                    if (_cadRun > WindowCadRunMax) WindowCadRunMax = _cadRun;
                } else if (!repeat) {
                    _cadRun = 0;
                }
                _lastGap = gap;
            } else {
                _cadRun = 0; _lastGap = -1;
            }
        }
        _lastRealKeyTick = eventTime;
        _lastVk = vk;
    }

    static void Write(string kind, uint flags, string cls)
    {
        Write(kind, flags, cls, true);
    }

    static void Write(string kind, uint flags, string cls, bool injected)
    {
        var line = new StringBuilder();
        line.Append("{\"ts\":").Append(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        line.Append(",\"kind\":\"").Append(kind).Append("\"");
        line.Append(",\"injected\":").Append(injected ? 1 : 0);
        line.Append(",\"lower_il\":").Append((flags & LLKHF_LOWER_IL_INJECTED) != 0 ? 1 : 0);
        line.Append(",\"class\":\"").Append(cls).Append("\"");
        line.Append(",\"fg\":\"").Append(Foreground().Replace("\"", "")).Append("\"}");
        lock (_lock) {
            try { File.AppendAllText(_out, line.ToString() + Environment.NewLine); }
            catch { }
        }
    }

    // Used by the volume sampler below. Goes through the same lock so a state
    // line can never interleave with a key line mid-write.
    public static void WriteState(string json)
    {
        lock (_lock) {
            try { File.AppendAllText(_out, json + Environment.NewLine); }
            catch { }
        }
    }

    static IntPtr KbProc(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0) {
            var d = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));
            int msg = (int)wParam;
            bool down = (msg == 0x0100 || msg == 0x0104);
            bool up   = (msg == 0x0101 || msg == 0x0105);
            bool injected = (d.flags & LLKHF_INJECTED) != 0;
            if (down || up) Latency(d.time);
            if (down) {
                string ctl = ControlClass(d.vkCode);
                if (ctl.Length > 0) {
                    ControlKeys++;
                    if (injected) ControlKeysInjected++;
                    _lastCtrlTick = (uint)Environment.TickCount;
                    Write("control-key", d.flags, ctl, injected);
                }
                if (injected) {
                    InjectedKeys++;
                    WindowInjectedKeys++;
                    Write("key", d.flags, KeyClass(d.vkCode));
                } else {
                    RealKeys++;
                    WindowRealKeys++;
                    Cadence(d.time, d.vkCode);
                    // Watched real-key families are already counted in
                    // aggregate. Timestamping them adds resolution, not a
                    // general content log: a phantom "." or "3" gets a time,
                    // a foreground window and a real/injected verdict, and
                    // letters / other symbols stay anonymous counts only.
                    string pc = KeyClass(d.vkCode);
                    if (pc == "period-greater" || pc == "slash-question" ||
                        pc == "equals-plus") {
                        Write("punct-key", d.flags, pc, false);
                    } else if (IsDigitClass(pc)) {
                        Write("digit-key", d.flags, pc, false);
                    }
                }
            } else if (up && injected) {
                InjectedKeyUps++;
            }
        }
        return CallNextHookEx(_kb, nCode, wParam, lParam);
    }

    static IntPtr MsProc(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0) {
            var d = (MSLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(MSLLHOOKSTRUCT));
            int msg = (int)wParam;
            bool click = (msg == 0x0201 || msg == 0x0204);
            bool move  = (msg == 0x0200);
            bool inj   = (d.flags & 0x01) != 0;       // LLMHF_INJECTED

            if (move) {
                Latency(d.time);
                if (inj) {
                    InjectedMoves++;
                    // Movement is continuous, so a line per event would be
                    // megabytes. Write one at the start of every burst — a run
                    // broken by a >400 ms gap — so a brief synthetic reposition
                    // is caught, not just multiples of 250. Keep the every-250
                    // sample as a heartbeat inside a long continuous burst.
                    long since = _lastInjMoveTick == 0
                        ? 999999 : (long)(d.time - _lastInjMoveTick);
                    if (since > 400) {
                        InjectedMoveBursts++;
                        Write("move", d.flags, "cursor");
                    } else if (InjectedMoves % 250 == 0) {
                        Write("move", d.flags, "cursor");
                    }
                    _lastInjMoveTick = d.time;
                } else {
                    RealMoves++;
                }
            } else if (click) {
                Latency(d.time);
                if (inj) {
                    InjectedClicks++;
                    Write("click", d.flags, "button");
                } else {
                    RealClicks++;
                }
            }
        }
        return CallNextHookEx(_ms, nCode, wParam, lParam);
    }

    public static void Start(string outFile)
    {
        _out = outFile;
        _kbProc = KbProc;
        _msProc = MsProc;
        IntPtr mod = GetModuleHandle(null);
        _kb = SetWindowsHookEx(WH_KEYBOARD_LL, _kbProc, mod, 0);
        _ms = SetWindowsHookEx(WH_MOUSE_LL,    _msProc, mod, 0);
        if (_kb == IntPtr.Zero) throw new Exception("SetWindowsHookEx (keyboard) failed");
    }

    public static string Counters()
    {
        long avg = LatSamples > 0 ? LatTotalMs / LatSamples : 0;
        return "{\"real_keys\":" + RealKeys + ",\"injected_keys\":" + InjectedKeys +
               ",\"real_clicks\":" + RealClicks + ",\"injected_clicks\":" + InjectedClicks +
               ",\"real_moves\":" + RealMoves + ",\"injected_moves\":" + InjectedMoves +
               ",\"injected_keyups\":" + InjectedKeyUps +
               ",\"injected_move_bursts\":" + InjectedMoveBursts +
               ",\"real_key_gaps\":" + RealKeyGaps +
               ",\"real_key_sub20\":" + RealKeySub20 +
               ",\"real_key_sub8\":" + RealKeySub8 +
               ",\"cad_run_max\":" + CadRunMax +
               ",\"lat_avg_ms\":" + avg + ",\"lat_max_ms\":" + LatMaxMs +
               ",\"lat_over50\":" + LatOver50 + ",\"lat_samples\":" + LatSamples + "}";
    }

    public static string TakeWindowCounters()
    {
        lock (_lock) {
            string value = "{\"real_keys\":" + WindowRealKeys +
                ",\"injected_keys\":" + WindowInjectedKeys +
                ",\"real_key_gaps\":" + WindowRealKeyGaps +
                ",\"real_key_sub20\":" + WindowRealKeySub20 +
                ",\"real_key_sub8\":" + WindowRealKeySub8 +
                ",\"cad_run_max\":" + WindowCadRunMax +
                ",\"equals_keys\":" + WindowEqualsKeys +
                ",\"slash_keys\":" + WindowSlashKeys +
                ",\"period_keys\":" + WindowPeriodKeys +
                ",\"digit_keys\":" + WindowDigitKeys + "}";
            WindowRealKeys = WindowInjectedKeys = 0;
            WindowRealKeyGaps = WindowRealKeySub20 = WindowRealKeySub8 = 0;
            WindowCadRunMax = 0;
            WindowEqualsKeys = WindowSlashKeys = WindowPeriodKeys = 0;
            WindowDigitKeys = 0;
            return value;
        }
    }
}
'@

Add-Type -TypeDefinition $src -ReferencedAssemblies System.Windows.Forms, System.Drawing

# Record our own pid. Matching on command lines to find this process does not
# work: the query itself contains the script name, so it matches itself and the
# helper looks like it is already running when it never started.
[JarvisInputHook]::Start($OutFile)

# Written only after the hook is actually installed, so the pid file's presence
# means "watching", not merely "process started". Start() throws if
# SetWindowsHookEx fails, and in that case no pid file appears at all.
$pidFile = [IO.Path]::ChangeExtension($OutFile, '.pid')
Set-Content -Path $pidFile -Value $PID -Encoding ascii

# A heartbeat proves the monitor is alive. Without it, a hook that silently
# died and a genuinely quiet keyboard look identical.
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = $HeartbeatSeconds * 1000
# The heartbeat also says which session this helper and the desktop are in: a
# hook outside the desktop session is alive and counting nothing.
$ownSession = (Get-Process -Id $PID).SessionId
$timer.Add_Tick({
    $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $c  = [JarvisInputHook]::Counters()
    $w  = [JarvisInputHook]::TakeWindowCounters()
    $desk = (Get-Process explorer -EA SilentlyContinue | Select-Object -First 1).SessionId
    if ($null -eq $desk) { $desk = -1 }
    Add-Content -Path $OutFile -Value ("{""ts"":$ts,""kind"":""heartbeat"",""pid"":$PID,""session"":$ownSession,""desktop"":$desk,""counters"":$c,""window"":$w}")
})
$timer.Start()

# A faster, contentless liveness beat. The watchdog on the WSL side reads only
# this file's mtime — a local stat, no interop — so a dead or wedged helper is
# caught within one watchdog interval instead of waiting a full heartbeat. If
# the message loop stalls, this timer stops too, which is the point.
$aliveFile = [IO.Path]::ChangeExtension($OutFile, '.alive')
$writePulse = { try { [IO.File]::WriteAllText($aliveFile,
    ("" + $PID + ":" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())) } catch { } }
& $writePulse
$pulse = New-Object System.Windows.Forms.Timer
$pulse.Interval = 10000
$pulse.Add_Tick($writePulse)
$pulse.Start()

# --- audio state sampler ------------------------------------------------------
# The keyboard hook sees volume keys. It does not see everything that can change
# the volume: a consumer-control HID often delivers WM_APPCOMMAND straight to the
# foreground window without traversing WH_KEYBOARD_LL, and any process can move
# the master level through CoreAudio with no input event at all.
#
# So the level itself is sampled, and each change is logged with how long ago a
# control key was seen. A change with no key behind it is the signal worth
# having: something moved the volume that was not the keyboard in front of you.
$audioSrc = @'
using System;
using System.Runtime.InteropServices;
[Guid("5CDF2C82-841E-4546-9722-0CF74078229A"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioEndpointVolume {
  int RegisterControlChangeNotify(IntPtr n);
  int UnregisterControlChangeNotify(IntPtr n);
  int GetChannelCount(out uint c);
  int SetMasterVolumeLevel(float f, ref Guid g);
  int SetMasterVolumeLevelScalar(float f, ref Guid g);
  int GetMasterVolumeLevel(out float f);
  int GetMasterVolumeLevelScalar(out float f);
  int SetChannelVolumeLevel(uint i, float f, ref Guid g);
  int SetChannelVolumeLevelScalar(uint i, float f, ref Guid g);
  int GetChannelVolumeLevel(uint i, out float f);
  int GetChannelVolumeLevelScalar(uint i, out float f);
  int SetMute(bool m, ref Guid g);
  int GetMute(out bool m);
}
[Guid("D666063F-1587-4E43-81F1-B948E807363F"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDevice {
  int Activate(ref Guid iid, int ctx, IntPtr p, [MarshalAs(UnmanagedType.IUnknown)] out object o);
}
[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDeviceEnumerator {
  int EnumAudioEndpoints(int f, int m, out IntPtr c);
  int GetDefaultAudioEndpoint(int flow, int role, out IMMDevice d);
}
[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumeratorComObject { }
public class JarvisAudio {
  static IAudioEndpointVolume Endpoint() {
    IMMDevice dev;
    ((IMMDeviceEnumerator)new MMDeviceEnumeratorComObject()).GetDefaultAudioEndpoint(0, 1, out dev);
    Guid iid = typeof(IAudioEndpointVolume).GUID;
    object o; dev.Activate(ref iid, 23, IntPtr.Zero, out o);
    return (IAudioEndpointVolume)o;
  }
  public static int Level() { float f; Endpoint().GetMasterVolumeLevelScalar(out f); return (int)Math.Round(f * 100); }
  public static bool Muted() { bool m; Endpoint().GetMute(out m); return m; }
}
'@
$audioOk = $true
try { Add-Type -TypeDefinition $audioSrc -ErrorAction Stop } catch { $audioOk = $false }

if ($audioOk) {
    $script:lastVol = -1
    $script:lastMute = $null
    $sampleAudio = {
        try {
            $v = [JarvisAudio]::Level(); $m = [JarvisAudio]::Muted()
        } catch { return }
        if ($script:lastVol -lt 0) { $script:lastVol = $v; $script:lastMute = $m; return }
        if ($v -eq $script:lastVol -and $m -eq $script:lastMute) { return }
        $gap = [JarvisInputHook]::MsSinceControlKey()
        # 1500 ms is generous for the gap between a key-down and the level
        # actually moving; beyond it, no key explains the change.
        $keyed = if ($gap -le 1500) { 1 } else { 0 }
        $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $json = '{"ts":' + $ts + ',"kind":"control-state","control":"volume"' +
                ',"from":' + $script:lastVol + ',"to":' + $v +
                ',"muted":' + $(if ($m) { 1 } else { 0 }) +
                ',"was_muted":' + $(if ($script:lastMute) { 1 } else { 0 }) +
                ',"keyed":' + $keyed + ',"key_gap_ms":' + $gap +
                ',"fg":"' + ([JarvisInputHook]::Foreground() -replace '"','') + '"}'
        [JarvisInputHook]::WriteState($json)
        $script:lastVol = $v; $script:lastMute = $m
    }
    & $sampleAudio
    $audioTimer = New-Object System.Windows.Forms.Timer
    # Fast enough that a press-and-hold ramp is not collapsed into one jump,
    # cheap enough to be invisible: two COM reads per tick.
    $audioTimer.Interval = 1000
    $audioTimer.Add_Tick($sampleAudio)
    $audioTimer.Start()
}

[System.Windows.Forms.Application]::Run()
