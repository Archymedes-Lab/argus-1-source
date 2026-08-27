# Injected-keystroke monitor.
#
# Windows tags every keyboard and mouse event that did not come from real
# hardware. A low-level hook is the only place that tag is visible, so this
# installs one and watches for it.
#
# It deliberately does NOT record what was typed. A hook that logs key values
# is a keylogger, and writing one to an unencrypted disk would be a worse
# problem than the one it detects. Only injected events are recorded, and only
# as metadata: when, which flags, a coarse key class, and which window had
# focus. Real keystrokes are counted and nothing more.
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

public static class SentryInputHook
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
    static string KeyClass(uint vk)
    {
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

    static string Foreground()
    {
        try {
            uint pid;
            GetWindowThreadProcessId(GetForegroundWindow(), out pid);
            if (pid == 0) return "";
            return Process.GetProcessById((int)pid).ProcessName;
        } catch { return ""; }
    }

    static void Write(string kind, uint flags, string cls)
    {
        var line = new StringBuilder();
        line.Append("{\"ts\":").Append(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        line.Append(",\"kind\":\"").Append(kind).Append("\"");
        line.Append(",\"injected\":1");
        line.Append(",\"lower_il\":").Append((flags & LLKHF_LOWER_IL_INJECTED) != 0 ? 1 : 0);
        line.Append(",\"class\":\"").Append(cls).Append("\"");
        line.Append(",\"fg\":\"").Append(Foreground().Replace("\"", "")).Append("\"}");
        lock (_lock) {
            try { File.AppendAllText(_out, line.ToString() + Environment.NewLine); }
            catch { }
        }
    }

    static IntPtr KbProc(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0) {
            var d = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));
            bool down = ((int)wParam == 0x0100 || (int)wParam == 0x0104);
            if (down) {
                Latency(d.time);
                if ((d.flags & LLKHF_INJECTED) != 0) {
                    InjectedKeys++;
                    Write("key", d.flags, KeyClass(d.vkCode));
                } else {
                    RealKeys++;
                }
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
                    // Movement is continuous, so writing a line per event would
                    // produce megabytes. One line per burst is enough to say
                    // "something moved the cursor, here, then".
                    if (InjectedMoves == 1 || InjectedMoves % 250 == 0)
                        Write("move", d.flags, "cursor");
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
               ",\"lat_avg_ms\":" + avg + ",\"lat_max_ms\":" + LatMaxMs +
               ",\"lat_over50\":" + LatOver50 + ",\"lat_samples\":" + LatSamples + "}";
    }
}
'@

Add-Type -TypeDefinition $src -ReferencedAssemblies System.Windows.Forms, System.Drawing

# Record our own pid. Matching on command lines to find this process does not
# work: the query itself contains the script name, so it matches itself and the
# helper looks like it is already running when it never started.
[SentryInputHook]::Start($OutFile)

# Written only after the hook is actually installed, so the pid file's presence
# means "watching", not merely "process started". Start() throws if
# SetWindowsHookEx fails, and in that case no pid file appears at all.
$pidFile = [IO.Path]::ChangeExtension($OutFile, '.pid')
Set-Content -Path $pidFile -Value $PID -Encoding ascii

# A heartbeat proves the monitor is alive. Without it, a hook that silently
# died and a genuinely quiet keyboard look identical.
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = $HeartbeatSeconds * 1000
$timer.Add_Tick({
    $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $c  = [SentryInputHook]::Counters()
    Add-Content -Path $OutFile -Value ("{""ts"":$ts,""kind"":""heartbeat"",""counters"":$c}")
})
$timer.Start()

[System.Windows.Forms.Application]::Run()
