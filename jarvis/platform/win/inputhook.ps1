# Injected-keystroke monitor.
#
# Windows tags every keyboard and mouse event that did not come from real
# hardware. A low-level hook is the only place that tag is visible, so this
# installs one and watches for it.
#
# It deliberately does NOT record what the person at the keyboard typed. A hook
# that logs arbitrary hardware key values is a keylogger, and writing one to an
# unencrypted disk would be a worse problem than the one it detects. Real keys
# are counted without identity, apart from a short allowlist of families the
# operator asked to timestamp: =/+, /?, ./ >, and digits 0-9.
#
# Injected keys are the opposite case: nobody typed them, and "which key, from
# where, into what" is the whole investigation. Each one is recorded forensically
# — virtual key, scan code, the exact character it produces under the focused
# window's layout, modifiers, raw flags, dwExtraInfo, millisecond time, the
# focused window and control — and every burst gets a context record naming the
# lower-integrity and just-started processes that could have sent it.
#
# The one exception is a long printable burst: that is what a password manager's
# auto-type looks like, so past -RedactBurstOver printable characters the text
# is replaced by its length and composition. A lone phantom character is always
# kept exactly. -RedactBurstOver -1 disables redaction.
param(
    [Parameter(Mandatory = $true)][string]$OutFile,
    [int]$HeartbeatSeconds = 60,
    [int]$RedactBurstOver = 6
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms

$src = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

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
        if (vk == 0xE7) return "unicode-packet";    // SendInput KEYEVENTF_UNICODE
        if (vk == 0xE5) return "ime-processkey";
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

    // ---- forensic capture of injected keys -----------------------------------
    //
    // An injected key is software typing, not the person, so it is recorded in
    // full. The hook callback itself only copies the raw event and the facts
    // that are gone a moment later (modifier state, the layout and window in
    // focus); everything slow — process names, integrity levels, candidate
    // injectors, disk writes — happens on a background writer, because Windows
    // silently removes a low-level hook that takes too long to return.

    [DllImport("user32.dll")]
    static extern IntPtr GetKeyboardLayout(uint tid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int ToUnicodeEx(uint vk, uint scan, byte[] state, StringBuilder buf,
                                  int cch, uint flags, IntPtr hkl);
    [DllImport("user32.dll")]
    static extern short GetAsyncKeyState(int vk);
    [DllImport("user32.dll")]
    static extern short GetKeyState(int vk);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int GetKeyNameText(int lParam, StringBuilder sb, int n);
    // Reads the cached title without sending WM_GETTEXT, so a hung target
    // window cannot stall the hook.
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int InternalGetWindowText(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int GetClassName(IntPtr h, StringBuilder sb, int n);
    [StructLayout(LayoutKind.Sequential)]
    struct RECT { public int l, t, r, b; }
    [StructLayout(LayoutKind.Sequential)]
    struct GUITHREADINFO {
        public int cbSize; public uint flags;
        public IntPtr hwndActive, hwndFocus, hwndCapture, hwndMenuOwner, hwndMoveSize, hwndCaret;
        public RECT rcCaret;
    }
    [DllImport("user32.dll")]
    static extern bool GetGUIThreadInfo(uint tid, ref GUITHREADINFO g);
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll")]
    static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr tok);
    [DllImport("advapi32.dll")]
    static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr buf, int len, out int ret);
    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthority(IntPtr sid, uint n);
    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern bool QueryFullProcessImageName(IntPtr p, int flags, StringBuilder sb, ref int size);
    [DllImport("kernel32.dll")]
    static extern bool GetProcessTimes(IntPtr p, out long create, out long exit,
                                       out long kernel, out long user);
    [DllImport("kernel32.dll")]
    static extern bool ProcessIdToSessionId(uint pid, out uint session);

    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint TOKEN_QUERY = 0x8;
    const int TokenIntegrityLevel = 25, TokenIsAppContainer = 29;

    class InjEvent {
        public long Ms, SinceRealKey, SinceRealClick, SinceRealMove;
        public bool Down;
        public uint Vk, Scan, Flags, Tick, FgPid, FgTid;
        public ulong Extra;
        public string Chr = "", Mods = "", Title = "", WinClass = "", FocusClass = "";
    }

    static readonly ConcurrentQueue<InjEvent> _inj = new ConcurrentQueue<InjEvent>();
    static int _redactOver = 6;
    public static long InjDropped;
    static long _lastRealKeyMs, _lastRealClickMs, _lastRealMoveMs;

    static long NowMs() { return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); }

    static long Since(long now, long then) { return then == 0 ? -1 : now - then; }

    static bool Held(int vk) { return (GetAsyncKeyState(vk) & 0x8000) != 0; }

    static string Mods()
    {
        var m = new List<string>();
        if (Held(0x10)) m.Add("shift");
        if (Held(0x11)) m.Add("ctrl");
        if (Held(0x12)) m.Add("alt");
        if (Held(0x5B) || Held(0x5C)) m.Add("win");
        if ((GetKeyState(0x14) & 1) != 0) m.Add("capslock");
        return string.Join("+", m);
    }

    // The character this key produces in the focused window, under that
    // window's own keyboard layout and the modifiers held right now. Flag 0x4
    // tells ToUnicodeEx not to touch the kernel keyboard state, so translating
    // here cannot eat a dead key the user is composing.
    static string CharFor(uint vk, uint scan, uint fgTid)
    {
        // VK_PACKET is SendInput with KEYEVENTF_UNICODE: there is no key at all,
        // and the scan code field carries the UTF-16 unit itself.
        if (vk == 0xE7) return ((char)(scan & 0xFFFF)).ToString();
        try {
            var state = new byte[256];
            if (Held(0x10)) state[0x10] = 0x80;
            if (Held(0x11)) state[0x11] = 0x80;
            if (Held(0x12)) state[0x12] = 0x80;
            if ((GetKeyState(0x14) & 1) != 0) state[0x14] = 0x01;
            var sb = new StringBuilder(16);
            int n = ToUnicodeEx(vk, scan, state, sb, sb.Capacity, 0x4, GetKeyboardLayout(fgTid));
            string r = sb.ToString();
            if (n > 0) return r.Length > n ? r.Substring(0, n) : r;
            if (n < 0) return "dead:" + (r.Length > 0 ? r.Substring(0, 1) : "");
        } catch { }
        return "";
    }

    static void Capture(KBDLLHOOKSTRUCT d, bool down)
    {
        // A runaway injector must not grow memory without bound; the counters
        // above still count every event, and the drop is reported.
        if (_inj.Count > 20000) { Interlocked.Increment(ref InjDropped); return; }
        var e = new InjEvent();
        e.Ms = NowMs(); e.Down = down;
        e.Vk = d.vkCode; e.Scan = d.scanCode; e.Flags = d.flags; e.Tick = d.time;
        e.Extra = unchecked((ulong)d.dwExtraInfo.ToInt64());
        e.SinceRealKey = Since(e.Ms, _lastRealKeyMs);
        e.SinceRealClick = Since(e.Ms, _lastRealClickMs);
        e.SinceRealMove = Since(e.Ms, _lastRealMoveMs);
        try {
            IntPtr fg = GetForegroundWindow();
            e.FgTid = GetWindowThreadProcessId(fg, out e.FgPid);
            var sb = new StringBuilder(256);
            InternalGetWindowText(fg, sb, sb.Capacity); e.Title = sb.ToString();
            sb.Length = 0; GetClassName(fg, sb, sb.Capacity); e.WinClass = sb.ToString();
            var gi = new GUITHREADINFO(); gi.cbSize = Marshal.SizeOf(typeof(GUITHREADINFO));
            if (GetGUIThreadInfo(e.FgTid, ref gi) && gi.hwndFocus != IntPtr.Zero) {
                sb.Length = 0; GetClassName(gi.hwndFocus, sb, sb.Capacity);
                e.FocusClass = sb.ToString();
            }
        } catch { }
        e.Mods = Mods();
        if (down) e.Chr = CharFor(d.vkCode, d.scanCode, e.FgTid);
        _inj.Enqueue(e);
    }

    static string VkName(uint vk)
    {
        if ((vk >= 0x41 && vk <= 0x5A) || (vk >= 0x30 && vk <= 0x39)) return "VK_" + (char)vk;
        if (vk >= 0x60 && vk <= 0x69) return "VK_NUMPAD" + (vk - 0x60);
        if (vk >= 0x70 && vk <= 0x87) return "VK_F" + (vk - 0x6F);
        switch (vk) {
            case 0x08: return "VK_BACK";     case 0x09: return "VK_TAB";
            case 0x0D: return "VK_RETURN";   case 0x10: return "VK_SHIFT";
            case 0x11: return "VK_CONTROL";  case 0x12: return "VK_MENU";
            case 0x13: return "VK_PAUSE";    case 0x14: return "VK_CAPITAL";
            case 0x1B: return "VK_ESCAPE";   case 0x20: return "VK_SPACE";
            case 0x21: return "VK_PRIOR";    case 0x22: return "VK_NEXT";
            case 0x23: return "VK_END";      case 0x24: return "VK_HOME";
            case 0x25: return "VK_LEFT";     case 0x26: return "VK_UP";
            case 0x27: return "VK_RIGHT";    case 0x28: return "VK_DOWN";
            case 0x2C: return "VK_SNAPSHOT"; case 0x2D: return "VK_INSERT";
            case 0x2E: return "VK_DELETE";   case 0x5B: return "VK_LWIN";
            case 0x5C: return "VK_RWIN";     case 0x5D: return "VK_APPS";
            case 0xA0: return "VK_LSHIFT";   case 0xA1: return "VK_RSHIFT";
            case 0xA2: return "VK_LCONTROL"; case 0xA3: return "VK_RCONTROL";
            case 0xA4: return "VK_LMENU";    case 0xA5: return "VK_RMENU";
            case 0xBA: return "VK_OEM_1";    case 0xBB: return "VK_OEM_PLUS";
            case 0xBC: return "VK_OEM_COMMA"; case 0xBD: return "VK_OEM_MINUS";
            case 0xBE: return "VK_OEM_PERIOD"; case 0xBF: return "VK_OEM_2";
            case 0xC0: return "VK_OEM_3";    case 0xDB: return "VK_OEM_4";
            case 0xDC: return "VK_OEM_5";    case 0xDD: return "VK_OEM_6";
            case 0xDE: return "VK_OEM_7";    case 0xE5: return "VK_PROCESSKEY";
            case 0xE7: return "VK_PACKET";   case 0xFF: return "VK_NONE";
        }
        return "VK_0x" + vk.ToString("X2");
    }

    static string KeyName(InjEvent e)
    {
        try {
            int lp = (int)((e.Scan & 0xFF) << 16);
            if ((e.Flags & 0x01) != 0) lp |= 1 << 24;          // LLKHF_EXTENDED
            var sb = new StringBuilder(64);
            GetKeyNameText(lp, sb, sb.Capacity);
            return sb.ToString();
        } catch { return ""; }
    }

    static bool Printable(InjEvent e)
    {
        return e.Down && e.Chr.Length > 0 && !e.Chr.StartsWith("dead:")
            && e.Chr[0] >= 0x20 && e.Chr[0] != 0x7F;
    }

    static string Esc(string s)
    {
        if (s == null) return "";
        var o = new StringBuilder(s.Length + 8);
        foreach (char c in s) {
            if (c == '"' || c == '\\') o.Append('\\').Append(c);
            else if (c < 0x20 || c > 0x7E) o.Append("\\u").Append(((int)c).ToString("x4"));
            else o.Append(c);
        }
        return o.ToString();
    }

    class J {
        readonly StringBuilder _b = new StringBuilder("{");
        bool _first = true;
        void Key(string k) {
            if (!_first) _b.Append(',');
            _first = false;
            _b.Append('"').Append(k).Append("\":");
        }
        public J S(string k, string v) { Key(k); _b.Append('"').Append(Esc(v)).Append('"'); return this; }
        public J N(string k, long v) { Key(k); _b.Append(v); return this; }
        public J Raw(string k, string json) { Key(k); _b.Append(json); return this; }
        public string Done() { return _b.Append('}').ToString(); }
    }

    static string IlName(int rid)
    {
        if (rid < 0) return "unknown";
        if (rid < 0x1000) return "untrusted";
        if (rid < 0x2000) return "low";
        if (rid < 0x3000) return "medium";
        if (rid < 0x4000) return "high";
        return "system";
    }

    static int Integrity(IntPtr proc)
    {
        IntPtr tok;
        if (!OpenProcessToken(proc, TOKEN_QUERY, out tok)) return -1;
        try {
            int len;
            GetTokenInformation(tok, TokenIntegrityLevel, IntPtr.Zero, 0, out len);
            if (len <= 0) return -1;
            IntPtr buf = Marshal.AllocHGlobal(len);
            try {
                if (!GetTokenInformation(tok, TokenIntegrityLevel, buf, len, out len)) return -1;
                IntPtr sid = Marshal.ReadIntPtr(buf);
                int count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                return Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1)));
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { CloseHandle(tok); }
    }

    static bool IsAppContainer(IntPtr proc)
    {
        IntPtr tok;
        if (!OpenProcessToken(proc, TOKEN_QUERY, out tok)) return false;
        IntPtr buf = Marshal.AllocHGlobal(4);
        try {
            int len;
            return GetTokenInformation(tok, TokenIsAppContainer, buf, 4, out len)
                && Marshal.ReadInt32(buf) != 0;
        } finally { Marshal.FreeHGlobal(buf); CloseHandle(tok); }
    }

    static string ImagePath(IntPtr proc)
    {
        var sb = new StringBuilder(1024); int size = sb.Capacity;
        return QueryFullProcessImageName(proc, 0, sb, ref size) ? sb.ToString() : "";
    }

    // One process, described the way the burst needs it. Returns null if the
    // process cannot be opened even for limited query.
    static J Describe(int pid, long burstMs)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try {
            int rid = Integrity(h);
            long create, exit, kernel, user, startedMs = 0;
            if (GetProcessTimes(h, out create, out exit, out kernel, out user) && create > 0)
                startedMs = new DateTimeOffset(DateTime.FromFileTimeUtc(create)).ToUnixTimeMilliseconds();
            string name = "";
            try { using (var p = Process.GetProcessById(pid)) name = p.ProcessName; } catch { }
            return new J().N("pid", pid).S("name", name).S("il", IlName(rid))
                .N("appcontainer", IsAppContainer(h) ? 1 : 0)
                .N("started_ms_before", startedMs == 0 ? -1 : burstMs - startedMs)
                .S("path", ImagePath(h));
        } catch { return null; }
        finally { CloseHandle(h); }
    }

    // Who could have sent it. Windows does not record the sending process, so
    // this is a suspect list, not an attribution: processes in the desktop
    // session that run below medium integrity (when the event says it came from
    // a lower integrity level) and anything that started in the two minutes
    // before the burst.
    static string Candidates(long burstMs, uint fgPid, bool lowerIl)
    {
        var sb = new StringBuilder("[");
        uint fgSession;
        if (!ProcessIdToSessionId(fgPid, out fgSession)) fgSession = uint.MaxValue;
        int n = 0;
        Process[] all;
        try { all = Process.GetProcesses(); } catch { return "[]"; }
        foreach (var p in all) {
            try {
                if (n >= 80) continue;
                int pid = p.Id;
                uint sess;
                if (fgSession != uint.MaxValue &&
                    (!ProcessIdToSessionId((uint)pid, out sess) || sess != fgSession)) continue;
                IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h == IntPtr.Zero) continue;
                int rid; long startedMs = 0;
                try {
                    rid = Integrity(h);
                    long create, exit, kernel, user;
                    if (GetProcessTimes(h, out create, out exit, out kernel, out user) && create > 0)
                        startedMs = new DateTimeOffset(DateTime.FromFileTimeUtc(create)).ToUnixTimeMilliseconds();
                } finally { CloseHandle(h); }
                long age = startedMs == 0 ? -1 : burstMs - startedMs;
                bool recent = startedMs != 0 && age >= -2000 && age <= 120000;
                bool low = rid >= 0 && rid < 0x2000;
                if (!(recent || (lowerIl && low))) continue;
                J d = Describe(pid, burstMs);
                if (d == null) continue;
                d.S("why", recent && low ? "lower-integrity,started-recently"
                                         : recent ? "started-recently" : "lower-integrity");
                if (n++ > 0) sb.Append(',');
                sb.Append(d.Done());
            } catch { }
            finally { p.Dispose(); }
        }
        return sb.Append(']').ToString();
    }

    static void WriterLoop()
    {
        var pending = new List<InjEvent>();
        while (true) {
            try {
                InjEvent e;
                while (_inj.TryDequeue(out e)) pending.Add(e);
                // A burst ends after 800 ms of silence, which keeps one paste or
                // one auto-type together and separates unrelated phantoms.
                if (pending.Count > 0 &&
                        (NowMs() - pending[pending.Count - 1].Ms > 800 || pending.Count >= 2000)) {
                    Flush(pending);
                    pending.Clear();
                }
            } catch { pending.Clear(); }
            Thread.Sleep(100);
        }
    }

    static void Flush(List<InjEvent> ev)
    {
        InjEvent first = ev[0], last = ev[ev.Count - 1];
        string burst = first.Ms + "-" + first.Tick;
        int downs = 0, ups = 0, printable = 0, upper = 0, lower = 0, digit = 0, space = 0, symbol = 0;
        bool anyLowerIl = false;
        var text = new StringBuilder();
        var extras = new List<string>();
        var held = new Dictionary<uint, int>();
        var secretVks = new HashSet<uint>();
        foreach (var e in ev) {
            if ((e.Flags & LLKHF_LOWER_IL_INJECTED) != 0) anyLowerIl = true;
            string x = "0x" + e.Extra.ToString("X");
            if (!extras.Contains(x) && extras.Count < 8) extras.Add(x);
            int c;
            held.TryGetValue(e.Vk, out c);
            if (e.Down) { downs++; held[e.Vk] = c + 1; }
            else { ups++; held[e.Vk] = c - 1; }
            if (!Printable(e)) continue;
            printable++;
            secretVks.Add(e.Vk);
            text.Append(e.Chr);
            char ch = e.Chr[0];
            if (char.IsUpper(ch)) upper++;
            else if (char.IsLower(ch)) lower++;
            else if (char.IsDigit(ch)) digit++;
            else if (char.IsWhiteSpace(ch)) space++;
            else symbol++;
        }
        bool redact = _redactOver >= 0 && printable > _redactOver;
        var unmatched = new List<string>();
        foreach (var kv in held)
            if (kv.Value != 0 && !(redact && secretVks.Contains(kv.Key)))
                unmatched.Add("\"" + VkName(kv.Key) + (kv.Value > 0 ? " down-without-up" : " up-without-down") + "\"");

        string fgName = "";
        try { using (var p = Process.GetProcessById((int)first.FgPid)) fgName = p.ProcessName; } catch { }
        string fg = first.FgPid == 0 ? "" : fgName + ":" + first.FgPid;

        int seq = 0;
        foreach (var e in ev) {
            if (seq >= 400) break;
            bool hide = redact && Printable(e);
            string cls = KeyClass(e.Vk);
            if (hide && cls.StartsWith("digit-")) cls = "digit";
            var j = new J()
                .N("ts", e.Ms / 1000).S("kind", e.Down ? "key" : "key-up")
                .N("injected", 1)
                .N("lower_il", (e.Flags & LLKHF_LOWER_IL_INJECTED) != 0 ? 1 : 0)
                .S("class", cls).S("fg", fg.Replace("\"", ""))
                .N("ms", e.Ms).S("burst", burst).N("seq", seq++)
                .N("vk", hide ? -1L : (long)e.Vk).S("vk_name", hide ? "" : VkName(e.Vk))
                .N("scan", hide ? -1L : (long)e.Scan).S("key_name", hide ? "" : KeyName(e))
                .S("chr", hide ? "" : e.Chr).N("redacted", hide ? 1 : 0)
                .S("mods", e.Mods).S("flags", "0x" + e.Flags.ToString("X2"))
                .N("extended", (e.Flags & 0x01) != 0 ? 1 : 0)
                .N("alt_down", (e.Flags & 0x20) != 0 ? 1 : 0)
                .S("extra", "0x" + e.Extra.ToString("X")).N("event_tick", e.Tick);
            WriteState(j.Done());
        }

        var comp = new J().N("upper", upper).N("lower", lower).N("digit", digit)
            .N("space", space).N("symbol", symbol);
        var fgProc = first.FgPid == 0 ? null : Describe((int)first.FgPid, first.Ms);
        var summary = new J()
            .N("ts", first.Ms / 1000).S("kind", "inject-burst").S("burst", burst)
            .N("ms_start", first.Ms).N("ms_end", last.Ms)
            .N("events", ev.Count).N("downs", downs).N("ups", ups)
            .N("printable", printable).N("redacted", redact ? 1 : 0)
            .S("text", redact ? "" : text.ToString()).Raw("composition", comp.Done())
            .N("lower_il", anyLowerIl ? 1 : 0)
            .Raw("extra_values", "[\"" + string.Join("\",\"", extras) + "\"]")
            .Raw("unmatched", "[" + string.Join(",", unmatched) + "]")
            .S("fg", fg.Replace("\"", "")).S("fg_title", first.Title)
            .S("fg_class", first.WinClass).S("focus_class", first.FocusClass)
            .Raw("fg_process", fgProc == null ? "null" : fgProc.Done())
            .N("ms_since_real_key", first.SinceRealKey)
            .N("ms_since_real_click", first.SinceRealClick)
            .N("ms_since_real_move", first.SinceRealMove)
            .N("dropped_total", Interlocked.Read(ref InjDropped))
            .Raw("candidates", Candidates(first.Ms, first.FgPid, anyLowerIl));
        WriteState(summary.Done());
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
                    Capture(d, true);
                } else {
                    RealKeys++;
                    WindowRealKeys++;
                    _lastRealKeyMs = NowMs();
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
                Capture(d, false);
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
                    _lastRealMoveMs = NowMs();
                }
            } else if (click) {
                Latency(d.time);
                if (inj) {
                    InjectedClicks++;
                    Write("click", d.flags, "button");
                } else {
                    RealClicks++;
                    _lastRealClickMs = NowMs();
                }
            }
        }
        return CallNextHookEx(_ms, nCode, wParam, lParam);
    }

    public static void Start(string outFile, int redactOver)
    {
        _out = outFile;
        _redactOver = redactOver;
        var writer = new Thread(WriterLoop);
        writer.IsBackground = true;
        writer.Name = "jarvis-forensic-writer";
        writer.Start();
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
[JarvisInputHook]::Start($OutFile, $RedactBurstOver)

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
