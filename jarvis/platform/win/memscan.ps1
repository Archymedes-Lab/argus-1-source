# Instruction-level inspection of running processes.
#
# Three questions, none of which any other collector here asks:
#
#   1. Is there executable memory that no file backs? A module loaded from
#      disk is MEM_IMAGE. Code that was written into a process at runtime —
#      reflective loading, manual mapping, plain shellcode — is MEM_PRIVATE
#      and executable, because there is no file for it to be backed by.
#
#   2. Do ntdll's syscall stubs still look like syscall stubs? On x64 every
#      one begins `4C 8B D1 B8 <ssn>` (mov r10,rcx; mov eax,SSN). A jump at
#      byte zero means something is intercepting the call before the kernel
#      ever sees it.
#
#   3. Are the per-process exploit mitigations actually on? CFG, ACG and
#      CET/shadow-stack are the difference between a memory bug being a crash
#      and being an execution primitive.
#
# Without elevation only processes owned by this user can be opened. That is
# reported rather than silently reducing the sample.
$ErrorActionPreference = 'SilentlyContinue'

$src = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public static class JarvisMem
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION64 {
        public ulong BaseAddress; public ulong AllocationBase;
        public uint AllocationProtect; public int __alignment1;
        public ulong RegionSize; public uint State; public uint Protect;
        public uint Type; public int __alignment2;
    }

    const uint MEM_COMMIT = 0x1000, MEM_PRIVATE = 0x20000, MEM_IMAGE = 0x1000000;
    const uint PAGE_EXECUTE = 0x10, PAGE_EXECUTE_READ = 0x20,
               PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80;
    const uint PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    static extern int VirtualQueryEx(IntPtr h, IntPtr addr,
        out MEMORY_BASIC_INFORMATION64 mbi, int len);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf,
        int size, out IntPtr read);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr mod, string name);

    static bool IsExec(uint p)
    {
        return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ
            || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    }

    public class Region { public ulong Base; public ulong Size; public uint Protect; }

    // Executable memory with no file behind it.
    public static List<Region> Unbacked(IntPtr h, int cap)
    {
        var found = new List<Region>();
        ulong addr = 0;
        MEMORY_BASIC_INFORMATION64 mbi;
        int guard = 0;
        while (VirtualQueryEx(h, (IntPtr)addr, out mbi,
                              Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64))) != 0)
        {
            if (guard++ > 200000) break;
            if (mbi.RegionSize == 0) break;
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && IsExec(mbi.Protect))
                found.Add(new Region { Base = mbi.BaseAddress,
                                       Size = mbi.RegionSize, Protect = mbi.Protect });
            addr = mbi.BaseAddress + mbi.RegionSize;
            if (addr >= 0x7FFFFFFF0000UL) break;
            if (found.Count >= cap) break;
        }
        return found;
    }

    // The syscall stubs most worth watching: allocation, protection changes,
    // thread creation and process access are what an injector has to call.
    static readonly string[] Watched = {
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory",
        "NtCreateThreadEx", "NtOpenProcess", "NtMapViewOfSection",
        "NtQueryInformationProcess", "NtSetContextThread", "NtResumeThread",
        "NtCreateUserProcess", "NtDeviceIoControlFile", "NtLoadDriver",
    };

    public static string StubReport(IntPtr h)
    {
        IntPtr nt = GetModuleHandle("ntdll.dll");
        if (nt == IntPtr.Zero) return "";
        var sb = new StringBuilder();
        foreach (var name in Watched)
        {
            IntPtr fn = GetProcAddress(nt, name);
            if (fn == IntPtr.Zero) continue;
            var buf = new byte[8];
            IntPtr got;
            if (!ReadProcessMemory(h, fn, buf, buf.Length, out got)) continue;
            if (got == IntPtr.Zero) continue;
            // Healthy x64 stub: 4C 8B D1 B8 <ssn:4>
            bool clean = (buf[0] == 0x4C && buf[1] == 0x8B && buf[2] == 0xD1 && buf[3] == 0xB8);
            if (clean) continue;
            var hex = new StringBuilder();
            for (int i = 0; i < buf.Length; i++) hex.Append(buf[i].ToString("X2"));
            if (sb.Length > 0) sb.Append(";");
            sb.Append(name).Append("=").Append(hex.ToString());
        }
        return sb.ToString();
    }

    public static string Scan(int maxProcs, int regionCap)
    {
        var sb = new StringBuilder();
        sb.Append("[");
        bool first = true;
        int opened = 0, denied = 0;
        foreach (var p in Process.GetProcesses())
        {
            if (opened >= maxProcs) break;
            IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, p.Id);
            if (h == IntPtr.Zero) { denied++; continue; }
            opened++;
            try
            {
                var regions = Unbacked(h, regionCap);
                string stubs = StubReport(h);
                if (regions.Count == 0 && stubs.Length == 0) continue;
                ulong total = 0; uint rwx = 0;
                foreach (var r in regions) {
                    total += r.Size;
                    if (r.Protect == PAGE_EXECUTE_READWRITE) rwx++;
                }
                if (!first) sb.Append(",");
                first = false;
                sb.Append("{\"pid\":").Append(p.Id)
                  .Append(",\"name\":\"").Append(p.ProcessName.Replace("\"", "")).Append("\"")
                  .Append(",\"regions\":").Append(regions.Count)
                  .Append(",\"bytes\":").Append(total)
                  .Append(",\"rwx\":").Append(rwx)
                  .Append(",\"stubs\":\"").Append(stubs).Append("\"}");
            }
            catch { }
            finally { CloseHandle(h); }
        }
        sb.Append("]");
        return "{\"opened\":" + opened + ",\"denied\":" + denied +
               ",\"procs\":" + sb.ToString() + "}";
    }
}
'@

Add-Type -TypeDefinition $src

$o = [ordered]@{}
$o.memory = [JarvisMem]::Scan(400, 4000) | ConvertFrom-Json

# Per-process mitigations. Get-ProcessMitigation is built in on Win10+ and
# needs no P/Invoke; only a sample of processes is queried because it is slow.
$o.mitigations = @()
foreach ($n in @('explorer','WindowsTerminal','firefox','msedge','powershell',
                 'Code','node','python','ollama','Teams')) {
  $proc = Get-Process -Name $n -EA SilentlyContinue | Select-Object -First 1
  if (-not $proc) { continue }
  $m = Get-ProcessMitigation -Id $proc.Id -EA SilentlyContinue
  if (-not $m) { continue }
  $o.mitigations += [pscustomobject]@{
    name = $n
    pid  = $proc.Id
    cfg  = [string]$m.CFG.Enable
    dep  = [string]$m.DEP.Enable
    aslr = [string]$m.ASLR.ForceRelocateImages
    acg  = [string]$m.DynamicCode.ProhibitDynamicCode
    cet  = [string]$m.UserShadowStack.UserShadowStack
    sig  = [string]$m.BinarySignature.MicrosoftSignedOnly
  }
}

$sys = Get-ProcessMitigation -System -EA SilentlyContinue
$o.system = [pscustomobject]@{
  dep  = [string]$sys.DEP.Enable
  cfg  = [string]$sys.CFG.Enable
  aslr = [string]$sys.ASLR.ForceRelocateImages
  botm = [string]$sys.ASLR.BottomUp
  heap = [string]$sys.Heap.TerminateOnError
  cet  = [string]$sys.UserShadowStack.UserShadowStack
}

$json = [pscustomobject]$o | ConvertTo-Json -Depth 6 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
