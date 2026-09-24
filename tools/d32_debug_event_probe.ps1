$ErrorActionPreference = 'Stop'

$nativeSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

public sealed class D32ImagePin {
    public string Path;
    public string Sha256;
    public uint VolumeSerial;
    public uint FileIndexHigh;
    public uint FileIndexLow;
}

public sealed class D32ProcessEvidence {
    public uint Pid;
    public uint ParentPid;
    public long ParentCreationTime;
    public long CreationTime;
    public string ImagePath;
    public string Sha256;
    public string FileId;
    public bool Approved;
    public bool Exited;
    public uint ExitCode;
}
public sealed class D32ExceptionEvidence {
    public uint Pid;
    public uint Code;
    public uint FirstChance;
    public string Action;
}
public sealed class D32SyntheticEvent {
    public string Kind;
    public uint Pid;
    public long CreationTime;
    public uint ParentPid;
    public long ParentCreationTime;
}
public sealed class D32SyntheticValidation {
    public bool Accepted;
    public string Reason;
}

public sealed class D32ProbeResult {
    public string Name;
    public uint DebuggerPid;
    public long DebuggerCreationTime;
    public string State;
    public string Reason;
    public int CreateEvents;
    public int ExitEvents;
    public int WaitTimeouts;
    public int LastWaitError;
    public uint JobTotalProcesses;
    public uint JobActiveProcesses;
    public bool JobAccountingAvailable;
    public bool LedgerConsistent;
    public List<D32ProcessEvidence> Processes = new List<D32ProcessEvidence>();
    public List<D32ExceptionEvidence> Exceptions = new List<D32ExceptionEvidence>();
}

public static class D32NativeDebugProbe {
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint DEBUG_PROCESS = 0x00000001;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    const uint DBG_CONTINUE = 0x00010002;
    const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
    const uint EXCEPTION_DEBUG_EVENT = 1;
    const uint CREATE_PROCESS_DEBUG_EVENT = 3;
    const uint EXIT_PROCESS_DEBUG_EVENT = 5;
    const uint CREATE_THREAD_DEBUG_EVENT = 2;
    const uint EXIT_THREAD_DEBUG_EVENT = 4;
    const uint LOAD_DLL_DEBUG_EVENT = 6;
    const uint UNLOAD_DLL_DEBUG_EVENT = 7;
    const uint OUTPUT_DEBUG_STRING_EVENT = 8;
    const uint RIP_EVENT = 9;
    const uint STATUS_BREAKPOINT = 0x80000003;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_READ = 1;
    const uint FILE_SHARE_WRITE = 2;
    const uint FILE_SHARE_DELETE = 4;
    const uint OPEN_EXISTING = 3;
    const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    const uint JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1;

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct STARTUPINFO {
        public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize;
        public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute;
        public uint dwFlags; public ushort wShowWindow; public ushort cbReserved2;
        public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION {
        public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId;
    }
    [StructLayout(LayoutKind.Sequential)] struct FILETIME { public uint Low; public uint High; }
    [StructLayout(LayoutKind.Sequential)] struct BY_HANDLE_FILE_INFORMATION {
        public uint FileAttributes; public FILETIME CreationTime; public FILETIME LastAccessTime; public FILETIME LastWriteTime;
        public uint VolumeSerialNumber; public uint FileSizeHigh; public uint FileSizeLow; public uint NumberOfLinks;
        public uint FileIndexHigh; public uint FileIndexLow;
    }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_BASIC_INFORMATION {
        public int ExitStatus; public IntPtr PebBaseAddress; public IntPtr AffinityMask;
        public int BasePriority; public IntPtr UniqueProcessId; public IntPtr InheritedFromUniqueProcessId;
    }
    [StructLayout(LayoutKind.Sequential)] struct CREATE_PROCESS_DEBUG_INFO {
        public IntPtr hFile; public IntPtr hProcess; public IntPtr hThread; public IntPtr lpBaseOfImage;
        public uint dwDebugInfoFileOffset; public uint nDebugInfoSize; public IntPtr lpThreadLocalBase;
        public IntPtr lpStartAddress; public IntPtr lpImageName; public ushort fUnicode;
    }
    [StructLayout(LayoutKind.Sequential)] struct EXIT_PROCESS_DEBUG_INFO { public uint dwExitCode; }
    [StructLayout(LayoutKind.Sequential)] struct EXCEPTION_RECORD {
        public uint ExceptionCode; public uint ExceptionFlags; public IntPtr ExceptionRecord; public IntPtr ExceptionAddress;
        public uint NumberParameters;
        public IntPtr Parameter0; public IntPtr Parameter1; public IntPtr Parameter2; public IntPtr Parameter3; public IntPtr Parameter4;
        public IntPtr Parameter5; public IntPtr Parameter6; public IntPtr Parameter7; public IntPtr Parameter8; public IntPtr Parameter9;
        public IntPtr Parameter10; public IntPtr Parameter11; public IntPtr Parameter12; public IntPtr Parameter13; public IntPtr Parameter14;
    }
    [StructLayout(LayoutKind.Sequential)] struct EXCEPTION_DEBUG_INFO {
        public EXCEPTION_RECORD ExceptionRecord; public uint dwFirstChance;
    }
    [StructLayout(LayoutKind.Sequential)] struct CREATE_THREAD_DEBUG_INFO { public IntPtr hThread; public IntPtr lpThreadLocalBase; public IntPtr lpStartAddress; }
    [StructLayout(LayoutKind.Sequential)] struct LOAD_DLL_DEBUG_INFO {
        public IntPtr hFile; public IntPtr lpBaseOfDll; public uint dwDebugInfoFileOffset; public uint nDebugInfoSize;
        public IntPtr lpImageName; public ushort fUnicode;
    }
    [StructLayout(LayoutKind.Explicit, Size=256)] struct DEBUG_EVENT_UNION {
        [FieldOffset(0)] public CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
        [FieldOffset(0)] public EXIT_PROCESS_DEBUG_INFO ExitProcessInfo;
        [FieldOffset(0)] public EXCEPTION_DEBUG_INFO ExceptionInfo;
        [FieldOffset(0)] public CREATE_THREAD_DEBUG_INFO CreateThreadInfo;
        [FieldOffset(0)] public LOAD_DLL_DEBUG_INFO LoadDllInfo;
    }
    [StructLayout(LayoutKind.Sequential)] struct DEBUG_EVENT {
        public uint dwDebugEventCode; public uint dwProcessId; public uint dwThreadId; public DEBUG_EVENT_UNION u;
    }
    [StructLayout(LayoutKind.Sequential)] struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
        public long TotalUserTime; public long TotalKernelTime; public long ThisPeriodTotalUserTime; public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount; public uint TotalProcesses; public uint ActiveProcesses; public uint TotalTerminatedProcesses;
    }

    sealed class ActiveProcess {
        public D32ProcessEvidence Evidence;
        public IntPtr Handle;
    }

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateProcessW(string app, StringBuilder commandLine, IntPtr procAttrs, IntPtr threadAttrs,
        bool inheritHandles, uint flags, IntPtr environment, string currentDirectory, ref STARTUPINFO startup, out PROCESS_INFORMATION info);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr attrs, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job, uint infoClass, out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info, uint length, IntPtr returnedLength);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WaitForDebugEvent(out DEBUG_EVENT ev, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ContinueDebugEvent(uint processId, uint threadId, uint continueStatus);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr process, out FILETIME creation, out FILETIME exit, out FILETIME kernel, out FILETIME user);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr file, out BY_HANDLE_FILE_INFORMATION info);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetFinalPathNameByHandleW(IntPtr file, StringBuilder path, uint size, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr attrs, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess, out IntPtr targetHandle, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll")] static extern uint GetCurrentProcessId();
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr process, int infoClass, out PROCESS_BASIC_INFORMATION info, int length, out int returnLength);

    static long Ft(FILETIME f) { return ((long)f.High << 32) | f.Low; }
    static string Normalize(string p) {
        if (p.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase)) p = "\\\\" + p.Substring(8);
        else if (p.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase)) p = p.Substring(4);
        return p.Replace('/', '\\').TrimEnd('\\');
    }
    static string GetPath(IntPtr file) {
        StringBuilder b = new StringBuilder(32768);
        uint n = GetFinalPathNameByHandleW(file, b, (uint)b.Capacity, 0);
        if (n == 0 || n >= b.Capacity) throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFinalPathNameByHandle failed");
        return Normalize(b.ToString());
    }
    static string GetHash(IntPtr file) {
        using (SafeFileHandle safe = new SafeFileHandle(file, false))
        using (FileStream stream = new FileStream(safe, FileAccess.Read))
        using (SHA256 sha = SHA256.Create()) {
            stream.Position = 0;
            byte[] hash = sha.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
    }
    static string FileId(BY_HANDLE_FILE_INFORMATION i) {
        return i.VolumeSerialNumber.ToString("x8") + ":" + i.FileIndexHigh.ToString("x8") + i.FileIndexLow.ToString("x8");
    }
    static D32ImagePin PinFromHandle(IntPtr file) {
        BY_HANDLE_FILE_INFORMATION fi;
        if (!GetFileInformationByHandle(file, out fi)) throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandle failed");
        return new D32ImagePin { Path = GetPath(file), Sha256 = GetHash(file), VolumeSerial = fi.VolumeSerialNumber, FileIndexHigh = fi.FileIndexHigh, FileIndexLow = fi.FileIndexLow };
    }
    public static D32ImagePin PinPath(string path) {
        IntPtr f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (f == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFile pin failed");
        try { return PinFromHandle(f); } finally { CloseHandle(f); }
    }
    static bool EqualsPin(D32ImagePin a, D32ImagePin b) {
        return String.Equals(Normalize(a.Path), Normalize(b.Path), StringComparison.OrdinalIgnoreCase)
            && String.Equals(a.Sha256, b.Sha256, StringComparison.OrdinalIgnoreCase)
            && a.VolumeSerial == b.VolumeSerial && a.FileIndexHigh == b.FileIndexHigh && a.FileIndexLow == b.FileIndexLow;
    }
    static uint ParentPid(IntPtr process) {
        PROCESS_BASIC_INFORMATION pbi; int returned;
        int status = NtQueryInformationProcess(process, 0, out pbi, Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), out returned);
        if (status != 0) throw new InvalidOperationException("NtQueryInformationProcess status 0x" + status.ToString("x8"));
        return unchecked((uint)pbi.InheritedFromUniqueProcessId.ToInt64());
    }
    static long Creation(IntPtr process) {
        FILETIME c, e, k, u;
        if (!GetProcessTimes(process, out c, out e, out k, out u)) throw new Win32Exception(Marshal.GetLastWin32Error(), "GetProcessTimes failed");
        return Ft(c);
    }
    static void CloseIfValid(IntPtr h) { if (h != IntPtr.Zero && h != new IntPtr(-1)) CloseHandle(h); }
    static void Fail(D32ProbeResult result, string reason) {
        if (String.IsNullOrEmpty(result.Reason)) result.Reason = reason;
        result.State = "BLOCKED";
    }
    public static bool ValidateAccounting(int creates, int exits, uint jobTotal, uint jobActive) {
        return creates >= 0 && creates == exits && (uint)creates == jobTotal && jobActive == 0;
    }
    public static D32SyntheticValidation ValidateSyntheticLedger(D32SyntheticEvent[] events) {
        Dictionary<uint, long> active = new Dictionary<uint, long>();
        HashSet<string> identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (D32SyntheticEvent e in events) {
            if (e == null || (e.Kind != "CREATE" && e.Kind != "EXIT"))
                return new D32SyntheticValidation { Accepted=false, Reason="unknown-or-null-event" };
            string identity = e.Pid.ToString() + "@" + e.CreationTime.ToString();
            if (e.Kind == "CREATE") {
                if (active.ContainsKey(e.Pid)) return new D32SyntheticValidation { Accepted=false, Reason="overlapping-pid-reuse" };
                if (!identities.Add(identity)) return new D32SyntheticValidation { Accepted=false, Reason="duplicate-process-identity" };
                if (e.ParentPid != 0) {
                    long parentCreation;
                    if (!active.TryGetValue(e.ParentPid, out parentCreation) || parentCreation != e.ParentCreationTime)
                        return new D32SyntheticValidation { Accepted=false, Reason="unknown-or-ambiguous-parent-identity" };
                }
                active.Add(e.Pid, e.CreationTime);
            } else {
                long currentCreation;
                if (!active.TryGetValue(e.Pid, out currentCreation) || currentCreation != e.CreationTime)
                    return new D32SyntheticValidation { Accepted=false, Reason="missing-or-mismatched-exit-identity" };
                active.Remove(e.Pid);
            }
        }
        if (active.Count != 0) return new D32SyntheticValidation { Accepted=false, Reason="missing-exit-event" };
        return new D32SyntheticValidation { Accepted=true, Reason="closed" };
    }

    public static D32ProbeResult Run(string name, string app, string args, string cwd, string[] envEntries, D32ImagePin[] approvedPins, bool interruptFirstCreate, uint timeoutMs) {
        D32ProbeResult result = new D32ProbeResult { Name=name, State="RUNNING" };
        IntPtr job = IntPtr.Zero, env = IntPtr.Zero;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        Dictionary<uint, ActiveProcess> active = new Dictionary<uint, ActiveProcess>();
        HashSet<string> identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        HashSet<uint> startupBreakpoints = new HashSet<uint>();
        List<IntPtr> retained = new List<IntPtr>();
        bool created = false;
        try {
            string block = String.Join("\0", envEntries) + "\0\0";
            env = Marshal.StringToHGlobalUni(block);
            job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed");
            STARTUPINFO si = new STARTUPINFO(); si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            StringBuilder cmd = new StringBuilder("\"" + app + "\" " + args, 32768);
            uint flags = CREATE_SUSPENDED | DEBUG_PROCESS | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
            if (!CreateProcessW(app, cmd, IntPtr.Zero, IntPtr.Zero, false, flags, env, cwd, ref si, out pi))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW failed");
            created = true;
            if (!AssignProcessToJobObject(job, pi.hProcess)) throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject failed");
            result.DebuggerPid = GetCurrentProcessId();
            result.DebuggerCreationTime = Creation(GetCurrentProcess());
            // DEBUG_PROCESS queues CREATE_PROCESS_DEBUG_EVENT when the primary thread is first resumed.
            // The debugger event itself stops the process before its user-mode entry point.
            if (ResumeThread(pi.hThread) == 0xFFFFFFFF) throw new Win32Exception(Marshal.GetLastWin32Error(), "initial ResumeThread failed");
            ulong deadline = (ulong)Environment.TickCount64 + timeoutMs;
            bool interrupted = false;
            while ((ulong)Environment.TickCount64 < deadline) {
                DEBUG_EVENT ev;
                uint remaining = (uint)Math.Max(1, Math.Min(500, (long)(deadline - (ulong)Environment.TickCount64)));
                if (!WaitForDebugEvent(out ev, remaining)) {
                    int error = Marshal.GetLastWin32Error();
                    result.LastWaitError = error;
                    result.WaitTimeouts++;
                    if (error == 121) continue;
                    Fail(result, "WaitForDebugEvent failed: " + error);
                    TerminateJobObject(job, 0xD3200001);
                    break;
                }
                uint continueStatus = DBG_CONTINUE;
                if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
                    result.CreateEvents++;
                    CREATE_PROCESS_DEBUG_INFO c = ev.u.CreateProcessInfo;
                    ActiveProcess rec = null;
                    try {
                        if (c.hFile == IntPtr.Zero) throw new InvalidOperationException("CREATE_PROCESS_DEBUG_EVENT hFile is null");
                        D32ImagePin actual = PinFromHandle(c.hFile);
                        long creation = Creation(c.hProcess);
                        uint parent = ParentPid(c.hProcess);
                        string identity = ev.dwProcessId.ToString() + "@" + creation.ToString();
                        if (!identities.Add(identity)) throw new InvalidOperationException("duplicate process identity");
                        if (active.ContainsKey(ev.dwProcessId)) throw new InvalidOperationException("PID reused while previous identity still active");
                        if (result.CreateEvents == 1) {
                            if (parent != GetCurrentProcessId()) throw new InvalidOperationException("root parent PID is not the debugger process");
                        } else {
                            ActiveProcess parentRec;
                            if (!active.TryGetValue(parent, out parentRec)) throw new InvalidOperationException("unknown or non-active parent PID " + parent);
                        }
                        long parentCreationTime = 0;
                        if (result.CreateEvents == 1) parentCreationTime = result.DebuggerCreationTime;
                        else {
                            ActiveProcess parentRec;
                            if (!active.TryGetValue(parent, out parentRec)) throw new InvalidOperationException("unknown parent identity");
                            parentCreationTime = parentRec.Evidence.CreationTime;
                        }
                        bool approved = false;
                        foreach (D32ImagePin pin in approvedPins) if (EqualsPin(pin, actual)) { approved = true; break; }
                        D32ProcessEvidence evidence = new D32ProcessEvidence {
                            Pid=ev.dwProcessId, ParentPid=parent, ParentCreationTime=parentCreationTime, CreationTime=creation, ImagePath=actual.Path,
                            Sha256=actual.Sha256, FileId=actual.VolumeSerial.ToString("x8") + ":" + actual.FileIndexHigh.ToString("x8") + actual.FileIndexLow.ToString("x8"),
                            Approved=approved, Exited=false
                        };
                        IntPtr retainedProcess;
                        if (!DuplicateHandle(GetCurrentProcess(), c.hProcess, GetCurrentProcess(), out retainedProcess, 0, false, 2))
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "DuplicateHandle for process identity failed");
                        rec = new ActiveProcess { Evidence=evidence, Handle=retainedProcess };
                        active.Add(ev.dwProcessId, rec);
                        retained.Add(retainedProcess);
                        result.Processes.Add(evidence);
                        if (!approved) {
                            Fail(result, "unapproved process image: " + actual.Path);
                            TerminateJobObject(job, 0xD3200002);
                        }
                        if (interruptFirstCreate && result.CreateEvents == 1) {
                            Fail(result, "debug-chain interruption injected before first ContinueDebugEvent");
                            TerminateJobObject(job, 0xD3200003);
                            interrupted = true;
                        }
                    } finally {
                        CloseIfValid(c.hFile);
                        CloseIfValid(c.hThread);
                    }
                    if (interrupted) {
                        // Fail closed: delay continuation until after Job termination, then drain the EXIT event.
                        if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)) {
                            Fail(result, "ContinueDebugEvent cleanup failed after injected interruption: " + Marshal.GetLastWin32Error());
                            break;
                        }
                        continue;
                    }
                    if (result.State == "BLOCKED") {
                        // The process remains explicitly suspended; termination precedes event release.
                    }
                    if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)) {
                        Fail(result, "ContinueDebugEvent failed after create: " + Marshal.GetLastWin32Error());
                        TerminateJobObject(job, 0xD3200004);
                        break;
                    }
                    if (result.State == "BLOCKED") {
                        // We released only a CREATE_SUSPENDED event after terminating the Job; user code did not run.
                    }
                    continue;
                }
                if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                    result.ExitEvents++;
                    ActiveProcess rec;
                    if (!active.TryGetValue(ev.dwProcessId, out rec)) {
                        Fail(result, "EXIT_PROCESS_DEBUG_EVENT without matching active CREATE identity");
                    } else {
                        rec.Evidence.Exited = true;
                        rec.Evidence.ExitCode = ev.u.ExitProcessInfo.dwExitCode;
                        active.Remove(ev.dwProcessId);
                        IntPtr processHandle = rec.Handle;
                        if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)) {
                            Fail(result, "ContinueDebugEvent failed after exit: " + Marshal.GetLastWin32Error());
                            break;
                        }
                        uint waitResult = WaitForSingleObject(processHandle, 5000);
                        if (waitResult != 0) Fail(result, "process handle did not signal after EXIT event: " + waitResult);
                        CloseIfValid(processHandle);
                        retained.Remove(processHandle);
                        if (result.CreateEvents == result.ExitEvents && active.Count == 0 && created) break;
                        continue;
                    }
                    if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)) {
                        Fail(result, "ContinueDebugEvent failed after exit: " + Marshal.GetLastWin32Error());
                        break;
                    }
                    if (result.CreateEvents == result.ExitEvents && active.Count == 0 && created) break;
                    continue;
                }
                if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                    uint code = ev.u.ExceptionInfo.ExceptionRecord.ExceptionCode;
                    if (code == STATUS_BREAKPOINT && startupBreakpoints.Add(ev.dwProcessId)) continueStatus = DBG_CONTINUE;
                    else if (ev.u.ExceptionInfo.dwFirstChance != 0) {
                        ActiveProcess exceptionOwner;
                        if (!active.TryGetValue(ev.dwProcessId, out exceptionOwner) || !exceptionOwner.Evidence.Approved) {
                            Fail(result, "first-chance exception has no approved active process identity");
                            TerminateJobObject(job, 0xD3200006);
                        }
                        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                        result.Exceptions.Add(new D32ExceptionEvidence { Pid=ev.dwProcessId, Code=code, FirstChance=1, Action="pass-through" });
                    } else {
                        Fail(result, "second-chance unhandled debug exception 0x" + code.ToString("x8"));
                        TerminateJobObject(job, 0xD3200006);
                        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                        result.Exceptions.Add(new D32ExceptionEvidence { Pid=ev.dwProcessId, Code=code, FirstChance=0, Action="blocked" });
                    }
                } else if (ev.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
                    CloseIfValid(ev.u.CreateThreadInfo.hThread);
                } else if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
                    CloseIfValid(ev.u.LoadDllInfo.hFile);
                } else if (ev.dwDebugEventCode != EXIT_THREAD_DEBUG_EVENT && ev.dwDebugEventCode != UNLOAD_DLL_DEBUG_EVENT && ev.dwDebugEventCode != OUTPUT_DEBUG_STRING_EVENT && ev.dwDebugEventCode != RIP_EVENT) {
                    Fail(result, "unknown debug event type " + ev.dwDebugEventCode);
                    TerminateJobObject(job, 0xD3200007);
                }
                if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continueStatus)) {
                    Fail(result, "ContinueDebugEvent failed: " + Marshal.GetLastWin32Error());
                    TerminateJobObject(job, 0xD3200008);
                    break;
                }
            }
            if (result.CreateEvents != result.ExitEvents || active.Count != 0) {
                if (result.State == "RUNNING") Fail(result, "missing CREATE/EXIT event closure or active process remains");
                if (job != IntPtr.Zero) TerminateJobObject(job, 0xD3200009);
            }
            if (job != IntPtr.Zero) {
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
                if (QueryInformationJobObject(job, JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION, out accounting,
                    (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)), IntPtr.Zero)) {
                    result.JobAccountingAvailable = true;
                    result.JobTotalProcesses = accounting.TotalProcesses;
                    result.JobActiveProcesses = accounting.ActiveProcesses;
                    ulong settleDeadline = (ulong)Environment.TickCount64 + 2000;
                    while (accounting.ActiveProcesses != 0 && (ulong)Environment.TickCount64 < settleDeadline) {
                        System.Threading.Thread.Sleep(20);
                        if (!QueryInformationJobObject(job, JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION, out accounting,
                            (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)), IntPtr.Zero)) break;
                        result.JobTotalProcesses = accounting.TotalProcesses;
                        result.JobActiveProcesses = accounting.ActiveProcesses;
                    }
                    result.LedgerConsistent = ValidateAccounting(result.CreateEvents, result.ExitEvents, accounting.TotalProcesses, accounting.ActiveProcesses);
                    if (!result.LedgerConsistent && result.State == "RUNNING") Fail(result, "Job accounting mismatch");
                } else if (result.State == "RUNNING") Fail(result, "QueryInformationJobObject failed: " + Marshal.GetLastWin32Error());
            }
            if (result.State == "RUNNING") result.State = "COMPLETED";
            return result;
        } catch (Exception ex) {
            Fail(result, ex.GetType().Name + ": " + ex.Message);
            if (job != IntPtr.Zero) TerminateJobObject(job, 0xD320000A);
            return result;
        } finally {
            foreach (IntPtr h in retained) CloseIfValid(h);
            if (created) {
                CloseIfValid(pi.hThread);
                CloseIfValid(pi.hProcess);
            }
            CloseIfValid(job);
            if (env != IntPtr.Zero) Marshal.FreeHGlobal(env);
        }
    }
}
'@

Add-Type -TypeDefinition $nativeSource -Language CSharp

$tempRoot = Join-Path $env:TEMP ('D32-WinDebug-Proto-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
$fixturePath = Join-Path $tempRoot 'D32Probe.cmd'
$markerPath = Join-Path $tempRoot 'should-not-exist.txt'
$unknownHelperMarkerPath = Join-Path $tempRoot 'unknown-helper-executed.txt'
$allowedHelperMarkerPath = Join-Path $tempRoot 'allowed-helper-executed.txt'
$tamperedHelperMarkerPath = Join-Path $tempRoot 'tampered-helper-executed.txt'
[System.IO.File]::WriteAllText($fixturePath, ('@echo launched>"' + $markerPath + '"' + "`r`n"), [System.Text.Encoding]::ASCII)
$allowedHelperPath = Join-Path $tempRoot 'd32-allowed-helper.exe'
$unknownParentPath = Join-Path $tempRoot 'd32-unknown-parent.exe'
$tamperedHelperPath = Join-Path $tempRoot 'd32-tampered-helper.exe'
$allowedHelperSourcePath = Join-Path $tempRoot 'd32-allowed-helper.cs'
$unknownParentSourcePath = Join-Path $tempRoot 'd32-unknown-parent.cs'
$tamperedHelperSourcePath = Join-Path $tempRoot 'd32-tampered-helper.cs'
$cscPath = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$powershell51Path = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$scriptOriginalPin = $null
$scriptTamperedPin = $null
$manifestPath = Join-Path $tempRoot 'Cargo.toml'
$sourceDir = Join-Path $tempRoot 'src'
$binDir = Join-Path $sourceDir 'bin'
$cargoHome = Join-Path $tempRoot 'cargo-home'
$targetDir = Join-Path $tempRoot 'target'
New-Item -ItemType Directory -Path $sourceDir,$binDir,$cargoHome | Out-Null
$manifest = @'
[package]
name = "d32-debug-probe"
version = "0.1.0"
edition = "2021"

[dependencies]
'@
$source = 'fn main() {}'
$unknownSource = 'fn main() {}'
[System.IO.File]::WriteAllText($manifestPath, $manifest, [System.Text.Encoding]::UTF8)
[System.IO.File]::WriteAllText((Join-Path $sourceDir 'main.rs'), $source, [System.Text.Encoding]::UTF8)
[System.IO.File]::WriteAllText((Join-Path $binDir 'd32-unknown-helper.rs'), $unknownSource, [System.Text.Encoding]::UTF8)

$cargoDir = 'C:\Users\zuo\.rustup\toolchains\1.95.0-x86_64-pc-windows-msvc\bin'
$rustlibBin = 'C:\Users\zuo\.rustup\toolchains\1.95.0-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\bin'
$rustLldPath = Join-Path $rustlibBin 'rust-lld.exe'
$rustcPath = Join-Path $cargoDir 'rustc.exe'
$cargoPath = Join-Path $cargoDir 'cargo.exe'
$cmdPath = Join-Path $env:SystemRoot 'System32\cmd.exe'
$pwshPath = (Get-Command pwsh.exe).Source
$wherePath = Join-Path $env:SystemRoot 'System32\where.exe'
$conhostPath = Join-Path $env:SystemRoot 'System32\conhost.exe'

function Get-Pin([string] $Path) {
    [D32NativeDebugProbe]::PinPath($Path)
}

$rustcPin = Get-Pin $rustcPath
$cargoPin = Get-Pin $cargoPath
$rustLldPin = Get-Pin $rustLldPath
$cmdPin = Get-Pin $cmdPath
$pwshPin = Get-Pin $pwshPath
$wherePin = Get-Pin $wherePath
$conhostPin = Get-Pin $conhostPath
$cscPin = Get-Pin $cscPath
$scriptOriginalPin = Get-Pin $fixturePath

function Compile-Fixture([string] $SourcePath, [string] $OutputPath, [string] $Source) {
    [System.IO.File]::WriteAllText($SourcePath, $Source, [System.Text.Encoding]::UTF8)
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $cscPath
    $psi.Arguments = '/nologo /target:exe /out:"' + $OutputPath + '" "' + $SourcePath + '"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.Environment.Clear()
    foreach ($key in @('SystemRoot', 'WINDIR', 'TEMP', 'TMP')) {
        $psi.Environment[$key] = (Get-Item ('Env:' + $key)).Value
    }
    $psi.Environment['TEMP'] = $tempRoot
    $psi.Environment['TMP'] = $tempRoot
    $psi.Environment['PATH'] = @((Split-Path -Parent $cscPath), (Join-Path $env:SystemRoot 'System32')) -join ';'
    $psi.Environment['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'
    $compiler = [System.Diagnostics.Process]::Start($psi)
    if (-not $compiler.WaitForExit(30000)) {
        $compiler.Kill()
        throw 'Timed out compiling the local prototype fixture.'
    }
    $stdout = $compiler.StandardOutput.ReadToEnd()
    $stderr = $compiler.StandardError.ReadToEnd()
    if ($compiler.ExitCode -ne 0 -or -not (Test-Path $OutputPath)) {
        throw ('Local prototype fixture compile failed: ' + $stdout + $stderr)
    }
}

$allowedHelperSource = @"
using System.IO;
public static class D32AllowedFixture {
    public static void Main() { File.WriteAllText(@"$allowedHelperMarkerPath", "executed"); }
}
"@
$unknownParentSource = @"
using System.Diagnostics;
public static class D32UnknownParent {
    public static void Main() {
        ProcessStartInfo psi = new ProcessStartInfo(@"$powershell51Path", @"-NoProfile -NonInteractive -Command ""[IO.File]::WriteAllText('$unknownHelperMarkerPath','executed')""");
        psi.UseShellExecute = false;
        Process.Start(psi).WaitForExit();
    }
}
"@
$tamperedHelperSource = @"
using System.IO;
public static class D32TamperedFixture {
    public static void Main() { File.WriteAllText(@"$tamperedHelperMarkerPath", "executed"); }
}
"@
Compile-Fixture $allowedHelperSourcePath $allowedHelperPath $allowedHelperSource
Compile-Fixture $unknownParentSourcePath $unknownParentPath $unknownParentSource
Compile-Fixture $tamperedHelperSourcePath $tamperedHelperPath $tamperedHelperSource

function Run-Probe([string] $Name, [string] $App, [string] $CommandArguments, [D32ImagePin[]] $Pins, [string[]] $PathEntries, [bool] $Interrupt = $false) {
    $sys32 = Join-Path $env:SystemRoot 'System32'
    $envEntries = @(
        ('SystemRoot=' + $env:SystemRoot),
        ('WINDIR=' + $env:SystemRoot),
        ('TEMP=' + $tempRoot),
        ('TMP=' + $tempRoot),
        ('CARGO_HOME=' + $cargoHome),
        ('CARGO_NET_OFFLINE=true'),
        ('CARGO_TARGET_DIR=' + $targetDir),
        ('RUSTC=' + $rustcPath),
        ('RUSTFLAGS=-C linker=' + $rustLldPath),
        ('PATH=' + ($PathEntries -join ';')),
        ('PATHEXT=.COM;.EXE;.BAT;.CMD')
    ) | Sort-Object { $_.Split('=', 2)[0] }
    [D32NativeDebugProbe]::Run($Name, $App, $CommandArguments, $tempRoot, [string[]]$envEntries, $Pins, $Interrupt, 45000)
}

$cases = [System.Collections.Generic.List[object]]::new()

# A fast-exiting command processor must be observed and blocked while its initial thread is suspended.
$fastCmdResult = Run-Probe 'fast-exit-cmd' $cmdPath '/d /c exit 0' @() @($cargoDir, (Join-Path $env:SystemRoot 'System32'))
$cases.Add($fastCmdResult)

# Both PATH and absolute .cmd dispatch are denied at the command-processor image before script code runs.
$pathCmdResult = Run-Probe 'path-cmd-script' $cmdPath ('/d /c call ' + [IO.Path]::GetFileName($fixturePath)) @() @($tempRoot, $cargoDir, (Join-Path $env:SystemRoot 'System32'))
$cases.Add($pathCmdResult)
if (Test-Path $markerPath) { throw 'PATH .cmd negative test executed its marker.' }
$absoluteCmdResult = Run-Probe 'absolute-cmd-script' $cmdPath ('/d /c call "' + $fixturePath + '"') @() @($tempRoot, $cargoDir, (Join-Path $env:SystemRoot 'System32'))
$cases.Add($absoluteCmdResult)
if (Test-Path $markerPath) { throw 'Absolute .cmd negative test executed its marker.' }

# Cargo check runs a normal, pinned Cargo -> rustc toolchain chain without invoking the installed
# MSVC linker, whose mandatory VCTIP telemetry child is intentionally not allowed to run here.
# Every CREATE/EXIT event plus independent Job accounting is still required to close.
$cargoArgs = 'check --offline --manifest-path "' + $manifestPath + '" --target-dir "' + $targetDir + '" --color never'
$toolchainResult = Run-Probe 'allowed-toolchain-child' $cargoPath $cargoArgs @($cargoPin, $rustcPin, $rustLldPin, $conhostPin) @($tempRoot, $cargoDir, $rustlibBin, (Join-Path $env:SystemRoot 'System32'))
$cases.Add($toolchainResult)

# A known generated image is allowed and reaches user mode. A separately pinned fixture parent
# tries to create Windows PowerShell 5.1, which is deliberately not pinned; its marker must remain
# absent because the child image is stopped at CREATE_PROCESS_DEBUG_EVENT.
$allowedHelperPin = Get-Pin $allowedHelperPath
$allowedHelperResult = Run-Probe 'allowed-generated-executable' $allowedHelperPath '' @($allowedHelperPin, $conhostPin) @($tempRoot, (Join-Path $env:SystemRoot 'System32'))
$cases.Add($allowedHelperResult)
if (-not (Test-Path $allowedHelperMarkerPath)) { throw 'Pinned generated executable did not reach its entry point.' }
$unknownParentPin = Get-Pin $unknownParentPath
$unknownHelperResult = Run-Probe 'unknown-helper-child' $unknownParentPath '' @($unknownParentPin, $conhostPin) @($tempRoot, (Join-Path $env:SystemRoot 'System32'))
$cases.Add($unknownHelperResult)
if (Test-Path $unknownHelperMarkerPath) { throw 'Unpinned helper wrote its marker before image validation.' }

# Mutate a second generated PE after pinning. File identity remains stable while byte hash changes;
# the retained CREATE_PROCESS_DEBUG_EVENT image handle must detect that change before Main runs.
$tamperedHelperPin = Get-Pin $tamperedHelperPath
$stream = [System.IO.File]::Open($tamperedHelperPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
try {
    $stream.Position = $stream.Length
    $stream.WriteByte([byte]0x41)
    $stream.Flush()
} finally {
    $stream.Dispose()
}
$tamperedImagePin = Get-Pin $tamperedHelperPath
$tamperedHelperResult = Run-Probe 'image-byte-tamper' $tamperedHelperPath '' @($tamperedHelperPin, $conhostPin) @($tempRoot, (Join-Path $env:SystemRoot 'System32'))
$cases.Add($tamperedHelperResult)
if (Test-Path $tamperedHelperMarkerPath) { throw 'Byte-tampered executable ran before image validation.' }

# A resident .cmd file is not launched, and a same-file byte mutation must change its observed hash.
$scriptStream = [System.IO.File]::Open($fixturePath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
try {
    $scriptBytes = [System.Text.Encoding]::ASCII.GetBytes('@rem tamper-after-pin' + "`r`n")
    $scriptStream.Write($scriptBytes, 0, $scriptBytes.Length)
    $scriptStream.Flush()
} finally {
    $scriptStream.Dispose()
}
$scriptTamperedPin = Get-Pin $fixturePath

# Deliberately omit ContinueDebugEvent on the first CREATE event, terminate the Job, and require a fail-closed result.
$interruptResult = Run-Probe 'debug-chain-interruption' $cmdPath '/d /c exit 0' @($cmdPin) @($cargoDir, (Join-Path $env:SystemRoot 'System32')) $true
$cases.Add($interruptResult)

function New-SyntheticEvent([string] $Kind, [uint32] $ProcessId, [long] $CreationTime, [uint32] $ParentProcessId = 0, [long] $ParentCreationTime = 0) {
    $event = [D32SyntheticEvent]::new()
    $event.Kind = $Kind
    $event.Pid = $ProcessId
    $event.CreationTime = $CreationTime
    $event.ParentPid = $ParentProcessId
    $event.ParentCreationTime = $ParentCreationTime
    return $event
}
$validPidReuse = [D32NativeDebugProbe]::ValidateSyntheticLedger([D32SyntheticEvent[]]@(
    (New-SyntheticEvent 'CREATE' 41 100),
    (New-SyntheticEvent 'EXIT' 41 100),
    (New-SyntheticEvent 'CREATE' 41 200),
    (New-SyntheticEvent 'EXIT' 41 200)
))
$overlappingPidReuse = [D32NativeDebugProbe]::ValidateSyntheticLedger([D32SyntheticEvent[]]@(
    (New-SyntheticEvent 'CREATE' 41 100),
    (New-SyntheticEvent 'CREATE' 41 200),
    (New-SyntheticEvent 'EXIT' 41 200)
))
$missingExit = [D32NativeDebugProbe]::ValidateSyntheticLedger([D32SyntheticEvent[]]@(
    (New-SyntheticEvent 'CREATE' 42 300)
))
$ambiguousParent = [D32NativeDebugProbe]::ValidateSyntheticLedger([D32SyntheticEvent[]]@(
    (New-SyntheticEvent 'CREATE' 50 500),
    (New-SyntheticEvent 'EXIT' 50 500),
    (New-SyntheticEvent 'CREATE' 51 600 50 500),
    (New-SyntheticEvent 'EXIT' 51 600 50 500)
))
$mismatchedExitIdentity = [D32NativeDebugProbe]::ValidateSyntheticLedger([D32SyntheticEvent[]]@(
    (New-SyntheticEvent 'CREATE' 41 100),
    (New-SyntheticEvent 'EXIT' 41 100),
    (New-SyntheticEvent 'CREATE' 41 200),
    (New-SyntheticEvent 'EXIT' 41 100)
))
$missingExitAccountingAccepted = [D32NativeDebugProbe]::ValidateAccounting(
    $toolchainResult.CreateEvents, $toolchainResult.ExitEvents - 1, $toolchainResult.JobTotalProcesses, $toolchainResult.JobActiveProcesses)

$parentChainsValid = $true
foreach ($case in $cases) {
    foreach ($process in $case.Processes) {
        if ($process.ParentPid -eq $case.DebuggerPid) {
            if ($process.ParentCreationTime -ne $case.DebuggerCreationTime) { $parentChainsValid = $false }
        } else {
            $parentRecord = @($case.Processes | Where-Object { $_.Pid -eq $process.ParentPid -and $_.CreationTime -eq $process.ParentCreationTime })
            if ($parentRecord.Count -ne 1) { $parentChainsValid = $false }
        }
    }
}

$prototypeAssertionsPassed = (
    $toolchainResult.State -eq 'COMPLETED' -and $toolchainResult.LedgerConsistent -and
    $toolchainResult.CreateEvents -gt 1 -and
    $allowedHelperResult.State -eq 'COMPLETED' -and $allowedHelperResult.LedgerConsistent -and
    $validPidReuse.Accepted -and -not $overlappingPidReuse.Accepted -and -not $missingExit.Accepted -and
    -not $ambiguousParent.Accepted -and -not $mismatchedExitIdentity.Accepted -and
    -not $missingExitAccountingAccepted -and $parentChainsValid -and
    $unknownHelperResult.State -eq 'BLOCKED' -and $tamperedHelperResult.State -eq 'BLOCKED' -and
    $tamperedHelperPin.VolumeSerial -eq $tamperedImagePin.VolumeSerial -and
    $tamperedHelperPin.FileIndexHigh -eq $tamperedImagePin.FileIndexHigh -and
    $tamperedHelperPin.FileIndexLow -eq $tamperedImagePin.FileIndexLow -and
    $tamperedHelperPin.Sha256 -ne $tamperedImagePin.Sha256 -and
    $scriptOriginalPin.VolumeSerial -eq $scriptTamperedPin.VolumeSerial -and
    $scriptOriginalPin.FileIndexHigh -eq $scriptTamperedPin.FileIndexHigh -and
    $scriptOriginalPin.FileIndexLow -eq $scriptTamperedPin.FileIndexLow -and
    $scriptOriginalPin.Sha256 -ne $scriptTamperedPin.Sha256 -and
    $fastCmdResult.State -eq 'BLOCKED' -and $pathCmdResult.State -eq 'BLOCKED' -and $absoluteCmdResult.State -eq 'BLOCKED' -and
    $interruptResult.State -eq 'BLOCKED' -and
    -not (Test-Path $markerPath) -and -not (Test-Path $unknownHelperMarkerPath) -and -not (Test-Path $tamperedHelperMarkerPath)
)

$report = [pscustomobject]@{
    Candidate = (git -C (Split-Path -Parent $PSScriptRoot) rev-parse HEAD 2>$null)
    TempRoot = $tempRoot
    Pins = @($cargoPin, $rustcPin, $rustLldPin, $cmdPin, $wherePin, $conhostPin, $cscPin, $allowedHelperPin, $unknownParentPin, $tamperedHelperPin) | Where-Object { $null -ne $_ } | ForEach-Object {
        [pscustomobject]@{ Path=$_.Path; Sha256=$_.Sha256; FileId=('{0:x8}:{1:x8}{2:x8}' -f $_.VolumeSerial, $_.FileIndexHigh, $_.FileIndexLow) }
    }
    Cases = @($cases | ForEach-Object {
        [pscustomobject]@{
            Name=$_.Name; State=$_.State; Reason=$_.Reason; DebuggerPid=$_.DebuggerPid; DebuggerCreationTime=$_.DebuggerCreationTime; CreateEvents=$_.CreateEvents; ExitEvents=$_.ExitEvents;
            WaitTimeouts=$_.WaitTimeouts; LastWaitError=$_.LastWaitError;
            JobTotalProcesses=$_.JobTotalProcesses; JobActiveProcesses=$_.JobActiveProcesses;
            JobAccountingAvailable=$_.JobAccountingAvailable; LedgerConsistent=$_.LedgerConsistent;
            Exceptions=@($_.Exceptions | ForEach-Object { [pscustomobject]@{ Pid=$_.Pid; Code=('0x{0:x8}' -f $_.Code); FirstChance=$_.FirstChance; Action=$_.Action } });
            Processes=@($_.Processes | ForEach-Object {
                [pscustomobject]@{ Pid=$_.Pid; ParentPid=$_.ParentPid; ParentCreationTime=$_.ParentCreationTime; CreationTime=$_.CreationTime; ImagePath=$_.ImagePath; Sha256=$_.Sha256; FileId=$_.FileId; Approved=$_.Approved; Exited=$_.Exited; ExitCode=$_.ExitCode }
            })
        }
    })
    MarkersAbsent = -not (Test-Path $markerPath) -and -not (Test-Path $unknownHelperMarkerPath) -and -not (Test-Path $tamperedHelperMarkerPath)
    AllowedGeneratedExecutableReachedEntry = Test-Path $allowedHelperMarkerPath
    DormantCmdPresent = Test-Path $fixturePath
    CargoCheckCompleted = $toolchainResult.State -eq 'COMPLETED'
    TamperedImageSameFileId = $tamperedHelperPin.VolumeSerial -eq $tamperedImagePin.VolumeSerial -and $tamperedHelperPin.FileIndexHigh -eq $tamperedImagePin.FileIndexHigh -and $tamperedHelperPin.FileIndexLow -eq $tamperedImagePin.FileIndexLow
    TamperedImageShaChanged = $tamperedHelperPin.Sha256 -ne $tamperedImagePin.Sha256
    DormantScriptSameFileId = $scriptOriginalPin.VolumeSerial -eq $scriptTamperedPin.VolumeSerial -and $scriptOriginalPin.FileIndexHigh -eq $scriptTamperedPin.FileIndexHigh -and $scriptOriginalPin.FileIndexLow -eq $scriptTamperedPin.FileIndexLow
    DormantScriptShaChanged = $scriptOriginalPin.Sha256 -ne $scriptTamperedPin.Sha256
    SyntheticLedger = [pscustomobject]@{
        ValidPidReuseAccepted=$validPidReuse.Accepted
        OverlappingPidReuseRejected=(-not $overlappingPidReuse.Accepted)
        MissingExitRejected=(-not $missingExit.Accepted)
        AmbiguousParentRejected=(-not $ambiguousParent.Accepted)
        MismatchedExitIdentityRejected=(-not $mismatchedExitIdentity.Accepted)
        DroppedExitAccountingRejected=(-not $missingExitAccountingAccepted)
        Rejections=@($overlappingPidReuse.Reason,$missingExit.Reason,$ambiguousParent.Reason,$mismatchedExitIdentity.Reason)
    }
    ParentChainsValid = $parentChainsValid
    PrototypeAssertionsPassed = $prototypeAssertionsPassed
}
$report | ConvertTo-Json -Depth 8
