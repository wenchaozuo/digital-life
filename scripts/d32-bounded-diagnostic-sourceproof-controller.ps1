# Durable module-free supervisor for one caller-authorized SourceProofOnly run.
# No shell, helper executable, retry, or free-form child argv is accepted.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$CandidateSha,
    [Parameter(Mandatory = $true)][string]$ExecutionAuthorityPath,
    [Parameter(Mandatory = $true)][string]$ExpectedExecutionAuthoritySha256,
    [Parameter(Mandatory = $true)][long]$LifecycleT0Ticks
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$script:D32LifecycleType = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_EXECUTION_AUTHORITY_V1'
$script:D32LifecycleResultType = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_EXECUTION_V1'
$script:D32LifecyclePolicy = 'D32_SOURCEPROOF_LIFECYCLE_V1'
$script:D32LifecycleNow = { [Diagnostics.Stopwatch]::GetTimestamp() }
$script:D32LifecycleOpened = [System.Collections.Generic.List[object]]::new()
$script:D32LifecycleFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
$script:D32LifecycleEvents = [System.Collections.Generic.List[object]]::new()
$script:D32LifecycleSecondary = [System.Collections.Generic.List[string]]::new()
$script:D32LifecyclePrimary = $null
$script:D32LifecycleAuthority = $null
$script:D32LifecycleAuthorityReference = $null
$script:D32LifecycleAdmissionValidated = $false
$script:D32LifecycleNativeProcess = $null
$script:D32LifecycleReaderAttemptCount = 0
$script:D32LifecycleStatus = 'REFUSED'
$script:D32LifecycleJournalStream = $null
$script:D32LifecycleJournalBytes = [long]0
$script:D32LifecycleWrittenResultReference = $null
$script:D32LifecycleStartedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
$script:D32LifecycleCompletedAtUtc = $script:D32LifecycleStartedAtUtc
$script:D32LifecycleClockRecord = $null
$script:D32LifecycleCaptureRecord = [PSCustomObject]@{
    stdout_bytes = [long]0; stdout_sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; stdout_truncated = $false
    stderr_bytes = [long]0; stderr_sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; stderr_truncated = $false
    allowlisted_marker_count = [long]0; output_unavailable = $true
}
$script:D32LifecycleReaderRecord = [PSCustomObject]@{
    launch_attempt_count = [long]0; process_id = $null; creation_filetime_ticks = $null; job_instance_id = $null
    job_assignment = 'NOT_ATTEMPTED'; exit_code = $null
}
$script:D32LifecycleArtifactRecord = [PSCustomObject]@{
    state = 'NOT_READ'; path = ''; bytes = $null; sha256 = $null; volume_serial_hex = $null; file_id_hex = $null; inner_status = $null
}
$script:D32LifecycleCleanupRecord = [PSCustomObject]@{
    state = 'NOT_STARTED'; termination_requested = $false; join_verified = $false
    job_active_process_count = $null; job_closed = $false; kill_on_close_enabled = $false
}
$script:D32LifecycleCleanupRoutineStarted = $false
$script:D32LifecycleControllerEntryTicks = [Diagnostics.Stopwatch]::GetTimestamp()

# The caller captures T0 before invoking this entry. Parameter binding, this
# script's admission, native type initialization, and child creation all spend
# the same fixed window; no child-local restart is accepted.

$nativeSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

public sealed class D32LifecycleCaptureV1 {
    public long Bytes { get; internal set; }
    public bool Truncated { get; internal set; }
    public string Sha256 { get; internal set; }
    public bool Complete { get; internal set; }
    public readonly List<byte> Prefix = new List<byte>(16000);
    public string Failure;
    internal readonly object Sync = new object();
}

public sealed class D32LifecycleOwnedProcessV1 {
    public IntPtr Job;
    public IntPtr Process;
    public IntPtr Thread;
    public IntPtr StdoutRead;
    public IntPtr StderrRead;
    public uint ProcessId;
    public long CreationFileTime;
    public string JobInstanceId;
    public bool JobKillOnClose;
    public bool JobClosedByNative;
    public bool CreateProcessAttempted;
    public long CreateProcessAttemptTicks;
    public long ReaderResumeTicks;
    public long JobAssignmentTicks;
    public bool Assigned;
    public bool Resumed;
    public string Failure;
    public D32LifecycleCaptureV1 Stdout;
    public D32LifecycleCaptureV1 Stderr;
    internal Thread StdoutThread;
    internal Thread StderrThread;
}

public static class D32BoundedSourceProofLifecycleNativeV1 {
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    const int JobObjectBasicAccountingInformation = 1;
    const int JobObjectExtendedLimitInformation = 9;
    const int PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
    const uint HANDLE_FLAG_INHERIT = 0x00000001;
    const uint WAIT_OBJECT_0 = 0;
    const uint WAIT_TIMEOUT = 258;
    const uint STILL_ACTIVE = 259;
    const int ERROR_BROKEN_PIPE = 109;

    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }
    [StructLayout(LayoutKind.Sequential)] struct StartupInfo {
        public int cb; public IntPtr lpReserved; public IntPtr lpDesktop; public IntPtr lpTitle;
        public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars; public uint dwYCountChars;
        public uint dwFillAttribute; public uint dwFlags; public ushort wShowWindow; public ushort cbReserved2;
        public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupInfoEx { public StartupInfo StartupInfo; public IntPtr lpAttributeList; }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInformation { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }
    [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; public long Value { get { return ((long)High << 32) | Low; } } }
    [StructLayout(LayoutKind.Sequential)] struct BasicLimitInformation {
        public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit;
        public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount; public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimitInformation {
        public BasicLimitInformation BasicLimitInformation; public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit; public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed;
    }
    [StructLayout(LayoutKind.Sequential)] struct BasicAccountingInformation {
        public long TotalUserTime; public long TotalKernelTime; public long ThisPeriodTotalUserTime; public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaults; public uint TotalProcesses; public uint ActiveProcesses; public uint TotalTerminatedProcesses;
    }
    [StructLayout(LayoutKind.Sequential)] struct ByHandleFileInformation {
        public uint FileAttributes; public uint CreationTimeLow; public uint CreationTimeHigh; public uint LastAccessTimeLow; public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow; public uint LastWriteTimeHigh; public uint VolumeSerialNumber; public uint FileSizeHigh; public uint FileSizeLow;
        public uint NumberOfLinks; public uint FileIndexHigh; public uint FileIndexLow;
    }
    public sealed class FileIdentity {
        public long Bytes { get; set; }
        public string Sha256 { get; set; }
        public string VolumeSerialHex { get; set; }
        public string FileIdHex { get; set; }
        public uint Attributes { get; set; }
    }

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimitInformation info, uint length);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job, int infoClass, ref BasicAccountingInformation info, uint length, out uint returned);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CreatePipe(out IntPtr readPipe, out IntPtr writePipe, ref SecurityAttributes attributes, uint size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool CreateProcessW(string app, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string currentDirectory, ref StartupInfoEx startup, out ProcessInformation processInformation);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError=true)] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr process, out FileTime creation, out FileTime exit, out FileTime kernel, out FileTime user);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadFile(IntPtr file, byte[] buffer, uint count, out uint read, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr file, out ByHandleFileInformation info);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern uint GetFinalPathNameByHandleW(IntPtr file, StringBuilder path, uint length, uint flags);

    static Exception LastError(string name) { return new Win32Exception(Marshal.GetLastWin32Error(), name); }
    static bool Close(ref IntPtr handle) {
        if (handle == IntPtr.Zero) return true;
        if (!CloseHandle(handle)) return false;
        handle = IntPtr.Zero;
        return true;
    }

    public static FileIdentity GetPathIdentity(IntPtr handle) {
        ByHandleFileInformation info;
        if (!GetFileInformationByHandle(handle, out info)) throw LastError("GetFileInformationByHandle failed");
        ulong fileId = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
        ulong size = ((ulong)info.FileSizeHigh << 32) | info.FileSizeLow;
        return new FileIdentity { Bytes = checked((long)size), VolumeSerialHex = info.VolumeSerialNumber.ToString("x16"), FileIdHex = fileId.ToString("x32"), Attributes = info.FileAttributes };
    }

    public static FileIdentity GetDirectoryIdentity(string path) {
        IntPtr handle = CreateFileW(path, 0x00000080, 0x00000007, IntPtr.Zero, 3, 0x02000000 | 0x00200000, IntPtr.Zero);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) throw LastError("open directory identity failed");
        try {
            FileIdentity identity = GetPathIdentity(handle);
            if ((identity.Attributes & 0x10) == 0 || (identity.Attributes & 0x400) != 0) throw new IOException("directory is not a non-reparse directory object");
            StringBuilder finalPath = new StringBuilder(32768); uint length = GetFinalPathNameByHandleW(handle, finalPath, (uint)finalPath.Capacity, 0);
            if (length == 0 || length >= finalPath.Capacity) throw LastError("GetFinalPathNameByHandleW(directory) failed");
            string actual = finalPath.ToString();
            if (actual.StartsWith("\\\\?\\", StringComparison.Ordinal)) actual = actual.Substring(4);
            if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(actual), Path.GetFullPath(path))) throw new IOException("directory final path differs from requested path");
            return identity;
        } finally { CloseHandle(handle); }
    }

    public static string QuoteArgument(string value) {
        if (value == null) value = "";
        if (value.Length > 0 && value.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0) return value;
        StringBuilder result = new StringBuilder(); result.Append('"'); int slashes = 0;
        foreach (char ch in value) {
            if (ch == '\\') { slashes++; continue; }
            if (ch == '"') { result.Append('\\', slashes * 2 + 1); result.Append('"'); slashes = 0; continue; }
            result.Append('\\', slashes); slashes = 0; result.Append(ch);
        }
        result.Append('\\', slashes * 2); result.Append('"'); return result.ToString();
    }

    static void CaptureLoop(IntPtr read, D32LifecycleCaptureV1 capture) {
        byte[] buffer = new byte[4096]; long total = 0;
        try {
            while (true) {
                uint got; bool ok = ReadFile(read, buffer, (uint)buffer.Length, out got, IntPtr.Zero);
                if (!ok) { int error = Marshal.GetLastWin32Error(); if (error != ERROR_BROKEN_PIPE) throw new Win32Exception(error); break; }
                if (got == 0) break;
                lock (capture.Sync) {
                    int keep = Math.Min((int)got, Math.Max(0, 16000 - capture.Prefix.Count));
                    for (int i = 0; i < keep; i++) capture.Prefix.Add(buffer[i]);
                    total = Math.Min(Int64.MaxValue, total + got);
                    if (total > 16000) capture.Truncated = true;
                }
            }
        } catch (Exception ex) { capture.Truncated = true; capture.Failure = ex.GetType().Name; }
        finally {
            lock (capture.Sync) {
                capture.Bytes = capture.Prefix.Count;
                capture.Sha256 = BitConverter.ToString(SHA256.HashData(capture.Prefix.ToArray())).Replace("-", "").ToLowerInvariant();
                capture.Complete = true;
            }
        }
    }

    static bool InitPipe(out IntPtr read, out IntPtr write) {
        SecurityAttributes sa = new SecurityAttributes(); sa.nLength = Marshal.SizeOf<SecurityAttributes>(); sa.bInheritHandle = 1;
        if (!CreatePipe(out read, out write, ref sa, 0)) throw LastError("CreatePipe failed");
        if (!SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0)) { Close(ref read); Close(ref write); throw LastError("SetHandleInformation(pipe read end) failed"); }
        return true;
    }

    public static D32LifecycleOwnedProcessV1 StartSuspendedAssignedAndResume(string image, string commandLine, string workingDirectory, string environmentBlock, long workDeadlineTicks) {
        D32LifecycleOwnedProcessV1 owned = new D32LifecycleOwnedProcessV1();
        IntPtr stdin = IntPtr.Zero, stdoutWrite = IntPtr.Zero, stderrWrite = IntPtr.Zero, attr = IntPtr.Zero, attrValue = IntPtr.Zero, env = IntPtr.Zero;
        ProcessInformation pi = new ProcessInformation();
        try {
            owned.Job = CreateJobObjectW(IntPtr.Zero, null); if (owned.Job == IntPtr.Zero) throw LastError("CreateJobObjectW failed");
            ExtendedLimitInformation limits = new ExtendedLimitInformation(); limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!SetInformationJobObject(owned.Job, JobObjectExtendedLimitInformation, ref limits, (uint)Marshal.SizeOf<ExtendedLimitInformation>())) throw LastError("SetInformationJobObject(KILL_ON_JOB_CLOSE) failed");
            owned.JobKillOnClose = true; owned.JobInstanceId = Guid.NewGuid().ToString("N");
            SecurityAttributes sa = new SecurityAttributes(); sa.nLength = Marshal.SizeOf<SecurityAttributes>(); sa.bInheritHandle = 1;
            stdin = CreateFileW("NUL", 0x80000000, 3, IntPtr.Zero, 3, 0x80, IntPtr.Zero); if (stdin == new IntPtr(-1)) throw LastError("open NUL stdin failed");
            InitPipe(out owned.StdoutRead, out stdoutWrite); InitPipe(out owned.StderrRead, out stderrWrite);
            IntPtr size = IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            attr = Marshal.AllocHGlobal(size); if (!InitializeProcThreadAttributeList(attr, 1, 0, ref size)) throw LastError("InitializeProcThreadAttributeList failed");
            attrValue = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(attrValue, 0, stdin); Marshal.WriteIntPtr(attrValue, IntPtr.Size, stdoutWrite); Marshal.WriteIntPtr(attrValue, IntPtr.Size * 2, stderrWrite);
            if (!UpdateProcThreadAttribute(attr, 0, new IntPtr(PROC_THREAD_ATTRIBUTE_HANDLE_LIST), attrValue, new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero)) throw LastError("UpdateProcThreadAttribute(handle list) failed");
            env = Marshal.StringToHGlobalUni(environmentBlock);
            StartupInfoEx startup = new StartupInfoEx(); startup.StartupInfo.cb = Marshal.SizeOf<StartupInfoEx>(); startup.StartupInfo.dwFlags = 0x00000100;
            startup.StartupInfo.hStdInput = stdin; startup.StartupInfo.hStdOutput = stdoutWrite; startup.StartupInfo.hStdError = stderrWrite; startup.lpAttributeList = attr;
            if (System.Diagnostics.Stopwatch.GetTimestamp() >= workDeadlineTicks) throw new TimeoutException("proof-work cutoff reached before the single CreateProcess attempt");
            owned.Failure = null; // the sole CreateProcess attempt begins here
            owned.CreateProcessAttemptTicks = System.Diagnostics.Stopwatch.GetTimestamp();
            owned.CreateProcessAttempted = true;
            if (!CreateProcessW(image, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, true,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                env, workingDirectory, ref startup, out pi)) { owned.Failure = LastError("CreateProcessW failed").Message; return owned; }
            owned.Process = pi.hProcess; owned.Thread = pi.hThread; owned.ProcessId = pi.dwProcessId;
            FileTime created, exited, kernel, user;
            if (!GetProcessTimes(owned.Process, out created, out exited, out kernel, out user)) { owned.Failure = LastError("GetProcessTimes(reader) failed").Message; TerminateProcess(owned.Process, 0xD3203001); return owned; }
            owned.CreationFileTime = created.Value;
            if (!AssignProcessToJobObject(owned.Job, owned.Process)) { owned.Failure = LastError("AssignProcessToJobObject failed").Message; TerminateProcess(owned.Process, 0xD3203002); return owned; }
            owned.Assigned = true;
            owned.JobAssignmentTicks = System.Diagnostics.Stopwatch.GetTimestamp();
            if (System.Diagnostics.Stopwatch.GetTimestamp() >= workDeadlineTicks) { owned.Failure = "proof-work cutoff reached before reader resume"; TerminateJobObject(owned.Job, 0xD3203006); return owned; }
            uint previousSuspendCount = ResumeThread(owned.Thread);
            if (previousSuspendCount != 1) { owned.Failure = previousSuspendCount == UInt32.MaxValue ? LastError("ResumeThread failed").Message : "ResumeThread did not observe exactly one suspended count"; TerminateJobObject(owned.Job, 0xD3203003); return owned; }
            owned.Resumed = true;
            owned.ReaderResumeTicks = System.Diagnostics.Stopwatch.GetTimestamp();
            owned.Stdout = new D32LifecycleCaptureV1(); owned.Stderr = new D32LifecycleCaptureV1();
            owned.StdoutThread = new Thread(() => CaptureLoop(owned.StdoutRead, owned.Stdout)); owned.StdoutThread.IsBackground = true; owned.StdoutThread.Start();
            owned.StderrThread = new Thread(() => CaptureLoop(owned.StderrRead, owned.Stderr)); owned.StderrThread.IsBackground = true; owned.StderrThread.Start();
            return owned;
        }
        catch (Exception ex) { owned.Failure = ex.GetType().Name + ": " + ex.Message; return owned; }
        finally {
            Close(ref stdin); Close(ref stdoutWrite); Close(ref stderrWrite);
            if (attr != IntPtr.Zero) { DeleteProcThreadAttributeList(attr); Marshal.FreeHGlobal(attr); }
            if (attrValue != IntPtr.Zero) Marshal.FreeHGlobal(attrValue);
            if (env != IntPtr.Zero) Marshal.FreeHGlobal(env);
            if (owned.Failure != null && owned.Process == IntPtr.Zero) { Close(ref owned.StdoutRead); Close(ref owned.StderrRead); Close(ref owned.Job); owned.JobClosedByNative = true; }
        }
    }

    public static uint Wait(IntPtr process, uint milliseconds) { return WaitForSingleObject(process, milliseconds); }
    public static bool IsSignaled(IntPtr process) { return process != IntPtr.Zero && WaitForSingleObject(process, 0) == WAIT_OBJECT_0; }
    public static int? ExitCode(IntPtr process) { uint code; return GetExitCodeProcess(process, out code) ? (int?)code : null; }
    public static bool TerminateJob(IntPtr job, uint code) { return job != IntPtr.Zero && TerminateJobObject(job, code); }
    public static bool TerminateExactProcess(IntPtr process, uint code) { return process != IntPtr.Zero && TerminateProcess(process, code); }
    public static int? ActiveProcesses(IntPtr job) { BasicAccountingInformation info = new BasicAccountingInformation(); uint returned; return QueryInformationJobObject(job, JobObjectBasicAccountingInformation, ref info, (uint)Marshal.SizeOf<BasicAccountingInformation>(), out returned) ? (int?)info.ActiveProcesses : null; }
    public static bool JoinCaptures(D32LifecycleOwnedProcessV1 process, int milliseconds) {
        bool a = process.StdoutThread == null || process.StdoutThread.Join(milliseconds);
        bool b = process.StderrThread == null || process.StderrThread.Join(Math.Max(0, milliseconds));
        return a && b;
    }
    public static bool CloseJob(D32LifecycleOwnedProcessV1 process) {
        if (process.Job == IntPtr.Zero) return process.JobClosedByNative;
        if (!Close(ref process.Job)) return false;
        process.JobClosedByNative = true;
        return true;
    }
    public static bool CloseAll(D32LifecycleOwnedProcessV1 process) {
        if (process == null) return true;
        bool closed = Close(ref process.Thread);
        closed = Close(ref process.Process) && closed;
        closed = Close(ref process.StdoutRead) && closed;
        closed = Close(ref process.StderrRead) && closed;
        closed = CloseJob(process) && closed;
        return closed;
    }
    public static void CloseJobHandleIfFailed(D32LifecycleOwnedProcessV1 process) { if (process != null && process.Failure != null) CloseJob(process); }
}
'@

function Test-D32LifecycleNoReparsePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $full = [IO.Path]::GetFullPath($Path)
        if ($full -cne $Path) { return $false }
        $root = [IO.Path]::GetPathRoot($full); $current = $root
        foreach ($part in @($full.Substring($root.Length) -split '[\\/]+' )) {
            if ([String]::IsNullOrWhiteSpace($part)) { continue }
            $current = [IO.Path]::Combine($current, $part)
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        }
        return $true
    } catch { return $false }
}

function ConvertFrom-D32LifecycleJsonElement {
    param([System.Text.Json.JsonElement]$Element)
    switch ($Element.ValueKind) {
        'Object' {
            $ordered = [ordered]@{}
            foreach ($property in $Element.EnumerateObject()) { $ordered.Add($property.Name, (ConvertFrom-D32LifecycleJsonElement -Element $property.Value)) }
            return [PSCustomObject]$ordered
        }
        'Array' { $items = [System.Collections.Generic.List[object]]::new(); foreach ($item in $Element.EnumerateArray()) { $items.Add((ConvertFrom-D32LifecycleJsonElement -Element $item)) }; return ,$items.ToArray() }
        'String' { return $Element.GetString() }
        'Number' { [Int64]$integer = 0; if ($Element.TryGetInt64([ref]$integer)) { return $integer }; return $null }
        'True' { return $true }
        'False' { return $false }
        default { return $null }
    }
}

function Test-D32LifecycleJsonDuplicates {
    param([System.Text.Json.JsonElement]$Element)
    switch ($Element.ValueKind) {
        'Object' {
            $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($property in $Element.EnumerateObject()) { if (-not $names.Add($property.Name) -or (Test-D32LifecycleJsonDuplicates -Element $property.Value)) { return $true } }
        }
        'Array' { foreach ($item in $Element.EnumerateArray()) { if (Test-D32LifecycleJsonDuplicates -Element $item) { return $true } } }
    }
    return $false
}

function Get-D32LifecycleNow { return [Int64](& $script:D32LifecycleNow) }
function Get-D32LifecycleReferenceBytes {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][long]$MaximumBytes,
        [Parameter(Mandatory = $true)][long]$DeadlineTicks)
    if ((Get-D32LifecycleNow) -ge $DeadlineTicks) { throw 'D32_SOURCEPROOF_LIFECYCLE_BUDGET_STOPPED: source-proof work cutoff reached before bounded input read' }
    if (-not (Test-D32LifecycleNoReparsePath -Path $Path)) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: path is noncanonical, missing, or reparse-backed' }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $identity = [D32BoundedSourceProofLifecycleNativeV1]::GetPathIdentity($stream.SafeFileHandle.DangerousGetHandle())
        if ($identity.Bytes -le 0 -or $identity.Bytes -gt $MaximumBytes) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: bounded input byte count is outside the fixed limit' }
        $bytes = [byte[]]::new([int]$identity.Bytes); $offset = 0
        while ($offset -lt $bytes.Length) {
            if ((Get-D32LifecycleNow) -ge $DeadlineTicks) { throw 'D32_SOURCEPROOF_LIFECYCLE_BUDGET_STOPPED: source-proof work cutoff reached before bounded input read' }
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: opened input ended before its pinned length' }
            if ((Get-D32LifecycleNow) -ge $DeadlineTicks) { throw 'D32_SOURCEPROOF_LIFECYCLE_BUDGET_STOPPED: late bounded input bytes discarded before hashing' }
            $offset += $read
        }
        if ((Get-D32LifecycleNow) -ge $DeadlineTicks) { throw 'D32_SOURCEPROOF_LIFECYCLE_BUDGET_STOPPED: late bounded input bytes discarded before hashing' }
        if ($stream.Length -ne $identity.Bytes) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: opened input length changed during bounded read' }
        $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        return [PSCustomObject]@{ Stream = $stream; Bytes = $bytes; Reference = [PSCustomObject]@{
            path = $Path; bytes = [Int64]$identity.Bytes; sha256 = $sha
            volume_serial_hex = [string]$identity.VolumeSerialHex; file_id_hex = [string]$identity.FileIdHex
        } }
    } catch { $stream.Dispose(); throw }
}

function Add-D32LifecycleEvent {
    param([Parameter(Mandatory = $true)][string]$Name, [AllowNull()][long]$ScheduledTicks = $null)
    $observed = Get-D32LifecycleNow
    if ($null -ne $ScheduledTicks -and $observed -lt $ScheduledTicks) { throw 'D32_SOURCEPROOF_LIFECYCLE_BLOCKED: observed monotonic counter precedes scheduled boundary' }
    $lateness = if ($null -eq $ScheduledTicks) { $null } else { [Int64]($observed - $ScheduledTicks) }
    if ($script:D32LifecycleEvents.Count -ge 16) { throw 'D32_SOURCEPROOF_LIFECYCLE_UNRESOLVED: bounded event record limit reached' }
    $script:D32LifecycleEvents.Add([PSCustomObject][ordered]@{ event = $Name; scheduled_ticks = $ScheduledTicks; observed_ticks = [Int64]$observed; lateness_ticks = $lateness })
    return [Int64]$observed
}

function Add-D32LifecycleJournalFact {
    param([Parameter(Mandatory = $true)][string]$Event, [Parameter(Mandatory = $true)][long]$ObservedTicks, [AllowNull()][long]$ScheduledTicks = $null)
    if ($null -eq $script:D32LifecycleJournalStream) { return }
    $fact = [PSCustomObject][ordered]@{ event = $Event; observed_ticks = $ObservedTicks; scheduled_ticks = $ScheduledTicks; gate_authority = 'NONE' }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $fact -Depth 8 -Compress) + "`n")
    if ($script:D32LifecycleJournalBytes + $bytes.Length -gt 65536) { throw 'D32_SOURCEPROOF_LIFECYCLE_UNRESOLVED: journal byte ceiling reached' }
    $script:D32LifecycleJournalStream.Write($bytes, 0, $bytes.Length); $script:D32LifecycleJournalStream.Flush($true)
    $script:D32LifecycleJournalBytes += $bytes.Length
}

function Get-D32LifecycleProcessCreationFileTime {
    $process = [Diagnostics.Process]::GetCurrentProcess()
    try { return [Int64]$process.StartTime.ToFileTime() } finally { $process.Dispose() }
}

function Get-D32LifecycleDirectoryIdentity {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-D32LifecycleNoReparsePath -Path $Path)) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: output parent is missing, noncanonical, or reparse-backed' }
    return [D32BoundedSourceProofLifecycleNativeV1]::GetDirectoryIdentity($Path)
}

function Close-D32LifecycleAdmissionHandles {
    foreach ($opened in $script:D32LifecycleOpened) {
        if ($null -ne $opened.Stream -and -not $opened.Stream.SafeFileHandle.IsClosed) { $opened.Stream.Dispose() }
    }
    foreach ($fence in $script:D32LifecycleFences.Values) {
        if ($null -ne $fence.Handle -and -not $fence.Handle.IsClosed) { $fence.Handle.Dispose() }
    }
}

function Close-D32LifecycleJournalStream {
    if ($null -eq $script:D32LifecycleJournalStream) { return $true }
    try {
        $script:D32LifecycleJournalStream.Flush($true)
        $script:D32LifecycleJournalStream.Dispose()
        $script:D32LifecycleJournalStream = $null
        return $true
    } catch { return $false }
}

function Copy-D32LifecycleCaptureMetadata {
    if ($null -eq $script:D32LifecycleNativeProcess -or $null -eq $script:D32LifecycleNativeProcess.Stdout -or
        $null -eq $script:D32LifecycleNativeProcess.Stderr -or -not [D32BoundedSourceProofLifecycleNativeV1]::JoinCaptures($script:D32LifecycleNativeProcess, 0)) {
        $script:D32LifecycleCaptureRecord.output_unavailable = $true
        return $false
    }
    $script:D32LifecycleCaptureRecord.stdout_bytes = [Int64]$script:D32LifecycleNativeProcess.Stdout.Bytes
    $script:D32LifecycleCaptureRecord.stdout_sha256 = [string]$script:D32LifecycleNativeProcess.Stdout.Sha256
    $script:D32LifecycleCaptureRecord.stdout_truncated = [bool]$script:D32LifecycleNativeProcess.Stdout.Truncated
    $script:D32LifecycleCaptureRecord.stderr_bytes = [Int64]$script:D32LifecycleNativeProcess.Stderr.Bytes
    $script:D32LifecycleCaptureRecord.stderr_sha256 = [string]$script:D32LifecycleNativeProcess.Stderr.Sha256
    $script:D32LifecycleCaptureRecord.stderr_truncated = [bool]$script:D32LifecycleNativeProcess.Stderr.Truncated
    $markerMatches = [regex]::Matches([Text.Encoding]::UTF8.GetString($script:D32LifecycleNativeProcess.Stdout.Prefix.ToArray()), 'D32SP1 p=')
    $script:D32LifecycleCaptureRecord.allowlisted_marker_count = [long][Math]::Min(256, $markerMatches.Count)
    $script:D32LifecycleCaptureRecord.output_unavailable = (-not [String]::IsNullOrEmpty([string]$script:D32LifecycleNativeProcess.Stdout.Failure) -or
        -not [String]::IsNullOrEmpty([string]$script:D32LifecycleNativeProcess.Stderr.Failure))
    return (-not $script:D32LifecycleCaptureRecord.output_unavailable)
}

function Get-D32LifecycleErrorText {
    param([System.Exception]$Exception)
    $text = if ($null -eq $Exception) { 'unspecified lifecycle failure' } else { ([string]$Exception.GetType().Name + ': ' + [string]$Exception.Message) }
    $text = [regex]::Replace($text, '[\r\n\t]', ' ')
    if ($text.Length -gt 2048) { $text = $text.Substring(0, 2048) }
    return $text
}

function Write-D32LifecycleFinalRecord {
    if ($null -eq $script:D32LifecycleAuthority -or $null -eq $script:D32LifecycleAuthorityReference) { return $false }
    $now = Get-D32LifecycleNow
    if ($now -ge [Int64]$script:D32LifecycleClockRecord.terminal_audit_deadline_ticks) { return $false }
    $parentNow = Get-D32LifecycleDirectoryIdentity ([string]$script:D32LifecycleAuthority.output.parent_path)
    if ($parentNow.VolumeSerialHex -cne [string]$script:D32LifecycleAuthority.output.parent_volume_serial_hex -or
        $parentNow.FileIdHex -cne [string]$script:D32LifecycleAuthority.output.parent_file_id_hex -or
        [IO.File]::Exists([string]$script:D32LifecycleAuthority.output.execution_record_path) -or
        [IO.Directory]::Exists([string]$script:D32LifecycleAuthority.output.execution_record_path)) { return $false }
    $script:D32LifecycleCompletedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
    $record = [PSCustomObject][ordered]@{
        schema_version = 1; record_type = $script:D32LifecycleResultType; timing_policy = $script:D32LifecyclePolicy; gate_authority = 'NONE'
        candidate_sha = $script:D32LifecycleAuthority.candidate_sha; run_id = $script:D32LifecycleAuthority.run_id
        authority = $script:D32LifecycleAuthorityReference
        status = $script:D32LifecycleStatus
        source_pins = @($script:D32LifecycleAuthority.source_pins)
        powershell_runtime = [PSCustomObject]@{ path = $script:D32LifecycleAuthority.powershell_runtime.path; bytes = $script:D32LifecycleAuthority.powershell_runtime.bytes; sha256 = $script:D32LifecycleAuthority.powershell_runtime.sha256; volume_serial_hex = $script:D32LifecycleAuthority.powershell_runtime.volume_serial_hex; file_id_hex = $script:D32LifecycleAuthority.powershell_runtime.file_id_hex }
        output = $script:D32LifecycleAuthority.output
        clock = $script:D32LifecycleClockRecord
        controller = [PSCustomObject]@{ process_id = [Int64]$PID; creation_filetime_ticks = (Get-D32LifecycleProcessCreationFileTime) }
        reader = $script:D32LifecycleReaderRecord
        artifact = $script:D32LifecycleArtifactRecord
        captures = $script:D32LifecycleCaptureRecord
        cleanup = $script:D32LifecycleCleanupRecord
        events = @($script:D32LifecycleEvents.ToArray())
        primary_error = $script:D32LifecyclePrimary
        secondary_errors = @($script:D32LifecycleSecondary.ToArray())
        started_at_utc = $script:D32LifecycleStartedAtUtc; completed_at_utc = $script:D32LifecycleCompletedAtUtc
    }
    if (-not (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $record)) { throw 'D32_SOURCEPROOF_LIFECYCLE_UNRESOLVED: final execution record failed its exact in-memory schema' }
    $json = ConvertTo-Json -InputObject $record -Depth 100 -Compress -ErrorAction Stop
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    if ($bytes.Length -gt 65536 -or (Get-D32LifecycleNow) -ge [Int64]$script:D32LifecycleClockRecord.terminal_audit_deadline_ticks) { return $false }
    $path = [string]$script:D32LifecycleAuthority.output.execution_record_path
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    # The record cannot contain the tick at which its own flush returned.
    # Retain only its bounded artifact reference so a separate final journal
    # fact can bind the already-completed create-new write without rewriting
    # the execution record.
    $persistedAt = Get-D32LifecycleNow
    $script:D32LifecycleWrittenResultReference = [PSCustomObject][ordered]@{
        path = $path; bytes = [Int64]$bytes.Length
        sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        persisted_observed_ticks = [Int64]$persistedAt
    }
    return ($persistedAt -lt [Int64]$script:D32LifecycleClockRecord.terminal_audit_deadline_ticks)
}

function Add-D32LifecycleExecutionRecordPersistedFact {
    if ($null -eq $script:D32LifecycleJournalStream -or $null -eq $script:D32LifecycleWrittenResultReference) { return $false }
    $reference = $script:D32LifecycleWrittenResultReference
    $scheduled = [Int64]$script:D32LifecycleClockRecord.cleanup_deadline_ticks
    $deadline = [Int64]$script:D32LifecycleClockRecord.terminal_audit_deadline_ticks
    $observed = [Int64]$reference.persisted_observed_ticks
    if ($observed -lt $scheduled -or $observed -ge $deadline -or (Get-D32LifecycleNow) -ge $deadline) { return $false }
    $fact = [PSCustomObject][ordered]@{
        event = 'EXECUTION_RECORD_PERSISTED'; scheduled_ticks = $scheduled
        observed_ticks = $observed; lateness_ticks = [Int64]($observed - $scheduled)
        deadline_ticks = $deadline; remaining_ticks = [Int64]($deadline - $observed)
        execution_record_path = [string]$reference.path; execution_record_bytes = [Int64]$reference.bytes
        execution_record_sha256 = [string]$reference.sha256; gate_authority = 'NONE'
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $fact -Depth 8 -Compress) + "`n")
    if ($script:D32LifecycleJournalBytes + $bytes.Length -gt 65536 -or (Get-D32LifecycleNow) -ge $scheduled) { return $false }
    $script:D32LifecycleJournalStream.Write($bytes, 0, $bytes.Length)
    $script:D32LifecycleJournalStream.Flush($true)
    $script:D32LifecycleJournalBytes += $bytes.Length
    return ((Get-D32LifecycleNow) -lt $scheduled)
}

function Test-D32LifecycleOwnedCleanupReady {
    if ($null -eq $script:D32LifecycleNativeProcess) { return $false }
    $native = $script:D32LifecycleNativeProcess
    $hasProcess = $native.Process -ne [IntPtr]::Zero
    $signaled = $hasProcess -and [D32BoundedSourceProofLifecycleNativeV1]::IsSignaled($native.Process)
    if ($hasProcess -and -not $signaled) { return $false }
    if ($signaled) {
        if ($null -eq $script:D32LifecycleClockRecord.reader_exit_ticks) { $script:D32LifecycleClockRecord.reader_exit_ticks = Get-D32LifecycleNow }
        $script:D32LifecycleReaderRecord.exit_code = [D32BoundedSourceProofLifecycleNativeV1]::ExitCode($native.Process)
        if (@($script:D32LifecycleEvents | Where-Object { $_.event -ceq 'READER_EXIT' }).Count -eq 0) {
            $readerExitObserved = Add-D32LifecycleEvent -Name 'READER_EXIT'
            Add-D32LifecycleJournalFact -Event 'READER_EXIT' -ObservedTicks $readerExitObserved
        }
    }
    if ($native.Job -ne [IntPtr]::Zero) {
        $active = [D32BoundedSourceProofLifecycleNativeV1]::ActiveProcesses($native.Job)
        if ($null -eq $active -or [Int32]$active -ne 0) {
            $script:D32LifecycleCleanupRecord.job_active_process_count = $active
            return $false
        }
        $script:D32LifecycleCleanupRecord.job_active_process_count = 0
    } elseif ($hasProcess -and $native.Assigned) { return $false }
    if (-not [D32BoundedSourceProofLifecycleNativeV1]::JoinCaptures($native, 0)) { return $false }
    if ($hasProcess -and -not $native.JobKillOnClose) { return $false }

    if ($hasProcess) { $null = Copy-D32LifecycleCaptureMetadata }
    $jobClosed = [D32BoundedSourceProofLifecycleNativeV1]::CloseJob($native)
    if (-not $jobClosed) { return $false }
    if (-not [D32BoundedSourceProofLifecycleNativeV1]::CloseAll($native)) { return $false }

    $script:D32LifecycleCleanupRecord.state = 'VERIFIED'
    $script:D32LifecycleCleanupRecord.join_verified = $true
    $script:D32LifecycleCleanupRecord.job_active_process_count = 0
    $script:D32LifecycleCleanupRecord.job_closed = $true
    $script:D32LifecycleCleanupRecord.kill_on_close_enabled = [bool]$native.JobKillOnClose
    $script:D32LifecycleClockRecord.cleanup_verified_ticks = Get-D32LifecycleNow
    $null = Add-D32LifecycleEvent -Name 'CLEANUP_VERIFIED'
    return $true
}

function Add-D32LifecycleProofExpiryIfDue {
    $now = Get-D32LifecycleNow
    if ($now -ge [Int64]$script:D32LifecycleClockRecord.work_deadline_ticks -and
        @($script:D32LifecycleEvents | Where-Object { $_.event -ceq 'WORK_CUTOFF' }).Count -eq 0) {
        $workObserved = Add-D32LifecycleEvent -Name 'WORK_CUTOFF' -ScheduledTicks ([Int64]$script:D32LifecycleClockRecord.work_deadline_ticks)
        Add-D32LifecycleJournalFact -Event 'WORK_CUTOFF' -ObservedTicks $workObserved -ScheduledTicks ([Int64]$script:D32LifecycleClockRecord.work_deadline_ticks)
    }
    if ($now -ge [Int64]$script:D32LifecycleClockRecord.proof_expiry_ticks -and
        @($script:D32LifecycleEvents | Where-Object { $_.event -ceq 'PROOF_EXPIRY' }).Count -eq 0) {
        $expiryObserved = Add-D32LifecycleEvent -Name 'PROOF_EXPIRY' -ScheduledTicks ([Int64]$script:D32LifecycleClockRecord.proof_expiry_ticks)
        Add-D32LifecycleJournalFact -Event 'PROOF_EXPIRY' -ObservedTicks $expiryObserved -ScheduledTicks ([Int64]$script:D32LifecycleClockRecord.proof_expiry_ticks)
    }
}

function Request-D32LifecycleOwnedTermination {
    if ($null -eq $script:D32LifecycleNativeProcess -or $script:D32LifecycleCleanupRecord.termination_requested) { return }
    $native = $script:D32LifecycleNativeProcess
    $script:D32LifecycleCleanupRecord.termination_requested = $true
    $scheduled = [Int64]$script:D32LifecycleClockRecord.proof_expiry_ticks
    $observed = Add-D32LifecycleEvent -Name 'TERMINATION_REQUEST' -ScheduledTicks $scheduled
    $ok = $true
    if ($native.Process -ne [IntPtr]::Zero -and -not $native.Assigned) { $ok = [D32BoundedSourceProofLifecycleNativeV1]::TerminateExactProcess($native.Process, 0xD3203004) }
    elseif ($native.Job -ne [IntPtr]::Zero) { $ok = [D32BoundedSourceProofLifecycleNativeV1]::TerminateJob($native.Job, 0xD3203004) }
    elseif ($native.Process -ne [IntPtr]::Zero) { $ok = [D32BoundedSourceProofLifecycleNativeV1]::TerminateExactProcess($native.Process, 0xD3203004) }
    if (-not $ok -and $script:D32LifecycleSecondary.Count -lt 8) {
        $script:D32LifecycleSecondary.Add('exact retained process or Job termination request failed')
    }
    Add-D32LifecycleJournalFact -Event 'TERMINATION_REQUEST' -ObservedTicks $observed -ScheduledTicks $scheduled
}

function Invoke-D32LifecycleCleanupAndAudit {
    if ($null -eq $script:D32LifecycleClockRecord) { return }
    if ($script:D32LifecycleCleanupRoutineStarted) { throw 'D32_SOURCEPROOF_LIFECYCLE_UNRESOLVED: cleanup routine is single-entry and cannot be retried' }
    $script:D32LifecycleCleanupRoutineStarted = $true
    $cleanupDeadline = [Int64]$script:D32LifecycleClockRecord.cleanup_deadline_ticks
    $expiryDeadline = [Int64]$script:D32LifecycleClockRecord.proof_expiry_ticks
    $terminalDeadline = [Int64]$script:D32LifecycleClockRecord.terminal_audit_deadline_ticks
    $cleanupVerified = $false

    if ((Get-D32LifecycleNow) -lt $cleanupDeadline) { Close-D32LifecycleAdmissionHandles }
    Add-D32LifecycleProofExpiryIfDue

    $hasNativeHandle = ($null -ne $script:D32LifecycleNativeProcess -and
        ($script:D32LifecycleNativeProcess.Process -ne [IntPtr]::Zero -or $script:D32LifecycleNativeProcess.Job -ne [IntPtr]::Zero))
    if ($hasNativeHandle) {
        while ((Get-D32LifecycleNow) -lt $expiryDeadline) {
            if (Test-D32LifecycleOwnedCleanupReady) { $cleanupVerified = $true; break }
            $now = Get-D32LifecycleNow
            if ($now -ge $expiryDeadline) { break }
            $remaining = [Int64]($expiryDeadline - $now)
            $native = $script:D32LifecycleNativeProcess
            if ($native.Process -ne [IntPtr]::Zero -and -not [D32BoundedSourceProofLifecycleNativeV1]::IsSignaled($native.Process)) {
                $null = [D32BoundedSourceProofLifecycleNativeV1]::Wait($native.Process, [uint32][Math]::Min(100, [Math]::Max(1, $remaining * 1000.0 / [Diagnostics.Stopwatch]::Frequency)))
            } else { Start-Sleep -Milliseconds ([int][Math]::Min(10, [Math]::Max(1, [Math]::Ceiling($remaining * 1000.0 / [Diagnostics.Stopwatch]::Frequency)))) }
        }
        Add-D32LifecycleProofExpiryIfDue
        if (-not $cleanupVerified -and (Get-D32LifecycleNow) -ge $expiryDeadline) {
            if ($script:D32LifecycleStatus -eq 'COMPLETED_DIAGNOSTIC_ONLY') {
                $script:D32LifecycleStatus = 'UNRESOLVED'
                if (-not $script:D32LifecyclePrimary) { $script:D32LifecyclePrimary = 'The complete candidate did not have owned-process cleanup verified by the 300-second proof expiry.' }
            } elseif ($script:D32LifecycleReaderAttemptCount -gt 0 -and $script:D32LifecycleStatus -notin @('BUDGET_STOPPED', 'REFUSED')) {
                $script:D32LifecycleStatus = 'UNRESOLVED'
                if (-not $script:D32LifecyclePrimary) { $script:D32LifecyclePrimary = 'Proof completion or reader cleanup was not verified by the 300-second proof expiry.' }
            } elseif ($script:D32LifecycleReaderAttemptCount -gt 0 -and -not $script:D32LifecyclePrimary) {
                $script:D32LifecyclePrimary = 'The 300-second proof expiry was reached before reader completion and cleanup verification.'
            }
            if ($script:D32LifecycleReaderAttemptCount -gt 0) { Request-D32LifecycleOwnedTermination }
        }
        if ($cleanupVerified -and [Int64]$script:D32LifecycleClockRecord.cleanup_verified_ticks -ge $expiryDeadline -and
            $script:D32LifecycleStatus -eq 'COMPLETED_DIAGNOSTIC_ONLY') {
            $script:D32LifecycleStatus = 'UNRESOLVED'
            if (-not $script:D32LifecyclePrimary) { $script:D32LifecyclePrimary = 'Owned cleanup completed at or after the 300-second proof-expiry boundary.' }
        }
        if ($cleanupVerified -and $script:D32LifecycleCaptureRecord.output_unavailable -and
            $script:D32LifecycleStatus -eq 'COMPLETED_DIAGNOSTIC_ONLY') {
            $script:D32LifecycleStatus = 'UNRESOLVED'
            if (-not $script:D32LifecyclePrimary) { $script:D32LifecyclePrimary = 'Bounded stdout/stderr capture was incomplete or unavailable.' }
        }

        while (-not $cleanupVerified -and (Get-D32LifecycleNow) -lt $cleanupDeadline) {
            if (Test-D32LifecycleOwnedCleanupReady) { $cleanupVerified = $true; break }
            $now = Get-D32LifecycleNow
            if ($now -ge $cleanupDeadline) { break }
            $remaining = [Int64]($cleanupDeadline - $now)
            $native = $script:D32LifecycleNativeProcess
            if ($native.Process -ne [IntPtr]::Zero -and -not [D32BoundedSourceProofLifecycleNativeV1]::IsSignaled($native.Process)) {
                $null = [D32BoundedSourceProofLifecycleNativeV1]::Wait($native.Process, [uint32][Math]::Min(100, [Math]::Max(1, $remaining * 1000.0 / [Diagnostics.Stopwatch]::Frequency)))
            } else { Start-Sleep -Milliseconds ([int][Math]::Min(25, [Math]::Max(1, [Math]::Ceiling($remaining * 1000.0 / [Diagnostics.Stopwatch]::Frequency)))) }
        }
        if (-not $cleanupVerified -and (Get-D32LifecycleNow) -ge $cleanupDeadline) {
            $script:D32LifecycleCleanupRecord.state = 'UNVERIFIED'
            $script:D32LifecycleCleanupRecord.job_active_process_count = $null
            $script:D32LifecycleCaptureRecord.output_unavailable = $true
            if ($script:D32LifecycleStatus -ne 'BUDGET_STOPPED') { $script:D32LifecycleStatus = 'UNRESOLVED' }
            if (-not $script:D32LifecyclePrimary) { $script:D32LifecyclePrimary = 'Owned-process exit, Job state, or capture-worker join was not verified by the 345-second cleanup deadline.' }
            $cleanupObserved = Add-D32LifecycleEvent -Name 'CLEANUP_UNVERIFIED' -ScheduledTicks $cleanupDeadline
            Add-D32LifecycleJournalFact -Event 'CLEANUP_UNVERIFIED' -ObservedTicks $cleanupObserved -ScheduledTicks $cleanupDeadline
            # At this boundary only the Job's fixed KILL_ON_JOB_CLOSE fail-safe
            # is allowed. Do not query, join, retry, or touch retained handles
            # after this close attempt.
            if ($script:D32LifecycleNativeProcess.Job -ne [IntPtr]::Zero) {
                $script:D32LifecycleCleanupRecord.job_closed = [D32BoundedSourceProofLifecycleNativeV1]::CloseJob($script:D32LifecycleNativeProcess)
            }
        }
    } else {
        $script:D32LifecycleCleanupRecord.state = 'NOT_STARTED'
        while ((Get-D32LifecycleNow) -lt $cleanupDeadline) { Start-Sleep -Milliseconds 5 }
    }

    if ((Get-D32LifecycleNow) -lt $cleanupDeadline) {
        while ((Get-D32LifecycleNow) -lt $cleanupDeadline) { Start-Sleep -Milliseconds 5 }
    }
    if ((Get-D32LifecycleNow) -ge $terminalDeadline) { return }
    $auditObserved = Add-D32LifecycleEvent -Name 'TERMINAL_AUDIT' -ScheduledTicks $cleanupDeadline
    Add-D32LifecycleJournalFact -Event 'TERMINAL_AUDIT' -ObservedTicks $auditObserved -ScheduledTicks $cleanupDeadline
    $recordWritten = $false
    try { $recordWritten = Write-D32LifecycleFinalRecord }
    catch {
        if ($script:D32LifecycleSecondary.Count -lt 8) { $script:D32LifecycleSecondary.Add((Get-D32LifecycleErrorText -Exception $_.Exception)) }
    }
    if (-not $recordWritten) {
        $script:D32LifecycleStatus = 'UNRESOLVED'
        if (-not $script:D32LifecyclePrimary) { $script:D32LifecyclePrimary = 'The bounded terminal audit result was not persisted before expiry.' }
        if ((Get-D32LifecycleNow) -ge $terminalDeadline) { return }
    } elseif (-not (Add-D32LifecycleExecutionRecordPersistedFact)) {
        $script:D32LifecycleStatus = 'UNRESOLVED'
        if (-not $script:D32LifecyclePrimary) { $script:D32LifecyclePrimary = 'Execution-record persistence was not confirmed by the bounded journal before expiry.' }
        if ((Get-D32LifecycleNow) -ge $terminalDeadline) { return }
    }
    if (-not (Close-D32LifecycleJournalStream)) {
        $script:D32LifecycleStatus = 'UNRESOLVED'
        if (-not $script:D32LifecyclePrimary) { $script:D32LifecyclePrimary = 'The bounded execution journal could not be closed before terminal expiry.' }
    }
    if ((Get-D32LifecycleNow) -ge $terminalDeadline) {
        $script:D32LifecycleStatus = 'UNRESOLVED'
        if (-not $script:D32LifecyclePrimary) { $script:D32LifecyclePrimary = 'Terminal journal closure crossed the fixed audit boundary.' }
    }
}

try {
    if ($PSVersionTable.PSVersion -lt [version]'7.5' -or -not [Environment]::Is64BitProcess -or
        $CandidateSha -cnotmatch '^[0-9a-f]{40}$' -or $ExpectedExecutionAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $LifecycleT0Ticks -le 0 -or [Diagnostics.Stopwatch]::Frequency -le 0 -or
        [IO.Path]::GetFullPath($Repository) -cne $Repository -or -not [IO.Path]::IsPathRooted($Repository)) {
        throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: fixed candidate, repository, runtime, or caller clock input is invalid'
    }
    if ($script:D32LifecycleControllerEntryTicks -lt $LifecycleT0Ticks) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: shared monotonic counter is before caller T0' }
    $now = Get-D32LifecycleNow
    $workDeadline = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $LifecycleT0Ticks -Frequency ([Diagnostics.Stopwatch]::Frequency) -DeadlineMilliseconds 270000L
    $expiryDeadline = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $LifecycleT0Ticks -Frequency ([Diagnostics.Stopwatch]::Frequency) -DeadlineMilliseconds 300000L
    $cleanupDeadline = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $LifecycleT0Ticks -Frequency ([Diagnostics.Stopwatch]::Frequency) -DeadlineMilliseconds 345000L
    $terminalDeadline = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $LifecycleT0Ticks -Frequency ([Diagnostics.Stopwatch]::Frequency) -DeadlineMilliseconds 360000L
    if ($now -lt $LifecycleT0Ticks -or $now -ge $workDeadline) { throw 'D32_SOURCEPROOF_LIFECYCLE_BUDGET_STOPPED: caller admission reached or crossed the proof-work cutoff' }

    Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop | Out-Null
    $executionBytes = Get-D32LifecycleReferenceBytes -Path $ExecutionAuthorityPath -MaximumBytes 1048576 -DeadlineTicks $workDeadline
    $script:D32LifecycleOpened.Add($executionBytes)
    if ($executionBytes.Reference.sha256 -cne $ExpectedExecutionAuthoritySha256) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: execution authority SHA differs from caller pin' }
    $jsonDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$executionBytes.Bytes))
    try {
        if ($jsonDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32LifecycleJsonDuplicates -Element $jsonDocument.RootElement)) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: authority root or duplicate-property check failed' }
        $script:D32LifecycleAuthority = ConvertFrom-D32LifecycleJsonElement -Element $jsonDocument.RootElement
    } finally { $jsonDocument.Dispose() }
    $script:D32LifecycleAuthorityReference = $executionBytes.Reference
    $script:D32LifecycleClockRecord = [PSCustomObject][ordered]@{
        counter_origin = 'QueryPerformanceCounter'; frequency = [Int64][Diagnostics.Stopwatch]::Frequency
        t0_ticks = [Int64]$LifecycleT0Ticks; work_deadline_ticks = [Int64]$workDeadline; proof_expiry_ticks = [Int64]$expiryDeadline
        cleanup_deadline_ticks = [Int64]$cleanupDeadline; terminal_audit_deadline_ticks = [Int64]$terminalDeadline
        controller_entry_ticks = [Int64]$script:D32LifecycleControllerEntryTicks; reader_create_attempt_ticks = $null; reader_resume_ticks = $null
        reader_exit_ticks = $null; artifact_verified_ticks = $null; cleanup_verified_ticks = $null; audit_persisted_ticks = $null; observed_ticks = [Int64]$now
    }

    # Resolve the source loader and policy only from caller-pinned bytes. The
    # scriptblock is created from that exact verified buffer, never re-read by
    # path after SHA validation.
    $moduleRelative = 'scripts/d32-powershell-module-authority.ps1'
    $modulePin = @($script:D32LifecycleAuthority.source_pins | Where-Object { [string]$_.path -ceq [IO.Path]::GetFullPath((Join-Path $Repository $moduleRelative)) })
    if ($modulePin.Count -ne 1) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: exact pinned module-free loader is absent' }
    $moduleBytes = Get-D32LifecycleReferenceBytes -Path ([string]$modulePin[0].path) -MaximumBytes 16777216 -DeadlineTicks $workDeadline
    $script:D32LifecycleOpened.Add($moduleBytes)
    foreach ($name in @('bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ([string]$moduleBytes.Reference.($name) -cne [string]$modulePin[0].($name)) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: pinned module-free loader drifted' } }
    . ([ScriptBlock]::Create([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$moduleBytes.Bytes)))
    $script:D32LifecycleFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
    $outerAuthorityOpened = Open-D32PowerShellAuthorityFile -Path $ExecutionAuthorityPath -DirectoryFences $script:D32LifecycleFences -MaximumBytes 1048576 -DeadlineTicks $workDeadline
    $script:D32LifecycleOpened.Add($outerAuthorityOpened)
    if ([string]$outerAuthorityOpened.Record.sha256 -cne $ExpectedExecutionAuthoritySha256 -or
        [Int64]$outerAuthorityOpened.Record.bytes -ne [Int64]$executionBytes.Reference.bytes -or
        [string]$outerAuthorityOpened.Record.volume_serial_hex -cne [string]$executionBytes.Reference.volume_serial_hex -or
        [string]$outerAuthorityOpened.Record.file_id_hex -cne [string]$executionBytes.Reference.file_id_hex) {
        throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: authority opened-handle identity differs from caller-pinned bytes'
    }
    $jsonDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$outerAuthorityOpened.Bytes))
    try {
        if ($jsonDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $jsonDocument.RootElement)) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: exact authority duplicate check failed on reopened bytes' }
        $script:D32LifecycleAuthority = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $jsonDocument.RootElement
    } finally { $jsonDocument.Dispose() }

    $policyPin = @($script:D32LifecycleAuthority.source_pins | Where-Object { [string]$_.path -ceq [IO.Path]::GetFullPath((Join-Path $Repository 'scripts/d32-bounded-compiler-diagnostic-policy.ps1')) })
    if ($policyPin.Count -ne 1) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: fixed policy pin is absent' }
    $policyBytes = Open-D32PowerShellAuthorityFile -Path ([string]$policyPin[0].path) -DirectoryFences $script:D32LifecycleFences -MaximumBytes 16777216 -DeadlineTicks $workDeadline
    $script:D32LifecycleOpened.Add($policyBytes)
    foreach ($name in @('bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ([string]$policyBytes.Record.($name) -cne [string]$policyPin[0].($name)) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: fixed policy source pin drifted' } }
    . ([ScriptBlock]::Create([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$policyBytes.Bytes)))
    $script:D32BoundedDiagnosticSourceProofLifecycleClock = [PSCustomObject]@{ counter_origin = 'QueryPerformanceCounter'; frequency = [Int64][Diagnostics.Stopwatch]::Frequency; t0_ticks = [Int64]$LifecycleT0Ticks; work_deadline_ticks = $workDeadline; proof_expiry_ticks = $expiryDeadline; cleanup_deadline_ticks = $cleanupDeadline; terminal_audit_deadline_ticks = $terminalDeadline }

    if (-not (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityShape -Document $script:D32LifecycleAuthority -ExpectedCandidateSha $CandidateSha -Repository $Repository) -or
        [string]$script:D32LifecycleAuthority.clock.counter_origin -cne 'QueryPerformanceCounter' -or
        [Int64]$script:D32LifecycleAuthority.clock.frequency -ne [Int64][Diagnostics.Stopwatch]::Frequency) {
        throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: strict execution-authority V1 validation failed'
    }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($PSCommandPath), [string]$script:D32LifecycleAuthority.source_pins[0].path) -or
        (Test-D32LifecycleNoReparsePath -Path $ExecutionAuthorityPath) -eq $false -or
        (Test-D32PowerShellAuthorityPathWithin -Child $ExecutionAuthorityPath -Parent $Repository) -or
        (Test-D32PowerShellAuthorityPathWithin -Child $ExecutionAuthorityPath -Parent 'E:\d32\inv7\r\c')) {
        throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: controller or execution-authority invocation path is outside its fixed no-reparse boundary'
    }
    if ([string]$script:D32LifecycleAuthority.source_repo -cne $Repository -or
        [string]$script:D32LifecycleAuthority.source_proof_authority.path -cne [IO.Path]::GetFullPath([string]$script:D32LifecycleAuthority.source_proof_authority.path) -or
        [string]$script:D32LifecycleAuthority.source_proof_authority.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $script:D32LifecycleAuthority.output.candidate_path -cne [IO.Path]::GetFullPath($script:D32LifecycleAuthority.output.candidate_path) -or
        $script:D32LifecycleAuthority.output.parent_path -cne [IO.Path]::GetFullPath($script:D32LifecycleAuthority.output.parent_path)) {
        throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: outer authority path or invocation binding is noncanonical'
    }

    $expectedRuntimePath = [IO.Path]::GetFullPath([string]$script:D32LifecycleAuthority.powershell_runtime.path)
    $currentRuntimePath = [IO.Path]::GetFullPath([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($expectedRuntimePath, $currentRuntimePath)) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: controller runtime image differs from caller-pinned PowerShell 7 image' }
    $repoIdentity = Get-D32LifecycleDirectoryIdentity $Repository
    if ($repoIdentity.VolumeSerialHex -cne [string]$script:D32LifecycleAuthority.repository_identity.volume_serial_hex -or
        $repoIdentity.FileIdHex -cne [string]$script:D32LifecycleAuthority.repository_identity.file_id_hex) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: current repository directory identity differs from authority' }

    # After the strict outer authority, runtime, repository and create-new
    # output parent are reopened and matched, a later inner/source-pin failure
    # is a durable REFUSED attempt rather than an unclassified disappearance.
    $parentIdentity = Get-D32LifecycleDirectoryIdentity ([string]$script:D32LifecycleAuthority.output.parent_path)
    if ($parentIdentity.VolumeSerialHex -cne [string]$script:D32LifecycleAuthority.output.parent_volume_serial_hex -or
        $parentIdentity.FileIdHex -cne [string]$script:D32LifecycleAuthority.output.parent_file_id_hex) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: output-parent opened identity differs from caller pin' }
    foreach ($path in @([string]$script:D32LifecycleAuthority.output.candidate_path, [string]$script:D32LifecycleAuthority.output.execution_record_path, [string]$script:D32LifecycleAuthority.output.journal_path)) {
        if ([IO.File]::Exists($path) -or [IO.Directory]::Exists($path)) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: create-new output target already exists' }
    }
    $script:D32LifecycleAdmissionValidated = $true
    $authorityRef = [PSCustomObject]@{ path = [string]$outerAuthorityOpened.Record.path; bytes = [Int64]$outerAuthorityOpened.Record.bytes; sha256 = [string]$outerAuthorityOpened.Record.sha256; volume_serial_hex = [string]$outerAuthorityOpened.Record.volume_serial_hex; file_id_hex = [string]$outerAuthorityOpened.Record.file_id_hex }
    $script:D32LifecycleAuthorityReference = $authorityRef
    $script:D32LifecycleStatus = 'REFUSED'
    $admittedAt = Add-D32LifecycleEvent -Name 'AUTHORITY_ADMISSION' -ScheduledTicks $LifecycleT0Ticks
    $script:D32LifecycleJournalStream = [IO.File]::Open([string]$script:D32LifecycleAuthority.output.journal_path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    Add-D32LifecycleJournalFact -Event 'AUTHORITY_ADMISSION' -ObservedTicks $admittedAt -ScheduledTicks $LifecycleT0Ticks

    $sourceOpened = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $script:D32LifecycleAuthority.source_pins.Count; $index++) {
        if ((Get-D32LifecycleNow) -ge $workDeadline) { throw 'D32_SOURCEPROOF_LIFECYCLE_BUDGET_STOPPED: authority/code-pin admission reached work cutoff' }
        $pin = $script:D32LifecycleAuthority.source_pins[$index]
        $opened = Open-D32PowerShellAuthorityFile -Path ([string]$pin.path) -DirectoryFences $script:D32LifecycleFences -MaximumBytes 16777216 -DeadlineTicks $workDeadline
        $sourceOpened.Add($opened); $script:D32LifecycleOpened.Add($opened)
        foreach ($name in @('bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ([string]$opened.Record.($name) -cne [string]$pin.($name)) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: fixed source closure identity or hash drifted' } }
    }
    $runtimeOpened = Open-D32PowerShellAuthorityFile -Path $expectedRuntimePath -DirectoryFences $script:D32LifecycleFences -MaximumBytes 16777216 -DeadlineTicks $workDeadline
    $script:D32LifecycleOpened.Add($runtimeOpened)
    foreach ($name in @('bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ([string]$runtimeOpened.Record.($name) -cne [string]$script:D32LifecycleAuthority.powershell_runtime.($name)) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: runtime image differs from caller pin' } }
    $profileOpened = Open-D32PowerShellAuthorityFile -Path ([string]$script:D32LifecycleAuthority.toolchain_profile.path) -DirectoryFences $script:D32LifecycleFences -MaximumBytes 16777216 -DeadlineTicks $workDeadline
    $script:D32LifecycleOpened.Add($profileOpened)
    foreach ($name in @('bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ([string]$profileOpened.Record.($name) -cne [string]$script:D32LifecycleAuthority.toolchain_profile.($name)) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: Profile V2 differs from outer caller pin' } }

    $innerAuthorityOpened = Open-D32PowerShellAuthorityFile -Path ([string]$script:D32LifecycleAuthority.source_proof_authority.path) -DirectoryFences $script:D32LifecycleFences -MaximumBytes 1048576 -DeadlineTicks $workDeadline
    $script:D32LifecycleOpened.Add($innerAuthorityOpened)
    foreach ($name in @('bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ([string]$innerAuthorityOpened.Record.($name) -cne [string]$script:D32LifecycleAuthority.source_proof_authority.($name)) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: inner source-proof authority differs from outer pinned reference' } }
    $innerJson = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$innerAuthorityOpened.Bytes))
    try {
        if ($innerJson.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $innerJson.RootElement)) { throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: inner SourceProof V3 JSON duplicate check failed' }
        $innerAuthority = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $innerJson.RootElement
    } finally { $innerJson.Dispose() }
    $entryPath = [string]$script:D32LifecycleAuthority.invocation.entry_path
    $innerShapeTimer = [Diagnostics.Stopwatch]::StartNew()
    if (-not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $innerAuthority -ExpectedCandidateSha $CandidateSha `
        -ExpectedHistoricalOriginCandidateSha '2de30edf5de48aa4ed3216c3d3df13c3e2f0ac51' -Repository $Repository `
        -EntryScriptPath $entryPath -RunnerPath ([string]$script:D32LifecycleAuthority.source_pins[2].path) `
        -ToolchainProfilePath ([string]$script:D32LifecycleAuthority.toolchain_profile.path) `
        -ToolchainProfileSha256 ([string]$script:D32LifecycleAuthority.toolchain_profile.sha256) `
        -ProofTimer $innerShapeTimer -DeadlineMilliseconds 270000L)) {
        throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: strict inner SourceProof V3 exact schema and frozen budget validation failed'
    }
    $innerAuthorityReference = [PSCustomObject]@{ path = [string]$innerAuthorityOpened.Record.path; bytes = [Int64]$innerAuthorityOpened.Record.bytes; sha256 = [string]$innerAuthorityOpened.Record.sha256; volume_serial_hex = [string]$innerAuthorityOpened.Record.volume_serial_hex; file_id_hex = [string]$innerAuthorityOpened.Record.file_id_hex }
    if (-not (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityBindings -ExecutionAuthority $script:D32LifecycleAuthority -SourceProofAuthority $innerAuthority `
        -SourceProofAuthorityReference $innerAuthorityReference -ExpectedCandidateSha $CandidateSha -Repository $Repository)) {
        throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: outer execution authority did not cross-bind the strict inner SourceProof V3'
    }

    if ((Get-D32LifecycleNow) -ge $workDeadline) { throw 'D32_SOURCEPROOF_LIFECYCLE_BUDGET_STOPPED: authority admission completed at or after work cutoff' }

    $entryPath = [string]$script:D32LifecycleAuthority.invocation.entry_path
    $sourceAuthority = [string]$script:D32LifecycleAuthority.source_proof_authority.path
    $profile = [string]$script:D32LifecycleAuthority.toolchain_profile.path
    $sourceEntryPin = $script:D32LifecycleAuthority.source_pins[1]
    $entrySha = [string]$sourceEntryPin.sha256
    $args = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $entryPath,
        '-Repository', $Repository, '-CandidateSha', $CandidateSha,
        '-HistoricalOriginCandidateSha', [string]$innerAuthority.historical_origin_candidate_sha,
        '-ToolchainProfilePath', $profile, '-ExpectedToolchainProfileSha256', [string]$script:D32LifecycleAuthority.toolchain_profile.sha256,
        '-SourceProofAuthorityPath', $sourceAuthority, '-ExpectedSourceProofAuthoritySha256', [string]$script:D32LifecycleAuthority.source_proof_authority.sha256,
        '-ExecutionAuthorityPath', $ExecutionAuthorityPath, '-ExpectedExecutionAuthoritySha256', $ExpectedExecutionAuthoritySha256,
        '-LifecycleT0Ticks', [string]$LifecycleT0Ticks, '-LifecycleCounterFrequency', [string][Diagnostics.Stopwatch]::Frequency,
        '-LifecycleWorkDeadlineTicks', [string]$workDeadline, '-LifecycleProofExpiryTicks', [string]$expiryDeadline)
    $commandLine = [D32BoundedSourceProofLifecycleNativeV1]::QuoteArgument($expectedRuntimePath) + ' ' + [string]::Join(' ', @($args | ForEach-Object { [D32BoundedSourceProofLifecycleNativeV1]::QuoteArgument([string]$_) }))
    $environment = $script:D32LifecycleAuthority.invocation.child_environment
    $environmentNames = @('SystemRoot', 'WINDIR', 'PATH', 'PSModulePath', 'PSModuleAutoLoadingPreference', 'POWERSHELL_TELEMETRY_OPTOUT', 'DOTNET_CLI_TELEMETRY_OPTOUT', 'TEMP', 'TMP')
    $environmentList = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $environmentNames) { $environmentList.Add(('{0}={1}' -f $name, [string]$environment.$name)) }
    $environmentArray = $environmentList.ToArray(); [Array]::Sort($environmentArray, [StringComparer]::OrdinalIgnoreCase)
    $environmentBlock = [string]::Join("`0", $environmentArray) + "`0`0"
    if ((Get-D32LifecycleNow) -ge $workDeadline) { throw 'D32_SOURCEPROOF_LIFECYCLE_BUDGET_STOPPED: final reader launch admission reached work cutoff' }
    $script:D32LifecycleNativeProcess = [D32BoundedSourceProofLifecycleNativeV1]::StartSuspendedAssignedAndResume($expectedRuntimePath, $commandLine, $Repository, $environmentBlock, [Int64]$workDeadline)
    if ($script:D32LifecycleNativeProcess.CreateProcessAttempted) {
        $script:D32LifecycleReaderAttemptCount = 1
        $script:D32LifecycleReaderRecord.launch_attempt_count = 1
        $createAttempt = [Int64]$script:D32LifecycleNativeProcess.CreateProcessAttemptTicks
        $script:D32LifecycleClockRecord.reader_create_attempt_ticks = $createAttempt
        $null = Add-D32LifecycleEvent -Name 'READER_CREATE_ATTEMPT' -ScheduledTicks $createAttempt
        Add-D32LifecycleJournalFact -Event 'READER_CREATE_ATTEMPT' -ObservedTicks (Get-D32LifecycleNow) -ScheduledTicks $createAttempt
    }
    if ($null -ne $script:D32LifecycleNativeProcess.Process -and $script:D32LifecycleNativeProcess.Process -ne [IntPtr]::Zero) {
        $script:D32LifecycleReaderRecord.process_id = [Int64]$script:D32LifecycleNativeProcess.ProcessId
        $script:D32LifecycleReaderRecord.creation_filetime_ticks = [Int64]$script:D32LifecycleNativeProcess.CreationFileTime
        $script:D32LifecycleReaderRecord.job_instance_id = [string]$script:D32LifecycleNativeProcess.JobInstanceId
        $script:D32LifecycleReaderRecord.job_assignment = if ($script:D32LifecycleNativeProcess.Assigned) { 'ASSIGNED' } else { 'FAILED' }
    } elseif ($null -ne $script:D32LifecycleNativeProcess.Job) { $script:D32LifecycleReaderRecord.job_assignment = 'FAILED' }
    if ($script:D32LifecycleNativeProcess.Assigned) {
        $assignedObserved = Add-D32LifecycleEvent -Name 'READER_ASSIGNED_TO_JOB' -ScheduledTicks $createAttempt
        Add-D32LifecycleJournalFact -Event 'READER_ASSIGNED_TO_JOB' -ObservedTicks $assignedObserved -ScheduledTicks $createAttempt
    }
    if (-not [String]::IsNullOrEmpty([string]$script:D32LifecycleNativeProcess.Failure) -or -not $script:D32LifecycleNativeProcess.Resumed) {
        $failureMessage = if ($script:D32LifecycleNativeProcess.Failure) {
            'D32_SOURCEPROOF_LIFECYCLE_UNRESOLVED: one reader creation attempt failed: ' + $script:D32LifecycleNativeProcess.Failure
        } else {
            'D32_SOURCEPROOF_LIFECYCLE_UNRESOLVED: reader was not resumed'
        }
        throw $failureMessage
    }
    $script:D32LifecycleCleanupRecord.kill_on_close_enabled = [bool]$script:D32LifecycleNativeProcess.JobKillOnClose
    $script:D32LifecycleStatus = 'UNRESOLVED'
    $resumeObserved = [Int64]$script:D32LifecycleNativeProcess.ReaderResumeTicks
    $script:D32LifecycleClockRecord.reader_resume_ticks = [Int64]$resumeObserved
    $null = Add-D32LifecycleEvent -Name 'READER_RESUMED' -ScheduledTicks $createAttempt
    Add-D32LifecycleJournalFact -Event 'READER_RESUMED' -ObservedTicks $resumeObserved -ScheduledTicks $createAttempt

    $workEvent = $false; $expiryEvent = $false; $readerExited = $false; $proofCompleted = $false; $cleanupVerified = $false
    while (-not $readerExited -and (Get-D32LifecycleNow) -lt $expiryDeadline) {
        $current = Get-D32LifecycleNow
        if (-not $workEvent -and $current -ge $workDeadline) {
            $workObserved = Add-D32LifecycleEvent -Name 'WORK_CUTOFF' -ScheduledTicks $workDeadline; Add-D32LifecycleJournalFact -Event 'WORK_CUTOFF' -ObservedTicks $workObserved -ScheduledTicks $workDeadline; $workEvent = $true
        }
        $remaining = [Int64]($expiryDeadline - $current)
        $slice = [uint32][Math]::Max(1, [Math]::Min(100, [Math]::Ceiling($remaining * 1000.0 / [Diagnostics.Stopwatch]::Frequency)))
        $waitState = [D32BoundedSourceProofLifecycleNativeV1]::Wait($script:D32LifecycleNativeProcess.Process, $slice)
        if ($waitState -eq [uint32]0) { $readerExited = $true; break }
        if ($waitState -ne [uint32]258) { throw 'D32_SOURCEPROOF_LIFECYCLE_UNRESOLVED: retained process wait failed' }
    }
    if (-not $workEvent -and (Get-D32LifecycleNow) -ge $workDeadline) {
        $workObserved = Add-D32LifecycleEvent -Name 'WORK_CUTOFF' -ScheduledTicks $workDeadline; Add-D32LifecycleJournalFact -Event 'WORK_CUTOFF' -ObservedTicks $workObserved -ScheduledTicks $workDeadline; $workEvent = $true
    }
    if ($readerExited) {
        $exitObserved = Get-D32LifecycleNow
        $script:D32LifecycleClockRecord.reader_exit_ticks = [Int64]$exitObserved
        $script:D32LifecycleReaderRecord.exit_code = [D32BoundedSourceProofLifecycleNativeV1]::ExitCode($script:D32LifecycleNativeProcess.Process)
        $null = Add-D32LifecycleEvent -Name 'READER_EXIT' -ScheduledTicks $null; Add-D32LifecycleJournalFact -Event 'READER_EXIT' -ObservedTicks $exitObserved
        if ($exitObserved -lt $expiryDeadline -and [IO.File]::Exists([string]$script:D32LifecycleAuthority.output.candidate_path)) {
            $artifactOpened = Open-D32PowerShellAuthorityFile -Path ([string]$script:D32LifecycleAuthority.output.candidate_path) -DirectoryFences $script:D32LifecycleFences -MaximumBytes 67108864 -DeadlineTicks $expiryDeadline
            try {
                $artifactJson = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$artifactOpened.Bytes))
                try {
                    if ($artifactJson.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $artifactJson.RootElement)) { throw 'candidate record has duplicate or invalid JSON shape' }
                    $candidateRecord = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $artifactJson.RootElement
                } finally { $artifactJson.Dispose() }
                $candidateFailures = [System.Collections.Generic.List[string]]::new()
                if ((Get-D32LifecycleNow) -ge $expiryDeadline -or -not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $candidateRecord -FailureReasons $candidateFailures -ProofTimer ([Diagnostics.Stopwatch]::StartNew()) -DeadlineMilliseconds 300000L) -or
                    (Get-D32LifecycleNow) -ge $expiryDeadline -or [string]$candidateRecord.candidate_sha -cne $CandidateSha -or
                    [string]$candidateRecord.proof_authority.path -cne [string]$script:D32LifecycleAuthority.source_proof_authority.path -or
                    [string]$candidateRecord.proof_authority.sha256 -cne [string]$script:D32LifecycleAuthority.source_proof_authority.sha256 -or
                    [string]$candidateRecord.proof_entry.path -cne $entryPath -or [string]$candidateRecord.proof_entry.sha256 -cne $entrySha) {
                    throw ('D32_SOURCEPROOF_LIFECYCLE_UNRESOLVED: candidate strict readback failed or reached proof expiry: ' + [string]::Join(',', $candidateFailures.ToArray()))
                }
                $script:D32LifecycleArtifactRecord = [PSCustomObject]@{ state = 'VERIFIED'; path = [string]$artifactOpened.Record.path; bytes = [Int64]$artifactOpened.Record.bytes; sha256 = [string]$artifactOpened.Record.sha256; volume_serial_hex = [string]$artifactOpened.Record.volume_serial_hex; file_id_hex = [string]$artifactOpened.Record.file_id_hex; inner_status = [string]$candidateRecord.status }
                $script:D32LifecycleClockRecord.artifact_verified_ticks = Get-D32LifecycleNow
                $proofCompleted = [string]$candidateRecord.status -ceq 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY'
            } finally { if ($null -ne $artifactOpened.Stream -and -not $artifactOpened.Stream.SafeFileHandle.IsClosed) { $artifactOpened.Stream.Dispose() } }
        } else { $script:D32LifecycleArtifactRecord.state = if ([IO.File]::Exists([string]$script:D32LifecycleAuthority.output.candidate_path)) { 'PARTIAL_OR_UNCONFIRMED' } else { 'ABSENT' }; $script:D32LifecycleArtifactRecord.path = [string]$script:D32LifecycleAuthority.output.candidate_path }
    }
    if (-not $readerExited) {
        $expiryObserved = Add-D32LifecycleEvent -Name 'PROOF_EXPIRY' -ScheduledTicks $expiryDeadline; Add-D32LifecycleJournalFact -Event 'PROOF_EXPIRY' -ObservedTicks $expiryObserved -ScheduledTicks $expiryDeadline; $expiryEvent = $true
        $script:D32LifecycleStatus = 'BUDGET_STOPPED'
        if (-not $script:D32LifecyclePrimary) { $script:D32LifecyclePrimary = 'The reader had not exited by the 300-second proof-expiry boundary.' }
        if ($script:D32LifecycleNativeProcess.Job -ne [IntPtr]::Zero) {
            $terminateObserved = Add-D32LifecycleEvent -Name 'TERMINATION_REQUEST' -ScheduledTicks $expiryDeadline
            $script:D32LifecycleCleanupRecord.termination_requested = $true
            if (-not [D32BoundedSourceProofLifecycleNativeV1]::TerminateJob($script:D32LifecycleNativeProcess.Job, 0xD3203004)) { $script:D32LifecycleSecondary.Add('exact owned Job termination request failed') }
            Add-D32LifecycleJournalFact -Event 'TERMINATION_REQUEST' -ObservedTicks $terminateObserved -ScheduledTicks $expiryDeadline
        }
    }
    if ($script:D32LifecycleStatus -ne 'BUDGET_STOPPED') {
        if ($proofCompleted -and $readerExited -and $script:D32LifecycleReaderRecord.exit_code -eq 0) { $script:D32LifecycleStatus = 'COMPLETED_DIAGNOSTIC_ONLY' }
        elseif ($workEvent) { $script:D32LifecycleStatus = 'BUDGET_STOPPED' }
        else { $script:D32LifecycleStatus = 'UNRESOLVED'; if (-not $script:D32LifecyclePrimary) { $script:D32LifecyclePrimary = 'SourceProofOnly reader exited without a complete positive candidate.' } }
    }

    Invoke-D32LifecycleCleanupAndAudit
} catch {
    $caughtError = Get-D32LifecycleErrorText -Exception $_.Exception
    if (-not $script:D32LifecyclePrimary) { $script:D32LifecyclePrimary = $caughtError }
    elseif ($script:D32LifecycleSecondary.Count -lt 8) { $script:D32LifecycleSecondary.Add($caughtError) }
    $caughtAt = Get-D32LifecycleNow
    $caughtMessage = [string]$_.Exception.Message
    if ($caughtMessage -match 'D32_SOURCEPROOF_LIFECYCLE_BUDGET_STOPPED' -or
        ($null -ne $script:D32LifecycleClockRecord -and $caughtAt -ge [Int64]$script:D32LifecycleClockRecord.work_deadline_ticks)) {
        $script:D32LifecycleStatus = 'BUDGET_STOPPED'
    } elseif ($script:D32LifecycleReaderAttemptCount -gt 0) { $script:D32LifecycleStatus = 'UNRESOLVED' }
    else { $script:D32LifecycleStatus = 'REFUSED' }
    if ($null -ne $script:D32LifecycleClockRecord -and $script:D32LifecycleAdmissionValidated -and
        (Get-D32LifecycleNow) -lt [Int64]$script:D32LifecycleClockRecord.terminal_audit_deadline_ticks -and
        @($script:D32LifecycleEvents | Where-Object { $_.event -ceq 'TERMINAL_AUDIT' }).Count -eq 0) {
        try {
            if ($caughtAt -ge [Int64]$script:D32LifecycleClockRecord.work_deadline_ticks -and
                @($script:D32LifecycleEvents | Where-Object { $_.event -ceq 'WORK_CUTOFF' }).Count -eq 0) {
                $workObserved = Add-D32LifecycleEvent -Name 'WORK_CUTOFF' -ScheduledTicks ([Int64]$script:D32LifecycleClockRecord.work_deadline_ticks)
                Add-D32LifecycleJournalFact -Event 'WORK_CUTOFF' -ObservedTicks $workObserved -ScheduledTicks ([Int64]$script:D32LifecycleClockRecord.work_deadline_ticks)
            }
            Invoke-D32LifecycleCleanupAndAudit
        } catch { if ($script:D32LifecycleSecondary.Count -lt 8) { $script:D32LifecycleSecondary.Add((Get-D32LifecycleErrorText -Exception $_.Exception)) } }
    }
} finally {
    # Finally is the interruption fail-safe, but it does not extend authority.
    # If the shared cleanup window is already gone, process exit closes the
    # non-breakaway KILL_ON_JOB_CLOSE handle at the OS boundary; do no late
    # file I/O, join, retry, or evidence management here.
    $cleanupStillAuthorized = $null -eq $script:D32LifecycleClockRecord -or (Get-D32LifecycleNow) -lt [Int64]$script:D32LifecycleClockRecord.cleanup_deadline_ticks
    if ($cleanupStillAuthorized) {
        if ($null -ne $script:D32LifecycleJournalStream) { try { $script:D32LifecycleJournalStream.Flush($true); $script:D32LifecycleJournalStream.Dispose() } catch {} }
        if ($null -ne $script:D32LifecycleNativeProcess) {
            if ($script:D32LifecycleNativeProcess.Job -ne [IntPtr]::Zero) { [void][D32BoundedSourceProofLifecycleNativeV1]::CloseJob($script:D32LifecycleNativeProcess) }
            [void][D32BoundedSourceProofLifecycleNativeV1]::CloseAll($script:D32LifecycleNativeProcess)
        }
        Close-D32LifecycleAdmissionHandles
    }
}

if ($script:D32LifecycleStatus -eq 'COMPLETED_DIAGNOSTIC_ONLY') { exit 0 }
if ($script:D32LifecycleStatus -eq 'BUDGET_STOPPED') { exit 86 }
exit 87
