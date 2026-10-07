# Durable module-free supervisor for one caller-authorized SourceProofOnly run.
# No shell, helper executable, retry, or free-form child argv is accepted.
[CmdletBinding(DefaultParameterSetName = 'SourceProofOnly')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][string]$Repository,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][string]$CandidateSha,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][string]$ExecutionAuthorityPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][string]$ExpectedExecutionAuthoritySha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][long]$LifecycleT0Ticks,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][switch]$NonSourceL1,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][string]$L1AuthorityPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][string]$ExpectedL1AuthoritySha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][long]$L1T0Ticks
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
$script:D32NonSourceL1Now = { [Diagnostics.Stopwatch]::GetTimestamp() }
$script:D32NonSourceL1Authority = $null
$script:D32NonSourceL1AuthorityReference = $null
$script:D32NonSourceL1AdmissionValidated = $false
$script:D32NonSourceL1Opened = [System.Collections.Generic.List[object]]::new()
$script:D32NonSourceL1Secondary = [System.Collections.Generic.List[string]]::new()
$script:D32NonSourceL1Primary = $null
$script:D32NonSourceL1Cases = [System.Collections.Generic.List[object]]::new()
$script:D32NonSourceL1JournalStream = $null
$script:D32NonSourceL1JournalBytes = [long]0
$script:D32NonSourceL1CreateAttempts = [long]0
$script:D32NonSourceL1PlannedTerminations = [long]0
$script:D32NonSourceL1FailSafeTerminations = [long]0
$script:D32NonSourceL1OwnedBuffers = [long]0
$script:D32NonSourceL1Status = 'REFUSED'
$script:D32NonSourceL1BatchDeadline = [long]0
# Operational invocations always leave this null. The module-free self-test
# binds a synthetic provider in-process so the actual case state machine can be
# exercised without calling CreateProcessW, Job APIs, or reader processes.
$script:D32NonSourceL1NativeAdapter = $null
$script:D32NonSourceL1FileAdapter = $null

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
    public string ImagePath;
    public string JobInstanceId;
    public bool JobKillOnClose;
    public bool JobActiveProcessLimitOne;
    public bool JobClosedByNative;
    public bool TemporaryHandlesClosed;
    public bool PrelaunchHandlesClosed;
    public bool CreateProcessAttempted;
    public long CreateProcessAttemptTicks;
    public D32LifecycleInvocationV1 Invocation;
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

public sealed class D32LifecycleInvocationV1 {
    public string ImagePath;
    public string[] Arguments;
    public string CommandLine;
    public string WorkingDirectory;
    public string[] EnvironmentEntries;
    public string EnvironmentBlockSha256;
    public string CaseId;
    public string CaseNonce;
    public long BatchT0Ticks;
    public long CaseT0Ticks;
    public long CounterFrequency;
    public long ActiveDeadlineTicks;
    public bool InheritHandles;
    public bool HandleListApplied;
    public string[] HandleRoles;
    public bool? StdinInheritable;
    public bool? StdoutWriteInheritable;
    public bool? StderrWriteInheritable;
    public bool? StdoutReadInheritable;
    public bool? StderrReadInheritable;
    public uint CreationFlags;
    public bool ApiAttempted;
    public long? ApiAttemptTicks;
    public bool? ApiReturned;
    public int? ApiErrorCode;
    public uint? ProcessId;
    public long? CreationFileTimeTicks;
    public string ProcessImagePath;
    public bool ProcessImageBindingVerified;
}

public static class D32BoundedSourceProofLifecycleNativeV1 {
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
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
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="CreateFileW")] static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="CreateFileW", ExactSpelling=true)] static extern IntPtr CreateFileWInheritable(string name, uint access, uint share, ref SecurityAttributes security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetHandleInformation(IntPtr handle, out uint flags);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool CreateProcessW(string app, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string currentDirectory, ref StartupInfoEx startup, out ProcessInformation processInformation);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError=true)] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr process, out FileTime creation, out FileTime exit, out FileTime kernel, out FileTime user);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder image, ref uint size);
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

    public static string GetProcessImagePath(IntPtr process) {
        StringBuilder image = new StringBuilder(32768); uint size = (uint)image.Capacity;
        if (!QueryFullProcessImageNameW(process, 0, image, ref size) || size == 0 || size >= image.Capacity) throw LastError("QueryFullProcessImageNameW failed");
        return image.ToString();
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

    static bool HandleInheritable(IntPtr handle, string role) {
        uint flags; if (!GetHandleInformation(handle, out flags)) throw LastError("GetHandleInformation(" + role + ") failed");
        return (flags & HANDLE_FLAG_INHERIT) != 0;
    }

    static string BuildEnvironmentBlock(string[] entries) {
        if (entries == null || entries.Length != 15) throw new InvalidDataException("fixed child environment must have exactly 15 entries");
        string[] sorted = (string[])entries.Clone(); Array.Sort(sorted, StringComparer.OrdinalIgnoreCase);
        HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string entry in sorted) {
            int separator = entry == null ? -1 : entry.IndexOf('=');
            if (separator <= 0 || !names.Add(entry.Substring(0, separator))) throw new InvalidDataException("fixed child environment contains a malformed or duplicate entry");
        }
        string[] expected = new string[] { "APPDATA", "DOTNET_CLI_TELEMETRY_OPTOUT", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "PATH", "PSHOME", "PSModuleAutoLoadingPreference", "PSModulePath", "SystemRoot", "TEMP", "TMP", "USERPROFILE", "WINDIR", "POWERSHELL_TELEMETRY_OPTOUT" };
        Array.Sort(expected, StringComparer.OrdinalIgnoreCase);
        if (sorted.Length != expected.Length) throw new InvalidDataException("fixed child environment names differ from the allowlist");
        for (int i = 0; i < expected.Length; i++) if (!StringComparer.OrdinalIgnoreCase.Equals(sorted[i].Substring(0, sorted[i].IndexOf('=')), expected[i])) throw new InvalidDataException("fixed child environment names differ from the allowlist");
        return String.Join("\0", sorted) + "\0\0";
    }

    static string HashEnvironmentBlock(string block) { return BitConverter.ToString(SHA256.HashData(Encoding.Unicode.GetBytes(block))).Replace("-", "").ToLowerInvariant(); }

    // Pure in-process preparation shared by the real launcher and L0's
    // synthetic native adapter. It constructs the exact CreateProcessW inputs
    // before any handle/job/process API is touched.
    public static string PrepareInvocation(D32LifecycleInvocationV1 invocation, string image, string[] arguments,
        string workingDirectory, string[] environmentEntries, string caseId, string caseNonce,
        long batchT0Ticks, long caseT0Ticks, long counterFrequency, long activeDeadlineTicks) {
        if (invocation == null) throw new ArgumentNullException("invocation");
        invocation.ImagePath = image; invocation.Arguments = arguments == null ? null : (string[])arguments.Clone(); invocation.WorkingDirectory = workingDirectory;
        invocation.EnvironmentEntries = environmentEntries == null ? null : (string[])environmentEntries.Clone();
        invocation.CaseId = caseId; invocation.CaseNonce = caseNonce; invocation.BatchT0Ticks = batchT0Ticks; invocation.CaseT0Ticks = caseT0Ticks;
        invocation.CounterFrequency = counterFrequency; invocation.ActiveDeadlineTicks = activeDeadlineTicks;
        invocation.HandleRoles = new string[] { "stdin:NUL", "stdout:PIPE_WRITE", "stderr:PIPE_WRITE" };
        invocation.CreationFlags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
        invocation.InheritHandles = true;
        if (String.IsNullOrWhiteSpace(image) || arguments == null || arguments.Length != 26 || String.IsNullOrWhiteSpace(workingDirectory) ||
            String.IsNullOrWhiteSpace(caseId) || caseNonce == null || caseNonce.Length != 32 || batchT0Ticks <= 0 || caseT0Ticks <= 0 || counterFrequency <= 0 || activeDeadlineTicks <= 0)
            throw new InvalidDataException("fixed reader invocation context is incomplete");
        string[] sortedEnvironmentEntries = (string[])environmentEntries.Clone(); Array.Sort(sortedEnvironmentEntries, StringComparer.OrdinalIgnoreCase);
        string environmentBlock = BuildEnvironmentBlock(sortedEnvironmentEntries);
        invocation.EnvironmentEntries = sortedEnvironmentEntries;
        invocation.EnvironmentBlockSha256 = HashEnvironmentBlock(environmentBlock);
        StringBuilder command = new StringBuilder(); command.Append(QuoteArgument(image));
        foreach (string argument in arguments) { command.Append(' '); command.Append(QuoteArgument(argument)); }
        invocation.CommandLine = command.ToString();
        if (invocation.CommandLine.Length >= 32767) throw new InvalidDataException("fixed reader command line exceeds the Windows limit");
        return environmentBlock;
    }

    public static D32LifecycleOwnedProcessV1 StartSuspendedAssignedAndResume(string image, string[] arguments, string workingDirectory, string[] environmentEntries,
        string caseId, string caseNonce, long batchT0Ticks, long caseT0Ticks, long counterFrequency, long activeDeadlineTicks, long workDeadlineTicks) {
        D32LifecycleOwnedProcessV1 owned = new D32LifecycleOwnedProcessV1();
        owned.Invocation = new D32LifecycleInvocationV1();
        IntPtr stdin = IntPtr.Zero, stdoutWrite = IntPtr.Zero, stderrWrite = IntPtr.Zero, attr = IntPtr.Zero, attrValue = IntPtr.Zero, env = IntPtr.Zero;
        ProcessInformation pi = new ProcessInformation();
        try {
            D32LifecycleInvocationV1 invocation = owned.Invocation;
            string environmentBlock = PrepareInvocation(invocation, image, arguments, workingDirectory, environmentEntries,
                caseId, caseNonce, batchT0Ticks, caseT0Ticks, counterFrequency, activeDeadlineTicks);
            owned.Job = CreateJobObjectW(IntPtr.Zero, null); if (owned.Job == IntPtr.Zero) throw LastError("CreateJobObjectW failed");
            ExtendedLimitInformation limits = new ExtendedLimitInformation();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = 1;
            if (!SetInformationJobObject(owned.Job, JobObjectExtendedLimitInformation, ref limits, (uint)Marshal.SizeOf<ExtendedLimitInformation>())) throw LastError("SetInformationJobObject(KILL_ON_JOB_CLOSE) failed");
            owned.JobKillOnClose = true; owned.JobActiveProcessLimitOne = true; owned.JobInstanceId = Guid.NewGuid().ToString("N");
            SecurityAttributes sa = new SecurityAttributes(); sa.nLength = Marshal.SizeOf<SecurityAttributes>(); sa.bInheritHandle = 1;
            stdin = CreateFileWInheritable("NUL", 0x80000000, 3, ref sa, 3, 0x80, IntPtr.Zero); if (stdin == new IntPtr(-1)) throw LastError("open inheritable NUL stdin failed");
            InitPipe(out owned.StdoutRead, out stdoutWrite); InitPipe(out owned.StderrRead, out stderrWrite);
            invocation.StdinInheritable = HandleInheritable(stdin, "stdin");
            invocation.StdoutWriteInheritable = HandleInheritable(stdoutWrite, "stdout_write");
            invocation.StderrWriteInheritable = HandleInheritable(stderrWrite, "stderr_write");
            invocation.StdoutReadInheritable = HandleInheritable(owned.StdoutRead, "stdout_read");
            invocation.StderrReadInheritable = HandleInheritable(owned.StderrRead, "stderr_read");
            if (invocation.StdinInheritable != true || invocation.StdoutWriteInheritable != true || invocation.StderrWriteInheritable != true ||
                invocation.StdoutReadInheritable != false || invocation.StderrReadInheritable != false) throw new InvalidDataException("observed standard-handle inheritance differs from the fixed allowlist");
            IntPtr size = IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            attr = Marshal.AllocHGlobal(size); if (!InitializeProcThreadAttributeList(attr, 1, 0, ref size)) throw LastError("InitializeProcThreadAttributeList failed");
            attrValue = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(attrValue, 0, stdin); Marshal.WriteIntPtr(attrValue, IntPtr.Size, stdoutWrite); Marshal.WriteIntPtr(attrValue, IntPtr.Size * 2, stderrWrite);
            if (!UpdateProcThreadAttribute(attr, 0, new IntPtr(PROC_THREAD_ATTRIBUTE_HANDLE_LIST), attrValue, new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero)) throw LastError("UpdateProcThreadAttribute(handle list) failed");
            invocation.HandleListApplied = true;
            env = Marshal.StringToHGlobalUni(environmentBlock);
            StartupInfoEx startup = new StartupInfoEx(); startup.StartupInfo.cb = Marshal.SizeOf<StartupInfoEx>(); startup.StartupInfo.dwFlags = 0x00000100;
            startup.StartupInfo.hStdInput = stdin; startup.StartupInfo.hStdOutput = stdoutWrite; startup.StartupInfo.hStdError = stderrWrite; startup.lpAttributeList = attr;
            if (System.Diagnostics.Stopwatch.GetTimestamp() >= workDeadlineTicks) throw new TimeoutException("proof-work cutoff reached before the single CreateProcess attempt");
            owned.Failure = null; // the sole CreateProcess attempt begins here
            owned.CreateProcessAttemptTicks = System.Diagnostics.Stopwatch.GetTimestamp();
            owned.CreateProcessAttempted = true;
            invocation.ApiAttempted = true;
            invocation.ApiAttemptTicks = owned.CreateProcessAttemptTicks;
            if (!CreateProcessW(image, new StringBuilder(invocation.CommandLine), IntPtr.Zero, IntPtr.Zero, invocation.InheritHandles,
                invocation.CreationFlags, env, workingDirectory, ref startup, out pi)) {
                invocation.ApiReturned = false; invocation.ApiErrorCode = Marshal.GetLastWin32Error();
                owned.Failure = new Win32Exception(invocation.ApiErrorCode.Value, "CreateProcessW failed").Message; return owned;
            }
            invocation.ApiReturned = true; invocation.ProcessId = pi.dwProcessId;
            owned.Process = pi.hProcess; owned.Thread = pi.hThread; owned.ProcessId = pi.dwProcessId;
            if (!AssignProcessToJobObject(owned.Job, owned.Process)) { owned.Failure = LastError("AssignProcessToJobObject failed").Message; TerminateProcess(owned.Process, 0xD3203002); return owned; }
            owned.Assigned = true;
            owned.JobAssignmentTicks = System.Diagnostics.Stopwatch.GetTimestamp();
            FileTime created, exited, kernel, user;
            if (!GetProcessTimes(owned.Process, out created, out exited, out kernel, out user)) { owned.Failure = LastError("GetProcessTimes(reader) failed").Message; TerminateJobObject(owned.Job, 0xD3203001); return owned; }
            owned.CreationFileTime = created.Value;
            invocation.CreationFileTimeTicks = created.Value;
            owned.ImagePath = GetProcessImagePath(owned.Process);
            invocation.ProcessImagePath = owned.ImagePath;
            invocation.ProcessImageBindingVerified = StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(owned.ImagePath), Path.GetFullPath(image));
            if (!invocation.ProcessImageBindingVerified) {
                owned.Failure = "actual process image differs from the fixed caller-pinned runtime"; TerminateJobObject(owned.Job, 0xD3203007); return owned;
            }
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
            bool temporaryClosed = Close(ref stdin);
            temporaryClosed = Close(ref stdoutWrite) && temporaryClosed;
            temporaryClosed = Close(ref stderrWrite) && temporaryClosed;
            if (attr != IntPtr.Zero) { DeleteProcThreadAttributeList(attr); Marshal.FreeHGlobal(attr); attr = IntPtr.Zero; }
            if (attrValue != IntPtr.Zero) { Marshal.FreeHGlobal(attrValue); attrValue = IntPtr.Zero; }
            if (env != IntPtr.Zero) { Marshal.FreeHGlobal(env); env = IntPtr.Zero; }
            owned.TemporaryHandlesClosed = temporaryClosed;
            if (!temporaryClosed && owned.Failure == null) owned.Failure = "temporary native launch handles did not all close";
            if (owned.Failure != null && owned.Process == IntPtr.Zero) {
                bool readPipesClosed = Close(ref owned.StdoutRead) && Close(ref owned.StderrRead);
                bool jobClosed = Close(ref owned.Job);
                owned.JobClosedByNative = jobClosed;
                owned.PrelaunchHandlesClosed = temporaryClosed && readPipesClosed && jobClosed;
                if ((!readPipesClosed || !jobClosed) && String.IsNullOrEmpty(owned.Failure)) owned.Failure = "failed native launch handles remain unverified";
            } else { owned.PrelaunchHandlesClosed = temporaryClosed; }
        }
    }

    public static uint Wait(IntPtr process, uint milliseconds) { return WaitForSingleObject(process, milliseconds); }
    public static bool IsSignaled(IntPtr process) { return process != IntPtr.Zero && WaitForSingleObject(process, 0) == WAIT_OBJECT_0; }
    public static int? ExitCode(IntPtr process) { uint code; return GetExitCodeProcess(process, out code) ? (int?)code : null; }
    public static bool TerminateJob(IntPtr job, uint code) { return job != IntPtr.Zero && TerminateJobObject(job, code); }
    public static bool TerminateExactProcess(IntPtr process, uint code) { return process != IntPtr.Zero && TerminateProcess(process, code); }
    public static int? ActiveProcesses(IntPtr job) { BasicAccountingInformation info = new BasicAccountingInformation(); uint returned; return QueryInformationJobObject(job, JobObjectBasicAccountingInformation, ref info, (uint)Marshal.SizeOf<BasicAccountingInformation>(), out returned) ? (int?)info.ActiveProcesses : null; }
    public static int? TotalProcesses(IntPtr job) { BasicAccountingInformation info = new BasicAccountingInformation(); uint returned; return QueryInformationJobObject(job, JobObjectBasicAccountingInformation, ref info, (uint)Marshal.SizeOf<BasicAccountingInformation>(), out returned) ? (int?)info.TotalProcesses : null; }
    public static string CaptureText(D32LifecycleCaptureV1 capture) { lock (capture.Sync) { return Encoding.UTF8.GetString(capture.Prefix.ToArray()); } }
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

function Get-D32NonSourceL1Now { return [Int64](& $script:D32NonSourceL1Now) }

function Get-D32NonSourceL1DeadlineTicks {
    param([long]$T0Ticks, [long]$Frequency, [long]$Milliseconds)
    if ($T0Ticks -le 0 -or $Frequency -le 0 -or $Milliseconds -le 0) { throw 'D32_NON_SOURCE_L1_REFUSED: invalid monotonic deadline input' }
    try {
        $delta = [decimal]$Frequency * [decimal]$Milliseconds / [decimal]1000
        if ($delta -lt 1 -or $delta -gt [decimal][Int64]::MaxValue) { throw 'deadline overflow' }
        $rounded = [Int64][Math]::Ceiling($delta)
        if ([decimal]$T0Ticks + [decimal]$rounded -gt [decimal][Int64]::MaxValue) { throw 'deadline overflow' }
        return [Int64]($T0Ticks + $rounded)
    } catch { throw 'D32_NON_SOURCE_L1_BLOCKED: checked monotonic deadline arithmetic failed' }
}

function Add-D32NonSourceL1JournalFact {
    param([Parameter(Mandatory = $true)][string]$Event, [string]$CaseId = '',
        [AllowNull()][Nullable[long]]$ScheduledTicks = $null, [Parameter(Mandatory = $true)][long]$ObservedTicks,
        [AllowNull()][object]$ResultReference = $null, [AllowNull()][object]$CaseEvidenceSha256 = $null)
    if ($null -eq $script:D32NonSourceL1JournalStream) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: result journal is unavailable' }
    $fact = [PSCustomObject][ordered]@{
        event = $Event; case_id = $CaseId; scheduled_ticks = $ScheduledTicks; observed_ticks = $ObservedTicks
        lateness_ticks = if ($null -eq $ScheduledTicks) { $null } else { [Int64]($ObservedTicks - $ScheduledTicks) }
        result_path = if ($null -eq $ResultReference) { $null } else { [string]$ResultReference.path }
        result_bytes = if ($null -eq $ResultReference) { $null } else { [Int64]$ResultReference.bytes }
        result_sha256 = if ($null -eq $ResultReference) { $null } else { [string]$ResultReference.sha256 }
        result_volume_serial_hex = if ($null -eq $ResultReference) { $null } else { [string]$ResultReference.volume_serial_hex }
        result_file_id_hex = if ($null -eq $ResultReference) { $null } else { [string]$ResultReference.file_id_hex }
        case_evidence_sha256 = $CaseEvidenceSha256
        gate_authority = 'NONE'
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $fact -Depth 8 -Compress) + "`n")
    if ($script:D32NonSourceL1JournalBytes + $bytes.Length -gt 65536 -or $ObservedTicks -ge $script:D32NonSourceL1BatchDeadline) {
        throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: fixed journal cap or batch deadline reached'
    }
    $script:D32NonSourceL1JournalStream.Write($bytes, 0, $bytes.Length); $script:D32NonSourceL1JournalStream.Flush($true)
    $script:D32NonSourceL1JournalBytes += $bytes.Length
}

function ConvertTo-D32NonSourceL1ResultBytes {
    param([Parameter(Mandatory = $true)][object]$Record)
    if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape $Record)) {
        throw 'D32_NON_SOURCE_L1_UNRESOLVED: exact result schema rejected producer record'
    }
    $json = ConvertTo-Json -InputObject $Record -Depth 32 -Compress -ErrorAction Stop
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    if ($bytes.Length -gt 65536) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: result exceeds the fixed 65536-byte output ceiling' }
    return ,$bytes
}

function New-D32NonSourceL1ResultPersistedFact {
    param([Parameter(Mandatory = $true)][object]$ResultReference, [Parameter(Mandatory = $true)][long]$ObservedTicks)
    return [PSCustomObject][ordered]@{
        event = 'L1_RESULT_PERSISTED'; case_id = ''; scheduled_ticks = $null; observed_ticks = $ObservedTicks; lateness_ticks = $null
        result_path = [string]$ResultReference.path; result_bytes = [Int64]$ResultReference.bytes
        result_sha256 = [string]$ResultReference.sha256; result_volume_serial_hex = [string]$ResultReference.volume_serial_hex
        result_file_id_hex = [string]$ResultReference.file_id_hex; case_evidence_sha256 = $null; gate_authority = 'NONE'
    }
}

function Get-D32NonSourceL1ErrorText {
    param([System.Exception]$Exception)
    $text = if ($null -eq $Exception) { 'unspecified NON_SOURCE_L1 failure' } else { [string]$Exception.GetType().Name + ': ' + [string]$Exception.Message }
    $text = [regex]::Replace($text, '[\r\n\t]+', ' ')
    $text = [regex]::Replace($text, '(?i)["''](?:[a-z]:\\|\\\\)[^"'']*["'']', '[path]')
    $text = [regex]::Replace($text, '(?i)(?:[a-z]:\\|\\\\)[^\s,;)]*', '[path]')
    $text = [regex]::Replace($text, '(?i)\b(password|secret|token|nonce|credential|authorization)\b(?:\s*[:=]\s*|\s+)[^\s,;]+', '$1=[redacted]')
    $text = [regex]::Replace($text, '(?i)\b[0-9a-f]{32,64}\b', '[id]')
    $text = [regex]::Replace($text, '[^\x20-\x7e]', '?')
    if ($text.Length -gt 2048) { $text = $text.Substring(0, 2048) }
    return $text
}

function Add-D32NonSourceL1Error {
    param([AllowNull()][System.Exception]$Exception, [AllowNull()][string]$Message)
    $text = if ($null -ne $Exception) { Get-D32NonSourceL1ErrorText -Exception $Exception } else { [string]$Message }
    if ([String]::IsNullOrWhiteSpace($text)) { $text = 'unspecified NON_SOURCE_L1 failure' }
    if (-not $script:D32NonSourceL1Primary) { $script:D32NonSourceL1Primary = $text }
    elseif ($script:D32NonSourceL1Secondary.Count -lt 8) { $script:D32NonSourceL1Secondary.Add($text) }
    return $text
}

function Get-D32NonSourceL1FailureStatus {
    param([AllowNull()][string]$ErrorText)
    if ([string]$ErrorText -match 'D32_NON_SOURCE_L1_BUDGET_STOPPED') { return 'BUDGET_STOPPED' }
    if ([string]$ErrorText -match 'D32_NON_SOURCE_L1_BLOCKED') { return 'BLOCKED' }
    if ($script:D32NonSourceL1AdmissionValidated) { return 'UNRESOLVED' }
    return 'REFUSED'
}

function Get-D32NonSourceL1ReaderRefusalError {
    param([AllowNull()][string]$StderrCapture)
    $prefix = 'D32NSL1|REFUSED|'
    if ([String]::IsNullOrEmpty($StderrCapture) -or -not $StderrCapture.StartsWith($prefix, [StringComparison]::Ordinal)) { return $null }
    $detail = $StderrCapture.Substring($prefix.Length)
    if ($detail.Length -gt 512) { $detail = $detail.Substring(0, 512) }
    return Get-D32NonSourceL1ErrorText -Exception ([InvalidOperationException]::new('fixed reader admission refused: ' + $detail))
}

function Write-D32NonSourceL1Diagnostic {
    param([Parameter(Mandatory = $true)][string]$Status,
        [AllowNull()][string]$PrimaryError,
        [AllowNull()][object[]]$SecondaryErrors = @(),
        [Parameter(Mandatory = $true)][System.IO.TextWriter]$Writer)
    $allowedStatuses = @('COMPLETE_NON_SOURCE_L1', 'BLOCKED', 'BUDGET_STOPPED', 'REFUSED', 'UNRESOLVED')
    if ($Status -cnotin $allowedStatuses) { $Status = 'UNRESOLVED' }
    $sanitize = {
        param([AllowNull()][string]$Value, [int]$MaximumLength)
        $value = if ([String]::IsNullOrWhiteSpace($Value)) { 'error unavailable' } else { [string]$Value }
        $value = [regex]::Replace($value, '[\r\n\t]+', ' ')
        $value = [regex]::Replace($value, '(?i)["''](?:[a-z]:\\|\\\\)[^"'']*["'']', '[path]')
        $value = [regex]::Replace($value, '(?i)(?:[a-z]:\\|\\\\)[^\s,;)]*', '[path]')
        $value = [regex]::Replace($value, '(?i)\b(password|secret|token|nonce|credential|authorization)\b(?:\s*[:=]\s*|\s+)[^\s,;]+', '$1=[redacted]')
        $value = [regex]::Replace($value, '(?i)\b[0-9a-f]{32,64}\b', '[id]')
        $value = [regex]::Replace($value, '[^\x20-\x7e]', '?')
        if ($value.Length -gt $MaximumLength) { $value = $value.Substring(0, $MaximumLength) }
        return $value
    }
    $detail = & $sanitize $PrimaryError 2048
    $line = 'D32_NON_SOURCE_L1 status=' + $Status + ' primary=' + $detail
    $secondaryIndex = 0
    foreach ($secondary in @($SecondaryErrors | Select-Object -First 2)) {
        $line += ' secondary' + $secondaryIndex + '=' + (& $sanitize ([string]$secondary) 768)
        $secondaryIndex++
    }
    if ($line.Length -gt 4094) { $line = $line.Substring(0, 4094) }
    try {
        $Writer.WriteLine($line)
        $Writer.Flush()
        return $true
    } catch { return $false }
}

function Get-D32NonSourceL1ReferenceFromOpened {
    param([Parameter(Mandatory = $true)][object]$Opened)
    return [PSCustomObject][ordered]@{
        path = [string]$Opened.Record.path; bytes = [Int64]$Opened.Record.bytes; sha256 = [string]$Opened.Record.sha256
        volume_serial_hex = [string]$Opened.Record.volume_serial_hex; file_id_hex = [string]$Opened.Record.file_id_hex
    }
}

function Open-D32NonSourceL1PinnedFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][object]$Pin)
    if ((Get-D32NonSourceL1Now) -ge $script:D32NonSourceL1BatchDeadline) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: fixed code/runtime pin read crossed the batch deadline' }
    if ($null -ne $script:D32NonSourceL1FileAdapter) { return & $script:D32NonSourceL1FileAdapter $Path $Pin }
    $opened = Open-D32PowerShellAuthorityFile -Path $Path -DirectoryFences $script:D32LifecycleFences -MaximumBytes 16777216 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
    $script:D32NonSourceL1OwnedBuffers += [Int64]$opened.Record.bytes
    if ($script:D32NonSourceL1OwnedBuffers -gt 16777216) { if ($null -ne $opened.Stream) { $opened.Stream.Dispose() }; throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: probe-owned input buffers exceed 16 MiB' }
    foreach ($name in @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) {
        if ([string]$opened.Record.($name) -cne [string]$Pin.($name)) {
            if ($null -ne $opened.Stream) { $opened.Stream.Dispose() }
            throw ('D32_NON_SOURCE_L1_REFUSED: fixed pin mismatch for ' + $name)
        }
    }
    $script:D32NonSourceL1Opened.Add($opened)
    return $opened
}

function Get-D32NonSourceL1MutatedSha256 {
    param([Parameter(Mandatory = $true)][string]$Sha256)
    return Get-D32BoundedDiagnosticSourceProofNonSourceL1DerivedEntryMismatchSha256 -Sha256 $Sha256
}

function New-D32NonSourceL1PreCreatePlan {
    param([Parameter(Mandatory = $true)][string]$CaseId, [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][long]$CaseT0Ticks, [Parameter(Mandatory = $true)][long]$ActiveDeadlineTicks,
        [switch]$DeriveEntryPinMismatch)
    $entryPin = $script:D32NonSourceL1Authority.source_pins[1]
    $runtimePin = $script:D32NonSourceL1Authority.powershell_runtime
    $entryOpened = Open-D32NonSourceL1PinnedFile -Path ([string]$entryPin.path) -Pin $entryPin
    $runtimeOpened = Open-D32NonSourceL1PinnedFile -Path ([string]$runtimePin.path) -Pin ([PSCustomObject]@{
        path = $runtimePin.path; bytes = $runtimePin.bytes; sha256 = $runtimePin.sha256
        volume_serial_hex = $runtimePin.volume_serial_hex; file_id_hex = $runtimePin.file_id_hex
    })
    $expectedEntrySha = if ($DeriveEntryPinMismatch) { Get-D32NonSourceL1MutatedSha256 -Sha256 ([string]$entryPin.sha256) } else { [string]$entryPin.sha256 }
    # Both the negative and positive cases traverse this same opened-handle
    # pre-create binding check. The negative differs only in one derived SHA bit.
    if ([string]$entryOpened.Record.sha256 -cne $expectedEntrySha) {
        if ($DeriveEntryPinMismatch -and [string]$entryOpened.Record.sha256 -ceq [string]$entryPin.sha256 -and $expectedEntrySha -cne [string]$entryPin.sha256) {
            $admission = [PSCustomObject][ordered]@{
                decision = 'ENTRY_PIN_BINDING_REFUSAL'; observed_ticks = Get-D32NonSourceL1Now
                entry_reference = [PSCustomObject][ordered]@{ path = $entryOpened.Record.path; bytes = [Int64]$entryOpened.Record.bytes; sha256 = [string]$entryOpened.Record.sha256; volume_serial_hex = [string]$entryOpened.Record.volume_serial_hex; file_id_hex = [string]$entryOpened.Record.file_id_hex }
                entry_expected_sha256 = $expectedEntrySha; entry_observed_sha256 = [string]$entryOpened.Record.sha256
                runtime_reference = [PSCustomObject][ordered]@{ path = $runtimeOpened.Record.path; bytes = [Int64]$runtimeOpened.Record.bytes; sha256 = [string]$runtimeOpened.Record.sha256; volume_serial_hex = [string]$runtimeOpened.Record.volume_serial_hex; file_id_hex = [string]$runtimeOpened.Record.file_id_hex }
                runtime_expected_sha256 = [string]$runtimePin.sha256; runtime_observed_sha256 = [string]$runtimeOpened.Record.sha256
                refusal_reason = 'ENTRY_SHA_MISMATCH'
            }
            return [PSCustomObject][ordered]@{ admitted = $false; refusal = 'ENTRY_PIN_BINDING_REFUSAL'; admission = $admission }
        }
        throw 'D32_NON_SOURCE_L1_REFUSED: common pre-create entry binding did not match its caller-pinned code reference'
    }
    if ($DeriveEntryPinMismatch) { throw 'D32_NON_SOURCE_L1_BLOCKED: derived negative entry pin unexpectedly matched' }
    if ([string]$runtimeOpened.Record.path -cne [IO.Path]::GetFullPath([string]$script:D32NonSourceL1Authority.powershell_runtime.path) -or
        (Get-D32NonSourceL1Now) -ge $ActiveDeadlineTicks) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: fixed runtime/entry pre-create admission missed the active deadline' }
    $entryPath = [string]$entryPin.path
    $args = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $entryPath,
        '-NonSourceL1', '-L1AuthorityPath', $L1AuthorityPath, '-ExpectedL1AuthoritySha256', $ExpectedL1AuthoritySha256,
        '-L1CandidateSha', $CandidateSha, '-L1BatchId', [string]$script:D32NonSourceL1Authority.batch_id,
        '-L1CaseId', $CaseId, '-L1Nonce', $Nonce, '-L1T0Ticks', [string]$L1T0Ticks,
        '-L1CounterFrequency', [string][Diagnostics.Stopwatch]::Frequency, '-L1CaseT0Ticks', [string]$CaseT0Ticks,
        '-L1ActiveDeadlineTicks', [string]$ActiveDeadlineTicks)
    $env = $script:D32NonSourceL1Authority.invocation.child_environment
    $admission = [PSCustomObject][ordered]@{
        decision = 'ADMITTED'; observed_ticks = Get-D32NonSourceL1Now
        entry_reference = [PSCustomObject][ordered]@{ path = $entryOpened.Record.path; bytes = [Int64]$entryOpened.Record.bytes; sha256 = [string]$entryOpened.Record.sha256; volume_serial_hex = [string]$entryOpened.Record.volume_serial_hex; file_id_hex = [string]$entryOpened.Record.file_id_hex }
        entry_expected_sha256 = [string]$entryPin.sha256; entry_observed_sha256 = [string]$entryOpened.Record.sha256
        runtime_reference = [PSCustomObject][ordered]@{ path = $runtimeOpened.Record.path; bytes = [Int64]$runtimeOpened.Record.bytes; sha256 = [string]$runtimeOpened.Record.sha256; volume_serial_hex = [string]$runtimeOpened.Record.volume_serial_hex; file_id_hex = [string]$runtimeOpened.Record.file_id_hex }
        runtime_expected_sha256 = [string]$runtimePin.sha256; runtime_observed_sha256 = [string]$runtimeOpened.Record.sha256
        refusal_reason = $null
    }
    $environmentEntries = Get-D32BoundedDiagnosticSourceProofNonSourceL1EnvironmentEntries -Environment $env
    return [PSCustomObject][ordered]@{ admitted = $true; admission = $admission; image = [string]$runtimePin.path
        arguments = [string[]]$args; environment_entries = [string[]]$environmentEntries
        working_directory = [string]$script:D32NonSourceL1Authority.output.root_path }
}

function Get-D32NonSourceL1RemainingWaitMilliseconds {
    param([long]$DeadlineTicks)
    $now = Get-D32NonSourceL1Now
    if ($now -ge $DeadlineTicks) { return [uint32]0 }
    $remaining = [decimal]($DeadlineTicks - $now) * [decimal]1000 / [decimal][Diagnostics.Stopwatch]::Frequency
    return [uint32][Math]::Max(1, [Math]::Min(50, [Math]::Ceiling($remaining)))
}

# The native-operation seam is private to the controller process. Operational
# invocation leaves the adapter null and therefore calls only the fixed native
# implementation below. The policy self-test installs a synthetic in-process
# provider to exercise the same case state machine without any P/Invoke child.
function Start-D32NonSourceL1NativeChild {
    param([string]$Image, [string[]]$Arguments, [string]$WorkingDirectory, [string[]]$EnvironmentEntries,
        [string]$CaseId, [string]$CaseNonce, [long]$BatchT0Ticks, [long]$CaseT0Ticks,
        [long]$CounterFrequency, [long]$ActiveDeadlineTicks, [long]$WorkDeadlineTicks)
    if ($null -ne $script:D32NonSourceL1NativeAdapter) {
        return & $script:D32NonSourceL1NativeAdapter.Start -Image $Image -Arguments $Arguments -WorkingDirectory $WorkingDirectory `
            -EnvironmentEntries $EnvironmentEntries -CaseId $CaseId -CaseNonce $CaseNonce -BatchT0Ticks $BatchT0Ticks `
            -CaseT0Ticks $CaseT0Ticks -CounterFrequency $CounterFrequency -ActiveDeadlineTicks $ActiveDeadlineTicks -WorkDeadlineTicks $WorkDeadlineTicks
    }
    return [D32BoundedSourceProofLifecycleNativeV1]::StartSuspendedAssignedAndResume($Image, $Arguments, $WorkingDirectory,
        $EnvironmentEntries, $CaseId, $CaseNonce, $BatchT0Ticks, $CaseT0Ticks, $CounterFrequency, $ActiveDeadlineTicks, $WorkDeadlineTicks)
}

function Test-D32NonSourceL1NativeSignaled {
    param([IntPtr]$Process)
    if ($null -ne $script:D32NonSourceL1NativeAdapter) { return [bool](& $script:D32NonSourceL1NativeAdapter.IsSignaled -Process $Process) }
    return [D32BoundedSourceProofLifecycleNativeV1]::IsSignaled($Process)
}

function Get-D32NonSourceL1NativeCaptureText {
    param([object]$Capture)
    if ($null -ne $script:D32NonSourceL1NativeAdapter) { return [string](& $script:D32NonSourceL1NativeAdapter.CaptureText -Capture $Capture) }
    return [D32BoundedSourceProofLifecycleNativeV1]::CaptureText($Capture)
}

function Stop-D32NonSourceL1NativeJob {
    param([IntPtr]$Job, [object]$ExitCode)
    if ($null -ne $script:D32NonSourceL1NativeAdapter) { return [bool](& $script:D32NonSourceL1NativeAdapter.TerminateJob -Job $Job -ExitCode $ExitCode) }
    return [D32BoundedSourceProofLifecycleNativeV1]::TerminateJob($Job, $ExitCode)
}

function Stop-D32NonSourceL1NativeProcess {
    param([IntPtr]$Process, [object]$ExitCode)
    if ($null -ne $script:D32NonSourceL1NativeAdapter) { return [bool](& $script:D32NonSourceL1NativeAdapter.TerminateExactProcess -Process $Process -ExitCode $ExitCode) }
    return [D32BoundedSourceProofLifecycleNativeV1]::TerminateExactProcess($Process, $ExitCode)
}

function Wait-D32NonSourceL1NativeProcess {
    param([IntPtr]$Process, [uint32]$Milliseconds)
    if ($null -ne $script:D32NonSourceL1NativeAdapter) { return [uint32](& $script:D32NonSourceL1NativeAdapter.Wait -Process $Process -Milliseconds $Milliseconds) }
    return [D32BoundedSourceProofLifecycleNativeV1]::Wait($Process, $Milliseconds)
}

function Get-D32NonSourceL1NativeExitCode {
    param([IntPtr]$Process)
    if ($null -ne $script:D32NonSourceL1NativeAdapter) { return & $script:D32NonSourceL1NativeAdapter.ExitCode -Process $Process }
    return [D32BoundedSourceProofLifecycleNativeV1]::ExitCode($Process)
}

function Get-D32NonSourceL1NativeActiveProcessCount {
    param([IntPtr]$Job)
    if ($null -ne $script:D32NonSourceL1NativeAdapter) { return & $script:D32NonSourceL1NativeAdapter.ActiveProcesses -Job $Job }
    return [D32BoundedSourceProofLifecycleNativeV1]::ActiveProcesses($Job)
}

function Get-D32NonSourceL1NativeTotalProcessCount {
    param([IntPtr]$Job)
    if ($null -ne $script:D32NonSourceL1NativeAdapter) { return & $script:D32NonSourceL1NativeAdapter.TotalProcesses -Job $Job }
    return [D32BoundedSourceProofLifecycleNativeV1]::TotalProcesses($Job)
}

function Join-D32NonSourceL1NativeCaptures {
    param([object]$Native, [int]$Milliseconds)
    if ($null -ne $script:D32NonSourceL1NativeAdapter) { return [bool](& $script:D32NonSourceL1NativeAdapter.JoinCaptures -Native $Native -Milliseconds $Milliseconds) }
    return [D32BoundedSourceProofLifecycleNativeV1]::JoinCaptures($Native, $Milliseconds)
}

function Close-D32NonSourceL1NativeJob {
    param([object]$Native)
    if ($null -ne $script:D32NonSourceL1NativeAdapter) { return [bool](& $script:D32NonSourceL1NativeAdapter.CloseJob -Native $Native) }
    return [D32BoundedSourceProofLifecycleNativeV1]::CloseJob($Native)
}

function Close-D32NonSourceL1NativeHandles {
    param([object]$Native)
    if ($null -ne $script:D32NonSourceL1NativeAdapter) { return [bool](& $script:D32NonSourceL1NativeAdapter.CloseAll -Native $Native) }
    return [D32BoundedSourceProofLifecycleNativeV1]::CloseAll($Native)
}

function Join-D32NonSourceL1CapturesUntilDeadline {
    param([Parameter(Mandatory = $true)][object]$Native, [Parameter(Mandatory = $true)][long]$DeadlineTicks)
    while ((Get-D32NonSourceL1Now) -lt $DeadlineTicks) {
        if (Join-D32NonSourceL1NativeCaptures -Native $Native -Milliseconds 20) { return $true }
    }
    return Join-D32NonSourceL1NativeCaptures -Native $Native -Milliseconds 0
}

function New-D32NonSourceL1ActualInvocationRecord {
    param([Parameter(Mandatory = $true)][object]$Native, [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][string]$CaseId, [Parameter(Mandatory = $true)][string]$CaseNonce,
        [Parameter(Mandatory = $true)][long]$CaseT0Ticks, [Parameter(Mandatory = $true)][long]$ActiveDeadlineTicks)
    $evidence = $Native.Invocation
    if ($null -eq $evidence) { return $null }
    return [PSCustomObject][ordered]@{
        case_id = $CaseId; case_nonce = $CaseNonce; batch_t0_ticks = [Int64]$L1T0Ticks; case_t0_ticks = $CaseT0Ticks
        counter_frequency = [Int64][Diagnostics.Stopwatch]::Frequency; active_deadline_ticks = $ActiveDeadlineTicks
        entry_reference = $Plan.admission.entry_reference; executable_reference = $Plan.admission.runtime_reference
        admission_observed_ticks = [Int64]$Plan.admission.observed_ticks
        image_path = [string]$evidence.ImagePath; arguments = @($evidence.Arguments); raw_command_line = [string]$evidence.CommandLine
        working_directory = [string]$evidence.WorkingDirectory; environment_entries = @($evidence.EnvironmentEntries)
        environment_block_sha256 = [string]$evidence.EnvironmentBlockSha256
        inherit_handles = [bool]$evidence.InheritHandles; handle_list_applied = [bool]$evidence.HandleListApplied
        handle_roles = @($evidence.HandleRoles)
        handle_observations = [PSCustomObject][ordered]@{
            stdin_inheritable = $evidence.StdinInheritable; stdout_write_inheritable = $evidence.StdoutWriteInheritable
            stderr_write_inheritable = $evidence.StderrWriteInheritable; stdout_read_inheritable = $evidence.StdoutReadInheritable
            stderr_read_inheritable = $evidence.StderrReadInheritable
        }
        creation_flags = [UInt32]$evidence.CreationFlags
        api_attempted = [bool]$evidence.ApiAttempted; api_attempt_ticks = $evidence.ApiAttemptTicks
        api_returned = $evidence.ApiReturned; api_error_code = $evidence.ApiErrorCode
        process_id = if ($null -eq $evidence.ProcessId) { $null } else { [Int64]$evidence.ProcessId }
        creation_filetime_ticks = $evidence.CreationFileTimeTicks; process_image_path = $evidence.ProcessImagePath
        process_image_binding_verified = [bool]$evidence.ProcessImageBindingVerified
    }
}

function Invoke-D32NonSourceL1Case {
    param([Parameter(Mandatory = $true)][int]$Index)
    $caseAuthority = $script:D32NonSourceL1Authority.cases[$Index]
    $caseId = [string]$caseAuthority.case_id
    $caseNonce = [string]$caseAuthority.nonce
    $caseT0 = Get-D32NonSourceL1Now
    $caseDeadlines = Get-D32BoundedDiagnosticSourceProofNonSourceL1CaseDeadlines -CaseT0Ticks $caseT0 -Frequency ([Diagnostics.Stopwatch]::Frequency) -BatchDeadlineTicks $script:D32NonSourceL1BatchDeadline
    $active = [Int64]$caseDeadlines.active_deadline_ticks; $cleanup = [Int64]$caseDeadlines.cleanup_deadline_ticks; $audit = [Int64]$caseDeadlines.audit_deadline_ticks
    $row = New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId $caseId -CaseNonce $caseNonce -CaseT0Ticks $caseT0 `
        -ActiveDeadlineTicks $active -CleanupDeadlineTicks $cleanup -AuditDeadlineTicks $audit -AdmissionObservedTicks (Get-D32NonSourceL1Now)
    if ((Get-D32NonSourceL1Now) -ge $active) { $row.state = 'BUDGET_STOPPED'; $row.primary_error = 'case admission reached active deadline'; return $row }
    $native = $null; $cleanupKnown = $true; $processExited = $false; $activeCount = $null; $totalCount = $null
    try {
        $plan = New-D32NonSourceL1PreCreatePlan -CaseId $caseId -Nonce ([string]$caseAuthority.nonce) -CaseT0Ticks $caseT0 -ActiveDeadlineTicks $active -DeriveEntryPinMismatch:($caseId -ceq 'ENTRY_PIN_BINDING_REFUSAL')
        $row.precreate_admission = $plan.admission
        if ($caseId -ceq 'ENTRY_PIN_BINDING_REFUSAL') {
            if ([bool]$plan.admitted -or [string]$plan.refusal -cne 'ENTRY_PIN_BINDING_REFUSAL') { throw 'expected pre-create entry-pin refusal was not observed' }
            $row.state = 'EXPECTED_REFUSAL_VERIFIED'; $row.primary_error = 'fixed reader entry SHA mismatch was rejected by common opened-handle pre-create binding'; return $row
        }
        if (-not [bool]$plan.admitted -or (Get-D32NonSourceL1Now) -ge $active) { throw 'fixed pre-create admission did not complete before active deadline' }
        $native = Start-D32NonSourceL1NativeChild -Image ([string]$plan.image) -Arguments ([string[]]$plan.arguments) `
            -WorkingDirectory ([string]$plan.working_directory) -EnvironmentEntries ([string[]]$plan.environment_entries) `
            -CaseId ([string]$caseId) -CaseNonce ([string]$caseNonce) -BatchT0Ticks ([Int64]$L1T0Ticks) -CaseT0Ticks ([Int64]$caseT0) `
            -CounterFrequency ([Int64][Diagnostics.Stopwatch]::Frequency) -ActiveDeadlineTicks ([Int64]$active) -WorkDeadlineTicks ([Int64]$active)
        $row.actual_invocation = New-D32NonSourceL1ActualInvocationRecord -Native $native -Plan $plan -CaseId $caseId -CaseNonce $caseNonce -CaseT0Ticks $caseT0 -ActiveDeadlineTicks $active
        if ($native.CreateProcessAttempted) { $script:D32NonSourceL1CreateAttempts++; $row.create_attempt_count = 1L; $row.create_attempt_ticks = [Int64]$native.CreateProcessAttemptTicks }
        $row.job_instance_id = if ([string]$native.JobInstanceId -match '^[0-9a-f]{32}$') { [string]$native.JobInstanceId } else { $null }
        $row.job_assigned = [bool]$native.Assigned; $row.resume_ticks = if ($native.Resumed) { [Int64]$native.ReaderResumeTicks } else { $null }
        $row.process_id = if ($native.Process -ne [IntPtr]::Zero) { [Int64]$native.ProcessId } else { $null }
        $row.creation_filetime_ticks = if ($native.CreationFileTime -gt 0) { [Int64]$native.CreationFileTime } else { $null }
        $row.process_image_path = if ([string]$native.ImagePath -match '^[A-Za-z]:\\') { [IO.Path]::GetFullPath([string]$native.ImagePath) } else { $null }
        $row.process_image_binding_verified = ($null -ne $row.process_image_path -and [StringComparer]::OrdinalIgnoreCase.Equals([string]$row.process_image_path, [string]$plan.image))
        $row.kill_on_close_enabled = [bool]$native.JobKillOnClose
        $row.job_active_process_limit_one = [bool]$native.JobActiveProcessLimitOne
        if (-not $native.TemporaryHandlesClosed) { throw 'native temporary launch handle close could not be verified' }
        if ($native.Process -eq [IntPtr]::Zero) {
            $cleanupKnown = [bool]$native.PrelaunchHandlesClosed
            $row.job_closed = [bool]$native.JobClosedByNative
            if (-not $cleanupKnown) { $row.state = 'UNRESOLVED'; $row.primary_error = 'native prelaunch handle cleanup has not been verified' }
            elseif ($native.CreateProcessAttempted) { $row.state = 'BLOCKED'; $row.primary_error = 'the single CreateProcess attempt did not create the fixed reader' }
            else { $row.state = 'BUDGET_STOPPED'; $row.primary_error = 'active deadline expired before CreateProcess was attempted' }
            return $row
        }
        if (-not $native.Assigned -or -not $native.Resumed -or -not $row.process_image_binding_verified -or
            [string]$native.Failure) { throw 'retained child identity, Job admission, resume, or actual image verification failed' }

        $ready = 'D32NSL1|' + $caseId + '|' + [string]$caseAuthority.nonce + '|READY'
        $plannedTerminationObserved = $false
        while ((Get-D32NonSourceL1Now) -lt $active) {
            if (Test-D32NonSourceL1NativeSignaled -Process $native.Process) { $processExited = $true; break }
            if ($caseId -ceq 'NORMAL_EXIT') { }
            else {
                $captureText = Get-D32NonSourceL1NativeCaptureText -Capture $native.Stdout
                if ($captureText.Contains($ready) -and -not (Test-D32NonSourceL1NativeSignaled -Process $native.Process)) {
                    $terminationTicks = Get-D32NonSourceL1Now
                    if ($terminationTicks -lt $active -and (Stop-D32NonSourceL1NativeJob -Job $native.Job -ExitCode 0xD3210002)) {
                        $plannedTerminationObserved = $true; $script:D32NonSourceL1PlannedTerminations++
                        $row.planned_termination_count = 1L; $row.planned_termination_ticks = $terminationTicks
                    } else { $row.primary_error = 'planned termination was not accepted while the retained child remained active' }
                    break
                }
            }
            $waitMs = Get-D32NonSourceL1RemainingWaitMilliseconds -DeadlineTicks $active
            if ($waitMs -eq 0) { break }
            $waitState = Wait-D32NonSourceL1NativeProcess -Process $native.Process -Milliseconds $waitMs
            if ($waitState -eq [uint32]0) { $processExited = $true; break }
            if ($waitState -ne [uint32]258) { throw 'retained process wait failed inside active window' }
        }
        if (Test-D32NonSourceL1NativeSignaled -Process $native.Process) { $processExited = $true }
        if (-not $processExited -and -not $plannedTerminationObserved) {
            $row.primary_error = if ($row.primary_error) { [string]$row.primary_error } else { 'fixed child did not complete or become ready within the active deadline' }
            $failSafeTicks = Get-D32NonSourceL1Now
            if ($failSafeTicks -lt $cleanup -and (Stop-D32NonSourceL1NativeJob -Job $native.Job -ExitCode 0xD3210003)) {
                $script:D32NonSourceL1FailSafeTerminations++; $row.fail_safe_termination_count = 1L; $row.fail_safe_termination_ticks = $failSafeTicks
            }
        }
        while (-not (Test-D32NonSourceL1NativeSignaled -Process $native.Process) -and (Get-D32NonSourceL1Now) -lt $cleanup) {
            $waitMs = Get-D32NonSourceL1RemainingWaitMilliseconds -DeadlineTicks $cleanup
            if ($waitMs -eq 0) { break }
            $waitState = Wait-D32NonSourceL1NativeProcess -Process $native.Process -Milliseconds $waitMs
            if ($waitState -eq [uint32]0) { break }
            if ($waitState -ne [uint32]258) { throw 'retained process wait failed inside cleanup window' }
        }
        $processExited = Test-D32NonSourceL1NativeSignaled -Process $native.Process
        if (-not $processExited) { $cleanupKnown = $false; throw 'owned reader exit remained unknown at cleanup deadline' }
        $row.exit_ticks = Get-D32NonSourceL1Now
        $row.exit_code = Get-D32NonSourceL1NativeExitCode -Process $native.Process
        $activeCount = Get-D32NonSourceL1NativeActiveProcessCount -Job $native.Job
        $totalCount = Get-D32NonSourceL1NativeTotalProcessCount -Job $native.Job
        $row.job_active_process_count = $activeCount; $row.job_total_process_count = $totalCount
        $joined = Join-D32NonSourceL1CapturesUntilDeadline -Native $native -DeadlineTicks $cleanup
        $row.capture_join_verified = [bool]$joined
        if ($null -ne $native.Stdout) { $row.stdout_bytes = [Int64]$native.Stdout.Bytes; $row.stdout_sha256 = [string]$native.Stdout.Sha256; $row.stdout_truncated = [bool]$native.Stdout.Truncated }
        if ($null -ne $native.Stderr) { $row.stderr_bytes = [Int64]$native.Stderr.Bytes; $row.stderr_sha256 = [string]$native.Stderr.Sha256; $row.stderr_truncated = [bool]$native.Stderr.Truncated }
        if (-not $joined -or $row.stdout_truncated -or $row.stderr_truncated -or $row.stdout_bytes -gt 1024 -or $row.stderr_bytes -gt 1024 -or
            [String]::IsNullOrEmpty([string]$native.Stdout.Failure) -eq $false -or [String]::IsNullOrEmpty([string]$native.Stderr.Failure) -eq $false -or
            $null -eq $activeCount -or [Int64]$activeCount -ne 0 -or $null -eq $totalCount -or [Int64]$totalCount -ne 1) {
            $row.primary_error = if ($row.primary_error) { [string]$row.primary_error } else { 'capture, Job accounting, or output bound did not verify' }
        }
        $expectedStdout = 'D32NSL1|' + $caseId + '|' + [string]$caseAuthority.nonce + '|READY'
        $expectedStderr = if ($caseId -ceq 'NORMAL_EXIT') { 'D32NSL1|FIXED|NORMAL' } else { 'D32NSL1|FIXED|FORCED' }
        $actualStdout = (Get-D32NonSourceL1NativeCaptureText -Capture $native.Stdout).TrimEnd([char[]]@("`r", "`n"))
        $actualStderr = (Get-D32NonSourceL1NativeCaptureText -Capture $native.Stderr).TrimEnd([char[]]@("`r", "`n"))
        $row.stdout_token_verified = ($joined -and -not $row.stdout_truncated -and $row.stdout_bytes -le 1024 -and $actualStdout -ceq $expectedStdout)
        $row.stderr_token_verified = ($joined -and -not $row.stderr_truncated -and $row.stderr_bytes -le 1024 -and $actualStderr -ceq $expectedStderr)
        if ($actualStdout -cne $expectedStdout -or $actualStderr -cne $expectedStderr) {
            $readerRefusalError = Get-D32NonSourceL1ReaderRefusalError -StderrCapture $actualStderr
            $row.primary_error = if ($readerRefusalError) { [string]$readerRefusalError } else { 'fixed fixture behavior token/capture did not match the exact case' }
        }
        if (-not (Close-D32NonSourceL1NativeJob -Native $native)) { $cleanupKnown = $false; throw 'owned kill-on-close Job handle did not close' }
        $row.job_closed = $true
        if (-not (Close-D32NonSourceL1NativeHandles -Native $native) -or -not $native.TemporaryHandlesClosed) { $cleanupKnown = $false; throw 'retained native process/thread/pipe cleanup did not verify' }
        $row.cleanup_observed_ticks = Get-D32NonSourceL1Now
        if (-not $cleanupKnown) { $row.state = 'UNRESOLVED' }
        elseif ($caseId -ceq 'NORMAL_EXIT' -and $row.exit_code -eq 0 -and $row.stdout_bytes -le 1024 -and $row.stderr_bytes -le 1024 -and -not $row.stdout_truncated -and -not $row.stderr_truncated -and $row.capture_join_verified -and $row.job_active_process_count -eq 0 -and $row.job_total_process_count -eq 1 -and $row.job_closed -and $row.kill_on_close_enabled) { $row.state = 'NATIVE_BOUNDARY_VERIFIED' }
        elseif ($caseId -ceq 'FORCED_OWNED_TERMINATION' -and $plannedTerminationObserved -and $row.planned_termination_count -eq 1 -and $row.planned_termination_ticks -lt $row.exit_ticks -and $row.exit_code -ne 0 -and $row.stdout_bytes -le 1024 -and $row.stderr_bytes -le 1024 -and -not $row.stdout_truncated -and -not $row.stderr_truncated -and $row.capture_join_verified -and $row.job_active_process_count -eq 0 -and $row.job_total_process_count -eq 1 -and $row.job_closed -and $row.kill_on_close_enabled) { $row.state = 'NATIVE_BOUNDARY_VERIFIED' }
        else { $row.state = 'BLOCKED'; if (-not $row.primary_error) { $row.primary_error = 'case did not satisfy its fixed native-boundary expectation' } }
    } catch {
        if (-not $row.primary_error) { $row.primary_error = Get-D32NonSourceL1ErrorText -Exception $_.Exception }
        else { if ($row.secondary_errors.Count -lt 8) { $row.secondary_errors += (Get-D32NonSourceL1ErrorText -Exception $_.Exception) } }
        if ($null -ne $native -and $native.Process -ne [IntPtr]::Zero) {
            try {
                if (-not (Test-D32NonSourceL1NativeSignaled -Process $native.Process) -and (Get-D32NonSourceL1Now) -lt $cleanup) {
                    $script:D32NonSourceL1FailSafeTerminations++
                    $row.fail_safe_termination_count = 1L; $row.fail_safe_termination_ticks = Get-D32NonSourceL1Now
                    if ($native.Job -ne [IntPtr]::Zero -and $native.Assigned) { [void](Stop-D32NonSourceL1NativeJob -Job $native.Job -ExitCode 0xD3210003) }
                    else { [void](Stop-D32NonSourceL1NativeProcess -Process $native.Process -ExitCode 0xD3210003) }
                    while (-not (Test-D32NonSourceL1NativeSignaled -Process $native.Process) -and (Get-D32NonSourceL1Now) -lt $cleanup) {
                        $waitMs = Get-D32NonSourceL1RemainingWaitMilliseconds -DeadlineTicks $cleanup
                        if ($waitMs -eq 0) { break }
                        if ((Wait-D32NonSourceL1NativeProcess -Process $native.Process -Milliseconds $waitMs) -eq [uint32]0) { break }
                    }
                }
                if (-not (Test-D32NonSourceL1NativeSignaled -Process $native.Process)) { $cleanupKnown = $false }
                else {
                    $row.exit_ticks = Get-D32NonSourceL1Now; $row.exit_code = Get-D32NonSourceL1NativeExitCode -Process $native.Process
                    $row.job_active_process_count = if ($native.Job -ne [IntPtr]::Zero) { Get-D32NonSourceL1NativeActiveProcessCount -Job $native.Job } else { $null }
                    $row.job_total_process_count = if ($native.Job -ne [IntPtr]::Zero) { Get-D32NonSourceL1NativeTotalProcessCount -Job $native.Job } else { $null }
                    $row.capture_join_verified = Join-D32NonSourceL1CapturesUntilDeadline -Native $native -DeadlineTicks $cleanup
                    if ($null -ne $native.Stdout) { $row.stdout_bytes = [Int64]$native.Stdout.Bytes; $row.stdout_sha256 = [string]$native.Stdout.Sha256; $row.stdout_truncated = [bool]$native.Stdout.Truncated }
                    if ($null -ne $native.Stderr) { $row.stderr_bytes = [Int64]$native.Stderr.Bytes; $row.stderr_sha256 = [string]$native.Stderr.Sha256; $row.stderr_truncated = [bool]$native.Stderr.Truncated }
                    if ($native.Job -ne [IntPtr]::Zero) { $row.job_closed = Close-D32NonSourceL1NativeJob -Native $native }
                    if (-not (Close-D32NonSourceL1NativeHandles -Native $native)) { $cleanupKnown = $false }
                    $row.cleanup_observed_ticks = Get-D32NonSourceL1Now
                }
            } catch { $cleanupKnown = $false; if ($row.secondary_errors.Count -lt 8) { $row.secondary_errors += (Get-D32NonSourceL1ErrorText -Exception $_.Exception) } }
        } elseif ($null -ne $native) {
            $cleanupKnown = $cleanupKnown -and [bool]$native.PrelaunchHandlesClosed
            $row.job_closed = [bool]$native.JobClosedByNative
        }
        $row.state = if ($cleanupKnown) { if ((Get-D32NonSourceL1Now) -ge $active) { 'BUDGET_STOPPED' } else { 'BLOCKED' } } else { 'UNRESOLVED' }
    }
    return $row
}

function Invoke-D32NonSourceL1CaseBatch {
    for ($index = 0; $index -lt 3; $index++) {
        if ($script:D32NonSourceL1CaseStop -or (Get-D32NonSourceL1Now) -ge $script:D32NonSourceL1BatchDeadline) { break }
        $row = Invoke-D32NonSourceL1Case -Index $index
        $row.case_completed_ticks = Get-D32NonSourceL1Now
        if ($row.state -cne 'UNRESOLVED' -and [Int64]$row.case_completed_ticks -ge [Int64]$row.audit_deadline_ticks) {
            $row.state = 'BUDGET_STOPPED'
            $auditError = 'case audit/completion returned at or beyond its fixed 15-second/batch-bounded deadline'
            if (-not $row.primary_error) { $row.primary_error = $auditError }
            elseif ($row.secondary_errors.Count -lt 8) { $row.secondary_errors += $auditError }
        }
        $row.case_evidence_sha256 = Get-D32BoundedDiagnosticSourceProofNonSourceL1CaseEvidenceSha256 -CaseNonce $row.case_nonce `
            -PrecreateAdmission $row.precreate_admission -ActualInvocation $row.actual_invocation
        $null = $script:D32NonSourceL1Cases.Add($row)
        Add-D32NonSourceL1JournalFact -Event ('CASE_' + [string]$row.state) -CaseId ([string]$row.case_id) `
            -ObservedTicks ([Int64]$row.case_completed_ticks) -CaseEvidenceSha256 ([string]$row.case_evidence_sha256)
        if ([string]$row.state -ceq 'UNRESOLVED') { $script:D32NonSourceL1CaseStop = $true }
    }
    while ($script:D32NonSourceL1Cases.Count -lt 3) {
        $nextCase = [string]$script:D32NonSourceL1Authority.cases[$script:D32NonSourceL1Cases.Count].case_id
        $null = $script:D32NonSourceL1Cases.Add((New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId $nextCase))
    }
    $batchOutcome = Resolve-D32BoundedDiagnosticSourceProofNonSourceL1BatchOutcome -Cases @($script:D32NonSourceL1Cases.ToArray()) `
        -CreateProcessAttemptCount $script:D32NonSourceL1CreateAttempts -PlannedTerminationCount $script:D32NonSourceL1PlannedTerminations `
        -FailSafeTerminationCount $script:D32NonSourceL1FailSafeTerminations `
        -BatchDeadlineReached:((Get-D32NonSourceL1Now) -ge $script:D32NonSourceL1BatchDeadline)
    $script:D32NonSourceL1Status = [string]$batchOutcome.status
    if (-not $script:D32NonSourceL1Primary -and $null -ne $batchOutcome.primary_error) { $script:D32NonSourceL1Primary = [string]$batchOutcome.primary_error }
    return $batchOutcome
}

function Invoke-D32NonSourceL1 {
    $script:D32NonSourceL1StartedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
    $script:D32NonSourceL1CaseStop = $false
    $resultWritten = $false; $journalClosed = $false; $returnCode = 87
    $authorityRaw = $null; $authorityRawReference = $null; $moduleRaw = $null
    try {
        if ($PSVersionTable.PSVersion -lt [version]'7.5' -or -not [Environment]::Is64BitProcess -or
            $CandidateSha -cnotmatch '^[0-9a-f]{40}$' -or $ExpectedL1AuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $L1T0Ticks -le 0 -or [Diagnostics.Stopwatch]::Frequency -le 0 -or
            $script:D32LifecycleControllerEntryTicks -lt $L1T0Ticks -or
            [IO.Path]::GetFullPath($Repository) -cne $Repository -or -not [IO.Path]::IsPathRooted($Repository) -or
            [IO.Path]::GetFullPath($L1AuthorityPath) -cne $L1AuthorityPath -or -not (Test-D32LifecycleNoReparsePath -Path $L1AuthorityPath)) {
            throw 'D32_NON_SOURCE_L1_REFUSED: fixed candidate/repository/runtime/caller clock input invalid'
        }
        $script:D32NonSourceL1Now = { [Diagnostics.Stopwatch]::GetTimestamp() }
        $frequency = [Int64][Diagnostics.Stopwatch]::Frequency
        $script:D32NonSourceL1BatchDeadline = Get-D32NonSourceL1DeadlineTicks -T0Ticks $L1T0Ticks -Frequency $frequency -Milliseconds 60000L
        if ((Get-D32NonSourceL1Now) -lt $L1T0Ticks -or (Get-D32NonSourceL1Now) -ge $script:D32NonSourceL1BatchDeadline) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: controller admission reached batch deadline' }

        # The fixed lifecycle type is used by the first caller-pinned byte read
        # to bind the opened authority identity. Initialize only this existing,
        # in-process native surface before that read; no native entry call occurs
        # until the authority, output root, and all code/runtime pins are admitted.
        Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop | Out-Null

        # The initial L1 record read is caller-pinned and bounded. The path is
        # re-opened through the fixed module-free authority loader below.
        $authorityRaw = Get-D32LifecycleReferenceBytes -Path $L1AuthorityPath -MaximumBytes 1048576 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1OwnedBuffers += [Int64]$authorityRaw.Reference.bytes
        $authorityRawReference = $authorityRaw.Reference
        if ($authorityRaw.Reference.sha256 -cne $ExpectedL1AuthoritySha256 -or $script:D32NonSourceL1OwnedBuffers -gt 16777216) {
            throw 'D32_NON_SOURCE_L1_REFUSED: caller-pinned L1 authority hash or buffer bound mismatch'
        }
        $authorityJson = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$authorityRaw.Bytes))
        try {
            if ($authorityJson.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32LifecycleJsonDuplicates -Element $authorityJson.RootElement)) { throw 'D32_NON_SOURCE_L1_REFUSED: authority root/duplicate check failed' }
            $script:D32NonSourceL1Authority = ConvertFrom-D32LifecycleJsonElement -Element $authorityJson.RootElement
        } finally { $authorityJson.Dispose() }
        if ($null -ne $authorityRaw.Stream) { $authorityRaw.Stream.Dispose(); $authorityRaw = $null }

        # Bootstrap solely from the independently caller-pinned six-file L1
        # authority. This branch never reads SourceProof authority/Profile/origin.
        $modulePath = [IO.Path]::GetFullPath((Join-Path $Repository 'scripts/d32-powershell-module-authority.ps1'))
        $modulePin = @($script:D32NonSourceL1Authority.source_pins | Where-Object { [string]$_.path -ceq $modulePath })
        if ($modulePin.Count -ne 1) { throw 'D32_NON_SOURCE_L1_REFUSED: exact fixed authority loader pin absent' }
        $moduleRaw = Get-D32LifecycleReferenceBytes -Path $modulePath -MaximumBytes 16777216 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1OwnedBuffers += [Int64]$moduleRaw.Reference.bytes
        foreach ($name in @('bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ([string]$moduleRaw.Reference.($name) -cne [string]$modulePin[0].($name)) { throw 'D32_NON_SOURCE_L1_REFUSED: bootstrap loader pin mismatch' } }
        if ($script:D32NonSourceL1OwnedBuffers -gt 16777216) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: fixed bootstrap buffers exceed 16 MiB' }
        . ([ScriptBlock]::Create([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$moduleRaw.Bytes)))
        if ($null -ne $moduleRaw.Stream) { $moduleRaw.Stream.Dispose(); $moduleRaw = $null }
        $script:D32LifecycleFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
        $authorityOpened = Open-D32PowerShellAuthorityFile -Path $L1AuthorityPath -DirectoryFences $script:D32LifecycleFences -MaximumBytes 1048576 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1Opened.Add($authorityOpened)
        $script:D32NonSourceL1OwnedBuffers += [Int64]$authorityOpened.Record.bytes
        foreach ($name in @('bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ([string]$authorityOpened.Record.($name) -cne [string]$authorityRawReference.($name)) { throw 'D32_NON_SOURCE_L1_REFUSED: authority reopened identity differs from initial caller pin' } }
        if ($script:D32NonSourceL1OwnedBuffers -gt 16777216) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: reopened authority buffer exceeds 16 MiB' }
        $authorityJson = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$authorityOpened.Bytes))
        try {
            if ($authorityJson.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $authorityJson.RootElement)) { throw 'D32_NON_SOURCE_L1_REFUSED: strict authority JSON duplicates or root shape invalid' }
            $script:D32NonSourceL1Authority = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $authorityJson.RootElement
        } finally { $authorityJson.Dispose() }
        $script:D32NonSourceL1AuthorityReference = Get-D32NonSourceL1ReferenceFromOpened -Opened $authorityOpened

        $policyPath = [IO.Path]::GetFullPath((Join-Path $Repository 'scripts/d32-bounded-compiler-diagnostic-policy.ps1'))
        $policyPin = @($script:D32NonSourceL1Authority.source_pins | Where-Object { [string]$_.path -ceq $policyPath })
        if ($policyPin.Count -ne 1) { throw 'D32_NON_SOURCE_L1_REFUSED: fixed policy pin absent' }
        $policyOpened = Open-D32PowerShellAuthorityFile -Path $policyPath -DirectoryFences $script:D32LifecycleFences -MaximumBytes 16777216 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1Opened.Add($policyOpened); $script:D32NonSourceL1OwnedBuffers += [Int64]$policyOpened.Record.bytes
        foreach ($name in @('bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ([string]$policyOpened.Record.($name) -cne [string]$policyPin[0].($name)) { throw 'D32_NON_SOURCE_L1_REFUSED: pinned strict L1 policy drifted' } }
        if ($script:D32NonSourceL1OwnedBuffers -gt 16777216) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: verified code buffers exceed 16 MiB' }
        . ([ScriptBlock]::Create([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$policyOpened.Bytes)))

        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $script:D32NonSourceL1Authority -ExpectedCandidateSha $CandidateSha -Repository $Repository) -or
            [string]$script:D32NonSourceL1Authority.source_pins[0].path -cne [IO.Path]::GetFullPath($PSCommandPath) -or
            [string]$script:D32NonSourceL1Authority.invocation.entry_path -cne [IO.Path]::GetFullPath((Join-Path $Repository 'scripts/d32-bounded-diagnostic-sourceproof.ps1')) -or
            (Test-D32PowerShellAuthorityPathWithin -Child $L1AuthorityPath -Parent $Repository) -or
            (Test-D32PowerShellAuthorityPathWithin -Child $L1AuthorityPath -Parent 'E:\d32\inv7\r\c') -or
            (Test-D32PowerShellAuthorityPathWithin -Child $L1AuthorityPath -Parent ([string]$script:D32NonSourceL1Authority.output.root_path))) {
            throw 'D32_NON_SOURCE_L1_REFUSED: strict L1 authority or fixed external role bindings failed'
        }
        if ([string]$script:D32NonSourceL1Authority.source_repo -cne $Repository -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$script:D32NonSourceL1Authority.powershell_runtime.path), [IO.Path]::GetFullPath([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName))) {
            throw 'D32_NON_SOURCE_L1_REFUSED: current repository/runtime role binding mismatch'
        }
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try { if ([string]$currentIdentity.User.Value -cne [string]$script:D32NonSourceL1Authority.owner_id) { throw 'D32_NON_SOURCE_L1_REFUSED: current Windows owner differs from the authority owner binding' } }
        finally { $currentIdentity.Dispose() }
        $repoIdentity = Get-D32LifecycleDirectoryIdentity $Repository
        if ($repoIdentity.VolumeSerialHex -cne [string]$script:D32NonSourceL1Authority.repository_identity.volume_serial_hex -or $repoIdentity.FileIdHex -cne [string]$script:D32NonSourceL1Authority.repository_identity.file_id_hex) {
            throw 'D32_NON_SOURCE_L1_REFUSED: repository directory identity drift'
        }
        $rootIdentity = Get-D32LifecycleDirectoryIdentity ([string]$script:D32NonSourceL1Authority.output.root_path)
        $parentIdentity = Get-D32LifecycleDirectoryIdentity ([string]$script:D32NonSourceL1Authority.output.parent_path)
        foreach ($pair in @(@('root_volume_serial_hex', 'root_file_id_hex', $rootIdentity), @('parent_volume_serial_hex', 'parent_file_id_hex', $parentIdentity))) {
            if ([string]$script:D32NonSourceL1Authority.output.($pair[0]) -cne [string]$pair[2].VolumeSerialHex -or [string]$script:D32NonSourceL1Authority.output.($pair[1]) -cne [string]$pair[2].FileIdHex) { throw 'D32_NON_SOURCE_L1_REFUSED: external root/parent opened identity drift' }
        }
        $rootSecurity = [System.IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new([string]$script:D32NonSourceL1Authority.output.root_path))
        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RootSecurity -Security $rootSecurity -OwnerSid ([string]$script:D32NonSourceL1Authority.owner_id))) {
            throw 'D32_NON_SOURCE_L1_REFUSED: fresh external root owner-bound DACL is not protected by the fixed trusted-writer allowlist'
        }
        if ((Test-D32PowerShellAuthorityPathWithin -Child ([string]$script:D32NonSourceL1Authority.output.root_path) -Parent $Repository) -or
            (Test-D32PowerShellAuthorityPathWithin -Child ([string]$script:D32NonSourceL1Authority.output.root_path) -Parent 'E:\d32\inv7\r\c')) { throw 'D32_NON_SOURCE_L1_REFUSED: external L1 root violates fixed containment' }
        foreach ($path in @([string]$script:D32NonSourceL1Authority.output.result_path, [string]$script:D32NonSourceL1Authority.output.journal_path)) {
            if ([IO.File]::Exists($path) -or [IO.Directory]::Exists($path)) { throw 'D32_NON_SOURCE_L1_REFUSED: create-new result/journal path already exists' }
        }
        $script:D32NonSourceL1AdmissionValidated = $true
        $script:D32NonSourceL1JournalStream = [IO.File]::Open([string]$script:D32NonSourceL1Authority.output.journal_path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        Add-D32NonSourceL1JournalFact -Event 'AUTHORITY_ADMISSION' -ScheduledTicks $L1T0Ticks -ObservedTicks (Get-D32NonSourceL1Now)

        # Open and hash only the six fixed script pins, plus the fixed runtime.
        # Profile V2 is treated as a pinned script byte sequence only: it is not
        # semantically parsed and no manifest/lock/config path is traversed.
        for ($index = 0; $index -lt 6; $index++) {
            $pin = $script:D32NonSourceL1Authority.source_pins[$index]
            $opened = Open-D32NonSourceL1PinnedFile -Path ([string]$pin.path) -Pin $pin
            if ($index -eq 3) { } # strict policy was already dot-sourced from these verified bytes
        }
        $runtimePin = $script:D32NonSourceL1Authority.powershell_runtime
        $runtimeOpened = Open-D32NonSourceL1PinnedFile -Path ([string]$runtimePin.path) -Pin ([PSCustomObject]@{
            path = $runtimePin.path; bytes = $runtimePin.bytes; sha256 = $runtimePin.sha256
            volume_serial_hex = $runtimePin.volume_serial_hex; file_id_hex = $runtimePin.file_id_hex
        })
        $script:D32NonSourceL1Opened.Add($runtimeOpened)

        $null = Invoke-D32NonSourceL1CaseBatch
    } catch {
        $caughtError = Get-D32NonSourceL1ErrorText -Exception $_.Exception
        $null = Add-D32NonSourceL1Error -Exception $_.Exception -Message $caughtError
        $script:D32NonSourceL1Status = Get-D32NonSourceL1FailureStatus -ErrorText $caughtError
    } finally {
        $cleanupFailed = $false
        if ($null -ne $authorityRaw -and $null -ne $authorityRaw.Stream) {
            try { $authorityRaw.Stream.Dispose() } catch { $cleanupFailed = $true; $null = Add-D32NonSourceL1Error -Exception $_.Exception }
        }
        if ($null -ne $moduleRaw -and $null -ne $moduleRaw.Stream) {
            try { $moduleRaw.Stream.Dispose() } catch { $cleanupFailed = $true; $null = Add-D32NonSourceL1Error -Exception $_.Exception }
        }
        foreach ($opened in $script:D32NonSourceL1Opened) {
            try { if ($null -ne $opened.Stream -and -not $opened.Stream.SafeFileHandle.IsClosed) { $opened.Stream.Dispose() } }
            catch { $cleanupFailed = $true; $null = Add-D32NonSourceL1Error -Exception $_.Exception }
        }
        if ($null -ne $script:D32LifecycleFences) {
            foreach ($fence in $script:D32LifecycleFences.Values) {
                try { if ($null -ne $fence.Handle -and -not $fence.Handle.IsClosed) { $fence.Handle.Dispose() } }
                catch { $cleanupFailed = $true; $null = Add-D32NonSourceL1Error -Exception $_.Exception }
            }
        }
        if ($cleanupFailed) { $script:D32NonSourceL1Status = 'UNRESOLVED' }
    }

    if (-not $script:D32NonSourceL1AdmissionValidated) { return 87 }
    if ((Get-D32NonSourceL1Now) -ge $script:D32NonSourceL1BatchDeadline) {
        $script:D32NonSourceL1Status = 'BUDGET_STOPPED'
        if (-not $script:D32NonSourceL1Primary) { $script:D32NonSourceL1Primary = 'batch deadline reached before bounded result persistence' }
    }
    try {
        $record = New-D32BoundedDiagnosticSourceProofNonSourceL1ResultCandidate -CandidateSha $CandidateSha `
            -BatchId ([string]$script:D32NonSourceL1Authority.batch_id) -RunId ([string]$script:D32NonSourceL1Authority.run_id) `
            -AuthorityReference $script:D32NonSourceL1AuthorityReference -SourcePins @($script:D32NonSourceL1Authority.source_pins) `
            -PowerShellRuntime ([PSCustomObject][ordered]@{ path = $script:D32NonSourceL1Authority.powershell_runtime.path; bytes = $script:D32NonSourceL1Authority.powershell_runtime.bytes; sha256 = $script:D32NonSourceL1Authority.powershell_runtime.sha256; volume_serial_hex = $script:D32NonSourceL1Authority.powershell_runtime.volume_serial_hex; file_id_hex = $script:D32NonSourceL1Authority.powershell_runtime.file_id_hex }) `
            -Output $script:D32NonSourceL1Authority.output `
            -Clock ([PSCustomObject][ordered]@{ counter_origin = 'QueryPerformanceCounter'; frequency = $frequency; batch_t0_ticks = $L1T0Ticks; batch_deadline_ticks = $script:D32NonSourceL1BatchDeadline; controller_entry_ticks = $script:D32LifecycleControllerEntryTicks }) `
            -Controller ([PSCustomObject][ordered]@{ process_id = [Int64]$PID; creation_filetime_ticks = (Get-D32LifecycleProcessCreationFileTime) }) `
            -Cases @($script:D32NonSourceL1Cases.ToArray()) -CreateProcessAttemptCount $script:D32NonSourceL1CreateAttempts `
            -PlannedTerminationCount $script:D32NonSourceL1PlannedTerminations -FailSafeTerminationCount $script:D32NonSourceL1FailSafeTerminations `
            -Status $script:D32NonSourceL1Status -PrimaryError $script:D32NonSourceL1Primary -SecondaryErrors @($script:D32NonSourceL1Secondary.ToArray()) `
            -StartedAtUtc $script:D32NonSourceL1StartedAtUtc -CompletedAtUtc ([DateTimeOffset]::UtcNow.ToString('o'))
        $bytes = ConvertTo-D32NonSourceL1ResultBytes -Record $record
        if ((Get-D32NonSourceL1Now) -ge $script:D32NonSourceL1BatchDeadline) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: result size or batch persistence deadline exceeded' }
        $resultStream = [IO.File]::Open([string]$script:D32NonSourceL1Authority.output.result_path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        try { $resultStream.Write($bytes, 0, $bytes.Length); $resultStream.Flush($true) } finally { $resultStream.Dispose() }
        if ((Get-D32NonSourceL1Now) -ge $script:D32NonSourceL1BatchDeadline) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: result flush returned after batch deadline' }
        $resultOpened = Open-D32PowerShellAuthorityFile -Path ([string]$script:D32NonSourceL1Authority.output.result_path) -DirectoryFences ([System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)) -MaximumBytes 65536 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $resultDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$resultOpened.Bytes))
        try {
            if ($resultDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $resultDocument.RootElement)) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: persisted L1 result JSON is duplicate or non-object' }
            $readback = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $resultDocument.RootElement
        } finally { $resultDocument.Dispose(); if ($null -ne $resultOpened.Stream) { $resultOpened.Stream.Dispose() } }
        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape $readback)) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: persisted L1 result failed strict readback' }
        $persistedFact = New-D32NonSourceL1ResultPersistedFact -ResultReference $resultOpened.Record -ObservedTicks (Get-D32NonSourceL1Now)
        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultBindings -Record $readback -Authority $script:D32NonSourceL1Authority `
            -AuthorityReference $script:D32NonSourceL1AuthorityReference -ExpectedAuthorityPath $L1AuthorityPath -ExpectedAuthoritySha256 $ExpectedL1AuthoritySha256 `
            -PersistedFact $persistedFact -ResultReference $resultOpened.Record)) {
            throw 'D32_NON_SOURCE_L1_UNRESOLVED: persisted result authority/source/runtime/case/flush chain failed binding'
        }
        Add-D32NonSourceL1JournalFact -Event 'L1_RESULT_PERSISTED' -ObservedTicks ([Int64]$persistedFact.observed_ticks) -ResultReference $resultOpened.Record
        $journalClosed = $false
        if ($null -ne $script:D32NonSourceL1JournalStream) {
            try { $script:D32NonSourceL1JournalStream.Flush($true); $script:D32NonSourceL1JournalStream.Dispose(); $script:D32NonSourceL1JournalStream = $null; $journalClosed = $true } catch { $journalClosed = $false }
        }
        $resultWritten = $true
        $journalFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
        $journalOpened = Open-D32PowerShellAuthorityFile -Path ([string]$script:D32NonSourceL1Authority.output.journal_path) -DirectoryFences $journalFences -MaximumBytes 65536 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        try {
            $journalCallerObserved = Get-D32NonSourceL1Now
            if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultPersistence -Record $readback -PersistedFact $persistedFact `
                -ResultReference $resultOpened.Record -JournalReference $journalOpened.Record -JournalBytes ([byte[]]$journalOpened.Bytes) -CallerObservedTicks $journalCallerObserved)) {
                throw 'D32_NON_SOURCE_L1_UNRESOLVED: caller journal re-readback or persistence reconciliation failed'
            }
        } finally {
            if ($null -ne $journalOpened.Stream) { $journalOpened.Stream.Dispose() }
            foreach ($fence in $journalFences.Values) { if ($null -ne $fence.Handle -and -not $fence.Handle.IsClosed) { $fence.Handle.Dispose() } }
        }
        if ($readback.status -ceq 'COMPLETE_NON_SOURCE_L1' -and $journalClosed -and (Get-D32NonSourceL1Now) -lt $script:D32NonSourceL1BatchDeadline) { $returnCode = 0 }
        elseif ($readback.status -ceq 'BUDGET_STOPPED') { $returnCode = 86 }
        else { $returnCode = 87 }
    } catch {
        $caughtError = Get-D32NonSourceL1ErrorText -Exception $_.Exception
        $null = Add-D32NonSourceL1Error -Exception $_.Exception -Message $caughtError
        if ($null -ne $script:D32NonSourceL1JournalStream) {
            try { $script:D32NonSourceL1JournalStream.Flush($true); $script:D32NonSourceL1JournalStream.Dispose(); $script:D32NonSourceL1JournalStream = $null }
            catch { $null = Add-D32NonSourceL1Error -Exception $_.Exception }
        }
        $returnCode = 87
    }
    return $returnCode
}

if ($PSCmdlet.ParameterSetName -ceq 'NonSourceL1') {
    $l1ExitCode = 87
    try { $l1ExitCode = [int](Invoke-D32NonSourceL1) }
    catch {
        $escapedError = Get-D32NonSourceL1ErrorText -Exception $_.Exception
        $null = Add-D32NonSourceL1Error -Exception $_.Exception -Message $escapedError
        if ($script:D32NonSourceL1AdmissionValidated) { $script:D32NonSourceL1Status = 'UNRESOLVED' }
        else { $script:D32NonSourceL1Status = Get-D32NonSourceL1FailureStatus -ErrorText $escapedError }
        $l1ExitCode = 87
    }
    $diagnosticStatus = [string]$script:D32NonSourceL1Status
    $diagnosticPrimary = [string]$script:D32NonSourceL1Primary
    if ($l1ExitCode -ne 0 -or $diagnosticStatus -cne 'COMPLETE_NON_SOURCE_L1') {
        if ([String]::IsNullOrWhiteSpace($diagnosticPrimary) -and $script:D32NonSourceL1Secondary.Count -gt 0) {
            $diagnosticPrimary = [string]$script:D32NonSourceL1Secondary[0]
        }
        if ($diagnosticStatus -ceq 'COMPLETE_NON_SOURCE_L1') { $diagnosticStatus = 'UNRESOLVED' }
        $null = Write-D32NonSourceL1Diagnostic -Status $diagnosticStatus -PrimaryError $diagnosticPrimary `
            -SecondaryErrors @($script:D32NonSourceL1Secondary.ToArray()) -Writer ([Console]::Error)
    }
    exit $l1ExitCode
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
