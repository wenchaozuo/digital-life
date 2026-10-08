# Durable module-free supervisor for one caller-authorized SourceProofOnly run.
# No shell, helper executable, retry, or free-form child argv is accepted.
[CmdletBinding(DefaultParameterSetName = 'SourceProofOnly')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][Parameter(Mandatory = $true, ParameterSetName = 'OuterCaller')][string]$Repository,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][Parameter(Mandatory = $true, ParameterSetName = 'OuterCaller')][string]$CandidateSha,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][string]$ExecutionAuthorityPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][string]$ExpectedExecutionAuthoritySha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][long]$LifecycleT0Ticks,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][switch]$NonSourceL1,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][Parameter(Mandatory = $true, ParameterSetName = 'OuterCaller')][string]$L1AuthorityPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][Parameter(Mandatory = $true, ParameterSetName = 'OuterCaller')][string]$ExpectedL1AuthoritySha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][string]$ExpectedOuterPrelaunchBindingSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][long]$L1T0Ticks,
    [Parameter(Mandatory = $true, ParameterSetName = 'OuterCaller')][switch]$FixedOuterCaller
)

$ErrorActionPreference = 'Stop'
if ($PSCmdlet.ParameterSetName -cne 'NonSourceL1') { Set-StrictMode -Version Latest }
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
# Private in-process synthetic test seam only. The operational entry never
# accepts this as an argument and leaves it null, preserving each fixed
# production metadata/file operation below.
$script:D32NonSourceL1EnvironmentAdapter = $null
$script:D32NonSourceL1OuterPrelaunchReference = $null
$script:D32NonSourceL1RuntimeAdmissions = @()
$script:D32NonSourceL1RuntimeAuthorityContent = $null
$script:D32NonSourceL1RuntimeAuthorityOpenedReference = $null
$script:D32NonSourceL1RuntimeAuthorityElement = $null
$script:D32NonSourceL1ModuleImportOrder = [System.Collections.Generic.List[string]]::new()
$script:D32NonSourceL1RuntimeContext = $null
$script:D32NonSourceL1CallerAdapter = $null
# Operational invocations leave this null. The module-free L0 self-test uses
# a private managed provider for the same fixed outer-caller lifecycle calls.
$script:D32NonSourceL1OuterNativeAdapter = $null

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
    public bool JobCreated;
    public bool JobActiveProcessLimitOne;
    public bool JobActiveProcessLimitTwo;
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

public sealed class D32LifecycleOuterLaunchPreparationV1 {
    public D32LifecycleOwnedProcessV1 Owned;
    public IntPtr Stdin;
    public IntPtr StdoutWrite;
    public IntPtr StderrWrite;
    public IntPtr AttributeList;
    public IntPtr AttributeValue;
    public IntPtr EnvironmentBlock;
    public string EnvironmentText;
    public bool AttributeListApplied;
    public bool AmbientHandleInheritanceRestricted;
    public uint StdinAccessMask;
    public uint StdoutWriteAccessMask;
    public uint StderrWriteAccessMask;
    public bool Prepared;
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
    [DllImport("kernel32.dll", SetLastError=true, EntryPoint="QueryInformationJobObject")] static extern bool QueryExtendedJobLimitInformation(IntPtr job, int infoClass, ref ExtendedLimitInformation info, uint length, out uint returned);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CreatePipe(out IntPtr readPipe, out IntPtr writePipe, ref SecurityAttributes attributes, uint size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="CreateFileW")] static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="CreateFileW", ExactSpelling=true)] static extern IntPtr CreateFileWInheritable(string name, uint access, uint share, ref SecurityAttributes security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetHandleInformation(IntPtr handle, out uint flags);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint GetFileType(IntPtr handle);
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
        if (String.IsNullOrWhiteSpace(image) || arguments == null || arguments.Length != 30 || String.IsNullOrWhiteSpace(workingDirectory) ||
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

    // The fixed outer caller prepares its actual NUL/pipe handles, nested Job,
    // and STARTUPINFOEX allowlist before it persists the H-bound prelaunch
    // record. Launch consumes that reopened record's exact command line.
    public static D32LifecycleOuterLaunchPreparationV1 PrepareOuterController(string image, string[] arguments,
        string workingDirectory, string[] environmentEntries) {
        if (String.IsNullOrWhiteSpace(image) || arguments == null || arguments.Length != 18 ||
            arguments[16] != "-ExpectedOuterPrelaunchBindingSha256" || arguments[17] == null || arguments[17].Length != 64)
            throw new InvalidDataException("fixed outer controller argv is incomplete");
        for (int i = 0; i < arguments.Length; i++) if (arguments[i] == null || arguments[i].IndexOf('\0') >= 0) throw new InvalidDataException("fixed outer argv contains null or NUL");
        if (arguments[17] != new String('0', 64)) throw new InvalidDataException("outer controller prelaunch binding placeholder is not canonical");
        if (String.IsNullOrWhiteSpace(workingDirectory)) throw new InvalidDataException("fixed outer working directory is empty");
        D32LifecycleOuterLaunchPreparationV1 prepared = new D32LifecycleOuterLaunchPreparationV1();
        prepared.Owned = new D32LifecycleOwnedProcessV1();
        prepared.Owned.Invocation = new D32LifecycleInvocationV1();
        D32LifecycleInvocationV1 invocation = prepared.Owned.Invocation;
        invocation.ImagePath = image; invocation.Arguments = (string[])arguments.Clone(); invocation.WorkingDirectory = workingDirectory;
        invocation.EnvironmentEntries = environmentEntries == null ? null : (string[])environmentEntries.Clone();
        invocation.HandleRoles = new string[] { "stdin:NUL", "stdout:PIPE_WRITE", "stderr:PIPE_WRITE" };
        invocation.CreationFlags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
        invocation.InheritHandles = true;
        String[] sorted = (string[])environmentEntries.Clone(); Array.Sort(sorted, StringComparer.OrdinalIgnoreCase);
        prepared.EnvironmentText = BuildEnvironmentBlock(sorted);
        invocation.EnvironmentEntries = sorted;
        invocation.EnvironmentBlockSha256 = HashEnvironmentBlock(prepared.EnvironmentText);
        StringBuilder projected = new StringBuilder(); projected.Append(QuoteArgument(image));
        foreach (string argument in arguments) { projected.Append(' '); projected.Append(QuoteArgument(argument)); }
        invocation.CommandLine = projected.ToString();
        if (invocation.CommandLine.Length >= 32767) throw new InvalidDataException("fixed outer controller command line exceeds Windows limit");
        try {
            prepared.Owned.Job = CreateJobObjectW(IntPtr.Zero, null);
            if (prepared.Owned.Job == IntPtr.Zero) throw LastError("CreateJobObjectW(outer caller) failed");
            prepared.Owned.JobCreated = true;
            ExtendedLimitInformation limits = new ExtendedLimitInformation();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = 2;
            if (!SetInformationJobObject(prepared.Owned.Job, JobObjectExtendedLimitInformation, ref limits, (uint)Marshal.SizeOf<ExtendedLimitInformation>()))
                throw LastError("SetInformationJobObject(outer caller) failed");
            ExtendedLimitInformation queriedLimits = new ExtendedLimitInformation(); uint returnedLimits;
            if (!QueryExtendedJobLimitInformation(prepared.Owned.Job, JobObjectExtendedLimitInformation, ref queriedLimits,
                    (uint)Marshal.SizeOf<ExtendedLimitInformation>(), out returnedLimits) || returnedLimits < Marshal.SizeOf<ExtendedLimitInformation>())
                throw LastError("QueryInformationJobObject(outer caller limits) failed");
            uint requiredFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            uint forbiddenFlags = 0x00000800 | 0x00001000; // BREAKAWAY_OK | SILENT_BREAKAWAY_OK
            if ((queriedLimits.BasicLimitInformation.LimitFlags & requiredFlags) != requiredFlags ||
                (queriedLimits.BasicLimitInformation.LimitFlags & forbiddenFlags) != 0 ||
                queriedLimits.BasicLimitInformation.ActiveProcessLimit != 2)
                throw new InvalidDataException("observed outer Job limits differ from the exact kill-on-close, two-process, non-breakaway contract");
            prepared.Owned.JobKillOnClose = true; prepared.Owned.JobActiveProcessLimitTwo = true;
            prepared.Owned.JobInstanceId = Guid.NewGuid().ToString("N");

            SecurityAttributes sa = new SecurityAttributes(); sa.nLength = Marshal.SizeOf<SecurityAttributes>(); sa.bInheritHandle = 1;
            prepared.Stdin = CreateFileWInheritable("NUL", 0x80000000, 3, ref sa, 3, 0x80, IntPtr.Zero);
            if (prepared.Stdin == IntPtr.Zero || prepared.Stdin == new IntPtr(-1)) throw LastError("open outer NUL stdin failed");
            InitPipe(out prepared.Owned.StdoutRead, out prepared.StdoutWrite);
            InitPipe(out prepared.Owned.StderrRead, out prepared.StderrWrite);
            invocation.StdinInheritable = HandleInheritable(prepared.Stdin, "outer stdin");
            invocation.StdoutWriteInheritable = HandleInheritable(prepared.StdoutWrite, "outer stdout write");
            invocation.StderrWriteInheritable = HandleInheritable(prepared.StderrWrite, "outer stderr write");
            invocation.StdoutReadInheritable = HandleInheritable(prepared.Owned.StdoutRead, "outer stdout read");
            invocation.StderrReadInheritable = HandleInheritable(prepared.Owned.StderrRead, "outer stderr read");
            if (GetFileType(prepared.Stdin) != 2 || GetFileType(prepared.StdoutWrite) != 3 || GetFileType(prepared.StderrWrite) != 3 ||
                GetFileType(prepared.Owned.StdoutRead) != 3 || GetFileType(prepared.Owned.StderrRead) != 3 ||
                invocation.StdinInheritable != true || invocation.StdoutWriteInheritable != true || invocation.StderrWriteInheritable != true ||
                invocation.StdoutReadInheritable != false || invocation.StderrReadInheritable != false)
                throw new InvalidDataException("observed outer standard handle type/access/inheritance differs from the exact allowlist");
            prepared.StdinAccessMask = 0x80000000; // GENERIC_READ on NUL; no write/append rights
            prepared.StdoutWriteAccessMask = 0x40000000; // CreatePipe write end
            prepared.StderrWriteAccessMask = 0x40000000;
            IntPtr size = IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            if (size == IntPtr.Zero) throw LastError("InitializeProcThreadAttributeList(size) outer failed");
            prepared.AttributeList = Marshal.AllocHGlobal(size);
            if (!InitializeProcThreadAttributeList(prepared.AttributeList, 1, 0, ref size)) throw LastError("InitializeProcThreadAttributeList(outer) failed");
            prepared.AttributeValue = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(prepared.AttributeValue, 0, prepared.Stdin);
            Marshal.WriteIntPtr(prepared.AttributeValue, IntPtr.Size, prepared.StdoutWrite);
            Marshal.WriteIntPtr(prepared.AttributeValue, IntPtr.Size * 2, prepared.StderrWrite);
            if (!UpdateProcThreadAttribute(prepared.AttributeList, 0, new IntPtr(PROC_THREAD_ATTRIBUTE_HANDLE_LIST),
                prepared.AttributeValue, new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero)) throw LastError("UpdateProcThreadAttribute(outer handle allowlist) failed");
            prepared.AttributeListApplied = true;
            prepared.AmbientHandleInheritanceRestricted = true;
            invocation.HandleListApplied = true;
            prepared.EnvironmentBlock = Marshal.StringToHGlobalUni(prepared.EnvironmentText);
            prepared.Prepared = true;
            return prepared;
        } catch {
            if (!CloseOuterControllerPreparation(prepared)) throw new IOException("outer controller preparation cleanup could not be verified");
            throw;
        }
    }

    public static D32LifecycleOwnedProcessV1 LaunchOuterController(D32LifecycleOuterLaunchPreparationV1 prepared,
        string exactPersistedCommandLine, long batchT0Ticks, long counterFrequency, long batchDeadlineTicks) {
        if (prepared == null || !prepared.Prepared || prepared.Owned == null || prepared.Owned.Invocation == null ||
            !prepared.AttributeListApplied || !prepared.AmbientHandleInheritanceRestricted ||
            String.IsNullOrEmpty(exactPersistedCommandLine) || exactPersistedCommandLine.IndexOf('\0') >= 0 ||
            exactPersistedCommandLine != prepared.Owned.Invocation.CommandLine || batchT0Ticks <= 0 || counterFrequency <= 0 || batchDeadlineTicks <= batchT0Ticks)
            throw new InvalidDataException("outer controller prelaunch was not prepared or exact persisted command line changed");
        D32LifecycleOwnedProcessV1 owned = prepared.Owned;
        D32LifecycleInvocationV1 invocation = owned.Invocation;
        ProcessInformation pi = new ProcessInformation();
        try {
            if (System.Diagnostics.Stopwatch.GetTimestamp() >= batchDeadlineTicks) throw new TimeoutException("outer caller batch cutoff before CreateProcessW");
            StartupInfoEx startup = new StartupInfoEx(); startup.StartupInfo.cb = Marshal.SizeOf<StartupInfoEx>();
            startup.StartupInfo.dwFlags = 0x00000100; startup.StartupInfo.hStdInput = prepared.Stdin;
            startup.StartupInfo.hStdOutput = prepared.StdoutWrite; startup.StartupInfo.hStdError = prepared.StderrWrite;
            startup.lpAttributeList = prepared.AttributeList;
            invocation.ApiAttempted = true; invocation.ApiAttemptTicks = System.Diagnostics.Stopwatch.GetTimestamp();
            owned.CreateProcessAttempted = true; owned.CreateProcessAttemptTicks = invocation.ApiAttemptTicks.Value;
            if (!CreateProcessW(invocation.ImagePath, new StringBuilder(exactPersistedCommandLine), IntPtr.Zero, IntPtr.Zero, true,
                    invocation.CreationFlags, prepared.EnvironmentBlock, invocation.WorkingDirectory, ref startup, out pi)) {
                invocation.ApiReturned = false; invocation.ApiErrorCode = Marshal.GetLastWin32Error();
                owned.Failure = new Win32Exception(invocation.ApiErrorCode.Value, "CreateProcessW(outer controller) failed").Message;
                return owned;
            }
            invocation.ApiReturned = true; invocation.ProcessId = pi.dwProcessId;
            owned.Process = pi.hProcess; owned.Thread = pi.hThread; owned.ProcessId = pi.dwProcessId;
            if (!AssignProcessToJobObject(owned.Job, owned.Process)) {
                owned.Failure = LastError("AssignProcessToJobObject(outer controller) failed").Message;
                TerminateProcess(owned.Process, 0xD3204001); return owned;
            }
            owned.Assigned = true; owned.JobAssignmentTicks = System.Diagnostics.Stopwatch.GetTimestamp();
            FileTime created, exited, kernel, user;
            if (!GetProcessTimes(owned.Process, out created, out exited, out kernel, out user)) {
                owned.Failure = LastError("GetProcessTimes(outer controller) failed").Message;
                TerminateJobObject(owned.Job, 0xD3204002); return owned;
            }
            owned.CreationFileTime = created.Value; invocation.CreationFileTimeTicks = created.Value;
            owned.ImagePath = GetProcessImagePath(owned.Process); invocation.ProcessImagePath = owned.ImagePath;
            invocation.ProcessImageBindingVerified = StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(owned.ImagePath), Path.GetFullPath(invocation.ImagePath));
            if (!invocation.ProcessImageBindingVerified) {
                owned.Failure = "outer controller image differs from the pinned PowerShell host";
                TerminateJobObject(owned.Job, 0xD3204003); return owned;
            }
            if (System.Diagnostics.Stopwatch.GetTimestamp() >= batchDeadlineTicks) {
                owned.Failure = "outer caller batch cutoff before controller resume";
                TerminateJobObject(owned.Job, 0xD3204004); return owned;
            }
            // Start both bounded readers while the controller is still
            // suspended so its first refusal/admission text cannot block on
            // an unserviced inherited pipe.
            owned.Stdout = new D32LifecycleCaptureV1(); owned.Stderr = new D32LifecycleCaptureV1();
            owned.StdoutThread = new Thread(() => CaptureLoop(owned.StdoutRead, owned.Stdout)); owned.StdoutThread.IsBackground = true; owned.StdoutThread.Start();
            owned.StderrThread = new Thread(() => CaptureLoop(owned.StderrRead, owned.Stderr)); owned.StderrThread.IsBackground = true; owned.StderrThread.Start();
            uint previous = ResumeThread(owned.Thread);
            if (previous != 1) {
                owned.Failure = previous == UInt32.MaxValue ? LastError("ResumeThread(outer controller) failed").Message : "outer controller was not exactly suspended once";
                TerminateJobObject(owned.Job, 0xD3204005); return owned;
            }
            owned.Resumed = true; owned.ReaderResumeTicks = System.Diagnostics.Stopwatch.GetTimestamp();
            return owned;
        } catch (Exception ex) {
            if (owned.Failure == null) owned.Failure = "outer controller launch path failed: " + ex.GetType().Name;
            if (owned.Process != IntPtr.Zero) {
                if (owned.Assigned && owned.Job != IntPtr.Zero) TerminateJobObject(owned.Job, 0xD3204006);
                else TerminateProcess(owned.Process, 0xD3204007);
            }
        } finally {
            bool parentPipeHandlesClosed = Close(ref prepared.Stdin) && Close(ref prepared.StdoutWrite) && Close(ref prepared.StderrWrite);
            if (prepared.AttributeList != IntPtr.Zero) { DeleteProcThreadAttributeList(prepared.AttributeList); Marshal.FreeHGlobal(prepared.AttributeList); prepared.AttributeList = IntPtr.Zero; }
            if (prepared.AttributeValue != IntPtr.Zero) { Marshal.FreeHGlobal(prepared.AttributeValue); prepared.AttributeValue = IntPtr.Zero; }
            if (prepared.EnvironmentBlock != IntPtr.Zero) { Marshal.FreeHGlobal(prepared.EnvironmentBlock); prepared.EnvironmentBlock = IntPtr.Zero; }
            owned.TemporaryHandlesClosed = parentPipeHandlesClosed && prepared.Stdin == IntPtr.Zero && prepared.StdoutWrite == IntPtr.Zero && prepared.StderrWrite == IntPtr.Zero;
            owned.PrelaunchHandlesClosed = owned.TemporaryHandlesClosed;
            if (owned.Process == IntPtr.Zero && owned.Job != IntPtr.Zero) {
                bool jobClosed = Close(ref owned.Job); owned.JobClosedByNative = jobClosed; owned.PrelaunchHandlesClosed = jobClosed && owned.PrelaunchHandlesClosed;
                bool readHandlesClosed = Close(ref owned.StdoutRead) && Close(ref owned.StderrRead);
                owned.PrelaunchHandlesClosed = readHandlesClosed && owned.PrelaunchHandlesClosed;
            }
        }
        return owned;
    }

    // Rebind only the already prepared fixed vector after the source-pinned
    // H projection has been persisted and independently reopened. The caller
    // passes the reopened raw command line unchanged to CreateProcessW.
    public static void BindOuterControllerCommandLine(D32LifecycleOuterLaunchPreparationV1 prepared,
        string[] persistedVector, string exactPersistedCommandLine, string expectedBindingSha256) {
        if (prepared == null || !prepared.Prepared || prepared.Owned == null || prepared.Owned.Invocation == null ||
            persistedVector == null || persistedVector.Length != 18 || String.IsNullOrEmpty(exactPersistedCommandLine) ||
            exactPersistedCommandLine.IndexOf('\0') >= 0 || expectedBindingSha256 == null || expectedBindingSha256.Length != 64 ||
            persistedVector[16] != "-ExpectedOuterPrelaunchBindingSha256" || persistedVector[17] != expectedBindingSha256)
            throw new InvalidDataException("persisted outer prelaunch binding/vector is not the fixed 18-argument form");
        for (int i = 0; i < expectedBindingSha256.Length; i++)
            if (!((expectedBindingSha256[i] >= '0' && expectedBindingSha256[i] <= '9') || (expectedBindingSha256[i] >= 'a' && expectedBindingSha256[i] <= 'f')))
                throw new InvalidDataException("persisted outer prelaunch binding is not lowercase hexadecimal");
        for (int i = 0; i < persistedVector.Length; i++)
            if (persistedVector[i] == null || persistedVector[i].IndexOf('\0') >= 0) throw new InvalidDataException("persisted outer argv contains null or NUL");
        StringBuilder rendered = new StringBuilder(); rendered.Append(QuoteArgument(prepared.Owned.Invocation.ImagePath));
        foreach (string argument in persistedVector) { rendered.Append(' '); rendered.Append(QuoteArgument(argument)); }
        if (rendered.Length >= 32767 || !StringComparer.Ordinal.Equals(rendered.ToString(), exactPersistedCommandLine))
            throw new InvalidDataException("persisted outer raw command line differs from the exact fixed renderer");
        prepared.Owned.Invocation.Arguments = (string[])persistedVector.Clone();
        prepared.Owned.Invocation.CommandLine = exactPersistedCommandLine;
    }

    public static bool WaitOuterController(D32LifecycleOwnedProcessV1 owned, int milliseconds) {
        if (owned == null || owned.Process == IntPtr.Zero || milliseconds < 0) return false;
        return WaitForSingleObject(owned.Process, (uint)milliseconds) == WAIT_OBJECT_0;
    }

    public static bool JoinOuterControllerCaptures(D32LifecycleOwnedProcessV1 owned, int milliseconds) {
        if (owned == null || milliseconds < 0) return false;
        bool stdout = owned.StdoutThread == null || owned.StdoutThread.Join(milliseconds);
        bool stderr = owned.StderrThread == null || owned.StderrThread.Join(Math.Max(0, milliseconds));
        return stdout && stderr;
    }

    public static bool CloseOuterController(D32LifecycleOwnedProcessV1 owned) {
        if (owned == null) return true;
        bool ok = true;
        // Closing the caller-owned kill-on-close Job is the only termination
        // mechanism. Never fall back to PID/name based termination.
        if (owned.Job != IntPtr.Zero) { bool closed = Close(ref owned.Job); owned.JobClosedByNative = closed; ok = closed && ok; }
        if (owned.Process != IntPtr.Zero) ok = Close(ref owned.Process) && ok;
        if (owned.Thread != IntPtr.Zero) ok = Close(ref owned.Thread) && ok;
        if (owned.StdoutRead != IntPtr.Zero) ok = Close(ref owned.StdoutRead) && ok;
        if (owned.StderrRead != IntPtr.Zero) ok = Close(ref owned.StderrRead) && ok;
        return ok;
    }

    public static int? OuterJobActiveProcesses(D32LifecycleOwnedProcessV1 owned) { return owned == null ? null : ActiveProcesses(owned.Job); }
    public static int? OuterJobTotalProcesses(D32LifecycleOwnedProcessV1 owned) { return owned == null ? null : TotalProcesses(owned.Job); }
    public static int? OuterControllerExitCode(D32LifecycleOwnedProcessV1 owned) { return owned == null ? null : ExitCode(owned.Process); }

    public static bool CloseOuterControllerPreparation(D32LifecycleOuterLaunchPreparationV1 prepared) {
        if (prepared == null) return true;
        bool ok = true;
        if (prepared.Stdin != IntPtr.Zero) ok = Close(ref prepared.Stdin) && ok;
        if (prepared.StdoutWrite != IntPtr.Zero) ok = Close(ref prepared.StdoutWrite) && ok;
        if (prepared.StderrWrite != IntPtr.Zero) ok = Close(ref prepared.StderrWrite) && ok;
        if (prepared.Owned != null) {
            if (prepared.Owned.StdoutRead != IntPtr.Zero) ok = Close(ref prepared.Owned.StdoutRead) && ok;
            if (prepared.Owned.StderrRead != IntPtr.Zero) ok = Close(ref prepared.Owned.StderrRead) && ok;
            if (prepared.Owned.Job != IntPtr.Zero) {
                bool jobClosed = Close(ref prepared.Owned.Job); prepared.Owned.JobClosedByNative = jobClosed; ok = jobClosed && ok;
            }
        }
        if (prepared.AttributeList != IntPtr.Zero) { DeleteProcThreadAttributeList(prepared.AttributeList); Marshal.FreeHGlobal(prepared.AttributeList); prepared.AttributeList = IntPtr.Zero; }
        if (prepared.AttributeValue != IntPtr.Zero) { Marshal.FreeHGlobal(prepared.AttributeValue); prepared.AttributeValue = IntPtr.Zero; }
        if (prepared.EnvironmentBlock != IntPtr.Zero) { Marshal.FreeHGlobal(prepared.EnvironmentBlock); prepared.EnvironmentBlock = IntPtr.Zero; }
        prepared.Prepared = false;
        return ok && prepared.Stdin == IntPtr.Zero && prepared.StdoutWrite == IntPtr.Zero && prepared.StderrWrite == IntPtr.Zero &&
            prepared.AttributeList == IntPtr.Zero && prepared.AttributeValue == IntPtr.Zero && prepared.EnvironmentBlock == IntPtr.Zero &&
            (prepared.Owned == null || (prepared.Owned.StdoutRead == IntPtr.Zero && prepared.Owned.StderrRead == IntPtr.Zero &&
                prepared.Owned.Job == IntPtr.Zero && (!prepared.Owned.JobCreated || prepared.Owned.JobClosedByNative)));
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

function Get-D32NonSourceL1CaptureT0 {
    param([Parameter(Mandatory = $true)][long]$Frequency)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        return [Int64](& $script:D32NonSourceL1EnvironmentAdapter.CaptureT0 -Frequency $Frequency)
    }
    return [Int64][Diagnostics.Stopwatch]::GetTimestamp()
}

function Get-D32NonSourceL1QpcFrequency {
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) { return [Int64](& $script:D32NonSourceL1EnvironmentAdapter.QpcFrequency) }
    return [Int64][Diagnostics.Stopwatch]::Frequency
}

function Get-D32NonSourceL1CurrentControllerPath {
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) { return [string](& $script:D32NonSourceL1EnvironmentAdapter.ControllerPath) }
    return [IO.Path]::GetFullPath($PSCommandPath)
}

function Get-D32NonSourceL1UniquePinnedPath {
    param([Parameter(Mandatory = $true)][object[]]$Pins, [Parameter(Mandatory = $true)][string]$Path)
    $found = $null; $count = 0
    foreach ($pin in $Pins) {
        if ([string]$pin.path -ceq $Path) { $found = $pin; $count++ }
    }
    if ($count -ne 1) { return $null }
    return $found
}

function Get-D32NonSourceL1CurrentRuntimePath {
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) { return [string](& $script:D32NonSourceL1EnvironmentAdapter.RuntimePath) }
    return [string][Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
}

function Get-D32NonSourceL1CurrentOwnerSid {
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) { return [string](& $script:D32NonSourceL1EnvironmentAdapter.OwnerSid) }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { return [string]$identity.User.Value } finally { $identity.Dispose() }
}

function Get-D32NonSourceL1CurrentProcessFacts {
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        if ($null -eq $script:D32NonSourceL1EnvironmentAdapter.ObserverProcess) {
            throw 'D32_NON_SOURCE_L1_REFUSED: trusted observer process provider is unavailable'
        }
        return & $script:D32NonSourceL1EnvironmentAdapter.ObserverProcess
    }
    $process = [Diagnostics.Process]::GetCurrentProcess()
    try {
        return [PSCustomObject][ordered]@{
            process_id = [Int64]$process.Id
            creation_filetime_ticks = [Int64]$process.StartTime.ToUniversalTime().ToFileTime()
            image_path = [IO.Path]::GetFullPath([string]$process.MainModule.FileName)
        }
    } finally { $process.Dispose() }
}

function Get-D32NonSourceL1CurrentTokenFacts {
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        if ($null -eq $script:D32NonSourceL1EnvironmentAdapter.CurrentToken) {
            throw 'D32_NON_SOURCE_L1_REFUSED: trusted observer token provider is unavailable'
        }
        return & $script:D32NonSourceL1EnvironmentAdapter.CurrentToken
    }
    return Get-D32PowerShellAuthorityCurrentToken
}

function Get-D32NonSourceL1CurrentStartupFacts {
    param([Parameter(Mandatory = $true)][string]$EntryScriptPath)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        if ($null -eq $script:D32NonSourceL1EnvironmentAdapter.ProcessStartup) {
            throw 'D32_NON_SOURCE_L1_REFUSED: trusted observer startup provider is unavailable'
        }
        return & $script:D32NonSourceL1EnvironmentAdapter.ProcessStartup -EntryScriptPath $EntryScriptPath
    }
    return Get-D32PowerShellAuthorityProcessStartup -EntryScriptPath $EntryScriptPath
}

function Get-D32NonSourceL1LoadedModuleNames {
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        if ($null -eq $script:D32NonSourceL1EnvironmentAdapter.LoadedModuleNames) {
            throw 'D32_NON_SOURCE_L1_REFUSED: module-state provider is unavailable'
        }
        return ,([string[]](& $script:D32NonSourceL1EnvironmentAdapter.LoadedModuleNames))
    }
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($module in $ExecutionContext.SessionState.Modules.Values) {
        if ($null -ne $module -and [string]$module.Name -cne 'Microsoft.PowerShell.Core') { $names.Add([string]$module.Name) }
    }
    return ,([string[]]$names.ToArray())
}

function Initialize-D32NonSourceL1ControllerRuntime {
    param([Parameter(Mandatory = $true)][object]$PreImportContext)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        if ($null -eq $script:D32NonSourceL1EnvironmentAdapter.InitializeRuntime) {
            throw 'D32_NON_SOURCE_L1_REFUSED: synthetic module provider is unavailable'
        }
        & $script:D32NonSourceL1EnvironmentAdapter.InitializeRuntime -PreImportContext $PreImportContext -NativeSource $nativeSource
        return
    }
    $utilityPath = [string]$PreImportContext.module_closure.manifest_reference.path
    $expectedUtilityManifestPath = [string]$script:D32NonSourceL1RuntimeAuthorityContent.module_policy.controller_utility_manifest.path
    if ([string]::IsNullOrWhiteSpace($utilityPath) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($utilityPath),$expectedUtilityManifestPath)) {
        throw 'D32_NON_SOURCE_L1_REFUSED: fixed Utility manifest path differs from the independently pinned module policy'
    }
    Import-Module -Name $utilityPath -ErrorAction Stop
    $script:D32NonSourceL1ModuleImportOrder.Add('Microsoft.PowerShell.Utility')
    Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop | Out-Null
}

function ConvertTo-D32NonSourceL1UtilityJson {
    param([Parameter(Mandatory = $true)][object]$InputObject, [Parameter(Mandatory = $true)][int]$Depth)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        if ($null -eq $script:D32NonSourceL1EnvironmentAdapter.ConvertToJson) {
            throw 'D32_NON_SOURCE_L1_REFUSED: synthetic managed JSON provider is unavailable'
        }
        return [string](& $script:D32NonSourceL1EnvironmentAdapter.ConvertToJson -InputObject $InputObject -Depth $Depth)
    }
    return [string](ConvertTo-Json -InputObject $InputObject -Depth $Depth -Compress -ErrorAction Stop)
}

function Test-D32NonSourceL1NoReparsePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) { return [bool](& $script:D32NonSourceL1EnvironmentAdapter.NoReparse -Path $Path) }
    return Test-D32LifecycleNoReparsePath -Path $Path
}

function Get-D32NonSourceL1InitialReferenceBytes {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][long]$MaximumBytes,
        [Parameter(Mandatory = $true)][long]$DeadlineTicks)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        return & $script:D32NonSourceL1EnvironmentAdapter.InitialReference -Path $Path -MaximumBytes $MaximumBytes -DeadlineTicks $DeadlineTicks
    }
    if ((Get-D32NonSourceL1Now) -ge $DeadlineTicks -or -not (Test-D32LifecycleNoReparsePath -Path $Path)) {
        throw 'D32_NON_SOURCE_L1_REFUSED: bounded initial bootstrap path is late, noncanonical, or reparse-backed'
    }
    $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes -or $stream.Length -gt [Int32]::MaxValue) {
            throw 'D32_NON_SOURCE_L1_REFUSED: bounded initial bootstrap byte count is outside the fixed ceiling'
        }
        $bytes = [byte[]]::new([int]$stream.Length); $offset = 0
        while ($offset -lt $bytes.Length) {
            if ((Get-D32NonSourceL1Now) -ge $DeadlineTicks) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: initial bootstrap read crossed the shared cutoff' }
            $read = $stream.Read($bytes,$offset,$bytes.Length-$offset)
            if ($read -le 0) { throw 'D32_NON_SOURCE_L1_REFUSED: initial bootstrap file changed during bounded read' }
            $offset += $read
        }
        if ($stream.Position -ne $stream.Length -or (Get-D32NonSourceL1Now) -ge $DeadlineTicks) {
            throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: late initial bootstrap bytes are discarded'
        }
        $reference = [PSCustomObject][ordered]@{path=[IO.Path]::GetFullPath($Path);bytes=[Int64]$bytes.Length
            sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
            volume_serial_hex=$null;file_id_hex=$null}
        return [PSCustomObject]@{Reference=$reference;Bytes=$bytes;Stream=$null}
    } finally { $stream.Dispose() }
}

function Get-D32NonSourceL1ModuleAuthorityDirectoryIdentity {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        return & $script:D32NonSourceL1EnvironmentAdapter.DirectoryIdentity -Path $Path
    }
    $full = [IO.Path]::GetFullPath($Path)
    Add-D32PowerShellAuthorityDirectoryChain -Directory $full -Fences $script:D32LifecycleFences
    $key = $full.TrimEnd([char[]]@('\','/'))
    if ($key.Length -eq 2 -and $key[1] -eq ':') { $key += [IO.Path]::DirectorySeparatorChar }
    $fence = $script:D32LifecycleFences[$key]
    if ($null -eq $fence -or -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$fence.Path,$full) -or
        $null -eq $fence.Handle -or $fence.Handle.IsClosed -or $fence.Handle.IsInvalid) {
        throw 'D32_NON_SOURCE_L1_REFUSED: opened directory identity fence is unavailable'
    }
    return [PSCustomObject][ordered]@{VolumeSerialHex=[string]$fence.VolumeSerialHex;FileIdHex=[string]$fence.FileIdHex}
}

function Open-D32NonSourceL1AuthorityRecord {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences,
        [Parameter(Mandatory = $true)][long]$MaximumBytes, [Parameter(Mandatory = $true)][long]$DeadlineTicks)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        return & $script:D32NonSourceL1EnvironmentAdapter.OpenAuthority -Path $Path -DirectoryFences $DirectoryFences -MaximumBytes $MaximumBytes -DeadlineTicks $DeadlineTicks
    }
    return Open-D32PowerShellAuthorityFile -Path $Path -DirectoryFences $DirectoryFences -MaximumBytes $MaximumBytes -DeadlineTicks $DeadlineTicks
}

function Get-D32NonSourceL1DirectoryIdentity {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) { return & $script:D32NonSourceL1EnvironmentAdapter.DirectoryIdentity -Path $Path }
    return Get-D32LifecycleDirectoryIdentity -Path $Path
}

function Get-D32NonSourceL1RootSecurity {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) { return & $script:D32NonSourceL1EnvironmentAdapter.RootSecurity -Path $Path }
    return [System.IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($Path))
}

function Test-D32NonSourceL1OutputPathExists {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) { return [bool](& $script:D32NonSourceL1EnvironmentAdapter.OutputPathExists -Path $Path) }
    return [IO.File]::Exists($Path) -or [IO.Directory]::Exists($Path)
}

function New-D32NonSourceL1JournalStream {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) { return & $script:D32NonSourceL1EnvironmentAdapter.CreateJournal -Path $Path }
    return [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
}

function New-D32NonSourceL1ResultStream {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) { return & $script:D32NonSourceL1EnvironmentAdapter.CreateResult -Path $Path }
    return [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
}

function New-D32NonSourceL1ArtifactStream {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][ValidateSet('OUTER_PRELAUNCH','RUNTIME_ADMISSION','CALLER_CAPTURE','CALLER_OUTCOME','CALLER_JOURNAL')][string]$Purpose)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        if ($null -eq $script:D32NonSourceL1EnvironmentAdapter.CreateArtifact) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: synthetic artifact writer is not installed' }
        return & $script:D32NonSourceL1EnvironmentAdapter.CreateArtifact -Path $Path -Purpose $Purpose
    }
    return [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
}

function Write-D32NonSourceL1CreateNewArtifact {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][ValidateSet('OUTER_PRELAUNCH','RUNTIME_ADMISSION','CALLER_CAPTURE','CALLER_OUTCOME','CALLER_JOURNAL')][string]$Purpose,
        [Parameter(Mandatory = $true)][long]$DeadlineTicks)
    if (($Bytes.Length -le 0 -and $Purpose -cne 'CALLER_CAPTURE') -or $Bytes.Length -gt 65536 -or (Get-D32NonSourceL1Now) -ge $DeadlineTicks) {
        throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: create-new caller/admission artifact is empty, over-bound, or late'
    }
    $stream = New-D32NonSourceL1ArtifactStream -Path $Path -Purpose $Purpose
    try { if ($Bytes.Length -gt 0) { $stream.Write($Bytes, 0, $Bytes.Length) }; $stream.Flush($true) } finally { $stream.Dispose() }
    if ((Get-D32NonSourceL1Now) -ge $DeadlineTicks) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: create-new caller/admission artifact flush returned late' }
}

function Get-D32NonSourceL1RuntimeContext {
    param([Parameter(Mandatory = $true)][object]$Authority, [Parameter(Mandatory = $true)][long]$DeadlineTicks,
        [switch]$PreImportOnly)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        if ($null -eq $script:D32NonSourceL1EnvironmentAdapter.RuntimeContext) {
            throw 'D32_NON_SOURCE_L1_REFUSED: synthetic runtime provider is not installed for the fixed L0 route'
        }
        return & $script:D32NonSourceL1EnvironmentAdapter.RuntimeContext -Authority $Authority -DeadlineTicks $DeadlineTicks -PreImportOnly:$PreImportOnly.IsPresent
    }
    if ($DeadlineTicks -le 0 -or (Get-D32NonSourceL1Now) -ge $DeadlineTicks -or
        $null -eq $script:D32NonSourceL1RuntimeAuthorityElement -or $null -eq $script:D32NonSourceL1RuntimeAuthorityContent) {
        throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: runtime context is missing its pinned content authority or shared deadline'
    }
    if ([string]$PSModuleAutoLoadingPreference -cne 'None' -or
        [string][Environment]::GetEnvironmentVariable('PSModuleAutoLoadingPreference',[EnvironmentVariableTarget]::Process) -cne 'None' -or
        [string][Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process) -cne ([string]$Authority.powershell_runtime.powershell_home.TrimEnd('\') + '\Modules')) {
        throw 'D32_NON_SOURCE_L1_REFUSED: process autoload/module-path startup differs from the fixed module-free policy'
    }
    $runtimeRoot = [IO.Path]::GetFullPath([string]$Authority.powershell_runtime.powershell_home)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$PSHOME),$runtimeRoot)) {
        throw 'D32_NON_SOURCE_L1_REFUSED: actual PSHOME differs from the independently pinned runtime'
    }
    $runtimeFiles = [System.Collections.Generic.List[object]]::new()
    $script:D32PowerShellAdmissionDirectoryFences = $script:D32LifecycleFences
    $runtimeSnapshot = Get-D32PowerShellAuthorityRuntimeDistributionSnapshot -PowerShellRoot $runtimeRoot `
        -DirectoryFences $script:D32LifecycleFences -OpenFiles $runtimeFiles
    if ((Get-D32NonSourceL1Now) -ge $DeadlineTicks -or
        -not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $script:D32NonSourceL1RuntimeAuthorityElement.GetProperty('distribution') -Value $runtimeSnapshot)) {
        throw 'D32_NON_SOURCE_L1_REFUSED: actual complete PSHOME inventory differs from the independent runtime-content candidate'
    }
    foreach ($file in $runtimeFiles) { if ($null -ne $file.Stream) { $script:D32NonSourceL1Opened.Add($file) } }
    $runtimeRecord = $script:D32NonSourceL1RuntimeAuthorityContent
    $osSecurity = Assert-D32PowerShellAuthorityResolverPolicyRecord -Element $script:D32NonSourceL1RuntimeAuthorityElement.GetProperty('resolver_policy') `
        -PowerShellRoot $runtimeRoot -DirectoryFences $script:D32LifecycleFences -OpenFiles $script:D32NonSourceL1Opened
    if ((Get-D32NonSourceL1Now) -ge $DeadlineTicks) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: protected Windows/Defender runtime namespace check reached the shared cutoff' }
    $resolver = Get-D32PowerShellAuthorityResolverSnapshot -OsSecurityComponents $osSecurity.Components `
        -OsSecurityInventorySha256 ([string]$osSecurity.InventorySha256) -ConfigureNativeSearch
    if ($resolver.Blockers.Count -gt 0 -or $resolver.TrustedPlatformPaths.Count -gt 1024 -or
        $resolver.NativeDirectories.Count -gt 1024 -or $resolver.DepsPaths.Count -gt 1024 -or
        $resolver.NativeModulePaths.Count -gt 4096 -or $resolver.LoadedManagedAssemblyPaths.Count -gt 4096 -or
        (Get-D32NonSourceL1Now) -ge $DeadlineTicks) {
        $detail = if ($resolver.Blockers.Count -gt 0) { [string]::Join('; ',[string[]]$resolver.Blockers) } else { 'fixed resolver inventory bound or deadline exceeded' }
        throw ('D32_NON_SOURCE_L1_REFUSED: actual resolver inputs or loaded origins are not admitted: ' + $detail)
    }
    $startup = $runtimeRecord.startup_inputs
    foreach ($group in @(
            [PSCustomObject]@{Name='trusted_platform_assemblies';Actual=[string[]]$resolver.TrustedPlatformPaths},
            [PSCustomObject]@{Name='native_search';Actual=[string[]]$resolver.NativeDirectories})) {
        $references = @($startup.($group.Name).paths)
        if ($references.Count -ne $group.Actual.Count) { throw ('D32_NON_SOURCE_L1_REFUSED: pinned ' + $group.Name + ' list count differs from actual resolver inputs') }
        $actualSorted = [string[]]$group.Actual.Clone(); [Array]::Sort($actualSorted,[StringComparer]::OrdinalIgnoreCase)
        for ($index=0; $index -lt $actualSorted.Count; $index++) {
            if ([string]$references[$index].path -cne $actualSorted[$index]) { throw ('D32_NON_SOURCE_L1_REFUSED: pinned ' + $group.Name + ' paths differ from actual runtime resolver inputs') }
        }
    }
    foreach ($input in @(@('deps','pwsh.deps.json'),@('runtime_config','pwsh.runtimeconfig.json'),@('protected_startup_config','powershell.config.json'))) {
        $state = $startup.([string]$input[0])
        $expectedPath = [IO.Path]::GetFullPath([IO.Path]::Combine($runtimeRoot,[string]$input[1]))
        if ([string]$state.state -ceq 'PRESENT') {
            $reference = $state.reference
            if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $reference) -or
                -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$reference.path,$expectedPath)) {
                throw ('D32_NON_SOURCE_L1_REFUSED: runtime startup file role is not the fixed PSHOME object: ' + [string]$input[0])
            }
            $openedInput = Open-D32PowerShellAuthorityFile -Path $expectedPath -DirectoryFences $script:D32LifecycleFences `
                -MaximumBytes 4194304 -DeadlineTicks $DeadlineTicks
            foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
                if ([string]$openedInput.Record.$name -cne [string]$reference.$name) { $openedInput.Stream.Dispose(); throw ('D32_NON_SOURCE_L1_REFUSED: actual runtime startup input differs from its content ref: ' + [string]$input[0]) }
            }
            $script:D32NonSourceL1Opened.Add($openedInput)
        } elseif ([string]$state.state -ceq 'PROTECTED_ABSENT') {
            if ([IO.File]::Exists($expectedPath) -or [IO.Directory]::Exists($expectedPath) -or
                -not (Test-D32NonSourceL1NoReparsePath -Path ([IO.Path]::GetDirectoryName($expectedPath)))) {
                throw ('D32_NON_SOURCE_L1_REFUSED: protected startup absence no longer holds: ' + [string]$input[0])
            }
        } else { throw ('D32_NON_SOURCE_L1_REFUSED: unknown runtime startup file state: ' + [string]$input[0]) }
    }
    if ([string]$startup.startup_hooks.state -cne 'ABSENT' -or $startup.startup_hooks.paths.Count -ne 0 -or
        [bool]$startup.profiling.enabled -or $startup.profiling.variables.Count -ne 0) {
        throw 'D32_NON_SOURCE_L1_REFUSED: startup hooks or runtime profiling are enabled'
    }
    $nativeEvidence = Get-D32PowerShellAuthorityNativeOriginEvidence -ResolverSnapshot $resolver `
        -RuntimeDistributionFiles @($runtimeSnapshot.files) -OsSecurityComponents @($osSecurity.Components) -PowerShellRoot $runtimeRoot
    Assert-D32PowerShellAuthorityRuntimeSnapshotCurrent -Snapshot $runtimeSnapshot -DirectoryFences $script:D32LifecycleFences -OpenFiles $runtimeFiles
    Assert-D32PowerShellAuthorityOsSecurityComponentsCurrent -Components $osSecurity.Components -DirectoryFences $script:D32LifecycleFences

    $utilityRole = $null
    foreach ($candidate in (Get-D32PowerShellAuthorityFixedModuleRoles -PowerShellRoot $runtimeRoot)) {
        if ([string]$candidate.Name -ceq 'Microsoft.PowerShell.Utility') { $utilityRole = $candidate; break }
    }
    if ($null -eq $utilityRole) { throw 'D32_NON_SOURCE_L1_REFUSED: fixed Utility module role is not defined by the pinned module authority' }
    $expectedModuleFiles = Get-D32PowerShellAuthorityExpectedModuleFiles -PowerShellRoot $runtimeRoot -Role $utilityRole
    $utilityFiles = [System.Collections.Generic.List[object]]::new()
    $utilityRecords = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $expectedModuleFiles.Paths) {
        $openedModule = if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$path,[string]$expectedModuleFiles.Manifest.Record.path)) {
            $expectedModuleFiles.Manifest
        } else { Open-D32PowerShellAuthorityFile -Path ([string]$path) -DirectoryFences $script:D32LifecycleFences -MaximumBytes 16777216 -DeadlineTicks $DeadlineTicks }
        $script:D32NonSourceL1Opened.Add($openedModule); $utilityFiles.Add($openedModule); $utilityRecords.Add($openedModule.Record)
    }
    $utilityDigest = Get-D32PowerShellAuthorityInventoryDigest -Role ([string]$utilityRole.Role) -Files $utilityRecords.ToArray()
    $utilityReference = $expectedModuleFiles.Manifest.Record
    $modulePolicy = $runtimeRecord.module_policy
    foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
        if ([string]$utilityReference.$name -cne [string]$modulePolicy.controller_utility_manifest.$name) {
            throw 'D32_NON_SOURCE_L1_REFUSED: current Utility manifest differs from the independent module-content candidate'
        }
    }
    if ($utilityDigest -cne [string]$modulePolicy.controller_utility_inventory_sha256) {
        throw 'D32_NON_SOURCE_L1_REFUSED: fixed Utility manifest closure inventory differs from the independent runtime candidate'
    }

    $loadedModules = [System.Collections.Generic.List[object]]::new()
    foreach ($module in $ExecutionContext.SessionState.Modules.Values) {
        if ($null -ne $module -and [string]$module.Name -cne 'Microsoft.PowerShell.Core') { $loadedModules.Add($module) }
    }
    if ($PreImportOnly) {
        return [PSCustomObject][ordered]@{
            runtime_snapshot=$runtimeSnapshot;os_security=$osSecurity;resolver=$resolver;native_origins=@($nativeEvidence)
            module_import_order=@();module_closure=[PSCustomObject][ordered]@{policy_id='NON_SOURCE_L1_UTILITY_ONLY_V1';inventory_sha256=$utilityDigest
                manifest_reference=[PSCustomObject][ordered]@{path=$utilityReference.path;bytes=$utilityReference.bytes;sha256=$utilityReference.sha256
                    volume_serial_hex=$utilityReference.volume_serial_hex;file_id_hex=$utilityReference.file_id_hex}}
            import_verification=[PSCustomObject][ordered]@{passed=$true;managed_origins=@();native_origins=@($nativeEvidence);utility_origin_count=0L;unexpected_origins=@()}
            namespace_witness=[PSCustomObject][ordered]@{runtime_inventory_sha256=[string]$runtimeSnapshot.inventory_sha256
                resolver_inventory_sha256=[string]$resolver.ResolverSha256;file_count=[Int64]$runtimeSnapshot.files.Count
                directory_count=[Int64]$runtimeSnapshot.directories.Count;live_fences_verified=$true;caller_owned=$true}
            utility_role=$utilityRole;utility_files=$utilityFiles.ToArray()
        }
    }
    if ($loadedModules.Count -ne 1 -or [string]$loadedModules[0].Name -cne 'Microsoft.PowerShell.Utility' -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$loadedModules[0].Path),[string]$utilityReference.path) -or
        $script:D32NonSourceL1ModuleImportOrder.Count -ne 1 -or $script:D32NonSourceL1ModuleImportOrder[0] -cne 'Microsoft.PowerShell.Utility') {
        throw 'D32_NON_SOURCE_L1_REFUSED: live controller imports do not equal the single fixed Utility manifest import'
    }
    $managedOrigins = [System.Collections.Generic.List[object]]::new()
    $managedSeen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $runtimeFileByPath = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in @($runtimeSnapshot.files)) { [void]$runtimeFileByPath.TryAdd([string]$file.path,$file) }
    foreach ($component in @($osSecurity.Components)) { foreach ($file in @($component.distribution.files)) { [void]$runtimeFileByPath.TryAdd([string]$file.path,$file) } }
    foreach ($path in @($resolver.LoadedManagedAssemblyPaths)) {
        if (-not $managedSeen.Add([string]$path)) { throw 'D32_NON_SOURCE_L1_REFUSED: duplicate managed origin path observed in the actual controller process' }
        if (-not $runtimeFileByPath.ContainsKey([string]$path)) { throw ('D32_NON_SOURCE_L1_REFUSED: loaded managed origin is outside the pinned runtime/OS authority: ' + [string]$path) }
        $managedOrigins.Add($runtimeFileByPath[[string]$path])
    }
    $script:D32NonSourceL1RuntimeContext = [PSCustomObject][ordered]@{
        runtime_snapshot=$runtimeSnapshot;os_security=$osSecurity;resolver=$resolver
        namespace_witness=[PSCustomObject][ordered]@{runtime_inventory_sha256=[string]$runtimeSnapshot.inventory_sha256
            resolver_inventory_sha256=[string]$resolver.ResolverSha256;file_count=[Int64]$runtimeSnapshot.files.Count
            directory_count=[Int64]$runtimeSnapshot.directories.Count;live_fences_verified=$true;caller_owned=$true}
        module_closure=[PSCustomObject][ordered]@{policy_id='NON_SOURCE_L1_UTILITY_ONLY_V1';inventory_sha256=$utilityDigest
            manifest_reference=[PSCustomObject][ordered]@{path=$utilityReference.path;bytes=$utilityReference.bytes;sha256=$utilityReference.sha256
                volume_serial_hex=$utilityReference.volume_serial_hex;file_id_hex=$utilityReference.file_id_hex}}
        resolver_admission=[PSCustomObject][ordered]@{state='VERIFIED';policy_id='D32_POWERSHELL_RESOLVER_DOMAIN_V2'
            resolver_sha256=[string]$resolver.ResolverSha256;os_security_inventory_sha256=[string]$resolver.OsSecurityInventorySha256
            native_policy=[string]$resolver.NativePolicy;module_search_path=[string]$resolver.ModuleSearchPath
            trusted_platform_paths=@($resolver.TrustedPlatformPaths);loaded_managed_assembly_paths=@($resolver.LoadedManagedAssemblyPaths)
            deps_paths=@($resolver.DepsPaths);native_directories=@($resolver.NativeDirectories);native_module_paths=@($resolver.NativeModulePaths)
            active_environment=@($resolver.ActiveEnvironment)}
        import_verification=[PSCustomObject][ordered]@{passed=$true;managed_origins=@($managedOrigins.ToArray());native_origins=@($nativeEvidence)
            utility_origin_count=1L;unexpected_origins=@()}
        module_closure_files=$utilityFiles.ToArray()
    }
    return $script:D32NonSourceL1RuntimeContext
}

function Get-D32NonSourceL1RuntimeObservation {
    param([Parameter(Mandatory = $true)][ValidateSet('CONTROLLER','NORMAL_READER','FORCED_READER')][string]$Role,
        [Parameter(Mandatory = $true)][object]$Authority, [AllowNull()][object]$ParentAdmission,
        [string[]]$Arguments = @(), [AllowNull()][object]$Native = $null)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        if ($null -eq $script:D32NonSourceL1EnvironmentAdapter.RuntimeObservation) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: synthetic runtime observer is not installed' }
        return & $script:D32NonSourceL1EnvironmentAdapter.RuntimeObservation -Role $Role -Authority $Authority -ParentAdmission $ParentAdmission `
            -Arguments $Arguments -Native $Native
    }
    if ($Role -cne 'CONTROLLER') {
        return Get-D32NonSourceL1ReaderRuntimeObservation -Role $Role -Authority $Authority -ParentAdmission $ParentAdmission `
            -Arguments $Arguments -Native $Native
    }
    if ($null -eq $script:D32NonSourceL1RuntimeContext -or $null -eq $script:D32NonSourceL1RuntimeAuthorityContent -or
        $null -eq $script:D32NonSourceL1RuntimeAuthorityElement) {
        throw 'D32_NON_SOURCE_L1_REFUSED: controller runtime admission preceded complete module-free runtime/input validation'
    }
    $process = [Diagnostics.Process]::GetCurrentProcess()
    try {
        $processId = [Int64]$process.Id
        $creation = [Int64]$process.StartTime.ToUniversalTime().ToFileTime()
        $imagePath = [IO.Path]::GetFullPath([string]$process.MainModule.FileName)
    } finally { $process.Dispose() }
    $runtime = $Authority.powershell_runtime
    $imageReference = [PSCustomObject][ordered]@{path=$runtime.path;bytes=[Int64]$runtime.bytes;sha256=$runtime.sha256
        volume_serial_hex=$runtime.volume_serial_hex;file_id_hex=$runtime.file_id_hex}
    if ($processId -ne [Int64]$PID -or $creation -le 0 -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals($imagePath,[string]$runtime.path)) {
        throw 'D32_NON_SOURCE_L1_REFUSED: current controller process identity/image differs from the independently pinned PowerShell host'
    }
    $token = Get-D32PowerShellAuthorityCurrentToken
    $environmentEntries = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @('SystemRoot','WINDIR','PATH','PSHOME','PSModulePath','PSModuleAutoLoadingPreference','POWERSHELL_TELEMETRY_OPTOUT',
            'DOTNET_CLI_TELEMETRY_OPTOUT','TEMP','TMP','USERPROFILE','APPDATA','LOCALAPPDATA','HOMEDRIVE','HOMEPATH')) {
        $value = [Environment]::GetEnvironmentVariable($name,[EnvironmentVariableTarget]::Process)
        if ($null -eq $value) { throw ('D32_NON_SOURCE_L1_REFUSED: fixed controller environment variable is absent: ' + $name) }
        $environmentEntries.Add($name + '=' + $value)
    }
    $actualEnvironment = $environmentEntries.ToArray(); [Array]::Sort($actualEnvironment,[StringComparer]::OrdinalIgnoreCase)
    $expectedEnvironment = [string[]](Get-D32BoundedDiagnosticSourceProofNonSourceL1EnvironmentEntries -Environment $Authority.invocation.child_environment)
    if ($actualEnvironment.Count -ne $expectedEnvironment.Count) { throw 'D32_NON_SOURCE_L1_REFUSED: controller environment entry count differs from the fixed cleared block' }
    for ($index=0; $index -lt $actualEnvironment.Count; $index++) {
        if ($actualEnvironment[$index] -cne $expectedEnvironment[$index]) { throw 'D32_NON_SOURCE_L1_REFUSED: controller environment differs from the fixed cleared block' }
    }
    $startup = Get-D32PowerShellAuthorityProcessStartup -EntryScriptPath ([string]$Authority.source_pins[0].path)
    if ($startup.FileOperand -cne [string]$Authority.source_pins[0].path -or
        [string]$PSModuleAutoLoadingPreference -cne 'None' -or
        [string][Environment]::GetEnvironmentVariable('PSModuleAutoLoadingPreference',[EnvironmentVariableTarget]::Process) -cne 'None' -or
        [string][Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process) -cne ([string]$runtime.powershell_home.TrimEnd('\') + '\Modules')) {
        throw 'D32_NON_SOURCE_L1_REFUSED: actual direct startup, module autoload, or module path differs from the fixed policy'
    }
    $actualArgs = [Environment]::GetCommandLineArgs()
    if ($actualArgs.Length -lt 2) { throw 'D32_NON_SOURCE_L1_REFUSED: actual controller argv is unavailable' }
    $actualArgumentVector = [string[]]$actualArgs[1..($actualArgs.Length - 1)]
    if ($Arguments.Count -gt 0) {
        if ($Arguments.Count -ne $actualArgumentVector.Count) { throw 'D32_NON_SOURCE_L1_REFUSED: supplied controller argv count differs from the actual process argv' }
        for ($index=0; $index -lt $Arguments.Count; $index++) { if ($Arguments[$index] -cne $actualArgumentVector[$index]) { throw 'D32_NON_SOURCE_L1_REFUSED: supplied controller argv differs from the actual process argv' } }
    }
    $expectedImports = @('Microsoft.PowerShell.Utility')
    $actualImports = [string[]]@($script:D32NonSourceL1ModuleImportOrder.ToArray())
    if ($actualImports.Count -ne 1 -or $actualImports[0] -cne $expectedImports[0]) {
        throw 'D32_NON_SOURCE_L1_REFUSED: controller Utility manifest import was not observed exactly once after module-free admission'
    }
    $expectedParent = [PSCustomObject][ordered]@{process_id=[Int64]$Authority.outer_caller.observer_process.process_id
        creation_filetime_ticks=[Int64]$Authority.outer_caller.observer_process.creation_filetime_ticks}
    return [PSCustomObject][ordered]@{
        process_id=$processId;creation_filetime_ticks=$creation;image_reference=$imageReference
        ordinary_token=[PSCustomObject][ordered]@{elevated=[bool]$token.is_elevated;high_integrity=([Int64]$token.integrity_rid -ge 0x3000)
            system_token=[bool]$token.is_system;thread_impersonation=[bool]$token.thread_impersonating}
        parent_process=$expectedParent;environment_entries=@($actualEnvironment);autoload=[string]$PSModuleAutoLoadingPreference
        module_path=[string][Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process)
        observed_ticks=(Get-D32NonSourceL1Now);namespace_witness=$script:D32NonSourceL1RuntimeContext.namespace_witness
        module_import_order=$actualImports;module_closure=$script:D32NonSourceL1RuntimeContext.module_closure
        resolver_admission=$script:D32NonSourceL1RuntimeContext.resolver_admission
        import_verification=$script:D32NonSourceL1RuntimeContext.import_verification;import_attempts=1L
    }
}

function Get-D32NonSourceL1ReaderRuntimeObservation {
    param([Parameter(Mandatory = $true)][ValidateSet('NORMAL_READER','FORCED_READER')][string]$Role,
        [Parameter(Mandatory = $true)][object]$Authority, [Parameter(Mandatory = $true)][object]$ParentAdmission,
        [Parameter(Mandatory = $true)][string[]]$Arguments, [Parameter(Mandatory = $true)][object]$Native)
    if ($null -eq $Native -or $Native.Process -eq [IntPtr]::Zero -or -not $Native.CreateProcessAttempted -or
        -not $Native.Assigned -or -not $Native.Resumed -or -not $Native.ProcessImageBindingVerified -or
        $null -eq $Native.Stdout -or -not $Native.Stdout.Complete -and $Native.Stdout.Prefix.Count -eq 0) {
        throw 'D32_NON_SOURCE_L1_UNRESOLVED: reader startup witness is absent from the retained, caller-owned process pipe'
    }
    $text = [D32BoundedSourceProofLifecycleNativeV1]::CaptureText($Native.Stdout)
    $lineEnd = $text.IndexOf("`n",[StringComparison]::Ordinal)
    if ($lineEnd -le 0 -or $lineEnd -gt 16000) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: reader startup witness has no bounded complete first frame' }
    $line = $text.Substring(0,$lineEnd).TrimEnd("`r")
    if (-not $line.StartsWith('D32NSL1-RUNTIME|',[StringComparison]::Ordinal)) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: reader first stdout frame is not the fixed runtime attestation' }
    $encoded = $line.Substring('D32NSL1-RUNTIME|'.Length)
    try {
        $payload = [Convert]::FromBase64String($encoded)
        if ($payload.Length -le 0 -or $payload.Length -gt 12000) { throw 'reader runtime frame byte bound' }
        $json = [Text.UTF8Encoding]::new($false,$true).GetString($payload)
        $document = [System.Text.Json.JsonDocument]::Parse($json)
    } catch { throw 'D32_NON_SOURCE_L1_UNRESOLVED: reader startup witness is malformed or over-bound' }
    try {
        if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
            (Test-D32PowerShellAuthorityJsonDuplicates -Element $document.RootElement)) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: reader startup witness contains duplicate fields or a non-object root' }
        $observation = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $document.RootElement
    } finally { $document.Dispose() }
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $observation @('process_id','creation_filetime_ticks','image_reference','ordinary_token','parent_process',
            'environment_entries','autoload','module_path','observed_ticks','namespace_witness','module_import_order','module_closure','resolver_admission',
            'import_verification','import_attempts')) -or
        [Int64]$observation.process_id -ne [Int64]$Native.ProcessId -or
        [Int64]$observation.creation_filetime_ticks -ne [Int64]$Native.CreationFileTime -or
        [string]$observation.image_reference.path -cne [string]$Authority.powershell_runtime.path -or
        [string]$observation.autoload -cne 'None' -or
        [string]$observation.module_path -cne ([string]$Authority.powershell_runtime.powershell_home.TrimEnd('\') + '\Modules') -or
        [Int64]$observation.import_attempts -ne 0 -or $observation.module_import_order.Count -ne 0 -or
        [Int64]$observation.parent_process.process_id -ne [Int64]$ParentAdmission.runner_process.process_id -or
        [Int64]$observation.parent_process.creation_filetime_ticks -ne [Int64]$ParentAdmission.runner_process.creation_filetime_ticks) {
        throw 'D32_NON_SOURCE_L1_UNRESOLVED: reader self-witness does not bind the retained native creation, direct parent, fixed runtime, or zero-import policy'
    }
    if ($observation.environment_entries -isnot [Array] -or $observation.environment_entries.Count -ne 15) {
        throw 'D32_NON_SOURCE_L1_UNRESOLVED: reader self-witness lacks the exact actual 15-entry child environment'
    }
    return $observation
}

function New-D32NonSourceL1RuntimeAdmissionArtifact {
    param([Parameter(Mandatory = $true)][object]$Authority, [Parameter(Mandatory = $true)][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][object]$OuterPrelaunchReference, [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$OutputPath, [AllowNull()][object]$ParentAdmissionReference,
        [AllowNull()][object]$ParentAdmission, [Parameter(Mandatory = $true)][object]$Observation,
        [Parameter(Mandatory = $true)][string[]]$Arguments, [Parameter(Mandatory = $true)][long]$T0Ticks,
        [Parameter(Mandatory = $true)][long]$DeadlineTicks)
    $entryIndex = if ($Role -ceq 'CONTROLLER') { 0 } else { 1 }
    $entryPin = $Authority.source_pins[$entryIndex]
    $runtime = $Authority.powershell_runtime
    $environmentEntries = Get-D32BoundedDiagnosticSourceProofNonSourceL1EnvironmentEntries -Environment $Authority.invocation.child_environment
    $switches = @('-NoLogo','-NoProfile','-NonInteractive')
    $expectedParent = if ($Role -ceq 'CONTROLLER') { $Authority.outer_caller.observer_process } else { $ParentAdmission.runner_process }
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Observation @('process_id','creation_filetime_ticks','image_reference','ordinary_token',
            'parent_process','environment_entries','autoload','module_path','observed_ticks','namespace_witness','module_import_order',
            'module_closure','resolver_admission','import_verification','import_attempts')) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Observation.process_id -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Observation.creation_filetime_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Observation.image_reference) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Observation.parent_process @('process_id','creation_filetime_ticks')) -or
        [Int64]$Observation.parent_process.process_id -ne [Int64]$expectedParent.process_id -or
        [Int64]$Observation.parent_process.creation_filetime_ticks -ne [Int64]$expectedParent.creation_filetime_ticks -or
        $Observation.environment_entries -isnot [Array] -or $Observation.environment_entries.Count -ne 15 -or
        [string]$Observation.autoload -cne 'None' -or [string]$Observation.module_path -cne ([string]$runtime.powershell_home.TrimEnd('\') + '\Modules') -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Observation.observed_ticks -Positive) -or
        [Int64]$Observation.observed_ticks -lt $T0Ticks -or [Int64]$Observation.observed_ticks -ge $DeadlineTicks -or
        $Observation.module_import_order -isnot [Array] -or $Observation.namespace_witness -isnot [System.Collections.IDictionary] -and $Observation.namespace_witness -isnot [PSCustomObject] -or
        $Observation.module_closure -isnot [System.Collections.IDictionary] -and $Observation.module_closure -isnot [PSCustomObject] -or
        $Observation.resolver_admission -isnot [System.Collections.IDictionary] -and $Observation.resolver_admission -isnot [PSCustomObject] -or
        $Observation.import_verification -isnot [System.Collections.IDictionary] -and $Observation.import_verification -isnot [PSCustomObject] -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Observation.import_attempts)) {
        throw 'D32_NON_SOURCE_L1_REFUSED: runtime observer returned incomplete, wrong-process, or late raw facts'
    }
    for ($index = 0; $index -lt 15; $index++) {
        if ([string]$Observation.environment_entries[$index] -cne [string]$environmentEntries[$index]) { throw 'D32_NON_SOURCE_L1_REFUSED: runtime observer environment differs from the fixed cleared block' }
    }
    $moduleImportOrder = [string[]]@($Observation.module_import_order)
    [string[]]$expectedImportOrder = if ($Role -ceq 'CONTROLLER') { @('Microsoft.PowerShell.Utility') } else { @() }
    if ($moduleImportOrder.Count -ne $expectedImportOrder.Count) { throw ('D32_NON_SOURCE_L1_REFUSED: FIXED_IMPORT_COUNT_MISMATCH role=' + $Role + ' observed=' + $moduleImportOrder.Count + ' expected=' + $expectedImportOrder.Count) }
    for ($index = 0; $index -lt $expectedImportOrder.Count; $index++) {
        if ($moduleImportOrder[$index] -cne $expectedImportOrder[$index]) { throw ('D32_NON_SOURCE_L1_REFUSED: FIXED_IMPORT_ORDER_MISMATCH role=' + $Role + ' observed=' + [string]$moduleImportOrder[$index] + ' expected=' + [string]$expectedImportOrder[$index]) }
    }
    $startupArguments = [string[]]$Arguments
    $commandLine = Get-D32BoundedDiagnosticSourceProofNonSourceL1ExpectedCommandLine -Image ([string]$runtime.path) -Arguments $startupArguments
    $admission = [PSCustomObject][ordered]@{
        schema_version=1; record_type='D32_NON_SOURCE_L1_RUNTIME_ADMISSION_V1'; purpose='NON_SOURCE_L1_PROCESS_RUNTIME_ADMISSION'; gate_authority='NONE'
        candidate_sha=$Authority.candidate_sha; batch_id=$Authority.batch_id; run_id=$Authority.run_id
        authority_reference=$AuthorityReference; runtime_authority_reference=$Authority.runtime_authority
        outer_prelaunch_reference=$OuterPrelaunchReference; parent_admission_reference=$ParentAdmissionReference
        powershell_host=[PSCustomObject][ordered]@{path=$runtime.path;sha256=$runtime.sha256;bytes=$runtime.bytes;volume_serial_hex=$runtime.volume_serial_hex;file_id_hex=$runtime.file_id_hex;pshome=$runtime.powershell_home}
        runner_process=[PSCustomObject][ordered]@{role=$Role;process_id=[Int64]$Observation.process_id;creation_filetime_ticks=[Int64]$Observation.creation_filetime_ticks
            image_reference=$Observation.image_reference;ordinary_token=$Observation.ordinary_token;parent_process=$Observation.parent_process}
        startup=[PSCustomObject][ordered]@{file_operand=$entryPin.path;switches=$switches;arguments=$startupArguments;command_line=$commandLine;startup_policy='DIRECT_NO_PROFILE_FILE_V1'}
        entry_script=[PSCustomObject][ordered]@{path=$entryPin.path;bytes=$entryPin.bytes;sha256=$entryPin.sha256;volume_serial_hex=$entryPin.volume_serial_hex;file_id_hex=$entryPin.file_id_hex}
        environment=[PSCustomObject][ordered]@{entries=@($Observation.environment_entries);block_sha256=(Get-D32BoundedDiagnosticSourceProofNonSourceL1EnvironmentBlockSha256 -Entries ([string[]]$Observation.environment_entries))
            inherited_environment_cleared=$true;autoload=[string]$Observation.autoload;module_path=[string]$Observation.module_path}
        clock=[PSCustomObject][ordered]@{counter_origin='QueryPerformanceCounter';frequency=(Get-D32NonSourceL1QpcFrequency);batch_t0_ticks=$T0Ticks
            observed_ticks=[Int64]$Observation.observed_ticks;deadline_ticks=$DeadlineTicks}
        namespace_witness=$Observation.namespace_witness; module_import_order=$moduleImportOrder; module_closure=$Observation.module_closure
        resolver_admission=$Observation.resolver_admission; import_verification=$Observation.import_verification; import_attempts=[Int64]$Observation.import_attempts
        status='ADMITTED'; primary_error=$null; secondary_errors=@()
    }
    if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeAdmissionShape -Admission $admission -Authority $Authority -Role $Role `
            -ParentAdmissionReference $ParentAdmissionReference -ParentAdmission $ParentAdmission -AuthorityReference $AuthorityReference `
            -OuterPrelaunchReference $OuterPrelaunchReference)) {
        throw 'D32_NON_SOURCE_L1_REFUSED: constructed runtime admission failed the frozen strict schema'
    }
    $json = ConvertTo-D32NonSourceL1UtilityJson -InputObject $admission -Depth 40
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    if ($bytes.Length -gt 65536) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: runtime admission exceeds 64 KiB' }
    Write-D32NonSourceL1CreateNewArtifact -Path $OutputPath -Bytes $bytes -Purpose RUNTIME_ADMISSION -DeadlineTicks $DeadlineTicks
    $opened = Open-D32NonSourceL1PersistedOutput -Path $OutputPath -DirectoryFences $script:D32LifecycleFences -MaximumBytes 65536 -DeadlineTicks $DeadlineTicks
    try {
        $record = $opened.Record
        if ([Int64]$record.bytes -ne $bytes.Length -or [string]$record.sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() -or
            $opened.Bytes.Length -ne $bytes.Length) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: runtime admission re-open did not match the flushed create-new bytes' }
        for ($byteIndex = 0; $byteIndex -lt $bytes.Length; $byteIndex++) { if ($opened.Bytes[$byteIndex] -ne $bytes[$byteIndex]) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: runtime admission re-open bytes changed' } }
        $document = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$opened.Bytes))
        try {
            if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $document.RootElement)) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: runtime admission readback has duplicate/non-object JSON' }
            $readback = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $document.RootElement
        } finally { $document.Dispose() }
        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeAdmissionShape -Admission $readback -Authority $Authority -Role $Role `
                -ParentAdmissionReference $ParentAdmissionReference -ParentAdmission $ParentAdmission -AuthorityReference $AuthorityReference `
                -OuterPrelaunchReference $OuterPrelaunchReference)) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: runtime admission strict JSON readback failed' }
        return (New-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeAdmissionSlot $Role 'ADMITTED' $record $readback)
    } finally { if ($null -ne $opened.Stream) { $opened.Stream.Dispose() } }
}

function New-D32NonSourceL1OuterPrelaunchRecord {
    param([Parameter(Mandatory = $true)][object]$Authority, [Parameter(Mandatory = $true)][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][object]$Observation, [Parameter(Mandatory = $true)][long]$T0Ticks,
        [Parameter(Mandatory = $true)][long]$CounterFrequency)
    $controllerPin = $Authority.source_pins[0]
    $runtime = $Authority.powershell_runtime
    $environmentEntries = [string[]](Get-D32BoundedDiagnosticSourceProofNonSourceL1EnvironmentEntries -Environment $Authority.invocation.child_environment)
    $vector = [string[]](Get-D32NonSourceL1OuterControllerVector -Authority $Authority -AuthorityReference $AuthorityReference -T0Ticks $T0Ticks)
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Observation @('caller_process','environment_entries','clock','standard_handles',
            'ambient_handles_proven_none','creation_flags','startup_info','outer_job','namespace_witness')) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Observation.caller_process @('process_id','creation_filetime_ticks','image_reference','ordinary_token')) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Observation.caller_process.process_id -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Observation.caller_process.creation_filetime_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Observation.caller_process.image_reference) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Observation.clock @('counter_origin','frequency','batch_t0_ticks')) -or
        [string]$Observation.clock.counter_origin -cne 'QueryPerformanceCounter' -or
        [Int64]$Observation.clock.frequency -ne $CounterFrequency -or [Int64]$Observation.clock.batch_t0_ticks -ne $T0Ticks -or
        $Observation.environment_entries -isnot [Array] -or $Observation.environment_entries.Count -ne 15 -or
        [Int64]$Observation.creation_flags -ne 0x08080404L -or
        $Observation.ambient_handles_proven_none -isnot [bool] -or -not $Observation.ambient_handles_proven_none -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Observation.standard_handles @('stdin','stdout_write','stderr_write','stdout_read','stderr_read')) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Observation.standard_handles.stdin @('role','access','inheritable')) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Observation.standard_handles.stdout_write @('role','access','inheritable')) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Observation.standard_handles.stderr_write @('role','access','inheritable')) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Observation.standard_handles.stdout_read @('role','access','inheritable')) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Observation.standard_handles.stderr_read @('role','access','inheritable')) -or
        [string]$Observation.standard_handles.stdin.role -cne 'stdin:NUL' -or [string]$Observation.standard_handles.stdin.access -cne 'READ_ONLY' -or
        $Observation.standard_handles.stdin.inheritable -isnot [bool] -or -not $Observation.standard_handles.stdin.inheritable -or
        [string]$Observation.standard_handles.stdout_write.role -cne 'stdout:PIPE_WRITE' -or [string]$Observation.standard_handles.stdout_write.access -cne 'PIPE_WRITE' -or $Observation.standard_handles.stdout_write.inheritable -isnot [bool] -or -not $Observation.standard_handles.stdout_write.inheritable -or
        [string]$Observation.standard_handles.stderr_write.role -cne 'stderr:PIPE_WRITE' -or [string]$Observation.standard_handles.stderr_write.access -cne 'PIPE_WRITE' -or $Observation.standard_handles.stderr_write.inheritable -isnot [bool] -or -not $Observation.standard_handles.stderr_write.inheritable -or
        [string]$Observation.standard_handles.stdout_read.role -cne 'stdout:PIPE_READ' -or [string]$Observation.standard_handles.stdout_read.access -cne 'PIPE_READ' -or $Observation.standard_handles.stdout_read.inheritable -isnot [bool] -or $Observation.standard_handles.stdout_read.inheritable -or
        [string]$Observation.standard_handles.stderr_read.role -cne 'stderr:PIPE_READ' -or [string]$Observation.standard_handles.stderr_read.access -cne 'PIPE_READ' -or $Observation.standard_handles.stderr_read.inheritable -isnot [bool] -or $Observation.standard_handles.stderr_read.inheritable -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Observation.startup_info @('extended_startupinfo','handle_list_applied','handle_roles')) -or
        $Observation.startup_info.extended_startupinfo -isnot [bool] -or -not $Observation.startup_info.extended_startupinfo -or
        $Observation.startup_info.handle_list_applied -isnot [bool] -or -not $Observation.startup_info.handle_list_applied -or
        $Observation.startup_info.handle_roles -isnot [Array] -or $Observation.startup_info.handle_roles.Count -ne 3 -or
        [string]$Observation.startup_info.handle_roles[0] -cne 'stdin:NUL' -or [string]$Observation.startup_info.handle_roles[1] -cne 'stdout:PIPE_WRITE' -or
        [string]$Observation.startup_info.handle_roles[2] -cne 'stderr:PIPE_WRITE' -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Observation.outer_job @('policy','active_process_limit','kill_on_close','non_breakaway')) -or
        [string]$Observation.outer_job.policy -cne 'CALLER_OWNED_NESTED_JOB_V1' -or [Int64]$Observation.outer_job.active_process_limit -ne 2 -or
        $Observation.outer_job.kill_on_close -isnot [bool] -or -not $Observation.outer_job.kill_on_close -or
        $Observation.outer_job.non_breakaway -isnot [bool] -or -not $Observation.outer_job.non_breakaway -or
        $Observation.namespace_witness -isnot [System.Collections.IDictionary] -and $Observation.namespace_witness -isnot [PSCustomObject]) {
        throw 'D32_NON_SOURCE_L1_REFUSED: outer-caller raw prelaunch observation is incomplete or violates fixed ownership/handle policy'
    }
    for ($index = 0; $index -lt 15; $index++) {
        if ([string]$Observation.environment_entries[$index] -cne [string]$environmentEntries[$index]) { throw 'D32_NON_SOURCE_L1_REFUSED: outer controller environment differs from the fixed cleared block' }
    }
    $record = [PSCustomObject][ordered]@{
        schema_version=1; record_type='D32_NON_SOURCE_L1_OUTER_PRELAUNCH_V1'; purpose='NON_SOURCE_L1_OUTER_PRELAUNCH_ONLY'; gate_authority='NONE'
        candidate_sha=$Authority.candidate_sha; batch_id=$Authority.batch_id; run_id=$Authority.run_id
        authority_reference=$AuthorityReference; runtime_authority_reference=$Authority.runtime_authority; source_pins=@($Authority.source_pins)
        caller_process=$Observation.caller_process
        clock=[PSCustomObject][ordered]@{counter_origin='QueryPerformanceCounter';frequency=$CounterFrequency;batch_t0_ticks=$T0Ticks}
        root_binding=[PSCustomObject][ordered]@{root_path=$Authority.output.root_path;root_volume_serial_hex=$Authority.output.root_volume_serial_hex
            root_file_id_hex=$Authority.output.root_file_id_hex;parent_path=$Authority.output.parent_path;parent_volume_serial_hex=$Authority.output.parent_volume_serial_hex
            parent_file_id_hex=$Authority.output.parent_file_id_hex;live_fences_verified=[bool]$Observation.namespace_witness.live_fences_verified}
        controller=[PSCustomObject][ordered]@{executable_reference=[PSCustomObject][ordered]@{path=$runtime.path;bytes=$runtime.bytes;sha256=$runtime.sha256
                volume_serial_hex=$runtime.volume_serial_hex;file_id_hex=$runtime.file_id_hex}
            entry_reference=$controllerPin
            arguments=[PSCustomObject][ordered]@{vector=$vector;command_line='';command_line_utf16_sha256=('0' * 64)}
            working_directory=[string]$Authority.output.root_path;environment_entries=@($Observation.environment_entries)
            environment_block_sha256=(Get-D32BoundedDiagnosticSourceProofNonSourceL1EnvironmentBlockSha256 -Entries ([string[]]$Observation.environment_entries))
            creation_flags=[Int64]$Observation.creation_flags;startup_info=$Observation.startup_info;outer_job=$Observation.outer_job}
        standard_handles=$Observation.standard_handles; ambient_handles_proven_none=[bool]$Observation.ambient_handles_proven_none
        namespace_witness=$Observation.namespace_witness
    }
    if ($record.controller.arguments.vector.Count -ne 18 -or
        [string]$record.controller.arguments.vector[16] -cne '-ExpectedOuterPrelaunchBindingSha256' -or
        [string]$record.controller.arguments.vector[17] -cne ('0' * 64)) {
        throw 'D32_NON_SOURCE_L1_REFUSED: outer caller generated a noncanonical controller argument vector'
    }
    return $record
}

function Get-D32NonSourceL1OuterControllerVector {
    param([Parameter(Mandatory = $true)][object]$Authority, [Parameter(Mandatory = $true)][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][long]$T0Ticks)
    if ($T0Ticks -le 0 -or -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $AuthorityReference) -or
        [string]$AuthorityReference.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Test-D32PowerShellAuthorityPathWithin -Child ([string]$AuthorityReference.path) -Parent ([string]$Authority.source_repo)) -or
        (Test-D32PowerShellAuthorityPathWithin -Child ([string]$AuthorityReference.path) -Parent 'E:\d32\inv7\r\c') -or
        (Test-D32PowerShellAuthorityPathWithin -Child ([string]$AuthorityReference.path) -Parent ([string]$Authority.output.root_path))) {
        throw 'D32_NON_SOURCE_L1_REFUSED: outer caller argv authority or shared T0 binding is invalid'
    }
    return ,([string[]]@('-NoLogo','-NoProfile','-NonInteractive','-File',[string]$Authority.source_pins[0].path,
        '-Repository',[string]$Authority.source_repo,'-CandidateSha',[string]$Authority.candidate_sha,'-NonSourceL1',
        '-L1AuthorityPath',[string]$AuthorityReference.path,'-ExpectedL1AuthoritySha256',[string]$AuthorityReference.sha256,
        '-L1T0Ticks',([Int64]$T0Ticks).ToString([Globalization.CultureInfo]::InvariantCulture),
        '-ExpectedOuterPrelaunchBindingSha256',('0' * 64)))
}

function Test-D32NonSourceL1SyntheticCallerReconciliation {
    param([Parameter(Mandatory = $true)][object]$Authority, [Parameter(Mandatory = $true)][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][object]$PrelaunchReference, [Parameter(Mandatory = $true)][object]$PrelaunchRecord,
        [Parameter(Mandatory = $true)][long]$ControllerReturnCode)
    throw 'D32_NON_SOURCE_L1_REFUSED: legacy synthetic-only caller reconciliation is disabled; use the fixed production caller reconciler'
    $outcomeOpened = $null; $journalOpened = $null; $stdoutOpened = $null; $stderrOpened = $null
    $innerResultOpened = $null; $innerJournalOpened = $null
    try {
        $outcomeOpened = Open-D32NonSourceL1PersistedOutput -Path ([string]$Authority.output.caller_outcome_path) `
            -DirectoryFences ([System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)) -MaximumBytes 65536 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $journalOpened = Open-D32NonSourceL1PersistedOutput -Path ([string]$Authority.output.caller_journal_path) `
            -DirectoryFences ([System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)) -MaximumBytes 65536 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $stdoutOpened = Open-D32NonSourceL1PersistedOutput -Path ([string]$Authority.output.stdout_path) `
            -DirectoryFences ([System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)) -MaximumBytes 16000 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $stderrOpened = Open-D32NonSourceL1PersistedOutput -Path ([string]$Authority.output.stderr_path) `
            -DirectoryFences ([System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)) -MaximumBytes 16000 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        foreach ($opened in @($outcomeOpened,$journalOpened,$stdoutOpened,$stderrOpened)) {
            if ([Int64]$opened.Record.bytes -ne $opened.Bytes.Length -or
                [string]$opened.Record.sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$opened.Bytes)).ToLowerInvariant()) { return $false }
        }
        $outcomeDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$outcomeOpened.Bytes))
        try {
            if ($outcomeDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $outcomeDocument.RootElement)) { return $false }
            $outcome = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $outcomeDocument.RootElement
        } finally { $outcomeDocument.Dispose() }
        $outcomeCanonical = ConvertTo-D32BoundedDiagnosticSourceProofCanonicalJsonBytes -Value $outcome
        if ($outcomeCanonical.Length -ne $outcomeOpened.Bytes.Length) { return $false }
        for ($index = 0; $index -lt $outcomeCanonical.Length; $index++) { if ($outcomeCanonical[$index] -ne $outcomeOpened.Bytes[$index]) { return $false } }

        $journalBytes = [byte[]]$journalOpened.Bytes
        if ($journalBytes.Length -lt 3 -or $journalBytes[$journalBytes.Length - 1] -ne 10 -or
            [Array]::IndexOf($journalBytes, [byte]10) -ne ($journalBytes.Length - 1) -or
            $journalBytes[$journalBytes.Length - 2] -eq 13) { return $false }
        $journalJsonBytes = [byte[]]::new($journalBytes.Length - 1)
        [Array]::Copy($journalBytes, $journalJsonBytes, $journalJsonBytes.Length)
        $journalDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString($journalJsonBytes))
        try {
            if ($journalDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $journalDocument.RootElement)) { return $false }
            $journal = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $journalDocument.RootElement
        } finally { $journalDocument.Dispose() }
        $journalCanonical = ConvertTo-D32BoundedDiagnosticSourceProofCanonicalJsonBytes -Value $journal
        if ($journalCanonical.Length -ne $journalJsonBytes.Length) { return $false }
        for ($index = 0; $index -lt $journalCanonical.Length; $index++) { if ($journalCanonical[$index] -ne $journalJsonBytes[$index]) { return $false } }

        $innerResultOpened = Open-D32NonSourceL1PersistedOutput -Path ([string]$Authority.output.result_path) `
            -DirectoryFences ([System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)) -MaximumBytes 65536 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $innerJournalOpened = Open-D32NonSourceL1PersistedOutput -Path ([string]$Authority.output.journal_path) `
            -DirectoryFences ([System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)) -MaximumBytes 65536 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $innerResultDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$innerResultOpened.Bytes))
        try {
            if ($innerResultDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                (Test-D32PowerShellAuthorityJsonDuplicates -Element $innerResultDocument.RootElement)) { return $false }
            $innerResult = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $innerResultDocument.RootElement
        } finally { $innerResultDocument.Dispose() }
        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $innerResult) -or
            [string]$innerResult.status -cne 'COMPLETE_NON_SOURCE_L1') { return $false }
        $innerJournalText = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$innerJournalOpened.Bytes)
        $innerJournalLines = @($innerJournalText.Split("`n", [StringSplitOptions]::RemoveEmptyEntries))
        if ($innerJournalLines.Count -lt 1 -or $innerJournalLines.Count -gt 64) { return $false }
        $innerLastFact = ConvertFrom-D32BoundedCompilerDiagnosticTestJson -Json $innerJournalLines[$innerJournalLines.Count - 1]
        if ([string]$innerLastFact.event -cne 'L1_RESULT_PERSISTED' -or
            [string]$innerLastFact.result_path -cne [string]$Authority.output.result_path -or
            [Int64]$innerLastFact.result_bytes -ne [Int64]$innerResultOpened.Record.bytes -or
            [string]$innerLastFact.result_sha256 -cne [string]$innerResultOpened.Record.sha256 -or
            [string]$innerLastFact.result_volume_serial_hex -cne [string]$innerResultOpened.Record.volume_serial_hex -or
            [string]$innerLastFact.result_file_id_hex -cne [string]$innerResultOpened.Record.file_id_hex) { return $false }

        $outcomeFields = @('schema_version','record_type','purpose','gate_authority','candidate_sha','batch_id','run_id','status','execution_mode',
            'outer_prelaunch_reference','controller','captures','runtime_admission_references','inner_result_reference','inner_journal_reference','clock','primary_error','secondary_errors')
        $journalFields = @('schema_version','record_type','purpose','gate_authority','candidate_sha','batch_id','run_id','event','outcome_reference','submission','controller_return_code','observed_ticks')
        $schemaValid = (Test-D32BoundedCompilerDiagnosticExactProperties $outcome $outcomeFields) -and
            (Test-D32BoundedCompilerDiagnosticExactProperties $journal $journalFields) -and
            [Int64]$outcome.schema_version -eq 1 -and [string]$outcome.record_type -ceq 'D32_NON_SOURCE_L1_CALLER_OUTCOME_V1' -and
            [string]$outcome.purpose -ceq 'NON_SOURCE_L1_CALLER_OUTCOME_ONLY' -and [string]$outcome.gate_authority -ceq 'NONE' -and
            [string]$outcome.status -ceq 'SYNTHETIC_L0_ONLY' -and [string]$outcome.execution_mode -ceq 'IN_PROCESS_SYNTHETIC_ADAPTER' -and
            [string]$outcome.candidate_sha -ceq [string]$Authority.candidate_sha -and [string]$outcome.batch_id -ceq [string]$Authority.batch_id -and
            [string]$outcome.run_id -ceq [string]$Authority.run_id -and $null -eq $outcome.primary_error -and
            $outcome.secondary_errors -is [Array] -and $outcome.secondary_errors.Count -eq 0
        $controllerValid = (Test-D32BoundedCompilerDiagnosticExactProperties $outcome.controller @('native_create_attempted','process_id','creation_filetime_ticks','assigned','resumed','exit_code','job_active_process_count','job_total_process_count','cleanup_state')) -and
            $outcome.controller.native_create_attempted -is [bool] -and -not $outcome.controller.native_create_attempted -and
            $null -eq $outcome.controller.process_id -and $null -eq $outcome.controller.creation_filetime_ticks -and
            $outcome.controller.assigned -is [bool] -and -not $outcome.controller.assigned -and
            $outcome.controller.resumed -is [bool] -and -not $outcome.controller.resumed -and
            [Int64]$outcome.controller.exit_code -eq $ControllerReturnCode -and
            $null -eq $outcome.controller.job_active_process_count -and $null -eq $outcome.controller.job_total_process_count -and
            [string]$outcome.controller.cleanup_state -ceq 'NOT_RUN_SYNTHETIC_ADAPTER'
        $captureValid = (Test-D32BoundedCompilerDiagnosticExactProperties $outcome.captures @('stdout_reference','stderr_reference','stdout_bytes','stderr_bytes','stdout_sha256','stderr_sha256','stdout_truncated','stderr_truncated','transport','complete')) -and
            (Test-D32BoundedCompilerDiagnosticCapturedStreamReferenceShape -Reference $outcome.captures.stdout_reference -ExpectedPath ([string]$Authority.output.stdout_path)) -and
            (Test-D32BoundedCompilerDiagnosticCapturedStreamReferenceShape -Reference $outcome.captures.stderr_reference -ExpectedPath ([string]$Authority.output.stderr_path)) -and
            [Int64]$outcome.captures.stdout_bytes -eq $stdoutOpened.Bytes.Length -and [Int64]$outcome.captures.stderr_bytes -eq $stderrOpened.Bytes.Length -and
            [string]$outcome.captures.stdout_reference.sha256 -ceq [string]$stdoutOpened.Record.sha256 -and
            [string]$outcome.captures.stderr_reference.sha256 -ceq [string]$stderrOpened.Record.sha256 -and
            [string]$outcome.captures.stdout_reference.volume_serial_hex -ceq [string]$stdoutOpened.Record.volume_serial_hex -and
            [string]$outcome.captures.stderr_reference.volume_serial_hex -ceq [string]$stderrOpened.Record.volume_serial_hex -and
            [string]$outcome.captures.stdout_reference.file_id_hex -ceq [string]$stdoutOpened.Record.file_id_hex -and
            [string]$outcome.captures.stderr_reference.file_id_hex -ceq [string]$stderrOpened.Record.file_id_hex -and
            [string]$outcome.captures.stdout_sha256 -ceq [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$stdoutOpened.Bytes)).ToLowerInvariant() -and
            [string]$outcome.captures.stderr_sha256 -ceq [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$stderrOpened.Bytes)).ToLowerInvariant() -and
            $outcome.captures.stdout_truncated -is [bool] -and -not $outcome.captures.stdout_truncated -and
            $outcome.captures.stderr_truncated -is [bool] -and -not $outcome.captures.stderr_truncated -and
            [string]$outcome.captures.transport -ceq 'IN_PROCESS_SYNTHETIC_TEXTWRITER' -and
            $outcome.captures.complete -is [bool] -and $outcome.captures.complete
        $clockValid = (Test-D32BoundedCompilerDiagnosticExactProperties $PrelaunchRecord.clock @('counter_origin','frequency','batch_t0_ticks')) -and
            (Test-D32BoundedCompilerDiagnosticExactProperties $outcome.clock @('counter_origin','frequency','batch_t0_ticks','completed_ticks')) -and
            [string]$outcome.clock.counter_origin -ceq 'QueryPerformanceCounter' -and
            (Test-D32BoundedCompilerDiagnosticInteger $outcome.clock.frequency -Positive) -and
            (Test-D32BoundedCompilerDiagnosticInteger $outcome.clock.batch_t0_ticks -Positive) -and
            (Test-D32BoundedCompilerDiagnosticInteger $outcome.clock.completed_ticks -Positive) -and
            [Int64]$outcome.clock.frequency -eq [Int64]$PrelaunchRecord.clock.frequency -and
            [Int64]$outcome.clock.batch_t0_ticks -eq [Int64]$PrelaunchRecord.clock.batch_t0_ticks -and
            [Int64]$outcome.clock.completed_ticks -ge [Int64]$outcome.clock.batch_t0_ticks -and
            [Int64]$outcome.clock.completed_ticks -lt (Get-D32NonSourceL1DeadlineTicks -T0Ticks ([Int64]$PrelaunchRecord.clock.batch_t0_ticks) `
                -Frequency ([Int64]$PrelaunchRecord.clock.frequency) -Milliseconds 60000L)
        $referenceValid = (Test-D32BoundedCompilerDiagnosticFileReferenceShape $outcome.outer_prelaunch_reference) -and
            [string]$outcome.outer_prelaunch_reference.path -ceq [string]$PrelaunchReference.path -and
            [Int64]$outcome.outer_prelaunch_reference.bytes -eq [Int64]$PrelaunchReference.bytes -and
            [string]$outcome.outer_prelaunch_reference.sha256 -ceq [string]$PrelaunchReference.sha256 -and
            [string]$outcome.outer_prelaunch_reference.volume_serial_hex -ceq [string]$PrelaunchReference.volume_serial_hex -and
            [string]$outcome.outer_prelaunch_reference.file_id_hex -ceq [string]$PrelaunchReference.file_id_hex -and
            [string]$outcome.inner_result_reference.path -ceq [string]$Authority.output.result_path -and
            [Int64]$outcome.inner_result_reference.bytes -eq [Int64]$innerResultOpened.Record.bytes -and
            [string]$outcome.inner_result_reference.sha256 -ceq [string]$innerResultOpened.Record.sha256 -and
            [string]$outcome.inner_result_reference.volume_serial_hex -ceq [string]$innerResultOpened.Record.volume_serial_hex -and
            [string]$outcome.inner_result_reference.file_id_hex -ceq [string]$innerResultOpened.Record.file_id_hex -and
            [string]$outcome.inner_journal_reference.path -ceq [string]$Authority.output.journal_path -and
            [Int64]$outcome.inner_journal_reference.bytes -eq [Int64]$innerJournalOpened.Record.bytes -and
            [string]$outcome.inner_journal_reference.sha256 -ceq [string]$innerJournalOpened.Record.sha256 -and
            [string]$outcome.inner_journal_reference.volume_serial_hex -ceq [string]$innerJournalOpened.Record.volume_serial_hex -and
            [string]$outcome.inner_journal_reference.file_id_hex -ceq [string]$innerJournalOpened.Record.file_id_hex
        $journalValid = [Int64]$journal.schema_version -eq 1 -and [string]$journal.record_type -ceq 'D32_NON_SOURCE_L1_CALLER_JOURNAL_V1' -and
            [string]$journal.purpose -ceq 'NON_SOURCE_L1_CALLER_JOURNAL_ONLY' -and [string]$journal.gate_authority -ceq 'NONE' -and
            [string]$journal.candidate_sha -ceq [string]$Authority.candidate_sha -and [string]$journal.batch_id -ceq [string]$Authority.batch_id -and
            [string]$journal.run_id -ceq [string]$Authority.run_id -and [string]$journal.event -ceq 'CALLER_OUTCOME_PERSISTED' -and
            [string]$journal.submission -ceq 'SYNTHETIC_L0_ONLY_OUTCOME_REOPENED' -and
            [Int64]$journal.controller_return_code -eq $ControllerReturnCode -and
            [Int64]$journal.observed_ticks -ge [Int64]$outcome.clock.completed_ticks -and
            [string]$journal.outcome_reference.path -ceq [string]$outcomeOpened.Record.path -and
            [Int64]$journal.outcome_reference.bytes -eq [Int64]$outcomeOpened.Record.bytes -and
            [string]$journal.outcome_reference.sha256 -ceq [string]$outcomeOpened.Record.sha256 -and
            [string]$journal.outcome_reference.volume_serial_hex -ceq [string]$outcomeOpened.Record.volume_serial_hex -and
            [string]$journal.outcome_reference.file_id_hex -ceq [string]$outcomeOpened.Record.file_id_hex
        if (-not $schemaValid -or -not $controllerValid -or -not $captureValid -or -not $clockValid -or -not $referenceValid -or -not $journalValid) {
            return $false
        }

        $expectedRuntimePaths = @([string]$Authority.output.controller_runtime_admission_path,
            [string]$Authority.output.normalreader_runtime_admission_path,[string]$Authority.output.forcedreader_runtime_admission_path)
        for ($slotIndex = 0; $slotIndex -lt 3; $slotIndex++) {
            $callerRef = $outcome.runtime_admission_references[$slotIndex]
            $resultSlot = $innerResult.runtime_admissions[$slotIndex]
            if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $callerRef) -or
                [string]$callerRef.path -cne $expectedRuntimePaths[$slotIndex] -or
                [string]$callerRef.path -cne [string]$resultSlot.reference.path -or
                [Int64]$callerRef.bytes -ne [Int64]$resultSlot.reference.bytes -or
                [string]$callerRef.sha256 -cne [string]$resultSlot.reference.sha256 -or
                [string]$callerRef.volume_serial_hex -cne [string]$resultSlot.reference.volume_serial_hex -or
                [string]$callerRef.file_id_hex -cne [string]$resultSlot.reference.file_id_hex) { return $false }
            $admissionOpened = Open-D32NonSourceL1PersistedOutput -Path ([string]$callerRef.path) `
                -DirectoryFences ([System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)) -MaximumBytes 65536 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
            try {
                if ([Int64]$admissionOpened.Record.bytes -ne [Int64]$callerRef.bytes -or
                    [string]$admissionOpened.Record.sha256 -cne [string]$callerRef.sha256 -or
                    [string]$admissionOpened.Record.volume_serial_hex -cne [string]$callerRef.volume_serial_hex -or
                    [string]$admissionOpened.Record.file_id_hex -cne [string]$callerRef.file_id_hex) { return $false }
                $admissionDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$admissionOpened.Bytes))
                try {
                    if ($admissionDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                        (Test-D32PowerShellAuthorityJsonDuplicates -Element $admissionDocument.RootElement)) { return $false }
                    $admission = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $admissionDocument.RootElement
                } finally { $admissionDocument.Dispose() }
                $parentReference = if ($slotIndex -eq 0) { $null } else { $innerResult.runtime_admissions[0].reference }
                $parentAdmission = if ($slotIndex -eq 0) { $null } else { $innerResult.runtime_admissions[0].admission }
                if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeAdmissionShape -Admission $admission -Authority $Authority `
                        -Role ([string]$resultSlot.role) -ParentAdmissionReference $parentReference -ParentAdmission $parentAdmission `
                        -AuthorityReference $AuthorityReference -OuterPrelaunchReference $PrelaunchReference)) { return $false }
            } finally { if ($null -ne $admissionOpened.Stream) { $admissionOpened.Stream.Dispose() } }
        }
        return $true
    } catch { return $false }
    finally {
        foreach ($opened in @($outcomeOpened,$journalOpened,$stdoutOpened,$stderrOpened,$innerResultOpened,$innerJournalOpened)) {
            if ($null -ne $opened -and $null -ne $opened.Stream) { try { $opened.Stream.Dispose() } catch {} }
        }
    }
}

function Write-D32NonSourceL1CallerArtifact {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Purpose, [Parameter(Mandatory = $true)][long]$DeadlineTicks)
    if ($Bytes.Length -gt 65536 -or (Get-D32NonSourceL1Now) -ge $DeadlineTicks) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: caller artifact exceeds its byte/time boundary' }
    Write-D32NonSourceL1CreateNewArtifact -Path $Path -Bytes $Bytes -Purpose $Purpose -DeadlineTicks $DeadlineTicks
    $opened = Open-D32NonSourceL1PersistedOutput -Path $Path -DirectoryFences $script:D32LifecycleFences -MaximumBytes 65536 -DeadlineTicks $DeadlineTicks
    try {
        if ([Int64]$opened.Record.bytes -ne $Bytes.Length -or [string]$opened.Record.sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant() -or
            $opened.Bytes.Length -ne $Bytes.Length) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: caller artifact readback changed bytes/hash' }
        for ($index=0; $index -lt $Bytes.Length; $index++) { if ($opened.Bytes[$index] -ne $Bytes[$index]) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: caller artifact reread bytes differ' } }
        return $opened.Record
    } finally { if ($null -ne $opened.Stream) { $opened.Stream.Dispose() } }
}

function Test-D32NonSourceL1ProductionCallerReconciliation {
    param([Parameter(Mandatory = $true)][object]$Authority, [Parameter(Mandatory = $true)][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][object]$PrelaunchReference, [Parameter(Mandatory = $true)][string]$ExpectedStatus,
        [Parameter(Mandatory = $true)][long]$T0Ticks, [Parameter(Mandatory = $true)][long]$Frequency,
        [Parameter(Mandatory = $true)][long]$ControllerReturnCode)
    $opened = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($path in @([string]$Authority.output.caller_outcome_path,[string]$Authority.output.caller_journal_path,
                [string]$Authority.output.stdout_path,[string]$Authority.output.stderr_path,
                [string]$Authority.output.result_path,[string]$Authority.output.journal_path)) {
            $maximum = if ($path -ceq [string]$Authority.output.stdout_path -or $path -ceq [string]$Authority.output.stderr_path) { 16000L } else { 65536L }
            $opened.Add((Open-D32NonSourceL1PersistedOutput -Path $path -DirectoryFences $script:D32LifecycleFences `
                -MaximumBytes $maximum -DeadlineTicks $script:D32NonSourceL1BatchDeadline))
        }
        foreach ($item in $opened) {
            if ([Int64]$item.Record.bytes -ne $item.Bytes.Length -or
                [string]$item.Record.sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$item.Bytes)).ToLowerInvariant()) { return $false }
        }
        $outcomeDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$opened[0].Bytes))
        try {
            if ($outcomeDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                (Test-D32PowerShellAuthorityJsonDuplicates -Element $outcomeDocument.RootElement)) { return $false }
            $outcome = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $outcomeDocument.RootElement
        } finally { $outcomeDocument.Dispose() }
        $canonical = ConvertTo-D32BoundedDiagnosticSourceProofCanonicalJsonBytes -Value $outcome
        if ($canonical.Length -ne $opened[0].Bytes.Length) { return $false }
        for ($i=0; $i -lt $canonical.Length; $i++) { if ($canonical[$i] -ne $opened[0].Bytes[$i]) { return $false } }
        $innerResultDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$opened[4].Bytes))
        try {
            if ($innerResultDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                (Test-D32PowerShellAuthorityJsonDuplicates -Element $innerResultDocument.RootElement)) { return $false }
            $innerResult = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $innerResultDocument.RootElement
        } finally { $innerResultDocument.Dispose() }
        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape $innerResult) -or
            [string]$innerResult.status -cne 'COMPLETE_NON_SOURCE_L1' -or
            [Int64]$innerResult.create_process_attempt_count -ne 2 -or [Int64]$innerResult.planned_termination_count -ne 1 -or
            [Int64]$innerResult.fail_safe_termination_count -ne 0 -or
            [string]$innerResult.cases[0].case_id -cne 'NORMAL_EXIT' -or [string]$innerResult.cases[0].state -cne 'NATIVE_BOUNDARY_VERIFIED' -or
            [string]$innerResult.cases[1].case_id -cne 'FORCED_OWNED_TERMINATION' -or [string]$innerResult.cases[1].state -cne 'NATIVE_BOUNDARY_VERIFIED' -or
            [string]$innerResult.cases[2].case_id -cne 'ENTRY_PIN_BINDING_REFUSAL' -or [string]$innerResult.cases[2].state -cne 'EXPECTED_REFUSAL_VERIFIED' -or
            [string]$innerResult.outer_prelaunch_reference.path -cne [string]$PrelaunchReference.path -or
            [string]$innerResult.outer_prelaunch_reference.sha256 -cne [string]$PrelaunchReference.sha256) { return $false }
        $innerJournalBytes = [byte[]]$opened[5].Bytes
        if ($innerJournalBytes.Length -lt 2 -or $innerJournalBytes[$innerJournalBytes.Length-1] -ne 10 -or
            [Array]::LastIndexOf($innerJournalBytes,[byte]10) -ne ($innerJournalBytes.Length-1) -or
            [Array]::IndexOf($innerJournalBytes,[byte]13) -ge 0) { return $false }
        $innerJournalText = [Text.UTF8Encoding]::new($false,$true).GetString($innerJournalBytes)
        $innerJournalLines = @($innerJournalText.Split("`n",[StringSplitOptions]::RemoveEmptyEntries))
        if ($innerJournalLines.Count -ne 5 -or $innerJournalBytes.Length -gt 65536) { return $false }
        $innerJournalFacts = [System.Collections.Generic.List[object]]::new()
        foreach ($line in $innerJournalLines) {
            $factDocument = [System.Text.Json.JsonDocument]::Parse([string]$line)
            try {
                if ($factDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                    (Test-D32PowerShellAuthorityJsonDuplicates -Element $factDocument.RootElement)) { return $false }
                $fact = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $factDocument.RootElement
            } finally { $factDocument.Dispose() }
            if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $fact @('event','case_id','scheduled_ticks','observed_ticks','lateness_ticks',
                    'result_path','result_bytes','result_sha256','result_volume_serial_hex','result_file_id_hex','case_evidence_sha256','gate_authority')) -or
                [string]$fact.gate_authority -cne 'NONE' -or -not (Test-D32BoundedCompilerDiagnosticInteger $fact.observed_ticks -Positive) -or
                [Int64]$fact.observed_ticks -lt $T0Ticks -or [Int64]$fact.observed_ticks -ge $script:D32NonSourceL1BatchDeadline) { return $false }
            $innerJournalFacts.Add($fact)
        }
        if ([string]$innerJournalFacts[0].event -cne 'AUTHORITY_ADMISSION' -or
            [string]$innerJournalFacts[1].event -cne ('CASE_' + [string]$innerResult.cases[0].state) -or
            [string]$innerJournalFacts[1].case_id -cne 'NORMAL_EXIT' -or
            [string]$innerJournalFacts[2].event -cne ('CASE_' + [string]$innerResult.cases[1].state) -or
            [string]$innerJournalFacts[2].case_id -cne 'FORCED_OWNED_TERMINATION' -or
            [string]$innerJournalFacts[3].event -cne ('CASE_' + [string]$innerResult.cases[2].state) -or
            [string]$innerJournalFacts[3].case_id -cne 'ENTRY_PIN_BINDING_REFUSAL' -or
            [string]$innerJournalFacts[4].event -cne 'L1_RESULT_PERSISTED' -or
            [string]$innerJournalFacts[4].result_path -cne [string]$Authority.output.result_path -or
            [Int64]$innerJournalFacts[4].result_bytes -ne [Int64]$opened[4].Record.bytes -or
            [string]$innerJournalFacts[4].result_sha256 -cne [string]$opened[4].Record.sha256 -or
            [string]$innerJournalFacts[4].result_volume_serial_hex -cne [string]$opened[4].Record.volume_serial_hex -or
            [string]$innerJournalFacts[4].result_file_id_hex -cne [string]$opened[4].Record.file_id_hex) { return $false }
        $outcomeFields = @('schema_version','record_type','purpose','gate_authority','candidate_sha','batch_id','run_id','status','execution_mode',
            'outer_prelaunch_reference','controller','captures','runtime_admission_references','inner_result_reference','inner_journal_reference','clock','primary_error','secondary_errors')
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $outcome $outcomeFields) -or
            -not (Test-D32BoundedCompilerDiagnosticExactProperties $outcome.controller @('native_create_attempted','process_id','creation_filetime_ticks','assigned','resumed',
                'exit_code','job_active_process_count','job_total_process_count','handles_closed','cleanup_state')) -or
            -not (Test-D32BoundedCompilerDiagnosticExactProperties $outcome.captures @('stdout_reference','stderr_reference','stdout_bytes','stderr_bytes','stdout_sha256','stderr_sha256',
                'stdout_truncated','stderr_truncated','transport','complete')) -or
            [Int64]$outcome.schema_version -ne 1 -or [string]$outcome.record_type -cne 'D32_NON_SOURCE_L1_CALLER_OUTCOME_V1' -or
            [string]$outcome.purpose -cne 'NON_SOURCE_L1_CALLER_OUTCOME_ONLY' -or [string]$outcome.gate_authority -cne 'NONE' -or
            [string]$outcome.status -cne $ExpectedStatus -or [string]$outcome.execution_mode -cne 'FIXED_NATIVE_OUTER_CALLER_V1' -or
            $null -ne $outcome.primary_error -or $outcome.secondary_errors -isnot [Array] -or $outcome.secondary_errors.Count -ne 0 -or
            [string]$outcome.candidate_sha -cne [string]$Authority.candidate_sha -or [string]$outcome.batch_id -cne [string]$Authority.batch_id -or
            [string]$outcome.run_id -cne [string]$Authority.run_id -or
            -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $AuthorityReference) -or
            -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $PrelaunchReference) -or
            [string]$outcome.outer_prelaunch_reference.path -cne [string]$PrelaunchReference.path -or
            [string]$outcome.outer_prelaunch_reference.sha256 -cne [string]$PrelaunchReference.sha256 -or
            [Int64]$outcome.outer_prelaunch_reference.bytes -ne [Int64]$PrelaunchReference.bytes -or
            [string]$outcome.outer_prelaunch_reference.volume_serial_hex -cne [string]$PrelaunchReference.volume_serial_hex -or
            [string]$outcome.outer_prelaunch_reference.file_id_hex -cne [string]$PrelaunchReference.file_id_hex -or
            [string]$outcome.inner_result_reference.path -cne [string]$Authority.output.result_path -or
            [string]$outcome.inner_journal_reference.path -cne [string]$Authority.output.journal_path -or
            [Int64]$outcome.clock.batch_t0_ticks -ne $T0Ticks -or [Int64]$outcome.clock.frequency -ne $Frequency -or
            [Int64]$outcome.clock.completed_ticks -ge $script:D32NonSourceL1BatchDeadline -or
            [Int64]$outcome.controller.exit_code -ne $ControllerReturnCode -or
            $outcome.controller.native_create_attempted -isnot [bool] -or -not $outcome.controller.native_create_attempted -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $outcome.controller.process_id -Positive) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $outcome.controller.creation_filetime_ticks -Positive) -or
            $outcome.controller.assigned -isnot [bool] -or -not $outcome.controller.assigned -or
            $outcome.controller.resumed -isnot [bool] -or -not $outcome.controller.resumed -or
            $outcome.controller.handles_closed -isnot [bool] -or -not $outcome.controller.handles_closed -or
            [string]$outcome.controller.cleanup_state -cne 'OWNED_JOB_QUIESCENT_CAPTURE_JOINED_HANDLES_CLOSED' -or
            [Int64]$outcome.controller.job_active_process_count -ne 0 -or
            [Int64]$outcome.controller.job_total_process_count -lt 1 -or [Int64]$outcome.controller.job_total_process_count -gt 3 -or
            [Int64]$outcome.controller.exit_code -ne 0 -or
            [Int64]$outcome.captures.stdout_bytes -ne $opened[2].Bytes.Length -or
            [Int64]$outcome.captures.stderr_bytes -ne $opened[3].Bytes.Length -or
            [string]$outcome.captures.stdout_sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$opened[2].Bytes)).ToLowerInvariant() -or
            [string]$outcome.captures.stderr_sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$opened[3].Bytes)).ToLowerInvariant() -or
            $outcome.captures.complete -isnot [bool] -or -not $outcome.captures.complete -or
            $outcome.captures.stdout_truncated -isnot [bool] -or $outcome.captures.stdout_truncated -or
            $outcome.captures.stderr_truncated -isnot [bool] -or $outcome.captures.stderr_truncated -or
            [string]$outcome.captures.transport -cne 'NATIVE_BOUNDED_PIPE_CAPTURE' -or
            [string]$outcome.captures.stdout_reference.sha256 -cne [string]$opened[2].Record.sha256 -or
            [string]$outcome.captures.stderr_reference.sha256 -cne [string]$opened[3].Record.sha256) { return $false }
        foreach ($pair in @(@($outcome.inner_result_reference,$opened[4].Record),@($outcome.inner_journal_reference,$opened[5].Record))) {
            if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $pair[0])) { return $false }
            foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
                if ([string]$pair[0].$name -cne [string]$pair[1].$name) { return $false }
            }
        }
        if ($outcome.runtime_admission_references -isnot [Array] -or $outcome.runtime_admission_references.Count -ne 3) { return $false }
        for ($index=0; $index -lt 3; $index++) {
            $callerRef = $outcome.runtime_admission_references[$index]
            $resultSlot = $innerResult.runtime_admissions[$index]
            $runtimePaths = @([string]$Authority.output.controller_runtime_admission_path,[string]$Authority.output.normalreader_runtime_admission_path,
                [string]$Authority.output.forcedreader_runtime_admission_path)
            if ([string]$resultSlot.status -cne 'ADMITTED' -or -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $callerRef) -or
                [string]$callerRef.path -cne $runtimePaths[$index] -or
                [string]$callerRef.path -cne [string]$resultSlot.reference.path) { return $false }
            foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
                if ([string]$callerRef.$name -cne [string]$resultSlot.reference.$name) { return $false }
            }
            $admissionOpened = Open-D32NonSourceL1PersistedOutput -Path $runtimePaths[$index] -DirectoryFences $script:D32LifecycleFences `
                -MaximumBytes 65536 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
            try {
                foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
                    if ([string]$admissionOpened.Record.$name -cne [string]$callerRef.$name) { return $false }
                }
                $admissionDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$admissionOpened.Bytes))
                try {
                    if ($admissionDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                        (Test-D32PowerShellAuthorityJsonDuplicates -Element $admissionDocument.RootElement)) { return $false }
                    $admission = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $admissionDocument.RootElement
                } finally { $admissionDocument.Dispose() }
                $parentReference = if ($index -eq 0) { $null } else { $innerResult.runtime_admissions[0].reference }
                $parentAdmission = if ($index -eq 0) { $null } else { $innerResult.runtime_admissions[0].admission }
                if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeAdmissionShape -Admission $admission -Authority $Authority `
                        -Role ([string]$resultSlot.role) -ParentAdmissionReference $parentReference -ParentAdmission $parentAdmission `
                        -AuthorityReference $AuthorityReference -OuterPrelaunchReference $PrelaunchReference)) { return $false }
            } finally { if ($null -ne $admissionOpened.Stream) { $admissionOpened.Stream.Dispose() } }
        }
        $journalBytes = [byte[]]$opened[1].Bytes
        if ($journalBytes.Length -lt 2 -or $journalBytes[$journalBytes.Length-1] -ne 10 -or
            [Array]::IndexOf($journalBytes,[byte]10) -ne ($journalBytes.Length-1) -or [Array]::IndexOf($journalBytes,[byte]13) -ge 0) { return $false }
        $journalJson = [byte[]]::new($journalBytes.Length-1); [Array]::Copy($journalBytes,$journalJson,$journalJson.Length)
        $journalDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString($journalJson))
        try {
            if ($journalDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                (Test-D32PowerShellAuthorityJsonDuplicates -Element $journalDocument.RootElement)) { return $false }
            $journal = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $journalDocument.RootElement
        } finally { $journalDocument.Dispose() }
        $journalCanonical = ConvertTo-D32BoundedDiagnosticSourceProofCanonicalJsonBytes -Value $journal
        if ($journalCanonical.Length -ne $journalJson.Length) { return $false }
        for ($index=0; $index -lt $journalCanonical.Length; $index++) { if ($journalCanonical[$index] -ne $journalJson[$index]) { return $false } }
        $journalFields = @('schema_version','record_type','purpose','gate_authority','candidate_sha','batch_id','run_id','event','outcome_reference','submission','controller_return_code','observed_ticks')
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $journal $journalFields) -or
            [Int64]$journal.schema_version -ne 1 -or [string]$journal.record_type -cne 'D32_NON_SOURCE_L1_CALLER_JOURNAL_V1' -or
            [string]$journal.purpose -cne 'NON_SOURCE_L1_CALLER_JOURNAL_ONLY' -or [string]$journal.gate_authority -cne 'NONE' -or
            [string]$journal.event -cne 'CALLER_OUTCOME_PERSISTED' -or [string]$journal.submission -cne 'CALLER_OUTCOME_REOPENED' -or
            [string]$journal.candidate_sha -cne [string]$Authority.candidate_sha -or [string]$journal.batch_id -cne [string]$Authority.batch_id -or
            [string]$journal.run_id -cne [string]$Authority.run_id -or [Int64]$journal.controller_return_code -ne $ControllerReturnCode -or
            [string]$journal.outcome_reference.path -cne [string]$opened[0].Record.path -or
            [string]$journal.outcome_reference.sha256 -cne [string]$opened[0].Record.sha256 -or
            [string]$journal.outcome_reference.volume_serial_hex -cne [string]$opened[0].Record.volume_serial_hex -or
            [string]$journal.outcome_reference.file_id_hex -cne [string]$opened[0].Record.file_id_hex -or
            [Int64]$journal.observed_ticks -lt [Int64]$outcome.clock.completed_ticks) { return $false }
        return $true
    } catch { return $false }
    finally { foreach ($item in $opened) { if ($null -ne $item.Stream) { try { $item.Stream.Dispose() } catch {} } } }
}

function Test-D32NonSourceL1ProductionNoCreateRefusalReconciliation {
    param([Parameter(Mandatory = $true)][object]$Authority, [Parameter(Mandatory = $true)][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][object]$OutcomeReference,
        [Parameter(Mandatory = $true)][long]$T0Ticks, [Parameter(Mandatory = $true)][long]$Frequency,
        [Parameter(Mandatory = $true)][long]$DeadlineTicks, [Parameter(Mandatory = $true)][long]$ControllerReturnCode,
        [Parameter(Mandatory = $true)][string]$ExpectedStatus, [Parameter(Mandatory = $true)][bool]$NativeCreateAttempted,
        [Parameter(Mandatory = $true)][bool]$HandlesClosed, [Parameter(Mandatory = $true)][AllowNull()][object]$PrelaunchReference,
        [AllowNull()][string]$ExpectedBindingSha256)
    $outcomeOpened = $null; $journalOpened = $null
    try {
        $outcomeOpened = Open-D32NonSourceL1PersistedOutput -Path ([string]$Authority.output.caller_outcome_path) `
            -DirectoryFences $script:D32LifecycleFences -MaximumBytes 65536 -DeadlineTicks $DeadlineTicks
        $journalOpened = Open-D32NonSourceL1PersistedOutput -Path ([string]$Authority.output.caller_journal_path) `
            -DirectoryFences $script:D32LifecycleFences -MaximumBytes 65536 -DeadlineTicks $DeadlineTicks
        foreach ($opened in @($outcomeOpened,$journalOpened)) {
            if ([Int64]$opened.Record.bytes -ne $opened.Bytes.Length -or
                [string]$opened.Record.sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$opened.Bytes)).ToLowerInvariant()) { return $false }
        }
        $outcomeDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$outcomeOpened.Bytes))
        try {
            if ($outcomeDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                (Test-D32PowerShellAuthorityJsonDuplicates -Element $outcomeDocument.RootElement)) { return $false }
            $outcome = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $outcomeDocument.RootElement
        } finally { $outcomeDocument.Dispose() }
        $canonical = ConvertTo-D32BoundedDiagnosticSourceProofCanonicalJsonBytes -Value $outcome
        if ($canonical.Length -ne $outcomeOpened.Bytes.Length) { return $false }
        for ($index=0; $index -lt $canonical.Length; $index++) { if ($canonical[$index] -ne $outcomeOpened.Bytes[$index]) { return $false } }
        $outcomeFields = @('schema_version','record_type','purpose','gate_authority','candidate_sha','batch_id','run_id','status','execution_mode',
            'outer_prelaunch_reference','controller','captures','runtime_admission_references','inner_result_reference','inner_journal_reference','clock','primary_error','secondary_errors')
        $controllerFields = @('native_create_attempted','process_id','creation_filetime_ticks','assigned','resumed','exit_code','job_active_process_count',
            'job_total_process_count','handles_closed','cleanup_state')
        $captureFields = @('stdout_reference','stderr_reference','stdout_bytes','stderr_bytes','stdout_sha256','stderr_sha256','stdout_truncated','stderr_truncated','transport','complete')
        $clockFields = @('counter_origin','frequency','batch_t0_ticks','completed_ticks')
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $outcome $outcomeFields) -or
            -not (Test-D32BoundedCompilerDiagnosticExactProperties $outcome.controller $controllerFields) -or
            -not (Test-D32BoundedCompilerDiagnosticExactProperties $outcome.captures $captureFields) -or
            -not (Test-D32BoundedCompilerDiagnosticExactProperties $outcome.clock $clockFields) -or
            [Int64]$outcome.schema_version -ne 1 -or [string]$outcome.record_type -cne 'D32_NON_SOURCE_L1_CALLER_OUTCOME_V1' -or
            [string]$outcome.purpose -cne 'NON_SOURCE_L1_CALLER_OUTCOME_ONLY' -or [string]$outcome.gate_authority -cne 'NONE' -or
            [string]$outcome.candidate_sha -cne [string]$Authority.candidate_sha -or [string]$outcome.batch_id -cne [string]$Authority.batch_id -or
            [string]$outcome.run_id -cne [string]$Authority.run_id -or [string]$outcome.status -cne $ExpectedStatus -or
            $ExpectedStatus -cnotin @('REFUSED','BLOCKED','UNRESOLVED') -or [string]$outcome.execution_mode -cne 'FIXED_NATIVE_OUTER_CALLER_V1' -or
            $null -ne $outcome.captures.stdout_reference -or $null -ne $outcome.captures.stderr_reference -or
            [Int64]$outcome.captures.stdout_bytes -ne 0 -or [Int64]$outcome.captures.stderr_bytes -ne 0 -or
            $null -ne $outcome.captures.stdout_sha256 -or $null -ne $outcome.captures.stderr_sha256 -or
            $outcome.captures.stdout_truncated -isnot [bool] -or $outcome.captures.stdout_truncated -or
            $outcome.captures.stderr_truncated -isnot [bool] -or $outcome.captures.stderr_truncated -or
            [string]$outcome.captures.transport -cne 'NO_PROCESS_CREATED' -or $outcome.captures.complete -isnot [bool] -or -not $outcome.captures.complete -or
            $outcome.runtime_admission_references -isnot [Array] -or $outcome.runtime_admission_references.Count -ne 0 -or
            $null -ne $outcome.inner_result_reference -or $null -ne $outcome.inner_journal_reference -or
            $outcome.controller.native_create_attempted -isnot [bool] -or [bool]$outcome.controller.native_create_attempted -ne $NativeCreateAttempted -or
            $null -ne $outcome.controller.process_id -or $null -ne $outcome.controller.creation_filetime_ticks -or
            $outcome.controller.assigned -isnot [bool] -or $outcome.controller.assigned -or
            $outcome.controller.resumed -isnot [bool] -or $outcome.controller.resumed -or
            $null -ne $outcome.controller.exit_code -or $null -ne $outcome.controller.job_active_process_count -or
            $null -ne $outcome.controller.job_total_process_count -or $outcome.controller.handles_closed -isnot [bool] -or
            [bool]$outcome.controller.handles_closed -ne $HandlesClosed -or
            [string]$outcome.controller.cleanup_state -cne $(switch ($ExpectedStatus) { 'REFUSED' { 'NOT_REQUIRED' } 'BLOCKED' { 'OWNED_CLEANUP_FAILED' } default { 'UNRESOLVED' } }) -or
            [string]$outcome.clock.counter_origin -cne 'QueryPerformanceCounter' -or [Int64]$outcome.clock.frequency -ne $Frequency -or
            [Int64]$outcome.clock.batch_t0_ticks -ne $T0Ticks -or [Int64]$outcome.clock.completed_ticks -lt $T0Ticks -or
            [Int64]$outcome.clock.completed_ticks -ge $DeadlineTicks -or [string]::IsNullOrWhiteSpace([string]$outcome.primary_error) -or
            $outcome.secondary_errors -isnot [Array]) { return $false }
        if ($null -eq $PrelaunchReference) {
            if ($null -ne $outcome.outer_prelaunch_reference) { return $false }
        } else {
            if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $PrelaunchReference) -or
                -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $outcome.outer_prelaunch_reference) -or
                $ExpectedBindingSha256 -cnotmatch '^[0-9a-f]{64}$') { return $false }
            foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
                if ([string]$outcome.outer_prelaunch_reference.$name -cne [string]$PrelaunchReference.$name) { return $false }
            }
            $prelaunch = Open-D32NonSourceL1OuterPrelaunchRecord -Authority $Authority -AuthorityReference $AuthorityReference `
                -ExpectedBindingSha256 $ExpectedBindingSha256 -DeadlineTicks $DeadlineTicks
            if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $prelaunch.reference)) { return $false }
            foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
                if ([string]$prelaunch.reference.$name -cne [string]$PrelaunchReference.$name) { return $false }
            }
        }

        $journalBytes = [byte[]]$journalOpened.Bytes
        if ($journalBytes.Length -lt 2 -or $journalBytes[$journalBytes.Length-1] -ne 10 -or
            [Array]::IndexOf($journalBytes,[byte]10) -ne ($journalBytes.Length-1) -or [Array]::IndexOf($journalBytes,[byte]13) -ge 0) { return $false }
        $journalJson = [byte[]]::new($journalBytes.Length-1); [Array]::Copy($journalBytes,$journalJson,$journalJson.Length)
        $journalDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString($journalJson))
        try {
            if ($journalDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                (Test-D32PowerShellAuthorityJsonDuplicates -Element $journalDocument.RootElement)) { return $false }
            $journal = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $journalDocument.RootElement
        } finally { $journalDocument.Dispose() }
        $journalCanonical = ConvertTo-D32BoundedDiagnosticSourceProofCanonicalJsonBytes -Value $journal
        if ($journalCanonical.Length -ne $journalJson.Length) { return $false }
        for ($index=0; $index -lt $journalCanonical.Length; $index++) { if ($journalCanonical[$index] -ne $journalJson[$index]) { return $false } }
        $journalFields = @('schema_version','record_type','purpose','gate_authority','candidate_sha','batch_id','run_id','event','outcome_reference','submission','controller_return_code','observed_ticks')
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $OutcomeReference)) { return $false }
        foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
            if ([string]$OutcomeReference.$name -cne [string]$outcomeOpened.Record.$name) { return $false }
        }
        return ((Test-D32BoundedCompilerDiagnosticExactProperties $journal $journalFields) -and
            [Int64]$journal.schema_version -eq 1 -and [string]$journal.record_type -ceq 'D32_NON_SOURCE_L1_CALLER_JOURNAL_V1' -and
            [string]$journal.purpose -ceq 'NON_SOURCE_L1_CALLER_JOURNAL_ONLY' -and [string]$journal.gate_authority -ceq 'NONE' -and
            [string]$journal.candidate_sha -ceq [string]$Authority.candidate_sha -and [string]$journal.batch_id -ceq [string]$Authority.batch_id -and
            [string]$journal.run_id -ceq [string]$Authority.run_id -and [string]$journal.event -ceq 'CALLER_OUTCOME_PERSISTED' -and
            [string]$journal.submission -ceq 'CALLER_OUTCOME_REOPENED' -and [Int64]$journal.controller_return_code -eq $ControllerReturnCode -and
            [Int64]$journal.observed_ticks -ge [Int64]$outcome.clock.completed_ticks -and [Int64]$journal.observed_ticks -lt $DeadlineTicks -and
            (Test-D32BoundedCompilerDiagnosticFileReferenceShape $journal.outcome_reference) -and
            [string]$journal.outcome_reference.path -ceq [string]$OutcomeReference.path -and
            [Int64]$journal.outcome_reference.bytes -eq [Int64]$OutcomeReference.bytes -and
            [string]$journal.outcome_reference.sha256 -ceq [string]$OutcomeReference.sha256 -and
            [string]$journal.outcome_reference.volume_serial_hex -ceq [string]$OutcomeReference.volume_serial_hex -and
            [string]$journal.outcome_reference.file_id_hex -ceq [string]$OutcomeReference.file_id_hex)
    } catch { return $false }
    finally {
        foreach ($opened in @($outcomeOpened,$journalOpened)) { if ($null -ne $opened -and $null -ne $opened.Stream) { try { $opened.Stream.Dispose() } catch {} } }
    }
}

function Write-D32NonSourceL1ProductionNoCreateRefusal {
    param([Parameter(Mandatory = $true)][object]$Authority, [Parameter(Mandatory = $true)][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][long]$T0Ticks, [Parameter(Mandatory = $true)][long]$Frequency,
        [Parameter(Mandatory = $true)][long]$DeadlineTicks, [Parameter(Mandatory = $true)][string]$PrimaryError,
        [Parameter(Mandatory = $true)][string]$Status, [Parameter(Mandatory = $true)][bool]$NativeCreateAttempted,
        [Parameter(Mandatory = $true)][bool]$HandlesClosed, [Parameter(Mandatory = $true)][AllowNull()][object]$PrelaunchReference,
        [AllowNull()][string]$ExpectedBindingSha256)
    if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $Authority -ExpectedCandidateSha $CandidateSha -Repository $Repository) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $AuthorityReference) -or
        [string]$AuthorityReference.path -cne $L1AuthorityPath -or [string]$AuthorityReference.sha256 -cne $ExpectedL1AuthoritySha256 -or
        [string]::IsNullOrWhiteSpace($PrimaryError) -or (Get-D32NonSourceL1Now) -ge $DeadlineTicks) {
        throw 'D32_NON_SOURCE_L1_UNRESOLVED: zero-create refusal is not safe to persist against the current strict authority'
    }
    $completed = Get-D32NonSourceL1Now
    $outcome = [PSCustomObject][ordered]@{
        schema_version=1;record_type='D32_NON_SOURCE_L1_CALLER_OUTCOME_V1';purpose='NON_SOURCE_L1_CALLER_OUTCOME_ONLY';gate_authority='NONE'
        candidate_sha=$Authority.candidate_sha;batch_id=$Authority.batch_id;run_id=$Authority.run_id;status=$Status;execution_mode='FIXED_NATIVE_OUTER_CALLER_V1'
        outer_prelaunch_reference=$PrelaunchReference
        controller=[PSCustomObject][ordered]@{native_create_attempted=$NativeCreateAttempted;process_id=$null;creation_filetime_ticks=$null;assigned=$false;resumed=$false
            exit_code=$null;job_active_process_count=$null;job_total_process_count=$null;handles_closed=$HandlesClosed
            cleanup_state=$(switch ($Status) { 'REFUSED' { 'NOT_REQUIRED' } 'BLOCKED' { 'OWNED_CLEANUP_FAILED' } default { 'UNRESOLVED' } })}
        captures=[PSCustomObject][ordered]@{stdout_reference=$null;stderr_reference=$null;stdout_bytes=0L;stderr_bytes=0L;stdout_sha256=$null;stderr_sha256=$null
            stdout_truncated=$false;stderr_truncated=$false;transport='NO_PROCESS_CREATED';complete=$true}
        runtime_admission_references=@();inner_result_reference=$null;inner_journal_reference=$null
        clock=[PSCustomObject][ordered]@{counter_origin='QueryPerformanceCounter';frequency=$Frequency;batch_t0_ticks=$T0Ticks;completed_ticks=$completed}
        primary_error=$PrimaryError;secondary_errors=@()
    }
    $outcomeBytes=ConvertTo-D32BoundedDiagnosticSourceProofCanonicalJsonBytes -Value $outcome
    $outcomeReference=Write-D32NonSourceL1CallerArtifact -Path ([string]$Authority.output.caller_outcome_path) -Bytes $outcomeBytes -Purpose CALLER_OUTCOME -DeadlineTicks $DeadlineTicks
    $record=[PSCustomObject][ordered]@{schema_version=1;record_type='D32_NON_SOURCE_L1_CALLER_JOURNAL_V1';purpose='NON_SOURCE_L1_CALLER_JOURNAL_ONLY'
        gate_authority='NONE';candidate_sha=$Authority.candidate_sha;batch_id=$Authority.batch_id;run_id=$Authority.run_id;event='CALLER_OUTCOME_PERSISTED'
        outcome_reference=$outcomeReference;submission='CALLER_OUTCOME_REOPENED';controller_return_code=87;observed_ticks=(Get-D32NonSourceL1Now)}
    $json=ConvertTo-D32BoundedDiagnosticSourceProofCanonicalJsonBytes -Value $record
    $journalBytes=[byte[]]::new($json.Length+1);[Array]::Copy($json,$journalBytes,$json.Length);$journalBytes[$journalBytes.Length-1]=10
    $null=Write-D32NonSourceL1CallerArtifact -Path ([string]$Authority.output.caller_journal_path) -Bytes $journalBytes -Purpose CALLER_JOURNAL -DeadlineTicks $DeadlineTicks
    if (-not (Test-D32NonSourceL1ProductionNoCreateRefusalReconciliation -Authority $Authority -AuthorityReference $AuthorityReference -OutcomeReference $outcomeReference `
            -T0Ticks $T0Ticks -Frequency $Frequency -DeadlineTicks $DeadlineTicks -ControllerReturnCode 87 -ExpectedStatus $Status `
            -NativeCreateAttempted $NativeCreateAttempted -HandlesClosed $HandlesClosed -PrelaunchReference $PrelaunchReference `
            -ExpectedBindingSha256 $ExpectedBindingSha256)) {
        throw 'D32_NON_SOURCE_L1_UNRESOLVED: zero-create refusal outcome/journal strict reopen failed'
    }
    return $outcomeReference
}

function New-D32NonSourceL1OuterControllerPreparation {
    param([Parameter(Mandatory = $true)][string]$Image, [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory, [Parameter(Mandatory = $true)][string[]]$EnvironmentEntries)
    if ($null -ne $script:D32NonSourceL1OuterNativeAdapter) {
        if ($null -eq $script:D32NonSourceL1OuterNativeAdapter.Prepare) { throw 'D32_NON_SOURCE_L1_REFUSED: fixed synthetic outer preparation provider is unavailable' }
        return & $script:D32NonSourceL1OuterNativeAdapter.Prepare -Image $Image -Arguments $Arguments `
            -WorkingDirectory $WorkingDirectory -EnvironmentEntries $EnvironmentEntries
    }
    return [D32BoundedSourceProofLifecycleNativeV1]::PrepareOuterController($Image,$Arguments,$WorkingDirectory,$EnvironmentEntries)
}

function Bind-D32NonSourceL1OuterControllerCommandLine {
    param([Parameter(Mandatory = $true)][object]$Prepared, [Parameter(Mandatory = $true)][string[]]$Vector,
        [Parameter(Mandatory = $true)][string]$CommandLine, [Parameter(Mandatory = $true)][string]$BindingSha256)
    if ($null -ne $script:D32NonSourceL1OuterNativeAdapter) {
        if ($null -eq $Prepared.Owned -or $null -eq $Prepared.Owned.Invocation -or $Vector.Count -ne 18 -or
            $Vector[16] -cne '-ExpectedOuterPrelaunchBindingSha256' -or $Vector[17] -cne $BindingSha256 -or
            $BindingSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $CommandLine -cne (Get-D32BoundedDiagnosticSourceProofOuterPrelaunchCommandLine -Image ([string]$Prepared.Owned.Invocation.ImagePath) -Vector $Vector)) {
            throw 'D32_NON_SOURCE_L1_REFUSED: synthetic persisted outer command line is not the exact H-bound vector'
        }
        $Prepared.Owned.Invocation.Arguments = [string[]]$Vector.Clone()
        $Prepared.Owned.Invocation.CommandLine = $CommandLine
        return
    }
    [D32BoundedSourceProofLifecycleNativeV1]::BindOuterControllerCommandLine($Prepared,$Vector,$CommandLine,$BindingSha256)
}

function Start-D32NonSourceL1OuterController {
    param([Parameter(Mandatory = $true)][object]$Prepared, [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][long]$T0Ticks, [Parameter(Mandatory = $true)][long]$Frequency,
        [Parameter(Mandatory = $true)][long]$DeadlineTicks)
    if ($null -ne $script:D32NonSourceL1OuterNativeAdapter) {
        if ($null -eq $script:D32NonSourceL1OuterNativeAdapter.Launch) { throw 'D32_NON_SOURCE_L1_REFUSED: fixed synthetic outer launch provider is unavailable' }
        return & $script:D32NonSourceL1OuterNativeAdapter.Launch -Prepared $Prepared -CommandLine $CommandLine `
            -T0Ticks $T0Ticks -Frequency $Frequency -DeadlineTicks $DeadlineTicks
    }
    return [D32BoundedSourceProofLifecycleNativeV1]::LaunchOuterController($Prepared,$CommandLine,$T0Ticks,$Frequency,$DeadlineTicks)
}

function Wait-D32NonSourceL1OuterController {
    param([Parameter(Mandatory = $true)][object]$Owned, [Parameter(Mandatory = $true)][int]$Milliseconds)
    if ($null -ne $script:D32NonSourceL1OuterNativeAdapter) { return [bool](& $script:D32NonSourceL1OuterNativeAdapter.Wait -Owned $Owned -Milliseconds $Milliseconds) }
    return [bool][D32BoundedSourceProofLifecycleNativeV1]::WaitOuterController($Owned,$Milliseconds)
}

function Stop-D32NonSourceL1OuterJob {
    param([Parameter(Mandatory = $true)][object]$Owned, [Parameter(Mandatory = $true)][int]$ExitCode)
    if ($null -ne $script:D32NonSourceL1OuterNativeAdapter) { return [bool](& $script:D32NonSourceL1OuterNativeAdapter.TerminateJob -Owned $Owned -ExitCode $ExitCode) }
    return [bool][D32BoundedSourceProofLifecycleNativeV1]::TerminateJob($Owned.Job,$ExitCode)
}

function Stop-D32NonSourceL1OuterProcess {
    param([Parameter(Mandatory = $true)][object]$Owned, [Parameter(Mandatory = $true)][int]$ExitCode)
    if ($null -ne $script:D32NonSourceL1OuterNativeAdapter) { return [bool](& $script:D32NonSourceL1OuterNativeAdapter.TerminateProcess -Owned $Owned -ExitCode $ExitCode) }
    return [bool][D32BoundedSourceProofLifecycleNativeV1]::TerminateExactProcess($Owned.Process,$ExitCode)
}

function Get-D32NonSourceL1OuterControllerExitCode {
    param([Parameter(Mandatory = $true)][object]$Owned)
    if ($null -ne $script:D32NonSourceL1OuterNativeAdapter) { return & $script:D32NonSourceL1OuterNativeAdapter.ExitCode -Owned $Owned }
    return [D32BoundedSourceProofLifecycleNativeV1]::OuterControllerExitCode($Owned)
}

function Get-D32NonSourceL1OuterJobActiveProcesses {
    param([Parameter(Mandatory = $true)][object]$Owned)
    if ($null -ne $script:D32NonSourceL1OuterNativeAdapter) { return & $script:D32NonSourceL1OuterNativeAdapter.ActiveProcesses -Owned $Owned }
    return [D32BoundedSourceProofLifecycleNativeV1]::OuterJobActiveProcesses($Owned)
}

function Get-D32NonSourceL1OuterJobTotalProcesses {
    param([Parameter(Mandatory = $true)][object]$Owned)
    if ($null -ne $script:D32NonSourceL1OuterNativeAdapter) { return & $script:D32NonSourceL1OuterNativeAdapter.TotalProcesses -Owned $Owned }
    return [D32BoundedSourceProofLifecycleNativeV1]::OuterJobTotalProcesses($Owned)
}

function Join-D32NonSourceL1OuterCaptures {
    param([Parameter(Mandatory = $true)][object]$Owned, [Parameter(Mandatory = $true)][int]$Milliseconds)
    if ($null -ne $script:D32NonSourceL1OuterNativeAdapter) { return [bool](& $script:D32NonSourceL1OuterNativeAdapter.JoinCaptures -Owned $Owned -Milliseconds $Milliseconds) }
    return [bool][D32BoundedSourceProofLifecycleNativeV1]::JoinOuterControllerCaptures($Owned,$Milliseconds)
}

function Close-D32NonSourceL1OuterController {
    param([Parameter(Mandatory = $true)][object]$Owned)
    if ($null -ne $script:D32NonSourceL1OuterNativeAdapter) { return [bool](& $script:D32NonSourceL1OuterNativeAdapter.Close -Owned $Owned) }
    return [bool][D32BoundedSourceProofLifecycleNativeV1]::CloseOuterController($Owned)
}

function Close-D32NonSourceL1OuterPreparation {
    param([Parameter(Mandatory = $true)][object]$Prepared)
    if ($null -ne $script:D32NonSourceL1OuterNativeAdapter) { return [bool](& $script:D32NonSourceL1OuterNativeAdapter.ClosePreparation -Prepared $Prepared) }
    return [bool][D32BoundedSourceProofLifecycleNativeV1]::CloseOuterControllerPreparation($Prepared)
}

function Invoke-D32NonSourceL1ProductionOuterCaller {
    param([Parameter(Mandatory = $true)][System.IO.TextWriter]$DiagnosticWriter)
    $frequency = [Int64](Get-D32NonSourceL1QpcFrequency)
    $t0 = [Int64](Get-D32NonSourceL1CaptureT0 -Frequency $frequency)
    if ($frequency -le 0) { throw 'D32_NON_SOURCE_L1_REFUSED: trusted caller monotonic frequency is unavailable' }
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        $script:D32NonSourceL1Now = { [Int64](& $script:D32NonSourceL1EnvironmentAdapter.Now) }
        if ($null -eq $script:D32NonSourceL1CallerAdapter -or
            [string]$script:D32NonSourceL1CallerAdapter.route -cne 'IN_PROCESS_SYNTHETIC_L0' -or
            $null -eq $script:D32NonSourceL1OuterNativeAdapter) {
            throw 'D32_NON_SOURCE_L1_REFUSED: synthetic providers are incomplete or not bound to the private L0 route'
        }
    } else {
        if ($null -ne $script:D32NonSourceL1CallerAdapter -or $null -ne $script:D32NonSourceL1OuterNativeAdapter) {
            throw 'D32_NON_SOURCE_L1_REFUSED: production route received a synthetic caller/native provider'
        }
        $script:D32NonSourceL1Now = { [Diagnostics.Stopwatch]::GetTimestamp() }
    }
    $script:D32NonSourceL1BatchDeadline = Get-D32NonSourceL1DeadlineTicks -T0Ticks $t0 -Frequency $frequency -Milliseconds 60000L
    $script:D32NonSourceL1Opened = [System.Collections.Generic.List[object]]::new()
    $script:D32NonSourceL1OwnedBuffers = 0L; $script:D32NonSourceL1RuntimeContext = $null
    $script:D32NonSourceL1RuntimeAuthorityElement = $null; $script:D32NonSourceL1ModuleImportOrder = [System.Collections.Generic.List[string]]::new()
    $script:D32LifecycleFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
    $prepared = $null; $owned = $null; $authority = $null; $authorityRef = $null; $prelaunchRef = $null
    $callerError = $null; $secondary = [System.Collections.Generic.List[string]]::new(); $returnCode = 87
    $stdoutBytes = [byte[]]::new(0); $stderrBytes = [byte[]]::new(0); $innerResultRef = $null; $innerJournalRef = $null
    $runtimeAdmissionRefs = [object[]]@($null,$null,$null); $cleanupState = 'NOT_REQUIRED'; $jobActive = $null; $jobTotal = $null
    $outerProcessAttempted = $false; $outerProcessId = $null; $outerCreation = $null; $outerAssigned = $false; $outerResumed = $false; $outerExit = $null
    $captured = $false; $attempted = $false; $outerHandlesClosed = $true; $outerControllerClosed = $false; $outerCleanupFailureKnown = $false
    $callerOutputsValidated = $false; $outerPreparationAttempted = $false
    $outerBindingSha256 = $null
    try {
        if (-not $FixedOuterCaller.IsPresent -or $PSVersionTable.PSVersion -lt [version]'7.5' -or -not [Environment]::Is64BitProcess -or
            $CandidateSha -cnotmatch '^[0-9a-f]{40}$' -or $ExpectedL1AuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [IO.Path]::GetFullPath($Repository) -cne $Repository -or [IO.Path]::GetFullPath($L1AuthorityPath) -cne $L1AuthorityPath -or
            -not (Test-D32NonSourceL1NoReparsePath -Path $L1AuthorityPath)) { throw 'D32_NON_SOURCE_L1_REFUSED: fixed trusted-caller candidate/repository/authority startup input is invalid' }
        $initial = Get-D32NonSourceL1InitialReferenceBytes -Path $L1AuthorityPath -MaximumBytes 1048576 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1OwnedBuffers += [Int64]$initial.Reference.bytes
        if ($initial.Reference.sha256 -cne $ExpectedL1AuthoritySha256 -or $script:D32NonSourceL1OwnedBuffers -gt 16777216) { throw 'D32_NON_SOURCE_L1_REFUSED: fixed caller authority SHA or bootstrap buffer bound mismatch' }
        $authorityDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$initial.Bytes))
        try {
            if ($authorityDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32LifecycleJsonDuplicates -Element $authorityDocument.RootElement)) { throw 'D32_NON_SOURCE_L1_REFUSED: authority is not strict unique-key JSON' }
            $authority = ConvertFrom-D32LifecycleJsonElement -Element $authorityDocument.RootElement
        } finally { $authorityDocument.Dispose() }
        $modulePath = [IO.Path]::GetFullPath([IO.Path]::Combine($Repository,'scripts/d32-powershell-module-authority.ps1'))
        $modulePin = Get-D32NonSourceL1UniquePinnedPath -Pins @($authority.source_pins) -Path $modulePath
        if ($null -eq $modulePin) { throw 'D32_NON_SOURCE_L1_REFUSED: fixed module-free authority source pin is absent' }
        $moduleRaw = Get-D32NonSourceL1InitialReferenceBytes -Path $modulePath -MaximumBytes 16777216 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1OwnedBuffers += [Int64]$moduleRaw.Reference.bytes
        foreach ($name in @('path','bytes','sha256')) { if ([string]$moduleRaw.Reference.$name -cne [string]$modulePin.$name) { throw 'D32_NON_SOURCE_L1_REFUSED: module-free authority source content pin mismatch' } }
        if ($script:D32NonSourceL1OwnedBuffers -gt 16777216) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: caller bootstrap input bytes exceed the fixed buffer cap' }
        . ([ScriptBlock]::Create([Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$moduleRaw.Bytes)))
        $authorityOpened = Open-D32NonSourceL1AuthorityRecord -Path $L1AuthorityPath -DirectoryFences $script:D32LifecycleFences -MaximumBytes 1048576 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1Opened.Add($authorityOpened)
        foreach ($name in @('path','bytes','sha256')) { if ([string]$authorityOpened.Record.$name -cne [string]$initial.Reference.$name) { throw 'D32_NON_SOURCE_L1_REFUSED: secure authority reopen differs from caller-pinned bytes' } }
        $authorityRef = Get-D32NonSourceL1ReferenceFromOpened -Opened $authorityOpened
        $authorityDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$authorityOpened.Bytes))
        try {
            if ($authorityDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $authorityDocument.RootElement)) { throw 'D32_NON_SOURCE_L1_REFUSED: secure authority reopen contains malformed JSON' }
            $authority = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $authorityDocument.RootElement
        } finally { $authorityDocument.Dispose() }
        $policyPath = [IO.Path]::GetFullPath([IO.Path]::Combine($Repository,'scripts/d32-bounded-compiler-diagnostic-policy.ps1'))
        $policyPin = Get-D32NonSourceL1UniquePinnedPath -Pins @($authority.source_pins) -Path $policyPath
        if ($null -eq $policyPin) { throw 'D32_NON_SOURCE_L1_REFUSED: fixed strict policy pin is absent' }
        $policyOpened = Open-D32NonSourceL1AuthorityRecord -Path $policyPath -DirectoryFences $script:D32LifecycleFences -MaximumBytes 16777216 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1Opened.Add($policyOpened); $script:D32NonSourceL1OwnedBuffers += [Int64]$policyOpened.Record.bytes
        foreach ($name in @('bytes','sha256','volume_serial_hex','file_id_hex')) { if ([string]$policyOpened.Record.$name -cne [string]$policyPin.$name) { throw 'D32_NON_SOURCE_L1_REFUSED: pinned strict policy bytes/identity mismatch' } }
        if ($script:D32NonSourceL1OwnedBuffers -gt 16777216) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: caller pinned policy inputs exceed the fixed buffer cap' }
        . ([ScriptBlock]::Create([Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$policyOpened.Bytes)))
        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $authority -ExpectedCandidateSha $CandidateSha -Repository $Repository) -or
            [string]$authority.source_repo -cne $Repository -or [string]$authority.source_pins[0].path -cne (Get-D32NonSourceL1CurrentControllerPath) -or
            [string]$authority.outer_caller.entry_reference.path -cne [string]$authority.source_pins[0].path -or
            [string]$authority.outer_caller.observer_host_reference.path -cne [string]$authority.powershell_runtime.path -or
            [string]$authority.outer_caller.observer_process.image_reference.path -cne [string]$authority.powershell_runtime.path -or
            [string]$authorityRef.path -cne $L1AuthorityPath -or [string]$authorityRef.sha256 -cne $ExpectedL1AuthoritySha256) {
            throw 'D32_NON_SOURCE_L1_REFUSED: strict authority/candidate/source/outer-caller binding failed'
        }
        foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
            if ([string]$authority.outer_caller.observer_host_reference.$name -cne [string]$authority.powershell_runtime.$name -or
                [string]$authority.outer_caller.observer_process.image_reference.$name -cne [string]$authority.powershell_runtime.$name) {
                throw 'D32_NON_SOURCE_L1_REFUSED: observer host/process image refs differ from the pinned PowerShell runtime image'
            }
        }
        $runtimeRaw = Open-D32NonSourceL1AuthorityRecord -Path ([string]$authority.runtime_authority.path) -DirectoryFences $script:D32LifecycleFences -MaximumBytes 4194304 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1Opened.Add($runtimeRaw); $script:D32NonSourceL1OwnedBuffers += [Int64]$runtimeRaw.Record.bytes
        if ($script:D32NonSourceL1OwnedBuffers -gt 16777216) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: caller runtime candidate exceeds the fixed buffer cap' }
        $runtimeDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$runtimeRaw.Bytes))
        try {
            if ($runtimeDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $runtimeDocument.RootElement)) { throw 'D32_NON_SOURCE_L1_REFUSED: runtime content candidate JSON is malformed' }
            $script:D32NonSourceL1RuntimeAuthorityContent = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $runtimeDocument.RootElement
            $script:D32NonSourceL1RuntimeAuthorityElement = $runtimeDocument.RootElement.Clone()
        } finally { $runtimeDocument.Dispose() }
        $script:D32NonSourceL1RuntimeAuthorityOpenedReference = Get-D32NonSourceL1ReferenceFromOpened -Opened $runtimeRaw
        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeContentAuthorityBinding -Document $script:D32NonSourceL1RuntimeAuthorityContent `
                -Authority $authority -OpenedReference $script:D32NonSourceL1RuntimeAuthorityOpenedReference)) { throw 'D32_NON_SOURCE_L1_REFUSED: caller runtime-content candidate is not independently bound' }
        for ($index=0; $index -lt 6; $index++) {
            $pin = $authority.source_pins[$index]
            $opened = Open-D32NonSourceL1AuthorityRecord -Path ([string]$pin.path) -DirectoryFences $script:D32LifecycleFences -MaximumBytes 16777216 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
            $script:D32NonSourceL1Opened.Add($opened); $script:D32NonSourceL1OwnedBuffers += [Int64]$opened.Record.bytes
            foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) { if ([string]$opened.Record.$name -cne [string]$pin.$name) { throw 'D32_NON_SOURCE_L1_REFUSED: one of the six fixed candidate source pins drifted' } }
        }
        if ($script:D32NonSourceL1OwnedBuffers -gt 16777216) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: six fixed source/runtime buffers exceed the exact 16 MiB cap' }
        if ([string]$authority.owner_id -cne (Get-D32NonSourceL1CurrentOwnerSid)) { throw 'D32_NON_SOURCE_L1_REFUSED: actual trusted observer owner differs from the authority owner SID' }
        $repoIdentity = Get-D32NonSourceL1ModuleAuthorityDirectoryIdentity -Path $Repository
        if ($repoIdentity.VolumeSerialHex -cne [string]$authority.repository_identity.volume_serial_hex -or $repoIdentity.FileIdHex -cne [string]$authority.repository_identity.file_id_hex) { throw 'D32_NON_SOURCE_L1_REFUSED: actual source repository identity differs from the authority' }
        $rootIdentity = Get-D32NonSourceL1ModuleAuthorityDirectoryIdentity -Path ([string]$authority.output.root_path)
        $parentIdentity = Get-D32NonSourceL1ModuleAuthorityDirectoryIdentity -Path ([string]$authority.output.parent_path)
        $rootSecurity = Get-D32NonSourceL1RootSecurity -Path ([string]$authority.output.root_path)
        if ($rootIdentity.VolumeSerialHex -cne [string]$authority.output.root_volume_serial_hex -or $rootIdentity.FileIdHex -cne [string]$authority.output.root_file_id_hex -or
            $parentIdentity.VolumeSerialHex -cne [string]$authority.output.parent_volume_serial_hex -or $parentIdentity.FileIdHex -cne [string]$authority.output.parent_file_id_hex -or
            -not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RootSecurity -Security $rootSecurity -OwnerSid ([string]$authority.owner_id))) {
            throw 'D32_NON_SOURCE_L1_REFUSED: caller root/parent identity or owner-bound ACL changed'
        }
        foreach ($path in @($authority.output.outer_prelaunch_path,$authority.output.controller_runtime_admission_path,$authority.output.normalreader_runtime_admission_path,
                $authority.output.forcedreader_runtime_admission_path,$authority.output.caller_outcome_path,$authority.output.caller_journal_path,
                $authority.output.stdout_path,$authority.output.stderr_path,$authority.output.result_path,$authority.output.journal_path)) {
            if (Test-D32NonSourceL1OutputPathExists -Path ([string]$path)) { throw 'D32_NON_SOURCE_L1_REFUSED: one or more fixed create-new outputs already exist' }
        }
        $callerOutputsValidated = $true
        $processFacts = Get-D32NonSourceL1CurrentProcessFacts
        $callerPid = [Int64]$processFacts.process_id
        $callerCreation = [Int64]$processFacts.creation_filetime_ticks
        $callerImage = [IO.Path]::GetFullPath([string]$processFacts.image_path)
        $observer = $authority.outer_caller.observer_process
        if ($callerPid -ne [Int64]$observer.process_id -or $callerCreation -ne [Int64]$observer.creation_filetime_ticks -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals($callerImage,[string]$observer.image_reference.path)) { throw 'D32_NON_SOURCE_L1_REFUSED: actual trusted observer PID/creation/image differs from the caller pin' }
        $observerImageOpened = Open-D32NonSourceL1AuthorityRecord -Path $callerImage -DirectoryFences $script:D32LifecycleFences -MaximumBytes 268435456 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1Opened.Add($observerImageOpened); $script:D32NonSourceL1OwnedBuffers += [Int64]$observerImageOpened.Record.bytes
        foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
            if ([string]$observerImageOpened.Record.$name -cne [string]$observer.image_reference.$name -or
                [string]$observerImageOpened.Record.$name -cne [string]$authority.outer_caller.observer_host_reference.$name) {
                throw 'D32_NON_SOURCE_L1_REFUSED: actual trusted observer image opened identity/content differs from its external pins'
            }
        }
        if ($script:D32NonSourceL1OwnedBuffers -gt 16777216) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: trusted observer image pushes owned input buffers over the fixed cap' }
        $token = Get-D32NonSourceL1CurrentTokenFacts
        $actualHighIntegrity = [Int64]$token.integrity_rid -ge 0x3000
        if ($token.is_elevated -or $actualHighIntegrity -or $token.is_system -or $token.thread_impersonating -or
            [bool]$observer.ordinary_token.elevated -ne [bool]$token.is_elevated -or
            [bool]$observer.ordinary_token.high_integrity -ne [bool]$actualHighIntegrity -or
            [bool]$observer.ordinary_token.system_token -ne [bool]$token.is_system -or
            [bool]$observer.ordinary_token.thread_impersonation -ne [bool]$token.thread_impersonating) {
            throw 'D32_NON_SOURCE_L1_REFUSED: trusted observer token differs from the pin or is elevated, high-integrity, system, or impersonating'
        }
        $startup = Get-D32NonSourceL1CurrentStartupFacts -EntryScriptPath ([string]$authority.source_pins[0].path)
        if ($startup.FileOperand -cne [string]$authority.source_pins[0].path) { throw 'D32_NON_SOURCE_L1_REFUSED: trusted observer startup is not direct pinned -File execution' }
        $preImportContext = Get-D32NonSourceL1RuntimeContext -Authority $authority -DeadlineTicks $script:D32NonSourceL1BatchDeadline -PreImportOnly
        $loadedModules = [string[]](Get-D32NonSourceL1LoadedModuleNames)
        if ($loadedModules.Count -ne 0) { throw 'D32_NON_SOURCE_L1_REFUSED: trusted observer loaded a module before prelaunch admission' }
        Initialize-D32NonSourceL1ControllerRuntime -PreImportContext $preImportContext
        $script:D32NonSourceL1RuntimeContext = Get-D32NonSourceL1RuntimeContext -Authority $authority -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $environmentEntries = [string[]](Get-D32BoundedDiagnosticSourceProofNonSourceL1EnvironmentEntries -Environment $authority.invocation.child_environment)
        $vector = [string[]](Get-D32NonSourceL1OuterControllerVector -Authority $authority -AuthorityReference $authorityRef -T0Ticks $t0)
        $outerPreparationAttempted = $true
        $outerHandlesClosed = $false
        $prepared = New-D32NonSourceL1OuterControllerPreparation -Image ([string]$authority.powershell_runtime.path) -Arguments $vector `
            -WorkingDirectory ([string]$authority.output.root_path) -EnvironmentEntries $environmentEntries
        $imageReference = Get-D32NonSourceL1ReferenceFromOpened -Opened $observerImageOpened
        $processRecord = [PSCustomObject][ordered]@{process_id=$callerPid;creation_filetime_ticks=$callerCreation;image_reference=$imageReference
            ordinary_token=[PSCustomObject][ordered]@{elevated=[bool]$token.is_elevated;high_integrity=([Int64]$token.integrity_rid -ge 0x3000)
                system_token=[bool]$token.is_system;thread_impersonation=[bool]$token.thread_impersonating}}
        $invocation = $prepared.Owned.Invocation
        $observation = [PSCustomObject][ordered]@{
            caller_process=$processRecord;environment_entries=@($invocation.EnvironmentEntries)
            clock=[PSCustomObject][ordered]@{counter_origin='QueryPerformanceCounter';frequency=$frequency;batch_t0_ticks=$t0}
            standard_handles=[PSCustomObject][ordered]@{
                stdin=[PSCustomObject][ordered]@{role='stdin:NUL';access='READ_ONLY';inheritable=[bool]$invocation.StdinInheritable}
                stdout_write=[PSCustomObject][ordered]@{role='stdout:PIPE_WRITE';access='PIPE_WRITE';inheritable=[bool]$invocation.StdoutWriteInheritable}
                stderr_write=[PSCustomObject][ordered]@{role='stderr:PIPE_WRITE';access='PIPE_WRITE';inheritable=[bool]$invocation.StderrWriteInheritable}
                stdout_read=[PSCustomObject][ordered]@{role='stdout:PIPE_READ';access='PIPE_READ';inheritable=[bool]$invocation.StdoutReadInheritable}
                stderr_read=[PSCustomObject][ordered]@{role='stderr:PIPE_READ';access='PIPE_READ';inheritable=[bool]$invocation.StderrReadInheritable}}
            ambient_handles_proven_none=[bool]$prepared.AmbientHandleInheritanceRestricted;creation_flags=[Int64]$invocation.CreationFlags
            startup_info=[PSCustomObject][ordered]@{extended_startupinfo=([bool]($invocation.CreationFlags -band 0x00080000));handle_list_applied=[bool]$invocation.HandleListApplied;handle_roles=@($invocation.HandleRoles)}
            outer_job=[PSCustomObject][ordered]@{policy='CALLER_OWNED_NESTED_JOB_V1';active_process_limit=2L
                kill_on_close=[bool]$prepared.Owned.JobKillOnClose;non_breakaway=[bool]$prepared.Owned.JobActiveProcessLimitTwo}
            namespace_witness=$script:D32NonSourceL1RuntimeContext.namespace_witness}
        $prelaunch = New-D32NonSourceL1OuterPrelaunchRecord -Authority $authority -AuthorityReference $authorityRef -Observation $observation -T0Ticks $t0 -CounterFrequency $frequency
        $bound = Set-D32BoundedDiagnosticSourceProofOuterPrelaunchBinding -Record $prelaunch
        $outerBindingSha256 = [string]$bound.binding_sha256
        $prelaunchBytes = ConvertTo-D32BoundedDiagnosticSourceProofCanonicalJsonBytes -Value $bound.record
        if ($prelaunchBytes.Length -gt 65536) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: outer prelaunch exceeds 64 KiB' }
        $prelaunchRef = Write-D32NonSourceL1CallerArtifact -Path ([string]$authority.output.outer_prelaunch_path) -Bytes $prelaunchBytes -Purpose OUTER_PRELAUNCH -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $reopened = Open-D32NonSourceL1OuterPrelaunchRecord -Authority $authority -AuthorityReference $authorityRef -ExpectedBindingSha256 ([string]$bound.binding_sha256) -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $prelaunchRef = $reopened.reference
        if ($null -ne $script:D32NonSourceL1CallerAdapter) {
            if ($null -eq $script:D32NonSourceL1CallerAdapter.RefuseRealRoute -or
                [bool](& $script:D32NonSourceL1CallerAdapter.RefuseRealRoute -BindingSha256 ([string]$bound.binding_sha256))) {
                throw 'D32_NON_SOURCE_L1_REFUSED: synthetic caller did not refuse a real native route'
            }
        }
        Bind-D32NonSourceL1OuterControllerCommandLine -Prepared $prepared -Vector ([string[]]$reopened.record.controller.arguments.vector) `
            -CommandLine ([string]$reopened.record.controller.arguments.command_line) -BindingSha256 ([string]$bound.binding_sha256)
        if ((Get-D32NonSourceL1Now) -ge $script:D32NonSourceL1BatchDeadline) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: outer controller creation cutoff reached before its sole attempt' }
        $attempted = $true
        $owned = Start-D32NonSourceL1OuterController -Prepared $prepared -CommandLine ([string]$reopened.record.controller.arguments.command_line) `
            -T0Ticks $t0 -Frequency $frequency -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $prepared = $null
        $outerProcessAttempted = [bool]$owned.CreateProcessAttempted; $outerProcessId = if ($owned.ProcessId -gt 0) { [Int64]$owned.ProcessId } else { $null }
        $outerCreation = if ($owned.CreationFileTime -gt 0) { [Int64]$owned.CreationFileTime } else { $null }
        $outerAssigned = [bool]$owned.Assigned; $outerResumed = [bool]$owned.Resumed
        $now = Get-D32NonSourceL1Now; $remainingTicks = [Math]::Max([Int64]0,([Int64]$script:D32NonSourceL1BatchDeadline-$now))
        $waitMs = [int][Math]::Min(60000,[Math]::Ceiling(([double]$remainingTicks*1000.0)/[double]$frequency))
        $signaled = Wait-D32NonSourceL1OuterController -Owned $owned -Milliseconds $waitMs
        if (-not $signaled -and $owned.Job -ne [IntPtr]::Zero) {
            $cleanupState = if (Stop-D32NonSourceL1OuterJob -Owned $owned -ExitCode 0xD3205001) { 'OWNED_JOB_TERMINATION_REQUESTED' } else { 'UNRESOLVED' }
            $now = Get-D32NonSourceL1Now; $remainingTicks = [Math]::Max([Int64]0,([Int64]$script:D32NonSourceL1BatchDeadline-$now))
            $cleanupWait = [int][Math]::Min(15000,[Math]::Ceiling(([double]$remainingTicks*1000.0)/[double]$frequency))
            $signaled = Wait-D32NonSourceL1OuterController -Owned $owned -Milliseconds $cleanupWait
        }
        if ($signaled) { $outerExit = Get-D32NonSourceL1OuterControllerExitCode -Owned $owned }
        $jobActive = Get-D32NonSourceL1OuterJobActiveProcesses -Owned $owned; $jobTotal = Get-D32NonSourceL1OuterJobTotalProcesses -Owned $owned
        $now = Get-D32NonSourceL1Now; $remainingTicks = [Math]::Max([Int64]0,([Int64]$script:D32NonSourceL1BatchDeadline-$now))
        $joinMs = [int][Math]::Min(15000,[Math]::Ceiling(([double]$remainingTicks*1000.0)/[double]$frequency))
        $joined = Join-D32NonSourceL1OuterCaptures -Owned $owned -Milliseconds $joinMs
        if ($null -ne $owned.Stdout) { $stdoutBytes=[byte[]]$owned.Stdout.Prefix.ToArray() }
        if ($null -ne $owned.Stderr) { $stderrBytes=[byte[]]$owned.Stderr.Prefix.ToArray() }
        $captured = [bool]($joined -and $null -ne $owned.Stdout -and $owned.Stdout.Complete -and $null -ne $owned.Stderr -and $owned.Stderr.Complete -and
            -not $owned.Stdout.Truncated -and -not $owned.Stderr.Truncated -and $stdoutBytes.Length -le 16000 -and $stderrBytes.Length -le 16000)
        if ($null -ne $owned.Failure) { $callerError = Get-D32NonSourceL1ErrorText -Exception ([InvalidOperationException]::new([string]$owned.Failure)) }
        $closeReturned = Close-D32NonSourceL1OuterController -Owned $owned
        $outerHandlesClosed = [bool]($closeReturned -and $owned.Job -eq [IntPtr]::Zero -and $owned.Process -eq [IntPtr]::Zero -and
            $owned.Thread -eq [IntPtr]::Zero -and $owned.StdoutRead -eq [IntPtr]::Zero -and $owned.StderrRead -eq [IntPtr]::Zero -and
            [bool]$owned.JobClosedByNative)
        $outerControllerClosed = $outerHandlesClosed
        if (-not $signaled -or -not $joined -or -not $captured -or $null -eq $outerExit -or $null -eq $jobActive -or $null -eq $jobTotal) {
            if (-not $callerError) { $callerError='D32_NON_SOURCE_L1_UNRESOLVED: outer controller wait/capture/job accounting is incomplete' }
            $cleanupState = 'UNRESOLVED'
        } elseif ($jobActive -ne 0 -or -not $owned.Assigned -or -not $owned.Resumed -or -not $owned.TemporaryHandlesClosed -or -not $outerHandlesClosed) {
            $callerError='D32_NON_SOURCE_L1_UNRESOLVED: outer controller assignment/resume/Job cleanup was not fully observed'; $cleanupState='UNRESOLVED'
        } else { $cleanupState='OWNED_JOB_QUIESCENT_CAPTURE_JOINED_HANDLES_CLOSED' }
        $stdoutRef = Write-D32NonSourceL1CallerArtifact -Path ([string]$authority.output.stdout_path) -Bytes $stdoutBytes -Purpose CALLER_CAPTURE -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $stderrRef = Write-D32NonSourceL1CallerArtifact -Path ([string]$authority.output.stderr_path) -Bytes $stderrBytes -Purpose CALLER_CAPTURE -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        if ($outerExit -eq 0 -and $captured -and $cleanupState -ceq 'OWNED_JOB_QUIESCENT_CAPTURE_JOINED_HANDLES_CLOSED') {
            $resultOpened = Open-D32NonSourceL1PersistedOutput -Path ([string]$authority.output.result_path) -DirectoryFences $script:D32LifecycleFences -MaximumBytes 65536 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
            $journalOpened = Open-D32NonSourceL1PersistedOutput -Path ([string]$authority.output.journal_path) -DirectoryFences $script:D32LifecycleFences -MaximumBytes 65536 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
            try {
                $resultDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$resultOpened.Bytes))
                try {
                    if ($resultDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $resultDocument.RootElement)) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: inner result contains duplicate or non-object JSON' }
                    $innerResult = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $resultDocument.RootElement
                } finally { $resultDocument.Dispose() }
                $journalText = [Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$journalOpened.Bytes)
                $journalLines = @($journalText.Split("`n",[StringSplitOptions]::RemoveEmptyEntries))
                if ($journalLines.Count -lt 1 -or $journalLines.Count -gt 64) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: inner journal line count is outside its fixed bound' }
                $lastFactDocument = [System.Text.Json.JsonDocument]::Parse([string]$journalLines[$journalLines.Count-1])
                try {
                    if ($lastFactDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                        (Test-D32PowerShellAuthorityJsonDuplicates -Element $lastFactDocument.RootElement)) {
                        throw 'D32_NON_SOURCE_L1_UNRESOLVED: inner journal final fact is malformed'
                    }
                    $lastFact = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $lastFactDocument.RootElement
                } finally { $lastFactDocument.Dispose() }
                if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape $innerResult) -or
                    [string]$innerResult.status -cne 'COMPLETE_NON_SOURCE_L1' -or
                    [string]$lastFact.event -cne 'L1_RESULT_PERSISTED' -or [string]$lastFact.result_path -cne [string]$authority.output.result_path -or
                    [string]$lastFact.result_sha256 -cne [string]$resultOpened.Record.sha256 -or [Int64]$lastFact.result_bytes -ne [Int64]$resultOpened.Record.bytes) {
                    throw 'D32_NON_SOURCE_L1_UNRESOLVED: inner result/journal did not reconcile as complete'
                }
                $innerResultRef=$resultOpened.Record; $innerJournalRef=$journalOpened.Record
                $runtimeAdmissionRefs = [object[]]@($innerResult.runtime_admissions | ForEach-Object { $_.reference })
            } finally { if ($null -ne $resultOpened.Stream) {$resultOpened.Stream.Dispose()}; if ($null -ne $journalOpened.Stream) {$journalOpened.Stream.Dispose()} }
        }
        if ($null -ne $callerError) { $script:D32NonSourceL1Status='BLOCKED'; $returnCode=87 }
        elseif ($null -ne $innerResultRef -and $cleanupState -ceq 'OWNED_JOB_QUIESCENT_CAPTURE_JOINED_HANDLES_CLOSED') { $script:D32NonSourceL1Status='COMPLETE_NON_SOURCE_L1'; $returnCode=0 }
        else { $script:D32NonSourceL1Status='UNRESOLVED'; $callerError='D32_NON_SOURCE_L1_UNRESOLVED: child did not return a complete, reconciled result'; $returnCode=87 }
        $completed = Get-D32NonSourceL1Now
        $outcome = [PSCustomObject][ordered]@{
            schema_version=1;record_type='D32_NON_SOURCE_L1_CALLER_OUTCOME_V1';purpose='NON_SOURCE_L1_CALLER_OUTCOME_ONLY';gate_authority='NONE'
            candidate_sha=$authority.candidate_sha;batch_id=$authority.batch_id;run_id=$authority.run_id;status=$script:D32NonSourceL1Status;execution_mode='FIXED_NATIVE_OUTER_CALLER_V1'
            outer_prelaunch_reference=$prelaunchRef
            controller=[PSCustomObject][ordered]@{native_create_attempted=[bool]$outerProcessAttempted;process_id=$outerProcessId;creation_filetime_ticks=$outerCreation
                assigned=[bool]$outerAssigned;resumed=[bool]$outerResumed;exit_code=$outerExit;job_active_process_count=$jobActive;job_total_process_count=$jobTotal
                handles_closed=[bool]$outerHandlesClosed;cleanup_state=$cleanupState}
            captures=[PSCustomObject][ordered]@{stdout_reference=$stdoutRef;stderr_reference=$stderrRef;stdout_bytes=[Int64]$stdoutBytes.Length;stderr_bytes=[Int64]$stderrBytes.Length
                stdout_sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stdoutBytes)).ToLowerInvariant();stderr_sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stderrBytes)).ToLowerInvariant()
                stdout_truncated=[bool]($null -ne $owned -and $owned.Stdout.Truncated);stderr_truncated=[bool]($null -ne $owned -and $owned.Stderr.Truncated);transport='NATIVE_BOUNDED_PIPE_CAPTURE';complete=[bool]$captured}
            runtime_admission_references=@($runtimeAdmissionRefs);inner_result_reference=$innerResultRef;inner_journal_reference=$innerJournalRef
            clock=[PSCustomObject][ordered]@{counter_origin='QueryPerformanceCounter';frequency=$frequency;batch_t0_ticks=$t0;completed_ticks=$completed}
            primary_error=$callerError;secondary_errors=@($secondary.ToArray())}
        $outcomeBytes=ConvertTo-D32BoundedDiagnosticSourceProofCanonicalJsonBytes -Value $outcome
        $outcomeRef=Write-D32NonSourceL1CallerArtifact -Path ([string]$authority.output.caller_outcome_path) -Bytes $outcomeBytes -Purpose CALLER_OUTCOME -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $journalRecord=[PSCustomObject][ordered]@{schema_version=1;record_type='D32_NON_SOURCE_L1_CALLER_JOURNAL_V1';purpose='NON_SOURCE_L1_CALLER_JOURNAL_ONLY'
            gate_authority='NONE';candidate_sha=$authority.candidate_sha;batch_id=$authority.batch_id;run_id=$authority.run_id;event='CALLER_OUTCOME_PERSISTED'
            outcome_reference=$outcomeRef;submission='CALLER_OUTCOME_REOPENED';controller_return_code=$returnCode;observed_ticks=(Get-D32NonSourceL1Now)}
        $json=ConvertTo-D32BoundedDiagnosticSourceProofCanonicalJsonBytes -Value $journalRecord
        $journalBytes=[byte[]]::new($json.Length+1);[Array]::Copy($json,$journalBytes,$json.Length);$journalBytes[$journalBytes.Length-1]=10
        $null=Write-D32NonSourceL1CallerArtifact -Path ([string]$authority.output.caller_journal_path) -Bytes $journalBytes -Purpose CALLER_JOURNAL -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        if (-not (Test-D32NonSourceL1ProductionCallerReconciliation -Authority $authority -AuthorityReference $authorityRef -PrelaunchReference $prelaunchRef `
                -ExpectedStatus $script:D32NonSourceL1Status -T0Ticks $t0 -Frequency $frequency -ControllerReturnCode $returnCode)) {
            throw 'D32_NON_SOURCE_L1_UNRESOLVED: production caller strict outcome/journal/capture reopen failed'
        }
    } catch {
        $callerError = Get-D32NonSourceL1ErrorText -Exception $_.Exception
        try { $DiagnosticWriter.WriteLine(('D32_NON_SOURCE_L1 status=REFUSED primary=' + $callerError)); $DiagnosticWriter.Flush() } catch {}
        $returnCode = 87
    } finally {
        if ($null -ne $prepared) {
            try {
                $outerHandlesClosed = [bool](Close-D32NonSourceL1OuterPreparation -Prepared $prepared)
                if (-not $outerHandlesClosed) { $outerCleanupFailureKnown=$true }
            }
            catch { $outerHandlesClosed=$false; $cleanupState='UNRESOLVED'; $returnCode=87 }
        }
        if ($null -ne $owned -and -not $outerControllerClosed) {
            try {
                $stillRunning = -not (Wait-D32NonSourceL1OuterController -Owned $owned -Milliseconds 0)
                if ($owned.Process -ne [IntPtr]::Zero -and $stillRunning) {
                    if ($owned.Assigned -and $owned.Job -ne [IntPtr]::Zero) { [void](Stop-D32NonSourceL1OuterJob -Owned $owned -ExitCode 0xD3205002) }
                    else { [void](Stop-D32NonSourceL1OuterProcess -Owned $owned -ExitCode 0xD3205003) }
                    $now=Get-D32NonSourceL1Now; $remaining=[int][Math]::Min(15000,[Math]::Max(0,[Math]::Ceiling(([double]($script:D32NonSourceL1BatchDeadline-$now)*1000.0)/[double]$frequency)))
                    [void](Wait-D32NonSourceL1OuterController -Owned $owned -Milliseconds $remaining)
                }
                $closeOk = [bool](Close-D32NonSourceL1OuterController -Owned $owned)
                $outerHandlesClosed = $closeOk -and $owned.Job -eq [IntPtr]::Zero -and $owned.Process -eq [IntPtr]::Zero -and
                    $owned.Thread -eq [IntPtr]::Zero -and $owned.StdoutRead -eq [IntPtr]::Zero -and $owned.StderrRead -eq [IntPtr]::Zero -and
                    (-not $owned.JobCreated -or [bool]$owned.JobClosedByNative)
                $outerControllerClosed = $outerHandlesClosed
                if (-not $outerHandlesClosed) { $outerCleanupFailureKnown=$closeOk -eq $false; $cleanupState='UNRESOLVED'; $returnCode=87 }
            } catch { $outerHandlesClosed=$false; $cleanupState='UNRESOLVED'; $returnCode=87 }
        }
    }
    $processCreated = $null -ne $owned -and ($owned.Process -ne [IntPtr]::Zero -or $owned.ProcessId -gt 0)
    if ($callerOutputsValidated -and $null -ne $authority -and $null -ne $authorityRef -and -not $processCreated) {
        $noCreateStatus = if ($outerHandlesClosed) { 'REFUSED' } elseif ($outerCleanupFailureKnown) { 'BLOCKED' } else { 'UNRESOLVED' }
        $nativeCreateWasAttempted = [bool]($null -ne $owned -and $owned.CreateProcessAttempted)
        if ($null -eq $callerError) { $callerError='D32_NON_SOURCE_L1_REFUSED: fixed outer caller stopped before controller creation' }
        try {
            $null = Write-D32NonSourceL1ProductionNoCreateRefusal -Authority $authority -AuthorityReference $authorityRef `
                -T0Ticks $t0 -Frequency $frequency -DeadlineTicks $script:D32NonSourceL1BatchDeadline -PrimaryError $callerError `
                -Status $noCreateStatus -NativeCreateAttempted $nativeCreateWasAttempted -HandlesClosed $outerHandlesClosed `
                -PrelaunchReference $prelaunchRef -ExpectedBindingSha256 $outerBindingSha256
            $script:D32NonSourceL1Status = $noCreateStatus
        } catch { $secondary.Add((Get-D32NonSourceL1ErrorText -Exception $_.Exception)); $script:D32NonSourceL1Status='UNRESOLVED'; $returnCode=87 }
    }
    foreach ($opened in $script:D32NonSourceL1Opened) { try { if ($null -ne $opened.Stream -and -not $opened.Stream.SafeFileHandle.IsClosed) { $opened.Stream.Dispose() } } catch { $returnCode=87 } }
    foreach ($fence in $script:D32LifecycleFences.Values) { try { if ($null -ne $fence.Handle -and -not $fence.Handle.IsClosed) { $fence.Handle.Dispose() } } catch { $returnCode=87 } }
    return [int]$returnCode
}

function Invoke-D32NonSourceL1FixedOuterCaller {
    param([Parameter(Mandatory = $true)][System.IO.TextWriter]$DiagnosticWriter)
    return Invoke-D32NonSourceL1ProductionOuterCaller -DiagnosticWriter $DiagnosticWriter
}

function Open-D32NonSourceL1PersistedOutput {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences,
        [Parameter(Mandatory = $true)][long]$MaximumBytes, [Parameter(Mandatory = $true)][long]$DeadlineTicks)
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
        return & $script:D32NonSourceL1EnvironmentAdapter.OpenOutput -Path $Path -DirectoryFences $DirectoryFences -MaximumBytes $MaximumBytes -DeadlineTicks $DeadlineTicks
    }
    return Open-D32PowerShellAuthorityFile -Path $Path -DirectoryFences $DirectoryFences -MaximumBytes $MaximumBytes -DeadlineTicks $DeadlineTicks
}

function Open-D32NonSourceL1OuterPrelaunchRecord {
    param([Parameter(Mandatory = $true)][object]$Authority, [Parameter(Mandatory = $true)][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][string]$ExpectedBindingSha256, [Parameter(Mandatory = $true)][long]$DeadlineTicks)
    if ($ExpectedBindingSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'D32_NON_SOURCE_L1_REFUSED: outer-prelaunch binding input is malformed' }
    $path = [string]$Authority.output.outer_prelaunch_path
    $opened = Open-D32NonSourceL1PersistedOutput -Path $path -DirectoryFences $script:D32LifecycleFences -MaximumBytes 65536 -DeadlineTicks $DeadlineTicks
    try {
        $document = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$opened.Bytes))
        try {
            if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $document.RootElement)) {
                throw 'D32_NON_SOURCE_L1_REFUSED: outer-prelaunch JSON contains duplicate keys or a non-object root'
            }
            $record = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $document.RootElement
        } finally { $document.Dispose() }
        if ([Int64]$opened.Record.bytes -ne $opened.Bytes.Length -or
            [string]$opened.Record.sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$opened.Bytes)).ToLowerInvariant() -or
            [string]$record.record_type -cne 'D32_NON_SOURCE_L1_OUTER_PRELAUNCH_V1' -or
            [string]$record.purpose -cne 'NON_SOURCE_L1_OUTER_PRELAUNCH_ONLY' -or [string]$record.gate_authority -cne 'NONE' -or
            [string]$record.candidate_sha -cne [string]$Authority.candidate_sha -or [string]$record.batch_id -cne [string]$Authority.batch_id -or
            [string]$record.run_id -cne [string]$Authority.run_id -or
            [string]$record.authority_reference.path -cne [string]$AuthorityReference.path -or
            [string]$record.authority_reference.sha256 -cne [string]$AuthorityReference.sha256 -or
            [string]$record.runtime_authority_reference.path -cne [string]$Authority.runtime_authority.path -or
            -not (Test-D32BoundedDiagnosticSourceProofOuterPrelaunchBinding -Record $record -ExpectedBindingSha256 $ExpectedBindingSha256)) {
            throw 'D32_NON_SOURCE_L1_REFUSED: outer-prelaunch identity/candidate/reference/binding mismatch'
        }
        return [PSCustomObject][ordered]@{ record=$record; reference=$opened.Record }
    } finally { if ($null -ne $opened.Stream) { $opened.Stream.Dispose() } }
}

function Get-D32NonSourceL1ControllerCreationFileTime {
    if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) { return [Int64](& $script:D32NonSourceL1EnvironmentAdapter.ControllerCreationFileTime) }
    return Get-D32LifecycleProcessCreationFileTime
}

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
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-D32NonSourceL1UtilityJson -InputObject $fact -Depth 8) + "`n")
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
    $json = ConvertTo-D32NonSourceL1UtilityJson -InputObject $Record -Depth 32
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
    foreach ($secondary in $SecondaryErrors) {
        if ($secondaryIndex -ge 2) { break }
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
        '-L1CounterFrequency', [string](Get-D32NonSourceL1QpcFrequency), '-L1CaseT0Ticks', [string]$CaseT0Ticks,
        '-L1ActiveDeadlineTicks', [string]$ActiveDeadlineTicks,
        '-ExpectedOuterPrelaunchBindingSha256', [string]$ExpectedOuterPrelaunchBindingSha256,
        '-ExpectedControllerRuntimeAdmissionSha256', [string]$script:D32NonSourceL1RuntimeAdmissions[0].reference.sha256)
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
    $remaining = [decimal]($DeadlineTicks - $now) * [decimal]1000 / [decimal](Get-D32NonSourceL1QpcFrequency)
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
        counter_frequency = Get-D32NonSourceL1QpcFrequency; active_deadline_ticks = $ActiveDeadlineTicks
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
    $caseDeadlines = Get-D32BoundedDiagnosticSourceProofNonSourceL1CaseDeadlines -CaseT0Ticks $caseT0 -Frequency (Get-D32NonSourceL1QpcFrequency) -BatchDeadlineTicks $script:D32NonSourceL1BatchDeadline
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
            -CounterFrequency (Get-D32NonSourceL1QpcFrequency) -ActiveDeadlineTicks ([Int64]$active) -WorkDeadlineTicks ([Int64]$active)
        if ($native.Process -ne [IntPtr]::Zero) {
            $readerRole = if ($caseId -ceq 'NORMAL_EXIT') { 'NORMAL_READER' } else { 'FORCED_READER' }
            $readerSlotIndex = if ($readerRole -ceq 'NORMAL_READER') { 1 } else { 2 }
            $controllerSlot = $script:D32NonSourceL1RuntimeAdmissions[0]
            if ([string]$controllerSlot.status -cne 'ADMITTED' -or $null -eq $controllerSlot.admission -or $null -eq $controllerSlot.reference) {
                throw 'D32_NON_SOURCE_L1_UNRESOLVED: child runtime admission has no persisted controller parent'
            }
            $readerObservation = Get-D32NonSourceL1RuntimeObservation -Role $readerRole -Authority $script:D32NonSourceL1Authority `
                -ParentAdmission $controllerSlot.admission -Arguments ([string[]]$plan.arguments) -Native $native
            $readerOutputPath = if ($readerRole -ceq 'NORMAL_READER') { [string]$script:D32NonSourceL1Authority.output.normalreader_runtime_admission_path } `
                else { [string]$script:D32NonSourceL1Authority.output.forcedreader_runtime_admission_path }
            $readerSlot = New-D32NonSourceL1RuntimeAdmissionArtifact -Authority $script:D32NonSourceL1Authority `
                -AuthorityReference $script:D32NonSourceL1AuthorityReference -OuterPrelaunchReference $script:D32NonSourceL1OuterPrelaunchReference `
                -Role $readerRole -OutputPath $readerOutputPath -ParentAdmissionReference $controllerSlot.reference -ParentAdmission $controllerSlot.admission `
                -Observation $readerObservation -Arguments ([string[]]$plan.arguments) -T0Ticks $L1T0Ticks -DeadlineTicks $script:D32NonSourceL1BatchDeadline
            $script:D32NonSourceL1RuntimeAdmissions[$readerSlotIndex] = $readerSlot
        }
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
            $ExpectedOuterPrelaunchBindingSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $L1T0Ticks -le 0 -or (Get-D32NonSourceL1QpcFrequency) -le 0 -or
            $script:D32LifecycleControllerEntryTicks -lt $L1T0Ticks -or
            [IO.Path]::GetFullPath($Repository) -cne $Repository -or -not [IO.Path]::IsPathRooted($Repository) -or
            [IO.Path]::GetFullPath($L1AuthorityPath) -cne $L1AuthorityPath -or -not (Test-D32NonSourceL1NoReparsePath -Path $L1AuthorityPath)) {
            throw 'D32_NON_SOURCE_L1_REFUSED: fixed candidate/repository/runtime/caller clock input invalid'
        }
        if ($null -ne $script:D32NonSourceL1EnvironmentAdapter) {
            $script:D32NonSourceL1Now = { [Int64](& $script:D32NonSourceL1EnvironmentAdapter.Now) }
        } else { $script:D32NonSourceL1Now = { [Diagnostics.Stopwatch]::GetTimestamp() } }
        $frequency = Get-D32NonSourceL1QpcFrequency
        $script:D32NonSourceL1BatchDeadline = Get-D32NonSourceL1DeadlineTicks -T0Ticks $L1T0Ticks -Frequency $frequency -Milliseconds 60000L
        if ((Get-D32NonSourceL1Now) -lt $L1T0Ticks -or (Get-D32NonSourceL1Now) -ge $script:D32NonSourceL1BatchDeadline) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: controller admission reached batch deadline' }

        # Bootstrap bytes are read through managed, bounded streams. Their exact
        # caller SHA is checked before the pinned module-free identity reader is
        # loaded; opened identity is then established by that reader before any
        # authority input is admitted or process API is called.
        $authorityRaw = Get-D32NonSourceL1InitialReferenceBytes -Path $L1AuthorityPath -MaximumBytes 1048576 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
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
        $modulePath = [IO.Path]::GetFullPath([IO.Path]::Combine($Repository, 'scripts/d32-powershell-module-authority.ps1'))
        $modulePin = Get-D32NonSourceL1UniquePinnedPath -Pins @($script:D32NonSourceL1Authority.source_pins) -Path $modulePath
        if ($null -eq $modulePin) { throw 'D32_NON_SOURCE_L1_REFUSED: exact fixed authority loader pin absent' }
        $moduleRaw = Get-D32NonSourceL1InitialReferenceBytes -Path $modulePath -MaximumBytes 16777216 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1OwnedBuffers += [Int64]$moduleRaw.Reference.bytes
        foreach ($name in @('path','bytes','sha256')) { if ([string]$moduleRaw.Reference.($name) -cne [string]$modulePin[0].($name)) { throw 'D32_NON_SOURCE_L1_REFUSED: bootstrap loader content pin mismatch' } }
        if ($script:D32NonSourceL1OwnedBuffers -gt 16777216) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: fixed bootstrap buffers exceed 16 MiB' }
        . ([ScriptBlock]::Create([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$moduleRaw.Bytes)))
        if ($null -ne $moduleRaw.Stream) { $moduleRaw.Stream.Dispose(); $moduleRaw = $null }
        $script:D32LifecycleFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
        $authorityOpened = Open-D32NonSourceL1AuthorityRecord -Path $L1AuthorityPath -DirectoryFences $script:D32LifecycleFences -MaximumBytes 1048576 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1Opened.Add($authorityOpened)
        $script:D32NonSourceL1OwnedBuffers += [Int64]$authorityOpened.Record.bytes
        foreach ($name in @('path','bytes','sha256')) { if ([string]$authorityOpened.Record.($name) -cne [string]$authorityRawReference.($name)) { throw 'D32_NON_SOURCE_L1_REFUSED: authority secure reopen differs from the initial caller-pinned bytes' } }
        if ($script:D32NonSourceL1OwnedBuffers -gt 16777216) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: reopened authority buffer exceeds 16 MiB' }
        $authorityJson = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$authorityOpened.Bytes))
        try {
            if ($authorityJson.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $authorityJson.RootElement)) { throw 'D32_NON_SOURCE_L1_REFUSED: strict authority JSON duplicates or root shape invalid' }
            $script:D32NonSourceL1Authority = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $authorityJson.RootElement
        } finally { $authorityJson.Dispose() }
        $script:D32NonSourceL1AuthorityReference = Get-D32NonSourceL1ReferenceFromOpened -Opened $authorityOpened

        $policyPath = [IO.Path]::GetFullPath([IO.Path]::Combine($Repository, 'scripts/d32-bounded-compiler-diagnostic-policy.ps1'))
        $policyPin = Get-D32NonSourceL1UniquePinnedPath -Pins @($script:D32NonSourceL1Authority.source_pins) -Path $policyPath
        if ($null -eq $policyPin) { throw 'D32_NON_SOURCE_L1_REFUSED: fixed policy pin absent' }
        $policyOpened = Open-D32NonSourceL1AuthorityRecord -Path $policyPath -DirectoryFences $script:D32LifecycleFences -MaximumBytes 16777216 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1Opened.Add($policyOpened); $script:D32NonSourceL1OwnedBuffers += [Int64]$policyOpened.Record.bytes
        foreach ($name in @('bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ([string]$policyOpened.Record.($name) -cne [string]$policyPin[0].($name)) { throw 'D32_NON_SOURCE_L1_REFUSED: pinned strict L1 policy drifted' } }
        if ($script:D32NonSourceL1OwnedBuffers -gt 16777216) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: verified code buffers exceed 16 MiB' }
        . ([ScriptBlock]::Create([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$policyOpened.Bytes)))

        $runtimeAuthorityPath = [string]$script:D32NonSourceL1Authority.runtime_authority.path
        $runtimeAuthorityOpened = Open-D32NonSourceL1AuthorityRecord -Path $runtimeAuthorityPath `
            -DirectoryFences $script:D32LifecycleFences -MaximumBytes 4194304 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1Opened.Add($runtimeAuthorityOpened)
        $script:D32NonSourceL1OwnedBuffers += [Int64]$runtimeAuthorityOpened.Record.bytes
        if ($script:D32NonSourceL1OwnedBuffers -gt 16777216) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: runtime authority and fixed source buffers exceed 16 MiB' }
        $runtimeAuthorityJson = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$runtimeAuthorityOpened.Bytes))
        try {
            if ($runtimeAuthorityJson.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                (Test-D32PowerShellAuthorityJsonDuplicates -Element $runtimeAuthorityJson.RootElement)) {
                throw 'D32_NON_SOURCE_L1_REFUSED: runtime content authority JSON is duplicate or non-object'
            }
            $script:D32NonSourceL1RuntimeAuthorityContent = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $runtimeAuthorityJson.RootElement
            $script:D32NonSourceL1RuntimeAuthorityElement = $runtimeAuthorityJson.RootElement.Clone()
        } finally { $runtimeAuthorityJson.Dispose() }
        $script:D32NonSourceL1RuntimeAuthorityOpenedReference = Get-D32NonSourceL1ReferenceFromOpened -Opened $runtimeAuthorityOpened
        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeContentAuthorityBinding `
                -Document $script:D32NonSourceL1RuntimeAuthorityContent -Authority $script:D32NonSourceL1Authority `
                -OpenedReference $script:D32NonSourceL1RuntimeAuthorityOpenedReference)) {
            throw 'D32_NON_SOURCE_L1_REFUSED: runtime content candidate did not bind its independent file reference, repository, candidate, and runtime'
        }

        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $script:D32NonSourceL1Authority -ExpectedCandidateSha $CandidateSha -Repository $Repository) -or
            [string]$script:D32NonSourceL1Authority.source_pins[0].path -cne (Get-D32NonSourceL1CurrentControllerPath) -or
            [string]$script:D32NonSourceL1Authority.invocation.entry_path -cne [IO.Path]::GetFullPath([IO.Path]::Combine($Repository, 'scripts/d32-bounded-diagnostic-sourceproof.ps1')) -or
            (Test-D32PowerShellAuthorityPathWithin -Child $L1AuthorityPath -Parent $Repository) -or
            (Test-D32PowerShellAuthorityPathWithin -Child $L1AuthorityPath -Parent 'E:\d32\inv7\r\c') -or
            (Test-D32PowerShellAuthorityPathWithin -Child $L1AuthorityPath -Parent ([string]$script:D32NonSourceL1Authority.output.root_path))) {
            throw 'D32_NON_SOURCE_L1_REFUSED: strict L1 authority or fixed external role bindings failed'
        }
        if ([string]$script:D32NonSourceL1Authority.source_repo -cne $Repository -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$script:D32NonSourceL1Authority.powershell_runtime.path), [IO.Path]::GetFullPath((Get-D32NonSourceL1CurrentRuntimePath)))) {
            throw 'D32_NON_SOURCE_L1_REFUSED: current repository/runtime role binding mismatch'
        }
        if ((Get-D32NonSourceL1CurrentOwnerSid) -cne [string]$script:D32NonSourceL1Authority.owner_id) { throw 'D32_NON_SOURCE_L1_REFUSED: current Windows owner differs from the authority owner binding' }
        $repoIdentity = Get-D32NonSourceL1DirectoryIdentity $Repository
        if ($repoIdentity.VolumeSerialHex -cne [string]$script:D32NonSourceL1Authority.repository_identity.volume_serial_hex -or $repoIdentity.FileIdHex -cne [string]$script:D32NonSourceL1Authority.repository_identity.file_id_hex) {
            throw 'D32_NON_SOURCE_L1_REFUSED: repository directory identity drift'
        }
        $rootIdentity = Get-D32NonSourceL1DirectoryIdentity ([string]$script:D32NonSourceL1Authority.output.root_path)
        $parentIdentity = Get-D32NonSourceL1DirectoryIdentity ([string]$script:D32NonSourceL1Authority.output.parent_path)
        foreach ($pair in @(@('root_volume_serial_hex', 'root_file_id_hex', $rootIdentity), @('parent_volume_serial_hex', 'parent_file_id_hex', $parentIdentity))) {
            if ([string]$script:D32NonSourceL1Authority.output.($pair[0]) -cne [string]$pair[2].VolumeSerialHex -or [string]$script:D32NonSourceL1Authority.output.($pair[1]) -cne [string]$pair[2].FileIdHex) { throw 'D32_NON_SOURCE_L1_REFUSED: external root/parent opened identity drift' }
        }
        $rootSecurity = Get-D32NonSourceL1RootSecurity -Path ([string]$script:D32NonSourceL1Authority.output.root_path)
        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RootSecurity -Security $rootSecurity -OwnerSid ([string]$script:D32NonSourceL1Authority.owner_id))) {
            throw 'D32_NON_SOURCE_L1_REFUSED: fresh external root owner-bound DACL is not protected by the fixed trusted-writer allowlist'
        }
        if ((Test-D32PowerShellAuthorityPathWithin -Child ([string]$script:D32NonSourceL1Authority.output.root_path) -Parent $Repository) -or
            (Test-D32PowerShellAuthorityPathWithin -Child ([string]$script:D32NonSourceL1Authority.output.root_path) -Parent 'E:\d32\inv7\r\c')) { throw 'D32_NON_SOURCE_L1_REFUSED: external L1 root violates fixed containment' }
        foreach ($path in @([string]$script:D32NonSourceL1Authority.output.result_path, [string]$script:D32NonSourceL1Authority.output.journal_path,
                [string]$script:D32NonSourceL1Authority.output.controller_runtime_admission_path,
                [string]$script:D32NonSourceL1Authority.output.normalreader_runtime_admission_path,
                [string]$script:D32NonSourceL1Authority.output.forcedreader_runtime_admission_path)) {
            if (Test-D32NonSourceL1OutputPathExists -Path $path) { throw 'D32_NON_SOURCE_L1_REFUSED: create-new result/journal path already exists' }
        }
        for ($index = 0; $index -lt 6; $index++) {
            $pin = $script:D32NonSourceL1Authority.source_pins[$index]
            $null = Open-D32NonSourceL1PinnedFile -Path ([string]$pin.path) -Pin $pin
        }
        $runtimePin = $script:D32NonSourceL1Authority.powershell_runtime
        $runtimeOpened = Open-D32NonSourceL1PinnedFile -Path ([string]$runtimePin.path) -Pin ([PSCustomObject]@{
            path = $runtimePin.path; bytes = $runtimePin.bytes; sha256 = $runtimePin.sha256
            volume_serial_hex = $runtimePin.volume_serial_hex; file_id_hex = $runtimePin.file_id_hex
        })
        $script:D32NonSourceL1Opened.Add($runtimeOpened)
        $prelaunchOpened = Open-D32NonSourceL1OuterPrelaunchRecord -Authority $script:D32NonSourceL1Authority `
            -AuthorityReference $script:D32NonSourceL1AuthorityReference -ExpectedBindingSha256 $ExpectedOuterPrelaunchBindingSha256 `
            -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1OuterPrelaunchReference = $prelaunchOpened.reference
        $controllerArguments = [string[]]$prelaunchOpened.record.controller.arguments.vector
        if ($null -eq $script:D32NonSourceL1EnvironmentAdapter) {
            # Outer prelaunch has been reopened and H-verified. Complete all
            # module-free startup/runtime/input admission before the sole fixed
            # Utility import and before compiling the already-pinned native API.
            $preImportContext = Get-D32NonSourceL1RuntimeContext -Authority $script:D32NonSourceL1Authority `
                -DeadlineTicks $script:D32NonSourceL1BatchDeadline -PreImportOnly
            $nonCoreModules = [System.Collections.Generic.List[object]]::new()
            foreach ($module in $ExecutionContext.SessionState.Modules.Values) {
                if ($null -ne $module -and [string]$module.Name -cne 'Microsoft.PowerShell.Core') { $nonCoreModules.Add($module) }
            }
            if ($nonCoreModules.Count -ne 0 -or $script:D32NonSourceL1ModuleImportOrder.Count -ne 0) {
                throw 'D32_NON_SOURCE_L1_REFUSED: a module was loaded before module-free runtime admission completed'
            }
            $utilityManifestPath = [string]$preImportContext.module_closure.manifest_reference.path
            $expectedUtilityManifestPath = [string]$script:D32NonSourceL1RuntimeAuthorityContent.module_policy.controller_utility_manifest.path
            if ([string]::IsNullOrWhiteSpace($utilityManifestPath) -or
                -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($utilityManifestPath),$expectedUtilityManifestPath)) {
                throw 'D32_NON_SOURCE_L1_REFUSED: fixed Utility manifest path differs from the independently pinned module policy'
            }
            Import-Module -Name $utilityManifestPath -ErrorAction Stop
            $script:D32NonSourceL1ModuleImportOrder.Add('Microsoft.PowerShell.Utility')
            $null = Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop
            $null = Get-D32NonSourceL1RuntimeContext -Authority $script:D32NonSourceL1Authority -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        } else {
            # L0-only synthetic provider: compile the fixed in-process adapter
            # surface without importing runtime modules or invoking P/Invoke.
            if ($null -eq ('D32BoundedSourceProofLifecycleNativeV1' -as [type])) {
                $null = Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop
            }
        }
        $controllerObservation = Get-D32NonSourceL1RuntimeObservation -Role CONTROLLER -Authority $script:D32NonSourceL1Authority -ParentAdmission $null
        $controllerAdmission = New-D32NonSourceL1RuntimeAdmissionArtifact -Authority $script:D32NonSourceL1Authority `
            -AuthorityReference $script:D32NonSourceL1AuthorityReference -OuterPrelaunchReference $script:D32NonSourceL1OuterPrelaunchReference `
            -Role CONTROLLER -OutputPath ([string]$script:D32NonSourceL1Authority.output.controller_runtime_admission_path) `
            -ParentAdmissionReference $null -ParentAdmission $null -Observation $controllerObservation -Arguments $controllerArguments `
            -T0Ticks $L1T0Ticks -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $script:D32NonSourceL1RuntimeAdmissions = @($controllerAdmission,
            (New-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeAdmissionSlot 'NORMAL_READER'),
            (New-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeAdmissionSlot 'FORCED_READER'))
        $script:D32NonSourceL1AdmissionValidated = $true
        $script:D32NonSourceL1JournalStream = New-D32NonSourceL1JournalStream -Path ([string]$script:D32NonSourceL1Authority.output.journal_path)
        Add-D32NonSourceL1JournalFact -Event 'AUTHORITY_ADMISSION' -ScheduledTicks $L1T0Ticks -ObservedTicks (Get-D32NonSourceL1Now)

        # Open and hash only the six fixed script pins, plus the fixed runtime.
        # Profile V2 is treated as a pinned script byte sequence only: it is not
        # semantically parsed and no manifest/lock/config path is traversed.
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
        $controllerAdmissionProcess = $script:D32NonSourceL1RuntimeAdmissions[0].admission.runner_process
        $controllerCreationFileTime = Get-D32NonSourceL1ControllerCreationFileTime
        if ([Int64]$controllerAdmissionProcess.process_id -le 0 -or
            [Int64]$controllerAdmissionProcess.creation_filetime_ticks -le 0 -or
            [Int64]$controllerAdmissionProcess.creation_filetime_ticks -ne [Int64]$controllerCreationFileTime) {
            throw 'D32_NON_SOURCE_L1_UNRESOLVED: result controller identity differs from the post-startup runtime admission'
        }
        $record = New-D32BoundedDiagnosticSourceProofNonSourceL1ResultCandidate -CandidateSha $CandidateSha `
            -BatchId ([string]$script:D32NonSourceL1Authority.batch_id) -RunId ([string]$script:D32NonSourceL1Authority.run_id) `
            -AuthorityReference $script:D32NonSourceL1AuthorityReference -SourcePins @($script:D32NonSourceL1Authority.source_pins) `
            -PowerShellRuntime ([PSCustomObject][ordered]@{ path = $script:D32NonSourceL1Authority.powershell_runtime.path; bytes = $script:D32NonSourceL1Authority.powershell_runtime.bytes; sha256 = $script:D32NonSourceL1Authority.powershell_runtime.sha256; volume_serial_hex = $script:D32NonSourceL1Authority.powershell_runtime.volume_serial_hex; file_id_hex = $script:D32NonSourceL1Authority.powershell_runtime.file_id_hex }) `
            -RuntimeAuthority $script:D32NonSourceL1Authority.runtime_authority `
            -OuterPrelaunchReference $script:D32NonSourceL1OuterPrelaunchReference -RuntimeAdmissions @($script:D32NonSourceL1RuntimeAdmissions) `
            -Output $script:D32NonSourceL1Authority.output `
            -Clock ([PSCustomObject][ordered]@{ counter_origin = 'QueryPerformanceCounter'; frequency = $frequency; batch_t0_ticks = $L1T0Ticks; batch_deadline_ticks = $script:D32NonSourceL1BatchDeadline; controller_entry_ticks = $script:D32LifecycleControllerEntryTicks }) `
            -Controller ([PSCustomObject][ordered]@{ process_id = [Int64]$controllerAdmissionProcess.process_id; creation_filetime_ticks = [Int64]$controllerCreationFileTime }) `
            -Cases @($script:D32NonSourceL1Cases.ToArray()) -CreateProcessAttemptCount $script:D32NonSourceL1CreateAttempts `
            -PlannedTerminationCount $script:D32NonSourceL1PlannedTerminations -FailSafeTerminationCount $script:D32NonSourceL1FailSafeTerminations `
            -Status $script:D32NonSourceL1Status -PrimaryError $script:D32NonSourceL1Primary -SecondaryErrors @($script:D32NonSourceL1Secondary.ToArray()) `
            -StartedAtUtc $script:D32NonSourceL1StartedAtUtc -CompletedAtUtc ([DateTimeOffset]::UtcNow.ToString('o'))
        $bytes = ConvertTo-D32NonSourceL1ResultBytes -Record $record
        if ((Get-D32NonSourceL1Now) -ge $script:D32NonSourceL1BatchDeadline) { throw 'D32_NON_SOURCE_L1_BUDGET_STOPPED: result size or batch persistence deadline exceeded' }
        $resultStream = New-D32NonSourceL1ResultStream -Path ([string]$script:D32NonSourceL1Authority.output.result_path)
        try { $resultStream.Write($bytes, 0, $bytes.Length); $resultStream.Flush($true) } finally { $resultStream.Dispose() }
        if ((Get-D32NonSourceL1Now) -ge $script:D32NonSourceL1BatchDeadline) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: result flush returned after batch deadline' }
        $resultOpened = Open-D32NonSourceL1PersistedOutput -Path ([string]$script:D32NonSourceL1Authority.output.result_path) -DirectoryFences ([System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)) -MaximumBytes 65536 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
        $resultDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$resultOpened.Bytes))
        try {
            if ($resultDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $resultDocument.RootElement)) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: persisted L1 result JSON is duplicate or non-object' }
            $readback = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $resultDocument.RootElement
        } finally { $resultDocument.Dispose(); if ($null -ne $resultOpened.Stream) { $resultOpened.Stream.Dispose() } }
        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape $readback)) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: persisted L1 result failed strict readback' }
        $persistedFact = New-D32NonSourceL1ResultPersistedFact -ResultReference $resultOpened.Record -ObservedTicks (Get-D32NonSourceL1Now)
        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultBindings -Record $readback -Authority $script:D32NonSourceL1Authority `
            -AuthorityReference $script:D32NonSourceL1AuthorityReference -ExpectedAuthorityPath $L1AuthorityPath -ExpectedAuthoritySha256 $ExpectedL1AuthoritySha256 `
            -PersistedFact $persistedFact -ResultReference $resultOpened.Record -RuntimeAuthorityContent $script:D32NonSourceL1RuntimeAuthorityContent `
            -RuntimeAuthorityOpenedReference $script:D32NonSourceL1RuntimeAuthorityOpenedReference)) {
            throw 'D32_NON_SOURCE_L1_UNRESOLVED: persisted result authority/source/runtime/case/flush chain failed binding'
        }
        Add-D32NonSourceL1JournalFact -Event 'L1_RESULT_PERSISTED' -ObservedTicks ([Int64]$persistedFact.observed_ticks) -ResultReference $resultOpened.Record
        $journalClosed = $false
        if ($null -ne $script:D32NonSourceL1JournalStream) {
            try { $script:D32NonSourceL1JournalStream.Flush($true); $script:D32NonSourceL1JournalStream.Dispose(); $script:D32NonSourceL1JournalStream = $null; $journalClosed = $true } catch { $journalClosed = $false }
        }
        $resultWritten = $true
        $journalFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
        $journalOpened = Open-D32NonSourceL1PersistedOutput -Path ([string]$script:D32NonSourceL1Authority.output.journal_path) -DirectoryFences $journalFences -MaximumBytes 65536 -DeadlineTicks $script:D32NonSourceL1BatchDeadline
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

function Invoke-D32NonSourceL1ControllerBoundary {
    param([Parameter(Mandatory = $true)][System.IO.TextWriter]$DiagnosticWriter)
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
            -SecondaryErrors @($script:D32NonSourceL1Secondary.ToArray()) -Writer $DiagnosticWriter
    }
    return [int]$l1ExitCode
}

if ($PSCmdlet.ParameterSetName -ceq 'NonSourceL1') {
    exit (Invoke-D32NonSourceL1ControllerBoundary -DiagnosticWriter ([Console]::Error))
}

if ($PSCmdlet.ParameterSetName -ceq 'OuterCaller') {
    return (Invoke-D32NonSourceL1FixedOuterCaller -DiagnosticWriter ([Console]::Error))
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
