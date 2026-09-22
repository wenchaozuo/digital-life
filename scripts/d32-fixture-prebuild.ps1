[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$OutputRoot,
    [string]$ManifestPath,
    [ValidateRange(1, 3600)]
    [int]$TimeoutSeconds = 600,
    [ValidateRange(1, 16)]
    [int]$BuildJobs = 1,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:OwnerMarkerName = '.d32-fixture-prebuild-owned'
$script:OwnerMarker = 'D32_FIXTURE_PREBUILD_OWNER_V1'
$script:SchemaVersion = 2
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

$script:FixtureSpecs = @(
    [ordered]@{
        name             = 'd29h1-authority-fixture'
        project          = 'src-tauri'
        manifest         = 'src-tauri/Cargo.toml'
        binary           = 'd29h1-authority-fixture'
        features         = @('d29-h1-host-fixture')
        artifact         = 'src-tauri/target/debug/d29h1-authority-fixture.exe'
    },
    [ordered]@{
        name             = 'd29h7-authority-fixture'
        project          = 'src-tauri'
        manifest         = 'src-tauri/Cargo.toml'
        binary           = 'd29h7-authority-fixture'
        features         = @('d29-h7-host-fixture')
        artifact         = 'src-tauri/target/debug/d29h7-authority-fixture.exe'
    },
    [ordered]@{
        name             = 'd29h7-process-fixture'
        project          = 'vita-agent'
        manifest         = 'vita-agent/Cargo.toml'
        binary           = 'd29h7-process-fixture'
        features         = @()
        artifact         = 'vita-agent/target/debug/d29h7-process-fixture.exe'
    },
    [ordered]@{
        name             = 'd29h7-git-helper-fixture'
        project          = 'vita-agent'
        manifest         = 'vita-agent/Cargo.toml'
        binary           = 'd29h7-git-helper-fixture'
        features         = @('d29-h7-test-helper')
        artifact         = 'vita-agent/target/debug/d29h7-git-helper-fixture.exe'
    },
    [ordered]@{
        name             = 'd32a-sandbox-fixture'
        project          = 'vita-agent'
        manifest         = 'vita-agent/Cargo.toml'
        binary           = 'd32a-sandbox-fixture'
        features         = @('d32-a-test-helper')
        artifact         = 'vita-agent/target/debug/d32a-sandbox-fixture.exe'
    }
)

function Get-D32FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path))
}

function Test-D32PathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $pathFull = (Get-D32FullPath $Path).TrimEnd('\')
    $rootFull = (Get-D32FullPath $Root).TrimEnd('\')
    if ($pathFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $pathFull.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Ensure-D32OwnedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Get-D32FullPath $Path
    if (Test-Path -LiteralPath $full) {
        if (-not (Test-Path -LiteralPath $full -PathType Container)) {
            throw "OUTPUT_NOT_OWNED: output root is not a directory: $full"
        }
        $markerPath = Join-Path $full $script:OwnerMarkerName
        if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf) -or
            ([IO.File]::ReadAllText($markerPath).Trim() -ne $script:OwnerMarker)) {
            throw "OUTPUT_NOT_OWNED: refusing to reuse an unmarked output directory: $full"
        }
        return $full
    }

    New-Item -ItemType Directory -Path $full -Force:$false | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $full $script:OwnerMarkerName),
        $script:OwnerMarker,
        [Text.UTF8Encoding]::new($false)
    )
    return $full
}

function Assert-D32ManifestDestination {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OwnedRoot
    )

    $full = Get-D32FullPath $Path
    if (-not (Test-D32PathWithin -Path $full -Root $OwnedRoot) -or
        $full.Equals((Get-D32FullPath $OwnedRoot), [StringComparison]::OrdinalIgnoreCase)) {
        throw "OUTPUT_NOT_OWNED: manifest must be inside the owned output root: $full"
    }
    $parent = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force:$false | Out-Null
    }
    return $full
}

function Remove-D32OwnedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Get-D32FullPath $Path
    $markerPath = Join-Path $full $script:OwnerMarkerName
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf) -or
        ([IO.File]::ReadAllText($markerPath).Trim() -ne $script:OwnerMarker)) {
        throw "OUTPUT_NOT_OWNED: refusing to remove an unmarked directory: $full"
    }
    Remove-Item -LiteralPath $full -Recurse -Force
}

function Get-D32GitOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $git = (Get-Command git.exe -ErrorAction Stop).Source
    $output = @(& $git -C $Root @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "GIT_FAILED: git $($Arguments -join ' ') ($LASTEXITCODE): $($output -join ' ')"
    }
    return ($output -join "`n").Trim()
}

function Get-D32CandidateSha {
    param([Parameter(Mandatory = $true)][string]$Root)

    $sha = Get-D32GitOutput -Root $Root -Arguments @('rev-parse', 'HEAD')
    if ($sha -notmatch '^[0-9a-fA-F]{40}$') {
        throw "GIT_FAILED: HEAD is not a full commit SHA: $sha"
    }
    return $sha.ToLowerInvariant()
}

function Get-D32EnvironmentPlan {
    param([Parameter(Mandatory = $true)][string]$EnvironmentRoot)

    $originalUserProfile = [Environment]::GetEnvironmentVariable('USERPROFILE', 'Process')
    if ([String]::IsNullOrWhiteSpace($originalUserProfile)) {
        $originalUserProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    }
    if ([String]::IsNullOrWhiteSpace($originalUserProfile)) {
        throw 'ENVIRONMENT_INVALID: the real USERPROFILE could not be resolved'
    }
    $originalUserProfile = Get-D32FullPath $originalUserProfile

    $cargoHome = [Environment]::GetEnvironmentVariable('CARGO_HOME', 'Process')
    if ([String]::IsNullOrWhiteSpace($cargoHome)) {
        $cargoHome = Join-Path $originalUserProfile '.cargo'
    }
    $rustupHome = [Environment]::GetEnvironmentVariable('RUSTUP_HOME', 'Process')
    if ([String]::IsNullOrWhiteSpace($rustupHome)) {
        $rustupHome = Join-Path $originalUserProfile '.rustup'
    }
    $toolchain = [Environment]::GetEnvironmentVariable('RUSTUP_TOOLCHAIN', 'Process')

    $environmentRoot = Ensure-D32OwnedDirectory $EnvironmentRoot
    $codexHome = Ensure-D32OwnedDirectory (Join-Path $environmentRoot 'codex-home')
    $isolatedUserProfile = Ensure-D32OwnedDirectory (Join-Path $environmentRoot 'user-profile')

    return [ordered]@{
        original_userprofile = $originalUserProfile
        codex_home           = $codexHome
        userprofile          = $isolatedUserProfile
        cargo_home           = Get-D32FullPath $cargoHome
        rustup_home          = Get-D32FullPath $rustupHome
        rustup_toolchain     = $toolchain
    }
}

function Set-D32IsolatedEnvironment {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Plan,
        [Parameter(Mandatory = $true)][int]$Jobs
    )

    $names = @('CODEX_HOME', 'USERPROFILE', 'CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN', 'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL', 'CARGO_TERM_COLOR')
    $saved = @{}
    foreach ($name in $names) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    [Environment]::SetEnvironmentVariable('CODEX_HOME', $Plan.codex_home, 'Process')
    [Environment]::SetEnvironmentVariable('USERPROFILE', $Plan.userprofile, 'Process')
    [Environment]::SetEnvironmentVariable('CARGO_HOME', $Plan.cargo_home, 'Process')
    [Environment]::SetEnvironmentVariable('RUSTUP_HOME', $Plan.rustup_home, 'Process')
    [Environment]::SetEnvironmentVariable('RUSTUP_TOOLCHAIN', $Plan.rustup_toolchain, 'Process')
    [Environment]::SetEnvironmentVariable('CARGO_BUILD_JOBS', [string]$Jobs, 'Process')
    [Environment]::SetEnvironmentVariable('CARGO_INCREMENTAL', '0', 'Process')
    [Environment]::SetEnvironmentVariable('CARGO_TERM_COLOR', 'never', 'Process')
    return $saved
}

function Restore-D32Environment {
    param([Parameter(Mandatory = $true)][hashtable]$Saved)

    foreach ($entry in $Saved.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
}

function ConvertTo-D32CommandLine {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    return (($Arguments | ForEach-Object {
                if ($_ -match '[\s"]') {
                    '"' + $_.Replace('"', '\"') + '"'
                }
                else {
                    $_
                }
            }) -join ' ')
}

function Assert-D32CleanGitStatus {
    param(
        [AllowNull()][string]$Status,
        [Parameter(Mandatory = $true)][string]$Root
    )

    if (-not [String]::IsNullOrWhiteSpace($Status)) {
        throw "WORKTREE_DIRTY: refusing fixture prebuild PASS for dirty repository $($Root): $Status"
    }
}

function Ensure-D32NativeLauncher {
    $type = ([System.Management.Automation.PSTypeName]'D32FixtureNativeProcessV2').Type
    if ($null -ne $type) { return }

    $savedLib = [Environment]::GetEnvironmentVariable('LIB', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('LIB', $null, 'Process')
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public sealed class D32NativeCleanupEvidenceV2
{
    public bool JobTerminateCallSucceeded { get; internal set; }
    public int JobTerminateLastError { get; internal set; }
    public bool ProcessWasAlreadySignaled { get; internal set; }
    public bool ProcessWaitSignaled { get; internal set; }
    public bool JobCloseSucceeded { get; internal set; }
    public bool CleanupSucceeded { get; internal set; }
    public bool AlreadyClosed { get; internal set; }
    public string Detail { get; internal set; }
}

public sealed class D32FixtureNativeProcessV2 : IDisposable
{
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint HandleFlagInherit = 0x00000001;
    private const uint JobObjectExtendedLimitInformationClass = 9;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint WaitObject0 = 0x00000000;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public int Cb;
        public IntPtr Reserved;
        public IntPtr Desktop;
        public IntPtr Title;
        public int X;
        public int Y;
        public int XSize;
        public int YSize;
        public int XCountChars;
        public int YCountChars;
        public int FillAttribute;
        public uint Flags;
        public short ShowWindow;
        public short Reserved2;
        public IntPtr Reserved2Pointer;
        public IntPtr StandardInput;
        public IntPtr StandardOutput;
        public IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObjectW(IntPtr jobAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        uint jobObjectInformationClass,
        ref JobObjectExtendedLimitInformation jobObjectInformation,
        uint jobObjectInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(
        out IntPtr readPipe,
        out IntPtr writePipe,
        ref SecurityAttributes pipeAttributes,
        uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        ref SecurityAttributes securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    private IntPtr _job;
    private IntPtr _process;
    private IntPtr _thread;
    private SafeFileHandle _stdoutHandle;
    private SafeFileHandle _stderrHandle;
    private FileStream _stdoutStream;
    private FileStream _stderrStream;
    private bool _disposed;

    public int ProcessId { get; private set; }
    public bool JobAssigned { get; private set; }
    public string LaunchMode { get { return "CreateProcessW(CREATE_SUSPENDED)+AssignProcessToJobObject(KILL_ON_JOB_CLOSE)+ResumeThread"; } }

    private D32FixtureNativeProcessV2(
        IntPtr job,
        IntPtr process,
        IntPtr thread,
        IntPtr stdoutRead,
        IntPtr stderrRead,
        uint processId)
    {
        _job = job;
        _process = process;
        _thread = thread;
        _stdoutHandle = new SafeFileHandle(stdoutRead, true);
        _stderrHandle = new SafeFileHandle(stderrRead, true);
        ProcessId = checked((int)processId);
        JobAssigned = true;
    }

    private static void ThrowLastError(string prefix)
    {
        int error = Marshal.GetLastWin32Error();
        throw new Win32Exception(error, prefix + " (win32=" + error.ToString() + ")");
    }

    private static void CloseIfOpen(ref IntPtr handle)
    {
        if (handle != IntPtr.Zero && handle != new IntPtr(-1))
        {
            CloseHandle(handle);
            handle = IntPtr.Zero;
        }
    }

    private static void ConfigureKillOnClose(IntPtr job)
    {
        JobObjectExtendedLimitInformation limits = new JobObjectExtendedLimitInformation();
        limits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
        if (!SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformationClass,
            ref limits,
            (uint)Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation))))
        {
            ThrowLastError("SetInformationJobObject(KILL_ON_JOB_CLOSE) failed");
        }
    }

    public static D32FixtureNativeProcessV2 Start(
        string filePath,
        string commandLine,
        string workingDirectory)
    {
        if (String.IsNullOrWhiteSpace(filePath)) throw new ArgumentException("filePath");
        if (String.IsNullOrWhiteSpace(workingDirectory)) throw new ArgumentException("workingDirectory");

        IntPtr job = IntPtr.Zero;
        IntPtr stdoutRead = IntPtr.Zero;
        IntPtr stdoutWrite = IntPtr.Zero;
        IntPtr stderrRead = IntPtr.Zero;
        IntPtr stderrWrite = IntPtr.Zero;
        IntPtr stdin = IntPtr.Zero;
        ProcessInformation pi = new ProcessInformation();
        bool transferred = false;

        try
        {
            job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero) ThrowLastError("CreateJobObjectW failed");
            ConfigureKillOnClose(job);

            SecurityAttributes pipeAttributes = new SecurityAttributes();
            pipeAttributes.Length = Marshal.SizeOf(typeof(SecurityAttributes));
            pipeAttributes.InheritHandle = 1;
            if (!CreatePipe(out stdoutRead, out stdoutWrite, ref pipeAttributes, 0))
                ThrowLastError("CreatePipe(stdout) failed");
            if (!SetHandleInformation(stdoutRead, HandleFlagInherit, 0))
                ThrowLastError("SetHandleInformation(stdout) failed");
            if (!CreatePipe(out stderrRead, out stderrWrite, ref pipeAttributes, 0))
                ThrowLastError("CreatePipe(stderr) failed");
            if (!SetHandleInformation(stderrRead, HandleFlagInherit, 0))
                ThrowLastError("SetHandleInformation(stderr) failed");

            stdin = CreateFileW(
                "NUL",
                GenericRead,
                FileShareRead | FileShareWrite,
                ref pipeAttributes,
                OpenExisting,
                FileAttributeNormal,
                IntPtr.Zero);
            if (stdin == IntPtr.Zero || stdin == new IntPtr(-1))
                ThrowLastError("CreateFileW(NUL) failed");

            StartupInfo startup = new StartupInfo();
            startup.Cb = Marshal.SizeOf(typeof(StartupInfo));
            startup.Flags = StartfUseStdHandles;
            startup.StandardInput = stdin;
            startup.StandardOutput = stdoutWrite;
            startup.StandardError = stderrWrite;
            StringBuilder mutableCommandLine = new StringBuilder(commandLine ?? String.Empty);
            if (!CreateProcessW(
                filePath,
                mutableCommandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                CreateSuspended | CreateNoWindow | CreateUnicodeEnvironment,
                IntPtr.Zero,
                workingDirectory,
                ref startup,
                out pi))
            {
                ThrowLastError("CreateProcessW failed");
            }

            CloseIfOpen(ref stdoutWrite);
            CloseIfOpen(ref stderrWrite);
            CloseIfOpen(ref stdin);

            if (!AssignProcessToJobObject(job, pi.Process))
                ThrowLastError("AssignProcessToJobObject failed");

            uint resumeResult = ResumeThread(pi.Thread);
            if (resumeResult == UInt32.MaxValue)
                ThrowLastError("ResumeThread failed");

            D32FixtureNativeProcessV2 result = new D32FixtureNativeProcessV2(
                job,
                pi.Process,
                pi.Thread,
                stdoutRead,
                stderrRead,
                pi.ProcessId);
            job = IntPtr.Zero;
            pi.Process = IntPtr.Zero;
            pi.Thread = IntPtr.Zero;
            stdoutRead = IntPtr.Zero;
            stderrRead = IntPtr.Zero;
            transferred = true;
            return result;
        }
        catch (Exception error)
        {
            string cleanup = "attempted";
            try
            {
                if (pi.Process != IntPtr.Zero)
                {
                    if (job != IntPtr.Zero) TerminateJobObject(job, 1);
                    TerminateProcess(pi.Process, 1);
                    WaitForSingleObject(pi.Process, 5000);
                }
            }
            catch (Exception cleanupError)
            {
                cleanup = "failed:" + cleanupError.Message;
            }
            throw new InvalidOperationException(
                "D32_NATIVE_LAUNCH_FAILED: " + error.Message + "; native cleanup=" + cleanup,
                error);
        }
        finally
        {
            if (!transferred)
            {
                CloseIfOpen(ref stdoutWrite);
                CloseIfOpen(ref stderrWrite);
                CloseIfOpen(ref stdin);
                CloseIfOpen(ref stdoutRead);
                CloseIfOpen(ref stderrRead);
                CloseIfOpen(ref pi.Thread);
                CloseIfOpen(ref pi.Process);
                CloseIfOpen(ref job);
            }
        }
    }

    public bool HasExited
    {
        get { return WaitForSingleObject(_process, 0) == WaitObject0; }
    }

    public bool WaitForExit(int timeoutMilliseconds)
    {
        if (timeoutMilliseconds < 0) timeoutMilliseconds = 0;
        return WaitForSingleObject(_process, (uint)timeoutMilliseconds) == WaitObject0;
    }

    public int ExitCode
    {
        get
        {
            uint code;
            if (!GetExitCodeProcess(_process, out code)) ThrowLastError("GetExitCodeProcess failed");
            return unchecked((int)code);
        }
    }

    public Stream StdoutStream
    {
        get
        {
            if (_stdoutStream == null)
                _stdoutStream = new FileStream(_stdoutHandle, FileAccess.Read, 4096, false);
            return _stdoutStream;
        }
    }

    public Stream StderrStream
    {
        get
        {
            if (_stderrStream == null)
                _stderrStream = new FileStream(_stderrHandle, FileAccess.Read, 4096, false);
            return _stderrStream;
        }
    }

    public Stream OpenStdoutStream()
    {
        return StdoutStream;
    }

    public Stream OpenStderrStream()
    {
        return StderrStream;
    }

    public D32NativeCleanupEvidenceV2 CloseJobAndWait(int timeoutMilliseconds)
    {
        D32NativeCleanupEvidenceV2 evidence = new D32NativeCleanupEvidenceV2();
        if (_job == IntPtr.Zero)
        {
            evidence.AlreadyClosed = true;
            evidence.ProcessWaitSignaled = WaitForExit(timeoutMilliseconds);
            evidence.CleanupSucceeded = evidence.ProcessWaitSignaled;
            evidence.Detail = "job handle already closed";
            return evidence;
        }

        evidence.ProcessWasAlreadySignaled = HasExited;
        if (!evidence.ProcessWasAlreadySignaled)
        {
            evidence.JobTerminateCallSucceeded = TerminateJobObject(_job, 1);
            if (!evidence.JobTerminateCallSucceeded)
                evidence.JobTerminateLastError = Marshal.GetLastWin32Error();
        }
        else
        {
            evidence.JobTerminateCallSucceeded = true;
        }
        evidence.ProcessWaitSignaled = WaitForExit(timeoutMilliseconds);
        evidence.JobCloseSucceeded = CloseHandle(_job);
        _job = IntPtr.Zero;
        evidence.CleanupSucceeded = evidence.JobCloseSucceeded && evidence.ProcessWaitSignaled;
        evidence.Detail = evidence.CleanupSucceeded
            ? "owned job closed and root process signaled"
            : "owned job close or root process wait failed";
        return evidence;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_job != IntPtr.Zero)
        {
            CloseHandle(_job);
            _job = IntPtr.Zero;
        }
        if (_stdoutStream != null) _stdoutStream.Dispose();
        if (_stderrStream != null) _stderrStream.Dispose();
        if (_stdoutHandle != null) _stdoutHandle.Dispose();
        if (_stderrHandle != null) _stderrHandle.Dispose();
        CloseIfOpen(ref _thread);
        CloseIfOpen(ref _process);
    }
}
'@ -Language CSharp
    }
    finally {
        [Environment]::SetEnvironmentVariable('LIB', $savedLib, 'Process')
    }
}

function New-D32ProcessIdentityRecord {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [AllowNull()][Nullable[int]]$ParentProcessId,
        [AllowNull()][string]$Name,
        [AllowNull()][string]$CommandLine,
        [AllowNull()][string]$CreationDate,
        [Parameter(Mandatory = $true)][string]$ObservedAtUtc,
        [Parameter(Mandatory = $true)][bool]$IdentityVerified
    )

    return [pscustomobject][ordered]@{
        ProcessId       = $ProcessId
        ParentProcessId = $ParentProcessId
        Name            = $Name
        CommandLine     = $CommandLine
        CreationDate    = $CreationDate
        ObservedAtUtc   = $ObservedAtUtc
        IdentityVerified = $IdentityVerified
    }
}

function Get-D32ProcessSnapshot {
    param([int]$ProcessId = 0)

    try {
        $observedAt = [DateTimeOffset]::UtcNow.ToString('o')
        $filter = if ($ProcessId -gt 0) { "ProcessId=$ProcessId" } else { $null }
        $items = if ($null -eq $filter) {
            @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
        }
        else {
            @(Get-CimInstance -ClassName Win32_Process -Filter $filter -ErrorAction Stop)
        }
        return @($items | ForEach-Object {
            $name = if ($null -eq $_.Name) { $null } else { [string]$_.Name }
            $creation = if ($null -eq $_.CreationDate) { $null } else { [string]$_.CreationDate }
            $parent = if ($null -eq $_.ParentProcessId) { $null } else { [int]$_.ParentProcessId }
            $commandLine = if ($null -eq $_.CommandLine) { $null } else { [string]$_.CommandLine }
            New-D32ProcessIdentityRecord `
                -ProcessId ([int]$_.ProcessId) `
                -ParentProcessId $parent `
                -Name $name `
                -CommandLine $commandLine `
                -CreationDate $creation `
                -ObservedAtUtc $observedAt `
                -IdentityVerified ($null -ne $name -and $name.Length -gt 0 -and $null -ne $creation -and $creation.Length -gt 0)
        })
    }
    catch {
        throw "PROCESS_TREE_ENUMERATION_FAILED: $($_.Exception.Message)"
    }
}

function ConvertTo-D32IdentityDocument {
    param([AllowNull()][object]$Record)

    if ($null -eq $Record) { return $null }
    return [ordered]@{
        process_id        = if ($null -eq $Record.ProcessId) { $null } else { [int]$Record.ProcessId }
        parent_process_id = if ($null -eq $Record.ParentProcessId) { $null } else { [int]$Record.ParentProcessId }
        name              = $Record.Name
        creation_date     = $Record.CreationDate
        command_line      = $Record.CommandLine
        observed_at_utc   = $Record.ObservedAtUtc
        identity_verified = [bool]$Record.IdentityVerified
    }
}

function ConvertTo-D32NativeCleanupDocument {
    param([AllowNull()][object]$Evidence)

    if ($null -eq $Evidence) { return $null }
    return [ordered]@{
        job_terminate_call_succeeded = [bool]$Evidence.JobTerminateCallSucceeded
        job_terminate_last_error     = [int]$Evidence.JobTerminateLastError
        process_was_already_signaled = [bool]$Evidence.ProcessWasAlreadySignaled
        process_wait_signaled        = [bool]$Evidence.ProcessWaitSignaled
        job_close_succeeded          = [bool]$Evidence.JobCloseSucceeded
        cleanup_succeeded            = [bool]$Evidence.CleanupSucceeded
        already_closed               = [bool]$Evidence.AlreadyClosed
        detail                       = [string]$Evidence.Detail
    }
}

function Get-D32DescendantProcessRecordsFromSnapshot {
    param(
        [Parameter(Mandatory = $true)][object[]]$Snapshot,
        [Parameter(Mandatory = $true)][int]$RootPid
    )

    $byParent = @{}
    foreach ($record in $Snapshot) {
        if ($null -eq $record.ParentProcessId) { continue }
        $parent = [int]$record.ParentProcessId
        if (-not $byParent.ContainsKey($parent)) { $byParent[$parent] = @() }
        $byParent[$parent] += $record
    }
    $pending = [System.Collections.Generic.Queue[int]]::new()
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    $pending.Enqueue($RootPid)
    [void]$seen.Add($RootPid)
    $descendants = [System.Collections.Generic.List[object]]::new()
    while ($pending.Count -gt 0) {
        $parent = $pending.Dequeue()
        if (-not $byParent.ContainsKey($parent)) { continue }
        foreach ($record in $byParent[$parent]) {
            $child = [int]$record.ProcessId
            if ($seen.Add($child)) {
                $descendants.Add($record)
                $pending.Enqueue($child)
            }
        }
    }
    return @($descendants)
}

function Get-D32DescendantProcessRecords {
    param([Parameter(Mandatory = $true)][int]$RootPid)

    return @(Get-D32DescendantProcessRecordsFromSnapshot -Snapshot (Get-D32ProcessSnapshot) -RootPid $RootPid)
}

function Get-D32ProcessIdentityKey {
    param([Parameter(Mandatory = $true)][object]$Record)

    $creation = if ($null -eq $Record.CreationDate) { '<none>' } else { [string]$Record.CreationDate }
    return "$([int]$Record.ProcessId)|$creation"
}

function Merge-D32ProcessIdentityRecords {
    param(
        [AllowNull()][object[]]$Existing,
        [AllowNull()][object[]]$Incoming
    )

    $merged = [ordered]@{}
    foreach ($record in @($Existing) + @($Incoming)) {
        if ($null -eq $record) { continue }
        $key = Get-D32ProcessIdentityKey $record
        $merged[$key] = $record
    }
    return @($merged.Values)
}

function New-D32FallbackProcessIdentity {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][string]$ObservedAtUtc
    )

    return New-D32ProcessIdentityRecord `
        -ProcessId $ProcessId `
        -ParentProcessId $null `
        -Name ([IO.Path]::GetFileName($FilePath)) `
        -CommandLine $CommandLine `
        -CreationDate $null `
        -ObservedAtUtc $ObservedAtUtc `
        -IdentityVerified $false
}

function Test-D32CapturedProcessAlive {
    param([Parameter(Mandatory = $true)][object]$Record)

    $current = @(Get-D32ProcessSnapshot -ProcessId ([int]$Record.ProcessId))
    if ($current.Count -eq 0) { return $false }
    $candidate = $current[0]
    if (-not [bool]$Record.IdentityVerified) {
        throw "PROCESS_IDENTITY_UNVERIFIED: pid $($Record.ProcessId) is still present but its captured identity was incomplete"
    }
    if ([string]$candidate.Name -cne [string]$Record.Name -or
        [string]$candidate.CreationDate -cne [string]$Record.CreationDate) {
        throw "PROCESS_IDENTITY_MISMATCH: captured pid $($Record.ProcessId) no longer matches name/creation identity"
    }
    return $true
}

function Stop-D32ProcessTreeAndVerify {
    param(
        [Parameter(Mandatory = $true)][object]$RootRecord,
        [AllowNull()][object[]]$CapturedDescendantRecords = @(),
        [AllowNull()][object]$NativeProcess = $null
    )

    $records = @(Merge-D32ProcessIdentityRecords -Existing @($RootRecord) -Incoming $CapturedDescendantRecords)
    $killOutput = [System.Collections.Generic.List[string]]::new()
    $nativeCleanup = $null
    if ($null -ne $NativeProcess) {
        try {
            $nativeCleanup = $NativeProcess.CloseJobAndWait(10000)
            if (-not [bool]$nativeCleanup.CleanupSucceeded) {
                throw "native job close did not verify process termination: $($nativeCleanup.Detail)"
            }
        }
        catch {
            throw "PROCESS_GROUP_REAP_FAILED: $($_.Exception.Message)"
        }
    }
    $rootAlive = Test-D32CapturedProcessAlive -Record $RootRecord
    if ($rootAlive) {
        $killOutput.AddRange([string[]]@(& taskkill.exe /PID ([int]$RootRecord.ProcessId) /T /F 2>&1))
    }
    else {
        $killOutput.Add('root process identity was already gone; per-identity verification continues')
    }

    # Do not wait for a dead root to make a detached child disappear. The
    # retained name/creation identity is the authorization for each explicit
    # per-PID kill, so this remains safe across reparenting and PID reuse.
    foreach ($record in $records) {
        if ([int]$record.ProcessId -eq [int]$RootRecord.ProcessId) { continue }
        if (Test-D32CapturedProcessAlive -Record $record) {
            $killOutput.AddRange([string[]]@(& taskkill.exe /PID ([int]$record.ProcessId) /F 2>&1))
        }
    }

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
    do {
        $alive = [System.Collections.Generic.List[object]]::new()
        foreach ($record in $records) {
            if (Test-D32CapturedProcessAlive -Record $record) { $alive.Add($record) }
        }
        if ($alive.Count -eq 0) {
            return [ordered]@{
                ProcessIds = @($records | ForEach-Object { [int]$_.ProcessId })
                CapturedRecords = @($records)
                ResidualRecords = @()
                KillOutput = @($killOutput)
                NativeCleanup = $nativeCleanup
                VerifiedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    # The recursive taskkill is the first action. Explicitly target every
    # captured identity once more so a process that detached or raced the tree
    # capture cannot be silently inherited by the next phase. Never target a
    # PID whose name/creation identity no longer matches the capture.
    foreach ($record in $records) {
        if (Test-D32CapturedProcessAlive -Record $record) {
            $killOutput.AddRange([string[]]@(& taskkill.exe /PID ([int]$record.ProcessId) /F 2>&1))
        }
    }
    Start-Sleep -Milliseconds 250
    $residual = [System.Collections.Generic.List[object]]::new()
    foreach ($record in $records) {
        if (Test-D32CapturedProcessAlive -Record $record) { $residual.Add($record) }
    }
    if ($residual.Count -gt 0) {
        $details = ($residual | ForEach-Object { "$($_.Name):$($_.ProcessId):parent=$($_.ParentProcessId):creation=$($_.CreationDate)" }) -join ', '
        throw "PROCESS_TREE_REAP_FAILED: captured process identities remained alive after recursive and per-PID kill: $details"
    }
    return [ordered]@{
        ProcessIds = @($records | ForEach-Object { [int]$_.ProcessId })
        CapturedRecords = @($records)
        ResidualRecords = @()
        KillOutput = @($killOutput)
        NativeCleanup = $nativeCleanup
        VerifiedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
    }
}

function Test-D32NoOwnedCargoDescendants {
    param(
        [Parameter(Mandatory = $true)][object[]]$PhaseEvidence,
        [Parameter(Mandatory = $true)][string]$CheckName
    )

    $tracked = [System.Collections.Generic.List[object]]::new()
    foreach ($evidence in $PhaseEvidence) {
        if ($null -ne $evidence.root_record) { $tracked.Add($evidence.root_record) }
        foreach ($record in @($evidence.descendant_records)) {
            if ($null -ne $record) { $tracked.Add($record) }
        }
        if ($null -ne $evidence.root_record) {
            # Failed phases are deliberately included here. A normal phase
            # may have no descendants, while a process-tree error must retain
            # every identity captured before the error.
            [void](Stop-D32ProcessTreeAndVerify -RootRecord $evidence.root_record -CapturedDescendantRecords @($evidence.descendant_records))
        }
    }

    $snapshot = Get-D32ProcessSnapshot
    $byParent = @{}
    foreach ($record in $snapshot) {
        if ($null -eq $record.ParentProcessId) { continue }
        $parent = [int]$record.ParentProcessId
        if (-not $byParent.ContainsKey($parent)) { $byParent[$parent] = @() }
        $byParent[$parent] += $record
    }
    $residual = [System.Collections.Generic.List[object]]::new()
    foreach ($record in (Merge-D32ProcessIdentityRecords -Existing @() -Incoming @($tracked))) {
        if (Test-D32CapturedProcessAlive -Record $record) { $residual.Add($record) }
    }

    $rootQueue = [System.Collections.Generic.Queue[int]]::new()
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($evidence in $PhaseEvidence) {
        if ($null -eq $evidence.root_record) { continue }
        if (Test-D32CapturedProcessAlive -Record $evidence.root_record) {
            $rootQueue.Enqueue([int]$evidence.root_record.ProcessId)
        }
    }
    $relevantPattern = '(?i)(cargo|rustc|rustup|lld-link|(^|[-_])link([-.]|$)|fixture)'
    while ($rootQueue.Count -gt 0) {
        $parent = $rootQueue.Dequeue()
        if (-not $byParent.ContainsKey($parent)) { continue }
        foreach ($record in $byParent[$parent]) {
            $child = [int]$record.ProcessId
            if (-not $seen.Add($child)) { continue }
            $rootQueue.Enqueue($child)
            if ([string]$record.Name -match $relevantPattern) { $residual.Add($record) }
        }
    }
    if ($residual.Count -gt 0) {
        $details = ($residual | ForEach-Object { "$($_.Name):$($_.ProcessId):parent=$($_.ParentProcessId):creation=$($_.CreationDate)" }) -join ', '
        throw "PROCESS_TREE_REAP_FAILED: $CheckName found owned process descendants in relevant set ($relevantPattern): $details"
    }
    return [ordered]@{
        checked_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        relevant_pattern = $relevantPattern
        residual_identities = @()
    }
}

function Invoke-D32BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$PhaseLog,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [ValidateSet('none', 'spawn-init', 'cim-init', 'pipe-init')]
        [string]$FailureInjection = 'none'
    )

    Ensure-D32NativeLauncher
    $stdoutPath = "$PhaseLog.stdout.log"
    $stderrPath = "$PhaseLog.stderr.log"
    $started = [DateTimeOffset]::UtcNow
    $commandLine = ConvertTo-D32CommandLine (@($FilePath) + $Arguments)
    $nativeProcess = $null
    $nativeCleanup = $null
    $processId = $null
    $rootIdentity = $null
    $capturedDescendantRecords = @()
    $residualDescendantRecords = @()
    $stdoutTarget = $null
    $stderrTarget = $null
    $stdoutStream = $null
    $stderrStream = $null
    $stdoutCopy = $null
    $stderrCopy = $null
    $initError = $null
    $treeError = $null
    $timedOut = $false
    $exitCode = $null
    $reap = $null
    $killOutput = [System.Collections.Generic.List[string]]::new()
    $script:D32LastProcessEvidence = [ordered]@{
        root_record = $null
        descendant_records = @()
        native_launch = $null
        native_cleanup = $null
        started_at_utc = $started.ToString('o')
    }

    try {
        $nativeProcess = [D32FixtureNativeProcessV2]::Start(
            (Get-D32FullPath $FilePath),
            $commandLine,
            (Get-D32FullPath $WorkingDirectory))
        $processId = [int]$nativeProcess.ProcessId
        $script:D32LastProcessEvidence.native_launch = [ordered]@{
            process_id = $processId
            job_assigned = [bool]$nativeProcess.JobAssigned
            launch_mode = [string]$nativeProcess.LaunchMode
        }
        if ($FailureInjection -eq 'spawn-init') {
            throw 'SELFTEST_INJECTED_SPAWN_INIT_EXCEPTION'
        }

        for ($attempt = 0; $attempt -lt 5; $attempt++) {
            if ($FailureInjection -eq 'cim-init') {
                throw 'SELFTEST_INJECTED_CIM_INIT_EXCEPTION'
            }
            $rootCandidates = @(Get-D32ProcessSnapshot -ProcessId $processId)
            if ($rootCandidates.Count -eq 1) {
                $rootIdentity = $rootCandidates[0]
                break
            }
            if ($nativeProcess.HasExited) { break }
            Start-Sleep -Milliseconds 50
        }
        if ($null -eq $rootIdentity) {
            $rootIdentity = New-D32FallbackProcessIdentity `
                -ProcessId $processId `
                -FilePath $FilePath `
                -CommandLine $commandLine `
                -ObservedAtUtc ([DateTimeOffset]::UtcNow.ToString('o'))
            if (-not $nativeProcess.HasExited) {
                throw "PROCESS_IDENTITY_UNVERIFIED: root pid $processId remained alive without a complete CIM identity"
            }
        }
        $script:D32LastProcessEvidence.root_record = $rootIdentity

        $stdoutTarget = [IO.File]::Open(
            $stdoutPath,
            [IO.FileMode]::Create,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read)
        $stderrTarget = [IO.File]::Open(
            $stderrPath,
            [IO.FileMode]::Create,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read)
        $stdoutStream = $nativeProcess.OpenStdoutStream()
        if ($FailureInjection -eq 'pipe-init') {
            throw 'SELFTEST_INJECTED_PIPE_INIT_EXCEPTION'
        }
        $stderrStream = $nativeProcess.OpenStderrStream()
        $stdoutCopy = $stdoutStream.CopyToAsync($stdoutTarget)
        $stderrCopy = $stderrStream.CopyToAsync($stderrTarget)
    }
    catch {
        $initError = $_.Exception.Message
   }

   if ($null -ne $initError) {
        try {
            if ($null -ne $nativeProcess) {
                $nativeCleanup = $nativeProcess.CloseJobAndWait(10000)
                if (-not [bool]$nativeCleanup.CleanupSucceeded) {
                    $treeError = "PROCESS_GROUP_REAP_FAILED: $($nativeCleanup.Detail)"
                }
            }
        }
        catch {
            $treeError = "PROCESS_GROUP_REAP_FAILED: $($_.Exception.Message)"
        }
    }
    else {
        try {
            $deadline = $started.AddSeconds($TimeoutSeconds)
            while (-not $nativeProcess.HasExited) {
                try {
                    $capturedDescendantRecords = @(Merge-D32ProcessIdentityRecords `
                        -Existing $capturedDescendantRecords `
                        -Incoming (Get-D32DescendantProcessRecords -RootPid $processId))
                    $script:D32LastProcessEvidence.descendant_records = $capturedDescendantRecords
                }
                catch {
                    $treeError = $_.Exception.Message
                    break
                }
                if ([DateTimeOffset]::UtcNow -ge $deadline) {
                    $timedOut = $true
                    break
                }
                Start-Sleep -Milliseconds 250
            }

            $graceSamples = if ($timedOut) { 1 } else { 4 }
            for ($sample = 0; $sample -lt $graceSamples; $sample++) {
                try {
                    $capturedDescendantRecords = @(Merge-D32ProcessIdentityRecords `
                        -Existing $capturedDescendantRecords `
                        -Incoming (Get-D32DescendantProcessRecords -RootPid $processId))
                    $script:D32LastProcessEvidence.descendant_records = $capturedDescendantRecords
                }
                catch {
                    if ($null -eq $treeError) { $treeError = $_.Exception.Message }
                    break
                }
                if ($sample -lt ($graceSamples - 1)) { Start-Sleep -Milliseconds 100 }
            }

            if (-not $timedOut) {
                if (-not $nativeProcess.WaitForExit(1000)) {
                    if ($null -eq $treeError) {
                        $treeError = "PROCESS_EXIT_WAIT_FAILED: root pid $processId did not signal after observed exit"
                    }
                }
                else {
                    $exitCode = [int]$nativeProcess.ExitCode
                }
            }

            if ($timedOut -or $capturedDescendantRecords.Count -gt 0 -or $null -ne $treeError) {
                try {
                    $reap = Stop-D32ProcessTreeAndVerify `
                        -RootRecord $rootIdentity `
                        -CapturedDescendantRecords $capturedDescendantRecords `
                        -NativeProcess $nativeProcess
                    $nativeCleanup = $reap.NativeCleanup
                    $killOutput.AddRange([string[]]@($reap.KillOutput))
                    $residualDescendantRecords = @($reap.ResidualRecords | Where-Object { [int]$_.ProcessId -ne [int]$rootIdentity.ProcessId })
                }
                catch {
                    if ($null -eq $treeError) { $treeError = $_.Exception.Message }
                    else { $treeError = "$treeError; $($_.Exception.Message)" }
                }
            }
        }
        catch {
            $treeError = if ($null -eq $treeError) { $_.Exception.Message } else { "$treeError; $($_.Exception.Message)" }
        }
    }

    try {
        if ($null -ne $nativeProcess -and $null -eq $nativeCleanup) {
            $nativeCleanup = $nativeProcess.CloseJobAndWait(10000)
        }
        if ($null -ne $nativeCleanup -and -not [bool]$nativeCleanup.CleanupSucceeded -and $null -eq $treeError) {
            $treeError = "PROCESS_GROUP_REAP_FAILED: $($nativeCleanup.Detail)"
        }
    }
    catch {
        if ($null -eq $treeError) { $treeError = "PROCESS_GROUP_REAP_FAILED: $($_.Exception.Message)" }
        else { $treeError = "$treeError; PROCESS_GROUP_REAP_FAILED: $($_.Exception.Message)" }
    }
    finally {
        try {
            if ($null -ne $stdoutCopy) { [void]$stdoutCopy.Wait(1000) }
            if ($null -ne $stderrCopy) { [void]$stderrCopy.Wait(1000) }
        }
        catch {
            if ($null -eq $treeError) { $treeError = "PIPE_DRAIN_FAILED: $($_.Exception.Message)" }
            else { $treeError = "$treeError; PIPE_DRAIN_FAILED: $($_.Exception.Message)" }
        }
        foreach ($stream in @($stdoutStream, $stderrStream, $stdoutTarget, $stderrTarget)) {
            if ($null -ne $stream) {
                try { $stream.Dispose() } catch {
                    if ($null -eq $treeError) { $treeError = "PIPE_CLOSE_FAILED: $($_.Exception.Message)" }
                    else { $treeError = "$treeError; PIPE_CLOSE_FAILED: $($_.Exception.Message)" }
                }
            }
        }
        if ($null -ne $nativeProcess) {
            try { $nativeProcess.Dispose() } catch {
                if ($null -eq $treeError) { $treeError = "NATIVE_HANDLE_CLOSE_FAILED: $($_.Exception.Message)" }
                else { $treeError = "$treeError; NATIVE_HANDLE_CLOSE_FAILED: $($_.Exception.Message)" }
            }
        }
    }

    $script:D32LastProcessEvidence.native_cleanup = ConvertTo-D32NativeCleanupDocument $nativeCleanup
    $capturedDescendantPids = @($capturedDescendantRecords | ForEach-Object { [int]$_.ProcessId } | Select-Object -Unique)
    $residualDescendantPids = @($residualDescendantRecords | ForEach-Object { [int]$_.ProcessId } | Select-Object -Unique)
    if ($timedOut) {
        [IO.File]::AppendAllText(
            $stderrPath,
            "`nD32_FIXTURE_PHASE=timeout`nCAPTURED_DESCENDANT_PIDS=$($capturedDescendantPids -join ',')`n$($killOutput -join "`n")`n",
            [Text.UTF8Encoding]::new($false))
    }
    $finished = [DateTimeOffset]::UtcNow
    [IO.File]::AppendAllText(
        $stdoutPath,
        "`nD32_FIXTURE_EXIT_CODE=$exitCode`nD32_FIXTURE_DESCENDANTS=$($capturedDescendantPids -join ',')`n",
        [Text.UTF8Encoding]::new($false))
    return [ordered]@{
        status = if ($null -ne $treeError) { 'process_tree_error' } elseif ($null -ne $initError) { 'spawn_failed' } elseif ($timedOut) { 'timeout' } elseif ($exitCode -eq 0) { 'succeeded' } else { 'failed' }
        exit_code = $exitCode
        pid = $processId
        elapsed_ms = ($finished - $started).TotalMilliseconds
        phase_log = (Get-D32FullPath $PhaseLog)
        stdout_log = (Get-D32FullPath $stdoutPath)
        stderr_log = (Get-D32FullPath $stderrPath)
        root_identity = ConvertTo-D32IdentityDocument $rootIdentity
        root_identity_record = $rootIdentity
        captured_descendant_records = @($capturedDescendantRecords)
        descendant_pids = @($residualDescendantPids)
        captured_descendant_pids = @($capturedDescendantPids)
        descendant_identities = @($capturedDescendantRecords | ForEach-Object { ConvertTo-D32IdentityDocument $_ })
        residual_descendant_identities = @($residualDescendantRecords | ForEach-Object { ConvertTo-D32IdentityDocument $_ })
        native_launch = $script:D32LastProcessEvidence.native_launch
        native_cleanup = ConvertTo-D32NativeCleanupDocument $nativeCleanup
        reap = if ($null -eq $reap) { $null } else {
            [ordered]@{
                process_ids = @($reap.ProcessIds)
                verified_at_utc = $reap.VerifiedAtUtc
                residual_identities = @($reap.ResidualRecords | ForEach-Object { ConvertTo-D32IdentityDocument $_ })
                native_cleanup = ConvertTo-D32NativeCleanupDocument $reap.NativeCleanup
                kill_output = @($reap.KillOutput)
            }
        }
        error = if ($null -ne $treeError) { $treeError } elseif ($null -ne $initError) { $initError } elseif ($timedOut) { 'bounded timeout; process group was killed and every captured identity was reaped' } else { $null }
    }
}

function Get-D32Artifact {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Get-D32FullPath $Path
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "FIXTURE_MISSING: expected fixture output was not produced: $full"
    }
    $item = Get-Item -LiteralPath $full
    $hash = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
    return [ordered]@{
        path   = $item.FullName
        bytes  = [uint64]$item.Length
        sha256 = $hash
    }
}

function Write-D32Manifest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Document
    )

    $temporary = Join-Path (Split-Path -Parent $Path) ('.fixture-manifest.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $json = $Document | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($temporary, $json, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Invoke-D32SelfTest {
    $root = Join-Path ([IO.Path]::GetTempPath()) ('d32-fixture-prebuild-selftest-' + [Guid]::NewGuid().ToString('N'))
    $passed = 0
    $owned = $false
    try {
        [void](Ensure-D32OwnedDirectory $root)
        $owned = $true
        $manifest = Assert-D32ManifestDestination -Path (Join-Path $root 'manifest.json') -OwnedRoot $root
        $sample = Join-Path $root 'sample.bin'
        [IO.File]::WriteAllBytes($sample, [byte[]](1, 2, 3, 4))
        $artifact = Get-D32Artifact $sample
        if ($artifact.bytes -ne 4 -or $artifact.sha256.Length -ne 64) {
            throw 'SELFTEST_FAILED: artifact manifest record'
        }
        $passed++

        $powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
        $encodedExitZero = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes('exit 0')
        )
        $zero = Invoke-D32BoundedProcess `
            -FilePath $powershell `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedExitZero) `
            -WorkingDirectory $root `
            -PhaseLog (Join-Path $root 'zero-phase') `
            -TimeoutSeconds 5
        if ($zero.status -ne 'succeeded' -or $zero.exit_code -ne 0) {
            throw "SELFTEST_FAILED: zero exit code was not captured exactly (status=$($zero.status), exit=$($zero.exit_code), error=$($zero.error))"
        }
        $passed++
        if ($null -eq $zero.native_cleanup -or
            -not [bool]$zero.native_cleanup.cleanup_succeeded -or
            -not [bool]$zero.native_cleanup.job_close_succeeded) {
            throw 'SELFTEST_FAILED: normal exit did not produce verified job-close cleanup evidence'
        }
        $passed++

        $encodedExitSeven = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes('exit 7')
        )
        $nonZero = Invoke-D32BoundedProcess `
            -FilePath $powershell `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedExitSeven) `
            -WorkingDirectory $root `
            -PhaseLog (Join-Path $root 'nonzero-phase') `
            -TimeoutSeconds 5
        if ($nonZero.status -ne 'failed' -or $nonZero.exit_code -ne 7) {
            throw "SELFTEST_FAILED: non-zero exit code was not captured exactly (status=$($nonZero.status), exit=$($nonZero.exit_code))"
        }
        $passed++

        $normalChildScript = Join-Path $root 'descendant-normal.ps1'
        [IO.File]::WriteAllText(
            $normalChildScript,
            "Start-Process -FilePath '$powershell' -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 5' -WindowStyle Hidden | Out-Null`nStart-Sleep -Milliseconds 750`nexit 0`n",
            [Text.UTF8Encoding]::new($false)
        )
        $normalWithChild = Invoke-D32BoundedProcess `
            -FilePath $powershell `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $normalChildScript) `
            -WorkingDirectory $root `
            -PhaseLog (Join-Path $root 'normal-descendant-phase') `
            -TimeoutSeconds 5
        if ($normalWithChild.status -ne 'succeeded' -or
            $normalWithChild.exit_code -ne 0 -or
            @($normalWithChild.captured_descendant_pids).Count -lt 1 -or
            @($normalWithChild.descendant_pids).Count -ne 0 -or
            $null -ne $normalWithChild.error) {
            throw 'SELFTEST_FAILED: normal exit with captured child was not cleanly reaped'
        }
        $normalIdentity = @($normalWithChild.descendant_identities)[0]
        foreach ($field in @('process_id', 'parent_process_id', 'name', 'creation_date', 'command_line', 'observed_at_utc', 'identity_verified')) {
            if (-not $normalIdentity.Contains($field)) {
                throw "SELFTEST_FAILED: descendant identity field was not persisted: $field"
            }
        }
        $passed++

        $nonZeroChildScript = Join-Path $root 'descendant-nonzero.ps1'
        [IO.File]::WriteAllText(
            $nonZeroChildScript,
            "Start-Process -FilePath '$powershell' -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 5' -WindowStyle Hidden | Out-Null`nStart-Sleep -Milliseconds 750`nexit 7`n",
            [Text.UTF8Encoding]::new($false)
        )
        $nonZeroWithChild = Invoke-D32BoundedProcess `
            -FilePath $powershell `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $nonZeroChildScript) `
            -WorkingDirectory $root `
            -PhaseLog (Join-Path $root 'nonzero-descendant-phase') `
            -TimeoutSeconds 5
        if ($nonZeroWithChild.status -ne 'failed' -or
            $nonZeroWithChild.exit_code -ne 7 -or
            @($nonZeroWithChild.captured_descendant_pids).Count -lt 1 -or
            @($nonZeroWithChild.descendant_pids).Count -ne 0 -or
            $null -ne $nonZeroWithChild.error) {
            throw 'SELFTEST_FAILED: non-zero exit with captured child was not cleanly reaped'
        }
        $passed++

        $mismatch = New-D32ProcessIdentityRecord `
            -ProcessId $PID `
            -ParentProcessId $null `
            -Name 'd32-identity-mismatch.exe' `
            -CommandLine 'synthetic mismatch' `
            -CreationDate 'synthetic-mismatch' `
            -ObservedAtUtc ([DateTimeOffset]::UtcNow.ToString('o')) `
            -IdentityVerified $true
        try {
            [void](Test-D32CapturedProcessAlive -Record $mismatch)
            throw 'SELFTEST_FAILED: PID identity mismatch was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'PROCESS_IDENTITY_MISMATCH:*') { throw }
        }
        $passed++

        $outside = Join-Path ([IO.Path]::GetTempPath()) ('d32-fixture-prebuild-outside-' + [Guid]::NewGuid().ToString('N') + '.json')
        try {
            [void](Assert-D32ManifestDestination -Path $outside -OwnedRoot $root)
            throw 'SELFTEST_FAILED: unowned manifest destination was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'OUTPUT_NOT_OWNED:*') {
                throw
            }
        }
        $passed++

        $envPlan = Get-D32EnvironmentPlan (Join-Path $root 'env')
        $realCodexHome = Get-D32FullPath (Join-Path $envPlan.original_userprofile '.codex')
        if ($envPlan.codex_home -eq $envPlan.userprofile -or
            $envPlan.codex_home.Equals($realCodexHome, [StringComparison]::OrdinalIgnoreCase) -or
            $envPlan.userprofile.Equals($envPlan.original_userprofile, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'SELFTEST_FAILED: environment isolation plan'
        }
        $passed++

        $earlyChildPidPath = Join-Path $root 'early-child.pid'
        $earlyChildScript = Join-Path $root 'parent-early-exit.ps1'
        $earlyChildContent = @(
            '$child = Start-Process -FilePath ''{0}'' -ArgumentList ''-NoLogo'',''-NoProfile'',''-NonInteractive'',''-Command'',''Start-Sleep -Seconds 5'' -WindowStyle Hidden -PassThru'
            '[IO.File]::WriteAllText(''{1}'',[string]$child.Id)'
            'exit 0'
        ) -join [Environment]::NewLine
        [IO.File]::WriteAllText($earlyChildScript, ($earlyChildContent -f $powershell, $earlyChildPidPath), [Text.UTF8Encoding]::new($false))
        $earlyExitChild = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $earlyChildScript) -WorkingDirectory $root -PhaseLog (Join-Path $root 'parent-early-exit-phase') -TimeoutSeconds 5
        $earlyChildPid = [int][IO.File]::ReadAllText($earlyChildPidPath)
        if ($earlyExitChild.status -ne 'succeeded' -or
            $earlyExitChild.exit_code -ne 0 -or
            @(Get-D32ProcessSnapshot -ProcessId $earlyChildPid).Count -ne 0 -or
            $null -eq $earlyExitChild.native_cleanup -or
            -not [bool]$earlyExitChild.native_cleanup.cleanup_succeeded) {
            throw 'SELFTEST_FAILED: parent early exit child was not closed by the owned job'
        }
        $passed++

        $detachedChildPidPath = Join-Path $root 'detached-child.pid'
        $detachedChildScript = Join-Path $root 'detached-reparent.ps1'
        $detachedChildContent = @(
            '$child = Start-Process -FilePath ''{0}'' -ArgumentList ''-NoLogo'',''-NoProfile'',''-NonInteractive'',''-Command'',''Start-Sleep -Seconds 5'' -WindowStyle Hidden -PassThru'
            '[IO.File]::WriteAllText(''{1}'',[string]$child.Id)'
            'exit 0'
        ) -join [Environment]::NewLine
        [IO.File]::WriteAllText($detachedChildScript, ($detachedChildContent -f $powershell, $detachedChildPidPath), [Text.UTF8Encoding]::new($false))
        $detachedChild = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $detachedChildScript) -WorkingDirectory $root -PhaseLog (Join-Path $root 'detached-reparent-phase') -TimeoutSeconds 5
        $detachedPid = [int][IO.File]::ReadAllText($detachedChildPidPath)
        if ($detachedChild.status -ne 'succeeded' -or
            @(Get-D32ProcessSnapshot -ProcessId $detachedPid).Count -ne 0 -or
            $null -eq $detachedChild.native_cleanup -or
            -not [bool]$detachedChild.native_cleanup.cleanup_succeeded) {
            throw 'SELFTEST_FAILED: detached/reparented child was not closed by the owned job'
        }
        $passed++

        $spawnInit = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedExitZero) -WorkingDirectory $root -PhaseLog (Join-Path $root 'spawn-init-exception-phase') -TimeoutSeconds 5 -FailureInjection spawn-init
        if ($spawnInit.status -ne 'spawn_failed' -or
            $spawnInit.error -notlike '*SELFTEST_INJECTED_SPAWN_INIT_EXCEPTION*' -or
            $null -eq $spawnInit.native_cleanup -or
            -not [bool]$spawnInit.native_cleanup.cleanup_succeeded) {
            throw 'SELFTEST_FAILED: spawn initialization exception did not close its owned job'
        }
        $passed++

        $cimInit = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedExitZero) -WorkingDirectory $root -PhaseLog (Join-Path $root 'cim-init-exception-phase') -TimeoutSeconds 5 -FailureInjection cim-init
        if ($cimInit.status -ne 'spawn_failed' -or
            $cimInit.error -notlike '*SELFTEST_INJECTED_CIM_INIT_EXCEPTION*' -or
            $null -eq $cimInit.native_cleanup -or
            -not [bool]$cimInit.native_cleanup.cleanup_succeeded) {
            throw 'SELFTEST_FAILED: CIM initialization exception did not close its owned job'
        }
        $passed++

        $pipeInit = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedExitZero) -WorkingDirectory $root -PhaseLog (Join-Path $root 'pipe-init-exception-phase') -TimeoutSeconds 5 -FailureInjection pipe-init
        if ($pipeInit.status -ne 'spawn_failed' -or
            $pipeInit.error -notlike '*SELFTEST_INJECTED_PIPE_INIT_EXCEPTION*' -or
            $null -eq $pipeInit.native_cleanup -or
            -not [bool]$pipeInit.native_cleanup.cleanup_succeeded) {
            throw 'SELFTEST_FAILED: pipe initialization exception did not close its owned job'
        }
        $passed++

        try {
            Assert-D32CleanGitStatus -Status ' M synthetic-dirty-file' -Root $root
            throw 'SELFTEST_FAILED: dirty worktree was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'WORKTREE_DIRTY:*') { throw }
        }
        $passed++

        $missingExecutable = Join-Path $root 'missing-fixture-executable.exe'
        $handleFailure = Invoke-D32BoundedProcess -FilePath $missingExecutable -Arguments @('-NoLogo') -WorkingDirectory $root -PhaseLog (Join-Path $root 'handle-failure-phase') -TimeoutSeconds 5
        if ($handleFailure.status -ne 'spawn_failed' -or
            $handleFailure.error -notlike '*D32_NATIVE_LAUNCH_FAILED*' -or
            $null -ne $handleFailure.pid) {
            throw 'SELFTEST_FAILED: native spawn/handle failure was not fail-closed'
        }
        $passed++

        $childScript = Join-Path $root 'descendant-timeout.ps1'
        [IO.File]::WriteAllText(
            $childScript,
            "Start-Process -FilePath '$powershell' -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 5' -WindowStyle Hidden | Out-Null`nStart-Sleep -Seconds 5`n",
            [Text.UTF8Encoding]::new($false)
        )
        $bounded = Invoke-D32BoundedProcess `
            -FilePath $powershell `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $childScript) `
            -WorkingDirectory $root `
            -PhaseLog (Join-Path $root 'timeout-phase') `
            -TimeoutSeconds 1
        if ($bounded.status -ne 'timeout' -or $bounded.error -notlike '*captured identity*reaped*' -or @($bounded.captured_descendant_pids).Count -lt 1 -or @($bounded.descendant_pids).Count -ne 0) {
            throw 'SELFTEST_FAILED: bounded timeout/tree reap'
        }
        $passed++

        Write-Host "D32_FIXTURE_PREBUILD_SELFTEST PASS ($passed checks)"
    }
    finally {
        if ($owned -and (Test-Path -LiteralPath $root)) {
            Remove-D32OwnedDirectory $root
        }
    }
}

if ($SelfTest) {
    Invoke-D32SelfTest
    exit 0
}

if ([String]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Join-Path $script:ScriptRoot '..'
}
$RepoRoot = Get-D32FullPath $RepoRoot
if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot '.git'))) {
    throw "REPOSITORY_INVALID: not a Git repository root: $RepoRoot"
}

$candidateSha = Get-D32CandidateSha $RepoRoot
if ([String]::IsNullOrWhiteSpace($OutputRoot)) {
    if (-not [String]::IsNullOrWhiteSpace($ManifestPath)) {
        $OutputRoot = Split-Path -Parent (Get-D32FullPath $ManifestPath)
    }
    else {
        $OutputRoot = Join-Path ([IO.Path]::GetTempPath()) (Join-Path 'digital-life-d32-fixtures' $candidateSha)
    }
}
$OutputRoot = Ensure-D32OwnedDirectory $OutputRoot
if ([String]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $OutputRoot 'fixture-manifest.json'
}
$ManifestPath = Assert-D32ManifestDestination -Path $ManifestPath -OwnedRoot $OutputRoot
$logRoot = Ensure-D32OwnedDirectory (Join-Path $OutputRoot 'logs')
$environmentPlan = Get-D32EnvironmentPlan (Join-Path $OutputRoot 'isolated-env')

$gitStatus = Get-D32GitOutput -Root $RepoRoot -Arguments @('status', '--short')
Assert-D32CleanGitStatus -Status $gitStatus -Root $RepoRoot
$cargo = (Get-Command cargo.exe -ErrorAction Stop).Source
$savedEnvironment = Set-D32IsolatedEnvironment -Plan $environmentPlan -Jobs $BuildJobs
$results = @()
$phaseEvidence = @()
$startedAt = [DateTimeOffset]::UtcNow
try {
    $phase = 0
    foreach ($spec in $script:FixtureSpecs) {
        $phase++
        $manifest = Get-D32FullPath (Join-Path $RepoRoot $spec.manifest)
        $artifactPath = Get-D32FullPath (Join-Path $RepoRoot $spec.artifact)
        $arguments = @('build', '--quiet', '--locked', '--manifest-path', $manifest, '--bin', $spec.binary)
        if ($spec.features.Count -gt 0) {
            $arguments += @('--features', ($spec.features -join ' '))
        }
        $phaseLog = Join-Path $logRoot (('{0:D2}-{1}' -f $phase, $spec.name))
        Write-Host "D32_FIXTURE_PHASE=$phase name=$($spec.name) timeout_seconds=$TimeoutSeconds"
        try {
            $processResult = Invoke-D32BoundedProcess `
                -FilePath $cargo `
                -Arguments $arguments `
                -WorkingDirectory $RepoRoot `
                -PhaseLog $phaseLog `
                -TimeoutSeconds $TimeoutSeconds
            $phaseEvidence += [pscustomobject]@{
                root_record = $processResult.root_identity_record
                descendant_records = @($processResult.captured_descendant_records)
            }
            $artifact = $null
            $artifactError = $null
            if ($processResult.status -eq 'succeeded') {
                try {
                    $artifact = Get-D32Artifact $artifactPath
                }
                catch {
                    $artifactError = $_.Exception.Message
                }
            }
            $status = if ($processResult.status -eq 'succeeded' -and $null -ne $artifact) { 'succeeded' } else { $processResult.status }
            if ($null -ne $artifactError) {
                $status = 'artifact_missing'
            }
            $results += [ordered]@{
                phase          = $phase
                name           = $spec.name
                project        = $spec.project
                binary         = $spec.binary
                manifest_path  = $manifest
                features       = @($spec.features)
                command        = ('cargo ' + (ConvertTo-D32CommandLine $arguments))
                status         = $status
                exit_code      = $processResult.exit_code
                pid            = $processResult.pid
                descendant_pids = @($processResult.descendant_pids)
                captured_descendant_pids = @($processResult.captured_descendant_pids)
                root_identity  = $processResult.root_identity
                descendant_identities = @($processResult.descendant_identities)
                residual_descendant_identities = @($processResult.residual_descendant_identities)
                reap           = $processResult.reap
                elapsed_ms     = $processResult.elapsed_ms
                phase_log      = $processResult.phase_log
                stdout_log     = $processResult.stdout_log
                stderr_log     = $processResult.stderr_log
                error          = if ($null -ne $artifactError) { $artifactError } else { $processResult.error }
                artifact       = $artifact
            }
        }
        catch {
            $failureEvidence = $script:D32LastProcessEvidence
            $phaseEvidence += [pscustomobject]@{
                root_record = $failureEvidence.root_record
                descendant_records = @($failureEvidence.descendant_records)
            }
            $results += [ordered]@{
                phase          = $phase
                name           = $spec.name
                project        = $spec.project
                binary         = $spec.binary
                manifest_path  = $manifest
                features       = @($spec.features)
                command        = ('cargo ' + (ConvertTo-D32CommandLine $arguments))
                status         = 'phase_error'
                exit_code      = $null
                pid            = if ($null -eq $failureEvidence.root_record) { $null } else { [int]$failureEvidence.root_record.ProcessId }
                descendant_pids = @()
                captured_descendant_pids = @($failureEvidence.descendant_records | ForEach-Object { [int]$_.ProcessId })
                root_identity  = ConvertTo-D32IdentityDocument $failureEvidence.root_record
                descendant_identities = @($failureEvidence.descendant_records | ForEach-Object { ConvertTo-D32IdentityDocument $_ })
                residual_descendant_identities = @()
                reap           = $null
                elapsed_ms     = $null
                phase_log      = (Get-D32FullPath $phaseLog)
                stdout_log     = (Get-D32FullPath "$phaseLog.stdout.log")
                stderr_log     = (Get-D32FullPath "$phaseLog.stderr.log")
                error          = $_.Exception.Message
                artifact       = $null
            }
        }
    }
}
finally {
    Restore-D32Environment $savedEnvironment
}

$globalProcessError = $null
try {
    [void](Test-D32NoOwnedCargoDescendants -PhaseEvidence $phaseEvidence -CheckName 'final fixture prebuild cleanup')
}
catch {
    $globalProcessError = $_.Exception.Message
}

$phaseTreeErrors = @($results | Where-Object { $_.status -eq 'process_tree_error' } | ForEach-Object { $_.error })
$allProcessErrors = @($phaseTreeErrors)
if ($null -ne $globalProcessError) { $allProcessErrors += $globalProcessError }
$manifestProcessError = if ($allProcessErrors.Count -eq 0) { $null } else { $allProcessErrors -join ' | ' }

$manifestDocument = [ordered]@{
    schema_version = $script:SchemaVersion
    candidate_sha  = $candidateSha
    source_repo = $RepoRoot
    generated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    started_at_utc = $startedAt.ToString('o')
    elapsed_ms = ([DateTimeOffset]::UtcNow - $startedAt).TotalMilliseconds
    working_tree_status = $gitStatus
    build_policy = [ordered]@{
        timeout_seconds = $TimeoutSeconds
        cargo_build_jobs = $BuildJobs
        nested_builds = $false
        process_tree_timeout_action = 'native Job Object kill-on-close, then verify every captured identity and relevant descendant'
    }
    environment = $environmentPlan
    process_tree_check = if ($null -eq $manifestProcessError) { 'succeeded' } else { 'failed' }
    process_tree_error = $manifestProcessError
    fixtures = @($results)
}
Write-D32Manifest -Path $ManifestPath -Document $manifestDocument

$failures = @($results | Where-Object { $_.status -ne 'succeeded' })
$failures += @([pscustomobject]@{ name = 'global-process-tree'; status = 'failed' } | Where-Object { $null -ne $globalProcessError })
Write-Host "D32_FIXTURE_PREBUILD_MANIFEST=$ManifestPath"
if ($failures.Count -gt 0) {
    $summary = ($failures | ForEach-Object { "$($_.name)=$($_.status)" }) -join ', '
    throw "FIXTURE_PREBUILD_BLOCKED: $summary; see manifest and phase logs: $ManifestPath"
}
Write-Host "D32_FIXTURE_PREBUILD PASS: $($results.Count) fixtures candidate=$candidateSha"
