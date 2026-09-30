#Requires -Version 7.5
[CmdletBinding()]
param(
    [string]$Repository,
    [string]$ExpectedCandidateSha,
    [string]$ToolchainProfilePath,
    [string]$ExpectedToolchainProfileSha256,
    [string]$PowerShellModuleAuthorityPath,
    [string]$ExpectedPowerShellModuleAuthoritySha256,
    [string]$PinnedGitPath,
    [string]$PinnedGitSha256
)
. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
$null = Initialize-D32PowerShellModuleAuthority -CallerProfilePath $ToolchainProfilePath `
    -CallerExpectedProfileSha256 $ExpectedToolchainProfileSha256 `
    -CallerModuleAuthorityPath $PowerShellModuleAuthorityPath -CallerExpectedModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
    -CallerCandidateSha $ExpectedCandidateSha -CallerRepository $Repository -CallerGitPath $PinnedGitPath -CallerGitSha256 $PinnedGitSha256 `
    -EntryScriptPath $PSCommandPath
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$descendantCount = 291

$fixtureScript = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-fixture-prebuild.ps1'))
$fixtureLibraryAdmissionPins = [ordered]@{
    RepoRoot = [string]$Repository
    ExpectedCandidateSha = [string]$ExpectedCandidateSha
    ToolchainProfilePath = [string]$ToolchainProfilePath
    ExpectedToolchainProfileSha256 = [string]$ExpectedToolchainProfileSha256
    PowerShellModuleAuthorityPath = [string]$PowerShellModuleAuthorityPath
    ExpectedPowerShellModuleAuthoritySha256 = [string]$ExpectedPowerShellModuleAuthoritySha256
    PinnedGitPath = [string]$PinnedGitPath
    PinnedGitSha256 = [string]$PinnedGitSha256
}
. $fixtureScript -D32LauncherLibraryOnly @fixtureLibraryAdmissionPins

$root = Join-Path ([IO.Path]::GetTempPath()) ('d32-debug-trace-load-' + [Guid]::NewGuid().ToString('N'))
[void](Ensure-D32OwnedDirectory -Path $root)
try {
    $windowsDirectory = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows))
    $systemDirectory = Join-Path $windowsDirectory 'System32'
    $compilerPath = Join-Path $windowsDirectory 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    if (-not (Test-Path -LiteralPath $compilerPath -PathType Leaf)) {
        $compilerPath = Join-Path $windowsDirectory 'Microsoft.NET/Framework/v4.0.30319/csc.exe'
    }
    $wherePath = Join-Path $systemDirectory 'where.exe'
    $conhostPath = Join-Path $systemDirectory 'conhost.exe'
    foreach ($path in @($compilerPath, $wherePath, $conhostPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "SELFTEST_UNAVAILABLE: required Windows test image is missing: $path" }
        [void](Assert-D32NoReparsePath -Path $path)
    }

    $launcherSourcePath = Join-Path $root 'd32-debug-trace-load-launcher.cs'
    $launcherPath = Join-Path $root 'd32-debug-trace-load-launcher.exe'
    $launcherSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

public static class D32DebugTraceLoadLauncher
{
    private static string Quote(string value)
    {
        if (value.Length > 0 && value.IndexOfAny(new char[] { ' ', '\t', '"' }) < 0) return value;
        StringBuilder output = new StringBuilder();
        output.Append('"');
        int slashes = 0;
        foreach (char c in value)
        {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { output.Append('\\', slashes * 2 + 1); output.Append('"'); slashes = 0; continue; }
            output.Append('\\', slashes); slashes = 0; output.Append(c);
        }
        output.Append('\\', slashes * 2); output.Append('"');
        return output.ToString();
    }

    private static Process Start(string image, string[] arguments)
    {
        StringBuilder command = new StringBuilder();
        for (int i = 0; i < arguments.Length; i++)
        {
            if (i != 0) command.Append(' ');
            command.Append(Quote(arguments[i]));
        }
        ProcessStartInfo start = new ProcessStartInfo();
        start.FileName = image;
        start.Arguments = command.ToString();
        start.WorkingDirectory = Environment.CurrentDirectory;
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        return Process.Start(start);
    }

    public static int Main(string[] args)
    {
        if (args == null || args.Length < 2) return 41;
        if (args[0] == "load")
        {
            File.WriteAllText(args[1], "load-root-ran");
            if (args.Length != 3) return 42;
            int count;
            if (!Int32.TryParse(args[2], out count) || (count != 16 && count != 291)) return 43;
            string where = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "where.exe");
            for (int i = 0; i < count; i++)
            {
                using (Process child = Start(where, new string[] { "D32_SELFTEST_NO_MATCH" }))
                {
                    if (child == null || !child.WaitForExit(10000)) return 44;
                }
            }
            return 0;
        }
        if (args[0] == "delayed-marker")
        {
            Thread.Sleep(10000);
            File.WriteAllText(args[1], "delayed-root-ran");
            return 0;
        }
        return 45;
    }
}
'@
    [IO.File]::WriteAllText($launcherSourcePath, $launcherSource, [Text.UTF8Encoding]::new($false))

    $savedLib = [Environment]::GetEnvironmentVariable('LIB', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('LIB', $null, 'Process')
        $compiler = [Diagnostics.ProcessStartInfo]::new()
        $compiler.FileName = $compilerPath
        $compiler.Arguments = ConvertTo-D32CommandLine @('/nologo', "/out:$launcherPath", $launcherSourcePath)
        $compiler.WorkingDirectory = $root
        $compiler.UseShellExecute = $false
        $compiler.CreateNoWindow = $true
        $process = [Diagnostics.Process]::Start($compiler)
        if (-not $process.WaitForExit(30000) -or $process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $launcherPath -PathType Leaf)) {
            throw 'SELFTEST_UNAVAILABLE: the local .NET Framework compiler did not build the benign trace-load launcher'
        }
        $process.Dispose()
    }
    finally { [Environment]::SetEnvironmentVariable('LIB', $savedLib, 'Process') }

    $toPin = {
        param([Parameter(Mandatory = $true)][string]$Path)
        $artifact = Get-D32BoundArtifactWithFileId -Path $Path
        return [PSCustomObject]@{
            Path = [string]$artifact.path
            Bytes = [uint64]$artifact.bytes
            Sha256 = [string]$artifact.sha256
            VolumeSerialHex = [string]$artifact.volume_serial_hex
            FileIdHex = [string]$artifact.file_id_hex
        }
    }
    $launcherPin = ConvertTo-D32DebugImagePinText -Image (& $toPin $launcherPath)
    $wherePin = ConvertTo-D32DebugImagePinText -Image (& $toPin $wherePath)
    $conhostPin = ConvertTo-D32DebugImagePinText -Image (& $toPin $conhostPath)
    $environment = ConvertTo-D32EnvironmentBlock ([ordered]@{
        SystemRoot = $windowsDirectory
        TEMP = $root
        TMP = $root
        PATH = $systemDirectory
    })

    $allowedImagePaths = @($launcherPath, $wherePath, $conhostPath) | ForEach-Object { [IO.Path]::GetFullPath($_) }
    $loadResults = [System.Collections.Generic.List[object]]::new()
    foreach ($count in @(16, $descendantCount)) {
        $loadMarker = Join-Path $root "load-$count-root.marker"
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $load = Invoke-D32DebugSelfTestProcess -FilePath $launcherPath `
            -Arguments @('load', $loadMarker, [string]$count) `
            -WorkingDirectory $root -ExpectedRootPin $launcherPin -ApprovedImagePins @($wherePin, $conhostPin) `
            -EnvironmentBlock $environment -TimeoutMilliseconds 3600000
        $clock.Stop()
        $minimumProcessCount = if ($count -eq 16) { 17 } else { 583 }
        $maximumProcessCount = if ($count -eq 16) { 34 } else { 584 }
        $unexpectedImages = @($load.Trace.Processes | Where-Object {
            $record = $_
            -not [bool]$record.ImageVerified -or -not [bool]$record.Exited -or
            @($allowedImagePaths | Where-Object { [string]::Equals([string]$record.ImagePath, [string]$_, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0
        })
        if ($load.Trace.State -cne 'COMPLETED' -or -not $load.Trace.EventChainComplete -or
            -not $load.Trace.AccountingConsistent -or $load.Trace.ProcessCreateEventCount -lt $minimumProcessCount -or
            $load.Trace.ProcessCreateEventCount -gt $maximumProcessCount -or
            $load.Trace.ProcessExitEventCount -ne $load.Trace.ProcessCreateEventCount -or
            $load.Trace.JobTotalProcesses -ne $load.Trace.ProcessCreateEventCount -or $unexpectedImages.Count -ne 0 -or
            $load.Trace.JobActiveProcesses -ne 0 -or -not $load.Cleanup.CleanupSucceeded -or
            -not $load.Cleanup.DebuggerThreadJoined -or -not $load.Cleanup.RetainedProcessHandlesSignaled -or
            -not $load.Cleanup.DebuggerAssociationAbsent -or [uint32]$load.Cleanup.JobActiveProcessCount -ne 0 -or
            -not (Test-Path -LiteralPath $loadMarker -PathType Leaf)) {
            throw "SELFTEST_FAILED: synthetic $count-descendant process trace did not fully reconcile: creates=$($load.Trace.ProcessCreateEventCount) exits=$($load.Trace.ProcessExitEventCount) job_total=$($load.Trace.JobTotalProcesses) unexpected_images=$($unexpectedImages.Count) active=$($load.Trace.JobActiveProcesses) state=$($load.Trace.State) reason=$($load.Trace.BlockReason) cleanup=$($load.Cleanup.Detail)"
        }
        $loadResults.Add([PSCustomObject]@{ DescendantCount = $count; Trace = $load.Trace; Cleanup = $load.Cleanup; ElapsedMilliseconds = $clock.Elapsed.TotalMilliseconds })
        Write-Output ("D32_TRACE_LOAD=PASS requested_descendants={0} create_exit_processes={1} debug_events={2} process_events={3} elapsed_ms={4:N0} milliseconds_per_event={5:N4} retained_handles={6} job_active={7}" -f `
            $count, $load.Trace.ProcessCreateEventCount, $load.Trace.DebugEventCount, $load.Trace.ProcessEventCount, $clock.Elapsed.TotalMilliseconds,
            ($clock.Elapsed.TotalMilliseconds / [Math]::Max(1, $load.Trace.DebugEventCount)),
            $load.Cleanup.RetainedProcessHandleCount, $load.Trace.JobActiveProcesses)
    }
    $small = $loadResults[0]
    $large = $loadResults[1]
    $eventScale = [double]$large.Trace.DebugEventCount / [Math]::Max(1, [double]$small.Trace.DebugEventCount)
    $timeScale = [double]$large.ElapsedMilliseconds / [Math]::Max(1, [double]$small.ElapsedMilliseconds)
    Write-Output ("D32_TRACE_SCALE=small_to_large events_x={0:N2} time_x={1:N2} normalized_time_per_event_x={2:N2}" -f `
        $eventScale, $timeScale, ($timeScale / [Math]::Max(0.01, $eventScale)))

    $timeoutMarker = Join-Path $root 'timeout-root.marker'
    $timeout = Invoke-D32DebugSelfTestProcess -FilePath $launcherPath `
        -Arguments @('delayed-marker', $timeoutMarker) `
        -WorkingDirectory $root -ExpectedRootPin $launcherPin -ApprovedImagePins @($wherePin, $conhostPin) -EnvironmentBlock $environment `
        -TimeoutMilliseconds 250
    if ($timeout.Trace.State -cne 'BLOCKED' -or $timeout.Trace.BlockReason -notmatch '^WaitForDebugEvent deadline exceeded' -or
        $timeout.Trace.UncontinuedCreateContinueCallCount -ne 0 -or
        (Test-Path -LiteralPath $timeoutMarker) -or -not $timeout.Cleanup.CleanupSucceeded -or
        -not $timeout.Cleanup.ProcessWaitSignaled -or -not $timeout.Cleanup.DebuggerThreadExited -or
        -not $timeout.Cleanup.DebuggerThreadJoined -or -not $timeout.Cleanup.DebuggerKillOnExitEnabled -or
        -not $timeout.Cleanup.RetainedProcessHandlesSignaled -or -not $timeout.Cleanup.DebuggerAssociationQueryVerified -or
        -not $timeout.Cleanup.DebuggerAssociationAbsent -or -not $timeout.Cleanup.JobActiveProcessCountVerified -or
        [uint32]$timeout.Cleanup.JobActiveProcessCount -ne 0) {
        throw "SELFTEST_FAILED: short real wait deadline was not fail-closed with complete cleanup: reason=$($timeout.Trace.BlockReason) continue=$($timeout.ContinueCalls) marker=$([bool](Test-Path -LiteralPath $timeoutMarker)) cleanup=$($timeout.Cleanup.Detail)"
    }
    Write-Output ("D32_TRACE_TIMEOUT_NEGATIVE=PASS real_wait_deadline=true blocked=true continue_calls={0} marker=false debugger_joined={1} handles_signaled={2} debugger_absent={3} job_active={4}" -f `
        $timeout.ContinueCalls, $timeout.Cleanup.DebuggerThreadJoined, $timeout.Cleanup.RetainedProcessHandlesSignaled,
        $timeout.Cleanup.DebuggerAssociationAbsent, $timeout.Cleanup.JobActiveProcessCount)
}
finally {
    if (Test-Path -LiteralPath $root -PathType Container) {
        [void](Assert-D32NoReparsePath -Path $root)
        Remove-D32OwnedDirectory -Path $root
    }
}
