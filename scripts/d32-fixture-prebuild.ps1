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

function Get-D32ProcessSnapshot {
    try {
        return @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
            Select-Object ProcessId, ParentProcessId, Name, CommandLine, CreationDate)
    }
    catch {
        throw "PROCESS_TREE_ENUMERATION_FAILED: $($_.Exception.Message)"
    }
}

function Get-D32DescendantProcessIds {
    param([Parameter(Mandatory = $true)][int]$RootPid)

    $snapshot = Get-D32ProcessSnapshot
    $pending = [System.Collections.Generic.Queue[int]]::new()
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    $pending.Enqueue($RootPid)
    [void]$seen.Add($RootPid)
    $descendants = [System.Collections.Generic.List[int]]::new()
    while ($pending.Count -gt 0) {
        $parent = $pending.Dequeue()
        foreach ($record in $snapshot | Where-Object { [int]$_.ParentProcessId -eq $parent }) {
            $child = [int]$record.ProcessId
            if ($seen.Add($child)) {
                $descendants.Add($child)
                $pending.Enqueue($child)
            }
        }
    }
    return @($descendants)
}

function Test-D32ProcessIdsExited {
    param([Parameter(Mandatory = $true)][int[]]$ProcessIds)

    foreach ($processId in $ProcessIds) {
        if (Get-Process -Id $processId -ErrorAction SilentlyContinue) {
            return $false
        }
    }
    return $true
}

function Test-D32CapturedProcessAlive {
    param([Parameter(Mandatory = $true)][object]$Record)

    $current = @(Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$([int]$Record.ProcessId)" -ErrorAction Stop)
    if ($current.Count -eq 0) { return $false }
    $candidate = $current[0]
    return ([string]$candidate.Name -ceq [string]$Record.Name -and
        [string]$candidate.CreationDate -ceq [string]$Record.CreationDate)
}

function Stop-D32ProcessTreeAndVerify {
    param(
        [Parameter(Mandatory = $true)][int]$RootPid,
        [Parameter(Mandatory = $true)][int[]]$CapturedDescendants
    )

    $captured = @($RootPid) + @($CapturedDescendants) | Select-Object -Unique
    $snapshot = Get-D32ProcessSnapshot
    $records = @($snapshot | Where-Object { $captured -contains [int]$_.ProcessId })
    $rootRecord = @($records | Where-Object { [int]$_.ProcessId -eq $RootPid })
    $killOutput = if ($rootRecord.Count -eq 1) { @(& taskkill.exe /PID $RootPid /T /F 2>&1) } else { @('root process identity was already gone; per-PID verification continues') }
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
    do {
        $alive = @($records | Where-Object { Test-D32CapturedProcessAlive -Record $_ })
        if ($alive.Count -eq 0) {
            return [ordered]@{ ProcessIds = $captured; Residual = @(); KillOutput = @($killOutput) }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    # The recursive taskkill is the first action.  Explicitly target every
    # captured PID once more so a process that detached or raced the tree
    # capture cannot be silently inherited by the next phase.
    foreach ($record in $records) {
        if (Test-D32CapturedProcessAlive -Record $record) {
            $killOutput += @(& taskkill.exe /PID ([int]$record.ProcessId) /F 2>&1)
        }
    }
    Start-Sleep -Milliseconds 250
    $residual = @($records | Where-Object { Test-D32CapturedProcessAlive -Record $_ })
    if ($residual.Count -gt 0) {
        throw "PROCESS_TREE_REAP_FAILED: captured process IDs remained alive after recursive and per-PID kill: $($residual -join ',')"
    }
    return [ordered]@{ ProcessIds = $captured; Residual = @(); KillOutput = @($killOutput) }
}

function Test-D32NoOwnedCargoDescendants {
    param(
        [Parameter(Mandatory = $true)][int[]]$RootPids,
        [Parameter(Mandatory = $true)][string]$CheckName
    )

    $snapshot = Get-D32ProcessSnapshot
    $byParent = @{}
    foreach ($record in $snapshot) {
        $parent = [int]$record.ParentProcessId
        if (-not $byParent.ContainsKey($parent)) { $byParent[$parent] = @() }
        $byParent[$parent] += $record
    }
    $pending = [System.Collections.Generic.Queue[int]]::new()
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($rootPid in $RootPids) { $pending.Enqueue($rootPid) }
    $residual = [System.Collections.Generic.List[object]]::new()
    while ($pending.Count -gt 0) {
        $parent = $pending.Dequeue()
        if (-not $byParent.ContainsKey($parent)) { continue }
        foreach ($record in $byParent[$parent]) {
            $child = [int]$record.ProcessId
            if (-not $seen.Add($child)) { continue }
            $pending.Enqueue($child)
            if ([string]$record.Name -match '^(cargo|rustc)(\.exe)?$') {
                $residual.Add($record)
            }
        }
    }
    if ($residual.Count -gt 0) {
        $details = ($residual | ForEach-Object { "$($_.Name):$($_.ProcessId):parent=$($_.ParentProcessId)" }) -join ', '
        throw "PROCESS_TREE_REAP_FAILED: $CheckName found owned Cargo/rustc descendants: $details"
    }
    return $true
}

function Invoke-D32BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$PhaseLog,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $stdoutPath = "$PhaseLog.stdout.log"
    $stderrPath = "$PhaseLog.stderr.log"
    $started = [DateTimeOffset]::UtcNow
    $process = $null
    $stdoutStream = $null
    $stderrStream = $null
    $stdoutCopy = $null
    $stderrCopy = $null
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $FilePath
        $startInfo.Arguments = ConvertTo-D32CommandLine $Arguments
        $startInfo.WorkingDirectory = $WorkingDirectory
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        $stdoutStream = [IO.File]::Open(
            $stdoutPath,
            [IO.FileMode]::Create,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read
        )
        $stderrStream = [IO.File]::Open(
            $stderrPath,
            [IO.FileMode]::Create,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read
        )
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw "PROCESS_SPAWN_FAILED: process did not start: $FilePath"
        }
        $processId = [int]$process.Id
        $stdoutCopy = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
        $stderrCopy = $process.StandardError.BaseStream.CopyToAsync($stderrStream)
    }
    catch {
        if ($null -ne $process) {
            try {
                if (-not $process.HasExited) {
                    [void](& taskkill.exe /PID $process.Id /T /F 2>&1)
                }
            }
            catch {
                # Preserve the original spawn/capture error.
            }
            $process.Dispose()
        }
        if ($null -ne $stdoutStream) { $stdoutStream.Flush(); $stdoutStream.Close(); $stdoutStream.Dispose() }
        if ($null -ne $stderrStream) { $stderrStream.Flush(); $stderrStream.Close(); $stderrStream.Dispose() }
        return [ordered]@{
            status     = 'spawn_failed'
            exit_code  = $null
            pid        = $null
            elapsed_ms = ([DateTimeOffset]::UtcNow - $started).TotalMilliseconds
            phase_log  = (Get-D32FullPath $PhaseLog)
            stdout_log = (Get-D32FullPath $stdoutPath)
            stderr_log = (Get-D32FullPath $stderrPath)
            error      = $_.Exception.Message
        }
    }

    $deadline = $started.AddSeconds($TimeoutSeconds)
    $timedOut = $false
    $capturedDescendants = @()
    $killOutput = @()
    $treeError = $null
    while (-not $process.HasExited) {
        if ([DateTimeOffset]::UtcNow -ge $deadline) {
            # Capture the complete tree before taskkill can remove the parent;
            # the captured IDs are then checked individually after the kill.
            $capturedDescendants = @(Get-D32DescendantProcessIds -RootPid $process.Id)
            $timedOut = $true
            break
        }
        Start-Sleep -Milliseconds 250
        $process.Refresh()
    }

    if ($timedOut) {
        try {
            $reap = Stop-D32ProcessTreeAndVerify `
                -RootPid $processId `
                -CapturedDescendants $capturedDescendants
            $killOutput = @($reap.KillOutput)
        }
        catch {
            $treeError = $_.Exception.Message
        }
        if ($process.HasExited) { [void]$process.WaitForExit() }
        $exitCode = $null
    }
    else {
        # Wait on the retained native Process handle before reading ExitCode.
        # Start-Process without -Wait can return a detached wrapper whose
        # ExitCode reads as zero even when the child returned non-zero.
        [void]$process.WaitForExit()
        try {
            $exitCode = [int]$process.ExitCode
        }
        catch {
            throw "PROCESS_EXIT_CODE_UNAVAILABLE: pid $processId exited but its exit code could not be read: $($_.Exception.Message)"
        }
        $capturedDescendants = @(Get-D32DescendantProcessIds -RootPid $processId)
        if ($capturedDescendants.Count -gt 0) {
            $reap = Stop-D32ProcessTreeAndVerify `
                -RootPid $processId `
                -CapturedDescendants $capturedDescendants
            $killOutput = @($reap.KillOutput)
            $treeError = "PROCESS_TREE_REAP_FAILED: pid $processId exited with residual descendants: $($capturedDescendants -join ',')"
        }
    }

    try {
        if ($null -eq $treeError) {
            if ($null -ne $stdoutCopy) { $stdoutCopy.Wait() }
            if ($null -ne $stderrCopy) { $stderrCopy.Wait() }
        }
        else {
            # A failed tree reap must remain bounded; do not wait forever on
            # a pipe that may still be held by an unverified descendant.
            if ($null -ne $stdoutCopy) { [void]$stdoutCopy.Wait(1000) }
            if ($null -ne $stderrCopy) { [void]$stderrCopy.Wait(1000) }
        }
    }
    finally {
        if ($null -ne $process) {
            $process.StandardOutput.Close()
            $process.StandardError.Close()
        }
        if ($null -ne $stdoutStream) { $stdoutStream.Flush(); $stdoutStream.Close(); $stdoutStream.Dispose() }
        if ($null -ne $stderrStream) { $stderrStream.Flush(); $stderrStream.Close(); $stderrStream.Dispose() }
        if ($null -ne $process) { $process.Dispose() }
    }

    if ($timedOut) {
        [IO.File]::AppendAllText(
            $stderrPath,
            "`nD32_FIXTURE_PHASE=timeout`nCAPTURED_DESCENDANT_PIDS=$($capturedDescendants -join ',')`n$($killOutput -join "`n")`n",
            [Text.UTF8Encoding]::new($false)
        )
    }
    if ($null -ne $treeError) { throw $treeError }

    $finished = [DateTimeOffset]::UtcNow
    [IO.File]::AppendAllText(
        $stdoutPath,
        "`nD32_FIXTURE_EXIT_CODE=$exitCode`nD32_FIXTURE_DESCENDANTS=$($capturedDescendants -join ',')`n",
        [Text.UTF8Encoding]::new($false)
    )
    return [ordered]@{
        status            = if ($timedOut) { 'timeout' } elseif ($exitCode -eq 0) { 'succeeded' } else { 'failed' }
        exit_code         = $exitCode
        pid               = $processId
        elapsed_ms        = ($finished - $started).TotalMilliseconds
        phase_log         = (Get-D32FullPath $PhaseLog)
        stdout_log        = (Get-D32FullPath $stdoutPath)
        stderr_log        = (Get-D32FullPath $stderrPath)
        descendant_pids   = @($capturedDescendants)
        error             = if ($timedOut) { 'bounded timeout; process tree was killed and every captured PID was reaped' } else { $null }
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
            throw "SELFTEST_FAILED: zero exit code was not captured exactly (status=$($zero.status), exit=$($zero.exit_code))"
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
        if ($bounded.status -ne 'timeout' -or $bounded.error -notlike '*captured PID*reaped*' -or @($bounded.descendant_pids).Count -lt 1) {
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
$cargo = (Get-Command cargo.exe -ErrorAction Stop).Source
$savedEnvironment = Set-D32IsolatedEnvironment -Plan $environmentPlan -Jobs $BuildJobs
$results = @()
$phaseRootPids = @()
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
            if ($null -ne $processResult.pid) {
                $phaseRootPids += [int]$processResult.pid
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
                elapsed_ms     = $processResult.elapsed_ms
                phase_log      = $processResult.phase_log
                stdout_log     = $processResult.stdout_log
                stderr_log     = $processResult.stderr_log
                error          = if ($null -ne $artifactError) { $artifactError } else { $processResult.error }
                artifact       = $artifact
            }
        }
        catch {
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
                pid            = $null
                descendant_pids = @()
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
    [void](Test-D32NoOwnedCargoDescendants -RootPids ([int[]]$phaseRootPids) -CheckName 'final fixture prebuild cleanup')
}
catch {
    $globalProcessError = $_.Exception.Message
}

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
        process_tree_timeout_action = 'taskkill /T /F then verify every captured descendant PID'
    }
    environment = $environmentPlan
    process_tree_check = if ($null -eq $globalProcessError) { 'succeeded' } else { 'failed' }
    process_tree_error = $globalProcessError
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
