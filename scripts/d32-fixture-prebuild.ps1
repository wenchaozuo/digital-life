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
        [AllowNull()][object[]]$CapturedDescendantRecords = @()
    )

    $records = @(Merge-D32ProcessIdentityRecords -Existing @($RootRecord) -Incoming $CapturedDescendantRecords)
    $killOutput = [System.Collections.Generic.List[string]]::new()
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
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $stdoutPath = "$PhaseLog.stdout.log"
    $stderrPath = "$PhaseLog.stderr.log"
    $started = [DateTimeOffset]::UtcNow
    $commandLine = ConvertTo-D32CommandLine $Arguments
    $process = $null
    $processId = $null
    $rootIdentity = $null
    $capturedDescendantRecords = @()
    $residualDescendantRecords = @()
    $stdoutStream = $null
    $stderrStream = $null
    $stdoutCopy = $null
    $stderrCopy = $null
    $script:D32LastProcessEvidence = [ordered]@{
        root_record = $null
        descendant_records = @()
        started_at_utc = $started.ToString('o')
    }

    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $FilePath
        $startInfo.Arguments = $commandLine
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
        for ($attempt = 0; $attempt -lt 5; $attempt++) {
            $rootCandidates = @(Get-D32ProcessSnapshot -ProcessId $processId)
            if ($rootCandidates.Count -eq 1) {
                $rootIdentity = $rootCandidates[0]
                break
            }
            if ($process.HasExited) { break }
            Start-Sleep -Milliseconds 50
        }
        if ($null -eq $rootIdentity) {
            $rootIdentity = New-D32FallbackProcessIdentity `
                -ProcessId $processId `
                -FilePath $FilePath `
                -CommandLine $commandLine `
                -ObservedAtUtc ([DateTimeOffset]::UtcNow.ToString('o'))
        }
        $script:D32LastProcessEvidence.root_record = $rootIdentity
        $stdoutCopy = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
        $stderrCopy = $process.StandardError.BaseStream.CopyToAsync($stderrStream)
    }
    catch {
        $spawnError = $_.Exception.Message
        $cleanupError = $null
        if ($null -ne $process) {
            try {
                if ($null -eq $rootIdentity) {
                    $rootCandidates = @(Get-D32ProcessSnapshot -ProcessId ([int]$process.Id))
                    if ($rootCandidates.Count -eq 1) { $rootIdentity = $rootCandidates[0] }
                }
                if ($null -ne $rootIdentity -and (Test-D32CapturedProcessAlive -Record $rootIdentity)) {
                    [void](& taskkill.exe /PID ([int]$process.Id) /T /F 2>&1)
                }
                elseif ($null -eq $rootIdentity -and -not $process.HasExited) {
                    $cleanupError = "PROCESS_IDENTITY_UNVERIFIED: refusing to kill unknown process pid $($process.Id) after spawn/capture failure"
                }
            }
            catch {
                $cleanupError = $_.Exception.Message
            }
            if ($null -ne $rootIdentity) { $script:D32LastProcessEvidence.root_record = $rootIdentity }
            $process.Dispose()
        }
        if ($null -ne $stdoutStream) { $stdoutStream.Flush(); $stdoutStream.Close(); $stdoutStream.Dispose() }
        if ($null -ne $stderrStream) { $stderrStream.Flush(); $stderrStream.Close(); $stderrStream.Dispose() }
        return [ordered]@{
            status = if ($null -ne $cleanupError) { 'process_tree_error' } else { 'spawn_failed' }
            exit_code = $null
            pid = $processId
            elapsed_ms = ([DateTimeOffset]::UtcNow - $started).TotalMilliseconds
            phase_log = (Get-D32FullPath $PhaseLog)
            stdout_log = (Get-D32FullPath $stdoutPath)
            stderr_log = (Get-D32FullPath $stderrPath)
            root_identity = ConvertTo-D32IdentityDocument $rootIdentity
            root_identity_record = $rootIdentity
            captured_descendant_records = @()
            descendant_pids = @()
            captured_descendant_pids = @()
            descendant_identities = @()
            residual_descendant_identities = @()
            reap = $null
            error = if ($null -ne $cleanupError) { "$spawnError; $cleanupError" } else { $spawnError }
        }
    }

    $deadline = $started.AddSeconds($TimeoutSeconds)
    $timedOut = $false
    $killOutput = [System.Collections.Generic.List[string]]::new()
    $treeError = $null
    $reap = $null

    while (-not $process.HasExited) {
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
        $process.Refresh()
    }

    # A short post-exit grace captures descendants that were reparented while
    # the root was exiting. Any identity captured in an earlier snapshot is
    # retained and is later checked by PID/name/creation, even after reparent.
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

    $exitCode = $null
    if (-not $timedOut) {
        # Wait on the retained native Process handle before reading ExitCode.
        # Start-Process without -Wait can return a detached wrapper whose
        # ExitCode reads as zero even when the child returned non-zero.
        try {
            [void]$process.WaitForExit()
            $exitCode = [int]$process.ExitCode
        }
        catch {
            if ($null -eq $treeError) { $treeError = "PROCESS_EXIT_CODE_UNAVAILABLE: pid $processId exited but its exit code could not be read: $($_.Exception.Message)" }
        }
    }

    if ($timedOut -or $capturedDescendantRecords.Count -gt 0 -or $null -ne $treeError) {
        try {
            $reap = Stop-D32ProcessTreeAndVerify `
                -RootRecord $rootIdentity `
                -CapturedDescendantRecords $capturedDescendantRecords
            $killOutput.AddRange([string[]]@($reap.KillOutput))
            $residualDescendantRecords = @($reap.ResidualRecords | Where-Object { [int]$_.ProcessId -ne [int]$rootIdentity.ProcessId })
        }
        catch {
            if ($null -eq $treeError) { $treeError = $_.Exception.Message }
            else { $treeError = "$treeError; $($_.Exception.Message)" }
        }
    }

    try {
        if ($null -eq $treeError) {
            if ($null -ne $stdoutCopy) { $stdoutCopy.Wait() }
            if ($null -ne $stderrCopy) { $stderrCopy.Wait() }
        }
        else {
            # A failed tree/identity cleanup must remain bounded; do not wait
            # forever on a pipe that may still be held by an unsafe descendant.
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

    $capturedDescendantPids = @($capturedDescendantRecords | ForEach-Object { [int]$_.ProcessId } | Select-Object -Unique)
    $residualDescendantPids = @($residualDescendantRecords | ForEach-Object { [int]$_.ProcessId } | Select-Object -Unique)
    if ($timedOut) {
        [IO.File]::AppendAllText(
            $stderrPath,
            "`nD32_FIXTURE_PHASE=timeout`nCAPTURED_DESCENDANT_PIDS=$($capturedDescendantPids -join ',')`n$($killOutput -join "`n")`n",
            [Text.UTF8Encoding]::new($false)
        )
    }
    $finished = [DateTimeOffset]::UtcNow
    [IO.File]::AppendAllText(
        $stdoutPath,
        "`nD32_FIXTURE_EXIT_CODE=$exitCode`nD32_FIXTURE_DESCENDANTS=$($capturedDescendantPids -join ',')`n",
        [Text.UTF8Encoding]::new($false)
    )
    return [ordered]@{
        status = if ($null -ne $treeError) { 'process_tree_error' } elseif ($timedOut) { 'timeout' } elseif ($exitCode -eq 0) { 'succeeded' } else { 'failed' }
        exit_code = $exitCode
        pid = $processId
        elapsed_ms = ($finished - $started).TotalMilliseconds
        phase_log = (Get-D32FullPath $PhaseLog)
        stdout_log = (Get-D32FullPath $stdoutPath)
        stderr_log = (Get-D32FullPath $stderrPath)
        root_identity = ConvertTo-D32IdentityDocument $rootIdentity
        root_identity_record = $rootIdentity
        captured_descendant_records = @($capturedDescendantRecords)
        # descendant_pids is intentionally the residual set for compatibility
        # with the fixture preflight contract. The complete captured/reaped
        # evidence is persisted separately and is never discarded.
        descendant_pids = @($residualDescendantPids)
        captured_descendant_pids = @($capturedDescendantPids)
        descendant_identities = @($capturedDescendantRecords | ForEach-Object { ConvertTo-D32IdentityDocument $_ })
        residual_descendant_identities = @($residualDescendantRecords | ForEach-Object { ConvertTo-D32IdentityDocument $_ })
        reap = if ($null -eq $reap) { $null } else {
            [ordered]@{
                process_ids = @($reap.ProcessIds)
                verified_at_utc = $reap.VerifiedAtUtc
                residual_identities = @($reap.ResidualRecords | ForEach-Object { ConvertTo-D32IdentityDocument $_ })
                kill_output = @($reap.KillOutput)
            }
        }
        error = if ($null -ne $treeError) { $treeError } elseif ($timedOut) { 'bounded timeout; process tree was killed and every captured identity was reaped' } else { $null }
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
        process_tree_timeout_action = 'taskkill /T /F then verify every captured descendant PID'
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
