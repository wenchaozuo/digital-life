[CmdletBinding()]
param(
    [switch]$Phase0LibraryOnly,
    [Alias('SelfTest')][switch]$Phase0SelfTest,
    [Alias('RepoRoot')][string]$Phase0RepoRoot,
    [Alias('OutputRoot')][string]$Phase0OutputRoot,
    [Alias('ExpectedCandidateSha')][string]$Phase0ExpectedCandidateSha,
    [Alias('ToolchainProfilePath')][string]$Phase0ToolchainProfilePath,
    [Alias('ExpectedToolchainProfileSha256')][string]$Phase0ExpectedToolchainProfileSha256,
    [Alias('PinnedGitPath')][string]$Phase0PinnedGitPath,
    [Alias('PinnedGitSha256')][string]$Phase0PinnedGitSha256,
    [Alias('TimeoutSeconds')][ValidateRange(60, 7200)][int]$Phase0TimeoutSeconds = 1800
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'd32-build-toolchain-profile.ps1')

$script:D32Phase0Type = 'D32_PHASE0_MATRIX_RECORD_V1'
$script:D32Phase0SchemaVersion = 1
$script:D32Phase0Status = 'PASS'
$script:D32Phase0BundleHashes = 'PENDING'
$script:D32Phase0Scope = 'local-fixture-and-test-matrix-only; no release build; no D31 real-process/seeder; no real provider; no physical capture; no host real canary'
$script:D32Phase0DeferredVita = @('d31_c_real_process_crash_recovery_canary')
$script:D32Phase0DeferredHost = @(
    'd31_c_real_process_workspace_replace_canary',
    'd31_c_real_process_workspace_replace_revocation_canary',
    'd31_d_real_process_workspace_patch_canary',
    'd31_d_real_process_workspace_patch_conflict_canary',
    'd31_d_real_process_workspace_patch_revocation_canary',
    'd31_c_real_process_recovery_canary',
    'd31_c_real_process_recovery_revocation_canary',
    'd31_b_real_process_workspace_read_canary',
    'd31_b_real_process_workspace_read_revocation_canary'
)
$script:D32Phase0IgnoredVita = @(
    'd29g2_real_provider_smoke',
    'd29g2_r1_minimal_provider_probe',
    'd29g2_r2_structural_diagnostic',
    'd29g2_r2_role_matrix'
)
$script:D32Phase0IgnoredHost = @(
    'real_windows_picker_production_capture_smoke',
    'real_windows_local_ocr_production_observation_smoke',
    'real_windows_automated_production_capture_smoke'
)
$script:D32Phase0FocusedVita = @(
    'provider_gateway::tests::d32_native_responses_two_round_golden_and_pairing_are_exact',
    'provider_gateway::tests::d32_second_turn_omits_forced_tool_choice',
    'sidecar::tests::d32_forced_tool_latch_requires_exact_two_round_contract',
    'd32a::tests::d32_vita_failure_preserves_primary_and_secondary_cleanup'
)
$script:D32Phase0FocusedHost = @(
    'vita_sidecar::tests::d32_each_host_mode_has_uniform_missing_provider_preflight',
    'vita_sidecar::tests::d32_all_eight_modes_satisfy_the_pure_trace_contract',
    'vita_sidecar::tests::d32_cancel_worker_completion_covers_return_panic_and_scope_cleanup',
    'vita_sidecar::tests::d32_cancel_worker_hang_is_bounded_without_detach_and_can_cleanup',
    'vita_sidecar::tests::d32_a_same_valid_host_grant_replay_is_denied',
    'vita_sidecar::tests::d32_cargo_binding_requires_the_fixed_non_git_marker'
)

function ConvertTo-D32Phase0WindowsArgument {
    param([AllowEmptyString()][string]$Value)

    if ($Value -notmatch '[\s"]') { return $Value }
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append([char]'\', (2 * $slashes + 1))
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) {
            [void]$builder.Append([char]'\', $slashes)
            $slashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) { [void]$builder.Append([char]'\', (2 * $slashes)) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-D32Phase0CommandLine {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    return (($Arguments | ForEach-Object { ConvertTo-D32Phase0WindowsArgument -Value ([string]$_) }) -join ' ')
}

function ConvertTo-D32Phase0EnvironmentBlock {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Environment)
    $items = [System.Collections.Generic.List[string]]::new()
    foreach ($key in @($Environment.Keys | Sort-Object { [string]$_ } -CaseSensitive)) {
        $name = [string]$key
        $value = [string]$Environment[$key]
        if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$' -or $value.Contains("`0")) { throw 'phase0 child environment contains an invalid key/value' }
        $items.Add("$name=$value")
    }
    return (($items -join "`0") + "`0`0")
}

function Get-D32Phase0GitState {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$GitSha256
    )
    $findings = [System.Collections.ArrayList]::new()
    $head = Get-D32Head -Repository $Repository -TrustedGitPath $GitPath -TrustedGitSha256 $GitSha256 -Findings $findings
    $clean = Test-D32GitClean -Repository $Repository -TrustedGitPath $GitPath -TrustedGitSha256 $GitSha256 -Findings $findings
    if (-not (Test-D32Sha40 -Value $head) -or -not $clean) { throw 'PHASE0_CANDIDATE_BLOCKED: exact candidate SHA or clean status failed' }
    return [PSCustomObject]@{ Head = [string]$head; Clean = $true }
}

function Get-D32Phase0ProcessSnapshot {
    try {
        $now = [DateTimeOffset]::UtcNow.ToString('o')
        return @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                process_id = [int]$_.ProcessId
                parent_process_id = if ($null -eq $_.ParentProcessId) { $null } else { [int]$_.ParentProcessId }
                name = if ($null -eq $_.Name) { $null } else { [string]$_.Name }
                image_path = if ($null -eq $_.ExecutablePath) { $null } else { [string]$_.ExecutablePath }
                command_line = if ($null -eq $_.CommandLine) { $null } else { [string]$_.CommandLine }
                creation_date = if ($null -eq $_.CreationDate) { $null } else { [string]$_.CreationDate }
                observed_at_utc = $now
            }
        })
    }
    catch { throw "PHASE0_PROCESS_TREE_BLOCKED: process identity census failed: $($_.Exception.Message)" }
}

function Get-D32Phase0ObservedDescendants {
    param([Parameter(Mandatory = $true)][int]$RootPid, [Parameter(Mandatory = $true)][object[]]$Snapshot)
    $byPid = @{}
    foreach ($item in $Snapshot) { $byPid[[int]$item.process_id] = $item }
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    [void]$seen.Add($RootPid)
    $result = [System.Collections.Generic.List[object]]::new()
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($item in $Snapshot) {
            $pid = [int]$item.process_id
            if ($seen.Contains($pid) -or $null -eq $item.parent_process_id) { continue }
            if ($seen.Contains([int]$item.parent_process_id)) {
                [void]$seen.Add($pid)
                $result.Add($item)
                $changed = $true
            }
        }
    }
    return @($result.ToArray())
}

function ConvertTo-D32Phase0ProcessRecord {
    param(
        [Parameter(Mandatory = $true)][object]$Process,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$Repository
    )
    if ($Process.process_id -le 0 -or $null -eq $Process.parent_process_id -or
        [String]::IsNullOrWhiteSpace([string]$Process.name) -or
        [String]::IsNullOrWhiteSpace([string]$Process.image_path) -or
        [String]::IsNullOrWhiteSpace([string]$Process.command_line) -or
        [String]::IsNullOrWhiteSpace([string]$Process.creation_date)) {
        throw 'PHASE0_PROCESS_TREE_BLOCKED: process identity fields are incomplete'
    }
    $imagePath = [IO.Path]::GetFullPath([string]$Process.image_path)
    $snapshot = Get-D32ProfileFileSnapshot -Path $imagePath
    $allowReason = Get-D32Phase0AllowedChildImageReason -ImagePath $imagePath -ValidatedProfile $ValidatedProfile -Repository $Repository
    if ([String]::IsNullOrWhiteSpace($allowReason)) { throw 'PHASE0_PROCESS_TREE_BLOCKED: unknown child image is outside the pinned toolchain/native inventory and candidate debug targets' }
    $matching = @($ValidatedProfile.ExecutableInventory | Where-Object { Test-D32ProfilePathEqual -Left $_.Path -Right $imagePath })
    if ($matching.Count -gt 1) { throw "PHASE0_PROCESS_TREE_BLOCKED: duplicate pinned process image identity: $imagePath" }
    if ($matching.Count -eq 1) {
        if ($matching[0].Sha256 -cne $snapshot.Sha256 -or $matching[0].Bytes -ne $snapshot.Bytes -or
            $matching[0].VolumeSerialHex -cne $snapshot.VolumeSerialHex -or $matching[0].FileIdHex -cne $snapshot.FileIdHex) {
            throw "PHASE0_PROCESS_TREE_BLOCKED: pinned child process identity changed: $imagePath"
        }
    }
    return [ordered]@{
        process_id = [int]$Process.process_id
        parent_process_id = [int]$Process.parent_process_id
        name = [string]$Process.name
        image_path = $snapshot.Path
        command_line = [string]$Process.command_line
        creation_date = [string]$Process.creation_date
        observed_at_utc = [string]$Process.observed_at_utc
        sha256 = $snapshot.Sha256
        bytes = [Int64]$snapshot.Bytes
        volume_serial_hex = $snapshot.VolumeSerialHex
        file_id_hex = $snapshot.FileIdHex
        allowed_image_reason = $allowReason
        identity_verified = $true
    }
}

function Get-D32Phase0AllowedChildImageReason {
    param([Parameter(Mandatory = $true)][string]$ImagePath, [Parameter(Mandatory = $true)][object]$ValidatedProfile, [Parameter(Mandatory = $true)][string]$Repository)
    $pinned = @($ValidatedProfile.ExecutableInventory | Where-Object { Test-D32ProfilePathEqual -Left $_.Path -Right $ImagePath })
    if ($pinned.Count -eq 1) { return 'caller-pinned-toolchain-or-native-image' }
    if ($pinned.Count -gt 1) { return $null }
    foreach ($relativeTarget in @(
        'vita-agent\target\debug', 'src-tauri\target\debug', 'vita-agent-protocol\target\debug',
        'vita-agent\target\release', 'src-tauri\target\release', 'vita-agent-protocol\target\release'
    )) {
        if (Test-D32ProfilePathWithin -Child $ImagePath -Parent (Join-Path $Repository $relativeTarget)) {
            return 'candidate-owned-target-image-observed-by-opened-handle'
        }
    }
    return $null
}

function Test-D32Phase0SuiteCounts {
    param([Parameter(Mandatory = $true)][object]$Counts, [Parameter(Mandatory = $true)][int64]$TestCount, [Parameter(Mandatory = $true)][int64]$ExpectedIgnored, [Parameter(Mandatory = $true)][int64]$ExpectedFiltered)
    if (-not (Test-D32Phase0ExactProperties -Object $Counts -Expected @('passed', 'failed', 'ignored', 'measured', 'filtered_out'))) { return $false }
    foreach ($field in @('passed', 'failed', 'ignored', 'measured', 'filtered_out')) { if (-not (Test-D32Phase0Integer -Value $Counts.$field)) { return $false } }
    return ([Int64]$Counts.failed -eq 0 -and [Int64]$Counts.ignored -eq $ExpectedIgnored -and [Int64]$Counts.filtered_out -eq $ExpectedFiltered -and ([Int64]$Counts.passed + [Int64]$Counts.ignored + [Int64]$Counts.measured + [Int64]$Counts.filtered_out) -eq $TestCount)
}

function Get-D32Phase0FixtureGitStates {
    param([Parameter(Mandatory = $true)][string[]]$Lines, [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha)
    if ($ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$') { throw 'Phase0 fixture Git-state expected SHA is malformed' }
    $states = [System.Collections.Generic.List[object]]::new()
    foreach ($line in $Lines) {
        if ($line -notmatch '^D32_FIXTURE_GIT_STATE phase=([1-5]) edge=(before|after) head=([0-9a-f]{40}) clean=(true|false)$') { continue }
        $phase = [int]$Matches[1]
        $edge = [string]$Matches[2]
        $head = [string]$Matches[3]
        $clean = [string]$Matches[4] -ceq 'true'
        if ($head -cne $ExpectedCandidateSha -or -not $clean) { throw "PHASE0_FIXTURE_STATE_BLOCKED: phase $phase $edge candidate/clean check failed" }
        $states.Add([ordered]@{ phase = $phase; edge = $edge; head = $head; clean = $clean })
    }
    if ($states.Count -ne 10) { throw "PHASE0_FIXTURE_STATE_BLOCKED: expected 10 per-phase Git-state lines, observed $($states.Count)" }
    $expectedKeys = @()
    for ($phase = 1; $phase -le 5; $phase++) { $expectedKeys += @("$phase|before", "$phase|after") }
    $actualKeys = @($states | ForEach-Object { "$($_.phase)|$($_.edge)" })
    if (($actualKeys -join '|') -cne ($expectedKeys -join '|')) { throw 'PHASE0_FIXTURE_STATE_BLOCKED: per-phase Git-state lines are missing, duplicated, reordered, or extra' }
    return @($states.ToArray())
}

function Get-D32Phase0FixtureLogPaths {
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][object[]]$FixtureRecords,
        [Parameter(Mandatory = $true)][object[]]$LockInputs
    )

    $expectedNames = @('d29h1-authority-fixture', 'd29h7-authority-fixture', 'd29h7-process-fixture', 'd29h7-git-helper-fixture', 'd32a-sandbox-fixture')
    if ($FixtureRecords.Count -ne $expectedNames.Count) { throw 'PHASE0_LOG_BLOCKED: fixture log inventory must contain exactly the five fixed fixture phases' }
    $paths = [System.Collections.Generic.List[string]]::new()
    $logsRoot = Join-Path $OutputRoot 'logs'
    for ($index = 0; $index -lt $expectedNames.Count; $index++) {
        $record = $FixtureRecords[$index]
        if ($null -eq $record -or $record.name -isnot [string] -or $record.name -cne $expectedNames[$index]) { throw "PHASE0_LOG_BLOCKED: fixture log phase name/order differs at index $index" }
        $stem = Join-Path $logsRoot ('{0:D2}-{1}' -f ($index + 1), $expectedNames[$index])
        if ($record.phase_log -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $record.phase_log -Right $stem) -or
            $record.stdout_log -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $record.stdout_log -Right ($stem + '.stdout.log')) -or
            $record.stderr_log -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $record.stderr_log -Right ($stem + '.stderr.log'))) {
            throw "PHASE0_LOG_BLOCKED: fixed fixture log paths differ at index $index"
        }
        # phase_log is a filename stem, not an emitted file. Only the actual
        # bounded-process stdout/stderr captures are evidence files.
        $paths.Add([IO.Path]::GetFullPath($record.stdout_log))
        $paths.Add([IO.Path]::GetFullPath($record.stderr_log))
    }
    for ($index = 0; $index -lt $LockInputs.Count; $index++) {
        $stem = Join-Path $logsRoot ('fixture-{0:D2}-fetch' -f ($index + 1))
        $paths.Add([IO.Path]::GetFullPath($stem + '.stdout.log'))
        $paths.Add([IO.Path]::GetFullPath($stem + '.stderr.log'))
    }
    return @($paths.ToArray())
}

function Test-D32Phase0ExecutedCommandEvidence {
    param([Parameter(Mandatory = $true)][object]$Document)
    $inventory = $Document.test_inventory
    $commandByName = @{}
    foreach ($command in $Document.commands) {
        if ($commandByName.ContainsKey([string]$command.name)) { throw 'Phase0 command log evidence contains duplicate names' }
        $commandByName[[string]$command.name] = $command
    }
    foreach ($package in @('protocol', 'vita', 'host')) {
        foreach ($kind in @('test-list', 'ignored-list')) {
            $name = "$package-$kind"
            if (-not $commandByName.ContainsKey($name)) { throw "Phase0 actual command evidence is missing $name" }
            $lines = @(Get-D32Phase0TextFromLogs -CommandRecord $commandByName[$name])
            $declared = if ($kind -eq 'test-list') { @($inventory.$package.test_names) } else { @($inventory.$package.ignored_names) }
            $isIgnoredList = $kind -eq 'ignored-list'
            if (-not (Test-D32Phase0ExactTestListOutput -Lines $lines -Expected $declared -Ignored:$isIgnoredList)) { throw "Phase0 $package $kind names do not match the captured command logs" }
        }
        $suiteName = "$package-full-local-suite"
        if (-not $commandByName.ContainsKey($suiteName)) { throw "Phase0 actual command evidence is missing $suiteName" }
        $suite = @($Document.local_suites | Where-Object { $_.package -ceq $package })
        if ($suite.Count -ne 1) { throw "Phase0 suite result is missing/duplicated for $package" }
        $suiteLines = @(Get-D32Phase0TextFromLogs -CommandRecord $commandByName[$suiteName])
        $summaries = @(Get-D32Phase0Summaries -Lines $suiteLines)
        if ($summaries.Count -eq 0 -or $summaries.Count -ne $suite[0].summary_count -or @($summaries | Where-Object { $_.status -cne 'ok' }).Count -ne 0) { throw "Phase0 $package suite summaries do not match its captured logs" }
        $actualCounts = [ordered]@{
            passed = [Int64](($summaries | Measure-Object -Property passed -Sum).Sum)
            failed = [Int64](($summaries | Measure-Object -Property failed -Sum).Sum)
            ignored = [Int64](($summaries | Measure-Object -Property ignored -Sum).Sum)
            measured = [Int64](($summaries | Measure-Object -Property measured -Sum).Sum)
            filtered_out = [Int64](($summaries | Measure-Object -Property filtered_out -Sum).Sum)
        }
        if (-not (Test-D32Phase0SuiteCounts -Counts $suite[0].counts -TestCount ([Int64]$inventory.$package.test_count) -ExpectedIgnored ([Int64]$inventory.$package.ignored_count) -ExpectedFiltered ([Int64]$suite[0].exact_deferred_skip_count))) { throw "Phase0 $package suite count record is invalid" }
        foreach ($field in @('passed', 'failed', 'ignored', 'measured', 'filtered_out')) { if ([Int64]$suite[0].counts.$field -ne [Int64]$actualCounts[$field]) { throw "Phase0 $package suite $field count differs from actual test-result logs" } }
    }
    foreach ($package in @('vita', 'host')) {
        $suffixes = if ($package -eq 'vita') { $script:D32Phase0FocusedVita } else { $script:D32Phase0FocusedHost }
        foreach ($suffix in $suffixes) {
            $names = @($inventory.$package.test_names | Where-Object { $_.EndsWith($suffix, [StringComparison]::Ordinal) })
            if ($names.Count -ne 1) { throw "Phase0 focused test name is no longer unique in inventory: $suffix" }
            $fullName = [string]$names[0]
            $commandName = "$package-focused-$($fullName.Split('::')[-1])"
            if (-not $commandByName.ContainsKey($commandName)) { throw "Phase0 focused command log is missing: $commandName" }
            $records = @($Document.focused_tests | Where-Object { $_.package -ceq $package -and $_.full_name -ceq $fullName })
            if ($records.Count -ne 1 -or -not (Test-D32Phase0ExactProperties -Object $records[0] -Expected @('package', 'full_name', 'command', 'status', 'passed', 'failed')) -or $records[0].status -cne 'PASS' -or $records[0].command -cne $commandName -or -not (Test-D32Phase0Integer -Value $records[0].passed) -or -not (Test-D32Phase0Integer -Value $records[0].failed)) { throw "Phase0 focused result record is malformed: $fullName" }
            $focusedLines = @(Get-D32Phase0TextFromLogs -CommandRecord $commandByName[$commandName])
            $focusedSummaries = @(Get-D32Phase0Summaries -Lines $focusedLines)
            $passed = [Int64](($focusedSummaries | Measure-Object -Property passed -Sum).Sum)
            $failed = [Int64](($focusedSummaries | Measure-Object -Property failed -Sum).Sum)
            $ignored = [Int64](($focusedSummaries | Measure-Object -Property ignored -Sum).Sum)
            if ($focusedSummaries.Count -eq 0 -or @($focusedSummaries | Where-Object { $_.status -cne 'ok' }).Count -ne 0 -or $passed -ne 1 -or $failed -ne 0 -or $ignored -ne 0 -or [Int64]$records[0].passed -ne $passed -or [Int64]$records[0].failed -ne $failed) { throw "Phase0 focused test log is not exactly one passing execution: $fullName" }
        }
    }
    return $true
}

function Invoke-D32Phase0PinnedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Environment,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$GitSha256
    )
    if (-not ('D32FixtureNativeProcessV2' -as [type])) { throw 'PHASE0_PROCESS_TREE_BLOCKED: fixture Job Object launcher was not initialized' }
    $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $ValidatedProfile
    $pre = Get-D32Phase0GitState -Repository $Repository -GitPath $GitPath -GitSha256 $GitSha256
    if ($pre.Head -cne $ExpectedCandidateSha) { throw 'PHASE0_CANDIDATE_BLOCKED: HEAD changed before a fixed command' }
    $image = Get-D32ProfileFileSnapshot -Path $Executable
    $expectedTool = @($ValidatedProfile.ExecutableInventory | Where-Object { Test-D32ProfilePathEqual -Left $_.Path -Right $Executable })
    if ($expectedTool.Count -ne 1 -or $expectedTool[0].Sha256 -cne $image.Sha256 -or $expectedTool[0].Bytes -ne $image.Bytes -or $expectedTool[0].VolumeSerialHex -cne $image.VolumeSerialHex -or $expectedTool[0].FileIdHex -cne $image.FileIdHex) {
        throw "PHASE0_TOOL_IDENTITY_BLOCKED: executable is not the current pinned image: $Executable"
    }
    if (Test-Path -LiteralPath $LogPath) { throw "PHASE0_LOG_BLOCKED: refusing to overwrite command output: $LogPath" }
    $stdoutPath = "$LogPath.stdout.log"
    $stderrPath = "$LogPath.stderr.log"
    if ((Test-Path -LiteralPath $stdoutPath) -or (Test-Path -LiteralPath $stderrPath)) { throw 'PHASE0_LOG_BLOCKED: stdout/stderr log path already exists' }
    $commandArguments = @($Executable) + @($Arguments)
    $commandLine = ConvertTo-D32Phase0CommandLine -Arguments $commandArguments
    $environmentBlock = ConvertTo-D32Phase0EnvironmentBlock -Environment $Environment
    $started = [DateTimeOffset]::UtcNow
    $native = $null
    $stdoutTarget = $null
    $stderrTarget = $null
    $stdoutStream = $null
    $stderrStream = $null
    $stdoutCopy = $null
    $stderrCopy = $null
    $cleanup = $null
    $rootSnapshot = $null
    $descendants = [ordered]@{}
    $exitCode = $null
    $timedOut = $false
    $failure = $null
    try {
        $native = [D32FixtureNativeProcessV2]::Start($Executable, $commandLine, $WorkingDirectory, $environmentBlock, '')
        $rootPid = [int]$native.ProcessId
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            $rootSnapshot = @(Get-D32Phase0ProcessSnapshot | Where-Object { $_.process_id -eq $rootPid } | Select-Object -First 1)
            if ($rootSnapshot.Count -eq 1) { $rootSnapshot = $rootSnapshot[0]; break }
            if ($native.HasExited) { break }
            Start-Sleep -Milliseconds 50
        }
        if ($null -eq $rootSnapshot -or $rootSnapshot -is [Array]) { throw 'PHASE0_PROCESS_TREE_BLOCKED: root process identity could not be observed' }
        if ($rootSnapshot.parent_process_id -ne $PID) { throw 'PHASE0_PROCESS_TREE_BLOCKED: fixed command parent is not the pinned current PowerShell host' }
        $rootRecord = ConvertTo-D32Phase0ProcessRecord -Process $rootSnapshot -ValidatedProfile $ValidatedProfile -Repository $Repository
        if (-not (Test-D32ProfilePathEqual -Left $rootRecord.image_path -Right $image.Path) -or $rootRecord.sha256 -cne $image.Sha256 -or
            $rootRecord.volume_serial_hex -cne $image.VolumeSerialHex -or $rootRecord.file_id_hex -cne $image.FileIdHex -or
            $rootRecord.command_line -cne $commandLine) {
            throw 'PHASE0_PROCESS_IDENTITY_BLOCKED: root executable path/hash/file ID/argv mismatch'
        }
        $stdoutTarget = [IO.File]::Open($stdoutPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $stderrTarget = [IO.File]::Open($stderrPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $stdoutStream = $native.OpenStdoutStream()
        $stderrStream = $native.OpenStderrStream()
        $stdoutCopy = $stdoutStream.CopyToAsync($stdoutTarget)
        $stderrCopy = $stderrStream.CopyToAsync($stderrTarget)
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
        while (-not $native.HasExited) {
            $observed = Get-D32Phase0ProcessSnapshot
            foreach ($child in @(Get-D32Phase0ObservedDescendants -RootPid $rootPid -Snapshot $observed)) {
                $key = "$($child.process_id)|$($child.creation_date)"
                if (-not $descendants.Contains($key)) {
                    $descendants[$key] = ConvertTo-D32Phase0ProcessRecord -Process $child -ValidatedProfile $ValidatedProfile -Repository $Repository
                }
            }
            if ([DateTimeOffset]::UtcNow -ge $deadline) { $timedOut = $true; break }
            Start-Sleep -Milliseconds 150
        }
        if (-not $native.HasExited) { $timedOut = $true }
        if ($native.HasExited) { $exitCode = [int]$native.ExitCode }
        $cleanup = $native.CloseJobAndWait(15000)
        if (-not $cleanup.CleanupSucceeded -or [uint32]$cleanup.JobActiveProcessCount -ne 0) {
            throw 'PHASE0_PROCESS_TREE_BLOCKED: Job Object did not prove zero remaining processes'
        }
        if (-not $stdoutCopy.Wait(15000) -or -not $stderrCopy.Wait(15000) -or $stdoutCopy.IsFaulted -or $stderrCopy.IsFaulted) {
            throw 'PHASE0_LOG_BLOCKED: stdout/stderr drain failed'
        }
        if ($timedOut) { throw "PHASE0_COMMAND_TIMEOUT: $Name exceeded $TimeoutSeconds seconds; Job Object reaped the process group" }
    }
    catch {
        $failure = $_.Exception.Message
        if ($null -ne $native -and $null -eq $cleanup) {
            try { $cleanup = $native.CloseJobAndWait(15000) } catch { $failure += '; cleanup=' + $_.Exception.Message }
        }
    }
    finally {
        foreach ($stream in @($stdoutStream, $stderrStream, $stdoutTarget, $stderrTarget)) {
            if ($null -ne $stream) { try { $stream.Dispose() } catch { if ($null -eq $failure) { $failure = 'PHASE0_LOG_BLOCKED: stream close failed' } } }
        }
        if ($null -ne $native) { try { $native.Dispose() } catch { if ($null -eq $failure) { $failure = 'PHASE0_PROCESS_TREE_BLOCKED: native launcher close failed' } } }
    }
    if ($null -eq $cleanup -or -not [bool]$cleanup.CleanupSucceeded -or [uint32]$cleanup.JobActiveProcessCount -ne 0) {
        throw 'PHASE0_PROCESS_TREE_BLOCKED: no completed Job Object process-tree cleanup evidence'
    }
    $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $ValidatedProfile
    $post = Get-D32Phase0GitState -Repository $Repository -GitPath $GitPath -GitSha256 $GitSha256
    if ($post.Head -cne $ExpectedCandidateSha) { throw 'PHASE0_CANDIDATE_BLOCKED: HEAD changed after a fixed command' }
    if ($null -ne $failure) { throw $failure }
    if ($exitCode -ne 0) { throw "PHASE0_COMMAND_FAILED: $Name exit_code=$exitCode" }
    $stdoutRef = Get-D32Phase0FileReference -Path $stdoutPath
    $stderrRef = Get-D32Phase0FileReference -Path $stderrPath
    return [ordered]@{
        name = $Name
        executable = $image.Path
        executable_sha256 = $image.Sha256
        executable_bytes = [Int64]$image.Bytes
        executable_volume_serial_hex = $image.VolumeSerialHex
        executable_file_id_hex = $image.FileIdHex
        argv = @($Executable) + @($Arguments)
        arguments = @($Arguments)
        command_line = $commandLine
        working_directory = [IO.Path]::GetFullPath($WorkingDirectory)
        candidate_sha_before = $pre.Head
        clean_before = $true
        started_at_utc = $started.ToString('o')
        completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        exit_code = [int]$exitCode
        root_process = $rootRecord
        descendant_processes = @($descendants.Values)
        process_tree_cleanup = [ordered]@{
            launch_mode = [string]$native.LaunchMode
            job_close_succeeded = [bool]$cleanup.JobCloseSucceeded
            process_wait_signaled = [bool]$cleanup.ProcessWaitSignaled
            active_process_count_verified = [bool]$cleanup.JobActiveProcessCountVerified
            active_process_count = [uint32]$cleanup.JobActiveProcessCount
            cleanup_succeeded = [bool]$cleanup.CleanupSucceeded
            detail = [string]$cleanup.Detail
        }
        stdout = $stdoutRef
        stderr = $stderrRef
        candidate_sha_after = $post.Head
        clean_after = $true
    }
}

function Invoke-D32Phase0LoggedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][ref]$Ordinal,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$Records,
        [Parameter(Mandatory = $true)][string]$LogRoot,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Environment,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$GitSha256
    )
    $Ordinal.Value++
    $safeName = $Name -replace '[^A-Za-z0-9._-]', '_'
    $record = Invoke-D32Phase0PinnedProcess `
        -Name $Name -Executable $Executable -Arguments $Arguments `
        -WorkingDirectory $Repository `
        -LogPath (Join-Path $LogRoot ('phase0-{0:D2}-{1}' -f $Ordinal.Value, $safeName)) `
        -Environment $Environment -TimeoutSeconds $TimeoutSeconds `
        -ValidatedProfile $ValidatedProfile -Repository $Repository `
        -ExpectedCandidateSha $ExpectedCandidateSha -GitPath $GitPath -GitSha256 $GitSha256
    $Records.Add($record)
    return $record
}

function Get-D32Phase0FileReference {
    param([Parameter(Mandatory = $true)][string]$Path)
    $snapshot = Get-D32ProfileFileSnapshot -Path $Path
    return [ordered]@{
        path = $snapshot.Path
        bytes = [Int64]$snapshot.Bytes
        sha256 = $snapshot.Sha256
        volume_serial_hex = $snapshot.VolumeSerialHex
        file_id_hex = $snapshot.FileIdHex
    }
}

function Test-D32Phase0JsonElementDuplicateKeys {
    param([Parameter(Mandatory = $true)][System.Text.Json.JsonElement]$Element, [int]$Depth = 0)
    if ($Depth -gt 64) { return $true }
    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) { return $true }
            if (Test-D32Phase0JsonElementDuplicateKeys -Element $property.Value -Depth ($Depth + 1)) { return $true }
        }
    }
    elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            if (Test-D32Phase0JsonElementDuplicateKeys -Element $item -Depth ($Depth + 1)) { return $true }
        }
    }
    return $false
}

function Test-D32Phase0JsonDuplicateKeys {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Json)
    $document = $null
    try {
        $options = [System.Text.Json.JsonDocumentOptions]::new()
        $options.MaxDepth = 64
        $document = [System.Text.Json.JsonDocument]::Parse($Json, $options)
        return Test-D32Phase0JsonElementDuplicateKeys -Element $document.RootElement
    }
    catch { return $true }
    finally { if ($null -ne $document) { $document.Dispose() } }
}

function ConvertFrom-D32Phase0Json {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$Json)
    process {
        $converter = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
        if (-not $converter.Parameters.ContainsKey('DateKind')) { throw 'D32 Phase0 requires PowerShell 7.5 or newer for timestamp-preserving JSON parsing' }
        return $Json | ConvertFrom-Json -DateKind String
    }
}

function Test-D32Phase0ExactProperties {
    param([AllowNull()][object]$Object, [Parameter(Mandatory = $true)][string[]]$Expected)
    if ($null -eq $Object -or $Object -is [string] -or $Object -is [Array] -or $Object -is [ValueType]) { return $false }
    $actual = @($Object.PSObject.Properties | ForEach-Object { [string]$_.Name })
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) { if ($actual -cnotcontains $name) { return $false } }
    return $true
}

function Test-D32Phase0Integer {
    param([AllowNull()][object]$Value, [switch]$Positive)
    $valid = $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [uint16] -or $Value -is [int16] -or $Value -is [uint32] -or $Value -is [int32] -or $Value -is [uint64] -or $Value -is [int64]
    if (-not $valid) { return $false }
    if ($Positive) { return [Int64]$Value -gt 0 }
    return [Int64]$Value -ge 0
}

function Test-D32Phase0FileReference {
    param([AllowNull()][object]$Reference, [Parameter(Mandatory = $true)][string]$AllowedRoot)
    if (-not (Test-D32Phase0ExactProperties -Object $Reference -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) { throw 'Phase0 file reference has missing/extra fields' }
    foreach ($name in @('path', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ($Reference.$name -isnot [string]) { throw "Phase0 file reference $name must be a JSON string" } }
    if (-not (Test-D32Phase0Integer -Value $Reference.bytes) -or $Reference.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $Reference.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or $Reference.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { throw 'Phase0 file reference hash/size/identity scalar is malformed' }
    if (-not (Test-D32ProfileCanonicalPathString -Path $Reference.path) -or -not (Test-D32ProfilePathWithin -Child $Reference.path -Parent $AllowedRoot)) { throw 'Phase0 file reference path is outside its approved root or non-canonical' }
    $actual = Get-D32ProfileFileSnapshot -Path $Reference.path
    if ($actual.Bytes -ne [Int64]$Reference.bytes -or $actual.Sha256 -cne $Reference.sha256 -or $actual.VolumeSerialHex -cne $Reference.volume_serial_hex -or $actual.FileIdHex -cne $Reference.file_id_hex) { throw 'Phase0 referenced file bytes or opened-handle identity changed' }
    return $actual
}

function Test-D32Phase0FixtureBuildProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$SidecarPath,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][int]$ExpectedRunnerProcessId,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile
    )
    $expectedSidecar = [IO.Path]::GetFullPath((Join-Path $OutputRoot 'fixture-build-provenance.json'))
    if (-not (Test-D32ProfilePathEqual -Left $SidecarPath -Right $expectedSidecar) -or -not (Test-D32ProfileNoReparsePath -Path $expectedSidecar)) { throw 'PHASE0_FIXTURE_BLOCKED: fixture build provenance sidecar path is not the fixed external regular file' }
    $sidecarReference = Get-D32Phase0FileReference -Path $expectedSidecar
    $raw = [IO.File]::ReadAllText($expectedSidecar, [Text.Encoding]::UTF8)
    if (Test-D32Phase0JsonDuplicateKeys -Json $raw) { throw 'PHASE0_FIXTURE_BLOCKED: fixture build provenance sidecar has duplicate or invalid JSON keys' }
    $document = $raw | ConvertFrom-D32Phase0Json
    $topFields = @('schema_version', 'record_type', 'candidate_sha', 'source_repo', 'fixture_manifest_path', 'fixture_manifest_sha256', 'fixture_manifest_bytes', 'fixture_manifest_volume_serial_hex', 'fixture_manifest_file_id_hex', 'environment')
    if (-not (Test-D32Phase0ExactProperties -Object $document -Expected $topFields) -or -not (Test-D32Phase0Integer -Value $document.schema_version) -or [Int64]$document.schema_version -ne 1 -or
        $document.record_type -isnot [string] -or $document.record_type -cne 'D32_FIXTURE_BUILD_PROVENANCE_V1' -or
        $document.candidate_sha -isnot [string] -or $document.candidate_sha -cne $ExpectedCandidateSha -or
        $document.source_repo -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $document.source_repo -Right $Repository) -or
        $document.fixture_manifest_path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $document.fixture_manifest_path -Right $ManifestPath) -or
        $document.fixture_manifest_sha256 -isnot [string] -or $document.fixture_manifest_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $document.fixture_manifest_volume_serial_hex -isnot [string] -or $document.fixture_manifest_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        $document.fixture_manifest_file_id_hex -isnot [string] -or $document.fixture_manifest_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        -not (Test-D32Phase0Integer -Value $document.fixture_manifest_bytes -Positive)) { throw 'PHASE0_FIXTURE_BLOCKED: fixture build provenance sidecar schema/candidate/source/manifest binding is invalid' }
    $manifestSnapshot = Get-D32ProfileFileSnapshot -Path $ManifestPath
    if ([Int64]$document.fixture_manifest_bytes -ne [Int64]$manifestSnapshot.Bytes -or $document.fixture_manifest_sha256 -cne $manifestSnapshot.Sha256 -or
        $document.fixture_manifest_volume_serial_hex -cne $manifestSnapshot.VolumeSerialHex -or $document.fixture_manifest_file_id_hex -cne $manifestSnapshot.FileIdHex) { throw 'PHASE0_FIXTURE_BLOCKED: sidecar does not bind current fixture manifest bytes and opened-handle identity' }
    $environmentFields = @('toolchain_profile_path', 'toolchain_profile_sha256', 'target_triple', 'env_policy', 'cargo_policy', 'cargo_home', 'temp_root', 'run_id', 'fetch_manifests', 'offline_after_fetch')
    $environment = $document.environment
    if (-not (Test-D32Phase0ExactProperties -Object $environment -Expected $environmentFields)) { throw 'PHASE0_FIXTURE_BLOCKED: fixture build environment sidecar schema has missing or extra fields' }
    foreach ($field in @('toolchain_profile_path', 'toolchain_profile_sha256', 'target_triple', 'env_policy', 'cargo_policy', 'cargo_home', 'temp_root', 'run_id')) {
        if ($environment.$field -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$environment.$field)) { throw "PHASE0_FIXTURE_BLOCKED: sidecar environment $field must be a nonempty JSON string" }
    }
    if ($environment.run_id -cnotmatch '^[0-9a-f]{32}$') { throw 'PHASE0_FIXTURE_BLOCKED: fixture sidecar run_id must be a lowercase 32-hex fresh-run identifier' }
    if (-not (Test-D32ProfilePathEqual -Left $environment.toolchain_profile_path -Right $ValidatedProfile.ProfilePath) -or $environment.toolchain_profile_sha256 -cne $ValidatedProfile.Digest -or
        $environment.target_triple -cne [string]$ValidatedProfile.Profile.target_triple -or $environment.env_policy -cne [string]$ValidatedProfile.Profile.env_policy -or
        $environment.cargo_policy -cne [string]$ValidatedProfile.Profile.cargo_policy -or $environment.offline_after_fetch -isnot [bool] -or -not $environment.offline_after_fetch) { throw 'PHASE0_FIXTURE_BLOCKED: fixture sidecar profile/target/policy binding differs from current caller-pinned profile' }
    foreach ($pathField in @('cargo_home', 'temp_root')) {
        if (-not (Test-D32ProfileCanonicalPathString -Path $environment.$pathField) -or -not (Test-D32ProfileNoReparsePath -Path $environment.$pathField) -or -not (Test-D32ProfilePathWithin -Child $environment.$pathField -Parent $OutputRoot)) { throw "PHASE0_FIXTURE_BLOCKED: fixture sidecar $pathField must be a canonical regular directory beneath OutputRoot" }
    }
    $cargoHomeParent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($environment.cargo_home))
    $tempRootParent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($environment.temp_root))
    if (-not (Test-D32ProfilePathEqual -Left $cargoHomeParent -Right $tempRootParent)) { throw 'PHASE0_FIXTURE_BLOCKED: fixture Cargo home and temp must be siblings under one fresh run root' }
    if ([IO.Path]::GetFileName($cargoHomeParent) -cne "fixture-toolchain-run-$($environment.run_id)") { throw 'PHASE0_FIXTURE_BLOCKED: fixture run root folder does not bind the exact generated run_id' }
    if ($environment.fetch_manifests -isnot [Array] -or $environment.fetch_manifests.Count -ne $ValidatedProfile.LockInputs.Count) { throw 'PHASE0_FETCH_BLOCKED: fixture sidecar fetch array/count differs from the exact locked manifest inventory' }
    $fetchProcessIds = [System.Collections.Generic.HashSet[int]]::new()
    for ($i = 0; $i -lt $ValidatedProfile.LockInputs.Count; $i++) {
        $fetch = $environment.fetch_manifests[$i]
        $fetchFields = @('manifest_path', 'lock_sha256', 'command', 'status', 'exit_code', 'process_identity')
        if (-not (Test-D32Phase0ExactProperties -Object $fetch -Expected $fetchFields) -or
            $fetch.manifest_path -isnot [string] -or $fetch.manifest_path -cne $ValidatedProfile.LockInputs[$i].ManifestPath -or
            $fetch.lock_sha256 -isnot [string] -or $fetch.lock_sha256 -cne $ValidatedProfile.LockInputs[$i].LockSha256 -or
            $fetch.command -isnot [Array] -or @($fetch.command | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
            $fetch.status -isnot [string] -or $fetch.status -cne 'succeeded' -or -not (Test-D32Phase0Integer -Value $fetch.exit_code) -or $fetch.exit_code -ne 0) { throw "PHASE0_FETCH_BLOCKED: fixed locked fetch record is invalid at index $i" }
        $expectedFetchArgs = @('fetch', '--locked', '--manifest-path', $ValidatedProfile.LockInputs[$i].ManifestFullPath, '--target', [string]$ValidatedProfile.Profile.target_triple)
        if (($fetch.command -join "`0") -cne ($expectedFetchArgs -join "`0")) { throw "PHASE0_FETCH_BLOCKED: fixed locked fetch argv mismatch at index $i" }
        $identity = $fetch.process_identity
        if (-not (Test-D32Phase0ExactProperties -Object $identity -Expected @('process_id', 'parent_process_id', 'name', 'image_path', 'creation_date', 'command_line', 'observed_at_utc', 'identity_verified')) -or
            -not (Test-D32Phase0Integer -Value $identity.process_id -Positive) -or -not (Test-D32Phase0Integer -Value $identity.parent_process_id -Positive) -or $identity.parent_process_id -ne $ExpectedRunnerProcessId -or
            $identity.process_id -eq $ExpectedRunnerProcessId -or -not $fetchProcessIds.Add([int]$identity.process_id) -or
            @($identity.PSObject.Properties | Where-Object { @('name', 'image_path', 'creation_date', 'command_line', 'observed_at_utc') -contains $_.Name -and $_.Value -isnot [string] }).Count -ne 0 -or
            $identity.name -cne 'cargo.exe' -or -not (Test-D32ProfilePathEqual -Left $identity.image_path -Right $ValidatedProfile.Profile.toolchain.cargo.path) -or
            $identity.command_line -cne (ConvertTo-D32Phase0CommandLine -Arguments (@([string]$ValidatedProfile.Profile.toolchain.cargo.path) + $expectedFetchArgs)) -or
            $identity.identity_verified -isnot [bool] -or -not $identity.identity_verified) { throw "PHASE0_FETCH_BLOCKED: Cargo process identity evidence is invalid at index $i" }
    }
    return [PSCustomObject]@{ Document = $document; Reference = $sidecarReference; ManifestReference = (Get-D32Phase0FileReference -Path $ManifestPath) }
}

function Get-D32Phase0ExpectedCommandPlan {
    param([Parameter(Mandatory = $true)][object]$Profile, [Parameter(Mandatory = $true)][object]$Inventory)
    $cargo = [string]$Profile.toolchain.cargo.path
    $rustc = [string]$Profile.toolchain.rustc.path
    $plan = [System.Collections.Generic.List[object]]::new()
    $plan.Add([PSCustomObject]@{ name = 'rustc-target-probe'; executable = $rustc; arguments = @('--print', 'cfg', '--target', 'x86_64-pc-windows-msvc') })
    foreach ($package in @('protocol', 'vita', 'host')) {
        $plan.Add([PSCustomObject]@{ name = "$package-test-list"; executable = $cargo; arguments = @(Get-D32Phase0TestCommand -Package $package -Kind list) })
        $plan.Add([PSCustomObject]@{ name = "$package-ignored-list"; executable = $cargo; arguments = @(Get-D32Phase0TestCommand -Package $package -Kind ignored-list) })
    }
    foreach ($package in @('protocol', 'vita', 'host')) {
        $plan.Add([PSCustomObject]@{ name = "$package-full-local-suite"; executable = $cargo; arguments = @(Get-D32Phase0TestCommand -Package $package -Kind suite) })
    }
    foreach ($package in @('vita', 'host')) {
        $suffixes = if ($package -eq 'vita') { $script:D32Phase0FocusedVita } else { $script:D32Phase0FocusedHost }
        foreach ($suffix in $suffixes) {
            $matches = @($Inventory.$package.test_names | Where-Object { $_.EndsWith($suffix, [StringComparison]::Ordinal) })
            if ($matches.Count -ne 1) { throw "Phase0 fixed focused name is absent/ambiguous: $suffix" }
            $plan.Add([PSCustomObject]@{ name = "$package-focused-$($suffix.Split('::')[-1])"; executable = $cargo; arguments = @(Get-D32Phase0TestCommand -Package $package -Kind focused -ExactName $matches[0]) })
        }
    }
    return @($plan.ToArray())
}

function Test-D32Phase0MatrixRecord {
    param(
        [Parameter(Mandatory = $true)][string]$RecordPath,
        [Parameter(Mandatory = $true)][string]$ExpectedRecordSha256,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
        [Parameter(Mandatory = $true)][string]$ExpectedToolchainProfileSha256,
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$GitSha256
    )
    $result = [ordered]@{ IsValid = $false; Failure = $null; Record = $null; RecordPath = $null; Digest = $null; Identity = $null; CargoHome = $null; OutputRoot = $null }
    try {
        if ($ExpectedRecordSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'independent Phase0 record SHA-256 must be lowercase 64-hex' }
        if ($ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$') { throw 'expected candidate SHA must be lowercase 40-hex' }
        $recordFull = [IO.Path]::GetFullPath($RecordPath)
        if (-not (Test-D32ProfileCanonicalPathString -Path $RecordPath) -or -not (Test-D32ProfileNoReparsePath -Path $recordFull)) { throw 'Phase0 record is missing, non-canonical, or reparse-backed' }
        $recordSnapshot = Get-D32ProfileFileSnapshot -Path $recordFull
        if ($recordSnapshot.Sha256 -cne $ExpectedRecordSha256) { throw 'Phase0 record bytes do not match the independently supplied exact SHA-256' }
        $outputRoot = [IO.Path]::GetDirectoryName($recordFull)
        if ([IO.Path]::GetFileName($recordFull) -cne 'D32-PHASE0-MATRIX.json' -or -not (Test-D32ProfileNoReparsePath -Path $outputRoot)) { throw 'Phase0 record must be the fixed filename beneath a non-reparse output root' }
        $repo = [IO.Path]::GetFullPath($Repository)
        if ((Test-D32ProfilePathWithin -Child $outputRoot -Parent $repo) -or (Test-D32ProfilePathWithin -Child $repo -Parent $outputRoot)) { throw 'Phase0 output root must be outside and non-overlapping with repository' }
        $raw = [IO.File]::ReadAllText($recordFull, [Text.Encoding]::UTF8)
        if (Test-D32Phase0JsonDuplicateKeys -Json $raw) { throw 'Phase0 record has duplicate object keys or invalid JSON structure' }
        $document = $raw | ConvertFrom-D32Phase0Json
        $topFields = @('schema_version', 'record_type', 'runner_process_id', 'candidate_sha', 'source_repo', 'output_root', 'status', 'bundle_hashes', 'started_at_utc', 'completed_at_utc', 'final_candidate_sha', 'final_clean', 'powershell', 'toolchain_profile', 'cargo_home', 'fetches', 'fixture', 'commands', 'test_inventory', 'local_suites', 'focused_tests', 'deferred_d31_tests', 'deferred_d29g2_provider_tests', 'not_run_capture_tests', 'governance_inputs', 'phase0_scope')
        if (-not (Test-D32Phase0ExactProperties -Object $document -Expected $topFields)) { throw 'Phase0 record top-level schema has missing or extra fields' }
        if (-not (Test-D32Phase0Integer -Value $document.schema_version) -or [Int64]$document.schema_version -ne $script:D32Phase0SchemaVersion) { throw 'Phase0 record schema_version must be the supported JSON integer version 1' }
        if ($document.record_type -isnot [string] -or $document.record_type -cne $script:D32Phase0Type) { throw 'Phase0 record_type is unsupported' }
        if (-not (Test-D32Phase0Integer -Value $document.runner_process_id -Positive)) { throw 'Phase0 runner_process_id must be a positive JSON integer' }
        foreach ($name in @('candidate_sha', 'source_repo', 'output_root', 'status', 'bundle_hashes', 'started_at_utc', 'completed_at_utc', 'final_candidate_sha', 'phase0_scope')) { if ($document.$name -isnot [string]) { throw "Phase0 $name must be a JSON string" } }
        if ($document.candidate_sha -cne $ExpectedCandidateSha -or $document.final_candidate_sha -cne $ExpectedCandidateSha) { throw 'Phase0 record candidate SHA binding mismatch' }
        if (-not (Test-D32ProfilePathEqual -Left $document.source_repo -Right $repo) -or -not (Test-D32ProfilePathEqual -Left $document.output_root -Right $outputRoot)) { throw 'Phase0 source/output path binding mismatch' }
        if ($document.status -cne $script:D32Phase0Status -or $document.bundle_hashes -cne $script:D32Phase0BundleHashes -or $document.phase0_scope -cne $script:D32Phase0Scope) { throw 'Phase0 status/scope must be local-only PASS with bundle hashes PENDING' }
        if ($document.final_clean -isnot [bool] -or -not $document.final_clean) { throw 'Phase0 final_clean must be boolean true' }
        foreach ($timestamp in @('started_at_utc', 'completed_at_utc')) {
            $parsedTimestamp = [DateTimeOffset]::MinValue
            if (-not [DateTimeOffset]::TryParse([string]$document.$timestamp, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsedTimestamp)) { throw "Phase0 $timestamp is not a supported ISO timestamp" }
        }

        $profile = Test-D32BuildToolchainProfile -ProfilePath $ToolchainProfilePath -ExpectedSha256 $ExpectedToolchainProfileSha256 -Repository $repo -EvidenceRoot $outputRoot
        if (-not $profile.IsValid) { throw "Phase0 pinned toolchain profile is not current: $($profile.Failure)" }
        if (-not (Test-D32Phase0ExactProperties -Object $document.toolchain_profile -Expected @('path', 'sha256', 'file_identity', 'target_triple', 'toolchain', 'executable_inventory', 'lock_inputs', 'env_policy'))) { throw 'Phase0 toolchain_profile schema has missing/extra fields' }
        if ($document.toolchain_profile.path -cne $profile.ProfilePath -or $document.toolchain_profile.sha256 -cne $profile.Digest -or $document.toolchain_profile.target_triple -cne 'x86_64-pc-windows-msvc' -or $document.toolchain_profile.env_policy -cne 'D32_BUILD_ENV_V1') { throw 'Phase0 profile path/SHA/target/environment policy mismatch' }
        if (-not (Test-D32Phase0ExactProperties -Object $document.toolchain_profile.file_identity -Expected @('bytes', 'volume_serial_hex', 'file_id_hex')) -or
            -not (Test-D32Phase0Integer -Value $document.toolchain_profile.file_identity.bytes -Positive) -or
            $document.toolchain_profile.file_identity.bytes -ne [Int64]$profile.Identity.Bytes -or
            $document.toolchain_profile.file_identity.volume_serial_hex -cne $profile.Identity.VolumeSerialHex -or
            $document.toolchain_profile.file_identity.file_id_hex -cne $profile.Identity.FileIdHex) { throw 'Phase0 profile opened-handle identity binding mismatch' }
        if (-not (Test-D32Phase0ExactProperties -Object $document.powershell -Expected @('name', 'path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'reason')) -or
            ($document.powershell | ConvertTo-Json -Depth 5 -Compress) -cne ($profile.Profile.powershell | ConvertTo-Json -Depth 5 -Compress)) { throw 'Phase0 current PowerShell image identity differs from caller-pinned profile' }
        $expectedInventory = @($profile.ExecutableInventory | ForEach-Object { [ordered]@{ path = $_.Path; sha256 = $_.Sha256; bytes = [Int64]$_.Bytes; volume_serial_hex = $_.VolumeSerialHex; file_id_hex = $_.FileIdHex } })
        $recordToolchainJson = ConvertTo-Json -InputObject $document.toolchain_profile.toolchain -Depth 8 -Compress
        $expectedToolchainJson = ConvertTo-Json -InputObject $profile.Profile.toolchain -Depth 8 -Compress
        $recordInventoryJson = ConvertTo-Json -InputObject $document.toolchain_profile.executable_inventory -Depth 12 -Compress
        $expectedInventoryJson = ConvertTo-Json -InputObject $expectedInventory -Depth 12 -Compress
        if ($recordToolchainJson -cne $expectedToolchainJson -or $recordInventoryJson -cne $expectedInventoryJson) { throw 'Phase0 direct tool/executable inventory differs from the current caller-pinned profile' }
        if ($document.toolchain_profile.lock_inputs -isnot [Array] -or $document.toolchain_profile.lock_inputs.Count -ne $profile.LockInputs.Count) { throw 'Phase0 lock input inventory has wrong array/count' }
        for ($i = 0; $i -lt $profile.LockInputs.Count; $i++) {
            $lockRecord = $document.toolchain_profile.lock_inputs[$i]
            if (-not (Test-D32Phase0ExactProperties -Object $lockRecord -Expected @('manifest_path', 'lock_sha256')) -or $lockRecord.manifest_path -cne $profile.LockInputs[$i].ManifestPath -or $lockRecord.lock_sha256 -cne $profile.LockInputs[$i].LockSha256) { throw 'Phase0 lock paths/SHA differ from the current caller-pinned profile' }
        }

        if (-not (Test-D32Phase0ExactProperties -Object $document.cargo_home -Expected @('path', 'temp_root', 'run_id', 'nonempty_after_fetch')) -or
            $document.cargo_home.path -isnot [string] -or $document.cargo_home.temp_root -isnot [string] -or $document.cargo_home.run_id -isnot [string] -or $document.cargo_home.nonempty_after_fetch -isnot [bool] -or -not $document.cargo_home.nonempty_after_fetch) { throw 'Phase0 Cargo home schema/fresh-fetch evidence is invalid' }
        if (-not (Test-D32ProfilePathWithin -Child $document.cargo_home.path -Parent $outputRoot) -or -not (Test-D32ProfilePathWithin -Child $document.cargo_home.temp_root -Parent $outputRoot)) { throw 'Phase0 Cargo home/temp must remain beneath external output root' }
        $cargoHomeCheck = Test-D32CargoHome -Path $document.cargo_home.path -Repository $repo
        if ($cargoHomeCheck.Empty -or -not (Test-D32ProfileNoReparsePath -Path $document.cargo_home.temp_root)) { throw 'Phase0 Cargo home is empty or temp root is missing/reparse-backed' }
        $expectedFetches = @($profile.LockInputs)
        if ($document.fetches -isnot [Array] -or $document.fetches.Count -ne $expectedFetches.Count) { throw 'Phase0 locked fetch array/count mismatch' }
        for ($i = 0; $i -lt $expectedFetches.Count; $i++) {
            $fetch = $document.fetches[$i]
            if (-not (Test-D32Phase0ExactProperties -Object $fetch -Expected @('manifest_path', 'lock_sha256', 'command', 'status', 'exit_code', 'process_identity')) -or
                $fetch.manifest_path -cne $expectedFetches[$i].ManifestPath -or $fetch.lock_sha256 -cne $expectedFetches[$i].LockSha256 -or
                $fetch.status -cne 'succeeded' -or -not (Test-D32Phase0Integer -Value $fetch.exit_code) -or $fetch.exit_code -ne 0 -or $fetch.command -isnot [Array]) { throw 'Phase0 fixed locked fetch record is invalid' }
            $expectedFetchArgs = @('fetch', '--locked', '--manifest-path', $expectedFetches[$i].ManifestFullPath, '--target', [string]$profile.Profile.target_triple)
            if (($fetch.command -join "`0") -cne ($expectedFetchArgs -join "`0")) { throw 'Phase0 locked fetch argv does not equal the exact fixed invocation' }
            $fetchIdentity = $fetch.process_identity
            if (-not (Test-D32Phase0ExactProperties -Object $fetchIdentity -Expected @('process_id', 'parent_process_id', 'name', 'image_path', 'creation_date', 'command_line', 'observed_at_utc', 'identity_verified')) -or
                $fetchIdentity.identity_verified -isnot [bool] -or -not $fetchIdentity.identity_verified -or -not (Test-D32ProfilePathEqual -Left $fetchIdentity.image_path -Right $profile.Profile.toolchain.cargo.path)) { throw 'Phase0 Cargo fetch process identity is invalid' }
        }

        if (-not (Test-D32Phase0ExactProperties -Object $document.fixture -Expected @('manifest', 'build_provenance', 'transcript', 'schema_version', 'process_tree_check', 'fixture_names', 'fixture_records', 'log_references', 'per_phase_git_states')) -or $document.fixture.schema_version -ne 3 -or $document.fixture.process_tree_check -cne 'succeeded') { throw 'Phase0 fixture summary schema/cleanup is invalid' }
        $fixtureRef = Test-D32Phase0FileReference -Reference $document.fixture.manifest -AllowedRoot $outputRoot
        $fixtureProvenanceRef = Test-D32Phase0FileReference -Reference $document.fixture.build_provenance -AllowedRoot $outputRoot
        $transcriptRef = Test-D32Phase0FileReference -Reference $document.fixture.transcript -AllowedRoot $outputRoot
        $fixtureLogLines = [IO.File]::ReadAllLines([string]$transcriptRef.Path)
        $observedFixtureGitStates = @(Get-D32Phase0FixtureGitStates -Lines $fixtureLogLines -ExpectedCandidateSha $ExpectedCandidateSha)
        if ($document.fixture.per_phase_git_states -isnot [Array] -or ($document.fixture.per_phase_git_states | ConvertTo-Json -Depth 8 -Compress) -cne ($observedFixtureGitStates | ConvertTo-Json -Depth 8 -Compress)) { throw 'Phase0 per-phase fixture candidate/clean claims do not match captured runner transcript' }
        $fixturePath = [string]$fixtureRef.Path
        if ([IO.Path]::GetFileName($fixturePath) -cne 'fixture-manifest.json') { throw 'Phase0 fixture manifest path is not fixed' }
        $fixtureRaw = [IO.File]::ReadAllText($fixturePath, [Text.Encoding]::UTF8)
        if (Test-D32Phase0JsonDuplicateKeys -Json $fixtureRaw) { throw 'Phase0 fixture manifest has duplicate JSON keys' }
        $fixtureDocument = $fixtureRaw | ConvertFrom-D32Phase0Json
        $fixtureFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest $fixtureDocument -FixtureManifestPath $fixturePath -Head $ExpectedCandidateSha -Repository $repo -Findings $fixtureFindings
        if (@($fixtureFindings | Where-Object { $_.Severity -eq 'ERROR' }).Count -gt 0) { throw 'Phase0 fixture schema/artifact validation failed' }
        if ([IO.Path]::GetFileName($fixtureProvenanceRef.Path) -cne 'fixture-build-provenance.json') { throw 'Phase0 fixture build provenance path is not fixed' }
        $fixtureProvenance = Test-D32Phase0FixtureBuildProvenance -SidecarPath $fixtureProvenanceRef.Path -ManifestPath $fixturePath -Repository $repo -OutputRoot $outputRoot -ExpectedCandidateSha $ExpectedCandidateSha -ExpectedRunnerProcessId ([int]$document.runner_process_id) -ValidatedProfile $profile
        if (($fixtureProvenance.Reference | ConvertTo-Json -Depth 5 -Compress) -cne ($document.fixture.build_provenance | ConvertTo-Json -Depth 5 -Compress)) { throw 'Phase0 fixture provenance sidecar reference does not match current opened-handle bytes/identity' }
        if (($document.fixture.fixture_names -join '|') -cne 'd29h1-authority-fixture|d29h7-authority-fixture|d29h7-process-fixture|d29h7-git-helper-fixture|d32a-sandbox-fixture' -or
            ($fixtureDocument.fixtures | ConvertTo-Json -Depth 20 -Compress) -cne ($document.fixture.fixture_records | ConvertTo-Json -Depth 20 -Compress)) { throw 'Phase0 fixture records do not match the independently validated fixture manifest' }
        $fixtureEnvironment = $fixtureProvenance.Document.environment
        if (-not (Test-D32ProfilePathEqual -Left $fixtureEnvironment.cargo_home -Right $document.cargo_home.path) -or -not (Test-D32ProfilePathEqual -Left $fixtureEnvironment.temp_root -Right $document.cargo_home.temp_root) -or $fixtureEnvironment.run_id -cne $document.cargo_home.run_id -or $fixtureEnvironment.toolchain_profile_sha256 -cne $profile.Digest) { throw 'Phase0 fixture sidecar is not bound to the recorded Cargo home/profile' }
        $expectedFixtureLogPaths = @(Get-D32Phase0FixtureLogPaths -OutputRoot $outputRoot -FixtureRecords @($fixtureDocument.fixtures) -LockInputs @($profile.LockInputs))
        if ($document.fixture.log_references -isnot [Array] -or $document.fixture.log_references.Count -ne $expectedFixtureLogPaths.Count) { throw "Phase0 fixture log-reference inventory must contain exactly $($expectedFixtureLogPaths.Count) fixed stdout/stderr files" }
        for ($logIndex = 0; $logIndex -lt $expectedFixtureLogPaths.Count; $logIndex++) {
            $log = $document.fixture.log_references[$logIndex]
            $null = Test-D32Phase0FileReference -Reference $log -AllowedRoot $outputRoot
            if (-not (Test-D32ProfilePathEqual -Left $log.path -Right $expectedFixtureLogPaths[$logIndex])) { throw "Phase0 fixture log reference path/order differs at index $logIndex" }
        }
        foreach ($reference in @($fixtureRef, $fixtureProvenanceRef, $transcriptRef)) { $null = $reference }

        $inventory = $document.test_inventory
        if (-not (Test-D32Phase0ExactProperties -Object $inventory -Expected @('protocol', 'vita', 'host'))) { throw 'Phase0 test_inventory must contain exactly protocol/Vita/Host' }
        $testInventories = @{}
        foreach ($package in @('protocol', 'vita', 'host')) {
            $record = $inventory.$package
            if (-not (Test-D32Phase0ExactProperties -Object $record -Expected @('test_names', 'ignored_names', 'test_count', 'ignored_count')) -or
                $record.test_names -isnot [Array] -or $record.ignored_names -isnot [Array] -or
                -not (Test-D32Phase0Integer -Value $record.test_count) -or -not (Test-D32Phase0Integer -Value $record.ignored_count) -or
                $record.test_count -ne $record.test_names.Count -or $record.ignored_count -ne $record.ignored_names.Count) { throw "Phase0 $package inventory schema/count mismatch" }
            if (@($record.test_names | Where-Object { $_ -isnot [string] }).Count -ne 0 -or @($record.ignored_names | Where-Object { $_ -isnot [string] }).Count -ne 0) { throw "Phase0 $package test names must be strings" }
            $testInventories[$package] = [PSCustomObject]@{ all = @($record.test_names); ignored = @($record.ignored_names) }
        }
        $null = Test-D32Phase0FixedInventory -Inventories $testInventories

        $expectedPlan = @(Get-D32Phase0ExpectedCommandPlan -Profile $profile.Profile -Inventory $inventory)
        if ($document.commands -isnot [Array] -or $document.commands.Count -ne $expectedPlan.Count) { throw 'Phase0 command inventory is missing/extra fixed commands' }
        $commandFields = @('name', 'executable', 'executable_sha256', 'executable_bytes', 'executable_volume_serial_hex', 'executable_file_id_hex', 'argv', 'arguments', 'command_line', 'working_directory', 'candidate_sha_before', 'clean_before', 'started_at_utc', 'completed_at_utc', 'exit_code', 'root_process', 'descendant_processes', 'process_tree_cleanup', 'stdout', 'stderr', 'candidate_sha_after', 'clean_after')
        for ($i = 0; $i -lt $expectedPlan.Count; $i++) {
            $command = $document.commands[$i]
            $plan = $expectedPlan[$i]
            if (-not (Test-D32Phase0ExactProperties -Object $command -Expected $commandFields)) { throw "Phase0 command[$i] has missing/extra fields" }
            foreach ($field in @('name', 'executable', 'executable_sha256', 'executable_volume_serial_hex', 'executable_file_id_hex', 'command_line', 'working_directory', 'candidate_sha_before', 'started_at_utc', 'completed_at_utc', 'candidate_sha_after')) {
                if ($command.$field -isnot [string]) { throw "Phase0 command[$i] $field must be a JSON string" }
            }
            foreach ($arrayName in @('argv', 'arguments')) {
                if ($command.$arrayName -isnot [Array] -or @($command.$arrayName | Where-Object { $_ -isnot [string] }).Count -ne 0) { throw "Phase0 command[$i] $arrayName must be an array of JSON strings" }
            }
            foreach ($timestampName in @('started_at_utc', 'completed_at_utc')) {
                $parsedCommandTime = [DateTimeOffset]::MinValue
                if (-not [DateTimeOffset]::TryParse([string]$command.$timestampName, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsedCommandTime)) { throw "Phase0 command[$i] $timestampName is not an ISO timestamp" }
            }
            if ([DateTimeOffset]::Parse([string]$command.completed_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) -lt [DateTimeOffset]::Parse([string]$command.started_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)) { throw "Phase0 command[$i] completion precedes start" }
            if ($command.name -cne $plan.name -or -not (Test-D32ProfilePathEqual -Left $command.executable -Right $plan.executable) -or
                $command.arguments -isnot [Array] -or ($command.arguments -join "`0") -cne ($plan.arguments -join "`0") -or
                $command.argv -isnot [Array] -or (@($command.argv) -join "`0") -cne ((@($plan.executable) + @($plan.arguments)) -join "`0")) { throw "Phase0 command[$i] does not match the code-owned argv/name/executable" }
            $expectedLine = ConvertTo-D32Phase0CommandLine -Arguments (@($plan.executable) + @($plan.arguments))
            if ($command.command_line -cne $expectedLine -or -not (Test-D32ProfilePathEqual -Left $command.working_directory -Right $repo)) { throw "Phase0 command[$i] command line/cwd mismatch" }
            if ($command.candidate_sha_before -cne $ExpectedCandidateSha -or $command.candidate_sha_after -cne $ExpectedCandidateSha -or $command.clean_before -isnot [bool] -or -not $command.clean_before -or $command.clean_after -isnot [bool] -or -not $command.clean_after -or -not (Test-D32Phase0Integer -Value $command.exit_code) -or $command.exit_code -ne 0) { throw "Phase0 command[$i] candidate/clean/exit record is invalid" }
            if (-not (Test-D32ProfileCanonicalPathString -Path $command.executable) -or $command.executable_sha256 -cnotmatch '^[0-9a-f]{64}$' -or -not (Test-D32Phase0Integer -Value $command.executable_bytes -Positive) -or $command.executable_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or $command.executable_file_id_hex -cnotmatch '^[0-9a-f]{32}$') { throw "Phase0 command[$i] executable identity scalars malformed" }
            $toolRecord = if (Test-D32ProfilePathEqual -Left $plan.executable -Right $profile.Profile.toolchain.rustc.path) { $profile.Profile.toolchain.rustc } else { $profile.Profile.toolchain.cargo }
            if ($command.executable_sha256 -cne $toolRecord.sha256 -or [Int64]$command.executable_bytes -ne [Int64]$toolRecord.bytes -or $command.executable_volume_serial_hex -cne $toolRecord.volume_serial_hex -or $command.executable_file_id_hex -cne $toolRecord.file_id_hex) { throw "Phase0 command[$i] executable does not match current pinned tool identity" }
            $null = Test-D32Phase0FileReference -Reference $command.stdout -AllowedRoot $outputRoot
            $null = Test-D32Phase0FileReference -Reference $command.stderr -AllowedRoot $outputRoot
            if (-not (Test-D32Phase0ExactProperties -Object $command.process_tree_cleanup -Expected @('launch_mode', 'job_close_succeeded', 'process_wait_signaled', 'active_process_count_verified', 'active_process_count', 'cleanup_succeeded', 'detail')) -or
                $command.process_tree_cleanup.launch_mode -cne 'CreateProcessW(CREATE_SUSPENDED|EXTENDED_STARTUP_INFO)+HANDLE_LIST(stdout/stderr)+AssignProcessToJobObject(KILL_ON_JOB_CLOSE)+ResumeThread' -or
                $command.process_tree_cleanup.job_close_succeeded -isnot [bool] -or -not $command.process_tree_cleanup.job_close_succeeded -or
                $command.process_tree_cleanup.process_wait_signaled -isnot [bool] -or -not $command.process_tree_cleanup.process_wait_signaled -or
                $command.process_tree_cleanup.active_process_count_verified -isnot [bool] -or -not $command.process_tree_cleanup.active_process_count_verified -or
                -not (Test-D32Phase0Integer -Value $command.process_tree_cleanup.active_process_count) -or $command.process_tree_cleanup.active_process_count -ne 0 -or
                $command.process_tree_cleanup.cleanup_succeeded -isnot [bool] -or -not $command.process_tree_cleanup.cleanup_succeeded) { throw "Phase0 command[$i] lacks verified process-tree cleanup" }
            $rootProcess = $command.root_process
            if (-not (Test-D32Phase0ExactProperties -Object $rootProcess -Expected @('process_id', 'parent_process_id', 'name', 'image_path', 'command_line', 'creation_date', 'observed_at_utc', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'allowed_image_reason', 'identity_verified')) -or
                -not (Test-D32Phase0Integer -Value $rootProcess.process_id -Positive) -or -not (Test-D32Phase0Integer -Value $rootProcess.parent_process_id -Positive) -or
                @($rootProcess.PSObject.Properties | Where-Object { @('name', 'image_path', 'command_line', 'creation_date', 'observed_at_utc', 'sha256', 'volume_serial_hex', 'file_id_hex', 'allowed_image_reason') -contains $_.Name -and $_.Value -isnot [string] }).Count -ne 0 -or
                $rootProcess.identity_verified -isnot [bool] -or -not $rootProcess.identity_verified -or
                $rootProcess.parent_process_id -ne [int]$document.runner_process_id -or -not (Test-D32ProfilePathEqual -Left $rootProcess.image_path -Right $plan.executable) -or $rootProcess.command_line -cne $expectedLine -or
                $rootProcess.sha256 -cne $command.executable_sha256 -or [Int64]$rootProcess.bytes -ne [Int64]$command.executable_bytes -or
                $rootProcess.volume_serial_hex -cne $command.executable_volume_serial_hex -or $rootProcess.file_id_hex -cne $command.executable_file_id_hex) { throw "Phase0 command[$i] root process identity mismatch" }
            if ($command.descendant_processes -isnot [Array]) { throw "Phase0 command[$i] descendants must be a JSON array" }
            $processKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            [void]$processKeys.Add("$($rootProcess.process_id)|$($rootProcess.creation_date)")
            $observedPids = [System.Collections.Generic.HashSet[int]]::new()
            [void]$observedPids.Add([int]$rootProcess.process_id)
            foreach ($child in $command.descendant_processes) {
                if (-not (Test-D32Phase0ExactProperties -Object $child -Expected @('process_id', 'parent_process_id', 'name', 'image_path', 'command_line', 'creation_date', 'observed_at_utc', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'allowed_image_reason', 'identity_verified')) -or
                    -not (Test-D32Phase0Integer -Value $child.process_id -Positive) -or -not (Test-D32Phase0Integer -Value $child.parent_process_id -Positive) -or
                    @($child.PSObject.Properties | Where-Object { @('name', 'image_path', 'command_line', 'creation_date', 'observed_at_utc', 'sha256', 'volume_serial_hex', 'file_id_hex', 'allowed_image_reason') -contains $_.Name -and $_.Value -isnot [string] }).Count -ne 0 -or
                    $child.identity_verified -isnot [bool] -or -not $child.identity_verified -or $child.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                    -not (Test-D32Phase0Integer -Value $child.bytes -Positive) -or $child.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or $child.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { throw "Phase0 command[$i] child process identity schema is invalid" }
                if (-not $observedPids.Add([int]$child.process_id) -or -not $processKeys.Add("$($child.process_id)|$($child.creation_date)")) { throw "Phase0 command[$i] process snapshot contains duplicate PID/creation identity" }
                $childImage = Get-D32ProfileFileSnapshot -Path $child.image_path
                if ($childImage.Sha256 -cne $child.sha256 -or $childImage.Bytes -ne [Int64]$child.bytes -or $childImage.VolumeSerialHex -cne $child.volume_serial_hex -or $childImage.FileIdHex -cne $child.file_id_hex) { throw "Phase0 command[$i] child image bytes/ID changed" }
                $actualReason = Get-D32Phase0AllowedChildImageReason -ImagePath $child.image_path -ValidatedProfile $profile -Repository $repo
                if ([String]::IsNullOrWhiteSpace($actualReason) -or $child.allowed_image_reason -cne $actualReason) { throw "Phase0 command[$i] contains unknown child image" }
            }
        }

        $null = Test-D32Phase0ExecutedCommandEvidence -Document $document

        if ($document.local_suites -isnot [Array] -or $document.local_suites.Count -ne 3) { throw 'Phase0 full local suite inventory must contain exactly three package results' }
        foreach ($package in @('protocol', 'vita', 'host')) {
            $suite = @($document.local_suites | Where-Object { $_.package -ceq $package })
            if ($suite.Count -ne 1 -or -not (Test-D32Phase0ExactProperties -Object $suite[0] -Expected @('package', 'command', 'status', 'summary_count', 'counts', 'exact_deferred_skip_count')) -or $suite[0].status -cne 'PASS') { throw "Phase0 local suite evidence missing or invalid for $package" }
            $wantedIgnored = [Int64]$inventory.$package.ignored_count
            $wantedFiltered = if ($package -eq 'vita') { $script:D32Phase0DeferredVita.Count } elseif ($package -eq 'host') { $script:D32Phase0DeferredHost.Count } else { 0 }
            if (-not (Test-D32Phase0SuiteCounts -Counts $suite[0].counts -TestCount ([Int64]$inventory.$package.test_count) -ExpectedIgnored $wantedIgnored -ExpectedFiltered $wantedFiltered)) { throw "Phase0 $package test counts do not reconcile with test/ignore/skip inventory" }
        }
        if ($document.focused_tests -isnot [Array] -or $document.focused_tests.Count -ne ($script:D32Phase0FocusedVita.Count + $script:D32Phase0FocusedHost.Count)) { throw 'Phase0 focused-test inventory has missing/extra records' }
        foreach ($package in @('vita', 'host')) {
            $suffixes = if ($package -eq 'vita') { $script:D32Phase0FocusedVita } else { $script:D32Phase0FocusedHost }
            foreach ($suffix in $suffixes) {
                $focusedRecord = @($document.focused_tests | Where-Object { $_.package -ceq $package -and $_.full_name.EndsWith($suffix, [StringComparison]::Ordinal) })
                if ($focusedRecord.Count -ne 1 -or $focusedRecord[0].status -cne 'PASS' -or $focusedRecord[0].passed -ne 1 -or $focusedRecord[0].failed -ne 0) { throw "Phase0 focused named test is missing or did not PASS: $suffix" }
            }
        }

        $expectedDeferred = @(@($script:D32Phase0DeferredVita | ForEach-Object { "vita|$_" }) + @($script:D32Phase0DeferredHost | ForEach-Object { "host|$_" }))
        if ($document.deferred_d31_tests -isnot [Array] -or $document.deferred_d31_tests.Count -ne $expectedDeferred.Count) { throw 'Phase0 explicit D31 NOT RUN inventory is incomplete' }
        foreach ($item in $document.deferred_d31_tests) {
            if (-not (Test-D32Phase0ExactProperties -Object $item -Expected @('package', 'test_name', 'result', 'status')) -or $item.status -cne 'NOT RUN' -or $item.result -cne 'NOT RUN — deferred until validated bundle and full aggregate') { throw 'Phase0 D31 deferral is not explicitly NOT RUN' }
        }
        if ((@($document.deferred_d31_tests | ForEach-Object { "$($_.package)|$($_.test_name)" }) -join '|') -cne ($expectedDeferred -join '|')) { throw 'Phase0 D31 deferred names/order differ from the fixed ten-case list' }
        if ($document.deferred_d29g2_provider_tests -isnot [Array] -or $document.deferred_d29g2_provider_tests.Count -ne $script:D32Phase0IgnoredVita.Count) { throw 'Phase0 D29G2 provider NOT RUN inventory is incomplete' }
        for ($i = 0; $i -lt $script:D32Phase0IgnoredVita.Count; $i++) { $item = $document.deferred_d29g2_provider_tests[$i]; if ($item.test_name -cne $script:D32Phase0IgnoredVita[$i] -or $item.status -cne 'NOT RUN') { throw 'Phase0 D29G2 provider tests must be NOT RUN until authorized provider evidence' } }
        if ($document.not_run_capture_tests -isnot [Array] -or $document.not_run_capture_tests.Count -ne $script:D32Phase0IgnoredHost.Count) { throw 'Phase0 capture N/A inventory is incomplete' }
        for ($i = 0; $i -lt $script:D32Phase0IgnoredHost.Count; $i++) { $item = $document.not_run_capture_tests[$i]; if ($item.test_name -cne $script:D32Phase0IgnoredHost[$i] -or $item.status -cne 'N/A — NOT RUN') { throw 'Phase0 interactive/physical capture tests must remain N/A — NOT RUN' } }

        $expectedGovernance = @('AGENTS.md', 'docs/governance/PROJECT_SOURCE_OF_TRUTH.md', 'docs/governance/CURRENT_DEVELOPMENT_STATE.md', 'docs/governance/FROZEN_INVARIANTS.md', 'docs/governance/ARCHITECTURE_DECISIONS.md', 'docs/governance/MODEL_ROUTING.md', 'docs/governance/CODEX_DEVELOPMENT_PROTOCOL.md')
        if ($document.governance_inputs -isnot [Array] -or $document.governance_inputs.Count -ne $expectedGovernance.Count) { throw 'Phase0 governance input inventory has wrong count' }
        for ($i = 0; $i -lt $expectedGovernance.Count; $i++) {
            $entry = $document.governance_inputs[$i]
            if (-not (Test-D32Phase0ExactProperties -Object $entry -Expected @('relative_path', 'file')) -or $entry.relative_path -cne $expectedGovernance[$i].Replace('\', '/')) { throw 'Phase0 governance path inventory differs from the fixed set/order' }
            $current = Test-D32Phase0FileReference -Reference $entry.file -AllowedRoot $repo
            if (-not (Test-D32ProfilePathEqual -Left $current.Path -Right (Join-Path $repo $expectedGovernance[$i]))) { throw 'Phase0 governance file path binding mismatch' }
        }

        $gitState = Get-D32Phase0GitState -Repository $repo -GitPath $GitPath -GitSha256 $GitSha256
        if ($gitState.Head -cne $ExpectedCandidateSha) { throw 'current exact clean HEAD does not match Phase0 candidate' }
        $profileAgain = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $profile
        $recordSnapshotAfter = Get-D32ProfileFileSnapshot -Path $recordFull
        if ($recordSnapshotAfter.Sha256 -cne $recordSnapshot.Sha256 -or $recordSnapshotAfter.VolumeSerialHex -cne $recordSnapshot.VolumeSerialHex -or $recordSnapshotAfter.FileIdHex -cne $recordSnapshot.FileIdHex) { throw 'Phase0 record changed identity during validation' }
        $result.IsValid = $true
        $result.Record = $document
        $result.RecordPath = $recordFull
        $result.Digest = $recordSnapshot.Sha256
        $result.Identity = $recordSnapshot
        $result.CargoHome = [string]$document.cargo_home.path
        $result.OutputRoot = $outputRoot
        return [PSCustomObject]$result
    }
    catch {
        $result.Failure = $_.Exception.Message
        return [PSCustomObject]$result
    }
}

function Get-D32Phase0TestCommand {
    param([Parameter(Mandatory = $true)][string]$Package, [Parameter(Mandatory = $true)][string]$Kind, [string]$ExactName)
    $manifest = switch ($Package) {
        'protocol' { 'vita-agent-protocol/Cargo.toml' }
        'vita' { 'vita-agent/Cargo.toml' }
        'host' { 'src-tauri/Cargo.toml' }
        default { throw "unknown Phase0 package: $Package" }
    }
    $arguments = [System.Collections.Generic.List[string]]::new()
    foreach ($part in @('test', '--manifest-path', $manifest, '--all-targets', '--locked', '--offline')) { $arguments.Add($part) }
    if ($Package -eq 'vita') { $arguments.Add('--features'); $arguments.Add('d32-a-test-helper') }
    if ($Package -eq 'host') { $arguments.Add('--features'); $arguments.Add('d32-a-host-canary') }
    if ($Kind -eq 'list') { $arguments.Add('--'); $arguments.Add('--list') }
    elseif ($Kind -eq 'ignored-list') { $arguments.Add('--'); $arguments.Add('--ignored'); $arguments.Add('--list') }
    elseif ($Kind -eq 'suite') {
        if ($Package -ne 'protocol') {
            $arguments.Add('--')
            $skips = if ($Package -eq 'vita') { $script:D32Phase0DeferredVita } else { $script:D32Phase0DeferredHost }
            foreach ($skip in $skips) { $arguments.Add('--skip'); $arguments.Add($skip) }
        }
    }
    elseif ($Kind -eq 'focused') {
        if ([String]::IsNullOrWhiteSpace($ExactName)) { throw 'focused exact test name is required' }
        $arguments.Add('--'); $arguments.Add('--exact'); $arguments.Add($ExactName)
    }
    else { throw "unknown Phase0 command kind: $Kind" }
    return @($arguments.ToArray())
}

function Get-D32Phase0ListedTests {
    param([Parameter(Mandatory = $true)][string[]]$Lines)
    $tests = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $Lines) {
        if ($line -match '^\s*(.+): test\s*$') { $tests.Add([string]$Matches[1]) }
    }
    return @($tests.ToArray())
}

function Get-D32Phase0IgnoredTests {
    param([Parameter(Mandatory = $true)][string[]]$Lines)
    return @(Get-D32Phase0ListedTests -Lines $Lines)
}

function Test-D32Phase0ExactTestListOutput {
    param([Parameter(Mandatory = $true)][string[]]$Lines, [Parameter(Mandatory = $true)][string[]]$Expected, [switch]$Ignored)
    $observed = if ($Ignored) { @(Get-D32Phase0IgnoredTests -Lines $Lines) } else { @(Get-D32Phase0ListedTests -Lines $Lines) }
    return (($observed -join "`0") -ceq ($Expected -join "`0"))
}

function Get-D32Phase0Summaries {
    param([Parameter(Mandatory = $true)][string[]]$Lines)
    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($line in $Lines) {
        if ($line -match '^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;') {
            $records.Add([PSCustomObject]@{
                status = [string]$Matches[1]
                passed = [Int64]$Matches[2]
                failed = [Int64]$Matches[3]
                ignored = [Int64]$Matches[4]
                measured = [Int64]$Matches[5]
                filtered_out = [Int64]$Matches[6]
            })
        }
    }
    return @($records.ToArray())
}

function Get-D32Phase0TextFromLogs {
    param([Parameter(Mandatory = $true)][object]$CommandRecord)
    $text = [System.Collections.Generic.List[string]]::new()
    foreach ($reference in @($CommandRecord.stdout, $CommandRecord.stderr)) {
        $text.AddRange([IO.File]::ReadAllLines([string]$reference.path))
    }
    return @($text.ToArray())
}

function Assert-D32Phase0OutputRoot {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Repository)
    if (-not [IO.Path]::IsPathRooted($Path) -or -not (Test-D32ProfileCanonicalPathString -Path $Path)) { throw 'PHASE0_OUTPUT_BLOCKED: OutputRoot must be canonical absolute path' }
    $full = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($full)
    if ([String]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container) -or -not (Test-D32ProfileNoReparsePath -Path $parent)) { throw 'PHASE0_OUTPUT_BLOCKED: OutputRoot parent must exist and be non-reparse' }
    if ((Test-D32ProfilePathWithin -Child $full -Parent $Repository) -or (Test-D32ProfilePathWithin -Child $Repository -Parent $full)) { throw 'PHASE0_OUTPUT_BLOCKED: OutputRoot must be outside and non-overlapping with repository' }
    if (Test-Path -LiteralPath $full) { throw 'PHASE0_OUTPUT_BLOCKED: OutputRoot must not exist or overwrite user data' }
    return $full
}

function Test-D32Phase0FixedInventory {
    param([Parameter(Mandatory = $true)][hashtable]$Inventories)
    foreach ($package in @('protocol', 'vita', 'host')) {
        if (-not $Inventories.ContainsKey($package)) { throw "PHASE0_INVENTORY_BLOCKED: missing package inventory $package" }
        $names = @($Inventories[$package].all)
        if ($names.Count -eq 0 -or @($names | Select-Object -Unique).Count -ne $names.Count) { throw "PHASE0_INVENTORY_BLOCKED: empty or duplicate --list test names in $package" }
    }
    foreach ($name in $script:D32Phase0DeferredVita) { if (@($Inventories.vita.all | Where-Object { $_.EndsWith("::$name", [StringComparison]::Ordinal) -or $_ -ceq $name }).Count -ne 1) { throw "PHASE0_INVENTORY_BLOCKED: deferred Vita test must occur exactly once: $name" } }
    foreach ($name in $script:D32Phase0DeferredHost) { if (@($Inventories.host.all | Where-Object { $_.EndsWith("::$name", [StringComparison]::Ordinal) -or $_ -ceq $name }).Count -ne 1) { throw "PHASE0_INVENTORY_BLOCKED: deferred Host test must occur exactly once: $name" } }
    foreach ($name in $script:D32Phase0IgnoredVita) { if (@($Inventories.vita.ignored | Where-Object { $_.EndsWith("::$name", [StringComparison]::Ordinal) -or $_ -ceq $name }).Count -ne 1) { throw "PHASE0_INVENTORY_BLOCKED: source-ignored Vita test inventory differs: $name" } }
    foreach ($name in $script:D32Phase0IgnoredHost) { if (@($Inventories.host.ignored | Where-Object { $_.EndsWith("::$name", [StringComparison]::Ordinal) -or $_ -ceq $name }).Count -ne 1) { throw "PHASE0_INVENTORY_BLOCKED: source-ignored Host test inventory differs: $name" } }
    if (@($Inventories.protocol.ignored).Count -ne 0 -or @($Inventories.vita.ignored).Count -ne $script:D32Phase0IgnoredVita.Count -or @($Inventories.host.ignored).Count -ne $script:D32Phase0IgnoredHost.Count) {
        throw 'PHASE0_INVENTORY_BLOCKED: unapproved source-ignored tests exist'
    }
    foreach ($name in $script:D32Phase0FocusedVita) { if (@($Inventories.vita.all | Where-Object { $_.EndsWith($name, [StringComparison]::Ordinal) }).Count -ne 1) { throw "PHASE0_INVENTORY_BLOCKED: focused Vita test is not unique: $name" } }
    foreach ($name in $script:D32Phase0FocusedHost) { if (@($Inventories.host.all | Where-Object { $_.EndsWith($name, [StringComparison]::Ordinal) }).Count -ne 1) { throw "PHASE0_INVENTORY_BLOCKED: focused Host test is not unique: $name" } }
    return $true
}

function Invoke-D32Phase0Matrix {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedSha,
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$ProfileSha256,
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$GitSha256,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )
    if ($PSVersionTable.PSVersion -lt [Version]'7.5') { throw 'PHASE0_BLOCKED: PowerShell 7.5 or newer is required' }
    $repo = [IO.Path]::GetFullPath($Repository)
    if (-not (Test-D32ProfileNoReparsePath -Path $repo) -or -not (Test-Path -LiteralPath $repo -PathType Container)) { throw 'PHASE0_BLOCKED: repository must be an existing non-reparse directory' }
    if ($ExpectedSha -cnotmatch '^[0-9a-f]{40}$') { throw 'PHASE0_BLOCKED: exact candidate SHA must be lowercase 40-hex' }
    if ($GitSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'PHASE0_BLOCKED: Git SHA must be lowercase 64-hex' }
    $output = Assert-D32Phase0OutputRoot -Path $EvidenceRoot -Repository $repo
    $profile = Test-D32BuildToolchainProfile -ProfilePath $ProfilePath -ExpectedSha256 $ProfileSha256 -Repository $repo -EvidenceRoot $output
    if (-not $profile.IsValid) { throw "PHASE0_TOOLCHAIN_BLOCKED: $($profile.Failure)" }
    $gitProfile = Test-D32TrustedGitImage -Path $GitPath -ExpectedSha256 $GitSha256
    if (-not $gitProfile.IsValid) { throw "PHASE0_GIT_BLOCKED: $($gitProfile.Failure)" }
    $pre = Get-D32Phase0GitState -Repository $repo -GitPath $GitPath -GitSha256 $GitSha256
    if ($pre.Head -cne $ExpectedSha) { throw 'PHASE0_CANDIDATE_BLOCKED: current HEAD does not equal caller-pinned candidate SHA' }
    $findings = [System.Collections.ArrayList]::new()
    Test-D32Governance -Repository $repo -Findings $findings
    if (@($findings | Where-Object { $_.Severity -eq 'ERROR' }).Count -gt 0) { throw 'PHASE0_GOVERNANCE_BLOCKED: current governance inputs failed preflight' }

    $started = [DateTimeOffset]::UtcNow
    $phaseCommands = [System.Collections.Generic.List[object]]::new()
    $fixtureScript = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-fixture-prebuild.ps1'))
    $fixtureManifestPath = Join-Path $output 'fixture-manifest.json'
    $fixtureTranscriptPath = Join-Path $output 'phase0-fixture-in-process.log'
    $fixtureArguments = @{
        RepoRoot = $repo
        OutputRoot = $output
        ManifestPath = $fixtureManifestPath
        PinnedGitPath = $GitPath
        PinnedGitSha256 = $GitSha256
        ExpectedCandidateSha = $ExpectedSha
        ToolchainProfilePath = $ProfilePath
        ExpectedToolchainProfileSha256 = $ProfileSha256
        TimeoutSeconds = [Math]::Min($TimeoutSeconds, 1800)
    }
    $fixtureOutput = @()
    $fixtureFailure = $null
    try { $fixtureOutput = @(& $fixtureScript @fixtureArguments *>&1) }
    catch {
        $fixtureFailure = $_.Exception.Message
        $fixtureOutput += [string]$_
    }
    $fixtureText = ($fixtureOutput | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    if ($fixtureText.Length -gt 16000000) { throw 'PHASE0_FIXTURE_BLOCKED: in-process fixture output exceeded 16 MB bound' }
    $fixtureGitStates = @(Get-D32Phase0FixtureGitStates -Lines @($fixtureText -split "`r?`n") -ExpectedCandidateSha $ExpectedSha)
    if (Test-Path -LiteralPath $output -PathType Container) {
        [IO.File]::WriteAllText($fixtureTranscriptPath, $fixtureText + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    }
    if ($null -ne $fixtureFailure) { throw "PHASE0_FIXTURE_BLOCKED: in-process fixed fixture runner failed: $fixtureFailure" }
    if (-not (Test-Path -LiteralPath $fixtureManifestPath -PathType Leaf)) { throw 'PHASE0_FIXTURE_BLOCKED: fixed fixture runner did not create its manifest' }
    $fixtureRaw = [IO.File]::ReadAllText($fixtureManifestPath, [Text.Encoding]::UTF8)
    if (Test-D32Phase0JsonDuplicateKeys -Json $fixtureRaw) { throw 'PHASE0_FIXTURE_BLOCKED: fixture manifest contains duplicate or invalid JSON structure' }
    $fixtureDoc = $fixtureRaw | ConvertFrom-D32Phase0Json
    $fixtureFindings = [System.Collections.ArrayList]::new()
    Test-D32FixtureManifest -FixtureManifest $fixtureDoc -FixtureManifestPath $fixtureManifestPath -Head $ExpectedSha -Repository $repo -Findings $fixtureFindings
    if (@($fixtureFindings | Where-Object { $_.Severity -eq 'ERROR' }).Count -gt 0) { throw 'PHASE0_FIXTURE_BLOCKED: fixed fixture manifest or generated output validation failed' }
    $fixtureNames = @($fixtureDoc.fixtures | ForEach-Object { [string]$_.name })
    $expectedFixtureNames = @('d29h1-authority-fixture', 'd29h7-authority-fixture', 'd29h7-process-fixture', 'd29h7-git-helper-fixture', 'd32a-sandbox-fixture')
    if (($fixtureNames -join '|') -cne ($expectedFixtureNames -join '|') -or @($fixtureDoc.fixtures | Where-Object { $_.status -cne 'succeeded' -or $_.exit_code -ne 0 }).Count -ne 0) { throw 'PHASE0_FIXTURE_BLOCKED: fixture phase inventory/result differs from the exact five-phase contract' }
    if ($fixtureDoc.build_policy.cargo_build_jobs -ne 1 -or $fixtureDoc.process_tree_check -cne 'succeeded' -or $null -ne $fixtureDoc.process_tree_error) { throw 'PHASE0_FIXTURE_BLOCKED: fixture process cleanup/build policy did not pass' }
    $fixtureProvenancePath = Join-Path $output 'fixture-build-provenance.json'
    $fixtureProvenanceEvidence = Test-D32Phase0FixtureBuildProvenance -SidecarPath $fixtureProvenancePath -ManifestPath $fixtureManifestPath -Repository $repo -OutputRoot $output -ExpectedCandidateSha $ExpectedSha -ExpectedRunnerProcessId $PID -ValidatedProfile $profile
    $fixtureEnvironment = $fixtureProvenanceEvidence.Document.environment
    $cargoHome = [string]$fixtureEnvironment.cargo_home
    $tempRoot = [string]$fixtureEnvironment.temp_root
    $runId = [string]$fixtureEnvironment.run_id
    if ([String]::IsNullOrWhiteSpace($runId) -or -not (Test-D32ProfilePathWithin -Child $cargoHome -Parent $output) -or -not (Test-D32ProfilePathWithin -Child $tempRoot -Parent $output)) { throw 'PHASE0_CARGO_HOME_BLOCKED: fixture Cargo home/temp are not bound beneath the external evidence root' }
    $cargoHomeCheck = Test-D32CargoHome -Path $cargoHome -Repository $repo
    $lockInputs = @(Get-D32BuildToolchainLockInputs -Repository $repo)
    if (@($fixtureEnvironment.fetch_manifests).Count -ne $lockInputs.Count) { throw 'PHASE0_FETCH_BLOCKED: fixture did not fetch each exact profile-bound manifest' }
    for ($i = 0; $i -lt $lockInputs.Count; $i++) {
        $fetch = $fixtureEnvironment.fetch_manifests[$i]
        if ($fetch.manifest_path -cne $lockInputs[$i].ManifestPath -or $fetch.lock_sha256 -cne $lockInputs[$i].LockSha256 -or $fetch.exit_code -ne 0 -or $fetch.status -cne 'succeeded') { throw "PHASE0_FETCH_BLOCKED: exact locked fetch evidence missing for $($lockInputs[$i].ManifestPath)" }
        $expectedFetchArgs = @('fetch', '--locked', '--manifest-path', $lockInputs[$i].ManifestFullPath, '--target', [string]$profile.Profile.target_triple)
        if (@($fetch.command).Count -ne $expectedFetchArgs.Count -or (@($fetch.command) -join "`0") -cne ($expectedFetchArgs -join "`0")) { throw "PHASE0_FETCH_BLOCKED: fixed locked fetch argv differs for $($lockInputs[$i].ManifestPath)" }
    }
    $fixtureRef = Get-D32Phase0FileReference -Path $fixtureManifestPath
    $fixtureProvenanceRef = $fixtureProvenanceEvidence.Reference
    $fixtureTranscriptRef = Get-D32Phase0FileReference -Path $fixtureTranscriptPath

    $phaseRoot = [string]$fixtureEnvironment.temp_root
    $childEnvironment = Get-D32BuildToolchainEnvironment -ValidatedProfile $profile -CargoHome $cargoHome -TempRoot $phaseRoot -Offline $true
    $cargo = [string]$profile.Profile.toolchain.cargo.path
    $rustc = [string]$profile.Profile.toolchain.rustc.path
    $rustdoc = [string]$profile.Profile.toolchain.rustdoc.path
    $workingDirectory = $repo
    $inventory = [ordered]@{}
    $commandOrdinal = 0
    $testLogRoot = Join-Path $output 'logs'
    if (-not (Test-Path -LiteralPath $testLogRoot -PathType Container) -or -not (Test-D32ProfileNoReparsePath -Path $testLogRoot)) { throw 'PHASE0_LOG_BLOCKED: fixture did not create the expected regular logs directory' }
    $commandArgs = @{
        Ordinal = [ref]$commandOrdinal
        Records = $phaseCommands
        LogRoot = $testLogRoot
        Repository = $repo
        ValidatedProfile = $profile
        Environment = $childEnvironment
        TimeoutSeconds = $TimeoutSeconds
        ExpectedCandidateSha = $ExpectedSha
        GitPath = $GitPath
        GitSha256 = $GitSha256
    }

    $rustcProbe = Invoke-D32Phase0LoggedCommand @commandArgs -Name 'rustc-target-probe' -Executable $rustc -Arguments @('--print', 'cfg', '--target', 'x86_64-pc-windows-msvc')
    $rustcProbeText = Get-D32Phase0TextFromLogs -CommandRecord $rustcProbe
    if (($rustcProbeText -join "`n") -notmatch 'target_arch="x86_64"' -or ($rustcProbeText -join "`n") -notmatch 'target_os="windows"' -or ($rustcProbeText -join "`n") -notmatch 'target_env="msvc"') { throw 'PHASE0_TOOLCHAIN_BLOCKED: pinned rustc target probe did not confirm x86_64-pc-windows-msvc' }

    $listCommands = @{}
    foreach ($package in @('protocol', 'vita', 'host')) {
        $list = Invoke-D32Phase0LoggedCommand @commandArgs -Name "$package-test-list" -Executable $cargo -Arguments (Get-D32Phase0TestCommand -Package $package -Kind list)
        $ignoredList = Invoke-D32Phase0LoggedCommand @commandArgs -Name "$package-ignored-list" -Executable $cargo -Arguments (Get-D32Phase0TestCommand -Package $package -Kind ignored-list)
        $listCommands[$package] = [PSCustomObject]@{
            all = @(Get-D32Phase0ListedTests -Lines @(Get-D32Phase0TextFromLogs -CommandRecord $list))
            ignored = @(Get-D32Phase0IgnoredTests -Lines @(Get-D32Phase0TextFromLogs -CommandRecord $ignoredList))
            list_command = $list.name
            ignored_command = $ignoredList.name
        }
    }
    $inventoryHashtable = @{}
    foreach ($package in @('protocol', 'vita', 'host')) { $inventoryHashtable[$package] = $listCommands[$package] }
    $null = Test-D32Phase0FixedInventory -Inventories $inventoryHashtable
    foreach ($package in @('protocol', 'vita', 'host')) {
        $inventory[$package] = [ordered]@{
            test_names = @($listCommands[$package].all)
            ignored_names = @($listCommands[$package].ignored)
            test_count = [Int64]$listCommands[$package].all.Count
            ignored_count = [Int64]$listCommands[$package].ignored.Count
        }
    }

    $suites = [System.Collections.Generic.List[object]]::new()
    foreach ($package in @('protocol', 'vita', 'host')) {
        $suite = Invoke-D32Phase0LoggedCommand @commandArgs -Name "$package-full-local-suite" -Executable $cargo -Arguments (Get-D32Phase0TestCommand -Package $package -Kind suite)
        $summaries = @(Get-D32Phase0Summaries -Lines @(Get-D32Phase0TextFromLogs -CommandRecord $suite))
        if ($summaries.Count -eq 0) { throw "PHASE0_TEST_BLOCKED: test result summary missing for $package suite" }
        $counts = [ordered]@{
            passed = [Int64](($summaries | Measure-Object -Property passed -Sum).Sum)
            failed = [Int64](($summaries | Measure-Object -Property failed -Sum).Sum)
            ignored = [Int64](($summaries | Measure-Object -Property ignored -Sum).Sum)
            measured = [Int64](($summaries | Measure-Object -Property measured -Sum).Sum)
            filtered_out = [Int64](($summaries | Measure-Object -Property filtered_out -Sum).Sum)
        }
        $expectedIgnored = [Int64]$listCommands[$package].ignored.Count
        $expectedFiltered = if ($package -eq 'vita') { $script:D32Phase0DeferredVita.Count } elseif ($package -eq 'host') { $script:D32Phase0DeferredHost.Count } else { 0 }
        if (@($summaries | Where-Object { $_.status -cne 'ok' }).Count -ne 0 -or -not (Test-D32Phase0SuiteCounts -Counts $counts -TestCount ([Int64]$listCommands[$package].all.Count) -ExpectedIgnored $expectedIgnored -ExpectedFiltered $expectedFiltered)) {
            throw "PHASE0_TEST_BLOCKED: $package suite summary does not reconcile exactly with --list/ignored/deferred inventory"
        }
        $suites.Add([ordered]@{ package = $package; command = $suite.name; status = 'PASS'; summary_count = $summaries.Count; counts = $counts; exact_deferred_skip_count = $expectedFiltered })
    }

    $focused = [System.Collections.Generic.List[object]]::new()
    foreach ($package in @('vita', 'host')) {
        $suffixes = if ($package -eq 'vita') { $script:D32Phase0FocusedVita } else { $script:D32Phase0FocusedHost }
        foreach ($suffix in $suffixes) {
            $matches = @($listCommands[$package].all | Where-Object { $_.EndsWith($suffix, [StringComparison]::Ordinal) })
            if ($matches.Count -ne 1) { throw "PHASE0_TEST_BLOCKED: focused name no longer resolves uniquely: $suffix" }
            $focusedRecord = Invoke-D32Phase0LoggedCommand @commandArgs -Name "$package-focused-$($suffix.Split('::')[-1])" -Executable $cargo -Arguments (Get-D32Phase0TestCommand -Package $package -Kind focused -ExactName $matches[0])
            $focusedSummaries = @(Get-D32Phase0Summaries -Lines @(Get-D32Phase0TextFromLogs -CommandRecord $focusedRecord))
            $passed = [Int64](($focusedSummaries | Measure-Object -Property passed -Sum).Sum)
            $failed = [Int64](($focusedSummaries | Measure-Object -Property failed -Sum).Sum)
            if (@($focusedSummaries | Where-Object { $_.status -cne 'ok' }).Count -ne 0 -or $passed -ne 1 -or $failed -ne 0 -or [Int64](($focusedSummaries | Measure-Object -Property ignored -Sum).Sum) -ne 0) { throw "PHASE0_TEST_BLOCKED: focused test did not pass exactly once: $($matches[0])" }
            $focused.Add([ordered]@{ package = $package; full_name = [string]$matches[0]; command = $focusedRecord.name; status = 'PASS'; passed = $passed; failed = $failed })
        }
    }

    $final = Get-D32Phase0GitState -Repository $repo -GitPath $GitPath -GitSha256 $GitSha256
    if ($final.Head -cne $ExpectedSha) { throw 'PHASE0_CANDIDATE_BLOCKED: final HEAD mismatch' }
    $governanceFiles = @(
        'AGENTS.md', 'docs/governance/PROJECT_SOURCE_OF_TRUTH.md',
        'docs/governance/CURRENT_DEVELOPMENT_STATE.md', 'docs/governance/FROZEN_INVARIANTS.md',
        'docs/governance/ARCHITECTURE_DECISIONS.md', 'docs/governance/MODEL_ROUTING.md',
        'docs/governance/CODEX_DEVELOPMENT_PROTOCOL.md'
    )
    $governance = [System.Collections.Generic.List[object]]::new()
    foreach ($relative in $governanceFiles) {
        $path = Join-Path $repo $relative
        $reference = Get-D32Phase0FileReference -Path $path
        $governance.Add([ordered]@{ relative_path = $relative.Replace('\', '/'); file = $reference })
    }
    $deferred = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $script:D32Phase0DeferredVita) { $deferred.Add([ordered]@{ package = 'vita'; test_name = $name; result = 'NOT RUN — deferred until validated bundle and full aggregate'; status = 'NOT RUN' }) }
    foreach ($name in $script:D32Phase0DeferredHost) { $deferred.Add([ordered]@{ package = 'host'; test_name = $name; result = 'NOT RUN — deferred until validated bundle and full aggregate'; status = 'NOT RUN' }) }
    $provider = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $script:D32Phase0IgnoredVita) { $provider.Add([ordered]@{ package = 'vita'; test_name = $name; result = 'NOT RUN — user-authorized real provider required'; status = 'NOT RUN' }) }
    $capture = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $script:D32Phase0IgnoredHost) { $capture.Add([ordered]@{ package = 'host'; test_name = $name; result = 'N/A — NOT RUN — interactive/physical capture requires separate authorization and hardware'; status = 'N/A — NOT RUN' }) }
    $completed = [DateTimeOffset]::UtcNow
    $fixtureLogRefs = [System.Collections.Generic.List[object]]::new()
    foreach ($path in @(Get-D32Phase0FixtureLogPaths -OutputRoot $output -FixtureRecords @($fixtureDoc.fixtures) -LockInputs $lockInputs)) {
        $fixtureLogRefs.Add((Get-D32Phase0FileReference -Path $path))
    }
    $recordDocument = [ordered]@{
        schema_version = $script:D32Phase0SchemaVersion
        record_type = $script:D32Phase0Type
        runner_process_id = [int]$PID
        candidate_sha = $ExpectedSha
        source_repo = $repo
        output_root = $output
        status = $script:D32Phase0Status
        bundle_hashes = $script:D32Phase0BundleHashes
        started_at_utc = $started.ToString('o')
        completed_at_utc = $completed.ToString('o')
        final_candidate_sha = $final.Head
        final_clean = $true
        powershell = $profile.Profile.powershell
        toolchain_profile = [ordered]@{
            path = $profile.ProfilePath
            sha256 = $profile.Digest
            file_identity = [ordered]@{ bytes = [Int64]$profile.Identity.Bytes; volume_serial_hex = $profile.Identity.VolumeSerialHex; file_id_hex = $profile.Identity.FileIdHex }
            target_triple = [string]$profile.Profile.target_triple
            toolchain = $profile.Profile.toolchain
            executable_inventory = @($profile.ExecutableInventory | ForEach-Object { [ordered]@{ path = $_.Path; sha256 = $_.Sha256; bytes = [Int64]$_.Bytes; volume_serial_hex = $_.VolumeSerialHex; file_id_hex = $_.FileIdHex } })
            lock_inputs = @($profile.LockInputs | ForEach-Object { [ordered]@{ manifest_path = $_.ManifestPath; lock_sha256 = $_.LockSha256 } })
            env_policy = [string]$profile.Profile.env_policy
        }
        cargo_home = [ordered]@{ path = $cargoHome; temp_root = $tempRoot; run_id = $runId; nonempty_after_fetch = (-not $cargoHomeCheck.Empty) }
        fetches = @($fixtureEnvironment.fetch_manifests)
        fixture = [ordered]@{
            manifest = $fixtureRef
            build_provenance = $fixtureProvenanceRef
            transcript = $fixtureTranscriptRef
            schema_version = [Int64]$fixtureDoc.schema_version
            process_tree_check = [string]$fixtureDoc.process_tree_check
            per_phase_git_states = @($fixtureGitStates)
            fixture_names = @($fixtureNames)
            fixture_records = @($fixtureDoc.fixtures)
            log_references = @($fixtureLogRefs.ToArray())
        }
        commands = @($phaseCommands.ToArray())
        test_inventory = $inventory
        local_suites = @($suites.ToArray())
        focused_tests = @($focused.ToArray())
        deferred_d31_tests = @($deferred.ToArray())
        deferred_d29g2_provider_tests = @($provider.ToArray())
        not_run_capture_tests = @($capture.ToArray())
        governance_inputs = @($governance.ToArray())
        phase0_scope = $script:D32Phase0Scope
    }
    $recordPath = Join-Path $output 'D32-PHASE0-MATRIX.json'
    if (Test-Path -LiteralPath $recordPath) { throw 'PHASE0_RECORD_BLOCKED: refusing to overwrite existing record' }
    $json = ConvertTo-Json -InputObject $recordDocument -Depth 40 -Compress
    [IO.File]::WriteAllText($recordPath, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    $recordReference = Get-D32Phase0FileReference -Path $recordPath
    $post = Get-D32Phase0GitState -Repository $repo -GitPath $GitPath -GitSha256 $GitSha256
    if ($post.Head -cne $ExpectedSha) { throw 'PHASE0_CANDIDATE_BLOCKED: candidate changed before Phase0 record was finalized' }
    Write-Output "phase0_status=PASS"
    Write-Output "phase0_candidate_sha=$ExpectedSha"
    Write-Output "phase0_record_path=$recordPath"
    Write-Output "phase0_record_sha256=$($recordReference.sha256)"
    return [PSCustomObject]@{ Success = $true; RecordPath = $recordPath; Record = $recordDocument; RecordReference = $recordReference }
}

function New-D32Phase0SelfTestInventory {
    $vitaNames = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $script:D32Phase0DeferredVita) { $vitaNames.Add("vita::tests::$name") }
    foreach ($name in $script:D32Phase0FocusedVita) { $vitaNames.Add($name) }
    foreach ($name in $script:D32Phase0IgnoredVita) { $vitaNames.Add("vita::tests::$name") }
    $hostNames = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $script:D32Phase0DeferredHost) { $hostNames.Add("host::tests::$name") }
    foreach ($name in $script:D32Phase0FocusedHost) { $hostNames.Add($name) }
    foreach ($name in $script:D32Phase0IgnoredHost) { $hostNames.Add("host::tests::$name") }
    return @{
        protocol = [PSCustomObject]@{ all = @('protocol::tests::ordinary'); ignored = @() }
        vita = [PSCustomObject]@{ all = @($vitaNames.ToArray()); ignored = @($script:D32Phase0IgnoredVita | ForEach-Object { "vita::tests::$_" }) }
        host = [PSCustomObject]@{ all = @($hostNames.ToArray()); ignored = @($script:D32Phase0IgnoredHost | ForEach-Object { "host::tests::$_" }) }
    }
}

function Test-D32Phase0MatrixRecordSelfTest {
    $cases = [System.Collections.Generic.List[object]]::new()
    $add = { param([string]$Name, [bool]$Passed, [AllowNull()][string]$Detail = $null) $cases.Add([PSCustomObject]@{ name = $Name; passed = $Passed; detail = $Detail }) }.GetNewClosure()

    $inventory = New-D32Phase0SelfTestInventory
    try { $null = Test-D32Phase0FixedInventory -Inventories $inventory; & $add 'approved test inventory is accepted exactly' $true }
    catch { & $add 'approved test inventory is accepted exactly' $false }

    $missingD31 = New-D32Phase0SelfTestInventory
    $missingD31.vita.all = @($missingD31.vita.all | Where-Object { -not $_.EndsWith("::$($script:D32Phase0DeferredVita[0])", [StringComparison]::Ordinal) })
    try { $null = Test-D32Phase0FixedInventory -Inventories $missingD31; & $add 'missing D31 deferred name is rejected' $false }
    catch { & $add 'missing D31 deferred name is rejected' ($_.Exception.Message -match 'deferred Vita') }

    $duplicateName = New-D32Phase0SelfTestInventory
    $duplicateName.host.all = @($duplicateName.host.all) + @($duplicateName.host.all[0])
    try { $null = Test-D32Phase0FixedInventory -Inventories $duplicateName; & $add 'duplicate --list name is rejected' $false }
    catch { & $add 'duplicate --list name is rejected' ($_.Exception.Message -match 'duplicate') }

    $missingPackage = New-D32Phase0SelfTestInventory
    $null = $missingPackage.Remove('host')
    try { $null = Test-D32Phase0FixedInventory -Inventories $missingPackage; & $add 'missing package inventory is rejected' $false }
    catch { & $add 'missing package inventory is rejected' ($_.Exception.Message -match 'missing package') }

    $extraIgnored = New-D32Phase0SelfTestInventory
    $extraIgnored.vita.ignored = @($extraIgnored.vita.ignored) + @('vita::tests::unapproved_ignored_test')
    try { $null = Test-D32Phase0FixedInventory -Inventories $extraIgnored; & $add 'unapproved ignored test is rejected' $false }
    catch { & $add 'unapproved ignored test is rejected' ($_.Exception.Message -match 'unapproved source-ignored') }

    $missingIgnored = New-D32Phase0SelfTestInventory
    $missingIgnored.host.ignored = @($missingIgnored.host.ignored | Select-Object -Skip 1)
    try { $null = Test-D32Phase0FixedInventory -Inventories $missingIgnored; & $add 'missing approved ignored test is rejected' $false }
    catch { & $add 'missing approved ignored test is rejected' ($_.Exception.Message -match 'source-ignored Host') }

    $ambiguousFocused = New-D32Phase0SelfTestInventory
    $ambiguousFocused.vita.all = @($ambiguousFocused.vita.all) + @("other::$($script:D32Phase0FocusedVita[0])")
    try { $null = Test-D32Phase0FixedInventory -Inventories $ambiguousFocused; & $add 'ambiguous focused test is rejected' $false }
    catch { & $add 'ambiguous focused test is rejected' ($_.Exception.Message -match 'focused Vita') }

    $missingIgnoredPackage = New-D32Phase0SelfTestInventory
    $missingIgnoredPackage.protocol.ignored = @('protocol::tests::unapproved_ignored')
    try { $null = Test-D32Phase0FixedInventory -Inventories $missingIgnoredPackage; & $add 'source-ignored protocol test is rejected' $false }
    catch { & $add 'source-ignored protocol test is rejected' ($_.Exception.Message -match 'unapproved source-ignored') }

    & $add 'captured test list exactly matches the declared inventory' (Test-D32Phase0ExactTestListOutput -Lines @('module::a: test', 'module::b: test', '2 tests, 0 benchmarks') -Expected @('module::a', 'module::b'))
    & $add 'captured test list rejects a missing declared name' (-not (Test-D32Phase0ExactTestListOutput -Lines @('module::a: test') -Expected @('module::a', 'module::b')))
    & $add 'captured test list rejects an extra name' (-not (Test-D32Phase0ExactTestListOutput -Lines @('module::a: test', 'module::b: test') -Expected @('module::a')))
    & $add 'captured test list rejects a duplicate name' (-not (Test-D32Phase0ExactTestListOutput -Lines @('module::a: test', 'module::a: test') -Expected @('module::a')))

    $candidate = ('a' * 40) -join ''
    $gitStateLines = [System.Collections.Generic.List[string]]::new()
    for ($phase = 1; $phase -le 5; $phase++) {
        $gitStateLines.Add("D32_FIXTURE_GIT_STATE phase=$phase edge=before head=$candidate clean=true")
        $gitStateLines.Add("D32_FIXTURE_GIT_STATE phase=$phase edge=after head=$candidate clean=true")
    }
    try { $validGitStates = @(Get-D32Phase0FixtureGitStates -Lines @($gitStateLines.ToArray()) -ExpectedCandidateSha $candidate); & $add 'five fixture phases require exact pre/post candidate and clean evidence' ($validGitStates.Count -eq 10) }
    catch { & $add 'five fixture phases require exact pre/post candidate and clean evidence' $false }
    $fakeOutputRoot = Join-Path ([IO.Path]::GetTempPath()) ('d32-phase0-logs-selftest-' + [Guid]::NewGuid().ToString('N'))
    $fakeFixtureNames = @('d29h1-authority-fixture', 'd29h7-authority-fixture', 'd29h7-process-fixture', 'd29h7-git-helper-fixture', 'd32a-sandbox-fixture')
    $fakeFixtureRecords = @(
        for ($index = 0; $index -lt $fakeFixtureNames.Count; $index++) {
            $stem = Join-Path (Join-Path $fakeOutputRoot 'logs') ('{0:D2}-{1}' -f ($index + 1), $fakeFixtureNames[$index])
            [PSCustomObject]@{ name = $fakeFixtureNames[$index]; phase_log = $stem; stdout_log = $stem + '.stdout.log'; stderr_log = $stem + '.stderr.log' }
        }
    )
    $fakeLockInputs = @([PSCustomObject]@{}, [PSCustomObject]@{}, [PSCustomObject]@{})
    try {
        $fakeLogPaths = @(Get-D32Phase0FixtureLogPaths -OutputRoot $fakeOutputRoot -FixtureRecords $fakeFixtureRecords -LockInputs $fakeLockInputs)
        $expectedLogNames = [System.Collections.Generic.List[string]]::new()
        foreach ($fixtureName in $fakeFixtureNames) {
            $phaseIndex = [Array]::IndexOf($fakeFixtureNames, $fixtureName) + 1
            $stemName = '{0:D2}-{1}' -f $phaseIndex, $fixtureName
            $expectedLogNames.Add($stemName + '.stdout.log')
            $expectedLogNames.Add($stemName + '.stderr.log')
        }
        for ($fetchIndex = 1; $fetchIndex -le 3; $fetchIndex++) {
            $stemName = 'fixture-{0:D2}-fetch' -f $fetchIndex
            $expectedLogNames.Add($stemName + '.stdout.log')
            $expectedLogNames.Add($stemName + '.stderr.log')
        }
        $actualLogNames = @($fakeLogPaths | ForEach-Object { [IO.Path]::GetFileName($_) })
        & $add 'fixture log inventory binds only the exact ten fixture and six fetch stdout/stderr captures' ($fakeLogPaths.Count -eq 16 -and ($actualLogNames -join '|') -ceq ($expectedLogNames.ToArray() -join '|'))
    }
    catch { & $add 'fixture log inventory binds only the exact ten fixture and six fetch stdout/stderr captures' $false $_.Exception.Message }
    $wrongFixtureLogRecords = @($fakeFixtureRecords)
    $wrongFixtureLogRecords[0] = [PSCustomObject]@{ name = $fakeFixtureNames[0]; phase_log = $fakeFixtureRecords[0].phase_log; stdout_log = $fakeFixtureRecords[1].stdout_log; stderr_log = $fakeFixtureRecords[0].stderr_log }
    $wrongFixtureLogsRejected = $false
    try { $null = Get-D32Phase0FixtureLogPaths -OutputRoot $fakeOutputRoot -FixtureRecords $wrongFixtureLogRecords -LockInputs $fakeLockInputs }
    catch { $wrongFixtureLogsRejected = $_.Exception.Message -like '*fixed fixture log paths differ*' }
    & $add 'fixture log inventory rejects duplicate or swapped fixture output paths' $wrongFixtureLogsRejected
    $missingGitState = @($gitStateLines.ToArray() | Select-Object -SkipLast 1)
    try { $null = Get-D32Phase0FixtureGitStates -Lines $missingGitState -ExpectedCandidateSha $candidate; & $add 'missing fixture per-phase Git state is rejected' $false }
    catch { & $add 'missing fixture per-phase Git state is rejected' ($_.Exception.Message -match 'expected 10') }
    $dirtyGitState = @($gitStateLines.ToArray())
    $dirtyGitState[1] = $dirtyGitState[1].Replace('clean=true', 'clean=false')
    try { $null = Get-D32Phase0FixtureGitStates -Lines $dirtyGitState -ExpectedCandidateSha $candidate; & $add 'dirty fixture per-phase Git state is rejected' $false }
    catch { & $add 'dirty fixture per-phase Git state is rejected' ($_.Exception.Message -match 'candidate/clean check failed') }
    $wrongGitState = @($gitStateLines.ToArray())
    $wrongGitState[0] = $wrongGitState[0].Replace($candidate, ('b' * 40))
    try { $null = Get-D32Phase0FixtureGitStates -Lines $wrongGitState -ExpectedCandidateSha $candidate; & $add 'wrong fixture per-phase candidate SHA is rejected' $false }
    catch { & $add 'wrong fixture per-phase candidate SHA is rejected' ($_.Exception.Message -match 'candidate/clean check failed') }
    $duplicateGitState = @($gitStateLines.ToArray())
    $duplicateGitState[1] = $duplicateGitState[0]
    try { $null = Get-D32Phase0FixtureGitStates -Lines $duplicateGitState -ExpectedCandidateSha $candidate; & $add 'duplicate fixture state edge is rejected' $false }
    catch { & $add 'duplicate fixture state edge is rejected' ($_.Exception.Message -match 'missing, duplicated, reordered, or extra') }

    $goodShape = [PSCustomObject][ordered]@{ name = 'cargo.exe'; path = 'C:\\pinned\\cargo.exe' }
    & $add 'strict phase0 object schema accepts exact shape' (Test-D32Phase0ExactProperties -Object $goodShape -Expected @('name', 'path'))
    & $add 'strict phase0 object schema rejects missing field' (-not (Test-D32Phase0ExactProperties -Object ([PSCustomObject]@{ name = 'cargo.exe' }) -Expected @('name', 'path')))
    & $add 'strict phase0 object schema rejects extra field' (-not (Test-D32Phase0ExactProperties -Object ([PSCustomObject][ordered]@{ name = 'cargo.exe'; path = 'C:\\pinned\\cargo.exe'; extra = $true }) -Expected @('name', 'path')))
    & $add 'strict phase0 integers reject string coercion' (-not (Test-D32Phase0Integer -Value '1' -Positive))
    & $add 'Phase0 JSON parser detects duplicate keys recursively' (Test-D32Phase0JsonDuplicateKeys -Json '{"outer":{"name":1,"name":2}}')
    & $add 'Phase0 JSON parser rejects malformed JSON before schema parsing' (Test-D32Phase0JsonDuplicateKeys -Json '{"name":')
    & $add 'Phase0 JSON parser accepts exact nested JSON' (-not (Test-D32Phase0JsonDuplicateKeys -Json '{"outer":{"name":1},"items":[true,4]}'))
    $minimalProfile = [PSCustomObject]@{ ExecutableInventory = @() }
    & $add 'unapproved Git/SSH/credential image is blocked from process inventory' ([String]::IsNullOrWhiteSpace((Get-D32Phase0AllowedChildImageReason -ImagePath 'C:\\unapproved\\git.exe' -ValidatedProfile $minimalProfile -Repository 'C:\\candidate')))
    & $add 'candidate debug target process images require explicit candidate-owned classification' ((Get-D32Phase0AllowedChildImageReason -ImagePath 'C:\\candidate\\vita-agent\\target\\debug\\build-script.exe' -ValidatedProfile $minimalProfile -Repository 'C:\\candidate') -ceq 'candidate-owned-target-image-observed-by-opened-handle')
    & $add 'candidate release build-script images are covered by captured opened-handle identity' ((Get-D32Phase0AllowedChildImageReason -ImagePath 'C:\\candidate\\src-tauri\\target\\release\\build\\script.exe' -ValidatedProfile $minimalProfile -Repository 'C:\\candidate') -ceq 'candidate-owned-target-image-observed-by-opened-handle')

    $validCounts = [PSCustomObject][ordered]@{ passed = [Int64]3; failed = [Int64]0; ignored = [Int64]1; measured = [Int64]0; filtered_out = [Int64]1 }
    & $add 'suite counts reconcile with exact list, ignore and skip totals' (Test-D32Phase0SuiteCounts -Counts $validCounts -TestCount 5 -ExpectedIgnored 1 -ExpectedFiltered 1)
    & $add 'suite counts reject a missing field' (-not (Test-D32Phase0SuiteCounts -Counts ([PSCustomObject]@{ passed = 3; failed = 0; ignored = 1; measured = 0 }) -TestCount 5 -ExpectedIgnored 1 -ExpectedFiltered 1))
    & $add 'suite counts reject string-coerced scalars' (-not (Test-D32Phase0SuiteCounts -Counts ([PSCustomObject][ordered]@{ passed = '3'; failed = 0; ignored = 1; measured = 0; filtered_out = 1 }) -TestCount 5 -ExpectedIgnored 1 -ExpectedFiltered 1))
    & $add 'suite counts reject nonzero failures' (-not (Test-D32Phase0SuiteCounts -Counts ([PSCustomObject][ordered]@{ passed = 2; failed = 1; ignored = 1; measured = 0; filtered_out = 1 }) -TestCount 5 -ExpectedIgnored 1 -ExpectedFiltered 1))
    & $add 'suite counts reject unexpected ignore totals' (-not (Test-D32Phase0SuiteCounts -Counts $validCounts -TestCount 5 -ExpectedIgnored 0 -ExpectedFiltered 1))
    & $add 'suite counts reject unexpected filtered-out totals' (-not (Test-D32Phase0SuiteCounts -Counts $validCounts -TestCount 5 -ExpectedIgnored 1 -ExpectedFiltered 0))
    & $add 'suite counts reject totals that do not reconcile' (-not (Test-D32Phase0SuiteCounts -Counts $validCounts -TestCount 6 -ExpectedIgnored 1 -ExpectedFiltered 1))

    $suiteArgv = @(Get-D32Phase0TestCommand -Package vita -Kind suite)
    $expectedSkips = @()
    foreach ($name in $script:D32Phase0DeferredVita) { $expectedSkips += @('--skip', $name) }
    & $add 'full suite argv contains each exact D31 deferral only' (($suiteArgv -join "`0") -ceq ((@('test', '--manifest-path', 'vita-agent/Cargo.toml', '--all-targets', '--locked', '--offline', '--features', 'd32-a-test-helper', '--') + $expectedSkips) -join "`0"))
    & $add 'full suite argv does not globally serialize tests' (-not ($suiteArgv -contains '--test-threads=1'))
    & $add 'fixed test list parser ignores non-test benchmark count lines' ((@(Get-D32Phase0ListedTests -Lines @('module::case: test', '0 tests, 0 benchmarks')) -join '|') -ceq 'module::case')
    & $add 'ignored test parser returns exact listed names' ((@(Get-D32Phase0IgnoredTests -Lines @('module::ignored: test', '1 test, 0 benchmarks')) -join '|') -ceq 'module::ignored')

    $goodSummary = @(Get-D32Phase0Summaries -Lines @('test result: ok. 3 passed; 0 failed; 1 ignored; 0 measured; 1 filtered out; finished in 0.03s'))
    $failedSummary = @(Get-D32Phase0Summaries -Lines @('test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.03s'))
    & $add 'summary parser preserves integer counts' ($goodSummary.Count -eq 1 -and $goodSummary[0].passed -is [Int64] -and $goodSummary[0].ignored -eq 1 -and $goodSummary[0].filtered_out -eq 1)
    & $add 'summary parser preserves FAILED status' ($failedSummary.Count -eq 1 -and $failedSummary[0].status -ceq 'FAILED' -and $failedSummary[0].failed -eq 1)

    & $add 'fixed inventories enumerate the approved ten D31 deferrals' ($script:D32Phase0DeferredVita.Count + $script:D32Phase0DeferredHost.Count -eq 10)
    & $add 'provider and hardware cases remain explicit not-run cases' ($script:D32Phase0IgnoredVita.Count -eq 4 -and $script:D32Phase0IgnoredHost.Count -eq 3)
    & $add 'Phase0 record constants label local-only evidence and pending bundle hashes' ($script:D32Phase0Type -ceq 'D32_PHASE0_MATRIX_RECORD_V1' -and $script:D32Phase0Scope -like 'local-fixture-and-test-matrix-only*' -and $script:D32Phase0BundleHashes -ceq 'PENDING')

    $tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $selfTestRoot = Join-Path $tempBase ('d32-phase0-sidecar-selftest-' + [Guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $selfTestRoot) { throw 'Phase0 sidecar self-test root unexpectedly already exists' }
    [void][IO.Directory]::CreateDirectory($selfTestRoot)
    try {
        if (-not (Test-D32ProfileNoReparsePath -Path $selfTestRoot) -or -not (Test-D32ProfilePathEqual -Left ([IO.Path]::GetDirectoryName($selfTestRoot)) -Right $tempBase)) { throw 'Phase0 sidecar self-test temp root is not a direct regular temp child' }
        $runId = '0123456789abcdef0123456789abcdef'
        $runRoot = Join-Path $selfTestRoot "fixture-toolchain-run-$runId"
        $cargoHome = Join-Path $runRoot 'cargo-home'
        $tempRoot = Join-Path $runRoot 'temp'
        [void][IO.Directory]::CreateDirectory($cargoHome)
        [void][IO.Directory]::CreateDirectory($tempRoot)
        $manifestPath = Join-Path $selfTestRoot 'fixture-manifest.json'
        $sidecarPath = Join-Path $selfTestRoot 'fixture-build-provenance.json'
        $emptyLogPath = Join-Path $selfTestRoot 'empty-stderr.log'
        [IO.File]::WriteAllText($manifestPath, '{}', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllBytes($emptyLogPath, [byte[]]@())
        $manifestSnapshot = Get-D32ProfileFileSnapshot -Path $manifestPath
        $profilePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-build-toolchain-profile.ps1'))
        $fakeCargoPath = Join-Path $selfTestRoot 'toolchain/cargo.exe'
        $fakeLockInput = [PSCustomObject]@{
            ManifestPath = 'vita-agent/Cargo.toml'
            ManifestFullPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'vita-agent/Cargo.toml'))
            LockSha256 = ('f' * 64)
        }
        $fakeProfile = [PSCustomObject]@{
            ProfilePath = $profilePath
            Digest = ('b' * 64)
            Profile = [PSCustomObject]@{
                target_triple = 'x86_64-pc-windows-msvc'
                env_policy = 'D32_BUILD_ENV_V1'
                cargo_policy = 'FRESH_HOME_LOCKED_FETCH_OFFLINE_AFTER'
                toolchain = [PSCustomObject]@{ cargo = [PSCustomObject]@{ path = $fakeCargoPath } }
            }
            LockInputs = @($fakeLockInput)
        }
        $expectedFetchArgs = @('fetch', '--locked', '--manifest-path', $fakeLockInput.ManifestFullPath, '--target', $fakeProfile.Profile.target_triple)
        $fakeFetch = [ordered]@{
            manifest_path = $fakeLockInput.ManifestPath
            lock_sha256 = $fakeLockInput.LockSha256
            command = $expectedFetchArgs
            status = 'succeeded'
            exit_code = 0
            process_identity = [ordered]@{
                process_id = 2000000000
                parent_process_id = $PID
                name = 'cargo.exe'
                image_path = $fakeCargoPath
                creation_date = '2026-09-23T00:00:00.0000000Z'
                command_line = (ConvertTo-D32Phase0CommandLine -Arguments (@($fakeCargoPath) + $expectedFetchArgs))
                observed_at_utc = '2026-09-23T00:00:00.0000000Z'
                identity_verified = $true
            }
        }
        $sidecar = [ordered]@{
            schema_version = 1
            record_type = 'D32_FIXTURE_BUILD_PROVENANCE_V1'
            candidate_sha = $candidate
            source_repo = $PSScriptRoot
            fixture_manifest_path = $manifestSnapshot.Path
            fixture_manifest_sha256 = $manifestSnapshot.Sha256
            fixture_manifest_bytes = [Int64]$manifestSnapshot.Bytes
            fixture_manifest_volume_serial_hex = $manifestSnapshot.VolumeSerialHex
            fixture_manifest_file_id_hex = $manifestSnapshot.FileIdHex
            environment = [ordered]@{
                toolchain_profile_path = $profilePath
                toolchain_profile_sha256 = $fakeProfile.Digest
                target_triple = $fakeProfile.Profile.target_triple
                env_policy = $fakeProfile.Profile.env_policy
                cargo_policy = $fakeProfile.Profile.cargo_policy
                cargo_home = $cargoHome
                temp_root = $tempRoot
                run_id = $runId
                fetch_manifests = @($fakeFetch)
                offline_after_fetch = $true
            }
        }
        $writeSidecar = { param($value) [IO.File]::WriteAllText($sidecarPath, (ConvertTo-Json -InputObject $value -Depth 12), [Text.UTF8Encoding]::new($false)) }.GetNewClosure()
        & $writeSidecar $sidecar
        try {
            $validSidecar = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $PSScriptRoot -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile
            & $add 'fixture build provenance v1 accepts exact manifest identity/profile/fresh-home contract' ($validSidecar.Document.record_type -ceq 'D32_FIXTURE_BUILD_PROVENANCE_V1')
        }
        catch { & $add 'fixture build provenance v1 accepts exact manifest identity/profile/fresh-home contract' $false $_.Exception.Message }

        $missingEnvironmentField = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $missingEnvironmentField.environment.Remove('run_id')
        & $writeSidecar $missingEnvironmentField
        $missingRejected = $false
        $missingFailure = $null
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $PSScriptRoot -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $missingRejected = $_.Exception.Message -like '*missing or extra fields*'; if (-not $missingRejected) { $missingFailure = $_.Exception.Message } }
        & $add 'fixture provenance rejects a missing environment field' $missingRejected $missingFailure

        $extraEnvironmentField = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $extraEnvironmentField.environment.extra = 'unapproved'
        & $writeSidecar $extraEnvironmentField
        $extraRejected = $false
        $extraFailure = $null
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $PSScriptRoot -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $extraRejected = $_.Exception.Message -like '*missing or extra fields*'; if (-not $extraRejected) { $extraFailure = $_.Exception.Message } }
        & $add 'fixture provenance rejects an extra environment field' $extraRejected $extraFailure

        $missingFetchField = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $missingFetchField.environment.fetch_manifests[0].Remove('process_identity')
        & $writeSidecar $missingFetchField
        $fetchFieldRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $PSScriptRoot -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $fetchFieldRejected = $_.Exception.Message -like '*fixed locked fetch record is invalid*' }
        & $add 'fixture provenance rejects a missing nested locked-fetch evidence field' $fetchFieldRejected

        $wrongFetchArgv = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $wrongFetchArgv.environment.fetch_manifests[0].command[1] = '--offline'
        & $writeSidecar $wrongFetchArgv
        $fetchArgvRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $PSScriptRoot -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $fetchArgvRejected = $_.Exception.Message -like '*fixed locked fetch argv mismatch*' }
        & $add 'fixture provenance rejects altered locked-fetch argv' $fetchArgvRejected

        $wrongFetchParent = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $wrongFetchParent.environment.fetch_manifests[0].process_identity.parent_process_id = $PID + 1
        & $writeSidecar $wrongFetchParent
        $fetchParentRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $PSScriptRoot -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $fetchParentRejected = $_.Exception.Message -like '*Cargo process identity evidence is invalid*' }
        & $add 'fixture provenance requires fetch Cargo to be parented by the pinned Phase0 process' $fetchParentRejected

        $wrongManifestIdentity = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $wrongManifestIdentity.fixture_manifest_file_id_hex = '0' * 32
        & $writeSidecar $wrongManifestIdentity
        $identityRejected = $false
        $identityFailure = $null
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $PSScriptRoot -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $identityRejected = $_.Exception.Message -like '*does not bind current fixture manifest bytes and opened-handle identity*'; if (-not $identityRejected) { $identityFailure = $_.Exception.Message } }
        & $add 'fixture provenance rejects a same-bytes manifest identity mismatch' $identityRejected $identityFailure

        $emptyLogReference = [PSCustomObject](Get-D32Phase0FileReference -Path $emptyLogPath)
        $emptyLogAccepted = $false
        try { $emptySnapshot = Test-D32Phase0FileReference -Reference $emptyLogReference -AllowedRoot $selfTestRoot; $emptyLogAccepted = ($emptySnapshot.Bytes -eq 0) }
        catch { $emptyLogAccepted = $false }
        & $add 'zero-byte captured stderr/stdout references are valid with native identity' $emptyLogAccepted

        $stringBytesReference = [PSCustomObject](Get-D32Phase0FileReference -Path $emptyLogPath)
        $stringBytesReference.bytes = '0'
        $stringBytesRejected = $false
        try { $null = Test-D32Phase0FileReference -Reference $stringBytesReference -AllowedRoot $selfTestRoot }
        catch { $stringBytesRejected = $_.Exception.Message -like '*scalar is malformed*' }
        & $add 'file references reject string-coerced zero-byte size' $stringBytesRejected
    }
    finally {
        if (Test-Path -LiteralPath $selfTestRoot) {
            if (-not (Test-D32ProfileNoReparsePath -Path $selfTestRoot) -or -not (Test-D32ProfilePathEqual -Left ([IO.Path]::GetDirectoryName($selfTestRoot)) -Right $tempBase)) { throw 'Phase0 sidecar self-test cleanup target no longer resolves to its exact regular temp child' }
            [IO.Directory]::Delete($selfTestRoot, $true)
        }
    }
    return @($cases.ToArray())
}

if ($Phase0LibraryOnly) { return }
if ($Phase0SelfTest) {
    $cases = @(Test-D32Phase0MatrixRecordSelfTest)
    foreach ($case in $cases) {
        if (-not $case.passed) { Write-Output "PHASE0 SELFTEST FAIL: $($case.name) $($case.detail)" }
        else { Write-Output "PHASE0 SELFTEST PASS: $($case.name)" }
    }
    if (@($cases | Where-Object { -not $_.passed }).Count -gt 0) { exit 1 }
    Write-Output "D32 Phase0 runner SelfTest: PASS ($($cases.Count) assertions)"
    exit 0
}

if ([String]::IsNullOrWhiteSpace($Phase0RepoRoot)) { $Phase0RepoRoot = Split-Path -Parent $PSScriptRoot }
foreach ($required in @(@('OutputRoot', $Phase0OutputRoot), @('ExpectedCandidateSha', $Phase0ExpectedCandidateSha), @('ToolchainProfilePath', $Phase0ToolchainProfilePath), @('ExpectedToolchainProfileSha256', $Phase0ExpectedToolchainProfileSha256), @('PinnedGitPath', $Phase0PinnedGitPath), @('PinnedGitSha256', $Phase0PinnedGitSha256))) {
    if ([String]::IsNullOrWhiteSpace([string]$required[1])) { Write-Output "D32 Phase0: BLOCKED — -$($required[0]) is required"; exit 2 }
}
try {
    $result = Invoke-D32Phase0Matrix -Repository $Phase0RepoRoot -EvidenceRoot $Phase0OutputRoot -ExpectedSha $Phase0ExpectedCandidateSha -ProfilePath $Phase0ToolchainProfilePath -ProfileSha256 $Phase0ExpectedToolchainProfileSha256 -GitPath $Phase0PinnedGitPath -GitSha256 $Phase0PinnedGitSha256 -TimeoutSeconds $Phase0TimeoutSeconds
    if ($result.Success) { exit 0 }
    exit 1
}
catch {
    Write-Output "D32 Phase0: BLOCKED — $($_.Exception.Message)"
    exit 1
}
