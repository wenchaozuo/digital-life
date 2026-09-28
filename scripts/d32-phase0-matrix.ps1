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
    [string]$Phase0VendoredProtocAuthorityPath,
    [string]$Phase0ExpectedVendoredProtocAuthoritySha256,
    [string]$Phase0TauriMacrosSourceAuthorityPath,
    [string]$Phase0ExpectedTauriMacrosSourceAuthoritySha256,
    [string]$Phase0H7CGitAuthorityPath,
    [string]$Phase0ExpectedH7CGitAuthoritySha256,
    # Keep the original 1800-second default; owner-bound Phase0 callers may explicitly pin a bounded four-hour per-command limit.
    [Alias('TimeoutSeconds')][ValidateRange(60, 14400)][int]$Phase0TimeoutSeconds = 1800
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([String]::IsNullOrWhiteSpace($PSCommandPath)) { throw 'PHASE0_LOCATION_BLOCKED: the Phase0 runner must be loaded from its exact script file' }
$script:D32Phase0ScriptPath = [IO.Path]::GetFullPath($PSCommandPath)
$script:D32Phase0ScriptRoot = Split-Path -Parent $script:D32Phase0ScriptPath
. (Join-Path $script:D32Phase0ScriptRoot 'd32-build-toolchain-profile.ps1')
. (Join-Path $script:D32Phase0ScriptRoot 'd32-vendored-protoc-authority.ps1')
. (Join-Path $script:D32Phase0ScriptRoot 'd32-h7c-git-child-authority.ps1')

$script:D32Phase0Type = 'D32_PHASE0_MATRIX_RECORD_V5'
$script:D32Phase0SchemaVersion = 5
$script:D32Phase0FixtureOwnerMarkerName = '.d32-fixture-prebuild-owned'
$script:D32Phase0FixtureOwnerMarker = 'D32_FIXTURE_PREBUILD_OWNER_V1'
$script:D32Phase0OwnerBindingName = 'D32-PHASE0-OWNER.json'
$script:D32Phase0OwnerBindingType = 'D32_PHASE0_EVIDENCE_OWNER_V1'
$script:D32Phase0BlockedDiagnosticName = 'D32-PHASE0-BLOCKED-DIAGNOSTIC.json'
$script:D32Phase0BlockedDiagnosticType = 'D32_PHASE0_BLOCKED_DIAGNOSTIC_V1'
$script:D32Phase0FailureContext = $null
$script:D32Phase0LastProcessFailure = $null
$script:D32Phase0SelfTestSourcePatchAuthorityPath = $null
$script:D32Phase0SelfTestSourcePatchAuthoritySha256 = $null
$script:D32Phase0FixtureBuildSpecs = @(
    [PSCustomObject]@{ name = 'd29h1-authority-fixture'; manifest = 'src-tauri/Cargo.toml'; binary = 'd29h1-authority-fixture'; features = @('d29-h1-host-fixture') },
    [PSCustomObject]@{ name = 'd29h7-authority-fixture'; manifest = 'src-tauri/Cargo.toml'; binary = 'd29h7-authority-fixture'; features = @('d29-h7-host-fixture') },
    [PSCustomObject]@{ name = 'd29h7-process-fixture'; manifest = 'vita-agent/Cargo.toml'; binary = 'd29h7-process-fixture'; features = @() },
    [PSCustomObject]@{ name = 'd29h7-git-helper-fixture'; manifest = 'vita-agent/Cargo.toml'; binary = 'd29h7-git-helper-fixture'; features = @('d29-h7-test-helper') },
    [PSCustomObject]@{ name = 'd32a-sandbox-fixture'; manifest = 'vita-agent/Cargo.toml'; binary = 'd32a-sandbox-fixture'; features = @('d32-a-test-helper') }
)
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
$script:D32Phase0PreflightDependencyFunctionNames = @(
    'Get-D32Head',
    'New-D32FindingList',
    'Test-D32FixtureManifest',
    'Test-D32GitClean',
    'Test-D32Governance',
    'Test-D32Sha40',
    'Test-D32TrustedGitImage'
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
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ExpectedRootPath,
        [AllowNull()][object]$VendoredProtocGrant,
        [AllowNull()][object]$H7CGitRunGrant
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
    $allowReason = Get-D32Phase0AllowedChildImageReason -ImagePath $imagePath -ValidatedProfile $ValidatedProfile -Repository $Repository -ExpectedRootPath $ExpectedRootPath -ImageIdentity $snapshot -VendoredProtocGrant $VendoredProtocGrant -H7CGitRunGrant $H7CGitRunGrant
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
    param(
        [Parameter(Mandatory = $true)][string]$ImagePath,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ExpectedRootPath,
        [AllowNull()][object]$ImageIdentity,
        [AllowNull()][object]$VendoredProtocGrant,
        [AllowNull()][object]$H7CGitRunGrant
    )
    $imageName = [IO.Path]::GetFileName($ImagePath).ToLowerInvariant()
    $imageBytes = Get-D32Phase0DiagnosticPropertyValue -Object $ImageIdentity -Names @('bytes', 'Bytes')
    $imageSha256 = Get-D32Phase0DiagnosticPropertyValue -Object $ImageIdentity -Names @('sha256', 'Sha256')
    $knownVctipContent = Test-D32ProfilePinnedVctipContentIdentity -Bytes $imageBytes -Sha256 $imageSha256
    $knownVendoredProtocContent = ([Int64]$imageBytes -eq $script:D32VendoredProtocImageBytes -and [string]$imageSha256 -ceq $script:D32VendoredProtocImageSha256)
    if ($imageName -ceq 'git.exe') {
        if ($null -eq $H7CGitRunGrant -or $null -eq $H7CGitRunGrant.GitImage -or
            -not (Test-D32ProfilePathEqual -Left $ImagePath -Right $H7CGitRunGrant.GitImage.Path) -or
            [Int64]$imageBytes -ne [Int64]$H7CGitRunGrant.GitImage.Bytes -or $imageSha256 -cne [string]$H7CGitRunGrant.GitImage.Sha256) { return $null }
        $openedPath = Get-D32Phase0DiagnosticPropertyValue -Object $ImageIdentity -Names @('path', 'Path', 'image_path', 'ImagePath')
        $openedVolume = Get-D32Phase0DiagnosticPropertyValue -Object $ImageIdentity -Names @('volume_serial_hex', 'VolumeSerialHex')
        $openedFileId = Get-D32Phase0DiagnosticPropertyValue -Object $ImageIdentity -Names @('file_id_hex', 'FileIdHex')
        if ($openedPath -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $openedPath -Right $H7CGitRunGrant.GitImage.Path) -or
            $openedVolume -cne [string]$H7CGitRunGrant.GitImage.VolumeSerialHex -or $openedFileId -cne [string]$H7CGitRunGrant.GitImage.FileIdHex -or
            -not (Test-D32ProfilePathEqual -Left $ExpectedRootPath -Right ([string]$ValidatedProfile.Profile.toolchain.cargo.path))) { return $null }
        return 'narrow-caller-pinned-H7C-Git-child-v1'
    }
    if ($imageName -ceq 'vctip.exe' -or $knownVctipContent) {
        if ($imageName -cne 'vctip.exe') { return $null }
        $profileCargoPath = $null
        try { $profileCargoPath = [string]$ValidatedProfile.Profile.toolchain.cargo.path } catch { return $null }
        if ([String]::IsNullOrWhiteSpace($profileCargoPath)) { return $null }
        if (-not (Test-D32ProfilePathEqual -Left $ExpectedRootPath -Right $profileCargoPath)) { return $null }
        $vctip = Get-D32ProfileExactVctipImageRecord -ValidatedProfile $ValidatedProfile
        if (-not (Test-D32ProfilePathEqual -Left $vctip.Path -Right $ImagePath)) { return $null }
        if ($null -ne $ImageIdentity) {
            $openedPath = Get-D32Phase0DiagnosticPropertyValue -Object $ImageIdentity -Names @('path', 'Path', 'image_path', 'ImagePath')
            $openedBytes = Get-D32Phase0DiagnosticPropertyValue -Object $ImageIdentity -Names @('bytes', 'Bytes')
            $openedSha = Get-D32Phase0DiagnosticPropertyValue -Object $ImageIdentity -Names @('sha256', 'Sha256')
            $openedVolume = Get-D32Phase0DiagnosticPropertyValue -Object $ImageIdentity -Names @('volume_serial_hex', 'VolumeSerialHex')
            $openedFileId = Get-D32Phase0DiagnosticPropertyValue -Object $ImageIdentity -Names @('file_id_hex', 'FileIdHex')
            if (-not (Test-D32ProfilePathEqual -Left ([string]$openedPath) -Right ([string]$vctip.Path))) { return $null }
            if (-not (Test-D32Phase0Integer -Value $openedBytes -Positive)) { return $null }
            if ([Int64]$openedBytes -ne [Int64]$vctip.Bytes) { return $null }
            if ($openedSha -isnot [string] -or [string]$openedSha -cne [string]$vctip.Sha256) { return $null }
            if ($openedVolume -isnot [string] -or [string]$openedVolume -cne [string]$vctip.VolumeSerialHex) { return $null }
            if ($openedFileId -isnot [string] -or [string]$openedFileId -cne [string]$vctip.FileIdHex) { return $null }
        }
        return 'caller-pinned-msvc-vctip-descendant-of-fixed-cargo-root'
    }
    if ([IO.Path]::GetExtension($ImagePath).ToLowerInvariant() -in @('.bat', '.cmd') -or
        $imageName -in @('cmd.exe', 'command.com', 'cscript.exe', 'wscript.exe', 'mshta.exe', 'bash.exe', 'sh.exe', 'dash.exe', 'zsh.exe', 'fish.exe', 'nu.exe', 'pageant.exe') -or
        $imageName.StartsWith('powershell', [StringComparison]::Ordinal) -or $imageName.StartsWith('pwsh', [StringComparison]::Ordinal) -or $imageName.StartsWith('wsl', [StringComparison]::Ordinal) -or
        $imageName -ceq 'git.exe' -or $imageName.StartsWith('git-bash', [StringComparison]::Ordinal) -or $imageName.StartsWith('git-cmd', [StringComparison]::Ordinal) -or
        $imageName.StartsWith('git-lfs', [StringComparison]::Ordinal) -or $imageName.StartsWith('git-remote-', [StringComparison]::Ordinal) -or
        $imageName.StartsWith('git-credential', [StringComparison]::Ordinal) -or $imageName.Contains('credential') -or $imageName.StartsWith('ssh', [StringComparison]::Ordinal) -or
        $imageName.StartsWith('plink', [StringComparison]::Ordinal) -or $imageName.StartsWith('putty', [StringComparison]::Ordinal) -or $imageName.StartsWith('tortoiseplink', [StringComparison]::Ordinal)) { return $null }
    if ($imageName -ceq 'protoc.exe' -or $knownVendoredProtocContent) {
        if ($null -eq $VendoredProtocGrant -or $imageName -cne 'protoc.exe') { return $null }
        $profileCargoPath = $null
        $grantCargoHome = $null
        try {
            $profileCargoPath = [string]$ValidatedProfile.Profile.toolchain.cargo.path
            $grantCargoHome = [string]$VendoredProtocGrant.Document.cargo_home.path
        }
        catch { return $null }
        if ([String]::IsNullOrWhiteSpace($profileCargoPath)) { return $null }
        if (-not (Test-D32ProfilePathEqual -Left $ExpectedRootPath -Right $profileCargoPath)) { return $null }
        if ([String]::IsNullOrWhiteSpace($grantCargoHome)) { return $null }
        $pin = $VendoredProtocGrant.Image
        $expectedPinPath = Join-Path $grantCargoHome 'registry\src\index.crates.io-1949cf8c6b5b557f\protoc-bin-vendored-win32-3.2.0\bin\protoc.exe'
        if ($pin.Path -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$pin.Path)) { return $null }
        if (-not (Test-D32ProfilePathEqual -Left $pin.Path -Right $expectedPinPath)) { return $null }
        if (($pin.Bytes -isnot [int]) -and ($pin.Bytes -isnot [long]) -and ($pin.Bytes -isnot [int64]) -and ($pin.Bytes -isnot [uint64])) { return $null }
        if ([Int64]$pin.Bytes -ne $script:D32VendoredProtocImageBytes) { return $null }
        if ($pin.Sha256 -isnot [string] -or $pin.Sha256 -cne $script:D32VendoredProtocImageSha256) { return $null }
        if ($pin.VolumeSerialHex -isnot [string] -or $pin.VolumeSerialHex -cnotmatch '^[0-9a-f]{16}$') { return $null }
        if ($pin.FileIdHex -isnot [string] -or $pin.FileIdHex -cnotmatch '^[0-9a-f]{32}$') { return $null }
        if ($null -eq $ImageIdentity) { return $null }
        if (-not (Test-D32ProfilePathEqual -Left $ImagePath -Right $pin.Path)) { return $null }
        $openedPath = Get-D32Phase0DiagnosticPropertyValue -Object $ImageIdentity -Names @('path', 'Path', 'image_path', 'ImagePath')
        if ($openedPath -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $openedPath -Right $pin.Path)) { return $null }
        if (($imageBytes -isnot [int]) -and ($imageBytes -isnot [long]) -and ($imageBytes -isnot [int64]) -and ($imageBytes -isnot [uint64])) { return $null }
        if ([Int64]$imageBytes -ne [Int64]$pin.Bytes) { return $null }
        if ($imageSha256 -isnot [string] -or $imageSha256 -cne [string]$pin.Sha256) { return $null }
        $openedVolume = Get-D32Phase0DiagnosticPropertyValue -Object $ImageIdentity -Names @('volume_serial_hex', 'VolumeSerialHex')
        if ($openedVolume -isnot [string] -or $openedVolume -cne [string]$pin.VolumeSerialHex) { return $null }
        $openedFileId = Get-D32Phase0DiagnosticPropertyValue -Object $ImageIdentity -Names @('file_id_hex', 'FileIdHex')
        if ($openedFileId -isnot [string] -or $openedFileId -cne [string]$pin.FileIdHex) { return $null }
        return 'caller-pinned-locked-vendored-protoc-descendant-of-fixed-cargo-root'
    }
    $pinned = @($ValidatedProfile.ExecutableInventory | Where-Object { Test-D32ProfilePathEqual -Left $_.Path -Right $ImagePath })
    $windowsPinned = @($ValidatedProfile.WindowsImageInventory | Where-Object { Test-D32ProfilePathEqual -Left $_.Path -Right $ImagePath })
    if ($pinned.Count -eq 1 -or $windowsPinned.Count -eq 1) { return 'caller-pinned-toolchain-native-or-Windows-image' }
    if ($pinned.Count -gt 1) { return $null }
    if ($windowsPinned.Count -gt 1) { return $null }
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

function ConvertTo-D32Phase0DebugProcessTraceDocument {
    param([Parameter(Mandatory = $true)][object]$Trace)
    return [ordered]@{
        record_type = [string]$Trace.RecordType
        schema_version = [int]$Trace.SchemaVersion
        event_source = [string]$Trace.EventSource
        state = [string]$Trace.State
        block_reason = $Trace.BlockReason
        debugger_process_id = [int]$Trace.DebuggerProcessId
        uncontinued_create_process_id = [uint32]$Trace.UncontinuedCreateProcessId
        uncontinued_create_continue_call_count = [int]$Trace.UncontinuedCreateContinueCallCount
        debugger_thread_id = [uint32]$Trace.DebuggerThreadId
        dedicated_debugger_thread = [bool]$Trace.DedicatedDebuggerThread
        debugger_kill_on_exit_enabled = [bool]$Trace.DebuggerKillOnExitEnabled
        root_resumed_after_kill_on_exit = [bool]$Trace.RootResumedAfterKillOnExit
        debugger_thread_exited = [bool]$Trace.DebuggerThreadExited
        debugger_thread_joined = [bool]$Trace.DebuggerThreadJoined
        retained_process_handle_count = [int]$Trace.RetainedProcessHandleCount
        retained_process_handles_signaled = [bool]$Trace.RetainedProcessHandlesSignaled
        debugger_association_query_verified = [bool]$Trace.DebuggerAssociationQueryVerified
        debugger_association_absent = [bool]$Trace.DebuggerAssociationAbsent
        debugger_creation_filetime = [Int64]$Trace.DebuggerCreationFileTime
        debugger_created_at_utc = [string]$Trace.DebuggerCreatedAtUtc
        started_at_utc = [string]$Trace.StartedAtUtc
        completed_at_utc = [string]$Trace.CompletedAtUtc
        debug_event_count = [int]$Trace.DebugEventCount
        process_create_event_count = [int]$Trace.ProcessCreateEventCount
        process_exit_event_count = [int]$Trace.ProcessExitEventCount
        process_event_count = [int]$Trace.ProcessEventCount
        thread_create_event_count = [int]$Trace.ThreadCreateEventCount
        thread_exit_event_count = [int]$Trace.ThreadExitEventCount
        image_load_event_count = [int]$Trace.ImageLoadEventCount
        image_unload_event_count = [int]$Trace.ImageUnloadEventCount
        exception_event_count = [int]$Trace.ExceptionEventCount
        debug_string_event_count = [int]$Trace.DebugStringEventCount
        wait_timeout_count = [int]$Trace.WaitTimeoutCount
        debug_api_error_count = [int]$Trace.DebugApiErrorCount
        event_chain_complete = [bool]$Trace.EventChainComplete
        job_accounting_verified = [bool]$Trace.JobAccountingVerified
        job_total_processes = [uint32]$Trace.JobTotalProcesses
        job_active_processes = [uint32]$Trace.JobActiveProcesses
        accounting_consistent = [bool]$Trace.AccountingConsistent
        injected_interruption = [bool]$Trace.InjectedInterruption
        process_events = @($Trace.ProcessEvents | ForEach-Object {
            [ordered]@{
                sequence = [Int64]$_.Sequence
                kind = [string]$_.Kind
                process_id = [uint32]$_.ProcessId
                parent_process_id = [uint32]$_.ParentProcessId
                creation_filetime = [Int64]$_.CreationFileTime
                parent_creation_filetime = [Int64]$_.ParentCreationFileTime
                exit_code = [uint32]$_.ExitCode
            }
        })
        processes = @($Trace.Processes | ForEach-Object {
            [ordered]@{
                process_id = [uint32]$_.ProcessId
                parent_process_id = [uint32]$_.ParentProcessId
                creation_filetime = [Int64]$_.CreationFileTime
                parent_creation_filetime = [Int64]$_.ParentCreationFileTime
                image_path = $_.ImagePath
                bytes = [Int64]$_.Bytes
                sha256 = $_.Sha256
                volume_serial_hex = $_.VolumeSerialHex
                file_id_hex = $_.FileIdHex
                allowed_image_reason = $_.AllowedImageReason
                image_verified = [bool]$_.ImageVerified
                exited = [bool]$_.Exited
                exit_code = [uint32]$_.ExitCode
                create_sequence = [Int64]$_.CreateSequence
                exit_sequence = [Int64]$_.ExitSequence
                created_at_utc = $_.CreatedAtUtc
                exited_at_utc = $_.ExitedAtUtc
            }
        })
    }
}

function ConvertFrom-D32Phase0DebugProcess {
    param([Parameter(Mandatory = $true)][object]$Process, [AllowEmptyString()][string]$CommandLine = '')
    $created = if ([Int64]$Process.CreationFileTime -gt 0) { [DateTime]::FromFileTimeUtc([Int64]$Process.CreationFileTime).ToString('o') } else { $null }
    $proxy = [PSCustomObject]@{
        process_id = [int]$Process.ProcessId
        parent_process_id = [int]$Process.ParentProcessId
        name = [IO.Path]::GetFileName([string]$Process.ImagePath)
        image_path = [string]$Process.ImagePath
        command_line = $CommandLine
        creation_date = $created
        observed_at_utc = [string]$Process.CreatedAtUtc
    }
    return $proxy
}

function Test-D32Phase0DebugProcessTrace {
    param(
        [Parameter(Mandatory = $true)][object]$Trace,
        [Parameter(Mandatory = $true)][string]$ExpectedRootPath,
        [Parameter(Mandatory = $true)][object]$ExpectedRootIdentity,
        [Parameter(Mandatory = $true)][int]$ExpectedParentProcessId,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$Repository,
        [AllowNull()][object]$VendoredProtocGrant,
        [AllowNull()][object]$H7CGitAuthority,
        [AllowNull()][object]$H7CGitRunGrant
    )

    $fields = @('record_type', 'schema_version', 'event_source', 'state', 'block_reason', 'debugger_process_id', 'uncontinued_create_process_id', 'uncontinued_create_continue_call_count', 'debugger_thread_id',
        'dedicated_debugger_thread', 'debugger_kill_on_exit_enabled', 'root_resumed_after_kill_on_exit', 'debugger_thread_exited', 'debugger_thread_joined',
        'retained_process_handle_count', 'retained_process_handles_signaled', 'debugger_association_query_verified', 'debugger_association_absent', 'debugger_creation_filetime',
        'debugger_created_at_utc', 'started_at_utc', 'completed_at_utc', 'debug_event_count', 'process_create_event_count', 'process_exit_event_count',
        'process_event_count', 'thread_create_event_count', 'thread_exit_event_count', 'image_load_event_count', 'image_unload_event_count',
        'exception_event_count', 'debug_string_event_count', 'wait_timeout_count', 'debug_api_error_count', 'event_chain_complete',
        'job_accounting_verified', 'job_total_processes', 'job_active_processes', 'accounting_consistent', 'injected_interruption', 'process_events', 'processes')
    if (-not (Test-D32Phase0ExactProperties -Object $Trace -Expected $fields) -or
        $Trace.record_type -cne 'D32_DEBUG_JOB_PROCESS_TRACE_V2' -or -not (Test-D32Phase0Integer -Value $Trace.schema_version) -or $Trace.schema_version -ne 2 -or
        $Trace.event_source -cne 'Win32-WaitForDebugEvent-dedicated-OS-thread' -or $Trace.state -cne 'COMPLETED' -or $null -ne $Trace.block_reason -or
        -not (Test-D32Phase0Integer -Value $Trace.debugger_process_id -Positive) -or $Trace.debugger_process_id -ne $ExpectedParentProcessId -or
        -not (Test-D32Phase0Integer -Value $Trace.debugger_thread_id -Positive) -or
        -not (Test-D32Phase0Integer -Value $Trace.uncontinued_create_process_id) -or $Trace.uncontinued_create_process_id -ne 0 -or
        -not (Test-D32Phase0Integer -Value $Trace.uncontinued_create_continue_call_count) -or $Trace.uncontinued_create_continue_call_count -ne 0 -or
        $Trace.dedicated_debugger_thread -isnot [bool] -or -not $Trace.dedicated_debugger_thread -or
        $Trace.debugger_kill_on_exit_enabled -isnot [bool] -or -not $Trace.debugger_kill_on_exit_enabled -or
        $Trace.root_resumed_after_kill_on_exit -isnot [bool] -or -not $Trace.root_resumed_after_kill_on_exit -or
        $Trace.debugger_thread_exited -isnot [bool] -or -not $Trace.debugger_thread_exited -or
        $Trace.debugger_thread_joined -isnot [bool] -or -not $Trace.debugger_thread_joined -or
        -not (Test-D32Phase0Integer -Value $Trace.retained_process_handle_count -Positive) -or
        $Trace.retained_process_handle_count -lt ([int]$Trace.process_create_event_count + 1) -or
        $Trace.retained_process_handles_signaled -isnot [bool] -or -not $Trace.retained_process_handles_signaled -or
        $Trace.debugger_association_query_verified -isnot [bool] -or -not $Trace.debugger_association_query_verified -or
        $Trace.debugger_association_absent -isnot [bool] -or -not $Trace.debugger_association_absent -or
        -not (Test-D32Phase0Integer -Value $Trace.debugger_creation_filetime -Positive) -or
        $Trace.event_chain_complete -isnot [bool] -or -not $Trace.event_chain_complete -or
        $Trace.job_accounting_verified -isnot [bool] -or -not $Trace.job_accounting_verified -or
        $Trace.accounting_consistent -isnot [bool] -or -not $Trace.accounting_consistent -or
        $Trace.injected_interruption -isnot [bool] -or $Trace.injected_interruption -or
        -not (Test-D32Phase0Integer -Value $Trace.debug_api_error_count) -or $Trace.debug_api_error_count -ne 0 -or
        -not (Test-D32Phase0Integer -Value $Trace.debug_event_count -Positive) -or
        -not (Test-D32Phase0Integer -Value $Trace.process_create_event_count -Positive) -or
        -not (Test-D32Phase0Integer -Value $Trace.process_exit_event_count -Positive) -or
        -not (Test-D32Phase0Integer -Value $Trace.process_event_count -Positive) -or
        $Trace.process_create_event_count -ne $Trace.process_exit_event_count -or
        $Trace.process_event_count -ne ($Trace.process_create_event_count + $Trace.process_exit_event_count) -or
        $Trace.debug_event_count -lt $Trace.process_event_count -or
        -not (Test-D32Phase0Integer -Value $Trace.job_total_processes -Positive) -or $Trace.job_total_processes -ne $Trace.process_create_event_count -or
        -not (Test-D32Phase0Integer -Value $Trace.job_active_processes) -or $Trace.job_active_processes -ne 0 -or
        $Trace.process_events -isnot [Array] -or $Trace.processes -isnot [Array] -or
        $Trace.processes.Count -ne $Trace.process_create_event_count -or $Trace.process_events.Count -ne $Trace.process_event_count) {
        throw 'PROCESS_TRACE_BLOCKED: trace type/version, event-chain state, or independent Job accounting is invalid'
    }

    foreach ($name in @('debugger_created_at_utc', 'started_at_utc', 'completed_at_utc')) {
        $parsed = [DateTimeOffset]::MinValue
        if ($Trace.$name -isnot [string] -or -not [DateTimeOffset]::TryParse([string]$Trace.$name, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed)) { throw "PROCESS_TRACE_BLOCKED: $name is not an ISO timestamp" }
    }
    $createdFromFiletime = [DateTime]::FromFileTimeUtc([Int64]$Trace.debugger_creation_filetime).ToString('o')
    if (-not [DateTimeOffset]::TryParse([string]$Trace.debugger_created_at_utc, [ref]$parsed) -or
        [Math]::Abs(([DateTimeOffset]::Parse($createdFromFiletime) - [DateTimeOffset]::Parse([string]$Trace.debugger_created_at_utc)).TotalSeconds) -gt 1) {
        throw 'PROCESS_TRACE_BLOCKED: debugger PID creation identity does not match its retained process handle'
    }
    if (-not (Test-D32Phase0Integer -Value $Trace.wait_timeout_count) -or
        -not (Test-D32Phase0Integer -Value $Trace.thread_create_event_count) -or
        -not (Test-D32Phase0Integer -Value $Trace.thread_exit_event_count) -or
        -not (Test-D32Phase0Integer -Value $Trace.image_load_event_count) -or
        -not (Test-D32Phase0Integer -Value $Trace.image_unload_event_count) -or
        -not (Test-D32Phase0Integer -Value $Trace.exception_event_count) -or
        -not (Test-D32Phase0Integer -Value $Trace.debug_string_event_count)) { throw 'PROCESS_TRACE_BLOCKED: debug event counters are malformed' }
    $classifiedDebugEventCount = [Int64]$Trace.process_event_count + [Int64]$Trace.thread_create_event_count + [Int64]$Trace.thread_exit_event_count +
        [Int64]$Trace.image_load_event_count + [Int64]$Trace.image_unload_event_count + [Int64]$Trace.exception_event_count + [Int64]$Trace.debug_string_event_count
    if ([Int64]$Trace.debug_event_count -ne $classifiedDebugEventCount) { throw 'PROCESS_TRACE_BLOCKED: debug event total does not equal the complete classified event counters' }

    $eventFields = @('sequence', 'kind', 'process_id', 'parent_process_id', 'creation_filetime', 'parent_creation_filetime', 'exit_code')
    $recordFields = @('process_id', 'parent_process_id', 'creation_filetime', 'parent_creation_filetime', 'image_path', 'bytes', 'sha256',
        'volume_serial_hex', 'file_id_hex', 'allowed_image_reason', 'image_verified', 'exited', 'exit_code', 'create_sequence', 'exit_sequence', 'created_at_utc', 'exited_at_utc')
    $active = @{}
    $byIdentity = @{}
    $identitySet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($i = 0; $i -lt $Trace.process_events.Count; $i++) {
        $event = $Trace.process_events[$i]
        if (-not (Test-D32Phase0ExactProperties -Object $event -Expected $eventFields) -or
            -not (Test-D32Phase0Integer -Value $event.sequence -Positive) -or $event.sequence -ne ($i + 1) -or
            $event.kind -isnot [string] -or $event.kind -cnotin @('CREATE', 'EXIT') -or
            -not (Test-D32Phase0Integer -Value $event.process_id -Positive) -or
            -not (Test-D32Phase0Integer -Value $event.parent_process_id -Positive) -or
            -not (Test-D32Phase0Integer -Value $event.creation_filetime -Positive) -or
            -not (Test-D32Phase0Integer -Value $event.parent_creation_filetime -Positive) -or
            -not (Test-D32Phase0Integer -Value $event.exit_code)) { throw "PROCESS_TRACE_BLOCKED: process event[$i] schema/identity is invalid" }
        $identity = "$($event.process_id)|$($event.creation_filetime)"
        if ($event.kind -ceq 'CREATE') {
            if ($event.exit_code -ne 0 -or $active.ContainsKey([uint32]$event.process_id) -or -not $identitySet.Add($identity)) { throw "PROCESS_TRACE_BLOCKED: CREATE event carries exit data, overlaps PID reuse, or duplicates identity at event $i" }
            if ($i -eq 0) {
                if ($event.parent_process_id -ne $Trace.debugger_process_id -or $event.parent_creation_filetime -ne $Trace.debugger_creation_filetime) { throw 'PROCESS_TRACE_BLOCKED: root parent PID/creation identity does not match runner' }
            }
            else {
                $parentKey = "$($event.parent_process_id)"
                if (-not $active.ContainsKey([uint32]$event.parent_process_id) -or $active[[uint32]$event.parent_process_id].creation_filetime -ne $event.parent_creation_filetime) { throw "PROCESS_TRACE_BLOCKED: parent identity is unknown, exited, or ambiguous at event $i" }
            }
            $active[[uint32]$event.process_id] = [PSCustomObject]@{ creation_filetime = [Int64]$event.creation_filetime; parent_process_id = [uint32]$event.parent_process_id; parent_creation_filetime = [Int64]$event.parent_creation_filetime; create_sequence = [Int64]$event.sequence; exit_sequence = 0; exit_code = 0 }
        }
        else {
            if (-not $active.ContainsKey([uint32]$event.process_id)) { throw "PROCESS_TRACE_BLOCKED: exit has no active create identity at event $i" }
            $activeRecord = $active[[uint32]$event.process_id]
            if ($activeRecord.creation_filetime -ne $event.creation_filetime -or $activeRecord.parent_process_id -ne $event.parent_process_id -or $activeRecord.parent_creation_filetime -ne $event.parent_creation_filetime) { throw "PROCESS_TRACE_BLOCKED: exit identity does not match active process at event $i" }
            $activeRecord.exit_sequence = [Int64]$event.sequence
            $activeRecord.exit_code = [uint32]$event.exit_code
            $active.Remove([uint32]$event.process_id)
        }
    }
    if ($active.Count -ne 0) { throw 'PROCESS_TRACE_BLOCKED: process event ledger ends with active/unexited identities' }

    foreach ($record in $Trace.processes) {
        if (-not (Test-D32Phase0ExactProperties -Object $record -Expected $recordFields) -or
            -not (Test-D32Phase0Integer -Value $record.process_id -Positive) -or -not (Test-D32Phase0Integer -Value $record.parent_process_id -Positive) -or
            -not (Test-D32Phase0Integer -Value $record.creation_filetime -Positive) -or -not (Test-D32Phase0Integer -Value $record.parent_creation_filetime -Positive) -or
            $record.image_path -isnot [string] -or -not (Test-D32ProfileCanonicalPathString -Path $record.image_path) -or
            -not (Test-D32Phase0Integer -Value $record.bytes -Positive) -or $record.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $record.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or $record.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            $record.allowed_image_reason -isnot [string] -or [String]::IsNullOrWhiteSpace($record.allowed_image_reason) -or
            $record.image_verified -isnot [bool] -or -not $record.image_verified -or $record.exited -isnot [bool] -or -not $record.exited -or
            -not (Test-D32Phase0Integer -Value $record.exit_code) -or -not (Test-D32Phase0Integer -Value $record.create_sequence -Positive) -or
            -not (Test-D32Phase0Integer -Value $record.exit_sequence -Positive)) { throw 'PROCESS_TRACE_BLOCKED: process image/exit record is malformed or unverified' }
        $key = "$($record.process_id)|$($record.creation_filetime)"
        if ($byIdentity.ContainsKey($key)) { throw 'PROCESS_TRACE_BLOCKED: duplicate process identity record' }
        $byIdentity[$key] = $record
        $eventsForProcess = @($Trace.process_events | Where-Object { $_.process_id -eq $record.process_id -and $_.creation_filetime -eq $record.creation_filetime })
        if ($eventsForProcess.Count -ne 2 -or $eventsForProcess[0].kind -cne 'CREATE' -or $eventsForProcess[1].kind -cne 'EXIT' -or
            $record.create_sequence -ne $eventsForProcess[0].sequence -or $record.exit_sequence -ne $eventsForProcess[1].sequence -or
            $record.parent_process_id -ne $eventsForProcess[0].parent_process_id -or $record.parent_creation_filetime -ne $eventsForProcess[0].parent_creation_filetime -or
            $record.exit_code -ne $eventsForProcess[1].exit_code) { throw 'PROCESS_TRACE_BLOCKED: process identity record does not reconcile with ordered CREATE/EXIT events' }
        foreach ($timeName in @('created_at_utc', 'exited_at_utc')) {
            $time = [DateTimeOffset]::MinValue
            if ($record.$timeName -isnot [string] -or -not [DateTimeOffset]::TryParse([string]$record.$timeName, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$time)) { throw "PROCESS_TRACE_BLOCKED: process $timeName is not an ISO timestamp" }
        }
        if ([DateTimeOffset]::Parse([string]$record.exited_at_utc) -lt [DateTimeOffset]::Parse([string]$record.created_at_utc)) { throw 'PROCESS_TRACE_BLOCKED: process exit precedes create' }
    }
    if ($byIdentity.Count -ne $Trace.process_create_event_count) { throw 'PROCESS_TRACE_BLOCKED: process table is incomplete' }
    $rootEvent = $Trace.process_events[0]
    $rootKey = "$($rootEvent.process_id)|$($rootEvent.creation_filetime)"
    if (-not $byIdentity.ContainsKey($rootKey)) { throw 'PROCESS_TRACE_BLOCKED: root process identity is absent from process table' }
    $root = $byIdentity[$rootKey]
    if (-not (Test-D32ProfilePathEqual -Left $root.image_path -Right $ExpectedRootPath) -or
        $root.sha256 -cne [string]$ExpectedRootIdentity.sha256 -or [Int64]$root.bytes -ne [Int64]$ExpectedRootIdentity.bytes -or
        $root.volume_serial_hex -cne [string]$ExpectedRootIdentity.volume_serial_hex -or $root.file_id_hex -cne [string]$ExpectedRootIdentity.file_id_hex -or
        $root.allowed_image_reason -cne 'exact-caller-pinned-fixed-root-image') { throw 'PROCESS_TRACE_BLOCKED: root image path/hash/bytes/file identity differs from the fixed caller pin' }
    foreach ($record in $Trace.processes) {
        $identity = "$($record.process_id)|$($record.creation_filetime)"
        if ($identity -eq $rootKey) { continue }
        $actualReason = Get-D32Phase0AllowedChildImageReason -ImagePath $record.image_path -ValidatedProfile $ValidatedProfile -Repository $Repository -ExpectedRootPath $ExpectedRootPath -ImageIdentity $record -VendoredProtocGrant $VendoredProtocGrant -H7CGitRunGrant $H7CGitRunGrant
        if ([String]::IsNullOrWhiteSpace($actualReason) -or $record.allowed_image_reason -cne $actualReason) { throw "PROCESS_TRACE_BLOCKED: child/helper image is outside exact pinned inventory and candidate target roots: $($record.image_path)" }
        $pinned = @($ValidatedProfile.ExecutableInventory + $ValidatedProfile.WindowsImageInventory | Where-Object { Test-D32ProfilePathEqual -Left $_.Path -Right $record.image_path })
        if ($pinned.Count -gt 1) { throw 'PROCESS_TRACE_BLOCKED: pinned process image identity is ambiguous' }
        if ($pinned.Count -eq 1 -and ($record.sha256 -cne $pinned[0].Sha256 -or [Int64]$record.bytes -ne [Int64]$pinned[0].Bytes -or
            $record.volume_serial_hex -cne $pinned[0].VolumeSerialHex -or $record.file_id_hex -cne $pinned[0].FileIdHex)) { throw 'PROCESS_TRACE_BLOCKED: caller-pinned child image changed' }
    }
    $h7GitPath = if ($null -ne $H7CGitRunGrant) { [string]$H7CGitRunGrant.GitImage.Path } else { '__D32_NO_H7C_GIT_AUTHORITY__' }
    $gitChildren = @($Trace.processes | Where-Object { Test-D32ProfilePathEqual -Left $_.image_path -Right $h7GitPath })
    if ($gitChildren.Count -gt 0) {
        if ($null -eq $H7CGitRunGrant -or $null -eq $H7CGitAuthority -or
            -not (Test-D32ProfilePathEqual -Left $ExpectedRootPath -Right ([string]$ValidatedProfile.Profile.toolchain.cargo.path))) { throw 'PROCESS_TRACE_BLOCKED: a Git process appears without the exact H7-C fixed-suite run grant' }
        if ((ConvertTo-Json -InputObject $H7CGitRunGrant.Document.authority -Depth 6 -Compress) -cne
            (ConvertTo-Json -InputObject $H7CGitAuthority.Reference -Depth 6 -Compress)) { throw 'PROCESS_TRACE_BLOCKED: H7-C run grant authority differs from the independently caller-pinned external authority' }
        $rootRecord = @($Trace.processes | Where-Object { $_.create_sequence -eq 1 })
        if ($rootRecord.Count -ne 1) { throw 'PROCESS_TRACE_BLOCKED: H7-C Git trace has no unique fixed Cargo root' }
        foreach ($gitChild in $gitChildren) {
            $parent = @($Trace.processes | Where-Object { $_.process_id -eq $gitChild.parent_process_id -and $_.creation_filetime -eq $gitChild.parent_creation_filetime })
            if ($parent.Count -ne 1 -or $parent[0].parent_process_id -ne $rootRecord[0].process_id -or
                $parent[0].parent_creation_filetime -ne $rootRecord[0].creation_filetime -or
                $parent[0].image_path -notmatch '\\vita-agent\\target\\debug\\deps\\vita_agent-[0-9a-f]+\.exe$') { throw 'PROCESS_TRACE_BLOCKED: pinned Git is not a direct child of the exact candidate Vita libtest directly below the fixed Cargo root' }
        }
    }
    return $Trace
}

function Test-D32Phase0SuiteCounts {
    param([Parameter(Mandatory = $true)][object]$Counts, [Parameter(Mandatory = $true)][int64]$TestCount, [Parameter(Mandatory = $true)][int64]$ExpectedIgnored, [Parameter(Mandatory = $true)][int64]$ExpectedFiltered)
    if (-not (Test-D32Phase0ExactProperties -Object $Counts -Expected @('passed', 'failed', 'ignored', 'measured', 'filtered_out'))) { return $false }
    foreach ($field in @('passed', 'failed', 'ignored', 'measured', 'filtered_out')) { if (-not (Test-D32Phase0Integer -Value $Counts.$field)) { return $false } }
    return ([Int64]$Counts.failed -eq 0 -and [Int64]$Counts.ignored -eq $ExpectedIgnored -and [Int64]$Counts.filtered_out -eq $ExpectedFiltered -and ([Int64]$Counts.passed + [Int64]$Counts.ignored + [Int64]$Counts.measured + [Int64]$Counts.filtered_out) -eq $TestCount)
}

function Get-D32Phase0FixtureGitStates {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [switch]$AllowPartial
    )
    if ($ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$') { throw 'Phase0 fixture Git-state expected SHA is malformed' }
    $states = [System.Collections.Generic.List[object]]::new()
    foreach ($line in $Lines) {
        if ($line -notmatch '^D32_FIXTURE_GIT_STATE(?:\s|$)') { continue }
        if ($line -notmatch '^D32_FIXTURE_GIT_STATE phase=([1-5]) edge=(before|after) head=([0-9a-f]{40}) clean=(true|false)$') {
            throw 'PHASE0_FIXTURE_STATE_BLOCKED: malformed per-phase Git-state marker'
        }
        $phase = [int]$Matches[1]
        $edge = [string]$Matches[2]
        $head = [string]$Matches[3]
        $clean = [string]$Matches[4] -ceq 'true'
        if ($head -cne $ExpectedCandidateSha -or -not $clean) { throw "PHASE0_FIXTURE_STATE_BLOCKED: phase $phase $edge candidate/clean check failed" }
        $states.Add([ordered]@{ phase = $phase; edge = $edge; head = $head; clean = $clean })
    }
    $expectedKeys = @()
    for ($phase = 1; $phase -le 5; $phase++) { $expectedKeys += @("$phase|before", "$phase|after") }
    $actualKeys = @($states | ForEach-Object { "$($_.phase)|$($_.edge)" })
    if ($AllowPartial) {
        if ($states.Count -gt $expectedKeys.Count) { throw 'PHASE0_FIXTURE_STATE_BLOCKED: per-phase Git-state prefix contains extra markers' }
        if ($states.Count -gt 0 -and ($actualKeys -join '|') -cne (($expectedKeys | Select-Object -First $states.Count) -join '|')) {
            throw 'PHASE0_FIXTURE_STATE_BLOCKED: partial per-phase Git-state markers are not an ordered prefix'
        }
    }
    else {
        if ($states.Count -ne 10) { throw "PHASE0_FIXTURE_STATE_BLOCKED: expected 10 per-phase Git-state lines, observed $($states.Count)" }
        if (($actualKeys -join '|') -cne ($expectedKeys -join '|')) { throw 'PHASE0_FIXTURE_STATE_BLOCKED: per-phase Git-state lines are missing, duplicated, reordered, or extra' }
    }
    return @($states.ToArray())
}

function Get-D32Phase0FixtureLogPaths {
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$FixtureRecords,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$LockInputs
    )

    $expectedNames = @('d29h1-authority-fixture', 'd29h7-authority-fixture', 'd29h7-process-fixture', 'd29h7-git-helper-fixture', 'd32a-sandbox-fixture')
    if ($FixtureRecords.Count -ne $expectedNames.Count) { throw 'PHASE0_LOG_BLOCKED: fixture log inventory must contain exactly the five fixed fixture phases' }
    if ($LockInputs.Count -ne 3) { throw 'PHASE0_LOG_BLOCKED: fixture log inventory must contain exactly three fixed locked-fetch captures' }
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
        [Parameter(Mandatory = $true)][string]$GitSha256,
        [AllowNull()][object]$VendoredProtocRunGrant,
        [AllowNull()][object]$H7CGitAuthority,
        [AllowNull()][object]$H7CGitRunGrant
    )
    $script:D32Phase0LastProcessFailure = [ordered]@{
        PrimaryError = $null
        Command = [ordered]@{
            name = $Name
            executable = [IO.Path]::GetFullPath($Executable)
            arguments = @($Arguments)
            command_line = ConvertTo-D32Phase0CommandLine -Arguments (@($Executable) + @($Arguments))
            working_directory = [IO.Path]::GetFullPath($WorkingDirectory)
        }
        ProcessIdentity = $null
        RawV2Trace = $null
        NativeCleanup = $null
        StdoutPath = "$LogPath.stdout.log"
        StderrPath = "$LogPath.stderr.log"
    }
    if (-not ('D32FixtureNativeProcessV2' -as [type])) { throw 'PHASE0_PROCESS_TREE_BLOCKED: fixture Job Object launcher was not initialized' }
    $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $ValidatedProfile
    $pre = Get-D32Phase0GitState -Repository $Repository -GitPath $GitPath -GitSha256 $GitSha256
    if ($pre.Head -cne $ExpectedCandidateSha) { throw 'PHASE0_CANDIDATE_BLOCKED: HEAD changed before a fixed command' }
    $image = Get-D32ProfileFileSnapshot -Path $Executable
    $expectedTool = @($ValidatedProfile.ExecutableInventory | Where-Object { Test-D32ProfilePathEqual -Left $_.Path -Right $Executable })
    if ($expectedTool.Count -ne 1 -or $expectedTool[0].Sha256 -cne $image.Sha256 -or $expectedTool[0].Bytes -ne $image.Bytes -or $expectedTool[0].VolumeSerialHex -cne $image.VolumeSerialHex -or $expectedTool[0].FileIdHex -cne $image.FileIdHex) {
        throw "PHASE0_TOOL_IDENTITY_BLOCKED: executable is not the current pinned image: $Executable"
    }
    $script:D32Phase0LastProcessFailure.Command = [ordered]@{
        name = $Name
        executable = [string]$image.Path
        executable_sha256 = [string]$image.Sha256
        executable_bytes = [Int64]$image.Bytes
        executable_volume_serial_hex = [string]$image.VolumeSerialHex
        executable_file_id_hex = [string]$image.FileIdHex
        arguments = @($Arguments)
        command_line = ConvertTo-D32Phase0CommandLine -Arguments (@($Executable) + @($Arguments))
        working_directory = [IO.Path]::GetFullPath($WorkingDirectory)
    }
    if (Test-Path -LiteralPath $LogPath) { throw "PHASE0_LOG_BLOCKED: refusing to overwrite command output: $LogPath" }
    $stdoutPath = "$LogPath.stdout.log"
    $stderrPath = "$LogPath.stderr.log"
    if ((Test-Path -LiteralPath $stdoutPath) -or (Test-Path -LiteralPath $stderrPath)) { throw 'PHASE0_LOG_BLOCKED: stdout/stderr log path already exists' }
    $commandArguments = @($Executable) + @($Arguments)
    $commandLine = ConvertTo-D32Phase0CommandLine -Arguments $commandArguments
    $launchEnvironment = [ordered]@{}
    foreach ($environmentKey in $Environment.Keys) { $launchEnvironment[[string]$environmentKey] = [string]$Environment[$environmentKey] }
    $manifestIndex = [Array]::IndexOf([string[]]$Arguments, '--manifest-path')
    $fixedVendoredCargo = $false
    $manifestPath = $null
    if ($manifestIndex -ge 0 -and ($manifestIndex + 1) -lt $Arguments.Count) {
        $manifestArgument = [string]$Arguments[$manifestIndex + 1]
        $manifestPath = if ([IO.Path]::IsPathRooted($manifestArgument)) { [IO.Path]::GetFullPath($manifestArgument) } else { [IO.Path]::GetFullPath((Join-Path $Repository $manifestArgument)) }
        $fixedVendoredCargo = (Test-D32ProfilePathEqual -Left $manifestPath -Right (Join-Path $Repository 'vita-agent\Cargo.toml')) -or
            (Test-D32ProfilePathEqual -Left $manifestPath -Right (Join-Path $Repository 'src-tauri\Cargo.toml'))
    }
    $isCargoRoot = Test-D32ProfilePathEqual -Left $Executable -Right ([string]$ValidatedProfile.Profile.toolchain.cargo.path)
    $isBuildOrTest = $Arguments.Count -gt 0 -and [string]$Arguments[0] -cin @('build', 'test')
    $grantForProcess = $null
    if ($isCargoRoot -and $isBuildOrTest -and $fixedVendoredCargo) {
        if ($null -eq $VendoredProtocRunGrant) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: fixed Vita/src-tauri Cargo build/test has no validated per-run image grant' }
        $grantForProcess = $VendoredProtocRunGrant
        if (-not $launchEnvironment.Contains('CARGO_HOME') -or
            -not (Test-D32ProfilePathEqual -Left ([string]$launchEnvironment['CARGO_HOME']) -Right ([string]$grantForProcess.Document.cargo_home.path))) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: Cargo command CARGO_HOME differs from its run grant' }
        $currentProtoc = Get-D32ProfileFileSnapshot -Path ([string]$grantForProcess.Image.Path)
        if ($currentProtoc.Bytes -ne [Int64]$grantForProcess.Image.Bytes -or $currentProtoc.Sha256 -cne [string]$grantForProcess.Image.Sha256 -or
            $currentProtoc.VolumeSerialHex -cne [string]$grantForProcess.Image.VolumeSerialHex -or $currentProtoc.FileIdHex -cne [string]$grantForProcess.Image.FileIdHex) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: opened protoc identity changed before fixed Cargo command' }
        if (Test-D32ProfilePathEqual -Left $manifestPath -Right (Join-Path $Repository 'src-tauri\Cargo.toml')) {
            if ($launchEnvironment.Contains('PROTOC')) { throw 'VENDORED_PROTOC_ENV_BLOCKED: ambient PROTOC is forbidden; fixed src-tauri commands receive only the run-grant image' }
            $launchEnvironment['PROTOC'] = [string]$grantForProcess.Image.Path
        }
        elseif ($launchEnvironment.Contains('PROTOC')) { throw 'VENDORED_PROTOC_ENV_BLOCKED: Vita code-mode uses its locked vendored path and must not receive PROTOC' }
    }
    elseif ($launchEnvironment.Contains('PROTOC')) { throw 'VENDORED_PROTOC_ENV_BLOCKED: PROTOC is outside the exact fixed src-tauri build/test command scope' }
    $h7cNativePolicyText = $null
    if ($null -ne $H7CGitAuthority -or $null -ne $H7CGitRunGrant) {
        $fixedVitaSuiteArgs = @(Get-D32Phase0TestCommand -Package 'vita' -Kind suite)
        if ($Name -cne 'vita-full-local-suite' -or -not $isCargoRoot -or -not $isBuildOrTest -or
            -not (Test-D32ProfilePathEqual -Left $manifestPath -Right (Join-Path $Repository 'vita-agent\Cargo.toml')) -or
            ($Arguments -join "`0") -cne ($fixedVitaSuiteArgs -join "`0") -or $null -eq $H7CGitAuthority -or $null -eq $H7CGitRunGrant) {
            throw 'H7C_GIT_GRANT_BLOCKED: direct Git child authority is restricted to the one exact fixed Vita full-local-suite command'
        }
        if (-not (Test-D32ProfilePathEqual -Left $H7CGitRunGrant.Document.fixed_suite.executable -Right $Executable) -or
            ($H7CGitRunGrant.Document.fixed_suite.arguments -join "`0") -cne ($Arguments -join "`0") -or
            -not (Test-D32ProfilePathEqual -Left $H7CGitRunGrant.Document.fixed_suite.working_directory -Right $WorkingDirectory) -or
            [Int64]$H7CGitRunGrant.Document.fixed_suite.timeout_seconds -ne $TimeoutSeconds -or
            -not (Test-D32Phase0ExactProperties -Object $H7CGitRunGrant.Document.fixed_suite.policy.suite.environment -Expected @('D32_EXPECTED_CANDIDATE_SHA')) -or
            $H7CGitRunGrant.Document.fixed_suite.policy.suite.environment.D32_EXPECTED_CANDIDATE_SHA -cne $ExpectedCandidateSha -or
            (ConvertTo-Json -InputObject $H7CGitRunGrant.Document.authority -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $H7CGitAuthority.Reference -Depth 6 -Compress)) {
            throw 'H7C_GIT_GRANT_BLOCKED: per-run grant differs from the exact current authority, Vita suite executable/argv/cwd/timeout'
        }
        if ($launchEnvironment.Contains('D32_EXPECTED_CANDIDATE_SHA')) { throw 'H7C_GIT_GRANT_BLOCKED: candidate SHA environment is already present before the exact suite grant injection' }
        $launchEnvironment['D32_EXPECTED_CANDIDATE_SHA'] = $ExpectedCandidateSha
        $h7cNativePolicyText = Get-D32H7CGitNativePolicyText -RunGrant $H7CGitRunGrant -Repository $Repository -GitImage $H7CGitRunGrant.GitImage
        $script:D32Phase0ObservedH7CGitChildren = @()
    }
    $environmentBlock = ConvertTo-D32Phase0EnvironmentBlock -Environment $launchEnvironment
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
    $rootRecord = $null
    $descendants = [ordered]@{}
    $processTrace = $null
    $exitCode = $null
    $timedOut = $false
    $failure = $null
    try {
        $native = [D32FixtureNativeProcessV2]::StartDebug($Executable, $commandLine, $WorkingDirectory, $environmentBlock)
        $stdoutTarget = [IO.File]::Open($stdoutPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $stderrTarget = [IO.File]::Open($stderrPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $stdoutStream = $native.OpenStdoutStream()
        $stderrStream = $native.OpenStderrStream()
        $stdoutCopy = $stdoutStream.CopyToAsync($stdoutTarget)
        $stderrCopy = $stderrStream.CopyToAsync($stderrTarget)
        $currentProfile = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $ValidatedProfile
        $approvedImages = @($currentProfile.ExecutableInventory) + @($currentProfile.WindowsImageInventory)
        $approvedPinText = @($approvedImages | ForEach-Object {
            @([string]$_.Path, [string]$_.Bytes, [string]$_.Sha256, [string]$_.VolumeSerialHex, [string]$_.FileIdHex) -join "`t"
        })
        if ($null -ne $grantForProcess) {
            $approvedPinText += @([string]$grantForProcess.Image.Path, [string]$grantForProcess.Image.Bytes, [string]$grantForProcess.Image.Sha256, [string]$grantForProcess.Image.VolumeSerialHex, [string]$grantForProcess.Image.FileIdHex) -join "`t"
        }
        $candidateRoots = @(
            (Join-Path $Repository 'vita-agent\target\debug'),
            (Join-Path $Repository 'vita-agent\target\release'),
            (Join-Path $Repository 'src-tauri\target\debug'),
            (Join-Path $Repository 'src-tauri\target\release'),
            (Join-Path $Repository 'vita-agent-protocol\target\debug'),
            (Join-Path $Repository 'vita-agent-protocol\target\release')
        ) | ForEach-Object { [IO.Path]::GetFullPath($_) }
        $rootPinText = @([string]$image.Path, [string]$image.Bytes, [string]$image.Sha256, [string]$image.VolumeSerialHex, [string]$image.FileIdHex) -join "`t"
        $traceTimeout = [int][Math]::Min([int]::MaxValue, ([long]$TimeoutSeconds * 1000))
        if (Test-D32ProfilePathEqual -Left $image.Path -Right ([string]$currentProfile.Profile.toolchain.cargo.path)) {
            $null = Get-D32ProfileExactVctipImageRecord -ValidatedProfile $currentProfile
            if ($null -ne $grantForProcess -and $null -ne $H7CGitRunGrant) {
                $protocPinText = @([string]$grantForProcess.Image.Path, [string]$grantForProcess.Image.Bytes, [string]$grantForProcess.Image.Sha256,
                    [string]$grantForProcess.Image.VolumeSerialHex, [string]$grantForProcess.Image.FileIdHex) -join "`t"
                $native.ConfigurePinnedCargoDebugCaptureWithVendoredProtocAndH7CGit($rootPinText, [string[]]$approvedPinText, [string[]]$candidateRoots, $traceTimeout,
                    [string]$grantForProcess.Document.cargo_home.path, $protocPinText, $h7cNativePolicyText)
            }
            elseif ($null -ne $grantForProcess) {
                $protocPinText = @([string]$grantForProcess.Image.Path, [string]$grantForProcess.Image.Bytes, [string]$grantForProcess.Image.Sha256,
                    [string]$grantForProcess.Image.VolumeSerialHex, [string]$grantForProcess.Image.FileIdHex) -join "`t"
                $native.ConfigurePinnedCargoDebugCaptureWithVendoredProtoc($rootPinText, [string[]]$approvedPinText, [string[]]$candidateRoots, $traceTimeout,
                    [string]$grantForProcess.Document.cargo_home.path, $protocPinText)
            }
            else {
                $native.ConfigurePinnedCargoDebugCapture($rootPinText, [string[]]$approvedPinText, [string[]]$candidateRoots, $traceTimeout)
            }
        }
        else {
            $native.ConfigureDebugCapture($rootPinText, [string[]]$approvedPinText, [string[]]$candidateRoots, $traceTimeout, $false, $false)
        }
        $traceJoinTimeout = [int][Math]::Min([int]::MaxValue, ([long]$TimeoutSeconds * 1000 + 20000))
        $traceNative = $native.WaitForDebugTrace($traceJoinTimeout)
        if ($null -ne $H7CGitRunGrant) { $script:D32Phase0ObservedH7CGitChildren = @($native.GetH7CGitChildObservations() | ForEach-Object { ConvertTo-D32H7CGitObservationDocument -Observation $_ }) }
        $processTrace = ConvertTo-D32Phase0DebugProcessTraceDocument -Trace $traceNative
        $null = Test-D32Phase0DebugProcessTrace -Trace $processTrace -ExpectedRootPath $Executable -ExpectedRootIdentity $image -ExpectedParentProcessId $PID -ValidatedProfile $currentProfile -Repository $Repository -VendoredProtocGrant $grantForProcess -H7CGitAuthority $H7CGitAuthority -H7CGitRunGrant $H7CGitRunGrant
        if ($traceNative.State -cne 'COMPLETED' -or -not $traceNative.AccountingConsistent) { throw "PHASE0_PROCESS_TRACE_BLOCKED: $($traceNative.BlockReason)" }
        if ($traceNative.Processes.Count -eq 0) { throw 'PHASE0_PROCESS_TRACE_BLOCKED: root CREATE_PROCESS_DEBUG_EVENT is absent' }
        $rootSnapshot = ConvertFrom-D32Phase0DebugProcess -Process $traceNative.Processes[0] -CommandLine $commandLine
        if ($rootSnapshot.parent_process_id -ne $PID) { throw 'PHASE0_PROCESS_IDENTITY_BLOCKED: fixed command parent is not the exact runner identity' }
        $rootRecord = ConvertTo-D32Phase0ProcessRecord -Process $rootSnapshot -ValidatedProfile $currentProfile -Repository $Repository -ExpectedRootPath $Executable -VendoredProtocGrant $grantForProcess -H7CGitRunGrant $H7CGitRunGrant
        if (-not (Test-D32ProfilePathEqual -Left $rootRecord.image_path -Right $image.Path) -or $rootRecord.sha256 -cne $image.Sha256 -or
            $rootRecord.volume_serial_hex -cne $image.VolumeSerialHex -or $rootRecord.file_id_hex -cne $image.FileIdHex -or $rootRecord.command_line -cne $commandLine) {
            throw 'PHASE0_PROCESS_IDENTITY_BLOCKED: root executable path/hash/file ID/argv mismatch'
        }
        foreach ($child in @($traceNative.Processes | Select-Object -Skip 1)) {
            $childSnapshot = ConvertFrom-D32Phase0DebugProcess -Process $child
            $key = "$($childSnapshot.process_id)|$($childSnapshot.creation_date)"
            if ($descendants.Contains($key)) { throw 'PHASE0_PROCESS_TRACE_BLOCKED: duplicate child PID/creation identity' }
            $descendants[$key] = ConvertTo-D32Phase0ProcessRecord -Process $childSnapshot -ValidatedProfile $currentProfile -Repository $Repository -ExpectedRootPath $Executable -VendoredProtocGrant $grantForProcess -H7CGitRunGrant $H7CGitRunGrant
        }
        $exitCode = [int]$native.ExitCode
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
    $script:D32Phase0LastProcessFailure.RawV2Trace = $processTrace
    $script:D32Phase0LastProcessFailure.NativeCleanup = $cleanup
    $script:D32Phase0LastProcessFailure.ProcessIdentity = $rootRecord
    if ($null -ne $failure) { $script:D32Phase0LastProcessFailure.PrimaryError = [string]$failure }
    if ($null -eq $cleanup -or -not [bool]$cleanup.CleanupSucceeded -or [uint32]$cleanup.JobActiveProcessCount -ne 0) {
        $script:D32Phase0LastProcessFailure.PrimaryError = 'PHASE0_PROCESS_TREE_BLOCKED: no completed Job Object process-tree cleanup evidence'
        throw [string]$script:D32Phase0LastProcessFailure.PrimaryError
    }
    $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $ValidatedProfile
    $post = Get-D32Phase0GitState -Repository $Repository -GitPath $GitPath -GitSha256 $GitSha256
    if ($post.Head -cne $ExpectedCandidateSha) { $script:D32Phase0LastProcessFailure.PrimaryError = 'PHASE0_CANDIDATE_BLOCKED: HEAD changed after a fixed command'; throw [string]$script:D32Phase0LastProcessFailure.PrimaryError }
    if ($null -ne $failure) { $script:D32Phase0LastProcessFailure.PrimaryError = [string]$failure; throw [string]$failure }
    if ($exitCode -ne 0) { $script:D32Phase0LastProcessFailure.PrimaryError = "PHASE0_COMMAND_FAILED: $Name exit_code=$exitCode"; throw [string]$script:D32Phase0LastProcessFailure.PrimaryError }
    $stdoutRef = Get-D32Phase0FileReference -Path $stdoutPath
    $stderrRef = Get-D32Phase0FileReference -Path $stderrPath
    $script:D32Phase0LastProcessFailure = $null
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
        process_trace = $processTrace
        process_tree_cleanup = [ordered]@{
            launch_mode = [string]$native.LaunchMode
            job_close_succeeded = [bool]$cleanup.JobCloseSucceeded
            process_wait_signaled = [bool]$cleanup.ProcessWaitSignaled
            active_process_count_verified = [bool]$cleanup.JobActiveProcessCountVerified
            active_process_count = [uint32]$cleanup.JobActiveProcessCount
            debugger_thread_id = [uint32]$cleanup.DebuggerThreadId
            debugger_thread_exited = [bool]$cleanup.DebuggerThreadExited
            debugger_thread_joined = [bool]$cleanup.DebuggerThreadJoined
            debugger_kill_on_exit_enabled = [bool]$cleanup.DebuggerKillOnExitEnabled
            retained_process_handle_count = [int]$cleanup.RetainedProcessHandleCount
            retained_process_handles_signaled = [bool]$cleanup.RetainedProcessHandlesSignaled
            debugger_association_query_verified = [bool]$cleanup.DebuggerAssociationQueryVerified
            debugger_association_absent = [bool]$cleanup.DebuggerAssociationAbsent
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
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Records,
        [Parameter(Mandatory = $true)][string]$LogRoot,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Environment,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$GitSha256,
        [AllowNull()][object]$VendoredProtocRunGrant,
        [AllowNull()][object]$H7CGitAuthority,
        [AllowNull()][object]$H7CGitRunGrant
    )
    $Ordinal.Value++
    $safeName = $Name -replace '[^A-Za-z0-9._-]', '_'
    $record = Invoke-D32Phase0PinnedProcess `
        -Name $Name -Executable $Executable -Arguments $Arguments `
        -WorkingDirectory $Repository `
        -LogPath (Join-Path $LogRoot ('phase0-{0:D2}-{1}' -f $Ordinal.Value, $safeName)) `
        -Environment $Environment -TimeoutSeconds $TimeoutSeconds `
        -ValidatedProfile $ValidatedProfile -Repository $Repository `
        -ExpectedCandidateSha $ExpectedCandidateSha -GitPath $GitPath -GitSha256 $GitSha256 -VendoredProtocRunGrant $VendoredProtocRunGrant `
        -H7CGitAuthority $H7CGitAuthority -H7CGitRunGrant $H7CGitRunGrant
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

function Test-D32Phase0DirectoryEntryExists {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-D32ProfileCanonicalPathString -Path $Path)) { throw 'Phase0 directory-entry probe path is non-canonical' }
    $parent = [IO.Path]::GetDirectoryName($full)
    if ([String]::IsNullOrWhiteSpace($parent) -or -not (Test-D32ProfileNoReparsePath -Path $parent)) { throw 'Phase0 directory-entry probe parent is missing or reparse-backed' }
    $leaf = [IO.Path]::GetFileName($full)
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($parent)) {
        if ([IO.Path]::GetFileName($entry).Equals($leaf, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-D32Phase0DiagnosticPropertyValue {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    if ($null -eq $Object) { return $null }
    foreach ($name in $Names) {
        if ($Object -is [System.Collections.IDictionary]) {
            foreach ($key in $Object.Keys) {
                if ([String]::Equals([string]$key, $name, [StringComparison]::Ordinal)) { return $Object[$key] }
            }
        }
        $property = $Object.PSObject.Properties[$name]
        if ($null -ne $property) { return $property.Value }
    }
    return $null
}

function New-D32Phase0FixtureGitStatePrefixEvidence {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$States)

    if ($States.Count -eq 0) { return $null }
    $json = ConvertTo-Json -InputObject @($States) -Depth 8 -Compress
    return 'PHASE0_FIXTURE_GIT_STATE_PREFIX_V1:' + $json
}

function Write-D32Phase0BlockedDiagnostic {
    param(
        [Parameter(Mandatory = $true)][string]$PrimaryError,
        [AllowEmptyCollection()][string[]]$SecondaryErrors = @(),
        [AllowNull()][object]$Command,
        [AllowNull()][object]$ProcessIdentity,
        [AllowNull()][object]$RawV2Trace,
        [AllowNull()][object]$NativeCleanup,
        [AllowNull()][string]$StdoutPath,
        [AllowNull()][string]$StderrPath
    )

    $context = $script:D32Phase0FailureContext
    if ($null -eq $context) { throw 'PHASE0_DIAGNOSTIC_BLOCKED: evidence root owner binding is unavailable' }
    $owner = Test-D32Phase0OwnerBinding -EvidenceRoot $context.EvidenceRoot -ExpectedCandidateSha $context.CandidateSha -ValidatedProfile $context.Profile -ExpectedRunId $context.RunId -ExpectedRootIdentity $context.RootIdentity -ExpectedMarkerReference $context.OwnerMarker
    $diagnosticPath = Join-Path $context.EvidenceRoot $script:D32Phase0BlockedDiagnosticName
    if (Test-D32Phase0DirectoryEntryExists -Path $diagnosticPath) { throw 'PHASE0_DIAGNOSTIC_BLOCKED: refusing to overwrite an existing blocked-diagnostic sidecar' }
    $captures = [System.Collections.Generic.List[object]]::new()
    $ordinal = 0
    foreach ($entry in @(
        [PSCustomObject]@{ Stream = 'stdout'; Path = $StdoutPath },
        [PSCustomObject]@{ Stream = 'stderr'; Path = $StderrPath }
    )) {
        $ordinal++
        $capturePath = if ([String]::IsNullOrWhiteSpace([string]$entry.Path)) { $null } else { [IO.Path]::GetFullPath([string]$entry.Path) }
        $reference = $null
        $status = 'UNAVAILABLE'
        if ($null -ne $capturePath) {
            if (-not (Test-D32ProfilePathWithin -Child $capturePath -Parent $context.EvidenceRoot)) { throw "PHASE0_DIAGNOSTIC_BLOCKED: $($entry.Stream) capture path is outside the owner-bound EvidenceRoot" }
            $captureParent = [IO.Path]::GetDirectoryName($capturePath)
            if (-not (Test-D32ProfileNoReparsePath -Path $captureParent)) { throw "PHASE0_DIAGNOSTIC_BLOCKED: $($entry.Stream) capture parent is missing or reparse-backed" }
            if (Test-Path -LiteralPath $capturePath -PathType Leaf) {
                $reference = Get-D32Phase0FileReference -Path $capturePath
                $status = 'CAPTURED'
            }
        }
        $captures.Add([ordered]@{ ordinal = $ordinal; stream = $entry.Stream; path = $capturePath; status = $status; reference = $reference })
    }
    $unverified = [System.Collections.Generic.List[string]]::new()
    $traceRequirements = @(
        [PSCustomObject]@{ Name = 'dedicated_debugger_thread'; Expected = $true },
        [PSCustomObject]@{ Name = 'debugger_kill_on_exit_enabled'; Expected = $true },
        [PSCustomObject]@{ Name = 'debugger_thread_exited'; Expected = $true },
        [PSCustomObject]@{ Name = 'debugger_thread_joined'; Expected = $true },
        [PSCustomObject]@{ Name = 'retained_process_handles_signaled'; Expected = $true },
        [PSCustomObject]@{ Name = 'debugger_association_query_verified'; Expected = $true },
        [PSCustomObject]@{ Name = 'debugger_association_absent'; Expected = $true },
        [PSCustomObject]@{ Name = 'job_accounting_verified'; Expected = $true },
        [PSCustomObject]@{ Name = 'accounting_consistent'; Expected = $true },
        [PSCustomObject]@{ Name = 'event_chain_complete'; Expected = $true },
        [PSCustomObject]@{ Name = 'job_active_processes'; Expected = 0 }
    )
    foreach ($requirement in $traceRequirements) {
        $value = Get-D32Phase0DiagnosticPropertyValue -Object $RawV2Trace -Names @($requirement.Name)
        if ($null -eq $RawV2Trace -or $null -eq $value -or $value -ne $requirement.Expected) { $unverified.Add("trace.$($requirement.Name)") }
    }
    $cleanupRequirements = @(
        [PSCustomObject]@{ Name = 'CleanupSucceeded'; NativeNames = @('CleanupSucceeded', 'cleanup_succeeded'); TraceNames = @() },
        [PSCustomObject]@{ Name = 'JobCloseSucceeded'; NativeNames = @('JobCloseSucceeded', 'job_close_succeeded'); TraceNames = @() },
        [PSCustomObject]@{ Name = 'JobActiveProcessCountVerified'; NativeNames = @('JobActiveProcessCountVerified', 'job_active_process_count_verified'); TraceNames = @() },
        [PSCustomObject]@{ Name = 'DebuggerThreadJoined'; NativeNames = @('DebuggerThreadJoined', 'debugger_thread_joined'); TraceNames = @('debugger_thread_joined') },
        [PSCustomObject]@{ Name = 'RetainedProcessHandlesSignaled'; NativeNames = @('RetainedProcessHandlesSignaled', 'retained_process_handles_signaled'); TraceNames = @('retained_process_handles_signaled') },
        [PSCustomObject]@{ Name = 'DebuggerAssociationQueryVerified'; NativeNames = @('DebuggerAssociationQueryVerified', 'debugger_association_query_verified'); TraceNames = @('debugger_association_query_verified') },
        [PSCustomObject]@{ Name = 'DebuggerAssociationAbsent'; NativeNames = @('DebuggerAssociationAbsent', 'debugger_association_absent'); TraceNames = @('debugger_association_absent') }
    )
    foreach ($requirement in $cleanupRequirements) {
        $value = Get-D32Phase0DiagnosticPropertyValue -Object $NativeCleanup -Names $requirement.NativeNames
        if ($null -eq $value -and $requirement.TraceNames.Count -gt 0) {
            $value = Get-D32Phase0DiagnosticPropertyValue -Object $RawV2Trace -Names $requirement.TraceNames
        }
        $verified = $value -is [bool] -and $value
        if ($requirement.Name -ceq 'JobActiveProcessCountVerified') {
            $activeCount = Get-D32Phase0DiagnosticPropertyValue -Object $NativeCleanup -Names @('JobActiveProcessCount', 'job_active_process_count')
            $verified = $verified -and (Test-D32Phase0Integer -Value $activeCount) -and [Int64]$activeCount -eq 0
        }
        if (-not $verified) { $unverified.Add("cleanup.$($requirement.Name)") }
    }
    $profileIdentity = [ordered]@{
        bytes = [Int64]$context.Profile.Identity.Bytes
        volume_serial_hex = [string]$context.Profile.Identity.VolumeSerialHex
        file_id_hex = [string]$context.Profile.Identity.FileIdHex
    }
    $commandRecord = $null
    if ($null -ne $Command) {
        $commandRecord = $Command
    }
    $contextUnverified = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $commandRecord) { $contextUnverified.Add('failing_fixed_command') }
    if ($null -eq $ProcessIdentity) { $contextUnverified.Add('process_identity') }
    else {
        $identityVerified = Get-D32Phase0DiagnosticPropertyValue -Object $ProcessIdentity -Names @('identity_verified', 'IdentityVerified')
        if ($identityVerified -isnot [bool] -or -not $identityVerified) { $contextUnverified.Add('process_identity.identity_verified') }
    }
    foreach ($capture in $captures) { if ($capture.status -cne 'CAPTURED') { $contextUnverified.Add("stream.$($capture.stream)") } }
    $document = [ordered]@{
        schema_version = 1
        record_type = $script:D32Phase0BlockedDiagnosticType
        status = 'BLOCKED'
        gate_authority = 'NONE'
        phase1_allowed = $false
        aggregate_allowed = $false
        candidate_sha = [string]$context.CandidateSha
        toolchain_profile = [ordered]@{
            path = [string]$context.Profile.ProfilePath
            sha256 = [string]$context.Profile.Digest
            file_identity = $profileIdentity
        }
        evidence_root = [ordered]@{
            path = [string]$owner.EvidenceRootIdentity.Path
            volume_serial_hex = [string]$owner.EvidenceRootIdentity.VolumeSerialHex
            file_id_hex = [string]$owner.EvidenceRootIdentity.FileIdHex
            owner_marker = $owner.MarkerReference
        }
        run_id = [string]$owner.RunId
        failing_fixed_command = $commandRecord
        process_identity = $ProcessIdentity
        raw_v2_trace = $RawV2Trace
        unverified_fields = @($contextUnverified.ToArray())
        job_debug_cleanup = [ordered]@{
            verification = if ($unverified.Count -eq 0) { 'VERIFIED' } else { 'UNVERIFIED' }
            raw_native_cleanup = $NativeCleanup
            unverified_fields = @($unverified.ToArray())
        }
        ordered_stream_captures = @($captures.ToArray())
        primary_error = $PrimaryError
        secondary_errors = @($SecondaryErrors)
        generated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $json = ConvertTo-Json -InputObject $document -Depth 40 -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
    $stream = [IO.File]::Open($diagnosticPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    $null = Get-D32Phase0FileReference -Path $diagnosticPath
    return $diagnosticPath
}

function Get-D32Phase0FixtureFailurePayload {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$ExpectedRunId
    )

    $prefix = 'D32_PHASE0_BLOCKED_DIAGNOSTIC_PAYLOAD_V1:'
    $matches = @($Lines | Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) })
    if ($matches.Count -eq 0) { return $null }
    if ($matches.Count -ne 1) { throw 'PHASE0_DIAGNOSTIC_BLOCKED: fixture producer emitted duplicate blocked-diagnostic payloads' }
    $raw = $matches[0].Substring($prefix.Length)
    if (Test-D32Phase0JsonDuplicateKeys -Json $raw) { throw 'PHASE0_DIAGNOSTIC_BLOCKED: fixture failure payload has duplicate keys or invalid JSON' }
    $payload = $raw | ConvertFrom-D32Phase0Json
    $fields = @('schema_version', 'record_type', 'candidate_sha', 'toolchain_profile_path', 'toolchain_profile_sha256', 'run_id', 'failing_fixed_command', 'process_identity', 'raw_v2_trace', 'raw_job_debug_cleanup', 'ordered_stream_paths', 'primary_error', 'secondary_errors')
    if (-not (Test-D32Phase0ExactProperties -Object $payload -Expected $fields) -or
        -not (Test-D32Phase0Integer -Value $payload.schema_version) -or [Int64]$payload.schema_version -ne 1 -or
        $payload.record_type -cne 'D32_PHASE0_BLOCKED_DIAGNOSTIC_PAYLOAD_V1' -or
        $payload.candidate_sha -cne $ExpectedCandidateSha -or
        -not (Test-D32ProfilePathEqual -Left $payload.toolchain_profile_path -Right $ValidatedProfile.ProfilePath) -or
        $payload.toolchain_profile_sha256 -cne $ValidatedProfile.Digest -or $payload.run_id -cne $ExpectedRunId -or
        $payload.primary_error -isnot [string] -or [String]::IsNullOrWhiteSpace($payload.primary_error) -or
        $payload.secondary_errors -isnot [Array] -or @($payload.secondary_errors | Where-Object { $_ -isnot [string] }).Count -ne 0) {
        throw 'PHASE0_DIAGNOSTIC_BLOCKED: fixture failure payload schema, candidate/profile, run_id, or error binding is invalid'
    }
    $commandFields = @('name', 'executable', 'executable_sha256', 'executable_bytes', 'executable_volume_serial_hex', 'executable_file_id_hex', 'arguments', 'command_line', 'working_directory')
    $command = $payload.failing_fixed_command
    if (-not (Test-D32Phase0ExactProperties -Object $command -Expected $commandFields) -or
        $command.name -isnot [string] -or $command.executable -isnot [string] -or
        $command.executable_sha256 -cne [string]$ValidatedProfile.Profile.toolchain.cargo.sha256 -or
        $command.executable_bytes -ne [Int64]$ValidatedProfile.Profile.toolchain.cargo.bytes -or
        $command.executable_volume_serial_hex -cne [string]$ValidatedProfile.Profile.toolchain.cargo.volume_serial_hex -or
        $command.executable_file_id_hex -cne [string]$ValidatedProfile.Profile.toolchain.cargo.file_id_hex -or
        $command.arguments -isnot [Array] -or @($command.arguments | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
        -not (Test-D32ProfilePathEqual -Left $command.executable -Right $ValidatedProfile.Profile.toolchain.cargo.path) -or
        -not (Test-D32ProfilePathEqual -Left $command.working_directory -Right $Repository) -or
        $command.command_line -cne (ConvertTo-D32Phase0CommandLine -Arguments (@([string]$ValidatedProfile.Profile.toolchain.cargo.path) + @($command.arguments)))) {
        throw 'PHASE0_DIAGNOSTIC_BLOCKED: fixture failure payload does not bind the pinned Cargo image, cwd, and exact argv'
    }
    if ($payload.raw_job_debug_cleanup -isnot [PSCustomObject] -or
        -not (Test-D32Phase0ExactProperties -Object $payload.raw_job_debug_cleanup -Expected @('raw_native_cleanup', 'raw_process_evidence', 'trace_state', 'cleanup_status')) -or
        $payload.ordered_stream_paths -isnot [Array] -or $payload.ordered_stream_paths.Count -ne 2 -or
        $payload.ordered_stream_paths[0].ordinal -ne 1 -or $payload.ordered_stream_paths[0].stream -cne 'stdout' -or
        $payload.ordered_stream_paths[1].ordinal -ne 2 -or $payload.ordered_stream_paths[1].stream -cne 'stderr') {
        throw 'PHASE0_DIAGNOSTIC_BLOCKED: fixture failure payload cleanup/capture structure is malformed'
    }
    foreach ($capture in $payload.ordered_stream_paths) {
        if (-not (Test-D32Phase0ExactProperties -Object $capture -Expected @('ordinal', 'stream', 'path')) -or
            $capture.path -isnot [string] -or -not (Test-D32ProfileCanonicalPathString -Path $capture.path) -or
            -not (Test-D32ProfilePathWithin -Child $capture.path -Parent ([string]$script:D32Phase0FailureContext.EvidenceRoot))) {
            throw 'PHASE0_DIAGNOSTIC_BLOCKED: fixture failure stream path is not an exact canonical file under the owner-bound EvidenceRoot'
        }
    }
    return $payload
}

function Test-D32Phase0FixtureBuildProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$SidecarPath,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][int]$ExpectedRunnerProcessId,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [AllowNull()][string]$VendoredAuthorityPath,
        [AllowNull()][string]$ExpectedVendoredAuthoritySha256,
        [AllowNull()][object]$ValidatedVendoredGrant,
        [AllowNull()][string]$TauriMacrosSourceAuthorityPath,
        [AllowNull()][string]$ExpectedTauriMacrosSourceAuthoritySha256
    )
    $expectedSidecar = [IO.Path]::GetFullPath((Join-Path $OutputRoot 'fixture-build-provenance.json'))
    if (-not (Test-D32ProfilePathEqual -Left $SidecarPath -Right $expectedSidecar) -or -not (Test-D32ProfileNoReparsePath -Path $expectedSidecar)) { throw 'PHASE0_FIXTURE_BLOCKED: fixture build provenance sidecar path is not the fixed external regular file' }
    $sidecarReference = Get-D32Phase0FileReference -Path $expectedSidecar
    $raw = [IO.File]::ReadAllText($expectedSidecar, [Text.Encoding]::UTF8)
    if (Test-D32Phase0JsonDuplicateKeys -Json $raw) { throw 'PHASE0_FIXTURE_BLOCKED: fixture build provenance sidecar has duplicate or invalid JSON keys' }
    $document = $raw | ConvertFrom-D32Phase0Json
    $topFields = @('schema_version', 'record_type', 'candidate_sha', 'source_repo', 'fixture_manifest_path', 'fixture_manifest_sha256', 'fixture_manifest_bytes', 'fixture_manifest_volume_serial_hex', 'fixture_manifest_file_id_hex', 'environment', 'storage', 'process_traces', 'vendored_protoc_run_grant', 'tauri_macros_source_patch')
    if (-not (Test-D32Phase0ExactProperties -Object $document -Expected $topFields) -or -not (Test-D32Phase0Integer -Value $document.schema_version) -or [Int64]$document.schema_version -ne 5 -or
        $document.record_type -isnot [string] -or $document.record_type -cne 'D32_FIXTURE_BUILD_PROVENANCE_V5' -or
        $document.candidate_sha -isnot [string] -or $document.candidate_sha -cne $ExpectedCandidateSha -or
        $document.source_repo -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $document.source_repo -Right $Repository) -or
        $document.fixture_manifest_path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $document.fixture_manifest_path -Right $ManifestPath) -or
        $document.fixture_manifest_sha256 -isnot [string] -or $document.fixture_manifest_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $document.fixture_manifest_volume_serial_hex -isnot [string] -or $document.fixture_manifest_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        $document.fixture_manifest_file_id_hex -isnot [string] -or $document.fixture_manifest_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        -not (Test-D32Phase0Integer -Value $document.fixture_manifest_bytes -Positive)) { throw 'PHASE0_FIXTURE_BLOCKED: fixture build provenance sidecar schema/candidate/source/manifest binding is invalid' }
    if ([String]::IsNullOrWhiteSpace($TauriMacrosSourceAuthorityPath) -and -not [String]::IsNullOrWhiteSpace([string]$script:D32Phase0SelfTestSourcePatchAuthorityPath)) {
        $TauriMacrosSourceAuthorityPath = [string]$script:D32Phase0SelfTestSourcePatchAuthorityPath
        $ExpectedTauriMacrosSourceAuthoritySha256 = [string]$script:D32Phase0SelfTestSourcePatchAuthoritySha256
    }
    if ([String]::IsNullOrWhiteSpace($TauriMacrosSourceAuthorityPath) -or $ExpectedTauriMacrosSourceAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: fixture provenance validation requires the independently pinned external source-patch authority' }
    $sourcePatchAuthority = Test-D32TauriMacrosSourcePatchAuthority `
        -AuthorityPath $TauriMacrosSourceAuthorityPath -ExpectedAuthoritySha256 $ExpectedTauriMacrosSourceAuthoritySha256 `
        -Repository $Repository -CandidateSha $ExpectedCandidateSha -ValidatedProfile $ValidatedProfile -EvidenceRoot $OutputRoot
    if (-not (Test-D32VendoredObjectExactProperties -Object $document.tauri_macros_source_patch -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        (ConvertTo-Json -InputObject $document.tauri_macros_source_patch -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $sourcePatchAuthority.Reference -Depth 5 -Compress)) {
        throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: fixture provenance source-patch reference differs from current opened external authority bytes/identity'
    }
    $grantPath = Join-Path $OutputRoot 'D32-PHASE0-VENDORED-PROTOC-RUN-GRANT.json'
    if (-not (Test-D32VendoredObjectExactProperties -Object $document.vendored_protoc_run_grant -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        $document.vendored_protoc_run_grant.path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $document.vendored_protoc_run_grant.path -Right $grantPath) -or
        -not (Test-D32Phase0Integer -Value $document.vendored_protoc_run_grant.bytes -Positive) -or
        $document.vendored_protoc_run_grant.sha256 -isnot [string] -or $document.vendored_protoc_run_grant.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $document.vendored_protoc_run_grant.volume_serial_hex -isnot [string] -or $document.vendored_protoc_run_grant.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        $document.vendored_protoc_run_grant.file_id_hex -isnot [string] -or $document.vendored_protoc_run_grant.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { throw 'VENDORED_PROTOC_GRANT_BLOCKED: fixture provenance grant reference is malformed or not at its fixed path' }
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
    $storageFields = @('evidence_root', 'owner_marker', 'run_root', 'cargo_home', 'temp_root', 'run_id')
    if (-not (Test-D32Phase0ExactProperties -Object $document.storage -Expected $storageFields) -or
        $document.storage.run_id -isnot [string] -or $document.storage.run_id -cne $environment.run_id) { throw 'PHASE0_FIXTURE_BLOCKED: fixture compact storage schema/run_id mismatch' }
    foreach ($directoryName in @('evidence_root', 'run_root', 'cargo_home', 'temp_root')) {
        $directory = $document.storage.$directoryName
        if (-not (Test-D32Phase0ExactProperties -Object $directory -Expected @('path', 'volume_serial_hex', 'file_id_hex')) -or
            $directory.path -isnot [string] -or $directory.volume_serial_hex -isnot [string] -or $directory.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
            $directory.file_id_hex -isnot [string] -or $directory.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { throw "PHASE0_FIXTURE_BLOCKED: fixture storage $directoryName identity record is malformed" }
    }
    if (-not (Test-D32ProfilePathEqual -Left $document.storage.evidence_root.path -Right $OutputRoot) -or
        -not (Test-D32ProfilePathEqual -Left $document.storage.run_root.path -Right (Join-Path $OutputRoot 'r')) -or
        -not (Test-D32ProfilePathEqual -Left $document.storage.cargo_home.path -Right (Join-Path $OutputRoot 'r\c')) -or
        -not (Test-D32ProfilePathEqual -Left $document.storage.temp_root.path -Right (Join-Path $OutputRoot 'r\t')) -or
        -not (Test-D32ProfilePathEqual -Left $environment.cargo_home -Right $document.storage.cargo_home.path) -or
        -not (Test-D32ProfilePathEqual -Left $environment.temp_root -Right $document.storage.temp_root.path)) {
        throw 'PHASE0_FIXTURE_BLOCKED: Cargo home/temp must use fixed r\\c and r\\t paths under the exact new EvidenceRoot'
    }
    $rootIdentity = Get-D32ProfileDirectoryIdentity -Path $OutputRoot
    if ($rootIdentity.VolumeSerialHex -cne $document.storage.evidence_root.volume_serial_hex -or $rootIdentity.FileIdHex -cne $document.storage.evidence_root.file_id_hex) { throw 'PHASE0_FIXTURE_BLOCKED: EvidenceRoot opened-handle identity changed after fixture preparation' }
    $null = Test-D32Phase0FileReference -Reference $document.storage.owner_marker -AllowedRoot $OutputRoot
    $ownerBinding = Test-D32Phase0OwnerBinding -EvidenceRoot $OutputRoot -ExpectedCandidateSha $ExpectedCandidateSha -ValidatedProfile $ValidatedProfile -ExpectedRunId ([string]$environment.run_id) -ExpectedRootIdentity $rootIdentity -ExpectedMarkerReference $document.storage.owner_marker
    foreach ($directoryName in @('run_root', 'cargo_home', 'temp_root')) {
        $directory = $document.storage.$directoryName
        $null = Test-D32ProfileDirectoryIdentity -Path ([string]$directory.path) -VolumeSerialHex ([string]$directory.volume_serial_hex) -FileIdHex ([string]$directory.file_id_hex)
    }
    if (-not (Test-D32ProfilePathEqual -Left $ownerBinding.EvidenceRoot -Right $OutputRoot)) { throw 'PHASE0_FIXTURE_BLOCKED: fixture provenance owner binding changed EvidenceRoot' }
    $vendoredGrant = $null
    if ($null -ne $ValidatedVendoredGrant) {
        if ((ConvertTo-Json -InputObject $ValidatedVendoredGrant.Reference -Depth 5 -Compress) -cne
            (ConvertTo-Json -InputObject $document.vendored_protoc_run_grant -Depth 5 -Compress)) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: prevalidated per-run grant differs from fixture sidecar reference' }
        $vendoredGrant = $ValidatedVendoredGrant
    }
    elseif (-not [String]::IsNullOrWhiteSpace($VendoredAuthorityPath) -or -not [String]::IsNullOrWhiteSpace($ExpectedVendoredAuthoritySha256)) {
        if ([String]::IsNullOrWhiteSpace($VendoredAuthorityPath) -or $ExpectedVendoredAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'VENDORED_PROTOC_GRANT_BLOCKED: authority path and independent expected SHA must be supplied together' }
        $vendoredGrant = Test-D32VendoredProtocRunGrant `
            -Reference $document.vendored_protoc_run_grant -Repository $Repository -CandidateSha $ExpectedCandidateSha `
            -ValidatedProfile $ValidatedProfile -EvidenceRoot $OutputRoot -ExpectedRunId ([string]$environment.run_id) `
            -CargoHome ([string]$environment.cargo_home) -AuthorityPath $VendoredAuthorityPath `
            -AuthoritySha256 $ExpectedVendoredAuthoritySha256 -OwnerMarkerReference $document.storage.owner_marker
    }
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
    $cargoIdentity = $ValidatedProfile.Profile.toolchain.cargo
    $expectedTraceNames = @('fixture-01-fetch', 'fixture-02-fetch', 'fixture-03-fetch') + @($script:D32Phase0FixtureBuildSpecs | ForEach-Object { [string]$_.name })
    if ($document.process_traces -isnot [Array] -or $document.process_traces.Count -ne $expectedTraceNames.Count) { throw 'PHASE0_FIXTURE_BLOCKED: sidecar must contain the exact eight fetch/fixture process-event traces' }
    for ($i = 0; $i -lt $expectedTraceNames.Count; $i++) {
        $entry = $document.process_traces[$i]
        $wrapperFields = @('name', 'executable', 'arguments', 'command_line', 'working_directory', 'process_trace')
        if (-not (Test-D32Phase0ExactProperties -Object $entry -Expected $wrapperFields) -or
            $entry.name -isnot [string] -or $entry.name -cne $expectedTraceNames[$i] -or
            $entry.executable -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $entry.executable -Right $cargoIdentity.path) -or
            $entry.arguments -isnot [Array] -or @($entry.arguments | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
            $entry.command_line -isnot [string] -or $entry.working_directory -isnot [string] -or
            -not (Test-D32ProfilePathEqual -Left $entry.working_directory -Right $Repository)) { throw "PHASE0_FIXTURE_BLOCKED: sidecar process trace wrapper schema/cargo/cwd mismatch at index $i" }
        if ($i -lt $ValidatedProfile.LockInputs.Count) {
            $lock = $ValidatedProfile.LockInputs[$i]
            $expectedArgs = @('fetch', '--locked', '--manifest-path', $lock.ManifestFullPath, '--target', [string]$ValidatedProfile.Profile.target_triple)
        }
        else {
            $spec = $script:D32Phase0FixtureBuildSpecs[$i - $ValidatedProfile.LockInputs.Count]
            $manifest = [IO.Path]::GetFullPath((Join-Path $Repository $spec.manifest))
            $expectedArgs = @('build', '--quiet', '--locked', '--manifest-path', $manifest, '--bin', [string]$spec.binary)
            if ($spec.features.Count -gt 0) { $expectedArgs += @('--features', ($spec.features -join ' ')) }
            $expectedArgs += @('--jobs', '1')
        }
        if (($entry.arguments -join "`0") -cne ($expectedArgs -join "`0") -or
            $entry.command_line -cne (ConvertTo-D32Phase0CommandLine -Arguments (@([string]$cargoIdentity.path) + $expectedArgs))) { throw "PHASE0_FIXTURE_BLOCKED: fixed process trace command/cwd mismatch at index $i" }
        $traceGrant = if ($i -lt $ValidatedProfile.LockInputs.Count) { $null } else { $vendoredGrant }
        $null = Test-D32Phase0DebugProcessTrace -Trace $entry.process_trace -ExpectedRootPath ([string]$cargoIdentity.path) -ExpectedRootIdentity $cargoIdentity -ExpectedParentProcessId $ExpectedRunnerProcessId -ValidatedProfile $ValidatedProfile -Repository $Repository -VendoredProtocGrant $traceGrant
        $traceRoot = @($entry.process_trace.processes | Where-Object { $_.create_sequence -eq 1 })
        if ($traceRoot.Count -ne 1 -or $traceRoot[0].exit_code -ne 0) { throw "PHASE0_FIXTURE_BLOCKED: command root did not exit successfully in synchronized debug trace at index $i" }
        if ($i -lt $ValidatedProfile.LockInputs.Count) {
            $fetchIdentity = $document.environment.fetch_manifests[$i].process_identity
            $fetchFileTime = [DateTime]::Parse([string]$fetchIdentity.creation_date, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime().ToFileTimeUtc()
            if ($traceRoot[0].process_id -ne $fetchIdentity.process_id -or $traceRoot[0].creation_filetime -ne $fetchFileTime -or
                $traceRoot[0].parent_process_id -ne $fetchIdentity.parent_process_id -or
                -not (Test-D32ProfilePathEqual -Left $traceRoot[0].image_path -Right $fetchIdentity.image_path) -or
                $entry.command_line -cne $fetchIdentity.command_line) { throw "PHASE0_FETCH_BLOCKED: legacy fetch identity disagrees with synchronized process trace at index $i" }
        }
    }
    return [PSCustomObject]@{ Document = $document; Reference = $sidecarReference; ManifestReference = (Get-D32Phase0FileReference -Path $ManifestPath); VendoredGrant = $vendoredGrant; TauriMacrosSourcePatchAuthority = $sourcePatchAuthority }
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
    $result = [ordered]@{ IsValid = $false; Failure = $null; Record = $null; RecordPath = $null; Digest = $null; Identity = $null; CargoHome = $null; OutputRoot = $null; VendoredGrant = $null }
    try {
        if ($ExpectedRecordSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'independent Phase0 record SHA-256 must be lowercase 64-hex' }
        if ($ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$') { throw 'expected candidate SHA must be lowercase 40-hex' }
        $recordFull = [IO.Path]::GetFullPath($RecordPath)
        if (-not (Test-D32ProfileCanonicalPathString -Path $RecordPath) -or -not (Test-D32ProfileNoReparsePath -Path $recordFull)) { throw 'Phase0 record is missing, non-canonical, or reparse-backed' }
        $recordSnapshot = Get-D32ProfileFileSnapshot -Path $recordFull
        if ($recordSnapshot.Sha256 -cne $ExpectedRecordSha256) { throw 'Phase0 record bytes do not match the independently supplied exact SHA-256' }
        $outputRoot = [IO.Path]::GetDirectoryName($recordFull)
        if ([IO.Path]::GetFileName($recordFull) -cne 'D32-PHASE0-MATRIX.json' -or -not (Test-D32ProfileNoReparsePath -Path $outputRoot)) { throw 'Phase0 record must be the fixed filename beneath a non-reparse output root' }
        $blockedDiagnosticPath = Join-Path $outputRoot $script:D32Phase0BlockedDiagnosticName
        if (Test-D32Phase0DirectoryEntryExists -Path $blockedDiagnosticPath) { throw 'Phase0 blocked-diagnostic sidecar exists; failure evidence forbids Phase1/aggregate use' }
        $repo = [IO.Path]::GetFullPath($Repository)
        if ((Test-D32ProfilePathWithin -Child $outputRoot -Parent $repo) -or (Test-D32ProfilePathWithin -Child $repo -Parent $outputRoot)) { throw 'Phase0 output root must be outside and non-overlapping with repository' }
        $raw = [IO.File]::ReadAllText($recordFull, [Text.Encoding]::UTF8)
        if (Test-D32Phase0JsonDuplicateKeys -Json $raw) { throw 'Phase0 record has duplicate object keys or invalid JSON structure' }
        $document = $raw | ConvertFrom-D32Phase0Json
        $topFields = @('schema_version', 'record_type', 'runner_process_id', 'candidate_sha', 'source_repo', 'output_root', 'evidence_root_identity', 'owner_marker', 'vendored_protoc', 'tauri_macros_source_patch', 'h7c_git_child_authority', 'h7c_git_child_attestation', 'status', 'bundle_hashes', 'started_at_utc', 'completed_at_utc', 'final_candidate_sha', 'final_clean', 'powershell', 'toolchain_profile', 'cargo_home', 'fetches', 'fixture', 'commands', 'test_inventory', 'local_suites', 'focused_tests', 'deferred_d31_tests', 'deferred_d29g2_provider_tests', 'not_run_capture_tests', 'governance_inputs', 'phase0_scope')
        if (-not (Test-D32Phase0ExactProperties -Object $document -Expected $topFields)) { throw 'Phase0 record top-level schema has missing or extra fields' }
        if (-not (Test-D32Phase0Integer -Value $document.schema_version) -or [Int64]$document.schema_version -ne $script:D32Phase0SchemaVersion) { throw "Phase0 record schema_version must be the supported JSON integer version $($script:D32Phase0SchemaVersion)" }
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
        if (-not (Test-D32Phase0ExactProperties -Object $document.evidence_root_identity -Expected @('path', 'volume_serial_hex', 'file_id_hex')) -or
            $document.evidence_root_identity.path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $document.evidence_root_identity.path -Right $outputRoot) -or
            $document.evidence_root_identity.volume_serial_hex -isnot [string] -or $document.evidence_root_identity.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
            $document.evidence_root_identity.file_id_hex -isnot [string] -or $document.evidence_root_identity.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { throw 'Phase0 EvidenceRoot identity record is malformed' }
        $rootIdentity = Test-D32ProfileDirectoryIdentity -Path $outputRoot -VolumeSerialHex ([string]$document.evidence_root_identity.volume_serial_hex) -FileIdHex ([string]$document.evidence_root_identity.file_id_hex)
        $null = Test-D32Phase0FileReference -Reference $document.owner_marker -AllowedRoot $outputRoot
        $ownerBinding = Test-D32Phase0OwnerBinding -EvidenceRoot $outputRoot -ExpectedCandidateSha $ExpectedCandidateSha -ValidatedProfile $profile -ExpectedRunId ([string]$document.cargo_home.run_id) -ExpectedRootIdentity $rootIdentity -ExpectedMarkerReference $document.owner_marker
        if (-not (Test-D32Phase0ExactProperties -Object $document.toolchain_profile -Expected @('path', 'sha256', 'file_identity', 'target_triple', 'toolchain', 'executable_inventory', 'script_inventory', 'windows_image_inventory', 'lock_inputs', 'env_policy'))) { throw 'Phase0 toolchain_profile schema has missing/extra fields' }
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
        $expectedScriptInventory = @($profile.ScriptInventory | ForEach-Object { [ordered]@{ path = $_.Path; sha256 = $_.Sha256; bytes = [Int64]$_.Bytes; volume_serial_hex = $_.VolumeSerialHex; file_id_hex = $_.FileIdHex } })
        $expectedWindowsInventory = @($profile.WindowsImageInventory | ForEach-Object { [ordered]@{ path = $_.Path; sha256 = $_.Sha256; bytes = [Int64]$_.Bytes; volume_serial_hex = $_.VolumeSerialHex; file_id_hex = $_.FileIdHex } })
        $recordScriptInventoryJson = ConvertTo-Json -InputObject $document.toolchain_profile.script_inventory -Depth 12 -Compress
        $expectedScriptInventoryJson = ConvertTo-Json -InputObject $expectedScriptInventory -Depth 12 -Compress
        $recordWindowsInventoryJson = ConvertTo-Json -InputObject $document.toolchain_profile.windows_image_inventory -Depth 12 -Compress
        $expectedWindowsInventoryJson = ConvertTo-Json -InputObject $expectedWindowsInventory -Depth 12 -Compress
        if ($recordToolchainJson -cne $expectedToolchainJson -or $recordInventoryJson -cne $expectedInventoryJson -or
            $recordScriptInventoryJson -cne $expectedScriptInventoryJson -or $recordWindowsInventoryJson -cne $expectedWindowsInventoryJson) { throw 'Phase0 direct/executable/dormant-script/Windows-child image inventory differs from the current caller-pinned profile' }
        if ($document.toolchain_profile.lock_inputs -isnot [Array] -or $document.toolchain_profile.lock_inputs.Count -ne $profile.LockInputs.Count) { throw 'Phase0 lock input inventory has wrong array/count' }
        for ($i = 0; $i -lt $profile.LockInputs.Count; $i++) {
            $lockRecord = $document.toolchain_profile.lock_inputs[$i]
            if (-not (Test-D32Phase0ExactProperties -Object $lockRecord -Expected @('manifest_path', 'lock_sha256')) -or $lockRecord.manifest_path -cne $profile.LockInputs[$i].ManifestPath -or $lockRecord.lock_sha256 -cne $profile.LockInputs[$i].LockSha256) { throw 'Phase0 lock paths/SHA differ from the current caller-pinned profile' }
        }

        if (-not (Test-D32Phase0ExactProperties -Object $document.cargo_home -Expected @('path', 'temp_root', 'run_root', 'run_id', 'nonempty_after_fetch', 'run_root_identity', 'cargo_home_identity', 'temp_root_identity')) -or
            $document.cargo_home.path -isnot [string] -or $document.cargo_home.temp_root -isnot [string] -or $document.cargo_home.run_root -isnot [string] -or
            $document.cargo_home.run_id -isnot [string] -or $document.cargo_home.run_id -cnotmatch '^[0-9a-f]{32}$' -or
            $document.cargo_home.nonempty_after_fetch -isnot [bool] -or -not $document.cargo_home.nonempty_after_fetch) { throw 'Phase0 Cargo home schema/fresh-fetch evidence is invalid' }
        if (-not (Test-D32ProfilePathWithin -Child $document.cargo_home.path -Parent $outputRoot) -or -not (Test-D32ProfilePathWithin -Child $document.cargo_home.temp_root -Parent $outputRoot)) { throw 'Phase0 Cargo home/temp must remain beneath external output root' }
        if (-not (Test-D32ProfilePathEqual -Left $document.cargo_home.run_root -Right (Join-Path $outputRoot 'r')) -or
            -not (Test-D32ProfilePathEqual -Left $document.cargo_home.path -Right (Join-Path $outputRoot 'r\c')) -or
            -not (Test-D32ProfilePathEqual -Left $document.cargo_home.temp_root -Right (Join-Path $outputRoot 'r\t')) -or
            $document.cargo_home.run_id -cne $ownerBinding.RunId) { throw 'Phase0 Cargo home/temp/run_id do not match the fixed compact owner-bound layout' }
        foreach ($fieldName in @('run_root_identity', 'cargo_home_identity', 'temp_root_identity')) {
            $directoryIdentity = $document.cargo_home.$fieldName
            if (-not (Test-D32Phase0ExactProperties -Object $directoryIdentity -Expected @('volume_serial_hex', 'file_id_hex')) -or
                $directoryIdentity.volume_serial_hex -isnot [string] -or $directoryIdentity.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
                $directoryIdentity.file_id_hex -isnot [string] -or $directoryIdentity.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { throw "Phase0 $fieldName is malformed" }
        }
        $null = Test-D32ProfileDirectoryIdentity -Path $document.cargo_home.run_root -VolumeSerialHex ([string]$document.cargo_home.run_root_identity.volume_serial_hex) -FileIdHex ([string]$document.cargo_home.run_root_identity.file_id_hex)
        $null = Test-D32ProfileDirectoryIdentity -Path $document.cargo_home.path -VolumeSerialHex ([string]$document.cargo_home.cargo_home_identity.volume_serial_hex) -FileIdHex ([string]$document.cargo_home.cargo_home_identity.file_id_hex)
        $null = Test-D32ProfileDirectoryIdentity -Path $document.cargo_home.temp_root -VolumeSerialHex ([string]$document.cargo_home.temp_root_identity.volume_serial_hex) -FileIdHex ([string]$document.cargo_home.temp_root_identity.file_id_hex)
        $cargoHomeCheck = Test-D32CargoHome -Path $document.cargo_home.path -Repository $repo
        if ($cargoHomeCheck.Empty -or -not (Test-D32ProfileNoReparsePath -Path $document.cargo_home.temp_root)) { throw 'Phase0 Cargo home is empty or temp root is missing/reparse-backed' }
        if (-not (Test-D32Phase0ExactProperties -Object $document.vendored_protoc -Expected @('authority', 'run_grant')) -or
            -not (Test-D32VendoredObjectExactProperties -Object $document.vendored_protoc.authority -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) { throw 'Phase0 vendored-protoc authority/grant references are malformed' }
        $authorityPath = [string]$document.vendored_protoc.authority.path
        $authoritySha = [string]$document.vendored_protoc.authority.sha256
        $authorityValidation = Test-D32VendoredProtocAuthority -AuthorityPath $authorityPath -ExpectedAuthoritySha256 $authoritySha -Repository $repo -CandidateSha $ExpectedCandidateSha -ValidatedProfile $profile -EvidenceRoot $outputRoot
        if ((ConvertTo-Json -InputObject $authorityValidation.Reference -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $document.vendored_protoc.authority -Depth 5 -Compress)) { throw 'Phase0 external vendored-protoc authority reference bytes/identity changed' }
        $vendoredGrant = Test-D32VendoredProtocRunGrant `
            -Reference $document.vendored_protoc.run_grant -Repository $repo -CandidateSha $ExpectedCandidateSha `
            -ValidatedProfile $profile -EvidenceRoot $outputRoot -ExpectedRunId ([string]$document.cargo_home.run_id) `
            -CargoHome ([string]$document.cargo_home.path) -AuthorityPath $authorityPath -AuthoritySha256 $authoritySha `
            -OwnerMarkerReference $document.owner_marker
        if (-not (Test-D32Phase0ExactProperties -Object $document.tauri_macros_source_patch -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) { throw 'Phase0 tauri-macros source authority reference is malformed' }
        $tauriMacrosAuthority = Test-D32TauriMacrosSourcePatchAuthority -AuthorityPath ([string]$document.tauri_macros_source_patch.path) `
            -ExpectedAuthoritySha256 ([string]$document.tauri_macros_source_patch.sha256) -Repository $repo -CandidateSha $ExpectedCandidateSha -ValidatedProfile $profile -EvidenceRoot $outputRoot
        if ((ConvertTo-Json -InputObject $tauriMacrosAuthority.Reference -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $document.tauri_macros_source_patch -Depth 5 -Compress)) { throw 'Phase0 external tauri-macros source authority reference bytes/identity changed' }
        if (-not (Test-D32Phase0ExactProperties -Object $document.h7c_git_child_authority -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
            -not (Test-D32Phase0ExactProperties -Object $document.h7c_git_child_attestation -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) { throw 'Phase0 H7-C Git authority/companion reference is malformed' }
        $h7Inputs = Get-D32H7CGitChildAttestationInputs -Reference $document.h7c_git_child_attestation -EvidenceRoot $outputRoot
        if ((ConvertTo-Json -InputObject $h7Inputs.AuthorityReference -Depth 6 -Compress) -cne
            (ConvertTo-Json -InputObject $document.h7c_git_child_authority -Depth 6 -Compress)) { throw 'Phase0 independently pinned H7-C Git authority differs from the companion authority reference' }
        $h7GitImage = Get-D32ProfileFileSnapshot -Path $h7Inputs.GitImage.Path
        if ($h7GitImage.Bytes -ne $h7Inputs.GitImage.Bytes -or $h7GitImage.Sha256 -cne $h7Inputs.GitImage.Sha256 -or $h7GitImage.VolumeSerialHex -cne $h7Inputs.GitImage.VolumeSerialHex -or $h7GitImage.FileIdHex -cne $h7Inputs.GitImage.FileIdHex) { throw 'H7C_GIT_ATTESTATION_BLOCKED: Git image opened identity differs from the companion header' }
        $h7Authority = Test-D32H7CGitAuthority -AuthorityPath ([string]$document.h7c_git_child_authority.path) -ExpectedAuthoritySha256 ([string]$document.h7c_git_child_authority.sha256) `
            -Repository $repo -CandidateSha $ExpectedCandidateSha -ValidatedProfile $profile -EvidenceRoot $outputRoot -TempRoot ([string]$document.cargo_home.temp_root) `
            -GitImage $h7GitImage -TimeoutSeconds $h7Inputs.TimeoutSeconds
        if ((ConvertTo-Json -InputObject $h7Authority.Reference -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $document.h7c_git_child_authority -Depth 6 -Compress)) { throw 'Phase0 external H7-C Git authority bytes/opened identity changed' }
        $h7RunGrant = Test-D32H7CGitRunGrant -Reference $h7Inputs.Document.run_grant -Authority $h7Authority -Repository $repo -CandidateSha $ExpectedCandidateSha `
            -ValidatedProfile $profile -EvidenceRoot $outputRoot -TempRoot ([string]$document.cargo_home.temp_root) -RunId ([string]$document.cargo_home.run_id) `
            -OwnerMarker $ownerBinding.MarkerReference -GitImage $h7GitImage
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
        $fixtureProvenance = Test-D32Phase0FixtureBuildProvenance -SidecarPath $fixtureProvenanceRef.Path -ManifestPath $fixturePath -Repository $repo -OutputRoot $outputRoot -ExpectedCandidateSha $ExpectedCandidateSha -ExpectedRunnerProcessId ([int]$document.runner_process_id) -ValidatedProfile $profile -VendoredAuthorityPath $authorityPath -ExpectedVendoredAuthoritySha256 $authoritySha -ValidatedVendoredGrant $vendoredGrant -TauriMacrosSourceAuthorityPath ([string]$document.tauri_macros_source_patch.path) -ExpectedTauriMacrosSourceAuthoritySha256 ([string]$document.tauri_macros_source_patch.sha256)
        if ((ConvertTo-Json -InputObject $fixtureProvenance.Document.vendored_protoc_run_grant -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $document.vendored_protoc.run_grant -Depth 5 -Compress)) { throw 'Phase0 fixture provenance grant reference differs from matrix run grant reference' }
        if ((ConvertTo-Json -InputObject $fixtureProvenance.Document.tauri_macros_source_patch -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $document.tauri_macros_source_patch -Depth 5 -Compress)) { throw 'Phase0 fixture provenance tauri-macros source reference differs from matrix source authority reference' }
        if (($fixtureProvenance.Reference | ConvertTo-Json -Depth 5 -Compress) -cne ($document.fixture.build_provenance | ConvertTo-Json -Depth 5 -Compress)) { throw 'Phase0 fixture provenance sidecar reference does not match current opened-handle bytes/identity' }
        if (($document.fixture.fixture_names -join '|') -cne 'd29h1-authority-fixture|d29h7-authority-fixture|d29h7-process-fixture|d29h7-git-helper-fixture|d32a-sandbox-fixture' -or
            ($fixtureDocument.fixtures | ConvertTo-Json -Depth 20 -Compress) -cne ($document.fixture.fixture_records | ConvertTo-Json -Depth 20 -Compress)) { throw 'Phase0 fixture records do not match the independently validated fixture manifest' }
        $fixtureEnvironment = $fixtureProvenance.Document.environment
        if (-not (Test-D32ProfilePathEqual -Left $fixtureEnvironment.cargo_home -Right $document.cargo_home.path) -or
            -not (Test-D32ProfilePathEqual -Left $fixtureEnvironment.temp_root -Right $document.cargo_home.temp_root) -or
            $fixtureEnvironment.run_id -cne $document.cargo_home.run_id -or $fixtureEnvironment.toolchain_profile_sha256 -cne $profile.Digest -or
            -not (Test-D32ProfilePathEqual -Left $fixtureProvenance.Document.storage.run_root.path -Right $document.cargo_home.run_root) -or
            $fixtureProvenance.Document.storage.run_root.volume_serial_hex -cne $document.cargo_home.run_root_identity.volume_serial_hex -or
            $fixtureProvenance.Document.storage.run_root.file_id_hex -cne $document.cargo_home.run_root_identity.file_id_hex -or
            $fixtureProvenance.Document.storage.cargo_home.volume_serial_hex -cne $document.cargo_home.cargo_home_identity.volume_serial_hex -or
            $fixtureProvenance.Document.storage.cargo_home.file_id_hex -cne $document.cargo_home.cargo_home_identity.file_id_hex -or
            $fixtureProvenance.Document.storage.temp_root.volume_serial_hex -cne $document.cargo_home.temp_root_identity.volume_serial_hex -or
            $fixtureProvenance.Document.storage.temp_root.file_id_hex -cne $document.cargo_home.temp_root_identity.file_id_hex -or
            $fixtureProvenance.Document.storage.owner_marker.sha256 -cne $document.owner_marker.sha256 -or
            $fixtureProvenance.Document.storage.owner_marker.file_id_hex -cne $document.owner_marker.file_id_hex) { throw 'Phase0 fixture sidecar is not bound to the recorded compact directories, owner marker, profile, and run ID' }
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
        $commandFields = @('name', 'executable', 'executable_sha256', 'executable_bytes', 'executable_volume_serial_hex', 'executable_file_id_hex', 'argv', 'arguments', 'command_line', 'working_directory', 'candidate_sha_before', 'clean_before', 'started_at_utc', 'completed_at_utc', 'exit_code', 'root_process', 'descendant_processes', 'process_trace', 'process_tree_cleanup', 'stdout', 'stderr', 'candidate_sha_after', 'clean_after')
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
            if (-not (Test-D32Phase0ExactProperties -Object $command.process_tree_cleanup -Expected @('launch_mode', 'job_close_succeeded', 'process_wait_signaled', 'active_process_count_verified', 'active_process_count', 'debugger_thread_id', 'debugger_thread_exited', 'debugger_thread_joined', 'debugger_kill_on_exit_enabled', 'retained_process_handle_count', 'retained_process_handles_signaled', 'debugger_association_query_verified', 'debugger_association_absent', 'cleanup_succeeded', 'detail')) -or
                $command.process_tree_cleanup.launch_mode -cne 'DedicatedOSDebuggerThread(CreateProcessW(DEBUG_PROCESS|CREATE_SUSPENDED)+DebugSetProcessKillOnExit(TRUE)+ResumeThread+WaitForDebugEvent+ContinueDebugEvent)+EXTENDED_STARTUP_INFO+HANDLE_LIST(stdout/stderr)+AssignProcessToJobObject(KILL_ON_JOB_CLOSE)' -or
                $command.process_tree_cleanup.job_close_succeeded -isnot [bool] -or -not $command.process_tree_cleanup.job_close_succeeded -or
                $command.process_tree_cleanup.process_wait_signaled -isnot [bool] -or -not $command.process_tree_cleanup.process_wait_signaled -or
                $command.process_tree_cleanup.active_process_count_verified -isnot [bool] -or -not $command.process_tree_cleanup.active_process_count_verified -or
                -not (Test-D32Phase0Integer -Value $command.process_tree_cleanup.active_process_count) -or $command.process_tree_cleanup.active_process_count -ne 0 -or
                $command.process_tree_cleanup.debugger_thread_id -ne $command.process_trace.debugger_thread_id -or
                $command.process_tree_cleanup.debugger_thread_exited -isnot [bool] -or -not $command.process_tree_cleanup.debugger_thread_exited -or
                $command.process_tree_cleanup.debugger_thread_joined -isnot [bool] -or -not $command.process_tree_cleanup.debugger_thread_joined -or
                $command.process_tree_cleanup.debugger_kill_on_exit_enabled -isnot [bool] -or -not $command.process_tree_cleanup.debugger_kill_on_exit_enabled -or
                $command.process_tree_cleanup.retained_process_handle_count -ne $command.process_trace.retained_process_handle_count -or
                $command.process_tree_cleanup.retained_process_handles_signaled -isnot [bool] -or -not $command.process_tree_cleanup.retained_process_handles_signaled -or
                $command.process_tree_cleanup.debugger_association_query_verified -isnot [bool] -or -not $command.process_tree_cleanup.debugger_association_query_verified -or
                $command.process_tree_cleanup.debugger_association_absent -isnot [bool] -or -not $command.process_tree_cleanup.debugger_association_absent -or
                $command.process_tree_cleanup.cleanup_succeeded -isnot [bool] -or -not $command.process_tree_cleanup.cleanup_succeeded) { throw "Phase0 command[$i] lacks verified process-tree cleanup" }
            $rootProcess = $command.root_process
            if (-not (Test-D32Phase0ExactProperties -Object $rootProcess -Expected @('process_id', 'parent_process_id', 'name', 'image_path', 'command_line', 'creation_date', 'observed_at_utc', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'allowed_image_reason', 'identity_verified')) -or
                -not (Test-D32Phase0Integer -Value $rootProcess.process_id -Positive) -or -not (Test-D32Phase0Integer -Value $rootProcess.parent_process_id -Positive) -or
                @($rootProcess.PSObject.Properties | Where-Object { @('name', 'image_path', 'command_line', 'creation_date', 'observed_at_utc', 'sha256', 'volume_serial_hex', 'file_id_hex', 'allowed_image_reason') -contains $_.Name -and $_.Value -isnot [string] }).Count -ne 0 -or
                $rootProcess.identity_verified -isnot [bool] -or -not $rootProcess.identity_verified -or
                $rootProcess.parent_process_id -ne [int]$document.runner_process_id -or -not (Test-D32ProfilePathEqual -Left $rootProcess.image_path -Right $plan.executable) -or $rootProcess.command_line -cne $expectedLine -or
                $rootProcess.sha256 -cne $command.executable_sha256 -or [Int64]$rootProcess.bytes -ne [Int64]$command.executable_bytes -or
                $rootProcess.volume_serial_hex -cne $command.executable_volume_serial_hex -or $rootProcess.file_id_hex -cne $command.executable_file_id_hex) { throw "Phase0 command[$i] root process identity mismatch" }
            $commandH7Authority = if ($command.name -ceq 'vita-full-local-suite') { $h7Authority } else { $null }
            $commandH7RunGrant = if ($command.name -ceq 'vita-full-local-suite') { $h7RunGrant } else { $null }
            $null = Test-D32Phase0DebugProcessTrace -Trace $command.process_trace -ExpectedRootPath $plan.executable -ExpectedRootIdentity $toolRecord `
                -ExpectedParentProcessId ([int]$document.runner_process_id) -ValidatedProfile $profile -Repository $repo -VendoredProtocGrant $vendoredGrant `
                -H7CGitAuthority $commandH7Authority -H7CGitRunGrant $commandH7RunGrant
            $traceRoot = @($command.process_trace.processes | Where-Object { $_.create_sequence -eq 1 })
            $rootFileTime = [DateTime]::Parse([string]$rootProcess.creation_date, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime().ToFileTimeUtc()
            if ($traceRoot.Count -ne 1 -or $traceRoot[0].process_id -ne $rootProcess.process_id -or $traceRoot[0].creation_filetime -ne $rootFileTime -or
                $traceRoot[0].parent_process_id -ne $rootProcess.parent_process_id -or $traceRoot[0].exit_code -ne $command.exit_code) { throw "Phase0 command[$i] legacy root record/exit does not match debug CREATE/EXIT identity" }
            if ($command.descendant_processes -isnot [Array]) { throw "Phase0 command[$i] descendants must be a JSON array" }
            $processKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            [void]$processKeys.Add("$($rootProcess.process_id)|$($rootProcess.creation_date)")
            foreach ($child in $command.descendant_processes) {
                if (-not (Test-D32Phase0ExactProperties -Object $child -Expected @('process_id', 'parent_process_id', 'name', 'image_path', 'command_line', 'creation_date', 'observed_at_utc', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'allowed_image_reason', 'identity_verified')) -or
                    -not (Test-D32Phase0Integer -Value $child.process_id -Positive) -or -not (Test-D32Phase0Integer -Value $child.parent_process_id -Positive) -or
                    @($child.PSObject.Properties | Where-Object { @('name', 'image_path', 'command_line', 'creation_date', 'observed_at_utc', 'sha256', 'volume_serial_hex', 'file_id_hex', 'allowed_image_reason') -contains $_.Name -and $_.Value -isnot [string] }).Count -ne 0 -or
                    $child.identity_verified -isnot [bool] -or -not $child.identity_verified -or $child.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                    -not (Test-D32Phase0Integer -Value $child.bytes -Positive) -or $child.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or $child.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { throw "Phase0 command[$i] child process identity schema is invalid" }
                if (-not $processKeys.Add("$($child.process_id)|$($child.creation_date)")) { throw "Phase0 command[$i] process snapshot contains duplicate PID/creation identity" }
                $childFileTime = [DateTime]::Parse([string]$child.creation_date, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime().ToFileTimeUtc()
                $traceChild = @($command.process_trace.processes | Where-Object { $_.process_id -eq $child.process_id -and $_.creation_filetime -eq $childFileTime })
                if ($traceChild.Count -ne 1 -or -not (Test-D32ProfilePathEqual -Left $traceChild[0].image_path -Right $child.image_path) -or
                    $traceChild[0].sha256 -cne $child.sha256 -or $traceChild[0].bytes -ne $child.bytes -or
                    $traceChild[0].volume_serial_hex -cne $child.volume_serial_hex -or $traceChild[0].file_id_hex -cne $child.file_id_hex -or
                    $traceChild[0].parent_process_id -ne $child.parent_process_id) { throw "Phase0 command[$i] child record differs from synchronized debug CREATE evidence" }
                $actualReason = Get-D32Phase0AllowedChildImageReason -ImagePath $child.image_path -ValidatedProfile $profile -Repository $repo -ExpectedRootPath ([string]$plan.executable) -ImageIdentity $child -VendoredProtocGrant $vendoredGrant -H7CGitRunGrant $commandH7RunGrant
                if ([String]::IsNullOrWhiteSpace($actualReason) -or $child.allowed_image_reason -cne $actualReason) { throw "Phase0 command[$i] contains unknown child image" }
            }
        }

        $vitaSuiteCommand = @($document.commands | Where-Object { $_.name -ceq 'vita-full-local-suite' })
        if ($vitaSuiteCommand.Count -ne 1) { throw 'Phase0 H7-C companion requires exactly one fixed Vita full-local-suite command' }
        $h7Attestation = Test-D32H7CGitChildAttestation -Reference $document.h7c_git_child_attestation -Authority $h7Authority -RunGrant $h7RunGrant `
            -OwnerBinding $ownerBinding -Phase0Command $vitaSuiteCommand[0] -Repository $repo -CandidateSha $ExpectedCandidateSha `
            -ValidatedProfile $profile -EvidenceRoot $outputRoot -TempRoot ([string]$document.cargo_home.temp_root) -GitImage $h7GitImage
        if ((ConvertTo-Json -InputObject $h7Attestation.Reference -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $document.h7c_git_child_attestation -Depth 5 -Compress)) { throw 'Phase0 H7-C companion reference bytes/identity changed' }

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
        $result.VendoredGrant = $vendoredGrant
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
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines)
    if ($Lines.Count -eq 0) { throw 'PHASE0_TEST_OUTPUT_BLOCKED: captured Cargo test-list output is empty' }
    $tests = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $Lines) {
        if ($line -match '^\s*(.+): test\s*$') { $tests.Add([string]$Matches[1]) }
    }
    return @($tests.ToArray())
}

function Get-D32Phase0IgnoredTests {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines)
    return @(Get-D32Phase0ListedTests -Lines $Lines)
}

function Test-D32Phase0ExactTestListOutput {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines, [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Expected, [switch]$Ignored)
    if ($Lines.Count -eq 0) { return $false }
    $observed = if ($Ignored) { @(Get-D32Phase0IgnoredTests -Lines $Lines) } else { @(Get-D32Phase0ListedTests -Lines $Lines) }
    return (($observed -join "`0") -ceq ($Expected -join "`0"))
}

function Get-D32Phase0Summaries {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines)
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

function Test-D32Phase0OwnerBinding {
    param(
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$ExpectedRunId,
        [AllowNull()][object]$ExpectedRootIdentity,
        [AllowNull()][object]$ExpectedMarkerReference
    )

    if ($ExpectedRunId -cnotmatch '^[0-9a-f]{32}$') { throw 'PHASE0_OWNER_BLOCKED: run_id must be a lowercase 32-hex fresh-run identifier' }
    if ($ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$') { throw 'PHASE0_OWNER_BLOCKED: candidate SHA must be lowercase 40-hex' }
    $root = [IO.Path]::GetFullPath($EvidenceRoot)
    $rootIdentity = Get-D32ProfileDirectoryIdentity -Path $root
    if ($null -ne $ExpectedRootIdentity -and
        ($rootIdentity.VolumeSerialHex -cne [string]$ExpectedRootIdentity.VolumeSerialHex -or $rootIdentity.FileIdHex -cne [string]$ExpectedRootIdentity.FileIdHex)) {
        throw 'PHASE0_OWNER_BLOCKED: opened EvidenceRoot identity changed'
    }
    $markerPath = Join-Path $root $script:D32Phase0OwnerBindingName
    if (-not (Test-D32ProfileCanonicalPathString -Path $markerPath) -or -not (Test-D32ProfileNoReparsePath -Path $markerPath)) { throw 'PHASE0_OWNER_BLOCKED: identity-bound owner marker is missing, non-canonical, or reparse-backed' }
    $markerSnapshot = Get-D32ProfileFileSnapshot -Path $markerPath
    if ($null -ne $ExpectedMarkerReference -and
        ($markerSnapshot.Bytes -ne [Int64]$ExpectedMarkerReference.bytes -or $markerSnapshot.Sha256 -cne [string]$ExpectedMarkerReference.sha256 -or
            $markerSnapshot.VolumeSerialHex -cne [string]$ExpectedMarkerReference.volume_serial_hex -or $markerSnapshot.FileIdHex -cne [string]$ExpectedMarkerReference.file_id_hex)) {
        throw 'PHASE0_OWNER_BLOCKED: owner marker bytes or opened-handle identity changed'
    }
    $raw = [IO.File]::ReadAllText($markerPath, [Text.Encoding]::UTF8)
    if (Test-D32Phase0JsonDuplicateKeys -Json $raw) { throw 'PHASE0_OWNER_BLOCKED: owner marker has duplicate keys or invalid JSON' }
    $marker = $raw | ConvertFrom-D32Phase0Json
    $fields = @('schema_version', 'record_type', 'candidate_sha', 'toolchain_profile_path', 'toolchain_profile_sha256', 'toolchain_profile_bytes', 'toolchain_profile_volume_serial_hex', 'toolchain_profile_file_id_hex', 'evidence_root_path', 'evidence_root_volume_serial_hex', 'evidence_root_file_id_hex', 'run_id')
    if (-not (Test-D32Phase0ExactProperties -Object $marker -Expected $fields) -or
        -not (Test-D32Phase0Integer -Value $marker.schema_version) -or [Int64]$marker.schema_version -ne 1 -or
        $marker.record_type -isnot [string] -or $marker.record_type -cne $script:D32Phase0OwnerBindingType -or
        $marker.candidate_sha -isnot [string] -or $marker.candidate_sha -cne $ExpectedCandidateSha -or
        $marker.toolchain_profile_path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $marker.toolchain_profile_path -Right $ValidatedProfile.ProfilePath) -or
        $marker.toolchain_profile_sha256 -isnot [string] -or $marker.toolchain_profile_sha256 -cne [string]$ValidatedProfile.Digest -or
        -not (Test-D32Phase0Integer -Value $marker.toolchain_profile_bytes -Positive) -or [Int64]$marker.toolchain_profile_bytes -ne [Int64]$ValidatedProfile.Identity.Bytes -or
        $marker.toolchain_profile_volume_serial_hex -isnot [string] -or $marker.toolchain_profile_volume_serial_hex -cne [string]$ValidatedProfile.Identity.VolumeSerialHex -or
        $marker.toolchain_profile_file_id_hex -isnot [string] -or $marker.toolchain_profile_file_id_hex -cne [string]$ValidatedProfile.Identity.FileIdHex -or
        $marker.evidence_root_path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $marker.evidence_root_path -Right $root) -or
        $marker.evidence_root_volume_serial_hex -isnot [string] -or $marker.evidence_root_volume_serial_hex -cne $rootIdentity.VolumeSerialHex -or
        $marker.evidence_root_file_id_hex -isnot [string] -or $marker.evidence_root_file_id_hex -cne $rootIdentity.FileIdHex -or
        $marker.run_id -isnot [string] -or $marker.run_id -cne $ExpectedRunId) {
        throw 'PHASE0_OWNER_BLOCKED: owner marker does not bind this candidate, profile, opened EvidenceRoot, and fresh run_id'
    }
    $profileSnapshot = Get-D32ProfileFileSnapshot -Path ([string]$ValidatedProfile.ProfilePath)
    if ($profileSnapshot.Sha256 -cne [string]$ValidatedProfile.Digest -or $profileSnapshot.Bytes -ne [Int64]$ValidatedProfile.Identity.Bytes -or
        $profileSnapshot.VolumeSerialHex -cne [string]$ValidatedProfile.Identity.VolumeSerialHex -or $profileSnapshot.FileIdHex -cne [string]$ValidatedProfile.Identity.FileIdHex) {
        throw 'PHASE0_OWNER_BLOCKED: caller-pinned profile identity changed after owner binding'
    }
    return [PSCustomObject]@{
        EvidenceRoot = $root
        EvidenceRootIdentity = $rootIdentity
        RunId = [string]$marker.run_id
        MarkerPath = $markerPath
        Marker = $marker
        MarkerReference = [ordered]@{
            path = $markerSnapshot.Path
            bytes = [Int64]$markerSnapshot.Bytes
            sha256 = $markerSnapshot.Sha256
            volume_serial_hex = $markerSnapshot.VolumeSerialHex
            file_id_hex = $markerSnapshot.FileIdHex
        }
    }
}

function New-D32Phase0FixtureOutputRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$RunId
    )

    $full = Assert-D32Phase0OutputRoot -Path $Path -Repository $Repository
    try {
        $rootIdentity = New-D32ProfileDirectoryCreateNew -Path $full
        $staticMarkerPath = Join-Path $full $script:D32Phase0FixtureOwnerMarkerName
        $staticMarkerBytes = [Text.UTF8Encoding]::new($false).GetBytes($script:D32Phase0FixtureOwnerMarker)
        $staticMarkerStream = [IO.File]::Open($staticMarkerPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        try { $staticMarkerStream.Write($staticMarkerBytes, 0, $staticMarkerBytes.Length); $staticMarkerStream.Flush($true) }
        finally { $staticMarkerStream.Dispose() }

        $ownerDocument = [ordered]@{
            schema_version = 1
            record_type = $script:D32Phase0OwnerBindingType
            candidate_sha = $ExpectedCandidateSha
            toolchain_profile_path = [string]$ValidatedProfile.ProfilePath
            toolchain_profile_sha256 = [string]$ValidatedProfile.Digest
            toolchain_profile_bytes = [Int64]$ValidatedProfile.Identity.Bytes
            toolchain_profile_volume_serial_hex = [string]$ValidatedProfile.Identity.VolumeSerialHex
            toolchain_profile_file_id_hex = [string]$ValidatedProfile.Identity.FileIdHex
            evidence_root_path = [string]$rootIdentity.Path
            evidence_root_volume_serial_hex = [string]$rootIdentity.VolumeSerialHex
            evidence_root_file_id_hex = [string]$rootIdentity.FileIdHex
            run_id = $RunId
        }
        $ownerPath = Join-Path $full $script:D32Phase0OwnerBindingName
        $ownerBytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $ownerDocument -Depth 5 -Compress))
        $ownerStream = [IO.File]::Open($ownerPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        try { $ownerStream.Write($ownerBytes, 0, $ownerBytes.Length); $ownerStream.Flush($true) }
        finally { $ownerStream.Dispose() }

        $binding = Test-D32Phase0OwnerBinding -EvidenceRoot $full -ExpectedCandidateSha $ExpectedCandidateSha -ValidatedProfile $ValidatedProfile -ExpectedRunId $RunId -ExpectedRootIdentity $rootIdentity
        $items = @(Get-ChildItem -LiteralPath $full -Force -ErrorAction Stop)
        if ($items.Count -ne 2 -or
            @($items | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count -ne 0 -or
            @($items | ForEach-Object { [string]$_.Name } | Where-Object { $_ -notin @($script:D32Phase0FixtureOwnerMarkerName, $script:D32Phase0OwnerBindingName) }).Count -ne 0 -or
            [IO.File]::ReadAllText($staticMarkerPath).Trim() -cne $script:D32Phase0FixtureOwnerMarker) {
            throw 'new output root contains unexpected content or a reparse-backed owner marker'
        }
        return [PSCustomObject]@{
            Path = $full
            RunId = $binding.RunId
            RootIdentity = $binding.EvidenceRootIdentity
            OwnerMarker = $binding.MarkerReference
        }
    }
    catch {
        throw "PHASE0_OUTPUT_BLOCKED: could not exclusively initialize and bind the fresh external evidence root; any partial directory is preserved: $($_.Exception.Message)"
    }
}

function Write-D32Phase0FixtureTranscript {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [AllowEmptyString()][string]$FixtureText,
        [AllowNull()][string]$PrimaryFailure
    )

    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-D32ProfileCanonicalPathString -Path $Path) -or
        -not (Test-D32ProfilePathWithin -Child $full -Parent $OutputRoot) -or
        -not (Test-D32ProfileNoReparsePath -Path $OutputRoot) -or
        (Test-Path -LiteralPath $full)) {
        throw 'PHASE0_LOG_BLOCKED: startup transcript path is non-canonical, outside the new evidence root, reparse-backed, or already exists'
    }

    $builder = [Text.StringBuilder]::new()
    if (-not [String]::IsNullOrEmpty($FixtureText)) { [void]$builder.Append($FixtureText).Append([Environment]::NewLine) }
    if (-not [String]::IsNullOrWhiteSpace($PrimaryFailure)) {
        [void]$builder.AppendLine('D32_PHASE0_FIXTURE_PRIMARY_EXCEPTION_BEGIN')
        [void]$builder.AppendLine($PrimaryFailure)
        [void]$builder.AppendLine('D32_PHASE0_FIXTURE_PRIMARY_EXCEPTION_END')
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($builder.ToString())
    $stream = [IO.File]::Open($full, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    }
    finally { $stream.Dispose() }
    return (Get-D32Phase0FileReference -Path $full)
}

function Add-D32Phase0FixtureTranscriptDiagnostic {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$OutputRoot, [Parameter(Mandatory = $true)][string]$Message)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-D32ProfilePathWithin -Child $full -Parent $OutputRoot) -or
        -not (Test-D32ProfileNoReparsePath -Path $full)) {
        throw 'PHASE0_LOG_BLOCKED: cannot append a secondary startup diagnostic outside the verified transcript'
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("D32_PHASE0_FIXTURE_SECONDARY_DIAGNOSTIC_BEGIN`r`n$Message`r`nD32_PHASE0_FIXTURE_SECONDARY_DIAGNOSTIC_END`r`n")
    $stream = [IO.File]::Open($full, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    }
    finally { $stream.Dispose() }
    return (Get-D32Phase0FileReference -Path $full)
}

function Get-D32Phase0FixtureFailureSummary {
    param(
        [AllowNull()][string]$FixtureFailure,
        [AllowNull()][string]$GitStateFailure,
        [AllowNull()][string]$TranscriptFailure
    )

    if (-not [String]::IsNullOrWhiteSpace($FixtureFailure)) {
        $message = "PHASE0_FIXTURE_BLOCKED: $FixtureFailure"
        if (-not [String]::IsNullOrWhiteSpace($GitStateFailure)) { $message += "; secondary Git-state validation failure: $GitStateFailure" }
        if (-not [String]::IsNullOrWhiteSpace($TranscriptFailure)) { $message += "; secondary transcript persistence failure: $TranscriptFailure" }
        return $message
    }
    if (-not [String]::IsNullOrWhiteSpace($GitStateFailure)) { return $GitStateFailure }
    if (-not [String]::IsNullOrWhiteSpace($TranscriptFailure)) { return "PHASE0_LOG_BLOCKED: $TranscriptFailure" }
    return $null
}

function Invoke-D32Phase0FixtureProducerCapture {
    param([Parameter(Mandatory = $true)][scriptblock]$Producer)

    $lines = [System.Collections.Generic.List[string]]::new()
    $failure = $null
    try {
        & $Producer *>&1 | ForEach-Object { $null = $lines.Add([string]$_) }
    }
    catch { $failure = $_.Exception.Message }
    return [PSCustomObject]@{ Lines = @($lines.ToArray()); Failure = $failure }
}

function Test-D32Phase0FixedInventory {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][hashtable]$Inventories)
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
        [Parameter(Mandatory = $true)][string]$VendoredProtocAuthorityPath,
        [Parameter(Mandatory = $true)][string]$ExpectedVendoredProtocAuthoritySha256,
        [Parameter(Mandatory = $true)][string]$TauriMacrosSourceAuthorityPath,
        [Parameter(Mandatory = $true)][string]$ExpectedTauriMacrosSourceAuthoritySha256,
        [Parameter(Mandatory = $true)][string]$H7CGitAuthorityPath,
        [Parameter(Mandatory = $true)][string]$ExpectedH7CGitAuthoritySha256,
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
    $vendoredAuthority = Test-D32VendoredProtocAuthority `
        -AuthorityPath $VendoredProtocAuthorityPath -ExpectedAuthoritySha256 $ExpectedVendoredProtocAuthoritySha256 `
        -Repository $repo -CandidateSha $ExpectedSha -ValidatedProfile $profile -EvidenceRoot $output
    $tauriMacrosAuthority = Test-D32TauriMacrosSourcePatchAuthority `
        -AuthorityPath $TauriMacrosSourceAuthorityPath -ExpectedAuthoritySha256 $ExpectedTauriMacrosSourceAuthoritySha256 `
        -Repository $repo -CandidateSha $ExpectedSha -ValidatedProfile $profile -EvidenceRoot $output
    $gitImage = Get-D32ProfileFileSnapshot -Path $GitPath
    $expectedTempRoot = Join-Path (Join-Path $output 'r') 't'
    $h7cAuthority = Test-D32H7CGitAuthority `
        -AuthorityPath $H7CGitAuthorityPath -ExpectedAuthoritySha256 $ExpectedH7CGitAuthoritySha256 `
        -Repository $repo -CandidateSha $ExpectedSha -ValidatedProfile $profile `
        -EvidenceRoot $output -TempRoot $expectedTempRoot -GitImage $gitImage -TimeoutSeconds $TimeoutSeconds
    Set-D32GitCaptureContext -ValidatedProfile $profile -GitPath $GitPath -GitSha256 $GitSha256 -TimeoutSeconds 120
    $pre = Get-D32Phase0GitState -Repository $repo -GitPath $GitPath -GitSha256 $GitSha256
    if ($pre.Head -cne $ExpectedSha) { throw 'PHASE0_CANDIDATE_BLOCKED: current HEAD does not equal caller-pinned candidate SHA' }
    $findings = [System.Collections.ArrayList]::new()
    Test-D32Governance -Repository $repo -Findings $findings
    if (@($findings | Where-Object { $_.Severity -eq 'ERROR' }).Count -gt 0) { throw 'PHASE0_GOVERNANCE_BLOCKED: current governance inputs failed preflight' }

    # Claim the already caller-pinned, previously absent evidence root before
    # invoking the fixture producer. This lets the runner preserve the exact
    # producer failure even when the producer cannot reach its own root setup.
    $runId = [Guid]::NewGuid().ToString('N').ToLowerInvariant()
    $outputBinding = New-D32Phase0FixtureOutputRoot -Path $output -Repository $repo -ExpectedCandidateSha $ExpectedSha -ValidatedProfile $profile -RunId $runId
    $output = [string]$outputBinding.Path
    $script:D32Phase0FailureContext = [PSCustomObject]@{
        EvidenceRoot = $output
        CandidateSha = $ExpectedSha
        Profile = $profile
        RunId = $runId
        RootIdentity = $outputBinding.RootIdentity
        OwnerMarker = $outputBinding.OwnerMarker
    }
    $started = [DateTimeOffset]::UtcNow
    $phaseCommands = [System.Collections.Generic.List[object]]::new()
    $fixtureScript = [IO.Path]::GetFullPath((Join-Path $script:D32Phase0ScriptRoot 'd32-fixture-prebuild.ps1'))
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
        Phase0OwnerBinding = $outputBinding
        VendoredProtocAuthorityPath = $VendoredProtocAuthorityPath
        ExpectedVendoredProtocAuthoritySha256 = $ExpectedVendoredProtocAuthoritySha256
        TauriMacrosSourceAuthorityPath = $TauriMacrosSourceAuthorityPath
        ExpectedTauriMacrosSourceAuthoritySha256 = $ExpectedTauriMacrosSourceAuthoritySha256
        TimeoutSeconds = $TimeoutSeconds
    }
    $fixtureProducer = { & $fixtureScript @fixtureArguments }.GetNewClosure()
    $fixtureCapture = Invoke-D32Phase0FixtureProducerCapture -Producer $fixtureProducer
    $fixtureOutput = @($fixtureCapture.Lines)
    $fixtureFailure = $fixtureCapture.Failure
    $fixtureText = ($fixtureOutput | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    $fixtureOutputTooLarge = $fixtureText.Length -gt 16000000
    if ($fixtureOutputTooLarge) {
        $fixtureText = $fixtureText.Substring(0, 15900000) + [Environment]::NewLine + '[fixture output truncated at the 16 MB evidence bound]'
        if ($null -eq $fixtureFailure) { $fixtureFailure = 'in-process fixture output exceeded the 16 MB evidence bound' }
    }
    $transcriptFailure = $null
    try {
        $null = Write-D32Phase0FixtureTranscript -Path $fixtureTranscriptPath -OutputRoot $output -FixtureText $fixtureText -PrimaryFailure $fixtureFailure
    }
    catch { $transcriptFailure = $_.Exception.Message }

    $fixtureGitStates = @()
    $fixtureGitStateFailure = $null
    try {
        if ([String]::IsNullOrWhiteSpace($fixtureFailure)) {
            $fixtureGitStates = @(Get-D32Phase0FixtureGitStates -Lines @($fixtureText -split "`r?`n") -ExpectedCandidateSha $ExpectedSha)
        }
        else {
            $fixtureGitStates = @(Get-D32Phase0FixtureGitStates -Lines @($fixtureText -split "`r?`n") -ExpectedCandidateSha $ExpectedSha -AllowPartial)
            if ($fixtureGitStates.Count -lt 10) {
                $fixtureGitStateFailure = "PHASE0_FIXTURE_STATE_INCOMPLETE: producer failed after $($fixtureGitStates.Count) of 10 ordered clean-candidate Git-state markers; $((10 - $fixtureGitStates.Count)) remaining markers are unavailable after the primary failure"
            }
        }
    }
    catch { $fixtureGitStateFailure = $_.Exception.Message }
    if (-not [String]::IsNullOrWhiteSpace($fixtureGitStateFailure) -and [String]::IsNullOrWhiteSpace($transcriptFailure)) {
        try { $null = Add-D32Phase0FixtureTranscriptDiagnostic -Path $fixtureTranscriptPath -OutputRoot $output -Message $fixtureGitStateFailure }
        catch { $transcriptFailure = $_.Exception.Message }
    }
    $fixtureFailureSummary = Get-D32Phase0FixtureFailureSummary `
        -FixtureFailure $fixtureFailure `
        -GitStateFailure $fixtureGitStateFailure `
        -TranscriptFailure $transcriptFailure
    if ($null -ne $fixtureFailureSummary) {
        $payload = $null
        $diagnosticSecondary = [System.Collections.Generic.List[string]]::new()
        foreach ($secondary in @($fixtureGitStateFailure, $transcriptFailure)) {
            if (-not [String]::IsNullOrWhiteSpace([string]$secondary)) { $diagnosticSecondary.Add([string]$secondary) }
        }
        if ($null -ne $fixtureFailure -and $fixtureGitStates.Count -gt 0) {
            $prefixEvidence = New-D32Phase0FixtureGitStatePrefixEvidence -States @($fixtureGitStates)
            if (-not [String]::IsNullOrWhiteSpace($prefixEvidence)) { $diagnosticSecondary.Add($prefixEvidence) }
        }
        foreach ($captureFailure in @($fixtureText -split "`r?`n" | Where-Object { $_.StartsWith('D32_PHASE0_BLOCKED_DIAGNOSTIC_CAPTURE_ERROR:', [StringComparison]::Ordinal) })) {
            $diagnosticSecondary.Add([string]$captureFailure.Substring('D32_PHASE0_BLOCKED_DIAGNOSTIC_CAPTURE_ERROR:'.Length))
        }
        try {
            $payload = Get-D32Phase0FixtureFailurePayload -Lines @($fixtureText -split "`r?`n") -Repository $repo -ExpectedCandidateSha $ExpectedSha -ValidatedProfile $profile -ExpectedRunId $script:D32Phase0FailureContext.RunId
            if ($null -ne $payload) { foreach ($secondary in $payload.secondary_errors) { $diagnosticSecondary.Add([string]$secondary) } }
            else { $diagnosticSecondary.Add('fixture producer did not provide a structured fixed-command/process diagnostic payload') }
        }
        catch { $diagnosticSecondary.Add('fixture failure payload validation: ' + $_.Exception.Message) }
        try {
            $command = if ($null -eq $payload) { $null } else { $payload.failing_fixed_command }
            $processIdentity = if ($null -eq $payload) { $null } else { $payload.process_identity }
            $rawTrace = if ($null -eq $payload) { $null } else { $payload.raw_v2_trace }
            $rawProcessEvidence = if ($null -eq $payload) { $null } else { $payload.raw_job_debug_cleanup.raw_process_evidence }
            $nativeCleanupProperty = if ($null -eq $rawProcessEvidence) { $null } else { $rawProcessEvidence.PSObject.Properties['native_cleanup'] }
            $nativeCleanup = if ($null -ne $nativeCleanupProperty -and $null -ne $nativeCleanupProperty.Value) { $nativeCleanupProperty.Value } elseif ($null -eq $payload) { $null } else { $payload.raw_job_debug_cleanup.raw_native_cleanup }
            $stdoutPath = if ($null -eq $payload) { $null } else { $payload.ordered_stream_paths[0].path }
            $stderrPath = if ($null -eq $payload) { $null } else { $payload.ordered_stream_paths[1].path }
            $diagnosticPrimary = if ($null -ne $payload) { [string]$payload.primary_error } else { $fixtureFailureSummary }
            $null = Write-D32Phase0BlockedDiagnostic -PrimaryError $diagnosticPrimary -SecondaryErrors @($diagnosticSecondary.ToArray()) -Command $command -ProcessIdentity $processIdentity -RawV2Trace $rawTrace -NativeCleanup $nativeCleanup -StdoutPath $stdoutPath -StderrPath $stderrPath
        }
        catch { $fixtureFailureSummary += '; blocked diagnostic capture error=' + $_.Exception.Message }
        throw $fixtureFailureSummary
    }
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
    $fixtureProvenanceEvidence = Test-D32Phase0FixtureBuildProvenance `
        -SidecarPath $fixtureProvenancePath -ManifestPath $fixtureManifestPath -Repository $repo -OutputRoot $output `
        -ExpectedCandidateSha $ExpectedSha -ExpectedRunnerProcessId $PID -ValidatedProfile $profile `
        -VendoredAuthorityPath $VendoredProtocAuthorityPath -ExpectedVendoredAuthoritySha256 $ExpectedVendoredProtocAuthoritySha256 `
        -TauriMacrosSourceAuthorityPath $TauriMacrosSourceAuthorityPath -ExpectedTauriMacrosSourceAuthoritySha256 $ExpectedTauriMacrosSourceAuthoritySha256
    $fixtureEnvironment = $fixtureProvenanceEvidence.Document.environment
    $cargoHome = [string]$fixtureEnvironment.cargo_home
    $tempRoot = [string]$fixtureEnvironment.temp_root
    $runId = [string]$fixtureEnvironment.run_id
    if ([String]::IsNullOrWhiteSpace($runId) -or -not (Test-D32ProfilePathWithin -Child $cargoHome -Parent $output) -or -not (Test-D32ProfilePathWithin -Child $tempRoot -Parent $output)) { throw 'PHASE0_CARGO_HOME_BLOCKED: fixture Cargo home/temp are not bound beneath the external evidence root' }
    $h7cOwnerBinding = Test-D32Phase0OwnerBinding -EvidenceRoot $output -ExpectedCandidateSha $ExpectedSha -ValidatedProfile $profile -ExpectedRunId $runId -ExpectedRootIdentity $outputBinding.RootIdentity -ExpectedMarkerReference $outputBinding.OwnerMarker
    $h7cRunGrantCreated = New-D32H7CGitRunGrant -Authority $h7cAuthority -Repository $repo -CandidateSha $ExpectedSha -ValidatedProfile $profile `
        -EvidenceRoot $output -TempRoot $tempRoot -RunId $runId -OwnerMarker $h7cOwnerBinding.MarkerReference -GitImage $gitImage
    $h7cRunGrant = Test-D32H7CGitRunGrant -Reference $h7cRunGrantCreated.Reference -Authority $h7cAuthority -Repository $repo -CandidateSha $ExpectedSha `
        -ValidatedProfile $profile -EvidenceRoot $output -TempRoot $tempRoot -RunId $runId -OwnerMarker $h7cOwnerBinding.MarkerReference -GitImage $gitImage
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
    if ($childEnvironment.Contains('PROTOC')) { throw 'VENDORED_PROTOC_ENV_BLOCKED: base Phase0 environment must not contain ambient PROTOC' }
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
        VendoredProtocRunGrant = $fixtureProvenanceEvidence.VendoredGrant
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
    $h7cAttestation = $null
    foreach ($package in @('protocol', 'vita', 'host')) {
        if ($package -eq 'vita') {
            $suite = Invoke-D32Phase0LoggedCommand @commandArgs -Name "$package-full-local-suite" -Executable $cargo -Arguments (Get-D32Phase0TestCommand -Package $package -Kind suite) `
                -H7CGitAuthority $h7cAuthority -H7CGitRunGrant $h7cRunGrant
            $h7cAttestationCreated = New-D32H7CGitChildAttestation -Authority $h7cAuthority -RunGrant $h7cRunGrant -OwnerBinding $h7cOwnerBinding `
                -Phase0Command $suite -SuiteLines @(Get-D32Phase0TextFromLogs -CommandRecord $suite) -GitChildren @($script:D32Phase0ObservedH7CGitChildren) `
                -Repository $repo -CandidateSha $ExpectedSha -ValidatedProfile $profile -EvidenceRoot $output -TempRoot $tempRoot -GitImage $gitImage
            $h7cAttestation = Test-D32H7CGitChildAttestation -Reference $h7cAttestationCreated.Reference -Authority $h7cAuthority -RunGrant $h7cRunGrant `
                -OwnerBinding $h7cOwnerBinding -Phase0Command $suite -Repository $repo -CandidateSha $ExpectedSha -ValidatedProfile $profile `
                -EvidenceRoot $output -TempRoot $tempRoot -GitImage $gitImage
        } else {
            $suite = Invoke-D32Phase0LoggedCommand @commandArgs -Name "$package-full-local-suite" -Executable $cargo -Arguments (Get-D32Phase0TestCommand -Package $package -Kind suite)
        }
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
        evidence_root_identity = [ordered]@{
            path = [string]$outputBinding.RootIdentity.Path
            volume_serial_hex = [string]$outputBinding.RootIdentity.VolumeSerialHex
            file_id_hex = [string]$outputBinding.RootIdentity.FileIdHex
        }
        owner_marker = $outputBinding.OwnerMarker
        vendored_protoc = [ordered]@{
            authority = $vendoredAuthority.Reference
            run_grant = $fixtureProvenanceEvidence.VendoredGrant.Reference
        }
        tauri_macros_source_patch = $fixtureProvenanceEvidence.TauriMacrosSourcePatchAuthority.Reference
        h7c_git_child_authority = $h7cAuthority.Reference
        h7c_git_child_attestation = if ($null -eq $h7cAttestation) { $null } else { $h7cAttestation.Reference }
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
            script_inventory = @($profile.ScriptInventory | ForEach-Object { [ordered]@{ path = $_.Path; sha256 = $_.Sha256; bytes = [Int64]$_.Bytes; volume_serial_hex = $_.VolumeSerialHex; file_id_hex = $_.FileIdHex } })
            windows_image_inventory = @($profile.WindowsImageInventory | ForEach-Object { [ordered]@{ path = $_.Path; sha256 = $_.Sha256; bytes = [Int64]$_.Bytes; volume_serial_hex = $_.VolumeSerialHex; file_id_hex = $_.FileIdHex } })
            lock_inputs = @($profile.LockInputs | ForEach-Object { [ordered]@{ manifest_path = $_.ManifestPath; lock_sha256 = $_.LockSha256 } })
            env_policy = [string]$profile.Profile.env_policy
        }
        cargo_home = [ordered]@{
            path = $cargoHome
            temp_root = $tempRoot
            run_root = [string]$fixtureProvenanceEvidence.Document.storage.run_root.path
            run_id = $runId
            nonempty_after_fetch = (-not $cargoHomeCheck.Empty)
            run_root_identity = [ordered]@{ volume_serial_hex = [string]$fixtureProvenanceEvidence.Document.storage.run_root.volume_serial_hex; file_id_hex = [string]$fixtureProvenanceEvidence.Document.storage.run_root.file_id_hex }
            cargo_home_identity = [ordered]@{ volume_serial_hex = [string]$fixtureProvenanceEvidence.Document.storage.cargo_home.volume_serial_hex; file_id_hex = [string]$fixtureProvenanceEvidence.Document.storage.cargo_home.file_id_hex }
            temp_root_identity = [ordered]@{ volume_serial_hex = [string]$fixtureProvenanceEvidence.Document.storage.temp_root.volume_serial_hex; file_id_hex = [string]$fixtureProvenanceEvidence.Document.storage.temp_root.file_id_hex }
        }
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

function New-D32Phase0SelfTestDebugTrace {
    param(
        [Parameter(Mandatory = $true)][object]$Profile,
        [Parameter(Mandatory = $true)][int]$RunnerProcessId,
        [Parameter(Mandatory = $true)][int]$RootProcessId
    )
    $runner = [Diagnostics.Process]::GetCurrentProcess()
    try { $debuggerCreation = $runner.StartTime.ToUniversalTime().ToFileTimeUtc() }
    finally { $runner.Dispose() }
    $rootCreation = [DateTime]::UtcNow.ToFileTimeUtc()
    $debuggerAt = [DateTime]::FromFileTimeUtc($debuggerCreation).ToString('o')
    $rootAt = [DateTime]::FromFileTimeUtc($rootCreation).ToString('o')
    $started = [DateTimeOffset]::UtcNow.ToString('o')
    $completed = [DateTimeOffset]::UtcNow.AddMilliseconds(1).ToString('o')
    $cargo = $Profile.Profile.toolchain.cargo
    return [ordered]@{
        record_type = 'D32_DEBUG_JOB_PROCESS_TRACE_V2'
        schema_version = 2
        event_source = 'Win32-WaitForDebugEvent-dedicated-OS-thread'
        state = 'COMPLETED'
        block_reason = $null
        debugger_process_id = $RunnerProcessId
        uncontinued_create_process_id = 0
        uncontinued_create_continue_call_count = 0
        debugger_thread_id = $RunnerProcessId + 1
        dedicated_debugger_thread = $true
        debugger_kill_on_exit_enabled = $true
        root_resumed_after_kill_on_exit = $true
        debugger_thread_exited = $true
        debugger_thread_joined = $true
        retained_process_handle_count = 2
        retained_process_handles_signaled = $true
        debugger_association_query_verified = $true
        debugger_association_absent = $true
        debugger_creation_filetime = [Int64]$debuggerCreation
        debugger_created_at_utc = $debuggerAt
        started_at_utc = $started
        completed_at_utc = $completed
        debug_event_count = 2
        process_create_event_count = 1
        process_exit_event_count = 1
        process_event_count = 2
        thread_create_event_count = 0
        thread_exit_event_count = 0
        image_load_event_count = 0
        image_unload_event_count = 0
        exception_event_count = 0
        debug_string_event_count = 0
        wait_timeout_count = 0
        debug_api_error_count = 0
        event_chain_complete = $true
        job_accounting_verified = $true
        job_total_processes = 1
        job_active_processes = 0
        accounting_consistent = $true
        injected_interruption = $false
        process_events = @(
            [ordered]@{ sequence = 1; kind = 'CREATE'; process_id = $RootProcessId; parent_process_id = $RunnerProcessId; creation_filetime = [Int64]$rootCreation; parent_creation_filetime = [Int64]$debuggerCreation; exit_code = 0 },
            [ordered]@{ sequence = 2; kind = 'EXIT'; process_id = $RootProcessId; parent_process_id = $RunnerProcessId; creation_filetime = [Int64]$rootCreation; parent_creation_filetime = [Int64]$debuggerCreation; exit_code = 0 }
        )
        processes = @([ordered]@{
            process_id = $RootProcessId
            parent_process_id = $RunnerProcessId
            creation_filetime = [Int64]$rootCreation
            parent_creation_filetime = [Int64]$debuggerCreation
            image_path = [string]$cargo.path
            bytes = [Int64]$cargo.bytes
            sha256 = [string]$cargo.sha256
            volume_serial_hex = [string]$cargo.volume_serial_hex
            file_id_hex = [string]$cargo.file_id_hex
            allowed_image_reason = 'exact-caller-pinned-fixed-root-image'
            image_verified = $true
            exited = $true
            exit_code = 0
            create_sequence = 1
            exit_sequence = 2
            created_at_utc = $rootAt
            exited_at_utc = $rootAt
        })
    }
}

function Test-D32Phase0MatrixRecordSelfTest {
    $cases = [System.Collections.Generic.List[object]]::new()
    $add = { param([string]$Name, [bool]$Passed, [AllowNull()][string]$Detail = $null) $cases.Add([PSCustomObject]@{ name = $Name; passed = $Passed; detail = $Detail }) }.GetNewClosure()

    $timeoutContractFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($timeoutContract in @(
        [PSCustomObject]@{ Path = $script:D32Phase0ScriptPath; Name = 'Phase0TimeoutSeconds'; Minimum = 60; Maximum = 14400; Default = 1800 },
        [PSCustomObject]@{ Path = (Join-Path $script:D32Phase0ScriptRoot 'd32-fixture-prebuild.ps1'); Name = 'TimeoutSeconds'; Minimum = 1; Maximum = 14400; Default = 600 }
    )) {
        $tokens = $null
        $parseErrors = $null
        $timeoutAst = [System.Management.Automation.Language.Parser]::ParseFile(
            [IO.Path]::GetFullPath([string]$timeoutContract.Path), [ref]$tokens, [ref]$parseErrors)
        $parameters = @($timeoutAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -ceq [string]$timeoutContract.Name })
        if ($parseErrors.Count -ne 0 -or $parameters.Count -ne 1) {
            $timeoutContractFailures.Add("$($timeoutContract.Name):parse-or-parameter")
            continue
        }
        $rangeAttributes = @($parameters[0].Attributes | Where-Object { $_.TypeName.FullName -ceq 'ValidateRange' })
        if ($rangeAttributes.Count -ne 1 -or $rangeAttributes[0].PositionalArguments.Count -ne 2) {
            $timeoutContractFailures.Add("$($timeoutContract.Name):range-attribute")
            continue
        }
        $minimum = [int]$rangeAttributes[0].PositionalArguments[0].Value
        $maximum = [int]$rangeAttributes[0].PositionalArguments[1].Value
        $defaultValue = [int]$parameters[0].DefaultValue.Value
        if ($minimum -ne [int]$timeoutContract.Minimum -or $maximum -ne [int]$timeoutContract.Maximum -or $defaultValue -ne [int]$timeoutContract.Default) {
            $timeoutContractFailures.Add("$($timeoutContract.Name):expected=$($timeoutContract.Minimum),$($timeoutContract.Maximum),$($timeoutContract.Default);actual=$minimum,$maximum,$defaultValue")
        }
    }
    $phase0SourceText = [IO.File]::ReadAllText($script:D32Phase0ScriptPath)
    $timeoutForwardingValid = $phase0SourceText -match 'TimeoutSeconds\s*=\s*\$TimeoutSeconds' -and
        $phase0SourceText -notmatch 'TimeoutSeconds\s*=\s*\[Math\]::Min\s*\(\s*\$TimeoutSeconds\s*,\s*3600\s*\)'
    if (-not $timeoutForwardingValid) { $timeoutContractFailures.Add('Phase0TimeoutSeconds:unclamped-forwarding') }
    & $add 'Phase0 and fixture timeouts retain defaults and enforce the 14400-second Phase0 ceiling' `
        ($timeoutContractFailures.Count -eq 0) ($timeoutContractFailures -join ', ')

    $preflightLibraryPath = Join-Path $script:D32Phase0ScriptRoot 'd32-preflight.ps1'
    $preflightDependencyFailures = @(Get-D32Phase0PreflightDependencyFailures -PreflightLibraryPath $preflightLibraryPath)
    & $add 'Phase0 imports the exact preflight helper library in runner scope' ($preflightDependencyFailures.Count -eq 0) ($preflightDependencyFailures -join ', ')

    $governanceFindings = New-D32FindingList
    Test-D32Governance -Repository (Split-Path -Parent $script:D32Phase0ScriptRoot) -Findings $governanceFindings
    $governanceErrors = @($governanceFindings | Where-Object { $_.Severity -eq 'ERROR' })
    $governanceErrorChecks = @($governanceErrors | ForEach-Object { [string]$_.Check })
    & $add 'direct-runner governance dependency executes read-only and validates the candidate inputs' ($governanceErrors.Count -eq 0) ($governanceErrorChecks -join ', ')

    function Invoke-D32Phase0EmptyRecordAccumulatorProbe {
        function Invoke-D32Phase0PinnedProcess {
            param(
                [string]$Name,
                [string]$Executable,
                [string[]]$Arguments,
                [string]$WorkingDirectory,
                [string]$LogPath,
                [System.Collections.IDictionary]$Environment,
                [int]$TimeoutSeconds,
                [object]$ValidatedProfile,
                [string]$Repository,
                [string]$ExpectedCandidateSha,
                [string]$GitPath,
                [string]$GitSha256
            )
            return [PSCustomObject]@{ name = $Name; command_line = ($Arguments -join ' '); log_path = $LogPath }
        }

        $records = [System.Collections.Generic.List[object]]::new()
        $ordinal = 0
        $result = Invoke-D32Phase0LoggedCommand `
            -Name 'empty-record-accumulator-selftest' `
            -Executable 'C:\d32-selftest\cargo.exe' `
            -Arguments @('test') `
            -Ordinal ([ref]$ordinal) `
            -Records $records `
            -LogRoot 'C:\d32-selftest\logs' `
            -Repository 'C:\d32-selftest\repo' `
            -ValidatedProfile ([PSCustomObject]@{}) `
            -Environment @{ CARGO_HOME = 'C:\d32-selftest\cargo-home' } `
            -TimeoutSeconds 60 `
            -ExpectedCandidateSha ('a' * 40) `
            -GitPath 'C:\d32-selftest\git.exe' `
            -GitSha256 ('b' * 64)
        return [PSCustomObject]@{ Result = $result; Count = $records.Count; Ordinal = $ordinal; StoredName = if ($records.Count -eq 1) { $records[0].name } else { $null } }
    }

    $emptyRecordProbe = Invoke-D32Phase0EmptyRecordAccumulatorProbe
    & $add 'Phase0 logged-command helper enters with an empty accumulator and records the bounded result' `
        ($emptyRecordProbe.Count -eq 1 -and $emptyRecordProbe.Ordinal -eq 1 -and
            $emptyRecordProbe.StoredName -ceq 'empty-record-accumulator-selftest' -and
            $emptyRecordProbe.Result.name -ceq 'empty-record-accumulator-selftest')

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
    $emptyInventoryRejected = $false
    try { $null = Test-D32Phase0FixedInventory -Inventories @{} }
    catch { $emptyInventoryRejected = $_.Exception.Message -like 'PHASE0_INVENTORY_BLOCKED: missing package inventory*' }
    & $add 'empty package inventory reaches the validator and fails closed' $emptyInventoryRejected

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
    $emptyTestListOutputRejected = $false
    try { $null = Get-D32Phase0ListedTests -Lines @() }
    catch { $emptyTestListOutputRejected = $_.Exception.Message -ceq 'PHASE0_TEST_OUTPUT_BLOCKED: captured Cargo test-list output is empty' }
    & $add 'empty Cargo test-list output is explicit blocked evidence' $emptyTestListOutputRejected
    $emptyIgnoredListOutputRejected = $false
    try { $null = Get-D32Phase0IgnoredTests -Lines @() }
    catch { $emptyIgnoredListOutputRejected = $_.Exception.Message -ceq 'PHASE0_TEST_OUTPUT_BLOCKED: captured Cargo test-list output is empty' }
    & $add 'empty Cargo ignored-list output is explicit blocked evidence' $emptyIgnoredListOutputRejected
    & $add 'zero expected ignored tests require a nonempty captured Cargo list transcript' `
        (Test-D32Phase0ExactTestListOutput -Lines @('0 tests, 0 benchmarks') -Expected @() -Ignored)
    & $add 'empty captured Cargo list transcript never matches even an empty expected inventory' `
        (-not (Test-D32Phase0ExactTestListOutput -Lines @() -Expected @() -Ignored))

    $candidate = ('a' * 40) -join ''
    $gitStateLines = [System.Collections.Generic.List[string]]::new()
    for ($phase = 1; $phase -le 5; $phase++) {
        $gitStateLines.Add("D32_FIXTURE_GIT_STATE phase=$phase edge=before head=$candidate clean=true")
        $gitStateLines.Add("D32_FIXTURE_GIT_STATE phase=$phase edge=after head=$candidate clean=true")
    }
    try { $validGitStates = @(Get-D32Phase0FixtureGitStates -Lines @($gitStateLines.ToArray()) -ExpectedCandidateSha $candidate); & $add 'five fixture phases require exact pre/post candidate and clean evidence' ($validGitStates.Count -eq 10) }
    catch { & $add 'five fixture phases require exact pre/post candidate and clean evidence' $false }
    try {
        $partialGitStates = @(Get-D32Phase0FixtureGitStates -Lines @($gitStateLines.ToArray() | Select-Object -First 2) -ExpectedCandidateSha $candidate -AllowPartial)
        & $add 'failed fixture Git-state capture accepts only a valid ordered clean-candidate prefix' ($partialGitStates.Count -eq 2 -and $partialGitStates[0].phase -eq 1 -and $partialGitStates[0].edge -ceq 'before' -and $partialGitStates[1].edge -ceq 'after')
        $prefixEvidence = New-D32Phase0FixtureGitStatePrefixEvidence -States $partialGitStates
        $prefixPayload = ConvertFrom-D32Phase0Json ($prefixEvidence.Substring('PHASE0_FIXTURE_GIT_STATE_PREFIX_V1:'.Length))
        & $add 'blocked diagnostic can preserve the exact validated Git-state prefix without claiming later markers' `
            ($prefixEvidence.StartsWith('PHASE0_FIXTURE_GIT_STATE_PREFIX_V1:', [StringComparison]::Ordinal) -and
                $prefixPayload.Count -eq 2 -and $prefixPayload[0].phase -eq 1 -and $prefixPayload[0].edge -ceq 'before' -and
                $prefixPayload[1].phase -eq 1 -and $prefixPayload[1].edge -ceq 'after' -and
                @($prefixPayload | Where-Object { $_.clean -ne $true -or $_.head -cne $candidate }).Count -eq 0)
    }
    catch {
        & $add 'failed fixture Git-state capture accepts only a valid ordered clean-candidate prefix' $false $_.Exception.Message
        & $add 'blocked diagnostic can preserve the exact validated Git-state prefix without claiming later markers' $false $_.Exception.Message
    }
    $reorderedPartialGitState = @($gitStateLines.ToArray() | Select-Object -First 2)
    $reorderedPartialGitState[0], $reorderedPartialGitState[1] = $reorderedPartialGitState[1], $reorderedPartialGitState[0]
    $reorderedPartialRejected = $false
    try { $null = Get-D32Phase0FixtureGitStates -Lines $reorderedPartialGitState -ExpectedCandidateSha $candidate -AllowPartial }
    catch { $reorderedPartialRejected = $_.Exception.Message -like '*partial per-phase Git-state markers are not an ordered prefix*' }
    & $add 'failed fixture Git-state capture rejects reordered partial markers' $reorderedPartialRejected
    $malformedPartialRejected = $false
    try { $null = Get-D32Phase0FixtureGitStates -Lines @('D32_FIXTURE_GIT_STATE phase=1 edge=before malformed') -ExpectedCandidateSha $candidate -AllowPartial }
    catch { $malformedPartialRejected = $_.Exception.Message -like '*malformed per-phase Git-state marker*' }
    & $add 'fixture Git-state parser rejects malformed marker-shaped lines' $malformedPartialRejected

    $capturedDiagnosticPayloadLine = 'D32_PHASE0_BLOCKED_DIAGNOSTIC_PAYLOAD_V1:structured-selftest-payload'
    $fixtureProducerProbe = {
        Write-Host "D32_FIXTURE_GIT_STATE phase=1 edge=before head=$candidate clean=true"
        Write-Output $capturedDiagnosticPayloadLine
        throw 'SELFTEST_TERMINATING_FIXTURE_PRODUCER'
    }.GetNewClosure()
    $fixtureCaptureProbe = Invoke-D32Phase0FixtureProducerCapture -Producer $fixtureProducerProbe
    & $add 'producer capture preserves Git marker and structured diagnostic emitted before a terminating failure' `
        ($fixtureCaptureProbe.Failure -ceq 'SELFTEST_TERMINATING_FIXTURE_PRODUCER' -and
            @($fixtureCaptureProbe.Lines | Where-Object { $_ -ceq "D32_FIXTURE_GIT_STATE phase=1 edge=before head=$candidate clean=true" }).Count -eq 1 -and
            @($fixtureCaptureProbe.Lines | Where-Object { $_ -ceq $capturedDiagnosticPayloadLine }).Count -eq 1)

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
    $emptyFixtureLogInventoryRejected = $false
    try { $null = Get-D32Phase0FixtureLogPaths -OutputRoot $fakeOutputRoot -FixtureRecords @() -LockInputs $fakeLockInputs }
    catch { $emptyFixtureLogInventoryRejected = $_.Exception.Message -like 'PHASE0_LOG_BLOCKED: fixture log inventory must contain exactly the five*' }
    & $add 'empty fixture log inventory reaches the exact-five validator and fails closed' $emptyFixtureLogInventoryRejected
    $emptyFetchLogInventoryRejected = $false
    try { $null = Get-D32Phase0FixtureLogPaths -OutputRoot $fakeOutputRoot -FixtureRecords $fakeFixtureRecords -LockInputs @() }
    catch { $emptyFetchLogInventoryRejected = $_.Exception.Message -like 'PHASE0_LOG_BLOCKED: fixture log inventory must contain exactly three*' }
    & $add 'empty fetch log inventory reaches the exact-three validator and fails closed' $emptyFetchLogInventoryRejected
    $wrongFixtureLogRecords = @($fakeFixtureRecords)
    $wrongFixtureLogRecords[0] = [PSCustomObject]@{ name = $fakeFixtureNames[0]; phase_log = $fakeFixtureRecords[0].phase_log; stdout_log = $fakeFixtureRecords[1].stdout_log; stderr_log = $fakeFixtureRecords[0].stderr_log }
    $wrongFixtureLogsRejected = $false
    try { $null = Get-D32Phase0FixtureLogPaths -OutputRoot $fakeOutputRoot -FixtureRecords $wrongFixtureLogRecords -LockInputs $fakeLockInputs }
    catch { $wrongFixtureLogsRejected = $_.Exception.Message -like '*fixed fixture log paths differ*' }
    & $add 'fixture log inventory rejects duplicate or swapped fixture output paths' $wrongFixtureLogsRejected
    $missingGitState = @($gitStateLines.ToArray() | Select-Object -SkipLast 1)
    try { $null = Get-D32Phase0FixtureGitStates -Lines $missingGitState -ExpectedCandidateSha $candidate; & $add 'missing fixture per-phase Git state is rejected' $false }
    catch { & $add 'missing fixture per-phase Git state is rejected' ($_.Exception.Message -match 'expected 10') }
    $emptyGitStatesRejected = $false
    try { $null = Get-D32Phase0FixtureGitStates -Lines @() -ExpectedCandidateSha $candidate }
    catch { $emptyGitStatesRejected = $_.Exception.Message -ceq 'PHASE0_FIXTURE_STATE_BLOCKED: expected 10 per-phase Git-state lines, observed 0' }
    & $add 'empty fixture Git-state input reaches the exact-ten validator and fails closed' $emptyGitStatesRejected
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

    $originalFixtureFailure = 'GIT_PROCESS_IDENTITY_UNVERIFIED: retained Git process handle had no complete identity record'
    $secondaryFixtureStateFailure = 'PHASE0_FIXTURE_STATE_BLOCKED: expected 10 per-phase Git-state lines, observed 0'
    $prioritizedFailure = Get-D32Phase0FixtureFailureSummary `
        -FixtureFailure $originalFixtureFailure `
        -GitStateFailure $secondaryFixtureStateFailure `
        -TranscriptFailure $null
    & $add 'original fixture exception is primary and missing Git-state markers remain secondary' `
        ($prioritizedFailure.StartsWith("PHASE0_FIXTURE_BLOCKED: $originalFixtureFailure", [StringComparison]::Ordinal) -and
            $prioritizedFailure.Contains("secondary Git-state validation failure: $secondaryFixtureStateFailure"))

    $transcriptRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $transcriptPath = Join-Path $transcriptRoot ('d32-phase0-fixture-failure-selftest-' + [Guid]::NewGuid().ToString('N') + '.log')
    $transcriptDiagnostic = 'secondary Git-state marker check failed after the captured producer exception'
    $expectedPrimaryTranscript = "fixture producer output captured before marker parsing`r`nD32_PHASE0_FIXTURE_PRIMARY_EXCEPTION_BEGIN`r`n$originalFixtureFailure`r`nD32_PHASE0_FIXTURE_PRIMARY_EXCEPTION_END`r`n"
    $expectedTranscript = $expectedPrimaryTranscript + "D32_PHASE0_FIXTURE_SECONDARY_DIAGNOSTIC_BEGIN`r`n$transcriptDiagnostic`r`nD32_PHASE0_FIXTURE_SECONDARY_DIAGNOSTIC_END`r`n"
    try {
        $null = Write-D32Phase0FixtureTranscript -Path $transcriptPath -OutputRoot $transcriptRoot `
            -FixtureText 'fixture producer output captured before marker parsing' -PrimaryFailure $originalFixtureFailure
        $null = Add-D32Phase0FixtureTranscriptDiagnostic -Path $transcriptPath -OutputRoot $transcriptRoot -Message $transcriptDiagnostic
        $actualTranscript = [IO.File]::ReadAllText($transcriptPath)
        & $add 'failure transcript preserves the exact original exception before secondary marker diagnostics' ($actualTranscript -ceq $expectedTranscript)
    }
    catch { & $add 'failure transcript preserves the exact original exception before secondary marker diagnostics' $false $_.Exception.Message }
    finally {
        if (Test-Path -LiteralPath $transcriptPath -PathType Leaf) {
            try {
                $exactTestFile = (Test-D32ProfileCanonicalPathString -Path $transcriptPath) -and
                    (Test-D32ProfileNoReparsePath -Path $transcriptPath) -and
                    [IO.File]::ReadAllText($transcriptPath) -in @($expectedPrimaryTranscript, $expectedTranscript)
                if ($exactTestFile) { Remove-Item -LiteralPath $transcriptPath -Force -ErrorAction Stop }
            }
            catch { }
        }
    }

    $goodShape = [PSCustomObject][ordered]@{ name = 'cargo.exe'; path = 'C:\\pinned\\cargo.exe' }
    & $add 'strict phase0 object schema accepts exact shape' (Test-D32Phase0ExactProperties -Object $goodShape -Expected @('name', 'path'))
    & $add 'strict phase0 object schema rejects missing field' (-not (Test-D32Phase0ExactProperties -Object ([PSCustomObject]@{ name = 'cargo.exe' }) -Expected @('name', 'path')))
    & $add 'strict phase0 object schema rejects extra field' (-not (Test-D32Phase0ExactProperties -Object ([PSCustomObject][ordered]@{ name = 'cargo.exe'; path = 'C:\\pinned\\cargo.exe'; extra = $true }) -Expected @('name', 'path')))
    & $add 'strict phase0 integers reject string coercion' (-not (Test-D32Phase0Integer -Value '1' -Positive))
    & $add 'Phase0 JSON parser detects duplicate keys recursively' (Test-D32Phase0JsonDuplicateKeys -Json '{"outer":{"name":1,"name":2}}')
    & $add 'Phase0 JSON parser rejects malformed JSON before schema parsing' (Test-D32Phase0JsonDuplicateKeys -Json '{"name":')
    & $add 'Phase0 JSON parser accepts exact nested JSON' (-not (Test-D32Phase0JsonDuplicateKeys -Json '{"outer":{"name":1},"items":[true,4]}'))
    $minimalProfile = [PSCustomObject]@{ ExecutableInventory = @(); WindowsImageInventory = @() }
    $deniedProcessImages = @(
        'C:\\unapproved\\git.exe', 'C:\\unapproved\\git-remote-https.exe', 'C:\\unapproved\\git-credential-manager.exe',
        'C:\\unapproved\\ssh-add.exe', 'C:\\unapproved\\plink.exe', 'C:\\unapproved\\bash.exe', 'C:\\unapproved\\pwsh-preview.exe',
        'C:\\unapproved\\command.com', 'C:\\unapproved\\nested-script.cmd'
    )
    $deniedProcessImagesBlocked = @($deniedProcessImages | Where-Object { -not [String]::IsNullOrWhiteSpace((Get-D32Phase0AllowedChildImageReason -ImagePath $_ -ValidatedProfile $minimalProfile -Repository 'C:\\candidate' -ExpectedRootPath 'C:\\pinned\\cargo.exe')) }).Count -eq 0
    & $add 'command processors, shells, Git remotes, SSH clients, and credential helpers are blocked' $deniedProcessImagesBlocked
    & $add 'candidate debug target process images require explicit candidate-owned classification' ((Get-D32Phase0AllowedChildImageReason -ImagePath 'C:\\candidate\\vita-agent\\target\\debug\\build-script.exe' -ValidatedProfile $minimalProfile -Repository 'C:\\candidate' -ExpectedRootPath 'C:\\pinned\\cargo.exe') -ceq 'candidate-owned-target-image-observed-by-opened-handle')
    & $add 'candidate release build-script images are covered by captured opened-handle identity' ((Get-D32Phase0AllowedChildImageReason -ImagePath 'C:\\candidate\\src-tauri\\target\\release\\build\\script.exe' -ValidatedProfile $minimalProfile -Repository 'C:\\candidate' -ExpectedRootPath 'C:\\pinned\\cargo.exe') -ceq 'candidate-owned-target-image-observed-by-opened-handle')

    $approvedVctipRecord = [PSCustomObject]@{
        Path = 'E:\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\vctip.exe'
        Bytes = [Int64]335328
        Sha256 = 'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996'
        VolumeSerialHex = '749614a1961465c0'
        FileIdHex = '0b5d2000000001000000000000000000'
    }
    $cargoRootPath = 'C:\\pinned\\cargo.exe'
    $vctipProfile = [PSCustomObject]@{
        Profile = [PSCustomObject]@{ toolchain = [PSCustomObject]@{ cargo = [PSCustomObject]@{ path = $cargoRootPath } } }
        ExecutableInventory = @($approvedVctipRecord)
        WindowsImageInventory = @()
    }
    $vctipOpenedIdentity = [PSCustomObject]@{
        Path = $approvedVctipRecord.Path; Bytes = $approvedVctipRecord.Bytes; Sha256 = $approvedVctipRecord.Sha256
        VolumeSerialHex = $approvedVctipRecord.VolumeSerialHex; FileIdHex = $approvedVctipRecord.FileIdHex
    }
    $exactVctipAdmission = Get-D32Phase0AllowedChildImageReason -ImagePath $approvedVctipRecord.Path -ValidatedProfile $vctipProfile -Repository 'C:\\candidate' -ExpectedRootPath $cargoRootPath -ImageIdentity $vctipOpenedIdentity
    & $add 'exact Profile V2 VCTIP path and opened-handle identity are allowed only below the caller-pinned Cargo root' `
        ($exactVctipAdmission -ceq 'caller-pinned-msvc-vctip-descendant-of-fixed-cargo-root')
    & $add 'VCTIP is blocked below a non-Cargo root or a different profile Cargo path' `
        ((Get-D32Phase0AllowedChildImageReason -ImagePath $approvedVctipRecord.Path -ValidatedProfile $vctipProfile -Repository 'C:\\candidate' -ExpectedRootPath 'C:\\other\\cargo.exe' -ImageIdentity $vctipOpenedIdentity) -eq $null -and
            (Get-D32Phase0AllowedChildImageReason -ImagePath $approvedVctipRecord.Path -ValidatedProfile ([PSCustomObject]@{ Profile = [PSCustomObject]@{ toolchain = [PSCustomObject]@{ cargo = [PSCustomObject]@{ path = 'C:\\other\\cargo.exe' } } }; ExecutableInventory = @($approvedVctipRecord); WindowsImageInventory = @() }) -Repository 'C:\\candidate' -ExpectedRootPath $cargoRootPath -ImageIdentity $vctipOpenedIdentity) -eq $null)
    $vctipHandleDriftRejected = $false
    foreach ($mutation in @(
        [PSCustomObject]@{ Field = 'Bytes'; Value = [Int64]335329 },
        [PSCustomObject]@{ Field = 'Sha256'; Value = ('0' * 64) },
        [PSCustomObject]@{ Field = 'VolumeSerialHex'; Value = '749614a1961465c1' },
        [PSCustomObject]@{ Field = 'FileIdHex'; Value = '0b5d2000000001000000000000000001' }
    )) {
        $driftedIdentity = [PSCustomObject]@{
            Path = $approvedVctipRecord.Path; Bytes = $approvedVctipRecord.Bytes; Sha256 = $approvedVctipRecord.Sha256
            VolumeSerialHex = $approvedVctipRecord.VolumeSerialHex; FileIdHex = $approvedVctipRecord.FileIdHex
        }
        $driftedIdentity.($mutation.Field) = $mutation.Value
        if ($null -ne (Get-D32Phase0AllowedChildImageReason -ImagePath $approvedVctipRecord.Path -ValidatedProfile $vctipProfile -Repository 'C:\\candidate' -ExpectedRootPath $cargoRootPath -ImageIdentity $driftedIdentity)) { $vctipHandleDriftRejected = $false; break }
        $vctipHandleDriftRejected = $true
    }
    & $add 'VCTIP opened-handle bytes, hash, volume, and file-ID drift fail closed' $vctipHandleDriftRejected
    $renamedVctipIdentity = [PSCustomObject]@{
        Path = 'E:\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\vctip-copy.exe'
        Bytes = $approvedVctipRecord.Bytes; Sha256 = $approvedVctipRecord.Sha256
        VolumeSerialHex = $approvedVctipRecord.VolumeSerialHex; FileIdHex = '0b5d2000000001000000000000000001'
    }
    & $add 'copied or renamed VCTIP content cannot inherit ordinary pinned-image or candidate-target admission' `
        ((Get-D32Phase0AllowedChildImageReason -ImagePath $renamedVctipIdentity.Path -ValidatedProfile $vctipProfile -Repository 'C:\\candidate' -ExpectedRootPath $cargoRootPath -ImageIdentity $renamedVctipIdentity) -eq $null)
    $duplicateVctipProfile = [PSCustomObject]@{
        Profile = $vctipProfile.Profile
        ExecutableInventory = @($approvedVctipRecord, $renamedVctipIdentity)
        WindowsImageInventory = @()
    }
    $duplicateVctipProfileRejected = $false
    try { $null = Get-D32ProfileExactVctipImageRecord -ValidatedProfile $duplicateVctipProfile }
    catch { $duplicateVctipProfileRejected = $_.Exception.Message -like '*D32_VCTIP_PROFILE_PIN_BLOCKED*' }
    & $add 'Profile V2 rejects duplicate/copied VCTIP content under a renamed inventory path' $duplicateVctipProfileRejected

    $protocExpectedCargoHome = 'C:\\phase0-protoc-selftest\\r\\c'
    $protocExpectedImagePath = Join-Path $protocExpectedCargoHome 'registry\src\index.crates.io-1949cf8c6b5b557f\protoc-bin-vendored-win32-3.2.0\bin\protoc.exe'
    $protocExpectedIdentity = [PSCustomObject]@{
        Path = $protocExpectedImagePath; Bytes = [Int64]11934496
        Sha256 = 'cbd1ca1fd6afd1bb6ddd1c09c118ecd4c50f928980857f16fe6fc23704ea17e2'
        VolumeSerialHex = '0123456789abcdef'; FileIdHex = '0123456789abcdef0123456789abcdef'
    }
    $protocExpectedGrant = [PSCustomObject]@{
        Image = $protocExpectedIdentity
        Document = [PSCustomObject]@{ cargo_home = [PSCustomObject]@{ path = $protocExpectedCargoHome } }
    }
    $protocAllowedProfile = [PSCustomObject]@{
        Profile = [PSCustomObject]@{ toolchain = [PSCustomObject]@{ cargo = [PSCustomObject]@{ path = $cargoRootPath } } }
        ExecutableInventory = @(); WindowsImageInventory = @()
    }
    $exactProtocAdmission = Get-D32Phase0AllowedChildImageReason -ImagePath $protocExpectedImagePath -ValidatedProfile $protocAllowedProfile `
        -Repository 'C:\\candidate' -ExpectedRootPath $cargoRootPath -ImageIdentity $protocExpectedIdentity -VendoredProtocGrant $protocExpectedGrant
    & $add 'locked protoc is classified only by the exact per-run CargoHome grant and complete opened identity' `
        ($exactProtocAdmission -ceq 'caller-pinned-locked-vendored-protoc-descendant-of-fixed-cargo-root')
    $protocPriorHomeImagePath = Join-Path 'C:\\old-cargo-home' 'registry\src\index.crates.io-1949cf8c6b5b557f\protoc-bin-vendored-win32-3.2.0\bin\protoc.exe'
    $protocPriorHomeAdmission = Get-D32Phase0AllowedChildImageReason -ImagePath $protocPriorHomeImagePath -ValidatedProfile $protocAllowedProfile `
        -Repository 'C:\\candidate' -ExpectedRootPath $cargoRootPath -ImageIdentity $protocExpectedIdentity -VendoredProtocGrant $protocExpectedGrant
    $protocUnapprovedCases = [ordered]@{
        missing_grant = Get-D32Phase0AllowedChildImageReason -ImagePath $protocExpectedImagePath -ValidatedProfile $protocAllowedProfile -Repository 'C:\\candidate' -ExpectedRootPath $cargoRootPath -ImageIdentity $protocExpectedIdentity
        wrong_root = Get-D32Phase0AllowedChildImageReason -ImagePath $protocExpectedImagePath -ValidatedProfile $protocAllowedProfile -Repository 'C:\\candidate' -ExpectedRootPath 'C:\\other\\cargo.exe' -ImageIdentity $protocExpectedIdentity -VendoredProtocGrant $protocExpectedGrant
        renamed_alias = Get-D32Phase0AllowedChildImageReason -ImagePath $protocExpectedImagePath.Replace('protoc.exe', 'protoc-copy.exe') -ValidatedProfile $protocAllowedProfile -Repository 'C:\\candidate' -ExpectedRootPath $cargoRootPath -ImageIdentity $protocExpectedIdentity -VendoredProtocGrant $protocExpectedGrant
        prior_home = $protocPriorHomeAdmission
    }
    $protocIdentityDriftBlocked = $true
    foreach ($mutation in @(
        [PSCustomObject]@{ Field = 'Bytes'; Value = [Int64]11934497 },
        [PSCustomObject]@{ Field = 'Sha256'; Value = ('0' * 64) },
        [PSCustomObject]@{ Field = 'VolumeSerialHex'; Value = '0123456789abcdee' },
        [PSCustomObject]@{ Field = 'FileIdHex'; Value = '0123456789abcdef0123456789abcdee' }
    )) {
        $driftedProtocIdentity = [PSCustomObject]@{
            Path = $protocExpectedIdentity.Path; Bytes = $protocExpectedIdentity.Bytes; Sha256 = $protocExpectedIdentity.Sha256
            VolumeSerialHex = $protocExpectedIdentity.VolumeSerialHex; FileIdHex = $protocExpectedIdentity.FileIdHex
        }
        $driftedProtocIdentity.($mutation.Field) = $mutation.Value
        if ($null -ne (Get-D32Phase0AllowedChildImageReason -ImagePath $protocExpectedImagePath -ValidatedProfile $protocAllowedProfile `
            -Repository 'C:\\candidate' -ExpectedRootPath $cargoRootPath -ImageIdentity $driftedProtocIdentity -VendoredProtocGrant $protocExpectedGrant)) {
            $protocIdentityDriftBlocked = $false
            break
        }
    }
    $protocUnapprovedFailures = @($protocUnapprovedCases.GetEnumerator() | Where-Object { $null -ne $_.Value } | ForEach-Object { '{0}={1}' -f $_.Key,$_.Value })
    & $add 'protoc prior-home, missing grant, wrong Cargo root, alias, and opened identity drift are blocked' `
        ($protocUnapprovedFailures.Count -eq 0 -and $protocIdentityDriftBlocked) (($protocUnapprovedFailures -join ';') + ";prior_path=$protocPriorHomeImagePath;grant_path=$($protocExpectedGrant.Image.Path);path_equal=$(Test-D32ProfilePathEqual -Left $protocPriorHomeImagePath -Right $protocExpectedGrant.Image.Path)")

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
    $emptySummaryRecords = @(Get-D32Phase0Summaries -Lines @())
    & $add 'empty test output yields no summary records for the caller to reject' ($emptySummaryRecords.Count -eq 0)

    & $add 'fixed inventories enumerate the approved ten D31 deferrals' ($script:D32Phase0DeferredVita.Count + $script:D32Phase0DeferredHost.Count -eq 10)
    & $add 'provider and hardware cases remain explicit not-run cases' ($script:D32Phase0IgnoredVita.Count -eq 4 -and $script:D32Phase0IgnoredHost.Count -eq 3)
    & $add 'Phase0 record constants label local-only V5 evidence and pending bundle hashes' ($script:D32Phase0Type -ceq 'D32_PHASE0_MATRIX_RECORD_V5' -and $script:D32Phase0SchemaVersion -eq 5 -and $script:D32Phase0Scope -like 'local-fixture-and-test-matrix-only*' -and $script:D32Phase0BundleHashes -ceq 'PENDING')

    $tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $selfTestRoot = Join-Path $tempBase ('d32-phase0-sidecar-selftest-' + [Guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $selfTestRoot) { throw 'Phase0 sidecar self-test root unexpectedly already exists' }
    $profileSelfTestRoot = Join-Path $tempBase ('d32-phase0-profile-selftest-' + [Guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $profileSelfTestRoot) { throw 'Phase0 profile self-test root unexpectedly already exists' }
    $startupSelfTestRoot = Join-Path $tempBase ('d32-phase0-startup-selftest-' + [Guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $startupSelfTestRoot) { throw 'Phase0 startup self-test root unexpectedly already exists' }
    $startupSelfTestModuleName = 'D32Phase0StartupSelfTest_' + [Guid]::NewGuid().ToString('N')
    $startupSelfTestModule = $null
    [void][IO.Directory]::CreateDirectory($profileSelfTestRoot)
    try {
        if (-not (Test-D32ProfileNoReparsePath -Path $profileSelfTestRoot) -or -not (Test-D32ProfilePathEqual -Left ([IO.Path]::GetDirectoryName($profileSelfTestRoot)) -Right $tempBase)) { throw 'Phase0 profile self-test temp root is not a direct regular temp child' }
        $runId = '0123456789abcdef0123456789abcdef'
        $fixtureOutputRoot = $selfTestRoot
        $runRoot = Join-Path $fixtureOutputRoot 'r'
        $cargoHome = Join-Path $runRoot 'c'
        $tempRoot = Join-Path $runRoot 't'
        $testRepository = Split-Path -Parent $script:D32Phase0ScriptRoot
        $fakeProfile = $null
        $profileSelfTestCases = @(Test-D32BuildToolchainProfileSelfTest `
            -Root $profileSelfTestRoot `
            -Repository $testRepository `
            -ValidatedProfileOutput ([ref]$fakeProfile))
        $profileSelfTestFailures = @($profileSelfTestCases | Where-Object { -not $_.Passed })
        if ($profileSelfTestFailures.Count -gt 0 -or $null -eq $fakeProfile -or -not $fakeProfile.IsValid) {
            $failureNames = @($profileSelfTestFailures | ForEach-Object { $_.Name }) -join ', '
            throw "PHASE0_SELFTEST_BLOCKED: profile validator did not provide its passing validated test profile ($failureNames)"
        }
        $authorityEvidenceRoot = Join-Path $profileSelfTestRoot 'protoc-authority-fresh-root'
        $authorityPath = Join-Path $profileSelfTestRoot 'D32-VENDORED-PROTOC-AUTHORITY.json'
        $authorityDocument = New-D32VendoredProtocAuthorityDocument -Repository $testRepository -CandidateSha $candidate `
            -ValidatedProfile $fakeProfile -EvidenceRoot $authorityEvidenceRoot
        $authorityReference = Write-D32VendoredProtocAuthorityCreateNew -Path $authorityPath -Document $authorityDocument
        $authorityValidated = Test-D32VendoredProtocAuthority -AuthorityPath $authorityPath -ExpectedAuthoritySha256 $authorityReference.sha256 `
            -Repository $testRepository -CandidateSha $candidate -ValidatedProfile $fakeProfile -EvidenceRoot $authorityEvidenceRoot
        & $add 'external locked-protoc authority V1 validates only its independently pinned bytes and absent canonical fresh root' `
            ($authorityValidated.Reference.sha256 -ceq $authorityReference.sha256 -and -not (Test-Path -LiteralPath $authorityEvidenceRoot))

        $oldAuthorityDocument = [ordered]@{}
        foreach ($field in $authorityDocument.Keys) { $oldAuthorityDocument[$field] = $authorityDocument[$field] }
        $oldAuthorityDocument.schema_version = 0
        $oldAuthorityDocument.record_type = 'D32_VENDORED_PROTOC_AUTHORITY_V0'
        $oldAuthorityPath = Join-Path $profileSelfTestRoot 'D32-VENDORED-PROTOC-AUTHORITY-old.json'
        $oldAuthorityReference = Write-D32VendoredProtocAuthorityCreateNew -Path $oldAuthorityPath -Document $oldAuthorityDocument
        $oldAuthorityRejected = $false
        try {
            $null = Test-D32VendoredProtocAuthority -AuthorityPath $oldAuthorityPath -ExpectedAuthoritySha256 $oldAuthorityReference.sha256 `
                -Repository $testRepository -CandidateSha $candidate -ValidatedProfile $fakeProfile -EvidenceRoot $authorityEvidenceRoot
        }
        catch { $oldAuthorityRejected = $_.Exception.Message -like '*VENDORED_PROTOC_AUTHORITY_BLOCKED*' }
        & $add 'vendored-protoc authority rejects legacy and unknown record versions' $oldAuthorityRejected

        $extraAuthorityDocument = [ordered]@{}
        foreach ($field in $authorityDocument.Keys) { $extraAuthorityDocument[$field] = $authorityDocument[$field] }
        $extraAuthorityDocument.unapproved = $true
        $extraAuthorityPath = Join-Path $profileSelfTestRoot 'D32-VENDORED-PROTOC-AUTHORITY-extra.json'
        $extraAuthorityReference = Write-D32VendoredProtocAuthorityCreateNew -Path $extraAuthorityPath -Document $extraAuthorityDocument
        $extraAuthorityRejected = $false
        try {
            $null = Test-D32VendoredProtocAuthority -AuthorityPath $extraAuthorityPath -ExpectedAuthoritySha256 $extraAuthorityReference.sha256 `
                -Repository $testRepository -CandidateSha $candidate -ValidatedProfile $fakeProfile -EvidenceRoot $authorityEvidenceRoot
        }
        catch { $extraAuthorityRejected = $_.Exception.Message -like '*VENDORED_PROTOC_AUTHORITY_BLOCKED*' }
        & $add 'vendored-protoc authority rejects extra fields and schema extension' $extraAuthorityRejected

        $typedAuthorityDocument = [ordered]@{}
        foreach ($field in $authorityDocument.Keys) { $typedAuthorityDocument[$field] = $authorityDocument[$field] }
        $typedAuthorityDocument.toolchain_profile = [ordered]@{}
        foreach ($field in $authorityDocument.toolchain_profile.Keys) { $typedAuthorityDocument.toolchain_profile[$field] = $authorityDocument.toolchain_profile[$field] }
        $typedAuthorityDocument.toolchain_profile.bytes = [string]$typedAuthorityDocument.toolchain_profile.bytes
        $typedAuthorityPath = Join-Path $profileSelfTestRoot 'D32-VENDORED-PROTOC-AUTHORITY-string-number.json'
        $typedAuthorityReference = Write-D32VendoredProtocAuthorityCreateNew -Path $typedAuthorityPath -Document $typedAuthorityDocument
        $typedAuthorityRejected = $false
        try {
            $null = Test-D32VendoredProtocAuthority -AuthorityPath $typedAuthorityPath -ExpectedAuthoritySha256 $typedAuthorityReference.sha256 `
                -Repository $testRepository -CandidateSha $candidate -ValidatedProfile $fakeProfile -EvidenceRoot $authorityEvidenceRoot
        }
        catch { $typedAuthorityRejected = $_.Exception.Message -like '*VENDORED_PROTOC_AUTHORITY_BLOCKED*' }
        & $add 'vendored-protoc authority rejects string-coerced numeric identity fields' $typedAuthorityRejected

        $wrongAuthorityCandidateRejected = $false
        try {
            $null = Test-D32VendoredProtocAuthority -AuthorityPath $authorityPath -ExpectedAuthoritySha256 $authorityReference.sha256 `
                -Repository $testRepository -CandidateSha ('f' * 40) -ValidatedProfile $fakeProfile -EvidenceRoot $authorityEvidenceRoot
        }
        catch { $wrongAuthorityCandidateRejected = $_.Exception.Message -like '*VENDORED_PROTOC_AUTHORITY_BLOCKED*' }
        $wrongProfileAuthorityDocument = [ordered]@{}
        foreach ($field in $authorityDocument.Keys) { $wrongProfileAuthorityDocument[$field] = $authorityDocument[$field] }
        $wrongProfileAuthorityDocument.toolchain_profile = [ordered]@{}
        foreach ($field in $authorityDocument.toolchain_profile.Keys) { $wrongProfileAuthorityDocument.toolchain_profile[$field] = $authorityDocument.toolchain_profile[$field] }
        $wrongProfileAuthorityDocument.toolchain_profile.sha256 = '0' * 64
        $wrongProfileAuthorityPath = Join-Path $profileSelfTestRoot 'D32-VENDORED-PROTOC-AUTHORITY-wrong-profile.json'
        $wrongProfileAuthorityReference = Write-D32VendoredProtocAuthorityCreateNew -Path $wrongProfileAuthorityPath -Document $wrongProfileAuthorityDocument
        $wrongAuthorityProfileRejected = $false
        try {
            $null = Test-D32VendoredProtocAuthority -AuthorityPath $wrongProfileAuthorityPath -ExpectedAuthoritySha256 $wrongProfileAuthorityReference.sha256 `
                -Repository $testRepository -CandidateSha $candidate -ValidatedProfile $fakeProfile -EvidenceRoot $authorityEvidenceRoot
        }
        catch { $wrongAuthorityProfileRejected = $_.Exception.Message -like '*VENDORED_PROTOC_AUTHORITY_BLOCKED*' }
        $wrongAuthorityBindingDetail = 'candidate={0};profile={1}' -f $wrongAuthorityCandidateRejected,$wrongAuthorityProfileRejected
        & $add 'vendored-protoc authority rejects mismatched candidate and caller Profile V2 pins' `
            ($wrongAuthorityCandidateRejected -and $wrongAuthorityProfileRejected) $wrongAuthorityBindingDetail

        $tamperedLockRepository = Join-Path $profileSelfTestRoot 'tampered-vita-lock-repository'
        $tamperedLockVita = Join-Path $tamperedLockRepository 'vita-agent'
        [void][IO.Directory]::CreateDirectory($tamperedLockVita)
        $tamperedLockPath = Join-Path $tamperedLockVita 'Cargo.lock'
        [IO.File]::Copy((Join-Path $testRepository 'vita-agent\Cargo.lock'), $tamperedLockPath)
        $tamperedLockText = [IO.File]::ReadAllText($tamperedLockPath, [Text.Encoding]::UTF8).Replace(
            '95067976aca6421a523e491fce939a3e65249bac4b977adee0ee9771568e8aa3', ('0' * 64))
        [IO.File]::WriteAllText($tamperedLockPath, $tamperedLockText, [Text.UTF8Encoding]::new($false))
        $tamperedLockRejected = $false
        try { $null = Get-D32VendoredLockPackageRecords -Repository $tamperedLockRepository }
        catch { $tamperedLockRejected = $_.Exception.Message -like '*VENDORED_PROTOC_LOCK_BLOCKED*' }
        & $add 'locked protoc authority rejects modified Cargo.lock package checksum before any fetch/build' $tamperedLockRejected

        $tamperedArchivePath = Join-Path $profileSelfTestRoot 'tampered-protoc-win32.crate'
        [IO.File]::WriteAllBytes($tamperedArchivePath, [byte[]]@(0x44, 0x33, 0x32))
        $tamperedArchiveRejected = $false
        try { $null = Read-D32VendoredProtocArchive -ArchivePath $tamperedArchivePath }
        catch { $tamperedArchiveRejected = $_.Exception.Message -like '*VENDORED_PROTOC_ARCHIVE_BLOCKED*' }
        & $add 'vendored-protoc archive bytes/hash mismatch is rejected before tar member processing' $tamperedArchiveRejected

        function New-D32Phase0SelfTestTarGzip {
            param([Parameter(Mandatory = $true)][object[]]$Entries)
            $memory = [IO.MemoryStream]::new()
            $gzip = [IO.Compression.GZipStream]::new($memory, [IO.Compression.CompressionMode]::Compress, $true)
            $writer = [System.Formats.Tar.TarWriter]::new($gzip, [System.Formats.Tar.TarEntryFormat]::Pax, $true)
            try {
                foreach ($spec in $Entries) {
                    $tarEntry = [System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]$spec.type, [string]$spec.name)
                    if ($tarEntry.EntryType -eq [System.Formats.Tar.TarEntryType]::RegularFile) {
                        $entryData = [IO.MemoryStream]::new([byte[]]$spec.bytes)
                        try { $tarEntry.DataStream = $entryData; $writer.WriteEntry($tarEntry) }
                        finally { $entryData.Dispose() }
                    }
                    else {
                        if (-not [String]::IsNullOrWhiteSpace([string]$spec.link_name)) { $tarEntry.LinkName = [string]$spec.link_name }
                        $writer.WriteEntry($tarEntry)
                    }
                }
                $writer.Dispose(); $writer = $null
                $gzip.Dispose(); $gzip = $null
                return ,$memory.ToArray()
            }
            finally {
                if ($null -ne $writer) { $writer.Dispose() }
                if ($null -ne $gzip) { $gzip.Dispose() }
                $memory.Dispose()
            }
        }
        $tarPrefix = $script:D32VendoredProtocPackageRoot
        $regularTarEntry = { param($name) [PSCustomObject]@{ type = [System.Formats.Tar.TarEntryType]::RegularFile; name = $name; bytes = [byte[]]@(0x44, 0x33, 0x32); link_name = $null } }
        $duplicateEntryA = & $regularTarEntry "$tarPrefix/Cargo.toml"
        $duplicateEntryB = & $regularTarEntry "$tarPrefix/Cargo.toml"
        $caseEntryA = & $regularTarEntry "$tarPrefix/Bin/protoc.exe"
        $caseEntryB = & $regularTarEntry "$tarPrefix/bin/protoc.exe"
        $malformedTarCases = @(
            [PSCustomObject]@{ name = 'traversal component'; entries = @(& $regularTarEntry "$tarPrefix/../escape") },
            [PSCustomObject]@{ name = 'backslash alias'; entries = @(& $regularTarEntry "$tarPrefix/bin\protoc.exe") },
            [PSCustomObject]@{ name = 'foreign package root'; entries = @(& $regularTarEntry 'different-package-3.2.0/bin/protoc.exe') },
            [PSCustomObject]@{ name = 'duplicate member'; entries = @($duplicateEntryA, $duplicateEntryB) },
            [PSCustomObject]@{ name = 'case-colliding member'; entries = @($caseEntryA, $caseEntryB) },
            [PSCustomObject]@{ name = 'special symbolic link'; entries = @([PSCustomObject]@{ type = [System.Formats.Tar.TarEntryType]::SymbolicLink; name = "$tarPrefix/link"; bytes = [byte[]]@(); link_name = '../outside' }) }
        )
        $malformedTarFailures = [System.Collections.Generic.List[string]]::new()
        foreach ($tarCase in $malformedTarCases) {
            $compressedTar = New-D32Phase0SelfTestTarGzip -Entries @($tarCase.entries)
            $compressedMemory = [IO.MemoryStream]::new([byte[]]$compressedTar)
            $tarGzip = [IO.Compression.GZipStream]::new($compressedMemory, [IO.Compression.CompressionMode]::Decompress, $true)
            $rejectedTar = $false
            try { $null = Read-D32VendoredProtocTarMembers -TarStream $tarGzip }
            catch { $rejectedTar = $_.Exception.Message -like '*VENDORED_PROTOC_ARCHIVE_BLOCKED*' }
            finally { $tarGzip.Dispose(); $compressedMemory.Dispose() }
            if (-not $rejectedTar) { $malformedTarFailures.Add([string]$tarCase.name) }
        }
        & $add 'tar parser rejects traversal, separators/aliases, foreign root, duplicate/case-colliding and special members' `
            ($malformedTarFailures.Count -eq 0) (($malformedTarFailures -join '|'))

        $runAuthorityPath = Join-Path $profileSelfTestRoot 'D32-PHASE0-VENDORED-PROTOC-AUTHORITY-RUN.json'
        $runAuthorityDocument = New-D32VendoredProtocAuthorityDocument -Repository $testRepository -CandidateSha $candidate `
            -ValidatedProfile $fakeProfile -EvidenceRoot $fixtureOutputRoot
        $runAuthorityReference = Write-D32VendoredProtocAuthorityCreateNew -Path $runAuthorityPath -Document $runAuthorityDocument

        $ownerBinding = New-D32Phase0FixtureOutputRoot -Path $fixtureOutputRoot -Repository $testRepository -ExpectedCandidateSha $candidate -ValidatedProfile $fakeProfile -RunId $runId
        $runRootIdentity = New-D32ProfileDirectoryCreateNew -Path $runRoot
        $cargoHomeIdentity = New-D32ProfileDirectoryCreateNew -Path $cargoHome
        $tempRootIdentity = New-D32ProfileDirectoryCreateNew -Path $tempRoot
        $null = Test-D32ProfileDirectoryIdentity -Path $runRoot -VolumeSerialHex $runRootIdentity.VolumeSerialHex -FileIdHex $runRootIdentity.FileIdHex
        $null = Test-D32ProfileDirectoryIdentity -Path $cargoHome -VolumeSerialHex $cargoHomeIdentity.VolumeSerialHex -FileIdHex $cargoHomeIdentity.FileIdHex
        $null = Test-D32ProfileDirectoryIdentity -Path $tempRoot -VolumeSerialHex $tempRootIdentity.VolumeSerialHex -FileIdHex $tempRootIdentity.FileIdHex

        $archiveSourcePath = Join-Path (Join-Path $env:USERPROFILE '.cargo') $script:D32VendoredProtocArchiveRelativePath
        if (-not (Test-D32ProfileNoReparsePath -Path $archiveSourcePath)) { throw 'PHASE0_SELFTEST_BLOCKED: read-only source cache lacks the exact approved protoc archive' }
        $archiveSourceSnapshot = Get-D32ProfileFileSnapshot -Path $archiveSourcePath
        if ($archiveSourceSnapshot.Bytes -ne $script:D32VendoredProtocArchiveBytes -or $archiveSourceSnapshot.Sha256 -cne $script:D32VendoredProtocWin32Checksum) {
            throw 'PHASE0_SELFTEST_BLOCKED: read-only source cache archive is not the exact approved locked crate'
        }
        $runArchivePath = Join-Path $cargoHome $script:D32VendoredProtocArchiveRelativePath
        $null = Ensure-D32VendoredDirectoryChain -Path (Split-Path -Parent $runArchivePath) -Boundary $cargoHome
        [IO.File]::Copy($archiveSourcePath, $runArchivePath, $false)
        $runGrant = New-D32VendoredProtocRunGrant -AuthorityPath $runAuthorityPath -AuthoritySha256 $runAuthorityReference.sha256 `
            -Repository $testRepository -CandidateSha $candidate -ValidatedProfile $fakeProfile -EvidenceRoot $fixtureOutputRoot `
            -OwnerMarkerReference $ownerBinding.OwnerMarker -RunId $runId -CargoHome $cargoHome
        $runGrantValidated = Test-D32VendoredProtocRunGrant -Reference $runGrant.Reference -Repository $testRepository -CandidateSha $candidate `
            -ValidatedProfile $fakeProfile -EvidenceRoot $fixtureOutputRoot -ExpectedRunId $runId -CargoHome $cargoHome `
            -AuthorityPath $runAuthorityPath -AuthoritySha256 $runAuthorityReference.sha256 -OwnerMarkerReference $ownerBinding.OwnerMarker
        & $add 'run grant validates one owner-bound fresh home and materializes only exact locked source/image bytes' `
            ($runGrantValidated.Image.Sha256 -ceq $script:D32VendoredProtocImageSha256 -and
                $runGrantValidated.Image.Bytes -eq $script:D32VendoredProtocImageBytes -and
                (Test-D32ProfilePathEqual -Left $runGrantValidated.Image.Path -Right (Join-Path (Join-Path $cargoHome $script:D32VendoredProtocSourceRelativePath) 'bin\protoc.exe')) -and
                (Test-D32ProfileDirectoryIdentity -Path $cargoHome -VolumeSerialHex $cargoHomeIdentity.VolumeSerialHex -FileIdHex $cargoHomeIdentity.FileIdHex) -and
                $runGrantValidated.Reference.sha256 -ceq $runGrant.Reference.sha256)

        $wrongRunGrantRejected = $false
        try {
            $null = Test-D32VendoredProtocRunGrant -Reference $runGrant.Reference -Repository $testRepository -CandidateSha $candidate `
                -ValidatedProfile $fakeProfile -EvidenceRoot $fixtureOutputRoot -ExpectedRunId ('f' * 32) -CargoHome $cargoHome `
                -AuthorityPath $runAuthorityPath -AuthoritySha256 $runAuthorityReference.sha256 -OwnerMarkerReference $ownerBinding.OwnerMarker
        }
        catch { $wrongRunGrantRejected = $_.Exception.Message -like '*VENDORED_PROTOC_GRANT_BLOCKED*' }
        $wrongRootGrantRejected = $false
        try {
            $null = Test-D32VendoredProtocRunGrant -Reference $runGrant.Reference -Repository $testRepository -CandidateSha $candidate `
                -ValidatedProfile $fakeProfile -EvidenceRoot (Join-Path $profileSelfTestRoot 'different-root') -ExpectedRunId $runId -CargoHome $cargoHome `
                -AuthorityPath $runAuthorityPath -AuthoritySha256 $runAuthorityReference.sha256 -OwnerMarkerReference $ownerBinding.OwnerMarker
        }
        catch { $wrongRootGrantRejected = $_.Exception.Message -like '*VENDORED_PROTOC_BLOCKED*' -or $_.Exception.Message -like '*VENDORED_PROTOC_GRANT_BLOCKED*' }
        $wrongHomeGrantRejected = $false
        try {
            $null = Test-D32VendoredProtocRunGrant -Reference $runGrant.Reference -Repository $testRepository -CandidateSha $candidate `
                -ValidatedProfile $fakeProfile -EvidenceRoot $fixtureOutputRoot -ExpectedRunId $runId -CargoHome (Join-Path $runRoot 'old-c') `
                -AuthorityPath $runAuthorityPath -AuthoritySha256 $runAuthorityReference.sha256 -OwnerMarkerReference $ownerBinding.OwnerMarker
        }
        catch { $wrongHomeGrantRejected = $_.Exception.Message -like '*VENDORED_PROTOC_GRANT_BLOCKED*' }
        $wrongOwnerReference = [ordered]@{}
        foreach ($field in $ownerBinding.OwnerMarker.Keys) { $wrongOwnerReference[$field] = $ownerBinding.OwnerMarker[$field] }
        $wrongOwnerReference.file_id_hex = ('f' * 32)
        $wrongOwnerGrantRejected = $false
        try {
            $null = Test-D32VendoredProtocRunGrant -Reference $runGrant.Reference -Repository $testRepository -CandidateSha $candidate `
                -ValidatedProfile $fakeProfile -EvidenceRoot $fixtureOutputRoot -ExpectedRunId $runId -CargoHome $cargoHome `
                -AuthorityPath $runAuthorityPath -AuthoritySha256 $runAuthorityReference.sha256 -OwnerMarkerReference $wrongOwnerReference
        }
        catch { $wrongOwnerGrantRejected = $_.Exception.Message -like '*VENDORED_PROTOC_GRANT_BLOCKED*' }
        $wrongAuthorityGrantRejected = $false
        try {
            $null = Test-D32VendoredProtocRunGrant -Reference $runGrant.Reference -Repository $testRepository -CandidateSha $candidate `
                -ValidatedProfile $fakeProfile -EvidenceRoot $fixtureOutputRoot -ExpectedRunId $runId -CargoHome $cargoHome `
                -AuthorityPath $runAuthorityPath -AuthoritySha256 ('0' * 64) -OwnerMarkerReference $ownerBinding.OwnerMarker
        }
        catch { $wrongAuthorityGrantRejected = $_.Exception.Message -like '*VENDORED_PROTOC_AUTHORITY_BLOCKED*' }
        $wrongGrantReferenceHash = [ordered]@{}
        foreach ($field in $runGrant.Reference.Keys) { $wrongGrantReferenceHash[$field] = $runGrant.Reference[$field] }
        $wrongGrantReferenceHash.sha256 = ('0' * 64)
        $wrongGrantHashRejected = $false
        try {
            $null = Test-D32VendoredProtocRunGrant -Reference $wrongGrantReferenceHash -Repository $testRepository -CandidateSha $candidate `
                -ValidatedProfile $fakeProfile -EvidenceRoot $fixtureOutputRoot -ExpectedRunId $runId -CargoHome $cargoHome `
                -AuthorityPath $runAuthorityPath -AuthoritySha256 $runAuthorityReference.sha256 -OwnerMarkerReference $ownerBinding.OwnerMarker
        }
        catch { $wrongGrantHashRejected = $_.Exception.Message -like '*VENDORED_PROTOC_BLOCKED*' }
        $wrongGrantReferenceIdentity = [ordered]@{}
        foreach ($field in $runGrant.Reference.Keys) { $wrongGrantReferenceIdentity[$field] = $runGrant.Reference[$field] }
        $wrongGrantReferenceIdentity.file_id_hex = ('f' * 32)
        $wrongGrantIdentityRejected = $false
        try {
            $null = Test-D32VendoredProtocRunGrant -Reference $wrongGrantReferenceIdentity -Repository $testRepository -CandidateSha $candidate `
                -ValidatedProfile $fakeProfile -EvidenceRoot $fixtureOutputRoot -ExpectedRunId $runId -CargoHome $cargoHome `
                -AuthorityPath $runAuthorityPath -AuthoritySha256 $runAuthorityReference.sha256 -OwnerMarkerReference $ownerBinding.OwnerMarker
        }
        catch { $wrongGrantIdentityRejected = $_.Exception.Message -like '*VENDORED_PROTOC_BLOCKED*' }
        & $add 'run grant rejects stale/wrong run, root, CargoHome, owner marker, caller authority SHA, and grant hash/file identity' `
            ($wrongRunGrantRejected -and $wrongRootGrantRejected -and $wrongHomeGrantRejected -and $wrongOwnerGrantRejected -and
                $wrongAuthorityGrantRejected -and $wrongGrantHashRejected -and $wrongGrantIdentityRejected) `
            ("run=$wrongRunGrantRejected;root=$wrongRootGrantRejected;home=$wrongHomeGrantRejected;owner=$wrongOwnerGrantRejected;authority=$wrongAuthorityGrantRejected;hash=$wrongGrantHashRejected;identity=$wrongGrantIdentityRejected")

        $mismatchedSourceTreeRejected = $false
        $mutatedRelativePath = @($runGrant.Archive.Files.Keys | Where-Object { $_ -cne 'bin/protoc.exe' })[0]
        if ([String]::IsNullOrWhiteSpace([string]$mutatedRelativePath)) { throw 'PHASE0_SELFTEST_BLOCKED: exact package archive has no non-image member for source-tree mismatch test' }
        $mutatedSourcePath = Join-Path $runGrant.SourcePath ([string]$mutatedRelativePath.Replace('/', '\'))
        $mutatedSourceBytes = [IO.File]::ReadAllBytes($mutatedSourcePath)
        if ($mutatedSourceBytes.Length -eq 0) { throw 'PHASE0_SELFTEST_BLOCKED: selected source-tree member is unexpectedly empty' }
        $mutatedSourceBytes[0] = [byte]($mutatedSourceBytes[0] -bxor 0xff)
        [IO.File]::WriteAllBytes($mutatedSourcePath, $mutatedSourceBytes)
        try { $null = Ensure-D32VendoredProtocSource -CargoHome $cargoHome -Authority $runGrantValidated.Authority }
        catch { $mismatchedSourceTreeRejected = $_.Exception.Message -like '*VENDORED_PROTOC_SOURCE_BLOCKED*' }
        & $add 'materializer rejects an existing Cargo source tree whose member bytes differ from the locked archive' $mismatchedSourceTreeRejected

        $fixtureStartupScriptPath = Join-Path $script:D32Phase0ScriptRoot 'd32-fixture-prebuild.ps1'
        $startupTestModuleBody = {
            param([string]$Phase0ScriptPath, [string]$FixtureScriptPath)
            . $Phase0ScriptPath -Phase0LibraryOnly
            $preflightLibraryPath = Join-Path (Split-Path -Parent $Phase0ScriptPath) 'd32-preflight.ps1'
            . $preflightLibraryPath -LibraryOnly -Phase0DependencyLibraryOnly
            . $FixtureScriptPath -D32LauncherLibraryOnly

            function Invoke-D32Phase0StartupSelfTest {
                param(
                    [Parameter(Mandatory = $true)][string]$OutputRoot,
                    [Parameter(Mandatory = $true)][string]$Repository,
                    [Parameter(Mandatory = $true)][string]$CandidateSha,
                    [Parameter(Mandatory = $true)][object]$ValidatedProfile,
                    [Parameter(Mandatory = $true)][string]$RunId
                )

                $binding = New-D32Phase0FixtureOutputRoot `
                    -Path $OutputRoot `
                    -Repository $Repository `
                    -ExpectedCandidateSha $CandidateSha `
                    -ValidatedProfile $ValidatedProfile `
                    -RunId $RunId
                $fixtureOwner = Test-D32FixturePhase0OwnerBinding `
                    -OutputRoot $OutputRoot `
                    -ExpectedCandidateSha $CandidateSha `
                    -ValidatedProfile $ValidatedProfile `
                    -OwnerBinding $binding
                $storage = Initialize-D32FixturePhase0Storage `
                    -OutputRoot $OutputRoot `
                    -Repository $Repository `
                    -ExpectedCandidateSha $CandidateSha `
                    -ValidatedProfile $ValidatedProfile `
                    -OwnerBinding $binding
                $script:D32Phase0StorageContext = $storage.StorageContext

                $fakeBoundaryState = [PSCustomObject]@{ Called = $false }
                $fakeFetchAction = {
                    $fakeBoundaryState.Called = $true
                    throw 'PHASE0_SELFTEST_FAKE_PRE_CARGO_STOP'
                }.GetNewClosure()
                $previousFailureContext = $script:D32Phase0FailureContext
                $script:D32Phase0FailureContext = [PSCustomObject]@{
                    EvidenceRoot = $OutputRoot
                    CandidateSha = $CandidateSha
                    Profile = $ValidatedProfile
                    RunId = $binding.RunId
                    RootIdentity = $binding.RootIdentity
                    OwnerMarker = $binding.OwnerMarker
                }
                try {
                    $boundaryFailure = $null
                    try {
                        $null = Invoke-D32FixturePreCargoBoundary `
                            -OutputRoot $OutputRoot `
                            -Repository $Repository `
                            -ExpectedCandidateSha $CandidateSha `
                            -ValidatedProfile $ValidatedProfile `
                            -OwnerBinding $binding `
                            -StorageContext $storage.StorageContext `
                            -FetchAction $fakeFetchAction
                    }
                    catch { $boundaryFailure = $_.Exception.Message }

                    $tamperedStorage = [ordered]@{
                        evidence_root = $storage.StorageContext.evidence_root
                        owner_marker = $storage.StorageContext.owner_marker
                        run_root = $storage.StorageContext.run_root
                        cargo_home = $storage.StorageContext.cargo_home
                        temp_root = [ordered]@{
                            path = $storage.StorageContext.temp_root.path
                            volume_serial_hex = $storage.StorageContext.temp_root.volume_serial_hex
                            file_id_hex = 'f' * 32
                        }
                        run_id = $storage.StorageContext.run_id
                    }
                    $tamperedBoundaryState = [PSCustomObject]@{ Called = $false }
                    $neverFetchAction = { $tamperedBoundaryState.Called = $true }.GetNewClosure()
                    $tamperedBoundaryFailure = $null
                    try {
                        $null = Invoke-D32FixturePreCargoBoundary `
                            -OutputRoot $OutputRoot `
                            -Repository $Repository `
                            -ExpectedCandidateSha $CandidateSha `
                            -ValidatedProfile $ValidatedProfile `
                            -OwnerBinding $binding `
                            -StorageContext $tamperedStorage `
                            -FetchAction $neverFetchAction
                    }
                    catch { $tamperedBoundaryFailure = $_.Exception.Message }

                    $null = Write-D32Phase0BlockedDiagnostic `
                        -PrimaryError ([string]$boundaryFailure) `
                        -SecondaryErrors @('self-test fake boundary launched no child process') `
                        -Command $null `
                        -ProcessIdentity $null `
                        -RawV2Trace $null `
                        -NativeCleanup $null `
                        -StdoutPath $null `
                        -StderrPath $null
                    $diagnosticPath = Join-Path $OutputRoot $script:D32Phase0BlockedDiagnosticName
                    $diagnostic = [IO.File]::ReadAllText($diagnosticPath, [Text.Encoding]::UTF8) | ConvertFrom-D32Phase0Json

                    $rootAndOwnerPassed = $fixtureOwner.RunId -ceq $RunId -and
                        (Test-D32ProfilePathEqual -Left $fixtureOwner.EvidenceRoot -Right $OutputRoot) -and
                        $fixtureOwner.EvidenceRootIdentity.FileIdHex -ceq $binding.RootIdentity.FileIdHex -and
                        $fixtureOwner.OwnerMarker.file_id_hex -ceq $binding.OwnerMarker.file_id_hex -and
                        (Test-D32ProfileNoReparsePath -Path $OutputRoot)
                    $compactStoragePassed = (Test-D32ProfilePathEqual -Left $storage.RunRoot -Right (Join-Path $OutputRoot 'r')) -and
                        (Test-D32ProfilePathEqual -Left $storage.CargoHome -Right (Join-Path (Join-Path $OutputRoot 'r') 'c')) -and
                        (Test-D32ProfilePathEqual -Left $storage.TempRoot -Right (Join-Path (Join-Path $OutputRoot 'r') 't')) -and
                        (Test-D32CargoHome -Path $storage.CargoHome -Repository $Repository -RequireEmpty).Empty -and
                        $storage.StorageContext.run_id -ceq $RunId
                    $boundaryStoppedBeforeCargo = $fakeBoundaryState.Called -and
                        $boundaryFailure -ceq 'PHASE0_SELFTEST_FAKE_PRE_CARGO_STOP' -and
                        $diagnostic.primary_error -ceq 'PHASE0_SELFTEST_FAKE_PRE_CARGO_STOP'
                    $boundaryRejectsChangedIdentity = -not $tamperedBoundaryState.Called -and
                        -not [String]::IsNullOrWhiteSpace([string]$tamperedBoundaryFailure)

                    $requiredContextUnverified = @('failing_fixed_command', 'process_identity', 'stream.stdout', 'stream.stderr')
                    $requiredTraceUnverified = @(
                        'trace.dedicated_debugger_thread', 'trace.debugger_kill_on_exit_enabled', 'trace.debugger_thread_exited',
                        'trace.debugger_thread_joined', 'trace.retained_process_handles_signaled',
                        'trace.debugger_association_query_verified', 'trace.debugger_association_absent',
                        'trace.job_accounting_verified', 'trace.accounting_consistent', 'trace.event_chain_complete',
                        'trace.job_active_processes'
                    )
                    $requiredCleanupUnverified = @(
                        'cleanup.CleanupSucceeded', 'cleanup.JobCloseSucceeded', 'cleanup.JobActiveProcessCountVerified',
                        'cleanup.DebuggerThreadJoined', 'cleanup.RetainedProcessHandlesSignaled',
                        'cleanup.DebuggerAssociationQueryVerified', 'cleanup.DebuggerAssociationAbsent'
                    )
                    $noProcessSidecarPassed = $diagnostic.status -ceq 'BLOCKED' -and
                        $diagnostic.gate_authority -ceq 'NONE' -and $diagnostic.phase1_allowed -eq $false -and $diagnostic.aggregate_allowed -eq $false -and
                        $null -eq $diagnostic.failing_fixed_command -and $null -eq $diagnostic.process_identity -and $null -eq $diagnostic.raw_v2_trace -and
                        @($requiredContextUnverified | Where-Object { $diagnostic.unverified_fields -cnotcontains $_ }).Count -eq 0 -and
                        $diagnostic.job_debug_cleanup.verification -ceq 'UNVERIFIED' -and $null -eq $diagnostic.job_debug_cleanup.raw_native_cleanup -and
                        @($requiredTraceUnverified | Where-Object { $diagnostic.job_debug_cleanup.unverified_fields -cnotcontains $_ }).Count -eq 0 -and
                        @($requiredCleanupUnverified | Where-Object { $diagnostic.job_debug_cleanup.unverified_fields -cnotcontains $_ }).Count -eq 0 -and
                        $diagnostic.ordered_stream_captures.Count -eq 2 -and
                        $diagnostic.ordered_stream_captures[0].ordinal -eq 1 -and $diagnostic.ordered_stream_captures[0].stream -ceq 'stdout' -and
                        $diagnostic.ordered_stream_captures[0].status -ceq 'UNAVAILABLE' -and $null -eq $diagnostic.ordered_stream_captures[0].path -and $null -eq $diagnostic.ordered_stream_captures[0].reference -and
                        $diagnostic.ordered_stream_captures[1].ordinal -eq 2 -and $diagnostic.ordered_stream_captures[1].stream -ceq 'stderr' -and
                        $diagnostic.ordered_stream_captures[1].status -ceq 'UNAVAILABLE' -and $null -eq $diagnostic.ordered_stream_captures[1].path -and $null -eq $diagnostic.ordered_stream_captures[1].reference

                    return @(
                        [PSCustomObject]@{ Name = 'fixture startup validates fresh exclusive owner/root and creates compact directories with opened-handle identities'; Passed = [bool]$rootAndOwnerPassed -and [bool]$compactStoragePassed },
                        [PSCustomObject]@{ Name = 'pre-Cargo boundary reaches fake fail-closed callback without running Cargo'; Passed = [bool]$boundaryStoppedBeforeCargo },
                        [PSCustomObject]@{ Name = 'pre-Cargo boundary rejects tampered TEMP handle identity before invoking fetch callback'; Passed = [bool]$boundaryRejectsChangedIdentity },
                        [PSCustomObject]@{ Name = 'no-process blocked diagnostic preserves explicit V2/Job/stream UNVERIFIED fields and no gate authority'; Passed = [bool]$noProcessSidecarPassed }
                    )
                }
                finally { $script:D32Phase0FailureContext = $previousFailureContext }
            }
            Export-ModuleMember -Function Invoke-D32Phase0StartupSelfTest
        }
        $startupSelfTestModule = New-Module `
            -Name $startupSelfTestModuleName `
            -ArgumentList @($script:D32Phase0ScriptPath, $fixtureStartupScriptPath) `
            -ScriptBlock $startupTestModuleBody
        Import-Module $startupSelfTestModule -Force
        $startupSelfTestCases = @(Invoke-D32Phase0StartupSelfTest `
            -OutputRoot $startupSelfTestRoot `
            -Repository $testRepository `
            -CandidateSha $candidate `
            -ValidatedProfile $fakeProfile `
            -RunId 'abcdef0123456789abcdef0123456789')
        foreach ($startupCase in $startupSelfTestCases) { & $add $startupCase.Name ([bool]$startupCase.Passed) }
        Remove-Module -Name $startupSelfTestModuleName -Force -ErrorAction SilentlyContinue
        $startupSelfTestModule = $null

        $ownerRootNoReparse = Test-D32ProfileNoReparsePath -Path $selfTestRoot
        $staleOwnerRunRejected = $false
        try {
            $null = Test-D32Phase0OwnerBinding -EvidenceRoot $selfTestRoot -ExpectedCandidateSha $candidate -ValidatedProfile $fakeProfile -ExpectedRunId ('f' * 32) -ExpectedRootIdentity $ownerBinding.RootIdentity -ExpectedMarkerReference $ownerBinding.OwnerMarker
        }
        catch { $staleOwnerRunRejected = $_.Exception.Message -like '*does not bind this candidate, profile, opened EvidenceRoot, and fresh run_id*' }
        $ownerMarkerBeforeCollision = Get-D32Phase0FileReference -Path $ownerBinding.OwnerMarker.path
        $ownerRootCollisionRejected = $false
        try {
            $null = New-D32Phase0FixtureOutputRoot -Path $selfTestRoot -Repository $testRepository -ExpectedCandidateSha $candidate -ValidatedProfile $fakeProfile -RunId ('1' * 32)
        }
        catch { $ownerRootCollisionRejected = $_.Exception.Message -like 'PHASE0_OUTPUT_BLOCKED:*' }
        $ownerMarkerAfterCollision = Get-D32Phase0FileReference -Path $ownerBinding.OwnerMarker.path
        & $add 'owner binding is non-reparse and rejects stale run_id without altering marker' ($ownerRootNoReparse -and $staleOwnerRunRejected -and $ownerMarkerBeforeCollision.sha256 -ceq $ownerMarkerAfterCollision.sha256)
        & $add 'fresh EvidenceRoot create-new collision is refused without overwriting its owner marker' ($ownerRootCollisionRejected -and $ownerMarkerBeforeCollision.sha256 -ceq $ownerMarkerAfterCollision.sha256)
        $compactDirectoryCollisionRejected = $false
        try { $null = New-D32ProfileDirectoryCreateNew -Path $cargoHome }
        catch { $compactDirectoryCollisionRejected = $true }
        & $add 'fixed compact Cargo-home child refuses an existing-directory collision' $compactDirectoryCollisionRejected
        $schemaRejectPath = Join-Path $selfTestRoot 'D32-PHASE0-MATRIX.json'
        $phase0SchemaFields = @('schema_version', 'record_type', 'runner_process_id', 'candidate_sha', 'source_repo', 'output_root', 'evidence_root_identity', 'owner_marker', 'vendored_protoc', 'tauri_macros_source_patch', 'h7c_git_child_authority', 'h7c_git_child_attestation', 'status', 'bundle_hashes', 'started_at_utc', 'completed_at_utc', 'final_candidate_sha', 'final_clean', 'powershell', 'toolchain_profile', 'cargo_home', 'fetches', 'fixture', 'commands', 'test_inventory', 'local_suites', 'focused_tests', 'deferred_d31_tests', 'deferred_d29g2_provider_tests', 'not_run_capture_tests', 'governance_inputs', 'phase0_scope')
        foreach ($phase0SchemaCase in @(
                [PSCustomObject]@{ Version = 4; Type = 'D32_PHASE0_MATRIX_RECORD_V4'; Name = 'prior V4' },
                [PSCustomObject]@{ Version = 99; Type = 'D32_PHASE0_MATRIX_RECORD_V99'; Name = 'unknown V99' }
            )) {
            $phase0SchemaDocument = [ordered]@{}
            foreach ($fieldName in $phase0SchemaFields) { $phase0SchemaDocument[$fieldName] = $null }
            $phase0SchemaDocument.schema_version = [int]$phase0SchemaCase.Version
            $phase0SchemaDocument.record_type = [string]$phase0SchemaCase.Type
            [IO.File]::WriteAllText($schemaRejectPath, (ConvertTo-Json -InputObject $phase0SchemaDocument -Depth 5 -Compress), [Text.UTF8Encoding]::new($false))
            $phase0SchemaDigest = Get-D32ProfileFileSnapshot -Path $schemaRejectPath
            $phase0SchemaResult = Test-D32Phase0MatrixRecord -RecordPath $schemaRejectPath -ExpectedRecordSha256 $phase0SchemaDigest.Sha256 -Repository $testRepository -ExpectedCandidateSha $candidate -ToolchainProfilePath $fakeProfile.ProfilePath -ExpectedToolchainProfileSha256 $fakeProfile.Digest -GitPath 'C:\d32-phase0-selftest\git.exe' -GitSha256 ('b' * 64)
            & $add "Phase0 record reader rejects $($phase0SchemaCase.Name) before evidence parsing" (-not $phase0SchemaResult.IsValid -and $phase0SchemaResult.Failure -like '*schema_version must be the supported JSON integer version 5*')
        }
        [IO.File]::Delete($schemaRejectPath)
        $manifestPath = Join-Path $fixtureOutputRoot 'fixture-manifest.json'
        $sidecarPath = Join-Path $fixtureOutputRoot 'fixture-build-provenance.json'
        $emptyLogPath = Join-Path $fixtureOutputRoot 'empty-stderr.log'
        $emptyStdoutPath = Join-Path $fixtureOutputRoot 'empty-stdout.log'
        [IO.File]::WriteAllText($manifestPath, '{}', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllBytes($emptyLogPath, [byte[]]@())
        [IO.File]::WriteAllBytes($emptyStdoutPath, [byte[]]@())
        $previousFailureContext = $script:D32Phase0FailureContext
        $script:D32Phase0FailureContext = [PSCustomObject]@{
            EvidenceRoot = $selfTestRoot
            CandidateSha = $candidate
            Profile = $fakeProfile
            RunId = $runId
            RootIdentity = $ownerBinding.RootIdentity
            OwnerMarker = $ownerBinding.OwnerMarker
        }
        $payloadArguments = @('build', '--quiet', '--locked', '--manifest-path', (Join-Path $testRepository 'vita-agent/Cargo.toml'), '--bin', 'd32a-sandbox-fixture', '--jobs', '1')
        $payloadCargo = $fakeProfile.Profile.toolchain.cargo
        $capturedFailurePayload = [ordered]@{
            schema_version = 1
            record_type = 'D32_PHASE0_BLOCKED_DIAGNOSTIC_PAYLOAD_V1'
            candidate_sha = $candidate
            toolchain_profile_path = [string]$fakeProfile.ProfilePath
            toolchain_profile_sha256 = [string]$fakeProfile.Digest
            run_id = $runId
            failing_fixed_command = [ordered]@{
                name = 'd32a-sandbox-fixture'
                executable = [string]$payloadCargo.path
                executable_sha256 = [string]$payloadCargo.sha256
                executable_bytes = [Int64]$payloadCargo.bytes
                executable_volume_serial_hex = [string]$payloadCargo.volume_serial_hex
                executable_file_id_hex = [string]$payloadCargo.file_id_hex
                arguments = @($payloadArguments)
                command_line = ConvertTo-D32Phase0CommandLine -Arguments (@([string]$payloadCargo.path) + @($payloadArguments))
                working_directory = [IO.Path]::GetFullPath($testRepository)
            }
            process_identity = $null
            raw_v2_trace = [ordered]@{ record_type = 'D32_DEBUG_JOB_PROCESS_TRACE_V2'; state = 'BLOCKED'; block_reason = 'selftest trace evidence' }
            raw_job_debug_cleanup = [ordered]@{
                raw_native_cleanup = [ordered]@{ CleanupSucceeded = $false; JobActiveProcessCount = 1 }
                raw_process_evidence = [ordered]@{ raw_trace_retained = $true }
                trace_state = 'BLOCKED'
                cleanup_status = 'UNVERIFIED'
            }
            ordered_stream_paths = @(
                [ordered]@{ ordinal = 1; stream = 'stdout'; path = (Join-Path $selfTestRoot 'payload.stdout.log') },
                [ordered]@{ ordinal = 2; stream = 'stderr'; path = (Join-Path $selfTestRoot 'payload.stderr.log') }
            )
            primary_error = 'CARGO_PROCESS_IDENTITY_MISMATCH: selftest preserved primary'
            secondary_errors = @('selftest cleanup failure remains secondary')
        }
        $payloadLine = 'D32_PHASE0_BLOCKED_DIAGNOSTIC_PAYLOAD_V1:' + (ConvertTo-Json -InputObject $capturedFailurePayload -Depth 20 -Compress)
        $payloadProducer = { Write-Output $payloadLine; throw 'SELFTEST_FIXTURE_FAILURE_AFTER_PAYLOAD' }.GetNewClosure()
        $capturedPayloadOutput = Invoke-D32Phase0FixtureProducerCapture -Producer $payloadProducer
        $validatedCapturedPayload = Get-D32Phase0FixtureFailurePayload `
            -Lines $capturedPayloadOutput.Lines `
            -Repository $testRepository `
            -ExpectedCandidateSha $candidate `
            -ValidatedProfile $fakeProfile `
            -ExpectedRunId $runId
        & $add 'streaming fixture failure capture validates and retains primary, raw V2/cleanup, and ordered stream payload before throw' `
            ($capturedPayloadOutput.Failure -ceq 'SELFTEST_FIXTURE_FAILURE_AFTER_PAYLOAD' -and
                $validatedCapturedPayload.primary_error -ceq 'CARGO_PROCESS_IDENTITY_MISMATCH: selftest preserved primary' -and
                $validatedCapturedPayload.raw_v2_trace.block_reason -ceq 'selftest trace evidence' -and
                $validatedCapturedPayload.raw_job_debug_cleanup.raw_native_cleanup.JobActiveProcessCount -eq 1 -and
                $validatedCapturedPayload.raw_job_debug_cleanup.raw_process_evidence.raw_trace_retained -eq $true -and
                $validatedCapturedPayload.ordered_stream_paths.Count -eq 2 -and
                $validatedCapturedPayload.secondary_errors[0] -ceq 'selftest cleanup failure remains secondary')
        $diagnosticPathExpected = Join-Path $selfTestRoot $script:D32Phase0BlockedDiagnosticName
        $diagnosticInitiallyAbsent = -not (Test-D32Phase0DirectoryEntryExists -Path $diagnosticPathExpected)
        $diagnosticEntryDetected = $false
        $diagnosticWriteFailure = $null
        try {
            $diagnosticPath = Write-D32Phase0BlockedDiagnostic `
                -PrimaryError 'selftest primary failure' `
                -SecondaryErrors @('selftest secondary cleanup failure', (New-D32Phase0FixtureGitStatePrefixEvidence -States @($partialGitStates))) `
                -Command ([ordered]@{ name = 'selftest-fixed-command'; arguments = @('fetch', '--locked') }) `
                -ProcessIdentity $null `
                -RawV2Trace ([PSCustomObject]@{ record_type = 'D32_DEBUG_JOB_PROCESS_TRACE_V2'; schema_version = 2; state = 'BLOCKED'; event_chain_complete = $false; job_active_processes = 2 }) `
                -NativeCleanup ([PSCustomObject]@{ CleanupSucceeded = $false; JobCloseSucceeded = $false; JobActiveProcessCountVerified = $false; JobActiveProcessCount = 2 }) `
                -StdoutPath $emptyLogPath `
                -StderrPath (Join-Path $selfTestRoot 'missing-stderr.log')
            $diagnostic = [IO.File]::ReadAllText($diagnosticPath, [Text.Encoding]::UTF8) | ConvertFrom-D32Phase0Json
            $diagnosticEntryDetected = Test-D32Phase0DirectoryEntryExists -Path $diagnosticPath
            $diagnosticCapture = $diagnostic.ordered_stream_captures[0]
            $diagnosticCaptureIdentityValid = $diagnosticCapture.status -ceq 'CAPTURED' -and $diagnosticCapture.path -ceq $emptyLogPath -and
                $diagnosticCapture.reference.bytes -eq 0 -and $diagnosticCapture.reference.sha256 -ceq 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' -and
                $diagnosticCapture.reference.volume_serial_hex -cmatch '^[0-9a-f]{16}$' -and $diagnosticCapture.reference.file_id_hex -cmatch '^[0-9a-f]{32}$'
            $diagnosticBindingValid = $diagnostic.candidate_sha -ceq $candidate -and
                (Test-D32ProfilePathEqual -Left $diagnostic.toolchain_profile.path -Right $fakeProfile.ProfilePath) -and
                $diagnostic.toolchain_profile.sha256 -ceq $fakeProfile.Digest -and
                $diagnostic.toolchain_profile.file_identity.bytes -eq [Int64]$fakeProfile.Identity.Bytes -and
                $diagnostic.toolchain_profile.file_identity.volume_serial_hex -ceq [string]$fakeProfile.Identity.VolumeSerialHex -and
                $diagnostic.toolchain_profile.file_identity.file_id_hex -ceq [string]$fakeProfile.Identity.FileIdHex -and
                (Test-D32ProfilePathEqual -Left $diagnostic.evidence_root.path -Right $selfTestRoot) -and
                $diagnostic.evidence_root.volume_serial_hex -ceq [string]$ownerBinding.RootIdentity.VolumeSerialHex -and
                $diagnostic.evidence_root.file_id_hex -ceq [string]$ownerBinding.RootIdentity.FileIdHex -and
                (Test-D32ProfilePathEqual -Left $diagnostic.evidence_root.owner_marker.path -Right $ownerBinding.OwnerMarker.path) -and
                $diagnostic.evidence_root.owner_marker.bytes -eq [Int64]$ownerBinding.OwnerMarker.bytes -and
                $diagnostic.evidence_root.owner_marker.sha256 -ceq [string]$ownerBinding.OwnerMarker.sha256 -and
                $diagnostic.evidence_root.owner_marker.volume_serial_hex -ceq [string]$ownerBinding.OwnerMarker.volume_serial_hex -and
                $diagnostic.evidence_root.owner_marker.file_id_hex -ceq [string]$ownerBinding.OwnerMarker.file_id_hex
            $diagnosticInvalid = -not (Test-D32Phase0ExactProperties -Object $diagnostic -Expected @('schema_version', 'record_type', 'status', 'gate_authority', 'phase1_allowed', 'aggregate_allowed', 'candidate_sha', 'toolchain_profile', 'evidence_root', 'run_id', 'failing_fixed_command', 'process_identity', 'raw_v2_trace', 'unverified_fields', 'job_debug_cleanup', 'ordered_stream_captures', 'primary_error', 'secondary_errors', 'generated_at_utc')) -or
                $diagnostic.record_type -cne 'D32_PHASE0_BLOCKED_DIAGNOSTIC_V1' -or $diagnostic.status -cne 'BLOCKED' -or $diagnostic.gate_authority -cne 'NONE' -or
                $diagnostic.phase1_allowed -ne $false -or $diagnostic.aggregate_allowed -ne $false -or $diagnostic.run_id -cne $runId -or
                -not $diagnosticBindingValid -or
                $diagnostic.primary_error -cne 'selftest primary failure' -or @($diagnostic.secondary_errors | Where-Object { $_ -ceq 'selftest secondary cleanup failure' }).Count -ne 1 -or
                @($diagnostic.secondary_errors | Where-Object { $_ -ceq (New-D32Phase0FixtureGitStatePrefixEvidence -States @($partialGitStates)) }).Count -ne 1 -or
                $diagnostic.raw_v2_trace.record_type -cne 'D32_DEBUG_JOB_PROCESS_TRACE_V2' -or
                $diagnostic.job_debug_cleanup.verification -cne 'UNVERIFIED' -or @($diagnostic.job_debug_cleanup.unverified_fields).Count -eq 0 -or
                $diagnostic.job_debug_cleanup.raw_native_cleanup.CleanupSucceeded -ne $false -or $diagnostic.job_debug_cleanup.raw_native_cleanup.JobActiveProcessCount -ne 2 -or
                @($diagnostic.unverified_fields | Where-Object { $_ -ceq 'process_identity' -or $_ -ceq 'stream.stderr' }).Count -ne 2 -or
                $diagnostic.ordered_stream_captures.Count -ne 2 -or -not $diagnosticCaptureIdentityValid -or
                $diagnostic.ordered_stream_captures[1].status -cne 'UNAVAILABLE'
            if ($diagnosticInvalid) { throw 'blocked diagnostic did not preserve primary/secondary, raw V2 cleanup, and ordered capture identity/unverified evidence' }
            $diagnosticSnapshotBeforeCollision = Get-D32Phase0FileReference -Path $diagnosticPath
            $diagnosticCollisionRejected = $false
            try { $null = Write-D32Phase0BlockedDiagnostic -PrimaryError 'replacement failure' }
            catch { $diagnosticCollisionRejected = $_.Exception.Message -like '*refusing to overwrite an existing blocked-diagnostic sidecar*' }
            $diagnosticSnapshotAfterCollision = Get-D32Phase0FileReference -Path $diagnosticPath
            if (-not $diagnosticCollisionRejected -or $diagnosticSnapshotBeforeCollision.sha256 -cne $diagnosticSnapshotAfterCollision.sha256) { throw 'blocked diagnostic create-new collision overwrote or accepted an existing sidecar' }

            $ownedDiagnosticReference = Get-D32Phase0FileReference -Path $diagnosticPath
            if (-not (Test-D32ProfilePathWithin -Child $diagnosticPath -Parent $selfTestRoot) -or -not (Test-D32ProfileNoReparsePath -Path $diagnosticPath) -or
                (Get-D32Phase0FileReference -Path $diagnosticPath).sha256 -cne $ownedDiagnosticReference.sha256) { throw 'blocked diagnostic no-process self-test target is not the exact test-owned file' }
            [IO.File]::Delete($diagnosticPath)
            $noProcessDiagnosticPath = Write-D32Phase0BlockedDiagnostic `
                -PrimaryError 'selftest failure before process creation' `
                -Command $null `
                -ProcessIdentity $null `
                -RawV2Trace $null `
                -NativeCleanup $null `
                -StdoutPath $null `
                -StderrPath $null
            $noProcessDiagnostic = [IO.File]::ReadAllText($noProcessDiagnosticPath, [Text.Encoding]::UTF8) | ConvertFrom-D32Phase0Json
            $expectedUnverifiedNoProcess = @(
                'trace.dedicated_debugger_thread', 'trace.debugger_kill_on_exit_enabled', 'trace.debugger_thread_exited',
                'trace.debugger_thread_joined', 'trace.retained_process_handles_signaled', 'trace.debugger_association_query_verified',
                'trace.debugger_association_absent', 'trace.job_accounting_verified', 'trace.accounting_consistent',
                'trace.event_chain_complete', 'trace.job_active_processes', 'cleanup.CleanupSucceeded', 'cleanup.JobCloseSucceeded',
                'cleanup.JobActiveProcessCountVerified', 'cleanup.DebuggerThreadJoined', 'cleanup.RetainedProcessHandlesSignaled',
                'cleanup.DebuggerAssociationQueryVerified', 'cleanup.DebuggerAssociationAbsent'
            )
            $expectedContextUnverified = @('failing_fixed_command', 'process_identity', 'stream.stdout', 'stream.stderr')
            $missingNoProcessTraceFields = @($expectedUnverifiedNoProcess | Where-Object { $_ -notin @($noProcessDiagnostic.job_debug_cleanup.unverified_fields) })
            $missingNoProcessContextFields = @($expectedContextUnverified | Where-Object { $_ -notin @($noProcessDiagnostic.unverified_fields) })
            $noProcessUnverifiedValid = $null -eq $noProcessDiagnostic.raw_v2_trace -and $null -eq $noProcessDiagnostic.process_identity -and
                $null -eq $noProcessDiagnostic.failing_fixed_command -and $noProcessDiagnostic.job_debug_cleanup.verification -ceq 'UNVERIFIED' -and
                $null -eq $noProcessDiagnostic.job_debug_cleanup.raw_native_cleanup -and
                $noProcessDiagnostic.job_debug_cleanup.unverified_fields.Count -eq 18 -and $missingNoProcessTraceFields.Count -eq 0 -and
                $missingNoProcessContextFields.Count -eq 0 -and $noProcessDiagnostic.ordered_stream_captures.Count -eq 2 -and
                @($noProcessDiagnostic.ordered_stream_captures | Where-Object { $_.status -cne 'UNAVAILABLE' -or $null -ne $_.reference }).Count -eq 0
            & $add 'blocked diagnostic with no process creation leaves all 18 trace/cleanup fields explicitly UNVERIFIED' $noProcessUnverifiedValid

            $noProcessReference = Get-D32Phase0FileReference -Path $noProcessDiagnosticPath
            if (-not (Test-D32ProfilePathWithin -Child $noProcessDiagnosticPath -Parent $selfTestRoot) -or
                -not (Test-D32ProfileNoReparsePath -Path $noProcessDiagnosticPath) -or
                (Get-D32Phase0FileReference -Path $noProcessDiagnosticPath).sha256 -cne $noProcessReference.sha256) {
                throw 'blocked diagnostic snake-case cleanup self-test target is not the exact test-owned file'
            }
            [IO.File]::Delete($noProcessDiagnosticPath)
            $snakeCaseTrace = [ordered]@{
                record_type = 'D32_DEBUG_JOB_PROCESS_TRACE_V2'
                dedicated_debugger_thread = $true; debugger_kill_on_exit_enabled = $true; debugger_thread_exited = $true
                debugger_thread_joined = $true; retained_process_handles_signaled = $true
                debugger_association_query_verified = $true; debugger_association_absent = $true
                job_accounting_verified = $true; accounting_consistent = $false; event_chain_complete = $false; job_active_processes = 0
            }
            $snakeCaseCleanup = [ordered]@{
                cleanup_succeeded = $true; job_close_succeeded = $true; job_active_process_count_verified = $true
                job_active_process_count = 0
            }
            $snakeCaseDiagnosticPath = Write-D32Phase0BlockedDiagnostic `
                -PrimaryError 'selftest blocked after verified native cleanup' `
                -Command ([ordered]@{ name = 'selftest-fixed-cargo-command'; arguments = @('build', '--locked') }) `
                -ProcessIdentity ([ordered]@{ process_id = 30292; identity_verified = $false }) `
                -RawV2Trace $snakeCaseTrace `
                -NativeCleanup $snakeCaseCleanup `
                -StdoutPath $emptyStdoutPath `
                -StderrPath $emptyLogPath
            $snakeCaseDiagnostic = [IO.File]::ReadAllText($snakeCaseDiagnosticPath, [Text.Encoding]::UTF8) | ConvertFrom-D32Phase0Json
            $snakeCleanupFields = @($snakeCaseDiagnostic.job_debug_cleanup.unverified_fields | Where-Object { $_ -like 'cleanup.*' })
            $snakeTraceFields = @($snakeCaseDiagnostic.job_debug_cleanup.unverified_fields)
            $identityUnverified = @($snakeCaseDiagnostic.unverified_fields | Where-Object { $_ -ceq 'process_identity.identity_verified' }).Count -eq 1
            $snakeCaseCleanupValidated = $snakeCaseDiagnostic.job_debug_cleanup.verification -ceq 'UNVERIFIED' -and
                $snakeCleanupFields.Count -eq 0 -and $snakeTraceFields.Count -eq 2 -and
                $snakeTraceFields -contains 'trace.accounting_consistent' -and $snakeTraceFields -contains 'trace.event_chain_complete' -and
                $identityUnverified -and $snakeCaseDiagnostic.process_identity.identity_verified -eq $false
            & $add 'blocked diagnostic reads raw V2 snake-case cleanup precisely and marks incomplete process identity explicitly' $snakeCaseCleanupValidated
        }
        catch { $diagnosticWriteFailure = $_.Exception.Message }
        finally { $script:D32Phase0FailureContext = $previousFailureContext }
        & $add 'blocked diagnostic V1 preserves raw V2 failure and explicitly unverified Job/debug/capture fields without gate authority' ($null -eq $diagnosticWriteFailure) ([string]$diagnosticWriteFailure)
        & $add 'blocked diagnostic directory-entry probe distinguishes absence from a create-new sidecar' ($diagnosticInitiallyAbsent -and $diagnosticEntryDetected)
        $blockedRecordPath = Join-Path $selfTestRoot 'D32-PHASE0-MATRIX.json'
        [IO.File]::WriteAllText($blockedRecordPath, '{}', [Text.UTF8Encoding]::new($false))
        $blockedRecordSnapshot = Get-D32ProfileFileSnapshot -Path $blockedRecordPath
        $blockedRecordCheck = Test-D32Phase0MatrixRecord -RecordPath $blockedRecordPath -ExpectedRecordSha256 $blockedRecordSnapshot.Sha256 -Repository $testRepository -ExpectedCandidateSha $candidate -ToolchainProfilePath $fakeProfile.ProfilePath -ExpectedToolchainProfileSha256 $fakeProfile.Digest -GitPath 'C:\d32-selftest\git.exe' -GitSha256 ('c' * 64)
        & $add 'Phase1 Phase0 validator rejects any blocked-diagnostic sidecar before PASS record parsing' (-not $blockedRecordCheck.IsValid -and $blockedRecordCheck.Failure -like '*blocked-diagnostic sidecar exists*')
        $manifestSnapshot = Get-D32ProfileFileSnapshot -Path $manifestPath
        $profilePath = [string]$fakeProfile.ProfilePath
        $fakeCargoPath = [string]$fakeProfile.Profile.toolchain.cargo.path
        $fakeLockInputs = @($fakeProfile.LockInputs)
        $tauriArchivePath = $null
        if (-not [String]::IsNullOrWhiteSpace($env:USERPROFILE)) {
            $tauriArchiveCandidate = Join-Path (Join-Path $env:USERPROFILE '.cargo\registry\cache\index.crates.io-1949cf8c6b5b557f') 'tauri-macros-2.6.3.crate'
            if (Test-D32ProfileNoReparsePath -Path $tauriArchiveCandidate) { $tauriArchivePath = [IO.Path]::GetFullPath($tauriArchiveCandidate) }
        }
        if ([String]::IsNullOrWhiteSpace($tauriArchivePath)) { throw 'PHASE0_SELFTEST_BLOCKED: read-only local source cache lacks the exact locked tauri-macros 2.6.3 archive' }
        $tauriSourceAttesterPath = Join-Path $script:D32Phase0ScriptRoot 'd32-tauri-macros-source-attestation.ps1'
        if (-not (Test-D32ProfileNoReparsePath -Path $tauriSourceAttesterPath)) { throw 'PHASE0_SELFTEST_BLOCKED: exact source-patch facts generator is missing or reparse-backed' }
        $tauriSourceAuthorityPath = Join-Path $profileSelfTestRoot 'D32-TAURI-MACROS-SOURCE-PATCH-AUTHORITY.json'
        $tauriSourceFactsLines = @(& $tauriSourceAttesterPath -ArchivePath $tauriArchivePath -CandidateSha $candidate `
            -ToolchainProfilePath $fakeProfile.ProfilePath -ExpectedToolchainProfileSha256 $fakeProfile.Digest)
        if ($tauriSourceFactsLines.Count -ne 1 -or $tauriSourceFactsLines[0] -isnot [string]) { throw 'PHASE0_SELFTEST_BLOCKED: source-patch facts generator did not emit exactly one JSON document' }
        $tauriSourceFacts = ConvertFrom-D32Phase0Json -Json ([string]$tauriSourceFactsLines[0])
        $tauriSourceAuthorityReference = Write-D32VendoredProtocAuthorityCreateNew -Path $tauriSourceAuthorityPath -Document $tauriSourceFacts
        $tauriSourceAuthority = Test-D32TauriMacrosSourcePatchAuthority -AuthorityPath $tauriSourceAuthorityPath `
            -ExpectedAuthoritySha256 $tauriSourceAuthorityReference.sha256 -Repository $testRepository -CandidateSha $candidate `
            -ValidatedProfile $fakeProfile -EvidenceRoot $selfTestRoot
        $script:D32Phase0SelfTestSourcePatchAuthorityPath = [string]$tauriSourceAuthorityReference.path
        $script:D32Phase0SelfTestSourcePatchAuthoritySha256 = [string]$tauriSourceAuthorityReference.sha256
        & $add 'source-patch V1 authority binds exact locked archive, sole candidate-local wrapper patch, current profile, candidate, and opened external identity' `
            ($tauriSourceAuthority.Reference.sha256 -ceq $tauriSourceAuthorityReference.sha256 -and
                $tauriSourceFacts.record_type -ceq 'D32_TAURI_MACROS_SOURCE_PATCH_V1' -and
                $tauriSourceFacts.changed_files.Count -eq 1 -and $tauriSourceFacts.changed_files[0] -ceq 'src/command/wrapper.rs')
        $wrongSourceAuthorityShaRejected = $false
        try {
            $null = Test-D32TauriMacrosSourcePatchAuthority -AuthorityPath $tauriSourceAuthorityPath -ExpectedAuthoritySha256 ('0' * 64) `
                -Repository $testRepository -CandidateSha $candidate -ValidatedProfile $fakeProfile -EvidenceRoot $selfTestRoot
        }
        catch { $wrongSourceAuthorityShaRejected = $_.Exception.Message -like '*independent expected SHA-256*' }
        & $add 'source-patch reader rejects an authority whose bytes differ from its caller-pinned SHA' $wrongSourceAuthorityShaRejected
        $wrongSourceCandidateRejected = $false
        try {
            $null = Test-D32TauriMacrosSourcePatchAuthority -AuthorityPath $tauriSourceAuthorityPath -ExpectedAuthoritySha256 $tauriSourceAuthorityReference.sha256 `
                -Repository $testRepository -CandidateSha ('b' * 40) -ValidatedProfile $fakeProfile -EvidenceRoot $selfTestRoot
        }
        catch { $wrongSourceCandidateRejected = $_.Exception.Message -like '*exact source-patch schema/candidate/profile*' }
        & $add 'source-patch reader rejects a stale/wrong candidate binding' $wrongSourceCandidateRejected

        $expectedSelfTestLocks = @(Get-D32BuildToolchainLockInputs -Repository $testRepository)
        $lockProjectionExact = $fakeLockInputs.Count -eq 3 -and $expectedSelfTestLocks.Count -eq 3
        for ($lockIndex = 0; $lockIndex -lt [Math]::Min($fakeLockInputs.Count, $expectedSelfTestLocks.Count); $lockIndex++) {
            $actualLock = $fakeLockInputs[$lockIndex]
            $expectedLock = $expectedSelfTestLocks[$lockIndex]
            if (-not (Test-D32ProfileExactProperties -Object $actualLock -Expected @('ManifestPath', 'ManifestFullPath', 'LockPath', 'LockSha256', 'LockBytes')) -or
                $actualLock.ManifestPath -cne $expectedLock.ManifestPath -or
                $actualLock.ManifestFullPath -cne $expectedLock.ManifestFullPath -or
                $actualLock.LockPath -cne $expectedLock.LockPath -or
                $actualLock.LockSha256 -cne $expectedLock.LockSha256 -or
                $actualLock.LockBytes -ne $expectedLock.LockBytes) { $lockProjectionExact = $false }
        }
        & $add 'Phase0 provenance fixture uses all three exact profile-validator lock projections' $lockProjectionExact
        $fakeFetches = [System.Collections.Generic.List[object]]::new()
        $traceRecords = [System.Collections.Generic.List[object]]::new()
        $traceNames = @('fixture-01-fetch', 'fixture-02-fetch', 'fixture-03-fetch') + @($script:D32Phase0FixtureBuildSpecs | ForEach-Object { [string]$_.name })
        for ($traceIndex = 0; $traceIndex -lt $traceNames.Count; $traceIndex++) {
            if ($traceIndex -lt $fakeLockInputs.Count) {
                $lock = $fakeLockInputs[$traceIndex]
                $traceArguments = @('fetch', '--locked', '--manifest-path', $lock.ManifestFullPath, '--target', $fakeProfile.Profile.target_triple)
            }
            else {
                $spec = $script:D32Phase0FixtureBuildSpecs[$traceIndex - $fakeLockInputs.Count]
                $traceArguments = @('build', '--quiet', '--locked', '--manifest-path', [IO.Path]::GetFullPath((Join-Path $testRepository $spec.manifest)), '--bin', [string]$spec.binary)
                if ($spec.features.Count -gt 0) { $traceArguments += @('--features', ($spec.features -join ' ')) }
                $traceArguments += @('--jobs', '1')
            }
            $rootPid = 2000000000 + $traceIndex
            $trace = New-D32Phase0SelfTestDebugTrace -Profile $fakeProfile -RunnerProcessId $PID -RootProcessId $rootPid
            $root = $trace.processes[0]
            $traceRecords.Add([ordered]@{
                name = $traceNames[$traceIndex]
                executable = $fakeCargoPath
                arguments = @($traceArguments)
                command_line = ConvertTo-D32Phase0CommandLine -Arguments (@($fakeCargoPath) + $traceArguments)
                working_directory = $testRepository
                process_trace = $trace
            })
            if ($traceIndex -lt $fakeLockInputs.Count) {
                $fakeFetches.Add([ordered]@{
                    manifest_path = [string]$lock.ManifestPath
                    lock_sha256 = [string]$lock.LockSha256
                    command = @($traceArguments)
                    status = 'succeeded'
                    exit_code = 0
                    process_identity = [ordered]@{
                        process_id = [int]$root.process_id
                        parent_process_id = [int]$root.parent_process_id
                        name = 'cargo.exe'
                        image_path = [string]$root.image_path
                        creation_date = [DateTime]::FromFileTimeUtc([Int64]$root.creation_filetime).ToString('o')
                        command_line = [string]$traceRecords[$traceRecords.Count - 1].command_line
                        observed_at_utc = [string]$root.created_at_utc
                        identity_verified = $true
                    }
                })
            }
        }
        $sidecar = [ordered]@{
            schema_version = 5
            record_type = 'D32_FIXTURE_BUILD_PROVENANCE_V5'
            candidate_sha = $candidate
            source_repo = $testRepository
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
                fetch_manifests = @($fakeFetches.ToArray())
                offline_after_fetch = $true
            }
            storage = [ordered]@{
                evidence_root = [ordered]@{ path = $fixtureOutputRoot; volume_serial_hex = [string]$ownerBinding.RootIdentity.VolumeSerialHex; file_id_hex = [string]$ownerBinding.RootIdentity.FileIdHex }
                owner_marker = $ownerBinding.OwnerMarker
                run_root = [ordered]@{ path = $runRootIdentity.Path; volume_serial_hex = [string]$runRootIdentity.VolumeSerialHex; file_id_hex = [string]$runRootIdentity.FileIdHex }
                cargo_home = [ordered]@{ path = $cargoHomeIdentity.Path; volume_serial_hex = [string]$cargoHomeIdentity.VolumeSerialHex; file_id_hex = [string]$cargoHomeIdentity.FileIdHex }
                temp_root = [ordered]@{ path = $tempRootIdentity.Path; volume_serial_hex = [string]$tempRootIdentity.VolumeSerialHex; file_id_hex = [string]$tempRootIdentity.FileIdHex }
                run_id = $runId
            }
            process_traces = @($traceRecords.ToArray())
            vendored_protoc_run_grant = [ordered]@{
                path = (Join-Path $fixtureOutputRoot 'D32-PHASE0-VENDORED-PROTOC-RUN-GRANT.json')
                bytes = [Int64]1
                sha256 = ('a' * 64)
                volume_serial_hex = ('0' * 16)
                file_id_hex = ('0' * 32)
            }
            tauri_macros_source_patch = $tauriSourceAuthority.Reference
        }
        $writeSidecar = { param($value) [IO.File]::WriteAllText($sidecarPath, (ConvertTo-Json -InputObject $value -Depth 12), [Text.UTF8Encoding]::new($false)) }.GetNewClosure()
        & $writeSidecar $sidecar
        try {
            $validSidecar = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $fixtureOutputRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile
            & $add 'fixture build provenance v5 accepts exact owner-bound compact storage and manifest/profile/command/event evidence' ($validSidecar.Document.record_type -ceq 'D32_FIXTURE_BUILD_PROVENANCE_V5')
        }
        catch { & $add 'fixture build provenance v5 accepts exact owner-bound compact storage and manifest/profile/command/event evidence' $false $_.Exception.Message }

        $h7GitPath = 'E:\Program Files\Git\mingw64\bin\git.exe'
        $h7GitSnapshot = Get-D32ProfileFileSnapshot -Path $h7GitPath
        if ($h7GitSnapshot.Sha256 -cne '1f2ee2de971b6d0a7a13f053014998b66c22df47f30f1907a767346392eb8d78') { throw 'PHASE0_SELFTEST_BLOCKED: direct Git self-test image no longer matches its project pin' }
        $h7GitImage = [PSCustomObject]@{ Path = $h7GitSnapshot.Path; Bytes = [Int64]$h7GitSnapshot.Bytes; Sha256 = $h7GitSnapshot.Sha256; VolumeSerialHex = $h7GitSnapshot.VolumeSerialHex; FileIdHex = $h7GitSnapshot.FileIdHex }
        $h7AuthorityPath = Join-Path $profileSelfTestRoot 'D32-H7C-GIT-CHILD-AUTHORITY.json'
        $h7AuthorityDocument = Get-D32H7CGitAuthorityTemplate -Repository $testRepository -CandidateSha $candidate -ValidatedProfile $fakeProfile `
            -EvidenceRoot $selfTestRoot -TempRoot $tempRoot -GitImage $h7GitImage -TimeoutSeconds 1800
        $h7AuthorityReference = Write-D32H7CGitJsonCreateNew -Path $h7AuthorityPath -Document $h7AuthorityDocument
        $h7Authority = Test-D32H7CGitAuthority -AuthorityPath $h7AuthorityPath -ExpectedAuthoritySha256 $h7AuthorityReference.sha256 `
            -Repository $testRepository -CandidateSha $candidate -ValidatedProfile $fakeProfile -EvidenceRoot $selfTestRoot -TempRoot $tempRoot `
            -GitImage $h7GitImage -TimeoutSeconds 1800
        & $add 'H7-C external authority V1 pins only direct Git identity, exact Vita suite, fixed operations, slots, environment, and Job policy' `
            ($h7Authority.Reference.sha256 -ceq $h7AuthorityReference.sha256 -and $h7Authority.PolicySha256 -ceq $h7AuthorityDocument.policy_sha256)
        $h7WrongAuthorityShaRejected = $false
        try {
            $null = Test-D32H7CGitAuthority -AuthorityPath $h7AuthorityPath -ExpectedAuthoritySha256 ('0' * 64) -Repository $testRepository `
                -CandidateSha $candidate -ValidatedProfile $fakeProfile -EvidenceRoot $selfTestRoot -TempRoot $tempRoot -GitImage $h7GitImage -TimeoutSeconds 1800
        }
        catch { $h7WrongAuthorityShaRejected = $_.Exception.Message -like '*caller-pinned SHA-256*' }
        $h7WrongAuthorityCandidateRejected = $false
        try {
            $null = Test-D32H7CGitAuthority -AuthorityPath $h7AuthorityPath -ExpectedAuthoritySha256 $h7AuthorityReference.sha256 -Repository $testRepository `
                -CandidateSha ('f' * 40) -ValidatedProfile $fakeProfile -EvidenceRoot $selfTestRoot -TempRoot $tempRoot -GitImage $h7GitImage -TimeoutSeconds 1800
        }
        catch { $h7WrongAuthorityCandidateRejected = $_.Exception.Message -like '*strict authority schema/candidate/profile/fresh path binding differs*' }
        $h7WrongAuthorityImageRejected = $false
        try {
            $wrongGitImage = [PSCustomObject]@{ Path = $h7GitImage.Path; Bytes = $h7GitImage.Bytes; Sha256 = ('0' * 64); VolumeSerialHex = $h7GitImage.VolumeSerialHex; FileIdHex = $h7GitImage.FileIdHex }
            $null = Test-D32H7CGitAuthority -AuthorityPath $h7AuthorityPath -ExpectedAuthoritySha256 $h7AuthorityReference.sha256 -Repository $testRepository `
                -CandidateSha $candidate -ValidatedProfile $fakeProfile -EvidenceRoot $selfTestRoot -TempRoot $tempRoot -GitImage $wrongGitImage -TimeoutSeconds 1800
        }
        catch { $h7WrongAuthorityImageRejected = $_.Exception.Message -like '*exact caller-pinned direct Git image identity differs*' }
        & $add 'H7-C authority rejects wrong SHA, stale candidate, and mismatched Git image identity' `
            ($h7WrongAuthorityShaRejected -and $h7WrongAuthorityCandidateRejected -and $h7WrongAuthorityImageRejected)
        $h7OwnerBinding = Test-D32Phase0OwnerBinding -EvidenceRoot $selfTestRoot -ExpectedCandidateSha $candidate -ValidatedProfile $fakeProfile `
            -ExpectedRunId $runId -ExpectedRootIdentity $ownerBinding.RootIdentity -ExpectedMarkerReference $ownerBinding.OwnerMarker
        $h7RunGrant = New-D32H7CGitRunGrant -Authority $h7Authority -Repository $testRepository -CandidateSha $candidate -ValidatedProfile $fakeProfile `
            -EvidenceRoot $selfTestRoot -TempRoot $tempRoot -RunId $runId -OwnerMarker $ownerBinding.OwnerMarker -GitImage $h7GitImage
        $h7RunGrantValidated = Test-D32H7CGitRunGrant -Reference $h7RunGrant.Reference -Authority $h7Authority -Repository $testRepository `
            -CandidateSha $candidate -ValidatedProfile $fakeProfile -EvidenceRoot $selfTestRoot -TempRoot $tempRoot -RunId $runId `
            -OwnerMarker $ownerBinding.OwnerMarker -GitImage $h7GitImage
        & $add 'H7-C per-run grant creates exactly 35 fresh owner-bound slots with opened directory and empty-config identities' `
            ($h7RunGrantValidated.Slots.Count -eq 35 -and $h7RunGrantValidated.Document.status -ceq 'BOUND' -and
                $h7RunGrantValidated.Slots[0].slot -ceq 'd32-h7c-slot-01' -and $h7RunGrantValidated.Slots[34].slot -ceq 'd32-h7c-slot-35')
        $h7WrongRunRejected = $false
        try {
            $null = Test-D32H7CGitRunGrant -Reference $h7RunGrant.Reference -Authority $h7Authority -Repository $testRepository -CandidateSha $candidate `
                -ValidatedProfile $fakeProfile -EvidenceRoot $selfTestRoot -TempRoot $tempRoot -RunId ('f' * 32) -OwnerMarker $ownerBinding.OwnerMarker -GitImage $h7GitImage
        }
        catch { $h7WrongRunRejected = $_.Exception.Message -like '*per-run grant candidate/profile/owner/root/temp/image/policy binding is invalid*' }
        $h7WrongTempRootRejected = $false
        try {
            $null = Test-D32H7CGitRunGrant -Reference $h7RunGrant.Reference -Authority $h7Authority -Repository $testRepository -CandidateSha $candidate `
                -ValidatedProfile $fakeProfile -EvidenceRoot $selfTestRoot -TempRoot (Join-Path $profileSelfTestRoot 'wrong-temp-root') -RunId $runId `
                -OwnerMarker $ownerBinding.OwnerMarker -GitImage $h7GitImage
        }
        catch { $h7WrongTempRootRejected = $_.Exception.Message -like '*grant file reference/path is not fixed*' }
        $wrongH7Owner = [ordered]@{}
        foreach ($field in $ownerBinding.OwnerMarker.Keys) { $wrongH7Owner[$field] = $ownerBinding.OwnerMarker[$field] }
        $wrongH7Owner.file_id_hex = 'f' * 32
        $h7WrongOwnerRejected = $false
        try {
            $null = Test-D32H7CGitRunGrant -Reference $h7RunGrant.Reference -Authority $h7Authority -Repository $testRepository -CandidateSha $candidate `
                -ValidatedProfile $fakeProfile -EvidenceRoot $selfTestRoot -TempRoot $tempRoot -RunId $runId -OwnerMarker $wrongH7Owner -GitImage $h7GitImage
        }
        catch { $h7WrongOwnerRejected = $_.Exception.Message -like '*per-run grant candidate/profile/owner/root/temp/image/policy binding is invalid*' }
        $h7WrongRootRejected = $false
        try {
            $null = Test-D32H7CGitRunGrant -Reference $h7RunGrant.Reference -Authority $h7Authority -Repository $testRepository -CandidateSha $candidate `
                -ValidatedProfile $fakeProfile -EvidenceRoot (Join-Path $profileSelfTestRoot 'wrong-root') -TempRoot $tempRoot -RunId $runId `
                -OwnerMarker $ownerBinding.OwnerMarker -GitImage $h7GitImage
        }
        catch { $h7WrongRootRejected = $_.Exception.Message -like '*grant file reference/path is not fixed*' }
        & $add 'H7-C run-grant reader rejects stale/wrong run ID, EvidenceRoot, TempRoot, and owner identity' `
            ($h7WrongRunRejected -and $h7WrongRootRejected -and $h7WrongTempRootRejected -and $h7WrongOwnerRejected)
        $h7SuiteLogRoot = Join-Path $selfTestRoot 'h7c-suite-logs'
        [void][IO.Directory]::CreateDirectory($h7SuiteLogRoot)
        $h7SuiteStdout = Join-Path $h7SuiteLogRoot 'vita-full-local-suite.stdout.log'
        $h7SuiteStderr = Join-Path $h7SuiteLogRoot 'vita-full-local-suite.stderr.log'
        $h7SuiteLines = [System.Collections.Generic.List[string]]::new()
        foreach ($h7Name in $script:D32H7CGitTestInventory) { $h7SuiteLines.Add("test d29h7::tests::$h7Name ... ok") }
        $h7SuiteLines.Add('test result: ok. 46 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s')
        [IO.File]::WriteAllLines($h7SuiteStdout, $h7SuiteLines.ToArray(), [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($h7SuiteStderr, '', [Text.UTF8Encoding]::new($false))
        $h7SuiteArgs = @(Get-D32Phase0TestCommand -Package 'vita' -Kind 'suite')
        $h7SuiteTrace = New-D32Phase0SelfTestDebugTrace -Profile $fakeProfile -RunnerProcessId $PID -RootProcessId 2000001234
        $h7SuiteCommand = [PSCustomObject][ordered]@{
            name = 'vita-full-local-suite'
            executable = [string]$fakeProfile.Profile.toolchain.cargo.path
            executable_sha256 = [string]$fakeProfile.Profile.toolchain.cargo.sha256
            executable_bytes = [Int64]$fakeProfile.Profile.toolchain.cargo.bytes
            executable_volume_serial_hex = [string]$fakeProfile.Profile.toolchain.cargo.volume_serial_hex
            executable_file_id_hex = [string]$fakeProfile.Profile.toolchain.cargo.file_id_hex
            arguments = $h7SuiteArgs
            command_line = ConvertTo-D32Phase0CommandLine -Arguments (@([string]$fakeProfile.Profile.toolchain.cargo.path) + $h7SuiteArgs)
            working_directory = $testRepository
            exit_code = 0
            process_trace = $h7SuiteTrace
            stdout = Get-D32Phase0FileReference -Path $h7SuiteStdout
            stderr = Get-D32Phase0FileReference -Path $h7SuiteStderr
        }
        $h7Attestation = New-D32H7CGitChildAttestation -Authority $h7Authority -RunGrant $h7RunGrant -OwnerBinding $h7OwnerBinding `
            -Phase0Command $h7SuiteCommand -SuiteLines $h7SuiteLines.ToArray() -GitChildren @() -Repository $testRepository -CandidateSha $candidate `
            -ValidatedProfile $fakeProfile -EvidenceRoot $selfTestRoot -TempRoot $tempRoot -GitImage $h7GitImage
        $h7AttestationValidated = Test-D32H7CGitChildAttestation -Reference $h7Attestation.Reference -Authority $h7Authority -RunGrant $h7RunGrant `
            -OwnerBinding $h7OwnerBinding -Phase0Command $h7SuiteCommand -Repository $testRepository -CandidateSha $candidate -ValidatedProfile $fakeProfile `
            -EvidenceRoot $selfTestRoot -TempRoot $tempRoot -GitImage $h7GitImage
        & $add 'H7-C companion validates the fixed full-suite command, all 46 H7-C results, Trace V2 link, and zero unobserved Git children' `
            ($h7AttestationValidated.Reference.sha256 -ceq $h7Attestation.Reference.sha256 -and $h7AttestationValidated.Document.git_child_count -eq 0 -and $h7AttestationValidated.Document.test_inventory.Count -eq 46)
        $h7MissingTestRejected = $false
        try { $null = Get-D32H7CGitTestResults -Lines @($h7SuiteLines.ToArray() | Where-Object { $_ -notmatch 'h7c_git_status_schema_is_fixed' }) }
        catch { $h7MissingTestRejected = $_.Exception.Message -like '*required H7-C test result is absent*' }
        $h7DuplicateTestRejected = $false
        try { $null = Get-D32H7CGitTestResults -Lines (@($h7SuiteLines.ToArray()) + 'test d29h7::tests::h7c_git_status_schema_is_fixed ... ok') }
        catch { $h7DuplicateTestRejected = $_.Exception.Message -like '*duplicate H7-C test result row*' }
        $h7FailedTestRejected = $false
        try { $null = Get-D32H7CGitTestResults -Lines @($h7SuiteLines.ToArray() | ForEach-Object { $_ -replace 'h7c_git_status_schema_is_fixed \.\.\. ok$', 'h7c_git_status_schema_is_fixed ... FAILED' }) }
        catch { $h7FailedTestRejected = $_.Exception.Message -like '*required H7-C test did not pass*' }
        & $add 'H7-C result parser rejects missing, duplicate, and failed required inventory rows' ($h7MissingTestRejected -and $h7DuplicateTestRejected -and $h7FailedTestRejected)

        $vctipTraceProfile = [PSCustomObject]@{
            Profile = $fakeProfile.Profile
            ExecutableInventory = @($fakeProfile.ExecutableInventory) + @($approvedVctipRecord)
            WindowsImageInventory = @($fakeProfile.WindowsImageInventory)
        }
        $vctipTrace = ConvertFrom-D32Phase0Json -Json (ConvertTo-Json -InputObject $traceRecords[0].process_trace -Depth 12 -Compress)
        $vctipRootRecord = ConvertFrom-D32Phase0Json -Json (ConvertTo-Json -InputObject $vctipTrace.processes[0] -Depth 8 -Compress)
        $vctipRootPid = [uint32]$vctipRootRecord.process_id
        $vctipRootCreation = [Int64]$vctipRootRecord.creation_filetime
        $vctipChildPid = $vctipRootPid + 300
        $vctipChildCreation = $vctipRootCreation + 10
        $vctipChildCreatedAt = [DateTime]::FromFileTimeUtc($vctipChildCreation).ToString('o')
        $vctipChildExitCreation = $vctipRootCreation + 20
        $vctipChildExitAt = [DateTime]::FromFileTimeUtc($vctipChildExitCreation).ToString('o')
        $vctipRootExitCreation = $vctipRootCreation + 30
        $vctipRootExitAt = [DateTime]::FromFileTimeUtc($vctipRootExitCreation).ToString('o')
        $vctipRootRecord.exit_sequence = 4
        $vctipRootRecord.exited_at_utc = $vctipRootExitAt
        $vctipChildRecord = [PSCustomObject][ordered]@{
            process_id = $vctipChildPid; parent_process_id = $vctipRootPid
            creation_filetime = $vctipChildCreation; parent_creation_filetime = $vctipRootCreation
            image_path = $approvedVctipRecord.Path; bytes = [Int64]$approvedVctipRecord.Bytes
            sha256 = $approvedVctipRecord.Sha256; volume_serial_hex = $approvedVctipRecord.VolumeSerialHex
            file_id_hex = $approvedVctipRecord.FileIdHex
            allowed_image_reason = 'caller-pinned-msvc-vctip-descendant-of-fixed-cargo-root'
            image_verified = $true; exited = $true; exit_code = 0; create_sequence = 2; exit_sequence = 3
            created_at_utc = $vctipChildCreatedAt; exited_at_utc = $vctipChildExitAt
        }
        $vctipTrace.process_events = @(
            [PSCustomObject][ordered]@{ sequence = 1; kind = 'CREATE'; process_id = $vctipRootPid; parent_process_id = [uint32]$vctipRootRecord.parent_process_id; creation_filetime = $vctipRootCreation; parent_creation_filetime = [Int64]$vctipRootRecord.parent_creation_filetime; exit_code = 0 },
            [PSCustomObject][ordered]@{ sequence = 2; kind = 'CREATE'; process_id = $vctipChildPid; parent_process_id = $vctipRootPid; creation_filetime = $vctipChildCreation; parent_creation_filetime = $vctipRootCreation; exit_code = 0 },
            [PSCustomObject][ordered]@{ sequence = 3; kind = 'EXIT'; process_id = $vctipChildPid; parent_process_id = $vctipRootPid; creation_filetime = $vctipChildCreation; parent_creation_filetime = $vctipRootCreation; exit_code = 0 },
            [PSCustomObject][ordered]@{ sequence = 4; kind = 'EXIT'; process_id = $vctipRootPid; parent_process_id = [uint32]$vctipRootRecord.parent_process_id; creation_filetime = $vctipRootCreation; parent_creation_filetime = [Int64]$vctipRootRecord.parent_creation_filetime; exit_code = 0 }
        )
        $vctipTrace.processes = @($vctipRootRecord, $vctipChildRecord)
        $vctipTrace.process_create_event_count = 2; $vctipTrace.process_exit_event_count = 2; $vctipTrace.process_event_count = 4
        $vctipTrace.debug_event_count = [Int64]$vctipTrace.process_event_count + [Int64]$vctipTrace.thread_create_event_count +
            [Int64]$vctipTrace.thread_exit_event_count + [Int64]$vctipTrace.image_load_event_count +
            [Int64]$vctipTrace.image_unload_event_count + [Int64]$vctipTrace.exception_event_count +
            [Int64]$vctipTrace.debug_string_event_count
        $vctipTrace.job_total_processes = 2; $vctipTrace.retained_process_handle_count = 3
        $vctipTraceAccepted = $false
        $vctipTraceFailure = $null
        try {
            $null = Test-D32Phase0DebugProcessTrace -Trace $vctipTrace -ExpectedRootPath $fakeCargoPath `
                -ExpectedRootIdentity $fakeProfile.Profile.toolchain.cargo -ExpectedParentProcessId $PID `
                -ValidatedProfile $vctipTraceProfile -Repository $testRepository
            $vctipTraceAccepted = $true
        }
        catch { $vctipTraceFailure = $_.Exception.Message }
        & $add 'V2 process-trace validator accepts only an exact VCTIP image with the fixed Cargo root and retained parent chain' $vctipTraceAccepted ([string]$vctipTraceFailure)

        $protocTrace = ConvertFrom-D32Phase0Json -Json (ConvertTo-Json -InputObject $vctipTrace -Depth 12 -Compress)
        $protocTraceImagePath = Join-Path $cargoHome 'registry\src\index.crates.io-1949cf8c6b5b557f\protoc-bin-vendored-win32-3.2.0\bin\protoc.exe'
        $protocTraceImage = [PSCustomObject]@{
            Path = $protocTraceImagePath; Bytes = [Int64]11934496
            Sha256 = 'cbd1ca1fd6afd1bb6ddd1c09c118ecd4c50f928980857f16fe6fc23704ea17e2'
            VolumeSerialHex = '0123456789abcdef'; FileIdHex = '0123456789abcdef0123456789abcdef'
        }
        $protocTraceGrant = [PSCustomObject]@{
            Image = $protocTraceImage
            Document = [PSCustomObject]@{ cargo_home = [PSCustomObject]@{ path = $cargoHome } }
        }
        $protocTrace.processes[1].image_path = $protocTraceImage.Path
        $protocTrace.processes[1].bytes = [Int64]$protocTraceImage.Bytes
        $protocTrace.processes[1].sha256 = $protocTraceImage.Sha256
        $protocTrace.processes[1].volume_serial_hex = $protocTraceImage.VolumeSerialHex
        $protocTrace.processes[1].file_id_hex = $protocTraceImage.FileIdHex
        $protocTrace.processes[1].allowed_image_reason = 'caller-pinned-locked-vendored-protoc-descendant-of-fixed-cargo-root'
        $protocTraceFailure = $null
        try {
            $null = Test-D32Phase0DebugProcessTrace -Trace $protocTrace -ExpectedRootPath $fakeCargoPath `
                -ExpectedRootIdentity $fakeProfile.Profile.toolchain.cargo -ExpectedParentProcessId $PID `
                -ValidatedProfile $vctipTraceProfile -Repository $testRepository -VendoredProtocGrant $protocTraceGrant
            $protocTraceAccepted = $true
        }
        catch { $protocTraceFailure = $_.Exception.Message; $protocTraceAccepted = $false }
        & $add 'V2 trace accepts only the exact locked protoc path and hFile identity under its owner-bound run CargoHome' $protocTraceAccepted ([string]$protocTraceFailure)
        $protocTraceWithoutGrantRejected = $false
        try {
            $null = Test-D32Phase0DebugProcessTrace -Trace $protocTrace -ExpectedRootPath $fakeCargoPath `
                -ExpectedRootIdentity $fakeProfile.Profile.toolchain.cargo -ExpectedParentProcessId $PID `
                -ValidatedProfile $vctipTraceProfile -Repository $testRepository
        }
        catch { $protocTraceWithoutGrantRejected = $_.Exception.Message -like '*outside exact pinned inventory*' }
        & $add 'V2 trace denies locked protoc when the per-run owner grant is absent' $protocTraceWithoutGrantRejected
        $protocTraceDriftRejected = $true
        foreach ($mutation in @(
            [PSCustomObject]@{ Field = 'bytes'; Value = [Int64]11934497 },
            [PSCustomObject]@{ Field = 'sha256'; Value = ('0' * 64) },
            [PSCustomObject]@{ Field = 'volume_serial_hex'; Value = '0123456789abcdee' },
            [PSCustomObject]@{ Field = 'file_id_hex'; Value = '0123456789abcdef0123456789abcdee' }
        )) {
            $driftedProtocTrace = ConvertFrom-D32Phase0Json -Json (ConvertTo-Json -InputObject $protocTrace -Depth 12 -Compress)
            $driftedProtocTrace.processes[1].($mutation.Field) = $mutation.Value
            try {
                $null = Test-D32Phase0DebugProcessTrace -Trace $driftedProtocTrace -ExpectedRootPath $fakeCargoPath `
                    -ExpectedRootIdentity $fakeProfile.Profile.toolchain.cargo -ExpectedParentProcessId $PID `
                    -ValidatedProfile $vctipTraceProfile -Repository $testRepository -VendoredProtocGrant $protocTraceGrant
                $protocTraceDriftRejected = $false
                break
            }
            catch { }
        }
        & $add 'V2 trace rejects protoc opened hFile bytes/hash/volume/file-ID drift' $protocTraceDriftRejected
        $protocOldHomeTrace = ConvertFrom-D32Phase0Json -Json (ConvertTo-Json -InputObject $protocTrace -Depth 12 -Compress)
        $protocOldHomeTrace.processes[1].image_path = Join-Path (Join-Path $selfTestRoot 'old-r-c') 'registry\src\index.crates.io-1949cf8c6b5b557f\protoc-bin-vendored-win32-3.2.0\bin\protoc.exe'
        $protocOldHomeTraceRejected = $false
        $protocOldHomeTraceFailure = $null
        try {
            $null = Test-D32Phase0DebugProcessTrace -Trace $protocOldHomeTrace -ExpectedRootPath $fakeCargoPath `
                -ExpectedRootIdentity $fakeProfile.Profile.toolchain.cargo -ExpectedParentProcessId $PID `
                -ValidatedProfile $vctipTraceProfile -Repository $testRepository -VendoredProtocGrant $protocTraceGrant
        }
        catch { $protocOldHomeTraceFailure = $_.Exception.Message; $protocOldHomeTraceRejected = $protocOldHomeTraceFailure -like '*PROCESS_TRACE_BLOCKED*' }
        & $add 'V2 trace rejects a protoc image sourced from a prior/non-owner CargoHome' $protocOldHomeTraceRejected ([string]$protocOldHomeTraceFailure)
        $renamedProtocTrace = ConvertFrom-D32Phase0Json -Json (ConvertTo-Json -InputObject $protocTrace -Depth 12 -Compress)
        $renamedProtocTrace.processes[1].image_path = $protocTraceImagePath.Replace('protoc.exe', 'protoc-copy.exe')
        $renamedProtocTraceRejected = $false
        try {
            $null = Test-D32Phase0DebugProcessTrace -Trace $renamedProtocTrace -ExpectedRootPath $fakeCargoPath `
                -ExpectedRootIdentity $fakeProfile.Profile.toolchain.cargo -ExpectedParentProcessId $PID `
                -ValidatedProfile $vctipTraceProfile -Repository $testRepository -VendoredProtocGrant $protocTraceGrant
        }
        catch { $renamedProtocTraceRejected = $_.Exception.Message -like '*outside exact pinned inventory*' }
        & $add 'V2 trace rejects copied or renamed vendored protoc content before evidence acceptance' $renamedProtocTraceRejected

        $unknownVctipParent = ConvertFrom-D32Phase0Json -Json (ConvertTo-Json -InputObject $vctipTrace -Depth 12 -Compress)
        $unknownVctipParent.process_events[1].parent_process_id = $vctipChildPid + 1
        $unknownVctipParentRejected = $false
        $unknownVctipParentFailure = $null
        try {
            $null = Test-D32Phase0DebugProcessTrace -Trace $unknownVctipParent -ExpectedRootPath $fakeCargoPath `
                -ExpectedRootIdentity $fakeProfile.Profile.toolchain.cargo -ExpectedParentProcessId $PID `
                -ValidatedProfile $vctipTraceProfile -Repository $testRepository
        }
        catch { $unknownVctipParentFailure = $_.Exception.Message; $unknownVctipParentRejected = $unknownVctipParentFailure -like '*parent identity is unknown, exited, or ambiguous*' }
        & $add 'VCTIP CREATE with an unknown or non-retained parent is rejected by V2 event-chain validation' $unknownVctipParentRejected ([string]$unknownVctipParentFailure)
        $driftedVctipTrace = ConvertFrom-D32Phase0Json -Json (ConvertTo-Json -InputObject $vctipTrace -Depth 12 -Compress)
        $driftedVctipTrace.processes[1].file_id_hex = '0b5d2000000001000000000000000001'
        $driftedVctipTraceRejected = $false
        $driftedVctipTraceFailure = $null
        try {
            $null = Test-D32Phase0DebugProcessTrace -Trace $driftedVctipTrace -ExpectedRootPath $fakeCargoPath `
                -ExpectedRootIdentity $fakeProfile.Profile.toolchain.cargo -ExpectedParentProcessId $PID `
                -ValidatedProfile $vctipTraceProfile -Repository $testRepository
        }
        catch {
            $driftedVctipTraceFailure = $_.Exception.Message
            $driftedVctipTraceRejected = $driftedVctipTraceFailure -like '*outside exact pinned inventory*' -or $driftedVctipTraceFailure -like '*caller-pinned child image changed*'
        }
        & $add 'V2 trace rejects a VCTIP opened file-ID mismatch before evidence acceptance' $driftedVctipTraceRejected ([string]$driftedVctipTraceFailure)

        $unclassifiedEventTrace = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $unclassifiedEventTrace.process_traces[0].process_trace.debug_event_count++
        & $writeSidecar $unclassifiedEventTrace
        $unclassifiedEventRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $unclassifiedEventRejected = $_.Exception.Message -like '*PROCESS_TRACE_BLOCKED*' }
        & $add 'debug event total rejects unclassified or missing event records' $unclassifiedEventRejected

        $stringProcessEventCount = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $stringProcessEventCount.process_traces[0].process_trace.process_event_count = '2'
        & $writeSidecar $stringProcessEventCount
        $stringProcessEventCountRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $stringProcessEventCountRejected = $_.Exception.Message -like '*PROCESS_TRACE_BLOCKED*' }
        & $add 'debug process event count rejects numeric string coercion' $stringProcessEventCountRejected

        $oldTraceRecord = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $oldTrace = $oldTraceRecord.process_traces[0].process_trace
        $oldTrace.record_type = 'D32_DEBUG_JOB_PROCESS_TRACE_V2'
        $oldTrace.schema_version = 2
        $oldTrace.event_source = 'Win32-WaitForDebugEvent-synchronous'
        foreach ($field in @('uncontinued_create_process_id', 'uncontinued_create_continue_call_count', 'debugger_thread_id', 'dedicated_debugger_thread', 'debugger_kill_on_exit_enabled', 'root_resumed_after_kill_on_exit',
                'debugger_thread_exited', 'debugger_thread_joined', 'retained_process_handle_count', 'retained_process_handles_signaled',
                'debugger_association_query_verified', 'debugger_association_absent')) { $oldTrace.Remove($field) }
        & $writeSidecar $oldTraceRecord
        $oldTraceRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $oldTraceRejected = $_.Exception.Message -like '*PROCESS_TRACE_BLOCKED*' }
        & $add 'previous synchronous process trace V2 shape is rejected under approved dedicated-thread trace V2 contract' $oldTraceRejected

        $v1TraceRecord = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $v1TraceRecord.process_traces[0].process_trace.record_type = 'D32_DEBUG_JOB_PROCESS_TRACE_V1'
        $v1TraceRecord.process_traces[0].process_trace.schema_version = 1
        & $writeSidecar $v1TraceRecord
        $v1TraceRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $v1TraceRejected = $_.Exception.Message -like '*PROCESS_TRACE_BLOCKED*' }
        & $add 'previous process trace V1 is rejected' $v1TraceRejected

        $missingThreadProof = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $missingThreadProof.process_traces[0].process_trace.debugger_kill_on_exit_enabled = $false
        & $writeSidecar $missingThreadProof
        $missingThreadProofRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $missingThreadProofRejected = $_.Exception.Message -like '*PROCESS_TRACE_BLOCKED*' }
        & $add 'process trace rejects a missing debugger kill-on-exit proof' $missingThreadProofRejected

        $missingExitTrace = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $missingExitTrace.process_traces[0].process_trace.process_events = @($missingExitTrace.process_traces[0].process_trace.process_events[0])
        & $writeSidecar $missingExitTrace
        $missingExitRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $missingExitRejected = $_.Exception.Message -like '*PROCESS_TRACE_BLOCKED*' }
        & $add 'missing debug EXIT event is rejected' $missingExitRejected

        $reusedPidTrace = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $reuseTrace = $reusedPidTrace.process_traces[0].process_trace
        $createAgain = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($reuseTrace.process_events[0]))
        $createAgain.sequence = 2
        $exitAgain = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($reuseTrace.process_events[1]))
        $exitAgain.sequence = 4
        $firstExit = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($reuseTrace.process_events[1]))
        $firstExit.sequence = 3
        $reuseTrace.process_events = @($reuseTrace.process_events[0], $createAgain, $firstExit, $exitAgain)
        $reuseTrace.processes = @($reuseTrace.processes[0], [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($reuseTrace.processes[0])))
        $reuseTrace.processes[1].create_sequence = 2
        $reuseTrace.processes[1].exit_sequence = 4
        $reuseTrace.process_create_event_count = 2
        $reuseTrace.process_exit_event_count = 2
        $reuseTrace.process_event_count = 4
        $reuseTrace.debug_event_count = 4
        $reuseTrace.job_total_processes = 2
        & $writeSidecar $reusedPidTrace
        $pidReuseRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $pidReuseRejected = $_.Exception.Message -like '*PROCESS_TRACE_BLOCKED*' }
        & $add 'overlapping PID reuse without a distinct live identity is rejected' $pidReuseRejected

        $ambiguousParentTrace = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $ambiguousParentTrace.process_traces[0].process_trace.process_events[0].parent_process_id = $PID + 1
        & $writeSidecar $ambiguousParentTrace
        $ambiguousParentRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $ambiguousParentRejected = $_.Exception.Message -like '*PROCESS_TRACE_BLOCKED*' }
        & $add 'unknown root parent identity is rejected' $ambiguousParentRejected

        $interruptedTrace = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $interruptedTrace.process_traces[0].process_trace.injected_interruption = $true
        & $writeSidecar $interruptedTrace
        $interruptionRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $interruptionRejected = $_.Exception.Message -like '*PROCESS_TRACE_BLOCKED*' }
        & $add 'debug-chain interruption is rejected' $interruptionRejected

        $oldV2Provenance = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $oldV2Provenance.schema_version = 2
        $oldV2Provenance.record_type = 'D32_FIXTURE_BUILD_PROVENANCE_V2'
        & $writeSidecar $oldV2Provenance
        $oldV2ProvenanceRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $oldV2ProvenanceRejected = $_.Exception.Message -like '*schema/candidate/source/manifest binding is invalid*' }
        & $add 'fixture provenance rejects prior V2 compact-layout schema even with a fresh exact file' $oldV2ProvenanceRejected

        $oldV3Provenance = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $oldV3Provenance.schema_version = 4
        $oldV3Provenance.record_type = 'D32_FIXTURE_BUILD_PROVENANCE_V4'
        & $writeSidecar $oldV3Provenance
        $oldV4ProvenanceRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $oldV4ProvenanceRejected = $_.Exception.Message -like '*schema/candidate/source/manifest binding is invalid*' }
        & $add 'fixture provenance rejects prior V4 after the source-patch authority migration' $oldV4ProvenanceRejected

        $unknownV4Provenance = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $unknownV4Provenance.schema_version = 99
        $unknownV4Provenance.record_type = 'D32_FIXTURE_BUILD_PROVENANCE_V99'
        & $writeSidecar $unknownV4Provenance
        $unknownV4ProvenanceRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $unknownV4ProvenanceRejected = $_.Exception.Message -like '*schema/candidate/source/manifest binding is invalid*' }
        & $add 'fixture provenance rejects unknown future version instead of guessing its layout' $unknownV4ProvenanceRejected

        $oldProvenance = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $oldProvenance.schema_version = 1
        $oldProvenance.record_type = 'D32_FIXTURE_BUILD_PROVENANCE_V1'
        $oldProvenance.Remove('process_traces')
        & $writeSidecar $oldProvenance
        $oldProvenanceRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $oldProvenanceRejected = $_.Exception.Message -like '*schema/candidate/source/manifest binding is invalid*' }
        & $add 'fixture provenance V1 without synchronized process traces is rejected' $oldProvenanceRejected

        $missingEnvironmentField = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $missingEnvironmentField.environment.Remove('run_id')
        & $writeSidecar $missingEnvironmentField
        $missingRejected = $false
        $missingFailure = $null
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $missingRejected = $_.Exception.Message -like '*missing or extra fields*'; if (-not $missingRejected) { $missingFailure = $_.Exception.Message } }
        & $add 'fixture provenance rejects a missing environment field' $missingRejected $missingFailure

        $extraEnvironmentField = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $extraEnvironmentField.environment.extra = 'unapproved'
        & $writeSidecar $extraEnvironmentField
        $extraRejected = $false
        $extraFailure = $null
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $extraRejected = $_.Exception.Message -like '*missing or extra fields*'; if (-not $extraRejected) { $extraFailure = $_.Exception.Message } }
        & $add 'fixture provenance rejects an extra environment field' $extraRejected $extraFailure

        $missingFetchField = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $missingFetchField.environment.fetch_manifests[0].Remove('process_identity')
        & $writeSidecar $missingFetchField
        $fetchFieldRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $fetchFieldRejected = $_.Exception.Message -like '*fixed locked fetch record is invalid*' }
        & $add 'fixture provenance rejects a missing nested locked-fetch evidence field' $fetchFieldRejected

        $wrongFetchArgv = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $wrongFetchArgv.environment.fetch_manifests[0].command[1] = '--offline'
        & $writeSidecar $wrongFetchArgv
        $fetchArgvRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $fetchArgvRejected = $_.Exception.Message -like '*fixed locked fetch argv mismatch*' }
        & $add 'fixture provenance rejects altered locked-fetch argv' $fetchArgvRejected

        $wrongFetchParent = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $wrongFetchParent.environment.fetch_manifests[0].process_identity.parent_process_id = $PID + 1
        & $writeSidecar $wrongFetchParent
        $fetchParentRejected = $false
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $fetchParentRejected = $_.Exception.Message -like '*Cargo process identity evidence is invalid*' }
        & $add 'fixture provenance requires fetch Cargo to be parented by the pinned Phase0 process' $fetchParentRejected

        $wrongManifestIdentity = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sidecar))
        $wrongManifestIdentity.fixture_manifest_file_id_hex = '0' * 32
        & $writeSidecar $wrongManifestIdentity
        $identityRejected = $false
        $identityFailure = $null
        try { $null = Test-D32Phase0FixtureBuildProvenance -SidecarPath $sidecarPath -ManifestPath $manifestPath -Repository $testRepository -OutputRoot $selfTestRoot -ExpectedCandidateSha $candidate -ExpectedRunnerProcessId $PID -ValidatedProfile $fakeProfile }
        catch { $identityRejected = $_.Exception.Message -like '*does not bind current fixture manifest bytes and opened-handle identity*'; if (-not $identityRejected) { $identityFailure = $_.Exception.Message } }
        & $add 'fixture provenance rejects a same-bytes manifest identity mismatch' $identityRejected $identityFailure

        $emptyLogReference = [PSCustomObject](Get-D32Phase0FileReference -Path $emptyLogPath)
        $emptyLogAccepted = $false
        try { $emptySnapshot = Test-D32Phase0FileReference -Reference $emptyLogReference -AllowedRoot $selfTestRoot; $emptyLogAccepted = ($emptySnapshot.Bytes -eq 0) }
        catch { $emptyLogAccepted = $false }
        & $add 'zero-byte captured stderr/stdout references are valid with native identity' $emptyLogAccepted

        $forgedLogReference = [PSCustomObject](Get-D32Phase0FileReference -Path $fakeProfile.ProfilePath)
        $forgedLogPathRejected = $false
        try { $null = Test-D32Phase0FileReference -Reference $forgedLogReference -AllowedRoot $selfTestRoot }
        catch { $forgedLogPathRejected = $_.Exception.Message -like '*outside its approved root or non-canonical*' }
        & $add 'Phase0 file-reference reader rejects a forged external stdout/stderr path' $forgedLogPathRejected

        $stringBytesReference = [PSCustomObject](Get-D32Phase0FileReference -Path $emptyLogPath)
        $stringBytesReference.bytes = '0'
        $stringBytesRejected = $false
        try { $null = Test-D32Phase0FileReference -Reference $stringBytesReference -AllowedRoot $selfTestRoot }
        catch { $stringBytesRejected = $_.Exception.Message -like '*scalar is malformed*' }
        & $add 'file references reject string-coerced zero-byte size' $stringBytesRejected
    }
    finally {
        if ($null -ne $startupSelfTestModule) {
            Remove-Module -Name $startupSelfTestModuleName -Force -ErrorAction SilentlyContinue
            $startupSelfTestModule = $null
        }
        if (Test-Path -LiteralPath $selfTestRoot) {
            if (-not (Test-D32ProfileNoReparsePath -Path $selfTestRoot) -or -not (Test-D32ProfilePathEqual -Left ([IO.Path]::GetDirectoryName($selfTestRoot)) -Right $tempBase)) { throw 'Phase0 sidecar self-test cleanup target no longer resolves to its exact regular temp child' }
            [IO.Directory]::Delete($selfTestRoot, $true)
        }
        if (Test-Path -LiteralPath $startupSelfTestRoot) {
            if (-not (Test-D32ProfileNoReparsePath -Path $startupSelfTestRoot) -or -not (Test-D32ProfilePathEqual -Left ([IO.Path]::GetDirectoryName($startupSelfTestRoot)) -Right $tempBase)) { throw 'Phase0 startup self-test cleanup target no longer resolves to its exact regular temp child' }
            [IO.Directory]::Delete($startupSelfTestRoot, $true)
        }
        if (Test-Path -LiteralPath $profileSelfTestRoot) {
            if (-not (Test-D32ProfileNoReparsePath -Path $profileSelfTestRoot) -or -not (Test-D32ProfilePathEqual -Left ([IO.Path]::GetDirectoryName($profileSelfTestRoot)) -Right $tempBase)) { throw 'Phase0 profile self-test cleanup target no longer resolves to its exact regular temp child' }
            [IO.Directory]::Delete($profileSelfTestRoot, $true)
        }
    }
    return @($cases.ToArray())
}

function Get-D32Phase0PreflightDependencyFailures {
    param([Parameter(Mandatory = $true)][string]$PreflightLibraryPath)

    $expectedPath = [IO.Path]::GetFullPath($PreflightLibraryPath)
    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $script:D32Phase0PreflightDependencyFunctionNames) {
        $command = Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $command) {
            $failures.Add("missing:$name")
            continue
        }
        $sourcePath = [string]$command.ScriptBlock.Ast.Extent.File
        if ([String]::IsNullOrWhiteSpace($sourcePath) -or -not (Test-D32ProfilePathEqual -Left $sourcePath -Right $expectedPath)) {
            $failures.Add("wrong-source:$name")
        }
    }
    return @($failures.ToArray())
}

if ($Phase0LibraryOnly) { return }

try {
    $preflightLibraryPath = [IO.Path]::GetFullPath((Join-Path $script:D32Phase0ScriptRoot 'd32-preflight.ps1'))
    if (-not (Test-D32ProfileNoReparsePath -Path $preflightLibraryPath) -or -not (Test-Path -LiteralPath $preflightLibraryPath -PathType Leaf)) {
        throw 'PHASE0_DEPENDENCY_BLOCKED: exact d32-preflight.ps1 library path is missing or reparse-backed'
    }
    . $preflightLibraryPath -LibraryOnly -Phase0DependencyLibraryOnly
    $preflightDependencyFailures = @(Get-D32Phase0PreflightDependencyFailures -PreflightLibraryPath $preflightLibraryPath)
    if ($preflightDependencyFailures.Count -gt 0) {
        throw "PHASE0_DEPENDENCY_BLOCKED: preflight helper library is incomplete or shadowed ($($preflightDependencyFailures -join ', '))"
    }
}
catch {
    Write-Output "D32 Phase0: BLOCKED — $($_.Exception.Message)"
    exit 1
}

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

if ([String]::IsNullOrWhiteSpace($Phase0RepoRoot)) { $Phase0RepoRoot = Split-Path -Parent $script:D32Phase0ScriptRoot }
foreach ($required in @(@('OutputRoot', $Phase0OutputRoot), @('ExpectedCandidateSha', $Phase0ExpectedCandidateSha), @('ToolchainProfilePath', $Phase0ToolchainProfilePath), @('ExpectedToolchainProfileSha256', $Phase0ExpectedToolchainProfileSha256), @('PinnedGitPath', $Phase0PinnedGitPath), @('PinnedGitSha256', $Phase0PinnedGitSha256), @('VendoredProtocAuthorityPath', $Phase0VendoredProtocAuthorityPath), @('ExpectedVendoredProtocAuthoritySha256', $Phase0ExpectedVendoredProtocAuthoritySha256), @('TauriMacrosSourceAuthorityPath', $Phase0TauriMacrosSourceAuthorityPath), @('ExpectedTauriMacrosSourceAuthoritySha256', $Phase0ExpectedTauriMacrosSourceAuthoritySha256), @('H7CGitAuthorityPath', $Phase0H7CGitAuthorityPath), @('ExpectedH7CGitAuthoritySha256', $Phase0ExpectedH7CGitAuthoritySha256))) {
    if ([String]::IsNullOrWhiteSpace([string]$required[1])) { Write-Output "D32 Phase0: BLOCKED — -$($required[0]) is required"; exit 2 }
}
try {
    $result = Invoke-D32Phase0Matrix -Repository $Phase0RepoRoot -EvidenceRoot $Phase0OutputRoot -ExpectedSha $Phase0ExpectedCandidateSha -ProfilePath $Phase0ToolchainProfilePath -ProfileSha256 $Phase0ExpectedToolchainProfileSha256 -GitPath $Phase0PinnedGitPath -GitSha256 $Phase0PinnedGitSha256 -VendoredProtocAuthorityPath $Phase0VendoredProtocAuthorityPath -ExpectedVendoredProtocAuthoritySha256 $Phase0ExpectedVendoredProtocAuthoritySha256 -TauriMacrosSourceAuthorityPath $Phase0TauriMacrosSourceAuthorityPath -ExpectedTauriMacrosSourceAuthoritySha256 $Phase0ExpectedTauriMacrosSourceAuthoritySha256 -H7CGitAuthorityPath $Phase0H7CGitAuthorityPath -ExpectedH7CGitAuthoritySha256 $Phase0ExpectedH7CGitAuthoritySha256 -TimeoutSeconds $Phase0TimeoutSeconds
    if ($result.Success) { exit 0 }
    exit 1
}
catch {
    $primaryFailure = $_.Exception.Message
    $failureContext = $script:D32Phase0FailureContext
    if ($null -ne $failureContext) {
        $diagnosticPath = Join-Path $failureContext.EvidenceRoot $script:D32Phase0BlockedDiagnosticName
        if (-not (Test-D32Phase0DirectoryEntryExists -Path $diagnosticPath)) {
            try {
                $lastProcessFailure = $script:D32Phase0LastProcessFailure
                $command = if ($null -eq $lastProcessFailure) { $null } else { $lastProcessFailure.Command }
                $processIdentity = if ($null -eq $lastProcessFailure) { $null } else { $lastProcessFailure.ProcessIdentity }
                $rawTrace = if ($null -eq $lastProcessFailure) { $null } else { $lastProcessFailure.RawV2Trace }
                $nativeCleanup = if ($null -eq $lastProcessFailure) { $null } else { $lastProcessFailure.NativeCleanup }
                $stdoutPath = if ($null -eq $lastProcessFailure) { $null } else { $lastProcessFailure.StdoutPath }
                $stderrPath = if ($null -eq $lastProcessFailure) { $null } else { $lastProcessFailure.StderrPath }
                $secondary = @()
                if ($null -ne $lastProcessFailure -and -not [String]::IsNullOrWhiteSpace([string]$lastProcessFailure.PrimaryError) -and $lastProcessFailure.PrimaryError -cne $primaryFailure) {
                    $primaryFailure = [string]$lastProcessFailure.PrimaryError
                    $secondary = @($_.Exception.Message)
                }
                $null = Write-D32Phase0BlockedDiagnostic -PrimaryError $primaryFailure -SecondaryErrors $secondary -Command $command -ProcessIdentity $processIdentity -RawV2Trace $rawTrace -NativeCleanup $nativeCleanup -StdoutPath $stdoutPath -StderrPath $stderrPath
            }
            catch { $primaryFailure += '; blocked diagnostic capture error=' + $_.Exception.Message }
        }
    }
    Write-Output "D32 Phase0: BLOCKED — $primaryFailure"
    exit 1
}
