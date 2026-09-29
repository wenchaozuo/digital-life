[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
    [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
    [Parameter(Mandatory = $true)][string]$ExpectedToolchainProfileSha256,
    [Parameter(Mandatory = $true)][string]$PinnedGitPath,
    [Parameter(Mandatory = $true)][string]$PinnedGitSha256,
    [Parameter(Mandatory = $true)][string]$TauriMacrosSourceAuthorityPath,
    [Parameter(Mandatory = $true)][string]$ExpectedTauriMacrosSourceAuthoritySha256,
    [Parameter(Mandatory = $true)][string]$VendoredProtocAuthorityPath,
    [Parameter(Mandatory = $true)][string]$ExpectedVendoredProtocAuthoritySha256,
    [ValidateRange(60, 14400)][int]$Phase0TimeoutSeconds = 1800,
    [ValidateRange(1, 28800)][int]$Phase0InventoryListTimeoutSeconds = 28800
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([String]::IsNullOrWhiteSpace($PSCommandPath)) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: exact runner script location is required' }
$scriptRoot = Split-Path -Parent ([IO.Path]::GetFullPath($PSCommandPath))
. (Join-Path $scriptRoot 'd32-phase0-matrix.ps1') -Phase0LibraryOnly

foreach ($required in @('Phase0TimeoutSeconds', 'Phase0InventoryListTimeoutSeconds')) {
    if (-not $PSBoundParameters.ContainsKey($required)) { throw "TEST_INVENTORY_DISCOVERY_BLOCKED: caller must explicitly pin -$required" }
}
if ($PSVersionTable.PSVersion -lt [Version]'7.5' -or $Phase0TimeoutSeconds -ne 14400 -or $Phase0InventoryListTimeoutSeconds -ne 28800) {
    throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: discovery requires native PowerShell 7.5+, 14400-second fixed commands, and explicit 28800-second list commands'
}
if ($ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or $PinnedGitSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $ExpectedToolchainProfileSha256 -cnotmatch '^[0-9a-f]{64}$' -or $ExpectedTauriMacrosSourceAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $ExpectedVendoredProtocAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: exact lowercase caller pins are malformed' }

$repo = [IO.Path]::GetFullPath($Repository)
if (-not (Test-D32ProfileNoReparsePath -Path $repo) -or -not (Test-Path -LiteralPath $repo -PathType Container)) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: candidate repository must be an existing non-reparse directory' }
$output = Assert-D32Phase0OutputRoot -Path $EvidenceRoot -Repository $repo
$profile = Test-D32BuildToolchainProfile -ProfilePath $ToolchainProfilePath -ExpectedSha256 $ExpectedToolchainProfileSha256 -Repository $repo -EvidenceRoot $output
if (-not $profile.IsValid) { throw "TEST_INVENTORY_DISCOVERY_BLOCKED: current Profile V2 failed: $($profile.Failure)" }
$gitImage = Test-D32TrustedGitImage -Path $PinnedGitPath -ExpectedSha256 $PinnedGitSha256
if (-not $gitImage.IsValid) { throw "TEST_INVENTORY_DISCOVERY_BLOCKED: direct Git image failed: $($gitImage.Failure)" }
$sourceAuthority = Test-D32TauriMacrosSourcePatchAuthority -AuthorityPath $TauriMacrosSourceAuthorityPath -ExpectedAuthoritySha256 $ExpectedTauriMacrosSourceAuthoritySha256 `
    -Repository $repo -CandidateSha $ExpectedCandidateSha -ValidatedProfile $profile -EvidenceRoot $output
$protocAuthority = Test-D32VendoredProtocAuthority -AuthorityPath $VendoredProtocAuthorityPath -ExpectedAuthoritySha256 $ExpectedVendoredProtocAuthoritySha256 `
    -Repository $repo -CandidateSha $ExpectedCandidateSha -ValidatedProfile $profile -EvidenceRoot $output -ExpectedScope 'D32_TEST_INVENTORY_DISCOVERY_ONLY'
Set-D32GitCaptureContext -ValidatedProfile $profile -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256 -TimeoutSeconds 120
$before = Get-D32Phase0GitState -Repository $repo -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256
if ($before.Head -cne $ExpectedCandidateSha) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: exact clean candidate SHA does not match caller pin' }
$startedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
$findings = [System.Collections.ArrayList]::new()
Test-D32Governance -Repository $repo -Findings $findings
if (@($findings | Where-Object { $_.Severity -eq 'ERROR' }).Count -gt 0) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: current governance preflight failed' }
$capacity = Get-D32Phase0FixtureBuildCapacity -Repository $repo -EvidenceRoot $output -Phase0TimeoutSeconds $Phase0TimeoutSeconds
$runId = [Guid]::NewGuid().ToString('N').ToLowerInvariant()
$ownerRoot = New-D32Phase0FixtureOutputRoot -Path $output -Repository $repo -ExpectedCandidateSha $ExpectedCandidateSha -ValidatedProfile $profile -RunId $runId
$output = [string]$ownerRoot.Path

$runRoot = Join-Path $output 'r'
$cargoHome = Join-Path $runRoot 'c'
$tempRoot = Join-Path $runRoot 't'
foreach ($directory in @($runRoot, $cargoHome, $tempRoot)) { [void](New-D32ProfileDirectoryCreateNew -Path $directory) }
$logsRoot = Join-Path $output 'logs'
[void](New-D32ProfileDirectoryCreateNew -Path $logsRoot)
$null = Test-D32CargoHome -Path $cargoHome -Repository $repo -RequireEmpty
$null = Test-D32Phase0OwnerBinding -EvidenceRoot $output -ExpectedCandidateSha $ExpectedCandidateSha -ValidatedProfile $profile `
    -ExpectedRunId $runId -ExpectedRootIdentity $ownerRoot.RootIdentity -ExpectedMarkerReference $ownerRoot.OwnerMarker
$script:D32Phase0FailureContext = [PSCustomObject]@{
    EvidenceRoot = $output; CandidateSha = $ExpectedCandidateSha; Profile = $profile; RunId = $runId
    RootIdentity = $ownerRoot.RootIdentity; OwnerMarker = $ownerRoot.OwnerMarker
}

$cargo = [string]$profile.Profile.toolchain.cargo.path
$lockInputs = @(Get-D32BuildToolchainLockInputs -Repository $repo)
$onlineEnvironment = Get-D32BuildToolchainEnvironment -ValidatedProfile $profile -CargoHome $cargoHome -TempRoot $tempRoot -Offline $false
$offlineEnvironment = Get-D32BuildToolchainEnvironment -ValidatedProfile $profile -CargoHome $cargoHome -TempRoot $tempRoot -Offline $true
if ($onlineEnvironment.Contains('PROTOC') -or $offlineEnvironment.Contains('PROTOC')) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: ambient PROTOC is forbidden' }
$fetches = [System.Collections.Generic.List[object]]::new()
$inventoryCommands = [System.Collections.Generic.List[object]]::new()
$ordinal = 0
$common = @{
    Ordinal = [ref]$ordinal; Records = [System.Collections.Generic.List[object]]::new(); LogRoot = $logsRoot; Repository = $repo
    ValidatedProfile = $profile; Environment = $onlineEnvironment; TimeoutSeconds = $Phase0TimeoutSeconds
    ExpectedCandidateSha = $ExpectedCandidateSha; GitPath = $PinnedGitPath; GitSha256 = $PinnedGitSha256
    VendoredProtocRunGrant = $null; H7CGitAuthority = $null; H7CGitRunGrant = $null
}
foreach ($index in 0..2) {
    $lock = $lockInputs[$index]
    $arguments = @('fetch', '--locked', '--manifest-path', $lock.ManifestFullPath, '--target', [string]$profile.Profile.target_triple)
    $name = 'inventory-fetch-{0:D2}' -f ($index + 1)
    $command = Invoke-D32Phase0LoggedCommand @common -Name $name -Executable $cargo -Arguments $arguments
    $fetches.Add($command)
}

# The discovery grant is scoped to this fresh discovery run; Phase0 grants are not replayed.
$discoveryGrant = New-D32VendoredProtocRunGrant -AuthorityPath $VendoredProtocAuthorityPath -AuthoritySha256 $ExpectedVendoredProtocAuthoritySha256 `
    -Repository $repo -CandidateSha $ExpectedCandidateSha -ValidatedProfile $profile -EvidenceRoot $output -OwnerMarkerReference $ownerRoot.OwnerMarker `
    -RunId $runId -CargoHome $cargoHome -Scope 'D32_TEST_INVENTORY_DISCOVERY_ONLY'
$discoveryGrant = Test-D32VendoredProtocRunGrant -Reference $discoveryGrant.Reference -Repository $repo -CandidateSha $ExpectedCandidateSha `
    -ValidatedProfile $profile -EvidenceRoot $output -ExpectedRunId $runId -CargoHome $cargoHome -AuthorityPath $VendoredProtocAuthorityPath `
    -AuthoritySha256 $ExpectedVendoredProtocAuthoritySha256 -OwnerMarkerReference $ownerRoot.OwnerMarker -Scope 'D32_TEST_INVENTORY_DISCOVERY_ONLY'
$offlineEnvironment = New-D32VendoredProtocEnvironment -Environment $offlineEnvironment -RunGrant $discoveryGrant

$packageRows = @{}
$packageCommandMetadata = Get-D32TestInventoryExpectedCommands -Profile $profile.Profile
foreach ($expected in $packageCommandMetadata) {
    $arguments = @($expected.arguments)
    $name = [string]$expected.name
    $command = Invoke-D32Phase0LoggedCommand -Name $name -Executable $cargo -Arguments $arguments -Ordinal ([ref]$ordinal) `
        -Records ([System.Collections.Generic.List[object]]::new()) -LogRoot $logsRoot -Repository $repo -ValidatedProfile $profile `
        -Environment $offlineEnvironment -TimeoutSeconds $Phase0InventoryListTimeoutSeconds -ExpectedCandidateSha $ExpectedCandidateSha `
        -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256 -VendoredProtocRunGrant $discoveryGrant -H7CGitAuthority $null -H7CGitRunGrant $null
    $lines = @(Read-D32TestInventoryLogReference -Reference $command.stdout -AllowedRoot $output)
    $parsed = Get-D32TestInventoryListOutput -Lines $lines -Package $expected.package -ListingKind $expected.listing_kind
    $inventoryCommands.Add([ordered]@{
        package = [string]$expected.package
        listing_kind = [string]$expected.listing_kind
        features = @($expected.features)
        target_triple = [string]$profile.Profile.target_triple
        digest = Get-D32TestInventoryDigest -Rows $parsed.rows
        row_count = [Int64]$parsed.row_count
        test_count = [Int64]$parsed.test_count
        benchmark_count = [Int64]$parsed.benchmark_count
        rows = @($parsed.rows)
        command = $command
    })
    $packageRows[([string]$expected.package + '|' + [string]$expected.listing_kind)] = @($parsed.rows)
}

$packageInventories = [System.Collections.Generic.List[object]]::new()
foreach ($package in @('protocol', 'vita', 'host')) {
    [string[]]$deferred = @()
    [string[]]$focused = @()
    if ($package -ceq 'vita') { $deferred = @($script:D32Phase0DeferredVita); $focused = @($script:D32Phase0FocusedVita) }
    elseif ($package -ceq 'host') { $deferred = @($script:D32Phase0DeferredHost); $focused = @($script:D32Phase0FocusedHost) }
    $packageInventories.Add((Get-D32TestInventoryCategoryAssignments -Package $package -AllRows $packageRows[($package + '|all')] `
        -IgnoredRows $packageRows[($package + '|ignored')] -DeferredNames $deferred -FocusedSuffixes $focused))
}
$entries = @(Sort-D32TestInventoryBaselineEntries -Entries @($packageInventories | ForEach-Object { $_.entries }))
$packageDigests = [System.Collections.Generic.List[object]]::new()
$categoryCounts = [ordered]@{}
foreach ($inventory in $packageInventories) {
    $packageEntries = @($inventory.entries)
    $packageDigests.Add([ordered]@{ package = [string]$inventory.package; entry_count = [Int64]$packageEntries.Count; sha256 = Get-D32TestInventoryBaselineDigest -Entries $packageEntries })
    $categoryCounts[[string]$inventory.package] = $inventory.category_counts
}

$final = Get-D32Phase0GitState -Repository $repo -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256
if ($final.Head -cne $ExpectedCandidateSha) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: candidate SHA changed during discovery' }
$null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $profile
$storage = [ordered]@{
    run_root = [ordered]@{ path = [IO.Path]::GetFullPath($runRoot); volume_serial_hex = $ownerRoot.RootIdentity.VolumeSerialHex; file_id_hex = (Get-D32ProfileDirectoryIdentity -Path $runRoot).FileIdHex }
    cargo_home = [ordered]@{ path = [IO.Path]::GetFullPath($cargoHome); volume_serial_hex = (Get-D32ProfileDirectoryIdentity -Path $cargoHome).VolumeSerialHex; file_id_hex = (Get-D32ProfileDirectoryIdentity -Path $cargoHome).FileIdHex }
    temp_root = [ordered]@{ path = [IO.Path]::GetFullPath($tempRoot); volume_serial_hex = (Get-D32ProfileDirectoryIdentity -Path $tempRoot).VolumeSerialHex; file_id_hex = (Get-D32ProfileDirectoryIdentity -Path $tempRoot).FileIdHex }
}
$toolchainProfile = Get-D32TestInventoryProfileRecord -ValidatedProfile $profile
$record = [ordered]@{
    schema_version = 1
    record_type = 'D32_TEST_INVENTORY_DISCOVERY_V1'
    status = 'COMPLETE_FOR_COORDINATOR_REVIEW'
    gate_authority = 'NONE'
    runner_process_id = [int]$PID
    candidate_sha = $ExpectedCandidateSha
    source_repo = $repo
    evidence_root_identity = [ordered]@{ path = $ownerRoot.RootIdentity.Path; volume_serial_hex = $ownerRoot.RootIdentity.VolumeSerialHex; file_id_hex = $ownerRoot.RootIdentity.FileIdHex }
    owner_marker = $ownerRoot.OwnerMarker
    run_id = $runId
    toolchain_profile = $toolchainProfile
    lock_inputs = @($lockInputs | ForEach-Object { [ordered]@{ manifest_path = $_.ManifestPath; lock_sha256 = $_.LockSha256; lock_bytes = [Int64]$_.LockBytes } })
    source_patch_authority = $sourceAuthority.Reference
    protoc = [ordered]@{ authority = $protocAuthority.Reference; run_grant = $discoveryGrant.Reference }
    storage = $storage
    fetches = @($fetches.ToArray())
    inventory_commands = @($inventoryCommands.ToArray())
    test_inventory = [ordered]@{
        entries = $entries
        combined_digest = Get-D32TestInventoryBaselineDigest -Entries $entries
        package_digests = @($packageDigests.ToArray())
        category_counts = $categoryCounts
    }
    started_at_utc = $startedAtUtc
    completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    final_candidate_sha = $final.Head
    final_clean = $true
}
$recordPath = Join-Path $output 'D32-TEST-INVENTORY-DISCOVERY.json'
if (Test-Path -LiteralPath $recordPath) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: refusing to overwrite existing discovery record' }
$json = ConvertTo-Json -InputObject $record -Depth 40 -Compress
$bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
$recordStream = [IO.File]::Open($recordPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
try { $recordStream.Write($bytes, 0, $bytes.Length); $recordStream.Flush($true) }
finally { $recordStream.Dispose() }
$reference = Get-D32Phase0FileReference -Path $recordPath
Write-Output 'inventory_discovery_status=COMPLETE_FOR_COORDINATOR_REVIEW'
Write-Output 'inventory_discovery_gate_authority=NONE'
Write-Output "inventory_discovery_candidate_sha=$ExpectedCandidateSha"
Write-Output "inventory_discovery_path=$recordPath"
Write-Output "inventory_discovery_sha256=$($reference.sha256)"
