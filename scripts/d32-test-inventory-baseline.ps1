[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
    [Parameter(Mandatory = $true)][string]$DiscoveryPath,
    [Parameter(Mandatory = $true)][string]$ExpectedDiscoverySha256,
    [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
    [Parameter(Mandatory = $true)][string]$ExpectedToolchainProfileSha256,
    [Parameter(Mandatory = $true)][string]$PowerShellModuleAuthorityPath,
    [Parameter(Mandatory = $true)][string]$ExpectedPowerShellModuleAuthoritySha256,
    [Parameter(Mandatory = $true)][string]$PinnedGitPath,
    [Parameter(Mandatory = $true)][string]$PinnedGitSha256,
    [Parameter(Mandatory = $true)][string]$BaselineOutputPath
)

. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
$null = Initialize-D32PowerShellModuleAuthority -CallerProfilePath $ToolchainProfilePath `
    -CallerExpectedProfileSha256 $ExpectedToolchainProfileSha256 `
    -CallerModuleAuthorityPath $PowerShellModuleAuthorityPath -CallerExpectedModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
    -CallerCandidateSha $ExpectedCandidateSha -CallerRepository $Repository -CallerGitPath $PinnedGitPath -CallerGitSha256 $PinnedGitSha256 `
    -EntryScriptPath $PSCommandPath

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([String]::IsNullOrWhiteSpace($PSCommandPath)) { throw 'TEST_INVENTORY_BASELINE_BLOCKED: exact baseline builder script location is required' }
$scriptRoot = Split-Path -Parent ([IO.Path]::GetFullPath($PSCommandPath))
. (Join-Path $scriptRoot 'd32-phase0-matrix.ps1') -Phase0LibraryOnly `
    -Phase0ToolchainProfilePath $ToolchainProfilePath -Phase0ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256 `
    -Phase0PowerShellModuleAuthorityPath $PowerShellModuleAuthorityPath -Phase0ExpectedPowerShellModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
    -Phase0ExpectedCandidateSha $ExpectedCandidateSha -Phase0RepoRoot $Repository -Phase0PinnedGitPath $PinnedGitPath -Phase0PinnedGitSha256 $PinnedGitSha256
$preflightLibraryPath = [IO.Path]::GetFullPath((Join-Path $scriptRoot 'd32-preflight.ps1'))
if (-not (Test-D32ProfileNoReparsePath -Path $preflightLibraryPath) -or -not (Test-Path -LiteralPath $preflightLibraryPath -PathType Leaf)) {
    throw 'TEST_INVENTORY_BASELINE_BLOCKED: exact d32-preflight.ps1 helper library is missing or reparse-backed'
}
. $preflightLibraryPath -LibraryOnly -Phase0DependencyLibraryOnly -RepoRoot $Repository -ModuleAuthorityCandidateSha $ExpectedCandidateSha `
    -ToolchainProfilePath $ToolchainProfilePath -ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256 `
    -PowerShellModuleAuthorityPath $PowerShellModuleAuthorityPath -ExpectedPowerShellModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
    -TrustedGitPath $PinnedGitPath -TrustedGitSha256 $PinnedGitSha256
$preflightDependencyFailures = @(Get-D32Phase0PreflightDependencyFailures -PreflightLibraryPath $preflightLibraryPath)
if ($preflightDependencyFailures.Count -gt 0) {
    throw "TEST_INVENTORY_BASELINE_BLOCKED: preflight helper library is incomplete or shadowed ($($preflightDependencyFailures -join ', '))"
}

if ($ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or $ExpectedDiscoverySha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $ExpectedToolchainProfileSha256 -cnotmatch '^[0-9a-f]{64}$' -or $PinnedGitSha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw 'TEST_INVENTORY_BASELINE_BLOCKED: exact lowercase candidate/Profile/Git/discovery caller pins are required'
}
$repo = [IO.Path]::GetFullPath($Repository)
$profile = Test-D32BuildToolchainProfile -ProfilePath $ToolchainProfilePath -ExpectedSha256 $ExpectedToolchainProfileSha256 -Repository $repo -EvidenceRoot ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($DiscoveryPath)))
if (-not $profile.IsValid) { throw "TEST_INVENTORY_BASELINE_BLOCKED: current Profile V2 failed: $($profile.Failure)" }
$gitImage = Test-D32TrustedGitImage -Path $PinnedGitPath -ExpectedSha256 $PinnedGitSha256
if (-not $gitImage.IsValid) { throw "TEST_INVENTORY_BASELINE_BLOCKED: direct Git image failed: $($gitImage.Failure)" }
$discoveryReference = Get-D32Phase0FileReference -Path $DiscoveryPath
if ($discoveryReference.sha256 -cne $ExpectedDiscoverySha256) { throw 'TEST_INVENTORY_BASELINE_BLOCKED: discovery bytes differ from the independent caller SHA' }
$discovery = Test-D32Phase0TestInventoryDiscoveryRecord -Reference $discoveryReference -ExpectedSha256 $ExpectedDiscoverySha256 `
    -Repository $repo -CandidateSha $ExpectedCandidateSha -Profile $profile -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256
if (-not (Test-D32PowerShellModuleAdmissionProducerBinding -Document $global:D32PowerShellModuleAuthorityState.Admission -CandidateSha $ExpectedCandidateSha `
        -Repository $repo -ProducerRole inventory_baseline -ExpectedAdmissionContext $global:D32PowerShellModuleAuthorityState.Admission `
        -ExpectedProducerContext $global:D32PowerShellModuleAuthorityState.Admission)) {
    throw 'TEST_INVENTORY_BASELINE_BLOCKED: baseline generation requires the current direct baseline producer startup and entry context'
}
$document = New-D32TestInventoryBaselineDocument -Discovery $discovery.Document -DiscoveryReference $discovery.Reference `
    -PackageInventories $discovery.PackageInventories -ProducerAdmission $global:D32PowerShellModuleAuthorityState.Admission `
    -GeneratedAtUtc ([DateTimeOffset]::UtcNow.ToString('o'))
$expectedCommands = @(Get-D32TestInventoryExpectedCommands -Profile $profile.Profile)
$null = Test-D32TestInventoryBaselineDocument -Document $document -Discovery $discovery.Document -DiscoveryReference $discovery.Reference `
    -ExpectedCandidateSha $ExpectedCandidateSha -Repository $repo -Profile $profile -LockInputs $discovery.LockInputs `
    -SourcePatchAuthorityReference $discovery.Document.source_patch_authority -ProtocAuthorityReference $discovery.Document.protoc.authority `
    -ExpectedCommands $expectedCommands -ExpectedProducerAdmission $global:D32PowerShellModuleAuthorityState.Admission
$reference = Write-D32TestInventoryJsonCreateNew -Path $BaselineOutputPath -Document $document -Repository $repo -DiscoveryRoot $discovery.Root
Write-Output 'inventory_baseline_status=AWAITING_COORDINATOR_PIN'
Write-Output 'inventory_baseline_gate_authority=NONE'
Write-Output "inventory_baseline_candidate_sha=$ExpectedCandidateSha"
Write-Output "inventory_baseline_path=$($reference.path)"
Write-Output "inventory_baseline_bytes=$($reference.bytes)"
Write-Output "inventory_baseline_sha256=$($reference.sha256)"
Write-Output "inventory_baseline_volume_serial_hex=$($reference.volume_serial_hex)"
Write-Output "inventory_baseline_file_id_hex=$($reference.file_id_hex)"
