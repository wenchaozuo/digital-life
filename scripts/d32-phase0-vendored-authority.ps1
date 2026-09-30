[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$CandidateSha,
    [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
    [Parameter(Mandatory = $true)][string]$ExpectedToolchainProfileSha256,
    [Parameter(Mandatory = $true)][string]$PowerShellModuleAuthorityPath,
    [Parameter(Mandatory = $true)][string]$ExpectedPowerShellModuleAuthoritySha256,
    [Parameter(Mandatory = $true)][string]$PinnedGitPath,
    [Parameter(Mandatory = $true)][string]$PinnedGitSha256,
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [Parameter(Mandatory = $true)][string]$AuthorityOutputPath
)

. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
$null = Initialize-D32PowerShellModuleAuthority -CallerProfilePath $ToolchainProfilePath `
    -CallerExpectedProfileSha256 $ExpectedToolchainProfileSha256 `
    -CallerModuleAuthorityPath $PowerShellModuleAuthorityPath -CallerExpectedModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
    -CallerCandidateSha $CandidateSha -CallerRepository $Repository -CallerGitPath $PinnedGitPath -CallerGitSha256 $PinnedGitSha256 `
    -EntryScriptPath $PSCommandPath

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath($Repository)
. (Join-Path $PSScriptRoot 'd32-build-toolchain-profile.ps1')
. (Join-Path $PSScriptRoot 'd32-vendored-protoc-authority.ps1')
$profile = Test-D32BuildToolchainProfile -ProfilePath $ToolchainProfilePath -ExpectedSha256 $ExpectedToolchainProfileSha256 -Repository $repo -EvidenceRoot $EvidenceRoot
if (-not $profile.IsValid) { throw "VENDORED_PROTOC_AUTHORITY_BLOCKED: caller-pinned Profile V2 is invalid: $($profile.Failure)" }
$document = New-D32VendoredProtocAuthorityDocument -Repository $repo -CandidateSha $CandidateSha -ValidatedProfile $profile -EvidenceRoot $EvidenceRoot
$reference = Write-D32VendoredProtocAuthorityCreateNew -Path $AuthorityOutputPath -Document $document
Write-Output (ConvertTo-Json -InputObject ([ordered]@{ authority = $reference; exact_type = $script:D32VendoredProtocAuthorityType; candidate_sha = $CandidateSha; evidence_root_path = [IO.Path]::GetFullPath($EvidenceRoot) }) -Depth 8 -Compress)
