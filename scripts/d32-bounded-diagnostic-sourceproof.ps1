# Dedicated module-free entry for current dependency-source proof only.
# The runner's SourceProofOnly parameter set has no route to Cargo, Git, the
# diagnostic admission/bootstrap path, module import, or fixture prebuild.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$CandidateSha,
    [Parameter(Mandatory = $true)][string]$HistoricalOriginCandidateSha,
    [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
    [Parameter(Mandatory = $true)][string]$ExpectedToolchainProfileSha256,
    [Parameter(Mandatory = $true)][string]$SourceProofAuthorityPath,
    [Parameter(Mandatory = $true)][string]$ExpectedSourceProofAuthoritySha256
)

$runnerPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-bounded-compiler-diagnostic.ps1'))
& $runnerPath `
    -SourceProofOnly `
    -Repository $Repository `
    -CandidateSha $CandidateSha `
    -HistoricalOriginCandidateSha $HistoricalOriginCandidateSha `
    -ToolchainProfilePath $ToolchainProfilePath `
    -ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256 `
    -SourceProofEntryPath $PSCommandPath `
    -SourceProofAuthorityPath $SourceProofAuthorityPath `
    -ExpectedSourceProofAuthoritySha256 $ExpectedSourceProofAuthoritySha256
