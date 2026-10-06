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
    [Parameter(Mandatory = $true)][string]$ExpectedSourceProofAuthoritySha256,
    [Parameter(Mandatory = $true)][string]$ExecutionAuthorityPath,
    [Parameter(Mandatory = $true)][string]$ExpectedExecutionAuthoritySha256,
    [Parameter(Mandatory = $true)][long]$LifecycleT0Ticks,
    [Parameter(Mandatory = $true)][long]$LifecycleCounterFrequency,
    [Parameter(Mandatory = $true)][long]$LifecycleWorkDeadlineTicks,
    [Parameter(Mandatory = $true)][long]$LifecycleProofExpiryTicks
)

# Fail before opening any authority/profile/source pin when late startup means
# the shared proof-work window has already expired.
$lifecycleNowTicks = [Diagnostics.Stopwatch]::GetTimestamp()
if ($LifecycleT0Ticks -le 0 -or $LifecycleCounterFrequency -ne [Diagnostics.Stopwatch]::Frequency -or
    $LifecycleWorkDeadlineTicks -le $LifecycleT0Ticks -or $LifecycleProofExpiryTicks -le $LifecycleWorkDeadlineTicks -or
    $lifecycleNowTicks -lt $LifecycleT0Ticks -or $lifecycleNowTicks -ge $LifecycleWorkDeadlineTicks) {
    exit 86
}

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
    -ExpectedSourceProofAuthoritySha256 $ExpectedSourceProofAuthoritySha256 `
    -ExecutionAuthorityPath $ExecutionAuthorityPath `
    -ExpectedExecutionAuthoritySha256 $ExpectedExecutionAuthoritySha256 `
    -LifecycleT0Ticks $LifecycleT0Ticks `
    -LifecycleCounterFrequency $LifecycleCounterFrequency `
    -LifecycleWorkDeadlineTicks $LifecycleWorkDeadlineTicks `
    -LifecycleProofExpiryTicks $LifecycleProofExpiryTicks
