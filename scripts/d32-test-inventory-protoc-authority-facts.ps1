# Creates an untrusted D32 discovery-only protoc authority candidate from
# caller-supplied facts. It never creates/claims EvidenceRoot or imports modules.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$CandidateSha,
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedToolchainProfileSha256,
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, 'd32-build-toolchain-profile.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, 'd32-vendored-protoc-authority.ps1'))
$global:PSModuleAutoLoadingPreference = 'None'
$env:PSModulePath = [IO.Path]::GetFullPath([IO.Path]::Combine([string]$PSHOME, 'Modules'))
$global:D32PowerShellModuleImportAttempts = 0
$loadedModulesAtStart = Get-D32PowerShellAuthorityLoadedModuleSet
$null = Get-D32PowerShellAuthorityProcessStartup -EntryScriptPath $PSCommandPath
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = [IO.Path]::GetFullPath($Repository)
if ($Repository -cne $repo) { throw 'VENDORED_PROTOC_FACTS_BLOCKED: Repository must be canonical and absolute' }
$profile = Test-D32BuildToolchainProfileModuleFree -ProfilePath $ToolchainProfilePath -ExpectedSha256 $ExpectedToolchainProfileSha256 `
    -Repository $repo -EvidenceRoot $EvidenceRoot
if (-not $profile.IsValid) { throw "VENDORED_PROTOC_FACTS_BLOCKED: full module-free Profile V2 validation failed: $($profile.Failure)" }

$document = New-D32VendoredProtocAuthorityModuleFreeCandidate -Repository $repo -CandidateSha $CandidateSha `
    -ValidatedProfile $profile -EvidenceRoot $EvidenceRoot
$output = [IO.Path]::GetFullPath($OutputPath)
$parent = [IO.Path]::GetDirectoryName($output)
if ($OutputPath -cne $output -or [IO.File]::Exists($output) -or [IO.Directory]::Exists($output) -or
    (Test-D32PowerShellAuthorityPathWithin -Child $output -Parent $repo) -or
    -not [IO.Directory]::Exists($parent) -or -not (Test-D32PowerShellAuthorityPathNoReparse -Path $parent)) {
    throw 'VENDORED_PROTOC_FACTS_BLOCKED: output must be a canonical absent external file beneath an existing non-reparse parent'
}
$json = ConvertTo-D32PowerShellAuthorityJsonText -Value $document
$bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
$stream = [IO.File]::Open($output, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
finally { $stream.Dispose() }

$directoryFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
try {
    $written = Open-D32PowerShellAuthorityFile -Path $output -DirectoryFences $directoryFences
    try {
        $jsonDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$written.Bytes))
        try {
            if ((Test-D32PowerShellAuthorityJsonDuplicates -Element $jsonDocument.RootElement) -or
                $jsonDocument.RootElement.GetProperty('record_type').GetString() -cne 'D32_VENDORED_PROTOC_AUTHORITY_V1' -or
                $jsonDocument.RootElement.GetProperty('scope').GetString() -cne 'D32_TEST_INVENTORY_DISCOVERY_ONLY' -or
                $jsonDocument.RootElement.GetProperty('candidate_sha').GetString() -cne $CandidateSha -or
                $jsonDocument.RootElement.GetProperty('evidence_root_path').GetString() -cne [IO.Path]::GetFullPath($EvidenceRoot)) {
                throw 'VENDORED_PROTOC_FACTS_BLOCKED: newly written discovery-only candidate failed strict V1 binding checks'
            }
        }
        finally { $jsonDocument.Dispose() }
        if ($global:D32PowerShellModuleImportAttempts -ne 0) { throw 'VENDORED_PROTOC_FACTS_BLOCKED: facts preparation unexpectedly attempted a module import' }
        Assert-D32PowerShellAuthorityLoadedModuleSetUnchanged -Expected $loadedModulesAtStart
        [Console]::WriteLine("D32_VENDORED_PROTOC_FACTS_PATH=$output")
        [Console]::WriteLine("D32_VENDORED_PROTOC_FACTS_SHA256=$($written.Record.sha256)")
        [Console]::WriteLine("D32_VENDORED_PROTOC_FACTS_BYTES=$($written.Record.bytes)")
        [Console]::WriteLine('D32_VENDORED_PROTOC_FACTS_SCOPE=D32_TEST_INVENTORY_DISCOVERY_ONLY')
        [Console]::WriteLine('D32_VENDORED_PROTOC_FACTS_AUTHORITY=UNAUTHORIZED_CANDIDATE_ONLY')
    }
    finally { $written.Stream.Dispose() }
}
finally { foreach ($fence in $directoryFences.Values) { if ($null -ne $fence.Handle -and -not $fence.Handle.IsClosed) { $fence.Handle.Dispose() } } }
