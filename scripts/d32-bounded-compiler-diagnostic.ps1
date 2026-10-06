# One-shot, non-gating D32 compiler diagnostic. This runner is not a formal
# discovery, Phase0, build, test, or release gate.
[CmdletBinding(DefaultParameterSetName = 'Diagnostic')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Diagnostic')]
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [string]$Repository,
    [Parameter(Mandatory = $true, ParameterSetName = 'Diagnostic')]
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [string]$CandidateSha,
    [Parameter(Mandatory = $true, ParameterSetName = 'Diagnostic')]
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [string]$ToolchainProfilePath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Diagnostic')]
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [string]$ExpectedToolchainProfileSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Diagnostic')]
    [string]$PowerShellModuleAuthorityPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Diagnostic')]
    [string]$ExpectedPowerShellModuleAuthoritySha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Diagnostic')]
    [string]$PinnedGitPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Diagnostic')]
    [string]$PinnedGitSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Diagnostic')]
    [string]$DiagnosticAuthorityPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Diagnostic')]
    [string]$ExpectedDiagnosticAuthoritySha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [switch]$SourceProofOnly,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [string]$HistoricalOriginCandidateSha,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [string]$SourceProofEntryPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [string]$SourceProofAuthorityPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [string]$ExpectedSourceProofAuthoritySha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [string]$ExecutionAuthorityPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [string]$ExpectedExecutionAuthoritySha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [long]$LifecycleT0Ticks,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [long]$LifecycleCounterFrequency,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [long]$LifecycleWorkDeadlineTicks,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')]
    [long]$LifecycleProofExpiryTicks
)

$script:D32BoundedDiagnosticSourceProofProgressMarkerBytes = [long]0
$script:D32BoundedDiagnosticSourceProofProgressMarkerCount = 0
$script:D32BoundedDiagnosticSourceProofProgressMarkerOutputUnavailable = $false
$script:D32BoundedDiagnosticSourceProofWallTimer = if ($SourceProofOnly) { [Diagnostics.Stopwatch]::StartNew() } else { $null }
if ($SourceProofOnly) {
    $lifecycleNowTicks = [Diagnostics.Stopwatch]::GetTimestamp()
    if ($LifecycleT0Ticks -le 0 -or $LifecycleCounterFrequency -ne [Diagnostics.Stopwatch]::Frequency -or
        $LifecycleWorkDeadlineTicks -le $LifecycleT0Ticks -or $LifecycleProofExpiryTicks -le $LifecycleWorkDeadlineTicks -or
        $lifecycleNowTicks -lt $LifecycleT0Ticks -or $lifecycleNowTicks -ge $LifecycleWorkDeadlineTicks -or
        $ExpectedExecutionAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$') {
        exit 86
    }
    try { [Console]::Out.WriteLine('D32SP1 p=timer.start t=0 n=none') }
    catch { $script:D32BoundedDiagnosticSourceProofProgressMarkerOutputUnavailable = $true }
}

# Module-free bootstrap and diagnostic source/authority pins precede imports or
# operational helpers. The approved PowerShell module authority runs only after
# that bounded diagnostic context has been structurally admitted.
. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:D32BoundedDiagnosticHistoricalOriginCandidateSha = '2de30edf5de48aa4ed3216c3d3df13c3e2f0ac51'
if ($PSVersionTable.PSVersion -lt [version]'7.5') { throw 'D32_BOUNDED_DIAGNOSTIC_REFUSED: pinned PowerShell Core 7.5 or newer is required' }
if ([String]::IsNullOrWhiteSpace($PSCommandPath)) { throw 'D32_BOUNDED_DIAGNOSTIC_REFUSED: exact script path is unavailable' }

function Assert-D32BoundedDiagnosticBootstrapPins {
    param([Parameter(Mandatory = $true)][string]$Repo)
    $expectedTop = @('schema_version', 'record_type', 'registry_archive_policy', 'gate_authority', 'candidate_sha', 'source_repo', 'repository_identity',
        'toolchain_profile', 'module_authority', 'pinned_git', 'command', 'child_environment', 'git_queries', 'cargo_home',
        'dependency_origin', 'target', 'output', 'resource_budget', 'source_pins', 'image_grants', 'issued_at_utc')
    $authorityFull = [IO.Path]::GetFullPath($DiagnosticAuthorityPath)
    if (-not [IO.Path]::IsPathRooted($DiagnosticAuthorityPath) -or $authorityFull -cne $DiagnosticAuthorityPath -or
        -not (Test-D32PowerShellAuthorityPathNoReparse -Path $authorityFull) -or
        (Test-D32PowerShellAuthorityPathWithin -Child $authorityFull -Parent $Repo) -or
        $ExpectedDiagnosticAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'D32_BOUNDED_DIAGNOSTIC_AUTHORITY_BLOCKED: authority path/pin is not canonical, external, non-reparse, and exact'
    }
    $authorityFiles = [System.Collections.Generic.List[object]]::new()
    $directoryFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        $authorityFile = Open-D32PowerShellAuthorityFile -Path $authorityFull -DirectoryFences $directoryFences -MaximumBytes 1048576
        $authorityFiles.Add($authorityFile)
        if ([string]$authorityFile.Record.sha256 -cne $ExpectedDiagnosticAuthoritySha256) { throw 'D32_BOUNDED_DIAGNOSTIC_AUTHORITY_BLOCKED: independently supplied authority SHA differs from current opened bytes' }
        $jsonDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$authorityFile.Bytes))
        try {
            if ($jsonDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                (Test-D32PowerShellAuthorityJsonDuplicates -Element $jsonDocument.RootElement)) {
                throw 'D32_BOUNDED_DIAGNOSTIC_AUTHORITY_BLOCKED: exact authority root or duplicate-key validation failed before helper load'
            }
            Assert-D32PowerShellAuthorityExactJsonRecord -Element $jsonDocument.RootElement -Fields $expectedTop -Name 'bounded compiler diagnostic authority'
            $bootstrap = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $jsonDocument.RootElement
        }
        finally { $jsonDocument.Dispose() }
        if ([int64]$bootstrap.schema_version -ne 3 -or [string]$bootstrap.record_type -cne 'D32_BOUNDED_COMPILER_DIAGNOSTIC_AUTHORITY_V3' -or
            [string]$bootstrap.registry_archive_policy -cne 'D32_REGISTRY_TAR_USTAR_GNU_LONGNAME_V1' -or
            [string]$bootstrap.gate_authority -cne 'NONE' -or [string]$bootstrap.candidate_sha -cne $CandidateSha -or
            [string]$bootstrap.source_repo -cne $Repo -or $bootstrap.source_pins -isnot [Array] -or $bootstrap.source_pins.Count -ne 6) {
            throw 'D32_BOUNDED_DIAGNOSTIC_AUTHORITY_BLOCKED: module-free authority type/candidate/repository/source-pin boundary is invalid'
        }
        $expectedPaths = @(
            'scripts/d32-bounded-compiler-diagnostic.ps1',
            'scripts/d32-bounded-compiler-diagnostic-policy.ps1',
            'scripts/d32-bounded-compiler-diagnostic-selftest.ps1',
            'scripts/d32-fixture-prebuild.ps1',
            'scripts/d32-build-toolchain-profile.ps1',
            'scripts/d32-powershell-module-authority.ps1')
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($reference in $bootstrap.source_pins) {
            $referenceNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($property in $reference.PSObject.Properties) { [void]$referenceNames.Add([string]$property.Name) }
            $missingReferenceFields = @(@('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex') | Where-Object { -not $referenceNames.Contains($_) })
            if ($referenceNames.Count -ne 5 -or $missingReferenceFields.Count -ne 0) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: source pin has unknown or missing fields'
            }
            $path = [string]$reference.path
            if (-not [IO.Path]::IsPathRooted($path) -or [IO.Path]::GetFullPath($path) -cne $path -or
                -not (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $Repo) -or
                [Int64]$reference.bytes -le 0 -or [string]$reference.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                [string]$reference.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$reference.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
                -not $seen.Add([IO.Path]::GetRelativePath($Repo, $path).Replace('\', '/'))) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: source pin failed module-free path/schema/uniqueness validation'
            }
            $relative = [IO.Path]::GetRelativePath($Repo, $path).Replace('\', '/')
            if ($expectedPaths -cnotcontains $relative) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: source pin path is outside the fixed helper closure' }
            $opened = Open-D32PowerShellAuthorityFile -Path $path -DirectoryFences $directoryFences
            $authorityFiles.Add($opened)
            if ([Int64]$opened.Record.bytes -ne [Int64]$reference.bytes -or [string]$opened.Record.sha256 -cne [string]$reference.sha256 -or
                [string]$opened.Record.volume_serial_hex -cne [string]$reference.volume_serial_hex -or [string]$opened.Record.file_id_hex -cne [string]$reference.file_id_hex) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: current helper source differs from the independently pinned opened-file identity'
            }
        }
        foreach ($relative in $expectedPaths) { if (-not $seen.Contains($relative)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: fixed helper closure has a missing source pin' } }
        return $bootstrap
    }
    finally {
        foreach ($file in $authorityFiles) { if ($null -ne $file.Stream -and -not $file.Stream.SafeFileHandle.IsClosed) { $file.Stream.Dispose() } }
        foreach ($directory in $directoryFences.Values) { if ($null -ne $directory.Handle -and -not $directory.Handle.IsClosed) { $directory.Handle.Dispose() } }
    }
}

function Assert-D32BoundedDiagnosticSourceProofBootstrap {
    param([Parameter(Mandatory = $true)][string]$Repo)
    $expectedTop = @('schema_version', 'record_type', 'gate_authority', 'candidate_sha', 'historical_origin_candidate_sha',
        'registry_archive_policy', 'source_repo', 'repository_identity', 'toolchain_profile', 'source_pins', 'dependency_origin', 'proof_budget',
        'output_candidate', 'run_id', 'issued_at_utc')
    $authorityFull = [IO.Path]::GetFullPath($SourceProofAuthorityPath)
    $requiredOrigin = 'E:\d32\inv7\r\c'
    if (-not [IO.Path]::IsPathRooted($SourceProofAuthorityPath) -or $authorityFull -cne $SourceProofAuthorityPath -or
        -not (Test-D32PowerShellAuthorityPathNoReparse -Path $authorityFull) -or
        (Test-D32PowerShellAuthorityPathWithin -Child $authorityFull -Parent $Repo) -or
        (Test-D32PowerShellAuthorityPathWithin -Child $authorityFull -Parent $requiredOrigin) -or
        $ExpectedSourceProofAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedToolchainProfileSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $HistoricalOriginCandidateSha -cne $script:D32BoundedDiagnosticHistoricalOriginCandidateSha -or
        $CandidateSha -cnotmatch '^[0-9a-f]{40}$' -or $CandidateSha -ceq $HistoricalOriginCandidateSha) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: source-proof authority or current/historical candidate pin is invalid'
    }
    if ((Get-D32BoundedDiagnosticSourceProofCurrentElapsedMilliseconds -ProofTimer $script:D32BoundedDiagnosticSourceProofWallTimer) -ge 270000L) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: shared work deadline expired before SourceProof V3 admission'
    }
    $directoryFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
    $authorityFile = $null
    try {
        $authorityFile = Open-D32PowerShellAuthorityFile -Path $authorityFull -DirectoryFences $directoryFences -MaximumBytes 4194304 -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
        if ((Get-D32BoundedDiagnosticSourceProofCurrentElapsedMilliseconds -ProofTimer $script:D32BoundedDiagnosticSourceProofWallTimer) -ge 270000L) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: late SourceProof V3 authority bytes discarded at work cutoff'
        }
        if ([string]$authorityFile.Record.sha256 -cne $ExpectedSourceProofAuthoritySha256) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: independently supplied source-proof authority SHA differs from current opened bytes'
        }
        $jsonDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$authorityFile.Bytes))
        try {
            if ($jsonDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                (Test-D32PowerShellAuthorityJsonDuplicates -Element $jsonDocument.RootElement)) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: source-proof authority root or duplicate-key validation failed before helper load'
            }
            Assert-D32PowerShellAuthorityExactJsonRecord -Element $jsonDocument.RootElement -Fields $expectedTop -Name 'bounded diagnostic source-proof authority'
            $bootstrap = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $jsonDocument.RootElement
        }
        finally { $jsonDocument.Dispose() }
        if ([int64]$bootstrap.schema_version -ne 3 -or [string]$bootstrap.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_AUTHORITY_V3' -or
            [string]$bootstrap.registry_archive_policy -cne 'D32_REGISTRY_TAR_USTAR_GNU_LONGNAME_V1' -or
            [string]$bootstrap.gate_authority -cne 'NONE' -or [string]$bootstrap.candidate_sha -cne $CandidateSha -or
            [string]$bootstrap.historical_origin_candidate_sha -cne $HistoricalOriginCandidateSha -or
            [string]$bootstrap.source_repo -cne $Repo -or [string]$bootstrap.toolchain_profile.path -cne $ToolchainProfilePath -or
            [string]$bootstrap.toolchain_profile.sha256 -cne $ExpectedToolchainProfileSha256 -or
            $bootstrap.source_pins -isnot [Array] -or $bootstrap.source_pins.Count -ne 5) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: authority type, exact candidate/profile pins, or finite source-pin set is invalid'
        }
        $expectedRelative = @(
            'scripts/d32-bounded-diagnostic-sourceproof.ps1',
            'scripts/d32-bounded-compiler-diagnostic.ps1',
            'scripts/d32-bounded-compiler-diagnostic-policy.ps1',
            'scripts/d32-build-toolchain-profile.ps1',
            'scripts/d32-powershell-module-authority.ps1')
        $expectedPaths = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($relative in $expectedRelative) {
            $expectedPath = [IO.Path]::GetFullPath((Join-Path $Repo ($relative.Replace('/', '\'))))
            $expectedPaths.Add($relative, $expectedPath)
        }
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($reference in $bootstrap.source_pins) {
            if ((Get-D32BoundedDiagnosticSourceProofCurrentElapsedMilliseconds -ProofTimer $script:D32BoundedDiagnosticSourceProofWallTimer) -ge 270000L) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: shared work deadline expired before code-pin admission read'
            }
            $referenceFields = @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')
            $referenceNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($property in $reference.PSObject.Properties) { [void]$referenceNames.Add([string]$property.Name) }
            if ($referenceNames.Count -ne 5 -or @($referenceFields | Where-Object { -not $referenceNames.Contains($_) }).Count -ne 0) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: source-proof source pin has missing or extra fields'
            }
            $path = [string]$reference.path
            if (-not [IO.Path]::IsPathRooted($path) -or [IO.Path]::GetFullPath($path) -cne $path -or
                -not (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $Repo) -or
                [int64]$reference.bytes -le 0 -or [int64]$reference.bytes -gt 16777216 -or
                [string]$reference.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                [string]$reference.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
                [string]$reference.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or -not $seen.Add($path)) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: source-proof source pin path/identity/byte bound is invalid'
            }
            $relative = [IO.Path]::GetRelativePath($Repo, $path).Replace('\', '/')
            if (-not $expectedPaths.ContainsKey($relative)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: source-proof pin path is outside the fixed code closure' }
            if ([string]$reference.path -cne $expectedPaths[$relative] -or
                ([StringComparer]::OrdinalIgnoreCase.Equals($relative, 'scripts/d32-bounded-diagnostic-sourceproof.ps1') -and $path -cne [IO.Path]::GetFullPath($SourceProofEntryPath)) -or
                ([StringComparer]::OrdinalIgnoreCase.Equals($relative, 'scripts/d32-bounded-compiler-diagnostic.ps1') -and $path -cne [IO.Path]::GetFullPath($PSCommandPath))) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: entry or runner source pin differs from the exact invoked scripts'
            }
            $opened = Open-D32PowerShellAuthorityFile -Path $path -DirectoryFences $directoryFences -MaximumBytes 16777216 -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
            try {
                if ((Get-D32BoundedDiagnosticSourceProofCurrentElapsedMilliseconds -ProofTimer $script:D32BoundedDiagnosticSourceProofWallTimer) -ge 270000L) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: late code-pin bytes discarded at shared work cutoff'
                }
                if ([int64]$opened.Record.bytes -ne [int64]$reference.bytes -or [string]$opened.Record.sha256 -cne [string]$reference.sha256 -or
                    [string]$opened.Record.volume_serial_hex -cne [string]$reference.volume_serial_hex -or
                    [string]$opened.Record.file_id_hex -cne [string]$reference.file_id_hex) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: source-proof code differs from independent opened-file pin'
                }
            }
            finally { $opened.Stream.Dispose() }
        }
        foreach ($relative in $expectedRelative) { if (-not $seen.Contains($expectedPaths[$relative])) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: fixed source-proof code closure has a missing pin' } }
        $script:D32BoundedDiagnosticSourceProofAuthorityReference = [PSCustomObject]@{
            path = [string]$authorityFile.Record.path
            bytes = [Int64]$authorityFile.Record.bytes
            sha256 = [string]$authorityFile.Record.sha256
            volume_serial_hex = [string]$authorityFile.Record.volume_serial_hex
            file_id_hex = [string]$authorityFile.Record.file_id_hex
        }
        return $bootstrap
    }
    finally {
        if ($null -ne $authorityFile -and $null -ne $authorityFile.Stream -and -not $authorityFile.Stream.SafeFileHandle.IsClosed) { $authorityFile.Stream.Dispose() }
        foreach ($directory in $directoryFences.Values) { if ($null -ne $directory.Handle -and -not $directory.Handle.IsClosed) { $directory.Handle.Dispose() } }
    }
}

function Assert-D32BoundedDiagnosticSourceProofExecutionBootstrap {
    param([Parameter(Mandatory = $true)][string]$Repo)
    $authorityFull = [IO.Path]::GetFullPath($ExecutionAuthorityPath)
    if (-not [IO.Path]::IsPathRooted($ExecutionAuthorityPath) -or $authorityFull -cne $ExecutionAuthorityPath -or
        -not (Test-D32PowerShellAuthorityPathNoReparse -Path $authorityFull) -or
        (Test-D32PowerShellAuthorityPathWithin -Child $authorityFull -Parent $Repo) -or
        (Test-D32PowerShellAuthorityPathWithin -Child $authorityFull -Parent 'E:\d32\inv7\r\c') -or
        $ExpectedExecutionAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: execution authority path or caller-supplied pin is invalid'
    }
    if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $LifecycleWorkDeadlineTicks) {
        throw 'D32_SOURCEPROOF_LIFECYCLE_BUDGET_STOPPED: work cutoff reached before authority read'
    }
    $directoryFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
    $authorityFile = $null
    try {
        $authorityFile = Open-D32PowerShellAuthorityFile -Path $authorityFull -DirectoryFences $directoryFences -MaximumBytes 1048576 -DeadlineTicks $LifecycleWorkDeadlineTicks
        if ([Diagnostics.Stopwatch]::GetTimestamp() -ge $LifecycleWorkDeadlineTicks) {
            throw 'D32_SOURCEPROOF_LIFECYCLE_BUDGET_STOPPED: late authority bytes discarded at shared work cutoff'
        }
        if ([string]$authorityFile.Record.sha256 -cne $ExpectedExecutionAuthoritySha256) {
            throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: caller-pinned execution authority SHA differs from opened bytes'
        }
        $jsonDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$authorityFile.Bytes))
        try {
            if ($jsonDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                (Test-D32PowerShellAuthorityJsonDuplicates -Element $jsonDocument.RootElement)) {
                throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: execution authority root or duplicate-property validation failed'
            }
            Assert-D32PowerShellAuthorityExactJsonRecord -Element $jsonDocument.RootElement -Fields @('schema_version', 'record_type', 'timing_policy',
                'gate_authority', 'candidate_sha', 'source_repo', 'repository_identity', 'run_id', 'owner_id', 'source_proof_authority',
                'toolchain_profile', 'powershell_runtime', 'source_pins', 'invocation', 'output', 'clock', 'limits', 'issued_at_utc') `
                -Name 'bounded source-proof execution authority V1'
            $document = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $jsonDocument.RootElement
        }
        finally { $jsonDocument.Dispose() }
        if (-not (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityShape -Document $document -ExpectedCandidateSha $CandidateSha -Repository $Repo) -or
            [string]$document.source_proof_authority.path -cne [IO.Path]::GetFullPath($SourceProofAuthorityPath) -or
            [string]$document.source_proof_authority.sha256 -cne $ExpectedSourceProofAuthoritySha256 -or
            [string]$document.toolchain_profile.path -cne [IO.Path]::GetFullPath($ToolchainProfilePath) -or
            [string]$document.toolchain_profile.sha256 -cne $ExpectedToolchainProfileSha256 -or
            [string]$document.invocation.entry_path -cne [IO.Path]::GetFullPath($SourceProofEntryPath) -or
            [Int64]$document.clock.frequency -ne $LifecycleCounterFrequency -or
            $LifecycleWorkDeadlineTicks -ne (ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $LifecycleT0Ticks -Frequency $LifecycleCounterFrequency -DeadlineMilliseconds 270000L) -or
            $LifecycleProofExpiryTicks -ne (ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $LifecycleT0Ticks -Frequency $LifecycleCounterFrequency -DeadlineMilliseconds 300000L) -or
            [string]$document.powershell_runtime.path -cne [IO.Path]::GetFullPath([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)) {
            throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: execution authority does not bind the exact candidate, entry, inner authority, profile, runtime, or shared clock argv'
        }
        $reference = [PSCustomObject]@{
            path = [string]$authorityFile.Record.path
            bytes = [Int64]$authorityFile.Record.bytes
            sha256 = [string]$authorityFile.Record.sha256
            volume_serial_hex = [string]$authorityFile.Record.volume_serial_hex
            file_id_hex = [string]$authorityFile.Record.file_id_hex
        }
        $script:D32BoundedDiagnosticSourceProofLifecycleAuthorityReference = $reference
        $script:D32BoundedDiagnosticSourceProofLifecycleClock = [PSCustomObject]@{
            counter_origin = 'QueryPerformanceCounter'
            frequency = [Int64]$LifecycleCounterFrequency
            t0_ticks = [Int64]$LifecycleT0Ticks
            work_deadline_ticks = [Int64]$LifecycleWorkDeadlineTicks
            proof_expiry_ticks = [Int64]$LifecycleProofExpiryTicks
            cleanup_deadline_ticks = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $LifecycleT0Ticks -Frequency $LifecycleCounterFrequency -DeadlineMilliseconds 345000L
            terminal_audit_deadline_ticks = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $LifecycleT0Ticks -Frequency $LifecycleCounterFrequency -DeadlineMilliseconds 360000L
        }
        if ((Get-D32BoundedDiagnosticSourceProofCurrentElapsedMilliseconds -ProofTimer $script:D32BoundedDiagnosticSourceProofWallTimer) -ge 270000L) {
            throw 'D32_SOURCEPROOF_LIFECYCLE_BUDGET_STOPPED: execution authority admission crossed the shared work cutoff'
        }
        return [PSCustomObject]@{ Document = $document; Reference = $reference }
    }
    finally {
        if ($null -ne $authorityFile -and $null -ne $authorityFile.Stream -and -not $authorityFile.Stream.SafeFileHandle.IsClosed) { $authorityFile.Stream.Dispose() }
        foreach ($directory in $directoryFences.Values) { if ($null -ne $directory.Handle -and -not $directory.Handle.IsClosed) { $directory.Handle.Dispose() } }
    }
}

. (Join-Path $PSScriptRoot 'd32-bounded-compiler-diagnostic-policy.ps1')

$repositoryFull = [IO.Path]::GetFullPath($Repository)
if ($repositoryFull -cne $Repository -or $CandidateSha -cnotmatch '^[0-9a-f]{40}$') { throw 'D32_BOUNDED_DIAGNOSTIC_REFUSED: repository or candidate pin is not exact' }
if ($PSCmdlet.ParameterSetName -ceq 'SourceProofOnly') {
    $script:D32BoundedDiagnosticSourceProofExecutionBootstrapContext = Assert-D32BoundedDiagnosticSourceProofExecutionBootstrap -Repo $repositoryFull
    $script:D32BoundedDiagnosticSourceProofBootstrapAuthority = Assert-D32BoundedDiagnosticSourceProofBootstrap -Repo $repositoryFull
    if (-not (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityBindings `
        -ExecutionAuthority $script:D32BoundedDiagnosticSourceProofExecutionBootstrapContext.Document `
        -SourceProofAuthority $script:D32BoundedDiagnosticSourceProofBootstrapAuthority `
        -SourceProofAuthorityReference $script:D32BoundedDiagnosticSourceProofAuthorityReference `
        -ExpectedCandidateSha $CandidateSha -Repository $repositoryFull)) {
        throw 'D32_SOURCEPROOF_LIFECYCLE_REFUSED: execution authority and strict inner SourceProof V3 do not cross-bind'
    }
}
else {
    $script:D32BoundedDiagnosticBootstrapAuthority = Assert-D32BoundedDiagnosticBootstrapPins -Repo $repositoryFull
}

. (Join-Path $PSScriptRoot 'd32-build-toolchain-profile.ps1')

function Test-D32BoundedDiagnosticJsonDuplicates {
    param([Parameter(Mandatory = $true)][System.Text.Json.JsonElement]$Element)
    switch ($Element.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Object) {
            $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($property in $Element.EnumerateObject()) {
                if (-not $names.Add($property.Name) -or (Test-D32BoundedDiagnosticJsonDuplicates -Element $property.Value)) { return $true }
            }
        }
        ([System.Text.Json.JsonValueKind]::Array) {
            foreach ($item in $Element.EnumerateArray()) { if (Test-D32BoundedDiagnosticJsonDuplicates -Element $item) { return $true } }
        }
    }
    return $false
}

function Assert-D32BoundedDiagnosticCargoChecksumMetadata {
    param([Parameter(Mandatory = $true)][string]$Text)
    $metadataJson = [System.Text.Json.JsonDocument]::Parse($Text)
    try {
        if ($metadataJson.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
            (Test-D32BoundedDiagnosticJsonDuplicates -Element $metadataJson.RootElement)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: Cargo-generated checksum metadata is malformed'
        }
        $checksumMetadata = ConvertFrom-Json -InputObject $Text -Depth 20 -ErrorAction Stop
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $checksumMetadata @('files', 'package')) -or
            $checksumMetadata.files -is [string] -or $checksumMetadata.files -is [Array] -or
            ($null -ne $checksumMetadata.package -and [string]$checksumMetadata.package -cnotmatch '^[0-9a-f]{64}$')) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: Cargo-generated checksum metadata schema is unsupported'
        }
        foreach ($property in $checksumMetadata.files.PSObject.Properties) {
            if (-not (Test-D32BoundedCompilerDiagnosticTarPath ([string]$property.Name)) -or [string]$property.Value -cnotmatch '^[0-9a-f]{64}$') {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: Cargo-generated checksum metadata contains a malformed path or digest'
            }
        }
        return $checksumMetadata
    }
    finally { $metadataJson.Dispose() }
}

function Read-D32BoundedDiagnosticJson {
    param([Parameter(Mandatory = $true)][string]$Path, [long]$MaximumBytes = 16777216, [AllowNull()][object]$ExpectedReference,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds)
    $full = [IO.Path]::GetFullPath($Path)
    if ($MaximumBytes -le 0 -or $MaximumBytes -gt 16777216) { throw 'D32_BOUNDED_DIAGNOSTIC_AUTHORITY_BLOCKED: JSON read limit is outside the fixed 16 MiB ceiling' }
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_json.open' -Progress ([IO.Path]::GetFileName($full)) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
    $directoryFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
    $opened = $null
    try {
        $deadlineTicks = if ($null -ne $ProofTimer) { Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks } else { [Int64]0 }
        $opened = Open-D32PowerShellAuthorityFile -Path $full -DirectoryFences $directoryFences -MaximumBytes $MaximumBytes -DeadlineTicks $deadlineTicks
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_json.read_complete' -Progress 'late_input_discarded_before_parse' -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
        if ($null -ne $ExpectedReference -and
            ([string]$opened.Record.path -cne [string]$ExpectedReference.path -or [Int64]$opened.Record.bytes -ne [Int64]$ExpectedReference.bytes -or
                [string]$opened.Record.sha256 -cne [string]$ExpectedReference.sha256 -or
                [string]$opened.Record.volume_serial_hex -cne [string]$ExpectedReference.volume_serial_hex -or
                [string]$opened.Record.file_id_hex -cne [string]$ExpectedReference.file_id_hex)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_AUTHORITY_BLOCKED: JSON opened-file content/identity differs from its independent caller pin'
        }
        $text = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$opened.Bytes)
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_json.parse' -Progress ("bytes={0}" -f $opened.Bytes.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
        $document = [System.Text.Json.JsonDocument]::Parse($text)
        try {
            if (Test-D32BoundedDiagnosticJsonDuplicates -Element $document.RootElement) { throw 'D32_BOUNDED_DIAGNOSTIC_AUTHORITY_BLOCKED: duplicate JSON object fields are not permitted' }
        }
        finally { $document.Dispose() }
        $result = ConvertFrom-Json -InputObject $text -Depth 100 -ErrorAction Stop
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_json.convert' -Progress ("bytes={0}" -f $opened.Bytes.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
        return $result
    }
    finally {
        if ($null -ne $opened -and $null -ne $opened.Stream -and -not $opened.Stream.SafeFileHandle.IsClosed) { $opened.Stream.Dispose() }
        foreach ($directory in $directoryFences.Values) { if ($null -ne $directory.Handle -and -not $directory.Handle.IsClosed) { $directory.Handle.Dispose() } }
    }
}

function Assert-D32BoundedDiagnosticFileReference {
    param(
        [Parameter(Mandatory = $true)][object]$Reference,
        [AllowNull()][object]$MustBeWithin,
        [AllowNull()][object]$MustNotBeWithin,
        [Diagnostics.Stopwatch]$ProofTimer,
        [ValidateSet('Regular', 'CapturedStream')][string]$ReferenceKind = 'Regular',
        [string]$ReferenceField = 'file_reference',
        [string]$Caller = 'unspecified',
        [AllowNull()][string]$ExactPath,
        [long]$DeadlineMilliseconds = 300000,
        [switch]$MetadataOnly
    )
    if ($null -ne $ProofTimer) {
        Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'file_reference.identity_check' -Progress ("caller={0};field={1}" -f $Caller, $ReferenceField) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
    }
    $shapeFailure = $null
    if ($ReferenceKind -ceq 'CapturedStream') {
        if ([String]::IsNullOrWhiteSpace($ExactPath) -or -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $ExactPath)) {
            $shapeFailure = 'expected_capture_path_must_be_canonical_absolute_string'
        }
        elseif (-not (Test-D32BoundedCompilerDiagnosticCapturedStreamReferenceShape -Reference $Reference -ExpectedPath $ExactPath)) {
            $shapeFailure = Get-D32BoundedCompilerDiagnosticFileReferenceShapeFailure -Reference $Reference -AllowEmptyBytes
            if ($null -eq $shapeFailure) { $shapeFailure = 'path_must_equal_expected_capture_path' }
        }
    }
    elseif (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Reference)) {
        $shapeFailure = Get-D32BoundedCompilerDiagnosticFileReferenceShapeFailure -Reference $Reference
    }
    $callerValue = if ([String]::IsNullOrWhiteSpace($Caller)) { 'unspecified' } else { $Caller }
    $referenceFieldValue = if ([String]::IsNullOrWhiteSpace($ReferenceField)) { 'file_reference' } else { $ReferenceField }
    $path = [string]$Reference.path
    $actualReference = Format-D32BoundedCompilerDiagnosticPathForError $path
    $expectedRoot = if ($null -eq $MustBeWithin) { 'null' } else { Format-D32BoundedCompilerDiagnosticPathForError $MustBeWithin }
    $protectedRoot = if ($null -eq $MustNotBeWithin) { 'null' } else { Format-D32BoundedCompilerDiagnosticPathForError $MustNotBeWithin }
    if ($null -ne $shapeFailure) {
        $invalidField = switch -Regex ([string]$shapeFailure) {
            '^(?:path_|path$|expected_capture_path)' { 'path' }
            '^bytes_' { 'bytes' }
            '^sha256_' { 'sha256' }
            '^volume_file_identity_' { 'volume_serial_hex/file_id_hex' }
            '^property_set_' { 'properties' }
            default { 'reference' }
        }
        $fieldValue = if ($invalidField -ceq 'reference') { $referenceFieldValue } else { "$referenceFieldValue.$invalidField" }
        throw "D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: exact source file reference is malformed; caller=$callerValue; field=$fieldValue; reason=$shapeFailure; actual_ref=$actualReference; expected_root=$expectedRoot"
    }
    $referenceContext = "caller=$callerValue; field=$referenceFieldValue.path; actual_ref=$actualReference; expected_root=$expectedRoot"
    if ($null -ne $MustBeWithin) {
        if ($MustBeWithin -isnot [string] -or -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $MustBeWithin)) {
            throw "D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: authorized containment root is invalid; $referenceContext"
        }
        if (-not (Test-D32BoundedCompilerDiagnosticWithin -Child $path -Parent $MustBeWithin)) {
            throw "D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: source reference escaped its authorized root; $referenceContext"
        }
    }
    if ($null -ne $MustNotBeWithin) {
        if ($MustNotBeWithin -isnot [string] -or -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $MustNotBeWithin)) {
            throw "D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: protected source root is invalid; $referenceContext; protected_root=$protectedRoot"
        }
        if (Test-D32BoundedCompilerDiagnosticWithin -Child $path -Parent $MustNotBeWithin) {
            throw "D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: evidence reference overlaps a protected source root; $referenceContext; protected_root=$protectedRoot"
        }
    }
    if (-not (Test-D32ProfileNoReparsePath -Path $path)) {
        throw "D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: source file reference is missing or traverses a reparse point; $referenceContext"
    }
    $deadlineTicks = if ($null -ne $ProofTimer) { Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks } else { [Int64]0 }
    $snapshot = if ($MetadataOnly) { Get-D32ProfileFileMetadataSnapshot -Path $path } else { Get-D32ProfileFileSnapshot -Path $path -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks $deadlineTicks }
    if ($null -ne $ProofTimer) {
        Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase $(if ($MetadataOnly) { 'file_reference.metadata_check' } else { 'file_reference.content_hash' }) -Progress ("caller={0};field={1}" -f $Caller, $ReferenceField) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
    }
    if ($snapshot.Bytes -ne [Int64]$Reference.bytes -or
        (-not $MetadataOnly -and $snapshot.Sha256 -cne [string]$Reference.sha256) -or
        $snapshot.VolumeSerialHex -cne [string]$Reference.volume_serial_hex -or $snapshot.FileIdHex -cne [string]$Reference.file_id_hex) {
        throw "D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: current source file bytes or opened-handle identity differ from the independently pinned reference; $referenceContext; protected_root=$protectedRoot"
    }
    return $snapshot
}

function New-D32BoundedDiagnosticRegistryArchiveFileReferenceProjection {
    param([Parameter(Mandatory = $true)][object]$Reference)
    $archiveFields = @('source', 'name', 'version', 'checksum', 'path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $Reference -Expected $archiveFields) -or
        [string]$Reference.source -cne 'registry+https://github.com/rust-lang/crates.io-index' -or
        [string]$Reference.name -notmatch '^[A-Za-z0-9_-]+$' -or [string]$Reference.version -notmatch '^[0-9A-Za-z.+_-]+$' -or
        [string]$Reference.checksum -cnotmatch '^[0-9a-f]{64}$' -or [string]$Reference.sha256 -cne [string]$Reference.checksum -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Reference.path) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Reference.bytes -Positive) -or [Int64]$Reference.bytes -gt 268435456L -or
        [string]$Reference.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$Reference.file_id_hex -cnotmatch '^[0-9a-f]{32}$') {
        throw "D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: registry archive projection requires its exact nine-field caller schema; actual_ref=$(Format-D32BoundedCompilerDiagnosticPathForError $Reference.path)"
    }
    return [PSCustomObject][ordered]@{
        path = $Reference.path
        bytes = $Reference.bytes
        sha256 = $Reference.sha256
        volume_serial_hex = $Reference.volume_serial_hex
        file_id_hex = $Reference.file_id_hex
    }
}

function Assert-D32BoundedDiagnosticDirectoryReference {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$VolumeSerialHex, [Parameter(Mandatory = $true)][string]$FileIdHex)
    if (-not (Test-D32ProfileCanonicalPathString -Path $Path) -or -not (Test-D32ProfileNoReparsePath -Path $Path)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: authorized directory path is noncanonical, missing, or reparse-backed' }
    $identity = Get-D32ProfileDirectoryIdentity -Path $Path
    if ($identity.VolumeSerialHex -cne $VolumeSerialHex -or $identity.FileIdHex -cne $FileIdHex) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: authorized directory opened-handle identity changed' }
    return $identity
}

function Get-D32BoundedDiagnosticSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Get-D32BoundedDiagnosticSha256ForFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant() }
    finally { $stream.Dispose() }
}

function Assert-D32BoundedDiagnosticAuthorityDocument {
    param([Parameter(Mandatory = $true)][object]$Document, [Parameter(Mandatory = $true)][string]$Repo,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedEnvironment)
    if (-not (Test-D32BoundedCompilerDiagnosticAuthorityShape -Document $Document -ExpectedCandidateSha $CandidateSha -Repository $Repo `
        -ToolchainProfilePath $ToolchainProfilePath -ToolchainProfileSha256 $ExpectedToolchainProfileSha256 `
        -ModuleAuthorityPath $PowerShellModuleAuthorityPath -ModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
        -PinnedGitPath $PinnedGitPath -PinnedGitSha256 $PinnedGitSha256 -ExpectedEnvironment $ExpectedEnvironment)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_AUTHORITY_BLOCKED: authority is stale, malformed, cross-root, outside the exact invocation, or violates the bounded profile'
    }
}

function Assert-D32BoundedDiagnosticSourcePins {
    param([Parameter(Mandatory = $true)][object]$Document, [Parameter(Mandatory = $true)][string]$Repo)
    $requiredRelative = @(
        'scripts/d32-bounded-compiler-diagnostic.ps1',
        'scripts/d32-bounded-compiler-diagnostic-policy.ps1',
        'scripts/d32-bounded-compiler-diagnostic-selftest.ps1',
        'scripts/d32-fixture-prebuild.ps1',
        'scripts/d32-build-toolchain-profile.ps1',
        'scripts/d32-powershell-module-authority.ps1'
    )
    $seen = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $pinIndex = 0
    foreach ($pin in $Document.source_pins) {
        $snapshot = Assert-D32BoundedDiagnosticFileReference -Reference $pin -MustBeWithin $Repo -MustNotBeWithin $null `
            -ReferenceField "document.source_pins[$pinIndex]" -Caller 'Assert-D32BoundedDiagnosticSourcePins'
        $relative = [IO.Path]::GetRelativePath($Repo, [string]$pin.path).Replace('\', '/')
        if (-not $seen.TryAdd($relative, $snapshot)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: source pin is duplicated' }
        $pinIndex++
    }
    foreach ($relative in $requiredRelative) {
        if (-not $seen.ContainsKey($relative)) { throw "D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: required source identity is not pinned: $relative" }
    }
    return $true
}

function New-D32BoundedDiagnosticChildEnvironment {
    param([Parameter(Mandatory = $true)][object]$Profile, [Parameter(Mandatory = $true)][string]$CargoHome, [Parameter(Mandatory = $true)][string]$TempRoot)
    $native = $Profile.Profile.native
    $pathEntries = @((Join-Path ([string]$Profile.Profile.rust_toolchain_root) 'bin')) + @($native.path_entries | ForEach-Object { [string]$_ })
    $environment = [ordered]@{
        SystemRoot = [string]$Profile.Profile.system_root
        TEMP = [IO.Path]::GetFullPath($TempRoot)
        TMP = [IO.Path]::GetFullPath($TempRoot)
        PATH = $pathEntries -join [IO.Path]::PathSeparator
        INCLUDE = @($native.include_dirs | ForEach-Object { [string]$_ }) -join ';'
        LIB = @($native.lib_dirs | ForEach-Object { [string]$_ }) -join ';'
        LIBPATH = @($native.libpath_dirs | ForEach-Object { [string]$_ }) -join ';'
        CARGO_HOME = [IO.Path]::GetFullPath($CargoHome)
        RUSTC = [string]$Profile.Profile.toolchain.rustc.path
        RUSTDOC = [string]$Profile.Profile.toolchain.rustdoc.path
        CARGO_NET_OFFLINE = 'true'
    }
    foreach ($entry in $native.environment.PSObject.Properties) {
        if ($environment.Contains($entry.Name)) { throw 'D32_BOUNDED_DIAGNOSTIC_ENVIRONMENT_BLOCKED: Profile V2 repeats a fixed environment variable' }
        $environment[[string]$entry.Name] = [string]$entry.Value
    }
    if (-not (Test-D32BoundedCompilerDiagnosticExactEnvironment -Environment $environment -Expected $environment)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ENVIRONMENT_BLOCKED: child environment is not finite, exact, nonsecret, or profile-derived'
    }
    return $environment
}

function Get-D32BoundedDiagnosticEnvironmentSha256 {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Environment)
    $rows = [System.Collections.Generic.List[string]]::new()
    foreach ($key in @($Environment.Keys | Sort-Object -CaseSensitive)) { $rows.Add(([string]$key + "`t" + [string]$Environment[$key])) }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($rows -join "`n") + "`n")
    return Get-D32BoundedDiagnosticSha256 -Bytes $bytes
}

function New-D32BoundedDiagnosticReferenceFromSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $snapshot = Get-D32ProfileFileSnapshot -Path $Path
    return [PSCustomObject][ordered]@{
        path = [string]$snapshot.Path; bytes = [Int64]$snapshot.Bytes; sha256 = [string]$snapshot.Sha256
        volume_serial_hex = [string]$snapshot.VolumeSerialHex; file_id_hex = [string]$snapshot.FileIdHex
    }
}

function Assert-D32BoundedDiagnosticOwnerRecord {
    param([Parameter(Mandatory = $true)][object]$Reference,
        [Parameter(Mandatory = $true)][string]$Repo, [Parameter(Mandatory = $true)][string]$HistoricalOriginCandidateSha,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds)
    $originRoot = 'E:\d32\inv7'
    $expectedPath = Join-Path $originRoot 'D32-PHASE0-OWNER.json'
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Reference.path, $expectedPath)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: owner record is not the exact existing inv7 Phase0 owner marker'
    }
    $rootIdentity = Get-D32ProfileDirectoryIdentity -Path $originRoot
    $owner = Read-D32BoundedDiagnosticJson -Path ([string]$Reference.path) -ExpectedReference $Reference -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    $fields = @('schema_version', 'record_type', 'candidate_sha', 'toolchain_profile_path', 'toolchain_profile_sha256',
        'toolchain_profile_bytes', 'toolchain_profile_volume_serial_hex', 'toolchain_profile_file_id_hex',
        'evidence_root_path', 'evidence_root_volume_serial_hex', 'evidence_root_file_id_hex', 'run_id')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $owner $fields) -or
        [int64]$owner.schema_version -ne 1 -or [string]$owner.record_type -cne 'D32_PHASE0_EVIDENCE_OWNER_V1' -or
        [string]$owner.candidate_sha -cne $HistoricalOriginCandidateSha -or
        -not (Test-D32ProfileCanonicalPathString -Path ([string]$owner.toolchain_profile_path)) -or
        (Test-D32BoundedCompilerDiagnosticWithin ([string]$owner.toolchain_profile_path) $Repo) -or
        [string]$owner.toolchain_profile_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $owner.toolchain_profile_bytes -Positive) -or
        [string]$owner.toolchain_profile_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        [string]$owner.toolchain_profile_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$owner.evidence_root_path, $originRoot) -or
        [string]$owner.evidence_root_volume_serial_hex -cne [string]$rootIdentity.VolumeSerialHex -or
        [string]$owner.evidence_root_file_id_hex -cne [string]$rootIdentity.FileIdHex -or
        [string]$owner.run_id -cnotmatch '^[0-9a-f]{32}$') {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: historical owner record does not bind its original candidate/profile fields/opened inv7 root/run identity'
    }
    return [PSCustomObject]@{
        RunId = [string]$owner.run_id
        EvidenceRoot = $originRoot
        EvidenceRootIdentity = $rootIdentity
        HistoricalProfilePath = [string]$owner.toolchain_profile_path
        HistoricalProfileSha256 = [string]$owner.toolchain_profile_sha256
        HistoricalProfileBytes = [Int64]$owner.toolchain_profile_bytes
        HistoricalProfileVolumeSerialHex = [string]$owner.toolchain_profile_volume_serial_hex
        HistoricalProfileFileIdHex = [string]$owner.toolchain_profile_file_id_hex
    }
}

function Assert-D32BoundedDiagnosticPriorInv7Provenance {
    param(
        [Parameter(Mandatory = $true)][object]$Origin,
        [Parameter(Mandatory = $true)][object]$Owner,
        [Parameter(Mandatory = $true)][string]$Repo,
        [Parameter(Mandatory = $true)][string]$HistoricalOriginCandidateSha,
        [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds
    )
    $originRoot = 'E:\d32\inv7'
    $blockedPath = Join-Path $originRoot 'D32-PHASE0-BLOCKED-DIAGNOSTIC.json'
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Origin.blocked_diagnostic.path, $blockedPath)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: prior inv7 input is not the exact retained blocked attempt'
    }
    $null = Assert-D32BoundedDiagnosticFileReference -Reference $Origin.blocked_diagnostic -MustBeWithin $originRoot -MustNotBeWithin $Repo `
        -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -ReferenceField 'dependency_origin.blocked_diagnostic' -Caller 'Assert-D32BoundedDiagnosticPriorInv7Provenance'
    $blocked = Read-D32BoundedDiagnosticJson -Path $blockedPath -ExpectedReference $Origin.blocked_diagnostic -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    $blockedFields = @('schema_version', 'record_type', 'candidate_sha', 'run_id', 'status', 'gate_authority', 'phase1_allowed',
        'aggregate_allowed', 'toolchain_profile', 'evidence_root', 'failing_fixed_command', 'raw_v2_trace', 'ordered_stream_captures',
        'process_identity', 'job_debug_cleanup', 'unverified_fields', 'primary_error', 'secondary_errors', 'generated_at_utc')
    $blockedProfileFields = @('path', 'sha256', 'file_identity')
    $blockedRootFields = @('path', 'volume_serial_hex', 'file_id_hex', 'owner_marker')
    $blockedCommandFields = @('name', 'executable', 'executable_sha256', 'executable_bytes', 'executable_volume_serial_hex',
        'executable_file_id_hex', 'arguments', 'command_line', 'working_directory')
    $expectedArguments = @('test', '--manifest-path', 'vita-agent/Cargo.toml', '--all-targets', '--locked', '--offline',
        '--features', 'd32-a-test-helper', '--jobs', '4', '--', '--list')
    $expectedCapturePaths = @(
        (Join-Path (Join-Path $originRoot 'logs') 'phase0-06-vita-test-list.stdout.log'),
        (Join-Path (Join-Path $originRoot 'logs') 'phase0-06-vita-test-list.stderr.log'))
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $blocked $blockedFields) -or
        [int64]$blocked.schema_version -ne 1 -or [string]$blocked.record_type -cne 'D32_PHASE0_BLOCKED_DIAGNOSTIC_V1' -or
        [string]$blocked.candidate_sha -cne $HistoricalOriginCandidateSha -or [string]$blocked.run_id -cne [string]$Owner.RunId -or
        [string]$blocked.status -cne 'BLOCKED' -or [string]$blocked.gate_authority -cne 'NONE' -or
        $blocked.phase1_allowed -isnot [bool] -or [bool]$blocked.phase1_allowed -or
        $blocked.aggregate_allowed -isnot [bool] -or [bool]$blocked.aggregate_allowed -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $blocked.toolchain_profile $blockedProfileFields) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $blocked.toolchain_profile.file_identity @('bytes', 'volume_serial_hex', 'file_id_hex')) -or
        [string]$blocked.toolchain_profile.path -cne [string]$Owner.HistoricalProfilePath -or
        [string]$blocked.toolchain_profile.sha256 -cne [string]$Owner.HistoricalProfileSha256 -or
        [Int64]$blocked.toolchain_profile.file_identity.bytes -ne [Int64]$Owner.HistoricalProfileBytes -or
        [string]$blocked.toolchain_profile.file_identity.volume_serial_hex -cne [string]$Owner.HistoricalProfileVolumeSerialHex -or
        [string]$blocked.toolchain_profile.file_identity.file_id_hex -cne [string]$Owner.HistoricalProfileFileIdHex -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $blocked.evidence_root $blockedRootFields) -or
        [string]$blocked.evidence_root.path -cne $originRoot -or
        [string]$blocked.evidence_root.volume_serial_hex -cne [string]$Owner.EvidenceRootIdentity.VolumeSerialHex -or
        [string]$blocked.evidence_root.file_id_hex -cne [string]$Owner.EvidenceRootIdentity.FileIdHex -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $blocked.evidence_root.owner_marker) -or
        [string]$blocked.evidence_root.owner_marker.path -cne [string]$Origin.owner_record.path -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $blocked.failing_fixed_command $blockedCommandFields) -or
        [string]$blocked.failing_fixed_command.name -cne 'vita-test-list' -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$blocked.failing_fixed_command.working_directory, $Repo) -or
        $blocked.failing_fixed_command.arguments -isnot [Array] -or $blocked.failing_fixed_command.arguments.Count -ne $expectedArguments.Count -or
        $blocked.raw_v2_trace.record_type -cne 'D32_DEBUG_JOB_PROCESS_TRACE_V2' -or
        [int64]$blocked.raw_v2_trace.schema_version -ne 2 -or [string]$blocked.raw_v2_trace.state -cne 'BLOCKED' -or
        $blocked.ordered_stream_captures -isnot [Array] -or $blocked.ordered_stream_captures.Count -ne 2) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: retained inv7 record does not prove the exact blocked attempt; it is not a successful discovery record'
    }
    for ($index = 0; $index -lt $expectedArguments.Count; $index++) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'origin.prior_argument_bindings' -Progress ("arguments={0}/{1}" -f $index, $expectedArguments.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        if ($blocked.failing_fixed_command.arguments[$index] -isnot [string] -or
            [string]$blocked.failing_fixed_command.arguments[$index] -cne $expectedArguments[$index]) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: retained inv7 terminal command differs from the exact authorized test-list attempt'
        }
    }
    $captureNames = @('stdout', 'stderr')
    for ($index = 0; $index -lt 2; $index++) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'origin.prior_stream_bindings' -Progress ("captures={0}/2" -f $index) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
        $capture = $blocked.ordered_stream_captures[$index]
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $capture @('ordinal', 'path', 'reference', 'status', 'stream')) -or
            [int64]$capture.ordinal -ne ($index + 1) -or [string]$capture.stream -cne $captureNames[$index] -or [string]$capture.status -cne 'CAPTURED' -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$capture.path, $expectedCapturePaths[$index]) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$capture.reference.path, $expectedCapturePaths[$index])) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: retained inv7 final-command stdout/stderr capture identity is incomplete'
        }
        $null = Assert-D32BoundedDiagnosticFileReference -Reference $capture.reference -MustBeWithin (Join-Path $originRoot 'logs') `
            -MustNotBeWithin $Repo -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -ReferenceKind CapturedStream -ExactPath $expectedCapturePaths[$index] `
            -ReferenceField "dependency_origin.blocked_diagnostic.ordered_stream_captures[$index].reference" `
            -Caller 'Assert-D32BoundedDiagnosticPriorInv7Provenance'
    }

    return [PSCustomObject]@{
        RunId = [string]$Owner.RunId
        HistoricalCandidateSha = $HistoricalOriginCandidateSha
        BlockedDiagnosticPath = $blockedPath
        HistoricalAttemptState = 'BLOCKED'
        HistoricalFetchCompletion = 'NOT_RETAINED'
        HistoricalGateAuthority = 'NONE'
        HistoricalProtocGrantReadOrUsed = $false
    }
}

function Assert-D32BoundedDiagnosticArchiveMatchesExtractedSource {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][object]$ArchiveInventory,
        [Parameter(Mandatory = $true)][Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds,
        [Parameter(Mandatory = $true)][long]$MaximumEntries = 10000
    )
    $rootBefore = Get-D32ProfileDirectoryIdentity -Path $SourceRoot
    $expected = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $archiveIndex = 0
    foreach ($entry in $ArchiveInventory.entries) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.extracted_archive_map' -Progress ("members={0}/{1}" -f $archiveIndex, $ArchiveInventory.entries.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $archiveIndex++
        if (-not $expected.TryAdd([string]$entry.path, $entry)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: archive inventory has a duplicate/case-colliding path' }
    }
    $actualFiles = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $actualDirectories = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $metadata = [System.Collections.Generic.List[object]]::new()
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($SourceRoot)
    $count = 0
    $sourceBytes = [Int64]0
    while ($stack.Count -gt 0) {
        Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.extracted_directory' -Progress ("entries={0};pending={1}" -f $count, $stack.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
        $directory = $stack.Pop()
        foreach ($item in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.extracted_inventory' -Progress ("entries={0}/{1}" -f $count, $MaximumEntries) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
            $count++
            if ($count -gt $MaximumEntries) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: extracted registry source exceeds its fixed entry bound' }
            $attributes = [IO.File]::GetAttributes($item)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: extracted registry source contains a reparse entry' }
            $relative = [IO.Path]::GetRelativePath($SourceRoot, $item).Replace('\', '/')
            if (-not (Test-D32BoundedCompilerDiagnosticTarPath $relative)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: extracted registry source path is noncanonical or unsafe' }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                if (-not $expected.ContainsKey($relative) -or [string]$expected[$relative].kind -cne 'directory' -or
                    [string]$expected[$relative].path -cne $relative -or $actualDirectories.ContainsKey($relative)) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: extracted registry source has an extra/missing/case-colliding directory'
                }
                $directoryIdentity = Get-D32ProfileDirectoryIdentity -Path $item
                $null = $actualDirectories.Add($relative, [PSCustomObject]@{ path = $relative; volume_serial_hex = [string]$directoryIdentity.VolumeSerialHex; file_id_hex = [string]$directoryIdentity.FileIdHex })
                $stack.Push($item)
                continue
            }
            $expectedArchiveMember = $expected.ContainsKey($relative)
            $atSourceRoot = -not $relative.Contains('/')
            $generatedAuxiliary = Test-D32BoundedDiagnosticGeneratedRegistryAuxiliaryFile `
                -RelativePath $relative -AtRoot $atSourceRoot -ArchiveMember $expectedArchiveMember
            if ($generatedAuxiliary -and $relative -ceq '.cargo-ok') {
                $snapshot = Get-D32ProfileFileSnapshot -Path $item -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
                $sourceBytes += [Int64]$snapshot.Bytes
                if (-not (Test-D32BoundedDiagnosticRegistryCargoOkMarkerSnapshot -Bytes ([Int64]$snapshot.Bytes) -Sha256 ([string]$snapshot.Sha256))) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: Cargo-generated registry .cargo-ok marker is not the exact canonical 7-byte v1 record'
                }
                $markerAfter = Get-D32ProfileFileMetadataSnapshot -Path $item
                if ($markerAfter.Bytes -ne $snapshot.Bytes -or
                    $markerAfter.VolumeSerialHex -cne $snapshot.VolumeSerialHex -or $markerAfter.FileIdHex -cne $snapshot.FileIdHex) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: generated metadata changed while it was inspected'
                }
                $metadata.Add([PSCustomObject]@{ path = $relative; bytes = [Int64]$snapshot.Bytes; sha256 = [string]$snapshot.Sha256; volume_serial_hex = [string]$snapshot.VolumeSerialHex; file_id_hex = [string]$snapshot.FileIdHex })
                continue
            }
            if ($generatedAuxiliary -and $relative -ceq '.cargo-checksum.json') {
                $snapshot = Get-D32ProfileFileContentSnapshot -Path $item -MaximumBytes 16777216L -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
                $sourceBytes += [Int64]$snapshot.Bytes
                try { $metadataText = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$snapshot.Content) }
                catch { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: Cargo-generated checksum metadata is not strict UTF-8' }
                $null = Assert-D32BoundedDiagnosticCargoChecksumMetadata -Text $metadataText
                $metadataAfter = Get-D32ProfileFileMetadataSnapshot -Path $item
                if ($metadataAfter.Bytes -ne $snapshot.Bytes -or
                    $metadataAfter.VolumeSerialHex -cne $snapshot.VolumeSerialHex -or $metadataAfter.FileIdHex -cne $snapshot.FileIdHex) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: generated metadata changed while it was inspected'
                }
                $metadata.Add([PSCustomObject]@{ path = $relative; bytes = [Int64]$snapshot.Bytes; sha256 = [string]$snapshot.Sha256; volume_serial_hex = [string]$snapshot.VolumeSerialHex; file_id_hex = [string]$snapshot.FileIdHex })
                continue
            }
            $snapshot = Get-D32ProfileFileSnapshot -Path $item -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
            $sourceBytes += [Int64]$snapshot.Bytes
            $expectedEntry = $null
            if (-not $expected.TryGetValue($relative, [ref]$expectedEntry) -or [string]$expectedEntry.kind -cne 'file' -or
                [string]$expectedEntry.path -cne $relative -or [Int64]$expectedEntry.bytes -ne [Int64]$snapshot.Bytes -or
                [string]$expectedEntry.sha256 -cne [string]$snapshot.Sha256 -or -not $actualFiles.TryAdd($relative, $snapshot)) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: extracted registry file content differs from the lock-checksummed archive or has an extra/colliding path'
            }
        }
    }
    $directoryIndex = 0
    foreach ($directoryRecord in $actualDirectories.Values) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.extracted_directory_identity' -Progress ("directories={0}/{1}" -f $directoryIndex, $actualDirectories.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $directoryIndex++
        $directoryPath = Join-Path $SourceRoot ([string]$directoryRecord.path.Replace('/', '\'))
        $directoryAfter = Get-D32ProfileDirectoryIdentity -Path $directoryPath
        if ($directoryAfter.VolumeSerialHex -cne [string]$directoryRecord.volume_serial_hex -or
            $directoryAfter.FileIdHex -cne [string]$directoryRecord.file_id_hex) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: extracted source subdirectory identity changed during inventory'
        }
    }
    $archiveIndex = 0
    foreach ($entry in $ArchiveInventory.entries) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.extracted_archive_closure' -Progress ("members={0}/{1}" -f $archiveIndex, $ArchiveInventory.entries.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $archiveIndex++
        if ([string]$entry.kind -ceq 'file' -and -not $actualFiles.ContainsKey([string]$entry.path)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: lock-checksummed archive file is missing from its extracted source directory'
        }
        if ([string]$entry.kind -ceq 'directory' -and -not $actualDirectories.ContainsKey([string]$entry.path)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: lock-checksummed archive directory is missing from its extracted source directory'
        }
    }
    $rootAfter = Get-D32ProfileDirectoryIdentity -Path $SourceRoot
    if ($rootBefore.VolumeSerialHex -cne $rootAfter.VolumeSerialHex -or $rootBefore.FileIdHex -cne $rootAfter.FileIdHex) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: extracted source root identity changed during inventory'
    }
    $fileKeys = [string[]]@($actualFiles.Keys)
    $directoryKeys = [string[]]@($actualDirectories.Keys)
    Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.extracted_inventory_sort' -Progress ("files={0};directories={1}" -f $fileKeys.Length, $directoryKeys.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
    [Array]::Sort($fileKeys, [StringComparer]::Ordinal)
    [Array]::Sort($directoryKeys, [StringComparer]::Ordinal)
    Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.extracted_inventory_sort_complete' -Progress ("files={0};directories={1}" -f $fileKeys.Length, $directoryKeys.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
    $inventoryCanonical = [System.Collections.Generic.List[string]]::new()
    $canonicalIndex = 0
    foreach ($key in $fileKeys) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.extracted_inventory_file_rows' -Progress ("rows={0}/{1}" -f $canonicalIndex, $fileKeys.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $file = $actualFiles[$key]
        $inventoryCanonical.Add(('file' + "`t" + $key + "`t" + [Int64]$file.Bytes + "`t" + [string]$file.Sha256 + "`t" + [string]$file.VolumeSerialHex + "`t" + [string]$file.FileIdHex))
        $canonicalIndex++
    }
    $canonicalIndex = 0
    foreach ($key in $directoryKeys) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.extracted_inventory_directory_rows' -Progress ("rows={0}/{1}" -f $canonicalIndex, $directoryKeys.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $directory = $actualDirectories[$key]
        $inventoryCanonical.Add(('directory' + "`t" + $key + "`t" + [string]$directory.volume_serial_hex + "`t" + [string]$directory.file_id_hex))
        $canonicalIndex++
    }
    $metadataRows = [object[]]@($metadata.ToArray())
    [Array]::Sort($metadataRows, [System.Comparison[object]]{ param($left, $right) [StringComparer]::Ordinal.Compare([string]$left.path, [string]$right.path) })
    $canonicalIndex = 0
    foreach ($metadataRow in $metadataRows) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.extracted_inventory_metadata_rows' -Progress ("rows={0}/{1}" -f $canonicalIndex, $metadataRows.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $inventoryCanonical.Add(('metadata' + "`t" + [string]$metadataRow.path + "`t" + [Int64]$metadataRow.bytes + "`t" + [string]$metadataRow.sha256 + "`t" + [string]$metadataRow.volume_serial_hex + "`t" + [string]$metadataRow.file_id_hex))
        $canonicalIndex++
    }
    $inventorySha = Get-D32BoundedDiagnosticSha256FromLines -Lines ([string[]]$inventoryCanonical.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.extracted_inventory_digest'
    return [PSCustomObject][ordered]@{
        source_root = $SourceRoot
        source_root_volume_serial_hex = [string]$rootAfter.VolumeSerialHex
        source_root_file_id_hex = [string]$rootAfter.FileIdHex
        archived_file_count = [Int64]$actualFiles.Count
        archived_directory_count = [Int64]$actualDirectories.Count
        generated_metadata_count = [Int64]$metadata.Count
        observed_source_bytes = $sourceBytes
        source_inventory_sha256 = $inventorySha
    }
}

function New-D32BoundedDiagnosticRegistrySourceContentProof {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object]$Origin,
        [Parameter(Mandatory = $true)][string]$Repo,
        [Parameter(Mandatory = $true)][Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds
    )
    if ([string]$Plan.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_LOCK_SOURCE_PLAN_V2' -or [int]$Plan.schema_version -ne 2 -or
        [string]$Plan.gate_authority -cne 'NONE' -or [string]$Plan.verification_status -cne 'NOT_RUN' -or
        [string]$Plan.source_proof_status -cne 'NOT_VERIFIED' -or $Plan.registry_packages -isnot [Array] -or
        $Plan.registry_packages.Count -le 0 -or $Plan.registry_packages.Count -gt 1536 -or
        $Origin.registry_archives -isnot [Array] -or $Origin.registry_archives.Count -le 0 -or $Origin.registry_archives.Count -gt $Plan.registry_packages.Count) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: source plan or caller-pinned reachable-source archive subset is malformed or outside its finite package bound'
    }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Origin.registry_archive_root.path, [string]$Plan.registry_archive_root) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Origin.registry_source_root.path, [string]$Plan.registry_source_root)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: pinned archive/source roots do not match the lock-derived source plan'
    }
    $archiveRootBefore = Assert-D32BoundedDiagnosticDirectoryReference -Path ([string]$Origin.registry_archive_root.path) -VolumeSerialHex $Origin.registry_archive_root.volume_serial_hex -FileIdHex $Origin.registry_archive_root.file_id_hex
    $sourceRootBefore = Assert-D32BoundedDiagnosticDirectoryReference -Path ([string]$Origin.registry_source_root.path) -VolumeSerialHex $Origin.registry_source_root.volume_serial_hex -FileIdHex $Origin.registry_source_root.file_id_hex
    $archiveByKey = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($reference in $Origin.registry_archives) {
        $fields = @('source', 'name', 'version', 'checksum', 'path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $reference $fields)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: registry archive pin schema is invalid' }
        $key = [string]$reference.name + "`0" + [string]$reference.version
        if (-not $archiveByKey.TryAdd($key, $reference)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: duplicate registry archive pin' }
    }
    $packageByKey = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($package in $Plan.registry_packages) {
        $key = [string]$package.name + "`0" + [string]$package.version
        if (-not $packageByKey.TryAdd($key, $package)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: duplicate lock-derived registry name/version key' }
    }
    $proofRows = [System.Collections.Generic.List[object]]::new()
    $manifestCandidates = [System.Collections.Generic.List[object]]::new()
    $totalCompressed = [Int64]0
    $totalExpanded = [Int64]0
    $totalEntries = [Int64]0
    $manifestBytesTotal = [Int64]0
    $archiveIndex = 0
    foreach ($archive in $Origin.registry_archives) {
        Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.archive' -Progress ("archive={0}/{1};package={2}-{3}" -f $archiveIndex, $Origin.registry_archives.Count, $archive.name, $archive.version) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
        $key = [string]$archive.name + "`0" + [string]$archive.version
        $package = $null
        if (-not $packageByKey.TryGetValue($key, [ref]$package)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: caller-pinned archive is not one exact lock-catalog package' }
        if (-not $archiveByKey.ContainsKey($key) -or $null -eq $archive -or
            [string]$archive.source -cne 'registry+https://github.com/rust-lang/crates.io-index' -or
            [string]$archive.checksum -cne [string]$package.checksum -or [string]$archive.sha256 -cne [string]$package.checksum -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$archive.path, [string]$package.archive_path)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: registry archive reference does not exactly match its lock-derived package/checksum/path'
        }
        $archiveFileReference = New-D32BoundedDiagnosticRegistryArchiveFileReferenceProjection -Reference $archive
        $snapshot = Assert-D32BoundedDiagnosticFileReference -Reference $archiveFileReference -MustBeWithin $Plan.registry_archive_root `
            -MustNotBeWithin $Repo -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -MetadataOnly `
            -ReferenceField "dependency_origin.registry_archives[$archiveIndex].file_reference" `
            -Caller 'New-D32BoundedDiagnosticRegistrySourceContentProof'
        $archiveIndex++
        if ([Int64]$snapshot.Bytes -gt [Int64]$script:D32BoundedCompilerDiagnosticRegistryArchiveLimitBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: compressed registry archive exceeds its fixed 256 MiB buffered-input bound' }
        $totalCompressed += [Int64]$snapshot.Bytes
        if ($totalCompressed -gt 17179869184L) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: aggregate registry archive bytes exceed 16 GiB' }
        $archiveContent = Get-D32ProfileFileContentSnapshot -Path ([string]$archive.path) -MaximumBytes $script:D32BoundedCompilerDiagnosticRegistryArchiveLimitBytes `
            -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
        if ($archiveContent.Bytes -ne $snapshot.Bytes -or $archiveContent.Sha256 -cne [string]$package.checksum -or
            $archiveContent.VolumeSerialHex -cne $snapshot.VolumeSerialHex -or $archiveContent.FileIdHex -cne $snapshot.FileIdHex) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: opened registry archive content/identity differs from the lock-checksummed caller pin'
        }
        $inventory = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes ([byte[]]$archiveContent.Content) `
            -ExpectedPackageRoot ([string]$package.name + '-' + [string]$package.version) `
            -ExpectedArchiveSha256 ([string]$package.checksum) -OpenedHandleSha256 ([string]$archiveContent.Sha256) `
            -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
        $manifestBytesTotal += [Int64][Text.Encoding]::UTF8.GetByteCount([string]$inventory.manifest_text)
        if ($manifestBytesTotal -gt 33554432L) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: verified registry Cargo.toml contents exceed their combined 32 MiB working-set bound' }
        $sourceProof = Assert-D32BoundedDiagnosticArchiveMatchesExtractedSource -SourceRoot ([string]$package.extracted_source_path) `
            -ArchiveInventory $inventory -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -MaximumEntries 10000
        $totalExpanded += [Int64]$inventory.expanded_bytes
        $totalEntries += [Int64]$inventory.entries.Count
        if ($totalExpanded -gt 34359738368L -or $totalEntries -gt 1000000L) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: aggregate registry expanded-byte or member-count bound exceeded'
        }
        $proofRows.Add((New-D32BoundedDiagnosticRegistrySourceProofPackage -Package $package -ArchiveReference ([PSCustomObject]@{
            path = [string]$archive.path; bytes = [Int64]$snapshot.Bytes; sha256 = [string]$package.checksum
            volume_serial_hex = [string]$snapshot.VolumeSerialHex; file_id_hex = [string]$snapshot.FileIdHex
        }) -Inventory $inventory -SourceProof $sourceProof))
        $manifestCandidates.Add([PSCustomObject]@{ source_kind = 'registry'; source = [string]$package.source; source_path = 'Cargo.toml'; content = [string]$inventory.manifest_text; content_sha256 = [string]$inventory.manifest_sha256; package_id = [string]$package.package_id })
    }
    $archiveRootAfter = Assert-D32BoundedDiagnosticDirectoryReference -Path ([string]$Origin.registry_archive_root.path) -VolumeSerialHex $Origin.registry_archive_root.volume_serial_hex -FileIdHex $Origin.registry_archive_root.file_id_hex
    $sourceRootAfter = Assert-D32BoundedDiagnosticDirectoryReference -Path ([string]$Origin.registry_source_root.path) -VolumeSerialHex $Origin.registry_source_root.volume_serial_hex -FileIdHex $Origin.registry_source_root.file_id_hex
    if ($archiveRootBefore.VolumeSerialHex -cne $archiveRootAfter.VolumeSerialHex -or $archiveRootBefore.FileIdHex -cne $archiveRootAfter.FileIdHex -or
        $sourceRootBefore.VolumeSerialHex -cne $sourceRootAfter.VolumeSerialHex -or $sourceRootBefore.FileIdHex -cne $sourceRootAfter.FileIdHex) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: registry cache root identity changed during source verification'
    }
    $proof = New-D32BoundedDiagnosticRegistrySourceContentProofDocument -Packages @($proofRows.ToArray()) `
        -LockSha256 ([string]$Plan.lock_sha256) -RegistryTupleSha256 ([string]$Plan.registry_tuple_sha256) `
        -LockedRegistryCatalogCount ([Int64]$Plan.registry_package_count) -CompressedBytes $totalCompressed `
        -ExpandedBytes $totalExpanded -MemberCount $totalEntries -ElapsedMilliseconds ([Int64]$ProofTimer.ElapsedMilliseconds)
    return [PSCustomObject]@{ proof = $proof; manifest_candidates = @($manifestCandidates.ToArray()); manifest_candidate_bytes = [Int64]$manifestBytesTotal }
}

function Get-D32BoundedDiagnosticGitCatalog {
    param([Parameter(Mandatory = $true)][string]$Path, [long]$MaximumEntries = 64,
        [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds)
    $before = Get-D32ProfileDirectoryIdentity -Path $Path
    if (($before.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$before.Path), [IO.Path]::GetFullPath($Path))) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git catalog root is redirected or noncanonical'
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($itemPath in [IO.Directory]::EnumerateFileSystemEntries($Path)) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.catalog' -Progress ("path={0};entries={1}" -f $Path, $rows.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED' -NoProgress }
        if ($rows.Count -ge $MaximumEntries) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git catalog exceeds its fixed 64-entry bound' }
        $full = [IO.Path]::GetFullPath($itemPath)
        if (-not $full.StartsWith([IO.Path]::GetFullPath($Path).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-D32ProfileNoReparsePath -Path $full)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git catalog entry escaped or traverses a reparse point'
        }
        $attributes = [IO.File]::GetAttributes($full)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or ($attributes -band [IO.FileAttributes]::Device) -ne 0) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git catalog contains a reparse or non-regular device entry'
        }
        $relative = [IO.Path]::GetRelativePath($Path, $full).Replace('\', '/')
        if (-not (Test-D32BoundedCompilerDiagnosticTarPath $relative) -or -not $names.Add($relative)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git catalog path is unsafe or case-colliding'
        }
        $isDirectory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
        $item = Get-Item -LiteralPath $full -Force
        $identity = if ($isDirectory) { Get-D32ProfileDirectoryIdentity -Path $full } else { $null }
        $rows.Add([PSCustomObject]@{
            relative_path = $relative
            full_path = $full
            kind = if ($isDirectory) { 'directory' } else { 'file' }
            bytes = if ($isDirectory) { [Int64]0 } else { [Int64]$item.Length }
            attributes = [int]$attributes
            volume_serial_hex = if ($null -eq $identity) { $null } else { [string]$identity.VolumeSerialHex }
            file_id_hex = if ($null -eq $identity) { $null } else { [string]$identity.FileIdHex }
        })
    }
    $array = [object[]]@($rows.ToArray())
    [Array]::Sort($array, [System.Comparison[object]]{ param($left, $right) [StringComparer]::Ordinal.Compare([string]$left.relative_path, [string]$right.relative_path) })
    $canonicalRows = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $array) {
        $canonicalRows.Add(([string]$row.kind + "`t" + [string]$row.relative_path + "`t" + [Int64]$row.bytes + "`t" +
            [int]$row.attributes + "`t" + [string]$row.volume_serial_hex + "`t" + [string]$row.file_id_hex))
    }
    $digest = Get-D32BoundedDiagnosticSha256FromLines -Lines ([string[]]$canonicalRows.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'git.catalog_digest'
    $after = Get-D32ProfileDirectoryIdentity -Path $Path
    if ($before.VolumeSerialHex -cne $after.VolumeSerialHex -or $before.FileIdHex -cne $after.FileIdHex) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git catalog root identity changed during bounded inventory'
    }
    return [PSCustomObject]@{
        path = $Path
        volume_serial_hex = [string]$after.VolumeSerialHex
        file_id_hex = [string]$after.FileIdHex
        count = [Int64]$array.Count
        inventory_sha256 = $digest
        entries = $array
    }
}

function Get-D32BoundedDiagnosticGitRepositorySlug {
    param([Parameter(Mandatory = $true)][string]$Url)
    $parsed = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$parsed) -or $parsed.Scheme -cne 'https' -or
        -not [String]::IsNullOrEmpty($parsed.UserInfo) -or $parsed.AbsolutePath.Contains('%')) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git cache URL cannot be mapped without aliases or credentials'
    }
    $leaf = [IO.Path]::GetFileName($parsed.AbsolutePath.TrimEnd('/'))
    if ($leaf.EndsWith('.git', [StringComparison]::OrdinalIgnoreCase)) { $leaf = $leaf.Substring(0, $leaf.Length - 4) }
    $slug = $leaf.ToLowerInvariant()
    if ($slug -cnotmatch '^[a-z0-9][a-z0-9._-]{0,79}$') { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git cache slug is unsupported' }
    return $slug
}

function Get-D32BoundedDiagnosticGitBlobOidFromFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][long]$ExpectedBytes,
        [Parameter(Mandatory = $true)][Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds)
    if ($ExpectedBytes -lt 0 -or $ExpectedBytes -gt 67108864L) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout file exceeds the 64 MiB per-object bound' }
    if (-not (Test-D32ProfileNoReparsePath -Path $Path)) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout file is missing or traverses a reparse point' }
    Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.checkout_file' -Progress $Path -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED'
    try { $snapshot = Get-D32ProfileGitBlobSnapshot -Path $Path -ExpectedBytes $ExpectedBytes -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks) }
    catch { throw ('D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: opened checkout blob verification failed; path={0}; reason={1}' -f (Format-D32BoundedCompilerDiagnosticPathForError $Path), [string]$_.Exception.Message) }
    return [PSCustomObject]@{ oid = [string]$snapshot.GitBlobOid; bytes = [Int64]$snapshot.Bytes; sha256 = [string]$snapshot.Sha256; volume_serial_hex = [string]$snapshot.VolumeSerialHex; file_id_hex = [string]$snapshot.FileIdHex }
}

function Get-D32BoundedDiagnosticGitCheckoutContentProof {
    param(
        [Parameter(Mandatory = $true)][object]$Reader,
        [Parameter(Mandatory = $true)][string]$TreeOid,
        [Parameter(Mandatory = $true)][string]$CheckoutPath,
        [Parameter(Mandatory = $true)][string]$ExpectedCheckoutVolumeSerialHex,
        [Parameter(Mandatory = $true)][string]$ExpectedCheckoutFileIdHex,
        [Parameter(Mandatory = $true)][string]$DatabasePath,
        [Parameter(Mandatory = $true)][Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds,
        [long]$ExternalRetainedBytes = 0L,
        [int]$MaximumManifestCandidates = 4096,
        [long]$MaximumManifestBytes = 67108864L
    )
    $expected = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push([PSCustomObject]@{ oid = $TreeOid; path = ''; depth = 0; ancestors = [string[]]@() })
    $treeObjectCount = [Int64]0
    $managedInventoryEstimate = [Int64]0
    if ($ExternalRetainedBytes -lt 0 -or $ExternalRetainedBytes -gt [Int64]$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes -or
        $MaximumManifestCandidates -lt 0 -or $MaximumManifestCandidates -gt 4096 -or
        $MaximumManifestBytes -lt 0 -or $MaximumManifestBytes -gt 67108864L) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: retained prior manifest material exceeds the fixed managed-memory ceiling'
    }
    $managedInventoryLimit = [Int64]$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes - [Int64]$Reader.PeakWorkingBytes - $ExternalRetainedBytes
    if ($managedInventoryLimit -le 0) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: pack-reader peak leaves no managed-memory budget for checkout inventory proof' }
    while ($stack.Count -gt 0) {
        Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.tree_walk' -Progress ("trees={0};pending={1}" -f $treeObjectCount, $stack.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED'
        $frame = $stack.Pop()
        if ([int]$frame.depth -gt 64 -or [string]$frame.oid -cnotmatch '^[0-9a-f]{40}$' -or
            @($frame.ancestors | Where-Object { $_ -ceq [string]$frame.oid }).Count -gt 0) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git tree depth, object ID, or ancestry is invalid'
        }
        $tree = $Reader.Resolve([string]$frame.oid)
        try {
            $managedInventoryLimit = [Int64]$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes - [Int64]$Reader.PeakWorkingBytes
            if ($managedInventoryEstimate -gt $managedInventoryLimit) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: pack-reader peak leaves insufficient budget for the accumulated tree inventory' }
            if ([string]$tree.Type -cne 'tree') { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: commit/tree reference resolved to a non-tree object' }
            $treeParseEstimate = 12582912L + (3L * [Int64]$tree.Data.Length)
            $managedInventoryEstimate += $treeParseEstimate
            if ($managedInventoryEstimate -gt $managedInventoryLimit) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git tree parser exceeds the remaining 512 MiB managed-memory budget' }
            $entries = [D32BoundedGitPackReaderV1]::ParseTree($tree.Data, [Int64]($DeadlineMilliseconds - (Get-D32BoundedDiagnosticSourceProofCurrentElapsedMilliseconds -ProofTimer $ProofTimer)))
            if ($entries.Count -eq 0) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: empty Git tree is unsupported for Cargo checkout closure' }
            $treeObjectCount++
            foreach ($entry in $entries) {
                if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.tree_inventory' -Progress ("entries={0}" -f $expected.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED' -NoProgress }
                $relative = if ([String]::IsNullOrEmpty([string]$frame.path)) { [string]$entry.Name } else { [string]$frame.path + '/' + [string]$entry.Name }
                if (-not (Test-D32BoundedCompilerDiagnosticTarPath $relative) -or $relative.Length -gt 4096) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git tree path is unsafe or exceeds 4096 characters'
                }
                if ([string]$entry.Kind -cnotin @('tree', 'blob')) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: symlink and gitlink tree entries are unsupported' }
                if (-not $expected.TryAdd($relative, [PSCustomObject]@{ path = $relative; kind = [string]$entry.Kind; oid = [string]$entry.Oid; mode = [string]$entry.Mode })) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git tree path is duplicated or case-colliding on Windows'
                }
                $managedInventoryEstimate += 512L + (4L * $relative.Length)
                if ($expected.Count -gt 100000 -or $managedInventoryEstimate -gt $managedInventoryLimit) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: expected Git tree inventory exceeds its fixed entry or managed-memory budget'
                }
                if ([string]$entry.Kind -ceq 'tree') {
                    $ancestors = [string[]](@($frame.ancestors) + [string]$frame.oid)
                    $stack.Push([PSCustomObject]@{ oid = [string]$entry.Oid; path = $relative; depth = [int]$frame.depth + 1; ancestors = $ancestors })
                }
            }
            $managedInventoryEstimate -= $treeParseEstimate
            $entries = $null
        }
        finally { $Reader.Release($tree) }
    }
    if ($expected.ContainsKey('.git')) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: locked source tree collides with Cargo checkout Git metadata' }

    $checkoutBefore = Get-D32ProfileDirectoryIdentity -Path $CheckoutPath
    if (($checkoutBefore.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $checkoutBefore.VolumeSerialHex -cne $ExpectedCheckoutVolumeSerialHex -or $checkoutBefore.FileIdHex -cne $ExpectedCheckoutFileIdHex) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout root identity differs from its freshly enumerated parent entry or is a reparse directory'
    }
    $actual = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $directoryIdentities = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $inventoryRows = [System.Collections.Generic.List[string]]::new()
    $sourceMetadata = [System.Collections.Generic.List[string]]::new()
    $directoryIdentities.Add('', $checkoutBefore)
    $walk = [System.Collections.Generic.Stack[object]]::new()
    $walk.Push([PSCustomObject]@{ path = $CheckoutPath; relative = '' })
    $fileCount = [Int64]0
    $directoryCount = [Int64]0
    $sourceBytes = [Int64]0
    $metadataCount = [Int64]0
    $manifestTextRows = [System.Collections.Generic.List[object]]::new()
    $manifestBytesTotal = [Int64]0
    while ($walk.Count -gt 0) {
        Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.checkout_walk' -Progress ("files={0};directories={1};pending={2}" -f $fileCount, $directoryCount, $walk.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED'
        $directory = $walk.Pop()
        foreach ($itemPath in [IO.Directory]::EnumerateFileSystemEntries([string]$directory.path)) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.checkout_entries' -Progress ("files={0};directories={1}" -f $fileCount, $directoryCount) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED' -NoProgress }
            $full = [IO.Path]::GetFullPath($itemPath)
            if (-not $full.StartsWith([IO.Path]::GetFullPath($CheckoutPath).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
                -not (Test-D32ProfileNoReparsePath -Path $full)) {
                throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout entry escaped or traverses a reparse point'
            }
            $attributes = [IO.File]::GetAttributes($full)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout contains a reparse entry' }
            $relative = [IO.Path]::GetRelativePath($CheckoutPath, $full).Replace('\', '/')
            if (-not (Test-D32BoundedCompilerDiagnosticTarPath $relative) -or $relative.Length -gt 4096) {
                throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout path is unsafe or exceeds 4096 characters'
            }
            $isDirectory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
            $isAtRoot = -not $relative.Contains('/')
            if ($relative -ceq '.git' -and -not $expected.ContainsKey($relative)) {
                if ($isDirectory) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout .git indirection is a directory, not a bounded pointer file' }
                $pointerBefore = Get-D32ProfileFileContentSnapshot -Path $full -MaximumBytes 4096 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
                if ([Int64]$pointerBefore.Bytes -le 0 -or [Int64]$pointerBefore.Bytes -gt 4096) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout .git pointer is empty or exceeds 4096 bytes' }
                $pointerBytes = [byte[]]$pointerBefore.Content
                $pointerAfter = Get-D32ProfileFileContentSnapshot -Path $full -MaximumBytes 4096 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
                if ($pointerBytes.Length -gt 4096 -or $pointerAfter.Bytes -ne $pointerBefore.Bytes -or $pointerAfter.Sha256 -cne $pointerBefore.Sha256 -or
                    $pointerAfter.VolumeSerialHex -cne $pointerBefore.VolumeSerialHex -or $pointerAfter.FileIdHex -cne $pointerBefore.FileIdHex) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout .git pointer changed or exceeds its bounded read'
                }
                $pointerTarget = Get-D32BoundedDiagnosticGitPointerTarget -PointerBytes $pointerBytes -CheckoutPath $CheckoutPath
                if (-not (Test-D32BoundedDiagnosticExactGitPointerTarget -Target $pointerTarget -ExpectedTarget $DatabasePath) -or
                    -not (Test-D32ProfileNoReparsePath -Path $pointerTarget)) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout .git pointer resolves outside its exact locked database root'
                }
                $null = Get-D32ProfileDirectoryIdentity -Path $pointerTarget
                $sourceMetadata.Add(('gitdir' + "`t" + $relative + "`t" + [string]$pointerAfter.Sha256 + "`t" + [string]$pointerAfter.VolumeSerialHex + "`t" + [string]$pointerAfter.FileIdHex))
                $metadataCount++
                continue
            }
            $expectedGitArchiveMember = $expected.ContainsKey($relative)
            if ($relative -ceq '.cargo-ok' -and $isAtRoot -and
                (Test-D32BoundedDiagnosticGeneratedRegistryAuxiliaryFile -RelativePath $relative -AtRoot $true -ArchiveMember $expectedGitArchiveMember)) {
                if ($isDirectory) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Cargo .cargo-ok metadata is not a regular file' }
                $marker = Get-D32ProfileFileContentSnapshot -Path $full -MaximumBytes 0 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
                Assert-D32BoundedDiagnosticGitCargoOkMarkerEmpty -Bytes ([Int64]$marker.Bytes)
                $sourceMetadata.Add(('cargo-ok' + "`t" + $relative + "`t" + [string]$marker.Sha256 + "`t" + [string]$marker.VolumeSerialHex + "`t" + [string]$marker.FileIdHex))
                $metadataCount++
                continue
            }
            $expectedEntry = $null
            $foundExpected = $expected.TryGetValue($relative, [ref]$expectedEntry)
            if (-not $foundExpected -or [string]$expectedEntry.kind -cne $(if ($isDirectory) { 'tree' } else { 'blob' })) {
                throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout contains an untracked, missing-type, or unexpected tree entry'
            }
            if (-not [StringComparer]::Ordinal.Equals([string]$expectedEntry.path, [string]$relative)) {
                throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout path case differs from its locked Git tree'
            }
            if (-not $actual.Add($relative)) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout contains a duplicate/case-colliding path' }
            if ($isDirectory) {
                $directoryIdentity = Get-D32ProfileDirectoryIdentity -Path $full
                $directoryIdentities.Add($relative, $directoryIdentity)
                $directoryCount++
                $row = 'directory' + "`t" + $relative + "`t" + [string]$directoryIdentity.VolumeSerialHex + "`t" + [string]$directoryIdentity.FileIdHex
                $inventoryRows.Add($row)
                $managedInventoryEstimate += 1024L + (6L * $row.Length)
                $walk.Push([PSCustomObject]@{ path = $full; relative = $relative })
            }
            else {
                $item = Get-Item -LiteralPath $full -Force
                if ([Int64]$item.Length -gt 67108864L) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout file exceeds 64 MiB' }
                $blobProof = Get-D32BoundedDiagnosticGitBlobOidFromFile -Path $full -ExpectedBytes ([Int64]$item.Length) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
                if ([string]$blobProof.oid -cne [string]$expectedEntry.oid) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout file Git blob SHA-1 differs from its locked tree object ID' }
                if ([IO.Path]::GetFileName($relative) -ceq 'Cargo.toml') {
                    if ($manifestTextRows.Count -ge $MaximumManifestCandidates) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: checkout Cargo.toml entries exceed the remaining exact 4096-entry candidate catalog capacity' }
                    if ([Int64]$blobProof.bytes -gt 1048576L) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git Cargo.toml exceeds the 1 MiB dependency-graph parser bound' }
                    if ($manifestBytesTotal -gt ($MaximumManifestBytes - [Int64]$blobProof.bytes)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: Git Cargo.toml candidates exceed the remaining exact 64 MiB manifest-content catalog budget' }
                    $manifestBytesTotal += [Int64]$blobProof.bytes
                    if ($manifestBytesTotal -gt 33554432L) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: verified Git manifest buffer total exceeds its 32 MiB bound' }
                    $manifestManagedEstimate = 4096L + (3L * [Int64]$blobProof.bytes)
                    if ($managedInventoryEstimate -gt ($managedInventoryLimit - $manifestManagedEstimate)) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: manifest candidates plus checkout inventory exceed the remaining 512 MiB managed-memory budget before read' }
                    $manifestSnapshot = Get-D32ProfileFileContentSnapshot -Path $full -MaximumBytes 1048576L -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
                    if ($manifestSnapshot.Bytes -ne [Int64]$blobProof.bytes -or $manifestSnapshot.Sha256 -cne [string]$blobProof.sha256 -or
                        $manifestSnapshot.VolumeSerialHex -cne [string]$blobProof.volume_serial_hex -or
                        $manifestSnapshot.FileIdHex -cne [string]$blobProof.file_id_hex) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git Cargo.toml changed while its bounded manifest bytes were captured' }
                    try { $manifestText = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$manifestSnapshot.Content) }
                    catch { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git Cargo.toml is not strict UTF-8' }
                    $managedInventoryEstimate += $manifestManagedEstimate
                    if ($managedInventoryEstimate -gt $managedInventoryLimit) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: manifest candidates plus checkout inventory exceed the remaining 512 MiB managed-memory budget' }
                    $manifestTextRows.Add([PSCustomObject]@{ relative_path = $relative; text = $manifestText; content_sha256 = [string]$blobProof.sha256; bytes = [Int64]$blobProof.bytes })
                }
                $fileCount++
                $sourceBytes += [Int64]$blobProof.bytes
                if ($fileCount -gt 100000 -or $sourceBytes -gt 34359738368L) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout file count or source-byte total exceeds its fixed bound' }
                $row = 'file' + "`t" + $relative + "`t" + [Int64]$blobProof.bytes + "`t" + [string]$expectedEntry.mode + "`t" +
                    [string]$blobProof.oid + "`t" + [string]$blobProof.sha256 + "`t" + [string]$blobProof.volume_serial_hex + "`t" + [string]$blobProof.file_id_hex
                $inventoryRows.Add($row)
                $managedInventoryEstimate += 1024L + (6L * $row.Length)
            }
            if ($managedInventoryEstimate -gt $managedInventoryLimit) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: actual checkout inventory exceeds the remaining 512 MiB managed-memory budget' }
        }
    }
    if ($actual.Count -ne $expected.Count) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: current checkout file/directory inventory is incomplete for the locked commit tree' }
    $expectedIndex = 0
    foreach ($relative in $expected.Keys) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.checkout_expected_coverage' -Progress ("paths={0}/{1}" -f $expectedIndex, $expected.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED' -NoProgress }
        if (-not $actual.Contains($relative)) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: a locked Git tree path is absent from the current Cargo checkout' }
        $expectedIndex++
    }
    $directoryIdentityIndex = 0
    foreach ($relative in $directoryIdentities.Keys) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.checkout_directory_identity' -Progress ("directories={0}/{1}" -f $directoryIdentityIndex, $directoryIdentities.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED' -NoProgress }
        $path = if ([String]::IsNullOrEmpty([string]$relative)) { $CheckoutPath } else { Join-Path $CheckoutPath ([string]$relative.Replace('/', '\')) }
        $after = Get-D32ProfileDirectoryIdentity -Path $path
        $before = $directoryIdentities[$relative]
        if ($before.VolumeSerialHex -cne $after.VolumeSerialHex -or $before.FileIdHex -cne $after.FileIdHex) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout directory identity changed during its content proof'
        }
        $directoryIdentityIndex++
    }
    $checkoutAfter = Get-D32ProfileDirectoryIdentity -Path $CheckoutPath
    if ($checkoutBefore.VolumeSerialHex -cne $checkoutAfter.VolumeSerialHex -or $checkoutBefore.FileIdHex -cne $checkoutAfter.FileIdHex) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout root identity changed during its content proof'
    }
    $metadataIndex = 0
    foreach ($row in $sourceMetadata) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.checkout_metadata_inventory' -Progress ("rows={0}/{1}" -f $metadataIndex, $sourceMetadata.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED' -NoProgress }
        $inventoryRows.Add($row); $managedInventoryEstimate += 1024L + (6L * $row.Length); $metadataIndex++
    }
    if ($managedInventoryEstimate -gt $managedInventoryLimit) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout metadata inventory exceeds the remaining 512 MiB managed-memory budget' }
    $canonicalRows = [string[]]@($inventoryRows.ToArray())
    Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.checkout_inventory_sort' -Progress ("rows={0}" -f $canonicalRows.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED'
    [Array]::Sort($canonicalRows, [StringComparer]::Ordinal)
    Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.checkout_inventory_sort_complete' -Progress ("rows={0}" -f $canonicalRows.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED'
    $inventorySha = Get-D32BoundedDiagnosticSha256FromLines -Lines $canonicalRows -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'git.checkout_inventory_digest'
    return [PSCustomObject]@{
        checkout_path = $CheckoutPath
        checkout_volume_serial_hex = [string]$checkoutAfter.VolumeSerialHex
        checkout_file_id_hex = [string]$checkoutAfter.FileIdHex
        tree_oid = $TreeOid
        tree_object_count = $treeObjectCount
        file_count = $fileCount
        directory_count = $directoryCount
        metadata_count = $metadataCount
        source_bytes = $sourceBytes
        inventory_managed_estimate_bytes = $managedInventoryEstimate
        inventory_sha256 = $inventorySha
        manifest_retained_managed_estimate_bytes = [Int64]($manifestBytesTotal * 3L) + ([Int64]$manifestTextRows.Count * 4096L)
        manifest_texts = @($manifestTextRows.ToArray())
        manifest_bytes = $manifestBytesTotal
    }
}

function New-D32BoundedDiagnosticGitSourceContentProof {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object]$Origin,
        [Parameter(Mandatory = $true)][string]$Repo,
        [Parameter(Mandatory = $true)][Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds,
        [int]$MaximumManifestCandidates = 4096,
        [long]$ExternalRetainedManifestBytes = 0L,
        [long]$MaximumManifestBytes = 67108864L
    )
    if ([string]$Plan.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_LOCK_SOURCE_PLAN_V2' -or [int]$Plan.schema_version -ne 2 -or
        [string]$Plan.gate_authority -cne 'NONE' -or [string]$Plan.verification_status -cne 'NOT_RUN' -or
        $Plan.git_sources -isnot [Array] -or $Plan.git_sources.Count -le 0 -or $Plan.git_sources.Count -gt 16 -or
        $Origin.git_content_refs -isnot [Array] -or $Origin.git_content_refs.Count -le 0 -or $Origin.git_content_refs.Count -gt $Plan.git_sources.Count) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: lock-derived Git source plan or caller-pinned reachable-source subset is malformed or exceeds its fixed tuple bound'
    }
    if ($MaximumManifestCandidates -lt 0 -or $MaximumManifestCandidates -gt 4096 -or
        $ExternalRetainedManifestBytes -lt 0 -or $ExternalRetainedManifestBytes -gt [Int64]$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes -or
        $MaximumManifestBytes -lt 0 -or $MaximumManifestBytes -gt 67108864L) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: remaining verified manifest-candidate capacity is invalid'
    }
    $gitReferenceBySource = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $sourcePlanByIdentity = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($sourcePlan in $Plan.git_sources) {
        $sourceKey = [string]$sourcePlan.source + "`0" + [string]$sourcePlan.commit
        if (-not $sourcePlanByIdentity.TryAdd($sourceKey, $sourcePlan)) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: duplicate lock-derived Git source/commit tuple' }
    }
    $verifiedSourcePlans = [System.Collections.Generic.List[object]]::new()
    foreach ($reference in $Origin.git_content_refs) {
        Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.reference_map' -Progress ("references={0}" -f $verifiedSourcePlans.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED'
        if (-not (Test-D32BoundedCompilerDiagnosticGitContentReferenceShape $reference) -or
            -not $gitReferenceBySource.TryAdd([string]$reference.source, $reference)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: finite caller-pinned Git pack/index/checkout metadata references are malformed or duplicated'
        }
        $sourcePlan = $null
        if (-not $sourcePlanByIdentity.TryGetValue(([string]$reference.source + "`0" + [string]$reference.commit), [ref]$sourcePlan)) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: pinned Git source is absent from or ambiguous in the full current lock catalog' }
        $verifiedSourcePlans.Add($sourcePlan)
    }
    $databaseRoot = Join-Path ([string]$Origin.path) 'git/db'
    $checkoutRoot = Join-Path ([string]$Origin.path) 'git/checkouts'
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Origin.git_database_root.path, $databaseRoot) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Origin.git_checkout_root.path, $checkoutRoot)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git cache roots are not the exact lock-derived optional CargoHome paths'
    }
    $dbRootBefore = Assert-D32BoundedDiagnosticDirectoryReference -Path $databaseRoot -VolumeSerialHex $Origin.git_database_root.volume_serial_hex -FileIdHex $Origin.git_database_root.file_id_hex
    $checkoutRootBefore = Assert-D32BoundedDiagnosticDirectoryReference -Path $checkoutRoot -VolumeSerialHex $Origin.git_checkout_root.volume_serial_hex -FileIdHex $Origin.git_checkout_root.file_id_hex
    $dbRootCatalog = Get-D32BoundedDiagnosticGitCatalog -Path $databaseRoot -MaximumEntries 64 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    $checkoutRootCatalog = Get-D32BoundedDiagnosticGitCatalog -Path $checkoutRoot -MaximumEntries 64 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    $tupleRows = [System.Collections.Generic.List[object]]::new()
    $manifestCandidates = [System.Collections.Generic.List[object]]::new()
    $usedCacheNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $totalExpanded = [Int64]0
    $totalSourceBytes = [Int64]0
    $retainedManifestCandidateBytes = [Int64]$ExternalRetainedManifestBytes
    $retainedManifestContentBytes = [Int64]0
    foreach ($source in $verifiedSourcePlans) {
        Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.source' -Progress ("sources={0}/{1}" -f $tupleRows.Count, $verifiedSourcePlans.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED'
        $sourceFields = @('source', 'url', 'commit', 'database_root', 'checkout_root')
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $source -Expected $sourceFields) -or
            [string]$source.commit -cnotmatch '^[0-9a-f]{40}$' -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$source.database_root, $databaseRoot) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$source.checkout_root, $checkoutRoot)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: lock-derived Git tuple has an invalid exact schema or cache root'
        }
        if (-not $gitReferenceBySource.ContainsKey([string]$source.source)) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: a lock-derived Git source lacks its independently pinned storage references' }
        $gitReference = $gitReferenceBySource[[string]$source.source]
        if ([string]$gitReference.commit -cne [string]$source.commit) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: pinned Git storage commit differs from the exact current Cargo.lock commit' }
        $slug = Get-D32BoundedDiagnosticGitRepositorySlug -Url ([string]$source.url)
        $dbMatches = @($dbRootCatalog.entries | Where-Object { $_.kind -ceq 'directory' -and [string]$_.relative_path -match ('^' + [regex]::Escape($slug) + '-[0-9a-f]{16}$') })
        if ($dbMatches.Count -ne 1 -or -not $usedCacheNames.Add([string]$dbMatches[0].relative_path)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: lock URL does not map uniquely to one Cargo Git database directory'
        }
        $cacheName = [string]$dbMatches[0].relative_path
        $checkoutMatches = @($checkoutRootCatalog.entries | Where-Object { $_.kind -ceq 'directory' -and [string]$_.relative_path -ceq $cacheName })
        if ($checkoutMatches.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: matching Cargo Git checkout cache directory is absent or ambiguous' }
        $checkoutCacheEntry = $checkoutMatches[0]
        $databasePath = [string]$dbMatches[0].full_path
        $repoCheckoutRoot = [string]$checkoutCacheEntry.full_path
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals($databasePath, [string]$gitReference.database_path) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals($repoCheckoutRoot, [string]$gitReference.checkout_cache_path)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: selected database or checkout-cache directory differs from the exact caller-pinned source path'
        }
        $databaseIdentity = Get-D32ProfileDirectoryIdentity -Path $databasePath
        if ($databaseIdentity.VolumeSerialHex -cne [string]$dbMatches[0].volume_serial_hex -or $databaseIdentity.FileIdHex -cne [string]$dbMatches[0].file_id_hex -or
            $databaseIdentity.VolumeSerialHex -cne [string]$gitReference.database_volume_serial_hex -or $databaseIdentity.FileIdHex -cne [string]$gitReference.database_file_id_hex) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git database directory identity drifted after its parent catalog was enumerated'
        }
        $checkoutCacheIdentity = Get-D32ProfileDirectoryIdentity -Path $repoCheckoutRoot
        if ($checkoutCacheIdentity.VolumeSerialHex -cne [string]$checkoutCacheEntry.volume_serial_hex -or $checkoutCacheIdentity.FileIdHex -cne [string]$checkoutCacheEntry.file_id_hex -or
            $checkoutCacheIdentity.VolumeSerialHex -cne [string]$gitReference.checkout_cache_volume_serial_hex -or $checkoutCacheIdentity.FileIdHex -cne [string]$gitReference.checkout_cache_file_id_hex) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Cargo checkout cache directory identity drifted after its parent catalog was enumerated'
        }
        $databaseCatalog = Get-D32BoundedDiagnosticGitCatalog -Path $databasePath -MaximumEntries 64 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
        $repoCheckoutCatalog = Get-D32BoundedDiagnosticGitCatalog -Path $repoCheckoutRoot -MaximumEntries 8 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
        $shortCommit = [string]$source.commit.Substring(0, 7)
        $checkoutMatches = @($repoCheckoutCatalog.entries | Where-Object { $_.kind -ceq 'directory' -and [string]$_.relative_path -ceq $shortCommit })
        if ($checkoutMatches.Count -ne 1 -or -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$checkoutMatches[0].relative_path, $shortCommit)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Cargo short-commit checkout directory does not uniquely match the locked commit prefix'
        }
        $checkoutPath = [string]$checkoutMatches[0].full_path
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals($checkoutPath, [string]$gitReference.checkout_path) -or
            [string]$checkoutMatches[0].volume_serial_hex -cne [string]$gitReference.checkout_volume_serial_hex -or
            [string]$checkoutMatches[0].file_id_hex -cne [string]$gitReference.checkout_file_id_hex) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: selected short-commit checkout differs from its exact caller-pinned path/identity'
        }
        $objectsPath = Join-Path $databasePath 'objects'
        $objectsCatalog = Get-D32BoundedDiagnosticGitCatalog -Path $objectsPath -MaximumEntries 64 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
        if ($objectsCatalog.count -ne 2 -or
            @($objectsCatalog.entries | Where-Object { $_.kind -ceq 'directory' -and $_.relative_path -ceq 'info' }).Count -ne 1 -or
            @($objectsCatalog.entries | Where-Object { $_.kind -ceq 'directory' -and $_.relative_path -ceq 'pack' }).Count -ne 1) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: current Git object layout is not the pinned pack-only v2 format'
        }
        $infoCatalog = Get-D32BoundedDiagnosticGitCatalog -Path (Join-Path $objectsPath 'info') -MaximumEntries 64 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
        if ($infoCatalog.count -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git objects/info contains unsupported auxiliary or external-alternate entries' }
        $packPath = Join-Path $objectsPath 'pack'
        $packCatalog = Get-D32BoundedDiagnosticGitCatalog -Path $packPath -MaximumEntries 64 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
        if ($packCatalog.count -ne 2) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git cache must contain exactly one pack/index pair and no unsupported pack metadata' }
        $packFiles = @($packCatalog.entries | Where-Object { $_.kind -ceq 'file' })
        $packEntries = @($packFiles | Where-Object { $_.relative_path -cmatch '^pack-([0-9a-f]{40})\.pack$' })
        $indexEntries = @($packFiles | Where-Object { $_.relative_path -cmatch '^pack-([0-9a-f]{40})\.idx$' })
        if ($packFiles.Count -ne 2 -or $packEntries.Count -ne 1 -or $indexEntries.Count -ne 1 -or
            [string]$packEntries[0].relative_path.Substring(5, 40) -cne [string]$indexEntries[0].relative_path.Substring(5, 40)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: exact one-pack/one-index filename pairing is absent or ambiguous'
        }
        $packId = [string]$packEntries[0].relative_path.Substring(5, 40)
        $packReference = [PSCustomObject]@{ path = [string]$packEntries[0].full_path; bytes = [Int64]$packEntries[0].bytes; sha256 = ''; volume_serial_hex = ''; file_id_hex = '' }
        $indexReference = [PSCustomObject]@{ path = [string]$indexEntries[0].full_path; bytes = [Int64]$indexEntries[0].bytes; sha256 = ''; volume_serial_hex = ''; file_id_hex = '' }
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals($packReference.path, [string]$gitReference.pack_path) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals($indexReference.path, [string]$gitReference.index_path) -or
            $packReference.bytes -ne [Int64]$gitReference.pack_bytes -or $indexReference.bytes -ne [Int64]$gitReference.index_bytes -or
            $packReference.bytes -gt 268435456L -or $indexReference.bytes -gt 67108864L) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: exact pack/index path, caller-pinned byte lengths, or fixed size bounds do not match'
        }
        $packBefore = Get-D32ProfileFileMetadataSnapshot -Path $packReference.path
        $indexBefore = Get-D32ProfileFileMetadataSnapshot -Path $indexReference.path
        if ($packBefore.Bytes -ne $packReference.bytes -or $indexBefore.Bytes -ne $indexReference.bytes -or
            $packBefore.VolumeSerialHex -cne [string]$gitReference.pack_volume_serial_hex -or $packBefore.FileIdHex -cne [string]$gitReference.pack_file_id_hex -or
            $indexBefore.VolumeSerialHex -cne [string]$gitReference.index_volume_serial_hex -or $indexBefore.FileIdHex -cne [string]$gitReference.index_file_id_hex) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: opened pack/index length or object identity differs from the bounded caller pin'
        }
        $indexContent = Get-D32ProfileFileContentSnapshot -Path $indexReference.path -MaximumBytes 67108864L -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
        if ($indexContent.Bytes -ne $indexBefore.Bytes -or $indexContent.VolumeSerialHex -cne $indexBefore.VolumeSerialHex -or
            $indexContent.FileIdHex -cne $indexBefore.FileIdHex) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: opened Git pack index identity changed during its bounded read'
        }
        $indexBytes = [byte[]]$indexContent.Content
        $remainingMilliseconds = [Int64]$DeadlineMilliseconds - [Int64](Get-D32BoundedDiagnosticSourceProofCurrentElapsedMilliseconds -ProofTimer $ProofTimer)
        if ($remainingMilliseconds -le 0) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: no aggregate source-proof time remains for the Git pack closure' }
        Initialize-D32BoundedCompilerDiagnosticGitPackType
        $packStream = $null
        $reader = $null
        $checkoutProof = $null
        $packAfter = $null
        $indexAfter = $null
        $treeOid = $null
        $commitObject = $null
        $priorRetainedManifestCandidateBytes = [Int64]$retainedManifestCandidateBytes
        $remainingManifestCandidateCapacity = [Math]::Max(0, $MaximumManifestCandidates - $manifestCandidates.Count)
        $remainingManifestContentBytes = [Int64][Math]::Max(0L, $MaximumManifestBytes - $retainedManifestContentBytes)
        try {
            $packStream = [IO.FileStream]::new($packReference.path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $reader = [D32BoundedGitPackReaderV1]::new($packStream, $indexBytes, $packId, $remainingMilliseconds, 268435456L)
            $commitObject = $reader.Resolve([string]$source.commit)
            if ([string]$commitObject.Type -cne 'commit' -or [string]$commitObject.Oid -cne [string]$source.commit) {
                throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: locked commit did not resolve to an exact SHA-1 Git commit object'
            }
            $remainingTreeMilliseconds = [Int64]$DeadlineMilliseconds - [Int64](Get-D32BoundedDiagnosticSourceProofCurrentElapsedMilliseconds -ProofTimer $ProofTimer)
            if ($remainingTreeMilliseconds -le 0) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: no aggregate source-proof time remains for commit-tree parsing' }
            $treeOid = [D32BoundedGitPackReaderV1]::CommitTreeOid($commitObject.Data, $remainingTreeMilliseconds)
            $reader.Release($commitObject)
            $commitObject = $null
            $checkoutProof = Get-D32BoundedDiagnosticGitCheckoutContentProof -Reader $reader -TreeOid $treeOid -CheckoutPath $checkoutPath `
                -ExpectedCheckoutVolumeSerialHex ([string]$checkoutMatches[0].volume_serial_hex) -ExpectedCheckoutFileIdHex ([string]$checkoutMatches[0].file_id_hex) `
                -DatabasePath $databasePath -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds `
                -ExternalRetainedBytes $priorRetainedManifestCandidateBytes -MaximumManifestCandidates $remainingManifestCandidateCapacity `
                -MaximumManifestBytes $remainingManifestContentBytes
            $manifestIndex = 0
            foreach ($manifestText in $checkoutProof.manifest_texts) {
                if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.manifest_candidates' -Progress ("source={0};manifests={1}/{2}" -f $source.commit, $manifestIndex, $checkoutProof.manifest_texts.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED' -NoProgress }
                if ($manifestCandidates.Count -ge $MaximumManifestCandidates) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: verified Git Cargo.toml candidates exceed the remaining exact 4096-entry manifest-catalog capacity' }
                $manifestCandidates.Add([PSCustomObject]@{ source_kind = 'git'; source = [string]$source.source; source_path = [string]$manifestText.relative_path; content = [string]$manifestText.text; content_sha256 = [string]$manifestText.content_sha256; package_id = '' })
                $manifestIndex++
            }
            $totalExpanded += [Int64]$reader.ExpandedBytes
            $totalSourceBytes += [Int64]$checkoutProof.source_bytes
            if ($totalExpanded -gt 34359738368L -or $totalSourceBytes -gt 34359738368L -or
                ([Int64]$reader.PeakWorkingBytes + [Int64]$checkoutProof.inventory_managed_estimate_bytes + $priorRetainedManifestCandidateBytes) -gt [Int64]$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes) {
                throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: aggregate Git decompression, source bytes, or total managed working set exceeds its fixed bound'
            }
            $retainedManifestCandidateBytes = $priorRetainedManifestCandidateBytes + [Int64]$checkoutProof.manifest_retained_managed_estimate_bytes
            $retainedManifestContentBytes += [Int64]$checkoutProof.manifest_bytes
            $packAfter = Get-D32ProfileFileMetadataSnapshot -Path $packReference.path
            $indexAfter = Get-D32ProfileFileMetadataSnapshot -Path $indexReference.path
            if ($packBefore.Bytes -ne $packAfter.Bytes -or
                $packBefore.VolumeSerialHex -cne $packAfter.VolumeSerialHex -or $packBefore.FileIdHex -cne $packAfter.FileIdHex -or
                $indexBefore.Bytes -ne $indexAfter.Bytes -or
                $indexBefore.VolumeSerialHex -cne $indexAfter.VolumeSerialHex -or $indexBefore.FileIdHex -cne $indexAfter.FileIdHex) {
                throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: pack/index identity or content changed during Git source proof'
            }
            $databaseCatalogAfter = Get-D32BoundedDiagnosticGitCatalog -Path $databasePath -MaximumEntries 64 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
            $objectsCatalogAfter = Get-D32BoundedDiagnosticGitCatalog -Path $objectsPath -MaximumEntries 64 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
            $infoCatalogAfter = Get-D32BoundedDiagnosticGitCatalog -Path (Join-Path $objectsPath 'info') -MaximumEntries 64 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
            $packCatalogAfter = Get-D32BoundedDiagnosticGitCatalog -Path $packPath -MaximumEntries 64 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
            $repoCheckoutCatalogAfter = Get-D32BoundedDiagnosticGitCatalog -Path $repoCheckoutRoot -MaximumEntries 8 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
            if ($databaseCatalog.inventory_sha256 -cne $databaseCatalogAfter.inventory_sha256 -or
                $objectsCatalog.inventory_sha256 -cne $objectsCatalogAfter.inventory_sha256 -or
                $infoCatalog.inventory_sha256 -cne $infoCatalogAfter.inventory_sha256 -or
                $packCatalog.inventory_sha256 -cne $packCatalogAfter.inventory_sha256 -or
                $repoCheckoutCatalog.inventory_sha256 -cne $repoCheckoutCatalogAfter.inventory_sha256) {
                throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git metadata/pack/checkout catalogs drifted during current-source proof'
            }
            $tupleRows.Add([PSCustomObject][ordered]@{
                source = [string]$source.source
                url = [string]$source.url
                commit = [string]$source.commit
                tree_oid = [string]$treeOid
                database_path = $databasePath
                database_volume_serial_hex = [string]$databaseIdentity.VolumeSerialHex
                database_file_id_hex = [string]$databaseIdentity.FileIdHex
                pack_path = [string]$packReference.path
                pack_bytes = [Int64]$packBefore.Bytes
                pack_sha256 = [string]$reader.PackSha256
                pack_volume_serial_hex = [string]$packBefore.VolumeSerialHex
                pack_file_id_hex = [string]$packBefore.FileIdHex
                pack_content_sha1 = $packId
                index_path = [string]$indexReference.path
                index_bytes = [Int64]$indexBefore.Bytes
                index_sha256 = [string]$indexContent.Sha256
                index_volume_serial_hex = [string]$indexBefore.VolumeSerialHex
                index_file_id_hex = [string]$indexBefore.FileIdHex
                pack_object_count = [Int64]$reader.ObjectCount
                reader_peak_working_bytes = [Int64]$reader.PeakWorkingBytes
                reader_expanded_bytes = [Int64]$reader.ExpandedBytes
                checkout_path = [string]$checkoutProof.checkout_path
                checkout_volume_serial_hex = [string]$checkoutProof.checkout_volume_serial_hex
                checkout_file_id_hex = [string]$checkoutProof.checkout_file_id_hex
                checkout_file_count = [Int64]$checkoutProof.file_count
                checkout_directory_count = [Int64]$checkoutProof.directory_count
                checkout_metadata_count = [Int64]$checkoutProof.metadata_count
                checkout_source_bytes = [Int64]$checkoutProof.source_bytes
                checkout_inventory_sha256 = [string]$checkoutProof.inventory_sha256
            })
        }
        finally {
            if ($null -ne $commitObject) { $reader.Release($commitObject) }
            if ($null -ne $reader) { $reader.Dispose() }
            if ($null -ne $packStream) { $packStream.Dispose() }
            $indexBytes = $null
        }
    }
    if ($tupleRows.Count -ne $Origin.git_content_refs.Count) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: current Git source proof does not cover every caller-pinned tuple exactly once' }
    $dbRootAfter = Get-D32ProfileDirectoryIdentity -Path $databaseRoot
    $checkoutRootAfter = Get-D32ProfileDirectoryIdentity -Path $checkoutRoot
    $dbRootCatalogAfter = Get-D32BoundedDiagnosticGitCatalog -Path $databaseRoot -MaximumEntries 64 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    $checkoutRootCatalogAfter = Get-D32BoundedDiagnosticGitCatalog -Path $checkoutRoot -MaximumEntries 64 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    if ($dbRootBefore.VolumeSerialHex -cne $dbRootAfter.VolumeSerialHex -or $dbRootBefore.FileIdHex -cne $dbRootAfter.FileIdHex -or
        $checkoutRootBefore.VolumeSerialHex -cne $checkoutRootAfter.VolumeSerialHex -or $checkoutRootBefore.FileIdHex -cne $checkoutRootAfter.FileIdHex -or
        $dbRootCatalog.inventory_sha256 -cne $dbRootCatalogAfter.inventory_sha256 -or
        $checkoutRootCatalog.inventory_sha256 -cne $checkoutRootCatalogAfter.inventory_sha256) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: Git database/checkout root identity changed during proof'
    }
    $canonicalRows = [System.Collections.Generic.List[string]]::new()
    $canonicalIndex = 0
    foreach ($row in $tupleRows) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.proof_digest_rows' -Progress ("rows={0}/{1}" -f $canonicalIndex, $tupleRows.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED' -NoProgress }
        $canonicalRows.Add(([string]$row.source + "`t" + [string]$row.commit + "`t" + [string]$row.tree_oid + "`t" + [string]$row.pack_content_sha1 + "`t" +
            [string]$row.pack_sha256 + "`t" + [string]$row.index_sha256 + "`t" + [string]$row.checkout_inventory_sha256))
        $canonicalIndex++
    }
    Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.proof_digest_sort' -Progress ("rows={0}" -f $canonicalRows.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED'
    $canonicalRows.Sort([StringComparer]::Ordinal)
    Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'git.proof_digest_sort_complete' -Progress ("rows={0}" -f $canonicalRows.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED'
    $proofSha = Get-D32BoundedDiagnosticSha256FromLines -Lines ([string[]]$canonicalRows.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'git.proof_digest_hash'
    $verifiedGitSources = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($verifiedSource in $verifiedSourcePlans) { [void]$verifiedGitSources.Add([string]$verifiedSource.source) }
    $verifiedGitPackageIds = [System.Collections.Generic.List[string]]::new()
    foreach ($lockedPackage in $Plan.locked_packages) {
        if ([string]$lockedPackage.source_kind -ceq 'git' -and $verifiedGitSources.Contains([string]$lockedPackage.source)) { $verifiedGitPackageIds.Add([string]$lockedPackage.package_id) }
    }
    $proof = [PSCustomObject][ordered]@{
        schema_version = 2
        record_type = 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_CONTENT_PROOF_V2'
        gate_authority = 'NONE'
        status = 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY'
        formal_gate_usable = $false
        semantic_scope = 'EXACT_CALLER_PINNED_GIT_SOURCE_SUBSET_FOR_LOCKED_GRAPH_CANDIDATES'
        source_proof_sha256 = $proofSha
        lock_sha256 = [string]$Plan.lock_sha256
        git_tuple_sha256 = [string]$Plan.git_tuple_sha256
        database_root = [PSCustomObject]@{ path = $databaseRoot; volume_serial_hex = [string]$dbRootAfter.VolumeSerialHex; file_id_hex = [string]$dbRootAfter.FileIdHex; catalog_sha256 = [string]$dbRootCatalog.inventory_sha256 }
        checkout_root = [PSCustomObject]@{ path = $checkoutRoot; volume_serial_hex = [string]$checkoutRootAfter.VolumeSerialHex; file_id_hex = [string]$checkoutRootAfter.FileIdHex; catalog_sha256 = [string]$checkoutRootCatalog.inventory_sha256 }
        source_count = [Int64]$tupleRows.Count
        locked_git_source_catalog_count = [Int64]$Plan.git_source_count
        elapsed_milliseconds = [Int64]$ProofTimer.ElapsedMilliseconds
        expanded_object_bytes = $totalExpanded
        verified_checkout_source_bytes = $totalSourceBytes
        verifier_managed_buffer_cap_bytes = [Int64]$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes
        pack_reader_buffer_cap_bytes = 268435456L
        verified_package_ids = @($verifiedGitPackageIds.ToArray())
        sources = @($tupleRows.ToArray())
    }
    return [PSCustomObject]@{ proof = $proof; manifest_candidates = @($manifestCandidates.ToArray()) }
}

function Assert-D32BoundedDiagnosticInv7Origin {
    param([Parameter(Mandatory = $true)][object]$Origin, [Parameter(Mandatory = $true)][object]$Profile,
        [Parameter(Mandatory = $true)][string]$Repo,
        [Parameter(Mandatory = $true)][string]$CurrentCandidateSha,
        [string]$HistoricalOriginCandidateSha = $script:D32BoundedDiagnosticHistoricalOriginCandidateSha,
        [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds,
        [switch]$SourceProofOnly)
    if ($null -eq $ProofTimer) { $ProofTimer = [Diagnostics.Stopwatch]::StartNew() }
    elseif (-not $ProofTimer.IsRunning) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: supplied aggregate source-proof stopwatch must already be running' }
    Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'origin.start' -Progress 'origin_bindings' -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
    if ($CurrentCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or $HistoricalOriginCandidateSha -cne $script:D32BoundedDiagnosticHistoricalOriginCandidateSha -or
        $HistoricalOriginCandidateSha -ceq $CurrentCandidateSha) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: historical inv7 origin SHA is not distinct from the current diagnostic/source-proof candidate'
    }
    $originRoot = 'E:\d32\inv7'
    $cargoHome = 'E:\d32\inv7\r\c'
    $null = Assert-D32BoundedDiagnosticDirectoryReference -Path $Origin.path -VolumeSerialHex $Origin.volume_serial_hex -FileIdHex $Origin.file_id_hex
    if ([string]$Origin.path -cne $cargoHome) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: dependency origin is not the exact optional inv7 CargoHome' }
    $null = Assert-D32BoundedDiagnosticDirectoryReference -Path $cargoHome -VolumeSerialHex $Origin.volume_serial_hex -FileIdHex $Origin.file_id_hex
    $registryRootExpected = Join-Path $cargoHome 'registry/cache/index.crates.io-1949cf8c6b5b557f'
    $registrySourceRootExpected = Join-Path $cargoHome 'registry/src/index.crates.io-1949cf8c6b5b557f'
    $gitDatabaseRootExpected = Join-Path $cargoHome 'git/db'
    $gitCheckoutRootExpected = Join-Path $cargoHome 'git/checkouts'
    foreach ($rootPin in @(
        [PSCustomObject]@{ Reference = $Origin.registry_archive_root; Path = $registryRootExpected },
        [PSCustomObject]@{ Reference = $Origin.registry_source_root; Path = $registrySourceRootExpected },
        [PSCustomObject]@{ Reference = $Origin.git_database_root; Path = $gitDatabaseRootExpected },
        [PSCustomObject]@{ Reference = $Origin.git_checkout_root; Path = $gitCheckoutRootExpected })) {
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$rootPin.Reference.path, [string]$rootPin.Path)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: pinned optional-origin subtree path differs from its exact CargoHome location'
        }
        Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'origin.root_identity' -Progress ([IO.Path]::GetFileName([string]$rootPin.Path)) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
        $null = Assert-D32BoundedDiagnosticDirectoryReference -Path $rootPin.Path -VolumeSerialHex $rootPin.Reference.volume_serial_hex -FileIdHex $rootPin.Reference.file_id_hex
    }
    if (-not $SourceProofOnly) {
        $home = Test-D32CargoHome -Path $cargoHome -Repository $Repo
        if ([string]$home.Path -cne $cargoHome) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: optional CargoHome current path differs' }
    }
    $null = Assert-D32BoundedDiagnosticFileReference -Reference $Origin.owner_record -MustBeWithin $originRoot -MustNotBeWithin $Repo `
        -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -ReferenceField 'dependency_origin.owner_record' -Caller 'Assert-D32BoundedDiagnosticInv7Origin'
    $owner = Assert-D32BoundedDiagnosticOwnerRecord -Reference $Origin.owner_record -Repo $Repo `
        -HistoricalOriginCandidateSha $HistoricalOriginCandidateSha -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    $priorProvenance = Assert-D32BoundedDiagnosticPriorInv7Provenance -Origin $Origin -Owner $owner -Repo $Repo `
        -HistoricalOriginCandidateSha $HistoricalOriginCandidateSha -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    $historicalFetchCompletion = 'NOT_RETAINED'
    $fetchIndex = 0
    foreach ($fetch in $Origin.fetch_records) {
        $null = Assert-D32BoundedDiagnosticFileReference -Reference $fetch -MustBeWithin $originRoot -MustNotBeWithin $Repo `
            -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -ReferenceField "dependency_origin.fetch_records[$fetchIndex]" -Caller 'Assert-D32BoundedDiagnosticInv7Origin'
        $fetchIndex++
    }

    $expectedManifestPaths = @(
        'vita-agent-protocol/Cargo.toml', 'vita-agent-protocol/Cargo.lock',
        'vita-agent/Cargo.toml', 'vita-agent/Cargo.lock',
        'src-tauri/Cargo.toml', 'src-tauri/Cargo.lock'
    )
    $manifestByPath = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $manifestIndex = 0
    foreach ($reference in $Origin.manifest_refs) {
        $null = Assert-D32BoundedDiagnosticFileReference -Reference $reference -MustBeWithin $Repo -MustNotBeWithin $null `
            -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -ReferenceField "dependency_origin.manifest_refs[$manifestIndex]" -Caller 'Assert-D32BoundedDiagnosticInv7Origin'
        $relative = [IO.Path]::GetRelativePath($Repo, [string]$reference.path).Replace('\', '/')
        if (-not $manifestByPath.TryAdd($relative, $reference)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: manifest/lock reference is duplicated' }
        $manifestIndex++
    }
    if ($manifestByPath.Count -ne $expectedManifestPaths.Count) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: complete manifest/lock inventory is not pinned' }
    foreach ($relative in $expectedManifestPaths) {
        if (-not $manifestByPath.ContainsKey($relative)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: one exact D32 manifest/lock reference is missing' }
    }
    foreach ($lock in $Profile.LockInputs) {
        $relative = [string]$lock.LockPath
        $reference = $manifestByPath[$relative]
        if ([string]$reference.sha256 -cne [string]$lock.LockSha256) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: Profile V2 and dependency origin disagree on a locked manifest digest' }
    }
    $vitaLockReference = $manifestByPath['vita-agent/Cargo.lock']
    $vitaLockContent = Get-D32ProfileFileContentSnapshot -Path ([string]$vitaLockReference.path) -MaximumBytes 8388608L -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
    if ($vitaLockContent.Bytes -ne [Int64]$vitaLockReference.bytes -or $vitaLockContent.Sha256 -cne [string]$vitaLockReference.sha256 -or
        $vitaLockContent.VolumeSerialHex -cne [string]$vitaLockReference.volume_serial_hex -or $vitaLockContent.FileIdHex -cne [string]$vitaLockReference.file_id_hex) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: opened current vita-agent Cargo.lock content differs from its caller pin'
    }
    try { $vitaLockText = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$vitaLockContent.Content) }
    catch { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: current vita-agent Cargo.lock is not strict UTF-8' }
    $sourcePlan = Get-D32BoundedCompilerDiagnosticSourcePlan -LockText $vitaLockText -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    if ([Int64]$sourcePlan.locked_package_count -le 0 -or [string]$sourcePlan.lock_sha256 -cne [string]$Profile.LockInputs.Where({ $_.LockPath -ceq 'vita-agent/Cargo.lock' })[0].LockSha256) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: lock-derived source plan does not match the pinned current vita-agent lock'
    }
    $lockedPackages = @($sourcePlan.locked_packages)
    $lockedRegistry = @($lockedPackages | Where-Object { $_.source_kind -ceq 'registry' })
    $lockedGit = @($lockedPackages | Where-Object { $_.source_kind -ceq 'git' } | Group-Object -Property source | ForEach-Object { $_.Group[0] })
    $manifestIndex = 0
    foreach ($reference in $Origin.manifest_refs) {
        $null = Assert-D32BoundedDiagnosticFileReference -Reference $reference -MustBeWithin $Repo -MustNotBeWithin $null `
            -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -ReferenceField "dependency_origin.manifest_refs[$manifestIndex]" -Caller 'Assert-D32BoundedDiagnosticInv7Origin'
        $manifestIndex++
    }

    if ($sourcePlan.registry_package_count -ne $lockedRegistry.Count -or $sourcePlan.git_source_count -ne $lockedGit.Count -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Origin.registry_archive_root.path, $registryRootExpected)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: lock-derived registry tuple count/root differs from the pinned archive origin'
    }
    $archiveByKey = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $archiveIndex = 0
    $lockedRegistryByKey = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($package in $lockedRegistry) {
        $key = [string]$package.name + "`0" + [string]$package.version
        if (-not $lockedRegistryByKey.TryAdd($key, $package)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: duplicate locked registry name/version key' }
    }
    foreach ($archive in $Origin.registry_archives) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'origin.registry_refs' -Progress ("archives={0}/{1}" -f $archiveByKey.Count, $Origin.registry_archives.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $fields = @('source', 'name', 'version', 'checksum', 'path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $archive -Expected $fields) -or
            [string]$archive.source -cne 'registry+https://github.com/rust-lang/crates.io-index' -or
            [string]$archive.name -notmatch '^[A-Za-z0-9_-]+$' -or [string]$archive.version -notmatch '^[0-9A-Za-z.+_-]+$' -or
            [string]$archive.checksum -cnotmatch '^[0-9a-f]{64}$' -or [string]$archive.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$archive.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$archive.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $archive.bytes -Positive)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: registry archive source pin has an invalid exact schema' }
        $key = [string]$archive.name + "`0" + [string]$archive.version
        $expectedPath = Join-Path $registryRootExpected (([string]$archive.name + '-' + [string]$archive.version) + '.crate')
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$archive.path, $expectedPath) -or -not $archiveByKey.TryAdd($key, $archive)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: archive path or package/version key is wrong or duplicated'
        }
    }
    if ($archiveByKey.Count -gt $lockedRegistry.Count) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: caller-pinned registry subset exceeds the current lock catalog' }
    foreach ($archive in $Origin.registry_archives) {
        $key = [string]$archive.name + "`0" + [string]$archive.version
        $package = $null
        if (-not $archiveByKey.ContainsKey($key) -or -not $lockedRegistryByKey.TryGetValue($key, [ref]$package)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: caller-pinned archive is duplicated or absent from the exact current lock catalog' }
        if ([string]$archive.checksum -cne [string]$package.checksum -or [string]$archive.sha256 -cne [string]$package.checksum) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: registry archive checksum differs from Cargo.lock'
        }
        $archiveIndex++
    }
    Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'origin.registry_complete' -Progress ("archives={0}" -f $archiveIndex) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
    $registryContentResult = New-D32BoundedDiagnosticRegistrySourceContentProof -Plan $sourcePlan -Origin $Origin -Repo $Repo -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds

    if (-not $SourceProofOnly -and $null -ne $Origin.git_source_authority) {
        # This optional reference is historical context only. Current source
        # content is proved from the lock, pack/index, and checkout below.
        $null = Assert-D32BoundedDiagnosticFileReference -Reference $Origin.git_source_authority -MustBeWithin $originRoot -MustNotBeWithin $Repo `
            -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -ReferenceField 'dependency_origin.git_source_authority' -Caller 'Assert-D32BoundedDiagnosticInv7Origin'
    }
    $workspaceManifestReferenceCount = 0
    $workspaceManifestContentBytes = [Int64]0
    $workspaceManifestReferenceIndex = 0
    foreach ($reference in $Origin.manifest_refs) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'graph.workspace_manifest_capacity' -Progress ("references={0}/{1}" -f $workspaceManifestReferenceIndex, $Origin.manifest_refs.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        if ([IO.Path]::GetFileName([string]$reference.path) -ceq 'Cargo.toml') {
            if ([Int64]$reference.bytes -le 0 -or [Int64]$reference.bytes -gt 1048576L) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: pinned current workspace Cargo.toml exceeds the fixed 1 MiB manifest bound before Git traversal' }
            $workspaceManifestReferenceCount++
            $workspaceManifestContentBytes += [Int64]$reference.bytes
            if ($workspaceManifestContentBytes -gt 67108864L) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: current workspace Cargo.toml candidates exceed the exact 64 MiB manifest-content catalog budget' }
        }
        $workspaceManifestReferenceIndex++
    }
    $remainingGitManifestCandidateCapacity = 4096 - [int]$registryContentResult.manifest_candidates.Count - $workspaceManifestReferenceCount
    if ($remainingGitManifestCandidateCapacity -lt 0) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: registry and current workspace manifests exceed the exact 4096-entry candidate catalog cap before Git traversal' }
    $remainingGitManifestBytes = 67108864L - [Int64]$registryContentResult.manifest_candidate_bytes - $workspaceManifestContentBytes
    if ($remainingGitManifestBytes -lt 0) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: registry and current workspace Cargo.toml candidates exceed the exact 64 MiB content bound before Git traversal' }
    $registryManifestRetainedBytesEstimate = [Int64]0
    $registryCandidateIndex = 0
    foreach ($candidate in $registryContentResult.manifest_candidates) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'graph.registry_manifest_memory_estimate' -Progress ("candidates={0}/{1}" -f $registryCandidateIndex, $registryContentResult.manifest_candidates.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $candidateBytes = [Int64][Text.UTF8Encoding]::new($false).GetByteCount([string]$candidate.content)
        $registryManifestRetainedBytesEstimate += 4096L + (3L * $candidateBytes)
        if ($registryManifestRetainedBytesEstimate -gt [Int64]$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: retained registry manifest candidates exceed the fixed 512 MiB managed-memory budget' }
        $registryCandidateIndex++
    }
    $gitContentResult = New-D32BoundedDiagnosticGitSourceContentProof -Plan $sourcePlan -Origin $Origin -Repo $Repo -ProofTimer $ProofTimer `
        -DeadlineMilliseconds $DeadlineMilliseconds -MaximumManifestCandidates $remainingGitManifestCandidateCapacity `
        -ExternalRetainedManifestBytes $registryManifestRetainedBytesEstimate -MaximumManifestBytes $remainingGitManifestBytes
    $retainedManifestCandidateBytes = [Int64]$registryManifestRetainedBytesEstimate
    $gitCandidateIndex = 0
    foreach ($candidate in $gitContentResult.manifest_candidates) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'graph.git_manifest_memory_estimate' -Progress ("candidates={0}/{1}" -f $gitCandidateIndex, $gitContentResult.manifest_candidates.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $candidateBytes = [Int64][Text.UTF8Encoding]::new($false).GetByteCount([string]$candidate.content)
        $retainedManifestCandidateBytes += 4096L + (3L * $candidateBytes)
        if ($retainedManifestCandidateBytes -gt [Int64]$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: retained registry and Git manifest candidates exceed the fixed 512 MiB managed-memory budget' }
        $gitCandidateIndex++
    }
    $manifestCandidates = [System.Collections.Generic.List[object]]::new()
    $currentManifestProofs = [System.Collections.Generic.List[object]]::new()
    foreach ($candidate in $registryContentResult.manifest_candidates) { $manifestCandidates.Add($candidate) }
    foreach ($candidate in $gitContentResult.manifest_candidates) { $manifestCandidates.Add($candidate) }
    foreach ($reference in $Origin.manifest_refs) {
        $relative = [IO.Path]::GetRelativePath($Repo, [string]$reference.path).Replace('\', '/')
        if (-not $relative.EndsWith('/Cargo.toml', [StringComparison]::Ordinal)) { continue }
        if ([Int64]$reference.bytes -le 0 -or [Int64]$reference.bytes -gt 1048576L) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: pinned current workspace Cargo.toml exceeds the fixed 1 MiB manifest bound' }
        $workspaceManifestManagedEstimate = 4096L + (3L * [Int64]$reference.bytes)
        if ($retainedManifestCandidateBytes -gt ([Int64]$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes - $workspaceManifestManagedEstimate)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: retained registry, Git, and current workspace manifests exceed the fixed 512 MiB managed-memory budget' }
        $manifestContent = Get-D32ProfileFileContentSnapshot -Path ([string]$reference.path) -MaximumBytes 1048576L -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
        if ([Int64]$manifestContent.Bytes -ne [Int64]$reference.bytes -or [string]$manifestContent.Sha256 -cne [string]$reference.sha256 -or
            [string]$manifestContent.VolumeSerialHex -cne [string]$reference.volume_serial_hex -or [string]$manifestContent.FileIdHex -cne [string]$reference.file_id_hex) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: caller-pinned current workspace manifest changed during the bounded graph input read'
        }
        try { $content = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$manifestContent.Content) }
        catch { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: caller-pinned current workspace manifest is not strict UTF-8' }
        $retainedManifestCandidateBytes += $workspaceManifestManagedEstimate
        $manifestCandidates.Add([PSCustomObject]@{ source_kind = 'workspace'; source = $null; source_path = $relative; content = $content; content_sha256 = [string]$reference.sha256; package_id = '' })
        $currentManifestProofs.Add([PSCustomObject][ordered]@{
            manifest_path = $relative; bytes = [Int64]$reference.bytes; sha256 = [string]$reference.sha256
            volume_serial_hex = [string]$reference.volume_serial_hex; file_id_hex = [string]$reference.file_id_hex
        })
    }
    $resolvedManifestCatalog = Complete-D32BoundedDiagnosticManifestCatalog -Plan $sourcePlan -Candidates @($manifestCandidates.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    $graphContentProof = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $sourcePlan -ManifestCatalog $resolvedManifestCatalog.entries -RootManifestPath 'vita-agent/Cargo.toml' -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    $registryContentProof = $registryContentResult.proof
    $gitContentProof = $gitContentResult.proof
    $historicalSourceClosureReference = $null
    $gitAuthorityProperty = $Origin.PSObject.Properties['git_source_authority']
    if ($null -ne $gitAuthorityProperty -and $null -ne $gitAuthorityProperty.Value) { $historicalSourceClosureReference = [string]$gitAuthorityProperty.Value.path }
    return [PSCustomObject]@{
        CargoHome = $cargoHome
        OwnerRunId = [string]$owner.RunId
        CurrentCandidateSha = $CurrentCandidateSha
         HistoricalOriginCandidateSha = $HistoricalOriginCandidateSha
         HistoricalFetchCompletion = $historicalFetchCompletion
        HistoricalAttemptState = 'BLOCKED'
        HistoricalGateAuthority = 'NONE'
        FetchReferenceCount = [Int64]$Origin.fetch_records.Count
        RegistryArchiveCount = [Int64]$archiveByKey.Count
        RegistryContentProof = $registryContentProof
        GitContentProof = $gitContentProof
        SourceGraphProof = $graphContentProof
        CurrentManifestProof = @($currentManifestProofs.ToArray())
        LockedPackageCount = [Int64]$sourcePlan.locked_package_count
        ReachablePackageCount = [Int64]$graphContentProof.included_package_count
        ExcludedPackageCount = [Int64]$graphContentProof.excluded_package_count
        LockedGitSourceCount = [Int64]$sourcePlan.git_source_count
        HistoricalSourceClosureReference = $historicalSourceClosureReference
    }
}

function Assert-D32BoundedDiagnosticExtractedSourceInventory {
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][object[]]$Entries, [Parameter(Mandatory = $true)][string]$ExpectedDigest)
    $expected = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($entry in $Entries) {
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $entry @('relative_path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
            $entry.relative_path -isnot [string] -or [string]$entry.relative_path -match '(^/|^[A-Za-z]:|(^|/)\.\.?(/|$)|\\|\x00)' -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $entry.bytes -Positive) -or [string]$entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$entry.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$entry.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            -not $expected.TryAdd([string]$entry.relative_path, $entry)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: extracted-source manifest entry is malformed or duplicated' }
    }
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($Root)
    $actual = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    while ($stack.Count -gt 0) {
        $directory = $stack.Pop()
        foreach ($item in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $attributes = [IO.File]::GetAttributes($item)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: extracted Git checkout contains a reparse entry' }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { $stack.Push($item); continue }
            $relative = [IO.Path]::GetRelativePath($Root, $item).Replace('\', '/')
            if (-not $expected.ContainsKey($relative)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: extracted Git checkout contains an unpinned file' }
            $snapshot = Get-D32ProfileFileSnapshot -Path $item
            $entry = $expected[$relative]
            if ($snapshot.Bytes -ne [Int64]$entry.bytes -or $snapshot.Sha256 -cne [string]$entry.sha256 -or
                $snapshot.VolumeSerialHex -cne [string]$entry.volume_serial_hex -or $snapshot.FileIdHex -cne [string]$entry.file_id_hex -or
                -not $actual.TryAdd($relative, $snapshot)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: extracted Git source file content/identity differs from its independent manifest' }
            if ($actual.Count -gt 100000) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: extracted Git source inventory exceeds its fixed entry bound' }
        }
    }
    if ($actual.Count -ne $expected.Count) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: extracted Git source inventory is incomplete' }
    $canonical = [System.Collections.Generic.List[string]]::new()
    foreach ($relative in @($actual.Keys | Sort-Object -CaseSensitive)) {
        $snapshot = $actual[$relative]
        $canonical.Add(([string]$relative + "`t" + [Int64]$snapshot.Bytes + "`t" + [string]$snapshot.Sha256 + "`t" + [string]$snapshot.VolumeSerialHex + "`t" + [string]$snapshot.FileIdHex))
    }
    $text = ($canonical -join "`n") + "`n"
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($text))).ToLowerInvariant()
    if ($digest -cne $ExpectedDigest) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: extracted Git source inventory digest differs from the pinned closure' }
}

function Get-D32BoundedDiagnosticCapacity {
    param([Parameter(Mandatory = $true)][string]$EvidenceParent, [Parameter(Mandatory = $true)][string]$TargetDirectory)
    if ([Environment]::ProcessorCount -lt 8) { throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: fewer than eight logical CPUs are available' }
    $system = [D32FixtureNativeProcessV2]::GetInitialBoundedDiagnosticSystemCapacity()
    if (-not [bool]$system.Reliable -or [Int64]$system.AvailablePhysicalBytes -lt (12L * 1024L * 1024L * 1024L) -or
        [Int64]$system.CommitHeadroomBytes -lt (8L * 1024L * 1024L * 1024L)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: physical memory or commit headroom is below its fixed prelaunch minimum or unreliable'
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($EvidenceParent)))
    if (-not $drive.IsReady -or [Int64]$drive.AvailableFreeSpace -lt (200L * 1024L * 1024L * 1024L)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: output-volume free space is below 200 GiB or unavailable'
    }
    $targetDrive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($TargetDirectory)))
    if (-not $targetDrive.IsReady -or [Int64]$targetDrive.AvailableFreeSpace -lt (200L * 1024L * 1024L * 1024L)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: normal-target volume free space is below 200 GiB or unavailable'
    }
    $writerCensus = Assert-D32BoundedCompilerDiagnosticNoGlobalWriter -ProcessProbe {
        Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
    }
    return [PSCustomObject]@{
        checked_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        logical_processors = [int][Environment]::ProcessorCount
        available_physical_bytes = [Int64]$system.AvailablePhysicalBytes
        total_physical_bytes = [Int64]$system.TotalPhysicalBytes
        commit_headroom_bytes = [Int64]$system.CommitHeadroomBytes
        output_volume_free_bytes = [Int64]$drive.AvailableFreeSpace
        target_volume_free_bytes = [Int64]$targetDrive.AvailableFreeSpace
        process_census_count = [Int64]$writerCensus.process_count
        competing_target_writer_count = [Int64]$writerCensus.competing_target_writer_count
        competing_target_writers = @($writerCensus.competing_target_writers)
        target_writer_check = [string]$writerCensus.target_writer_check
    }
}

function Write-D32BoundedDiagnosticCreateNewJson {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][object]$Document,
        [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds,
        [long]$MaximumBytes = $script:D32BoundedDiagnosticSourceProofMaximumOutputBytes)
    if ($null -ne $ProofTimer) {
        if ($MaximumBytes -le 0 -or $MaximumBytes -gt $script:D32BoundedDiagnosticSourceProofMaximumOutputBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: result output bound is invalid or exceeds its fixed cap' }
        $null = Get-D32BoundedDiagnosticEstimatedJsonUpperBound -Document $Document -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -MaximumBytes $MaximumBytes
        Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'result.json_serialize' -Progress 'begin' -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
    }
    $json = ConvertTo-Json -InputObject $Document -Depth 80 -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
    if ($bytes.Length -le 0 -or ($null -ne $ProofTimer -and $bytes.Length -gt $MaximumBytes)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: serialized source-proof result exceeds its fixed byte ceiling' }
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'result.json_serialize_complete' -Progress ("bytes={0}" -f $bytes.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        if ($null -eq $ProofTimer) { $stream.Write($bytes, 0, $bytes.Length) }
        else {
            for ($offset = 0; $offset -lt $bytes.Length; $offset += 65536) {
                Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'result.write' -Progress ("bytes={0}/{1}" -f $offset, $bytes.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
                $take = [int][Math]::Min(65536, $bytes.Length - $offset)
                $stream.Write($bytes, $offset, $take)
                Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'result.write_complete' -Progress ("bytes={0}/{1}" -f ($offset + $take), $bytes.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
            }
        }
        $stream.Flush($true)
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'result.flush_complete' -Progress ("bytes={0}" -f $bytes.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
    }
    finally { $stream.Dispose() }
    return Get-D32ProfileFileSnapshot -Path $Path -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks)
}

function Write-D32BoundedDiagnosticSidecarLine {
    param([Parameter(Mandatory = $true)][IO.StreamWriter]$Writer, [Parameter(Mandatory = $true)][object]$Document)
    $Writer.WriteLine((ConvertTo-Json -InputObject $Document -Depth 50 -Compress))
    $Writer.Flush()
}

function Write-D32BoundedDiagnosticBoundedSidecarLine {
    param([Parameter(Mandatory = $true)][IO.StreamWriter]$Writer, [Parameter(Mandatory = $true)][object]$Document,
        [Parameter(Mandatory = $true)][long]$PriorBytes, [Parameter(Mandatory = $true)][long]$MaximumBytes)
    $line = ConvertTo-Json -InputObject $Document -Depth 40 -Compress
    $bytes = [Int64]([Text.UTF8Encoding]::new($false).GetByteCount($line) + 1)
    if ($bytes -le 0 -or ($PriorBytes + $bytes) -gt $MaximumBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_SIDECAR_LIMIT: sample sidecar reached its fixed byte ceiling' }
    $Writer.WriteLine($line)
    $Writer.Flush()
    return ($PriorBytes + $bytes)
}

function Protect-D32BoundedDiagnosticText {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return $null }
    $safe = [string]$Text
    $safe = [regex]::Replace($safe, '(?i)(https?://)[^/@\s]+:[^/@\s]+@', '$1[REDACTED]@')
    $safe = [regex]::Replace($safe, '(?i)(authorization\s*[:=]\s*bearer\s+)[^\s;]+', '$1[REDACTED]')
    $safe = [regex]::Replace($safe, '(?i)((?:token|password|secret|credential|authorization|api.?key)\s*[:=]\s*)("[^"]*"|\S+)', '$1[REDACTED]')
    return $safe
}

function Get-D32BoundedDiagnosticExceptionChain {
    param([AllowNull()][System.Exception]$Exception)
    $items = [System.Collections.Generic.List[object]]::new()
    $current = $Exception
    for ($depth = 0; $null -ne $current -and $depth -lt 8; $depth++) {
        $items.Add([ordered]@{
            depth = [int]$depth
            exception_type = [string]$current.GetType().FullName
            hresult_hex = ('0x{0:x8}' -f [uint32]$current.HResult)
            message = Protect-D32BoundedDiagnosticText -Text ([string]$current.Message)
        })
        if ([object]::ReferenceEquals($current, $current.InnerException)) { break }
        $current = $current.InnerException
    }
    return @($items.ToArray())
}

function New-D32BoundedDiagnosticProcessSampleDocument {
    param([Parameter(Mandatory = $true)][object]$Sample, [Parameter(Mandatory = $true)][long]$Sequence)
    if (-not [bool]$Sample.Reliable -or -not [bool]$Sample.JobAccountingVerified -or $Sample.Processes -isnot [Array]) {
        throw ('D32_BOUNDED_DIAGNOSTIC_METRICS_UNRELIABLE: ' + (Protect-D32BoundedDiagnosticText -Text ([string]$Sample.Failure)))
    }
    if ($Sample.Processes.Count -gt 512) { throw 'D32_BOUNDED_DIAGNOSTIC_METRICS_UNRELIABLE: retained process sample exceeds the fixed 512-row ceiling' }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($process in $Sample.Processes) {
        if ([uint32]$process.ProcessId -eq 0 -or [Int64]$process.CreationFileTime -le 0 -or
            -not [bool]$process.CpuVerified -or [Int64]$process.UserTime100Ns -lt 0 -or [Int64]$process.KernelTime100Ns -lt 0 -or
            (-not [bool]$process.ProcessSignaled -and (-not [bool]$process.MemoryVerified -or [Int64]$process.PrivateBytes -lt 0 -or [Int64]$process.WorkingSetBytes -lt 0))) {
            throw 'D32_BOUNDED_DIAGNOSTIC_METRICS_UNRELIABLE: one retained process sample lacks PID/creation/CPU/memory identity'
        }
        $rows.Add([ordered]@{
            process_id = [uint32]$process.ProcessId
            creation_filetime = [Int64]$process.CreationFileTime
            image_path = Protect-D32BoundedDiagnosticText -Text ([string]$process.ImagePath)
            process_signaled = [bool]$process.ProcessSignaled
            cpu_verified = [bool]$process.CpuVerified
            user_time_100ns = [Int64]$process.UserTime100Ns
            kernel_time_100ns = [Int64]$process.KernelTime100Ns
            memory_verified = [bool]$process.MemoryVerified
            private_bytes = if ([bool]$process.MemoryVerified) { [Int64]$process.PrivateBytes } else { $null }
            working_set_bytes = if ([bool]$process.MemoryVerified) { [Int64]$process.WorkingSetBytes } else { $null }
        })
    }
    return [ordered]@{
        record_type = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_SAMPLE_V1'
        sample_state = 'RELIABLE'
        sequence = [Int64]$Sequence
        stopwatch_ticks = [Int64]$Sample.StopwatchTicks
        available_physical_bytes = [Int64]$Sample.AvailablePhysicalBytes
        total_physical_bytes = [Int64]$Sample.TotalPhysicalBytes
        commit_used_bytes = [Int64]$Sample.CommitUsedBytes
        commit_limit_bytes = [Int64]$Sample.CommitLimitBytes
        system_commit_peak_bytes = [Int64]$Sample.SystemCommitPeakBytes
        commit_headroom_bytes = [Int64]$Sample.CommitHeadroomBytes
        job_total_processes = [uint32]$Sample.JobTotalProcesses
        job_active_processes = [uint32]$Sample.JobActiveProcesses
        job_accounting_verified = [bool]$Sample.JobAccountingVerified
        processes = @($rows.ToArray())
    }
}

function Get-D32BoundedDiagnosticSamplingSummary {
    param([Parameter(Mandatory = $true)][object[]]$Samples, [Parameter(Mandatory = $true)][object[]]$RustcRecords,
        [Parameter(Mandatory = $true)][long]$StopwatchFrequency, [Parameter(Mandatory = $true)][bool]$Complete,
        [Parameter(Mandatory = $true)][string]$StopReason)
    $processes = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $minimumAvailable = [Int64]::MaxValue
    $minimumCommit = [Int64]::MaxValue
    $maximumCommitUsed = [Int64]0
    $maximumSystemCommitPeak = [Int64]0
    $maximumSystemCommitLimit = [Int64]0
    $totalPhysical = [Int64]0
    $maximumGapTicks = [Int64]0
    for ($i = 0; $i -lt $Samples.Count; $i++) {
        $sample = $Samples[$i]
        $minimumAvailable = [Math]::Min($minimumAvailable, [Int64]$sample.available_physical_bytes)
        $minimumCommit = [Math]::Min($minimumCommit, [Int64]$sample.commit_headroom_bytes)
        $maximumCommitUsed = [Math]::Max($maximumCommitUsed, [Int64]$sample.commit_used_bytes)
        $maximumSystemCommitPeak = [Math]::Max($maximumSystemCommitPeak, [Int64]$sample.system_commit_peak_bytes)
        $maximumSystemCommitLimit = [Math]::Max($maximumSystemCommitLimit, [Int64]$sample.commit_limit_bytes)
        $totalPhysical = [Math]::Max($totalPhysical, [Int64]$sample.total_physical_bytes)
        if ($i -gt 0) { $maximumGapTicks = [Math]::Max($maximumGapTicks, [Int64]$sample.stopwatch_ticks - [Int64]$Samples[$i - 1].stopwatch_ticks) }
        foreach ($process in $sample.processes) {
            $key = ([uint32]$process.process_id).ToString([Globalization.CultureInfo]::InvariantCulture) + '|' + [Int64]$process.creation_filetime
            if (-not $processes.ContainsKey($key)) {
                $processes.Add($key, [ordered]@{
                    process_id = [uint32]$process.process_id; creation_filetime = [Int64]$process.creation_filetime
                    image_path = [string]$process.image_path; observed_sample_count = [Int64]0
                    first_user_time_100ns = $null; last_user_time_100ns = $null; first_kernel_time_100ns = $null; last_kernel_time_100ns = $null
                    observed_private_peak_bytes = [Int64]0; observed_working_set_peak_bytes = [Int64]0; memory_sample_count = [Int64]0
                })
            }
            $row = $processes[$key]
            $row.observed_sample_count++
            if ($null -eq $row.first_user_time_100ns) { $row.first_user_time_100ns = [Int64]$process.user_time_100ns; $row.first_kernel_time_100ns = [Int64]$process.kernel_time_100ns }
            $row.last_user_time_100ns = [Int64]$process.user_time_100ns
            $row.last_kernel_time_100ns = [Int64]$process.kernel_time_100ns
            if ([bool]$process.memory_verified) {
                $row.memory_sample_count++
                $row.observed_private_peak_bytes = [Math]::Max([Int64]$row.observed_private_peak_bytes, [Int64]$process.private_bytes)
                $row.observed_working_set_peak_bytes = [Math]::Max([Int64]$row.observed_working_set_peak_bytes, [Int64]$process.working_set_bytes)
            }
        }
    }
    $rustcRows = [System.Collections.Generic.List[object]]::new()
    foreach ($rustc in $RustcRecords) {
        $key = ([uint32]$rustc.ProcessId).ToString([Globalization.CultureInfo]::InvariantCulture) + '|' + [Int64]$rustc.CreationFileTime
        $matched = $null
        [void]$processes.TryGetValue($key, [ref]$matched)
        $rustcRows.Add([ordered]@{
            process_id = [uint32]$rustc.ProcessId
            creation_filetime = [Int64]$rustc.CreationFileTime
            parent_process_id = [uint32]$rustc.ParentProcessId
            parent_creation_filetime = [Int64]$rustc.ParentCreationFileTime
            image_path = [string]$rustc.ImagePath
            sampled = ($null -ne $matched)
            sampled_count = if ($null -ne $matched) { [Int64]$matched.observed_sample_count } else { 0L }
            observed_private_peak_bytes = if ($null -ne $matched) { [Int64]$matched.observed_private_peak_bytes } else { $null }
            observed_working_set_peak_bytes = if ($null -ne $matched) { [Int64]$matched.observed_working_set_peak_bytes } else { $null }
            memory_sample_count = if ($null -ne $matched) { [Int64]$matched.memory_sample_count } else { 0L }
            sampled_user_cpu_delta_100ns = if ($null -ne $matched -and $null -ne $matched.first_user_time_100ns) { [Math]::Max(0L, [Int64]$matched.last_user_time_100ns - [Int64]$matched.first_user_time_100ns) } else { $null }
            sampled_kernel_cpu_delta_100ns = if ($null -ne $matched -and $null -ne $matched.first_kernel_time_100ns) { [Math]::Max(0L, [Int64]$matched.last_kernel_time_100ns - [Int64]$matched.first_kernel_time_100ns) } else { $null }
        })
    }
    return [ordered]@{
        sample_count = [Int64]$Samples.Count
        sampling_complete = $Complete
        sampling_stop_reason = Protect-D32BoundedDiagnosticText -Text $StopReason
        maximum_sample_gap_ticks = $maximumGapTicks
        maximum_sample_gap_milliseconds = if ($StopwatchFrequency -gt 0) { [Int64][Math]::Ceiling($maximumGapTicks * 1000.0 / $StopwatchFrequency) } else { $null }
        maximum_sample_gap_at_or_below_10000ms = ($StopwatchFrequency -gt 0 -and $maximumGapTicks -le ([Int64]$StopwatchFrequency * 10))
        minimum_available_physical_bytes = if ($Samples.Count -gt 0) { $minimumAvailable } else { $null }
        minimum_commit_headroom_bytes = if ($Samples.Count -gt 0) { $minimumCommit } else { $null }
        maximum_observed_commit_used_bytes = if ($Samples.Count -gt 0) { $maximumCommitUsed } else { $null }
        maximum_observed_system_commit_peak_bytes = if ($Samples.Count -gt 0) { $maximumSystemCommitPeak } else { $null }
        maximum_observed_system_commit_limit_bytes = if ($Samples.Count -gt 0) { $maximumSystemCommitLimit } else { $null }
        maximum_observed_total_physical_bytes = if ($Samples.Count -gt 0) { $totalPhysical } else { $null }
        retained_process_identities = @($processes.Values)
        rustc_process_count = [Int64]$RustcRecords.Count
        rustc_processes = @($rustcRows.ToArray())
        rustc_processes_all_sampled = ($RustcRecords.Count -eq 0 -or @($rustcRows | Where-Object { -not $_.sampled }).Count -eq 0)
        private_peak_label = 'maximum observed 10-second sampled PrivateUsage; not a lifetime peak'
    }
}

function Get-D32BoundedDiagnosticCargoArtifacts {
    param([Parameter(Mandatory = $true)][string]$StdoutPath, [Parameter(Mandatory = $true)][string]$TargetRoot)
    $artifacts = [System.Collections.Generic.List[object]]::new()
    $buildFinished = [System.Collections.Generic.List[object]]::new()
    $knownReasons = @('compiler-artifact', 'compiler-message', 'build-script-executed', 'build-finished', 'future-incompat-report')
    $stream = [IO.File]::Open($StdoutPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true), $true)
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($line.Length -eq 0 -or $line.Length -gt 8388608) { throw 'D32_BOUNDED_DIAGNOSTIC_CARGO_JSON_UNVERIFIED: stdout contains an empty or overlarge JSON record' }
            $parsedDoc = [System.Text.Json.JsonDocument]::Parse($line)
            try {
                if (Test-D32BoundedDiagnosticJsonDuplicates -Element $parsedDoc.RootElement) { throw 'D32_BOUNDED_DIAGNOSTIC_CARGO_JSON_UNVERIFIED: Cargo JSON contains duplicate fields' }
            }
            finally { $parsedDoc.Dispose() }
            $item = ConvertFrom-Json -InputObject $line -Depth 60 -ErrorAction Stop
            if ($item.reason -isnot [string] -or $knownReasons -cnotcontains [string]$item.reason) { throw 'D32_BOUNDED_DIAGNOSTIC_CARGO_JSON_UNVERIFIED: stdout contains an unknown Cargo JSON record' }
            if ([string]$item.reason -ceq 'compiler-artifact') {
                if ($null -eq $item.target -or $item.target.name -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$item.target.name) -or
                    $item.target.kind -isnot [Array] -or $item.target.kind.Count -eq 0 -or $item.target.src_path -isnot [string] -or
                    $null -eq $item.profile -or $item.profile.test -isnot [bool] -or
                    ($null -ne $item.executable -and $item.executable -isnot [string]) -or $item.package_id -isnot [string]) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_CARGO_JSON_UNVERIFIED: compiler-artifact target record is missing required source/profile fields'
                }
                $executable = if ($null -eq $item.executable) { $null } else { [IO.Path]::GetFullPath([string]$item.executable) }
                if ($null -ne $executable -and -not (Test-D32BoundedCompilerDiagnosticWithin -Child $executable -Parent $TargetRoot)) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_CARGO_JSON_UNVERIFIED: executable artifact escaped the normal Vita target directory'
                }
                $artifacts.Add([PSCustomObject]@{
                    package_id = [string]$item.package_id
                    target_name = [string]$item.target.name
                    target_kind = @($item.target.kind | ForEach-Object { [string]$_ })
                    source_path = [IO.Path]::GetFullPath([string]$item.target.src_path)
                    profile_test = [bool]$item.profile.test
                    executable = $executable
                })
            }
            elseif ([string]$item.reason -ceq 'build-finished') {
                if ($item.success -isnot [bool]) { throw 'D32_BOUNDED_DIAGNOSTIC_CARGO_JSON_UNVERIFIED: build-finished record has no Boolean success field' }
                $buildFinished.Add([PSCustomObject]@{ success = [bool]$item.success })
            }
        }
    }
    finally { $reader.Dispose(); $stream.Dispose() }
    if ($buildFinished.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_CARGO_JSON_UNVERIFIED: exactly one Cargo build-finished record is required' }
    return [PSCustomObject]@{ artifacts = @($artifacts.ToArray()); build_finished = $buildFinished[0] }
}

function Get-D32BoundedDiagnosticRustcArgValue {
    param([Parameter(Mandatory = $true)][string[]]$Argv, [Parameter(Mandatory = $true)][string]$Name)
    $values = [System.Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $Argv.Count; $index++) {
        if ([string]$Argv[$index] -ceq $Name) {
            if (($index + 1) -ge $Argv.Count -or [String]::IsNullOrWhiteSpace([string]$Argv[$index + 1])) { throw 'D32_BOUNDED_DIAGNOSTIC_RUSTC_UNVERIFIED: rustc flag has no exact value' }
            $values.Add([string]$Argv[$index + 1])
        }
        elseif ([string]$Argv[$index].StartsWith($Name + '=', [StringComparison]::Ordinal)) {
            $values.Add([string]$Argv[$index].Substring($Name.Length + 1))
        }
    }
    if ($values.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_RUSTC_UNVERIFIED: rustc command does not have exactly one required flag value' }
    return $values[0]
}

function Assert-D32BoundedDiagnosticRustcArtifactCrossBinding {
    param([Parameter(Mandatory = $true)][object[]]$RustcRecords, [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][object]$Trace, [Parameter(Mandatory = $true)][string]$Repository)
    $testArtifacts = @($Artifacts | Where-Object { $_.profile_test -and $null -ne $_.executable })
    if ($testArtifacts.Count -eq 0) { throw 'D32_BOUNDED_DIAGNOSTIC_RUSTC_UNVERIFIED: Cargo JSON exposed no executable test targets to cross-bind' }
    $matchesByArtifact = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $testCommands = [System.Collections.Generic.List[object]]::new()
    foreach ($rustc in $RustcRecords) {
        if ($rustc.Argv -isnot [Array] -or $rustc.Argv.Count -lt 2 -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$rustc.Argv[0]), [IO.Path]::GetFullPath([string]$rustc.ImagePath))) {
            throw 'D32_BOUNDED_DIAGNOSTIC_RUSTC_UNVERIFIED: actual rustc argv[0] does not bind its CREATE image path'
        }
        $testFlagCount = @($rustc.Argv | Where-Object { [string]$_ -ceq '--test' }).Count
        if ($testFlagCount -gt 1) { throw 'D32_BOUNDED_DIAGNOSTIC_RUSTC_UNVERIFIED: duplicated --test flag is ambiguous' }
        if ($testFlagCount -eq 0) { continue }
        $crateName = Get-D32BoundedDiagnosticRustcArgValue -Argv $rustc.Argv -Name '--crate-name'
        $outDirectory = [IO.Path]::GetFullPath((Get-D32BoundedDiagnosticRustcArgValue -Argv $rustc.Argv -Name '--out-dir'))
        $sources = @($rustc.Argv | Where-Object { [string]$_ -match '(?i)\.rs$' -and [IO.Path]::IsPathRooted([string]$_) })
        if ($sources.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_RUSTC_UNVERIFIED: actual --test rustc argv does not identify exactly one absolute Rust source' }
        $sourcePath = [IO.Path]::GetFullPath([string]$sources[0])
        if (-not (Test-D32BoundedCompilerDiagnosticWithin -Child $sourcePath -Parent $Repository)) { throw 'D32_BOUNDED_DIAGNOSTIC_RUSTC_UNVERIFIED: --test source is outside the exact candidate repository' }
        $crateCanonical = $crateName.Replace('-', '_')
        $matches = @($testArtifacts | Where-Object {
            [string]$_.target_name.Replace('-', '_') -ceq $crateCanonical -and
            [StringComparer]::OrdinalIgnoreCase.Equals([string]$_.source_path, $sourcePath) -and
            [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$_.executable), $outDirectory)
        })
        if ($matches.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_RUSTC_UNVERIFIED: actual PID/creation-bound --test argv does not map uniquely to one Cargo JSON target record' }
        $artifactKey = [string]$matches[0].package_id + "`0" + [string]$matches[0].target_name + "`0" + [string]$matches[0].source_path + "`0" + [string]$matches[0].executable
        if ($matchesByArtifact.ContainsKey($artifactKey)) { throw 'D32_BOUNDED_DIAGNOSTIC_RUSTC_UNVERIFIED: two rustc processes claim one Cargo JSON test target' }
        $matchesByArtifact.Add($artifactKey, $rustc)
        $testCommands.Add([PSCustomObject]@{
            process_id = [uint32]$rustc.ProcessId
            creation_filetime = [Int64]$rustc.CreationFileTime
            parent_process_id = [uint32]$rustc.ParentProcessId
            parent_creation_filetime = [Int64]$rustc.ParentCreationFileTime
            image_path = [string]$rustc.ImagePath
            argv = @($rustc.Argv)
            cargo_target = [PSCustomObject]@{ package_id = [string]$matches[0].package_id; name = [string]$matches[0].target_name; kind = @($matches[0].target_kind); source_path = [string]$matches[0].source_path; executable = [string]$matches[0].executable }
        })
    }
    if ($matchesByArtifact.Count -ne $testArtifacts.Count) { throw 'D32_BOUNDED_DIAGNOSTIC_RUSTC_UNVERIFIED: not every Cargo JSON test target maps to one actual rustc CREATE argv' }
    $createdImages = @($Trace.Processes | ForEach-Object { [string]$_.ImagePath })
    $testExecutablePaths = @($testArtifacts | ForEach-Object { [string]$_.executable })
    if (-not (Test-D32BoundedCompilerDiagnosticTestBinaryNotStarted -CreatedProcessPaths $createdImages -ExecutableArtifactPaths $testExecutablePaths -TargetRoot (Join-Path $Repository 'vita-agent/target'))) {
        throw 'D32_BOUNDED_DIAGNOSTIC_TEST_EXECUTION_BLOCKED: a Cargo JSON test executable appeared in the native CREATE process trace'
    }
    return [PSCustomObject]@{ test_target_count = [Int64]$testArtifacts.Count; actual_rustc_test_commands = @($testCommands.ToArray()); test_executable_launch_count = 0 }
}

function New-D32BoundedDiagnosticResult {
    param([string]$Status, [string]$RunId, [string]$StartedAtUtc, [string]$CompletedAtUtc, [string]$PrimaryError,
        [string[]]$SecondaryErrors, [object]$Capacity, [object]$Command, [object]$ProcessIdentity,
        [object]$Trace, [object]$Cleanup, [object]$Sampling, [object]$CargoArtifacts, [object]$RustcCrossBinding,
        [object]$SourceClosure, [object]$Capture, [object]$NativeCounters, [object]$GitState)
    Assert-D32BoundedCompilerDiagnosticStatus -Status $Status | Out-Null
    if ($null -ne $SourceClosure -and
        ([string]$SourceClosure.CurrentCandidateSha -cne $CandidateSha -or
         [string]$SourceClosure.HistoricalOriginCandidateSha -cne $script:D32BoundedDiagnosticHistoricalOriginCandidateSha -or
         [string]$SourceClosure.CurrentCandidateSha -ceq [string]$SourceClosure.HistoricalOriginCandidateSha)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: diagnostic result source-origin closure is not cross-bound to this current candidate and the immutable historical origin'
    }
    return [ordered]@{
        schema_version = 3
        record_type = $script:D32BoundedCompilerDiagnosticResultType
        registry_archive_policy = $script:D32BoundedDiagnosticRegistryArchivePolicy
        gate_authority = 'NONE'
        phase1_allowed = $false
        aggregate_allowed = $false
        status = $Status
        candidate_sha = $CandidateSha
        source_repo = [IO.Path]::GetFullPath($Repository)
        run_id = $RunId
        started_at_utc = $StartedAtUtc
        completed_at_utc = $CompletedAtUtc
        elapsed_stopwatch_ticks = if ($script:D32BoundedLaunchStart -eq 0) { 0L } else { [Diagnostics.Stopwatch]::GetTimestamp() - $script:D32BoundedLaunchStart }
        toolchain_profile = [ordered]@{ path = $ToolchainProfilePath; sha256 = $ExpectedToolchainProfileSha256 }
        module_authority = [ordered]@{ path = $PowerShellModuleAuthorityPath; sha256 = $ExpectedPowerShellModuleAuthoritySha256 }
        diagnostic_authority = [ordered]@{ path = $DiagnosticAuthorityPath; sha256 = $ExpectedDiagnosticAuthoritySha256 }
        command = $Command
        git_state = $GitState
        dependency_origin = $SourceClosure
        fixture_build_capacity = $Capacity
        process_identity = $ProcessIdentity
        raw_v2_trace = $Trace
        cleanup = $Cleanup
        sampling = $Sampling
        native_measurement_counters = $NativeCounters
        cargo_artifacts = $CargoArtifacts
        rustc_artifact_cross_binding = $RustcCrossBinding
        raw_capture = $Capture
        primary_error = $PrimaryError
        secondary_errors = @($SecondaryErrors)
    }
}

function New-D32BoundedDiagnosticOwnedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedParent,
        [Parameter(Mandatory = $true)][string]$ExpectedParentVolumeSerialHex,
        [Parameter(Mandatory = $true)][string]$ExpectedParentFileIdHex,
        [Parameter(Mandatory = $true)][ValidateSet('OUTPUT_ROOT', 'TEMP_ROOT')][string]$Role,
        [Parameter(Mandatory = $true)][object]$Authority
    )
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -cne $Path -or [IO.Path]::GetDirectoryName($full) -cne $ExpectedParent -or
        (Test-Path -LiteralPath $full)) {
        throw "D32_BOUNDED_DIAGNOSTIC_OUTPUT_BLOCKED: $Role path is not a new canonical direct child of its caller-pinned parent"
    }
    $parent = Assert-D32BoundedDiagnosticDirectoryReference -Path $ExpectedParent `
        -VolumeSerialHex $ExpectedParentVolumeSerialHex -FileIdHex $ExpectedParentFileIdHex
    New-Item -ItemType Directory -LiteralPath $full -ErrorAction Stop | Out-Null
    $identity = Get-D32ProfileDirectoryIdentity -Path $full
    if (($identity.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
        [IO.Path]::GetFullPath([string]$identity.Path) -cne $full -or
        [IO.Path]::GetFullPath([string]$parent.Path) -cne $ExpectedParent) {
        throw "D32_BOUNDED_DIAGNOSTIC_OUTPUT_BLOCKED: created $Role identity is noncanonical or redirected"
    }
    $ownerPath = Join-Path $full 'D32-BOUNDED-COMPILER-DIAGNOSTIC-OWNER.json'
    $owner = [ordered]@{
        schema_version = 1
        record_type = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_OWNER_V1'
        gate_authority = 'NONE'
        role = $Role
        candidate_sha = $CandidateSha
        source_repo = [IO.Path]::GetFullPath($Repository)
        run_id = [string]$Authority.output.run_id
        path = $full
        volume_serial_hex = [string]$identity.VolumeSerialHex
        file_id_hex = [string]$identity.FileIdHex
        parent_path = $ExpectedParent
        parent_volume_serial_hex = $ExpectedParentVolumeSerialHex
        parent_file_id_hex = $ExpectedParentFileIdHex
        diagnostic_authority = [ordered]@{ path = $DiagnosticAuthorityPath; sha256 = $ExpectedDiagnosticAuthoritySha256 }
        runner_process_id = [int]$PID
        created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $ownerSnapshot = Write-D32BoundedDiagnosticCreateNewJson -Path $ownerPath -Document $owner
    return [PSCustomObject]@{
        Path = $full
        Identity = $identity
        OwnerPath = $ownerPath
        OwnerReference = New-D32BoundedDiagnosticReferenceFromSnapshot -Path $ownerPath
        OwnerSha256 = [string]$ownerSnapshot.Sha256
    }
}

function Remove-D32BoundedDiagnosticOwnedTempRoot {
    param([Parameter(Mandatory = $true)][object]$OwnedTempRoot, [Parameter(Mandatory = $true)][string]$RunId)
    $path = [IO.Path]::GetFullPath([string]$OwnedTempRoot.Path)
    $ownerPath = [IO.Path]::GetFullPath([string]$OwnedTempRoot.OwnerPath)
    if ([IO.Path]::GetDirectoryName($ownerPath) -cne $path -or
        [IO.Path]::GetFileName($ownerPath) -cne 'D32-BOUNDED-COMPILER-DIAGNOSTIC-OWNER.json') {
        throw 'D32_BOUNDED_DIAGNOSTIC_TEMP_CLEANUP_BLOCKED: owner path is not the exact direct child of the diagnostic TempRoot'
    }
    $owner = Read-D32BoundedDiagnosticJson -Path $ownerPath -MaximumBytes 1048576 -ExpectedReference $OwnedTempRoot.OwnerReference
    if ([string]$owner.record_type -cne 'D32_BOUNDED_COMPILER_DIAGNOSTIC_OWNER_V1' -or
        [string]$owner.role -cne 'TEMP_ROOT' -or [string]$owner.run_id -cne $RunId -or
        [string]$owner.path -cne $path -or
        [string]$owner.volume_serial_hex -cne [string]$OwnedTempRoot.Identity.VolumeSerialHex -or
        [string]$owner.file_id_hex -cne [string]$OwnedTempRoot.Identity.FileIdHex) {
        throw 'D32_BOUNDED_DIAGNOSTIC_TEMP_CLEANUP_BLOCKED: TempRoot owner record or directory identity changed'
    }
    $null = Assert-D32BoundedDiagnosticDirectoryReference -Path $path `
        -VolumeSerialHex ([string]$OwnedTempRoot.Identity.VolumeSerialHex) -FileIdHex ([string]$OwnedTempRoot.Identity.FileIdHex)
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($path)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $attributes = [IO.File]::GetAttributes($item)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or ($attributes -band [IO.FileAttributes]::Device) -ne 0) {
                throw 'D32_BOUNDED_DIAGNOSTIC_TEMP_CLEANUP_BLOCKED: refusing cleanup through a reparse or special entry'
            }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { $pending.Push($item) }
        }
    }
    [IO.Directory]::Delete($path, $true)
    return -not (Test-Path -LiteralPath $path)
}

function New-D32BoundedDiagnosticImageGrant {
    param(
        [AllowNull()][object]$Reference,
        [Parameter(Mandatory = $true)][ValidateSet('VCTIP', 'PROTOC')][string]$Kind,
        [Parameter(Mandatory = $true)][object]$Profile,
        [Parameter(Mandatory = $true)][string]$CargoHome,
        [AllowNull()][object]$SourceClosure
    )
    if ($null -eq $Reference) { return $null }
    $null = Assert-D32BoundedDiagnosticFileReference -Reference $Reference -MustBeWithin $null -MustNotBeWithin $Repository `
        -ReferenceField "toolchain_profile.image_grants.$Kind" -Caller 'New-D32BoundedDiagnosticImageGrant'
    $current = Get-D32ProfileFileSnapshot -Path ([string]$Reference.path)
    if ([Int64]$current.Bytes -ne [Int64]$Reference.bytes -or [string]$current.Sha256 -cne [string]$Reference.sha256 -or
        [string]$current.VolumeSerialHex -cne [string]$Reference.volume_serial_hex -or
        [string]$current.FileIdHex -cne [string]$Reference.file_id_hex) {
        throw "D32_BOUNDED_DIAGNOSTIC_IMAGE_BLOCKED: $Kind image changed from its independent exact pin"
    }
    $image = [PSCustomObject]@{
        Path = [string]$current.Path; Bytes = [Int64]$current.Bytes; Sha256 = [string]$current.Sha256
        VolumeSerialHex = [string]$current.VolumeSerialHex; FileIdHex = [string]$current.FileIdHex
    }
    if ($Kind -ceq 'VCTIP') {
        $profileImage = Get-D32ProfileExactVctipImageRecord -ValidatedProfile $Profile
        foreach ($name in @('Path', 'Bytes', 'Sha256', 'VolumeSerialHex', 'FileIdHex')) {
            if ([string]$image.$name -cne [string]$profileImage.$name) {
                throw 'D32_BOUNDED_DIAGNOSTIC_IMAGE_BLOCKED: VCTIP authority is not the exact independently pinned Profile V2 image'
            }
        }
        return $image
    }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFileName($image.Path), 'protoc.exe') -or
        -not (Test-D32BoundedCompilerDiagnosticWithin -Child $image.Path -Parent $CargoHome) -or
        -not (Test-D32ProfilePinnedVendoredProtocContentIdentity -Bytes $image.Bytes -Sha256 $image.Sha256)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_IMAGE_BLOCKED: protoc is not the exact pinned vendored image below this diagnostic CargoHome'
    }
    $sourceRoots = [Collections.Generic.List[string]]::new()
    foreach ($package in @($SourceClosure.RegistryContentProof.packages)) { $sourceRoots.Add([string]$package.source_root) }
    foreach ($tuple in @($SourceClosure.GitContentProof.sources)) { $sourceRoots.Add([string]$tuple.checkout_path) }
    $matches = @($sourceRoots | Where-Object { Test-D32BoundedCompilerDiagnosticWithin -Child $image.Path -Parent $_ })
    if ($matches.Count -ne 1) {
        throw 'D32_BOUNDED_DIAGNOSTIC_IMAGE_BLOCKED: new per-run protoc pin is not inside exactly one lock-derived and content-verified dependency source tree'
    }
    return $image
}

function Get-D32BoundedDiagnosticGitCommandEvidence {
    param([Parameter(Mandatory = $true)][object]$Result, [Parameter(Mandatory = $true)][string[]]$Arguments)
    if (-not (Test-D32BoundedCompilerDiagnosticFixedGitQuery -Arguments $Arguments) -or
        [int]$Result.ExitCode -ne 0 -or $null -eq $Result.Attempt) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GIT_BLOCKED: caller-pinned Git metadata query failed or lacks exact bounded query evidence'
    }
    $stdoutBytes = [Text.UTF8Encoding]::new($false).GetBytes([string]$Result.StdOut)
    $stderrBytes = [Text.UTF8Encoding]::new($false).GetBytes([string]$Result.StdErr)
    $trace = $Result.Attempt.process_trace
    $cleanup = $Result.Attempt.native_cleanup
    if ($null -eq $trace -or [string]$trace.record_type -cne 'D32_DEBUG_JOB_PROCESS_TRACE_V2' -or
        [string]$trace.state -cne 'COMPLETED' -or $null -eq $cleanup -or -not [bool]$cleanup.cleanup_succeeded -or
        -not [bool]$cleanup.job_active_process_count_verified -or [uint32]$cleanup.job_active_process_count -ne 0) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GIT_BLOCKED: Git metadata query did not complete its existing V2 process/Job cleanup proof'
    }
    return [PSCustomObject][ordered]@{
        argv = @($Arguments)
        timeout_ms = [Int64]$script:D32BoundedCompilerDiagnosticGitQueryTimeoutMilliseconds
        exit_code = [int]$Result.ExitCode
        stdout_bytes = [Int64]$stdoutBytes.Length
        stdout_sha256 = Get-D32BoundedDiagnosticSha256 -Bytes $stdoutBytes
        stderr_bytes = [Int64]$stderrBytes.Length
        stderr_sha256 = Get-D32BoundedDiagnosticSha256 -Bytes $stderrBytes
        process_trace_state = [string]$trace.state
        process_id = if (@($trace.processes).Count -gt 0) { [uint32]$trace.processes[0].process_id } else { $null }
        cleanup_verified = [bool]$cleanup.cleanup_succeeded
    }
}

function Invoke-D32BoundedDiagnosticGitState {
    param([Parameter(Mandatory = $true)][object]$Authority)
    $gitDirectory = Assert-D32RepositoryGitConfig -Root $Repository
    $locks = Open-D32GitMetadataLocks -Root $Repository -GitDirectory $gitDirectory.GitDirectory
    $commands = [Collections.Generic.List[object]]::new()
    try {
        $headArgs = [string[]]@('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}')
        $statusArgs = [string[]]@('status', '--porcelain=v1', '--untracked-files=all')
        $indexArgs = [string[]]@('ls-files', '-v', '-z')

        $headBeforeResult = Get-D32GitOutput -Root $Repository -Arguments $headArgs -MetadataLocks $locks -CaptureResult -BoundedCompilerDiagnosticQuery
        $commands.Add((Get-D32BoundedDiagnosticGitCommandEvidence -Result $headBeforeResult -Arguments $headArgs))
        $headBefore = ([string]$headBeforeResult.StdOut).Trim()
        if ($headBefore -cnotmatch '^[0-9a-f]{40}$' -or $headBefore -cne $CandidateSha) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_BLOCKED: initial HEAD differs from the caller-pinned candidate SHA' }

        $statusBeforeResult = Get-D32GitOutput -Root $Repository -Arguments $statusArgs -MetadataLocks $locks -CaptureResult -BoundedCompilerDiagnosticQuery
        $commands.Add((Get-D32BoundedDiagnosticGitCommandEvidence -Result $statusBeforeResult -Arguments $statusArgs))
        Assert-D32CleanGitStatus -Status ([string]$statusBeforeResult.StdOut) -Root $Repository

        $indexResult = Get-D32GitOutput -Root $Repository -Arguments $indexArgs -MetadataLocks $locks -CaptureResult -PreserveOutput -BoundedCompilerDiagnosticQuery
        $commands.Add((Get-D32BoundedDiagnosticGitCommandEvidence -Result $indexResult -Arguments $indexArgs))
        Assert-D32CleanGitIndexFlags -Output ([string]$indexResult.StdOut)

        return [PSCustomObject]@{
            Repository = $Repository
            CandidateSha = $CandidateSha
            MetadataLocks = $locks
            Commands = $commands
            HeadBefore = $headBefore
            StatusBeforeClean = $true
            IndexFlagsClean = $true
            PreCargoComplete = $true
        }
    }
    catch {
        if ($null -ne $locks) { Close-D32GitMetadataLocks -Locks $locks }
        throw
    }
}

function Complete-D32BoundedDiagnosticGitState {
    param([Parameter(Mandatory = $true)][object]$GitState)
    try {
        $headArgs = [string[]]@('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}')
        $statusArgs = [string[]]@('status', '--porcelain=v1', '--untracked-files=all')
        $headAfterResult = Get-D32GitOutput -Root $Repository -Arguments $headArgs -MetadataLocks $GitState.MetadataLocks -CaptureResult -BoundedCompilerDiagnosticQuery
        $GitState.Commands.Add((Get-D32BoundedDiagnosticGitCommandEvidence -Result $headAfterResult -Arguments $headArgs))
        $headAfter = ([string]$headAfterResult.StdOut).Trim()
        if ($headAfter -cne [string]$GitState.HeadBefore -or $headAfter -cne $CandidateSha) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_BLOCKED: HEAD changed across the one-shot diagnostic' }

        $statusAfterResult = Get-D32GitOutput -Root $Repository -Arguments $statusArgs -MetadataLocks $GitState.MetadataLocks -CaptureResult -BoundedCompilerDiagnosticQuery
        $GitState.Commands.Add((Get-D32BoundedDiagnosticGitCommandEvidence -Result $statusAfterResult -Arguments $statusArgs))
        Assert-D32CleanGitStatus -Status ([string]$statusAfterResult.StdOut) -Root $Repository
        Assert-D32GitMetadataLocksCurrent -Locks $GitState.MetadataLocks -Root $Repository
        $GitState | Add-Member -NotePropertyName HeadAfter -NotePropertyValue $headAfter -Force
        $GitState | Add-Member -NotePropertyName StatusAfterClean -NotePropertyValue $true -Force
        $GitState | Add-Member -NotePropertyName Complete -NotePropertyValue ($GitState.Commands.Count -eq 5) -Force
        if (-not [bool]$GitState.Complete) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_BLOCKED: exact five-query diagnostic metadata sequence is incomplete' }
    }
    finally {
        if ($null -ne $GitState.MetadataLocks) {
            Close-D32GitMetadataLocks -Locks $GitState.MetadataLocks
            $GitState | Add-Member -NotePropertyName MetadataLocks -NotePropertyValue $null -Force
        }
    }
}

function New-D32BoundedDiagnosticRawCaptureReference {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][bool]$Complete)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $snapshot = Get-D32BoundArtifactWithFileId -Path $Path
    return [PSCustomObject][ordered]@{
        path = [string]$snapshot.path
        bytes = [Int64]$snapshot.bytes
        sha256 = [string]$snapshot.sha256
        volume_serial_hex = [string]$snapshot.volume_serial_hex
        file_id_hex = [string]$snapshot.file_id_hex
        status = if ($Complete) { 'CAPTURED' } else { 'INCOMPLETE' }
    }
}

function Get-D32BoundedDiagnosticSourceProofProfile {
    param([Parameter(Mandatory = $true)][object]$Authority, [Parameter(Mandatory = $true)][string]$Repo,
        [Parameter(Mandatory = $true)][Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds)
    $profileReference = $Authority.toolchain_profile
    $null = Assert-D32BoundedDiagnosticFileReference -Reference $profileReference -MustBeWithin $null -MustNotBeWithin $Repo `
        -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -ReferenceField 'authority.toolchain_profile' -Caller 'Get-D32BoundedDiagnosticSourceProofProfile'
    if ([Int64]$profileReference.bytes -le 0 -or [Int64]$profileReference.bytes -gt 4194304) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: caller-pinned Profile V2 exceeds its fixed 4 MiB input bound'
    }
    $profileDocument = Read-D32BoundedDiagnosticJson -Path ([string]$profileReference.path) -MaximumBytes 4194304 -ExpectedReference $profileReference `
        -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    $topFields = @('schema_version', 'profile_type', 'target_triple', 'system_root', 'powershell_root', 'powershell', 'rust_toolchain_root',
        'toolchain', 'rust_toolchain_bin_images', 'native_roots', 'native', 'windows_child_images', 'fetch_manifests', 'fetch_git', 'env_policy', 'cargo_policy')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $profileDocument $topFields) -or
        [int64]$profileDocument.schema_version -ne 2 -or [string]$profileDocument.profile_type -cne 'D32_BUILD_TOOLCHAIN_PROFILE_V2' -or
        $profileDocument.fetch_manifests -isnot [Array] -or $profileDocument.fetch_manifests.Count -ne 3 -or
        $null -ne $profileDocument.fetch_git) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: caller-pinned Profile V2 does not contain the exact three current lock bindings or has fetch_git enabled'
    }
    $lockInputs = @(Get-D32BuildToolchainLockInputs -Repository $Repo -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -DeadlineTicks (Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks))
    Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'profile.lock_bindings' -Progress ("locks={0}" -f $lockInputs.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED'
    if ($lockInputs.Count -ne 3) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: current manifest/lock input set is not the exact three-file D32 profile inventory' }
    for ($index = 0; $index -lt $lockInputs.Count; $index++) {
        $record = $profileDocument.fetch_manifests[$index]
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $record @('manifest_path', 'lock_sha256')) -or
            [string]$record.manifest_path -cne [string]$lockInputs[$index].ManifestPath -or
            [string]$record.lock_sha256 -cne [string]$lockInputs[$index].LockSha256) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: Profile V2 does not bind the exact currently opened manifest/lock tuple'
        }
    }
    $after = Assert-D32BoundedDiagnosticFileReference -Reference $profileReference -MustBeWithin $null -MustNotBeWithin $Repo `
        -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -ReferenceField 'authority.toolchain_profile' -Caller 'Get-D32BoundedDiagnosticSourceProofProfile'
    if ([Int64]$after.Bytes -ne [Int64]$profileReference.bytes -or [string]$after.Sha256 -cne [string]$profileReference.sha256 -or
        [string]$after.VolumeSerialHex -cne [string]$profileReference.volume_serial_hex -or [string]$after.FileIdHex -cne [string]$profileReference.file_id_hex) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: Profile V2 changed while its current lock bindings were read'
    }
    return [PSCustomObject]@{
        Profile = $profileDocument
        ProfilePath = [string]$profileReference.path
        Digest = [string]$profileReference.sha256
        Identity = [PSCustomObject]@{
            Bytes = [Int64]$profileReference.bytes
            VolumeSerialHex = [string]$profileReference.volume_serial_hex
            FileIdHex = [string]$profileReference.file_id_hex
        }
        LockInputs = $lockInputs
    }
}

function Invoke-D32BoundedDiagnosticSourceProofRun {
    $proofTimer = $script:D32BoundedDiagnosticSourceProofWallTimer
    if ($null -eq $proofTimer -or -not $proofTimer.IsRunning) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: launch-bound aggregate source-proof timer is absent or stopped' }
    $workDeadlineMilliseconds = Get-D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds
    $resultValidationDeadlineMilliseconds = [Int64]$workDeadlineMilliseconds
    $blockedFallbackValidationDeadlineMilliseconds = [Int64]($script:D32BoundedDiagnosticSourceProofCombinedMilliseconds - 15000L)
    $script:D32BoundedDiagnosticSourceProofTimer = $proofTimer
    $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds = $workDeadlineMilliseconds
    $authority = $script:D32BoundedDiagnosticSourceProofBootstrapAuthority
    $output = $authority.output_candidate
    $startedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
    $status = 'BLOCKED'
    $primaryError = $null
    $profile = $null
    $sourceClosure = $null
    $persistAllowed = $false
    $sourcePinSummaries = @()
    $proofElapsedMilliseconds = 0L
    $completedAtUtc = $startedAtUtc
    try {
        Set-D32BoundedDiagnosticSourceProofProgress -Phase 'authority.output_preflight' -Progress 'candidate_parent_identity_and_create_new_absence'
        if (-not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.path) -or
            -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.parent_path) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$output.path), [string]$output.parent_path)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: create-new result path or parent is not canonical'
        }
        $null = Assert-D32BoundedDiagnosticDirectoryReference -Path ([string]$output.parent_path) `
            -VolumeSerialHex ([string]$output.parent_volume_serial_hex) -FileIdHex ([string]$output.parent_file_id_hex)
        if ([IO.File]::Exists([string]$output.path) -or [IO.Directory]::Exists([string]$output.path)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: caller-pinned proof-candidate output must be create-new and absent'
        }
        $persistAllowed = $true
        Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $proofTimer -Phase 'authority.strict_shape' -Progress 'begin' `
            -DeadlineMilliseconds $workDeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED'
        if (-not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $authority `
            -ExpectedCandidateSha $CandidateSha -ExpectedHistoricalOriginCandidateSha $HistoricalOriginCandidateSha `
            -Repository $Repository -EntryScriptPath $SourceProofEntryPath -RunnerPath $PSCommandPath `
            -ToolchainProfilePath $ToolchainProfilePath -ToolchainProfileSha256 $ExpectedToolchainProfileSha256 `
            -ProofTimer $proofTimer -DeadlineMilliseconds $workDeadlineMilliseconds)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: exact source-proof authority shape changed after module-free bootstrap'
        }
        Set-D32BoundedDiagnosticSourceProofProgress -Phase 'repository.identity' -Progress 'reopen_candidate_repository_identity'
        $repoIdentity = Get-D32ProfileDirectoryIdentity -Path $Repository
        if ([string]$repoIdentity.VolumeSerialHex -cne [string]$authority.repository_identity.volume_serial_hex -or
            [string]$repoIdentity.FileIdHex -cne [string]$authority.repository_identity.file_id_hex) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: opened current repository identity differs from the independent source-proof pin'
        }
        $sourcePinIndex = 0
        foreach ($pin in $authority.source_pins) {
            Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $proofTimer -Phase 'source_pins.current' -Progress ("pins={0}/{1}" -f $sourcePinIndex, $authority.source_pins.Count) -DeadlineMilliseconds $workDeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED'
            $pinSnapshot = Assert-D32BoundedDiagnosticFileReference -Reference $pin -MustBeWithin $Repository -MustNotBeWithin $null `
                -ProofTimer $proofTimer -DeadlineMilliseconds $workDeadlineMilliseconds -ReferenceField "authority.source_pins[$sourcePinIndex]" -Caller 'Invoke-D32BoundedDiagnosticSourceProofRun'
            if ([Int64]$pinSnapshot.Bytes -gt 16777216) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: source proof code input exceeds its fixed 16 MiB pin bound' }
            $sourcePinSummaries += [PSCustomObject]@{
                path = [string]$pin.path; bytes = [Int64]$pinSnapshot.Bytes; sha256 = [string]$pinSnapshot.Sha256
                volume_serial_hex = [string]$pinSnapshot.VolumeSerialHex; file_id_hex = [string]$pinSnapshot.FileIdHex
            }
            $sourcePinIndex++
        }

        $manifestIndex = 0
        foreach ($reference in $authority.dependency_origin.manifest_refs) {
            Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $proofTimer -Phase 'manifest_refs.current' -Progress ("references={0}/{1}" -f $manifestIndex, $authority.dependency_origin.manifest_refs.Count) -DeadlineMilliseconds $workDeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED'
            if ([Int64]$reference.bytes -gt [Int64]$authority.proof_budget.max_manifest_or_lock_file_bytes) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: current manifest or lock pin exceeds its finite content-read bound'
            }
            $null = Assert-D32BoundedDiagnosticFileReference -Reference $reference -MustBeWithin $Repository -MustNotBeWithin $null `
                -ProofTimer $proofTimer -DeadlineMilliseconds $workDeadlineMilliseconds -ReferenceField "authority.dependency_origin.manifest_refs[$manifestIndex]" `
                -Caller 'Invoke-D32BoundedDiagnosticSourceProofRun'
            $manifestIndex++
        }
        Set-D32BoundedDiagnosticSourceProofProgress -Phase 'current_profile_and_locks' -Progress 'open_profile_and_three_lock_bindings'
        $profile = Get-D32BoundedDiagnosticSourceProofProfile -Authority $authority -Repo $Repository -ProofTimer $proofTimer -DeadlineMilliseconds $workDeadlineMilliseconds
        Set-D32BoundedDiagnosticSourceProofProgress -Phase 'inv7_origin_and_source_graph' -Progress 'begin_current_historical_source_content_proof'
        $sourceClosure = Assert-D32BoundedDiagnosticInv7Origin -Origin $authority.dependency_origin -Profile $profile `
            -Repo $Repository -CurrentCandidateSha $CandidateSha -HistoricalOriginCandidateSha $HistoricalOriginCandidateSha `
            -ProofTimer $proofTimer -DeadlineMilliseconds $workDeadlineMilliseconds -SourceProofOnly
        $proofElapsedMilliseconds = [Int64]$proofTimer.ElapsedMilliseconds
        Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $proofTimer -Phase 'proof.complete_before_persist_reserve' `
            -Progress 'all_registry_git_manifest_graph_content_closure_complete' -DeadlineMilliseconds $workDeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED'
        $status = 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY'
    }
    catch {
        $proofElapsedMilliseconds = [Int64]$proofTimer.ElapsedMilliseconds
        $lastPhase = [string]$script:D32BoundedDiagnosticSourceProofPhase
        $lastProgress = [string]$script:D32BoundedDiagnosticSourceProofProgress
        $primaryError = Protect-D32BoundedDiagnosticText -Text (([string]$_.Exception.Message) + "; phase=$lastPhase; progress=$lastProgress; elapsed_ms=$proofElapsedMilliseconds; work_deadline_ms=$workDeadlineMilliseconds")
    }
    finally {
        $completedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
        $proofElapsedMilliseconds = [Int64]$proofTimer.ElapsedMilliseconds
        try {
        if ($persistAllowed) {
            $entryPins = @($authority.source_pins | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals([string]$_.path, $SourceProofEntryPath) })
            if ($entryPins.Count -ne 1) {
                $status = 'BLOCKED'; $sourceClosure = $null
                $pinFailure = 'SOURCEPROOF_RESULT_BLOCKED: exact source-proof entry pin is absent or ambiguous while constructing the result'
                $primaryError = if ([String]::IsNullOrWhiteSpace([string]$primaryError)) { $pinFailure } else { Protect-D32BoundedDiagnosticText -Text ([string]$primaryError + '; ' + $pinFailure) }
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: exact source-proof entry pin is absent or ambiguous; refusing to fabricate a result pin digest'
            }
            $entrySha = [string]$entryPins[0].sha256
            $currentProfileLockBindings = if ($null -eq $profile) { $null } else {
                @($profile.LockInputs | ForEach-Object { [PSCustomObject]@{ manifest_path = $_.ManifestPath; lock_path = $_.LockPath; lock_bytes = [Int64]$_.LockBytes; lock_sha256 = [string]$_.LockSha256 } })
            }
            $shapeFailures = [System.Collections.Generic.List[string]]::new()
            $record = $null
            try {
                $record = New-D32BoundedDiagnosticSourceProofCandidateDocument `
                    -CandidateSha $CandidateSha -HistoricalOriginCandidateSha $HistoricalOriginCandidateSha -Repository $Repository `
                    -Status $status -ProofAuthorityPath $SourceProofAuthorityPath -ProofAuthoritySha256 $ExpectedSourceProofAuthoritySha256 `
                    -ProofEntryPath $SourceProofEntryPath -ProofEntrySha256 $entrySha `
                    -ProofStartedAtUtc $startedAtUtc -ProofCompletedAtUtc $completedAtUtc -ProofElapsedMilliseconds $proofElapsedMilliseconds `
                    -ProofBudget $authority.proof_budget -SourcePins @($sourcePinSummaries) `
                    -CurrentProfileLockBindings $currentProfileLockBindings -CurrentSourceClosure $sourceClosure -PrimaryError $primaryError
                if (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $record -FailureReasons $shapeFailures `
                    -ProofTimer $proofTimer -DeadlineMilliseconds $resultValidationDeadlineMilliseconds)) {
                    throw ('SOURCEPROOF_RESULT_SHAPE_REJECTED: ' + [string]::Join(',', [string[]]$shapeFailures.ToArray()))
                }
            }
            catch {
                $originalPrimaryError = $primaryError
                $shapeFailureText = if ($shapeFailures.Count -gt 0) { [string]::Join(',', [string[]]$shapeFailures.ToArray()) } else { Protect-D32BoundedDiagnosticText -Text ([string]$_.Exception.Message) }
                $fallbackPrimaryError = 'SOURCEPROOF_RESULT_SHAPE_REJECTED: ' + $shapeFailureText
                if (-not [String]::IsNullOrWhiteSpace($originalPrimaryError)) { $fallbackPrimaryError = [string]$originalPrimaryError + '; ' + $fallbackPrimaryError }
                $status = 'BLOCKED'
                $primaryError = Protect-D32BoundedDiagnosticText -Text $fallbackPrimaryError
                $record = New-D32BoundedDiagnosticSourceProofCandidateDocument `
                    -CandidateSha $CandidateSha -HistoricalOriginCandidateSha $HistoricalOriginCandidateSha -Repository $Repository `
                    -Status $status -ProofAuthorityPath $SourceProofAuthorityPath -ProofAuthoritySha256 $ExpectedSourceProofAuthoritySha256 `
                    -ProofEntryPath $SourceProofEntryPath -ProofEntrySha256 $entrySha `
                    -ProofStartedAtUtc $startedAtUtc -ProofCompletedAtUtc $completedAtUtc -ProofElapsedMilliseconds $proofElapsedMilliseconds `
                    -ProofBudget $authority.proof_budget -SourcePins @($sourcePinSummaries) `
                    -CurrentProfileLockBindings $null -CurrentSourceClosure $null -PrimaryError $primaryError
                $fallbackFailures = [System.Collections.Generic.List[string]]::new()
                if (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $record -FailureReasons $fallbackFailures `
                    -ProofTimer $proofTimer -DeadlineMilliseconds $blockedFallbackValidationDeadlineMilliseconds)) {
                    $fallbackFailureText = if ($fallbackFailures.Count -gt 0) { [string]::Join(',', [string[]]$fallbackFailures.ToArray()) } else { 'validator-rejected-without-specific-code' }
                    $record = $null
                    $primaryError = Protect-D32BoundedDiagnosticText -Text ($fallbackPrimaryError + '; blocked_result_self_validation_failed=' + $fallbackFailureText)
                    throw ('D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: blocked result candidate failed self-validation; primary_error={0}; phase={1}; progress={2}; elapsed_ms={3}; combined_deadline_ms={4}' -f `
                        [string]$primaryError, [string]$script:D32BoundedDiagnosticSourceProofPhase, [string]$script:D32BoundedDiagnosticSourceProofProgress,
                        [Int64]$proofTimer.ElapsedMilliseconds, [Int64]$script:D32BoundedDiagnosticSourceProofCombinedMilliseconds)
                }
            }
            if ($null -eq $record) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: no strict result candidate was retained for create-new persistence' }
            $null = Write-D32BoundedDiagnosticCreateNewJson -Path ([string]$output.path) -Document $record `
                -ProofTimer $proofTimer -DeadlineMilliseconds $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds
            Write-Output ([PSCustomObject]@{ record_type = [string]$record.record_type; status = [string]$record.status; path = [string]$output.path })
        }
        else {
            $preflightFailure = if ([String]::IsNullOrWhiteSpace([string]$primaryError)) { 'no primary failure was retained' } else { Protect-D32BoundedDiagnosticText -Text ([string]$primaryError) }
            throw ('D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: result persistence was not admitted; primary_error={0}; phase={1}; progress={2}; elapsed_ms={3}; combined_deadline_ms={4}; no_result_written=true' -f `
                $preflightFailure, [string]$script:D32BoundedDiagnosticSourceProofPhase, [string]$script:D32BoundedDiagnosticSourceProofProgress,
                [Int64]$proofTimer.ElapsedMilliseconds, [Int64]$script:D32BoundedDiagnosticSourceProofCombinedMilliseconds)
        }
        }
        catch {
            $secondaryFailure = Protect-D32BoundedDiagnosticText -Text ([string]$_.Exception.Message)
            $retainedPrimary = if ([String]::IsNullOrWhiteSpace([string]$primaryError)) { 'none-retained' } else { Protect-D32BoundedDiagnosticText -Text ([string]$primaryError) }
            $phaseAtFailure = [string]$script:D32BoundedDiagnosticSourceProofPhase
            $progressAtFailure = [string]$script:D32BoundedDiagnosticSourceProofProgress
            $elapsedAtFailure = [Int64]$proofTimer.ElapsedMilliseconds
            throw ('D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: finalization failed; primary_error={0}; finalization_error={1}; phase={2}; progress={3}; elapsed_ms={4}; combined_deadline_ms={5}; result_path_state=absent_or_partial_or_unconfirmed_no_retry_or_overwrite' -f `
                $retainedPrimary, $secondaryFailure, $phaseAtFailure, $progressAtFailure, $elapsedAtFailure,
                [Int64]$script:D32BoundedDiagnosticSourceProofCombinedMilliseconds)
        }
    }
}

function Invoke-D32BoundedCompilerDiagnosticRun {
    $script:D32BoundedLaunchStart = 0L
    $profile = $null
    $authority = $script:D32BoundedDiagnosticBootstrapAuthority
    $environment = $null
    $outputRoot = $null
    $tempRoot = $null
    $nativeProcess = $null
    $stdoutCapture = $null
    $stderrCapture = $null
    $stdoutDestination = $null
    $stderrDestination = $null
    $sampleWriter = $null
    $sampleStream = $null
    $outputBudget = $null
    $gitState = $null
    $capacity = $null
    $sourceClosure = $null
    $cargoArtifacts = $null
    $rustcCrossBinding = $null
    $traceDocument = $null
    $cleanupDocument = $null
    $cleanupEvidence = $null
    $samplingSummary = $null
    $nativeCounters = $null
    $processIdentity = $null
    $command = $null
    $rawCapture = $null
    $status = 'REFUSED'
    $primaryException = $null
    $secondaryErrors = [Collections.Generic.List[string]]::new()
    $cargoLaunchAttemptCount = 0
    $cargoStarted = $false
    $stopIssued = $false
    $stopReason = ''
    $stopDrainDeadlineTicks = 0L
    $samplingComplete = $false
    $samples = [Collections.Generic.List[object]]::new()
    $sampleSidecarBytes = 0L
    $traceNative = $null
    $rustcRecords = @()
    $stdoutPath = $null
    $stderrPath = $null
    $samplePath = $null
    $rootOwner = $null
    $tempOwner = $null
    $tempCleanupVerified = $false
    $createdAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
    $startedAtUtc = $createdAtUtc
    $completedAtUtc = $createdAtUtc
    $targetIdentityBefore = $null
    $targetIdentityAfter = $null
    $runId = [string]$authority.output.run_id
    try {
        $profile = Test-D32BuildToolchainProfileModuleFree -ProfilePath $ToolchainProfilePath `
            -ExpectedSha256 $ExpectedToolchainProfileSha256 -Repository $Repository `
            -EvidenceRoot ([string]$authority.output.parent_path) -ExpectedTargetTriple 'x86_64-pc-windows-msvc'
        if (-not [bool]$profile.IsValid) { throw "D32_BOUNDED_DIAGNOSTIC_PROFILE_BLOCKED: $($profile.Failure)" }
        if ([string]$authority.toolchain_profile.path -cne $profile.ProfilePath -or
            [string]$authority.toolchain_profile.sha256 -cne $profile.Digest -or
            [string]$authority.module_authority.path -cne $PowerShellModuleAuthorityPath -or
            [string]$authority.module_authority.sha256 -cne $ExpectedPowerShellModuleAuthoritySha256 -or
            [string]$authority.pinned_git.path -cne [IO.Path]::GetFullPath($PinnedGitPath) -or
            [string]$authority.pinned_git.sha256 -cne $PinnedGitSha256) {
            throw 'D32_BOUNDED_DIAGNOSTIC_AUTHORITY_BLOCKED: command-line profile/module/Git pins differ from the independent diagnostic authority'
        }
        $environment = New-D32BoundedDiagnosticChildEnvironment -Profile $profile -CargoHome ([string]$authority.cargo_home.path) -TempRoot ([string]$authority.output.temp_path)
        Assert-D32BoundedDiagnosticAuthorityDocument -Document $authority -Repo $Repository -ExpectedEnvironment $environment
        Assert-D32BoundedDiagnosticSourcePins -Document $authority -Repo $Repository | Out-Null

        $repoIdentity = Get-D32ProfileDirectoryIdentity -Path $Repository
        if ([string]$repoIdentity.VolumeSerialHex -cne [string]$authority.repository_identity.volume_serial_hex -or
            [string]$repoIdentity.FileIdHex -cne [string]$authority.repository_identity.file_id_hex) {
            throw 'D32_BOUNDED_DIAGNOSTIC_REPOSITORY_BLOCKED: current repository directory identity differs from its independent caller pin'
        }
        $targetIdentityBefore = Assert-D32BoundedDiagnosticDirectoryReference -Path ([string]$authority.target.path) `
            -VolumeSerialHex ([string]$authority.target.volume_serial_hex) -FileIdHex ([string]$authority.target.file_id_hex)
        $null = Assert-D32BoundedDiagnosticDirectoryReference -Path ([string]$authority.cargo_home.path) `
            -VolumeSerialHex ([string]$authority.cargo_home.volume_serial_hex) -FileIdHex ([string]$authority.cargo_home.file_id_hex)
        $null = Assert-D32BoundedDiagnosticDirectoryReference -Path ([string]$authority.output.parent_path) `
            -VolumeSerialHex ([string]$authority.output.parent_volume_serial_hex) -FileIdHex ([string]$authority.output.parent_file_id_hex)
        foreach ($pair in @(
            [PSCustomObject]@{ Path = [string]$authority.output.root_path; Name = 'output root' },
            [PSCustomObject]@{ Path = [string]$authority.output.temp_path; Name = 'TempRoot' }
        )) {
            if (Test-Path -LiteralPath $pair.Path) { throw "D32_BOUNDED_DIAGNOSTIC_OUTPUT_BLOCKED: caller-pinned $($pair.Name) already exists; diagnostic roots are create-new only" }
        }
        $cargoHomeStatus = Test-D32CargoHome -Path ([string]$authority.cargo_home.path) -Repository $Repository
        if ([string]$cargoHomeStatus.Path -cne [string]$authority.cargo_home.path) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: optional CargoHome canonical path changed' }

        $rootOwner = New-D32BoundedDiagnosticOwnedDirectory -Path ([string]$authority.output.root_path) `
            -ExpectedParent ([string]$authority.output.parent_path) `
            -ExpectedParentVolumeSerialHex ([string]$authority.output.parent_volume_serial_hex) `
            -ExpectedParentFileIdHex ([string]$authority.output.parent_file_id_hex) -Role 'OUTPUT_ROOT' -Authority $authority
        $tempOwner = New-D32BoundedDiagnosticOwnedDirectory -Path ([string]$authority.output.temp_path) `
            -ExpectedParent ([string]$authority.output.root_path) `
            -ExpectedParentVolumeSerialHex ([string]$rootOwner.Identity.VolumeSerialHex) `
            -ExpectedParentFileIdHex ([string]$rootOwner.Identity.FileIdHex) -Role 'TEMP_ROOT' -Authority $authority
        $stdoutPath = Join-Path $rootOwner.Path 'cargo.stdout.log'
        $stderrPath = Join-Path $rootOwner.Path 'cargo.stderr.log'
        $samplePath = Join-Path $rootOwner.Path 'resource-samples.ndjson'

        $null = Initialize-D32PowerShellModuleAuthority `
            -CallerProfilePath $ToolchainProfilePath -CallerExpectedProfileSha256 $ExpectedToolchainProfileSha256 `
            -CallerModuleAuthorityPath $PowerShellModuleAuthorityPath -CallerExpectedModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
            -CallerCandidateSha $CandidateSha -CallerRepository $Repository -CallerGitPath $PinnedGitPath `
            -CallerGitSha256 $PinnedGitSha256 -EntryScriptPath $PSCommandPath
        $script:ValidatedToolchainProfile = $profile
        $script:PinnedGit = Get-D32PinnedGit -Path $PinnedGitPath -ExpectedSha256 $PinnedGitSha256
        $script:ExpectedCandidateSha = $CandidateSha
        . (Join-Path $PSScriptRoot 'd32-fixture-prebuild.ps1') `
            -RepoRoot $Repository -ExpectedCandidateSha $CandidateSha `
            -ToolchainProfilePath $ToolchainProfilePath -ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256 `
            -PowerShellModuleAuthorityPath $PowerShellModuleAuthorityPath `
            -ExpectedPowerShellModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
            -PinnedGitPath $PinnedGitPath -PinnedGitSha256 $PinnedGitSha256 `
            -D32ModuleAuthorityEntryScriptPath $PSCommandPath -D32LauncherLibraryOnly

        $capacity = Get-D32BoundedDiagnosticCapacity -EvidenceParent $rootOwner.Path -TargetDirectory ([string]$authority.target.path)
        $script:D32BoundedLaunchStart = [Diagnostics.Stopwatch]::GetTimestamp()
        $startedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
        $gitState = Invoke-D32BoundedDiagnosticGitState -Authority $authority
        if ($gitState.Commands.Count -ne 3) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_BLOCKED: initial three-query HEAD/status/index sequence is incomplete' }

        $sourceClosure = Assert-D32BoundedDiagnosticInv7Origin -Origin $authority.dependency_origin -Profile $profile -Repo $Repository `
            -CurrentCandidateSha $CandidateSha -HistoricalOriginCandidateSha ([string]$authority.dependency_origin.historical_origin_candidate_sha)
        if (-not (Test-D32BoundedCompilerDiagnosticHistoricalReplay -SourceClosure $sourceClosure)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: old fetch or discovery evidence acquired unauthorized success semantics'
        }
        $protocImage = New-D32BoundedDiagnosticImageGrant -Reference $authority.image_grants.protoc -Kind 'PROTOC' `
            -Profile $profile -CargoHome ([string]$authority.cargo_home.path) -SourceClosure $sourceClosure
        $vctipImage = New-D32BoundedDiagnosticImageGrant -Reference $authority.image_grants.vctip -Kind 'VCTIP' `
            -Profile $profile -CargoHome ([string]$authority.cargo_home.path) -SourceClosure $sourceClosure

        $capacity = [PSCustomObject]@{ before_source_proof = $capacity; before_cargo = $null }
        $capacity.before_cargo = Get-D32BoundedDiagnosticCapacity -EvidenceParent $rootOwner.Path -TargetDirectory ([string]$authority.target.path)
        $elapsedBeforeCargo = [Int64]([Diagnostics.Stopwatch]::GetTimestamp() - $script:D32BoundedLaunchStart) * 1000L / [Diagnostics.Stopwatch]::Frequency
        $remainingLaunchMs = [Int64]$authority.resource_budget.owned_launch_timeout_ms - $elapsedBeforeCargo
        if (-not (Test-D32BoundedCompilerDiagnosticCanStart -RemainingMilliseconds $remainingLaunchMs -Budget $authority.resource_budget)) {
            $status = 'BUDGET_STOPPED'
            throw 'D32_BOUNDED_DIAGNOSTIC_BUDGET_STOPPED: less than one full Cargo ceiling plus reserved cleanup and persistence time remains before the sole Cargo launch'
        }

        $cargoArgs = [string[]]@(Get-D32BoundedCompilerDiagnosticFixedArgv)
        if (-not (Test-D32BoundedCompilerDiagnosticFixedArgv $cargoArgs)) { throw 'D32_BOUNDED_DIAGNOSTIC_ARGV_BLOCKED: fixed Cargo argv failed its exact self-check' }
        $profileCurrent = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $profile
        $cargoImage = Get-D32ProfileFileSnapshot -Path ([string]$profileCurrent.Profile.toolchain.cargo.path)
        $cargoInventory = @($profileCurrent.ExecutableInventory | Where-Object { Test-D32ProfilePathEqual -Left ([string]$_.Path) -Right ([string]$cargoImage.Path) })
        if ($cargoInventory.Count -ne 1 -or [Int64]$cargoInventory[0].Bytes -ne [Int64]$cargoImage.Bytes -or
            [string]$cargoInventory[0].Sha256 -cne [string]$cargoImage.Sha256 -or
            [string]$cargoInventory[0].VolumeSerialHex -cne [string]$cargoImage.VolumeSerialHex -or
            [string]$cargoInventory[0].FileIdHex -cne [string]$cargoImage.FileIdHex) {
            throw 'D32_BOUNDED_DIAGNOSTIC_CARGO_BLOCKED: direct Cargo image differs from its exact caller-pinned Profile V2 executable inventory'
        }
        $approvedImages = @($profileCurrent.ExecutableInventory) + @($profileCurrent.WindowsImageInventory)
        if ($null -ne $vctipImage) { $approvedImages += $vctipImage }
        if ($null -ne $protocImage) { $approvedImages += $protocImage }
        $approvedImagePins = [string[]]@($approvedImages | ForEach-Object { ConvertTo-D32DebugImagePinText -Image $_ })
        $cargoRootPin = ConvertTo-D32DebugImagePinText -Image ([PSCustomObject]@{
            Path = [string]$cargoImage.Path; Bytes = [Int64]$cargoImage.Bytes; Sha256 = [string]$cargoImage.Sha256
            VolumeSerialHex = [string]$cargoImage.VolumeSerialHex; FileIdHex = [string]$cargoImage.FileIdHex
        })
        $commandLine = ConvertTo-D32CommandLine (@([string]$cargoImage.Path) + @($cargoArgs))
        $childEnvironment = ConvertTo-D32EnvironmentBlock -Environment $environment
        $stdoutDestination = [IO.File]::Open($stdoutPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $stderrDestination = [IO.File]::Open($stderrPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $sampleStream = [IO.File]::Open($samplePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $sampleWriter = [IO.StreamWriter]::new($sampleStream, [Text.UTF8Encoding]::new($false))
        $outputBudget = [D32BoundedCompilerDiagnosticOutputBudgetV1]::new([Int64]$authority.resource_budget.raw_capture_limit_bytes)

        $cargoLaunchAttemptCount++
        $nativeProcess = Start-D32FixtureBoundedNativeProcess -FilePath ([string]$cargoImage.Path) `
            -CommandLine $commandLine -WorkingDirectory $Repository -EnvironmentBlock $childEnvironment `
            -NativeTestFailure $null -RequireDebugEvents $true
        $cargoStarted = $true
        $command = [ordered]@{
            executable = [string]$cargoImage.Path
            executable_bytes = [Int64]$cargoImage.Bytes
            executable_sha256 = [string]$cargoImage.Sha256
            executable_volume_serial_hex = [string]$cargoImage.VolumeSerialHex
            executable_file_id_hex = [string]$cargoImage.FileIdHex
            argv = @($cargoArgs)
            command_line = $commandLine
            working_directory = $Repository
            manifest_path = 'vita-agent/Cargo.toml'
            target_directory = [string]$authority.target.path
            launch_attempt_count = $cargoLaunchAttemptCount
            timeout_ms = [Int64]$authority.resource_budget.cargo_timeout_ms
            child_environment_sha256 = Get-D32BoundedDiagnosticEnvironmentSha256 -Environment $environment
            child_environment = $environment
        }
        $stdoutCapture = [D32BoundedCompilerDiagnosticPipeCaptureV1]::new($nativeProcess.OpenStdoutStream(), $stdoutDestination, $outputBudget, 'stdout')
        $stdoutDestination = $null
        $stderrCapture = [D32BoundedCompilerDiagnosticPipeCaptureV1]::new($nativeProcess.OpenStderrStream(), $stderrDestination, $outputBudget, 'stderr')
        $stderrDestination = $null
        $nativeProcess.ConfigureBoundedCompilerDiagnosticCapture($cargoRootPin, $approvedImagePins,
            [string[]]@((Join-Path $Repository 'vita-agent/target/debug')), [int]$authority.resource_budget.cargo_timeout_ms,
            ($null -ne $vctipImage), [string]$authority.cargo_home.path,
            $(if ($null -ne $protocImage) { ConvertTo-D32DebugImagePinText -Image $protocImage } else { $null }))

        $cargoStartTicks = [Diagnostics.Stopwatch]::GetTimestamp()
        $maximumCargoTicks = [Int64]([long]$authority.resource_budget.cargo_timeout_ms * [Diagnostics.Stopwatch]::Frequency / 1000L)
        $overallDeadlineTicks = $script:D32BoundedLaunchStart + [Int64]([long]$authority.resource_budget.owned_launch_timeout_ms * [Diagnostics.Stopwatch]::Frequency / 1000L)
        $cleanupReserveTicks = [Int64]([long]$authority.resource_budget.cleanup_reserve_ms * [Diagnostics.Stopwatch]::Frequency / 1000L)
        $persistReserveTicks = [Int64]([long]$authority.resource_budget.persist_reserve_ms * [Diagnostics.Stopwatch]::Frequency / 1000L)
        $cargoDeadlineTicks = [Math]::Min($cargoStartTicks + $maximumCargoTicks, $overallDeadlineTicks - $cleanupReserveTicks - $persistReserveTicks)
        $samplePeriodTicks = [Int64]([long]$authority.resource_budget.sample_period_ms * [Diagnostics.Stopwatch]::Frequency / 1000L)
        $nextSampleTicks = [Diagnostics.Stopwatch]::GetTimestamp()
        $lastSampleTicks = 0L
        $sampleFailure = $null
        while (-not $nativeProcess.IsBoundedCompilerDiagnosticTraceReady()) {
            $nowTicks = [Diagnostics.Stopwatch]::GetTimestamp()
            if (-not $stopIssued -and $outputBudget.Exceeded) {
                $stopIssued = $true; $stopReason = 'RAW_CAPTURE_LIMIT_REACHED'
                $stopDrainDeadlineTicks = Get-D32BoundedCompilerDiagnosticStopDrainDeadlineTicks `
                    -NowTicks $nowTicks -StopwatchFrequency ([Diagnostics.Stopwatch]::Frequency) -OverallDeadlineTicks $overallDeadlineTicks `
                    -CleanupReserveMilliseconds ([long]$authority.resource_budget.cleanup_reserve_ms) -PersistReserveMilliseconds ([long]$authority.resource_budget.persist_reserve_ms)
                $nativeProcess.RequestBoundedCompilerDiagnosticStop($stopReason)
            }
            if (-not $stopIssued -and $nowTicks -ge $cargoDeadlineTicks) {
                $stopIssued = $true; $stopReason = 'CARGO_OR_TOTAL_DEADLINE_REACHED'
                $stopDrainDeadlineTicks = Get-D32BoundedCompilerDiagnosticStopDrainDeadlineTicks `
                    -NowTicks $nowTicks -StopwatchFrequency ([Diagnostics.Stopwatch]::Frequency) -OverallDeadlineTicks $overallDeadlineTicks `
                    -CleanupReserveMilliseconds ([long]$authority.resource_budget.cleanup_reserve_ms) -PersistReserveMilliseconds ([long]$authority.resource_budget.persist_reserve_ms)
                $nativeProcess.RequestBoundedCompilerDiagnosticStop($stopReason)
            }
            if (-not $stopIssued -and $nowTicks -ge $nextSampleTicks) {
                try {
                    if ($lastSampleTicks -ne 0 -and ($nowTicks - $lastSampleTicks) -lt $samplePeriodTicks) {
                        throw 'D32_BOUNDED_DIAGNOSTIC_METRICS_UNRELIABLE: native resource sample cadence would be more frequent than the pinned 10-second interval'
                    }
                    $nativeSample = $nativeProcess.GetBoundedCompilerDiagnosticSystemSample()
                    $sequence = [Int64]$samples.Count + 1L
                    if ([bool]$nativeSample.Reliable -and [bool]$nativeSample.JobAccountingVerified) {
                        $sampleDocument = New-D32BoundedDiagnosticProcessSampleDocument -Sample $nativeSample -Sequence $sequence
                        $sampleSidecarBytes = Write-D32BoundedDiagnosticBoundedSidecarLine -Writer $sampleWriter `
                            -Document $sampleDocument -PriorBytes $sampleSidecarBytes `
                            -MaximumBytes $script:D32BoundedCompilerDiagnosticSampleSidecarLimitBytes
                        $samples.Add($sampleDocument)
                    }
                    else {
                        $sampleDocument = [ordered]@{
                            record_type = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_SAMPLE_V1'
                            sequence = $sequence
                            sample_state = 'UNRELIABLE'
                            stopwatch_ticks = [Int64]$nativeSample.StopwatchTicks
                            failure = Protect-D32BoundedDiagnosticText -Text ([string]$nativeSample.Failure)
                            job_accounting_verified = [bool]$nativeSample.JobAccountingVerified
                            job_total_processes = [uint32]$nativeSample.JobTotalProcesses
                            job_active_processes = [uint32]$nativeSample.JobActiveProcesses
                            processes = @()
                        }
                        $sampleSidecarBytes = Write-D32BoundedDiagnosticBoundedSidecarLine -Writer $sampleWriter `
                            -Document $sampleDocument -PriorBytes $sampleSidecarBytes `
                            -MaximumBytes $script:D32BoundedCompilerDiagnosticSampleSidecarLimitBytes
                        $sampleFailure = [string]$nativeSample.Failure
                        $stopIssued = $true; $stopReason = 'RESOURCE_METRICS_UNRELIABLE'
                        $stopDrainDeadlineTicks = Get-D32BoundedCompilerDiagnosticStopDrainDeadlineTicks `
                            -NowTicks ([Diagnostics.Stopwatch]::GetTimestamp()) -StopwatchFrequency ([Diagnostics.Stopwatch]::Frequency) -OverallDeadlineTicks $overallDeadlineTicks `
                            -CleanupReserveMilliseconds ([long]$authority.resource_budget.cleanup_reserve_ms) -PersistReserveMilliseconds ([long]$authority.resource_budget.persist_reserve_ms)
                        $nativeProcess.RequestBoundedCompilerDiagnosticStop($stopReason)
                    }
                    $lastSampleTicks = [Diagnostics.Stopwatch]::GetTimestamp()
                    $nextSampleTicks = $lastSampleTicks + $samplePeriodTicks
                    if (-not $stopIssued -and (Test-D32BoundedCompilerDiagnosticResourceStop -Sample $nativeSample `
                        -MetricsReliable ([bool]$nativeSample.Reliable -and [bool]$nativeSample.JobAccountingVerified) `
                        -AdmissionSucceeded $true -CaptureLimitReached ([bool]$outputBudget.Exceeded) -DeadlineReached $false)) {
                        $stopIssued = $true; $stopReason = 'RESOURCE_THRESHOLD_REACHED'
                        $stopDrainDeadlineTicks = Get-D32BoundedCompilerDiagnosticStopDrainDeadlineTicks `
                            -NowTicks ([Diagnostics.Stopwatch]::GetTimestamp()) -StopwatchFrequency ([Diagnostics.Stopwatch]::Frequency) -OverallDeadlineTicks $overallDeadlineTicks `
                            -CleanupReserveMilliseconds ([long]$authority.resource_budget.cleanup_reserve_ms) -PersistReserveMilliseconds ([long]$authority.resource_budget.persist_reserve_ms)
                        $nativeProcess.RequestBoundedCompilerDiagnosticStop($stopReason)
                    }
                }
                catch {
                    $sampleFailure = $_.Exception.Message
                    $stopIssued = $true; $stopReason = 'RESOURCE_SIDECAR_OR_METRICS_FAILURE'
                    $stopDrainDeadlineTicks = Get-D32BoundedCompilerDiagnosticStopDrainDeadlineTicks `
                        -NowTicks ([Diagnostics.Stopwatch]::GetTimestamp()) -StopwatchFrequency ([Diagnostics.Stopwatch]::Frequency) -OverallDeadlineTicks $overallDeadlineTicks `
                        -CleanupReserveMilliseconds ([long]$authority.resource_budget.cleanup_reserve_ms) -PersistReserveMilliseconds ([long]$authority.resource_budget.persist_reserve_ms)
                    try { $nativeProcess.RequestBoundedCompilerDiagnosticStop($stopReason) } catch { $secondaryErrors.Add($_.Exception.Message) }
                }
            }
            if ($stopIssued -and $nowTicks -ge $stopDrainDeadlineTicks) { break }
            if ($nativeProcess.IsBoundedCompilerDiagnosticTraceReady()) { break }
            [Threading.Thread]::Sleep(250)
        }

        if (-not $nativeProcess.IsBoundedCompilerDiagnosticTraceReady()) {
            if (-not $stopIssued) {
                $stopIssued = $true; $stopReason = 'TOTAL_LAUNCH_DEADLINE_REACHED'
                $stopDrainDeadlineTicks = Get-D32BoundedCompilerDiagnosticStopDrainDeadlineTicks `
                    -NowTicks ([Diagnostics.Stopwatch]::GetTimestamp()) -StopwatchFrequency ([Diagnostics.Stopwatch]::Frequency) -OverallDeadlineTicks $overallDeadlineTicks `
                    -CleanupReserveMilliseconds ([long]$authority.resource_budget.cleanup_reserve_ms) -PersistReserveMilliseconds ([long]$authority.resource_budget.persist_reserve_ms)
            }
            try { $nativeProcess.RequestBoundedCompilerDiagnosticStop($stopReason) } catch { $secondaryErrors.Add($_.Exception.Message) }
        }
        $remainingCleanupMs = [Int64]([long]$authority.resource_budget.owned_launch_timeout_ms -
            ([Int64]([Diagnostics.Stopwatch]::GetTimestamp() - $script:D32BoundedLaunchStart) * 1000L / [Diagnostics.Stopwatch]::Frequency) -
            [long]$authority.resource_budget.persist_reserve_ms)
        $traceJoinMs = [int][Math]::Max(1, [Math]::Min(40000L, $remainingCleanupMs - 80000L))
        try { $traceNative = $nativeProcess.WaitForDebugTrace($traceJoinMs) }
        catch { $primaryException = $_.Exception; $secondaryErrors.Add('trace capture/join: ' + $_.Exception.Message) }
        if ($null -ne $traceNative) {
            try {
                $traceDocument = ConvertTo-D32DebugProcessTraceDocument -Trace $traceNative
                $rustcRecords = @($nativeProcess.GetBoundedCompilerDiagnosticRustcCommandRecords() | ForEach-Object {
                    [PSCustomObject]@{
                        ProcessId = [uint32]$_.ProcessId; CreationFileTime = [Int64]$_.CreationFileTime
                        ParentProcessId = [uint32]$_.ParentProcessId; ParentCreationFileTime = [Int64]$_.ParentCreationFileTime
                        ImagePath = [string]$_.ImagePath; CommandLine = [string]$_.CommandLine; Argv = @($_.Argv)
                    }
                })
                $rootProcess = @($traceNative.Processes | Where-Object { [int]$_.ProcessId -eq [int]$nativeProcess.ProcessId })
                if ($rootProcess.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_PROCESS_IDENTITY_UNRESOLVED: native trace does not contain the unique direct Cargo root' }
                $processIdentity = [ordered]@{
                    process_id = [uint32]$rootProcess[0].ProcessId
                    creation_filetime = [Int64]$rootProcess[0].CreationFileTime
                    parent_process_id = [uint32]$rootProcess[0].ParentProcessId
                    parent_creation_filetime = [Int64]$rootProcess[0].ParentCreationFileTime
                    image_path = [string]$rootProcess[0].ImagePath
                    image_bytes = [Int64]$rootProcess[0].Bytes
                    image_sha256 = [string]$rootProcess[0].Sha256
                    image_volume_serial_hex = [string]$rootProcess[0].VolumeSerialHex
                    image_file_id_hex = [string]$rootProcess[0].FileIdHex
                    image_verified = [bool]$rootProcess[0].ImageVerified
                    actual_command_line = [string]$rootProcess[0].CommandLineCapture.CommandLine
                    actual_argv = @($rootProcess[0].CommandLineCapture.Argv)
                    requested_command_line = $commandLine
                    requested_argv = @($cargoArgs)
                }
                $cargoArtifacts = Get-D32BoundedDiagnosticCargoArtifacts -StdoutPath $stdoutPath -TargetRoot ([string]$authority.target.path)
                if (-not $nativeProcess.HasExited) { throw 'D32_BOUNDED_DIAGNOSTIC_CARGO_UNRESOLVED: root Cargo process handle did not signal after trace completion' }
                $command.exit_code = [int]$nativeProcess.ExitCode
                $command.build_finished_success = [bool]$cargoArtifacts.build_finished.success
                if ([bool]$cargoArtifacts.build_finished.success -ne ([int]$nativeProcess.ExitCode -eq 0)) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_CARGO_UNRESOLVED: Cargo build-finished JSON and root process exit code disagree'
                }
                $rustcCrossBinding = Assert-D32BoundedDiagnosticRustcArtifactCrossBinding -RustcRecords $rustcRecords `
                    -Artifacts @($cargoArtifacts.artifacts) -Trace $traceNative -Repository $Repository
            }
            catch { if ($null -eq $primaryException) { $primaryException = $_.Exception } else { $secondaryErrors.Add('post-run parse/binding: ' + $_.Exception.Message) } }
        }

        $cleanupRemainingMs = [Int64]([long]$authority.resource_budget.owned_launch_timeout_ms -
            ([Int64]([Diagnostics.Stopwatch]::GetTimestamp() - $script:D32BoundedLaunchStart) * 1000L / [Diagnostics.Stopwatch]::Frequency) -
            [long]$authority.resource_budget.persist_reserve_ms)
        $cleanupTimeoutMs = [int][Math]::Max(1, [Math]::Min(45000L, $cleanupRemainingMs - 30000L))
        try {
            $cleanupEvidence = $nativeProcess.CloseJobAndWait($cleanupTimeoutMs)
            $cleanupDocument = ConvertTo-D32NativeCleanupDocument -Evidence $cleanupEvidence
        }
        catch { $secondaryErrors.Add('Job/debug cleanup: ' + $_.Exception.Message) }

        if ($null -ne $gitState -and $null -ne $cleanupEvidence -and (Test-D32BoundedCompilerDiagnosticCleanupVerified $cleanupEvidence)) {
            Complete-D32BoundedDiagnosticGitState -GitState $gitState
        }

        $captureWaitMs = [int][Math]::Max(1, [Math]::Min(10000L, [Int64]([long]$authority.resource_budget.owned_launch_timeout_ms -
            ([Int64]([Diagnostics.Stopwatch]::GetTimestamp() - $script:D32BoundedLaunchStart) * 1000L / [Diagnostics.Stopwatch]::Frequency) -
            [long]$authority.resource_budget.persist_reserve_ms)))
        if ($null -ne $stdoutCapture -and -not $stdoutCapture.Wait($captureWaitMs)) { $secondaryErrors.Add('stdout raw pipe reader did not join within its bounded cleanup slice') }
        if ($null -ne $stderrCapture -and -not $stderrCapture.Wait($captureWaitMs)) { $secondaryErrors.Add('stderr raw pipe reader did not join within its bounded cleanup slice') }
        if ($null -ne $stdoutCapture -and -not [String]::IsNullOrWhiteSpace([string]$stdoutCapture.Failure)) { $secondaryErrors.Add('stdout raw capture: ' + [string]$stdoutCapture.Failure) }
        if ($null -ne $stderrCapture -and -not [String]::IsNullOrWhiteSpace([string]$stderrCapture.Failure)) { $secondaryErrors.Add('stderr raw capture: ' + [string]$stderrCapture.Failure) }
        if ($null -ne $sampleWriter) { $sampleWriter.Flush(); $sampleWriter.Dispose(); $sampleWriter = $null; $sampleStream = $null }
        $rawCapture = [ordered]@{
            stdout = New-D32BoundedDiagnosticRawCaptureReference -Path $stdoutPath -Complete ($null -ne $stdoutCapture -and [bool]$stdoutCapture.Completed)
            stderr = New-D32BoundedDiagnosticRawCaptureReference -Path $stderrPath -Complete ($null -ne $stderrCapture -and [bool]$stderrCapture.Completed)
            sample_sidecar = New-D32BoundedDiagnosticRawCaptureReference -Path $samplePath -Complete $true
            reserved_bytes = if ($null -ne $outputBudget) { [Int64]$outputBudget.BytesReserved } else { 0L }
            limit_bytes = [Int64]$authority.resource_budget.raw_capture_limit_bytes
            limit_reached = if ($null -ne $outputBudget) { [bool]$outputBudget.Exceeded } else { $false }
            stdout_reader_complete = ($null -ne $stdoutCapture -and [bool]$stdoutCapture.Completed)
            stderr_reader_complete = ($null -ne $stderrCapture -and [bool]$stderrCapture.Completed)
        }
        $nativeCounters = if ($null -ne $nativeProcess) { $nativeProcess.GetBoundedCompilerDiagnosticNativeCounters() } else { $null }
        $samplingSummary = Get-D32BoundedCompilerDiagnosticSamplingSummary -Samples @($samples.ToArray()) -RustcRecords @($rustcRecords) `
            -StopwatchFrequency ([long]$nativeCounters.StopwatchFrequency) -Complete (-not $stopIssued -and $null -eq $sampleFailure) `
            -StopReason $(if ($stopIssued) { $stopReason } elseif ($null -ne $sampleFailure) { $sampleFailure } else { 'TRACE_COMPLETED' })
        if ($null -ne $targetIdentityBefore) {
            $targetIdentityAfter = Get-D32ProfileDirectoryIdentity -Path ([string]$authority.target.path)
            if ($targetIdentityAfter.VolumeSerialHex -cne $targetIdentityBefore.VolumeSerialHex -or
                $targetIdentityAfter.FileIdHex -cne $targetIdentityBefore.FileIdHex) {
                $secondaryErrors.Add('normal Cargo target directory identity changed during the bounded diagnostic')
            }
        }
        if ($null -ne $nativeProcess) {
            try { $nativeProcess.Dispose() }
            catch { $secondaryErrors.Add('native process dispose: ' + $_.Exception.Message) }
        }
        if ($null -ne $tempOwner -and ($cargoLaunchAttemptCount -eq 0 -or
            ($null -ne $cleanupEvidence -and (Test-D32BoundedCompilerDiagnosticCleanupVerified $cleanupEvidence)))) {
            try { $tempCleanupVerified = Remove-D32BoundedDiagnosticOwnedTempRoot -OwnedTempRoot $tempOwner -RunId $runId }
            catch { $secondaryErrors.Add('TempRoot cleanup: ' + $_.Exception.Message) }
        }
        if ($null -ne $cleanupEvidence -and -not (Test-D32BoundedCompilerDiagnosticCleanupVerified $cleanupEvidence)) {
            $secondaryErrors.Add('owned debug thread/retained handles/Job cleanup is unverified; no further child launch is permitted')
        }
        if ($stopIssued) { $status = 'BUDGET_STOPPED' }
        elseif ($null -ne $primaryException -or $secondaryErrors.Count -gt 0 -or
            $null -eq $traceNative -or [string]$traceNative.State -cne 'COMPLETED' -or
            -not [bool]$traceNative.AccountingConsistent -or -not [bool]$traceNative.EventChainComplete -or
            -not (Test-D32BoundedCompilerDiagnosticCleanupVerified $cleanupEvidence) -or
            $null -eq $stdoutCapture -or -not [bool]$stdoutCapture.Completed -or
            $null -eq $stderrCapture -or -not [bool]$stderrCapture.Completed -or
            $null -eq $cargoArtifacts -or $null -eq $rustcCrossBinding -or
            -not [bool]$samplingSummary.rustc_processes_all_sampled -or -not $tempCleanupVerified) {
            $status = 'UNRESOLVED'
        }
        else {
            $status = 'COMPLETED_DIAGNOSTIC'
        }
    }
    catch {
        if ($null -eq $primaryException) { $primaryException = $_.Exception }
        else { $secondaryErrors.Add($_.Exception.Message) }
        if ($cargoStarted) {
            if ($stopIssued -or $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_BUDGET_STOPPED:*') { $status = 'BUDGET_STOPPED' }
            else { $status = 'UNRESOLVED' }
            if ($null -ne $nativeProcess -and $null -eq $cleanupEvidence) {
                try {
                    $stopIssued = $true
                    if ([String]::IsNullOrWhiteSpace($stopReason)) { $stopReason = 'POST_LAUNCH_EXCEPTION' }
                    $nativeProcess.RequestBoundedCompilerDiagnosticStop($stopReason)
                    $traceNative = $nativeProcess.WaitForDebugTrace(30000)
                    $traceDocument = ConvertTo-D32DebugProcessTraceDocument -Trace $traceNative
                }
                catch { $secondaryErrors.Add('post-launch stop/trace join: ' + $_.Exception.Message) }
                try {
                    $cleanupEvidence = $nativeProcess.CloseJobAndWait(30000)
                    $cleanupDocument = ConvertTo-D32NativeCleanupDocument -Evidence $cleanupEvidence
                }
                catch { $secondaryErrors.Add('post-launch Job/debug cleanup: ' + $_.Exception.Message) }
            }
        }
        elseif ($cargoLaunchAttemptCount -gt 0) {
            $status = 'UNRESOLVED'
        }
        elseif ($_.Exception.Message -like '*300-second ceiling*' -or
            $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_BUDGET_STOPPED:*') {
            $status = 'BUDGET_STOPPED'
        }
        elseif ($script:D32BoundedLaunchStart -ne 0 -and
            (([Diagnostics.Stopwatch]::GetTimestamp() - $script:D32BoundedLaunchStart) -ge
                [Int64]([long]$authority.resource_budget.owned_launch_timeout_ms * [Diagnostics.Stopwatch]::Frequency / 1000L))) {
            $status = 'BUDGET_STOPPED'
        }
        else { $status = 'REFUSED' }
    }
    finally {
        if ($null -ne $sampleWriter) { try { $sampleWriter.Dispose() } catch { $secondaryErrors.Add('sample sidecar close: ' + $_.Exception.Message) } }
        if ($null -ne $sampleStream) { try { $sampleStream.Dispose() } catch { $secondaryErrors.Add('sample sidecar stream close: ' + $_.Exception.Message) } }
        if ($null -ne $stdoutDestination) { try { $stdoutDestination.Dispose() } catch { $secondaryErrors.Add('stdout file close: ' + $_.Exception.Message) } }
        if ($null -ne $stderrDestination) { try { $stderrDestination.Dispose() } catch { $secondaryErrors.Add('stderr file close: ' + $_.Exception.Message) } }
        if ($null -ne $gitState -and $null -ne $gitState.MetadataLocks) {
            try { Close-D32GitMetadataLocks -Locks $gitState.MetadataLocks } catch { $secondaryErrors.Add('Git metadata lock close: ' + $_.Exception.Message) }
        }
        $completedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
        if ($null -ne $rootOwner) {
            if ($null -eq $command) {
                $command = [ordered]@{
                    executable = [string]$profile.Profile.toolchain.cargo.path
                    argv = @(Get-D32BoundedCompilerDiagnosticFixedArgv)
                    working_directory = $Repository
                    manifest_path = 'vita-agent/Cargo.toml'
                    target_directory = [string]$authority.target.path
                    launch_attempt_count = $cargoLaunchAttemptCount
                    timeout_ms = [Int64]$authority.resource_budget.cargo_timeout_ms
                    child_environment_sha256 = if ($null -ne $environment) { Get-D32BoundedDiagnosticEnvironmentSha256 -Environment $environment } else { $null }
                    exit_code = if ($null -ne $nativeProcess -and $nativeProcess.HasExited) { [int]$nativeProcess.ExitCode } else { $null }
                    timed_out_or_stopped = [bool]$stopIssued
                    stop_reason = if ($stopIssued) { $stopReason } else { $null }
                }
            }
            if ($null -eq $rawCapture) {
                $rawCapture = [ordered]@{
                    stdout = if ($null -ne $stdoutPath) { New-D32BoundedDiagnosticRawCaptureReference -Path $stdoutPath -Complete ($null -ne $stdoutCapture -and [bool]$stdoutCapture.Completed) } else { $null }
                    stderr = if ($null -ne $stderrPath) { New-D32BoundedDiagnosticRawCaptureReference -Path $stderrPath -Complete ($null -ne $stderrCapture -and [bool]$stderrCapture.Completed) } else { $null }
                    sample_sidecar = if ($null -ne $samplePath) { New-D32BoundedDiagnosticRawCaptureReference -Path $samplePath -Complete $true } else { $null }
                    reserved_bytes = if ($null -ne $outputBudget) { [Int64]$outputBudget.BytesReserved } else { 0L }
                    limit_bytes = [Int64]$authority.resource_budget.raw_capture_limit_bytes
                    limit_reached = if ($null -ne $outputBudget) { [bool]$outputBudget.Exceeded } else { $false }
                    stdout_reader_complete = ($null -ne $stdoutCapture -and [bool]$stdoutCapture.Completed)
                    stderr_reader_complete = ($null -ne $stderrCapture -and [bool]$stderrCapture.Completed)
                }
            }
            if ($null -eq $samplingSummary) {
                $samplingSummary = [ordered]@{
                    sample_count = [Int64]$samples.Count
                    sampling_complete = $false
                    sampling_stop_reason = if ($stopIssued) { $stopReason } else { 'NOT_STARTED_OR_UNRESOLVED' }
                    maximum_sample_gap_at_or_below_10000ms = $false
                    retained_process_identities = @()
                    rustc_process_count = [Int64]$rustcRecords.Count
                    rustc_processes = @()
                    rustc_processes_all_sampled = $false
                    private_peak_label = 'maximum observed 10-second sampled PrivateUsage; not a lifetime peak'
                }
            }
            $primaryText = if ($null -eq $primaryException) { $null } else { Protect-D32BoundedDiagnosticText -Text ([string]$primaryException.Message) }
            $record = New-D32BoundedDiagnosticResult -Status $status -RunId $runId -StartedAtUtc $startedAtUtc `
                -CompletedAtUtc $completedAtUtc -PrimaryError $primaryText -SecondaryErrors @($secondaryErrors.ToArray()) `
                -Capacity $capacity -Command $command -ProcessIdentity $processIdentity -Trace $traceDocument `
                -Cleanup $cleanupDocument -Sampling $samplingSummary -CargoArtifacts $cargoArtifacts `
                -RustcCrossBinding $rustcCrossBinding -SourceClosure $sourceClosure -Capture $rawCapture `
                -NativeCounters $nativeCounters -GitState $(if ($null -eq $gitState) { $null } else { [PSCustomObject]@{
                    candidate_sha = [string]$gitState.CandidateSha
                    head_before = [string]$gitState.HeadBefore
                    head_after = if ($gitState.PSObject.Properties['HeadAfter']) { [string]$gitState.HeadAfter } else { $null }
                    pre_status_clean = [bool]$gitState.StatusBeforeClean
                    index_flags_clean = [bool]$gitState.IndexFlagsClean
                    post_status_clean = if ($gitState.PSObject.Properties['StatusAfterClean']) { [bool]$gitState.StatusAfterClean } else { $null }
                    complete = if ($gitState.PSObject.Properties['Complete']) { [bool]$gitState.Complete } else { $false }
                    query_count = [Int64]$gitState.Commands.Count
                    commands = @($gitState.Commands.ToArray())
                } })
            $record.output_owner = $rootOwner.OwnerReference
            $record.temp_owner = if ($null -eq $tempOwner) { $null } else { $tempOwner.OwnerReference }
            $record.temp_cleanup_verified = [bool]$tempCleanupVerified
            if ($null -ne $targetIdentityBefore -and $null -ne $targetIdentityAfter) {
                $record.target_identity_after = [ordered]@{
                    path = [string]$targetIdentityAfter.Path
                    volume_serial_hex = [string]$targetIdentityAfter.VolumeSerialHex
                    file_id_hex = [string]$targetIdentityAfter.FileIdHex
                    same_as_prelaunch = ($targetIdentityAfter.VolumeSerialHex -ceq $targetIdentityBefore.VolumeSerialHex -and
                        $targetIdentityAfter.FileIdHex -ceq $targetIdentityBefore.FileIdHex)
                }
            }
            $resultPath = Join-Path $rootOwner.Path 'D32-BOUNDED-COMPILER-DIAGNOSTIC.json'
            try { $null = Write-D32BoundedDiagnosticCreateNewJson -Path $resultPath -Document $record }
            catch {
                $secondaryErrors.Add('create-new diagnostic result persistence failed: ' + $_.Exception.Message)
                throw
            }
        }
    }
}

if ($PSCmdlet.ParameterSetName -ceq 'SourceProofOnly') {
    Invoke-D32BoundedDiagnosticSourceProofRun
}
else {
    Invoke-D32BoundedCompilerDiagnosticRun
}
