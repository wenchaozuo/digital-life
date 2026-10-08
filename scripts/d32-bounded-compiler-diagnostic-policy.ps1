# Pure policy helpers for the D32 bounded compiler diagnostic.
# This file defines functions only; it never imports modules or launches processes.

$script:D32BoundedCompilerDiagnosticAuthorityType = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_AUTHORITY_V3'
$script:D32BoundedCompilerDiagnosticResultType = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_V3'
$script:D32BoundedDiagnosticSourceProofAuthorityType = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_AUTHORITY_V3'
$script:D32BoundedDiagnosticSourceProofCandidateType = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_CANDIDATE_V4'
$script:D32BoundedDiagnosticRegistrySourceContentProofType = 'D32_BOUNDED_DIAGNOSTIC_REGISTRY_SOURCE_CONTENT_PROOF_V4'
$script:D32BoundedDiagnosticRegistryArchivePolicy = 'D32_REGISTRY_TAR_USTAR_GNU_LONGNAME_V1'
$script:D32BoundedDiagnosticArchiveFormatCensusAuthorityType = 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_FORMAT_CENSUS_AUTHORITY_V2'
$script:D32BoundedDiagnosticArchiveFormatCensusType = 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_FORMAT_CENSUS_V2'
$script:D32BoundedDiagnosticHistoricalInv7CandidateSha = '2de30edf5de48aa4ed3216c3d3df13c3e2f0ac51'
$script:D32BoundedCompilerDiagnosticGateAuthority = 'NONE'
$script:D32BoundedCompilerDiagnosticStatuses = @('COMPLETED_DIAGNOSTIC', 'BUDGET_STOPPED', 'REFUSED', 'UNRESOLVED')
$script:D32BoundedCompilerDiagnosticMaxCargoMilliseconds = 1200000
$script:D32BoundedCompilerDiagnosticMaxLaunchMilliseconds = 1800000
$script:D32BoundedCompilerDiagnosticCleanupReserveMilliseconds = 120000
$script:D32BoundedCompilerDiagnosticPersistReserveMilliseconds = 60000
$script:D32BoundedCompilerDiagnosticCaptureLimitBytes = 268435456
$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes = 536870912
$script:D32BoundedCompilerDiagnosticRegistryArchiveLimitBytes = 268435456
$script:D32BoundedCompilerDiagnosticSampleSidecarLimitBytes = 67108864
$script:D32BoundedCompilerDiagnosticGitQueryTimeoutMilliseconds = 5000
$script:D32BoundedCompilerDiagnosticGitJoinGraceMilliseconds = 5000
$script:D32BoundedCompilerDiagnosticGitPipeJoinMilliseconds = 5000
$script:D32BoundedDiagnosticSourceProofCombinedMilliseconds = 300000L
$script:D32BoundedDiagnosticSourceProofPersistReserveMilliseconds = 30000L
$script:D32BoundedDiagnosticSourceProofExecutionAuthorityType = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_EXECUTION_AUTHORITY_V1'
$script:D32BoundedDiagnosticSourceProofExecutionResultType = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_EXECUTION_V1'
$script:D32BoundedDiagnosticSourceProofLifecyclePolicy = 'D32_SOURCEPROOF_LIFECYCLE_V1'
$script:D32BoundedDiagnosticSourceProofLifecycleWorkMilliseconds = 270000L
$script:D32BoundedDiagnosticSourceProofLifecycleProofExpiryMilliseconds = 300000L
$script:D32BoundedDiagnosticSourceProofLifecycleCleanupMilliseconds = 345000L
$script:D32BoundedDiagnosticSourceProofLifecycleTerminalAuditMilliseconds = 360000L
$script:D32BoundedDiagnosticSourceProofLifecycleStdoutLimitBytes = 16000L
$script:D32BoundedDiagnosticSourceProofLifecycleRecordLimitBytes = 65536L
$script:D32BoundedDiagnosticSourceProofLifecycleCandidateLimitBytes = 67108864L
$script:D32BoundedDiagnosticSourceProofLifecycleManagedLimitBytes = 536870912L
$script:D32BoundedDiagnosticSourceProofNonSourceL1AuthorityType = 'D32_BOUNDED_SOURCEPROOF_NON_SOURCE_L1_AUTHORITY_V2'
$script:D32BoundedDiagnosticSourceProofNonSourceL1ResultType = 'D32_BOUNDED_SOURCEPROOF_NON_SOURCE_L1_V2'
$script:D32BoundedDiagnosticSourceProofNonSourceL1Policy = 'D32_SOURCEPROOF_NON_SOURCE_L1_V2'
$script:D32BoundedDiagnosticSourceProofOuterPrelaunchBindingArgumentIndex = 16
$script:D32BoundedDiagnosticSourceProofNonSourceL1Limits = [PSCustomObject][ordered]@{
    batch_milliseconds = 60000L; active_milliseconds = 5000L; cleanup_milliseconds = 10000L; audit_milliseconds = 15000L
    stdout_max_bytes = 16000L; stderr_max_bytes = 16000L; expected_output_max_bytes = 1024L
    owned_buffer_max_bytes = 16777216L; result_max_bytes = 65536L; journal_max_bytes = 65536L
    max_create_process_attempts = 2L; fixed_case_count = 3L
}
$script:D32BoundedDiagnosticSourceProofNonSourceL1CreateFlags = 0x08080404L
$script:D32BoundedDiagnosticSourceProofNonSourceL1HandleRoles = @('stdin:NUL', 'stdout:PIPE_WRITE', 'stderr:PIPE_WRITE')
$script:D32BoundedDiagnosticSourceProofNonSourceL1ObservedHandleFlags = [PSCustomObject][ordered]@{
    stdin_inheritable = $true; stdout_write_inheritable = $true; stderr_write_inheritable = $true
    stdout_read_inheritable = $false; stderr_read_inheritable = $false
}
$script:D32BoundedDiagnosticSourceProofLifecycleClock = $null
$script:D32BoundedDiagnosticSourceProofMaximumOutputBytes = 67108864L
$script:D32BoundedDiagnosticManifestValueNodeLimit = 100000L
$script:D32BoundedDiagnosticGraphCandidateComparisonLimit = 1000000L
$script:D32BoundedDiagnosticSourceProofPhase = 'bootstrap'
$script:D32BoundedDiagnosticSourceProofProgress = 'not_started'
$script:D32BoundedDiagnosticSourceProofTimer = $null
$script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds = 270000L
$script:D32BoundedDiagnosticSourceProofProgressMarkerAllowedPhases = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($phaseName in @(
    'authority.output_preflight', 'authority.strict_shape', 'repository.identity', 'source_pins.current', 'manifest_refs.current',
    'current_profile_and_locks', 'inv7_origin_and_source_graph', 'origin.root_identity', 'origin.registry_refs', 'origin.registry_complete',
    'registry.archive', 'registry.archive_headers', 'registry.archive_inventory_rows', 'registry.archive_header_inventory_digest',
    'registry.pair_inventory_digest', 'registry.control_metadata_digest', 'registry.extracted_directory', 'registry.extracted_inventory',
    'registry.extracted_directory_identity', 'git.checkout_walk', 'git.checkout_entries', 'git.checkout_expected_coverage',
    'git.checkout_metadata_inventory', 'git.tree_walk', 'git.manifest_candidates', 'graph.git_manifest_memory_estimate',
    'graph.registry_manifest_memory_estimate', 'graph.workspace_manifest_capacity', 'source_graph.index_manifests',
    'source_graph.index_edges', 'source_graph.index_packages', 'source_graph.canonical_manifests', 'source_graph.canonical_edges',
    'source_graph.canonical_decisions', 'source_graph.witness_budget', 'source_graph.witness_materialize',
    'source_graph.exclusion_materialize', 'source_graph.dependencies', 'source_graph.parents', 'source_graph.edge_candidates',
    'source_proof.result_registry_ids', 'source_proof.result_git_ids', 'source_proof.result_current_manifests',
    'source_proof.result_git_sources', 'source_proof.result_profile_bindings', 'proof.complete_before_persist_reserve',
    'result.json_serialize', 'result.write', 'result.write_complete', 'result.flush_complete'
)) { [void]$script:D32BoundedDiagnosticSourceProofProgressMarkerAllowedPhases.Add($phaseName) }
$script:D32BoundedDiagnosticSourceProofProgressMarkerPhases = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$script:D32BoundedDiagnosticSourceProofProgressMarkerLastCounters = [Collections.Generic.Dictionary[string,long]]::new([StringComparer]::Ordinal)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps = [Collections.Generic.Dictionary[string,long]]::new([StringComparer]::Ordinal)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('registry.archive', [long]64)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('origin.registry_refs', [long]128)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('git.checkout_entries', [long]4096)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('git.checkout_expected_coverage', [long]4096)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('git.checkout_directory_identity', [long]1024)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('git.checkout_metadata_inventory', [long]2048)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('registry.archive_inventory_rows', [long]1024)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('source_graph.canonical_manifests', [long]1024)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('source_graph.canonical_edges', [long]1024)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('source_graph.canonical_decisions', [long]1024)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('source_graph.witness_budget', [long]2048)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('source_graph.witness_materialize', [long]1024)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('source_graph.exclusion_materialize', [long]1024)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('registry.pair_inventory_digest', [long]1024)
$script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('registry.control_metadata_digest', [long]1024)

function Set-D32BoundedDiagnosticSourceProofProgress {
    param([Parameter(Mandatory = $true)][string]$Phase, [Parameter(Mandatory = $true)][string]$Progress)
    $script:D32BoundedDiagnosticSourceProofPhase = [regex]::Replace($Phase, '[^A-Za-z0-9_.#-]', '_')
    $script:D32BoundedDiagnosticSourceProofProgress = [regex]::Replace($Progress, '[^A-Za-z0-9_.#=/-]', '_')

    # Non-gating stdout only. Never serialize raw progress (which may contain a path,
    # package identifier, or other caller data); emit phases and coarse numeric counts.
    $timer = $script:D32BoundedDiagnosticSourceProofTimer
    if ($null -eq $timer -or -not $timer.IsRunning) { return }
    if ($script:D32BoundedDiagnosticSourceProofProgressMarkerOutputUnavailable -or
        $script:D32BoundedDiagnosticSourceProofProgressMarkerCount -ge 120) { return }

    $phaseValue = [string]$script:D32BoundedDiagnosticSourceProofPhase
    if (-not $script:D32BoundedDiagnosticSourceProofProgressMarkerAllowedPhases.Contains($phaseValue)) { return }
    $firstPhaseMarker = $script:D32BoundedDiagnosticSourceProofProgressMarkerPhases.Add($phaseValue)
    $coarseStep = [long]0
    $hasCoarseStep = $script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.TryGetValue($phaseValue, [ref]$coarseStep)
    if (-not $firstPhaseMarker -and -not $hasCoarseStep) { return }

    $counterValue = [long]-1
    $counterText = 'none'
    $counterMatch = [regex]::Match([string]$script:D32BoundedDiagnosticSourceProofProgress,
        '(?:^|_)(?<key>pins|references|archives|archive|members|files|directories|rows|sources|trees|entries|paths|candidates|offset|bytes|pending|locks|count)=(?<current>[0-9]{1,12})(?:/(?<total>[0-9]{1,12}))?(?=_|$)')
    if ($counterMatch.Success) {
        $counterKey = [string]$counterMatch.Groups['key'].Value
        $counterValue = [long]::Parse($counterMatch.Groups['current'].Value, [Globalization.CultureInfo]::InvariantCulture)
        $counterLabel = switch ($counterKey) {
            'archives' { 'arc' } 'archive' { 'arc' } 'members' { 'mem' } 'files' { 'file' }
            'directories' { 'dir' } 'rows' { 'row' } 'sources' { 'src' } 'trees' { 'tree' }
            'entries' { 'ent' } 'paths' { 'path' } 'candidates' { 'cand' } 'references' { 'ref' }
            'pins' { 'pin' } 'offset' { 'off' } 'bytes' { 'B' } 'pending' { 'pend' }
            'locks' { 'lock' } 'count' { 'n' } default { $counterKey }
        }
        $counterText = [string]$counterLabel + '=' + $counterMatch.Groups['current'].Value
        if ($counterMatch.Groups['total'].Success) { $counterText += '/' + $counterMatch.Groups['total'].Value }
        if ($counterText.Length -gt 28) { $counterText = $counterText.Substring(0, 28) }
    }

    $coarseMilestone = $false
    if (-not $firstPhaseMarker -and $hasCoarseStep -and $counterMatch.Success) {
        $lastValue = [long]-1
        if (-not $script:D32BoundedDiagnosticSourceProofProgressMarkerLastCounters.TryGetValue($phaseValue, [ref]$lastValue) -or
            $counterValue -ge ($lastValue + $coarseStep)) { $coarseMilestone = $true }
    }
    if (-not $firstPhaseMarker -and -not $coarseMilestone) { return }

    $line = 'D32SP1 p={0} t={1} n={2}' -f $phaseValue, [Int64]$timer.ElapsedMilliseconds, $counterText
    if ($line.Length -gt 120) { $line = $line.Substring(0, 120) }
    $lineBytes = [Text.Encoding]::ASCII.GetByteCount($line + [Environment]::NewLine)
    if ($script:D32BoundedDiagnosticSourceProofProgressMarkerBytes + $lineBytes -gt 16000) {
        $script:D32BoundedDiagnosticSourceProofProgressMarkerOutputUnavailable = $true
        return
    }
    try { [Console]::Out.WriteLine($line) }
    catch {
        $script:D32BoundedDiagnosticSourceProofProgressMarkerOutputUnavailable = $true
        return
    }
    $script:D32BoundedDiagnosticSourceProofProgressMarkerBytes += $lineBytes
    $script:D32BoundedDiagnosticSourceProofProgressMarkerCount++
    if ($counterMatch.Success) { $script:D32BoundedDiagnosticSourceProofProgressMarkerLastCounters[$phaseValue] = $counterValue }
}

function Get-D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds {
    param([long]$CombinedMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds,
        [long]$PersistReserveMilliseconds = $script:D32BoundedDiagnosticSourceProofPersistReserveMilliseconds)
    if ($CombinedMilliseconds -ne $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds -or
        $PersistReserveMilliseconds -le 0 -or $PersistReserveMilliseconds -ge $CombinedMilliseconds) {
        throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: invalid in-budget persistence reserve'
    }
    return [Int64]($CombinedMilliseconds - $PersistReserveMilliseconds)
}

function Test-D32BoundedDiagnosticSourceProofElapsedWithinDeadline {
    param([long]$ElapsedMilliseconds, [long]$DeadlineMilliseconds)
    return ($ElapsedMilliseconds -ge 0 -and $DeadlineMilliseconds -gt 0 -and $ElapsedMilliseconds -lt $DeadlineMilliseconds)
}

function Get-D32BoundedDiagnosticSourceProofSupervisorDisposition {
    param([long]$ElapsedMilliseconds, [bool]$ProcessExited)
    if ($ElapsedMilliseconds -lt 0) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: supervisor elapsed time is negative' }
    if ($ProcessExited) { return 'CHILD_EXITED' }
    if ($ElapsedMilliseconds -ge $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds) { return 'TOTAL_DEADLINE_EXPIRED' }
    if ($ElapsedMilliseconds -ge $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds) { return 'WORK_DEADLINE_ADVISORY' }
    return 'WORK_IN_PROGRESS'
}

function ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks {
    param([Parameter(Mandatory = $true)][long]$T0Ticks,
        [Parameter(Mandatory = $true)][long]$Frequency,
        [Parameter(Mandatory = $true)][long]$DeadlineMilliseconds)
    if ($T0Ticks -le 0 -or $Frequency -le 0 -or $DeadlineMilliseconds -le 0) {
        throw 'D32_SOURCEPROOF_LIFECYCLE_BLOCKED: monotonic clock origin, frequency, or deadline is invalid'
    }
    try {
        $delta = [decimal]::Ceiling(([decimal]$Frequency * [decimal]$DeadlineMilliseconds) / [decimal]1000)
        $absolute = [decimal]$T0Ticks + $delta
        if ($delta -le 0 -or $absolute -gt [decimal][Int64]::MaxValue) {
            throw 'checked deadline tick calculation overflowed'
        }
        return [Int64]$absolute
    }
    catch { throw 'D32_SOURCEPROOF_LIFECYCLE_BLOCKED: checked monotonic deadline calculation failed' }
}

function Get-D32BoundedDiagnosticSourceProofElapsedMilliseconds {
    param([Parameter(Mandatory = $true)][long]$T0Ticks,
        [Parameter(Mandatory = $true)][long]$Frequency,
        [long]$NowTicks = [Diagnostics.Stopwatch]::GetTimestamp())
    if ($T0Ticks -le 0 -or $Frequency -le 0 -or $NowTicks -lt $T0Ticks) {
        throw 'D32_SOURCEPROOF_LIFECYCLE_BLOCKED: monotonic counter rolled back or clock binding is invalid'
    }
    try {
        $elapsed = [decimal]($NowTicks - $T0Ticks) * [decimal]1000 / [decimal]$Frequency
        if ($elapsed -lt 0 -or $elapsed -gt [decimal][Int64]::MaxValue) {
            throw 'checked elapsed-time calculation overflowed'
        }
        return [Int64][Math]::Floor($elapsed)
    }
    catch { throw 'D32_SOURCEPROOF_LIFECYCLE_BLOCKED: checked monotonic elapsed-time calculation failed' }
}

function Get-D32BoundedDiagnosticSourceProofLifecyclePhase {
    param([Parameter(Mandatory = $true)][long]$T0Ticks,
        [Parameter(Mandatory = $true)][long]$Frequency,
        [long]$NowTicks = [Diagnostics.Stopwatch]::GetTimestamp())
    $elapsed = Get-D32BoundedDiagnosticSourceProofElapsedMilliseconds -T0Ticks $T0Ticks -Frequency $Frequency -NowTicks $NowTicks
    if ($elapsed -lt $script:D32BoundedDiagnosticSourceProofLifecycleWorkMilliseconds) { return 'PROOF_WORK' }
    if ($elapsed -lt $script:D32BoundedDiagnosticSourceProofLifecycleProofExpiryMilliseconds) { return 'FINALIZATION_ONLY' }
    if ($elapsed -lt $script:D32BoundedDiagnosticSourceProofLifecycleCleanupMilliseconds) { return 'CLEANUP_ONLY' }
    if ($elapsed -lt $script:D32BoundedDiagnosticSourceProofLifecycleTerminalAuditMilliseconds) { return 'AUDIT_ONLY' }
    return 'EXPIRED'
}

function Get-D32BoundedDiagnosticSourceProofCurrentElapsedMilliseconds {
    param([AllowNull()][Diagnostics.Stopwatch]$ProofTimer)
    if ($null -ne $script:D32BoundedDiagnosticSourceProofLifecycleClock) {
        return Get-D32BoundedDiagnosticSourceProofElapsedMilliseconds `
            -T0Ticks ([Int64]$script:D32BoundedDiagnosticSourceProofLifecycleClock.t0_ticks) `
            -Frequency ([Int64]$script:D32BoundedDiagnosticSourceProofLifecycleClock.frequency)
    }
    if ($null -eq $ProofTimer -or -not $ProofTimer.IsRunning) { throw 'D32_SOURCEPROOF_LIFECYCLE_BLOCKED: no active monotonic proof timer is available' }
    return [Int64]$ProofTimer.ElapsedMilliseconds
}

function Get-D32BoundedDiagnosticSourceProofWorkDeadlineTicks {
    if ($null -eq $script:D32BoundedDiagnosticSourceProofLifecycleClock) { return [Int64]0 }
    $deadline = [Int64]$script:D32BoundedDiagnosticSourceProofLifecycleClock.work_deadline_ticks
    if ($deadline -le [Int64]$script:D32BoundedDiagnosticSourceProofLifecycleClock.t0_ticks) {
        throw 'D32_SOURCEPROOF_LIFECYCLE_BLOCKED: shared monotonic work deadline is malformed'
    }
    return $deadline
}

function Test-D32BoundedDiagnosticSourceProofLifecycleClock {
    param([AllowNull()][object]$Clock)
    $fields = @('counter_origin', 'frequency', 't0_ticks', 'work_deadline_ticks', 'proof_expiry_ticks', 'cleanup_deadline_ticks', 'terminal_audit_deadline_ticks')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $Clock -Expected $fields) -or
        [string]$Clock.counter_origin -cne 'QueryPerformanceCounter' -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Clock.frequency -Positive) -or
        [Int64]$Clock.frequency -ne [Int64][Diagnostics.Stopwatch]::Frequency -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Clock.t0_ticks -Positive)) { return $false }
    foreach ($name in @('work_deadline_ticks', 'proof_expiry_ticks', 'cleanup_deadline_ticks', 'terminal_audit_deadline_ticks')) {
        if (-not (Test-D32BoundedCompilerDiagnosticInteger $Clock.($name) -Positive)) { return $false }
    }
    try {
        return ([Int64]$Clock.work_deadline_ticks -eq (ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks ([Int64]$Clock.t0_ticks) -Frequency ([Int64]$Clock.frequency) -DeadlineMilliseconds 270000L) -and
            [Int64]$Clock.proof_expiry_ticks -eq (ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks ([Int64]$Clock.t0_ticks) -Frequency ([Int64]$Clock.frequency) -DeadlineMilliseconds 300000L) -and
            [Int64]$Clock.cleanup_deadline_ticks -eq (ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks ([Int64]$Clock.t0_ticks) -Frequency ([Int64]$Clock.frequency) -DeadlineMilliseconds 345000L) -and
            [Int64]$Clock.terminal_audit_deadline_ticks -eq (ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks ([Int64]$Clock.t0_ticks) -Frequency ([Int64]$Clock.frequency) -DeadlineMilliseconds 360000L))
    }
    catch { return $false }
}

function Test-D32BoundedDiagnosticSourceProofExecutionAuthorityClock {
    param([AllowNull()][object]$Clock)
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $Clock -Expected @('counter_origin', 'frequency')) -or
        $Clock.counter_origin -isnot [string] -or [string]$Clock.counter_origin -cne 'QueryPerformanceCounter' -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Clock.frequency -Positive) -or
        [Int64]$Clock.frequency -ne [Int64][Diagnostics.Stopwatch]::Frequency) { return $false }
    return $true
}

function Test-D32BoundedDiagnosticSourceProofExecutionAuthorityShape {
    param([AllowNull()][object]$Document,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository)
    $fields = @('schema_version', 'record_type', 'timing_policy', 'gate_authority', 'candidate_sha', 'source_repo', 'repository_identity',
        'run_id', 'owner_id', 'source_proof_authority', 'toolchain_profile', 'powershell_runtime', 'source_pins', 'invocation', 'output', 'clock', 'limits', 'issued_at_utc')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $Document -Expected $fields) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Document.schema_version -Positive) -or [Int64]$Document.schema_version -ne 1 -or
        $Document.record_type -isnot [string] -or [string]$Document.record_type -cne $script:D32BoundedDiagnosticSourceProofExecutionAuthorityType -or
        $Document.timing_policy -isnot [string] -or [string]$Document.timing_policy -cne $script:D32BoundedDiagnosticSourceProofLifecyclePolicy -or
        $Document.gate_authority -isnot [string] -or [string]$Document.gate_authority -cne 'NONE' -or
        $Document.candidate_sha -isnot [string] -or [string]$Document.candidate_sha -cne $ExpectedCandidateSha -or $ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.source_repo) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Document.source_repo, [IO.Path]::GetFullPath($Repository)) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Document.repository_identity) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.repository_identity @('volume_serial_hex', 'file_id_hex')) -or
        [string]$Document.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        $Document.owner_id -isnot [string] -or [string]$Document.owner_id -cnotmatch '^[A-Za-z0-9._:-]{1,128}$') { return $false }

    foreach ($reference in @($Document.source_proof_authority, $Document.toolchain_profile)) {
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $reference) -or
            (Test-D32BoundedCompilerDiagnosticWithin $reference.path $Repository) -or
            (Test-D32BoundedCompilerDiagnosticWithin $reference.path 'E:\d32\inv7\r\c')) { return $false }
    }
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.powershell_runtime @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex', 'powershell_home', 'system_root')) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape ([PSCustomObject]@{ path = $Document.powershell_runtime.path; bytes = $Document.powershell_runtime.bytes;
            sha256 = $Document.powershell_runtime.sha256; volume_serial_hex = $Document.powershell_runtime.volume_serial_hex; file_id_hex = $Document.powershell_runtime.file_id_hex })) -or
        [string]$Document.powershell_runtime.path -cnotmatch '^[A-Za-z]:\\Program Files\\PowerShell\\7\\pwsh\.exe$' -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.powershell_runtime.powershell_home) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$Document.powershell_runtime.path), [string]$Document.powershell_runtime.powershell_home) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.powershell_runtime.system_root)) { return $false }

    $expectedRelative = @(
        'scripts/d32-bounded-diagnostic-sourceproof-controller.ps1',
        'scripts/d32-bounded-diagnostic-sourceproof.ps1',
        'scripts/d32-bounded-compiler-diagnostic.ps1',
        'scripts/d32-bounded-compiler-diagnostic-policy.ps1',
        'scripts/d32-build-toolchain-profile.ps1',
        'scripts/d32-powershell-module-authority.ps1')
    if ($Document.source_pins -isnot [Array] -or $Document.source_pins.Count -ne $expectedRelative.Count) { return $false }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    for ($index = 0; $index -lt $expectedRelative.Count; $index++) {
        $pin = $Document.source_pins[$index]
        $expectedPath = [IO.Path]::GetFullPath((Join-Path $Repository ($expectedRelative[$index].Replace('/', '\'))))
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $pin) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$pin.path, $expectedPath) -or
            -not (Test-D32BoundedCompilerDiagnosticWithin $pin.path $Repository) -or
            -not $seen.Add([string]$pin.path)) { return $false }
    }

    $invocationFields = @('role', 'entry_path', 'working_directory', 'environment_policy', 'argument_policy', 'child_environment')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.invocation $invocationFields) -or
        $Document.invocation.role -isnot [string] -or $Document.invocation.entry_path -isnot [string] -or
        $Document.invocation.working_directory -isnot [string] -or $Document.invocation.environment_policy -isnot [string] -or
        $Document.invocation.argument_policy -isnot [string] -or
        [string]$Document.invocation.role -cne 'D32_SOURCEPROOF_ONLY_FIXED_V1' -or
        [string]$Document.invocation.entry_path -cne [IO.Path]::GetFullPath((Join-Path $Repository 'scripts/d32-bounded-diagnostic-sourceproof.ps1')) -or
        [string]$Document.invocation.working_directory -cne [IO.Path]::GetFullPath($Repository) -or
        [string]$Document.invocation.environment_policy -cne 'D32_SOURCEPROOF_MINIMAL_ENV_V1' -or
        [string]$Document.invocation.argument_policy -cne 'D32_SOURCEPROOF_FIXED_ARGV_V1') { return $false }
    $environmentFields = @('SystemRoot', 'WINDIR', 'PATH', 'PSModulePath', 'PSModuleAutoLoadingPreference',
        'POWERSHELL_TELEMETRY_OPTOUT', 'DOTNET_CLI_TELEMETRY_OPTOUT', 'TEMP', 'TMP')
    $environment = $Document.invocation.child_environment
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $environment $environmentFields) -or
        @($environment.PSObject.Properties | Where-Object { $_.Value -isnot [string] }).Count -ne 0 -or
        [string]$environment.SystemRoot -cne [string]$Document.powershell_runtime.system_root -or
        [string]$environment.WINDIR -cne [string]$Document.powershell_runtime.system_root -or
        [string]$environment.PATH -cne ([string]$Document.powershell_runtime.system_root.TrimEnd('\') + '\System32;' + [string]$Document.powershell_runtime.powershell_home) -or
        [string]$environment.PSModulePath -cne ([string]$Document.powershell_runtime.powershell_home.TrimEnd('\') + '\Modules') -or
        [string]$environment.PSModuleAutoLoadingPreference -cne 'None' -or
        [string]$environment.POWERSHELL_TELEMETRY_OPTOUT -cne '1' -or
        [string]$environment.DOTNET_CLI_TELEMETRY_OPTOUT -cne '1' -or
        [string]$environment.TEMP -cne [string]$Document.output.parent_path -or
        [string]$environment.TMP -cne [string]$Document.output.parent_path) { return $false }

    $outputFields = @('candidate_path', 'execution_record_path', 'journal_path', 'parent_path', 'parent_volume_serial_hex', 'parent_file_id_hex')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.output $outputFields) -or
        $Document.output.candidate_path -isnot [string] -or $Document.output.execution_record_path -isnot [string] -or
        $Document.output.journal_path -isnot [string] -or $Document.output.parent_path -isnot [string] -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.output.candidate_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.output.execution_record_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.output.journal_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$Document.output.candidate_path), [string]$Document.output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$Document.output.execution_record_path), [string]$Document.output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$Document.output.journal_path), [string]$Document.output.parent_path) -or
        [string]$Document.output.parent_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        [string]$Document.output.parent_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        (Test-D32BoundedCompilerDiagnosticWithin $Document.output.parent_path $Repository) -or
        (Test-D32BoundedCompilerDiagnosticWithin $Document.output.parent_path 'E:\d32\inv7\r\c')) { return $false }
    $outputPaths = @([string]$Document.output.candidate_path, [string]$Document.output.execution_record_path, [string]$Document.output.journal_path)
    $outputSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $outputPaths) { if (-not $outputSet.Add($path)) { return $false } }

    if (-not (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityClock $Document.clock)) { return $false }
    $limitFields = @('work_milliseconds', 'proof_expiry_milliseconds', 'cleanup_deadline_milliseconds', 'terminal_audit_deadline_milliseconds',
        'stdout_max_bytes', 'record_max_bytes', 'candidate_max_bytes', 'managed_buffer_max_bytes')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.limits $limitFields)) { return $false }
    $expectedLimits = [ordered]@{ work_milliseconds = 270000L; proof_expiry_milliseconds = 300000L; cleanup_deadline_milliseconds = 345000L;
        terminal_audit_deadline_milliseconds = 360000L; stdout_max_bytes = 16000L; record_max_bytes = 65536L;
        candidate_max_bytes = 67108864L; managed_buffer_max_bytes = 536870912L }
    foreach ($name in $limitFields) {
        if (-not (Test-D32BoundedCompilerDiagnosticInteger $Document.limits.($name) -Positive) -or
            [Int64]$Document.limits.($name) -ne [Int64]$expectedLimits[$name]) { return $false }
    }
    try {
        $issued = [DateTimeOffset]::Parse([string]$Document.issued_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        if ($issued.Offset -ne [TimeSpan]::Zero) { return $false }
    }
    catch { return $false }
    return $true
}

function Test-D32BoundedDiagnosticSourceProofExecutionAuthorityBindings {
    param([AllowNull()][object]$ExecutionAuthority,
        [AllowNull()][object]$SourceProofAuthority,
        [AllowNull()][object]$SourceProofAuthorityReference,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository)
    if (-not (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityShape -Document $ExecutionAuthority -ExpectedCandidateSha $ExpectedCandidateSha -Repository $Repository) -or
        $null -eq $SourceProofAuthority -or
        [string]$SourceProofAuthority.record_type -cne $script:D32BoundedDiagnosticSourceProofAuthorityType -or
        [string]$ExecutionAuthority.run_id -cne [string]$SourceProofAuthority.run_id -or
        [string]$ExecutionAuthority.candidate_sha -cne [string]$SourceProofAuthority.candidate_sha -or
        [string]$ExecutionAuthority.source_repo -cne [string]$SourceProofAuthority.source_repo -or
        $null -eq $SourceProofAuthorityReference -or
        [string]$ExecutionAuthority.source_proof_authority.path -cne [string]$SourceProofAuthorityReference.path -or
        [Int64]$ExecutionAuthority.source_proof_authority.bytes -ne [Int64]$SourceProofAuthorityReference.bytes -or
        [string]$ExecutionAuthority.source_proof_authority.sha256 -cne [string]$SourceProofAuthorityReference.sha256 -or
        [string]$ExecutionAuthority.source_proof_authority.volume_serial_hex -cne [string]$SourceProofAuthorityReference.volume_serial_hex -or
        [string]$ExecutionAuthority.source_proof_authority.file_id_hex -cne [string]$SourceProofAuthorityReference.file_id_hex -or
        [string]$ExecutionAuthority.toolchain_profile.path -cne [string]$SourceProofAuthority.toolchain_profile.path -or
        [Int64]$ExecutionAuthority.toolchain_profile.bytes -ne [Int64]$SourceProofAuthority.toolchain_profile.bytes -or
        [string]$ExecutionAuthority.toolchain_profile.sha256 -cne [string]$SourceProofAuthority.toolchain_profile.sha256 -or
        [string]$ExecutionAuthority.output.candidate_path -cne [string]$SourceProofAuthority.output_candidate.path -or
        [string]$ExecutionAuthority.invocation.entry_path -cne [IO.Path]::GetFullPath((Join-Path $Repository 'scripts/d32-bounded-diagnostic-sourceproof.ps1'))) { return $false }
    if ($ExecutionAuthority.source_pins.Count -ne 6 -or $SourceProofAuthority.source_pins -isnot [Array] -or $SourceProofAuthority.source_pins.Count -ne 5) { return $false }
    for ($index = 0; $index -lt 5; $index++) {
        $outer = $ExecutionAuthority.source_pins[$index + 1]
        $inner = $SourceProofAuthority.source_pins[$index]
        foreach ($name in @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) {
            if ([string]$outer.($name) -cne [string]$inner.($name)) { return $false }
        }
    }
    return $true
}

function New-D32BoundedDiagnosticSourceProofExecutionAuthorityCandidate {
    param([Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][object]$RepositoryIdentity,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$OwnerId,
        [Parameter(Mandatory = $true)][object]$SourceProofAuthorityReference,
        [Parameter(Mandatory = $true)][object]$ToolchainProfileReference,
        [Parameter(Mandatory = $true)][object]$PowerShellRuntime,
        [Parameter(Mandatory = $true)][object[]]$SourcePins,
        [Parameter(Mandatory = $true)][object]$Output,
        [Parameter(Mandatory = $true)][object]$Clock,
        [Parameter(Mandatory = $true)][string]$IssuedAtUtc)
    $repositoryPath = [IO.Path]::GetFullPath($Repository)
    $runtimeHome = [IO.Path]::GetFullPath([string]$PowerShellRuntime.powershell_home)
    $systemRoot = [IO.Path]::GetFullPath([string]$PowerShellRuntime.system_root)
    $environment = [PSCustomObject][ordered]@{
        SystemRoot = $systemRoot
        WINDIR = $systemRoot
        PATH = [string]$systemRoot.TrimEnd('\') + '\System32;' + $runtimeHome
        PSModulePath = [string]$runtimeHome.TrimEnd('\') + '\Modules'
        PSModuleAutoLoadingPreference = 'None'
        POWERSHELL_TELEMETRY_OPTOUT = '1'
        DOTNET_CLI_TELEMETRY_OPTOUT = '1'
        TEMP = [string]$Output.parent_path
        TMP = [string]$Output.parent_path
    }
    return [PSCustomObject][ordered]@{
        schema_version = 1
        record_type = $script:D32BoundedDiagnosticSourceProofExecutionAuthorityType
        timing_policy = $script:D32BoundedDiagnosticSourceProofLifecyclePolicy
        gate_authority = 'NONE'
        candidate_sha = $CandidateSha
        source_repo = $repositoryPath
        repository_identity = $RepositoryIdentity
        run_id = $RunId
        owner_id = $OwnerId
        source_proof_authority = $SourceProofAuthorityReference
        toolchain_profile = $ToolchainProfileReference
        powershell_runtime = $PowerShellRuntime
        source_pins = @($SourcePins)
        invocation = [PSCustomObject][ordered]@{
            role = 'D32_SOURCEPROOF_ONLY_FIXED_V1'
            entry_path = [IO.Path]::GetFullPath((Join-Path $repositoryPath 'scripts/d32-bounded-diagnostic-sourceproof.ps1'))
            working_directory = $repositoryPath
            environment_policy = 'D32_SOURCEPROOF_MINIMAL_ENV_V1'
            argument_policy = 'D32_SOURCEPROOF_FIXED_ARGV_V1'
            child_environment = $environment
        }
        output = $Output
        clock = $Clock
        limits = [PSCustomObject][ordered]@{
            work_milliseconds = 270000L
            proof_expiry_milliseconds = 300000L
            cleanup_deadline_milliseconds = 345000L
            terminal_audit_deadline_milliseconds = 360000L
            stdout_max_bytes = 16000L
            record_max_bytes = 65536L
            candidate_max_bytes = 67108864L
            managed_buffer_max_bytes = 536870912L
        }
        issued_at_utc = $IssuedAtUtc
    }
}

function Test-D32BoundedDiagnosticSourceProofExecutionResultShape {
    param([AllowNull()][object]$Record)
    $fields = @('schema_version', 'record_type', 'timing_policy', 'gate_authority', 'candidate_sha', 'run_id', 'authority', 'status', 'source_pins',
        'powershell_runtime', 'output', 'clock', 'controller', 'reader', 'artifact', 'captures', 'cleanup', 'events', 'primary_error', 'secondary_errors', 'started_at_utc', 'completed_at_utc')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record $fields) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.schema_version -Positive) -or [Int64]$Record.schema_version -ne 1 -or
        [string]$Record.record_type -cne $script:D32BoundedDiagnosticSourceProofExecutionResultType -or
        [string]$Record.timing_policy -cne $script:D32BoundedDiagnosticSourceProofLifecyclePolicy -or
        [string]$Record.gate_authority -cne 'NONE' -or [string]$Record.candidate_sha -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Record.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Record.status -cnotin @('COMPLETED_DIAGNOSTIC_ONLY', 'BUDGET_STOPPED', 'REFUSED', 'UNRESOLVED') -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Record.authority) -or
        $Record.source_pins -isnot [Array] -or $Record.source_pins.Count -ne 6 -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.powershell_runtime @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Record.powershell_runtime) -or
        [string]$Record.powershell_runtime.path -cnotmatch '^[A-Za-z]:\\Program Files\\PowerShell\\7\\pwsh\.exe$' -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.output @('candidate_path', 'execution_record_path', 'journal_path', 'parent_path', 'parent_volume_serial_hex', 'parent_file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.output.candidate_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.output.execution_record_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.output.journal_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$Record.output.candidate_path), [string]$Record.output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$Record.output.execution_record_path), [string]$Record.output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$Record.output.journal_path), [string]$Record.output.parent_path) -or
        [string]$Record.output.parent_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$Record.output.parent_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.clock @('counter_origin', 'frequency', 't0_ticks', 'work_deadline_ticks',
            'proof_expiry_ticks', 'cleanup_deadline_ticks', 'terminal_audit_deadline_ticks', 'controller_entry_ticks', 'reader_create_attempt_ticks',
            'reader_resume_ticks', 'reader_exit_ticks', 'artifact_verified_ticks', 'cleanup_verified_ticks', 'audit_persisted_ticks', 'observed_ticks')) -or
        [string]$Record.clock.counter_origin -cne 'QueryPerformanceCounter' -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.clock.frequency -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.clock.t0_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.clock.work_deadline_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.clock.proof_expiry_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.clock.cleanup_deadline_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.clock.terminal_audit_deadline_ticks -Positive)) { return $false }
    $clock = [PSCustomObject]@{ counter_origin = $Record.clock.counter_origin; frequency = $Record.clock.frequency; t0_ticks = $Record.clock.t0_ticks;
        work_deadline_ticks = $Record.clock.work_deadline_ticks; proof_expiry_ticks = $Record.clock.proof_expiry_ticks;
        cleanup_deadline_ticks = $Record.clock.cleanup_deadline_ticks; terminal_audit_deadline_ticks = $Record.clock.terminal_audit_deadline_ticks }
    if (-not (Test-D32BoundedDiagnosticSourceProofLifecycleClock $clock)) { return $false }
    foreach ($index in 0..5) {
        $pin = $Record.source_pins[$index]
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $pin) -or
            [string]$pin.path -cnotmatch '^[A-Za-z]:\\' -or
            (Test-D32BoundedCompilerDiagnosticWithin $pin.path ([string]$Record.output.parent_path))) { return $false }
    }
    foreach ($name in @('controller_entry_ticks', 'reader_create_attempt_ticks', 'reader_resume_ticks', 'reader_exit_ticks', 'artifact_verified_ticks', 'cleanup_verified_ticks', 'audit_persisted_ticks', 'observed_ticks')) {
        $value = $Record.clock.($name)
        if ($null -ne $value -and (-not (Test-D32BoundedCompilerDiagnosticInteger $value -Positive) -or [Int64]$value -lt [Int64]$Record.clock.t0_ticks)) { return $false }
    }
    foreach ($name in @('controller_entry_ticks', 'reader_create_attempt_ticks', 'reader_resume_ticks', 'reader_exit_ticks', 'artifact_verified_ticks', 'cleanup_verified_ticks', 'audit_persisted_ticks', 'observed_ticks')) {
        $value = $Record.clock.($name)
        if ($null -ne $value -and [Int64]$value -ge [Int64]$Record.clock.terminal_audit_deadline_ticks) { return $false }
    }
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.controller @('process_id', 'creation_filetime_ticks')) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.controller.process_id -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.controller.creation_filetime_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.reader @('launch_attempt_count', 'process_id', 'creation_filetime_ticks', 'job_instance_id', 'job_assignment', 'exit_code')) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.reader.launch_attempt_count) -or [Int64]$Record.reader.launch_attempt_count -gt 1 -or
        (($null -ne $Record.reader.process_id) -and -not (Test-D32BoundedCompilerDiagnosticInteger $Record.reader.process_id -Positive)) -or
        (($null -ne $Record.reader.creation_filetime_ticks) -and -not (Test-D32BoundedCompilerDiagnosticInteger $Record.reader.creation_filetime_ticks -Positive)) -or
        (($null -ne $Record.reader.job_instance_id) -and [string]$Record.reader.job_instance_id -cnotmatch '^[0-9a-f]{32}$') -or
        [string]$Record.reader.job_assignment -cnotin @('NOT_ATTEMPTED', 'ASSIGNED', 'FAILED') -or
        (($null -ne $Record.reader.exit_code) -and -not (Test-D32BoundedCompilerDiagnosticInteger $Record.reader.exit_code))) { return $false }

    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.artifact @('state', 'path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex', 'inner_status')) -or
        [string]$Record.artifact.state -cnotin @('NOT_READ', 'ABSENT', 'PARTIAL_OR_UNCONFIRMED', 'VERIFIED') -or
        [string]$Record.artifact.path -notmatch '^[A-Za-z]:\\' -or
        (($null -ne $Record.artifact.bytes) -and (-not (Test-D32BoundedCompilerDiagnosticInteger $Record.artifact.bytes) -or [Int64]$Record.artifact.bytes -gt 67108864)) -or
        (($null -ne $Record.artifact.sha256) -and [string]$Record.artifact.sha256 -cnotmatch '^[0-9a-f]{64}$') -or
        (($null -ne $Record.artifact.volume_serial_hex) -and [string]$Record.artifact.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$') -or
        (($null -ne $Record.artifact.file_id_hex) -and [string]$Record.artifact.file_id_hex -cnotmatch '^[0-9a-f]{32}$') -or
        (($null -ne $Record.artifact.inner_status) -and [string]$Record.artifact.inner_status -cnotin @('BLOCKED', 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY'))) { return $false }
    if ([string]$Record.artifact.state -ceq 'VERIFIED' -and
        ($null -eq $Record.artifact.bytes -or $null -eq $Record.artifact.sha256 -or $null -eq $Record.artifact.volume_serial_hex -or
         $null -eq $Record.artifact.file_id_hex -or $null -eq $Record.artifact.inner_status -or $null -eq $Record.clock.artifact_verified_ticks)) { return $false }
    if ([string]$Record.artifact.state -ceq 'VERIFIED' -and
        (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Record.artifact.path, [string]$Record.output.candidate_path) -or
         [Int64]$Record.clock.artifact_verified_ticks -ge [Int64]$Record.clock.proof_expiry_ticks)) { return $false }

    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.captures @('stdout_bytes', 'stdout_sha256', 'stdout_truncated', 'stderr_bytes', 'stderr_sha256', 'stderr_truncated', 'allowlisted_marker_count', 'output_unavailable')) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.captures.stdout_bytes) -or [Int64]$Record.captures.stdout_bytes -gt 16000 -or
        [string]$Record.captures.stdout_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $Record.captures.stdout_truncated -isnot [bool] -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.captures.stderr_bytes) -or [Int64]$Record.captures.stderr_bytes -gt 16000 -or
        [string]$Record.captures.stderr_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $Record.captures.stderr_truncated -isnot [bool] -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.captures.allowlisted_marker_count) -or
        [Int64]$Record.captures.allowlisted_marker_count -gt 256 -or $Record.captures.output_unavailable -isnot [bool]) { return $false }
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.cleanup @('state', 'termination_requested', 'join_verified', 'job_active_process_count', 'job_closed', 'kill_on_close_enabled')) -or
        [string]$Record.cleanup.state -cnotin @('NOT_STARTED', 'VERIFIED', 'UNVERIFIED') -or
        $Record.cleanup.termination_requested -isnot [bool] -or $Record.cleanup.join_verified -isnot [bool] -or
        (($null -ne $Record.cleanup.job_active_process_count) -and -not (Test-D32BoundedCompilerDiagnosticInteger $Record.cleanup.job_active_process_count)) -or
        $Record.cleanup.job_closed -isnot [bool] -or $Record.cleanup.kill_on_close_enabled -isnot [bool]) { return $false }
    if ([string]$Record.cleanup.state -ceq 'VERIFIED' -and
        (-not $Record.cleanup.join_verified -or $null -eq $Record.cleanup.job_active_process_count -or [Int64]$Record.cleanup.job_active_process_count -ne 0 -or
         -not $Record.cleanup.job_closed -or -not $Record.cleanup.kill_on_close_enabled -or $null -eq $Record.clock.cleanup_verified_ticks)) { return $false }

    if ($Record.events -isnot [Array] -or $Record.events.Count -gt 16 -or
        $Record.secondary_errors -isnot [Array] -or $Record.secondary_errors.Count -gt 8 -or
        (($null -ne $Record.primary_error) -and ($Record.primary_error -isnot [string] -or ([string]$Record.primary_error).Length -gt 2048))) { return $false }
    $eventNames = @('AUTHORITY_ADMISSION', 'READER_CREATE_ATTEMPT', 'READER_ASSIGNED_TO_JOB', 'READER_RESUMED', 'WORK_CUTOFF', 'PROOF_EXPIRY', 'READER_EXIT', 'TERMINATION_REQUEST', 'CLEANUP_VERIFIED', 'CLEANUP_UNVERIFIED', 'TERMINAL_AUDIT')
    $observedEventNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $eventIndexes = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
    $eventIndex = 0
    $previousEventTicks = [Int64]$Record.clock.t0_ticks
    foreach ($event in $Record.events) {
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $event @('event', 'scheduled_ticks', 'observed_ticks', 'lateness_ticks')) -or
            [string]$event.event -cnotin $eventNames -or
            (($null -ne $event.scheduled_ticks) -and -not (Test-D32BoundedCompilerDiagnosticInteger $event.scheduled_ticks -Positive)) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $event.observed_ticks -Positive) -or
            (($null -ne $event.scheduled_ticks) -and [Int64]$event.observed_ticks -lt [Int64]$event.scheduled_ticks) -or
            (($null -ne $event.lateness_ticks) -and -not (Test-D32BoundedCompilerDiagnosticInteger $event.lateness_ticks)) -or
            (($null -ne $event.scheduled_ticks) -and ($null -eq $event.lateness_ticks -or
                [Int64]$event.lateness_ticks -ne ([Int64]$event.observed_ticks - [Int64]$event.scheduled_ticks))) -or
            (($null -eq $event.scheduled_ticks) -and $null -ne $event.lateness_ticks)) { return $false }
        if ([Int64]$event.observed_ticks -ge [Int64]$Record.clock.terminal_audit_deadline_ticks) { return $false }
        if ([Int64]$event.observed_ticks -lt $previousEventTicks) { return $false }
        $previousEventTicks = [Int64]$event.observed_ticks
        if (-not $observedEventNames.Add([string]$event.event)) { return $false }
        $eventIndexes.Add([string]$event.event, $eventIndex++)
        switch ([string]$event.event) {
            'AUTHORITY_ADMISSION' { if ($null -eq $event.scheduled_ticks -or [Int64]$event.scheduled_ticks -ne [Int64]$Record.clock.t0_ticks) { return $false } }
            'WORK_CUTOFF' { if ($null -eq $event.scheduled_ticks -or [Int64]$event.scheduled_ticks -ne [Int64]$Record.clock.work_deadline_ticks) { return $false } }
            'PROOF_EXPIRY' { if ($null -eq $event.scheduled_ticks -or [Int64]$event.scheduled_ticks -ne [Int64]$Record.clock.proof_expiry_ticks) { return $false } }
            'TERMINATION_REQUEST' { if ($null -eq $event.scheduled_ticks -or [Int64]$event.scheduled_ticks -ne [Int64]$Record.clock.proof_expiry_ticks) { return $false } }
            'CLEANUP_UNVERIFIED' { if ($null -eq $event.scheduled_ticks -or [Int64]$event.scheduled_ticks -ne [Int64]$Record.clock.cleanup_deadline_ticks) { return $false } }
            'TERMINAL_AUDIT' { if ($null -eq $event.scheduled_ticks -or [Int64]$event.scheduled_ticks -ne [Int64]$Record.clock.cleanup_deadline_ticks) { return $false } }
            'READER_CREATE_ATTEMPT' { if ($null -eq $event.scheduled_ticks -or $null -eq $Record.clock.reader_create_attempt_ticks -or [Int64]$event.scheduled_ticks -ne [Int64]$Record.clock.reader_create_attempt_ticks) { return $false } }
            'READER_ASSIGNED_TO_JOB' { if ($null -eq $event.scheduled_ticks -or $null -eq $Record.clock.reader_create_attempt_ticks -or [Int64]$event.scheduled_ticks -ne [Int64]$Record.clock.reader_create_attempt_ticks) { return $false } }
            default { }
        }
    }
    if ($observedEventNames.Contains('CLEANUP_VERIFIED') -and $observedEventNames.Contains('CLEANUP_UNVERIFIED')) { return $false }
    if ($observedEventNames.Contains('TERMINAL_AUDIT') -and $eventIndexes['TERMINAL_AUDIT'] -ne ($Record.events.Count - 1)) { return $false }
    foreach ($name in @('READER_ASSIGNED_TO_JOB', 'READER_RESUMED', 'READER_EXIT')) {
        if ($observedEventNames.Contains($name) -and
            (-not $observedEventNames.Contains('READER_CREATE_ATTEMPT') -or $eventIndexes[$name] -lt $eventIndexes['READER_CREATE_ATTEMPT'])) { return $false }
    }
    foreach ($name in @('READER_CREATE_ATTEMPT', 'READER_ASSIGNED_TO_JOB', 'READER_RESUMED', 'READER_EXIT', 'TERMINATION_REQUEST', 'CLEANUP_VERIFIED', 'CLEANUP_UNVERIFIED')) {
        if ($observedEventNames.Contains($name) -and -not $observedEventNames.Contains('AUTHORITY_ADMISSION')) { return $false }
    }
    if ($observedEventNames.Contains('PROOF_EXPIRY') -and $observedEventNames.Contains('WORK_CUTOFF') -and
        $eventIndexes['PROOF_EXPIRY'] -lt $eventIndexes['WORK_CUTOFF']) { return $false }
    if ([Int64]$Record.reader.launch_attempt_count -eq 0 -and $observedEventNames.Contains('READER_CREATE_ATTEMPT')) { return $false }
    if ([Int64]$Record.reader.launch_attempt_count -eq 1 -and
        ($null -eq $Record.clock.reader_create_attempt_ticks -or -not $observedEventNames.Contains('READER_CREATE_ATTEMPT'))) { return $false }
    if ([string]$Record.reader.job_assignment -ceq 'ASSIGNED' -and -not $observedEventNames.Contains('READER_ASSIGNED_TO_JOB')) { return $false }
    if ($null -ne $Record.reader.exit_code -and (-not $observedEventNames.Contains('READER_EXIT') -or $null -eq $Record.clock.reader_exit_ticks)) { return $false }
    if ([string]$Record.cleanup.state -ceq 'VERIFIED' -and -not $observedEventNames.Contains('CLEANUP_VERIFIED')) { return $false }
    if ([string]$Record.cleanup.state -ceq 'UNVERIFIED' -and -not $observedEventNames.Contains('CLEANUP_UNVERIFIED')) { return $false }
    if ($Record.cleanup.termination_requested -ne $observedEventNames.Contains('TERMINATION_REQUEST')) { return $false }
    foreach ($errorText in $Record.secondary_errors) { if ($errorText -isnot [string] -or ([string]$errorText).Length -gt 2048) { return $false } }
    try {
        $null = [DateTimeOffset]::Parse([string]$Record.started_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        $null = [DateTimeOffset]::Parse([string]$Record.completed_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
    }
    catch { return $false }

    if ([string]$Record.status -ceq 'COMPLETED_DIAGNOSTIC_ONLY' -and
        ([string]$Record.artifact.state -cne 'VERIFIED' -or [string]$Record.artifact.inner_status -cne 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY' -or
         [Int64]$Record.reader.launch_attempt_count -ne 1 -or $null -eq $Record.reader.exit_code -or [Int64]$Record.reader.exit_code -ne 0 -or
         $null -eq $Record.clock.reader_create_attempt_ticks -or [Int64]$Record.clock.reader_create_attempt_ticks -ge [Int64]$Record.clock.work_deadline_ticks -or
         $null -eq $Record.clock.reader_resume_ticks -or [Int64]$Record.clock.reader_resume_ticks -ge [Int64]$Record.clock.work_deadline_ticks -or
         $null -eq $Record.clock.reader_exit_ticks -or [Int64]$Record.clock.reader_exit_ticks -ge [Int64]$Record.clock.proof_expiry_ticks -or
         $null -eq $Record.clock.artifact_verified_ticks -or [Int64]$Record.clock.artifact_verified_ticks -ge [Int64]$Record.clock.proof_expiry_ticks -or
         $null -eq $Record.clock.cleanup_verified_ticks -or [Int64]$Record.clock.cleanup_verified_ticks -ge [Int64]$Record.clock.proof_expiry_ticks -or
         $null -eq $Record.reader.process_id -or [string]$Record.reader.job_assignment -cne 'ASSIGNED' -or
         $null -eq $Record.reader.job_instance_id -or [string]$Record.cleanup.state -cne 'VERIFIED' -or
         $null -eq $Record.reader.creation_filetime_ticks -or
         $Record.captures.output_unavailable -or $Record.cleanup.termination_requested -or
         -not $observedEventNames.Contains('AUTHORITY_ADMISSION') -or -not $observedEventNames.Contains('READER_CREATE_ATTEMPT') -or
         -not $observedEventNames.Contains('READER_ASSIGNED_TO_JOB') -or -not $observedEventNames.Contains('READER_RESUMED') -or
         -not $observedEventNames.Contains('READER_EXIT') -or -not $observedEventNames.Contains('CLEANUP_VERIFIED') -or
         -not $observedEventNames.Contains('TERMINAL_AUDIT') -or $observedEventNames.Contains('PROOF_EXPIRY') -or
         $observedEventNames.Contains('CLEANUP_UNVERIFIED') -or
         -not [String]::IsNullOrEmpty([string]$Record.primary_error))) { return $false }
    if ([string]$Record.status -ceq 'REFUSED' -and
        ([Int64]$Record.reader.launch_attempt_count -ne 0 -or $null -ne $Record.reader.process_id -or [String]::IsNullOrWhiteSpace([string]$Record.primary_error) -or
         $observedEventNames.Contains('READER_CREATE_ATTEMPT') -or $observedEventNames.Contains('READER_ASSIGNED_TO_JOB') -or
         $observedEventNames.Contains('READER_RESUMED') -or $observedEventNames.Contains('READER_EXIT') -or $observedEventNames.Contains('TERMINATION_REQUEST'))) { return $false }
    if ([string]$Record.status -ceq 'BUDGET_STOPPED' -and
        (-not (@($Record.events | Where-Object { [string]$_.event -in @('WORK_CUTOFF', 'PROOF_EXPIRY') }).Count -gt 0) -or
         [String]::IsNullOrWhiteSpace([string]$Record.primary_error))) { return $false }
    if ([string]$Record.status -ceq 'UNRESOLVED' -and [String]::IsNullOrWhiteSpace([string]$Record.primary_error)) { return $false }
    return $true
}

function Test-D32BoundedDiagnosticSourceProofExecutionResultBindings {
    param([AllowNull()][object]$Record,
        [AllowNull()][object]$ExecutionAuthority,
        [AllowNull()][object]$ExecutionAuthorityReference,
        [Parameter(Mandatory = $true)][string]$ExpectedExecutionAuthoritySha256,
        [Parameter(Mandatory = $true)][string]$ExpectedExecutionAuthorityPath)
    if (-not (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $Record) -or $null -eq $ExecutionAuthority -or $null -eq $ExecutionAuthorityReference -or
        -not (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityShape -Document $ExecutionAuthority -ExpectedCandidateSha ([string]$Record.candidate_sha) -Repository ([string]$ExecutionAuthority.source_repo)) -or
        [string]$Record.candidate_sha -cne [string]$ExecutionAuthority.candidate_sha -or
        [string]$Record.run_id -cne [string]$ExecutionAuthority.run_id -or
        [string]$Record.authority.path -cne $ExpectedExecutionAuthorityPath -or
        [string]$Record.authority.sha256 -cne $ExpectedExecutionAuthoritySha256 -or
        [string]$Record.authority.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [Int64]$Record.authority.bytes -le 0 -or
        [string]$Record.authority.path -cne [string]$ExecutionAuthorityReference.path -or
        [Int64]$Record.authority.bytes -ne [Int64]$ExecutionAuthorityReference.bytes -or
        [string]$Record.authority.sha256 -cne [string]$ExecutionAuthorityReference.sha256 -or
        [string]$Record.authority.volume_serial_hex -cne [string]$ExecutionAuthorityReference.volume_serial_hex -or
        [string]$Record.authority.file_id_hex -cne [string]$ExecutionAuthorityReference.file_id_hex -or
        [string]$Record.artifact.path -cne [string]$ExecutionAuthority.output.candidate_path -or
        [string]$Record.powershell_runtime.path -cne [string]$ExecutionAuthority.powershell_runtime.path -or
        [Int64]$Record.powershell_runtime.bytes -ne [Int64]$ExecutionAuthority.powershell_runtime.bytes -or
        [string]$Record.powershell_runtime.sha256 -cne [string]$ExecutionAuthority.powershell_runtime.sha256 -or
        [string]$Record.powershell_runtime.volume_serial_hex -cne [string]$ExecutionAuthority.powershell_runtime.volume_serial_hex -or
        [string]$Record.powershell_runtime.file_id_hex -cne [string]$ExecutionAuthority.powershell_runtime.file_id_hex) { return $false }
    foreach ($name in @('candidate_path', 'execution_record_path', 'journal_path', 'parent_path', 'parent_volume_serial_hex', 'parent_file_id_hex')) {
        if ([string]$Record.output.($name) -cne [string]$ExecutionAuthority.output.($name)) { return $false }
    }
    if ($Record.source_pins.Count -ne $ExecutionAuthority.source_pins.Count) { return $false }
    for ($index = 0; $index -lt $Record.source_pins.Count; $index++) {
        foreach ($name in @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) {
            if ([string]$Record.source_pins[$index].($name) -cne [string]$ExecutionAuthority.source_pins[$index].($name)) { return $false }
        }
    }
    if ([Int64]$Record.clock.frequency -ne [Int64]$ExecutionAuthority.clock.frequency -or
        [Int64]$ExecutionAuthority.limits.work_milliseconds -ne 270000L -or
        [Int64]$ExecutionAuthority.limits.proof_expiry_milliseconds -ne 300000L -or
        [Int64]$ExecutionAuthority.limits.cleanup_deadline_milliseconds -ne 345000L -or
        [Int64]$ExecutionAuthority.limits.terminal_audit_deadline_milliseconds -ne 360000L -or
        [Int64]$Record.clock.work_deadline_ticks -ne (ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks ([Int64]$Record.clock.t0_ticks) -Frequency ([Int64]$Record.clock.frequency) -DeadlineMilliseconds ([Int64]$ExecutionAuthority.limits.work_milliseconds)) -or
        [Int64]$Record.clock.proof_expiry_ticks -ne (ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks ([Int64]$Record.clock.t0_ticks) -Frequency ([Int64]$Record.clock.frequency) -DeadlineMilliseconds ([Int64]$ExecutionAuthority.limits.proof_expiry_milliseconds)) -or
        [Int64]$Record.clock.cleanup_deadline_ticks -ne (ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks ([Int64]$Record.clock.t0_ticks) -Frequency ([Int64]$Record.clock.frequency) -DeadlineMilliseconds ([Int64]$ExecutionAuthority.limits.cleanup_deadline_milliseconds)) -or
        [Int64]$Record.clock.terminal_audit_deadline_ticks -ne (ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks ([Int64]$Record.clock.t0_ticks) -Frequency ([Int64]$Record.clock.frequency) -DeadlineMilliseconds ([Int64]$ExecutionAuthority.limits.terminal_audit_deadline_milliseconds))) { return $false }
    return $true
}

function New-D32BoundedDiagnosticSourceProofExecutionResultCandidate {
    param([Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][object[]]$SourcePins,
        [Parameter(Mandatory = $true)][object]$PowerShellRuntime,
        [Parameter(Mandatory = $true)][object]$Output,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][object]$Clock,
        [Parameter(Mandatory = $true)][object]$Controller,
        [Parameter(Mandatory = $true)][object]$Reader,
        [Parameter(Mandatory = $true)][object]$Artifact,
        [Parameter(Mandatory = $true)][object]$Captures,
        [Parameter(Mandatory = $true)][object]$Cleanup,
        [Parameter(Mandatory = $true)][object[]]$Events,
        [AllowNull()][string]$PrimaryError,
        [string[]]$SecondaryErrors = @(),
        [Parameter(Mandatory = $true)][string]$StartedAtUtc,
        [Parameter(Mandatory = $true)][string]$CompletedAtUtc)
    return [PSCustomObject][ordered]@{
        schema_version = 1
        record_type = $script:D32BoundedDiagnosticSourceProofExecutionResultType
        timing_policy = $script:D32BoundedDiagnosticSourceProofLifecyclePolicy
        gate_authority = 'NONE'
        candidate_sha = $CandidateSha
        run_id = $RunId
        authority = $AuthorityReference
        status = $Status
        source_pins = @($SourcePins)
        powershell_runtime = $PowerShellRuntime
        output = $Output
        clock = $Clock
        controller = $Controller
        reader = $Reader
        artifact = $Artifact
        captures = $Captures
        cleanup = $Cleanup
        events = @($Events)
        primary_error = $PrimaryError
        secondary_errors = @($SecondaryErrors)
        started_at_utc = $StartedAtUtc
        completed_at_utc = $CompletedAtUtc
    }
}

function Get-D32BoundedDiagnosticSourceProofNonSourceL1SourcePaths {
    param([Parameter(Mandatory = $true)][string]$Repository)
    return @(
        [IO.Path]::GetFullPath([IO.Path]::Combine($Repository, 'scripts/d32-bounded-diagnostic-sourceproof-controller.ps1')),
        [IO.Path]::GetFullPath([IO.Path]::Combine($Repository, 'scripts/d32-bounded-diagnostic-sourceproof.ps1')),
        [IO.Path]::GetFullPath([IO.Path]::Combine($Repository, 'scripts/d32-bounded-compiler-diagnostic.ps1')),
        [IO.Path]::GetFullPath([IO.Path]::Combine($Repository, 'scripts/d32-bounded-compiler-diagnostic-policy.ps1')),
        [IO.Path]::GetFullPath([IO.Path]::Combine($Repository, 'scripts/d32-build-toolchain-profile.ps1')),
        [IO.Path]::GetFullPath([IO.Path]::Combine($Repository, 'scripts/d32-powershell-module-authority.ps1')))
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1Environment {
    param([AllowNull()][object]$Environment, [Parameter(Mandatory = $true)][object]$Runtime,
        [Parameter(Mandatory = $true)][string]$Root)
    $fields = @('SystemRoot', 'WINDIR', 'PATH', 'PSHOME', 'PSModulePath', 'PSModuleAutoLoadingPreference',
        'POWERSHELL_TELEMETRY_OPTOUT', 'DOTNET_CLI_TELEMETRY_OPTOUT', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'HOMEDRIVE', 'HOMEPATH')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Environment $fields)) { return $false }
    foreach ($property in $Environment.PSObject.Properties) { if ($property.Value -isnot [string]) { return $false } }
    $drive = [IO.Path]::GetPathRoot($Root).TrimEnd('\')
    $homePath = $Root.Substring($drive.Length)
    return ([string]$Environment.SystemRoot -ceq [string]$Runtime.system_root -and
        [string]$Environment.WINDIR -ceq [string]$Runtime.system_root -and
        [string]$Environment.PATH -ceq ([string]$Runtime.system_root.TrimEnd('\') + '\System32;' + [string]$Runtime.powershell_home) -and
        [string]$Environment.PSHOME -ceq [string]$Runtime.powershell_home -and
        [string]$Environment.PSModulePath -ceq ([string]$Runtime.powershell_home.TrimEnd('\') + '\Modules') -and
        [string]$Environment.PSModuleAutoLoadingPreference -ceq 'None' -and
        [string]$Environment.POWERSHELL_TELEMETRY_OPTOUT -ceq '1' -and
        [string]$Environment.DOTNET_CLI_TELEMETRY_OPTOUT -ceq '1' -and
        [string]$Environment.TEMP -ceq $Root -and [string]$Environment.TMP -ceq $Root -and
        [string]$Environment.USERPROFILE -ceq $Root -and [string]$Environment.APPDATA -ceq $Root -and
        [string]$Environment.LOCALAPPDATA -ceq $Root -and [string]$Environment.HOMEDRIVE -ceq $drive -and
        [string]$Environment.HOMEPATH -ceq $homePath)
}

function New-D32BoundedDiagnosticSourceProofNonSourceL1RootSecurity {
    param([Parameter(Mandatory = $true)][string]$OwnerSid)
    if ($OwnerSid -cnotmatch '^S-1-[0-9-]{5,80}$') { throw 'D32_NON_SOURCE_L1_ROOT_BLOCKED: owner SID is malformed' }
    $owner = [Security.Principal.SecurityIdentifier]::new($OwnerSid)
    $trustedWriterSids = @(
        'S-1-5-18',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464',
        'S-1-5-32-544')
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($owner)
    $security.SetAccessRuleProtection($true, $false)
    $principals = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    [void]$principals.Add($OwnerSid)
    foreach ($sid in $trustedWriterSids) { [void]$principals.Add($sid) }
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in $principals) {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity, [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    return $security
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1RootSecurity {
    param([AllowNull()][object]$Security, [Parameter(Mandatory = $true)][string]$OwnerSid)
    if ($null -eq $Security -or $Security -isnot [Security.AccessControl.DirectorySecurity] -or
        $OwnerSid -cnotmatch '^S-1-[0-9-]{5,80}$' -or -not $Security.AreAccessRulesProtected -or -not $Security.AreAccessRulesCanonical) { return $false }
    try { if ([string]$Security.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $OwnerSid) { return $false } }
    catch { return $false }
    $expectedSids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    [void]$expectedSids.Add($OwnerSid)
    foreach ($sid in @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544')) { [void]$expectedSids.Add($sid) }
    $rules = @($Security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne $expectedSids.Count) { return $false }
    $observedSids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $expectedInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($rule in $rules) {
        $sid = [string]$rule.IdentityReference.Value
        if (-not $expectedSids.Contains($sid) -or -not $observedSids.Add($sid) -or $rule.IsInherited -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            [Int64]$rule.FileSystemRights -ne [Int64][Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne $expectedInheritance -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { return $false }
    }
    return ($observedSids.Count -eq $expectedSids.Count)
}

function Get-D32BoundedDiagnosticSourceProofNonSourceL1DerivedEntryMismatchSha256 {
    param([Parameter(Mandatory = $true)][string]$Sha256)
    if ($Sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'D32_NON_SOURCE_L1_REFUSED: fixed entry pin is malformed' }
    $firstNibble = [Convert]::ToInt32($Sha256.Substring(0, 1), 16) -bxor 1
    return $firstNibble.ToString('x1', [Globalization.CultureInfo]::InvariantCulture) + $Sha256.Substring(1)
}

function ConvertTo-D32BoundedDiagnosticSourceProofNonSourceL1WindowsArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    if ($Value.Length -gt 0 -and $Value.IndexOfAny([char[]]@(' ', "`t", "`n", [char]11, '"')) -lt 0) { return $Value }
    $builder = [Text.StringBuilder]::new(); [void]$builder.Append('"'); $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) { $slashes++; continue }
        if ($character -eq [char]34) {
            for ($index = 0; $index -lt (($slashes * 2) + 1); $index++) { [void]$builder.Append([char]92) }
            [void]$builder.Append([char]34); $slashes = 0; continue
        }
        for ($index = 0; $index -lt $slashes; $index++) { [void]$builder.Append([char]92) }
        $slashes = 0; [void]$builder.Append($character)
    }
    for ($index = 0; $index -lt ($slashes * 2); $index++) { [void]$builder.Append([char]92) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Get-D32BoundedDiagnosticSourceProofNonSourceL1ExpectedReaderArguments {
    param([Parameter(Mandatory = $true)][object]$Record, [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][string]$OuterPrelaunchBindingSha256,
        [Parameter(Mandatory = $true)][string]$ControllerRuntimeAdmissionSha256)
    if ($OuterPrelaunchBindingSha256 -cnotmatch '^[0-9a-f]{64}$' -or $ControllerRuntimeAdmissionSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'D32_NON_SOURCE_L1_REFUSED: reader outer binding or controller admission pin is malformed'
    }
    $culture = [Globalization.CultureInfo]::InvariantCulture
    return @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', [string]$Record.source_pins[1].path,
        '-NonSourceL1', '-L1AuthorityPath', [string]$Record.authority.path,
        '-ExpectedL1AuthoritySha256', [string]$Record.authority.sha256,
        '-L1CandidateSha', [string]$Record.candidate_sha, '-L1BatchId', [string]$Record.batch_id,
        '-L1CaseId', [string]$Case.case_id, '-L1Nonce', [string]$Case.case_nonce,
        '-L1T0Ticks', ([Int64]$Record.clock.batch_t0_ticks).ToString($culture),
        '-L1CounterFrequency', ([Int64]$Record.clock.frequency).ToString($culture),
        '-L1CaseT0Ticks', ([Int64]$Case.case_t0_ticks).ToString($culture),
        '-L1ActiveDeadlineTicks', ([Int64]$Case.active_deadline_ticks).ToString($culture),
        '-ExpectedOuterPrelaunchBindingSha256', $OuterPrelaunchBindingSha256,
        '-ExpectedControllerRuntimeAdmissionSha256', $ControllerRuntimeAdmissionSha256)
}

function Get-D32BoundedDiagnosticSourceProofNonSourceL1EnvironmentEntries {
    param([Parameter(Mandatory = $true)][object]$Environment)
    $names = @('SystemRoot', 'WINDIR', 'PATH', 'PSHOME', 'PSModulePath', 'PSModuleAutoLoadingPreference',
        'POWERSHELL_TELEMETRY_OPTOUT', 'DOTNET_CLI_TELEMETRY_OPTOUT', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'HOMEDRIVE', 'HOMEPATH')
    $entries = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $names) { $entries.Add(('{0}={1}' -f $name, [string]$Environment.$name)) }
    $array = $entries.ToArray(); [Array]::Sort($array, [StringComparer]::OrdinalIgnoreCase)
    return ,$array
}

function Get-D32BoundedDiagnosticSourceProofNonSourceL1EnvironmentBlockSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Entries)
    $block = [string]::Join("`0", $Entries) + "`0`0"
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::Unicode.GetBytes($block))).ToLowerInvariant()
}

function Get-D32BoundedDiagnosticSourceProofNonSourceL1CaseEvidenceSha256 {
    param([AllowNull()][object]$CaseNonce, [AllowNull()][object]$PrecreateAdmission, [AllowNull()][object]$ActualInvocation)
    $evidence = [PSCustomObject][ordered]@{
        case_nonce = $CaseNonce
        precreate_admission = $PrecreateAdmission
        actual_invocation = $ActualInvocation
    }
    $json = ConvertTo-Json -InputObject $evidence -Depth 32 -Compress -ErrorAction Stop
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($json))).ToLowerInvariant()
}

function Get-D32BoundedDiagnosticSourceProofNonSourceL1ExpectedCommandLine {
    param([Parameter(Mandatory = $true)][string]$Image, [Parameter(Mandatory = $true)][string[]]$Arguments)
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add((ConvertTo-D32BoundedDiagnosticSourceProofNonSourceL1WindowsArgument -Value $Image))
    foreach ($argument in $Arguments) { $parts.Add((ConvertTo-D32BoundedDiagnosticSourceProofNonSourceL1WindowsArgument -Value ([string]$argument))) }
    return [string]::Join(' ', $parts.ToArray())
}

function Get-D32BoundedDiagnosticSourceProofNonSourceL1CaseDeadlines {
    param([Parameter(Mandatory = $true)][long]$CaseT0Ticks, [Parameter(Mandatory = $true)][long]$Frequency,
        [Parameter(Mandatory = $true)][long]$BatchDeadlineTicks)
    if ($CaseT0Ticks -le 0 -or $Frequency -le 0 -or $BatchDeadlineTicks -le $CaseT0Ticks) { throw 'D32_NON_SOURCE_L1_BLOCKED: invalid case/batch clock binding' }
    return [PSCustomObject][ordered]@{
        active_deadline_ticks = [Int64][Math]::Min((ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $CaseT0Ticks -Frequency $Frequency -DeadlineMilliseconds 5000L), $BatchDeadlineTicks)
        cleanup_deadline_ticks = [Int64][Math]::Min((ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $CaseT0Ticks -Frequency $Frequency -DeadlineMilliseconds 10000L), $BatchDeadlineTicks)
        audit_deadline_ticks = [Int64][Math]::Min((ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $CaseT0Ticks -Frequency $Frequency -DeadlineMilliseconds 15000L), $BatchDeadlineTicks)
    }
}

function Get-D32BoundedDiagnosticSourceProofNonSourceL1Phase {
    param([Parameter(Mandatory = $true)][long]$NowTicks, [Parameter(Mandatory = $true)][long]$CaseT0Ticks,
        [Parameter(Mandatory = $true)][long]$Frequency, [Parameter(Mandatory = $true)][long]$BatchT0Ticks,
        [Parameter(Mandatory = $true)][long]$BatchDeadlineTicks)
    if ($NowTicks -lt $CaseT0Ticks -or $CaseT0Ticks -lt $BatchT0Ticks) { throw 'D32_NON_SOURCE_L1_BLOCKED: monotonic clock rollback or case reset detected' }
    $deadlines = Get-D32BoundedDiagnosticSourceProofNonSourceL1CaseDeadlines -CaseT0Ticks $CaseT0Ticks -Frequency $Frequency -BatchDeadlineTicks $BatchDeadlineTicks
    if ($NowTicks -lt $deadlines.active_deadline_ticks) { return 'ACTIVE' }
    if ($NowTicks -lt $deadlines.cleanup_deadline_ticks) { return 'CLEANUP' }
    if ($NowTicks -lt $deadlines.audit_deadline_ticks) { return 'AUDIT' }
    if ($NowTicks -lt $BatchDeadlineTicks) { return 'AUDIT' }
    return 'BATCH_EXPIRED'
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShapeV1Internal {
    param([AllowNull()][object]$Document, [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository)
    $fields = @('schema_version', 'record_type', 'purpose', 'policy', 'gate_authority', 'candidate_sha', 'source_repo',
        'repository_identity', 'batch_id', 'run_id', 'owner_id', 'source_pins', 'powershell_runtime', 'invocation', 'cases',
        'output', 'limits', 'issued_at_utc')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document $fields) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Document.schema_version -Positive) -or [Int64]$Document.schema_version -ne 1 -or
        $Document.record_type -isnot [string] -or [string]$Document.record_type -cne 'D32_BOUNDED_SOURCEPROOF_NON_SOURCE_L1_AUTHORITY_V1' -or
        $Document.purpose -isnot [string] -or [string]$Document.purpose -cne 'NATIVE_LIFECYCLE_VALIDATION_ONLY' -or
        $Document.policy -isnot [string] -or [string]$Document.policy -cne 'D32_SOURCEPROOF_NON_SOURCE_L1_V1' -or
        $Document.gate_authority -isnot [string] -or [string]$Document.gate_authority -cne 'NONE' -or
        $Document.candidate_sha -isnot [string] -or [string]$Document.candidate_sha -cne $ExpectedCandidateSha -or $ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.source_repo) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Document.source_repo, [IO.Path]::GetFullPath($Repository)) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.repository_identity @('volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Document.repository_identity) -or
        [string]$Document.batch_id -cnotmatch '^[0-9a-f]{32}$' -or [string]$Document.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        $Document.owner_id -isnot [string] -or [string]$Document.owner_id -cnotmatch '^[A-Za-z0-9._:-]{1,128}$') { return $false }

    $expectedPaths = Get-D32BoundedDiagnosticSourceProofNonSourceL1SourcePaths -Repository $Repository
    if ($Document.source_pins -isnot [Array] -or $Document.source_pins.Count -ne 6) { return $false }
    for ($index = 0; $index -lt 6; $index++) {
        $pin = $Document.source_pins[$index]
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $pin) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$pin.path, [string]$expectedPaths[$index]) -or
            -not (Test-D32BoundedCompilerDiagnosticWithin ([string]$pin.path) $Repository)) { return $false }
    }
    $runtimeFields = @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex', 'powershell_home', 'system_root')
    $runtime = $Document.powershell_runtime
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $runtime $runtimeFields) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape ([PSCustomObject]@{ path = $runtime.path; bytes = $runtime.bytes; sha256 = $runtime.sha256; volume_serial_hex = $runtime.volume_serial_hex; file_id_hex = $runtime.file_id_hex })) -or
        [string]$runtime.path -cnotmatch '^[A-Za-z]:\\Program Files\\PowerShell\\7\\pwsh\.exe$' -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $runtime.powershell_home) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$runtime.path), [string]$runtime.powershell_home) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $runtime.system_root)) { return $false }

    $outputFields = @('root_path', 'parent_path', 'root_volume_serial_hex', 'root_file_id_hex', 'parent_volume_serial_hex', 'parent_file_id_hex', 'result_path', 'journal_path')
    $output = $Document.output
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $output $outputFields) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.root_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$output.root_path), [string]$output.parent_path) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $output -VolumeName 'parent_volume_serial_hex' -FileIdName 'parent_file_id_hex') -or
        [string]$output.root_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$output.root_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.result_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.journal_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$output.result_path), [string]$output.root_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$output.journal_path), [string]$output.root_path) -or
        [string]$output.result_path -ceq [string]$output.journal_path -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFileName([string]$output.result_path), ('D32-NSL1-' + [string]$Document.batch_id + '.json')) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFileName([string]$output.journal_path), ('D32-NSL1-' + [string]$Document.batch_id + '.jsonl')) -or
        (Test-D32BoundedCompilerDiagnosticWithin ([string]$output.root_path) $Repository) -or
        (Test-D32BoundedCompilerDiagnosticWithin ([string]$output.root_path) 'E:\d32\inv7\r\c')) { return $false }

    $invocationFields = @('role', 'entry_path', 'working_directory', 'argument_policy', 'environment_policy', 'child_environment')
    $invocation = $Document.invocation
    $entryPath = [string]$expectedPaths[1]
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $invocation $invocationFields) -or
        [string]$invocation.role -cne 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_V1' -or
        [string]$invocation.entry_path -cne $entryPath -or [string]$invocation.working_directory -cne [string]$output.root_path -or
        [string]$invocation.argument_policy -cne 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_ARGV_V1' -or
        [string]$invocation.environment_policy -cne 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_ENV_V1' -or
        -not (Test-D32BoundedDiagnosticSourceProofNonSourceL1Environment -Environment $invocation.child_environment -Runtime $runtime -Root ([string]$output.root_path))) { return $false }

    if ($Document.cases -isnot [Array] -or $Document.cases.Count -ne 3) { return $false }
    $caseIds = @('NORMAL_EXIT', 'FORCED_OWNED_TERMINATION', 'ENTRY_PIN_BINDING_REFUSAL')
    $behaviors = @('FINITE_TOKEN_EXIT_0', 'READY_THEN_FINITE_WAIT', 'DERIVED_ENTRY_SHA_MISMATCH')
    $createCounts = @(1L, 1L, 0L)
    $seenNonces = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($index = 0; $index -lt 3; $index++) {
        $case = $Document.cases[$index]
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $case @('case_id', 'behavior', 'expected_create_attempts', 'nonce')) -or
            $case.case_id -isnot [string] -or [string]$case.case_id -cne $caseIds[$index] -or
            $case.behavior -isnot [string] -or [string]$case.behavior -cne $behaviors[$index] -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $case.expected_create_attempts) -or [Int64]$case.expected_create_attempts -ne $createCounts[$index] -or
            $case.nonce -isnot [string] -or [string]$case.nonce -cnotmatch '^[0-9a-f]{32}$' -or -not $seenNonces.Add([string]$case.nonce)) { return $false }
    }
    $limitFields = @('batch_milliseconds', 'active_milliseconds', 'cleanup_milliseconds', 'audit_milliseconds', 'stdout_max_bytes', 'stderr_max_bytes',
        'expected_output_max_bytes', 'owned_buffer_max_bytes', 'result_max_bytes', 'journal_max_bytes', 'max_create_process_attempts', 'fixed_case_count')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.limits $limitFields)) { return $false }
    foreach ($field in $limitFields) {
        if (-not (Test-D32BoundedCompilerDiagnosticInteger $Document.limits.($field) -Positive) -or
            [Int64]$Document.limits.($field) -ne [Int64]$script:D32BoundedDiagnosticSourceProofNonSourceL1Limits.($field)) { return $false }
    }
    try { $null = [DateTimeOffset]::Parse([string]$Document.issued_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
    catch { return $false }
    return $true
}

function New-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityCandidateV1Internal {
    param([Parameter(Mandatory = $true)][string]$CandidateSha, [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][object]$RepositoryIdentity, [Parameter(Mandatory = $true)][string]$BatchId,
        [Parameter(Mandatory = $true)][string]$RunId, [Parameter(Mandatory = $true)][string]$OwnerId,
        [Parameter(Mandatory = $true)][object[]]$SourcePins, [Parameter(Mandatory = $true)][object]$PowerShellRuntime,
        [Parameter(Mandatory = $true)][object]$Invocation, [Parameter(Mandatory = $true)][object[]]$Cases,
        [Parameter(Mandatory = $true)][object]$Output, [string]$IssuedAtUtc = [DateTimeOffset]::UtcNow.ToString('o'))
    return [PSCustomObject][ordered]@{
        schema_version = 1; record_type = $script:D32BoundedDiagnosticSourceProofNonSourceL1AuthorityType
        purpose = 'NATIVE_LIFECYCLE_VALIDATION_ONLY'; policy = $script:D32BoundedDiagnosticSourceProofNonSourceL1Policy; gate_authority = 'NONE'
        candidate_sha = $CandidateSha; source_repo = $Repository; repository_identity = $RepositoryIdentity
        batch_id = $BatchId; run_id = $RunId; owner_id = $OwnerId; source_pins = @($SourcePins)
        powershell_runtime = $PowerShellRuntime; invocation = $Invocation; cases = @($Cases); output = $Output
        limits = $script:D32BoundedDiagnosticSourceProofNonSourceL1Limits; issued_at_utc = $IssuedAtUtc
    }
}

function Resolve-D32BoundedDiagnosticSourceProofNonSourceL1BatchOutcome {
    param([Parameter(Mandatory = $true)][object[]]$Cases,
        [Parameter(Mandatory = $true)][long]$CreateProcessAttemptCount,
        [Parameter(Mandatory = $true)][long]$PlannedTerminationCount,
        [Parameter(Mandatory = $true)][long]$FailSafeTerminationCount,
        [Parameter(Mandatory = $true)][bool]$BatchDeadlineReached)
    if ($Cases.Count -ne 3) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: fixed batch outcome requires exactly three ordered case rows' }
    $expectedIds = @('NORMAL_EXIT', 'FORCED_OWNED_TERMINATION', 'ENTRY_PIN_BINDING_REFUSAL')
    for ($index = 0; $index -lt 3; $index++) {
        if ([string]$Cases[$index].case_id -cne $expectedIds[$index]) { throw 'D32_NON_SOURCE_L1_UNRESOLVED: fixed batch outcome case order is malformed' }
    }
    if ([string]$Cases[0].state -ceq 'NATIVE_BOUNDARY_VERIFIED' -and
        [string]$Cases[1].state -ceq 'NATIVE_BOUNDARY_VERIFIED' -and
        [string]$Cases[2].state -ceq 'EXPECTED_REFUSAL_VERIFIED' -and
        $CreateProcessAttemptCount -eq 2L -and $PlannedTerminationCount -eq 1L -and $FailSafeTerminationCount -eq 0L) {
        return [PSCustomObject][ordered]@{ status = 'COMPLETE_NON_SOURCE_L1'; primary_error = $null }
    }
    $unresolved = $null; $budgetStopped = $null; $failedCase = $null
    foreach ($case in $Cases) {
        if ($null -eq $unresolved -and [string]$case.state -ceq 'UNRESOLVED') { $unresolved = $case }
        if ($null -eq $budgetStopped -and [string]$case.state -ceq 'BUDGET_STOPPED') { $budgetStopped = $case }
        if ($null -eq $failedCase -and [string]$case.state -cnotin @('NATIVE_BOUNDARY_VERIFIED', 'EXPECTED_REFUSAL_VERIFIED', 'NOT_RUN')) { $failedCase = $case }
    }
    if ($null -ne $unresolved) {
        return [PSCustomObject][ordered]@{ status = 'UNRESOLVED'; primary_error = [string]$unresolved.primary_error }
    }
    if ($null -ne $budgetStopped) {
        return [PSCustomObject][ordered]@{ status = 'BUDGET_STOPPED'; primary_error = [string]$budgetStopped.primary_error }
    }
    if ($BatchDeadlineReached) {
        return [PSCustomObject][ordered]@{ status = 'BUDGET_STOPPED'; primary_error = 'batch deadline reached before all fixed cases completed' }
    }
    $primary = if ($null -ne $failedCase -and -not [String]::IsNullOrWhiteSpace([string]$failedCase.primary_error)) {
        [string]$failedCase.primary_error
    } else { 'one or more fixed NON_SOURCE_L1 cases did not meet the contracted native boundary' }
    return [PSCustomObject][ordered]@{ status = 'BLOCKED'; primary_error = $primary }
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1PrecreateAdmission {
    param([AllowNull()][object]$Admission, [Parameter(Mandatory = $true)][object]$Record)
    if ($null -eq $Admission) { return $false }
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Admission @('decision', 'observed_ticks', 'entry_reference', 'entry_expected_sha256', 'entry_observed_sha256', 'runtime_reference', 'runtime_expected_sha256', 'runtime_observed_sha256', 'refusal_reason')) -or
        [string]$Admission.decision -cnotin @('ADMITTED', 'ENTRY_PIN_BINDING_REFUSAL') -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Admission.observed_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Admission.entry_reference) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Admission.runtime_reference) -or
        [string]$Admission.entry_expected_sha256 -cnotmatch '^[0-9a-f]{64}$' -or [string]$Admission.entry_observed_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Admission.runtime_expected_sha256 -cnotmatch '^[0-9a-f]{64}$' -or [string]$Admission.runtime_observed_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Admission.entry_reference.path -cne [string]$Record.source_pins[1].path -or
        [string]$Admission.runtime_reference.path -cne [string]$Record.powershell_runtime.path -or
        [string]$Admission.runtime_reference.sha256 -cne [string]$Admission.runtime_observed_sha256 -or
        [string]$Admission.runtime_expected_sha256 -cne [string]$Admission.runtime_observed_sha256) { return $false }
    if ([string]$Admission.decision -ceq 'ADMITTED') {
        return ([string]$Admission.entry_expected_sha256 -ceq [string]$Admission.entry_observed_sha256 -and $null -eq $Admission.refusal_reason -and
            [string]$Admission.entry_reference.sha256 -ceq [string]$Admission.entry_observed_sha256)
    }
    return ([string]$Admission.refusal_reason -ceq 'ENTRY_SHA_MISMATCH' -and
        [string]$Admission.entry_expected_sha256 -cne [string]$Admission.entry_observed_sha256 -and
        [string]$Admission.entry_reference.sha256 -ceq [string]$Admission.entry_observed_sha256)
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1ActualInvocation {
    param([AllowNull()][object]$Invocation, [Parameter(Mandatory = $true)][object]$Record,
        [Parameter(Mandatory = $true)][object]$Case, [Parameter(Mandatory = $true)][object]$Admission,
        [Parameter(Mandatory = $true)][object[]]$RuntimeAdmissions)
    if ($null -eq $Invocation -or $null -eq $Admission -or [string]$Admission.decision -cne 'ADMITTED') { return $false }
    $fields = @('case_id', 'case_nonce', 'batch_t0_ticks', 'case_t0_ticks', 'counter_frequency', 'active_deadline_ticks',
        'entry_reference', 'executable_reference', 'admission_observed_ticks', 'image_path', 'arguments', 'raw_command_line', 'working_directory',
        'environment_entries', 'environment_block_sha256', 'inherit_handles', 'handle_list_applied', 'handle_roles', 'handle_observations',
        'creation_flags', 'api_attempted', 'api_attempt_ticks', 'api_returned', 'api_error_code', 'process_id', 'creation_filetime_ticks',
        'process_image_path', 'process_image_binding_verified')
    $observationFields = @('stdin_inheritable', 'stdout_write_inheritable', 'stderr_write_inheritable', 'stdout_read_inheritable', 'stderr_read_inheritable')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Invocation $fields) -or
        [string]$Invocation.case_id -cne [string]$Case.case_id -or [string]$Invocation.case_nonce -cne [string]$Case.case_nonce -or
        [Int64]$Invocation.batch_t0_ticks -ne [Int64]$Record.clock.batch_t0_ticks -or
        [Int64]$Invocation.case_t0_ticks -ne [Int64]$Case.case_t0_ticks -or
        [Int64]$Invocation.counter_frequency -ne [Int64]$Record.clock.frequency -or
        [Int64]$Invocation.active_deadline_ticks -ne [Int64]$Case.active_deadline_ticks -or
        [Int64]$Invocation.admission_observed_ticks -ne [Int64]$Admission.observed_ticks -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Invocation.entry_reference) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Invocation.executable_reference) -or
        [string]$Invocation.entry_reference.path -cne [string]$Admission.entry_reference.path -or
        [string]$Invocation.entry_reference.sha256 -cne [string]$Admission.entry_reference.sha256 -or
        [string]$Invocation.executable_reference.path -cne [string]$Admission.runtime_reference.path -or
        [string]$Invocation.executable_reference.sha256 -cne [string]$Admission.runtime_reference.sha256 -or
        [string]$Invocation.image_path -cne [string]$Record.powershell_runtime.path -or
        [string]$Invocation.working_directory -cne [string]$Record.output.root_path -or
        [string]$Invocation.raw_command_line -isnot [string] -or ([string]$Invocation.raw_command_line).Length -ge 32767 -or
        [string]$Invocation.environment_block_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Invocation.arguments -isnot [Array] -or $Invocation.environment_entries -isnot [Array] -or $Invocation.handle_roles -isnot [Array] -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Invocation.creation_flags -Positive) -or
        [UInt32]$Invocation.creation_flags -ne [UInt32]$script:D32BoundedDiagnosticSourceProofNonSourceL1CreateFlags -or
        $Invocation.inherit_handles -isnot [bool] -or $Invocation.handle_list_applied -isnot [bool] -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Invocation.handle_observations $observationFields) -or
        $Invocation.api_attempted -isnot [bool] -or
        -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $Invocation.api_attempt_ticks) -or
        ($null -ne $Invocation.api_returned -and $Invocation.api_returned -isnot [bool]) -or
        ($null -ne $Invocation.api_error_code -and (-not (Test-D32BoundedCompilerDiagnosticInteger $Invocation.api_error_code) -or [Int64]$Invocation.api_error_code -gt [Int64][Int32]::MaxValue)) -or
        -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $Invocation.process_id) -or
        -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $Invocation.creation_filetime_ticks) -or
        (($null -ne $Invocation.process_image_path) -and -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Invocation.process_image_path)) -or
        $Invocation.process_image_binding_verified -isnot [bool]) { return $false }
    if ($RuntimeAdmissions.Count -ne 3 -or [string]$RuntimeAdmissions[0].role -cne 'CONTROLLER' -or
        [string]$RuntimeAdmissions[0].status -cne 'ADMITTED' -or $null -eq $RuntimeAdmissions[0].reference -or
        $null -eq $RuntimeAdmissions[0].admission -or $RuntimeAdmissions[0].admission.startup.arguments -isnot [Array]) { return $false }
    $controllerArguments = [string[]]$RuntimeAdmissions[0].admission.startup.arguments
    $bindingIndices = [System.Collections.Generic.List[int]]::new()
    for ($index = 0; $index -lt $controllerArguments.Count; $index++) {
        if ($controllerArguments[$index] -ceq '-ExpectedOuterPrelaunchBindingSha256') { $bindingIndices.Add($index) }
    }
    if ($bindingIndices.Count -ne 1 -or $bindingIndices[0] + 1 -ge $controllerArguments.Count -or
        $controllerArguments[$bindingIndices[0]] -ne '-ExpectedOuterPrelaunchBindingSha256' -or
        [string]$controllerArguments[$bindingIndices[0] + 1] -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$RuntimeAdmissions[0].reference.sha256 -cnotmatch '^[0-9a-f]{64}$') { return $false }
    $expectedArguments = Get-D32BoundedDiagnosticSourceProofNonSourceL1ExpectedReaderArguments -Record $Record -Case $Case `
        -OuterPrelaunchBindingSha256 ([string]$controllerArguments[$bindingIndices[0] + 1]) `
        -ControllerRuntimeAdmissionSha256 ([string]$RuntimeAdmissions[0].reference.sha256)
    if ($Invocation.arguments.Count -ne $expectedArguments.Count) { return $false }
    for ($index = 0; $index -lt $expectedArguments.Count; $index++) {
        if ($Invocation.arguments[$index] -isnot [string] -or [string]$Invocation.arguments[$index] -cne [string]$expectedArguments[$index]) { return $false }
    }
    if ([string]$Invocation.raw_command_line -cne (Get-D32BoundedDiagnosticSourceProofNonSourceL1ExpectedCommandLine -Image ([string]$Record.powershell_runtime.path) -Arguments $expectedArguments)) { return $false }
    $environmentNames = @('APPDATA', 'DOTNET_CLI_TELEMETRY_OPTOUT', 'HOMEDRIVE', 'HOMEPATH', 'LOCALAPPDATA', 'PATH', 'PSHOME',
        'PSModuleAutoLoadingPreference', 'PSModulePath', 'SystemRoot', 'TEMP', 'TMP', 'USERPROFILE', 'WINDIR', 'POWERSHELL_TELEMETRY_OPTOUT')
    $actualEnvironmentNames = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $Invocation.environment_entries) {
        if ($entry -isnot [string]) { return $false }
        $separator = ([string]$entry).IndexOf('=')
        if ($separator -le 0) { return $false }
        $actualEnvironmentNames.Add(([string]$entry).Substring(0, $separator))
    }
    $sortedEnvironmentNames = $actualEnvironmentNames.ToArray(); [Array]::Sort($sortedEnvironmentNames, [StringComparer]::OrdinalIgnoreCase)
    [Array]::Sort($environmentNames, [StringComparer]::OrdinalIgnoreCase)
    if ($sortedEnvironmentNames.Count -ne $environmentNames.Count) { return $false }
    for ($index = 0; $index -lt $environmentNames.Count; $index++) {
        if ([string]$sortedEnvironmentNames[$index] -cne [string]$environmentNames[$index]) { return $false }
    }
    if ([string]$Invocation.environment_block_sha256 -cne (Get-D32BoundedDiagnosticSourceProofNonSourceL1EnvironmentBlockSha256 -Entries ([string[]]$Invocation.environment_entries))) { return $false }
    if ($Invocation.handle_roles.Count -ne $script:D32BoundedDiagnosticSourceProofNonSourceL1HandleRoles.Count) { return $false }
    for ($index = 0; $index -lt $script:D32BoundedDiagnosticSourceProofNonSourceL1HandleRoles.Count; $index++) {
        if ([string]$Invocation.handle_roles[$index] -cne [string]$script:D32BoundedDiagnosticSourceProofNonSourceL1HandleRoles[$index]) { return $false }
    }
    foreach ($name in $observationFields) { if ($null -ne $Invocation.handle_observations.$name -and $Invocation.handle_observations.$name -isnot [bool]) { return $false } }
    if ($Invocation.api_attempted) {
        if ($null -eq $Invocation.api_attempt_ticks -or $null -eq $Invocation.api_returned -or
            $Invocation.inherit_handles -ne $true -or -not $Invocation.handle_list_applied -or
            $Invocation.handle_observations.stdin_inheritable -ne $true -or $Invocation.handle_observations.stdout_write_inheritable -ne $true -or
            $Invocation.handle_observations.stderr_write_inheritable -ne $true -or $Invocation.handle_observations.stdout_read_inheritable -ne $false -or
            $Invocation.handle_observations.stderr_read_inheritable -ne $false) { return $false }
        if ($Invocation.api_returned) {
            if ($null -ne $Invocation.api_error_code -or $null -eq $Invocation.process_id) { return $false }
        } elseif ($null -eq $Invocation.api_error_code -or $null -ne $Invocation.process_id -or
            $null -ne $Invocation.creation_filetime_ticks -or $null -ne $Invocation.process_image_path -or $Invocation.process_image_binding_verified) { return $false }
    } elseif ($null -ne $Invocation.api_attempt_ticks -or $null -ne $Invocation.api_returned -or $null -ne $Invocation.api_error_code -or
        $null -ne $Invocation.process_id -or $null -ne $Invocation.creation_filetime_ticks -or $null -ne $Invocation.process_image_path -or
        $Invocation.process_image_binding_verified) { return $false }
    if ($null -eq $Invocation.process_image_path) { return (-not $Invocation.process_image_binding_verified) }
    return ($Invocation.process_image_binding_verified -eq [StringComparer]::OrdinalIgnoreCase.Equals([string]$Invocation.process_image_path, [string]$Record.powershell_runtime.path))
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShapeV1Internal {
    param([AllowNull()][object]$Record, [object[]]$RuntimeAdmissions = @())
    $fields = @('schema_version', 'record_type', 'purpose', 'policy', 'gate_authority', 'candidate_sha', 'batch_id', 'run_id', 'authority',
        'source_pins', 'powershell_runtime', 'output', 'clock', 'controller', 'cases', 'create_process_attempt_count', 'planned_termination_count',
        'fail_safe_termination_count', 'abrupt_owner_abort', 'status', 'source_proof_checkpoint', 'source_closure', 'diagnostic_invocation_authority',
        'formal_gate_usable', 'formal_phase_allowed', 'formal_aggregate_allowed', 'primary_error', 'secondary_errors', 'started_at_utc', 'completed_at_utc')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record $fields) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.schema_version -Positive) -or [Int64]$Record.schema_version -ne 1 -or
        [string]$Record.record_type -cne 'D32_BOUNDED_SOURCEPROOF_NON_SOURCE_L1_V1' -or
        [string]$Record.purpose -cne 'NATIVE_LIFECYCLE_VALIDATION_ONLY' -or [string]$Record.policy -cne 'D32_SOURCEPROOF_NON_SOURCE_L1_V1' -or
        [string]$Record.gate_authority -cne 'NONE' -or [string]$Record.candidate_sha -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Record.batch_id -cnotmatch '^[0-9a-f]{32}$' -or [string]$Record.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Record.authority) -or
        $Record.source_pins -isnot [Array] -or $Record.source_pins.Count -ne 6 -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape ([PSCustomObject]@{ path = $Record.powershell_runtime.path; bytes = $Record.powershell_runtime.bytes; sha256 = $Record.powershell_runtime.sha256; volume_serial_hex = $Record.powershell_runtime.volume_serial_hex; file_id_hex = $Record.powershell_runtime.file_id_hex })) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.powershell_runtime @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.output @('root_path', 'parent_path', 'root_volume_serial_hex', 'root_file_id_hex', 'parent_volume_serial_hex', 'parent_file_id_hex', 'result_path', 'journal_path')) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.output.root_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$Record.output.root_path), [string]$Record.output.parent_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.output.result_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.output.journal_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$Record.output.result_path), [string]$Record.output.root_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$Record.output.journal_path), [string]$Record.output.root_path) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Record.output -VolumeName 'root_volume_serial_hex' -FileIdName 'root_file_id_hex') -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Record.output -VolumeName 'parent_volume_serial_hex' -FileIdName 'parent_file_id_hex') -or
        [string]$Record.status -cnotin @('COMPLETE_NON_SOURCE_L1', 'BLOCKED', 'BUDGET_STOPPED', 'REFUSED', 'UNRESOLVED') -or
        $Record.source_proof_checkpoint -isnot [bool] -or [bool]$Record.source_proof_checkpoint -or
        $Record.source_closure -isnot [bool] -or [bool]$Record.source_closure -or
        [string]$Record.diagnostic_invocation_authority -cne 'NONE' -or
        $Record.formal_gate_usable -isnot [bool] -or [bool]$Record.formal_gate_usable -or
        $Record.formal_phase_allowed -isnot [bool] -or [bool]$Record.formal_phase_allowed -or
        $Record.formal_aggregate_allowed -isnot [bool] -or [bool]$Record.formal_aggregate_allowed -or
        [string]$Record.abrupt_owner_abort -cne 'NOT_RUN' -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.create_process_attempt_count) -or [Int64]$Record.create_process_attempt_count -gt 2 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.planned_termination_count) -or [Int64]$Record.planned_termination_count -gt 1 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.fail_safe_termination_count) -or [Int64]$Record.fail_safe_termination_count -gt 2 -or
        $Record.cases -isnot [Array] -or $Record.cases.Count -ne 3 -or
        $Record.secondary_errors -isnot [Array] -or $Record.secondary_errors.Count -gt 8 -or
        (($null -ne $Record.primary_error) -and ($Record.primary_error -isnot [string] -or ([string]$Record.primary_error).Length -gt 2048))) { return $false }

    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.clock @('counter_origin', 'frequency', 'batch_t0_ticks', 'batch_deadline_ticks', 'controller_entry_ticks')) -or
        [string]$Record.clock.counter_origin -cne 'QueryPerformanceCounter' -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.clock.frequency -Positive) -or
        [Int64]$Record.clock.frequency -ne [Int64][Diagnostics.Stopwatch]::Frequency -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.clock.batch_t0_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.clock.batch_deadline_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.clock.controller_entry_ticks -Positive)) { return $false }
    try {
        if ([Int64]$Record.clock.batch_deadline_ticks -ne (ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks ([Int64]$Record.clock.batch_t0_ticks) -Frequency ([Int64]$Record.clock.frequency) -DeadlineMilliseconds 60000L) -or
            [Int64]$Record.clock.controller_entry_ticks -lt [Int64]$Record.clock.batch_t0_ticks -or
            [Int64]$Record.clock.controller_entry_ticks -ge [Int64]$Record.clock.batch_deadline_ticks) { return $false }
    } catch { return $false }
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.controller @('process_id', 'creation_filetime_ticks')) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.controller.process_id -Positive) -or
        -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $Record.controller.creation_filetime_ticks)) { return $false }

    $expectedCases = @('NORMAL_EXIT', 'FORCED_OWNED_TERMINATION', 'ENTRY_PIN_BINDING_REFUSAL')
    $createSum = [Int64]0; $termSum = [Int64]0; $failSafeSum = [Int64]0
    $caseSequenceClosed = $false
    $previousCaseCompletedTicks = [Int64]$Record.clock.controller_entry_ticks
    $emptyCaptureSha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    for ($index = 0; $index -lt 3; $index++) {
        $case = $Record.cases[$index]
        $caseFields = @('case_id', 'case_nonce', 'precreate_admission', 'actual_invocation', 'case_evidence_sha256', 'state', 'case_t0_ticks', 'active_deadline_ticks', 'cleanup_deadline_ticks', 'audit_deadline_ticks', 'admission_observed_ticks',
            'create_attempt_count', 'create_attempt_ticks', 'process_id', 'creation_filetime_ticks', 'process_image_path', 'process_image_binding_verified', 'job_instance_id', 'job_assigned', 'resume_ticks',
            'planned_termination_count', 'planned_termination_ticks', 'fail_safe_termination_count', 'fail_safe_termination_ticks',
            'exit_ticks', 'exit_code', 'job_active_process_count', 'job_total_process_count', 'kill_on_close_enabled', 'job_active_process_limit_one',
            'stdout_bytes', 'stdout_sha256', 'stdout_truncated', 'stdout_token_verified', 'stderr_bytes', 'stderr_sha256', 'stderr_truncated', 'stderr_token_verified', 'capture_join_verified',
            'job_closed', 'cleanup_observed_ticks', 'case_completed_ticks', 'primary_error', 'secondary_errors')
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $case $caseFields) -or
            [string]$case.case_id -cne $expectedCases[$index] -or
            [string]$case.state -cnotin @('NATIVE_BOUNDARY_VERIFIED', 'EXPECTED_REFUSAL_VERIFIED', 'BLOCKED', 'BUDGET_STOPPED', 'UNRESOLVED', 'NOT_RUN') -or
            (($null -ne $case.case_nonce) -and ($case.case_nonce -isnot [string] -or [string]$case.case_nonce -cnotmatch '^[0-9a-f]{32}$')) -or
            (($null -ne $case.case_evidence_sha256) -and [string]$case.case_evidence_sha256 -cnotmatch '^[0-9a-f]{64}$') -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $case.create_attempt_count) -or [Int64]$case.create_attempt_count -gt 1 -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $case.planned_termination_count) -or [Int64]$case.planned_termination_count -gt 1 -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $case.fail_safe_termination_count) -or [Int64]$case.fail_safe_termination_count -gt 1 -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.case_t0_ticks) -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.active_deadline_ticks) -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.cleanup_deadline_ticks) -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.audit_deadline_ticks) -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.admission_observed_ticks) -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.create_attempt_ticks) -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.process_id) -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.creation_filetime_ticks) -or
            (($null -ne $case.process_image_path) -and -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $case.process_image_path)) -or
            $case.process_image_binding_verified -isnot [bool] -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.resume_ticks) -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.planned_termination_ticks) -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.fail_safe_termination_ticks) -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.exit_ticks) -or
            (($null -ne $case.exit_code) -and -not (Test-D32BoundedDiagnosticNonSourceL1ExitCode $case.exit_code)) -or
            (($null -ne $case.job_active_process_count) -and -not (Test-D32BoundedCompilerDiagnosticInteger $case.job_active_process_count)) -or
            (($null -ne $case.job_total_process_count) -and -not (Test-D32BoundedCompilerDiagnosticInteger $case.job_total_process_count)) -or
            (($null -ne $case.job_instance_id) -and [string]$case.job_instance_id -cnotmatch '^[0-9a-f]{32}$') -or
            $case.job_assigned -isnot [bool] -or $case.kill_on_close_enabled -isnot [bool] -or $case.job_active_process_limit_one -isnot [bool] -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $case.stdout_bytes) -or [Int64]$case.stdout_bytes -gt 16000 -or
            [string]$case.stdout_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $case.stdout_truncated -isnot [bool] -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $case.stderr_bytes) -or [Int64]$case.stderr_bytes -gt 16000 -or
            [string]$case.stderr_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $case.stderr_truncated -isnot [bool] -or
            $case.stdout_token_verified -isnot [bool] -or $case.stderr_token_verified -isnot [bool] -or
            $case.capture_join_verified -isnot [bool] -or $case.job_closed -isnot [bool] -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.cleanup_observed_ticks) -or
            -not (Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger $case.case_completed_ticks) -or
            (($null -ne $case.primary_error) -and ($case.primary_error -isnot [string] -or ([string]$case.primary_error).Length -gt 2048)) -or
            $case.secondary_errors -isnot [Array] -or $case.secondary_errors.Count -gt 8) { return $false }
        if ([string]$case.state -ceq 'NOT_RUN') {
            $caseSequenceClosed = $true
            foreach ($name in @('case_t0_ticks', 'active_deadline_ticks', 'cleanup_deadline_ticks', 'audit_deadline_ticks', 'admission_observed_ticks',
                'create_attempt_ticks', 'process_id', 'creation_filetime_ticks', 'process_image_path', 'job_instance_id', 'resume_ticks',
                'planned_termination_ticks', 'fail_safe_termination_ticks', 'exit_ticks', 'exit_code', 'job_active_process_count', 'job_total_process_count',
                'cleanup_observed_ticks', 'case_completed_ticks')) { if ($null -ne $case.$name) { return $false } }
            if ($null -ne $case.case_nonce -or $null -ne $case.precreate_admission -or $null -ne $case.actual_invocation -or $null -ne $case.case_evidence_sha256 -or
                [Int64]$case.create_attempt_count -ne 0 -or [Int64]$case.planned_termination_count -ne 0 -or
                [Int64]$case.fail_safe_termination_count -ne 0 -or $case.process_image_binding_verified -or $case.job_assigned -or
                $case.kill_on_close_enabled -or $case.job_active_process_limit_one -or $case.stdout_truncated -or $case.stderr_truncated -or
                $case.stdout_token_verified -or $case.stderr_token_verified -or $case.capture_join_verified -or $case.job_closed -or
                [Int64]$case.stdout_bytes -ne 0 -or [Int64]$case.stderr_bytes -ne 0 -or
                [string]$case.stdout_sha256 -cne $emptyCaptureSha256 -or [string]$case.stderr_sha256 -cne $emptyCaptureSha256 -or
                $null -ne $case.primary_error -or $case.secondary_errors.Count -ne 0) { return $false }
            continue
        }
        if ($caseSequenceClosed -or $null -eq $case.case_t0_ticks -or $null -eq $case.active_deadline_ticks -or
            $null -eq $case.cleanup_deadline_ticks -or $null -eq $case.audit_deadline_ticks -or
            $null -eq $case.admission_observed_ticks -or $null -eq $case.case_completed_ticks -or
            $null -eq $case.case_nonce -or $null -eq $case.case_evidence_sha256 -or
            [Int64]$case.case_t0_ticks -lt $previousCaseCompletedTicks -or
            [Int64]$case.case_completed_ticks -lt [Int64]$case.admission_observed_ticks) { return $false }
        if ($null -ne $case.precreate_admission -and -not (Test-D32BoundedDiagnosticSourceProofNonSourceL1PrecreateAdmission -Admission $case.precreate_admission -Record $Record)) { return $false }
        if ($null -ne $case.actual_invocation -and -not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ActualInvocation -Invocation $case.actual_invocation -Record $Record -Case $case `
            -Admission $case.precreate_admission -RuntimeAdmissions $RuntimeAdmissions)) { return $false }
        if ([string]$case.case_evidence_sha256 -cne (Get-D32BoundedDiagnosticSourceProofNonSourceL1CaseEvidenceSha256 -CaseNonce $case.case_nonce -PrecreateAdmission $case.precreate_admission -ActualInvocation $case.actual_invocation)) { return $false }
        if ([Int64]$case.create_attempt_count -gt 0 -and ($null -eq $case.actual_invocation -or -not [bool]$case.actual_invocation.api_attempted)) { return $false }
        if ($null -ne $case.precreate_admission -and ([Int64]$case.precreate_admission.observed_ticks -lt [Int64]$case.admission_observed_ticks -or
            [Int64]$case.precreate_admission.observed_ticks -ge [Int64]$case.active_deadline_ticks)) { return $false }
        if ($null -ne $case.actual_invocation) {
            $actual = $case.actual_invocation
            if ([bool]$actual.api_attempted -ne ([Int64]$case.create_attempt_count -eq 1) -or
                (($null -eq $actual.api_attempt_ticks) -ne ($null -eq $case.create_attempt_ticks)) -or
                ($null -ne $actual.api_attempt_ticks -and [Int64]$actual.api_attempt_ticks -ne [Int64]$case.create_attempt_ticks) -or
                (($null -eq $actual.process_id) -ne ($null -eq $case.process_id)) -or
                ($null -ne $actual.process_id -and [Int64]$actual.process_id -ne [Int64]$case.process_id) -or
                (($null -eq $actual.creation_filetime_ticks) -ne ($null -eq $case.creation_filetime_ticks)) -or
                ($null -ne $actual.creation_filetime_ticks -and [Int64]$actual.creation_filetime_ticks -ne [Int64]$case.creation_filetime_ticks) -or
                (($null -eq $actual.process_image_path) -ne ($null -eq $case.process_image_path)) -or
                ($null -ne $actual.process_image_path -and [string]$actual.process_image_path -cne [string]$case.process_image_path) -or
                [bool]$actual.process_image_binding_verified -ne [bool]$case.process_image_binding_verified) { return $false }
        }
        $previousCaseCompletedTicks = [Int64]$case.case_completed_ticks
        $createSum += [Int64]$case.create_attempt_count; $termSum += [Int64]$case.planned_termination_count
        $failSafeSum += [Int64]$case.fail_safe_termination_count
        try {
            if ($null -ne $case.case_t0_ticks -and
                ([Int64]$case.active_deadline_ticks -ne [Math]::Min((ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks ([Int64]$case.case_t0_ticks) -Frequency ([Int64]$Record.clock.frequency) -DeadlineMilliseconds 5000L), [Int64]$Record.clock.batch_deadline_ticks) -or
                 [Int64]$case.cleanup_deadline_ticks -ne [Math]::Min((ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks ([Int64]$case.case_t0_ticks) -Frequency ([Int64]$Record.clock.frequency) -DeadlineMilliseconds 10000L), [Int64]$Record.clock.batch_deadline_ticks) -or
                 [Int64]$case.audit_deadline_ticks -ne [Math]::Min((ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks ([Int64]$case.case_t0_ticks) -Frequency ([Int64]$Record.clock.frequency) -DeadlineMilliseconds 15000L), [Int64]$Record.clock.batch_deadline_ticks) -or
                 [Int64]$case.audit_deadline_ticks -gt [Int64]$Record.clock.batch_deadline_ticks -or
                 [Int64]$case.admission_observed_ticks -lt [Int64]$case.case_t0_ticks -or
                 (([Int64]$case.create_attempt_count -gt 0 -or [string]$case.state -ceq 'EXPECTED_REFUSAL_VERIFIED') -and [Int64]$case.admission_observed_ticks -ge [Int64]$case.active_deadline_ticks))) { return $false }
        } catch { return $false }
        if ($null -ne $case.case_completed_ticks -and ([Int64]$case.case_completed_ticks -lt [Int64]$case.case_t0_ticks -or
            [Int64]$case.case_completed_ticks -ge [Int64]$Record.clock.batch_deadline_ticks)) { return $false }
        if ([Int64]$case.case_completed_ticks -ge [Int64]$case.audit_deadline_ticks -and
            [string]$case.state -cnotin @('BUDGET_STOPPED', 'UNRESOLVED')) { return $false }
        if ([string]$case.state -ceq 'NATIVE_BOUNDARY_VERIFIED') {
            if ($index -gt 1 -or [Int64]$case.create_attempt_count -ne 1 -or $null -eq $case.process_id -or
                $null -eq $case.actual_invocation -or -not [bool]$case.actual_invocation.api_attempted -or $case.actual_invocation.api_returned -ne $true -or
                $null -eq $case.creation_filetime_ticks -or $null -eq $case.job_instance_id -or -not $case.job_assigned -or
                $case.process_image_path -cne [string]$Record.powershell_runtime.path -or -not $case.process_image_binding_verified -or
                $null -eq $case.resume_ticks -or $null -eq $case.exit_ticks -or $null -eq $case.exit_code -or
                $null -eq $case.job_active_process_count -or [Int64]$case.job_active_process_count -ne 0 -or
                $null -eq $case.job_total_process_count -or [Int64]$case.job_total_process_count -ne 1 -or
                -not $case.kill_on_close_enabled -or -not $case.job_active_process_limit_one -or -not $case.capture_join_verified -or -not $case.job_closed -or
                -not $case.stdout_token_verified -or -not $case.stderr_token_verified -or
                [Int64]$case.stdout_bytes -gt 1024 -or [Int64]$case.stderr_bytes -gt 1024 -or
                $case.stdout_truncated -or $case.stderr_truncated -or $null -eq $case.cleanup_observed_ticks -or $null -eq $case.case_completed_ticks -or
                [Int64]$case.case_completed_ticks -ge [Int64]$case.audit_deadline_ticks -or $null -ne $case.primary_error -or $case.secondary_errors.Count -ne 0 -or
                [Int64]$case.create_attempt_ticks -lt [Int64]$case.case_t0_ticks -or [Int64]$case.create_attempt_ticks -ge [Int64]$case.active_deadline_ticks -or
                [Int64]$case.resume_ticks -lt [Int64]$case.create_attempt_ticks -or [Int64]$case.exit_ticks -lt [Int64]$case.resume_ticks -or
                [Int64]$case.exit_ticks -ge [Int64]$case.cleanup_deadline_ticks -or [Int64]$case.cleanup_observed_ticks -gt [Int64]$case.audit_deadline_ticks) { return $false }
            if ($index -eq 0 -and ([Int64]$case.exit_code -ne 0 -or [Int64]$case.planned_termination_count -ne 0 -or
                $null -ne $case.planned_termination_ticks -or [Int64]$case.fail_safe_termination_count -ne 0 -or $null -ne $case.fail_safe_termination_ticks)) { return $false }
            if ($index -eq 1 -and ([Int64]$case.planned_termination_count -ne 1 -or $null -eq $case.planned_termination_ticks -or
                [Int64]$case.planned_termination_ticks -lt [Int64]$case.resume_ticks -or [Int64]$case.planned_termination_ticks -ge [Int64]$case.exit_ticks -or
                [Int64]$case.fail_safe_termination_count -ne 0 -or $null -ne $case.fail_safe_termination_ticks)) { return $false }
        } elseif ([string]$case.state -ceq 'EXPECTED_REFUSAL_VERIFIED') {
            if ($index -ne 2 -or [Int64]$case.create_attempt_count -ne 0 -or $null -ne $case.create_attempt_ticks -or
                $null -eq $case.precreate_admission -or [string]$case.precreate_admission.decision -cne 'ENTRY_PIN_BINDING_REFUSAL' -or $null -ne $case.actual_invocation -or
                $null -ne $case.process_id -or $null -ne $case.creation_filetime_ticks -or $null -ne $case.job_instance_id -or
                $null -ne $case.process_image_path -or $case.process_image_binding_verified -or
                $case.job_assigned -or $null -ne $case.resume_ticks -or $null -ne $case.exit_ticks -or $null -ne $case.exit_code -or
                $null -ne $case.job_active_process_count -or $null -ne $case.job_total_process_count -or
                [Int64]$case.planned_termination_count -ne 0 -or $null -ne $case.planned_termination_ticks -or
                [Int64]$case.fail_safe_termination_count -ne 0 -or $null -ne $case.fail_safe_termination_ticks -or
                $case.kill_on_close_enabled -or $case.job_active_process_limit_one -or $case.capture_join_verified -or $case.job_closed -or
                $case.stdout_token_verified -or $case.stderr_token_verified -or [Int64]$case.stdout_bytes -ne 0 -or [Int64]$case.stderr_bytes -ne 0 -or
                $case.stdout_truncated -or $case.stderr_truncated -or [string]$case.stdout_sha256 -cne $emptyCaptureSha256 -or
                [string]$case.stderr_sha256 -cne $emptyCaptureSha256 -or $case.secondary_errors.Count -ne 0 -or
                $null -ne $case.cleanup_observed_ticks -or $null -eq $case.case_completed_ticks -or
                [Int64]$case.case_completed_ticks -ge [Int64]$case.audit_deadline_ticks -or
                [String]::IsNullOrWhiteSpace([string]$case.primary_error)) { return $false }
        } elseif ([string]$case.state -cin @('BLOCKED', 'BUDGET_STOPPED', 'UNRESOLVED')) {
            if ([String]::IsNullOrWhiteSpace([string]$case.primary_error)) { return $false }
        }
    }
    if ($createSum -ne [Int64]$Record.create_process_attempt_count -or $termSum -ne [Int64]$Record.planned_termination_count -or
        $failSafeSum -ne [Int64]$Record.fail_safe_termination_count -or $createSum -gt 2) { return $false }
    foreach ($errorText in $Record.secondary_errors) { if ($errorText -isnot [string] -or ([string]$errorText).Length -gt 2048) { return $false } }
    try { $null = [DateTimeOffset]::Parse([string]$Record.started_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind); $null = [DateTimeOffset]::Parse([string]$Record.completed_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
    catch { return $false }
    if ([string]$Record.status -ceq 'COMPLETE_NON_SOURCE_L1' -and
        ([string]$Record.cases[0].state -cne 'NATIVE_BOUNDARY_VERIFIED' -or [string]$Record.cases[1].state -cne 'NATIVE_BOUNDARY_VERIFIED' -or
         [string]$Record.cases[2].state -cne 'EXPECTED_REFUSAL_VERIFIED' -or $createSum -ne 2 -or $termSum -ne 1 -or $failSafeSum -ne 0 -or
         $null -ne $Record.primary_error)) { return $false }
    if ([string]$Record.status -in @('BLOCKED', 'BUDGET_STOPPED', 'REFUSED', 'UNRESOLVED') -and [String]::IsNullOrWhiteSpace([string]$Record.primary_error)) { return $false }
    return $true
}

function Test-D32BoundedDiagnosticNonSourceL1NullablePositiveInteger {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $true }
    return (Test-D32BoundedCompilerDiagnosticInteger $Value -Positive)
}

function Test-D32BoundedDiagnosticNonSourceL1ExitCode {
    param([AllowNull()][object]$Value)
    $isInteger = $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64]
    if (-not $isInteger) { return $false }
    try { return ([decimal]$Value -ge [decimal][int32]::MinValue -and [decimal]$Value -le [decimal][int32]::MaxValue) }
    catch { return $false }
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultBindingsV1Internal {
    param([AllowNull()][object]$Record, [AllowNull()][object]$Authority, [AllowNull()][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][string]$ExpectedAuthorityPath, [Parameter(Mandatory = $true)][string]$ExpectedAuthoritySha256,
        [AllowNull()][object]$PersistedFact, [AllowNull()][object]$ResultReference, [object[]]$RuntimeAdmissions = @())
    if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShapeV1Internal $Record -RuntimeAdmissions $RuntimeAdmissions) -or $null -eq $Authority -or $null -eq $AuthorityReference -or
        -not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShapeV1Internal -Document $Authority -ExpectedCandidateSha ([string]$Record.candidate_sha) -Repository ([string]$Authority.source_repo)) -or
        [string]$Record.candidate_sha -cne [string]$Authority.candidate_sha -or [string]$Record.batch_id -cne [string]$Authority.batch_id -or
        [string]$Record.run_id -cne [string]$Authority.run_id -or [string]$Record.authority.path -cne $ExpectedAuthorityPath -or
        [string]$Record.authority.sha256 -cne $ExpectedAuthoritySha256 -or [string]$Record.authority.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Record.authority.path -cne [string]$AuthorityReference.path -or [Int64]$Record.authority.bytes -ne [Int64]$AuthorityReference.bytes -or
        [string]$Record.authority.sha256 -cne [string]$AuthorityReference.sha256 -or
        [string]$Record.authority.volume_serial_hex -cne [string]$AuthorityReference.volume_serial_hex -or
        [string]$Record.authority.file_id_hex -cne [string]$AuthorityReference.file_id_hex -or
        $Record.source_pins.Count -ne $Authority.source_pins.Count) { return $false }
    for ($index = 0; $index -lt 6; $index++) { foreach ($name in @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ([string]$Record.source_pins[$index].$name -cne [string]$Authority.source_pins[$index].$name) { return $false } } }
    foreach ($name in @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ([string]$Record.powershell_runtime.$name -cne [string]$Authority.powershell_runtime.$name) { return $false } }
    foreach ($name in @('root_path', 'parent_path', 'root_volume_serial_hex', 'root_file_id_hex', 'parent_volume_serial_hex', 'parent_file_id_hex', 'result_path', 'journal_path')) { if ([string]$Record.output.$name -cne [string]$Authority.output.$name) { return $false } }
    if ([Int64]$Record.clock.frequency -ne [Int64][Diagnostics.Stopwatch]::Frequency) { return $false }
    for ($index = 0; $index -lt 3; $index++) {
        if ([string]$Record.cases[$index].case_id -cne [string]$Authority.cases[$index].case_id -or
            ([string]$Record.cases[$index].state -cne 'NOT_RUN' -and [string]$Record.cases[$index].case_nonce -cne [string]$Authority.cases[$index].nonce)) { return $false }
        $expectedCount = [Int64]$Authority.cases[$index].expected_create_attempts
        if ([string]$Record.cases[$index].state -ceq 'NATIVE_BOUNDARY_VERIFIED' -and $expectedCount -ne 1) { return $false }
        if ([string]$Record.cases[$index].state -ceq 'EXPECTED_REFUSAL_VERIFIED' -and $expectedCount -ne 0) { return $false }
        $admission = $Record.cases[$index].precreate_admission
        if ($null -ne $admission) {
            $entryPin = $Authority.source_pins[1]; $runtimePin = $Authority.powershell_runtime
            foreach ($name in @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) {
                if ([string]$admission.entry_reference.$name -cne [string]$entryPin.$name -or
                    [string]$admission.runtime_reference.$name -cne [string]$runtimePin.$name) { return $false }
            }
            $expectedAdmissionPin = if ([string]$admission.decision -ceq 'ENTRY_PIN_BINDING_REFUSAL') {
                Get-D32BoundedDiagnosticSourceProofNonSourceL1DerivedEntryMismatchSha256 -Sha256 ([string]$entryPin.sha256)
            } else { [string]$entryPin.sha256 }
            if ([string]$admission.entry_expected_sha256 -cne $expectedAdmissionPin -or
                [string]$admission.entry_observed_sha256 -cne [string]$entryPin.sha256 -or
                [string]$admission.runtime_expected_sha256 -cne [string]$runtimePin.sha256) { return $false }
        }
        $invocation = $Record.cases[$index].actual_invocation
        if ($null -ne $invocation) {
            $expectedEnvironment = Get-D32BoundedDiagnosticSourceProofNonSourceL1EnvironmentEntries -Environment $Authority.invocation.child_environment
            if ($invocation.environment_entries.Count -ne $expectedEnvironment.Count) { return $false }
            for ($environmentIndex = 0; $environmentIndex -lt $expectedEnvironment.Count; $environmentIndex++) {
                if ([string]$invocation.environment_entries[$environmentIndex] -cne [string]$expectedEnvironment[$environmentIndex]) { return $false }
            }
        }
    }
    if ([string]$Record.status -ceq 'COMPLETE_NON_SOURCE_L1') {
        if ($null -eq $PersistedFact -or $null -eq $ResultReference -or
            -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $ResultReference) -or
            -not (Test-D32BoundedCompilerDiagnosticExactProperties $PersistedFact @('event', 'case_id', 'scheduled_ticks', 'observed_ticks', 'lateness_ticks', 'result_path', 'result_bytes', 'result_sha256', 'result_volume_serial_hex', 'result_file_id_hex', 'case_evidence_sha256', 'gate_authority')) -or
            [string]$PersistedFact.event -cne 'L1_RESULT_PERSISTED' -or [string]$PersistedFact.result_path -cne [string]$Record.output.result_path -or
            [string]$PersistedFact.case_id -cne '' -or $null -ne $PersistedFact.scheduled_ticks -or $null -ne $PersistedFact.lateness_ticks -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $PersistedFact.result_bytes -Positive) -or
            [string]$PersistedFact.result_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$PersistedFact.result_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
            [string]$PersistedFact.result_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$PersistedFact.result_path -cne [string]$ResultReference.path -or
            [Int64]$PersistedFact.result_bytes -ne [Int64]$ResultReference.bytes -or
            [string]$PersistedFact.result_sha256 -cne [string]$ResultReference.sha256 -or
            [string]$PersistedFact.result_volume_serial_hex -cne [string]$ResultReference.volume_serial_hex -or
            [string]$PersistedFact.result_file_id_hex -cne [string]$ResultReference.file_id_hex -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $PersistedFact.observed_ticks -Positive) -or
            [Int64]$PersistedFact.observed_ticks -ge [Int64]$Record.clock.batch_deadline_ticks -or $null -ne $PersistedFact.case_evidence_sha256 -or
            [string]$PersistedFact.gate_authority -cne 'NONE') { return $false }
    }
    return $true
}

function Test-D32BoundedDiagnosticNonSourceL1JsonDuplicates {
    param([System.Text.Json.JsonElement]$Element)
    switch ($Element.ValueKind) {
        'Object' {
            $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($property in $Element.EnumerateObject()) {
                if (-not $names.Add($property.Name) -or (Test-D32BoundedDiagnosticNonSourceL1JsonDuplicates -Element $property.Value)) { return $true }
            }
        }
        'Array' { foreach ($item in $Element.EnumerateArray()) { if (Test-D32BoundedDiagnosticNonSourceL1JsonDuplicates -Element $item) { return $true } } }
    }
    return $false
}

function ConvertFrom-D32BoundedDiagnosticNonSourceL1JsonElement {
    param([System.Text.Json.JsonElement]$Element)
    switch ($Element.ValueKind) {
        'Object' { $ordered = [ordered]@{}; foreach ($property in $Element.EnumerateObject()) { $ordered.Add($property.Name, (ConvertFrom-D32BoundedDiagnosticNonSourceL1JsonElement -Element $property.Value)) }; return [PSCustomObject]$ordered }
        'Array' { $items = [System.Collections.Generic.List[object]]::new(); foreach ($item in $Element.EnumerateArray()) { $items.Add((ConvertFrom-D32BoundedDiagnosticNonSourceL1JsonElement -Element $item)) }; return ,$items.ToArray() }
        'String' { return $Element.GetString() }
        'Number' { [Int64]$integer = 0; if ($Element.TryGetInt64([ref]$integer)) { return $integer }; return $null }
        'True' { return $true }
        'False' { return $false }
        default { return $null }
    }
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultPersistenceV1Internal {
    param([AllowNull()][object]$Record, [AllowNull()][object]$PersistedFact, [AllowNull()][object]$ResultReference,
        [AllowNull()][object]$JournalReference, [Parameter(Mandatory = $true)][byte[]]$JournalBytes,
        [Parameter(Mandatory = $true)][long]$CallerObservedTicks, [object[]]$RuntimeAdmissions = @())
    if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShapeV1Internal $Record -RuntimeAdmissions $RuntimeAdmissions) -or $null -eq $PersistedFact -or
        [string]$Record.status -cnotin @('COMPLETE_NON_SOURCE_L1', 'BLOCKED', 'BUDGET_STOPPED', 'REFUSED', 'UNRESOLVED') -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $PersistedFact @('event', 'case_id', 'scheduled_ticks', 'observed_ticks', 'lateness_ticks', 'result_path', 'result_bytes', 'result_sha256', 'result_volume_serial_hex', 'result_file_id_hex', 'case_evidence_sha256', 'gate_authority')) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $ResultReference) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $JournalReference) -or
        [string]$ResultReference.path -cne [string]$Record.output.result_path -or
        [string]$JournalReference.path -cne [string]$Record.output.journal_path -or
        [string]$PersistedFact.event -cne 'L1_RESULT_PERSISTED' -or [string]$PersistedFact.result_path -cne [string]$ResultReference.path -or
        [Int64]$PersistedFact.result_bytes -ne [Int64]$ResultReference.bytes -or [string]$PersistedFact.result_sha256 -cne [string]$ResultReference.sha256 -or
        [string]$PersistedFact.result_volume_serial_hex -cne [string]$ResultReference.volume_serial_hex -or
        [string]$PersistedFact.result_file_id_hex -cne [string]$ResultReference.file_id_hex -or
        [string]$PersistedFact.case_id -cne '' -or $null -ne $PersistedFact.scheduled_ticks -or $null -ne $PersistedFact.lateness_ticks -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $PersistedFact.observed_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $CallerObservedTicks -Positive) -or
        [Int64]$JournalReference.bytes -ne $JournalBytes.Length -or $JournalBytes.Length -le 0 -or $JournalBytes.Length -gt 65536 -or
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($JournalBytes)).ToLowerInvariant() -cne [string]$JournalReference.sha256 -or
        $CallerObservedTicks -lt [Int64]$PersistedFact.observed_ticks -or $CallerObservedTicks -ge [Int64]$Record.clock.batch_deadline_ticks -or
        $null -ne $PersistedFact.case_evidence_sha256) { return $false }
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($JournalBytes)
        if (-not $text.EndsWith("`n", [StringComparison]::Ordinal) -or $text.Contains("`r")) { return $false }
        $splitLines = $text.Split("`n", [StringSplitOptions]::None)
        if ($splitLines.Length -lt 3 -or $splitLines.Length -gt 6 -or $splitLines[$splitLines.Length - 1] -cne '') { return $false }
        $lines = @($splitLines[0..($splitLines.Length - 2)])
        foreach ($line in $lines) { if ([string]::IsNullOrEmpty($line)) { return $false } }
        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($line in $lines) {
            $json = [System.Text.Json.JsonDocument]::Parse($line)
            try {
                if ($json.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32BoundedDiagnosticNonSourceL1JsonDuplicates -Element $json.RootElement)) { return $false }
                $rows.Add((ConvertFrom-D32BoundedDiagnosticNonSourceL1JsonElement -Element $json.RootElement))
            } finally { $json.Dispose() }
        }
        $last = $rows[$rows.Count - 1]
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $last @('event', 'case_id', 'scheduled_ticks', 'observed_ticks', 'lateness_ticks', 'result_path', 'result_bytes', 'result_sha256', 'result_volume_serial_hex', 'result_file_id_hex', 'case_evidence_sha256', 'gate_authority')) -or
            [string]$last.event -cne 'L1_RESULT_PERSISTED' -or [string]$last.result_path -cne [string]$PersistedFact.result_path -or
            [Int64]$last.result_bytes -ne [Int64]$PersistedFact.result_bytes -or [string]$last.result_sha256 -cne [string]$PersistedFact.result_sha256 -or
            [string]$last.result_volume_serial_hex -cne [string]$PersistedFact.result_volume_serial_hex -or
            [string]$last.result_file_id_hex -cne [string]$PersistedFact.result_file_id_hex -or
            [Int64]$last.observed_ticks -ne [Int64]$PersistedFact.observed_ticks -or $null -ne $last.case_evidence_sha256 -or [string]$last.gate_authority -cne 'NONE' -or
            [string]$last.case_id -cne '' -or $null -ne $last.scheduled_ticks -or $null -ne $last.lateness_ticks) { return $false }
        $first = $rows[0]
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $first @('event', 'case_id', 'scheduled_ticks', 'observed_ticks', 'lateness_ticks', 'result_path', 'result_bytes', 'result_sha256', 'result_volume_serial_hex', 'result_file_id_hex', 'case_evidence_sha256', 'gate_authority')) -or
            [string]$first.event -cne 'AUTHORITY_ADMISSION' -or [string]$first.case_id -cne '' -or
            [Int64]$first.scheduled_ticks -ne [Int64]$Record.clock.batch_t0_ticks -or
            $null -ne $first.result_path -or $null -ne $first.result_bytes -or $null -ne $first.result_sha256 -or
            $null -ne $first.result_volume_serial_hex -or $null -ne $first.result_file_id_hex -or $null -ne $first.case_evidence_sha256) { return $false }
        $previousObserved = [Int64]$Record.clock.batch_t0_ticks
        for ($index = 0; $index -lt $rows.Count; $index++) {
            $row = $rows[$index]
            if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $row @('event', 'case_id', 'scheduled_ticks', 'observed_ticks', 'lateness_ticks', 'result_path', 'result_bytes', 'result_sha256', 'result_volume_serial_hex', 'result_file_id_hex', 'case_evidence_sha256', 'gate_authority')) -or
                [string]$row.event -cnotin @('AUTHORITY_ADMISSION', 'CASE_NATIVE_BOUNDARY_VERIFIED', 'CASE_EXPECTED_REFUSAL_VERIFIED', 'CASE_BLOCKED', 'CASE_BUDGET_STOPPED', 'CASE_UNRESOLVED', 'L1_RESULT_PERSISTED') -or
                ($index -eq 0 -and [string]$row.event -cne 'AUTHORITY_ADMISSION') -or
                ($index -gt 0 -and [string]$row.event -ceq 'AUTHORITY_ADMISSION') -or
                [string]$row.case_id -cnotin @('', 'NORMAL_EXIT', 'FORCED_OWNED_TERMINATION', 'ENTRY_PIN_BINDING_REFUSAL') -or
                -not (Test-D32BoundedCompilerDiagnosticInteger $row.observed_ticks -Positive) -or [Int64]$row.observed_ticks -lt $previousObserved -or
                [Int64]$row.observed_ticks -ge [Int64]$Record.clock.batch_deadline_ticks -or [string]$row.gate_authority -cne 'NONE' -or
                (($null -eq $row.scheduled_ticks) -and $null -ne $row.lateness_ticks) -or
                (($null -ne $row.scheduled_ticks) -and (-not (Test-D32BoundedCompilerDiagnosticInteger $row.scheduled_ticks -Positive) -or
                    -not (Test-D32BoundedCompilerDiagnosticInteger $row.lateness_ticks) -or [Int64]$row.observed_ticks -lt [Int64]$row.scheduled_ticks -or
                    [Int64]$row.lateness_ticks -ne ([Int64]$row.observed_ticks - [Int64]$row.scheduled_ticks))) -or
                ($index -lt ($rows.Count - 1) -and [string]$row.event -ceq 'L1_RESULT_PERSISTED')) { return $false }
            if ([string]$row.event -like 'CASE_*') {
                if ([string]$row.case_evidence_sha256 -cnotmatch '^[0-9a-f]{64}$') { return $false }
            } elseif ($null -ne $row.case_evidence_sha256) { return $false }
            if ($index -eq 0 -and ($null -eq $row.scheduled_ticks -or
                [Int64]$row.observed_ticks -lt [Int64]$Record.clock.batch_t0_ticks)) { return $false }
            $previousObserved = [Int64]$row.observed_ticks
            if ($index -lt ($rows.Count - 1)) {
                foreach ($name in @('result_path', 'result_bytes', 'result_sha256', 'result_volume_serial_hex', 'result_file_id_hex')) { if ($null -ne $row.$name) { return $false } }
            }
        }
        $executedRows = 0
        $caseSequenceClosed = $false
        for ($caseIndex = 0; $caseIndex -lt 3; $caseIndex++) {
            $case = $Record.cases[$caseIndex]
            if ([string]$case.state -ceq 'NOT_RUN') { $caseSequenceClosed = $true; continue }
            if ($caseSequenceClosed) { return $false }
            $rowIndex = 1 + $executedRows
            if ($rowIndex -ge ($rows.Count - 1) -or $null -eq $case.case_t0_ticks -or $null -eq $case.case_completed_ticks) { return $false }
            $row = $rows[$rowIndex]
            $expectedEvent = 'CASE_' + [string]$case.state
            if ([string]$row.event -cne $expectedEvent -or [string]$row.case_id -cne [string]$case.case_id -or
                $null -ne $row.scheduled_ticks -or $null -ne $row.lateness_ticks -or
                [string]$row.case_evidence_sha256 -cne [string]$case.case_evidence_sha256 -or
                [Int64]$row.observed_ticks -ne [Int64]$case.case_completed_ticks -or
                [Int64]$row.observed_ticks -lt [Int64]$case.case_t0_ticks -or
                ([Int64]$row.observed_ticks -ge [Int64]$case.audit_deadline_ticks -and
                    [string]$case.state -cnotin @('BUDGET_STOPPED', 'UNRESOLVED'))) { return $false }
            $executedRows++
        }
        if ($rows.Count -ne (2 + $executedRows)) { return $false }
        if ([string]$Record.status -ceq 'COMPLETE_NON_SOURCE_L1' -and $executedRows -ne 3) { return $false }
        return ([string]$PersistedFact.result_path -ceq [string]$ResultReference.path -and
            [Int64]$PersistedFact.result_bytes -eq [Int64]$ResultReference.bytes -and
            [string]$PersistedFact.result_sha256 -ceq [string]$ResultReference.sha256 -and
            [string]$PersistedFact.result_volume_serial_hex -ceq [string]$ResultReference.volume_serial_hex -and
            [string]$PersistedFact.result_file_id_hex -ceq [string]$ResultReference.file_id_hex -and
            [Int64]$last.observed_ticks -ge [Int64]$PersistedFact.observed_ticks)
    } catch { return $false }
}

function New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate {
    param([Parameter(Mandatory = $true)][string]$CaseId, [string]$State = 'NOT_RUN', [AllowNull()][object]$CaseNonce = $null,
        [AllowNull()][object]$CaseT0Ticks = $null, [AllowNull()][object]$ActiveDeadlineTicks = $null,
        [AllowNull()][object]$CleanupDeadlineTicks = $null, [AllowNull()][object]$AuditDeadlineTicks = $null,
        [AllowNull()][object]$AdmissionObservedTicks = $null, [long]$CreateAttemptCount = 0L,
        [AllowNull()][object]$CreateAttemptTicks = $null, [AllowNull()][object]$ProcessId = $null,
        [AllowNull()][object]$CreationFiletimeTicks = $null, [AllowNull()][object]$ProcessImagePath = $null,
        [bool]$ProcessImageBindingVerified = $false, [AllowNull()][object]$JobInstanceId = $null,
        [bool]$JobAssigned = $false, [AllowNull()][object]$ResumeTicks = $null,
        [long]$PlannedTerminationCount = 0L, [AllowNull()][object]$PlannedTerminationTicks = $null,
        [long]$FailSafeTerminationCount = 0L, [AllowNull()][object]$FailSafeTerminationTicks = $null,
        [AllowNull()][object]$ExitTicks = $null, [AllowNull()][object]$ExitCode = $null,
        [AllowNull()][object]$JobActiveProcessCount = $null, [AllowNull()][object]$JobTotalProcessCount = $null,
        [bool]$KillOnCloseEnabled = $false, [bool]$JobActiveProcessLimitOne = $false, [long]$StdoutBytes = 0L,
        [string]$StdoutSha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        [bool]$StdoutTruncated = $false, [long]$StderrBytes = 0L,
        [string]$StderrSha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        [bool]$StderrTruncated = $false, [bool]$StdoutTokenVerified = $false, [bool]$StderrTokenVerified = $false,
        [bool]$CaptureJoinVerified = $false, [bool]$JobClosed = $false,
        [AllowNull()][object]$CleanupObservedTicks = $null, [AllowNull()][object]$CaseCompletedTicks = $null,
        [AllowNull()][object]$PrecreateAdmission = $null, [AllowNull()][object]$ActualInvocation = $null,
        [AllowNull()][object]$CaseEvidenceSha256 = $null,
        [AllowNull()][object]$PrimaryError = $null,
        [string[]]$SecondaryErrors = @())
    return [PSCustomObject][ordered]@{
        case_id = $CaseId; case_nonce = $CaseNonce; precreate_admission = $PrecreateAdmission
        actual_invocation = $ActualInvocation; case_evidence_sha256 = $CaseEvidenceSha256
        state = $State; case_t0_ticks = $CaseT0Ticks; active_deadline_ticks = $ActiveDeadlineTicks
        cleanup_deadline_ticks = $CleanupDeadlineTicks; audit_deadline_ticks = $AuditDeadlineTicks; admission_observed_ticks = $AdmissionObservedTicks
        create_attempt_count = [Int64]$CreateAttemptCount; create_attempt_ticks = $CreateAttemptTicks; process_id = $ProcessId
        creation_filetime_ticks = $CreationFiletimeTicks; process_image_path = $ProcessImagePath
        process_image_binding_verified = [bool]$ProcessImageBindingVerified; job_instance_id = $JobInstanceId; job_assigned = [bool]$JobAssigned
        resume_ticks = $ResumeTicks; planned_termination_count = [Int64]$PlannedTerminationCount
        planned_termination_ticks = $PlannedTerminationTicks; fail_safe_termination_count = [Int64]$FailSafeTerminationCount
        fail_safe_termination_ticks = $FailSafeTerminationTicks; exit_ticks = $ExitTicks; exit_code = $ExitCode
        job_active_process_count = $JobActiveProcessCount; job_total_process_count = $JobTotalProcessCount
        kill_on_close_enabled = [bool]$KillOnCloseEnabled; job_active_process_limit_one = [bool]$JobActiveProcessLimitOne
        stdout_bytes = [Int64]$StdoutBytes; stdout_sha256 = $StdoutSha256
        stdout_truncated = [bool]$StdoutTruncated; stderr_bytes = [Int64]$StderrBytes; stderr_sha256 = $StderrSha256
        stderr_truncated = [bool]$StderrTruncated; stdout_token_verified = [bool]$StdoutTokenVerified; stderr_token_verified = [bool]$StderrTokenVerified
        capture_join_verified = [bool]$CaptureJoinVerified; job_closed = [bool]$JobClosed
        cleanup_observed_ticks = $CleanupObservedTicks; case_completed_ticks = $CaseCompletedTicks
        primary_error = $PrimaryError; secondary_errors = @($SecondaryErrors)
    }
}

function New-D32BoundedDiagnosticSourceProofNonSourceL1ResultCandidateV1Internal {
    param([Parameter(Mandatory = $true)][string]$CandidateSha, [Parameter(Mandatory = $true)][string]$BatchId,
        [Parameter(Mandatory = $true)][string]$RunId, [Parameter(Mandatory = $true)][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][object[]]$SourcePins, [Parameter(Mandatory = $true)][object]$PowerShellRuntime,
        [Parameter(Mandatory = $true)][object]$Output, [Parameter(Mandatory = $true)][object]$Clock,
        [Parameter(Mandatory = $true)][object]$Controller, [Parameter(Mandatory = $true)][object[]]$Cases,
        [Parameter(Mandatory = $true)][long]$CreateProcessAttemptCount, [Parameter(Mandatory = $true)][long]$PlannedTerminationCount,
        [Parameter(Mandatory = $true)][long]$FailSafeTerminationCount, [Parameter(Mandatory = $true)][string]$Status,
        [AllowNull()][object]$PrimaryError, [string[]]$SecondaryErrors = @(),
        [Parameter(Mandatory = $true)][string]$StartedAtUtc, [Parameter(Mandatory = $true)][string]$CompletedAtUtc)
    return [PSCustomObject][ordered]@{
        schema_version = 1; record_type = 'D32_BOUNDED_SOURCEPROOF_NON_SOURCE_L1_V1'
        purpose = 'NATIVE_LIFECYCLE_VALIDATION_ONLY'; policy = 'D32_SOURCEPROOF_NON_SOURCE_L1_V1'; gate_authority = 'NONE'
        candidate_sha = $CandidateSha; batch_id = $BatchId; run_id = $RunId; authority = $AuthorityReference
        source_pins = @($SourcePins); powershell_runtime = $PowerShellRuntime; output = $Output; clock = $Clock
        controller = $Controller; cases = @($Cases); create_process_attempt_count = [Int64]$CreateProcessAttemptCount
        planned_termination_count = [Int64]$PlannedTerminationCount; fail_safe_termination_count = [Int64]$FailSafeTerminationCount
        abrupt_owner_abort = 'NOT_RUN'; status = $Status; source_proof_checkpoint = $false; source_closure = $false
        diagnostic_invocation_authority = 'NONE'; formal_gate_usable = $false; formal_phase_allowed = $false; formal_aggregate_allowed = $false
        primary_error = $PrimaryError; secondary_errors = @($SecondaryErrors); started_at_utc = $StartedAtUtc; completed_at_utc = $CompletedAtUtc
    }
}

function Get-D32BoundedDiagnosticSourceProofNonSourceL1OutputPaths {
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$BatchId)
    if ($BatchId -cnotmatch '^[0-9a-f]{32}$' -or -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Root)) {
        throw 'D32_NON_SOURCE_L1_REFUSED: output root or batch identifier is not canonical'
    }
    $prefix = 'D32-NSL1-' + $BatchId
    $combine = { param([string]$Name) [IO.Path]::GetFullPath([IO.Path]::Combine($Root, $Name)) }
    return [PSCustomObject][ordered]@{
        controller_runtime_admission_path = & $combine ($prefix + '-controller-runtime.json')
        normalreader_runtime_admission_path = & $combine ($prefix + '-normal-reader-runtime.json')
        forcedreader_runtime_admission_path = & $combine ($prefix + '-forced-reader-runtime.json')
        outer_prelaunch_path = & $combine ($prefix + '-outer-prelaunch.json')
        caller_outcome_path = & $combine ($prefix + '-caller-outcome.json')
        caller_journal_path = & $combine ($prefix + '-caller-journal.jsonl')
        stdout_path = & $combine ($prefix + '-controller-stdout.log')
        stderr_path = & $combine ($prefix + '-controller-stderr.log')
    }
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeFileState {
    param([AllowNull()][object]$State)
    try {
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $State @('state', 'reference', 'absence_witness_sha256'))) { return $false }
    if ([string]$State.state -ceq 'PRESENT') {
        return (Test-D32BoundedCompilerDiagnosticFileReferenceShape $State.reference) -and $null -eq $State.absence_witness_sha256
    }
    return ([string]$State.state -ceq 'PROTECTED_ABSENT' -and $null -eq $State.reference -and
        $State.absence_witness_sha256 -is [string] -and [string]$State.absence_witness_sha256 -cmatch '^[0-9a-f]{64}$')
    } catch { return $false }
}

function Assert-D32BoundedDiagnosticSourceProofCanonicalUnicode {
    param([Parameter(Mandatory = $true)][string]$Value)
    for ($index = 0; $index -lt $Value.Length; $index++) {
        $code = [int][char]$Value[$index]
        if ($code -ge 0xD800 -and $code -le 0xDBFF) {
            if ($index + 1 -ge $Value.Length) { throw 'D32_NON_SOURCE_L1_REFUSED: canonical JSON contains unpaired UTF-16 surrogate' }
            $next = [int][char]$Value[$index + 1]
            if ($next -lt 0xDC00 -or $next -gt 0xDFFF) { throw 'D32_NON_SOURCE_L1_REFUSED: canonical JSON contains unpaired UTF-16 surrogate' }
            $index++
        } elseif ($code -ge 0xDC00 -and $code -le 0xDFFF) {
            throw 'D32_NON_SOURCE_L1_REFUSED: canonical JSON contains unpaired UTF-16 surrogate'
        }
    }
}

function Write-D32BoundedDiagnosticSourceProofCanonicalJsonValue {
    param([Parameter(Mandatory = $true)][System.Text.Json.Utf8JsonWriter]$Writer, [AllowNull()][object]$Value)
    if ($null -eq $Value) { $Writer.WriteNullValue(); return }
    if ($Value -is [string]) {
        Assert-D32BoundedDiagnosticSourceProofCanonicalUnicode -Value $Value
        $Writer.WriteStringValue([string]$Value); return
    }
    if ($Value -is [bool]) { $Writer.WriteBooleanValue([bool]$Value); return }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64]) {
        $Writer.WriteRawValue([Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture), $false); return
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = [System.Collections.Generic.List[string]]::new()
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($key in $Value.Keys) {
            if ($key -isnot [string] -or -not $seen.Add([string]$key)) { throw 'D32_NON_SOURCE_L1_REFUSED: canonical JSON object has a non-string or duplicate key' }
            Assert-D32BoundedDiagnosticSourceProofCanonicalUnicode -Value ([string]$key)
            $keys.Add([string]$key)
        }
        $keyArray = $keys.ToArray(); [Array]::Sort($keyArray, [StringComparer]::Ordinal)
        $Writer.WriteStartObject()
        foreach ($key in $keyArray) { $Writer.WritePropertyName($key); Write-D32BoundedDiagnosticSourceProofCanonicalJsonValue -Writer $Writer -Value $Value[$key] }
        $Writer.WriteEndObject(); return
    }
    if ($Value -is [PSCustomObject]) {
        $properties = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
        foreach ($property in $Value.PSObject.Properties) {
            $name = [string]$property.Name
            if (-not $properties.TryAdd($name, $property.Value)) { throw 'D32_NON_SOURCE_L1_REFUSED: canonical JSON object has duplicate properties' }
            Assert-D32BoundedDiagnosticSourceProofCanonicalUnicode -Value $name
        }
        $keyArray = [string[]]@($properties.Keys); [Array]::Sort($keyArray, [StringComparer]::Ordinal)
        $Writer.WriteStartObject()
        foreach ($key in $keyArray) { $Writer.WritePropertyName($key); Write-D32BoundedDiagnosticSourceProofCanonicalJsonValue -Writer $Writer -Value $properties[$key] }
        $Writer.WriteEndObject(); return
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $Writer.WriteStartArray()
        foreach ($item in $Value) { Write-D32BoundedDiagnosticSourceProofCanonicalJsonValue -Writer $Writer -Value $item }
        $Writer.WriteEndArray(); return
    }
    throw 'D32_NON_SOURCE_L1_REFUSED: canonical JSON contains an unsupported value or non-integer number'
}

function ConvertTo-D32BoundedDiagnosticSourceProofCanonicalJsonBytes {
    param([Parameter(Mandatory = $true)][object]$Value)
    $stream = [IO.MemoryStream]::new()
    $writerOptions = [System.Text.Json.JsonWriterOptions]::new()
    $writerOptions.Indented = $false
    $writerOptions.Encoder = [System.Text.Encodings.Web.JavaScriptEncoder]::Default
    $writer = [System.Text.Json.Utf8JsonWriter]::new($stream, $writerOptions)
    try {
        Write-D32BoundedDiagnosticSourceProofCanonicalJsonValue -Writer $writer -Value $Value
        $writer.Flush()
        return ,([byte[]]$stream.ToArray())
    } finally { $writer.Dispose(); $stream.Dispose() }
}

function Copy-D32BoundedDiagnosticSourceProofCanonicalJsonValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [bool] -or $Value -is [ValueType]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $copy = [ordered]@{}
        foreach ($key in $Value.Keys) { if ($key -isnot [string] -or $copy.Contains([string]$key)) { throw 'D32_NON_SOURCE_L1_REFUSED: duplicate or invalid canonical JSON key' }; $copy[[string]$key] = Copy-D32BoundedDiagnosticSourceProofCanonicalJsonValue -Value $Value[$key] }
        return ,$copy
    }
    if ($Value -is [PSCustomObject]) {
        $copy = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) { if ($copy.Contains([string]$property.Name)) { throw 'D32_NON_SOURCE_L1_REFUSED: duplicate canonical JSON property' }; $copy[[string]$property.Name] = Copy-D32BoundedDiagnosticSourceProofCanonicalJsonValue -Value $property.Value }
        return ,$copy
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) { $items.Add((Copy-D32BoundedDiagnosticSourceProofCanonicalJsonValue -Value $item)) }
        return ,($items.ToArray())
    }
    throw 'D32_NON_SOURCE_L1_REFUSED: canonical projection contains an unsupported value'
}

function Get-D32BoundedDiagnosticSourceProofOuterPrelaunchCommandLine {
    param([Parameter(Mandatory = $true)][string]$Image, [Parameter(Mandatory = $true)][string[]]$Vector)
    if ([string]::IsNullOrWhiteSpace($Image) -or $Image.IndexOf([char]0) -ge 0) {
        throw 'D32_NON_SOURCE_L1_REFUSED: fixed outer executable has invalid Unicode or NUL'
    }
    Assert-D32BoundedDiagnosticSourceProofCanonicalUnicode -Value $Image
    foreach ($argument in $Vector) {
        if ($argument -isnot [string] -or $argument.IndexOf([char]0) -ge 0) { throw 'D32_NON_SOURCE_L1_REFUSED: outer argv contains non-string or NUL value' }
        Assert-D32BoundedDiagnosticSourceProofCanonicalUnicode -Value $argument
    }
    $line = Get-D32BoundedDiagnosticSourceProofNonSourceL1ExpectedCommandLine -Image $Image -Arguments $Vector
    if ($line.Length -ge 32767) { throw 'D32_NON_SOURCE_L1_REFUSED: fixed outer command line exceeds the Windows limit' }
    return $line
}

function Get-D32BoundedDiagnosticSourceProofOuterPrelaunchBindingSha256 {
    param([Parameter(Mandatory = $true)][object]$Record)
    $argumentFields = @('vector','command_line','command_line_utf16_sha256')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.controller.arguments $argumentFields) -or
        $Record.controller.arguments.vector -isnot [Array] -or $Record.controller.arguments.vector.Count -lt 1 -or
        [string]$Record.controller.arguments.command_line_utf16_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'D32_NON_SOURCE_L1_REFUSED: outer prelaunch argument record is incomplete or has extra fields'
    }
    foreach ($item in $Record.controller.arguments.vector) { if ($item -isnot [string]) { throw 'D32_NON_SOURCE_L1_REFUSED: outer argv contains a non-string value' } }
    $vector = [string[]]$Record.controller.arguments.vector
    $bindingParameterIndices = [System.Collections.Generic.List[int]]::new()
    for ($index = 0; $index -lt $vector.Count; $index++) { if ($vector[$index] -ceq '-ExpectedOuterPrelaunchBindingSha256') { $bindingParameterIndices.Add($index) } }
    if ($bindingParameterIndices.Count -ne 1 -or $bindingParameterIndices[0] -ne $script:D32BoundedDiagnosticSourceProofOuterPrelaunchBindingArgumentIndex -or
        $bindingParameterIndices[0] + 1 -ge $vector.Count) {
        throw 'D32_NON_SOURCE_L1_REFUSED: outer-prelaunch binding parameter is missing or duplicated'
    }
    $valueIndex = [int]($bindingParameterIndices[0] + 1)
    $binding = [string]$vector[$valueIndex]
    if ($binding -cnotmatch '^[0-9a-f]{64}$') { throw 'D32_NON_SOURCE_L1_REFUSED: outer-prelaunch binding value is malformed' }
    $image = [string]$Record.controller.executable_reference.path
    $actualCommandLine = Get-D32BoundedDiagnosticSourceProofOuterPrelaunchCommandLine -Image $image -Vector $vector
    $utf16Bytes = [Text.Encoding]::Unicode.GetBytes($actualCommandLine)
    $actualUtf16Sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf16Bytes)).ToLowerInvariant()
    if ([string]$Record.controller.arguments.command_line -cne $actualCommandLine -or
        [string]$Record.controller.arguments.command_line_utf16_sha256 -cne $actualUtf16Sha) {
        throw 'D32_NON_SOURCE_L1_REFUSED: raw outer command line differs from the source-pinned argv renderer'
    }
    $projection = Copy-D32BoundedDiagnosticSourceProofCanonicalJsonValue -Value $Record
    $projection.controller.arguments.vector[$valueIndex] = ('0' * 64)
    $projectionVector = [string[]]$projection.controller.arguments.vector
    $projectionCommandLine = Get-D32BoundedDiagnosticSourceProofOuterPrelaunchCommandLine -Image $image -Vector $projectionVector
    $projection.controller.arguments.command_line = $projectionCommandLine
    $projection.controller.arguments.command_line_utf16_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::Unicode.GetBytes($projectionCommandLine))).ToLowerInvariant()
    $canonicalBytes = ConvertTo-D32BoundedDiagnosticSourceProofCanonicalJsonBytes -Value $projection
    $prefix = [Text.Encoding]::ASCII.GetBytes("D32_NSL1_OUTER_PRELAUNCH_BINDING_V1`n")
    $material = [byte[]]::new($prefix.Length + $canonicalBytes.Length)
    [Array]::Copy($prefix, 0, $material, 0, $prefix.Length)
    [Array]::Copy($canonicalBytes, 0, $material, $prefix.Length, $canonicalBytes.Length)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($material)).ToLowerInvariant()
}

function Set-D32BoundedDiagnosticSourceProofOuterPrelaunchBinding {
    param([Parameter(Mandatory = $true)][object]$Record)
    if ($Record.controller.arguments.vector -isnot [Array]) { throw 'D32_NON_SOURCE_L1_REFUSED: outer prelaunch vector is missing' }
    foreach ($item in $Record.controller.arguments.vector) { if ($item -isnot [string]) { throw 'D32_NON_SOURCE_L1_REFUSED: outer argv contains a non-string value' } }
    $vector = [string[]]$Record.controller.arguments.vector
    $bindingIndices = [System.Collections.Generic.List[int]]::new()
    for ($index = 0; $index -lt $vector.Count; $index++) { if ($vector[$index] -ceq '-ExpectedOuterPrelaunchBindingSha256') { $bindingIndices.Add($index) } }
    if ($bindingIndices.Count -ne 1 -or $bindingIndices[0] -ne $script:D32BoundedDiagnosticSourceProofOuterPrelaunchBindingArgumentIndex -or
        $bindingIndices[0] + 1 -ge $vector.Count -or $vector[$bindingIndices[0] + 1] -cne ('0' * 64)) {
        throw 'D32_NON_SOURCE_L1_REFUSED: outer prelaunch must contain one fixed zero placeholder before binding'
    }
    $placeholderIndex = [int]($bindingIndices[0] + 1)
    $image = [string]$Record.controller.executable_reference.path
    $Record.controller.arguments.command_line = Get-D32BoundedDiagnosticSourceProofOuterPrelaunchCommandLine -Image $image -Vector $vector
    $Record.controller.arguments.command_line_utf16_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::Unicode.GetBytes([string]$Record.controller.arguments.command_line))).ToLowerInvariant()
    $binding = Get-D32BoundedDiagnosticSourceProofOuterPrelaunchBindingSha256 -Record $Record
    $vector[$placeholderIndex] = $binding
    $Record.controller.arguments.vector = $vector
    $Record.controller.arguments.command_line = Get-D32BoundedDiagnosticSourceProofOuterPrelaunchCommandLine -Image $image -Vector $vector
    $Record.controller.arguments.command_line_utf16_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::Unicode.GetBytes([string]$Record.controller.arguments.command_line))).ToLowerInvariant()
    return [PSCustomObject][ordered]@{ record=$Record; binding_sha256=$binding }
}

function Test-D32BoundedDiagnosticSourceProofOuterPrelaunchBinding {
    param([AllowNull()][object]$Record, [AllowNull()][object]$ExpectedBindingSha256)
    try {
        if ($null -eq $Record -or $ExpectedBindingSha256 -isnot [string] -or [string]$ExpectedBindingSha256 -cnotmatch '^[0-9a-f]{64}$') { return $false }
        $actual = Get-D32BoundedDiagnosticSourceProofOuterPrelaunchBindingSha256 -Record $Record
        $vector = [string[]]$Record.controller.arguments.vector
        $bindingIndex = -1
        for ($index = 0; $index -lt $vector.Count; $index++) { if ($vector[$index] -ceq '-ExpectedOuterPrelaunchBindingSha256') { $bindingIndex = $index + 1; break } }
        return ($actual -ceq [string]$ExpectedBindingSha256 -and
            $bindingIndex -eq ($script:D32BoundedDiagnosticSourceProofOuterPrelaunchBindingArgumentIndex + 1) -and
            $vector[$bindingIndex] -ceq [string]$ExpectedBindingSha256)
    } catch { return $false }
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeContentAuthorityShape {
    param([AllowNull()][object]$Document, [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository)
    try {
    $fields = @('schema_version','record_type','purpose','gate_authority','status','candidate_sha','source_repo','repository_identity',
        'powershell_runtime','distribution','resolver_policy','module_policy','startup_inputs','limits')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document $fields) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Document.schema_version -Positive) -or [Int64]$Document.schema_version -ne 1 -or
        [string]$Document.record_type -cne 'D32_NON_SOURCE_L1_RUNTIME_CONTENT_AUTHORITY_V1' -or
        [string]$Document.purpose -cne 'NON_SOURCE_L1_RUNTIME_ONLY' -or [string]$Document.gate_authority -cne 'NONE' -or
        [string]$Document.status -cne 'CANDIDATE_FOR_COORDINATOR_PIN' -or
        [string]$Document.candidate_sha -cne $ExpectedCandidateSha -or $ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.source_repo) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Document.source_repo,[IO.Path]::GetFullPath($Repository)) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Document.repository_identity)) { return $false }

    $runtime = $Document.powershell_runtime
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $runtime @('path','bytes','sha256','volume_serial_hex','file_id_hex','powershell_home','system_root')) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape ([PSCustomObject]@{path=$runtime.path;bytes=$runtime.bytes;sha256=$runtime.sha256;volume_serial_hex=$runtime.volume_serial_hex;file_id_hex=$runtime.file_id_hex})) -or
        [string]$runtime.path -cnotmatch '^[A-Za-z]:\\Program Files\\PowerShell\\7\\pwsh\.exe$' -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $runtime.powershell_home) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$runtime.path),[string]$runtime.powershell_home) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $runtime.system_root)) { return $false }

    $distribution = $Document.distribution
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $distribution @('root_path','inventory_sha256','directories','files','protected_ancestors','trusted_writer_sids')) -or
        [string]$distribution.root_path -cne [string]$runtime.powershell_home -or
        [string]$distribution.inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $distribution.directories -isnot [Array] -or $distribution.directories.Count -lt 1 -or $distribution.directories.Count -gt 1024 -or
        $distribution.files -isnot [Array] -or $distribution.files.Count -lt 1 -or $distribution.files.Count -gt 4096 -or
        $distribution.protected_ancestors -isnot [Array] -or $distribution.protected_ancestors.Count -lt 1 -or $distribution.protected_ancestors.Count -gt 1024) { return $false }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [decimal]$aggregateBytes = 0
    foreach ($spec in @(
        [PSCustomObject]@{ Items=@($distribution.directories); Fields=@('kind','path','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sddl','security_descriptor_sha256'); Kind='directory' },
        [PSCustomObject]@{ Items=@($distribution.files); Fields=@('kind','path','bytes','sha256','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sddl','security_descriptor_sha256'); Kind='file' },
        [PSCustomObject]@{ Items=@($distribution.protected_ancestors); Fields=@('kind','path','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sddl','security_descriptor_sha256'); Kind='ancestor' }
    )) {
        foreach ($entry in $spec.Items) {
            if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $entry $spec.Fields) -or
                [string]$entry.kind -cne $spec.Kind -or -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $entry.path) -or
                -not (Test-D32BoundedCompilerDiagnosticIdentityPair $entry) -or
                [string]$entry.owner_sid -cnotmatch '^S-1-(?:[0-9]{1,10}-)*[0-9]{1,10}$' -or
                [string]::IsNullOrWhiteSpace([string]$entry.security_descriptor_sddl) -or
                [string]$entry.security_descriptor_sha256 -cnotmatch '^[0-9a-f]{64}$' -or -not $seen.Add([string]$entry.path)) { return $false }
            if (($spec.Kind -ceq 'directory' -or $spec.Kind -ceq 'file') -and
                -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$entry.path,[string]$distribution.root_path) -and
                -not (Test-D32BoundedCompilerDiagnosticWithin ([string]$entry.path) ([string]$distribution.root_path))) { return $false }
            if ($spec.Kind -ceq 'ancestor' -and
                -not (Test-D32BoundedCompilerDiagnosticWithin ([string]$distribution.root_path) ([string]$entry.path))) { return $false }
            if ($spec.Kind -ceq 'file') {
                if (-not (Test-D32BoundedCompilerDiagnosticInteger $entry.bytes -Positive) -or [Int64]$entry.bytes -gt 268435456 -or
                    [string]$entry.sha256 -cnotmatch '^[0-9a-f]{64}$') { return $false }
                $aggregateBytes += [decimal]$entry.bytes
                if ($aggregateBytes -gt [decimal]2147483648) { return $false }
            }
        }
    }
    $expectedWriters = @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544')
    if ($distribution.trusted_writer_sids -isnot [Array] -or $distribution.trusted_writer_sids.Count -ne 3) { return $false }
    for ($index=0; $index -lt 3; $index++) { if ([string]$distribution.trusted_writer_sids[$index] -cne $expectedWriters[$index]) { return $false } }

    $resolver = $Document.resolver_policy
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $resolver @('policy_id','managed_distribution_root','managed_os_root','native_application_root','native_system_root','native_search_flags','forbidden_sources','os_security_components')) -or
        [string]$resolver.policy_id -cne 'D32_POWERSHELL_RESOLVER_DOMAIN_V2' -or
        [string]$resolver.managed_distribution_root -cne [string]$runtime.powershell_home -or
        [string]$resolver.native_application_root -cne [string]$runtime.powershell_home -or
        [string]$resolver.managed_os_root -cne [string]$runtime.system_root -or [string]$resolver.native_system_root -cne [string]$runtime.system_root -or
        $resolver.native_search_flags -isnot [Array] -or $resolver.forbidden_sources -isnot [Array] -or
        $resolver.os_security_components -isnot [Array] -or $resolver.os_security_components.Count -ne 2) { return $false }
    if ($resolver.native_search_flags.Count -ne 2 -or $resolver.forbidden_sources.Count -ne 6 -or
        [string]$resolver.native_search_flags[0] -cne 'LOAD_LIBRARY_SEARCH_APPLICATION_DIR' -or
        [string]$resolver.native_search_flags[1] -cne 'LOAD_LIBRARY_SEARCH_SYSTEM32' -or
        ([string]::Join('|',[string[]]$resolver.forbidden_sources) -cne 'CWD|PATH|USER_PSMODULEPATH|STARTUP_HOOKS|EXTERNAL_ASSEMBLIES|UNPINNED_DLL_DIRECTORIES') -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $resolver.os_security_components[0] @('component_type','version','root_path','root_volume_serial_hex','root_file_id_hex','inventory_sha256','source_proof','distribution','native_files')) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $resolver.os_security_components[1] @('component_type','version','root_path','root_volume_serial_hex','root_file_id_hex','inventory_sha256','source_proof','distribution','native_files')) -or
        [string]$resolver.os_security_components[0].component_type -cne 'MICROSOFT_WINDOWS_OS_INSTALLATION' -or
        [string]$resolver.os_security_components[1].component_type -cne 'MICROSOFT_WINDOWS_DEFENDER_PLATFORM' -or
        [string]$resolver.os_security_components[0].root_path -cne [string]$runtime.system_root -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $resolver.os_security_components[0] -VolumeName 'root_volume_serial_hex' -FileIdName 'root_file_id_hex') -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $resolver.os_security_components[1] -VolumeName 'root_volume_serial_hex' -FileIdName 'root_file_id_hex') -or
        [string]$resolver.os_security_components[0].inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$resolver.os_security_components[1].inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$resolver.os_security_components[0].source_proof.proof_type -cne 'GET_WINDOWSDIRECTORYW_OPENED_NAMESPACE_V1' -or
        [string]$resolver.os_security_components[1].source_proof.proof_type -cne 'WINTRUST_CACHE_ONLY_AUTHENTICODE_V1' -or
        [string]$resolver.os_security_components[1].source_proof.status -cne 'VERIFIED') { return $false }

    $modulePolicy = $Document.module_policy
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $modulePolicy @('policy_id','controller_utility_manifest','controller_utility_inventory_sha256','controller_import_count','reader_import_count','controller_allowed_commands','reader_wait_policy')) -or
        [string]$modulePolicy.policy_id -cne 'NON_SOURCE_L1_UTILITY_ONLY_V1' -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $modulePolicy.controller_utility_manifest) -or
        [string]$modulePolicy.controller_utility_manifest.path -cne [IO.Path]::GetFullPath([IO.Path]::Combine([string]$runtime.powershell_home,'Modules','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Utility.psd1')) -or
        [string]$modulePolicy.controller_utility_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $modulePolicy.controller_import_count -Positive) -or [Int64]$modulePolicy.controller_import_count -ne 1 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $modulePolicy.reader_import_count) -or [Int64]$modulePolicy.reader_import_count -ne 0 -or
        $modulePolicy.controller_allowed_commands -isnot [Array] -or $modulePolicy.controller_allowed_commands.Count -ne 2 -or
        [string]$modulePolicy.controller_allowed_commands[0] -cne 'Add-Type' -or [string]$modulePolicy.controller_allowed_commands[1] -cne 'ConvertTo-Json' -or
        [string]$modulePolicy.reader_wait_policy -cne 'MANAGED_FINITE_WAIT_V1') { return $false }

    $startup = $Document.startup_inputs
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $startup @('policy_id','deps','runtime_config','protected_startup_config','trusted_platform_assemblies','native_search','startup_hooks','profiling')) -or
        [string]$startup.policy_id -cne 'D32_NON_SOURCE_L1_STARTUP_INPUTS_V1' -or
        -not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeFileState $startup.deps) -or
        -not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeFileState $startup.runtime_config) -or
        -not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeFileState $startup.protected_startup_config)) { return $false }
    foreach ($input in @($startup.deps,$startup.runtime_config,$startup.protected_startup_config)) {
        if ([string]$input.state -ceq 'PRESENT' -and
            -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$input.reference.path),[string]$runtime.powershell_home) -and
            -not (Test-D32BoundedCompilerDiagnosticWithin ([string]$input.reference.path) ([string]$runtime.powershell_home))) { return $false }
    }
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $startup.trusted_platform_assemblies @('count','inventory_sha256','paths')) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $startup.trusted_platform_assemblies.count) -or [Int64]$startup.trusted_platform_assemblies.count -gt 1024 -or
        [string]$startup.trusted_platform_assemblies.inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $startup.trusted_platform_assemblies.paths -isnot [Array] -or $startup.trusted_platform_assemblies.paths.Count -ne [Int64]$startup.trusted_platform_assemblies.count -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $startup.native_search @('inventory_sha256','paths')) -or
        [string]$startup.native_search.inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $startup.native_search.paths -isnot [Array] -or
        $startup.native_search.paths.Count -gt 1024 -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $startup.startup_hooks @('state','paths')) -or
        [string]$startup.startup_hooks.state -cne 'ABSENT' -or $startup.startup_hooks.paths -isnot [Array] -or $startup.startup_hooks.paths.Count -ne 0 -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $startup.profiling @('enabled','variables')) -or
        $startup.profiling.enabled -isnot [bool] -or [bool]$startup.profiling.enabled -or
        $startup.profiling.variables -isnot [Array] -or $startup.profiling.variables.Count -ne 0) { return $false }
    foreach ($reference in @($startup.trusted_platform_assemblies.paths) + @($startup.native_search.paths)) {
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $reference) -or
            (-not (Test-D32BoundedCompilerDiagnosticWithin ([string]$reference.path) ([string]$runtime.powershell_home)) -and
             -not (Test-D32BoundedCompilerDiagnosticWithin ([string]$reference.path) ([string]$runtime.system_root)) -and
             -not (Test-D32BoundedCompilerDiagnosticWithin ([string]$reference.path) 'C:\ProgramData\Microsoft\Windows Defender\Platform'))) { return $false }
    }
    $limits = $Document.limits
    $expectedLimits = [ordered]@{ runtime_bytes=4194304L; file_count=4096L; directory_count=1024L; aggregate_bytes=2147483648L; single_file_bytes=268435456L; resolver_list_entries=1024L }
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $limits @($expectedLimits.Keys))) { return $false }
    foreach ($name in $expectedLimits.Keys) { if (-not (Test-D32BoundedCompilerDiagnosticInteger $limits.$name -Positive) -or [Int64]$limits.$name -ne [Int64]$expectedLimits[$name]) { return $false } }
    return ($distribution.files.Count -le [Int64]$limits.file_count -and $distribution.directories.Count -le [Int64]$limits.directory_count -and
        $aggregateBytes -le [decimal]$limits.aggregate_bytes)
    } catch { return $false }
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeContentAuthorityBinding {
    param([AllowNull()][object]$Document, [AllowNull()][object]$Authority,
        [AllowNull()][object]$OpenedReference)
    try {
        if ($null -eq $Authority -or $null -eq $OpenedReference -or
            -not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeContentAuthorityShape -Document $Document `
                -ExpectedCandidateSha ([string]$Authority.candidate_sha) -Repository ([string]$Authority.source_repo))) { return $false }
        foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
            if ([string]$Authority.runtime_authority.$name -cne [string]$OpenedReference.$name) { return $false }
        }
        if ([string]$Document.candidate_sha -cne [string]$Authority.candidate_sha -or
            [string]$Document.source_repo -cne [string]$Authority.source_repo -or
            [string]$Document.repository_identity.volume_serial_hex -cne [string]$Authority.repository_identity.volume_serial_hex -or
            [string]$Document.repository_identity.file_id_hex -cne [string]$Authority.repository_identity.file_id_hex) { return $false }
        foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex','powershell_home','system_root')) {
            if ([string]$Document.powershell_runtime.$name -cne [string]$Authority.powershell_runtime.$name) { return $false }
        }
        return $true
    } catch { return $false }
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeAdmissionShape {
    param([AllowNull()][object]$Admission, [Parameter(Mandatory = $true)][object]$Authority,
        [Parameter(Mandatory = $true)][string]$Role, [AllowNull()][object]$ParentAdmissionReference,
        [AllowNull()][object]$ParentAdmission, [Parameter(Mandatory = $true)][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][object]$OuterPrelaunchReference)
    try {
    $fields = @('schema_version','record_type','purpose','gate_authority','candidate_sha','batch_id','run_id','authority_reference',
        'runtime_authority_reference','outer_prelaunch_reference','parent_admission_reference','powershell_host','runner_process','startup',
        'entry_script','environment','clock','namespace_witness','module_import_order','module_closure','resolver_admission',
        'import_verification','import_attempts','status','primary_error','secondary_errors')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Admission $fields) -or
        [Int64]$Admission.schema_version -ne 1 -or [string]$Admission.record_type -cne 'D32_NON_SOURCE_L1_RUNTIME_ADMISSION_V1' -or
        [string]$Admission.purpose -cne 'NON_SOURCE_L1_PROCESS_RUNTIME_ADMISSION' -or [string]$Admission.gate_authority -cne 'NONE' -or
        [string]$Admission.candidate_sha -cne [string]$Authority.candidate_sha -or [string]$Admission.batch_id -cne [string]$Authority.batch_id -or
        [string]$Admission.run_id -cne [string]$Authority.run_id -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Admission.authority_reference) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $AuthorityReference) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Admission.runtime_authority_reference) -or
        [string]$Admission.runtime_authority_reference.path -cne [string]$Authority.runtime_authority.path -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Admission.outer_prelaunch_reference) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $OuterPrelaunchReference) -or
        (($null -eq $ParentAdmissionReference) -ne ($null -eq $Admission.parent_admission_reference)) -or
        ($null -ne $ParentAdmissionReference -and -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Admission.parent_admission_reference)) -or
        (($null -eq $ParentAdmission) -ne ($null -eq $ParentAdmissionReference)) -or
        [string]$Admission.status -cnotin @('ADMITTED','REFUSED') -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Admission.import_attempts) -or
        $Admission.secondary_errors -isnot [Array] -or $Admission.secondary_errors.Count -gt 8 -or
        (($null -ne $Admission.primary_error) -and ($Admission.primary_error -isnot [string] -or ([string]$Admission.primary_error).Length -gt 2048))) { return $false }
    foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
        if ([string]$Admission.runtime_authority_reference.$name -cne [string]$Authority.runtime_authority.$name -or
            [string]$Admission.authority_reference.$name -cne [string]$AuthorityReference.$name -or
            [string]$Admission.outer_prelaunch_reference.$name -cne [string]$OuterPrelaunchReference.$name) { return $false }
    }
    if ([string]$Admission.outer_prelaunch_reference.path -cne [string]$Authority.output.outer_prelaunch_path -or
        ([string]$Role -ceq 'CONTROLLER' -and $null -ne $ParentAdmissionReference) -or
        ([string]$Role -cne 'CONTROLLER' -and $null -eq $ParentAdmissionReference) -or
        ([string]$Role -cne 'CONTROLLER' -and [string]$Admission.parent_admission_reference.path -cne [string]$Authority.output.controller_runtime_admission_path) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Admission.runner_process @('role','process_id','creation_filetime_ticks','image_reference','ordinary_token','parent_process')) -or
        [string]$Admission.runner_process.role -cne $Role -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Admission.runner_process.process_id -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Admission.runner_process.creation_filetime_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Admission.runner_process.image_reference) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Admission.runner_process.ordinary_token @('elevated','high_integrity','system_token','thread_impersonation')) -or
        $Admission.runner_process.ordinary_token.elevated -isnot [bool] -or $Admission.runner_process.ordinary_token.high_integrity -isnot [bool] -or
        $Admission.runner_process.ordinary_token.system_token -isnot [bool] -or $Admission.runner_process.ordinary_token.thread_impersonation -isnot [bool] -or
        $Admission.runner_process.ordinary_token.elevated -or $Admission.runner_process.ordinary_token.high_integrity -or
        $Admission.runner_process.ordinary_token.system_token -or $Admission.runner_process.ordinary_token.thread_impersonation) { return $false }
    $entryIndex = if ($Role -ceq 'CONTROLLER') { 0 } else { 1 }
    $expectedEntryPin = $Authority.source_pins[$entryIndex]
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Admission.entry_script @('path','bytes','sha256','volume_serial_hex','file_id_hex')) -or
        [string]$Admission.entry_script.path -cne [string]$expectedEntryPin.path -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Admission.powershell_host @('path','sha256','bytes','volume_serial_hex','file_id_hex','pshome')) -or
        [string]$Admission.powershell_host.path -cne [string]$Authority.powershell_runtime.path -or
        [string]$Admission.powershell_host.sha256 -cne [string]$Authority.powershell_runtime.sha256 -or
        [Int64]$Admission.powershell_host.bytes -ne [Int64]$Authority.powershell_runtime.bytes -or
        [string]$Admission.powershell_host.volume_serial_hex -cne [string]$Authority.powershell_runtime.volume_serial_hex -or
        [string]$Admission.powershell_host.file_id_hex -cne [string]$Authority.powershell_runtime.file_id_hex -or
        [string]$Admission.powershell_host.pshome -cne [string]$Authority.powershell_runtime.powershell_home -or
        [string]$Admission.entry_script.sha256 -cne [string]$expectedEntryPin.sha256 -or
        [Int64]$Admission.entry_script.bytes -ne [Int64]$expectedEntryPin.bytes -or
        [string]$Admission.entry_script.volume_serial_hex -cne [string]$expectedEntryPin.volume_serial_hex -or
        [string]$Admission.entry_script.file_id_hex -cne [string]$expectedEntryPin.file_id_hex -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Admission.environment @('entries','block_sha256','inherited_environment_cleared','autoload','module_path')) -or
        $Admission.environment.entries -isnot [Array] -or $Admission.environment.entries.Count -ne 15 -or
        [string]$Admission.environment.block_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $Admission.environment.inherited_environment_cleared -isnot [bool] -or
        -not $Admission.environment.inherited_environment_cleared -or [string]$Admission.environment.autoload -cne 'None' -or
        [string]$Admission.environment.module_path -cne [string]$Authority.powershell_runtime.powershell_home.TrimEnd('\') + '\Modules') { return $false }
    $expectedEnvironment = Get-D32BoundedDiagnosticSourceProofNonSourceL1EnvironmentEntries -Environment $Authority.invocation.child_environment
    if ($Admission.environment.entries.Count -ne $expectedEnvironment.Count) { return $false }
    for ($index = 0; $index -lt $expectedEnvironment.Count; $index++) {
        if ($Admission.environment.entries[$index] -isnot [string] -or [string]$Admission.environment.entries[$index] -cne [string]$expectedEnvironment[$index]) { return $false }
    }
    if ([string]$Admission.environment.block_sha256 -cne (Get-D32BoundedDiagnosticSourceProofNonSourceL1EnvironmentBlockSha256 -Entries ([string[]]$Admission.environment.entries))) { return $false }
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Admission.startup @('file_operand','switches','arguments','command_line','startup_policy')) -or
        [string]$Admission.startup.file_operand -cne [string]$expectedEntryPin.path -or
        $Admission.startup.switches -isnot [Array] -or [string]$Admission.startup.startup_policy -cne 'DIRECT_NO_PROFILE_FILE_V1' -or
        $Admission.startup.arguments -isnot [Array] -or
        [string]$Admission.startup.command_line -match '(?i)(?:-Command|-EncodedCommand|-ConfigurationFile|Start-Process)' -or
        [string]$Admission.startup.command_line -cne (Get-D32BoundedDiagnosticSourceProofNonSourceL1ExpectedCommandLine -Image ([string]$Authority.powershell_runtime.path) -Arguments ([string[]]$Admission.startup.arguments)) -or
        [string]$Admission.startup.arguments[([Array]::IndexOf([object[]]$Admission.startup.arguments, '-File') + 1)] -cne [string]$expectedEntryPin.path) { return $false }
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Admission.clock @('counter_origin','frequency','batch_t0_ticks','observed_ticks','deadline_ticks')) -or
        [string]$Admission.clock.counter_origin -cne 'QueryPerformanceCounter' -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Admission.clock.frequency -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Admission.clock.batch_t0_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Admission.clock.observed_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Admission.clock.deadline_ticks -Positive) -or
        [Int64]$Admission.clock.observed_ticks -lt [Int64]$Admission.clock.batch_t0_ticks -or
        [Int64]$Admission.clock.observed_ticks -ge [Int64]$Admission.clock.deadline_ticks) { return $false }
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Admission.namespace_witness @('runtime_inventory_sha256','resolver_inventory_sha256','file_count','directory_count','live_fences_verified','caller_owned')) -or
        [string]$Admission.namespace_witness.runtime_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Admission.namespace_witness.resolver_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Admission.namespace_witness.file_count) -or [Int64]$Admission.namespace_witness.file_count -gt 4096 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Admission.namespace_witness.directory_count) -or [Int64]$Admission.namespace_witness.directory_count -gt 1024 -or
        $Admission.namespace_witness.live_fences_verified -isnot [bool] -or -not $Admission.namespace_witness.live_fences_verified -or
        $Admission.namespace_witness.caller_owned -isnot [bool] -or -not $Admission.namespace_witness.caller_owned) { return $false }
    if ($Admission.module_import_order -isnot [Array] -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Admission.module_closure @('policy_id','inventory_sha256','manifest_reference')) -or
        [string]$Admission.module_closure.policy_id -cne 'NON_SOURCE_L1_UTILITY_ONLY_V1' -or
        [string]$Admission.module_closure.inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Admission.module_closure.manifest_reference) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Admission.import_verification @('passed','managed_origins','native_origins','utility_origin_count','unexpected_origins')) -or
        $Admission.import_verification.passed -isnot [bool] -or $Admission.import_verification.managed_origins -isnot [Array] -or
        $Admission.import_verification.native_origins -isnot [Array] -or $Admission.import_verification.unexpected_origins -isnot [Array] -or
        $Admission.import_verification.unexpected_origins.Count -ne 0 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Admission.import_verification.utility_origin_count) -or
        $Admission.resolver_admission -isnot [System.Collections.IDictionary] -and $Admission.resolver_admission -isnot [PSCustomObject]) { return $false }
    $expectedImports = if ($Role -ceq 'CONTROLLER') { 1 } else { 0 }
    if ([Int64]$Admission.import_attempts -ne $expectedImports -or $Admission.module_import_order.Count -ne $expectedImports -or
        [Int64]$Admission.import_verification.utility_origin_count -ne $expectedImports -or
        ($expectedImports -eq 1 -and [string]$Admission.module_import_order[0] -cne 'Microsoft.PowerShell.Utility') -or
        [string]$Admission.resolver_admission.policy_id -cne 'D32_POWERSHELL_RESOLVER_DOMAIN_V2') { return $false }
    if ($null -ne $ParentAdmissionReference) {
        foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
            if ([string]$Admission.parent_admission_reference.$name -cne [string]$ParentAdmissionReference.$name) { return $false }
        }
        if ([string]$Admission.runner_process.parent_process.process_id -cne [string]$ParentAdmission.runner_process.process_id -or
            [string]$Admission.runner_process.parent_process.creation_filetime_ticks -cne [string]$ParentAdmission.runner_process.creation_filetime_ticks) { return $false }
    } else {
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Admission.runner_process.parent_process @('process_id','creation_filetime_ticks')) -or
            [Int64]$Admission.runner_process.parent_process.process_id -ne [Int64]$Authority.outer_caller.observer_process.process_id -or
            [Int64]$Admission.runner_process.parent_process.creation_filetime_ticks -ne [Int64]$Authority.outer_caller.observer_process.creation_filetime_ticks) { return $false }
    }
    return ($null -eq $Admission.primary_error -or [string]$Admission.status -ceq 'REFUSED')
    } catch { return $false }
}

function Get-D32BoundedDiagnosticSourceProofNonSourceL1ReferenceProjection {
    param([Parameter(Mandatory = $true)][object]$Reference)
    return [PSCustomObject][ordered]@{ path=$Reference.path; bytes=$Reference.bytes; sha256=$Reference.sha256; volume_serial_hex=$Reference.volume_serial_hex; file_id_hex=$Reference.file_id_hex }
}

function ConvertTo-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityV1Projection {
    param([Parameter(Mandatory = $true)][object]$Document)
    $output = [PSCustomObject][ordered]@{}
    foreach ($name in @('root_path','parent_path','root_volume_serial_hex','root_file_id_hex','parent_volume_serial_hex','parent_file_id_hex','result_path','journal_path')) {
        $null = Add-Member -InputObject $output -NotePropertyName $name -NotePropertyValue $Document.output.$name
    }
    $invocation = [PSCustomObject][ordered]@{ role='D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_V1'; entry_path=$Document.invocation.entry_path
        working_directory=$Document.invocation.working_directory; argument_policy='D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_ARGV_V1'
        environment_policy='D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_ENV_V1'; child_environment=$Document.invocation.child_environment }
    return [PSCustomObject][ordered]@{
        schema_version=1; record_type='D32_BOUNDED_SOURCEPROOF_NON_SOURCE_L1_AUTHORITY_V1'; purpose=$Document.purpose
        policy='D32_SOURCEPROOF_NON_SOURCE_L1_V1'; gate_authority=$Document.gate_authority; candidate_sha=$Document.candidate_sha
        source_repo=$Document.source_repo; repository_identity=$Document.repository_identity; batch_id=$Document.batch_id; run_id=$Document.run_id
        owner_id=$Document.owner_id; source_pins=@($Document.source_pins); powershell_runtime=$Document.powershell_runtime
        invocation=$invocation; cases=@($Document.cases); output=$output; limits=$Document.limits; issued_at_utc=$Document.issued_at_utc
    }
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1OuterCallerShape {
    param([AllowNull()][object]$OuterCaller, [Parameter(Mandatory = $true)][object]$Authority)
    try {
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $OuterCaller @('role','entry_reference','observer_host_reference','observer_process','observer_process_policy','invocation_policy','capture_policy','ownership_policy')) -or
        [string]$OuterCaller.role -cne 'D32_NON_SOURCE_L1_FIXED_OUTER_CALLER_V1' -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $OuterCaller.entry_reference) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $OuterCaller.observer_host_reference) -or
        [string]$OuterCaller.entry_reference.path -cne [string]$Authority.source_pins[0].path -or
        [string]$OuterCaller.observer_host_reference.path -cne [string]$Authority.powershell_runtime.path -or
        [string]$OuterCaller.observer_process_policy -cne 'EXISTING_TRUSTED_OBSERVER_CURRENT_PROCESS_V1' -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $OuterCaller.observer_process @('process_id','creation_filetime_ticks','image_reference','ordinary_token')) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $OuterCaller.observer_process.process_id -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $OuterCaller.observer_process.creation_filetime_ticks -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $OuterCaller.observer_process.image_reference) -or
        [string]$OuterCaller.observer_process.image_reference.path -cne [string]$Authority.powershell_runtime.path -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $OuterCaller.observer_process.ordinary_token @('elevated','high_integrity','system_token','thread_impersonation')) -or
        $OuterCaller.observer_process.ordinary_token.elevated -isnot [bool] -or $OuterCaller.observer_process.ordinary_token.high_integrity -isnot [bool] -or
        $OuterCaller.observer_process.ordinary_token.system_token -isnot [bool] -or $OuterCaller.observer_process.ordinary_token.thread_impersonation -isnot [bool] -or
        $OuterCaller.observer_process.ordinary_token.elevated -or $OuterCaller.observer_process.ordinary_token.high_integrity -or
        $OuterCaller.observer_process.ordinary_token.system_token -or $OuterCaller.observer_process.ordinary_token.thread_impersonation -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $OuterCaller.invocation_policy @('argv_policy','environment_policy','working_directory_policy','inherit_ambient_handles')) -or
        [string]$OuterCaller.invocation_policy.argv_policy -cne 'D32_NON_SOURCE_L1_FIXED_CONTROLLER_ARGV_V1' -or
        [string]$OuterCaller.invocation_policy.environment_policy -cne 'D32_NON_SOURCE_L1_CLEARED_FIXED_15_ENV_V1' -or
        [string]$OuterCaller.invocation_policy.working_directory_policy -cne 'OWNER_BOUND_L1_ROOT_V1' -or
        $OuterCaller.invocation_policy.inherit_ambient_handles -isnot [bool] -or $OuterCaller.invocation_policy.inherit_ambient_handles -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $OuterCaller.capture_policy @('stdout_path','stderr_path','stdout_max_bytes','stderr_max_bytes','create_new')) -or
        [string]$OuterCaller.capture_policy.stdout_path -cne [string]$Authority.output.stdout_path -or
        [string]$OuterCaller.capture_policy.stderr_path -cne [string]$Authority.output.stderr_path -or
        [Int64]$OuterCaller.capture_policy.stdout_max_bytes -ne 16000 -or [Int64]$OuterCaller.capture_policy.stderr_max_bytes -ne 16000 -or
        $OuterCaller.capture_policy.create_new -isnot [bool] -or -not $OuterCaller.capture_policy.create_new -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $OuterCaller.ownership_policy @('outer_job_policy','outer_active_process_limit','reader_active_process_limit','kill_on_close','non_breakaway','controller_creation_policy')) -or
        [string]$OuterCaller.ownership_policy.outer_job_policy -cne 'CALLER_OWNED_NESTED_JOB_V1' -or
        [Int64]$OuterCaller.ownership_policy.outer_active_process_limit -ne 2 -or [Int64]$OuterCaller.ownership_policy.reader_active_process_limit -ne 1 -or
        $OuterCaller.ownership_policy.kill_on_close -isnot [bool] -or -not $OuterCaller.ownership_policy.kill_on_close -or
        $OuterCaller.ownership_policy.non_breakaway -isnot [bool] -or -not $OuterCaller.ownership_policy.non_breakaway -or
        [string]$OuterCaller.ownership_policy.controller_creation_policy -cne 'SUSPENDED_ASSIGN_RESUME_ONCE_V1') { return $false }
    return $true
    } catch { return $false }
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape {
    param([AllowNull()][object]$Document, [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository)
    try {
    $fields = @('schema_version','record_type','purpose','policy','gate_authority','candidate_sha','source_repo','repository_identity','batch_id',
        'run_id','owner_id','source_pins','powershell_runtime','runtime_authority','invocation','outer_caller','cases','output','limits','issued_at_utc')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document $fields) -or
        [Int64]$Document.schema_version -ne 2 -or [string]$Document.record_type -cne $script:D32BoundedDiagnosticSourceProofNonSourceL1AuthorityType -or
        [string]$Document.policy -cne $script:D32BoundedDiagnosticSourceProofNonSourceL1Policy -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Document.runtime_authority) -or
        (Test-D32BoundedCompilerDiagnosticWithin ([string]$Document.runtime_authority.path) $Repository) -or
        (Test-D32BoundedCompilerDiagnosticWithin ([string]$Document.runtime_authority.path) 'E:\d32\inv7\r\c') -or
        (Test-D32BoundedCompilerDiagnosticWithin ([string]$Document.runtime_authority.path) ([string]$Document.output.root_path))) { return $false }
    $expectedPaths = Get-D32BoundedDiagnosticSourceProofNonSourceL1OutputPaths -Root ([string]$Document.output.root_path) -BatchId ([string]$Document.batch_id)
    $outputNames = @('root_path','parent_path','root_volume_serial_hex','root_file_id_hex','parent_volume_serial_hex','parent_file_id_hex','result_path','journal_path') + @($expectedPaths.PSObject.Properties.Name)
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.output $outputNames)) { return $false }
    foreach ($name in $expectedPaths.PSObject.Properties.Name) {
        if ([string]$Document.output.$name -cne [string]$expectedPaths.$name -or -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.output.$name)) { return $false }
    }
    if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1Environment -Environment $Document.invocation.child_environment -Runtime $Document.powershell_runtime -Root ([string]$Document.output.root_path)) -or
        [string]$Document.invocation.role -cne 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_V2' -or
        [string]$Document.invocation.argument_policy -cne 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_ARGV_V2' -or
        [string]$Document.invocation.environment_policy -cne 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_ENV_V2' -or
        -not (Test-D32BoundedDiagnosticSourceProofNonSourceL1OuterCallerShape -OuterCaller $Document.outer_caller -Authority $Document)) { return $false }
    $projection = ConvertTo-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityV1Projection -Document $Document
    return (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShapeV1Internal -Document $projection -ExpectedCandidateSha $ExpectedCandidateSha -Repository $Repository)
    } catch { return $false }
}

function New-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityCandidate {
    param([Parameter(Mandatory = $true)][string]$CandidateSha, [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][object]$RepositoryIdentity, [Parameter(Mandatory = $true)][string]$BatchId,
        [Parameter(Mandatory = $true)][string]$RunId, [Parameter(Mandatory = $true)][string]$OwnerId,
        [Parameter(Mandatory = $true)][object[]]$SourcePins, [Parameter(Mandatory = $true)][object]$PowerShellRuntime,
        [Parameter(Mandatory = $true)][object]$RuntimeAuthority, [Parameter(Mandatory = $true)][object]$Invocation,
        [Parameter(Mandatory = $true)][object]$OuterCaller, [Parameter(Mandatory = $true)][object[]]$Cases,
        [Parameter(Mandatory = $true)][object]$Output, [string]$IssuedAtUtc = [DateTimeOffset]::UtcNow.ToString('o'))
    $document = New-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityCandidateV1Internal -CandidateSha $CandidateSha -Repository $Repository `
        -RepositoryIdentity $RepositoryIdentity -BatchId $BatchId -RunId $RunId -OwnerId $OwnerId -SourcePins $SourcePins -PowerShellRuntime $PowerShellRuntime `
        -Invocation $Invocation -Cases $Cases -Output $Output -IssuedAtUtc $IssuedAtUtc
    $document.schema_version = 2; $document.record_type = $script:D32BoundedDiagnosticSourceProofNonSourceL1AuthorityType
    $document.policy = $script:D32BoundedDiagnosticSourceProofNonSourceL1Policy
    $null = Add-Member -InputObject $document -NotePropertyName runtime_authority -NotePropertyValue $RuntimeAuthority
    $document.invocation.role = 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_V2'
    $document.invocation.argument_policy = 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_ARGV_V2'
    $document.invocation.environment_policy = 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_ENV_V2'
    $null = Add-Member -InputObject $document -NotePropertyName outer_caller -NotePropertyValue $OuterCaller
    $derived = Get-D32BoundedDiagnosticSourceProofNonSourceL1OutputPaths -Root ([string]$document.output.root_path) -BatchId $BatchId
    foreach ($name in $derived.PSObject.Properties.Name) { $null = Add-Member -InputObject $document.output -NotePropertyName $name -NotePropertyValue $derived.$name }
    return $document
}

function ConvertTo-D32BoundedDiagnosticSourceProofNonSourceL1ResultV1Projection {
    param([Parameter(Mandatory = $true)][object]$Record)
    $output = [PSCustomObject][ordered]@{}
    foreach ($name in @('root_path','parent_path','root_volume_serial_hex','root_file_id_hex','parent_volume_serial_hex','parent_file_id_hex','result_path','journal_path')) {
        $null = Add-Member -InputObject $output -NotePropertyName $name -NotePropertyValue $Record.output.$name
    }
    $projection = [PSCustomObject][ordered]@{}
    foreach ($name in @('schema_version','purpose','gate_authority','candidate_sha','batch_id','run_id','authority','source_pins','powershell_runtime','clock','controller','cases',
        'create_process_attempt_count','planned_termination_count','fail_safe_termination_count','abrupt_owner_abort','status','source_proof_checkpoint','source_closure',
        'diagnostic_invocation_authority','formal_gate_usable','formal_phase_allowed','formal_aggregate_allowed','primary_error','secondary_errors','started_at_utc','completed_at_utc')) {
        if ($name -ceq 'schema_version') { $null = Add-Member -InputObject $projection -NotePropertyName $name -NotePropertyValue 1; continue }
        $null = Add-Member -InputObject $projection -NotePropertyName $name -NotePropertyValue $Record.$name
    }
    $null = Add-Member -InputObject $projection -NotePropertyName record_type -NotePropertyValue 'D32_BOUNDED_SOURCEPROOF_NON_SOURCE_L1_V1'
    $null = Add-Member -InputObject $projection -NotePropertyName policy -NotePropertyValue 'D32_SOURCEPROOF_NON_SOURCE_L1_V1'
    $null = Add-Member -InputObject $projection -NotePropertyName output -NotePropertyValue $output
    return $projection
}

function New-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeAdmissionSlot {
    param([Parameter(Mandatory = $true)][string]$Role, [string]$Status = 'NOT_RUN',
        [AllowNull()][object]$Reference = $null, [AllowNull()][object]$Admission = $null)
    return [PSCustomObject][ordered]@{ role=$Role; status=$Status; reference=$Reference; admission=$Admission }
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape {
    param([AllowNull()][object]$Record)
    try {
    $fields = @('schema_version','record_type','purpose','policy','gate_authority','candidate_sha','batch_id','run_id','authority','source_pins',
        'powershell_runtime','runtime_authority','outer_prelaunch_reference','runtime_admissions','output','clock','controller','cases',
        'create_process_attempt_count','planned_termination_count','fail_safe_termination_count','abrupt_owner_abort','status','source_proof_checkpoint',
        'source_closure','diagnostic_invocation_authority','formal_gate_usable','formal_phase_allowed','formal_aggregate_allowed','primary_error','secondary_errors','started_at_utc','completed_at_utc')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record $fields) -or [Int64]$Record.schema_version -ne 2 -or
        [string]$Record.record_type -cne $script:D32BoundedDiagnosticSourceProofNonSourceL1ResultType -or
        [string]$Record.policy -cne $script:D32BoundedDiagnosticSourceProofNonSourceL1Policy -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Record.runtime_authority) -or
        (($null -ne $Record.outer_prelaunch_reference) -and -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Record.outer_prelaunch_reference)) -or
        $Record.runtime_admissions -isnot [Array] -or $Record.runtime_admissions.Count -ne 3) { return $false }
    $roles = @('CONTROLLER','NORMAL_READER','FORCED_READER')
    for ($index=0; $index -lt 3; $index++) {
        $slot = $Record.runtime_admissions[$index]
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $slot @('role','status','reference','admission')) -or
            [string]$slot.role -cne $roles[$index] -or [string]$slot.status -cnotin @('ADMITTED','REFUSED','NOT_RUN')) { return $false }
        if ([string]$slot.status -ceq 'NOT_RUN') {
            if ($null -ne $slot.reference -or $null -ne $slot.admission) { return $false }
        } elseif (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $slot.reference) -or $null -eq $slot.admission -or
            [string]$slot.admission.status -cne [string]$slot.status -or [string]$slot.admission.candidate_sha -cne [string]$Record.candidate_sha -or
            [string]$slot.admission.batch_id -cne [string]$Record.batch_id -or [string]$slot.admission.run_id -cne [string]$Record.run_id) { return $false }
    }
    if ([string]$Record.status -ceq 'COMPLETE_NON_SOURCE_L1') {
        if ($null -eq $Record.outer_prelaunch_reference) { return $false }
        foreach ($slot in $Record.runtime_admissions) { if ([string]$slot.status -cne 'ADMITTED' -or $null -eq $slot.admission) { return $false } }
    }
    $projection = ConvertTo-D32BoundedDiagnosticSourceProofNonSourceL1ResultV1Projection -Record $Record
    return (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShapeV1Internal $projection -RuntimeAdmissions @($Record.runtime_admissions))
    } catch { return $false }
}

function New-D32BoundedDiagnosticSourceProofNonSourceL1ResultCandidate {
    param([Parameter(Mandatory = $true)][string]$CandidateSha, [Parameter(Mandatory = $true)][string]$BatchId,
        [Parameter(Mandatory = $true)][string]$RunId, [Parameter(Mandatory = $true)][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][object[]]$SourcePins, [Parameter(Mandatory = $true)][object]$PowerShellRuntime,
        [Parameter(Mandatory = $true)][object]$Output, [Parameter(Mandatory = $true)][object]$Clock,
        [Parameter(Mandatory = $true)][object]$Controller, [Parameter(Mandatory = $true)][object[]]$Cases,
        [Parameter(Mandatory = $true)][long]$CreateProcessAttemptCount, [Parameter(Mandatory = $true)][long]$PlannedTerminationCount,
        [Parameter(Mandatory = $true)][long]$FailSafeTerminationCount, [Parameter(Mandatory = $true)][string]$Status,
        [AllowNull()][object]$PrimaryError, [string[]]$SecondaryErrors = @(),
        [Parameter(Mandatory = $true)][string]$StartedAtUtc, [Parameter(Mandatory = $true)][string]$CompletedAtUtc,
        [Parameter(Mandatory = $true)][object]$RuntimeAuthority, [AllowNull()][object]$OuterPrelaunchReference = $null,
        [object[]]$RuntimeAdmissions = @())
    $record = New-D32BoundedDiagnosticSourceProofNonSourceL1ResultCandidateV1Internal -CandidateSha $CandidateSha -BatchId $BatchId -RunId $RunId `
        -AuthorityReference $AuthorityReference -SourcePins $SourcePins -PowerShellRuntime $PowerShellRuntime -Output $Output -Clock $Clock `
        -Controller $Controller -Cases $Cases -CreateProcessAttemptCount $CreateProcessAttemptCount -PlannedTerminationCount $PlannedTerminationCount `
        -FailSafeTerminationCount $FailSafeTerminationCount -Status $Status -PrimaryError $PrimaryError -SecondaryErrors $SecondaryErrors `
        -StartedAtUtc $StartedAtUtc -CompletedAtUtc $CompletedAtUtc
    $record.schema_version = 2; $record.record_type = $script:D32BoundedDiagnosticSourceProofNonSourceL1ResultType
    $record.policy = $script:D32BoundedDiagnosticSourceProofNonSourceL1Policy
    $null = Add-Member -InputObject $record -NotePropertyName runtime_authority -NotePropertyValue $RuntimeAuthority
    $null = Add-Member -InputObject $record -NotePropertyName outer_prelaunch_reference -NotePropertyValue $OuterPrelaunchReference
    if ($RuntimeAdmissions.Count -eq 0) {
        $RuntimeAdmissions = @((New-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeAdmissionSlot 'CONTROLLER'),
            (New-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeAdmissionSlot 'NORMAL_READER'),
            (New-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeAdmissionSlot 'FORCED_READER'))
    }
    $null = Add-Member -InputObject $record -NotePropertyName runtime_admissions -NotePropertyValue @($RuntimeAdmissions)
    return $record
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultBindings {
    param([AllowNull()][object]$Record, [AllowNull()][object]$Authority, [AllowNull()][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][string]$ExpectedAuthorityPath, [Parameter(Mandatory = $true)][string]$ExpectedAuthoritySha256,
        [AllowNull()][object]$PersistedFact, [AllowNull()][object]$ResultReference,
        [AllowNull()][object]$RuntimeAuthorityContent, [AllowNull()][object]$RuntimeAuthorityOpenedReference)
    try {
    if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape $Record) -or
        -not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $Authority -ExpectedCandidateSha ([string]$Record.candidate_sha) -Repository ([string]$Authority.source_repo))) { return $false }
    $projection = ConvertTo-D32BoundedDiagnosticSourceProofNonSourceL1ResultV1Projection -Record $Record
    $authorityProjection = ConvertTo-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityV1Projection -Document $Authority
    if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultBindingsV1Internal -Record $projection -Authority $authorityProjection `
        -AuthorityReference $AuthorityReference -ExpectedAuthorityPath $ExpectedAuthorityPath -ExpectedAuthoritySha256 $ExpectedAuthoritySha256 `
        -PersistedFact $PersistedFact -ResultReference $ResultReference -RuntimeAdmissions @($Record.runtime_admissions))) { return $false }
    if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeContentAuthorityBinding -Document $RuntimeAuthorityContent `
        -Authority $Authority -OpenedReference $RuntimeAuthorityOpenedReference)) { return $false }
    foreach ($name in @('path','bytes','sha256','volume_serial_hex','file_id_hex')) {
        if ([string]$Record.runtime_authority.$name -cne [string]$Authority.runtime_authority.$name) { return $false }
    }
    if ($null -ne $Record.outer_prelaunch_reference -and [string]$Record.outer_prelaunch_reference.path -cne [string]$Authority.output.outer_prelaunch_path) { return $false }
    for ($index=0; $index -lt 3; $index++) {
        $slot = $Record.runtime_admissions[$index]
        $expectedPath = @([string]$Authority.output.controller_runtime_admission_path,[string]$Authority.output.normalreader_runtime_admission_path,[string]$Authority.output.forcedreader_runtime_admission_path)[$index]
        if ([string]$slot.status -ceq 'NOT_RUN') { continue }
        if ([string]$slot.reference.path -cne $expectedPath -or
            -not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeAdmissionShape -Admission $slot.admission -Authority $Authority -Role ([string]$slot.role) `
                -ParentAdmissionReference $(if($index -eq 0){$null}else{$Record.runtime_admissions[0].reference}) `
                -ParentAdmission $(if($index -eq 0){$null}else{$Record.runtime_admissions[0].admission}) `
                -AuthorityReference $AuthorityReference -OuterPrelaunchReference $Record.outer_prelaunch_reference)) { return $false }
    }
    return $true
    } catch { return $false }
}

function Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultPersistence {
    param([AllowNull()][object]$Record, [AllowNull()][object]$PersistedFact, [AllowNull()][object]$ResultReference,
        [AllowNull()][object]$JournalReference, [Parameter(Mandatory = $true)][byte[]]$JournalBytes,
        [Parameter(Mandatory = $true)][long]$CallerObservedTicks)
    try {
    if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape $Record)) { return $false }
    $projection = ConvertTo-D32BoundedDiagnosticSourceProofNonSourceL1ResultV1Projection -Record $Record
    return (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultPersistenceV1Internal -Record $projection -PersistedFact $PersistedFact `
        -ResultReference $ResultReference -JournalReference $JournalReference -JournalBytes $JournalBytes -CallerObservedTicks $CallerObservedTicks `
        -RuntimeAdmissions @($Record.runtime_admissions))
    } catch { return $false }
}

function Assert-D32BoundedDiagnosticSourceProofDeadline {
    param([Parameter(Mandatory = $true)][Diagnostics.Stopwatch]$ProofTimer,
        [Parameter(Mandatory = $true)][string]$Phase,
        [string]$Progress = 'not_available',
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds,
        [string]$ErrorPrefix = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED',
        [switch]$NoProgress)
    $elapsedMilliseconds = Get-D32BoundedDiagnosticSourceProofCurrentElapsedMilliseconds -ProofTimer $ProofTimer
    if (-not $ProofTimer.IsRunning -or
        -not (Test-D32BoundedDiagnosticSourceProofElapsedWithinDeadline -ElapsedMilliseconds $elapsedMilliseconds -DeadlineMilliseconds $DeadlineMilliseconds)) {
        $phaseValue = [regex]::Replace($Phase, '[^A-Za-z0-9_.#-]', '_')
        $progressValue = [regex]::Replace($Progress, '[^A-Za-z0-9_.#=/-]', '_')
        throw ("{0}: combined source-proof deadline reached; phase={1}; progress={2}; elapsed_ms={3}; work_deadline_ms={4}" -f
            $ErrorPrefix, $phaseValue, $progressValue, $elapsedMilliseconds, $DeadlineMilliseconds)
    }
    if (-not $NoProgress) {
        Set-D32BoundedDiagnosticSourceProofProgress -Phase $Phase -Progress $Progress
        $elapsedMilliseconds = Get-D32BoundedDiagnosticSourceProofCurrentElapsedMilliseconds -ProofTimer $ProofTimer
        if (-not (Test-D32BoundedDiagnosticSourceProofElapsedWithinDeadline -ElapsedMilliseconds $elapsedMilliseconds -DeadlineMilliseconds $DeadlineMilliseconds)) {
            $phaseValue = [regex]::Replace($Phase, '[^A-Za-z0-9_.#-]', '_')
            $progressValue = [regex]::Replace($Progress, '[^A-Za-z0-9_.#=/-]', '_')
            throw ("{0}: shared deadline reached while emitting advisory phase; phase={1}; progress={2}; elapsed_ms={3}; deadline_ms={4}" -f
                $ErrorPrefix, $phaseValue, $progressValue, $elapsedMilliseconds, $DeadlineMilliseconds)
        }
    }
}

function Get-D32BoundedDiagnosticSha256FromBytes {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes,
        [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds,
        [string]$Phase = 'sha256-bytes')
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        for ($offset = 0; $offset -lt $Bytes.Length; $offset += 65536) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase $Phase -Progress ("offset={0}/{1}" -f $offset, $Bytes.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
            $take = [int][Math]::Min(65536, $Bytes.Length - $offset)
            $hash.AppendData($Bytes, $offset, $take)
        }
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase $Phase -Progress ("offset={0}/{1}" -f $Bytes.Length, $Bytes.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
        return [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
    }
    finally { $hash.Dispose() }
}

function Get-D32BoundedDiagnosticSha256FromLines {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines,
        [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds,
        [string]$Phase = 'sha256-lines')
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
    $utf8 = [Text.UTF8Encoding]::new($false)
    try {
        for ($index = 0; $index -lt $Lines.Length; $index++) {
            if ($null -ne $ProofTimer -and (($index -band 255) -eq 0)) {
                Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase $Phase -Progress ("row={0}/{1}" -f $index, $Lines.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
            }
            $rowBytes = $utf8.GetBytes([string]$Lines[$index] + "`n")
            $hash.AppendData($rowBytes)
        }
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase $Phase -Progress ("row={0}/{1}" -f $Lines.Length, $Lines.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
        return [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
    }
    finally { $hash.Dispose() }
}

function Get-D32BoundedDiagnosticGraphTupleKey {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Values)
    $builder = [Text.StringBuilder]::new()
    foreach ($value in $Values) { [void]$builder.Append($value.Length).Append(':').Append($value) }
    return $builder.ToString()
}

function Get-D32BoundedDiagnosticSourceGraphDigest {
    param([Parameter(Mandatory = $true)][string]$LockSha256,
        [Parameter(Mandatory = $true)][string]$LockDependencyEdgesSha256,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$RootIds,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$EdgeRows,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$DecisionRows,
        [Parameter(Mandatory = $true)][string]$ClosedSetSha256,
        [Parameter(Mandatory = $true)][string]$ManifestSetSha256,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds)
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
    $utf8 = [Text.UTF8Encoding]::new($false)
    $newline = [byte[]]@([byte]10)
    try {
        $prefix = [string]$LockSha256 + "`n" + [string]$LockDependencyEdgesSha256 + "`n" + [string]::Join("`n", $RootIds) + "`n"
        $hash.AppendData($utf8.GetBytes($prefix))
        $sections = [System.Collections.Generic.List[string[]]]::new()
        $sections.Add($EdgeRows); $sections.Add($DecisionRows)
        foreach ($rows in $sections) {
            for ($index = 0; $index -lt $rows.Count; $index++) {
                if ($null -ne $ProofTimer -and (($index -band 255) -eq 0)) {
                    Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.digest' -Progress ("section_rows={0}" -f $index) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED'
                }
                if ($index -gt 0) { $hash.AppendData($newline) }
                $hash.AppendData($utf8.GetBytes([string]$rows[$index]))
            }
            $hash.AppendData($newline)
        }
        $hash.AppendData($utf8.GetBytes([string]$ClosedSetSha256 + "`n" + [string]$ManifestSetSha256 + "`n"))
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.digest_complete' -Progress ("edge_rows={0};decision_rows={1}" -f $EdgeRows.Count, $DecisionRows.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
        return [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
    }
    finally { $hash.Dispose() }
}

function Get-D32BoundedDiagnosticEstimatedJsonUpperBound {
    param([Parameter(Mandatory = $true)][object]$Document,
        [Parameter(Mandatory = $true)][Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds,
        [long]$MaximumBytes = $script:D32BoundedDiagnosticSourceProofMaximumOutputBytes)
    $pending = [System.Collections.Generic.Stack[object]]::new()
    $pending.Push($Document)
    $estimate = [Int64]2
    $visited = [Int64]0
    while ($pending.Count -gt 0) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'result.estimate_output' -Progress ("nodes={0};pending={1};estimated_bytes={2}" -f $visited, $pending.Count, $estimate) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $visited++
        $value = $pending.Pop()
        if ($null -eq $value) { $estimate += 4; continue }
        if ($value -is [string]) { $estimate += (6L * [Int64]$value.Length) + 2L; continue }
        if ($value -is [bool] -or $value -is [ValueType]) { $estimate += 32L; continue }
        if ($value -is [System.Collections.IDictionary]) {
            $estimate += 2L + (2L * [Int64]$value.Count)
            $childIndex = 0
            foreach ($key in $value.Keys) {
                if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'result.estimate_dictionary' -Progress ("nodes={0};children={1}/{2};estimated_bytes={3}" -f $visited, $childIndex, $value.Count, $estimate) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
                $estimate += (6L * [Int64]([string]$key).Length) + 3L
                $pending.Push($value[$key])
                $childIndex++
                if ($estimate -gt $MaximumBytes) { throw ('D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: proof result exceeds its fixed {0}-byte serialization ceiling before JSON conversion' -f $MaximumBytes) }
            }
        }
        elseif ($value -is [Array] -or $value -is [System.Collections.IList]) {
            $estimate += 2L + (2L * [Int64]$value.Count)
            $childIndex = 0
            foreach ($item in $value) {
                if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'result.estimate_array' -Progress ("nodes={0};children={1}/{2};estimated_bytes={3}" -f $visited, $childIndex, $value.Count, $estimate) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
                $pending.Push($item)
                $childIndex++
            }
        }
        else {
            $properties = @($value.PSObject.Properties)
            $estimate += 2L + (2L * [Int64]$properties.Count)
            $childIndex = 0
            foreach ($property in $properties) {
                if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'result.estimate_object' -Progress ("nodes={0};children={1}/{2};estimated_bytes={3}" -f $visited, $childIndex, $properties.Count, $estimate) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
                $estimate += (6L * [Int64]$property.Name.Length) + 3L
                $pending.Push($property.Value)
                $childIndex++
                if ($estimate -gt $MaximumBytes) { throw ('D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: proof result exceeds its fixed {0}-byte serialization ceiling before JSON conversion' -f $MaximumBytes) }
            }
        }
        if ($estimate -gt $MaximumBytes) { throw ('D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: proof result exceeds its fixed {0}-byte serialization ceiling before JSON conversion' -f $MaximumBytes) }
    }
    Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'result.estimate_output_complete' -Progress ("nodes={0};estimated_bytes={1}" -f $visited, $estimate) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED'
    return $estimate
}

function Initialize-D32BoundedCompilerDiagnosticGitPackType {
    if ('D32BoundedGitPackReaderV1' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;

public sealed class D32BoundedGitObjectV1
{
    public string Type { get; internal set; }
    public string Oid { get; internal set; }
    public byte[] Data { get; internal set; }
    internal int Reservation { get; set; }
    internal D32BoundedGitPackReaderV1 Owner { get; set; }
}

public sealed class D32BoundedGitTreeEntryV1
{
    public string Name { get; internal set; }
    public string Mode { get; internal set; }
    public string Kind { get; internal set; }
    public string Oid { get; internal set; }
    internal byte[] NameBytes { get; set; }
}

public sealed class D32BoundedGitPackReaderV1
{
    // The preparation census found a largest approved pack just below 256 MiB.
    // Keep the parser below that observed format ceiling so whole-pack hashing
    // remains bounded without buffering the pack in managed memory.
    private const long MaxPackBytes = 256L * 1024L * 1024L;
    private const long MaxObjectBytes = 64L * 1024L * 1024L;
    private const long MaxWorkingBytes = 512L * 1024L * 1024L;
    private const long MaxExpandedBytes = 32L * 1024L * 1024L * 1024L;
    private const long MaxElapsedMilliseconds = 300000L;
    private const int MaxObjectCount = 500000;
    private const int HashBufferSize = 65536;
    private readonly Stream _pack;
    private byte[] _index;
    private byte[] _oids;
    private uint[] _crcs;
    private long[] _offsets;
    private long[] _sortedOffsets;
    private Dictionary<long, int> _indexByOffset;
    private readonly Stopwatch _timer;
    private readonly long _maxElapsedMilliseconds;
    private readonly long _maxWorkingBytes;
    private readonly long _packLength;
    private readonly int _objectCount;
    private readonly long _retainedEstimate;
    private long _workingBytes;
    private long _peakWorkingBytes;
    private long _expandedBytes;
    private int _resolvedCount;
    private bool _disposed;
    private string _packSha256;
    private static readonly uint[] CrcTable = MakeCrcTable();

    public int ObjectCount { get { return _objectCount; } }
    public long PackBytes { get { return _packLength; } }
    public long PeakWorkingBytes { get { return _peakWorkingBytes; } }
    public long ExpandedBytes { get { return _expandedBytes; } }
    public string PackSha256 { get { EnsureLive(); return _packSha256; } }

    public D32BoundedGitPackReaderV1(Stream pack, byte[] indexBytes, string expectedPackId)
        : this(pack, indexBytes, expectedPackId, MaxElapsedMilliseconds, MaxWorkingBytes)
    {
    }

    public D32BoundedGitPackReaderV1(Stream pack, byte[] indexBytes, string expectedPackId, long maximumElapsedMilliseconds)
        : this(pack, indexBytes, expectedPackId, maximumElapsedMilliseconds, MaxWorkingBytes)
    {
    }

    public D32BoundedGitPackReaderV1(Stream pack, byte[] indexBytes, string expectedPackId, long maximumElapsedMilliseconds, long maximumWorkingBytes)
    {
        if (pack == null || indexBytes == null || !pack.CanRead || !pack.CanSeek) throw new InvalidDataException("Git pack/index stream is not readable and seekable");
        if (expectedPackId == null || expectedPackId.Length != 40 || !IsLowerHex(expectedPackId)) throw new InvalidDataException("Git pack filename SHA-1 is malformed");
        if (maximumElapsedMilliseconds <= 0) throw new InvalidDataException("Git source proof has no remaining reserved time");
        if (maximumWorkingBytes <= 0 || maximumWorkingBytes > MaxWorkingBytes) throw new InvalidDataException("Git verifier buffer cap is invalid or exceeds 512 MiB");
        _maxElapsedMilliseconds = Math.Min(MaxElapsedMilliseconds, maximumElapsedMilliseconds);
        _maxWorkingBytes = maximumWorkingBytes;
        _pack = pack;
        _index = indexBytes;
        _packLength = pack.Length;
        _timer = Stopwatch.StartNew();
        if (_packLength < 32 || _packLength > MaxPackBytes || _index.Length < 1072 || _index.Length > 64 * 1024 * 1024) throw new InvalidDataException("Git pack/index exceeds fixed size bounds");
        if (ReadU32(_index, 0) != 0xff744f63U || ReadU32(_index, 4) != 2U) throw new InvalidDataException("Only SHA-1 Git index v2 is supported");
        byte[] indexDigest = HashBytes(_index, 0, _index.Length - 20, HashAlgorithmName.SHA1);
        if (!FixedTimeEqual(indexDigest, Slice(_index, _index.Length - 20, 20))) throw new InvalidDataException("Git index checksum mismatch");
        byte[] indexPackDigest = Slice(_index, _index.Length - 40, 20);
        uint count = ReadU32(_index, 8 + 255 * 4);
        if (count == 0 || count > MaxObjectCount) throw new InvalidDataException("Git pack object count is outside the fixed limit");
        _objectCount = checked((int)count);
        long oidStart = 8L + 256L * 4L;
        long crcStart = oidStart + 20L * count;
        long offsetStart = crcStart + 4L * count;
        long largeStart = offsetStart + 4L * count;
        long minimumLength = largeStart + 40L;
        if (minimumLength > _index.Length || ((_index.Length - minimumLength) % 8L) != 0) throw new InvalidDataException("Git index v2 has an invalid length");
        int largeOffsetCount = checked((int)((_index.Length - minimumLength) / 8L));
        if (largeOffsetCount > _objectCount) throw new InvalidDataException("Git index large-offset table exceeds its object count");
        _oids = new byte[checked((int)(20L * count))];
        _crcs = new uint[checked((int)count)];
        _offsets = new long[checked((int)count)];
        _indexByOffset = new Dictionary<long, int>(checked((int)count));
        _retainedEstimate = checked((long)_index.Length + (long)count * 256L + HashBufferSize);
        if (_retainedEstimate > _maxWorkingBytes) throw new InvalidDataException("Git pack index working set exceeds its fixed verifier buffer cap");
        _workingBytes = _retainedEstimate;
        _peakWorkingBytes = _workingBytes;
        uint priorFanout = 0;
        for (int i = 0; i < 256; i++) {
            if ((i & 63) == 0) CheckDeadline();
            uint current = ReadU32(_index, 8 + i * 4);
            if (current < priorFanout) throw new InvalidDataException("Git index fanout is not monotonic");
            priorFanout = current;
        }
        if (priorFanout != count) throw new InvalidDataException("Git index fanout count differs from object table");
        uint[] firstByteCounts = new uint[256];
        byte[] priorOid = null;
        for (int i = 0; i < _objectCount; i++) {
            if ((i & 1023) == 0) CheckDeadline();
            int dest = i * 20;
            Buffer.BlockCopy(_index, checked((int)(oidStart + (long)i * 20L)), _oids, dest, 20);
            byte[] oid = Slice(_oids, dest, 20);
            if (priorOid != null && CompareBytes(priorOid, oid) >= 0) throw new InvalidDataException("Git index object IDs are not strictly sorted");
            priorOid = oid;
            firstByteCounts[oid[0]]++;
            _crcs[i] = ReadU32(_index, checked((int)(crcStart + (long)i * 4L)));
        }
        uint cumulative = 0;
        for (int i = 0; i < 256; i++) {
            if ((i & 63) == 0) CheckDeadline();
            cumulative += firstByteCounts[i];
            if (ReadU32(_index, 8 + i * 4) != cumulative) throw new InvalidDataException("Git index fanout does not match the object ID table");
        }
        bool[] largeSlots = new bool[largeOffsetCount];
        for (int i = 0; i < _objectCount; i++) {
            if ((i & 1023) == 0) CheckDeadline();
            uint raw = ReadU32(_index, checked((int)(offsetStart + (long)i * 4L)));
            long offset;
            if ((raw & 0x80000000U) != 0) {
                uint slot = raw & 0x7fffffffU;
                if (slot >= largeOffsetCount || largeSlots[slot]) throw new InvalidDataException("Git index large-offset table reference is invalid or duplicated");
                largeSlots[slot] = true;
                ulong large = ReadU64(_index, checked((int)(largeStart + (long)slot * 8L)));
                if (large > Int64.MaxValue) throw new InvalidDataException("Git pack offset exceeds supported range");
                offset = (long)large;
            } else offset = raw;
            if (offset < 12 || offset >= _packLength - 20 || !_indexByOffset.TryAdd(offset, i)) throw new InvalidDataException("Git index contains an invalid or duplicate pack offset");
            _offsets[i] = offset;
        }
        for (int i = 0; i < largeSlots.Length; i++) { if ((i & 1023) == 0) CheckDeadline(); if (!largeSlots[i]) throw new InvalidDataException("Git index has an unreferenced large-offset slot"); }
        _sortedOffsets = (long[])_offsets.Clone();
        CheckDeadline();
        Array.Sort(_sortedOffsets);
        CheckDeadline();
        if (_sortedOffsets.Length == 0 || _sortedOffsets[0] != 12L) throw new InvalidDataException("Git pack does not begin with its first indexed object at byte 12");
        for (int i = 0; i < _sortedOffsets.Length; i++) {
            if ((i & 1023) == 0) CheckDeadline();
            long next = i + 1 < _sortedOffsets.Length ? _sortedOffsets[i + 1] : _packLength - 20L;
            long recordLength = next - _sortedOffsets[i];
            if (recordLength <= 0 || recordLength > MaxObjectBytes) throw new InvalidDataException("Git packed object record boundary exceeds the fixed 64 MiB cap");
        }
        VerifyPack(indexPackDigest, expectedPackId);
    }

    public D32BoundedGitObjectV1 Resolve(string oidHex)
    {
        EnsureLive();
        if (oidHex == null || oidHex.Length != 40 || !IsLowerHex(oidHex)) throw new InvalidDataException("Git object ID is malformed");
        byte[] oid = HexToBytes(oidHex);
        int index = FindOid(oid);
        if (index < 0) throw new InvalidDataException("Locked Git object is absent from the exact pinned pack index");
        return ResolveIndex(index, 0, new HashSet<int>());
    }

    public void Release(D32BoundedGitObjectV1 value)
    {
        if (value == null || value.Owner != this || value.Data == null) throw new InvalidDataException("Git object buffer release is invalid or duplicated");
        ReleaseBytes(value.Reservation);
        value.Data = null;
        value.Owner = null;
    }

    public static string CommitTreeOid(byte[] body)
    {
        return CommitTreeOid(body, MaxElapsedMilliseconds);
    }

    public static string CommitTreeOid(byte[] body, long maximumElapsedMilliseconds)
    {
        if (maximumElapsedMilliseconds <= 0) throw new InvalidDataException("Git commit parse has no remaining source-proof time");
        Stopwatch timer = Stopwatch.StartNew();
        if (body == null || body.Length == 0 || body.Length > 1024 * 1024) throw new InvalidDataException("Git commit body is empty or exceeds 1 MiB");
        int end = Array.IndexOf(body, (byte)10);
        CheckTreeDeadline(timer, maximumElapsedMilliseconds);
        if (end <= 5) throw new InvalidDataException("Git commit has no first tree line");
        string first = Encoding.ASCII.GetString(body, 0, end);
        if (!first.StartsWith("tree ", StringComparison.Ordinal) || first.Length != 45 || !IsLowerHex(first.Substring(5))) throw new InvalidDataException("Git commit first header is not a SHA-1 tree reference");
        int cursor = end + 1;
        bool blank = false;
        while (cursor < body.Length) {
            CheckTreeDeadline(timer, maximumElapsedMilliseconds);
            int lineEnd = Array.IndexOf(body, (byte)10, cursor);
            CheckTreeDeadline(timer, maximumElapsedMilliseconds);
            if (lineEnd < 0) throw new InvalidDataException("Git commit header is not LF-terminated");
            if (lineEnd == cursor) { blank = true; break; }
            string line = Encoding.ASCII.GetString(body, cursor, lineEnd - cursor);
            if (line.StartsWith("tree ", StringComparison.Ordinal)) throw new InvalidDataException("Git commit has a duplicate tree header");
            if (line.StartsWith("parent ", StringComparison.Ordinal) && (line.Length != 47 || !IsLowerHex(line.Substring(7)))) throw new InvalidDataException("Git commit parent header is malformed");
            cursor = lineEnd + 1;
        }
        if (!blank) throw new InvalidDataException("Git commit has no header/body separator");
        CheckTreeDeadline(timer, maximumElapsedMilliseconds);
        return first.Substring(5);
    }

    public static D32BoundedGitTreeEntryV1[] ParseTree(byte[] body)
    {
        return ParseTree(body, MaxElapsedMilliseconds);
    }

    public static D32BoundedGitTreeEntryV1[] ParseTree(byte[] body, long maximumElapsedMilliseconds)
    {
        if (maximumElapsedMilliseconds <= 0) throw new InvalidDataException("Git tree parse has no remaining source-proof time");
        Stopwatch timer = Stopwatch.StartNew();
        if (body == null || body.Length > MaxObjectBytes) throw new InvalidDataException("Git tree body exceeds the fixed object bound");
        List<D32BoundedGitTreeEntryV1> result = new List<D32BoundedGitTreeEntryV1>();
        HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        byte[] previous = null;
        bool previousTree = false;
        int cursor = 0;
        UTF8Encoding strictUtf8 = new UTF8Encoding(false, true);
        while (cursor < body.Length) {
            if ((result.Count & 255) == 0) CheckTreeDeadline(timer, maximumElapsedMilliseconds);
            if (result.Count >= 100000) throw new InvalidDataException("Git tree entry count exceeds the fixed 100000 limit");
            int modeStart = cursor;
            while (cursor < body.Length && body[cursor] != 32) { if ((cursor & 65535) == 0) CheckTreeDeadline(timer, maximumElapsedMilliseconds); cursor++; }
            if (cursor == modeStart || cursor >= body.Length) throw new InvalidDataException("Git tree mode separator is malformed");
            string mode = Encoding.ASCII.GetString(body, modeStart, cursor - modeStart);
            for (int i = 0; i < mode.Length; i++) if (mode[i] < '0' || mode[i] > '7') throw new InvalidDataException("Git tree mode is not octal");
            cursor++;
            int nameStart = cursor;
            while (cursor < body.Length && body[cursor] != 0) { if ((cursor & 65535) == 0) CheckTreeDeadline(timer, maximumElapsedMilliseconds); cursor++; }
            if (cursor == nameStart || cursor >= body.Length) throw new InvalidDataException("Git tree name is empty or unterminated");
            if (cursor - nameStart > 4096) throw new InvalidDataException("Git tree name exceeds the fixed Windows component bound");
            byte[] nameBytes = Slice(body, nameStart, cursor - nameStart);
            string name;
            try { name = strictUtf8.GetString(nameBytes); } catch { throw new InvalidDataException("Git tree name is not strict UTF-8"); }
            if (!IsSafeTreeName(name) || !names.Add(name)) throw new InvalidDataException("Git tree name is unsafe or case-colliding on Windows");
            cursor++;
            if (body.Length - cursor < 20) throw new InvalidDataException("Git tree object ID is truncated");
            string oid = BytesToHex(body, cursor, 20);
            cursor += 20;
            string kind;
            if (mode == "40000") kind = "tree";
            else if (mode == "100644" || mode == "100755") kind = "blob";
            else if (mode == "120000") kind = "symlink";
            else if (mode == "160000") kind = "gitlink";
            else throw new InvalidDataException("Git tree mode is unsupported");
            if (previous != null && CompareTreeNames(previous, previousTree, nameBytes, kind == "tree") >= 0) throw new InvalidDataException("Git tree entries are not in canonical Git order");
            previous = nameBytes;
            previousTree = kind == "tree";
            result.Add(new D32BoundedGitTreeEntryV1 { Name = name, Mode = mode, Kind = kind, Oid = oid, NameBytes = nameBytes });
        }
        return result.ToArray();
    }

    public static uint ComputeCrc32(byte[] bytes, int offset, int count)
    {
        if (bytes == null || offset < 0 || count < 0 || offset > bytes.Length - count) throw new InvalidDataException("CRC input bounds are invalid");
        uint crc = 0xffffffffU;
        for (int i = offset; i < offset + count; i++) crc = CrcTable[(crc ^ bytes[i]) & 0xffU] ^ (crc >> 8);
        return crc ^ 0xffffffffU;
    }

    private D32BoundedGitObjectV1 ResolveIndex(int index, int depth, HashSet<int> active)
    {
        CheckDeadline();
        if (depth > 32 || index < 0 || index >= _objectCount || !active.Add(index)) throw new InvalidDataException("Git delta chain is cyclic or exceeds depth 32");
        if (++_resolvedCount > MaxObjectCount) throw new InvalidDataException("Git object resolution count exceeds 500000");
        D32BoundedGitObjectV1 baseObject = null;
        byte[] entryBytes = null;
        byte[] inflated = null;
        byte[] output = null;
        long entryBudget = 0;
        long inflatedBudget = 0;
        long outputBudget = 0;
        bool outputReturned = false;
        try {
            long start = _offsets[index];
            long next = NextOffset(start);
            int entryLength = checked((int)(next - start));
            if (entryLength <= 0 || entryLength > MaxObjectBytes) throw new InvalidDataException("Git pack entry boundary is invalid or exceeds 64 MiB");
            Reserve(entryLength);
            entryBudget = entryLength;
            entryBytes = new byte[entryLength];
            _pack.Position = start;
            ReadPackExactly(entryBytes, 0, entryLength);
            if (ComputeCrc32Bounded(entryBytes, 0, entryLength) != _crcs[index]) throw new InvalidDataException("Git pack entry CRC differs from its v2 index record");
            int cursor = 0;
            int first = entryBytes[cursor++];
            int type = (first >> 4) & 7;
            long declaredSize = first & 15;
            int shift = 4;
            int current = first;
            int guard = 0;
            while ((current & 128) != 0) {
                if (cursor >= entryBytes.Length || shift >= 63 || ++guard > 9) throw new InvalidDataException("Git pack object header size varint is malformed");
                current = entryBytes[cursor++];
                declaredSize |= ((long)(current & 127)) << shift;
                shift += 7;
            }
            if (declaredSize < 0 || declaredSize > MaxObjectBytes) throw new InvalidDataException("Git pack object declared size exceeds 64 MiB");
            int baseIndex = -1;
            if (type == 6) {
                if (cursor >= entryBytes.Length) throw new InvalidDataException("Git OFS_DELTA base distance is truncated");
                int b = entryBytes[cursor++];
                long distance = b & 127;
                int ofsGuard = 0;
                while ((b & 128) != 0) {
                    if (cursor >= entryBytes.Length || ++ofsGuard > 9) throw new InvalidDataException("Git OFS_DELTA distance is malformed");
                    b = entryBytes[cursor++];
                    if (distance > (Int64.MaxValue >> 7)) throw new InvalidDataException("Git OFS_DELTA distance overflows");
                    distance = ((distance + 1) << 7) | (long)(b & 127);
                }
                long baseOffset = start - distance;
                if (distance <= 0 || baseOffset >= start || !_indexByOffset.TryGetValue(baseOffset, out baseIndex)) throw new InvalidDataException("Git OFS_DELTA base offset is not indexed");
            } else if (type == 7) {
                if (entryBytes.Length - cursor < 20) throw new InvalidDataException("Git REF_DELTA base object ID is truncated");
                byte[] baseOid = Slice(entryBytes, cursor, 20);
                cursor += 20;
                baseIndex = FindOid(baseOid);
                if (baseIndex < 0) throw new InvalidDataException("Git REF_DELTA base is absent from the exact locked repository pack");
            } else if (type < 1 || type > 4) throw new InvalidDataException("Git pack object type is reserved or unsupported");
            int compressedLength = entryBytes.Length - cursor;
            if (compressedLength <= 0 || compressedLength > MaxObjectBytes) throw new InvalidDataException("Git compressed object range is empty or exceeds 64 MiB");
            int declared = checked((int)declaredSize);
            Reserve(declared);
            inflatedBudget = declared;
            inflated = InflateExact(entryBytes, cursor, compressedLength, declared);
            ReleaseBytes(entryLength);
            entryBudget = 0;
            entryBytes = null;
            _expandedBytes = checked(_expandedBytes + declared);
            if (_expandedBytes > MaxExpandedBytes) throw new InvalidDataException("Git object decompression exceeds 32 GiB aggregate");
            if (type == 6 || type == 7) {
                baseObject = ResolveIndex(baseIndex, depth + 1, active);
                long resultLength = DeltaResultLength(inflated, baseObject.Data.Length);
                if (resultLength < 0 || resultLength > MaxObjectBytes) throw new InvalidDataException("Git delta result exceeds 64 MiB");
                Reserve(checked((int)resultLength));
                outputBudget = resultLength;
                output = ApplyDelta(baseObject.Data, inflated, (int)resultLength);
                ReleaseBytes(declared);
                inflatedBudget = 0;
                inflated = null;
                string resolvedType = baseObject.Type;
                Release(baseObject);
                baseObject = null;
                _expandedBytes = checked(_expandedBytes + resultLength);
                if (_expandedBytes > MaxExpandedBytes) throw new InvalidDataException("Git reconstructed object bytes exceed 32 GiB aggregate");
                return CreateVerifiedObject(index, resolvedType, output, ref outputReturned);
            }
            D32BoundedGitObjectV1 verified = CreateVerifiedObject(index, TypeName(type), inflated, ref outputReturned);
            inflatedBudget = 0;
            inflated = null;
            return verified;
        }
        finally {
            if (entryBytes != null) ReleaseBytes(entryBytes.Length); else if (entryBudget > 0) ReleaseBytes(entryBudget);
            if (inflated != null) ReleaseBytes(inflated.Length); else if (inflatedBudget > 0) ReleaseBytes(inflatedBudget);
            if (baseObject != null) Release(baseObject);
            if (output != null && !outputReturned) ReleaseBytes(output.Length); else if (output == null && outputBudget > 0 && !outputReturned) ReleaseBytes(outputBudget);
            active.Remove(index);
        }
    }
    private D32BoundedGitObjectV1 CreateVerifiedObject(int index, string type, byte[] data, ref bool returned)
    {
        byte[] digest = HashGitObject(type, data);
        if (!FixedTimeEqual(digest, Slice(_oids, index * 20, 20))) throw new InvalidDataException("Git object body SHA-1 does not match its indexed object ID");
        string oid = BytesToHex(_oids, index * 20, 20);
        returned = true;
        return new D32BoundedGitObjectV1 { Type = type, Oid = oid, Data = data, Reservation = data.Length, Owner = this };
    }

    private long DeltaResultLength(byte[] delta, int baseLength)
    {
        int cursor = 0;
        long sourceLength = ReadDeltaVarint(delta, ref cursor);
        long resultLength = ReadDeltaVarint(delta, ref cursor);
        if (sourceLength != baseLength || resultLength > MaxObjectBytes) throw new InvalidDataException("Git delta source/result length is invalid");
        return resultLength;
    }

    private byte[] ApplyDelta(byte[] baseData, byte[] delta, int resultLength)
    {
        int cursor = 0;
        long sourceLength = ReadDeltaVarint(delta, ref cursor);
        long encodedResultLength = ReadDeltaVarint(delta, ref cursor);
        if (sourceLength != baseData.Length || encodedResultLength != resultLength) throw new InvalidDataException("Git delta header lengths do not match their base/result buffers");
        byte[] result = new byte[resultLength];
        int written = 0;
        while (cursor < delta.Length) {
            if ((cursor & 4095) == 0) CheckDeadline();
            int instruction = delta[cursor++];
            if ((instruction & 128) != 0) {
                long offset = 0;
                long size = 0;
                int optionalBytes = 0;
                if ((instruction & 1) != 0) optionalBytes++;
                if ((instruction & 2) != 0) optionalBytes++;
                if ((instruction & 4) != 0) optionalBytes++;
                if ((instruction & 8) != 0) optionalBytes++;
                if ((instruction & 16) != 0) optionalBytes++;
                if ((instruction & 32) != 0) optionalBytes++;
                if ((instruction & 64) != 0) optionalBytes++;
                if (cursor > delta.Length - optionalBytes) throw new InvalidDataException("Git delta copy instruction is truncated");
                if ((instruction & 1) != 0) offset |= delta[cursor++];
                if ((instruction & 2) != 0) offset |= (long)delta[cursor++] << 8;
                if ((instruction & 4) != 0) offset |= (long)delta[cursor++] << 16;
                if ((instruction & 8) != 0) offset |= (long)delta[cursor++] << 24;
                if ((instruction & 16) != 0) size |= delta[cursor++];
                if ((instruction & 32) != 0) size |= (long)delta[cursor++] << 8;
                if ((instruction & 64) != 0) size |= (long)delta[cursor++] << 16;
                if (size == 0) size = 65536;
                if (offset < 0 || size < 0 || offset > baseData.Length - size || written > result.Length - size) throw new InvalidDataException("Git delta copy instruction is out of bounds");
                Buffer.BlockCopy(baseData, checked((int)offset), result, written, checked((int)size));
                written += checked((int)size);
            } else {
                int insert = instruction & 127;
                if (insert == 0 || cursor > delta.Length - insert || written > result.Length - insert) throw new InvalidDataException("Git delta insert instruction is empty or out of bounds");
                Buffer.BlockCopy(delta, cursor, result, written, insert);
                cursor += insert;
                written += insert;
            }
        }
        if (written != result.Length) throw new InvalidDataException("Git delta did not produce its declared result length");
        return result;
    }

    private long ReadDeltaVarint(byte[] data, ref int cursor)
    {
        long value = 0;
        int shift = 0;
        int guard = 0;
        int b;
        do {
            if (cursor >= data.Length || shift >= 63 || ++guard > 9) throw new InvalidDataException("Git delta length varint is malformed");
            b = data[cursor++];
            value |= (long)(b & 127) << shift;
            shift += 7;
        } while ((b & 128) != 0);
        return value;
    }

    private byte[] InflateExact(byte[] source, int offset, int length, int expectedSize)
    {
        Reserve(HashBufferSize);
        try {
            byte[] output = new byte[expectedSize];
            using (MemoryStream input = new MemoryStream(source, offset, length, false, true))
            using (ZLibStream inflater = new ZLibStream(input, CompressionMode.Decompress, true)) {
                int cursor = 0;
                byte[] buffer = new byte[HashBufferSize];
                while (cursor < output.Length) {
                    CheckDeadline();
                    int read = inflater.Read(buffer, 0, (int)Math.Min((long)buffer.Length, output.Length - cursor));
                    if (read <= 0) throw new InvalidDataException("Git zlib stream is truncated before its declared object size");
                    Buffer.BlockCopy(buffer, 0, output, cursor, read);
                    cursor += read;
                }
                if (inflater.ReadByte() != -1) throw new InvalidDataException("Git zlib stream exceeds its declared object size");
            }
            return output;
        } catch { throw; }
        finally { ReleaseBytes(HashBufferSize); }
    }

    private long NextOffset(long offset)
    {
        int index = Array.BinarySearch(_sortedOffsets, offset);
        if (index < 0) throw new InvalidDataException("Git indexed object offset is not in its sorted offset table");
        return index + 1 < _sortedOffsets.Length ? _sortedOffsets[index + 1] : _packLength - 20L;
    }

    private int FindOid(byte[] oid)
    {
        int low = 0, high = _objectCount - 1;
        while (low <= high) {
            int mid = low + ((high - low) >> 1);
            int compare = CompareBytes(_oids, mid * 20, oid, 0, 20);
            if (compare == 0) return mid;
            if (compare < 0) low = mid + 1; else high = mid - 1;
        }
        return -1;
    }

    private void VerifyPack(byte[] indexPackDigest, string expectedPackId)
    {
        byte[] header = new byte[12];
        _pack.Position = 0;
        ReadExactly(_pack, header, 0, header.Length);
        if (Encoding.ASCII.GetString(header, 0, 4) != "PACK" || ReadU32(header, 4) != 2U || ReadU32(header, 8) != (uint)_objectCount) throw new InvalidDataException("Git pack header/version/object count differs from its v2 index");
        byte[] trailer = new byte[20];
        _pack.Position = _packLength - 20L;
        ReadExactly(_pack, trailer, 0, 20);
        byte[] digest = HashStreamPrefix(_pack, _packLength - 20L, out _packSha256);
        if (!FixedTimeEqual(digest, trailer) || !FixedTimeEqual(indexPackDigest, trailer) || BytesToHex(trailer, 0, 20) != expectedPackId) throw new InvalidDataException("Git pack trailer, index pack checksum, or filename SHA-1 mismatch");
        _pack.Position = 0;
    }

    private byte[] HashStreamPrefix(Stream stream, long count, out string sha256Hex)
    {
        byte[] buffer = new byte[HashBufferSize];
        long original = stream.Position;
        try {
            stream.Position = 0;
            using (SHA1 sha = SHA1.Create()) {
                using (IncrementalHash sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)) {
                long remaining = count;
                while (remaining > 0) {
                    CheckDeadline();
                    int take = (int)Math.Min((long)buffer.Length, remaining);
                    int read = stream.Read(buffer, 0, take);
                    if (read <= 0) throw new InvalidDataException("Git pack ended during streaming checksum");
                    sha.TransformBlock(buffer, 0, read, buffer, 0);
                    sha256.AppendData(buffer, 0, read);
                    remaining -= read;
                }
                sha.TransformFinalBlock(new byte[0], 0, 0);
                sha256Hex = BytesToHex(sha256.GetHashAndReset(), 0, 32);
                return sha.Hash;
                }
            }
        } finally { stream.Position = original; }
    }

    private byte[] HashGitObject(string type, byte[] body)
    {
        byte[] prefix = Encoding.ASCII.GetBytes(type + " " + body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\0");
        using (SHA1 sha = SHA1.Create()) {
            sha.TransformBlock(prefix, 0, prefix.Length, prefix, 0);
            for (int offset = 0; offset < body.Length; offset += HashBufferSize) {
                CheckDeadline();
                int take = Math.Min(HashBufferSize, body.Length - offset);
                sha.TransformBlock(body, offset, take, body, offset);
            }
            sha.TransformFinalBlock(new byte[0], 0, 0);
            return sha.Hash;
        }
    }

    private void Reserve(long count)
    {
        if (count < 0 || _workingBytes > _maxWorkingBytes - count) throw new InvalidDataException("Git verifier-managed buffers exceed their fixed cap");
        _workingBytes += count;
        if (_workingBytes > _peakWorkingBytes) _peakWorkingBytes = _workingBytes;
    }

    private void ReleaseBytes(long count)
    {
        if (count < 0 || count > _workingBytes - _retainedEstimate) throw new InvalidDataException("Git verifier-managed buffer accounting underflow");
        _workingBytes -= count;
    }

    private void CheckDeadline()
    {
        if (_timer.ElapsedMilliseconds >= _maxElapsedMilliseconds) throw new InvalidDataException("Git source proof exceeded its remaining source-proof deadline");
    }

    private void ReadPackExactly(byte[] buffer, int offset, int count)
    {
        while (count > 0) {
            CheckDeadline();
            int take = Math.Min(HashBufferSize, count);
            int read = _pack.Read(buffer, offset, take);
            if (read <= 0) throw new InvalidDataException("Git pack entry ended during its bounded read");
            offset += read;
            count -= read;
        }
    }

    private uint ComputeCrc32Bounded(byte[] bytes, int offset, int count)
    {
        if (bytes == null || offset < 0 || count < 0 || offset > bytes.Length - count) throw new InvalidDataException("CRC input bounds are invalid");
        uint crc = 0xffffffffU;
        int end = offset + count;
        for (int i = offset; i < end; i++) {
            if (((i - offset) & 65535) == 0) CheckDeadline();
            crc = CrcTable[(crc ^ bytes[i]) & 0xffU] ^ (crc >> 8);
        }
        return crc ^ 0xffffffffU;
    }

    private void EnsureLive() { if (_disposed) throw new ObjectDisposedException("D32BoundedGitPackReaderV1"); CheckDeadline(); }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_indexByOffset != null) _indexByOffset.Clear();
        _index = null;
        _oids = null;
        _crcs = null;
        _offsets = null;
        _sortedOffsets = null;
    }

    private static uint[] MakeCrcTable()
    {
        uint[] table = new uint[256];
        for (uint n = 0; n < 256; n++) {
            uint c = n;
            for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xedb88320U ^ (c >> 1) : c >> 1;
            table[n] = c;
        }
        return table;
    }

    private byte[] HashBytes(byte[] bytes, int offset, int count, HashAlgorithmName algorithm)
    {
        if (bytes == null || offset < 0 || count < 0 || offset > bytes.Length - count) throw new InvalidDataException("Hash input bounds are invalid");
        using (IncrementalHash hash = IncrementalHash.CreateHash(algorithm)) {
            int end = offset + count;
            for (int cursor = offset; cursor < end; cursor += HashBufferSize) {
                CheckDeadline();
                int take = Math.Min(HashBufferSize, end - cursor);
                hash.AppendData(bytes, cursor, take);
            }
            return hash.GetHashAndReset();
        }
    }

    private static void CheckTreeDeadline(Stopwatch timer, long maximumElapsedMilliseconds)
    {
        if (timer.ElapsedMilliseconds >= maximumElapsedMilliseconds) throw new InvalidDataException("Git tree parse exceeded the remaining source-proof deadline");
    }

    private static uint ReadU32(byte[] bytes, int offset)
    {
        if (offset < 0 || offset > bytes.Length - 4) throw new InvalidDataException("Git binary field is truncated");
        return ((uint)bytes[offset] << 24) | ((uint)bytes[offset + 1] << 16) | ((uint)bytes[offset + 2] << 8) | bytes[offset + 3];
    }

    private static ulong ReadU64(byte[] bytes, int offset)
    {
        if (offset < 0 || offset > bytes.Length - 8) throw new InvalidDataException("Git binary field is truncated");
        ulong result = 0;
        for (int i = 0; i < 8; i++) result = (result << 8) | bytes[offset + i];
        return result;
    }

    private static byte[] Slice(byte[] bytes, int offset, int count)
    {
        if (offset < 0 || count < 0 || offset > bytes.Length - count) throw new InvalidDataException("Git binary slice exceeds its buffer");
        byte[] result = new byte[count];
        Buffer.BlockCopy(bytes, offset, result, 0, count);
        return result;
    }

    private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count)
    {
        while (count > 0) {
            int read = stream.Read(buffer, offset, count);
            if (read <= 0) throw new InvalidDataException("Git pack/index input is truncated");
            offset += read;
            count -= read;
        }
    }

    private static int CompareBytes(byte[] left, byte[] right) { return CompareBytes(left, 0, right, 0, Math.Min(left.Length, right.Length)); }

    private static int CompareBytes(byte[] left, int lo, byte[] right, int ro, int count)
    {
        for (int i = 0; i < count; i++) if (left[lo + i] != right[ro + i]) return left[lo + i] < right[ro + i] ? -1 : 1;
        return 0;
    }

    private static string TypeName(int type)
    {
        switch (type) { case 1: return "commit"; case 2: return "tree"; case 3: return "blob"; case 4: return "tag"; default: throw new InvalidDataException("Git object type is unsupported"); }
    }

    private static bool FixedTimeEqual(byte[] left, byte[] right)
    {
        if (left == null || right == null || left.Length != right.Length) return false;
        int diff = 0;
        for (int i = 0; i < left.Length; i++) diff |= left[i] ^ right[i];
        return diff == 0;
    }

    private static bool IsLowerHex(string value)
    {
        if (value == null) return false;
        for (int i = 0; i < value.Length; i++) if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return false;
        return true;
    }

    private static byte[] HexToBytes(string hex)
    {
        byte[] result = new byte[hex.Length / 2];
        for (int i = 0; i < result.Length; i++) result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return result;
    }

    private static string BytesToHex(byte[] bytes, int offset, int count)
    {
        StringBuilder result = new StringBuilder(count * 2);
        for (int i = 0; i < count; i++) result.Append(bytes[offset + i].ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
        return result.ToString();
    }

    private static bool IsSafeTreeName(string name)
    {
        if (String.IsNullOrEmpty(name) || name == "." || name == ".." || name.EndsWith(".", StringComparison.Ordinal) || name.EndsWith(" ", StringComparison.Ordinal) ||
            !String.Equals(name, name.Normalize(NormalizationForm.FormC), StringComparison.Ordinal)) return false;
        for (int i = 0; i < name.Length; i++) if (name[i] < 32 || name[i] == 127 || "\\/:*?\"<>|".IndexOf(name[i]) >= 0) return false;
        string stem = name.Split('.')[0];
        if (stem.Equals("CON", StringComparison.OrdinalIgnoreCase) || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase) || stem.Equals("AUX", StringComparison.OrdinalIgnoreCase) || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase)) return false;
        for (int i = 1; i <= 9; i++) if (stem.Equals("COM" + i, StringComparison.OrdinalIgnoreCase) || stem.Equals("LPT" + i, StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private static int CompareTreeNames(byte[] left, bool leftTree, byte[] right, bool rightTree)
    {
        int limit = Math.Max(left.Length, right.Length);
        for (int i = 0; i <= limit; i++) {
            int a = i < left.Length ? left[i] : (leftTree ? 47 : 0);
            int b = i < right.Length ? right[i] : (rightTree ? 47 : 0);
            if (a != b) return a < b ? -1 : 1;
        }
        return 0;
    }
}
'@
}

function Get-D32BoundedCompilerDiagnosticFixedArgv {
    return @('test', '--manifest-path', 'vita-agent/Cargo.toml', '--all-targets', '--locked', '--offline',
        '--features', 'd32-a-test-helper', '--jobs', '4', '--no-run', '--message-format=json', '-vv')
}

function Test-D32BoundedCompilerDiagnosticExactProperties {
    param([AllowNull()][object]$Object, [Parameter(Mandatory = $true)][string[]]$Expected)
    if ($null -eq $Object -or $Object -is [string] -or $Object -is [Array] -or $Object -is [ValueType]) { return $false }
    $actual = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($property in $Object.PSObject.Properties) { [void]$actual.Add([string]$property.Name) }
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) { if (-not $actual.Contains($name)) { return $false } }
    return $true
}

function Test-D32BoundedCompilerDiagnosticInteger {
    param([AllowNull()][object]$Value, [switch]$Positive)
    $isInteger = $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64]
    if (-not $isInteger) { return $false }
    if ($Positive) { return ([Int64]$Value -gt 0) }
    return ([Int64]$Value -ge 0)
}

function Test-D32BoundedDiagnosticGeneratedRegistryAuxiliaryFile {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][bool]$AtRoot,
        [Parameter(Mandatory = $true)][bool]$ArchiveMember
    )
    return $AtRoot -and -not $ArchiveMember -and
        ($RelativePath -ceq '.cargo-ok' -or $RelativePath -ceq '.cargo-checksum.json')
}

function Test-D32BoundedDiagnosticRegistryCargoOkMarkerBytes {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    $canonical = [Text.Encoding]::UTF8.GetBytes('{"v":1}')
    if ($Bytes.Length -ne $canonical.Length) { return $false }
    for ($index = 0; $index -lt $canonical.Length; $index++) {
        if ($Bytes[$index] -ne $canonical[$index]) { return $false }
    }
    return $true
}

function Test-D32BoundedDiagnosticRegistryCargoOkMarkerSnapshot {
    param(
        [Parameter(Mandatory = $true)][long]$Bytes,
        [Parameter(Mandatory = $true)][string]$Sha256
    )
    $canonical = [Text.Encoding]::UTF8.GetBytes('{"v":1}')
    $canonicalSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($canonical)).ToLowerInvariant()
    return $Bytes -eq $canonical.Length -and $Sha256 -ceq $canonicalSha256
}

function Assert-D32BoundedDiagnosticGitCargoOkMarkerEmpty {
    param([Parameter(Mandatory = $true)][long]$Bytes)
    if ($Bytes -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: generated .cargo-ok marker is not empty' }
}

function Get-D32BoundedDiagnosticGitPointerTarget {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$PointerBytes,
        [Parameter(Mandatory = $true)][string]$CheckoutPath
    )
    if ($PointerBytes.Length -le 0 -or $PointerBytes.Length -gt 4096) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout .git pointer is empty or exceeds 4096 bytes'
    }
    $pointerText = [Text.Encoding]::ASCII.GetString($PointerBytes)
    if ($pointerText -cnotmatch '^gitdir: ([^\r\n]+)\r?\n?$') {
        throw 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: checkout .git pointer format is unsupported'
    }
    $pointerValue = [string]$Matches[1]
    if ([IO.Path]::IsPathRooted($pointerValue)) { return [IO.Path]::GetFullPath($pointerValue) }
    return [IO.Path]::GetFullPath((Join-Path $CheckoutPath $pointerValue))
}

function Test-D32BoundedDiagnosticExactGitPointerTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$ExpectedTarget
    )
    return [StringComparer]::OrdinalIgnoreCase.Equals($Target, $ExpectedTarget)
}

function Get-D32BoundedCompilerDiagnosticGlobalWriterCensus {
    param([Parameter(Mandatory = $true)][scriptblock]$ProcessProbe)
    try { $probeResult = & $ProcessProbe }
    catch { throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: Win32_Process target-writer census failed' }
    if ($null -eq $probeResult) { throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: target-writer census returned no verifiable result' }
    $processes = @($probeResult)
    if ($processes.Count -eq 0) { throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: target-writer census returned an empty, unverifiable result' }

    $writerNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @('cargo.exe', 'rustc.exe', 'cl.exe', 'link.exe', 'build-script-build.exe')) { [void]$writerNames.Add($name) }
    $targetWriters = [System.Collections.Generic.List[string]]::new()
    foreach ($process in $processes) {
        $nameProperty = if ($null -eq $process) { $null } else { $process.PSObject.Properties['Name'] }
        $processIdProperty = if ($null -eq $process) { $null } else { $process.PSObject.Properties['ProcessId'] }
        if ($null -eq $nameProperty -or $null -eq $processIdProperty -or $nameProperty.Value -isnot [string] -or
            [String]::IsNullOrWhiteSpace([string]$nameProperty.Value) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger -Value $processIdProperty.Value)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: target-writer census contains an incomplete process identity'
        }
        $processName = [string]$nameProperty.Value
        $processId = [Int64]$processIdProperty.Value

        # Match the frozen Phase 0 census exceptions exactly; all other malformed
        # reserved identities fail closed instead of being treated as ordinary rows.
        if ($processId -eq 0 -or $processName -ceq 'System Idle Process') {
            $parentProperty = $process.PSObject.Properties['ParentProcessId']
            if ($processId -ne 0 -or $processName -cne 'System Idle Process' -or $null -eq $parentProperty -or
                -not (Test-D32BoundedCompilerDiagnosticInteger -Value $parentProperty.Value) -or [Int64]$parentProperty.Value -ne 0) {
                throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: PID-zero row is not the exact Windows System Idle Process identity'
            }
            continue
        }
        if ($processId -eq 4 -or $processName -ceq 'System') {
            $parentProperty = $process.PSObject.Properties['ParentProcessId']
            if ($processId -ne 4 -or $processName -cne 'System' -or $null -eq $parentProperty -or
                -not (Test-D32BoundedCompilerDiagnosticInteger -Value $parentProperty.Value) -or [Int64]$parentProperty.Value -ne 0) {
                throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: PID-four row is not the exact Windows System process identity'
            }
            continue
        }
        if ($processId -le 0) { throw 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: target-writer census contains an incomplete process identity' }
        if ($writerNames.Contains($processName)) {
            $targetWriters.Add("${processName} PID=${processId}: active build-class process cannot be excluded from candidate target trees")
        }
    }
    return [PSCustomObject]@{
        process_count = [Int64]$processes.Count
        competing_target_writer_count = [Int64]$targetWriters.Count
        target_writer_check = 'Win32-CIM-active-build-process-census'
        competing_target_writers = @($targetWriters.ToArray())
    }
}

function Assert-D32BoundedCompilerDiagnosticNoGlobalWriter {
    param([Parameter(Mandatory = $true)][scriptblock]$ProcessProbe)
    $census = Get-D32BoundedCompilerDiagnosticGlobalWriterCensus -ProcessProbe $ProcessProbe
    if ([Int64]$census.competing_target_writer_count -gt 0) {
        throw ('D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: competing target writer exists: ' + (@($census.competing_target_writers) -join '; '))
    }
    return $census
}

function Test-D32BoundedCompilerDiagnosticFixedArgv {
    param([AllowNull()][object]$Arguments)
    if ($Arguments -isnot [Array] -or $Arguments.Count -ne (Get-D32BoundedCompilerDiagnosticFixedArgv).Count) { return $false }
    $expected = @(Get-D32BoundedCompilerDiagnosticFixedArgv)
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if ($Arguments[$index] -isnot [string] -or [string]$Arguments[$index] -cne $expected[$index]) { return $false }
    }
    return $true
}

function Assert-D32BoundedCompilerDiagnosticBudget {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Budget)
    $fields = @('cargo_timeout_ms', 'owned_launch_timeout_ms', 'cleanup_reserve_ms', 'persist_reserve_ms', 'sample_period_ms', 'raw_capture_limit_bytes', 'cargo_jobs')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $Budget -Expected $fields) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.cargo_timeout_ms -Positive) -or [Int64]$Budget.cargo_timeout_ms -ne $script:D32BoundedCompilerDiagnosticMaxCargoMilliseconds -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.owned_launch_timeout_ms -Positive) -or [Int64]$Budget.owned_launch_timeout_ms -ne $script:D32BoundedCompilerDiagnosticMaxLaunchMilliseconds -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.cleanup_reserve_ms -Positive) -or [Int64]$Budget.cleanup_reserve_ms -lt $script:D32BoundedCompilerDiagnosticCleanupReserveMilliseconds -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.persist_reserve_ms -Positive) -or [Int64]$Budget.persist_reserve_ms -lt $script:D32BoundedCompilerDiagnosticPersistReserveMilliseconds -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.sample_period_ms -Positive) -or [Int64]$Budget.sample_period_ms -ne 10000 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.raw_capture_limit_bytes -Positive) -or [Int64]$Budget.raw_capture_limit_bytes -ne $script:D32BoundedCompilerDiagnosticCaptureLimitBytes -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Budget.cargo_jobs -Positive) -or [Int64]$Budget.cargo_jobs -ne 4 -or
        ([Int64]$Budget.cargo_timeout_ms + [Int64]$Budget.cleanup_reserve_ms + [Int64]$Budget.persist_reserve_ms) -gt [Int64]$Budget.owned_launch_timeout_ms) {
        throw 'D32_BOUNDED_DIAGNOSTIC_BUDGET_BLOCKED: exact Cargo/launch ceilings, reserved cleanup/persist time, sample cadence, capture cap, and jobs are mandatory'
    }
    return $true
}

function Assert-D32BoundedCompilerDiagnosticStatus {
    param([Parameter(Mandatory = $true)][string]$Status)
    if ($script:D32BoundedCompilerDiagnosticStatuses -cnotcontains $Status) {
        throw 'D32_BOUNDED_DIAGNOSTIC_STATUS_BLOCKED: diagnostic status is outside the four non-PASS outcomes'
    }
    return $Status
}

function Test-D32BoundedCompilerDiagnosticFormalReject {
    param([AllowNull()][object]$Record)
    if ($null -eq $Record) { return $true }
    return ($Record.record_type -isnot [string] -or [string]$Record.record_type -cne 'D32_PHASE0_MATRIX_RECORD_V8' -or
        $Record.gate_authority -isnot [string] -or [string]$Record.gate_authority -cne 'PHASE0' -or
        $Record.status -isnot [string] -or [string]$Record.status -cne 'PASS')
}

function Test-D32BoundedDiagnosticSourceGraphProof {
    param([AllowNull()][object]$Graph, [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds)
    $fields = @('schema_version', 'record_type', 'gate_authority', 'formal_gate_usable', 'status', 'semantic_scope', 'lock_sha256',
        'lock_dependency_edges_sha256', 'graph_sha256', 'root_manifest_path', 'selected_root_ids', 'root_selection_rule', 'host_triple',
        'target_triple', 'target_resolution_scope', 'locked_package_count', 'included_package_ids', 'included_package_count',
        'excluded_package_count', 'classification_count', 'classifications', 'included_edges', 'dependency_decisions',
        'inactive_target_edge_count', 'unknown_cfg_conservative_include_count', 'included_manifest_set_sha256', 'feature_rule',
        'root_dev_dependency_rule', 'nonroot_dev_dependency_rule', 'build_proc_macro_rule', 'closed_reachability_set_sha256',
        'source_plan_version', 'selected_target_mode', 'selected_crate_kinds')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Graph $fields) -or
        [int64]$Graph.schema_version -ne 2 -or [string]$Graph.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_SOURCE_GRAPH_PROOF_V2' -or
        [string]$Graph.gate_authority -cne 'NONE' -or $Graph.formal_gate_usable -isnot [bool] -or [bool]$Graph.formal_gate_usable -or
        [string]$Graph.status -cne 'CURRENT_LOCKED_SOURCE_GRAPH_VERIFIED_FOR_DIAGNOSTIC_ONLY' -or
        [string]$Graph.semantic_scope -cne 'FULL_LOCK_AUDIT_CATALOG_PLUS_SELECTED_REACHABLE_CONSERVATIVE_SUPERSET' -or
        [string]$Graph.lock_sha256 -cnotmatch '^[0-9a-f]{64}$' -or [string]$Graph.lock_dependency_edges_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Graph.graph_sha256 -cnotmatch '^[0-9a-f]{64}$' -or [string]$Graph.included_manifest_set_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Graph.closed_reachability_set_sha256 -cnotmatch '^[0-9a-f]{64}$' -or [string]$Graph.root_manifest_path -cne 'vita-agent/Cargo.toml' -or
        [string]$Graph.root_selection_rule -cne 'EXACT_PACKAGE_NAMED_BY_MANIFEST_PATH_DEFAULT_FEATURES_PLUS_D32_A_TEST_HELPER_NO_WORKSPACE_EXPANSION' -or
        [string]$Graph.host_triple -cne 'x86_64-pc-windows-msvc' -or [string]$Graph.target_triple -cne 'x86_64-pc-windows-msvc' -or
        [string]$Graph.target_resolution_scope -cne 'ONE_FIXED_X86_64_PC_WINDOWS_MSVC_HOST_AND_TARGET' -or [int]$Graph.source_plan_version -ne 2 -or
        [string]$Graph.selected_target_mode -cne 'ALL_TARGETS_FOR_SELECTED_PACKAGE_ONLY' -or
        $Graph.selected_crate_kinds -isnot [Array] -or
        [string]::Join(',', [string[]]$Graph.selected_crate_kinds) -cne 'lib,bin,example,test,bench,custom-build,proc-macro' -or
        [string]$Graph.feature_rule -cne 'ALL_OPTIONAL_AND_FEATURE_ACTIVATION_EDGES_INCLUDED_UNLESS_TARGET_PREDICATE_PROVEN_FALSE' -or
        [string]$Graph.root_dev_dependency_rule -cne 'INCLUDED_FOR_SELECTED_PACKAGE_ALL_TARGETS' -or
        [string]$Graph.nonroot_dev_dependency_rule -cne 'EXCLUDED_NOT_BUILT_FOR_DEPENDENCY_PACKAGE' -or
        [string]$Graph.build_proc_macro_rule -cne 'INCLUDED_HOST_EQUALS_TARGET' -or
        $Graph.selected_root_ids -isnot [Array] -or $Graph.selected_root_ids.Count -ne 1 -or
        $Graph.included_package_ids -isnot [Array] -or $Graph.classifications -isnot [Array] -or
        $Graph.included_edges -isnot [Array] -or $Graph.dependency_decisions -isnot [Array] -or
        [Int64]$Graph.locked_package_count -le 0 -or [Int64]$Graph.locked_package_count -gt 2048 -or
        [Int64]$Graph.included_package_count -lt 1 -or [Int64]$Graph.excluded_package_count -lt 0 -or
        [Int64]$Graph.classification_count -ne [Int64]$Graph.locked_package_count -or
        [Int64]$Graph.included_package_count + [Int64]$Graph.excluded_package_count -ne [Int64]$Graph.locked_package_count -or
        $Graph.classifications.Count -ne [Int64]$Graph.locked_package_count -or
        $Graph.included_package_ids.Count -ne [Int64]$Graph.included_package_count -or
        $Graph.dependency_decisions.Count -gt 65536 -or $Graph.included_edges.Count -gt 65536) { return $false }
    $rootId = [string]$Graph.selected_root_ids[0]
    if ($rootId -notmatch '^digital-life-vita-agent@[^|]+\|workspace\|workspace$') { return $false }
    $included = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $validationIndex = 0
    foreach ($id in $Graph.included_package_ids) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.included_ids' -Progress ("packages={0}/{1}" -f $validationIndex, $Graph.included_package_ids.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        if ($id -isnot [string] -or -not $included.Add([string]$id)) { return $false }
        $validationIndex++
    }
    if (-not $included.Contains($rootId)) { return $false }
    $classified = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $includedClassifications = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $excludedClassifications = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $validationIndex = 0
    foreach ($class in $Graph.classifications) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.classifications' -Progress ("rows={0}/{1}" -f $validationIndex, $Graph.classifications.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $validationIndex++
        if ([string]$class.classification -ceq 'INCLUDED') {
            $classFields = @('package_id', 'classification', 'source_kind', 'source_identity', 'manifest_path', 'manifest_sha256', 'witness_kind', 'witness_root_path', 'closed_reachability_sha256')
            if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $class $classFields) -or
                [string]$class.source_kind -cnotin @('workspace', 'registry', 'git') -or
                [string]$class.manifest_path -notmatch '^[A-Za-z0-9_./-]+/Cargo\.toml$|^Cargo\.toml$' -or
                [string]$class.manifest_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                [string]$class.closed_reachability_sha256 -cne [string]$Graph.closed_reachability_set_sha256 -or
                [string]$class.witness_kind -cne 'ROOT_PATH_IN_VERIFIED_DECLARATION_GRAPH' -or
                $class.witness_root_path -isnot [Array] -or $class.witness_root_path.Count -lt 1 -or
                [string]$class.witness_root_path[0] -cne $rootId -or
                [string]$class.witness_root_path[$class.witness_root_path.Count - 1] -cne [string]$class.package_id -or
                -not $classified.Add([string]$class.package_id) -or -not $included.Contains([string]$class.package_id)) { return $false }
            $identityMatch = [regex]::Match([string]$class.package_id, '^(?<name>[A-Za-z0-9_-]+)@(?<version>[0-9A-Za-z.+_-]+)\|(?<kind>workspace|registry|git)\|(?<source>.*)$')
            if (-not $identityMatch.Success -or [string]$identityMatch.Groups['kind'].Value -cne [string]$class.source_kind -or
                [string]$identityMatch.Groups['source'].Value -cne [string]$class.source_identity) { return $false }
            $includedClassifications.Add([string]$class.package_id, $class)
        }
        elseif ([string]$class.classification -ceq 'EXCLUDED_WITH_WITNESS') {
            $classFields = @('package_id', 'classification', 'source_kind', 'source_identity', 'witness_kind', 'unreachable_from_roots', 'complete_reachable_parent_count',
                'complete_reachable_dependency_decision_count', 'no_active_incoming_edge_from_included', 'closed_reachability_sha256')
            if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $class $classFields) -or
                [string]$class.source_kind -cnotin @('workspace', 'registry', 'git') -or
                [string]$class.witness_kind -cne 'CLOSED_REACHABILITY_CUT' -or $class.unreachable_from_roots -isnot [Array] -or
                $class.unreachable_from_roots.Count -ne 1 -or [string]$class.unreachable_from_roots[0] -cne $rootId -or
                $class.no_active_incoming_edge_from_included -isnot [bool] -or -not [bool]$class.no_active_incoming_edge_from_included -or
                [Int64]$class.complete_reachable_parent_count -ne [Int64]$Graph.included_package_count -or
                [Int64]$class.complete_reachable_dependency_decision_count -ne [Int64]$Graph.dependency_decisions.Count -or
                [string]$class.closed_reachability_sha256 -cne [string]$Graph.closed_reachability_set_sha256 -or
                -not $classified.Add([string]$class.package_id) -or $included.Contains([string]$class.package_id)) { return $false }
            $identityMatch = [regex]::Match([string]$class.package_id, '^(?<name>[A-Za-z0-9_-]+)@(?<version>[0-9A-Za-z.+_-]+)\|(?<kind>workspace|registry|git)\|(?<source>.*)$')
            if (-not $identityMatch.Success -or [string]$identityMatch.Groups['kind'].Value -cne [string]$class.source_kind -or
                [string]$identityMatch.Groups['source'].Value -cne [string]$class.source_identity) { return $false }
            $excludedClassifications.Add([string]$class.package_id, $class)
        }
        else { return $false }
    }
    if ($classified.Count -ne [Int64]$Graph.locked_package_count -or $includedClassifications.Count -ne [Int64]$Graph.included_package_count -or
        $excludedClassifications.Count -ne [Int64]$Graph.excluded_package_count) { return $false }
    $edgeKeyCounts = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
    $edgePairs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $includedEdgeTargets = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $validationIndex = 0
    foreach ($edge in $Graph.included_edges) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.edges' -Progress ("rows={0}/{1}" -f $validationIndex, $Graph.included_edges.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $validationIndex++
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $edge @('parent_package_id', 'target_package_id', 'lock_spec', 'dependency_alias', 'kind', 'target_predicate', 'predicate_proven', 'predicate_witness', 'optional_included')) -or
            -not $included.Contains([string]$edge.parent_package_id) -or -not $included.Contains([string]$edge.target_package_id) -or
            $edge.predicate_proven -isnot [bool] -or $edge.optional_included -isnot [bool]) { return $false }
        $edgeKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@(
            [string]$edge.parent_package_id, [string]$edge.target_package_id, [string]$edge.lock_spec, [string]$edge.dependency_alias,
            [string]$edge.kind, [string]$edge.target_predicate, [string]$edge.predicate_proven, [string]$edge.predicate_witness,
            [string]$edge.optional_included))
        if ($edgeKeyCounts.ContainsKey($edgeKey)) { $edgeKeyCounts[$edgeKey] = [int]$edgeKeyCounts[$edgeKey] + 1 }
        else { $edgeKeyCounts.Add($edgeKey, 1) }
        $pairKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@([string]$edge.parent_package_id, [string]$edge.target_package_id))
        [void]$edgePairs.Add($pairKey)
        [void]$includedEdgeTargets.Add([string]$edge.target_package_id)
    }
    $includedDecisionKeyCounts = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
    $includedDecisionTargets = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $validationIndex = 0
    foreach ($decision in $Graph.dependency_decisions) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.decisions' -Progress ("rows={0}/{1}" -f $validationIndex, $Graph.dependency_decisions.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $validationIndex++
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $decision @('parent_package_id', 'alias', 'kind', 'target', 'disposition', 'predicate_proven', 'predicate_witness', 'target_package_id', 'lock_specs', 'optional_included')) -or
            -not $included.Contains([string]$decision.parent_package_id) -or $decision.lock_specs -isnot [Array] -or
            $decision.predicate_proven -isnot [bool] -or $decision.optional_included -isnot [bool]) { return $false }
        if ([string]$decision.disposition -cin @('INCLUDED', 'INCLUDED_UNKNOWN_CFG')) {
            if (-not $included.Contains([string]$decision.target_package_id) -or $decision.lock_specs.Count -ne 1 -or
                $decision.lock_specs[0] -isnot [string]) { return $false }
            $decisionKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@(
                [string]$decision.parent_package_id, [string]$decision.target_package_id, [string]$decision.lock_specs[0], [string]$decision.alias,
                [string]$decision.kind, [string]$decision.target, [string]$decision.predicate_proven, [string]$decision.predicate_witness,
                [string]$decision.optional_included))
            if (-not $edgeKeyCounts.ContainsKey($decisionKey)) { return $false }
            if ($includedDecisionKeyCounts.ContainsKey($decisionKey)) { $includedDecisionKeyCounts[$decisionKey] = [int]$includedDecisionKeyCounts[$decisionKey] + 1 }
            else { $includedDecisionKeyCounts.Add($decisionKey, 1) }
            [void]$includedDecisionTargets.Add([string]$decision.target_package_id)
        }
    }
    if ($includedDecisionKeyCounts.Count -ne $edgeKeyCounts.Count) { return $false }
    $validationIndex = 0
    foreach ($edgeKey in $edgeKeyCounts.Keys) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.edge_keys' -Progress ("keys={0}/{1}" -f $validationIndex, $edgeKeyCounts.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        if ($edgeKeyCounts[$edgeKey] -ne 1 -or -not $includedDecisionKeyCounts.ContainsKey($edgeKey) -or $includedDecisionKeyCounts[$edgeKey] -ne 1) { return $false }
        $validationIndex++
    }
    $validationIndex = 0
    foreach ($id in $Graph.included_package_ids) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.witnesses' -Progress ("packages={0}/{1}" -f $validationIndex, $Graph.included_package_ids.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $validationIndex++
        $class = $includedClassifications[[string]$id]
        $path = [string[]]$class.witness_root_path
        for ($i = 1; $i -lt $path.Length; $i++) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.witness_edges' -Progress ("package={0};edges={1}/{2}" -f $id, $i, $path.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
            $pairKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@($path[$i - 1], $path[$i]))
            if (-not $edgePairs.Contains($pairKey)) { return $false }
        }
    }
    $validationIndex = 0
    foreach ($id in $excludedClassifications.Keys) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.exclusions' -Progress ("packages={0}/{1}" -f $validationIndex, $excludedClassifications.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $validationIndex++
        if ($includedEdgeTargets.Contains([string]$id) -or $includedDecisionTargets.Contains([string]$id)) { return $false }
    }
    $includedIds = [string[]]@($Graph.included_package_ids)
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.sort_closed_set' -Progress ("packages={0}" -f $includedIds.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    [Array]::Sort($includedIds, [StringComparer]::Ordinal)
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.sort_closed_set_complete' -Progress ("packages={0}" -f $includedIds.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $expectedClosedSha = Get-D32BoundedDiagnosticSha256FromLines -Lines $includedIds -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'source_graph.validate_closed_digest'
    if ($expectedClosedSha -cne [string]$Graph.closed_reachability_set_sha256) { return $false }
    $manifestCanon = [System.Collections.Generic.List[string]]::new()
    $validationIndex = 0
    foreach ($id in $includedIds) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.manifest_rows' -Progress ("rows={0}/{1}" -f $validationIndex, $includedIds.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $class = $includedClassifications[$id]
        $manifestCanon.Add($id + "`t" + [string]$class.source_kind + "`t" + [string]$class.source_identity + "`t" + [string]$class.manifest_path + "`t" + [string]$class.manifest_sha256)
        $validationIndex++
    }
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.sort_manifests' -Progress ("rows={0}" -f $manifestCanon.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $manifestCanon.Sort([StringComparer]::Ordinal)
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.sort_manifests_complete' -Progress ("rows={0}" -f $manifestCanon.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $expectedManifestSha = Get-D32BoundedDiagnosticSha256FromLines -Lines ([string[]]$manifestCanon.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'source_graph.validate_manifest_digest'
    if ($expectedManifestSha -cne [string]$Graph.included_manifest_set_sha256) { return $false }
    $edgeCanon = [System.Collections.Generic.List[string]]::new()
    $validationIndex = 0
    foreach ($edge in $Graph.included_edges) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.edge_rows' -Progress ("rows={0}/{1}" -f $validationIndex, $Graph.included_edges.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $edgeCanon.Add(([string]$edge.parent_package_id + "`t" + [string]$edge.target_package_id + "`t" + [string]$edge.dependency_alias + "`t" + [string]$edge.kind + "`t" + [string]$edge.target_predicate + "`t" + [string]$edge.predicate_witness + "`t" + [string]$edge.lock_spec)); $validationIndex++
    }
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.sort_edges' -Progress ("rows={0}" -f $edgeCanon.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $edgeCanon.Sort([StringComparer]::Ordinal)
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.sort_edges_complete' -Progress ("rows={0}" -f $edgeCanon.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $decisionCanon = [System.Collections.Generic.List[string]]::new()
    $validationIndex = 0
    foreach ($decision in $Graph.dependency_decisions) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.decision_rows' -Progress ("rows={0}/{1}" -f $validationIndex, $Graph.dependency_decisions.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $decisionCanon.Add(([string]$decision.parent_package_id + "`t" + [string]$decision.alias + "`t" + [string]$decision.kind + "`t" + [string]$decision.target + "`t" + [string]$decision.disposition + "`t" + [string]$decision.predicate_witness + "`t" + [string]$decision.target_package_id + "`t" + [string]::Join(',', [string[]]$decision.lock_specs) + "`t" + [string]$decision.predicate_proven + "`t" + [string]$decision.optional_included)); $validationIndex++
    }
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.sort_decisions' -Progress ("rows={0}" -f $decisionCanon.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $decisionCanon.Sort([StringComparer]::Ordinal)
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.result_validation.sort_decisions_complete' -Progress ("rows={0}" -f $decisionCanon.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $expectedGraphSha = Get-D32BoundedDiagnosticSourceGraphDigest -LockSha256 ([string]$Graph.lock_sha256) `
        -LockDependencyEdgesSha256 ([string]$Graph.lock_dependency_edges_sha256) -RootIds ([string[]]$Graph.selected_root_ids) `
        -EdgeRows ([string[]]$edgeCanon.ToArray()) -DecisionRows ([string[]]$decisionCanon.ToArray()) `
        -ClosedSetSha256 $expectedClosedSha -ManifestSetSha256 $expectedManifestSha -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    if ($expectedGraphSha -cne [string]$Graph.graph_sha256) { return $false }
    return $true
}

function Add-D32BoundedDiagnosticSourceProofCandidateFailureReason {
    param([AllowNull()][System.Collections.Generic.List[string]]$FailureReasons, [Parameter(Mandatory = $true)][string]$Reason)
    if ($null -ne $FailureReasons) { $FailureReasons.Add($Reason) }
}

function New-D32BoundedDiagnosticSourceProofCandidateDocument {
    param(
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][string]$HistoricalOriginCandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][ValidateSet('CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY', 'BLOCKED')][string]$Status,
        [Parameter(Mandatory = $true)][string]$ProofAuthorityPath,
        [Parameter(Mandatory = $true)][string]$ProofAuthoritySha256,
        [Parameter(Mandatory = $true)][string]$ProofEntryPath,
        [Parameter(Mandatory = $true)][string]$ProofEntrySha256,
        [Parameter(Mandatory = $true)][string]$ProofStartedAtUtc,
        [Parameter(Mandatory = $true)][string]$ProofCompletedAtUtc,
        [Parameter(Mandatory = $true)][long]$ProofElapsedMilliseconds,
        [Parameter(Mandatory = $true)][object]$ProofBudget,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$SourcePins,
        [AllowNull()][object]$CurrentProfileLockBindings,
        [AllowNull()][object]$CurrentSourceClosure,
        [AllowNull()][object]$PrimaryError
    )
    return [PSCustomObject][ordered]@{
        schema_version = 4
        record_type = $script:D32BoundedDiagnosticSourceProofCandidateType
        source_plan_semantics_version = 2
        registry_archive_policy = $script:D32BoundedDiagnosticRegistryArchivePolicy
        gate_authority = 'NONE'
        candidate_sha = $CandidateSha
        historical_origin_candidate_sha = $HistoricalOriginCandidateSha
        source_repo = $Repository
        status = $Status
        formal_phase1_allowed = $false
        formal_aggregate_allowed = $false
        diagnostic_invocation_authority = 'NONE_UNTRUSTED_CANDIDATE_ONLY'
        historical_origin = [PSCustomObject][ordered]@{
            fetch_completion = 'NOT_RETAINED'
            attempt_state = 'BLOCKED'
            gate_authority = 'NONE'
        }
        proof_authority = [PSCustomObject][ordered]@{ path = $ProofAuthorityPath; sha256 = $ProofAuthoritySha256 }
        proof_entry = [PSCustomObject][ordered]@{ path = $ProofEntryPath; sha256 = $ProofEntrySha256 }
        proof_started_at_utc = $ProofStartedAtUtc
        proof_completed_at_utc = $ProofCompletedAtUtc
        proof_elapsed_milliseconds = $ProofElapsedMilliseconds
        proof_budget = $ProofBudget
        source_pins = @($SourcePins)
        current_profile_lock_bindings = $CurrentProfileLockBindings
        current_source_closure = $CurrentSourceClosure
        primary_error = $PrimaryError
    }
}

function Get-D32BoundedDiagnosticRegistrySourceProofDigest {
    param([Parameter(Mandatory = $true)][object[]]$Packages,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds)
    $canonicalRows = [System.Collections.Generic.List[string]]::new()
    $packageIndex = 0
    foreach ($package in $Packages) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.result_digest' -Progress ("packages={0}/{1}" -f $packageIndex, $Packages.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $counts = $package.format_counts
        $parts = [string[]]@(
            [string]$package.package_id, [string]$package.name, [string]$package.version, [string]$package.checksum,
            [string]$package.archive_inventory_sha256, [string]$package.registry_archive_policy,
            [string]$package.header_inventory_sha256,
            ([Int64]$package.header_count).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$package.ordinary_header_count).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$package.longname_pair_count).ToString([Globalization.CultureInfo]::InvariantCulture),
            [string]$package.longname_pair_inventory_sha256,
            ([Int64]$package.longname_control_metadata_count).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$package.longname_control_metadata_bytes).ToString([Globalization.CultureInfo]::InvariantCulture),
            [string]$package.longname_control_metadata_sha256,
            ([Int64]$counts.ustar_regular).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$counts.ustar_directory).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$counts.gnu_regular).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$counts.gnu_directory).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$counts.gnu_longname_extension).ToString([Globalization.CultureInfo]::InvariantCulture),
            [string]$package.source_root_volume_serial_hex, [string]$package.source_root_file_id_hex,
            ([Int64]$package.source_file_count).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$package.source_directory_count).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$package.generated_metadata_count).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$package.source_bytes).ToString([Globalization.CultureInfo]::InvariantCulture),
            [string]$package.source_inventory_sha256)
        $canonicalRows.Add([string]::Join("`t", $parts))
        $packageIndex++
    }
    $canonicalRows.Sort([StringComparer]::Ordinal)
    return Get-D32BoundedDiagnosticSha256FromLines -Lines ([string[]]$canonicalRows.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.result_digest_hash'
}

function New-D32BoundedDiagnosticRegistrySourceProofPackage {
    param(
        [Parameter(Mandatory = $true)][object]$Package,
        [Parameter(Mandatory = $true)][object]$ArchiveReference,
        [Parameter(Mandatory = $true)][object]$Inventory,
        [Parameter(Mandatory = $true)][object]$SourceProof
    )
    return [PSCustomObject][ordered]@{
        package_id = [string]$Package.package_id
        name = [string]$Package.name
        version = [string]$Package.version
        checksum = [string]$Package.checksum
        archive_path = [string]$ArchiveReference.path
        archive_bytes = [Int64]$ArchiveReference.bytes
        archive_file_sha256 = [string]$ArchiveReference.sha256
        archive_volume_serial_hex = [string]$ArchiveReference.volume_serial_hex
        archive_file_id_hex = [string]$ArchiveReference.file_id_hex
        archive_inventory_sha256 = [string]$Inventory.inventory_sha256
        registry_archive_policy = [string]$Inventory.archive_policy_id
        header_inventory_sha256 = [string]$Inventory.header_inventory_sha256
        header_count = [Int64]$Inventory.header_inventory.Count
        ordinary_header_count = [Int64]$Inventory.ordinary_header_count
        longname_pair_count = [Int64]$Inventory.longname_pair_count
        longname_pair_inventory_sha256 = [string]$Inventory.longname_pair_inventory_sha256
        longname_control_metadata_count = [Int64]$Inventory.longname_control_metadata_count
        longname_control_metadata_bytes = [Int64]$Inventory.longname_control_metadata_bytes
        longname_control_metadata_sha256 = [string]$Inventory.longname_control_metadata_sha256
        format_counts = [PSCustomObject][ordered]@{
            ustar_regular = [Int64]$Inventory.format_counts.ustar_regular
            ustar_directory = [Int64]$Inventory.format_counts.ustar_directory
            gnu_regular = [Int64]$Inventory.format_counts.gnu_regular
            gnu_directory = [Int64]$Inventory.format_counts.gnu_directory
            gnu_longname_extension = [Int64]$Inventory.format_counts.gnu_longname_extension
        }
        source_root = [string]$SourceProof.source_root
        source_root_volume_serial_hex = [string]$SourceProof.source_root_volume_serial_hex
        source_root_file_id_hex = [string]$SourceProof.source_root_file_id_hex
        source_file_count = [Int64]$SourceProof.archived_file_count
        source_directory_count = [Int64]$SourceProof.archived_directory_count
        generated_metadata_count = [Int64]$SourceProof.generated_metadata_count
        source_bytes = [Int64]$SourceProof.observed_source_bytes
        source_inventory_sha256 = [string]$SourceProof.source_inventory_sha256
    }
}

function New-D32BoundedDiagnosticRegistrySourceContentProofDocument {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Packages,
        [Parameter(Mandatory = $true)][string]$LockSha256,
        [Parameter(Mandatory = $true)][string]$RegistryTupleSha256,
        [Parameter(Mandatory = $true)][long]$LockedRegistryCatalogCount,
        [Parameter(Mandatory = $true)][long]$CompressedBytes,
        [Parameter(Mandatory = $true)][long]$ExpandedBytes,
        [Parameter(Mandatory = $true)][long]$MemberCount,
        [Parameter(Mandatory = $true)][long]$ElapsedMilliseconds
    )
    $rows = [object[]]@($Packages)
    return [PSCustomObject][ordered]@{
        schema_version = 4
        record_type = $script:D32BoundedDiagnosticRegistrySourceContentProofType
        registry_archive_policy = $script:D32BoundedDiagnosticRegistryArchivePolicy
        gate_authority = 'NONE'
        status = 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY'
        formal_gate_usable = $false
        semantic_scope = 'EXACT_CALLER_PINNED_ARCHIVE_SUBSET_FOR_LOCKED_GRAPH_CANDIDATES'
        source_proof_sha256 = Get-D32BoundedDiagnosticRegistrySourceProofDigest -Packages $rows
        verifier_managed_buffer_cap_bytes = [Int64]$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes
        maximum_buffered_registry_archive_bytes = [Int64]$script:D32BoundedCompilerDiagnosticRegistryArchiveLimitBytes
        concurrent_buffered_registry_archives = 1
        lock_sha256 = $LockSha256
        registry_tuple_sha256 = $RegistryTupleSha256
        package_count = [Int64]$rows.Count
        locked_registry_catalog_count = $LockedRegistryCatalogCount
        verified_package_ids = @($rows | ForEach-Object { [string]$_.package_id })
        compressed_bytes = $CompressedBytes
        expanded_bytes = $ExpandedBytes
        member_count = $MemberCount
        elapsed_milliseconds = $ElapsedMilliseconds
        packages = $rows
    }
}

function Test-D32BoundedDiagnosticRegistrySourceContentProof {
    param([AllowNull()][object]$Proof, [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds)
    $fields = @('schema_version', 'record_type', 'registry_archive_policy', 'gate_authority', 'status', 'formal_gate_usable',
        'semantic_scope', 'source_proof_sha256', 'verifier_managed_buffer_cap_bytes', 'maximum_buffered_registry_archive_bytes',
        'concurrent_buffered_registry_archives', 'lock_sha256', 'registry_tuple_sha256', 'package_count', 'locked_registry_catalog_count',
        'verified_package_ids', 'compressed_bytes', 'expanded_bytes', 'member_count', 'elapsed_milliseconds', 'packages')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Proof $fields) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Proof.schema_version -Positive) -or [Int64]$Proof.schema_version -ne 4 -or
        $Proof.record_type -isnot [string] -or [string]$Proof.record_type -cne $script:D32BoundedDiagnosticRegistrySourceContentProofType -or
        $Proof.registry_archive_policy -isnot [string] -or [string]$Proof.registry_archive_policy -cne $script:D32BoundedDiagnosticRegistryArchivePolicy -or
        $Proof.gate_authority -isnot [string] -or [string]$Proof.gate_authority -cne 'NONE' -or
        $Proof.status -isnot [string] -or [string]$Proof.status -cne 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY' -or
        $Proof.formal_gate_usable -isnot [bool] -or [bool]$Proof.formal_gate_usable -or
        $Proof.semantic_scope -isnot [string] -or [string]$Proof.semantic_scope -cne 'EXACT_CALLER_PINNED_ARCHIVE_SUBSET_FOR_LOCKED_GRAPH_CANDIDATES' -or
        [string]$Proof.source_proof_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Proof.lock_sha256 -cnotmatch '^[0-9a-f]{64}$' -or [string]$Proof.registry_tuple_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Proof.verifier_managed_buffer_cap_bytes -Positive) -or [Int64]$Proof.verifier_managed_buffer_cap_bytes -ne 536870912 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Proof.maximum_buffered_registry_archive_bytes -Positive) -or [Int64]$Proof.maximum_buffered_registry_archive_bytes -ne 268435456 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Proof.concurrent_buffered_registry_archives -Positive) -or [Int64]$Proof.concurrent_buffered_registry_archives -ne 1 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Proof.package_count -Positive) -or [Int64]$Proof.package_count -gt 1115 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Proof.locked_registry_catalog_count -Positive) -or
        [Int64]$Proof.locked_registry_catalog_count -lt [Int64]$Proof.package_count -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Proof.compressed_bytes -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Proof.expanded_bytes -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Proof.member_count -Positive) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Proof.elapsed_milliseconds) -or [Int64]$Proof.elapsed_milliseconds -gt 300000 -or
        $Proof.packages -isnot [Array] -or $Proof.verified_package_ids -isnot [Array] -or
        $Proof.packages.Count -ne [Int64]$Proof.package_count -or $Proof.verified_package_ids.Count -ne [Int64]$Proof.package_count) { return $false }

    $packageIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $archiveFields = @('package_id', 'name', 'version', 'checksum', 'archive_path', 'archive_bytes', 'archive_file_sha256',
        'archive_volume_serial_hex', 'archive_file_id_hex', 'archive_inventory_sha256', 'registry_archive_policy',
        'header_inventory_sha256', 'header_count', 'ordinary_header_count', 'longname_pair_count', 'longname_pair_inventory_sha256',
        'longname_control_metadata_count', 'longname_control_metadata_bytes', 'longname_control_metadata_sha256',
        'format_counts', 'source_root', 'source_root_volume_serial_hex',
        'source_root_file_id_hex', 'source_file_count', 'source_directory_count', 'generated_metadata_count', 'source_bytes', 'source_inventory_sha256')
    $countsFields = @('ustar_regular', 'ustar_directory', 'gnu_regular', 'gnu_directory', 'gnu_longname_extension')
    $index = 0
    foreach ($package in $Proof.packages) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.result_validation' -Progress ("packages={0}/{1}" -f $index, $Proof.packages.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $package $archiveFields) -or
            $package.package_id -isnot [string] -or [string]$package.package_id -notmatch '^[A-Za-z0-9_-]+@[0-9A-Za-z.+_-]+\|registry\|registry\+https://github\.com/rust-lang/crates\.io-index$' -or
            -not $packageIds.Add([string]$package.package_id) -or $Proof.verified_package_ids[$index] -isnot [string] -or
            [string]$Proof.verified_package_ids[$index] -cne [string]$package.package_id -or
            [string]$package.name -notmatch '^[A-Za-z0-9_-]+$' -or [string]$package.version -notmatch '^[0-9A-Za-z.+_-]+$' -or
            [string]$package.checksum -cnotmatch '^[0-9a-f]{64}$' -or [string]$package.archive_file_sha256 -cne [string]$package.checksum -or
            [string]$package.registry_archive_policy -cne $script:D32BoundedDiagnosticRegistryArchivePolicy -or
            -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $package.archive_path) -or
            -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $package.source_root) -or
            [string]$package.archive_path -cne (Join-Path 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f' ([string]$package.name + '-' + [string]$package.version + '.crate')) -or
            [string]$package.source_root -cne (Join-Path 'E:\d32\inv7\r\c\registry\src\index.crates.io-1949cf8c6b5b557f' ([string]$package.name + '-' + [string]$package.version)) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $package.archive_bytes -Positive) -or [Int64]$package.archive_bytes -gt 268435456 -or
            [string]$package.archive_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$package.archive_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$package.archive_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$package.header_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $package.header_count -Positive) -or [Int64]$package.header_count -gt 10000 -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $package.ordinary_header_count -Positive) -or
            [Int64]$package.ordinary_header_count -gt 10000 -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $package.longname_pair_count) -or
            [Int64]$package.longname_pair_count -gt 10000 -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $package.longname_control_metadata_count) -or
            [Int64]$package.longname_control_metadata_count -gt 10000 -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $package.longname_control_metadata_bytes) -or
            [string]$package.longname_pair_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$package.longname_control_metadata_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-D32BoundedCompilerDiagnosticExactProperties $package.format_counts $countsFields) -or
            [string]$package.source_root_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
            [string]$package.source_root_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $package.source_file_count -Positive) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $package.source_directory_count) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $package.generated_metadata_count) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $package.source_bytes -Positive) -or
            [string]$package.source_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$') { return $false }
        $countSum = [Int64]0
        foreach ($countName in $countsFields) {
            if (-not (Test-D32BoundedCompilerDiagnosticInteger $package.format_counts.($countName)) -or
                [Int64]$package.format_counts.($countName) -gt 10000) { return $false }
            $countSum += [Int64]$package.format_counts.($countName)
        }
        $ordinarySum = [Int64]$package.format_counts.ustar_regular + [Int64]$package.format_counts.ustar_directory +
            [Int64]$package.format_counts.gnu_regular + [Int64]$package.format_counts.gnu_directory
        if ($countSum -ne [Int64]$package.header_count -or $ordinarySum -ne [Int64]$package.ordinary_header_count -or
            [Int64]$package.longname_pair_count -ne [Int64]$package.format_counts.gnu_longname_extension -or
            [Int64]$package.longname_control_metadata_count -ne [Int64]$package.longname_pair_count -or
            ([Int64]$package.longname_control_metadata_count -eq 0 -and [Int64]$package.longname_control_metadata_bytes -ne 0) -or
            ([Int64]$package.longname_control_metadata_count -gt 0 -and
                ([Int64]$package.longname_control_metadata_bytes -lt ([Int64]$package.longname_control_metadata_count * 2L) -or
                 [Int64]$package.longname_control_metadata_bytes -gt ([Int64]$package.longname_control_metadata_count * 4097L))) -or
            [Int64]$package.header_count -gt 10000) { return $false }
        $index++
    }
    try { return ((Get-D32BoundedDiagnosticRegistrySourceProofDigest -Packages @($Proof.packages) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds) -ceq [string]$Proof.source_proof_sha256) }
    catch { return $false }
}

function Test-D32BoundedDiagnosticSourceProofCandidate {
    param([AllowNull()][object]$Record, [AllowNull()][System.Collections.Generic.List[string]]$FailureReasons,
        [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds)
    $fields = @('schema_version', 'record_type', 'source_plan_semantics_version', 'gate_authority', 'candidate_sha', 'historical_origin_candidate_sha',
        'registry_archive_policy', 'source_repo', 'status', 'formal_phase1_allowed', 'formal_aggregate_allowed', 'diagnostic_invocation_authority',
        'historical_origin', 'proof_authority', 'proof_entry', 'proof_started_at_utc', 'proof_completed_at_utc',
        'proof_elapsed_milliseconds', 'proof_budget', 'source_pins', 'current_profile_lock_bindings', 'current_source_closure', 'primary_error')
    $historicalFields = @('fetch_completion', 'attempt_state', 'gate_authority')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record $fields) -or
        [int64]$Record.schema_version -ne 4 -or [string]$Record.record_type -cne $script:D32BoundedDiagnosticSourceProofCandidateType -or
        [int]$Record.source_plan_semantics_version -ne 2 -or
        [string]$Record.registry_archive_policy -cne $script:D32BoundedDiagnosticRegistryArchivePolicy -or
        [string]$Record.gate_authority -cne 'NONE' -or
        [string]$Record.candidate_sha -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Record.historical_origin_candidate_sha -cne $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -or
        [string]$Record.historical_origin_candidate_sha -ceq [string]$Record.candidate_sha -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.source_repo) -or
        [string]$Record.status -cnotin @('CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY', 'BLOCKED') -or
        $Record.formal_phase1_allowed -isnot [bool] -or [bool]$Record.formal_phase1_allowed -or
        $Record.formal_aggregate_allowed -isnot [bool] -or [bool]$Record.formal_aggregate_allowed -or
        [string]$Record.diagnostic_invocation_authority -cne 'NONE_UNTRUSTED_CANDIDATE_ONLY' -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.historical_origin $historicalFields) -or
        [string]$Record.historical_origin.fetch_completion -cne 'NOT_RETAINED' -or
        [string]$Record.historical_origin.attempt_state -cne 'BLOCKED' -or
        [string]$Record.historical_origin.gate_authority -cne 'NONE' -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.proof_authority @('path', 'sha256')) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.proof_authority.path) -or
        [string]$Record.proof_authority.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.proof_entry @('path', 'sha256')) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.proof_entry.path) -or
        [string]$Record.proof_entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.proof_elapsed_milliseconds) -or
        (($Record.primary_error -isnot [string]) -and ($null -ne $Record.primary_error)) -or
        (($Record.current_profile_lock_bindings -isnot [Array]) -and ($null -ne $Record.current_profile_lock_bindings)) -or
        (($null -ne $Record.current_source_closure) -and ([string]$Record.current_source_closure.HistoricalAttemptState -cne 'BLOCKED'))) {
        $reason = if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record $fields)) { 'candidate-exact-fields' }
            elseif (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.historical_origin $historicalFields)) { 'historical-origin-object-shape' }
            elseif (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.proof_authority @('path', 'sha256'))) { 'proof-authority-object-shape' }
            elseif (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.proof_entry @('path', 'sha256'))) { 'proof-entry-object-shape' }
            elseif ([string]$Record.status -ceq 'BLOCKED' -and [String]::IsNullOrWhiteSpace([string]$Record.primary_error)) { 'blocked-primary-error-missing' }
            else { 'candidate-envelope-or-common-values' }
        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason $reason
        return $false
    }
    if ($null -ne $Record.current_source_closure -and
        ([string]$Record.current_source_closure.CurrentCandidateSha -cne [string]$Record.candidate_sha -or
         [string]$Record.current_source_closure.HistoricalOriginCandidateSha -cne [string]$Record.historical_origin_candidate_sha)) {
        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'source-closure-current-historical-crossbind'
        return $false
    }
    if ([string]$Record.status -ceq 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY' -and $null -ne $Record.current_source_closure -and
        -not (Test-D32BoundedDiagnosticSourceGraphProof $Record.current_source_closure.SourceGraphProof -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds)) {
        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'source-graph-proof-shape-or-witness'
        return $false
    }
    if ([string]$Record.status -ceq 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY') {
        if ($null -eq $Record.current_source_closure -or [Int64]$Record.proof_elapsed_milliseconds -gt 300000 -or $null -ne $Record.primary_error) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'verified-result-closure-time-or-primary-error'
            return $false
        }
        if ($Record.source_pins -isnot [Array] -or $Record.source_pins.Count -ne 5) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'verified-result-source-pin-count'
            return $false
        }
        if ($Record.current_profile_lock_bindings -isnot [Array] -or $Record.current_profile_lock_bindings.Count -ne 3) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'verified-result-profile-lock-binding-count'
            return $false
        }
        if (
            [string]$Record.current_source_closure.HistoricalAttemptState -cne 'BLOCKED' -or
            [string]$Record.current_source_closure.HistoricalFetchCompletion -cne 'NOT_RETAINED' -or
            [string]$Record.current_source_closure.HistoricalGateAuthority -cne 'NONE') {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'historical-origin-status-binding'
            return $false
        }
        if (
            [string]$Record.current_source_closure.RegistryContentProof.record_type -cne $script:D32BoundedDiagnosticRegistrySourceContentProofType -or
            [string]$Record.current_source_closure.GitContentProof.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_CONTENT_PROOF_V2' -or
            [string]$Record.current_source_closure.SourceGraphProof.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_SOURCE_GRAPH_PROOF_V2' -or
            [string]$Record.current_source_closure.CurrentCandidateSha -cne [string]$Record.candidate_sha -or
            [string]$Record.current_source_closure.HistoricalOriginCandidateSha -cne [string]$Record.historical_origin_candidate_sha) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'proof-record-type-or-current-historical-binding'
            return $false
        }
        if ([Int64]$Record.current_source_closure.SourceGraphProof.included_package_count + [Int64]$Record.current_source_closure.SourceGraphProof.excluded_package_count -ne [Int64]$Record.current_source_closure.SourceGraphProof.locked_package_count) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'source-graph-package-partition-count'
            return $false
        }
        if ([string]$Record.current_source_closure.RegistryContentProof.status -cne 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY' -or
            [bool]$Record.current_source_closure.RegistryContentProof.formal_gate_usable -or
            -not (Test-D32BoundedDiagnosticRegistrySourceContentProof $Record.current_source_closure.RegistryContentProof -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds) -or
            [string]$Record.current_source_closure.RegistryContentProof.lock_sha256 -cne [string]$Record.current_source_closure.SourceGraphProof.lock_sha256 -or
            $Record.current_source_closure.RegistryContentProof.verified_package_ids -isnot [Array]) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'registry-proof-status-lock-or-package-set'
            return $false
        }
        if ([string]$Record.current_source_closure.GitContentProof.status -cne 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY' -or
            [bool]$Record.current_source_closure.GitContentProof.formal_gate_usable -or
            [string]$Record.current_source_closure.GitContentProof.lock_sha256 -cne [string]$Record.current_source_closure.SourceGraphProof.lock_sha256 -or
            $Record.current_source_closure.GitContentProof.verified_package_ids -isnot [Array] -or
            $Record.current_source_closure.CurrentManifestProof -isnot [Array]) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'git-proof-status-lock-package-or-manifest-set'
            return $false
        }
    }
    if ([string]$Record.status -ceq 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY') {
        $registryIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $closureIndex = 0
        foreach ($id in $Record.current_source_closure.RegistryContentProof.verified_package_ids) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_proof.result_registry_ids' -Progress ("packages={0}/{1}" -f $closureIndex, $Record.current_source_closure.RegistryContentProof.verified_package_ids.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
            if ($id -isnot [string] -or -not $registryIds.Add([string]$id)) {
                Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'registry-proof-package-id-set'
                return $false
            }
            $closureIndex++
        }
        $gitIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $closureIndex = 0
        foreach ($id in $Record.current_source_closure.GitContentProof.verified_package_ids) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_proof.result_git_ids' -Progress ("packages={0}/{1}" -f $closureIndex, $Record.current_source_closure.GitContentProof.verified_package_ids.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
            if ($id -isnot [string] -or -not $gitIds.Add([string]$id)) {
                Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'git-proof-package-id-set'
                return $false
            }
            $closureIndex++
        }
        $workspaceManifests = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
        $closureIndex = 0
        foreach ($manifest in $Record.current_source_closure.CurrentManifestProof) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_proof.result_current_manifests' -Progress ("manifests={0}/{1}" -f $closureIndex, $Record.current_source_closure.CurrentManifestProof.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
            if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $manifest @('manifest_path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
                [string]$manifest.manifest_path -notmatch '^[A-Za-z0-9_./-]+/Cargo\.toml$' -or
                -not (Test-D32BoundedCompilerDiagnosticInteger $manifest.bytes -Positive) -or [string]$manifest.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                [string]$manifest.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$manifest.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
                -not $workspaceManifests.TryAdd([string]$manifest.manifest_path, [string]$manifest.sha256)) {
                Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'workspace-manifest-proof-shape-or-duplicate'
                return $false
            }
            $closureIndex++
        }
        if ($workspaceManifests.Count -ne $Record.current_profile_lock_bindings.Count) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'workspace-manifest-to-profile-binding-count'
            return $false
        }
        $closureIndex = 0
        foreach ($binding in $Record.current_profile_lock_bindings) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_proof.result_profile_bindings' -Progress ("bindings={0}/{1}" -f $closureIndex, $Record.current_profile_lock_bindings.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
            if (-not $workspaceManifests.ContainsKey([string]$binding.manifest_path)) {
                Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'profile-binding-manifest-unmatched'
                return $false
            }
            $closureIndex++
        }
        $gitSourceCounts = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
        $closureIndex = 0
        foreach ($gitSource in $Record.current_source_closure.GitContentProof.sources) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_proof.result_git_sources' -Progress ("sources={0}/{1}" -f $closureIndex, $Record.current_source_closure.GitContentProof.sources.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
            $sourceName = [string]$gitSource.source
            if ($gitSourceCounts.ContainsKey($sourceName)) { $gitSourceCounts[$sourceName] = [int]$gitSourceCounts[$sourceName] + 1 } else { $gitSourceCounts.Add($sourceName, 1) }
            $closureIndex++
        }
        $closureIndex = 0
        foreach ($class in $Record.current_source_closure.SourceGraphProof.classifications) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_proof.result_classifications' -Progress ("classifications={0}/{1}" -f $closureIndex, $Record.current_source_closure.SourceGraphProof.classifications.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
            $closureIndex++
            if ([string]$class.classification -cne 'INCLUDED') { continue }
            switch ([string]$class.source_kind) {
                'workspace' {
                    if (-not $workspaceManifests.ContainsKey([string]$class.manifest_path) -or $workspaceManifests[[string]$class.manifest_path] -cne [string]$class.manifest_sha256) {
                        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'included-workspace-manifest-crossbind'
                        return $false
                    }
                }
                'registry' {
                    if (-not $registryIds.Contains([string]$class.package_id) -or [string]$class.source_identity -cne 'registry+https://github.com/rust-lang/crates.io-index') {
                        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'included-registry-package-crossbind'
                        return $false
                    }
                }
                'git' {
                    if (-not $gitIds.Contains([string]$class.package_id) -or
                        -not $gitSourceCounts.ContainsKey([string]$class.source_identity) -or $gitSourceCounts[[string]$class.source_identity] -ne 1) {
                        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'included-git-package-crossbind'
                        return $false
                    }
                }
                default {
                    Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'included-package-source-kind-unknown'
                    return $false
                }
            }
        }
        $lockBinding = @($Record.current_profile_lock_bindings | Where-Object { [string]$_.lock_path -ceq 'vita-agent/Cargo.lock' })
        if ($lockBinding.Count -ne 1 -or [string]$lockBinding[0].lock_sha256 -cne [string]$Record.current_source_closure.SourceGraphProof.lock_sha256) {
            Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'vita-agent-lock-profile-crossbind'
            return $false
        }
    }
    if ([string]$Record.status -ceq 'BLOCKED' -and [String]::IsNullOrWhiteSpace([string]$Record.primary_error)) {
        Add-D32BoundedDiagnosticSourceProofCandidateFailureReason -FailureReasons $FailureReasons -Reason 'blocked-primary-error-missing'
        return $false
    }
    return $true
}

function Test-D32BoundedDiagnosticSourceProofAuthorityShape {
    param(
        [AllowNull()][object]$Document,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$ExpectedHistoricalOriginCandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$EntryScriptPath,
        [Parameter(Mandatory = $true)][string]$RunnerPath,
        [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
        [Parameter(Mandatory = $true)][string]$ToolchainProfileSha256,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds
    )
    $top = @('schema_version', 'record_type', 'registry_archive_policy', 'gate_authority', 'candidate_sha', 'historical_origin_candidate_sha',
        'source_repo', 'repository_identity', 'toolchain_profile', 'source_pins', 'dependency_origin', 'proof_budget',
        'output_candidate', 'run_id', 'issued_at_utc')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $Document -Expected $top) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Document.schema_version -Positive) -or [int]$Document.schema_version -ne 3 -or
        $Document.record_type -isnot [string] -or [string]$Document.record_type -cne $script:D32BoundedDiagnosticSourceProofAuthorityType -or
        $Document.registry_archive_policy -isnot [string] -or [string]$Document.registry_archive_policy -cne $script:D32BoundedDiagnosticRegistryArchivePolicy -or
        $Document.gate_authority -isnot [string] -or [string]$Document.gate_authority -cne 'NONE' -or
        $Document.candidate_sha -isnot [string] -or [string]$Document.candidate_sha -cne $ExpectedCandidateSha -or
        $ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or
        $Document.historical_origin_candidate_sha -isnot [string] -or
        [string]$Document.historical_origin_candidate_sha -cne $ExpectedHistoricalOriginCandidateSha -or
        [string]$Document.historical_origin_candidate_sha -cne $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -or
        [string]$Document.historical_origin_candidate_sha -ceq [string]$Document.candidate_sha -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.source_repo) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$Document.source_repo), [IO.Path]::GetFullPath($Repository)) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Document.repository_identity) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.repository_identity @('volume_serial_hex', 'file_id_hex')) -or
        [string]$Document.run_id -cnotmatch '^[0-9a-f]{32}$') { return $false }

    $profile = $Document.toolchain_profile
    if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $profile) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$profile.path, [IO.Path]::GetFullPath($ToolchainProfilePath)) -or
        [string]$profile.sha256 -cne $ToolchainProfileSha256 -or
        [string]$profile.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Test-D32BoundedCompilerDiagnosticWithin $profile.path $Repository) -or
        (Test-D32BoundedCompilerDiagnosticWithin $profile.path 'E:\d32\inv7\r\c')) { return $false }

    $origin = $Document.dependency_origin
    $originFields = @('path', 'volume_serial_hex', 'file_id_hex', 'owner_record', 'blocked_diagnostic', 'fetch_records',
        'manifest_refs', 'registry_archives', 'registry_archive_root', 'registry_source_root', 'git_database_root', 'git_checkout_root', 'git_content_refs')
    $requiredOrigin = 'E:\d32\inv7\r\c'
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $origin $originFields) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.path, $requiredOrigin) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $origin) -or
        $origin.fetch_records -isnot [Array] -or $origin.fetch_records.Count -gt 3 -or
        $origin.manifest_refs -isnot [Array] -or $origin.manifest_refs.Count -ne 6 -or
        $origin.registry_archives -isnot [Array] -or $origin.registry_archives.Count -eq 0 -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.owner_record) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.owner_record.path, 'E:\d32\inv7\D32-PHASE0-OWNER.json') -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.blocked_diagnostic) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.blocked_diagnostic.path, 'E:\d32\inv7\D32-PHASE0-BLOCKED-DIAGNOSTIC.json')) { return $false }
    $referenceIndex = 0
    foreach ($reference in @($origin.fetch_records) + @($origin.manifest_refs)) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'authority_shape.origin_refs' -Progress ("references={0}" -f $referenceIndex) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED' -NoProgress }
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $reference)) { return $false }
        $referenceIndex++
    }
    $rootPaths = @(
        [PSCustomObject]@{ Name = 'registry_archive_root'; Path = 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f' },
        [PSCustomObject]@{ Name = 'registry_source_root'; Path = 'E:\d32\inv7\r\c\registry\src\index.crates.io-1949cf8c6b5b557f' },
        [PSCustomObject]@{ Name = 'git_database_root'; Path = 'E:\d32\inv7\r\c\git\db' },
        [PSCustomObject]@{ Name = 'git_checkout_root'; Path = 'E:\d32\inv7\r\c\git\checkouts' })
    foreach ($rootPin in $rootPaths) {
        $reference = $origin.PSObject.Properties[[string]$rootPin.Name].Value
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $reference @('path', 'volume_serial_hex', 'file_id_hex')) -or
            -not (Test-D32BoundedCompilerDiagnosticIdentityPair $reference) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$reference.path, [string]$rootPin.Path)) { return $false }
    }
    $archiveIndex = 0
    foreach ($archive in $origin.registry_archives) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'authority_shape.registry_archives' -Progress ("archives={0}/{1}" -f $archiveIndex, $origin.registry_archives.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED' -NoProgress }
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $archive @('source', 'name', 'version', 'checksum', 'path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
            [string]$archive.source -cne 'registry+https://github.com/rust-lang/crates.io-index' -or
            [string]$archive.name -notmatch '^[A-Za-z0-9_-]+$' -or [string]$archive.version -notmatch '^[0-9A-Za-z.+_-]+$' -or
            [string]$archive.checksum -cnotmatch '^[0-9a-f]{64}$' -or [string]$archive.sha256 -cne [string]$archive.checksum -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $archive.bytes -Positive) -or [Int64]$archive.bytes -gt 268435456 -or
            [string]$archive.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$archive.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$archive.path, (Join-Path ([string]$origin.registry_archive_root.path) ([string]$archive.name + '-' + [string]$archive.version + '.crate')))) { return $false }
        $archiveIndex++
    }
    if ($origin.git_content_refs -isnot [Array] -or $origin.git_content_refs.Count -eq 0 -or $origin.git_content_refs.Count -gt 16) { return $false }
    $gitSourcesSeen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $gitIndex = 0
    foreach ($reference in $origin.git_content_refs) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'authority_shape.git_refs' -Progress ("references={0}/{1}" -f $gitIndex, $origin.git_content_refs.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED' -NoProgress }
        if (-not (Test-D32BoundedCompilerDiagnosticGitContentReferenceShape $reference) -or -not $gitSourcesSeen.Add([string]$reference.source)) { return $false }
        $gitIndex++
    }

    $pins = $Document.source_pins
    $expectedPins = @(
        'scripts/d32-bounded-diagnostic-sourceproof.ps1',
        'scripts/d32-bounded-compiler-diagnostic.ps1',
        'scripts/d32-bounded-compiler-diagnostic-policy.ps1',
        'scripts/d32-build-toolchain-profile.ps1',
        'scripts/d32-powershell-module-authority.ps1')
    if ($pins -isnot [Array] -or $pins.Count -ne $expectedPins.Count) { return $false }
    $pinPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $sourcePinIndex = 0
    foreach ($pin in $pins) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'authority_shape.source_pins' -Progress ("pins={0}/{1}" -f $sourcePinIndex, $pins.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED' -NoProgress }
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $pin) -or
            -not (Test-D32BoundedCompilerDiagnosticWithin $pin.path $Repository) -or -not $pinPaths.Add([string]$pin.path)) { return $false }
        $sourcePinIndex++
    }
    foreach ($relative in $expectedPins) {
        $expectedPath = [IO.Path]::GetFullPath((Join-Path $Repository ($relative.Replace('/', '\'))))
        $matches = @($pins | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals([string]$_.path, $expectedPath) })
        if ($matches.Count -ne 1) { return $false }
    }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($EntryScriptPath), [IO.Path]::GetFullPath((Join-Path $Repository 'scripts/d32-bounded-diagnostic-sourceproof.ps1'))) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($RunnerPath), [IO.Path]::GetFullPath((Join-Path $Repository 'scripts/d32-bounded-compiler-diagnostic.ps1')))) { return $false }

    $budget = $Document.proof_budget
    $budgetFields = @('combined_milliseconds', 'managed_buffer_bytes', 'max_registry_archive_bytes', 'max_git_pack_bytes',
        'max_git_index_bytes', 'max_git_object_bytes', 'max_git_object_count', 'max_git_delta_depth', 'max_git_expanded_bytes', 'max_manifest_or_lock_file_bytes')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $budget $budgetFields)) { return $false }
    foreach ($name in $budgetFields) { if (-not (Test-D32BoundedCompilerDiagnosticInteger $budget.($name) -Positive)) { return $false } }
    if (
        [Int64]$budget.combined_milliseconds -ne 300000 -or [Int64]$budget.managed_buffer_bytes -ne 536870912 -or
        [Int64]$budget.max_registry_archive_bytes -ne 268435456 -or [Int64]$budget.max_git_pack_bytes -ne 268435456 -or
        [Int64]$budget.max_git_index_bytes -ne 67108864 -or [Int64]$budget.max_git_object_bytes -ne 67108864 -or
        [Int64]$budget.max_git_object_count -ne 500000 -or [Int64]$budget.max_git_delta_depth -ne 32 -or
        [Int64]$budget.max_git_expanded_bytes -ne 34359738368 -or [Int64]$budget.max_manifest_or_lock_file_bytes -ne 16777216) { return $false }

    $output = $Document.output_candidate
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $output @('path', 'parent_path', 'parent_volume_serial_hex', 'parent_file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$output.path), [string]$output.parent_path) -or
        [string]$output.parent_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$output.parent_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.path $Repository) -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.path $requiredOrigin) -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.path $profile.path)) { return $false }
    try { $null = [DateTimeOffset]::Parse([string]$Document.issued_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
    catch { return $false }
    return $true
}

function Test-D32BoundedCompilerDiagnosticCanonicalPath {
    param([AllowNull()][object]$Value)
    if ($Value -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$Value) -or -not [IO.Path]::IsPathRooted([string]$Value)) { return $false }
    try { return [IO.Path]::GetFullPath([string]$Value).TrimEnd('\', '/') -ceq ([string]$Value).TrimEnd('\', '/') }
    catch { return $false }
}

function Test-D32BoundedCompilerDiagnosticWithin {
    param([AllowNull()][object]$Child, [AllowNull()][object]$Parent)
    if ($Child -isnot [string] -or $Parent -isnot [string] -or
        [String]::IsNullOrWhiteSpace([string]$Child) -or [String]::IsNullOrWhiteSpace([string]$Parent) -or
        -not [IO.Path]::IsPathFullyQualified([string]$Child) -or -not [IO.Path]::IsPathFullyQualified([string]$Parent)) { return $false }
    try {
        $childFull = [IO.Path]::GetFullPath([string]$Child)
        $parentFull = [IO.Path]::GetFullPath([string]$Parent)
        $childRoot = [IO.Path]::GetPathRoot($childFull)
        $parentRoot = [IO.Path]::GetPathRoot($parentFull)
        if ([String]::IsNullOrWhiteSpace($childRoot) -or [String]::IsNullOrWhiteSpace($parentRoot)) { return $false }
        $childComparable = if ($childFull.Length -gt $childRoot.Length) { $childFull.TrimEnd('\', '/') } else { $childRoot }
        $parentComparable = if ($parentFull.Length -gt $parentRoot.Length) { $parentFull.TrimEnd('\', '/') } else { $parentRoot }
        if ([StringComparer]::OrdinalIgnoreCase.Equals($childComparable, $parentComparable)) { return $true }
        $parentIsRoot = [StringComparer]::OrdinalIgnoreCase.Equals($parentComparable, $parentRoot) -or
            [StringComparer]::OrdinalIgnoreCase.Equals($parentComparable.TrimEnd('\', '/'), $parentRoot.TrimEnd('\', '/'))
        $parentPrefix = if ($parentIsRoot) {
            if ($parentRoot.EndsWith([IO.Path]::DirectorySeparatorChar)) { $parentRoot } else { $parentRoot + [IO.Path]::DirectorySeparatorChar }
        } else { $parentComparable + [IO.Path]::DirectorySeparatorChar }
        return $childFull.StartsWith($parentPrefix, [StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

function Format-D32BoundedCompilerDiagnosticPathForError {
    param([AllowNull()][object]$Path)
    if ($null -eq $Path) { return 'null' }
    if ($Path -isnot [string]) { return '<non-string>' }
    return ConvertTo-Json -InputObject ([string]$Path) -Compress -Depth 2 -WarningAction SilentlyContinue
}

function Test-D32BoundedCompilerDiagnosticIdentityPair {
    param([AllowNull()][object]$Object, [string]$VolumeName = 'volume_serial_hex', [string]$FileIdName = 'file_id_hex')
    if ($null -eq $Object -or $Object.PSObject.Properties[$VolumeName] -eq $null -or $Object.PSObject.Properties[$FileIdName] -eq $null) { return $false }
    return ([string]$Object.$VolumeName -cmatch '^[0-9a-f]{16}$' -and [string]$Object.$FileIdName -cmatch '^[0-9a-f]{32}$')
}

function Get-D32BoundedCompilerDiagnosticFileReferenceShapeFailure {
    param([AllowNull()][object]$Reference, [switch]$AllowEmptyBytes)
    if ($null -eq $Reference) { return 'reference_is_null' }
    if ($Reference -is [string] -or $Reference -is [Array] -or $Reference -is [ValueType]) { return 'reference_is_not_an_object' }
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $Reference -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) {
        return 'property_set_is_not_exact'
    }
    if (-not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Reference.path)) { return 'path_must_be_canonical_absolute_string' }
    if (-not (Test-D32BoundedCompilerDiagnosticInteger $Reference.bytes)) { return 'bytes_must_be_integer' }
    if ($AllowEmptyBytes) {
        if ([Int64]$Reference.bytes -lt 0) { return 'bytes_must_be_nonnegative' }
    }
    elseif ([Int64]$Reference.bytes -le 0) { return 'bytes_must_be_positive' }
    if ([string]$Reference.sha256 -cnotmatch '^[0-9a-f]{64}$') { return 'sha256_must_be_lowercase_hex' }
    if (-not (Test-D32BoundedCompilerDiagnosticIdentityPair $Reference)) { return 'volume_file_identity_must_be_exact_hex' }
    return $null
}

function Test-D32BoundedCompilerDiagnosticFileReferenceShape {
    param([AllowNull()][object]$Reference)
    return ($null -eq (Get-D32BoundedCompilerDiagnosticFileReferenceShapeFailure -Reference $Reference))
}

function Test-D32BoundedCompilerDiagnosticCapturedStreamReferenceShape {
    param([AllowNull()][object]$Reference, [Parameter(Mandatory = $true)][string]$ExpectedPath)
    if (-not (Test-D32BoundedCompilerDiagnosticCanonicalPath $ExpectedPath)) { return $false }
    if ($null -ne (Get-D32BoundedCompilerDiagnosticFileReferenceShapeFailure -Reference $Reference -AllowEmptyBytes)) { return $false }
    return [StringComparer]::OrdinalIgnoreCase.Equals([string]$Reference.path, $ExpectedPath)
}

function Test-D32BoundedCompilerDiagnosticGitContentReferenceShape {
    param([AllowNull()][object]$Reference)
    $fields = @('source', 'commit', 'database_path', 'database_volume_serial_hex', 'database_file_id_hex',
        'checkout_cache_path', 'checkout_cache_volume_serial_hex', 'checkout_cache_file_id_hex',
        'checkout_path', 'checkout_volume_serial_hex', 'checkout_file_id_hex',
        'pack_path', 'pack_bytes', 'pack_volume_serial_hex', 'pack_file_id_hex',
        'index_path', 'index_bytes', 'index_volume_serial_hex', 'index_file_id_hex')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Reference $fields) -or
        $Reference.source -isnot [string] -or $Reference.commit -isnot [string] -or
        [string]$Reference.commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Reference.source -notmatch '^git\+https://[^?#@\s]+(?:\?[^#\r\n]+)?#([0-9a-f]{40})$' -or
        [string]$Matches[1] -cne [string]$Reference.commit) { return $false }
    $databaseRoot = 'E:\d32\inv7\r\c\git\db'
    $checkoutRoot = 'E:\d32\inv7\r\c\git\checkouts'
    foreach ($path in @($Reference.database_path, $Reference.checkout_cache_path, $Reference.checkout_path, $Reference.pack_path, $Reference.index_path)) {
        if (-not (Test-D32BoundedCompilerDiagnosticCanonicalPath $path)) { return $false }
    }
    if (-not (Test-D32BoundedCompilerDiagnosticWithin $Reference.database_path $databaseRoot) -or
        -not (Test-D32BoundedCompilerDiagnosticWithin $Reference.checkout_cache_path $checkoutRoot) -or
        -not (Test-D32BoundedCompilerDiagnosticWithin $Reference.checkout_path $Reference.checkout_cache_path) -or
        -not (Test-D32BoundedCompilerDiagnosticWithin $Reference.pack_path $Reference.database_path) -or
        -not (Test-D32BoundedCompilerDiagnosticWithin $Reference.index_path $Reference.database_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$Reference.pack_path), [IO.Path]::GetDirectoryName([string]$Reference.index_path)) -or
        [IO.Path]::GetFileName([string]$Reference.checkout_path) -cne ([string]$Reference.commit).Substring(0, 7) -or
        [IO.Path]::GetFileName([string]$Reference.pack_path) -cnotmatch '^pack-([0-9a-f]{40})\.pack$' -or
        [IO.Path]::GetFileName([string]$Reference.index_path) -cnotmatch '^pack-([0-9a-f]{40})\.idx$') { return $false }
    $packId = [regex]::Match([IO.Path]::GetFileName([string]$Reference.pack_path), '^pack-([0-9a-f]{40})\.pack$').Groups[1].Value
    $indexId = [regex]::Match([IO.Path]::GetFileName([string]$Reference.index_path), '^pack-([0-9a-f]{40})\.idx$').Groups[1].Value
    if ($packId -cne $indexId -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Reference.pack_bytes -Positive) -or [Int64]$Reference.pack_bytes -gt 268435456 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Reference.index_bytes -Positive) -or [Int64]$Reference.index_bytes -gt 67108864) { return $false }
    foreach ($name in @('database', 'checkout_cache', 'checkout', 'pack', 'index')) {
        $volumeName = $name + '_volume_serial_hex'
        $fileName = $name + '_file_id_hex'
        if ([string]$Reference.PSObject.Properties[$volumeName].Value -cnotmatch '^[0-9a-f]{16}$' -or
            [string]$Reference.PSObject.Properties[$fileName].Value -cnotmatch '^[0-9a-f]{32}$') { return $false }
    }
    return $true
}

function Test-D32BoundedCompilerDiagnosticGitQueryList {
    param([AllowNull()][object]$Queries)
    $expectedRows = [System.Collections.Generic.List[object]]::new()
    $expectedRows.Add([string[]]@('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}'))
    $expectedRows.Add([string[]]@('status', '--porcelain=v1', '--untracked-files=all'))
    $expectedRows.Add([string[]]@('ls-files', '-v', '-z'))
    $expectedRows.Add([string[]]@('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}'))
    $expectedRows.Add([string[]]@('status', '--porcelain=v1', '--untracked-files=all'))
    $expected = $expectedRows.ToArray()
    if ($Queries -isnot [Array] -or $Queries.Count -ne $expected.Count) { return $false }
    for ($i = 0; $i -lt $expected.Count; $i++) {
        if ($Queries[$i] -isnot [Array] -or $Queries[$i].Count -ne $expected[$i].Count) { return $false }
        for ($j = 0; $j -lt $expected[$i].Count; $j++) {
            if ($Queries[$i][$j] -isnot [string] -or [string]$Queries[$i][$j] -cne [string]$expected[$i][$j]) { return $false }
        }
    }
    return $true
}

function Test-D32BoundedCompilerDiagnosticFixedGitQuery {
    param([AllowNull()][object]$Arguments)
    if ($Arguments -isnot [Array]) { return $false }
    $allowed = [object[]]::new(3)
    $allowed[0] = [string[]]@('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}')
    $allowed[1] = [string[]]@('status', '--porcelain=v1', '--untracked-files=all')
    $allowed[2] = [string[]]@('ls-files', '-v', '-z')
    foreach ($candidate in $allowed) {
        if ($Arguments.Count -ne $candidate.Count) { continue }
        $matches = $true
        for ($index = 0; $index -lt $candidate.Count; $index++) {
            if ($Arguments[$index] -isnot [string] -or [string]$Arguments[$index] -cne $candidate[$index]) { $matches = $false; break }
        }
        if ($matches) { return $true }
    }
    return $false
}

function Test-D32BoundedCompilerDiagnosticHistoricalReplay {
    param([AllowNull()][object]$SourceClosure)
    return ($null -ne $SourceClosure -and
        [string]$SourceClosure.HistoricalFetchCompletion -ceq 'NOT_RETAINED' -and
        [string]$SourceClosure.HistoricalAttemptState -ceq 'BLOCKED' -and
        [string]$SourceClosure.HistoricalGateAuthority -ceq 'NONE')
}

function Get-D32BoundedCompilerDiagnosticStopDrainDeadlineTicks {
    param(
        [Parameter(Mandatory = $true)][long]$NowTicks,
        [Parameter(Mandatory = $true)][long]$StopwatchFrequency,
        [Parameter(Mandatory = $true)][long]$OverallDeadlineTicks,
        [Parameter(Mandatory = $true)][long]$CleanupReserveMilliseconds,
        [Parameter(Mandatory = $true)][long]$PersistReserveMilliseconds
    )
    if ($NowTicks -le 0 -or $StopwatchFrequency -le 0 -or $OverallDeadlineTicks -le 0 -or
        $CleanupReserveMilliseconds -lt $script:D32BoundedCompilerDiagnosticCleanupReserveMilliseconds -or
        $PersistReserveMilliseconds -lt $script:D32BoundedCompilerDiagnosticPersistReserveMilliseconds) {
        throw 'D32_BOUNDED_DIAGNOSTIC_BUDGET_BLOCKED: stop-drain deadline inputs are invalid or below their retained reserves'
    }
    $drainTicks = $NowTicks + [Int64](30L * $StopwatchFrequency)
    $cargoStopBoundary = $OverallDeadlineTicks - [Int64]($CleanupReserveMilliseconds * $StopwatchFrequency / 1000L) -
        [Int64]($PersistReserveMilliseconds * $StopwatchFrequency / 1000L)
    return [Math]::Max($NowTicks, [Math]::Min($drainTicks, $cargoStopBoundary))
}

function Test-D32BoundedCompilerDiagnosticAuthorityShape {
    param(
        [AllowNull()][object]$Document,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
        [Parameter(Mandatory = $true)][string]$ToolchainProfileSha256,
        [Parameter(Mandatory = $true)][string]$ModuleAuthorityPath,
        [Parameter(Mandatory = $true)][string]$ModuleAuthoritySha256,
        [Parameter(Mandatory = $true)][string]$PinnedGitPath,
        [Parameter(Mandatory = $true)][string]$PinnedGitSha256,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedEnvironment
    )
    $top = @('schema_version', 'record_type', 'registry_archive_policy', 'gate_authority', 'candidate_sha', 'source_repo', 'repository_identity',
        'toolchain_profile', 'module_authority', 'pinned_git', 'command', 'child_environment', 'git_queries', 'cargo_home', 'dependency_origin',
        'target', 'output', 'resource_budget', 'source_pins', 'image_grants', 'issued_at_utc')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $Document -Expected $top) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Document.schema_version -Positive) -or [int]$Document.schema_version -ne 3 -or
        $Document.record_type -isnot [string] -or $Document.record_type -cne $script:D32BoundedCompilerDiagnosticAuthorityType -or
        $Document.registry_archive_policy -isnot [string] -or $Document.registry_archive_policy -cne $script:D32BoundedDiagnosticRegistryArchivePolicy -or
        $Document.gate_authority -isnot [string] -or $Document.gate_authority -cne 'NONE' -or
        $Document.candidate_sha -isnot [string] -or $Document.candidate_sha -cne $ExpectedCandidateSha -or $ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.source_repo) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$Document.source_repo), [IO.Path]::GetFullPath($Repository)) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Document.repository_identity) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties -Object $Document.repository_identity -Expected @('volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticGitQueryList $Document.git_queries)) { return $false }

    $profile = $Document.toolchain_profile
    $module = $Document.module_authority
    $git = $Document.pinned_git
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $profile @('path', 'sha256')) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $module @('path', 'sha256')) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $git @('path', 'sha256')) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$profile.path), [IO.Path]::GetFullPath($ToolchainProfilePath)) -or
        [string]$profile.sha256 -cne $ToolchainProfileSha256 -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$module.path), [IO.Path]::GetFullPath($ModuleAuthorityPath)) -or
        [string]$module.sha256 -cne $ModuleAuthoritySha256 -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$git.path), [IO.Path]::GetFullPath($PinnedGitPath)) -or
        [string]$git.sha256 -cne $PinnedGitSha256 -or
        $ToolchainProfileSha256 -cnotmatch '^[0-9a-f]{64}$' -or $ModuleAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or $PinnedGitSha256 -cnotmatch '^[0-9a-f]{64}$') { return $false }

    $command = $Document.command
    $targetPath = [IO.Path]::Combine([IO.Path]::GetFullPath($Repository), 'vita-agent', 'target')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $command @('argv', 'working_directory', 'manifest_path', 'target_directory')) -or
        -not (Test-D32BoundedCompilerDiagnosticFixedArgv $command.argv) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$command.working_directory), [IO.Path]::GetFullPath($Repository)) -or
        [string]$command.manifest_path -cne 'vita-agent/Cargo.toml' -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$command.target_directory), $targetPath)) { return $false }

    if (-not (Test-D32BoundedCompilerDiagnosticExactEnvironment -Environment $Document.child_environment -Expected $ExpectedEnvironment)) { return $false }

    $cargoHome = $Document.cargo_home
    $origin = $Document.dependency_origin
    $cargoFields = @('path', 'volume_serial_hex', 'file_id_hex')
    $originFields = @('path', 'volume_serial_hex', 'file_id_hex', 'historical_origin_candidate_sha', 'owner_record', 'blocked_diagnostic', 'protoc_run_grant', 'fetch_records', 'manifest_refs', 'registry_archive_root', 'registry_source_root', 'git_database_root', 'git_checkout_root', 'registry_archives', 'git_source_authority', 'git_content_refs')
    $requiredOrigin = 'E:\d32\inv7\r\c'
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $cargoHome $cargoFields) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $origin $originFields) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$cargoHome.path, $requiredOrigin) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.path, $requiredOrigin) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $cargoHome) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $origin) -or
        [string]$origin.historical_origin_candidate_sha -cne $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -or
        [string]$origin.historical_origin_candidate_sha -ceq [string]$Document.candidate_sha -or
        [string]$cargoHome.volume_serial_hex -cne [string]$origin.volume_serial_hex -or [string]$cargoHome.file_id_hex -cne [string]$origin.file_id_hex -or
        $origin.fetch_records -isnot [Array] -or $origin.fetch_records.Count -gt 3 -or
        $origin.manifest_refs -isnot [Array] -or $origin.manifest_refs.Count -ne 6 -or
        $origin.registry_archives -isnot [Array] -or $origin.registry_archives.Count -eq 0 -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.owner_record) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.blocked_diagnostic) -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.protoc_run_grant) -or
        $origin.git_content_refs -isnot [Array] -or $origin.git_content_refs.Count -eq 0 -or $origin.git_content_refs.Count -gt 16 -or
        ($null -ne $origin.git_source_authority -and -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $origin.git_source_authority)) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $origin.registry_archive_root @('path', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $origin.registry_archive_root) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $origin.registry_source_root @('path', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $origin.registry_source_root) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $origin.git_database_root @('path', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $origin.git_database_root) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $origin.git_checkout_root @('path', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $origin.git_checkout_root)) { return $false }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.registry_archive_root.path, (Join-Path $requiredOrigin 'registry/cache/index.crates.io-1949cf8c6b5b557f')) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.registry_source_root.path, (Join-Path $requiredOrigin 'registry/src/index.crates.io-1949cf8c6b5b557f')) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.git_database_root.path, (Join-Path $requiredOrigin 'git/db')) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$origin.git_checkout_root.path, (Join-Path $requiredOrigin 'git/checkouts'))) { return $false }
    foreach ($reference in $origin.fetch_records) { if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $reference)) { return $false } }
    foreach ($reference in $origin.manifest_refs) { if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $reference)) { return $false } }
    $seenGitContentSources = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($reference in $origin.git_content_refs) {
        if (-not (Test-D32BoundedCompilerDiagnosticGitContentReferenceShape $reference) -or -not $seenGitContentSources.Add([string]$reference.source)) { return $false }
    }

    $target = $Document.target
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $target @('path', 'volume_serial_hex', 'file_id_hex', 'source_sha256', 'build_owner_mode')) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$target.path), $targetPath) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $target) -or
        [string]$target.source_sha256 -cne $ExpectedCandidateSha -or
        [string]$target.build_owner_mode -cne 'EXCLUSIVE_INTEGRATION_BUILD_OWNER') { return $false }

    $output = $Document.output
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $output @('root_path', 'parent_path', 'parent_volume_serial_hex', 'parent_file_id_hex', 'temp_path', 'run_id')) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.root_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.parent_path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.temp_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$output.root_path), [string]$output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$output.temp_path, [IO.Path]::Combine([string]$output.root_path, 'temp')) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $output 'parent_volume_serial_hex' 'parent_file_id_hex') -or
        [string]$output.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.root_path $Repository) -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.root_path $requiredOrigin) -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.root_path $cargoHome.path)) { return $false }

    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.image_grants @('vctip', 'protoc'))) { return $false }
    foreach ($image in @($Document.image_grants.vctip, $Document.image_grants.protoc)) {
        if ($null -ne $image -and (-not (Test-D32BoundedCompilerDiagnosticExactProperties $image @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
            -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $image.path) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $image.bytes -Positive) -or
            [string]$image.sha256 -cnotmatch '^[0-9a-f]{64}$' -or -not (Test-D32BoundedCompilerDiagnosticIdentityPair $image))) { return $false }
    }
    if ($Document.source_pins -isnot [Array] -or $Document.source_pins.Count -ne 6) { return $false }
    $seenPins = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($pin in $Document.source_pins) {
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $pin) -or
            -not (Test-D32BoundedCompilerDiagnosticWithin $pin.path $Repository) -or -not $seenPins.Add([string]$pin.path)) { return $false }
    }
    try { $null = [DateTimeOffset]::Parse([string]$Document.issued_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
    catch { return $false }
    try { Assert-D32BoundedCompilerDiagnosticBudget -Budget $Document.resource_budget | Out-Null }
    catch { return $false }
    return $true
}

function Test-D32BoundedCompilerDiagnosticFetchEvidenceComplete {
    param([AllowNull()][object]$FetchRecords)
    if ($FetchRecords -isnot [Array] -or $FetchRecords.Count -ne 3) { return $false }
    foreach ($reference in $FetchRecords) {
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $reference)) { return $false }
    }
    return $true
}

function Test-D32BoundedCompilerDiagnosticExactEnvironment {
    param(
        [AllowNull()][object]$Environment,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Expected
    )
    if ($null -eq $Environment -or $Environment -is [string] -or $Environment -is [Array]) { return $false }
    $actual = [System.Collections.Generic.List[object]]::new()
    if ($Environment -is [System.Collections.IDictionary]) {
        foreach ($key in $Environment.Keys) { $actual.Add([PSCustomObject]@{ Name = [string]$key; Value = $Environment[$key] }) }
    }
    else { foreach ($property in $Environment.PSObject.Properties) { $actual.Add($property) } }
    if ($actual.Count -ne $Expected.Count) { return $false }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($property in $actual) {
        $name = [string]$property.Name
        if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$' -or -not $seen.Add($name) -or -not $Expected.Contains($name)) { return $false }
        if ($property.Value -isnot [string] -or [string]$property.Value -cne [string]$Expected[$name] -or
            [string]$property.Value -match '[\r\n\x00]' -or [string]$property.Value -match '(?i)https?://[^/@\s]+:[^/@\s]+@' -or
            $name -match '(?i)(token|password|secret|credential|authorization|api.?key)') { return $false }
    }
    foreach ($forbidden in @('HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_TARGET_DIR', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY')) {
        if ($seen.Contains($forbidden)) { return $false }
    }
    return $true
}

function Test-D32BoundedCompilerDiagnosticCanStart {
    param([AllowNull()][object]$RemainingMilliseconds, [AllowNull()][object]$Budget)
    $cleanupReserve = $script:D32BoundedCompilerDiagnosticCleanupReserveMilliseconds
    $persistReserve = $script:D32BoundedCompilerDiagnosticPersistReserveMilliseconds
    if ($null -ne $Budget) {
        try {
            Assert-D32BoundedCompilerDiagnosticBudget -Budget $Budget | Out-Null
            $cleanupReserve = [Int64]$Budget.cleanup_reserve_ms
            $persistReserve = [Int64]$Budget.persist_reserve_ms
        }
        catch { return $false }
    }
    return (Test-D32BoundedCompilerDiagnosticInteger $RemainingMilliseconds) -and
        [Int64]$RemainingMilliseconds -ge ($script:D32BoundedCompilerDiagnosticMaxCargoMilliseconds + $cleanupReserve + $persistReserve)
}

function Test-D32BoundedCompilerDiagnosticResourceStop {
    param(
        [AllowNull()][object]$Sample,
        [Parameter(Mandatory = $true)][bool]$MetricsReliable,
        [Parameter(Mandatory = $true)][bool]$AdmissionSucceeded,
        [Parameter(Mandatory = $true)][bool]$CaptureLimitReached,
        [Parameter(Mandatory = $true)][bool]$DeadlineReached
    )
    if (-not $AdmissionSucceeded -or -not $MetricsReliable -or $CaptureLimitReached -or $DeadlineReached) { return $true }
    if ($null -eq $Sample -or $Sample.Reliable -isnot [bool] -or -not [bool]$Sample.Reliable) { return $true }
    return ([Int64]$Sample.AvailablePhysicalBytes -lt (4L * 1024L * 1024L * 1024L) -or
        [Int64]$Sample.CommitHeadroomBytes -lt (2L * 1024L * 1024L * 1024L))
}

function Test-D32BoundedCompilerDiagnosticCleanupVerified {
    param([AllowNull()][object]$Cleanup)
    if ($null -eq $Cleanup) { return $false }
    return ([bool]$Cleanup.DebuggerThreadExited -and [bool]$Cleanup.DebuggerThreadJoined -and
        [bool]$Cleanup.RetainedProcessHandlesSignaled -and [bool]$Cleanup.DebuggerAssociationQueryVerified -and
        [bool]$Cleanup.DebuggerAssociationAbsent -and [bool]$Cleanup.JobActiveProcessCountVerified -and
        [uint32]$Cleanup.JobActiveProcessCount -eq 0 -and [bool]$Cleanup.JobCloseSucceeded -and [bool]$Cleanup.CleanupSucceeded)
}

function Get-D32BoundedCompilerDiagnosticSamplingSummary {
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
        sampling_stop_reason = $StopReason
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

function Test-D32BoundedCompilerDiagnosticTestBinaryNotStarted {
    param([AllowNull()][object[]]$CreatedProcessPaths, [AllowNull()][object[]]$ExecutableArtifactPaths, [Parameter(Mandatory = $true)][string]$TargetRoot)
    $dependencyExecutableRoot = Join-Path (Join-Path $TargetRoot 'debug') 'deps'
    foreach ($artifact in $ExecutableArtifactPaths) {
        if ($artifact -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$artifact)) { return $false }
        try { if (-not (Test-D32BoundedCompilerDiagnosticWithin -Child ([IO.Path]::GetFullPath([string]$artifact)) -Parent $TargetRoot)) { return $false } }
        catch { return $false }
        foreach ($created in $CreatedProcessPaths) {
            if ($created -isnot [string]) { return $false }
            try {
                $createdFull = [IO.Path]::GetFullPath([string]$created)
                $artifactFull = [IO.Path]::GetFullPath([string]$artifact)
                if ($createdFull.Equals($artifactFull, [StringComparison]::OrdinalIgnoreCase) -or
                    (Test-D32BoundedCompilerDiagnosticWithin -Child $createdFull -Parent $dependencyExecutableRoot)) { return $false }
            }
            catch { return $false }
        }
    }
    return $true
}

function ConvertFrom-D32BoundedDiagnosticLockStringArray {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Body,
        [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds,
        [int]$MaximumItems = 65536)
    if ($MaximumItems -lt 0 -or $MaximumItems -gt 65536) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: dependency-array item budget is outside its fixed 65536-edge ceiling' }
    $items = [System.Collections.Generic.List[string]]::new()
    $index = 0
    while ($index -lt $Body.Length) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'lock.dependency_array_parse' -Progress ("offset={0}/{1}" -f $index, $Body.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        while ($index -lt $Body.Length -and ($Body[$index] -eq ',' -or [char]::IsWhiteSpace($Body[$index]))) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'lock.dependency_array_whitespace' -Progress ("offset={0}/{1}" -f $index, $Body.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
            $index++
        }
        if ($index -ge $Body.Length) { break }
        if ($Body[$index] -cne '"') { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: dependency array has an unsupported TOML token' }
        $index++
        $value = [Text.StringBuilder]::new()
        $closed = $false
        while ($index -lt $Body.Length) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'lock.dependency_string_parse' -Progress ("offset={0}/{1}" -f $index, $Body.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
            $character = $Body[$index++]
            if ($character -ceq '"') { $closed = $true; break }
            if ($character -ceq '\') {
                if ($index -ge $Body.Length) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: truncated TOML string escape' }
                $escape = $Body[$index++]
                if ($escape -cnotin @('"', '\', 'n', 'r', 't')) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: unsupported dependency-string escape' }
                $character = switch ($escape) { 'n' { [char]10 } 'r' { [char]13 } 't' { [char]9 } default { $escape } }
            }
            [void]$value.Append($character)
        }
        if (-not $closed) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: unterminated dependency string' }
        if ($items.Count -ge $MaximumItems) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: Cargo.lock dependency edges exceed their fixed aggregate 65536-entry limit' }
        $items.Add($value.ToString())
        while ($index -lt $Body.Length -and [char]::IsWhiteSpace($Body[$index])) { $index++ }
        if ($index -lt $Body.Length -and $Body[$index] -cne ',') { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: dependency array separator is unsupported' }
    }
    return $items.ToArray()
}

function ConvertFrom-D32BoundedDiagnosticLockDependencySpec {
    param([Parameter(Mandatory = $true)][string]$Value)
    $match = [regex]::Match($Value, '^(?<name>[A-Za-z0-9_-]+)(?: (?<version>[0-9][0-9A-Za-z.+_-]*))?(?: \((?<source>[^()\r\n]+)\))?$')
    if (-not $match.Success) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: dependency edge identity is outside the supported finite Cargo.lock format' }
    return [PSCustomObject][ordered]@{
        raw = $Value
        name = [string]$match.Groups['name'].Value
        version = if ($match.Groups['version'].Success) { [string]$match.Groups['version'].Value } else { $null }
        source = if ($match.Groups['source'].Success) { [string]$match.Groups['source'].Value } else { $null }
    }
}

function Get-D32BoundedCompilerDiagnosticLockSources {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$LockText,
        [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds)
    if ($LockText.Length -le 0 -or $LockText.Length -gt 8388608) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: finite Cargo.lock input is empty or exceeds 8 MiB' }
    $packages = [System.Collections.Generic.List[object]]::new()
    $current = $null
    $collectingEdges = $false
    $lockVersion = $null
    $totalEdgeTextCount = 0
    $lineIndex = 0
    $lineStart = 0
    while ($lineStart -le $LockText.Length) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'lock.line_parse' -Progress ("lines={0}" -f $lineIndex) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $lineEnd = $LockText.IndexOf("`n", $lineStart)
        $hasLineFeed = ($lineEnd -ge 0)
        if (-not $hasLineFeed) { $lineEnd = $LockText.Length }
        $rawLength = $lineEnd - $lineStart
        if ($hasLineFeed -and $rawLength -gt 0 -and $LockText[$lineEnd - 1] -ceq "`r") { $rawLength-- }
        $line = $LockText.Substring($lineStart, $rawLength)
        $lineStart = if ($hasLineFeed) { $lineEnd + 1 } else { $LockText.Length + 1 }
        $lineIndex++
        if ($line -cmatch '^\[\[package\]\]$') {
            if ($collectingEdges) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: truncated Cargo.lock dependency array before the next package' }
            if ($null -ne $current) { $packages.Add($current) }
            if ($packages.Count -gt 2048) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: Cargo.lock package count exceeds its fixed 2048-entry limit' }
            $current = [ordered]@{ name = $null; version = $null; source = $null; checksum = $null; dependency_text = $null; dependency_lines = $null; dependencies = @() }
            continue
        }
        if ($null -eq $current) {
            $rootLine = $line.Trim()
            if ([String]::IsNullOrWhiteSpace($rootLine) -or $rootLine.StartsWith('#')) { continue }
            if ($rootLine -cmatch '^version\s*=\s*([0-9]+)\s*$') {
                if ($null -ne $lockVersion -or [int]$Matches[1] -notin @(3, 4)) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: Cargo.lock version is duplicated or outside the finite supported v3/v4 formats' }
                $lockVersion = [int]$Matches[1]
                continue
            }
            throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: unsupported Cargo.lock root statement or table before package catalog'
        }
        if ($collectingEdges) {
            if ($current.dependency_lines.Count -ge 65536) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: one multiline dependency array exceeds the fixed 65536-line parser bound' }
            $current.dependency_lines.Add([string]$line)
            if ($line -match '\]') {
                $dependencyText = [string]::Join("`n", [string[]]$current.dependency_lines.ToArray())
                $close = $dependencyText.LastIndexOf(']')
                if ($close -lt 0 -or -not [String]::IsNullOrWhiteSpace($dependencyText.Substring($close + 1))) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: dependency array tail is unsupported' }
                $body = $dependencyText.Substring(0, $close)
                $current.dependencies = @(ConvertFrom-D32BoundedDiagnosticLockStringArray -Body $body -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -MaximumItems ([Math]::Max(0, 65536 - $totalEdgeTextCount)))
                $totalEdgeTextCount += $current.dependencies.Count
                if ($totalEdgeTextCount -gt 65536) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: Cargo.lock dependency edge count exceeds its fixed 65536-entry limit' }
                $collectingEdges = $false
                $current.dependency_lines = $null
            }
            continue
        }
        if ([String]::IsNullOrWhiteSpace($line) -or $line.Trim().StartsWith('#')) { continue }
        if ($line -cmatch '^name\s*=\s*"([^"\\]+)"\s*$') { if ($null -ne $current.name) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: duplicate package name field' }; $current.name = [string]$Matches[1]; continue }
        if ($line -cmatch '^version\s*=\s*"([^"\\]+)"\s*$') { if ($null -ne $current.version) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: duplicate package version field' }; $current.version = [string]$Matches[1]; continue }
        if ($line -cmatch '^source\s*=\s*"([^"\\]+)"\s*$') { if ($null -ne $current.source) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: duplicate package source field' }; $current.source = [string]$Matches[1]; continue }
        if ($line -cmatch '^checksum\s*=\s*"([^"\\]+)"\s*$') { if ($null -ne $current.checksum) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: duplicate package checksum field' }; $current.checksum = [string]$Matches[1]; continue }
        if ($line -cmatch '^dependencies\s*=\s*\[(.*)$') {
            if ($null -ne $current.dependency_text) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: duplicate package dependency array' }
            $current.dependency_text = [string]$Matches[1]
            if ($current.dependency_text -match '\]') {
                $close = $current.dependency_text.LastIndexOf(']')
                if (-not [String]::IsNullOrWhiteSpace($current.dependency_text.Substring($close + 1))) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: dependency array tail is unsupported' }
                $current.dependencies = @(ConvertFrom-D32BoundedDiagnosticLockStringArray -Body $current.dependency_text.Substring(0, $close) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -MaximumItems ([Math]::Max(0, 65536 - $totalEdgeTextCount)))
                $totalEdgeTextCount += $current.dependencies.Count
                if ($totalEdgeTextCount -gt 65536) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: Cargo.lock dependency edge count exceeds its fixed 65536-entry limit' }
            }
            else { $current.dependency_lines = [System.Collections.Generic.List[string]]::new(); $current.dependency_lines.Add([string]$current.dependency_text); $collectingEdges = $true }
            continue
        }
        throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: package record contains an unsupported or malformed Cargo.lock field/table'
    }
    if ($collectingEdges) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: unterminated Cargo.lock dependency array' }
    if ($null -ne $current) { $packages.Add($current) }
    if ($null -eq $lockVersion -or $packages.Count -eq 0 -or $packages.Count -gt 2048) { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: finite Cargo.lock requires one supported version and a bounded nonempty package catalog' }
    $output = [System.Collections.Generic.List[object]]::new()
    $packageIndex = 0
    foreach ($package in $packages) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'lock.package_normalize' -Progress ("packages={0}/{1}" -f $packageIndex, $packages.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $packageIndex++
        if ([String]::IsNullOrWhiteSpace([string]$package.name) -or [string]$package.name -notmatch '^[A-Za-z0-9_-]+$' -or
            [String]::IsNullOrWhiteSpace([string]$package.version) -or [string]$package.version -notmatch '^[0-9A-Za-z.+_-]+$') {
            throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: Cargo.lock package identity is malformed'
        }
        $sourceKind = $null
        $commit = $null
        if ($null -ne $package.source -and [string]$package.source -like 'registry+*') {
            if ([string]$package.checksum -cnotmatch '^[0-9a-f]{64}$') { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: locked registry package lacks its exact SHA-256 checksum' }
            $sourceKind = 'registry'
        }
        elseif ($null -ne $package.source -and [string]$package.source -like 'git+*') {
            $gitMatch = [regex]::Match([string]$package.source, '#([0-9a-f]{40})$')
            if (-not $gitMatch.Success -or [string]$package.checksum -ne '') { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: locked Git package source/commit is incomplete' }
            $sourceKind = 'git'
            $commit = [string]$gitMatch.Groups[1].Value
        }
        elseif ($null -eq $package.source -and $null -eq $package.checksum) { $sourceKind = 'workspace' }
        else { throw 'D32_BOUNDED_DIAGNOSTIC_LOCK_BLOCKED: Cargo.lock source kind is unsupported or incomplete' }
        $sourceIdentity = if ($null -eq $package.source) { 'workspace' } else { [string]$package.source }
        $id = [string]$package.name + '@' + [string]$package.version + '|' + $sourceKind + '|' + $sourceIdentity
        $edgeSpecs = [System.Collections.Generic.List[object]]::new()
        $dependencyIndex = 0
        foreach ($dependencyText in $package.dependencies) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'lock.dependency_specs' -Progress ("package={0};dependencies={1}" -f $package.name, $dependencyIndex) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
            $dependencyIndex++
            $edgeSpecs.Add((ConvertFrom-D32BoundedDiagnosticLockDependencySpec -Value ([string]$dependencyText)))
        }
        $output.Add([PSCustomObject][ordered]@{
            package_id = $id; name = [string]$package.name; version = [string]$package.version; source = $package.source
            source_kind = $sourceKind; checksum = $package.checksum; commit = $commit; dependency_specs = @($edgeSpecs.ToArray()); dependency_ids = @()
        })
    }
    return $output.ToArray()
}

function Get-D32BoundedCompilerDiagnosticSourcePlan {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$LockText,
        [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds)
    $maxLockCharacters = 8388608
    $maxLockedPackages = 2048
    $maxRegistryPackages = 1536
    $maxGitSources = 16
    if ($LockText.Length -le 0 -or $LockText.Length -gt $maxLockCharacters) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: lock input is empty or exceeds its fixed 8 MiB text bound' }
    $packages = @(Get-D32BoundedCompilerDiagnosticLockSources -LockText $LockText -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds)
    if ($packages.Count -eq 0 -or $packages.Count -gt $maxLockedPackages) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: locked package inventory is empty or exceeds its fixed 2048-entry bound' }
    $catalog = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $packagesByName = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]]::new([StringComparer]::Ordinal)
    $packagesByNameVersion = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]]::new([StringComparer]::Ordinal)
    $packagesByNameSource = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]]::new([StringComparer]::Ordinal)
    $packagesByExactDependencyIdentity = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $packageIndex = 0
    foreach ($package in $packages) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.index_packages' -Progress ("packages={0}/{1}" -f $packageIndex, $packages.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $packageIndex++
        if (-not $catalog.TryAdd([string]$package.package_id, $package)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: duplicate full Cargo.lock package identity' }
        if (-not $packagesByName.ContainsKey([string]$package.name)) { $packagesByName.Add([string]$package.name, [System.Collections.Generic.List[object]]::new()) }
        $packagesByName[[string]$package.name].Add($package)
        $nameVersionKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@([string]$package.name, [string]$package.version))
        if (-not $packagesByNameVersion.ContainsKey($nameVersionKey)) { $packagesByNameVersion.Add($nameVersionKey, [System.Collections.Generic.List[object]]::new()) }
        $packagesByNameVersion[$nameVersionKey].Add($package)
        $nameSourceKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@([string]$package.name, [string]$package.source))
        if (-not $packagesByNameSource.ContainsKey($nameSourceKey)) { $packagesByNameSource.Add($nameSourceKey, [System.Collections.Generic.List[object]]::new()) }
        $packagesByNameSource[$nameSourceKey].Add($package)
        $exactKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@([string]$package.name, [string]$package.version, [string]$package.source))
        if (-not $packagesByExactDependencyIdentity.TryAdd($exactKey, $package)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: duplicate exact dependency name/version/source identity' }
    }
    $edges = [System.Collections.Generic.List[object]]::new()
    $packageIndex = 0
    foreach ($package in $packages) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.resolve_dependencies' -Progress ("packages={0}/{1};edges={2}" -f $packageIndex, $packages.Count, $edges.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $packageIndex++
        $targets = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $dependencyIndex = 0
        foreach ($spec in $package.dependency_specs) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.resolve_edge' -Progress ("package={0};dependencies={1}" -f $package.package_id, $dependencyIndex) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
            $dependencyIndex++
            $candidates = $null
            if ($null -ne $spec.version -and $null -ne $spec.source) {
                $exactKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@([string]$spec.name, [string]$spec.version, [string]$spec.source))
                $exactPackage = $null
                if (-not $packagesByExactDependencyIdentity.TryGetValue($exactKey, [ref]$exactPackage)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: exact Cargo.lock dependency edge does not resolve to an audited package identity' }
                $candidates = [System.Collections.Generic.List[object]]::new(1)
                $candidates.Add($exactPackage)
            }
            elseif ($null -ne $spec.version) {
                $nameVersionKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@([string]$spec.name, [string]$spec.version))
                if (-not $packagesByNameVersion.TryGetValue($nameVersionKey, [ref]$candidates)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: versioned Cargo.lock dependency edge does not resolve to an audited package identity' }
            }
            elseif ($null -ne $spec.source) {
                $nameSourceKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@([string]$spec.name, [string]$spec.source))
                if (-not $packagesByNameSource.TryGetValue($nameSourceKey, [ref]$candidates)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: sourced Cargo.lock dependency edge does not resolve to an audited package identity' }
            }
            elseif (-not $packagesByName.TryGetValue([string]$spec.name, [ref]$candidates)) {
                throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: Cargo.lock dependency edge does not resolve to exactly one audited package ID'
            }
            $target = $null
            $matchCount = 0
            foreach ($candidate in $candidates) {
                if (($null -eq $spec.version -or [string]$candidate.version -ceq [string]$spec.version) -and
                    ($null -eq $spec.source -or [string]$candidate.source -ceq [string]$spec.source)) { $target = $candidate; $matchCount++ }
            }
            if ($matchCount -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: Cargo.lock dependency edge does not resolve to exactly one audited package ID' }
            if (-not $targets.Add([string]$target.package_id)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: duplicate dependency edge target is unsupported' }
            $edges.Add([PSCustomObject][ordered]@{ parent_package_id = [string]$package.package_id; target_package_id = [string]$target.package_id; lock_spec = [string]$spec.raw })
        }
        $targetIds = [string[]]@($targets)
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.sort_target_ids' -Progress ("package={0};targets={1}" -f $package.package_id, $targetIds.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
        [Array]::Sort($targetIds, [StringComparer]::Ordinal)
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.sort_target_ids_complete' -Progress ("package={0};targets={1}" -f $package.package_id, $targetIds.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
        $package.dependency_ids = @($targetIds)
    }
    $cargoHome = 'E:\d32\inv7\r\c'
    $registryIndex = 'index.crates.io-1949cf8c6b5b557f'
    $registryCache = Join-Path $cargoHome ('registry/cache/' + $registryIndex)
    $registrySource = Join-Path $cargoHome ('registry/src/' + $registryIndex)
    $registryRows = [System.Collections.Generic.List[object]]::new()
    $gitBySource = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $packageKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pathKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $packageIndex = 0
    foreach ($package in $packages) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.map_source_rows' -Progress ("packages={0}/{1}" -f $packageIndex, $packages.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $packageIndex++
        if ($package.source_kind -ceq 'registry') {
            if ([string]$package.source -cne 'registry+https://github.com/rust-lang/crates.io-index') { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: non-crates.io registry source is outside the approved finite origin' }
            $key = [string]$package.name + [char]0 + [string]$package.version
            if (-not $packageKeys.Add($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: duplicate locked registry name/version tuple' }
            $archivePath = [IO.Path]::GetFullPath((Join-Path $registryCache ([string]$package.name + '-' + [string]$package.version + '.crate')))
            $sourcePath = [IO.Path]::GetFullPath((Join-Path $registrySource ([string]$package.name + '-' + [string]$package.version)))
            if (-not $pathKeys.Add($archivePath) -or -not $pathKeys.Add($sourcePath)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: case-insensitive registry path collision' }
            $registryRows.Add([PSCustomObject][ordered]@{ package_id = $package.package_id; name = $package.name; version = $package.version; checksum = $package.checksum; source = $package.source; archive_path = $archivePath; extracted_source_path = $sourcePath })
        }
        elseif ($package.source_kind -ceq 'git') {
            $source = [string]$package.source
            $match = [regex]::Match($source, '^git\+(https://[^?#@\s]+(?:\?[^#\r\n]+)?)#([0-9a-f]{40})$')
            if (-not $match.Success -or [string]$match.Groups[2].Value -cne [string]$package.commit) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: Git source must be an immutable HTTPS URL plus the same full lowercase 40-hex lock commit' }
            $url = [string]$match.Groups[1].Value
            $parsedUrl = $null
            if (-not [Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$parsedUrl) -or $parsedUrl.Scheme -cne 'https' -or [String]::IsNullOrEmpty($parsedUrl.Host) -or -not [String]::IsNullOrEmpty($parsedUrl.UserInfo)) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: Git source URL is not an absolute credential-free HTTPS URL' }
            $query = if ($url.Contains('?')) { $url.Substring($url.IndexOf('?') + 1) } else { '' }
            if ($query -cnotmatch ('(?:^|&)rev=' + [regex]::Escape([string]$package.commit) + '(?:&|$)')) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: Git source query does not pin the exact full commit with rev=' }
            if (-not $gitBySource.ContainsKey($source)) {
                $gitBySource.Add($source, [PSCustomObject][ordered]@{ source = $source; url = $url; commit = [string]$package.commit; database_root = [IO.Path]::GetFullPath((Join-Path $cargoHome 'git/db')); checkout_root = [IO.Path]::GetFullPath((Join-Path $cargoHome 'git/checkouts')) })
            }
        }
        elseif ($package.source_kind -cne 'workspace') { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: lock contains an unapproved source kind' }
    }
    if ($registryRows.Count -gt $maxRegistryPackages -or $gitBySource.Count -gt $maxGitSources) { throw 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PLAN_BLOCKED: registry or Git tuple count exceeds its fixed finite bound' }
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.sort_registry_rows' -Progress ("rows={0}" -f $registryRows.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
    $registryRows.Sort([System.Comparison[object]]{ param($a, $b) [StringComparer]::Ordinal.Compare(([string]$a.name + [char]0 + [string]$a.version), ([string]$b.name + [char]0 + [string]$b.version)) })
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.sort_registry_rows_complete' -Progress ("rows={0}" -f $registryRows.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
    $gitRows = [System.Collections.Generic.List[object]]::new()
    foreach ($source in @($gitBySource.Keys | Sort-Object -CaseSensitive)) { $gitRows.Add($gitBySource[$source]) }
    $registryCanonical = [System.Collections.Generic.List[string]]::new()
    $canonicalIndex = 0
    foreach ($row in $registryRows) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.registry_rows' -Progress ("rows={0}/{1}" -f $canonicalIndex, $registryRows.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $registryCanonical.Add(('registry' + [char]9 + $row.name + [char]9 + $row.version + [char]9 + $row.checksum)); $canonicalIndex++
    }
    $gitCanonical = [System.Collections.Generic.List[string]]::new()
    $canonicalIndex = 0
    foreach ($row in $gitRows) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.git_rows' -Progress ("rows={0}/{1}" -f $canonicalIndex, $gitRows.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $gitCanonical.Add(('git' + [char]9 + $row.url + [char]9 + $row.commit)); $canonicalIndex++
    }
    $edgeCanonical = [System.Collections.Generic.List[string]]::new()
    $canonicalIndex = 0
    foreach ($edge in $edges) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.edge_rows' -Progress ("rows={0}/{1}" -f $canonicalIndex, $edges.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' -NoProgress }
        $edgeCanonical.Add(([string]$edge.parent_package_id + [char]9 + [string]$edge.target_package_id + [char]9 + [string]$edge.lock_spec)); $canonicalIndex++
    }
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.sort_edges' -Progress ("rows={0}" -f $edgeCanonical.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
    $edgeCanonical.Sort([StringComparer]::Ordinal)
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.sort_edges_complete' -Progress ("rows={0}" -f $edgeCanonical.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
    $utf8 = [Text.UTF8Encoding]::new($false)
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_plan.digests' -Progress ("packages={0};edges={1}" -f $packages.Count, $edges.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED' }
    $registryDigest = Get-D32BoundedDiagnosticSha256FromLines -Lines ([string[]]$registryCanonical.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'source_plan.registry_digest'
    $gitDigest = Get-D32BoundedDiagnosticSha256FromLines -Lines ([string[]]$gitCanonical.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'source_plan.git_digest'
    $edgeDigest = Get-D32BoundedDiagnosticSha256FromLines -Lines ([string[]]$edgeCanonical.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'source_plan.edge_digest'
    $lockDigest = Get-D32BoundedDiagnosticSha256FromBytes -Bytes ($utf8.GetBytes($LockText)) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'source_plan.lock_digest'
    return [PSCustomObject][ordered]@{
        schema_version = 2; record_type = 'D32_BOUNDED_DIAGNOSTIC_LOCK_SOURCE_PLAN_V2'; gate_authority = 'NONE'; verification_status = 'NOT_RUN'
        semantic_scope = 'FULL_LOCK_AUDIT_CATALOG_PLUS_SELECTED_REACHABLE_CONSERVATIVE_SUPERSET'
        cargo_home = $cargoHome; target_triple = 'x86_64-pc-windows-msvc'; host_triple = 'x86_64-pc-windows-msvc'
        lock_bytes = [Int64]$utf8.GetByteCount($LockText); lock_sha256 = $lockDigest
        locked_package_count = [Int64]$packages.Count; locked_packages = @($packages)
        lock_dependency_edge_count = [Int64]$edges.Count; lock_dependency_edges = @($edges.ToArray()); lock_dependency_edges_sha256 = $edgeDigest
        registry_package_count = [Int64]$registryRows.Count; registry_tuple_sha256 = $registryDigest
        registry_archive_root = [IO.Path]::GetFullPath($registryCache); registry_source_root = [IO.Path]::GetFullPath($registrySource); registry_packages = @($registryRows.ToArray())
        git_source_count = [Int64]$gitRows.Count; git_tuple_sha256 = $gitDigest; git_sources = @($gitRows.ToArray())
        selected_roots = @(); selected_root_rule = 'NOT_RESOLVED_WITHOUT_PINNED_MANIFEST'; requested_features = @('default', 'd32-a-test-helper')
        verifier_managed_buffer_cap_bytes = [Int64]$script:D32BoundedCompilerDiagnosticSourceWorkingBufferLimitBytes; source_proof_status = 'NOT_VERIFIED'
    }
}

function Split-D32BoundedDiagnosticTopLevel {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text, [char]$Separator = ',',
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds,
        [int]$MaximumParts = 65536)
    if ($MaximumParts -le 0 -or $MaximumParts -gt 65536) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: TOML split part bound is invalid' }
    $parts = [System.Collections.Generic.List[string]]::new()
    $start = 0; $depthSquare = 0; $depthCurly = 0; $depthParen = 0; $quote = [char]0; $escaped = $false
    for ($i = 0; $i -lt $Text.Length; $i++) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest.split_top_level' -Progress ("offset={0}/{1}" -f $i, $Text.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED' -NoProgress }
        $ch = $Text[$i]
        if ($quote -ne [char]0) {
            if ($quote -ceq '"' -and $escaped) { $escaped = $false; continue }
            if ($quote -ceq '"' -and $ch -ceq '\\') { $escaped = $true; continue }
            if ($ch -ceq $quote) { $quote = [char]0 }
            continue
        }
        if ($ch -ceq '"' -or $ch -ceq "'") { $quote = $ch; continue }
        if ($ch -ceq '[') { $depthSquare++; continue }
        if ($ch -ceq ']') { $depthSquare--; if ($depthSquare -lt 0) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unbalanced TOML array' }; continue }
        if ($ch -ceq '{') { $depthCurly++; continue }
        if ($ch -ceq '}') { $depthCurly--; if ($depthCurly -lt 0) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unbalanced TOML inline table' }; continue }
        if ($ch -ceq '(') { $depthParen++; continue }
        if ($ch -ceq ')') { $depthParen--; if ($depthParen -lt 0) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unbalanced cfg parenthesis' }; continue }
        if ($ch -ceq $Separator -and $depthSquare -eq 0 -and $depthCurly -eq 0 -and $depthParen -eq 0) {
            if ($parts.Count -ge $MaximumParts) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: TOML split exceeds the fixed per-value part bound' }
            $parts.Add($Text.Substring($start, $i - $start).Trim()); $start = $i + 1
        }
    }
    if ($quote -ne [char]0 -or $depthSquare -ne 0 -or $depthCurly -ne 0 -or $depthParen -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: TOML value has unbalanced string/container delimiters' }
    if ($start -lt $Text.Length -or $Text.Length -eq 0) {
        if ($parts.Count -ge $MaximumParts) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: TOML split exceeds the fixed per-value part bound' }
        $parts.Add($Text.Substring($start).Trim())
    }
    return $parts.ToArray()
}

function Remove-D32BoundedDiagnosticTomlComment {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds)
    $quote = [char]0; $escaped = $false
    for ($i = 0; $i -lt $Line.Length; $i++) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest.strip_comment' -Progress ("offset={0}/{1}" -f $i, $Line.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED' -NoProgress }
        $ch = $Line[$i]
        if ($quote -ne [char]0) {
            if ($quote -ceq '"' -and $escaped) { $escaped = $false; continue }
            if ($quote -ceq '"' -and $ch -ceq '\\') { $escaped = $true; continue }
            if ($ch -ceq $quote) { $quote = [char]0 }
            continue
        }
        if ($ch -ceq '"' -or $ch -ceq "'") { $quote = $ch; continue }
        if ($ch -ceq '#') { return $Line.Substring(0, $i) }
    }
    return $Line
}

function ConvertFrom-D32BoundedDiagnosticTomlString {
    param([Parameter(Mandatory = $true)][string]$Text,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds)
    $value = $Text.Trim()
    if ($value.Length -lt 2 -or ($value[0] -cne '"' -and $value[0] -cne "'") -or $value[$value.Length - 1] -cne $value[0]) {
        throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: expected a bounded TOML string'
    }
    $quote = $value[0]; $result = [Text.StringBuilder]::new()
    for ($i = 1; $i -lt ($value.Length - 1); $i++) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest.decode_string' -Progress ("offset={0}/{1}" -f $i, $value.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED' -NoProgress }
        $ch = $value[$i]
        if ($quote -ceq '"' -and $ch -ceq '\\') {
            $i++; if ($i -ge ($value.Length - 1)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: truncated TOML string escape' }
            $escape = $value[$i]
            $decoded = switch ($escape) {
                '"' { '"' } '\\' { '\\' } 'n' { [char]10 } 'r' { [char]13 } 't' { [char]9 } 'b' { [char]8 } 'f' { [char]12 }
                default { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unsupported TOML string escape' }
            }
            [void]$result.Append($decoded); continue
        }
        [void]$result.Append($ch)
    }
    return $result.ToString()
}

function ConvertFrom-D32BoundedDiagnosticCargoValue {
    param([Parameter(Mandatory = $true)][string]$Text,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds,
        [int]$Depth = 0,
        [System.Collections.IDictionary]$ValueNodeBudget)
    if ($Depth -lt 0 -or $Depth -gt 64) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: TOML value nesting exceeds the fixed 64-level parser stack bound' }
    if ($null -eq $ValueNodeBudget) { $ValueNodeBudget = [ordered]@{ nodes = 0L; maximum = [Int64]$script:D32BoundedDiagnosticManifestValueNodeLimit } }
    if (-not $ValueNodeBudget.Contains('nodes') -or -not $ValueNodeBudget.Contains('maximum') -or
        [Int64]$ValueNodeBudget.maximum -le 0 -or [Int64]$ValueNodeBudget.maximum -gt [Int64]$script:D32BoundedDiagnosticManifestValueNodeLimit) {
        throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: aggregate TOML value-node budget is invalid'
    }
    if ([Int64]$ValueNodeBudget.nodes -ge [Int64]$ValueNodeBudget.maximum) {
        throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: aggregate TOML value-node budget reached its fixed in-memory cap'
    }
    $ValueNodeBudget.nodes = [Int64]$ValueNodeBudget.nodes + 1L
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest.value_depth' -Progress ("depth={0}" -f $Depth) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED' }
    $value = $Text.Trim()
    if ($value.Length -ge 2 -and (($value[0] -ceq '"' -and $value[$value.Length - 1] -ceq '"') -or ($value[0] -ceq "'" -and $value[$value.Length - 1] -ceq "'"))) {
        return [PSCustomObject]@{ kind = 'string'; value = (ConvertFrom-D32BoundedDiagnosticTomlString -Text $value -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds) }
    }
    if ($value -ceq 'true' -or $value -ceq 'false') { return [PSCustomObject]@{ kind = 'bool'; value = ($value -ceq 'true') } }
    if ($value.StartsWith('[') -and $value.EndsWith(']')) {
        $items = [System.Collections.Generic.List[string]]::new()
        $inner = $value.Substring(1, $value.Length - 2)
        foreach ($part in (Split-D32BoundedDiagnosticTopLevel -Text $inner -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -MaximumParts 65536)) {
            if ([String]::IsNullOrWhiteSpace($part)) { continue }
            $parsed = ConvertFrom-D32BoundedDiagnosticCargoValue -Text $part -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Depth ($Depth + 1) -ValueNodeBudget $ValueNodeBudget
            if ([string]$parsed.kind -cne 'string') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: only bounded string arrays are supported in dependency metadata' }
            $items.Add([string]$parsed.value)
        }
        return [PSCustomObject]@{ kind = 'array'; value = @($items.ToArray()) }
    }
    if ($value.StartsWith('{') -and $value.EndsWith('}')) {
        $map = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
        $inner = $value.Substring(1, $value.Length - 2)
        foreach ($part in (Split-D32BoundedDiagnosticTopLevel -Text $inner -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -MaximumParts 65536)) {
            if ([String]::IsNullOrWhiteSpace($part)) { continue }
            $assignment = [regex]::Match($part, '^\s*(?<key>[A-Za-z0-9_-]+)\s*=\s*(?<value>.+?)\s*$')
            if (-not $assignment.Success) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unsupported inline-table field syntax' }
            $key = [string]$assignment.Groups['key'].Value
            if ($map.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate inline-table field' }
            $map.Add($key, (ConvertFrom-D32BoundedDiagnosticCargoValue -Text ([string]$assignment.Groups['value'].Value) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Depth ($Depth + 1) -ValueNodeBudget $ValueNodeBudget))
        }
        return [PSCustomObject]@{ kind = 'table'; value = $map }
    }
    throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unsupported TOML value in the finite dependency parser'
}

function Test-D32BoundedDiagnosticTomlStatementComplete {
    param([Parameter(Mandatory = $true)][string]$Text,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds)
    $square = 0; $curly = 0; $quote = [char]0; $escaped = $false
    for ($i = 0; $i -lt $Text.Length; $i++) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest.statement_check' -Progress ("offset={0}/{1}" -f $i, $Text.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED' -NoProgress }
        $ch = $Text[$i]
        if ($quote -ne [char]0) {
            if ($quote -ceq '"' -and $escaped) { $escaped = $false; continue }
            if ($quote -ceq '"' -and $ch -ceq '\\') { $escaped = $true; continue }
            if ($ch -ceq $quote) { $quote = [char]0 }
            continue
        }
        if ($ch -ceq '"' -or $ch -ceq "'") { $quote = $ch; continue }
        if ($ch -ceq '[') { $square++ } elseif ($ch -ceq ']') { $square-- } elseif ($ch -ceq '{') { $curly++ } elseif ($ch -ceq '}') { $curly-- }
        if ($square -lt 0 -or $curly -lt 0) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: TOML statement has unbalanced delimiters' }
    }
    return ($quote -eq [char]0 -and $square -eq 0 -and $curly -eq 0)
}

function Update-D32BoundedDiagnosticTomlStatementState {
    param([Parameter(Mandatory = $true)][string]$Line,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$State,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds)
    for ($i = 0; $i -lt $Line.Length; $i++) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest.statement_incremental' -Progress ("offset={0}/{1}" -f $i, $Line.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED' -NoProgress }
        $ch = $Line[$i]
        if ([char]$State.quote -ne [char]0) {
            if ([char]$State.quote -ceq '"' -and [bool]$State.escaped) { $State.escaped = $false; continue }
            if ([char]$State.quote -ceq '"' -and $ch -ceq '\\') { $State.escaped = $true; continue }
            if ($ch -ceq [char]$State.quote) { $State.quote = [char]0 }
            continue
        }
        if ($ch -ceq '"' -or $ch -ceq "'") { $State.quote = $ch; continue }
        if ($ch -ceq '[') { $State.square = [int]$State.square + 1 }
        elseif ($ch -ceq ']') { $State.square = [int]$State.square - 1 }
        elseif ($ch -ceq '{') { $State.curly = [int]$State.curly + 1 }
        elseif ($ch -ceq '}') { $State.curly = [int]$State.curly - 1 }
        if ([int]$State.square -lt 0 -or [int]$State.curly -lt 0) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: TOML statement has unbalanced delimiters' }
    }
    return ([char]$State.quote -eq [char]0 -and [int]$State.square -eq 0 -and [int]$State.curly -eq 0)
}

function ConvertFrom-D32BoundedDiagnosticCargoManifest {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text, [string]$SourcePath = '',
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds,
        [System.Collections.IDictionary]$ValueNodeBudget)
    if ($Text.Length -le 0 -or [Text.Encoding]::UTF8.GetByteCount($Text) -gt 1048576 -or $Text.Contains("`0")) {
        throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: manifest is empty or exceeds the 1 MiB finite input bound'
    }
    $section = 'other'; $targetCondition = ''; $nestedAlias = ''; $nestedKind = 'dependencies'; $nestedKey = ''
    $pendingBuilder = [Text.StringBuilder]::new(); $pendingActive = $false
    $statementState = [ordered]@{ square = 0; curly = 0; quote = [char]0; escaped = $false }
    $package = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $workspace = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $workspacePackage = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $dependencies = [System.Collections.Generic.List[object]]::new(); $workspaceDependencies = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $features = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal); $patches = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $nestedDeps = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    if ($null -eq $ValueNodeBudget) { $ValueNodeBudget = [ordered]@{ nodes = 0L; maximum = [Int64]$script:D32BoundedDiagnosticManifestValueNodeLimit } }
    $workspaceRootSeen = $false
    $lineNumber = 0; $sourceOffset = 0L; $lineStart = 0
    while ($lineStart -le $Text.Length) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest.lines' -Progress ("line={0};offset={1}/{2}" -f $lineNumber, $sourceOffset, $Text.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED' -NoProgress }
        $lineEnd = $Text.IndexOf("`n", $lineStart)
        $hasLineFeed = ($lineEnd -ge 0)
        if (-not $hasLineFeed) { $lineEnd = $Text.Length }
        $rawLength = $lineEnd - $lineStart
        if ($rawLength -gt 0 -and $Text[$lineEnd - 1] -ceq "`r") { $rawLength-- }
        $rawLine = $Text.Substring($lineStart, $rawLength)
        $sourceOffset = [Int64]$lineEnd + [Int64][int]$hasLineFeed
        $lineNumber++
        if ($hasLineFeed) { $lineStart = $lineEnd + 1 } else { $lineStart = $Text.Length + 1 }
        $line = (Remove-D32BoundedDiagnosticTomlComment -Line $rawLine -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds).Trim()
        if ([String]::IsNullOrWhiteSpace($line)) { continue }
        if (-not $pendingActive -and $line.StartsWith('[')) {
            if ($line -match '^\[\[.*\]\]$') { $section = 'other'; $targetCondition = ''; $nestedAlias = ''; $nestedKey = ''; continue }
            if ($line -notmatch '^\[(?<body>[^\[\]]+)\]$') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unsupported TOML table header' }
            $body = [string]$Matches['body']; $section = 'other'; $targetCondition = ''; $nestedAlias = ''; $nestedKey = ''; $nestedKind = 'dependencies'
            switch -Regex ($body) {
                '^package$' { $section = 'package'; break }
                '^workspace$' { $section = 'workspace'; $workspaceRootSeen = $true; break }
                '^workspace\.package$' { $section = 'workspace_package'; break }
                '^workspace\.dependencies$' { $section = 'workspace_dependencies'; break }
                '^features$' { $section = 'features'; break }
                '^patch\.crates-io$' { $section = 'patches'; break }
                '^(?<dependency_kind>dependencies|dev-dependencies|build-dependencies)$' { $section = [string]$Matches['dependency_kind']; break }
                '^(?<parent>dependencies|dev-dependencies|build-dependencies)\.(?<alias>[A-Za-z0-9_-]+)$' { $section = 'nested_dependency'; $nestedKind = [string]$Matches['parent']; $nestedAlias = [string]$Matches['alias']; $targetCondition = ''; $nestedKey = $nestedKind + [char]0 + $nestedAlias; break }
                '^workspace\.dependencies\.(?<alias>[A-Za-z0-9_-]+)$' { $section = 'nested_workspace_dependency'; $nestedAlias = [string]$Matches['alias']; break }
                '^target\.(?<target>"[^"]+"|''[^'']+''|[A-Za-z0-9_-]+)\.(?<kind>dependencies|dev-dependencies|build-dependencies)$' {
                    $targetCondition = [string]$Matches['target']; if ($targetCondition.Length -ge 2) { $targetCondition = $targetCondition.Substring(1, $targetCondition.Length - 2) }; $section = 'target_' + [string]$Matches['kind']; break
                }
                '^target\.(?<target>"[^"]+"|''[^'']+''|[A-Za-z0-9_-]+)\.(?<kind>dependencies|dev-dependencies|build-dependencies)\.(?<alias>[A-Za-z0-9_-]+)$' {
                    $targetCondition = [string]$Matches['target']; if ($targetCondition.Length -ge 2) { $targetCondition = $targetCondition.Substring(1, $targetCondition.Length - 2) }; $section = 'nested_dependency'; $nestedKind = [string]$Matches['kind']; $nestedAlias = [string]$Matches['alias']; $nestedKey = $nestedKind + [char]0 + $targetCondition + [char]0 + $nestedAlias; break
                }
                default {
                    if ($body -match '^(?:replace(?:\.|$)|patch\.)' -and $body -cne 'patch.crates-io') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unsupported source-affecting replace or patch table' }
                    $section = 'other'
                }
            }
            continue
        }
        if ($pendingActive) { [void]$pendingBuilder.Append(' ') } else { $pendingActive = $true }
        [void]$pendingBuilder.Append($line)
        if (-not (Update-D32BoundedDiagnosticTomlStatementState -Line $line -State $statementState -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds)) { continue }
        $pending = $pendingBuilder.ToString()
        $assignment = [regex]::Match($pending, '^\s*(?<key>[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?)\s*=\s*(?<value>.+?)\s*$')
        if (-not $assignment.Success) { if ($section -ne 'other') { throw ('D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: unsupported assignment at ' + $SourcePath + ':' + $lineNumber) }; $pendingBuilder.Clear() | Out-Null; $pendingActive = $false; $statementState = [ordered]@{ square = 0; curly = 0; quote = [char]0; escaped = $false }; continue }
        $key = [string]$assignment.Groups['key'].Value; $value = ConvertFrom-D32BoundedDiagnosticCargoValue -Text ([string]$assignment.Groups['value'].Value) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -ValueNodeBudget $ValueNodeBudget
        switch -Regex ($section) {
            '^package$' { if ($package.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate package field' }; $package.Add($key, $value); break }
            '^workspace$' { if ($workspace.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate workspace field' }; $workspace.Add($key, $value); break }
            '^workspace_package$' { if ($workspacePackage.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate workspace package field' }; $workspacePackage.Add($key, $value); break }
            '^features$' { if ($features.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate feature declaration' }; $features.Add($key, $value); break }
            '^dependencies$|^dev-dependencies$|^build-dependencies$|^target_' {
                $kind = $section; $condition = $targetCondition
                if ($section.StartsWith('target_')) { $kind = $section.Substring(7) }
                if ($value.kind -ceq 'string') { $fields = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal); $fields.Add('version', $value) }
                elseif ($value.kind -ceq 'table') { $fields = $value.value }
                else { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: dependency declaration must be a string or inline table' }
                $dependencies.Add([PSCustomObject]@{ alias = $key; kind = $kind; target = $condition; fields = $fields }); break
            }
            '^nested_dependency$' {
                $fields = $null
                if (-not $nestedDeps.TryGetValue($nestedKey, [ref]$fields)) { $fields = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal); $nestedDeps.Add($nestedKey, [PSCustomObject]@{ alias = $nestedAlias; kind = $nestedKind; target = $targetCondition; fields = $fields }) }
                else { $fields = $nestedDeps[$nestedKey].fields }
                if ($fields.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate nested dependency field' }; $fields.Add($key, $value); break
            }
            '^workspace_dependencies$' {
                if ($value.kind -ceq 'string') { $fields = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal); $fields.Add('version', $value) }
                elseif ($value.kind -ceq 'table') { $fields = $value.value } else { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: workspace dependency must be a string or inline table' }
                if ($workspaceDependencies.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate workspace dependency' }; $workspaceDependencies.Add($key, $fields); break
            }
            '^nested_workspace_dependency$' {
                $fields = $null
                if (-not $workspaceDependencies.TryGetValue($nestedAlias, [ref]$fields)) { $fields = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal); $workspaceDependencies.Add($nestedAlias, $fields) }
                if ($fields.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate nested workspace dependency field' }; $fields.Add($key, $value); break
            }
            '^patches$' {
                if ($value.kind -ceq 'string') { $fields = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal); $fields.Add('version', $value) }
                elseif ($value.kind -ceq 'table') { $fields = $value.value } else { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: patch declaration must be a string or inline table' }
                if ($patches.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: duplicate patch declaration' }; $patches.Add($key, $fields); break
            }
            default { }
        }
        $pendingBuilder.Clear() | Out-Null; $pendingActive = $false; $statementState = [ordered]@{ square = 0; curly = 0; quote = [char]0; escaped = $false }
    }
    if ($pendingActive) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: manifest ends with an incomplete TOML statement' }
    $nestedIndex = 0
    foreach ($nestedKeyValue in $nestedDeps.Keys) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest.nested_dependency_finalize' -Progress ("dependencies={0}/{1}" -f $nestedIndex, $nestedDeps.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED' -NoProgress }
        $nested = $nestedDeps[$nestedKeyValue]
        $dependencies.Add([PSCustomObject]@{ alias = [string]$nested.alias; kind = [string]$nested.kind; target = [string]$nested.target; fields = $nested.fields })
        $nestedIndex++
    }
    foreach ($key in @('name', 'version')) {
        if ($package.ContainsKey($key) -and $package[$key].kind -cne 'string') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: package name/version must be literal strings unless workspace inheritance is explicit' }
    }
    if ($package.ContainsKey('workspace') -and $package['workspace'].kind -cne 'string') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: package.workspace must be a literal relative path' }
    if ($package.ContainsKey('version.workspace') -and ($package['version.workspace'].kind -cne 'bool' -or -not [bool]$package['version.workspace'].value)) { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: package version workspace inheritance must be explicitly true' }
    if ($workspace.ContainsKey('members') -and $workspace['members'].kind -cne 'array') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: workspace members must be a supported string array' }
    if ($workspace.ContainsKey('default-members') -and $workspace['default-members'].kind -cne 'array') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: workspace default-members must be a supported string array' }
    foreach ($feature in $features.Values) { if ($feature.kind -cne 'array') { throw 'D32_BOUNDED_DIAGNOSTIC_MANIFEST_BLOCKED: feature activation declarations must be bounded string arrays' } }
    return [PSCustomObject][ordered]@{
        source_path = $SourcePath
        package_name = if ($package.ContainsKey('name')) { [string]$package['name'].value } else { $null }
        package_version = if ($package.ContainsKey('version')) { [string]$package['version'].value } else { $null }
        package_version_workspace = ($package.ContainsKey('version.workspace') -and $package['version.workspace'].kind -ceq 'bool' -and [bool]$package['version.workspace'].value)
        is_workspace_root = $workspaceRootSeen
        workspace_root_path = if ($package.ContainsKey('workspace')) { [string]$package['workspace'].value } else { $null }
        workspace_members = if ($workspace.ContainsKey('members') -and $workspace['members'].kind -ceq 'array') { @($workspace['members'].value) } else { @() }
        workspace_default_members = if ($workspace.ContainsKey('default-members') -and $workspace['default-members'].kind -ceq 'array') { @($workspace['default-members'].value) } else { @() }
        workspace_package = $workspacePackage; workspace_dependencies = $workspaceDependencies; dependencies = @($dependencies.ToArray()); features = $features; patches = $patches
    }
}

function Get-D32BoundedDiagnosticTargetPredicate {
    param([Parameter(Mandatory = $true)][string]$Expression, [Parameter(Mandatory = $true)][string]$TargetTriple,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds,
        [int]$Depth = 0,
        [System.Collections.IDictionary]$ParseBudget)
    if ($Depth -lt 0 -or $Depth -gt 64) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: cfg predicate recursion exceeds the fixed 64-level parser stack bound' }
    if ($null -eq $ParseBudget) { $ParseBudget = [ordered]@{ scanned_chars = 0L; maximum = 8388608L } }
    if (-not $ParseBudget.Contains('scanned_chars') -or -not $ParseBudget.Contains('maximum') -or
        [Int64]$ParseBudget.maximum -le 0 -or [Int64]$ParseBudget.maximum -gt 8388608L -or
        [Int64]$Expression.Length -gt ([Int64]$ParseBudget.maximum - [Int64]$ParseBudget.scanned_chars)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: cumulative cfg predicate parsing exceeds its fixed 8 Mi-character work bound'
    }
    $ParseBudget.scanned_chars = [Int64]$ParseBudget.scanned_chars + [Int64]$Expression.Length
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.cfg_predicate' -Progress ("depth={0};scanned_chars={1}" -f $Depth, $ParseBudget.scanned_chars) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    if ($Expression -ceq $TargetTriple) { return [PSCustomObject]@{ value = $true; proven = $true; witness = 'exact target triple' } }
    if ($Expression -match '^cfg\((?<inner>.*)\)$') { $inner = [string]$Matches['inner'] } else { return [PSCustomObject]@{ value = $true; proven = $false; witness = 'unknown target selector conservatively included' } }
    $inner = $inner.Trim()
    foreach ($operator in @('all', 'any', 'not')) {
        if ($inner.StartsWith($operator + '(') -and $inner.EndsWith(')')) {
            $parts = @(Split-D32BoundedDiagnosticTopLevel -Text $inner.Substring($operator.Length + 1, $inner.Length - $operator.Length - 2) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds)
            if ($operator -ceq 'not') { if ($parts.Count -ne 1) { return [PSCustomObject]@{ value = $true; proven = $false; witness = 'malformed unknown cfg conservatively included' } }; $child = Get-D32BoundedDiagnosticTargetPredicate -Expression ('cfg(' + $parts[0] + ')') -TargetTriple $TargetTriple -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Depth ($Depth + 1) -ParseBudget $ParseBudget; if (-not $child.proven) { return [PSCustomObject]@{ value = $true; proven = $false; witness = 'not of unknown cfg conservatively included' } }; return [PSCustomObject]@{ value = -not [bool]$child.value; proven = $true; witness = 'not(' + [string]$child.witness + ')' } }
            $children = @($parts | ForEach-Object { Get-D32BoundedDiagnosticTargetPredicate -Expression ('cfg(' + $_ + ')') -TargetTriple $TargetTriple -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Depth ($Depth + 1) -ParseBudget $ParseBudget })
            if ($operator -ceq 'all') { if (@($children | Where-Object { $_.proven -and -not $_.value }).Count -gt 0) { return [PSCustomObject]@{ value = $false; proven = $true; witness = 'all contains proven-false target predicate' } }; if (@($children | Where-Object { -not $_.proven }).Count -gt 0) { return [PSCustomObject]@{ value = $true; proven = $false; witness = 'unknown member of all conservatively included' } }; return [PSCustomObject]@{ value = $true; proven = $true; witness = 'all target predicates proven true' } }
            if (@($children | Where-Object { $_.proven -and $_.value }).Count -gt 0) { return [PSCustomObject]@{ value = $true; proven = $true; witness = 'any contains proven-true target predicate' } }; if (@($children | Where-Object { -not $_.proven }).Count -gt 0) { return [PSCustomObject]@{ value = $true; proven = $false; witness = 'unknown member of any conservatively included' } }; return [PSCustomObject]@{ value = $false; proven = $true; witness = 'all any-target predicates proven false' }
        }
    }
    $atom = [regex]::Match($inner, '^(?<name>[A-Za-z0-9_]+)\s*=\s*(?<value>"[^"]+")$')
    if ($atom.Success) {
        $name = [string]$atom.Groups['name'].Value; $value = [string]$atom.Groups['value'].Value.Trim('"')
        $facts = @{ target_arch = 'x86_64'; target_os = 'windows'; target_family = 'windows'; target_env = 'msvc'; target_vendor = 'pc'; target_endian = 'little'; target_pointer_width = '64' }
        if ($facts.ContainsKey($name)) { return [PSCustomObject]@{ value = ($facts[$name] -ceq $value); proven = $true; witness = ($name + '=' + $facts[$name]) } }
        return [PSCustomObject]@{ value = $true; proven = $false; witness = 'unknown cfg atom conservatively included' }
    }
    if ($inner -ceq 'windows') { return [PSCustomObject]@{ value = $true; proven = $true; witness = 'windows host/target fact' } }
    if ($inner -ceq 'unix') { return [PSCustomObject]@{ value = $false; proven = $true; witness = 'not a Unix target' } }
    return [PSCustomObject]@{ value = $true; proven = $false; witness = 'unknown cfg expression conservatively included' }
}

function Test-D32BoundedDiagnosticVersionRequirement {
    param([Parameter(Mandatory = $true)][string]$Requirement, [Parameter(Mandatory = $true)][string]$LockedVersion)
    if ($Requirement.Length -gt 4096) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: semver dependency requirement exceeds its fixed 4096-character parser work bound' }
    if ($Requirement -ceq '*') { return $true }
    if ($Requirement -match '^=(?<exact>[0-9A-Za-z.+_-]+)$') { return [string]$Matches['exact'] -ceq $LockedVersion }
    if ($Requirement.Contains('-') -and $Requirement -ceq $LockedVersion) { return $true }
    if ($LockedVersion -match '-' -or $LockedVersion -notmatch '^(?<major>0|[1-9][0-9]*)\.(?<minor>0|[1-9][0-9]*)\.(?<patch>0|[1-9][0-9]*)(?:\+(?<build>[0-9A-Za-z.-]+))?$') { return $false }
    $locked = [version]::new([int]$Matches.major, [int]$Matches.minor, [int]$Matches.patch)
    foreach ($part in [regex]::Split($Requirement, '\s*,\s*')) {
        if ($part -match '^(?<op>>=|<=|>|<|\^|~|=)?\s*(?<major>0|[1-9][0-9]*)(?:\.(?<minor>0|[1-9][0-9]*|\*))?(?:\.(?<patch>0|[1-9][0-9]*|\*))?$') {
            $op = if ($Matches.op) { [string]$Matches.op } else { '^' }; $major = [int]$Matches.major
            $minor = if ($Matches.minor -and $Matches.minor -ne '*') { [int]$Matches.minor } else { 0 }; $patch = if ($Matches.patch -and $Matches.patch -ne '*') { [int]$Matches.patch } else { 0 }
            $minorWildcard = ($Matches.minor -ceq '*')
            $patchWildcard = ($Matches.patch -ceq '*')
            $specified = if ($Matches.patch -and -not $patchWildcard) { 3 } elseif ($Matches.minor -and -not $minorWildcard) { 2 } else { 1 }
            if (($minorWildcard -or $patchWildcard) -and $op -cnotin @('^', '')) { return $false }
            if ($minorWildcard -and $Matches.patch -and $Matches.patch -cne '*') { return $false }
            $base = [version]::new($major, $minor, $patch)
            if ($minorWildcard) { if ([int]$locked.Major -ne $major) { return $false }; continue }
            if ($patchWildcard) { if ([int]$locked.Major -ne $major -or [int]$locked.Minor -ne $minor) { return $false }; continue }
            $ok = switch ($op) {
                '=' { $locked -eq $base -and $specified -eq 3 }
                '>' { $locked -gt $base }
                '>=' { $locked -ge $base }
                '<' { $locked -lt $base }
                '<=' { $locked -le $base }
                '~' { if ($specified -ge 2) { $locked -ge $base -and $locked -lt [version]::new($major, $minor + 1, 0) } else { $locked -ge $base -and $locked -lt [version]::new($major + 1, 0, 0) } }
                default { if ($major -gt 0 -or $specified -eq 1) { $locked -ge $base -and $locked -lt [version]::new($major + 1, 0, 0) } elseif ($minor -gt 0 -or $specified -eq 2) { $locked -ge $base -and $locked -lt [version]::new(0, $minor + 1, 0) } else { $locked -ge $base -and $locked -lt [version]::new(0, 0, $patch + 1) } }
            }
            if (-not $ok) { return $false }; continue
        }
        return $false
    }
    return $true
}

function Resolve-D32BoundedDiagnosticWorkspaceDependency {
    param([Parameter(Mandatory = $true)][object]$Dependency, [AllowNull()][object]$WorkspaceManifest)
    $fields = $Dependency.fields
    if (-not ($fields -is [System.Collections.IDictionary])) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency fields are not a supported map' }
    $workspaceFlag = $fields.ContainsKey('workspace') -and $fields['workspace'].kind -ceq 'bool' -and [bool]$fields['workspace'].value
    if (-not $workspaceFlag) { return $Dependency }
    if ($null -eq $WorkspaceManifest -or -not $WorkspaceManifest.workspace_dependencies.ContainsKey([string]$Dependency.alias)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: inherited dependency has no verified workspace declaration'
    }
    $merged = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($key in $WorkspaceManifest.workspace_dependencies[[string]$Dependency.alias].Keys) { $merged.Add([string]$key, $WorkspaceManifest.workspace_dependencies[[string]$Dependency.alias][$key]) }
    foreach ($key in $fields.Keys) {
        if ($key -ceq 'workspace') { continue }
        if ($key -cin @('features', 'optional', 'default-features')) { continue }
        throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: workspace-inherited dependency overrides a source/version field'
    }
    return [PSCustomObject]@{ alias = $Dependency.alias; kind = $Dependency.kind; target = $Dependency.target; fields = $merged }
}

function Assert-D32BoundedDiagnosticDependencyFields {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fields)
    $allowed = @('version', 'package', 'path', 'git', 'rev', 'branch', 'tag', 'registry', 'optional', 'default-features', 'features', 'workspace')
    foreach ($key in $Fields.Keys) {
        if ($allowed -cnotcontains [string]$key) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency manifest uses an unsupported field that may alter package selection or source identity' }
        $value = $Fields[$key]
        switch ([string]$key) {
            { $_ -in @('version', 'package', 'path', 'git', 'rev', 'branch', 'tag', 'registry') } {
                if ($null -eq $value -or [string]$value.kind -cne 'string' -or [String]::IsNullOrWhiteSpace([string]$value.value)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: source/version dependency field is not a nonempty literal string' }
                break
            }
            { $_ -in @('optional', 'default-features', 'workspace') } {
                if ($null -eq $value -or [string]$value.kind -cne 'bool') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency activation field is not a literal boolean' }
                if ([string]$key -ceq 'workspace' -and -not [bool]$value.value) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: workspace inheritance must be explicitly true when present' }
                break
            }
            'features' {
                if ($null -eq $value -or [string]$value.kind -cne 'array' -or $value.value -isnot [Array]) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency features are not a bounded string array' }
                break
            }
        }
    }
    $sourceSelectors = 0
    foreach ($key in @('path', 'git', 'registry')) { if ($Fields.ContainsKey($key)) { $sourceSelectors++ } }
    if ($sourceSelectors -gt 1 -or ($Fields.ContainsKey('rev') -and -not $Fields.ContainsKey('git')) -or
        (($Fields.ContainsKey('branch') -or $Fields.ContainsKey('tag')) -and -not $Fields.ContainsKey('git')) -or
        ($Fields.ContainsKey('branch') -and $Fields.ContainsKey('tag'))) {
        throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency has ambiguous or unsupported source selectors'
    }
}

function Get-D32BoundedDiagnosticDependencyExpectedSource {
    param([Parameter(Mandatory = $true)][object]$Dependency, [Parameter(Mandatory = $true)][object]$RootManifest,
        [Parameter(Mandatory = $true)][object]$ParentPackage,
        [AllowNull()][System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]]$RootPatchIndex)
    $fields = $Dependency.fields; Assert-D32BoundedDiagnosticDependencyFields -Fields $fields
    $packageName = if ($fields.ContainsKey('package')) { [string]$fields['package'].value } else { [string]$Dependency.alias }
    if ($fields.ContainsKey('path')) {
        if ([string]$ParentPackage.source_kind -ceq 'workspace') { return [PSCustomObject]@{ name = $packageName; source_kind = 'workspace'; source = $null; path = [string]$fields['path'].value; path_base = 'DEPENDENCY_PARENT_MANIFEST' } }
        if ([string]$ParentPackage.source_kind -ceq 'git') { return [PSCustomObject]@{ name = $packageName; source_kind = 'git'; source = [string]$ParentPackage.source; path = [string]$fields['path'].value; path_base = 'DEPENDENCY_PARENT_MANIFEST' } }
        throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: path dependency from a registry package is outside the approved current source mapping'
    }
    if ($fields.ContainsKey('git')) {
        if (-not $fields.ContainsKey('rev') -or [string]$fields['rev'].value -cnotmatch '^[0-9a-f]{40}$' -or $fields.ContainsKey('branch') -or $fields.ContainsKey('tag')) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: Git dependency must use one exact full-commit rev and no floating selector' }
        $url = [string]$fields['git'].value
        if ($url.Contains('?') -or $url.Contains('#') -or $url -match '[@\s]') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: Git dependency URL has query, fragment, credentials, or whitespace outside the finite form' }
        $source = 'git+' + $url + '?rev=' + [string]$fields['rev'].value + '#' + [string]$fields['rev'].value
        return [PSCustomObject]@{ name = $packageName; source_kind = 'git'; source = $source }
    }
    if ($fields.ContainsKey('registry') -and [string]$fields['registry'].value -cne 'crates-io') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: non-crates.io registry dependency is outside the fixed source domain' }
    $patch = $null
    $patchMatches = $null
    if ($null -ne $RootPatchIndex) { [void]$RootPatchIndex.TryGetValue($packageName, [ref]$patchMatches) }
    else {
        $patchMatches = [System.Collections.Generic.List[object]]::new()
        foreach ($patchAlias in $RootManifest.patches.Keys) {
            $patchFields = $RootManifest.patches[$patchAlias]
            $patchedName = if ($patchFields.ContainsKey('package')) { [string]$patchFields['package'].value } else { [string]$patchAlias }
            if ($patchedName -ceq $packageName) { $patchMatches.Add($patchFields) }
        }
    }
    if ($null -ne $patchMatches) {
        if ($patchMatches.Count -gt 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: ambiguous root crates.io patch target' }
        if ($patchMatches.Count -eq 1) { $patch = $patchMatches[0] }
    }
    if ($null -ne $patch) {
        Assert-D32BoundedDiagnosticDependencyFields -Fields $patch
        if ($patch.ContainsKey('path')) { return [PSCustomObject]@{ name = $packageName; source_kind = 'workspace'; source = $null; path = [string]$patch['path'].value; path_base = 'SELECTED_WORKSPACE_PATCH_MANIFEST' } }
        if ($patch.ContainsKey('git') -and $patch.ContainsKey('rev')) {
            if ([string]$patch['rev'].value -cnotmatch '^[0-9a-f]{40}$' -or $patch.ContainsKey('branch') -or $patch.ContainsKey('tag') -or
                [string]$patch['git'].value -match '[@\s?#]') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: root patch Git source is not one exact full-commit immutable URL' }
            $source = 'git+' + [string]$patch['git'].value + '?rev=' + [string]$patch['rev'].value + '#' + [string]$patch['rev'].value
            return [PSCustomObject]@{ name = $packageName; source_kind = 'git'; source = $source }
        }
        throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: unsupported root patch declaration'
    }
    return [PSCustomObject]@{ name = $packageName; source_kind = 'registry'; source = 'registry+https://github.com/rust-lang/crates.io-index' }
}

function Test-D32BoundedDiagnosticPathDependencyBinding {
    param([Parameter(Mandatory = $true)][object]$ParentPackage, [Parameter(Mandatory = $true)][object]$ParentManifest,
        [Parameter(Mandatory = $true)][object]$TargetPackage, [Parameter(Mandatory = $true)][object]$TargetManifest, [Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or [IO.Path]::IsPathRooted($Path) -or $Path.Contains(':') -or $Path.Contains('\') -or $Path.Contains("`0")) { return $false }
    if ([string]$ParentPackage.source_kind -ceq 'workspace') {
        if ([string]$TargetPackage.source_kind -cne 'workspace') { return $false }
    }
    elseif ([string]$ParentPackage.source_kind -ceq 'git') {
        if ([string]$TargetPackage.source_kind -cne 'git' -or [string]$TargetPackage.source -cne [string]$ParentPackage.source) { return $false }
    }
    else { return $false }
    $parentDirectory = [IO.Path]::GetDirectoryName(([string]$ParentManifest.source_path).Replace('/', '\'))
    if ($null -eq $parentDirectory) { $parentDirectory = '' }
    $sourceRoot = 'C:\d32\graph-source-root'
    $targetDirectory = [IO.Path]::GetFullPath((Join-Path $sourceRoot (Join-Path $parentDirectory $Path.Replace('/', '\'))))
    $relativeDirectory = [IO.Path]::GetRelativePath($sourceRoot, $targetDirectory).Replace('\', '/')
    if ($relativeDirectory -match '(^/|^[A-Za-z]:|(^|/)\.\.(?:/|$)|\x00)') { return $false }
    $expectedManifestPath = if ([String]::IsNullOrEmpty($relativeDirectory)) { 'Cargo.toml' } else { $relativeDirectory + '/Cargo.toml' }
    return [StringComparer]::Ordinal.Equals([string]$TargetManifest.source_path, $expectedManifestPath)
}

function Complete-D32BoundedDiagnosticManifestCatalog {
    param([Parameter(Mandatory = $true)][object]$Plan, [Parameter(Mandatory = $true)][object[]]$Candidates,
        [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds)
    if ($Candidates.Count -gt 4096) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: candidate manifest count exceeds its fixed 4096-entry bound' }
    $lockedPackageById = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $lockedPackageIndex = 0
    foreach ($lockedPackage in $Plan.locked_packages) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest_catalog.lock_index' -Progress ("packages={0}/{1}" -f $lockedPackageIndex, $Plan.locked_packages.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        if (-not $lockedPackageById.TryAdd([string]$lockedPackage.package_id, $lockedPackage)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: source-plan package identity is duplicated before manifest mapping'
        }
        $lockedPackageIndex++
    }
    $gitSourceSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($gitSource in $Plan.git_sources) { [void]$gitSourceSet.Add([string]$gitSource.source) }
    $parsed = [System.Collections.Generic.List[object]]::new()
    $bySourcePath = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $manifestValueNodeBudget = [ordered]@{ nodes = 0L; maximum = [Int64]$script:D32BoundedDiagnosticManifestValueNodeLimit }
    $candidateBytes = [Int64]0
    $candidateIndex = 0
    foreach ($candidate in $Candidates) {
        if ($null -ne $ProofTimer) {
            Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest_catalog.parse' -Progress ("candidates={0}/{1}" -f $candidateIndex, $Candidates.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED'
        }
        if ([string]$candidate.source_kind -cnotin @('workspace', 'registry', 'git') -or
            [string]$candidate.source_path -notmatch '^[A-Za-z0-9_./-]+/Cargo\.toml$|^Cargo\.toml$' -or
            [string]$candidate.content_sha256 -cnotmatch '^[0-9a-f]{64}$' -or [string]$candidate.content -isnot [string]) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: current source manifest candidate is not exact, bounded, or checksum-bound'
        }
        foreach ($segment in ([string]$candidate.source_path).Split('/')) {
            if ([String]::IsNullOrEmpty($segment) -or $segment -ceq '.' -or $segment -ceq '..') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: source manifest candidate path has an empty, dot, or traversal segment' }
        }
        $candidateSize = [Int64][Text.Encoding]::UTF8.GetByteCount([string]$candidate.content)
        if ($candidateSize -gt 1048576) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: source manifest exceeds the 1 MiB content ceiling' }
        $candidateBytes += $candidateSize
        if ($candidateBytes -gt 67108864L) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: combined source-manifest candidate bytes exceed the 64 MiB managed buffer bound' }
        $candidateContentBytes = [Text.UTF8Encoding]::new($false).GetBytes([string]$candidate.content)
        $actualSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($candidateContentBytes)).ToLowerInvariant()
        $candidateContentBytes = $null
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest_catalog.content_digest' -Progress ("candidate={0}/{1}" -f $candidateIndex, $Candidates.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
        if ($actualSha -cne [string]$candidate.content_sha256) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: manifest bytes differ from their archive/tree/file content digest' }
        if (-not [String]::IsNullOrEmpty([string]$candidate.package_id)) {
            if (-not $lockedPackageById.ContainsKey([string]$candidate.package_id)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: manifest candidate package ID is absent from the exact lock catalog' }
            $boundPackage = $lockedPackageById[[string]$candidate.package_id]
            $expectedCandidateSource = if ($null -eq $boundPackage.source) { 'workspace' } else { [string]$boundPackage.source }
            $actualCandidateSource = if ($candidate.source_kind -ceq 'workspace') { 'workspace' } else { [string]$candidate.source }
            if ([string]$candidate.source_kind -cne [string]$boundPackage.source_kind -or
                [string]$actualCandidateSource -cne [string]$expectedCandidateSource) {
                throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: explicit manifest package ID is cross-bound to another locked source kind or identity'
            }
        }
        elseif ($candidate.source_kind -ceq 'workspace' -and $null -ne $candidate.source) {
            throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: workspace manifest candidate unexpectedly names an external source identity'
        }
        $groupSource = if ($candidate.source_kind -ceq 'workspace') { 'workspace' } else { [string]$candidate.source }
        if ($candidate.source_kind -ceq 'registry' -and ($groupSource -cne 'registry+https://github.com/rust-lang/crates.io-index' -or [String]::IsNullOrEmpty([string]$candidate.package_id))) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: registry manifest candidate has a non-approved source or lacks its exact lock package binding' }
        if ($candidate.source_kind -ceq 'git' -and -not $gitSourceSet.Contains($groupSource)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: Git manifest candidate is not from an exact lock-derived Git source' }
        $groupIdentity = if ($candidate.source_kind -ceq 'registry') { $groupSource + [char]0 + [string]$candidate.package_id } else { $groupSource }
        $key = $candidate.source_kind + [char]0 + $groupIdentity + [char]0 + [string]$candidate.source_path
        if ($bySourcePath.ContainsKey($key)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: duplicate manifest path within one verified source identity' }
        $model = ConvertFrom-D32BoundedDiagnosticCargoManifest -Text ([string]$candidate.content) -SourcePath ([string]$candidate.source_path) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -ValueNodeBudget $manifestValueNodeBudget
        $entry = [PSCustomObject]@{ source_kind = [string]$candidate.source_kind; source = $groupSource; group_identity = $groupIdentity; source_path = [string]$candidate.source_path; content_sha256 = [string]$candidate.content_sha256; explicit_package_id = [string]$candidate.package_id; model = $model }
        $parsed.Add($entry); $bySourcePath.Add($key, $entry)
        $candidateIndex++
    }
    $workspaceIndex = 0
    foreach ($entry in $parsed) {
        if ($null -ne $ProofTimer -and (($workspaceIndex -band 63) -eq 0)) {
            Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest_catalog.workspace_resolution' -Progress ("candidates={0}/{1}" -f $workspaceIndex, $parsed.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED'
        }
        $workspaceIndex++
        $model = $entry.model
        if ([String]::IsNullOrEmpty([string]$model.package_name)) { continue }
        $manifestDirectory = [IO.Path]::GetDirectoryName([string]$entry.source_path.Replace('/', '\'))
        if ($null -eq $manifestDirectory) { $manifestDirectory = '' }
        $workspaceManifest = $null
        if (-not [String]::IsNullOrWhiteSpace([string]$model.workspace_root_path)) {
            $targetDir = [IO.Path]::GetFullPath((Join-Path ('C:\d32\manifest-root') (Join-Path $manifestDirectory ([string]$model.workspace_root_path))))
            $relativeDir = [IO.Path]::GetRelativePath('C:\d32\manifest-root', $targetDir).Replace('\', '/')
            if ($relativeDir -match '(^|/)\.\.(?:/|$)' -or [IO.Path]::IsPathRooted($relativeDir)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: explicit Cargo workspace path escapes its verified source root' }
            $workspacePath = if ([String]::IsNullOrEmpty($relativeDir)) { 'Cargo.toml' } else { $relativeDir + '/Cargo.toml' }
            $workspaceKey = $entry.source_kind + [char]0 + [string]$entry.group_identity + [char]0 + $workspacePath
            if (-not $bySourcePath.ContainsKey($workspaceKey) -or -not [bool]$bySourcePath[$workspaceKey].model.is_workspace_root) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: explicit package workspace manifest is absent from verified current source content' }
            $workspaceManifest = $bySourcePath[$workspaceKey].model
        }
        else {
            if ([bool]$model.is_workspace_root) { $workspaceManifest = $model }
            $ancestor = $manifestDirectory
            $ancestorIndex = 0
            while ($null -eq $workspaceManifest -and -not [String]::IsNullOrEmpty($ancestor)) {
                if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest_catalog.workspace_ancestor' -Progress ("candidate={0}/{1};depth={2}" -f $workspaceIndex, $parsed.Count, $ancestorIndex) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
                $workspacePath = $ancestor.Replace('\', '/') + '/Cargo.toml'
                $workspaceKey = $entry.source_kind + [char]0 + [string]$entry.group_identity + [char]0 + $workspacePath
                if ($bySourcePath.ContainsKey($workspaceKey) -and [bool]$bySourcePath[$workspaceKey].model.is_workspace_root) { $workspaceManifest = $bySourcePath[$workspaceKey].model; break }
                $separator = $ancestor.LastIndexOf('\'); if ($separator -lt 0) { $ancestor = '' } elseif ($separator -eq 0) { $ancestor = '' } else { $ancestor = $ancestor.Substring(0, $separator) }
                $ancestorIndex++
            }
        }
        if ($model.package_version_workspace) {
            if ($null -eq $workspaceManifest -or -not $workspaceManifest.workspace_package.ContainsKey('version') -or [string]$workspaceManifest.workspace_package['version'].kind -cne 'string') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: inherited package version lacks a verified workspace.package.version' }
            $model.package_version = [string]$workspaceManifest.workspace_package['version'].value
        }
        if ($null -ne $workspaceManifest) { $model | Add-Member -NotePropertyName workspace_manifest -NotePropertyValue $workspaceManifest -Force }
    }
    $explicitByPackageIdentity = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]]::new([StringComparer]::Ordinal)
    $unboundBySourceIdentity = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]]::new([StringComparer]::Ordinal)
    $identityIndex = 0
    foreach ($entry in $parsed) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest_catalog.index_identities' -Progress ("candidates={0}/{1}" -f $identityIndex, $parsed.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $identityIndex++
        if ([String]::IsNullOrEmpty([string]$entry.model.package_name) -or [String]::IsNullOrEmpty([string]$entry.model.package_version)) { continue }
        if (-not [String]::IsNullOrEmpty([string]$entry.explicit_package_id)) {
            $key = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@([string]$entry.model.package_name, [string]$entry.model.package_version, [string]$entry.explicit_package_id))
            if (-not $explicitByPackageIdentity.ContainsKey($key)) { $explicitByPackageIdentity.Add($key, [System.Collections.Generic.List[object]]::new()) }
            $explicitByPackageIdentity[$key].Add($entry)
            continue
        }
        $key = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@([string]$entry.model.package_name, [string]$entry.model.package_version, [string]$entry.source_kind, [string]$entry.source))
        if (-not $unboundBySourceIdentity.ContainsKey($key)) { $unboundBySourceIdentity.Add($key, [System.Collections.Generic.List[object]]::new()) }
        $unboundBySourceIdentity[$key].Add($entry)
    }
    $catalog = [System.Collections.Generic.List[object]]::new()
    $packageIndex = 0
    foreach ($package in $Plan.locked_packages) {
        if ($null -ne $ProofTimer -and (($packageIndex -band 63) -eq 0)) {
            Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'manifest_catalog.map_locked_packages' -Progress ("packages={0}/{1}" -f $packageIndex, $Plan.locked_packages.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED'
        }
        $packageIndex++
        $matches = [System.Collections.Generic.List[object]]::new()
        $explicitKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@([string]$package.name, [string]$package.version, [string]$package.package_id))
        if ($explicitByPackageIdentity.ContainsKey($explicitKey)) { foreach ($entry in $explicitByPackageIdentity[$explicitKey]) { $matches.Add($entry) } }
        $sourceIdentity = if ([string]$package.source_kind -ceq 'workspace') { 'workspace' } else { [string]$package.source }
        $unboundKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@([string]$package.name, [string]$package.version, [string]$package.source_kind, $sourceIdentity))
        if ($unboundBySourceIdentity.ContainsKey($unboundKey)) { foreach ($entry in $unboundBySourceIdentity[$unboundKey]) { $matches.Add($entry) } }
        if ($matches.Count -gt 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: multiple verified current manifests match one locked package identity' }
        if ($matches.Count -eq 1) {
            $entry = $matches[0]
            $catalog.Add([PSCustomObject]@{ package_id = [string]$package.package_id; source_kind = [string]$entry.source_kind; source_identity = [string]$entry.source; source_path = [string]$entry.source_path; content_sha256 = [string]$entry.content_sha256; model = $entry.model })
        }
    }
    return [PSCustomObject]@{ entries = @($catalog.ToArray()); verified_candidate_manifest_count = [Int64]$parsed.Count }
}

function Resolve-D32BoundedDiagnosticLockedDependencyGraph {
    param([Parameter(Mandatory = $true)][object]$Plan, [Parameter(Mandatory = $true)][object[]]$ManifestCatalog,
        [string]$RootManifestPath = 'vita-agent/Cargo.toml',
        [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds)
    if ([string]$Plan.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_LOCK_SOURCE_PLAN_V2' -or [int]$Plan.schema_version -ne 2 -or
        [string]$Plan.semantic_scope -cne 'FULL_LOCK_AUDIT_CATALOG_PLUS_SELECTED_REACHABLE_CONSERVATIVE_SUPERSET' -or
        [string]$Plan.host_triple -cne 'x86_64-pc-windows-msvc' -or [string]$Plan.target_triple -cne 'x86_64-pc-windows-msvc' -or
        $Plan.locked_packages -isnot [Array] -or $Plan.lock_dependency_edges -isnot [Array] -or $ManifestCatalog -isnot [Array] -or
        [string]$RootManifestPath -cne 'vita-agent/Cargo.toml' -or $Plan.locked_packages.Count -le 0 -or $Plan.locked_packages.Count -gt 2048 -or
        $Plan.lock_dependency_edges.Count -gt 65536 -or [string]$Plan.lock_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Plan.lock_dependency_edges_sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: source-plan version, fixed target, root selection, or manifest catalog is invalid' }
    $packageById = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $packageIndex = 0
    foreach ($package in $Plan.locked_packages) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.index_packages' -Progress ("packages={0}/{1}" -f $packageIndex, $Plan.locked_packages.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $packageIndex++
        if (-not $packageById.TryAdd([string]$package.package_id, $package)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: lock catalog package identity is duplicated' }
    }
    $edgeByParent = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]]::new([StringComparer]::Ordinal)
    $edgeByParentAndTargetName = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]]::new([StringComparer]::Ordinal)
    $edgeIdentitySet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $edgeIndex = 0
    foreach ($edge in $Plan.lock_dependency_edges) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.index_edges' -Progress ("edges={0}/{1}" -f $edgeIndex, $Plan.lock_dependency_edges.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $edgeIndex++
        if (-not $packageById.ContainsKey([string]$edge.parent_package_id) -or -not $packageById.ContainsKey([string]$edge.target_package_id)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: lock edge references an unknown catalog package' }
        if ([String]::IsNullOrWhiteSpace([string]$edge.lock_spec) -or -not $edgeIdentitySet.Add(([string]$edge.parent_package_id + [char]0 + [string]$edge.lock_spec))) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: duplicate or empty lock edge identity cannot support exhaustive reconciliation' }
        if (-not $edgeByParent.ContainsKey([string]$edge.parent_package_id)) { $edgeByParent.Add([string]$edge.parent_package_id, [System.Collections.Generic.List[object]]::new()) }
        $edgeByParent[[string]$edge.parent_package_id].Add($edge)
        $targetName = [string]$packageById[[string]$edge.target_package_id].name
        $targetKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@([string]$edge.parent_package_id, $targetName))
        if (-not $edgeByParentAndTargetName.ContainsKey($targetKey)) { $edgeByParentAndTargetName.Add($targetKey, [System.Collections.Generic.List[object]]::new()) }
        $edgeByParentAndTargetName[$targetKey].Add($edge)
    }
    $manifestById = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $manifestRecordById = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $manifestIndex = 0
    foreach ($manifest in $ManifestCatalog) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.index_manifests' -Progress ("manifests={0}/{1}" -f $manifestIndex, $ManifestCatalog.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $manifestPackage = $null
        if ($null -ne $manifest -and $packageById.ContainsKey([string]$manifest.package_id)) { $manifestPackage = $packageById[[string]$manifest.package_id] }
        $expectedSourceIdentity = if ($null -eq $manifestPackage -or $null -eq $manifestPackage.source) { 'workspace' } else { [string]$manifestPackage.source }
        if ([string]$manifest.package_id -cnotmatch '^.+\|(?:workspace|registry|git)\|.+$' -or [string]$manifest.content_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $null -eq $manifest.model -or
            $null -eq $manifestPackage -or [string]$manifest.source_kind -cne [string]$manifestPackage.source_kind -or
            [string]$manifest.source_identity -cne $expectedSourceIdentity -or
            -not $manifestById.TryAdd([string]$manifest.package_id, $manifest.model)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: source-verified manifest record is malformed or duplicated' }
        $manifestRecordById.Add([string]$manifest.package_id, $manifest)
        $manifestIndex++
    }
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.select_root' -Progress ("manifests={0}" -f $ManifestCatalog.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $rootModels = @($ManifestCatalog | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals([string]$_.source_path, $RootManifestPath) })
    if ($rootModels.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: selected manifest path does not identify exactly one caller-pinned current root' }
    $rootModel = $rootModels[0].model
    if ([string]$rootModel.package_name -cne 'digital-life-vita-agent' -or $null -eq $rootModel.package_version -or
        -not $rootModel.features.ContainsKey('d32-a-test-helper')) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: selected current manifest package/feature identity differs from the fixed command' }
    $rootIds = @($Plan.locked_packages | Where-Object { $_.source_kind -ceq 'workspace' -and $_.name -ceq [string]$rootModel.package_name -and $_.version -ceq [string]$rootModel.package_version } | ForEach-Object { [string]$_.package_id })
    if ($rootIds.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: current selected package does not resolve to exactly one local lock package' }
    if (-not $manifestById.ContainsKey($rootIds[0])) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: selected root package lacks its exact current source-manifest pin' }
    $selectedRootWorkspace = if ($null -ne $rootModel.PSObject.Properties['workspace_manifest']) { $rootModel.workspace_manifest } else { $rootModel }
    $rootPatchByName = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]]::new([StringComparer]::Ordinal)
    if ($null -ne $rootModel.patches) {
        $patchIndex = 0
        foreach ($patchAlias in $rootModel.patches.Keys) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.root_patches' -Progress ("patches={0}/{1}" -f $patchIndex, $rootModel.patches.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
            $patchFields = $rootModel.patches[$patchAlias]
            $patchedName = if ($patchFields.ContainsKey('package')) { [string]$patchFields['package'].value } else { [string]$patchAlias }
            if (-not $rootPatchByName.ContainsKey($patchedName)) { $rootPatchByName.Add($patchedName, [System.Collections.Generic.List[object]]::new()) }
            $rootPatchByName[$patchedName].Add($patchFields)
            $patchIndex++
        }
    }

    $queue = [System.Collections.Generic.Queue[string]]::new(); $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $parentPath = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $depthById = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
    $visitOrder = [System.Collections.Generic.List[string]]::new()
    foreach ($rootId in $rootIds) { $queue.Enqueue($rootId); $parentPath[$rootId] = $rootId; $depthById[$rootId] = 0 }
    $graphEdges = [System.Collections.Generic.List[object]]::new(); $dependencyDecisions = [System.Collections.Generic.List[object]]::new(); $unknownCfgCount = 0L; $inactiveCfgCount = 0L
    $visitedParentCount = 0L
    $candidateComparisonCount = [Int64]0
    $candidateComparisonCharacterWork = [Int64]0
    while ($queue.Count -gt 0) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.parents' -Progress ("visited={0};pending={1};edges={2};decisions={3}" -f $visitedParentCount, $queue.Count, $graphEdges.Count, $dependencyDecisions.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
        $parentId = $queue.Dequeue(); if (-not $visited.Add($parentId)) { continue }
        $visitOrder.Add($parentId)
        $visitedParentCount++
        if (-not $manifestById.ContainsKey($parentId)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: reachable locked package lacks a verified current source manifest; absence cannot prove exclusion' }
        $parentPackage = $packageById[$parentId]; $manifestModel = $manifestById[$parentId]
        if ([string]$manifestModel.package_name -cne [string]$parentPackage.name -or [string]$manifestModel.package_version -cne [string]$parentPackage.version) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: verified package manifest identity differs from its exact Cargo.lock package record' }
        $workspaceModel = if ($null -ne $manifestModel.PSObject.Properties['workspace_manifest']) { $manifestModel.workspace_manifest } elseif ([bool]$manifestModel.is_workspace_root) { $manifestModel } else { $null }
        $lockEdges = if ($edgeByParent.ContainsKey($parentId)) { @($edgeByParent[$parentId].ToArray()) } else { @() }
        $matchedLockEdges = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $dependencyRows = [System.Collections.Generic.List[object]]::new()
        $dependencyIndex = 0
        foreach ($rawDependency in $manifestModel.dependencies) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.dependencies' -Progress ("parent={0};dependencies={1};edges={2}" -f $parentId, $dependencyIndex, $graphEdges.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
            $dependencyIndex++
            $dependency = Resolve-D32BoundedDiagnosticWorkspaceDependency -Dependency $rawDependency -WorkspaceManifest $workspaceModel
            Assert-D32BoundedDiagnosticDependencyFields -Fields $dependency.fields
            $nonRootDev = ([string]$dependency.kind -ceq 'dev-dependencies' -and $parentId -cne $rootIds[0])
            $condition = if ([String]::IsNullOrEmpty([string]$dependency.target)) { [PSCustomObject]@{ value = $true; proven = $true; witness = 'unconditional dependency' } } else { Get-D32BoundedDiagnosticTargetPredicate -Expression ([string]$dependency.target) -TargetTriple ([string]$Plan.target_triple) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds }
            $resolvedTargets = [System.Collections.Generic.List[object]]::new()
            $declarationFields = $dependency.fields
            $targetName = if ($declarationFields.ContainsKey('package')) { [string]$declarationFields['package'].value } else { [string]$dependency.alias }
            $targetNameKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@([string]$parentId, $targetName))
            $candidateLockEdges = if ($edgeByParentAndTargetName.ContainsKey($targetNameKey)) { $edgeByParentAndTargetName[$targetNameKey] } else { $null }
            $expectedSource = Get-D32BoundedDiagnosticDependencyExpectedSource -Dependency $dependency -RootManifest $selectedRootWorkspace -ParentPackage $parentPackage -RootPatchIndex $rootPatchByName
            $versionField = if ($declarationFields.ContainsKey('version')) { $declarationFields['version'] } else { $null }
            if ($null -ne $versionField -and [string]$versionField.kind -cne 'string') { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency version is not a supported string' }
            $requirement = if ($null -eq $versionField) { '*' } else { [string]$versionField.value }
            $edgeCandidateIndex = 0
            foreach ($edge in $candidateLockEdges) {
                if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.edge_candidates' -Progress ("parent={0};name={1};candidates={2}" -f $parentId, $targetName, $edgeCandidateIndex) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
                $edgeCandidateIndex++
                $candidateComparisonCount++
                $candidateComparisonCharacters = [Int64]$requirement.Length + [Int64]$targetPackage.version.Length
                $candidateComparisonCharacterWork += [Math]::Max(1L, $candidateComparisonCharacters)
                if ($candidateComparisonCount -gt [Int64]$script:D32BoundedDiagnosticGraphCandidateComparisonLimit -or $candidateComparisonCharacterWork -gt 16777216L) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency-to-lock candidate comparisons exceed the fixed graph work bound'
                }
                $targetPackage = $packageById[[string]$edge.target_package_id]
                if ([string]$targetPackage.name -cne $targetName) { continue }
                if (-not (Test-D32BoundedDiagnosticVersionRequirement -Requirement $requirement -LockedVersion ([string]$targetPackage.version))) { continue }
                if ([string]$targetPackage.source_kind -cne [string]$expectedSource.source_kind -or
                    (($null -eq $expectedSource.source) -ne ($null -eq $targetPackage.source)) -or
                    ($null -ne $expectedSource.source -and [string]$targetPackage.source -cne [string]$expectedSource.source)) { continue }
                if ($expectedSource.PSObject.Properties['path'] -and -not [String]::IsNullOrEmpty([string]$expectedSource.path)) {
                    if (-not $manifestById.ContainsKey([string]$targetPackage.package_id)) { continue }
                    $pathParentPackage = $parentPackage; $pathParentManifest = $manifestModel
                    if ([string]$expectedSource.path_base -ceq 'SELECTED_WORKSPACE_PATCH_MANIFEST') { $pathParentPackage = $packageById[$rootIds[0]]; $pathParentManifest = $selectedRootWorkspace }
                    if (-not (Test-D32BoundedDiagnosticPathDependencyBinding -ParentPackage $pathParentPackage -ParentManifest $pathParentManifest -TargetPackage $targetPackage -TargetManifest $manifestById[[string]$targetPackage.package_id] -Path ([string]$expectedSource.path))) { continue }
                }
                $resolvedTargets.Add($edge)
                if ($resolvedTargets.Count -gt 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: dependency declaration resolves ambiguously to multiple exact lock edges' }
            }
            if ($nonRootDev) {
                if ($resolvedTargets.Count -gt 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: non-root development dependency maps ambiguously to lock edges' }
                if ($resolvedTargets.Count -eq 1) { [void]$matchedLockEdges.Add(([string]$parentId + [char]0 + [string]$resolvedTargets[0].lock_spec)) }
                $dependencyRows.Add([PSCustomObject]@{ parent_package_id = $parentId; alias = [string]$dependency.alias; kind = [string]$dependency.kind; target = [string]$dependency.target; disposition = 'EXCLUDED_NONROOT_DEV_DEPENDENCY'; predicate_proven = [bool]$condition.proven; predicate_witness = 'Cargo does not build dependency-package dev-dependencies for selected root all-targets command'; target_package_id = if ($resolvedTargets.Count -eq 1) { [string]$resolvedTargets[0].target_package_id } else { $null }; lock_specs = @($resolvedTargets | ForEach-Object { [string]$_.lock_spec }); optional_included = ($dependency.fields.ContainsKey('optional') -and [bool]$dependency.fields['optional'].value) })
                continue
            }
            if (-not [bool]$condition.value) {
                $inactiveCfgCount++
                if ($resolvedTargets.Count -gt 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: inactive target dependency maps ambiguously to lock edges' }
                if ($resolvedTargets.Count -eq 1) { [void]$matchedLockEdges.Add(([string]$parentId + [char]0 + [string]$resolvedTargets[0].lock_spec)) }
                $dependencyRows.Add([PSCustomObject]@{ parent_package_id = $parentId; alias = [string]$dependency.alias; kind = [string]$dependency.kind; target = [string]$dependency.target; disposition = 'EXCLUDED_TARGET_PREDICATE_PROVEN_FALSE'; predicate_proven = [bool]$condition.proven; predicate_witness = [string]$condition.witness; target_package_id = if ($resolvedTargets.Count -eq 1) { [string]$resolvedTargets[0].target_package_id } else { $null }; lock_specs = @($resolvedTargets | ForEach-Object { [string]$_.lock_spec }); optional_included = ($dependency.fields.ContainsKey('optional') -and [bool]$dependency.fields['optional'].value) })
                continue
            }
            if (-not $condition.proven) { $unknownCfgCount++ }
            if ($resolvedTargets.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: active/conservatively included manifest dependency does not resolve to exactly one exact lock edge' }
            $edge = $resolvedTargets[0]; [void]$matchedLockEdges.Add(([string]$parentId + [char]0 + [string]$edge.lock_spec))
            $isOptional = ($dependency.fields.ContainsKey('optional') -and [bool]$dependency.fields['optional'].value)
            $graphEdges.Add([PSCustomObject]@{ parent_package_id = $parentId; target_package_id = [string]$edge.target_package_id; lock_spec = [string]$edge.lock_spec; dependency_alias = [string]$dependency.alias; kind = [string]$dependency.kind; target_predicate = [string]$dependency.target; predicate_proven = [bool]$condition.proven; predicate_witness = [string]$condition.witness; optional_included = $isOptional })
            $dependencyRows.Add([PSCustomObject]@{ parent_package_id = $parentId; alias = [string]$dependency.alias; kind = [string]$dependency.kind; target = [string]$dependency.target; disposition = if ($condition.proven) { 'INCLUDED' } else { 'INCLUDED_UNKNOWN_CFG' }; predicate_proven = [bool]$condition.proven; predicate_witness = [string]$condition.witness; target_package_id = [string]$edge.target_package_id; lock_specs = @([string]$edge.lock_spec); optional_included = $isOptional })
            if (-not $visited.Contains([string]$edge.target_package_id)) {
                $queue.Enqueue([string]$edge.target_package_id)
                if (-not $parentPath.ContainsKey([string]$edge.target_package_id)) {
                    $parentPath[[string]$edge.target_package_id] = $parentId
                    $depthById[[string]$edge.target_package_id] = [int]$depthById[$parentId] + 1
                }
            }
        }
        $lockEdgeIndex = 0
        foreach ($edge in $lockEdges) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.reconcile_parent_edges' -Progress ("parent={0};edges={1}/{2}" -f $parentId, $lockEdgeIndex, $lockEdges.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
            if (-not $matchedLockEdges.Contains(([string]$parentId + [char]0 + [string]$edge.lock_spec))) {
                throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: reachable parent has an unexplained lock dependency edge not reconciled with its complete manifest declarations'
            }
            $lockEdgeIndex++
        }
        $decisionIndex = 0
        foreach ($decision in $dependencyRows) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.append_parent_decisions' -Progress ("parent={0};decisions={1}/{2}" -f $parentId, $decisionIndex, $dependencyRows.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
            $dependencyDecisions.Add($decision); $decisionIndex++
        }
    }
    $rootSetCanonical = [string]::Join("`n", [string[]]$rootIds)
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.sort_included_ids' -Progress ("packages={0}" -f $visited.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $includedIds = [string[]]@($visited); [Array]::Sort($includedIds, [StringComparer]::Ordinal)
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.sort_included_ids_complete' -Progress ("packages={0}" -f $includedIds.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $excludedList = [System.Collections.Generic.List[string]]::new()
    $excludedScanIndex = 0
    foreach ($package in $Plan.locked_packages) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.excluded_id_scan' -Progress ("packages={0}/{1}" -f $excludedScanIndex, $Plan.locked_packages.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        if (-not $visited.Contains([string]$package.package_id)) { $excludedList.Add([string]$package.package_id) }
        $excludedScanIndex++
    }
    $excludedIds = [string[]]$excludedList.ToArray()
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.sort_excluded_ids' -Progress ("packages={0}" -f $excludedIds.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    [Array]::Sort($excludedIds, [StringComparer]::Ordinal)
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.sort_excluded_ids_complete' -Progress ("packages={0}" -f $excludedIds.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $edgeCanon = [System.Collections.Generic.List[string]]::new(); $manifestCanon = [System.Collections.Generic.List[string]]::new()
    $canonicalIndex = 0
    foreach ($id in $includedIds) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.canonical_manifests' -Progress ("rows={0}/{1}" -f $canonicalIndex, $includedIds.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $row = $manifestRecordById[$id]; $manifestCanon.Add($id + "`t" + [string]$row.source_kind + "`t" + [string]$row.source_identity + "`t" + [string]$row.source_path + "`t" + [string]$row.content_sha256); $canonicalIndex++
    }
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.sort_manifest_rows' -Progress ("rows={0}" -f $manifestCanon.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $manifestCanon.Sort([StringComparer]::Ordinal)
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.sort_manifest_rows_complete' -Progress ("rows={0}" -f $manifestCanon.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $canonicalIndex = 0
    foreach ($edge in $graphEdges) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.canonical_edges' -Progress ("rows={0}/{1}" -f $canonicalIndex, $graphEdges.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $edgeCanon.Add(([string]$edge.parent_package_id + "`t" + [string]$edge.target_package_id + "`t" + [string]$edge.dependency_alias + "`t" + [string]$edge.kind + "`t" + [string]$edge.target_predicate + "`t" + [string]$edge.predicate_witness + "`t" + [string]$edge.lock_spec)); $canonicalIndex++
    }
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.sort_edge_rows' -Progress ("rows={0}" -f $edgeCanon.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $edgeCanon.Sort([StringComparer]::Ordinal)
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.sort_edge_rows_complete' -Progress ("rows={0}" -f $edgeCanon.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $decisionCanon = [System.Collections.Generic.List[string]]::new()
    $canonicalIndex = 0
    foreach ($decision in $dependencyDecisions) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.canonical_decisions' -Progress ("rows={0}/{1}" -f $canonicalIndex, $dependencyDecisions.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $decisionCanon.Add(([string]$decision.parent_package_id + "`t" + [string]$decision.alias + "`t" + [string]$decision.kind + "`t" + [string]$decision.target + "`t" + [string]$decision.disposition + "`t" + [string]$decision.predicate_witness + "`t" + [string]$decision.target_package_id + "`t" + [string]::Join(',', [string[]]$decision.lock_specs) + "`t" + [string]$decision.predicate_proven + "`t" + [string]$decision.optional_included)); $canonicalIndex++
    }
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.sort_decision_rows' -Progress ("rows={0}" -f $decisionCanon.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $decisionCanon.Sort([StringComparer]::Ordinal)
    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.sort_decision_rows_complete' -Progress ("rows={0}" -f $decisionCanon.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' }
    $closedSetSha = Get-D32BoundedDiagnosticSha256FromLines -Lines $includedIds -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'source_graph.closed_set_digest'
    $manifestSha = Get-D32BoundedDiagnosticSha256FromLines -Lines ([string[]]$manifestCanon.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'source_graph.manifest_digest'
    $graphSha = Get-D32BoundedDiagnosticSourceGraphDigest -LockSha256 ([string]$Plan.lock_sha256) `
        -LockDependencyEdgesSha256 ([string]$Plan.lock_dependency_edges_sha256) -RootIds ([string[]]$rootIds) `
        -EdgeRows ([string[]]$edgeCanon.ToArray()) -DecisionRows ([string[]]$decisionCanon.ToArray()) `
        -ClosedSetSha256 $closedSetSha -ManifestSetSha256 $manifestSha -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
    $pathUtf8BytesById = [System.Collections.Generic.Dictionary[string,Int64]]::new([StringComparer]::Ordinal)
    $witnessArrayLowerBound = [Int64]0; $witnessBudgetIndex = 0
    foreach ($id in $visitOrder) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.witness_budget' -Progress ("packages={0}/{1};lower_bound_bytes={2}" -f $witnessBudgetIndex, $visitOrder.Count, $witnessArrayLowerBound) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $pathBytes = if ($parentPath[$id] -ceq $id) { [Int64]$id.Length } else { [Int64]$pathUtf8BytesById[[string]$parentPath[$id]] + [Int64]$id.Length }
        $pathUtf8BytesById.Add($id, $pathBytes)
        $pathCount = [Int64]$depthById[$id] + 1L
        $arrayLowerBound = $pathBytes + (3L * $pathCount) + 1L
        if ($witnessArrayLowerBound -gt ([Int64]::MaxValue - $arrayLowerBound)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: included root-path witnesses exceed checked arithmetic bounds' }
        $witnessArrayLowerBound += $arrayLowerBound
        $witnessBudgetIndex++
    }
    if ($witnessArrayLowerBound -gt $script:D32BoundedDiagnosticSourceProofMaximumOutputBytes) {
        throw ('D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: exhaustive included-root path witnesses alone exceed the fixed {0}-byte output ceiling; witness_array_lower_bound_bytes={1}' -f $script:D32BoundedDiagnosticSourceProofMaximumOutputBytes, $witnessArrayLowerBound)
    }
    $classifications = [System.Collections.Generic.List[object]]::new()
    $classificationIndex = 0
    foreach ($id in $includedIds) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.witness_materialize' -Progress ("packages={0}/{1}" -f $classificationIndex, $includedIds.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $row = $manifestRecordById[$id]
        $pathLength = [int]$depthById[$id] + 1
        $path = [string[]]::new($pathLength); $cursor = $id; $pathIndex = $pathLength - 1
        while ($pathIndex -gt 0) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.witness_path' -Progress ("package={0};remaining={1}" -f $id, $pathIndex) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
            if (-not $parentPath.ContainsKey($cursor)) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: included package lacks a bounded root reachability witness path' }
            $path[$pathIndex] = $cursor
            $cursor = [string]$parentPath[$cursor]
            $pathIndex--
        }
        if ($pathLength -eq 1) { $path[0] = $id } else { $path[0] = $cursor }
        if ([string]$path[0] -cne [string]$rootIds[0]) { throw 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED: computed witness root differs from the selected root' }
        $classifications.Add([PSCustomObject]@{ package_id = $id; classification = 'INCLUDED'; source_kind = [string]$packageById[$id].source_kind; source_identity = [string]$row.source_identity; manifest_path = [string]$row.source_path; manifest_sha256 = [string]$row.content_sha256; witness_kind = 'ROOT_PATH_IN_VERIFIED_DECLARATION_GRAPH'; witness_root_path = $path; closed_reachability_sha256 = $closedSetSha })
        $classificationIndex++
    }
    foreach ($id in $excludedIds) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'source_graph.exclusion_materialize' -Progress ("classifications={0}/{1}" -f $classificationIndex, $packageById.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED' -NoProgress }
        $classifications.Add([PSCustomObject]@{ package_id = $id; classification = 'EXCLUDED_WITH_WITNESS'; source_kind = [string]$packageById[$id].source_kind; source_identity = if ($null -eq $packageById[$id].source) { 'workspace' } else { [string]$packageById[$id].source }; witness_kind = 'CLOSED_REACHABILITY_CUT'; unreachable_from_roots = @($rootIds); complete_reachable_parent_count = [Int64]$visited.Count; complete_reachable_dependency_decision_count = [Int64]$dependencyDecisions.Count; no_active_incoming_edge_from_included = $true; closed_reachability_sha256 = $closedSetSha }); $classificationIndex++
    }
    return [PSCustomObject][ordered]@{
        schema_version = 2; record_type = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_GRAPH_PROOF_V2'; gate_authority = 'NONE'; formal_gate_usable = $false
        status = 'CURRENT_LOCKED_SOURCE_GRAPH_VERIFIED_FOR_DIAGNOSTIC_ONLY'; semantic_scope = [string]$Plan.semantic_scope
        lock_sha256 = [string]$Plan.lock_sha256; lock_dependency_edges_sha256 = [string]$Plan.lock_dependency_edges_sha256; graph_sha256 = $graphSha
        root_manifest_path = $RootManifestPath; selected_root_ids = @($rootIds); root_selection_rule = 'EXACT_PACKAGE_NAMED_BY_MANIFEST_PATH_DEFAULT_FEATURES_PLUS_D32_A_TEST_HELPER_NO_WORKSPACE_EXPANSION'
        host_triple = [string]$Plan.host_triple; target_triple = [string]$Plan.target_triple; target_resolution_scope = 'ONE_FIXED_X86_64_PC_WINDOWS_MSVC_HOST_AND_TARGET'
        locked_package_count = [Int64]$packageById.Count; included_package_ids = @($includedIds); included_package_count = [Int64]$includedIds.Count
        excluded_package_count = [Int64]$excludedIds.Count; classification_count = [Int64]$classifications.Count; classifications = @($classifications.ToArray())
        included_edges = @($graphEdges.ToArray()); dependency_decisions = @($dependencyDecisions.ToArray()); inactive_target_edge_count = $inactiveCfgCount; unknown_cfg_conservative_include_count = $unknownCfgCount; included_manifest_set_sha256 = $manifestSha
        feature_rule = 'ALL_OPTIONAL_AND_FEATURE_ACTIVATION_EDGES_INCLUDED_UNLESS_TARGET_PREDICATE_PROVEN_FALSE'
        root_dev_dependency_rule = 'INCLUDED_FOR_SELECTED_PACKAGE_ALL_TARGETS'; nonroot_dev_dependency_rule = 'EXCLUDED_NOT_BUILT_FOR_DEPENDENCY_PACKAGE'
        build_proc_macro_rule = 'INCLUDED_HOST_EQUALS_TARGET'; closed_reachability_set_sha256 = $closedSetSha; source_plan_version = 2
        selected_target_mode = 'ALL_TARGETS_FOR_SELECTED_PACKAGE_ONLY'; selected_crate_kinds = @('lib', 'bin', 'example', 'test', 'bench', 'custom-build', 'proc-macro')
    }
}

function Read-D32BoundedCompilerDiagnosticStreamExact {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][int]$Count,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds,
        [string]$Phase = 'registry.archive_stream_read')
    if ($Count -lt 0 -or $Count -gt 65536) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: invalid bounded read length' }
    $buffer = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase $Phase -Progress ("bytes={0}/{1}" -f $offset, $Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED' }
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase $Phase -Progress ("bytes={0}/{1}" -f ($offset + $read), $Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED' }
        if ($read -le 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: truncated tar stream' }
        $offset += $read
    }
    return ,$buffer
}

function Get-D32BoundedCompilerDiagnosticTarText {
    param([Parameter(Mandatory = $true)][byte[]]$Header, [Parameter(Mandatory = $true)][int]$Offset, [Parameter(Mandatory = $true)][int]$Length)
    $end = $Offset + $Length
    $zero = $end
    for ($index = $Offset; $index -lt $end; $index++) { if ($Header[$index] -eq 0) { $zero = $index; break } }
    for ($index = $zero; $index -lt $end; $index++) {
        if ($Header[$index] -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar text field has nonzero bytes after terminator' }
    }
    try { return [Text.UTF8Encoding]::new($false, $true).GetString($Header, $Offset, $zero - $Offset) }
    catch { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar path is not strict UTF-8' }
}

function Get-D32BoundedCompilerDiagnosticTarTextField {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Header,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][int]$Length,
        [switch]$AllowInvalidUtf8
    )
    if ($Offset -lt 0 -or $Length -lt 1 -or ($Offset + $Length) -gt $Header.Length) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar text field is outside the fixed header'
    }
    $raw = [byte[]]$Header[$Offset..($Offset + $Length - 1)]
    $contentLength = $Length
    for ($index = 0; $index -lt $Length; $index++) {
        if ($raw[$index] -eq 0) { $contentLength = $index; break }
    }
    for ($index = $contentLength; $index -lt $Length; $index++) {
        if ($raw[$index] -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar text field has nonzero bytes after terminator' }
    }
    $content = [byte[]]::new($contentLength)
    if ($contentLength -gt 0) { [Array]::Copy($raw, 0, $content, 0, $contentLength) }
    $text = $null
    $decoded = $true
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($content, 0, $content.Length) }
    catch {
        if (-not $AllowInvalidUtf8) { throw ('D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar path field at byte offset ' + $Offset.ToString([Globalization.CultureInfo]::InvariantCulture) + ' is not strict UTF-8 (' + [string]$_.Exception.Message + ')') }
        $decoded = $false
    }
    return [PSCustomObject][ordered]@{
        text = $text
        decoded = [bool]$decoded
        content_bytes = $content
        content_length = [Int64]$contentLength
        field_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($raw)).ToLowerInvariant()
        all_zero = [bool]($contentLength -eq 0)
        raw_bytes = $raw
    }
}

function Get-D32BoundedCompilerDiagnosticTarOctal {
    param([Parameter(Mandatory = $true)][byte[]]$Header, [Parameter(Mandatory = $true)][int]$Offset, [Parameter(Mandatory = $true)][int]$Length)
    if ($Offset -lt 0 -or $Length -lt 1 -or $Length -gt 16 -or ($Offset + $Length) -gt $Header.Length -or
        ($Header[$Offset] -band 0x80) -ne 0) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar numeric field is unsupported or out of bounds'
    }
    $end = $Offset + $Length
    $cursor = $Offset
    while ($cursor -lt $end -and $Header[$cursor] -eq 32) { $cursor++ }
    if ($cursor -eq $end) { return [Int64]0 }
    $value = [Int64]0
    $digitCount = 0
    while ($cursor -lt $end -and $Header[$cursor] -ge 48 -and $Header[$cursor] -le 55) {
        $digit = [Int64]($Header[$cursor] - 48)
        if ($value -gt ([Int64]::MaxValue - $digit) / 8L) {
            throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar numeric field overflows its bound'
        }
        $value = ($value * 8L) + $digit
        $digitCount++
        $cursor++
    }
    if ($digitCount -eq 0) {
        for ($index = $Offset; $index -lt $end; $index++) {
            if ($Header[$index] -ne 0 -and $Header[$index] -ne 32) {
                throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar numeric field is not strict octal'
            }
        }
        return [Int64]0
    }
    if ($cursor -eq $end) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar numeric field lacks its required NUL/space terminator'
    }
    while ($cursor -lt $end) {
        if ($Header[$cursor] -ne 0 -and $Header[$cursor] -ne 32) {
            throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar numeric field has hidden or noncanonical trailing data'
        }
        $cursor++
    }
    return $value
}

function Test-D32BoundedCompilerDiagnosticTarZeroBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][int]$Offset, [Parameter(Mandatory = $true)][int]$Length)
    if ($Offset -lt 0 -or $Length -lt 0 -or ($Offset + $Length) -gt $Bytes.Length) { return $false }
    for ($index = $Offset; $index -lt ($Offset + $Length); $index++) { if ($Bytes[$index] -ne 0) { return $false } }
    return $true
}

function Test-D32BoundedCompilerDiagnosticByteArraysEqual {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Left,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Right
    )
    if ($Left.Length -ne $Right.Length) { return $false }
    for ($index = 0; $index -lt $Left.Length; $index++) { if ($Left[$index] -ne $Right[$index]) { return $false } }
    return $true
}

function Get-D32BoundedDiagnosticRegistryArchiveHeader {
    param([Parameter(Mandatory = $true)][byte[]]$Header, [switch]$AllowRawNameProjection)
    if ($Header.Length -ne 512) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar header is not exactly 512 bytes' }
    $checksum = Get-D32BoundedCompilerDiagnosticTarOctal -Header $Header -Offset 148 -Length 8
    $actualChecksum = [Int64]0
    for ($index = 0; $index -lt 512; $index++) {
        $actualChecksum += if ($index -ge 148 -and $index -lt 156) { 32 } else { [Int64]$Header[$index] }
    }
    $magic = [byte[]]$Header[257..262]
    $version = [byte[]]$Header[263..264]
    $magicHex = [Convert]::ToHexString($magic).ToLowerInvariant()
    $versionHex = [Convert]::ToHexString($version).ToLowerInvariant()
    $format = if ($magicHex -ceq '757374617200' -and $versionHex -ceq '3030') { 'USTAR' }
        elseif ($magicHex -ceq '757374617220' -and $versionHex -ceq '2000') { 'GNU' }
        else { $null }
    if ($actualChecksum -ne $checksum -or $null -eq $format) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: header checksum or approved USTAR/GNU format validation failed'
    }

    $mode = Get-D32BoundedCompilerDiagnosticTarOctal -Header $Header -Offset 100 -Length 8
    $uid = Get-D32BoundedCompilerDiagnosticTarOctal -Header $Header -Offset 108 -Length 8
    $gid = Get-D32BoundedCompilerDiagnosticTarOctal -Header $Header -Offset 116 -Length 8
    $size = Get-D32BoundedCompilerDiagnosticTarOctal -Header $Header -Offset 124 -Length 12
    $mtime = Get-D32BoundedCompilerDiagnosticTarOctal -Header $Header -Offset 136 -Length 12
    $linkName = Get-D32BoundedCompilerDiagnosticTarText -Header $Header -Offset 157 -Length 100
    if (-not (Test-D32BoundedCompilerDiagnosticTarZeroBytes -Bytes $Header -Offset 157 -Length 100)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar linkname is not the required all-zero field'
    }
    $uname = Get-D32BoundedCompilerDiagnosticTarText -Header $Header -Offset 265 -Length 32
    $gname = Get-D32BoundedCompilerDiagnosticTarText -Header $Header -Offset 297 -Length 32
    $devmajor = Get-D32BoundedCompilerDiagnosticTarOctal -Header $Header -Offset 329 -Length 8
    $devminor = Get-D32BoundedCompilerDiagnosticTarOctal -Header $Header -Offset 337 -Length 8
    if ($devmajor -ne 0 -or $devminor -ne 0) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar device numbers must be zero'
    }

    $nameField = Get-D32BoundedCompilerDiagnosticTarTextField -Header $Header -Offset 0 -Length 100 -AllowInvalidUtf8:$AllowRawNameProjection
    $name = if ($nameField.decoded) { [string]$nameField.text } else { $null }
    $prefix = ''
    $prefixFieldSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$Header[345..499])).ToLowerInvariant()
    if ($format -ceq 'USTAR') {
        $prefixField = Get-D32BoundedCompilerDiagnosticTarTextField -Header $Header -Offset 345 -Length 155
        $prefix = [string]$prefixField.text
        $prefixFieldSha256 = [string]$prefixField.field_sha256
        if (-not (Test-D32BoundedCompilerDiagnosticTarZeroBytes -Bytes $Header -Offset 500 -Length 12)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: USTAR reserved tail bytes are nonzero'
        }
    }
    else {
        $atime = Get-D32BoundedCompilerDiagnosticTarOctal -Header $Header -Offset 345 -Length 12
        $ctime = Get-D32BoundedCompilerDiagnosticTarOctal -Header $Header -Offset 357 -Length 12
        $multiVolumeOffset = Get-D32BoundedCompilerDiagnosticTarOctal -Header $Header -Offset 369 -Length 12
        if ($multiVolumeOffset -ne 0 -or
            -not (Test-D32BoundedCompilerDiagnosticTarZeroBytes -Bytes $Header -Offset 381 -Length 5) -or
            -not (Test-D32BoundedCompilerDiagnosticTarZeroBytes -Bytes $Header -Offset 386 -Length 96) -or
            $Header[482] -ne 0) {
            throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU multi-volume, reserved, sparse, or continuation fields are unsupported'
        }
        $realSize = Get-D32BoundedCompilerDiagnosticTarOctal -Header $Header -Offset 483 -Length 12
        if ($realSize -ne 0 -or -not (Test-D32BoundedCompilerDiagnosticTarZeroBytes -Bytes $Header -Offset 495 -Length 17)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU real-size or tail padding field is unsupported'
        }
        $null = $atime
        $null = $ctime
    }
    $typeFlag = [int]$Header[156]
    $kind = if ($typeFlag -eq 76) { 'longname' } elseif ($typeFlag -eq 53) { 'directory' } elseif ($typeFlag -eq 48 -or $typeFlag -eq 0) { 'file' } else { $null }
    if ($null -eq $kind) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: links, non-longname extensions, sparse files, and special tar entries are unsupported'
    }
    if ($kind -ceq 'longname' -and ($format -cne 'GNU' -or $nameField.content_length -ne 13 -or
        [Text.Encoding]::ASCII.GetString([byte[]]$nameField.content_bytes) -cne '././@LongLink' -or
        $size -lt 2 -or $size -gt 4097)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname control header has an invalid format, placeholder, or bounded size'
    }
    if ($kind -ceq 'directory' -and $size -ne 0) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar directory entry has nonzero data'
    }
    $fullName = if ($null -eq $name) { $null } elseif ([String]::IsNullOrEmpty($prefix)) { $name } else { $prefix + '/' + $name }
    if ($kind -ceq 'directory' -and $null -ne $fullName -and $fullName.EndsWith('/')) { $fullName = $fullName.Substring(0, $fullName.Length - 1) }
    return [PSCustomObject][ordered]@{
        format = $format
        name = $name
        prefix = $prefix
        path = $fullName
        name_field_content_bytes = [byte[]]$nameField.content_bytes
        name_field_raw_bytes = [byte[]]$nameField.raw_bytes
        name_field_content_length = [Int64]$nameField.content_length
        name_field_sha256 = [string]$nameField.field_sha256
        name_field_all_zero = [bool]$nameField.all_zero
        prefix_field_sha256 = [string]$prefixFieldSha256
        name_field_decoded = [bool]$nameField.decoded
        type_flag = $typeFlag
        kind = $kind
        size = [Int64]$size
        mode = [Int64]$mode
        uid = [Int64]$uid
        gid = [Int64]$gid
        mtime = [Int64]$mtime
        uname = $uname
        gname = $gname
        checksum = [Int64]$checksum
        header_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Header)).ToLowerInvariant()
    }
}

function ConvertFrom-D32BoundedCompilerDiagnosticGnuLongNamePayload {
    param([Parameter(Mandatory = $true)][byte[]]$Payload, [Parameter(Mandatory = $true)][string]$NextKind)
    if ($Payload.Length -lt 2 -or $Payload.Length -gt 4097 -or $Payload[$Payload.Length - 1] -ne 0) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname payload length or terminal NUL is invalid'
    }
    $pathLength = $Payload.Length - 1
    if ($pathLength -lt 1) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname payload path is empty' }
    for ($index = 0; $index -lt $pathLength; $index++) {
        if ($Payload[$index] -eq 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname payload contains an interior NUL' }
    }
    $pathBytes = [byte[]]$Payload[0..($pathLength - 1)]
    if ($pathBytes.Length -ge 3 -and $pathBytes[0] -eq 0xef -and $pathBytes[1] -eq 0xbb -and $pathBytes[2] -eq 0xbf) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname payload contains a UTF-8 BOM'
    }
    try { $path = [Text.UTF8Encoding]::new($false, $true).GetString($pathBytes) }
    catch { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname payload is not strict UTF-8' }
    if (-not [StringComparer]::Ordinal.Equals($path.Normalize([Text.NormalizationForm]::FormC), $path)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname payload is not already NFC'
    }
    $hadDirectorySlash = $path.EndsWith('/')
    if ($hadDirectorySlash) {
        if ($NextKind -cne 'directory' -or $path.EndsWith('//')) {
            throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname trailing slash is only valid once for a directory'
        }
        $path = $path.Substring(0, $path.Length - 1)
        $pathBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($path)
    }
    if (-not (Test-D32BoundedCompilerDiagnosticTarPath $path)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname effective path is unsafe or noncanonical'
    }
    return [PSCustomObject][ordered]@{
        encoded_path = [string]$path
        effective_path = [string]$path
        effective_path_bytes = [byte[]]$pathBytes
        directory_structural_slash_removed = [bool]$hadDirectorySlash
        control_payload_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Payload)).ToLowerInvariant()
        control_payload_bytes = [Int64]$Payload.Length
    }
}

function Get-D32BoundedCompilerDiagnosticGnuLongNameBinding {
    param([Parameter(Mandatory = $true)][object]$Pending, [Parameter(Mandatory = $true)][object]$HeaderRecord)
    if ([string]$HeaderRecord.kind -notin @('file', 'directory')) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname is not followed by an ordinary file or directory'
    }
    $expected = [byte[]]$Pending.effective_path_bytes
    $nameBytes = [byte[]]$HeaderRecord.name_field_content_bytes
    $prefixBytes = if ([string]$HeaderRecord.format -ceq 'USTAR' -and -not [String]::IsNullOrEmpty([string]$HeaderRecord.prefix)) {
        [Text.UTF8Encoding]::new($false, $true).GetBytes([string]$HeaderRecord.prefix)
    } else { [byte[]]::new(0) }
    $exact = $false
    if ([string]$HeaderRecord.format -ceq 'USTAR' -and $prefixBytes.Length -gt 0) {
        $joined = [byte[]]::new($prefixBytes.Length + 1 + $nameBytes.Length)
        [Array]::Copy($prefixBytes, 0, $joined, 0, $prefixBytes.Length)
        $joined[$prefixBytes.Length] = 47
        [Array]::Copy($nameBytes, 0, $joined, $prefixBytes.Length + 1, $nameBytes.Length)
        $exact = Test-D32BoundedCompilerDiagnosticByteArraysEqual -Left $joined -Right $expected
    }
    else { $exact = Test-D32BoundedCompilerDiagnosticByteArraysEqual -Left $nameBytes -Right $expected }
    if ($exact) { return 'FULL_EXACT' }

    if ([string]$HeaderRecord.format -ceq 'GNU' -and [bool]$HeaderRecord.name_field_decoded -and
        [bool]$HeaderRecord.name_field_all_zero -and $expected.Length -gt 100) { return 'GNU_EXPLICIT_EMPTY' }

    if ([string]::IsNullOrEmpty([string]$HeaderRecord.prefix) -and $expected.Length -gt 100) {
        if ($nameBytes.Length -eq 100) {
            $prefix = [byte[]]$expected[0..99]
            if (Test-D32BoundedCompilerDiagnosticByteArraysEqual -Left $nameBytes -Right $prefix) { return 'RAW_100_BYTE_PREFIX' }
        }
        $boundary = 0
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        for ($length = 99; $length -ge 1; $length--) {
            try {
                $candidate = $utf8.GetString([byte[]]$expected[0..($length - 1)])
                if ($utf8.GetByteCount($candidate) -eq $length) { $boundary = $length; break }
            } catch { }
        }
        if ($boundary -in @(99, 100) -and $nameBytes.Length -eq $boundary -and
            (Test-D32BoundedCompilerDiagnosticByteArraysEqual -Left $nameBytes -Right ([byte[]]$expected[0..($boundary - 1)]))) {
            return ('UTF8_BOUNDARY_' + $boundary.ToString([Globalization.CultureInfo]::InvariantCulture))
        }
    }
    throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname fallback fields do not bind to the exact pending path'
}

function New-D32BoundedCompilerDiagnosticGnuLongNamePair {
    param(
        [Parameter(Mandatory = $true)][object]$Pending,
        [Parameter(Mandatory = $true)][object]$HeaderRecord,
        [Parameter(Mandatory = $true)][long]$NextHeaderOffset,
        [Parameter(Mandatory = $true)][string]$FallbackKind,
        [Parameter(Mandatory = $true)][string]$EffectivePath
    )
    return [PSCustomObject][ordered]@{
        longname_offset = [Int64]$Pending.offset
        longname_header_sha256 = [string]$Pending.header_sha256
        longname_size = [Int64]$Pending.size
        control_payload_sha256 = [string]$Pending.control_payload_sha256
        next_header_offset = [Int64]$NextHeaderOffset
        next_header_sha256 = [string]$HeaderRecord.header_sha256
        ordinary_format = [string]$HeaderRecord.format
        ordinary_type_flag = [Int64]$HeaderRecord.type_flag
        ordinary_size = [Int64]$HeaderRecord.size
        raw_name_field_sha256 = [string]$HeaderRecord.name_field_sha256
        raw_prefix_field_sha256 = [string]$HeaderRecord.prefix_field_sha256
        effective_path = $EffectivePath
        fallback_kind = $FallbackKind
    }
}

function Get-D32BoundedCompilerDiagnosticLongNamePairDigest {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Pairs,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds)
    $canonical = [System.Collections.Generic.List[string]]::new()
    $pairIndex = 0
    foreach ($pair in $Pairs) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.pair_inventory_digest' -Progress ("pairs={0}/{1}" -f $pairIndex, $Pairs.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED' -NoProgress }
        $canonical.Add([string]::Join("`t", [string[]]@(
            ([Int64]$pair.longname_offset).ToString([Globalization.CultureInfo]::InvariantCulture),
            [string]$pair.longname_header_sha256,
            ([Int64]$pair.longname_size).ToString([Globalization.CultureInfo]::InvariantCulture),
            [string]$pair.control_payload_sha256,
            ([Int64]$pair.next_header_offset).ToString([Globalization.CultureInfo]::InvariantCulture),
            [string]$pair.next_header_sha256,
            [string]$pair.ordinary_format,
            ([Int64]$pair.ordinary_type_flag).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$pair.ordinary_size).ToString([Globalization.CultureInfo]::InvariantCulture),
            [string]$pair.raw_name_field_sha256,
            [string]$pair.raw_prefix_field_sha256,
            [string]$pair.effective_path,
            [string]$pair.fallback_kind)))
        $pairIndex++
    }
    return Get-D32BoundedDiagnosticSha256FromLines -Lines ([string[]]$canonical.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.pair_inventory_digest_hash'
}

function Get-D32BoundedCompilerDiagnosticLongNameControlDigest {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Pairs,
        [Diagnostics.Stopwatch]$ProofTimer = $script:D32BoundedDiagnosticSourceProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds)
    $canonical = [System.Collections.Generic.List[string]]::new()
    $pairIndex = 0
    foreach ($pair in $Pairs) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.control_metadata_digest' -Progress ("pairs={0}/{1}" -f $pairIndex, $Pairs.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED' -NoProgress }
        $offset = if ($null -ne $pair.PSObject.Properties['longname_offset']) { [Int64]$pair.longname_offset } else { [Int64]$pair.offset }
        $size = if ($null -ne $pair.PSObject.Properties['longname_size']) { [Int64]$pair.longname_size } else { [Int64]$pair.size }
        $canonical.Add($offset.ToString([Globalization.CultureInfo]::InvariantCulture) + "`t" +
            $size.ToString([Globalization.CultureInfo]::InvariantCulture) + "`t" + [string]$pair.control_payload_sha256)
        $pairIndex++
    }
    return Get-D32BoundedDiagnosticSha256FromLines -Lines ([string[]]$canonical.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.control_metadata_digest_hash'
}

function Test-D32BoundedCompilerDiagnosticTarPath {
    param([AllowNull()][string]$Path)
    if ($null -eq $Path -or [String]::IsNullOrEmpty($Path) -or $Path.Length -gt 4096 -or
        $Path -match '[\\:\x00-\x1f\x7f<>"|?*]' -or $Path.StartsWith('/') -or $Path.StartsWith('\') -or
        -not [StringComparer]::Ordinal.Equals($Path.Normalize([Text.NormalizationForm]::FormC), $Path)) { return $false }
    foreach ($segment in $Path.Split('/')) {
        if ([String]::IsNullOrEmpty($segment) -or $segment -ceq '.' -or $segment -ceq '..' -or
            $segment.EndsWith('.') -or $segment.EndsWith(' ') -or
            $segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$') { return $false }
    }
    return $true
}

function Get-D32BoundedCompilerDiagnosticCrateArchiveInventory {
    param(
        [Parameter(Mandatory = $true)][byte[]]$CompressedBytes,
        [Parameter(Mandatory = $true)][string]$ExpectedPackageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedArchiveSha256,
        [long]$MaximumCompressedBytes = 268435456L,
        [long]$MaximumExpandedBytes = 1073741824L,
        [long]$MaximumMemberBytes = 134217728L,
        [int]$MaximumMembers = 10000,
        [Diagnostics.Stopwatch]$ProofTimer,
        [long]$DeadlineMilliseconds = $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds,
        [AllowNull()][string]$OpenedHandleSha256
    )
    if ($null -ne $ProofTimer -and (-not $ProofTimer.IsRunning -or (Get-D32BoundedDiagnosticSourceProofCurrentElapsedMilliseconds -ProofTimer $ProofTimer) -ge $DeadlineMilliseconds)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: aggregate source-proof timer is absent, stopped, or expired before archive parsing'
    }
    if ($CompressedBytes.Length -le 0 -or [Int64]$CompressedBytes.Length -gt $MaximumCompressedBytes -or
        $ExpectedArchiveSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedPackageRoot -cnotmatch '^[A-Za-z0-9_-]+-[0-9A-Za-z.+_-]+$' -or
        $MaximumExpandedBytes -le 0 -or $MaximumMemberBytes -le 0 -or $MaximumMembers -le 0 -or $MaximumMembers -gt 10000) {
        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive bytes, expected package identity, or finite parser bound is invalid'
    }
    $archiveSha = if ([String]::IsNullOrEmpty($OpenedHandleSha256)) {
        Get-D32BoundedDiagnosticSha256FromBytes -Bytes $CompressedBytes -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.archive_hash'
    } else { [string]$OpenedHandleSha256 }
    if ($archiveSha -cnotmatch '^[0-9a-f]{64}$') { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: opened-handle archive digest is malformed' }
    if ($archiveSha -cne $ExpectedArchiveSha256) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: compressed registry archive SHA-256 differs from Cargo.lock checksum' }
    $compressed = [IO.MemoryStream]::new($CompressedBytes, $false)
    $gzip = $null
    try {
        $gzip = [IO.Compression.GZipStream]::new($compressed, [IO.Compression.CompressionMode]::Decompress, $true)
        $expected = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        $rawNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $pathTrieRoot = [PSCustomObject]@{ segment = ''; path = ''; kind = 'directory'; explicit = $true; children = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase) }
        $rawMemberCount = 0
        $expandedBytes = [Int64]0
        $rootPrefix = $ExpectedPackageRoot + '/'
        $rootSeen = $false
        $manifestText = $null; $manifestContentSha256 = $null
        $headerRows = [System.Collections.Generic.List[object]]::new()
        $pairRows = [System.Collections.Generic.List[object]]::new()
        $controlMetadataRows = [System.Collections.Generic.List[object]]::new()
        $formatCounts = [ordered]@{ ustar_regular = 0L; ustar_directory = 0L; gnu_regular = 0L; gnu_directory = 0L; gnu_longname_extension = 0L }
        $ordinaryHeaderCount = [Int64]0
        $controlMetadataBytes = [Int64]0
        $pendingLongName = $null
        $ended = $false
        while (-not $ended) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.archive_headers' -Progress ("headers={0};expanded={1}" -f $rawMemberCount, $expandedBytes) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED' }
            $headerOffset = [Int64]$expandedBytes
            $header = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count 512 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.archive_header_read'
            $expandedBytes += 512
            if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: expanded archive exceeded its fixed byte ceiling' }
            $allZero = $true
            for ($index = 0; $index -lt 512; $index++) { if ($header[$index] -ne 0) { $allZero = $false; break } }
            if ($allZero) {
                if ($null -ne $pendingLongName) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname pending at tar terminator without its adjacent ordinary header' }
                $second = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count 512 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.archive_end_marker_read'
                $expandedBytes += 512
                for ($index = 0; $index -lt 512; $index++) { if ($second[$index] -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar terminator is not two complete zero blocks' } }
                while (($read = $gzip.Read($header, 0, 512)) -gt 0) {
                    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.archive_trailing_data' -Progress ("expanded={0}" -f $expandedBytes) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED' }
                    $expandedBytes += $read
                    if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: trailing archive data exceeds its fixed byte ceiling' }
                    for ($index = 0; $index -lt $read; $index++) { if ($header[$index] -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: nonzero data follows the tar terminator' } }
                }
                $ended = $true
                continue
            }
            $rawMemberCount++
            if ($rawMemberCount -gt $MaximumMembers) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive member count exceeds its fixed ceiling' }
            $headerRecord = Get-D32BoundedDiagnosticRegistryArchiveHeader -Header $header -AllowRawNameProjection:($null -ne $pendingLongName)
            $typeFlag = [int]$headerRecord.type_flag
            $size = [Int64]$headerRecord.size
            $isDirectory = [string]$headerRecord.kind -ceq 'directory'
            if ($size -lt 0 -or $size -gt $MaximumMemberBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: tar member exceeds its fixed byte ceiling' }
            if ([string]$headerRecord.kind -ceq 'longname') {
                if ($null -ne $pendingLongName) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: chained GNU longname controls are unsupported' }
                $payload = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count ([int]$size) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.archive_longname_read'
                $expandedBytes += [Int64]$size
                if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: expanded archive exceeded its fixed byte ceiling while reading GNU longname metadata' }
                $payloadSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($payload)).ToLowerInvariant()
                $padding = [int]((512 - ($size % 512)) % 512)
                if ($padding -gt 0) {
                    $pad = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count $padding -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.archive_longname_padding'
                    if (-not (Test-D32BoundedCompilerDiagnosticTarZeroBytes -Bytes $pad -Offset 0 -Length $pad.Length)) {
                        throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname control padding is nonzero'
                    }
                    $expandedBytes += $padding
                }
                if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: expanded archive exceeded its fixed byte ceiling after GNU longname metadata' }
                $controlMetadataBytes += [Int64]$size
                $controlMetadataRows.Add([PSCustomObject][ordered]@{ offset = $headerOffset; size = $size; control_payload_sha256 = $payloadSha })
                $headerRows.Add([PSCustomObject][ordered]@{
                    offset = $headerOffset; format = 'GNU_LONGNAME_EXTENSION'; path = ''; kind = 'control'
                    size = $size; type_flag = $typeFlag; header_sha256 = [string]$headerRecord.header_sha256
                    name_field_sha256 = [string]$headerRecord.name_field_sha256; prefix_field_sha256 = [string]$headerRecord.prefix_field_sha256
                    fallback_kind = ''
                })
                $formatCounts.gnu_longname_extension = [Int64]$formatCounts.gnu_longname_extension + 1L
                $pendingLongName = [PSCustomObject][ordered]@{
                    offset = $headerOffset; header_sha256 = [string]$headerRecord.header_sha256; size = $size
                    control_payload_sha256 = $payloadSha; expected_next_offset = [Int64]$expandedBytes; payload = $payload
                }
                continue
            }
            $fallbackKind = ''
            $fullName = [string]$headerRecord.path
            if ($null -ne $pendingLongName) {
                if ([Int64]$pendingLongName.expected_next_offset -ne $headerOffset) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: GNU longname is not physically adjacent to its ordinary header'
                }
                $longName = ConvertFrom-D32BoundedCompilerDiagnosticGnuLongNamePayload -Payload ([byte[]]$pendingLongName.payload) -NextKind ([string]$headerRecord.kind)
                $fallbackKind = Get-D32BoundedCompilerDiagnosticGnuLongNameBinding -Pending $longName -HeaderRecord $headerRecord
                $fullName = [string]$longName.effective_path
            }
            elseif ($null -eq $fullName) {
                throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: ordinary tar name is not strict UTF-8'
            }
            $ordinaryHeaderCount++
            if ($fullName -ceq $ExpectedPackageRoot) {
                if (-not $isDirectory -or $rootSeen -or -not $rawNames.Add($fullName)) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: package root header is duplicated or not a directory' }
                $rootSeen = $true
            }
            else {
                if (-not $fullName.StartsWith($rootPrefix, [StringComparison]::Ordinal) -or
                    -not (Test-D32BoundedCompilerDiagnosticTarPath $fullName) -or -not $rawNames.Add($fullName)) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive member path escaped, aliased, collided, or duplicated'
                }
                $relative = $fullName.Substring($rootPrefix.Length)
                if ($isDirectory) { $relative = $relative.TrimEnd('/') }
                if ([String]::IsNullOrEmpty($relative)) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: empty non-root member path is invalid' }
                $segments = $relative.Split('/'); $trieNode = $pathTrieRoot
                for ($segmentIndex = 0; $segmentIndex -lt $segments.Count; $segmentIndex++) {
                    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.archive_path_trie' -Progress ("member={0};segments={1}/{2};entries={3}" -f $rawMemberCount, $segmentIndex, $segments.Count, $expected.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED' -NoProgress }
                    if ([string]$trieNode.kind -ceq 'file') { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive member uses a file as a parent directory' }
                    $segment = [string]$segments[$segmentIndex]; $childNode = $null
                    if ($trieNode.children.TryGetValue($segment, [ref]$childNode)) {
                        if ([string]$childNode.segment -cne $segment) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive path collides by Windows case-insensitive segment identity' }
                    }
                    else {
                        $nodePath = if ([String]::IsNullOrEmpty([string]$trieNode.path)) { $segment } else { [string]$trieNode.path + '/' + $segment }
                        $childNode = [PSCustomObject]@{ segment = $segment; path = $nodePath; kind = 'directory'; explicit = $false; children = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase) }
                        $trieNode.children.Add($segment, $childNode)
                        if ($segmentIndex -lt ($segments.Count - 1) -or $isDirectory) {
                            $expected.Add($nodePath, [PSCustomObject]@{ path = $nodePath; kind = 'directory'; bytes = 0L; sha256 = $null })
                            if ($expected.Count -gt 10000) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: inferred source inventory exceeds the matching extracted-tree 10000-entry bound' }
                        }
                    }
                    $isFinalSegment = ($segmentIndex -eq ($segments.Count - 1))
                    if (-not $isFinalSegment) {
                        if ([string]$childNode.kind -cne 'directory') { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive member uses a non-directory node as a parent' }
                    }
                    elseif ($isDirectory) {
                        if ([string]$childNode.kind -cne 'directory' -or [bool]$childNode.explicit) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive contains a duplicate directory or case/type collision' }
                        $childNode.explicit = $true
                    }
                    else {
                        if ([bool]$childNode.explicit -or [string]$childNode.kind -cne 'directory' -or $childNode.children.Count -gt 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive contains a duplicate file or file/directory collision' }
                        $childNode.kind = 'file'; $childNode.explicit = $true
                    }
                    $trieNode = $childNode
                }
                if (-not $isDirectory) {
                    $hash = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
                    $captureManifest = ($relative -ceq 'Cargo.toml')
                    if ($captureManifest -and $size -gt 1048576L) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: crate Cargo.toml exceeds its 1 MiB dependency-graph parser bound' }
                    $manifestBuffer = if ($captureManifest) { [IO.MemoryStream]::new([int]$size) } else { $null }
                    try {
                        $remaining = [Int64]$size
                        $buffer = [byte[]]::new(65536)
                        while ($remaining -gt 0) {
                            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.archive_member_hash' -Progress ("path={0};remaining={1}" -f $relative, $remaining) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED' }
                            $take = [int][Math]::Min([Int64]$buffer.Length, $remaining)
                            $read = $gzip.Read($buffer, 0, $take)
                            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.archive_member_hash' -Progress ("path={0};remaining={1}" -f $relative, $remaining) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED' }
                            if ($read -le 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: truncated file member data' }
                            $hash.AppendData($buffer, 0, $read)
                            if ($captureManifest) { $manifestBuffer.Write($buffer, 0, $read) }
                            $remaining -= $read
                        }
                        $fileSha = [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
                        if ($captureManifest) {
                            $manifestBytes = $manifestBuffer.ToArray()
                            try { $manifestText = [Text.UTF8Encoding]::new($false, $true).GetString($manifestBytes) }
                            catch { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: Cargo.toml is not strict UTF-8' }
                            $manifestContentSha256 = $fileSha
                        }
                    }
                    finally { $hash.Dispose(); if ($null -ne $manifestBuffer) { $manifestBuffer.Dispose() } }
                    $expandedBytes += [Int64]$size
                    if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: expanded archive exceeded its fixed byte ceiling' }
                    $padding = [int]((512 - ($size % 512)) % 512)
                    if ($padding -gt 0) {
                        $pad = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count $padding -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.archive_file_padding'
                        for ($index = 0; $index -lt $pad.Length; $index++) { if ($pad[$index] -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: nonzero file padding is unsupported' } }
                        $expandedBytes += $padding
                    }
                    $expected.Add($relative, [PSCustomObject]@{ path = $relative; kind = 'file'; bytes = [Int64]$size; sha256 = $fileSha })
                    if ($expected.Count -gt 10000) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: source inventory exceeds the matching extracted-tree 10000-entry bound' }
                    $headerRows.Add([PSCustomObject][ordered]@{ offset = $headerOffset; format = [string]$headerRecord.format; path = $fullName; kind = 'file'; size = $size; type_flag = $typeFlag; header_sha256 = [string]$headerRecord.header_sha256; name_field_sha256 = [string]$headerRecord.name_field_sha256; prefix_field_sha256 = [string]$headerRecord.prefix_field_sha256; fallback_kind = $fallbackKind })
                    $countKey = ([string]$headerRecord.format).ToLowerInvariant() + '_regular'
                    $formatCounts[$countKey] = [Int64]$formatCounts[$countKey] + 1L
                if ($null -ne $pendingLongName) {
                    $pairRows.Add((New-D32BoundedCompilerDiagnosticGnuLongNamePair -Pending $pendingLongName -HeaderRecord $headerRecord -NextHeaderOffset $headerOffset -FallbackKind $fallbackKind -EffectivePath $fullName))
                    $pendingLongName = $null
                    $payload = $null
                }
                    continue
                }
            }
            $headerRows.Add([PSCustomObject][ordered]@{ offset = $headerOffset; format = [string]$headerRecord.format; path = $fullName; kind = $(if ($isDirectory) { 'directory' } else { 'file' }); size = $size; type_flag = $typeFlag; header_sha256 = [string]$headerRecord.header_sha256; name_field_sha256 = [string]$headerRecord.name_field_sha256; prefix_field_sha256 = [string]$headerRecord.prefix_field_sha256; fallback_kind = $fallbackKind })
            $countKey = ([string]$headerRecord.format).ToLowerInvariant() + $(if ($isDirectory) { '_directory' } else { '_regular' })
            $formatCounts[$countKey] = [Int64]$formatCounts[$countKey] + 1L
            $paddingSize = [int]((512 - ($size % 512)) % 512)
            if ($size -gt 0) {
                $discard = [byte[]]::new(65536)
                $remaining = [Int64]$size
                while ($remaining -gt 0) {
                    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.archive_member_discard' -Progress ("path={0};remaining={1}" -f $fullName, $remaining) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED' }
                    $read = $gzip.Read($discard, 0, [int][Math]::Min([Int64]$discard.Length, $remaining))
                    if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.archive_member_discard' -Progress ("path={0};remaining={1}" -f $fullName, $remaining) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED' }
                    if ($read -le 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: truncated unsupported member data' }
                    $remaining -= $read
                }
                $expandedBytes += [Int64]$size
            }
            if ($paddingSize -gt 0) {
                $pad = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count $paddingSize -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.archive_member_padding'
                for ($index = 0; $index -lt $pad.Length; $index++) { if ($pad[$index] -ne 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: nonzero tar padding is unsupported' } }
                $expandedBytes += $paddingSize
            }
            if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: expanded archive exceeded its fixed byte ceiling' }
            if ($null -ne $pendingLongName) {
                $pairRows.Add((New-D32BoundedCompilerDiagnosticGnuLongNamePair -Pending $pendingLongName -HeaderRecord $headerRecord -NextHeaderOffset $headerOffset -FallbackKind $fallbackKind -EffectivePath $fullName))
                $pendingLongName = $null
                $payload = $null
            }
        }
        if ($null -ne $pendingLongName) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: dangling GNU longname control at archive end' }
        if ($controlMetadataRows.Count -ne $pairRows.Count) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: not every GNU longname control is bound to exactly one ordinary member' }
        if ($expected.Count -eq 0) { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: archive member inventory is empty' }
        if ($null -eq $manifestText -or [string]$manifestContentSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: checksum-matched crate archive lacks one regular root Cargo.toml' }
        $paths = [string[]]@($expected.Keys)
        [Array]::Sort($paths, [StringComparer]::Ordinal)
        $rows = [System.Collections.Generic.List[object]]::new()
        $canonical = [System.Collections.Generic.List[string]]::new()
        $inventoryIndex = 0
        foreach ($path in $paths) {
            if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.archive_inventory_rows' -Progress ("rows={0}/{1}" -f $inventoryIndex, $paths.Length) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED' -NoProgress }
            $entry = $expected[$path]
            $rows.Add($entry)
            $canonical.Add(([string]$entry.kind + "`t" + [string]$entry.path + "`t" + [Int64]$entry.bytes + "`t" + [string]$entry.sha256))
            $inventoryIndex++
        }
        $headerCanonical = [System.Collections.Generic.List[string]]::new()
        $headerIndex = 0
        foreach ($headerRow in $headerRows) {
        if ($null -ne $ProofTimer) { Assert-D32BoundedDiagnosticSourceProofDeadline -ProofTimer $ProofTimer -Phase 'registry.archive_header_digest_rows' -Progress ("rows={0}/{1}" -f $headerIndex, $headerRows.Count) -DeadlineMilliseconds $DeadlineMilliseconds -ErrorPrefix 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED' -NoProgress }
        $headerCanonical.Add(([Int64]$headerRow.offset).ToString([Globalization.CultureInfo]::InvariantCulture) + "`t" +
            [string]$headerRow.format + "`t" + [string]$headerRow.path + "`t" + [string]$headerRow.kind + "`t" +
            ([Int64]$headerRow.type_flag).ToString([Globalization.CultureInfo]::InvariantCulture) + "`t" +
            ([Int64]$headerRow.size).ToString([Globalization.CultureInfo]::InvariantCulture) + "`t" + [string]$headerRow.header_sha256 + "`t" +
            [string]$headerRow.name_field_sha256 + "`t" + [string]$headerRow.prefix_field_sha256 + "`t" + [string]$headerRow.fallback_kind)
            $headerIndex++
        }
        $headerInventorySha = Get-D32BoundedDiagnosticSha256FromLines -Lines ([string[]]$headerCanonical.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.archive_header_inventory_digest'
        $pairInventorySha = Get-D32BoundedCompilerDiagnosticLongNamePairDigest -Pairs @($pairRows.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
        $controlMetadataSha = Get-D32BoundedCompilerDiagnosticLongNameControlDigest -Pairs @($controlMetadataRows.ToArray()) -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds
        $formatCanonical = [string]::Join("`t", [string[]]@($script:D32BoundedDiagnosticRegistryArchivePolicy,
            ([Int64]$formatCounts.ustar_regular).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$formatCounts.ustar_directory).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$formatCounts.gnu_regular).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$formatCounts.gnu_directory).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$formatCounts.gnu_longname_extension).ToString([Globalization.CultureInfo]::InvariantCulture)))
        $inventoryDigestRows = [string[]]::new($canonical.Count + 3)
        $canonical.CopyTo($inventoryDigestRows, 0)
        $inventoryDigestRows[$canonical.Count] = $headerInventorySha
        $inventoryDigestRows[$canonical.Count + 1] = $pairInventorySha
        $inventoryDigestRows[$canonical.Count + 2] = $formatCanonical
        $inventorySha = Get-D32BoundedDiagnosticSha256FromLines -Lines $inventoryDigestRows -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.archive_inventory_digest'
        return [PSCustomObject][ordered]@{
            archive_sha256 = $archiveSha
            archive_policy_id = $script:D32BoundedDiagnosticRegistryArchivePolicy
            expanded_bytes = $expandedBytes
            member_count = [Int64]$rawMemberCount
            ordinary_header_count = [Int64]$ordinaryHeaderCount
            longname_pair_count = [Int64]$pairRows.Count
            longname_pair_inventory_sha256 = $pairInventorySha
            longname_control_metadata_count = [Int64]$controlMetadataRows.Count
            longname_control_metadata_bytes = [Int64]$controlMetadataBytes
            longname_control_metadata_sha256 = $controlMetadataSha
            entries = @($rows.ToArray())
            inventory_sha256 = $inventorySha
            header_inventory_sha256 = $headerInventorySha
            format_counts = [PSCustomObject][ordered]@{
                ustar_regular = [Int64]$formatCounts.ustar_regular
                ustar_directory = [Int64]$formatCounts.ustar_directory
                gnu_regular = [Int64]$formatCounts.gnu_regular
                gnu_directory = [Int64]$formatCounts.gnu_directory
                gnu_longname_extension = [Int64]$formatCounts.gnu_longname_extension
            }
            longname_pairs = @($pairRows.ToArray())
            header_inventory = @($headerRows.ToArray())
            manifest_text = $manifestText
            manifest_sha256 = $manifestContentSha256
        }
    }
    finally {
        if ($null -ne $gzip) { $gzip.Dispose() }
        $compressed.Dispose()
    }
}

function Get-D32BoundedDiagnosticArchiveFormatCensusInventory {
    param(
        [Parameter(Mandatory = $true)][byte[]]$CompressedBytes,
        [Parameter(Mandatory = $true)][string]$ExpectedPackageRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedArchiveSha256,
        [Parameter(Mandatory = $true)][Diagnostics.Stopwatch]$CensusTimer,
        [long]$MaximumCompressedBytes = 268435456L,
        [long]$MaximumExpandedBytes = 1073741824L,
        [long]$MaximumMemberBytes = 134217728L,
        [int]$MaximumMembers = 10000
    )
    $headerRows = [System.Collections.Generic.List[string]]::new()
    $pairRows = [System.Collections.Generic.List[object]]::new()
    $controlMetadataRows = [System.Collections.Generic.List[object]]::new()
    $formatCounts = [ordered]@{ ustar_regular = 0L; ustar_directory = 0L; gnu_regular = 0L; gnu_directory = 0L; gnu_longname_extension = 0L }
    $ordinaryHeaderCount = [Int64]0
    $controlMetadataBytes = [Int64]0
    $pendingLongName = $null
    $archiveSha = $null
    $expandedBytes = [Int64]0
    $memberCount = [Int64]0
    $currentOffset = $null
    $currentHeaderSha = $null
    $currentMemberHeader = $false
    $currentHeaderRecorded = $false
    $currentTypeFlag = $null
    $currentHeaderFormat = $null
    $currentHeaderSize = $null
    $currentHeaderNameFieldSha = $null
    $currentHeaderPrefixFieldSha = $null
    $failureReason = $null
    $status = 'COMPLETE_DIAGNOSTIC'
    $gzip = $null
    $compressed = $null
    $expected = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $rawNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $rootPrefix = $ExpectedPackageRoot + '/'
    $rootSeen = $false
    $tarFramingVerified = $false
    $preflightBudgetInvalid = $null -eq $CensusTimer -or -not $CensusTimer.IsRunning -or $CensusTimer.ElapsedMilliseconds -ge 300000 -or
        $CompressedBytes.Length -le 0 -or [Int64]$CompressedBytes.Length -gt $MaximumCompressedBytes -or
        $MaximumExpandedBytes -le 0 -or $MaximumMemberBytes -le 0 -or $MaximumMembers -le 0 -or $MaximumMembers -gt 10000
    $preflightIdentityInvalid = $ExpectedArchiveSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedPackageRoot -cnotmatch '^[A-Za-z0-9_-]+-[0-9A-Za-z.+_-]+$'
    if ($preflightBudgetInvalid -or $preflightIdentityInvalid) {
        $preflightStatus = if ($preflightBudgetInvalid) { 'BUDGET_STOPPED' } else { 'BLOCKED' }
        $preflightReason = if ($preflightBudgetInvalid) {
            'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: preflight aggregate deadline, archive size, or finite limit reached'
        } else { 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: caller archive checksum or package-root identity is malformed' }
        return [PSCustomObject][ordered]@{
            status = $preflightStatus; archive_sha256 = $null; expanded_bytes = 0L; header_count = 0L; member_count = 0L
            ordinary_header_count = 0L; longname_pair_count = 0L; longname_pair_inventory_sha256 = Get-D32BoundedCompilerDiagnosticLongNamePairDigest -Pairs @()
            longname_control_metadata_count = 0L; longname_control_metadata_bytes = 0L
            longname_control_metadata_sha256 = Get-D32BoundedCompilerDiagnosticLongNameControlDigest -Pairs @()
            format_counts = [PSCustomObject][ordered]@{ ustar_regular = 0L; ustar_directory = 0L; gnu_regular = 0L; gnu_directory = 0L; gnu_longname_extension = 0L }
            header_inventory_sha256 = $null; first_failure_offset = 0L; first_failure_header_sha256 = $null
            first_failure_reason = $preflightReason; remainder_unknown = $true; framing_verified = $false
        }
    }
    try {
        $archiveSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($CompressedBytes)).ToLowerInvariant()
        if ($archiveSha -cne $ExpectedArchiveSha256) {
            throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: opened archive SHA-256 differs from the caller-pinned Cargo.lock checksum'
        }
        $compressed = [IO.MemoryStream]::new($CompressedBytes, $false)
        $gzip = [IO.Compression.GZipStream]::new($compressed, [IO.Compression.CompressionMode]::Decompress, $true)
        $ended = $false
        while (-not $ended) {
            if ($CensusTimer.ElapsedMilliseconds -ge 300000) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: combined census deadline reached' }
            $currentOffset = [Int64]$expandedBytes
            $currentHeaderSha = $null
            $currentMemberHeader = $false
            $currentHeaderRecorded = $false
            $currentTypeFlag = $null
            $currentHeaderFormat = $null
            $currentHeaderSize = $null
            $currentHeaderNameFieldSha = $null
            $currentHeaderPrefixFieldSha = $null
            $header = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count 512 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.archive_header_read'
            $currentHeaderSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($header)).ToLowerInvariant()
            $expandedBytes += 512L
            if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: expanded archive limit reached' }
            $allZero = $true
            for ($index = 0; $index -lt 512; $index++) { if ($header[$index] -ne 0) { $allZero = $false; break } }
            if ($allZero) {
                if ($null -ne $pendingLongName) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: GNU longname pending at tar terminator without adjacent ordinary header' }
                $secondOffset = [Int64]$expandedBytes
                $second = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count 512 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds -Phase 'registry.archive_end_marker_read'
                $expandedBytes += 512L
                if ($expandedBytes -gt $MaximumExpandedBytes -or -not (Test-D32BoundedCompilerDiagnosticTarZeroBytes -Bytes $second -Offset 0 -Length 512)) {
                    $currentOffset = $secondOffset
                    $currentHeaderSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($second)).ToLowerInvariant()
                    throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: tar terminator is not two complete zero blocks'
                }
                $trailing = [byte[]]::new(512)
                while (($read = $gzip.Read($trailing, 0, $trailing.Length)) -gt 0) {
                    if ($CensusTimer.ElapsedMilliseconds -ge 300000) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: combined census deadline reached while validating tar tail' }
                    $expandedBytes += $read
                    if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: expanded archive limit reached in tar tail' }
                    for ($index = 0; $index -lt $read; $index++) {
                        if ($trailing[$index] -ne 0) {
                            $currentOffset = [Int64]($expandedBytes - $read + $index)
                            $currentHeaderSha = $null
                            throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: nonzero data follows the tar terminator'
                        }
                    }
                }
                $tarFramingVerified = $true
                $ended = $true
                continue
            }

            $memberCount++
            $currentMemberHeader = $true
            $currentTypeFlag = [Int64][int]$header[156]
            if ($memberCount -gt $MaximumMembers) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: archive member-count limit reached' }
            try { $headerRecord = Get-D32BoundedDiagnosticRegistryArchiveHeader -Header $header -AllowRawNameProjection:($null -ne $pendingLongName) }
            catch {
                $headerRows.Add([string]::Join("`t", [string[]]@(
                    ([Int64]$currentOffset).ToString([Globalization.CultureInfo]::InvariantCulture), 'UNSUPPORTED', '', 'unsupported',
                    ([Int64][int]$header[156]).ToString([Globalization.CultureInfo]::InvariantCulture), '0', [string]$currentHeaderSha,
                    '', '', '')))
                $currentHeaderRecorded = $true
                throw ('D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: ' + [string]$_.Exception.Message)
            }
            $currentHeaderFormat = [string]$headerRecord.format
            $currentHeaderSize = [Int64]$headerRecord.size
            $currentHeaderNameFieldSha = [string]$headerRecord.name_field_sha256
            $currentHeaderPrefixFieldSha = [string]$headerRecord.prefix_field_sha256
            if ([Int64]$headerRecord.size -gt $MaximumMemberBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: tar member exceeds the fixed per-member expanded-byte bound' }
            if ([string]$headerRecord.kind -ceq 'longname') {
                $formatCounts.gnu_longname_extension = [Int64]$formatCounts.gnu_longname_extension + 1L
                if ($null -ne $pendingLongName) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: chained GNU longname controls are unsupported' }
                $payload = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count ([int]$headerRecord.size)
                $payloadSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($payload)).ToLowerInvariant()
                $controlMetadataRows.Add([PSCustomObject][ordered]@{
                    offset = [Int64]$currentOffset; size = [Int64]$headerRecord.size; control_payload_sha256 = $payloadSha
                })
                $controlMetadataBytes += [Int64]$headerRecord.size
                $expandedBytes += [Int64]$headerRecord.size
                if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: expanded archive limit reached in GNU longname metadata' }
                $padding = [int]((512 - ([Int64]$headerRecord.size % 512)) % 512)
                if ($padding -gt 0) {
                    $pad = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count $padding
                    if (-not (Test-D32BoundedCompilerDiagnosticTarZeroBytes -Bytes $pad -Offset 0 -Length $pad.Length)) {
                        throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: GNU longname control padding is nonzero'
                    }
                    $expandedBytes += $padding
                }
                if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: expanded archive limit reached after GNU longname metadata' }
                $headerRows.Add([string]::Join("`t", [string[]]@(
                    ([Int64]$currentOffset).ToString([Globalization.CultureInfo]::InvariantCulture), 'GNU_LONGNAME_EXTENSION', '', 'control',
                    '76', ([Int64]$headerRecord.size).ToString([Globalization.CultureInfo]::InvariantCulture), [string]$currentHeaderSha,
                    [string]$headerRecord.name_field_sha256, [string]$headerRecord.prefix_field_sha256, '')))
                $currentHeaderRecorded = $true
                $pendingLongName = [PSCustomObject][ordered]@{
                    offset = [Int64]$currentOffset; header_sha256 = [string]$currentHeaderSha; size = [Int64]$headerRecord.size
                    control_payload_sha256 = $payloadSha; expected_next_offset = [Int64]$expandedBytes; payload = $payload
                }
                continue
            }
            $fallbackKind = ''
            $fullName = [string]$headerRecord.path
            if ($null -ne $pendingLongName) {
                if ([Int64]$pendingLongName.expected_next_offset -ne [Int64]$currentOffset) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: GNU longname is not physically adjacent to its ordinary header'
                }
                $longName = ConvertFrom-D32BoundedCompilerDiagnosticGnuLongNamePayload -Payload ([byte[]]$pendingLongName.payload) -NextKind ([string]$headerRecord.kind)
                $fallbackKind = Get-D32BoundedCompilerDiagnosticGnuLongNameBinding -Pending $longName -HeaderRecord $headerRecord
                $fullName = [string]$longName.effective_path
            }
            elseif ($null -eq $fullName) {
                throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: ordinary tar name is not strict UTF-8'
            }
            $isDirectory = [string]$headerRecord.kind -ceq 'directory'
            if ($fullName -ceq $ExpectedPackageRoot) {
                if (-not $isDirectory -or $rootSeen -or -not $rawNames.Add($fullName)) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: exact package root directory header is duplicated or malformed' }
                $rootSeen = $true
            }
            else {
                if (-not $fullName.StartsWith($rootPrefix, [StringComparison]::Ordinal) -or
                    -not (Test-D32BoundedCompilerDiagnosticTarPath $fullName) -or -not $rawNames.Add($fullName)) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: archive member path escaped, aliased, collided, or duplicated'
                }
                $relative = $fullName.Substring($rootPrefix.Length)
                if ($isDirectory) { $relative = $relative.TrimEnd('/') }
                if ([String]::IsNullOrEmpty($relative)) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: empty non-root member path is invalid' }
                $segments = $relative.Split('/')
                $parentPath = ''
                for ($segmentIndex = 0; $segmentIndex -lt ($segments.Count - 1); $segmentIndex++) {
                    $parentPath = if ([String]::IsNullOrEmpty($parentPath)) { $segments[$segmentIndex] } else { $parentPath + '/' + $segments[$segmentIndex] }
                    if ($expected.ContainsKey($parentPath)) {
                        if ([string]$expected[$parentPath].kind -cne 'directory' -or [string]$expected[$parentPath].path -cne $parentPath) {
                            throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: archive member has a case collision or a file used as a directory'
                        }
                    }
                    else { $expected.Add($parentPath, [PSCustomObject]@{ path = $parentPath; kind = 'directory' }) }
                }
                if ($expected.ContainsKey($relative)) {
                    if (-not $isDirectory -or [string]$expected[$relative].kind -cne 'directory' -or [string]$expected[$relative].path -cne $relative) {
                        throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: archive contains a duplicate member or case/type collision'
                    }
                }
                elseif ($isDirectory) { $expected.Add($relative, [PSCustomObject]@{ path = $relative; kind = 'directory' }) }
                else { $expected.Add($relative, [PSCustomObject]@{ path = $relative; kind = 'file' }) }
            }
            $row = [string]::Join("`t", [string[]]@(
                ([Int64]$currentOffset).ToString([Globalization.CultureInfo]::InvariantCulture),
                [string]$headerRecord.format, [string]$fullName, [string]$headerRecord.kind,
                ([Int64]$headerRecord.type_flag).ToString([Globalization.CultureInfo]::InvariantCulture),
                ([Int64]$headerRecord.size).ToString([Globalization.CultureInfo]::InvariantCulture), [string]$currentHeaderSha,
                [string]$headerRecord.name_field_sha256, [string]$headerRecord.prefix_field_sha256, $fallbackKind))
            $headerRows.Add($row)
            $currentHeaderRecorded = $true
            if ($null -ne $pendingLongName) { $pairRows.Add((New-D32BoundedCompilerDiagnosticGnuLongNamePair -Pending $pendingLongName -HeaderRecord $headerRecord -NextHeaderOffset ([Int64]$currentOffset) -FallbackKind $fallbackKind -EffectivePath $fullName)) }
            $ordinaryHeaderCount++
            $countKey = ([string]$headerRecord.format).ToLowerInvariant() + $(if ($isDirectory) { '_directory' } else { '_regular' })
            $formatCounts[$countKey] = [Int64]$formatCounts[$countKey] + 1L
            $remaining = [Int64]$headerRecord.size
            $discard = [byte[]]::new(65536)
            while ($remaining -gt 0) {
                if ($CensusTimer.ElapsedMilliseconds -ge 300000) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: combined census deadline reached while discarding member payload' }
                $read = $gzip.Read($discard, 0, [int][Math]::Min([Int64]$discard.Length, $remaining))
                if ($read -le 0) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: truncated tar member payload' }
                $remaining -= $read
                $expandedBytes += $read
                if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: expanded archive limit reached while discarding payload' }
            }
            $padding = [int]((512 - ([Int64]$headerRecord.size % 512)) % 512)
            if ($padding -gt 0) {
                $pad = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $gzip -Count $padding
                if (-not (Test-D32BoundedCompilerDiagnosticTarZeroBytes -Bytes $pad -Offset 0 -Length $pad.Length)) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: member padding is nonzero' }
                $expandedBytes += $padding
            }
            if ($expandedBytes -gt $MaximumExpandedBytes) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: expanded archive limit reached after member padding' }
            if ($null -ne $pendingLongName) { $pendingLongName = $null }
            $payload = $null
        }
        if ($memberCount -eq 0) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: archive contains no member headers' }
        $currentOffset = $null
        $currentHeaderSha = $null
    }
    catch {
        $failureReason = [string]$_.Exception.Message
        if ($failureReason -like 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED:*') { $status = 'BUDGET_STOPPED' }
        else { $status = 'BLOCKED' }
        if ($currentMemberHeader -and -not $currentHeaderRecorded -and $null -ne $currentOffset -and $null -ne $currentHeaderSha) {
            if ($currentHeaderFormat -ceq 'GNU' -and $currentTypeFlag -eq 76 -and $null -ne $currentHeaderSize) {
                $headerRows.Add([string]::Join("`t", [string[]]@(
                    ([Int64]$currentOffset).ToString([Globalization.CultureInfo]::InvariantCulture), 'GNU_LONGNAME_EXTENSION', '', 'control',
                    '76', ([Int64]$currentHeaderSize).ToString([Globalization.CultureInfo]::InvariantCulture), [string]$currentHeaderSha,
                    [string]$currentHeaderNameFieldSha, [string]$currentHeaderPrefixFieldSha, '')))
            }
            else {
                $headerRows.Add([string]::Join("`t", [string[]]@(
                    ([Int64]$currentOffset).ToString([Globalization.CultureInfo]::InvariantCulture), 'UNSUPPORTED', '', '',
                    $(if ($null -eq $currentTypeFlag) { '0' } else { ([Int64]$currentTypeFlag).ToString([Globalization.CultureInfo]::InvariantCulture) }),
                    '0', [string]$currentHeaderSha)))
            }
        }
    }
    finally {
        if ($null -ne $gzip) { try { $gzip.Dispose() } catch { if ($null -eq $failureReason) { $status = 'BLOCKED'; $failureReason = 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: gzip trailer verification failed' } } }
        if ($null -ne $compressed) { $compressed.Dispose() }
    }
    $headerCanonical = ($headerRows -join "`n") + $(if ($headerRows.Count -gt 0) { "`n" } else { '' })
    $headerInventorySha = if ($headerRows.Count -eq 0) { $null } else {
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($headerCanonical))).ToLowerInvariant()
    }
    $pairInventorySha = Get-D32BoundedCompilerDiagnosticLongNamePairDigest -Pairs @($pairRows.ToArray())
    $controlMetadataSha = Get-D32BoundedCompilerDiagnosticLongNameControlDigest -Pairs @($controlMetadataRows.ToArray())
    return [PSCustomObject][ordered]@{
        status = $status
        archive_sha256 = $archiveSha
        expanded_bytes = $expandedBytes
        header_count = [Int64]$headerRows.Count
        member_count = $memberCount
        ordinary_header_count = $ordinaryHeaderCount
        longname_pair_count = [Int64]$pairRows.Count
        longname_pair_inventory_sha256 = $pairInventorySha
        longname_control_metadata_count = [Int64]$controlMetadataRows.Count
        longname_control_metadata_bytes = $controlMetadataBytes
        longname_control_metadata_sha256 = $controlMetadataSha
        format_counts = [PSCustomObject][ordered]@{
            ustar_regular = [Int64]$formatCounts.ustar_regular
            ustar_directory = [Int64]$formatCounts.ustar_directory
            gnu_regular = [Int64]$formatCounts.gnu_regular
            gnu_directory = [Int64]$formatCounts.gnu_directory
            gnu_longname_extension = [Int64]$formatCounts.gnu_longname_extension
        }
        ordinary_payload_read_and_discarded = $true
        ordinary_payload_hashed = $false
        ordinary_payload_retained = $false
        longname_control_metadata_hashed = $true
        longname_control_metadata_retained = $false
        source_extraction_performed = $false
        header_inventory_sha256 = $headerInventorySha
        first_failure_offset = $currentOffset
        first_failure_header_sha256 = $currentHeaderSha
        first_failure_reason = $failureReason
        remainder_unknown = ($status -cne 'COMPLETE_DIAGNOSTIC')
        framing_verified = $tarFramingVerified -and $status -ceq 'COMPLETE_DIAGNOSTIC'
    }
}

function Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape {
    param(
        [AllowNull()][object]$Document,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$EntryScriptPath,
        [Parameter(Mandatory = $true)][string]$PolicyPath,
        [Parameter(Mandatory = $true)][string]$ProfileScriptPath
    )
    $top = @('schema_version', 'record_type', 'registry_archive_policy', 'source_plan_semantics_version', 'semantic_scope',
        'registry_tuple_sha256', 'gate_authority', 'candidate_sha', 'source_repo', 'repository_identity', 'lock_reference',
        'dependency_origin', 'historical_origin', 'source_pins', 'archive_refs',
        'output_candidate', 'run_id', 'resource_budget', 'issued_at_utc')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document $top) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Document.schema_version -Positive) -or [Int64]$Document.schema_version -ne 2 -or
        $Document.record_type -isnot [string] -or [string]$Document.record_type -cne $script:D32BoundedDiagnosticArchiveFormatCensusAuthorityType -or
        $Document.registry_archive_policy -isnot [string] -or [string]$Document.registry_archive_policy -cne $script:D32BoundedDiagnosticRegistryArchivePolicy -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Document.source_plan_semantics_version -Positive) -or [Int64]$Document.source_plan_semantics_version -ne 2 -or
        [string]$Document.semantic_scope -cne 'EXACT_CALLER_PINNED_CURRENT_LOCK_ARCHIVE_FORMAT_SUBSET' -or
        [string]$Document.registry_tuple_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Document.gate_authority -isnot [string] -or [string]$Document.gate_authority -cne 'NONE' -or
        $Document.candidate_sha -isnot [string] -or [string]$Document.candidate_sha -cne $ExpectedCandidateSha -or $ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Document.source_repo) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$Document.source_repo), [IO.Path]::GetFullPath($Repository)) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.repository_identity @('volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Document.repository_identity) -or
        [string]$Document.run_id -cnotmatch '^[0-9a-f]{32}$') { return $false }

    $lockPath = [IO.Path]::GetFullPath((Join-Path $Repository 'vita-agent/Cargo.lock'))
    if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Document.lock_reference) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Document.lock_reference.path, $lockPath) -or
        -not (Test-D32BoundedCompilerDiagnosticWithin ([string]$Document.lock_reference.path) $Repository)) { return $false }

    $originFields = @('path', 'volume_serial_hex', 'file_id_hex', 'registry_archive_root')
    $cargoHome = 'E:\d32\inv7\r\c'
    $archiveRoot = Join-Path $cargoHome 'registry/cache/index.crates.io-1949cf8c6b5b557f'
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.dependency_origin $originFields) -or
        [string]$Document.dependency_origin.path -cne $cargoHome -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Document.dependency_origin) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.dependency_origin.registry_archive_root @('path', 'volume_serial_hex', 'file_id_hex')) -or
        [string]$Document.dependency_origin.registry_archive_root.path -cne $archiveRoot -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Document.dependency_origin.registry_archive_root)) { return $false }

    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.historical_origin @('candidate_sha', 'attempt_state', 'fetch_completion', 'gate_authority', 'owner_record', 'blocked_diagnostic')) -or
        [string]$Document.historical_origin.candidate_sha -cne $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -or
        [string]$Document.historical_origin.attempt_state -cne 'BLOCKED' -or
        [string]$Document.historical_origin.fetch_completion -cne 'NOT_RETAINED' -or
        [string]$Document.historical_origin.gate_authority -cne 'NONE' -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Document.historical_origin.owner_record) -or
        [string]$Document.historical_origin.owner_record.path -cne 'E:\d32\inv7\D32-PHASE0-OWNER.json' -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Document.historical_origin.blocked_diagnostic) -or
        [string]$Document.historical_origin.blocked_diagnostic.path -cne 'E:\d32\inv7\D32-PHASE0-BLOCKED-DIAGNOSTIC.json') { return $false }

    $expectedPins = @(
        [IO.Path]::GetFullPath($EntryScriptPath),
        [IO.Path]::GetFullPath($PolicyPath),
        [IO.Path]::GetFullPath($ProfileScriptPath),
        [IO.Path]::GetFullPath((Join-Path $Repository 'scripts/d32-powershell-module-authority.ps1')))
    if ($Document.source_pins -isnot [Array] -or $Document.source_pins.Count -ne $expectedPins.Count) { return $false }
    $seenPins = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($pin in $Document.source_pins) {
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $pin) -or
            -not (Test-D32BoundedCompilerDiagnosticWithin $pin.path $Repository) -or -not $seenPins.Add([string]$pin.path)) { return $false }
    }
    foreach ($expectedPath in $expectedPins) {
        if (@($Document.source_pins | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals([string]$_.path, $expectedPath) }).Count -ne 1) { return $false }
    }

    if ($Document.archive_refs -isnot [Array] -or $Document.archive_refs.Count -lt 1 -or $Document.archive_refs.Count -gt 1115) { return $false }
    $archiveKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($archive in $Document.archive_refs) {
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $archive @('source', 'name', 'version', 'checksum', 'path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
            [string]$archive.source -cne 'registry+https://github.com/rust-lang/crates.io-index' -or
            [string]$archive.name -notmatch '^[A-Za-z0-9_-]+$' -or [string]$archive.version -notmatch '^[0-9A-Za-z.+_-]+$' -or
            [string]$archive.checksum -cnotmatch '^[0-9a-f]{64}$' -or [string]$archive.sha256 -cne [string]$archive.checksum -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $archive.bytes -Positive) -or [Int64]$archive.bytes -gt 268435456 -or
            [string]$archive.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$archive.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$archive.path, (Join-Path $archiveRoot ([string]$archive.name + '-' + [string]$archive.version + '.crate'))) -or
            -not (Test-D32BoundedCompilerDiagnosticWithin $archive.path $archiveRoot) -or
            -not $archiveKeys.Add([string]$archive.name + "`0" + [string]$archive.version)) { return $false }
    }

    $budgetFields = @('combined_milliseconds', 'managed_buffer_bytes', 'max_archive_bytes', 'max_archive_expanded_bytes',
        'max_archive_member_bytes', 'max_archive_members', 'max_aggregate_expanded_bytes', 'max_aggregate_members', 'maximum_output_bytes')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Document.resource_budget $budgetFields)) { return $false }
    foreach ($field in $budgetFields) { if (-not (Test-D32BoundedCompilerDiagnosticInteger $Document.resource_budget.($field) -Positive)) { return $false } }
    if ([Int64]$Document.resource_budget.combined_milliseconds -ne 300000 -or
        [Int64]$Document.resource_budget.managed_buffer_bytes -ne 536870912 -or
        [Int64]$Document.resource_budget.max_archive_bytes -ne 268435456 -or
        [Int64]$Document.resource_budget.max_archive_expanded_bytes -ne 1073741824 -or
        [Int64]$Document.resource_budget.max_archive_member_bytes -ne 134217728 -or
        [Int64]$Document.resource_budget.max_archive_members -ne 10000 -or
        [Int64]$Document.resource_budget.max_aggregate_expanded_bytes -ne 34359738368 -or
        [Int64]$Document.resource_budget.max_aggregate_members -ne 1000000 -or
        [Int64]$Document.resource_budget.maximum_output_bytes -ne 67108864) { return $false }

    $output = $Document.output_candidate
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $output @('path', 'parent_path', 'parent_volume_serial_hex', 'parent_file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$output.path), [string]$output.parent_path) -or
        [string]$output.parent_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$output.parent_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.path $Repository) -or
        (Test-D32BoundedCompilerDiagnosticWithin $output.path $cargoHome)) { return $false }
    try { $null = [DateTimeOffset]::Parse([string]$Document.issued_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
    catch { return $false }
    return $true
}

function Get-D32BoundedDiagnosticArchiveFormatCensusCoverageDigest {
    param([Parameter(Mandatory = $true)][object[]]$Archives)
    $rows = [System.Collections.Generic.List[string]]::new()
    foreach ($archive in $Archives) {
        $parts = [string[]]@(
            [string]$archive.archive_id, [string]$archive.archive_sha256, [string]$archive.header_inventory_sha256,
            [string]$archive.opened_archive_bytes, [string]$archive.opened_archive_sha256,
            [string]$archive.opened_archive_volume_serial_hex, [string]$archive.opened_archive_file_id_hex,
            ([Int64]$archive.header_count).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$archive.ordinary_header_count).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$archive.longname_pair_count).ToString([Globalization.CultureInfo]::InvariantCulture),
            [string]$archive.longname_pair_inventory_sha256,
            ([Int64]$archive.longname_control_metadata_count).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$archive.longname_control_metadata_bytes).ToString([Globalization.CultureInfo]::InvariantCulture),
            [string]$archive.longname_control_metadata_sha256,
            ([Int64]$archive.format_counts.ustar_regular).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$archive.format_counts.ustar_directory).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$archive.format_counts.gnu_regular).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$archive.format_counts.gnu_directory).ToString([Globalization.CultureInfo]::InvariantCulture),
            ([Int64]$archive.format_counts.gnu_longname_extension).ToString([Globalization.CultureInfo]::InvariantCulture),
            [string]$archive.status, [string]$archive.first_failure_offset,
            [string]$archive.first_failure_header_sha256, [string]$archive.first_failure_reason,
            [string]$archive.framing_verified, [string]$archive.remainder_unknown)
        $rows.Add([string]::Join("`t", $parts))
    }
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.UTF8Encoding]::new($false).GetBytes(($rows -join "`n") + "`n"))).ToLowerInvariant()
}

function New-D32BoundedDiagnosticArchiveFormatCensusCoverageRow {
    param(
        [Parameter(Mandatory = $true)][object]$Archive,
        [Parameter(Mandatory = $true)][string]$Status,
        [AllowNull()][object]$OpenedReference,
        [AllowNull()][object]$Inventory,
        [AllowNull()][object]$FailureReason
    )
    $zeroCounts = [PSCustomObject][ordered]@{ ustar_regular = 0L; ustar_directory = 0L; gnu_regular = 0L; gnu_directory = 0L; gnu_longname_extension = 0L }
    $counts = if ($null -eq $Inventory) { $zeroCounts } else { $Inventory.format_counts }
    $openedBytes = $null
    $openedSha256 = $null
    $openedVolumeSerialHex = $null
    $openedFileIdHex = $null
    $expandedBytes = 0L
    $headerCount = 0L
    $ordinaryHeaderCount = 0L
    $longnamePairCount = 0L
    $longnamePairInventorySha256 = Get-D32BoundedCompilerDiagnosticLongNamePairDigest -Pairs @()
    $longnameControlMetadataCount = 0L
    $longnameControlMetadataBytes = 0L
    $longnameControlMetadataSha256 = Get-D32BoundedCompilerDiagnosticLongNameControlDigest -Pairs @()
    $headerInventorySha256 = $null
    $framingVerified = $false
    $firstFailureOffset = $null
    $firstFailureHeaderSha256 = $null
    $firstFailureReason = $null
    if ($null -ne $OpenedReference) {
        $openedBytes = [Int64]$OpenedReference.bytes
        $openedSha256 = [string]$OpenedReference.sha256
        $openedVolumeSerialHex = [string]$OpenedReference.volume_serial_hex
        $openedFileIdHex = [string]$OpenedReference.file_id_hex
    }
    if ($null -ne $Inventory) {
        $expandedBytes = [Int64]$Inventory.expanded_bytes
        $headerCount = [Int64]$Inventory.header_count
        $ordinaryHeaderCount = [Int64]$Inventory.ordinary_header_count
        $longnamePairCount = [Int64]$Inventory.longname_pair_count
        $longnamePairInventorySha256 = [string]$Inventory.longname_pair_inventory_sha256
        $longnameControlMetadataCount = [Int64]$Inventory.longname_control_metadata_count
        $longnameControlMetadataBytes = [Int64]$Inventory.longname_control_metadata_bytes
        $longnameControlMetadataSha256 = [string]$Inventory.longname_control_metadata_sha256
        if ($null -ne $Inventory.header_inventory_sha256) { $headerInventorySha256 = [string]$Inventory.header_inventory_sha256 }
        $framingVerified = [bool]$Inventory.framing_verified
        if ($null -ne $Inventory.first_failure_offset) { $firstFailureOffset = $Inventory.first_failure_offset }
        if ($null -ne $Inventory.first_failure_header_sha256) { $firstFailureHeaderSha256 = [string]$Inventory.first_failure_header_sha256 }
        if ($null -ne $Inventory.first_failure_reason) { $firstFailureReason = [string]$Inventory.first_failure_reason }
    }
    if ($null -ne $FailureReason) { $firstFailureReason = $FailureReason }
    return [PSCustomObject][ordered]@{
        archive_id = [string]$Archive.name + '@' + [string]$Archive.version
        source = [string]$Archive.source; name = [string]$Archive.name; version = [string]$Archive.version
        checksum = [string]$Archive.checksum; archive_path = [string]$Archive.path; archive_bytes = [Int64]$Archive.bytes
        archive_sha256 = [string]$Archive.sha256; archive_volume_serial_hex = [string]$Archive.volume_serial_hex
        archive_file_id_hex = [string]$Archive.file_id_hex
        opened_archive_bytes = $openedBytes
        opened_archive_sha256 = $openedSha256
        opened_archive_volume_serial_hex = $openedVolumeSerialHex
        opened_archive_file_id_hex = $openedFileIdHex
        status = $Status
        expanded_bytes = $expandedBytes
        header_count = $headerCount
        ordinary_header_count = $ordinaryHeaderCount
        longname_pair_count = $longnamePairCount
        longname_pair_inventory_sha256 = $longnamePairInventorySha256
        longname_control_metadata_count = $longnameControlMetadataCount
        longname_control_metadata_bytes = $longnameControlMetadataBytes
        longname_control_metadata_sha256 = $longnameControlMetadataSha256
        format_counts = $counts
        header_inventory_sha256 = $headerInventorySha256
        framing_verified = $framingVerified
        remainder_unknown = ($Status -cne 'COMPLETE_SUPPORTED')
        first_failure_offset = $firstFailureOffset
        first_failure_header_sha256 = $firstFailureHeaderSha256
        first_failure_reason = $firstFailureReason
    }
}

function New-D32BoundedDiagnosticArchiveFormatCensusUnexaminedRow {
    param([Parameter(Mandatory = $true)][object]$Archive, [Parameter(Mandatory = $true)][string]$Reason)
    return New-D32BoundedDiagnosticArchiveFormatCensusCoverageRow -Archive $Archive -Status 'UNEXAMINED' `
        -OpenedReference $null -Inventory $null -FailureReason $Reason
}

function New-D32BoundedDiagnosticArchiveFormatCensusResult {
    param(
        [Parameter(Mandatory = $true)][object]$Authority,
        [Parameter(Mandatory = $true)][object]$AuthorityReference,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$StartedAtUtc,
        [Parameter(Mandatory = $true)][string]$CompletedAtUtc,
        [Parameter(Mandatory = $true)][Int64]$ElapsedMilliseconds,
        [Parameter(Mandatory = $true)][object[]]$Archives,
        [AllowNull()][object]$PrimaryError,
        [string[]]$SecondaryErrors = @()
    )
    $rows = [object[]]@($Archives)
    $unexamined = [string[]]@($rows | Where-Object { [string]$_.status -ceq 'UNEXAMINED' } | ForEach-Object { [string]$_.archive_id })
    $blockedCount = [Int64]@($rows | Where-Object { [string]$_.status -cin @('UNSUPPORTED', 'PREFLIGHT_BLOCKED') }).Count
    $coveredCount = [Int64]@($rows | Where-Object { [string]$_.status -cne 'UNEXAMINED' }).Count
    $aggregateCounts = [ordered]@{ ustar_regular = 0L; ustar_directory = 0L; gnu_regular = 0L; gnu_directory = 0L; gnu_longname_extension = 0L }
    $aggregateOrdinaryHeaders = [Int64]0
    $aggregatePairs = [Int64]0
    $aggregateControlCount = [Int64]0
    $aggregateControlBytes = [Int64]0
    $controlDigestRows = [System.Collections.Generic.List[string]]::new()
    $pairDigestRows = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $rows) {
        foreach ($formatName in @('ustar_regular', 'ustar_directory', 'gnu_regular', 'gnu_directory', 'gnu_longname_extension')) {
            $aggregateCounts[$formatName] = [Int64]$aggregateCounts[$formatName] + [Int64]$row.format_counts.($formatName)
        }
        $aggregateOrdinaryHeaders += [Int64]$row.ordinary_header_count
        $aggregatePairs += [Int64]$row.longname_pair_count
        $aggregateControlCount += [Int64]$row.longname_control_metadata_count
        $aggregateControlBytes += [Int64]$row.longname_control_metadata_bytes
        $controlDigestRows.Add([string]$row.archive_id + "`t" + [string]$row.longname_control_metadata_sha256)
        $pairDigestRows.Add([string]$row.archive_id + "`t" + [string]$row.longname_pair_inventory_sha256)
    }
    $effectivePrimaryError = if ($null -eq $PrimaryError) { $null } else { [string]$PrimaryError }
    if ($Status -cne 'COMPLETE_DIAGNOSTIC' -and [String]::IsNullOrWhiteSpace($effectivePrimaryError)) {
        $effectivePrimaryError = 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: strict census coverage did not complete'
    }
    $reference = [PSCustomObject][ordered]@{
        path = [string]$AuthorityReference.path; bytes = [Int64]$AuthorityReference.bytes
        sha256 = [string]$AuthorityReference.sha256; volume_serial_hex = [string]$AuthorityReference.volume_serial_hex
        file_id_hex = [string]$AuthorityReference.file_id_hex
    }
    return [PSCustomObject][ordered]@{
        schema_version = 2; record_type = $script:D32BoundedDiagnosticArchiveFormatCensusType
        registry_archive_policy = $script:D32BoundedDiagnosticRegistryArchivePolicy; gate_authority = 'NONE'
        formal_phase1_allowed = $false; formal_aggregate_allowed = $false; source_proof_checkpoint = $false
        diagnostic_invocation_authority = 'NONE'; status = $Status
        candidate_sha = [string]$Authority.candidate_sha; source_repo = [string]$Authority.source_repo
        source_plan_semantics_version = [Int64]$Authority.source_plan_semantics_version
        semantic_scope = [string]$Authority.semantic_scope; registry_tuple_sha256 = [string]$Authority.registry_tuple_sha256
        repository_identity = $Authority.repository_identity
        census_authority_reference = $reference
        lock_reference = $Authority.lock_reference; dependency_origin = $Authority.dependency_origin
        historical_origin = $Authority.historical_origin; source_pins = @($Authority.source_pins)
        output_candidate = $Authority.output_candidate; resource_budget = $Authority.resource_budget
        run_id = [string]$Authority.run_id; started_at_utc = $StartedAtUtc
        completed_at_utc = $CompletedAtUtc; elapsed_milliseconds = [Int64]$ElapsedMilliseconds
        requested_archive_count = [Int64]@($Authority.archive_refs).Count; covered_archive_count = $coveredCount
        blocked_archive_count = $blockedCount; unexamined_archive_count = [Int64]$unexamined.Count
        archives = $rows; unexamined_archive_ids = $unexamined
        aggregate_format_counts = [PSCustomObject][ordered]@{
            ustar_regular = [Int64]$aggregateCounts.ustar_regular; ustar_directory = [Int64]$aggregateCounts.ustar_directory
            gnu_regular = [Int64]$aggregateCounts.gnu_regular; gnu_directory = [Int64]$aggregateCounts.gnu_directory
            gnu_longname_extension = [Int64]$aggregateCounts.gnu_longname_extension
        }
        ordinary_header_count = $aggregateOrdinaryHeaders
        longname_pair_count = $aggregatePairs
        longname_pair_inventory_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes(($pairDigestRows -join "`n") + "`n"))).ToLowerInvariant()
        longname_control_metadata_count = $aggregateControlCount
        longname_control_metadata_bytes = $aggregateControlBytes
        longname_control_metadata_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes(($controlDigestRows -join "`n") + "`n"))).ToLowerInvariant()
        archive_header_inventory_sha256 = Get-D32BoundedDiagnosticArchiveFormatCensusCoverageDigest -Archives $rows
        ordinary_payload_read_and_discarded = $true; ordinary_payload_hashed = $false; ordinary_payload_retained = $false
        longname_control_metadata_hashed = $true; longname_control_metadata_retained = $false; source_extraction_performed = $false
        formal_gate_usable = $false; primary_error = $effectivePrimaryError; secondary_errors = [string[]]@($SecondaryErrors)
    }
}

function Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure {
    param([AllowNull()][System.Collections.Generic.List[string]]$FailureReasons, [Parameter(Mandatory = $true)][string]$Reason)
    if ($null -ne $FailureReasons) { $FailureReasons.Add($Reason) }
}

function Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityCoverage {
    param(
        [AllowNull()][object]$Result,
        [AllowNull()][object]$Authority,
        [AllowNull()][object]$ExpectedAuthorityReference,
        [AllowNull()][System.Collections.Generic.List[string]]$FailureReasons
    )
    if ($null -ne $FailureReasons) { $FailureReasons.Clear() }
    if ($null -eq $Result -or $null -eq $Authority -or $Authority.archive_refs -isnot [Array] -or $Result.archives -isnot [Array]) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'authority_coverage.result_or_authority_shape'
        return $false
    }
    if ($Result.archives.Count -ne $Authority.archive_refs.Count -or
        [Int64]$Result.requested_archive_count -ne [Int64]$Authority.archive_refs.Count) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'authority_coverage.archive_count'
        return $false
    }
    if ($null -ne $ExpectedAuthorityReference -and
        ([string]$Result.census_authority_reference.path -cne [string]$ExpectedAuthorityReference.path -or
         [Int64]$Result.census_authority_reference.bytes -ne [Int64]$ExpectedAuthorityReference.bytes -or
         [string]$Result.census_authority_reference.sha256 -cne [string]$ExpectedAuthorityReference.sha256 -or
         [string]$Result.census_authority_reference.volume_serial_hex -cne [string]$ExpectedAuthorityReference.volume_serial_hex -or
         [string]$Result.census_authority_reference.file_id_hex -cne [string]$ExpectedAuthorityReference.file_id_hex)) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'census_authority_reference.caller_pinned_identity'
        return $false
    }
    for ($index = 0; $index -lt $Authority.archive_refs.Count; $index++) {
        $expected = $Authority.archive_refs[$index]
        $actual = $Result.archives[$index]
        if ([string]$actual.source -cne [string]$expected.source -or
            [string]$actual.name -cne [string]$expected.name -or [string]$actual.version -cne [string]$expected.version -or
            [string]$actual.checksum -cne [string]$expected.checksum -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$actual.archive_path, [string]$expected.path) -or
            [Int64]$actual.archive_bytes -ne [Int64]$expected.bytes -or
            [string]$actual.archive_sha256 -cne [string]$expected.sha256 -or
            [string]$actual.archive_volume_serial_hex -cne [string]$expected.volume_serial_hex -or
            [string]$actual.archive_file_id_hex -cne [string]$expected.file_id_hex) {
            Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "archives[$index].authority_archive_reference_binding"
            return $false
        }
    }
    return $true
}

function Test-D32BoundedDiagnosticArchiveFormatCensusResult {
    param([AllowNull()][object]$Record, [AllowNull()][System.Collections.Generic.List[string]]$FailureReasons)
    if ($null -ne $FailureReasons) { $FailureReasons.Clear() }
    $fields = @('schema_version', 'record_type', 'registry_archive_policy', 'gate_authority', 'formal_phase1_allowed', 'formal_aggregate_allowed',
        'source_proof_checkpoint', 'diagnostic_invocation_authority', 'status', 'candidate_sha', 'source_repo', 'source_plan_semantics_version',
        'semantic_scope', 'registry_tuple_sha256', 'repository_identity', 'census_authority_reference', 'lock_reference',
        'dependency_origin', 'historical_origin', 'source_pins', 'output_candidate', 'resource_budget', 'run_id',
        'started_at_utc', 'completed_at_utc', 'elapsed_milliseconds', 'requested_archive_count', 'covered_archive_count',
        'blocked_archive_count', 'unexamined_archive_count', 'archives', 'unexamined_archive_ids', 'aggregate_format_counts',
        'ordinary_header_count', 'longname_pair_count', 'longname_pair_inventory_sha256',
        'longname_control_metadata_count', 'longname_control_metadata_bytes', 'longname_control_metadata_sha256',
        'archive_header_inventory_sha256', 'ordinary_payload_read_and_discarded', 'ordinary_payload_hashed', 'ordinary_payload_retained',
        'longname_control_metadata_hashed', 'longname_control_metadata_retained', 'source_extraction_performed',
        'formal_gate_usable', 'primary_error', 'secondary_errors')
    $countFields = @('ustar_regular', 'ustar_directory', 'gnu_regular', 'gnu_directory', 'gnu_longname_extension')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record $fields)) {
        if ($null -eq $Record -or $Record -is [string] -or $Record -is [Array] -or $Record -is [ValueType]) {
            Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'result.object_shape'
        }
        else {
            $actualFieldNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($property in $Record.PSObject.Properties) { [void]$actualFieldNames.Add([string]$property.Name) }
            $missingFieldNames = @($fields | Where-Object { -not $actualFieldNames.Contains($_) })
            $extraFieldNames = @($actualFieldNames | Where-Object { $_ -notin $fields })
            Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason (
                'result.property_set.missing=' + ($missingFieldNames -join ',') + ';extra=' + ($extraFieldNames -join ','))
        }
        return $false
    }
    if ($Record.started_at_utc -isnot [string] -or $Record.completed_at_utc -isnot [string]) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'started_at_utc_or_completed_at_utc.string'
        return $false
    }
    $startedAt = [DateTimeOffset]::MinValue
    $completedAt = [DateTimeOffset]::MinValue
    $roundtripStyle = [Globalization.DateTimeStyles]::RoundtripKind
    $startedValid = [DateTimeOffset]::TryParseExact([string]$Record.started_at_utc, 'o', [Globalization.CultureInfo]::InvariantCulture, $roundtripStyle, [ref]$startedAt)
    $completedValid = [DateTimeOffset]::TryParseExact([string]$Record.completed_at_utc, 'o', [Globalization.CultureInfo]::InvariantCulture, $roundtripStyle, [ref]$completedAt)
    if (-not $startedValid -or -not $completedValid -or $completedAt -lt $startedAt) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'started_at_utc_or_completed_at_utc.roundtrip_order'
        return $false
    }
    if (-not (Test-D32BoundedCompilerDiagnosticInteger $Record.schema_version -Positive) -or [Int64]$Record.schema_version -ne 2 -or
        [string]$Record.record_type -cne $script:D32BoundedDiagnosticArchiveFormatCensusType -or
        [string]$Record.registry_archive_policy -cne $script:D32BoundedDiagnosticRegistryArchivePolicy -or
        [string]$Record.gate_authority -cne 'NONE' -or $Record.formal_phase1_allowed -isnot [bool] -or [bool]$Record.formal_phase1_allowed -or
        $Record.formal_aggregate_allowed -isnot [bool] -or [bool]$Record.formal_aggregate_allowed -or
        $Record.source_proof_checkpoint -isnot [bool] -or [bool]$Record.source_proof_checkpoint -or
        [string]$Record.diagnostic_invocation_authority -cne 'NONE' -or
        [string]$Record.status -cnotin @('COMPLETE_DIAGNOSTIC', 'BLOCKED', 'BUDGET_STOPPED') -or
        [string]$Record.candidate_sha -cnotmatch '^[0-9a-f]{40}$' -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $Record.source_repo) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.source_plan_semantics_version -Positive) -or [Int64]$Record.source_plan_semantics_version -ne 2 -or
        [string]$Record.semantic_scope -cne 'EXACT_CALLER_PINNED_CURRENT_LOCK_ARCHIVE_FORMAT_SUBSET' -or
        [string]$Record.registry_tuple_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.repository_identity @('volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Record.repository_identity) -or
        [string]$Record.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.elapsed_milliseconds) -or [Int64]$Record.elapsed_milliseconds -gt 300000 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.requested_archive_count -Positive) -or [Int64]$Record.requested_archive_count -gt 1115 -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.covered_archive_count) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.blocked_archive_count) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.unexamined_archive_count) -or
        $Record.archives -isnot [Array] -or $Record.unexamined_archive_ids -isnot [Array] -or
        $Record.archives.Count -ne [Int64]$Record.requested_archive_count -or
        [Int64]$Record.covered_archive_count + [Int64]$Record.unexamined_archive_count -ne [Int64]$Record.requested_archive_count -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.aggregate_format_counts $countFields) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.ordinary_header_count) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.longname_pair_count) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.longname_control_metadata_count) -or
        -not (Test-D32BoundedCompilerDiagnosticInteger $Record.longname_control_metadata_bytes) -or
        [string]$Record.longname_pair_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Record.longname_control_metadata_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Record.archive_header_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Record.ordinary_payload_read_and_discarded -isnot [bool] -or [bool]$Record.ordinary_payload_read_and_discarded -ne $true -or
        $Record.ordinary_payload_hashed -isnot [bool] -or [bool]$Record.ordinary_payload_hashed -or
        $Record.ordinary_payload_retained -isnot [bool] -or [bool]$Record.ordinary_payload_retained -or
        $Record.longname_control_metadata_hashed -isnot [bool] -or [bool]$Record.longname_control_metadata_hashed -ne $true -or
        $Record.longname_control_metadata_retained -isnot [bool] -or [bool]$Record.longname_control_metadata_retained -or
        $Record.source_extraction_performed -isnot [bool] -or [bool]$Record.source_extraction_performed -or
        $Record.formal_gate_usable -isnot [bool] -or [bool]$Record.formal_gate_usable -or
        (($Record.primary_error -isnot [string]) -and ($null -ne $Record.primary_error)) -or
        $Record.secondary_errors -isnot [Array]) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'result.schema_policy_candidate_status_counts_or_payload_fields'
        return $false
    }
    if (@($Record.secondary_errors | Where-Object { $_ -isnot [string] }).Count -gt 0 -or $Record.secondary_errors.Count -gt 64) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'secondary_errors.items_or_count'
        return $false
    }

    $cargoHome = 'E:\d32\inv7\r\c'
    $archiveRoot = Join-Path $cargoHome 'registry/cache/index.crates.io-1949cf8c6b5b557f'
    $authorityReferenceFailure = Get-D32BoundedCompilerDiagnosticFileReferenceShapeFailure -Reference $Record.census_authority_reference
    if ($null -ne $authorityReferenceFailure) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "census_authority_reference.$authorityReferenceFailure"
        return $false
    }
    if ([Int64]$Record.census_authority_reference.bytes -gt 16777216 -or
        (Test-D32BoundedCompilerDiagnosticWithin ([string]$Record.census_authority_reference.path) ([string]$Record.source_repo)) -or
        (Test-D32BoundedCompilerDiagnosticWithin ([string]$Record.census_authority_reference.path) $cargoHome)) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'census_authority_reference.bytes_or_external_path'
        return $false
    }
    $lockReferenceFailure = Get-D32BoundedCompilerDiagnosticFileReferenceShapeFailure -Reference $Record.lock_reference
    if ($null -ne $lockReferenceFailure -or [Int64]$Record.lock_reference.bytes -gt 16777216 -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Record.lock_reference.path, [IO.Path]::GetFullPath((Join-Path ([string]$Record.source_repo) 'vita-agent/Cargo.lock'))) -or
        -not (Test-D32BoundedCompilerDiagnosticWithin ([string]$Record.lock_reference.path) ([string]$Record.source_repo))) {
        $failure = if ($null -ne $lockReferenceFailure) { $lockReferenceFailure } else { 'bytes_or_canonical_lock_path' }
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "lock_reference.$failure"
        return $false
    }

    $originFields = @('path', 'volume_serial_hex', 'file_id_hex', 'registry_archive_root')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.dependency_origin $originFields) -or
        [string]$Record.dependency_origin.path -cne $cargoHome -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Record.dependency_origin) -or
        -not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.dependency_origin.registry_archive_root @('path', 'volume_serial_hex', 'file_id_hex')) -or
        [string]$Record.dependency_origin.registry_archive_root.path -cne $archiveRoot -or
        -not (Test-D32BoundedCompilerDiagnosticIdentityPair $Record.dependency_origin.registry_archive_root)) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'dependency_origin.registry_archive_root_or_identity'
        return $false
    }

    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.historical_origin @('candidate_sha', 'attempt_state', 'fetch_completion', 'gate_authority', 'owner_record', 'blocked_diagnostic')) -or
        [string]$Record.historical_origin.candidate_sha -cne $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -or
        [string]$Record.historical_origin.attempt_state -cne 'BLOCKED' -or [string]$Record.historical_origin.fetch_completion -cne 'NOT_RETAINED' -or
        [string]$Record.historical_origin.gate_authority -cne 'NONE' -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Record.historical_origin.owner_record) -or
        [string]$Record.historical_origin.owner_record.path -cne 'E:\d32\inv7\D32-PHASE0-OWNER.json' -or
        -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $Record.historical_origin.blocked_diagnostic) -or
        [string]$Record.historical_origin.blocked_diagnostic.path -cne 'E:\d32\inv7\D32-PHASE0-BLOCKED-DIAGNOSTIC.json') {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'historical_origin.identity_or_references'
        return $false
    }

    $expectedPinPaths = @(
        [IO.Path]::GetFullPath((Join-Path ([string]$Record.source_repo) 'scripts/d32-bounded-diagnostic-archive-format-census.ps1')),
        [IO.Path]::GetFullPath((Join-Path ([string]$Record.source_repo) 'scripts/d32-bounded-compiler-diagnostic-policy.ps1')),
        [IO.Path]::GetFullPath((Join-Path ([string]$Record.source_repo) 'scripts/d32-build-toolchain-profile.ps1')),
        [IO.Path]::GetFullPath((Join-Path ([string]$Record.source_repo) 'scripts/d32-powershell-module-authority.ps1')))
    if ($Record.source_pins -isnot [Array] -or $Record.source_pins.Count -ne $expectedPinPaths.Count) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'source_pins.array_or_count'
        return $false
    }
    $seenPinPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pinIndex = 0
    foreach ($pin in $Record.source_pins) {
        if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $pin) -or
            [Int64]$pin.bytes -gt 16777216 -or
            -not (Test-D32BoundedCompilerDiagnosticWithin ([string]$pin.path) ([string]$Record.source_repo)) -or
            -not $seenPinPaths.Add([string]$pin.path)) {
            Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "source_pins[$pinIndex].reference_or_unique_path"
            return $false
        }
        $pinIndex++
    }
    foreach ($expectedPinPath in $expectedPinPaths) {
        if (@($Record.source_pins | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals([string]$_.path, $expectedPinPath) }).Count -ne 1) {
            Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "source_pins.expected_path:$expectedPinPath"
            return $false
        }
    }

    $output = $Record.output_candidate
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $output @('path', 'parent_path', 'parent_volume_serial_hex', 'parent_file_id_hex')) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.path) -or
        -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $output.parent_path) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName([string]$output.path), [string]$output.parent_path) -or
        [string]$output.parent_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$output.parent_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        (Test-D32BoundedCompilerDiagnosticWithin ([string]$output.path) ([string]$Record.source_repo)) -or
        (Test-D32BoundedCompilerDiagnosticWithin ([string]$output.path) $cargoHome)) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'output_candidate.path_parent_identity_or_externality'
        return $false
    }

    $budgetFields = @('combined_milliseconds', 'managed_buffer_bytes', 'max_archive_bytes', 'max_archive_expanded_bytes',
        'max_archive_member_bytes', 'max_archive_members', 'max_aggregate_expanded_bytes', 'max_aggregate_members', 'maximum_output_bytes')
    if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $Record.resource_budget $budgetFields)) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'resource_budget.property_set'
        return $false
    }
    foreach ($budgetField in $budgetFields) { if (-not (Test-D32BoundedCompilerDiagnosticInteger $Record.resource_budget.($budgetField) -Positive)) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "resource_budget.$budgetField.integer"
        return $false
    } }
    if (
        [Int64]$Record.resource_budget.combined_milliseconds -ne 300000 -or [Int64]$Record.resource_budget.managed_buffer_bytes -ne 536870912 -or
        [Int64]$Record.resource_budget.max_archive_bytes -ne 268435456 -or [Int64]$Record.resource_budget.max_archive_expanded_bytes -ne 1073741824 -or
        [Int64]$Record.resource_budget.max_archive_member_bytes -ne 134217728 -or [Int64]$Record.resource_budget.max_archive_members -ne 10000 -or
        [Int64]$Record.resource_budget.max_aggregate_expanded_bytes -ne 34359738368 -or [Int64]$Record.resource_budget.max_aggregate_members -ne 1000000 -or
        [Int64]$Record.resource_budget.maximum_output_bytes -ne 67108864) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'resource_budget.fixed_bound_values'
        return $false
    }
    foreach ($field in $countFields) { if (-not (Test-D32BoundedCompilerDiagnosticInteger $Record.aggregate_format_counts.($field))) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "aggregate_format_counts.$field.integer"
        return $false
    } }
    if ([string]$Record.longname_pair_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Record.longname_control_metadata_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'aggregate_longname_digest.lowercase_hex'
        return $false
    }
    $unexamined = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $unexaminedIndex = 0
    foreach ($id in $Record.unexamined_archive_ids) { if ($id -isnot [string] -or -not $unexamined.Add([string]$id)) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "unexamined_archive_ids[$unexaminedIndex].string_or_unique"
        return $false
    }; $unexaminedIndex++ }
    $coverageFields = @('archive_id', 'source', 'name', 'version', 'checksum', 'archive_path', 'archive_bytes', 'archive_sha256',
        'archive_volume_serial_hex', 'archive_file_id_hex', 'opened_archive_bytes', 'opened_archive_sha256',
        'opened_archive_volume_serial_hex', 'opened_archive_file_id_hex', 'status', 'expanded_bytes', 'header_count',
        'ordinary_header_count', 'longname_pair_count', 'longname_pair_inventory_sha256', 'longname_control_metadata_count',
        'longname_control_metadata_bytes', 'longname_control_metadata_sha256', 'format_counts',
        'header_inventory_sha256', 'framing_verified', 'remainder_unknown', 'first_failure_offset', 'first_failure_header_sha256', 'first_failure_reason')
    $coverageIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $computedUnexamined = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $actualCounts = [ordered]@{ ustar_regular = 0L; ustar_directory = 0L; gnu_regular = 0L; gnu_directory = 0L; gnu_longname_extension = 0L }
    $actualOrdinaryHeaderCount = [Int64]0
    $actualPairCount = [Int64]0
    $actualControlCount = [Int64]0
    $actualControlBytes = [Int64]0
    $aggregateExpandedBytes = [Int64]0
    $aggregateHeaderCount = [Int64]0
    $pairDigestRows = [System.Collections.Generic.List[string]]::new()
    $controlDigestRows = [System.Collections.Generic.List[string]]::new()
    $archiveIndex = 0
    foreach ($archive in $Record.archives) {
        if (-not (Test-D32BoundedCompilerDiagnosticExactProperties $archive $coverageFields)) {
            Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "archives[$archiveIndex].property_set"
            return $false
        }
        if ($archive.archive_id -isnot [string] -or -not $coverageIds.Add([string]$archive.archive_id) -or
            [string]$archive.source -cne 'registry+https://github.com/rust-lang/crates.io-index' -or
            [string]$archive.name -notmatch '^[A-Za-z0-9_-]+$' -or [string]$archive.version -notmatch '^[0-9A-Za-z.+_-]+$' -or
            [string]$archive.archive_id -cne ([string]$archive.name + '@' + [string]$archive.version) -or
            [string]$archive.checksum -cnotmatch '^[0-9a-f]{64}$' -or [string]$archive.archive_sha256 -cne [string]$archive.checksum -or
            -not (Test-D32BoundedCompilerDiagnosticCanonicalPath $archive.archive_path) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$archive.archive_path,
                (Join-Path 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f' ([string]$archive.name + '-' + [string]$archive.version + '.crate'))) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $archive.archive_bytes -Positive) -or [Int64]$archive.archive_bytes -gt 268435456 -or
            [string]$archive.archive_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$archive.archive_file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            (($archive.opened_archive_bytes -isnot [long] -and $archive.opened_archive_bytes -isnot [int]) -and ($null -ne $archive.opened_archive_bytes)) -or
            (($archive.opened_archive_sha256 -isnot [string]) -and ($null -ne $archive.opened_archive_sha256)) -or
            (($archive.opened_archive_volume_serial_hex -isnot [string]) -and ($null -ne $archive.opened_archive_volume_serial_hex)) -or
            (($archive.opened_archive_file_id_hex -isnot [string]) -and ($null -ne $archive.opened_archive_file_id_hex)) -or
            [string]$archive.status -cnotin @('COMPLETE_SUPPORTED', 'UNSUPPORTED', 'PREFLIGHT_BLOCKED', 'BUDGET_STOPPED', 'UNEXAMINED') -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $archive.expanded_bytes) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $archive.header_count) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $archive.ordinary_header_count) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $archive.longname_pair_count) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $archive.longname_control_metadata_count) -or
            -not (Test-D32BoundedCompilerDiagnosticInteger $archive.longname_control_metadata_bytes) -or
            [Int64]$archive.expanded_bytes -gt 1073741824 -or [Int64]$archive.header_count -gt 10000 -or
            [Int64]$archive.ordinary_header_count -gt 10000 -or [Int64]$archive.longname_pair_count -gt 10000 -or
            [Int64]$archive.longname_control_metadata_count -gt 10000 -or
            [string]$archive.longname_pair_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$archive.longname_control_metadata_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-D32BoundedCompilerDiagnosticExactProperties $archive.format_counts $countFields) -or
            ([Int64]$archive.header_count -gt 0 -and [string]$archive.header_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$') -or
            ([Int64]$archive.header_count -eq 0 -and $null -ne $archive.header_inventory_sha256) -or
            $archive.framing_verified -isnot [bool] -or $archive.remainder_unknown -isnot [bool] -or
            (($archive.first_failure_offset -isnot [long] -and $archive.first_failure_offset -isnot [int]) -and ($null -ne $archive.first_failure_offset)) -or
            (($archive.first_failure_header_sha256 -isnot [string]) -and ($null -ne $archive.first_failure_header_sha256)) -or
            (($archive.first_failure_reason -isnot [string]) -and ($null -ne $archive.first_failure_reason))) {
            Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "archives[$archiveIndex].shape_identity_status_or_scalar_type"
            return $false
        }
        if ($null -ne $archive.first_failure_offset -and [Int64]$archive.first_failure_offset -lt 0) {
            Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "archives[$archiveIndex].first_failure_offset.nonnegative"
            return $false
        }
        if ($null -ne $archive.first_failure_header_sha256 -and [string]$archive.first_failure_header_sha256 -cnotmatch '^[0-9a-f]{64}$') {
            Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "archives[$archiveIndex].first_failure_header_sha256.lowercase_hex"
            return $false
        }
        if ($null -eq $archive.opened_archive_bytes) {
            if ($null -ne $archive.opened_archive_sha256 -or $null -ne $archive.opened_archive_volume_serial_hex -or $null -ne $archive.opened_archive_file_id_hex) {
                Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "archives[$archiveIndex].opened_archive_reference.null_tuple"
                return $false
            }
        }
        else {
            if ([Int64]$archive.opened_archive_bytes -le 0 -or [Int64]$archive.opened_archive_bytes -gt 268435456 -or
                [string]$archive.opened_archive_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                [string]$archive.opened_archive_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
                [string]$archive.opened_archive_file_id_hex -cnotmatch '^[0-9a-f]{32}$') {
                Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "archives[$archiveIndex].opened_archive_reference.identity_tuple"
                return $false
            }
        }
        foreach ($field in $countFields) {
            if (-not (Test-D32BoundedCompilerDiagnosticInteger $archive.format_counts.($field)) -or
                [Int64]$archive.format_counts.($field) -gt 10000) {
                Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "archives[$archiveIndex].format_counts.$field.integer"
                return $false
            }
            $actualCounts[$field] = [Int64]$actualCounts[$field] + [Int64]$archive.format_counts.($field)
        }
        $formatTotal = [Int64]$archive.format_counts.ustar_regular + [Int64]$archive.format_counts.ustar_directory +
            [Int64]$archive.format_counts.gnu_regular + [Int64]$archive.format_counts.gnu_directory +
            [Int64]$archive.format_counts.gnu_longname_extension
        $ordinaryFormatTotal = [Int64]$archive.format_counts.ustar_regular + [Int64]$archive.format_counts.ustar_directory +
            [Int64]$archive.format_counts.gnu_regular + [Int64]$archive.format_counts.gnu_directory
        $actualOrdinaryHeaderCount += [Int64]$archive.ordinary_header_count
        $actualPairCount += [Int64]$archive.longname_pair_count
        $actualControlCount += [Int64]$archive.longname_control_metadata_count
        $actualControlBytes += [Int64]$archive.longname_control_metadata_bytes
        $aggregateExpandedBytes += [Int64]$archive.expanded_bytes
        $aggregateHeaderCount += [Int64]$archive.header_count
        $pairDigestRows.Add([string]$archive.archive_id + "`t" + [string]$archive.longname_pair_inventory_sha256)
        $controlDigestRows.Add([string]$archive.archive_id + "`t" + [string]$archive.longname_control_metadata_sha256)
        if ($formatTotal -gt [Int64]$archive.header_count) {
            Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "archives[$archiveIndex].format_counts.header_count_bound"
            return $false
        }
        if ($ordinaryFormatTotal -ne [Int64]$archive.ordinary_header_count -or
            [Int64]$archive.longname_pair_count -gt [Int64]$archive.longname_control_metadata_count -or
            [Int64]$archive.longname_control_metadata_count -gt [Int64]$archive.format_counts.gnu_longname_extension -or
            ([Int64]$archive.longname_control_metadata_count -gt 0 -and [Int64]$archive.longname_control_metadata_bytes -lt ([Int64]$archive.longname_control_metadata_count * 2L)) -or
            [Int64]$archive.longname_control_metadata_bytes -gt ([Int64]$archive.longname_control_metadata_count * 4097L) -or
            ([Int64]$archive.longname_control_metadata_count -eq 0 -and [Int64]$archive.longname_control_metadata_bytes -ne 0)) {
            Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "archives[$archiveIndex].ordinary_pair_control_count_or_byte_bound"
            return $false
        }
        if ([string]$archive.status -ceq 'COMPLETE_SUPPORTED') {
            if ($formatTotal -ne [Int64]$archive.header_count -or
                [Int64]$archive.longname_pair_count -ne [Int64]$archive.format_counts.gnu_longname_extension -or
                [Int64]$archive.longname_control_metadata_count -ne [Int64]$archive.longname_pair_count -or
                [bool]$archive.remainder_unknown -or -not [bool]$archive.framing_verified -or
                [string]$archive.header_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                [Int64]$archive.opened_archive_bytes -ne [Int64]$archive.archive_bytes -or
                [string]$archive.opened_archive_sha256 -cne [string]$archive.checksum -or
                [string]$archive.opened_archive_volume_serial_hex -cne [string]$archive.archive_volume_serial_hex -or
                [string]$archive.opened_archive_file_id_hex -cne [string]$archive.archive_file_id_hex -or
                $null -ne $archive.first_failure_reason -or $null -ne $archive.first_failure_offset -or
                $null -ne $archive.first_failure_header_sha256) {
                Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "archives[$archiveIndex].complete_status_invariants"
                return $false
            }
        }
        else {
            if (-not [bool]$archive.remainder_unknown -or [string]$archive.first_failure_reason -notlike 'D32_BOUNDED_DIAGNOSTIC_CENSUS_*:*') {
                Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "archives[$archiveIndex].blocked_status_remainder_or_first_failure_reason"
                return $false
            }
            if ([string]$archive.status -ceq 'UNEXAMINED') { [void]$computedUnexamined.Add([string]$archive.archive_id) }
        }
        $archiveIndex++
    }
    if ($unexamined.Count -ne $computedUnexamined.Count -or
        @($unexamined | Where-Object { -not $computedUnexamined.Contains($_) }).Count -ne 0 -or
        [Int64]$Record.covered_archive_count -ne @($Record.archives | Where-Object { [string]$_.status -cne 'UNEXAMINED' }).Count -or
        [Int64]$Record.blocked_archive_count -ne @($Record.archives | Where-Object { [string]$_.status -cin @('UNSUPPORTED', 'PREFLIGHT_BLOCKED') }).Count) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'coverage_counts_or_unexamined_archive_ids'
        return $false
    }
    if ($aggregateExpandedBytes -gt 34359738368 -or $aggregateHeaderCount -gt 1000000) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'coverage.aggregate_expanded_bytes_or_member_count_bound'
        return $false
    }
    foreach ($field in $countFields) { if ([Int64]$Record.aggregate_format_counts.($field) -ne [Int64]$actualCounts[$field]) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason "aggregate_format_counts.$field.coverage_sum"
        return $false
    } }
    if ([Int64]$Record.ordinary_header_count -ne $actualOrdinaryHeaderCount -or
        [Int64]$Record.longname_pair_count -ne $actualPairCount -or
        [Int64]$Record.longname_control_metadata_count -ne $actualControlCount -or
        [Int64]$Record.longname_control_metadata_bytes -ne $actualControlBytes -or
        [string]$Record.longname_pair_inventory_sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes(($pairDigestRows -join "`n") + "`n"))).ToLowerInvariant() -or
        [string]$Record.longname_control_metadata_sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes(($controlDigestRows -join "`n") + "`n"))).ToLowerInvariant()) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'aggregate_longname_counts_or_digests.coverage_sum'
        return $false
    }
    $expectedArchiveDigest = Get-D32BoundedDiagnosticArchiveFormatCensusCoverageDigest -Archives @($Record.archives)
    if ([string]$Record.archive_header_inventory_sha256 -cne $expectedArchiveDigest) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'archive_header_inventory_sha256.coverage_digest'
        return $false
    }
    if ([string]$Record.status -ceq 'COMPLETE_DIAGNOSTIC' -and
        ([Int64]$Record.covered_archive_count -ne [Int64]$Record.requested_archive_count -or [Int64]$Record.blocked_archive_count -ne 0 -or
         [Int64]$Record.unexamined_archive_count -ne 0 -or @($Record.archives | Where-Object { [string]$_.status -cne 'COMPLETE_SUPPORTED' }).Count -ne 0 -or
         $null -ne $Record.primary_error)) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'status.COMPLETE_DIAGNOSTIC.coverage_or_primary_error'
        return $false
    }
    if ([string]$Record.status -ceq 'BLOCKED' -and ([Int64]$Record.blocked_archive_count -eq 0 -or
        [String]::IsNullOrWhiteSpace([string]$Record.primary_error))) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'status.BLOCKED.blocked_count_or_primary_error'
        return $false
    }
    if ([string]$Record.status -ceq 'BUDGET_STOPPED' -and
        (@($Record.archives | Where-Object { [string]$_.status -ceq 'BUDGET_STOPPED' }).Count -eq 0 -and [Int64]$Record.unexamined_archive_count -eq 0 -or
         [String]::IsNullOrWhiteSpace([string]$Record.primary_error))) {
        Add-D32BoundedDiagnosticArchiveFormatCensusValidationFailure -FailureReasons $FailureReasons -Reason 'status.BUDGET_STOPPED.budget_row_unexamined_or_primary_error'
        return $false
    }
    return $true
}
