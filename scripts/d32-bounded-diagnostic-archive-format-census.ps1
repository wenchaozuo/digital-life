# Exact-SHA, caller-authorized, read-only archive-format census. This entry
# consumes only finite registry archive references and never starts Cargo, Git,
# rustc, another process, a helper, or a network operation.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$CandidateSha,
    [Parameter(Mandatory = $true)][string]$CensusAuthorityPath,
    [Parameter(Mandatory = $true)][string]$ExpectedCensusAuthoritySha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$censusStartedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
$censusTimer = [Diagnostics.Stopwatch]::StartNew()
$moduleAuthorityPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-powershell-module-authority.ps1'))
. $moduleAuthorityPath

function Test-D32ArchiveCensusFileReferenceExact {
    param([object]$Actual, [object]$Expected)
    $expectedNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { [void]$expectedNames.Add($name) }
    if ($null -eq $Actual -or $Actual -is [string] -or $Actual -is [Array] -or $Actual -is [ValueType]) { return $false }
    $actualNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    if ($Actual -is [System.Collections.IDictionary]) {
        foreach ($key in $Actual.Keys) { [void]$actualNames.Add([string]$key) }
    }
    else { foreach ($property in $Actual.PSObject.Properties) { [void]$actualNames.Add([string]$property.Name) } }
    if ($actualNames.Count -ne $expectedNames.Count) { return $false }
    foreach ($name in $expectedNames) { if (-not $actualNames.Contains($name)) { return $false } }
    return ([string]$Actual.path -ceq [string]$Expected.path -and [Int64]$Actual.bytes -eq [Int64]$Expected.bytes -and
        [string]$Actual.sha256 -ceq [string]$Expected.sha256 -and
        [string]$Actual.volume_serial_hex -ceq [string]$Expected.volume_serial_hex -and
        [string]$Actual.file_id_hex -ceq [string]$Expected.file_id_hex)
}

function Assert-D32ArchiveCensusDirectoryIdentity {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$VolumeSerialHex, [Parameter(Mandatory = $true)][string]$FileIdHex)
    $identity = Get-D32ProfileDirectoryIdentity -Path $Path
    if (($identity.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
        [IO.Path]::GetFullPath([string]$identity.Path) -cne [IO.Path]::GetFullPath($Path) -or
        [string]$identity.VolumeSerialHex -cne $VolumeSerialHex -or [string]$identity.FileIdHex -cne $FileIdHex) {
        throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: pinned directory identity or no-reparse fence changed'
    }
    return $identity
}

$repoFull = [IO.Path]::GetFullPath($Repository)
$entryPath = [IO.Path]::GetFullPath($PSCommandPath)
$policyPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-bounded-compiler-diagnostic-policy.ps1'))
$profilePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-build-toolchain-profile.ps1'))
$expectedAuthorityFull = [IO.Path]::GetFullPath($CensusAuthorityPath)
if ($repoFull -cne $Repository -or $CandidateSha -cnotmatch '^[0-9a-f]{40}$' -or
    $expectedAuthorityFull -cne $CensusAuthorityPath -or
    $ExpectedCensusAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or
    -not [StringComparer]::OrdinalIgnoreCase.Equals($entryPath, [IO.Path]::GetFullPath((Join-Path $repoFull 'scripts/d32-bounded-diagnostic-archive-format-census.ps1'))) -or
    (Test-D32PowerShellAuthorityPathWithin -Child $expectedAuthorityFull -Parent $repoFull)) {
    throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: direct entry, repository, candidate or external caller-pin path is invalid'
}

$fences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
$authorityFile = $null
$authorityDocument = $null
try {
    $authorityFile = Open-D32PowerShellAuthorityFile -Path $expectedAuthorityFull -DirectoryFences $fences -MaximumBytes 16777216
    if ([string]$authorityFile.Record.sha256 -cne $ExpectedCensusAuthoritySha256) {
        throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: caller-pinned census authority SHA differs from opened bytes'
    }
    $authorityText = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$authorityFile.Bytes)
    $authorityJson = [System.Text.Json.JsonDocument]::Parse($authorityText)
    try {
        if ($authorityJson.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
            (Test-D32PowerShellAuthorityJsonDuplicates -Element $authorityJson.RootElement)) {
            throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: census authority JSON root or duplicate-key check failed'
        }
        $authorityDocument = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $authorityJson.RootElement
    }
    finally { $authorityJson.Dispose() }
}
finally {
    if ($null -ne $authorityFile -and $null -ne $authorityFile.Stream) { $authorityFile.Stream.Dispose() }
}

$sourcePins = @(
    [PSCustomObject]@{ path = $entryPath; field = 'entry' },
    [PSCustomObject]@{ path = $policyPath; field = 'policy' },
    [PSCustomObject]@{ path = $profilePath; field = 'profile' },
    [PSCustomObject]@{ path = $moduleAuthorityPath; field = 'module_authority' })
if ($null -eq $authorityDocument -or $authorityDocument.source_pins -isnot [Array] -or $authorityDocument.source_pins.Count -ne $sourcePins.Count) {
    throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: exact finite source-pin array is absent before current-code validation'
}
$openedPinByPath = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($expectedPin in $sourcePins) {
    $pin = @($authorityDocument.source_pins | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals([string]$_.path, [string]$expectedPin.path) })
    if ($pin.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: exact current entry/policy/Profile/module-authority pin is missing or ambiguous' }
    $openedPin = Open-D32PowerShellAuthorityFile -Path ([string]$pin[0].path) -DirectoryFences $fences -MaximumBytes 16777216
    try {
        if (-not (Test-D32ArchiveCensusFileReferenceExact -Actual $openedPin.Record -Expected $pin[0])) {
            throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: current code file differs from its independent exact-SHA pin'
        }
        $openedPinByPath.Add([string]$expectedPin.path, $pin[0])
    }
    finally { $openedPin.Stream.Dispose() }
}
. $profilePath
. $policyPath

if (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $authorityDocument -ExpectedCandidateSha $CandidateSha `
    -Repository $repoFull -EntryScriptPath $entryPath -PolicyPath $policyPath -ProfileScriptPath $profilePath)) {
    throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: strict census authority shape, policy or exact finite bounds rejected'
}

$repositoryIdentity = Assert-D32ArchiveCensusDirectoryIdentity -Path $repoFull `
    -VolumeSerialHex ([string]$authorityDocument.repository_identity.volume_serial_hex) `
    -FileIdHex ([string]$authorityDocument.repository_identity.file_id_hex)
$cargoHome = [string]$authorityDocument.dependency_origin.path
$archiveRoot = [string]$authorityDocument.dependency_origin.registry_archive_root.path
if ((Test-D32PowerShellAuthorityPathWithin -Child $expectedAuthorityFull -Parent $cargoHome) -or
    (Test-D32PowerShellAuthorityPathWithin -Child ([string]$authorityDocument.output_candidate.path) -Parent $cargoHome)) {
    throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: authority or output overlaps the source CargoHome'
}
$null = Assert-D32ArchiveCensusDirectoryIdentity -Path $cargoHome `
    -VolumeSerialHex ([string]$authorityDocument.dependency_origin.volume_serial_hex) `
    -FileIdHex ([string]$authorityDocument.dependency_origin.file_id_hex)
$null = Assert-D32ArchiveCensusDirectoryIdentity -Path $archiveRoot `
    -VolumeSerialHex ([string]$authorityDocument.dependency_origin.registry_archive_root.volume_serial_hex) `
    -FileIdHex ([string]$authorityDocument.dependency_origin.registry_archive_root.file_id_hex)
$outputParentIdentity = Assert-D32ArchiveCensusDirectoryIdentity -Path ([string]$authorityDocument.output_candidate.parent_path) `
    -VolumeSerialHex ([string]$authorityDocument.output_candidate.parent_volume_serial_hex) `
    -FileIdHex ([string]$authorityDocument.output_candidate.parent_file_id_hex)
if (Test-Path -LiteralPath ([string]$authorityDocument.output_candidate.path)) {
    throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: create-new census result path already exists'
}

$lockFile = $null
try {
    $lockFile = Open-D32PowerShellAuthorityFile -Path ([string]$authorityDocument.lock_reference.path) -DirectoryFences $fences -MaximumBytes 16777216
    if (-not (Test-D32ArchiveCensusFileReferenceExact -Actual $lockFile.Record -Expected $authorityDocument.lock_reference)) {
        throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: current Cargo.lock bytes, SHA or opened identity differ from caller pin'
    }
    $lockText = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$lockFile.Bytes)
    $sourcePlan = Get-D32BoundedCompilerDiagnosticSourcePlan -LockText $lockText
    if ([string]$sourcePlan.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_LOCK_SOURCE_PLAN_V2' -or
        [string]$sourcePlan.lock_sha256 -cne [string]$authorityDocument.lock_reference.sha256 -or
        [string]$sourcePlan.registry_tuple_sha256 -cne [string]$authorityDocument.registry_tuple_sha256) {
        throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: current lock source-plan V2 tuple differs from the independently pinned authority'
    }
    $lockArchiveByKey = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($package in $sourcePlan.registry_packages) {
        $key = [string]$package.name + "`0" + [string]$package.version
        if (-not $lockArchiveByKey.TryAdd($key, $package)) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: current lock has duplicate registry package identities' }
    }
    foreach ($archive in $authorityDocument.archive_refs) {
        $key = [string]$archive.name + "`0" + [string]$archive.version
        if (-not $lockArchiveByKey.ContainsKey($key) -or
            [string]$lockArchiveByKey[$key].checksum -cne [string]$archive.checksum -or
            [string]$lockArchiveByKey[$key].archive_path -cne [string]$archive.path) {
            throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: finite archive reference is not the exact current lock source/checksum/path'
        }
    }
}
finally {
    if ($null -ne $lockFile -and $null -ne $lockFile.Stream) { $lockFile.Stream.Dispose() }
}

$coverage = [System.Collections.Generic.List[object]]::new()
$secondaryErrors = [System.Collections.Generic.List[string]]::new()
$aggregateExpanded = [Int64]0
$aggregateMembers = [Int64]0
$blocked = $false
$budgetStopped = $false
$globalRootFailure = $false
$archives = @($authorityDocument.archive_refs)
for ($archiveIndex = 0; $archiveIndex -lt $archives.Count; $archiveIndex++) {
    $archive = $archives[$archiveIndex]
    if ($censusTimer.ElapsedMilliseconds -ge [Int64]$authorityDocument.resource_budget.combined_milliseconds -or
        $aggregateExpanded -ge [Int64]$authorityDocument.resource_budget.max_aggregate_expanded_bytes -or
        $aggregateMembers -ge [Int64]$authorityDocument.resource_budget.max_aggregate_members) {
        $budgetStopped = $true
        for ($remainingIndex = $archiveIndex; $remainingIndex -lt $archives.Count; $remainingIndex++) {
            $coverage.Add((New-D32BoundedDiagnosticArchiveFormatCensusUnexaminedRow -Archive $archives[$remainingIndex] -Reason 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: finite global budget ended before this archive'))
        }
        break
    }
    $opened = $null
    $openedReference = $null
    $inventory = $null
    $rowStatus = 'PREFLIGHT_BLOCKED'
    $failureReason = $null
    try {
        $null = Assert-D32ArchiveCensusDirectoryIdentity -Path $cargoHome `
            -VolumeSerialHex ([string]$authorityDocument.dependency_origin.volume_serial_hex) `
            -FileIdHex ([string]$authorityDocument.dependency_origin.file_id_hex)
        $null = Assert-D32ArchiveCensusDirectoryIdentity -Path $archiveRoot `
            -VolumeSerialHex ([string]$authorityDocument.dependency_origin.registry_archive_root.volume_serial_hex) `
            -FileIdHex ([string]$authorityDocument.dependency_origin.registry_archive_root.file_id_hex)
        $opened = Open-D32PowerShellAuthorityFile -Path ([string]$archive.path) -DirectoryFences $fences `
            -MaximumBytes ([Int64]$authorityDocument.resource_budget.max_archive_bytes)
        $openedReference = $opened.Record
        if (-not (Test-D32ArchiveCensusFileReferenceExact -Actual $opened.Record -Expected $archive)) {
            $failureReason = 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: opened archive bytes, SHA or identity differs from caller pin'
            $rowStatus = 'PREFLIGHT_BLOCKED'
        }
        elseif ([string]$opened.Record.sha256 -cne [string]$lockArchiveByKey[[string]$archive.name + "`0" + [string]$archive.version].checksum) {
            $failureReason = 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: opened archive SHA differs from exact current lock checksum'
            $rowStatus = 'PREFLIGHT_BLOCKED'
        }
        else {
            $remainingExpanded = [Int64]$authorityDocument.resource_budget.max_aggregate_expanded_bytes - $aggregateExpanded
            $remainingMembers = [Int64]$authorityDocument.resource_budget.max_aggregate_members - $aggregateMembers
            $inventory = Get-D32BoundedDiagnosticArchiveFormatCensusInventory -CompressedBytes ([byte[]]$opened.Bytes) `
                -ExpectedPackageRoot ([string]$archive.name + '-' + [string]$archive.version) `
                -ExpectedArchiveSha256 ([string]$archive.checksum) -CensusTimer $censusTimer `
                -MaximumCompressedBytes ([Int64]$authorityDocument.resource_budget.max_archive_bytes) `
                -MaximumExpandedBytes ([Math]::Min([Int64]$authorityDocument.resource_budget.max_archive_expanded_bytes, $remainingExpanded)) `
                -MaximumMemberBytes ([Int64]$authorityDocument.resource_budget.max_archive_member_bytes) `
                -MaximumMembers ([int][Math]::Min([Int64]$authorityDocument.resource_budget.max_archive_members, $remainingMembers))
            $snapshotAfter = Get-D32ProfileFileSnapshot -Path ([string]$archive.path)
            if ($snapshotAfter.Bytes -ne [Int64]$archive.bytes -or $snapshotAfter.Sha256 -cne [string]$archive.sha256 -or
                $snapshotAfter.VolumeSerialHex -cne [string]$archive.volume_serial_hex -or $snapshotAfter.FileIdHex -cne [string]$archive.file_id_hex) {
                $failureReason = 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: archive path identity or content changed across the bounded census read'
                $rowStatus = 'PREFLIGHT_BLOCKED'
                $inventory = $null
            }
            elseif ([string]$inventory.status -ceq 'COMPLETE_DIAGNOSTIC') { $rowStatus = 'COMPLETE_SUPPORTED' }
            elseif ([string]$inventory.status -ceq 'BUDGET_STOPPED') { $rowStatus = 'BUDGET_STOPPED'; $budgetStopped = $true }
            else { $rowStatus = 'UNSUPPORTED'; $blocked = $true }
            if ($null -eq $failureReason -and $null -ne $inventory.first_failure_reason) { $failureReason = [string]$inventory.first_failure_reason }
        }
    }
    catch {
        $failureReason = if ([string]$_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED:*') {
            'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: finite archive read or time bound reached'
        } else { 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: pinned archive could not be reopened within its exact root/identity fence' }
        if ($failureReason -like '*BUDGET_STOPPED:*') { $rowStatus = 'BUDGET_STOPPED'; $budgetStopped = $true }
        else { $rowStatus = 'PREFLIGHT_BLOCKED'; $blocked = $true }
        if ($null -eq $openedReference -and $null -ne $opened) { $openedReference = $opened.Record }
    }
    finally {
        if ($null -ne $opened -and $null -ne $opened.Stream) { $opened.Stream.Dispose() }
    }
    if ($null -ne $inventory) {
        $aggregateExpanded += [Int64]$inventory.expanded_bytes
        $aggregateMembers += [Int64]$inventory.member_count
    }
    if ($null -eq $failureReason -and $rowStatus -cne 'COMPLETE_SUPPORTED') {
        $failureReason = 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: archive could not be fully covered under the approved format policy'
    }
    $coverage.Add((New-D32BoundedDiagnosticArchiveFormatCensusCoverageRow -Archive $archive -Status $rowStatus -OpenedReference $openedReference -Inventory $inventory -FailureReason $failureReason))
    if ($null -ne $failureReason -and $secondaryErrors.Count -lt 64) { $secondaryErrors.Add($failureReason) }
    if ($rowStatus -ceq 'PREFLIGHT_BLOCKED') {
        try {
            $null = Assert-D32ArchiveCensusDirectoryIdentity -Path $archiveRoot `
                -VolumeSerialHex ([string]$authorityDocument.dependency_origin.registry_archive_root.volume_serial_hex) `
                -FileIdHex ([string]$authorityDocument.dependency_origin.registry_archive_root.file_id_hex)
        }
        catch {
            $globalRootFailure = $true
            for ($remainingIndex = $archiveIndex + 1; $remainingIndex -lt $archives.Count; $remainingIndex++) {
                $coverage.Add((New-D32BoundedDiagnosticArchiveFormatCensusUnexaminedRow -Archive $archives[$remainingIndex] -Reason 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: root identity changed; later references were not opened'))
            }
            break
        }
    }
    if ($rowStatus -ceq 'BUDGET_STOPPED') {
        for ($remainingIndex = $archiveIndex + 1; $remainingIndex -lt $archives.Count; $remainingIndex++) {
            $coverage.Add((New-D32BoundedDiagnosticArchiveFormatCensusUnexaminedRow -Archive $archives[$remainingIndex] -Reason 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: finite global budget ended before this archive'))
        }
        break
    }
}

if ($censusTimer.ElapsedMilliseconds -ge [Int64]$authorityDocument.resource_budget.combined_milliseconds) {
    $budgetStopped = $true
    if ($coverage.Count -gt 0 -and [string]$coverage[0].status -ceq 'COMPLETE_SUPPORTED') {
        $coverage[0].status = 'BUDGET_STOPPED'; $coverage[0].remainder_unknown = $true
        $coverage[0].framing_verified = $false; $coverage[0].first_failure_offset = $null
        $coverage[0].first_failure_header_sha256 = $null
        $coverage[0].first_failure_reason = 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: aggregate deadline expired before final input fences and persistence'
        if ($secondaryErrors.Count -lt 64) { $secondaryErrors.Add([string]$coverage[0].first_failure_reason) }
    }
}
else {
    $finalFenceFailure = $false
    try {
        $null = Assert-D32ArchiveCensusDirectoryIdentity -Path $repoFull `
            -VolumeSerialHex ([string]$authorityDocument.repository_identity.volume_serial_hex) `
            -FileIdHex ([string]$authorityDocument.repository_identity.file_id_hex)
        $null = Assert-D32ArchiveCensusDirectoryIdentity -Path $cargoHome `
            -VolumeSerialHex ([string]$authorityDocument.dependency_origin.volume_serial_hex) `
            -FileIdHex ([string]$authorityDocument.dependency_origin.file_id_hex)
        $null = Assert-D32ArchiveCensusDirectoryIdentity -Path $archiveRoot `
            -VolumeSerialHex ([string]$authorityDocument.dependency_origin.registry_archive_root.volume_serial_hex) `
            -FileIdHex ([string]$authorityDocument.dependency_origin.registry_archive_root.file_id_hex)
        $finalAuthority = Open-D32PowerShellAuthorityFile -Path $expectedAuthorityFull -DirectoryFences $fences -MaximumBytes 16777216
        try {
            if (-not (Test-D32ArchiveCensusFileReferenceExact -Actual $finalAuthority.Record -Expected $authorityFile.Record)) {
                throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: authority bytes or identity changed during archive census'
            }
        }
        finally { $finalAuthority.Stream.Dispose() }
        foreach ($pin in $sourcePins) {
            $expectedPin = @($authorityDocument.source_pins | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals([string]$_.path, [string]$pin.path) })
            if ($expectedPin.Count -ne 1) { throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: final source pin set changed during archive census' }
            $finalPin = Open-D32PowerShellAuthorityFile -Path ([string]$pin.path) -DirectoryFences $fences -MaximumBytes 16777216
            try {
                if (-not (Test-D32ArchiveCensusFileReferenceExact -Actual $finalPin.Record -Expected $expectedPin[0])) {
                    throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: code/Profile/module-authority bytes or identity changed during archive census'
                }
            }
            finally { $finalPin.Stream.Dispose() }
        }
        $finalLock = Open-D32PowerShellAuthorityFile -Path ([string]$authorityDocument.lock_reference.path) -DirectoryFences $fences -MaximumBytes 16777216
        try {
            if (-not (Test-D32ArchiveCensusFileReferenceExact -Actual $finalLock.Record -Expected $authorityDocument.lock_reference)) {
                throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: lock bytes or identity changed during archive census'
            }
            $finalLockText = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$finalLock.Bytes)
            $finalSourcePlan = Get-D32BoundedCompilerDiagnosticSourcePlan -LockText $finalLockText
            if ([string]$finalSourcePlan.record_type -cne 'D32_BOUNDED_DIAGNOSTIC_LOCK_SOURCE_PLAN_V2' -or
                [string]$finalSourcePlan.lock_sha256 -cne [string]$authorityDocument.lock_reference.sha256 -or
                [string]$finalSourcePlan.registry_tuple_sha256 -cne [string]$authorityDocument.registry_tuple_sha256) {
                throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: lock source-plan V2 tuple changed during archive census'
            }
        }
        finally { $finalLock.Stream.Dispose() }
        $null = Assert-D32ArchiveCensusDirectoryIdentity -Path ([string]$authorityDocument.output_candidate.parent_path) `
            -VolumeSerialHex ([string]$authorityDocument.output_candidate.parent_volume_serial_hex) `
            -FileIdHex ([string]$authorityDocument.output_candidate.parent_file_id_hex)
        if ($censusTimer.ElapsedMilliseconds -ge [Int64]$authorityDocument.resource_budget.combined_milliseconds) {
            $budgetStopped = $true
            if ($coverage.Count -gt 0 -and [string]$coverage[0].status -ceq 'COMPLETE_SUPPORTED') {
                $coverage[0].status = 'BUDGET_STOPPED'; $coverage[0].remainder_unknown = $true
                $coverage[0].framing_verified = $false; $coverage[0].first_failure_offset = $null
                $coverage[0].first_failure_header_sha256 = $null
                $coverage[0].first_failure_reason = 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: aggregate deadline expired during final input fences'
                if ($secondaryErrors.Count -lt 64) { $secondaryErrors.Add([string]$coverage[0].first_failure_reason) }
            }
        }
    }
    catch { $finalFenceFailure = $true }
    if ($finalFenceFailure) {
        $blocked = $true
        $finalFailureReason = 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: final authority, source, lock, repository, or origin identity fence changed during census'
        if ($secondaryErrors.Count -lt 64) { $secondaryErrors.Add($finalFailureReason) }
        if ($coverage.Count -gt 0 -and [string]$coverage[0].status -ceq 'COMPLETE_SUPPORTED') {
            $coverage[0].status = 'PREFLIGHT_BLOCKED'; $coverage[0].remainder_unknown = $true
            $coverage[0].framing_verified = $false; $coverage[0].first_failure_offset = $null
            $coverage[0].first_failure_header_sha256 = $null; $coverage[0].first_failure_reason = $finalFailureReason
        }
    }
}

$blockedCount = @($coverage | Where-Object { [string]$_.status -cin @('UNSUPPORTED', 'PREFLIGHT_BLOCKED') }).Count
$resultStatus = if ($budgetStopped) { 'BUDGET_STOPPED' } elseif ($blocked -or $globalRootFailure -or $blockedCount -gt 0) { 'BLOCKED' } else { 'COMPLETE_DIAGNOSTIC' }
$primaryError = if ($resultStatus -ceq 'COMPLETE_DIAGNOSTIC') { $null }
    elseif ($secondaryErrors.Count -gt 0) { [string]$secondaryErrors[0] }
    elseif ($resultStatus -ceq 'BUDGET_STOPPED') { 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: one or more caller-pinned archive references remain unexamined' }
    else { 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: one or more caller-pinned archives did not satisfy strict format/identity coverage' }
$authorityReference = [PSCustomObject][ordered]@{
    path = [string]$authorityFile.Record.path; bytes = [Int64]$authorityFile.Record.bytes
    sha256 = [string]$authorityFile.Record.sha256; volume_serial_hex = [string]$authorityFile.Record.volume_serial_hex
    file_id_hex = [string]$authorityFile.Record.file_id_hex
}
$result = New-D32BoundedDiagnosticArchiveFormatCensusResult -Authority $authorityDocument -AuthorityReference $authorityReference `
    -Status $resultStatus -StartedAtUtc $censusStartedAtUtc -CompletedAtUtc ([DateTimeOffset]::UtcNow.ToString('o')) `
    -ElapsedMilliseconds ([Int64]$censusTimer.ElapsedMilliseconds) -Archives ([object[]]$coverage.ToArray()) `
    -PrimaryError $primaryError -SecondaryErrors ([string[]]$secondaryErrors.ToArray())
$resultValidationFailures = [System.Collections.Generic.List[string]]::new()
if (-not (Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $result -FailureReasons $resultValidationFailures)) {
    $validationReason = if ($resultValidationFailures.Count -gt 0) { $resultValidationFailures -join '; ' } else { 'validator returned false without a reason' }
    $firstCoverage = if ($result.archives.Count -gt 0) { [string]$result.archives[0].status + ':' + [string]$result.archives[0].archive_id } else { 'none' }
    throw ('D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: result self-validation failed; validator=' + $validationReason +
        '; primary_error=' + [string]$result.primary_error + '; requested=' + [Int64]$result.requested_archive_count +
        '; covered=' + [Int64]$result.covered_archive_count + '; blocked=' + [Int64]$result.blocked_archive_count +
        '; unexamined=' + [Int64]$result.unexamined_archive_count + '; first_coverage=' + $firstCoverage +
        '; coverage_sha256=' + [string]$result.archive_header_inventory_sha256)
}
$resultFailureContext = '; primary_error=' + [string]$result.primary_error +
    '; requested=' + [Int64]$result.requested_archive_count + '; covered=' + [Int64]$result.covered_archive_count +
    '; blocked=' + [Int64]$result.blocked_archive_count + '; unexamined=' + [Int64]$result.unexamined_archive_count +
    '; coverage_sha256=' + [string]$result.archive_header_inventory_sha256
try { $resultJson = ConvertTo-Json -InputObject $result -Depth 100 -Compress -ErrorAction Stop }
catch { throw ('D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: result serialization failed: ' + $_.Exception.Message + $resultFailureContext) }
$resultBytes = [Text.UTF8Encoding]::new($false).GetBytes($resultJson)
if ([Int64]$resultBytes.Length -gt [Int64]$authorityDocument.resource_budget.maximum_output_bytes) {
    throw ('D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: result exceeds its fixed 64 MiB persistence bound; output_bytes=' +
        [Int64]$resultBytes.Length + $resultFailureContext)
}
$null = Assert-D32ArchiveCensusDirectoryIdentity -Path ([string]$authorityDocument.output_candidate.parent_path) `
    -VolumeSerialHex ([string]$authorityDocument.output_candidate.parent_volume_serial_hex) `
    -FileIdHex ([string]$authorityDocument.output_candidate.parent_file_id_hex)
if (Test-Path -LiteralPath ([string]$authorityDocument.output_candidate.path)) {
    throw 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: create-new result path appeared before persistence'
}
$resultStream = [IO.FileStream]::new([string]$authorityDocument.output_candidate.path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) }
finally { $resultStream.Dispose() }
$persistedResult = $null
try {
    $persistedResult = Open-D32PowerShellAuthorityFile -Path ([string]$authorityDocument.output_candidate.path) `
        -DirectoryFences $fences -MaximumBytes ([Int64]$authorityDocument.resource_budget.maximum_output_bytes)
    $expectedResultSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($resultBytes)).ToLowerInvariant()
    if ([Int64]$persistedResult.Record.bytes -ne [Int64]$resultBytes.Length -or [string]$persistedResult.Record.sha256 -cne $expectedResultSha256) {
        throw ('D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: persisted result bytes differ from producer output; primary_error=' +
            [string]$result.primary_error + '; expected_bytes=' + $resultBytes.Length + '; actual_bytes=' + $persistedResult.Record.bytes +
            '; expected_sha256=' + $expectedResultSha256 + '; actual_sha256=' + [string]$persistedResult.Record.sha256)
    }
    $readBackText = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$persistedResult.Bytes)
    $readBackJson = [System.Text.Json.JsonDocument]::Parse($readBackText)
    try {
        if ($readBackJson.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
            (Test-D32PowerShellAuthorityJsonDuplicates -Element $readBackJson.RootElement)) {
            throw ('D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: persisted result JSON root/duplicate-key check failed' + $resultFailureContext)
        }
        $readBackResult = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $readBackJson.RootElement
    }
    finally { $readBackJson.Dispose() }
    $readBackValidationFailures = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $readBackResult -FailureReasons $readBackValidationFailures)) {
        $validationReason = if ($readBackValidationFailures.Count -gt 0) { $readBackValidationFailures -join '; ' } else { 'validator returned false without a reason' }
        throw ('D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: serialized result readback rejected; validator=' + $validationReason +
            '; primary_error=' + [string]$result.primary_error + '; requested=' + [Int64]$result.requested_archive_count +
            '; covered=' + [Int64]$result.covered_archive_count + '; blocked=' + [Int64]$result.blocked_archive_count +
            '; unexamined=' + [Int64]$result.unexamined_archive_count + '; coverage_sha256=' + [string]$result.archive_header_inventory_sha256)
    }
    $authorityCoverageFailures = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityCoverage -Result $readBackResult -Authority $authorityDocument `
        -ExpectedAuthorityReference $authorityReference -FailureReasons $authorityCoverageFailures)) {
        $bindingReason = if ($authorityCoverageFailures.Count -gt 0) { $authorityCoverageFailures -join '; ' } else { 'authority binding returned false without a reason' }
        throw ('D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: serialized result archive coverage differs from the caller-pinned finite authority; validator=' +
            $bindingReason + '; primary_error=' + [string]$result.primary_error + '; requested=' + [Int64]$result.requested_archive_count +
            '; covered=' + [Int64]$result.covered_archive_count + '; unexamined=' + [Int64]$result.unexamined_archive_count +
            '; coverage_sha256=' + [string]$result.archive_header_inventory_sha256)
    }
    $result = $readBackResult
}
finally { if ($null -ne $persistedResult -and $null -ne $persistedResult.Stream) { $persistedResult.Stream.Dispose() } }
Write-Output ('D32_BOUNDED_DIAGNOSTIC_ARCHIVE_FORMAT_CENSUS: status=' + [string]$result.status + '; run_id=' + [string]$result.run_id +
    '; path=' + [string]$authorityDocument.output_candidate.path + '; bytes=' + [Int64]$persistedResult.Record.bytes + '; sha256=' + [string]$persistedResult.Record.sha256)
foreach ($fence in $fences.Values) { if ($null -ne $fence.Handle -and -not $fence.Handle.IsClosed) { $fence.Handle.Dispose() } }
