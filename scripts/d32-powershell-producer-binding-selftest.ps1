# Focused module-free checks for D32 PowerShell producer-context links.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath([IO.Path]::Combine($PSScriptRoot, '..'))
. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
$global:PSModuleAutoLoadingPreference = 'None'
$env:PSModulePath = [IO.Path]::GetFullPath([IO.Path]::Combine([string]$PSHOME, 'Modules'))
$global:D32PowerShellModuleImportAttempts = 0
$loadedAtStart = Get-D32PowerShellAuthorityLoadedModuleSet

$cases = [System.Collections.Generic.List[object]]::new()
$failures = [System.Collections.Generic.List[string]]::new()
function Add-D32ProducerBindingCase {
    param([string]$Name, [bool]$Passed, [AllowNull()][string]$Detail = $null)
    $script:cases.Add([PSCustomObject]@{ name = $Name; passed = $Passed; detail = $Detail })
    if (-not $Passed) { $script:failures.Add($Name) }
}
$jsonShapeInput = [ordered]@{
    resolver_admission = [ordered]@{
        deps_paths = [string[]]@('C:\Program Files\PowerShell\7\pwsh.deps.json')
        active_environment = [object[]]@()
    }
}
$jsonShapeCopy = Copy-D32PowerShellAuthorityJsonShape -Value $jsonShapeInput
$jsonShapeClonePreservesArrays =
    ($jsonShapeCopy.resolver_admission.deps_paths -is [Array]) -and
    ($jsonShapeCopy.resolver_admission.deps_paths.Count -eq 1) -and
    ($jsonShapeCopy.resolver_admission.deps_paths[0] -ceq $jsonShapeInput.resolver_admission.deps_paths[0]) -and
    ($jsonShapeCopy.resolver_admission.active_environment -is [Array]) -and
    ($jsonShapeCopy.resolver_admission.active_environment.Count -eq 0) -and
    ((ConvertTo-D32PowerShellAuthorityJsonText -Value $jsonShapeCopy) -ceq (ConvertTo-D32PowerShellAuthorityJsonText -Value $jsonShapeInput))
Add-D32ProducerBindingCase 'SelfTest JSON-shape copies preserve singleton and empty resolver arrays exactly as strict readers consume them' $jsonShapeClonePreservesArrays

$profileReferenceFixture = [ordered]@{
    path = [IO.Path]::GetFullPath([IO.Path]::Combine($repo, 'd32-profile-shape-fixture.json'))
    sha256 = 'a' * 64
    bytes = [Int64]39018
    volume_serial_hex = '0000000000000001'
    file_id_hex = '1' * 32
}
$profileAdmissionFixture = [ordered]@{ profile_reference = $profileReferenceFixture }
$profileRecordFlatFixture = [ordered]@{
    path = $profileReferenceFixture.path
    sha256 = $profileReferenceFixture.sha256
    bytes = $profileReferenceFixture.bytes
    volume_serial_hex = $profileReferenceFixture.volume_serial_hex
    file_id_hex = $profileReferenceFixture.file_id_hex
    target_triple = 'x86_64-pc-windows-msvc'
}
$profileRecordNestedFixture = [ordered]@{
    path = $profileReferenceFixture.path
    sha256 = $profileReferenceFixture.sha256
    file_identity = [ordered]@{
        bytes = $profileReferenceFixture.bytes
        volume_serial_hex = $profileReferenceFixture.volume_serial_hex
        file_id_hex = $profileReferenceFixture.file_id_hex
    }
    target_triple = 'x86_64-pc-windows-msvc'
}
$profileRecordFormsAccepted = & {
    # The baseline validator runs under StrictMode. Keep the producer-context
    # test aligned so a missing flattened file_identity member cannot pass by
    # being read as null only in this focused harness.
    Set-StrictMode -Version Latest
    $flatObjectFixture = [PSCustomObject]$profileRecordFlatFixture
    $nestedObjectFixture = [PSCustomObject]$profileRecordNestedFixture
    (Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $profileAdmissionFixture -ProfileRecord $profileRecordFlatFixture) -and
    (Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $profileAdmissionFixture -ProfileRecord $profileRecordNestedFixture) -and
    (Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $profileAdmissionFixture -ProfileRecord $flatObjectFixture) -and
    (Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $profileAdmissionFixture -ProfileRecord $nestedObjectFixture)
}
Add-D32ProducerBindingCase 'module admission profile binding accepts discovery nested and baseline flattened profile identity layouts under StrictMode for dictionary and parsed object records' $profileRecordFormsAccepted
$profileBindingMismatchCases = & {
    Set-StrictMode -Version Latest
    $mismatches = [System.Collections.Generic.List[object]]::new()
    foreach ($profileField in @('path','sha256','bytes','volume_serial_hex','file_id_hex')) {
        $mutatedProfileAdmission = Copy-D32PowerShellAuthorityJsonShape -Value $profileAdmissionFixture
        switch ($profileField) {
            'path' { $mutatedProfileAdmission.profile_reference.path = [IO.Path]::GetFullPath([IO.Path]::Combine($repo, 'd32-other-profile-fixture.json')) }
            'sha256' { $mutatedProfileAdmission.profile_reference.sha256 = 'b' * 64 }
            'bytes' { $mutatedProfileAdmission.profile_reference.bytes = [Int64]39019 }
            'volume_serial_hex' { $mutatedProfileAdmission.profile_reference.volume_serial_hex = '0000000000000002' }
            'file_id_hex' { $mutatedProfileAdmission.profile_reference.file_id_hex = '2' * 32 }
        }
        $acceptedMutation = Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $mutatedProfileAdmission -ProfileRecord $profileRecordFlatFixture
        $mutationContext = Get-D32PowerShellModuleAdmissionValidationContext
        $mutationDetail = Get-D32PowerShellModuleAdmissionValidationDetail
        $detailExact = $null -ne $mutationDetail -and [string]$mutationDetail.field -ceq $profileField -and
            $null -ne $mutationDetail.actual_value -and $null -ne $mutationDetail.expected_value
        $mismatches.Add([PSCustomObject]@{
            field = $profileField
            rejected = -not $acceptedMutation
            exact_context = $mutationContext -ceq "profile.reference.$profileField"
            exact_values_reported = $detailExact
        })
    }
    $mismatches.ToArray()
}
$allProfileMismatchesPrecise = $profileBindingMismatchCases.Count -eq 5 -and
    @($profileBindingMismatchCases | Where-Object { -not $_.rejected -or -not $_.exact_context -or -not $_.exact_values_reported }).Count -eq 0
Add-D32ProducerBindingCase 'flattened baseline profile binding rejects each profile-reference field at its exact predicate with expected and actual diagnostics' `
    $allProfileMismatchesPrecise `
    (ConvertTo-D32PowerShellAuthorityJsonText -Value @($profileBindingMismatchCases))
$flatMissingFieldRejected = & {
    Set-StrictMode -Version Latest
    $missing = Copy-D32PowerShellAuthorityJsonShape -Value $profileRecordFlatFixture
    [void]$missing.Remove('file_id_hex')
    $accepted = Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $profileAdmissionFixture -ProfileRecord $missing
    $context = Get-D32PowerShellModuleAdmissionValidationContext
    (-not $accepted) -and $context -ceq 'profile.reference.file_id_hex'
}
$nestedNullIdentityRejected = & {
    Set-StrictMode -Version Latest
    $missing = Copy-D32PowerShellAuthorityJsonShape -Value $profileRecordNestedFixture
    $missing.file_identity = $null
    $accepted = Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $profileAdmissionFixture -ProfileRecord $missing
    $context = Get-D32PowerShellModuleAdmissionValidationContext
    (-not $accepted) -and $context -ceq 'profile.profile-record.nested-identity'
}
Add-D32ProducerBindingCase 'profile admission binding rejects malformed flattened and nested identity shapes under StrictMode with exact context' `
    ($flatMissingFieldRejected -and $nestedNullIdentityRejected) `
    'Missing flattened file IDs are rejected at their field predicate; a present-but-null nested identity fails closed as a malformed nested profile record.'

function New-D32ProducerBindingAdmissionFixture {
    param([string]$EntryName, [int]$ProcessId, [Int64]$StartTicks)
    $entry = [IO.Path]::GetFullPath([IO.Path]::Combine($repo, 'scripts', $EntryName))
    return [ordered]@{
        entry_script_path = $entry
        startup = [ordered]@{ file_operand = $entry; switches = @('-NoProfile','-NonInteractive'); startup_policy = 'DIRECT_NO_PROFILE_FILE_V1' }
        entry_script = [ordered]@{ path = $entry; bytes = [Int64]1; sha256 = ('a' * 64); volume_serial_hex = '0000000000000001'; file_id_hex = ('1' * 32) }
        runner_process = [ordered]@{ process_id = $ProcessId; start_time_utc_ticks = $StartTicks; image_path = [IO.Path]::Combine([string]$PSHOME, 'pwsh.exe'); image_file_id_hex = ('2' * 32); token_state = [ordered]@{ is_elevated = $false } }
    }
}
function Test-D32ProducerEntryRoleFixture {
    param([object]$Admission, [string]$Role)
    return Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $Admission -Repository $repo `
        -ProducerRole $Role -ExpectedProducerContext $Admission
}

$phase0Admission = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-phase0-matrix.ps1' -ProcessId 3101 -StartTicks 638949001000000000
$fixtureEmbeddedAdmission = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($phase0Admission))
$fixtureTopRunnerPositive = (Test-D32PowerShellModuleProducerContextEqual -Document $fixtureEmbeddedAdmission -ExpectedContext $phase0Admission) -and
    (Test-D32ProducerEntryRoleFixture -Admission $fixtureEmbeddedAdmission -Role fixture_provenance) -and
    -not (Test-D32PowerShellModuleProducerProcessDistinct -Document $fixtureEmbeddedAdmission -OtherAdmission $phase0Admission)
$fakeFixtureEntry = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-fixture-prebuild.ps1' -ProcessId 3101 -StartTicks 638949001000000000
$fixtureFakeEntryRejected = -not (Test-D32PowerShellModuleProducerContextEqual -Document $fakeFixtureEntry -ExpectedContext $phase0Admission)
Add-D32ProducerBindingCase 'in-process fixture provenance preserves the actual Phase0 top -File runner context' $fixtureTopRunnerPositive
Add-D32ProducerBindingCase 'fixture provenance rejects substituting the helper script as the top -File operand' $fixtureFakeEntryRejected

$discoveryAdmission = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-test-inventory-discovery.ps1' -ProcessId 3201 -StartTicks 638949002000000000
$baselineAdmission = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-test-inventory-baseline.ps1' -ProcessId 3202 -StartTicks 638949003000000000
$phase0MatrixAdmission = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-phase0-matrix.ps1' -ProcessId 3203 -StartTicks 638949003500000000
$baselineOwnPositive = (Test-D32PowerShellModuleProducerContextEqual -Document $baselineAdmission -ExpectedContext $baselineAdmission) -and
    (Test-D32ProducerEntryRoleFixture -Admission $baselineAdmission -Role inventory_baseline) -and
    (Test-D32PowerShellModuleProducerProcessDistinct -Document $baselineAdmission -OtherAdmission $discoveryAdmission)
$baselineOwnCopyRejected = -not (Test-D32ProducerEntryRoleFixture -Admission $discoveryAdmission -Role inventory_baseline) -and
    -not (Test-D32PowerShellModuleProducerProcessDistinct -Document $discoveryAdmission -OtherAdmission $discoveryAdmission)
$oldBaselineAdmission = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-test-inventory-baseline.ps1' -ProcessId 3199 -StartTicks 638949000000000000
$baselineOldProducerRejected = -not (Test-D32PowerShellModuleProducerContextEqual -Document $oldBaselineAdmission -ExpectedContext $baselineAdmission)
$baselineEmbedded = [ordered]@{ discovery_module_admission = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($discoveryAdmission)); powershell_module_admission = $baselineAdmission }
$baselineDiscoveryLinkPositive = (ConvertTo-D32PowerShellAuthorityJsonText -Value $baselineEmbedded.discovery_module_admission) -ceq
    (ConvertTo-D32PowerShellAuthorityJsonText -Value $discoveryAdmission)
$openedDiscoveryAdmission = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($baselineEmbedded.discovery_module_admission))
$baselineEmbedded.discovery_module_admission.entry_script.sha256 = ('b' * 64)
$baselineDiscoveryTamperRejected = (Test-D32PowerShellModuleProducerContextEqual -Document $baselineEmbedded.discovery_module_admission -ExpectedContext $openedDiscoveryAdmission) -eq $false
$baselineDiscoveryCopiedAsOwnRejected = -not (Test-D32PowerShellModuleProducerProcessDistinct -Document $baselineEmbedded.discovery_module_admission -OtherAdmission $baselineEmbedded.discovery_module_admission)
Add-D32ProducerBindingCase 'baseline own producer is role-correct and process-distinct from linked discovery' $baselineOwnPositive
Add-D32ProducerBindingCase 'baseline rejects discovery admission copied into its own producer slot' ($baselineOwnCopyRejected -and $baselineDiscoveryCopiedAsOwnRejected)
Add-D32ProducerBindingCase 'baseline writer context rejects a prior same-role producer process' $baselineOldProducerRejected
Add-D32ProducerBindingCase 'baseline discovery slot remains exactly linked to its opened discovery producer admission' ($baselineDiscoveryLinkPositive -and $baselineDiscoveryTamperRejected)
Add-D32ProducerBindingCase 'discovery, baseline, and Phase0 shape-only producers use their exact role entries and distinct process identities' `
    ((Test-D32ProducerEntryRoleFixture -Admission $discoveryAdmission -Role inventory_discovery) -and
        (Test-D32ProducerEntryRoleFixture -Admission $baselineAdmission -Role inventory_baseline) -and
        (Test-D32ProducerEntryRoleFixture -Admission $phase0MatrixAdmission -Role phase0_matrix) -and
        (Test-D32PowerShellModuleProducerProcessDistinct -Document $phase0MatrixAdmission -OtherAdmission $baselineAdmission) -and
        (Test-D32PowerShellModuleProducerProcessDistinct -Document $phase0MatrixAdmission -OtherAdmission $discoveryAdmission))

# Exercise the production producer-context predicate directly with shape-only
# records. These deliberately omit the shared ADMITTED schema and therefore
# cannot be mistaken for an actual module admission; the full-record validator
# remains mandatory in production callers.
$roleCases = @(
    @{ role = 'fixture_provenance'; entry = 'd32-phase0-matrix.ps1'; wrong = 'd32-test-inventory-discovery.ps1' },
    @{ role = 'inventory_discovery'; entry = 'd32-test-inventory-discovery.ps1'; wrong = 'd32-test-inventory-baseline.ps1' },
    @{ role = 'inventory_baseline'; entry = 'd32-test-inventory-baseline.ps1'; wrong = 'd32-test-inventory-discovery.ps1' },
    @{ role = 'phase0_matrix'; entry = 'd32-phase0-matrix.ps1'; wrong = 'd32-test-inventory-discovery.ps1' },
    @{ role = 'release_attestation'; entry = 'd32-preflight.ps1'; wrong = 'd32-phase0-matrix.ps1' },
    @{ role = 'post_bundle_aggregate'; entry = 'd32-preflight.ps1'; wrong = 'd32-phase0-matrix.ps1' }
)
$roleContextResults = [System.Collections.Generic.List[object]]::new()
foreach ($roleCase in $roleCases) {
    $roleAdmission = New-D32ProducerBindingAdmissionFixture -EntryName ([string]$roleCase.entry) -ProcessId (3400 + $roleContextResults.Count) -StartTicks (638949006000000000 + $roleContextResults.Count)
    $rolePositive = Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $roleAdmission -Repository $repo `
        -ProducerRole ([string]$roleCase.role) -ExpectedProducerContext $roleAdmission
    $wrongRoleAdmission = New-D32ProducerBindingAdmissionFixture -EntryName ([string]$roleCase.wrong) -ProcessId (3500 + $roleContextResults.Count) -StartTicks (638949007000000000 + $roleContextResults.Count)
    $wrongRoleRejected = -not (Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $wrongRoleAdmission -Repository $repo `
        -ProducerRole ([string]$roleCase.role) -ExpectedProducerContext $roleAdmission)
    $roleContextResults.Add([PSCustomObject]@{ role = [string]$roleCase.role; accepted = [bool]$rolePositive; wrong_entry_rejected = [bool]$wrongRoleRejected })
    Add-D32ProducerBindingCase "shape-only producer context accepts exact $($roleCase.role) role entry" $rolePositive
    Add-D32ProducerBindingCase "shape-only producer context rejects wrong $($roleCase.role) role entry" $wrongRoleRejected
}
$extendedRepository = '\\?\' + $repo
$allProducerRolesAcceptEquivalentDrivePathForms = $true
$allProducerRolesRejectMismatchedStartupSpelling = $true
$equivalentRoleEntryCount = 0
foreach ($roleCase in $roleCases) {
    $roleEntryPaths = @(Get-D32PowerShellModuleProducerEntryPaths -Repository $repo -ProducerRole ([string]$roleCase.role))
    foreach ($roleEntryPath in $roleEntryPaths) {
        $entryName = [IO.Path]::GetFileName([string]$roleEntryPath)
        $ordinaryAdmission = New-D32ProducerBindingAdmissionFixture -EntryName $entryName -ProcessId (3700 + $equivalentRoleEntryCount) -StartTicks (638949008100000000 + $equivalentRoleEntryCount)
        $extendedRootAccepted = Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $ordinaryAdmission -Repository $extendedRepository `
            -ProducerRole ([string]$roleCase.role) -ExpectedProducerContext $ordinaryAdmission

        $extendedAdmission = Copy-D32PowerShellAuthorityJsonShape -Value $ordinaryAdmission
        $extendedEntryPath = '\\?\' + [string]$extendedAdmission.entry_script_path
        $extendedAdmission.entry_script_path = $extendedEntryPath
        $extendedAdmission.entry_script.path = $extendedEntryPath
        $extendedAdmission.startup.file_operand = $extendedEntryPath
        $ordinaryRootAccepted = Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $extendedAdmission -Repository $repo `
            -ProducerRole ([string]$roleCase.role) -ExpectedProducerContext $extendedAdmission

        $wrongStartupSpelling = Copy-D32PowerShellAuthorityJsonShape -Value $extendedAdmission
        $wrongStartupSpelling.startup.file_operand = [string]$ordinaryAdmission.entry_script_path
        $startupMismatchRejected = -not (Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $wrongStartupSpelling -Repository $repo `
            -ProducerRole ([string]$roleCase.role) -ExpectedProducerContext $wrongStartupSpelling)
        $allProducerRolesAcceptEquivalentDrivePathForms = $allProducerRolesAcceptEquivalentDrivePathForms -and $extendedRootAccepted -and $ordinaryRootAccepted
        $allProducerRolesRejectMismatchedStartupSpelling = $allProducerRolesRejectMismatchedStartupSpelling -and $startupMismatchRejected
        $equivalentRoleEntryCount++
    }
}
Add-D32ProducerBindingCase 'all six producer roles accept only equivalent ordinary/extended forms for every fixed entry script and retain the exact startup operand' `
    ($equivalentRoleEntryCount -eq 11 -and $allProducerRolesAcceptEquivalentDrivePathForms -and $allProducerRolesRejectMismatchedStartupSpelling) `
    "role_entry_pairs=$equivalentRoleEntryCount; equivalent_forms=$allProducerRolesAcceptEquivalentDrivePathForms; exact_startup=$allProducerRolesRejectMismatchedStartupSpelling"

$invalidProducerRootsRejected =
    $null -eq (ConvertTo-D32PowerShellModuleLocalPathIdentity -Path '.\relative-repository') -and
    $null -eq (ConvertTo-D32PowerShellModuleLocalPathIdentity -Path ($repo + '\scripts\..')) -and
    $null -eq (ConvertTo-D32PowerShellModuleLocalPathIdentity -Path '\\server\share\digital-life') -and
    $null -eq (ConvertTo-D32PowerShellModuleLocalPathIdentity -Path '\\?\UNC\server\share\digital-life') -and
    $null -eq (ConvertTo-D32PowerShellModuleLocalPathIdentity -Path '\\.\E:\device-path')
$wrongRootRoleRejected = $false
$outOfBoundsAdmission = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-preflight.ps1' -ProcessId 3790 -StartTicks 638949008190000000
$outOfBoundsAdmission.entry_script_path = [IO.Path]::GetFullPath([IO.Path]::Combine($repo, 'docs', 'governance', 'PROJECT_SOURCE_OF_TRUTH.md'))
$outOfBoundsAdmission.startup.file_operand = [string]$outOfBoundsAdmission.entry_script_path
$outOfBoundsAdmission.entry_script.path = [string]$outOfBoundsAdmission.entry_script_path
$wrongRootRoleRejected = -not (Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $outOfBoundsAdmission -Repository $repo `
    -ProducerRole post_bundle_aggregate -ExpectedProducerContext $outOfBoundsAdmission)
$wrongRepositoryRootRejected = -not (Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $outOfBoundsAdmission -Repository 'E:\d32' `
    -ProducerRole post_bundle_aggregate -ExpectedProducerContext $outOfBoundsAdmission)
$knownReparseAlias = 'C:\Users\zuo\Application Data'
$unapprovedReparseAliasRejected = (Test-D32PowerShellAuthorityPathNoReparse -Path $knownReparseAlias) -eq $false -and
    $null -eq (ConvertTo-D32PowerShellModuleLocalPathIdentity -Path $knownReparseAlias)
Add-D32ProducerBindingCase 'producer path normalization rejects relative/traversal/UNC/device namespaces and an existing unapproved reparse alias' `
    ($invalidProducerRootsRejected -and $wrongRootRoleRejected -and $wrongRepositoryRootRejected -and $unapprovedReparseAliasRejected) `
    "invalid_roots=$invalidProducerRootsRejected; out_of_bounds_role=$wrongRootRoleRejected; wrong_repository_root=$wrongRepositoryRootRejected; reparse_alias=$unapprovedReparseAliasRejected"

$entryScriptPathForRecordTest = [IO.Path]::GetFullPath([IO.Path]::Combine($repo, 'scripts', 'd32-preflight.ps1'))
$entryFencesForRecordTest = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
$entrySnapshotForRecordTest = Open-D32PowerShellAuthorityFile -Path $entryScriptPathForRecordTest -DirectoryFences $entryFencesForRecordTest
$entryReferenceForRecordTest = Copy-D32PowerShellAuthorityJsonShape -Value $entrySnapshotForRecordTest.Record
$entrySnapshotForRecordTest.Stream.Dispose()
foreach ($directoryFence in $entryFencesForRecordTest.Values) { if ($null -ne $directoryFence.Handle -and -not $directoryFence.Handle.IsClosed) { $directoryFence.Handle.Dispose() } }
$externalReference = {
    param([string]$Name)
    [ordered]@{ path = [IO.Path]::GetFullPath([IO.Path]::Combine('E:\d32', $Name)); sha256 = ('a' * 64); bytes = [Int64]1; volume_serial_hex = '0000000000000001'; file_id_hex = ('1' * 32) }
}
$minimalEntryBindingRecord = [ordered]@{
    record_type = 'D32_POWERSHELL_MODULE_ADMISSION_V2'
    schema_version = 2
    status = 'ADMITTED'
    candidate_sha = 'a' * 40
    source_repo = $repo
    authority_reference = & $externalReference 'module-authority-candidate.json'
    profile_reference = & $externalReference 'profile-candidate.json'
    git_image = & $externalReference 'git-image-candidate.json'
    powershell_host = [ordered]@{}
    runner_process = [ordered]@{}
    startup = [ordered]@{ file_operand = $entryScriptPathForRecordTest; switches = @('-NoProfile','-NonInteractive'); startup_policy = 'DIRECT_NO_PROFILE_FILE_V1' }
    entry_script_path = $entryScriptPathForRecordTest
    entry_script = $entryReferenceForRecordTest
    module_import_order = [string[]]@('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','CimCmdlets')
    module_closure = [ordered]@{}
    resolver_admission = [ordered]@{}
    import_verification = [ordered]@{ state = 'VERIFIED'; verified_import_count = 3; modules = [object[]]@(1,2,3); assemblies = [object[]]@(1); commands = [object[]]@(1); native_modules = [object[]]@(1) }
    import_attempts = 3
}
$mixedRepositoryRepresentationReachesEntryIdentityCheck = -not (Test-D32PowerShellModuleAdmissionRecord -Document $minimalEntryBindingRecord `
    -CandidateSha ([string]$minimalEntryBindingRecord.candidate_sha) -Repository $extendedRepository -ExpectedContext $null) -and
    (Get-D32PowerShellModuleAdmissionValidationContext) -ceq 'record.powershell-host-reference'
$missingEntryIdentityRecord = Copy-D32PowerShellAuthorityJsonShape -Value $minimalEntryBindingRecord
[void]$missingEntryIdentityRecord.entry_script.Remove('file_id_hex')
$missingIdentityRejectedAtExactPredicate = -not (Test-D32PowerShellModuleAdmissionRecord -Document $missingEntryIdentityRecord `
    -CandidateSha ([string]$minimalEntryBindingRecord.candidate_sha) -Repository $extendedRepository -ExpectedContext $null) -and
    (Get-D32PowerShellModuleAdmissionValidationContext) -ceq 'record.entry-script-reference-shape'
$repositoryOwnedReferenceRecord = Copy-D32PowerShellAuthorityJsonShape -Value $minimalEntryBindingRecord
$repositoryOwnedReferenceRecord.authority_reference.path = [IO.Path]::GetFullPath([IO.Path]::Combine($repo, 'docs', 'governance', 'PROJECT_SOURCE_OF_TRUTH.md'))
$repositoryOwnedReferenceRejectedAcrossPathForms = -not (Test-D32PowerShellModuleAdmissionRecord -Document $repositoryOwnedReferenceRecord `
    -CandidateSha ([string]$minimalEntryBindingRecord.candidate_sha) -Repository $extendedRepository -ExpectedContext $null) -and
    (Get-D32PowerShellModuleAdmissionValidationContext) -ceq 'record.reference.authority_reference'
$extendedRepositoryOwnedReferenceRecord = Copy-D32PowerShellAuthorityJsonShape -Value $minimalEntryBindingRecord
$extendedRepositoryOwnedReferenceRecord.authority_reference.path = '\\?\' + [IO.Path]::GetFullPath([IO.Path]::Combine($repo, 'docs', 'governance', 'PROJECT_SOURCE_OF_TRUTH.md'))
$extendedRepositoryOwnedReferenceRejectedAcrossPathForms = -not (Test-D32PowerShellModuleAdmissionRecord -Document $extendedRepositoryOwnedReferenceRecord `
    -CandidateSha ([string]$minimalEntryBindingRecord.candidate_sha) -Repository $repo -ExpectedContext $null) -and
    (Get-D32PowerShellModuleAdmissionValidationContext) -ceq 'record.reference.authority_reference'
$changedEntryIdentityRecord = Copy-D32PowerShellAuthorityJsonShape -Value $minimalEntryBindingRecord
$replacementEntryId = if ($changedEntryIdentityRecord.entry_script.file_id_hex -ceq ('0' * 32)) { '1' * 32 } else { '0' * 32 }
$changedEntryIdentityRecord.entry_script.file_id_hex = $replacementEntryId
$changedIdentityRejectedAtOpenedObjectPredicate = -not (Test-D32PowerShellModuleAdmissionRecord -Document $changedEntryIdentityRecord `
    -CandidateSha ([string]$minimalEntryBindingRecord.candidate_sha) -Repository $repo -ExpectedContext $null) -and
    (Get-D32PowerShellModuleAdmissionValidationContext) -ceq 'record.entry-script-opened-reference'
Add-D32ProducerBindingCase 'mixed repository path forms reach the opened entry identity check while missing/stale entry file identities reject at their exact predicates' `
    ($mixedRepositoryRepresentationReachesEntryIdentityCheck -and $missingIdentityRejectedAtExactPredicate -and $changedIdentityRejectedAtOpenedObjectPredicate -and
        $repositoryOwnedReferenceRejectedAcrossPathForms -and $extendedRepositoryOwnedReferenceRejectedAcrossPathForms) `
    "mixed_path=$mixedRepositoryRepresentationReachesEntryIdentityCheck; missing_identity=$missingIdentityRejectedAtExactPredicate; changed_identity=$changedIdentityRejectedAtOpenedObjectPredicate; ordinary_reference_inside_repo=$repositoryOwnedReferenceRejectedAcrossPathForms; extended_reference_inside_repo=$extendedRepositoryOwnedReferenceRejectedAcrossPathForms"
$syntheticPreflightContext = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-preflight.ps1' -ProcessId 3600 -StartTicks 638949008000000000
$syntheticDiscoveryContext = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-test-inventory-discovery.ps1' -ProcessId 3601 -StartTicks 638949008010000000
$syntheticBaselineContext = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-test-inventory-baseline.ps1' -ProcessId 3602 -StartTicks 638949008020000000
$syntheticPhase0Context = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-phase0-matrix.ps1' -ProcessId 3603 -StartTicks 638949008030000000
$sixPredicateResults = [ordered]@{
    discovery_accepts_own = Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $syntheticDiscoveryContext -Repository $repo `
        -ProducerRole inventory_discovery -ExpectedProducerContext $syntheticDiscoveryContext
    baseline_accepts_own_distinct_from_discovery = Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $syntheticBaselineContext -Repository $repo `
        -ProducerRole inventory_baseline -ExpectedProducerContext $syntheticBaselineContext -DistinctFromAdmission $syntheticDiscoveryContext
    copied_discovery_rejected_as_baseline = -not (Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $syntheticDiscoveryContext -Repository $repo `
        -ProducerRole inventory_baseline -ExpectedProducerContext $syntheticBaselineContext -DistinctFromAdmission $syntheticDiscoveryContext)
    baseline_rejects_same_process = -not (Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $syntheticBaselineContext -Repository $repo `
        -ProducerRole inventory_baseline -ExpectedProducerContext $syntheticBaselineContext -DistinctFromAdmission $syntheticBaselineContext)
    phase0_accepts_own = Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $syntheticPhase0Context -Repository $repo `
        -ProducerRole phase0_matrix -ExpectedProducerContext $syntheticPhase0Context
    caller_context_rejected_as_fake_phase0_producer = -not (Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $syntheticPreflightContext -Repository $repo `
        -ProducerRole phase0_matrix -ExpectedProducerContext $syntheticPhase0Context)
}
Add-D32ProducerBindingCase 'all six SelfTest producer predicates replay with exact role and process contexts without constructing an admission record' `
    (@($sixPredicateResults.Values | Where-Object { -not [bool]$_ }).Count -eq 0)
$startupMismatch = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-test-inventory-discovery.ps1' -ProcessId 3604 -StartTicks 638949008040000000
$startupMismatch.startup.file_operand = [IO.Path]::GetFullPath([IO.Path]::Combine($repo, 'scripts', 'd32-test-inventory-baseline.ps1'))
Add-D32ProducerBindingCase 'producer context rejects a role-correct entry with a different startup -File operand' `
    (-not (Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $startupMismatch -Repository $repo -ProducerRole inventory_discovery))

$leasePriorAdmission = [PSCustomObject]@{ marker = 'prior-shape-only' }
$leaseSyntheticAdmission = [PSCustomObject]@{ marker = 'synthetic-shape-only' }
$immediateFailureLeaseRecovery = Test-D32PowerShellModuleSelfTestAdmissionImmediateFailureRecovery `
    -PriorAdmission $leasePriorAdmission -SyntheticAdmission $leaseSyntheticAdmission
Add-D32ProducerBindingCase 'synthetic admission lease restores state after failure immediately following the switch' $immediateFailureLeaseRecovery

$aggregateAdmission = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-preflight.ps1' -ProcessId 3301 -StartTicks 638949004000000000
$historicalReaderAdmission = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-preflight.ps1' -ProcessId 3302 -StartTicks 638949005000000000
$oldAggregateAdmission = New-D32ProducerBindingAdmissionFixture -EntryName 'd32-preflight.ps1' -ProcessId 3299 -StartTicks 638949003900000000
$aggregateWriterPositive = Test-D32PowerShellModuleProducerContextEqual -Document $aggregateAdmission -ExpectedContext $aggregateAdmission
$aggregateHistoricalReaderPositive = (Test-D32ProducerEntryRoleFixture -Admission $aggregateAdmission -Role post_bundle_aggregate) -and
    -not (Test-D32PowerShellModuleProducerContextEqual -Document $aggregateAdmission -ExpectedContext $historicalReaderAdmission)
$aggregateCopiedDiscoveryRejected = -not (Test-D32ProducerEntryRoleFixture -Admission $discoveryAdmission -Role post_bundle_aggregate)
$aggregateOldWriterRejected = -not (Test-D32PowerShellModuleProducerContextEqual -Document $oldAggregateAdmission -ExpectedContext $aggregateAdmission)
Add-D32ProducerBindingCase 'aggregate writer binds the current preflight process/startup/entry' $aggregateWriterPositive
Add-D32ProducerBindingCase 'aggregate historical reader validates embedded producer context without equating it to reader PID' $aggregateHistoricalReaderPositive
Add-D32ProducerBindingCase 'aggregate rejects a copied discovery admission or unrelated prior producer context' ($aggregateCopiedDiscoveryRejected -and $aggregateOldWriterRejected)

$sourceFiles = @{
    helper = [IO.File]::ReadAllText([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'), [Text.UTF8Encoding]::new($false, $true))
    fixture = [IO.File]::ReadAllText([IO.Path]::Combine($PSScriptRoot, 'd32-fixture-prebuild.ps1'), [Text.UTF8Encoding]::new($false, $true))
    phase0 = [IO.File]::ReadAllText([IO.Path]::Combine($PSScriptRoot, 'd32-phase0-matrix.ps1'), [Text.UTF8Encoding]::new($false, $true))
    preflight = [IO.File]::ReadAllText([IO.Path]::Combine($PSScriptRoot, 'd32-preflight.ps1'), [Text.UTF8Encoding]::new($false, $true))
    discovery = [IO.File]::ReadAllText([IO.Path]::Combine($PSScriptRoot, 'd32-test-inventory-discovery.ps1'), [Text.UTF8Encoding]::new($false, $true))
    baseline = [IO.File]::ReadAllText([IO.Path]::Combine($PSScriptRoot, 'd32-test-inventory-baseline.ps1'), [Text.UTF8Encoding]::new($false, $true))
    inventory = [IO.File]::ReadAllText([IO.Path]::Combine($PSScriptRoot, 'd32-test-inventory-authority.ps1'), [Text.UTF8Encoding]::new($false, $true))
}
$strictSelfTestJsonCopiesUseWireShape =
    $sourceFiles.preflight.Contains('Copy-D32PowerShellAuthorityJsonShape -Value $TemplateAdmission') -and
    $sourceFiles.fixture.Contains('Copy-D32PowerShellAuthorityJsonShape -Value $global:D32PowerShellModuleAuthorityState.Admission') -and
    $sourceFiles.phase0.Contains('Copy-D32PowerShellAuthorityJsonShape -Value $sidecar') -and
    $sourceFiles.phase0.Contains('Copy-D32PowerShellAuthorityJsonShape -Value $syntheticListRecord') -and
    -not $sourceFiles.phase0.Contains('PSSerializer')
Add-D32ProducerBindingCase 'strict D32 SelfTest record mutations clone the JSON wire shape without PSSerializer array coercion' $strictSelfTestJsonCopiesUseWireShape
$sourceParseErrors = [System.Collections.Generic.List[string]]::new()
foreach ($name in $sourceFiles.Keys) {
    $tokens = $null; $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($sourceFiles[$name], [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { $sourceParseErrors.Add("$name=$($parseErrors.Count)") }
}
$aggregateReaderText = ''
$aggregateWriterText = ''
$preflightSyntheticInventoryText = ''
$preflightAstTokens = $null; $preflightAstErrors = $null
$preflightAst = [System.Management.Automation.Language.Parser]::ParseInput($sourceFiles.preflight, [ref]$preflightAstTokens, [ref]$preflightAstErrors)
$aggregateReaderAst = $preflightAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32PostBundleAggregateRecord' }, $true)
$aggregateWriterAst = $preflightAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-D32GeneratePostBundleAggregateRecord' }, $true)
$preflightSyntheticInventoryAst = $preflightAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'New-D32PreflightSelfTestInventoryAuthorityArtifacts' }, $true)
$syntheticAdmissionBuilderAst = $preflightAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'New-D32PreflightSelfTestSyntheticModuleAdmission' }, $true)
if ($null -ne $aggregateReaderAst) { $aggregateReaderText = $aggregateReaderAst.Extent.Text }
if ($null -ne $aggregateWriterAst) { $aggregateWriterText = $aggregateWriterAst.Extent.Text }
if ($null -ne $preflightSyntheticInventoryAst) { $preflightSyntheticInventoryText = $preflightSyntheticInventoryAst.Extent.Text }
$syntheticAdmissionBuilderText = if ($null -ne $syntheticAdmissionBuilderAst) { $syntheticAdmissionBuilderAst.Extent.Text } else { '' }
$fixtureWriterBound = $sourceFiles.fixture.Contains('Test-D32PowerShellModuleAdmissionProducerBinding -Document $Document.powershell_module_admission') -and
    $sourceFiles.fixture.Contains('-ExpectedProducerContext $global:D32PowerShellModuleAuthorityState.Admission')
$phase0FixtureReferenceBound = $sourceFiles.phase0.Contains('-ExpectedProducerAdmission $document.powershell_module_admission')
$phase0WriterBound = $sourceFiles.phase0.Contains('-ProducerRole phase0_matrix') -and $sourceFiles.phase0.Contains('-ExpectedProducerContext $global:D32PowerShellModuleAuthorityState.Admission')
$discoveryWriterBound = $sourceFiles.discovery.Contains('-ProducerRole inventory_discovery') -and $sourceFiles.discovery.Contains('-ExpectedProducerContext $global:D32PowerShellModuleAuthorityState.Admission')
$baselineSlotsBound = $sourceFiles.inventory.Contains('discovery_module_admission = $Discovery.powershell_module_admission') -and
    $sourceFiles.inventory.Contains('-ExactLinkedAdmission $Discovery.powershell_module_admission') -and
    $sourceFiles.inventory.Contains('-DistinctFromAdmission $Document.discovery_module_admission') -and
    $sourceFiles.baseline.Contains('-ExpectedProducerAdmission $global:D32PowerShellModuleAuthorityState.Admission')
$preflightWritersBound = $sourceFiles.preflight.Contains('-ProducerRole release_attestation') -and
    $sourceFiles.preflight.Contains('-ProducerRole post_bundle_aggregate') -and
    $sourceFiles.preflight.Contains('-ExpectedProducerContext $global:D32PowerShellModuleAuthorityState.Admission')
$historicalRolesBound = $sourceFiles.preflight.Contains('-ProducerRole release_attestation') -and
    $sourceFiles.preflight.Contains('-ProducerRole post_bundle_aggregate') -and
    $sourceFiles.preflight.Contains('-ProducerRole phase0_matrix')
$aggregateWriterCurrentContextBound = $aggregateWriterText.Contains('-ExpectedProducerContext $global:D32PowerShellModuleAuthorityState.Admission')
$aggregateHistoricalReaderDoesNotBindReaderProcess = $aggregateReaderText.Contains('-ProducerRole post_bundle_aggregate') -and
    $aggregateReaderText.Contains('-ExpectedAdmissionContext $global:D32PowerShellModuleAuthorityState.Admission') -and
    -not $aggregateReaderText.Contains('-ExpectedProducerContext')
$baselineSyntheticProducersDistinct = $preflightSyntheticInventoryText.Contains('[Parameter(Mandatory = $true)][object]$DiscoveryProducerAdmission') -and
    $preflightSyntheticInventoryText.Contains('[Parameter(Mandatory = $true)][object]$BaselineProducerAdmission') -and
    $preflightSyntheticInventoryText.Contains('$syntheticDiscoveryAdmission = $DiscoveryProducerAdmission') -and
    $preflightSyntheticInventoryText.Contains('runner_process_id = [int]$syntheticDiscoveryAdmission.runner_process.process_id') -and
    $preflightSyntheticInventoryText.Contains('powershell_module_admission = $syntheticDiscoveryAdmission') -and
    $preflightSyntheticInventoryText.Contains('-ProducerAdmission $BaselineProducerAdmission') -and
    $preflightSyntheticInventoryText.Contains('-ExpectedProducerAdmission $BaselineProducerAdmission')
$mainSelfTestText = ''
$mainSelfTestAst = $preflightAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-D32SelfTest' }, $true)
if ($null -ne $mainSelfTestAst) { $mainSelfTestText = $mainSelfTestAst.Extent.Text }
$syntheticRolePlaceholderIndex = $mainSelfTestText.IndexOf('preflight SelfTest synthetic role-entry placeholder path must be absent', [StringComparison]::Ordinal)
$fixtureGitAddIndex = $mainSelfTestText.IndexOf("@('add', '.')", [StringComparison]::Ordinal)
$syntheticRolePlaceholdersCommittedBeforeCleanChecks = $syntheticRolePlaceholderIndex -ge 0 -and $fixtureGitAddIndex -gt $syntheticRolePlaceholderIndex
$syntheticAdmissionDiagnosticsBound = $mainSelfTestText.Contains('$syntheticDiscoveryProducerContext = Get-D32PowerShellModuleAdmissionValidationContext') -and
    $mainSelfTestText.Contains('$syntheticBaselineProducerContext = Get-D32PowerShellModuleAdmissionValidationContext') -and
    $mainSelfTestText.Contains('$syntheticCopiedDiscoveryValidationContext = Get-D32PowerShellModuleAdmissionValidationContext') -and
    $mainSelfTestText.Contains('$syntheticBaselineSameProcessValidationContext = Get-D32PowerShellModuleAdmissionValidationContext') -and
    $mainSelfTestText.Contains('$syntheticPhase0ProducerContext = Get-D32PowerShellModuleAdmissionValidationContext') -and
    $mainSelfTestText.Contains('$actualCallerFixtureProducerValidationContext = Get-D32PowerShellModuleAdmissionValidationContext') -and
    $mainSelfTestText.Contains('actual_document = Get-D32PreflightSelfTestProducerContextDiagnostic') -and
    $mainSelfTestText.Contains('expected_producer_context = Get-D32PreflightSelfTestProducerContextDiagnostic') -and
    $mainSelfTestText.Contains('expected_admission_context = Get-D32PreflightSelfTestProducerContextDiagnostic') -and
    $mainSelfTestText.Contains('synthetic producer-binding predicate diagnostics')
$syntheticAdmissionLifecycleBound = $mainSelfTestText.Contains('-DiscoveryProducerAdmission $syntheticDiscoveryAdmission') -and
    $mainSelfTestText.Contains('-BaselineProducerAdmission $syntheticBaselineAdmission') -and
    $mainSelfTestText.Contains("-EntryScriptPath `$syntheticDiscoveryEntryPath") -and
    $mainSelfTestText.Contains("-EntryScriptPath `$syntheticBaselineEntryPath") -and
    $mainSelfTestText.Contains("Join-Path `$fixture 'scripts\d32-phase0-matrix.ps1'") -and
    $mainSelfTestText.Contains('preflight SelfTest synthetic role-entry placeholder path must be absent') -and
    $mainSelfTestText.Contains('never executed and not an actual admitted -File launch or module-admission proof') -and
    $mainSelfTestText.Contains('Test-D32PowerShellModuleSelfTestAdmissionImmediateFailureRecovery') -and
    $mainSelfTestText.Contains('Set-D32PowerShellModuleSelfTestAdmission -Lease $syntheticModuleAdmissionLease -Admission $syntheticPreflightAdmission') -and
    $mainSelfTestText.Contains('Restore-D32PowerShellModuleSelfTestAdmission -Lease $syntheticModuleAdmissionLease') -and
    $mainSelfTestText.Contains('syntheticPhase0Admission.runner_process.process_id') -and
    $mainSelfTestText.Contains('role-specific discovery/baseline/Phase0 entry and process identities') -and
    $syntheticAdmissionDiagnosticsBound
$syntheticAdmissionBuilderComplete = $syntheticAdmissionBuilderText.Contains('This shape-only context is confined to the owned temporary SelfTest') -and
    $syntheticAdmissionBuilderText.Contains('$admission.candidate_sha = $CandidateSha') -and
    $syntheticAdmissionBuilderText.Contains('$admission.source_repo = $repo') -and
    $syntheticAdmissionBuilderText.Contains('$admission.authority_reference = $SyntheticAuthorityReference') -and
    $syntheticAdmissionBuilderText.Contains('$admission.profile_reference = $profileReference') -and
    $syntheticAdmissionBuilderText.Contains('$admission.runner_process.process_id = [int]$SyntheticProcessId') -and
    $syntheticAdmissionBuilderText.Contains('$admission.runner_process.start_time_utc_ticks = [Int64]$SyntheticStartTimeUtcTicks') -and
    $syntheticAdmissionBuilderText.Contains('$admission.entry_script_path = $entry') -and
    $syntheticAdmissionBuilderText.Contains('$admission.startup.file_operand = $entry') -and
    $syntheticAdmissionBuilderText.Contains('does not claim')
$fixturePrebuildAstTokens = $null; $fixturePrebuildAstErrors = $null
$fixturePrebuildAst = [System.Management.Automation.Language.Parser]::ParseInput($sourceFiles.fixture, [ref]$fixturePrebuildAstTokens, [ref]$fixturePrebuildAstErrors)
$fixturePrebuildSelfTestAst = $fixturePrebuildAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-D32SelfTest' }, $true)
$fixturePrebuildSelfTestText = if ($null -ne $fixturePrebuildSelfTestAst) { $fixturePrebuildSelfTestAst.Extent.Text } else { '' }
$fixtureSyntheticAdmissionClosure = $fixturePrebuildSelfTestText.Contains('$fixtureSyntheticAdmission.entry_script_path = $syntheticEntryScriptPath') -and
    $fixturePrebuildSelfTestText.Contains('$fixtureSyntheticAdmission.runner_process.process_id = [int]$syntheticRunnerProcessId') -and
    $fixturePrebuildSelfTestText.Contains('powershell_module_admission = $fixtureSyntheticAdmission') -and
    $fixturePrebuildSelfTestText.Contains('Set-D32PowerShellModuleSelfTestAdmission -Lease $syntheticModuleAdmissionLease -Admission $fixtureSyntheticAdmission') -and
    $fixturePrebuildSelfTestText.Contains('Restore-D32PowerShellModuleSelfTestAdmission -Lease $syntheticModuleAdmissionLease')
$baselineDiagnosticsBound = $sourceFiles.inventory.Contains('failedAdmissionBindings') -and
    $sourceFiles.inventory.Contains("discoveryProducerContext = Get-D32PowerShellModuleAdmissionValidationContext") -and
    $sourceFiles.inventory.Contains("baselineProducerContext = Get-D32PowerShellModuleAdmissionValidationContext") -and
    $sourceFiles.inventory.Contains("baselineProfileContext = Get-D32PowerShellModuleAdmissionValidationContext") -and
    $sourceFiles.inventory.Contains("baselineProfileDetail = Get-D32PowerShellModuleAdmissionValidationDetail") -and
    $sourceFiles.inventory.Contains('baseline_profile:$($baselineProfileContext):$baselineProfileDetailJson') -and
    $sourceFiles.helper.Contains('producer.role-entry-path') -and $sourceFiles.helper.Contains('producer.exact-linked-admission') -and
    $sourceFiles.helper.Contains('producer.distinct-process-identity')
$expectedProducerBindingCallCounts = [ordered]@{
    fixture = 1
    phase0 = 4
    preflight = 12
    discovery = 1
    baseline = 1
    inventory = 2
}
$actualProducerBindingCallCounts = [ordered]@{}
$producerBindingCallTotal = 0
foreach ($callerName in $expectedProducerBindingCallCounts.Keys) {
    $callerTokens = $null; $callerParseErrors = $null
    $callerAst = [System.Management.Automation.Language.Parser]::ParseInput($sourceFiles[$callerName], [ref]$callerTokens, [ref]$callerParseErrors)
    $bindingCalls = $callerAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Test-D32PowerShellModuleAdmissionProducerBinding' }, $true)
    $actualProducerBindingCallCounts[$callerName] = [Int32]$bindingCalls.Count
    $producerBindingCallTotal += [Int32]$bindingCalls.Count
}
$producerBindingCallCensusExact = $actualProducerBindingCallCounts.Count -eq $expectedProducerBindingCallCounts.Count -and
    @($expectedProducerBindingCallCounts.Keys | Where-Object { $actualProducerBindingCallCounts[$_] -ne $expectedProducerBindingCallCounts[$_] }).Count -eq 0 -and
    $producerBindingCallTotal -eq 21
Add-D32ProducerBindingCase 'source lifecycle parses and binds fixture/discovery/baseline/Phase0/release/aggregate producer contexts' `
    ($sourceParseErrors.Count -eq 0 -and $fixtureWriterBound -and $phase0FixtureReferenceBound -and $phase0WriterBound -and $discoveryWriterBound -and $baselineSlotsBound -and $preflightWritersBound -and $historicalRolesBound -and $aggregateWriterCurrentContextBound -and $aggregateHistoricalReaderDoesNotBindReaderProcess -and $baselineSyntheticProducersDistinct -and $syntheticAdmissionLifecycleBound -and $syntheticAdmissionBuilderComplete -and $fixtureSyntheticAdmissionClosure -and $baselineDiagnosticsBound -and $producerBindingCallCensusExact) `
    "parse_errors=$($sourceParseErrors -join ','); fixture=$fixtureWriterBound; phase0_fixture=$phase0FixtureReferenceBound; phase0_writer=$phase0WriterBound; discovery=$discoveryWriterBound; baseline=$baselineSlotsBound; preflight_writers=$preflightWritersBound; historical=$historicalRolesBound; aggregate_writer=$aggregateWriterCurrentContextBound; aggregate_reader_historical=$aggregateHistoricalReaderDoesNotBindReaderProcess; baseline_synthetic=$baselineSyntheticProducersDistinct; synthetic_lifecycle=$syntheticAdmissionLifecycleBound; synthetic_builder=$syntheticAdmissionBuilderComplete; fixture_synthetic=$fixtureSyntheticAdmissionClosure; baseline_diagnostics=$baselineDiagnosticsBound; binding_calls=$((ConvertTo-D32PowerShellAuthorityJsonText -Value $actualProducerBindingCallCounts)); all_callers_shared=$producerBindingCallCensusExact; predicate_diagnostics=$syntheticAdmissionDiagnosticsBound"
Add-D32ProducerBindingCase 'SelfTest role-entry placeholders are committed before exact clean-candidate admission checks' `
    $syntheticRolePlaceholdersCommittedBeforeCleanChecks `
    "role_placeholder_index=$syntheticRolePlaceholderIndex; git_add_index=$fixtureGitAddIndex"

Assert-D32PowerShellAuthorityLoadedModuleSetUnchanged -Expected $loadedAtStart
$passed = $cases.Where({ $_.passed }).Count
$result = [ordered]@{
    record_type = 'D32_POWERSHELL_PRODUCER_BINDING_SELFTEST_V1'
    case_count = $cases.Count
    passed = $passed
    failed = @($failures.ToArray())
    cases = $cases.ToArray()
    module_import_attempts = [int]$global:D32PowerShellModuleImportAttempts
    shape_only_producer_role_results = $roleContextResults.ToArray()
    shape_only_six_predicate_results = $sixPredicateResults
    actual_module_admission_constructed = $false
    cargo_invoked = $false
    discovery_invoked = $false
    formal_root_claimed = $false
}
[Console]::WriteLine((ConvertTo-D32PowerShellAuthorityJsonText -Value $result))
if ($failures.Count -gt 0 -or $global:D32PowerShellModuleImportAttempts -ne 0) { exit 1 }
