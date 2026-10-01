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
    $allowed = @(Get-D32PowerShellModuleProducerEntryPaths -Repository $repo -ProducerRole $Role)
    foreach ($path in $allowed) {
        if ([StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$Admission.entry_script_path), [IO.Path]::GetFullPath([string]$path)) -and
            [StringComparer]::OrdinalIgnoreCase.Equals([string]$Admission.startup.file_operand, [string]$Admission.entry_script_path)) { return $true }
    }
    return $false
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
$syntheticAdmissionLifecycleBound = $mainSelfTestText.Contains('-DiscoveryProducerAdmission $syntheticDiscoveryAdmission') -and
    $mainSelfTestText.Contains('-BaselineProducerAdmission $syntheticPreflightAdmission') -and
    $mainSelfTestText.Contains('$actualModuleAdmissionState.Admission = $syntheticPreflightAdmission') -and
    $mainSelfTestText.Contains('$actualModuleAdmissionState.Admission = $actualModuleAdmissionForRestore') -and
    $mainSelfTestText.Contains('owned SelfTest-only producer contexts bind the fixture candidate/Profile/entry')
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
    $fixturePrebuildSelfTestText.Contains('$moduleAdmissionState.Admission = $fixtureSyntheticAdmission') -and
    $fixturePrebuildSelfTestText.Contains('$moduleAdmissionState.Admission = $moduleAdmissionForRestore')
Add-D32ProducerBindingCase 'source lifecycle parses and binds fixture/discovery/baseline/Phase0/release/aggregate producer contexts' `
    ($sourceParseErrors.Count -eq 0 -and $fixtureWriterBound -and $phase0FixtureReferenceBound -and $phase0WriterBound -and $discoveryWriterBound -and $baselineSlotsBound -and $preflightWritersBound -and $historicalRolesBound -and $aggregateWriterCurrentContextBound -and $aggregateHistoricalReaderDoesNotBindReaderProcess -and $baselineSyntheticProducersDistinct -and $syntheticAdmissionLifecycleBound -and $syntheticAdmissionBuilderComplete -and $fixtureSyntheticAdmissionClosure) `
    "parse_errors=$($sourceParseErrors -join ','); fixture=$fixtureWriterBound; phase0_fixture=$phase0FixtureReferenceBound; phase0_writer=$phase0WriterBound; discovery=$discoveryWriterBound; baseline=$baselineSlotsBound; preflight_writers=$preflightWritersBound; historical=$historicalRolesBound; aggregate_writer=$aggregateWriterCurrentContextBound; aggregate_reader_historical=$aggregateHistoricalReaderDoesNotBindReaderProcess; baseline_synthetic=$baselineSyntheticProducersDistinct; synthetic_lifecycle=$syntheticAdmissionLifecycleBound; synthetic_builder=$syntheticAdmissionBuilderComplete; fixture_synthetic=$fixtureSyntheticAdmissionClosure"

Assert-D32PowerShellAuthorityLoadedModuleSetUnchanged -Expected $loadedAtStart
$passed = $cases.Where({ $_.passed }).Count
$result = [ordered]@{
    record_type = 'D32_POWERSHELL_PRODUCER_BINDING_SELFTEST_V1'
    case_count = $cases.Count
    passed = $passed
    failed = @($failures.ToArray())
    cases = $cases.ToArray()
    module_import_attempts = [int]$global:D32PowerShellModuleImportAttempts
    cargo_invoked = $false
    discovery_invoked = $false
    formal_root_claimed = $false
}
[Console]::WriteLine((ConvertTo-D32PowerShellAuthorityJsonText -Value $result))
if ($failures.Count -gt 0 -or $global:D32PowerShellModuleImportAttempts -ne 0) { exit 1 }
