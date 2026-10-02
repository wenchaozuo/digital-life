[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
    [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
    [Parameter(Mandatory = $true)][string]$ExpectedToolchainProfileSha256,
    [Parameter(Mandatory = $true)][string]$PowerShellModuleAuthorityPath,
    [Parameter(Mandatory = $true)][string]$ExpectedPowerShellModuleAuthoritySha256,
    [Parameter(Mandatory = $true)][string]$PinnedGitPath,
    [Parameter(Mandatory = $true)][string]$PinnedGitSha256,
    [Parameter(Mandatory = $true)][string]$TauriMacrosSourceAuthorityPath,
    [Parameter(Mandatory = $true)][string]$ExpectedTauriMacrosSourceAuthoritySha256,
    [Parameter(Mandatory = $true)][string]$VendoredProtocAuthorityPath,
    [Parameter(Mandatory = $true)][string]$ExpectedVendoredProtocAuthoritySha256,
    [ValidateRange(60, 14400)][int]$Phase0TimeoutSeconds = 1800,
    [ValidateRange(1, 28800)][int]$Phase0InventoryListTimeoutSeconds = 28800,
    [Parameter(DontShow = $true)][switch]$LoaderSelfTest
)

. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
$null = Initialize-D32PowerShellModuleAuthority -CallerProfilePath $ToolchainProfilePath `
    -CallerExpectedProfileSha256 $ExpectedToolchainProfileSha256 `
    -CallerModuleAuthorityPath $PowerShellModuleAuthorityPath -CallerExpectedModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
    -CallerCandidateSha $ExpectedCandidateSha -CallerRepository $Repository -CallerGitPath $PinnedGitPath -CallerGitSha256 $PinnedGitSha256 `
    -EntryScriptPath $PSCommandPath -LocalSelfTestOnly:$LoaderSelfTest

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([String]::IsNullOrWhiteSpace($PSCommandPath)) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: exact runner script location is required' }
$scriptRoot = Split-Path -Parent ([IO.Path]::GetFullPath($PSCommandPath))
. (Join-Path $scriptRoot 'd32-phase0-matrix.ps1') -Phase0LibraryOnly `
    -Phase0ToolchainProfilePath $ToolchainProfilePath -Phase0ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256 `
    -Phase0PowerShellModuleAuthorityPath $PowerShellModuleAuthorityPath -Phase0ExpectedPowerShellModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
    -Phase0ExpectedCandidateSha $ExpectedCandidateSha -Phase0RepoRoot $Repository -Phase0PinnedGitPath $PinnedGitPath -Phase0PinnedGitSha256 $PinnedGitSha256 `
    -Phase0InventoryListTimeoutSeconds $Phase0InventoryListTimeoutSeconds -Phase0TimeoutSeconds $Phase0TimeoutSeconds
$preflightLibraryPath = [IO.Path]::GetFullPath((Join-Path $scriptRoot 'd32-preflight.ps1'))
if (-not (Test-D32ProfileNoReparsePath -Path $preflightLibraryPath) -or -not (Test-Path -LiteralPath $preflightLibraryPath -PathType Leaf)) {
    throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: exact d32-preflight.ps1 helper library is missing or reparse-backed'
}
. $preflightLibraryPath -LibraryOnly -Phase0DependencyLibraryOnly -RepoRoot $Repository -EvidenceRoot $EvidenceRoot -ModuleAuthorityCandidateSha $ExpectedCandidateSha `
    -ToolchainProfilePath $ToolchainProfilePath -ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256 `
    -PowerShellModuleAuthorityPath $PowerShellModuleAuthorityPath -ExpectedPowerShellModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
    -TrustedGitPath $PinnedGitPath -TrustedGitSha256 $PinnedGitSha256
$preflightDependencyFailures = @(Get-D32Phase0PreflightDependencyFailures -PreflightLibraryPath $preflightLibraryPath)
if ($preflightDependencyFailures.Count -gt 0) {
    throw "TEST_INVENTORY_DISCOVERY_BLOCKED: preflight helper library is incomplete or shadowed ($($preflightDependencyFailures -join ', '))"
}

function Test-D32InventoryRunnerLoaderDependencyClosure {
    param([Parameter(Mandatory = $true)][string[]]$RunnerScriptPaths)

    $expectedSourcePaths = @($RunnerScriptPaths) + @(
        (Join-Path $scriptRoot 'd32-phase0-matrix.ps1'),
        (Join-Path $scriptRoot 'd32-build-toolchain-profile.ps1'),
        (Join-Path $scriptRoot 'd32-vendored-protoc-authority.ps1'),
        (Join-Path $scriptRoot 'd32-h7c-git-child-authority.ps1'),
        (Join-Path $scriptRoot 'd32-test-inventory-authority.ps1'),
        (Join-Path $scriptRoot 'd32-preflight.ps1'),
        (Join-Path $scriptRoot 'd32-fixture-prebuild.ps1'),
        (Join-Path $scriptRoot 'd32-powershell-module-authority.ps1')
    )
    $expectedSourcePaths = @($expectedSourcePaths | ForEach-Object { [IO.Path]::GetFullPath([string]$_) })
    $expectedSourceSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($expectedSource in $expectedSourcePaths) { [void]$expectedSourceSet.Add([string]$expectedSource) }
    $failures = [System.Collections.Generic.List[string]]::new()
    $staticFunctions = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($expectedSource in $expectedSourcePaths) {
        $sourceTokens = $null
        $sourceErrors = $null
        $sourceAst = [System.Management.Automation.Language.Parser]::ParseFile($expectedSource, [ref]$sourceTokens, [ref]$sourceErrors)
        if ($sourceErrors.Count -gt 0) {
            foreach ($sourceError in $sourceErrors) { $failures.Add("dependency-parse:$([IO.Path]::GetFileName($expectedSource)):$($sourceError.Message)") }
            continue
        }
        foreach ($definition in $sourceAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            $staticFunctions[[string]$definition.Name] = $definition
        }
    }
    $visitedCommands = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $visitedFunctions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $visitedModules = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pending = [System.Collections.Generic.Queue[string]]::new()
    foreach ($runnerScriptPath in $RunnerScriptPaths) {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($runnerScriptPath, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count -gt 0) {
            foreach ($parseError in $parseErrors) { $failures.Add("parse:$([IO.Path]::GetFileName($runnerScriptPath)):$($parseError.Message)") }
            continue
        }
        foreach ($commandAst in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $commandName = $commandAst.GetCommandName()
            if (-not [String]::IsNullOrWhiteSpace($commandName)) { $pending.Enqueue([string]$commandName) }
        }
    }

    while ($pending.Count -gt 0) {
        $commandName = $pending.Dequeue()
        if (-not $visitedCommands.Add($commandName)) { continue }
        $command = Microsoft.PowerShell.Core\Get-Command -Name $commandName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $command) {
            if ($staticFunctions.ContainsKey($commandName)) {
                $definition = $staticFunctions[$commandName]
                $sourcePath = [IO.Path]::GetFullPath([string]$definition.Extent.File)
                if (-not $expectedSourceSet.Contains($sourcePath)) {
                    $failures.Add("static-function-from-unexpected-source:$commandName")
                    continue
                }
                if (-not $visitedFunctions.Add($commandName)) { continue }
                foreach ($nestedCommandAst in $definition.Body.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                    $nestedCommandName = $nestedCommandAst.GetCommandName()
                    if (-not [String]::IsNullOrWhiteSpace($nestedCommandName)) { $pending.Enqueue([string]$nestedCommandName) }
                }
                continue
            }
            $failures.Add("missing-command:$commandName")
            continue
        }
        if ($command.CommandType -eq [System.Management.Automation.CommandTypes]::Alias) {
            if ([String]::IsNullOrWhiteSpace([string]$command.Definition)) { $failures.Add("unresolved-alias:$commandName") }
            else { $pending.Enqueue([string]$command.Definition) }
            continue
        }
        if ($command.CommandType -eq [System.Management.Automation.CommandTypes]::Function) {
            $sourcePath = [string]$command.ScriptBlock.Ast.Extent.File
            if ([String]::IsNullOrWhiteSpace($sourcePath)) {
                $failures.Add("function-without-source:$commandName")
                continue
            }
            $sourcePath = [IO.Path]::GetFullPath($sourcePath)
            if (-not $expectedSourceSet.Contains($sourcePath)) {
                $failures.Add("function-from-unexpected-source:$commandName")
                continue
            }
            if (-not $visitedFunctions.Add($commandName)) { continue }
            foreach ($nestedCommandAst in $command.ScriptBlock.Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $nestedCommandName = $nestedCommandAst.GetCommandName()
                if (-not [String]::IsNullOrWhiteSpace($nestedCommandName)) { $pending.Enqueue([string]$nestedCommandName) }
            }
            continue
        }
        if ($command.CommandType -eq [System.Management.Automation.CommandTypes]::Cmdlet) {
            $moduleName = [string]$command.ModuleName
            if (-not [String]::IsNullOrWhiteSpace($moduleName)) {
                if ($moduleName -cnotin @('Microsoft.PowerShell.Core', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility', 'CimCmdlets')) {
                    $failures.Add("unapproved-cmdlet-module:$moduleName")
                }
                elseif ($moduleName -cne 'Microsoft.PowerShell.Core') {
                    $expectedModulePath = switch ($moduleName) {
                        'Microsoft.PowerShell.Management' { [IO.Path]::Combine([IO.Path]::GetFullPath([IO.Path]::Combine($PSHOME, 'Modules')), 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Management.psd1') }
                        'Microsoft.PowerShell.Utility' { [IO.Path]::Combine([IO.Path]::GetFullPath([IO.Path]::Combine($PSHOME, 'Modules')), 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Utility.psd1') }
                        'CimCmdlets' { [IO.Path]::Combine($PSHOME, 'Microsoft.Management.Infrastructure.CimCmdlets.dll') }
                    }
                    $actualModulePath = if ($null -eq $command.Module) { '' } else { [string]$command.Module.Path }
                    if ([String]::IsNullOrWhiteSpace($actualModulePath) -or
                        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($actualModulePath), [IO.Path]::GetFullPath($expectedModulePath)) -or
                        -not (Test-D32PowerShellAuthorityPathNoReparse -Path $actualModulePath)) {
                        $failures.Add("untrusted-cmdlet-module-path:$moduleName")
                    }
                }
                [void]$visitedModules.Add($moduleName)
            }
            continue
        }
        $failures.Add("unapproved-command-type:$commandName/$($command.CommandType)")
    }

    return [PSCustomObject]@{
        Passed = ($failures.Count -eq 0)
        FunctionCount = $visitedFunctions.Count
        Modules = @($visitedModules | Sort-Object -CaseSensitive)
        Failures = @($failures.ToArray())
    }
}

if ($LoaderSelfTest) {
    $runnerScriptPaths = @(
        [IO.Path]::GetFullPath($PSCommandPath),
        [IO.Path]::GetFullPath((Join-Path $scriptRoot 'd32-test-inventory-baseline.ps1')),
        [IO.Path]::GetFullPath((Join-Path $scriptRoot 'd32-phase0-matrix.ps1')),
        [IO.Path]::GetFullPath((Join-Path $scriptRoot 'd32-preflight.ps1'))
    )
    $loader = Test-D32InventoryRunnerLoaderDependencyClosure -RunnerScriptPaths $runnerScriptPaths
    if (-not $loader.Passed) { throw "TEST_INVENTORY_DISCOVERY_LOADER_SELFTEST_FAILED: $($loader.Failures -join ', ')" }
    Write-Output 'D32_TEST_INVENTORY_DISCOVERY_LOADER=PASS'
    Write-Output 'discovery_admission=PAST_IMPORT'
    Write-Output 'powershell_module_authority=EXACT_PSHOME_MODULES_NO_AUTOLOAD'
    Write-Output "custom_function_dependencies=$($loader.FunctionCount)"
    Write-Output "cmdlet_modules=$($loader.Modules -join ',')"
    Write-Output 'cargo_invocations=0'
    Write-Output 'evidence_root_claimed=false'
    return
}

foreach ($required in @('Phase0TimeoutSeconds', 'Phase0InventoryListTimeoutSeconds')) {
    if (-not $PSBoundParameters.ContainsKey($required)) { throw "TEST_INVENTORY_DISCOVERY_BLOCKED: caller must explicitly pin -$required" }
}
if ($PSVersionTable.PSVersion -lt [Version]'7.5' -or $Phase0TimeoutSeconds -ne 14400 -or $Phase0InventoryListTimeoutSeconds -ne 28800) {
    throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: discovery requires native PowerShell 7.5+, 14400-second fixed commands, and explicit 28800-second list commands'
}
if ($ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or $PinnedGitSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $ExpectedToolchainProfileSha256 -cnotmatch '^[0-9a-f]{64}$' -or $ExpectedTauriMacrosSourceAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $ExpectedVendoredProtocAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: exact lowercase caller pins are malformed' }

$repo = [IO.Path]::GetFullPath($Repository)
if (-not (Test-D32ProfileNoReparsePath -Path $repo) -or -not (Test-Path -LiteralPath $repo -PathType Container)) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: candidate repository must be an existing non-reparse directory' }
$output = Assert-D32Phase0OutputRoot -Path $EvidenceRoot -Repository $repo
$profile = Test-D32BuildToolchainProfile -ProfilePath $ToolchainProfilePath -ExpectedSha256 $ExpectedToolchainProfileSha256 -Repository $repo -EvidenceRoot $output
if (-not $profile.IsValid) { throw "TEST_INVENTORY_DISCOVERY_BLOCKED: current Profile V2 failed: $($profile.Failure)" }
$gitImage = Test-D32TrustedGitImage -Path $PinnedGitPath -ExpectedSha256 $PinnedGitSha256
if (-not $gitImage.IsValid) { throw "TEST_INVENTORY_DISCOVERY_BLOCKED: direct Git image failed: $($gitImage.Failure)" }
$sourceAuthority = Test-D32TauriMacrosSourcePatchAuthority -AuthorityPath $TauriMacrosSourceAuthorityPath -ExpectedAuthoritySha256 $ExpectedTauriMacrosSourceAuthoritySha256 `
    -Repository $repo -CandidateSha $ExpectedCandidateSha -ValidatedProfile $profile -EvidenceRoot $output
$protocAuthority = Test-D32VendoredProtocAuthority -AuthorityPath $VendoredProtocAuthorityPath -ExpectedAuthoritySha256 $ExpectedVendoredProtocAuthoritySha256 `
    -Repository $repo -CandidateSha $ExpectedCandidateSha -ValidatedProfile $profile -EvidenceRoot $output -ExpectedScope 'D32_TEST_INVENTORY_DISCOVERY_ONLY'
Set-D32GitCaptureContext -ValidatedProfile $profile -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256 -TimeoutSeconds 120
$before = Get-D32Phase0GitState -Repository $repo -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256
if ($before.Head -cne $ExpectedCandidateSha) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: exact clean candidate SHA does not match caller pin' }
$startedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
$findings = [System.Collections.ArrayList]::new()
Test-D32Governance -Repository $repo -Findings $findings
if (@($findings | Where-Object { $_.Severity -eq 'ERROR' }).Count -gt 0) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: current governance preflight failed' }
$capacity = Get-D32Phase0FixtureBuildCapacity -Repository $repo -EvidenceRoot $output -Phase0TimeoutSeconds $Phase0TimeoutSeconds
$runId = [Guid]::NewGuid().ToString('N').ToLowerInvariant()
$ownerRoot = New-D32Phase0FixtureOutputRoot -Path $output -Repository $repo -ExpectedCandidateSha $ExpectedCandidateSha -ValidatedProfile $profile -RunId $runId
$output = [string]$ownerRoot.Path
Set-D32Phase0FailureContext -Context ([PSCustomObject]@{
    EvidenceRoot = $output; CandidateSha = $ExpectedCandidateSha; Profile = $profile; RunId = $runId
    RootIdentity = $ownerRoot.RootIdentity; OwnerMarker = $ownerRoot.OwnerMarker
})

try {

$runRoot = Join-Path $output 'r'
$cargoHome = Join-Path $runRoot 'c'
$tempRoot = Join-Path $runRoot 't'
foreach ($directory in @($runRoot, $cargoHome, $tempRoot)) { [void](New-D32ProfileDirectoryCreateNew -Path $directory) }
$logsRoot = Join-Path $output 'logs'
[void](New-D32ProfileDirectoryCreateNew -Path $logsRoot)
$null = Test-D32CargoHome -Path $cargoHome -Repository $repo -RequireEmpty
$null = Test-D32Phase0OwnerBinding -EvidenceRoot $output -ExpectedCandidateSha $ExpectedCandidateSha -ValidatedProfile $profile `
    -ExpectedRunId $runId -ExpectedRootIdentity $ownerRoot.RootIdentity -ExpectedMarkerReference $ownerRoot.OwnerMarker

$cargo = [string]$profile.Profile.toolchain.cargo.path
$lockInputs = @(Get-D32BuildToolchainLockInputs -Repository $repo)
$onlineEnvironment = Get-D32BuildToolchainEnvironment -ValidatedProfile $profile -CargoHome $cargoHome -TempRoot $tempRoot -Offline $false
$offlineEnvironment = Get-D32BuildToolchainEnvironment -ValidatedProfile $profile -CargoHome $cargoHome -TempRoot $tempRoot -Offline $true
if ($onlineEnvironment.Contains('PROTOC') -or $offlineEnvironment.Contains('PROTOC')) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: ambient PROTOC is forbidden' }
$fetches = [System.Collections.Generic.List[object]]::new()
$inventoryCommands = [System.Collections.Generic.List[object]]::new()
$ordinal = 0
$common = @{
    Ordinal = [ref]$ordinal; Records = [System.Collections.Generic.List[object]]::new(); LogRoot = $logsRoot; Repository = $repo
    ValidatedProfile = $profile; Environment = $onlineEnvironment; TimeoutSeconds = $Phase0TimeoutSeconds
    ExpectedCandidateSha = $ExpectedCandidateSha; GitPath = $PinnedGitPath; GitSha256 = $PinnedGitSha256
    VendoredProtocRunGrant = $null; H7CGitAuthority = $null; H7CGitRunGrant = $null
}
foreach ($index in 0..2) {
    $lock = $lockInputs[$index]
    $arguments = @('fetch', '--locked', '--manifest-path', $lock.ManifestFullPath, '--target', [string]$profile.Profile.target_triple)
    $name = 'inventory-fetch-{0:D2}' -f ($index + 1)
    $command = Invoke-D32Phase0LoggedCommand @common -Name $name -Executable $cargo -Arguments $arguments
    $fetches.Add($command)
}

# The discovery grant is scoped to this fresh discovery run; Phase0 grants are not replayed.
$discoveryGrant = New-D32VendoredProtocRunGrant -AuthorityPath $VendoredProtocAuthorityPath -AuthoritySha256 $ExpectedVendoredProtocAuthoritySha256 `
    -Repository $repo -CandidateSha $ExpectedCandidateSha -ValidatedProfile $profile -EvidenceRoot $output -OwnerMarkerReference $ownerRoot.OwnerMarker `
    -RunId $runId -CargoHome $cargoHome -Scope 'D32_TEST_INVENTORY_DISCOVERY_ONLY'
$discoveryGrant = Test-D32VendoredProtocRunGrant -Reference $discoveryGrant.Reference -Repository $repo -CandidateSha $ExpectedCandidateSha `
    -ValidatedProfile $profile -EvidenceRoot $output -ExpectedRunId $runId -CargoHome $cargoHome -AuthorityPath $VendoredProtocAuthorityPath `
    -AuthoritySha256 $ExpectedVendoredProtocAuthoritySha256 -OwnerMarkerReference $ownerRoot.OwnerMarker -Scope 'D32_TEST_INVENTORY_DISCOVERY_ONLY'
$packageRows = @{}
$packageCommandMetadata = Get-D32TestInventoryExpectedCommands -Profile $profile.Profile
foreach ($expected in $packageCommandMetadata) {
    $arguments = @($expected.arguments)
    $name = [string]$expected.name
    $protocPolicy = Resolve-D32TestInventoryProtocPolicy -Package ([string]$expected.package) -Environment $offlineEnvironment `
        -RunGrant $(if ([string]$expected.package -ceq 'protocol') { $null } else { $discoveryGrant })
    $command = Invoke-D32Phase0LoggedCommand -Name $name -Executable $cargo -Arguments $arguments -Ordinal ([ref]$ordinal) `
        -Records ([System.Collections.Generic.List[object]]::new()) -LogRoot $logsRoot -Repository $repo -ValidatedProfile $profile `
        -Environment $protocPolicy.Environment -TimeoutSeconds $Phase0InventoryListTimeoutSeconds -ExpectedCandidateSha $ExpectedCandidateSha `
        -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256 -VendoredProtocRunGrant $protocPolicy.RunGrant -H7CGitAuthority $null -H7CGitRunGrant $null
    $lines = @(Read-D32TestInventoryLogReference -Reference $command.stdout -AllowedRoot $output)
    $parsed = Get-D32TestInventoryListOutput -Lines $lines -Package $expected.package -ListingKind $expected.listing_kind
    $inventoryCommands.Add([ordered]@{
        package = [string]$expected.package
        listing_kind = [string]$expected.listing_kind
        features = @($expected.features)
        target_triple = [string]$profile.Profile.target_triple
        digest = Get-D32TestInventoryDigest -Rows $parsed.rows
        row_count = [Int64]$parsed.row_count
        test_count = [Int64]$parsed.test_count
        benchmark_count = [Int64]$parsed.benchmark_count
        rows = @($parsed.rows)
        command = $command
    })
    $packageRows[([string]$expected.package + '|' + [string]$expected.listing_kind)] = @($parsed.rows)
}

$packageInventories = [System.Collections.Generic.List[object]]::new()
foreach ($package in @('protocol', 'vita', 'host')) {
    [string[]]$deferred = @()
    [string[]]$focused = @()
    if ($package -ceq 'vita') { $deferred = @($script:D32Phase0DeferredVita); $focused = @($script:D32Phase0FocusedVita) }
    elseif ($package -ceq 'host') { $deferred = @($script:D32Phase0DeferredHost); $focused = @($script:D32Phase0FocusedHost) }
    $packageInventories.Add((Get-D32TestInventoryCategoryAssignments -Package $package -AllRows $packageRows[($package + '|all')] `
        -IgnoredRows $packageRows[($package + '|ignored')] -DeferredNames $deferred -FocusedSuffixes $focused))
}
$entries = @(Sort-D32TestInventoryBaselineEntries -Entries @($packageInventories | ForEach-Object { $_.entries }))
$packageDigests = [System.Collections.Generic.List[object]]::new()
$categoryCounts = [ordered]@{}
foreach ($inventory in $packageInventories) {
    $packageEntries = @($inventory.entries)
    $packageDigests.Add([ordered]@{ package = [string]$inventory.package; entry_count = [Int64]$packageEntries.Count; sha256 = Get-D32TestInventoryBaselineDigest -Entries $packageEntries })
    $categoryCounts[[string]$inventory.package] = $inventory.category_counts
}

$final = Get-D32Phase0GitState -Repository $repo -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256
if ($final.Head -cne $ExpectedCandidateSha) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: candidate SHA changed during discovery' }
$null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $profile
$storage = [ordered]@{
    run_root = [ordered]@{ path = [IO.Path]::GetFullPath($runRoot); volume_serial_hex = $ownerRoot.RootIdentity.VolumeSerialHex; file_id_hex = (Get-D32ProfileDirectoryIdentity -Path $runRoot).FileIdHex }
    cargo_home = [ordered]@{ path = [IO.Path]::GetFullPath($cargoHome); volume_serial_hex = (Get-D32ProfileDirectoryIdentity -Path $cargoHome).VolumeSerialHex; file_id_hex = (Get-D32ProfileDirectoryIdentity -Path $cargoHome).FileIdHex }
    temp_root = [ordered]@{ path = [IO.Path]::GetFullPath($tempRoot); volume_serial_hex = (Get-D32ProfileDirectoryIdentity -Path $tempRoot).VolumeSerialHex; file_id_hex = (Get-D32ProfileDirectoryIdentity -Path $tempRoot).FileIdHex }
}
$toolchainProfile = Get-D32TestInventoryProfileRecord -ValidatedProfile $profile
$record = [ordered]@{
    schema_version = 2
    record_type = 'D32_TEST_INVENTORY_DISCOVERY_V2'
    status = 'COMPLETE_FOR_COORDINATOR_REVIEW'
    gate_authority = 'NONE'
    runner_process_id = [int]$PID
    candidate_sha = $ExpectedCandidateSha
    source_repo = $repo
    evidence_root_identity = [ordered]@{ path = $ownerRoot.RootIdentity.Path; volume_serial_hex = $ownerRoot.RootIdentity.VolumeSerialHex; file_id_hex = $ownerRoot.RootIdentity.FileIdHex }
    owner_marker = $ownerRoot.OwnerMarker
    run_id = $runId
    toolchain_profile = $toolchainProfile
    lock_inputs = @($lockInputs | ForEach-Object { [ordered]@{ manifest_path = $_.ManifestPath; lock_sha256 = $_.LockSha256; lock_bytes = [Int64]$_.LockBytes } })
    source_patch_authority = $sourceAuthority.Reference
    protoc = [ordered]@{ authority = $protocAuthority.Reference; run_grant = $discoveryGrant.Reference }
    storage = $storage
    fetches = @($fetches.ToArray())
    inventory_commands = @($inventoryCommands.ToArray())
    test_inventory = [ordered]@{
        entries = $entries
        combined_digest = Get-D32TestInventoryBaselineDigest -Entries $entries
        package_digests = @($packageDigests.ToArray())
        category_counts = $categoryCounts
    }
    powershell_module_admission = $global:D32PowerShellModuleAuthorityState.Admission
    started_at_utc = $startedAtUtc
    completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    final_candidate_sha = $final.Head
    final_clean = $true
}
if (-not (Test-D32PowerShellModuleAdmissionProducerBinding -Document $record.powershell_module_admission -CandidateSha $ExpectedCandidateSha `
        -Repository $repo -ProducerRole inventory_discovery -ExpectedAdmissionContext $global:D32PowerShellModuleAuthorityState.Admission `
        -ExpectedProducerContext $global:D32PowerShellModuleAuthorityState.Admission) -or
    -not (Test-D32PowerShellModuleAdmissionRunnerBinding -Document $record.powershell_module_admission -ExpectedProcessId ([Int64]$record.runner_process_id))) {
    throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: discovery writer admission is not the current direct discovery producer context'
}
$recordPath = Join-Path $output 'D32-TEST-INVENTORY-DISCOVERY.json'
if (Test-Path -LiteralPath $recordPath) { throw 'TEST_INVENTORY_DISCOVERY_BLOCKED: refusing to overwrite existing discovery record' }
$json = ConvertTo-Json -InputObject $record -Depth 40 -Compress
$bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
$recordStream = [IO.File]::Open($recordPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
try { $recordStream.Write($bytes, 0, $bytes.Length); $recordStream.Flush($true) }
finally { $recordStream.Dispose() }
$reference = Get-D32Phase0FileReference -Path $recordPath
Write-Output 'inventory_discovery_status=COMPLETE_FOR_COORDINATOR_REVIEW'
Write-Output 'inventory_discovery_gate_authority=NONE'
Write-Output "inventory_discovery_candidate_sha=$ExpectedCandidateSha"
Write-Output "inventory_discovery_path=$recordPath"
Write-Output "inventory_discovery_sha256=$($reference.sha256)"
}
catch {
    $caughtError = [string]$_.Exception.Message
    $primaryError = $caughtError
    $secondaryErrors = [System.Collections.Generic.List[string]]::new()
    $evidence = $null
    $includeCompletedCommandContext = $caughtError -match '^(TEST_INVENTORY_BLOCKED|TEST_INVENTORY_BASELINE_BLOCKED|PHASE0_TEST_INVENTORY_BLOCKED):' -or
        $caughtError.StartsWith('TEST_INVENTORY_DISCOVERY_BLOCKED: captured raw list output differs from structured ', [StringComparison]::Ordinal)
    try {
        if ($includeCompletedCommandContext) { $evidence = Get-D32Phase0DiscoveryFailureEvidence -IncludeCompletedCommandContext }
        else { $evidence = Get-D32Phase0DiscoveryFailureEvidence }
    }
    catch { $secondaryErrors.Add('last fixed-command evidence retrieval failed: ' + $_.Exception.Message) }
    if ($null -ne $evidence) {
        if (-not [String]::IsNullOrWhiteSpace([string]$evidence.PrimaryError) -and [string]$evidence.PrimaryError -cne $caughtError) {
            $primaryError = [string]$evidence.PrimaryError
            $secondaryErrors.Add('discovery orchestration failure: ' + $caughtError)
        }
        foreach ($secondary in @($evidence.SecondaryErrors)) {
            if (-not [String]::IsNullOrWhiteSpace([string]$secondary)) { $secondaryErrors.Add([string]$secondary) }
        }
    }
    $commandResult = if ($null -eq $evidence) { $null } else { $evidence.CommandResult }
    $command = if ($null -eq $evidence) { $null } else { $evidence.Command }
    $processIdentity = if ($null -eq $evidence) { $null } else { $evidence.ProcessIdentity }
    $rawTrace = if ($null -eq $evidence) { $null } else { $evidence.RawV2Trace }
    $nativeCleanup = if ($null -eq $evidence) { $null } else { $evidence.NativeCleanup }
    $stdoutPath = if ($null -eq $evidence) { $null } else { $evidence.StdoutPath }
    $stderrPath = if ($null -eq $evidence) { $null } else { $evidence.StderrPath }
    $stdoutReference = if ($null -eq $commandResult) { $null } else { $commandResult.stdout }
    $stderrReference = if ($null -eq $commandResult) { $null } else { $commandResult.stderr }
    foreach ($capture in @([PSCustomObject]@{ Name = 'stdout'; Path = $stdoutPath }, [PSCustomObject]@{ Name = 'stderr'; Path = $stderrPath })) {
        if ([String]::IsNullOrWhiteSpace([string]$capture.Path)) { continue }
        try {
            $captureParent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath([string]$capture.Path))
            if ([String]::IsNullOrWhiteSpace($captureParent) -or -not (Test-D32ProfileNoReparsePath -Path $captureParent)) {
                $secondaryErrors.Add("$($capture.Name) capture parent is missing or reparse-backed; capture reference is explicitly unavailable")
                if ($capture.Name -ceq 'stdout') { $stdoutPath = $null } else { $stderrPath = $null }
            }
        }
        catch {
            $secondaryErrors.Add("$($capture.Name) capture-path validation failed: $($_.Exception.Message)")
            if ($capture.Name -ceq 'stdout') { $stdoutPath = $null } else { $stderrPath = $null }
        }
    }
    try {
        $null = Write-D32Phase0BlockedDiagnostic -PrimaryError $primaryError -SecondaryErrors @($secondaryErrors.ToArray()) `
            -Command $command -ProcessIdentity $processIdentity -RawV2Trace $rawTrace -NativeCleanup $nativeCleanup `
            -StdoutPath $stdoutPath -StderrPath $stderrPath -ExpectedStdoutReference $stdoutReference -ExpectedStderrReference $stderrReference
    }
    catch { $secondaryErrors.Add('blocked diagnostic capture failed: ' + $_.Exception.Message) }
    if ($secondaryErrors.Count -gt 0) {
        [Console]::Error.WriteLine('TEST_INVENTORY_DISCOVERY_SECONDARY_ERRORS: ' + ($secondaryErrors -join ' | '))
    }
    throw "TEST_INVENTORY_DISCOVERY_BLOCKED: $primaryError"
}
