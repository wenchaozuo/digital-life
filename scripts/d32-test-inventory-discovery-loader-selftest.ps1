#Requires -Version 7.5
[CmdletBinding()]
param()

. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
$null = Initialize-D32PowerShellModuleAuthority -LocalSelfTestOnly

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$repository = [IO.Path]::GetFullPath((Split-Path -Parent $scriptRoot))
$phase0Script = [IO.Path]::GetFullPath((Join-Path $scriptRoot 'd32-phase0-matrix.ps1'))
$preflightScript = [IO.Path]::GetFullPath((Join-Path $scriptRoot 'd32-preflight.ps1'))
$discoveryScript = [IO.Path]::GetFullPath((Join-Path $scriptRoot 'd32-test-inventory-discovery.ps1'))
$baselineScript = [IO.Path]::GetFullPath((Join-Path $scriptRoot 'd32-test-inventory-baseline.ps1'))
$pwshImage = [IO.Path]::GetFullPath((Join-Path $PSHOME 'pwsh.exe'))
foreach ($path in @($phase0Script, $preflightScript, $discoveryScript, $baselineScript, $pwshImage)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "SELFTEST_BLOCKED: required PowerShell discovery loader image is missing: $path" }
}

function Invoke-D32DiscoveryLoaderChild {
    param(
        [Parameter(Mandatory = $true)][string]$RunnerScript,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$PSModulePathOverride,
        [Parameter(Mandatory = $true)][string]$MarkerPath
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pwshImage
    $startInfo.WorkingDirectory = $repository
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Environment['PSModulePath'] = $PSModulePathOverride
    $startInfo.Environment['D32_MODULE_AUTHORITY_SELFTEST_MARKER'] = $MarkerPath
    foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $RunnerScript) + $Arguments) {
        [void]$startInfo.ArgumentList.Add([string]$argument)
    }

    $process = [Diagnostics.Process]::new()
    try {
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { throw 'SELFTEST_BLOCKED: fresh PowerShell child did not start' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) {
            try { $process.Kill() } catch { }
            throw 'SELFTEST_FAILED: fresh PowerShell discovery loader exceeded 60 seconds'
        }
        $process.WaitForExit()
        return [PSCustomObject]@{
            ExitCode = [int]$process.ExitCode
            StdOut = [string]$stdoutTask.GetAwaiter().GetResult()
            StdErr = [string]$stderrTask.GetAwaiter().GetResult()
        }
    }
    finally { $process.Dispose() }
}

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))
$testRoot = [IO.Path]::GetFullPath((Join-Path $tempBase ('D32-inventory-module-authority-selftest-' + [Guid]::NewGuid().ToString('N'))))
if (Test-Path -LiteralPath $testRoot) { throw 'SELFTEST_BLOCKED: generated temporary module-authority fixture path already exists' }
[void][IO.Directory]::CreateDirectory($testRoot)

try {
    $ambientRoot = Join-Path $testRoot 'ambient-modules'
    $utilityRoot = Join-Path $ambientRoot 'Microsoft.PowerShell.Utility'
    $managementRoot = Join-Path $ambientRoot 'Microsoft.PowerShell.Management'
    $coreRoot = Join-Path $ambientRoot 'Microsoft.PowerShell.Core'
    $cimRoot = Join-Path $ambientRoot 'CimCmdlets'
    [void][IO.Directory]::CreateDirectory($utilityRoot)
    [void][IO.Directory]::CreateDirectory($managementRoot)
    [void][IO.Directory]::CreateDirectory($coreRoot)
    [void][IO.Directory]::CreateDirectory($cimRoot)
    $utilityManifest = @'
@{
    RootModule = 'Microsoft.PowerShell.Utility.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'd3200000-0000-4000-8000-000000000001'
    FunctionsToExport = @('Select-Object')
    CmdletsToExport = @()
    AliasesToExport = @()
    VariablesToExport = @()
}
'@
    $managementManifest = @'
@{
    RootModule = 'Microsoft.PowerShell.Management.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'd3200000-0000-4000-8000-000000000002'
    FunctionsToExport = @('Split-Path')
    CmdletsToExport = @()
    AliasesToExport = @()
    VariablesToExport = @()
}
'@
    $cimManifest = @'
@{
    RootModule = 'CimCmdlets.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'd3200000-0000-4000-8000-000000000003'
    FunctionsToExport = @('Get-CimInstance')
    CmdletsToExport = @()
    AliasesToExport = @()
    VariablesToExport = @()
}
'@
    $coreManifest = @'
@{
    RootModule = 'Microsoft.PowerShell.Core.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'd3200000-0000-4000-8000-000000000004'
    FunctionsToExport = @('Get-Command', 'Get-Module', 'Import-Module')
    CmdletsToExport = @()
    AliasesToExport = @()
    VariablesToExport = @()
}
'@
    $moduleBody = @'
$marker = [Environment]::GetEnvironmentVariable('D32_MODULE_AUTHORITY_SELFTEST_MARKER')
if (-not [String]::IsNullOrWhiteSpace($marker)) { [IO.File]::WriteAllText($marker, 'untrusted module initialization ran') }
'@
    $utilityBody = $moduleBody + "`nfunction Select-Object { throw 'D32_UNTRUSTED_MODULE_EXECUTED' }`nExport-ModuleMember -Function Select-Object`n"
    $managementBody = $moduleBody + "`nfunction Split-Path { throw 'D32_UNTRUSTED_MODULE_EXECUTED' }`nExport-ModuleMember -Function Split-Path`n"
    $cimBody = $moduleBody + "`nfunction Get-CimInstance { throw 'D32_UNTRUSTED_MODULE_EXECUTED' }`nExport-ModuleMember -Function Get-CimInstance`n"
    $coreBody = $moduleBody + "`nfunction Get-Command { throw 'D32_UNTRUSTED_MODULE_EXECUTED' }`nfunction Get-Module { throw 'D32_UNTRUSTED_MODULE_EXECUTED' }`nfunction Import-Module { throw 'D32_UNTRUSTED_MODULE_EXECUTED' }`nExport-ModuleMember -Function Get-Command,Get-Module,Import-Module`n"
    [IO.File]::WriteAllText((Join-Path $utilityRoot 'Microsoft.PowerShell.Utility.psd1'), $utilityManifest, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $utilityRoot 'Microsoft.PowerShell.Utility.psm1'), $utilityBody, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $managementRoot 'Microsoft.PowerShell.Management.psd1'), $managementManifest, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $managementRoot 'Microsoft.PowerShell.Management.psm1'), $managementBody, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $cimRoot 'CimCmdlets.psd1'), $cimManifest, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $cimRoot 'CimCmdlets.psm1'), $cimBody, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $coreRoot 'Microsoft.PowerShell.Core.psd1'), $coreManifest, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $coreRoot 'Microsoft.PowerShell.Core.psm1'), $coreBody, [Text.UTF8Encoding]::new($false))

    $pwshBytes = [IO.File]::ReadAllBytes($pwshImage)
    $pwshSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($pwshBytes)).ToLowerInvariant()
    $profileDocument = [ordered]@{
        schema_version = 2
        profile_type = 'D32_BUILD_TOOLCHAIN_PROFILE_V2'
        powershell_root = [IO.Path]::GetFullPath($PSHOME)
        powershell = [ordered]@{
            name = 'pwsh.exe'
            path = $pwshImage
            sha256 = $pwshSha256
            bytes = [Int64]$pwshBytes.LongLength
        }
    }
    $profilePath = Join-Path $testRoot 'caller-profile-fixture.json'
    $profileJson = ConvertTo-Json -InputObject $profileDocument -Depth 6 -Compress
    $profileBytes = [Text.UTF8Encoding]::new($false).GetBytes($profileJson)
    [IO.File]::WriteAllBytes($profilePath, $profileBytes)
    $profileSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($profileBytes)).ToLowerInvariant()

    $probeRoot = Join-Path $testRoot 'evidence-root-NOT-CREATED'
    $zeroSha40 = '0' * 40
    $zeroSha64 = '0' * 64
    $dummyGit = Join-Path $testRoot 'git-NOT-CREATED.exe'
    $dummyAuthority = Join-Path $testRoot 'authority-NOT-CREATED.json'
    $requiredArguments = @(
        '-Repository', $repository,
        '-EvidenceRoot', $probeRoot,
        '-ExpectedCandidateSha', $zeroSha40,
        '-ToolchainProfilePath', $profilePath,
        '-ExpectedToolchainProfileSha256', $profileSha256,
        '-PinnedGitPath', $dummyGit,
        '-PinnedGitSha256', $zeroSha64,
        '-TauriMacrosSourceAuthorityPath', $dummyAuthority,
        '-ExpectedTauriMacrosSourceAuthoritySha256', $zeroSha64,
        '-VendoredProtocAuthorityPath', $dummyAuthority,
        '-ExpectedVendoredProtocAuthoritySha256', $zeroSha64
    )
    $ambientModulePath = $ambientRoot + [IO.Path]::PathSeparator + [IO.Path]::Combine($PSHOME, 'Modules')
    $loaderMarker = Join-Path $testRoot 'loader-marker-NOT-CREATED'
    $discoveryMarker = Join-Path $testRoot 'discovery-marker-NOT-CREATED'
    $badPinMarker = Join-Path $testRoot 'bad-pin-marker-NOT-CREATED'
    $baselineMarker = Join-Path $testRoot 'baseline-marker-NOT-CREATED'
    $phase0Marker = Join-Path $testRoot 'phase0-marker-NOT-CREATED'
    $phase0LibraryMarker = Join-Path $testRoot 'phase0-library-marker-NOT-CREATED'
    $preflightLibraryMarker = Join-Path $testRoot 'preflight-library-marker-NOT-CREATED'
    $preflightMarker = Join-Path $testRoot 'preflight-marker-NOT-CREATED'

    $loader = Invoke-D32DiscoveryLoaderChild -RunnerScript $discoveryScript -Arguments ($requiredArguments + @('-LoaderSelfTest')) `
        -PSModulePathOverride $ambientModulePath -MarkerPath $loaderMarker
    $loaderOutput = $loader.StdOut + $loader.StdErr
    if ($loader.ExitCode -ne 0 -or $loaderOutput -notmatch 'D32_TEST_INVENTORY_DISCOVERY_LOADER=PASS' -or
        $loaderOutput -notmatch 'discovery_admission=PAST_IMPORT' -or
        $loaderOutput -notmatch 'powershell_module_authority=EXACT_PSHOME_MODULES_NO_AUTOLOAD' -or
        $loaderOutput -notmatch 'cargo_invocations=0' -or $loaderOutput -notmatch 'evidence_root_claimed=false' -or
        (Test-Path -LiteralPath $loaderMarker)) {
        throw "SELFTEST_FAILED: fresh loader did not isolate ambient modules (exit=$($loader.ExitCode), marker=$([IO.File]::Exists($loaderMarker))): $loaderOutput"
    }

    # This real runner path has a valid caller pin for the PowerShell runtime but
    # intentionally omits required discovery timeouts; it must stop before root/Cargo.
    $admission = Invoke-D32DiscoveryLoaderChild -RunnerScript $discoveryScript -Arguments $requiredArguments `
        -PSModulePathOverride $ambientModulePath -MarkerPath $discoveryMarker
    $admissionOutput = $admission.StdOut + $admission.StdErr
    if ($admission.ExitCode -eq 0 -or $admissionOutput -notmatch 'TEST_INVENTORY_DISCOVERY_BLOCKED: caller must explicitly pin -Phase0TimeoutSeconds' -or
        (Test-Path -LiteralPath $discoveryMarker) -or (Test-Path -LiteralPath $probeRoot)) {
        throw "SELFTEST_FAILED: discovery did not isolate modules and stop at caller-pin admission (exit=$($admission.ExitCode), marker=$([IO.File]::Exists($discoveryMarker))): $admissionOutput"
    }

    $badPinArguments = @($requiredArguments)
    $shaIndex = [Array]::IndexOf([object[]]$badPinArguments, '-ExpectedToolchainProfileSha256')
    if ($shaIndex -lt 0) { throw 'SELFTEST_BLOCKED: caller profile SHA argument was not found' }
    $badPinArguments[$shaIndex + 1] = $zeroSha64
    $badPin = Invoke-D32DiscoveryLoaderChild -RunnerScript $discoveryScript -Arguments $badPinArguments `
        -PSModulePathOverride $ambientModulePath -MarkerPath $badPinMarker
    $badPinOutput = $badPin.StdOut + $badPin.StdErr
    if ($badPin.ExitCode -eq 0 -or $badPinOutput -notmatch 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: caller Profile V2 bytes do not match its pinned SHA' -or
        (Test-Path -LiteralPath $badPinMarker) -or (Test-Path -LiteralPath $probeRoot)) {
        throw "SELFTEST_FAILED: invalid caller Profile V2 pin was not rejected before module initialization (exit=$($badPin.ExitCode), marker=$([IO.File]::Exists($badPinMarker))): $badPinOutput"
    }

    $baselineArguments = @(
        '-Repository', $repository,
        '-ExpectedCandidateSha', 'not-an-exact-sha',
        '-DiscoveryPath', (Join-Path $testRoot 'discovery-NOT-CREATED.json'),
        '-ExpectedDiscoverySha256', $zeroSha64,
        '-ToolchainProfilePath', $profilePath,
        '-ExpectedToolchainProfileSha256', $profileSha256,
        '-PinnedGitPath', $dummyGit,
        '-PinnedGitSha256', $zeroSha64,
        '-BaselineOutputPath', (Join-Path $testRoot 'baseline-NOT-CREATED.json')
    )
    $baseline = Invoke-D32DiscoveryLoaderChild -RunnerScript $baselineScript -Arguments $baselineArguments `
        -PSModulePathOverride $ambientModulePath -MarkerPath $baselineMarker
    $baselineOutput = $baseline.StdOut + $baseline.StdErr
    if ($baseline.ExitCode -eq 0 -or $baselineOutput -notmatch 'TEST_INVENTORY_BASELINE_BLOCKED: exact lowercase candidate/Profile/Git/discovery caller pins are required' -or
        (Test-Path -LiteralPath $baselineMarker) -or (Test-Path -LiteralPath (Join-Path $testRoot 'baseline-NOT-CREATED.json'))) {
        throw "SELFTEST_FAILED: baseline builder did not isolate modules and stop at caller-pin admission (exit=$($baseline.ExitCode), marker=$([IO.File]::Exists($baselineMarker))): $baselineOutput"
    }

    $phase0Library = Invoke-D32DiscoveryLoaderChild -RunnerScript $phase0Script -Arguments @('-Phase0LibraryOnly') `
        -PSModulePathOverride $ambientModulePath -MarkerPath $phase0LibraryMarker
    $phase0LibraryOutput = $phase0Library.StdOut + $phase0Library.StdErr
    if ($phase0Library.ExitCode -eq 0 -or $phase0LibraryOutput -notmatch 'caller-pinned Profile V2 path and SHA are required before module loading' -or
        (Test-Path -LiteralPath $phase0LibraryMarker)) {
        throw "SELFTEST_FAILED: standalone Phase0 library-only mode bypassed caller Profile admission (exit=$($phase0Library.ExitCode), marker=$([IO.File]::Exists($phase0LibraryMarker))): $phase0LibraryOutput"
    }

    $preflightLibrary = Invoke-D32DiscoveryLoaderChild -RunnerScript $preflightScript -Arguments @('-LibraryOnly') `
        -PSModulePathOverride $ambientModulePath -MarkerPath $preflightLibraryMarker
    $preflightLibraryOutput = $preflightLibrary.StdOut + $preflightLibrary.StdErr
    if ($preflightLibrary.ExitCode -eq 0 -or $preflightLibraryOutput -notmatch 'caller-pinned Profile V2 path and SHA are required before module loading' -or
        (Test-Path -LiteralPath $preflightLibraryMarker)) {
        throw "SELFTEST_FAILED: standalone preflight library-only mode bypassed caller Profile admission (exit=$($preflightLibrary.ExitCode), marker=$([IO.File]::Exists($preflightLibraryMarker))): $preflightLibraryOutput"
    }

    $phase0 = Invoke-D32DiscoveryLoaderChild -RunnerScript $phase0Script -Arguments @('-Phase0SelfTest') `
        -PSModulePathOverride $ambientModulePath -MarkerPath $phase0Marker
    $phase0Output = $phase0.StdOut + $phase0.StdErr
    if ($phase0.ExitCode -ne 0 -or $phase0Output -notmatch 'D32 Phase0 runner SelfTest: PASS \(171 assertions\)' -or
        (Test-Path -LiteralPath $phase0Marker)) {
        throw "SELFTEST_FAILED: Phase0 preflight dependency path loaded an ambient module or its no-Cargo SelfTest failed (exit=$($phase0.ExitCode), marker=$([IO.File]::Exists($phase0Marker))): $phase0Output"
    }

    $preflight = Invoke-D32DiscoveryLoaderChild -RunnerScript $preflightScript -Arguments @('-SelfTest') `
        -PSModulePathOverride $ambientModulePath -MarkerPath $preflightMarker
    $preflightOutput = $preflight.StdOut + $preflight.StdErr
    if ($preflight.ExitCode -ne 2 -or $preflightOutput -notmatch 'D32 preflight self-test: BLOCKED' -or
        $preflightOutput -notmatch 'caller-pinned toolchain-profile path/SHA are mandatory' -or
        (Test-Path -LiteralPath $preflightMarker)) {
        throw "SELFTEST_FAILED: standalone preflight loader did not isolate ambient modules before the required caller-pin stop (exit=$($preflight.ExitCode), marker=$([IO.File]::Exists($preflightMarker))): $preflightOutput"
    }

    Write-Output 'D32 discovery loader self-test: PASS'
    Write-Output 'ambient_module_name_spoofing=Microsoft.PowerShell.Core,Microsoft.PowerShell.Management,Microsoft.PowerShell.Utility,CimCmdlets; initialization=0'
    Write-Output 'caller_profile_pin_checked_before_module_initialization=PASS'
    Write-Output 'discovery_and_baseline_admission_after_pinned_import=PASS'
    Write-Output 'standalone_library_only_modes_require_caller_profile=PASS (Phase0 and preflight; ambient marker=0)'
    Write-Output 'phase0_preflight_dependency_guard=PASS (171 assertions; ambient marker=0)'
    Write-Output 'standalone_preflight_loader=PASS (unavailable caller pins stopped self-test before authority use; ambient marker=0)'
    Write-Output 'powershell_module_authority=EXACT_PSHOME_MODULES_NO_AUTOLOAD'
    Write-Output 'cargo_invocations=0'
    Write-Output 'evidence_root_claimed=false'
    Write-Output "custom_function_dependencies=$(([regex]::Match($loaderOutput, 'custom_function_dependencies=(\d+)')).Groups[1].Value)"
    Write-Output "cmdlet_modules=$(([regex]::Match($loaderOutput, 'cmdlet_modules=([^\r\n]*)')).Groups[1].Value)"
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        if (-not (Test-D32PowerShellAuthorityPathNoReparse -Path $testRoot) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($testRoot)), $tempBase)) {
            throw 'SELFTEST_BLOCKED: temporary module-authority cleanup target no longer resolves to its exact regular child'
        }
        [IO.Directory]::Delete($testRoot, $true)
    }
}
