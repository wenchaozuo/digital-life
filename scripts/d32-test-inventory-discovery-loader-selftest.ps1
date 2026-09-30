#Requires -Version 7.5
[CmdletBinding()]
param()

. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
$global:PSModuleAutoLoadingPreference = 'None'
$env:PSModulePath = [IO.Path]::GetFullPath([IO.Path]::Combine([string]$PSHOME, 'Modules'))
$global:D32PowerShellModuleImportAttempts = 0
$global:D32PowerShellModuleAuthorityState = $null
$runner = [IO.Path]::GetFullPath($PSCommandPath)
$null = Get-D32PowerShellAuthorityProcessStartup -EntryScriptPath $runner
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$testCount = 0
$failures = [System.Collections.Generic.List[string]]::new()
function Assert-D32ModuleFreeSelfTest {
    param([bool]$Condition, [string]$Name)
    $script:testCount++
    if (-not $Condition) { $script:failures.Add($Name) }
}
function Get-D32ExpectedModuleFreeRejection {
    param([scriptblock]$Action)
    try { & $Action; return '' }
    catch { return [string]$_.Exception.Message }
}

$validArguments = [string[]]@('pwsh.exe','-NoLogo','-NoProfile','-NonInteractive','-File',$runner)
$startup = Get-D32PowerShellAuthorityProcessStartup -EntryScriptPath $runner -ArgumentVector $validArguments
Assert-D32ModuleFreeSelfTest -Condition ([StringComparer]::OrdinalIgnoreCase.Equals($startup.FileOperand, $runner) -and $startup.Switches.Count -eq 3) -Name 'finite direct NoProfile -File startup is accepted'

$badStartupCases = @(
    [PSCustomObject]@{ Name = 'ConfigurationFile'; Args = [string[]]@('pwsh.exe','-NoProfile','-ConfigurationFile','evil.pssc','-File',$runner) },
    [PSCustomObject]@{ Name = 'Command'; Args = [string[]]@('pwsh.exe','-NoProfile','-Command','Import-Module evil') },
    [PSCustomObject]@{ Name = 'EncodedCommand'; Args = [string[]]@('pwsh.exe','-NoProfile','-EncodedCommand','SQBFAFgA') },
    [PSCustomObject]@{ Name = 'CommandWithArgs'; Args = [string[]]@('pwsh.exe','-NoProfile','-CommandWithArgs','Import-Module evil') },
    [PSCustomObject]@{ Name = 'ambiguous switch'; Args = [string[]]@('pwsh.exe','-NoProfile','-c','Import-Module evil','-File',$runner) },
    [PSCustomObject]@{ Name = 'wrong File operand'; Args = [string[]]@('pwsh.exe','-NoProfile','-File',[IO.Path]::Combine($PSScriptRoot,'d32-preflight.ps1')) },
    [PSCustomObject]@{ Name = 'missing NoProfile'; Args = [string[]]@('pwsh.exe','-File',$runner) },
    [PSCustomObject]@{ Name = 'duplicate NoProfile'; Args = [string[]]@('pwsh.exe','-NoProfile','-NoProfile','-File',$runner) }
)
foreach ($case in $badStartupCases) {
    $message = Get-D32ExpectedModuleFreeRejection { Get-D32PowerShellAuthorityProcessStartup -EntryScriptPath $runner -ArgumentVector $case.Args }
    Assert-D32ModuleFreeSelfTest -Condition ($message -like 'POWERSHELL_MODULE_AUTHORITY_BLOCKED:*' -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name "startup rejects $($case.Name) before module import"
}

$fixtureSource = [IO.File]::ReadAllText([IO.Path]::Combine($PSScriptRoot, 'd32-fixture-prebuild.ps1'))
$fixtureTokens = $null
$fixtureParseErrors = $null
$fixtureAst = [System.Management.Automation.Language.Parser]::ParseInput($fixtureSource, [ref]$fixtureTokens, [ref]$fixtureParseErrors)
$fixtureAdmissionCalls = @($fixtureAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Test-D32PowerShellModuleAdmissionRecord' }, $true))
$fixtureProducerAdmissionBound = $false
foreach ($call in $fixtureAdmissionCalls) {
    $elements = @($call.CommandElements | ForEach-Object { $_.Extent.Text })
    if ($elements -contains '-ExpectedContext' -and ($elements -join ' ') -match '\$global:D32PowerShellModuleAuthorityState\.Admission') {
        $fixtureProducerAdmissionBound = $true
        break
    }
}
Assert-D32ModuleFreeSelfTest -Condition ($fixtureParseErrors.Count -eq 0 -and $fixtureProducerAdmissionBound -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'fixture provenance reader binds its embedded admission to this producer context before import'
$authorityGeneratorSource = [IO.File]::ReadAllText([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority-create.ps1'))
$authorityGeneratorTokens = $null
$authorityGeneratorParseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput($authorityGeneratorSource, [ref]$authorityGeneratorTokens, [ref]$authorityGeneratorParseErrors)
Assert-D32ModuleFreeSelfTest -Condition ($authorityGeneratorParseErrors.Count -eq 0 -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'module-free authority generator source parses without executing it'

$missingPinCases = @(
    [PSCustomObject]@{ Name = 'ordinary runner'; SelfTest = $false },
    [PSCustomObject]@{ Name = 'SelfTest'; SelfTest = $true },
    [PSCustomObject]@{ Name = 'LoaderSelfTest'; SelfTest = $true },
    [PSCustomObject]@{ Name = 'LibraryOnly'; SelfTest = $false }
)
foreach ($case in $missingPinCases) {
    $global:D32PowerShellModuleImportAttempts = 0
    $message = Get-D32ExpectedModuleFreeRejection {
        Initialize-D32PowerShellModuleAuthority -EntryScriptPath $runner -LocalSelfTestOnly:$case.SelfTest
    }
    Assert-D32ModuleFreeSelfTest -Condition ($message -like 'POWERSHELL_MODULE_AUTHORITY_BLOCKED:*' -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name "$($case.Name) without independent pins records import_attempts=0"
}

$savedState = $global:D32PowerShellModuleAuthorityState
try {
    $global:D32PowerShellModuleAuthorityState = [PSCustomObject]@{ Admission = [PSCustomObject]@{ candidate_sha = ('a' * 40) }; ImportAttempts = 0 }
    $global:D32PowerShellModuleImportAttempts = 0
    $message = Get-D32ExpectedModuleFreeRejection { Initialize-D32PowerShellModuleAuthority -EntryScriptPath $runner }
    Assert-D32ModuleFreeSelfTest -Condition ($message -like 'POWERSHELL_MODULE_AUTHORITY_BLOCKED:*' -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'forged or stale global library-reuse state is rejected with zero imports'
}
finally { $global:D32PowerShellModuleAuthorityState = $savedState }

$duplicateJson = [System.Text.Json.JsonDocument]::Parse('{"schema_version":1,"schema_version":1}')
try { $duplicateDetected = Test-D32PowerShellAuthorityJsonDuplicates -Element $duplicateJson.RootElement }
finally { $duplicateJson.Dispose() }
Assert-D32ModuleFreeSelfTest -Condition ($duplicateDetected -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'module-free authority validator detects duplicate JSON keys'
$exactFieldsJson = [System.Text.Json.JsonDocument]::Parse('{"a":1,"b":2}')
$extraFieldsJson = [System.Text.Json.JsonDocument]::Parse('{"a":1,"b":2,"c":3}')
$missingFieldsJson = [System.Text.Json.JsonDocument]::Parse('{"a":1}')
try {
    $exactFieldsAccepted = Test-D32PowerShellAuthorityJsonFields -Element $exactFieldsJson.RootElement -Expected @('a','b')
    $extraFieldsRejected = -not (Test-D32PowerShellAuthorityJsonFields -Element $extraFieldsJson.RootElement -Expected @('a','b'))
    $missingFieldsRejected = -not (Test-D32PowerShellAuthorityJsonFields -Element $missingFieldsJson.RootElement -Expected @('a','b'))
}
finally { $exactFieldsJson.Dispose(); $extraFieldsJson.Dispose(); $missingFieldsJson.Dispose() }
Assert-D32ModuleFreeSelfTest -Condition ($exactFieldsAccepted -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'strict JSON field validator accepts an exact record field set'
Assert-D32ModuleFreeSelfTest -Condition ($extraFieldsRejected -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'strict JSON field validator rejects unknown fields'
Assert-D32ModuleFreeSelfTest -Condition ($missingFieldsRejected -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'strict JSON field validator rejects missing fields'
$componentJson = [System.Text.Json.JsonDocument]::Parse('{"role":"windows","root":{"file_id":"0011","version":"10.0"},"bytes":2,"files":["a.dll","b.dll"]}')
$matchingComponent = [ordered]@{ role = 'windows'; root = [ordered]@{ file_id = '0011'; version = '10.0' }; bytes = [Int64]2; files = @('a.dll','b.dll') }
$driftedComponent = [ordered]@{ role = 'windows'; root = [ordered]@{ file_id = '0022'; version = '10.0' }; bytes = [Int64]2; files = @('a.dll','b.dll') }
try {
    $componentDeepMatch = Test-D32PowerShellAuthorityJsonMatchesObject -Element $componentJson.RootElement -Value $matchingComponent
    $componentDriftRejected = -not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $componentJson.RootElement -Value $driftedComponent)
}
finally { $componentJson.Dispose() }
Assert-D32ModuleFreeSelfTest -Condition ($componentDeepMatch -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'deep Windows component authority comparison accepts exact nested records before import'
Assert-D32ModuleFreeSelfTest -Condition ($componentDriftRejected -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'deep Windows component authority comparison rejects nested object identity drift before import'

$manifestBytes = [Text.UTF8Encoding]::new($false).GetBytes("@{ RootModule = 'Exact.dll'; NestedModules = @('Nested.dll'); RequiredAssemblies = @('Required.dll') }")
$manifest = Get-D32PowerShellAuthorityManifestData -Bytes $manifestBytes -ModuleName 'Synthetic'
Assert-D32ModuleFreeSelfTest -Condition ($manifest.RootModule -ceq 'Exact.dll' -and $manifest.NestedModules.Count -eq 1 -and $manifest.RequiredAssemblies.Count -eq 1 -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'module-free literal-manifest parser binds exact root/nested/required-assembly relationships'
$manifestNegativeCases = @(
    [PSCustomObject]@{ Name = 'dynamic expression'; Text = "@{ RootModule = (Get-Date).ToString() }" },
    [PSCustomObject]@{ Name = 'ModuleToProcess alias'; Text = "@{ ModuleToProcess = 'Legacy.psm1' }" },
    [PSCustomObject]@{ Name = 'wildcard dependency'; Text = "@{ NestedModules = @('*.dll') }" },
    [PSCustomObject]@{ Name = 'nonempty module prefix'; Text = "@{ Prefix = 'Shadow'; RootModule = 'Exact.dll' }" }
)
foreach ($case in $manifestNegativeCases) {
    $manifestRejected = $false
    try { $null = Get-D32PowerShellAuthorityManifestData -Bytes ([Text.UTF8Encoding]::new($false).GetBytes([string]$case.Text)) -ModuleName 'Synthetic' }
    catch { $manifestRejected = $_.Exception.Message -like 'POWERSHELL_MODULE_AUTHORITY_BLOCKED:*' }
    Assert-D32ModuleFreeSelfTest -Condition ($manifestRejected -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name "module-free manifest parser rejects $($case.Name) before import"
}

$legacyAdmission = [ordered]@{ record_type = 'D32_POWERSHELL_MODULE_ADMISSION_V1'; schema_version = 1 }
$v2MissingProofAdmission = [ordered]@{ record_type = 'D32_POWERSHELL_MODULE_ADMISSION_V2'; schema_version = 2 }
Assert-D32ModuleFreeSelfTest -Condition (-not (Test-D32PowerShellModuleAdmissionRecord -Document $legacyAdmission -CandidateSha ('a' * 40) -Repository $PSScriptRoot) -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'prior shared admission V1 is rejected with zero imports'
Assert-D32ModuleFreeSelfTest -Condition (-not (Test-D32PowerShellModuleAdmissionRecord -Document $v2MissingProofAdmission -CandidateSha ('a' * 40) -Repository $PSScriptRoot) -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'V2 admission missing resolver/content fields is rejected with zero imports'
$v2ExtraFieldAdmission = [ordered]@{ record_type = 'D32_POWERSHELL_MODULE_ADMISSION_V2'; schema_version = 2; unrecognized = $true }
$v2WrongVersionAdmission = [ordered]@{ record_type = 'D32_POWERSHELL_MODULE_ADMISSION_V2'; schema_version = '2' }
Assert-D32ModuleFreeSelfTest -Condition (-not (Test-D32PowerShellModuleAdmissionRecord -Document $v2ExtraFieldAdmission -CandidateSha ('a' * 40) -Repository $PSScriptRoot) -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'V2 admission unknown fields are rejected with zero imports'
Assert-D32ModuleFreeSelfTest -Condition (-not (Test-D32PowerShellModuleAdmissionRecord -Document $v2WrongVersionAdmission -CandidateSha ('a' * 40) -Repository $PSScriptRoot) -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'V2 admission wrong schema-version type is rejected with zero imports'

$safeTokenRecord = Get-D32PowerShellAuthorityCurrentToken
Assert-D32ModuleFreeSelfTest -Condition ((Test-D32PowerShellAuthorityTokenRecord -Token $safeTokenRecord) -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'current runner process token is non-elevated, non-system, below high integrity, and not impersonating'
foreach ($unsafeToken in @(
    [ordered]@{ is_elevated = $true; integrity_rid = 0x2000; is_system = $false; thread_impersonating = $false },
    [ordered]@{ is_elevated = $false; integrity_rid = 0x3000; is_system = $false; thread_impersonating = $false },
    [ordered]@{ is_elevated = $false; integrity_rid = 0x2000; is_system = $true; thread_impersonating = $false },
    [ordered]@{ is_elevated = $false; integrity_rid = 0x2000; is_system = $false; thread_impersonating = $true }
)) {
    Assert-D32ModuleFreeSelfTest -Condition ((-not (Test-D32PowerShellAuthorityTokenRecord -Token $unsafeToken)) -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'synthetic elevated/high-integrity/system/impersonated process token is rejected before import'
}

$pshomeImage = [IO.Path]::GetFullPath([IO.Path]::Combine([string]$PSHOME, 'pwsh.exe'))
$syntheticOsComponents = @(
    [ordered]@{ component_type = 'MICROSOFT_WINDOWS_OS_INSTALLATION'; inventory_sha256 = ('a' * 64); native_files = @(); distribution = [ordered]@{ directories = @() } },
    [ordered]@{ component_type = 'MICROSOFT_WINDOWS_DEFENDER_PLATFORM'; inventory_sha256 = ('b' * 64); native_files = @(); distribution = [ordered]@{ directories = @() } }
)
$syntheticOsDigest = Get-D32PowerShellAuthorityOsSecurityInventoryDigest -Components $syntheticOsComponents
Assert-D32ModuleFreeSelfTest -Condition ($syntheticOsDigest -match '^[0-9a-f]{64}$' -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'fixed OS and Defender component inventory digest is deterministic-shape and module-free'
$reorderedOsComponents = @($syntheticOsComponents[1], $syntheticOsComponents[0])
$missingOsComponentRejected = $false
$wrongOsRoleRejected = $false
$wrongOsOrderRejected = $false
try { $null = Get-D32PowerShellAuthorityOsSecurityInventoryDigest -Components @($syntheticOsComponents[0]) }
catch { $missingOsComponentRejected = $_.Exception.Message -like 'POWERSHELL_MODULE_AUTHORITY_BLOCKED:*' }
$wrongOsRoleComponents = @([ordered]@{ component_type = 'MICROSOFT_WINDOWS_OS_INSTALLATION'; inventory_sha256 = ('a' * 64) }, [ordered]@{ component_type = 'MICROSOFT_WINDOWS_OS_INSTALLATION'; inventory_sha256 = ('b' * 64) })
try { $null = Get-D32PowerShellAuthorityOsSecurityInventoryDigest -Components $wrongOsRoleComponents }
catch { $wrongOsRoleRejected = $_.Exception.Message -like 'POWERSHELL_MODULE_AUTHORITY_BLOCKED:*' }
try { $null = Get-D32PowerShellAuthorityOsSecurityInventoryDigest -Components $reorderedOsComponents }
catch { $wrongOsOrderRejected = $_.Exception.Message -like 'POWERSHELL_MODULE_AUTHORITY_BLOCKED:*' }
Assert-D32ModuleFreeSelfTest -Condition ($missingOsComponentRejected -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'OS security digest rejects a missing finite component role before import'
Assert-D32ModuleFreeSelfTest -Condition ($wrongOsRoleRejected -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'OS security digest rejects duplicate/spoofed component roles before import'
Assert-D32ModuleFreeSelfTest -Condition ($wrongOsOrderRejected -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'OS security digest rejects an order-swapped component list before import'
$syntheticResolverArgs = @{
    NativeModulePaths = @($pshomeImage)
    ManagedAssemblyPaths = @($pshomeImage)
    TrustedPlatformAssemblyPaths = @($pshomeImage)
    DepsFilePaths = @($pshomeImage)
    NativeDirectoryPaths = @([IO.Path]::GetFullPath([string]$PSHOME))
    OsSecurityComponents = $syntheticOsComponents
    OsSecurityInventorySha256 = $syntheticOsDigest
}
$safeSyntheticResolver = Get-D32PowerShellAuthorityResolverSnapshot @syntheticResolverArgs
$safeConfiguredResolver = Get-D32PowerShellAuthorityResolverSnapshot @syntheticResolverArgs -ConfigureNativeSearch
$unsafeNativeResolver = Get-D32PowerShellAuthorityResolverSnapshot -NativeModulePaths @($pshomeImage, 'C:\Program Files (x86)\RivaTuner Statistics Server\RTSSHooks64.dll') -ManagedAssemblyPaths @($pshomeImage) -TrustedPlatformAssemblyPaths @($pshomeImage) -DepsFilePaths @($pshomeImage) -NativeDirectoryPaths @([IO.Path]::GetFullPath([string]$PSHOME)) -OsSecurityComponents $syntheticOsComponents -OsSecurityInventorySha256 $syntheticOsDigest
$unsafeWindowsResolver = Get-D32PowerShellAuthorityResolverSnapshot -NativeModulePaths @($pshomeImage, 'C:\WINDOWS\System32\untrusted-resolver.dll') -ManagedAssemblyPaths @($pshomeImage) -TrustedPlatformAssemblyPaths @($pshomeImage) -DepsFilePaths @($pshomeImage) -NativeDirectoryPaths @([IO.Path]::GetFullPath([string]$PSHOME)) -OsSecurityComponents $syntheticOsComponents -OsSecurityInventorySha256 $syntheticOsDigest
$unsafeDefenderResolver = Get-D32PowerShellAuthorityResolverSnapshot -NativeModulePaths @($pshomeImage, 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\untrusted-resolver.dll') -ManagedAssemblyPaths @($pshomeImage) -TrustedPlatformAssemblyPaths @($pshomeImage) -DepsFilePaths @($pshomeImage) -NativeDirectoryPaths @([IO.Path]::GetFullPath([string]$PSHOME)) -OsSecurityComponents $syntheticOsComponents -OsSecurityInventorySha256 $syntheticOsDigest
$unsafeManagedResolver = Get-D32PowerShellAuthorityResolverSnapshot -NativeModulePaths @($pshomeImage) -ManagedAssemblyPaths @($pshomeImage, 'C:\Users\Public\untrusted\resolver.dll') -TrustedPlatformAssemblyPaths @($pshomeImage) -DepsFilePaths @($pshomeImage) -NativeDirectoryPaths @([IO.Path]::GetFullPath([string]$PSHOME)) -OsSecurityComponents $syntheticOsComponents -OsSecurityInventorySha256 $syntheticOsDigest
$nativeEscapeDetected = $false
foreach ($blocker in $unsafeNativeResolver.Blockers) { if ($blocker -like '*no exact caller-pinned OS component file reference*RTSSHooks64.dll') { $nativeEscapeDetected = $true } }
$windowsComponentEscapeDetected = $false
foreach ($blocker in $unsafeWindowsResolver.Blockers) { if ($blocker -like '*no exact caller-pinned OS component file reference*untrusted-resolver.dll') { $windowsComponentEscapeDetected = $true } }
$defenderComponentEscapeDetected = $false
foreach ($blocker in $unsafeDefenderResolver.Blockers) { if ($blocker -like '*no exact caller-pinned OS component file reference*untrusted-resolver.dll') { $defenderComponentEscapeDetected = $true } }
$managedEscapeDetected = $false
foreach ($blocker in $unsafeManagedResolver.Blockers) { if ($blocker -like '*managed assembly/deps resolver input is not an exact admitted*untrusted*') { $managedEscapeDetected = $true } }
Assert-D32ModuleFreeSelfTest -Condition ($safeSyntheticResolver.Blockers.Count -eq 0 -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'synthetic resolver domain accepts only pinned PSHOME entries before import'
Assert-D32ModuleFreeSelfTest -Condition ($safeConfiguredResolver.Blockers.Count -eq 0 -and $safeConfiguredResolver.NativePolicy -ceq 'LOAD_LIBRARY_SEARCH_APPLICATION_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32; SetDllDirectoryW(NULL); verified in current process' -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'process-local DLL search is configured with documented application/System32 roots before import'
Assert-D32ModuleFreeSelfTest -Condition ($nativeEscapeDetected -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'synthetic third-party native preload blocks before import with zero attempts'
Assert-D32ModuleFreeSelfTest -Condition ($windowsComponentEscapeDetected -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'SystemRoot path alone cannot authorize an unpinned native image before import'
Assert-D32ModuleFreeSelfTest -Condition ($defenderComponentEscapeDetected -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'Defender package name/path alone cannot authorize an unpinned image before import'
Assert-D32ModuleFreeSelfTest -Condition ($managedEscapeDetected -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'synthetic external managed resolver path blocks before import with zero attempts'
$savedModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', [EnvironmentVariableTarget]::Process)
try {
    [Environment]::SetEnvironmentVariable('PSModulePath', 'C:\Users\Public\untrusted-modules', [EnvironmentVariableTarget]::Process)
    $ambientModuleResolver = Get-D32PowerShellAuthorityResolverSnapshot @syntheticResolverArgs
}
finally { [Environment]::SetEnvironmentVariable('PSModulePath', $savedModulePath, [EnvironmentVariableTarget]::Process) }
Assert-D32ModuleFreeSelfTest -Condition (@($ambientModuleResolver.Blockers | Where-Object { $_ -ceq 'process PSModulePath is not the exact pinned PSHOME Modules directory' }).Count -eq 1 -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'synthetic ambient PSModulePath is rejected before import'
$savedStartupHook = [Environment]::GetEnvironmentVariable('DOTNET_STARTUP_HOOKS', [EnvironmentVariableTarget]::Process)
try {
    [Environment]::SetEnvironmentVariable('DOTNET_STARTUP_HOOKS', 'C:\Users\Public\untrusted\hook.dll', [EnvironmentVariableTarget]::Process)
    $startupInjectionResolver = Get-D32PowerShellAuthorityResolverSnapshot @syntheticResolverArgs
}
finally { [Environment]::SetEnvironmentVariable('DOTNET_STARTUP_HOOKS', $savedStartupHook, [EnvironmentVariableTarget]::Process) }
Assert-D32ModuleFreeSelfTest -Condition (@($startupInjectionResolver.Blockers | Where-Object { $_ -like '*startup environment injection is active: DOTNET_STARTUP_HOOKS*' }).Count -eq 1 -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'synthetic .NET startup-hook injection is rejected before import'

$trustedSecurity = [Security.AccessControl.FileSecurity]::new()
$trustedSecurity.SetSecurityDescriptorSddlForm('O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)')
$trustedAcl = [PSCustomObject]@{ OwnerSid = [string]$trustedSecurity.GetOwner([Security.Principal.SecurityIdentifier]).Value; Security = $trustedSecurity }
$untrustedSecurity = [Security.AccessControl.FileSecurity]::new()
$untrustedSecurity.SetSecurityDescriptorSddlForm('O:SYG:SYD:(A;;FA;;;WD)')
$untrustedAcl = [PSCustomObject]@{ OwnerSid = [string]$untrustedSecurity.GetOwner([Security.Principal.SecurityIdentifier]).Value; Security = $untrustedSecurity }
$untrustedOwnerSecurity = [Security.AccessControl.FileSecurity]::new()
$untrustedOwnerSecurity.SetSecurityDescriptorSddlForm('O:WDG:SYD:(A;;FA;;;SY)')
$untrustedOwnerAcl = [PSCustomObject]@{ OwnerSid = [string]$untrustedOwnerSecurity.GetOwner([Security.Principal.SecurityIdentifier]).Value; Security = $untrustedOwnerSecurity }
$nullDaclSecurity = [Security.AccessControl.FileSecurity]::new()
$nullDaclSetup = $false
$nullDaclRejected = $false
try {
    $nullDaclSecurity.SetSecurityDescriptorSddlForm('O:SYG:SYD:NO_ACCESS_CONTROL')
    $nullDaclSetup = $true
    $nullDaclRejected = -not (Test-D32PowerShellAuthorityProtectedSecurity -Security ([PSCustomObject]@{ OwnerSid = 'S-1-5-18'; Security = $nullDaclSecurity }) -IsDirectory:$false)
}
catch { }
$trustedAclAccepted = Test-D32PowerShellAuthorityProtectedSecurity -Security $trustedAcl -IsDirectory:$false
Assert-D32ModuleFreeSelfTest -Condition ($trustedAclAccepted -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'synthetic protected ACL allows only trusted writer SIDs'
Assert-D32ModuleFreeSelfTest -Condition ((-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $untrustedAcl -IsDirectory:$false)) -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'synthetic untrusted write ACE fails closed'
Assert-D32ModuleFreeSelfTest -Condition ((-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $untrustedOwnerAcl -IsDirectory:$false)) -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'synthetic untrusted owner fails closed'
Assert-D32ModuleFreeSelfTest -Condition ($nullDaclSetup -and $nullDaclRejected -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'null or absent DACL is rejected before import'
$programDataSafeSecurity = [Security.AccessControl.DirectorySecurity]::new()
$programDataSafeSecurity.SetSecurityDescriptorSddlForm('O:SYG:SYD:(A;;0x12019f;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)')
$programDataSafeAcl = [PSCustomObject]@{ Path = 'C:\ProgramData'; OwnerSid = [string]$programDataSafeSecurity.GetOwner([Security.Principal.SecurityIdentifier]).Value; Security = $programDataSafeSecurity }
$programDataRedirectSecurity = [Security.AccessControl.DirectorySecurity]::new()
$programDataRedirectSecurity.SetSecurityDescriptorSddlForm('O:SYG:SYD:(A;;0x12019f;;;WD)(A;;0x40;;;WD)(A;;FA;;;SY)')
$programDataRedirectAcl = [PSCustomObject]@{ Path = 'C:\ProgramData'; OwnerSid = [string]$programDataRedirectSecurity.GetOwner([Security.Principal.SecurityIdentifier]).Value; Security = $programDataRedirectSecurity }
$programDataWrongPathAcl = [PSCustomObject]@{ Path = 'C:\Users\Public'; OwnerSid = [string]$programDataSafeSecurity.GetOwner([Security.Principal.SecurityIdentifier]).Value; Security = $programDataSafeSecurity }
$programDataAclAccepted = Test-D32PowerShellAuthorityProtectedSecurity -Security $programDataSafeAcl -IsDirectory:$true -IsProgramDataAncestor
Assert-D32ModuleFreeSelfTest -Condition ($programDataAclAccepted -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'known ProgramData ancestor permits only unrelated-child and metadata rights'
Assert-D32ModuleFreeSelfTest -Condition ((-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $programDataRedirectAcl -IsDirectory:$true -IsProgramDataAncestor)) -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'ProgramData delete-child right blocks namespace redirection proof'
Assert-D32ModuleFreeSelfTest -Condition ((-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $programDataWrongPathAcl -IsDirectory:$true -IsProgramDataAncestor)) -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'ProgramData rights exception cannot be applied to another ancestor'
$programDataMicrosoftSecurity = [Security.AccessControl.DirectorySecurity]::new()
$programDataMicrosoftSecurity.SetSecurityDescriptorSddlForm('O:SYG:SYD:PAI(A;OICI;0x1200a9;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
$programDataMicrosoftAcl = [PSCustomObject]@{ Path = 'C:\ProgramData\Microsoft'; OwnerSid = [string]$programDataMicrosoftSecurity.GetOwner([Security.Principal.SecurityIdentifier]).Value; Security = $programDataMicrosoftSecurity }
$programDataMicrosoftUnprotected = [Security.AccessControl.DirectorySecurity]::new()
$programDataMicrosoftUnprotected.SetSecurityDescriptorSddlForm('O:SYG:SYD:AI(A;OICI;0x1200a9;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
$programDataMicrosoftUnprotectedAcl = [PSCustomObject]@{ Path = 'C:\ProgramData\Microsoft'; OwnerSid = [string]$programDataMicrosoftUnprotected.GetOwner([Security.Principal.SecurityIdentifier]).Value; Security = $programDataMicrosoftUnprotected }
Assert-D32ModuleFreeSelfTest -Condition ((Test-D32PowerShellAuthorityProtectedSecurity -Security $programDataMicrosoftAcl -IsDirectory:$true) -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'the exact SYSTEM-owned ProgramData Microsoft child requires a protected ACL and safe descriptor'
Assert-D32ModuleFreeSelfTest -Condition ((-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $programDataMicrosoftUnprotectedAcl -IsDirectory:$true)) -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name 'an unprotected ProgramData Microsoft child cannot prove no redirection'
$aclWriteRights = @(
    [Security.AccessControl.FileSystemRights]::WriteData,
    [Security.AccessControl.FileSystemRights]::AppendData,
    [Security.AccessControl.FileSystemRights]::CreateDirectories,
    [Security.AccessControl.FileSystemRights]::Delete,
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
    [Security.AccessControl.FileSystemRights]::ChangePermissions,
    [Security.AccessControl.FileSystemRights]::TakeOwnership
)
foreach ($rights in $aclWriteRights) {
    $syntheticSecurity = [Security.AccessControl.FileSecurity]::new()
    $syntheticSecurity.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
    $syntheticSecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'), [Security.AccessControl.FileSystemRights]$rights, [Security.AccessControl.AccessControlType]::Allow))
    $syntheticAcl = [PSCustomObject]@{ OwnerSid = [string]$syntheticSecurity.GetOwner([Security.Principal.SecurityIdentifier]).Value; Security = $syntheticSecurity }
    Assert-D32ModuleFreeSelfTest -Condition ((-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $syntheticAcl -IsDirectory:$true)) -and $global:D32PowerShellModuleImportAttempts -eq 0) -Name "synthetic untrusted namespace write right $rights is rejected"
}

$liveResolver = Get-D32PowerShellAuthorityResolverSnapshot
Assert-D32ModuleFreeSelfTest -Condition ($global:D32PowerShellModuleImportAttempts -eq 0) -Name 'live resolver census is module-free and records zero import attempts'
if ($liveResolver.Blockers.Count -gt 0) {
    [Console]::WriteLine(('MODULE_FREE_RESOLVER_CENSUS BLOCKED before imports: {0}' -f ($liveResolver.Blockers -join '; ')))
}
else {
    [Console]::WriteLine('MODULE_FREE_RESOLVER_CENSUS contains no observed escape; this is not a module-admission result')
}

if ($failures.Count -gt 0) {
    [Console]::Error.WriteLine(('D32 discovery loader selftest FAILED: {0} failures; import_attempts={1}' -f $failures.Count, $global:D32PowerShellModuleImportAttempts))
    foreach ($failure in $failures) { [Console]::Error.WriteLine(('SELFTEST FAIL: ' + $failure)) }
    exit 1
}
[Console]::WriteLine(('D32 discovery loader selftest PASS: {0} checks; import_attempts={1}; Cargo=0; root=false' -f $testCount, $global:D32PowerShellModuleImportAttempts))
