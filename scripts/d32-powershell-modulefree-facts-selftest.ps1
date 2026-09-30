# Focused no-Cargo checks for module-free facts generation and reviewed fixes.
[CmdletBinding()]
param([switch]$PrepareCurrentCandidates)

$repo = [IO.Path]::GetFullPath([IO.Path]::Combine($PSScriptRoot, '..'))
$pwsh = [IO.Path]::GetFullPath([IO.Path]::Combine([string]$PSHOME, 'pwsh.exe'))
. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, 'd32-build-toolchain-profile.ps1'))
$global:PSModuleAutoLoadingPreference = 'None'
$env:PSModulePath = [IO.Path]::GetFullPath([IO.Path]::Combine([string]$PSHOME, 'Modules'))
$global:D32PowerShellModuleImportAttempts = 0
$moduleSetAtStart = Get-D32PowerShellAuthorityLoadedModuleSet
$null = Get-D32PowerShellAuthorityProcessStartup -EntryScriptPath $PSCommandPath
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$cases = [System.Collections.Generic.List[object]]::new()
$ownedFiles = [System.Collections.Generic.List[string]]::new()
$failures = [System.Collections.Generic.List[string]]::new()
$testId = [Guid]::NewGuid().ToString('N')
$scratch = 'E:\d32'
if (-not [IO.Directory]::Exists($scratch) -or -not (Test-D32PowerShellAuthorityPathNoReparse -Path $scratch)) { throw 'MODULEFREE_SELFTEST_BLOCKED: E:\d32 must already exist and be non-reparse' }

function Add-D32FactsSelfTestCase {
    param([string]$Name, [bool]$Passed, [AllowNull()][string]$Detail = $null)
    $cases.Add([PSCustomObject]@{ name = $Name; passed = $Passed; detail = $Detail })
    if (-not $Passed) { $failures.Add($Name) }
}

function Write-D32FactsSelfTestFile {
    param([string]$Path, [string]$Text)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    $ownedFiles.Add($Path)
}

function New-D32FactsSelfTestAuthorityFileReference {
    param([string]$Path)
    $canonical = [IO.Path]::GetFullPath($Path)
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($canonical))).ToLowerInvariant()
    return [PSCustomObject]@{
        path = $canonical; bytes = [Int64]1; sha256 = $hash
        volume_serial_hex = '0000000000000001'; file_id_hex = $hash.Substring(0, 32)
        owner_sid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'; security_descriptor_sha256 = ('b' * 64)
    }
}

function New-D32FactsSelfTestResolverSnapshotOverride {
    param([object]$Snapshot, [System.Collections.IDictionary]$Overrides)
    $copy = [ordered]@{}
    foreach ($property in $Snapshot.PSObject.Properties) { $copy[[string]$property.Name] = $property.Value }
    foreach ($key in $Overrides.Keys) { $copy[[string]$key] = $Overrides[$key] }
    return [PSCustomObject]$copy
}

function Invoke-D32FactsSelfTestChild {
    param([string[]]$Arguments, [int]$TimeoutSeconds = 300)
    $start = [Diagnostics.ProcessStartInfo]::new($pwsh)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    foreach ($argument in $Arguments) { [void]$start.ArgumentList.Add([string]$argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw 'MODULEFREE_SELFTEST_BLOCKED: direct pinned pwsh child failed to start' }
    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill($true) } catch { }
            $process.WaitForExit()
            throw "MODULEFREE_SELFTEST_TIMEOUT: direct child exceeded ${TimeoutSeconds}s"
        }
        return [PSCustomObject]@{ ExitCode = $process.ExitCode; Stdout = $stdoutTask.GetAwaiter().GetResult(); Stderr = $stderrTask.GetAwaiter().GetResult() }
    }
    finally { $process.Dispose() }
}

function New-D32FactsSelfTestSecurity {
    param([string]$Path, [string]$OwnerSid, [int64]$EveryoneRights, [bool]$Protected = $true, [switch]$FileObject)
    $security = if ($FileObject) { [Security.AccessControl.FileSecurity]::new() } else { [Security.AccessControl.DirectorySecurity]::new() }
    $security.SetAccessRuleProtection($Protected, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new($OwnerSid))
    $everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($everyone, [Security.AccessControl.FileSystemRights]$EveryoneRights, [Security.AccessControl.AccessControlType]::Allow)
    $security.AddAccessRule($rule)
    return [PSCustomObject]@{ Path = $Path; OwnerSid = $OwnerSid; Sddl = ''; AclSha256 = ''; Security = $security }
}

function New-D32FactsSelfTestNullAclSecurity {
    param([ValidateSet('NullDacl','MissingDacl')][string]$Kind)
    $flags = [Security.AccessControl.ControlFlags]::SelfRelative
    if ($Kind -ceq 'NullDacl') { $flags = $flags -bor [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent }
    $owner = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $group = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($flags, $owner, $group, $null, $null)
    $bytes = [byte[]]::new($raw.BinaryLength)
    $raw.GetBinaryForm($bytes, 0)
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorBinaryForm($bytes)
    return $security
}

function Test-D32FactsSelfTestJsonEqual {
    param([System.Text.Json.JsonElement]$Left, [System.Text.Json.JsonElement]$Right)
    if ($Left.ValueKind -ne $Right.ValueKind) { return $false }
    switch ($Left.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Object) {
            $leftProperties = [System.Collections.Generic.List[System.Text.Json.JsonProperty]]::new()
            foreach ($property in $Left.EnumerateObject()) { $leftProperties.Add($property) }
            $rightCount = 0
            foreach ($property in $Right.EnumerateObject()) { $rightCount++ }
            if ($leftProperties.Count -ne $rightCount) { return $false }
            foreach ($property in $leftProperties) {
                $other = [System.Text.Json.JsonElement]::new()
                if (-not $Right.TryGetProperty($property.Name, [ref]$other) -or -not (Test-D32FactsSelfTestJsonEqual -Left $property.Value -Right $other)) { return $false }
            }
            return $true
        }
        ([System.Text.Json.JsonValueKind]::Array) {
            if ($Left.GetArrayLength() -ne $Right.GetArrayLength()) { return $false }
            for ($index = 0; $index -lt $Left.GetArrayLength(); $index++) {
                if (-not (Test-D32FactsSelfTestJsonEqual -Left $Left[$index] -Right $Right[$index])) { return $false }
            }
            return $true
        }
        ([System.Text.Json.JsonValueKind]::String) { return $Left.GetString() -ceq $Right.GetString() }
        ([System.Text.Json.JsonValueKind]::Number) {
            $leftNumber = [Int64]0; $rightNumber = [Int64]0
            return $Left.TryGetInt64([ref]$leftNumber) -and $Right.TryGetInt64([ref]$rightNumber) -and $leftNumber -eq $rightNumber
        }
        ([System.Text.Json.JsonValueKind]::True) { return $true }
        ([System.Text.Json.JsonValueKind]::False) { return $true }
        ([System.Text.Json.JsonValueKind]::Null) { return $true }
        default { return $false }
    }
}

try {
    $singletonArrayJson = [System.Text.Json.JsonDocument]::Parse('{"distribution":{"protected_ancestors":[{"path":"C:\\","depth":0}]}}')
    try {
        $singletonArrayCandidate = [ordered]@{ distribution = [ordered]@{ protected_ancestors = @([ordered]@{ path = 'C:\'; depth = [int64]0 }) } }
        $singletonObjectCandidate = [ordered]@{ distribution = [ordered]@{ protected_ancestors = [ordered]@{ path = 'C:\'; depth = [int64]0 } } }
        $singletonArrayAccepted = Test-D32PowerShellAuthorityJsonMatchesObject -Element $singletonArrayJson.RootElement -Value $singletonArrayCandidate
        $singletonObjectRejected = -not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $singletonArrayJson.RootElement -Value $singletonObjectCandidate)
        Add-D32FactsSelfTestCase 'strict authority JSON comparison preserves nested singleton arrays and rejects object substitution' `
            ($singletonArrayAccepted -and $singletonObjectRejected -and $global:D32PowerShellModuleImportAttempts -eq 0) `
            'A one-element protected_ancestors array must remain an array through recursive comparison; this test is module-free.'
    }
    finally { $singletonArrayJson.Dispose() }

    $helperPath = [IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1')
    $helperText = [IO.File]::ReadAllText($helperPath, [Text.UTF8Encoding]::new($false, $true))
    $assertStart = $helperText.IndexOf('function Assert-D32PowerShellModuleAdmissionCurrent', [StringComparison]::Ordinal)
    $helperInitializeStart = $helperText.IndexOf('function Initialize-D32PowerShellModuleAuthority', [StringComparison]::Ordinal)
    $helperFirstImport = $helperText.IndexOf('Import-Module', $helperInitializeStart, [StringComparison]::Ordinal)
    $originWrite = $helperText.IndexOf('$State.Admission.import_verification.commands = @($commandOrigins.Values)', $assertStart, [StringComparison]::Ordinal)
    $strictRecordCheck = $helperText.IndexOf('Test-D32PowerShellModuleAdmissionRecord -Document $State.Admission', $assertStart, [StringComparison]::Ordinal)
    $originShape = $helperText.IndexOf('effective_module_name = [string]$effective.Module.Name; effective_module_path = [string]$effective.Module.Path', $assertStart, [StringComparison]::Ordinal)
    $exportLoop = $helperText.IndexOf('foreach ($command in $match[0].ExportedCommands.Values)', $assertStart, [StringComparison]::Ordinal)
    $effectiveLookup = $helperText.IndexOf('Microsoft.PowerShell.Core\Get-Command -Name ([string]$command.Name) -All', $assertStart, [StringComparison]::Ordinal)
    $originMap = $helperText.IndexOf('$commandOrigins[$key] = [ordered]@{', $assertStart, [StringComparison]::Ordinal)
    $moduleOriginShape = $helperText.IndexOf('module_name = $moduleName; command_name = [string]$command.Name; module_path = [string]$command.Module.Path', $assertStart, [StringComparison]::Ordinal)
    Add-D32FactsSelfTestCase 'admission command origins are derived from actual loaded module exports and assigned before strict record validation' `
        ($assertStart -ge 0 -and $exportLoop -gt $assertStart -and $effectiveLookup -gt $exportLoop -and $originMap -gt $effectiveLookup -and
         $moduleOriginShape -gt $originMap -and $originShape -gt $moduleOriginShape -and $originWrite -gt $originShape -and $strictRecordCheck -gt $originWrite) `
        'Static source-lifecycle assertion verifies the record is projected from admitted ExportedCommands and actual Get-Command resolution; positive three-module runtime origins still require newly pinned authority and are intentionally UNVERIFIED.'

    $initializePostSnapshot = $helperText.IndexOf('$postImportResolver = Get-D32PowerShellAuthorityResolverSnapshot', $helperInitializeStart, [StringComparison]::Ordinal)
    $initializeTransition = $helperText.IndexOf('Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $resolverState -After $postImportResolver', $helperInitializeStart, [StringComparison]::Ordinal)
    $initializeAdmission = $helperText.IndexOf('$admission = [PSCustomObject][ordered]@{', $initializeTransition, [StringComparison]::Ordinal)
    $initializePostDigest = $helperText.IndexOf('resolver_sha256 = [string]$postImportResolver.ResolverSha256', $initializeAdmission, [StringComparison]::Ordinal)
    $initializeOriginEvidence = $helperText.IndexOf('Get-D32PowerShellAuthorityNativeOriginEvidence -ResolverSnapshot $postImportResolver', $initializePostDigest, [StringComparison]::Ordinal)
    $initializeAssertCurrent = $helperText.IndexOf('Assert-D32PowerShellModuleAdmissionCurrent -State $state', $initializeOriginEvidence, [StringComparison]::Ordinal)
    $assertCurrentStart = $helperText.IndexOf('function Assert-D32PowerShellModuleAdmissionCurrent', [StringComparison]::Ordinal)
    $reusePriorSnapshot = $helperText.IndexOf('Get-D32PowerShellAuthorityResolverSnapshotFromAdmission -Admission $State.Admission', $assertCurrentStart, [StringComparison]::Ordinal)
    $reuseCurrentSnapshot = $helperText.IndexOf('$currentResolver = Get-D32PowerShellAuthorityResolverSnapshot', $reusePriorSnapshot, [StringComparison]::Ordinal)
    $reuseTransition = $helperText.IndexOf('Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $priorResolver -After $currentResolver', $reuseCurrentSnapshot, [StringComparison]::Ordinal)
    $reuseUpdate = $helperText.IndexOf('Update-D32PowerShellAuthorityAdmissionResolverSnapshot -Admission $State.Admission', $reuseTransition, [StringComparison]::Ordinal)
    $reuseModuleCheck = $helperText.IndexOf('foreach ($info in $moduleInfos)', $reuseUpdate, [StringComparison]::Ordinal)
    $reuseCommandOrigins = $helperText.IndexOf('foreach ($command in $match[0].ExportedCommands.Values)', $reuseModuleCheck, [StringComparison]::Ordinal)
    $digestRoleProof = $helperText.IndexOf('Get-D32PowerShellAuthorityResolverDigestSet -ModuleSearchPath', $helperText.IndexOf('function Test-D32PowerShellModuleAdmissionRecord', [StringComparison]::Ordinal), [StringComparison]::Ordinal)
    $reuseStrictCheck = $helperText.IndexOf('Test-D32PowerShellModuleAdmissionRecord -Document $State.Admission', $reuseCommandOrigins, [StringComparison]::Ordinal)
    $reuseBranchStart = $helperText.IndexOf('if ($null -ne $priorState)', $helperInitializeStart, [StringComparison]::Ordinal)
    $reuseCallerPins = $helperText.IndexOf('all caller-owned authority, Profile, Git, candidate, repository, and library-entry pins are required for reuse', $reuseBranchStart, [StringComparison]::Ordinal)
    $reuseAssertPrior = $helperText.IndexOf('Assert-D32PowerShellModuleAdmissionCurrent -State $priorState', $reuseCallerPins, [StringComparison]::Ordinal)
    $crossProcessBinding = $helperText.IndexOf('return $null -ne $Document -and [Int64]$Document.runner_process.process_id -eq $ExpectedProcessId', [StringComparison]::Ordinal)
    $expectedContextLifecycleBinding = $helperText.IndexOf("foreach (`$field in @('authority_reference','profile_reference','git_image','powershell_host','module_import_order','module_closure','resolver_admission','import_verification','import_attempts'))", [StringComparison]::Ordinal)
    $currentProcessIdentityCheck = $helperText.IndexOf('$process.StartTime.ToUniversalTime().Ticks -ne [Int64]$State.Admission.runner_process.start_time_utc_ticks', $assertCurrentStart, [StringComparison]::Ordinal)
    $producerFiles = @('d32-preflight.ps1','d32-phase0-matrix.ps1','d32-phase0-vendored-authority.ps1','d32-fixture-prebuild.ps1','d32-debug-trace-load-selftest.ps1','d32-tauri-macros-source-attestation.ps1','d32-test-inventory-baseline.ps1','d32-test-inventory-discovery.ps1')
    $producersBound = $true
    foreach ($producerName in $producerFiles) {
        $producerPath = [IO.Path]::Combine($PSScriptRoot, $producerName)
        if (-not [IO.File]::Exists($producerPath) -or -not [IO.File]::ReadAllText($producerPath, [Text.UTF8Encoding]::new($false, $true)).Contains('Initialize-D32PowerShellModuleAuthority')) { $producersBound = $false }
    }
    $consumerFiles = @('d32-preflight.ps1','d32-phase0-matrix.ps1','d32-fixture-prebuild.ps1','d32-test-inventory-authority.ps1')
    $consumersBound = $true
    foreach ($consumerName in $consumerFiles) {
        $consumerPath = [IO.Path]::Combine($PSScriptRoot, $consumerName)
        $consumerText = if ([IO.File]::Exists($consumerPath)) { [IO.File]::ReadAllText($consumerPath, [Text.UTF8Encoding]::new($false, $true)) } else { '' }
        if (-not $consumerText.Contains('Test-D32PowerShellModuleAdmissionRecord') -or -not $consumerText.Contains('-ExpectedContext')) { $consumersBound = $false }
    }
    $runnerConsumersBound = $true
    foreach ($consumerName in @('d32-preflight.ps1','d32-phase0-matrix.ps1')) {
        $consumerPath = [IO.Path]::Combine($PSScriptRoot, $consumerName)
        $consumerText = if ([IO.File]::Exists($consumerPath)) { [IO.File]::ReadAllText($consumerPath, [Text.UTF8Encoding]::new($false, $true)) } else { '' }
        if (-not $consumerText.Contains('Test-D32PowerShellModuleAdmissionRunnerBinding') -or -not $consumerText.Contains('Test-D32PowerShellModuleAdmissionProfileRecordBinding')) { $runnerConsumersBound = $false }
    }
    $phase0Source = [IO.File]::ReadAllText([IO.Path]::Combine($PSScriptRoot, 'd32-phase0-matrix.ps1'), [Text.UTF8Encoding]::new($false, $true))
    $fixtureRunnerEvidenceBound = $phase0Source.Contains('-ExpectedRunnerProcessId ([int]$document.runner_process_id)') -and $phase0Source.Contains('Test-D32Phase0FixtureBuildProvenance')
    $startupRecordFixture = [ordered]@{ file_operand = 'C:\d32-synthetic-entry.ps1'; switches = @('-NoProfile','-NonInteractive'); startup_policy = 'DIRECT_NO_PROFILE_FILE_V1' }
    $startupStateFixture = [PSCustomObject]@{ FileOperand = [string]$startupRecordFixture.file_operand; Switches = [string[]]@($startupRecordFixture.switches) }
    $startupStateRecordBound = $helperText.Contains('Startup = [PSCustomObject]@{ FileOperand = [string]$admission.startup.file_operand; Switches = [string[]]@($admission.startup.switches) }') -and
        -not $helperText.Contains('Startup = $admission.startup') -and
        $startupStateFixture.FileOperand -ceq $startupRecordFixture.file_operand -and $startupStateFixture.Switches.Count -eq 2 -and
        [StringComparer]::Ordinal.Equals($startupStateFixture.Switches[0], [string]$startupRecordFixture.switches[0]) -and
        [StringComparer]::Ordinal.Equals($startupStateFixture.Switches[1], [string]$startupRecordFixture.switches[1])
    Add-D32FactsSelfTestCase 'internal reuse state maps the strict snake-case startup record into the typed startup binding' `
        $startupStateRecordBound 'AdmissionV2 stores startup.file_operand/startup.switches; the reuse helper consumes typed FileOperand/Switches.'
    Add-D32FactsSelfTestCase 'three-import admission uses post-import actual origins, typed resolver digest, pinned reuse, actual command provenance, and cross-process consumer binding' `
        ($helperInitializeStart -ge 0 -and $helperFirstImport -gt $helperInitializeStart -and $initializePostSnapshot -gt $helperFirstImport -and $initializeTransition -gt $initializePostSnapshot -and $initializeAdmission -gt $initializeTransition -and
         $initializePostDigest -gt $initializeAdmission -and $initializeOriginEvidence -gt $initializePostDigest -and $initializeAssertCurrent -gt $initializeOriginEvidence -and
         $reusePriorSnapshot -gt $assertCurrentStart -and $reuseCurrentSnapshot -gt $reusePriorSnapshot -and $reuseTransition -gt $reuseCurrentSnapshot -and
         $reuseUpdate -gt $reuseTransition -and $reuseModuleCheck -gt $reuseUpdate -and $reuseCommandOrigins -gt $reuseModuleCheck -and $reuseStrictCheck -gt $reuseCommandOrigins -and
         $reuseCallerPins -gt $reuseBranchStart -and $reuseAssertPrior -gt $reuseCallerPins -and $digestRoleProof -gt 0 -and $crossProcessBinding -gt 0 -and
         $expectedContextLifecycleBinding -gt 0 -and $currentProcessIdentityCheck -gt $assertCurrentStart -and $producersBound -and $consumersBound -and $runnerConsumersBound -and $fixtureRunnerEvidenceBound -and
         $global:D32PowerShellModuleImportAttempts -eq 0) `
        ("initialize=$initializePostSnapshot/$initializeTransition/$initializeAdmission/$initializePostDigest/$initializeOriginEvidence/$initializeAssertCurrent; reuse=$reusePriorSnapshot/$reuseCurrentSnapshot/$reuseTransition/$reuseUpdate/$reuseCommandOrigins/$reuseStrictCheck; digest=$digestRoleProof; process=$crossProcessBinding/$expectedContextLifecycleBinding/$currentProcessIdentityCheck; producers=$producersBound; consumers=$consumersBound; runner_consumers=$runnerConsumersBound; fixture_trace=$fixtureRunnerEvidenceBound; import_attempts=0")

    $everyoneCreateDirectory = [int64][Security.AccessControl.FileSystemRights]::CreateDirectories
    $programDataSafe = [int64][Security.AccessControl.FileSystemRights]::CreateFiles -bor [int64][Security.AccessControl.FileSystemRights]::CreateDirectories -bor `
        [int64][Security.AccessControl.FileSystemRights]::WriteAttributes -bor [int64][Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
    $actualVolumeRoot = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath([string]$PSHOME))
    $windowsAncestor = New-D32FactsSelfTestSecurity -Path ([IO.Path]::Combine($actualVolumeRoot, 'Windows')) -OwnerSid 'S-1-5-18' -EveryoneRights $everyoneCreateDirectory
    Add-D32FactsSelfTestCase 'untrusted directory creation on a non-ProgramData OS ancestor is denied' `
        (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $windowsAncestor -IsDirectory:$true -IsProtectedAncestor))
    $trustedVolumeRoot = New-D32FactsSelfTestSecurity -Path $actualVolumeRoot -OwnerSid 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' -EveryoneRights $everyoneCreateDirectory
    Add-D32FactsSelfTestCase 'only the exact TrustedInstaller-owned current volume root permits unrelated child-directory creation' `
        (Test-D32PowerShellAuthorityProtectedSecurity -Security $trustedVolumeRoot -IsDirectory:$true -IsProtectedAncestor)
    $openedRootBinding = (Test-D32PowerShellAuthorityPathWithin -Child ([IO.Path]::GetFullPath([string]$PSHOME)) -Parent ([string]$trustedVolumeRoot.Path)) -and
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$PSHOME), [string]$trustedVolumeRoot.Path) -and
        $trustedVolumeRoot.Path -ceq [IO.Path]::GetFullPath([string]$trustedVolumeRoot.Path) -and
        $trustedVolumeRoot.OwnerSid -ceq 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' -and
        $trustedVolumeRoot.Security.AreAccessRulesProtected
    Add-D32FactsSelfTestCase 'root exception is bound to the exact local PSHOME volume-root path, owner and protected descriptor' $openedRootBinding
    $otherVolumeRoot = New-D32FactsSelfTestSecurity -Path 'E:\' -OwnerSid 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' -EveryoneRights $everyoneCreateDirectory
    Add-D32FactsSelfTestCase 'volume-root exception does not extend to another drive' `
        (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $otherVolumeRoot -IsDirectory:$true -IsProtectedAncestor))
    $rootNotAncestor = Test-D32PowerShellAuthorityProtectedSecurity -Security $trustedVolumeRoot -IsDirectory:$true
    Add-D32FactsSelfTestCase 'volume-root right is not accepted when the opened object is not an ancestor of PSHOME' (-not $rootNotAncestor)
    $nestedAncestor = New-D32FactsSelfTestSecurity -Path 'C:\Temp' -OwnerSid 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' -EveryoneRights $everyoneCreateDirectory
    Add-D32FactsSelfTestCase 'the volume-root exception does not extend to an arbitrary nested ancestor' `
        (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $nestedAncestor -IsDirectory:$true -IsProtectedAncestor))
    $nestedWindowsAncestor = New-D32FactsSelfTestSecurity -Path ([IO.Path]::Combine($actualVolumeRoot, 'Windows', 'System32')) -OwnerSid 'S-1-5-18' -EveryoneRights $everyoneCreateDirectory
    Add-D32FactsSelfTestCase 'volume-root exception does not extend to C:\Windows or nested OS ancestors' `
        ((-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $windowsAncestor -IsDirectory:$true -IsProtectedAncestor)) -and
         (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $nestedWindowsAncestor -IsDirectory:$true -IsProtectedAncestor)))
    $volumeRootFileCreate = New-D32FactsSelfTestSecurity -Path $actualVolumeRoot -OwnerSid 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' -EveryoneRights $everyoneCreateDirectory -FileObject
    Add-D32FactsSelfTestCase 'directory-only ACL exception fails when object classification is file' `
        (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $volumeRootFileCreate -IsDirectory:$false -IsProtectedAncestor))
    $volumeRootCreateFile = New-D32FactsSelfTestSecurity -Path $actualVolumeRoot -OwnerSid 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' -EveryoneRights ([int64][Security.AccessControl.FileSystemRights]::CreateFiles)
    Add-D32FactsSelfTestCase 'volume-root exception does not permit file creation (0x2)' `
        (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $volumeRootCreateFile -IsDirectory:$true -IsProtectedAncestor))
    $volumeRootUntrustedRights = @(
        [Security.AccessControl.FileSystemRights]::WriteAttributes,
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes,
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
        [Security.AccessControl.FileSystemRights]::Delete,
        [Security.AccessControl.FileSystemRights]::ChangePermissions,
        [Security.AccessControl.FileSystemRights]::TakeOwnership,
        [Security.AccessControl.FileSystemRights]::FullControl
    )
    $volumeRootOtherRightsDenied = $true
    foreach ($right in $volumeRootUntrustedRights) {
        $badRoot = New-D32FactsSelfTestSecurity -Path $actualVolumeRoot -OwnerSid 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' -EveryoneRights ([int64]$right)
        if (Test-D32PowerShellAuthorityProtectedSecurity -Security $badRoot -IsDirectory:$true -IsProtectedAncestor) { $volumeRootOtherRightsDenied = $false }
    }
    Add-D32FactsSelfTestCase 'volume-root exception rejects metadata, delete-child/delete, DACL/owner and generic/full writes' $volumeRootOtherRightsDenied
    $adminVolumeRoot = New-D32FactsSelfTestSecurity -Path $actualVolumeRoot -OwnerSid 'S-1-5-32-544' -EveryoneRights $everyoneCreateDirectory
    Add-D32FactsSelfTestCase 'Administrator-owned volume root cannot use the exact TrustedInstaller exception' `
        (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $adminVolumeRoot -IsDirectory:$true -IsProtectedAncestor))
    $unprotectedVolumeRoot = New-D32FactsSelfTestSecurity -Path $actualVolumeRoot -OwnerSid 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' -EveryoneRights $everyoneCreateDirectory -Protected:$false
    Add-D32FactsSelfTestCase 'an unprotected volume-root ACL cannot use the narrow unrelated-child exception' `
        (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $unprotectedVolumeRoot -IsDirectory:$true -IsProtectedAncestor))
    Add-D32FactsSelfTestCase 'missing volume-root security descriptor fails closed' `
        (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security ([PSCustomObject]@{ Path = $actualVolumeRoot; OwnerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'; Security = $null }) -IsDirectory:$true -IsProtectedAncestor))
    foreach ($aclKind in @('NullDacl','MissingDacl')) {
        $nullAclRoot = [PSCustomObject]@{ Path = $actualVolumeRoot; OwnerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'; Security = (New-D32FactsSelfTestNullAclSecurity -Kind $aclKind) }
        Add-D32FactsSelfTestCase "volume-root $aclKind descriptor is rejected" `
            (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $nullAclRoot -IsDirectory:$true -IsProtectedAncestor))
    }
    $adminProgramData = New-D32FactsSelfTestSecurity -Path 'C:\ProgramData' -OwnerSid 'S-1-5-32-544' -EveryoneRights $everyoneCreateDirectory
    Add-D32FactsSelfTestCase 'Administrator-owned exact ProgramData does not qualify for the SYSTEM-only exception' `
        (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $adminProgramData -IsDirectory:$true -IsProtectedAncestor -IsProgramDataAncestor))
    $systemProgramData = New-D32FactsSelfTestSecurity -Path 'C:\ProgramData' -OwnerSid 'S-1-5-18' -EveryoneRights $programDataSafe
    Add-D32FactsSelfTestCase 'SYSTEM-owned exact ProgramData permits only the documented unrelated-child/metadata additions' `
        (Test-D32PowerShellAuthorityProtectedSecurity -Security $systemProgramData -IsDirectory:$true -IsProtectedAncestor -IsProgramDataAncestor)
    $unprotectedProgramData = New-D32FactsSelfTestSecurity -Path 'C:\ProgramData' -OwnerSid 'S-1-5-18' -EveryoneRights $programDataSafe -Protected:$false
    Add-D32FactsSelfTestCase 'ProgramData contract remains independent and does not require its own DACL protection flag' `
        (Test-D32PowerShellAuthorityProtectedSecurity -Security $unprotectedProgramData -IsDirectory:$true -IsProtectedAncestor -IsProgramDataAncestor)
    $programDataDeleteChild = New-D32FactsSelfTestSecurity -Path 'C:\ProgramData' -OwnerSid 'S-1-5-18' -EveryoneRights ([int64][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles)
    Add-D32FactsSelfTestCase 'ProgramData delete-child remains denied under its separate exception' `
        (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $programDataDeleteChild -IsDirectory:$true -IsProtectedAncestor -IsProgramDataAncestor))
    $programDataRootRuleBypass = Test-D32PowerShellAuthorityProtectedSecurity -Security $systemProgramData -IsDirectory:$true -IsProtectedAncestor
    Add-D32FactsSelfTestCase 'the volume-root allowance does not bypass ProgramData rights policy' (-not $programDataRootRuleBypass)
    $protectedMicrosoft = New-D32FactsSelfTestSecurity -Path 'C:\ProgramData\Microsoft' -OwnerSid 'S-1-5-18' -EveryoneRights ([int64][Security.AccessControl.FileSystemRights]::ReadAndExecute)
    Add-D32FactsSelfTestCase 'protected Microsoft child with no untrusted mutation rights remains admissible' `
        (Test-D32PowerShellAuthorityProtectedSecurity -Security $protectedMicrosoft -IsDirectory:$true -IsProtectedAncestor)
    $unprotectedMicrosoft = New-D32FactsSelfTestSecurity -Path 'C:\ProgramData\Microsoft' -OwnerSid 'S-1-5-18' -EveryoneRights ([int64][Security.AccessControl.FileSystemRights]::ReadAndExecute) -Protected:$false
    Add-D32FactsSelfTestCase 'unprotected Microsoft child is denied even when ProgramData itself is accepted' `
        (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $unprotectedMicrosoft -IsDirectory:$true -IsProtectedAncestor))
    $writableMicrosoft = New-D32FactsSelfTestSecurity -Path 'C:\ProgramData\Microsoft' -OwnerSid 'S-1-5-18' -EveryoneRights ([int64][Security.AccessControl.FileSystemRights]::CreateDirectories)
    Add-D32FactsSelfTestCase 'Microsoft child cannot carry inherited or explicit untrusted creation rights' `
        (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $writableMicrosoft -IsDirectory:$true -IsProtectedAncestor))

    $sourceText = [IO.File]::ReadAllText($helperPath, [Text.UTF8Encoding]::new($false, $true))
    $chainStart = $sourceText.IndexOf('function Add-D32PowerShellAuthorityDirectoryChain', [StringComparison]::Ordinal)
    $chainFence = $sourceText.IndexOf('Open-D32PowerShellAuthorityDirectoryFence -Path $key', $chainStart, [StringComparison]::Ordinal)
    $openFenceStart = $sourceText.IndexOf('function Open-D32PowerShellAuthorityDirectoryFence', [StringComparison]::Ordinal)
    $openedDirectoryType = $sourceText.IndexOf('($identity.Attributes -band [int][IO.FileAttributes]::Directory) -eq 0', $openFenceStart, [StringComparison]::Ordinal)
    $openedReparseReject = $sourceText.IndexOf('($identity.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0', $openFenceStart, [StringComparison]::Ordinal)
    $snapshotStart = $sourceText.IndexOf('function Get-D32PowerShellAuthorityRuntimeDistributionSnapshot', [StringComparison]::Ordinal)
    $rootAncestorRecord = $sourceText.IndexOf('$ancestorRecords.Add([ordered]@{ kind = ''ancestor''; path = [string]$fence.Path; volume_serial_hex = [string]$fence.VolumeSerialHex; file_id_hex = [string]$fence.FileIdHex; owner_sid = [string]$fence.OwnerSid; security_descriptor_sddl = [string]$fence.Sddl; security_descriptor_sha256 = [string]$fence.AclSha256 })', $snapshotStart, [StringComparison]::Ordinal)
    $resolverStart = $sourceText.IndexOf('function Get-D32PowerShellAuthorityResolverSnapshot', [StringComparison]::Ordinal)
    $resolverOutsideReject = $sourceText.IndexOf('native resolver directory is not an exact protected PowerShell or Windows namespace', $resolverStart, [StringComparison]::Ordinal)
    $resolverPolicyStart = $sourceText.IndexOf('function Assert-D32PowerShellAuthorityResolverPolicyRecord', [StringComparison]::Ordinal)
    $resolverForbidden = $sourceText.IndexOf("@('CWD','PATH','USER_PSMODULEPATH','STARTUP_HOOKS','EXTERNAL_ASSEMBLIES','UNPINNED_DLL_DIRECTORIES')", $resolverPolicyStart, [StringComparison]::Ordinal)
    $importStart = $sourceText.IndexOf('function Initialize-D32PowerShellModuleAuthority', [StringComparison]::Ordinal)
    $snapshotBeforeImport = $sourceText.IndexOf('Assert-D32PowerShellAuthorityRuntimeSnapshotCurrent -Snapshot $runtimeDistribution', $importStart, [StringComparison]::Ordinal)
    $resolverBeforeImport = $sourceText.IndexOf('Get-D32PowerShellAuthorityResolverSnapshot -OsSecurityComponents $osSecurity.Components', $importStart, [StringComparison]::Ordinal)
    $firstImport = $sourceText.IndexOf('Import-Module', $importStart, [StringComparison]::Ordinal)
    $currentSnapshotStart = $sourceText.IndexOf('function Assert-D32PowerShellAuthorityRuntimeSnapshotCurrent', [StringComparison]::Ordinal)
    $identityDriftCheck = $sourceText.IndexOf('$identity.FileIdHex -cne [string]$directory.file_id_hex', $currentSnapshotStart, [StringComparison]::Ordinal)
    $descriptorDriftCheck = $sourceText.IndexOf('$security.AclSha256 -cne [string]$directory.security_descriptor_sha256', $currentSnapshotStart, [StringComparison]::Ordinal)
    $unexpectedEntryCheck = $sourceText.IndexOf('unexpected or aliased runtime resolver entry appeared before import', $currentSnapshotStart, [StringComparison]::Ordinal)
    Add-D32FactsSelfTestCase 'opened PSHOME ancestor chain is identity/SD-bound and volume-root siblings stay outside the admitted resolver domain before import' `
        ($chainStart -ge 0 -and $chainFence -gt $chainStart -and $openFenceStart -ge 0 -and $openedDirectoryType -gt $openFenceStart -and $openedReparseReject -gt $openedDirectoryType -and
         $snapshotStart -gt $chainFence -and $rootAncestorRecord -gt $snapshotStart -and $currentSnapshotStart -gt $rootAncestorRecord -and
         $identityDriftCheck -gt $currentSnapshotStart -and $descriptorDriftCheck -gt $identityDriftCheck -and $unexpectedEntryCheck -gt $descriptorDriftCheck -and
         $resolverStart -gt $snapshotStart -and $resolverOutsideReject -gt $resolverStart -and $resolverPolicyStart -gt $resolverStart -and $resolverForbidden -gt $resolverPolicyStart -and
         $snapshotBeforeImport -gt $importStart -and $resolverBeforeImport -gt $importStart -and $firstImport -gt $resolverBeforeImport) `
        ("chain=$chainStart/$chainFence; open=$openFenceStart/$openedDirectoryType/$openedReparseReject; snapshot=$snapshotStart/$rootAncestorRecord; reuse=$currentSnapshotStart/$identityDriftCheck/$descriptorDriftCheck/$unexpectedEntryCheck; resolver=$resolverStart/$resolverOutsideReject/$resolverPolicyStart/$resolverForbidden; admission=$importStart/$snapshotBeforeImport/$resolverBeforeImport/$firstImport. Root identity/content/security descriptor are pinned; live three-module resolver admission remains unverified without current external pins.")

    $rootIdentity = [ordered]@{ path = $actualVolumeRoot; volume_serial_hex = '0000000000000001'; file_id_hex = '11111111111111111111111111111111' }
    $rootIdentityDoc = [System.Text.Json.JsonDocument]::Parse((ConvertTo-D32PowerShellAuthorityJsonText -Value $rootIdentity))
    try {
        $exactRootSnapshot = [PSCustomObject]@{ Path = $actualVolumeRoot; VolumeSerialHex = '0000000000000001'; FileIdHex = '11111111111111111111111111111111' }
        $exactRootIdentityAccepted = $true
        try { Assert-D32PowerShellAuthorityDirectoryRecord -Element $rootIdentityDoc.RootElement -Actual $exactRootSnapshot -Name 'synthetic opened volume-root identity' }
        catch { $exactRootIdentityAccepted = $false }
        Add-D32FactsSelfTestCase 'strict external volume-root reference accepts its exact opened object identity' $exactRootIdentityAccepted
        $mutatedRootIdentity = [ordered]@{ path = "\\?\$actualVolumeRoot"; volume_serial_hex = '0000000000000001'; file_id_hex = '11111111111111111111111111111111' }
        $mutatedRootDoc = [System.Text.Json.JsonDocument]::Parse((ConvertTo-D32PowerShellAuthorityJsonText -Value $mutatedRootIdentity))
        try {
            $aliasRejected = $false
            try { Assert-D32PowerShellAuthorityDirectoryRecord -Element $mutatedRootDoc.RootElement -Actual $exactRootSnapshot -Name 'synthetic volume-root alias' }
            catch { $aliasRejected = $true }
            Add-D32FactsSelfTestCase 'strict volume-root identity reference rejects an alias/noncanonical path' $aliasRejected
        }
        finally { $mutatedRootDoc.Dispose() }
        $wrongIdRejected = $false
        $wrongRootSnapshot = [PSCustomObject]@{ Path = $actualVolumeRoot; VolumeSerialHex = '0000000000000002'; FileIdHex = '22222222222222222222222222222222' }
        try { Assert-D32PowerShellAuthorityDirectoryRecord -Element $rootIdentityDoc.RootElement -Actual $wrongRootSnapshot -Name 'synthetic substituted volume-root identity' }
        catch { $wrongIdRejected = $true }
        Add-D32FactsSelfTestCase 'strict volume-root reference rejects substituted volume and file IDs' $wrongIdRejected
    }
    finally { $rootIdentityDoc.Dispose() }

    $windowsRoot = Get-D32PowerShellAuthorityWindowsRootPath
    $system32Path = [IO.Path]::Combine($windowsRoot, 'System32')
    $trustedPlatformFile = [IO.Path]::Combine([string]$PSHOME, 'System.Management.Automation.dll')
    $depsFile = [IO.Path]::Combine([string]$PSHOME, 'pwsh.deps.json')
    $kernelBasePath = [IO.Path]::Combine($system32Path, 'kernelbase.dll')
    $ntdllPath = [IO.Path]::Combine($system32Path, 'ntdll.dll')
    $powershellImagePath = [IO.Path]::Combine([string]$PSHOME, 'pwsh.exe')
    $powershellImageReference = New-D32FactsSelfTestAuthorityFileReference -Path $powershellImagePath
    $kernelBaseReference = New-D32FactsSelfTestAuthorityFileReference -Path $kernelBasePath
    $ntdllReference = New-D32FactsSelfTestAuthorityFileReference -Path $ntdllPath
    $osComponents = @(
        [PSCustomObject]@{
            component_type = 'MICROSOFT_WINDOWS_OS_INSTALLATION'
            inventory_sha256 = ('1' * 64)
            native_files = @($kernelBaseReference, $ntdllReference)
            distribution = [PSCustomObject]@{ directories = @([PSCustomObject]@{ path = $system32Path }); files = @($kernelBaseReference, $ntdllReference) }
        },
        [PSCustomObject]@{
            component_type = 'MICROSOFT_WINDOWS_DEFENDER_PLATFORM'
            inventory_sha256 = ('2' * 64)
            native_files = @()
            distribution = [PSCustomObject]@{ directories = @(); files = @() }
        }
    )
    $osComponentsDigest = Get-D32PowerShellAuthorityOsSecurityInventoryDigest -Components $osComponents
    $resolverParameters = @{
        TrustedPlatformAssemblyPaths = @($trustedPlatformFile)
        ManagedAssemblyPaths = @($trustedPlatformFile, $kernelBasePath)
        DepsFilePaths = @($depsFile)
        NativeDirectoryPaths = @([IO.Path]::GetFullPath([string]$PSHOME), $system32Path)
        NativeModulePaths = @($powershellImagePath, $kernelBasePath)
        OsSecurityComponents = $osComponents
        OsSecurityInventorySha256 = $osComponentsDigest
    }
    $resolverPositive = Get-D32PowerShellAuthorityResolverSnapshot @resolverParameters
    Add-D32FactsSelfTestCase 'synthetic resolver closure accepts only exact pinned PSHOME and System32 inputs' `
        ($resolverPositive.Blockers.Count -eq 0) ($resolverPositive.Blockers -join '; ')
    $rootSibling = [IO.Path]::Combine($actualVolumeRoot, "d32-synthetic-$testId.dll")

    $resolverPostParameters = $resolverParameters.Clone()
    $resolverPostParameters.NativeModulePaths = @($resolverParameters.NativeModulePaths + $ntdllPath)
    $resolverPostParameters.ManagedAssemblyPaths = @($resolverParameters.ManagedAssemblyPaths + $ntdllPath)
    $resolverPostImport = Get-D32PowerShellAuthorityResolverSnapshot @resolverPostParameters
    $pinnedNativeRefs = @(
        $powershellImageReference,
        $kernelBaseReference,
        $ntdllReference
    )
    $pinnedManagedRefs = @(
        (New-D32FactsSelfTestAuthorityFileReference -Path $trustedPlatformFile),
        $kernelBaseReference,
        $ntdllReference
    )
    $syntheticNativeEvidence = Get-D32PowerShellAuthorityNativeOriginEvidence -ResolverSnapshot $resolverPositive -RuntimeDistributionFiles @($powershellImageReference) `
        -OsSecurityComponents $osComponents -PowerShellRoot ([string]$PSHOME)
    $syntheticAdmission = [PSCustomObject]@{
        resolver_admission = [ordered]@{
            state = 'VERIFIED'; policy_id = 'D32_POWERSHELL_RESOLVER_DOMAIN_V2'; resolver_sha256 = [string]$resolverPositive.ResolverSha256
            os_security_inventory_sha256 = [string]$resolverPositive.OsSecurityInventorySha256; native_policy = [string]$resolverPositive.NativePolicy
            module_search_path = [string]$resolverPositive.ModuleSearchPath; trusted_platform_paths = @($resolverPositive.TrustedPlatformPaths)
            loaded_managed_assembly_paths = @($resolverPositive.LoadedManagedAssemblyPaths); deps_paths = @($resolverPositive.DepsPaths)
            native_directories = @($resolverPositive.NativeDirectories); native_module_paths = @($resolverPositive.NativeModulePaths)
            active_environment = @($resolverPositive.ActiveEnvironment)
        }
        import_verification = [ordered]@{ native_modules = @($syntheticNativeEvidence) }
    }
    $reconstructedResolver = Get-D32PowerShellAuthorityResolverSnapshotFromAdmission -Admission $syntheticAdmission
    $positiveTransition = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $resolverPositive -After $resolverPostImport `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    $positiveTransitionJson = ConvertTo-D32PowerShellAuthorityJsonText -Value $positiveTransition.Diagnostic
    $preResolverDigests = Get-D32PowerShellAuthorityResolverDigestSet -ModuleSearchPath $resolverPositive.ModuleSearchPath -OsSecurityInventorySha256 $resolverPositive.OsSecurityInventorySha256 `
        -TrustedPlatformPaths $resolverPositive.TrustedPlatformPaths -DepsPaths $resolverPositive.DepsPaths -NativeDirectories $resolverPositive.NativeDirectories `
        -NativeModulePaths $resolverPositive.NativeModulePaths -ActiveEnvironment $resolverPositive.ActiveEnvironment -NativePolicy $resolverPositive.NativePolicy -NativeFileComponents $resolverPositive.NativeFileComponents
    $postResolverDigests = Get-D32PowerShellAuthorityResolverDigestSet -ModuleSearchPath $resolverPostImport.ModuleSearchPath -OsSecurityInventorySha256 $resolverPostImport.OsSecurityInventorySha256 `
        -TrustedPlatformPaths $resolverPostImport.TrustedPlatformPaths -DepsPaths $resolverPostImport.DepsPaths -NativeDirectories $resolverPostImport.NativeDirectories `
        -NativeModulePaths $resolverPostImport.NativeModulePaths -ActiveEnvironment $resolverPostImport.ActiveEnvironment -NativePolicy $resolverPostImport.NativePolicy -NativeFileComponents $resolverPostImport.NativeFileComponents
    Add-D32FactsSelfTestCase 'authorized post-import native and managed origins are admitted only as exact caller-pinned additions, and V2 resolver digest recomputes with component roles' `
        ($positiveTransition.Passed -and $resolverPositive.ResolverSha256 -cne $resolverPostImport.ResolverSha256 -and
         $resolverPositive.PolicySha256 -ceq $resolverPostImport.PolicySha256 -and
         $preResolverDigests.ResolverSha256 -ceq $resolverPositive.ResolverSha256 -and $postResolverDigests.ResolverSha256 -ceq $resolverPostImport.ResolverSha256 -and
         $reconstructedResolver.ResolverSha256 -ceq $resolverPositive.ResolverSha256 -and $reconstructedResolver.PolicySha256 -ceq $resolverPositive.PolicySha256 -and
         $positiveTransition.Diagnostic.native_images.added_content_refs.Count -eq 1 -and $positiveTransition.Diagnostic.native_images.added_content_refs[0].caller_pinned -and
         $positiveTransition.Diagnostic.managed_assemblies.added_content_refs.Count -eq 1 -and $positiveTransition.Diagnostic.managed_assemblies.added_content_refs[0].caller_pinned -and
         $global:D32PowerShellModuleImportAttempts -eq 0) `
        ("policy-sha=$($resolverPostImport.PolicySha256); resolver-sha-before=$($resolverPositive.ResolverSha256); resolver-sha-after=$($resolverPostImport.ResolverSha256); diagnostic=$positiveTransitionJson; import_attempts=0")

    $unknownNativePath = 'C:\ProgramData\D32Synthetic\unclassified-native.dll'
    $resolverUnknownParameters = $resolverParameters.Clone()
    $resolverUnknownParameters.NativeModulePaths = @($resolverParameters.NativeModulePaths + $unknownNativePath)
    $resolverUnknown = Get-D32PowerShellAuthorityResolverSnapshot @resolverUnknownParameters
    $unknownTransition = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $resolverPositive -After $resolverUnknown `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    $unknownDiagnostic = ConvertTo-D32PowerShellAuthorityJsonText -Value $unknownTransition.Diagnostic
    Add-D32FactsSelfTestCase 'unknown native image is denied with hashed unclassified-path diagnostic and zero imports' `
        (-not $unknownTransition.Passed -and $unknownDiagnostic.Contains('UNCLASSIFIED') -and -not $unknownDiagnostic.Contains($unknownNativePath) -and $global:D32PowerShellModuleImportAttempts -eq 0) $unknownDiagnostic

    $unknownManagedPath = 'C:\ProgramData\D32Synthetic\unclassified-managed.dll'
    $resolverUnknownManagedParameters = $resolverParameters.Clone()
    $resolverUnknownManagedParameters.ManagedAssemblyPaths = @($resolverParameters.ManagedAssemblyPaths + $unknownManagedPath)
    $resolverUnknownManaged = Get-D32PowerShellAuthorityResolverSnapshot @resolverUnknownManagedParameters
    $unknownManagedTransition = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $resolverPositive -After $resolverUnknownManaged `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    Add-D32FactsSelfTestCase 'unknown managed assembly is denied outside the caller-pinned PowerShell/Windows domains' `
        (-not $unknownManagedTransition.Passed -and @($unknownManagedTransition.Diagnostic.issues | Where-Object { $_ -match 'managed assembly' }).Count -gt 0 -and $global:D32PowerShellModuleImportAttempts -eq 0) `
        (ConvertTo-D32PowerShellAuthorityJsonText -Value $unknownManagedTransition.Diagnostic)

    $resolverNativeRemovedParameters = $resolverPostParameters.Clone()
    $resolverNativeRemovedParameters.NativeModulePaths = @($resolverPostParameters.NativeModulePaths | Where-Object { $_ -cne $kernelBasePath })
    $resolverNativeRemoved = Get-D32PowerShellAuthorityResolverSnapshot @resolverNativeRemovedParameters
    $nativeRemovedTransition = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $resolverPositive -After $resolverNativeRemoved `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    Add-D32FactsSelfTestCase 'a removed native loader snapshot entry is accepted only with an exact caller-pinned content reference' `
        ($nativeRemovedTransition.Passed -and $nativeRemovedTransition.Diagnostic.native_images.removed_content_refs.Count -eq 1 -and
         $nativeRemovedTransition.Diagnostic.native_images.removed_content_refs[0].caller_pinned -and
         $nativeRemovedTransition.Diagnostic.native_images.removed_content_refs[0].location.domain -ceq 'WINDOWS_OS' -and
         $nativeRemovedTransition.Diagnostic.native_images.removed_content_refs[0].sha256 -ceq $kernelBaseReference.sha256 -and
         $global:D32PowerShellModuleImportAttempts -eq 0) `
        (ConvertTo-D32PowerShellAuthorityJsonText -Value $nativeRemovedTransition.Diagnostic)

    $resolverManagedRemovedParameters = $resolverPostParameters.Clone()
    $resolverManagedRemovedParameters.ManagedAssemblyPaths = @($resolverPostParameters.ManagedAssemblyPaths | Where-Object { $_ -cne $kernelBasePath })
    $resolverManagedRemoved = Get-D32PowerShellAuthorityResolverSnapshot @resolverManagedRemovedParameters
    $managedRemovedTransition = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $resolverPositive -After $resolverManagedRemoved `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    Add-D32FactsSelfTestCase 'managed assembly disappearance remains denied across the fixed imports' `
        (-not $managedRemovedTransition.Passed -and @($managedRemovedTransition.Diagnostic.issues | Where-Object { $_ -match 'managed assembly disappeared' }).Count -eq 1 -and $global:D32PowerShellModuleImportAttempts -eq 0) `
        (ConvertTo-D32PowerShellAuthorityJsonText -Value $managedRemovedTransition.Diagnostic)

    $resolverPolicyDriftParameters = $resolverParameters.Clone()
    $resolverPolicyDriftParameters.TrustedPlatformAssemblyPaths = @($trustedPlatformFile, $rootSibling)
    $resolverPolicyDrift = Get-D32PowerShellAuthorityResolverSnapshot @resolverPolicyDriftParameters
    $policyDriftTransition = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $resolverPositive -After $resolverPolicyDrift `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    $policyDriftDiagnostic = ConvertTo-D32PowerShellAuthorityJsonText -Value $policyDriftTransition.Diagnostic
    Add-D32FactsSelfTestCase 'fixed TPA resolver policy drift is denied and diagnostic does not disclose unclassified path text' `
        (-not $policyDriftTransition.Passed -and $policyDriftDiagnostic.Contains('TrustedPlatformPaths') -and -not $policyDriftDiagnostic.Contains($rootSibling) -and $global:D32PowerShellModuleImportAttempts -eq 0) $policyDriftDiagnostic

    $injectedEnvironment = New-D32FactsSelfTestResolverSnapshotOverride -Snapshot $resolverPositive -Overrides ([ordered]@{ ActiveEnvironment = @([ordered]@{ name = 'DOTNET_STARTUP_HOOKS'; value = 'synthetic-sensitive-value' }) })
    $environmentTransition = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $resolverPositive -After $injectedEnvironment `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    $environmentDiagnostic = ConvertTo-D32PowerShellAuthorityJsonText -Value $environmentTransition.Diagnostic
    Add-D32FactsSelfTestCase 'synthetic runtime injection-environment drift is denied without logging environment values' `
        (-not $environmentTransition.Passed -and $environmentDiagnostic.Contains('ActiveEnvironment') -and -not $environmentDiagnostic.Contains('synthetic-sensitive-value') -and $global:D32PowerShellModuleImportAttempts -eq 0) $environmentDiagnostic

    $reorderedOrigins = New-D32FactsSelfTestResolverSnapshotOverride -Snapshot $resolverPostImport -Overrides ([ordered]@{ NativeModulePaths = @($resolverPostImport.NativeModulePaths[1], $resolverPostImport.NativeModulePaths[0], $resolverPostImport.NativeModulePaths[2]) })
    $reorderedTransition = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $resolverPositive -After $reorderedOrigins `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    Add-D32FactsSelfTestCase 'native image reorder cannot masquerade as an import-only monotonic transition' `
        (-not $reorderedTransition.Passed -and @($reorderedTransition.Diagnostic.issues | Where-Object { $_ -match 'order changed' }).Count -gt 0 -and $global:D32PowerShellModuleImportAttempts -eq 0) `
        (ConvertTo-D32PowerShellAuthorityJsonText -Value $reorderedTransition.Diagnostic)

    $caseChangedPath = $kernelBasePath.Replace('kernelbase.dll', 'KERNELBASE.dll')
    $caseChangedOrigins = New-D32FactsSelfTestResolverSnapshotOverride -Snapshot $resolverPostImport -Overrides ([ordered]@{ NativeModulePaths = @($powershellImagePath, $caseChangedPath, $ntdllPath) })
    $caseChangedTransition = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $resolverPositive -After $caseChangedOrigins `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    Add-D32FactsSelfTestCase 'native file identity path case drift is denied despite case-insensitive lookup aliases' `
        (-not $caseChangedTransition.Passed -and @($caseChangedTransition.Diagnostic.issues | Where-Object { $_ -match 'casing changed' }).Count -gt 0 -and $global:D32PowerShellModuleImportAttempts -eq 0) `
        (ConvertTo-D32PowerShellAuthorityJsonText -Value $caseChangedTransition.Diagnostic)

    $wrongRoleComponents = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $resolverPostImport.NativeModulePaths) {
        $componentType = [string]$resolverPostImport.NativeFileComponents[[string]$path]
        if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$path, $ntdllPath)) { $componentType = 'MICROSOFT_WINDOWS_DEFENDER_PLATFORM' }
        $wrongRoleComponents.Add([string]$path, $componentType)
    }
    $wrongRoleOrigins = New-D32FactsSelfTestResolverSnapshotOverride -Snapshot $resolverPostImport -Overrides ([ordered]@{ NativeFileComponents = $wrongRoleComponents })
    $wrongRoleTransition = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $resolverPositive -After $wrongRoleOrigins `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    Add-D32FactsSelfTestCase 'pinned content cannot be re-labelled as an incompatible Windows/Defender component role' `
        (-not $wrongRoleTransition.Passed -and $wrongRoleTransition.Diagnostic.native_component_role_differences.Count -gt 0 -and $global:D32PowerShellModuleImportAttempts -eq 0) `
        (ConvertTo-D32PowerShellAuthorityJsonText -Value $wrongRoleTransition.Diagnostic)

    $resolverSiblingManaged = @{
        TrustedPlatformAssemblyPaths = @($trustedPlatformFile, $rootSibling)
        ManagedAssemblyPaths = @($trustedPlatformFile, $kernelBasePath, $rootSibling)
        DepsFilePaths = @($depsFile)
        NativeDirectoryPaths = @([IO.Path]::GetFullPath([string]$PSHOME), $system32Path)
        NativeModulePaths = @([IO.Path]::Combine([string]$PSHOME, 'pwsh.exe'), $kernelBasePath)
        OsSecurityComponents = $osComponents
        OsSecurityInventorySha256 = $osComponentsDigest
    }
    $resolverManagedSiblingResult = Get-D32PowerShellAuthorityResolverSnapshot @resolverSiblingManaged
    Add-D32FactsSelfTestCase 'a new volume-root sibling cannot enter the TPA/deps managed resolver domain' `
        ($resolverManagedSiblingResult.Blockers.Count -gt 0 -and ($resolverManagedSiblingResult.Blockers -join '; ') -match 'not an exact admitted PowerShell or Windows OS file') `
        ($resolverManagedSiblingResult.Blockers -join '; ')
    $resolverSiblingNative = @{
        TrustedPlatformAssemblyPaths = @($trustedPlatformFile)
        ManagedAssemblyPaths = @($trustedPlatformFile, $kernelBasePath)
        DepsFilePaths = @($depsFile)
        NativeDirectoryPaths = @([IO.Path]::GetFullPath([string]$PSHOME), $system32Path, $actualVolumeRoot)
        NativeModulePaths = @([IO.Path]::Combine([string]$PSHOME, 'pwsh.exe'), $kernelBasePath)
        OsSecurityComponents = $osComponents
        OsSecurityInventorySha256 = $osComponentsDigest
    }
    $resolverNativeSiblingResult = Get-D32PowerShellAuthorityResolverSnapshot @resolverSiblingNative
    Add-D32FactsSelfTestCase 'the volume root itself is not admitted as a native resolver directory' `
        ($resolverNativeSiblingResult.Blockers.Count -gt 0 -and ($resolverNativeSiblingResult.Blockers -join '; ') -match 'native resolver directory is not an exact protected') `
        ($resolverNativeSiblingResult.Blockers -join '; ')
    $programDataAsRoot = Test-D32PowerShellAuthorityProtectedSecurity -Security $systemProgramData -IsDirectory:$true -IsProtectedAncestor
    Add-D32FactsSelfTestCase 'volume-root allowance cannot be applied to ProgramData without its distinct exception context' (-not $programDataAsRoot)

    $oldProfilePath = 'E:\d32\D32_BUILD_TOOLCHAIN_PROFILE_V2-28c579267a71ba80f06d5ba77081f7b0cf987867.json'
    if (-not [IO.File]::Exists($oldProfilePath)) { throw 'MODULEFREE_SELFTEST_BLOCKED: comparison-only prior Profile V2 facts are unavailable' }
    $oldProfileJson = [IO.File]::ReadAllText($oldProfilePath, [Text.UTF8Encoding]::new($false, $true))
    $oldProfileDoc = [System.Text.Json.JsonDocument]::Parse($oldProfileJson)
    try {
        if ((Test-D32PowerShellAuthorityJsonDuplicates -Element $oldProfileDoc.RootElement) -or
            $oldProfileDoc.RootElement.GetProperty('profile_type').GetString() -cne 'D32_BUILD_TOOLCHAIN_PROFILE_V2') { throw 'MODULEFREE_SELFTEST_BLOCKED: comparison-only input has an unexpected Profile V2 shape' }
        $oldProfile = $oldProfileDoc.RootElement
        $native = $oldProfile.GetProperty('native')
        $roots = [ordered]@{}
        foreach ($root in $oldProfile.GetProperty('native_roots').EnumerateArray()) { $roots.Add($root.GetProperty('name').GetString(), $root.GetProperty('path').GetString()) }
        $facts = [ordered]@{
            schema_version = 1
            record_type = 'D32_BUILD_TOOLCHAIN_PROFILE_FACTS_REQUEST_V1'
            repository = $repo
            rust_toolchain_root = $oldProfile.GetProperty('rust_toolchain_root').GetString()
            msvc_root = [string]$roots['msvc']
            windows_sdk_root = [string]$roots['windows-sdk']
            msvc_path_entries = @()
            windows_sdk_path_entries = @()
            msvc_include_directories = @()
            windows_sdk_include_directories = @()
            msvc_lib_directories = @()
            windows_sdk_lib_directories = @()
            msvc_libpath_directories = @()
            windows_sdk_libpath_directories = @()
            vc_tools_version = $native.GetProperty('environment').GetProperty('VCToolsVersion').GetString()
            windows_sdk_version = $native.GetProperty('environment').GetProperty('WindowsSDKVersion').GetString()
        }
        foreach ($definition in @(
            [PSCustomObject]@{ Json = 'path_entries'; Msvc = 'msvc_path_entries'; Sdk = 'windows_sdk_path_entries' },
            [PSCustomObject]@{ Json = 'include_dirs'; Msvc = 'msvc_include_directories'; Sdk = 'windows_sdk_include_directories' },
            [PSCustomObject]@{ Json = 'lib_dirs'; Msvc = 'msvc_lib_directories'; Sdk = 'windows_sdk_lib_directories' },
            [PSCustomObject]@{ Json = 'libpath_dirs'; Msvc = 'msvc_libpath_directories'; Sdk = 'windows_sdk_libpath_directories' }
        )) {
            $msvcValues = [System.Collections.Generic.List[string]]::new()
            $sdkValues = [System.Collections.Generic.List[string]]::new()
            foreach ($value in $native.GetProperty([string]$definition.Json).EnumerateArray()) {
                $path = $value.GetString()
                if (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent ([string]$roots['msvc'])) { $msvcValues.Add($path) }
                elseif (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent ([string]$roots['windows-sdk'])) { $sdkValues.Add($path) }
                else { throw "MODULEFREE_SELFTEST_BLOCKED: prior profile contains an unowned native input directory: $path" }
            }
            $facts[[string]$definition.Msvc] = $msvcValues.ToArray()
            $facts[[string]$definition.Sdk] = $sdkValues.ToArray()
        }
        $environment = $native.GetProperty('environment')
        foreach ($optional in @(
            [PSCustomObject]@{ Json = 'VCToolsRedistDir'; Fact = 'vc_tools_redist_dir' },
            [PSCustomObject]@{ Json = 'VSINSTALLDIR'; Fact = 'vs_install_dir' },
            [PSCustomObject]@{ Json = 'VisualStudioVersion'; Fact = 'visual_studio_version' },
            [PSCustomObject]@{ Json = 'VSCMD_VER'; Fact = 'vscmd_version' }
        )) {
            $optionalElement = [System.Text.Json.JsonElement]::new()
            if ($environment.TryGetProperty([string]$optional.Json, [ref]$optionalElement) -and $optionalElement.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                $facts[[string]$optional.Fact] = $optionalElement.GetString()
            }
        }
    }
    finally { $oldProfileDoc.Dispose() }

    $candidateSha = [IO.File]::ReadAllText([IO.Path]::Combine($repo, '.git', 'HEAD'), [Text.Encoding]::ASCII).Trim()
    if ($candidateSha -notmatch '^[0-9a-f]{40}$') { throw 'MODULEFREE_SELFTEST_BLOCKED: expected detached candidate HEAD for no-Cargo facts generation' }
    $factsJson = ConvertTo-D32PowerShellAuthorityJsonText -Value $facts
    $factsPath = [IO.Path]::Combine($scratch, "d32-facts-$testId.json")
    $profileOutput = if ($PrepareCurrentCandidates) { [IO.Path]::Combine($scratch, "D32_BUILD_TOOLCHAIN_PROFILE_V2-$candidateSha.json") } else { [IO.Path]::Combine($scratch, "d32-profile-$testId.json") }
    $protocOutput = if ($PrepareCurrentCandidates) { [IO.Path]::Combine($scratch, "D32_VENDORED_PROTOC_AUTHORITY_V1-D32_TEST_INVENTORY_DISCOVERY_ONLY-$candidateSha.json") } else { [IO.Path]::Combine($scratch, "d32-protoc-$testId.json") }
    $tauriOutput = if ($PrepareCurrentCandidates) { [IO.Path]::Combine($scratch, "D32_TAURI_MACROS_SOURCE_PATCH_V1-$candidateSha.json") } else { [IO.Path]::Combine($scratch, "d32-tauri-source-$testId.json") }
    $moduleAuthorityOutput = if ($PrepareCurrentCandidates) { [IO.Path]::Combine($scratch, "D32_POWERSHELL_MODULE_CONTENT_AUTHORITY_V2-$candidateSha.json") } else { [IO.Path]::Combine($scratch, "d32-module-authority-$testId.json") }
    if ($PrepareCurrentCandidates) {
        foreach ($candidatePath in @($profileOutput,$protocOutput,$tauriOutput,$moduleAuthorityOutput)) {
            if ([IO.File]::Exists($candidatePath) -or [IO.Directory]::Exists($candidatePath)) { throw "MODULEFREE_SELFTEST_BLOCKED: current candidate output already exists; refusing overwrite: $candidatePath" }
        }
    }
    Write-D32FactsSelfTestFile -Path $factsPath -Text $factsJson
    if ([IO.File]::Exists($profileOutput) -or [IO.Directory]::Exists($profileOutput)) { throw 'MODULEFREE_SELFTEST_BLOCKED: unique Profile candidate test path already exists' }
    $decodedFacts = Read-D32PowerShellAuthorityFactsRequest -Path $factsPath -ExpectedRecordType 'D32_BUILD_TOOLCHAIN_PROFILE_FACTS_REQUEST_V1' `
        -RequiredFields @('schema_version','record_type','repository','rust_toolchain_root','msvc_root','windows_sdk_root',`
            'msvc_path_entries','windows_sdk_path_entries','msvc_include_directories','windows_sdk_include_directories',`
            'msvc_lib_directories','windows_sdk_lib_directories','msvc_libpath_directories','windows_sdk_libpath_directories',`
            'vc_tools_version','windows_sdk_version') -OptionalFields @('vc_tools_redist_dir','vs_install_dir','visual_studio_version','vscmd_version')
    $arrayRoundTrip = $true
    foreach ($field in @('msvc_path_entries','windows_sdk_path_entries','msvc_include_directories','windows_sdk_include_directories',`
        'msvc_lib_directories','windows_sdk_lib_directories','msvc_libpath_directories','windows_sdk_libpath_directories')) {
        $expectedArray = [string[]]$facts[$field]
        $actualArray = [string[]]$decodedFacts.PSObject.Properties[$field].Value
        if ($expectedArray.Count -ne $actualArray.Count -or ($expectedArray -join "`0") -cne ($actualArray -join "`0")) { $arrayRoundTrip = $false }
    }
    Add-D32FactsSelfTestCase 'strict facts request round-trips every array entry and preserves group/order' $arrayRoundTrip

    $badCases = [System.Collections.Generic.List[object]]::new()
    $duplicateText = $factsJson.Insert(1, '"record_type":"D32_BUILD_TOOLCHAIN_PROFILE_FACTS_REQUEST_V1",')
    $badCases.Add([PSCustomObject]@{ Name = 'duplicate field'; Text = $duplicateText })
    $extraFacts = [ordered]@{}
    foreach ($key in $facts.Keys) { $extraFacts[$key] = $facts[$key] }
    $extraFacts['unexpected'] = 'rejected'
    $badCases.Add([PSCustomObject]@{ Name = 'extra field'; Text = (ConvertTo-D32PowerShellAuthorityJsonText -Value $extraFacts) })
    $missingFacts = [ordered]@{}
    foreach ($key in $facts.Keys) { if ($key -cne 'vc_tools_version') { $missingFacts[$key] = $facts[$key] } }
    $badCases.Add([PSCustomObject]@{ Name = 'missing field'; Text = (ConvertTo-D32PowerShellAuthorityJsonText -Value $missingFacts) })
    $wrongVersionFacts = [ordered]@{}
    foreach ($key in $facts.Keys) { $wrongVersionFacts[$key] = $facts[$key] }
    $wrongVersionFacts['schema_version'] = 2
    $badCases.Add([PSCustomObject]@{ Name = 'wrong version'; Text = (ConvertTo-D32PowerShellAuthorityJsonText -Value $wrongVersionFacts) })
    $wrongTypeFacts = [ordered]@{}
    foreach ($key in $facts.Keys) { $wrongTypeFacts[$key] = $facts[$key] }
    $wrongTypeFacts['msvc_path_entries'] = 'not-an-array'
    $wrongElementFacts = [ordered]@{}
    foreach ($key in $facts.Keys) { $wrongElementFacts[$key] = $facts[$key] }
    $wrongElementFacts['msvc_path_entries'] = @('C:\synthetic\bin', 7)
    $largeFacts = [ordered]@{}
    foreach ($key in $facts.Keys) { $largeFacts[$key] = $facts[$key] }
    $largeFacts['padding'] = 'x' * 70000
    $badCases.Add([PSCustomObject]@{ Name = 'oversized input'; Text = (ConvertTo-D32PowerShellAuthorityJsonText -Value $largeFacts) })
    $negativeFactsRejected = $true
    foreach ($badCase in $badCases) {
        $badPath = [IO.Path]::Combine($scratch, "d32-facts-$testId-$($badCase.Name.Replace(' ', '-')).json")
        Write-D32FactsSelfTestFile -Path $badPath -Text ([string]$badCase.Text)
        $rejected = $false
        try {
            $null = Read-D32PowerShellAuthorityFactsRequest -Path $badPath -ExpectedRecordType 'D32_BUILD_TOOLCHAIN_PROFILE_FACTS_REQUEST_V1' `
                -RequiredFields @('schema_version','record_type','repository','rust_toolchain_root','msvc_root','windows_sdk_root',`
                    'msvc_path_entries','windows_sdk_path_entries','msvc_include_directories','windows_sdk_include_directories',`
                    'msvc_lib_directories','windows_sdk_lib_directories','msvc_libpath_directories','windows_sdk_libpath_directories',`
                    'vc_tools_version','windows_sdk_version') -OptionalFields @('vc_tools_redist_dir','vs_install_dir','visual_studio_version','vscmd_version')
        }
        catch { $rejected = [string]$_.Exception.Message -like '*FACTS_REQUEST_BLOCKED:*' }
        if (-not $rejected) { $negativeFactsRejected = $false; $failures.Add("strict parser accepted $($badCase.Name)") }
    }
    Add-D32FactsSelfTestCase 'strict facts request rejects duplicate/extra/missing/wrong-version/oversize inputs' $negativeFactsRejected
    $noncanonicalRejected = $false
    $noncanonicalPath = [IO.Path]::Combine($scratch, '.', [IO.Path]::GetFileName($factsPath))
    try {
        $null = Read-D32PowerShellAuthorityFactsRequest -Path $noncanonicalPath -ExpectedRecordType 'D32_BUILD_TOOLCHAIN_PROFILE_FACTS_REQUEST_V1' `
            -RequiredFields @('schema_version','record_type')
    }
    catch { $noncanonicalRejected = [string]$_.Exception.Message -like '*FACTS_REQUEST_BLOCKED:*' }
    Add-D32FactsSelfTestCase 'facts request rejects a noncanonical literal path before opening it' $noncanonicalRejected

    $profileScript = [IO.Path]::Combine($PSScriptRoot, 'd32-profile-candidate.ps1')
    $profileArgs = [System.Collections.Generic.List[string]]::new()
    foreach ($argument in @('-NoProfile','-NonInteractive','-File',$profileScript,'-FactsRequestPath',$factsPath,'-OutputPath',$profileOutput)) { $profileArgs.Add($argument) }
    $profileChild = Invoke-D32FactsSelfTestChild -Arguments $profileArgs.ToArray() -TimeoutSeconds 480
    $profileGenerated = $profileChild.ExitCode -eq 0 -and [IO.File]::Exists($profileOutput)
    if ($profileGenerated -and -not $PrepareCurrentCandidates) { $ownedFiles.Add($profileOutput) }
    Add-D32FactsSelfTestCase 'direct -NoProfile -File ProfileV2 generator completes full module-free validation' $profileGenerated `
        ("exit=$($profileChild.ExitCode); stdout=$($profileChild.Stdout.Trim()); stderr=$($profileChild.Stderr.Trim())")
    if ($profileGenerated) {
        $profileHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($profileOutput))).ToLowerInvariant()
        $profileHostSha = $null
        $generatedDoc = [System.Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText($profileOutput, [Text.UTF8Encoding]::new($false, $true)))
        try {
            $generatedProfile = $generatedDoc.RootElement
            $profileHostSha = $generatedProfile.GetProperty('powershell').GetProperty('sha256').GetString()
            $arrayGroupsExact = $true
            foreach ($definition in @(
                [PSCustomObject]@{ Json = 'path_entries'; Msvc = 'msvc_path_entries'; Sdk = 'windows_sdk_path_entries' },
                [PSCustomObject]@{ Json = 'include_dirs'; Msvc = 'msvc_include_directories'; Sdk = 'windows_sdk_include_directories' },
                [PSCustomObject]@{ Json = 'lib_dirs'; Msvc = 'msvc_lib_directories'; Sdk = 'windows_sdk_lib_directories' },
                [PSCustomObject]@{ Json = 'libpath_dirs'; Msvc = 'msvc_libpath_directories'; Sdk = 'windows_sdk_libpath_directories' }
            )) {
                $expectedGroup = [System.Collections.Generic.List[string]]::new()
                foreach ($entry in [string[]]$facts[[string]$definition.Msvc]) { $expectedGroup.Add($entry) }
                foreach ($entry in [string[]]$facts[[string]$definition.Sdk]) { $expectedGroup.Add($entry) }
                $actualGroup = [System.Collections.Generic.List[string]]::new()
                foreach ($entry in $generatedProfile.GetProperty('native').GetProperty([string]$definition.Json).EnumerateArray()) { $actualGroup.Add($entry.GetString()) }
                if ($expectedGroup.Count -ne $actualGroup.Count -or ($expectedGroup -join "`0") -cne ($actualGroup -join "`0")) { $arrayGroupsExact = $false }
            }
            Add-D32FactsSelfTestCase 'new ProfileV2 preserves all prior profile native directory arrays exactly by group and order' $arrayGroupsExact `
                'Prior profile was used only as comparison/request facts; its old authority/pins were not reused.'

            $baselineDoc = [System.Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText($oldProfilePath, [Text.UTF8Encoding]::new($false, $true)))
            try {
                $stableFieldsExact = $true
                foreach ($field in @('schema_version','profile_type','target_triple','system_root','rust_toolchain_root','toolchain',
                    'rust_toolchain_bin_images','native_roots','native','windows_child_images','fetch_manifests','fetch_git','env_policy','cargo_policy')) {
                    if (-not (Test-D32FactsSelfTestJsonEqual -Left $baselineDoc.RootElement.GetProperty($field) -Right $generatedProfile.GetProperty($field))) { $stableFieldsExact = $false; break }
                }
                $hostRebound = $generatedProfile.GetProperty('powershell_root').GetString() -cne $baselineDoc.RootElement.GetProperty('powershell_root').GetString() -and
                    $generatedProfile.GetProperty('powershell').GetProperty('path').GetString() -cne $baselineDoc.RootElement.GetProperty('powershell').GetProperty('path').GetString()
                Add-D32FactsSelfTestCase 'ProfileV2 preserves all stable existing profile semantics while rebinding only the PowerShell host/root' `
                    ($stableFieldsExact -and $hostRebound) 'The prior profile is a read-only comparison baseline only; candidate and authority pins are not inherited.'
            }
            finally { $baselineDoc.Dispose() }
        }
        finally { $generatedDoc.Dispose() }
        $profileBeforeCollision = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($profileOutput))).ToLowerInvariant()
        $collisionChild = Invoke-D32FactsSelfTestChild -Arguments $profileArgs.ToArray() -TimeoutSeconds 180
        $profileAfterCollision = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($profileOutput))).ToLowerInvariant()
        Add-D32FactsSelfTestCase 'ProfileV2 generator refuses existing destination without overwriting candidate bytes' `
            ($collisionChild.ExitCode -ne 0 -and $profileBeforeCollision -ceq $profileAfterCollision) `
            ("exit=$($collisionChild.ExitCode); existing-sha256=$profileAfterCollision")

        $wrongTypePath = [IO.Path]::Combine($scratch, "d32-facts-$testId-wrong-type.json")
        $wrongTypeOutput = [IO.Path]::Combine($scratch, "d32-profile-$testId-wrong-type.json")
        if ([IO.File]::Exists($wrongTypeOutput) -or [IO.Directory]::Exists($wrongTypeOutput)) { throw 'MODULEFREE_SELFTEST_BLOCKED: unique wrong-type Profile output path already exists' }
        Write-D32FactsSelfTestFile -Path $wrongTypePath -Text (ConvertTo-D32PowerShellAuthorityJsonText -Value $wrongTypeFacts)
        $wrongTypeArgs = [System.Collections.Generic.List[string]]::new()
        foreach ($argument in @('-NoProfile','-NonInteractive','-File',$profileScript,'-FactsRequestPath',$wrongTypePath,'-OutputPath',$wrongTypeOutput)) { $wrongTypeArgs.Add($argument) }
        $wrongTypeChild = Invoke-D32FactsSelfTestChild -Arguments $wrongTypeArgs.ToArray() -TimeoutSeconds 120
        Add-D32FactsSelfTestCase 'ProfileV2 facts CLI rejects wrong array field type before creating an output candidate' `
            ($wrongTypeChild.ExitCode -ne 0 -and -not [IO.File]::Exists($wrongTypeOutput)) `
            ("exit=$($wrongTypeChild.ExitCode); stdout=$($wrongTypeChild.Stdout.Trim()); stderr=$($wrongTypeChild.Stderr.Trim())")

        $wrongElementPath = [IO.Path]::Combine($scratch, "d32-facts-$testId-wrong-element.json")
        $wrongElementOutput = [IO.Path]::Combine($scratch, "d32-profile-$testId-wrong-element.json")
        if ([IO.File]::Exists($wrongElementOutput) -or [IO.Directory]::Exists($wrongElementOutput)) { throw 'MODULEFREE_SELFTEST_BLOCKED: unique wrong-element Profile output path already exists' }
        Write-D32FactsSelfTestFile -Path $wrongElementPath -Text (ConvertTo-D32PowerShellAuthorityJsonText -Value $wrongElementFacts)
        $wrongElementArgs = [System.Collections.Generic.List[string]]::new()
        foreach ($argument in @('-NoProfile','-NonInteractive','-File',$profileScript,'-FactsRequestPath',$wrongElementPath,'-OutputPath',$wrongElementOutput)) { $wrongElementArgs.Add([string]$argument) }
        $wrongElementChild = Invoke-D32FactsSelfTestChild -Arguments $wrongElementArgs.ToArray() -TimeoutSeconds 120
        Add-D32FactsSelfTestCase 'ProfileV2 facts CLI rejects non-string array elements before creating an output candidate' `
            ($wrongElementChild.ExitCode -ne 0 -and -not [IO.File]::Exists($wrongElementOutput)) `
            ("exit=$($wrongElementChild.ExitCode); stdout=$($wrongElementChild.Stdout.Trim()); stderr=$($wrongElementChild.Stderr.Trim())")

        $evidenceRoot = 'E:\d32\inv1'
        if ([IO.File]::Exists($evidenceRoot) -or [IO.Directory]::Exists($evidenceRoot)) { throw 'MODULEFREE_SELFTEST_BLOCKED: D32 inventory root is not absent; facts test will not claim it' }
        if ([IO.File]::Exists($protocOutput) -or [IO.Directory]::Exists($protocOutput)) { throw 'MODULEFREE_SELFTEST_BLOCKED: unique protoc output path already exists' }
        $protocScript = [IO.Path]::Combine($PSScriptRoot, 'd32-test-inventory-protoc-authority-facts.ps1')
        $protocArgs = [System.Collections.Generic.List[string]]::new()
        foreach ($argument in @('-NoProfile','-NonInteractive','-File',$protocScript,'-CandidateSha',$candidateSha,'-Repository',$repo,
            '-ToolchainProfilePath',$profileOutput,'-ExpectedToolchainProfileSha256',$profileHash,'-EvidenceRoot',$evidenceRoot,'-OutputPath',$protocOutput)) { $protocArgs.Add($argument) }
        $protocChild = Invoke-D32FactsSelfTestChild -Arguments $protocArgs.ToArray() -TimeoutSeconds 480
        $protocGenerated = $protocChild.ExitCode -eq 0 -and [IO.File]::Exists($protocOutput) -and -not [IO.Directory]::Exists($evidenceRoot)
        if ($protocGenerated -and -not $PrepareCurrentCandidates) { $ownedFiles.Add($protocOutput) }
        Add-D32FactsSelfTestCase 'direct discovery-only protoc facts generator validates ProfileV2 without claiming inv1' $protocGenerated `
            ("exit=$($protocChild.ExitCode); stdout=$($protocChild.Stdout.Trim()); stderr=$($protocChild.Stderr.Trim()); inv1-exists=$([IO.Directory]::Exists($evidenceRoot))")
        if ($protocGenerated) {
            $protocDoc = [System.Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText($protocOutput, [Text.UTF8Encoding]::new($false, $true)))
            try {
                Add-D32FactsSelfTestCase 'protoc V1 candidate preserves exact discovery-only scope and current candidate/profile bindings' `
                    ($protocDoc.RootElement.GetProperty('scope').GetString() -ceq 'D32_TEST_INVENTORY_DISCOVERY_ONLY' -and
                     $protocDoc.RootElement.GetProperty('candidate_sha').GetString() -ceq $candidateSha -and
                     $protocDoc.RootElement.GetProperty('toolchain_profile').GetProperty('sha256').GetString() -ceq $profileHash)
            }
            finally { $protocDoc.Dispose() }
            $protocHashBeforeCollision = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($protocOutput))).ToLowerInvariant()
            $protocCollisionChild = Invoke-D32FactsSelfTestChild -Arguments $protocArgs.ToArray() -TimeoutSeconds 240
            $protocHashAfterCollision = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($protocOutput))).ToLowerInvariant()
            Add-D32FactsSelfTestCase 'protoc facts generator refuses an existing destination without overwriting candidate bytes' `
                ($protocCollisionChild.ExitCode -ne 0 -and $protocHashBeforeCollision -ceq $protocHashAfterCollision) `
                ("exit=$($protocCollisionChild.ExitCode); existing-sha256=$protocHashAfterCollision")
        }

        $archivePath = 'C:\Users\zuo\.cargo\registry\cache\index.crates.io-1949cf8c6b5b557f\tauri-macros-2.6.3.crate'
        if ([IO.File]::Exists($archivePath)) {
            if ([IO.File]::Exists($tauriOutput) -or [IO.Directory]::Exists($tauriOutput)) { throw 'MODULEFREE_SELFTEST_BLOCKED: unique Tauri source output path already exists' }
            $tauriScript = [IO.Path]::Combine($PSScriptRoot, 'd32-tauri-macros-source-attestation.ps1')
            $tauriArgs = [System.Collections.Generic.List[string]]::new()
            foreach ($argument in @('-NoProfile','-NonInteractive','-File',$tauriScript,'-FactsOnly','-ArchivePath',$archivePath,
                '-CandidateSha',$candidateSha,'-ToolchainProfilePath',$profileOutput,'-ExpectedToolchainProfileSha256',$profileHash,
                '-Repository',$repo,'-FactsOutputPath',$tauriOutput)) { $tauriArgs.Add($argument) }
            $tauriChild = Invoke-D32FactsSelfTestChild -Arguments $tauriArgs.ToArray() -TimeoutSeconds 480
            $tauriGenerated = $tauriChild.ExitCode -eq 0 -and [IO.File]::Exists($tauriOutput)
            if ($tauriGenerated -and -not $PrepareCurrentCandidates) { $ownedFiles.Add($tauriOutput) }
            Add-D32FactsSelfTestCase 'direct module-free Tauri source facts entry emits a V1 candidate without imports' $tauriGenerated `
                ("exit=$($tauriChild.ExitCode); stdout=$($tauriChild.Stdout.Trim()); stderr=$($tauriChild.Stderr.Trim())")
            if ($tauriGenerated) {
                $tauriDoc = [System.Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText($tauriOutput, [Text.UTF8Encoding]::new($false, $true)))
                try {
                    Add-D32FactsSelfTestCase 'Tauri source patch candidate schema/status remains unchanged and caller candidate/profile bindings are exact' `
                        ($tauriDoc.RootElement.GetProperty('record_type').GetString() -ceq 'D32_TAURI_MACROS_SOURCE_PATCH_V1' -and
                         $tauriDoc.RootElement.GetProperty('schema_version').GetInt32() -eq 1 -and
                         $tauriDoc.RootElement.GetProperty('candidate_sha').GetString() -ceq $candidateSha -and
                         $tauriDoc.RootElement.GetProperty('toolchain_profile').GetProperty('sha256').GetString() -ceq $profileHash)
                }
                finally { $tauriDoc.Dispose() }
                $tauriHashBeforeCollision = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($tauriOutput))).ToLowerInvariant()
                $tauriCollisionChild = Invoke-D32FactsSelfTestChild -Arguments $tauriArgs.ToArray() -TimeoutSeconds 240
                $tauriHashAfterCollision = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($tauriOutput))).ToLowerInvariant()
                Add-D32FactsSelfTestCase 'Tauri source facts generator refuses an existing destination without overwriting candidate bytes' `
                    ($tauriCollisionChild.ExitCode -ne 0 -and $tauriHashBeforeCollision -ceq $tauriHashAfterCollision) `
                    ("exit=$($tauriCollisionChild.ExitCode); existing-sha256=$tauriHashAfterCollision")
            }
        }
        else { Add-D32FactsSelfTestCase 'Tauri source facts end-to-end fixture archive is available' $false "locked archive is absent at $archivePath" }

        if ($profileGenerated) {
            $authorityScript = [IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority-create.ps1')
            if ([IO.File]::Exists($moduleAuthorityOutput) -or [IO.Directory]::Exists($moduleAuthorityOutput)) { throw 'MODULEFREE_SELFTEST_BLOCKED: unique module authority candidate path already exists' }
            $authorityArgs = [System.Collections.Generic.List[string]]::new()
            foreach ($argument in @('-NoProfile','-NonInteractive','-File',$authorityScript,'-CreateNew','-Repository',$repo,'-CandidateSha',$candidateSha,
                '-ToolchainProfilePath',$profileOutput,'-ExpectedToolchainProfileSha256',$profileHash,'-OutputPath',$moduleAuthorityOutput)) { $authorityArgs.Add([string]$argument) }
            $authorityChild = Invoke-D32FactsSelfTestChild -Arguments $authorityArgs.ToArray() -TimeoutSeconds 900
            $authorityGenerated = $authorityChild.ExitCode -eq 0 -and [IO.File]::Exists($moduleAuthorityOutput) -and -not [IO.Directory]::Exists($moduleAuthorityOutput)
            if ($authorityGenerated -and -not $PrepareCurrentCandidates) { $ownedFiles.Add($moduleAuthorityOutput) }
            $authorityRootBound = $false
            $authoritySummary = "exit=$($authorityChild.ExitCode); stdout=$($authorityChild.Stdout.Trim()); stderr=$($authorityChild.Stderr.Trim())"
            if ($authorityGenerated) {
                $authorityDoc = [System.Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText($moduleAuthorityOutput, [Text.UTF8Encoding]::new($false, $true)))
                try {
                    $authorityElement = $authorityDoc.RootElement
                    if (Test-D32PowerShellAuthorityJsonDuplicates -Element $authorityElement) { throw 'MODULEFREE_SELFTEST_BLOCKED: module authority candidate contains duplicate keys' }
                    Assert-D32PowerShellAuthorityExactJsonRecord -Element $authorityElement -Fields @('schema_version','authority_type','status','gate_authority','candidate_sha','source_repo','profile','powershell_host','powershell_root','distribution','resolver_policy','modules') -Name 'module-content V2 candidate'
                    $moduleRoot = $authorityElement.GetProperty('powershell_root').GetProperty('path').GetString()
                    $rootPath = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($moduleRoot))
                    $ancestorMatches = [System.Collections.Generic.List[System.Text.Json.JsonElement]]::new()
                    foreach ($ancestor in $authorityElement.GetProperty('distribution').GetProperty('protected_ancestors').EnumerateArray()) {
                        if ([StringComparer]::OrdinalIgnoreCase.Equals($ancestor.GetProperty('path').GetString(), $rootPath)) { $ancestorMatches.Add($ancestor) }
                    }
                    $rootRecordValid = $false
                    if ($ancestorMatches.Count -eq 1) {
                        $rootRecord = $ancestorMatches[0]
                        $rootSddl = $rootRecord.GetProperty('security_descriptor_sddl').GetString()
                        $rootRawSecurity = [Security.AccessControl.RawSecurityDescriptor]::new($rootSddl)
                        $rootSddlHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($rootSddl))).ToLowerInvariant()
                        $rootRecordValid = $rootRecord.GetProperty('kind').GetString() -ceq 'ancestor' -and
                            $rootRecord.GetProperty('owner_sid').GetString() -ceq 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' -and
                            $rootRecord.GetProperty('volume_serial_hex').GetString() -match '^[0-9a-f]{16}$' -and
                            $rootRecord.GetProperty('file_id_hex').GetString() -match '^[0-9a-f]{32}$' -and
                            $rootRecord.GetProperty('security_descriptor_sha256').GetString() -match '^[0-9a-f]{64}$' -and
                            $rootRecord.GetProperty('security_descriptor_sha256').GetString() -ceq $rootSddlHash -and
                            $null -ne $rootRawSecurity.DiscretionaryAcl -and
                            ($rootRawSecurity.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -ne 0 -and
                            ($rootRawSecurity.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0
                    }
                    $moduleRoles = [System.Collections.Generic.List[string]]::new()
                    foreach ($module in $authorityElement.GetProperty('modules').EnumerateArray()) { $moduleRoles.Add($module.GetProperty('role').GetString()) }
                    $osComponentElements = $authorityElement.GetProperty('resolver_policy').GetProperty('os_security_components')
                    $osComponentRoles = [System.Collections.Generic.List[string]]::new()
                    foreach ($component in $osComponentElements.EnumerateArray()) { $osComponentRoles.Add($component.GetProperty('component_type').GetString()) }
                    $programDataRecordValid = $false
                    $microsoftChildRecordValid = $false
                    if ($osComponentElements.GetArrayLength() -eq 2) {
                        $defenderComponent = $osComponentElements[1]
                        foreach ($ancestor in $defenderComponent.GetProperty('distribution').GetProperty('protected_ancestors').EnumerateArray()) {
                            $ancestorPath = $ancestor.GetProperty('path').GetString()
                            if ([StringComparer]::OrdinalIgnoreCase.Equals($ancestorPath, 'C:\ProgramData')) {
                                $pdSddl = $ancestor.GetProperty('security_descriptor_sddl').GetString()
                                $pdRaw = [Security.AccessControl.RawSecurityDescriptor]::new($pdSddl)
                                $pdSddlHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($pdSddl))).ToLowerInvariant()
                                $programDataRecordValid = $ancestor.GetProperty('owner_sid').GetString() -ceq 'S-1-5-18' -and
                                    $ancestor.GetProperty('volume_serial_hex').GetString() -match '^[0-9a-f]{16}$' -and
                                    $ancestor.GetProperty('file_id_hex').GetString() -match '^[0-9a-f]{32}$' -and
                                    $ancestor.GetProperty('security_descriptor_sha256').GetString() -ceq $pdSddlHash -and
                                    $null -ne $pdRaw.DiscretionaryAcl -and
                                    ($pdRaw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -ne 0
                            }
                            elseif ([StringComparer]::OrdinalIgnoreCase.Equals($ancestorPath, 'C:\ProgramData\Microsoft')) {
                                $microsoftSddl = $ancestor.GetProperty('security_descriptor_sddl').GetString()
                                $microsoftRaw = [Security.AccessControl.RawSecurityDescriptor]::new($microsoftSddl)
                                $microsoftSddlHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($microsoftSddl))).ToLowerInvariant()
                                $microsoftChildRecordValid = $ancestor.GetProperty('owner_sid').GetString() -ceq 'S-1-5-18' -and
                                    $ancestor.GetProperty('volume_serial_hex').GetString() -match '^[0-9a-f]{16}$' -and
                                    $ancestor.GetProperty('file_id_hex').GetString() -match '^[0-9a-f]{32}$' -and
                                    $ancestor.GetProperty('security_descriptor_sha256').GetString() -ceq $microsoftSddlHash -and
                                    $null -ne $microsoftRaw.DiscretionaryAcl -and
                                    ($microsoftRaw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -ne 0 -and
                                    ($microsoftRaw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0
                            }
                        }
                    }
                    $authorityRootBound = $authorityElement.GetProperty('schema_version').GetInt32() -eq 2 -and
                        $authorityElement.GetProperty('authority_type').GetString() -ceq 'D32_POWERSHELL_MODULE_CONTENT_AUTHORITY_V2' -and
                        $authorityElement.GetProperty('status').GetString() -ceq 'CANDIDATE_FOR_COORDINATOR_PIN' -and
                        $authorityElement.GetProperty('gate_authority').GetString() -ceq 'NONE' -and
                        $authorityElement.GetProperty('candidate_sha').GetString() -ceq $candidateSha -and
                        $authorityElement.GetProperty('source_repo').GetString() -ceq $repo -and
                        $authorityElement.GetProperty('profile').GetProperty('path').GetString() -ceq [IO.Path]::GetFullPath($profileOutput) -and
                        $authorityElement.GetProperty('profile').GetProperty('bytes').GetInt64() -eq [Int64]([IO.FileInfo]::new($profileOutput).Length) -and
                        $authorityElement.GetProperty('profile').GetProperty('sha256').GetString() -ceq $profileHash -and
                        $authorityElement.GetProperty('powershell_host').GetProperty('sha256').GetString() -ceq $profileHostSha -and
                        $authorityElement.GetProperty('powershell_root').GetProperty('path').GetString() -ceq [IO.Path]::GetFullPath([string]$PSHOME) -and
                        $authorityElement.GetProperty('distribution').GetProperty('root_path').GetString() -ceq [IO.Path]::GetFullPath([string]$PSHOME) -and
                        $authorityElement.GetProperty('distribution').GetProperty('inventory_sha256').GetString() -match '^[0-9a-f]{64}$' -and
                        $authorityElement.GetProperty('modules').GetArrayLength() -eq 3 -and ($moduleRoles -join "`0") -ceq "Management`0Utility`0CimCmdlets" -and $rootRecordValid -and
                        $osComponentElements.GetArrayLength() -eq 2 -and ($osComponentRoles -join "`0") -ceq "MICROSOFT_WINDOWS_OS_INSTALLATION`0MICROSOFT_WINDOWS_DEFENDER_PLATFORM" -and
                        $authorityElement.GetProperty('resolver_policy').GetProperty('native_application_root').GetString() -ceq [IO.Path]::GetFullPath([string]$PSHOME) -and
                        $authorityElement.GetProperty('resolver_policy').GetProperty('native_system_root').GetString() -ceq $windowsRoot -and
                        $programDataRecordValid -and $microsoftChildRecordValid
                    $authorityBytes = [IO.File]::ReadAllBytes($moduleAuthorityOutput)
                    $authoritySummary = "path=$moduleAuthorityOutput; bytes=$($authorityBytes.Length); sha256=$([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($authorityBytes)).ToLowerInvariant()); schema=2; gate_authority=NONE; volume_root_ancestor_bound=$rootRecordValid; programdata_bound=$programDataRecordValid; protected_microsoft_child_bound=$microsoftChildRecordValid; candidate_sha=$candidateSha; profile_sha256=$profileHash; imports=0"
                }
                finally { $authorityDoc.Dispose() }
            }
            Add-D32FactsSelfTestCase 'module-content V2 generator emits an untrusted exact-SHA/Profile candidate with a full opened volume-root ancestor record' `
                ($authorityGenerated -and $authorityRootBound) $authoritySummary
        }
        else { Add-D32FactsSelfTestCase 'module-content V2 candidate generation requires a valid current Profile V2 candidate' $false 'Profile V2 candidate was unavailable' }
    }
    else {
        Add-D32FactsSelfTestCase 'new ProfileV2 preserves all prior profile native directory arrays exactly by group and order' $false 'candidate generation did not complete'
        Add-D32FactsSelfTestCase 'ProfileV2 generator refuses existing destination without overwriting candidate bytes' $false 'candidate generation did not complete'
        Add-D32FactsSelfTestCase 'discovery-only protoc facts preparation' $false 'candidate profile was unavailable'
    }
}
finally {
    foreach ($path in $ownedFiles) { if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) } }
    Assert-D32PowerShellAuthorityLoadedModuleSetUnchanged -Expected $moduleSetAtStart
}

$result = [ordered]@{ record_type = 'D32_POWERSHELL_MODULEFREE_FACTS_SELFTEST_V1'; case_count = $cases.Count; passed = $cases.Where({ $_.passed }).Count; failed = @($failures.ToArray()); cases = $cases.ToArray(); temp_files_removed = $ownedFiles.Count; candidate_outputs_preserved = [bool]$PrepareCurrentCandidates; candidate_sha = if ($PrepareCurrentCandidates) { $candidateSha } else { $null }; module_import_attempts = [int]$global:D32PowerShellModuleImportAttempts; cargo_invoked = $false; discovery_invoked = $false; evidence_root_claimed = $false }
[Console]::WriteLine((ConvertTo-D32PowerShellAuthorityJsonText -Value $result))
if ($failures.Count -gt 0) { exit 1 }
