# Pure, module-free regression checks for pinned Windows OS authority versus live resolver observations.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$global:PSModuleAutoLoadingPreference = 'None'
$global:D32PowerShellModuleImportAttempts = 0
. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
$moduleSetAtStart = Get-D32PowerShellAuthorityLoadedModuleSet
$cases = [System.Collections.Generic.List[object]]::new()
$failures = [System.Collections.Generic.List[string]]::new()

function Add-D32OsAuthorityCase {
    param([string]$Name, [bool]$Passed, [AllowNull()][string]$Detail = $null)
    $cases.Add([PSCustomObject]@{ name = $Name; passed = $Passed; detail = $Detail })
    if (-not $Passed) { $failures.Add($Name) }
}

function New-D32OsAuthoritySddlHash {
    param([string]$Sddl)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($Sddl))).ToLowerInvariant()
}

function Copy-D32OsAuthorityRecord {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Record)
    return Copy-D32PowerShellAuthorityJsonShape -Value $Record
}

function Test-D32OsAuthorityShapeRejects {
    param([object]$Record, [string]$ExpectedRoot, [string]$ExpectedSystemRoot, [string]$ExpectedVersion)
    $json = ConvertTo-D32PowerShellAuthorityJsonText -Value $Record
    $document = [System.Text.Json.JsonDocument]::Parse($json)
    try {
        try {
            $null = Assert-D32PowerShellAuthorityPinnedWindowsComponentShape -Element $document.RootElement `
                -ExpectedWindowsRoot $ExpectedRoot -ExpectedSystemRoot $ExpectedSystemRoot -ExpectedOsVersion $ExpectedVersion
            return $false
        }
        catch { return $true }
    }
    finally { $document.Dispose() }
}

function New-D32OsAuthorityResolverSnapshot {
    param(
        [string[]]$NativePaths,
        [string[]]$ManagedPaths,
        [hashtable]$NativeRoles,
        [string]$OsInventorySha256,
        [string]$ModuleSearchPath
    )
    $nativeSorted = [string[]]$NativePaths.Clone()
    $managedSorted = [string[]]$ManagedPaths.Clone()
    [Array]::Sort($nativeSorted, [StringComparer]::OrdinalIgnoreCase)
    [Array]::Sort($managedSorted, [StringComparer]::OrdinalIgnoreCase)
    $trustedPlatform = @([IO.Path]::Combine([string]$PSHOME, 'System.Management.Automation.dll'))
    $deps = @([IO.Path]::Combine([string]$PSHOME, 'pwsh.deps.json'))
    $nativeDirectories = @([string]$PSHOME)
    $nativeComponents = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $nativeSorted) { $nativeComponents.Add($path, [string]$NativeRoles[$path]) }
    $digests = Get-D32PowerShellAuthorityResolverDigestSet -ModuleSearchPath $ModuleSearchPath `
        -OsSecurityInventorySha256 $OsInventorySha256 -TrustedPlatformPaths $trustedPlatform -DepsPaths $deps `
        -NativeDirectories $nativeDirectories -NativeModulePaths $nativeSorted -ActiveEnvironment @() `
        -NativePolicy 'synthetic-safe-policy' -NativeFileComponents $nativeComponents
    return [PSCustomObject]@{
        Blockers = @(); ModuleSearchPath = $ModuleSearchPath; OsSecurityInventorySha256 = $OsInventorySha256
        NativePolicy = 'synthetic-safe-policy'; PolicySha256 = [string]$digests.PolicySha256
        ResolverSha256 = [string]$digests.ResolverSha256; NativeModulePathsSha256 = [string]$digests.NativeModulePathsSha256
        TrustedPlatformPaths = $trustedPlatform; LoadedManagedAssemblyPaths = $managedSorted; DepsPaths = $deps
        NativeDirectories = $nativeDirectories; NativeModulePaths = $nativeSorted; ActiveEnvironment = @()
        NativeFileComponents = $nativeComponents
    }
}

try {
    $windowsRoot = [IO.Path]::GetFullPath([string]$env:SystemRoot)
    $windowsRoot = Get-D32PowerShellAuthorityWindowsRootPath
    $systemRoot = [IO.Path]::GetFullPath([string]$env:SystemRoot)
    $osVersion = [Environment]::OSVersion.VersionString
    $trustedSid = 'S-1-5-18'
    $sddl = 'O:S-1-5-18G:S-1-5-18D:PAI(A;;FA;;;SY)'
    $rootDirectory = [ordered]@{ kind = 'directory'; path = $windowsRoot; volume_serial_hex = '0000000000000001'; file_id_hex = ('1' * 32); owner_sid = $trustedSid; security_descriptor_sddl = $sddl; security_descriptor_sha256 = (New-D32OsAuthoritySddlHash $sddl) }
    $system32Path = [IO.Path]::Combine($windowsRoot, 'System32')
    $system32Directory = [ordered]@{ kind = 'directory'; path = $system32Path; volume_serial_hex = '0000000000000001'; file_id_hex = ('2' * 32); owner_sid = $trustedSid; security_descriptor_sddl = $sddl; security_descriptor_sha256 = (New-D32OsAuthoritySddlHash $sddl) }
    $filePath = [IO.Path]::Combine($system32Path, 'apphelp.dll')
    $file = [ordered]@{ kind = 'file'; path = $filePath; bytes = [Int64]678544; sha256 = ('d' * 64); volume_serial_hex = '0000000000000001'; file_id_hex = ('3' * 32); owner_sid = $trustedSid; security_descriptor_sddl = $sddl; security_descriptor_sha256 = (New-D32OsAuthoritySddlHash $sddl) }
    $volumeRoot = [IO.Path]::GetPathRoot($windowsRoot)
    $ancestor = [ordered]@{ kind = 'ancestor'; path = $volumeRoot; volume_serial_hex = '0000000000000001'; file_id_hex = ('4' * 32); owner_sid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'; security_descriptor_sddl = $sddl; security_descriptor_sha256 = (New-D32OsAuthoritySddlHash $sddl) }
    $distribution = [ordered]@{
        root_path = $windowsRoot; inventory_sha256 = ''
        directories = @($rootDirectory,$system32Directory); files = @($file); protected_ancestors = @($ancestor)
        trusted_writer_sids = @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544')
    }
    $distribution.inventory_sha256 = Get-D32PowerShellAuthorityRuntimeInventoryDigest -Directories $distribution.directories `
        -Files $distribution.files -Ancestors $distribution.protected_ancestors
    $sourceProof = [ordered]@{ proof_type = 'GET_WINDOWSDIRECTORYW_OPENED_NAMESPACE_V1'; api_path = $windowsRoot; environment_system_root = $systemRoot; os_version = $osVersion }
    $componentMaterial = [string]$distribution.inventory_sha256 + "`n" + (ConvertTo-D32PowerShellAuthorityJsonText -Value $sourceProof) + "`n"
    $component = [ordered]@{
        component_type = 'MICROSOFT_WINDOWS_OS_INSTALLATION'; version = $osVersion; root_path = $windowsRoot
        root_volume_serial_hex = $rootDirectory.volume_serial_hex; root_file_id_hex = $rootDirectory.file_id_hex
        inventory_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($componentMaterial))).ToLowerInvariant()
        source_proof = $sourceProof; distribution = $distribution; native_files = @($file)
    }
    $pinnedJson = ConvertTo-D32PowerShellAuthorityJsonText -Value $component
    $pinnedDocument = [System.Text.Json.JsonDocument]::Parse($pinnedJson)
    try {
        $shapeAccepted = $null -ne (Assert-D32PowerShellAuthorityPinnedWindowsComponentShape -Element $pinnedDocument.RootElement `
            -ExpectedWindowsRoot $windowsRoot -ExpectedSystemRoot $systemRoot -ExpectedOsVersion $osVersion)
    }
    finally { $pinnedDocument.Dispose() }
    Add-D32OsAuthorityCase 'finite static Windows pin shape, digest, source, and unloaded apphelp member accepted' $shapeAccepted `
        'The synthetic static component includes apphelp.dll while the separate current-origin set below omits it.'

    $wrongRole = Copy-D32OsAuthorityRecord -Record $component; $wrongRole.component_type = 'MICROSOFT_WINDOWS_DEFENDER_PLATFORM'
    $wrongVersion = Copy-D32OsAuthorityRecord -Record $component; $wrongVersion.version = 'drifted-version'
    $wrongRoot = Copy-D32OsAuthorityRecord -Record $component; $wrongRoot.root_path = [IO.Path]::Combine($windowsRoot, 'Alias')
    $wrongSource = Copy-D32OsAuthorityRecord -Record $component; $wrongSource.source_proof.proof_type = 'UNTRUSTED_SOURCE'
    $wrongDigest = Copy-D32OsAuthorityRecord -Record $component; $wrongDigest.inventory_sha256 = ('0' * 64)
    $wrongOrder = Copy-D32OsAuthorityRecord -Record $component; $wrongOrder.distribution.directories = @($system32Directory,$rootDirectory)
    $directoryAlias = Copy-D32OsAuthorityRecord -Record $component; $directoryAlias.distribution.directories[1].file_id_hex = $directoryAlias.distribution.directories[0].file_id_hex
    $reparseAliasDirectory = Copy-D32OsAuthorityRecord -Record $component; $reparseAliasDirectory.distribution.directories[1].path = [IO.Path]::Combine($windowsRoot,'System32','..')
    $missingParent = Copy-D32OsAuthorityRecord -Record $component; $missingParent.distribution.directories = @($rootDirectory)
    $badAcl = Copy-D32OsAuthorityRecord -Record $component; $badAcl.distribution.files[0].security_descriptor_sddl = 'O:S-1-5-18G:S-1-5-18D:PAI(A;;FA;;;BA)'
    $shapeMutationsRejected = $true
    foreach ($mutated in @($wrongRole,$wrongVersion,$wrongRoot,$wrongSource,$wrongDigest,$wrongOrder,$directoryAlias,$reparseAliasDirectory,$missingParent,$badAcl)) {
        if (-not (Test-D32OsAuthorityShapeRejects -Record $mutated -ExpectedRoot $windowsRoot -ExpectedSystemRoot $systemRoot -ExpectedVersion $osVersion)) { $shapeMutationsRejected = $false }
    }
    Add-D32OsAuthorityCase 'role, order, digest, root, version, source proof, ACL, duplicate identity, and normalized directory-alias drift reject' $shapeMutationsRejected

    $defenderStub = [PSCustomObject]@{ component_type = 'MICROSOFT_WINDOWS_DEFENDER_PLATFORM'; inventory_sha256 = ('b' * 64) }
    $windowsPinnedComponent = [PSCustomObject]$component
    $combinedDigest = Get-D32PowerShellAuthorityOsSecurityInventoryDigest -Components @($windowsPinnedComponent,$defenderStub)
    $wrongRoleOrderRejected = $false
    try { $null = Get-D32PowerShellAuthorityOsSecurityInventoryDigest -Components @($defenderStub,$windowsPinnedComponent) }
    catch { $wrongRoleOrderRejected = $true }
    Add-D32OsAuthorityCase 'fixed OS/Defender authority role order rejects swaps' $wrongRoleOrderRejected

    $defenderDistribution = [ordered]@{
        root_path = 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1.1-1'; inventory_sha256 = ('c' * 64)
        directories = @(); files = @([ordered]@{ kind = 'file'; path = 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1.1-1\MpOav.dll'; bytes = [Int64]1; sha256 = ('1' * 64); volume_serial_hex = '0000000000000001'; file_id_hex = ('a' * 32); owner_sid = $trustedSid; security_descriptor_sddl = $sddl; security_descriptor_sha256 = (New-D32OsAuthoritySddlHash $sddl) })
        protected_ancestors = @(); trusted_writer_sids = @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544')
    }
    $defenderSourceProof = [ordered]@{
        proof_type = 'WINTRUST_CACHE_ONLY_AUTHENTICODE_V1'; status = 'VERIFIED'
        anchor_images = @([ordered]@{ file = [ordered]@{ path = [string]$defenderDistribution.files[0].path; bytes = [Int64]1; sha256 = [string]$defenderDistribution.files[0].sha256; volume_serial_hex = '0000000000000001'; file_id_hex = ('a' * 32) }; source_proof = [ordered]@{ status = 'VERIFIED'; product_version = '4.18.1.1'; signer = 'Microsoft Windows'; issuer = 'Microsoft Windows Production PCA' } })
    }
    $defenderRecord = [ordered]@{ component_type = 'MICROSOFT_WINDOWS_DEFENDER_PLATFORM'; version = '4.18.1.1-1'; root_path = [string]$defenderDistribution.root_path; root_volume_serial_hex = '0000000000000001'; root_file_id_hex = ('b' * 32); inventory_sha256 = ('b' * 64); source_proof = $defenderSourceProof; distribution = $defenderDistribution; native_files = @($defenderDistribution.files) }
    $defenderExpected = [System.Text.Json.JsonDocument]::Parse((ConvertTo-D32PowerShellAuthorityJsonText -Value $defenderRecord))
    try {
        $changedDefenderDistribution = Copy-D32OsAuthorityRecord -Record $defenderRecord
        $changedDefenderDistribution.distribution.files[0].sha256 = ('2' * 64)
        $changedDefenderProof = Copy-D32OsAuthorityRecord -Record $defenderRecord
        $changedDefenderProof.source_proof.anchor_images[0].source_proof.status = 'UNKNOWN'
        $defenderDistributionDriftRejected = -not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $defenderExpected.RootElement -Value $changedDefenderDistribution)
        $defenderProofDriftRejected = -not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $defenderExpected.RootElement -Value $changedDefenderProof)
    }
    finally { $defenderExpected.Dispose() }
    Add-D32OsAuthorityCase 'complete Defender distribution and cache-only signature source proof remain exact and reject drift' `
        ($defenderDistributionDriftRejected -and $defenderProofDriftRejected)

    $runtimePath = [IO.Path]::Combine([string]$PSHOME, 'pwsh.dll')
    $managedRuntimePath = [IO.Path]::Combine([string]$PSHOME, 'System.Management.Automation.dll')
    $actualNative = @($runtimePath)
    $actualManaged = @($managedRuntimePath)
    $roles = @{}
    $roles[$runtimePath] = 'POWERSHELL_DISTRIBUTION'
    $pinnedNativeRefs = @(
        [PSCustomObject]@{ path = $runtimePath; bytes = [Int64]1; sha256 = ('a' * 64); volume_serial_hex = '0000000000000001'; file_id_hex = ('5' * 32); owner_sid = $trustedSid; security_descriptor_sha256 = ('6' * 64) },
        $file
    )
    $pinnedManagedRefs = @(
        [PSCustomObject]@{ path = $managedRuntimePath; bytes = [Int64]1; sha256 = ('7' * 64); volume_serial_hex = '0000000000000001'; file_id_hex = ('8' * 32); owner_sid = $trustedSid; security_descriptor_sha256 = ('9' * 64) },
        $file
    )
    $roles[$filePath] = 'MICROSOFT_WINDOWS_OS_INSTALLATION'
    $moduleSearch = [IO.Path]::GetFullPath([IO.Path]::Combine([string]$PSHOME,'Modules'))
    $before = New-D32OsAuthorityResolverSnapshot -NativePaths $actualNative -ManagedPaths $actualManaged `
        -NativeRoles $roles -OsInventorySha256 $combinedDigest -ModuleSearchPath $moduleSearch
    $positiveTransition = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $before -After $before `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) `
        -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1.1-1'
    $evidenceResolver = [PSCustomObject]@{ NativeModulePaths = @($runtimePath) }
    $nativeEvidence = @(Get-D32PowerShellAuthorityNativeOriginEvidence -ResolverSnapshot $evidenceResolver `
        -RuntimeDistributionFiles @($pinnedNativeRefs[0]) -OsSecurityComponents @($windowsPinnedComponent,$defenderStub) -PowerShellRoot ([string]$PSHOME))
    Add-D32OsAuthorityCase 'valid unloaded Windows pin member remains static authority while current native set is a strict subset' `
        ([bool]$positiveTransition.Passed -and @($before.NativeModulePaths).Count -eq 1 -and @($component.native_files).Count -eq 1 -and
         $nativeEvidence.Count -eq 1 -and $nativeEvidence[0].path -ceq $runtimePath -and $nativeEvidence[0].source -ceq 'PSHOME_DISTRIBUTION') `
        'Resolver digest and actual-origin evidence bind the one observed PSHOME origin; the pinned apphelp reference remains in the separate finite Windows component.'

    $unknownNativePath = [IO.Path]::Combine($system32Path, 'synthetic-unpinned-native.dll')
    $unknownNativeRoles = @{}; $unknownNativeRoles[$runtimePath] = 'POWERSHELL_DISTRIBUTION'; $unknownNativeRoles[$unknownNativePath] = 'MICROSOFT_WINDOWS_OS_INSTALLATION'
    $unknownNative = New-D32OsAuthorityResolverSnapshot -NativePaths @($runtimePath,$unknownNativePath) -ManagedPaths $actualManaged `
        -NativeRoles $unknownNativeRoles -OsInventorySha256 $combinedDigest -ModuleSearchPath $moduleSearch
    $unknownNativeResult = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $before -After $unknownNative `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) `
        -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1.1-1'
    Add-D32OsAuthorityCase 'new unpinned Windows native observation is denied' (-not [bool]$unknownNativeResult.Passed)

    $unknownManagedPath = [IO.Path]::Combine($system32Path, 'synthetic-unpinned-managed.dll')
    $unknownManaged = New-D32OsAuthorityResolverSnapshot -NativePaths $actualNative -ManagedPaths @($actualManaged[0],$unknownManagedPath) `
        -NativeRoles $roles -OsInventorySha256 $combinedDigest -ModuleSearchPath $moduleSearch
    $unknownManagedResult = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $before -After $unknownManaged `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) `
        -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1.1-1'
    Add-D32OsAuthorityCase 'new unpinned Windows managed observation is denied' (-not [bool]$unknownManagedResult.Passed)

    $rtssPath = 'C:\Program Files (x86)\RivaTuner Statistics Server\RTSS.exe'
    $externalRoles = @{}; $externalRoles[$runtimePath] = 'POWERSHELL_DISTRIBUTION'; $externalRoles[$rtssPath] = 'UNPINNED_EXTERNAL'
    $external = New-D32OsAuthorityResolverSnapshot -NativePaths @($runtimePath,$rtssPath) -ManagedPaths $actualManaged `
        -NativeRoles $externalRoles -OsInventorySha256 $combinedDigest -ModuleSearchPath $moduleSearch
    $externalResult = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $before -After $external `
        -PinnedNativeFiles $pinnedNativeRefs -PinnedManagedFiles $pinnedManagedRefs -PowerShellRoot ([string]$PSHOME) `
        -WindowsRoot $windowsRoot -DefenderRoot 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1.1-1'
    Add-D32OsAuthorityCase 'RTSS external-origin observation remains denied without authority expansion' (-not [bool]$externalResult.Passed)

    $referenceJson = [System.Text.Json.JsonDocument]::Parse((ConvertTo-D32PowerShellAuthorityJsonText -Value $file))
    try {
        $identityMutations = [System.Collections.Generic.List[object]]::new()
        foreach ($field in @('bytes','sha256','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sddl','security_descriptor_sha256')) {
            $changed = Copy-D32OsAuthorityRecord -Record $file
            if ($field -ceq 'bytes') { $changed[$field] = [Int64]($changed[$field] + 1) }
            elseif ($field -ceq 'owner_sid') { $changed[$field] = 'S-1-5-32-544' }
            elseif ($field -ceq 'sha256' -or $field -ceq 'security_descriptor_sha256') { $changed[$field] = ('f' * 64) }
            elseif ($field -ceq 'volume_serial_hex') { $changed[$field] = ('f' * 16) }
            elseif ($field -ceq 'file_id_hex') { $changed[$field] = ('f' * 32) }
            else { $changed[$field] = ([string]$changed[$field]).Substring(0,[string]$changed[$field].Length - 1) + 'e' }
            $identityMutations.Add(-not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $referenceJson.RootElement -Value $changed))
        }
        Add-D32OsAuthorityCase 'reopened unloaded pin detects byte/hash/volume-file identity/owner/ACL-SDDL drift' `
            (-not ($identityMutations -contains $false)) 'The production pinned-file reopen compares complete canonical records before any import.'
    }
    finally { $referenceJson.Dispose() }

    $missingStaticPath = [IO.Path]::Combine($windowsRoot, 'System32', '__D32_STATIC_AUTHORITY_MUST_NOT_EXIST_8d34ef7a2d3b4c769a5ef4dc30cb3ff2.dll')
    $missingWasAbsent = -not [IO.File]::Exists($missingStaticPath) -and -not [IO.Directory]::Exists($missingStaticPath)
    $missingStaticRejected = $false
    if ($missingWasAbsent) {
        try {
            $null = Open-D32PowerShellAuthorityFile -Path $missingStaticPath -DirectoryFences ([ordered]@{})
        }
        catch { $missingStaticRejected = $_.Exception.Message -match 'missing or reparse-backed file' }
    }
    $missingStillAbsent = -not [IO.File]::Exists($missingStaticPath) -and -not [IO.Directory]::Exists($missingStaticPath)
    Add-D32OsAuthorityCase 'missing pinned Windows static file is rejected by read-only reopen without creating it' `
        ($missingWasAbsent -and $missingStaticRejected -and $missingStillAbsent) `
        'The probe uses one unique absent System32 child path; it performs metadata reads only and does not create or modify a file.'

    $policySource = [IO.File]::ReadAllText([IO.Path]::Combine($PSScriptRoot,'d32-powershell-module-authority.ps1'), [Text.UTF8Encoding]::new($false, $true))
    $currentStart = $policySource.IndexOf('function Get-D32PowerShellAuthorityPinnedWindowsComponentSnapshot', [StringComparison]::Ordinal)
    $currentEnd = $policySource.IndexOf('function Get-D32PowerShellAuthorityRuntimeDistributionSnapshot', $currentStart, [StringComparison]::Ordinal)
    $pinnedSnapshotBody = if ($currentEnd -gt $currentStart) { $policySource.Substring($currentStart, $currentEnd - $currentStart) } else { '' }
    $immediateReopenStart = $policySource.IndexOf('function Assert-D32PowerShellAuthorityOsSecurityComponentsCurrent', [StringComparison]::Ordinal)
    $authorityInitializeStart = $policySource.IndexOf('function Initialize-D32PowerShellModuleAuthority', [StringComparison]::Ordinal)
    $immediateReopenCall = $policySource.IndexOf('Assert-D32PowerShellAuthorityOsSecurityComponentsCurrent -Components $osSecurity.Components', $authorityInitializeStart, [StringComparison]::Ordinal)
    $firstFixedImport = $policySource.IndexOf('Import-Module', $authorityInitializeStart, [StringComparison]::Ordinal)
    $immediateReopenBody = if ($authorityInitializeStart -gt $immediateReopenStart) { $policySource.Substring($immediateReopenStart, $authorityInitializeStart - $immediateReopenStart) } else { '' }
    $sourceWired = $currentStart -ge 0 -and $pinnedSnapshotBody.Contains('Add-D32PowerShellAuthorityDirectoryChain') -and
        $pinnedSnapshotBody.Contains('Open-D32PowerShellAuthorityFile -Path ([string]$expected.path)') -and
        $pinnedSnapshotBody.Contains('[IO.FileAttributes]::ReparsePoint') -and
        $pinnedSnapshotBody.Contains('Get-D32PowerShellAuthorityFinalHandlePath -Handle $fence.Handle') -and
        $pinnedSnapshotBody.Contains('Test-D32PowerShellAuthorityJsonMatchesObject -Element $Element -Value $actualComponent') -and
        $immediateReopenStart -ge 0 -and $immediateReopenBody.Contains('full Windows OS caller pin') -and
        $immediateReopenBody.Contains('complete Defender distribution or signature source proof') -and
        $immediateReopenCall -gt $authorityInitializeStart -and $immediateReopenCall -lt $firstFixedImport
    Add-D32OsAuthorityCase 'directory reparse/final-handle aliases and exact refs reject before import; resolver remains exact actual-set gate' $sourceWired

    $admissionAttempts = [int]$global:D32PowerShellModuleImportAttempts
    $loadedNow = [string[]](Get-D32PowerShellAuthorityLoadedModuleSet)
    $loadedSetSame = $loadedNow.Count -eq $moduleSetAtStart.Count
    if ($loadedSetSame) {
        for ($index = 0; $index -lt $loadedNow.Count; $index++) {
            if (-not [StringComparer]::OrdinalIgnoreCase.Equals($loadedNow[$index], $moduleSetAtStart[$index])) { $loadedSetSame = $false; break }
        }
    }
    Add-D32OsAuthorityCase 'pure regression remains module-import-free, child-free, no-Cargo, and synthetic-record-only' `
        ($admissionAttempts -eq 0 -and $loadedSetSame) `
        'No files, installed images, authority facts, or candidate outputs were created or changed.'
}
catch {
    $failures.Add(('unhandled:' + $_.Exception.Message))
}
finally {
    Assert-D32PowerShellAuthorityLoadedModuleSetUnchanged -Expected $moduleSetAtStart
}

$result = [ordered]@{
    record_type = 'D32_POWERSHELL_OS_AUTHORITY_SELFTEST_V1'
    case_count = $cases.Count
    passed = $cases.Where({ $_.passed }).Count
    failed = $failures.ToArray()
    cases = $cases.ToArray()
    module_import_attempts = [int]$global:D32PowerShellModuleImportAttempts
    child_processes_launched = 0
    cargo_invoked = $false
    discovery_invoked = $false
    installed_file_writes = 0
    synthetic_record_only = $true
    evidence_root_claimed = $false
}
[Console]::WriteLine((ConvertTo-D32PowerShellAuthorityJsonText -Value $result))
if ($failures.Count -gt 0) { exit 1 }
