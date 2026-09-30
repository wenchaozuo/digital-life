function Test-D32PowerShellAuthorityPathNoReparse {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
        $root = [IO.Path]::GetPathRoot($fullPath)
        if ([String]::IsNullOrWhiteSpace($root)) { return $false }
        $current = $root
        $segments = $fullPath.Substring($root.Length).Split([IO.Path]::DirectorySeparatorChar, [StringSplitOptions]::RemoveEmptyEntries)
        foreach ($segment in $segments) {
            $current = [IO.Path]::Combine($current, $segment)
            if (-not [IO.Directory]::Exists($current) -and -not [IO.File]::Exists($current)) { return $false }
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Get-D32PowerShellAuthorityOpenedBytes {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-D32PowerShellAuthorityPathNoReparse -Path $Path)) {
        throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned file is missing or reparse-backed: $Path"
    }
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt [Int32]::MaxValue) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned file has an invalid length'
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned file changed while being read' }
            $offset += $read
        }
        if ($stream.Position -ne $stream.Length) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned file length changed while being read' }
        return [PSCustomObject]@{ Stream = $stream; Bytes = $bytes }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Assert-D32PowerShellAuthorityModuleInventory {
    param([Parameter(Mandatory = $true)][string]$ModuleRoot)

    $canonicalModuleRoot = [IO.Path]::GetFullPath($ModuleRoot)
    if ($PSModuleAutoLoadingPreference -cne 'None' -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$env:PSModulePath), $canonicalModuleRoot)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: automatic import or ambient module search path was re-enabled'
    }
    $expected = @{
        'Microsoft.PowerShell.Management' = [IO.Path]::GetFullPath([IO.Path]::Combine($canonicalModuleRoot, 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Management.psd1'))
        'Microsoft.PowerShell.Utility' = [IO.Path]::GetFullPath([IO.Path]::Combine($canonicalModuleRoot, 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Utility.psd1'))
        'CimCmdlets' = [IO.Path]::GetFullPath([IO.Path]::Combine([IO.Path]::GetDirectoryName($canonicalModuleRoot), 'Microsoft.Management.Infrastructure.CimCmdlets.dll'))
    }
    $moduleInfos = @(Microsoft.PowerShell.Core\Get-Module)
    foreach ($moduleInfo in $moduleInfos) {
        if ($moduleInfo.Name -ceq 'Microsoft.PowerShell.Core') { continue }
        if (-not $expected.ContainsKey([string]$moduleInfo.Name)) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: unapproved preloaded module: $($moduleInfo.Name)"
        }
        if ([String]::IsNullOrWhiteSpace([string]$moduleInfo.Path) -or
            -not (Test-D32PowerShellAuthorityPathNoReparse -Path ([string]$moduleInfo.Path)) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$moduleInfo.Path), [string]$expected[[string]$moduleInfo.Name])) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: module path is outside its exact caller-pinned module root: $($moduleInfo.Name)"
        }
    }
    foreach ($name in $expected.Keys) {
        $matches = @(Microsoft.PowerShell.Core\Get-Module -Name $name)
        if ($matches.Count -ne 1) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: exact trusted module is not uniquely loaded: $name" }
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$matches[0].Path), [string]$expected[$name])) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: loaded module path does not match its exact manifest: $name"
        }
    }
}

function Initialize-D32PowerShellModuleAuthority {
    [CmdletBinding()]
    param(
        [AllowNull()][string]$CallerProfilePath,
        [AllowNull()][string]$CallerExpectedProfileSha256,
        [switch]$LocalSelfTestOnly
    )

    $priorAutoLoadingPreference = [string]$PSModuleAutoLoadingPreference
    $global:PSModuleAutoLoadingPreference = 'None'
    $state = $global:D32PowerShellModuleAuthorityState
    if ($null -ne $state) {
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$PSHOME), [string]$state.PowerShellRoot) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$env:PSModulePath), [string]$state.ModuleRoot) -or
            $priorAutoLoadingPreference -cne 'None') {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: process module authority changed after initialization'
        }
        Assert-D32PowerShellAuthorityModuleInventory -ModuleRoot ([string]$state.ModuleRoot)
        if (-not [String]::IsNullOrWhiteSpace($CallerExpectedProfileSha256) -and
            $CallerExpectedProfileSha256 -cne [string]$state.ProfileSha256) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: repeated loader supplied a different caller profile pin'
        }
        return $state
    }

    $loadedBeforeAdmission = @(Microsoft.PowerShell.Core\Get-Module)
    if ($loadedBeforeAdmission.Count -gt 0) {
        $loadedNames = [System.Collections.Generic.List[string]]::new()
        foreach ($loadedModule in $loadedBeforeAdmission) { $loadedNames.Add([string]$loadedModule.Name) }
        throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runner must start in a fresh PowerShell process with no imported modules (found: $($loadedNames -join ', '))"
    }
    $processArguments = [Environment]::GetCommandLineArgs()
    $noProfileIndex = -1
    $fileModeIndex = -1
    $commandModeIndex = -1
    for ($argumentIndex = 1; $argumentIndex -lt $processArguments.Length; $argumentIndex++) {
        $processArgument = [string]$processArguments[$argumentIndex]
        if ($noProfileIndex -lt 0 -and
            ([StringComparer]::OrdinalIgnoreCase.Equals($processArgument, '-NoProfile') -or
                [StringComparer]::OrdinalIgnoreCase.Equals($processArgument, '-nop'))) {
            $noProfileIndex = $argumentIndex
        }
        if ($fileModeIndex -lt 0 -and
            ([StringComparer]::OrdinalIgnoreCase.Equals($processArgument, '-File') -or
                [StringComparer]::OrdinalIgnoreCase.Equals($processArgument, '-f'))) {
            $fileModeIndex = $argumentIndex
        }
        if ($commandModeIndex -lt 0 -and
            ([StringComparer]::OrdinalIgnoreCase.Equals($processArgument, '-Command') -or
                [StringComparer]::OrdinalIgnoreCase.Equals($processArgument, '-c') -or
                [StringComparer]::OrdinalIgnoreCase.Equals($processArgument, '-EncodedCommand') -or
                [StringComparer]::OrdinalIgnoreCase.Equals($processArgument, '-ec') -or
                [StringComparer]::OrdinalIgnoreCase.Equals($processArgument, '-CommandWithArgs') -or
                [StringComparer]::OrdinalIgnoreCase.Equals($processArgument, '-cwa'))) {
            $commandModeIndex = $argumentIndex
        }
    }
    $noProfileWasPinned = $noProfileIndex -gt 0 -and $fileModeIndex -gt $noProfileIndex -and
        ($commandModeIndex -lt 0 -or $fileModeIndex -lt $commandModeIndex)
    if (-not $noProfileWasPinned) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: runner process must start with -NoProfile before PowerShell -File mode'
    }

    $powerShellRoot = [IO.Path]::GetFullPath([string]$PSHOME)
    $profileSha256 = $null
    if ([String]::IsNullOrWhiteSpace($CallerProfilePath) -or [String]::IsNullOrWhiteSpace($CallerExpectedProfileSha256)) {
        # Only explicit no-Cargo selftests may start without an external Profile V2 pin.
        # Library-only imports reuse an authority state already established by their caller.
        if (-not $LocalSelfTestOnly) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: a caller-pinned Profile V2 path and SHA are required before module loading'
        }
    }
    else {
        if ($CallerExpectedProfileSha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: caller Profile V2 SHA must be exact lowercase SHA-256'
        }
        if (-not [IO.Path]::IsPathRooted($CallerProfilePath)) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: caller Profile V2 path must be absolute'
        }
        $profilePath = [IO.Path]::GetFullPath($CallerProfilePath)
        $profileSnapshot = Get-D32PowerShellAuthorityOpenedBytes -Path $profilePath
        $profileSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$profileSnapshot.Bytes)).ToLowerInvariant()
        if ($profileSha256 -cne $CallerExpectedProfileSha256) {
            $profileSnapshot.Stream.Dispose()
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: caller Profile V2 bytes do not match its pinned SHA'
        }
        $profileDocument = $null
        try {
            $profileText = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$profileSnapshot.Bytes)
            $profileDocument = [System.Text.Json.JsonDocument]::Parse([string]$profileText)
            $profileObject = $profileDocument.RootElement
            if ($profileObject.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                $profileObject.GetProperty('schema_version').GetInt32() -ne 2 -or
                $profileObject.GetProperty('profile_type').GetString() -cne 'D32_BUILD_TOOLCHAIN_PROFILE_V2') {
                throw 'caller Profile V2 type or version is invalid'
            }
            $profilePowerShellRoot = [IO.Path]::GetFullPath($profileObject.GetProperty('powershell_root').GetString())
            $profilePowerShell = $profileObject.GetProperty('powershell')
            $profilePowerShellPath = [IO.Path]::GetFullPath($profilePowerShell.GetProperty('path').GetString())
            $profilePowerShellSha = $profilePowerShell.GetProperty('sha256').GetString()
            $profilePowerShellBytes = $profilePowerShell.GetProperty('bytes').GetInt64()
            $actualPowerShellPath = [IO.Path]::GetFullPath([IO.Path]::Combine($powerShellRoot, 'pwsh.exe'))
            if (-not [StringComparer]::OrdinalIgnoreCase.Equals($profilePowerShellRoot, $powerShellRoot) -or
                -not [StringComparer]::OrdinalIgnoreCase.Equals($profilePowerShellPath, $actualPowerShellPath)) {
                throw 'caller-pinned PowerShell root or image path does not match this process'
            }
            $hostSnapshot = Get-D32PowerShellAuthorityOpenedBytes -Path $actualPowerShellPath
            $hostSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$hostSnapshot.Bytes)).ToLowerInvariant()
            if ($hostSnapshot.Bytes.LongLength -ne $profilePowerShellBytes -or $hostSha -cne $profilePowerShellSha) {
                $hostSnapshot.Stream.Dispose()
                throw 'running PowerShell image bytes or SHA differ from the caller-pinned Profile V2'
            }
            $hostProcess = [Diagnostics.Process]::GetCurrentProcess()
            try {
                $mainModulePath = [IO.Path]::GetFullPath([string]$hostProcess.MainModule.FileName)
                if (-not [StringComparer]::OrdinalIgnoreCase.Equals($mainModulePath, $actualPowerShellPath)) {
                    $hostSnapshot.Stream.Dispose()
                    throw 'current PowerShell process image path differs from the caller-pinned Profile V2'
                }
            }
            finally { $hostProcess.Dispose() }
            $powerShellRoot = $profilePowerShellRoot
            $global:D32PowerShellModuleAuthorityHostStream = $hostSnapshot.Stream
        }
        catch {
            $profileSnapshot.Stream.Dispose()
            if ($null -ne $profileDocument) { $profileDocument.Dispose() }
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: caller Profile V2 could not establish the PowerShell runtime root: $($_.Exception.Message)"
        }
        if ($null -ne $profileDocument) { $profileDocument.Dispose() }
        $global:D32PowerShellModuleAuthorityProfileStream = $profileSnapshot.Stream
    }

    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$PSHOME), $powerShellRoot) -or
        -not (Test-D32PowerShellAuthorityPathNoReparse -Path $powerShellRoot)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: PowerShell root is not a canonical non-reparse directory'
    }
    $moduleRoot = [IO.Path]::GetFullPath([IO.Path]::Combine($powerShellRoot, 'Modules'))
    if (-not (Test-D32PowerShellAuthorityPathNoReparse -Path $moduleRoot)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: PowerShell module root is missing or reparse-backed'
    }
    $env:PSModulePath = $moduleRoot

    $moduleManifests = @(
        [IO.Path]::Combine($moduleRoot, 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Management.psd1'),
        [IO.Path]::Combine($moduleRoot, 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Utility.psd1'),
        [IO.Path]::Combine($moduleRoot, 'CimCmdlets', 'CimCmdlets.psd1')
    )
    foreach ($manifestPath in $moduleManifests) {
        $manifestPath = [IO.Path]::GetFullPath($manifestPath)
        if (-not (Test-D32PowerShellAuthorityPathNoReparse -Path $manifestPath)) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: exact trusted module manifest is missing or reparse-backed: $manifestPath"
        }
        Microsoft.PowerShell.Core\Import-Module -Name $manifestPath -ErrorAction Stop
    }
    Assert-D32PowerShellAuthorityModuleInventory -ModuleRoot $moduleRoot
    $global:D32PowerShellModuleAuthorityState = [PSCustomObject]@{
        PowerShellRoot = $powerShellRoot
        ModuleRoot = $moduleRoot
        ProfileSha256 = $profileSha256
        ModuleNames = @('Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility', 'CimCmdlets')
    }
    return $global:D32PowerShellModuleAuthorityState
}
