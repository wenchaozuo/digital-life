# Emits an untrusted candidate only. The Coordinator must independently review
# it and provide a caller-side path/SHA pin before any runner will import modules.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][switch]$CreateNew,
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$CandidateSha,
    [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
    [Parameter(Mandatory = $true)][string]$ExpectedToolchainProfileSha256,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
$global:PSModuleAutoLoadingPreference = 'None'
$env:PSModulePath = [IO.Path]::GetFullPath([IO.Path]::Combine([string]$PSHOME, 'Modules'))
$global:D32PowerShellModuleImportAttempts = 0
$loadedModulesAtStart = Get-D32PowerShellAuthorityLoadedModuleSet
if ($CandidateSha -cnotmatch '^[0-9a-f]{40}$' -or $ExpectedToolchainProfileSha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw 'MODULE_AUTHORITY_CREATE_BLOCKED: candidate and Profile V2 SHA pins must be exact lowercase digests'
}
if (-not $CreateNew) { throw 'MODULE_AUTHORITY_CREATE_BLOCKED: only CreateNew candidate output is supported' }
$repo = [IO.Path]::GetFullPath($Repository)
$entry = [IO.Path]::GetFullPath($PSCommandPath)
$null = Get-D32PowerShellAuthorityProcessStartup -EntryScriptPath $entry
if ($repo -cne $Repository -or -not (Test-D32PowerShellAuthorityPathNoReparse -Path $repo)) { throw 'MODULE_AUTHORITY_CREATE_BLOCKED: repository path must be canonical and non-reparse' }
$profilePath = [IO.Path]::GetFullPath($ToolchainProfilePath)
$outputPathFull = [IO.Path]::GetFullPath($OutputPath)
if (-not [IO.Path]::IsPathRooted($ToolchainProfilePath) -or -not [IO.Path]::IsPathRooted($OutputPath) -or [IO.File]::Exists($outputPathFull) -or [IO.Directory]::Exists($outputPathFull)) {
    throw 'MODULE_AUTHORITY_CREATE_BLOCKED: exact absolute Profile path and absent CreateNew output path are required'
}
$directoryFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
$script:D32PowerShellAdmissionDirectoryFences = $directoryFences
$openFiles = [System.Collections.Generic.List[object]]::new()
$candidate = $null
try {
    $profile = Open-D32PowerShellAuthorityFile -Path $profilePath -DirectoryFences $directoryFences
    $openFiles.Add($profile)
    if ($profile.Record.sha256 -cne $ExpectedToolchainProfileSha256) { throw 'MODULE_AUTHORITY_CREATE_BLOCKED: Profile V2 bytes do not match the supplied SHA' }
    $profileDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$profile.Bytes))
    try {
        if ((Test-D32PowerShellAuthorityJsonDuplicates -Element $profileDocument.RootElement) -or $profileDocument.RootElement.GetProperty('schema_version').GetInt32() -ne 2 -or
            $profileDocument.RootElement.GetProperty('profile_type').GetString() -cne 'D32_BUILD_TOOLCHAIN_PROFILE_V2') { throw 'MODULE_AUTHORITY_CREATE_BLOCKED: Profile V2 is malformed or non-current' }
        $powerShellRoot = [IO.Path]::GetFullPath($profileDocument.RootElement.GetProperty('powershell_root').GetString())
        $hostElement = $profileDocument.RootElement.GetProperty('powershell')
        $hostPath = [IO.Path]::GetFullPath($hostElement.GetProperty('path').GetString())
        $profileHostSha = $hostElement.GetProperty('sha256').GetString()
        $profileHostBytes = $hostElement.GetProperty('bytes').GetInt64()
    }
    finally { $profileDocument.Dispose() }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($powerShellRoot, [IO.Path]::GetFullPath([string]$PSHOME)) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals($hostPath, [IO.Path]::Combine($powerShellRoot, 'pwsh.exe'))) { throw 'MODULE_AUTHORITY_CREATE_BLOCKED: Profile V2 does not identify this PowerShell host and PSHOME' }
    $hostImage = Open-D32PowerShellAuthorityFile -Path $hostPath -DirectoryFences $directoryFences
    $openFiles.Add($hostImage)
    if ($hostImage.Record.sha256 -cne $profileHostSha -or [Int64]$hostImage.Record.bytes -ne [Int64]$profileHostBytes) { throw 'MODULE_AUTHORITY_CREATE_BLOCKED: Profile V2 host image identity mismatch' }
    $rootPath = [IO.Path]::GetFullPath($powerShellRoot)
    $rootKey = $rootPath.TrimEnd([char[]]@('\','/'))
    if ($rootKey.Length -eq 2 -and $rootKey[1] -eq ':') { $rootKey += [IO.Path]::DirectorySeparatorChar }
    $root = $directoryFences[$rootKey]
    $distribution = Get-D32PowerShellAuthorityRuntimeDistributionSnapshot -PowerShellRoot $powerShellRoot -DirectoryFences $directoryFences -OpenFiles $openFiles
    $osSecurity = Get-D32PowerShellAuthorityCurrentOsSecurityComponents -ExpectedDefenderRoot '' -DirectoryFences $directoryFences -OpenFiles $openFiles
    $windowsRoot = [string]$osSecurity.WindowsRoot
    $resolverPolicy = [ordered]@{
        policy_id = 'D32_POWERSHELL_RESOLVER_DOMAIN_V2'
        managed_distribution_root = $powerShellRoot
        managed_os_root = $windowsRoot
        native_application_root = $powerShellRoot
        native_system_root = $windowsRoot
        native_search_flags = @('LOAD_LIBRARY_SEARCH_APPLICATION_DIR','LOAD_LIBRARY_SEARCH_SYSTEM32')
        forbidden_sources = @('CWD','PATH','USER_PSMODULEPATH','STARTUP_HOOKS','EXTERNAL_ASSEMBLIES','UNPINNED_DLL_DIRECTORIES')
        os_security_components = @($osSecurity.Components)
    }
    $modules = [System.Collections.Generic.List[object]]::new()
    $globalIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($role in (Get-D32PowerShellAuthorityFixedModuleRoles -PowerShellRoot $powerShellRoot)) {
        $expected = Get-D32PowerShellAuthorityExpectedModuleFiles -PowerShellRoot $powerShellRoot -Role $role
        $openFiles.Add($expected.Manifest)
        $fileRecords = [System.Collections.Generic.List[object]]::new()
        foreach ($path in $expected.Paths) {
            $snapshot = if ([StringComparer]::OrdinalIgnoreCase.Equals($path, [string]$expected.Manifest.Record.path)) { $expected.Manifest } else { Open-D32PowerShellAuthorityFile -Path $path -DirectoryFences $directoryFences }
            if (-not [StringComparer]::OrdinalIgnoreCase.Equals($path, [string]$snapshot.Record.path) -or
                -not $globalIds.Add(([string]$snapshot.Record.volume_serial_hex + ':' + [string]$snapshot.Record.file_id_hex))) { throw "MODULE_AUTHORITY_CREATE_BLOCKED: module closure contains a path alias: $path" }
            if (-not [StringComparer]::OrdinalIgnoreCase.Equals($path, [string]$expected.Manifest.Record.path)) { $openFiles.Add($snapshot) }
            $fileRecords.Add($snapshot.Record)
        }
        $files = $fileRecords.ToArray()
        $modules.Add([ordered]@{ role = [string]$role.Role; module_name = [string]$role.Name; manifest_path = [IO.Path]::GetFullPath([string]$role.Manifest); files = $files; inventory_sha256 = (Get-D32PowerShellAuthorityInventoryDigest -Role ([string]$role.Role) -Files $files) })
    }
    $candidate = [ordered]@{
        schema_version = 2
        authority_type = 'D32_POWERSHELL_MODULE_CONTENT_AUTHORITY_V2'
        status = 'CANDIDATE_FOR_COORDINATOR_PIN'
        gate_authority = 'NONE'
        candidate_sha = $CandidateSha
        source_repo = $repo
        profile = [ordered]@{ path = [string]$profile.Record.path; bytes = [Int64]$profile.Record.bytes; sha256 = [string]$profile.Record.sha256; volume_serial_hex = [string]$profile.Record.volume_serial_hex; file_id_hex = [string]$profile.Record.file_id_hex }
        powershell_host = [ordered]@{ path = [string]$hostImage.Record.path; bytes = [Int64]$hostImage.Record.bytes; sha256 = [string]$hostImage.Record.sha256; volume_serial_hex = [string]$hostImage.Record.volume_serial_hex; file_id_hex = [string]$hostImage.Record.file_id_hex }
        powershell_root = [ordered]@{ path = [string]$root.Path; volume_serial_hex = [string]$root.VolumeSerialHex; file_id_hex = [string]$root.FileIdHex }
        distribution = $distribution
        resolver_policy = $resolverPolicy
        modules = $modules.ToArray()
    }
}
finally {
    foreach ($file in $openFiles) { if ($null -ne $file.Stream) { $file.Stream.Dispose() } }
    foreach ($directory in $directoryFences.Values) { if ($null -ne $directory.Handle) { $directory.Handle.Dispose() } }
}

$json = ConvertTo-D32PowerShellAuthorityJsonText -Value $candidate
$bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
$outputParent = [IO.Path]::GetDirectoryName($outputPathFull)
if (-not [IO.Directory]::Exists($outputParent) -or -not (Test-D32PowerShellAuthorityPathNoReparse -Path $outputParent)) { throw 'MODULE_AUTHORITY_CREATE_BLOCKED: output parent must exist and be non-reparse' }
if ([int]$global:D32PowerShellModuleImportAttempts -ne 0) { throw 'MODULE_AUTHORITY_CREATE_BLOCKED: candidate generation attempted a module import' }
Assert-D32PowerShellAuthorityLoadedModuleSetUnchanged -Expected $loadedModulesAtStart
$stream = [IO.FileStream]::new($outputPathFull, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
finally { $stream.Dispose() }
[Console]::WriteLine(('MODULE_AUTHORITY_CANDIDATE_CREATED path={0} bytes={1} sha256={2} gate_authority=NONE', $outputPathFull, $bytes.Length, [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()))
