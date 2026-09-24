#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][string]$RustToolchainRoot,
    [Parameter(Mandatory = $true)][string]$MsvcRoot,
    [Parameter(Mandatory = $true)][string]$WindowsSdkRoot,
    [Parameter(Mandatory = $true)][string[]]$MsvcPathEntry,
    [Parameter(Mandatory = $true)][string[]]$WindowsSdkPathEntry,
    [Parameter(Mandatory = $true)][string[]]$MsvcIncludeDirectory,
    [Parameter(Mandatory = $true)][string[]]$WindowsSdkIncludeDirectory,
    [Parameter(Mandatory = $true)][string[]]$MsvcLibDirectory,
    [Parameter(Mandatory = $true)][string[]]$WindowsSdkLibDirectory,
    [Parameter(Mandatory = $true)][string[]]$MsvcLibPathDirectory,
    [Parameter(Mandatory = $true)][string[]]$WindowsSdkLibPathDirectory,
    [Parameter(Mandatory = $true)][string]$VCToolsVersion,
    [Parameter(Mandatory = $true)][string]$WindowsSDKVersion,
    [string]$VCToolsRedistDir,
    [string]$VSInstallDir,
    [string]$VisualStudioVersion,
    [string]$VscmdVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'd32-build-toolchain-profile.ps1')

function Get-CandidateDirectoryList {
    param([Parameter(Mandatory = $true)][string[]]$Path, [Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][string]$Root)
    if ($Path.Count -eq 0) { throw "$Name must contain at least one explicit directory" }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $result = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $Path) {
        if (-not (Test-D32ProfileCanonicalPathString -Path $item)) { throw "$Name contains a non-canonical path: $item" }
        $full = Assert-D32ProfileDirectory -Path $item
        if (-not (Test-D32ProfilePathWithin -Child $full -Parent $Root)) { throw "$Name is outside its explicitly approved root: $full" }
        if (-not $seen.Add($full)) { throw "$Name contains a duplicate directory: $full" }
        $result.Add($full)
    }
    return @($result.ToArray())
}

function ConvertTo-CandidateIdentity {
    param([Parameter(Mandatory = $true)][object]$Snapshot, [Parameter(Mandatory = $true)][string]$Reason)
    return [ordered]@{
        name = [IO.Path]::GetFileName([string]$Snapshot.Path)
        path = [string]$Snapshot.Path
        sha256 = [string]$Snapshot.Sha256
        bytes = [Int64]$Snapshot.Bytes
        volume_serial_hex = [string]$Snapshot.VolumeSerialHex
        file_id_hex = [string]$Snapshot.FileIdHex
        reason = $Reason
    }
}

$repoFull = Assert-D32ProfileDirectory -Path $Repository
$outputFull = [IO.Path]::GetFullPath($OutputPath)
if (-not (Test-D32ProfileCanonicalPathString -Path $OutputPath)) { throw 'OutputPath must already be canonical' }
$outputParent = [IO.Path]::GetDirectoryName($outputFull)
if (-not (Test-D32ProfileNoReparsePath -Path $outputParent) -or -not (Test-D32ProfileNoReparsePath -Path $outputFull -AllowMissingLeaf)) { throw 'profile candidate destination parent must be a non-reparse directory and the leaf must be absent' }
if ((Test-D32ProfilePathWithin -Child $outputFull -Parent $repoFull) -or (Test-D32ProfilePathWithin -Child $repoFull -Parent $outputFull)) { throw 'profile candidate must be external to and non-overlapping with the repository' }
if (Test-Path -LiteralPath $outputFull) { throw "PROFILE_CANDIDATE_NOT_NEW: refusing to overwrite $outputFull" }

$rustRoot = Assert-D32ProfileDirectory -Path $RustToolchainRoot
$rustBin = Assert-D32ProfileDirectory -Path (Join-Path $rustRoot 'bin')
$msvcFull = Assert-D32ProfileDirectory -Path $MsvcRoot
$sdkFull = Assert-D32ProfileDirectory -Path $WindowsSdkRoot
$nativeMsvcPath = @(Get-CandidateDirectoryList -Path $MsvcPathEntry -Name 'MsvcPathEntry' -Root $msvcFull)
$nativeSdkPath = @(Get-CandidateDirectoryList -Path $WindowsSdkPathEntry -Name 'WindowsSdkPathEntry' -Root $sdkFull)
$msvcIncludes = @(Get-CandidateDirectoryList -Path $MsvcIncludeDirectory -Name 'MsvcIncludeDirectory' -Root $msvcFull)
$sdkIncludes = @(Get-CandidateDirectoryList -Path $WindowsSdkIncludeDirectory -Name 'WindowsSdkIncludeDirectory' -Root $sdkFull)
$msvcLibs = @(Get-CandidateDirectoryList -Path $MsvcLibDirectory -Name 'MsvcLibDirectory' -Root $msvcFull)
$sdkLibs = @(Get-CandidateDirectoryList -Path $WindowsSdkLibDirectory -Name 'WindowsSdkLibDirectory' -Root $sdkFull)
$msvcLibPaths = @(Get-CandidateDirectoryList -Path $MsvcLibPathDirectory -Name 'MsvcLibPathDirectory' -Root $msvcFull)
$sdkLibPaths = @(Get-CandidateDirectoryList -Path $WindowsSdkLibPathDirectory -Name 'WindowsSdkLibPathDirectory' -Root $sdkFull)
$pathEntries = @($nativeMsvcPath) + @($nativeSdkPath)
$allPathDirectories = @($rustBin) + @($pathEntries)
$allNativeRoots = @($rustRoot, $msvcFull, $sdkFull)

$windowsRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows))
$powerShellPath = Get-D32CurrentPowerShellImagePath
$powerShellRoot = [IO.Path]::GetDirectoryName($powerShellPath)
$powershellPin = ConvertTo-CandidateIdentity -Snapshot (Get-D32ProfileFileSnapshot -Path $powerShellPath) -Reason 'direct pinned PowerShell host executable'
$cargo = ConvertTo-CandidateIdentity -Snapshot (Get-D32ProfileFileSnapshot -Path (Join-Path $rustBin 'cargo.exe')) -Reason 'direct pinned cargo executable'
$rustc = ConvertTo-CandidateIdentity -Snapshot (Get-D32ProfileFileSnapshot -Path (Join-Path $rustBin 'rustc.exe')) -Reason 'direct pinned rustc executable'
$rustdoc = ConvertTo-CandidateIdentity -Snapshot (Get-D32ProfileFileSnapshot -Path (Join-Path $rustBin 'rustdoc.exe')) -Reason 'direct pinned rustdoc executable'
$rustImages = @(Get-D32ProfileCurrentExecutableInventory -Directories @($rustBin) | ForEach-Object { ConvertTo-CandidateIdentity -Snapshot $_ -Reason 'caller-pinned Rust toolchain PATH executable' })
$nativeImages = @(Get-D32ProfileCurrentExecutableInventory -Directories $pathEntries | ForEach-Object { ConvertTo-CandidateIdentity -Snapshot $_ -Reason 'caller-pinned MSVC/Windows SDK PATH executable' })
$pathScripts = @(Get-D32ProfileCurrentScriptInventory -Directories $allPathDirectories | ForEach-Object { ConvertTo-CandidateIdentity -Snapshot $_ -Reason 'dormant script inventory only; never launchable' })
$conhost = ConvertTo-CandidateIdentity -Snapshot (Get-D32ProfileFileSnapshot -Path (Join-Path $windowsRoot 'System32\conhost.exe')) -Reason 'direct pinned Windows console host child image'
$locks = @(Get-D32BuildToolchainLockInputs -Repository $repoFull)

$nativeEnvironment = [ordered]@{
    VCToolsInstallDir = $msvcFull
    WindowsSdkDir = $sdkFull
    VCToolsVersion = $VCToolsVersion
    WindowsSDKVersion = $WindowsSDKVersion
    VSCMD_ARG_TGT_ARCH = 'x64'
}
if ($VCToolsRedistDir) { $nativeEnvironment.VCToolsRedistDir = Assert-D32ProfileDirectory -Path $VCToolsRedistDir }
if ($VSInstallDir) { $nativeEnvironment.VSINSTALLDIR = Assert-D32ProfileDirectory -Path $VSInstallDir }
if ($VisualStudioVersion) { $nativeEnvironment.VisualStudioVersion = $VisualStudioVersion }
if ($VscmdVersion) { $nativeEnvironment.VSCMD_VER = $VscmdVersion }

$profile = [ordered]@{
    schema_version = 2
    profile_type = 'D32_BUILD_TOOLCHAIN_PROFILE_V2'
    target_triple = 'x86_64-pc-windows-msvc'
    system_root = $windowsRoot
    powershell_root = $powerShellRoot
    powershell = $powershellPin
    rust_toolchain_root = $rustRoot
    toolchain = [ordered]@{ cargo = $cargo; rustc = $rustc; rustdoc = $rustdoc }
    rust_toolchain_bin_images = @($rustImages)
    native_roots = @(
        [ordered]@{ name = 'msvc'; path = $msvcFull },
        [ordered]@{ name = 'windows-sdk'; path = $sdkFull }
    )
    native = [ordered]@{
        path_entries = @($pathEntries)
        include_dirs = @($msvcIncludes) + @($sdkIncludes)
        lib_dirs = @($msvcLibs) + @($sdkLibs)
        libpath_dirs = @($msvcLibPaths) + @($sdkLibPaths)
        environment = $nativeEnvironment
        path_images = @($nativeImages)
        path_scripts = @($pathScripts)
    }
    windows_child_images = @($conhost)
    fetch_manifests = @($locks | ForEach-Object { [ordered]@{ manifest_path = $_.ManifestPath; lock_sha256 = $_.LockSha256 } })
    fetch_git = $null
    env_policy = 'D32_BUILD_ENV_V1'
    cargo_policy = 'FRESH_HOME_LOCKED_FETCH_OFFLINE_AFTER'
}

$json = $profile | ConvertTo-Json -Depth 24
$stream = [IO.File]::Open($outputFull, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
try {
    $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
    try { $writer.Write($json); $writer.Flush(); $stream.Flush($true) }
    finally { $writer.Dispose() }
}
finally { $stream.Dispose() }
$snapshot = Get-D32ProfileFileSnapshot -Path $outputFull
$validation = Test-D32BuildToolchainProfile -ProfilePath $outputFull -ExpectedSha256 $snapshot.Sha256 -Repository $repoFull
if (-not $validation.IsValid) { throw "PROFILE_CANDIDATE_BLOCKED: newly created candidate failed strict v2 validation: $($validation.Failure); path=$outputFull" }
Write-Output "D32_PROFILE_CANDIDATE_PATH=$outputFull"
Write-Output "D32_PROFILE_CANDIDATE_SHA256=$($snapshot.Sha256)"
Write-Output 'D32_PROFILE_CANDIDATE_VERSION=2'
Write-Output "D32_PROFILE_RESIDENT_SCRIPTS=$($validation.ScriptInventory.Count) (dormant identity only; no launch authority)"
