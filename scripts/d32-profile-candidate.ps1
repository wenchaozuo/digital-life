#Requires -Version 7.5
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

# Profile facts are deliberately collected without importing any PowerShell
# module. This is a candidate generator only; it does not self-authorize or
# claim that its output passed the independent Profile V2 validator.
. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
$global:PSModuleAutoLoadingPreference = 'None'
$null = Get-D32PowerShellAuthorityProcessStartup -EntryScriptPath $PSCommandPath
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$directoryFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
$openedFiles = [System.Collections.Generic.List[object]]::new()

function Assert-CandidateCanonicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path -cne $full) { throw "PROFILE_CANDIDATE_BLOCKED: path must be canonical and absolute: $Path" }
    return $full
}

function Assert-CandidateDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = Assert-CandidateCanonicalPath -Path $Path
    if (-not (Test-D32PowerShellAuthorityPathNoReparse -Path $full)) { throw "PROFILE_CANDIDATE_BLOCKED: directory is missing or traverses a reparse point: $full" }
    $attributes = [IO.File]::GetAttributes($full)
    if (($attributes -band [IO.FileAttributes]::Directory) -eq 0) { throw "PROFILE_CANDIDATE_BLOCKED: expected directory: $full" }
    return $full
}

function Assert-CandidateFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = Assert-CandidateCanonicalPath -Path $Path
    $snapshot = Open-D32PowerShellAuthorityFile -Path $full -DirectoryFences $script:directoryFences
    $script:openedFiles.Add($snapshot)
    return $snapshot
}

function ConvertTo-CandidateIdentity {
    param([Parameter(Mandatory = $true)][object]$Snapshot, [Parameter(Mandatory = $true)][string]$Reason)
    return [ordered]@{
        name = [IO.Path]::GetFileName([string]$Snapshot.Record.path)
        path = [string]$Snapshot.Record.path
        sha256 = [string]$Snapshot.Record.sha256
        bytes = [Int64]$Snapshot.Record.bytes
        volume_serial_hex = [string]$Snapshot.Record.volume_serial_hex
        file_id_hex = [string]$Snapshot.Record.file_id_hex
        reason = $Reason
    }
}

function Get-CandidateDirectoryList {
    param([Parameter(Mandatory = $true)][string[]]$Path, [Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][string]$Root)
    if ($Path.Count -eq 0) { throw "PROFILE_CANDIDATE_BLOCKED: $Name must contain at least one explicit directory" }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $result = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $Path) {
        $full = Assert-CandidateDirectory -Path $item
        if (-not (Test-D32PowerShellAuthorityPathWithin -Child $full -Parent $Root)) { throw "PROFILE_CANDIDATE_BLOCKED: $Name is outside its explicitly approved root: $full" }
        if (-not $seen.Add($full)) { throw "PROFILE_CANDIDATE_BLOCKED: $Name contains a duplicate directory: $full" }
        $result.Add($full)
    }
    return $result.ToArray()
}

function Get-CandidateDirectoryFileInventory {
    param([Parameter(Mandatory = $true)][string[]]$Directories, [Parameter(Mandatory = $true)][string[]]$Extensions, [Parameter(Mandatory = $true)][string]$Reason)
    $records = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($directory in $Directories) {
        $null = Assert-CandidateDirectory -Path $directory
        foreach ($path in [IO.Directory]::GetFiles($directory, '*', [IO.SearchOption]::TopDirectoryOnly)) {
            $extension = [IO.Path]::GetExtension($path)
            if ($extension -notin $Extensions) { continue }
            $full = [IO.Path]::GetFullPath($path)
            if (-not $seen.Add($full)) { throw "PROFILE_CANDIDATE_BLOCKED: duplicate directory inventory entry: $full" }
            if ([IO.Path]::GetFileName($full) -match '^(?i:git|ssh|ssh-agent|git-credential[^.]*)\.exe$') {
                throw "PROFILE_CANDIDATE_BLOCKED: Profile V2 may not expose Git/SSH/credential helper images: $full"
            }
            $records.Add((ConvertTo-CandidateIdentity -Snapshot (Assert-CandidateFile -Path $full) -Reason $Reason))
        }
    }
    return $records.ToArray()
}

function Get-CandidateGitSourceCount {
    param([Parameter(Mandatory = $true)][string]$Text)
    $count = 0
    foreach ($line in ($Text -split '\r?\n')) {
        if ($line -notmatch '^\s*source\s*=\s*"(git\+[^"\r\n]+)"\s*$') { continue }
        $source = [string]$Matches[1]
        if ($source -notmatch '#([0-9a-f]{40})$') { throw 'PROFILE_CANDIDATE_BLOCKED: Cargo.lock contains a Git source without a full immutable 40-hex commit object ID' }
        $commit = [string]$Matches[1]
        if ($source -match '(?:\?|&)rev=([0-9a-f]{40})(?:&|#)' -and [string]$Matches[1] -cne $commit) {
            throw 'PROFILE_CANDIDATE_BLOCKED: Cargo.lock Git source rev query differs from its locked commit object ID'
        }
        $count++
    }
    return $count
}

try {
    $repoFull = Assert-CandidateDirectory -Path $Repository
    $outputFull = Assert-CandidateCanonicalPath -Path $OutputPath
    $outputParent = [IO.Path]::GetDirectoryName($outputFull)
    $null = Assert-CandidateDirectory -Path $outputParent
    if ([IO.File]::Exists($outputFull) -or [IO.Directory]::Exists($outputFull) -or
        (Test-D32PowerShellAuthorityPathWithin -Child $outputFull -Parent $repoFull) -or
        (Test-D32PowerShellAuthorityPathWithin -Child $repoFull -Parent $outputFull)) {
        throw "PROFILE_CANDIDATE_NOT_NEW: destination must be absent and external to the repository: $outputFull"
    }

    $rustRoot = Assert-CandidateDirectory -Path $RustToolchainRoot
    $rustBin = Assert-CandidateDirectory -Path ([IO.Path]::Combine($rustRoot, 'bin'))
    $msvcFull = Assert-CandidateDirectory -Path $MsvcRoot
    $sdkFull = Assert-CandidateDirectory -Path $WindowsSdkRoot
    if ((Test-D32PowerShellAuthorityPathWithin -Child $rustRoot -Parent $repoFull) -or (Test-D32PowerShellAuthorityPathWithin -Child $repoFull -Parent $rustRoot) -or
        (Test-D32PowerShellAuthorityPathWithin -Child $msvcFull -Parent $repoFull) -or (Test-D32PowerShellAuthorityPathWithin -Child $repoFull -Parent $msvcFull) -or
        (Test-D32PowerShellAuthorityPathWithin -Child $sdkFull -Parent $repoFull) -or (Test-D32PowerShellAuthorityPathWithin -Child $repoFull -Parent $sdkFull)) {
        throw 'PROFILE_CANDIDATE_BLOCKED: Rust/MSVC/Windows SDK roots must be disjoint from the repository'
    }
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

    $process = [Diagnostics.Process]::GetCurrentProcess()
    try { $powerShellPath = [IO.Path]::GetFullPath([string]$process.MainModule.FileName) }
    finally { $process.Dispose() }
    $powerShellRoot = [IO.Path]::GetDirectoryName($powerShellPath)
    if ($powerShellRoot -cne [IO.Path]::GetFullPath([string]$PSHOME) -or [IO.Path]::GetFileName($powerShellPath) -cne 'pwsh.exe') {
        throw 'PROFILE_CANDIDATE_BLOCKED: current process image is not the direct PowerShell Core host under PSHOME'
    }
    $windowsRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows))
    if ([String]::IsNullOrWhiteSpace($windowsRoot) -or -not (Test-D32PowerShellAuthorityPathNoReparse -Path $windowsRoot)) { throw 'PROFILE_CANDIDATE_BLOCKED: current Windows root is unavailable or reparse-backed' }

    $powershellPin = ConvertTo-CandidateIdentity -Snapshot (Assert-CandidateFile -Path $powerShellPath) -Reason 'direct pinned PowerShell host executable'
    $cargo = ConvertTo-CandidateIdentity -Snapshot (Assert-CandidateFile -Path ([IO.Path]::Combine($rustBin, 'cargo.exe'))) -Reason 'direct pinned cargo executable'
    $rustc = ConvertTo-CandidateIdentity -Snapshot (Assert-CandidateFile -Path ([IO.Path]::Combine($rustBin, 'rustc.exe'))) -Reason 'direct pinned rustc executable'
    $rustdoc = ConvertTo-CandidateIdentity -Snapshot (Assert-CandidateFile -Path ([IO.Path]::Combine($rustBin, 'rustdoc.exe'))) -Reason 'direct pinned rustdoc executable'
    $rustImages = @(Get-CandidateDirectoryFileInventory -Directories @($rustBin) -Extensions @('.exe', '.com') -Reason 'caller-pinned Rust toolchain PATH executable')
    $nativeImages = @(Get-CandidateDirectoryFileInventory -Directories $pathEntries -Extensions @('.exe', '.com') -Reason 'caller-pinned MSVC/Windows SDK PATH executable')
    $pathScripts = @(Get-CandidateDirectoryFileInventory -Directories $allPathDirectories -Extensions @('.bat', '.cmd') -Reason 'dormant script inventory only; never launchable')
    $conhost = ConvertTo-CandidateIdentity -Snapshot (Assert-CandidateFile -Path ([IO.Path]::Combine($windowsRoot, 'System32', 'conhost.exe'))) -Reason 'direct pinned Windows console host child image'

    $locks = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in @(
            [ordered]@{ manifest_path = 'vita-agent-protocol/Cargo.toml'; lock_path = 'vita-agent-protocol/Cargo.lock' },
            [ordered]@{ manifest_path = 'vita-agent/Cargo.toml'; lock_path = 'vita-agent/Cargo.lock' },
            [ordered]@{ manifest_path = 'src-tauri/Cargo.toml'; lock_path = 'src-tauri/Cargo.lock' }
        )) {
        $manifest = [IO.Path]::GetFullPath([IO.Path]::Combine($repoFull, [string]$entry.manifest_path.Replace('/', [IO.Path]::DirectorySeparatorChar)))
        $lock = [IO.Path]::GetFullPath([IO.Path]::Combine($repoFull, [string]$entry.lock_path.Replace('/', [IO.Path]::DirectorySeparatorChar)))
        $null = Assert-CandidateFile -Path $manifest
        $lockSnapshot = Assert-CandidateFile -Path $lock
        $lockText = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$lockSnapshot.Bytes)
        $null = Get-CandidateGitSourceCount -Text $lockText
        $locks.Add([ordered]@{ manifest_path = [string]$entry.manifest_path; lock_sha256 = [string]$lockSnapshot.Record.sha256 })
    }

    $nativeEnvironment = [ordered]@{
        VCToolsInstallDir = $msvcFull
        WindowsSdkDir = $sdkFull
        VCToolsVersion = $VCToolsVersion
        WindowsSDKVersion = $WindowsSDKVersion
        VSCMD_ARG_TGT_ARCH = 'x64'
    }
    if ($VCToolsRedistDir) { $nativeEnvironment.VCToolsRedistDir = Assert-CandidateDirectory -Path $VCToolsRedistDir }
    if ($VSInstallDir) { $nativeEnvironment.VSINSTALLDIR = Assert-CandidateDirectory -Path $VSInstallDir }
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
        native_roots = @([ordered]@{ name = 'msvc'; path = $msvcFull }, [ordered]@{ name = 'windows-sdk'; path = $sdkFull })
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
        fetch_manifests = @($locks.ToArray())
        fetch_git = $null
        env_policy = 'D32_BUILD_ENV_V1'
        cargo_policy = 'FRESH_HOME_LOCKED_FETCH_OFFLINE_AFTER'
    }

    $json = [System.Text.Json.JsonSerializer]::Serialize([object]$profile)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $outputStream = [IO.File]::Open($outputFull, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $outputStream.Write($bytes, 0, $bytes.Length); $outputStream.Flush($true) }
    finally { $outputStream.Dispose() }
    $outputSnapshot = Assert-CandidateFile -Path $outputFull
    $profileDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$outputSnapshot.Bytes))
    try {
        if ((Test-D32PowerShellAuthorityJsonDuplicates -Element $profileDocument.RootElement) -or
            $profileDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
            $profileDocument.RootElement.GetProperty('schema_version').GetInt32() -ne 2 -or
            $profileDocument.RootElement.GetProperty('profile_type').GetString() -cne 'D32_BUILD_TOOLCHAIN_PROFILE_V2') {
            throw 'PROFILE_CANDIDATE_BLOCKED: newly written candidate failed module-free schema/type sanity checks'
        }
    }
    finally { $profileDocument.Dispose() }
    [Console]::WriteLine("D32_PROFILE_CANDIDATE_PATH=$outputFull")
    [Console]::WriteLine("D32_PROFILE_CANDIDATE_SHA256=$($outputSnapshot.Record.sha256)")
    [Console]::WriteLine('D32_PROFILE_CANDIDATE_VERSION=2')
    [Console]::WriteLine("D32_PROFILE_RESIDENT_SCRIPTS=$($pathScripts.Count) (dormant identity only; no launch authority)")
    [Console]::WriteLine('D32_PROFILE_CANDIDATE_AUTHORITY=UNAUTHORIZED_CANDIDATE_ONLY')
}
finally {
    foreach ($file in $openedFiles) { if ($null -ne $file.Stream -and -not $file.Stream.SafeFileHandle.IsClosed) { $file.Stream.Dispose() } }
    foreach ($directory in $directoryFences.Values) { if ($null -ne $directory.Handle -and -not $directory.Handle.IsClosed) { $directory.Handle.Dispose() } }
}
