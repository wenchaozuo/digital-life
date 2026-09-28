[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArchivePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$CandidateSha,

    [Parameter(Mandatory = $true)]
    [string]$ToolchainProfilePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedToolchainProfileSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ExpectedArchiveSha256 = 'e8b394794f399a421811d06966343e7933fcae92d59f5180b9388d1174497a45'
$script:ExpectedArchiveBytes = 34903
$script:ExpectedSourceTreeSha256 = '68e44e75bf963a52b2fbda751c876c68ed4c8656dd6628e593478f47d18ea983'
$script:ExpectedRootManifestSha256 = 'e05e2f819ae667eb7a738f8d54a0e45f210093fc4f4bee1ca849eca80ed250db'
$script:ExpectedRootLockSha256 = '8818a24ee4ba8f7d628f443ce181b0686f6353f759d76e2e7305c47da603049c'
$script:ExpectedVendorManifestSha256 = '359f36b12d366f379f46fb9b59d78678e2df4a1617e605c9c480301d3d57e4b3'
$script:ExpectedVendorLockSha256 = '4d96652714b4cdb6494b7a7c957babbf5c704c5197f31043d180d8f43ec968f3'
$script:PackageRootName = 'tauri-macros-2.6.3'
$script:WrapperRelativePath = 'src/command/wrapper.rs'

function Get-D32Sha256Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([Convert]::ToHexString($sha.ComputeHash($Bytes))).ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Test-D32ByteSequenceEqual {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) { return $false }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) { return $false }
    }
    return $true
}

function ConvertTo-D32CanonicalTextBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $text = $strictUtf8.GetString($Bytes)
    if ([regex]::IsMatch($text, "`r(?!`n)")) { throw 'Source file contains a non-canonical lone CR byte.' }
    return ,$strictUtf8.GetBytes($text.Replace("`r`n", "`n"))
}

function Get-D32FileSha256Hex {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            return ([Convert]::ToHexString($sha.ComputeHash($stream))).ToLowerInvariant()
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-D32RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [IO.Path]::IsPathRooted($Path)) { throw "Path must be absolute: $Path" }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force
    if ($item -isnot [IO.FileInfo] -or -not $item.Exists) { throw "Expected a regular file: $fullPath" }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse-point file is not accepted: $fullPath" }
    return $fullPath
}

function Get-D32ArchiveMembers {
    param([Parameter(Mandatory = $true)][string]$Path)

    $members = [Collections.Generic.Dictionary[string, byte[]]]::new([StringComparer]::Ordinal)
    $caseFolded = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $fileStream = [IO.File]::OpenRead($Path)
    try {
        $gzip = [IO.Compression.GZipStream]::new($fileStream, [IO.Compression.CompressionMode]::Decompress, $true)
        try {
            $reader = [System.Formats.Tar.TarReader]::new($gzip, $true)
            try {
                while ($null -ne ($entry = $reader.GetNextEntry($false))) {
                    if ($entry.EntryType.ToString() -cne 'RegularFile') { throw "Unexpected archive entry type '$($entry.EntryType)' for '$($entry.Name)'" }
                    $name = [string]$entry.Name
                    $prefix = $script:PackageRootName + '/'
                    if (-not $name.StartsWith($prefix, [StringComparison]::Ordinal) -or $name.Contains('\') -or $name.StartsWith('/') -or $name.Contains(':')) {
                        throw "Non-canonical archive member path: $name"
                    }
                    $relativePath = $name.Substring($prefix.Length)
                    $segments = $relativePath.Split('/')
                    if ($relativePath.Length -eq 0 -or @($segments | Where-Object { $_.Length -eq 0 -or $_ -ceq '.' -or $_ -ceq '..' }).Count -ne 0) {
                        throw "Unsafe archive member path: $name"
                    }
                    if (-not $caseFolded.Add($relativePath)) { throw "Duplicate/case-colliding archive member: $relativePath" }

                    $memory = [IO.MemoryStream]::new()
                    try {
                        if ($null -ne $entry.DataStream) { $entry.DataStream.CopyTo($memory) }
                        $members.Add($relativePath, $memory.ToArray())
                    }
                    finally {
                        $memory.Dispose()
                    }
                }
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            $gzip.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
    return ,$members
}

function Get-D32TreeDigest {
    param([Parameter(Mandatory = $true)][Collections.IDictionary]$Members)

    $paths = [string[]]@($Members.Keys)
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $builder = [Text.StringBuilder]::new()
    foreach ($relativePath in $paths) {
        $fileHash = Get-D32Sha256Hex -Bytes $Members[$relativePath]
        [void]$builder.Append($relativePath).Append([char]0).Append($fileHash).Append("`n")
    }
    return Get-D32Sha256Hex -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($builder.ToString()))
}

function Get-D32VendorMembers {
    param([Parameter(Mandatory = $true)][string]$Root)

    $rootItem = Get-Item -LiteralPath $Root -Force
    if ($rootItem -isnot [IO.DirectoryInfo] -or (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Vendored crate root must be a real directory: $Root"
    }

    $members = [Collections.Generic.Dictionary[string, byte[]]]::new([StringComparer]::Ordinal)
    $caseFolded = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pending = [Collections.Generic.Stack[IO.DirectoryInfo]]::new()
    $pending.Push($rootItem)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($childDirectory in $directory.GetDirectories()) {
            if (($childDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Vendored directory reparse point is not accepted: $($childDirectory.FullName)" }
            $pending.Push($childDirectory)
        }
        foreach ($file in $directory.GetFiles()) {
            if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Vendored file reparse point is not accepted: $($file.FullName)" }
            $relativePath = [IO.Path]::GetRelativePath($Root, $file.FullName).Replace('\', '/')
            if (-not $caseFolded.Add($relativePath)) { throw "Duplicate/case-colliding vendored file: $relativePath" }
            $members.Add($relativePath, (ConvertTo-D32CanonicalTextBytes -Bytes ([IO.File]::ReadAllBytes($file.FullName))))
        }
    }
    return ,$members
}

$archiveFullPath = Assert-D32RegularFile -Path $ArchivePath
$profileFullPath = Assert-D32RegularFile -Path $ToolchainProfilePath
$archiveBytes = [IO.File]::ReadAllBytes($archiveFullPath)
$archiveSha256 = Get-D32Sha256Hex -Bytes $archiveBytes
if ($archiveBytes.LongLength -ne $script:ExpectedArchiveBytes -or $archiveSha256 -cne $script:ExpectedArchiveSha256) {
    throw 'Locked tauri-macros 2.6.3 archive byte count or SHA-256 mismatch.'
}

$profileInfo = Get-Item -LiteralPath $profileFullPath -Force
$profileSha256 = Get-D32FileSha256Hex -Path $profileFullPath
if ($profileSha256 -cne $ExpectedToolchainProfileSha256) { throw 'Toolchain profile SHA-256 differs from caller-pinned expectation.' }

$archivedMembers = Get-D32ArchiveMembers -Path $archiveFullPath
if ($archivedMembers.Count -ne 15) { throw "Expected exactly 15 locked source files; found $($archivedMembers.Count)." }
$sourceTreeSha256 = Get-D32TreeDigest -Members $archivedMembers
if ($sourceTreeSha256 -cne $script:ExpectedSourceTreeSha256) { throw 'Locked source tree digest mismatch.' }
if (-not $archivedMembers.ContainsKey($script:WrapperRelativePath)) { throw 'Locked source archive omits the patched wrapper source.' }

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$tauriRoot = Join-Path $repoRoot 'src-tauri'
$vendorRoot = Join-Path (Join-Path $tauriRoot 'vendor') $script:PackageRootName
$vendoredMembers = Get-D32VendorMembers -Root $vendorRoot
if ($vendoredMembers.Count -ne $archivedMembers.Count) { throw 'Vendored source file count differs from the locked archive.' }
foreach ($relativePath in $archivedMembers.Keys) {
    if (-not $vendoredMembers.ContainsKey($relativePath)) { throw "Vendored source file missing: $relativePath" }
}
foreach ($relativePath in $vendoredMembers.Keys) {
    if (-not $archivedMembers.ContainsKey($relativePath)) { throw "Unapproved extra vendored source file: $relativePath" }
}

$utf8Strict = [Text.UTF8Encoding]::new($false, $true)
$originalWrapper = $utf8Strict.GetString($archivedMembers[$script:WrapperRelativePath])
$patchedWrapper = $utf8Strict.GetString($vendoredMembers[$script:WrapperRelativePath])
$lf = "`n"
$oldWrapperBlock = @(
    'fn cross_command(bin: &str) -> std::process::Command {',
    '  #[cfg(target_os = "windows")]',
    '  let cmd = {',
    '    let mut cmd = std::process::Command::new("cmd");',
    '    cmd.arg("/c").arg(bin);',
    '    cmd',
    '  };',
    '  #[cfg(not(target_os = "windows"))]',
    '  let cmd = std::process::Command::new(bin);',
    '  cmd',
    '}'
) -join $lf
$newWrapperBlock = @(
    'fn cross_command(bin: &str) -> std::process::Command {',
    '  #[cfg(target_os = "windows")]',
    '  let cmd = {',
    '    // D32 provides the caller-pinned absolute RUSTC path; reject missing or relative input.',
    '    let _ = bin;',
    '    let rustc = std::env::var_os("RUSTC")',
    '      .filter(|path| std::path::Path::new(path).is_absolute())',
    '      .expect("D32 requires the caller-pinned absolute RUSTC path");',
    '    std::process::Command::new(rustc)',
    '  };',
    '  #[cfg(not(target_os = "windows"))]',
    '  let cmd = std::process::Command::new(bin);',
    '  cmd',
    '}'
) -join $lf
if ([string]::IsNullOrEmpty($oldWrapperBlock) -or $originalWrapper.IndexOf($oldWrapperBlock, [StringComparison]::Ordinal) -lt 0) {
    throw 'Locked wrapper source does not contain the exact approved original cross_command block.'
}
if ($originalWrapper.IndexOf($oldWrapperBlock, [StringComparison]::Ordinal) -ne $originalWrapper.LastIndexOf($oldWrapperBlock, [StringComparison]::Ordinal)) {
    throw 'Locked wrapper source contains more than one original cross_command block.'
}
$expectedPatchedWrapper = $originalWrapper.Replace($oldWrapperBlock, $newWrapperBlock)
$expectedPatchedBytes = $utf8Strict.GetBytes($expectedPatchedWrapper)
if (-not (Test-D32ByteSequenceEqual -Left $vendoredMembers[$script:WrapperRelativePath] -Right $expectedPatchedBytes)) {
    throw 'Vendored wrapper is not exactly the approved direct absolute-RUSTC source patch.'
}
foreach ($relativePath in $archivedMembers.Keys) {
    if ($relativePath -ceq $script:WrapperRelativePath) { continue }
    if (-not (Test-D32ByteSequenceEqual -Left $archivedMembers[$relativePath] -Right $vendoredMembers[$relativePath])) {
        throw "Vendored source differs from locked archive outside the approved wrapper patch: $relativePath"
    }
}

$vendorPackageManifest = Join-Path $vendorRoot 'Cargo.toml'
$vendorPackageLock = Join-Path $vendorRoot 'Cargo.lock'
$rootManifest = Join-Path $tauriRoot 'Cargo.toml'
$rootLock = Join-Path $tauriRoot 'Cargo.lock'
$vendorManifestText = $utf8Strict.GetString($vendoredMembers['Cargo.toml'])
if ($vendorManifestText -notmatch '(?m)^name\s*=\s*"tauri-macros"\s*$' -or $vendorManifestText -notmatch '(?m)^version\s*=\s*"2\.6\.3"\s*$') {
    throw 'Vendored package manifest identity is not tauri-macros 2.6.3.'
}
$rootManifestBytes = ConvertTo-D32CanonicalTextBytes -Bytes ([IO.File]::ReadAllBytes($rootManifest))
$rootManifestText = $utf8Strict.GetString($rootManifestBytes)
$requiredPatch = '[patch.crates-io]' + $lf + 'tauri-macros = { path = "vendor/tauri-macros-2.6.3" }'
if (-not $rootManifestText.Contains($requiredPatch)) { throw 'Root Cargo.toml does not contain the exact candidate-local crates.io patch declaration.' }
$rootLockBytes = ConvertTo-D32CanonicalTextBytes -Bytes ([IO.File]::ReadAllBytes($rootLock))
$rootLockText = $utf8Strict.GetString($rootLockBytes)
$packageBlocks = @($rootLockText -split '(?m)^\[\[package\]\]\r?\n' | Where-Object { $_ -match '(?m)^name = "tauri-macros"\r?$' })
if ($packageBlocks.Count -ne 1 -or $packageBlocks[0] -notmatch '(?m)^version = "2\.6\.3"\r?$' -or $packageBlocks[0] -match '(?m)^(source|checksum)\s*=') {
    throw 'Root Cargo.lock does not contain exactly one local tauri-macros 2.6.3 package entry without registry source/checksum.'
}

$sourceWrapperSha256 = Get-D32Sha256Hex -Bytes $archivedMembers[$script:WrapperRelativePath]
$patchedSourceSha256 = Get-D32Sha256Hex -Bytes $vendoredMembers[$script:WrapperRelativePath]
$vendoredTreeSha256 = Get-D32TreeDigest -Members $vendoredMembers
$patchDescriptor = @(
    'D32_TAURI_MACROS_SOURCE_PATCH_V1',
    $script:WrapperRelativePath,
    $sourceWrapperSha256,
    $patchedSourceSha256,
    (Get-D32Sha256Hex -Bytes $utf8Strict.GetBytes($oldWrapperBlock)),
    (Get-D32Sha256Hex -Bytes $utf8Strict.GetBytes($newWrapperBlock))
) -join "`n"
$patchSha256 = Get-D32Sha256Hex -Bytes $utf8Strict.GetBytes($patchDescriptor)
$rootManifestSha256 = Get-D32Sha256Hex -Bytes $rootManifestBytes
$rootLockSha256 = Get-D32Sha256Hex -Bytes $rootLockBytes
$vendorManifestSha256 = Get-D32Sha256Hex -Bytes $vendoredMembers['Cargo.toml']
$vendorLockSha256 = Get-D32Sha256Hex -Bytes $vendoredMembers['Cargo.lock']
if ($rootManifestSha256 -cne $script:ExpectedRootManifestSha256 -or
    $rootLockSha256 -cne $script:ExpectedRootLockSha256 -or
    $vendorManifestSha256 -cne $script:ExpectedVendorManifestSha256 -or
    $vendorLockSha256 -cne $script:ExpectedVendorLockSha256) {
    throw 'Root or vendored Cargo manifest/lock SHA-256 differs from the exact approved local-source patch state.'
}

$record = [ordered]@{
    schema_version = 1
    record_type = 'D32_TAURI_MACROS_SOURCE_PATCH_V1'
    status = 'SOURCE_PATCH_VERIFIED'
    candidate_sha = $CandidateSha
    toolchain_profile = [ordered]@{
        path = $profileFullPath
        sha256 = $profileSha256
        bytes = [long]$profileInfo.Length
    }
    package_name = 'tauri-macros'
    package_version = '2.6.3'
    registry_source = 'registry+https://github.com/rust-lang/crates.io-index'
    archive_path = $archiveFullPath
    archive_bytes = [long]$archiveBytes.LongLength
    archive_sha256 = $archiveSha256
    source_tree_sha256 = $sourceTreeSha256
    expected_source_tree_sha256 = $script:ExpectedSourceTreeSha256
    vendored_path = [IO.Path]::GetRelativePath($repoRoot, $vendorRoot).Replace('\', '/')
    vendored_tree_sha256 = $vendoredTreeSha256
    changed_files = @($script:WrapperRelativePath)
    source_wrapper_sha256 = $sourceWrapperSha256
    patched_source_sha256 = $patchedSourceSha256
    patch_sha256 = $patchSha256
    manifest_sha256 = $rootManifestSha256
    lock_sha256 = $rootLockSha256
    vendor_manifest_sha256 = $vendorManifestSha256
    vendor_lock_sha256 = $vendorLockSha256
}

[Console]::Out.WriteLine(($record | ConvertTo-Json -Depth 8 -Compress))
