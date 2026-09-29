# D32-only, fail-closed authority for the exact locked vendored protoc image.
# Dot-source after d32-build-toolchain-profile.ps1. This file never starts a process.

$script:D32VendoredProtocAuthorityType = 'D32_VENDORED_PROTOC_AUTHORITY_V1'
$script:D32VendoredProtocRunGrantType = 'D32_PHASE0_VENDORED_PROTOC_RUN_GRANT_V1'
$script:D32VendoredProtocUmbrellaChecksum = 'd1c381df33c98266b5f08186583660090a4ffa0889e76c7e9a5e175f645a67fa'
$script:D32VendoredProtocWin32Checksum = '95067976aca6421a523e491fce939a3e65249bac4b977adee0ee9771568e8aa3'
$script:D32VendoredProtocImageSha256 = 'cbd1ca1fd6afd1bb6ddd1c09c118ecd4c50f928980857f16fe6fc23704ea17e2'
$script:D32VendoredProtocImageBytes = [Int64]11934496
$script:D32VendoredProtocArchiveBytes = [Int64]3426255
$script:D32VendoredProtocRegistryHash = 'index.crates.io-1949cf8c6b5b557f'
$script:D32VendoredProtocPackageRoot = 'protoc-bin-vendored-win32-3.2.0'
$script:D32VendoredProtocArchiveRelativePath = "registry\cache\$($script:D32VendoredProtocRegistryHash)\protoc-bin-vendored-win32-3.2.0.crate"
$script:D32VendoredProtocSourceRelativePath = "registry\src\$($script:D32VendoredProtocRegistryHash)\$($script:D32VendoredProtocPackageRoot)"
$script:D32TauriMacrosSourcePatchType = 'D32_TAURI_MACROS_SOURCE_PATCH_V1'
$script:D32TauriMacrosArchiveSha256 = 'e8b394794f399a421811d06966343e7933fcae92d59f5180b9388d1174497a45'
$script:D32TauriMacrosArchiveBytes = [Int64]34903
$script:D32TauriMacrosSourceTreeSha256 = '68e44e75bf963a52b2fbda751c876c68ed4c8656dd6628e593478f47d18ea983'
$script:D32TauriMacrosSourceWrapperSha256 = '1ff1fbc6f18e0eeed00b8d33eda8e5111b0b203f5ff77e1a0cfd5929975b21e3'
$script:D32TauriMacrosVendoredTreeSha256 = '52842cfa519dd31f59d684bcbd7fedc19bb709081ca16c9b9d0741b08594fb1b'
$script:D32TauriMacrosPatchSha256 = 'a8d76c969d38c9525762906955a51b33fec360a174dc2ff3a6051be3db4021cd'
$script:D32TauriMacrosPatchedSourceSha256 = '1bac6f2bdb822c890f7c645560dcb3c28737908c5aebaafd2c2e0742cb05593b'
$script:D32TauriMacrosRootManifestSha256 = 'e05e2f819ae667eb7a738f8d54a0e45f210093fc4f4bee1ca849eca80ed250db'
$script:D32TauriMacrosRootLockSha256 = '8818a24ee4ba8f7d628f443ce181b0686f6353f759d76e2e7305c47da603049c'
$script:D32TauriMacrosVendorManifestSha256 = '359f36b12d366f379f46fb9b59d78678e2df4a1617e605c9c480301d3d57e4b3'
$script:D32TauriMacrosVendorLockSha256 = '4d96652714b4cdb6494b7a7c957babbf5c704c5197f31043d180d8f43ec968f3'

function Get-D32TauriMacrosArchiveWrapperSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$ArchiveBytes)

    $memory = [IO.MemoryStream]::new($ArchiveBytes, $false)
    $gzip = $null
    $reader = $null
    try {
        $gzip = [IO.Compression.GZipStream]::new($memory, [IO.Compression.CompressionMode]::Decompress, $true)
        $reader = [System.Formats.Tar.TarReader]::new($gzip, $true)
        $wrapperBytes = $null
        $wrapperCount = 0
        while ($null -ne ($entry = $reader.GetNextEntry($false))) {
            if ($entry.EntryType.ToString() -cne 'RegularFile') { throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: pinned source archive contains a non-regular member' }
            $name = [string]$entry.Name
            $prefix = 'tauri-macros-2.6.3/'
            if (-not $name.StartsWith($prefix, [StringComparison]::Ordinal) -or $name.Contains('\') -or $name.Contains(':') -or $name.StartsWith('/')) {
                throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: pinned source archive contains a non-canonical member path'
            }
            $relative = $name.Substring($prefix.Length)
            if ($relative.Length -eq 0 -or @($relative.Split('/') | Where-Object { $_.Length -eq 0 -or $_ -ceq '.' -or $_ -ceq '..' }).Count -gt 0) {
                throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: pinned source archive contains an unsafe member path'
            }
            if ($relative -ceq 'src/command/wrapper.rs') {
                $wrapperCount++
                $content = [IO.MemoryStream]::new()
                try {
                    if ($null -ne $entry.DataStream) { $entry.DataStream.CopyTo($content) }
                    $wrapperBytes = $content.ToArray()
                }
                finally { $content.Dispose() }
            }
        }
        if ($wrapperCount -ne 1 -or $null -eq $wrapperBytes) { throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: exact archive must contain one regular command wrapper source' }
        return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($wrapperBytes)).ToLowerInvariant()
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $gzip) { $gzip.Dispose() }
        $memory.Dispose()
    }
}

function Get-D32TauriMacrosPatchDescriptorSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$SourceWrapperSha256,
        [Parameter(Mandatory = $true)][string]$PatchedSourceSha256
    )

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
    ) -join "`n"
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
    ) -join "`n"
    $utf8 = [Text.UTF8Encoding]::new($false)
    $oldSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes($oldWrapperBlock))).ToLowerInvariant()
    $newSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes($newWrapperBlock))).ToLowerInvariant()
    $descriptor = @('D32_TAURI_MACROS_SOURCE_PATCH_V1', 'src/command/wrapper.rs', $SourceWrapperSha256, $PatchedSourceSha256, $oldSha, $newSha) -join "`n"
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes($descriptor))).ToLowerInvariant()
}

function Get-D32VendoredOrdinaryPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) { return ('\\' + $full.Substring(8)) }
    if ($full.StartsWith('\\?\', [StringComparison]::Ordinal)) { return $full.Substring(4) }
    return $full
}

function Test-D32VendoredObjectExactProperties {
    param([AllowNull()][object]$Object, [Parameter(Mandatory = $true)][string[]]$Expected)
    if ($null -eq $Object -or $Object -is [string] -or $Object -is [Array] -or $Object -is [ValueType]) { return $false }
    if ($Object -is [System.Collections.IDictionary]) {
        $actual = @($Object.Keys | ForEach-Object { [string]$_ })
    }
    else {
        $actual = @($Object.PSObject.Properties | ForEach-Object { [string]$_.Name })
    }
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) { if ($actual -cnotcontains $name) { return $false } }
    return $true
}

function Get-D32VendoredProperty {
    param([AllowNull()][object]$Object, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-D32VendoredInteger {
    param([AllowNull()][object]$Value, [switch]$Positive)
    $numericTypes = @([byte], [sbyte], [uint16], [int16], [uint32], [int32], [uint64], [int64])
    if ($null -eq $Value -or $numericTypes -notcontains $Value.GetType()) { return $false }
    if ($Positive) { return [Int64]$Value -gt 0 }
    return [Int64]$Value -ge 0
}

function Get-D32VendoredFileReference {
    param([Parameter(Mandatory = $true)][string]$Path)
    $snapshot = Get-D32ProfileFileSnapshot -Path $Path
    return [ordered]@{
        path = [string]$snapshot.Path
        bytes = [Int64]$snapshot.Bytes
        sha256 = [string]$snapshot.Sha256
        volume_serial_hex = [string]$snapshot.VolumeSerialHex
        file_id_hex = [string]$snapshot.FileIdHex
    }
}

function Get-D32TauriMacrosCanonicalFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-D32ProfileNoReparsePath -Path $Path)) { throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: a source or metadata file is missing or reparse-backed' }
    $bytes = [IO.File]::ReadAllBytes($Path)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -eq 13) {
            if (($i + 1) -ge $bytes.Length -or $bytes[$i + 1] -ne 10) { throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: lone CR is not canonical source text' }
            $i++
        }
    }
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    try { $text = $strictUtf8.GetString($bytes).Replace("`r`n", "`n") }
    catch { throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: source file is not valid UTF-8' }
    $canonical = [Text.UTF8Encoding]::new($false).GetBytes($text)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($canonical)).ToLowerInvariant()
}

function Get-D32TauriMacrosCanonicalTreeSha256 {
    param([Parameter(Mandatory = $true)][string]$Root)
    $fullRoot = [IO.Path]::GetFullPath($Root)
    if (-not (Test-D32ProfileNoReparsePath -Path $fullRoot) -or -not (Test-Path -LiteralPath $fullRoot -PathType Container)) { throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: vendored source root is missing or reparse-backed' }
    $expectedCount = 15
    $files = @(Get-ChildItem -LiteralPath $fullRoot -File -Recurse -Force -ErrorAction Stop)
    $directories = @(Get-ChildItem -LiteralPath $fullRoot -Directory -Recurse -Force -ErrorAction Stop)
    foreach ($entry in @($files) + @($directories)) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: vendored source tree contains a reparse entry' }
    }
    if ($files.Count -ne $expectedCount) { throw "TAURI_MACROS_SOURCE_PATCH_BLOCKED: vendored source tree must contain exactly $expectedCount regular archive members" }
    $records = [System.Collections.Generic.List[string]]::new()
    foreach ($file in $files) {
        $relative = [IO.Path]::GetRelativePath($fullRoot, $file.FullName).Replace('\', '/')
        if ($relative.StartsWith('../', [StringComparison]::Ordinal) -or $relative.Contains(':') -or $relative -match '(^|/)\.\.?(/|$)') { throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: vendored source member path is not canonical' }
        $fileSha = Get-D32TauriMacrosCanonicalFileSha256 -Path $file.FullName
        $records.Add($relative + [char]0 + $fileSha + "`n")
    }
    $records.Sort([StringComparer]::Ordinal)
    $payload = [Text.UTF8Encoding]::new($false).GetBytes(($records.ToArray() -join ''))
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($payload)).ToLowerInvariant()
}

function Get-D32TauriMacrosSourcePatchFileReference {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-D32VendoredFileReference -Path $Path
}

function Test-D32TauriMacrosSourcePatchAuthority {
    param(
        [Parameter(Mandatory = $true)][string]$AuthorityPath,
        [Parameter(Mandatory = $true)][string]$ExpectedAuthoritySha256,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot
    )
    if ($ExpectedAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-D32ProfileCanonicalPathString -Path $AuthorityPath) -or
        -not (Test-D32ProfileNoReparsePath -Path $AuthorityPath) -or
        (Test-D32ProfilePathWithin -Child $AuthorityPath -Parent $Repository) -or
        (Test-D32ProfilePathWithin -Child $AuthorityPath -Parent $EvidenceRoot)) {
        throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: source authority must be an independently SHA-pinned external regular file'
    }
    $authorityStream = [IO.File]::Open($AuthorityPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $before = Get-D32ProfileFileSnapshot -Path $AuthorityPath
        if ($before.Sha256 -cne $ExpectedAuthoritySha256) { throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: authority bytes differ from the independent expected SHA-256' }
        $authorityStream.Position = 0
        $reader = [IO.StreamReader]::new($authorityStream, [Text.Encoding]::UTF8, $true, 4096, $true)
        try { $raw = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $after = Get-D32ProfileFileSnapshot -Path $AuthorityPath
        if ($before.Bytes -ne $after.Bytes -or $before.Sha256 -cne $after.Sha256 -or $before.VolumeSerialHex -cne $after.VolumeSerialHex -or $before.FileIdHex -cne $after.FileIdHex) {
            throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: authority changed during opened-handle validation'
        }
    }
    finally { $authorityStream.Dispose() }
    $json = [System.Text.Json.JsonDocument]::Parse($raw)
    try { if (Test-D32ProfileJsonElementDuplicates -Element $json.RootElement) { throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: authority JSON contains duplicate keys' } }
    finally { $json.Dispose() }
    $doc = $raw | ConvertFrom-Json -DateKind String
    $fields = @('schema_version', 'record_type', 'status', 'candidate_sha', 'toolchain_profile', 'package_name', 'package_version', 'registry_source', 'archive_path', 'archive_bytes', 'archive_sha256', 'source_tree_sha256', 'expected_source_tree_sha256', 'vendored_path', 'vendored_tree_sha256', 'changed_files', 'source_wrapper_sha256', 'patched_source_sha256', 'patch_sha256', 'manifest_sha256', 'lock_sha256', 'vendor_manifest_sha256', 'vendor_lock_sha256')
    if (-not (Test-D32VendoredObjectExactProperties -Object $doc -Expected $fields) -or
        -not (Test-D32VendoredInteger -Value $doc.schema_version) -or [Int64]$doc.schema_version -ne 1 -or
        $doc.record_type -isnot [string] -or $doc.record_type -cne $script:D32TauriMacrosSourcePatchType -or
        $doc.status -isnot [string] -or $doc.status -cne 'SOURCE_PATCH_VERIFIED' -or
        $doc.candidate_sha -isnot [string] -or $doc.candidate_sha -cne $CandidateSha -or
        -not (Test-D32VendoredObjectExactProperties -Object $doc.toolchain_profile -Expected @('path', 'sha256', 'bytes')) -or
        $doc.toolchain_profile.path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $doc.toolchain_profile.path -Right $ValidatedProfile.ProfilePath) -or
        $doc.toolchain_profile.sha256 -isnot [string] -or $doc.toolchain_profile.sha256 -cne $ValidatedProfile.Digest -or
        -not (Test-D32VendoredInteger -Value $doc.toolchain_profile.bytes -Positive) -or [Int64]$doc.toolchain_profile.bytes -ne [Int64]$ValidatedProfile.Identity.Bytes -or
        $doc.package_name -isnot [string] -or $doc.package_name -cne 'tauri-macros' -or
        $doc.package_version -isnot [string] -or $doc.package_version -cne '2.6.3' -or
        $doc.registry_source -isnot [string] -or $doc.registry_source -cne 'registry+https://github.com/rust-lang/crates.io-index' -or
        $doc.archive_path -isnot [string] -or -not [IO.Path]::IsPathRooted($doc.archive_path) -or
        -not (Test-D32VendoredInteger -Value $doc.archive_bytes -Positive) -or [Int64]$doc.archive_bytes -ne $script:D32TauriMacrosArchiveBytes -or
        $doc.archive_sha256 -isnot [string] -or $doc.archive_sha256 -cne $script:D32TauriMacrosArchiveSha256 -or
        $doc.source_tree_sha256 -isnot [string] -or $doc.source_tree_sha256 -cne $script:D32TauriMacrosSourceTreeSha256 -or
        $doc.expected_source_tree_sha256 -isnot [string] -or $doc.expected_source_tree_sha256 -cne $script:D32TauriMacrosSourceTreeSha256 -or
        $doc.vendored_path -isnot [string] -or $doc.vendored_path -cne 'src-tauri/vendor/tauri-macros-2.6.3' -or
        $doc.vendored_tree_sha256 -isnot [string] -or $doc.vendored_tree_sha256 -cne $script:D32TauriMacrosVendoredTreeSha256 -or
        $doc.changed_files -isnot [Array] -or $doc.changed_files.Count -ne 1 -or $doc.changed_files[0] -cne 'src/command/wrapper.rs') {
        throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: authority is not the exact current source-patch schema/candidate/profile/locked package approval'
    }
    foreach ($field in @('source_wrapper_sha256', 'patched_source_sha256', 'patch_sha256', 'manifest_sha256', 'lock_sha256', 'vendor_manifest_sha256', 'vendor_lock_sha256')) {
        if ($doc.$field -isnot [string] -or $doc.$field -cnotmatch '^[0-9a-f]{64}$') { throw "TAURI_MACROS_SOURCE_PATCH_BLOCKED: $field is not a lowercase SHA-256" }
    }
    if (-not (Test-D32ProfileCanonicalPathString -Path ([string]$doc.archive_path)) -or
        -not (Test-D32ProfileNoReparsePath -Path ([string]$doc.archive_path)) -or
        (Test-D32ProfilePathWithin -Child ([string]$doc.archive_path) -Parent $Repository) -or
        (Test-D32ProfilePathWithin -Child ([string]$doc.archive_path) -Parent $EvidenceRoot)) {
        throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: original archive must be a regular canonical file outside repository and run EvidenceRoot'
    }
    $archiveSnapshot = Get-D32ProfileFileSnapshot -Path ([string]$doc.archive_path)
    $archiveBytes = [IO.File]::ReadAllBytes([string]$doc.archive_path)
    $archiveBytesSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($archiveBytes)).ToLowerInvariant()
    if ($archiveSnapshot.Bytes -ne [Int64]$doc.archive_bytes -or $archiveSnapshot.Sha256 -cne $script:D32TauriMacrosArchiveSha256 -or
        $archiveBytes.LongLength -ne $script:D32TauriMacrosArchiveBytes -or $archiveBytesSha256 -cne $script:D32TauriMacrosArchiveSha256) {
        throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: source archive content/size differs from the exact approved registry archive'
    }
    $archivedWrapperSha256 = Get-D32TauriMacrosArchiveWrapperSha256 -ArchiveBytes $archiveBytes
    if ($archivedWrapperSha256 -cne $script:D32TauriMacrosSourceWrapperSha256 -or $doc.source_wrapper_sha256 -cne $archivedWrapperSha256) {
        throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: source_wrapper_sha256 is not the exact wrapper extracted from the pinned registry archive'
    }
    $repo = [IO.Path]::GetFullPath($Repository)
    $vendor = [IO.Path]::GetFullPath((Join-Path $repo 'src-tauri\vendor\tauri-macros-2.6.3'))
    if (-not (Test-D32ProfilePathEqual -Left (Join-Path $repo ([string]$doc.vendored_path.Replace('/', '\'))) -Right $vendor)) { throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: vendor root is not candidate-local at its fixed path' }
    $treeSha = Get-D32TauriMacrosCanonicalTreeSha256 -Root $vendor
    if ($treeSha -cne $doc.vendored_tree_sha256) { throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: current candidate-local source tree differs from the independently pinned exact patch tree' }
    $fixedHashes = @{
        patched_source_sha256 = $script:D32TauriMacrosPatchedSourceSha256
        patch_sha256 = $script:D32TauriMacrosPatchSha256
        manifest_sha256 = $script:D32TauriMacrosRootManifestSha256
        lock_sha256 = $script:D32TauriMacrosRootLockSha256
        vendor_manifest_sha256 = $script:D32TauriMacrosVendorManifestSha256
        vendor_lock_sha256 = $script:D32TauriMacrosVendorLockSha256
    }
    $recomputedPatchSha256 = Get-D32TauriMacrosPatchDescriptorSha256 -SourceWrapperSha256 $archivedWrapperSha256 -PatchedSourceSha256 $script:D32TauriMacrosPatchedSourceSha256
    if ([string]$doc.source_wrapper_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $recomputedPatchSha256 -cne $script:D32TauriMacrosPatchSha256 -or $doc.patch_sha256 -cne $recomputedPatchSha256) {
        throw 'TAURI_MACROS_SOURCE_PATCH_BLOCKED: source-patch descriptor does not recompute from the exact archived and patched wrapper hashes'
    }
    foreach ($field in $fixedHashes.Keys) {
        if ([string]$doc.$field -cne [string]$fixedHashes[$field]) { throw "TAURI_MACROS_SOURCE_PATCH_BLOCKED: authority field $field differs from the approved exact source patch" }
    }
    $localFiles = @(
        [PSCustomObject]@{ Path = (Join-Path $repo 'src-tauri\Cargo.toml'); Sha = $script:D32TauriMacrosRootManifestSha256 },
        [PSCustomObject]@{ Path = (Join-Path $repo 'src-tauri\Cargo.lock'); Sha = $script:D32TauriMacrosRootLockSha256 },
        [PSCustomObject]@{ Path = (Join-Path $vendor 'Cargo.toml'); Sha = $script:D32TauriMacrosVendorManifestSha256 },
        [PSCustomObject]@{ Path = (Join-Path $vendor 'Cargo.lock'); Sha = $script:D32TauriMacrosVendorLockSha256 },
        [PSCustomObject]@{ Path = (Join-Path $vendor 'src\command\wrapper.rs'); Sha = $script:D32TauriMacrosPatchedSourceSha256 }
    )
    foreach ($file in $localFiles) {
        if ((Get-D32TauriMacrosCanonicalFileSha256 -Path $file.Path) -cne $file.Sha) { throw "TAURI_MACROS_SOURCE_PATCH_BLOCKED: candidate-local file differs from the pinned patch authority: $($file.Path)" }
    }
    return [PSCustomObject]@{ Document = $doc; Reference = (Get-D32VendoredFileReference -Path $AuthorityPath); Archive = $archiveSnapshot; VendoredTreeSha256 = $treeSha }
}

function Assert-D32VendoredFileReference {
    param(
        [Parameter(Mandatory = $true)][object]$Reference,
        [Parameter(Mandatory = $true)][string]$AllowedRoot,
        [AllowNull()][string]$ExpectedPath
    )
    $fields = @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')
    if (-not (Test-D32VendoredObjectExactProperties -Object $Reference -Expected $fields)) { throw 'VENDORED_PROTOC_BLOCKED: file reference has missing or extra fields' }
    $path = [string](Get-D32VendoredProperty $Reference 'path')
    $bytes = Get-D32VendoredProperty $Reference 'bytes'
    $sha = [string](Get-D32VendoredProperty $Reference 'sha256')
    $volume = [string](Get-D32VendoredProperty $Reference 'volume_serial_hex')
    $fileId = [string](Get-D32VendoredProperty $Reference 'file_id_hex')
    if (-not (Test-D32ProfileCanonicalPathString -Path $path) -or
        -not (Test-D32ProfilePathWithin -Child $path -Parent $AllowedRoot) -or
        ($ExpectedPath -and -not (Test-D32ProfilePathEqual -Left $path -Right $ExpectedPath)) -or
        $bytes -isnot [byte] -and $bytes -isnot [sbyte] -and $bytes -isnot [uint16] -and $bytes -isnot [int16] -and $bytes -isnot [uint32] -and $bytes -isnot [int32] -and $bytes -isnot [uint64] -and $bytes -isnot [int64] -or
        [Int64]$bytes -le 0 -or $sha -cnotmatch '^[0-9a-f]{64}$' -or $volume -cnotmatch '^[0-9a-f]{16}$' -or $fileId -cnotmatch '^[0-9a-f]{32}$') {
        throw 'VENDORED_PROTOC_BLOCKED: file reference path/hash/bytes/identity is malformed'
    }
    $snapshot = Get-D32ProfileFileSnapshot -Path $path
    if ($snapshot.Bytes -ne [Int64]$bytes -or $snapshot.Sha256 -cne $sha -or $snapshot.VolumeSerialHex -cne $volume -or $snapshot.FileIdHex -cne $fileId) {
        throw 'VENDORED_PROTOC_BLOCKED: file bytes or opened-handle identity changed'
    }
    return $snapshot
}

function Get-D32VendoredLockPackageRecords {
    param([Parameter(Mandatory = $true)][string]$Repository)
    $repositoryPath = Get-D32VendoredOrdinaryPath -Path $Repository
    $lockPath = [IO.Path]::GetFullPath((Join-Path $repositoryPath 'vita-agent\Cargo.lock'))
    if (-not (Test-D32ProfileNoReparsePath -Path $lockPath)) { throw 'VENDORED_PROTOC_LOCK_BLOCKED: Vita Cargo.lock is missing or reparse-backed' }
    $lockStream = [IO.File]::Open($lockPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $lockSnapshot = Get-D32ProfileFileSnapshot -Path $lockPath
        $lockStream.Position = 0
        $lockReader = [IO.StreamReader]::new($lockStream, [Text.Encoding]::UTF8, $true, 4096, $true)
        try { $lock = $lockReader.ReadToEnd() }
        finally { $lockReader.Dispose() }
        $lockSnapshotAfterRead = Get-D32ProfileFileSnapshot -Path $lockPath
        if ($lockSnapshotAfterRead.Bytes -ne $lockSnapshot.Bytes -or $lockSnapshotAfterRead.Sha256 -cne $lockSnapshot.Sha256 -or
            $lockSnapshotAfterRead.VolumeSerialHex -cne $lockSnapshot.VolumeSerialHex -or $lockSnapshotAfterRead.FileIdHex -cne $lockSnapshot.FileIdHex) {
            throw 'VENDORED_PROTOC_LOCK_BLOCKED: Cargo.lock path or opened identity changed while reading the locked package tuples'
        }
    }
    finally { $lockStream.Dispose() }
    $packages = [System.Collections.Generic.List[object]]::new()
    foreach ($block in [regex]::Split($lock, '(?m)(?=^\[\[package\]\]\s*$)')) {
        if ($block -notmatch '(?m)^name\s*=\s*"(protoc-bin-vendored(?:-win32)?)"\s*$') { continue }
        $name = [string]$Matches[1]
        $versionMatch = [regex]::Match($block, '(?m)^version\s*=\s*"([^"]+)"\s*$')
        $sourceMatch = [regex]::Match($block, '(?m)^source\s*=\s*"([^"]+)"\s*$')
        $checksumMatch = [regex]::Match($block, '(?m)^checksum\s*=\s*"([0-9a-f]{64})"\s*$')
        if (-not $versionMatch.Success -or -not $sourceMatch.Success -or -not $checksumMatch.Success) { throw "VENDORED_PROTOC_LOCK_BLOCKED: incomplete locked package record: $name" }
        $packages.Add([PSCustomObject]@{ name = $name; version = [string]$versionMatch.Groups[1].Value; source = [string]$sourceMatch.Groups[1].Value; checksum = [string]$checksumMatch.Groups[1].Value })
    }
    if (@($packages | Where-Object { $_.name -ceq 'protoc-bin-vendored' }).Count -ne 1 -or
        @($packages | Where-Object { $_.name -ceq 'protoc-bin-vendored-win32' }).Count -ne 1) {
        throw 'VENDORED_PROTOC_LOCK_BLOCKED: Vita lock must contain exactly one umbrella and one win32 protoc-bin-vendored 3.2.0 package'
    }
    $umbrella = @($packages | Where-Object { $_.name -ceq 'protoc-bin-vendored' })[0]
    $win32 = @($packages | Where-Object { $_.name -ceq 'protoc-bin-vendored-win32' })[0]
    $source = 'registry+https://github.com/rust-lang/crates.io-index'
    if ($umbrella.version -cne '3.2.0' -or $umbrella.source -cne $source -or $umbrella.checksum -cne $script:D32VendoredProtocUmbrellaChecksum -or
        $win32.version -cne '3.2.0' -or $win32.source -cne $source -or $win32.checksum -cne $script:D32VendoredProtocWin32Checksum) {
        throw 'VENDORED_PROTOC_LOCK_BLOCKED: locked protoc package name/version/source/checksum differs from the exact approval'
    }
    return [PSCustomObject]@{ Path = $lockPath; Snapshot = $lockSnapshot; Umbrella = $umbrella; Win32 = $win32 }
}

function New-D32VendoredProtocAuthorityDocument {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [ValidateSet('D32_PHASE0_PHASE1_ONLY', 'D32_TEST_INVENTORY_DISCOVERY_ONLY')][string]$Scope = 'D32_PHASE0_PHASE1_ONLY'
    )
    $repo = [IO.Path]::GetFullPath($Repository)
    $root = [IO.Path]::GetFullPath($EvidenceRoot)
    $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $ValidatedProfile
    if ($CandidateSha -cnotmatch '^[0-9a-f]{40}$' -or -not (Test-D32ProfileCanonicalPathString -Path $EvidenceRoot) -or
        (Test-D32ProfilePathWithin -Child $root -Parent $repo) -or (Test-D32ProfilePathWithin -Child $repo -Parent $root) -or
        -not (Test-D32ProfileNoReparsePath -Path $root -AllowMissingLeaf) -or (Test-Path -LiteralPath $root)) {
        throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: candidate/root shape or fresh external non-reparse EvidenceRoot is invalid'
    }
    $lock = Get-D32VendoredLockPackageRecords -Repository $repo
    $expectedHome = Join-Path (Join-Path $root 'r') 'c'
    $expectedTemp = Join-Path (Join-Path $root 'r') 't'
    return [ordered]@{
        schema_version = 1
        record_type = $script:D32VendoredProtocAuthorityType
        scope = $Scope
        candidate_sha = $CandidateSha
        toolchain_profile = [ordered]@{
            path = [string]$ValidatedProfile.ProfilePath
            sha256 = [string]$ValidatedProfile.Digest
            bytes = [Int64]$ValidatedProfile.Identity.Bytes
            volume_serial_hex = [string]$ValidatedProfile.Identity.VolumeSerialHex
            file_id_hex = [string]$ValidatedProfile.Identity.FileIdHex
        }
        evidence_root_path = $root
        cargo_home_path = [IO.Path]::GetFullPath($expectedHome)
        temp_root_path = [IO.Path]::GetFullPath($expectedTemp)
        vita_cargo_lock = [ordered]@{ path = $lock.Snapshot.Path; sha256 = $lock.Snapshot.Sha256; bytes = [Int64]$lock.Snapshot.Bytes }
        packages = @(
            [ordered]@{ name = $lock.Umbrella.name; version = $lock.Umbrella.version; source = $lock.Umbrella.source; checksum = $lock.Umbrella.checksum },
            [ordered]@{ name = $lock.Win32.name; version = $lock.Win32.version; source = $lock.Win32.source; checksum = $lock.Win32.checksum }
        )
        cargo_archive = [ordered]@{ relative_path = $script:D32VendoredProtocArchiveRelativePath; bytes = $script:D32VendoredProtocArchiveBytes; sha256 = $script:D32VendoredProtocWin32Checksum }
        image = [ordered]@{ relative_path = (Join-Path $script:D32VendoredProtocSourceRelativePath 'bin\protoc.exe'); bytes = $script:D32VendoredProtocImageBytes; sha256 = $script:D32VendoredProtocImageSha256 }
    }
}

function Write-D32VendoredProtocAuthorityCreateNew {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][object]$Document)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-D32ProfileCanonicalPathString -Path $full) -or -not (Test-D32ProfileNoReparsePath -Path $full -AllowMissingLeaf)) { throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: authority output is non-canonical or reparse-backed' }
    $parent = [IO.Path]::GetDirectoryName($full)
    if ([String]::IsNullOrWhiteSpace($parent) -or -not (Test-D32ProfileNoReparsePath -Path $parent)) { throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: authority output parent is missing or reparse-backed' }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Document -Depth 12 -Compress) + [Environment]::NewLine)
    $stream = [IO.File]::Open($full, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    return Get-D32VendoredFileReference -Path $full
}

function Test-D32VendoredProtocAuthority {
    param(
        [Parameter(Mandatory = $true)][string]$AuthorityPath,
        [Parameter(Mandatory = $true)][string]$ExpectedAuthoritySha256,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [ValidateSet('D32_PHASE0_PHASE1_ONLY', 'D32_TEST_INVENTORY_DISCOVERY_ONLY')][string]$ExpectedScope = 'D32_PHASE0_PHASE1_ONLY'
    )
    if ($ExpectedAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or -not (Test-D32ProfileCanonicalPathString -Path $AuthorityPath) -or
        -not (Test-D32ProfileNoReparsePath -Path $AuthorityPath) -or (Test-D32ProfilePathWithin -Child $AuthorityPath -Parent $Repository) -or
        (Test-D32ProfilePathWithin -Child $AuthorityPath -Parent $EvidenceRoot)) { throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: authority path/hash must be independently pinned outside repository and EvidenceRoot' }
    $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $ValidatedProfile
    $authorityStream = [IO.File]::Open($AuthorityPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $snapshot = Get-D32ProfileFileSnapshot -Path $AuthorityPath
        if ($snapshot.Sha256 -cne $ExpectedAuthoritySha256) { throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: external authority bytes differ from the caller-pinned SHA-256' }
        $authorityStream.Position = 0
        $authorityReader = [IO.StreamReader]::new($authorityStream, [Text.Encoding]::UTF8, $true, 4096, $true)
        try { $raw = $authorityReader.ReadToEnd() }
        finally { $authorityReader.Dispose() }
        $snapshotAfterRead = Get-D32ProfileFileSnapshot -Path $AuthorityPath
        if ($snapshotAfterRead.Bytes -ne $snapshot.Bytes -or $snapshotAfterRead.Sha256 -cne $snapshot.Sha256 -or
            $snapshotAfterRead.VolumeSerialHex -cne $snapshot.VolumeSerialHex -or $snapshotAfterRead.FileIdHex -cne $snapshot.FileIdHex) {
            throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: external authority changed while validating its exact caller-pinned bytes'
        }
    }
    finally { $authorityStream.Dispose() }
    $jsonDocument = [System.Text.Json.JsonDocument]::Parse($raw)
    try { if (Test-D32ProfileJsonElementDuplicates -Element $jsonDocument.RootElement) { throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: authority JSON contains duplicate keys' } }
    finally { $jsonDocument.Dispose() }
    $document = $raw | ConvertFrom-Json -DateKind String
    $expectedFields = @('schema_version', 'record_type', 'scope', 'candidate_sha', 'toolchain_profile', 'evidence_root_path', 'cargo_home_path', 'temp_root_path', 'vita_cargo_lock', 'packages', 'cargo_archive', 'image')
    if (-not (Test-D32VendoredObjectExactProperties -Object $document -Expected $expectedFields) -or
        -not (Test-D32VendoredInteger -Value $document.schema_version) -or [Int64]$document.schema_version -ne 1 -or $document.record_type -cne $script:D32VendoredProtocAuthorityType -or
        $document.record_type -isnot [string] -or $document.scope -isnot [string] -or $document.scope -cne $ExpectedScope -or
        $document.candidate_sha -isnot [string] -or $document.candidate_sha -cnotmatch '^[0-9a-f]{40}$' -or $document.candidate_sha -cne $CandidateSha -or
        -not (Test-D32VendoredObjectExactProperties -Object $document.toolchain_profile -Expected @('path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex')) -or
        $document.toolchain_profile.path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $document.toolchain_profile.path -Right $ValidatedProfile.ProfilePath) -or
        $document.toolchain_profile.sha256 -isnot [string] -or $document.toolchain_profile.sha256 -cne $ValidatedProfile.Digest -or
        -not (Test-D32VendoredInteger -Value $document.toolchain_profile.bytes -Positive) -or [Int64]$document.toolchain_profile.bytes -ne [Int64]$ValidatedProfile.Identity.Bytes -or
        $document.toolchain_profile.volume_serial_hex -isnot [string] -or $document.toolchain_profile.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or $document.toolchain_profile.volume_serial_hex -cne $ValidatedProfile.Identity.VolumeSerialHex -or
        $document.toolchain_profile.file_id_hex -isnot [string] -or $document.toolchain_profile.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or $document.toolchain_profile.file_id_hex -cne $ValidatedProfile.Identity.FileIdHex -or
        $document.evidence_root_path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $document.evidence_root_path -Right $EvidenceRoot) -or
        $document.cargo_home_path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $document.cargo_home_path -Right (Join-Path (Join-Path $EvidenceRoot 'r') 'c')) -or
        $document.temp_root_path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $document.temp_root_path -Right (Join-Path (Join-Path $EvidenceRoot 'r') 't'))) {
        throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: strict authority schema/candidate/profile/root binding is invalid or legacy/unknown'
    }
    $lock = Get-D32VendoredLockPackageRecords -Repository $Repository
    if (-not (Test-D32VendoredObjectExactProperties -Object $document.vita_cargo_lock -Expected @('path', 'sha256', 'bytes'))) { throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: authority Vita Cargo.lock reference shape is invalid' }
    if ($document.vita_cargo_lock.path -isnot [string] -or $document.vita_cargo_lock.sha256 -isnot [string] -or
        -not (Test-D32VendoredInteger -Value $document.vita_cargo_lock.bytes -Positive)) { throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: authority Vita Cargo.lock reference scalar types are invalid' }
    if (-not (Test-D32ProfilePathEqual -Left $document.vita_cargo_lock.path -Right $lock.Snapshot.Path)) { throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: authority Vita Cargo.lock path differs from current lock path' }
    if ($document.vita_cargo_lock.sha256 -cne $lock.Snapshot.Sha256) { throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: authority Vita Cargo.lock SHA-256 differs from current lock bytes' }
    if ([Int64]$document.vita_cargo_lock.bytes -ne [Int64]$lock.Snapshot.Bytes) { throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: authority Vita Cargo.lock byte count differs from current lock bytes' }
    if ($document.packages -isnot [Array] -or $document.packages.Count -ne 2) { throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: authority package array does not contain exactly two locked entries' }
    $expectedPackages = @($lock.Umbrella, $lock.Win32)
    for ($index = 0; $index -lt 2; $index++) {
        $entry = $document.packages[$index]
        $expected = $expectedPackages[$index]
        if (-not (Test-D32VendoredObjectExactProperties -Object $entry -Expected @('name', 'version', 'source', 'checksum')) -or
            $entry.name -isnot [string] -or $entry.version -isnot [string] -or $entry.source -isnot [string] -or $entry.checksum -isnot [string] -or
            $entry.name -cne $expected.name -or $entry.version -cne $expected.version -or $entry.source -cne $expected.source -or $entry.checksum -cne $expected.checksum) {
            throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: package tuple order/content differs from the two exact lock entries'
        }
    }
    if (-not (Test-D32VendoredObjectExactProperties -Object $document.cargo_archive -Expected @('relative_path', 'bytes', 'sha256')) -or
        $document.cargo_archive.relative_path -cne $script:D32VendoredProtocArchiveRelativePath -or
        -not (Test-D32VendoredInteger -Value $document.cargo_archive.bytes -Positive) -or [Int64]$document.cargo_archive.bytes -ne $script:D32VendoredProtocArchiveBytes -or $document.cargo_archive.sha256 -cne $script:D32VendoredProtocWin32Checksum -or
        -not (Test-D32VendoredObjectExactProperties -Object $document.image -Expected @('relative_path', 'bytes', 'sha256')) -or
        $document.image.relative_path -cne (Join-Path $script:D32VendoredProtocSourceRelativePath 'bin\protoc.exe') -or
        -not (Test-D32VendoredInteger -Value $document.image.bytes -Positive) -or [Int64]$document.image.bytes -ne $script:D32VendoredProtocImageBytes -or $document.image.sha256 -cne $script:D32VendoredProtocImageSha256) {
        throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: immutable archive/image values differ from the exact approval'
    }
    $snapshotAfter = Get-D32ProfileFileSnapshot -Path $AuthorityPath
    if ($snapshotAfter.Sha256 -cne $snapshot.Sha256 -or $snapshotAfter.Bytes -ne $snapshot.Bytes -or $snapshotAfter.VolumeSerialHex -cne $snapshot.VolumeSerialHex -or $snapshotAfter.FileIdHex -cne $snapshot.FileIdHex) {
        throw 'VENDORED_PROTOC_AUTHORITY_BLOCKED: external authority changed during strict validation'
    }
    return [PSCustomObject]@{ Document = $document; Reference = [ordered]@{ path = $snapshot.Path; bytes = $snapshot.Bytes; sha256 = $snapshot.Sha256; volume_serial_hex = $snapshot.VolumeSerialHex; file_id_hex = $snapshot.FileIdHex }; Snapshot = $snapshot }
}

function Read-D32VendoredProtocTarMembers {
    param([Parameter(Mandatory = $true)][IO.Stream]$TarStream)
    $reader = [System.Formats.Tar.TarReader]::new($TarStream, $true)
    $files = [System.Collections.Generic.Dictionary[string, byte[]]]::new([StringComparer]::OrdinalIgnoreCase)
    $expectedPrefix = $script:D32VendoredProtocPackageRoot + '/'
    $expanded = [Int64]0
    try {
        while ($null -ne ($entry = $reader.GetNextEntry($false))) {
            if ($entry.EntryType -ne [System.Formats.Tar.TarEntryType]::RegularFile) { throw 'VENDORED_PROTOC_ARCHIVE_BLOCKED: non-regular/special tar member is forbidden' }
            $name = [string]$entry.Name
            if ([String]::IsNullOrEmpty($name) -or $name.IndexOf([char]92) -ge 0 -or $name.Contains(':') -or $name.StartsWith('/') -or -not $name.StartsWith($expectedPrefix, [StringComparison]::Ordinal)) { throw 'VENDORED_PROTOC_ARCHIVE_BLOCKED: tar member is not in the exact package root or uses an alias' }
            $relative = $name.Substring($expectedPrefix.Length)
            $parts = @($relative.Split('/'))
            if ($parts.Count -eq 0 -or @($parts | Where-Object { [String]::IsNullOrEmpty($_) -or $_ -ceq '.' -or $_ -ceq '..' }).Count -gt 0) { throw 'VENDORED_PROTOC_ARCHIVE_BLOCKED: tar member contains an empty/dot/traversal component' }
            if ($entry.Length -lt 0 -or $entry.Length -gt 50000000 -or $expanded + [Int64]$entry.Length -gt 50000000) { throw 'VENDORED_PROTOC_ARCHIVE_BLOCKED: tar member size exceeds the fixed archive bound' }
            if ($files.ContainsKey($relative)) { throw 'VENDORED_PROTOC_ARCHIVE_BLOCKED: duplicate or case-colliding tar member' }
            $memory = [IO.MemoryStream]::new()
            try {
                if ($null -eq $entry.DataStream) { throw 'VENDORED_PROTOC_ARCHIVE_BLOCKED: regular tar member has no data stream' }
                $entry.DataStream.CopyTo($memory)
                if ($memory.Length -ne [Int64]$entry.Length) { throw 'VENDORED_PROTOC_ARCHIVE_BLOCKED: tar member byte count differs from its header' }
                $files.Add($relative, $memory.ToArray())
                $expanded += [Int64]$entry.Length
            }
            finally { $memory.Dispose() }
        }
    }
    finally { $reader.Dispose() }
    return [PSCustomObject]@{ Files = $files; ExpandedBytes = $expanded }
}

function Read-D32VendoredProtocArchive {
    param([Parameter(Mandatory = $true)][string]$ArchivePath)
    if (-not (Test-D32ProfileNoReparsePath -Path $ArchivePath)) { throw 'VENDORED_PROTOC_ARCHIVE_BLOCKED: locked archive path is missing or reparse-backed' }
    $stream = [IO.File]::Open($ArchivePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        # The retained read handle denies write/delete opens while the separate
        # identity snapshot hashes the same named file. The exact archive hash
        # then binds the bytes consumed by TarReader to the caller-approved crate.
        $before = Get-D32ProfileFileSnapshot -Path $ArchivePath
        if ($before.Bytes -ne $script:D32VendoredProtocArchiveBytes -or $before.Sha256 -cne $script:D32VendoredProtocWin32Checksum) { throw 'VENDORED_PROTOC_ARCHIVE_BLOCKED: archive bytes/hash do not match the exact locked win32 crate' }
        $stream.Position = 0
        $gzip = [IO.Compression.GZipStream]::new($stream, [IO.Compression.CompressionMode]::Decompress, $true)
        try { $members = Read-D32VendoredProtocTarMembers -TarStream $gzip }
        finally { $gzip.Dispose() }
        $files = $members.Files
        if ($files.Count -ne 21 -or -not $files.ContainsKey('bin/protoc.exe')) { throw 'VENDORED_PROTOC_ARCHIVE_BLOCKED: package entry inventory differs from the unique approved archive' }
        $image = $files['bin/protoc.exe']
        $imageSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($image)).ToLowerInvariant()
        if ([Int64]$image.Length -ne $script:D32VendoredProtocImageBytes -or $imageSha -cne $script:D32VendoredProtocImageSha256) { throw 'VENDORED_PROTOC_ARCHIVE_BLOCKED: unique bin/protoc.exe member bytes/hash differ from approval' }
        $after = Get-D32ProfileFileSnapshot -Path $ArchivePath
        if ($after.Bytes -ne $before.Bytes -or $after.Sha256 -cne $before.Sha256 -or $after.VolumeSerialHex -cne $before.VolumeSerialHex -or $after.FileIdHex -cne $before.FileIdHex) { throw 'VENDORED_PROTOC_ARCHIVE_BLOCKED: archive path or opened identity changed during validation' }
        return [PSCustomObject]@{ Path = $ArchivePath; Snapshot = $before; Files = $files; ImageBytes = $image }
    }
    finally { $stream.Dispose() }
}

function Ensure-D32VendoredDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $full) {
        if (-not (Test-D32ProfileNoReparsePath -Path $full) -or -not (Test-Path -LiteralPath $full -PathType Container)) { throw "VENDORED_PROTOC_SOURCE_BLOCKED: existing path is not a regular directory: $full" }
        return Get-D32ProfileDirectoryIdentity -Path $full
    }
    $parent = [IO.Path]::GetDirectoryName($full)
    if (-not (Test-D32ProfileNoReparsePath -Path $parent)) { throw 'VENDORED_PROTOC_SOURCE_BLOCKED: parent directory is missing or reparse-backed' }
    return New-D32ProfileDirectoryCreateNew -Path $full
}

function Ensure-D32VendoredDirectoryChain {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Boundary)
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetFullPath($Boundary)
    if (-not (Test-D32ProfilePathWithin -Child $full -Parent $root)) { throw 'VENDORED_PROTOC_SOURCE_BLOCKED: directory chain escaped the approved CargoHome' }
    $relative = [IO.Path]::GetRelativePath($root, $full)
    $current = $root
    foreach ($component in $relative.Split([char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))) {
        if ([String]::IsNullOrWhiteSpace($component) -or $component -ceq '.' -or $component -ceq '..') { throw 'VENDORED_PROTOC_SOURCE_BLOCKED: malformed canonical directory component' }
        $current = Join-Path $current $component
        $null = Ensure-D32VendoredDirectory -Path $current
    }
    return Get-D32ProfileDirectoryIdentity -Path $full
}

function Test-D32VendoredSourceTree {
    param([Parameter(Mandatory = $true)][string]$SourceRoot, [Parameter(Mandatory = $true)][object]$Archive)
    if (-not (Test-D32ProfileNoReparsePath -Path $SourceRoot) -or -not (Test-Path -LiteralPath $SourceRoot -PathType Container)) { throw 'VENDORED_PROTOC_SOURCE_BLOCKED: Cargo source package directory is missing/reparse-backed' }
    $expectedFiles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $expectedDirectories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($relative in $Archive.Files.Keys) { [void]$expectedFiles.Add([string]$relative.Replace('/', '\')) }
    foreach ($relative in $Archive.Files.Keys) {
        $parent = Split-Path -Parent ([string]$relative.Replace('/', '\'))
        while (-not [String]::IsNullOrWhiteSpace($parent)) {
            [void]$expectedDirectories.Add($parent)
            $parent = Split-Path -Parent $parent
        }
    }
    [void]$expectedFiles.Add('.cargo-ok')
    $actualFiles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in Get-ChildItem -LiteralPath $SourceRoot -File -Recurse -Force -ErrorAction Stop) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'VENDORED_PROTOC_SOURCE_BLOCKED: source tree contains a reparse-backed file' }
        $relative = [IO.Path]::GetRelativePath($SourceRoot, $file.FullName)
        if (-not $actualFiles.Add($relative)) { throw 'VENDORED_PROTOC_SOURCE_BLOCKED: source tree contains case-colliding entries' }
    }
    $actualDirectories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($directory in Get-ChildItem -LiteralPath $SourceRoot -Directory -Recurse -Force -ErrorAction Stop) {
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'VENDORED_PROTOC_SOURCE_BLOCKED: source tree contains a reparse-backed directory' }
        $relativeDirectory = [IO.Path]::GetRelativePath($SourceRoot, $directory.FullName)
        if (-not $actualDirectories.Add($relativeDirectory)) { throw 'VENDORED_PROTOC_SOURCE_BLOCKED: source tree contains case-colliding directories' }
    }
    if ($actualDirectories.Count -ne $expectedDirectories.Count) { throw 'VENDORED_PROTOC_SOURCE_BLOCKED: Cargo source tree directory inventory has unexpected/missing entries' }
    foreach ($relative in $expectedDirectories) { if (-not $actualDirectories.Contains($relative)) { throw "VENDORED_PROTOC_SOURCE_BLOCKED: Cargo source tree is missing approved directory $relative" } }
    if ($actualFiles.Count -ne $expectedFiles.Count) { throw 'VENDORED_PROTOC_SOURCE_BLOCKED: Cargo source tree file inventory has unexpected/missing members' }
    foreach ($relative in $expectedFiles) { if (-not $actualFiles.Contains($relative)) { throw "VENDORED_PROTOC_SOURCE_BLOCKED: Cargo source tree is missing approved file $relative" } }
    foreach ($relative in $Archive.Files.Keys) {
        $path = Join-Path $SourceRoot ([string]$relative.Replace('/', '\'))
        $expectedBytes = $Archive.Files[$relative]
        $actual = Get-D32ProfileFileSnapshot -Path $path
        $expectedHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($expectedBytes)).ToLowerInvariant()
        if ($actual.Bytes -ne $expectedBytes.Length -or $actual.Sha256 -cne $expectedHash) {
            throw "VENDORED_PROTOC_SOURCE_BLOCKED: extracted package member content differs from locked archive: $relative"
        }
    }
    $markerPath = Join-Path $SourceRoot '.cargo-ok'
    $marker = Get-D32ProfileFileSnapshot -Path $markerPath
    $expectedMarker = [Text.Encoding]::UTF8.GetBytes('{"v":1}')
    $expectedMarkerHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($expectedMarker)).ToLowerInvariant()
    if ($marker.Bytes -ne $expectedMarker.Length -or $marker.Sha256 -cne $expectedMarkerHash) { throw 'VENDORED_PROTOC_SOURCE_BLOCKED: Cargo extraction marker differs from the exact canonical marker' }
    return $true
}

function Ensure-D32VendoredProtocSource {
    param([Parameter(Mandatory = $true)][string]$CargoHome, [Parameter(Mandatory = $true)][object]$Authority)
    $archivePath = [IO.Path]::GetFullPath((Join-Path $CargoHome $script:D32VendoredProtocArchiveRelativePath))
    $sourceRoot = [IO.Path]::GetFullPath((Join-Path $CargoHome $script:D32VendoredProtocSourceRelativePath))
    if (-not (Test-D32ProfilePathWithin -Child $archivePath -Parent $CargoHome) -or -not (Test-D32ProfilePathWithin -Child $sourceRoot -Parent $CargoHome)) { throw 'VENDORED_PROTOC_SOURCE_BLOCKED: archive/source path escaped the exact run CargoHome' }
    $archive = Read-D32VendoredProtocArchive -ArchivePath $archivePath
    if (Test-Path -LiteralPath $sourceRoot) {
        Test-D32VendoredSourceTree -SourceRoot $sourceRoot -Archive $archive | Out-Null
    }
    else {
        $null = Ensure-D32VendoredDirectoryChain -Path $sourceRoot -Boundary $CargoHome
        foreach ($relative in $archive.Files.Keys) {
            $target = Join-Path $sourceRoot ([string]$relative.Replace('/', '\'))
            $directory = Split-Path -Parent $target
            if (-not (Test-D32ProfilePathEqual -Left $directory -Right $sourceRoot)) {
                $null = Ensure-D32VendoredDirectoryChain -Path $directory -Boundary $sourceRoot
            }
            $bytes = $archive.Files[$relative]
            $file = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) }
            finally { $file.Dispose() }
        }
        $cargoMarkerPath = Join-Path $sourceRoot '.cargo-ok'
        $marker = [IO.File]::Open($cargoMarkerPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $markerBytes = [Text.Encoding]::UTF8.GetBytes('{"v":1}')
        try { $marker.Write($markerBytes, 0, $markerBytes.Length); $marker.Flush($true) } finally { $marker.Dispose() }
        Test-D32VendoredSourceTree -SourceRoot $sourceRoot -Archive $archive | Out-Null
    }
    $imagePath = Join-Path $sourceRoot 'bin\protoc.exe'
    $image = Get-D32ProfileFileSnapshot -Path $imagePath
    if ($image.Bytes -ne $script:D32VendoredProtocImageBytes -or $image.Sha256 -cne $script:D32VendoredProtocImageSha256) { throw 'VENDORED_PROTOC_SOURCE_BLOCKED: exact extracted protoc image has wrong bytes/hash' }
    return [PSCustomObject]@{ Archive = $archive; SourcePath = $sourceRoot; SourceIdentity = (Get-D32ProfileDirectoryIdentity -Path $sourceRoot); Image = $image }
}

function New-D32VendoredProtocRunGrant {
    param(
        [Parameter(Mandatory = $true)][string]$AuthorityPath,
        [Parameter(Mandatory = $true)][string]$AuthoritySha256,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][object]$OwnerMarkerReference,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$CargoHome,
        [ValidateSet('D32_PHASE0_PHASE1_ONLY', 'D32_TEST_INVENTORY_DISCOVERY_ONLY')][string]$Scope = 'D32_PHASE0_PHASE1_ONLY'
    )
    $authority = Test-D32VendoredProtocAuthority -AuthorityPath $AuthorityPath -ExpectedAuthoritySha256 $AuthoritySha256 -Repository $Repository -CandidateSha $CandidateSha -ValidatedProfile $ValidatedProfile -EvidenceRoot $EvidenceRoot -ExpectedScope $Scope
    if ($RunId -cnotmatch '^[0-9a-f]{32}$' -or -not (Test-D32ProfilePathEqual -Left $CargoHome -Right $authority.Document.cargo_home_path)) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: run id or fresh CargoHome differs from authority template' }
    $rootIdentity = Get-D32ProfileDirectoryIdentity -Path $EvidenceRoot
    $homeIdentity = Get-D32ProfileDirectoryIdentity -Path $CargoHome
    $ownerPath = Join-Path $EvidenceRoot 'D32-PHASE0-OWNER.json'
    $actualOwner = Get-D32VendoredFileReference -Path $ownerPath
    if ((ConvertTo-Json -InputObject $actualOwner -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $OwnerMarkerReference -Depth 5 -Compress)) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: owner marker ref differs from retained caller-bound owner' }
    $materialized = Ensure-D32VendoredProtocSource -CargoHome $CargoHome -Authority $authority
    $lock = Get-D32VendoredLockPackageRecords -Repository $Repository
    $document = [ordered]@{
        schema_version = 1
        record_type = $script:D32VendoredProtocRunGrantType
        scope = $Scope
        authority = $authority.Reference
        candidate_sha = $CandidateSha
        toolchain_profile = [ordered]@{ path = $ValidatedProfile.ProfilePath; sha256 = $ValidatedProfile.Digest; bytes = [Int64]$ValidatedProfile.Identity.Bytes; volume_serial_hex = $ValidatedProfile.Identity.VolumeSerialHex; file_id_hex = $ValidatedProfile.Identity.FileIdHex }
        evidence_root = [ordered]@{ path = $rootIdentity.Path; volume_serial_hex = $rootIdentity.VolumeSerialHex; file_id_hex = $rootIdentity.FileIdHex }
        owner_marker = $actualOwner
        run_id = $RunId
        cargo_home = [ordered]@{ path = $homeIdentity.Path; volume_serial_hex = $homeIdentity.VolumeSerialHex; file_id_hex = $homeIdentity.FileIdHex }
        vita_cargo_lock = Get-D32VendoredFileReference -Path $lock.Path
        cargo_archive = Get-D32VendoredFileReference -Path $materialized.Archive.Path
        source_directory = [ordered]@{ path = $materialized.SourceIdentity.Path; volume_serial_hex = $materialized.SourceIdentity.VolumeSerialHex; file_id_hex = $materialized.SourceIdentity.FileIdHex }
        protoc_image = [ordered]@{ path = $materialized.Image.Path; bytes = [Int64]$materialized.Image.Bytes; sha256 = [string]$materialized.Image.Sha256; volume_serial_hex = [string]$materialized.Image.VolumeSerialHex; file_id_hex = [string]$materialized.Image.FileIdHex }
    }
    $grantName = if ($Scope -ceq 'D32_TEST_INVENTORY_DISCOVERY_ONLY') { 'D32-TEST-INVENTORY-VENDORED-PROTOC-RUN-GRANT.json' } else { 'D32-PHASE0-VENDORED-PROTOC-RUN-GRANT.json' }
    $grantPath = Join-Path $EvidenceRoot $grantName
    $grantRef = Write-D32VendoredProtocAuthorityCreateNew -Path $grantPath -Document $document
    return [PSCustomObject]@{ Document = $document; Reference = $grantRef; Authority = $authority; Image = $materialized.Image; Archive = $materialized.Archive; SourcePath = $materialized.SourcePath }
}

function Test-D32VendoredProtocRunGrant {
    param(
        [Parameter(Mandatory = $true)][object]$Reference,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedRunId,
        [Parameter(Mandatory = $true)][string]$CargoHome,
        [Parameter(Mandatory = $true)][string]$AuthorityPath,
        [Parameter(Mandatory = $true)][string]$AuthoritySha256,
        [Parameter(Mandatory = $true)][object]$OwnerMarkerReference,
        [ValidateSet('D32_PHASE0_PHASE1_ONLY', 'D32_TEST_INVENTORY_DISCOVERY_ONLY')][string]$Scope = 'D32_PHASE0_PHASE1_ONLY'
    )
    $grantPath = [string](Get-D32VendoredProperty $Reference 'path')
    $grantName = if ($Scope -ceq 'D32_TEST_INVENTORY_DISCOVERY_ONLY') { 'D32-TEST-INVENTORY-VENDORED-PROTOC-RUN-GRANT.json' } else { 'D32-PHASE0-VENDORED-PROTOC-RUN-GRANT.json' }
    $grantSnapshot = Assert-D32VendoredFileReference -Reference $Reference -AllowedRoot $EvidenceRoot -ExpectedPath (Join-Path $EvidenceRoot $grantName)
    $grantStream = [IO.File]::Open($grantPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $grantBeforeRead = Get-D32ProfileFileSnapshot -Path $grantPath
        if ($grantBeforeRead.Bytes -ne $grantSnapshot.Bytes -or $grantBeforeRead.Sha256 -cne $grantSnapshot.Sha256 -or
            $grantBeforeRead.VolumeSerialHex -cne $grantSnapshot.VolumeSerialHex -or $grantBeforeRead.FileIdHex -cne $grantSnapshot.FileIdHex) {
            throw 'VENDORED_PROTOC_GRANT_BLOCKED: grant opened identity changed before reading its exact schema'
        }
        $grantStream.Position = 0
        $grantReader = [IO.StreamReader]::new($grantStream, [Text.Encoding]::UTF8, $true, 4096, $true)
        try { $raw = $grantReader.ReadToEnd() }
        finally { $grantReader.Dispose() }
        $grantAfterRead = Get-D32ProfileFileSnapshot -Path $grantPath
        if ($grantAfterRead.Bytes -ne $grantSnapshot.Bytes -or $grantAfterRead.Sha256 -cne $grantSnapshot.Sha256 -or
            $grantAfterRead.VolumeSerialHex -cne $grantSnapshot.VolumeSerialHex -or $grantAfterRead.FileIdHex -cne $grantSnapshot.FileIdHex) {
            throw 'VENDORED_PROTOC_GRANT_BLOCKED: grant changed while validating its exact run-bound bytes'
        }
    }
    finally { $grantStream.Dispose() }
    $jsonDocument = [System.Text.Json.JsonDocument]::Parse($raw)
    try { if (Test-D32ProfileJsonElementDuplicates -Element $jsonDocument.RootElement) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: duplicate JSON keys' } }
    finally { $jsonDocument.Dispose() }
    $doc = $raw | ConvertFrom-Json -DateKind String
    $fields = @('schema_version', 'record_type', 'scope', 'authority', 'candidate_sha', 'toolchain_profile', 'evidence_root', 'owner_marker', 'run_id', 'cargo_home', 'vita_cargo_lock', 'cargo_archive', 'source_directory', 'protoc_image')
    if (-not (Test-D32VendoredObjectExactProperties -Object $doc -Expected $fields) -or
        -not (Test-D32VendoredInteger -Value $doc.schema_version) -or [Int64]$doc.schema_version -ne 1 -or $doc.record_type -cne $script:D32VendoredProtocRunGrantType -or $doc.scope -cne $Scope -or
        $doc.candidate_sha -isnot [string] -or $doc.candidate_sha -cnotmatch '^[0-9a-f]{40}$' -or $doc.candidate_sha -cne $CandidateSha -or
        $doc.run_id -isnot [string] -or $doc.run_id -cnotmatch '^[0-9a-f]{32}$' -or $doc.run_id -cne $ExpectedRunId -or
        -not (Test-D32VendoredObjectExactProperties -Object $doc.toolchain_profile -Expected @('path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex')) -or
        $doc.toolchain_profile.path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $doc.toolchain_profile.path -Right $ValidatedProfile.ProfilePath) -or
        $doc.toolchain_profile.sha256 -isnot [string] -or $doc.toolchain_profile.sha256 -cne $ValidatedProfile.Digest -or
        -not (Test-D32VendoredInteger -Value $doc.toolchain_profile.bytes -Positive) -or [Int64]$doc.toolchain_profile.bytes -ne [Int64]$ValidatedProfile.Identity.Bytes -or
        $doc.toolchain_profile.volume_serial_hex -isnot [string] -or $doc.toolchain_profile.volume_serial_hex -cne $ValidatedProfile.Identity.VolumeSerialHex -or
        $doc.toolchain_profile.file_id_hex -isnot [string] -or $doc.toolchain_profile.file_id_hex -cne $ValidatedProfile.Identity.FileIdHex -or
        -not (Test-D32VendoredObjectExactProperties -Object $doc.evidence_root -Expected @('path', 'volume_serial_hex', 'file_id_hex')) -or
        $doc.evidence_root.path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $doc.evidence_root.path -Right $EvidenceRoot) -or
        $doc.evidence_root.volume_serial_hex -isnot [string] -or $doc.evidence_root.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        $doc.evidence_root.file_id_hex -isnot [string] -or $doc.evidence_root.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        -not (Test-D32VendoredObjectExactProperties -Object $doc.cargo_home -Expected @('path', 'volume_serial_hex', 'file_id_hex')) -or
        $doc.cargo_home.path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $doc.cargo_home.path -Right $CargoHome) -or
        $doc.cargo_home.volume_serial_hex -isnot [string] -or $doc.cargo_home.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        $doc.cargo_home.file_id_hex -isnot [string] -or $doc.cargo_home.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        (ConvertTo-Json -InputObject $doc.owner_marker -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $OwnerMarkerReference -Depth 5 -Compress)) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: strict run-grant candidate/profile/root/owner/run/home binding failed' }
    $rootIdentity = Get-D32ProfileDirectoryIdentity -Path $EvidenceRoot
    $homeIdentity = Get-D32ProfileDirectoryIdentity -Path $CargoHome
    if ($doc.evidence_root.volume_serial_hex -cne $rootIdentity.VolumeSerialHex -or $doc.evidence_root.file_id_hex -cne $rootIdentity.FileIdHex -or
        $doc.cargo_home.volume_serial_hex -cne $homeIdentity.VolumeSerialHex -or $doc.cargo_home.file_id_hex -cne $homeIdentity.FileIdHex) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: opened root or CargoHome identity changed' }
    $ownerMarkerPath = Join-Path $EvidenceRoot 'D32-PHASE0-OWNER.json'
    $actualOwnerReference = Get-D32VendoredFileReference -Path $ownerMarkerPath
    if ((ConvertTo-Json -InputObject $actualOwnerReference -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $OwnerMarkerReference -Depth 5 -Compress) -or
        (ConvertTo-Json -InputObject $actualOwnerReference -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $doc.owner_marker -Depth 5 -Compress)) {
        throw 'VENDORED_PROTOC_GRANT_BLOCKED: current owner marker bytes/opened identity do not match the independently validated owner binding'
    }
    $authority = Test-D32VendoredProtocAuthority -AuthorityPath $AuthorityPath -ExpectedAuthoritySha256 $AuthoritySha256 -Repository $Repository -CandidateSha $CandidateSha -ValidatedProfile $ValidatedProfile -EvidenceRoot $EvidenceRoot -ExpectedScope $Scope
    $null = Assert-D32VendoredFileReference -Reference $doc.authority -AllowedRoot ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($AuthorityPath))) -ExpectedPath $AuthorityPath
    if ((ConvertTo-Json -InputObject $doc.authority -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $authority.Reference -Depth 5 -Compress)) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: external authority file identity/hash differs' }
    $lock = Get-D32VendoredLockPackageRecords -Repository $Repository
    $lockRef = Assert-D32VendoredFileReference -Reference $doc.vita_cargo_lock -AllowedRoot $Repository -ExpectedPath $lock.Path
    if ($lockRef.Sha256 -cne $lock.Snapshot.Sha256) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: Vita Cargo.lock changed' }
    $archivePath = Join-Path $CargoHome $script:D32VendoredProtocArchiveRelativePath
    $archive = Assert-D32VendoredFileReference -Reference $doc.cargo_archive -AllowedRoot $CargoHome -ExpectedPath $archivePath
    if ($archive.Bytes -ne $script:D32VendoredProtocArchiveBytes -or $archive.Sha256 -cne $script:D32VendoredProtocWin32Checksum) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: run archive identity/hash is not the exact locked package' }
    $sourcePath = Join-Path $CargoHome $script:D32VendoredProtocSourceRelativePath
    if (-not (Test-D32VendoredObjectExactProperties -Object $doc.source_directory -Expected @('path', 'volume_serial_hex', 'file_id_hex')) -or
        $doc.source_directory.path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $doc.source_directory.path -Right $sourcePath) -or
        $doc.source_directory.volume_serial_hex -isnot [string] -or $doc.source_directory.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        $doc.source_directory.file_id_hex -isnot [string] -or $doc.source_directory.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { throw 'VENDORED_PROTOC_GRANT_BLOCKED: source-directory path or identity is not the canonical Cargo registry slot' }
    $sourceIdentity = Get-D32ProfileDirectoryIdentity -Path $sourcePath
    if ($sourceIdentity.VolumeSerialHex -cne $doc.source_directory.volume_serial_hex -or $sourceIdentity.FileIdHex -cne $doc.source_directory.file_id_hex) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: source directory opened identity changed' }
    $protocPath = Join-Path $sourcePath 'bin\protoc.exe'
    $protoc = Assert-D32VendoredFileReference -Reference $doc.protoc_image -AllowedRoot $CargoHome -ExpectedPath $protocPath
    if ($protoc.Bytes -ne $script:D32VendoredProtocImageBytes -or $protoc.Sha256 -cne $script:D32VendoredProtocImageSha256) { throw 'VENDORED_PROTOC_GRANT_BLOCKED: extracted protoc image is not the exact approved bytes/hash' }
    $archiveContents = Read-D32VendoredProtocArchive -ArchivePath $archivePath
    Test-D32VendoredSourceTree -SourceRoot $sourcePath -Archive $archiveContents | Out-Null
    $grantFinal = Get-D32ProfileFileSnapshot -Path $grantPath
    if ($grantFinal.Bytes -ne $grantSnapshot.Bytes -or $grantFinal.Sha256 -cne $grantSnapshot.Sha256 -or
        $grantFinal.VolumeSerialHex -cne $grantSnapshot.VolumeSerialHex -or $grantFinal.FileIdHex -cne $grantSnapshot.FileIdHex) {
        throw 'VENDORED_PROTOC_GRANT_BLOCKED: grant bytes/opened identity changed during end-to-end validation'
    }
    return [PSCustomObject]@{ Document = $doc; Reference = $Reference; Snapshot = $grantSnapshot; Authority = $authority; Image = $protoc; Archive = $archive; SourcePath = $sourcePath }
}

function New-D32VendoredProtocEnvironment {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Environment, [Parameter(Mandatory = $true)][object]$RunGrant)
    $copy = [ordered]@{}
    foreach ($key in $Environment.Keys) { $copy[[string]$key] = [string]$Environment[$key] }
    $copy['PROTOC'] = [string]$RunGrant.Image.Path
    return $copy
}
