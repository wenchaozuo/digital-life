# Module-free, no-Cargo policy regression tests. This file is intentionally not
# referenced by any operational runner and must be run only as a focused test.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'd32-bounded-compiler-diagnostic-policy.ps1')

function Assert-D32BoundedCompilerDiagnosticSelfTest {
    param([string]$Name, [bool]$Condition)
    if (-not $Condition) { throw "D32_BOUNDED_COMPILER_DIAGNOSTIC_SELFTEST_FAILED: $Name" }
}

function ConvertFrom-D32BoundedCompilerDiagnosticTestJson {
    param([Parameter(Mandatory = $true)][string]$Json)
    $document = [System.Text.Json.JsonDocument]::Parse($Json)
    try {
        if ((Test-D32PowerShellAuthorityJsonDuplicates -Element $document.RootElement)) { throw 'synthetic JSON fixture has duplicate property names' }
        return ConvertFrom-D32PowerShellAuthorityJsonElement -Element $document.RootElement
    }
    finally { $document.Dispose() }
}

function Copy-D32BoundedCompilerDiagnosticTestJson {
    param([Parameter(Mandatory = $true)][object]$Record)
    return ConvertFrom-D32BoundedCompilerDiagnosticTestJson -Json (ConvertTo-Json -InputObject $Record -Depth 100 -Compress -ErrorAction Stop)
}

function Set-D32BoundedCompilerDiagnosticTestTarText {
    param([byte[]]$Header, [int]$Offset, [int]$Length, [string]$Value)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    if ($bytes.Length -gt $Length) { throw 'test tar text exceeds its fixed field' }
    [Array]::Copy($bytes, 0, $Header, $Offset, $bytes.Length)
}

function Set-D32BoundedCompilerDiagnosticTestTarOctal {
    param([byte[]]$Header, [int]$Offset, [int]$Length, [long]$Value)
    $text = [Convert]::ToString($Value, 8).PadLeft($Length - 1, '0') + "`0"
    $bytes = [Text.Encoding]::ASCII.GetBytes($text)
    if ($bytes.Length -ne $Length) { throw 'test tar octal exceeds its fixed field' }
    [Array]::Copy($bytes, 0, $Header, $Offset, $bytes.Length)
}

function Set-D32BoundedCompilerDiagnosticTestTarChecksum {
    param([Parameter(Mandatory = $true)][byte[]]$Header)
    for ($index = 148; $index -lt 156; $index++) { $Header[$index] = 32 }
    $sum = [Int64]0
    foreach ($value in $Header) { $sum += [Int64]$value }
    $checksum = [Convert]::ToString($sum, 8).PadLeft(6, '0') + "`0 "
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes($checksum), 0, $Header, 148, 8)
}

function Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected {
    param([Parameter(Mandatory = $true)][byte[]]$Header)
    try { $null = Get-D32BoundedDiagnosticRegistryArchiveHeader -Header $Header; return $false }
    catch { return $true }
}

function New-D32BoundedCompilerDiagnosticTestTarHeader {
    param([Parameter(Mandatory = $true)][object]$Entry)
    $header = [byte[]]::new(512)
    $format = if ($null -ne $Entry.PSObject.Properties['format']) { [string]$Entry.format } else { 'USTAR' }
    if ($null -ne $Entry.PSObject.Properties['name_field_bytes']) {
        $nameBytes = [byte[]]$Entry.name_field_bytes
        if ($nameBytes.Length -gt 100) { throw 'test tar raw name field exceeds its fixed size' }
        [Array]::Copy($nameBytes, 0, $header, 0, $nameBytes.Length)
    }
    else {
        $name = if ($null -ne $Entry.PSObject.Properties['name_field']) { [string]$Entry.name_field } else { [string]$Entry.path }
        Set-D32BoundedCompilerDiagnosticTestTarText -Header $header -Offset 0 -Length 100 -Value $name
    }
    if ($format -ceq 'USTAR' -and $null -ne $Entry.PSObject.Properties['prefix_field_bytes']) {
        $prefixBytes = [byte[]]$Entry.prefix_field_bytes
        if ($prefixBytes.Length -gt 155) { throw 'test tar raw prefix field exceeds its fixed size' }
        [Array]::Copy($prefixBytes, 0, $header, 345, $prefixBytes.Length)
    }
    elseif ($format -ceq 'USTAR' -and $null -ne $Entry.PSObject.Properties['prefix_field']) {
        Set-D32BoundedCompilerDiagnosticTestTarText -Header $header -Offset 345 -Length 155 -Value ([string]$Entry.prefix_field)
    }
    Set-D32BoundedCompilerDiagnosticTestTarOctal -Header $header -Offset 100 -Length 8 -Value $(if ($null -ne $Entry.PSObject.Properties['mode']) { [long]$Entry.mode } else { 420L })
    Set-D32BoundedCompilerDiagnosticTestTarOctal -Header $header -Offset 108 -Length 8 -Value $(if ($null -ne $Entry.PSObject.Properties['uid']) { [long]$Entry.uid } else { 0L })
    Set-D32BoundedCompilerDiagnosticTestTarOctal -Header $header -Offset 116 -Length 8 -Value $(if ($null -ne $Entry.PSObject.Properties['gid']) { [long]$Entry.gid } else { 0L })
    $content = if ($null -eq $Entry.PSObject.Properties['content'] -or $null -eq $Entry.content) { [byte[]]::new(0) } else { [byte[]]$Entry.content }
    $size = if ($null -ne $Entry.PSObject.Properties['size_override']) { [long]$Entry.size_override } else { [long]$content.Length }
    Set-D32BoundedCompilerDiagnosticTestTarOctal -Header $header -Offset 124 -Length 12 -Value $size
    Set-D32BoundedCompilerDiagnosticTestTarOctal -Header $header -Offset 136 -Length 12 -Value $(if ($null -ne $Entry.PSObject.Properties['mtime']) { [long]$Entry.mtime } else { 0L })
    if ($format -ceq 'USTAR') {
        [Array]::Copy([Text.Encoding]::ASCII.GetBytes("ustar`0"), 0, $header, 257, 6)
        [Array]::Copy([Text.Encoding]::ASCII.GetBytes('00'), 0, $header, 263, 2)
    }
    elseif ($format -ceq 'GNU') {
        [Array]::Copy([Text.Encoding]::ASCII.GetBytes('ustar '), 0, $header, 257, 6)
        [Array]::Copy([byte[]]@(32, 0), 0, $header, 263, 2)
        foreach ($field in @(
            [PSCustomObject]@{ name = 'atime'; offset = 345 },
            [PSCustomObject]@{ name = 'ctime'; offset = 357 },
            [PSCustomObject]@{ name = 'multi_volume_offset'; offset = 369 },
            [PSCustomObject]@{ name = 'real_size'; offset = 483 })) {
            if ($null -ne $Entry.PSObject.Properties[[string]$field.name]) {
                Set-D32BoundedCompilerDiagnosticTestTarOctal -Header $header -Offset ([int]$field.offset) -Length 12 -Value ([long]$Entry.([string]$field.name))
            }
        }
        if ($null -ne $Entry.PSObject.Properties['tail_mutator']) { & $Entry.tail_mutator $header }
    }
    else { throw 'unsupported synthetic tar fixture format' }
    if ($null -ne $Entry.PSObject.Properties['linkname_field']) {
        Set-D32BoundedCompilerDiagnosticTestTarText -Header $header -Offset 157 -Length 100 -Value ([string]$Entry.linkname_field)
    }
    if ($null -ne $Entry.PSObject.Properties['uname_field']) {
        Set-D32BoundedCompilerDiagnosticTestTarText -Header $header -Offset 265 -Length 32 -Value ([string]$Entry.uname_field)
    }
    if ($null -ne $Entry.PSObject.Properties['gname_field']) {
        Set-D32BoundedCompilerDiagnosticTestTarText -Header $header -Offset 297 -Length 32 -Value ([string]$Entry.gname_field)
    }
    if ($null -ne $Entry.PSObject.Properties['devmajor']) { Set-D32BoundedCompilerDiagnosticTestTarOctal -Header $header -Offset 329 -Length 8 -Value ([long]$Entry.devmajor) }
    if ($null -ne $Entry.PSObject.Properties['devminor']) { Set-D32BoundedCompilerDiagnosticTestTarOctal -Header $header -Offset 337 -Length 8 -Value ([long]$Entry.devminor) }
    if ($null -ne $Entry.PSObject.Properties['header_mutator']) { & $Entry.header_mutator $header }
    $typeFlag = if ($null -ne $Entry.PSObject.Properties['type_flag']) { $Entry.type_flag } elseif ([string]$Entry.kind -ceq 'directory') { '5' } else { '0' }
    if ($typeFlag -is [byte] -or $typeFlag -is [int]) { $header[156] = [byte]$typeFlag } else { $header[156] = [byte][char][string]$typeFlag }
    Set-D32BoundedCompilerDiagnosticTestTarChecksum -Header $header
    return ,$header
}

function New-D32BoundedCompilerDiagnosticTestGnuLongNameControl {
    param([Parameter(Mandatory = $true)][byte[]]$Payload, [int]$PaddingByte = 0, [long]$SizeOverride = -1L)
    $size = if ($SizeOverride -ge 0) { $SizeOverride } else { [Int64]$Payload.Length }
    return [PSCustomObject][ordered]@{
        format = 'GNU'; path = '././@LongLink'; name_field = '././@LongLink'; kind = 'file'; type_flag = 'L'
        content = $Payload; size_override = $size; padding_byte = $PaddingByte
    }
}

function New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries {
    param(
        [Parameter(Mandatory = $true)][string]$EffectivePath,
        [ValidateSet('GNU', 'USTAR')][string]$Format = 'GNU',
        [AllowNull()][string]$NameField,
        [AllowNull()][string]$PrefixField,
        [AllowNull()][AllowEmptyCollection()][byte[]]$NameFieldBytes,
        [ValidateSet('file', 'directory')][string]$Kind = 'file',
        [switch]$PayloadDirectorySlash,
        [AllowNull()][byte[]]$Content = $null,
        [int]$ControlPaddingByte = 0
    )
    $payloadPath = $EffectivePath
    if ($PayloadDirectorySlash) { $payloadPath += '/' }
    $pathBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($payloadPath)
    $payload = [byte[]]::new($pathBytes.Length + 1)
    [Array]::Copy($pathBytes, 0, $payload, 0, $pathBytes.Length)
    $payload[$payload.Length - 1] = 0
    $control = New-D32BoundedCompilerDiagnosticTestGnuLongNameControl -Payload $payload -PaddingByte $ControlPaddingByte
    $member = [PSCustomObject][ordered]@{
        format = $Format; path = $EffectivePath; kind = $Kind
        content = $(if ($Kind -ceq 'directory') { [byte[]]::new(0) } elseif ($null -eq $Content) { [byte[]]@([byte]1) } else { [byte[]]$Content })
    }
    if ($null -ne $NameFieldBytes) { $member | Add-Member -NotePropertyName name_field_bytes -NotePropertyValue ([byte[]]$NameFieldBytes) }
    elseif ($null -ne $NameField) { $member | Add-Member -NotePropertyName name_field -NotePropertyValue $NameField }
    if ($Format -ceq 'USTAR' -and $null -ne $PrefixField) { $member | Add-Member -NotePropertyName prefix_field -NotePropertyValue $PrefixField }
    return ,@($control, $member)
}

function New-D32BoundedCompilerDiagnosticTestTarGzip {
    param(
        [Parameter(Mandatory = $true)][object[]]$Entries,
        [int]$TerminatorBlocks = 2,
        [byte[]]$TrailingBytes = @(),
        [switch]$CorruptGzipTrailer
    )
    $tar = [IO.MemoryStream]::new()
    try {
        foreach ($entry in $Entries) {
            $header = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry $entry
            $content = if ($null -eq $entry.content) { [byte[]]::new(0) } else { [byte[]]$entry.content }
            $tar.Write($header, 0, $header.Length)
            if ($content.Length -gt 0) { $tar.Write($content, 0, $content.Length) }
            $padding = (512 - ($content.Length % 512)) % 512
            if ($padding -gt 0) {
                $paddingBytes = [byte[]]::new($padding)
                if ($null -ne $entry.PSObject.Properties['padding_byte']) { $paddingBytes[0] = [byte]$entry.padding_byte }
                $tar.Write($paddingBytes, 0, $padding)
            }
        }
        for ($terminatorIndex = 0; $terminatorIndex -lt $TerminatorBlocks; $terminatorIndex++) {
            $zeroBlock = [byte[]]::new(512)
            $tar.Write($zeroBlock, 0, $zeroBlock.Length)
        }
        if ($TrailingBytes.Length -gt 0) { $tar.Write($TrailingBytes, 0, $TrailingBytes.Length) }
        $compressed = [IO.MemoryStream]::new()
        try {
            $gzip = [IO.Compression.GZipStream]::new($compressed, [IO.Compression.CompressionMode]::Compress, $true)
            try { $bytes = $tar.ToArray(); $gzip.Write($bytes, 0, $bytes.Length) }
            finally { $gzip.Dispose() }
            $result = $compressed.ToArray()
            if ($CorruptGzipTrailer -and $result.Length -gt 0) { $result[$result.Length - 1] = $result[$result.Length - 1] -bxor 1 }
            return ,$result
        }
        finally { $compressed.Dispose() }
    }
    finally { $tar.Dispose() }
}

function New-D32BoundedCompilerDiagnosticTestZlib {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $output = [IO.MemoryStream]::new()
    try {
        $compressor = [IO.Compression.ZLibStream]::new($output, [IO.Compression.CompressionLevel]::Optimal, $true)
        try { $compressor.Write($Bytes, 0, $Bytes.Length) }
        finally { $compressor.Dispose() }
        return ,$output.ToArray()
    }
    finally { $output.Dispose() }
}

function Get-D32BoundedCompilerDiagnosticTestGitObjectOid {
    param([Parameter(Mandatory = $true)][string]$Type, [Parameter(Mandatory = $true)][byte[]]$Body)
    $prefix = [Text.Encoding]::ASCII.GetBytes($Type + ' ' + $Body.Length + [char]0)
    $input = [byte[]]::new($prefix.Length + $Body.Length)
    [Array]::Copy($prefix, 0, $input, 0, $prefix.Length)
    [Array]::Copy($Body, 0, $input, $prefix.Length, $Body.Length)
    return [Convert]::ToHexString([Security.Cryptography.SHA1]::HashData($input)).ToLowerInvariant()
}

function New-D32BoundedCompilerDiagnosticTestGitPackEntry {
    param([int]$Type, [long]$DeclaredSize, [byte[]]$ExtraHeader, [byte[]]$Body)
    $header = [System.Collections.Generic.List[byte]]::new()
    $remaining = $DeclaredSize
    $first = ($Type -shl 4) -bor [int]($remaining -band 15L)
    $remaining = $remaining -shr 4
    if ($remaining -gt 0) { $first = $first -bor 128 }
    $header.Add([byte]$first)
    while ($remaining -gt 0) {
        $next = [int]($remaining -band 127L)
        $remaining = $remaining -shr 7
        if ($remaining -gt 0) { $next = $next -bor 128 }
        $header.Add([byte]$next)
    }
    $stream = [IO.MemoryStream]::new()
    try {
        $headerBytes = [byte[]]$header.ToArray()
        $stream.Write($headerBytes, 0, $headerBytes.Length)
        if ($null -ne $ExtraHeader -and $ExtraHeader.Length -gt 0) { $stream.Write($ExtraHeader, 0, $ExtraHeader.Length) }
        $stream.Write($Body, 0, $Body.Length)
        return ,$stream.ToArray()
    }
    finally { $stream.Dispose() }
}

function Write-D32BoundedCompilerDiagnosticTestU32BE {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream, [Parameter(Mandatory = $true)][uint32]$Value)
    $bytes = [byte[]]@([byte]($Value -shr 24), [byte](($Value -shr 16) -band 255), [byte](($Value -shr 8) -band 255), [byte]($Value -band 255))
    $Stream.Write($bytes, 0, 4)
}

function New-D32BoundedCompilerDiagnosticTestGitPack {
    $baseBytes = [Text.Encoding]::ASCII.GetBytes('hello world')
    $resultBytes = [Text.Encoding]::ASCII.GetBytes('hello world!')
    $baseOid = Get-D32BoundedCompilerDiagnosticTestGitObjectOid -Type 'blob' -Body $baseBytes
    $resultOid = Get-D32BoundedCompilerDiagnosticTestGitObjectOid -Type 'blob' -Body $resultBytes
    $baseEntry = New-D32BoundedCompilerDiagnosticTestGitPackEntry -Type 3 -DeclaredSize $baseBytes.Length -ExtraHeader ([byte[]]::new(0)) -Body (New-D32BoundedCompilerDiagnosticTestZlib -Bytes $baseBytes)
    $deltaBody = [byte[]]@([byte]11, [byte]12, [byte]0x90, [byte]11, [byte]1, [byte][char]'!')
    $baseOidBytes = [Convert]::FromHexString($baseOid)
    $deltaEntry = New-D32BoundedCompilerDiagnosticTestGitPackEntry -Type 7 -DeclaredSize $deltaBody.Length -ExtraHeader $baseOidBytes -Body (New-D32BoundedCompilerDiagnosticTestZlib -Bytes $deltaBody)
    $pack = [IO.MemoryStream]::new()
    try {
        $pack.Write([byte[]]@(0x50, 0x41, 0x43, 0x4b), 0, 4)
        Write-D32BoundedCompilerDiagnosticTestU32BE -Stream $pack -Value 2
        Write-D32BoundedCompilerDiagnosticTestU32BE -Stream $pack -Value 2
        $entries = [System.Collections.Generic.List[object]]::new()
        $baseOffset = [Int64]$pack.Position
        $pack.Write($baseEntry, 0, $baseEntry.Length)
        $entries.Add([PSCustomObject]@{ oid = $baseOid; offset = $baseOffset; bytes = $baseEntry; crc = [D32BoundedGitPackReaderV1]::ComputeCrc32($baseEntry, 0, $baseEntry.Length) })
        $deltaOffset = [Int64]$pack.Position
        $pack.Write($deltaEntry, 0, $deltaEntry.Length)
        $entries.Add([PSCustomObject]@{ oid = $resultOid; offset = $deltaOffset; bytes = $deltaEntry; crc = [D32BoundedGitPackReaderV1]::ComputeCrc32($deltaEntry, 0, $deltaEntry.Length) })
        $withoutTrailer = $pack.ToArray()
        $packDigest = [Security.Cryptography.SHA1]::HashData($withoutTrailer)
        $packId = [Convert]::ToHexString($packDigest).ToLowerInvariant()
        $pack.Write($packDigest, 0, $packDigest.Length)
        $packBytes = $pack.ToArray()
    }
    finally { $pack.Dispose() }

    $index = [IO.MemoryStream]::new()
    try {
        $objects = [object[]]@($entries.ToArray() | Sort-Object -Property oid -CaseSensitive)
        Write-D32BoundedCompilerDiagnosticTestU32BE -Stream $index -Value ([Convert]::ToUInt32('ff744f63', 16))
        Write-D32BoundedCompilerDiagnosticTestU32BE -Stream $index -Value 2
        $fanout = [uint32[]]::new(256)
        foreach ($entry in $objects) { $fanout[[Convert]::ToByte(([string]$entry.oid).Substring(0, 2), 16)]++ }
        $cumulative = [uint32]0
        for ($i = 0; $i -lt 256; $i++) { $cumulative += $fanout[$i]; Write-D32BoundedCompilerDiagnosticTestU32BE -Stream $index -Value $cumulative }
        foreach ($entry in $objects) { $oid = [Convert]::FromHexString([string]$entry.oid); $index.Write($oid, 0, $oid.Length) }
        foreach ($entry in $objects) { Write-D32BoundedCompilerDiagnosticTestU32BE -Stream $index -Value ([uint32]$entry.crc) }
        foreach ($entry in $objects) { Write-D32BoundedCompilerDiagnosticTestU32BE -Stream $index -Value ([uint32]$entry.offset) }
        $index.Write($packDigest, 0, $packDigest.Length)
        $indexPrefix = $index.ToArray()
        $indexDigest = [Security.Cryptography.SHA1]::HashData($indexPrefix)
        $index.Write($indexDigest, 0, $indexDigest.Length)
        return [PSCustomObject]@{ pack = $packBytes; index = $index.ToArray(); pack_id = $packId; base_oid = $baseOid; result_oid = $resultOid; result_bytes = $resultBytes }
    }
    finally { $index.Dispose() }
}

Initialize-D32BoundedCompilerDiagnosticGitPackType
$gitPackFixture = New-D32BoundedCompilerDiagnosticTestGitPack
$gitPackStream = [IO.MemoryStream]::new([byte[]]$gitPackFixture.pack, $false)
$gitPackReader = $null
try {
    $gitPackReader = [D32BoundedGitPackReaderV1]::new($gitPackStream, [byte[]]$gitPackFixture.index, [string]$gitPackFixture.pack_id, 10000L, 1048576L)
    $resolvedDelta = $gitPackReader.Resolve([string]$gitPackFixture.result_oid)
    try {
        Assert-D32BoundedCompilerDiagnosticSelfTest 'bounded Git pack reader resolves a checksummed two-object REF_DELTA chain' (
            $resolvedDelta.Type -ceq 'blob' -and $resolvedDelta.Oid -ceq [string]$gitPackFixture.result_oid -and
            [Text.Encoding]::ASCII.GetString($resolvedDelta.Data) -ceq 'hello world!' -and
            $gitPackReader.ObjectCount -eq 2 -and $gitPackReader.PeakWorkingBytes -le 1048576L)
    }
    finally { $gitPackReader.Release($resolvedDelta) }
}
finally {
    if ($null -ne $gitPackReader) { $gitPackReader.Dispose() }
    $gitPackStream.Dispose()
}

$wrongPackIdStream = [IO.MemoryStream]::new([byte[]]$gitPackFixture.pack, $false)
try {
    try { $null = [D32BoundedGitPackReaderV1]::new($wrongPackIdStream, [byte[]]$gitPackFixture.index, ('0' * 40), 10000L, 1048576L); $wrongPackIdRejected = $false }
    catch { $wrongPackIdRejected = $_.Exception.Message.Contains('pack trailer, index pack checksum, or filename SHA-1 mismatch') }
    Assert-D32BoundedCompilerDiagnosticSelfTest 'Git pack filename/trailer hash mismatch rejected' $wrongPackIdRejected
}
finally { $wrongPackIdStream.Dispose() }

$badIndexDigest = [byte[]]$gitPackFixture.index.Clone()
$badIndexDigest[$badIndexDigest.Length - 1] = $badIndexDigest[$badIndexDigest.Length - 1] -bxor 1
$badIndexStream = [IO.MemoryStream]::new([byte[]]$gitPackFixture.pack, $false)
try {
    try { $null = [D32BoundedGitPackReaderV1]::new($badIndexStream, $badIndexDigest, [string]$gitPackFixture.pack_id, 10000L, 1048576L); $badIndexRejected = $false }
    catch { $badIndexRejected = $_.Exception.Message.Contains('Git index checksum mismatch') }
    Assert-D32BoundedCompilerDiagnosticSelfTest 'Git index checksum mismatch rejected' $badIndexRejected
}
finally { $badIndexStream.Dispose() }

$badCrcIndex = [byte[]]$gitPackFixture.index.Clone()
$baseIndexOrdinal = if ([StringComparer]::Ordinal.Compare([string]$gitPackFixture.base_oid, [string]$gitPackFixture.result_oid) -lt 0) { 0 } else { 1 }
$crcTableOffset = 8 + (256 * 4) + (2 * 20)
$badCrcIndex[$crcTableOffset + ($baseIndexOrdinal * 4) + 3] = $badCrcIndex[$crcTableOffset + ($baseIndexOrdinal * 4) + 3] -bxor 1
$indexContentLength = $badCrcIndex.Length - 20
$indexPrefixBytes = [byte[]]::new($indexContentLength)
[Array]::Copy($badCrcIndex, 0, $indexPrefixBytes, 0, $indexContentLength)
$newIndexDigest = [Security.Cryptography.SHA1]::HashData($indexPrefixBytes)
[Array]::Copy($newIndexDigest, 0, $badCrcIndex, $indexContentLength, 20)
$badCrcStream = [IO.MemoryStream]::new([byte[]]$gitPackFixture.pack, $false)
$badCrcReader = $null
try {
    $badCrcReader = [D32BoundedGitPackReaderV1]::new($badCrcStream, $badCrcIndex, [string]$gitPackFixture.pack_id, 10000L, 1048576L)
    try { $null = $badCrcReader.Resolve([string]$gitPackFixture.result_oid); $badCrcRejected = $false }
    catch { $badCrcRejected = $_.Exception.Message.Contains('Git pack entry CRC differs from its v2 index record') }
    Assert-D32BoundedCompilerDiagnosticSelfTest 'Git packed-record CRC mismatch rejected after valid pack/index checksums' $badCrcRejected
}
finally {
    if ($null -ne $badCrcReader) { $badCrcReader.Dispose() }
    $badCrcStream.Dispose()
}

$treeBody = [IO.MemoryStream]::new()
try {
    $treeEntryPrefix = [Text.Encoding]::ASCII.GetBytes('100644 file.txt' + [char]0)
    $treeBody.Write($treeEntryPrefix, 0, $treeEntryPrefix.Length)
    $treeBlobOid = [Convert]::FromHexString([string]$gitPackFixture.result_oid)
    $treeBody.Write($treeBlobOid, 0, $treeBlobOid.Length)
    $treeBytes = $treeBody.ToArray()
}
finally { $treeBody.Dispose() }
$parsedTree = [D32BoundedGitPackReaderV1]::ParseTree($treeBytes)
$treeOid = Get-D32BoundedCompilerDiagnosticTestGitObjectOid -Type 'tree' -Body $treeBytes
$commitBytes = [Text.Encoding]::ASCII.GetBytes(('tree ' + $treeOid + "`nauthor Example <e@example.invalid> 1 +0000`ncommitter Example <e@example.invalid> 1 +0000`n`nmessage`n"))
Assert-D32BoundedCompilerDiagnosticSelfTest 'Git tree and first commit tree header parse strictly' (
    $parsedTree.Count -eq 1 -and $parsedTree[0].Name -ceq 'file.txt' -and $parsedTree[0].Kind -ceq 'blob' -and
    [D32BoundedGitPackReaderV1]::CommitTreeOid($commitBytes) -ceq $treeOid)
$unsafeTreePrefix = [Text.Encoding]::ASCII.GetBytes('100644 ../escape' + [char]0)
$unsafeTreeBytes = [byte[]]::new($unsafeTreePrefix.Length + 20)
[Array]::Copy($unsafeTreePrefix, 0, $unsafeTreeBytes, 0, $unsafeTreePrefix.Length)
try { $null = [D32BoundedGitPackReaderV1]::ParseTree($unsafeTreeBytes); $unsafeTreeRejected = $false } catch { $unsafeTreeRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'unsafe Git tree path rejected' $unsafeTreeRejected
$collisionTreeStream = [IO.MemoryStream]::new()
try {
    foreach ($name in @('README', 'Readme')) {
        $prefix = [Text.Encoding]::ASCII.GetBytes('100644 ' + $name + [char]0)
        $collisionTreeStream.Write($prefix, 0, $prefix.Length)
        $collisionTreeStream.Write($treeBlobOid, 0, $treeBlobOid.Length)
    }
    $collisionTreeBytes = $collisionTreeStream.ToArray()
}
finally { $collisionTreeStream.Dispose() }
try { $null = [D32BoundedGitPackReaderV1]::ParseTree($collisionTreeBytes); $treeCollisionRejected = $false } catch { $treeCollisionRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'case-insensitive Git tree path collision rejected' $treeCollisionRejected

$fixedArgv = @(Get-D32BoundedCompilerDiagnosticFixedArgv)
Assert-D32BoundedCompilerDiagnosticSelfTest 'exact argv accepted' (Test-D32BoundedCompilerDiagnosticFixedArgv $fixedArgv)
$extraArgv = @($fixedArgv) + @('--', 'some_test')
Assert-D32BoundedCompilerDiagnosticSelfTest 'extra test execution argv rejected' (-not (Test-D32BoundedCompilerDiagnosticFixedArgv $extraArgv))
$runArgv = @($fixedArgv)
$runIndex = [Array]::IndexOf($runArgv, '--no-run')
$runArgv[$runIndex] = '--run'
Assert-D32BoundedCompilerDiagnosticSelfTest 'missing no-run guard rejected' (-not (Test-D32BoundedCompilerDiagnosticFixedArgv $runArgv))
$fixedGitQueries = [object[]]::new(5)
$fixedGitQueries[0] = [string[]]@('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}')
$fixedGitQueries[1] = [string[]]@('status', '--porcelain=v1', '--untracked-files=all')
$fixedGitQueries[2] = [string[]]@('ls-files', '-v', '-z')
$fixedGitQueries[3] = [string[]]@('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}')
$fixedGitQueries[4] = [string[]]@('status', '--porcelain=v1', '--untracked-files=all')
Assert-D32BoundedCompilerDiagnosticSelfTest 'exact five-query Git metadata sequence accepted' (Test-D32BoundedCompilerDiagnosticGitQueryList $fixedGitQueries)
Assert-D32BoundedCompilerDiagnosticSelfTest 'each exact Git metadata query receives the diagnostic-only finite query bound' (@($fixedGitQueries | Where-Object { Test-D32BoundedCompilerDiagnosticFixedGitQuery $_ }).Count -eq 5 -and $script:D32BoundedCompilerDiagnosticGitQueryTimeoutMilliseconds -eq 5000 -and $script:D32BoundedCompilerDiagnosticGitJoinGraceMilliseconds -eq 5000 -and $script:D32BoundedCompilerDiagnosticGitPipeJoinMilliseconds -eq 5000)
$unsafeGitQuery = [string[]]@('-c', 'core.pager=malicious', 'status', '--porcelain=v1', '--untracked-files=all')
Assert-D32BoundedCompilerDiagnosticSelfTest 'arbitrary Git config/query rejected by bounded diagnostic helper' (-not (Test-D32BoundedCompilerDiagnosticFixedGitQuery $unsafeGitQuery))
$wrongGitQueries = [object[]]@($fixedGitQueries); $wrongGitQueries[3] = [string[]]@('rev-parse', 'HEAD')
Assert-D32BoundedCompilerDiagnosticSelfTest 'wrong final Git query is rejected' (-not (Test-D32BoundedCompilerDiagnosticGitQueryList $wrongGitQueries))

$quietProcessRows = @(
    [PSCustomObject]@{ Name = 'System Idle Process'; ProcessId = [uint32]0; ParentProcessId = [uint32]0; CommandLine = $null; ExecutablePath = $null },
    [PSCustomObject]@{ Name = 'System'; ProcessId = [uint32]4; ParentProcessId = [uint32]0; CommandLine = $null; ExecutablePath = $null },
    [PSCustomObject]@{ Name = 'powershell.exe'; ProcessId = [uint32]600; ParentProcessId = [uint32]4; CommandLine = $null; ExecutablePath = $null; WorkingDirectory = $null }
)
$quietCensus = Assert-D32BoundedCompilerDiagnosticNoGlobalWriter -ProcessProbe { $quietProcessRows }
Assert-D32BoundedCompilerDiagnosticSelfTest 'complete global process census with no build-class process is accepted despite unrelated null command lines and unknown working directories' ($quietCensus.process_count -eq 3 -and $quietCensus.competing_target_writer_count -eq 0 -and $quietCensus.target_writer_check -ceq 'Win32-CIM-active-build-process-census')

$globalWriterNames = @('cargo.exe', 'rustc.exe', 'cl.exe', 'link.exe', 'build-script-build.exe')
foreach ($writerName in $globalWriterNames) {
    $unrelatedHomeWriterRows = @(
        [PSCustomObject]@{ Name = 'System Idle Process'; ProcessId = [uint32]0; ParentProcessId = [uint32]0 },
        [PSCustomObject]@{ Name = [string]$writerName; ProcessId = [uint32]700; ParentProcessId = [uint32]4; CommandLine = $null; ExecutablePath = 'C:\\unrelated\\tool.exe'; WorkingDirectory = $null }
    )
    $unrelatedHomeCensus = Get-D32BoundedCompilerDiagnosticGlobalWriterCensus -ProcessProbe { $unrelatedHomeWriterRows }
    $unrelatedHomeWriterBlocked = $false
    try { $null = Assert-D32BoundedCompilerDiagnosticNoGlobalWriter -ProcessProbe { $unrelatedHomeWriterRows } }
    catch { $unrelatedHomeWriterBlocked = $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: competing target writer exists:*' }
    Assert-D32BoundedCompilerDiagnosticSelfTest "global $writerName blocks regardless of unrelated executable path, null command line, or unknown cwd" ($unrelatedHomeCensus.competing_target_writer_count -eq 1 -and $unrelatedHomeWriterBlocked)
}

$unrelatedPathWriterRows = @(
    [PSCustomObject]@{ Name = 'System Idle Process'; ProcessId = [uint32]0; ParentProcessId = [uint32]0 },
    [PSCustomObject]@{ Name = 'cargo.exe'; ProcessId = [uint32]701; ParentProcessId = [uint32]4; CommandLine = 'cargo build --manifest-path other-project/Cargo.toml'; ExecutablePath = 'D:\\other\\cargo.exe'; WorkingDirectory = 'D:\\other' }
)
$unrelatedPathCensus = Get-D32BoundedCompilerDiagnosticGlobalWriterCensus -ProcessProbe { $unrelatedPathWriterRows }
Assert-D32BoundedCompilerDiagnosticSelfTest 'known Cargo process blocks even when command line and working directory name a different project' ($unrelatedPathCensus.competing_target_writer_count -eq 1)

$queryErrorBlocked = $false
try { $null = Assert-D32BoundedCompilerDiagnosticNoGlobalWriter -ProcessProbe { throw 'simulated Win32_Process query error' } }
catch { $queryErrorBlocked = $_.Exception.Message -ceq 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: Win32_Process target-writer census failed' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'Win32_Process query error blocks census admission' $queryErrorBlocked
$nullCensusBlocked = $false
try { $null = Assert-D32BoundedCompilerDiagnosticNoGlobalWriter -ProcessProbe { $null } }
catch { $nullCensusBlocked = $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED:*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'null/hidden census result blocks admission' $nullCensusBlocked
$emptyCensusBlocked = $false
try { $null = Assert-D32BoundedCompilerDiagnosticNoGlobalWriter -ProcessProbe { [object[]]::new(0) } }
catch { $emptyCensusBlocked = $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED:*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'empty global census blocks admission as unverifiable' $emptyCensusBlocked
$incompleteProcessBlocked = $false
try { $null = Assert-D32BoundedCompilerDiagnosticNoGlobalWriter -ProcessProbe { [PSCustomObject]@{ ProcessId = [uint32]702 } } }
catch { $incompleteProcessBlocked = $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: target-writer census contains an incomplete process identity' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'missing process name in global census blocks admission' $incompleteProcessBlocked
$mismatchedIdleBlocked = $false
try { $null = Assert-D32BoundedCompilerDiagnosticNoGlobalWriter -ProcessProbe { @([PSCustomObject]@{ Name = 'System Idle Process'; ProcessId = [uint32]8; ParentProcessId = [uint32]0 }) } }
catch { $mismatchedIdleBlocked = $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_CAPACITY_BLOCKED: PID-zero row*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'borrowed Windows pseudo-process name cannot evade global census' $mismatchedIdleBlocked
$runnerPath = Join-Path $PSScriptRoot 'd32-bounded-compiler-diagnostic.ps1'
$policyPath = Join-Path $PSScriptRoot 'd32-bounded-compiler-diagnostic-policy.ps1'
$policyTokens = $null; $policyParseErrors = $null
$policyAst = [System.Management.Automation.Language.Parser]::ParseFile($policyPath, [ref]$policyTokens, [ref]$policyParseErrors)
$runnerTokens = $null; $runnerParseErrors = $null
$runnerAst = [System.Management.Automation.Language.Parser]::ParseFile($runnerPath, [ref]$runnerTokens, [ref]$runnerParseErrors)
$sourceProofProgressMarkerAst = $policyAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Set-D32BoundedDiagnosticSourceProofProgress' }, $true)
$sourceProofProgressMarkerText = if ($null -eq $sourceProofProgressMarkerAst) { '' } else { [string]$sourceProofProgressMarkerAst.Extent.Text }
$profileLibraryPath = Join-Path $PSScriptRoot 'd32-build-toolchain-profile.ps1'
$profileLibraryTokens = $null; $profileLibraryParseErrors = $null
$profileLibraryAst = [System.Management.Automation.Language.Parser]::ParseFile($profileLibraryPath, [ref]$profileLibraryTokens, [ref]$profileLibraryParseErrors)
$moduleAuthorityPath = Join-Path $PSScriptRoot 'd32-powershell-module-authority.ps1'
$moduleAuthorityTokens = $null; $moduleAuthorityParseErrors = $null
$moduleAuthorityAst = [System.Management.Automation.Language.Parser]::ParseFile($moduleAuthorityPath, [ref]$moduleAuthorityTokens, [ref]$moduleAuthorityParseErrors)
$diagnosticJsonDuplicatesAst = $runnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32BoundedDiagnosticJsonDuplicates' }, $true)
$cargoChecksumValidatorAst = $runnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-D32BoundedDiagnosticCargoChecksumMetadata' }, $true)
$registryAuxiliaryPredicateAst = $policyAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32BoundedDiagnosticGeneratedRegistryAuxiliaryFile' }, $true)
$registryMarkerBytesAst = $policyAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32BoundedDiagnosticRegistryCargoOkMarkerBytes' }, $true)
$registryMarkerSnapshotAst = $policyAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32BoundedDiagnosticRegistryCargoOkMarkerSnapshot' }, $true)
$gitMarkerEmptyAst = $policyAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-D32BoundedDiagnosticGitCargoOkMarkerEmpty' }, $true)
$gitPointerTargetAst = $policyAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-D32BoundedDiagnosticGitPointerTarget' }, $true)
$gitPointerCompareAst = $policyAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32BoundedDiagnosticExactGitPointerTarget' }, $true)
$profileWithinAst = $profileLibraryAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32ProfilePathWithin' }, $true)
$authorityWithinAst = $moduleAuthorityAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32PowerShellAuthorityPathWithin' }, $true)
$profileFullPathAst = $profileLibraryAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-D32ProfileFullPath' }, $true)
$noReparseAst = $profileLibraryAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32ProfileNoReparsePath' }, $true)
$fileReferenceAssertAst = $runnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-D32BoundedDiagnosticFileReference' }, $true)
$fileReferenceProjectionAst = $runnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'New-D32BoundedDiagnosticRegistryArchiveFileReferenceProjection' }, $true)
$registryContentProofAst = $runnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'New-D32BoundedDiagnosticRegistrySourceContentProof' }, $true)
$inv7OriginAst = $runnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-D32BoundedDiagnosticInv7Origin' }, $true)
$capturedStreamShapeAst = $policyAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32BoundedCompilerDiagnosticCapturedStreamReferenceShape' }, $true)
$fileReferenceFailureAst = $policyAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-D32BoundedCompilerDiagnosticFileReferenceShapeFailure' }, $true)
$profileTestAst = $profileLibraryAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32BuildToolchainProfile' }, $true)
$profileCurrentAst = $profileLibraryAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-D32BuildToolchainProfileCurrent' }, $true)
$authorityWithinTokens = $null; $authorityWithinParseErrors = $null
$authorityWithinSyntaxAst = if ($null -ne $authorityWithinAst) { [System.Management.Automation.Language.Parser]::ParseInput($authorityWithinAst.Extent.Text, [ref]$authorityWithinTokens, [ref]$authorityWithinParseErrors) } else { $null }
$pathHelperParseExact = $policyParseErrors.Count -eq 0 -and $runnerParseErrors.Count -eq 0 -and $profileLibraryParseErrors.Count -eq 0 -and
    $null -ne $authorityWithinSyntaxAst -and $authorityWithinParseErrors.Count -eq 0 -and
    $null -ne $profileWithinAst -and $null -ne $authorityWithinAst -and $null -ne $profileFullPathAst -and $null -ne $noReparseAst -and
    $null -ne $fileReferenceAssertAst -and $null -ne $fileReferenceProjectionAst -and $null -ne $registryContentProofAst -and
    $null -ne $inv7OriginAst -and $null -ne $capturedStreamShapeAst -and $null -ne $fileReferenceFailureAst -and
    $null -ne $profileTestAst -and $null -ne $profileCurrentAst
Assert-D32BoundedCompilerDiagnosticSelfTest 'all source-origin/root-containment functions parse for the synthetic containment census' $pathHelperParseExact

$registryMetadataAstReady = $null -ne $diagnosticJsonDuplicatesAst -and $null -ne $cargoChecksumValidatorAst -and
    $null -ne $registryAuxiliaryPredicateAst -and $null -ne $registryMarkerBytesAst -and
    $null -ne $registryMarkerSnapshotAst -and $null -ne $gitMarkerEmptyAst -and
    $null -ne $gitPointerTargetAst -and $null -ne $gitPointerCompareAst -and
    $runnerParseErrors.Count -eq 0 -and $policyParseErrors.Count -eq 0
Assert-D32BoundedCompilerDiagnosticSelfTest 'all Cargo auxiliary metadata validators parse for module-free fixtures' $registryMetadataAstReady
Invoke-Expression $diagnosticJsonDuplicatesAst.Extent.Text
Invoke-Expression $cargoChecksumValidatorAst.Extent.Text
Invoke-Expression $gitPointerTargetAst.Extent.Text
Invoke-Expression $gitPointerCompareAst.Extent.Text

$canonicalCargoMarker = [Text.Encoding]::UTF8.GetBytes('{"v":1}')
$canonicalCargoMarkerSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($canonicalCargoMarker)).ToLowerInvariant()
Assert-D32BoundedCompilerDiagnosticSelfTest 'registry marker accepts only exact seven-byte canonical Cargo v1 JSON and its matching bounded snapshot' `
    ((Test-D32BoundedDiagnosticRegistryCargoOkMarkerBytes -Bytes $canonicalCargoMarker) -and
     (Test-D32BoundedDiagnosticRegistryCargoOkMarkerSnapshot -Bytes $canonicalCargoMarker.Length -Sha256 $canonicalCargoMarkerSha256))
$registryMarkerNegativeCases = @(
    [PSCustomObject]@{ name = 'empty'; bytes = [byte[]]::new(0) },
    [PSCustomObject]@{ name = 'unknown version'; bytes = [Text.Encoding]::UTF8.GetBytes('{"v":2}') },
    [PSCustomObject]@{ name = 'extra field'; bytes = [Text.Encoding]::UTF8.GetBytes('{"v":1,"x":0}') },
    [PSCustomObject]@{ name = 'trailing byte'; bytes = [Text.Encoding]::UTF8.GetBytes('{"v":1} ') },
    [PSCustomObject]@{ name = 'UTF-8 BOM'; bytes = [byte[]]@([byte]0xef, [byte]0xbb, [byte]0xbf) + $canonicalCargoMarker },
    [PSCustomObject]@{ name = 'noncanonical whitespace'; bytes = [Text.Encoding]::UTF8.GetBytes('{ "v":1}') },
    [PSCustomObject]@{ name = 'noncanonical numeric value'; bytes = [Text.Encoding]::UTF8.GetBytes('{"v":1.0}') }
)
foreach ($markerCase in $registryMarkerNegativeCases) {
    $caseSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$markerCase.bytes)).ToLowerInvariant()
    Assert-D32BoundedCompilerDiagnosticSelfTest "registry .cargo-ok rejects $($markerCase.name) bytes and snapshot" `
        (-not (Test-D32BoundedDiagnosticRegistryCargoOkMarkerBytes -Bytes ([byte[]]$markerCase.bytes)) -and
         -not (Test-D32BoundedDiagnosticRegistryCargoOkMarkerSnapshot -Bytes ([long]$markerCase.bytes.Length) -Sha256 $caseSha256))
}

Assert-D32BoundedCompilerDiagnosticSelfTest 'generated registry metadata classification preserves archive-member validation for both auxiliary names' `
    ((Test-D32BoundedDiagnosticGeneratedRegistryAuxiliaryFile -RelativePath '.cargo-ok' -AtRoot $true -ArchiveMember $false) -and
     -not (Test-D32BoundedDiagnosticGeneratedRegistryAuxiliaryFile -RelativePath '.cargo-ok' -AtRoot $true -ArchiveMember $true) -and
     (Test-D32BoundedDiagnosticGeneratedRegistryAuxiliaryFile -RelativePath '.cargo-checksum.json' -AtRoot $true -ArchiveMember $false) -and
     -not (Test-D32BoundedDiagnosticGeneratedRegistryAuxiliaryFile -RelativePath '.cargo-checksum.json' -AtRoot $true -ArchiveMember $true) -and
     -not (Test-D32BoundedDiagnosticGeneratedRegistryAuxiliaryFile -RelativePath 'nested/.cargo-ok' -AtRoot $false -ArchiveMember $false) -and
     -not (Test-D32BoundedDiagnosticGeneratedRegistryAuxiliaryFile -RelativePath '.CARGO-OK' -AtRoot $true -ArchiveMember $false))
$emptyGitMarkerAccepted = $true
try { Assert-D32BoundedDiagnosticGitCargoOkMarkerEmpty -Bytes 0L } catch { $emptyGitMarkerAccepted = $false }
$nonemptyGitMarkerRejected = $false
try { Assert-D32BoundedDiagnosticGitCargoOkMarkerEmpty -Bytes 1L }
catch { $nonemptyGitMarkerRejected = $_.Exception.Message -ceq 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_BLOCKED: generated .cargo-ok marker is not empty' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'Git checkout .cargo-ok retains its distinct empty-file rule and rejects nonempty bytes' `
    ($emptyGitMarkerAccepted -and $nonemptyGitMarkerRejected)

$gitPointerCheckout = 'C:\d32-pointer-fixture\checkout'
$gitPointerDatabase = 'C:\d32-pointer-fixture\git\db'
$relativeGitPointer = [Text.Encoding]::ASCII.GetBytes("gitdir: ..\git\db`n")
$absoluteGitPointer = [Text.Encoding]::ASCII.GetBytes("gitdir: $gitPointerDatabase`r`n")
$relativeGitPointerTarget = Get-D32BoundedDiagnosticGitPointerTarget -PointerBytes $relativeGitPointer -CheckoutPath $gitPointerCheckout
$absoluteGitPointerTarget = Get-D32BoundedDiagnosticGitPointerTarget -PointerBytes $absoluteGitPointer -CheckoutPath $gitPointerCheckout
$trailingTextGitPointerTarget = Get-D32BoundedDiagnosticGitPointerTarget `
    -PointerBytes ([Text.Encoding]::ASCII.GetBytes('gitdir: ../git/db extra')) -CheckoutPath $gitPointerCheckout
Assert-D32BoundedCompilerDiagnosticSelfTest 'bounded .git pointer parser resolves permitted relative and absolute exact database roots' `
    ((Test-D32BoundedDiagnosticExactGitPointerTarget -Target $relativeGitPointerTarget -ExpectedTarget $gitPointerDatabase) -and
     (Test-D32BoundedDiagnosticExactGitPointerTarget -Target $absoluteGitPointerTarget -ExpectedTarget $gitPointerDatabase) -and
     (Test-D32BoundedDiagnosticExactGitPointerTarget -Target $gitPointerDatabase.ToUpperInvariant() -ExpectedTarget $gitPointerDatabase) -and
     -not (Test-D32BoundedDiagnosticExactGitPointerTarget -Target 'C:\d32-pointer-fixture\other\db' -ExpectedTarget $gitPointerDatabase) -and
     -not (Test-D32BoundedDiagnosticExactGitPointerTarget -Target $trailingTextGitPointerTarget -ExpectedTarget $gitPointerDatabase))
$malformedGitPointerCases = @(
    [PSCustomObject]@{ name = 'empty'; bytes = [byte[]]::new(0) },
    [PSCustomObject]@{ name = 'oversized'; bytes = [byte[]]::new(4097) },
    [PSCustomObject]@{ name = 'missing keyword'; bytes = [Text.Encoding]::ASCII.GetBytes('git-dir: ../git/db') },
    [PSCustomObject]@{ name = 'missing target'; bytes = [Text.Encoding]::ASCII.GetBytes('gitdir: ') },
    [PSCustomObject]@{ name = 'leading whitespace'; bytes = [Text.Encoding]::ASCII.GetBytes(' gitdir: ../git/db') },
    [PSCustomObject]@{ name = 'multiple lines'; bytes = [Text.Encoding]::ASCII.GetBytes("gitdir: ../git/db`ngitdir: ../other`n") }
)
foreach ($pointerCase in $malformedGitPointerCases) {
    $pointerRejected = $false
    try { $null = Get-D32BoundedDiagnosticGitPointerTarget -PointerBytes ([byte[]]$pointerCase.bytes) -CheckoutPath $gitPointerCheckout }
    catch { $pointerRejected = $true }
    Assert-D32BoundedCompilerDiagnosticSelfTest "bounded .git pointer parser rejects $($pointerCase.name)" $pointerRejected
}

$checksumFileSha = 'a' * 64
$checksumPackageSha = 'b' * 64
$validCargoChecksumText = '{"files":{"src/lib.rs":"' + $checksumFileSha + '"},"package":"' + $checksumPackageSha + '"}'
$validCargoChecksum = Assert-D32BoundedDiagnosticCargoChecksumMetadata -Text $validCargoChecksumText
Assert-D32BoundedCompilerDiagnosticSelfTest 'generated Cargo checksum metadata accepts exact files/package shape and canonical digests' `
    ((Test-D32BoundedCompilerDiagnosticExactProperties $validCargoChecksum @('files', 'package')) -and
     [string]$validCargoChecksum.files.'src/lib.rs' -ceq $checksumFileSha -and [string]$validCargoChecksum.package -ceq $checksumPackageSha)
$validNullPackageChecksum = Assert-D32BoundedDiagnosticCargoChecksumMetadata -Text ('{"files":{"Cargo.toml":"' + $checksumFileSha + '"},"package":null}')
Assert-D32BoundedCompilerDiagnosticSelfTest 'Cargo checksum metadata retains the supported null package value' ($null -eq $validNullPackageChecksum.package)
$invalidCargoChecksumCases = @(
    [PSCustomObject]@{ name = 'extra field'; text = '{"files":{},"package":null,"extra":0}' },
    [PSCustomObject]@{ name = 'missing package'; text = '{"files":{}}' },
    [PSCustomObject]@{ name = 'array files'; text = '{"files":[],"package":null}' },
    [PSCustomObject]@{ name = 'invalid package digest'; text = '{"files":{},"package":"xyz"}' },
    [PSCustomObject]@{ name = 'duplicate top-level field'; text = '{"files":{},"package":null,"package":null}' },
    [PSCustomObject]@{ name = 'duplicate file path'; text = '{"files":{"src/lib.rs":"' + $checksumFileSha + '","src/lib.rs":"' + $checksumFileSha + '"},"package":null}' },
    [PSCustomObject]@{ name = 'unsafe relative path'; text = '{"files":{"../outside":"' + $checksumFileSha + '"},"package":null}' },
    [PSCustomObject]@{ name = 'invalid file digest'; text = '{"files":{"src/lib.rs":"bad"},"package":null}' },
    [PSCustomObject]@{ name = 'UTF-8 BOM'; text = [string]([char]0xfeff) + '{"files":{},"package":null}' },
    [PSCustomObject]@{ name = 'trailing content'; text = '{"files":{},"package":null} trailing' }
)
foreach ($checksumCase in $invalidCargoChecksumCases) {
    $checksumRejected = $false
    try { $null = Assert-D32BoundedDiagnosticCargoChecksumMetadata -Text ([string]$checksumCase.text) }
    catch { $checksumRejected = $true }
    Assert-D32BoundedCompilerDiagnosticSelfTest "generated Cargo checksum metadata rejects $($checksumCase.name)" $checksumRejected
}

$registrySourceInventoryAst = $runnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-D32BoundedDiagnosticArchiveMatchesExtractedSource' }, $true)
$registryContentFunctionText = if ($null -eq $registrySourceInventoryAst) { '' } else { [string]$registrySourceInventoryAst.Extent.Text }
$gitContentProofAst = $runnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-D32BoundedDiagnosticGitCheckoutContentProof' }, $true)
$gitContentFunctionText = if ($null -eq $gitContentProofAst) { '' } else { [string]$gitContentProofAst.Extent.Text }
$registryAuxiliaryBranchesWired = $registryContentFunctionText.Contains('Test-D32BoundedDiagnosticGeneratedRegistryAuxiliaryFile') -and
    $registryContentFunctionText.Contains('Test-D32BoundedDiagnosticRegistryCargoOkMarkerSnapshot') -and
    $registryContentFunctionText.Contains('Assert-D32BoundedDiagnosticCargoChecksumMetadata') -and
    $registryContentFunctionText.Contains('extracted registry file content differs from the lock-checksummed archive')
$gitAuxiliaryBranchesWired = $gitContentFunctionText.Contains('Test-D32BoundedDiagnosticGeneratedRegistryAuxiliaryFile') -and
    $gitContentFunctionText.Contains('Assert-D32BoundedDiagnosticGitCargoOkMarkerEmpty') -and
    $gitContentFunctionText.Contains('Get-D32BoundedDiagnosticGitPointerTarget') -and
    $gitContentFunctionText.Contains('Test-D32BoundedDiagnosticExactGitPointerTarget') -and
    $gitContentFunctionText.Contains('Test-D32ProfileNoReparsePath') -and
    $gitContentFunctionText.Contains('checkout path case differs from its locked Git tree')
$gitPointerReadCall = 'Get-D32ProfileFileContentSnapshot -Path $full -MaximumBytes 4096 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds'
$gitMarkerReadCall = 'Get-D32ProfileFileContentSnapshot -Path $full -MaximumBytes 0 -ProofTimer $ProofTimer -DeadlineMilliseconds $DeadlineMilliseconds'
$gitPointerReadsBoundedAndRevalidated = ([regex]::Matches($gitContentFunctionText, [regex]::Escape($gitPointerReadCall))).Count -eq 2 -and
    $gitContentFunctionText.Contains('$pointerBytes = [byte[]]$pointerBefore.Content') -and
    $gitContentFunctionText.Contains('$pointerAfter.Sha256 -cne $pointerBefore.Sha256') -and
    $gitContentFunctionText.Contains('$pointerAfter.FileIdHex -cne $pointerBefore.FileIdHex') -and
    -not $gitContentFunctionText.Contains('[IO.File]::ReadAllBytes($full)') -and
    -not $gitContentFunctionText.Contains('Get-D32ProfileFileSnapshot -Path $full')
$gitMarkerReadIsZeroByteBounded = $gitContentFunctionText.Contains($gitMarkerReadCall) -and
    $gitContentFunctionText.Contains('Assert-D32BoundedDiagnosticGitCargoOkMarkerEmpty -Bytes ([Int64]$marker.Bytes)') -and
    -not $gitContentFunctionText.Contains('Get-D32ProfileFileSnapshot -Path $full')
Assert-D32BoundedCompilerDiagnosticSelfTest 'registry generated-vs-archive auxiliary routing and checksum parser remain wired to archive proof' $registryAuxiliaryBranchesWired
Assert-D32BoundedCompilerDiagnosticSelfTest 'Git empty marker rule remains wired without replacing locked tree comparison' $gitAuxiliaryBranchesWired
Assert-D32BoundedCompilerDiagnosticSelfTest 'checkout .git pointer uses two deadline-aware 4096-byte snapshots and parses the bounded snapshot bytes' $gitPointerReadsBoundedAndRevalidated
Assert-D32BoundedCompilerDiagnosticSelfTest 'checkout .cargo-ok rejects nonempty files before any unbounded content hashing' $gitMarkerReadIsZeroByteBounded

Invoke-Expression $profileWithinAst.Extent.Text
Invoke-Expression $authorityWithinAst.Extent.Text
$containmentFunctions = @(
    [PSCustomObject]@{ Name = 'source-proof policy'; Test = { param($Child, $Parent) Test-D32BoundedCompilerDiagnosticWithin -Child $Child -Parent $Parent } },
    [PSCustomObject]@{ Name = 'Profile V2 source roots'; Test = { param($Child, $Parent) Test-D32ProfilePathWithin -Child $Child -Parent $Parent } },
    [PSCustomObject]@{ Name = 'module bootstrap authorities'; Test = { param($Child, $Parent) Test-D32PowerShellAuthorityPathWithin -Child $Child -Parent $Parent } }
)
$containmentCases = @(
    [PSCustomObject]@{ Name = 'same root'; Child = 'C:\D32-containment-fixture\repo'; Parent = 'C:\D32-containment-fixture\repo'; Expected = $true },
    [PSCustomObject]@{ Name = 'root itself with separator'; Child = 'C:\D32-containment-fixture\repo\'; Parent = 'C:\D32-containment-fixture\repo'; Expected = $true },
    [PSCustomObject]@{ Name = 'normal descendant'; Child = 'C:\D32-containment-fixture\repo\src\lib.rs'; Parent = 'C:\D32-containment-fixture\repo'; Expected = $true },
    [PSCustomObject]@{ Name = 'case-insensitive Windows child'; Child = 'c:\d32-CONTAINMENT-fixture\REPO\src\lib.rs'; Parent = 'C:\D32-containment-fixture\repo'; Expected = $true },
    [PSCustomObject]@{ Name = 'sibling prefix'; Child = 'C:\D32-containment-fixture\repo-sibling\file'; Parent = 'C:\D32-containment-fixture\repo'; Expected = $false },
    [PSCustomObject]@{ Name = 'parent traversal escape'; Child = 'C:\D32-containment-fixture\repo\..\outside\file'; Parent = 'C:\D32-containment-fixture\repo'; Expected = $false },
    [PSCustomObject]@{ Name = 'normalized traversal within root'; Child = 'C:\D32-containment-fixture\repo\src\..\Cargo.toml'; Parent = 'C:\D32-containment-fixture\repo'; Expected = $true },
    [PSCustomObject]@{ Name = 'different absolute drive'; Child = 'D:\D32-containment-fixture\repo\file'; Parent = 'C:\D32-containment-fixture\repo'; Expected = $false },
    [PSCustomObject]@{ Name = 'drive root child'; Child = 'C:\D32-containment-fixture\repo\file'; Parent = 'C:\'; Expected = $true },
    [PSCustomObject]@{ Name = 'drive root itself'; Child = 'C:\'; Parent = 'C:\'; Expected = $true },
    [PSCustomObject]@{ Name = 'UNC share root child'; Child = '\\d32-containment.invalid\share\repo\file'; Parent = '\\d32-containment.invalid\share\repo'; Expected = $true },
    [PSCustomObject]@{ Name = 'UNC share root itself'; Child = '\\d32-containment.invalid\share\'; Parent = '\\d32-containment.invalid\share'; Expected = $true },
    [PSCustomObject]@{ Name = 'UNC sibling share prefix'; Child = '\\d32-containment.invalid\share2\file'; Parent = '\\d32-containment.invalid\share'; Expected = $false },
    [PSCustomObject]@{ Name = 'drive-relative path rejected'; Child = 'C:relative\file'; Parent = 'C:\D32-containment-fixture\repo'; Expected = $false },
    [PSCustomObject]@{ Name = 'empty path rejected'; Child = ''; Parent = 'C:\D32-containment-fixture\repo'; Expected = $false }
)
foreach ($containmentFunction in $containmentFunctions) {
    foreach ($containmentCase in $containmentCases) {
        $observed = $false
        try { $observed = [bool](& ([scriptblock]$containmentFunction.Test) ([string]$containmentCase.Child) ([string]$containmentCase.Parent)) } catch { $observed = $false }
        Assert-D32BoundedCompilerDiagnosticSelfTest "$($containmentFunction.Name): $($containmentCase.Name)" ($observed -eq [bool]$containmentCase.Expected)
    }
}
$sourceProofWithinAst = $policyAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32BoundedCompilerDiagnosticWithin' }, $true)
$sourceReferenceNoReparseExact = $fileReferenceAssertAst.Extent.Text.Contains('Test-D32ProfileNoReparsePath -Path $path') -and
    $fileReferenceAssertAst.Extent.Text.IndexOf('Test-D32BoundedCompilerDiagnosticWithin') -lt $fileReferenceAssertAst.Extent.Text.IndexOf('Test-D32ProfileNoReparsePath -Path $path') -and
    $null -ne $sourceProofWithinAst -and $sourceProofWithinAst.Extent.Text.Contains('[IO.Path]::IsPathFullyQualified')
Assert-D32BoundedCompilerDiagnosticSelfTest 'reference reparse guard remains after lexical source-root containment and roots require fully-qualified paths' $sourceReferenceNoReparseExact

$profileTestText = [string]$profileTestAst.Extent.Text
$profileCurrentText = [string]$profileCurrentAst.Extent.Text
$evidenceRootNullBindingExact = $profileTestText.Contains('[AllowNull()][object]$EvidenceRoot') -and
    $profileTestText.Contains('$null -ne $EvidenceRoot') -and
    $profileTestText.Contains('Test-D32ProfileCanonicalPathString -Path ([string]$EvidenceRoot)') -and
    $profileCurrentText.Contains('$evidenceRoot = $ValidatedProfile.EvidenceRoot') -and
    $profileCurrentText.Contains('-EvidenceRoot $evidenceRoot') -and
    -not $profileCurrentText.Contains('-EvidenceRoot ([string]$ValidatedProfile.EvidenceRoot)')
Assert-D32BoundedCompilerDiagnosticSelfTest 'optional EvidenceRoot preserves null and rejects explicit empty roots instead of truthiness-skipping the fence' $evidenceRootNullBindingExact

Invoke-Expression $profileFullPathAst.Extent.Text
Invoke-Expression ($noReparseAst.Extent.Text.Replace('function Test-D32ProfileNoReparsePath', 'function Test-D32ProfileNoReparsePathSynthetic'))
Invoke-Expression $fileReferenceAssertAst.Extent.Text
Invoke-Expression $fileReferenceProjectionAst.Extent.Text
function Test-D32ProfileNoReparsePath { param([string]$Path) return $true }
function Get-D32ProfileFileSnapshot {
    param([string]$Path)
    if ($Path -ceq 'C:\D32-sourceproof-synthetic\logs\stdout.log') {
        return [PSCustomObject]@{ Path = $Path; Bytes = 0L; Sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; VolumeSerialHex = '0123456789abcdef'; FileIdHex = '0123456789abcdef0123456789abcdef' }
    }
    return [PSCustomObject]@{ Path = $Path; Bytes = 1L; Sha256 = ('a' * 64); VolumeSerialHex = '0123456789abcdef'; FileIdHex = '0123456789abcdef0123456789abcdef' }
}
$syntheticRepoRoot = 'C:\D32-sourceproof-synthetic\repo'
$syntheticProfileReference = [PSCustomObject]@{ path = 'C:\D32-sourceproof-synthetic\toolchain-profile.json'; bytes = 1L; sha256 = 'a' * 64; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
$syntheticLogRoot = 'C:\D32-sourceproof-synthetic\logs'
$syntheticEmptyStreamPath = Join-Path $syntheticLogRoot 'stdout.log'
$syntheticEmptyStreamReference = [PSCustomObject][ordered]@{
    path = $syntheticEmptyStreamPath; bytes = 0L; sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef'
}
$zeroStreamStrictFileRefRejected = -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $syntheticEmptyStreamReference)
$zeroStreamExactCaptureAccepted = Test-D32BoundedCompilerDiagnosticCapturedStreamReferenceShape -Reference $syntheticEmptyStreamReference -ExpectedPath $syntheticEmptyStreamPath
$zeroStreamWrongExpectedPathRejected = -not (Test-D32BoundedCompilerDiagnosticCapturedStreamReferenceShape -Reference $syntheticEmptyStreamReference -ExpectedPath (Join-Path $syntheticLogRoot 'stderr.log'))
$zeroStreamNegativeBytes = [PSCustomObject][ordered]@{
    path = $syntheticEmptyStreamPath; bytes = -1L; sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef'
}
$zeroStreamNegativeBytesRejected = -not (Test-D32BoundedCompilerDiagnosticCapturedStreamReferenceShape -Reference $zeroStreamNegativeBytes -ExpectedPath $syntheticEmptyStreamPath)
$zeroStreamExtraField = [PSCustomObject][ordered]@{
    path = $syntheticEmptyStreamPath; bytes = 0L; sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef'; status = 'CAPTURED'
}
$zeroStreamExtraFieldRejected = -not (Test-D32BoundedCompilerDiagnosticCapturedStreamReferenceShape -Reference $zeroStreamExtraField -ExpectedPath $syntheticEmptyStreamPath)
Assert-D32BoundedCompilerDiagnosticSelfTest 'regular source-file references remain strictly positive while exact captured streams admit zero bytes' `
    ($zeroStreamStrictFileRefRejected -and $zeroStreamExactCaptureAccepted -and $zeroStreamWrongExpectedPathRejected -and $zeroStreamNegativeBytesRejected -and $zeroStreamExtraFieldRejected)
$zeroStreamGenericError = $null
try {
    $null = Assert-D32BoundedDiagnosticFileReference -Reference $syntheticEmptyStreamReference -MustBeWithin $syntheticLogRoot -MustNotBeWithin $syntheticRepoRoot `
        -ReferenceField 'prior.blocked.ordered_stream_captures[0].reference' -Caller 'SyntheticStreamFixture'
}
catch { $zeroStreamGenericError = $_.Exception.Message }
$zeroStreamExpectedRoot = Format-D32BoundedCompilerDiagnosticPathForError $syntheticLogRoot
$zeroStreamActualPath = Format-D32BoundedCompilerDiagnosticPathForError $syntheticEmptyStreamPath
Assert-D32BoundedCompilerDiagnosticSelfTest 'strict-reference rejection identifies caller, exact bytes field, actual ref, expected root and positive-byte reason' `
    ($null -ne $zeroStreamGenericError -and $zeroStreamGenericError.Contains('caller=SyntheticStreamFixture') -and
        $zeroStreamGenericError.Contains('field=prior.blocked.ordered_stream_captures[0].reference.bytes') -and
        $zeroStreamGenericError.Contains('reason=bytes_must_be_positive') -and
        $zeroStreamGenericError.Contains("actual_ref=$zeroStreamActualPath") -and $zeroStreamGenericError.Contains("expected_root=$zeroStreamExpectedRoot"))
$zeroStreamExactCaptureAcceptedByAssert = $false
try {
    $snapshot = Assert-D32BoundedDiagnosticFileReference -Reference $syntheticEmptyStreamReference -MustBeWithin $syntheticLogRoot -MustNotBeWithin $syntheticRepoRoot `
        -ReferenceKind CapturedStream -ExactPath $syntheticEmptyStreamPath -ReferenceField 'prior.blocked.ordered_stream_captures[0].reference' `
        -Caller 'SyntheticStreamFixture'
    $zeroStreamExactCaptureAcceptedByAssert = $snapshot.Bytes -eq 0 -and $snapshot.Sha256 -ceq $syntheticEmptyStreamReference.sha256
}
catch { $zeroStreamExactCaptureAcceptedByAssert = $false }
Assert-D32BoundedCompilerDiagnosticSelfTest 'exact captured-stream exception still verifies zero-byte digest and opened identity under its authorized log root' $zeroStreamExactCaptureAcceptedByAssert
$zeroStreamEscapeReported = $false
try {
    $null = Assert-D32BoundedDiagnosticFileReference -Reference $syntheticEmptyStreamReference -MustBeWithin 'C:\D32-sourceproof-synthetic\logs-sibling' -MustNotBeWithin $syntheticRepoRoot `
        -ReferenceKind CapturedStream -ExactPath $syntheticEmptyStreamPath -ReferenceField 'prior.blocked.ordered_stream_captures[0].reference' `
        -Caller 'SyntheticStreamFixture'
}
catch { $zeroStreamEscapeReported = $_.Exception.Message.Contains('source reference escaped its authorized root') -and $_.Exception.Message.Contains("actual_ref=$zeroStreamActualPath") -and $_.Exception.Message.Contains("expected_root=$(Format-D32BoundedCompilerDiagnosticPathForError 'C:\D32-sourceproof-synthetic\logs-sibling')") }
Assert-D32BoundedCompilerDiagnosticSelfTest 'captured-stream exception does not weaken exact-root containment or diagnostics' $zeroStreamEscapeReported
$syntheticArchiveTuple = [PSCustomObject][ordered]@{
    source = 'registry+https://github.com/rust-lang/crates.io-index'; name = 'synthetic-crate'; version = '1.0.0'; checksum = 'a' * 64
    path = 'C:\D32-sourceproof-synthetic\registry-cache\synthetic-crate-1.0.0.crate'; bytes = 1L; sha256 = 'a' * 64
    volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef'
}
$syntheticArchiveProjection = New-D32BoundedDiagnosticRegistryArchiveFileReferenceProjection -Reference $syntheticArchiveTuple
$syntheticArchiveProjectionExact = $syntheticArchiveTuple -is [PSCustomObject] -and
    -not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $syntheticArchiveTuple) -and
    (Test-D32BoundedCompilerDiagnosticExactProperties -Object $syntheticArchiveProjection -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -and
    (Test-D32BoundedCompilerDiagnosticFileReferenceShape $syntheticArchiveProjection) -and
    $syntheticArchiveProjection.bytes -is [long] -and [string]$syntheticArchiveProjection.path -ceq [string]$syntheticArchiveTuple.path
Assert-D32BoundedCompilerDiagnosticSelfTest 'registry archive tuple is projected to an exact five-field file reference after strict nine-field validation without coercion or schema relaxation' $syntheticArchiveProjectionExact
$badArchiveTupleRejected = $false
try {
    $null = New-D32BoundedDiagnosticRegistryArchiveFileReferenceProjection -Reference ([PSCustomObject][ordered]@{ path = $syntheticArchiveTuple.path; bytes = 1L; sha256 = 'a' * 64; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef'; extra = 'not-an-archive-tuple' })
}
catch { $badArchiveTupleRejected = $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_SOURCE_BLOCKED: registry archive projection requires its exact nine-field caller schema*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'archive projection rejects a regular-file reference or arbitrary extra-field object instead of silently dropping unknown properties' $badArchiveTupleRejected
$archiveProjectionConsumersExact = $registryContentProofAst.Extent.Text.Contains('New-D32BoundedDiagnosticRegistryArchiveFileReferenceProjection -Reference $archive') -and
    $registryContentProofAst.Extent.Text.Contains('-Reference $archiveFileReference') -and
    -not $inv7OriginAst.Extent.Text.Contains('New-D32BoundedDiagnosticRegistryArchiveFileReferenceProjection') -and
    $inv7OriginAst.Extent.Text.Contains('registry archive source pin has an invalid exact schema') -and
    $inv7OriginAst.Extent.Text.Contains('registry archive checksum differs from Cargo.lock')
Assert-D32BoundedCompilerDiagnosticSelfTest 'origin validator keeps the exact nine-field lock/root tuple while the sole content reader projects it before file IO' $archiveProjectionConsumersExact
$capturedStreamOptInCalls = @($runnerAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq 'Assert-D32BoundedDiagnosticFileReference' -and $node.Extent.Text.Contains('-ReferenceKind CapturedStream') }, $true)).Count
Assert-D32BoundedCompilerDiagnosticSelfTest 'zero-byte allowance is explicit and limited to the historical ordered capture consumer' ($capturedStreamOptInCalls -eq 1)
$nullRequiredRootAccepted = $false
try {
    $null = Assert-D32BoundedDiagnosticFileReference -Reference $syntheticProfileReference -MustBeWithin $null -MustNotBeWithin $syntheticRepoRoot
    $nullRequiredRootAccepted = $true
}
catch { $nullRequiredRootAccepted = $false }
Assert-D32BoundedCompilerDiagnosticSelfTest 'explicitly absent required root remains null for Profile V2 while protected repository root still applies' $nullRequiredRootAccepted
$escapedReferenceMessage = $null
$escapedReferenceRejected = $false
try {
    $null = Assert-D32BoundedDiagnosticFileReference -Reference $syntheticProfileReference -MustBeWithin $syntheticRepoRoot -MustNotBeWithin $null
}
catch { $escapedReferenceMessage = $_.Exception.Message; $escapedReferenceRejected = $true }
$escapedActualPathJson = Format-D32BoundedCompilerDiagnosticPathForError $syntheticProfileReference.path
$escapedExpectedRootJson = Format-D32BoundedCompilerDiagnosticPathForError $syntheticRepoRoot
Assert-D32BoundedCompilerDiagnosticSelfTest 'escaped source reference reports safe actual_ref and expected_root and fails closed' `
    ($escapedReferenceRejected -and $escapedReferenceMessage.Contains("actual_ref=$escapedActualPathJson") -and $escapedReferenceMessage.Contains("expected_root=$escapedExpectedRootJson"))
$emptyRequiredRootRejected = $false
try { $null = Assert-D32BoundedDiagnosticFileReference -Reference $syntheticProfileReference -MustBeWithin '' -MustNotBeWithin $null }
catch { $emptyRequiredRootRejected = $_.Exception.Message.Contains('expected_root=""') }
Assert-D32BoundedCompilerDiagnosticSelfTest 'explicit empty required root is rejected rather than interpreted as an absent root' $emptyRequiredRootRejected
$protectedReference = [PSCustomObject]@{ path = 'C:\D32-sourceproof-synthetic\repo\owner.json'; bytes = 1L; sha256 = 'a' * 64; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
$protectedRootReported = $false
try { $null = Assert-D32BoundedDiagnosticFileReference -Reference $protectedReference -MustBeWithin $null -MustNotBeWithin $syntheticRepoRoot }
catch { $protectedRootReported = $_.Exception.Message.Contains("actual_ref=$(Format-D32BoundedCompilerDiagnosticPathForError $protectedReference.path)") -and $_.Exception.Message.Contains("protected_root=$(Format-D32BoundedCompilerDiagnosticPathForError $syntheticRepoRoot)") }
Assert-D32BoundedCompilerDiagnosticSelfTest 'protected-root overlap reports the actual reference and protected root' $protectedRootReported

$reparseFixtureStatus = 'UNAVAILABLE'
$reparseFixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('D32-containment-fixture-' + [Guid]::NewGuid().ToString('N'))
$reparseAuthorizedRoot = Join-Path $reparseFixtureRoot 'authorized'
$reparseTargetRoot = Join-Path $reparseFixtureRoot 'outside'
$reparseLinkPath = Join-Path $reparseAuthorizedRoot 'linked-outside'
$reparseLinkCreated = $false
try {
    $null = [IO.Directory]::CreateDirectory($reparseAuthorizedRoot)
    $null = [IO.Directory]::CreateDirectory($reparseTargetRoot)
    try {
        $null = [IO.Directory]::CreateSymbolicLink($reparseLinkPath, $reparseTargetRoot)
        $reparseLinkCreated = $true
    }
    catch [System.Exception] {
        $reparseFixtureStatus = 'UNAVAILABLE'
        try { if (([IO.File]::GetAttributes($reparseLinkPath) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $reparseLinkCreated = $true } } catch { }
    }
    if ($reparseLinkCreated) {
        $reparseChild = Join-Path $reparseLinkPath 'synthetic-source'
        $lexicallyInside = Test-D32BoundedCompilerDiagnosticWithin -Child $reparseChild -Parent $reparseAuthorizedRoot
        $reparseDenied = -not (Test-D32ProfileNoReparsePathSynthetic -Path $reparseChild)
        $reparseFixtureStatus = if ($lexicallyInside -and $reparseDenied) { 'PASS' } else { 'FAIL' }
        Assert-D32BoundedCompilerDiagnosticSelfTest 'synthetic reparse-point path is lexically beneath the root but rejected by the source no-reparse guard' ($lexicallyInside -and $reparseDenied)
    }
}
finally {
    if ($reparseLinkCreated) { [IO.Directory]::Delete($reparseLinkPath, $false) }
    if ([IO.Directory]::Exists($reparseAuthorizedRoot)) { [IO.Directory]::Delete($reparseAuthorizedRoot, $false) }
    if ([IO.Directory]::Exists($reparseTargetRoot)) { [IO.Directory]::Delete($reparseTargetRoot, $false) }
    if ([IO.Directory]::Exists($reparseFixtureRoot)) { [IO.Directory]::Delete($reparseFixtureRoot, $false) }
}
$script:D32ContainmentReparseFixtureStatus = $reparseFixtureStatus

$capacityAst = $runnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-D32BoundedDiagnosticCapacity' }, $true)
$capacityText = if ($null -eq $capacityAst) { '' } else { [string]$capacityAst.Extent.Text }
$globalCensusWiringExact = $runnerParseErrors.Count -eq 0 -and $null -ne $capacityAst -and
    $capacityText.Contains('Get-CimInstance -ClassName Win32_Process -ErrorAction Stop') -and
    $capacityText.Contains('Assert-D32BoundedCompilerDiagnosticNoGlobalWriter') -and
    -not $capacityText.Contains('CommandLine') -and -not $capacityText.Contains('WorkingDirectory') -and -not $capacityText.Contains('targetFull')
Assert-D32BoundedCompilerDiagnosticSelfTest 'actual diagnostic capacity preflight uses exact global census and no command-line/cwd/path filter' $globalCensusWiringExact

$budget = [PSCustomObject][ordered]@{
    cargo_timeout_ms = 1200000L
    owned_launch_timeout_ms = 1800000L
    cleanup_reserve_ms = 120000L
    persist_reserve_ms = 60000L
    sample_period_ms = 10000L
    raw_capture_limit_bytes = 268435456L
    cargo_jobs = 4L
}
Assert-D32BoundedCompilerDiagnosticSelfTest 'fixed bounded budget accepted' (Assert-D32BoundedCompilerDiagnosticBudget $budget)
$shortBudget = [PSCustomObject]@{ cargo_timeout_ms = 1200000; owned_launch_timeout_ms = 1300000; cleanup_reserve_ms = 120000; persist_reserve_ms = 60000; sample_period_ms = 10000; raw_capture_limit_bytes = 268435456; cargo_jobs = 4 }
try { $null = Assert-D32BoundedCompilerDiagnosticBudget $shortBudget; $budgetRejected = $false } catch { $budgetRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'insufficient reserved ceiling rejected' $budgetRejected
$slowSampleBudget = [PSCustomObject]@{ cargo_timeout_ms = 1200000; owned_launch_timeout_ms = 1800000; cleanup_reserve_ms = 120000; persist_reserve_ms = 60000; sample_period_ms = 10001; raw_capture_limit_bytes = 268435456; cargo_jobs = 4 }
try { $null = Assert-D32BoundedCompilerDiagnosticBudget $slowSampleBudget; $sampleRejected = $false } catch { $sampleRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'sampler slower than 10 seconds rejected' $sampleRejected
$fastSampleBudget = [PSCustomObject]@{ cargo_timeout_ms = 1200000; owned_launch_timeout_ms = 1800000; cleanup_reserve_ms = 120000; persist_reserve_ms = 60000; sample_period_ms = 9999; raw_capture_limit_bytes = 268435456; cargo_jobs = 4 }
try { $null = Assert-D32BoundedCompilerDiagnosticBudget $fastSampleBudget; $fastSampleRejected = $false } catch { $fastSampleRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'sampler more frequent than 10 seconds rejected' $fastSampleRejected
Assert-D32BoundedCompilerDiagnosticSelfTest 'Cargo plus cleanup and persist reserve accepted' (Test-D32BoundedCompilerDiagnosticCanStart 1380000)
Assert-D32BoundedCompilerDiagnosticSelfTest 'less than Cargo plus cleanup and persist reserve rejected' (-not (Test-D32BoundedCompilerDiagnosticCanStart 1379999))
$largerReserves = [PSCustomObject]@{ cargo_timeout_ms = 1200000; owned_launch_timeout_ms = 1800000; cleanup_reserve_ms = 140000; persist_reserve_ms = 70000; sample_period_ms = 10000; raw_capture_limit_bytes = 268435456; cargo_jobs = 4 }
Assert-D32BoundedCompilerDiagnosticSelfTest 'caller-pinned larger cleanup/persist reserves are enforced' (Test-D32BoundedCompilerDiagnosticCanStart 1410000 $largerReserves -and -not (Test-D32BoundedCompilerDiagnosticCanStart 1409999 $largerReserves))
$earlyDrain = Get-D32BoundedCompilerDiagnosticStopDrainDeadlineTicks -NowTicks 100000 -StopwatchFrequency 1000 -OverallDeadlineTicks 2000000 -CleanupReserveMilliseconds 120000 -PersistReserveMilliseconds 60000
$lateDrain = Get-D32BoundedCompilerDiagnosticStopDrainDeadlineTicks -NowTicks 1820000 -StopwatchFrequency 1000 -OverallDeadlineTicks 2000000 -CleanupReserveMilliseconds 120000 -PersistReserveMilliseconds 60000
Assert-D32BoundedCompilerDiagnosticSelfTest 'early stop gets at most 30 seconds of trace-drain time' ($earlyDrain -eq 130000)
Assert-D32BoundedCompilerDiagnosticSelfTest 'stop-drain never crosses cleanup and persistence reserve boundary' ($lateDrain -eq 1820000)

$expectedEnvironment = [ordered]@{ SystemRoot = 'C:\Windows'; TEMP = 'E:\diagnostic\temp'; TMP = 'E:\diagnostic\temp'; CARGO_HOME = 'E:\d32\inv7\r\c'; CARGO_NET_OFFLINE = 'true'; RUSTC = 'C:\toolchain\bin\rustc.exe'; RUSTDOC = 'C:\toolchain\bin\rustdoc.exe'; PATH = 'C:\toolchain\bin'; INCLUDE = 'C:\msvc\include'; LIB = 'C:\msvc\lib'; LIBPATH = 'C:\msvc\libpath' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'exact profile environment accepted' (Test-D32BoundedCompilerDiagnosticExactEnvironment -Environment $expectedEnvironment -Expected $expectedEnvironment)
$environmentWithHome = [ordered]@{}; foreach ($key in $expectedEnvironment.Keys) { $environmentWithHome[$key] = $expectedEnvironment[$key] }; $environmentWithHome['HOME'] = 'C:\Users\untrusted'
Assert-D32BoundedCompilerDiagnosticSelfTest 'home configuration injection rejected' (-not (Test-D32BoundedCompilerDiagnosticExactEnvironment -Environment $environmentWithHome -Expected $expectedEnvironment))
$environmentWithFlags = [ordered]@{}; foreach ($key in $expectedEnvironment.Keys) { $environmentWithFlags[$key] = $expectedEnvironment[$key] }; $environmentWithFlags['RUSTFLAGS'] = '-C opt-level=3'
Assert-D32BoundedCompilerDiagnosticSelfTest 'ambient compiler flag rejected' (-not (Test-D32BoundedCompilerDiagnosticExactEnvironment -Environment $environmentWithFlags -Expected $expectedEnvironment))
$environmentWithTarget = [ordered]@{}; foreach ($key in $expectedEnvironment.Keys) { $environmentWithTarget[$key] = $expectedEnvironment[$key] }; $environmentWithTarget['CARGO_TARGET_DIR'] = 'E:\somewhere-else'
Assert-D32BoundedCompilerDiagnosticSelfTest 'target override rejected' (-not (Test-D32BoundedCompilerDiagnosticExactEnvironment -Environment $environmentWithTarget -Expected $expectedEnvironment))

$highSample = [PSCustomObject]@{ Reliable = $true; AvailablePhysicalBytes = 5L * 1024L * 1024L * 1024L; CommitHeadroomBytes = 3L * 1024L * 1024L * 1024L }
$lowSample = [PSCustomObject]@{ Reliable = $true; AvailablePhysicalBytes = 3L * 1024L * 1024L * 1024L; CommitHeadroomBytes = 3L * 1024L * 1024L * 1024L }
Assert-D32BoundedCompilerDiagnosticSelfTest 'healthy sample continues' (-not (Test-D32BoundedCompilerDiagnosticResourceStop -Sample $highSample -MetricsReliable $true -AdmissionSucceeded $true -CaptureLimitReached $false -DeadlineReached $false))
Assert-D32BoundedCompilerDiagnosticSelfTest 'physical-memory threshold stops' (Test-D32BoundedCompilerDiagnosticResourceStop -Sample $lowSample -MetricsReliable $true -AdmissionSucceeded $true -CaptureLimitReached $false -DeadlineReached $false)
Assert-D32BoundedCompilerDiagnosticSelfTest 'unreliable sample stops' (Test-D32BoundedCompilerDiagnosticResourceStop -Sample $null -MetricsReliable $false -AdmissionSucceeded $true -CaptureLimitReached $false -DeadlineReached $false)
Assert-D32BoundedCompilerDiagnosticSelfTest 'capture ceiling stops' (Test-D32BoundedCompilerDiagnosticResourceStop -Sample $highSample -MetricsReliable $true -AdmissionSucceeded $true -CaptureLimitReached $true -DeadlineReached $false)
Assert-D32BoundedCompilerDiagnosticSelfTest 'deadline stops' (Test-D32BoundedCompilerDiagnosticResourceStop -Sample $highSample -MetricsReliable $true -AdmissionSucceeded $true -CaptureLimitReached $false -DeadlineReached $true)

$sourceProofWorkDeadline = Get-D32BoundedDiagnosticSourceProofWorkDeadlineMilliseconds
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof keeps its fixed 300-second combined budget and 30-second result reserve' `
    ($script:D32BoundedDiagnosticSourceProofCombinedMilliseconds -eq 300000L -and $sourceProofWorkDeadline -eq 270000L)
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof deadline comparison is strictly below the pinned ceiling' `
    ((Test-D32BoundedDiagnosticSourceProofElapsedWithinDeadline -ElapsedMilliseconds 269999L -DeadlineMilliseconds 270000L) -and
     -not (Test-D32BoundedDiagnosticSourceProofElapsedWithinDeadline -ElapsedMilliseconds 270000L -DeadlineMilliseconds 270000L))
$supervisorBoundaries =
    ((Get-D32BoundedDiagnosticSourceProofSupervisorDisposition -ElapsedMilliseconds 0L -ProcessExited $false) -ceq 'WORK_IN_PROGRESS') -and
    ((Get-D32BoundedDiagnosticSourceProofSupervisorDisposition -ElapsedMilliseconds 269999L -ProcessExited $false) -ceq 'WORK_IN_PROGRESS') -and
    ((Get-D32BoundedDiagnosticSourceProofSupervisorDisposition -ElapsedMilliseconds 270000L -ProcessExited $false) -ceq 'WORK_DEADLINE_ADVISORY') -and
    ((Get-D32BoundedDiagnosticSourceProofSupervisorDisposition -ElapsedMilliseconds 299999L -ProcessExited $false) -ceq 'WORK_DEADLINE_ADVISORY') -and
    ((Get-D32BoundedDiagnosticSourceProofSupervisorDisposition -ElapsedMilliseconds 300000L -ProcessExited $false) -ceq 'TOTAL_DEADLINE_EXPIRED') -and
    ((Get-D32BoundedDiagnosticSourceProofSupervisorDisposition -ElapsedMilliseconds 300000L -ProcessExited $true) -ceq 'CHILD_EXITED')
$negativeSupervisorElapsedRejected = $false
try { $null = Get-D32BoundedDiagnosticSourceProofSupervisorDisposition -ElapsedMilliseconds -1L -ProcessExited $false } catch { $negativeSupervisorElapsedRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'supervisor leaves 270 seconds advisory-only, waits through the 30-second reserve, and terminates only at total expiry' ($supervisorBoundaries -and $negativeSupervisorElapsedRejected)
$stoppedSourceProofTimer = [Diagnostics.Stopwatch]::new()
$deadlineStreamBytes = [byte[]]@(1, 2, 3, 4)
$deadlineMemoryStream = [IO.MemoryStream]::new($deadlineStreamBytes, $false)
$exactReadDeadlineRejected = $false
try { $null = Read-D32BoundedCompilerDiagnosticStreamExact -Stream $deadlineMemoryStream -Count 4 -ProofTimer $stoppedSourceProofTimer -DeadlineMilliseconds 270000L } catch { $exactReadDeadlineRejected = $_.Exception.Message -like '*deadline reached*' -or $_.Exception.Message -like '*no active monotonic proof timer*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'archive exact-read deadline is checked before a bounded stream read without sleeping' ($exactReadDeadlineRejected -and $deadlineMemoryStream.Position -eq 0)
$deadlineMemoryStream.Dispose()

$lockText = @'
version = 4

[[package]]
name = "sample-crate"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
dependencies = []

[[package]]
name = "git-crate"
version = "0.1.0"
source = "git+https://example.invalid/repo?rev=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[[package]]
name = "workspace-crate"
version = "0.1.0"
'@
$lockRows = @(Get-D32BoundedCompilerDiagnosticLockSources -LockText $lockText)
Assert-D32BoundedCompilerDiagnosticSelfTest 'registry archive and immutable Git source parsed' ($lockRows.Count -eq 3 -and $lockRows[0].source_kind -ceq 'registry' -and $lockRows[1].source_kind -ceq 'git' -and $lockRows[1].commit -ceq ('b' * 40) -and $lockRows[2].source_kind -ceq 'workspace')
$lockLf = $lockText.Replace("`r`n", "`n")
$lockCrLf = [regex]::Replace($lockText, '\r?\n', "`r`n")
$lockNoFinalNewline = $lockText.TrimEnd("`r", "`n")
$lockLfRows = @(Get-D32BoundedCompilerDiagnosticLockSources -LockText $lockLf)
$lockCrLfRows = @(Get-D32BoundedCompilerDiagnosticLockSources -LockText $lockCrLf)
$lockNoFinalRows = @(Get-D32BoundedCompilerDiagnosticLockSources -LockText $lockNoFinalNewline)
$lineEndingSemanticsExact = @($lockLfRows | ForEach-Object { [string]$_.package_id }) -join "`n" -ceq (@($lockRows | ForEach-Object { [string]$_.package_id }) -join "`n") -and
    (@($lockCrLfRows | ForEach-Object { [string]$_.package_id }) -join "`n") -ceq (@($lockRows | ForEach-Object { [string]$_.package_id }) -join "`n") -and
    (@($lockNoFinalRows | ForEach-Object { [string]$_.package_id }) -join "`n") -ceq (@($lockRows | ForEach-Object { [string]$_.package_id }) -join "`n")
Assert-D32BoundedCompilerDiagnosticSelfTest 'streaming Cargo.lock line scanner preserves LF, CRLF, and no-final-newline package semantics' $lineEndingSemanticsExact
$stoppedLockDeadlineRejected = $false
try { $null = Get-D32BoundedCompilerDiagnosticLockSources -LockText $lockText -ProofTimer $stoppedSourceProofTimer -DeadlineMilliseconds 270000L } catch { $stoppedLockDeadlineRejected = $_.Exception.Message -like '*deadline reached*' -or $_.Exception.Message -like '*no active monotonic proof timer*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'streaming Cargo.lock parser fails closed at an expired in-memory deadline' $stoppedLockDeadlineRejected
$sourcePlan = Get-D32BoundedCompilerDiagnosticSourcePlan -LockText $lockText
Assert-D32BoundedCompilerDiagnosticSelfTest 'source plan V2 is explicitly non-authorizing and not verified' ($sourcePlan.record_type -ceq 'D32_BOUNDED_DIAGNOSTIC_LOCK_SOURCE_PLAN_V2' -and $sourcePlan.schema_version -eq 2 -and $sourcePlan.gate_authority -ceq 'NONE' -and $sourcePlan.verification_status -ceq 'NOT_RUN' -and $sourcePlan.source_proof_status -ceq 'NOT_VERIFIED' -and $sourcePlan.lock_dependency_edge_count -eq 0)
Assert-D32BoundedCompilerDiagnosticSelfTest 'source plan declares the verifier-wide 512 MiB cap and single buffered-archive ceiling' ($sourcePlan.verifier_managed_buffer_cap_bytes -eq 536870912L -and $script:D32BoundedCompilerDiagnosticRegistryArchiveLimitBytes -eq 268435456L)
Assert-D32BoundedCompilerDiagnosticSelfTest 'source plan emits exact registry archive and source paths' ($sourcePlan.registry_package_count -eq 1 -and $sourcePlan.registry_packages[0].archive_path -ceq 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f\sample-crate-1.2.3.crate' -and $sourcePlan.registry_packages[0].extracted_source_path -ceq 'E:\d32\inv7\r\c\registry\src\index.crates.io-1949cf8c6b5b557f\sample-crate-1.2.3')
Assert-D32BoundedCompilerDiagnosticSelfTest 'source plan emits immutable Git URL/commit tuple and fixed roots' ($sourcePlan.git_source_count -eq 1 -and $sourcePlan.git_sources[0].url -ceq ('https://example.invalid/repo?rev=' + ('b' * 40)) -and $sourcePlan.git_sources[0].commit -ceq ('b' * 40) -and $sourcePlan.git_sources[0].database_root -ceq 'E:\d32\inv7\r\c\git\db' -and $sourcePlan.git_sources[0].checkout_root -ceq 'E:\d32\inv7\r\c\git\checkouts')
try { $null = Get-D32BoundedCompilerDiagnosticSourcePlan -LockText $lockText.Replace('version = 4', 'version = 2'); $oldLockVersionRejected = $false } catch { $oldLockVersionRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'unsupported Cargo.lock format version rejected by finite lock parser' $oldLockVersionRejected
try { $null = Get-D32BoundedCompilerDiagnosticSourcePlan -LockText $lockText.Replace('version = 4', 'version = 4' + "`n[metadata]`n") ; $unknownLockTableRejected = $false } catch { $unknownLockTableRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'unknown Cargo.lock root table rejected instead of silently omitted from the audit catalog' $unknownLockTableRejected
function Add-D32BoundedCompilerDiagnosticGraphFixturePackage {
    param([System.Collections.Generic.List[string]]$Lines, [string]$Name, [string[]]$DependencySpecs = @(), [switch]$Workspace)
    $Lines.Add(''); $Lines.Add('[[package]]'); $Lines.Add(('name = "' + $Name + '"')); $Lines.Add('version = "1.0.0"')
    if (-not $Workspace) { $Lines.Add('source = "registry+https://github.com/rust-lang/crates.io-index"'); $Lines.Add(('checksum = "' + ('a' * 64) + '"')) }
    if ($DependencySpecs.Count -gt 0) { $Lines.Add('dependencies = ['); foreach ($spec in $DependencySpecs) { $Lines.Add(('    "' + $spec + '",')) }; $Lines.Add(']') }
}
function New-D32BoundedCompilerDiagnosticGraphFixtureEntry {
    param([object]$Plan, [string]$Name, [string]$Text, [string]$SourcePath = 'Cargo.toml')
    $package = @($Plan.locked_packages | Where-Object { [string]$_.name -ceq $Name })
    if ($package.Count -ne 1) { throw ('graph fixture lock identity missing/ambiguous: ' + $Name) }
    $model = ConvertFrom-D32BoundedDiagnosticCargoManifest -Text $Text -SourcePath $SourcePath
    $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($Text))).ToLowerInvariant()
    $sourceKind = [string]$package[0].source_kind
    $sourceIdentity = if ($null -eq $package[0].source) { 'workspace' } else { [string]$package[0].source }
    return [PSCustomObject]@{ package_id = [string]$package[0].package_id; source_kind = $sourceKind; source_identity = $sourceIdentity; source_path = $SourcePath; content_sha256 = $sha; content = $Text; model = $model }
}
$manifestLineFixture = "[package]`nname = `"streaming-fixture`"`nversion = `"1.2.3`"`n[dependencies]`nsmall = { version = `"1`", optional = true }`n"
$manifestLineFixtureCrLf = [regex]::Replace($manifestLineFixture, '\r?\n', "`r`n")
$manifestLineFixtureNoFinalNewline = $manifestLineFixture.TrimEnd("`r", "`n")
$manifestLineModels = @(
    (ConvertFrom-D32BoundedDiagnosticCargoManifest -Text $manifestLineFixture -SourcePath 'fixture/Cargo.toml'),
    (ConvertFrom-D32BoundedDiagnosticCargoManifest -Text $manifestLineFixtureCrLf -SourcePath 'fixture/Cargo.toml'),
    (ConvertFrom-D32BoundedDiagnosticCargoManifest -Text $manifestLineFixtureNoFinalNewline -SourcePath 'fixture/Cargo.toml'))
$manifestLineSemanticsExact = @($manifestLineModels | Where-Object { $_.package_name -ceq 'streaming-fixture' -and $_.package_version -ceq '1.2.3' -and $_.dependencies.Count -eq 1 -and $_.dependencies[0].alias -ceq 'small' }).Count -eq 3
Assert-D32BoundedCompilerDiagnosticSelfTest 'streaming Cargo.toml scanner preserves LF, CRLF, trailing LF, inline dependency, and no-final-newline semantics' $manifestLineSemanticsExact
$stoppedManifestDeadlineRejected = $false
try { $null = ConvertFrom-D32BoundedDiagnosticCargoManifest -Text $manifestLineFixture -SourcePath 'fixture/Cargo.toml' -ProofTimer $stoppedSourceProofTimer -DeadlineMilliseconds 270000L } catch { $stoppedManifestDeadlineRejected = $_.Exception.Message -like '*deadline reached*' -or $_.Exception.Message -like '*no active monotonic proof timer*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'streaming Cargo.toml parser fails closed at an expired in-memory deadline' $stoppedManifestDeadlineRejected
$nestedTomlDepth64 = [Text.StringBuilder]::new()
[void]$nestedTomlDepth64.Append('{')
for ($index = 0; $index -lt 63; $index++) { [void]$nestedTomlDepth64.Append('k={') }
[void]$nestedTomlDepth64.Append('leaf="v"')
for ($index = 0; $index -lt 64; $index++) { [void]$nestedTomlDepth64.Append('}') }
$nestedToml64Accepted = $false
try { $nestedToml64Accepted = (ConvertFrom-D32BoundedDiagnosticCargoValue -Text $nestedTomlDepth64.ToString()).kind -ceq 'table' } catch { $nestedToml64Accepted = $false }
Assert-D32BoundedCompilerDiagnosticSelfTest 'finite TOML inline-table nesting depth 64 remains accepted' $nestedToml64Accepted
$nestedTomlDepth65 = [Text.StringBuilder]::new()
[void]$nestedTomlDepth65.Append('{')
for ($index = 0; $index -lt 64; $index++) { [void]$nestedTomlDepth65.Append('k={') }
[void]$nestedTomlDepth65.Append('leaf="v"')
for ($index = 0; $index -lt 65; $index++) { [void]$nestedTomlDepth65.Append('}') }
$nestedToml65Rejected = $false
try { $null = ConvertFrom-D32BoundedDiagnosticCargoValue -Text $nestedTomlDepth65.ToString() } catch { $nestedToml65Rejected = $_.Exception.Message -like '*nesting exceeds the fixed 64-level parser stack bound*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'TOML inline-table nesting beyond the fixed depth 64 fails closed' $nestedToml65Rejected
$boundedSplitRejected = $false
try { $null = Split-D32BoundedDiagnosticTopLevel -Text 'a,b,c' -MaximumParts 2 } catch { $boundedSplitRejected = $_.Exception.Message -like '*fixed per-value part bound*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'TOML top-level split stops before materializing beyond its finite part bound' $boundedSplitRejected
$smallValueNodeBudget = [ordered]@{ nodes = 0L; maximum = 2L }
$boundedValueNodesRejected = $false
try { $null = ConvertFrom-D32BoundedDiagnosticCargoValue -Text '["a","b"]' -ValueNodeBudget $smallValueNodeBudget } catch { $boundedValueNodesRejected = $_.Exception.Message -like '*aggregate TOML value-node budget reached*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'TOML value materialization fails closed at its aggregate node budget' ($boundedValueNodesRejected -and $smallValueNodeBudget.nodes -eq 2L)
$emptyTupleComponentKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@('workspace', ''))
$nonemptyTupleComponentKey = Get-D32BoundedDiagnosticGraphTupleKey -Values ([string[]]@('workspace'))
Assert-D32BoundedCompilerDiagnosticSelfTest 'length-prefixed graph tuple keys preserve intentional empty source components without colliding' ($emptyTupleComponentKey -ceq '9:workspace0:' -and $emptyTupleComponentKey -cne $nonemptyTupleComponentKey)
$graphRegistrySource = 'registry+https://github.com/rust-lang/crates.io-index'
$graphLines = [System.Collections.Generic.List[string]]::new(); $graphLines.Add('version = 4')
$rootEdgeSpecs = [System.Collections.Generic.List[string]]::new(); $rootEdgeSpecs.Add('local-protocol 1.0.0')
foreach ($name in @('left', 'right', 'shared', 'windows-only', 'unix-only', 'unknown-cfg', 'build-helper', 'root-dev', 'proc-macro-helper')) { $rootEdgeSpecs.Add(($name + ' 1.0.0 (' + $graphRegistrySource + ')')) }
Add-D32BoundedCompilerDiagnosticGraphFixturePackage -Lines $graphLines -Name 'digital-life-vita-agent' -DependencySpecs $rootEdgeSpecs -Workspace
Add-D32BoundedCompilerDiagnosticGraphFixturePackage -Lines $graphLines -Name 'local-protocol' -Workspace
Add-D32BoundedCompilerDiagnosticGraphFixturePackage -Lines $graphLines -Name 'left' -DependencySpecs @('shared 1.0.0 (' + $graphRegistrySource + ')')
Add-D32BoundedCompilerDiagnosticGraphFixturePackage -Lines $graphLines -Name 'right' -DependencySpecs @('shared 1.0.0 (' + $graphRegistrySource + ')')
foreach ($leaf in @('shared', 'windows-only', 'unix-only', 'unknown-cfg', 'build-helper', 'root-dev', 'proc-macro-helper', 'unreferenced')) { Add-D32BoundedCompilerDiagnosticGraphFixturePackage -Lines $graphLines -Name $leaf }
$graphPlan = Get-D32BoundedCompilerDiagnosticSourcePlan -LockText ($graphLines -join "`n")
$graphRootManifest = "[package]`nname = `"digital-life-vita-agent`"`nversion = `"1.0.0`"`n[features]`ndefault = []`nd32-a-test-helper = []`n[dependencies]`nlocal-protocol = { path = `"../vita-agent-protocol`", version = `"1`" }`nrenamed-left = { package = `"left`", version = `"1`" }`noptional-right = { package = `"right`", version = `"1`", optional = true }`nproc-macro-helper = `"1`"`n[target.'cfg(windows)'.dependencies]`nwindows-only = `"1`"`n[target.'cfg(unix)'.dependencies]`nunix-only = `"1`"`nshared = `"1`"`n[target.'cfg(target_feature = `"future_extension`")'.dependencies]`nunknown-cfg = `"1`"`n[build-dependencies]`nbuild-helper = `"1`"`n[dev-dependencies]`nroot-dev = `"1`"`n"
$graphCatalog = [System.Collections.Generic.List[object]]::new()
$graphCatalog.Add((New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name 'digital-life-vita-agent' -Text $graphRootManifest -SourcePath 'vita-agent/Cargo.toml'))
$graphCatalog.Add((New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name 'local-protocol' -Text "[package]`nname = `"local-protocol`"`nversion = `"1.0.0`"`n" -SourcePath 'vita-agent-protocol/Cargo.toml'))
$graphCatalog.Add((New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name 'left' -Text "[package]`nname = `"left`"`nversion = `"1.0.0`"`n[dependencies]`nshared = `"1`"`n"))
$graphCatalog.Add((New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name 'right' -Text "[package]`nname = `"right`"`nversion = `"1.0.0`"`n[dependencies]`nshared = `"1`"`n"))
foreach ($leaf in @('shared', 'windows-only', 'unknown-cfg', 'build-helper', 'root-dev')) { $graphCatalog.Add((New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name $leaf -Text ('[package]' + "`n" + 'name = "' + $leaf + '"' + "`nversion = `"1.0.0`"`n"))) }
$graphCatalog.Add((New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name 'proc-macro-helper' -Text "[package]`nname = `"proc-macro-helper`"`nversion = `"1.0.0`"`n[lib]`nproc-macro = true`n"))
$graphProof = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog @($graphCatalog.ToArray())
$graphCrateKinds = @($graphProof.selected_crate_kinds)
$graphProof.selected_crate_kinds = [string]::Join(',', [string[]]$graphCrateKinds)
Assert-D32BoundedCompilerDiagnosticSelfTest 'graph proof selected crate-kind list must remain an exact typed array' (-not (Test-D32BoundedDiagnosticSourceGraphProof $graphProof))
$graphProof.selected_crate_kinds = $graphCrateKinds
Assert-D32BoundedCompilerDiagnosticSelfTest 'graph proof exact selected crate kinds and all-targets package scope validate' (Test-D32BoundedDiagnosticSourceGraphProof $graphProof)
$priorGraphCandidateComparisonLimit = [Int64]$script:D32BoundedDiagnosticGraphCandidateComparisonLimit
$script:D32BoundedDiagnosticGraphCandidateComparisonLimit = 1L
$graphCandidateComparisonBudgetRejected = $false
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog @($graphCatalog.ToArray()) } catch { $graphCandidateComparisonBudgetRejected = $_.Exception.Message -like '*fixed graph work bound*' }
finally { $script:D32BoundedDiagnosticGraphCandidateComparisonLimit = $priorGraphCandidateComparisonLimit }
Assert-D32BoundedCompilerDiagnosticSelfTest 'actual dependency graph producer stops after its explicit aggregate candidate-comparison budget' $graphCandidateComparisonBudgetRejected
$graphManifestCandidates = [System.Collections.Generic.List[object]]::new()
foreach ($entry in $graphCatalog) {
    $kind = if ([string]$entry.package_id -like '*|workspace|*') { 'workspace' } else { 'registry' }
    $source = if ($kind -ceq 'registry') { $graphRegistrySource } else { $null }
    $graphManifestCandidates.Add([PSCustomObject]@{ source_kind = $kind; source = $source; source_path = [string]$entry.source_path; content = [string]$entry.content; content_sha256 = [string]$entry.content_sha256; package_id = [string]$entry.package_id })
}
$rootLockPackage = @($graphPlan.locked_packages | Where-Object { [string]$_.name -ceq 'digital-life-vita-agent' })[0]
$protocolLockPackage = @($graphPlan.locked_packages | Where-Object { [string]$_.name -ceq 'local-protocol' })[0]
$catalogBudgetFixtureCandidates = @(
    [PSCustomObject]@{ source_kind = 'workspace'; source = $null; source_path = 'vita-agent/Cargo.toml'; content = "[package]`nname = `"digital-life-vita-agent`"`nversion = `"1.0.0`"`n"; content_sha256 = ''; package_id = [string]$rootLockPackage.package_id },
    [PSCustomObject]@{ source_kind = 'workspace'; source = $null; source_path = 'vita-agent-protocol/Cargo.toml'; content = "[package]`nname = `"local-protocol`"`nversion = `"1.0.0`"`n"; content_sha256 = ''; package_id = [string]$protocolLockPackage.package_id }
)
foreach ($candidate in $catalogBudgetFixtureCandidates) { $candidate.content_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes([string]$candidate.content))).ToLowerInvariant() }
$priorManifestValueNodeLimit = [Int64]$script:D32BoundedDiagnosticManifestValueNodeLimit
$script:D32BoundedDiagnosticManifestValueNodeLimit = 3L
$aggregateCatalogNodeBudgetRejected = $false
try { $null = Complete-D32BoundedDiagnosticManifestCatalog -Plan $graphPlan -Candidates $catalogBudgetFixtureCandidates } catch { $aggregateCatalogNodeBudgetRejected = $_.Exception.Message -like '*aggregate TOML value-node budget reached*' }
finally { $script:D32BoundedDiagnosticManifestValueNodeLimit = $priorManifestValueNodeLimit }
Assert-D32BoundedCompilerDiagnosticSelfTest 'actual manifest-catalog producer shares one aggregate TOML node budget across candidate manifests' $aggregateCatalogNodeBudgetRejected
$completedGraphCatalog = Complete-D32BoundedDiagnosticManifestCatalog -Plan $graphPlan -Candidates @($graphManifestCandidates.ToArray())
$completedGraphProof = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog $completedGraphCatalog.entries
Assert-D32BoundedCompilerDiagnosticSelfTest 'verified archive/tree/current-manifest catalog closes into the same graph proof without retaining raw source authority' ($completedGraphProof.graph_sha256 -ceq $graphProof.graph_sha256 -and $completedGraphCatalog.verified_candidate_manifest_count -eq $graphCatalog.Count)
$crossBoundCandidate = [PSCustomObject]@{ source_kind = 'registry'; source = $graphRegistrySource; source_path = [string]$graphManifestCandidates[0].source_path; content = [string]$graphManifestCandidates[0].content; content_sha256 = [string]$graphManifestCandidates[0].content_sha256; package_id = [string]$graphManifestCandidates[0].package_id }
$crossBoundCandidates = @($crossBoundCandidate) + @($graphManifestCandidates | Select-Object -Skip 1)
try { $null = Complete-D32BoundedDiagnosticManifestCatalog -Plan $graphPlan -Candidates $crossBoundCandidates; $candidateSourceCrossBindRejected = $false } catch { $candidateSourceCrossBindRejected = $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED:*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'explicit manifest package ID cannot be rebound to another locked source kind' $candidateSourceCrossBindRejected
$badManifestBinding = [PSCustomObject]@{ package_id = [string]$graphCatalog[0].package_id; source_kind = 'registry'; source_identity = $graphRegistrySource; source_path = [string]$graphCatalog[0].source_path; content_sha256 = [string]$graphCatalog[0].content_sha256; model = $graphCatalog[0].model }
$badManifestBindingCatalog = @($badManifestBinding) + @($graphCatalog | Select-Object -Skip 1)
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog $badManifestBindingCatalog; $graphSourceIdentityMismatchRejected = $false } catch { $graphSourceIdentityMismatchRejected = $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED:*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'graph catalog manifest source kind and identity must equal the exact lock package source' $graphSourceIdentityMismatchRejected
$changedManifestCandidate = @($graphManifestCandidates.ToArray()); $changedManifestCandidate[1] = [PSCustomObject]@{ source_kind = $changedManifestCandidate[1].source_kind; source = $changedManifestCandidate[1].source; source_path = $changedManifestCandidate[1].source_path; content = $changedManifestCandidate[1].content + "`n# drift"; content_sha256 = $changedManifestCandidate[1].content_sha256; package_id = $changedManifestCandidate[1].package_id }
try { $null = Complete-D32BoundedDiagnosticManifestCatalog -Plan $graphPlan -Candidates $changedManifestCandidate; $sourceManifestDriftRejected = $false } catch { $sourceManifestDriftRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'manifest bytes must match their independently proved archive/tree/current-file digest' $sourceManifestDriftRejected
Assert-D32BoundedCompilerDiagnosticSelfTest 'locked graph emits exhaustive included/excluded V2 partition and closure witness' ($graphProof.record_type -ceq 'D32_BOUNDED_DIAGNOSTIC_SOURCE_GRAPH_PROOF_V2' -and $graphProof.gate_authority -ceq 'NONE' -and $graphProof.locked_package_count -eq 12 -and $graphProof.included_package_count -eq 10 -and $graphProof.excluded_package_count -eq 2 -and $graphProof.classification_count -eq 12 -and @($graphProof.classifications | Where-Object { $_.package_id -like 'unreferenced@*' -and $_.classification -ceq 'EXCLUDED_WITH_WITNESS' -and $_.witness_kind -ceq 'CLOSED_REACHABILITY_CUT' }).Count -eq 1)
Assert-D32BoundedCompilerDiagnosticSelfTest 'renamed optional, root dev, host build, and proc-macro dependencies remain included' (@($graphProof.included_package_ids | Where-Object { $_ -like 'left@*' }).Count -eq 1 -and @($graphProof.included_package_ids | Where-Object { $_ -like 'right@*' }).Count -eq 1 -and @($graphProof.included_package_ids | Where-Object { $_ -like 'root-dev@*' }).Count -eq 1 -and @($graphProof.included_package_ids | Where-Object { $_ -like 'build-helper@*' }).Count -eq 1 -and @($graphProof.included_package_ids | Where-Object { $_ -like 'proc-macro-helper@*' }).Count -eq 1)
Assert-D32BoundedCompilerDiagnosticSelfTest 'two incoming routes to shared dependency are both retained' (@($graphProof.included_edges | Where-Object { $_.target_package_id -like 'shared@*' }).Count -eq 2)
Assert-D32BoundedCompilerDiagnosticSelfTest 'proven-false incoming cfg edge does not exclude a package reachable through other active routes' (@($graphProof.classifications | Where-Object { $_.package_id -like 'shared@*' -and $_.classification -ceq 'INCLUDED' }).Count -eq 1 -and @($graphProof.dependency_decisions | Where-Object { $_.target_package_id -like 'shared@*' -and $_.disposition -ceq 'EXCLUDED_TARGET_PREDICATE_PROVEN_FALSE' }).Count -eq 1)
Assert-D32BoundedCompilerDiagnosticSelfTest 'known Windows cfg includes while known Unix cfg is excluded' (@($graphProof.included_package_ids | Where-Object { $_ -like 'windows-only@*' }).Count -eq 1 -and @($graphProof.classifications | Where-Object { $_.package_id -like 'unix-only@*' -and $_.classification -ceq 'EXCLUDED_WITH_WITNESS' }).Count -eq 1)
Assert-D32BoundedCompilerDiagnosticSelfTest 'unknown target cfg is conservatively included, never treated as false' ($graphProof.unknown_cfg_conservative_include_count -eq 1 -and @($graphProof.included_package_ids | Where-Object { $_ -like 'unknown-cfg@*' }).Count -eq 1)
Assert-D32BoundedCompilerDiagnosticSelfTest 'absent unreferenced lock source is excluded only with a closed-cut witness, not because its manifest is absent' (@($graphProof.classifications | Where-Object { $_.package_id -like 'unreferenced@*' -and $_.classification -ceq 'EXCLUDED_WITH_WITNESS' -and $_.complete_reachable_parent_count -eq $graphProof.included_package_count -and $_.no_active_incoming_edge_from_included }).Count -eq 1)
$workspaceRootManifest = $graphRootManifest.Replace('[dev-dependencies]', "[workspace]`nmembers = [`"vita-agent-protocol`"]`ndefault-members = [`"vita-agent-protocol`"]`n[workspace.dependencies]`nbuild-helper = { version = `"1`" }`n[dev-dependencies]").Replace('build-helper = "1"', 'build-helper = { workspace = true }')
$workspaceRoot = New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name 'digital-life-vita-agent' -Text $workspaceRootManifest -SourcePath 'vita-agent/Cargo.toml'
$workspaceCatalog = @($workspaceRoot) + @($graphCatalog | Where-Object { $_.source_path -cne 'vita-agent/Cargo.toml' })
$workspaceProof = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog $workspaceCatalog
Assert-D32BoundedCompilerDiagnosticSelfTest 'explicit selected package manifest wins over different workspace default-members; inherited host build dependency remains included' (@($workspaceProof.selected_root_ids).Count -eq 1 -and [string]$workspaceProof.selected_root_ids[0] -like 'digital-life-vita-agent@*' -and @($workspaceProof.included_package_ids | Where-Object { $_ -like 'build-helper@*' }).Count -eq 1 -and @($workspaceProof.dependency_decisions | Where-Object { $_.alias -ceq 'build-helper' -and $_.disposition -ceq 'INCLUDED' }).Count -eq 1)
$unsupportedDependencyRoot = New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name 'digital-life-vita-agent' -Text $graphRootManifest.Replace('optional = true', 'optional = true, artifact = "bin"') -SourcePath 'vita-agent/Cargo.toml'
$unsupportedDependencyCatalog = @($unsupportedDependencyRoot) + @($graphCatalog | Where-Object { $_.source_path -cne 'vita-agent/Cargo.toml' })
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog $unsupportedDependencyCatalog; $unknownDepFieldRejected = $false } catch { $unknownDepFieldRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'unsupported source-affecting dependency field fails closed' $unknownDepFieldRejected
$ambiguousSourceRoot = New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name 'digital-life-vita-agent' -Text $graphRootManifest.Replace('path = "../vita-agent-protocol"', ('path = "../vita-agent-protocol", git = "https://example.invalid/repo", rev = "' + ('b' * 40) + '"')) -SourcePath 'vita-agent/Cargo.toml'
$ambiguousSourceCatalog = @($ambiguousSourceRoot) + @($graphCatalog | Where-Object { $_.source_path -cne 'vita-agent/Cargo.toml' })
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog $ambiguousSourceCatalog; $ambiguousSourceRejected = $false } catch { $ambiguousSourceRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'conflicting path and Git source selectors rejected' $ambiguousSourceRejected
Assert-D32BoundedCompilerDiagnosticSelfTest 'bounded semver wildcard uses exact major/minor range rather than broad caret range' (-not (Test-D32BoundedDiagnosticVersionRequirement -Requirement '1.2.*' -LockedVersion '1.3.0') -and (Test-D32BoundedDiagnosticVersionRequirement -Requirement '1.2.*' -LockedVersion '1.2.9'))
$oversizedSemverRejected = $false
try { $null = Test-D32BoundedDiagnosticVersionRequirement -Requirement ('1' * 4097) -LockedVersion '1.0.0' } catch { $oversizedSemverRejected = $_.Exception.Message -like '*4096-character parser work bound*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'semver requirement scanning rejects input beyond its finite per-value work bound' $oversizedSemverRejected
$cfgDepth64Body = 'windows'
for ($index = 0; $index -lt 64; $index++) { $cfgDepth64Body = 'not(' + $cfgDepth64Body + ')' }
$cfgDepth64 = Get-D32BoundedDiagnosticTargetPredicate -Expression ('cfg(' + $cfgDepth64Body + ')') -TargetTriple 'x86_64-pc-windows-msvc'
$cfgDepth65Body = 'windows'
for ($index = 0; $index -lt 65; $index++) { $cfgDepth65Body = 'not(' + $cfgDepth65Body + ')' }
$cfgDepth65Rejected = $false
try { $null = Get-D32BoundedDiagnosticTargetPredicate -Expression ('cfg(' + $cfgDepth65Body + ')') -TargetTriple 'x86_64-pc-windows-msvc' } catch { $cfgDepth65Rejected = $_.Exception.Message -like '*cfg predicate recursion exceeds the fixed 64-level parser stack bound*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'cfg predicate recursion stays within its finite stack bound and preserves all accepted nested result semantics' ($cfgDepth64.proven -and $cfgDepth65Rejected)
$smallCfgBudget = [ordered]@{ scanned_chars = 0L; maximum = 4L }
$cfgCharacterBudgetRejected = $false
try { $null = Get-D32BoundedDiagnosticTargetPredicate -Expression 'cfg(windows)' -TargetTriple 'x86_64-pc-windows-msvc' -ParseBudget $smallCfgBudget } catch { $cfgCharacterBudgetRejected = $_.Exception.Message -like '*fixed 8 Mi-character work bound*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'cfg parser shares an explicit aggregate scanned-character budget across recursive calls' $cfgCharacterBudgetRejected
$oldPlanType = $graphPlan.record_type; $graphPlan.record_type = 'D32_BOUNDED_DIAGNOSTIC_LOCK_SOURCE_PLAN_V1'
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog @($graphCatalog.ToArray()); $oldPlanRejected = $false } catch { $oldPlanRejected = $true }
$graphPlan.record_type = $oldPlanType
Assert-D32BoundedCompilerDiagnosticSelfTest 'old source-plan proof semantics cannot be reused for graph classification' $oldPlanRejected
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog @($graphCatalog.ToArray()) -RootManifestPath 'src-tauri/Cargo.toml'; $wrongRootRejected = $false } catch { $wrongRootRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'wrong root manifest path rejected' $wrongRootRejected
$wrongPathRoot = New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name 'digital-life-vita-agent' -Text $graphRootManifest.Replace('../vita-agent-protocol', '../elsewhere') -SourcePath 'vita-agent/Cargo.toml'
$wrongPathCatalog = @($wrongPathRoot) + @($graphCatalog | Where-Object { $_.source_path -cne 'vita-agent/Cargo.toml' })
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog $wrongPathCatalog; $wrongPathRejected = $false } catch { $wrongPathRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'path dependency source location must bind to the exact verified target manifest' $wrongPathRejected
$priorGraphTarget = $graphPlan.target_triple; $graphPlan.target_triple = 'x86_64-unknown-linux-gnu'
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog @($graphCatalog.ToArray()); $wrongGraphTargetRejected = $false } catch { $wrongGraphTargetRejected = $true }
$graphPlan.target_triple = $priorGraphTarget
Assert-D32BoundedCompilerDiagnosticSelfTest 'wrong host/target platform rejected' $wrongGraphTargetRejected
$missingBuildManifest = @($graphCatalog | Where-Object { $_.package_id -notlike 'build-helper@*' })
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog $missingBuildManifest; $missingBuildRejected = $false } catch { $missingBuildRejected = $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED:*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'reachable missing build macro manifest is unresolved, not excluded' $missingBuildRejected
$missingProcMacroManifest = @($graphCatalog | Where-Object { $_.package_id -notlike 'proc-macro-helper@*' })
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog $missingProcMacroManifest; $missingProcMacroRejected = $false } catch { $missingProcMacroRejected = $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED:*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'reachable missing proc-macro manifest is unresolved, not excluded' $missingProcMacroRejected
$missingDevManifest = @($graphCatalog | Where-Object { $_.package_id -notlike 'root-dev@*' })
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog $missingDevManifest; $missingDevRejected = $false } catch { $missingDevRejected = $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_GRAPH_BLOCKED:*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'selected root dev dependency without source is unresolved, not excluded' $missingDevRejected
$wrongVersionRoot = New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name 'digital-life-vita-agent' -Text $graphRootManifest.Replace('package = "left", version = "1"', 'package = "left", version = "9"') -SourcePath 'vita-agent/Cargo.toml'
$wrongVersionCatalog = @($wrongVersionRoot) + @($graphCatalog | Where-Object { $_.source_path -cne 'vita-agent/Cargo.toml' })
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog $wrongVersionCatalog; $wrongVersionRejected = $false } catch { $wrongVersionRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'manifest version range mismatch against exact lock edge blocked' $wrongVersionRejected
$missingDeclarationText = $graphRootManifest.Replace('renamed-left = { package = "left", version = "1" }' + "`n", '')
$missingDeclarationRoot = New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name 'digital-life-vita-agent' -Text $missingDeclarationText -SourcePath 'vita-agent/Cargo.toml'
$missingDeclarationCatalog = @($missingDeclarationRoot) + @($graphCatalog | Where-Object { $_.source_path -cne 'vita-agent/Cargo.toml' })
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog $missingDeclarationCatalog; $missingDeclarationRejected = $false } catch { $missingDeclarationRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'unexplained Cargo.lock edge absent from a reachable parent manifest is blocked' $missingDeclarationRejected
$wrongSourceText = $graphRootManifest.Replace('package = "left", version = "1"', ('package = "left", version = "1", git = "https://example.invalid/repo", rev = "' + ('b' * 40) + '"'))
$wrongSourceRoot = New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name 'digital-life-vita-agent' -Text $wrongSourceText -SourcePath 'vita-agent/Cargo.toml'
$wrongSourceCatalog = @($wrongSourceRoot) + @($graphCatalog | Where-Object { $_.source_path -cne 'vita-agent/Cargo.toml' })
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog $wrongSourceCatalog; $wrongSourceRejected = $false } catch { $wrongSourceRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'manifest source mismatch against full lock source identity blocked' $wrongSourceRejected
$helperlessRoot = New-D32BoundedCompilerDiagnosticGraphFixtureEntry -Plan $graphPlan -Name 'digital-life-vita-agent' -Text $graphRootManifest.Replace('d32-a-test-helper = []', 'other-feature = []') -SourcePath 'vita-agent/Cargo.toml'
$helperlessCatalog = @($helperlessRoot) + @($graphCatalog | Where-Object { $_.source_path -cne 'vita-agent/Cargo.toml' })
try { $null = Resolve-D32BoundedDiagnosticLockedDependencyGraph -Plan $graphPlan -ManifestCatalog $helperlessCatalog; $helperFeatureRejected = $false } catch { $helperFeatureRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'selected root must declare d32-a-test-helper' $helperFeatureRejected
$altRegistryLock = $lockText.Replace('registry+https://github.com/rust-lang/crates.io-index', 'registry+https://example.invalid/index')
try { $null = Get-D32BoundedCompilerDiagnosticSourcePlan -LockText $altRegistryLock; $altRegistryRejected = $false } catch { $altRegistryRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'non-crates.io registry source rejected' $altRegistryRejected
$mismatchedGitLock = $lockText.Replace(('?rev=' + ('b' * 40) + '#' + ('b' * 40)), ('?rev=' + ('c' * 40) + '#' + ('b' * 40)))
try { $null = Get-D32BoundedCompilerDiagnosticSourcePlan -LockText $mismatchedGitLock; $mismatchedGitRejected = $false } catch { $mismatchedGitRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'Git rev query differing from immutable commit rejected' $mismatchedGitRejected
$archiveRoot = 'sample-crate-1.2.3'
$archiveMembers = @(
    [PSCustomObject]@{ path = "$archiveRoot/"; kind = 'directory'; content = [byte[]]::new(0) },
    [PSCustomObject]@{ path = "$archiveRoot/src/"; kind = 'directory'; content = [byte[]]::new(0) },
    [PSCustomObject]@{ path = "$archiveRoot/Cargo.toml"; kind = 'file'; content = [Text.Encoding]::UTF8.GetBytes('[package]' + "`n" + 'name = "sample-crate"' + "`n" + 'version = "1.2.3"' + "`n") },
    [PSCustomObject]@{ path = "$archiveRoot/src/lib.rs"; kind = 'file'; content = [Text.Encoding]::UTF8.GetBytes('pub fn sample() {}' + "`n") })
$archiveBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries $archiveMembers
$archiveSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($archiveBytes)).ToLowerInvariant()
$archiveInventory = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $archiveBytes -ExpectedPackageRoot $archiveRoot -ExpectedArchiveSha256 $archiveSha
Assert-D32BoundedCompilerDiagnosticSelfTest 'strict USTAR archive parsed with bounded verified root Cargo.toml content' ($archiveInventory.member_count -eq 4 -and $archiveInventory.entries.Count -eq 3 -and $archiveInventory.archive_sha256 -ceq $archiveSha -and @($archiveInventory.entries | Where-Object { $_.path -ceq 'src/lib.rs' }).Count -eq 1 -and $archiveInventory.manifest_text.Contains('sample-crate') -and $archiveInventory.manifest_sha256 -ceq $archiveInventory.entries[0].sha256)
$stoppedProofTimer = [Diagnostics.Stopwatch]::new(); $stoppedProofTimer.Stop()
try { $null = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $archiveBytes -ExpectedPackageRoot $archiveRoot -ExpectedArchiveSha256 $archiveSha -ProofTimer $stoppedProofTimer; $stoppedArchiveTimerRejected = $false }
catch { $stoppedArchiveTimerRejected = $_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED: aggregate source-proof timer*' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof archive parser rejects a missing or stopped aggregate timer before parsing' $stoppedArchiveTimerRejected
try { $null = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $archiveBytes -ExpectedPackageRoot $archiveRoot -ExpectedArchiveSha256 ('0' * 64); $archiveChecksumRejected = $false } catch { $archiveChecksumRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'registry archive checksum mismatch rejected before parsing' $archiveChecksumRejected
$traversalMembers = @($archiveMembers[0], [PSCustomObject]@{ path = "$archiveRoot/../escape.rs"; kind = 'file'; content = [byte[]]@([byte]1) })
$traversalBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries $traversalMembers
$traversalSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($traversalBytes)).ToLowerInvariant()
try { $null = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $traversalBytes -ExpectedPackageRoot $archiveRoot -ExpectedArchiveSha256 $traversalSha; $traversalRejected = $false } catch { $traversalRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'tar path traversal rejected' $traversalRejected
$caseCollisionMembers = @($archiveMembers[0],
    [PSCustomObject]@{ path = "$archiveRoot/src/Lib.rs"; kind = 'file'; content = [byte[]]@([byte]1) },
    [PSCustomObject]@{ path = "$archiveRoot/src/lib.rs"; kind = 'file'; content = [byte[]]@([byte]2) })
$caseCollisionBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries $caseCollisionMembers
$caseCollisionSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($caseCollisionBytes)).ToLowerInvariant()
try { $null = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $caseCollisionBytes -ExpectedPackageRoot $archiveRoot -ExpectedArchiveSha256 $caseCollisionSha; $caseCollisionRejected = $false } catch { $caseCollisionRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'case-insensitive archive path collision rejected' $caseCollisionRejected
$linkMembers = @($archiveMembers[0], [PSCustomObject]@{ path = "$archiveRoot/link"; kind = 'file'; type_flag = '2'; content = [byte[]]::new(0) })
$linkBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries $linkMembers
$linkSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($linkBytes)).ToLowerInvariant()
try { $null = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $linkBytes -ExpectedPackageRoot $archiveRoot -ExpectedArchiveSha256 $linkSha; $linkRejected = $false } catch { $linkRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'tar link member rejected' $linkRejected

# Complete in-memory USTAR/GNU header and scanner matrix. These fixtures never
# open registry cache paths; they exercise the same decoder used by both the
# source-proof producer and the separately authorized diagnostic census.
$prefixHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'lib.rs'; prefix_field = 'sample-crate-1.2.3/src'; kind = 'file'; content = [byte[]]@([byte]1)
})
$prefixRecord = Get-D32BoundedDiagnosticRegistryArchiveHeader -Header $prefixHeader
Assert-D32BoundedCompilerDiagnosticSelfTest 'USTAR prefix field is interpreted only under exact USTAR magic/version and builds the canonical path' `
    ($prefixRecord.format -ceq 'USTAR' -and $prefixRecord.path -ceq 'sample-crate-1.2.3/src/lib.rs')
$gnuFullWidthHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'GNU'; name_field = ('g' * 100); path = ('g' * 100); kind = 'file'; atime = 1L; ctime = 2L; content = [byte[]]@([byte]1)
})
$gnuFullWidthRecord = Get-D32BoundedDiagnosticRegistryArchiveHeader -Header $gnuFullWidthHeader
Assert-D32BoundedCompilerDiagnosticSelfTest 'GNU fixed-width 100-byte name without a NUL is valid while text after first NUL remains forbidden' `
    ($gnuFullWidthRecord.format -ceq 'GNU' -and $gnuFullWidthRecord.path -ceq ('g' * 100) -and $gnuFullWidthRecord.name.Length -eq 100 -and $gnuFullWidthRecord.size -eq 1)
$gnuNamedHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'GNU'; path = 'sample-crate-1.2.3/file'; kind = 'file'; atime = 7L; ctime = 9L; uname_field = 'root'; gname_field = 'staff'
})
$gnuNamedRecord = Get-D32BoundedDiagnosticRegistryArchiveHeader -Header $gnuNamedHeader
Assert-D32BoundedCompilerDiagnosticSelfTest 'GNU nonnegative atime/ctime and strict UTF-8 zero-padded uname/gname positive fields remain supported' `
    ($gnuNamedRecord.format -ceq 'GNU' -and $gnuNamedRecord.uname -ceq 'root' -and $gnuNamedRecord.gname -ceq 'staff')
$gnuTailCases = @(
    [PSCustomObject]@{ name = 'multivolume offset'; offset = 369; kind = 'octal' },
    [PSCustomObject]@{ name = 'reserved bytes 381-384'; offset = 381; kind = 'byte' },
    [PSCustomObject]@{ name = 'reserved byte 385'; offset = 385; kind = 'byte' },
    [PSCustomObject]@{ name = 'sparse offset 1'; offset = 386; kind = 'octal' },
    [PSCustomObject]@{ name = 'sparse size 1'; offset = 398; kind = 'octal' },
    [PSCustomObject]@{ name = 'sparse offset 2'; offset = 410; kind = 'octal' },
    [PSCustomObject]@{ name = 'sparse size 2'; offset = 422; kind = 'octal' },
    [PSCustomObject]@{ name = 'sparse offset 3'; offset = 434; kind = 'octal' },
    [PSCustomObject]@{ name = 'sparse size 3'; offset = 446; kind = 'octal' },
    [PSCustomObject]@{ name = 'sparse offset 4'; offset = 458; kind = 'octal' },
    [PSCustomObject]@{ name = 'sparse size 4'; offset = 470; kind = 'octal' },
    [PSCustomObject]@{ name = 'sparse continuation flag'; offset = 482; kind = 'byte' },
    [PSCustomObject]@{ name = 'real-size'; offset = 483; kind = 'octal' },
    [PSCustomObject]@{ name = 'GNU padding first byte'; offset = 495; kind = 'byte' },
    [PSCustomObject]@{ name = 'GNU padding last byte'; offset = 511; kind = 'byte' })
$gnuTailRejected = 0
foreach ($tailCase in $gnuTailCases) {
    $offset = [int]$tailCase.offset
    $mutator = if ($tailCase.kind -ceq 'octal') {
        [scriptblock]::Create("param(`$h) Set-D32BoundedCompilerDiagnosticTestTarOctal -Header `$h -Offset $offset -Length 12 -Value 1L")
    } else {
        [scriptblock]::Create("param(`$h) `$h[$offset] = 1")
    }
    $badHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
        format = 'GNU'; path = 'sample-crate-1.2.3/file'; kind = 'file'; content = [byte[]]@([byte]1); tail_mutator = $mutator
    })
    if (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badHeader) { $gnuTailRejected++ }
}
Assert-D32BoundedCompilerDiagnosticSelfTest 'GNU tail independently rejects multivolume, both reserved spans, all eight sparse numbers, continuation, real-size, and both padding endpoints' ($gnuTailRejected -eq $gnuTailCases.Count)
$badUstarReserved = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'sample-crate-1.2.3/file'; kind = 'file'; header_mutator = { param($h) $h[511] = 1 }
})
$badUstarVersion = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'sample-crate-1.2.3/file'; kind = 'file'; header_mutator = { param($h) $h[264] = 49 }
})
$badMagic = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'GNU'; path = 'sample-crate-1.2.3/file'; kind = 'file'; header_mutator = { param($h) $h[262] = 0 }
})
Assert-D32BoundedCompilerDiagnosticSelfTest 'USTAR reserved bytes, unsupported version, and non-exact GNU magic/version dispatch are rejected' `
    ((Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badUstarReserved) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badUstarVersion) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badMagic))
$leadingSpaceHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'sample-crate-1.2.3/file'; kind = 'file'; header_mutator = {
        param($h) [Array]::Copy([byte[]]@(32, 54, 52, 52, 0, 32, 32, 32), 0, $h, 100, 8)
    }
})
$leadingSpaceRecord = Get-D32BoundedDiagnosticRegistryArchiveHeader -Header $leadingSpaceHeader
$hiddenOctalHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'sample-crate-1.2.3/file'; kind = 'file'; header_mutator = {
        param($h) [Array]::Copy([byte[]]@(48, 0, 49, 0, 0, 0, 0, 0), 0, $h, 100, 8)
    }
})
$unterminatedOctalHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'sample-crate-1.2.3/file'; kind = 'file'; header_mutator = {
        param($h) [Array]::Copy([byte[]]@(55, 55, 55, 55, 55, 55, 55, 55), 0, $h, 100, 8)
    }
})
$base256Header = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'sample-crate-1.2.3/file'; kind = 'file'; header_mutator = { param($h) $h[100] = 128 }
})
$signedOctalHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'sample-crate-1.2.3/file'; kind = 'file'; header_mutator = { param($h) $h[100] = 45 }
})
$badAtimeHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'GNU'; path = 'sample-crate-1.2.3/file'; kind = 'file'; tail_mutator = { param($h) $h[345] = 45 }
})
$badCtimeHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'GNU'; path = 'sample-crate-1.2.3/file'; kind = 'file'; tail_mutator = { param($h) $h[357] = 128 }
})
Assert-D32BoundedCompilerDiagnosticSelfTest 'strict octal accepts leading spaces and rejects hidden digits, unterminated full-width digits, base-256, and signs' `
    ($leadingSpaceRecord.mode -eq 420 -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $hiddenOctalHeader) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $unterminatedOctalHeader) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $base256Header) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $signedOctalHeader) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badAtimeHeader) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badCtimeHeader))
$badUtf8Header = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'sample-crate-1.2.3/file'; kind = 'file'; header_mutator = { param($h) $h[0] = 255 }
})
$badNamePaddingHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'x'; kind = 'file'; header_mutator = { param($h) $h[2] = 120 }
})
$badLinknameHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'sample-crate-1.2.3/file'; kind = 'file'; linkname_field = 'link'
})
$badDeviceHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'sample-crate-1.2.3/file'; kind = 'file'; devmajor = 1L
})
$badUnamePaddingHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'sample-crate-1.2.3/file'; kind = 'file'; header_mutator = { param($h) $h[265] = 0; $h[266] = 120 }
})
Assert-D32BoundedCompilerDiagnosticSelfTest 'strict UTF-8 text, first-NUL zero padding, empty linkname, zero devices, and zero-padded uname/gname fields enforced' `
    ((Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badUtf8Header) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badNamePaddingHeader) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badLinknameHeader) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badDeviceHeader) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badUnamePaddingHeader))
$badChecksumHeader = [byte[]]$prefixHeader.Clone(); $badChecksumHeader[148] = $badChecksumHeader[148] -bxor 1
Assert-D32BoundedCompilerDiagnosticSelfTest 'header checksum is the unsigned 512-byte sum with checksum field treated as eight spaces' `
    (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badChecksumHeader)
$unsupportedTypes = @('1', '2', '3', '4', '6', '7', 'x', 'g', 'K', 'S')
$unsupportedTypeRejections = 0
foreach ($unsupportedType in $unsupportedTypes) {
    $typeHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
        format = 'USTAR'; path = 'sample-crate-1.2.3/file'; kind = 'file'; type_flag = $unsupportedType
    })
    if (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $typeHeader) { $unsupportedTypeRejections++ }
}
$positiveNulTypeHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = 'sample-crate-1.2.3/file'; kind = 'file'; type_flag = [byte]0
})
$positiveZeroTypeHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'GNU'; path = 'sample-crate-1.2.3/file'; kind = 'file'; type_flag = '0'
})
$positiveGnuTailDigestHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'GNU'; path = 'sample-crate-1.2.3/file'; kind = 'file'; type_flag = '0'; atime = 1L
})
$positiveGnuTailDigestParsed = Get-D32BoundedDiagnosticRegistryArchiveHeader -Header $positiveGnuTailDigestHeader
$positiveGnuTailDigestExpected = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$positiveGnuTailDigestHeader[345..499])).ToLowerInvariant()
$positiveDirectoryHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'GNU'; path = 'sample-crate-1.2.3/dir/'; kind = 'directory'; type_flag = '5'; size_override = 1L
})
$positiveGnuLongNameHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'GNU'; path = '././@LongLink'; name_field = '././@LongLink'; kind = 'file'; type_flag = 'L'; size_override = 2L
})
$ustarGnuLongNameHeader = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'USTAR'; path = '././@LongLink'; name_field = '././@LongLink'; kind = 'file'; type_flag = 'L'; size_override = 2L
})
$badGnuLongNamePlaceholder = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'GNU'; path = '././@LongLink'; name_field = 'placeholder'; kind = 'file'; type_flag = 'L'; size_override = 2L
})
$badGnuLongNameSize = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'GNU'; path = '././@LongLink'; name_field = '././@LongLink'; kind = 'file'; type_flag = 'L'; size_override = 4098L
})
$undersizedGnuLongName = New-D32BoundedCompilerDiagnosticTestTarHeader -Entry ([PSCustomObject]@{
    format = 'GNU'; path = '././@LongLink'; name_field = '././@LongLink'; kind = 'file'; type_flag = 'L'; size_override = 1L
})
Assert-D32BoundedCompilerDiagnosticSelfTest 'NUL/0 regular files and only exact bounded GNU L control header are accepted while links, other extensions, sparse/special types, USTAR L, and nonzero-size directories reject' `
    ($unsupportedTypeRejections -eq $unsupportedTypes.Count -and
     (Get-D32BoundedDiagnosticRegistryArchiveHeader -Header $positiveNulTypeHeader).kind -ceq 'file' -and
     (Get-D32BoundedDiagnosticRegistryArchiveHeader -Header $positiveZeroTypeHeader).kind -ceq 'file' -and
     (Get-D32BoundedDiagnosticRegistryArchiveHeader -Header $positiveGnuLongNameHeader).kind -ceq 'longname' -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $positiveDirectoryHeader) -and
     $positiveGnuTailDigestParsed.prefix_field_sha256 -ceq $positiveGnuTailDigestExpected -and
     $positiveGnuTailDigestParsed.prefix -ceq '')
Assert-D32BoundedCompilerDiagnosticSelfTest 'GNU L placeholder and 2..4097 size are strict, and USTAR L remains unsupported' `
    ((Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $ustarGnuLongNameHeader) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badGnuLongNamePlaceholder) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $badGnuLongNameSize) -and
     (Test-D32BoundedCompilerDiagnosticTestTarHeaderRejected -Header $undersizedGnuLongName))

$layoutRoot = 'layout-crate-1.2.3'
$layoutManifest = [Text.Encoding]::UTF8.GetBytes('[package]' + "`n" + 'name = "layout-crate"' + "`n" + 'version = "1.2.3"' + "`n")
$layoutUstarMembers = @(
    [PSCustomObject]@{ format = 'USTAR'; path = "$layoutRoot/Cargo.toml"; kind = 'file'; content = $layoutManifest },
    [PSCustomObject]@{ format = 'USTAR'; path = "$layoutRoot/src/lib.rs"; name_field = 'lib.rs'; prefix_field = "$layoutRoot/src"; kind = 'file'; content = [Text.Encoding]::UTF8.GetBytes('pub fn f() {}') })
$layoutGnuMembers = @(
    [PSCustomObject]@{ format = 'GNU'; path = "$layoutRoot/Cargo.toml"; kind = 'file'; content = $layoutManifest },
    [PSCustomObject]@{ format = 'GNU'; path = "$layoutRoot/src/lib.rs"; name_field = "$layoutRoot/src/lib.rs"; kind = 'file'; content = [Text.Encoding]::UTF8.GetBytes('pub fn f() {}') })
$layoutMixedMembers = @(
    [PSCustomObject]@{ format = 'USTAR'; path = "$layoutRoot/Cargo.toml"; kind = 'file'; content = $layoutManifest },
    [PSCustomObject]@{ format = 'GNU'; path = "$layoutRoot/src/lib.rs"; name_field = "$layoutRoot/src/lib.rs"; kind = 'file'; content = [Text.Encoding]::UTF8.GetBytes('pub fn f() {}') })
$layoutUstarBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries $layoutUstarMembers
$layoutGnuBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries $layoutGnuMembers
$layoutMixedBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries $layoutMixedMembers
$layoutUstarSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($layoutUstarBytes)).ToLowerInvariant()
$layoutGnuSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($layoutGnuBytes)).ToLowerInvariant()
$layoutMixedSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($layoutMixedBytes)).ToLowerInvariant()
$layoutUstarInventory = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $layoutUstarBytes -ExpectedPackageRoot $layoutRoot -ExpectedArchiveSha256 $layoutUstarSha
$layoutGnuInventory = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $layoutGnuBytes -ExpectedPackageRoot $layoutRoot -ExpectedArchiveSha256 $layoutGnuSha
$layoutMixedInventory = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $layoutMixedBytes -ExpectedPackageRoot $layoutRoot -ExpectedArchiveSha256 $layoutMixedSha
$layoutProjection = { param($inventory) ConvertTo-Json -InputObject @($inventory.entries) -Depth 8 -Compress }
$layoutUstarProjection = & $layoutProjection $layoutUstarInventory
$layoutGnuProjection = & $layoutProjection $layoutGnuInventory
$layoutMixedProjection = & $layoutProjection $layoutMixedInventory
Assert-D32BoundedCompilerDiagnosticSelfTest 'USTAR-prefix, GNU-full-name, and mixed per-header dispatch produce identical member inventories without requiring an explicit package-root directory header' `
    ($layoutUstarProjection -ceq $layoutGnuProjection -and
     $layoutUstarProjection -ceq $layoutMixedProjection -and
     $layoutUstarInventory.header_inventory_sha256 -cne $layoutGnuInventory.header_inventory_sha256 -and
     $layoutMixedInventory.format_counts.ustar_regular -eq 1 -and $layoutMixedInventory.format_counts.gnu_regular -eq 1 -and
     $layoutMixedInventory.entries.Count -eq 3)
$longNameRoot = 'longname-layout-1.0.0'
$longNameManifest = [Text.Encoding]::UTF8.GetBytes('[package]' + "`n" + 'name = "longname-layout"' + "`n" + 'version = "1.0.0"' + "`n")
$fullUstarPrefix = "$longNameRoot/src"
$fullUstarName = 'full-' + ('f' * 82) + '.rs'
$fullUstarPath = $fullUstarPrefix + '/' + $fullUstarName
$sameLongMemberContent = [Text.Encoding]::UTF8.GetBytes('same long member across formats')
$sameLongUstarBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries @(
    [PSCustomObject]@{ format = 'USTAR'; path = "$longNameRoot/Cargo.toml"; kind = 'file'; content = $longNameManifest },
    [PSCustomObject]@{ format = 'USTAR'; path = $fullUstarPath; name_field = $fullUstarName; prefix_field = $fullUstarPrefix; kind = 'file'; content = $sameLongMemberContent })
$sameLongGnuPair = New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $fullUstarPath `
    -Format GNU -NameFieldBytes ([byte[]]::new(0)) -Content $sameLongMemberContent
$sameLongGnuBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries @(
    [PSCustomObject]@{ format = 'GNU'; path = "$longNameRoot/Cargo.toml"; kind = 'file'; content = $longNameManifest },
    $sameLongGnuPair[0], $sameLongGnuPair[1])
$sameLongUstarSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($sameLongUstarBytes)).ToLowerInvariant()
$sameLongGnuSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($sameLongGnuBytes)).ToLowerInvariant()
$sameLongUstarInventory = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $sameLongUstarBytes -ExpectedPackageRoot $longNameRoot -ExpectedArchiveSha256 $sameLongUstarSha
$sameLongGnuInventory = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $sameLongGnuBytes -ExpectedPackageRoot $longNameRoot -ExpectedArchiveSha256 $sameLongGnuSha
Assert-D32BoundedCompilerDiagnosticSelfTest 'one long USTAR prefix/name member and its GNU L plus explicit-empty fallback have the same complete semantic inventory' `
    ((& $layoutProjection $sameLongUstarInventory) -ceq (& $layoutProjection $sameLongGnuInventory) -and
     $sameLongUstarInventory.longname_pair_count -eq 0 -and $sameLongGnuInventory.longname_pair_count -eq 1)
$layoutScanTimer = [Diagnostics.Stopwatch]::StartNew()
$layoutScan = Get-D32BoundedDiagnosticArchiveFormatCensusInventory -CompressedBytes $layoutMixedBytes -ExpectedPackageRoot $layoutRoot `
    -ExpectedArchiveSha256 $layoutMixedSha -CensusTimer $layoutScanTimer
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof producer and census consumer bind the same mixed-format header digest, counts, offsets, and header inventory' `
    ($layoutScan.status -ceq 'COMPLETE_DIAGNOSTIC' -and $layoutScan.header_count -eq $layoutMixedInventory.member_count -and
     $layoutScan.header_inventory_sha256 -ceq $layoutMixedInventory.header_inventory_sha256 -and
     $layoutScan.format_counts.ustar_regular -eq $layoutMixedInventory.format_counts.ustar_regular -and
     $layoutScan.format_counts.gnu_regular -eq $layoutMixedInventory.format_counts.gnu_regular -and
     -not $layoutScan.ordinary_payload_hashed -and -not $layoutScan.ordinary_payload_retained -and
     $layoutScan.longname_control_metadata_hashed -and -not $layoutScan.longname_control_metadata_retained -and $layoutScan.framing_verified)

$longNameEntries = [System.Collections.Generic.List[object]]::new()
$longNameEntries.Add([PSCustomObject]@{ format = 'GNU'; path = "$longNameRoot/Cargo.toml"; kind = 'file'; content = $longNameManifest })

$longNameEntries.AddRange([object[]](New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $fullUstarPath `
    -Format USTAR -PrefixField $fullUstarPrefix -NameField $fullUstarName))

$raw100Path = "$longNameRoot/src/" + ('r' * 115) + '.rs'
$raw100Bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($raw100Path)
$raw100Field = [byte[]]$raw100Bytes[0..99]
$longNameEntries.AddRange([object[]](New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $raw100Path -NameFieldBytes $raw100Field))

$boundary99Base = "$longNameRoot/src/"
$boundary99BaseBytes = [Text.UTF8Encoding]::new($false, $true).GetByteCount($boundary99Base)
$boundary99Path = $boundary99Base + ('u' * (97 - $boundary99BaseBytes)) + 'é' + ('q' * 24) + '.rs'
$boundary99Bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($boundary99Path)
$boundary99Field = [byte[]]$boundary99Bytes[0..98]
$longNameEntries.AddRange([object[]](New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $boundary99Path -NameFieldBytes $boundary99Field))

$splitPrefix = "$longNameRoot/src/"
$splitPrefixBytes = [Text.UTF8Encoding]::new($false, $true).GetByteCount($splitPrefix)
$split100Path = $splitPrefix + ('s' * (99 - $splitPrefixBytes)) + '😀' + ('t' * 24) + '.rs'
$split100Bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($split100Path)
$split100Field = [byte[]]$split100Bytes[0..99]
$longNameEntries.AddRange([object[]](New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $split100Path -NameFieldBytes $split100Field))

$split100UstarPath = $splitPrefix + ('v' * (99 - $splitPrefixBytes)) + '🛡' + ('w' * 24) + '.rs'
$split100UstarBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($split100UstarPath)
$split100UstarField = [byte[]]$split100UstarBytes[0..99]
$longNameEntries.AddRange([object[]](New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $split100UstarPath `
    -Format USTAR -NameFieldBytes $split100UstarField))

$explicitEmptyPath = "$longNameRoot/src/" + ('e' * 120) + '.rs'
$emptyShortField = [byte[]]::new(0)
$longNameEntries.AddRange([object[]](New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $explicitEmptyPath -NameFieldBytes $emptyShortField))

$shortFullPath = "$longNameRoot/src/short-name.rs"
$longNameEntries.AddRange([object[]](New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $shortFullPath -NameField $shortFullPath))

$longNameDirectoryPath = "$longNameRoot/src/long-directory"
$longNameEntries.AddRange([object[]](New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $longNameDirectoryPath `
    -Kind directory -PayloadDirectorySlash -NameField $longNameDirectoryPath))
$maximumPayloadPrefix = "$longNameRoot/src"
$maximumPayloadRemaining = 4096 - [Text.UTF8Encoding]::new($false, $true).GetByteCount($maximumPayloadPrefix)
$maximumPayloadSegments = [System.Collections.Generic.List[string]]::new()
$maximumPayloadSegments.Add($maximumPayloadPrefix)
while ($maximumPayloadRemaining -gt 201) {
    $maximumPayloadSegments.Add(('m' * 200))
    $maximumPayloadRemaining -= 201
}
$maximumPayloadSegments.Add(('z' * ($maximumPayloadRemaining - 1)))
$maximumPayloadPath = $maximumPayloadSegments -join '/'
if ([Text.UTF8Encoding]::new($false, $true).GetByteCount($maximumPayloadPath) -ne 4096) { throw 'max GNU longname fixture did not reach the 4096-byte path boundary' }
$longNameEntries.AddRange([object[]](New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $maximumPayloadPath `
    -NameFieldBytes ([byte[]]::new(0))))

$longNameArchive = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries ([object[]]$longNameEntries.ToArray())
$longNameArchiveSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($longNameArchive)).ToLowerInvariant()
$longNameInventory = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $longNameArchive `
    -ExpectedPackageRoot $longNameRoot -ExpectedArchiveSha256 $longNameArchiveSha
$longNameCensus = Get-D32BoundedDiagnosticArchiveFormatCensusInventory -CompressedBytes $longNameArchive `
    -ExpectedPackageRoot $longNameRoot -ExpectedArchiveSha256 $longNameArchiveSha -CensusTimer ([Diagnostics.Stopwatch]::StartNew())
$longNameFallbacks = @($longNameInventory.longname_pairs | ForEach-Object { [string]$_.fallback_kind })
Assert-D32BoundedCompilerDiagnosticSelfTest 'GNU L pairs accept full USTAR prefix/name, short GNU full name, raw 100-byte prefix including a split UTF-8 scalar for GNU and empty-prefix USTAR, 99-byte scalar-boundary prefix, GNU explicit-empty fallback, repeated placeholders, and directory slash; source-proof and census digests match' `
    ($longNameInventory.archive_policy_id -ceq 'D32_REGISTRY_TAR_USTAR_GNU_LONGNAME_V1' -and
     $longNameInventory.longname_pair_count -eq 9 -and $longNameInventory.member_count -eq 19 -and
     $longNameInventory.ordinary_header_count -eq 10 -and $longNameInventory.format_counts.gnu_longname_extension -eq 9 -and
     $longNameInventory.longname_control_metadata_count -eq 9 -and $longNameInventory.longname_control_metadata_bytes -ge 4097 -and
     $longNameInventory.longname_control_metadata_bytes -le 9 * 4097 -and
     $longNameFallbacks -contains 'FULL_EXACT' -and $longNameFallbacks -contains 'RAW_100_BYTE_PREFIX' -and
     $longNameFallbacks -contains 'UTF8_BOUNDARY_99' -and $longNameFallbacks -contains 'GNU_EXPLICIT_EMPTY' -and
     $longNameInventory.header_inventory_sha256 -ceq $longNameCensus.header_inventory_sha256 -and
     $longNameInventory.longname_pair_inventory_sha256 -ceq $longNameCensus.longname_pair_inventory_sha256 -and
     $longNameInventory.longname_control_metadata_sha256 -ceq $longNameCensus.longname_control_metadata_sha256 -and
     $longNameCensus.status -ceq 'COMPLETE_DIAGNOSTIC' -and $longNameCensus.framing_verified -and
     -not $longNameCensus.ordinary_payload_hashed -and -not $longNameCensus.ordinary_payload_retained -and
     $longNameCensus.longname_control_metadata_hashed -and -not $longNameCensus.longname_control_metadata_retained -and
     @($longNameInventory.entries | Where-Object { [string]$_.path -match '@LongLink' }).Count -eq 0)

function Test-D32BoundedCompilerDiagnosticTestArchiveRejected {
    param([Parameter(Mandatory = $true)][object[]]$Entries)
    $bytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries $Entries
    $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    try { $null = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $bytes -ExpectedPackageRoot $longNameRoot -ExpectedArchiveSha256 $sha; return $false }
    catch { return ([string]$_.Exception.Message -like 'D32_BOUNDED_DIAGNOSTIC_ARCHIVE_BLOCKED:*') }
}

$validNegativeBase = [PSCustomObject]@{ format = 'GNU'; path = "$longNameRoot/Cargo.toml"; kind = 'file'; content = $longNameManifest }
$validNegativeLongPath = "$longNameRoot/src/" + ('n' * 110) + '.rs'
$validNegativePair = New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $validNegativeLongPath `
    -NameFieldBytes ([byte[]]([Text.UTF8Encoding]::new($false, $true).GetBytes($validNegativeLongPath)[0..99]))
$baseControl = $validNegativePair[0]
$baseOrdinary = $validNegativePair[1]
$negativeLongPayloads = @(
    [PSCustomObject]@{ name = 'missing terminal NUL'; bytes = [Text.UTF8Encoding]::UTF8.GetBytes('bad-payload') },
    [PSCustomObject]@{ name = 'double NUL'; bytes = [byte[]]@([byte]65, [byte]0, [byte]0) },
    [PSCustomObject]@{ name = 'interior NUL'; bytes = [byte[]]@([byte]65, [byte]0, [byte]66, [byte]0) },
    [PSCustomObject]@{ name = 'BOM'; bytes = [byte[]]@([byte]0xef, [byte]0xbb, [byte]0xbf, [byte]65, [byte]0) },
    [PSCustomObject]@{ name = 'invalid UTF-8'; bytes = [byte[]]@([byte]0xc3, [byte]0x28, [byte]0) },
    [PSCustomObject]@{ name = 'non-NFC'; bytes = [Text.Encoding]::UTF8.GetBytes("$longNameRoot/src/e$([char]0x0301).rs`0") },
    [PSCustomObject]@{ name = 'root escape'; bytes = [Text.Encoding]::UTF8.GetBytes("$longNameRoot/../escape.rs`0") },
    [PSCustomObject]@{ name = 'absolute path'; bytes = [Text.Encoding]::UTF8.GetBytes("/outside/path.rs`0") },
    [PSCustomObject]@{ name = 'UNC path'; bytes = [Text.Encoding]::UTF8.GetBytes("\\server\share\outside.rs`0") },
    [PSCustomObject]@{ name = 'drive or stream syntax'; bytes = [Text.Encoding]::UTF8.GetBytes("$longNameRoot/src/C:/outside.rs`0") },
    [PSCustomObject]@{ name = 'dot segment'; bytes = [Text.Encoding]::UTF8.GetBytes("$longNameRoot/src/./outside.rs`0") },
    [PSCustomObject]@{ name = 'repeated separator'; bytes = [Text.Encoding]::UTF8.GetBytes("$longNameRoot/src//outside.rs`0") },
    [PSCustomObject]@{ name = 'Windows device alias'; bytes = [Text.Encoding]::UTF8.GetBytes("$longNameRoot/src/CON.txt`0") }
)
$badLongPayloadRejections = 0
foreach ($badPayload in $negativeLongPayloads) {
    $badControl = New-D32BoundedCompilerDiagnosticTestGnuLongNameControl -Payload ([byte[]]$badPayload.bytes)
    if (Test-D32BoundedCompilerDiagnosticTestArchiveRejected -Entries @($validNegativeBase, $badControl, $baseOrdinary)) { $badLongPayloadRejections++ }
}
$badLongPadding = New-D32BoundedCompilerDiagnosticTestGnuLongNameControl -Payload ([byte[]]@([byte]97, [byte]0)) -PaddingByte 1
Assert-D32BoundedCompilerDiagnosticSelfTest 'GNU L payload validates exact terminal NUL, strict UTF-8/NFC/path namespace/containment, and zero padding without repairing paths' `
    ($badLongPayloadRejections -eq $negativeLongPayloads.Count -and
     (Test-D32BoundedCompilerDiagnosticTestArchiveRejected -Entries @($validNegativeBase, $badLongPadding, $baseOrdinary)))
$chainedControl = New-D32BoundedCompilerDiagnosticTestGnuLongNameControl -Payload ([Text.Encoding]::UTF8.GetBytes("$validNegativeLongPath`0"))
$danglingControlArchive = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries @($validNegativeBase, $baseControl)
$danglingControlSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($danglingControlArchive)).ToLowerInvariant()
$danglingControlScan = Get-D32BoundedDiagnosticArchiveFormatCensusInventory -CompressedBytes $danglingControlArchive `
    -ExpectedPackageRoot $longNameRoot -ExpectedArchiveSha256 $danglingControlSha -CensusTimer ([Diagnostics.Stopwatch]::StartNew())
$wrongKindOrdinary = [PSCustomObject]@{ format = 'GNU'; path = $validNegativeLongPath; name_field = 'x'; kind = 'file'; type_flag = 'K'; content = [byte[]]::new(0) }
$oversizedLongPayload = [byte[]]::new(4098)
$oversizedLongPayload[4097] = 0
Assert-D32BoundedCompilerDiagnosticSelfTest 'GNU L rejects chained, dangling/terminator, unsupported-next-type, and over-4097 payload states; census keeps the remainder unknown' `
    ((Test-D32BoundedCompilerDiagnosticTestArchiveRejected -Entries @($validNegativeBase, $baseControl, $chainedControl, $baseOrdinary)) -and
     $danglingControlScan.status -ceq 'BLOCKED' -and $danglingControlScan.remainder_unknown -and -not $danglingControlScan.framing_verified -and
     (Test-D32BoundedCompilerDiagnosticTestArchiveRejected -Entries @($validNegativeBase, $baseControl, $wrongKindOrdinary)) -and
     (Test-D32BoundedCompilerDiagnosticTestArchiveRejected -Entries @($validNegativeBase, (New-D32BoundedCompilerDiagnosticTestGnuLongNameControl -Payload $oversizedLongPayload), $baseOrdinary)))

$mismatchOrdinary = [PSCustomObject]@{ format = 'GNU'; path = $validNegativeLongPath; name_field = 'different.rs'; kind = 'file'; content = [byte[]]@([byte]1) }
$badEmptyUstarPair = New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $validNegativeLongPath -Format USTAR -NameFieldBytes ([byte[]]::new(0))
$nonemptyPrefixBadPair = New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $validNegativeLongPath `
    -Format USTAR -PrefixField $fullUstarPrefix -NameFieldBytes $raw100Field
$boundary98Path = "$longNameRoot/src/" + ('b' * 120) + '.rs'
$boundary98Bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($boundary98Path)
$boundary98Field = [byte[]]$boundary98Bytes[0..97]
$badBoundary98Pair = New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $boundary98Path -NameFieldBytes $boundary98Field
$fileWithDirectoryPayload = New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath "$longNameRoot/src/not-a-dir" -PayloadDirectorySlash
$doubleSlashDirectoryPayload = New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath "$longNameRoot/src/repeated/" `
    -Kind directory -PayloadDirectorySlash -NameField "$longNameRoot/src/repeated/"
$duplicateLongPathPair = New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath $validNegativeLongPath `
    -NameFieldBytes ([byte[]]::new(0))
$caseCollisionLongPath = New-D32BoundedCompilerDiagnosticTestGnuLongNamePairEntries -EffectivePath ("$longNameRoot/src/" + ('N' * 110) + '.rs') `
    -NameFieldBytes ([byte[]]::new(0))
Assert-D32BoundedCompilerDiagnosticSelfTest 'GNU L fallback accepts only exact/full, prescribed raw-100 or scalar-boundary prefix, and GNU-only empty representation; mismatched names, USTAR empty/truncated-prefix, other truncation length, and directory slash/file disagreement reject' `
    ((Test-D32BoundedCompilerDiagnosticTestArchiveRejected -Entries @($validNegativeBase, $baseControl, $mismatchOrdinary)) -and
     (Test-D32BoundedCompilerDiagnosticTestArchiveRejected -Entries @($validNegativeBase, $badEmptyUstarPair[0], $badEmptyUstarPair[1])) -and
     (Test-D32BoundedCompilerDiagnosticTestArchiveRejected -Entries @($validNegativeBase, $nonemptyPrefixBadPair[0], $nonemptyPrefixBadPair[1])) -and
     (Test-D32BoundedCompilerDiagnosticTestArchiveRejected -Entries @($validNegativeBase, $badBoundary98Pair[0], $badBoundary98Pair[1])) -and
     (Test-D32BoundedCompilerDiagnosticTestArchiveRejected -Entries @($validNegativeBase, $fileWithDirectoryPayload[0], $fileWithDirectoryPayload[1])) -and
     (Test-D32BoundedCompilerDiagnosticTestArchiveRejected -Entries @($validNegativeBase, $doubleSlashDirectoryPayload[0], $doubleSlashDirectoryPayload[1])) -and
     (Test-D32BoundedCompilerDiagnosticTestArchiveRejected -Entries @($validNegativeBase, $duplicateLongPathPair[0], $duplicateLongPathPair[1], $duplicateLongPathPair[0], $duplicateLongPathPair[1])) -and
     (Test-D32BoundedCompilerDiagnosticTestArchiveRejected -Entries @($validNegativeBase, $duplicateLongPathPair[0], $duplicateLongPathPair[1], $caseCollisionLongPath[0], $caseCollisionLongPath[1])))
$explicitRootBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries @(
    [PSCustomObject]@{ format = 'GNU'; path = "$layoutRoot/"; kind = 'directory'; content = [byte[]]::new(0) }, $layoutGnuMembers[0], $layoutGnuMembers[1])
$explicitRootSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($explicitRootBytes)).ToLowerInvariant()
$explicitRootInventory = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $explicitRootBytes -ExpectedPackageRoot $layoutRoot -ExpectedArchiveSha256 $explicitRootSha
$duplicateRootBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries @(
    [PSCustomObject]@{ format = 'USTAR'; path = "$layoutRoot/"; kind = 'directory'; content = [byte[]]::new(0) },
    [PSCustomObject]@{ format = 'GNU'; path = "$layoutRoot/"; kind = 'directory'; content = [byte[]]::new(0) }, $layoutGnuMembers[0])
$duplicateRootSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($duplicateRootBytes)).ToLowerInvariant()
try { $null = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $duplicateRootBytes -ExpectedPackageRoot $layoutRoot -ExpectedArchiveSha256 $duplicateRootSha; $duplicateRootRejected = $false } catch { $duplicateRootRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'package-root directory header may be absent or appear once only; duplicate root header rejects' `
    ($explicitRootInventory.member_count -eq 3 -and $explicitRootInventory.entries.Count -eq 3 -and $duplicateRootRejected)

$framingFailures = [System.Collections.Generic.List[string]]::new()
$oneTerminatorBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries $layoutGnuMembers -TerminatorBlocks 1
$oneTerminatorSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($oneTerminatorBytes)).ToLowerInvariant()
$oneTerminatorScan = Get-D32BoundedDiagnosticArchiveFormatCensusInventory -CompressedBytes $oneTerminatorBytes -ExpectedPackageRoot $layoutRoot -ExpectedArchiveSha256 $oneTerminatorSha -CensusTimer ([Diagnostics.Stopwatch]::StartNew())
$nonzeroTrailingBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries $layoutGnuMembers -TrailingBytes ([byte[]]@(0, 1, 0))
$nonzeroTrailingSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($nonzeroTrailingBytes)).ToLowerInvariant()
$nonzeroTrailingScan = Get-D32BoundedDiagnosticArchiveFormatCensusInventory -CompressedBytes $nonzeroTrailingBytes -ExpectedPackageRoot $layoutRoot -ExpectedArchiveSha256 $nonzeroTrailingSha -CensusTimer ([Diagnostics.Stopwatch]::StartNew())
$badPaddingBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries @(
    [PSCustomObject]@{ format = 'GNU'; path = "$layoutRoot/Cargo.toml"; kind = 'file'; content = [byte[]]@([byte]1); padding_byte = 1 })
$badPaddingSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($badPaddingBytes)).ToLowerInvariant()
$badPaddingScan = Get-D32BoundedDiagnosticArchiveFormatCensusInventory -CompressedBytes $badPaddingBytes -ExpectedPackageRoot $layoutRoot -ExpectedArchiveSha256 $badPaddingSha -CensusTimer ([Diagnostics.Stopwatch]::StartNew())
$badGzipBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries $layoutGnuMembers -CorruptGzipTrailer
$badGzipSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($badGzipBytes)).ToLowerInvariant()
$badGzipScan = Get-D32BoundedDiagnosticArchiveFormatCensusInventory -CompressedBytes $badGzipBytes -ExpectedPackageRoot $layoutRoot -ExpectedArchiveSha256 $badGzipSha -CensusTimer ([Diagnostics.Stopwatch]::StartNew())
$framingFailureCount = @(@($oneTerminatorScan, $nonzeroTrailingScan, $badPaddingScan, $badGzipScan) | Where-Object { $_.status -ceq 'BLOCKED' }).Count
Assert-D32BoundedCompilerDiagnosticSelfTest 'census stops on one zero block, nonzero post-terminator tail, nonzero member padding, and corrupt gzip trailer' `
    ($framingFailureCount -eq 4 -and -not $oneTerminatorScan.framing_verified -and -not $nonzeroTrailingScan.framing_verified -and
     -not $badPaddingScan.framing_verified -and -not $badGzipScan.framing_verified)
$stoppedCensusTimer = [Diagnostics.Stopwatch]::new(); $stoppedCensusTimer.Stop()
$stoppedCensusScan = Get-D32BoundedDiagnosticArchiveFormatCensusInventory -CompressedBytes $layoutMixedBytes -ExpectedPackageRoot $layoutRoot `
    -ExpectedArchiveSha256 $layoutMixedSha -CensusTimer $stoppedCensusTimer
$memberLimitScan = Get-D32BoundedDiagnosticArchiveFormatCensusInventory -CompressedBytes $layoutMixedBytes -ExpectedPackageRoot $layoutRoot `
    -ExpectedArchiveSha256 $layoutMixedSha -CensusTimer ([Diagnostics.Stopwatch]::StartNew()) -MaximumMembers 1
Assert-D32BoundedCompilerDiagnosticSelfTest 'census time and member bounds stop without resuming, silently truncating inventory, or marking framing complete' `
    ($stoppedCensusScan.status -ceq 'BUDGET_STOPPED' -and $memberLimitScan.status -ceq 'BUDGET_STOPPED' -and
     $stoppedCensusScan.remainder_unknown -and $memberLimitScan.remainder_unknown -and -not $stoppedCensusScan.framing_verified)
$unicodeAliasBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries @(
    [PSCustomObject]@{ format = 'USTAR'; path = "$layoutRoot/Cargo.toml"; kind = 'file'; content = $layoutManifest },
    [PSCustomObject]@{ format = 'GNU'; path = "$layoutRoot/src/e$([char]0x0301).rs"; kind = 'file'; content = [byte[]]@([byte]1) })
$unicodeAliasSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($unicodeAliasBytes)).ToLowerInvariant()
try { $null = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $unicodeAliasBytes -ExpectedPackageRoot $layoutRoot -ExpectedArchiveSha256 $unicodeAliasSha; $decomposedUnicodeRejected = $false } catch { $decomposedUnicodeRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'non-NFC member names are rejected instead of normalized or repaired' $decomposedUnicodeRejected
$badArchivePaths = @(
    "$layoutRoot/../escape.rs", "$layoutRoot/./dot.rs", "$layoutRoot/src/NUL", "$layoutRoot/src/CON.txt",
    "$layoutRoot/src/name.", "$layoutRoot/src/name ", "$layoutRoot/src/name:stream", "$layoutRoot/src\backslash.rs",
    "$layoutRoot//double-separator.rs", '\\server\share\escape.rs', 'C:\escape.rs')
$badPathRejectCount = 0
foreach ($badArchivePath in $badArchivePaths) {
    $pathBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries @(
        [PSCustomObject]@{ format = 'USTAR'; path = "$layoutRoot/Cargo.toml"; kind = 'file'; content = $layoutManifest },
        [PSCustomObject]@{ format = 'GNU'; path = $badArchivePath; kind = 'file'; content = [byte[]]@([byte]1) })
    $pathSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($pathBytes)).ToLowerInvariant()
    try { $null = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $pathBytes -ExpectedPackageRoot $layoutRoot -ExpectedArchiveSha256 $pathSha }
    catch { $badPathRejectCount++ }
}
$fileParentConflictBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries @(
    [PSCustomObject]@{ format = 'USTAR'; path = "$layoutRoot/Cargo.toml"; kind = 'file'; content = $layoutManifest },
    [PSCustomObject]@{ format = 'USTAR'; path = "$layoutRoot/src"; kind = 'file'; content = [byte[]]@([byte]1) },
    [PSCustomObject]@{ format = 'GNU'; path = "$layoutRoot/src/child.rs"; kind = 'file'; content = [byte[]]@([byte]2) })
$fileParentConflictSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($fileParentConflictBytes)).ToLowerInvariant()
try { $null = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $fileParentConflictBytes -ExpectedPackageRoot $layoutRoot -ExpectedArchiveSha256 $fileParentConflictSha; $fileParentConflictRejected = $false } catch { $fileParentConflictRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'archive path policy rejects traversal, dot/empty segments, reserved Windows devices, trailing dot/space, ADS, backslash, UNC/absolute paths, and file-parent conflicts without normalization' `
    ($badPathRejectCount -eq $badArchivePaths.Count -and $fileParentConflictRejected)

function New-D32BoundedCompilerDiagnosticTestReference {
    param([string]$Path)
    return [PSCustomObject][ordered]@{ path = $Path; bytes = 1L; sha256 = 'a' * 64; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
}
function New-D32BoundedCompilerDiagnosticTestGitContentReference {
    param([string]$Commit = ('b' * 40))
    $database = 'E:\d32\inv7\r\c\git\db\repo-0123456789abcdef'
    $checkoutCache = 'E:\d32\inv7\r\c\git\checkouts\repo-0123456789abcdef'
    $checkout = Join-Path $checkoutCache $Commit.Substring(0, 7)
    $packId = 'c' * 40
    return [PSCustomObject][ordered]@{
        source = "git+https://example.invalid/org/repo?rev=$Commit#$Commit"
        commit = $Commit
        database_path = $database
        database_volume_serial_hex = '0123456789abcdef'
        database_file_id_hex = '0123456789abcdef0123456789abcdef'
        checkout_cache_path = $checkoutCache
        checkout_cache_volume_serial_hex = '0123456789abcdef'
        checkout_cache_file_id_hex = '0123456789abcdef0123456789abcdef'
        checkout_path = $checkout
        checkout_volume_serial_hex = '0123456789abcdef'
        checkout_file_id_hex = '0123456789abcdef0123456789abcdef'
        pack_path = Join-Path $database "objects\pack\pack-$packId.pack"
        pack_bytes = 4096L
        pack_volume_serial_hex = '0123456789abcdef'
        pack_file_id_hex = '0123456789abcdef0123456789abcdef'
        index_path = Join-Path $database "objects\pack\pack-$packId.idx"
        index_bytes = 256L
        index_volume_serial_hex = '0123456789abcdef'
        index_file_id_hex = '0123456789abcdef0123456789abcdef'
    }
}
$testRepo = 'C:\d32-diagnostic-policy-test\repo'
$testCandidate = '1' * 40
$testProfilePath = 'C:\d32-diagnostic-policy-test\profile.json'
$testModuleAuthorityPath = 'C:\d32-diagnostic-policy-test\module-authority.json'
$testGitPath = 'C:\d32-diagnostic-policy-test\git.exe'
$testTarget = Join-Path $testRepo 'vita-agent\target'
$testOutputRoot = 'C:\d32-diagnostic-policy-test\external\run'
$testOwnerReference = New-D32BoundedCompilerDiagnosticTestReference 'E:\d32\inv7\owner.json'
$testBlockedReference = New-D32BoundedCompilerDiagnosticTestReference 'E:\d32\inv7\D32-PHASE0-BLOCKED-DIAGNOSTIC.json'
$testGrantReference = New-D32BoundedCompilerDiagnosticTestReference 'E:\d32\inv7\D32-TEST-INVENTORY-VENDORED-PROTOC-RUN-GRANT.json'
$testFetchReferences = @(
    (New-D32BoundedCompilerDiagnosticTestReference 'E:\d32\inv7\fetch-1.json'),
    (New-D32BoundedCompilerDiagnosticTestReference 'E:\d32\inv7\fetch-2.json'),
    (New-D32BoundedCompilerDiagnosticTestReference 'E:\d32\inv7\fetch-3.json'))
$testGitContentReference = New-D32BoundedCompilerDiagnosticTestGitContentReference
$testManifestReferences = @(
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'vita-agent-protocol\Cargo.toml')),
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'vita-agent-protocol\Cargo.lock')),
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'vita-agent\Cargo.toml')),
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'vita-agent\Cargo.lock')),
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'src-tauri\Cargo.toml')),
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'src-tauri\Cargo.lock')))
$testSourcePins = @(
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'scripts\d32-bounded-compiler-diagnostic.ps1')),
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'scripts\d32-bounded-compiler-diagnostic-policy.ps1')),
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'scripts\d32-bounded-compiler-diagnostic-selftest.ps1')),
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'scripts\d32-fixture-prebuild.ps1')),
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'scripts\d32-build-toolchain-profile.ps1')),
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'scripts\d32-powershell-module-authority.ps1')))
$testGitQueryList = [System.Collections.Generic.List[object]]::new()
$testGitQueryList.Add([string[]]@('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}'))
$testGitQueryList.Add([string[]]@('status', '--porcelain=v1', '--untracked-files=all'))
$testGitQueryList.Add([string[]]@('ls-files', '-v', '-z'))
$testGitQueryList.Add([string[]]@('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}'))
$testGitQueryList.Add([string[]]@('status', '--porcelain=v1', '--untracked-files=all'))
$testGitQueries = $testGitQueryList.ToArray()
$authority = [PSCustomObject][ordered]@{
    schema_version = 3
    record_type = $script:D32BoundedCompilerDiagnosticAuthorityType
    registry_archive_policy = $script:D32BoundedDiagnosticRegistryArchivePolicy
    gate_authority = 'NONE'
    candidate_sha = $testCandidate
    source_repo = $testRepo
    repository_identity = [PSCustomObject]@{ volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
    toolchain_profile = [PSCustomObject]@{ path = $testProfilePath; sha256 = '2' * 64 }
    module_authority = [PSCustomObject]@{ path = $testModuleAuthorityPath; sha256 = '3' * 64 }
    pinned_git = [PSCustomObject]@{ path = $testGitPath; sha256 = '4' * 64 }
    command = [PSCustomObject]@{ argv = $fixedArgv; working_directory = $testRepo; manifest_path = 'vita-agent/Cargo.toml'; target_directory = $testTarget }
    child_environment = $expectedEnvironment
    git_queries = $testGitQueries
    cargo_home = [PSCustomObject]@{ path = 'E:\d32\inv7\r\c'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
    dependency_origin = [PSCustomObject]@{
        path = 'E:\d32\inv7\r\c'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef'
        historical_origin_candidate_sha = $script:D32BoundedDiagnosticHistoricalInv7CandidateSha
        owner_record = $testOwnerReference; blocked_diagnostic = $testBlockedReference; protoc_run_grant = $testGrantReference
        fetch_records = $testFetchReferences; manifest_refs = $testManifestReferences
        registry_archive_root = [PSCustomObject]@{ path = 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
        registry_source_root = [PSCustomObject]@{ path = 'E:\d32\inv7\r\c\registry\src\index.crates.io-1949cf8c6b5b557f'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
        git_database_root = [PSCustomObject]@{ path = 'E:\d32\inv7\r\c\git\db'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
        git_checkout_root = [PSCustomObject]@{ path = 'E:\d32\inv7\r\c\git\checkouts'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
        git_content_refs = @($testGitContentReference)
        registry_archives = @([PSCustomObject]@{ name = 'sample-crate'; version = '1.2.3'; source = 'registry+https://github.com/rust-lang/crates.io-index'; checksum = 'a' * 64 })
        git_source_authority = (New-D32BoundedCompilerDiagnosticTestReference 'E:\d32\inv7\git-source-closure.json')
    }
    target = [PSCustomObject]@{ path = $testTarget; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef'; source_sha256 = $testCandidate; build_owner_mode = 'EXCLUSIVE_INTEGRATION_BUILD_OWNER' }
    output = [PSCustomObject]@{ root_path = $testOutputRoot; parent_path = 'C:\d32-diagnostic-policy-test\external'; parent_volume_serial_hex = '0123456789abcdef'; parent_file_id_hex = '0123456789abcdef0123456789abcdef'; temp_path = (Join-Path $testOutputRoot 'temp'); run_id = '5' * 32 }
    resource_budget = $budget
    source_pins = $testSourcePins
    image_grants = [PSCustomObject]@{ vctip = $null; protoc = $null }
    issued_at_utc = '2026-10-03T00:00:00.0000000+00:00'
}
$authorityValid = Test-D32BoundedCompilerDiagnosticAuthorityShape -Document $authority -ExpectedCandidateSha $testCandidate -Repository $testRepo `
    -ToolchainProfilePath $testProfilePath -ToolchainProfileSha256 ('2' * 64) -ModuleAuthorityPath $testModuleAuthorityPath `
    -ModuleAuthoritySha256 ('3' * 64) -PinnedGitPath $testGitPath -PinnedGitSha256 ('4' * 64) -ExpectedEnvironment $expectedEnvironment
Assert-D32BoundedCompilerDiagnosticSelfTest 'exact new authority shape accepted' $authorityValid
$authority.dependency_origin.historical_origin_candidate_sha = $testCandidate
Assert-D32BoundedCompilerDiagnosticSelfTest 'full diagnostic source origin rejects current-SHA rebinding of historical inv7 owner/blocked evidence' (-not (Test-D32BoundedCompilerDiagnosticAuthorityShape -Document $authority -ExpectedCandidateSha $testCandidate -Repository $testRepo `
    -ToolchainProfilePath $testProfilePath -ToolchainProfileSha256 ('2' * 64) -ModuleAuthorityPath $testModuleAuthorityPath `
    -ModuleAuthoritySha256 ('3' * 64) -PinnedGitPath $testGitPath -PinnedGitSha256 ('4' * 64) -ExpectedEnvironment $expectedEnvironment))
$authority.dependency_origin.historical_origin_candidate_sha = $script:D32BoundedDiagnosticHistoricalInv7CandidateSha
$authority.dependency_origin.git_content_refs[0].pack_bytes = 268435457L
Assert-D32BoundedCompilerDiagnosticSelfTest 'full diagnostic rejects caller-pinned Git pack sizes above the approved cap' (-not (Test-D32BoundedCompilerDiagnosticAuthorityShape -Document $authority -ExpectedCandidateSha $testCandidate -Repository $testRepo `
    -ToolchainProfilePath $testProfilePath -ToolchainProfileSha256 ('2' * 64) -ModuleAuthorityPath $testModuleAuthorityPath `
    -ModuleAuthoritySha256 ('3' * 64) -PinnedGitPath $testGitPath -PinnedGitSha256 ('4' * 64) -ExpectedEnvironment $expectedEnvironment))
$authority.dependency_origin.git_content_refs[0].pack_bytes = 4096L
$authority.dependency_origin.fetch_records = @()
$authority.dependency_origin.git_source_authority = $null
$authorityWithSourceEvidenceGap = Test-D32BoundedCompilerDiagnosticAuthorityShape -Document $authority -ExpectedCandidateSha $testCandidate -Repository $testRepo `
    -ToolchainProfilePath $testProfilePath -ToolchainProfileSha256 ('2' * 64) -ModuleAuthorityPath $testModuleAuthorityPath `
    -ModuleAuthoritySha256 ('3' * 64) -PinnedGitPath $testGitPath -PinnedGitSha256 ('4' * 64) -ExpectedEnvironment $expectedEnvironment
Assert-D32BoundedCompilerDiagnosticSelfTest 'missing prior fetch and locked-Git evidence can be represented without fabricated success records' $authorityWithSourceEvidenceGap
Assert-D32BoundedCompilerDiagnosticSelfTest 'missing prior fetch evidence is incomplete' (-not (Test-D32BoundedCompilerDiagnosticFetchEvidenceComplete $authority.dependency_origin.fetch_records))
$authority.dependency_origin.fetch_records = @($testFetchReferences[0], $testFetchReferences[1])
Assert-D32BoundedCompilerDiagnosticSelfTest 'partial prior fetch evidence is incomplete' (-not (Test-D32BoundedCompilerDiagnosticFetchEvidenceComplete $authority.dependency_origin.fetch_records))
$authority.dependency_origin.fetch_records = $testFetchReferences
Assert-D32BoundedCompilerDiagnosticSelfTest 'three exact prior fetch references are structurally complete' (Test-D32BoundedCompilerDiagnosticFetchEvidenceComplete $authority.dependency_origin.fetch_records)
$historicalReplay = [PSCustomObject]@{ HistoricalFetchCompletion = 'NOT_RETAINED'; HistoricalAttemptState = 'BLOCKED'; HistoricalGateAuthority = 'NONE' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'historical inv7 replay preserves missing-fetch and blocked/no-authority semantics' (Test-D32BoundedCompilerDiagnosticHistoricalReplay $historicalReplay)
$historicalReplay.HistoricalAttemptState = 'COMPLETED'
Assert-D32BoundedCompilerDiagnosticSelfTest 'historical attempt cannot be upgraded to successful discovery semantics' (-not (Test-D32BoundedCompilerDiagnosticHistoricalReplay $historicalReplay))
$historicalReplay.HistoricalAttemptState = 'BLOCKED'; $historicalReplay.HistoricalGateAuthority = 'PHASE0'
Assert-D32BoundedCompilerDiagnosticSelfTest 'historical blocked attempt cannot acquire gate authority' (-not (Test-D32BoundedCompilerDiagnosticHistoricalReplay $historicalReplay))
$authority.dependency_origin.fetch_records = @($testFetchReferences) + @($testFetchReferences[0])
$authorityWithExcessFetchRecords = Test-D32BoundedCompilerDiagnosticAuthorityShape -Document $authority -ExpectedCandidateSha $testCandidate -Repository $testRepo `
    -ToolchainProfilePath $testProfilePath -ToolchainProfileSha256 ('2' * 64) -ModuleAuthorityPath $testModuleAuthorityPath `
    -ModuleAuthoritySha256 ('3' * 64) -PinnedGitPath $testGitPath -PinnedGitSha256 ('4' * 64) -ExpectedEnvironment $expectedEnvironment
Assert-D32BoundedCompilerDiagnosticSelfTest 'more than three prior fetch records rejected' (-not $authorityWithExcessFetchRecords)
$authority.dependency_origin.git_source_authority = (New-D32BoundedCompilerDiagnosticTestReference 'E:\d32\inv7\git-source-closure.json')
$authority.dependency_origin.fetch_records = $testFetchReferences
$authority.dependency_origin.path = 'E:\d32\other-run\cargo-home'
Assert-D32BoundedCompilerDiagnosticSelfTest 'wrong Cargo-home source rejected' (-not (Test-D32BoundedCompilerDiagnosticAuthorityShape -Document $authority -ExpectedCandidateSha $testCandidate -Repository $testRepo -ToolchainProfilePath $testProfilePath -ToolchainProfileSha256 ('2' * 64) -ModuleAuthorityPath $testModuleAuthorityPath -ModuleAuthoritySha256 ('3' * 64) -PinnedGitPath $testGitPath -PinnedGitSha256 ('4' * 64) -ExpectedEnvironment $expectedEnvironment))
$authority.dependency_origin.path = 'E:\d32\inv7\r\c'
$authority.candidate_sha = '6' * 40
Assert-D32BoundedCompilerDiagnosticSelfTest 'stale candidate authority rejected' (-not (Test-D32BoundedCompilerDiagnosticAuthorityShape -Document $authority -ExpectedCandidateSha $testCandidate -Repository $testRepo -ToolchainProfilePath $testProfilePath -ToolchainProfileSha256 ('2' * 64) -ModuleAuthorityPath $testModuleAuthorityPath -ModuleAuthoritySha256 ('3' * 64) -PinnedGitPath $testGitPath -PinnedGitSha256 ('4' * 64) -ExpectedEnvironment $expectedEnvironment))
$authority.candidate_sha = $testCandidate
$authority.image_grants.vctip = [PSCustomObject]@{ path = 'C:\MSVC\vctip.exe'; bytes = 5; sha256 = 'not-a-pin'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'wrong VCTIP grant rejected' (-not (Test-D32BoundedCompilerDiagnosticAuthorityShape -Document $authority -ExpectedCandidateSha $testCandidate -Repository $testRepo -ToolchainProfilePath $testProfilePath -ToolchainProfileSha256 ('2' * 64) -ModuleAuthorityPath $testModuleAuthorityPath -ModuleAuthoritySha256 ('3' * 64) -PinnedGitPath $testGitPath -PinnedGitSha256 ('4' * 64) -ExpectedEnvironment $expectedEnvironment))
$authority.image_grants.vctip = $null
$authority.command.argv = @($fixedArgv) + @('--target-dir', 'C:\wrong-target')
Assert-D32BoundedCompilerDiagnosticSelfTest 'target override authority rejected' (-not (Test-D32BoundedCompilerDiagnosticAuthorityShape -Document $authority -ExpectedCandidateSha $testCandidate -Repository $testRepo -ToolchainProfilePath $testProfilePath -ToolchainProfileSha256 ('2' * 64) -ModuleAuthorityPath $testModuleAuthorityPath -ModuleAuthoritySha256 ('3' * 64) -PinnedGitPath $testGitPath -PinnedGitSha256 ('4' * 64) -ExpectedEnvironment $expectedEnvironment))

$cleanupGood = [PSCustomObject]@{ DebuggerThreadExited = $true; DebuggerThreadJoined = $true; RetainedProcessHandlesSignaled = $true; DebuggerAssociationQueryVerified = $true; DebuggerAssociationAbsent = $true; JobActiveProcessCountVerified = $true; JobActiveProcessCount = [uint32]0; JobCloseSucceeded = $true; CleanupSucceeded = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'fully verified cleanup accepted' (Test-D32BoundedCompilerDiagnosticCleanupVerified $cleanupGood)
$cleanupMissingJoin = [PSCustomObject]@{ DebuggerThreadExited = $true; DebuggerThreadJoined = $false; RetainedProcessHandlesSignaled = $true; DebuggerAssociationQueryVerified = $true; DebuggerAssociationAbsent = $true; JobActiveProcessCountVerified = $true; JobActiveProcessCount = [uint32]0; JobCloseSucceeded = $true; CleanupSucceeded = $false }
Assert-D32BoundedCompilerDiagnosticSelfTest 'missing debugger join rejected' (-not (Test-D32BoundedCompilerDiagnosticCleanupVerified $cleanupMissingJoin))
Assert-D32BoundedCompilerDiagnosticSelfTest 'no test executable launch accepted' (Test-D32BoundedCompilerDiagnosticTestBinaryNotStarted -CreatedProcessPaths @('E:\repo\vita-agent\target\debug\build-script.exe') -ExecutableArtifactPaths @('E:\repo\vita-agent\target\debug\deps\vita_agent-test.exe') -TargetRoot 'E:\repo\vita-agent\target')
Assert-D32BoundedCompilerDiagnosticSelfTest 'test executable launch rejected' (-not (Test-D32BoundedCompilerDiagnosticTestBinaryNotStarted -CreatedProcessPaths @('E:\repo\vita-agent\target\debug\deps\vita_agent-test.exe') -ExecutableArtifactPaths @('E:\repo\vita-agent\target\debug\deps\vita_agent-test.exe') -TargetRoot 'E:\repo\vita-agent\target'))
Assert-D32BoundedCompilerDiagnosticSelfTest 'any dependency executable launch rejected' (-not (Test-D32BoundedCompilerDiagnosticTestBinaryNotStarted -CreatedProcessPaths @('E:\repo\vita-agent\target\debug\deps\build_script_build.exe') -ExecutableArtifactPaths @('E:\repo\vita-agent\target\debug\deps\vita_agent-test.exe') -TargetRoot 'E:\repo\vita-agent\target'))

$sampleOne = [PSCustomObject]@{ available_physical_bytes = 8L; commit_headroom_bytes = 9L; commit_used_bytes = 10L; system_commit_peak_bytes = 11L; commit_limit_bytes = 12L; total_physical_bytes = 13L; stopwatch_ticks = 1000L; processes = @([PSCustomObject]@{ process_id = 44; creation_filetime = 444; image_path = 'E:\toolchain\rustc.exe'; user_time_100ns = 100; kernel_time_100ns = 50; memory_verified = $true; private_bytes = 2048L; working_set_bytes = 4096L }) }
$sampleTwo = [PSCustomObject]@{ available_physical_bytes = 7L; commit_headroom_bytes = 8L; commit_used_bytes = 11L; system_commit_peak_bytes = 12L; commit_limit_bytes = 13L; total_physical_bytes = 13L; stopwatch_ticks = 11000L; processes = @([PSCustomObject]@{ process_id = 44; creation_filetime = 444; image_path = 'E:\toolchain\rustc.exe'; user_time_100ns = 175; kernel_time_100ns = 80; memory_verified = $true; private_bytes = 3072L; working_set_bytes = 5120L }) }
$rustcRecords = @(
    [PSCustomObject]@{ ProcessId = 44; CreationFileTime = 444; ParentProcessId = 31; ParentCreationFileTime = 313; ImagePath = 'E:\toolchain\rustc.exe' },
    [PSCustomObject]@{ ProcessId = 45; CreationFileTime = 455; ParentProcessId = 31; ParentCreationFileTime = 313; ImagePath = 'E:\toolchain\rustc.exe' })
$samplingProjection = Get-D32BoundedCompilerDiagnosticSamplingSummary -Samples @($sampleOne, $sampleTwo) -RustcRecords $rustcRecords -StopwatchFrequency 1000 -Complete $true -StopReason 'TRACE_COMPLETED'
Assert-D32BoundedCompilerDiagnosticSelfTest 'raw sample projection binds by PID and creation identity and reports observed maxima/deltas' ($samplingProjection.rustc_processes[0].sampled -and $samplingProjection.rustc_processes[0].sampled_count -eq 2 -and $samplingProjection.rustc_processes[0].observed_private_peak_bytes -eq 3072 -and $samplingProjection.rustc_processes[0].sampled_user_cpu_delta_100ns -eq 75 -and $samplingProjection.private_peak_label -like '*not a lifetime peak*')
Assert-D32BoundedCompilerDiagnosticSelfTest 'unobserved rustc remains explicitly unsampled and un-attributed' (-not $samplingProjection.rustc_processes[1].sampled -and $null -eq $samplingProjection.rustc_processes[1].observed_private_peak_bytes -and $null -eq $samplingProjection.rustc_processes[1].sampled_user_cpu_delta_100ns -and -not $samplingProjection.rustc_processes_all_sampled)
$sampleWrongCreation = [PSCustomObject]@{ available_physical_bytes = 7L; commit_headroom_bytes = 8L; commit_used_bytes = 11L; system_commit_peak_bytes = 12L; commit_limit_bytes = 13L; total_physical_bytes = 13L; stopwatch_ticks = 11000L; processes = @([PSCustomObject]@{ process_id = 44; creation_filetime = 999; image_path = 'E:\toolchain\rustc.exe'; user_time_100ns = 180; kernel_time_100ns = 82; memory_verified = $true; private_bytes = 4096L; working_set_bytes = 6144L }) }
$wrongCreationProjection = Get-D32BoundedCompilerDiagnosticSamplingSummary -Samples @($sampleWrongCreation) -RustcRecords @($rustcRecords[0]) -StopwatchFrequency 1000 -Complete $false -StopReason 'UNRELIABLE'
Assert-D32BoundedCompilerDiagnosticSelfTest 'PID reuse with a different creation time is not attributed to prior rustc identity' (-not $wrongCreationProjection.rustc_processes[0].sampled -and $null -eq $wrongCreationProjection.rustc_processes[0].observed_private_peak_bytes)

$diagnosticRecord = [PSCustomObject]@{ schema_version = 3; record_type = $script:D32BoundedCompilerDiagnosticResultType; registry_archive_policy = $script:D32BoundedDiagnosticRegistryArchivePolicy; gate_authority = 'NONE'; status = 'COMPLETED_DIAGNOSTIC' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'diagnostic result rejected by formal record gate' (Test-D32BoundedCompilerDiagnosticFormalReject $diagnosticRecord)
$formalRecord = [PSCustomObject]@{ record_type = 'D32_PHASE0_MATRIX_RECORD_V8'; gate_authority = 'PHASE0'; status = 'PASS' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'formal Phase0 record remains outside diagnostic reject helper' (-not (Test-D32BoundedCompilerDiagnosticFormalReject $formalRecord))
$sourceProofRecord = [PSCustomObject]@{ record_type = $script:D32BoundedDiagnosticSourceProofCandidateType; gate_authority = 'NONE'; status = 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof candidate is rejected by the formal Phase0 record gate' (Test-D32BoundedCompilerDiagnosticFormalReject $sourceProofRecord)

$sourceProofEntryPath = Join-Path $testRepo 'scripts\d32-bounded-diagnostic-sourceproof.ps1'
$sourceProofRunnerPath = Join-Path $testRepo 'scripts\d32-bounded-compiler-diagnostic.ps1'
$sourceProofProfilePath = 'C:\d32-diagnostic-policy-test\profile.json'
$sourceProofCurrentSha = '1' * 40
$sourceProofPins = @(
    (New-D32BoundedCompilerDiagnosticTestReference $sourceProofEntryPath),
    (New-D32BoundedCompilerDiagnosticTestReference $sourceProofRunnerPath),
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'scripts\d32-bounded-compiler-diagnostic-policy.ps1')),
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'scripts\d32-build-toolchain-profile.ps1')),
    (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'scripts\d32-powershell-module-authority.ps1')))
$sourceProofOrigin = [PSCustomObject][ordered]@{
    path = 'E:\d32\inv7\r\c'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef'
    owner_record = New-D32BoundedCompilerDiagnosticTestReference 'E:\d32\inv7\D32-PHASE0-OWNER.json'
    blocked_diagnostic = New-D32BoundedCompilerDiagnosticTestReference 'E:\d32\inv7\D32-PHASE0-BLOCKED-DIAGNOSTIC.json'
    fetch_records = @()
    manifest_refs = $testManifestReferences
    registry_archive_root = [PSCustomObject]@{ path = 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
    registry_source_root = [PSCustomObject]@{ path = 'E:\d32\inv7\r\c\registry\src\index.crates.io-1949cf8c6b5b557f'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
    git_database_root = [PSCustomObject]@{ path = 'E:\d32\inv7\r\c\git\db'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
    git_checkout_root = [PSCustomObject]@{ path = 'E:\d32\inv7\r\c\git\checkouts'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
    git_content_refs = @($testGitContentReference)
    registry_archives = @([PSCustomObject]@{
        source = 'registry+https://github.com/rust-lang/crates.io-index'; name = 'sample-crate'; version = '1.2.3'
        checksum = 'a' * 64; path = 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f\sample-crate-1.2.3.crate'
        bytes = 1024L; sha256 = 'a' * 64; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef'
    })
}
$sourceProofAuthority = [PSCustomObject][ordered]@{
    schema_version = 3
    record_type = $script:D32BoundedDiagnosticSourceProofAuthorityType
    registry_archive_policy = $script:D32BoundedDiagnosticRegistryArchivePolicy
    gate_authority = 'NONE'
    candidate_sha = $sourceProofCurrentSha
    historical_origin_candidate_sha = $script:D32BoundedDiagnosticHistoricalInv7CandidateSha
    source_repo = $testRepo
    repository_identity = [PSCustomObject]@{ volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
    toolchain_profile = New-D32BoundedCompilerDiagnosticTestReference $sourceProofProfilePath
    source_pins = $sourceProofPins
    dependency_origin = $sourceProofOrigin
    proof_budget = [PSCustomObject][ordered]@{
        combined_milliseconds = 300000L; managed_buffer_bytes = 536870912L; max_registry_archive_bytes = 268435456L
        max_git_pack_bytes = 268435456L; max_git_index_bytes = 67108864L; max_git_object_bytes = 67108864L
        max_git_object_count = 500000L; max_git_delta_depth = 32L; max_git_expanded_bytes = 34359738368L
        max_manifest_or_lock_file_bytes = 16777216L
    }
    output_candidate = [PSCustomObject]@{
        path = 'C:\d32-diagnostic-policy-test\external\source-proof-candidate.json'
        parent_path = 'C:\d32-diagnostic-policy-test\external'
        parent_volume_serial_hex = '0123456789abcdef'; parent_file_id_hex = '0123456789abcdef0123456789abcdef'
    }
    run_id = '7' * 32
    issued_at_utc = '2026-10-04T00:00:00.0000000+00:00'
}
$sourceProofAuthorityValid = Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha `
    -Repository $testRepo -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath `
    -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64)
Assert-D32BoundedCompilerDiagnosticSelfTest 'separate exact current source-proof authority shape accepted with historical inv7 SHA kept distinct' $sourceProofAuthorityValid

$moduleAuthorityPath = Join-Path $PSScriptRoot 'd32-powershell-module-authority.ps1'
$moduleAuthorityTokens = $null; $moduleAuthorityParseErrors = $null
$moduleAuthorityAst = [System.Management.Automation.Language.Parser]::ParseFile($moduleAuthorityPath, [ref]$moduleAuthorityTokens, [ref]$moduleAuthorityParseErrors)
$authorityDecoderAsts = @($moduleAuthorityAst.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'ConvertFrom-D32PowerShellAuthorityJsonElement'
}, $true))
$authorityShapeDecoderAsts = @($moduleAuthorityAst.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'ConvertFrom-D32PowerShellAuthorityJsonShapeElement'
}, $true))
$authorityShapeCopyAst = $moduleAuthorityAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Copy-D32PowerShellAuthorityJsonShape'
}, $true)
$authoritySerializerAst = $moduleAuthorityAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'ConvertTo-D32PowerShellAuthorityJsonText'
}, $true)
$authorityDuplicateCheckerAst = $moduleAuthorityAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32PowerShellAuthorityJsonDuplicates'
}, $true)
$authorityDecoderAstContract = $moduleAuthorityParseErrors.Count -eq 0 -and $authorityDecoderAsts.Count -eq 1 -and
    $authorityShapeDecoderAsts.Count -eq 1 -and $null -ne $authorityShapeCopyAst -and $null -ne $authoritySerializerAst -and
    $null -ne $authorityDuplicateCheckerAst -and
    $authorityShapeCopyAst.Extent.Text.Contains('ConvertFrom-D32PowerShellAuthorityJsonShapeElement') -and
    -not $authorityShapeCopyAst.Extent.Text.Contains('ConvertFrom-D32PowerShellAuthorityJsonElement')
Assert-D32BoundedCompilerDiagnosticSelfTest 'canonical authority decoder is not overwritten by the separate ordered-dictionary SelfTest shape decoder' $authorityDecoderAstContract

# Evaluate only the pure JSON conversion and duplicate-check functions extracted from their
# ASTs. This exercises the implementation without dot-sourcing the authority
# module or invoking any file/native/process helpers.
Invoke-Expression $authoritySerializerAst.Extent.Text
Invoke-Expression $authorityDecoderAsts[0].Extent.Text
Invoke-Expression $authorityShapeDecoderAsts[0].Extent.Text
Invoke-Expression $authorityShapeCopyAst.Extent.Text
Invoke-Expression $authorityDuplicateCheckerAst.Extent.Text
$longNameProofPackageInput = [PSCustomObject][ordered]@{
    package_id = 'longname-layout@1.0.0|registry|registry+https://github.com/rust-lang/crates.io-index'
    name = 'longname-layout'; version = '1.0.0'; checksum = $longNameArchiveSha
}
$longNameProofArchiveReference = [PSCustomObject][ordered]@{
    path = 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f\longname-layout-1.0.0.crate'
    bytes = [Int64]$longNameArchive.Length; sha256 = $longNameArchiveSha
    volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef'
}
$longNameProofSourceProjection = [PSCustomObject][ordered]@{
    source_root = 'E:\d32\inv7\r\c\registry\src\index.crates.io-1949cf8c6b5b557f\longname-layout-1.0.0'
    source_root_volume_serial_hex = '0123456789abcdef'; source_root_file_id_hex = '0123456789abcdef0123456789abcdef'
    archived_file_count = 7L; archived_directory_count = 2L; generated_metadata_count = 0L
    observed_source_bytes = 512L; source_inventory_sha256 = 'f' * 64
}
$longNameProofPackage = New-D32BoundedDiagnosticRegistrySourceProofPackage -Package $longNameProofPackageInput `
    -ArchiveReference $longNameProofArchiveReference -Inventory $longNameInventory -SourceProof $longNameProofSourceProjection
$longNameProof = New-D32BoundedDiagnosticRegistrySourceContentProofDocument -Packages @($longNameProofPackage) `
    -LockSha256 ('1' * 64) -RegistryTupleSha256 ('2' * 64) -LockedRegistryCatalogCount 1L `
    -CompressedBytes ([Int64]$longNameArchive.Length) -ExpandedBytes ([Int64]$longNameInventory.expanded_bytes) `
    -MemberCount ([Int64]$longNameInventory.entries.Count) -ElapsedMilliseconds 100L
$longNameProofReadback = Copy-D32BoundedCompilerDiagnosticTestJson -Record $longNameProof
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof producer projection binds real synthetic L parser inventory through V4 proof builder, strict consumer, and JSON readback' `
    ((Test-D32BoundedDiagnosticRegistrySourceContentProof -Proof $longNameProofReadback) -and
     $longNameProofReadback.packages[0].header_count -eq $longNameInventory.header_inventory.Count -and
     $longNameProofReadback.packages[0].ordinary_header_count -eq $longNameInventory.ordinary_header_count -and
     $longNameProofReadback.packages[0].longname_pair_count -eq $longNameInventory.longname_pair_count -and
     $longNameProofReadback.packages[0].longname_control_metadata_bytes -eq $longNameInventory.longname_control_metadata_bytes -and
     $longNameProofReadback.packages[0].format_counts.gnu_longname_extension -eq 9 -and
     $longNameProofReadback.packages[0].source_inventory_sha256 -ceq $longNameProofSourceProjection.source_inventory_sha256)
$longNameProofMutation = Copy-D32BoundedCompilerDiagnosticTestJson -Record $longNameProofReadback
$longNameProofMutation.packages[0].longname_control_metadata_bytes =
    [Int64]$longNameProofMutation.packages[0].longname_control_metadata_count * 4097L + 1L
$longNameProofMutation.source_proof_sha256 = Get-D32BoundedDiagnosticRegistrySourceProofDigest -Packages @($longNameProofMutation.packages)
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof V4 rejects an over-budget control-metadata byte sum even when the package proof digest is recomputed' `
    (-not (Test-D32BoundedDiagnosticRegistrySourceContentProof -Proof $longNameProofMutation))
$longNamePairCountMutation = Copy-D32BoundedCompilerDiagnosticTestJson -Record $longNameProofReadback
$longNamePairCountMutation.packages[0].longname_pair_count -= 1L
$longNamePairCountMutation.source_proof_sha256 = Get-D32BoundedDiagnosticRegistrySourceProofDigest -Packages @($longNamePairCountMutation.packages)
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof V4 rejects a longname pair-count substitution even after recomputing the enclosing proof digest' `
    (-not (Test-D32BoundedDiagnosticRegistrySourceContentProof -Proof $longNamePairCountMutation))
$sourceProofRoundTripJson = ConvertTo-D32PowerShellAuthorityJsonText -Value $sourceProofAuthority
$sourceProofRoundTripDocument = [System.Text.Json.JsonDocument]::Parse($sourceProofRoundTripJson)
try { $sourceProofRoundTrip = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $sourceProofRoundTripDocument.RootElement }
finally { $sourceProofRoundTripDocument.Dispose() }
$sourceProofRoundTripValid = Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofRoundTrip `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha `
    -Repository $testRepo -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath `
    -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64)
Assert-D32BoundedCompilerDiagnosticSelfTest 'serialized source-proof authority JSON roundtrip remains valid with distinct current and historical SHA pins' $sourceProofRoundTripValid
$sourceProofRoundTripCollectionsExact = $sourceProofRoundTrip -is [PSCustomObject] -and
    $sourceProofRoundTrip.source_pins -is [Array] -and $sourceProofRoundTrip.source_pins.Count -eq 5 -and
    $sourceProofRoundTrip.source_pins[0] -is [PSCustomObject] -and
    $sourceProofRoundTrip.dependency_origin.manifest_refs -is [Array] -and $sourceProofRoundTrip.dependency_origin.manifest_refs.Count -eq 6 -and
    $sourceProofRoundTrip.dependency_origin.fetch_records -is [Array] -and $sourceProofRoundTrip.dependency_origin.fetch_records.Count -eq 0 -and
    [string]$sourceProofRoundTrip.candidate_sha -ceq $sourceProofCurrentSha -and
    [string]$sourceProofRoundTrip.historical_origin_candidate_sha -ceq $script:D32BoundedDiagnosticHistoricalInv7CandidateSha
Assert-D32BoundedCompilerDiagnosticSelfTest 'JSON conversion preserves nested PSCustomObjects and empty/singleton-capable collection wire types' $sourceProofRoundTripCollectionsExact
$sourceProofShapeCopy = Copy-D32PowerShellAuthorityJsonShape -Value $sourceProofAuthority
$sourceProofShapeCopyCollectionsExact = $sourceProofShapeCopy -is [System.Collections.IDictionary] -and
    $sourceProofShapeCopy.source_pins -is [Array] -and $sourceProofShapeCopy.source_pins.Count -eq 5 -and
    $sourceProofShapeCopy.source_pins[0] -is [System.Collections.IDictionary] -and
    $sourceProofShapeCopy.dependency_origin.manifest_refs -is [Array] -and $sourceProofShapeCopy.dependency_origin.fetch_records -is [Array] -and
    $sourceProofShapeCopy.dependency_origin.fetch_records.Count -eq 0
Assert-D32BoundedCompilerDiagnosticSelfTest 'SelfTest JSON shape copy keeps ordered-dictionary records distinct while preserving nested arrays' $sourceProofShapeCopyCollectionsExact
Assert-D32BoundedCompilerDiagnosticSelfTest 'strict source-proof authority consumer fails closed for dictionary representations rather than mistaking adapter properties for JSON fields' (-not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofShapeCopy `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha `
    -Repository $testRepo -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath `
    -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64)))

$sourceProofMissingTopValue = $sourceProofAuthority.run_id
$sourceProofAuthority.PSObject.Properties.Remove('run_id')
$sourceProofMissingTopRejected = -not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha `
    -Repository $testRepo -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath `
    -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64))
$sourceProofAuthority | Add-Member -NotePropertyName run_id -NotePropertyValue $sourceProofMissingTopValue
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof authority rejects a missing exact top-level field' $sourceProofMissingTopRejected
$sourceProofAuthority | Add-Member -NotePropertyName unexpected_field -NotePropertyValue 'extra'
$sourceProofExtraTopRejected = -not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha `
    -Repository $testRepo -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath `
    -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64))
$sourceProofAuthority.PSObject.Properties.Remove('unexpected_field')
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof authority rejects an extra exact top-level field' $sourceProofExtraTopRejected
$sourceProofPin = $sourceProofAuthority.source_pins[0]
$sourceProofPinFileId = [string]$sourceProofPin.file_id_hex
$sourceProofPin.PSObject.Properties.Remove('file_id_hex')
$sourceProofMissingPinFieldRejected = -not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha `
    -Repository $testRepo -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath `
    -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64))
$sourceProofPin | Add-Member -NotePropertyName file_id_hex -NotePropertyValue $sourceProofPinFileId
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof authority rejects a missing nested source-pin field' $sourceProofMissingPinFieldRejected
$sourceProofPin | Add-Member -NotePropertyName unexpected_field -NotePropertyValue 'extra'
$sourceProofExtraPinFieldRejected = -not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha `
    -Repository $testRepo -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath `
    -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64))
$sourceProofPin.PSObject.Properties.Remove('unexpected_field')
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof authority rejects an extra nested source-pin field' $sourceProofExtraPinFieldRejected
$sourceProofPinsOriginal = $sourceProofAuthority.source_pins
$sourceProofAuthority.source_pins = $sourceProofAuthority.source_pins[0]
$sourceProofNestedCollectionRejected = -not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha `
    -Repository $testRepo -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath `
    -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64))
$sourceProofAuthority.source_pins = $sourceProofPinsOriginal
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof authority rejects a record where the finite source-pin collection is not an array' $sourceProofNestedCollectionRejected

$sourceProofAuthority.historical_origin_candidate_sha = $sourceProofCurrentSha
Assert-D32BoundedCompilerDiagnosticSelfTest 'cross-run current/historical SHA rebinding rejected by source-proof authority' (-not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $sourceProofCurrentSha -Repository $testRepo `
    -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64)))
$sourceProofAuthority.historical_origin_candidate_sha = $script:D32BoundedDiagnosticHistoricalInv7CandidateSha
$sourceProofAuthority.candidate_sha = '6' * 40
Assert-D32BoundedCompilerDiagnosticSelfTest 'stale current candidate SHA rejected while historical SHA stays immutable' (-not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -Repository $testRepo `
    -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64)))
$sourceProofAuthority.candidate_sha = $sourceProofCurrentSha
$sourceProofAuthority.historical_origin_candidate_sha = '3' * 40
Assert-D32BoundedCompilerDiagnosticSelfTest 'wrong historical origin SHA rejected' (-not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha ('3' * 40) -Repository $testRepo `
    -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64)))
$sourceProofAuthority.historical_origin_candidate_sha = $script:D32BoundedDiagnosticHistoricalInv7CandidateSha
$sourceProofAuthority.dependency_origin | Add-Member -NotePropertyName protoc_run_grant -NotePropertyValue $testGrantReference
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof-only authority rejects old grant authority fields' (-not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -Repository $testRepo `
    -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64)))
$sourceProofAuthority.dependency_origin.PSObject.Properties.Remove('protoc_run_grant')
$sourceProofAuthority.dependency_origin.git_content_refs[0].index_bytes = 67108865L
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof-only authority rejects oversized caller-pinned Git index' (-not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -Repository $testRepo `
    -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64)))
$sourceProofAuthority.dependency_origin.git_content_refs[0].index_bytes = 256L
$sourceProofAuthority.proof_budget.combined_milliseconds = 300001L
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof timer extension rejected' (-not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -Repository $testRepo `
    -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64)))
$sourceProofAuthority.proof_budget.combined_milliseconds = 300000L
$sourceProofAuthority.dependency_origin.owner_record = $testBlockedReference
Assert-D32BoundedCompilerDiagnosticSelfTest 'swapped historical owner/blocked source reference rejected' (-not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -Repository $testRepo `
    -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64)))
$sourceProofAuthority.dependency_origin.owner_record = New-D32BoundedCompilerDiagnosticTestReference 'E:\d32\inv7\D32-PHASE0-OWNER.json'
$sourceProofAuthority.output_candidate.path = 'E:\d32\inv7\r\c\source-proof-candidate.json'
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof output overlapping the historical CargoHome rejected' (-not (Test-D32BoundedDiagnosticSourceProofAuthorityShape -Document $sourceProofAuthority `
    -ExpectedCandidateSha $sourceProofCurrentSha -ExpectedHistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha -Repository $testRepo `
    -EntryScriptPath $sourceProofEntryPath -RunnerPath $sourceProofRunnerPath -ToolchainProfilePath $sourceProofProfilePath -ToolchainProfileSha256 ('a' * 64)))

$sourceProofEntryPathReal = Join-Path $PSScriptRoot 'd32-bounded-diagnostic-sourceproof.ps1'
$sourceProofRunnerPathReal = Join-Path $PSScriptRoot 'd32-bounded-compiler-diagnostic.ps1'
$sourceProofEntryTokens = $null; $sourceProofEntryParseErrors = $null
$sourceProofEntryAst = [System.Management.Automation.Language.Parser]::ParseFile($sourceProofEntryPathReal, [ref]$sourceProofEntryTokens, [ref]$sourceProofEntryParseErrors)
$sourceProofEntryText = [string]$sourceProofEntryAst.Extent.Text
$sourceProofExpectedParameters = @('Repository', 'CandidateSha', 'HistoricalOriginCandidateSha', 'ToolchainProfilePath',
    'ExpectedToolchainProfileSha256', 'SourceProofAuthorityPath', 'ExpectedSourceProofAuthoritySha256', 'ExecutionAuthorityPath',
    'ExpectedExecutionAuthoritySha256', 'LifecycleT0Ticks', 'LifecycleCounterFrequency', 'LifecycleWorkDeadlineTicks', 'LifecycleProofExpiryTicks',
    'NonSourceL1', 'L1AuthorityPath', 'ExpectedL1AuthoritySha256', 'L1CandidateSha', 'L1BatchId', 'L1CaseId', 'L1Nonce', 'L1T0Ticks', 'L1CounterFrequency', 'L1CaseT0Ticks', 'L1ActiveDeadlineTicks')
$sourceProofActualParameters = @($sourceProofEntryAst.ParamBlock.Parameters | ForEach-Object { [string]$_.Name.VariablePath.UserPath })
$sourceProofEntryParametersExact = $sourceProofEntryAst.ParamBlock.Parameters.Count -eq $sourceProofExpectedParameters.Count
for ($parameterIndex = 0; $parameterIndex -lt $sourceProofExpectedParameters.Count -and $sourceProofEntryParametersExact; $parameterIndex++) {
    $parameter = $sourceProofEntryAst.ParamBlock.Parameters[$parameterIndex]
    $parameterType = [string]$parameter.StaticType.Name
    $mandatoryAttribute = @($parameter.Attributes | Where-Object {
        $_ -is [System.Management.Automation.Language.AttributeAst] -and $_.TypeName.FullName -ceq 'Parameter' -and
        @($_.NamedArguments | Where-Object { $_.ArgumentName -ceq 'Mandatory' -and $_.Argument.Extent.Text -ceq '$true' }).Count -eq 1
    }).Count -eq 1
    $expectedParameterType = switch ($sourceProofExpectedParameters[$parameterIndex]) {
        { $_ -in @('Repository', 'CandidateSha', 'HistoricalOriginCandidateSha', 'ToolchainProfilePath', 'ExpectedToolchainProfileSha256', 'SourceProofAuthorityPath', 'ExpectedSourceProofAuthoritySha256', 'ExecutionAuthorityPath', 'ExpectedExecutionAuthoritySha256', 'L1AuthorityPath', 'ExpectedL1AuthoritySha256', 'L1CandidateSha', 'L1BatchId', 'L1CaseId', 'L1Nonce') } { 'String' }
        'NonSourceL1' { 'SwitchParameter' }
        default { 'Int64' }
    }
    $expectedSet = if ($parameterIndex -lt 13) { 'SourceProofOnly' } else { 'NonSourceL1' }
    if ($sourceProofActualParameters[$parameterIndex] -cne $sourceProofExpectedParameters[$parameterIndex] -or
        $parameterType -cne $expectedParameterType -or -not $mandatoryAttribute -or
        @($parameter.Attributes | Where-Object { $_ -is [System.Management.Automation.Language.AttributeAst] -and $_.TypeName.FullName -ceq 'Parameter' -and
            @($_.NamedArguments | Where-Object { $_.ArgumentName -ceq 'ParameterSetName' -and $_.Argument.Extent.Text -ceq ("'" + $expectedSet + "'") }).Count -eq 1 }).Count -ne 1) { $sourceProofEntryParametersExact = $false }
}
$sourceProofInvocationCommands = @($sourceProofEntryAst.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and $node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Ampersand
}, $true))
$sourceProofExpectedInvocationElements = @('$runnerPath', '-SourceProofOnly', '-Repository', '$Repository', '-CandidateSha', '$CandidateSha',
    '-HistoricalOriginCandidateSha', '$HistoricalOriginCandidateSha', '-ToolchainProfilePath', '$ToolchainProfilePath',
    '-ExpectedToolchainProfileSha256', '$ExpectedToolchainProfileSha256', '-SourceProofEntryPath', '$PSCommandPath',
    '-SourceProofAuthorityPath', '$SourceProofAuthorityPath', '-ExpectedSourceProofAuthoritySha256', '$ExpectedSourceProofAuthoritySha256',
    '-ExecutionAuthorityPath', '$ExecutionAuthorityPath', '-ExpectedExecutionAuthoritySha256', '$ExpectedExecutionAuthoritySha256',
    '-LifecycleT0Ticks', '$LifecycleT0Ticks', '-LifecycleCounterFrequency', '$LifecycleCounterFrequency',
    '-LifecycleWorkDeadlineTicks', '$LifecycleWorkDeadlineTicks', '-LifecycleProofExpiryTicks', '$LifecycleProofExpiryTicks')
$sourceProofInvocationExact = $sourceProofInvocationCommands.Count -eq 1
$sourceProofInvocationElements = @()
if ($sourceProofInvocationExact) {
    $sourceProofInvocationElements = @($sourceProofInvocationCommands[0].CommandElements | ForEach-Object { [string]$_.Extent.Text })
    $sourceProofInvocationExact = $sourceProofInvocationElements.Count -eq $sourceProofExpectedInvocationElements.Count
    for ($elementIndex = 0; $elementIndex -lt $sourceProofExpectedInvocationElements.Count -and $sourceProofInvocationExact; $elementIndex++) {
        if ($sourceProofInvocationElements[$elementIndex] -cne $sourceProofExpectedInvocationElements[$elementIndex]) { $sourceProofInvocationExact = $false }
    }
}
$sourceProofForbiddenEntryCommands = @($sourceProofEntryAst.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
    ([string]$node.GetCommandName() -match '^(?i:Start-Process|Start-Job|Invoke-Expression|Import-Module|Get-CimInstance|cargo|git|rustc)$')
}, $true))
$nonSourceL1BranchIndex = $sourceProofEntryText.IndexOf("if (`$PSCmdlet.ParameterSetName -ceq 'NonSourceL1')", [StringComparison]::Ordinal)
$sourceProofClockCheckIndex = $sourceProofEntryText.IndexOf('$lifecycleNowTicks =', [StringComparison]::Ordinal)
$sourceProofRunnerJoinIndex = $sourceProofEntryText.IndexOf("Join-Path `$PSScriptRoot 'd32-bounded-compiler-diagnostic.ps1'", [StringComparison]::Ordinal)
$nonSourceL1BranchTerminal = $nonSourceL1BranchIndex -ge 0 -and $nonSourceL1BranchIndex -lt $sourceProofClockCheckIndex -and
    $nonSourceL1BranchIndex -lt $sourceProofRunnerJoinIndex -and
    $sourceProofEntryText.Substring($nonSourceL1BranchIndex, $sourceProofClockCheckIndex - $nonSourceL1BranchIndex).Contains('exit 0') -and
    $sourceProofEntryText.Contains('NATIVE_LIFECYCLE_VALIDATION_ONLY') -and
    -not $sourceProofEntryText.Substring($nonSourceL1BranchIndex, $sourceProofClockCheckIndex - $nonSourceL1BranchIndex).Contains('SourceProofAuthorityPath')
$nonSourceL1BranchText = if ($nonSourceL1BranchIndex -ge 0 -and $sourceProofClockCheckIndex -gt $nonSourceL1BranchIndex) {
    $sourceProofEntryText.Substring($nonSourceL1BranchIndex, $sourceProofClockCheckIndex - $nonSourceL1BranchIndex)
} else { '' }
$nonSourceL1BranchNoSourceInputs = -not $nonSourceL1BranchText.Contains('ToolchainProfilePath') -and
    -not $nonSourceL1BranchText.Contains('HistoricalOriginCandidateSha') -and
    -not $nonSourceL1BranchText.Contains('Assert-D32BoundedDiagnosticInv7Origin') -and
    -not $nonSourceL1BranchText.Contains('Invoke-D32BoundedDiagnosticSourceProofRun')
$sourceProofEntrySafetyExact = $sourceProofEntryParametersExact -and $sourceProofInvocationExact -and
    $sourceProofForbiddenEntryCommands.Count -eq 0 -and -not $sourceProofEntryText.Contains('. $runnerPath') -and
    $nonSourceL1BranchTerminal -and $nonSourceL1BranchNoSourceInputs
$sourceProofRunnerAst = $runnerAst
$sourceProofInvokerAst = $sourceProofRunnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-D32BoundedDiagnosticSourceProofRun' }, $true)
$sourceProofInvokerText = if ($null -eq $sourceProofInvokerAst) { '' } else { [string]$sourceProofInvokerAst.Extent.Text }
$sourceProofResultWriterAst = $sourceProofRunnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Write-D32BoundedDiagnosticCreateNewJson' }, $true)
$sourceProofResultWriterText = if ($null -eq $sourceProofResultWriterAst) { '' } else { [string]$sourceProofResultWriterAst.Extent.Text }
$sourceProofResultWriterDeadlineExact = $null -ne $sourceProofResultWriterAst -and
    $sourceProofResultWriterText.Contains("Phase 'result.write'") -and
    $sourceProofResultWriterText.Contains("Phase 'result.write_complete'") -and
    $sourceProofResultWriterText.Contains("Phase 'result.flush_complete'") -and
    $sourceProofResultWriterText.Contains('MaximumBytes') -and $sourceProofResultWriterText.Contains('CreateNew')
Assert-D32BoundedCompilerDiagnosticSelfTest 'create-new proof-result persistence remains byte-capped and checks the single combined deadline before and after writes and flush' $sourceProofResultWriterDeadlineExact
$sourceProofDeadlinePartitionExact = $sourceProofInvokerText.Contains('$resultValidationDeadlineMilliseconds = [Int64]$workDeadlineMilliseconds') -and
    $sourceProofInvokerText.Contains('$blockedFallbackValidationDeadlineMilliseconds = [Int64]($script:D32BoundedDiagnosticSourceProofCombinedMilliseconds - 15000L)') -and
    $sourceProofInvokerText.Contains('-DeadlineMilliseconds $blockedFallbackValidationDeadlineMilliseconds') -and
    -not $sourceProofInvokerText.Contains('-DeadlineMilliseconds $script:D32BoundedDiagnosticSourceProofCombinedMilliseconds))')
Assert-D32BoundedCompilerDiagnosticSelfTest 'source proof result validation and blocked fallback leave the fixed final persistence interval inside the unchanged combined deadline' $sourceProofDeadlinePartitionExact
$sourceOriginAst = $runnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-D32BoundedDiagnosticInv7Origin' }, $true)
$sourceOriginText = if ($null -eq $sourceOriginAst) { '' } else { [string]$sourceOriginAst.Extent.Text }
$sourceProofBootstrapAst = $runnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-D32BoundedDiagnosticSourceProofBootstrap' }, $true)
$sourceProofBootstrapText = if ($null -eq $sourceProofBootstrapAst) { '' } else { [string]$sourceProofBootstrapAst.Extent.Text }
$sourceProofBootstrapConsumerExact = $null -ne $sourceProofBootstrapAst -and
    $sourceProofBootstrapText.Contains('ConvertFrom-D32PowerShellAuthorityJsonElement') -and
    $sourceProofBootstrapText.Contains("@('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')") -and
    $sourceProofBootstrapText.Contains('$reference.PSObject.Properties') -and
    $sourceProofBootstrapText.Contains('$bootstrap.candidate_sha -cne $CandidateSha') -and
    $sourceProofBootstrapText.Contains('$bootstrap.historical_origin_candidate_sha -cne $HistoricalOriginCandidateSha')
Assert-D32BoundedCompilerDiagnosticSelfTest 'proof-only bootstrap consumer retains exact pin fields and dual current/historical SHA binding' $sourceProofBootstrapConsumerExact
$diagnosticResultAst = $runnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'New-D32BoundedDiagnosticResult' }, $true)
$diagnosticResultText = if ($null -eq $diagnosticResultAst) { '' } else { [string]$diagnosticResultAst.Extent.Text }
$diagnosticOriginInvocations = @($runnerAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and [string]$node.GetCommandName() -ceq 'Assert-D32BoundedDiagnosticInv7Origin' }, $true))
$currentHistoricalCrossBindingExact = $sourceOriginText.Contains('[string]$CurrentCandidateSha') -and
    $sourceOriginText.Contains('$HistoricalOriginCandidateSha -ceq $CurrentCandidateSha') -and
    $sourceProofInvokerText.Contains('-CurrentCandidateSha $CandidateSha') -and
    $diagnosticOriginInvocations.Count -eq 2 -and
    $diagnosticResultText.Contains('$SourceClosure.CurrentCandidateSha -cne $CandidateSha') -and
    $diagnosticResultText.Contains('$SourceClosure.HistoricalOriginCandidateSha -cne $script:D32BoundedDiagnosticHistoricalOriginCandidateSha')
Assert-D32BoundedCompilerDiagnosticSelfTest 'both diagnostic and proof-only origin readers require explicit current SHA; diagnostic result writer rechecks current/historical cross-binding' $currentHistoricalCrossBindingExact
$sourceProofDispatchExact = $runnerParseErrors.Count -eq 0 -and $sourceProofEntryParseErrors.Count -eq 0 -and
    $sourceProofEntryText.Contains('-SourceProofOnly') -and $sourceProofEntryText.Contains('& $runnerPath') -and
    -not $sourceProofEntryText.Contains('. $runnerPath') -and $null -ne $sourceProofInvokerAst -and
    $runnerAst.Extent.Text.Contains('$script:D32BoundedDiagnosticSourceProofWallTimer = if ($SourceProofOnly) { [Diagnostics.Stopwatch]::StartNew() } else { $null }') -and
    $sourceProofInvokerText.Contains('$script:D32BoundedDiagnosticSourceProofWallTimer') -and
    $sourceProofInvokerText.Contains('$script:D32BoundedDiagnosticSourceProofTimer = $proofTimer') -and
    -not $sourceProofInvokerText.Contains('StartNew()') -and $sourceProofInvokerText.Contains('Assert-D32BoundedDiagnosticInv7Origin') -and
    -not $sourceProofInvokerText.Contains('Invoke-D32BoundedCompilerDiagnosticRun') -and
    -not $sourceProofInvokerText.Contains('Initialize-D32PowerShellModuleAuthority') -and
    -not $sourceProofInvokerText.Contains('Start-Process') -and -not $sourceProofInvokerText.Contains('Import-Module') -and
    -not $sourceProofInvokerText.Contains('Get-CimInstance') -and -not $sourceProofInvokerText.Contains('PinnedGit')
Assert-D32BoundedCompilerDiagnosticSelfTest 'separate proof-only entry dispatches explicit source mode and its runner path does not invoke diagnostic admission, Cargo, Git, or installed imports' $sourceProofDispatchExact
Assert-D32BoundedCompilerDiagnosticSelfTest 'proof-only entry exact mandatory parameter contract and sole direct runner invocation shape accepted' $sourceProofEntrySafetyExact
Assert-D32BoundedCompilerDiagnosticSelfTest 'NON_SOURCE_L1 reader branch terminates before Profile, historical origin, SourceProof authority, or proof-runner access' `
    $nonSourceL1BranchNoSourceInputs
$sourceProofProgressMarkerBounded = $null -ne $sourceProofProgressMarkerAst -and
    $sourceProofProgressMarkerText.Contains('D32SP1 p={0} t={1} n={2}') -and
    $sourceProofProgressMarkerText.Contains('ProgressMarkerCount -ge 120') -and
    $sourceProofProgressMarkerText.Contains('ProgressMarkerBytes + $lineBytes -gt 16000') -and
    $sourceProofProgressMarkerText.Contains('ProgressMarkerPhases.Add($phaseValue)') -and
    $sourceProofProgressMarkerText.Contains('ProgressMarkerAllowedPhases.Contains($phaseValue)') -and
    $sourceProofProgressMarkerText.Contains('ProgressMarkerCoarseSteps.TryGetValue') -and
    $sourceProofProgressMarkerText.Contains('$line = ''D32SP1 p={0} t={1} n={2}'' -f $phaseValue, [Int64]$timer.ElapsedMilliseconds, $counterText') -and
    -not $sourceProofProgressMarkerText.Contains('path=') -and
    -not $sourceProofProgressMarkerText.Contains('volume_serial_hex') -and
    -not $sourceProofProgressMarkerText.Contains('file_id_hex')
$timerStartMarkerIndex = $runnerAst.Extent.Text.IndexOf('$script:D32BoundedDiagnosticSourceProofWallTimer = if ($SourceProofOnly) { [Diagnostics.Stopwatch]::StartNew() } else { $null }', [StringComparison]::Ordinal)
$timerStartAdvisoryIndex = $runnerAst.Extent.Text.IndexOf("[Console]::Out.WriteLine('D32SP1 p=timer.start t=0 n=none')", [StringComparison]::Ordinal)
$moduleBootstrapAfterTimerMarkerIndex = $runnerAst.Extent.Text.IndexOf(". ([IO.Path]::Combine(`$PSScriptRoot, 'd32-powershell-module-authority.ps1'))", [StringComparison]::Ordinal)
$timerStartMarkerExact = $timerStartMarkerIndex -ge 0 -and $timerStartAdvisoryIndex -gt $timerStartMarkerIndex -and
    $moduleBootstrapAfterTimerMarkerIndex -gt $timerStartAdvisoryIndex -and
    ([Text.Encoding]::ASCII.GetByteCount('D32SP1 p=timer.start t=0 n=none' + [Environment]::NewLine) + 16000) -le 16384 -and
    $runnerAst.Extent.Text.Contains('$script:D32BoundedDiagnosticSourceProofProgressMarkerOutputUnavailable = $true')
Assert-D32BoundedCompilerDiagnosticSelfTest 'proof-only emits a fixed non-gating timer-start marker before bootstrap and caps all later phase/count markers' ($sourceProofProgressMarkerBounded -and $timerStartMarkerExact)

Invoke-Expression $sourceProofProgressMarkerAst.Extent.Text
$markerTimer = [Diagnostics.Stopwatch]::StartNew()
$previousConsoleOut = [Console]::Out
$markerWriter = [IO.StringWriter]::new([Globalization.CultureInfo]::InvariantCulture)
try {
    [Console]::SetOut($markerWriter)
    $script:D32BoundedDiagnosticSourceProofTimer = $markerTimer
    $script:D32BoundedDiagnosticSourceProofProgressMarkerBytes = [long]0
    $script:D32BoundedDiagnosticSourceProofProgressMarkerCount = 0
    $script:D32BoundedDiagnosticSourceProofProgressMarkerOutputUnavailable = $false
    $script:D32BoundedDiagnosticSourceProofProgressMarkerAllowedPhases = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($safePhase in @('registry.archive', 'git.tree_walk')) { [void]$script:D32BoundedDiagnosticSourceProofProgressMarkerAllowedPhases.Add($safePhase) }
    $script:D32BoundedDiagnosticSourceProofProgressMarkerPhases = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $script:D32BoundedDiagnosticSourceProofProgressMarkerLastCounters = [Collections.Generic.Dictionary[string,long]]::new([StringComparer]::Ordinal)
    $script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps = [Collections.Generic.Dictionary[string,long]]::new([StringComparer]::Ordinal)
    $script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps.Add('registry.archive', [long]64)
    Set-D32BoundedDiagnosticSourceProofProgress -Phase 'registry.archive' -Progress 'archive=0/870;package=fixture-private;path=C:\fixture-private'
    Set-D32BoundedDiagnosticSourceProofProgress -Phase 'registry.archive' -Progress 'archive=63/870;package=fixture-private;path=C:\fixture-private'
    Set-D32BoundedDiagnosticSourceProofProgress -Phase 'registry.archive' -Progress 'archive=64/870;package=fixture-private;path=C:\fixture-private'
    Set-D32BoundedDiagnosticSourceProofProgress -Phase 'git.tree_walk' -Progress 'trees=64;pending=2;path=C:\fixture-private'
    Set-D32BoundedDiagnosticSourceProofProgress -Phase 'C:\fixture-private\source-aaaaaaaa' -Progress 'files=99;path=C:\fixture-private'
    $markerSampleText = $markerWriter.ToString()
    $markerSampleLines = @($markerSampleText -split "`r?`n" | Where-Object { -not [String]::IsNullOrEmpty($_) })
    $markerSampleSafe = $markerSampleLines.Count -eq 3 -and
        $markerSampleLines[0].Contains('p=registry.archive') -and $markerSampleLines[0].Contains('arc=0/870') -and
        $markerSampleLines[1].Contains('arc=64/870') -and $markerSampleLines[2].Contains('p=git.tree_walk') -and
        ($markerSampleLines | Where-Object { $_.Length -gt 120 }).Count -eq 0 -and
        -not $markerSampleText.Contains('fixture-private') -and -not $markerSampleText.Contains('C:\') -and
        -not $markerSampleText.Contains('volume_serial_hex') -and -not $markerSampleText.Contains('file_id_hex')
    $markerWriter.GetStringBuilder().Clear() | Out-Null
    $script:D32BoundedDiagnosticSourceProofProgressMarkerBytes = [long]0
    $script:D32BoundedDiagnosticSourceProofProgressMarkerCount = 0
    $script:D32BoundedDiagnosticSourceProofProgressMarkerPhases.Clear()
    $script:D32BoundedDiagnosticSourceProofProgressMarkerLastCounters.Clear()
    for ($markerIndex = 0; $markerIndex -lt 150; $markerIndex++) {
        $syntheticMarkerPhase = 'synthetic.phase.{0}' -f $markerIndex
        [void]$script:D32BoundedDiagnosticSourceProofProgressMarkerAllowedPhases.Add($syntheticMarkerPhase)
        Set-D32BoundedDiagnosticSourceProofProgress -Phase $syntheticMarkerPhase -Progress 'no-data'
    }
    $markerCapLines = @($markerWriter.ToString() -split "`r?`n" | Where-Object { -not [String]::IsNullOrEmpty($_) })
    $markerCapSafe = $markerCapLines.Count -eq 120 -and
        $script:D32BoundedDiagnosticSourceProofProgressMarkerCount -eq 120 -and
        $script:D32BoundedDiagnosticSourceProofProgressMarkerBytes -le 16000 -and
        [Text.Encoding]::ASCII.GetByteCount($markerWriter.ToString()) -le 16000
}
finally {
    $markerTimer.Stop()
    [Console]::SetOut($previousConsoleOut)
    $markerWriter.Dispose()
    $script:D32BoundedDiagnosticSourceProofTimer = $null
}
Assert-D32BoundedCompilerDiagnosticSelfTest 'advisory progress emits only phase transitions and 64-row coarse milestones without raw fixture paths' $markerSampleSafe
Assert-D32BoundedCompilerDiagnosticSelfTest 'advisory progress output stops at 120 lines and 16,000 bytes without affecting proof status' $markerCapSafe
$previousConsoleOut = [Console]::Out
$disposedMarkerWriter = [IO.StringWriter]::new([Globalization.CultureInfo]::InvariantCulture)
$disposedMarkerWriter.Dispose()
$markerSinkFailureHandled = $false
try {
    [Console]::SetOut($disposedMarkerWriter)
    $script:D32BoundedDiagnosticSourceProofTimer = [Diagnostics.Stopwatch]::StartNew()
    $script:D32BoundedDiagnosticSourceProofProgressMarkerBytes = [long]0
    $script:D32BoundedDiagnosticSourceProofProgressMarkerCount = 0
    $script:D32BoundedDiagnosticSourceProofProgressMarkerOutputUnavailable = $false
    $script:D32BoundedDiagnosticSourceProofProgressMarkerAllowedPhases = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    [void]$script:D32BoundedDiagnosticSourceProofProgressMarkerAllowedPhases.Add('registry.archive')
    $script:D32BoundedDiagnosticSourceProofProgressMarkerPhases = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $script:D32BoundedDiagnosticSourceProofProgressMarkerLastCounters = [Collections.Generic.Dictionary[string,long]]::new([StringComparer]::Ordinal)
    $script:D32BoundedDiagnosticSourceProofProgressMarkerCoarseSteps = [Collections.Generic.Dictionary[string,long]]::new([StringComparer]::Ordinal)
    $proofStatusBeforeMarkerFailure = 'BLOCKED'
    Set-D32BoundedDiagnosticSourceProofProgress -Phase 'registry.archive' -Progress 'archive=1/870'
    $markerSinkFailureHandled = $script:D32BoundedDiagnosticSourceProofProgressMarkerOutputUnavailable -and
        $script:D32BoundedDiagnosticSourceProofProgressMarkerCount -eq 0 -and $proofStatusBeforeMarkerFailure -ceq 'BLOCKED'
}
finally {
    if ($null -ne $script:D32BoundedDiagnosticSourceProofTimer) { $script:D32BoundedDiagnosticSourceProofTimer.Stop() }
    $script:D32BoundedDiagnosticSourceProofTimer = $null
    [Console]::SetOut($previousConsoleOut)
}
Assert-D32BoundedCompilerDiagnosticSelfTest 'advisory stdout failure is swallowed and does not mutate diagnostic status' $markerSinkFailureHandled
$sourceProofInvocationWithoutHistoricalOrigin = @($sourceProofExpectedInvocationElements | Where-Object { $_ -cne '-HistoricalOriginCandidateSha' -and $_ -cne '$HistoricalOriginCandidateSha' })
Assert-D32BoundedCompilerDiagnosticSelfTest 'proof-only entry invocation contract rejects omission of historical origin SHA parameter' ($sourceProofInvocationWithoutHistoricalOrigin.Count -ne $sourceProofExpectedInvocationElements.Count)
Assert-D32BoundedCompilerDiagnosticSelfTest 'proof-only entry passes current and historical SHA pins to distinct runner parameters' ($sourceProofInvocationExact -and
    $sourceProofInvocationElements[5] -ceq '$CandidateSha' -and $sourceProofInvocationElements[7] -ceq '$HistoricalOriginCandidateSha')
$sourceProofResultBuilderCalls = @($sourceProofInvokerAst.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'New-D32BoundedDiagnosticSourceProofCandidateDocument'
}, $true))
$sourceProofResultSelfValidationCalls = @($sourceProofInvokerAst.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Test-D32BoundedDiagnosticSourceProofCandidate'
}, $true))
$sourceProofBlockedFallbackExact = $sourceProofResultBuilderCalls.Count -eq 2 -and $sourceProofResultSelfValidationCalls.Count -eq 2 -and
    $sourceProofInvokerText.Contains('$originalPrimaryError') -and $sourceProofInvokerText.Contains('SOURCEPROOF_RESULT_SHAPE_REJECTED: ') -and
    $sourceProofInvokerText.Contains('$status = ''BLOCKED''') -and $sourceProofInvokerText.Contains('-CurrentProfileLockBindings $null') -and
    $sourceProofInvokerText.Contains('-CurrentSourceClosure $null') -and $sourceProofInvokerText.Contains('$fallbackFailures') -and
    -not $sourceProofInvokerText.Contains('generated untrusted source-proof candidate failed its own non-gating result shape')
Assert-D32BoundedCompilerDiagnosticSelfTest 'proof-only runner preserves primary failures and downgrades rejected success payloads to self-validated BLOCKED records' $sourceProofBlockedFallbackExact
$sourceProofCurrentProfileLockBindings = @(
        [PSCustomObject]@{ manifest_path = 'vita-agent-protocol/Cargo.toml'; lock_path = 'vita-agent-protocol/Cargo.lock'; lock_bytes = 10L; lock_sha256 = 'a' * 64 },
        [PSCustomObject]@{ manifest_path = 'vita-agent/Cargo.toml'; lock_path = 'vita-agent/Cargo.lock'; lock_bytes = 10L; lock_sha256 = [string]$graphPlan.lock_sha256 },
        [PSCustomObject]@{ manifest_path = 'src-tauri/Cargo.toml'; lock_path = 'src-tauri/Cargo.lock'; lock_bytes = 10L; lock_sha256 = 'c' * 64 })
$sourceProofCurrentClosure = [PSCustomObject]@{
        CurrentCandidateSha = $sourceProofCurrentSha
        HistoricalOriginCandidateSha = $script:D32BoundedDiagnosticHistoricalInv7CandidateSha
        HistoricalAttemptState = 'BLOCKED'; HistoricalFetchCompletion = 'NOT_RETAINED'; HistoricalGateAuthority = 'NONE'
        RegistryContentProof = $null
        GitContentProof = [PSCustomObject]@{ record_type = 'D32_BOUNDED_DIAGNOSTIC_GIT_SOURCE_CONTENT_PROOF_V2'; status = 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY'; formal_gate_usable = $false; lock_sha256 = [string]$graphPlan.lock_sha256; verified_package_ids = @(); sources = @() }
        SourceGraphProof = $graphProof
        CurrentManifestProof = @($graphProof.classifications | Where-Object { $_.classification -ceq 'INCLUDED' -and $_.source_kind -ceq 'workspace' } | ForEach-Object { [PSCustomObject]@{ manifest_path = [string]$_.manifest_path; bytes = 1L; sha256 = [string]$_.manifest_sha256; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' } }) + @([PSCustomObject]@{ manifest_path = 'src-tauri/Cargo.toml'; bytes = 1L; sha256 = 'd' * 64; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' })
    }
$registryProofPackages = [System.Collections.Generic.List[object]]::new()
foreach ($classification in @($graphProof.classifications | Where-Object { [string]$_.classification -ceq 'INCLUDED' -and [string]$_.source_kind -ceq 'registry' })) {
    $locked = @($graphPlan.locked_packages | Where-Object { [string]$_.package_id -ceq [string]$classification.package_id })
    if ($locked.Count -ne 1) { throw 'registry proof synthetic fixture lock row is missing or ambiguous' }
    $packageRoot = [string]$locked[0].name + '-' + [string]$locked[0].version
    $registryProofPackages.Add([PSCustomObject][ordered]@{
        package_id = [string]$locked[0].package_id; name = [string]$locked[0].name; version = [string]$locked[0].version
        checksum = [string]$locked[0].checksum
        archive_path = 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f\' + $packageRoot + '.crate'
        archive_bytes = 1024L; archive_file_sha256 = [string]$locked[0].checksum
        archive_volume_serial_hex = '0123456789abcdef'; archive_file_id_hex = '0123456789abcdef0123456789abcdef'
        archive_inventory_sha256 = 'a' * 64; registry_archive_policy = $script:D32BoundedDiagnosticRegistryArchivePolicy
        header_inventory_sha256 = 'b' * 64; header_count = 1L; ordinary_header_count = 1L
        longname_pair_count = 0L; longname_pair_inventory_sha256 = (Get-D32BoundedCompilerDiagnosticLongNamePairDigest -Pairs @())
        longname_control_metadata_count = 0L; longname_control_metadata_bytes = 0L
        longname_control_metadata_sha256 = (Get-D32BoundedCompilerDiagnosticLongNameControlDigest -Pairs @())
        format_counts = [PSCustomObject][ordered]@{ ustar_regular = 1L; ustar_directory = 0L; gnu_regular = 0L; gnu_directory = 0L; gnu_longname_extension = 0L }
        source_root = 'E:\d32\inv7\r\c\registry\src\index.crates.io-1949cf8c6b5b557f\' + $packageRoot
        source_root_volume_serial_hex = '0123456789abcdef'; source_root_file_id_hex = '0123456789abcdef0123456789abcdef'
        source_file_count = 1L; source_directory_count = 0L; generated_metadata_count = 0L; source_bytes = 1L; source_inventory_sha256 = 'c' * 64
    })
}
$registryPackageRows = @($registryProofPackages.ToArray())
$registryContentProof = [PSCustomObject][ordered]@{
    schema_version = 4; record_type = $script:D32BoundedDiagnosticRegistrySourceContentProofType
    registry_archive_policy = $script:D32BoundedDiagnosticRegistryArchivePolicy; gate_authority = 'NONE'
    status = 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY'; formal_gate_usable = $false
    semantic_scope = 'EXACT_CALLER_PINNED_ARCHIVE_SUBSET_FOR_LOCKED_GRAPH_CANDIDATES'
    source_proof_sha256 = Get-D32BoundedDiagnosticRegistrySourceProofDigest -Packages $registryPackageRows
    verifier_managed_buffer_cap_bytes = 536870912L; maximum_buffered_registry_archive_bytes = 268435456L
    concurrent_buffered_registry_archives = 1L; lock_sha256 = [string]$graphPlan.lock_sha256
    registry_tuple_sha256 = [string]$graphPlan.registry_tuple_sha256; package_count = [Int64]$registryPackageRows.Count
    locked_registry_catalog_count = [Int64]$graphPlan.registry_package_count
    verified_package_ids = @($registryPackageRows | ForEach-Object { [string]$_.package_id })
    compressed_bytes = [Int64]($registryPackageRows.Count * 1024); expanded_bytes = [Int64]($registryPackageRows.Count * 2048)
    member_count = [Int64]$registryPackageRows.Count; elapsed_milliseconds = 1000L; packages = $registryPackageRows
}
$sourceProofCurrentClosure.RegistryContentProof = $registryContentProof
$sourceProofCandidate = New-D32BoundedDiagnosticSourceProofCandidateDocument `
    -CandidateSha $sourceProofCurrentSha -HistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha `
    -Repository $testRepo -Status 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY' `
    -ProofAuthorityPath 'C:\d32-diagnostic-policy-test\external\source-proof-authority.json' -ProofAuthoritySha256 ('a' * 64) `
    -ProofEntryPath $sourceProofEntryPath -ProofEntrySha256 ('b' * 64) `
    -ProofStartedAtUtc '2026-10-04T00:00:00.0000000+00:00' -ProofCompletedAtUtc '2026-10-04T00:00:01.0000000+00:00' `
    -ProofElapsedMilliseconds 1000L -ProofBudget $sourceProofAuthority.proof_budget -SourcePins $sourceProofPins `
    -CurrentProfileLockBindings $sourceProofCurrentProfileLockBindings -CurrentSourceClosure $sourceProofCurrentClosure -PrimaryError $null
$sourceProofCandidateReasons = [System.Collections.Generic.List[string]]::new()
$sourceProofCandidateValid = Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate -FailureReasons $sourceProofCandidateReasons
Assert-D32BoundedCompilerDiagnosticSelfTest ('current source-proof-only candidate is valid while remaining untrusted and non-gating (' + [string]::Join(',', [string[]]$sourceProofCandidateReasons.ToArray()) + ')') $sourceProofCandidateValid
$registryHeaderDigestOriginal = [string]$registryContentProof.packages[0].header_inventory_sha256
$registryContentProof.packages[0].header_inventory_sha256 = 'd' * 64
Assert-D32BoundedCompilerDiagnosticSelfTest 'registry V4 source-proof rejects a substituted header-inventory digest' (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate))
$registryContentProof.packages[0].header_inventory_sha256 = $registryHeaderDigestOriginal
$registryRegularCountOriginal = [Int64]$registryContentProof.packages[0].format_counts.ustar_regular
$registryContentProof.packages[0].format_counts.ustar_regular = $registryRegularCountOriginal + 1L
Assert-D32BoundedCompilerDiagnosticSelfTest 'registry V4 source-proof rejects substituted format counts and a header-count mismatch' (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate))
$registryContentProof.packages[0].format_counts.ustar_regular = $registryRegularCountOriginal
$registryPolicyOriginal = [string]$registryContentProof.registry_archive_policy
$registryContentProof.registry_archive_policy = 'D32_REGISTRY_TAR_USTAR_ONLY_V1'
Assert-D32BoundedCompilerDiagnosticSelfTest 'registry V4 source-proof rejects policy substitution rather than accepting old USTAR-only records' (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate))
$registryContentProof.registry_archive_policy = $registryPolicyOriginal
$registryProofSchemaOriginal = [Int64]$registryContentProof.schema_version
$registryContentProof.schema_version = 2L
Assert-D32BoundedCompilerDiagnosticSelfTest 'registry V3 source-content proof cannot be relabeled as the new V4 format proof' (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate))
$registryContentProof.schema_version = $registryProofSchemaOriginal

function New-D32BoundedCompilerDiagnosticTestCensusArchiveReference {
    param([string]$Name = 'layout-crate', [string]$Version = '1.2.3', [string]$Sha256 = ('a' * 64), [long]$Bytes = 4096L)
    $root = 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f'
    return [PSCustomObject][ordered]@{
        source = 'registry+https://github.com/rust-lang/crates.io-index'; name = $Name; version = $Version
        checksum = $Sha256; path = Join-Path $root ($Name + '-' + $Version + '.crate'); bytes = $Bytes; sha256 = $Sha256
        volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef'
    }
}
$censusEntryFixture = Join-Path $testRepo 'scripts\d32-bounded-diagnostic-archive-format-census.ps1'
$censusPolicyFixture = Join-Path $testRepo 'scripts\d32-bounded-compiler-diagnostic-policy.ps1'
$censusProfileFixture = Join-Path $testRepo 'scripts\d32-build-toolchain-profile.ps1'
$censusModuleFixture = Join-Path $testRepo 'scripts\d32-powershell-module-authority.ps1'
$censusArchiveFixture = New-D32BoundedCompilerDiagnosticTestCensusArchiveReference -Bytes ([Int64]$layoutMixedBytes.Length) -Sha256 $layoutMixedSha
$censusAuthorityFixture = [PSCustomObject][ordered]@{
    schema_version = 2; record_type = $script:D32BoundedDiagnosticArchiveFormatCensusAuthorityType
    registry_archive_policy = $script:D32BoundedDiagnosticRegistryArchivePolicy; source_plan_semantics_version = 2
    semantic_scope = 'EXACT_CALLER_PINNED_CURRENT_LOCK_ARCHIVE_FORMAT_SUBSET'; registry_tuple_sha256 = [string]$graphPlan.registry_tuple_sha256
    gate_authority = 'NONE'; candidate_sha = $testCandidate; source_repo = $testRepo
    repository_identity = [PSCustomObject][ordered]@{ volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
    lock_reference = (New-D32BoundedCompilerDiagnosticTestReference (Join-Path $testRepo 'vita-agent\Cargo.lock'))
    dependency_origin = [PSCustomObject][ordered]@{
        path = 'E:\d32\inv7\r\c'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef'
        registry_archive_root = [PSCustomObject][ordered]@{
            path = 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f'
            volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef'
        }
    }
    historical_origin = [PSCustomObject][ordered]@{
        candidate_sha = $script:D32BoundedDiagnosticHistoricalInv7CandidateSha; attempt_state = 'BLOCKED'
        fetch_completion = 'NOT_RETAINED'; gate_authority = 'NONE'
        owner_record = (New-D32BoundedCompilerDiagnosticTestReference 'E:\d32\inv7\D32-PHASE0-OWNER.json')
        blocked_diagnostic = (New-D32BoundedCompilerDiagnosticTestReference 'E:\d32\inv7\D32-PHASE0-BLOCKED-DIAGNOSTIC.json')
    }
    source_pins = @(
        (New-D32BoundedCompilerDiagnosticTestReference $censusEntryFixture),
        (New-D32BoundedCompilerDiagnosticTestReference $censusPolicyFixture),
        (New-D32BoundedCompilerDiagnosticTestReference $censusProfileFixture),
        (New-D32BoundedCompilerDiagnosticTestReference $censusModuleFixture))
    archive_refs = @($censusArchiveFixture)
    output_candidate = [PSCustomObject][ordered]@{
        path = 'C:\d32-diagnostic-policy-test\external\archive-census\result.json'
        parent_path = 'C:\d32-diagnostic-policy-test\external\archive-census'
        parent_volume_serial_hex = '0123456789abcdef'; parent_file_id_hex = '0123456789abcdef0123456789abcdef'
    }
    run_id = 'a' * 32
    resource_budget = [PSCustomObject][ordered]@{
        combined_milliseconds = 300000L; managed_buffer_bytes = 536870912L; max_archive_bytes = 268435456L
        max_archive_expanded_bytes = 1073741824L; max_archive_member_bytes = 134217728L; max_archive_members = 10000L
        max_aggregate_expanded_bytes = 34359738368L; max_aggregate_members = 1000000L; maximum_output_bytes = 67108864L
    }
    issued_at_utc = '2026-10-05T00:00:00.0000000+00:00'
}
$censusAuthorityValid = Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $censusAuthorityFixture `
    -ExpectedCandidateSha $testCandidate -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture
Assert-D32BoundedCompilerDiagnosticSelfTest 'new census authority V2 exact shape binds current candidate, V2 source plan, inv7 origin, historical BLOCKED/NONE metadata, four source pins, finite refs, resource bounds, and external create-new output' $censusAuthorityValid
$censusAuthorityFixture.PSObject.Properties.Remove('registry_tuple_sha256')
$censusAuthorityMissingFieldRejected = -not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $censusAuthorityFixture `
    -ExpectedCandidateSha $testCandidate -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture)
$censusAuthorityFixture | Add-Member -NotePropertyName unexpected_authority_field -NotePropertyValue 'must fail closed'
$censusAuthorityExtraFieldRejected = -not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $censusAuthorityFixture `
    -ExpectedCandidateSha $testCandidate -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture)
$censusAuthorityFixture.PSObject.Properties.Remove('unexpected_authority_field')
$censusAuthorityFixture | Add-Member -NotePropertyName registry_tuple_sha256 -NotePropertyValue ([string]$graphPlan.registry_tuple_sha256)
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority exact-shape validator rejects missing and unexpected top-level fields before reaccepting restored shape' `
    ($censusAuthorityMissingFieldRejected -and $censusAuthorityExtraFieldRejected -and
     (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $censusAuthorityFixture -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture))
$censusAuthorityRoundtrip = ConvertFrom-D32BoundedCompilerDiagnosticTestJson -Json (ConvertTo-Json -InputObject $censusAuthorityFixture -Depth 100 -Compress -ErrorAction Stop)
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority exact finite schema survives canonical JSON serialization/deserialization' `
    (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $censusAuthorityRoundtrip -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture)
$badCensusAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$badCensusAuthority.registry_archive_policy = 'D32_REGISTRY_TAR_USTAR_ONLY_V1'
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority rejects policy substitution rather than widening/rewriting the approved format contract' `
    (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $badCensusAuthority -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture))
$badCensusAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$badCensusAuthority.source_plan_semantics_version = 1
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority rejects old source-plan semantics and cannot reuse legacy V1 closure evidence' `
    (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $badCensusAuthority -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture))
$badCensusAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$badCensusAuthority.candidate_sha = '2' * 40
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority rejects candidate rebind and exact candidate SHA substitution' `
    (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $badCensusAuthority -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture))
$badCensusAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$badCensusAuthority.dependency_origin.registry_archive_root.path += '-sibling'
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority rejects archive-root suffix sibling and does not infer trust from directory-name suffix' `
    (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $badCensusAuthority -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture))
$badCensusAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$badCensusAuthority.archive_refs[0].path = 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f-sibling\layout-crate-1.2.3.crate'
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority rejects archive path outside the exact pinned cache root even when its basename matches' `
    (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $badCensusAuthority -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture))
$badCensusAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$badCensusAuthority.source_pins[0].path = Join-Path $testRepo 'scripts\d32-bounded-compiler-diagnostic.ps1'
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority rejects substituting a source pin for the exact census entry path' `
    (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $badCensusAuthority -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture))
$badCensusAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$badCensusAuthority.lock_reference.path = Join-Path $testRepo 'vita-agent/Cargo.toml'
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority rejects manifest-as-lock path substitution' `
    (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $badCensusAuthority -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture))
$badCensusAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$badCensusAuthority.archive_refs[0].bytes = 268435457L
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority rejects oversized archive reference before any file open' `
    (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $badCensusAuthority -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture))
$badCensusAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$badCensusAuthority.resource_budget.max_archive_members = 10001
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority rejects expanded member-count budget and never accepts caller-supplied larger limits' `
    (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $badCensusAuthority -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture))
$badCensusAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$badCensusAuthority.output_candidate.path = 'C:\d32-diagnostic-policy-test\repo\result.json'
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority rejects an output path overlapping the candidate repository' `
    (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $badCensusAuthority -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture))
$badCensusAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$badCensusAuthority.archive_refs = @()
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority rejects an empty finite archive set instead of treating empty coverage as success' `
    (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $badCensusAuthority -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture))
$tooManyArchiveRefs = [System.Collections.Generic.List[object]]::new()
for ($archiveIndex = 0; $archiveIndex -lt 1116; $archiveIndex++) {
    $tooManyArchiveRefs.Add((New-D32BoundedCompilerDiagnosticTestCensusArchiveReference -Name 'crate' -Version ('1.0.' + $archiveIndex) -Sha256 ('a' * 64)))
}
$badCensusAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$badCensusAuthority.archive_refs = @($tooManyArchiveRefs.ToArray())
Assert-D32BoundedCompilerDiagnosticSelfTest 'census authority rejects archive reference set above the frozen 1115-package maximum' `
    (-not (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape -Document $badCensusAuthority -ExpectedCandidateSha $testCandidate `
        -Repository $testRepo -EntryScriptPath $censusEntryFixture -PolicyPath $censusPolicyFixture -ProfileScriptPath $censusProfileFixture))

$censusCompleteInventory = [PSCustomObject][ordered]@{
    expanded_bytes = [Int64]$layoutScan.expanded_bytes; header_count = [Int64]$layoutScan.header_count
    ordinary_header_count = [Int64]$layoutScan.ordinary_header_count
    longname_pair_count = [Int64]$layoutScan.longname_pair_count
    longname_pair_inventory_sha256 = [string]$layoutScan.longname_pair_inventory_sha256
    longname_control_metadata_count = [Int64]$layoutScan.longname_control_metadata_count
    longname_control_metadata_bytes = [Int64]$layoutScan.longname_control_metadata_bytes
    longname_control_metadata_sha256 = [string]$layoutScan.longname_control_metadata_sha256
    format_counts = $layoutScan.format_counts; header_inventory_sha256 = [string]$layoutScan.header_inventory_sha256
    framing_verified = $true; first_failure_offset = $null; first_failure_header_sha256 = $null; first_failure_reason = $null
}
$censusCompleteOpenedReference = [PSCustomObject][ordered]@{
    bytes = [Int64]$censusArchiveFixture.bytes; sha256 = [string]$censusArchiveFixture.sha256
    volume_serial_hex = [string]$censusArchiveFixture.volume_serial_hex; file_id_hex = [string]$censusArchiveFixture.file_id_hex
}
$censusCompleteArchiveRow = New-D32BoundedDiagnosticArchiveFormatCensusCoverageRow -Archive $censusArchiveFixture `
    -Status 'COMPLETE_SUPPORTED' -OpenedReference $censusCompleteOpenedReference -Inventory $censusCompleteInventory -FailureReason $null
$censusAuthorityReferenceFixture = New-D32BoundedCompilerDiagnosticTestReference 'C:\d32-diagnostic-policy-test\external\archive-census\authority.json'
$censusCompleteResultFixture = New-D32BoundedDiagnosticArchiveFormatCensusResult -Authority $censusAuthorityFixture `
    -AuthorityReference $censusAuthorityReferenceFixture -Status 'COMPLETE_DIAGNOSTIC' `
    -StartedAtUtc '2026-10-05T00:00:00.0000000+00:00' -CompletedAtUtc '2026-10-05T00:00:01.0000000+00:00' `
    -ElapsedMilliseconds 1000L -Archives @($censusCompleteArchiveRow) -PrimaryError $null -SecondaryErrors @()
$badLongPaddingArchive = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries @($validNegativeBase, $badLongPadding)
$badLongPaddingSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($badLongPaddingArchive)).ToLowerInvariant()
$badLongPaddingScan = Get-D32BoundedDiagnosticArchiveFormatCensusInventory -CompressedBytes $badLongPaddingArchive `
    -ExpectedPackageRoot $longNameRoot -ExpectedArchiveSha256 $badLongPaddingSha -CensusTimer ([Diagnostics.Stopwatch]::StartNew())
$badLongPaddingRef = New-D32BoundedCompilerDiagnosticTestCensusArchiveReference -Name 'longname-padding' -Version '1.0.0' `
    -Sha256 $badLongPaddingSha -Bytes ([Int64]$badLongPaddingArchive.Length)
$badLongPaddingOpened = [PSCustomObject][ordered]@{
    bytes = [Int64]$badLongPaddingRef.bytes; sha256 = [string]$badLongPaddingRef.sha256
    volume_serial_hex = [string]$badLongPaddingRef.volume_serial_hex; file_id_hex = [string]$badLongPaddingRef.file_id_hex
}
$badLongPaddingRow = New-D32BoundedDiagnosticArchiveFormatCensusCoverageRow -Archive $badLongPaddingRef -Status 'UNSUPPORTED' `
    -OpenedReference $badLongPaddingOpened -Inventory $badLongPaddingScan -FailureReason $badLongPaddingScan.first_failure_reason
$badLongPaddingAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$badLongPaddingAuthority.archive_refs = @($badLongPaddingRef)
$badLongPaddingResult = New-D32BoundedDiagnosticArchiveFormatCensusResult -Authority $badLongPaddingAuthority `
    -AuthorityReference $censusAuthorityReferenceFixture -Status 'BLOCKED' `
    -StartedAtUtc '2026-10-05T00:00:00.0000000+00:00' -CompletedAtUtc '2026-10-05T00:00:01.0000000+00:00' `
    -ElapsedMilliseconds 1000L -Archives @($badLongPaddingRow) -PrimaryError $badLongPaddingScan.first_failure_reason `
    -SecondaryErrors @($badLongPaddingScan.first_failure_reason)
Assert-D32BoundedCompilerDiagnosticSelfTest 'census V2 preserves a recognized GNU L header, hashed control bytes, zero pair count, and primary failure when padding is rejected' `
    ($badLongPaddingScan.status -ceq 'BLOCKED' -and $badLongPaddingScan.format_counts.gnu_longname_extension -eq 1 -and
     $badLongPaddingScan.longname_control_metadata_count -eq 1 -and $badLongPaddingScan.longname_pair_count -eq 0 -and
     (Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $badLongPaddingResult))
$censusResultFailures = [System.Collections.Generic.List[string]]::new()
$censusResultValid = Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $censusCompleteResultFixture -FailureReasons $censusResultFailures
$censusResultReadback = ConvertFrom-D32BoundedCompilerDiagnosticTestJson -Json (ConvertTo-Json -InputObject $censusCompleteResultFixture -Depth 100 -Compress -ErrorAction Stop)
$censusReadbackFailures = [System.Collections.Generic.List[string]]::new()
$censusReadbackValid = Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $censusResultReadback -FailureReasons $censusReadbackFailures
$censusCoverageFailures = [System.Collections.Generic.List[string]]::new()
$censusAuthorityCoverageValid = Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityCoverage -Result $censusResultReadback `
    -Authority $censusAuthorityFixture -ExpectedAuthorityReference $censusAuthorityReferenceFixture -FailureReasons $censusCoverageFailures
Assert-D32BoundedCompilerDiagnosticSelfTest 'actual census coverage-row and result builders produce a strict object that survives JSON readback and binds each row to the finite authority set' `
    ($censusResultValid -and $censusReadbackValid -and $censusAuthorityCoverageValid -and $censusResultFailures.Count -eq 0 -and $censusReadbackFailures.Count -eq 0)
$longNameCensusArchiveReference = New-D32BoundedCompilerDiagnosticTestCensusArchiveReference -Name 'longname-layout' `
    -Version '1.0.0' -Sha256 $longNameArchiveSha -Bytes ([Int64]$longNameArchive.Length)
$longNameCensusOpenedReference = [PSCustomObject][ordered]@{
    bytes = [Int64]$longNameCensusArchiveReference.bytes; sha256 = [string]$longNameCensusArchiveReference.sha256
    volume_serial_hex = [string]$longNameCensusArchiveReference.volume_serial_hex; file_id_hex = [string]$longNameCensusArchiveReference.file_id_hex
}
$longNameCensusCoverageRow = New-D32BoundedDiagnosticArchiveFormatCensusCoverageRow -Archive $longNameCensusArchiveReference `
    -Status 'COMPLETE_SUPPORTED' -OpenedReference $longNameCensusOpenedReference -Inventory $longNameCensus -FailureReason $null
$longNameCensusAuthorityFixture = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$longNameCensusAuthorityFixture.archive_refs = @($longNameCensusArchiveReference)
$longNameCensusResultFixture = New-D32BoundedDiagnosticArchiveFormatCensusResult -Authority $longNameCensusAuthorityFixture `
    -AuthorityReference $censusAuthorityReferenceFixture -Status 'COMPLETE_DIAGNOSTIC' `
    -StartedAtUtc '2026-10-05T00:00:00.0000000+00:00' -CompletedAtUtc '2026-10-05T00:00:01.0000000+00:00' `
    -ElapsedMilliseconds 1000L -Archives @($longNameCensusCoverageRow) -PrimaryError $null -SecondaryErrors @()
$longNameCensusResultReadback = Copy-D32BoundedCompilerDiagnosticTestJson -Record $longNameCensusResultFixture
$longNameCensusResultFailures = [System.Collections.Generic.List[string]]::new()
$longNameCensusResultValid = Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $longNameCensusResultReadback `
    -FailureReasons $longNameCensusResultFailures
$longNameCensusBindingFailures = [System.Collections.Generic.List[string]]::new()
$longNameCensusBound = Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityCoverage -Result $longNameCensusResultReadback `
    -Authority $longNameCensusAuthorityFixture -ExpectedAuthorityReference $censusAuthorityReferenceFixture `
    -FailureReasons $longNameCensusBindingFailures
Assert-D32BoundedCompilerDiagnosticSelfTest 'actual census parser and row/result producers carry every GNU L pair/control count and digest through strict V2 JSON readback and caller-reference binding' `
    ($longNameCensusResultValid -and $longNameCensusBound -and $longNameCensusResultFailures.Count -eq 0 -and
     $longNameCensusBindingFailures.Count -eq 0 -and $longNameCensusResultReadback.longname_pair_count -eq 9 -and
     $longNameCensusResultReadback.longname_control_metadata_count -eq 9 -and
     $longNameCensusResultReadback.longname_control_metadata_bytes -eq $longNameCensus.longname_control_metadata_bytes -and
     $longNameCensusResultReadback.aggregate_format_counts.gnu_longname_extension -eq 9 -and
     $longNameCensusResultReadback.archives[0].longname_pair_inventory_sha256 -ceq $longNameCensus.longname_pair_inventory_sha256)
$longNameCensusTamper = Copy-D32BoundedCompilerDiagnosticTestJson -Record $longNameCensusResultReadback
$longNameCensusTamper.archives[0].longname_pair_count -= 1L
$longNameCensusTamper.archive_header_inventory_sha256 = Get-D32BoundedDiagnosticArchiveFormatCensusCoverageDigest -Archives @($longNameCensusTamper.archives)
Assert-D32BoundedCompilerDiagnosticSelfTest 'census V2 rejects a GNU pair-count substitution after recomputing the outer coverage digest' `
    (-not (Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $longNameCensusTamper))
$badCensusResult = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusCompleteResultFixture
$badCensusResult.PSObject.Properties.Remove('run_id')
$censusResultMissingFieldFailures = [System.Collections.Generic.List[string]]::new()
$censusResultMissingFieldRejected = -not (Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $badCensusResult -FailureReasons $censusResultMissingFieldFailures)
$badCensusResult = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusCompleteResultFixture
$badCensusResult | Add-Member -NotePropertyName unexpected_result_field -NotePropertyValue 'must fail closed'
$censusResultExtraFieldRejected = -not (Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $badCensusResult)
Assert-D32BoundedCompilerDiagnosticSelfTest 'census result exact schema rejects missing and extra top-level fields with a field-set diagnostic' `
    ($censusResultMissingFieldRejected -and $censusResultExtraFieldRejected -and $censusResultMissingFieldFailures[0] -like 'result.property_set.*')
$orderedReferenceResult = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusCompleteResultFixture
$orderedReferenceResult.census_authority_reference = [ordered]@{
    path = [string]$censusAuthorityReferenceFixture.path; bytes = [Int64]$censusAuthorityReferenceFixture.bytes
    sha256 = [string]$censusAuthorityReferenceFixture.sha256; volume_serial_hex = [string]$censusAuthorityReferenceFixture.volume_serial_hex
    file_id_hex = [string]$censusAuthorityReferenceFixture.file_id_hex
}
$orderedReferenceFailures = [System.Collections.Generic.List[string]]::new()
$orderedReferenceAccepted = Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $orderedReferenceResult -FailureReasons $orderedReferenceFailures
Assert-D32BoundedCompilerDiagnosticSelfTest 'the prior Open authority ordered-dictionary shape fails with an exact census_authority_reference diagnostic while the real producer emits PSCustomObject' `
    (-not $orderedReferenceAccepted -and $orderedReferenceFailures.Count -eq 1 -and
     $orderedReferenceFailures[0] -ceq 'census_authority_reference.property_set_is_not_exact' -and
     $censusCompleteResultFixture.census_authority_reference -is [PSCustomObject])

$censusResultMutationCases = @(
    [PSCustomObject]@{ name = 'top-level coverage digest'; mutate = { param($r) $r.archive_header_inventory_sha256 = '0' * 64 } },
    [PSCustomObject]@{ name = 'per-archive header digest'; mutate = { param($r) $r.archives[0].header_inventory_sha256 = '0' * 64 } },
    [PSCustomObject]@{ name = 'header-count to format-count binding'; mutate = { param($r) $r.archives[0].header_count += 1L; $r.archive_header_inventory_sha256 = Get-D32BoundedDiagnosticArchiveFormatCensusCoverageDigest -Archives @($r.archives) } },
    [PSCustomObject]@{ name = 'format-count to header-count binding'; mutate = { param($r) $r.archives[0].format_counts.gnu_regular = 0L; $r.aggregate_format_counts.gnu_regular = 0L; $r.archive_header_inventory_sha256 = Get-D32BoundedDiagnosticArchiveFormatCensusCoverageDigest -Archives @($r.archives) } },
    [PSCustomObject]@{ name = 'policy substitution'; mutate = { param($r) $r.registry_archive_policy = 'D32_REGISTRY_TAR_USTAR_ONLY_V1' } },
    [PSCustomObject]@{ name = 'formal/source-proof claim'; mutate = { param($r) $r.source_proof_checkpoint = $true } },
    [PSCustomObject]@{ name = 'archive-root sibling rebind'; mutate = { param($r) $r.dependency_origin.registry_archive_root.path += '-sibling' } },
    [PSCustomObject]@{ name = 'source pin substitution'; mutate = { param($r) $r.source_pins[0].path = Join-Path $testRepo 'scripts/d32-bounded-compiler-diagnostic.ps1' } },
    [PSCustomObject]@{ name = 'resource budget expansion'; mutate = { param($r) $r.resource_budget.combined_milliseconds = 300001L } },
    [PSCustomObject]@{ name = 'output authority rebound'; mutate = { param($r) $r.output_candidate.path = Join-Path $testRepo 'output.json' } },
    [PSCustomObject]@{ name = 'ordered-dictionary file reference'; mutate = { param($r) $r.census_authority_reference = [ordered]@{ path = 'C:\external\authority.json'; bytes = 32L; sha256 = 'a' * 64; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' } } },
    [PSCustomObject]@{ name = 'null nested reference'; mutate = { param($r) $r.lock_reference = $null } },
    [PSCustomObject]@{ name = 'empty archive rows'; mutate = { param($r) $r.archives = @() } },
    [PSCustomObject]@{ name = 'empty unexamined array mismatch'; mutate = { param($r) $r.unexamined_archive_ids = @([string]$r.archives[0].archive_id) } },
    [PSCustomObject]@{ name = 'null aggregate format counts'; mutate = { param($r) $r.aggregate_format_counts = $null } },
    [PSCustomObject]@{ name = 'negative aggregate numeric'; mutate = { param($r) $r.aggregate_format_counts.ustar_regular = -1L } },
    [PSCustomObject]@{ name = 'fractional top-level numeric'; mutate = { param($r) $r.elapsed_milliseconds = 1.5 } },
    [PSCustomObject]@{ name = 'zero requested bound'; mutate = { param($r) $r.requested_archive_count = 0L } },
    [PSCustomObject]@{ name = 'malformed timestamp'; mutate = { param($r) $r.started_at_utc = 'yesterday' } },
    [PSCustomObject]@{ name = 'timestamp order'; mutate = { param($r) $r.completed_at_utc = '2026-10-04T23:59:59.0000000+00:00' } },
    [PSCustomObject]@{ name = 'error scalar type'; mutate = { param($r) $r.primary_error = $true } },
    [PSCustomObject]@{ name = 'secondary error element type'; mutate = { param($r) $r.secondary_errors = @('valid', 7) } },
    [PSCustomObject]@{ name = 'ordinary payload hash claim'; mutate = { param($r) $r.ordinary_payload_hashed = $true } },
    [PSCustomObject]@{ name = 'control metadata retained claim'; mutate = { param($r) $r.longname_control_metadata_retained = $true } },
    [PSCustomObject]@{ name = 'pair digest substitution'; mutate = { param($r) $r.archives[0].longname_pair_inventory_sha256 = '0' * 64 } },
    [PSCustomObject]@{ name = 'control metadata byte substitution'; mutate = { param($r) $r.archives[0].longname_control_metadata_bytes += 1L } },
    [PSCustomObject]@{ name = 'row ordered-dictionary shape'; mutate = { param($r) $r.archives[0] = [ordered]@{ archive_id = 'not-an-object' } } },
    [PSCustomObject]@{ name = 'row null format counts'; mutate = { param($r) $r.archives[0].format_counts = $null } },
    [PSCustomObject]@{ name = 'row unrecognized state'; mutate = { param($r) $r.archives[0].status = 'PASS' } },
    [PSCustomObject]@{ name = 'partial opened identity tuple'; mutate = { param($r) $r.archives[0].opened_archive_file_id_hex = $null } },
    [PSCustomObject]@{ name = 'fractional failure offset'; mutate = { param($r) $r.archives[0].first_failure_offset = 1.5 } },
    [PSCustomObject]@{ name = 'coverage ID mismatch'; mutate = { param($r) $r.archives[0].archive_id = 'other@1.0.0' } }
)
foreach ($mutation in $censusResultMutationCases) {
    $badCensusResult = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusCompleteResultFixture
    & $mutation.mutate $badCensusResult
    $mutationFailures = [System.Collections.Generic.List[string]]::new()
    $mutationAccepted = Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $badCensusResult -FailureReasons $mutationFailures
    Assert-D32BoundedCompilerDiagnosticSelfTest ("census result strict schema rejects $($mutation.name) and identifies a validator location") `
        (-not $mutationAccepted -and $mutationFailures.Count -gt 0)
}

$synthetic870ArchiveRefs = [System.Collections.Generic.List[object]]::new()
$synthetic870Rows = [System.Collections.Generic.List[object]]::new()
$synthetic870FormatCounts = [PSCustomObject][ordered]@{ ustar_regular = 1L; ustar_directory = 0L; gnu_regular = 0L; gnu_directory = 0L; gnu_longname_extension = 0L }
for ($index = 0; $index -lt 870; $index++) {
    $syntheticId = ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.UTF8Encoding]::new($false).GetBytes('D32-census-synthetic-metadata-' + $index))).ToLowerInvariant())
    $archive = New-D32BoundedCompilerDiagnosticTestCensusArchiveReference -Name ('synthetic-crate-' + $index.ToString('D4')) `
        -Version '1.0.0' -Sha256 $syntheticId -Bytes ([Int64](4096 + $index))
    $archive.volume_serial_hex = '0123456789abcdef'; $archive.file_id_hex = $syntheticId.Substring(0, 32)
    $synthetic870ArchiveRefs.Add($archive)
    $opened = [PSCustomObject][ordered]@{
        bytes = [Int64]$archive.bytes; sha256 = [string]$archive.sha256
        volume_serial_hex = [string]$archive.volume_serial_hex; file_id_hex = [string]$archive.file_id_hex
    }
    $inventory = [PSCustomObject][ordered]@{
        expanded_bytes = 1L; header_count = 1L; ordinary_header_count = 1L; longname_pair_count = 0L
        longname_pair_inventory_sha256 = Get-D32BoundedCompilerDiagnosticLongNamePairDigest -Pairs @()
        longname_control_metadata_count = 0L; longname_control_metadata_bytes = 0L
        longname_control_metadata_sha256 = Get-D32BoundedCompilerDiagnosticLongNameControlDigest -Pairs @()
        format_counts = $synthetic870FormatCounts
        header_inventory_sha256 = 'e' * 64; framing_verified = $true
        first_failure_offset = $null; first_failure_header_sha256 = $null; first_failure_reason = $null
    }
    $synthetic870Rows.Add((New-D32BoundedDiagnosticArchiveFormatCensusCoverageRow -Archive $archive -Status 'COMPLETE_SUPPORTED' `
        -OpenedReference $opened -Inventory $inventory -FailureReason $null))
}
$synthetic870Authority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$synthetic870Authority.archive_refs = [object[]]$synthetic870ArchiveRefs.ToArray()
$synthetic870Result = New-D32BoundedDiagnosticArchiveFormatCensusResult -Authority $synthetic870Authority `
    -AuthorityReference $censusAuthorityReferenceFixture -Status 'COMPLETE_DIAGNOSTIC' `
    -StartedAtUtc '2026-10-05T00:00:00.0000000+00:00' -CompletedAtUtc '2026-10-05T00:00:01.0000000+00:00' `
    -ElapsedMilliseconds 1000L -Archives ([object[]]$synthetic870Rows.ToArray()) -PrimaryError $null -SecondaryErrors @()
$synthetic870Readback = ConvertFrom-D32BoundedCompilerDiagnosticTestJson -Json (
    ConvertTo-Json -InputObject $synthetic870Result -Depth 100 -Compress -ErrorAction Stop)
$synthetic870Failures = [System.Collections.Generic.List[string]]::new()
$synthetic870Valid = Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $synthetic870Readback -FailureReasons $synthetic870Failures
$synthetic870BindingFailures = [System.Collections.Generic.List[string]]::new()
$synthetic870Bound = Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityCoverage -Result $synthetic870Readback `
    -Authority $synthetic870Authority -ExpectedAuthorityReference $censusAuthorityReferenceFixture -FailureReasons $synthetic870BindingFailures
$synthetic870Tamper = Copy-D32BoundedCompilerDiagnosticTestJson -Record $synthetic870Readback
$synthetic870Tamper.archives[869].archive_file_id_hex = '0' * 32
$synthetic870TamperFailures = [System.Collections.Generic.List[string]]::new()
$synthetic870TamperAccepted = Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityCoverage -Result $synthetic870Tamper `
    -Authority $synthetic870Authority -ExpectedAuthorityReference $censusAuthorityReferenceFixture -FailureReasons $synthetic870TamperFailures
Assert-D32BoundedCompilerDiagnosticSelfTest '870 synthetic finite archive references use the real row/result producers, survive strict JSON readback, bind in order through the final row, and reject a last-row identity substitution' `
    ($synthetic870Valid -and $synthetic870Bound -and $synthetic870Failures.Count -eq 0 -and
     $synthetic870BindingFailures.Count -eq 0 -and -not $synthetic870TamperAccepted -and
     $synthetic870TamperFailures.Count -eq 1 -and $synthetic870TamperFailures[0] -ceq 'archives[869].authority_archive_reference_binding')

$unsupportedArchiveBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries @(
    $layoutGnuMembers[0], [PSCustomObject]@{ format = 'GNU'; path = "$layoutRoot/src/rejected.rs"; kind = 'file'; type_flag = 'x'; content = [byte[]]@([byte]1) })
$unsupportedArchiveSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($unsupportedArchiveBytes)).ToLowerInvariant()
$unsupportedScan = Get-D32BoundedDiagnosticArchiveFormatCensusInventory -CompressedBytes $unsupportedArchiveBytes -ExpectedPackageRoot $layoutRoot `
    -ExpectedArchiveSha256 $unsupportedArchiveSha -CensusTimer ([Diagnostics.Stopwatch]::StartNew())
$unsupportedArchiveFixture = New-D32BoundedCompilerDiagnosticTestCensusArchiveReference -Sha256 $unsupportedArchiveSha -Bytes $unsupportedArchiveBytes.Length
$unsupportedOpenedReference = [PSCustomObject][ordered]@{
    bytes = [Int64]$unsupportedArchiveFixture.bytes; sha256 = [string]$unsupportedArchiveFixture.sha256
    volume_serial_hex = [string]$unsupportedArchiveFixture.volume_serial_hex; file_id_hex = [string]$unsupportedArchiveFixture.file_id_hex
}
$blockedRow = New-D32BoundedDiagnosticArchiveFormatCensusCoverageRow -Archive $unsupportedArchiveFixture `
    -Status 'UNSUPPORTED' -OpenedReference $unsupportedOpenedReference -Inventory $unsupportedScan `
    -FailureReason ([string]$unsupportedScan.first_failure_reason)
$blockedAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$blockedAuthority.archive_refs = @($unsupportedArchiveFixture)
$blockedResult = New-D32BoundedDiagnosticArchiveFormatCensusResult -Authority $blockedAuthority `
    -AuthorityReference $censusAuthorityReferenceFixture -Status 'BLOCKED' `
    -StartedAtUtc '2026-10-05T00:00:00.0000000+00:00' -CompletedAtUtc '2026-10-05T00:00:01.0000000+00:00' `
    -ElapsedMilliseconds 1000L -Archives @($blockedRow) -PrimaryError ([string]$unsupportedScan.first_failure_reason) `
    -SecondaryErrors @([string]$unsupportedScan.first_failure_reason)
$blockedCoverageFailures = [System.Collections.Generic.List[string]]::new()
$blockedCoverageValid = Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityCoverage -Result $blockedResult `
    -Authority $blockedAuthority -ExpectedAuthorityReference $censusAuthorityReferenceFixture -FailureReasons $blockedCoverageFailures
Assert-D32BoundedCompilerDiagnosticSelfTest 'strict unsupported census coverage preserves first failing header offset/hash, unknown remainder, source archive identity, and a non-PASS result' `
    ($unsupportedScan.status -ceq 'BLOCKED' -and $null -ne $unsupportedScan.first_failure_offset -and
     $null -ne $unsupportedScan.first_failure_header_sha256 -and
     [string]$blockedResult.primary_error -ceq [string]$unsupportedScan.first_failure_reason -and
     (Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $blockedResult) -and $blockedCoverageValid)
$preflightArchive = New-D32BoundedCompilerDiagnosticTestCensusArchiveReference -Name 'preflight-crate' -Version '1.0.0' -Sha256 ('d' * 64)
$preflightRow = New-D32BoundedDiagnosticArchiveFormatCensusCoverageRow -Archive $preflightArchive -Status 'PREFLIGHT_BLOCKED' `
    -OpenedReference $null -Inventory $null -FailureReason 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BLOCKED: synthetic identity preflight failed'
$preflightAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$preflightAuthority.archive_refs = @($preflightArchive)
$preflightResult = New-D32BoundedDiagnosticArchiveFormatCensusResult -Authority $preflightAuthority `
    -AuthorityReference $censusAuthorityReferenceFixture -Status 'BLOCKED' `
    -StartedAtUtc '2026-10-05T00:00:00.0000000+00:00' -CompletedAtUtc '2026-10-05T00:00:01.0000000+00:00' `
    -ElapsedMilliseconds 1000L -Archives @($preflightRow) -PrimaryError ([string]$preflightRow.first_failure_reason) `
    -SecondaryErrors @([string]$preflightRow.first_failure_reason)
Assert-D32BoundedCompilerDiagnosticSelfTest 'producer and strict consumer accept honest preflight-blocked coverage with absent opened-reference tuple and preserved primary reason' `
    (Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $preflightResult)
$budgetArchiveTwo = New-D32BoundedCompilerDiagnosticTestCensusArchiveReference -Name 'second-crate' -Version '2.0.0' -Sha256 ('c' * 64)
$budgetReason = 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: fixed test budget exhausted'
$budgetRow = New-D32BoundedDiagnosticArchiveFormatCensusCoverageRow -Archive $censusArchiveFixture -Status 'BUDGET_STOPPED' `
    -OpenedReference $null -Inventory $null -FailureReason $budgetReason
$unexaminedRow = New-D32BoundedDiagnosticArchiveFormatCensusUnexaminedRow -Archive $budgetArchiveTwo `
    -Reason 'D32_BOUNDED_DIAGNOSTIC_CENSUS_BUDGET_STOPPED: later authorized reference not opened'
$budgetAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$budgetAuthority.archive_refs = @($censusArchiveFixture, $budgetArchiveTwo)
$budgetResult = New-D32BoundedDiagnosticArchiveFormatCensusResult -Authority $budgetAuthority `
    -AuthorityReference $censusAuthorityReferenceFixture -Status 'BUDGET_STOPPED' `
    -StartedAtUtc '2026-10-05T00:00:00.0000000+00:00' -CompletedAtUtc '2026-10-05T00:00:01.0000000+00:00' `
    -ElapsedMilliseconds 1000L -Archives @($budgetRow, $unexaminedRow) -PrimaryError $budgetReason `
    -SecondaryErrors @($budgetReason, [string]$unexaminedRow.first_failure_reason)
$budgetOnlyAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $censusAuthorityFixture
$budgetOnlyAuthority.archive_refs = @($censusArchiveFixture)
$budgetOnlyResult = New-D32BoundedDiagnosticArchiveFormatCensusResult -Authority $budgetOnlyAuthority `
    -AuthorityReference $censusAuthorityReferenceFixture -Status 'BUDGET_STOPPED' `
    -StartedAtUtc '2026-10-05T00:00:00.0000000+00:00' -CompletedAtUtc '2026-10-05T00:00:01.0000000+00:00' `
    -ElapsedMilliseconds 1000L -Archives @($budgetRow) -PrimaryError $budgetReason -SecondaryErrors @($budgetReason)
$completeWithGap = Copy-D32BoundedCompilerDiagnosticTestJson -Record $budgetResult
$completeWithGap.status = 'COMPLETE_DIAGNOSTIC'; $completeWithGap.primary_error = $null
$completeWithGap.blocked_archive_count = 0L
Assert-D32BoundedCompilerDiagnosticSelfTest 'global budget result separates stopped archive and whole unexamined set, preserving explicit remainder uncertainty and never reporting COMPLETE' `
    ((Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $budgetResult) -and
     (Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $budgetOnlyResult) -and
     (Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityCoverage -Result $budgetResult -Authority $budgetAuthority -ExpectedAuthorityReference $censusAuthorityReferenceFixture) -and
     -not (Test-D32BoundedDiagnosticArchiveFormatCensusResult -Record $completeWithGap))

$censusEntryPathActual = Join-Path $PSScriptRoot 'd32-bounded-diagnostic-archive-format-census.ps1'
$censusEntryTokens = $null; $censusEntryParseErrors = $null
$censusEntryAst = [Management.Automation.Language.Parser]::ParseFile($censusEntryPathActual, [ref]$censusEntryTokens, [ref]$censusEntryParseErrors)
$censusEntryCommands = @($censusEntryAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
$censusForbiddenCommands = @($censusEntryCommands | Where-Object { [string]$_.GetCommandName() -match '^(?i:Start-Process|Start-Job|Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod|Import-Module|cargo|git|rustc)$' })
$censusScannerCalls = @($censusEntryCommands | Where-Object { [string]$_.GetCommandName() -ceq 'Get-D32BoundedDiagnosticArchiveFormatCensusInventory' })
$censusCoverageProducerCalls = @($censusEntryCommands | Where-Object { [string]$_.GetCommandName() -ceq 'New-D32BoundedDiagnosticArchiveFormatCensusCoverageRow' })
$censusResultProducerCalls = @($censusEntryCommands | Where-Object { [string]$_.GetCommandName() -ceq 'New-D32BoundedDiagnosticArchiveFormatCensusResult' })
$censusStrictResultValidatorCalls = @($censusEntryCommands | Where-Object { [string]$_.GetCommandName() -ceq 'Test-D32BoundedDiagnosticArchiveFormatCensusResult' })
$censusAuthorityCoverageCalls = @($censusEntryCommands | Where-Object { [string]$_.GetCommandName() -ceq 'Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityCoverage' })
Assert-D32BoundedCompilerDiagnosticSelfTest 'separate census entry parses cleanly, uses real row/result producers, strict in-memory and serialized readback validators, finite authority-set binding, create-new persistence, and one bounded in-process scanner without external commands' `
    ($censusEntryParseErrors.Count -eq 0 -and $censusForbiddenCommands.Count -eq 0 -and $censusScannerCalls.Count -eq 1 -and
     $censusCoverageProducerCalls.Count -eq 1 -and $censusResultProducerCalls.Count -eq 1 -and
     $censusStrictResultValidatorCalls.Count -eq 2 -and $censusAuthorityCoverageCalls.Count -eq 1 -and
     [string]$censusEntryAst.Extent.Text -match 'Test-D32BoundedDiagnosticArchiveFormatCensusAuthorityShape' -and
     [string]$censusEntryAst.Extent.Text -match 'CreateNew' -and
     [string]$censusEntryAst.Extent.Text -match 'ConvertFrom-D32PowerShellAuthorityJsonElement' -and
     -not ([string]$censusEntryAst.Extent.Text).Contains('New-D32BoundedDiagnosticSourceProofCandidateDocument'))

$legacyAuthorityShape = Copy-D32PowerShellAuthorityJsonShape -Value $authority
$legacyAuthorityShape.schema_version = 2L
$legacyAuthorityShape.record_type = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_AUTHORITY_V2'
Assert-D32BoundedCompilerDiagnosticSelfTest 'compiler-diagnostic authority V2 is rejected by the strict V3 policy migration' (-not (Test-D32BoundedCompilerDiagnosticAuthorityShape -Document $legacyAuthorityShape -ExpectedCandidateSha $testCandidate -Repository $testRepo `
    -ToolchainProfilePath $testProfilePath -ToolchainProfileSha256 ('2' * 64) -ModuleAuthorityPath $testModuleAuthorityPath `
    -ModuleAuthoritySha256 ('3' * 64) -PinnedGitPath $testGitPath -PinnedGitSha256 ('4' * 64) -ExpectedEnvironment $expectedEnvironment))
$legacySourceProofCandidate = [PSCustomObject][ordered]@{}
foreach ($property in $sourceProofCandidate.PSObject.Properties) { $legacySourceProofCandidate | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value }
$legacySourceProofCandidate.historical_origin = [ordered]@{ fetch_completion = 'NOT_RETAINED'; attempt_state = 'BLOCKED'; gate_authority = 'NONE' }
$legacySourceProofCandidate.proof_authority = [ordered]@{ path = [string]$sourceProofCandidate.proof_authority.path; sha256 = [string]$sourceProofCandidate.proof_authority.sha256 }
$legacySourceProofCandidate.proof_entry = [ordered]@{ path = [string]$sourceProofCandidate.proof_entry.path; sha256 = [string]$sourceProofCandidate.proof_entry.sha256 }
$legacyCandidateReasons = [System.Collections.Generic.List[string]]::new()
$legacyNestedDictionaryRejected = -not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $legacySourceProofCandidate -FailureReasons $legacyCandidateReasons)
Assert-D32BoundedCompilerDiagnosticSelfTest 'old producer shape with ordered-dictionary nested records is the exact strict-validator rejection cause' `
    ($legacyNestedDictionaryRejected -and $legacyCandidateReasons.Count -eq 1 -and $legacyCandidateReasons[0] -ceq 'historical-origin-object-shape')
$legacySourceProofCandidate.historical_origin = [PSCustomObject]@{ fetch_completion = 'NOT_RETAINED'; attempt_state = 'BLOCKED'; gate_authority = 'NONE' }
$legacyCandidateReasons.Clear()
$legacyAuthorityDictionaryRejected = -not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $legacySourceProofCandidate -FailureReasons $legacyCandidateReasons)
Assert-D32BoundedCompilerDiagnosticSelfTest 'legacy proof-authority dictionary independently fails its exact nested record shape' `
    ($legacyAuthorityDictionaryRejected -and $legacyCandidateReasons.Count -eq 1 -and $legacyCandidateReasons[0] -ceq 'proof-authority-object-shape')
$legacySourceProofCandidate.proof_authority = [PSCustomObject]@{ path = [string]$sourceProofCandidate.proof_authority.path; sha256 = [string]$sourceProofCandidate.proof_authority.sha256 }
$legacyCandidateReasons.Clear()
$legacyEntryDictionaryRejected = -not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $legacySourceProofCandidate -FailureReasons $legacyCandidateReasons)
Assert-D32BoundedCompilerDiagnosticSelfTest 'legacy proof-entry dictionary independently fails its exact nested record shape' `
    ($legacyEntryDictionaryRejected -and $legacyCandidateReasons.Count -eq 1 -and $legacyCandidateReasons[0] -ceq 'proof-entry-object-shape')
$dictionarySourceProofCandidate = Copy-D32PowerShellAuthorityJsonShape -Value $sourceProofCandidate
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof consumer rejects a dictionary root representation' `
    ($dictionarySourceProofCandidate -is [System.Collections.IDictionary] -and -not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $dictionarySourceProofCandidate))
$nestedDictionarySourceProofCandidate = [PSCustomObject][ordered]@{}
foreach ($property in $sourceProofCandidate.PSObject.Properties) { $nestedDictionarySourceProofCandidate | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value }
$nestedDictionarySourceProofCandidate.proof_entry = [ordered]@{ path = [string]$sourceProofCandidate.proof_entry.path; sha256 = [string]$sourceProofCandidate.proof_entry.sha256 }
$nestedCandidateReasons = [System.Collections.Generic.List[string]]::new()
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof consumer rejects a nested dictionary even when the candidate root is a PSCustomObject' `
    (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $nestedDictionarySourceProofCandidate -FailureReasons $nestedCandidateReasons) -and
     $nestedCandidateReasons.Count -eq 1 -and $nestedCandidateReasons[0] -ceq 'proof-entry-object-shape')
$sourceProofCandidateJson = ConvertTo-D32PowerShellAuthorityJsonText -Value $sourceProofCandidate
$sourceProofCandidateJsonDocument = [System.Text.Json.JsonDocument]::Parse($sourceProofCandidateJson)
try { $sourceProofCandidateRoundTrip = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $sourceProofCandidateJsonDocument.RootElement }
finally { $sourceProofCandidateJsonDocument.Dispose() }
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof success candidate survives module-free JSON roundtrip with graph/manifest arrays and dual pins' `
    ((Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidateRoundTrip) -and
     $sourceProofCandidateRoundTrip.source_pins -is [Array] -and $sourceProofCandidateRoundTrip.source_pins.Count -eq 5 -and
     $sourceProofCandidateRoundTrip.current_profile_lock_bindings -is [Array] -and $sourceProofCandidateRoundTrip.current_profile_lock_bindings.Count -eq 3 -and
     [string]$sourceProofCandidateRoundTrip.candidate_sha -ceq $sourceProofCurrentSha -and
     [string]$sourceProofCandidateRoundTrip.historical_origin_candidate_sha -ceq $script:D32BoundedDiagnosticHistoricalInv7CandidateSha)

$sourceProofBlockedCases = @(
    [PSCustomObject]@{ name = 'source exception'; elapsed = 412L; cause = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_CONTENT_BLOCKED: registry source mismatch' },
    [PSCustomObject]@{ name = 'exact deadline'; elapsed = 300000L; cause = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: combined proof deadline reached' },
    [PSCustomObject]@{ name = 'budget overrun'; elapsed = 300001L; cause = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: combined proof budget exceeded' },
    [PSCustomObject]@{ name = 'early bootstrap after persistence admission'; elapsed = 1L; cause = 'D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_BLOCKED: current profile unavailable' }
)
foreach ($blockedCase in $sourceProofBlockedCases) {
    $blockedCandidate = New-D32BoundedDiagnosticSourceProofCandidateDocument `
        -CandidateSha $sourceProofCurrentSha -HistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha `
        -Repository $testRepo -Status 'BLOCKED' `
        -ProofAuthorityPath 'C:\d32-diagnostic-policy-test\external\source-proof-authority.json' -ProofAuthoritySha256 ('a' * 64) `
        -ProofEntryPath $sourceProofEntryPath -ProofEntrySha256 ('b' * 64) `
        -ProofStartedAtUtc '2026-10-04T00:00:00.0000000+00:00' -ProofCompletedAtUtc '2026-10-04T00:00:01.0000000+00:00' `
        -ProofElapsedMilliseconds ([long]$blockedCase.elapsed) -ProofBudget $sourceProofAuthority.proof_budget -SourcePins @() `
        -CurrentProfileLockBindings $null -CurrentSourceClosure $null -PrimaryError ([string]$blockedCase.cause)
    $blockedReasons = [System.Collections.Generic.List[string]]::new()
    $blockedValid = Test-D32BoundedDiagnosticSourceProofCandidate -Record $blockedCandidate -FailureReasons $blockedReasons
    Assert-D32BoundedCompilerDiagnosticSelfTest "source-proof $($blockedCase.name) emits a valid non-gating failure candidate retaining primary cause" `
        ($blockedValid -and $blockedReasons.Count -eq 0 -and [string]$blockedCandidate.status -ceq 'BLOCKED' -and
         [string]$blockedCandidate.gate_authority -ceq 'NONE' -and [string]$blockedCandidate.primary_error -ceq [string]$blockedCase.cause -and
         $blockedCandidate.source_pins -is [Array] -and $blockedCandidate.source_pins.Count -eq 0 -and
         -not [bool]$blockedCandidate.formal_phase1_allowed -and -not [bool]$blockedCandidate.formal_aggregate_allowed)
}

$badResultGraphCount = [long]$sourceProofCandidate.current_source_closure.SourceGraphProof.locked_package_count
$sourceProofCandidate.current_source_closure.SourceGraphProof.locked_package_count = $badResultGraphCount + 1
$sourceProofShapeReasons = [System.Collections.Generic.List[string]]::new()
$badSuccessResultRejected = -not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate -FailureReasons $sourceProofShapeReasons)
$sourceProofCandidate.current_source_closure.SourceGraphProof.locked_package_count = $badResultGraphCount
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof result shape rejection exposes a specific graph-schema/witness category without weakening validation' `
    ($badSuccessResultRejected -and $sourceProofShapeReasons.Count -eq 1 -and $sourceProofShapeReasons[0] -ceq 'source-graph-proof-shape-or-witness')
$sourceProofFallbackCause = 'SOURCEPROOF_RESULT_SHAPE_REJECTED: ' + [string]::Join(',', [string[]]$sourceProofShapeReasons.ToArray())
$sourceProofFallback = New-D32BoundedDiagnosticSourceProofCandidateDocument `
    -CandidateSha $sourceProofCurrentSha -HistoricalOriginCandidateSha $script:D32BoundedDiagnosticHistoricalInv7CandidateSha `
    -Repository $testRepo -Status 'BLOCKED' `
    -ProofAuthorityPath 'C:\d32-diagnostic-policy-test\external\source-proof-authority.json' -ProofAuthoritySha256 ('a' * 64) `
    -ProofEntryPath $sourceProofEntryPath -ProofEntrySha256 ('b' * 64) `
    -ProofStartedAtUtc '2026-10-04T00:00:00.0000000+00:00' -ProofCompletedAtUtc '2026-10-04T00:00:01.0000000+00:00' `
    -ProofElapsedMilliseconds 1000L -ProofBudget $sourceProofAuthority.proof_budget -SourcePins $sourceProofPins `
    -CurrentProfileLockBindings $null -CurrentSourceClosure $null -PrimaryError $sourceProofFallbackCause
Assert-D32BoundedCompilerDiagnosticSelfTest 'invalid verified payload is downgraded to a legal blocked candidate that preserves the shape cause' `
    ((Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofFallback) -and
     [string]$sourceProofFallback.status -ceq 'BLOCKED' -and [string]$sourceProofFallback.primary_error -ceq $sourceProofFallbackCause -and
     $null -eq $sourceProofFallback.current_source_closure -and [string]$sourceProofFallback.candidate_sha -ceq $sourceProofCurrentSha -and
     [string]$sourceProofFallback.historical_origin_candidate_sha -ceq $script:D32BoundedDiagnosticHistoricalInv7CandidateSha)
$sourceProofFallbackJson = ConvertTo-D32PowerShellAuthorityJsonText -Value $sourceProofFallback
$sourceProofFallbackJsonDocument = [System.Text.Json.JsonDocument]::Parse($sourceProofFallbackJson)
try { $sourceProofFallbackRoundTrip = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $sourceProofFallbackJsonDocument.RootElement }
finally { $sourceProofFallbackJsonDocument.Dispose() }
Assert-D32BoundedCompilerDiagnosticSelfTest 'blocked source-proof primary error and dual candidate pins survive module-free JSON roundtrip' `
    ((Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofFallbackRoundTrip) -and
     [string]$sourceProofFallbackRoundTrip.status -ceq 'BLOCKED' -and
     [string]$sourceProofFallbackRoundTrip.primary_error -ceq $sourceProofFallbackCause -and
     [string]$sourceProofFallbackRoundTrip.candidate_sha -ceq $sourceProofCurrentSha -and
     [string]$sourceProofFallbackRoundTrip.historical_origin_candidate_sha -ceq $script:D32BoundedDiagnosticHistoricalInv7CandidateSha)

$sourceProofCandidate.PSObject.Properties.Remove('primary_error')
$sourceProofMissingResultFieldRejected = -not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate)
$sourceProofCandidate | Add-Member -NotePropertyName primary_error -NotePropertyValue $null
$sourceProofCandidate | Add-Member -NotePropertyName unexpected_result_field -NotePropertyValue 'must fail closed'
$sourceProofExtraResultFieldRejected = -not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate)
$sourceProofCandidate.PSObject.Properties.Remove('unexpected_result_field')
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof result exact-field negatives reject missing and extra top-level properties' `
    ($sourceProofMissingResultFieldRejected -and $sourceProofExtraResultFieldRejected)
$candidateClosureSha = [string]$sourceProofCandidate.current_source_closure.CurrentCandidateSha
$sourceProofCandidate.current_source_closure.CurrentCandidateSha = [string]$sourceProofCandidate.historical_origin_candidate_sha
Assert-D32BoundedCompilerDiagnosticSelfTest 'current source closure cannot be rebound to historical inv7 SHA' (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate))
$sourceProofCandidate.current_source_closure.CurrentCandidateSha = $candidateClosureSha
$candidateTopSha = [string]$sourceProofCandidate.candidate_sha
$sourceProofCandidate.candidate_sha = [string]$sourceProofCandidate.historical_origin_candidate_sha
Assert-D32BoundedCompilerDiagnosticSelfTest 'current source proof candidate SHA cannot be swapped to the historical inv7 SHA' (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate))
$sourceProofCandidate.candidate_sha = $candidateTopSha
$registryIdsBeforeTamper = @($sourceProofCandidate.current_source_closure.RegistryContentProof.verified_package_ids)
$sourceProofCandidate.current_source_closure.RegistryContentProof.verified_package_ids = @($registryIdsBeforeTamper | Select-Object -Skip 1)
Assert-D32BoundedCompilerDiagnosticSelfTest 'every included registry source package must cross-bind to its exact content proof ID' (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate))
$sourceProofCandidate.current_source_closure.RegistryContentProof.verified_package_ids = $registryIdsBeforeTamper
$workspaceProofIndex = -1
for ($proofIndex = 0; $proofIndex -lt $sourceProofCandidate.current_source_closure.CurrentManifestProof.Count; $proofIndex++) {
    if ([string]$sourceProofCandidate.current_source_closure.CurrentManifestProof[$proofIndex].manifest_path -ceq 'vita-agent/Cargo.toml') { $workspaceProofIndex = $proofIndex; break }
}
if ($workspaceProofIndex -lt 0) { throw 'D32_BOUNDED_COMPILER_DIAGNOSTIC_SELFTEST_FAILED: workspace manifest fixture is missing' }
$workspaceProofSha = [string]$sourceProofCandidate.current_source_closure.CurrentManifestProof[$workspaceProofIndex].sha256
$sourceProofCandidate.current_source_closure.CurrentManifestProof[$workspaceProofIndex].sha256 = 'e' * 64
Assert-D32BoundedCompilerDiagnosticSelfTest 'current workspace manifest digest cannot be swapped independently of its included graph classification' (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate))
$sourceProofCandidate.current_source_closure.CurrentManifestProof[$workspaceProofIndex].sha256 = $workspaceProofSha
$rootWitness = @($sourceProofCandidate.current_source_closure.SourceGraphProof.classifications | Where-Object { $_.classification -ceq 'INCLUDED' -and $_.source_kind -ceq 'workspace' -and $_.manifest_path -ceq 'vita-agent/Cargo.toml' })[0]
$rootWitness.witness_root_path[0] = 'stale-cross-run-root'
Assert-D32BoundedCompilerDiagnosticSelfTest 'stale/cross-run root path witness cannot pass source graph proof validation' (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate))
$rootWitness.witness_root_path[0] = [string]$sourceProofCandidate.current_source_closure.SourceGraphProof.selected_root_ids[0]
$bindingLockSha = [string]$sourceProofCandidate.current_profile_lock_bindings[1].lock_sha256
$sourceProofCandidate.current_profile_lock_bindings[1].lock_sha256 = 'f' * 64
Assert-D32BoundedCompilerDiagnosticSelfTest 'source graph lock digest must cross-bind to the current Profile V2 lock tuple' (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate))
$sourceProofCandidate.current_profile_lock_bindings[1].lock_sha256 = $bindingLockSha
$sourceProofPlanVersion = [int]$sourceProofCandidate.source_plan_semantics_version
$sourceProofCandidate.source_plan_semantics_version = 1
Assert-D32BoundedCompilerDiagnosticSelfTest 'source proof candidate with prior graph semantics version cannot be reused' (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate))
$sourceProofCandidate.source_plan_semantics_version = $sourceProofPlanVersion
$sourceProofCandidate.status = 'PASS'
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof-only candidate cannot acquire a PASS status' (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate))
$sourceProofCandidate.status = 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY'
$sourceProofCandidate.gate_authority = 'PHASE0'
Assert-D32BoundedCompilerDiagnosticSelfTest 'source-proof-only candidate cannot acquire formal gate authority' (-not (Test-D32BoundedDiagnosticSourceProofCandidate -Record $sourceProofCandidate))
try { $null = Assert-D32BoundedCompilerDiagnosticStatus 'PASS'; $passStatusRejected = $false } catch { $passStatusRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'PASS status unavailable' $passStatusRejected
$rawReplayStatuses = @('COMPLETED_DIAGNOSTIC', 'BUDGET_STOPPED', 'REFUSED', 'UNRESOLVED')
foreach ($rawStatus in $rawReplayStatuses) {
    $replay = [PSCustomObject]@{ record_type = $script:D32BoundedCompilerDiagnosticResultType; schema_version = 3; registry_archive_policy = $script:D32BoundedDiagnosticRegistryArchivePolicy; gate_authority = 'NONE'; status = $rawStatus; phase1_allowed = $false; aggregate_allowed = $false }
    Assert-D32BoundedCompilerDiagnosticStatus $rawStatus | Out-Null
    Assert-D32BoundedCompilerDiagnosticSelfTest "raw replay $rawStatus remains non-gating" (Test-D32BoundedCompilerDiagnosticFormalReject $replay -and -not [bool]$replay.phase1_allowed -and -not [bool]$replay.aggregate_allowed)
}
$formalConsumerSchemas = @(
    [PSCustomObject]@{ path = (Join-Path $PSScriptRoot 'd32-preflight.ps1'); schema = 'D32_PHASE0_MATRIX_RECORD_V8' },
    [PSCustomObject]@{ path = (Join-Path $PSScriptRoot 'd32-phase0-matrix.ps1'); schema = 'D32_PHASE0_MATRIX_RECORD_V8' },
    [PSCustomObject]@{ path = (Join-Path $PSScriptRoot 'd32-downstream-readiness.ps1'); schema = 'D32_POST_BUNDLE_AGGREGATE_RECORD_V8' }
)
# Shared SourceProof lifecycle V1 is exercised with synthetic QPC records only.
# No lifecycle entry, native method, child process, cache object, or source file
# is opened from these fixtures.
$lifecycleControllerPath = Join-Path $testRepo 'scripts\d32-bounded-diagnostic-sourceproof-controller.ps1'
$lifecycleCandidateSha = $sourceProofCurrentSha
$lifecycleRunId = '8' * 32
$lifecycleParent = 'C:\d32-diagnostic-policy-test\lifecycle-output'
$lifecycleOutput = [PSCustomObject][ordered]@{
    candidate_path = Join-Path $lifecycleParent 'source-proof-candidate.json'
    execution_record_path = Join-Path $lifecycleParent 'source-proof-execution.json'
    journal_path = Join-Path $lifecycleParent 'source-proof-journal.jsonl'
    parent_path = $lifecycleParent
    parent_volume_serial_hex = '1122334455667788'
    parent_file_id_hex = '11223344556677881122334455667788'
}
$lifecyclePins = @((New-D32BoundedCompilerDiagnosticTestReference $lifecycleControllerPath)) + @($sourceProofPins)
$lifecycleInnerAuthority = Copy-D32BoundedCompilerDiagnosticTestJson -Record $sourceProofAuthority
$lifecycleInnerAuthority.run_id = $lifecycleRunId
$lifecycleInnerAuthority.output_candidate.path = $lifecycleOutput.candidate_path
$lifecycleInnerAuthority.output_candidate.parent_path = $lifecycleParent
$lifecycleInnerAuthority.output_candidate.parent_volume_serial_hex = $lifecycleOutput.parent_volume_serial_hex
$lifecycleInnerAuthority.output_candidate.parent_file_id_hex = $lifecycleOutput.parent_file_id_hex
$lifecycleSourceAuthorityReference = New-D32BoundedCompilerDiagnosticTestReference 'C:\d32-diagnostic-policy-test\external\lifecycle-source-proof-authority.json'
$lifecycleProfileReference = $lifecycleInnerAuthority.toolchain_profile
$lifecycleRuntime = [PSCustomObject][ordered]@{
    path = 'C:\Program Files\PowerShell\7\pwsh.exe'; bytes = 4096L; sha256 = 'd' * 64
    volume_serial_hex = '2233445566778899'; file_id_hex = '22334455667788992233445566778899'
    powershell_home = 'C:\Program Files\PowerShell\7'; system_root = 'C:\Windows'
}
$lifecycleFrequency = [Int64][Diagnostics.Stopwatch]::Frequency
$lifecycleT0 = [Int64]1000000000
$lifecycleClockInput = [PSCustomObject][ordered]@{ counter_origin = 'QueryPerformanceCounter'; frequency = $lifecycleFrequency }
$lifecycleAuthority = New-D32BoundedDiagnosticSourceProofExecutionAuthorityCandidate `
    -CandidateSha $lifecycleCandidateSha -Repository $testRepo `
    -RepositoryIdentity $sourceProofAuthority.repository_identity -RunId $lifecycleRunId -OwnerId 'synthetic-lifecycle-test' `
    -SourceProofAuthorityReference $lifecycleSourceAuthorityReference -ToolchainProfileReference $lifecycleProfileReference `
    -PowerShellRuntime $lifecycleRuntime -SourcePins $lifecyclePins -Output $lifecycleOutput -Clock $lifecycleClockInput `
    -IssuedAtUtc '2026-10-04T00:00:00.0000000+00:00'
Assert-D32BoundedCompilerDiagnosticSelfTest 'lifecycle authority candidate producer creates the frozen exact V1 authority shape' `
    (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityShape -Document $lifecycleAuthority -ExpectedCandidateSha $lifecycleCandidateSha -Repository $testRepo)
Assert-D32BoundedCompilerDiagnosticSelfTest 'execution authority binds all six fixed source pins and the unchanged inner SourceProof V3 run/output/profile' `
    (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityBindings -ExecutionAuthority $lifecycleAuthority `
        -SourceProofAuthority $lifecycleInnerAuthority -SourceProofAuthorityReference $lifecycleSourceAuthorityReference `
        -ExpectedCandidateSha $lifecycleCandidateSha -Repository $testRepo)
$lifecycleAuthorityJson = ConvertTo-D32PowerShellAuthorityJsonText -Value $lifecycleAuthority
$lifecycleAuthorityRoundTrip = ConvertFrom-D32BoundedCompilerDiagnosticTestJson -Json $lifecycleAuthorityJson
Assert-D32BoundedCompilerDiagnosticSelfTest 'execution authority producer survives duplicate-aware module-free JSON serialization/readback and strict revalidation' `
    ((Test-D32BoundedDiagnosticSourceProofExecutionAuthorityShape -Document $lifecycleAuthorityRoundTrip -ExpectedCandidateSha $lifecycleCandidateSha -Repository $testRepo) -and
     (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityBindings -ExecutionAuthority $lifecycleAuthorityRoundTrip `
        -SourceProofAuthority $lifecycleInnerAuthority -SourceProofAuthorityReference $lifecycleSourceAuthorityReference `
        -ExpectedCandidateSha $lifecycleCandidateSha -Repository $testRepo))
$lifecycleAuthorityBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleAuthority
$lifecycleAuthorityBad.timing_policy = 'D32_SOURCEPROOF_LIFECYCLE_V0'
Assert-D32BoundedCompilerDiagnosticSelfTest 'old lifecycle timing policy cannot be substituted into a fresh execution authority' `
    (-not (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityShape -Document $lifecycleAuthorityBad -ExpectedCandidateSha $lifecycleCandidateSha -Repository $testRepo))
$lifecycleAuthorityBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleAuthority
$lifecycleAuthorityBad.limits.cleanup_deadline_milliseconds = 360000L
Assert-D32BoundedCompilerDiagnosticSelfTest 'authority cannot expand cleanup or audit-only deadlines' `
    (-not (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityShape -Document $lifecycleAuthorityBad -ExpectedCandidateSha $lifecycleCandidateSha -Repository $testRepo))
$lifecycleAuthorityBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleAuthority
$lifecycleAuthorityBad.clock | Add-Member -NotePropertyName child_t0_ticks -NotePropertyValue $lifecycleT0
Assert-D32BoundedCompilerDiagnosticSelfTest 'authority clock rejects a reader-local reset field' `
    (-not (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityShape -Document $lifecycleAuthorityBad -ExpectedCandidateSha $lifecycleCandidateSha -Repository $testRepo))
$lifecycleAuthorityBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleAuthority
$lifecycleAuthorityBad.source_pins[2] = $lifecycleAuthorityBad.source_pins[1]
Assert-D32BoundedCompilerDiagnosticSelfTest 'authority fixed source closure rejects duplicate/reordered pin identity' `
    (-not (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityShape -Document $lifecycleAuthorityBad -ExpectedCandidateSha $lifecycleCandidateSha -Repository $testRepo))
$lifecycleAuthorityBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleAuthority
$lifecycleAuthorityBad.limits.work_milliseconds = '270000'
Assert-D32BoundedCompilerDiagnosticSelfTest 'execution authority rejects numeric-looking string limits instead of coercing JSON types' `
    (-not (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityShape -Document $lifecycleAuthorityBad -ExpectedCandidateSha $lifecycleCandidateSha -Repository $testRepo))

function New-D32LifecycleSelfTestClock {
    param([long]$T0, [long]$Frequency, [AllowNull()][object]$Create = $null, [AllowNull()][object]$Resume = $null,
        [AllowNull()][object]$Exit = $null, [AllowNull()][object]$Artifact = $null, [AllowNull()][object]$Cleanup = $null)
    return [PSCustomObject][ordered]@{
        counter_origin = 'QueryPerformanceCounter'; frequency = $Frequency; t0_ticks = $T0
        work_deadline_ticks = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $T0 -Frequency $Frequency -DeadlineMilliseconds 270000L
        proof_expiry_ticks = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $T0 -Frequency $Frequency -DeadlineMilliseconds 300000L
        cleanup_deadline_ticks = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $T0 -Frequency $Frequency -DeadlineMilliseconds 345000L
        terminal_audit_deadline_ticks = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $T0 -Frequency $Frequency -DeadlineMilliseconds 360000L
        controller_entry_ticks = $T0 + 10L; reader_create_attempt_ticks = $Create; reader_resume_ticks = $Resume
        reader_exit_ticks = $Exit; artifact_verified_ticks = $Artifact; cleanup_verified_ticks = $Cleanup
        audit_persisted_ticks = $null; observed_ticks = $T0 + 20L
    }
}
function New-D32LifecycleSelfTestEvent {
    param([string]$Name, [long]$Observed, [AllowNull()][object]$Scheduled = $null)
    return [PSCustomObject][ordered]@{
        event = $Name; scheduled_ticks = if ($null -eq $Scheduled) { $null } else { [Int64]$Scheduled }
        observed_ticks = $Observed
        lateness_ticks = if ($null -eq $Scheduled) { $null } else { [Int64]($Observed - [Int64]$Scheduled) }
    }
}
function New-D32LifecycleSelfTestRecord {
    param([string]$Status, [object]$Clock, [object[]]$Events, [object]$Reader, [object]$Artifact,
        [object]$Captures, [object]$Cleanup, [AllowNull()][string]$PrimaryError)
    $authorityReference = New-D32BoundedCompilerDiagnosticTestReference 'C:\d32-diagnostic-policy-test\external\lifecycle-execution-authority.json'
    $authorityReference.bytes = 4096L; $authorityReference.sha256 = 'f' * 64
    $runtimeReference = [PSCustomObject][ordered]@{ path = $lifecycleRuntime.path; bytes = $lifecycleRuntime.bytes; sha256 = $lifecycleRuntime.sha256; volume_serial_hex = $lifecycleRuntime.volume_serial_hex; file_id_hex = $lifecycleRuntime.file_id_hex }
    return New-D32BoundedDiagnosticSourceProofExecutionResultCandidate `
        -CandidateSha $lifecycleCandidateSha -RunId $lifecycleRunId -AuthorityReference $authorityReference `
        -SourcePins $lifecycleAuthority.source_pins -PowerShellRuntime $runtimeReference -Output $lifecycleAuthority.output `
        -Status $Status -Clock $Clock -Controller ([PSCustomObject]@{ process_id = 100; creation_filetime_ticks = 1000L }) `
        -Reader $Reader -Artifact $Artifact -Captures $Captures -Cleanup $Cleanup -Events $Events `
        -PrimaryError $PrimaryError -StartedAtUtc '2026-10-04T00:00:00.0000000+00:00' -CompletedAtUtc '2026-10-04T00:00:02.0000000+00:00'
}

$lifecycleWork = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $lifecycleT0 -Frequency $lifecycleFrequency -DeadlineMilliseconds 270000L
$lifecycleExpiry = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $lifecycleT0 -Frequency $lifecycleFrequency -DeadlineMilliseconds 300000L
$lifecycleCleanup = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $lifecycleT0 -Frequency $lifecycleFrequency -DeadlineMilliseconds 345000L
$lifecycleTerminal = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $lifecycleT0 -Frequency $lifecycleFrequency -DeadlineMilliseconds 360000L
$lifecyclePhaseCases = @(
    [PSCustomObject]@{ ticks = [Int64]($lifecycleWork - 1); phase = 'PROOF_WORK' },
    [PSCustomObject]@{ ticks = $lifecycleWork; phase = 'FINALIZATION_ONLY' },
    [PSCustomObject]@{ ticks = [Int64]($lifecycleExpiry - 1); phase = 'FINALIZATION_ONLY' },
    [PSCustomObject]@{ ticks = $lifecycleExpiry; phase = 'CLEANUP_ONLY' },
    [PSCustomObject]@{ ticks = [Int64]($lifecycleCleanup - 1); phase = 'CLEANUP_ONLY' },
    [PSCustomObject]@{ ticks = $lifecycleCleanup; phase = 'AUDIT_ONLY' },
    [PSCustomObject]@{ ticks = [Int64]($lifecycleTerminal - 1); phase = 'AUDIT_ONLY' },
    [PSCustomObject]@{ ticks = $lifecycleTerminal; phase = 'EXPIRED' })
$lifecyclePhaseValid = $true
foreach ($case in $lifecyclePhaseCases) {
    if ((Get-D32BoundedDiagnosticSourceProofLifecyclePhase -T0Ticks $lifecycleT0 -Frequency $lifecycleFrequency -NowTicks $case.ticks) -cne $case.phase) { $lifecyclePhaseValid = $false; break }
}
Assert-D32BoundedCompilerDiagnosticSelfTest 'shared monotonic phase boundaries are exact at 269999/270000, 299999/300000, 345000 and 360000' $lifecyclePhaseValid
$lifecycleClockRollbackRejected = $false
try { $null = Get-D32BoundedDiagnosticSourceProofElapsedMilliseconds -T0Ticks $lifecycleT0 -Frequency $lifecycleFrequency -NowTicks ($lifecycleT0 - 1) } catch { $lifecycleClockRollbackRejected = $true }
$lifecycleClockOverflowRejected = $false
try { $null = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks ([Int64]::MaxValue - 1) -Frequency $lifecycleFrequency -DeadlineMilliseconds 360000L } catch { $lifecycleClockOverflowRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'shared monotonic counter rollback and checked deadline overflow fail closed' ($lifecycleClockRollbackRejected -and $lifecycleClockOverflowRejected)

$lifecycleClock = New-D32LifecycleSelfTestClock -T0 $lifecycleT0 -Frequency $lifecycleFrequency `
    -Create ($lifecycleT0 + 100L) -Resume ($lifecycleT0 + 130L) -Exit ($lifecycleT0 + 200L) `
    -Artifact ($lifecycleT0 + 250L) -Cleanup ($lifecycleT0 + 300L)
$lifecycleEvents = @(
    (New-D32LifecycleSelfTestEvent -Name 'AUTHORITY_ADMISSION' -Scheduled $lifecycleT0 -Observed ($lifecycleT0 + 50L)),
    (New-D32LifecycleSelfTestEvent -Name 'READER_CREATE_ATTEMPT' -Scheduled $lifecycleClock.reader_create_attempt_ticks -Observed ($lifecycleClock.reader_create_attempt_ticks + 1L)),
    (New-D32LifecycleSelfTestEvent -Name 'READER_ASSIGNED_TO_JOB' -Scheduled $lifecycleClock.reader_create_attempt_ticks -Observed ($lifecycleT0 + 110L)),
    (New-D32LifecycleSelfTestEvent -Name 'READER_RESUMED' -Observed $lifecycleClock.reader_resume_ticks),
    (New-D32LifecycleSelfTestEvent -Name 'READER_EXIT' -Observed $lifecycleClock.reader_exit_ticks),
    (New-D32LifecycleSelfTestEvent -Name 'CLEANUP_VERIFIED' -Observed $lifecycleClock.cleanup_verified_ticks),
    (New-D32LifecycleSelfTestEvent -Name 'TERMINAL_AUDIT' -Scheduled $lifecycleCleanup -Observed ($lifecycleCleanup + 10L)))
$lifecycleReader = [PSCustomObject][ordered]@{ launch_attempt_count = 1L; process_id = 4242L; creation_filetime_ticks = 424200L; job_instance_id = 'a' * 32; job_assignment = 'ASSIGNED'; exit_code = 0 }
$emptyCaptureSha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
$lifecycleCaptures = [PSCustomObject][ordered]@{ stdout_bytes = 0L; stdout_sha256 = $emptyCaptureSha; stdout_truncated = $false; stderr_bytes = 0L; stderr_sha256 = $emptyCaptureSha; stderr_truncated = $false; allowlisted_marker_count = 0L; output_unavailable = $false }
$lifecycleArtifact = [PSCustomObject][ordered]@{ state = 'VERIFIED'; path = $lifecycleOutput.candidate_path; bytes = 2048L; sha256 = 'b' * 64; volume_serial_hex = '1122334455667788'; file_id_hex = '33445566778899aa33445566778899aa'; inner_status = 'CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY' }
$lifecycleCleanupRecord = [PSCustomObject][ordered]@{ state = 'VERIFIED'; termination_requested = $false; join_verified = $true; job_active_process_count = 0L; job_closed = $true; kill_on_close_enabled = $true }
$lifecycleResult = New-D32LifecycleSelfTestRecord -Status 'COMPLETED_DIAGNOSTIC_ONLY' -Clock $lifecycleClock -Events $lifecycleEvents `
    -Reader $lifecycleReader -Artifact $lifecycleArtifact -Captures $lifecycleCaptures -Cleanup $lifecycleCleanupRecord -PrimaryError $null
Assert-D32BoundedCompilerDiagnosticSelfTest 'complete lifecycle result producer emits a strictly valid non-gating completed record' `
    (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleResult)
$lifecycleResultAuthorityReference = $lifecycleResult.authority
Assert-D32BoundedCompilerDiagnosticSelfTest 'execution result binds the authority SHA, current six source pins, runtime, candidate output and deadlines' `
    (Test-D32BoundedDiagnosticSourceProofExecutionResultBindings -Record $lifecycleResult -ExecutionAuthority $lifecycleAuthority `
        -ExecutionAuthorityReference $lifecycleResultAuthorityReference -ExpectedExecutionAuthoritySha256 ([string]$lifecycleResultAuthorityReference.sha256) `
        -ExpectedExecutionAuthorityPath ([string]$lifecycleResultAuthorityReference.path))
$lifecycleResultJson = ConvertTo-D32PowerShellAuthorityJsonText -Value $lifecycleResult
$lifecycleResultRoundTrip = ConvertFrom-D32BoundedCompilerDiagnosticTestJson -Json $lifecycleResultJson
Assert-D32BoundedCompilerDiagnosticSelfTest 'execution result producer survives duplicate-aware JSON readback and strict consumer bindings' `
    (Test-D32BoundedDiagnosticSourceProofExecutionResultBindings -Record $lifecycleResultRoundTrip -ExecutionAuthority $lifecycleAuthority `
        -ExecutionAuthorityReference $lifecycleResultAuthorityReference -ExpectedExecutionAuthoritySha256 ([string]$lifecycleResultAuthorityReference.sha256) `
        -ExpectedExecutionAuthorityPath ([string]$lifecycleResultAuthorityReference.path))
Assert-D32BoundedCompilerDiagnosticSelfTest 'lifecycle execution result is rejected by formal candidate status gate' (Test-D32BoundedCompilerDiagnosticFormalReject $lifecycleResultRoundTrip)

$lifecycleBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleResult
$lifecycleBad.gate_authority = 'PHASE0'
Assert-D32BoundedCompilerDiagnosticSelfTest 'lifecycle result cannot gain formal gate authority' (-not (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleBad))
$lifecycleBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleResult
$lifecycleBad | Add-Member -NotePropertyName unexpected_checkpoint -NotePropertyValue $true
Assert-D32BoundedCompilerDiagnosticSelfTest 'lifecycle result rejects extra checkpoint fields' (-not (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleBad))
$lifecycleBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleResult
$lifecycleBad.reader.creation_filetime_ticks = $null
Assert-D32BoundedCompilerDiagnosticSelfTest 'completed status requires the retained process creation identity in addition to PID' (-not (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleBad))
$lifecycleBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleResult
$lifecycleBad.clock.cleanup_verified_ticks = $lifecycleExpiry
Assert-D32BoundedCompilerDiagnosticSelfTest 'late cleanup after 300 seconds rejects a completed-diagnostic claim even when exit is zero' (-not (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleBad))
$lifecycleBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleResult
$lifecycleBad.clock.reader_exit_ticks = $lifecycleExpiry
$lifecycleBad.events[4].observed_ticks = $lifecycleExpiry
Assert-D32BoundedCompilerDiagnosticSelfTest 'reader exit observed exactly at 300 seconds loses the exit/deadline race and cannot complete' (-not (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleBad))
$lifecycleBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleResult
$lifecycleBad.captures.stdout_bytes = 16001L
Assert-D32BoundedCompilerDiagnosticSelfTest 'execution result rejects a stdout capture larger than its fixed 16000-byte retained prefix' (-not (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleBad))
$lifecycleBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleResult
$lifecycleBad.events[1].scheduled_ticks = $lifecycleWork
$lifecycleBad.events[1].observed_ticks = $lifecycleWork + 1L
$lifecycleBad.events[1].lateness_ticks = 1L
$lifecycleBad.clock.reader_create_attempt_ticks = $lifecycleWork
Assert-D32BoundedCompilerDiagnosticSelfTest 'reader creation at the work cutoff is not admitted as a completed run' (-not (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleBad))
$lifecycleBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleResult
$lifecycleBad.events[6].scheduled_ticks = $lifecycleCleanup + 1L
$lifecycleBad.events[6].observed_ticks = $lifecycleCleanup + 2L
$lifecycleBad.events[6].lateness_ticks = 1L
Assert-D32BoundedCompilerDiagnosticSelfTest 'terminal audit cannot be rebound to a later deadline' (-not (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleBad))
$lifecycleBad = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleResult
$lifecycleBad.events[1].event = 'READER_RESUMED'
Assert-D32BoundedCompilerDiagnosticSelfTest 'duplicate event names and launch/resume event substitution are rejected' (-not (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleBad))
$lifecycleLateSuccess = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleResult
$lifecycleLateSuccess.clock.reader_exit_ticks = $lifecycleExpiry + 1L
$lifecycleLateSuccess.clock.cleanup_verified_ticks = $lifecycleExpiry + 2L
$lifecycleLateSuccess.events[4].observed_ticks = $lifecycleExpiry + 1L
$lifecycleLateSuccess.events[5].observed_ticks = $lifecycleExpiry + 2L
$lifecycleLateSuccess.events[6].observed_ticks = $lifecycleCleanup + 10L
Assert-D32BoundedCompilerDiagnosticSelfTest 'late exit zero and later cleanup cannot be promoted by status mutation to completed proof' (-not (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleLateSuccess))
$lifecyclePartial = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleResult
$lifecyclePartial.status = 'UNRESOLVED'
$lifecyclePartial.primary_error = 'synthetic partial candidate must remain unresolved'
$lifecyclePartial.artifact.state = 'PARTIAL_OR_UNCONFIRMED'
$lifecyclePartial.artifact.bytes = $null; $lifecyclePartial.artifact.sha256 = $null
$lifecyclePartial.artifact.volume_serial_hex = $null; $lifecyclePartial.artifact.file_id_hex = $null; $lifecyclePartial.artifact.inner_status = $null
$lifecyclePartial.clock.artifact_verified_ticks = $null
Assert-D32BoundedCompilerDiagnosticSelfTest 'partial candidate output cannot be upgraded by reader exit zero' (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecyclePartial)
$duplicateLifecycleJson = $lifecycleResultJson.Replace('"gate_authority":"NONE"', '"gate_authority":"NONE","gate_authority":"PHASE0"')
$duplicateLifecycleDocument = [System.Text.Json.JsonDocument]::Parse($duplicateLifecycleJson)
try { $lifecycleDuplicateRejected = Test-D32PowerShellAuthorityJsonDuplicates -Element $duplicateLifecycleDocument.RootElement }
finally { $duplicateLifecycleDocument.Dispose() }
Assert-D32BoundedCompilerDiagnosticSelfTest 'duplicate JSON properties in lifecycle results are rejected before schema projection' $lifecycleDuplicateRejected

$lifecycleRefusedClock = New-D32LifecycleSelfTestClock -T0 $lifecycleT0 -Frequency $lifecycleFrequency
$lifecycleRefusedEvents = @(
    (New-D32LifecycleSelfTestEvent -Name 'AUTHORITY_ADMISSION' -Scheduled $lifecycleT0 -Observed ($lifecycleT0 + 50L)),
    (New-D32LifecycleSelfTestEvent -Name 'TERMINAL_AUDIT' -Scheduled $lifecycleCleanup -Observed ($lifecycleCleanup + 10L)))
$lifecycleRefusedReader = [PSCustomObject][ordered]@{ launch_attempt_count = 0L; process_id = $null; creation_filetime_ticks = $null; job_instance_id = $null; job_assignment = 'NOT_ATTEMPTED'; exit_code = $null }
$lifecycleNotReadArtifact = [PSCustomObject][ordered]@{ state = 'NOT_READ'; path = $lifecycleOutput.candidate_path; bytes = $null; sha256 = $null; volume_serial_hex = $null; file_id_hex = $null; inner_status = $null }
$lifecycleNotStartedCleanup = [PSCustomObject][ordered]@{ state = 'NOT_STARTED'; termination_requested = $false; join_verified = $false; job_active_process_count = $null; job_closed = $false; kill_on_close_enabled = $false }
$lifecycleRefused = New-D32LifecycleSelfTestRecord -Status 'REFUSED' -Clock $lifecycleRefusedClock -Events $lifecycleRefusedEvents `
    -Reader $lifecycleRefusedReader -Artifact $lifecycleNotReadArtifact -Captures $lifecycleCaptures -Cleanup $lifecycleNotStartedCleanup `
    -PrimaryError 'synthetic strict prelaunch refusal'
Assert-D32BoundedCompilerDiagnosticSelfTest 'strict prelaunch refusal is a durable no-launch status, not a proof result' `
    (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleRefused)

$lifecycleBudgetClock = New-D32LifecycleSelfTestClock -T0 $lifecycleT0 -Frequency $lifecycleFrequency `
    -Create ($lifecycleT0 + 100L) -Resume ($lifecycleT0 + 130L) -Exit ($lifecycleExpiry + 3L) -Cleanup ($lifecycleExpiry + 100L)
$lifecycleBudgetEvents = @(
    (New-D32LifecycleSelfTestEvent -Name 'AUTHORITY_ADMISSION' -Scheduled $lifecycleT0 -Observed ($lifecycleT0 + 50L)),
    (New-D32LifecycleSelfTestEvent -Name 'READER_CREATE_ATTEMPT' -Scheduled $lifecycleBudgetClock.reader_create_attempt_ticks -Observed ($lifecycleBudgetClock.reader_create_attempt_ticks + 1L)),
    (New-D32LifecycleSelfTestEvent -Name 'READER_ASSIGNED_TO_JOB' -Scheduled $lifecycleBudgetClock.reader_create_attempt_ticks -Observed ($lifecycleT0 + 110L)),
    (New-D32LifecycleSelfTestEvent -Name 'READER_RESUMED' -Observed $lifecycleBudgetClock.reader_resume_ticks),
    (New-D32LifecycleSelfTestEvent -Name 'WORK_CUTOFF' -Scheduled $lifecycleWork -Observed ($lifecycleWork + 1L)),
    (New-D32LifecycleSelfTestEvent -Name 'PROOF_EXPIRY' -Scheduled $lifecycleExpiry -Observed ($lifecycleExpiry + 1L)),
    (New-D32LifecycleSelfTestEvent -Name 'TERMINATION_REQUEST' -Scheduled $lifecycleExpiry -Observed ($lifecycleExpiry + 2L)),
    (New-D32LifecycleSelfTestEvent -Name 'READER_EXIT' -Observed $lifecycleBudgetClock.reader_exit_ticks),
    (New-D32LifecycleSelfTestEvent -Name 'CLEANUP_VERIFIED' -Observed $lifecycleBudgetClock.cleanup_verified_ticks),
    (New-D32LifecycleSelfTestEvent -Name 'TERMINAL_AUDIT' -Scheduled $lifecycleCleanup -Observed ($lifecycleCleanup + 10L)))
$lifecycleBudgetCleanup = [PSCustomObject][ordered]@{ state = 'VERIFIED'; termination_requested = $true; join_verified = $true; job_active_process_count = 0L; job_closed = $true; kill_on_close_enabled = $true }
$lifecycleBudgetRecord = New-D32LifecycleSelfTestRecord -Status 'BUDGET_STOPPED' -Clock $lifecycleBudgetClock -Events $lifecycleBudgetEvents `
    -Reader $lifecycleReader -Artifact $lifecycleNotReadArtifact -Captures $lifecycleCaptures -Cleanup $lifecycleBudgetCleanup `
    -PrimaryError 'synthetic 270/300 second budget cutoff'
Assert-D32BoundedCompilerDiagnosticSelfTest 'exit zero after expiry remains BUDGET_STOPPED and cannot be upgraded by later cleanup' `
    (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleBudgetRecord)
$lifecycleUnknownCleanup = Copy-D32BoundedCompilerDiagnosticTestJson -Record $lifecycleBudgetRecord
$lifecycleUnknownCleanup.status = 'UNRESOLVED'
$lifecycleUnknownCleanup.primary_error = 'synthetic cleanup remains unknown'
$lifecycleUnknownCleanup.cleanup.state = 'UNVERIFIED'
$lifecycleUnknownCleanup.cleanup.join_verified = $false
$lifecycleUnknownCleanup.cleanup.job_active_process_count = 1L
$lifecycleUnknownCleanup.cleanup.job_closed = $true
$lifecycleUnknownCleanup.clock.cleanup_verified_ticks = $null
$lifecycleUnknownCleanup.captures.output_unavailable = $true
$lifecycleUnknownCleanup.events = @($lifecycleUnknownCleanup.events | Where-Object { $_.event -cne 'CLEANUP_VERIFIED' -and $_.event -cne 'TERMINAL_AUDIT' }) + @(
    (New-D32LifecycleSelfTestEvent -Name 'CLEANUP_UNVERIFIED' -Scheduled $lifecycleCleanup -Observed ($lifecycleCleanup + 1L)),
    (New-D32LifecycleSelfTestEvent -Name 'TERMINAL_AUDIT' -Scheduled $lifecycleCleanup -Observed ($lifecycleCleanup + 10L)))
Assert-D32BoundedCompilerDiagnosticSelfTest 'unknown cleanup remains UNRESOLVED even after kill-on-close intent and cannot claim joined ownership' `
    (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $lifecycleUnknownCleanup)

# NON_SOURCE_L1 is a separate authority/result domain. All rows below are pure
# synthetic objects; this block never invokes the controller or a child.
$l1Repository = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$l1CandidateSha = 'a' * 40; $l1BatchId = 'b' * 32; $l1RunId = 'c' * 32
$l1Root = 'C:\d32-l1-selftest\external\fresh-root'; $l1Parent = Split-Path -Parent $l1Root
$l1RuntimePath = 'C:\Program Files\PowerShell\7\pwsh.exe'
$l1RuntimeHome = Split-Path -Parent $l1RuntimePath
$l1SystemRoot = 'C:\Windows'
$l1OwnerId = 'S-1-5-21-0-0-0-1000'
$l1SourcePaths = Get-D32BoundedDiagnosticSourceProofNonSourceL1SourcePaths -Repository $l1Repository
$l1SourcePins = @(); $l1PinIndex = 0
foreach ($l1Path in $l1SourcePaths) {
    $pinDigit = [Convert]::ToString(($l1PinIndex + 1), 16)
    $l1SourcePins += [PSCustomObject][ordered]@{ path = $l1Path; bytes = [Int64](100 + $l1PinIndex); sha256 = $pinDigit * 64
        volume_serial_hex = '1111111111111111'; file_id_hex = ([Convert]::ToString($l1PinIndex + 1, 16).PadLeft(32, '0')) }
    $l1PinIndex++
}
$l1Runtime = [PSCustomObject][ordered]@{ path = $l1RuntimePath; bytes = 301368L; sha256 = 'd' * 64
    volume_serial_hex = '2222222222222222'; file_id_hex = '22222222222222222222222222222222'
    powershell_home = $l1RuntimeHome; system_root = $l1SystemRoot }
$l1RuntimeRef = [PSCustomObject][ordered]@{ path = $l1Runtime.path; bytes = $l1Runtime.bytes; sha256 = $l1Runtime.sha256
    volume_serial_hex = $l1Runtime.volume_serial_hex; file_id_hex = $l1Runtime.file_id_hex }
$l1Drive = [IO.Path]::GetPathRoot($l1Root).TrimEnd('\'); $l1HomePath = $l1Root.Substring($l1Drive.Length)
$l1ChildEnvironment = [PSCustomObject][ordered]@{
    SystemRoot = $l1SystemRoot; WINDIR = $l1SystemRoot; PATH = ($l1SystemRoot.TrimEnd('\') + '\System32;' + $l1RuntimeHome)
    PSHOME = $l1RuntimeHome; PSModulePath = ($l1RuntimeHome.TrimEnd('\') + '\Modules')
    PSModuleAutoLoadingPreference = 'None'; POWERSHELL_TELEMETRY_OPTOUT = '1'; DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    TEMP = $l1Root; TMP = $l1Root; USERPROFILE = $l1Root; APPDATA = $l1Root; LOCALAPPDATA = $l1Root
    HOMEDRIVE = $l1Drive; HOMEPATH = $l1HomePath
}
$l1Invocation = [PSCustomObject][ordered]@{ role = 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_V1'; entry_path = $l1SourcePaths[1]
    working_directory = $l1Root; argument_policy = 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_ARGV_V1'
    environment_policy = 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_ENV_V1'; child_environment = $l1ChildEnvironment }
$l1CasesAuthority = @(
    [PSCustomObject][ordered]@{ case_id = 'NORMAL_EXIT'; behavior = 'FINITE_TOKEN_EXIT_0'; expected_create_attempts = 1L; nonce = 'e' * 32 },
    [PSCustomObject][ordered]@{ case_id = 'FORCED_OWNED_TERMINATION'; behavior = 'READY_THEN_FINITE_WAIT'; expected_create_attempts = 1L; nonce = 'f' * 32 },
    [PSCustomObject][ordered]@{ case_id = 'ENTRY_PIN_BINDING_REFUSAL'; behavior = 'DERIVED_ENTRY_SHA_MISMATCH'; expected_create_attempts = 0L; nonce = '9' * 32 })
$l1Output = [PSCustomObject][ordered]@{ root_path = $l1Root; parent_path = $l1Parent; root_volume_serial_hex = '3333333333333333'
    root_file_id_hex = '33333333333333333333333333333333'; parent_volume_serial_hex = '4444444444444444'
    parent_file_id_hex = '44444444444444444444444444444444'; result_path = (Join-Path $l1Root ('D32-NSL1-' + $l1BatchId + '.json'))
    journal_path = (Join-Path $l1Root ('D32-NSL1-' + $l1BatchId + '.jsonl')) }
$l1Authority = New-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityCandidate -CandidateSha $l1CandidateSha -Repository $l1Repository `
    -RepositoryIdentity ([PSCustomObject][ordered]@{ volume_serial_hex = '5555555555555555'; file_id_hex = '55555555555555555555555555555555' }) `
    -BatchId $l1BatchId -RunId $l1RunId -OwnerId $l1OwnerId -SourcePins $l1SourcePins -PowerShellRuntime $l1Runtime `
    -Invocation $l1Invocation -Cases $l1CasesAuthority -Output $l1Output -IssuedAtUtc '2026-10-06T00:00:00.0000000+00:00'
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 strict authority producer emits the exact independent authority domain' `
    (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $l1Authority -ExpectedCandidateSha $l1CandidateSha -Repository $l1Repository)
$l1AuthorityJson = ConvertTo-Json -InputObject $l1Authority -Depth 40 -Compress -ErrorAction Stop
$l1AuthorityReadback = ConvertFrom-D32BoundedCompilerDiagnosticTestJson -Json $l1AuthorityJson
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 authority producer→JSON→consumer roundtrip is exact' `
    (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $l1AuthorityReadback -ExpectedCandidateSha $l1CandidateSha -Repository $l1Repository)
$l1BadAuthority = Copy-D32BoundedCompilerDiagnosticTestJson $l1Authority; $l1BadAuthority.record_type = 'D32_BOUNDED_SOURCEPROOF_EXECUTION_AUTHORITY_V1'
Assert-D32BoundedCompilerDiagnosticSelfTest 'SourceProof execution authority type cannot be substituted for NON_SOURCE_L1 authority' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $l1BadAuthority -ExpectedCandidateSha $l1CandidateSha -Repository $l1Repository))
$l1BadAuthority = Copy-D32BoundedCompilerDiagnosticTestJson $l1Authority; $l1BadAuthority | Add-Member -NotePropertyName extra -NotePropertyValue $true
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 authority rejects unknown fields' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $l1BadAuthority -ExpectedCandidateSha $l1CandidateSha -Repository $l1Repository))
$l1BadAuthority = Copy-D32BoundedCompilerDiagnosticTestJson $l1Authority; $l1BadAuthority.limits.batch_milliseconds = 60001L
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 authority rejects expanded timing budgets' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $l1BadAuthority -ExpectedCandidateSha $l1CandidateSha -Repository $l1Repository))
$l1BadAuthority = Copy-D32BoundedCompilerDiagnosticTestJson $l1Authority; $l1BadAuthority.invocation.child_environment | Add-Member -NotePropertyName CARGO_HOME -NotePropertyValue 'C:\secret'
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 authority rejects inherited/unlisted child environment keys' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $l1BadAuthority -ExpectedCandidateSha $l1CandidateSha -Repository $l1Repository))
$l1BadAuthority = Copy-D32BoundedCompilerDiagnosticTestJson $l1Authority; $l1BadAuthority.cases[1].nonce = $l1BadAuthority.cases[0].nonce
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 authority rejects duplicate case nonce bindings' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $l1BadAuthority -ExpectedCandidateSha $l1CandidateSha -Repository $l1Repository))
$l1BadAuthority = Copy-D32BoundedCompilerDiagnosticTestJson $l1Authority; $l1BadAuthority.cases = @($l1BadAuthority.cases[1], $l1BadAuthority.cases[0], $l1BadAuthority.cases[2])
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 authority rejects case reordering' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $l1BadAuthority -ExpectedCandidateSha $l1CandidateSha -Repository $l1Repository))
$l1BadAuthority = Copy-D32BoundedCompilerDiagnosticTestJson $l1Authority; $l1BadAuthority.source_pins[1].path = $l1BadAuthority.source_pins[2].path
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 authority rejects reader-entry pin substitution' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $l1BadAuthority -ExpectedCandidateSha $l1CandidateSha -Repository $l1Repository))
$l1BadAuthority = Copy-D32BoundedCompilerDiagnosticTestJson $l1Authority; $l1BadAuthority.output.root_path = Join-Path $l1Repository 'scripts\l1-output'
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 authority rejects output roots inside the repository' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1AuthorityShape -Document $l1BadAuthority -ExpectedCandidateSha $l1CandidateSha -Repository $l1Repository))

$l1EntryPath = Join-Path $PSScriptRoot 'd32-bounded-diagnostic-sourceproof.ps1'
$l1EntryTokens = $null; $l1EntryErrors = $null
$l1EntryAst = [Management.Automation.Language.Parser]::ParseFile($l1EntryPath, [ref]$l1EntryTokens, [ref]$l1EntryErrors)
foreach ($functionName in @('Test-D32NonSourceL1ReaderJsonDuplicates', 'Test-D32NonSourceL1ReaderExactProperties', 'Test-D32NonSourceL1ReaderString',
    'Test-D32NonSourceL1ReaderPositiveInteger', 'Test-D32NonSourceL1ReaderNonnegativeInteger', 'Test-D32NonSourceL1ReaderFileReference',
    'Test-D32NonSourceL1ReaderAuthority', 'Get-D32NonSourceL1ReaderRefusalText')) {
    $functionAst = $l1EntryAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $functionName }, $true)
    Assert-D32BoundedCompilerDiagnosticSelfTest "reader strict consumer helper exists: $functionName" ($null -ne $functionAst)
    if ($null -ne $functionAst) {
        . ([ScriptBlock]::Create([string]$functionAst.Extent.Text))
    }
}
$l1ReaderDocument = [System.Text.Json.JsonDocument]::Parse($l1AuthorityJson)
try {
    $l1ReaderAuthorityAccepted = Test-D32NonSourceL1ReaderAuthority -Authority $l1ReaderDocument.RootElement -CaseId 'NORMAL_EXIT' `
        -Nonce $l1CasesAuthority[0].nonce -CandidateSha $l1CandidateSha -BatchId $l1BatchId -AuthorityPath $l1EntryPath `
        -RuntimePath $l1RuntimePath -OwnerId $l1OwnerId -SystemRoot $l1SystemRoot
} finally { $l1ReaderDocument.Dispose() }
Assert-D32BoundedCompilerDiagnosticSelfTest 'fixed module-free child authority consumer accepts the actual producer JSON without SourceProof authority/profile reads' $l1ReaderAuthorityAccepted
$l1ReaderRefusalDetail = Get-D32NonSourceL1ReaderRefusalText -Exception ([InvalidOperationException]::new('reader token=private nonce=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee at "C:\private user\source\authority.json"'))
Assert-D32BoundedCompilerDiagnosticSelfTest 'reader admission failures emit a bounded sanitized refusal detail without paths, nonce values, or long IDs' `
    ($l1ReaderRefusalDetail.StartsWith('InvalidOperationException:', [StringComparison]::Ordinal) -and
     -not $l1ReaderRefusalDetail.Contains('private') -and -not $l1ReaderRefusalDetail.Contains('authority.json') -and
     -not $l1ReaderRefusalDetail.Contains('eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee') -and $l1ReaderRefusalDetail.Length -le 512)
$l1DuplicateAuthorityJson = $l1AuthorityJson.Replace('"gate_authority":"NONE"', '"gate_authority":"NONE","gate_authority":"PHASE0"')
$l1DuplicateDoc = [System.Text.Json.JsonDocument]::Parse($l1DuplicateAuthorityJson)
try { $l1DuplicateRejected = Test-D32NonSourceL1ReaderJsonDuplicates -Element $l1DuplicateDoc.RootElement }
finally { $l1DuplicateDoc.Dispose() }
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 reader rejects duplicate authority properties before projection' $l1DuplicateRejected
$l1UnknownAuthorityJson = $l1AuthorityJson.TrimEnd('}') + ',"unexpected":true}'
$l1UnknownDoc = [System.Text.Json.JsonDocument]::Parse($l1UnknownAuthorityJson)
try { $l1UnknownRejected = -not (Test-D32NonSourceL1ReaderAuthority -Authority $l1UnknownDoc.RootElement -CaseId 'NORMAL_EXIT' `
        -Nonce $l1CasesAuthority[0].nonce -CandidateSha $l1CandidateSha -BatchId $l1BatchId -AuthorityPath $l1EntryPath `
        -RuntimePath $l1RuntimePath -OwnerId $l1OwnerId -SystemRoot $l1SystemRoot) }
finally { $l1UnknownDoc.Dispose() }
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 reader strict consumer rejects unknown authority properties' $l1UnknownRejected
$l1WrongTypeAuthorityJson = $l1AuthorityJson.Replace('"schema_version":1', '"schema_version":"1"')
$l1WrongTypeDocument = [System.Text.Json.JsonDocument]::Parse($l1WrongTypeAuthorityJson)
try {
    $l1WrongTypeRejected = -not (Test-D32NonSourceL1ReaderAuthority -Authority $l1WrongTypeDocument.RootElement -CaseId 'NORMAL_EXIT' `
        -Nonce $l1CasesAuthority[0].nonce -CandidateSha $l1CandidateSha -BatchId $l1BatchId -AuthorityPath $l1EntryPath `
        -RuntimePath $l1RuntimePath -OwnerId $l1OwnerId -SystemRoot $l1SystemRoot)
} finally { $l1WrongTypeDocument.Dispose() }
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 reader strict consumer rejects a string where an integer schema field is required' $l1WrongTypeRejected

$l1Frequency = [Int64][Diagnostics.Stopwatch]::Frequency; $l1T0 = 1000000000000L
$l1BatchDeadline = ConvertTo-D32BoundedDiagnosticSourceProofDeadlineTicks -T0Ticks $l1T0 -Frequency $l1Frequency -DeadlineMilliseconds 60000L
$l1Case0T0 = $l1T0 + 100000L; $l1Case0Deadlines = Get-D32BoundedDiagnosticSourceProofNonSourceL1CaseDeadlines -CaseT0Ticks $l1Case0T0 -Frequency $l1Frequency -BatchDeadlineTicks $l1BatchDeadline
$l1Case1T0 = $l1T0 + 1100000L; $l1Case1Deadlines = Get-D32BoundedDiagnosticSourceProofNonSourceL1CaseDeadlines -CaseT0Ticks $l1Case1T0 -Frequency $l1Frequency -BatchDeadlineTicks $l1BatchDeadline
$l1Case2T0 = $l1T0 + 6100000L; $l1Case2Deadlines = Get-D32BoundedDiagnosticSourceProofNonSourceL1CaseDeadlines -CaseT0Ticks $l1Case2T0 -Frequency $l1Frequency -BatchDeadlineTicks $l1BatchDeadline
$l1ExpectedOut0 = 'D32NSL1|NORMAL_EXIT|' + $l1CasesAuthority[0].nonce + '|READY' + "`r`n"
$l1ExpectedErr0 = 'D32NSL1|FIXED|NORMAL' + "`r`n"
$l1ExpectedOut1 = 'D32NSL1|FORCED_OWNED_TERMINATION|' + $l1CasesAuthority[1].nonce + '|READY' + "`r`n"
$l1ExpectedErr1 = 'D32NSL1|FIXED|FORCED' + "`r`n"
$l1OutBytes0 = [Text.UTF8Encoding]::new($false).GetBytes($l1ExpectedOut0); $l1ErrBytes0 = [Text.UTF8Encoding]::new($false).GetBytes($l1ExpectedErr0)
$l1OutBytes1 = [Text.UTF8Encoding]::new($false).GetBytes($l1ExpectedOut1); $l1ErrBytes1 = [Text.UTF8Encoding]::new($false).GetBytes($l1ExpectedErr1)
$l1Sha = { param([byte[]]$Bytes) [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant() }
$l1Row0 = New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'NORMAL_EXIT' -State 'NATIVE_BOUNDARY_VERIFIED' `
    -CaseT0Ticks $l1Case0T0 -ActiveDeadlineTicks $l1Case0Deadlines.active_deadline_ticks -CleanupDeadlineTicks $l1Case0Deadlines.cleanup_deadline_ticks `
    -AuditDeadlineTicks $l1Case0Deadlines.audit_deadline_ticks -AdmissionObservedTicks ($l1Case0T0 + 100L) -CreateAttemptCount 1L `
    -CreateAttemptTicks ($l1Case0T0 + 1000L) -ProcessId 12345L -CreationFiletimeTicks 134000000000000000L -ProcessImagePath $l1RuntimePath `
    -ProcessImageBindingVerified $true -JobInstanceId ('1' * 32) -JobAssigned $true -ResumeTicks ($l1Case0T0 + 2000L) `
    -ExitTicks ($l1Case0T0 + 6000L) -ExitCode 0 -JobActiveProcessCount 0L -JobTotalProcessCount 1L -KillOnCloseEnabled $true -JobActiveProcessLimitOne $true `
    -StdoutBytes $l1OutBytes0.Length -StdoutSha256 (& $l1Sha $l1OutBytes0) -StdoutTokenVerified $true `
    -StderrBytes $l1ErrBytes0.Length -StderrSha256 (& $l1Sha $l1ErrBytes0) -StderrTokenVerified $true `
    -CaptureJoinVerified $true -JobClosed $true -CleanupObservedTicks ($l1Case0T0 + 7500L) -CaseCompletedTicks ($l1Case0T0 + 8000L)
$l1Row1 = New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'FORCED_OWNED_TERMINATION' -State 'NATIVE_BOUNDARY_VERIFIED' `
    -CaseT0Ticks $l1Case1T0 -ActiveDeadlineTicks $l1Case1Deadlines.active_deadline_ticks -CleanupDeadlineTicks $l1Case1Deadlines.cleanup_deadline_ticks `
    -AuditDeadlineTicks $l1Case1Deadlines.audit_deadline_ticks -AdmissionObservedTicks ($l1Case1T0 + 100L) -CreateAttemptCount 1L `
    -CreateAttemptTicks ($l1Case1T0 + 1000L) -ProcessId 12346L -CreationFiletimeTicks 134000000000000001L -ProcessImagePath $l1RuntimePath `
    -ProcessImageBindingVerified $true -JobInstanceId ('2' * 32) -JobAssigned $true -ResumeTicks ($l1Case1T0 + 2000L) `
    -PlannedTerminationCount 1L -PlannedTerminationTicks ($l1Case1T0 + 1000000L) -ExitTicks ($l1Case1T0 + 1200000L) -ExitCode ([Int32]-1) `
    -JobActiveProcessCount 0L -JobTotalProcessCount 1L -KillOnCloseEnabled $true -JobActiveProcessLimitOne $true `
    -StdoutBytes $l1OutBytes1.Length -StdoutSha256 (& $l1Sha $l1OutBytes1) -StdoutTokenVerified $true `
    -StderrBytes $l1ErrBytes1.Length -StderrSha256 (& $l1Sha $l1ErrBytes1) -StderrTokenVerified $true `
    -CaptureJoinVerified $true -JobClosed $true -CleanupObservedTicks ($l1Case1T0 + 1500000L) -CaseCompletedTicks ($l1Case1T0 + 2000000L)
$l1Row2 = New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'ENTRY_PIN_BINDING_REFUSAL' -State 'EXPECTED_REFUSAL_VERIFIED' `
    -CaseT0Ticks $l1Case2T0 -ActiveDeadlineTicks $l1Case2Deadlines.active_deadline_ticks -CleanupDeadlineTicks $l1Case2Deadlines.cleanup_deadline_ticks `
    -AuditDeadlineTicks $l1Case2Deadlines.audit_deadline_ticks -AdmissionObservedTicks ($l1Case2T0 + 100L) -CaseCompletedTicks ($l1Case2T0 + 2000L) `
    -PrimaryError 'synthetic fixed opened-handle entry pin mismatch'
$l1AuthorityRef = [PSCustomObject][ordered]@{ path = 'C:\d32-l1-selftest\authority\L1.json'; bytes = 4096L; sha256 = '6' * 64
    volume_serial_hex = '6666666666666666'; file_id_hex = '66666666666666666666666666666666' }
$l1Controller = [PSCustomObject][ordered]@{ process_id = 321L; creation_filetime_ticks = 134000000000000000L }
$l1Clock = [PSCustomObject][ordered]@{ counter_origin = 'QueryPerformanceCounter'; frequency = $l1Frequency; batch_t0_ticks = $l1T0
    batch_deadline_ticks = $l1BatchDeadline; controller_entry_ticks = ($l1T0 + 10L) }
$l1Result = New-D32BoundedDiagnosticSourceProofNonSourceL1ResultCandidate -CandidateSha $l1CandidateSha -BatchId $l1BatchId -RunId $l1RunId `
    -AuthorityReference $l1AuthorityRef -SourcePins $l1SourcePins -PowerShellRuntime $l1RuntimeRef -Output $l1Output -Clock $l1Clock -Controller $l1Controller `
    -Cases @($l1Row0, $l1Row1, $l1Row2) -CreateProcessAttemptCount 2L -PlannedTerminationCount 1L -FailSafeTerminationCount 0L `
    -Status 'COMPLETE_NON_SOURCE_L1' -PrimaryError $null -StartedAtUtc '2026-10-06T00:00:01.0000000+00:00' -CompletedAtUtc '2026-10-06T00:00:02.0000000+00:00'
$l1BatchCompleteOutcome = Resolve-D32BoundedDiagnosticSourceProofNonSourceL1BatchOutcome -Cases @($l1Row0, $l1Row1, $l1Row2) `
    -CreateProcessAttemptCount 2L -PlannedTerminationCount 1L -FailSafeTerminationCount 0L -BatchDeadlineReached:$false
Assert-D32BoundedCompilerDiagnosticSelfTest 'actual pure L1 batch outcome producer emits COMPLETE only for the two verified launches and the zero-create refusal' `
    ([string]$l1BatchCompleteOutcome.status -ceq 'COMPLETE_NON_SOURCE_L1' -and $null -eq $l1BatchCompleteOutcome.primary_error)
$l1UnresolvedCase = Copy-D32BoundedCompilerDiagnosticTestJson $l1Row0
$l1UnresolvedCase.state = 'UNRESOLVED'; $l1UnresolvedCase.primary_error = 'synthetic owned cleanup state unknown'
$l1UnresolvedOutcome = Resolve-D32BoundedDiagnosticSourceProofNonSourceL1BatchOutcome `
    -Cases @($l1UnresolvedCase, (New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'FORCED_OWNED_TERMINATION'), `
        (New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'ENTRY_PIN_BINDING_REFUSAL')) `
    -CreateProcessAttemptCount 1L -PlannedTerminationCount 0L -FailSafeTerminationCount 1L -BatchDeadlineReached:$true
Assert-D32BoundedCompilerDiagnosticSelfTest 'unknown owned cleanup dominates later statuses and preserves the first case cause without launching more cases' `
    ([string]$l1UnresolvedOutcome.status -ceq 'UNRESOLVED' -and [string]$l1UnresolvedOutcome.primary_error -ceq 'synthetic owned cleanup state unknown')
$policyAstForL1 = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'd32-bounded-compiler-diagnostic-policy.ps1'), [ref]$null, [ref]$null)
$resultShapeAstForL1 = $policyAstForL1.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape' }, $true)
. ([ScriptBlock]::Create([string]$resultShapeAstForL1.Extent.Text))
$l1ResultShapeOkay = Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1Result
Assert-D32BoundedCompilerDiagnosticSelfTest 'actual L1 result producer creates exact complete native-boundary schema with zero-create refusal' `
    $l1ResultShapeOkay
$l1BadResult = Copy-D32BoundedCompilerDiagnosticTestJson $l1Result
$l1BadResult.cases[1].case_t0_ticks = [Int64]$l1BadResult.cases[0].case_completed_ticks - 1L
$l1BadOrderDeadlines = Get-D32BoundedDiagnosticSourceProofNonSourceL1CaseDeadlines -CaseT0Ticks ([Int64]$l1BadResult.cases[1].case_t0_ticks) `
    -Frequency $l1Frequency -BatchDeadlineTicks $l1BatchDeadline
$l1BadResult.cases[1].active_deadline_ticks = [Int64]$l1BadOrderDeadlines.active_deadline_ticks
$l1BadResult.cases[1].cleanup_deadline_ticks = [Int64]$l1BadOrderDeadlines.cleanup_deadline_ticks
$l1BadResult.cases[1].audit_deadline_ticks = [Int64]$l1BadOrderDeadlines.audit_deadline_ticks
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 result rejects a later executed case whose T0 precedes the prior case completion' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadResult))
$l1BadResult = Copy-D32BoundedCompilerDiagnosticTestJson $l1Result; $l1BadResult.cases[0].primary_error = 'forged failure on verified native case'
Assert-D32BoundedCompilerDiagnosticSelfTest 'verified native rows cannot retain a failure primary error' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadResult))
$l1BadResult = Copy-D32BoundedCompilerDiagnosticTestJson $l1Result; $l1BadResult.cases[2].primary_error = $null
Assert-D32BoundedCompilerDiagnosticSelfTest 'expected refusal must preserve its concrete pre-create binding reason' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadResult))
$l1BadResult = Copy-D32BoundedCompilerDiagnosticTestJson $l1Result; $l1BadResult.cases[2].job_total_process_count = 1L
Assert-D32BoundedCompilerDiagnosticSelfTest 'zero-create refusal cannot fabricate Job process accounting without a created process' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadResult))
$l1BadResult = Copy-D32BoundedCompilerDiagnosticTestJson $l1Result
$l1BadResult.cases[1].fail_safe_termination_count = 1L; $l1BadResult.cases[1].fail_safe_termination_ticks = [Int64]$l1Row1.resume_ticks + 1L
$l1BadResult.fail_safe_termination_count = 1L
Assert-D32BoundedCompilerDiagnosticSelfTest 'verified native-boundary cases cannot relabel fail-safe termination as expected behavior' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadResult))
$l1LateCaseT0 = $l1T0 + 200000L
$l1LateCaseDeadlines = Get-D32BoundedDiagnosticSourceProofNonSourceL1CaseDeadlines -CaseT0Ticks $l1LateCaseT0 -Frequency $l1Frequency -BatchDeadlineTicks $l1BatchDeadline
$l1LateCase = New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'NORMAL_EXIT' -State 'BUDGET_STOPPED' `
    -CaseT0Ticks $l1LateCaseT0 -ActiveDeadlineTicks ([Int64]$l1LateCaseDeadlines.active_deadline_ticks) `
    -CleanupDeadlineTicks ([Int64]$l1LateCaseDeadlines.cleanup_deadline_ticks) -AuditDeadlineTicks ([Int64]$l1LateCaseDeadlines.audit_deadline_ticks) `
    -AdmissionObservedTicks ($l1LateCaseT0 + 10L) -CaseCompletedTicks ([Int64]$l1LateCaseDeadlines.audit_deadline_ticks) `
    -PrimaryError 'synthetic row reached the case audit boundary'
$l1LateResult = New-D32BoundedDiagnosticSourceProofNonSourceL1ResultCandidate -CandidateSha $l1CandidateSha -BatchId $l1BatchId -RunId $l1RunId `
    -AuthorityReference $l1AuthorityRef -SourcePins $l1SourcePins -PowerShellRuntime $l1RuntimeRef -Output $l1Output -Clock $l1Clock -Controller $l1Controller `
    -Cases @($l1LateCase, (New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'FORCED_OWNED_TERMINATION'), `
        (New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'ENTRY_PIN_BINDING_REFUSAL')) `
    -CreateProcessAttemptCount 0L -PlannedTerminationCount 0L -FailSafeTerminationCount 0L -Status 'BUDGET_STOPPED' `
    -PrimaryError 'synthetic case audit budget stopped' -StartedAtUtc '2026-10-06T00:00:01.0000000+00:00' -CompletedAtUtc '2026-10-06T00:00:02.0000000+00:00'
$l1BudgetOutcome = Resolve-D32BoundedDiagnosticSourceProofNonSourceL1BatchOutcome -Cases @($l1LateCase, $l1LateResult.cases[1], $l1LateResult.cases[2]) `
    -CreateProcessAttemptCount 0L -PlannedTerminationCount 0L -FailSafeTerminationCount 0L -BatchDeadlineReached:$false
Assert-D32BoundedCompilerDiagnosticSelfTest 'actual pure L1 batch outcome propagates case deadline as BUDGET_STOPPED with its cause' `
    ([string]$l1BudgetOutcome.status -ceq 'BUDGET_STOPPED' -and [string]$l1BudgetOutcome.primary_error -ceq [string]$l1LateCase.primary_error)
Assert-D32BoundedCompilerDiagnosticSelfTest 'result preserves a case completed at its audit deadline only as BUDGET_STOPPED with its primary reason' `
    (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1LateResult)
$l1BadLateResult = Copy-D32BoundedCompilerDiagnosticTestJson $l1LateResult; $l1BadLateResult.status = 'BLOCKED'; $l1BadLateResult.cases[0].state = 'BLOCKED'
Assert-D32BoundedCompilerDiagnosticSelfTest 'case audit deadline cannot be mislabeled as an ordinary BLOCKED row' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadLateResult))
$l1BadNotRun = Copy-D32BoundedCompilerDiagnosticTestJson $l1LateResult; $l1BadNotRun.cases[1].process_id = 12348L
Assert-D32BoundedCompilerDiagnosticSelfTest 'NOT_RUN suffix rows contain no fabricated process identity' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadNotRun))
$l1BadNotRun = Copy-D32BoundedCompilerDiagnosticTestJson $l1LateResult; $l1BadNotRun.cases[1].stdout_sha256 = '0' * 64
Assert-D32BoundedCompilerDiagnosticSelfTest 'NOT_RUN suffix rows retain only the empty-capture digest' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadNotRun))
$l1ResultJson = ConvertTo-Json -InputObject $l1Result -Depth 50 -Compress -ErrorAction Stop
$l1ResultReadback = ConvertFrom-D32BoundedCompilerDiagnosticTestJson -Json $l1ResultJson
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 result producer→JSON→consumer roundtrip is exact' `
    (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1ResultReadback)
$l1BadResult = Copy-D32BoundedCompilerDiagnosticTestJson $l1Result; $l1BadResult.formal_gate_usable = $true
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 result cannot assert formal gate usability' (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadResult))
$l1BadResult = Copy-D32BoundedCompilerDiagnosticTestJson $l1Result; $l1BadResult.cases[2].process_id = 12347L
Assert-D32BoundedCompilerDiagnosticSelfTest 'zero-create expected refusal cannot fabricate PID identity' (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadResult))
$l1BadResult = Copy-D32BoundedCompilerDiagnosticTestJson $l1Result; $l1BadResult.cases[1].job_active_process_limit_one = $false
Assert-D32BoundedCompilerDiagnosticSelfTest 'complete L1 rows require the actual one-process Job limit' (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadResult))
$l1BadResult = Copy-D32BoundedCompilerDiagnosticTestJson $l1Result; $l1BadResult.cases[0].stdout_bytes = 1025L
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 result enforces expected fixture output bound independently of stream cap' (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadResult))
$l1BadResult = Copy-D32BoundedCompilerDiagnosticTestJson $l1Result; $l1BadResult.cases[0].stdout_token_verified = $false
Assert-D32BoundedCompilerDiagnosticSelfTest 'complete L1 result requires exact fixed behavior token verification' (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadResult))
$l1BadResult = Copy-D32BoundedCompilerDiagnosticTestJson $l1Result; $l1BadResult.record_type = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_V3'
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 result cannot be relabeled as formal compiler diagnostic V3' (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1BadResult))
Assert-D32BoundedCompilerDiagnosticSelfTest 'SourceProof execution authority consumer rejects L1 authority type' `
    (-not (Test-D32BoundedDiagnosticSourceProofExecutionAuthorityShape -Document $l1Authority -ExpectedCandidateSha $l1CandidateSha -Repository $l1Repository))
Assert-D32BoundedCompilerDiagnosticSelfTest 'SourceProof execution result consumer rejects L1 result type' `
    (-not (Test-D32BoundedDiagnosticSourceProofExecutionResultShape -Record $l1Result))

$l1ResultBytes = [Text.UTF8Encoding]::new($false).GetBytes($l1ResultJson)
$l1ResultRef = [PSCustomObject][ordered]@{ path = $l1Output.result_path; bytes = [Int64]$l1ResultBytes.Length
    sha256 = (& $l1Sha $l1ResultBytes); volume_serial_hex = '7777777777777777'; file_id_hex = '77777777777777777777777777777777' }
$l1PersistedFact = [PSCustomObject][ordered]@{ event = 'L1_RESULT_PERSISTED'; case_id = ''; scheduled_ticks = $null
    observed_ticks = ($l1T0 + 7000000L); lateness_ticks = $null; result_path = $l1ResultRef.path; result_bytes = $l1ResultRef.bytes
    result_sha256 = $l1ResultRef.sha256; result_volume_serial_hex = $l1ResultRef.volume_serial_hex; result_file_id_hex = $l1ResultRef.file_id_hex; gate_authority = 'NONE' }
$l1JournalRows = [System.Collections.Generic.List[object]]::new()
$l1JournalRows.Add([PSCustomObject][ordered]@{ event = 'AUTHORITY_ADMISSION'; case_id = ''; scheduled_ticks = $l1T0; observed_ticks = ($l1T0 + 50L)
    lateness_ticks = 50L; result_path = $null; result_bytes = $null; result_sha256 = $null; result_volume_serial_hex = $null; result_file_id_hex = $null; gate_authority = 'NONE' })
foreach ($case in @($l1Row0, $l1Row1, $l1Row2)) {
    $l1JournalRows.Add([PSCustomObject][ordered]@{ event = 'CASE_' + [string]$case.state; case_id = [string]$case.case_id; scheduled_ticks = $null
        observed_ticks = [Int64]$case.case_completed_ticks; lateness_ticks = $null; result_path = $null; result_bytes = $null; result_sha256 = $null
        result_volume_serial_hex = $null; result_file_id_hex = $null; gate_authority = 'NONE' })
}
$l1JournalRows.Add($l1PersistedFact)
$l1JournalText = ((@($l1JournalRows | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 12 -Compress -ErrorAction Stop })) -join "`n") + "`n"
$l1JournalBytes = [Text.UTF8Encoding]::new($false).GetBytes($l1JournalText)
$l1JournalRef = [PSCustomObject][ordered]@{ path = $l1Output.journal_path; bytes = [Int64]$l1JournalBytes.Length
    sha256 = (& $l1Sha $l1JournalBytes); volume_serial_hex = '8888888888888888'; file_id_hex = '88888888888888888888888888888888' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 persisted authority/current-code/result binding closes on exact synthetic result reference' `
    (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultBindings -Record $l1ResultReadback -Authority $l1AuthorityReadback `
        -AuthorityReference $l1AuthorityRef -ExpectedAuthorityPath $l1AuthorityRef.path -ExpectedAuthoritySha256 $l1AuthorityRef.sha256 `
        -PersistedFact $l1PersistedFact -ResultReference $l1ResultRef)
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 journal producer→strict reader reconciles ordered all-case status and exact post-result bytes/hash/identity' `
    (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultPersistence -Record $l1ResultReadback -PersistedFact $l1PersistedFact `
        -ResultReference $l1ResultRef -JournalReference $l1JournalRef -JournalBytes $l1JournalBytes -CallerObservedTicks ($l1T0 + 8000000L))
$l1BadJournalRows = [System.Collections.Generic.List[object]]::new(); foreach ($row in $l1JournalRows) { $l1BadJournalRows.Add((Copy-D32BoundedCompilerDiagnosticTestJson $row)) }
$l1BadJournalRows[2].case_id = 'FORGED_CASE'
$l1BadJournalText = ((@($l1BadJournalRows | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 12 -Compress })) -join "`n") + "`n"
$l1BadJournalBytes = [Text.UTF8Encoding]::new($false).GetBytes($l1BadJournalText)
$l1BadJournalRef = [PSCustomObject][ordered]@{ path = $l1Output.journal_path; bytes = [Int64]$l1BadJournalBytes.Length
    sha256 = (& $l1Sha $l1BadJournalBytes); volume_serial_hex = $l1JournalRef.volume_serial_hex; file_id_hex = $l1JournalRef.file_id_hex }
Assert-D32BoundedCompilerDiagnosticSelfTest 'journal reader rejects case-id substitution despite a correctly recomputed journal hash' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultPersistence -Record $l1ResultReadback -PersistedFact $l1PersistedFact `
        -ResultReference $l1ResultRef -JournalReference $l1BadJournalRef -JournalBytes $l1BadJournalBytes -CallerObservedTicks ($l1T0 + 8000000L)))
$l1LateFact = Copy-D32BoundedCompilerDiagnosticTestJson $l1PersistedFact; $l1LateFact.observed_ticks = $l1T0 + 600000000L
$l1LateRows = [System.Collections.Generic.List[object]]::new(); foreach ($row in $l1JournalRows) { $l1LateRows.Add((Copy-D32BoundedCompilerDiagnosticTestJson $row)) }
$l1LateRows[$l1LateRows.Count - 1].observed_ticks = $l1LateFact.observed_ticks
$l1LateText = ((@($l1LateRows | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 12 -Compress })) -join "`n") + "`n"
$l1LateBytes = [Text.UTF8Encoding]::new($false).GetBytes($l1LateText)
$l1LateRef = [PSCustomObject][ordered]@{ path = $l1Output.journal_path; bytes = [Int64]$l1LateBytes.Length; sha256 = (& $l1Sha $l1LateBytes)
    volume_serial_hex = $l1JournalRef.volume_serial_hex; file_id_hex = $l1JournalRef.file_id_hex }
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 result and caller reconciliation reject a persisted fact at the 60-second batch deadline' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultPersistence -Record $l1ResultReadback -PersistedFact $l1LateFact `
        -ResultReference $l1ResultRef -JournalReference $l1LateRef -JournalBytes $l1LateBytes -CallerObservedTicks ($l1T0 + 600000001L)))
$l1Partial = New-D32BoundedDiagnosticSourceProofNonSourceL1ResultCandidate -CandidateSha $l1CandidateSha -BatchId $l1BatchId -RunId $l1RunId `
    -AuthorityReference $l1AuthorityRef -SourcePins $l1SourcePins -PowerShellRuntime $l1RuntimeRef -Output $l1Output -Clock $l1Clock -Controller $l1Controller `
    -Cases @((New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'NORMAL_EXIT'),
        (New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'FORCED_OWNED_TERMINATION'),
        (New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'ENTRY_PIN_BINDING_REFUSAL')) `
    -CreateProcessAttemptCount 0L -PlannedTerminationCount 0L -FailSafeTerminationCount 0L -Status 'BLOCKED' -PrimaryError 'synthetic pre-case refusal' `
    -StartedAtUtc '2026-10-06T00:00:01.0000000+00:00' -CompletedAtUtc '2026-10-06T00:00:02.0000000+00:00'
$l1PartialJsonBytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $l1Partial -Depth 50 -Compress))
$l1PartialRef = [PSCustomObject][ordered]@{ path = $l1Output.result_path; bytes = [Int64]$l1PartialJsonBytes.Length; sha256 = (& $l1Sha $l1PartialJsonBytes)
    volume_serial_hex = '7777777777777777'; file_id_hex = '99999999999999999999999999999999' }
$l1PartialFact = Copy-D32BoundedCompilerDiagnosticTestJson $l1PersistedFact; $l1PartialFact.observed_ticks = $l1T0 + 1000L
foreach ($name in @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) { $propertyName = if ($name -ceq 'path') { 'result_path' } elseif ($name -ceq 'bytes') { 'result_bytes' } elseif ($name -ceq 'sha256') { 'result_sha256' } else { 'result_' + $name }; $l1PartialFact.$propertyName = $l1PartialRef.$name }
$l1PartialJournalRows = @(
    [PSCustomObject][ordered]@{ event = 'AUTHORITY_ADMISSION'; case_id = ''; scheduled_ticks = $l1T0; observed_ticks = ($l1T0 + 50L); lateness_ticks = 50L
        result_path = $null; result_bytes = $null; result_sha256 = $null; result_volume_serial_hex = $null; result_file_id_hex = $null; gate_authority = 'NONE' },
    $l1PartialFact)
$l1PartialJournalBytes = [Text.UTF8Encoding]::new($false).GetBytes(((($l1PartialJournalRows | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 12 -Compress }) -join "`n") + "`n"))
$l1PartialJournalRef = [PSCustomObject][ordered]@{ path = $l1Output.journal_path; bytes = [Int64]$l1PartialJournalBytes.Length; sha256 = (& $l1Sha $l1PartialJournalBytes)
    volume_serial_hex = '8888888888888888'; file_id_hex = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'strict L1 persistence accepts durable BLOCKED result with only admission and persisted facts' `
    (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultPersistence -Record $l1Partial -PersistedFact $l1PartialFact -ResultReference $l1PartialRef `
        -JournalReference $l1PartialJournalRef -JournalBytes $l1PartialJournalBytes -CallerObservedTicks ($l1T0 + 2000L))
$l1RefusedResult = New-D32BoundedDiagnosticSourceProofNonSourceL1ResultCandidate -CandidateSha $l1CandidateSha -BatchId $l1BatchId -RunId $l1RunId `
    -AuthorityReference $l1AuthorityRef -SourcePins $l1SourcePins -PowerShellRuntime $l1RuntimeRef -Output $l1Output -Clock $l1Clock -Controller $l1Controller `
    -Cases @((New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'NORMAL_EXIT'),
        (New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'FORCED_OWNED_TERMINATION'),
        (New-D32BoundedDiagnosticSourceProofNonSourceL1CaseCandidate -CaseId 'ENTRY_PIN_BINDING_REFUSAL')) `
    -CreateProcessAttemptCount 0L -PlannedTerminationCount 0L -FailSafeTerminationCount 0L -Status 'REFUSED' `
    -PrimaryError 'InvalidOperationException: fixed lifecycle identity type unavailable' `
    -StartedAtUtc '2026-10-06T00:00:01.0000000+00:00' -CompletedAtUtc '2026-10-06T00:00:02.0000000+00:00'
$l1RefusedJsonBytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $l1RefusedResult -Depth 50 -Compress))
$l1RefusedResultRef = [PSCustomObject][ordered]@{ path = $l1Output.result_path; bytes = [Int64]$l1RefusedJsonBytes.Length
    sha256 = (& $l1Sha $l1RefusedJsonBytes); volume_serial_hex = '7777777777777777'; file_id_hex = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }
$l1RefusedPersistedFact = [PSCustomObject][ordered]@{ event = 'L1_RESULT_PERSISTED'; case_id = ''; scheduled_ticks = $null
    observed_ticks = ($l1T0 + 1000L); lateness_ticks = $null; result_path = $l1RefusedResultRef.path; result_bytes = $l1RefusedResultRef.bytes
    result_sha256 = $l1RefusedResultRef.sha256; result_volume_serial_hex = $l1RefusedResultRef.volume_serial_hex
    result_file_id_hex = $l1RefusedResultRef.file_id_hex; gate_authority = 'NONE' }
$l1RefusedJournalRows = @(
    [PSCustomObject][ordered]@{ event = 'AUTHORITY_ADMISSION'; case_id = ''; scheduled_ticks = $l1T0; observed_ticks = ($l1T0 + 50L)
        lateness_ticks = 50L; result_path = $null; result_bytes = $null; result_sha256 = $null; result_volume_serial_hex = $null
        result_file_id_hex = $null; gate_authority = 'NONE' },
    $l1RefusedPersistedFact)
$l1RefusedJournalBytes = [Text.UTF8Encoding]::new($false).GetBytes(((($l1RefusedJournalRows | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 12 -Compress }) -join "`n") + "`n"))
$l1RefusedJournalRef = [PSCustomObject][ordered]@{ path = $l1Output.journal_path; bytes = [Int64]$l1RefusedJournalBytes.Length
    sha256 = (& $l1Sha $l1RefusedJournalBytes); volume_serial_hex = '8888888888888888'; file_id_hex = 'cccccccccccccccccccccccccccccccc' }
$l1RefusedResultReadback = ConvertFrom-D32BoundedCompilerDiagnosticTestJson -Json ([Text.UTF8Encoding]::new($false).GetString($l1RefusedJsonBytes))
$l1RefusedShapePass = Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultShape -Record $l1RefusedResultReadback
Assert-D32BoundedCompilerDiagnosticSelfTest 'pre-case REFUSED producer→JSON→strict reader preserves primary error with only NOT_RUN rows after authority admission' `
    ($l1RefusedShapePass -and
     [string]$l1RefusedResultReadback.status -ceq 'REFUSED' -and
     [string]$l1RefusedResultReadback.primary_error -ceq [string]$l1RefusedResult.primary_error)
Assert-D32BoundedCompilerDiagnosticSelfTest 'pre-case REFUSED result still requires exact authority binding and persisted journal reconciliation' `
    ((Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultBindings -Record $l1RefusedResultReadback -Authority $l1AuthorityReadback `
        -AuthorityReference $l1AuthorityRef -ExpectedAuthorityPath $l1AuthorityRef.path -ExpectedAuthoritySha256 $l1AuthorityRef.sha256 `
        -PersistedFact $l1RefusedPersistedFact -ResultReference $l1RefusedResultRef) -and
     (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultPersistence -Record $l1RefusedResultReadback `
        -PersistedFact $l1RefusedPersistedFact -ResultReference $l1RefusedResultRef -JournalReference $l1RefusedJournalRef `
        -JournalBytes $l1RefusedJournalBytes -CallerObservedTicks ($l1T0 + 1200L)))
$l1LateResultBytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $l1LateResult -Depth 50 -Compress))
$l1LateResultRef = [PSCustomObject][ordered]@{ path = $l1Output.result_path; bytes = [Int64]$l1LateResultBytes.Length; sha256 = (& $l1Sha $l1LateResultBytes)
    volume_serial_hex = '7777777777777777'; file_id_hex = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }
$l1LatePersistedFact = Copy-D32BoundedCompilerDiagnosticTestJson $l1PersistedFact
$l1LatePersistedFact.observed_ticks = [Int64]$l1LateCaseDeadlines.audit_deadline_ticks + 100L
foreach ($name in @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) {
    $propertyName = if ($name -ceq 'path') { 'result_path' } elseif ($name -ceq 'bytes') { 'result_bytes' } elseif ($name -ceq 'sha256') { 'result_sha256' } else { 'result_' + $name }
    $l1LatePersistedFact.$propertyName = $l1LateResultRef.$name
}
$l1LateJournalRows = @(
    [PSCustomObject][ordered]@{ event = 'AUTHORITY_ADMISSION'; case_id = ''; scheduled_ticks = $l1T0; observed_ticks = ($l1T0 + 50L); lateness_ticks = 50L
        result_path = $null; result_bytes = $null; result_sha256 = $null; result_volume_serial_hex = $null; result_file_id_hex = $null; gate_authority = 'NONE' },
    [PSCustomObject][ordered]@{ event = 'CASE_BUDGET_STOPPED'; case_id = 'NORMAL_EXIT'; scheduled_ticks = $null
        observed_ticks = [Int64]$l1LateCase.case_completed_ticks; lateness_ticks = $null; result_path = $null; result_bytes = $null; result_sha256 = $null
        result_volume_serial_hex = $null; result_file_id_hex = $null; gate_authority = 'NONE' },
    $l1LatePersistedFact)
$l1LateJournalBytes = [Text.UTF8Encoding]::new($false).GetBytes(((($l1LateJournalRows | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 12 -Compress }) -join "`n") + "`n"))
$l1LateJournalRef = [PSCustomObject][ordered]@{ path = $l1Output.journal_path; bytes = [Int64]$l1LateJournalBytes.Length; sha256 = (& $l1Sha $l1LateJournalBytes)
    volume_serial_hex = '8888888888888888'; file_id_hex = 'cccccccccccccccccccccccccccccccc' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'persistence consumer reconciles an at-audit BUDGET_STOPPED case without misclassifying it as ordinary BLOCKED' `
    (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultPersistence -Record $l1LateResult -PersistedFact $l1LatePersistedFact `
        -ResultReference $l1LateResultRef -JournalReference $l1LateJournalRef -JournalBytes $l1LateJournalBytes `
        -CallerObservedTicks ([Int64]$l1LatePersistedFact.observed_ticks + 100L))
$l1PartialBadBytes = [Text.UTF8Encoding]::new($false).GetBytes($l1PartialJournalBytes + [Text.Encoding]::UTF8.GetBytes("`n"))
$l1PartialBadRef = [PSCustomObject][ordered]@{ path = $l1Output.journal_path; bytes = [Int64]$l1PartialBadBytes.Length; sha256 = (& $l1Sha $l1PartialBadBytes)
    volume_serial_hex = $l1PartialJournalRef.volume_serial_hex; file_id_hex = $l1PartialJournalRef.file_id_hex }
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 persistence rejects injected blank journal lines' `
    (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1ResultPersistence -Record $l1Partial -PersistedFact $l1PartialFact -ResultReference $l1PartialRef `
        -JournalReference $l1PartialBadRef -JournalBytes $l1PartialBadBytes -CallerObservedTicks ($l1T0 + 2000L)))

$l1BoundaryBatch = $l1T0 + 60000L
$l1BoundaryDeadlines = Get-D32BoundedDiagnosticSourceProofNonSourceL1CaseDeadlines -CaseT0Ticks $l1T0 -Frequency 1000L -BatchDeadlineTicks $l1BoundaryBatch
$l1ClockBoundaries = (Get-D32BoundedDiagnosticSourceProofNonSourceL1Phase -NowTicks ($l1T0 + 4999L) -CaseT0Ticks $l1T0 -Frequency 1000L -BatchT0Ticks $l1T0 -BatchDeadlineTicks $l1BoundaryBatch) -ceq 'ACTIVE' -and
    (Get-D32BoundedDiagnosticSourceProofNonSourceL1Phase -NowTicks ($l1T0 + 5000L) -CaseT0Ticks $l1T0 -Frequency 1000L -BatchT0Ticks $l1T0 -BatchDeadlineTicks $l1BoundaryBatch) -ceq 'CLEANUP' -and
    (Get-D32BoundedDiagnosticSourceProofNonSourceL1Phase -NowTicks ($l1T0 + 10000L) -CaseT0Ticks $l1T0 -Frequency 1000L -BatchT0Ticks $l1T0 -BatchDeadlineTicks $l1BoundaryBatch) -ceq 'AUDIT' -and
    (Get-D32BoundedDiagnosticSourceProofNonSourceL1Phase -NowTicks ($l1T0 + 15000L) -CaseT0Ticks $l1T0 -Frequency 1000L -BatchT0Ticks $l1T0 -BatchDeadlineTicks $l1BoundaryBatch) -ceq 'AUDIT' -and
    (Get-D32BoundedDiagnosticSourceProofNonSourceL1Phase -NowTicks $l1BoundaryBatch -CaseT0Ticks $l1T0 -Frequency 1000L -BatchT0Ticks $l1T0 -BatchDeadlineTicks $l1BoundaryBatch) -ceq 'BATCH_EXPIRED' -and
    [Int64]$l1BoundaryDeadlines.active_deadline_ticks -eq ($l1T0 + 5000L) -and
    [Int64]$l1BoundaryDeadlines.cleanup_deadline_ticks -eq ($l1T0 + 10000L) -and
    [Int64]$l1BoundaryDeadlines.audit_deadline_ticks -eq ($l1T0 + 15000L)
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 pure QPC clock model enforces active/cleanup/audit/batch boundaries without sleeping' $l1ClockBoundaries
$l1RollbackRejected = $false
try { $null = Get-D32BoundedDiagnosticSourceProofNonSourceL1Phase -NowTicks ($l1T0 - 1L) -CaseT0Ticks $l1T0 -Frequency 1000L -BatchT0Ticks $l1T0 -BatchDeadlineTicks $l1BoundaryBatch }
catch { $l1RollbackRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 pure QPC phase rejects counter rollback rather than resetting the budget' $l1RollbackRejected

$controllerPath = Join-Path $PSScriptRoot 'd32-bounded-diagnostic-sourceproof-controller.ps1'
$controllerTokens = $null; $controllerParseErrors = $null
$controllerAst = [System.Management.Automation.Language.Parser]::ParseFile($controllerPath, [ref]$controllerTokens, [ref]$controllerParseErrors)
$controllerText = [string]$controllerAst.Extent.Text
$controllerForbiddenCommands = @($controllerAst.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
    ([string]$node.GetCommandName() -match '^(?i:Start-Process|Start-Job|Invoke-Expression|Import-Module|Get-CimInstance|Get-Process|Stop-Process|cargo|git|rustc)$')
}, $true))
$controllerNativeCreationOrder = $controllerText.IndexOf('CreateProcessW(image,') -ge 0 -and
    $controllerText.IndexOf('CreateProcessW(image,') -lt $controllerText.IndexOf('AssignProcessToJobObject(owned.Job, owned.Process)') -and
    $controllerText.IndexOf('AssignProcessToJobObject(owned.Job, owned.Process)') -lt $controllerText.IndexOf('ResumeThread(owned.Thread)')
$controllerSafetyAst = $controllerParseErrors.Count -eq 0 -and $controllerForbiddenCommands.Count -eq 0 -and
    $controllerNativeCreationOrder -and $controllerText.Contains('CREATE_SUSPENDED') -and
    $controllerText.Contains('JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE') -and $controllerText.Contains('StartSuspendedAssignedAndResume') -and
    $controllerText.Contains("'-NoLogo', '-NoProfile', '-NonInteractive', '-File'") -and
    -not $controllerText.Contains('Process.GetProcesses') -and -not $controllerText.Contains('.Kill()') -and
    $controllerText.Contains('cleanup_deadline_ticks') -and $controllerText.Contains('terminal_audit_deadline_ticks')
Assert-D32BoundedCompilerDiagnosticSelfTest 'durable controller AST has one fixed suspended CreateProcess→Job assignment→resume order and no free-form helper/commands' $controllerSafetyAst
$l1PreCreatePlanAst = $controllerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'New-D32NonSourceL1PreCreatePlan'
}, $true)
$l1CaseRunnerAst = $controllerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-D32NonSourceL1Case'
}, $true)
$l1PlanText = if ($null -eq $l1PreCreatePlanAst) { '' } else { [string]$l1PreCreatePlanAst.Extent.Text }
$l1CaseText = if ($null -eq $l1CaseRunnerAst) { '' } else { [string]$l1CaseRunnerAst.Extent.Text }
$l1RefusalIndex = $l1CaseText.IndexOf("if (`$caseId -ceq 'ENTRY_PIN_BINDING_REFUSAL')", [StringComparison]::Ordinal)
$l1CreateIndex = $l1CaseText.IndexOf('StartSuspendedAssignedAndResume(', [StringComparison]::Ordinal)
$l1ControllerBranchIndex = $controllerText.LastIndexOf("if (`$PSCmdlet.ParameterSetName -ceq 'NonSourceL1')", [StringComparison]::Ordinal)
$l1ControllerProofStart = if ($l1ControllerBranchIndex -ge 0) {
    $controllerText.IndexOf("if (`$PSVersionTable.PSVersion -lt [version]'7.5'", $l1ControllerBranchIndex + 1, [StringComparison]::Ordinal)
} else { -1 }
$l1ControllerBranchText = if ($l1ControllerBranchIndex -ge 0 -and $l1ControllerProofStart -gt $l1ControllerBranchIndex) {
    $controllerText.Substring($l1ControllerBranchIndex, $l1ControllerProofStart - $l1ControllerBranchIndex)
} else { '' }
$l1ControllerModeIsolation = $l1PlanText.Contains("@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', `$entryPath,") -and
    $l1PlanText.Contains("'-NonSourceL1', '-L1AuthorityPath', `$L1AuthorityPath, '-ExpectedL1AuthoritySha256', `$ExpectedL1AuthoritySha256") -and
    $l1PlanText.Contains("'-L1CandidateSha', `$CandidateSha, '-L1BatchId'") -and
    $l1PlanText.Contains("'-L1CaseId', `$CaseId, '-L1Nonce', `$Nonce") -and
    $l1PlanText.Contains("'-L1T0Ticks', [string]`$L1T0Ticks") -and
    $l1PlanText.Contains("'-L1ActiveDeadlineTicks', [string]`$ActiveDeadlineTicks") -and
    -not $l1PlanText.Contains('SourceProofAuthorityPath') -and -not $l1PlanText.Contains('ToolchainProfilePath') -and
    -not $l1PlanText.Contains('HistoricalOriginCandidateSha') -and
    $l1RefusalIndex -ge 0 -and $l1CreateIndex -gt $l1RefusalIndex -and
    $l1CaseText.Contains('-DeriveEntryPinMismatch:($caseId -ceq ''ENTRY_PIN_BINDING_REFUSAL'')') -and
    $l1ControllerBranchText.Contains('try { $l1ExitCode = [int](Invoke-D32NonSourceL1) }') -and
    -not $l1ControllerBranchText.Contains('Invoke-D32BoundedDiagnosticSourceProofRun')
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 fixed controller argv/roles exclude SourceProof inputs; actual zero-create refusal returns before the only case launch' $l1ControllerModeIsolation
$l1InvokeAst = $controllerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-D32NonSourceL1'
}, $true)
$l1InvokeText = if ($null -eq $l1InvokeAst) { '' } else { [string]$l1InvokeAst.Extent.Text }
$l1NativeInitAt = $l1InvokeText.IndexOf('Add-Type -TypeDefinition $nativeSource', [StringComparison]::Ordinal)
$l1AuthorityReadAt = $l1InvokeText.IndexOf('Get-D32LifecycleReferenceBytes -Path $L1AuthorityPath', [StringComparison]::Ordinal)
$l1AdmissionValidatedAt = $l1InvokeText.IndexOf('$script:D32NonSourceL1AdmissionValidated = $true', [StringComparison]::Ordinal)
$l1FirstCaseAt = $l1InvokeText.IndexOf('Invoke-D32NonSourceL1Case -Index $index', [StringComparison]::Ordinal)
$l1NativeBootstrapOrder = $l1NativeInitAt -ge 0 -and $l1AuthorityReadAt -gt $l1NativeInitAt -and
    $l1AdmissionValidatedAt -gt $l1AuthorityReadAt -and $l1FirstCaseAt -gt $l1AdmissionValidatedAt -and
    ([regex]::Matches($l1InvokeText, 'Add-Type -TypeDefinition \$nativeSource')).Count -eq 1
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 initializes its existing in-process identity surface before the first pinned-handle read and launches cases only after admission' $l1NativeBootstrapOrder
$l1ErrorFormatterAst = $controllerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-D32NonSourceL1ErrorText'
}, $true)
$l1ErrorAccumulatorAst = $controllerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Add-D32NonSourceL1Error'
}, $true)
$l1FailureStatusAst = $controllerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-D32NonSourceL1FailureStatus'
}, $true)
$l1DiagnosticWriterAst = $controllerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Write-D32NonSourceL1Diagnostic'
}, $true)
$l1ReaderRefusalExtractorAst = $controllerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-D32NonSourceL1ReaderRefusalError'
}, $true)
$l1ErrorFormatterLoaded = $false; $l1ErrorAccumulatorLoaded = $false; $l1FailureStatusLoaded = $false; $l1DiagnosticWriterLoaded = $false; $l1ReaderRefusalExtractorLoaded = $false
if ($null -ne $l1ErrorFormatterAst) { . ([ScriptBlock]::Create([string]$l1ErrorFormatterAst.Extent.Text)); $l1ErrorFormatterLoaded = $true }
if ($null -ne $l1ErrorAccumulatorAst) { . ([ScriptBlock]::Create([string]$l1ErrorAccumulatorAst.Extent.Text)); $l1ErrorAccumulatorLoaded = $true }
if ($null -ne $l1FailureStatusAst) { . ([ScriptBlock]::Create([string]$l1FailureStatusAst.Extent.Text)); $l1FailureStatusLoaded = $true }
if ($null -ne $l1DiagnosticWriterAst) { . ([ScriptBlock]::Create([string]$l1DiagnosticWriterAst.Extent.Text)); $l1DiagnosticWriterLoaded = $true }
if ($null -ne $l1ReaderRefusalExtractorAst) { . ([ScriptBlock]::Create([string]$l1ReaderRefusalExtractorAst.Extent.Text)); $l1ReaderRefusalExtractorLoaded = $true }
$l1ErrorDetail = Get-D32NonSourceL1ErrorText -Exception ([InvalidOperationException]::new('bad token=secret-value nonce=0123456789abcdef0123456789abcdef at "C:\private user\settings.json" 0123456789abcdef0123456789abcdef01234567' + "`r`nsecondary line"))
$l1DiagnosticWriter = [IO.StringWriter]::new()
$l1DiagnosticWriteSucceeded = Write-D32NonSourceL1Diagnostic -Status 'REFUSED' -PrimaryError $l1ErrorDetail `
    -SecondaryErrors @('secondary token=not-secret at \\\\server\\private\\proof.json', 'second secondary') -Writer $l1DiagnosticWriter
$l1DiagnosticCapture = $l1DiagnosticWriter.ToString()
$l1DiagnosticLine = $l1DiagnosticCapture.TrimEnd([char[]]@("`r", "`n"))
$l1DiagnosticSafe = $l1ErrorFormatterLoaded -and $l1ErrorAccumulatorLoaded -and $l1FailureStatusLoaded -and $l1DiagnosticWriterLoaded -and $l1ReaderRefusalExtractorLoaded -and $l1DiagnosticWriteSucceeded -and
    $l1DiagnosticLine.StartsWith('D32_NON_SOURCE_L1 status=REFUSED primary=', [StringComparison]::Ordinal) -and
    -not $l1DiagnosticCapture.Contains('secret-value') -and -not $l1DiagnosticCapture.Contains('C:\private') -and
    -not $l1DiagnosticCapture.Contains('private user') -and -not $l1DiagnosticCapture.Contains('0123456789abcdef0123456789abcdef') -and
    -not $l1DiagnosticCapture.Contains('server') -and $l1DiagnosticCapture.Contains('secondary0=') -and
    -not $l1DiagnosticLine.Contains("`r") -and -not $l1DiagnosticLine.Contains("`n") -and
     [Text.Encoding]::UTF8.GetByteCount($l1DiagnosticCapture) -le 4096
Assert-D32BoundedCompilerDiagnosticSelfTest 'early L1 errors become one bounded stderr-compatible line with path/token redaction' $l1DiagnosticSafe
$l1ControllerReaderRefusalError = Get-D32NonSourceL1ReaderRefusalError -StderrCapture 'D32NSL1|REFUSED|RuntimeException: rejected token=hidden at "C:\private source\authority.json"'
$l1UnknownReaderError = Get-D32NonSourceL1ReaderRefusalError -StderrCapture 'D32NSL1|FIXED|NORMAL'
Assert-D32BoundedCompilerDiagnosticSelfTest 'controller preserves only the reader refusal detail with its exact fixed prefix and keeps other stderr mismatches generic' `
    ($l1ControllerReaderRefusalError -like '*reader admission refused*' -and -not $l1ControllerReaderRefusalError.Contains('hidden') -and
     -not $l1ControllerReaderRefusalError.Contains('private source') -and $null -eq $l1UnknownReaderError)
$l1SavedPrimary = $script:D32NonSourceL1Primary; $l1SavedSecondary = $script:D32NonSourceL1Secondary
try {
    $script:D32NonSourceL1Primary = $null
    $script:D32NonSourceL1Secondary = [System.Collections.Generic.List[string]]::new()
    $null = Add-D32NonSourceL1Error -Exception ([InvalidOperationException]::new('first failure'))
    $null = Add-D32NonSourceL1Error -Exception ([InvalidOperationException]::new('secondary cleanup failure'))
    $script:D32NonSourceL1AdmissionValidated = $false
    $l1PreadmissionStatus = Get-D32NonSourceL1FailureStatus -ErrorText 'reader authority refused'
    $script:D32NonSourceL1AdmissionValidated = $true
    $l1PostAdmissionStatus = Get-D32NonSourceL1FailureStatus -ErrorText 'unexpected controller exception'
    $l1ErrorsPreserved = $script:D32NonSourceL1Primary -like '*first failure*' -and
        $script:D32NonSourceL1Secondary.Count -eq 1 -and $script:D32NonSourceL1Secondary[0] -like '*secondary cleanup failure*' -and
        $l1PreadmissionStatus -ceq 'REFUSED' -and $l1PostAdmissionStatus -ceq 'UNRESOLVED'
} finally {
    $script:D32NonSourceL1Primary = $l1SavedPrimary; $script:D32NonSourceL1Secondary = $l1SavedSecondary
    Remove-Variable -Scope Script -Name D32NonSourceL1AdmissionValidated -ErrorAction SilentlyContinue
}
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 preserves the first failure, bounds secondary cleanup errors, and distinguishes pre-admission refusal from post-admission unresolved state' $l1ErrorsPreserved
$l1LongDiagnosticWriter = [IO.StringWriter]::new()
$l1LongWriteSucceeded = Write-D32NonSourceL1Diagnostic -Status 'UNRECOGNIZED' -PrimaryError ('X' * 10000) -Writer $l1LongDiagnosticWriter
$l1LongCapture = $l1LongDiagnosticWriter.ToString()
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 diagnostic fallback maps unknown states to UNRESOLVED and remains under the stream cap' `
    ($l1LongWriteSucceeded -and $l1LongCapture.StartsWith('D32_NON_SOURCE_L1 status=UNRESOLVED ', [StringComparison]::Ordinal) -and
     [Text.Encoding]::UTF8.GetByteCount($l1LongCapture) -le 4096)
$l1ErrorWriterBranch = $l1ControllerBranchText.Contains('if ($l1ExitCode -ne 0 -or $diagnosticStatus -cne ''COMPLETE_NON_SOURCE_L1'')') -and
    $l1ControllerBranchText.Contains('Write-D32NonSourceL1Diagnostic') -and
    $l1ControllerBranchText.Contains('-SecondaryErrors @($script:D32NonSourceL1Secondary.ToArray())') -and
    $l1ControllerBranchText.IndexOf('Write-D32NonSourceL1Diagnostic', [StringComparison]::Ordinal) -lt $l1ControllerBranchText.LastIndexOf('exit $l1ExitCode', [StringComparison]::Ordinal)
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 controller catches escaped exceptions and emits diagnostics before preserving its fixed exit code' $l1ErrorWriterBranch
$l1ReaderText = [string]$l1EntryAst.Extent.Text
$l1ReaderOwnRuntimeBinding = $l1ReaderText.Contains('$currentImagePath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName') -and
    $l1ReaderText.Contains('$currentOwnerId = [string]$currentIdentity.User.Value') -and
    $l1ReaderText.Contains('$currentSystemRoot = [Environment]::GetEnvironmentVariable(''SystemRoot'')') -and
    $l1ReaderText.Contains('-RuntimePath $currentImagePath -OwnerId $currentOwnerId -SystemRoot $currentSystemRoot') -and
    $l1ReaderText.Contains("[Console]::Error.WriteLine(('D32NSL1|REFUSED|' + `$readerErrorText))")
Assert-D32BoundedCompilerDiagnosticSelfTest 'reader runtime/owner/system-root remain bound to actual process identity while refusal output is bounded and sanitized' $l1ReaderOwnRuntimeBinding
$l1CleanupCatches = [regex]::Matches($l1InvokeText, 'catch \{ \$cleanupFailed = \$true; \$null = Add-D32NonSourceL1Error -Exception \$_\.Exception \}').Count -ge 3
$l1PrimaryCatchPreserved = $l1InvokeText.Contains('$null = Add-D32NonSourceL1Error -Exception $_.Exception -Message $caughtError') -and
    $l1InvokeText.Contains("if (`$cleanupFailed) { `$script:D32NonSourceL1Status = 'UNRESOLVED' }") -and
    $l1InvokeText.Contains("if (-not `$script:D32NonSourceL1AdmissionValidated) { return 87 }")
Assert-D32BoundedCompilerDiagnosticSelfTest 'L1 cleanup errors are collected without bypassing trusted pre-admission refusal or later result persistence' ($l1CleanupCatches -and $l1PrimaryCatchPreserved)
$controllerClockFunction = $controllerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-D32LifecycleNow'
}, $true)
$controllerReaderFunction = $controllerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-D32LifecycleReferenceBytes'
}, $true)
$controllerClockReaderText = if ($null -eq $controllerReaderFunction) { '' } else { [string]$controllerReaderFunction.Extent.Text }
$controllerFakeClockWorked = $false
if ($null -ne $controllerClockFunction) {
    . ([ScriptBlock]::Create([string]$controllerClockFunction.Extent.Text))
    try {
        $script:D32LifecycleNow = { [Int64]424242 }
        $clockBeforeBoundary = Get-D32LifecycleNow
        $script:D32LifecycleNow = { [Int64]$lifecycleWork }
        $clockAtWorkBoundary = Get-D32LifecycleNow
        $controllerFakeClockWorked = ($clockBeforeBoundary -eq 424242L -and $clockAtWorkBoundary -eq $lifecycleWork -and
            $controllerClockReaderText.Contains('(Get-D32LifecycleNow)') -and -not $controllerClockReaderText.Contains('Stopwatch]::GetTimestamp'))
    } catch { $controllerFakeClockWorked = $false }
    finally {
        Remove-Item Function:\Get-D32LifecycleNow -ErrorAction SilentlyContinue
        Remove-Variable -Scope Script -Name D32LifecycleNow -ErrorAction SilentlyContinue
    }
}
Assert-D32BoundedCompilerDiagnosticSelfTest 'controller bounded-input clock checks use the injectable shared monotonic source at both pre/post-read boundaries' $controllerFakeClockWorked
$controllerPreservesPrimaryAst = $controllerText.Contains('if (-not $script:D32LifecyclePrimary) { $script:D32LifecyclePrimary = $caughtError }') -and
    $controllerText.Contains('elseif ($script:D32LifecycleSecondary.Count -lt 8)') -and
    $controllerText.Contains('The bounded terminal audit result was not persisted before expiry.')
Assert-D32BoundedCompilerDiagnosticSelfTest 'controller preserves the first primary cause, bounds secondary errors, and records terminal persistence failure' $controllerPreservesPrimaryAst
$resultPersistCall = $controllerText.IndexOf('try { $recordWritten = Write-D32LifecycleFinalRecord }', [StringComparison]::Ordinal)
$resultJournalCall = $controllerText.IndexOf('Add-D32LifecycleExecutionRecordPersistedFact', $resultPersistCall, [StringComparison]::Ordinal)
$journalCloseCall = $controllerText.IndexOf('Close-D32LifecycleJournalStream', $resultJournalCall, [StringComparison]::Ordinal)
$persistedJournalFunction = if ($null -eq ($controllerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Add-D32LifecycleExecutionRecordPersistedFact' }, $true))) { '' } else { [string]($controllerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Add-D32LifecycleExecutionRecordPersistedFact' }, $true).Extent.Text) }
$controllerResultPersistClosure = $resultPersistCall -ge 0 -and $resultPersistCall -lt $resultJournalCall -and $resultJournalCall -lt $journalCloseCall -and
    $persistedJournalFunction.Contains('execution_record_sha256') -and $persistedJournalFunction.Contains('execution_record_bytes') -and
    $persistedJournalFunction.Contains('remaining_ticks') -and $persistedJournalFunction.Contains('65536') -and
    $persistedJournalFunction.Contains("gate_authority = 'NONE'")
Assert-D32BoundedCompilerDiagnosticSelfTest 'post-write journal fact binds exact result bytes/hash and observed timing before bounded journal close' $controllerResultPersistClosure
$controllerNativeAssignment = $controllerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text.EndsWith('nativeSource')
}, $true)
$controllerNativeSourceText = if ($null -eq $controllerNativeAssignment) { '' } else { [string]$controllerNativeAssignment.Right.Expression.Value }
Assert-D32BoundedCompilerDiagnosticSelfTest 'controller in-process native source itself has exactly one CreateProcess API and retained-handle-only cleanup' `
    ($controllerNativeSourceText -match 'static extern bool CreateProcessW\(' -and
     ([regex]::Matches($controllerNativeSourceText, 'if \(!CreateProcessW\(image,')).Count -eq 1 -and
     $controllerNativeSourceText.Contains('JOB_OBJECT_LIMIT_ACTIVE_PROCESS') -and
     $controllerNativeSourceText.Contains('ActiveProcessLimit = 1') -and
     $controllerNativeSourceText.Contains('TerminateExactProcess') -and
     $controllerNativeSourceText.Contains('AssignProcessToJobObject(owned.Job, owned.Process)') -and
     $controllerNativeSourceText.Contains('Close(ref process.Process)'))
$controllerNativeCompilationCovered = $controllerNativeSourceText.Contains('using System;') -and
    $controllerNativeSourceText.Contains('static extern bool CreateProcessW(')
$controllerNativeCompilationSucceeded = $false
try { Add-Type -TypeDefinition $controllerNativeSourceText -Language CSharp -ErrorAction Stop; $controllerNativeCompilationSucceeded = $true } catch { $controllerNativeCompilationSucceeded = $false }
Assert-D32BoundedCompilerDiagnosticSelfTest 'native supervisor surface compiles in-process without invoking P/Invoke or launching a native child' ($controllerNativeCompilationCovered -and $controllerNativeCompilationSucceeded)

foreach ($consumer in $formalConsumerSchemas) {
    $consumerText = [IO.File]::ReadAllText($consumer.path, [Text.UTF8Encoding]::new($false, $true))
    Assert-D32BoundedCompilerDiagnosticSelfTest "formal consumer remains on its exact schema and rejects diagnostic V3/census V2: $([IO.Path]::GetFileName($consumer.path))" `
        ($consumerText.Contains([string]$consumer.schema) -and -not $consumerText.Contains('D32_BOUNDED_COMPILER_DIAGNOSTIC_V3') -and
         -not $consumerText.Contains('D32_BOUNDED_DIAGNOSTIC_ARCHIVE_FORMAT_CENSUS_V2'))
}

Write-Output 'D32_BOUNDED_COMPILER_DIAGNOSTIC_POLICY_SELFTEST_COVERAGE: exact Git query and global writer bounds, argv/budget/environment, source-plan V1 rejection, locked-source graph V2 roots/hosts/targets, edge reconciliation, conservative feature/cfg evaluation, exhaustive inclusion/exclusion witnesses, in-memory Git pack/index SHA-1/CRC/REF_DELTA parsing, strict USTAR/GNU/mixed registry archive decoding, GNU L controls, exact fallback/pair/inventory digests and strict negative matrix, USTAR prefix/reserved-byte and numeric/checksum/text/type/path/NFC/collision negatives, optional unique package-root directory, inferred/explicit parent equivalence, same-member-inventory cross-layout fixtures, producer/census header digest/count equivalence, ordinary-payload-discard versus control-metadata-hash census behavior, gzip/tar framing/padding/truncation/time/member-budget outcomes, strict census-authority V2 and census-result V2 exact-schema/policy/root/identity/source-pin/archive-set/budget/output/coverage/header-count/format-count/status/primary-error roundtrips and mutation negatives, unsupported first-header and unexamined-remainder preservation, no-auto-launch/caller-pinned entry AST checks, strict source-proof V4/header-digest/count/policy crossbinding, canonical Cargo registry .cargo-ok bytes and distinct Git marker rules, auxiliary metadata routing, Cargo checksum and .git pointer malformed-input negatives, source-proof constructor/fallback/timeout branches and dual current/historical bindings, source-proof execution authority/result V1 producer-validator-JSON-consumer closure and strict scalar/schema mutations, isolated NON_SOURCE_L1 authority/result V1 producer→reader→JSON→consumer closure, exact six-code pin reader terminal branch and mode-disjoint fixed argv/environment roles, 2-create/1-termination/0-create refusal lifecycle evidence, one-reader Job active-process limit and retained-identity AST checks, 60-second shared T0 and 5/10/15-second case deadlines, ordered execution/NOT_RUN suffix and at-audit BUDGET_STOPPED result/journal reconciliation, no fabricated PID/capture on refusal, formal/SourceProof-domain cross-rejection, shared synthetic QPC phase boundaries at 269999/270000/299999/300000/345000/360000, clock rollback/overflow and reset rejection, exit/deadline race and late-zero/partial-result refusal, fake-clock controller read boundaries, retained-handle/job AST ordering and PID-creation identity requirements, bounded capture/journal/candidate limits, exact result-persisted journal bytes/hash/timing ordering, primary-error preservation and formal-consumer refusal. Pure synthetic fixtures only: no Cargo, native child/PInvoke invocation, network, registry cache, or archive content access.'
Write-Output ('D32_BOUNDED_COMPILER_DIAGNOSTIC_CONTAINMENT_REPARSE_FIXTURE: ' + $script:D32ContainmentReparseFixtureStatus)
