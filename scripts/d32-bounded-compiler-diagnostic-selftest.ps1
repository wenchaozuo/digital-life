# Module-free, no-Cargo policy regression tests. This file is intentionally not
# referenced by any operational runner and must be run only as a focused test.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'd32-bounded-compiler-diagnostic-policy.ps1')

function Assert-D32BoundedCompilerDiagnosticSelfTest {
    param([string]$Name, [bool]$Condition)
    if (-not $Condition) { throw "D32_BOUNDED_COMPILER_DIAGNOSTIC_SELFTEST_FAILED: $Name" }
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

function New-D32BoundedCompilerDiagnosticTestTarGzip {
    param([Parameter(Mandatory = $true)][object[]]$Entries)
    $tar = [IO.MemoryStream]::new()
    try {
        foreach ($entry in $Entries) {
            $header = [byte[]]::new(512)
            Set-D32BoundedCompilerDiagnosticTestTarText -Header $header -Offset 0 -Length 100 -Value ([string]$entry.path)
            Set-D32BoundedCompilerDiagnosticTestTarOctal -Header $header -Offset 100 -Length 8 -Value 420
            Set-D32BoundedCompilerDiagnosticTestTarOctal -Header $header -Offset 108 -Length 8 -Value 0
            Set-D32BoundedCompilerDiagnosticTestTarOctal -Header $header -Offset 116 -Length 8 -Value 0
            $content = if ($null -eq $entry.content) { [byte[]]::new(0) } else { [byte[]]$entry.content }
            Set-D32BoundedCompilerDiagnosticTestTarOctal -Header $header -Offset 124 -Length 12 -Value $content.Length
            Set-D32BoundedCompilerDiagnosticTestTarOctal -Header $header -Offset 136 -Length 12 -Value 0
            [Array]::Copy([Text.Encoding]::ASCII.GetBytes("ustar`0"), 0, $header, 257, 6)
            [Array]::Copy([Text.Encoding]::ASCII.GetBytes('00'), 0, $header, 263, 2)
            $typeFlag = if ($null -ne $entry.type_flag) { [string]$entry.type_flag } elseif ([string]$entry.kind -ceq 'directory') { '5' } else { '0' }
            $header[156] = [byte][char]$typeFlag
            for ($index = 148; $index -lt 156; $index++) { $header[$index] = 32 }
            $sum = [Int64]0
            foreach ($value in $header) { $sum += [Int64]$value }
            $checksum = [Convert]::ToString($sum, 8).PadLeft(6, '0') + "`0 "
            [Array]::Copy([Text.Encoding]::ASCII.GetBytes($checksum), 0, $header, 148, 8)
            $tar.Write($header, 0, $header.Length)
            if ($content.Length -gt 0) { $tar.Write($content, 0, $content.Length) }
            $padding = (512 - ($content.Length % 512)) % 512
            if ($padding -gt 0) { $tar.Write([byte[]]::new($padding), 0, $padding) }
        }
        $tar.Write([byte[]]::new(1024), 0, 1024)
        $compressed = [IO.MemoryStream]::new()
        try {
            $gzip = [IO.Compression.GZipStream]::new($compressed, [IO.Compression.CompressionMode]::Compress, $true)
            try { $bytes = $tar.ToArray(); $gzip.Write($bytes, 0, $bytes.Length) }
            finally { $gzip.Dispose() }
            return ,$compressed.ToArray()
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

$lockText = @'
version = 4

[[package]]
name = "sample-crate"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
dependencies = ["another-crate"]

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
$sourcePlan = Get-D32BoundedCompilerDiagnosticSourcePlan -LockText $lockText
Assert-D32BoundedCompilerDiagnosticSelfTest 'source plan is explicitly non-authorizing and not verified' ($sourcePlan.record_type -ceq 'D32_BOUNDED_DIAGNOSTIC_LOCK_SOURCE_PLAN_V1' -and $sourcePlan.gate_authority -ceq 'NONE' -and $sourcePlan.verification_status -ceq 'NOT_RUN' -and $sourcePlan.source_proof_status -ceq 'NOT_VERIFIED')
Assert-D32BoundedCompilerDiagnosticSelfTest 'source plan declares the verifier-wide 512 MiB cap and single buffered-archive ceiling' ($sourcePlan.verifier_managed_buffer_cap_bytes -eq 536870912L -and $script:D32BoundedCompilerDiagnosticRegistryArchiveLimitBytes -eq 268435456L)
Assert-D32BoundedCompilerDiagnosticSelfTest 'source plan emits exact registry archive and source paths' ($sourcePlan.registry_package_count -eq 1 -and $sourcePlan.registry_packages[0].archive_path -ceq 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f\sample-crate-1.2.3.crate' -and $sourcePlan.registry_packages[0].extracted_source_path -ceq 'E:\d32\inv7\r\c\registry\src\index.crates.io-1949cf8c6b5b557f\sample-crate-1.2.3')
Assert-D32BoundedCompilerDiagnosticSelfTest 'source plan emits immutable Git URL/commit tuple and fixed roots' ($sourcePlan.git_source_count -eq 1 -and $sourcePlan.git_sources[0].url -ceq ('https://example.invalid/repo?rev=' + ('b' * 40)) -and $sourcePlan.git_sources[0].commit -ceq ('b' * 40) -and $sourcePlan.git_sources[0].database_root -ceq 'E:\d32\inv7\r\c\git\db' -and $sourcePlan.git_sources[0].checkout_root -ceq 'E:\d32\inv7\r\c\git\checkouts')
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
    [PSCustomObject]@{ path = "$archiveRoot/src/lib.rs"; kind = 'file'; content = [Text.Encoding]::UTF8.GetBytes('pub fn sample() {}' + "`n") })
$archiveBytes = New-D32BoundedCompilerDiagnosticTestTarGzip -Entries $archiveMembers
$archiveSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($archiveBytes)).ToLowerInvariant()
$archiveInventory = Get-D32BoundedCompilerDiagnosticCrateArchiveInventory -CompressedBytes $archiveBytes -ExpectedPackageRoot $archiveRoot -ExpectedArchiveSha256 $archiveSha
Assert-D32BoundedCompilerDiagnosticSelfTest 'strict USTAR archive parsed into complete file and directory hashes' ($archiveInventory.member_count -eq 3 -and $archiveInventory.entries.Count -eq 2 -and $archiveInventory.archive_sha256 -ceq $archiveSha -and $archiveInventory.entries[1].path -ceq 'src/lib.rs')
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

function New-D32BoundedCompilerDiagnosticTestReference {
    param([string]$Path)
    return [PSCustomObject][ordered]@{ path = $Path; bytes = 1L; sha256 = 'a' * 64; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
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
    schema_version = 1
    record_type = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_AUTHORITY_V1'
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
        owner_record = $testOwnerReference; blocked_diagnostic = $testBlockedReference; protoc_run_grant = $testGrantReference
        fetch_records = $testFetchReferences; manifest_refs = $testManifestReferences
        registry_archive_root = [PSCustomObject]@{ path = 'E:\d32\inv7\r\c\registry\cache\index.crates.io-1949cf8c6b5b557f'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
        registry_source_root = [PSCustomObject]@{ path = 'E:\d32\inv7\r\c\registry\src\index.crates.io-1949cf8c6b5b557f'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
        git_database_root = [PSCustomObject]@{ path = 'E:\d32\inv7\r\c\git\db'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
        git_checkout_root = [PSCustomObject]@{ path = 'E:\d32\inv7\r\c\git\checkouts'; volume_serial_hex = '0123456789abcdef'; file_id_hex = '0123456789abcdef0123456789abcdef' }
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

$diagnosticRecord = [PSCustomObject]@{ record_type = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_V1'; gate_authority = 'NONE'; status = 'COMPLETED_DIAGNOSTIC' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'diagnostic result rejected by formal record gate' (Test-D32BoundedCompilerDiagnosticFormalReject $diagnosticRecord)
$formalRecord = [PSCustomObject]@{ record_type = 'D32_PHASE0_MATRIX_RECORD_V8'; gate_authority = 'PHASE0'; status = 'PASS' }
Assert-D32BoundedCompilerDiagnosticSelfTest 'formal Phase0 record remains outside diagnostic reject helper' (-not (Test-D32BoundedCompilerDiagnosticFormalReject $formalRecord))
try { $null = Assert-D32BoundedCompilerDiagnosticStatus 'PASS'; $passStatusRejected = $false } catch { $passStatusRejected = $true }
Assert-D32BoundedCompilerDiagnosticSelfTest 'PASS status unavailable' $passStatusRejected
$rawReplayStatuses = @('COMPLETED_DIAGNOSTIC', 'BUDGET_STOPPED', 'REFUSED', 'UNRESOLVED')
foreach ($rawStatus in $rawReplayStatuses) {
    $replay = [PSCustomObject]@{ record_type = 'D32_BOUNDED_COMPILER_DIAGNOSTIC_V1'; gate_authority = 'NONE'; status = $rawStatus; phase1_allowed = $false; aggregate_allowed = $false }
    Assert-D32BoundedCompilerDiagnosticStatus $rawStatus | Out-Null
    Assert-D32BoundedCompilerDiagnosticSelfTest "raw replay $rawStatus remains non-gating" (Test-D32BoundedCompilerDiagnosticFormalReject $replay -and -not [bool]$replay.phase1_allowed -and -not [bool]$replay.aggregate_allowed)
}
$formalConsumerSchemas = @(
    [PSCustomObject]@{ path = (Join-Path $PSScriptRoot 'd32-preflight.ps1'); schema = 'D32_PHASE0_MATRIX_RECORD_V8' },
    [PSCustomObject]@{ path = (Join-Path $PSScriptRoot 'd32-phase0-matrix.ps1'); schema = 'D32_PHASE0_MATRIX_RECORD_V8' },
    [PSCustomObject]@{ path = (Join-Path $PSScriptRoot 'd32-downstream-readiness.ps1'); schema = 'D32_POST_BUNDLE_AGGREGATE_RECORD_V8' }
)
foreach ($consumer in $formalConsumerSchemas) {
    $consumerText = [IO.File]::ReadAllText($consumer.path, [Text.UTF8Encoding]::new($false, $true))
    Assert-D32BoundedCompilerDiagnosticSelfTest "formal consumer remains on its exact schema: $([IO.Path]::GetFileName($consumer.path))" ($consumerText.Contains([string]$consumer.schema) -and -not $consumerText.Contains('D32_BOUNDED_COMPILER_DIAGNOSTIC_V1'))
}

Write-Output 'D32_BOUNDED_COMPILER_DIAGNOSTIC_POLICY_SELFTEST_COVERAGE: exact Git query bounds, argv/budget/environment, lock-derived source plan, in-memory Git pack/index SHA-1/CRC/REF_DELTA/tree parsing and rejection cases, strict registry USTAR/path/hash parsing, PID+creation-time raw sampling replay, historical BLOCKED/NONE replay, resource/capture/deadline policy, cleanup and no-test-launch checks, exact formal-consumer schema rejection, all four non-PASS statuses. No Cargo, native child, external source, or inv7 content access.'
