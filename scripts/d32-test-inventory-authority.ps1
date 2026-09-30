# D32 external test-inventory discovery/baseline helpers.
# This file defines functions only; the Phase0 runner owns invocation and trust.

function Get-D32TestInventoryPackages {
    return @(
        [PSCustomObject]@{ package = 'protocol'; manifest = 'vita-agent-protocol/Cargo.toml'; features = @() },
        [PSCustomObject]@{ package = 'vita'; manifest = 'vita-agent/Cargo.toml'; features = @('d32-a-test-helper') },
        [PSCustomObject]@{ package = 'host'; manifest = 'src-tauri/Cargo.toml'; features = @('d32-a-host-canary') }
    )
}

function Get-D32TestInventoryProfileRecord {
    param([Parameter(Mandatory = $true)][object]$ValidatedProfile)
    return [ordered]@{
        path = [string]$ValidatedProfile.ProfilePath
        sha256 = [string]$ValidatedProfile.Digest
        file_identity = [ordered]@{
            bytes = [Int64]$ValidatedProfile.Identity.Bytes
            volume_serial_hex = [string]$ValidatedProfile.Identity.VolumeSerialHex
            file_id_hex = [string]$ValidatedProfile.Identity.FileIdHex
        }
        target_triple = [string]$ValidatedProfile.Profile.target_triple
        toolchain = $ValidatedProfile.Profile.toolchain
        executable_inventory = @($ValidatedProfile.ExecutableInventory | ForEach-Object {
            [ordered]@{ path = [string]$_.Path; sha256 = [string]$_.Sha256; bytes = [Int64]$_.Bytes; volume_serial_hex = [string]$_.VolumeSerialHex; file_id_hex = [string]$_.FileIdHex }
        })
        script_inventory = @($ValidatedProfile.ScriptInventory | ForEach-Object {
            [ordered]@{ path = [string]$_.Path; sha256 = [string]$_.Sha256; bytes = [Int64]$_.Bytes; volume_serial_hex = [string]$_.VolumeSerialHex; file_id_hex = [string]$_.FileIdHex }
        })
        windows_image_inventory = @($ValidatedProfile.WindowsImageInventory | ForEach-Object {
            [ordered]@{ path = [string]$_.Path; sha256 = [string]$_.Sha256; bytes = [Int64]$_.Bytes; volume_serial_hex = [string]$_.VolumeSerialHex; file_id_hex = [string]$_.FileIdHex }
        })
        lock_inputs = @($ValidatedProfile.LockInputs | ForEach-Object { [ordered]@{ manifest_path = [string]$_.ManifestPath; lock_sha256 = [string]$_.LockSha256 } })
        env_policy = [string]$ValidatedProfile.Profile.env_policy
    }
}

function Get-D32TestInventoryRowKey {
    param([Parameter(Mandatory = $true)][object]$Row)
    return ([string]$Row.kind + "`0" + [string]$Row.full_name)
}

function Get-D32TestInventoryListOutput {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$Package,
        [Parameter(Mandatory = $true)][ValidateSet('all', 'ignored')][string]$ListingKind
    )

    if ($Package -cnotin @('protocol', 'vita', 'host')) { throw "TEST_INVENTORY_BLOCKED: unknown package $Package" }
    if ($Lines.Count -eq 0) { throw "TEST_INVENTORY_BLOCKED: $Package/$ListingKind stdout is empty" }
    $rows = [System.Collections.Generic.List[object]]::new()
    $summaries = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($line in $Lines) {
        if ($line -ceq '') { throw "TEST_INVENTORY_BLOCKED: blank/truncated libtest list output row in $Package/$ListingKind" }
        if ($line -cmatch '^(?<name>.+): (?<kind>test|benchmark)$') {
            $name = [string]$Matches.name
            $kind = [string]$Matches.kind
            if ([String]::IsNullOrWhiteSpace($name) -or $name.Trim() -cne $name -or $name -match '[\x00-\x1f\x7f]' -or
                -not $seen.Add(($kind + "`0" + $name))) {
                throw "TEST_INVENTORY_BLOCKED: malformed or duplicate full name in $Package/$ListingKind"
            }
            $rows.Add([PSCustomObject][ordered]@{ package = $Package; kind = $kind; full_name = $name })
            continue
        }
        if ($line -cmatch '^(?<tests>\d+) (?<test_label>test|tests), (?<benches>\d+) (?<benchmark_label>benchmark|benchmarks)$') {
            $testLabel = if ([Int64]$Matches.tests -eq 1) { 'test' } else { 'tests' }
            $benchmarkLabel = if ([Int64]$Matches.benches -eq 1) { 'benchmark' } else { 'benchmarks' }
            if ($Matches.test_label -cne $testLabel -or $Matches.benchmark_label -cne $benchmarkLabel) {
                throw "TEST_INVENTORY_BLOCKED: count-specific libtest summary grammar is invalid in $Package/$ListingKind"
            }
            $summaries.Add([PSCustomObject][ordered]@{ tests = [Int64]$Matches.tests; benchmarks = [Int64]$Matches.benches })
            continue
        }
        throw "TEST_INVENTORY_BLOCKED: unknown/truncated libtest list output row in $Package/$ListingKind"
    }
    if ($summaries.Count -ne 1) { throw "TEST_INVENTORY_BLOCKED: exactly one libtest list summary is required in $Package/$ListingKind" }
    $testRows = [Int64]@($rows | Where-Object { $_.kind -ceq 'test' }).Count
    $benchmarkRows = [Int64]@($rows | Where-Object { $_.kind -ceq 'benchmark' }).Count
    $summaryTests = [Int64]$summaries[0].tests
    $summaryBenchmarks = [Int64]$summaries[0].benchmarks
    if ($summaryTests -ne $testRows -or $summaryBenchmarks -ne $benchmarkRows) {
        throw "TEST_INVENTORY_BLOCKED: complete libtest list rows do not reconcile with summaries in $Package/$ListingKind"
    }
    if ($ListingKind -eq 'all' -and $rows.Count -eq 0) { throw "TEST_INVENTORY_BLOCKED: nonempty package inventory required for $Package" }
    return [PSCustomObject]@{
        package = $Package
        listing_kind = $ListingKind
        rows = @($rows.ToArray())
        row_count = [Int64]$rows.Count
        test_count = $testRows
        benchmark_count = $benchmarkRows
        summary_count = [Int64]$summaries.Count
    }
}

function Get-D32TestInventoryCanonicalLines {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows)
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $Rows) {
        if ($row.package -isnot [string] -or $row.kind -isnot [string] -or $row.full_name -isnot [string] -or
            $row.package -notin @('protocol', 'vita', 'host') -or $row.kind -notin @('test', 'benchmark') -or
            [String]::IsNullOrWhiteSpace([string]$row.full_name) -or [string]$row.full_name -match '[\x00-\x1f\x7f]') {
            throw 'TEST_INVENTORY_BLOCKED: canonical inventory tuple has invalid package/kind/full-name fields'
        }
        $lines.Add(([string]$row.package + "`t" + [string]$row.kind + "`t" + [string]$row.full_name))
    }
    $array = [string[]]$lines.ToArray()
    [Array]::Sort($array, [StringComparer]::Ordinal)
    return @($array)
}

function Get-D32TestInventoryDigest {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows)
    $lines = @(Get-D32TestInventoryCanonicalLines -Rows $Rows)
    $text = if ($lines.Count -eq 0) { '' } else { ($lines -join "`n") + "`n" }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
    $sha = [Security.Cryptography.SHA256]::HashData($bytes)
    return [Convert]::ToHexString($sha).ToLowerInvariant()
}

function Get-D32TestInventoryBaselineCanonicalLines {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries)
    $lines = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $Entries) {
        if ($entry.package -isnot [string] -or $entry.kind -isnot [string] -or $entry.full_name -isnot [string] -or $entry.category -isnot [string] -or
            $entry.package -notin @('protocol', 'vita', 'host') -or $entry.kind -notin @('test', 'benchmark') -or
            $entry.category -notin @('ordinary', 'ignored', 'deferred', 'focused') -or [String]::IsNullOrWhiteSpace($entry.full_name) -or
            $entry.full_name -match '[\x00-\x1f\x7f]') {
            throw 'TEST_INVENTORY_BASELINE_BLOCKED: tuple category/schema is invalid'
        }
        $key = [string]$entry.package + "`0" + [string]$entry.kind + "`0" + [string]$entry.full_name
        if (-not $seen.Add($key)) { throw 'TEST_INVENTORY_BASELINE_BLOCKED: duplicate full inventory tuple' }
        $lines.Add(([string]$entry.package + "`t" + [string]$entry.kind + "`t" + [string]$entry.full_name + "`t" + [string]$entry.category))
    }
    $array = [string[]]$lines.ToArray()
    [Array]::Sort($array, [StringComparer]::Ordinal)
    return @($array)
}

function Sort-D32TestInventoryBaselineEntries {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries)
    $lines = @(Get-D32TestInventoryBaselineCanonicalLines -Entries $Entries)
    $byLine = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($entry in $Entries) {
        $line = [string]$entry.package + "`t" + [string]$entry.kind + "`t" + [string]$entry.full_name + "`t" + [string]$entry.category
        if ($byLine.ContainsKey($line)) { throw 'TEST_INVENTORY_BASELINE_BLOCKED: duplicate canonical entry line' }
        $byLine.Add($line, $entry)
    }
    return @($lines | ForEach-Object { $byLine[[string]$_] })
}

function Get-D32TestInventoryBaselineDigest {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Entries)
    $lines = @(Get-D32TestInventoryBaselineCanonicalLines -Entries $Entries)
    $text = if ($lines.Count -eq 0) { '' } else { ($lines -join "`n") + "`n" }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Get-D32TestInventoryJsonDigest {
    param([Parameter(Mandatory = $true)][object]$Value)
    $json = ConvertTo-Json -InputObject $Value -Depth 40 -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Read-D32TestInventoryJsonReference {
    param(
        [Parameter(Mandatory = $true)][object]$Reference,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Repository
    )
    if (-not (Test-D32Phase0ExactProperties -Object $Reference -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        $Reference.path -isnot [string] -or -not (Test-D32Phase0Integer -Value $Reference.bytes -Positive) -or
        $Reference.sha256 -isnot [string] -or $Reference.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Reference.volume_serial_hex -isnot [string] -or $Reference.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        $Reference.file_id_hex -isnot [string] -or $Reference.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        $ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$' -or $Reference.sha256 -cne $ExpectedSha256 -or
        -not (Test-D32ProfileCanonicalPathString -Path $Reference.path) -or -not (Test-D32ProfilePathEqual -Left $Reference.path -Right $ExpectedPath) -or
        (Test-D32ProfilePathWithin -Child $Reference.path -Parent $Repository)) {
        throw 'TEST_INVENTORY_BLOCKED: external discovery/baseline reference is malformed, unpinned, or inside repository'
    }
    $snapshot = Get-D32ProfileFileSnapshot -Path ([string]$Reference.path)
    if ($snapshot.Bytes -ne [Int64]$Reference.bytes -or $snapshot.Sha256 -cne $ExpectedSha256 -or
        $snapshot.VolumeSerialHex -cne $Reference.volume_serial_hex -or $snapshot.FileIdHex -cne $Reference.file_id_hex) {
        throw 'TEST_INVENTORY_BLOCKED: external discovery/baseline bytes or opened-handle identity differ from the pinned reference'
    }
    $stream = [IO.File]::Open([string]$Reference.path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $before = Get-D32ProfileFileSnapshot -Path ([string]$Reference.path)
        if ($before.Bytes -ne $snapshot.Bytes -or $before.Sha256 -cne $snapshot.Sha256 -or
            $before.VolumeSerialHex -cne $snapshot.VolumeSerialHex -or $before.FileIdHex -cne $snapshot.FileIdHex) {
            throw 'TEST_INVENTORY_BLOCKED: referenced JSON opened identity changed before read'
        }
        $memory = [IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            if ($memory.Length -ne $snapshot.Bytes) { throw 'TEST_INVENTORY_BLOCKED: referenced JSON byte count changed while reading' }
            $bytes = $memory.ToArray()
        }
        finally { $memory.Dispose() }
        $actualSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        $after = Get-D32ProfileFileSnapshot -Path ([string]$Reference.path)
        if ($actualSha -cne $ExpectedSha256 -or $after.Bytes -ne $snapshot.Bytes -or $after.Sha256 -cne $snapshot.Sha256 -or
            $after.VolumeSerialHex -cne $snapshot.VolumeSerialHex -or $after.FileIdHex -cne $snapshot.FileIdHex) {
            throw 'TEST_INVENTORY_BLOCKED: referenced JSON changed while read through the retained handle'
        }
        $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    }
    finally { $stream.Dispose() }
    if (Test-D32Phase0JsonDuplicateKeys -Json $raw) { throw 'TEST_INVENTORY_BLOCKED: referenced JSON has duplicate keys or malformed JSON' }
    return [PSCustomObject]@{ Document = ($raw | ConvertFrom-D32Phase0Json); Raw = $raw; Snapshot = $snapshot; Reference = $Reference }
}

function Read-D32TestInventoryLogReference {
    param(
        [Parameter(Mandatory = $true)][object]$Reference,
        [Parameter(Mandatory = $true)][string]$AllowedRoot
    )
    $null = Test-D32Phase0FileReference -Reference $Reference -AllowedRoot $AllowedRoot
    $stream = [IO.File]::Open([string]$Reference.path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $before = Get-D32ProfileFileSnapshot -Path ([string]$Reference.path)
        if ($before.Bytes -ne [Int64]$Reference.bytes -or $before.Sha256 -cne $Reference.sha256 -or
            $before.VolumeSerialHex -cne $Reference.volume_serial_hex -or $before.FileIdHex -cne $Reference.file_id_hex) {
            throw 'TEST_INVENTORY_BLOCKED: raw log opened identity changed before retained-handle read'
        }
        $memory = [IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            if ($memory.Length -ne [Int64]$Reference.bytes) { throw 'TEST_INVENTORY_BLOCKED: raw log byte count changed while reading through retained handle' }
            $bytes = $memory.ToArray()
        }
        finally { $memory.Dispose() }
        $actualSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        $after = Get-D32ProfileFileSnapshot -Path ([string]$Reference.path)
        if ($actualSha -cne $Reference.sha256 -or $after.Bytes -ne [Int64]$Reference.bytes -or $after.Sha256 -cne $Reference.sha256 -or
            $after.VolumeSerialHex -cne $Reference.volume_serial_hex -or $after.FileIdHex -cne $Reference.file_id_hex) {
            throw 'TEST_INVENTORY_BLOCKED: raw log bytes/opened identity changed during retained-handle read'
        }
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    }
    finally { $stream.Dispose() }
    $lines = [System.Collections.Generic.List[string]]::new()
    $reader = [IO.StringReader]::new($text)
    try { while ($null -ne ($line = $reader.ReadLine())) { $lines.Add($line) } }
    finally { $reader.Dispose() }
    return @($lines.ToArray())
}

function Write-D32TestInventoryJsonCreateNew {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Document,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$DiscoveryRoot
    )
    $full = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($full)
    if ([IO.Path]::GetFileName($full) -cne 'D32-TEST-INVENTORY-BASELINE.json' -or
        -not (Test-D32ProfileCanonicalPathString -Path $Path) -or -not (Test-D32ProfileNoReparsePath -Path $full -AllowMissingLeaf) -or
        [String]::IsNullOrWhiteSpace($parent) -or -not (Test-D32ProfileNoReparsePath -Path $parent) -or
        (Test-D32ProfilePathWithin -Child $full -Parent $Repository) -or (Test-D32ProfilePathWithin -Child $full -Parent $DiscoveryRoot) -or
        (Test-Path -LiteralPath $full)) { throw 'TEST_INVENTORY_BASELINE_BLOCKED: create-new external output path/parent is unsafe or already exists' }
    $json = ConvertTo-Json -InputObject $Document -Depth 40 -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
    $stream = [IO.File]::Open($full, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    return Get-D32Phase0FileReference -Path $full
}

function Get-D32TestInventoryCategoryAssignments {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('protocol', 'vita', 'host')][string]$Package,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$AllRows,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$IgnoredRows,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$DeferredNames,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$FocusedSuffixes
    )

    $allByKey = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($row in $AllRows) {
        if ($row.kind -notin @('test', 'benchmark') -or $row.full_name -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$row.full_name)) {
            throw "TEST_INVENTORY_BLOCKED: malformed all-list row in $Package"
        }
        $key = Get-D32TestInventoryRowKey -Row $row
        if ($allByKey.ContainsKey($key)) { throw "TEST_INVENTORY_BLOCKED: duplicate all-list tuple in $Package" }
        $allByKey.Add($key, $row)
    }
    if ($allByKey.Count -eq 0) { throw "TEST_INVENTORY_BLOCKED: empty all-list inventory in $Package" }

    $ignoredKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($row in $IgnoredRows) {
        $key = Get-D32TestInventoryRowKey -Row $row
        if (-not $allByKey.ContainsKey($key) -or -not $ignoredKeys.Add($key)) {
            throw "TEST_INVENTORY_BLOCKED: ignored list must be a unique subset of all-list in $Package"
        }
    }

    $deferredKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $DeferredNames) {
        $matches = @($AllRows | Where-Object { $_.kind -ceq 'test' -and ($_.full_name -ceq $name -or $_.full_name.EndsWith("::$name", [StringComparison]::Ordinal)) })
        if ($matches.Count -ne 1) { throw "TEST_INVENTORY_BLOCKED: deferred test must resolve exactly once in ${Package}: $name" }
        $key = Get-D32TestInventoryRowKey -Row $matches[0]
        if ($ignoredKeys.Contains($key) -or -not $deferredKeys.Add($key)) { throw "TEST_INVENTORY_BLOCKED: deferred test overlaps ignored/duplicate inventory in ${Package}: $name" }
    }

    $focusedKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($suffix in $FocusedSuffixes) {
        $matches = @($AllRows | Where-Object { $_.kind -ceq 'test' -and $_.full_name.EndsWith($suffix, [StringComparison]::Ordinal) })
        if ($matches.Count -ne 1) { throw "TEST_INVENTORY_BLOCKED: focused test must resolve exactly once in ${Package}: $suffix" }
        $key = Get-D32TestInventoryRowKey -Row $matches[0]
        if ($ignoredKeys.Contains($key) -or $deferredKeys.Contains($key) -or -not $focusedKeys.Add($key)) {
            throw "TEST_INVENTORY_BLOCKED: focused test overlaps ignored/deferred/duplicate inventory in ${Package}: $suffix"
        }
    }

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $AllRows) {
        $key = Get-D32TestInventoryRowKey -Row $row
        $category = if ($ignoredKeys.Contains($key)) { 'ignored' } elseif ($deferredKeys.Contains($key)) { 'deferred' } elseif ($focusedKeys.Contains($key)) { 'focused' } else { 'ordinary' }
        $entries.Add([PSCustomObject][ordered]@{ package = $Package; kind = [string]$row.kind; full_name = [string]$row.full_name; category = $category })
    }
    $sortedLines = @(Get-D32TestInventoryCanonicalLines -Rows @($entries.ToArray()))
    $entryByLine = @{}
    foreach ($entry in $entries) { $entryByLine[([string]$entry.package + "`t" + [string]$entry.kind + "`t" + [string]$entry.full_name)] = $entry }
    $sortedEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($line in $sortedLines) { $sortedEntries.Add($entryByLine[$line]) }
    return [PSCustomObject]@{
        package = $Package
        entries = @($sortedEntries.ToArray())
        test_names = @($AllRows | Where-Object { $_.kind -ceq 'test' } | ForEach-Object { [string]$_.full_name })
        ignored_names = @($IgnoredRows | Where-Object { $_.kind -ceq 'test' } | ForEach-Object { [string]$_.full_name })
        entry_count = [Int64]$entries.Count
        test_count = [Int64]@($AllRows | Where-Object { $_.kind -ceq 'test' }).Count
        ignored_count = [Int64]@($IgnoredRows | Where-Object { $_.kind -ceq 'test' }).Count
        digest = Get-D32TestInventoryDigest -Rows @($entries.ToArray())
        category_counts = [ordered]@{
            ordinary = [Int64]@($entries | Where-Object { $_.category -ceq 'ordinary' }).Count
            ignored = [Int64]@($entries | Where-Object { $_.category -ceq 'ignored' }).Count
            deferred = [Int64]@($entries | Where-Object { $_.category -ceq 'deferred' }).Count
            focused = [Int64]@($entries | Where-Object { $_.category -ceq 'focused' }).Count
        }
    }
}

function New-D32TestInventoryBaselineDocument {
    param(
        [Parameter(Mandatory = $true)][object]$Discovery,
        [Parameter(Mandatory = $true)][object]$DiscoveryReference,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$PackageInventories,
        [Parameter(Mandatory = $true)][string]$GeneratedAtUtc
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    $packageDigests = [System.Collections.Generic.List[object]]::new()
    $counts = [ordered]@{}
    foreach ($package in @('protocol', 'vita', 'host')) {
        $inventory = @($PackageInventories | Where-Object { $_.package -ceq $package })
        if ($inventory.Count -ne 1) { throw "TEST_INVENTORY_BASELINE_BLOCKED: package inventory missing/duplicated: $package" }
        foreach ($entry in @($inventory[0].entries)) { $entries.Add($entry) }
        $packageRows = @($inventory[0].entries)
        $packageDigests.Add([ordered]@{ package = $package; entry_count = [Int64]$packageRows.Count; sha256 = Get-D32TestInventoryBaselineDigest -Entries $packageRows })
        $counts[$package] = [ordered]@{
            ordinary = [Int64]$inventory[0].category_counts.ordinary
            ignored = [Int64]$inventory[0].category_counts.ignored
            deferred = [Int64]$inventory[0].category_counts.deferred
            focused = [Int64]$inventory[0].category_counts.focused
        }
    }
    $allEntries = @(Sort-D32TestInventoryBaselineEntries -Entries @($entries.ToArray()))
    $baselineCommands = [System.Collections.Generic.List[object]]::new()
    for ($commandIndex = 0; $commandIndex -lt $Discovery.inventory_commands.Count; $commandIndex++) {
        $item = $Discovery.inventory_commands[$commandIndex]
        $baselineCommands.Add([ordered]@{
            command_index = [Int64]$commandIndex
            package = [string]$item.package
            listing_kind = [string]$item.listing_kind
            name = [string]$item.command.name
            candidate_sha = [string]$item.command.candidate_sha_before
            clean_before = [bool]$item.command.clean_before
            clean_after = [bool]$item.command.clean_after
            exit_code = [Int64]$item.command.exit_code
            root_process_id = [Int64]$item.command.root_process.process_id
            root_process_creation_date = [string]$item.command.root_process.creation_date
            process_trace_sha256 = Get-D32TestInventoryJsonDigest -Value $item.command.process_trace
            executable = [string]$item.command.executable
            executable_sha256 = [string]$item.command.executable_sha256
            argv = @($item.command.argv)
            working_directory = [string]$item.command.working_directory
            timeout_seconds = [Int64]$item.command.timeout_seconds
            feature_set = @($item.features)
            target_triple = [string]$Discovery.toolchain_profile.target_triple
            output_digest = [string]$item.digest
            output_count = [Int64]$item.row_count
            output_test_count = [Int64]$item.test_count
            output_benchmark_count = [Int64]$item.benchmark_count
            stdout = $item.command.stdout
            stderr = $item.command.stderr
        })
    }
    return [ordered]@{
        schema_version = 2
        record_type = 'D32_TEST_INVENTORY_BASELINE_V2'
        status = 'AWAITING_COORDINATOR_PIN'
        gate_authority = 'NONE'
        candidate_sha = [string]$Discovery.candidate_sha
        source_repo = [string]$Discovery.source_repo
        target_triple = [string]$Discovery.toolchain_profile.target_triple
        toolchain_profile = [ordered]@{
            path = [string]$Discovery.toolchain_profile.path
            sha256 = [string]$Discovery.toolchain_profile.sha256
            bytes = [Int64]$Discovery.toolchain_profile.file_identity.bytes
            volume_serial_hex = [string]$Discovery.toolchain_profile.file_identity.volume_serial_hex
            file_id_hex = [string]$Discovery.toolchain_profile.file_identity.file_id_hex
            target_triple = [string]$Discovery.toolchain_profile.target_triple
        }
        lock_inputs = @($Discovery.lock_inputs)
        source_patch_authority = $Discovery.source_patch_authority
        protoc_discovery_authority = $Discovery.protoc.authority
        discovery_module_admission = $Discovery.powershell_module_admission
        powershell_module_admission = $global:D32PowerShellModuleAuthorityState.Admission
        discovery = [ordered]@{
            reference = $DiscoveryReference
            candidate_sha = [string]$Discovery.candidate_sha
            run_id = [string]$Discovery.run_id
            evidence_root = $Discovery.evidence_root_identity
            cargo_home = $Discovery.storage.cargo_home
            temp_root = $Discovery.storage.temp_root
            completed_at_utc = [string]$Discovery.completed_at_utc
        }
        commands = @($baselineCommands.ToArray())
        entries = $allEntries
        package_digests = @($packageDigests.ToArray())
        combined_digest = Get-D32TestInventoryBaselineDigest -Entries $allEntries
        category_counts = $counts
        generated_at_utc = $GeneratedAtUtc
    }
}

function Assert-D32TestInventoryExpectedCommand {
    param(
        [Parameter(Mandatory = $true)][object]$Actual,
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$DiscoveryCommand,
        [Parameter(Mandatory = $true)][int]$Index,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][object]$Profile
    )
    $commandFields = @('command_index', 'package', 'listing_kind', 'name', 'candidate_sha', 'clean_before', 'clean_after', 'exit_code', 'root_process_id',
        'root_process_creation_date', 'process_trace_sha256', 'executable', 'executable_sha256', 'argv', 'working_directory', 'timeout_seconds',
        'feature_set', 'target_triple', 'output_digest', 'output_count', 'output_test_count', 'output_benchmark_count', 'stdout', 'stderr')
    $checks = [ordered]@{
        schema = Test-D32Phase0ExactProperties -Object $Actual -Expected $commandFields
        index = (Test-D32Phase0Integer -Value $Actual.command_index) -and [Int64]$Actual.command_index -eq $Index
        package = ($Actual.package -is [string]) -and $Actual.package -ceq $Expected.package
        listing_kind = ($Actual.listing_kind -is [string]) -and $Actual.listing_kind -ceq $Expected.listing_kind
        name = ($Actual.name -is [string]) -and $Actual.name -ceq $Expected.name
        candidate = ($Actual.candidate_sha -is [string]) -and $Actual.candidate_sha -ceq $CandidateSha
        clean = ($Actual.clean_before -is [bool]) -and $Actual.clean_before -and ($Actual.clean_after -is [bool]) -and $Actual.clean_after
        exit_code = (Test-D32Phase0Integer -Value $Actual.exit_code) -and [Int64]$Actual.exit_code -eq 0
        root_process = (Test-D32Phase0Integer -Value $Actual.root_process_id -Positive) -and $Actual.root_process_id -eq $DiscoveryCommand.root_process.process_id
        root_creation = ($Actual.root_process_creation_date -is [string]) -and $Actual.root_process_creation_date -ceq $DiscoveryCommand.root_process.creation_date
        process_trace = ($Actual.process_trace_sha256 -is [string]) -and $Actual.process_trace_sha256 -ceq (Get-D32TestInventoryJsonDigest -Value $DiscoveryCommand.process_trace)
        executable_path = Test-D32ProfilePathEqual -Left $Actual.executable -Right $Profile.Profile.toolchain.cargo.path
        executable_sha = ($Actual.executable_sha256 -is [string]) -and $Actual.executable_sha256 -ceq $Profile.Profile.toolchain.cargo.sha256
        argv = ($Actual.argv -is [Array]) -and (($Actual.argv -join "`0") -ceq ((@($Expected.executable) + @($Expected.arguments)) -join "`0"))
        working_directory = Test-D32ProfilePathEqual -Left $Actual.working_directory -Right $Repository
        timeout = (Test-D32Phase0Integer -Value $Actual.timeout_seconds) -and [Int64]$Actual.timeout_seconds -eq 28800
        features = ($Actual.feature_set -is [Array]) -and (($Actual.feature_set -join "`0") -ceq (@($Expected.features) -join "`0"))
        target = ($Actual.target_triple -is [string]) -and $Actual.target_triple -ceq $Profile.Profile.target_triple
        output_digest = ($Actual.output_digest -is [string]) -and $Actual.output_digest -cmatch '^[0-9a-f]{64}$'
        output_count = if ($Expected.listing_kind -ceq 'all') { Test-D32Phase0Integer -Value $Actual.output_count -Positive } else { Test-D32Phase0Integer -Value $Actual.output_count }
        output_test_count = Test-D32Phase0Integer -Value $Actual.output_test_count
        output_benchmark_count = Test-D32Phase0Integer -Value $Actual.output_benchmark_count
    }
    $failedChecks = @($checks.Keys | Where-Object { -not $checks[$_] })
    if ($failedChecks.Count -gt 0) {
        throw "TEST_INVENTORY_BASELINE_BLOCKED: list command[$Index] differs from the exact six-command jobs-4/28800 inventory plan (failed: $($failedChecks -join ', '))"
    }
    foreach ($streamName in @('stdout', 'stderr')) {
        if ((ConvertTo-Json -InputObject $Actual.$streamName -Depth 6 -Compress) -cne
            (ConvertTo-Json -InputObject $DiscoveryCommand.$streamName -Depth 6 -Compress)) {
            throw "TEST_INVENTORY_BASELINE_BLOCKED: $($Expected.name) $streamName reference differs from its opened discovery command"
        }
    }
}

function Test-D32TestInventoryBaselineDocument {
    param(
        [Parameter(Mandatory = $true)][object]$Document,
        [Parameter(Mandatory = $true)][object]$Discovery,
        [Parameter(Mandatory = $true)][object]$DiscoveryReference,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][object]$Profile,
        [Parameter(Mandatory = $true)][object[]]$LockInputs,
        [Parameter(Mandatory = $true)][object]$SourcePatchAuthorityReference,
        [Parameter(Mandatory = $true)][object]$ProtocAuthorityReference,
        [Parameter(Mandatory = $true)][object[]]$ExpectedCommands
    )
    $fields = @('schema_version', 'record_type', 'status', 'gate_authority', 'candidate_sha', 'source_repo', 'target_triple', 'toolchain_profile', 'lock_inputs',
        'source_patch_authority', 'protoc_discovery_authority', 'discovery_module_admission', 'powershell_module_admission', 'discovery', 'commands', 'entries', 'package_digests', 'combined_digest', 'category_counts', 'generated_at_utc')
    if (-not (Test-D32Phase0ExactProperties -Object $Document -Expected $fields) -or
        -not (Test-D32Phase0Integer -Value $Document.schema_version) -or [Int64]$Document.schema_version -ne 2 -or
        $Document.record_type -isnot [string] -or $Document.record_type -cne 'D32_TEST_INVENTORY_BASELINE_V2' -or
        $Document.status -isnot [string] -or $Document.status -cne 'AWAITING_COORDINATOR_PIN' -or
        $Document.gate_authority -isnot [string] -or $Document.gate_authority -cne 'NONE' -or
        $Document.candidate_sha -isnot [string] -or $Document.candidate_sha -cne $ExpectedCandidateSha -or
        $Document.source_repo -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $Document.source_repo -Right $Repository) -or
        $Document.target_triple -isnot [string] -or $Document.target_triple -cne $Profile.Profile.target_triple -or
        $Document.combined_digest -isnot [string] -or $Document.combined_digest -cnotmatch '^[0-9a-f]{64}$' -or
        $Document.entries -isnot [Array] -or $Document.entries.Count -eq 0 -or
        $Document.commands -isnot [Array] -or $Document.commands.Count -ne 6 -or
        $Document.package_digests -isnot [Array] -or $Document.package_digests.Count -ne 3 -or
        ($Document.category_counts -isnot [System.Management.Automation.PSCustomObject] -and $Document.category_counts -isnot [System.Collections.IDictionary]) -or
        -not (Test-D32Phase0ExactProperties -Object $Document.category_counts -Expected @('protocol', 'vita', 'host'))) {
        throw 'TEST_INVENTORY_BASELINE_BLOCKED: record must be exact V2 awaiting independent Coordinator pin, candidate-bound, and non-authoritative'
    }
    if (-not (Test-D32PowerShellModuleAdmissionRecord -Document $Document.discovery_module_admission -CandidateSha $ExpectedCandidateSha -Repository $Repository -ExpectedContext $Discovery.powershell_module_admission) -or
        -not (Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $Document.discovery_module_admission -ProfileRecord $Discovery.toolchain_profile) -or
        -not (Test-D32PowerShellModuleAdmissionRecord -Document $Document.powershell_module_admission -CandidateSha $ExpectedCandidateSha -Repository $Repository -ExpectedContext $global:D32PowerShellModuleAuthorityState.Admission) -or
        -not (Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $Document.powershell_module_admission -ProfileRecord $Document.toolchain_profile)) {
        throw 'TEST_INVENTORY_BASELINE_BLOCKED: baseline must carry the validated discovery admission and its own producer admission'
    }
    $targetTriple = [string]$Profile.Profile.target_triple
    $expectedProfile = [ordered]@{
        path = [string]$Profile.ProfilePath
        sha256 = [string]$Profile.Digest
        bytes = [Int64]$Profile.Identity.Bytes
        volume_serial_hex = [string]$Profile.Identity.VolumeSerialHex
        file_id_hex = [string]$Profile.Identity.FileIdHex
        target_triple = $targetTriple
    }
    if ((ConvertTo-Json -InputObject $Document.toolchain_profile -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $expectedProfile -Depth 5 -Compress)) {
        throw 'TEST_INVENTORY_BASELINE_BLOCKED: profile path/hash/opened identity/target differs from the current caller-pinned profile'
    }
    if ($Document.lock_inputs -isnot [Array] -or $Document.lock_inputs.Count -ne 3) { throw 'TEST_INVENTORY_BASELINE_BLOCKED: exact three lock inputs are required' }
    for ($index = 0; $index -lt 3; $index++) {
        $expectedLock = $LockInputs[$index]
        $actualLock = $Document.lock_inputs[$index]
        if (-not (Test-D32Phase0ExactProperties -Object $actualLock -Expected @('manifest_path', 'lock_sha256', 'lock_bytes')) -or
            $actualLock.manifest_path -cne $expectedLock.ManifestPath -or $actualLock.lock_sha256 -cne $expectedLock.LockSha256 -or
            [Int64]$actualLock.lock_bytes -ne [Int64]$expectedLock.LockBytes) { throw 'TEST_INVENTORY_BASELINE_BLOCKED: lock input path/hash/bytes differ from current locked inputs' }
    }
    foreach ($binding in @(
        [PSCustomObject]@{ Name = 'source_patch_authority'; Expected = $SourcePatchAuthorityReference },
        [PSCustomObject]@{ Name = 'protoc_discovery_authority'; Expected = $ProtocAuthorityReference }
    )) {
        if ((ConvertTo-Json -InputObject $Document.($binding.Name) -Depth 8 -Compress) -cne (ConvertTo-Json -InputObject $binding.Expected -Depth 8 -Compress)) {
            throw "TEST_INVENTORY_BASELINE_BLOCKED: $($binding.Name) reference differs from current independently pinned authority"
        }
    }
    if (-not (Test-D32Phase0ExactProperties -Object $Document.discovery -Expected @('reference', 'candidate_sha', 'run_id', 'evidence_root', 'cargo_home', 'temp_root', 'completed_at_utc')) -or
        (ConvertTo-Json -InputObject $Document.discovery.reference -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $DiscoveryReference -Depth 6 -Compress) -or
        $Document.discovery.candidate_sha -cne $ExpectedCandidateSha -or $Document.discovery.run_id -cne $Discovery.run_id -or
        (ConvertTo-Json -InputObject $Document.discovery.evidence_root -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $Discovery.evidence_root_identity -Depth 6 -Compress) -or
        (ConvertTo-Json -InputObject $Document.discovery.cargo_home -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $Discovery.storage.cargo_home -Depth 6 -Compress) -or
        (ConvertTo-Json -InputObject $Document.discovery.temp_root -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $Discovery.storage.temp_root -Depth 6 -Compress) -or
        $Document.discovery.completed_at_utc -isnot [string] -or $Document.discovery.completed_at_utc -cne [string]$Discovery.completed_at_utc) {
        throw 'TEST_INVENTORY_BASELINE_BLOCKED: discovery reference/run/root/CargoHome/TempRoot binding differs from validated source record'
    }
    if ($Document.commands.Count -ne $ExpectedCommands.Count) { throw 'TEST_INVENTORY_BASELINE_BLOCKED: exactly six ordered list command records required' }
    for ($index = 0; $index -lt 6; $index++) {
        $expected = $ExpectedCommands[$index]
        $actual = $Document.commands[$index]
        Assert-D32TestInventoryExpectedCommand -Actual $actual -Expected $expected -DiscoveryCommand $Discovery.inventory_commands[$index].command `
            -Index $index -CandidateSha $ExpectedCandidateSha -Repository $Repository -Profile $Profile
        $sourceCommand = $Discovery.inventory_commands[$index].command
        $expectedRows = @($Discovery.inventory_commands[$index].rows)
        if ($actual.output_count -ne $expectedRows.Count -or
            $actual.output_test_count -ne @($expectedRows | Where-Object { $_.kind -ceq 'test' }).Count -or
            $actual.output_benchmark_count -ne @($expectedRows | Where-Object { $_.kind -ceq 'benchmark' }).Count -or
            $actual.output_digest -cne (Get-D32TestInventoryDigest -Rows $expectedRows)) {
            throw "TEST_INVENTORY_BASELINE_BLOCKED: $($expected.name) command summary differs from the complete parsed discovery rows"
        }
    }
    $canonical = @(Get-D32TestInventoryBaselineCanonicalLines -Entries $Document.entries)
    $sortedEntries = @(Sort-D32TestInventoryBaselineEntries -Entries $Document.entries)
    if ($canonical.Count -ne $Document.entries.Count -or
        -not (Test-D32TestInventoryRowsEqual -Left $Document.entries -Right $sortedEntries -IncludeCategory) -or
        $Document.combined_digest -cne (Get-D32TestInventoryBaselineDigest -Entries $Document.entries)) {
        throw 'TEST_INVENTORY_BASELINE_BLOCKED: combined canonical UTF-8 inventory digest mismatch'
    }
    if (-not (Test-D32TestInventoryRowsEqual -Left $Document.entries -Right @($Discovery.test_inventory.entries) -IncludeCategory)) {
        throw 'TEST_INVENTORY_BASELINE_BLOCKED: baseline entries differ from the independently recorded complete discovery set'
    }
    for ($packageIndex = 0; $packageIndex -lt 3; $packageIndex++) {
        $package = @('protocol', 'vita', 'host')[$packageIndex]
        $digestRecord = $Document.package_digests[$packageIndex]
        $packageEntries = @($Document.entries | Where-Object { $_.package -ceq $package })
        if (-not (Test-D32Phase0ExactProperties -Object $digestRecord -Expected @('package', 'entry_count', 'sha256')) -or
            $digestRecord.package -cne $package -or $digestRecord.entry_count -ne $packageEntries.Count -or
            $digestRecord.sha256 -cne (Get-D32TestInventoryBaselineDigest -Entries $packageEntries)) { throw "TEST_INVENTORY_BASELINE_BLOCKED: package digest/count mismatch for $package" }
        $counts = $Document.category_counts.$package
        if (-not (Test-D32Phase0ExactProperties -Object $counts -Expected @('ordinary', 'ignored', 'deferred', 'focused'))) { throw "TEST_INVENTORY_BASELINE_BLOCKED: category count schema mismatch for $package" }
        foreach ($category in @('ordinary', 'ignored', 'deferred', 'focused')) {
            $actualCategoryCount = [Int64]@($packageEntries | Where-Object { $_.category -ceq $category }).Count
            if (-not (Test-D32Phase0Integer -Value $counts.$category) -or [Int64]$counts.$category -ne $actualCategoryCount) {
                throw "TEST_INVENTORY_BASELINE_BLOCKED: category count mismatch for $package/$category"
            }
        }
        $discoveryCommandSet = @($Discovery.inventory_commands | Where-Object { $_.package -ceq $package })
        if ($discoveryCommandSet.Count -ne 2) { throw "TEST_INVENTORY_BASELINE_BLOCKED: discovery lacks both list captures for $package" }
    }
    $generated = [DateTimeOffset]::MinValue
    $discoveryCompleted = [DateTimeOffset]::MinValue
    if ($Document.generated_at_utc -isnot [string] -or -not [DateTimeOffset]::TryParse([string]$Document.generated_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$generated) -or
        -not [DateTimeOffset]::TryParse([string]$Discovery.completed_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$discoveryCompleted) -or
        $generated -lt $discoveryCompleted) {
        throw 'TEST_INVENTORY_BASELINE_BLOCKED: generated_at_utc must be an ISO timestamp'
    }
    return $true
}

function Test-D32TestInventoryRowsEqual {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Left,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Right,
        [switch]$IncludeCategory
    )
    $leftLines = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $Left) {
        $line = [string]$row.package + "`t" + [string]$row.kind + "`t" + [string]$row.full_name
        if ($IncludeCategory) { $line += "`t" + [string]$row.category }
        $leftLines.Add($line)
    }
    $rightLines = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $Right) {
        $line = [string]$row.package + "`t" + [string]$row.kind + "`t" + [string]$row.full_name
        if ($IncludeCategory) { $line += "`t" + [string]$row.category }
        $rightLines.Add($line)
    }
    $leftArray = [string[]]$leftLines.ToArray()
    $rightArray = [string[]]$rightLines.ToArray()
    [Array]::Sort($leftArray, [StringComparer]::Ordinal)
    [Array]::Sort($rightArray, [StringComparer]::Ordinal)
    return (($leftArray -join "`0") -ceq ($rightArray -join "`0"))
}

function Get-D32Phase0SuiteTestResultRows {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines)
    $rows = [System.Collections.Generic.List[object]]::new()
    $summaries = [System.Collections.Generic.List[object]]::new()
    foreach ($line in $Lines) {
        if ($line -ceq '') { continue }
        if ($line -match '^running \d+ tests?$') { continue }
        if ($line -match '^test (?<name>.+) \.\.\. (?<status>ok|ignored|FAILED)$') {
            if ([String]::IsNullOrWhiteSpace($Matches.name) -or $Matches.name.Trim() -cne $Matches.name -or $Matches.name -match '[\x00-\x1f\x7f]') {
                throw 'PHASE0_TEST_INVENTORY_BLOCKED: malformed full test-result name'
            }
            $rows.Add([ordered]@{ full_name = [string]$Matches.name; status = [string]$Matches.status })
            continue
        }
        if ($line -match '^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;') {
            $summaries.Add([ordered]@{ status = [string]$Matches[1]; passed = [Int64]$Matches[2]; failed = [Int64]$Matches[3]; ignored = [Int64]$Matches[4]; measured = [Int64]$Matches[5]; filtered_out = [Int64]$Matches[6] })
            continue
        }
        throw 'PHASE0_TEST_INVENTORY_BLOCKED: unknown or truncated libtest result output row'
    }
    if ($summaries.Count -eq 0) { throw 'PHASE0_TEST_INVENTORY_BLOCKED: full-suite libtest result summary is missing' }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($row in $rows) { if (-not $seen.Add([string]$row.full_name)) { throw 'PHASE0_TEST_INVENTORY_BLOCKED: duplicate full test-result name' } }
    return [PSCustomObject]@{ rows = @($rows.ToArray()); summaries = @($summaries.ToArray()) }
}

function Assert-D32TestInventorySuiteRows {
    param(
        [Parameter(Mandatory = $true)][string]$Package,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$BaselineEntries,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines,
        [Parameter(Mandatory = $true)][int64]$ExpectedIgnored,
        [Parameter(Mandatory = $true)][int64]$ExpectedDeferred
    )
    $parsed = Get-D32Phase0SuiteTestResultRows -Lines $Lines
    $expected = @($BaselineEntries | Where-Object { $_.package -ceq $Package -and $_.kind -ceq 'test' -and $_.category -cne 'deferred' })
    $expectedCount = $expected.Count
    $expectedByName = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $expected) {
        if ($entry.kind -cne 'test' -or $expectedByName.ContainsKey([string]$entry.full_name)) { throw "PHASE0_TEST_INVENTORY_BLOCKED: unsupported/duplicate full test baseline entry in $Package" }
        $expectedByName.Add([string]$entry.full_name, [string]$entry.category)
    }
    if ($parsed.rows.Count -ne $expectedByName.Count) { throw "PHASE0_TEST_INVENTORY_BLOCKED: $Package full-suite result row count differs from pinned baseline" }
    foreach ($row in $parsed.rows) {
        if (-not $expectedByName.ContainsKey([string]$row.full_name)) { throw "PHASE0_TEST_INVENTORY_BLOCKED: $Package full-suite contains an unpinned or renamed test result: $($row.full_name)" }
        $category = $expectedByName[[string]$row.full_name]
        $expectedStatus = if ($category -ceq 'ignored') { 'ignored' } else { 'ok' }
        if ($row.status -cne $expectedStatus) { throw "PHASE0_TEST_INVENTORY_BLOCKED: $Package test result status differs from pinned category: $($row.full_name)" }
        [void]$expectedByName.Remove([string]$row.full_name)
    }
    if ($expectedByName.Count -ne 0) { throw "PHASE0_TEST_INVENTORY_BLOCKED: $Package full-suite omitted baseline test names" }
    $counts = [ordered]@{ passed = [Int64]0; failed = [Int64]0; ignored = [Int64]0; measured = [Int64]0; filtered_out = [Int64]0 }
    foreach ($summary in $parsed.summaries) {
        foreach ($field in @('passed', 'failed', 'ignored', 'measured', 'filtered_out')) {
            $counts[$field] = [Int64]$counts[$field] + [Int64]$summary[$field]
        }
    }
    $expectedPassed = [Int64]@($expected | Where-Object { $_.category -cne 'ignored' -and $_.kind -ceq 'test' }).Count
    $expectedIgnoredActual = [Int64]@($expected | Where-Object { $_.category -ceq 'ignored' -and $_.kind -ceq 'test' }).Count
    if (@($parsed.summaries | Where-Object { $_.status -cne 'ok' }).Count -ne 0 -or
        $counts.ignored -ne $ExpectedIgnored -or $counts.filtered_out -ne $ExpectedDeferred -or $counts.failed -ne 0 -or
        $counts.passed -ne $expectedPassed -or $counts.ignored -ne $expectedIgnoredActual -or $counts.measured -ne 0 -or
        ($counts.passed + $counts.ignored + $counts.measured + $counts.filtered_out) -ne ($expectedCount + $ExpectedDeferred)) {
        throw "PHASE0_TEST_INVENTORY_BLOCKED: $Package suite summary does not reconcile to exact pinned test rows"
    }
    return [PSCustomObject]@{ Rows = $parsed.rows; Summaries = $parsed.summaries; Counts = $counts }
}
