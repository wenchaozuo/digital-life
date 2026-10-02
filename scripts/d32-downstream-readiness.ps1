[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('EmitPacket', 'ReconcileCapture', 'SelfTest')]
    [string]$Action,

    [string]$RepositoryRoot,
    [string]$CandidateSha,
    [string]$AggregateRecordPath,
    [string]$ExpectedAggregateRecordSha256,
    [string]$BundleManifestPath,
    [string]$ExpectedBundleManifestSha256,
    [string]$AttestationPath,
    [string]$ExpectedAttestationSha256,
    [string]$SeederCompanionPath,
    [string]$ExpectedSeederCompanionSha256,
    [string]$CapturePacketPath,
    [string]$ExpectedCapturePacketSha256,
    [ValidateSet('UNDECIDED', 'NOT_APPLICABLE', 'APPLICABLE_USER_AUTHORIZED', 'APPLICABLE_UNAUTHORIZED')]
    [string]$ProviderDisposition = 'UNDECIDED',
    [string]$ProviderNotApplicableReason
)

# This file is intentionally module-free and process-free.  It emits an
# untrusted execution packet or reconciles already captured evidence; it never
# starts Cargo, a Host canary, a provider request, or another process, and it
# never reads provider/Codex configuration or credential environment values.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:D32DownstreamHostModes = @(
    'positive',
    'grant-replay',
    'revoke-before-revalidation',
    'life-before-revalidation',
    'cancel-before-revalidation',
    'migration-before-revalidation',
    'executable-identity-tamper',
    'environment-profile-tamper'
)

$script:D32DownstreamD31Cases = @(
    [ordered]@{ name = 'd31_c_real_process_crash_recovery_canary'; package = 'vita-agent'; inventory_package = 'vita'; manifest = 'vita-agent/Cargo.toml'; feature = 'd32-a-test-helper'; required_env = [ordered]@{ D31_C_REQUIRE_REAL_CANARY = '1' }; seeder_required = $false },
    [ordered]@{ name = 'd31_c_real_process_workspace_replace_canary'; package = 'src-tauri'; inventory_package = 'host'; manifest = 'src-tauri/Cargo.toml'; feature = 'd32-a-host-canary'; required_env = [ordered]@{ D31_C_REQUIRE_REAL_CANARY = '1' }; seeder_required = $false },
    [ordered]@{ name = 'd31_c_real_process_workspace_replace_revocation_canary'; package = 'src-tauri'; inventory_package = 'host'; manifest = 'src-tauri/Cargo.toml'; feature = 'd32-a-host-canary'; required_env = [ordered]@{ D31_C_REQUIRE_REAL_CANARY = '1' }; seeder_required = $false },
    [ordered]@{ name = 'd31_d_real_process_workspace_patch_canary'; package = 'src-tauri'; inventory_package = 'host'; manifest = 'src-tauri/Cargo.toml'; feature = 'd32-a-host-canary'; required_env = [ordered]@{ D31_D_REQUIRE_REAL_CANARY = '1' }; seeder_required = $false },
    [ordered]@{ name = 'd31_d_real_process_workspace_patch_conflict_canary'; package = 'src-tauri'; inventory_package = 'host'; manifest = 'src-tauri/Cargo.toml'; feature = 'd32-a-host-canary'; required_env = [ordered]@{ D31_D_REQUIRE_REAL_CANARY = '1' }; seeder_required = $false },
    [ordered]@{ name = 'd31_d_real_process_workspace_patch_revocation_canary'; package = 'src-tauri'; inventory_package = 'host'; manifest = 'src-tauri/Cargo.toml'; feature = 'd32-a-host-canary'; required_env = [ordered]@{ D31_D_REQUIRE_REAL_CANARY = '1' }; seeder_required = $false },
    [ordered]@{ name = 'd31_c_real_process_recovery_canary'; package = 'src-tauri'; inventory_package = 'host'; manifest = 'src-tauri/Cargo.toml'; feature = 'd32-a-host-canary'; required_env = [ordered]@{}; seeder_required = $true },
    [ordered]@{ name = 'd31_c_real_process_recovery_revocation_canary'; package = 'src-tauri'; inventory_package = 'host'; manifest = 'src-tauri/Cargo.toml'; feature = 'd32-a-host-canary'; required_env = [ordered]@{}; seeder_required = $true },
    [ordered]@{ name = 'd31_b_real_process_workspace_read_canary'; package = 'src-tauri'; inventory_package = 'host'; manifest = 'src-tauri/Cargo.toml'; feature = 'd32-a-host-canary'; required_env = [ordered]@{ D31_B_REQUIRE_REAL_CANARY = '1' }; seeder_required = $false },
    [ordered]@{ name = 'd31_b_real_process_workspace_read_revocation_canary'; package = 'src-tauri'; inventory_package = 'host'; manifest = 'src-tauri/Cargo.toml'; feature = 'd32-a-host-canary'; required_env = [ordered]@{ D31_B_REQUIRE_REAL_CANARY = '1' }; seeder_required = $false }
)

$script:D32DownstreamProviderCases = @(
    [ordered]@{ name = 'd29g2_real_provider_smoke'; expected_requests = 1 },
    [ordered]@{ name = 'd29g2_r1_minimal_provider_probe'; expected_requests = 1 },
    [ordered]@{ name = 'd29g2_r2_structural_diagnostic'; expected_requests = 1 },
    [ordered]@{ name = 'd29g2_r2_role_matrix'; expected_requests = 2 }
)

$script:D32DownstreamAggregateFields = @(
    'schema_version', 'record_type', 'scope', 'candidate_sha', 'source_repo',
    'evidence_root', 'status', 'bundle_hashes', 'downstream_gates', 'references',
    'powershell_module_admission'
)

$script:D32DownstreamAggregateReferenceFields = @(
    'path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'
)

$script:D32DownstreamCleanupFields = @(
    'launch_mode', 'job_close_succeeded', 'process_wait_signaled',
    'active_process_count_verified', 'active_process_count', 'debugger_thread_id',
    'debugger_thread_exited', 'debugger_thread_joined',
    'debugger_kill_on_exit_enabled', 'retained_process_handle_count',
    'retained_process_handles_signaled', 'debugger_association_query_verified',
    'debugger_association_absent', 'cleanup_succeeded', 'detail'
)

function Assert-D32DownstreamHex {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][ValidateSet(40, 64)][int]$Length,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($Value -isnot [string] -or $Value -cnotmatch ("^[0-9a-f]{{{0}}}$" -f $Length)) {
        throw "$Name must be $Length lowercase hexadecimal characters"
    }
}

function Assert-D32DownstreamNonSecretReason {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Value, [Parameter(Mandatory = $true)][string]$Name)
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Value) -or ([string]$Value).Length -gt 512 -or
        [string]$Value -match '(?i)(VITA_D29G2_[A-Z_]*API_KEY\s*[=:]|authorization\s*:\s*bearer\s+\S+|\bapi[_-]?key\s*[=:]\s*\S+|\bsk-[A-Za-z0-9]{8,})') {
        throw "$Name must be a short non-secret rationale and must not contain credential-like material"
    }
}

function Assert-D32DownstreamInteger {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string]$Name,
        [int64]$Minimum = 0
    )
    $exact = [decimal]0
    try {
        if ($Value -isnot [ValueType] -or $Value -is [bool]) { throw 'not an integer value' }
        $exact = [decimal]$Value
    }
    catch {
        throw "$Name must be an integer >= $Minimum"
    }
    if ($exact -ne [decimal]::Truncate($exact) -or $exact -lt [decimal]$Minimum) {
        throw "$Name must be an integer >= $Minimum"
    }
}

function Assert-D32DownstreamExactKeys {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($Value -isnot [System.Collections.IDictionary]) {
        throw "$Name must be a JSON object"
    }
    $actual = @($Value.Keys | ForEach-Object { [string]$_ })
    if ($actual.Count -ne $Expected.Count) {
        throw "$Name has a missing or extra property"
    }
    foreach ($field in $Expected) {
        if (@($actual | Where-Object { $_ -ceq $field }).Count -ne 1) {
            throw "$Name has a missing or mis-cased property '$field'"
        }
    }
}

function Get-D32DownstreamCanonicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        throw 'all evidence paths must be absolute'
    }
    $full = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full.Length -gt $root.Length) { return $full.TrimEnd([char[]]@('\', '/')) }
    return $root
}

function Test-D32DownstreamPathEqual {
    param([Parameter(Mandatory = $true)][string]$Left, [Parameter(Mandatory = $true)][string]$Right)
    $a = Get-D32DownstreamCanonicalPath -Path $Left
    $b = Get-D32DownstreamCanonicalPath -Path $Right
    return [string]::Equals($a, $b, [StringComparison]::OrdinalIgnoreCase)
}

function Read-D32DownstreamPinnedBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$AllowEmpty,
        [int64]$MaximumBytes = 16777216
    )
    Assert-D32DownstreamHex -Value $ExpectedSha256 -Length 64 -Name "$Name pin"
    $fullPath = Get-D32DownstreamCanonicalPath -Path $Path
    $info = [System.IO.FileInfo]::new($fullPath)
    if (-not $info.Exists -or ($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Name must be an existing regular non-reparse file"
    }
    if ((-not $AllowEmpty -and $info.Length -le 0) -or $info.Length -gt $MaximumBytes) {
        throw "$Name is empty or exceeds the bounded read size"
    }
    $stream = $null
    $memory = $null
    try {
        $stream = [System.IO.File]::Open($fullPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        if ($stream.Length -ne $info.Length -or $stream.Length -gt $MaximumBytes) {
            throw "$Name length changed before its pinned read"
        }
        $memory = [System.IO.MemoryStream]::new()
        $buffer = [byte[]]::new(65536)
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $memory.Write($buffer, 0, $read)
            if ($memory.Length -gt $MaximumBytes) { throw "$Name exceeded the bounded read size" }
        }
        $bytes = $memory.ToArray()
        $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        if ($digest -cne $ExpectedSha256) { throw "$Name bytes do not match the independent SHA-256 pin" }
        return [ordered]@{ path = $fullPath; bytes = [int64]$bytes.Length; sha256 = $digest; content = $bytes }
    }
    finally {
        if ($null -ne $memory) { $memory.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function ConvertFrom-D32DownstreamJsonBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][string]$Name)
    try {
        $encoding = [System.Text.UTF8Encoding]::new($false, $true)
        $text = $encoding.GetString($Bytes)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
        $value = ConvertFrom-Json -InputObject $text -AsHashtable -Depth 100 -ErrorAction Stop
        if ($value -isnot [System.Collections.IDictionary]) { throw 'root was not an object' }
        return $value
    }
    catch {
        throw "$Name is not a valid UTF-8 JSON object"
    }
}

function Read-D32DownstreamPinnedJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Name,
        [int64]$MaximumBytes = 16777216
    )
    $snapshot = Read-D32DownstreamPinnedBytes -Path $Path -ExpectedSha256 $ExpectedSha256 -Name $Name -MaximumBytes $MaximumBytes
    $document = ConvertFrom-D32DownstreamJsonBytes -Bytes $snapshot.content -Name $Name
    return [ordered]@{ snapshot = $snapshot; document = $document }
}

function Assert-D32DownstreamReference {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Reference,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [switch]$RequireAggregateIdentity
    )
    $fields = if ($RequireAggregateIdentity) { $script:D32DownstreamAggregateReferenceFields } else { @('path', 'bytes', 'sha256') }
    Assert-D32DownstreamExactKeys -Value $Reference -Expected $fields -Name $Name
    if ($Reference.path -isnot [string] -or -not (Test-D32DownstreamPathEqual -Left ([string]$Reference.path) -Right $ExpectedPath)) {
        throw "$Name path does not match its explicit caller pin"
    }
    Assert-D32DownstreamInteger -Value $Reference.bytes -Name "$Name byte count" -Minimum 1
    Assert-D32DownstreamHex -Value $Reference.sha256 -Length 64 -Name "$Name SHA"
    if ($Reference.sha256 -cne $ExpectedSha256) { throw "$Name SHA differs from its independent caller pin" }
    if ($RequireAggregateIdentity) {
        Assert-D32DownstreamHex -Value $Reference.volume_serial_hex -Length 16 -Name "$Name volume identity"
        Assert-D32DownstreamHex -Value $Reference.file_id_hex -Length 32 -Name "$Name file identity"
    }
    $snapshot = Read-D32DownstreamPinnedBytes -Path $ExpectedPath -ExpectedSha256 $ExpectedSha256 -Name $Name
    if ($snapshot.bytes -ne [int64]$Reference.bytes) { throw "$Name current bytes differ from the aggregate reference" }
    return $snapshot
}

function Assert-D32DownstreamAggregateBundlePins {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][string]$AggregateRecordPath,
        [Parameter(Mandatory = $true)][string]$ExpectedAggregateRecordSha256,
        [Parameter(Mandatory = $true)][string]$BundleManifestPath,
        [Parameter(Mandatory = $true)][string]$ExpectedBundleManifestSha256,
        [Parameter(Mandatory = $true)][string]$AttestationPath,
        [Parameter(Mandatory = $true)][string]$ExpectedAttestationSha256
    )
    Assert-D32DownstreamHex -Value $CandidateSha -Length 40 -Name 'candidate SHA'
    Assert-D32DownstreamHex -Value $ExpectedAggregateRecordSha256 -Length 64 -Name 'aggregate SHA'
    Assert-D32DownstreamHex -Value $ExpectedBundleManifestSha256 -Length 64 -Name 'bundle-manifest SHA'
    Assert-D32DownstreamHex -Value $ExpectedAttestationSha256 -Length 64 -Name 'release-attestation SHA'

    $repo = Get-D32DownstreamCanonicalPath -Path $RepositoryRoot
    $aggregateRead = Read-D32DownstreamPinnedJson -Path $AggregateRecordPath -ExpectedSha256 $ExpectedAggregateRecordSha256 -Name 'post-bundle aggregate'
    $aggregate = $aggregateRead.document
    Assert-D32DownstreamExactKeys -Value $aggregate -Expected $script:D32DownstreamAggregateFields -Name 'post-bundle aggregate'
    if ($aggregate.schema_version -isnot [ValueType] -or $aggregate.schema_version -is [bool] -or [int]$aggregate.schema_version -ne 8 -or
        $aggregate.record_type -cne 'D32_POST_BUNDLE_AGGREGATE_RECORD_V8' -or
        $aggregate.scope -cne 'PRE_DOWNSTREAM_LOCAL_SCOPE' -or
        $aggregate.candidate_sha -cne $CandidateSha -or
        $aggregate.status -cne 'PRE_DOWNSTREAM_AGGREGATE_PASS' -or
        $aggregate.bundle_hashes -cne 'VERIFIED' -or
        $aggregate.downstream_gates -cne 'NOT RUN' -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$aggregate.source_repo) -Right $repo)) {
        throw 'aggregate is not the exact V8 pre-downstream record for the candidate with verified bundle hashes and downstream still NOT RUN'
    }
    if ($aggregate.powershell_module_admission -isnot [System.Collections.IDictionary]) {
        throw 'aggregate has no PowerShell module-admission record; run the official aggregate consumer before using this packet'
    }
    $evidenceRoot = Get-D32DownstreamCanonicalPath -Path ([string]$aggregate.evidence_root)
    $expectedBundlePath = Join-Path (Join-Path $evidenceRoot 'd32-gate-bundle') 'BUNDLE-MANIFEST.json'
    $expectedAttestationPath = Join-Path $evidenceRoot 'D32-RELEASE-ATTESTATION.json'
    if (-not (Test-D32DownstreamPathEqual -Left $BundleManifestPath -Right $expectedBundlePath) -or
        -not (Test-D32DownstreamPathEqual -Left $AttestationPath -Right $expectedAttestationPath)) {
        throw 'bundle manifest and release attestation are not the fixed siblings referenced by the pinned aggregate evidence root'
    }
    $references = $aggregate.references
    Assert-D32DownstreamExactKeys -Value $references -Expected @(
        'phase0_matrix', 'toolchain_profile', 'fixture_manifest', 'provenance_manifest',
        'bundle_manifest', 'attestation', 'trusted_git', 'test_inventory_baseline',
        'test_inventory_discovery'
    ) -Name 'aggregate references'
    $profileReference = $references.toolchain_profile
    Assert-D32DownstreamExactKeys -Value $profileReference -Expected $script:D32DownstreamAggregateReferenceFields -Name 'aggregate toolchain-profile reference'
    Assert-D32DownstreamHex -Value $profileReference.sha256 -Length 64 -Name 'aggregate toolchain-profile SHA'
    $profileSnapshot = Read-D32DownstreamPinnedBytes -Path ([string]$profileReference.path) -ExpectedSha256 ([string]$profileReference.sha256) -Name 'aggregate toolchain profile'
    if ($profileSnapshot.bytes -ne [int64]$profileReference.bytes) { throw 'toolchain profile bytes differ from aggregate reference' }
    foreach ($identityField in @('volume_serial_hex', 'file_id_hex')) {
        $length = if ($identityField -ceq 'volume_serial_hex') { 16 } else { 32 }
        Assert-D32DownstreamHex -Value $profileReference[$identityField] -Length $length -Name "aggregate toolchain-profile $identityField"
    }
    $profile = ConvertFrom-D32DownstreamJsonBytes -Bytes $profileSnapshot.content -Name 'aggregate toolchain profile'
    Assert-D32DownstreamExactKeys -Value $profile -Expected @(
        'schema_version', 'profile_type', 'target_triple', 'system_root', 'powershell_root', 'powershell',
        'rust_toolchain_root', 'toolchain', 'rust_toolchain_bin_images', 'native_roots', 'native',
        'windows_child_images', 'fetch_manifests', 'fetch_git', 'env_policy', 'cargo_policy'
    ) -Name 'toolchain profile'
    if ($profile.schema_version -isnot [ValueType] -or $profile.schema_version -is [bool] -or [int]$profile.schema_version -ne 2 -or
        $profile.profile_type -cne 'D32_BUILD_TOOLCHAIN_PROFILE_V2' -or
        $profile.target_triple -cne 'x86_64-pc-windows-msvc' -or
        $profile.env_policy -cne 'D32_BUILD_ENV_V1' -or
        $profile.cargo_policy -cne 'FRESH_HOME_LOCKED_FETCH_OFFLINE_AFTER') {
        throw 'aggregate toolchain profile is not the current pinned Profile V2 policy'
    }
    Assert-D32DownstreamExactKeys -Value $profile.toolchain -Expected @('cargo', 'rustc', 'rustdoc') -Name 'toolchain profile direct toolchain'
    foreach ($toolName in @('cargo', 'rustc', 'rustdoc')) {
        $tool = $profile.toolchain[$toolName]
        Assert-D32DownstreamExactKeys -Value $tool -Expected @('name', 'path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'reason') -Name "toolchain profile $toolName identity"
        if ($tool.path -isnot [string] -or -not [System.IO.Path]::IsPathRooted([string]$tool.path) -or
            [System.IO.Path]::GetFileName([string]$tool.path) -cne "$toolName.exe" -or
            [string]$tool.name -cne "$toolName.exe" -or [string]$tool.reason -ne "direct pinned $toolName executable") {
            throw "toolchain profile $toolName identity is not a direct absolute executable pin"
        }
        Assert-D32DownstreamHex -Value $tool.sha256 -Length 64 -Name "toolchain profile $toolName SHA"
        Assert-D32DownstreamHex -Value $tool.volume_serial_hex -Length 16 -Name "toolchain profile $toolName volume identity"
        Assert-D32DownstreamHex -Value $tool.file_id_hex -Length 32 -Name "toolchain profile $toolName file identity"
        Assert-D32DownstreamInteger -Value $tool.bytes -Name "toolchain profile $toolName bytes" -Minimum 1
    }

    $baselineReference = $references.test_inventory_baseline
    Assert-D32DownstreamExactKeys -Value $baselineReference -Expected $script:D32DownstreamAggregateReferenceFields -Name 'aggregate test-inventory-baseline reference'
    Assert-D32DownstreamHex -Value $baselineReference.sha256 -Length 64 -Name 'aggregate test-inventory-baseline SHA'
    foreach ($identityField in @('volume_serial_hex', 'file_id_hex')) {
        $length = if ($identityField -ceq 'volume_serial_hex') { 16 } else { 32 }
        Assert-D32DownstreamHex -Value $baselineReference[$identityField] -Length $length -Name "aggregate test-inventory-baseline $identityField"
    }
    $baselineSnapshot = Read-D32DownstreamPinnedBytes -Path ([string]$baselineReference.path) -ExpectedSha256 ([string]$baselineReference.sha256) -Name 'aggregate test-inventory baseline'
    if ($baselineSnapshot.bytes -ne [int64]$baselineReference.bytes) { throw 'test-inventory baseline bytes differ from aggregate reference' }
    $baseline = ConvertFrom-D32DownstreamJsonBytes -Bytes $baselineSnapshot.content -Name 'aggregate test-inventory baseline'
    Assert-D32DownstreamExactKeys -Value $baseline -Expected @(
        'schema_version', 'record_type', 'status', 'gate_authority', 'candidate_sha', 'source_repo',
        'target_triple', 'toolchain_profile', 'lock_inputs', 'source_patch_authority',
        'protoc_discovery_authority', 'discovery_module_admission', 'powershell_module_admission',
        'discovery', 'commands', 'entries', 'package_digests', 'combined_digest', 'category_counts', 'generated_at_utc'
    ) -Name 'test-inventory baseline'
    if ($baseline.schema_version -isnot [ValueType] -or $baseline.schema_version -is [bool] -or [int]$baseline.schema_version -ne 2 -or
        $baseline.record_type -cne 'D32_TEST_INVENTORY_BASELINE_V2' -or
        $baseline.candidate_sha -cne $CandidateSha -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$baseline.source_repo) -Right $repo) -or
        $baseline.gate_authority -cne 'NONE' -or $baseline.entries -isnot [array]) {
        throw 'aggregate test-inventory baseline is not bound to this candidate/repository'
    }
    if ($baseline.toolchain_profile -isnot [System.Collections.IDictionary] -or
        $baseline.toolchain_profile.sha256 -cne $profileSnapshot.sha256 -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$baseline.toolchain_profile.path) -Right $profileSnapshot.path)) {
        throw 'test-inventory baseline and aggregate toolchain-profile references disagree'
    }
    $inventoryEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $baseline.entries) {
        Assert-D32DownstreamExactKeys -Value $entry -Expected @('package', 'kind', 'full_name', 'category') -Name 'test-inventory baseline entry'
        if ($entry.package -isnot [string] -or $entry.kind -isnot [string] -or $entry.full_name -isnot [string] -or
            $entry.category -isnot [string] -or $entry.kind -cnotin @('test', 'benchmark')) {
            throw 'test-inventory baseline contains a malformed entry'
        }
        $inventoryEntries.Add($entry)
    }
    $resolvedD31Names = [ordered]@{}
    foreach ($case in $script:D32DownstreamD31Cases) {
        $matches = @($inventoryEntries | Where-Object {
            $_.package -ceq $case.inventory_package -and $_.kind -ceq 'test' -and
            $_.category -ceq 'deferred' -and ($_.full_name -ceq $case.name -or $_.full_name.EndsWith("::$($case.name)", [StringComparison]::Ordinal))
        })
        if ($matches.Count -ne 1) { throw "candidate baseline does not resolve D31 test exactly once as deferred: $($case.name)" }
        $resolvedD31Names[$case.name] = [string]$matches[0].full_name
    }
    $resolvedProviderNames = [ordered]@{}
    foreach ($case in $script:D32DownstreamProviderCases) {
        $matches = @($inventoryEntries | Where-Object {
            $_.package -ceq 'vita' -and $_.kind -ceq 'test' -and $_.category -ceq 'ignored' -and
            ($_.full_name -ceq $case.name -or $_.full_name.EndsWith("::$($case.name)", [StringComparison]::Ordinal))
        })
        if ($matches.Count -ne 1) { throw "candidate baseline does not resolve ignored provider test exactly once: $($case.name)" }
        $resolvedProviderNames[$case.name] = [string]$matches[0].full_name
    }
    $bundleReference = Assert-D32DownstreamReference -Reference $references.bundle_manifest -Name 'aggregate bundle-manifest reference' `
        -ExpectedPath $BundleManifestPath -ExpectedSha256 $ExpectedBundleManifestSha256 -RequireAggregateIdentity
    $attestationReference = Assert-D32DownstreamReference -Reference $references.attestation -Name 'aggregate release-attestation reference' `
        -ExpectedPath $AttestationPath -ExpectedSha256 $ExpectedAttestationSha256 -RequireAggregateIdentity

    $bundleRead = Read-D32DownstreamPinnedJson -Path $BundleManifestPath -ExpectedSha256 $ExpectedBundleManifestSha256 -Name 'bundle manifest'
    $bundle = $bundleRead.document
    if ($bundle.schema_version -isnot [ValueType] -or [int]$bundle.schema_version -ne 1 -or
        $bundle.candidate_sha -cne $CandidateSha -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$bundle.attestation_path) -Right $AttestationPath) -or
        $bundle.attestation_sha256 -cne $ExpectedAttestationSha256 -or
        $bundle.runtime_resources -isnot [array] -or $bundle.runtime_resources.Count -ne 0) {
        throw 'pinned bundle manifest does not cross-bind the exact candidate, attestation bytes and runtime_resources=[]'
    }
    $bundleNames = @($bundle.artifacts | ForEach-Object { [string]$_.name })
    $expectedBundleNames = @('vita-agent.exe', 'd32a-production-canary-host.exe', 'digital_life_lib.dll')
    if ($bundle.artifacts -isnot [array] -or $bundle.artifacts.Count -ne 3 -or
        @($expectedBundleNames | Where-Object { $bundleNames -cnotcontains $_ }).Count -ne 0 -or
        @($bundleNames | Where-Object { $expectedBundleNames -cnotcontains $_ }).Count -ne 0) {
        throw 'pinned bundle manifest does not contain exactly the three fixed flat artifact names'
    }
    $hostArtifact = @($bundle.artifacts | Where-Object { [string]$_.name -ceq 'd32a-production-canary-host.exe' })[0]
    Assert-D32DownstreamExactKeys -Value $hostArtifact -Expected @('name', 'build_path', 'bundle_path', 'build_bytes', 'bundle_bytes', 'build_sha256', 'bundle_sha256', 'build_identity', 'bundle_identity', 'exact_match') -Name 'Host bundle artifact'
    Assert-D32DownstreamExactKeys -Value $hostArtifact.bundle_identity -Expected @('FullName', 'Length', 'CreationTimeUtcTicks', 'LastWriteUtcTicks', 'Attributes', 'VolumeSerialHex', 'FileIdHex') -Name 'Host bundle artifact native file identity'
    Assert-D32DownstreamHex -Value $hostArtifact.bundle_sha256 -Length 64 -Name 'Host bundle image SHA'
    $hostImagePath = Get-D32DownstreamCanonicalPath -Path ([string]$hostArtifact.bundle_path)
    $hostImageSnapshot = Read-D32DownstreamPinnedBytes -Path $hostImagePath -ExpectedSha256 ([string]$hostArtifact.bundle_sha256) -Name 'pinned Host bundle image' -MaximumBytes 536870912
    Assert-D32DownstreamInteger -Value $hostArtifact.bundle_bytes -Name 'Host bundle image bytes' -Minimum 1
    Assert-D32DownstreamHex -Value $hostArtifact.bundle_identity.VolumeSerialHex -Length 16 -Name 'Host bundle identity volume serial'
    Assert-D32DownstreamHex -Value $hostArtifact.bundle_identity.FileIdHex -Length 32 -Name 'Host bundle identity file ID'
    Assert-D32DownstreamInteger -Value $hostArtifact.bundle_identity.Length -Name 'Host bundle identity length' -Minimum 1
    if ($hostImageSnapshot.bytes -ne [int64]$hostArtifact.bundle_bytes -or
        [int64]$hostArtifact.bundle_identity.Length -ne [int64]$hostArtifact.bundle_bytes -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$hostArtifact.bundle_identity.FullName) -Right $hostImagePath) -or
        $hostArtifact.exact_match -isnot [bool] -or -not $hostArtifact.exact_match -or
        $hostArtifact.build_sha256 -cne $hostArtifact.bundle_sha256 -or
        [int64]$hostArtifact.build_bytes -ne [int64]$hostArtifact.bundle_bytes) {
        throw 'current Host bundle image bytes/build binding/native identity differ from the pinned bundle manifest'
    }

    $attestationRead = Read-D32DownstreamPinnedJson -Path $AttestationPath -ExpectedSha256 $ExpectedAttestationSha256 -Name 'release attestation'
    $attestation = $attestationRead.document
    if ($attestation.schema_version -isnot [ValueType] -or $attestation.schema_version -is [bool] -or [int]$attestation.schema_version -ne 9 -or
        $attestation.attestation_type -cne 'D32_RELEASE_BUILD_ATTESTATION_V9' -or
        $attestation.candidate_sha -cne $CandidateSha) {
        throw 'pinned release attestation is not the exact V9 candidate record'
    }
    return [ordered]@{
        candidate_sha = $CandidateSha
        repository_root = $repo
        aggregate = [ordered]@{ path = $aggregateRead.snapshot.path; sha256 = $aggregateRead.snapshot.sha256 }
        bundle_manifest = [ordered]@{ path = $bundleReference.path; sha256 = $bundleReference.sha256 }
        release_attestation = [ordered]@{ path = $attestationReference.path; sha256 = $attestationReference.sha256 }
        test_inventory_baseline = [ordered]@{ path = $baselineSnapshot.path; sha256 = $baselineSnapshot.sha256 }
        toolchain_profile = [ordered]@{ path = $profileSnapshot.path; sha256 = $profileSnapshot.sha256; reference = $profileReference; cargo = $profile.toolchain.cargo; document = $profile }
        inventory = [ordered]@{ d31_test_names = $resolvedD31Names; provider_test_names = $resolvedProviderNames }
        host_image = [ordered]@{ path = $hostImagePath; sha256 = [string]$hostArtifact.bundle_sha256; bytes = [int64]$hostArtifact.bundle_bytes; volume_serial_hex = [string]$hostArtifact.bundle_identity.VolumeSerialHex; file_id_hex = [string]$hostArtifact.bundle_identity.FileIdHex }
        evidence_root = $evidenceRoot
    }
}

function Assert-D32DownstreamD31FileIdentity {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Identity, [Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][int64]$ExpectedBytes)
    Assert-D32DownstreamExactKeys -Value $Identity -Expected @('volume_serial', 'file_index', 'file_size', 'directory', 'reparse') -Name "$Name file identity"
    foreach ($field in @('volume_serial', 'file_index', 'file_size')) { Assert-D32DownstreamInteger -Value $Identity[$field] -Name "$Name file_identity.$field" -Minimum 0 }
    if ([decimal]$Identity.volume_serial -gt [decimal]4294967295 -or
        [decimal]$Identity.file_index -gt [decimal]18446744073709551615 -or
        [decimal]$Identity.file_size -gt [decimal]18446744073709551615) {
        throw "$Name file identity exceeds its uint32/uint64 wire type"
    }
    if ($Identity.file_size -ne $ExpectedBytes -or $Identity.directory -isnot [bool] -or $Identity.directory -or
        $Identity.reparse -isnot [bool] -or $Identity.reparse) {
        throw "$Name file identity is not a regular non-reparse file with the referenced byte length"
    }
}

function Assert-D32DownstreamD31FileReference {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Reference,
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$WithFileIdentity,
        [switch]$AllowEmpty,
        [AllowNull()][string]$ExpectedPath
    )
    $expected = if ($WithFileIdentity) { @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex', 'file_identity') } else { $script:D32DownstreamAggregateReferenceFields }
    Assert-D32DownstreamExactKeys -Value $Reference -Expected $expected -Name "$Name reference"
    Assert-D32DownstreamInteger -Value $Reference.bytes -Name "$Name bytes" -Minimum $(if ($AllowEmpty) { 0 } else { 1 })
    Assert-D32DownstreamHex -Value $Reference.sha256 -Length 64 -Name "$Name SHA"
    Assert-D32DownstreamHex -Value $Reference.volume_serial_hex -Length 16 -Name "$Name volume identity"
    Assert-D32DownstreamHex -Value $Reference.file_id_hex -Length 32 -Name "$Name file identity"
    if ($ExpectedPath -and -not (Test-D32DownstreamPathEqual -Left ([string]$Reference.path) -Right $ExpectedPath)) {
        throw "$Name path differs from its fixed layout"
    }
    $snapshot = Read-D32DownstreamPinnedBytes -Path ([string]$Reference.path) -ExpectedSha256 ([string]$Reference.sha256) -Name $Name -AllowEmpty:$AllowEmpty -MaximumBytes 268435456
    if ($snapshot.bytes -ne [int64]$Reference.bytes) { throw "$Name live byte length differs from its reference" }
    if ($WithFileIdentity) { Assert-D32DownstreamD31FileIdentity -Identity $Reference.file_identity -Name $Name -ExpectedBytes ([int64]$Reference.bytes) }
    return $snapshot
}

function Assert-D32DownstreamD31DirectoryReference {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Reference, [Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][string]$ExpectedPath)
    Assert-D32DownstreamExactKeys -Value $Reference -Expected @('path', 'volume_serial_hex', 'file_id_hex') -Name "$Name directory identity"
    if ($Reference.path -isnot [string] -or -not (Test-D32DownstreamPathEqual -Left ([string]$Reference.path) -Right $ExpectedPath)) {
        throw "$Name directory differs from its fixed path"
    }
    Assert-D32DownstreamHex -Value $Reference.volume_serial_hex -Length 16 -Name "$Name directory volume identity"
    Assert-D32DownstreamHex -Value $Reference.file_id_hex -Length 32 -Name "$Name directory file identity"
}

function Assert-D32DownstreamD31ProcessIdentityDocument {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Identity,
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$AllowMissingCommandLine
    )
    Assert-D32DownstreamExactKeys -Value $Identity -Expected @('process_id', 'parent_process_id', 'name', 'image_path', 'creation_date', 'command_line', 'observed_at_utc', 'identity_verified') -Name $Name
    Assert-D32DownstreamInteger -Value $Identity.process_id -Name "$Name process id" -Minimum 1
    Assert-D32DownstreamInteger -Value $Identity.parent_process_id -Name "$Name parent process id" -Minimum 1
    if ($Identity.name -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Identity.name) -or
        $Identity.image_path -isnot [string] -or -not [System.IO.Path]::IsPathRooted([string]$Identity.image_path) -or
        $Identity.creation_date -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Identity.creation_date) -or
        $Identity.command_line -isnot [string] -or
        ([string]::IsNullOrWhiteSpace([string]$Identity.command_line) -and
            (-not $AllowMissingCommandLine -or $Identity.command_line.Length -ne 0)) -or
        $Identity.observed_at_utc -isnot [string] -or $Identity.identity_verified -isnot [bool] -or -not $Identity.identity_verified) {
        throw "$Name process identity is malformed or unverified"
    }
}

function Assert-D32DownstreamD31NativeCleanup {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Cleanup, [Parameter(Mandatory = $true)][string]$Name)
    Assert-D32DownstreamExactKeys -Value $Cleanup -Expected @(
        'job_terminate_call_succeeded', 'job_terminate_last_error', 'process_was_already_signaled',
        'process_wait_signaled', 'job_active_process_count_verified', 'job_active_process_count',
        'job_active_process_count_last_error', 'job_close_succeeded', 'cleanup_succeeded', 'already_closed', 'detail'
    ) -Name "$Name native cleanup"
    foreach ($field in @('job_terminate_call_succeeded', 'process_was_already_signaled', 'process_wait_signaled',
            'job_active_process_count_verified', 'job_close_succeeded', 'cleanup_succeeded', 'already_closed')) {
        if ($Cleanup[$field] -isnot [bool]) { throw "$Name native cleanup.$field is not Boolean" }
    }
    foreach ($field in @('job_terminate_last_error', 'job_active_process_count', 'job_active_process_count_last_error')) {
        Assert-D32DownstreamInteger -Value $Cleanup[$field] -Name "$Name native cleanup.$field"
    }
    if (-not $Cleanup.process_wait_signaled -or -not $Cleanup.job_active_process_count_verified -or
        [int64]$Cleanup.job_active_process_count -ne 0 -or -not $Cleanup.job_close_succeeded -or
        -not $Cleanup.cleanup_succeeded -or $Cleanup.already_closed -or
        $Cleanup.job_terminate_last_error -ne 0 -or $Cleanup.job_active_process_count_last_error -ne 0 -or
        $Cleanup.detail -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Cleanup.detail)) {
        throw "$Name native cleanup does not prove a successful wait, zero-active Job, and closed Job"
    }
}

function ConvertTo-D32DownstreamCommandLine {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($argumentValue in $Arguments) {
        $argument = [string]$argumentValue
        if ($argument.Length -gt 0 -and $argument -notmatch '[\s"]') {
            $parts.Add($argument)
            continue
        }
        $builder = [System.Text.StringBuilder]::new()
        [void]$builder.Append('"')
        $slashes = 0
        foreach ($character in $argument.ToCharArray()) {
            if ($character -eq '\') { $slashes++; continue }
            if ($character -eq '"') {
                [void]$builder.Append([char]'\', (2 * $slashes) + 1)
                [void]$builder.Append('"')
                $slashes = 0
                continue
            }
            if ($slashes -gt 0) {
                [void]$builder.Append([char]'\', $slashes)
                $slashes = 0
            }
            [void]$builder.Append($character)
        }
        if ($slashes -gt 0) { [void]$builder.Append([char]'\', 2 * $slashes) }
        [void]$builder.Append('"')
        $parts.Add($builder.ToString())
    }
    return ($parts -join ' ')
}

function Assert-D32DownstreamD31IdentityMatchesTrace {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Identity,
        [Parameter(Mandatory = $true)][AllowNull()][object]$TraceProcess,
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$AllowMissingCommandLine
    )
    Assert-D32DownstreamD31ProcessIdentityDocument -Identity $Identity -Name $Name -AllowMissingCommandLine:$AllowMissingCommandLine
    if ([decimal]$Identity.process_id -ne [decimal]$TraceProcess.process_id -or
        [decimal]$Identity.parent_process_id -ne [decimal]$TraceProcess.parent_process_id -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$Identity.image_path) -Right ([string]$TraceProcess.image_path)) -or
        [System.IO.Path]::GetFileName([string]$Identity.image_path) -cne [string]$Identity.name) {
        throw "$Name D31 process identity differs from its ordered Trace V2 process record"
    }
}

function Assert-D32DownstreamStringArrayExact {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Actual, [Parameter(Mandatory = $true)][string[]]$Expected, [Parameter(Mandatory = $true)][string]$Name)
    if ($Actual -isnot [array] -or $Actual.Count -ne $Expected.Count) { throw "$Name is not the exact expected argv array" }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if ($Actual[$index] -isnot [string] -or $Actual[$index] -cne $Expected[$index]) {
            throw "$Name differs from fixed argv at index $index"
        }
    }
}

function Get-D32DownstreamD31CargoArgv {
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$Feature,
        [Parameter(Mandatory = $true)][string]$FullTestName
    )
    return @('test', '--manifest-path', $ManifestPath, '--locked', '--offline', '--features', $Feature,
        '--', '--exact', $FullTestName, '--nocapture')
}

function Get-D32DownstreamProviderCargoArgv {
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$FullTestName
    )
    return @('test', '--manifest-path', $ManifestPath, '--locked', '--offline', '--features', 'd32-a-test-helper',
        '--', '--ignored', '--exact', $FullTestName, '--nocapture')
}

function Assert-D32DownstreamD31Phase {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Phase,
        [Parameter(Mandatory = $true)][AllowNull()][object]$RecordPhase,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ExpectedPhaseName,
        [Parameter(Mandatory = $true)][string]$CargoPath,
        [Parameter(Mandatory = $true)][string]$CargoSha256,
        [Parameter(Mandatory = $true)][int64]$CargoBytes,
        [Parameter(Mandatory = $true)][string]$CargoVolumeSerialHex,
        [Parameter(Mandatory = $true)][string]$CargoFileIdHex,
        [Parameter(Mandatory = $true)][string[]]$ExpectedArgv,
        [AllowEmptyString()][string]$ExpectedManifestPath,
        [Parameter(Mandatory = $true)][int64]$RunnerProcessId,
        [Parameter(Mandatory = $true)][string]$ExpectedWorkingDirectory,
        [Parameter(Mandatory = $true)][string]$ExpectedPhaseLog,
        [Parameter(Mandatory = $true)][string]$ProtocPath,
        [Parameter(Mandatory = $true)][string]$ProtocSha256,
        [Parameter(Mandatory = $true)][int64]$ProtocBytes,
        [string]$ProtocVolumeSerialHex,
        [string]$ProtocFileIdHex
    )
    $phaseFields = @(
        'name', 'executable', 'command', 'command_line', 'working_directory', 'status', 'exit_code',
        'process_identity', 'root_record', 'descendant_records', 'process_trace', 'native_cleanup', 'reap',
        'phase_log', 'stdout_log', 'stderr_log', 'stdout_log_ref', 'stderr_log_ref'
    )
    $isFetch = $ExpectedPhaseName -match '-fetch$'
    if ($isFetch) { $phaseFields += @('manifest_path', 'lock_sha256') }
    Assert-D32DownstreamExactKeys -Value $Phase -Expected $phaseFields -Name "$Name phase"
    if ($Phase.name -cne $ExpectedPhaseName -or $Phase.status -cne 'succeeded' -or
        $Phase.exit_code -isnot [ValueType] -or [int]$Phase.exit_code -ne 0 -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$Phase.executable) -Right $CargoPath) -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$Phase.working_directory) -Right $ExpectedWorkingDirectory) -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$Phase.phase_log) -Right $ExpectedPhaseLog) -or
        $null -ne $Phase.reap) {
        throw "$Name phase is not the successful fixed command/working-directory capture or reports a reap"
    }
    Assert-D32DownstreamStringArrayExact -Actual $Phase.command -Expected $ExpectedArgv -Name "$Name command argv"
    $expectedCommandLine = ConvertTo-D32DownstreamCommandLine -Arguments (@($CargoPath) + $ExpectedArgv)
    if ($Phase.command_line -isnot [string] -or $Phase.command_line -cne $expectedCommandLine) {
        throw "$Name command line is not the exact direct Cargo path plus fixed argv"
    }
    if ($isFetch) {
        if ($Phase.manifest_path -isnot [string] -or
            [string]::IsNullOrWhiteSpace($ExpectedManifestPath) -or
            $Phase.manifest_path -cne $ExpectedManifestPath -or
            $Phase.lock_sha256 -isnot [string]) {
            throw "$Name fetch phase is not bound to its exact relative Profile V2 lock input"
        }
        Assert-D32DownstreamHex -Value $Phase.lock_sha256 -Length 64 -Name "$Name lock SHA"
    }
    if ($null -ne $RecordPhase) {
        Assert-D32DownstreamExactKeys -Value $RecordPhase -Expected @('manifest_path', 'lock_sha256', 'command', 'status', 'exit_code', 'process_identity') -Name "$Name D31 V2 fetch phase"
        if ($RecordPhase.status -cne 'succeeded' -or $RecordPhase.exit_code -isnot [ValueType] -or
            [int]$RecordPhase.exit_code -ne 0 -or $RecordPhase.lock_sha256 -cne $Phase.lock_sha256 -or
            -not (Test-D32DownstreamPathEqual -Left ([string]$RecordPhase.manifest_path) -Right ([string]$Phase.manifest_path))) {
            throw "$Name D31 V2 fetch phase differs from companion success evidence"
        }
        Assert-D32DownstreamStringArrayExact -Actual $RecordPhase.command -Expected $ExpectedArgv -Name "$Name D31 V2 command argv"
    }
    if ($Phase.process_identity -isnot [System.Collections.IDictionary] -or
        $Phase.root_record -isnot [System.Collections.IDictionary] -or
        $Phase.descendant_records -isnot [array]) {
        throw "$Name lacks exact root and ordered descendant process identities"
    }
    Assert-D32DownstreamD31ProcessIdentityDocument -Identity $Phase.process_identity -Name "$Name process identity"
    Assert-D32DownstreamD31ProcessIdentityDocument -Identity $Phase.root_record -Name "$Name root process identity"
    foreach ($field in @('process_id', 'parent_process_id', 'name', 'image_path', 'creation_date', 'command_line')) {
        if ($field -ceq 'image_path') {
            if (-not (Test-D32DownstreamPathEqual -Left ([string]$Phase.process_identity[$field]) -Right ([string]$Phase.root_record[$field]))) {
                throw "$Name process_identity and root_record refer to different process images"
            }
        }
        elseif ([string]$Phase.process_identity[$field] -cne [string]$Phase.root_record[$field]) {
            throw "$Name process_identity and root_record refer to different Cargo processes"
        }
    }
    if ([decimal]$Phase.process_identity.parent_process_id -ne [decimal]$RunnerProcessId -or
        [string]$Phase.process_identity.name -ine 'cargo.exe' -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$Phase.process_identity.image_path) -Right $CargoPath) -or
        [string]$Phase.process_identity.command_line -cne $expectedCommandLine) {
        throw "$Name Cargo process identity does not match the runner parent and fixed command line"
    }
    if ($null -ne $RecordPhase -and
        ([decimal]$Phase.process_identity.process_id -ne [decimal]$RecordPhase.process_identity.process_id -or
            [decimal]$RecordPhase.process_identity.parent_process_id -ne [decimal]$RunnerProcessId -or
            [string]$RecordPhase.process_identity.command_line -cne $expectedCommandLine)) {
        throw "$Name D31 V2 fetch process identity differs from the captured root"
    }
    $traceEvidence = Assert-D32DownstreamTraceV2 -Reference $Phase.process_trace -Cleanup $Phase.native_cleanup -Name $Name -RunnerProcessId $RunnerProcessId -ExpectedRootImagePath $CargoPath -ExpectedRootImageSha256 $CargoSha256 -ExpectedRootImageBytes $CargoBytes -ExpectedRootImageVolumeSerialHex $CargoVolumeSerialHex -ExpectedRootImageFileIdHex $CargoFileIdHex
    $trace = $traceEvidence.document
    $rootProcesses = @($trace.processes | Where-Object { $_.create_sequence -eq 1 })
    if ($rootProcesses.Count -ne 1 -or [decimal]$rootProcesses[0].process_id -ne [decimal]$Phase.process_identity.process_id -or
        [decimal]$rootProcesses[0].parent_process_id -ne [decimal]$RunnerProcessId) {
        throw "$Name Trace V2 root differs from its D31 process identity"
    }
    Assert-D32DownstreamD31IdentityMatchesTrace -Identity $Phase.root_record -TraceProcess $rootProcesses[0] -Name "$Name root"
    if ($Phase.root_record.command_line -cne $expectedCommandLine) {
        throw "$Name root record command line differs from its fixed direct Cargo invocation"
    }
    if ($Phase.descendant_records.Count -ne ($trace.processes.Count - 1)) {
        throw "$Name descendant identity count differs from Trace V2 process order"
    }
    for ($index = 0; $index -lt $Phase.descendant_records.Count; $index++) {
        Assert-D32DownstreamD31IdentityMatchesTrace -Identity $Phase.descendant_records[$index] -TraceProcess $trace.processes[$index + 1] `
            -Name "$Name descendant[$index]" -AllowMissingCommandLine
    }
    foreach ($process in $trace.processes) {
        if ([string]$process.image_path -match '(?i)(^|[\\/])vctip(?:\.exe)?$') { throw "$Name Trace V2 contains prohibited VCTIP" }
        if ($isFetch -and [System.IO.Path]::GetFileName([string]$process.image_path) -ieq 'protoc.exe') {
            throw "$Name fetch Trace V2 must not contain a protoc child"
        }
        if ([System.IO.Path]::GetFileName([string]$process.image_path) -ieq 'protoc.exe' -and
            (-not (Test-D32DownstreamPathEqual -Left ([string]$process.image_path) -Right $ProtocPath) -or
                $process.sha256 -cne $ProtocSha256 -or [int64]$process.bytes -ne $ProtocBytes -or
                (-not [string]::IsNullOrWhiteSpace($ProtocVolumeSerialHex) -and $process.volume_serial_hex -cne $ProtocVolumeSerialHex) -or
                (-not [string]::IsNullOrWhiteSpace($ProtocFileIdHex) -and $process.file_id_hex -cne $ProtocFileIdHex))) {
            throw "$Name Trace V2 contains protoc outside its exact D31-run-granted immutable image"
        }
    }
    if (@($trace.processes | Where-Object { [System.IO.Path]::GetFileName([string]$_.image_path) -ieq 'protoc.exe' }).Count -gt 1) {
        throw "$Name Trace V2 contains more than one protoc image identity"
    }
    $expectedStdout = "$ExpectedPhaseLog.stdout.log"
    $expectedStderr = "$ExpectedPhaseLog.stderr.log"
    if ($Phase.stdout_log -isnot [string] -or -not (Test-D32DownstreamPathEqual -Left $Phase.stdout_log -Right $expectedStdout) -or
        $Phase.stderr_log -isnot [string] -or -not (Test-D32DownstreamPathEqual -Left $Phase.stderr_log -Right $expectedStderr)) {
        throw "$Name raw log paths do not derive from the fixed unique phase-log base"
    }
    $stdoutSnapshot = Assert-D32DownstreamD31FileReference -Reference $Phase.stdout_log_ref -Name "$Name stdout log" -WithFileIdentity -ExpectedPath $expectedStdout -AllowEmpty
    $stderrSnapshot = Assert-D32DownstreamD31FileReference -Reference $Phase.stderr_log_ref -Name "$Name stderr log" -WithFileIdentity -ExpectedPath $expectedStderr -AllowEmpty
    if ([System.IO.Path]::GetFullPath($Phase.stdout_log) -ieq [System.IO.Path]::GetFullPath($Phase.stderr_log)) {
        throw "$Name stdout and stderr log paths alias"
    }
    $decoder = [System.Text.UTF8Encoding]::new($false, $true)
    try {
        $null = $decoder.GetString($stdoutSnapshot.content)
        $null = $decoder.GetString($stderrSnapshot.content)
    }
    catch { throw "$Name raw stdout/stderr captures are not strict UTF-8" }
}

function Assert-D32DownstreamSeederCompanion {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][object]$ExpectedToolchainProfile
    )
    $profileReference = $ExpectedToolchainProfile.reference
    $profileDocument = $ExpectedToolchainProfile.document
    $read = Read-D32DownstreamPinnedJson -Path $Path -ExpectedSha256 $ExpectedSha256 -Name 'D31 recovery seeder companion'
    $companion = $read.document
    Assert-D32DownstreamExactKeys -Value $companion -Expected @(
        'schema_version', 'record_type', 'status', 'candidate_sha', 'source_repo', 'run_id', 'runner_process_id',
        'toolchain_profile', 'powershell_module_admission', 'source_protoc_authority', 'owner_marker',
        'protoc_run_grant', 'run_root', 'cargo_home', 'temp_root', 'fetch_phases', 'build_phase',
        'seeder_record', 'artifact', 'process_cleanup', 'blocked_reason'
    ) -Name 'D31 recovery seeder companion'
    if ([System.IO.Path]::GetFileName($read.snapshot.path) -cne 'd31-recovery-seeder-companion.json' -or
        $companion.schema_version -isnot [ValueType] -or $companion.schema_version -is [bool] -or [int]$companion.schema_version -ne 1 -or
        $companion.record_type -cne 'D32_D31_RECOVERY_SEEDER_COMPANION_V1' -or
        $companion.status -cne 'succeeded' -or $companion.candidate_sha -cne $CandidateSha -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$companion.source_repo) -Right $RepositoryRoot) -or
        $companion.run_id -isnot [string] -or $companion.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        $companion.runner_process_id -isnot [ValueType] -or $companion.runner_process_id -is [bool] -or [int64]$companion.runner_process_id -le 0 -or
        $null -ne $companion.blocked_reason) {
        throw 'D31 companion is not a succeeded schema-v1 record for this exact candidate/repository/run'
    }
    if ($companion.fetch_phases -isnot [array] -or $companion.fetch_phases.Count -ne 3 -or
        $companion.powershell_module_admission -isnot [System.Collections.IDictionary] -or
        $companion.process_cleanup -isnot [System.Collections.IDictionary] -or
        $companion.build_phase -isnot [System.Collections.IDictionary]) {
        throw 'D31 companion lacks three ordered fetch phases, module admission, fixed build phase, or cleanup evidence'
    }

    Assert-D32DownstreamExactKeys -Value $companion.toolchain_profile -Expected $script:D32DownstreamAggregateReferenceFields -Name 'D31 companion toolchain-profile reference'
    foreach ($field in $script:D32DownstreamAggregateReferenceFields) {
        if ($field -ceq 'path') {
            if (-not (Test-D32DownstreamPathEqual -Left ([string]$companion.toolchain_profile.path) -Right ([string]$profileReference.path))) {
                throw 'D31 companion toolchain-profile path differs from the pinned aggregate'
            }
        }
        elseif ($companion.toolchain_profile[$field] -cne $profileReference[$field]) {
            throw "D31 companion toolchain-profile $field differs from the pinned aggregate"
        }
    }

    $companionDir = Split-Path -Parent $read.snapshot.path
    $expectedRunRoot = Join-Path $companionDir ("d31-recovery-seeder-run-{0}" -f $companion.run_id)
    $expectedCargoHome = Join-Path $expectedRunRoot 'cargo-home'
    $expectedTempRoot = Join-Path $expectedRunRoot 'temp'
    $expectedRecordPath = Join-Path $companionDir 'd31-recovery-seeder-build.json'
    $expectedTargetPath = Join-Path $companionDir 'd31-recovery-seeder-target'
    if ((Test-D32DownstreamPathEqual -Left $companionDir -Right $RepositoryRoot) -or
        (Test-D32DownstreamPathEqual -Left $expectedRunRoot -Right $RepositoryRoot) -or
        (Test-D32DownstreamPathEqual -Left $expectedRunRoot -Right $companionDir)) {
        throw 'D31 seeder roots must be external, unique, and non-overlapping with the repository'
    }
    foreach ($entry in @(
            [ordered]@{ name = 'run_root'; path = $expectedRunRoot },
            [ordered]@{ name = 'cargo_home'; path = $expectedCargoHome },
            [ordered]@{ name = 'temp_root'; path = $expectedTempRoot }
        )) {
        Assert-D32DownstreamD31DirectoryReference -Reference $companion[$entry.name] -Name "D31 companion $($entry.name)" -ExpectedPath $entry.path
        $directoryInfo = [System.IO.DirectoryInfo]::new([string]$companion[$entry.name].path)
        if (-not $directoryInfo.Exists -or ($directoryInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "D31 companion $($entry.name) is missing or reparse-backed"
        }
    }

    $admission = $companion.powershell_module_admission
    Assert-D32DownstreamExactKeys -Value $admission -Expected @(
        'record_type', 'schema_version', 'status', 'candidate_sha', 'source_repo', 'authority_reference',
        'profile_reference', 'git_image', 'powershell_host', 'runner_process', 'startup', 'entry_script_path',
        'entry_script', 'module_import_order', 'module_closure', 'resolver_admission', 'import_verification', 'import_attempts'
    ) -Name 'D31 companion PowerShell module admission V2'
    if ($admission.record_type -cne 'D32_POWERSHELL_MODULE_ADMISSION_V2' -or
        $admission.schema_version -isnot [ValueType] -or [int]$admission.schema_version -ne 2 -or
        $admission.status -cne 'ADMITTED' -or $admission.candidate_sha -cne $CandidateSha -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$admission.source_repo) -Right $RepositoryRoot) -or
        $admission.import_attempts -isnot [ValueType] -or [int]$admission.import_attempts -ne 3 -or
        $admission.profile_reference -isnot [System.Collections.IDictionary] -or
        $admission.runner_process -isnot [System.Collections.IDictionary] -or
        $admission.powershell_host -isnot [System.Collections.IDictionary] -or
        $admission.startup -isnot [System.Collections.IDictionary] -or
        $admission.module_closure -isnot [System.Collections.IDictionary] -or
        $admission.resolver_admission -isnot [System.Collections.IDictionary] -or
        $admission.import_verification -isnot [System.Collections.IDictionary]) {
        throw 'D31 companion does not carry a current admitted PowerShell Module Admission V2 record'
    }
    foreach ($field in $script:D32DownstreamAggregateReferenceFields) {
        if ($field -ceq 'path') {
            if (-not (Test-D32DownstreamPathEqual -Left ([string]$admission.profile_reference.path) -Right ([string]$profileReference.path))) {
                throw 'D31 producer admission profile path differs from the aggregate pin'
            }
        }
        elseif ($admission.profile_reference[$field] -cne $profileReference[$field]) {
            throw "D31 producer admission profile $field differs from the aggregate pin"
        }
    }
    $entryScriptPath = Join-Path $RepositoryRoot 'scripts/d32-fixture-prebuild.ps1'
    if ($admission.entry_script_path -isnot [string] -or
        -not (Test-D32DownstreamPathEqual -Left $admission.entry_script_path -Right $entryScriptPath) -or
        $admission.entry_script -isnot [System.Collections.IDictionary]) {
        throw 'D31 producer admission is not bound to the exact in-repository D31 seeder entry script'
    }
    Assert-D32DownstreamExactKeys -Value $admission.entry_script -Expected $script:D32DownstreamAggregateReferenceFields -Name 'D31 admitted entry-script reference'
    if (-not (Test-D32DownstreamPathEqual -Left ([string]$admission.entry_script.path) -Right $entryScriptPath)) {
        throw 'D31 admission entry-script reference path differs from its File operand'
    }
    $entrySnapshot = Read-D32DownstreamPinnedBytes -Path $entryScriptPath -ExpectedSha256 ([string]$admission.entry_script.sha256) -Name 'D31 admitted entry script' -MaximumBytes 4194304
    if ($entrySnapshot.bytes -ne [int64]$admission.entry_script.bytes) { throw 'D31 admitted entry-script bytes differ from the current source' }
    if ($admission.runner_process.process_id -isnot [ValueType] -or
        [int64]$admission.runner_process.process_id -ne [int64]$companion.runner_process_id -or
        $admission.runner_process.image_path -isnot [string] -or
        -not (Test-D32DownstreamPathEqual -Left $admission.runner_process.image_path -Right ([string]$admission.powershell_host.path)) -or
        $admission.startup.file_operand -isnot [string] -or
        -not (Test-D32DownstreamPathEqual -Left $admission.startup.file_operand -Right $entryScriptPath) -or
        $admission.startup.switches -isnot [array] -or $admission.startup.switches -cnotcontains '-NoProfile' -or
        $admission.module_import_order -isnot [array] -or
        (($admission.module_import_order -join '|') -cne 'Microsoft.PowerShell.Management|Microsoft.PowerShell.Utility|CimCmdlets') -or
        $admission.import_verification.state -cne 'VERIFIED') {
        throw 'D31 producer admission runner/startup/module-import evidence is not bound to its companion process and entry'
    }
    $hostPin = $profileDocument.powershell
    foreach ($field in @('path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex')) {
        if ($admission.powershell_host[$field] -cne $hostPin[$field]) { throw "D31 admission PowerShell host $field differs from Profile V2" }
    }
    if ($admission.runner_process.image_file_id_hex -cne $hostPin.file_id_hex) {
        throw 'D31 producer admission runner image file identity differs from the pinned PowerShell host'
    }

    $processCleanup = $companion.process_cleanup
    Assert-D32DownstreamExactKeys -Value $processCleanup -Expected @('status', 'checked_at_utc', 'relevant_pattern', 'residual_identities', 'error') -Name 'D31 seeder process cleanup'
    $cleanupTime = [DateTimeOffset]::MinValue
    if ($processCleanup.status -cne 'succeeded' -or $processCleanup.checked_at_utc -isnot [string] -or
        -not [DateTimeOffset]::TryParse([string]$processCleanup.checked_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$cleanupTime) -or
        $processCleanup.relevant_pattern -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$processCleanup.relevant_pattern) -or
        $processCleanup.residual_identities -isnot [array] -or $processCleanup.residual_identities.Count -ne 0 -or
        $null -ne $processCleanup.error) {
        throw 'D31 seeder process cleanup is absent, failed, or reports residual process identities'
    }

    $recordRef = $companion.seeder_record
    $recordSnapshot = Assert-D32DownstreamD31FileReference -Reference $recordRef -Name 'D31 companion seeder-record reference' -WithFileIdentity -ExpectedPath $expectedRecordPath
    $artifactPath = Join-Path (Join-Path $expectedTargetPath 'debug') 'vita-agent.exe'
    $artifactRef = $companion.artifact
    $artifactSnapshot = Assert-D32DownstreamD31FileReference -Reference $artifactRef -Name 'D31 companion artifact reference' -WithFileIdentity -ExpectedPath $artifactPath
    $recordRead = ConvertFrom-D32DownstreamJsonBytes -Bytes $recordSnapshot.content -Name 'D31 V2 build record'
    Assert-D32DownstreamExactKeys -Value $recordRead -Expected @(
        'schema_version', 'purpose', 'run_id', 'candidate_sha', 'runner_process_id', 'source_repo', 'manifest_path',
        'feature', 'command', 'target_dir', 'run_root', 'cargo_home', 'temp_root', 'toolchain_profile_path',
        'toolchain_profile_sha256', 'target_triple', 'powershell', 'toolchain', 'fetch_manifests', 'fetch_phases',
        'cargo_path', 'process_identity', 'status', 'exit_code', 'artifact'
    ) -Name 'D31 recovery seeder V2 build record'
    if ($recordRead.schema_version -isnot [ValueType] -or [int]$recordRead.schema_version -ne 2 -or
        $recordRead.purpose -cne 'd31-recovery-seeder-test-helper' -or $recordRead.status -cne 'succeeded' -or
        $recordRead.exit_code -isnot [ValueType] -or [int]$recordRead.exit_code -ne 0 -or
        $recordRead.candidate_sha -cne $CandidateSha -or $recordRead.run_id -cne $companion.run_id -or
        [int64]$recordRead.runner_process_id -ne [int64]$companion.runner_process_id -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$recordRead.source_repo) -Right $RepositoryRoot) -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$recordRead.manifest_path) -Right (Join-Path $RepositoryRoot 'vita-agent/Cargo.toml')) -or
        $recordRead.feature -cne 'd29-h9-test-helper' -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$recordRead.target_dir) -Right $expectedTargetPath) -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$recordRead.run_root) -Right $expectedRunRoot) -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$recordRead.cargo_home) -Right $expectedCargoHome) -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$recordRead.temp_root) -Right $expectedTempRoot) -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$recordRead.toolchain_profile_path) -Right ([string]$profileReference.path)) -or
        $recordRead.toolchain_profile_sha256 -cne $profileReference.sha256 -or
        $recordRead.target_triple -cne $profileDocument.target_triple -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$recordRead.cargo_path) -Right ([string]$profileDocument.toolchain.cargo.path))) {
        throw 'D31 V2 build record is not a successful exact-candidate run under the fixed seeder/profile layout'
    }
    Assert-D32DownstreamStringArrayExact -Actual $recordRead.command -Expected @(
        'build', '--quiet', '--locked', '--manifest-path', [string]$recordRead.manifest_path,
        '--bin', 'vita-agent', '--features', 'd29-h9-test-helper', '--target-dir', [string]$recordRead.target_dir
    ) -Name 'D31 V2 fixed build argv'
    Assert-D32DownstreamExactKeys -Value $recordRead.artifact -Expected @('path', 'bytes', 'sha256', 'file_identity') -Name 'D31 V2 artifact record'
    if (-not (Test-D32DownstreamPathEqual -Left ([string]$recordRead.artifact.path) -Right $artifactPath) -or
        $recordRead.artifact.sha256 -cne $artifactRef.sha256 -or [decimal]$recordRead.artifact.bytes -ne [decimal]$artifactRef.bytes) {
        throw 'D31 companion and V2 record artifact paths, bytes, or hashes differ'
    }
    Assert-D32DownstreamD31FileIdentity -Identity $recordRead.artifact.file_identity -Name 'D31 V2 artifact' -ExpectedBytes ([int64]$artifactRef.bytes)
    foreach ($field in @('volume_serial', 'file_index', 'file_size', 'directory', 'reparse')) {
        if ($recordRead.artifact.file_identity[$field] -cne $artifactRef.file_identity[$field]) {
            throw "D31 companion artifact file_identity.$field differs from the strict V2 build record"
        }
    }
    if ($recordSnapshot.bytes -ne [int64]$recordRef.bytes -or $artifactSnapshot.bytes -ne [int64]$artifactRef.bytes) {
        throw 'D31 companion record/artifact live bytes differ from their independently referenced sizes'
    }

    if ($recordRead.powershell -isnot [System.Collections.IDictionary] -or $recordRead.toolchain -isnot [System.Collections.IDictionary] -or
        $recordRead.fetch_manifests -isnot [array] -or $recordRead.fetch_manifests.Count -ne 3 -or
        $recordRead.fetch_phases -isnot [array] -or $recordRead.fetch_phases.Count -ne 3) {
        throw 'D31 V2 record is missing exact Profile V2 toolchain, lock inputs, or ordered fetch phases'
    }
    foreach ($toolName in @('cargo', 'rustc', 'rustdoc')) {
        Assert-D32DownstreamExactKeys -Value $recordRead.toolchain[$toolName] -Expected @('name', 'path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'reason') -Name "D31 V2 $toolName identity"
        foreach ($field in @('name', 'path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'reason')) {
            if ($field -ceq 'path') {
                if (-not (Test-D32DownstreamPathEqual -Left ([string]$recordRead.toolchain[$toolName].path) -Right ([string]$profileDocument.toolchain[$toolName].path))) {
                    throw "D31 V2 $toolName path differs from pinned Profile V2"
                }
            }
            elseif ($recordRead.toolchain[$toolName][$field] -cne $profileDocument.toolchain[$toolName][$field]) {
                throw "D31 V2 $toolName $field differs from pinned Profile V2"
            }
        }
    }
    Assert-D32DownstreamExactKeys -Value $recordRead.powershell -Expected @('name', 'path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'reason') -Name 'D31 V2 PowerShell identity'
    foreach ($field in @('name', 'path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'reason')) {
        if ($field -ceq 'path') {
            if (-not (Test-D32DownstreamPathEqual -Left ([string]$recordRead.powershell.path) -Right ([string]$profileDocument.powershell.path))) {
                throw 'D31 V2 PowerShell path differs from Profile V2'
            }
        }
        elseif ($recordRead.powershell[$field] -cne $profileDocument.powershell[$field]) {
            throw "D31 V2 PowerShell $field differs from Profile V2"
        }
    }

    if ($profileDocument.fetch_manifests -isnot [array] -or $profileDocument.fetch_manifests.Count -ne 3) {
        throw 'Pinned Profile V2 must contain the exact three D31 fetch-lock inputs'
    }
    $expectedFetchRelative = @('vita-agent-protocol/Cargo.toml', 'vita-agent/Cargo.toml', 'src-tauri/Cargo.toml')
    for ($index = 0; $index -lt 3; $index++) {
        $profileFetch = $profileDocument.fetch_manifests[$index]
        Assert-D32DownstreamExactKeys -Value $profileFetch -Expected @('manifest_path', 'lock_sha256') -Name "Profile V2 fetch input[$index]"
        Assert-D32DownstreamExactKeys -Value $recordRead.fetch_manifests[$index] -Expected @('manifest_path', 'lock_sha256') -Name "D31 V2 fetch input[$index]"
        if ($profileFetch.manifest_path -cne $expectedFetchRelative[$index] -or
            $recordRead.fetch_manifests[$index].manifest_path -cne $profileFetch.manifest_path -or
            $recordRead.fetch_manifests[$index].lock_sha256 -cne $profileFetch.lock_sha256) {
            throw "D31 V2 fetch input[$index] differs from ordered Profile V2 lock inputs"
        }
        Assert-D32DownstreamHex -Value $profileFetch.lock_sha256 -Length 64 -Name "Profile V2 fetch input[$index] lock SHA"
        $manifestFullPath = Join-Path $RepositoryRoot ($profileFetch.manifest_path -replace '/', '\')
        $phaseName = 'd31-seeder-{0:D2}-fetch' -f ($index + 1)
        $phase = $companion.fetch_phases[$index]
        if ($phase.manifest_path -isnot [string] -or
            $phase.manifest_path -cne $profileFetch.manifest_path -or
            $phase.lock_sha256 -cne $profileFetch.lock_sha256) {
            throw "$phaseName companion fetch lock binding differs from Profile V2"
        }
        $args = @('fetch', '--locked', '--manifest-path', $manifestFullPath, '--target', [string]$profileDocument.target_triple)
        $recordPhase = $recordRead.fetch_phases[$index]
        if ($recordPhase.manifest_path -cne $profileFetch.manifest_path -or $recordPhase.lock_sha256 -cne $profileFetch.lock_sha256) {
            throw "$phaseName V2 fetch phase differs from Profile V2"
        }
        $phaseLog = Join-Path (Join-Path $expectedRunRoot 'logs') $phaseName
        Assert-D32DownstreamD31Phase -Phase $phase -RecordPhase $recordPhase -Name $phaseName -ExpectedPhaseName $phaseName -CargoPath ([string]$profileDocument.toolchain.cargo.path) -CargoSha256 ([string]$profileDocument.toolchain.cargo.sha256) -CargoBytes ([int64]$profileDocument.toolchain.cargo.bytes) -CargoVolumeSerialHex ([string]$profileDocument.toolchain.cargo.volume_serial_hex) -CargoFileIdHex ([string]$profileDocument.toolchain.cargo.file_id_hex) -ExpectedArgv $args -ExpectedManifestPath ([string]$profileFetch.manifest_path) -RunnerProcessId ([int64]$companion.runner_process_id) -ExpectedWorkingDirectory $RepositoryRoot -ExpectedPhaseLog $phaseLog -ProtocPath (Join-Path $expectedCargoHome 'registry\src\index.crates.io-1949cf8c6b5b557f\protoc-bin-vendored-win32-3.2.0\bin\protoc.exe') -ProtocSha256 'cbd1ca1fd6afd1bb6ddd1c09c118ecd4c50f928980857f16fe6fc23704ea17e2' -ProtocBytes 11934496
    }

    $sourceAuthority = Read-D32DownstreamSeederRef -Reference $companion.source_protoc_authority -Name 'D31 source protoc authority'
    $ownerPath = Join-Path $expectedRunRoot 'D32-D31-RECOVERY-SEEDER-OWNER.json'
    $ownerSnapshot = Read-D32DownstreamSeederRef -Reference $companion.owner_marker -Name 'D31 seeder owner marker'
    if (-not (Test-D32DownstreamPathEqual -Left ([string]$companion.owner_marker.path) -Right $ownerPath)) { throw 'D31 seeder owner marker path is not the fixed fresh-run marker' }
    $ownerDocument = ConvertFrom-D32DownstreamJsonBytes -Bytes $ownerSnapshot.content -Name 'D31 seeder owner marker'
    Assert-D32DownstreamExactKeys -Value $ownerDocument -Expected @(
        'schema_version', 'record_type', 'candidate_sha', 'toolchain_profile_path', 'toolchain_profile_sha256',
        'toolchain_profile_bytes', 'toolchain_profile_volume_serial_hex', 'toolchain_profile_file_id_hex',
        'run_root_path', 'run_root_volume_serial_hex', 'run_root_file_id_hex', 'run_id', 'runner_process_id'
    ) -Name 'D31 create-new owner marker'
    foreach ($field in @('schema_version', 'toolchain_profile_bytes', 'runner_process_id')) {
        Assert-D32DownstreamInteger -Value $ownerDocument[$field] -Name "D31 owner marker $field" -Minimum 1
    }
    Assert-D32DownstreamHex -Value $ownerDocument.toolchain_profile_sha256 -Length 64 -Name 'D31 owner toolchain-profile SHA'
    Assert-D32DownstreamHex -Value $ownerDocument.toolchain_profile_volume_serial_hex -Length 16 -Name 'D31 owner profile volume identity'
    Assert-D32DownstreamHex -Value $ownerDocument.toolchain_profile_file_id_hex -Length 32 -Name 'D31 owner profile file identity'
    Assert-D32DownstreamHex -Value $ownerDocument.run_root_volume_serial_hex -Length 16 -Name 'D31 owner run-root volume identity'
    Assert-D32DownstreamHex -Value $ownerDocument.run_root_file_id_hex -Length 32 -Name 'D31 owner run-root file identity'
    if ($ownerDocument.schema_version -is [bool] -or [int]$ownerDocument.schema_version -ne 1 -or
        $ownerDocument.record_type -cne 'D32_D31_RECOVERY_SEEDER_OWNER_V1' -or
        $ownerDocument.candidate_sha -cne $CandidateSha -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$ownerDocument.toolchain_profile_path) -Right ([string]$profileReference.path)) -or
        $ownerDocument.toolchain_profile_sha256 -cne $profileReference.sha256 -or
        [decimal]$ownerDocument.toolchain_profile_bytes -ne [decimal]$profileReference.bytes -or
        $ownerDocument.toolchain_profile_volume_serial_hex -cne $profileReference.volume_serial_hex -or
        $ownerDocument.toolchain_profile_file_id_hex -cne $profileReference.file_id_hex -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$ownerDocument.run_root_path) -Right $expectedRunRoot) -or
        $ownerDocument.run_root_volume_serial_hex -cne $companion.run_root.volume_serial_hex -or
        $ownerDocument.run_root_file_id_hex -cne $companion.run_root.file_id_hex -or
        $ownerDocument.run_id -cne $companion.run_id -or
        [decimal]$ownerDocument.runner_process_id -ne [decimal]$companion.runner_process_id) {
        throw 'D31 owner marker does not exactly bind this candidate, pinned profile, unique run root, run id, and runner'
    }
    $grantPath = Join-Path $expectedRunRoot 'D32-D31-RECOVERY-SEEDER-PROTOC-RUN-GRANT.json'
    $grantSnapshot = Read-D32DownstreamSeederRef -Reference $companion.protoc_run_grant -Name 'D31-only protoc run grant'
    if (-not (Test-D32DownstreamPathEqual -Left ([string]$companion.protoc_run_grant.path) -Right $grantPath)) {
        throw 'D31 protoc run grant is not at the fixed fresh-run grant path'
    }
    $grant = ConvertFrom-D32DownstreamJsonBytes -Bytes $grantSnapshot.content -Name 'D31-only protoc run grant'
    Assert-D32DownstreamExactKeys -Value $grant -Expected @(
        'schema_version', 'record_type', 'scope', 'source_authority', 'candidate_sha', 'toolchain_profile', 'run_root',
        'owner_marker', 'run_id', 'runner_process_id', 'cargo_home', 'temp_root', 'vita_cargo_lock', 'cargo_archive',
        'source_directory', 'protoc_image'
    ) -Name 'D31 protoc run grant'
    if ($grant.schema_version -is [bool] -or $grant.schema_version -isnot [ValueType] -or [int]$grant.schema_version -ne 1 -or
        $grant.record_type -cne 'D32_D31_RECOVERY_SEEDER_PROTOC_RUN_GRANT_V1' -or
        $grant.scope -cne 'D32_D31_RECOVERY_SEEDER_ONLY' -or
        $grant.candidate_sha -cne $CandidateSha -or $grant.run_id -cne $companion.run_id -or
        $grant.runner_process_id -is [bool] -or $grant.runner_process_id -isnot [ValueType] -or
        [decimal]$grant.runner_process_id -ne [decimal]$companion.runner_process_id) {
        throw 'D31 protoc run grant has the wrong strict D31 type/scope or candidate/run/runner binding'
    }
    Assert-D32DownstreamExactKeys -Value $grant.toolchain_profile -Expected $script:D32DownstreamAggregateReferenceFields -Name 'D31 grant toolchain-profile reference'
    foreach ($field in $script:D32DownstreamAggregateReferenceFields) {
        if ($field -ceq 'path') {
            if (-not (Test-D32DownstreamPathEqual -Left ([string]$grant.toolchain_profile.path) -Right ([string]$profileReference.path))) {
                throw 'D31 grant toolchain-profile path differs from the pinned aggregate'
            }
        }
        elseif ($grant.toolchain_profile[$field] -cne $profileReference[$field]) {
            throw "D31 grant toolchain-profile $field differs from the pinned aggregate"
        }
    }
    foreach ($binding in @(
            [ordered]@{ name = 'run_root'; actual = $grant.run_root; expected = $companion.run_root },
            [ordered]@{ name = 'cargo_home'; actual = $grant.cargo_home; expected = $companion.cargo_home },
            [ordered]@{ name = 'temp_root'; actual = $grant.temp_root; expected = $companion.temp_root }
        )) {
        Assert-D32DownstreamExactKeys -Value $binding.actual -Expected @('path', 'volume_serial_hex', 'file_id_hex') -Name "D31 grant $($binding.name) identity"
        foreach ($field in @('path', 'volume_serial_hex', 'file_id_hex')) {
            if ($field -ceq 'path') {
                if (-not (Test-D32DownstreamPathEqual -Left ([string]$binding.actual.path) -Right ([string]$binding.expected.path))) {
                    throw "D31 grant $($binding.name) path differs from companion"
                }
            }
            elseif ($binding.actual[$field] -cne $binding.expected[$field]) {
                throw "D31 grant $($binding.name) $field differs from companion"
            }
        }
    }
    foreach ($binding in @(
            [ordered]@{ name = 'source_authority'; actual = $grant.source_authority; expected = $companion.source_protoc_authority },
            [ordered]@{ name = 'owner_marker'; actual = $grant.owner_marker; expected = $companion.owner_marker }
        )) {
        Assert-D32DownstreamExactKeys -Value $binding.actual -Expected $script:D32DownstreamAggregateReferenceFields -Name "D31 grant $($binding.name) file reference"
        foreach ($field in $script:D32DownstreamAggregateReferenceFields) {
            if ($field -ceq 'path') {
                if (-not (Test-D32DownstreamPathEqual -Left ([string]$binding.actual.path) -Right ([string]$binding.expected.path))) {
                    throw "D31 grant $($binding.name) path differs from companion"
                }
            }
            elseif ($binding.actual[$field] -cne $binding.expected[$field]) {
                throw "D31 grant $($binding.name) $field differs from companion"
            }
        }
    }
    $grantFileRefs = @(
        [ordered]@{ name = 'Vita Cargo.lock'; reference = $grant.vita_cargo_lock; path = (Join-Path $RepositoryRoot 'vita-agent/Cargo.lock') },
        [ordered]@{ name = 'locked protoc archive'; reference = $grant.cargo_archive; path = (Join-Path $expectedCargoHome 'registry\cache\index.crates.io-1949cf8c6b5b557f\protoc-bin-vendored-win32-3.2.0.crate') },
        [ordered]@{ name = 'locked protoc image'; reference = $grant.protoc_image; path = (Join-Path $expectedCargoHome 'registry\src\index.crates.io-1949cf8c6b5b557f\protoc-bin-vendored-win32-3.2.0\bin\protoc.exe') }
    )
    foreach ($entry in $grantFileRefs) {
        Assert-D32DownstreamExactKeys -Value $entry.reference -Expected $script:D32DownstreamAggregateReferenceFields -Name "D31 grant $($entry.name) file reference"
        Assert-D32DownstreamInteger -Value $entry.reference.bytes -Name "D31 grant $($entry.name) bytes" -Minimum 1
        Assert-D32DownstreamHex -Value $entry.reference.sha256 -Length 64 -Name "D31 grant $($entry.name) SHA"
        Assert-D32DownstreamHex -Value $entry.reference.volume_serial_hex -Length 16 -Name "D31 grant $($entry.name) volume identity"
        Assert-D32DownstreamHex -Value $entry.reference.file_id_hex -Length 32 -Name "D31 grant $($entry.name) file identity"
        if (-not (Test-D32DownstreamPathEqual -Left ([string]$entry.reference.path) -Right ([string]$entry.path))) {
            throw "D31 grant $($entry.name) is not bound to its fixed repository/fresh CargoHome path"
        }
    }
    if ($grant.cargo_archive.sha256 -cne '95067976aca6421a523e491fce939a3e65249bac4b977adee0ee9771568e8aa3' -or
        [decimal]$grant.cargo_archive.bytes -ne [decimal]3426255 -or
        $grant.protoc_image.sha256 -cne 'cbd1ca1fd6afd1bb6ddd1c09c118ecd4c50f928980857f16fe6fc23704ea17e2' -or
        [decimal]$grant.protoc_image.bytes -ne [decimal]11934496 -or
        $profileDocument.fetch_manifests[1].manifest_path -cne 'vita-agent/Cargo.toml' -or
        $grant.vita_cargo_lock.sha256 -cne $profileDocument.fetch_manifests[1].lock_sha256 -or
        $null -eq $sourceAuthority) {
        throw 'D31 protoc grant does not bind exact locked 3.2.0 archive/image and source authority'
    }
    Assert-D32DownstreamExactKeys -Value $grant.source_directory -Expected @('path', 'volume_serial_hex', 'file_id_hex') -Name 'D31 grant protoc source-directory identity'
    Assert-D32DownstreamHex -Value $grant.source_directory.volume_serial_hex -Length 16 -Name 'D31 grant source-directory volume identity'
    Assert-D32DownstreamHex -Value $grant.source_directory.file_id_hex -Length 32 -Name 'D31 grant source-directory file identity'
    $expectedProtocSource = Join-Path $expectedCargoHome 'registry\src\index.crates.io-1949cf8c6b5b557f\protoc-bin-vendored-win32-3.2.0'
    if (-not (Test-D32DownstreamPathEqual -Left ([string]$grant.source_directory.path) -Right $expectedProtocSource)) {
        throw 'D31 grant protoc source directory is outside its exact fresh CargoHome crate source'
    }
    $protocSourceDirectory = [System.IO.DirectoryInfo]::new([string]$grant.source_directory.path)
    if (-not $protocSourceDirectory.Exists -or ($protocSourceDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'D31 grant protoc source directory is absent or reparse-backed'
    }
    $lockSnapshot = Read-D32DownstreamPinnedBytes -Path ([string]$grant.vita_cargo_lock.path) -ExpectedSha256 ([string]$grant.vita_cargo_lock.sha256) -Name 'D31 grant Vita Cargo.lock' -MaximumBytes 4194304
    $archiveSnapshot = Read-D32DownstreamPinnedBytes -Path ([string]$grant.cargo_archive.path) -ExpectedSha256 ([string]$grant.cargo_archive.sha256) -Name 'D31 grant locked protoc archive' -MaximumBytes 16777216
    $protocSnapshot = Read-D32DownstreamPinnedBytes -Path ([string]$grant.protoc_image.path) -ExpectedSha256 ([string]$grant.protoc_image.sha256) -Name 'D31 grant locked protoc image' -MaximumBytes 16777216
    if ($lockSnapshot.bytes -ne [int64]$grant.vita_cargo_lock.bytes -or
        $archiveSnapshot.bytes -ne [int64]$grant.cargo_archive.bytes -or
        $protocSnapshot.bytes -ne [int64]$grant.protoc_image.bytes) {
        throw 'D31 grant locked Cargo/protoc files differ from the exact referenced byte lengths'
    }

    $buildArgv = @('build', '--quiet', '--locked', '--manifest-path', (Join-Path $RepositoryRoot 'vita-agent/Cargo.toml'), '--bin', 'vita-agent', '--features', 'd29-h9-test-helper', '--target-dir', $expectedTargetPath)
    $buildPhase = $companion.build_phase
    $buildLog = Join-Path (Join-Path $expectedRunRoot 'logs') 'd31-recovery-seeder'
    Assert-D32DownstreamD31Phase -Phase $buildPhase -RecordPhase $null -Name 'd31-recovery-seeder' -ExpectedPhaseName 'd31-recovery-seeder' -CargoPath ([string]$profileDocument.toolchain.cargo.path) -CargoSha256 ([string]$profileDocument.toolchain.cargo.sha256) -CargoBytes ([int64]$profileDocument.toolchain.cargo.bytes) -CargoVolumeSerialHex ([string]$profileDocument.toolchain.cargo.volume_serial_hex) -CargoFileIdHex ([string]$profileDocument.toolchain.cargo.file_id_hex) -ExpectedArgv $buildArgv -RunnerProcessId ([int64]$companion.runner_process_id) -ExpectedWorkingDirectory $RepositoryRoot -ExpectedPhaseLog $buildLog -ProtocPath (Join-Path $expectedCargoHome 'registry\src\index.crates.io-1949cf8c6b5b557f\protoc-bin-vendored-win32-3.2.0\bin\protoc.exe') -ProtocSha256 'cbd1ca1fd6afd1bb6ddd1c09c118ecd4c50f928980857f16fe6fc23704ea17e2' -ProtocBytes 11934496 -ProtocVolumeSerialHex ([string]$grant.protoc_image.volume_serial_hex) -ProtocFileIdHex ([string]$grant.protoc_image.file_id_hex)
    if ($recordRead.process_identity -isnot [System.Collections.IDictionary]) { throw 'D31 V2 build record lacks the root Cargo identity' }
    Assert-D32DownstreamD31ProcessIdentityDocument -Identity $recordRead.process_identity -Name 'D31 V2 build Cargo identity'
    foreach ($field in @('process_id', 'parent_process_id', 'name', 'image_path', 'creation_date', 'command_line')) {
        if ($field -ceq 'image_path') {
            if (-not (Test-D32DownstreamPathEqual -Left ([string]$recordRead.process_identity[$field]) -Right ([string]$buildPhase.process_identity[$field]))) { throw 'D31 V2 build Cargo image differs from companion trace root' }
        }
        elseif ([string]$recordRead.process_identity[$field] -cne [string]$buildPhase.process_identity[$field]) {
            throw "D31 V2 build Cargo identity $field differs from companion evidence"
        }
    }
    if ([int64]$buildPhase.process_identity.parent_process_id -ne [int64]$companion.runner_process_id) {
        throw 'D31 V2 build Cargo parent differs from its fresh PowerShell runner'
    }

    return [ordered]@{
        path = $read.snapshot.path
        sha256 = $read.snapshot.sha256
        record_path = $recordSnapshot.path
        record_sha256 = $recordSnapshot.sha256
        run_id = [string]$companion.run_id
        profile_path = [string]$profileReference.path
        profile_sha256 = [string]$profileReference.sha256
        artifact_path = $artifactSnapshot.path
        artifact_sha256 = $artifactSnapshot.sha256
        artifact_bytes = $artifactSnapshot.bytes
        runner_process_id = [int64]$companion.runner_process_id
        status = 'LOCALLY_RECONCILED_ONLY'
        admission_requires_official_deep_validation = $true
    }
}

function Read-D32DownstreamSeederRef {
    param([object]$Reference, [string]$Name, [string[]]$Fields = @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))
    Assert-D32DownstreamExactKeys -Value $Reference -Expected $Fields -Name "$Name reference"
    Assert-D32DownstreamHex -Value $Reference.sha256 -Length 64 -Name "$Name SHA"
    Assert-D32DownstreamHex -Value $Reference.volume_serial_hex -Length 16 -Name "$Name volume identity"
    Assert-D32DownstreamHex -Value $Reference.file_id_hex -Length 32 -Name "$Name file identity"
    Assert-D32DownstreamInteger -Value $Reference.bytes -Name "$Name bytes" -Minimum 1
    $snapshot = Read-D32DownstreamPinnedBytes -Path ([string]$Reference.path) -ExpectedSha256 ([string]$Reference.sha256) -Name $Name -MaximumBytes 268435456
    if ($snapshot.bytes -ne [int64]$Reference.bytes) { throw "$Name current byte length differs from its companion reference" }
    return $snapshot
}

function New-D32DownstreamExecutionPacket {
    param(
        [Parameter(Mandatory = $true)][object]$Pins,
        [Parameter(Mandatory = $true)][string]$ProviderDisposition,
        [AllowNull()][string]$ProviderNotApplicableReason,
        [AllowNull()][object]$Seeder
    )
    $blockers = [System.Collections.Generic.List[string]]::new()
    $blockers.Add('DOWNSTREAM_LAUNCHER_NOT_ADMITTED: this packet tool does not launch children; no downstream owner-bound Trace V2/Job capture executor is included in this patch')
    $blockers.Add('DOWNSTREAM_ENTRY_ADMISSION_NOT_PINNED: any future child-launching entry must use fresh shared PowerShell Module Admission V2 for its exact direct -NoProfile -File operand before module imports')
    $blockers.Add('TRACE_DESCENDANT_POLICY_UNBOUND: this local consumer checks Trace V2 structure/root pins but does not independently bind every descendant image to a candidate-approved child-image set')
    $blockers.Add('OPENED_FILE_ID_EVIDENCE_UNVERIFIED: local artifact/log/report/trace reads verify bytes and SHA only; required opened-handle volume/file IDs need the official native validators')
    $blockers.Add('DOWNSTREAM_ATTEMPT_OWNER_MISSING: this packet/capture contract has no create-new owner marker binding the shared attempt root and all cases to one runner instance, so stale cross-attempt replay is not excluded')
    $blockers.Add('EXACT_CLEAN_HEAD_RECHECK_REQUIRED: no current Git HEAD/cleanliness check is performed before and after each downstream case')
    $blockers.Add('HOST_PROVIDER_READINESS_UNKNOWN: production Host provider readiness/user authorization has no supplied independent safe evidence; all eight Host modes stay blocked')
    if ($null -eq $Seeder) { $blockers.Add('D31_RECOVERY_SEEDER_COMPANION_MISSING: both D31 recovery cases remain blocked until the candidate-bound D32 companion and V2 record are pinned') }
    elseif ($Seeder.status -cne 'LOCALLY_RECONCILED_ONLY' -or $Seeder.admission_requires_official_deep_validation -ne $true) {
        $blockers.Add('D31_RECOVERY_SEEDER_OFFICIAL_VALIDATION_REQUIRED: local companion checks do not replace the shared PowerShell Module Admission V2 validator and official D31 record consumer')
    }
    if ($ProviderDisposition -eq 'UNDECIDED') { $blockers.Add('D29G2_PROVIDER_APPLICABILITY_UNKNOWN: provider cases cannot be counted until applicability is explicitly decided') }
    if ($ProviderDisposition -eq 'APPLICABLE_UNAUTHORIZED') { $blockers.Add('D29G2_USER_AUTHORIZATION_MISSING: applicable provider cases remain NOT RUN and block D32 closure') }

    $d31 = @($script:D32DownstreamD31Cases | ForEach-Object {
        $case = $_
        $testName = [string]$case.name
        $fullTestName = [string]$Pins.inventory.d31_test_names[$testName]
        $isRecovery = [bool]$case.seeder_required
        $caseState = 'BLOCKED_LAUNCHER_NOT_ADMITTED'
        if ($isRecovery -and $null -eq $Seeder) { $caseState = 'BLOCKED_SEEDER_COMPANION_AND_LAUNCHER' }
        $cargoArgs = Get-D32DownstreamD31CargoArgv -ManifestPath (Join-Path $Pins.repository_root $case.manifest) -Feature ([string]$case.feature) -FullTestName $fullTestName
        $seederEnvironment = $null
        if ($isRecovery -and $null -ne $Seeder) {
            $seederEnvironment = [ordered]@{
                D31_RECOVERY_SEEDER_RECORD_PATH = $Seeder.record_path
                D31_RECOVERY_SEEDER_RECORD_SHA256 = $Seeder.record_sha256
                D31_RECOVERY_SEEDER_RUN_ID = $Seeder.run_id
                D32_BUILD_TOOLCHAIN_PROFILE_PATH = $Seeder.profile_path
                D32_EXPECTED_TOOLCHAIN_PROFILE_SHA256 = $Seeder.profile_sha256
                D32_EXPECTED_CANDIDATE_SHA = $Pins.candidate_sha
            }
        }
        [ordered]@{
            ordinal = [array]::IndexOf($script:D32DownstreamD31Cases, $case) + 1
            package = [string]$case.package
            feature = [string]$case.feature
            inventory_category = 'deferred'
            manifest_path = Join-Path $Pins.repository_root $case.manifest
            selected_test_name = $fullTestName
            selector_argv = @('--exact', $fullTestName, '--nocapture')
            cargo_argv = $cargoArgs
            run_environment = [ordered]@{
                D32_EXPECTED_CANDIDATE_SHA = $Pins.candidate_sha
                D32_BUILD_TOOLCHAIN_PROFILE_PATH = $Pins.toolchain_profile.path
                D32_EXPECTED_TOOLCHAIN_PROFILE_SHA256 = $Pins.toolchain_profile.sha256
                additional_case_environment = $case.required_env
            }
            ignored_test = $false
            required_nonsecret_environment = $case.required_env
            seed_companion_required = $isRecovery
            seeder_environment = $seederEnvironment
            seeder_evidence = if ($isRecovery -and $null -ne $Seeder) {
                [ordered]@{ companion_path = $Seeder.path; companion_sha256 = $Seeder.sha256; record_path = $Seeder.record_path; record_sha256 = $Seeder.record_sha256; run_id = $Seeder.run_id; artifact_sha256 = $Seeder.artifact_sha256 }
            } else { $null }
            status = $caseState
            acceptance = 'one exact D31 test is explicitly selected and passed, failed=0, ignored=0; required D31 case environment is set; raw output and Trace V2/Job cleanup evidence pinned; any D31 skip marker blocks'
        }
    })

    $providerStatus = switch ($ProviderDisposition) {
        'NOT_APPLICABLE' { 'N_A_NOT_RUN' }
        'APPLICABLE_USER_AUTHORIZED' { 'BLOCKED_LAUNCHER_NOT_ADMITTED' }
        'APPLICABLE_UNAUTHORIZED' { 'BLOCKED_USER_AUTHORIZATION' }
        default { 'BLOCKED_APPLICABILITY_UNDECIDED' }
    }
    $providerCases = if ($ProviderDisposition -in @('APPLICABLE_USER_AUTHORIZED', 'APPLICABLE_UNAUTHORIZED')) {
        @($script:D32DownstreamProviderCases | ForEach-Object {
            $fullTestName = [string]$Pins.inventory.provider_test_names[[string]$_.name]
            [ordered]@{
                selected_test_name = $fullTestName
                expected_provider_requests = [int]$_.expected_requests
                expected_successful_responses = if ($_.name -ceq 'd29g2_r2_role_matrix') { 1 } else { [int]$_.expected_requests }
                selector_argv = @('--ignored', '--exact', $fullTestName, '--nocapture')
                package = 'vita-agent'
                feature = 'd32-a-test-helper'
                manifest_path = Join-Path $Pins.repository_root 'vita-agent/Cargo.toml'
                cargo_argv = Get-D32DownstreamProviderCargoArgv -ManifestPath (Join-Path $Pins.repository_root 'vita-agent/Cargo.toml') -FullTestName $fullTestName
                required_inputs = @('VITA_D29G2_PROVIDER_ID', 'VITA_D29G2_BASE_URL', 'VITA_D29G2_MODEL', 'VITA_D29G2_API_KEY')
                secret_value_output = 'PROHIBITED; API key must be supplied in memory only by the explicitly authorized caller and is never placed in this packet or evidence'
                secret_policy = 'caller may inject API key only after explicit user authorization; this tool never reads, stores, echoes, or logs values'
                inventory_category = 'ignored'
                status = $providerStatus
                acceptance = 'one exact ignored test passed, failed=0, ignored=0; provider request count equals policy; response and process cleanup evidence pinned'
            }
        })
    }
    else { @() }

    $host = @($script:D32DownstreamHostModes | ForEach-Object {
        $mode = [string]$_
        $expectedTerminal = switch ($mode) {
            'positive' { 'completed' }
            'grant-replay' { 'completed' }
            'cancel-before-revalidation' { 'cancelled' }
            default { 'failed' }
        }
        [ordered]@{
            ordinal = [array]::IndexOf($script:D32DownstreamHostModes, [string]$_) + 1
            mode = [string]$_
            executable = $Pins.host_image.path
            executable_sha256 = $Pins.host_image.sha256
            executable_bytes = $Pins.host_image.bytes
            argv = @([string]$_)
            expected_status = if ($mode -ceq 'positive') { 'EXECUTED' } else { 'DENIED' }
            expected_terminal_phase = $expectedTerminal
            expected_native_evidence_status = if ($mode -ceq 'positive') { 'started_and_exited' } else { 'denied' }
            default_mode_allowed = $false
            success_report_must_have = @('ok=true', 'exact mode', 'mode-specific status and terminal phase', 'trace', 'nativeEvidence.record', 'cleanup', 'stdout JSON exactly equals report file')
            external_capture_must_have = @('candidate/image pins', 'stdout/stderr/report file refs', 'V2 process trace', 'Job close', 'active process count=0', 'debugger thread joined', 'all retained process handles signaled')
            status = 'BLOCKED_HOST_PROVIDER_READINESS_UNKNOWN'
        }
    })
    $orderedSteps = @(
        [ordered]@{
            ordinal = 1
            group = 'D31_REAL_PROCESS'
            seeder_preflight = [ordered]@{
                required_for_cases = @('d31_c_real_process_recovery_canary', 'd31_c_real_process_recovery_revocation_canary')
                run_after = 'PRE_DOWNSTREAM_AGGREGATE_PASS'
                run_before = 'D31 case ordinal 7'
                executor = 'existing D31 seeder producer only; fixed V2 fetch/build command and separate D31-only grant are not launched by this packet'
                companion_status = if ($null -eq $Seeder) { 'BLOCKED_SEEDER_COMPANION_MISSING' } else { 'BLOCKED_OFFICIAL_VALIDATION_REQUIRED' }
            }
            cases = $d31
        },
        [ordered]@{ ordinal = 2; group = 'D29G2_REAL_PROVIDER'; disposition = $ProviderDisposition; not_applicable_reason = $ProviderNotApplicableReason; cases = $providerCases },
        [ordered]@{ ordinal = 3; group = 'D32_HOST_REAL_CANARY'; modes = $host }
    )
    return [ordered]@{
        packet_type = 'D32_DOWNSTREAM_EXECUTION_PACKET_V1'
        gate_authority = 'NONE'
        formal_gate_result = 'NOT PROVIDED'
        candidate_sha = $Pins.candidate_sha
        repository_root = $Pins.repository_root
        exact_sha_recheck_required_before_each_step = $true
        bundle_manifest = $Pins.bundle_manifest
        release_attestation = $Pins.release_attestation
        aggregate_record = $Pins.aggregate
        aggregate_interpretation = 'V8 PRE_DOWNSTREAM_AGGREGATE_PASS only; downstream_gates is deliberately NOT RUN'
        test_inventory_baseline = $Pins.test_inventory_baseline
        seeder_companion = $Seeder
        provider_disposition = $ProviderDisposition
        host_provider_preflight = 'UNKNOWN_BLOCKED; this packet accepts no boolean override or real Host/Codex config path'
        powershell_admission = 'the companion carries the full shared V2 document; this local verifier checks only its bound subset and the official shared validator remains required'
        downstream_steps = $orderedSteps
        blockers = @($blockers.ToArray())
        launch_policy = 'OUTPUT_ONLY: no Cargo, child process, provider request, Host launch, test, build, network, config/credential read, or evidence write occurs'
        reconciliation_note = 'Reconciliation output is local consistency feedback only; it cannot replace official aggregate validation, raw trace review, required negative evidence, Luna High, or Sol closure.'
    }
}

function Assert-D32DownstreamProcessCleanup {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Cleanup, [Parameter(Mandatory = $true)][string]$Name)
    Assert-D32DownstreamExactKeys -Value $Cleanup -Expected $script:D32DownstreamCleanupFields -Name "$Name cleanup"
    $requiredTrue = @('job_close_succeeded', 'process_wait_signaled', 'active_process_count_verified', 'debugger_thread_exited', 'debugger_thread_joined', 'debugger_kill_on_exit_enabled', 'retained_process_handles_signaled', 'debugger_association_query_verified', 'debugger_association_absent', 'cleanup_succeeded')
    foreach ($field in $requiredTrue) {
        if ($Cleanup[$field] -isnot [bool] -or -not $Cleanup[$field]) { throw "$Name cleanup lacks verified '$field'" }
    }
    Assert-D32DownstreamInteger -Value $Cleanup.active_process_count -Name "$Name cleanup active process count"
    Assert-D32DownstreamInteger -Value $Cleanup.retained_process_handle_count -Name "$Name cleanup retained process handle count" -Minimum 1
    Assert-D32DownstreamInteger -Value $Cleanup.debugger_thread_id -Name "$Name cleanup debugger thread id" -Minimum 1
    if ([int64]$Cleanup.active_process_count -ne 0 -or
        $Cleanup.detail -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Cleanup.detail)) {
        throw "$Name cleanup counters or debugger detail are invalid"
    }
    $expectedLaunchMode = 'DedicatedOSDebuggerThread(CreateProcessW(DEBUG_PROCESS|CREATE_SUSPENDED)+DebugSetProcessKillOnExit(TRUE)+ResumeThread+WaitForDebugEvent+ContinueDebugEvent)+EXTENDED_STARTUP_INFO+HANDLE_LIST(stdout/stderr)+AssignProcessToJobObject(KILL_ON_JOB_CLOSE)'
    if ($Cleanup.launch_mode -cne $expectedLaunchMode) { throw "$Name cleanup does not identify the exact approved V2 process capture boundary" }
}

function Assert-D32DownstreamFileReference {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Reference,
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$AllowEmpty
    )
    Assert-D32DownstreamExactKeys -Value $Reference -Expected @('path', 'bytes', 'sha256') -Name "$Name reference"
    Assert-D32DownstreamHex -Value $Reference.sha256 -Length 64 -Name "$Name SHA"
    Assert-D32DownstreamInteger -Value $Reference.bytes -Name "$Name byte count" -Minimum $(if ($AllowEmpty) { 0 } else { 1 })
    $snapshot = Read-D32DownstreamPinnedBytes -Path ([string]$Reference.path) -ExpectedSha256 ([string]$Reference.sha256) -Name $Name -AllowEmpty:$AllowEmpty -MaximumBytes 268435456
    if ($snapshot.bytes -ne [int64]$Reference.bytes) { throw "$Name current byte count differs from its capture reference" }
    return $snapshot
}

function Get-D32DownstreamLastCargoSummary {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$ExpectedSha256, [Parameter(Mandatory = $true)][string]$Name)
    $snapshot = Read-D32DownstreamPinnedBytes -Path $Path -ExpectedSha256 $ExpectedSha256 -Name $Name -MaximumBytes 268435456
    $text = [System.Text.Encoding]::UTF8.GetString($snapshot.content)
    $matches = [regex]::Matches($text, '(?m)^test result: ok\.\s+(\d+) passed; (\d+) failed; (\d+) ignored;')
    if ($matches.Count -eq 0) { throw "$Name has no unambiguous successful Cargo test summary" }
    $last = $matches[$matches.Count - 1]
    return [ordered]@{ passed = [int]$last.Groups[1].Value; failed = [int]$last.Groups[2].Value; ignored = [int]$last.Groups[3].Value }
}

function Assert-D32DownstreamCargoCaseOutput {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$StdoutReference,
        [Parameter(Mandatory = $true)][AllowNull()][object]$StderrReference,
        [Parameter(Mandatory = $true)][AllowNull()][object]$Summary,
        [Parameter(Mandatory = $true)][string]$SelectedTestName,
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$ProviderOutput
    )
    $stdout = Assert-D32DownstreamFileReference -Reference $StdoutReference -Name "$Name stdout"
    $stderr = Assert-D32DownstreamFileReference -Reference $StderrReference -Name "$Name stderr" -AllowEmpty
    $decoder = [System.Text.UTF8Encoding]::new($false, $true)
    try {
        $text = $decoder.GetString($stdout.content) + "`n" + $decoder.GetString($stderr.content)
    }
    catch {
        throw "$Name stdout/stderr is not strict UTF-8"
    }
    Assert-D32DownstreamNoD31SkipMarker -Text $text -Name $Name
    if ($ProviderOutput -and $text -match '(?i)(VITA_D29G2_[A-Z_]*API_KEY\s*[=:]|authorization\s*:\s*bearer\s+\S+|\bapi[_-]?key\s*[=:]\s*\S+)') {
        throw "$Name output appears to disclose provider credential material"
    }
    $summaryMatches = [regex]::Matches($text, '(?m)^test result: ok\.\s+(\d+) passed; (\d+) failed; (\d+) ignored;')
    if ($summaryMatches.Count -eq 0) { throw "$Name raw output has no Cargo test summary" }
    $observed = [System.Collections.Generic.List[object]]::new()
    foreach ($match in $summaryMatches) {
        $observed.Add([ordered]@{ passed = [int]$match.Groups[1].Value; failed = [int]$match.Groups[2].Value; ignored = [int]$match.Groups[3].Value })
    }
    $selectedOutput = [regex]::Matches($text, '(?m)^test ' + [regex]::Escape($SelectedTestName) + '\s+\.\.\. ok\s*$')
    $selectedNonPass = [regex]::Matches($text, '(?m)^test ' + [regex]::Escape($SelectedTestName) + '\s+\.\.\. (?!ok\s*$).+$')
    $passedRows = @($observed | Where-Object { $_.passed -eq 1 -and $_.failed -eq 0 -and $_.ignored -eq 0 })
    $otherRows = @($observed | Where-Object { $_.passed -ne 1 -or $_.failed -ne 0 -or $_.ignored -ne 0 })
    if ($selectedOutput.Count -ne 1 -or $selectedNonPass.Count -ne 0 -or $passedRows.Count -ne 1 -or
        @($otherRows | Where-Object { $_.passed -ne 0 -or $_.failed -ne 0 -or $_.ignored -ne 0 }).Count -ne 0) {
        throw "$Name raw test output does not show exactly one selected passing test and zero failed/ignored tests"
    }
    Assert-D32DownstreamExactKeys -Value $Summary -Expected @('passed', 'failed', 'ignored') -Name "$Name captured Cargo summary"
    foreach ($field in @('passed', 'failed', 'ignored')) { Assert-D32DownstreamInteger -Value $Summary[$field] -Name "$Name summary.$field" }
    if ([int]$Summary.passed -ne 1 -or [int]$Summary.failed -ne 0 -or [int]$Summary.ignored -ne 0) {
        throw "$Name captured summary claims skip/failure or more than one test"
    }
    return [ordered]@{ stdout = $stdout; stderr = $stderr; observed_summary = [ordered]@{ passed = 1; failed = 0; ignored = 0 } }
}

function Assert-D32DownstreamNoD31SkipMarker {
    param([Parameter(Mandatory = $true)][string]$Text, [Parameter(Mandatory = $true)][string]$Name)
    if ($Text -match '(?i)(skipping D31|D31[^\r\n]*(NOT RUN|skipped)|D31[^\r\n]*set D31_[BCD]_REQUIRE_REAL_CANARY)') {
        throw "$Name contains a silent-skip/NOT-RUN marker"
    }
}

function Assert-D32DownstreamProviderOutputEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$CaseName,
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][int]$ExpectedRequests
    )
    $requestValue = $null
    switch ($CaseName) {
        'd29g2_real_provider_smoke' {
            $rows = [regex]::Matches($Text, '(?m)^D29-G2 PASS [^\r\n]+$')
            if ($rows.Count -ne 1 -or $rows[0].Value -notmatch '\bprovider_http_status=200\b' -or
                $rows[0].Value -notmatch '\bcodex_to_vita_requests=1\b' -or
                $rows[0].Value -notmatch '\bvita_to_provider_requests=1\b' -or
                $rows[0].Value -notmatch '\bredirect_followed=NO\b' -or $rows[0].Value -notmatch '\bproxy_used=NO\b' -or
                $rows[0].Value -notmatch '\braw_credential_logged=NO\b' -or $rows[0].Value -notmatch '\braw_credential_persisted=NO\b' -or
                $rows[0].Value -notmatch '\buser_codex=UNTOUCHED\b' -or $rows[0].Value -notmatch '\bthread_manager_final_count=0\b' -or
                $rows[0].Value -notmatch '\blistener=CLOSED/JOINED\b' -or $rows[0].Value -notmatch '\bopenai_account_dependency=NONE\b' -or
                $rows[0].Value -notmatch '\bcodex_login_dependency=NONE\b' -or $rows[0].Value -notmatch '\bexternal_hosts=provider_only\b') {
                throw 'D29-G2 smoke raw output lacks the one successful real-provider evidence row or safe-execution facts'
            }
            $requestValue = [regex]::Match($rows[0].Value, '\bprovider_requests=(\d+)\b')
        }
        'd29g2_r1_minimal_provider_probe' {
            $rows = [regex]::Matches($Text, '(?m)^D29-G2-R1 MINIMAL_PROVIDER_PROBE [^\r\n]+$')
            if ($rows.Count -ne 1 -or $rows[0].Value -notmatch '\bstatus=2\d\d\b' -or
                $rows[0].Value -notmatch '\bvalid_chat_completion=true\b' -or
                $rows[0].Value -notmatch '\braw_credential_logged=NO\b') {
                throw 'D29-G2 R1 raw output lacks the exact valid one-request provider-probe evidence row'
            }
            $requestValue = [regex]::Match($rows[0].Value, '\bprovider_requests=(\d+)\b')
        }
        'd29g2_r2_structural_diagnostic' {
            $rows = [regex]::Matches($Text, '(?m)^D29-G2-R2 STRUCTURAL_DIAGNOSTIC [^\r\n]+$')
            if ($rows.Count -ne 1 -or $rows[0].Value -notmatch '\bstatus=200\b' -or
                $rows[0].Value -notmatch '\braw_response_logged=NO\b') {
                throw 'D29-G2 R2 structural raw output lacks the exact one-request successful diagnostic evidence row'
            }
            $requestValue = [regex]::Match($rows[0].Value, '\bprovider_requests=(\d+)\b')
        }
        'd29g2_r2_role_matrix' {
            $rows = [regex]::Matches($Text, '(?m)^D29-G2-R2 ROLE_MATRIX [^\r\n]+$')
            if ($rows.Count -ne 2 -or $rows[0].Value -notmatch '\broles=system\+user\b' -or
                $rows[0].Value -notmatch '\bstatus=200\b' -or $rows[0].Value -notmatch '\bcode=none\b' -or
                $rows[1].Value -notmatch '\broles=developer\+user\b' -or
                $rows[1].Value -notmatch '\bstatus=400\b' -or $rows[1].Value -notmatch '\bcode=1214\b' -or
                $rows[0].Value -notmatch '\braw_response_logged=NO\b' -or $rows[1].Value -notmatch '\braw_response_logged=NO\b') {
                throw 'D29-G2 R2 role-matrix raw output lacks both exact ordered role/status evidence rows'
            }
            $requestValue = [regex]::Match(($rows | ForEach-Object { $_.Value }) -join "`n", '\bprovider_requests=(\d+)\b')
            if (-not $requestValue.Success) { throw 'D29-G2 R2 role matrix omits per-role provider request counts' }
            $countValues = [regex]::Matches(($rows | ForEach-Object { $_.Value }) -join "`n", '\bprovider_requests=(\d+)\b')
            if ($countValues.Count -ne 2 -or [int]$countValues[0].Groups[1].Value -ne 1 -or [int]$countValues[1].Groups[1].Value -ne 1 -or $ExpectedRequests -ne 2) {
                throw 'D29-G2 R2 role-matrix request counts do not prove exactly two non-retried provider calls'
            }
            return [ordered]@{ requests = 2; successful_responses = 1 }
        }
        default { throw "unknown D29G2 provider-output contract: $CaseName" }
    }
    if (-not $requestValue.Success -or [int]$requestValue.Groups[1].Value -ne $ExpectedRequests) {
        throw "$CaseName raw provider evidence does not report the exact expected request count"
    }
    return [ordered]@{ requests = [int]$requestValue.Groups[1].Value; successful_responses = 1 }
}

function Assert-D32DownstreamNoCredentialLeak {
    param([Parameter(Mandatory = $true)][AllowNull()][object[]]$Snapshots, [Parameter(Mandatory = $true)][string]$Name)
    $decoder = [System.Text.UTF8Encoding]::new($false, $true)
    foreach ($snapshot in $Snapshots) {
        try { $text = $decoder.GetString($snapshot.content) }
        catch { throw "$Name has a non-UTF-8 captured log" }
        if ($text -match '(?i)(VITA_D29G2_[A-Z_]*API_KEY\s*[=:]|authorization\s*:\s*bearer\s+\S+|\bapi[_-]?key\s*[=:]\s*\S+)') {
            throw "$Name captured logs appear to disclose credential material"
        }
    }
}

function Assert-D32DownstreamTraceV2 {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Reference,
        [Parameter(Mandatory = $true)][AllowNull()][object]$Cleanup,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int64]$RunnerProcessId,
        [AllowNull()][string]$ExpectedRootImagePath,
        [AllowNull()][string]$ExpectedRootImageSha256,
        [int64]$ExpectedRootImageBytes = 0,
        [AllowNull()][string]$ExpectedRootImageVolumeSerialHex,
        [AllowNull()][string]$ExpectedRootImageFileIdHex
    )
    $traceSnapshot = $null
    if ($Reference -is [System.Collections.IDictionary] -and $Reference.Contains('record_type')) {
        $trace = $Reference
    }
    else {
        Assert-D32DownstreamExactKeys -Value $Reference -Expected @('version', 'path', 'bytes', 'sha256') -Name "$Name Trace V2 reference"
        if ($Reference.version -isnot [ValueType] -or [int]$Reference.version -ne 2) { throw "$Name process trace reference is not V2" }
        $traceSnapshot = Assert-D32DownstreamFileReference -Reference ([ordered]@{
            path = $Reference.path; bytes = $Reference.bytes; sha256 = $Reference.sha256
        }) -Name "$Name Trace V2"
        $trace = ConvertFrom-D32DownstreamJsonBytes -Bytes $traceSnapshot.content -Name "$Name Trace V2"
    }
    $fields = @(
        'record_type', 'schema_version', 'event_source', 'state', 'block_reason', 'debugger_process_id',
        'uncontinued_create_process_id', 'uncontinued_create_continue_call_count', 'debugger_thread_id',
        'dedicated_debugger_thread', 'debugger_kill_on_exit_enabled', 'root_resumed_after_kill_on_exit',
        'debugger_thread_exited', 'debugger_thread_joined', 'retained_process_handle_count',
        'retained_process_handles_signaled', 'debugger_association_query_verified', 'debugger_association_absent',
        'debugger_creation_filetime', 'debugger_created_at_utc', 'started_at_utc', 'completed_at_utc',
        'debug_event_count', 'process_create_event_count', 'process_exit_event_count', 'process_event_count',
        'thread_create_event_count', 'thread_exit_event_count', 'image_load_event_count',
        'image_unload_event_count', 'exception_event_count', 'debug_string_event_count', 'wait_timeout_count',
        'debug_api_error_count', 'event_chain_complete', 'job_accounting_verified', 'job_total_processes',
        'job_active_processes', 'accounting_consistent', 'injected_interruption', 'process_events', 'processes'
    )
    Assert-D32DownstreamExactKeys -Value $trace -Expected $fields -Name "$Name Trace V2 record"
    if ($trace.record_type -cne 'D32_DEBUG_JOB_PROCESS_TRACE_V2' -or
        $trace.schema_version -isnot [ValueType] -or [int]$trace.schema_version -ne 2 -or
        $trace.event_source -cne 'Win32-WaitForDebugEvent-dedicated-OS-thread' -or
        $trace.state -cne 'COMPLETED' -or $null -ne $trace.block_reason -or
        [int64]$trace.debugger_process_id -ne $RunnerProcessId -or
        [int64]$trace.uncontinued_create_process_id -ne 0 -or
        [int64]$trace.uncontinued_create_continue_call_count -ne 0 -or
        $trace.dedicated_debugger_thread -isnot [bool] -or -not $trace.dedicated_debugger_thread -or
        $trace.debugger_kill_on_exit_enabled -isnot [bool] -or -not $trace.debugger_kill_on_exit_enabled -or
        $trace.root_resumed_after_kill_on_exit -isnot [bool] -or -not $trace.root_resumed_after_kill_on_exit -or
        $trace.debugger_thread_exited -isnot [bool] -or -not $trace.debugger_thread_exited -or
        $trace.debugger_thread_joined -isnot [bool] -or -not $trace.debugger_thread_joined -or
        $trace.retained_process_handles_signaled -isnot [bool] -or -not $trace.retained_process_handles_signaled -or
        $trace.debugger_association_query_verified -isnot [bool] -or -not $trace.debugger_association_query_verified -or
        $trace.debugger_association_absent -isnot [bool] -or -not $trace.debugger_association_absent -or
        $trace.event_chain_complete -isnot [bool] -or -not $trace.event_chain_complete -or
        $trace.job_accounting_verified -isnot [bool] -or -not $trace.job_accounting_verified -or
        $trace.accounting_consistent -isnot [bool] -or -not $trace.accounting_consistent -or
        $trace.injected_interruption -isnot [bool] -or $trace.injected_interruption -or
        $trace.process_events -isnot [array] -or $trace.processes -isnot [array]) {
        throw "$Name Trace V2 is blocked, incomplete, or not bound to its recorded runner process"
    }
    foreach ($field in @('debugger_process_id', 'debugger_thread_id', 'debugger_creation_filetime', 'debug_event_count',
            'process_create_event_count', 'process_exit_event_count', 'process_event_count', 'thread_create_event_count',
            'thread_exit_event_count', 'image_load_event_count', 'image_unload_event_count', 'exception_event_count',
            'debug_string_event_count', 'wait_timeout_count', 'debug_api_error_count', 'retained_process_handle_count',
            'job_total_processes', 'job_active_processes', 'uncontinued_create_process_id', 'uncontinued_create_continue_call_count')) {
        Assert-D32DownstreamInteger -Value $trace[$field] -Name "$Name trace.$field"
    }
    foreach ($field in @('debugger_thread_id', 'debugger_creation_filetime', 'process_create_event_count', 'process_exit_event_count',
            'process_event_count', 'retained_process_handle_count', 'job_total_processes')) {
        Assert-D32DownstreamInteger -Value $trace[$field] -Name "$Name trace.$field" -Minimum 1
    }
    if ($trace.job_active_processes -ne 0 -or $trace.process_create_event_count -ne $trace.process_exit_event_count -or
        $trace.process_event_count -ne ($trace.process_create_event_count + $trace.process_exit_event_count) -or
        $trace.debug_event_count -lt $trace.process_event_count -or
        $trace.job_total_processes -ne $trace.process_create_event_count -or
        $trace.processes.Count -ne $trace.process_create_event_count -or
        $trace.process_events.Count -ne $trace.process_event_count -or
        $trace.retained_process_handle_count -lt ($trace.process_create_event_count + 1) -or
        $trace.debug_event_count -ne ($trace.process_event_count + $trace.thread_create_event_count + $trace.thread_exit_event_count +
            $trace.image_load_event_count + $trace.image_unload_event_count + $trace.exception_event_count + $trace.debug_string_event_count)) {
        throw "$Name Trace V2 Job/process counters are inconsistent or incomplete"
    }
    $eventFields = @('sequence', 'kind', 'process_id', 'parent_process_id', 'creation_filetime', 'parent_creation_filetime', 'exit_code')
    $recordFields = @('process_id', 'parent_process_id', 'creation_filetime', 'parent_creation_filetime', 'image_path', 'bytes', 'sha256',
        'volume_serial_hex', 'file_id_hex', 'allowed_image_reason', 'image_verified', 'exited', 'exit_code', 'create_sequence',
        'exit_sequence', 'created_at_utc', 'exited_at_utc')
    $active = @{}
    $recordsByIdentity = @{}
    $eventIdentities = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($i = 0; $i -lt $trace.process_events.Count; $i++) {
        $event = $trace.process_events[$i]
        Assert-D32DownstreamExactKeys -Value $event -Expected $eventFields -Name "$Name process event[$i]"
        foreach ($field in @('sequence', 'process_id', 'parent_process_id', 'creation_filetime', 'parent_creation_filetime', 'exit_code')) {
            Assert-D32DownstreamInteger -Value $event[$field] -Name "$Name process event[$i].$field"
        }
        if ($event.sequence -ne ($i + 1) -or $event.kind -isnot [string] -or $event.kind -cnotin @('CREATE', 'EXIT') -or
            $event.process_id -le 0 -or $event.parent_process_id -le 0 -or $event.creation_filetime -le 0 -or $event.parent_creation_filetime -le 0) {
            throw "$Name process event[$i] has malformed order or identity"
        }
        $key = "$($event.process_id)|$($event.creation_filetime)"
        if ($event.kind -ceq 'CREATE') {
            if ($event.exit_code -ne 0 -or $active.ContainsKey([string]$event.process_id) -or -not $eventIdentities.Add($key)) {
                throw "$Name CREATE event[$i] contains exit data or reused/duplicate PID identity"
            }
            if ($i -eq 0) {
                if ($event.parent_process_id -ne $trace.debugger_process_id -or $event.parent_creation_filetime -ne $trace.debugger_creation_filetime) {
                    throw "$Name Trace V2 root is not parented by the captured runner"
                }
            }
            elseif (-not $active.ContainsKey([string]$event.parent_process_id) -or
                $active[[string]$event.parent_process_id].creation_filetime -ne $event.parent_creation_filetime) {
                throw "$Name CREATE event[$i] has an unknown or already-exited parent identity"
            }
            $active[[string]$event.process_id] = [ordered]@{
                creation_filetime = [int64]$event.creation_filetime
                parent_process_id = [int64]$event.parent_process_id
                parent_creation_filetime = [int64]$event.parent_creation_filetime
                create_sequence = [int64]$event.sequence
                exit_sequence = 0
                exit_code = 0
            }
        }
        else {
            if (-not $active.ContainsKey([string]$event.process_id)) { throw "$Name EXIT event[$i] has no live CREATE identity" }
            $activeRecord = $active[[string]$event.process_id]
            if ($activeRecord.creation_filetime -ne $event.creation_filetime -or
                $activeRecord.parent_process_id -ne $event.parent_process_id -or
                $activeRecord.parent_creation_filetime -ne $event.parent_creation_filetime) {
                throw "$Name EXIT event[$i] identity differs from its active CREATE"
            }
            $activeRecord.exit_sequence = [int64]$event.sequence
            $activeRecord.exit_code = [int64]$event.exit_code
            $active.Remove([string]$event.process_id)
        }
    }
    if ($active.Count -ne 0) { throw "$Name Trace V2 event ledger leaves live processes" }
    foreach ($record in $trace.processes) {
        Assert-D32DownstreamExactKeys -Value $record -Expected $recordFields -Name "$Name process identity"
        foreach ($field in @('process_id', 'parent_process_id', 'creation_filetime', 'parent_creation_filetime', 'bytes', 'exit_code', 'create_sequence', 'exit_sequence')) {
            Assert-D32DownstreamInteger -Value $record[$field] -Name "$Name process.$field"
        }
        foreach ($field in @('process_id', 'parent_process_id', 'creation_filetime', 'parent_creation_filetime', 'bytes', 'create_sequence', 'exit_sequence')) {
            Assert-D32DownstreamInteger -Value $record[$field] -Name "$Name process.$field" -Minimum 1
        }
        Assert-D32DownstreamHex -Value $record.sha256 -Length 64 -Name "$Name process image SHA"
        Assert-D32DownstreamHex -Value $record.volume_serial_hex -Length 16 -Name "$Name process image volume identity"
        Assert-D32DownstreamHex -Value $record.file_id_hex -Length 32 -Name "$Name process image file identity"
        if ($record.image_path -isnot [string] -or -not [System.IO.Path]::IsPathRooted([string]$record.image_path) -or
            [string]::IsNullOrWhiteSpace([string]$record.allowed_image_reason) -or
            $record.image_verified -isnot [bool] -or -not $record.image_verified -or
            $record.exited -isnot [bool] -or -not $record.exited) {
            throw "$Name process image record is not verified/exited"
        }
        $identity = "$($record.process_id)|$($record.creation_filetime)"
        if (-not $eventIdentities.Contains($identity) -or $recordsByIdentity.ContainsKey($identity)) {
            throw "$Name process table has a duplicate or event-unbound identity"
        }
        $recordsByIdentity[$identity] = $record
        $matchingEvents = @($trace.process_events | Where-Object { $_.process_id -eq $record.process_id -and $_.creation_filetime -eq $record.creation_filetime })
        if ($matchingEvents.Count -ne 2 -or $matchingEvents[0].kind -cne 'CREATE' -or $matchingEvents[1].kind -cne 'EXIT' -or
            $record.create_sequence -ne $matchingEvents[0].sequence -or $record.exit_sequence -ne $matchingEvents[1].sequence -or
            $record.parent_process_id -ne $matchingEvents[0].parent_process_id -or
            $record.parent_creation_filetime -ne $matchingEvents[0].parent_creation_filetime -or
            $record.exit_code -ne $matchingEvents[1].exit_code) {
            throw "$Name process identity record does not reconcile with ordered CREATE/EXIT events"
        }
    }
    if ($recordsByIdentity.Count -ne $trace.process_create_event_count) { throw "$Name Trace V2 process identity table is incomplete" }
    if ($ExpectedRootImagePath) {
        $root = $trace.processes | Where-Object { $_.create_sequence -eq 1 }
        if (@($root).Count -ne 1 -or
            -not (Test-D32DownstreamPathEqual -Left ([string]$root[0].image_path) -Right $ExpectedRootImagePath) -or
            $root[0].sha256 -cne $ExpectedRootImageSha256 -or [int64]$root[0].bytes -ne $ExpectedRootImageBytes) {
            throw "$Name Trace V2 root image differs from the independently pinned executable"
        }
        if (($ExpectedRootImageVolumeSerialHex -and $root[0].volume_serial_hex -cne $ExpectedRootImageVolumeSerialHex) -or
            ($ExpectedRootImageFileIdHex -and $root[0].file_id_hex -cne $ExpectedRootImageFileIdHex)) {
            throw "$Name Trace V2 root image file identity differs from the independently pinned executable"
        }
    }
    if ($null -ne $Cleanup) {
        Assert-D32DownstreamProcessCleanup -Cleanup $Cleanup -Name $Name
        if ([int64]$Cleanup.debugger_thread_id -ne [int64]$trace.debugger_thread_id -or
            [int64]$Cleanup.retained_process_handle_count -ne [int64]$trace.retained_process_handle_count) {
            throw "$Name cleanup record differs from Trace V2 debugger/handle identities"
        }
    }
    foreach ($field in @('debugger_created_at_utc', 'started_at_utc', 'completed_at_utc')) {
        $parsed = [DateTimeOffset]::MinValue
        if ($trace[$field] -isnot [string] -or -not [DateTimeOffset]::TryParse([string]$trace[$field], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed)) {
            throw "$Name trace.$field is not a round-trip timestamp"
        }
    }
    return [ordered]@{ snapshot = $traceSnapshot; document = $trace }
}

function Assert-D32DownstreamCapturedProcess {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Reference,
        [Parameter(Mandatory = $true)][AllowNull()][object]$Cleanup,
        [Parameter(Mandatory = $true)][object]$RunnerProcessId,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ExpectedRootImagePath,
        [Parameter(Mandatory = $true)][string]$ExpectedRootImageSha256,
        [Parameter(Mandatory = $true)][int64]$ExpectedRootImageBytes,
        [AllowNull()][string]$ExpectedRootImageVolumeSerialHex,
        [AllowNull()][string]$ExpectedRootImageFileIdHex
    )
    Assert-D32DownstreamInteger -Value $RunnerProcessId -Name "$Name runner process id" -Minimum 1
    $traceEvidence = Assert-D32DownstreamTraceV2 -Reference $Reference -Cleanup $Cleanup -Name $Name `
        -RunnerProcessId ([int64]$RunnerProcessId) -ExpectedRootImagePath $ExpectedRootImagePath `
        -ExpectedRootImageSha256 $ExpectedRootImageSha256 -ExpectedRootImageBytes $ExpectedRootImageBytes `
        -ExpectedRootImageVolumeSerialHex $ExpectedRootImageVolumeSerialHex -ExpectedRootImageFileIdHex $ExpectedRootImageFileIdHex
    $trace = $traceEvidence.document
    foreach ($process in $trace.processes) {
        $imageName = [System.IO.Path]::GetFileName([string]$process.image_path)
        if ($imageName -match '(?i)^vctip(?:\.exe)?$') { throw "$Name Trace V2 contains prohibited VCTIP" }
        if ($imageName -ieq 'protoc.exe') { throw "$Name Trace V2 contains an ungranted protoc child" }
    }
    $roots = @($trace.processes | Where-Object { $_.create_sequence -eq 1 })
    if ($roots.Count -ne 1 -or [int64]$roots[0].parent_process_id -ne [int64]$RunnerProcessId -or
        [int64]$roots[0].process_id -le 0 -or $roots[0].exit_code -ne 0) {
        throw "$Name Trace V2 root is missing, not parented by the pinned runner, or did not exit successfully"
    }
    return $traceEvidence
}

function Assert-D32DownstreamModeSequence {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Actual, [Parameter(Mandatory = $true)][string[]]$Expected, [Parameter(Mandatory = $true)][string]$Name)
    if ($Actual -isnot [array] -or $Actual.Count -ne $Expected.Count) { throw "$Name does not contain the exact expected number of ordered entries" }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        $actualValue = if ($Actual[$index] -is [System.Collections.IDictionary]) { [string]$Actual[$index].mode } else { [string]$Actual[$index] }
        if ($actualValue -cne $Expected[$index]) { throw "$Name differs from its required order at index $index" }
    }
}

function Assert-D32DownstreamHostEnvelope {
    param([Parameter(Mandatory = $true)][string]$Mode, [Parameter(Mandatory = $true)][AllowNull()][object]$Report)
    Assert-D32DownstreamExactKeys -Value $Report -Expected @('mode', 'status', 'trace', 'nativeEvidence', 'terminalPhase', 'turnError', 'nativeDiagnostic', 'cleanup', 'ok') -Name "Host report $Mode"
    if ($Report.ok -isnot [bool] -or -not $Report.ok -or $Report.mode -isnot [string] -or $Report.mode -cne $Mode) {
        throw "Host report $Mode has ok=false/missing or a wrong mode"
    }
    $expectedStatus = if ($Mode -ceq 'positive') { 'EXECUTED' } else { 'DENIED' }
    if ($Report.status -isnot [string] -or $Report.status -cne $expectedStatus -or
        $Report.terminalPhase -isnot [string] -or
        ($null -ne $Report.turnError -and $Report.turnError -isnot [string]) -or
        $Report.trace -isnot [System.Collections.IDictionary]) {
        throw "Host report $Mode status/terminal/trace envelope does not match the canonical mode"
    }
    $expectedTerminal = switch ($Mode) {
        'positive' { 'completed' }
        'grant-replay' { 'completed' }
        'cancel-before-revalidation' { 'cancelled' }
        default { 'failed' }
    }
    if ($Report.terminalPhase -cne $expectedTerminal) { throw "Host report $Mode has the wrong terminal phase" }
    Assert-D32DownstreamExactKeys -Value $Report.cleanup -Expected @('attempted', 'validated', 'removed', 'unsafeLeft', 'error') -Name "Host report $Mode cleanup"
    if ($Report.cleanup.attempted -isnot [bool] -or -not $Report.cleanup.attempted -or
        $Report.cleanup.validated -isnot [bool] -or -not $Report.cleanup.validated -or
        $Report.cleanup.removed -isnot [bool] -or -not $Report.cleanup.removed -or
        $Report.cleanup.unsafeLeft -isnot [bool] -or $Report.cleanup.unsafeLeft -or $null -ne $Report.cleanup.error) {
        throw "Host report $Mode is missing successful validated cleanup evidence"
    }
}

function Assert-D32DownstreamHostReport {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$ReportPath,
        [Parameter(Mandatory = $true)][string]$ExpectedReportSha256
    )
    $snapshot = Read-D32DownstreamPinnedBytes -Path $ReportPath -ExpectedSha256 $ExpectedReportSha256 -Name "Host report $Mode" -MaximumBytes 4194304
    $report = ConvertFrom-D32DownstreamJsonBytes -Bytes $snapshot.content -Name "Host report $Mode"
    Assert-D32DownstreamHostEnvelope -Mode $Mode -Report $report
    $trace = $report.trace
    Assert-D32DownstreamExactKeys -Value $trace -Expected @(
        'authorityEvaluate', 'confirmationRequired', 'issueGrant', 'revalidateGrant', 'grantRevalidatedAllowed',
        'grantRevalidatedDenied', 'grantDenialCode', 'turnCompleted', 'turnFailed', 'actionCancelled', 'replayChecked',
        'replayDenied', 'replayExactRequestCount', 'replayExactSessionCount', 'replayFirstAllowed', 'replaySecondDenied',
        'replayWireResponses', 'preNativeFenceSeen', 'tamperDenied', 'revokeApplied', 'lifeSwitchApplied',
        'isolatedMigrationApplied', 'exactCapability', 'exactTool', 'exactProfile', 'exactCargoCheck',
        'bindingFieldsValidated', 'nativeEvidenceRunId', 'nativeEvidenceSessionId', 'nativeEvidenceLifeId',
        'nativeEvidenceTaskId', 'nativeEvidenceTurnId', 'nativeEvidenceToolCallId', 'nativeDiagnostic', 'stageTelemetry'
    ) -Name "Host report $Mode trace"
    foreach ($field in @('authorityEvaluate', 'confirmationRequired', 'issueGrant', 'revalidateGrant', 'grantRevalidatedAllowed',
            'grantRevalidatedDenied', 'turnCompleted', 'turnFailed', 'actionCancelled', 'replayExactRequestCount',
            'replayExactSessionCount', 'replayFirstAllowed', 'replaySecondDenied', 'replayWireResponses')) {
        Assert-D32DownstreamInteger -Value $trace[$field] -Name "Host report $Mode trace.$field"
    }
    foreach ($field in @('replayChecked', 'replayDenied', 'preNativeFenceSeen', 'tamperDenied', 'revokeApplied',
            'lifeSwitchApplied', 'isolatedMigrationApplied', 'exactCapability', 'exactTool', 'exactProfile',
            'exactCargoCheck', 'bindingFieldsValidated')) {
        if ($trace[$field] -isnot [bool]) { throw "Host report $Mode trace.$field is not a Boolean" }
    }
    if ($trace.grantDenialCode -isnot [string] -and $null -ne $trace.grantDenialCode) { throw "Host report $Mode trace.grantDenialCode has the wrong type" }
    foreach ($field in @('nativeEvidenceRunId', 'nativeEvidenceSessionId', 'nativeEvidenceLifeId', 'nativeEvidenceTaskId', 'nativeEvidenceTurnId', 'nativeEvidenceToolCallId')) {
        if ($trace[$field] -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$trace[$field])) { throw "Host report $Mode trace.$field is missing" }
    }
    if ($trace.nativeDiagnostic -isnot [System.Collections.IDictionary] -and $null -ne $trace.nativeDiagnostic) {
        throw "Host report $Mode trace.nativeDiagnostic has the wrong type"
    }
    if ($trace.stageTelemetry -isnot [System.Collections.IDictionary]) { throw "Host report $Mode trace.stageTelemetry is missing" }
    Assert-D32DownstreamExactKeys -Value $trace.stageTelemetry -Expected @(
        'layout', 'catalog', 'sandbox', 'actionPrepare', 'scopeAuthority', 'populate', 'confirmationBridge', 'grant',
        'revalidate', 'evidence', 'cleanup', 'bridgeSent', 'bridgeReplied', 'bridgePending', 'bridgePendingActive',
        'bridgeState', 'bridgeDecision', 'bridgeConfirmed', 'bridgeDenied', 'bridgeCancelled', 'bridgeTimedOut', 'bridgeFailed'
    ) -Name "Host report $Mode stage telemetry"
    foreach ($stage in @('layout', 'catalog', 'sandbox', 'actionPrepare', 'scopeAuthority', 'populate', 'confirmationBridge', 'grant', 'revalidate', 'evidence', 'cleanup')) {
        $counters = $trace.stageTelemetry[$stage]
        Assert-D32DownstreamExactKeys -Value $counters -Expected @('started', 'passed', 'denied', 'failed', 'lastFailureCode') -Name "Host report $Mode stage $stage telemetry"
        foreach ($field in @('started', 'passed', 'denied', 'failed')) { Assert-D32DownstreamInteger -Value $counters[$field] -Name "Host report $Mode stage $stage.$field" -Minimum 0 }
        if ($null -ne $counters.lastFailureCode -and $counters.lastFailureCode -isnot [string]) { throw "Host report $Mode stage $stage.lastFailureCode has the wrong type" }
    }
    foreach ($field in @('bridgeSent', 'bridgeReplied', 'bridgePending', 'bridgeConfirmed', 'bridgeDenied', 'bridgeCancelled', 'bridgeTimedOut', 'bridgeFailed')) {
        Assert-D32DownstreamInteger -Value $trace.stageTelemetry[$field] -Name "Host report $Mode stageTelemetry.$field" -Minimum 0
    }
    if ($trace.stageTelemetry.bridgePendingActive -isnot [bool] -or $trace.stageTelemetry.bridgeState -isnot [string] -or
        $trace.stageTelemetry.bridgeDecision -isnot [string]) { throw "Host report $Mode stage bridge state is malformed" }
    $expectedRevalidate = if ($Mode -ceq 'grant-replay') { 2 } else { 1 }
    if ($trace.authorityEvaluate -ne 1 -or $trace.confirmationRequired -ne 1 -or $trace.issueGrant -ne 1 -or
        $trace.revalidateGrant -ne $expectedRevalidate -or $trace.replayWireResponses -ne 1 -or
        -not $trace.preNativeFenceSeen -or -not $trace.exactCapability -or -not $trace.exactTool -or -not $trace.exactProfile -or -not $trace.exactCargoCheck) {
        throw "Host report $Mode common trace counters/bindings are invalid"
    }
    $expectedSeams = [ordered]@{
        revokeApplied = ($Mode -ceq 'revoke-before-revalidation')
        lifeSwitchApplied = ($Mode -ceq 'life-before-revalidation')
        isolatedMigrationApplied = ($Mode -ceq 'migration-before-revalidation')
        tamperDenied = ($Mode -in @('executable-identity-tamper', 'environment-profile-tamper'))
    }
    foreach ($field in $expectedSeams.Keys) {
        if ($trace[$field] -ne [bool]$expectedSeams[$field]) { throw "Host report $Mode has unexpected or missing mode seam '$field'" }
    }
    if ($Mode -ceq 'positive') {
        if ($report.terminalPhase -cne 'completed' -or $null -ne $report.turnError -or
            $trace.grantRevalidatedAllowed -ne 1 -or $trace.grantRevalidatedDenied -ne 0 -or
            $trace.turnCompleted -ne 1 -or $trace.turnFailed -ne 0 -or $null -ne $trace.grantDenialCode -or
            -not $trace.bindingFieldsValidated) { throw 'Host positive mode lacks the exact completed/allowed trace contract' }
    }
    else {
        if ($trace.grantRevalidatedAllowed -ne 0 -or $trace.grantRevalidatedDenied -ne 1 -or
            ($trace.turnCompleted + $trace.turnFailed + $trace.actionCancelled) -ne 1 -or
            [string]::IsNullOrWhiteSpace([string]$trace.grantDenialCode)) { throw "Host report $Mode lacks exact fail-closed denial evidence" }
        $expectedPhase = switch ($Mode) {
            'grant-replay' { 'completed' }
            'cancel-before-revalidation' { 'cancelled' }
            default { 'failed' }
        }
        if ($report.terminalPhase -cne $expectedPhase) { throw "Host report $Mode has the wrong terminal phase" }
        if ($Mode -ceq 'cancel-before-revalidation' -and $trace.actionCancelled -ne 1) { throw 'Host cancellation mode lacks its cancellation acknowledgement' }
        if ($Mode -ceq 'grant-replay') {
            if (-not $trace.replayChecked -or -not $trace.replayDenied -or $trace.replayExactRequestCount -ne 2 -or
                $trace.replayExactSessionCount -ne 2 -or $trace.replayFirstAllowed -ne 1 -or $trace.replaySecondDenied -ne 1) {
                throw 'Host grant-replay mode lacks exact two-request/session denial evidence'
            }
        }
        elseif ($trace.replayExactRequestCount -ne 0 -or $trace.replayExactSessionCount -ne 0 -or
            $trace.replayFirstAllowed -ne 0 -or $trace.replaySecondDenied -ne 0) {
            throw "Host report $Mode contains unexpected replay evidence"
        }
        if ($Mode -ceq 'revoke-before-revalidation' -and -not $trace.revokeApplied) { throw 'Host revoke mode did not apply the revoke seam' }
        if ($Mode -ceq 'life-before-revalidation' -and -not $trace.lifeSwitchApplied) { throw 'Host Life mode did not apply the Life-switch seam' }
        if ($Mode -ceq 'migration-before-revalidation' -and -not $trace.isolatedMigrationApplied) { throw 'Host migration mode did not apply the isolated migration seam' }
        if ($Mode -in @('executable-identity-tamper', 'environment-profile-tamper') -and -not $trace.tamperDenied) { throw "Host report $Mode did not deny the tamper" }
    }

    if ($report.nativeEvidence -isnot [System.Collections.IDictionary]) { throw "Host report $Mode is missing native-evidence binding" }
    Assert-D32DownstreamExactKeys -Value $report.nativeEvidence -Expected @('record', 'sha256', 'identity', 'bytes') -Name "Host report $Mode nativeEvidence"
    Assert-D32DownstreamHex -Value $report.nativeEvidence.sha256 -Length 64 -Name "Host report $Mode native-evidence SHA"
    if ($report.nativeEvidence.record -isnot [System.Collections.IDictionary]) { throw "Host report $Mode native-evidence record is missing" }
    $native = $report.nativeEvidence.record
    $nativeFields = @('version', 'runId', 'sessionId', 'lifeId', 'taskId', 'turnId', 'toolCallId', 'capabilityId', 'programId', 'profileId', 'status', 'processCreated', 'processCreatedCount', 'threadResumed', 'threadResumedCount', 'userCodeStarted', 'userCodeStartedCount', 'processExit', 'processExitVerified', 'processExitCount', 'exitCode', 'processTreeObserved', 'processTreeObservationCount', 'processTreeRemaining', 'processTreeObserverFailed', 'jobTerminationAttempted', 'jobTerminated')
    Assert-D32DownstreamExactKeys -Value $native -Expected $nativeFields -Name "Host report $Mode native-evidence record"
    foreach ($field in @('version', 'processCreatedCount', 'threadResumedCount', 'userCodeStartedCount', 'processExitCount', 'processTreeObservationCount', 'processTreeRemaining')) {
        Assert-D32DownstreamInteger -Value $native[$field] -Name "Host report $Mode nativeEvidence.record.$field"
    }
    foreach ($field in @('processCreated', 'threadResumed', 'userCodeStarted', 'processExit', 'processExitVerified', 'processTreeObserved', 'processTreeObserverFailed', 'jobTerminationAttempted', 'jobTerminated')) {
        if ($native[$field] -isnot [bool]) { throw "Host report $Mode nativeEvidence.record.$field is not a Boolean" }
    }
    foreach ($field in @('runId', 'sessionId', 'lifeId', 'taskId', 'turnId', 'toolCallId', 'capabilityId', 'programId', 'profileId', 'status')) {
        if ($native[$field] -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$native[$field])) { throw "Host report $Mode nativeEvidence.record.$field is missing" }
    }
    if ($native.capabilityId -cne 'vita.process.workspace.cargo_check' -or
        $native.programId -cne 'cargo-check-v1' -or $native.profileId -cne 'd32.workspace.cargo_check.v1') {
        throw "Host report $Mode native-evidence record is not bound to the fixed Cargo capability/program/profile"
    }
    Assert-D32DownstreamInteger -Value $report.nativeEvidence.bytes -Name "Host report $Mode native evidence bytes" -Minimum 1
    $nativeIdentityParts = @()
    if ($report.nativeEvidence.identity -is [string] -and $report.nativeEvidence.identity -cmatch '^[0-9a-f]{8}-[0-9a-f]{16}-[0-9a-f]{16}$') {
        $nativeIdentityParts = ([string]$report.nativeEvidence.identity).Split('-')
    }
    $nativeIdentityBytes = [uint64]0
    if ($nativeIdentityParts.Count -eq 3) { $nativeIdentityBytes = [Convert]::ToUInt64($nativeIdentityParts[2], 16) }
    if ($nativeIdentityParts.Count -ne 3 -or $nativeIdentityBytes -ne [uint64]$report.nativeEvidence.bytes -or
        $native.version -ne 2 -or $native.processTreeRemaining -ne 0 -or $native.processTreeObserverFailed -or
        $trace.nativeEvidenceRunId -cne $native.runId -or $trace.nativeEvidenceSessionId -cne $native.sessionId -or
        $trace.nativeEvidenceLifeId -cne $native.lifeId -or $trace.nativeEvidenceTaskId -cne $native.taskId -or
        $trace.nativeEvidenceTurnId -cne $native.turnId -or $trace.nativeEvidenceToolCallId -cne $native.toolCallId -or
        $native.processCreatedCount -ne [int]([bool]$native.processCreated) -or
        $native.threadResumedCount -ne [int]([bool]$native.threadResumed) -or
        $native.userCodeStartedCount -ne [int]([bool]$native.userCodeStarted) -or
        $native.processExit -ne $native.processExitVerified -or
        $native.processExitCount -ne [int]([bool]$native.processExitVerified) -or
        $native.processTreeObserved -ne ($native.processTreeObservationCount -gt 0)) {
        throw "Host report $Mode native process lifecycle counters are inconsistent or not cleaned"
    }
    if ($Mode -ceq 'positive') {
        if ($native.exitCode -isnot [ValueType] -or $native.exitCode -is [bool] -or
            $native.status -cne 'started_and_exited' -or -not $native.processCreated -or -not $native.threadResumed -or
            -not $native.userCodeStarted -or $native.exitCode -ne 0 -or -not $native.processExitVerified -or
            -not $native.processTreeObserved -or $native.processTreeObservationCount -le 0) {
            throw 'Host positive mode lacks verified process/thread start and zero-exit evidence'
        }
    }
    else {
        if ($native.status -cne 'denied' -or $native.processCreated -or $native.threadResumed -or $native.userCodeStarted -or
            $null -ne $native.exitCode -or $native.processExitVerified -or $native.processTreeObserved -or
            $native.processTreeObservationCount -ne 0 -or $native.jobTerminationAttempted -or $native.jobTerminated) {
            throw "Host negative mode $Mode did not deny before native process creation"
        }
    }
    return [ordered]@{ snapshot = $snapshot; document = $report }
}

function Assert-D32DownstreamEvidencePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $fullPath = Get-D32DownstreamCanonicalPath -Path $Path
    $fullRoot = Get-D32DownstreamCanonicalPath -Path $EvidenceRoot
    $repo = Get-D32DownstreamCanonicalPath -Path $RepositoryRoot
    $rootPrefix = $fullRoot.TrimEnd([char[]]@('\', '/')) + '\'
    $repoPrefix = $repo.TrimEnd([char[]]@('\', '/')) + '\'
    if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($fullRoot, $repo, [StringComparison]::OrdinalIgnoreCase) -or
        $fullRoot.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $repo.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Name is not strictly inside a dedicated external attempt root"
    }
    $rootInfo = [System.IO.DirectoryInfo]::new($fullRoot)
    if (-not $rootInfo.Exists -or ($rootInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'downstream attempt root is absent or reparse-backed'
    }
    return $fullPath
}

function Assert-D32DownstreamCaptureFileReference {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Reference,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [switch]$AllowEmpty
    )
    Assert-D32DownstreamExactKeys -Value $Reference -Expected @('path', 'bytes', 'sha256') -Name "$Name reference"
    $null = Assert-D32DownstreamEvidencePath -Path ([string]$Reference.path) -EvidenceRoot $EvidenceRoot -RepositoryRoot $RepositoryRoot -Name $Name
    return Assert-D32DownstreamFileReference -Reference $Reference -Name $Name -AllowEmpty:$AllowEmpty
}

function Assert-D32DownstreamJsonOutputMatches {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][AllowNull()][object]$ExpectedDocument,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $decoder = [System.Text.UTF8Encoding]::new($false, $true)
    try { $text = $decoder.GetString($Bytes) }
    catch { throw "$Name is not strict UTF-8" }
    if ($text.EndsWith("`r`n", [StringComparison]::Ordinal)) { $line = $text.Substring(0, $text.Length - 2) }
    elseif ($text.EndsWith("`n", [StringComparison]::Ordinal)) { $line = $text.Substring(0, $text.Length - 1) }
    else { throw "$Name has no single JSON line terminator" }
    if ([string]::IsNullOrWhiteSpace($line) -or $line.Contains("`n") -or $line.Contains("`r")) {
        throw "$Name contains extra output beyond its one canonical JSON report line"
    }
    try { $actual = ConvertFrom-Json -InputObject $line -AsHashtable -Depth 100 -ErrorAction Stop }
    catch { throw "$Name is not one valid JSON object line" }
    $actualJson = ConvertTo-Json -InputObject $actual -Depth 100 -Compress
    $expectedJson = ConvertTo-Json -InputObject $ExpectedDocument -Depth 100 -Compress
    if ($actualJson -cne $expectedJson) { throw "$Name JSON line differs from the separately pinned Host report file" }
}

function Test-D32DownstreamCapturePacket {
    param(
        [Parameter(Mandatory = $true)][object]$Pins,
        [Parameter(Mandatory = $true)][string]$CapturePacketPath,
        [Parameter(Mandatory = $true)][string]$ExpectedCapturePacketSha256,
        [Parameter(Mandatory = $true)][string]$ProviderDisposition,
        [AllowNull()][string]$ProviderNotApplicableReason,
        [AllowNull()][object]$Seeder
    )
    $captureRead = Read-D32DownstreamPinnedJson -Path $CapturePacketPath -ExpectedSha256 $ExpectedCapturePacketSha256 -Name 'downstream capture packet' -MaximumBytes 8388608
    $capture = $captureRead.document
    $captureFields = @(
        'schema_version', 'record_type', 'gate_authority', 'candidate_sha', 'source_repo', 'run_id', 'evidence_root',
        'aggregate_record_sha256', 'bundle_manifest_sha256', 'release_attestation_sha256',
        'test_inventory_baseline_sha256', 'toolchain_profile_sha256', 'runner_trace_version',
        'd31_cases', 'provider_disposition', 'provider_authorized_by_user', 'provider_not_applicable_reason',
        'provider_cases', 'host_modes', 'host_provider_readiness'
    )
    Assert-D32DownstreamExactKeys -Value $capture -Expected $captureFields -Name 'downstream capture packet'
    if ($capture.schema_version -isnot [ValueType] -or $capture.schema_version -is [bool] -or [int]$capture.schema_version -ne 1 -or
        $capture.record_type -cne 'D32_DOWNSTREAM_EXECUTION_CAPTURE_V1' -or $capture.gate_authority -cne 'NONE' -or
        $capture.candidate_sha -cne $Pins.candidate_sha -or
        -not (Test-D32DownstreamPathEqual -Left ([string]$capture.source_repo) -Right $Pins.repository_root) -or
        $capture.run_id -isnot [string] -or $capture.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        $capture.aggregate_record_sha256 -cne $Pins.aggregate.sha256 -or
        $capture.bundle_manifest_sha256 -cne $Pins.bundle_manifest.sha256 -or
        $capture.release_attestation_sha256 -cne $Pins.release_attestation.sha256 -or
        $capture.test_inventory_baseline_sha256 -cne $Pins.test_inventory_baseline.sha256 -or
        $capture.toolchain_profile_sha256 -cne $Pins.toolchain_profile.sha256 -or
        $capture.runner_trace_version -isnot [ValueType] -or [int]$capture.runner_trace_version -ne 2) {
        throw 'downstream capture is stale, cross-candidate, cross-bundle/profile, or not tied to Trace V2'
    }
    if ($capture.provider_disposition -cne $ProviderDisposition) {
        throw 'capture provider disposition differs from the explicit caller decision'
    }
    $evidenceRoot = Get-D32DownstreamCanonicalPath -Path ([string]$capture.evidence_root)
    $null = Assert-D32DownstreamEvidencePath -Path $captureRead.snapshot.path -EvidenceRoot $evidenceRoot -RepositoryRoot $Pins.repository_root -Name 'downstream capture packet'
    $evidencePaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void]$evidencePaths.Add($captureRead.snapshot.path)
    $addEvidencePath = {
        param([string]$Path, [string]$Name)
        $full = Assert-D32DownstreamEvidencePath -Path $Path -EvidenceRoot $evidenceRoot -RepositoryRoot $Pins.repository_root -Name $Name
        if (-not $evidencePaths.Add($full)) { throw "$Name aliases another pinned evidence file in this attempt" }
        return $full
    }

    if ($null -ne $Seeder) {
        if (-not (Test-D32DownstreamPathEqual -Left (Split-Path -Parent ([string]$Seeder.path)) -Right $evidenceRoot)) {
            throw 'D31 seeder companion is not a sibling in this exact downstream attempt root'
        }
        foreach ($seedFile in @(
                [ordered]@{ path = $Seeder.path; name = 'D31 seeder companion' },
                [ordered]@{ path = $Seeder.record_path; name = 'D31 seeder V2 record' },
                [ordered]@{ path = $Seeder.artifact_path; name = 'D31 seeder artifact' }
            )) {
            $null = & $addEvidencePath ([string]$seedFile.path) ([string]$seedFile.name)
        }
    }

    if ($capture.d31_cases -isnot [array] -or $capture.d31_cases.Count -ne $script:D32DownstreamD31Cases.Count) {
        throw 'downstream capture must contain all ten D31 cases exactly once and in canonical order'
    }
    $d31Results = [System.Collections.Generic.List[object]]::new()
    $d31EnvironmentNames = @(
        'D32_EXPECTED_CANDIDATE_SHA',
        'D32_BUILD_TOOLCHAIN_PROFILE_PATH',
        'D32_EXPECTED_TOOLCHAIN_PROFILE_SHA256',
        'D31_B_REQUIRE_REAL_CANARY',
        'D31_C_REQUIRE_REAL_CANARY',
        'D31_D_REQUIRE_REAL_CANARY'
    )
    for ($i = 0; $i -lt $script:D32DownstreamD31Cases.Count; $i++) {
        $policy = $script:D32DownstreamD31Cases[$i]
        $case = $capture.d31_cases[$i]
        $caseFields = @(
            'case_name', 'selected_test_name', 'inventory_category', 'exit_code', 'summary',
            'runner_process_id', 'command_argv', 'command_line', 'working_directory', 'root_process_identity',
            'environment', 'required_nonsecret_environment', 'seeder_environment', 'stdout', 'stderr',
            'process_trace', 'process_tree_cleanup', 'seeder_companion_path', 'seeder_companion_sha256',
            'seeder_record_path', 'seeder_record_sha256', 'seeder_run_id'
        )
        Assert-D32DownstreamExactKeys -Value $case -Expected $caseFields -Name "D31 case[$i]"
        $testName = [string]$Pins.inventory.d31_test_names[[string]$policy.name]
        $manifestPath = Join-Path $Pins.repository_root ([string]$policy.manifest)
        $expectedArgv = Get-D32DownstreamD31CargoArgv -ManifestPath $manifestPath -Feature ([string]$policy.feature) -FullTestName $testName
        $expectedCommandLine = ConvertTo-D32DownstreamCommandLine -Arguments (@([string]$Pins.toolchain_profile.cargo.path) + $expectedArgv)
        $expectedEnvironment = [ordered]@{
            D32_EXPECTED_CANDIDATE_SHA = [string]$Pins.candidate_sha
            D32_BUILD_TOOLCHAIN_PROFILE_PATH = [string]$Pins.toolchain_profile.path
            D32_EXPECTED_TOOLCHAIN_PROFILE_SHA256 = [string]$Pins.toolchain_profile.sha256
            D31_B_REQUIRE_REAL_CANARY = $null
            D31_C_REQUIRE_REAL_CANARY = $null
            D31_D_REQUIRE_REAL_CANARY = $null
        }
        foreach ($environmentName in $policy.required_env.Keys) { $expectedEnvironment[$environmentName] = [string]$policy.required_env[$environmentName] }
        if ($case.case_name -cne $policy.name -or $case.selected_test_name -cne $testName -or
            $case.inventory_category -cne 'deferred' -or
            -not (Test-D32DownstreamPathEqual -Left ([string]$case.working_directory) -Right $Pins.repository_root) -or
            $case.command_line -isnot [string] -or $case.command_line -cne $expectedCommandLine) {
            throw "D31 case[$i] is missing, not the exact deferred baseline test, out of order, or failed"
        }
        Assert-D32DownstreamInteger -Value $case.exit_code -Name "D31 case $($policy.name) exit code"
        if ([int]$case.exit_code -ne 0) { throw "D31 case $($policy.name) exited unsuccessfully" }
        Assert-D32DownstreamStringArrayExact -Actual $case.command_argv -Expected $expectedArgv -Name "D31 case $($policy.name) Cargo argv"
        Assert-D32DownstreamExactKeys -Value $case.environment -Expected $d31EnvironmentNames -Name "D31 case[$i] effective pinned environment"
        foreach ($name in $d31EnvironmentNames) {
            if ($case.environment[$name] -cne $expectedEnvironment[$name]) { throw "D31 case $($policy.name) effective environment $name differs from the fixed policy" }
        }
        Assert-D32DownstreamExactKeys -Value $case.required_nonsecret_environment -Expected @($policy.required_env.Keys) -Name "D31 case[$i] required canary environment"
        foreach ($name in $policy.required_env.Keys) {
            if ($case.required_nonsecret_environment[$name] -cne '1' -or $case.environment[$name] -cne '1') {
                throw "D31 case $($policy.name) did not force $name=1"
            }
        }
        Assert-D32DownstreamInteger -Value $case.runner_process_id -Name "D31 case $($policy.name) runner process id" -Minimum 1
        Assert-D32DownstreamD31ProcessIdentityDocument -Identity $case.root_process_identity -Name "D31 case $($policy.name) Cargo root identity"
        if (-not (Test-D32DownstreamPathEqual -Left ([string]$case.root_process_identity.image_path) -Right ([string]$Pins.toolchain_profile.cargo.path)) -or
            [string]$case.root_process_identity.command_line -cne $expectedCommandLine) {
            throw "D31 case $($policy.name) captured Cargo root identity differs from its fixed image/argv"
        }
        $stdoutPath = & $addEvidencePath ([string]$case.stdout.path) "D31 $($policy.name) stdout"
        $stderrPath = & $addEvidencePath ([string]$case.stderr.path) "D31 $($policy.name) stderr"
        $tracePath = & $addEvidencePath ([string]$case.process_trace.path) "D31 $($policy.name) Trace V2"
        if ($case.process_trace.version -isnot [ValueType] -or [int]$case.process_trace.version -ne 2) {
            throw "D31 case $($policy.name) process trace is not V2"
        }
        $case.stdout.path = $stdoutPath
        $case.stderr.path = $stderrPath
        $case.process_trace.path = $tracePath
        $null = Assert-D32DownstreamCargoCaseOutput -StdoutReference $case.stdout -StderrReference $case.stderr -Summary $case.summary -SelectedTestName $testName -Name "D31 case $($policy.name)"
        $traceEvidence = Assert-D32DownstreamCapturedProcess -Reference $case.process_trace -Cleanup $case.process_tree_cleanup -RunnerProcessId $case.runner_process_id -Name "D31 case $($policy.name)" -ExpectedRootImagePath ([string]$Pins.toolchain_profile.cargo.path) -ExpectedRootImageSha256 ([string]$Pins.toolchain_profile.cargo.sha256) -ExpectedRootImageBytes ([int64]$Pins.toolchain_profile.cargo.bytes) -ExpectedRootImageVolumeSerialHex ([string]$Pins.toolchain_profile.cargo.volume_serial_hex) -ExpectedRootImageFileIdHex ([string]$Pins.toolchain_profile.cargo.file_id_hex)
        $root = @($traceEvidence.document.processes | Where-Object { $_.create_sequence -eq 1 })[0]
        Assert-D32DownstreamD31IdentityMatchesTrace -Identity $case.root_process_identity -TraceProcess $root -Name "D31 case $($policy.name) Cargo root"
        if ($policy.seeder_required) {
            if ($null -eq $Seeder) { throw "D31 recovery case $($policy.name) has no validated candidate-bound seeder companion" }
            $expectedSeederEnvironment = [ordered]@{
                D31_RECOVERY_SEEDER_RECORD_PATH = [string]$Seeder.record_path
                D31_RECOVERY_SEEDER_RECORD_SHA256 = [string]$Seeder.record_sha256
                D31_RECOVERY_SEEDER_RUN_ID = [string]$Seeder.run_id
                D32_BUILD_TOOLCHAIN_PROFILE_PATH = [string]$Seeder.profile_path
                D32_EXPECTED_TOOLCHAIN_PROFILE_SHA256 = [string]$Seeder.profile_sha256
                D32_EXPECTED_CANDIDATE_SHA = [string]$Pins.candidate_sha
            }
            Assert-D32DownstreamExactKeys -Value $case.seeder_environment -Expected @($expectedSeederEnvironment.Keys) -Name "D31 recovery case $($policy.name) seeder environment"
            foreach ($name in $expectedSeederEnvironment.Keys) {
                if ($case.seeder_environment[$name] -cne $expectedSeederEnvironment[$name]) { throw "D31 recovery case $($policy.name) has a wrong $name seeder pin" }
            }
            if (-not (Test-D32DownstreamPathEqual -Left ([string]$case.seeder_companion_path) -Right ([string]$Seeder.path)) -or
                $case.seeder_companion_sha256 -cne $Seeder.sha256 -or
                -not (Test-D32DownstreamPathEqual -Left ([string]$case.seeder_record_path) -Right ([string]$Seeder.record_path)) -or
                $case.seeder_record_sha256 -cne $Seeder.record_sha256 -or $case.seeder_run_id -cne $Seeder.run_id) {
                throw "D31 recovery case $($policy.name) is not bound to the exact validated seeder companion, V2 record, and run"
            }
        }
        elseif ($null -ne $case.seeder_environment -or $null -ne $case.seeder_companion_path -or
            $null -ne $case.seeder_companion_sha256 -or $null -ne $case.seeder_record_path -or
            $null -ne $case.seeder_record_sha256 -or $null -ne $case.seeder_run_id) {
            throw "non-recovery D31 case $($policy.name) unexpectedly cites a D31 recovery seeder"
        }
        $d31Results.Add([ordered]@{ case = [string]$policy.name; selected_test_name = $testName; disposition = 'RECONCILED_CAPTURE_ONLY' })
    }

    $providerResults = [System.Collections.Generic.List[object]]::new()
    if ($ProviderDisposition -eq 'APPLICABLE_USER_AUTHORIZED') {
        if ($capture.provider_authorized_by_user -isnot [bool] -or -not $capture.provider_authorized_by_user -or
            $null -ne $capture.provider_not_applicable_reason -or
            $capture.provider_cases -isnot [array] -or $capture.provider_cases.Count -ne $script:D32DownstreamProviderCases.Count) {
            throw 'applicable provider execution lacks explicit Boolean user authorization or all four cases'
        }
        for ($i = 0; $i -lt $script:D32DownstreamProviderCases.Count; $i++) {
            $policy = $script:D32DownstreamProviderCases[$i]
            $case = $capture.provider_cases[$i]
            $caseFields = @(
                'case_name', 'selected_test_name', 'inventory_category', 'exit_code', 'summary', 'runner_process_id',
                'command_argv', 'command_line', 'working_directory', 'root_process_identity', 'provider_environment_names',
                'provider_request_count', 'successful_response_count', 'provider_inputs_injected', 'secret_values_recorded',
                'stdout', 'stderr', 'process_trace', 'process_tree_cleanup'
            )
            Assert-D32DownstreamExactKeys -Value $case -Expected $caseFields -Name "provider case[$i]"
            $testName = [string]$Pins.inventory.provider_test_names[[string]$policy.name]
            $manifestPath = Join-Path $Pins.repository_root 'vita-agent/Cargo.toml'
            $expectedArgv = Get-D32DownstreamProviderCargoArgv -ManifestPath $manifestPath -FullTestName $testName
            $expectedCommandLine = ConvertTo-D32DownstreamCommandLine -Arguments (@([string]$Pins.toolchain_profile.cargo.path) + $expectedArgv)
            $requiredInputs = @('VITA_D29G2_PROVIDER_ID', 'VITA_D29G2_BASE_URL', 'VITA_D29G2_MODEL', 'VITA_D29G2_API_KEY')
            if ($case.case_name -cne $policy.name -or $case.selected_test_name -cne $testName -or
                $case.inventory_category -cne 'ignored' -or
                -not (Test-D32DownstreamPathEqual -Left ([string]$case.working_directory) -Right $Pins.repository_root) -or
                $case.command_line -isnot [string] -or $case.command_line -cne $expectedCommandLine -or
                $case.provider_inputs_injected -isnot [bool] -or -not $case.provider_inputs_injected -or
                $case.secret_values_recorded -isnot [bool] -or $case.secret_values_recorded) {
                throw "provider case $($policy.name) is absent, unauthorized, ignored, failed, or has the wrong request count"
            }
            Assert-D32DownstreamInteger -Value $case.exit_code -Name "provider case $($policy.name) exit code"
            Assert-D32DownstreamInteger -Value $case.provider_request_count -Name "provider case $($policy.name) request count"
            Assert-D32DownstreamInteger -Value $case.successful_response_count -Name "provider case $($policy.name) successful response count"
            $expectedSuccessfulResponses = if ($policy.name -ceq 'd29g2_r2_role_matrix') { 1 } else { [int]$policy.expected_requests }
            if ([int]$case.exit_code -ne 0 -or [int]$case.provider_request_count -ne [int]$policy.expected_requests -or
                [int]$case.successful_response_count -ne $expectedSuccessfulResponses) {
                throw "provider case $($policy.name) has an unsuccessful exit or wrong provider response count"
            }
            Assert-D32DownstreamStringArrayExact -Actual $case.command_argv -Expected $expectedArgv -Name "provider case $($policy.name) Cargo argv"
            Assert-D32DownstreamStringArrayExact -Actual $case.provider_environment_names -Expected $requiredInputs -Name "provider case $($policy.name) injected environment names"
            Assert-D32DownstreamExactKeys -Value $case.summary -Expected @('passed', 'failed', 'ignored') -Name "provider case[$i] summary"
            Assert-D32DownstreamInteger -Value $case.summary.passed -Name "provider case $($policy.name) summary.passed"
            Assert-D32DownstreamInteger -Value $case.summary.failed -Name "provider case $($policy.name) summary.failed"
            Assert-D32DownstreamInteger -Value $case.summary.ignored -Name "provider case $($policy.name) summary.ignored"
            if ([int]$case.summary.passed -ne 1 -or [int]$case.summary.failed -ne 0 -or [int]$case.summary.ignored -ne 0) {
                throw "provider case $($policy.name) did not execute exactly one passing ignored test"
            }
            Assert-D32DownstreamInteger -Value $case.runner_process_id -Name "provider case $($policy.name) runner process id" -Minimum 1
            Assert-D32DownstreamD31ProcessIdentityDocument -Identity $case.root_process_identity -Name "provider case $($policy.name) Cargo root identity"
            if (-not (Test-D32DownstreamPathEqual -Left ([string]$case.root_process_identity.image_path) -Right ([string]$Pins.toolchain_profile.cargo.path)) -or
                [string]$case.root_process_identity.command_line -cne $expectedCommandLine) {
                throw "provider case $($policy.name) Cargo root identity differs from its fixed image/argv"
            }
            $stdoutPath = & $addEvidencePath ([string]$case.stdout.path) "provider $($policy.name) stdout"
            $stderrPath = & $addEvidencePath ([string]$case.stderr.path) "provider $($policy.name) stderr"
            $tracePath = & $addEvidencePath ([string]$case.process_trace.path) "provider $($policy.name) Trace V2"
            if ($case.process_trace.version -isnot [ValueType] -or [int]$case.process_trace.version -ne 2) {
                throw "provider case $($policy.name) process trace is not V2"
            }
            $case.stdout.path = $stdoutPath
            $case.stderr.path = $stderrPath
            $case.process_trace.path = $tracePath
            $providerOutput = Assert-D32DownstreamCargoCaseOutput -StdoutReference $case.stdout -StderrReference $case.stderr -Summary $case.summary -SelectedTestName $testName -Name "provider case $($policy.name)" -ProviderOutput
            $decoder = [System.Text.UTF8Encoding]::new($false, $true)
            $providerOutputText = $decoder.GetString($providerOutput.stdout.content) + "`n" + $decoder.GetString($providerOutput.stderr.content)
            $logSnapshots = @($providerOutput.stdout, $providerOutput.stderr)
            Assert-D32DownstreamNoCredentialLeak -Snapshots $logSnapshots -Name "provider case $($policy.name)"
            $providerOutputFacts = Assert-D32DownstreamProviderOutputEvidence -CaseName $policy.name -Text $providerOutputText -ExpectedRequests ([int]$policy.expected_requests)
            if ([int]$case.provider_request_count -ne [int]$providerOutputFacts.requests -or
                [int]$case.successful_response_count -ne [int]$providerOutputFacts.successful_responses) {
                throw "provider case $($policy.name) caller summary does not match the test-generated raw provider report"
            }
            $traceEvidence = Assert-D32DownstreamCapturedProcess -Reference $case.process_trace -Cleanup $case.process_tree_cleanup -RunnerProcessId $case.runner_process_id -Name "provider case $($policy.name)" -ExpectedRootImagePath ([string]$Pins.toolchain_profile.cargo.path) -ExpectedRootImageSha256 ([string]$Pins.toolchain_profile.cargo.sha256) -ExpectedRootImageBytes ([int64]$Pins.toolchain_profile.cargo.bytes) -ExpectedRootImageVolumeSerialHex ([string]$Pins.toolchain_profile.cargo.volume_serial_hex) -ExpectedRootImageFileIdHex ([string]$Pins.toolchain_profile.cargo.file_id_hex)
            $root = @($traceEvidence.document.processes | Where-Object { $_.create_sequence -eq 1 })[0]
            Assert-D32DownstreamD31IdentityMatchesTrace -Identity $case.root_process_identity -TraceProcess $root -Name "provider case $($policy.name) Cargo root"
            $providerResults.Add([ordered]@{ case = [string]$policy.name; selected_test_name = $testName; requests = [int]$policy.expected_requests; disposition = 'RECONCILED_CAPTURE_ONLY' })
        }
    }
    elseif ($ProviderDisposition -eq 'APPLICABLE_UNAUTHORIZED') {
        if ($capture.provider_authorized_by_user -isnot [bool] -or $capture.provider_authorized_by_user -or
            $null -ne $capture.provider_not_applicable_reason -or
            $capture.provider_cases -isnot [array] -or $capture.provider_cases.Count -ne 0) {
            throw 'unauthorized applicable provider disposition must prove no provider test was launched and no authorization was asserted'
        }
        $providerResults.Add([ordered]@{ disposition = 'BLOCKED_USER_AUTHORIZATION'; provider_cases = 0 })
    }
    elseif ($ProviderDisposition -eq 'NOT_APPLICABLE') {
        if ($capture.provider_authorized_by_user -isnot [bool] -or $capture.provider_authorized_by_user -or
            [string]::IsNullOrWhiteSpace([string]$ProviderNotApplicableReason) -or
            $capture.provider_not_applicable_reason -cne $ProviderNotApplicableReason -or
            $capture.provider_cases -isnot [array] -or $capture.provider_cases.Count -ne 0) {
            throw 'provider N/A requires an explicit rationale, Boolean false authorization state, and no provider attempts'
        }
        Assert-D32DownstreamNonSecretReason -Value $capture.provider_not_applicable_reason -Name 'provider N/A reason'
        $providerResults.Add([ordered]@{ disposition = 'N_A_NOT_RUN'; rationale = $ProviderNotApplicableReason })
    }
    else {
        throw 'provider cases remain BLOCKED unless N/A is justified or explicit user authorization is supplied'
    }

    Assert-D32DownstreamModeSequence -Actual $capture.host_modes -Expected $script:D32DownstreamHostModes -Name 'downstream capture Host mode sequence'
    if ($capture.host_provider_readiness -cne 'UNKNOWN_BLOCKED') {
        throw 'Host provider readiness is not accepted from a caller-supplied status string; independent safe readiness evidence is absent'
    }
    $hostResults = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $script:D32DownstreamHostModes.Count; $i++) {
        $mode = [string]$script:D32DownstreamHostModes[$i]
        $case = $capture.host_modes[$i]
        $caseFields = @(
            'mode', 'mode_argument', 'command_argv', 'command_line', 'working_directory', 'runner_process_id',
            'root_process_identity', 'default_mode_used', 'candidate_sha', 'image_path', 'image_sha256', 'image_bytes',
            'image_volume_serial_hex', 'image_file_id_hex', 'exit_code', 'report', 'stdout', 'stderr',
            'process_trace', 'process_tree_cleanup'
        )
        Assert-D32DownstreamExactKeys -Value $case -Expected $caseFields -Name "Host mode[$i]"
        $expectedArgv = @($mode)
        $expectedCommandLine = ConvertTo-D32DownstreamCommandLine -Arguments (@([string]$Pins.host_image.path) + $expectedArgv)
        if ($case.mode -cne $mode -or $case.mode_argument -cne $mode -or
            $case.default_mode_used -isnot [bool] -or $case.default_mode_used -or
            $case.candidate_sha -cne $Pins.candidate_sha -or
            -not (Test-D32DownstreamPathEqual -Left ([string]$case.image_path) -Right $Pins.host_image.path) -or
            $case.image_sha256 -cne $Pins.host_image.sha256 -or
            [int64]$case.image_bytes -ne [int64]$Pins.host_image.bytes -or
            $case.image_volume_serial_hex -cne $Pins.host_image.volume_serial_hex -or
            $case.image_file_id_hex -cne $Pins.host_image.file_id_hex -or
            $case.command_line -isnot [string] -or $case.command_line -cne $expectedCommandLine -or
            -not (Test-D32DownstreamPathEqual -Left ([string]$case.working_directory) -Right $Pins.repository_root)) {
            throw "Host mode[$i] is out of order or not the exact pinned image/candidate with explicit mode argv and status"
        }
        Assert-D32DownstreamInteger -Value $case.exit_code -Name "Host mode $mode exit code"
        if ([int]$case.exit_code -ne 0) { throw "Host mode $mode exited unsuccessfully" }
        Assert-D32DownstreamStringArrayExact -Actual $case.command_argv -Expected $expectedArgv -Name "Host mode $mode argv"
        Assert-D32DownstreamInteger -Value $case.runner_process_id -Name "Host mode $mode runner process id" -Minimum 1
        Assert-D32DownstreamD31ProcessIdentityDocument -Identity $case.root_process_identity -Name "Host mode $mode process root identity"
        if (-not (Test-D32DownstreamPathEqual -Left ([string]$case.root_process_identity.image_path) -Right $Pins.host_image.path) -or
            [string]$case.root_process_identity.command_line -cne $expectedCommandLine) {
            throw "Host mode $mode root process identity differs from its fixed image/argv"
        }
        Assert-D32DownstreamExactKeys -Value $case.report -Expected @('path', 'bytes', 'sha256') -Name "Host mode $mode report reference"
        $reportPath = & $addEvidencePath ([string]$case.report.path) "Host $mode report"
        $stdoutPath = & $addEvidencePath ([string]$case.stdout.path) "Host $mode stdout"
        $stderrPath = & $addEvidencePath ([string]$case.stderr.path) "Host $mode stderr"
        $tracePath = & $addEvidencePath ([string]$case.process_trace.path) "Host $mode Trace V2"
        $case.report.path = $reportPath
        $case.stdout.path = $stdoutPath
        $case.stderr.path = $stderrPath
        $case.process_trace.path = $tracePath
        if ($case.process_trace.version -isnot [ValueType] -or [int]$case.process_trace.version -ne 2) {
            throw "Host mode $mode process trace is not V2"
        }
        $reportEvidence = Assert-D32DownstreamHostReport -Mode $mode -ReportPath ([string]$case.report.path) -ExpectedReportSha256 ([string]$case.report.sha256)
        if ($reportEvidence.snapshot.bytes -ne [int64]$case.report.bytes) { throw "Host mode $mode report bytes differ from its capture reference" }
        $stdoutSnapshot = Assert-D32DownstreamFileReference -Reference $case.stdout -Name "Host $mode stdout"
        $stderrSnapshot = Assert-D32DownstreamFileReference -Reference $case.stderr -Name "Host $mode stderr" -AllowEmpty
        Assert-D32DownstreamJsonOutputMatches -Bytes $stdoutSnapshot.content -ExpectedDocument $reportEvidence.document -Name "Host $mode stdout report"
        Assert-D32DownstreamNoCredentialLeak -Snapshots @($stdoutSnapshot, $stderrSnapshot) -Name "Host mode $mode"
        $traceEvidence = Assert-D32DownstreamCapturedProcess -Reference $case.process_trace -Cleanup $case.process_tree_cleanup -RunnerProcessId $case.runner_process_id -Name "Host mode $mode" -ExpectedRootImagePath ([string]$Pins.host_image.path) -ExpectedRootImageSha256 ([string]$Pins.host_image.sha256) -ExpectedRootImageBytes ([int64]$Pins.host_image.bytes) -ExpectedRootImageVolumeSerialHex ([string]$Pins.host_image.volume_serial_hex) -ExpectedRootImageFileIdHex ([string]$Pins.host_image.file_id_hex)
        $root = @($traceEvidence.document.processes | Where-Object { $_.create_sequence -eq 1 })[0]
        Assert-D32DownstreamD31IdentityMatchesTrace -Identity $case.root_process_identity -TraceProcess $root -Name "Host mode $mode root"
        $hostResults.Add([ordered]@{ mode = $mode; disposition = 'RECONCILED_CAPTURE_ONLY' })
    }

    $blockers = @(
        'DOWNSTREAM_LAUNCHER_NOT_ADMITTED: no child-launching downstream runner is admitted by this output-only packet script',
        'DOWNSTREAM_ENTRY_ADMISSION_NOT_PINNED: a launching runner needs exact direct -NoProfile -File startup and fresh shared PowerShell Module Admission V2 before imports',
        'TRACE_DESCENDANT_POLICY_UNBOUND: Trace V2 descendant image records are not compared to a separate exact candidate-approved image allowlist here',
        'OPENED_FILE_ID_EVIDENCE_UNVERIFIED: these local file reads verify bytes/SHA but not opened-handle volume/file IDs required by the formal consumers',
        'DOWNSTREAM_ATTEMPT_OWNER_MISSING: capture run_id and evidence_root are caller fields without a create-new owner marker binding every downstream case to one runner attempt',
        'EXACT_CLEAN_HEAD_RECHECK_REQUIRED: this process-free consumer cannot establish clean Git status and exact HEAD before each ordered case',
        'HOST_PROVIDER_READINESS_UNKNOWN: the canary reads production provider configuration; no real configuration was read and no independent user-authorized readiness evidence was supplied',
        'OFFICIAL_GATE_STILL_REQUIRED: shared aggregate/identity/admission consumers, required negative evidence review, Luna High and Sol closure remain outside this local checker'
    )
    if ($null -eq $Seeder) {
        $blockers += 'D31_RECOVERY_SEEDER_COMPANION_MISSING: the two recovery cases cannot be accepted without a pinned successful candidate-bound D31 companion'
    }
    else {
        $blockers += 'D31_RECOVERY_SEEDER_OFFICIAL_VALIDATION_REQUIRED: local companion checks do not invoke the shared PowerShell Module Admission V2 validator or official D31 record consumer'
    }
    if ($ProviderDisposition -eq 'APPLICABLE_USER_AUTHORIZED') {
        $blockers += 'PROVIDER_EXTERNAL_AUTHORIZATION_SCOPE: four provider captures are reconciled only; this checker never injects credentials, reads ambient values, or performs provider requests'
    }
    elseif ($ProviderDisposition -eq 'APPLICABLE_UNAUTHORIZED') {
        $blockers += 'D29G2_USER_AUTHORIZATION_MISSING: applicable provider tests remain NOT RUN and block D32 closure'
    }
    return [ordered]@{
        reconciliation_type = 'D32_DOWNSTREAM_LOCAL_RECONCILIATION_V1'
        gate_authority = 'NONE'
        status = 'RECONCILED_CAPTURE_ONLY'
        exact_pins = [ordered]@{
            candidate_sha = $Pins.candidate_sha
            aggregate_record_sha256 = $Pins.aggregate.sha256
            bundle_manifest_sha256 = $Pins.bundle_manifest.sha256
            release_attestation_sha256 = $Pins.release_attestation.sha256
            test_inventory_baseline_sha256 = $Pins.test_inventory_baseline.sha256
            toolchain_profile_sha256 = $Pins.toolchain_profile.sha256
            capture_packet_sha256 = $captureRead.snapshot.sha256
            attempt_root = $evidenceRoot
        }
        d31_cases = @($d31Results.ToArray())
        provider_disposition = $ProviderDisposition
        provider_cases = @($providerResults.ToArray())
        host_modes = @($hostResults.ToArray())
        downstream_capture_reconciled = $true
        stage_closure_ready = $false
        blockers = $blockers
        note = 'Consistency feedback only; not PASS, not a phase completion claim, and not a substitute for the official exact-SHA D32 evidence gate.'
    }
}
function Assert-D32DownstreamSelfTest {
    param([Parameter(Mandatory = $true)][bool]$Condition, [Parameter(Mandatory = $true)][string]$Name)
    if (-not $Condition) { throw "SELFTEST_FAILED: $Name" }
}

function Invoke-D32DownstreamSelfTest {
    Assert-D32DownstreamSelfTest -Condition ($script:D32DownstreamD31Cases.Count -eq 10) -Name 'complete ten-case D31 list'
    Assert-D32DownstreamSelfTest -Condition ($script:D32DownstreamProviderCases.Count -eq 4) -Name 'complete four-case provider list'
    Assert-D32DownstreamSelfTest -Condition ($script:D32DownstreamHostModes.Count -eq 8) -Name 'complete ordered eight-mode Host list'
    Assert-D32DownstreamSelfTest -Condition ($script:D32DownstreamD31Cases[6].seeder_required -and $script:D32DownstreamD31Cases[7].seeder_required) -Name 'only two recovery cases require the seeder companion'
    Assert-D32DownstreamSelfTest -Condition ($script:D32DownstreamProviderCases[3].expected_requests -eq 2) -Name 'provider role matrix retains exactly two requests'
    Assert-D32DownstreamSelfTest -Condition ($script:D32DownstreamHostModes[0] -ceq 'positive' -and $script:D32DownstreamHostModes[7] -ceq 'environment-profile-tamper') -Name 'Host mode boundaries retain canonical order'
    $d31Argv = Get-D32DownstreamD31CargoArgv -ManifestPath 'E:\repo\src-tauri/Cargo.toml' -Feature 'd32-a-host-canary' -FullTestName 'module::d31_case'
    $providerArgv = Get-D32DownstreamProviderCargoArgv -ManifestPath 'E:\repo\vita-agent/Cargo.toml' -FullTestName 'module::provider_case'
    Assert-D32DownstreamSelfTest -Condition ($d31Argv -notcontains '--ignored' -and $d31Argv -notcontains '--skip' -and
        $d31Argv[-3] -ceq '--exact' -and $d31Argv[-2] -ceq 'module::d31_case') -Name 'D31 cases select their exact deferred test without an ignored filter or skip'
    Assert-D32DownstreamSelfTest -Condition ($providerArgv -contains '--ignored' -and $providerArgv[-3] -ceq '--exact' -and
        $providerArgv[-2] -ceq 'module::provider_case') -Name 'provider selectors explicitly execute their ignored exact test'
    $rejectedD31Skip = $false
    try { Assert-D32DownstreamNoD31SkipMarker -Text 'skipping D31-C process canary; set D31_C_REQUIRE_REAL_CANARY=1' -Name 'fixture D31 stdout' }
    catch { $rejectedD31Skip = $true }
    Assert-D32DownstreamSelfTest -Condition $rejectedD31Skip -Name 'D31 silent skip marker is rejected'
    $roleOutput = @(
        'D29-G2-R2 ROLE_MATRIX roles=system+user status=200 provider_requests=1 code=none raw_response_logged=NO'
        'D29-G2-R2 ROLE_MATRIX roles=developer+user status=400 provider_requests=1 code=1214 raw_response_logged=NO'
    ) -join "`n"
    $roleFacts = Assert-D32DownstreamProviderOutputEvidence -CaseName 'd29g2_r2_role_matrix' -Text $roleOutput -ExpectedRequests 2
    Assert-D32DownstreamSelfTest -Condition ($roleFacts.requests -eq 2 -and $roleFacts.successful_responses -eq 1) -Name 'provider role-matrix output binds two requests and one successful response'
    $rejectedWrongRoleOutput = $false
    try { Assert-D32DownstreamProviderOutputEvidence -CaseName 'd29g2_r2_role_matrix' -Text ($roleOutput -replace 'code=1214', 'code=none') -ExpectedRequests 2 }
    catch { $rejectedWrongRoleOutput = $true }
    Assert-D32DownstreamSelfTest -Condition $rejectedWrongRoleOutput -Name 'provider role-matrix output rejects incorrect negative response evidence'

    $fakePositive = [ordered]@{
        mode = 'positive'; status = 'EXECUTED'; trace = [ordered]@{}; nativeEvidence = [ordered]@{}
        terminalPhase = 'completed'; turnError = $null; nativeDiagnostic = $null
        cleanup = [ordered]@{ attempted = $true; validated = $true; removed = $true; unsafeLeft = $false; error = $null }
        ok = $true
    }
    Assert-D32DownstreamHostEnvelope -Mode 'positive' -Report $fakePositive
    $wrongMode = [ordered]@{}; foreach ($key in $fakePositive.Keys) { $wrongMode[$key] = $fakePositive[$key] }; $wrongMode.mode = 'grant-replay'
    $rejectedWrongMode = $false
    try { Assert-D32DownstreamHostEnvelope -Mode 'positive' -Report $wrongMode } catch { $rejectedWrongMode = $true }
    $wrongStatus = [ordered]@{}; foreach ($key in $fakePositive.Keys) { $wrongStatus[$key] = $fakePositive[$key] }; $wrongStatus.status = 'DENIED'
    $rejectedWrongStatus = $false
    try { Assert-D32DownstreamHostEnvelope -Mode 'positive' -Report $wrongStatus } catch { $rejectedWrongStatus = $true }
    $missingTrace = [ordered]@{}; foreach ($key in $fakePositive.Keys) { if ($key -cne 'trace') { $missingTrace[$key] = $fakePositive[$key] } }
    $rejectedMissingTrace = $false
    try { Assert-D32DownstreamHostEnvelope -Mode 'positive' -Report $missingTrace } catch { $rejectedMissingTrace = $true }
    $missingCleanup = [ordered]@{}; foreach ($key in $fakePositive.Keys) { $missingCleanup[$key] = $fakePositive[$key] }; $missingCleanup.cleanup = [ordered]@{ attempted = $true; validated = $true; removed = $true; unsafeLeft = $false }
    $rejectedMissingCleanup = $false
    try { Assert-D32DownstreamHostEnvelope -Mode 'positive' -Report $missingCleanup } catch { $rejectedMissingCleanup = $true }
    Assert-D32DownstreamSelfTest -Condition ($rejectedWrongMode -and $rejectedWrongStatus -and $rejectedMissingTrace -and $rejectedMissingCleanup) -Name 'ok=true cannot mask wrong mode/status or missing trace/cleanup'
    $wrongOrder = @($script:D32DownstreamHostModes); $wrongOrder[1] = 'positive'
    $rejectedWrongOrder = $false
    try { Assert-D32DownstreamModeSequence -Actual $wrongOrder -Expected $script:D32DownstreamHostModes -Name 'fixture Host mode sequence' } catch { $rejectedWrongOrder = $true }
    Assert-D32DownstreamSelfTest -Condition $rejectedWrongOrder -Name 'wrong Host mode order is rejected'
    return [ordered]@{
        selftest = 'D32_DOWNSTREAM_READINESS_SELFTEST_V1'
        result = 'SELFTEST_ONLY'
        gate_authority = 'NONE'
        cases_checked = 14
        note = 'in-memory policy checks only; no filesystem, process, Cargo, provider, network, module, credential, or gate action'
    }
}

try {
    if ($Action -eq 'SelfTest') {
        Invoke-D32DownstreamSelfTest | ConvertTo-Json -Depth 30 -Compress
        exit 0
    }

    foreach ($requiredName in @('RepositoryRoot', 'CandidateSha', 'AggregateRecordPath', 'ExpectedAggregateRecordSha256', 'BundleManifestPath', 'ExpectedBundleManifestSha256', 'AttestationPath', 'ExpectedAttestationSha256')) {
        if ([string]::IsNullOrWhiteSpace([string](Get-Variable -Name $requiredName -ValueOnly))) { throw "$requiredName is required" }
    }
    $pins = Assert-D32DownstreamAggregateBundlePins -RepositoryRoot $RepositoryRoot -CandidateSha $CandidateSha `
        -AggregateRecordPath $AggregateRecordPath -ExpectedAggregateRecordSha256 $ExpectedAggregateRecordSha256 `
        -BundleManifestPath $BundleManifestPath -ExpectedBundleManifestSha256 $ExpectedBundleManifestSha256 `
        -AttestationPath $AttestationPath -ExpectedAttestationSha256 $ExpectedAttestationSha256

    if ($ProviderDisposition -eq 'NOT_APPLICABLE' -and [string]::IsNullOrWhiteSpace($ProviderNotApplicableReason)) {
        throw 'ProviderNotApplicableReason is required when provider disposition is NOT_APPLICABLE'
    }
    if ($ProviderDisposition -eq 'NOT_APPLICABLE') {
        Assert-D32DownstreamNonSecretReason -Value $ProviderNotApplicableReason -Name 'ProviderNotApplicableReason'
    }
    $seeder = $null
    if (-not [string]::IsNullOrWhiteSpace($SeederCompanionPath) -or -not [string]::IsNullOrWhiteSpace($ExpectedSeederCompanionSha256)) {
        if ([string]::IsNullOrWhiteSpace($SeederCompanionPath) -or [string]::IsNullOrWhiteSpace($ExpectedSeederCompanionSha256)) {
            throw 'Seeder companion path and independent SHA-256 pin must be supplied together'
        }
        $seeder = Assert-D32DownstreamSeederCompanion -RepositoryRoot $pins.repository_root -CandidateSha $CandidateSha `
            -Path $SeederCompanionPath -ExpectedSha256 $ExpectedSeederCompanionSha256 `
            -ExpectedToolchainProfile $pins.toolchain_profile
    }

    if ($Action -eq 'EmitPacket') {
        $packet = New-D32DownstreamExecutionPacket -Pins $pins -ProviderDisposition $ProviderDisposition `
            -ProviderNotApplicableReason $ProviderNotApplicableReason -Seeder $seeder
        $packet | ConvertTo-Json -Depth 50 -Compress
        exit 2
    }

    if ($Action -eq 'ReconcileCapture') {
        if ([string]::IsNullOrWhiteSpace($CapturePacketPath) -or [string]::IsNullOrWhiteSpace($ExpectedCapturePacketSha256)) {
            throw 'CapturePacketPath and ExpectedCapturePacketSha256 are required for ReconcileCapture'
        }
        $result = Test-D32DownstreamCapturePacket -Pins $pins -CapturePacketPath $CapturePacketPath `
            -ExpectedCapturePacketSha256 $ExpectedCapturePacketSha256 -ProviderDisposition $ProviderDisposition `
            -ProviderNotApplicableReason $ProviderNotApplicableReason -Seeder $seeder
        $result | ConvertTo-Json -Depth 50 -Compress
        exit 2
    }
    throw 'unsupported action'
}
catch {
    [ordered]@{
        gate_authority = 'NONE'
        status = 'BLOCKED'
        error = [string]$_.Exception.Message
        note = 'no child process was started and no evidence was modified'
    } | ConvertTo-Json -Depth 10 -Compress | Write-Output
    exit 1
}
