[CmdletBinding()]
param(
    [Alias('Generate')]
    [switch]$GenerateManifest,

    [Alias('Validate')]
    [switch]$ValidateOnly,

    [switch]$SelfTest,

    [switch]$GitProcessSelfTest,

    [Alias('Root')]
    [string]$RepoRoot,

    [Alias('ProvenancePath', 'TargetManifest')]
    [string]$ManifestPath,

    [Alias('ReleaseImage')]
    [string]$ImagePath,

    [Alias('BundleManifest')]
    [string]$BundleManifestPath,

    [string]$AttestationPath,

    [switch]$GenerateBundle,

    [switch]$GenerateAggregateRecord,

    [switch]$LibraryOnly,

    [Parameter(DontShow = $true)]
    [switch]$Phase0DependencyLibraryOnly,

    [string]$EvidenceRoot,

    [string]$Phase0RecordPath,

    [string]$Phase0RecordSha256,

    [string]$AggregateRecordPath,

    [string]$AggregateRecordSha256,

    [string]$ToolchainProfilePath,

    [string]$ExpectedToolchainProfileSha256,

    [Alias('FixtureManifest')]
    [string]$FixtureManifestPath,

    [Alias('CandidateSha', 'ExactSha')]
    [string]$ExpectedSha,

    [Alias('Base', 'BaseCommit')]
    [string]$BaseSha,

    [Alias('MergeBase', 'ExpectedMergeBase')]
    [string]$MergeBaseSha,

    [Alias('OutputRoot', 'LogRoot')]
    [string]$RunOutputRoot,

    # Git is never resolved from PATH for a validation run.  The caller must
    # supply the exact local executable and its expected SHA-256.  This script
    # performs only advisory path/hash/identity checks; Host's retained-handle
    # Git parser remains the security authority.
    [string]$TrustedGitPath,

    [string]$TrustedGitSha256,

    [string[]]$RequestedModes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:D32PreflightGitCaptureModule = $null
$script:D32GitCaptureContext = $null
$script:D32LastPreflightGitCapture = $null
. (Join-Path $PSScriptRoot 'd32-build-toolchain-profile.ps1')
if ($Phase0DependencyLibraryOnly -and -not $LibraryOnly) {
    throw 'PHASE0_DEPENDENCY_IMPORT_INVALID: dependency-only import requires -LibraryOnly'
}
if (-not $Phase0DependencyLibraryOnly) {
    . (Join-Path $PSScriptRoot 'd32-phase0-matrix.ps1') -Phase0LibraryOnly
}

# This is the exact D32-A Host mode spelling.  Do not add aliases here: the
# preflight is deliberately the place where mode drift is reported before an
# expensive canary is started.
$script:D32CanonicalModes = @(
    'positive',
    'grant-replay',
    'revoke-before-revalidation',
    'life-before-revalidation',
    'cancel-before-revalidation',
    'migration-before-revalidation',
    'executable-identity-tamper',
    'environment-profile-tamper'
)

$script:D32RequiredProvenanceFields = @(
    'candidate_sha',
    'source_repo',
    'image_path',
    'image_sha256',
    'git_status',
    'build_profile',
    'build_command'
)

$script:D32BuildCommand = 'cargo build --manifest-path vita-agent/Cargo.toml --release --locked --bin vita-agent --target-dir vita-agent/target'
$script:D32ReleaseBuildCommands = @(
    [ordered]@{
        name = 'vita-agent-release'
        command = 'cargo build --manifest-path vita-agent/Cargo.toml --release --locked --bin vita-agent --target-dir vita-agent/target'
        arguments = @('build', '--manifest-path', 'vita-agent/Cargo.toml', '--release', '--locked', '--bin', 'vita-agent', '--target-dir', 'vita-agent/target')
    },
    [ordered]@{
        name = 'tauri-host-release'
        command = 'cargo build --manifest-path src-tauri/Cargo.toml --release --locked --features d32-a-host-canary --bin d32a-production-canary-host --lib --target-dir src-tauri/target'
        arguments = @('build', '--manifest-path', 'src-tauri/Cargo.toml', '--release', '--locked', '--features', 'd32-a-host-canary', '--bin', 'd32a-production-canary-host', '--lib', '--target-dir', 'src-tauri/target')
    }
)
$script:D32BundleSchemaVersion = 1
$script:D32AttestationSchemaVersion = 3
$script:D32PostBundleAggregateSchemaVersion = 2
$script:D32PostBundleAggregateRecordName = 'D32-POST-BUNDLE-AGGREGATE.json'
$script:D32PostBundleAggregateRecordType = 'D32_POST_BUNDLE_AGGREGATE_RECORD_V2'
$script:D32PostBundleAggregateScope = 'PRE_DOWNSTREAM_LOCAL_SCOPE'
$script:D32BundleDirectoryName = 'd32-gate-bundle'
$script:D32BundleManifestName = 'BUNDLE-MANIFEST.json'
$script:D32AttestationName = 'D32-RELEASE-ATTESTATION.json'
$script:D32GitOutputLimit = 4096
$script:D32GitTimeoutMilliseconds = 120000
$script:D32SecurityClassification = [ordered]@{
    advisory_only                   = $true
    host_official_preflight_required = $true
    git_image_validation             = 'path/hash/identity revalidation; not equivalent to a retained handle'
    host_security_authority         = 'Host official preflight and retained-handle Git parser'
}
$script:D32BundleArtifactNames = @(
    'vita-agent.exe',
    'd32a-production-canary-host.exe',
    'digital_life_lib.dll'
)
$script:D32BundleSourceRelativePaths = [ordered]@{
    'vita-agent.exe' = 'vita-agent\target\release\vita-agent.exe'
    'd32a-production-canary-host.exe' = 'src-tauri\target\release\d32a-production-canary-host.exe'
    'digital_life_lib.dll' = 'src-tauri\target\release\digital_life_lib.dll'
}
$script:D32FixtureSchemaVersion = 3
$script:D32FixtureProcessTreePolicy = 'native Job Object kill-on-close, then verify every captured identity and relevant descendant'
$script:D32FixtureSpecs = @(
    [ordered]@{
        phase = 1
        name = 'd29h1-authority-fixture'
        project = 'src-tauri'
        manifest = 'src-tauri\Cargo.toml'
        binary = 'd29h1-authority-fixture'
        features = @('d29-h1-host-fixture')
        artifact = 'src-tauri\target\debug\d29h1-authority-fixture.exe'
    },
    [ordered]@{
        phase = 2
        name = 'd29h7-authority-fixture'
        project = 'src-tauri'
        manifest = 'src-tauri\Cargo.toml'
        binary = 'd29h7-authority-fixture'
        features = @('d29-h7-host-fixture')
        artifact = 'src-tauri\target\debug\d29h7-authority-fixture.exe'
    },
    [ordered]@{
        phase = 3
        name = 'd29h7-process-fixture'
        project = 'vita-agent'
        manifest = 'vita-agent\Cargo.toml'
        binary = 'd29h7-process-fixture'
        features = @()
        artifact = 'vita-agent\target\debug\d29h7-process-fixture.exe'
    },
    [ordered]@{
        phase = 4
        name = 'd29h7-git-helper-fixture'
        project = 'vita-agent'
        manifest = 'vita-agent\Cargo.toml'
        binary = 'd29h7-git-helper-fixture'
        features = @('d29-h7-test-helper')
        artifact = 'vita-agent\target\debug\d29h7-git-helper-fixture.exe'
    },
    [ordered]@{
        phase = 5
        name = 'd32a-sandbox-fixture'
        project = 'vita-agent'
        manifest = 'vita-agent\Cargo.toml'
        binary = 'd32a-sandbox-fixture'
        features = @('d32-a-test-helper')
        artifact = 'vita-agent\target\debug\d32a-sandbox-fixture.exe'
    }
)

function New-D32FindingList {
    return ,(New-Object System.Collections.ArrayList)
}

function Add-D32Finding {
    param(
        [AllowEmptyCollection()][System.Collections.ArrayList]$Findings,
        [ValidateSet('PASS', 'INFO', 'ERROR')]
        [string]$Severity,
        [string]$Check,
        [string]$Message
    )

    [void]$Findings.Add([PSCustomObject]@{
            Severity = $Severity
            Check    = $Check
            Message  = $Message
        })
}

function Test-D32Windows {
    return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Test-D32SupportedPowerShellVersion {
    param([AllowNull()][Version]$Version)

    return $null -ne $Version -and $Version -ge [Version]'7.5.0'
}

function ConvertTo-D32ExtendedPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $normalized = $Path -replace '/', '\'
    if (-not (Test-D32Windows)) {
        return $normalized
    }
    if ($normalized.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        return $normalized
    }
    if ($normalized.StartsWith('\\', [StringComparison]::Ordinal)) {
        return ('\\?\UNC\' + $normalized.TrimStart('\'))
    }
    if ($normalized.Length -ge 2 -and $normalized[1] -eq ':') {
        return ('\\?\' + $normalized)
    }
    return ('\\?\' + $normalized)
}

function Get-D32AbsolutePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $full = [System.IO.Path]::GetFullPath($Path)
    }
    catch {
        $full = $Path
    }
    return ConvertTo-D32ExtendedPath -Path $full
}

function Get-D32CanonicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = @(Resolve-Path -LiteralPath $Path -ErrorAction Stop)
    if ($resolved.Count -ne 1) {
        throw "path resolved to an unexpected number of entries: $Path"
    }
    return ConvertTo-D32ExtendedPath -Path $resolved[0].ProviderPath
}

function Get-D32RustRepositoryPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    # d32_candidate_release_image has an intentional asymmetry: Rust builds
    # repository_root from CARGO_MANIFEST_DIR and compares source_repo as that
    # ordinary absolute PathBuf string, while the release image goes through
    # fs::canonicalize and therefore uses Windows' extended \\?\ form.  Keep
    # this helper separate from Get-D32CanonicalPath so preflight mirrors the
    # frozen parser instead of inventing a stronger (and incompatible) schema.
    $absolute = Get-D32AbsolutePath -Path $Path
    if (Test-D32Windows) {
        if ($absolute.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
            return ('\\' + $absolute.Substring(8))
        }
        if ($absolute.StartsWith('\\?\', [StringComparison]::Ordinal)) {
            return $absolute.Substring(4)
        }
    }
    return $absolute
}

function Test-D32PathEqual {
    param(
        [AllowNull()][string]$Left,
        [AllowNull()][string]$Right
    )

    if ($null -eq $Left -or $null -eq $Right) {
        return $false
    }
    $comparison = if (Test-D32Windows) {
        [StringComparison]::OrdinalIgnoreCase
    }
    else {
        [StringComparison]::Ordinal
    }
    return [String]::Equals($Left, $Right, $comparison)
}

function Test-D32PathInside {
    param(
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $childValue = $Child.TrimEnd('\')
    $parentValue = $Parent.TrimEnd('\')
    if (Test-D32PathEqual -Left $childValue -Right $parentValue) {
        return $true
    }
    $prefix = $parentValue + '\'
    $comparison = if (Test-D32Windows) {
        [StringComparison]::OrdinalIgnoreCase
    }
    else {
        [StringComparison]::Ordinal
    }
    return $childValue.StartsWith($prefix, $comparison)
}

function Get-D32JsonProperty {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return ,$property.Value
}

function Test-D32JsonProperty {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Object) {
        return $false
    }
    return $null -ne $Object.PSObject.Properties[$Name]
}

function Remove-D32JsonProperty {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "cannot remove missing JSON property: $Name"
    }
    [void]$Object.PSObject.Properties.Remove($Name)
}

function New-D32FixtureSchemaField {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('string', 'bool', 'u32', 'i32', 'u64', 'f64', 'object', 'array')]
        [string]$Type,
        [switch]$Nullable,
        [switch]$NonEmpty,
        [AllowNull()][object]$Fields,
        [AllowNull()][object]$Items
    )

    $field = [ordered]@{
        type      = $Type
        nullable  = [bool]$Nullable
        non_empty = [bool]$NonEmpty
    }
    if ($PSBoundParameters.ContainsKey('Fields')) {
        $field.fields = $Fields
    }
    if ($PSBoundParameters.ContainsKey('Items')) {
        $field.items = $Items
    }
    return $field
}

function Get-D32ExactJsonProperty {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }
    return @($Object.PSObject.Properties | Where-Object { $_.Name -ceq $Name } | Select-Object -First 1)
}

function Test-D32FixtureIntegerValue {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][decimal]$Minimum,
        [Parameter(Mandatory = $true)][decimal]$Maximum
    )

    if ($null -eq $Value -or $Value -is [bool]) {
        return $false
    }
    $integralTypes = @(
        [byte], [sbyte], [uint16], [int16], [uint32], [int32],
        [uint64], [int64]
    )
    if ($integralTypes -notcontains $Value.GetType()) {
        return $false
    }
    try {
        $number = [decimal]$Value
    }
    catch {
        return $false
    }
    return $number -ge $Minimum -and $number -le $Maximum
}

function Test-D32FixtureScalarType {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string]$Type
    )

    switch ($Type) {
        'string' { return $Value -is [string] }
        'bool' { return $Value -is [bool] }
        'u32' { return Test-D32FixtureIntegerValue -Value $Value -Minimum ([decimal]0) -Maximum ([decimal]4294967295) }
        'i32' { return Test-D32FixtureIntegerValue -Value $Value -Minimum ([decimal]-2147483648) -Maximum ([decimal]2147483647) }
        'u64' {
            return Test-D32FixtureIntegerValue -Value $Value -Minimum ([decimal]0) -Maximum ([decimal]::Parse('18446744073709551615'))
        }
        'f64' {
            if ($null -eq $Value -or $Value -is [bool]) {
                return $false
            }
            $floatingTypes = @([single], [double], [decimal], [byte], [sbyte], [uint16], [int16], [uint32], [int32], [uint64], [int64])
            if ($floatingTypes -notcontains $Value.GetType()) {
                return $false
            }
            try {
                $number = [double]$Value
                return -not [double]::IsNaN($number) -and -not [double]::IsInfinity($number)
            }
            catch {
                return $false
            }
        }
        default { return $false }
    }
}

function Test-D32FixtureSchemaObject {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][object]$Schema,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    if ($null -eq $Object -or $Object -is [Array] -or $Object -is [string]) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.schema' -Message "$Path must be an object"
        return
    }

    $propertyNames = @($Object.PSObject.Properties.Name)
    foreach ($propertyName in $propertyNames) {
        if (@($Schema.Keys | Where-Object { $_ -ceq $propertyName }).Count -eq 0) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.schema' -Message "$Path.$propertyName is an unknown field"
        }
    }
    foreach ($fieldName in @($Schema.Keys)) {
        $field = $Schema[$fieldName]
        $property = Get-D32ExactJsonProperty -Object $Object -Name $fieldName
        if ($null -eq $property) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.schema' -Message "$Path.$fieldName is required"
            continue
        }
        $value = $property.Value
        if ($null -eq $value) {
            if (-not [bool]$field.nullable) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.schema' -Message "$Path.$fieldName cannot be null"
            }
            continue
        }
        switch ($field.type) {
            'object' {
                Test-D32FixtureSchemaObject -Object $value -Schema $field.fields -Path "$Path.$fieldName" -Findings $Findings
            }
            'array' {
                if ($value -isnot [Array]) {
                    Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.schema' -Message "$Path.$fieldName must be an array"
                    continue
                }
                $index = 0
                foreach ($item in $value) {
                    $itemPath = "$Path.$fieldName[$index]"
                    if ($null -eq $item) {
                        if (-not [bool]$field.items.nullable) {
                            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.schema' -Message "$itemPath cannot be null"
                        }
                    }
                    elseif ($field.items.type -eq 'object') {
                        Test-D32FixtureSchemaObject -Object $item -Schema $field.items.fields -Path $itemPath -Findings $Findings
                    }
                    elseif (-not (Test-D32FixtureScalarType -Value $item -Type $field.items.type)) {
                        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.schema' -Message "$itemPath has invalid type; expected $($field.items.type)"
                    }
                    $index++
                }
            }
            default {
                if (-not (Test-D32FixtureScalarType -Value $value -Type $field.type)) {
                    Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.schema' -Message "$Path.$fieldName has invalid type; expected $($field.type)"
                }
                elseif ([bool]$field.non_empty -and [String]::IsNullOrWhiteSpace([string]$value)) {
                    Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.schema' -Message "$Path.$fieldName must not be empty"
                }
            }
        }
    }
}

$script:D32FixtureIdentitySchema = [ordered]@{
    process_id        = New-D32FixtureSchemaField -Type 'u32'
    parent_process_id = New-D32FixtureSchemaField -Type 'u32' -Nullable
    name              = New-D32FixtureSchemaField -Type 'string' -Nullable
    creation_date     = New-D32FixtureSchemaField -Type 'string' -Nullable
    command_line      = New-D32FixtureSchemaField -Type 'string' -Nullable
    observed_at_utc   = New-D32FixtureSchemaField -Type 'string'
    identity_verified = New-D32FixtureSchemaField -Type 'bool'
}
$script:D32FixtureNativeCleanupSchema = [ordered]@{
    job_terminate_call_succeeded       = New-D32FixtureSchemaField -Type 'bool'
    job_terminate_last_error           = New-D32FixtureSchemaField -Type 'i32'
    process_was_already_signaled      = New-D32FixtureSchemaField -Type 'bool'
    process_wait_signaled              = New-D32FixtureSchemaField -Type 'bool'
    job_active_process_count_verified  = New-D32FixtureSchemaField -Type 'bool'
    job_active_process_count           = New-D32FixtureSchemaField -Type 'u32'
    job_active_process_count_last_error = New-D32FixtureSchemaField -Type 'i32'
    job_close_succeeded                = New-D32FixtureSchemaField -Type 'bool'
    cleanup_succeeded                  = New-D32FixtureSchemaField -Type 'bool'
    already_closed                     = New-D32FixtureSchemaField -Type 'bool'
    detail                             = New-D32FixtureSchemaField -Type 'string'
}
$script:D32FixtureReapSchema = [ordered]@{
    process_ids        = New-D32FixtureSchemaField -Type 'array' -Items (New-D32FixtureSchemaField -Type 'u32')
    verified_at_utc    = New-D32FixtureSchemaField -Type 'string' -NonEmpty
    residual_identities = New-D32FixtureSchemaField -Type 'array' -Items (New-D32FixtureSchemaField -Type 'object' -Fields $script:D32FixtureIdentitySchema)
    native_cleanup     = New-D32FixtureSchemaField -Type 'object' -Nullable -Fields $script:D32FixtureNativeCleanupSchema
    kill_output        = New-D32FixtureSchemaField -Type 'array' -Items (New-D32FixtureSchemaField -Type 'string')
}
$script:D32FixtureArtifactSchema = [ordered]@{
    path   = New-D32FixtureSchemaField -Type 'string'
    bytes  = New-D32FixtureSchemaField -Type 'u64'
    sha256 = New-D32FixtureSchemaField -Type 'string'
}
$script:D32FixtureRecordSchema = [ordered]@{
    phase                         = New-D32FixtureSchemaField -Type 'u32'
    name                          = New-D32FixtureSchemaField -Type 'string'
    project                       = New-D32FixtureSchemaField -Type 'string'
    binary                        = New-D32FixtureSchemaField -Type 'string'
    manifest_path                 = New-D32FixtureSchemaField -Type 'string'
    features                      = New-D32FixtureSchemaField -Type 'array' -Items (New-D32FixtureSchemaField -Type 'string')
    command                       = New-D32FixtureSchemaField -Type 'string'
    status                        = New-D32FixtureSchemaField -Type 'string'
    exit_code                     = New-D32FixtureSchemaField -Type 'i32' -Nullable
    pid                           = New-D32FixtureSchemaField -Type 'u32' -Nullable
    descendant_pids               = New-D32FixtureSchemaField -Type 'array' -Items (New-D32FixtureSchemaField -Type 'u32')
    root_identity                 = New-D32FixtureSchemaField -Type 'object' -Nullable -Fields $script:D32FixtureIdentitySchema
    descendant_identities         = New-D32FixtureSchemaField -Type 'array' -Items (New-D32FixtureSchemaField -Type 'object' -Fields $script:D32FixtureIdentitySchema)
    residual_descendant_identities = New-D32FixtureSchemaField -Type 'array' -Items (New-D32FixtureSchemaField -Type 'object' -Fields $script:D32FixtureIdentitySchema)
    reap                          = New-D32FixtureSchemaField -Type 'object' -Nullable -Fields $script:D32FixtureReapSchema
    elapsed_ms                    = New-D32FixtureSchemaField -Type 'f64' -Nullable
    phase_log                     = New-D32FixtureSchemaField -Type 'string' -NonEmpty
    stdout_log                    = New-D32FixtureSchemaField -Type 'string' -NonEmpty
    stderr_log                    = New-D32FixtureSchemaField -Type 'string' -NonEmpty
    error                         = New-D32FixtureSchemaField -Type 'string' -Nullable
    artifact                      = New-D32FixtureSchemaField -Type 'object' -Nullable -Fields $script:D32FixtureArtifactSchema
}
$script:D32FixtureBuildPolicySchema = [ordered]@{
    timeout_seconds             = New-D32FixtureSchemaField -Type 'u64'
    cargo_build_jobs            = New-D32FixtureSchemaField -Type 'u64'
    nested_builds               = New-D32FixtureSchemaField -Type 'bool'
    process_tree_timeout_action = New-D32FixtureSchemaField -Type 'string'
}
$script:D32FixtureEnvironmentSchema = [ordered]@{
    original_userprofile = New-D32FixtureSchemaField -Type 'string' -NonEmpty
    codex_home           = New-D32FixtureSchemaField -Type 'string' -NonEmpty
    userprofile          = New-D32FixtureSchemaField -Type 'string' -NonEmpty
    cargo_home           = New-D32FixtureSchemaField -Type 'string' -NonEmpty
    rustup_home          = New-D32FixtureSchemaField -Type 'string' -NonEmpty
    rustup_toolchain     = New-D32FixtureSchemaField -Type 'string' -Nullable
}
$script:D32FixtureSchema = [ordered]@{
    schema_version       = New-D32FixtureSchemaField -Type 'u32'
    candidate_sha        = New-D32FixtureSchemaField -Type 'string'
    source_repo          = New-D32FixtureSchemaField -Type 'string'
    generated_at_utc     = New-D32FixtureSchemaField -Type 'string' -NonEmpty
    started_at_utc       = New-D32FixtureSchemaField -Type 'string' -NonEmpty
    elapsed_ms           = New-D32FixtureSchemaField -Type 'f64'
    working_tree_status  = New-D32FixtureSchemaField -Type 'string'
    build_policy         = New-D32FixtureSchemaField -Type 'object' -Fields $script:D32FixtureBuildPolicySchema
    environment          = New-D32FixtureSchemaField -Type 'object' -Fields $script:D32FixtureEnvironmentSchema
    process_tree_check    = New-D32FixtureSchemaField -Type 'string'
    process_tree_error   = New-D32FixtureSchemaField -Type 'string' -Nullable
    fixtures              = New-D32FixtureSchemaField -Type 'array' -Items (New-D32FixtureSchemaField -Type 'object' -Fields $script:D32FixtureRecordSchema)
}

function ConvertFrom-D32Json {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$Json
    )

    process {
        $converter = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
        if (-not $converter.Parameters.ContainsKey('DateKind')) {
            throw 'D32 preflight requires PowerShell 7.5 or newer for timestamp-preserving JSON parsing'
        }
        return $Json | ConvertFrom-Json -DateKind String
    }
}

function Read-D32Json {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings,
        [Parameter(Mandatory = $true)][string]$Check
    )

    try {
        $raw = [System.IO.File]::ReadAllText($Path)
        $value = $raw | ConvertFrom-D32Json
        if ($null -eq $value) {
            throw 'JSON document was empty'
        }
        return $value
    }
    catch {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check $Check -Message $_.Exception.Message
        return $null
    }
}

function Write-D32Json {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Value
    )

    $json = $Value | ConvertTo-Json -Depth 12
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, $utf8)
}

function Get-D32FileDigest {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return $null
        }
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        return [PSCustomObject]@{
            Path   = $Path
            Length = [Int64]$item.Length
            Hash   = $hash
        }
    }
    catch {
        return $null
    }
}

function Test-D32JsonDuplicateKeys {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Json)

    if (-not ('D32JsonDuplicateKeyScanner' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Text;

public static class D32JsonDuplicateKeyScanner
{
    public static bool HasDuplicateOrInvalidStructure(string json)
    {
        var parser = new Parser(json ?? String.Empty);
        return parser.Scan();
    }

    private sealed class Parser
    {
        private readonly string text;
        private int position;
        private bool invalid;
        private bool duplicate;

        public Parser(string value) { text = value; }

        public bool Scan()
        {
            SkipWhitespace();
            ParseValue(0);
            SkipWhitespace();
            return invalid || duplicate || position != text.Length;
        }

        private void SkipWhitespace()
        {
            while (position < text.Length && (text[position] == ' ' || text[position] == '\t' || text[position] == '\r' || text[position] == '\n')) position++;
        }

        private void ParseValue(int depth)
        {
            SkipWhitespace();
            if (depth > 64) { invalid = true; return; }
            if (position >= text.Length) { invalid = true; return; }
            char c = text[position];
            if (c == '{') { ParseObject(depth + 1); return; }
            if (c == '[') { ParseArray(depth + 1); return; }
            if (c == '"') { ParseString(); return; }
            int start = position;
            while (position < text.Length && text[position] != ',' && text[position] != ']' && text[position] != '}' && text[position] != ' ' && text[position] != '\t' && text[position] != '\r' && text[position] != '\n') position++;
            if (position == start) { invalid = true; position++; }
        }

        private void ParseObject(int depth)
        {
            position++;
            SkipWhitespace();
            var names = new HashSet<string>(StringComparer.Ordinal);
            if (position < text.Length && text[position] == '}') { position++; return; }
            while (position < text.Length)
            {
                SkipWhitespace();
                if (position >= text.Length || text[position] != '"') { invalid = true; return; }
                string name = ParseString();
                if (!names.Add(name)) duplicate = true;
                SkipWhitespace();
                if (position >= text.Length || text[position] != ':') { invalid = true; return; }
                position++;
                ParseValue(depth);
                SkipWhitespace();
                if (position < text.Length && text[position] == ',') { position++; continue; }
                if (position < text.Length && text[position] == '}') { position++; return; }
                invalid = true;
                return;
            }
            invalid = true;
        }

        private void ParseArray(int depth)
        {
            position++;
            SkipWhitespace();
            if (position < text.Length && text[position] == ']') { position++; return; }
            while (position < text.Length)
            {
                ParseValue(depth);
                SkipWhitespace();
                if (position < text.Length && text[position] == ',') { position++; continue; }
                if (position < text.Length && text[position] == ']') { position++; return; }
                invalid = true;
                return;
            }
            invalid = true;
        }

        private string ParseString()
        {
            var value = new StringBuilder();
            position++;
            while (position < text.Length)
            {
                char c = text[position++];
                if (c == '"') return value.ToString();
                if (c != '\\') { value.Append(c); continue; }
                if (position >= text.Length) { invalid = true; return value.ToString(); }
                char escape = text[position++];
                switch (escape)
                {
                    case '"': value.Append('"'); break;
                    case '\\': value.Append('\\'); break;
                    case '/': value.Append('/'); break;
                    case 'b': value.Append('\b'); break;
                    case 'f': value.Append('\f'); break;
                    case 'n': value.Append('\n'); break;
                    case 'r': value.Append('\r'); break;
                    case 't': value.Append('\t'); break;
                    case 'u':
                        if (position + 4 > text.Length) { invalid = true; return value.ToString(); }
                        int code;
                        if (!Int32.TryParse(text.Substring(position, 4), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out code)) { invalid = true; return value.ToString(); }
                        value.Append((char)code);
                        position += 4;
                        break;
                    default: invalid = true; value.Append(escape); break;
                }
            }
            invalid = true;
            return value.ToString();
        }
    }
}
'@
    }
    return [D32JsonDuplicateKeyScanner]::HasDuplicateOrInvalidStructure($Json)
}

function Read-D32EvidenceJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings,
        [Parameter(Mandatory = $true)][string]$Check
    )

    $stream = $null
    $memory = $null
    $sha = $null
    try {
        if (-not (Test-D32NoReparseComponents -Path $Path)) {
            throw 'evidence JSON is missing or traverses a reparse point'
        }
        $before = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($before -isnot [System.IO.FileInfo] -or ($before.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $before.Length -gt 4194304) {
            throw 'evidence JSON must be a regular non-reparse file no larger than 4 MiB'
        }
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $openedIdentity = Get-D32FileIdentity -Path $Path -Stream $stream
        if (($openedIdentity.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $openedIdentity.Length -gt 4194304) {
            throw 'opened evidence JSON must be a regular non-reparse file no larger than 4 MiB'
        }
        $memory = New-Object System.IO.MemoryStream
        $stream.CopyTo($memory)
        $bytes = $memory.ToArray()
        if ($bytes.Length -gt 4194304) { throw 'evidence JSON grew beyond the 4 MiB limit' }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
        $afterStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            $afterIdentity = Get-D32FileIdentity -Path $Path -Stream $afterStream
        }
        finally {
            $afterStream.Dispose()
        }
        if (-not (Test-D32FileIdentityEqual -Left $openedIdentity -Right $afterIdentity) -or -not (Test-D32NoReparseComponents -Path $Path)) {
            throw 'evidence JSON identity or path changed while reading'
        }
        $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $json = $utf8.GetString($bytes)
        if ($json.Length -gt 0 -and $json[0] -eq [char]0xFEFF) { $json = $json.Substring(1) }
        if (Test-D32JsonDuplicateKeys -Json $json) { throw 'evidence JSON has duplicate object keys or excessive nesting' }
        $value = $json | ConvertFrom-D32Json
        if ($null -eq $value) { throw 'evidence JSON document was empty' }
        return [PSCustomObject]@{
            Value = $value
            Digest = [PSCustomObject]@{ Path = $afterIdentity.FullName; Length = [Int64]$bytes.Length; Hash = $hash; Identity = $afterIdentity }
        }
    }
    catch {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check $Check -Message $_.Exception.Message
        return $null
    }
    finally {
        if ($null -ne $sha) { $sha.Dispose() }
        if ($null -ne $memory) { $memory.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Test-D32NoReparseComponents {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $full = [System.IO.Path]::GetFullPath($Path)
        $root = [System.IO.Path]::GetPathRoot($full)
        if ([String]::IsNullOrWhiteSpace($root)) {
            return $false
        }
        $current = $root
        $tail = $full.Substring($root.Length).TrimStart([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
        foreach ($part in @($tail -split '[\\/]+' | Where-Object { -not [String]::IsNullOrWhiteSpace($_) })) {
            $current = Join-Path $current $part
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
        }
        return $true
    }
    catch {
        return $false
    }
}

function Get-D32EvidenceFileDigest {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = $null
    $afterStream = $null
    $sha = $null
    try {
        if (-not (Test-D32NoReparseComponents -Path $Path)) {
            return $null
        }
        # Hash and identity come from the same open Windows handle. Reopening
        # the path afterward must yield the same volume/file ID and metadata.
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $openedIdentity = Get-D32FileIdentity -Path $Path -Stream $stream
        if (($openedIdentity.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $null
        }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha.ComputeHash($stream)
        $hash = ([BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
        $length = [Int64]$stream.Length
        $afterStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $afterIdentity = Get-D32FileIdentity -Path $Path -Stream $afterStream
        if (-not (Test-D32FileIdentityEqual -Left $openedIdentity -Right $afterIdentity) -or $length -ne [Int64]$afterIdentity.Length -or -not (Test-D32NoReparseComponents -Path $Path)) {
            return $null
        }
        return [PSCustomObject]@{
            Path     = [string]$afterIdentity.FullName
            Length   = $length
            Hash     = $hash
            Identity = $afterIdentity
        }
    }
    catch {
        return $null
    }
    finally {
        if ($null -ne $sha) { $sha.Dispose() }
        if ($null -ne $afterStream) { $afterStream.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Test-D32ExactObjectProperties {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    if ($null -eq $Object -or $Object -is [string] -or $Object -is [Array] -or $Object -is [ValueType]) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check $Check -Message 'value must be a JSON object with an exact property set'
        return $false
    }
    $actual = @($Object.PSObject.Properties | ForEach-Object { [string]$_.Name })
    $missing = @($Expected | Where-Object { $actual -cnotcontains $_ })
    $extra = @($actual | Where-Object { $Expected -cnotcontains $_ })
    if ($missing.Count -gt 0 -or $extra.Count -gt 0 -or $actual.Count -ne $Expected.Count) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check $Check -Message ("property set mismatch; missing=[{0}] extra=[{1}]" -f ($missing -join ','), ($extra -join ','))
        return $false
    }
    return $true
}

function Test-D32IdentityDocument {
    param(
        [AllowNull()][object]$Declared,
        [AllowNull()][object]$Actual,
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    $fields = @('FullName', 'Length', 'CreationTimeUtcTicks', 'LastWriteUtcTicks', 'Attributes', 'VolumeSerialHex', 'FileIdHex')
    $valid = Test-D32ExactObjectProperties -Object $Declared -Expected $fields -Check "$Check.identity.schema" -Findings $Findings
    if ($null -eq $Actual -or -not $valid) {
        return $false
    }
    foreach ($field in $fields) {
        $left = Get-D32JsonProperty -Object $Declared -Name $field
        $right = $Actual.$field
        if ($field -ceq 'FullName') {
            $same = $false
            if ($left -is [string] -and $right -is [string] -and (Test-D32AbsoluteFilesystemPath -Path $left) -and (Test-D32AbsoluteFilesystemPath -Path $right)) {
                try {
                    $same = Test-D32PathEqual -Left (Get-D32AbsolutePath -Path $left) -Right (Get-D32AbsolutePath -Path $right)
                }
                catch {
                    $same = $false
                }
            }
        }
        elseif ($field -in @('VolumeSerialHex', 'FileIdHex')) {
            $expectedPattern = if ($field -ceq 'VolumeSerialHex') { '^[0-9a-f]{16}$' } else { '^[0-9a-f]{32}$' }
            $same = $left -is [string] -and $right -is [string] -and $left -cmatch $expectedPattern -and $right -cmatch $expectedPattern -and $left -ceq $right
        }
        else {
            $leftValue = [Int64]0
            $rightValue = [Int64]0
            $same = (Test-D32NonNegativeInt64 -Value $left -Parsed ([ref]$leftValue)) -and
                (Test-D32NonNegativeInt64 -Value $right -Parsed ([ref]$rightValue)) -and
                $leftValue -eq $rightValue
            if ($field -ceq 'Attributes') {
                $same = $same -and $leftValue -le [Int32]::MaxValue
            }
        }
        if (-not $same) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check "$Check.identity.schema" -Message "identity field $field has an invalid scalar type or does not match the opened file"
            return $false
        }
    }
    return $true
}

function Get-D32SecurityClassification {
    return [PSCustomObject]$script:D32SecurityClassification
}

function Test-D32AbsoluteFilesystemPath {
    param([AllowNull()][string]$Path)

    if ([String]::IsNullOrWhiteSpace($Path)) {
        return $false
    }
    # Path.IsPathRooted also accepts a drive-relative `C:foo` path.  Git image
    # trust requires a fully-qualified drive or UNC path, including \\?\ paths.
    return $Path -match '^(?:[A-Za-z]:[\\/]|\\\\)'
}

function Get-D32FileIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.IO.FileStream]$Stream
    )

    if (-not (Test-D32Windows)) {
        throw 'opened-handle volume/file identity is supported only on Windows'
    }
    if (-not ('D32NativeFileIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public sealed class D32NativeIdentityRecord
{
    public long Length { get; set; }
    public long CreationTimeUtcTicks { get; set; }
    public long LastWriteUtcTicks { get; set; }
    public int Attributes { get; set; }
    public string VolumeSerialHex { get; set; }
    public string FileIdHex { get; set; }
}

public static class D32NativeFileIdentity
{
    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        public uint Low;
        public uint High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION information);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int informationClass, IntPtr information, uint bufferSize);

    private static long ToUtcTicks(FILETIME value)
    {
        long fileTime = unchecked((long)(((ulong)value.High << 32) | value.Low));
        return DateTime.FromFileTimeUtc(fileTime).Ticks;
    }

    public static D32NativeIdentityRecord Read(SafeFileHandle handle)
    {
        if (handle == null || handle.IsInvalid || handle.IsClosed)
            throw new ArgumentException("A live file handle is required", "handle");

        BY_HANDLE_FILE_INFORMATION basic;
        if (!GetFileInformationByHandle(handle, out basic))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        IntPtr idBuffer = Marshal.AllocHGlobal(24);
        try
        {
            // FILE_INFO_BY_HANDLE_CLASS.FileIdInfo == 18; FILE_ID_INFO is
            // an 8-byte volume serial followed by a 128-bit file identifier.
            if (!GetFileInformationByHandleEx(handle, 18, idBuffer, 24))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            ulong volumeSerial = unchecked((ulong)Marshal.ReadInt64(idBuffer, 0));
            byte[] fileId = new byte[16];
            Marshal.Copy(IntPtr.Add(idBuffer, 8), fileId, 0, fileId.Length);
            ulong fileLength = ((ulong)basic.FileSizeHigh << 32) | basic.FileSizeLow;
            if (fileLength > long.MaxValue)
                throw new IOException("File length exceeds the supported identity range");

            return new D32NativeIdentityRecord {
                Length = (long)fileLength,
                CreationTimeUtcTicks = ToUtcTicks(basic.CreationTime),
                LastWriteUtcTicks = ToUtcTicks(basic.LastWriteTime),
                Attributes = unchecked((int)basic.FileAttributes),
                VolumeSerialHex = volumeSerial.ToString("x16", CultureInfo.InvariantCulture),
                FileIdHex = BitConverter.ToString(fileId).Replace("-", "").ToLowerInvariant()
            };
        }
        finally
        {
            Marshal.FreeHGlobal(idBuffer);
        }
    }
}
'@
    }

    $native = [D32NativeFileIdentity]::Read($Stream.SafeFileHandle)
    return [PSCustomObject]@{
        FullName             = [System.IO.Path]::GetFullPath($Path)
        Length               = [Int64]$native.Length
        CreationTimeUtcTicks = [Int64]$native.CreationTimeUtcTicks
        LastWriteUtcTicks    = [Int64]$native.LastWriteUtcTicks
        Attributes           = [int]$native.Attributes
        VolumeSerialHex      = [string]$native.VolumeSerialHex
        FileIdHex            = [string]$native.FileIdHex
    }
}

function Test-D32FileIdentityEqual {
    param(
        [AllowNull()][object]$Left,
        [AllowNull()][object]$Right
    )

    if ($null -eq $Left -or $null -eq $Right) {
        return $false
    }
    return [String]::Equals($Left.FullName, $Right.FullName, [StringComparison]::OrdinalIgnoreCase) -and
        [Int64]$Left.Length -eq [Int64]$Right.Length -and
        [Int64]$Left.CreationTimeUtcTicks -eq [Int64]$Right.CreationTimeUtcTicks -and
        [Int64]$Left.LastWriteUtcTicks -eq [Int64]$Right.LastWriteUtcTicks -and
        [int]$Left.Attributes -eq [int]$Right.Attributes -and
        [String]::Equals([string]$Left.VolumeSerialHex, [string]$Right.VolumeSerialHex, [StringComparison]::Ordinal) -and
        [String]::Equals([string]$Left.FileIdHex, [string]$Right.FileIdHex, [StringComparison]::Ordinal)
}

function Test-D32TrustedGitImage {
    param(
        [AllowNull()][string]$Path,
        [AllowNull()][string]$ExpectedSha256
    )

    $result = [ordered]@{
        IsValid        = $false
        Path           = $null
        ExpectedSha256 = $ExpectedSha256
        ActualSha256   = $null
        Identity       = $null
        Failure        = 'trusted Git path/hash were not supplied'
    }
    if (-not (Test-D32AbsoluteFilesystemPath -Path $Path)) {
        $result.Failure = 'trusted Git path must be an absolute drive or UNC path'
        return [PSCustomObject]$result
    }
    if (-not (Test-D32Sha64 -Value $ExpectedSha256)) {
        $result.Failure = 'trusted Git SHA-256 must be lowercase 64-hex'
        return [PSCustomObject]$result
    }

    $approved = [ordered]@{
        Path = 'E:\Program Files\Git\mingw64\bin\git.exe'
        Sha256 = '1f2ee2de971b6d0a7a13f053014998b66c22df47f30f1907a767346392eb8d78'
        Bytes = [Int64]4238224
        VolumeSerialHex = '749614a1961465c0'
        FileIdHex = '4aff000000000b000000000000000000'
    }

    try {
        $digest = Get-D32EvidenceFileDigest -Path $Path
        if ($null -eq $digest) {
            $result.Failure = 'trusted Git path is missing, unstable, reparse-backed, or unreadable'
            return [PSCustomObject]$result
        }
        $result.Path = [string]$digest.Path
        $result.ActualSha256 = [string]$digest.Hash
        $result.Identity = $digest.Identity
        if (-not [String]::Equals([string]$digest.Path, [string]$approved.Path, [StringComparison]::OrdinalIgnoreCase) -or
            $digest.Hash -cne [string]$approved.Sha256 -or $ExpectedSha256 -cne [string]$approved.Sha256 -or
            [Int64]$digest.Length -ne [Int64]$approved.Bytes -or
            [string]$digest.Identity.VolumeSerialHex -cne [string]$approved.VolumeSerialHex -or
            [string]$digest.Identity.FileIdHex -cne [string]$approved.FileIdHex) {
            $result.Failure = 'trusted Git path/hash/bytes/volume/file-ID do not match the Coordinator-approved direct root'
            return [PSCustomObject]$result
        }
        $result.IsValid = $true
        $result.Failure = $null
        return [PSCustomObject]$result
    }
    catch {
        # Never echo an exception from Git/image inspection: it can contain
        # config-derived paths or provider output.
        $result.Failure = 'trusted Git path could not be inspected'
        return [PSCustomObject]$result
    }
}

function ConvertTo-D32ProcessArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashes++
            continue
        }
        if ($character -eq '"') {
            for ($index = 0; $index -lt (($slashes * 2) + 1); $index++) {
                [void]$builder.Append('\')
            }
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        for ($index = 0; $index -lt $slashes; $index++) {
            [void]$builder.Append('\')
        }
        [void]$builder.Append($character)
        $slashes = 0
    }
    for ($index = 0; $index -lt ($slashes * 2); $index++) {
        [void]$builder.Append('\')
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-D32ProcessArguments {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    return (($Arguments | ForEach-Object { ConvertTo-D32ProcessArgument -Value ([string]$_) }) -join ' ')
}

function ConvertTo-D32GitOutput {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [AllowNull()][string]$StdOut,
        [AllowNull()][string]$StdErr
    )

    # Only return data whose grammar is fixed by the command.  Status paths,
    # stderr, config text, and all other Git output are deliberately discarded.
    # The source strings are bounded before parsing so a noisy process cannot
    # become a diagnostic/logging channel.
    $stdoutValue = if ($null -eq $StdOut) { '' } else { $StdOut }
    $stderrValue = if ($null -eq $StdErr) { '' } else { $StdErr }
    $stdoutBounded = if ($stdoutValue.Length -gt $script:D32GitOutputLimit) {
        $stdoutValue.Substring(0, $script:D32GitOutputLimit)
    }
    else {
        $stdoutValue
    }
    $command = if ($Arguments.Count -gt 0) { [string]$Arguments[0] } else { '' }
    $safeText = ''
    if ($command -eq 'rev-parse' -or $command -eq 'merge-base') {
        foreach ($line in ($stdoutBounded -split "`r?`n")) {
            if ($line -cmatch '^\s*([0-9a-f]{40})\s*$') {
                $safeText = $Matches[1]
                break
            }
        }
    }
    return [PSCustomObject]@{
        Text            = $safeText
        HasOutput       = -not [String]::IsNullOrWhiteSpace($stdoutValue)
        HasErrorOutput  = -not [String]::IsNullOrWhiteSpace($stderrValue)
        OutputTruncated = $stdoutValue.Length -gt $script:D32GitOutputLimit
    }
}

function New-D32OwnedTempRoot {
    param([Parameter(Mandatory = $true)][string]$Purpose)

    $base = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $root = Join-Path $base ('d32-preflight-owned-' + $Purpose + '-' + [Guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop)
    $token = [Guid]::NewGuid().ToString('N')
    $marker = Join-Path $root 'd32-owned.marker'
    [System.IO.File]::WriteAllText($marker, $token, (New-Object System.Text.UTF8Encoding($false)))
    return [PSCustomObject]@{ Root = $root; Marker = $marker; Token = $token }
}

function Remove-D32OwnedTempRoot {
    param(
        [AllowNull()][string]$Root,
        [AllowNull()][string]$Marker,
        [AllowNull()][string]$Token
    )

    if ([String]::IsNullOrWhiteSpace($Root) -or [String]::IsNullOrWhiteSpace($Marker) -or [String]::IsNullOrWhiteSpace($Token)) {
        return $false
    }
    try {
        $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
        $markerItem = Get-Item -LiteralPath $Marker -Force -ErrorAction Stop
        if (-not $rootItem.PSIsContainer -or $markerItem.PSIsContainer) {
            return $false
        }
        if (([System.IO.FileAttributes]$rootItem.Attributes).HasFlag([System.IO.FileAttributes]::ReparsePoint) -or
            ([System.IO.FileAttributes]$markerItem.Attributes).HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
            return $false
        }
        $rootFull = [System.IO.Path]::GetFullPath($rootItem.FullName).TrimEnd('\')
        $markerFull = [System.IO.Path]::GetFullPath($markerItem.FullName)
        if (-not [String]::Equals((Split-Path -Parent $markerFull).TrimEnd('\'), $rootFull, [StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
        if (-not [String]::Equals([System.IO.File]::ReadAllText($markerFull), $Token, [StringComparison]::Ordinal)) {
            return $false
        }
        Remove-Item -LiteralPath $rootItem.FullName -Recurse -Force -ErrorAction Stop
        return -not (Test-Path -LiteralPath $rootItem.FullName)
    }
    catch {
        return $false
    }
}

function Invoke-D32Git {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [AllowNull()][string]$TrustedGitPath,
        [AllowNull()][string]$TrustedGitSha256
    )

    $result = [ordered]@{
        ExitCode         = -1
        Text             = ''
        HasOutput        = $false
        HasErrorOutput   = $false
        OutputTruncated  = $false
        Failure          = $null
        TrustedGitBefore = $null
        TrustedGitAfter  = $null
    }
    $script:D32LastPreflightGitCapture = $null
    $before = Test-D32TrustedGitImage -Path $TrustedGitPath -ExpectedSha256 $TrustedGitSha256
    $result.TrustedGitBefore = $before
    if (-not $before.IsValid) {
        $result.Failure = $before.Failure
        return [PSCustomObject]$result
    }
    try {
        $context = $script:D32GitCaptureContext
        if ($null -eq $context -or $null -eq $context.Profile) {
            throw 'caller-pinned V2 Git/toolchain profile context is unavailable'
        }
        if (-not [String]::Equals([string]$context.GitPath, [string]$before.Path, [StringComparison]::OrdinalIgnoreCase) -or
            [string]$context.GitSha256 -cne [string]$TrustedGitSha256) {
            throw 'requested Git image does not match the established caller-pinned V2 capture context'
        }
        $setupSignatures = @("init`0-q", "add`0.", "commit`0-q`0-m`0selftest fixture")
        $signature = @($Arguments) -join "`0"
        $isSelfTestSetup = $setupSignatures -ccontains $signature
        if ($isSelfTestSetup -and
            ([String]::IsNullOrWhiteSpace([string]$context.SelfTestOwnedRoot) -or
             [String]::IsNullOrWhiteSpace([string]$context.SelfTestMarkerPath) -or
             [String]::IsNullOrWhiteSpace([string]$context.SelfTestMarkerToken))) {
            throw 'Git fixture setup is allowed only under the live exact-marker SelfTest context'
        }
        $module = Get-D32PreflightGitCaptureModule
        $call = [ordered]@{
            Repository = $Repository
            Arguments = @($Arguments)
            TrustedGitPath = $before.Path
            TrustedGitSha256 = [string]$TrustedGitSha256
            ProfilePath = [string]$context.Profile.ProfilePath
            ProfileSha256 = [string]$context.Profile.Digest
            TimeoutSeconds = [int]$context.TimeoutSeconds
            SelfTestFixtureSetup = [bool]$isSelfTestSetup
            SelfTestOwnedRoot = if ($isSelfTestSetup) { [string]$context.SelfTestOwnedRoot } else { '' }
            SelfTestMarkerPath = if ($isSelfTestSetup) { [string]$context.SelfTestMarkerPath } else { '' }
            SelfTestMarkerToken = if ($isSelfTestSetup) { [string]$context.SelfTestMarkerToken } else { '' }
        }
        $capture = & $module { param($parameters) Invoke-D32PreflightPinnedGitCapture @parameters } $call
        $script:D32LastPreflightGitCapture = $capture.Attempt
        if (-not [bool]$capture.ProcessValidated) {
            $result.Failure = 'trusted Git V2 process capture, metadata fence, or cleanup failed'
            return [PSCustomObject]$result
        }
        $safeOutput = ConvertTo-D32GitOutput -Arguments $Arguments -StdOut ([string]$capture.StdOut) -StdErr ([string]$capture.StdErr)
        $result.ExitCode = [int]$capture.ExitCode
        $result.Text = [string]$safeOutput.Text
        $result.HasOutput = [bool]$safeOutput.HasOutput
        $result.HasErrorOutput = [bool]$safeOutput.HasErrorOutput
        $result.OutputTruncated = [bool]$safeOutput.OutputTruncated
        if ($result.ExitCode -ne 0) {
            $result.Failure = 'trusted Git command returned a non-zero exit code'
        }
    }
    catch {
        $result.Failure = 'trusted Git V2 process capture, metadata fence, or cleanup failed'
    }
    finally {
        $after = Test-D32TrustedGitImage -Path $TrustedGitPath -ExpectedSha256 $TrustedGitSha256
        $result.TrustedGitAfter = $after
        if (-not $after.IsValid) {
            $result.ExitCode = -1
            $result.Failure = 'trusted Git image failed post-execution revalidation'
        }
        elseif (-not (Test-D32FileIdentityEqual -Left $before.Identity -Right $after.Identity)) {
            $result.ExitCode = -1
            $result.Failure = 'trusted Git image identity changed during execution'
        }
    }
    return [PSCustomObject]$result
}

function Get-D32PreflightGitCaptureModule {
    if ($null -ne $script:D32PreflightGitCaptureModule) { return $script:D32PreflightGitCaptureModule }
    $fixtureScript = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-fixture-prebuild.ps1'))
    if (-not (Test-D32NoReparseComponents -Path $fixtureScript) -or -not (Test-Path -LiteralPath $fixtureScript -PathType Leaf)) {
        throw 'trusted Git V2 launcher path is missing or reparse-backed'
    }
    $script:D32PreflightGitCaptureModule = New-Module -Name D32PreflightGitCapture -ArgumentList $fixtureScript -ScriptBlock {
        param([string]$FixtureScriptPath)
        . $FixtureScriptPath -D32LauncherLibraryOnly

        function Invoke-D32PreflightPinnedGitCapture {
            param(
                [Parameter(Mandatory = $true)][string]$Repository,
                [Parameter(Mandatory = $true)][string[]]$Arguments,
                [Parameter(Mandatory = $true)][string]$TrustedGitPath,
                [Parameter(Mandatory = $true)][string]$TrustedGitSha256,
                [Parameter(Mandatory = $true)][string]$ProfilePath,
                [Parameter(Mandatory = $true)][string]$ProfileSha256,
                [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
                [bool]$SelfTestFixtureSetup = $false,
                [string]$SelfTestOwnedRoot,
                [string]$SelfTestMarkerPath,
                [string]$SelfTestMarkerToken
            )

            $script:PinnedGit = Get-D32PinnedGit -Path $TrustedGitPath -ExpectedSha256 $TrustedGitSha256
            Assert-D32ApprovedPinnedGitRoot
            $profile = Test-D32BuildToolchainProfile -ProfilePath $ProfilePath -ExpectedSha256 $ProfileSha256 -Repository $Repository -ExpectedTargetTriple 'x86_64-pc-windows-msvc'
            if ($null -eq $profile -or -not [bool]$profile.IsValid) {
                throw 'caller-pinned toolchain profile or Windows child-image inventory failed validation'
            }
            $script:ValidatedToolchainProfile = $profile
            $script:TimeoutSeconds = [Math]::Max(1, [Math]::Min(3600, $TimeoutSeconds))
            Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $profile | Out-Null
            try {
                $captured = if ($SelfTestFixtureSetup) {
                    Get-D32GitOutput -Root $Repository -Arguments $Arguments -PreserveOutput -CaptureResult `
                        -SelfTestFixtureSetup -SelfTestOwnedRoot $SelfTestOwnedRoot -SelfTestMarkerPath $SelfTestMarkerPath -SelfTestMarkerToken $SelfTestMarkerToken
                }
                else {
                    Get-D32GitOutput -Root $Repository -Arguments $Arguments -PreserveOutput -CaptureResult
                }
                return [PSCustomObject]@{
                    ProcessValidated = $true
                    ExitCode = [int]$captured.ExitCode
                    StdOut = [string]$captured.StdOut
                    StdErr = [string]$captured.StdErr
                    Attempt = $captured.Attempt
                }
            }
            catch {
                return [PSCustomObject]@{
                    ProcessValidated = $false
                    ExitCode = -1
                    StdOut = ''
                    StdErr = ''
                    Attempt = $script:D32LastPinnedGitAttempt
                }
            }
        }
    }
    return $script:D32PreflightGitCaptureModule
}

function Set-D32GitCaptureContext {
    param(
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$GitSha256,
        [ValidateRange(1, 3600)][int]$TimeoutSeconds = 120
    )

    if ($null -eq $ValidatedProfile -or -not [bool]$ValidatedProfile.IsValid -or
        -not (Test-D32Sha64 -Value ([string]$ValidatedProfile.Digest)) -or
        -not (Test-D32AbsoluteFilesystemPath -Path ([string]$ValidatedProfile.ProfilePath))) {
        throw 'caller-pinned toolchain profile is invalid or incomplete for V2 Git capture'
    }
    $trustedGit = Test-D32TrustedGitImage -Path $GitPath -ExpectedSha256 $GitSha256
    if (-not $trustedGit.IsValid) { throw 'caller-pinned direct Git root identity failed V2 capture context validation' }
    $profileCurrent = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $ValidatedProfile
    if (@($profileCurrent.WindowsImageInventory).Count -ne 1 -or
        -not [String]::Equals([IO.Path]::GetFileName([string]$profileCurrent.WindowsImageInventory[0].Path), 'conhost.exe', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'caller-pinned toolchain profile must contain exactly the approved conhost child image'
    }
    $script:D32GitCaptureContext = [PSCustomObject]@{
        GitPath = [string]$trustedGit.Path
        GitSha256 = [string]$trustedGit.ActualSha256
        Profile = $ValidatedProfile
        TimeoutSeconds = [int]$TimeoutSeconds
        SelfTestOwnedRoot = $null
        SelfTestMarkerPath = $null
        SelfTestMarkerToken = $null
    }
}

function Assert-D32PreflightGitCaptureAttempt {
    param([Parameter(Mandatory = $true)][object]$Attempt, [Parameter(Mandatory = $true)][string]$Name)

    $trace = $Attempt.process_trace
    $cleanup = $Attempt.native_cleanup
    $runtime = $Attempt.cleanup_runtime
    if ($null -eq $trace -or $null -eq $cleanup -or $null -eq $runtime -or
        $trace.state -cne 'COMPLETED' -or -not [bool]$trace.event_chain_complete -or
        -not [bool]$trace.job_accounting_verified -or -not [bool]$trace.accounting_consistent -or
        [int]$trace.process_create_event_count -le 0 -or
        [int]$trace.process_create_event_count -ne [int]$trace.process_exit_event_count -or
        [uint32]$trace.job_total_processes -ne [uint32]$trace.process_create_event_count -or
        [uint32]$trace.job_active_processes -ne 0 -or
        -not [bool]$cleanup.cleanup_succeeded -or -not [bool]$cleanup.job_active_process_count_verified -or
        [uint32]$cleanup.job_active_process_count -ne 0 -or
        -not [bool]$runtime.debugger_thread_exited -or -not [bool]$runtime.debugger_thread_joined -or
        -not [bool]$runtime.debugger_kill_on_exit_enabled -or -not [bool]$runtime.retained_process_handles_signaled -or
        -not [bool]$runtime.debugger_association_query_verified -or -not [bool]$runtime.debugger_association_absent) {
        throw "PREFLIGHT_GIT_SELFTEST_BLOCKED: $Name lacks complete V2 CREATE/EXIT, Job, debugger, handle, or cleanup accounting"
    }
    foreach ($process in @($trace.processes)) {
        if (-not [bool]$process.image_verified -or -not [bool]$process.exited) {
            throw "PREFLIGHT_GIT_SELFTEST_BLOCKED: $Name contains a process without a pre-continue verified and exited image"
        }
    }
}

function Invoke-D32PreflightGitProcessSelfTest {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$GitSha256
    )

    $priorContext = $script:D32GitCaptureContext
    $owned = New-D32OwnedTempRoot -Purpose 'preflight-git-v2-selftest'
    try {
        $validatedProfile = $null
        $profileCases = @(Test-D32BuildToolchainProfileSelfTest -Root $owned.Root -Repository $Repository -ValidatedProfileOutput ([ref]$validatedProfile))
        $profileFailures = @($profileCases | Where-Object { -not [bool]$_.Passed })
        if ($profileFailures.Count -gt 0 -or $null -eq $validatedProfile -or -not [bool]$validatedProfile.IsValid) {
            $failedNames = @($profileFailures | ForEach-Object { [string]$_.Name }) -join ', '
            throw "PREFLIGHT_GIT_SELFTEST_BLOCKED: a temporary exact V2 test profile was unavailable: $failedNames"
        }
        Set-D32GitCaptureContext -ValidatedProfile $validatedProfile -GitPath $GitPath -GitSha256 $GitSha256 -TimeoutSeconds 30

        $commands = @(
            [PSCustomObject]@{ Name = 'rev-parse'; Arguments = @('rev-parse', '--verify', 'HEAD'); RequireText = $true },
            [PSCustomObject]@{ Name = 'status'; Arguments = @('status', '--porcelain=v1', '--untracked-files=all'); RequireText = $false },
            [PSCustomObject]@{ Name = 'ls-files'; Arguments = @('ls-files', '-v', '-z'); RequireText = $false }
        )
        $expectedHead = $null
        foreach ($command in $commands) {
            $result = Invoke-D32Git -Repository $Repository -Arguments $command.Arguments -TrustedGitPath $GitPath -TrustedGitSha256 $GitSha256
            if ($result.ExitCode -ne 0 -or $null -ne $result.Failure -or $null -eq $script:D32LastPreflightGitCapture) {
                throw "PREFLIGHT_GIT_SELFTEST_BLOCKED: direct-root $($command.Name) did not complete through V2: $($result.Failure)"
            }
            Assert-D32PreflightGitCaptureAttempt -Attempt $script:D32LastPreflightGitCapture -Name $command.Name
            if ($command.RequireText) {
                if (-not (Test-D32Sha40 -Value ([string]$result.Text))) { throw 'PREFLIGHT_GIT_SELFTEST_BLOCKED: direct-root rev-parse did not preserve an exact full HEAD' }
                $expectedHead = [string]$result.Text
            }
        }
        if ([String]::IsNullOrWhiteSpace($expectedHead)) { throw 'PREFLIGHT_GIT_SELFTEST_BLOCKED: no exact HEAD was captured for the focused V2 Git checks' }
        $phase0State = Get-D32Phase0GitState -Repository $Repository -GitPath $GitPath -GitSha256 $GitSha256
        if ($phase0State.Head -cne $expectedHead -or -not [bool]$phase0State.Clean) {
            throw 'PREFLIGHT_GIT_SELFTEST_BLOCKED: Phase0 Git-state consumer did not preserve exact HEAD and clean-state semantics'
        }

        $fixtureRepository = Join-Path $owned.Root 'fixture-repository'
        [void][IO.Directory]::CreateDirectory($fixtureRepository)
        [IO.File]::WriteAllText((Join-Path $fixtureRepository 'selftest.txt'), 'D32 preflight Git V2 fixture', [Text.UTF8Encoding]::new($false))
        $script:D32GitCaptureContext | Add-Member -NotePropertyName SelfTestOwnedRoot -NotePropertyValue $owned.Root -Force
        $script:D32GitCaptureContext | Add-Member -NotePropertyName SelfTestMarkerPath -NotePropertyValue $owned.Marker -Force
        $script:D32GitCaptureContext | Add-Member -NotePropertyName SelfTestMarkerToken -NotePropertyValue $owned.Token -Force
        foreach ($setup in @(
            [PSCustomObject]@{ Name = 'init'; Arguments = @('init', '-q') },
            [PSCustomObject]@{ Name = 'add'; Arguments = @('add', '.') },
            [PSCustomObject]@{ Name = 'commit'; Arguments = @('commit', '-q', '-m', 'selftest fixture') }
        )) {
            $setupResult = Invoke-D32Git -Repository $fixtureRepository -Arguments $setup.Arguments -TrustedGitPath $GitPath -TrustedGitSha256 $GitSha256
            if ($setupResult.ExitCode -ne 0 -or $null -ne $setupResult.Failure -or $null -eq $script:D32LastPreflightGitCapture) {
                throw "PREFLIGHT_GIT_SELFTEST_BLOCKED: marker-owned fixture $($setup.Name) did not complete through V2: $($setupResult.Failure)"
            }
            Assert-D32PreflightGitCaptureAttempt -Attempt $script:D32LastPreflightGitCapture -Name "fixture-$($setup.Name)"
        }
        $fixtureHead = Invoke-D32Git -Repository $fixtureRepository -Arguments @('rev-parse', '--verify', 'HEAD') -TrustedGitPath $GitPath -TrustedGitSha256 $GitSha256
        Assert-D32PreflightGitCaptureAttempt -Attempt $script:D32LastPreflightGitCapture -Name 'fixture-rev-parse'
        $fixtureStatus = Invoke-D32Git -Repository $fixtureRepository -Arguments @('status', '--porcelain=v1', '--untracked-files=all') -TrustedGitPath $GitPath -TrustedGitSha256 $GitSha256
        Assert-D32PreflightGitCaptureAttempt -Attempt $script:D32LastPreflightGitCapture -Name 'fixture-status'
        if ($fixtureHead.ExitCode -ne 0 -or $fixtureHead.Text.Trim() -cnotmatch '^[0-9a-f]{40}$' -or
            $fixtureStatus.ExitCode -ne 0 -or $fixtureStatus.HasOutput -or $null -ne $fixtureHead.Failure -or $null -ne $fixtureStatus.Failure) {
            throw 'PREFLIGHT_GIT_SELFTEST_BLOCKED: marker-owned fixture setup did not preserve exact commit and clean-status semantics'
        }

        $gitInstallRoot = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent (Split-Path -Parent $GitPath)) '..'))
        $wrapperPath = Join-Path $gitInstallRoot 'cmd\git.exe'
        if (-not (Test-Path -LiteralPath $wrapperPath -PathType Leaf)) { throw 'PREFLIGHT_GIT_SELFTEST_BLOCKED: installed Git wrapper is unavailable for path-denial evidence' }
        $wrapperDigest = Get-D32EvidenceFileDigest -Path $wrapperPath
        if ($null -eq $wrapperDigest) { throw 'PREFLIGHT_GIT_SELFTEST_BLOCKED: installed Git wrapper identity could not be captured' }
        $script:D32LastPreflightGitCapture = $null
        $wrapperResult = Invoke-D32Git -Repository $Repository -Arguments @('rev-parse', '--verify', 'HEAD') -TrustedGitPath $wrapperPath -TrustedGitSha256 $wrapperDigest.Hash
        if ($wrapperResult.ExitCode -ne -1 -or $null -eq $wrapperResult.Failure -or $null -ne $script:D32LastPreflightGitCapture) {
            throw 'PREFLIGHT_GIT_SELFTEST_BLOCKED: wrapper Git image was not rejected before any process trace'
        }
        $script:D32LastPreflightGitCapture = $null
        $hashMismatch = Invoke-D32Git -Repository $Repository -Arguments @('rev-parse', '--verify', 'HEAD') -TrustedGitPath $GitPath -TrustedGitSha256 ('0' * 64)
        if ($hashMismatch.ExitCode -ne -1 -or $null -eq $hashMismatch.Failure -or $null -ne $script:D32LastPreflightGitCapture) {
            throw 'PREFLIGHT_GIT_SELFTEST_BLOCKED: Coordinator Git SHA mismatch was not rejected before process creation'
        }

        $metadataRoot = Join-Path $owned.Root 'metadata-indirection-repository'
        $gitDirectory = Join-Path $metadataRoot '.git'
        foreach ($relativeDirectory in @('.git/objects/info', '.git/refs/heads', '.git/info', 'vita-agent/target')) {
            [void][IO.Directory]::CreateDirectory((Join-Path $metadataRoot $relativeDirectory))
        }
        [IO.File]::WriteAllText((Join-Path $gitDirectory 'HEAD'), "ref: refs/heads/main`n", [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllBytes((Join-Path $gitDirectory 'index'), [byte[]]@())
        [IO.File]::WriteAllText((Join-Path $gitDirectory 'info/exclude'), "# allowed comments`n`nvita-agent/target/`n", [Text.UTF8Encoding]::new($false))
        $ordinaryConfig = "[core]`n`t repositoryformatversion = 0`n`t filemode = false`n`t bare = false`n`t logallrefupdates = true`n"
        [IO.File]::WriteAllText((Join-Path $gitDirectory 'config'), $ordinaryConfig, [Text.UTF8Encoding]::new($false))
        $module = Get-D32PreflightGitCaptureModule
        foreach ($negative in @(
            [PSCustomObject]@{ Name = 'source-config includeIf'; Configure = { param($gitDir) [IO.File]::WriteAllText((Join-Path $gitDir 'config'), "[includeIf `"gitdir:outside/`"]`n`t path = outside.gitconfig`n", [Text.UTF8Encoding]::new($false)) }; Expected = 'GIT_CONFIG_REJECTED:*' },
            [PSCustomObject]@{ Name = 'metadata alternates indirection'; Configure = { param($gitDir) [IO.File]::WriteAllText((Join-Path $gitDir 'config'), $ordinaryConfig, [Text.UTF8Encoding]::new($false)); [IO.File]::WriteAllText((Join-Path $gitDir 'objects/info/alternates'), 'outside-objects', [Text.UTF8Encoding]::new($false)) }; Expected = 'GIT_REPOSITORY_INVALID:*' }
        )) {
            $configure = $negative.Configure
            & $configure $gitDirectory
            $probe = & $module {
                param($Repository, $PinnedPath, $PinnedHash, $Profile, $ExpectedPattern)
                $script:PinnedGit = Get-D32PinnedGit -Path $PinnedPath -ExpectedSha256 $PinnedHash
                $script:ValidatedToolchainProfile = $Profile
                $script:TimeoutSeconds = 30
                $script:D32LastPinnedGitAttempt = $null
                try {
                    $null = Get-D32GitOutput -Root $Repository -Arguments @('rev-parse', '--verify', 'HEAD')
                    return [PSCustomObject]@{ Rejected = $false; Error = $null; Attempt = $script:D32LastPinnedGitAttempt }
                }
                catch {
                    return [PSCustomObject]@{ Rejected = $_.Exception.Message -like $ExpectedPattern; Error = $_.Exception.Message; Attempt = $script:D32LastPinnedGitAttempt }
                }
            } $metadataRoot $GitPath $GitSha256 $validatedProfile ([string]$negative.Expected)
            if (-not [bool]$probe.Rejected -or $null -ne $probe.Attempt) {
                throw "PREFLIGHT_GIT_SELFTEST_BLOCKED: $($negative.Name) was not rejected before a V2 process was created"
            }
            if ($negative.Name -ceq 'metadata alternates indirection') {
                Remove-Item -LiteralPath (Join-Path $gitDirectory 'objects/info/alternates') -Force -ErrorAction Stop
            }
        }

        & $module {
            param($PinnedPath, $PinnedHash, $Repository)
            Invoke-D32PinnedGitProcessIdentitySelfTest -PinnedPath $PinnedPath -PinnedSha256 $PinnedHash -Repository $Repository
        } $GitPath $GitSha256 $Repository
        Write-Host 'D32_PREFLIGHT_GIT_PROCESS_SELFTEST PASS (preflight and Phase0 consumers use V2 fast rev-parse/status/ls-files with exact clean-state semantics; wrapper and root-hash mismatch denied before launch; config/source and alternates indirection blocked pre-launch; pinned-root PID/parent/descendant/cleanup negatives verified)'
        return $true
    }
    finally {
        $script:D32GitCaptureContext = $priorContext
        if (-not (Remove-D32OwnedTempRoot -Root $owned.Root -Marker $owned.Marker -Token $owned.Token)) {
            throw 'PREFLIGHT_GIT_SELFTEST_CLEANUP_BLOCKED: owned focused Git self-test temp root did not clean up'
        }
    }
}

function Test-D32Sha40 {
    param([AllowNull()][object]$Value)
    return $Value -is [string] -and $Value -cmatch '^[0-9a-f]{40}$'
}

function Test-D32Sha64 {
    param([AllowNull()][object]$Value)
    return $Value -is [string] -and $Value -cmatch '^[0-9a-f]{64}$'
}

function Test-D32NonNegativeInt64 {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][ref]$Parsed
    )

    $Parsed.Value = [Int64]0
    if ($null -eq $Value -or @([sbyte], [byte], [int16], [uint16], [int32], [uint32], [int64], [uint64]) -notcontains $Value.GetType()) {
        return $false
    }
    try {
        $decimalValue = [decimal]$Value
        if ($decimalValue -lt 0 -or $decimalValue -gt [decimal][Int64]::MaxValue) {
            return $false
        }
        $Parsed.Value = [Int64]$decimalValue
        return $true
    }
    catch {
        return $false
    }
}

function Get-D32Head {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$TrustedGitPath,
        [Parameter(Mandatory = $true)][string]$TrustedGitSha256,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    $result = Invoke-D32Git -Repository $Repository -Arguments @('rev-parse', '--verify', 'HEAD') -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256
    $head = $result.Text.Trim()
    if ($result.ExitCode -ne 0 -or -not (Test-D32Sha40 -Value $head)) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'git.head' -Message 'exact HEAD could not be read from the trusted Git image'
        return $null
    }
    Add-D32Finding -Findings $Findings -Severity PASS -Check 'git.head' -Message "HEAD=$head"
    return $head
}

function Test-D32GitClean {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$TrustedGitPath,
        [Parameter(Mandatory = $true)][string]$TrustedGitSha256,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    $result = Invoke-D32Git -Repository $Repository -Arguments @('status', '--porcelain=v1', '--untracked-files=all') -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256
    if ($result.ExitCode -ne 0) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'git.clean' -Message 'trusted Git status failed; raw Git output is suppressed'
        return $false
    }
    if ($result.HasOutput) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'git.clean' -Message 'working tree is dirty (path details suppressed)'
        return $false
    }
    Add-D32Finding -Findings $Findings -Severity PASS -Check 'git.clean' -Message 'working tree is clean'
    return $true
}

function Test-D32BaseInputs {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$TrustedGitPath,
        [Parameter(Mandatory = $true)][string]$TrustedGitSha256,
        [AllowNull()][string]$Head,
        [AllowNull()][string]$Base,
        [AllowNull()][string]$MergeBase,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    if ([String]::IsNullOrWhiteSpace($Base) -and [String]::IsNullOrWhiteSpace($MergeBase)) {
        Add-D32Finding -Findings $Findings -Severity INFO -Check 'git.base' -Message 'no base or merge-base expectation supplied'
        return
    }

    if (-not [String]::IsNullOrWhiteSpace($Base)) {
        if (-not (Test-D32Sha40 -Value $Base)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'git.base' -Message "base is not a lowercase 40-hex commit: $Base"
        }
        elseif ($null -ne $Head) {
            $ancestor = Invoke-D32Git -Repository $Repository -Arguments @('merge-base', '--is-ancestor', $Base, $Head) -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256
            if ($ancestor.ExitCode -ne 0) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'git.base' -Message "base $Base is not an ancestor of HEAD $Head"
            }
            else {
                Add-D32Finding -Findings $Findings -Severity PASS -Check 'git.base' -Message "base $Base is an ancestor of HEAD"
            }
        }
    }

    if (-not [String]::IsNullOrWhiteSpace($MergeBase)) {
        if (-not (Test-D32Sha40 -Value $MergeBase)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'git.merge-base' -Message "merge-base is not a lowercase 40-hex commit: $MergeBase"
        }
        elseif ($null -ne $Head -and -not [String]::IsNullOrWhiteSpace($Base) -and (Test-D32Sha40 -Value $Base)) {
            $computed = Invoke-D32Git -Repository $Repository -Arguments @('merge-base', $Head, $Base) -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256
            $computedValue = $computed.Text.Trim()
            if ($computed.ExitCode -ne 0 -or $computedValue -cne $MergeBase) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'git.merge-base' -Message "expected $MergeBase but computed $computedValue"
            }
            else {
                Add-D32Finding -Findings $Findings -Severity PASS -Check 'git.merge-base' -Message "merge-base=$MergeBase"
            }
        }
        elseif ($null -ne $Head) {
            $resolved = Invoke-D32Git -Repository $Repository -Arguments @('rev-parse', '--verify', "$MergeBase^{commit}") -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256
            if ($resolved.ExitCode -ne 0 -or $resolved.Text.Trim() -cne $MergeBase) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'git.merge-base' -Message "merge-base commit could not be resolved exactly: $MergeBase"
            }
            else {
                Add-D32Finding -Findings $Findings -Severity PASS -Check 'git.merge-base' -Message "merge-base commit resolved=$MergeBase"
            }
        }
    }
}

function Test-D32Governance {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    $required = @(
        'AGENTS.md',
        'docs/governance/PROJECT_SOURCE_OF_TRUTH.md',
        'docs/governance/CURRENT_DEVELOPMENT_STATE.md',
        'docs/governance/FROZEN_INVARIANTS.md',
        'docs/governance/ARCHITECTURE_DECISIONS.md',
        'docs/governance/MODEL_ROUTING.md',
        'docs/governance/CODEX_DEVELOPMENT_PROTOCOL.md'
    )
    foreach ($relative in $required) {
        $path = Join-Path $Repository ($relative -replace '/', '\')
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'governance.files' -Message "missing required governance/index file: $relative"
        }
        elseif ((Get-Item -LiteralPath $path -Force).Length -eq 0) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'governance.files' -Message "required governance/index file is empty: $relative"
        }
        else {
            Add-D32Finding -Findings $Findings -Severity PASS -Check 'governance.files' -Message "present: $relative"
        }
    }
    $agents = Join-Path $Repository 'AGENTS.md'
    if (Test-Path -LiteralPath $agents -PathType Leaf) {
        try {
            $agentsText = [System.IO.File]::ReadAllText($agents)
            $requiredLinks = @(
                'docs/governance/PROJECT_SOURCE_OF_TRUTH.md',
                'docs/governance/CURRENT_DEVELOPMENT_STATE.md',
                'docs/governance/FROZEN_INVARIANTS.md',
                'docs/governance/ARCHITECTURE_DECISIONS.md',
                'docs/governance/CODEX_DEVELOPMENT_PROTOCOL.md'
            )
            $missingLinks = @($requiredLinks | Where-Object { $agentsText -notmatch [regex]::Escape($_) })
            if ($missingLinks.Count -gt 0) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'governance.index' -Message ("AGENTS.md does not index the required governance inputs: " + ($missingLinks -join ', '))
            }
            else {
                Add-D32Finding -Findings $Findings -Severity PASS -Check 'governance.index' -Message 'AGENTS.md indexes the required source-of-truth, state, invariant, architecture, and protocol inputs'
            }
        }
        catch {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'governance.index' -Message $_.Exception.Message
        }
    }
    $protocolPath = Join-Path $Repository 'docs\governance\CODEX_DEVELOPMENT_PROTOCOL.md'
    if (Test-Path -LiteralPath $protocolPath -PathType Leaf) {
        try {
            $protocolText = [System.IO.File]::ReadAllText($protocolPath)
            if ($protocolText -notmatch 'MODEL_ROUTING\.md') {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'governance.model-routing' -Message 'CODEX_DEVELOPMENT_PROTOCOL.md does not identify the current MODEL_ROUTING.md authority'
            }
            else {
                Add-D32Finding -Findings $Findings -Severity PASS -Check 'governance.model-routing' -Message 'the current protocol identifies the role/model routing table'
            }
        }
        catch {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'governance.model-routing' -Message $_.Exception.Message
        }
    }
}

function Test-D32RequestedModes {
    param(
        [AllowNull()][string[]]$Modes,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    $actual = New-Object System.Collections.ArrayList
    $modeInput = if ($null -eq $Modes) { $script:D32CanonicalModes } else { $Modes }
    foreach ($mode in $modeInput) {
        [void]$actual.Add($mode)
    }
    $ok = $true
    if ($actual.Count -ne $script:D32CanonicalModes.Count) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'd32.modes' -Message "expected exactly 8 canonical modes, received $($actual.Count)"
        $ok = $false
    }
    $limit = [Math]::Min($actual.Count, $script:D32CanonicalModes.Count)
    for ($index = 0; $index -lt $limit; $index++) {
        if ($null -eq $actual[$index] -or $actual[$index] -cne $script:D32CanonicalModes[$index]) {
            $received = if ($null -eq $actual[$index]) { '<null>' } else { $actual[$index] }
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'd32.modes' -Message "mode[$index] expected '$($script:D32CanonicalModes[$index])', received '$received'"
            $ok = $false
        }
    }
    if ($actual.Count -gt $script:D32CanonicalModes.Count) {
        for ($index = $script:D32CanonicalModes.Count; $index -lt $actual.Count; $index++) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'd32.modes' -Message "unexpected extra mode[$index]='$($actual[$index])'"
        }
    }
    if ($ok) {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'd32.modes' -Message 'exact canonical eight-mode sequence validated'
    }
    return [PSCustomObject]@{
        IsValid = $ok
        Modes   = [string[]]$actual.ToArray()
    }
}

function Test-D32RunOutputRoot {
    param(
        [AllowNull()][string]$RunRoot,
        [Parameter(Mandatory = $true)][string]$Manifest,
        [AllowNull()][string]$BundleManifest,
        [AllowNull()][string]$Attestation,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    if ([String]::IsNullOrWhiteSpace($RunRoot)) {
        Add-D32Finding -Findings $Findings -Severity INFO -Check 'run-output-root' -Message 'no run output/log root supplied; this script will not create one'
        return
    }
    if (Test-Path -LiteralPath $RunRoot) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'run-output-root' -Message "run output/log root already exists and must not be overwritten: $RunRoot"
        return
    }
    $rootAbsolute = Get-D32AbsolutePath -Path $RunRoot
    $manifestAbsolute = Get-D32AbsolutePath -Path $Manifest
    if ((Test-D32PathInside -Child $manifestAbsolute -Parent $rootAbsolute) -or (Test-D32PathInside -Child $rootAbsolute -Parent $manifestAbsolute)) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'run-output-root' -Message 'run output/log root overlaps the provenance manifest path'
    }
    if (-not [String]::IsNullOrWhiteSpace($BundleManifest)) {
        $bundleAbsolute = Get-D32AbsolutePath -Path $BundleManifest
        if ((Test-D32PathInside -Child $bundleAbsolute -Parent $rootAbsolute) -or (Test-D32PathInside -Child $rootAbsolute -Parent $bundleAbsolute)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'run-output-root' -Message 'run output/log root overlaps the bundle manifest path'
        }
    }
    if (-not [String]::IsNullOrWhiteSpace($Attestation)) {
        $attestationAbsolute = Get-D32AbsolutePath -Path $Attestation
        if ((Test-D32PathInside -Child $attestationAbsolute -Parent $rootAbsolute) -or (Test-D32PathInside -Child $rootAbsolute -Parent $attestationAbsolute)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'run-output-root' -Message 'run output/log root overlaps the build-attestation path'
        }
    }
    if (-not ($Findings | Where-Object { $_.Check -eq 'run-output-root' -and $_.Severity -eq 'ERROR' })) {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'run-output-root' -Message 'run output/log root is absent and will not be overwritten'
    }
}

function Test-D32ProvenanceManifest {
    param(
        [AllowNull()][object]$Manifest,
        [AllowNull()][string]$Head,
        [Parameter(Mandatory = $true)][string]$ExpectedSourceRepo,
        [Parameter(Mandatory = $true)][string]$ExpectedImagePath,
        [AllowNull()][object]$ImageDigest,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    if ($null -eq $Manifest) {
        return
    }
    foreach ($field in $script:D32RequiredProvenanceFields) {
        if (-not (Test-D32JsonProperty -Object $Manifest -Name $field)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'provenance.schema' -Message "missing Host-required field: $field"
        }
    }
    $candidate = Get-D32JsonProperty -Object $Manifest -Name 'candidate_sha'
    $sourceRepo = Get-D32JsonProperty -Object $Manifest -Name 'source_repo'
    $imagePath = Get-D32JsonProperty -Object $Manifest -Name 'image_path'
    $imageSha = Get-D32JsonProperty -Object $Manifest -Name 'image_sha256'
    $gitStatus = Get-D32JsonProperty -Object $Manifest -Name 'git_status'
    $profile = Get-D32JsonProperty -Object $Manifest -Name 'build_profile'
    $command = Get-D32JsonProperty -Object $Manifest -Name 'build_command'

    if (-not (Test-D32Sha40 -Value $candidate)) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'provenance.candidate_sha' -Message 'candidate_sha must be lowercase 40-hex'
    }
    elseif ($null -ne $Head -and $candidate -cne $Head) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'provenance.candidate_sha' -Message "manifest candidate_sha=$candidate does not equal exact HEAD=$Head"
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'provenance.candidate_sha' -Message "candidate_sha=$candidate"
    }
    if ($sourceRepo -isnot [string] -or $sourceRepo -cne $ExpectedSourceRepo) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'provenance.source_repo' -Message "source_repo is not the Rust repository-root path: '$sourceRepo'"
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'provenance.source_repo' -Message 'source_repo matches Rust repository-root path'
    }
    if ($imagePath -isnot [string] -or $imagePath -cne $ExpectedImagePath) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'provenance.image_path' -Message "image_path is not the Rust-canonical release path: '$imagePath'"
    }
    elseif ((Test-D32Windows) -and -not $imagePath.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'provenance.image_path' -Message 'image_path must use the Windows extended \\?\ form used by Rust canonicalize'
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'provenance.image_path' -Message 'image_path matches Rust-canonical release path'
    }
    if (-not (Test-D32Sha64 -Value $imageSha)) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'provenance.image_sha256' -Message 'image_sha256 must be lowercase 64-hex'
    }
    elseif ($null -eq $ImageDigest) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'provenance.image_sha256' -Message 'release image hash could not be computed'
    }
    elseif ($imageSha -cne $ImageDigest.Hash) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'provenance.image_sha256' -Message "manifest image_sha256=$imageSha does not match image hash=$($ImageDigest.Hash)"
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'provenance.image_sha256' -Message 'release image hash matches'
    }
    if ($gitStatus -cne 'clean') {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'provenance.git_status' -Message "git_status must be 'clean', received '$gitStatus'"
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'provenance.git_status' -Message 'git_status=clean'
    }
    if ($profile -cne 'release') {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'provenance.build_profile' -Message "build_profile must be 'release', received '$profile'"
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'provenance.build_profile' -Message 'build_profile=release'
    }
    if ($command -cne $script:D32BuildCommand) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'provenance.build_command' -Message 'build_command does not match the fixed Host release command'
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'provenance.build_command' -Message 'fixed release build command matches'
    }
}

function Test-D32BundleManifest {
    param(
        [AllowNull()][object]$Bundle,
        [Parameter(Mandatory = $true)][string]$BundleFilePath,
        [AllowNull()][string]$Head,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    if ($null -eq $Bundle) {
        return
    }
    $candidate = Get-D32JsonProperty -Object $Bundle -Name 'candidate_sha'
    if (-not (Test-D32Sha40 -Value $candidate)) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.candidate_sha' -Message 'bundle candidate_sha must be lowercase 40-hex'
    }
    elseif ($null -ne $Head -and $candidate -cne $Head) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.candidate_sha' -Message "bundle candidate_sha=$candidate does not equal exact HEAD=$Head"
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'bundle.candidate_sha' -Message "bundle candidate_sha=$candidate"
    }

    $expectedRepo = Get-D32CanonicalPath -Path $Repository
    $sourceClone = Get-D32JsonProperty -Object $Bundle -Name 'source_clone'
    if ($sourceClone -isnot [string]) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.source_clone' -Message 'bundle source_clone is missing or not a string'
    }
    else {
        try {
            $actualSource = Get-D32CanonicalPath -Path $sourceClone
            if (-not (Test-D32PathEqual -Left $actualSource -Right $expectedRepo)) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.source_clone' -Message "source_clone does not resolve to repository root: $sourceClone"
            }
            else {
                Add-D32Finding -Findings $Findings -Severity PASS -Check 'bundle.source_clone' -Message 'source_clone resolves to repository root'
            }
        }
        catch {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.source_clone' -Message $_.Exception.Message
        }
    }

    $bundleDirectory = $null
    try {
        $bundleFileCanonical = Get-D32CanonicalPath -Path $BundleFilePath
        $bundleDirectory = Get-D32CanonicalPath -Path (Split-Path -Parent $BundleFilePath)
    }
    catch {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.path' -Message "bundle manifest canonical path failed: $($_.Exception.Message)"
    }
    $bundlePath = Get-D32JsonProperty -Object $Bundle -Name 'bundle_path'
    if ($bundlePath -isnot [string]) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.path' -Message 'bundle_path is missing or not a string'
    }
    elseif ($null -ne $bundleDirectory) {
        try {
            $declaredBundle = Get-D32CanonicalPath -Path $bundlePath
            if (-not (Test-D32PathEqual -Left $declaredBundle -Right $bundleDirectory)) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.path' -Message "bundle_path does not match the manifest parent: $bundlePath"
            }
            else {
                Add-D32Finding -Findings $Findings -Severity PASS -Check 'bundle.path' -Message 'bundle_path matches manifest parent'
            }
        }
        catch {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.path' -Message $_.Exception.Message
        }
    }

    $targets = Get-D32JsonProperty -Object $Bundle -Name 'build_targets'
    foreach ($targetName in @('vita', 'host')) {
        $target = Get-D32JsonProperty -Object $targets -Name $targetName
        if ($target -isnot [string] -or -not (Test-Path -LiteralPath $target -PathType Container)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.build_targets' -Message "build_targets.$targetName is missing or not an existing directory"
        }
        else {
            Add-D32Finding -Findings $Findings -Severity PASS -Check 'bundle.build_targets' -Message "build_targets.$targetName exists"
        }
    }

    $artifacts = Get-D32JsonProperty -Object $Bundle -Name 'artifacts'
    if ($null -eq $artifacts -or $artifacts -isnot [Array]) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.artifacts' -Message 'artifacts must be an array'
        return
    }
    if ($artifacts.Count -ne 3) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.artifacts' -Message "expected exactly three artifacts, received $($artifacts.Count)"
    }
    $names = @($artifacts | ForEach-Object { Get-D32JsonProperty -Object $_ -Name 'name' })
    foreach ($expectedName in $script:D32BundleArtifactNames) {
        if ($names -notcontains $expectedName) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.artifacts' -Message "required artifact is absent: $expectedName"
        }
    }
    foreach ($name in $names) {
        if ($null -ne $name -and @($names | Where-Object { $_ -ceq $name }).Count -gt 1) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.artifacts' -Message "duplicate artifact name: $name"
        }
        if ($null -ne $name -and $script:D32BundleArtifactNames -notcontains $name) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.artifacts' -Message "unknown artifact name: $name"
        }
    }

    $declaredTotal = Get-D32JsonProperty -Object $Bundle -Name 'total_bytes'
    $totalBytes = [Int64]0
    foreach ($artifact in $artifacts) {
        $name = Get-D32JsonProperty -Object $artifact -Name 'name'
        $buildPath = Get-D32JsonProperty -Object $artifact -Name 'build_path'
        $bundlePathValue = Get-D32JsonProperty -Object $artifact -Name 'bundle_path'
        $buildBytes = Get-D32JsonProperty -Object $artifact -Name 'build_bytes'
        $bundleBytes = Get-D32JsonProperty -Object $artifact -Name 'bundle_bytes'
        $buildHash = Get-D32JsonProperty -Object $artifact -Name 'build_sha256'
        $bundleHash = Get-D32JsonProperty -Object $artifact -Name 'bundle_sha256'
        $exactMatch = Get-D32JsonProperty -Object $artifact -Name 'exact_match'
        $artifactCheck = "bundle.artifact.$name"
        $buildBytesValue = [Int64]0
        $bundleBytesValue = [Int64]0
        $buildBytesValid = Test-D32NonNegativeInt64 -Value $buildBytes -Parsed ([ref]$buildBytesValue)
        $bundleBytesValid = Test-D32NonNegativeInt64 -Value $bundleBytes -Parsed ([ref]$bundleBytesValue)

        if ($buildPath -isnot [string] -or -not (Test-Path -LiteralPath $buildPath -PathType Leaf)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message 'build_path is missing or not an existing file'
        }
        if ($bundlePathValue -isnot [string] -or -not (Test-Path -LiteralPath $bundlePathValue -PathType Leaf)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message 'bundle_path is missing or not an existing file'
        }
        if ($null -ne $bundleDirectory -and $bundlePathValue -is [string] -and (Test-Path -LiteralPath $bundlePathValue -PathType Leaf)) {
            try {
                $bundleArtifactCanonical = Get-D32CanonicalPath -Path $bundlePathValue
                if (-not (Test-D32PathInside -Child $bundleArtifactCanonical -Parent $bundleDirectory)) {
                    Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message 'bundle artifact escapes bundle_path'
                }
            }
            catch {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message $_.Exception.Message
            }
        }
        if (-not $buildBytesValid) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message 'build_bytes is not a non-negative number'
        }
        if (-not $bundleBytesValid) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message 'bundle_bytes is not a non-negative number'
        }
        if ($buildBytesValid -and $bundleBytesValid -and $buildBytesValue -ne $bundleBytesValue) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message "build_bytes=$buildBytes differs from bundle_bytes=$bundleBytes"
        }
        elseif ($buildBytesValid) {
            $totalBytes += $buildBytesValue
        }
        if (-not (Test-D32Sha64 -Value $buildHash) -or -not (Test-D32Sha64 -Value $bundleHash)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message 'build_sha256 and bundle_sha256 must both be lowercase 64-hex'
        }
        elseif ($buildHash -cne $bundleHash) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message 'build_sha256 differs from bundle_sha256'
        }
        if ($exactMatch -isnot [bool] -or -not $exactMatch) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message 'exact_match must be true'
        }
        $buildDigest = if ($buildPath -is [string]) { Get-D32FileDigest -Path $buildPath } else { $null }
        $bundleDigest = if ($bundlePathValue -is [string]) { Get-D32FileDigest -Path $bundlePathValue } else { $null }
        if ($null -ne $buildDigest) {
            if ($buildBytesValid -and $buildBytesValue -ne $buildDigest.Length) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message "build_bytes=$buildBytes does not match file length=$($buildDigest.Length)"
            }
            if ((Test-D32Sha64 -Value $buildHash) -and $buildHash -cne $buildDigest.Hash) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message "build_sha256 does not match build file hash=$($buildDigest.Hash)"
            }
        }
        if ($null -ne $bundleDigest) {
            if ($bundleBytesValid -and $bundleBytesValue -ne $bundleDigest.Length) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message "bundle_bytes=$bundleBytes does not match file length=$($bundleDigest.Length)"
            }
            if ((Test-D32Sha64 -Value $bundleHash) -and $bundleHash -cne $bundleDigest.Hash) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message "bundle_sha256 does not match bundle file hash=$($bundleDigest.Hash)"
            }
        }
        if ($null -ne $buildDigest -and $null -ne $bundleDigest -and ($buildDigest.Hash -cne $bundleDigest.Hash -or $buildDigest.Length -ne $bundleDigest.Length)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check $artifactCheck -Message 'build and bundle files differ in hash or size'
        }
        elseif ($null -ne $buildDigest -and $null -ne $bundleDigest) {
            Add-D32Finding -Findings $Findings -Severity PASS -Check $artifactCheck -Message 'build==bundle hash/size verified'
        }
    }
    $declaredTotalValue = [Int64]0
    $declaredTotalValid = Test-D32NonNegativeInt64 -Value $declaredTotal -Parsed ([ref]$declaredTotalValue)
    if ($declaredTotalValid) {
        if ($declaredTotalValue -ne $totalBytes) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.total_bytes' -Message "total_bytes=$declaredTotal differs from artifact sum=$totalBytes"
        }
        else {
            Add-D32Finding -Findings $Findings -Severity PASS -Check 'bundle.total_bytes' -Message "total_bytes=$declaredTotal"
        }
    }
    else {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.total_bytes' -Message 'total_bytes is missing or not numeric'
    }
    $resources = Get-D32JsonProperty -Object $Bundle -Name 'runtime_resources'
    if (-not (Test-D32JsonProperty -Object $Bundle -Name 'runtime_resources') -or ($null -ne $resources -and $resources -isnot [Array])) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.runtime_resources' -Message 'runtime_resources must be an array'
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'bundle.runtime_resources' -Message 'runtime_resources array is present'
    }
}

function Test-D32UtcTimestamp {
    param([AllowNull()][object]$Value)

    if ($Value -isnot [string] -or [String]::IsNullOrWhiteSpace($Value)) {
        return $false
    }
    if ($Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|\+00:00)$') {
        return $false
    }
    try {
        $parseValue = if ($Value.EndsWith('Z', [StringComparison]::Ordinal)) { $Value.Substring(0, $Value.Length - 1) + '+00:00' } else { $Value }
        $fractionLength = 0
        if ($Value.Length -gt 19 -and $Value[19] -eq '.') {
            $fractionLength = $Value.IndexOfAny([char[]]@('Z', '+'), 20) - 20
        }
        $fractionFormat = if ($fractionLength -gt 0) { '.' + ('f' * $fractionLength) } else { '' }
        $format = "yyyy-MM-dd'T'HH:mm:ss${fractionFormat}zzz"
        $parsed = [DateTimeOffset]::ParseExact($parseValue, $format, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None)
        return $parsed.Offset -eq [TimeSpan]::Zero
    }
    catch {
        return $false
    }
}

function Test-D32IdentityDocumentsEqual {
    param([AllowNull()][object]$Left, [AllowNull()][object]$Right)

    $fields = @('FullName', 'Length', 'CreationTimeUtcTicks', 'LastWriteUtcTicks', 'Attributes', 'VolumeSerialHex', 'FileIdHex')
    $leftFindings = New-D32FindingList
    $rightFindings = New-D32FindingList
    if (-not (Test-D32IdentityDocument -Declared $Left -Actual $Left -Check 'identity.left' -Findings $leftFindings) -or
        -not (Test-D32IdentityDocument -Declared $Right -Actual $Right -Check 'identity.right' -Findings $rightFindings)) {
        return $false
    }
    foreach ($field in $fields) {
        $leftValue = Get-D32JsonProperty -Object $Left -Name $field
        $rightValue = Get-D32JsonProperty -Object $Right -Name $field
        if ($field -ceq 'FullName') {
            if ($leftValue -isnot [string] -or $rightValue -isnot [string] -or -not (Test-D32PathEqual -Left (Get-D32AbsolutePath -Path ([string]$leftValue)) -Right (Get-D32AbsolutePath -Path ([string]$rightValue)))) {
                return $false
            }
        }
        elseif ($field -in @('VolumeSerialHex', 'FileIdHex')) {
            if ($leftValue -isnot [string] -or $rightValue -isnot [string] -or $leftValue -cne $rightValue) { return $false }
        }
        elseif ([string]$leftValue -cne [string]$rightValue) {
            return $false
        }
    }
    return $true
}

function Test-D32TauriResourceMap {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    $configPath = Join-Path $Repository 'src-tauri\tauri.conf.json'
    if (-not (Test-D32NoReparseComponents -Path $configPath)) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.tauri-resources' -Message 'tauri.conf.json is missing or traverses a reparse point'
        return
    }
    $configLoaded = Read-D32EvidenceJson -Path $configPath -Findings $Findings -Check 'bundle.tauri-config'
    $config = if ($null -ne $configLoaded) { $configLoaded.Value } else { $null }
    $bundle = Get-D32JsonProperty -Object $config -Name 'bundle'
    $resources = Get-D32JsonProperty -Object $bundle -Name 'resources'
    $expectedSource = '../vita-agent/target/release/vita-agent.exe'
    $expectedDestination = 'vita-agent.exe'
    if ($null -eq $resources -or $resources -is [Array] -or $resources -is [string]) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.tauri-resources' -Message 'bundle.resources must be the existing single-entry object mapping'
        return
    }
    $properties = @($resources.PSObject.Properties)
    if ($properties.Count -ne 1 -or $properties[0].Name -cne $expectedSource -or $properties[0].Value -isnot [string] -or [string]$properties[0].Value -cne $expectedDestination) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.tauri-resources' -Message 'Tauri resource map must contain only the fixed vita-agent source to vita-agent.exe destination'
        return
    }
    Add-D32Finding -Findings $Findings -Severity PASS -Check 'bundle.tauri-resources' -Message 'existing sole Tauri sidecar resource mapping is exact; shipping configuration is unchanged'
}

function Get-D32FreshReleaseOutputRecords {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    $records = New-Object System.Collections.ArrayList
    foreach ($name in $script:D32BundleArtifactNames) {
        $relativeSource = [string]$script:D32BundleSourceRelativePaths[$name]
        $sourcePath = Get-D32AbsolutePath -Path (Join-Path $Repository $relativeSource)
        $relativeParent = Split-Path -Parent $relativeSource
        $current = Get-D32CanonicalPath -Path $Repository
        $parentIsSafe = $true
        foreach ($part in @($relativeParent -split '[\\/]+' | Where-Object { -not [String]::IsNullOrWhiteSpace($_) })) {
            $current = Join-Path $current $part
            try {
                $attributes = [System.IO.File]::GetAttributes($current)
            }
            catch [System.IO.FileNotFoundException] {
                break
            }
            catch [System.IO.DirectoryNotFoundException] {
                break
            }
            catch {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check "bundle.build.fresh-output.$name" -Message 'release output parent could not be inspected; refusing to build'
                $parentIsSafe = $false
                break
            }
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or ($attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check "bundle.build.fresh-output.$name" -Message 'release output parent is not a regular non-reparse directory; refusing to build'
                $parentIsSafe = $false
                break
            }
        }
        if (-not $parentIsSafe) { continue }

        $outputExists = $false
        try {
            [void][System.IO.File]::GetAttributes($sourcePath)
            $outputExists = $true
        }
        catch [System.IO.FileNotFoundException] {
            $outputExists = $false
        }
        catch [System.IO.DirectoryNotFoundException] {
            $outputExists = $false
        }
        catch {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check "bundle.build.fresh-output.$name" -Message 'release output path could not be inspected; refusing to build'
            continue
        }
        if ($outputExists) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check "bundle.build.fresh-output.$name" -Message 'fixed release artifact already exists; stale outputs are not accepted and no target data was modified'
            continue
        }
        [void]$records.Add([ordered]@{
            name = $name
            build_path = Get-D32AbsolutePath -Path $sourcePath
            absent_before_build = $true
        })
    }
    return ,$records.ToArray()
}

function Get-D32ExternalEvidenceReferenceSnapshot {
    param(
        [Parameter(Mandatory = $true)][object]$Reference,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string[]]$ExpectedFields
    )
    if (-not (Test-D32Phase0ExactProperties -Object $Reference -Expected $ExpectedFields)) { throw "$Name reference has missing or extra fields" }
    foreach ($field in @('path', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ($Reference.$field -isnot [string]) { throw "$Name.$field must be a JSON string" } }
    if (-not (Test-D32Phase0Integer -Value $Reference.bytes -Positive) -or $Reference.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $Reference.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or $Reference.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { throw "$Name bytes/SHA/opened-handle ID fields are malformed" }
    if (-not (Test-D32ProfileCanonicalPathString -Path $Reference.path) -or -not (Test-D32ProfileNoReparsePath -Path $Reference.path)) { throw "$Name path is not canonical regular-file path" }
    if ((Test-D32ProfilePathWithin -Child $Reference.path -Parent $Repository) -or (Test-D32ProfilePathWithin -Child $Repository -Parent $Reference.path)) { throw "$Name must be outside and non-overlapping with the candidate repository" }
    $snapshot = Get-D32ProfileFileSnapshot -Path $Reference.path
    if ($snapshot.Bytes -ne [Int64]$Reference.bytes -or $snapshot.Sha256 -cne $Reference.sha256 -or $snapshot.VolumeSerialHex -cne $Reference.volume_serial_hex -or $snapshot.FileIdHex -cne $Reference.file_id_hex) { throw "$Name current bytes/opened-handle file identity differs from its reference" }
    return $snapshot
}

function Test-D32ReleaseEvidenceBundle {
    param(
        [AllowNull()][object]$Bundle,
        [Parameter(Mandatory = $true)][string]$BundleFilePath,
        [AllowNull()][object]$Attestation,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$AttestationFilePath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$AttestationSha256,
        [AllowNull()][string]$Head,
        [Parameter(Mandatory = $true)][string]$Repository,
        [AllowNull()][string]$ExpectedPhase0RecordPath,
        [AllowNull()][string]$ExpectedPhase0RecordSha256,
        [AllowNull()][string]$ExpectedToolchainProfilePath,
        [AllowNull()][string]$ExpectedToolchainProfileSha256,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    $bundleFields = @('schema_version', 'candidate_sha', 'source_clone', 'bundle_path', 'attestation_path', 'attestation_sha256', 'build_targets', 'artifacts', 'total_bytes', 'runtime_resources')
    $attestationFields = @('schema_version', 'attestation_type', 'runner_process_id', 'candidate_sha', 'source_clone', 'git_status', 'build_profile', 'started_at_utc', 'completed_at_utc', 'cargo_path', 'cargo_sha256', 'cargo_identity', 'toolchain_profile', 'phase0_matrix', 'cargo_home', 'fresh_outputs', 'commands', 'artifacts')
    $artifactFields = @('name', 'build_path', 'bundle_path', 'build_bytes', 'bundle_bytes', 'build_sha256', 'bundle_sha256', 'build_identity', 'bundle_identity', 'exact_match')
    $attestedArtifactFields = @('name', 'build_path', 'build_bytes', 'build_sha256', 'build_identity')
    $commandFields = @('name', 'command', 'working_directory', 'argv', 'candidate_sha_before', 'git_status_before', 'started_at_utc', 'completed_at_utc', 'exit_code', 'process_id', 'root_process', 'descendant_processes', 'process_trace', 'process_tree_cleanup', 'stdout', 'stderr', 'candidate_sha_after', 'git_status_after')
    $freshOutputFields = @('name', 'build_path', 'absent_before_build')

    if ($null -eq $Bundle) {
        return
    }
    [void](Test-D32ExactObjectProperties -Object $Bundle -Expected $bundleFields -Check 'bundle.schema' -Findings $Findings)
    $bundleSchemaVersion = Get-D32JsonProperty -Object $Bundle -Name 'schema_version'
    $bundleSchemaValue = [Int64]0
    $bundleSchemaIsInteger = $null -ne $bundleSchemaVersion -and @([byte], [sbyte], [uint16], [int16], [uint32], [int32], [uint64], [int64]) -contains $bundleSchemaVersion.GetType()
    if (-not $bundleSchemaIsInteger -or -not (Test-D32NonNegativeInt64 -Value $bundleSchemaVersion -Parsed ([ref]$bundleSchemaValue)) -or $bundleSchemaValue -ne $script:D32BundleSchemaVersion) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.schema' -Message "schema_version must equal $($script:D32BundleSchemaVersion)"
    }
    if ($null -eq $Attestation) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.attestation' -Message 'build attestation is missing or unreadable'
        return
    }
    if (-not (Test-D32NoReparseComponents -Path $Repository)) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.repository' -Message 'candidate repository path is missing or traverses a reparse point'
    }
    [void](Test-D32ExactObjectProperties -Object $Attestation -Expected $attestationFields -Check 'attestation.schema' -Findings $Findings)
    $attestationSchemaVersion = Get-D32JsonProperty -Object $Attestation -Name 'schema_version'
    $attestationSchemaValue = [Int64]0
    $attestationSchemaIsInteger = $null -ne $attestationSchemaVersion -and @([byte], [sbyte], [uint16], [int16], [uint32], [int32], [uint64], [int64]) -contains $attestationSchemaVersion.GetType()
    if (-not $attestationSchemaIsInteger -or -not (Test-D32NonNegativeInt64 -Value $attestationSchemaVersion -Parsed ([ref]$attestationSchemaValue)) -or $attestationSchemaValue -ne $script:D32AttestationSchemaVersion -or (Get-D32JsonProperty -Object $Attestation -Name 'attestation_type') -cne 'D32_RELEASE_BUILD_ATTESTATION_V3') {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.schema' -Message 'attestation schema version or type is not the fixed D32 release-build format'
    }
    $attestationRunnerPid = Get-D32JsonProperty -Object $Attestation -Name 'runner_process_id'
    $attestationRunnerPidValue = [Int64]0
    if (-not (Test-D32NonNegativeInt64 -Value $attestationRunnerPid -Parsed ([ref]$attestationRunnerPidValue)) -or $attestationRunnerPidValue -le 0) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.runner' -Message 'runner_process_id must be a positive JSON integer'
    }

    $candidate = Get-D32JsonProperty -Object $Bundle -Name 'candidate_sha'
    $attestedCandidate = Get-D32JsonProperty -Object $Attestation -Name 'candidate_sha'
    if (-not (Test-D32Sha40 -Value $candidate) -or $null -ne $Head -and $candidate -cne $Head -or $attestedCandidate -cne $candidate) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.candidate_sha' -Message 'bundle and attestation candidate SHA must both equal the exact current HEAD'
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'bundle.candidate_sha' -Message "bundle and build attestation bind exact candidate SHA=$candidate"
    }

    $expectedRepo = Get-D32CanonicalPath -Path $Repository
    foreach ($entry in @(@{ Object = $Bundle; Field = 'source_clone'; Check = 'bundle.source_clone' }, @{ Object = $Attestation; Field = 'source_clone'; Check = 'attestation.source_clone' })) {
        $source = Get-D32JsonProperty -Object $entry.Object -Name $entry.Field
        try {
            if ($source -isnot [string] -or -not (Test-D32PathEqual -Left (Get-D32CanonicalPath -Path ([string]$source)) -Right $expectedRepo)) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check $entry.Check -Message 'source_clone does not resolve to the exact repository root'
            }
            else {
                Add-D32Finding -Findings $Findings -Severity PASS -Check $entry.Check -Message 'source_clone resolves to the exact repository root'
            }
        }
        catch {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check $entry.Check -Message $_.Exception.Message
        }
    }

    $bundleDirectory = $null
    $bundleFileCanonical = $null
    $attestationCanonical = $null
    try {
        $bundleDirectory = Get-D32CanonicalPath -Path (Split-Path -Parent $BundleFilePath)
        $bundleFileCanonical = Get-D32CanonicalPath -Path $BundleFilePath
        $attestationCanonical = Get-D32CanonicalPath -Path $AttestationFilePath
        if (-not (Test-D32NoReparseComponents -Path $BundleFilePath) -or -not (Test-D32NoReparseComponents -Path $AttestationFilePath)) {
            throw 'bundle manifest or attestation path traverses a reparse point'
        }
        if ([System.IO.Path]::GetFileName($BundleFilePath) -cne $script:D32BundleManifestName -or [System.IO.Path]::GetFileName($AttestationFilePath) -cne $script:D32AttestationName) {
            throw 'manifest and attestation filenames must use the fixed D32 evidence names'
        }
        if ([System.IO.Path]::GetFileName($bundleDirectory) -cne $script:D32BundleDirectoryName) {
            throw 'bundle manifest must be inside the fixed d32-gate-bundle directory'
        }
        $bundleParent = Get-D32CanonicalPath -Path (Split-Path -Parent $bundleDirectory)
        $attestationParent = Get-D32CanonicalPath -Path (Split-Path -Parent $attestationCanonical)
        if (-not (Test-D32PathEqual -Left $bundleParent -Right $attestationParent)) {
            throw 'attestation must be a sibling of the dedicated bundle directory under the evidence root'
        }
        if ((Test-D32PathInside -Child $bundleDirectory -Parent $expectedRepo) -or (Test-D32PathInside -Child $expectedRepo -Parent $bundleDirectory) -or (Test-D32PathInside -Child $attestationCanonical -Parent $expectedRepo) -or (Test-D32PathInside -Child $expectedRepo -Parent $attestationCanonical)) {
            throw 'gate evidence bundle and attestation must be outside and non-overlapping with the candidate clone'
        }
    }
    catch {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.path' -Message $_.Exception.Message
    }
    $declaredBundlePath = Get-D32JsonProperty -Object $Bundle -Name 'bundle_path'
    $declaredAttestationPath = Get-D32JsonProperty -Object $Bundle -Name 'attestation_path'
    if ($null -ne $bundleDirectory) {
        try {
            if ($declaredBundlePath -isnot [string] -or -not (Test-D32PathEqual -Left (Get-D32CanonicalPath -Path ([string]$declaredBundlePath)) -Right $bundleDirectory)) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.path' -Message 'bundle_path must equal the canonical manifest parent'
            }
            else {
                Add-D32Finding -Findings $Findings -Severity PASS -Check 'bundle.path' -Message 'bundle_path equals the canonical manifest parent'
            }
            if ($declaredAttestationPath -isnot [string] -or $null -eq $attestationCanonical -or -not (Test-D32PathEqual -Left (Get-D32CanonicalPath -Path ([string]$declaredAttestationPath)) -Right $attestationCanonical)) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.attestation-path' -Message 'manifest attestation_path must equal the explicitly supplied canonical attestation path'
            }
        }
        catch {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.path' -Message $_.Exception.Message
        }
    }

    $bundleDigest = Get-D32EvidenceFileDigest -Path $BundleFilePath
    $attestationDigest = Get-D32EvidenceFileDigest -Path $AttestationFilePath
    if ($null -eq $bundleDigest -or $null -eq $attestationDigest -or -not (Test-D32Sha64 -Value $AttestationSha256) -or $attestationDigest.Hash -cne $AttestationSha256) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.attestation-hash' -Message 'manifest-attestation binding does not match the stable current attestation file SHA-256'
    }
    elseif ((Get-D32JsonProperty -Object $Bundle -Name 'attestation_sha256') -cne $AttestationSha256) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.attestation-hash' -Message 'manifest attestation_sha256 differs from the explicitly validated attestation'
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'bundle.attestation-hash' -Message 'manifest binds the exact stable build-attestation bytes'
    }

    if ((Get-D32JsonProperty -Object $Attestation -Name 'git_status') -cne 'clean' -or (Get-D32JsonProperty -Object $Attestation -Name 'build_profile') -cne 'release') {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.clean-build' -Message 'attestation must record a clean working tree and release build profile'
    }
    $attestationStart = Get-D32JsonProperty -Object $Attestation -Name 'started_at_utc'
    $attestationEnd = Get-D32JsonProperty -Object $Attestation -Name 'completed_at_utc'
    $attestationTimesValid = Test-D32UtcTimestamp -Value $attestationStart
    $attestationTimesValid = $attestationTimesValid -and (Test-D32UtcTimestamp -Value $attestationEnd)
    if ($attestationTimesValid) {
        $attestationTimesValid = [DateTimeOffset]::Parse([string]$attestationEnd, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() -ge [DateTimeOffset]::Parse([string]$attestationStart, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    }
    if (-not $attestationTimesValid) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.timestamps' -Message 'attestation start/completion timestamps must be ordered UTC timestamps'
    }

    $cargoPath = Get-D32JsonProperty -Object $Attestation -Name 'cargo_path'
    $cargoHash = Get-D32JsonProperty -Object $Attestation -Name 'cargo_sha256'
    if ($cargoPath -isnot [string] -or [System.IO.Path]::GetFileName($cargoPath) -ine 'cargo.exe' -or -not (Test-D32Sha64 -Value $cargoHash)) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.cargo' -Message 'attestation must identify a regular cargo.exe image and lowercase SHA-256'
    }
    else {
        $cargoDigest = Get-D32EvidenceFileDigest -Path $cargoPath
        if ($null -eq $cargoDigest -or $cargoDigest.Hash -cne $cargoHash) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.cargo' -Message 'attested cargo.exe is missing, unstable, a reparse point, or has changed bytes'
        }
        else {
            [void](Test-D32IdentityDocument -Declared (Get-D32JsonProperty -Object $Attestation -Name 'cargo_identity') -Actual $cargoDigest.Identity -Check 'attestation.cargo' -Findings $Findings)
        }
    }

    $phase0OutputRoot = $null
    $phase0Document = $null
    $releaseToolchainProfile = $null
    $toolchainProfileReference = Get-D32JsonProperty -Object $Attestation -Name 'toolchain_profile'
    $phase0MatrixReference = Get-D32JsonProperty -Object $Attestation -Name 'phase0_matrix'
    $cargoHomeEvidence = Get-D32JsonProperty -Object $Attestation -Name 'cargo_home'
    try {
        $toolchainSnapshot = Get-D32ExternalEvidenceReferenceSnapshot -Reference $toolchainProfileReference -Name 'attestation.toolchain_profile' -Repository $Repository -ExpectedFields @('path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex')
        $phase0Snapshot = Get-D32ExternalEvidenceReferenceSnapshot -Reference $phase0MatrixReference -Name 'attestation.phase0_matrix' -Repository $Repository -ExpectedFields @('path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'candidate_sha', 'status')
        $expectedPhase0Pins = @($ExpectedPhase0RecordPath, $ExpectedPhase0RecordSha256, $ExpectedToolchainProfilePath, $ExpectedToolchainProfileSha256)
        $hasAnyExpectedPhase0Pin = @($expectedPhase0Pins | Where-Object { -not [String]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0
        $hasAllExpectedPhase0Pins = @($expectedPhase0Pins | Where-Object { [String]::IsNullOrWhiteSpace([string]$_) }).Count -eq 0
        if ($hasAnyExpectedPhase0Pin -and -not $hasAllExpectedPhase0Pins) { throw 'caller-pinned Phase0/profile path and SHA values must be supplied as a complete set' }
        if ($hasAllExpectedPhase0Pins -and
            (-not (Test-D32ProfilePathEqual -Left $phase0MatrixReference.path -Right $ExpectedPhase0RecordPath) -or $phase0Snapshot.Sha256 -cne $ExpectedPhase0RecordSha256 -or
             -not (Test-D32ProfilePathEqual -Left $toolchainProfileReference.path -Right $ExpectedToolchainProfilePath) -or $toolchainSnapshot.Sha256 -cne $ExpectedToolchainProfileSha256)) { throw 'attestation references do not match the independently caller-pinned Phase0 record/toolchain profile path and SHA values' }
        if (-not (Test-D32Sha64 -Value $toolchainProfileReference.sha256)) { throw 'toolchain profile SHA-256 is malformed' }
        if ($phase0MatrixReference.candidate_sha -isnot [string] -or $phase0MatrixReference.candidate_sha -cne $candidate -or $phase0MatrixReference.status -isnot [string] -or $phase0MatrixReference.status -cne 'PASS') { throw 'Phase0 matrix reference does not bind the exact candidate and local-only PASS status' }
        if ([IO.Path]::GetFileName([string]$phase0MatrixReference.path) -cne 'D32-PHASE0-MATRIX.json') { throw 'Phase0 matrix reference must use the fixed D32-PHASE0-MATRIX.json filename' }
        $phase0OutputRoot = [IO.Path]::GetDirectoryName([string]$phase0MatrixReference.path)
        $phase0Raw = [IO.File]::ReadAllText([string]$phase0MatrixReference.path, [Text.Encoding]::UTF8)
        if (Test-D32JsonDuplicateKeys -Json $phase0Raw) { throw 'referenced Phase0 matrix has duplicate/invalid JSON keys' }
        $phase0Document = $phase0Raw | ConvertFrom-D32Json
        $phase0Fields = @('schema_version', 'record_type', 'runner_process_id', 'candidate_sha', 'source_repo', 'output_root', 'status', 'bundle_hashes', 'started_at_utc', 'completed_at_utc', 'final_candidate_sha', 'final_clean', 'powershell', 'toolchain_profile', 'cargo_home', 'fetches', 'fixture', 'commands', 'test_inventory', 'local_suites', 'focused_tests', 'deferred_d31_tests', 'deferred_d29g2_provider_tests', 'not_run_capture_tests', 'governance_inputs', 'phase0_scope')
        if (-not (Test-D32Phase0ExactProperties -Object $phase0Document -Expected $phase0Fields) -or $phase0Document.schema_version -ne 2 -or $phase0Document.record_type -cne 'D32_PHASE0_MATRIX_RECORD_V2' -or $phase0Document.candidate_sha -cne $candidate -or $phase0Document.final_candidate_sha -cne $candidate -or $phase0Document.status -cne 'PASS' -or $phase0Document.bundle_hashes -cne 'PENDING' -or $phase0Document.final_clean -isnot [bool] -or -not $phase0Document.final_clean) { throw 'referenced Phase0 matrix has unsupported schema, candidate, status, clean state, or bundle-hash status' }
        if (-not (Test-D32ProfilePathEqual -Left $phase0Document.source_repo -Right $Repository) -or -not (Test-D32ProfilePathEqual -Left $phase0Document.output_root -Right $phase0OutputRoot)) { throw "referenced Phase0 source/output roots do not match current candidate and record path (source=$($phase0Document.source_repo); repository=$Repository; output=$($phase0Document.output_root); record_parent=$phase0OutputRoot)" }
        if (-not (Test-D32Phase0Integer -Value $phase0Document.schema_version) -or [Int64]$phase0Document.schema_version -ne 2 -or
            -not (Test-D32Phase0ExactProperties -Object $phase0Document.toolchain_profile -Expected @('path', 'sha256', 'file_identity', 'target_triple', 'toolchain', 'executable_inventory', 'script_inventory', 'windows_image_inventory', 'lock_inputs', 'env_policy')) -or
            -not (Test-D32Phase0ExactProperties -Object $phase0Document.toolchain_profile.file_identity -Expected @('bytes', 'volume_serial_hex', 'file_id_hex')) -or
            -not (Test-D32Phase0Integer -Value $phase0Document.toolchain_profile.file_identity.bytes -Positive) -or
            -not (Test-D32ProfilePathEqual -Left $phase0Document.toolchain_profile.path -Right $toolchainProfileReference.path) -or $phase0Document.toolchain_profile.sha256 -cne $toolchainProfileReference.sha256 -or
            $phase0Document.toolchain_profile.file_identity.bytes -ne $toolchainProfileReference.bytes -or $phase0Document.toolchain_profile.file_identity.volume_serial_hex -cne $toolchainProfileReference.volume_serial_hex -or $phase0Document.toolchain_profile.file_identity.file_id_hex -cne $toolchainProfileReference.file_id_hex) { throw 'Phase0 matrix does not bind the attested caller-pinned toolchain profile reference' }
        $releaseToolchainProfile = Test-D32BuildToolchainProfile -ProfilePath ([string]$toolchainProfileReference.path) -ExpectedSha256 ([string]$toolchainProfileReference.sha256) -Repository $Repository
        if (-not $releaseToolchainProfile.IsValid) { throw "caller-pinned v2 toolchain profile is not current: $($releaseToolchainProfile.Failure)" }
        $expectedScripts = @($releaseToolchainProfile.ScriptInventory | ForEach-Object { [ordered]@{ path = $_.Path; sha256 = $_.Sha256; bytes = [Int64]$_.Bytes; volume_serial_hex = $_.VolumeSerialHex; file_id_hex = $_.FileIdHex } })
        $expectedWindowsImages = @($releaseToolchainProfile.WindowsImageInventory | ForEach-Object { [ordered]@{ path = $_.Path; sha256 = $_.Sha256; bytes = [Int64]$_.Bytes; volume_serial_hex = $_.VolumeSerialHex; file_id_hex = $_.FileIdHex } })
        if ((ConvertTo-Json -InputObject $phase0Document.toolchain_profile.script_inventory -Depth 12 -Compress) -cne (ConvertTo-Json -InputObject $expectedScripts -Depth 12 -Compress) -or
            (ConvertTo-Json -InputObject $phase0Document.toolchain_profile.windows_image_inventory -Depth 12 -Compress) -cne (ConvertTo-Json -InputObject $expectedWindowsImages -Depth 12 -Compress)) { throw 'Phase0 matrix dormant-script/Windows-child inventory differs from the independently revalidated profile' }
        if (-not (Test-D32Phase0ExactProperties -Object $phase0Document.cargo_home -Expected @('path', 'temp_root', 'run_id', 'nonempty_after_fetch')) -or $phase0Document.cargo_home.nonempty_after_fetch -isnot [bool] -or -not $phase0Document.cargo_home.nonempty_after_fetch -or
            -not (Test-D32Phase0ExactProperties -Object $cargoHomeEvidence -Expected @('path', 'temp_root', 'run_id')) -or $cargoHomeEvidence.path -isnot [string] -or $cargoHomeEvidence.temp_root -isnot [string] -or $cargoHomeEvidence.run_id -isnot [string] -or
            -not (Test-D32ProfileCanonicalPathString -Path $cargoHomeEvidence.path) -or -not (Test-D32ProfileCanonicalPathString -Path $cargoHomeEvidence.temp_root) -or
            -not (Test-D32ProfilePathWithin -Child $cargoHomeEvidence.path -Parent $phase0OutputRoot) -or -not (Test-D32ProfilePathWithin -Child $cargoHomeEvidence.temp_root -Parent $phase0OutputRoot) -or
            -not (Test-D32ProfilePathEqual -Left $phase0Document.cargo_home.path -Right $cargoHomeEvidence.path) -or -not (Test-D32ProfilePathEqual -Left $phase0Document.cargo_home.temp_root -Right $cargoHomeEvidence.temp_root) -or $phase0Document.cargo_home.run_id -cne $cargoHomeEvidence.run_id) { throw 'attested Cargo home/temp/run ID do not match the validated Phase0 matrix reference' }
        $cargoHomeCheck = Test-D32CargoHome -Path $cargoHomeEvidence.path -Repository $Repository
        if ($cargoHomeCheck.Empty -or -not (Test-D32ProfileNoReparsePath -Path $cargoHomeEvidence.temp_root)) { throw 'attested Phase0 Cargo home is empty or its temp root is missing/reparse-backed' }
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'attestation.phase0-toolchain' -Message 'attestation profile and Phase0 references bind the exact current external bytes/opened-handle identities; Phase0 remains bundle_hashes=PENDING'
    }
    catch {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.phase0-toolchain' -Message $_.Exception.Message
    }

    $freshOutputs = Get-D32JsonProperty -Object $Attestation -Name 'fresh_outputs'
    if ($freshOutputs -isnot [Array] -or $freshOutputs.Count -ne $script:D32BundleArtifactNames.Count) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.fresh-outputs' -Message 'attestation must record the three fixed artifact paths as absent before this build'
    }
    else {
        $freshByName = @{}
        foreach ($fresh in $freshOutputs) {
            [void](Test-D32ExactObjectProperties -Object $fresh -Expected $freshOutputFields -Check 'attestation.fresh-output.schema' -Findings $Findings)
            $freshName = Get-D32JsonProperty -Object $fresh -Name 'name'
            $freshPath = Get-D32JsonProperty -Object $fresh -Name 'build_path'
            $absentBeforeBuild = Get-D32JsonProperty -Object $fresh -Name 'absent_before_build'
            if ($freshName -isnot [string] -or $script:D32BundleArtifactNames -cnotcontains $freshName -or $freshByName.ContainsKey([string]$freshName)) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.fresh-outputs' -Message 'fresh output names must be the unique fixed artifact set'
                continue
            }
            $freshByName[[string]$freshName] = $fresh
            $expectedFreshPath = Get-D32AbsolutePath -Path (Join-Path $Repository $script:D32BundleSourceRelativePaths[[string]$freshName])
            if ($freshPath -isnot [string] -or -not (Test-D32PathEqual -Left ([string]$freshPath) -Right $expectedFreshPath) -or $absentBeforeBuild -isnot [bool] -or -not $absentBeforeBuild) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.fresh-outputs' -Message "fresh output $freshName must bind its exact source path and boolean absent_before_build=true"
            }
        }
        if ($freshByName.Count -ne $script:D32BundleArtifactNames.Count) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.fresh-outputs' -Message 'fresh output evidence is missing one or more fixed artifacts'
        }
    }

    $commands = Get-D32JsonProperty -Object $Attestation -Name 'commands'
    if ($commands -isnot [Array] -or $commands.Count -ne $script:D32ReleaseBuildCommands.Count) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.commands' -Message 'attestation must record exactly the two fixed release-build commands in order'
    }
    else {
        for ($i = 0; $i -lt $script:D32ReleaseBuildCommands.Count; $i++) {
            $commandRecord = $commands[$i]
            [void](Test-D32ExactObjectProperties -Object $commandRecord -Expected $commandFields -Check "attestation.command.$i.schema" -Findings $Findings)
            $expectedCommand = $script:D32ReleaseBuildCommands[$i]
            $stringFields = @('name', 'command', 'working_directory', 'candidate_sha_before', 'git_status_before', 'started_at_utc', 'completed_at_utc', 'candidate_sha_after', 'git_status_after')
            foreach ($field in $stringFields) {
                if ((Get-D32JsonProperty -Object $commandRecord -Name $field) -isnot [string]) {
                    Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i.schema-types" -Message "command field $field must be a JSON string"
                }
            }
            $argv = Get-D32JsonProperty -Object $commandRecord -Name 'argv'
            if ($argv -isnot [Array] -or @($argv | Where-Object { $_ -isnot [string] }).Count -ne 0) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i.argv" -Message 'argv must be an exact array of JSON strings'
            }
            $commandStart = Get-D32JsonProperty -Object $commandRecord -Name 'started_at_utc'
            $commandEnd = Get-D32JsonProperty -Object $commandRecord -Name 'completed_at_utc'
            $commandName = Get-D32JsonProperty -Object $commandRecord -Name 'name'
            $commandText = Get-D32JsonProperty -Object $commandRecord -Name 'command'
            if ($commandName -isnot [string] -or $commandText -isnot [string] -or $commandName -cne $expectedCommand.name -or $commandText -cne $expectedCommand.command) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i" -Message 'recorded release command does not match the fixed D32 command/argument vector'
            }
            $expectedReleaseArgv = @([string]$cargoPath) + @($expectedCommand.arguments)
            if ($argv -isnot [Array] -or ($argv -join "`0") -cne ($expectedReleaseArgv -join "`0")) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i.argv" -Message "argv must equal the exact direct pinned Cargo path plus ADR-fixed command arguments (actual_type=$(if($null -eq $argv){'null'}else{$argv.GetType().FullName}); actual=$($argv -join '|'); expected=$($expectedReleaseArgv -join '|'))"
            }
            $workingDirectory = Get-D32JsonProperty -Object $commandRecord -Name 'working_directory'
            if ($workingDirectory -isnot [string] -or -not (Test-D32PathEqual -Left $workingDirectory -Right $expectedRepo)) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i" -Message 'command working_directory must be the canonical candidate repository string'
            }
            $exitCode = Get-D32JsonProperty -Object $commandRecord -Name 'exit_code'
            $processId = Get-D32JsonProperty -Object $commandRecord -Name 'process_id'
            $candidateBefore = Get-D32JsonProperty -Object $commandRecord -Name 'candidate_sha_before'
            $statusBefore = Get-D32JsonProperty -Object $commandRecord -Name 'git_status_before'
            $candidateAfter = Get-D32JsonProperty -Object $commandRecord -Name 'candidate_sha_after'
            $statusAfter = Get-D32JsonProperty -Object $commandRecord -Name 'git_status_after'
            $exitValue = [Int64]0
            $processValue = [Int64]0
            $exitValid = Test-D32NonNegativeInt64 -Value $exitCode -Parsed ([ref]$exitValue)
            $processValid = Test-D32NonNegativeInt64 -Value $processId -Parsed ([ref]$processValue)
            if (-not $exitValid -or $exitValue -ne 0 -or -not $processValid -or $processValue -le 0) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i" -Message 'each fixed release build must record exit_code=0 and a positive process_id'
            }
            if (-not (Test-D32Sha40 -Value $candidateBefore) -or $candidateBefore -cne $candidate -or $statusBefore -isnot [string] -or $statusBefore -cne 'clean') {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i.pre-state" -Message 'each fixed release build must begin at the attested candidate SHA with a clean working tree'
            }
            if (-not (Test-D32Sha40 -Value $candidateAfter) -or $candidateAfter -cne $candidate -or $statusAfter -isnot [string] -or $statusAfter -cne 'clean') {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i.post-state" -Message 'each fixed release build must end at the attested candidate SHA with a clean working tree'
            }
            if (-not (Test-D32UtcTimestamp -Value $commandStart) -or -not (Test-D32UtcTimestamp -Value $commandEnd)) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i" -Message 'command completion timestamps must be UTC'
            }
            elseif ([DateTimeOffset]::Parse([string]$commandEnd, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() -lt [DateTimeOffset]::Parse([string]$commandStart, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i" -Message 'command completion timestamp precedes command start'
            }

            $rootProcess = Get-D32JsonProperty -Object $commandRecord -Name 'root_process'
            $rootProcessFields = @('process_id', 'parent_process_id', 'name', 'image_path', 'command_line', 'creation_date', 'observed_at_utc', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'allowed_image_reason', 'identity_verified')
            $rootValid = Test-D32Phase0ExactProperties -Object $rootProcess -Expected $rootProcessFields
            if ($rootValid) {
                foreach ($field in @('name', 'image_path', 'command_line', 'creation_date', 'observed_at_utc', 'sha256', 'volume_serial_hex', 'file_id_hex', 'allowed_image_reason')) { if ($rootProcess.$field -isnot [string]) { $rootValid = $false } }
                if (-not (Test-D32Phase0Integer -Value $rootProcess.process_id -Positive) -or -not (Test-D32Phase0Integer -Value $rootProcess.parent_process_id -Positive) -or -not (Test-D32Phase0Integer -Value $rootProcess.bytes -Positive) -or $rootProcess.identity_verified -isnot [bool] -or -not $rootProcess.identity_verified) { $rootValid = $false }
                if ($rootProcess.name -cne 'cargo.exe' -or -not (Test-D32ProfilePathEqual -Left $rootProcess.image_path -Right $cargoPath) -or $rootProcess.parent_process_id -ne $attestationRunnerPidValue -or $rootProcess.process_id -ne $processValue -or $rootProcess.sha256 -cne $cargoHash -or $rootProcess.command_line -cne (ConvertTo-D32Phase0CommandLine -Arguments $expectedReleaseArgv)) { $rootValid = $false }
                if ($rootProcess.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $rootProcess.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or $rootProcess.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { $rootValid = $false }
                if ($null -ne $cargoDigest -and ($rootProcess.bytes -ne $cargoDigest.Length -or $rootProcess.volume_serial_hex -cne $cargoDigest.Identity.VolumeSerialHex -or $rootProcess.file_id_hex -cne $cargoDigest.Identity.FileIdHex)) { $rootValid = $false }
            }
            if (-not $rootValid) { Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i.process" -Message 'direct Cargo root-process path/hash/bytes/native ID/argv/parent identity does not match caller-pinned release evidence' }

            $descendants = Get-D32JsonProperty -Object $commandRecord -Name 'descendant_processes'
            try {
                if ($null -eq $releaseToolchainProfile -or -not $releaseToolchainProfile.IsValid) { throw 'caller-pinned v2 profile was not validated for the release process trace' }
                $null = Test-D32Phase0DebugProcessTrace -Trace (Get-D32JsonProperty -Object $commandRecord -Name 'process_trace') -ExpectedRootPath $cargoPath -ExpectedRootIdentity $releaseToolchainProfile.Profile.toolchain.cargo -ExpectedParentProcessId ([int]$attestationRunnerPidValue) -ValidatedProfile $releaseToolchainProfile -Repository $Repository
                $trace = Get-D32JsonProperty -Object $commandRecord -Name 'process_trace'
                $traceRoot = @($trace.processes | Where-Object { $_.create_sequence -eq 1 })
                $rootFileTime = [DateTime]::Parse([string]$rootProcess.creation_date, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime().ToFileTimeUtc()
                if ($traceRoot.Count -ne 1 -or $traceRoot[0].process_id -ne $rootProcess.process_id -or $traceRoot[0].creation_filetime -ne $rootFileTime -or
                    $traceRoot[0].parent_process_id -ne $rootProcess.parent_process_id -or $traceRoot[0].exit_code -ne $exitValue -or
                    -not (Test-D32ProfilePathEqual -Left $traceRoot[0].image_path -Right $rootProcess.image_path) -or
                    $traceRoot[0].sha256 -cne $rootProcess.sha256 -or $traceRoot[0].bytes -ne $rootProcess.bytes -or
                    $traceRoot[0].volume_serial_hex -cne $rootProcess.volume_serial_hex -or $traceRoot[0].file_id_hex -cne $rootProcess.file_id_hex) { throw 'release root process projection/exit differs from synchronized CREATE/EXIT evidence' }
                $traceChildren = @($trace.processes | Where-Object { $_.create_sequence -ne 1 })
                if ($descendants -isnot [Array] -or $descendants.Count -ne $traceChildren.Count) { throw 'legacy release descendant projection count differs from synchronized trace' }
                foreach ($traceChild in $traceChildren) {
                    $traceChildFileTime = [Int64]$traceChild.creation_filetime
                    $legacyChild = @($descendants | Where-Object {
                        $_.process_id -eq $traceChild.process_id -and
                        [DateTime]::Parse([string]$_.creation_date, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime().ToFileTimeUtc() -eq $traceChildFileTime
                    })
                    if ($legacyChild.Count -ne 1 -or
                        -not (Test-D32ProfilePathEqual -Left $legacyChild[0].image_path -Right $traceChild.image_path) -or
                        $legacyChild[0].parent_process_id -ne $traceChild.parent_process_id -or
                        $legacyChild[0].sha256 -cne $traceChild.sha256 -or $legacyChild[0].bytes -ne $traceChild.bytes -or
                        $legacyChild[0].volume_serial_hex -cne $traceChild.volume_serial_hex -or $legacyChild[0].file_id_hex -cne $traceChild.file_id_hex -or
                        $legacyChild[0].allowed_image_reason -cne $traceChild.allowed_image_reason) { throw 'legacy release descendant projection differs from synchronized CREATE evidence' }
                }
            }
            catch { Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i.process-trace" -Message $_.Exception.Message }

            $cleanup = Get-D32JsonProperty -Object $commandRecord -Name 'process_tree_cleanup'
            if (-not (Test-D32Phase0ExactProperties -Object $cleanup -Expected @('launch_mode', 'job_close_succeeded', 'process_wait_signaled', 'active_process_count_verified', 'active_process_count', 'debugger_thread_id', 'debugger_thread_exited', 'debugger_thread_joined', 'debugger_kill_on_exit_enabled', 'retained_process_handle_count', 'retained_process_handles_signaled', 'debugger_association_query_verified', 'debugger_association_absent', 'cleanup_succeeded', 'detail')) -or
                $cleanup.launch_mode -cne 'DedicatedOSDebuggerThread(CreateProcessW(DEBUG_PROCESS|CREATE_SUSPENDED)+DebugSetProcessKillOnExit(TRUE)+ResumeThread+WaitForDebugEvent+ContinueDebugEvent)+EXTENDED_STARTUP_INFO+HANDLE_LIST(stdout/stderr)+AssignProcessToJobObject(KILL_ON_JOB_CLOSE)' -or
                $cleanup.job_close_succeeded -isnot [bool] -or -not $cleanup.job_close_succeeded -or $cleanup.process_wait_signaled -isnot [bool] -or -not $cleanup.process_wait_signaled -or
                $cleanup.active_process_count_verified -isnot [bool] -or -not $cleanup.active_process_count_verified -or -not (Test-D32Phase0Integer -Value $cleanup.active_process_count) -or $cleanup.active_process_count -ne 0 -or
                $cleanup.debugger_thread_id -ne $commandRecord.process_trace.debugger_thread_id -or
                $cleanup.debugger_thread_exited -isnot [bool] -or -not $cleanup.debugger_thread_exited -or
                $cleanup.debugger_thread_joined -isnot [bool] -or -not $cleanup.debugger_thread_joined -or
                $cleanup.debugger_kill_on_exit_enabled -isnot [bool] -or -not $cleanup.debugger_kill_on_exit_enabled -or
                $cleanup.retained_process_handle_count -ne $commandRecord.process_trace.retained_process_handle_count -or
                $cleanup.retained_process_handles_signaled -isnot [bool] -or -not $cleanup.retained_process_handles_signaled -or
                $cleanup.debugger_association_query_verified -isnot [bool] -or -not $cleanup.debugger_association_query_verified -or
                $cleanup.debugger_association_absent -isnot [bool] -or -not $cleanup.debugger_association_absent -or
                $cleanup.cleanup_succeeded -isnot [bool] -or -not $cleanup.cleanup_succeeded -or $cleanup.detail -isnot [string]) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i.process-tree" -Message 'release command lacks verified native Job Object cleanup and zero active-process proof'
            }
            $descendants = Get-D32JsonProperty -Object $commandRecord -Name 'descendant_processes'
            if ($descendants -isnot [Array]) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i.descendants" -Message "descendant_processes must be an array of observed child process identities (actual_type=$(if($null -eq $descendants){'null'}else{$descendants.GetType().FullName}))"
            }
            else {
                $seenProcessIdentities = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                if ($rootProcess -and (Test-D32Phase0Integer -Value $rootProcess.process_id -Positive) -and $rootProcess.creation_date -is [string]) {
                    try { [void]$seenProcessIdentities.Add("$($rootProcess.process_id)|$([DateTime]::Parse([string]$rootProcess.creation_date, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime().ToFileTimeUtc())") } catch { }
                }
                foreach ($child in $descendants) {
                    $childFields = @('process_id', 'parent_process_id', 'name', 'image_path', 'command_line', 'creation_date', 'observed_at_utc', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'allowed_image_reason', 'identity_verified')
                    $childValid = Test-D32Phase0ExactProperties -Object $child -Expected $childFields
                    if ($childValid) {
                        foreach ($field in @('name', 'image_path', 'command_line', 'creation_date', 'observed_at_utc', 'sha256', 'volume_serial_hex', 'file_id_hex', 'allowed_image_reason')) { if ($child.$field -isnot [string]) { $childValid = $false } }
                        if (-not (Test-D32Phase0Integer -Value $child.process_id -Positive) -or -not (Test-D32Phase0Integer -Value $child.parent_process_id -Positive) -or -not (Test-D32Phase0Integer -Value $child.bytes -Positive) -or $child.identity_verified -isnot [bool] -or -not $child.identity_verified) { $childValid = $false }
                        if ($child.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $child.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or $child.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { $childValid = $false }
                    }
                    $childIdentityKey = $null
                    if ($childValid) { try { $childIdentityKey = "$($child.process_id)|$([DateTime]::Parse([string]$child.creation_date, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime().ToFileTimeUtc())" } catch { $childValid = $false } }
                    if (-not $childValid -or -not $seenProcessIdentities.Add([string]$childIdentityKey)) { Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i.descendants" -Message 'release descendant non-recycled identity is malformed or duplicated'; continue }
                    try {
                        $childImage = Get-D32ProfileFileSnapshot -Path $child.image_path
                        if ($childImage.Sha256 -cne $child.sha256 -or $childImage.Bytes -ne [Int64]$child.bytes -or $childImage.VolumeSerialHex -cne $child.volume_serial_hex -or $childImage.FileIdHex -cne $child.file_id_hex) { throw 'current child image identity mismatch' }
                        $phase0ToolInventory = @($phase0Document.toolchain_profile.executable_inventory + $phase0Document.toolchain_profile.windows_image_inventory | ForEach-Object { [PSCustomObject]@{ Path = $_.path; Sha256 = $_.sha256; Bytes = $_.bytes; VolumeSerialHex = $_.volume_serial_hex; FileIdHex = $_.file_id_hex } })
                        $pinnedChild = @($phase0ToolInventory | Where-Object { Test-D32ProfilePathEqual -Left $_.Path -Right $child.image_path })
                        if ($pinnedChild.Count -eq 0 -and -not ((Test-D32ProfilePathWithin -Child $child.image_path -Parent (Join-Path $Repository 'vita-agent\target\release')) -or (Test-D32ProfilePathWithin -Child $child.image_path -Parent (Join-Path $Repository 'src-tauri\target\release')))) { throw 'child image is not pinned or under a fixed candidate release target' }
                        if ($pinnedChild.Count -gt 1) { throw 'child image occurs multiple times in pinned executable inventory' }
                        if ($pinnedChild.Count -eq 1 -and ($pinnedChild[0].Sha256 -cne $child.sha256 -or [Int64]$pinnedChild[0].Bytes -ne [Int64]$child.bytes -or $pinnedChild[0].VolumeSerialHex -cne $child.volume_serial_hex -or $pinnedChild[0].FileIdHex -cne $child.file_id_hex)) { throw 'child image does not match pinned tool profile' }
                    }
                    catch { Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i.descendants" -Message $_.Exception.Message }
                }
            }
            try {
                $externalEvidenceRoot = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($BundleFilePath)))
                $null = Test-D32Phase0FileReference -Reference $commandRecord.stdout -AllowedRoot $externalEvidenceRoot
                $null = Test-D32Phase0FileReference -Reference $commandRecord.stderr -AllowedRoot $externalEvidenceRoot
            }
            catch { Add-D32Finding -Findings $Findings -Severity ERROR -Check "attestation.command.$i.logs" -Message $_.Exception.Message }
        }
    }

    $targets = Get-D32JsonProperty -Object $Bundle -Name 'build_targets'
    [void](Test-D32ExactObjectProperties -Object $targets -Expected @('vita', 'host') -Check 'bundle.build_targets.schema' -Findings $Findings)
    $expectedVitaTarget = Get-D32AbsolutePath -Path (Join-Path $Repository 'vita-agent\target\release')
    $expectedHostTarget = Get-D32AbsolutePath -Path (Join-Path $Repository 'src-tauri\target\release')
    foreach ($targetSpec in @(@{ Name = 'vita'; Path = $expectedVitaTarget }, @{ Name = 'host'; Path = $expectedHostTarget })) {
        $declaredTarget = Get-D32JsonProperty -Object $targets -Name $targetSpec.Name
        if ($declaredTarget -isnot [string] -or -not (Test-D32PathEqual -Left ([string]$declaredTarget) -Right $targetSpec.Path) -or -not (Test-Path -LiteralPath $targetSpec.Path -PathType Container)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.build_targets' -Message "build_targets.$($targetSpec.Name) must equal the fixed release directory under the candidate clone"
        }
    }

    $attestedArtifacts = Get-D32JsonProperty -Object $Attestation -Name 'artifacts'
    $artifacts = Get-D32JsonProperty -Object $Bundle -Name 'artifacts'
    if ($attestedArtifacts -isnot [Array] -or $artifacts -isnot [Array] -or $attestedArtifacts.Count -ne 3 -or $artifacts.Count -ne 3) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.artifacts' -Message 'attestation and bundle must each contain exactly three artifact records'
        return
    }
    $attestedByName = @{}
    $bundleByName = @{}
    foreach ($item in $attestedArtifacts) {
        [void](Test-D32ExactObjectProperties -Object $item -Expected $attestedArtifactFields -Check 'attestation.artifact.schema' -Findings $Findings)
        $name = Get-D32JsonProperty -Object $item -Name 'name'
        if ($name -isnot [string] -or $script:D32BundleArtifactNames -cnotcontains $name -or $attestedByName.ContainsKey([string]$name)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.artifacts' -Message 'attestation artifact names must be the unique fixed three-name set'
        }
        else { $attestedByName[[string]$name] = $item }
    }
    foreach ($item in $artifacts) {
        [void](Test-D32ExactObjectProperties -Object $item -Expected $artifactFields -Check 'bundle.artifact.schema' -Findings $Findings)
        $name = Get-D32JsonProperty -Object $item -Name 'name'
        if ($name -isnot [string] -or $script:D32BundleArtifactNames -cnotcontains $name -or $bundleByName.ContainsKey([string]$name)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.artifacts' -Message 'bundle artifact names must be the unique fixed three-name set'
        }
        else { $bundleByName[[string]$name] = $item }
    }
    if ($attestedByName.Count -ne 3 -or $bundleByName.Count -ne 3) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.artifacts' -Message 'one or more required artifact names are absent'
    }

    $expectedEntries = @($script:D32BundleArtifactNames + $script:D32BundleManifestName)
    if ($null -ne $bundleDirectory) {
        try {
            $entries = @(Get-ChildItem -LiteralPath $bundleDirectory -Force -ErrorAction Stop)
            $entryNames = @($entries | ForEach-Object { [string]$_.Name })
            if ($entries.Count -ne $expectedEntries.Count -or @($expectedEntries | Where-Object { $entryNames -cnotcontains $_ }).Count -gt 0 -or @($entryNames | Where-Object { $expectedEntries -cnotcontains $_ }).Count -gt 0) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.contents' -Message 'bundle directory must contain only the three flat artifacts and BUNDLE-MANIFEST.json'
            }
            foreach ($entry in $entries) {
                if ($entry.PSIsContainer -or ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or -not (Test-D32NoReparseComponents -Path $entry.FullName)) {
                    Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.contents' -Message "bundle entry is a directory or reparse point: $($entry.Name)"
                }
            }
        }
        catch {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.contents' -Message $_.Exception.Message
        }
    }

    $totalBytes = [Int64]0
    foreach ($name in $script:D32BundleArtifactNames) {
        if (-not $attestedByName.ContainsKey($name) -or -not $bundleByName.ContainsKey($name)) { continue }
        $attested = $attestedByName[$name]
        $record = $bundleByName[$name]
        $relativeSource = [string]$script:D32BundleSourceRelativePaths[$name]
        $expectedSource = Get-D32AbsolutePath -Path (Join-Path $Repository $relativeSource)
        $expectedDestination = Get-D32AbsolutePath -Path (Join-Path $bundleDirectory $name)
        $buildPath = Get-D32JsonProperty -Object $record -Name 'build_path'
        $attestedPath = Get-D32JsonProperty -Object $attested -Name 'build_path'
        $destinationPath = Get-D32JsonProperty -Object $record -Name 'bundle_path'
        if ($buildPath -isnot [string] -or $attestedPath -isnot [string] -or -not (Test-D32PathEqual -Left ([string]$buildPath) -Right $expectedSource) -or -not (Test-D32PathEqual -Left ([string]$attestedPath) -Right $expectedSource)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check "bundle.artifact.$name.path" -Message 'source path must equal the fixed release output path for this artifact'
        }
        if ($destinationPath -isnot [string] -or -not (Test-D32PathEqual -Left ([string]$destinationPath) -Right $expectedDestination)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check "bundle.artifact.$name.path" -Message 'destination must be the exact flat artifact filename directly under bundle_path'
        }
        $buildDigest = Get-D32EvidenceFileDigest -Path $expectedSource
        $destinationDigest = Get-D32EvidenceFileDigest -Path $expectedDestination
        $declaredBuildBytes = Get-D32JsonProperty -Object $record -Name 'build_bytes'
        $declaredBundleBytes = Get-D32JsonProperty -Object $record -Name 'bundle_bytes'
        $declaredBuildHash = Get-D32JsonProperty -Object $record -Name 'build_sha256'
        $declaredBundleHash = Get-D32JsonProperty -Object $record -Name 'bundle_sha256'
        $attestedBytes = Get-D32JsonProperty -Object $attested -Name 'build_bytes'
        $attestedHash = Get-D32JsonProperty -Object $attested -Name 'build_sha256'
        if ($null -eq $buildDigest -or $null -eq $destinationDigest) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check "bundle.artifact.$name.file" -Message 'source or destination is missing, unstable, reparse-backed, or unreadable'
            continue
        }
        [void](Test-D32IdentityDocument -Declared (Get-D32JsonProperty -Object $record -Name 'build_identity') -Actual $buildDigest.Identity -Check "bundle.artifact.$name.build" -Findings $Findings)
        [void](Test-D32IdentityDocument -Declared (Get-D32JsonProperty -Object $record -Name 'bundle_identity') -Actual $destinationDigest.Identity -Check "bundle.artifact.$name.bundle" -Findings $Findings)
        if (-not (Test-D32IdentityDocumentsEqual -Left (Get-D32JsonProperty -Object $record -Name 'build_identity') -Right (Get-D32JsonProperty -Object $attested -Name 'build_identity'))) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check "bundle.artifact.$name.attestation" -Message 'manifest source identity differs from the build attestation'
        }
        $declaredBuildBytesValue = [Int64]0
        $declaredBundleBytesValue = [Int64]0
        $attestedBytesValue = [Int64]0
        $declaredBuildBytesValid = Test-D32NonNegativeInt64 -Value $declaredBuildBytes -Parsed ([ref]$declaredBuildBytesValue)
        $declaredBundleBytesValid = Test-D32NonNegativeInt64 -Value $declaredBundleBytes -Parsed ([ref]$declaredBundleBytesValue)
        $attestedBytesValid = Test-D32NonNegativeInt64 -Value $attestedBytes -Parsed ([ref]$attestedBytesValue)
        if (-not $declaredBuildBytesValid -or $declaredBuildBytesValue -ne $buildDigest.Length -or -not $attestedBytesValid -or $attestedBytesValue -ne $buildDigest.Length -or -not $declaredBundleBytesValid -or $declaredBundleBytesValue -ne $destinationDigest.Length -or $buildDigest.Length -ne $destinationDigest.Length) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check "bundle.artifact.$name.bytes" -Message 'attested, source, and flat destination byte counts must exactly match current files'
        }
        if (-not (Test-D32Sha64 -Value $declaredBuildHash) -or -not (Test-D32Sha64 -Value $declaredBundleHash) -or -not (Test-D32Sha64 -Value $attestedHash) -or $declaredBuildHash -cne $buildDigest.Hash -or $declaredBundleHash -cne $destinationDigest.Hash -or $attestedHash -cne $buildDigest.Hash -or $buildDigest.Hash -cne $destinationDigest.Hash) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check "bundle.artifact.$name.sha256" -Message 'attested, source, and destination SHA-256 values must exactly match current bytes'
        }
        if ((Get-D32JsonProperty -Object $record -Name 'exact_match') -isnot [bool] -or -not (Get-D32JsonProperty -Object $record -Name 'exact_match')) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check "bundle.artifact.$name.exact-match" -Message 'exact_match must be boolean true'
        }
        $totalBytes += [Int64]$buildDigest.Length
    }
    $declaredTotal = Get-D32JsonProperty -Object $Bundle -Name 'total_bytes'
    $declaredTotalValue = [Int64]0
    $declaredTotalValid = Test-D32NonNegativeInt64 -Value $declaredTotal -Parsed ([ref]$declaredTotalValue)
    if (-not $declaredTotalValid -or $declaredTotalValue -ne $totalBytes) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.total_bytes' -Message 'total_bytes must equal the sum of the three current release artifacts'
    }
    $resourcesProperty = $Bundle.PSObject.Properties['runtime_resources']
    $resources = $null
    if ($null -ne $resourcesProperty) { $resources = $resourcesProperty.Value }
    if ($null -eq $resourcesProperty -or $resources -isnot [Array] -or $resources.Count -ne 0) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'bundle.runtime_resources' -Message 'runtime_resources must be exactly an empty array; Tauri shipping resources remain separate'
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'bundle.runtime_resources' -Message 'gate evidence bundle carries no Tauri runtime resources'
    }
    Test-D32TauriResourceMap -Repository $Repository -Findings $Findings
}

function New-D32PostBundleAggregateFileReference {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Repository
    )

    if (-not (Test-D32NoReparseComponents -Path $Path)) { throw "aggregate source is missing or reparse-backed: $Path" }
    $snapshot = Get-D32EvidenceFileDigest -Path $Path
    if ($null -eq $snapshot) { throw "aggregate source is not a stable regular file: $Path" }
    if ((Test-D32PathInside -Child $snapshot.Path -Parent $Repository) -or (Test-D32PathInside -Child $Repository -Parent $snapshot.Path)) {
        throw "aggregate source must be external to and non-overlapping with the candidate repository: $Path"
    }
    return [ordered]@{
        path = [string]$snapshot.Path
        bytes = [Int64]$snapshot.Length
        sha256 = [string]$snapshot.Hash
        volume_serial_hex = [string]$snapshot.Identity.VolumeSerialHex
        file_id_hex = [string]$snapshot.Identity.FileIdHex
    }
}

function Test-D32PostBundleAggregateFileReference {
    param(
        [AllowNull()][object]$Reference,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$Repository
    )

    if (-not (Test-D32Phase0ExactProperties -Object $Reference -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) { throw "$Name reference has missing or extra fields" }
    foreach ($field in @('path', 'sha256', 'volume_serial_hex', 'file_id_hex')) { if ($Reference.$field -isnot [string]) { throw "$Name.$field must be a JSON string" } }
    if (-not (Test-D32Phase0Integer -Value $Reference.bytes -Positive) -or $Reference.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $Reference.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or $Reference.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { throw "$Name bytes/SHA/opened-handle identity fields are malformed" }
    if (-not (Test-D32ProfileCanonicalPathString -Path $Reference.path) -or -not (Test-D32ProfileNoReparsePath -Path $Reference.path)) { throw "$Name path is not a canonical regular-file path" }
    if (-not (Test-D32ProfilePathEqual -Left $Reference.path -Right $ExpectedPath)) { throw "$Name path differs from its explicit command-line source" }
    if ((Test-D32PathInside -Child $Reference.path -Parent $Repository) -or (Test-D32PathInside -Child $Repository -Parent $Reference.path)) { throw "$Name must be external to and non-overlapping with the candidate repository" }
    $snapshot = Get-D32EvidenceFileDigest -Path $Reference.path
    if ($null -eq $snapshot -or $snapshot.Length -ne [Int64]$Reference.bytes -or $snapshot.Hash -cne $Reference.sha256 -or $snapshot.Identity.VolumeSerialHex -cne $Reference.volume_serial_hex -or $snapshot.Identity.FileIdHex -cne $Reference.file_id_hex) {
        throw "$Name current bytes/opened-handle identity differ from the aggregate reference"
    }
    return $snapshot
}

function Test-D32PostBundleAggregateReadiness {
    param(
        [Parameter(Mandatory = $true)][object]$Validation,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    if (-not $Validation.Success) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'aggregate.inputs' -Message 'base candidate/provenance/Phase0/bundle validation did not succeed'
        return $false
    }
    $requiredPasses = @(
        'git.trusted-image', 'git.head', 'git.clean', 'git.expected-sha', 'phase0.record',
        'governance.index', 'governance.model-routing', 'provenance.candidate_sha', 'provenance.source_repo', 'provenance.image_path',
        'provenance.image_sha256', 'provenance.git_status', 'provenance.build_profile', 'provenance.build_command',
        'fixture-manifest.candidate_sha', 'fixture-manifest.source_repo', 'fixture-manifest.policy', 'fixture-manifest.cleanup',
        'bundle.candidate_sha', 'bundle.source_clone', 'bundle.path', 'bundle.attestation-hash', 'bundle.runtime_resources',
        'bundle.tauri-resources', 'bundle.total_bytes', 'attestation.phase0-toolchain', 'd32.modes'
    )
    foreach ($check in $requiredPasses) {
        $matches = @($Validation.Findings | Where-Object { $_.Check -ceq $check -and $_.Severity -ceq 'PASS' })
        if ($matches.Count -lt 1) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'aggregate.required-evidence' -Message "required validated evidence is absent: $check"
        }
    }
    if (@($Validation.Findings | Where-Object { $_.Check -ceq 'governance.files' -and $_.Severity -ceq 'PASS' }).Count -ne 7) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'aggregate.required-evidence' -Message 'the exact seven required governance inputs were not validated'
    }
    if (@($Validation.Findings | Where-Object { $_.Check -ceq 'bundle.build_targets' -and $_.Severity -ceq 'PASS' }).Count -ne 2) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'aggregate.required-evidence' -Message 'both fixed Cargo release target directories were not validated'
    }
    foreach ($spec in $script:D32FixtureSpecs) {
        $check = "fixture-manifest.$($spec.name)"
        if (@($Validation.Findings | Where-Object { $_.Check -ceq $check -and $_.Severity -ceq 'PASS' }).Count -ne 1) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'aggregate.required-evidence' -Message "Phase0 fixture output was not independently validated: $($spec.name)"
        }
    }
    foreach ($name in $script:D32BundleArtifactNames) {
        $check = "bundle.artifact.$name"
        if (@($Validation.Findings | Where-Object { $_.Check -ceq $check -and $_.Severity -ceq 'PASS' }).Count -ne 1) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'aggregate.required-evidence' -Message "bundle artifact hash/bytes/file identity was not verified: $name"
        }
    }
    if (@($Validation.Findings | Where-Object { $_.Severity -ceq 'ERROR' }).Count -gt 0) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'aggregate.inputs' -Message 'one or more candidate, governance, provenance, bundle, or Phase0 checks contain errors'
        return $false
    }
    Add-D32Finding -Findings $Findings -Severity PASS -Check 'aggregate.local-scope' -Message 'exact-SHA governance/provenance, verified bundle hashes and Tauri map, and the fully validated Phase0 provider/tool, ordered local mode, and cleanup evidence satisfy the pre-downstream local scope; deferred real gates remain NOT RUN'
    return $true
}

function Test-D32PostBundleAggregateRecord {
    param(
        [Parameter(Mandatory = $true)][string]$RecordPath,
        [Parameter(Mandatory = $true)][string]$ExpectedRecordSha256,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$Phase0RecordPath,
        [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
        [Parameter(Mandatory = $true)][string]$FixtureManifestPath,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$BundleManifestPath,
        [Parameter(Mandatory = $true)][string]$AttestationPath,
        [Parameter(Mandatory = $true)][string]$TrustedGitPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    try {
        if ($ExpectedRecordSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'aggregate record needs an independent lowercase SHA-256 pin' }
        $repo = Get-D32CanonicalPath -Path $Repository
        $evidence = Get-D32CanonicalPath -Path $EvidenceRoot
        if (-not (Test-D32NoReparseComponents -Path $evidence) -or (Test-D32PathInside -Child $evidence -Parent $repo) -or (Test-D32PathInside -Child $repo -Parent $evidence)) { throw 'aggregate evidence root is missing, reparse-backed, or overlaps the candidate repository' }
        $expectedRecord = Join-Path $evidence $script:D32PostBundleAggregateRecordName
        $recordPathMatches = Test-D32PathEqual -Left (Get-D32AbsolutePath -Path $RecordPath) -Right $expectedRecord
        $recordPathIsNoReparse = Test-D32NoReparseComponents -Path $RecordPath
        if (-not $recordPathMatches -or -not $recordPathIsNoReparse) { throw "aggregate record path must be the fixed regular file beneath the supplied external evidence root (path_match=$recordPathMatches; non_reparse=$recordPathIsNoReparse)" }
        $recordDigest = Get-D32EvidenceFileDigest -Path $RecordPath
        if ($null -eq $recordDigest -or $recordDigest.Hash -cne $ExpectedRecordSha256) { throw 'aggregate record bytes do not match the independently supplied SHA-256' }
        $raw = [IO.File]::ReadAllText($RecordPath, [Text.Encoding]::UTF8)
        if (Test-D32JsonDuplicateKeys -Json $raw) { throw 'aggregate record has duplicate object keys or invalid JSON' }
        $record = $raw | ConvertFrom-D32Json
        $recordFields = @('schema_version', 'record_type', 'scope', 'candidate_sha', 'source_repo', 'evidence_root', 'status', 'bundle_hashes', 'downstream_gates', 'references')
        if (-not (Test-D32Phase0ExactProperties -Object $record -Expected $recordFields)) { throw 'aggregate record has missing or extra top-level fields' }
        if (-not (Test-D32Phase0Integer -Value $record.schema_version) -or [Int64]$record.schema_version -ne $script:D32PostBundleAggregateSchemaVersion -or
            $record.record_type -isnot [string] -or $record.record_type -cne $script:D32PostBundleAggregateRecordType -or
            $record.scope -isnot [string] -or $record.scope -cne $script:D32PostBundleAggregateScope -or
            $record.candidate_sha -isnot [string] -or $record.candidate_sha -cne $ExpectedCandidateSha -or
            $record.source_repo -isnot [string] -or -not (Test-D32PathEqual -Left $record.source_repo -Right $repo) -or
            $record.evidence_root -isnot [string] -or -not (Test-D32PathEqual -Left $record.evidence_root -Right $evidence) -or
            $record.status -isnot [string] -or $record.status -cne 'PRE_DOWNSTREAM_AGGREGATE_PASS' -or
            $record.bundle_hashes -isnot [string] -or $record.bundle_hashes -cne 'VERIFIED' -or
            $record.downstream_gates -isnot [string] -or $record.downstream_gates -cne 'NOT RUN') { throw 'aggregate record version/type/scope/candidate/repository/evidence-root/status/bundle/downstream binding is invalid' }
        $expectedBundleManifest = Join-Path (Join-Path $evidence $script:D32BundleDirectoryName) $script:D32BundleManifestName
        $expectedAttestation = Join-Path $evidence $script:D32AttestationName
        if (-not (Test-D32PathEqual -Left (Get-D32AbsolutePath -Path $BundleManifestPath) -Right $expectedBundleManifest) -or -not (Test-D32PathEqual -Left (Get-D32AbsolutePath -Path $AttestationPath) -Right $expectedAttestation)) { throw 'bundle manifest and attestation must be the fixed siblings under the aggregate evidence root' }
        $references = $record.references
        $referenceFields = @('phase0_matrix', 'toolchain_profile', 'fixture_manifest', 'provenance_manifest', 'bundle_manifest', 'attestation', 'trusted_git')
        if (-not (Test-D32Phase0ExactProperties -Object $references -Expected $referenceFields)) { throw 'aggregate record references object has missing or extra evidence sources' }
        $expectedSources = [ordered]@{
            phase0_matrix = $Phase0RecordPath
            toolchain_profile = $ToolchainProfilePath
            fixture_manifest = $FixtureManifestPath
            provenance_manifest = $ManifestPath
            bundle_manifest = $BundleManifestPath
            attestation = $AttestationPath
            trusted_git = $TrustedGitPath
        }
        foreach ($name in $referenceFields) {
            $null = Test-D32PostBundleAggregateFileReference -Reference $references.$name -Name "aggregate.references.$name" -ExpectedPath ([string]$expectedSources[$name]) -Repository $repo
        }
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'aggregate.record' -Message "independently SHA-pinned pre-downstream aggregate record binds a validated local-scope pass, VERIFIED bundle hashes, NOT RUN downstream gates, this candidate, and all seven current external source files; record SHA-256=$($recordDigest.Hash)"
        return [PSCustomObject]@{ IsValid = $true; Record = $record; Digest = $recordDigest.Hash; Identity = $recordDigest.Identity; RecordPath = $recordDigest.Path; EvidenceRoot = $evidence }
    }
    catch {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'aggregate.record' -Message $_.Exception.Message
        return [PSCustomObject]@{ IsValid = $false; Failure = $_.Exception.Message }
    }
}

function ConvertTo-D32FixtureCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][hashtable]$Spec
    )

    $manifest = [System.IO.Path]::GetFullPath((Join-Path $Repository $Spec.manifest)).Replace('/', '\')
    $command = "cargo build --quiet --locked --manifest-path $manifest --bin $($Spec.binary)"
    if (@($Spec.features).Count -gt 0) {
        $command += " --features $(@($Spec.features) -join ' ')"
    }
    return $command
}

function Test-D32FixtureManifest {
    param(
        [AllowNull()][object]$FixtureManifest,
        [Parameter(Mandatory = $true)][string]$FixtureManifestPath,
        [AllowNull()][string]$Head,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings
    )

    if ($null -eq $FixtureManifest) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.file' -Message "fixture manifest is missing or unreadable: $FixtureManifestPath"
        return
    }
    Test-D32FixtureSchemaObject -Object $FixtureManifest -Schema $script:D32FixtureSchema -Path 'fixture-manifest' -Findings $Findings
    $manifestElapsed = Get-D32JsonProperty -Object $FixtureManifest -Name 'elapsed_ms'
    if ($null -ne $manifestElapsed) {
        try {
            if ([double]$manifestElapsed -lt 0) {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.schema' -Message 'fixture-manifest.elapsed_ms must be non-negative'
            }
        }
        catch {
            # The recursive schema validator owns type errors and has already
            # emitted the bounded diagnostic for a non-numeric value.
        }
    }
    $workingTreeStatus = Get-D32JsonProperty -Object $FixtureManifest -Name 'working_tree_status'
    if ($null -ne $workingTreeStatus -and ([string]$workingTreeStatus -cne '')) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.schema' -Message 'fixture-manifest.working_tree_status must be empty'
    }
    $schema = Get-D32JsonProperty -Object $FixtureManifest -Name 'schema_version'
    if ($schema -ne $script:D32FixtureSchemaVersion) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.schema' -Message "schema_version=$schema expected $($script:D32FixtureSchemaVersion)"
    }
    $candidate = Get-D32JsonProperty -Object $FixtureManifest -Name 'candidate_sha'
    if (-not (Test-D32Sha40 -Value $candidate)) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.candidate_sha' -Message 'fixture candidate_sha must be lowercase 40-hex'
    }
    elseif ($null -ne $Head -and $candidate -cne $Head) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.candidate_sha' -Message "fixture candidate_sha=$candidate does not equal exact HEAD=$Head"
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'fixture-manifest.candidate_sha' -Message "fixture candidate_sha=$candidate"
    }
    $sourceRepo = Get-D32JsonProperty -Object $FixtureManifest -Name 'source_repo'
    try {
        $expectedSource = Get-D32RustRepositoryPath -Path $Repository
        if (-not ($sourceRepo -is [string]) -or -not (Test-D32PathEqual -Left ([string]$sourceRepo) -Right $expectedSource)) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.source_repo' -Message "source_repo does not match repository root: $sourceRepo"
        }
        else {
            Add-D32Finding -Findings $Findings -Severity PASS -Check 'fixture-manifest.source_repo' -Message 'source_repo matches repository root'
        }
    }
    catch {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.source_repo' -Message $_.Exception.Message
    }
    $policy = Get-D32JsonProperty -Object $FixtureManifest -Name 'build_policy'
    if ($null -eq $policy) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.policy' -Message 'build_policy is missing'
    }
    else {
        $nested = Get-D32JsonProperty -Object $policy -Name 'nested_builds'
        $action = Get-D32JsonProperty -Object $policy -Name 'process_tree_timeout_action'
        $timeout = Get-D32JsonProperty -Object $policy -Name 'timeout_seconds'
        $jobs = Get-D32JsonProperty -Object $policy -Name 'cargo_build_jobs'
        if ($nested -ne $false -or $timeout -isnot [ValueType] -or [double]$timeout -le 0 -or $jobs -isnot [ValueType] -or [double]$jobs -le 0 -or $action -cne $script:D32FixtureProcessTreePolicy) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.policy' -Message 'bounded existing-only build policy is not exact'
        }
        else {
            Add-D32Finding -Findings $Findings -Severity PASS -Check 'fixture-manifest.policy' -Message 'bounded existing-only build policy validated'
        }
    }
    $processCheck = Get-D32JsonProperty -Object $FixtureManifest -Name 'process_tree_check'
    $processError = Get-D32JsonProperty -Object $FixtureManifest -Name 'process_tree_error'
    if ($processCheck -cne 'succeeded' -or $null -ne $processError) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.cleanup' -Message 'global Cargo/rustc descendant cleanup did not succeed'
    }
    else {
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'fixture-manifest.cleanup' -Message 'global Cargo/rustc descendant cleanup validated'
    }
    $environment = Get-D32JsonProperty -Object $FixtureManifest -Name 'environment'
    if ($null -eq $environment) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.environment' -Message 'environment metadata is missing'
    }
    else {
        $environmentInvalid = @(@('original_userprofile', 'codex_home', 'userprofile', 'cargo_home', 'rustup_home') | Where-Object {
            $value = Get-D32JsonProperty -Object $environment -Name $_
            -not ($value -is [string]) -or [String]::IsNullOrWhiteSpace($value)
        })
        if ($environmentInvalid.Count -gt 0) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.environment' -Message "environment fields are missing: $($environmentInvalid -join ',')"
        }
    }
    $fixtures = Get-D32JsonProperty -Object $FixtureManifest -Name 'fixtures'
    if ($null -eq $fixtures -or $fixtures -isnot [Array] -or $fixtures.Count -ne $script:D32FixtureSpecs.Count) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.fixtures' -Message "expected exactly $($script:D32FixtureSpecs.Count) fixture records"
        return
    }
    $actualNames = @($fixtures | ForEach-Object { [string](Get-D32JsonProperty -Object $_ -Name 'name') })
    $expectedNames = @($script:D32FixtureSpecs | ForEach-Object { $_.name })
    if (($actualNames -join '|') -cne ($expectedNames -join '|')) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.fixtures' -Message "fixture names/order are not the canonical five: $($actualNames -join ',')"
    }
    foreach ($spec in $script:D32FixtureSpecs) {
        $record = @($fixtures | Where-Object { (Get-D32JsonProperty -Object $_ -Name 'name') -ceq $spec.name })
        $check = "fixture-manifest.$($spec.name)"
        if ($record.Count -ne 1) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check $check -Message 'fixture record is missing or duplicated'
            continue
        }
        $record = $record[0]
        $recordErrors = [System.Collections.ArrayList]::new()
        if ((Get-D32JsonProperty -Object $record -Name 'phase') -ne $spec.phase) { [void]$recordErrors.Add('phase') }
        if ((Get-D32JsonProperty -Object $record -Name 'project') -cne $spec.project) { [void]$recordErrors.Add('project') }
        if ((Get-D32JsonProperty -Object $record -Name 'binary') -cne $spec.binary) { [void]$recordErrors.Add('binary') }
        $features = @((Get-D32JsonProperty -Object $record -Name 'features'))
        if (($features -join '|') -cne (@($spec.features) -join '|')) { [void]$recordErrors.Add('features') }
        if ((Get-D32JsonProperty -Object $record -Name 'status') -cne 'succeeded') { [void]$recordErrors.Add('status') }
        if ((Get-D32JsonProperty -Object $record -Name 'exit_code') -ne 0) { [void]$recordErrors.Add('exit_code') }
        if (@((Get-D32JsonProperty -Object $record -Name 'descendant_pids')).Count -ne 0) { [void]$recordErrors.Add('descendant_pids') }
        if ($null -eq (Get-D32JsonProperty -Object $record -Name 'pid')) { [void]$recordErrors.Add('pid') }
        if ($null -eq (Get-D32JsonProperty -Object $record -Name 'root_identity')) { [void]$recordErrors.Add('root_identity') }
        if ($null -eq (Get-D32JsonProperty -Object $record -Name 'elapsed_ms')) { [void]$recordErrors.Add('elapsed_ms') }
        if ($null -ne (Get-D32JsonProperty -Object $record -Name 'error')) { [void]$recordErrors.Add('error') }
        $expectedManifestPath = [System.IO.Path]::GetFullPath((Join-Path $Repository $spec.manifest))
        $declaredManifestPath = Get-D32JsonProperty -Object $record -Name 'manifest_path'
        if (-not ($declaredManifestPath -is [string]) -or -not (Test-D32PathEqual -Left ([string]$declaredManifestPath) -Right $expectedManifestPath)) { [void]$recordErrors.Add('manifest_path') }
        $expectedCommand = ConvertTo-D32FixtureCommand -Repository $Repository -Spec $spec
        if (([string](Get-D32JsonProperty -Object $record -Name 'command')).Replace('/', '\') -cne $expectedCommand) { [void]$recordErrors.Add('command') }
        $artifact = Get-D32JsonProperty -Object $record -Name 'artifact'
        $artifactPath = if ($null -ne $artifact) { Get-D32JsonProperty -Object $artifact -Name 'path' } else { $null }
        $artifactHash = if ($null -ne $artifact) { Get-D32JsonProperty -Object $artifact -Name 'sha256' } else { $null }
        $artifactBytes = if ($null -ne $artifact) { Get-D32JsonProperty -Object $artifact -Name 'bytes' } else { $null }
        $expectedArtifactPath = [System.IO.Path]::GetFullPath((Join-Path $Repository $spec.artifact))
        if (-not ($artifactPath -is [string]) -or -not (Test-D32PathEqual -Left ([string]$artifactPath) -Right $expectedArtifactPath)) { [void]$recordErrors.Add('artifact.path') }
        if (-not (Test-D32Sha64 -Value $artifactHash)) { [void]$recordErrors.Add('artifact.sha256') }
        $digest = if ($artifactPath -is [string]) { Get-D32FileDigest -Path $artifactPath } else { $null }
        if ($null -eq $digest) {
            [void]$recordErrors.Add('artifact.missing')
        }
        else {
            if ($artifactBytes -ne $digest.Length) { [void]$recordErrors.Add('artifact.bytes') }
            if (([string]$artifactHash) -cne $digest.Hash) { [void]$recordErrors.Add('artifact.hash_current') }
        }
        if ($recordErrors.Count -gt 0) {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check $check -Message "fixture metadata/artifact mismatch: $($recordErrors -join ',')"
        }
        else {
            Add-D32Finding -Findings $Findings -Severity PASS -Check $check -Message 'fixture schema, build metadata, path, hash, and size validated'
        }
    }
}

function Invoke-D32Validation {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Manifest,
        [Parameter(Mandatory = $true)][string]$Image,
        [Parameter(Mandatory = $true)][string]$BundleManifest,
        [AllowEmptyString()][string]$AttestationPath,
        [AllowNull()][string]$FixtureManifest,
        [AllowNull()][string]$TrustedGitPath,
        [AllowNull()][string]$TrustedGitSha256,
        [AllowNull()][string]$ExpectedCandidateSha,
        [AllowNull()][string]$Base,
        [AllowNull()][string]$MergeBase,
        [AllowNull()][string]$RunRoot,
        [AllowNull()][string[]]$Modes,
        [AllowNull()][string]$Phase0RecordPath,
        [AllowNull()][string]$Phase0RecordSha256,
        [AllowNull()][string]$ToolchainProfilePath,
        [AllowNull()][string]$ExpectedToolchainProfileSha256
    )

    $findings = New-D32FindingList
    $classification = Get-D32SecurityClassification
    Add-D32Finding -Findings $findings -Severity INFO -Check 'security.classification' -Message 'advisory_only=true; host_official_preflight_required=true; path/hash Git checks are not retained-handle authority'
    $trustedGit = Test-D32TrustedGitImage -Path $TrustedGitPath -ExpectedSha256 $TrustedGitSha256
    if (-not $trustedGit.IsValid) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'git.trusted-image' -Message "explicit trusted Git image is required and failed validation: $($trustedGit.Failure)"
    }
    else {
        Add-D32Finding -Findings $findings -Severity PASS -Check 'git.trusted-image' -Message 'explicit trusted Git regular/non-reparse image and SHA-256 validated (advisory only)'
    }
    $head = $null
    if (-not (Test-Path -LiteralPath $Repository -PathType Container)) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'repository' -Message "repository root is not an existing directory: $Repository"
    }
    elseif ($trustedGit.IsValid) {
        $head = Get-D32Head -Repository $Repository -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings
        [void](Test-D32GitClean -Repository $Repository -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings)
        Test-D32BaseInputs -Repository $Repository -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Head $head -Base $Base -MergeBase $MergeBase -Findings $findings
        if (-not [String]::IsNullOrWhiteSpace($ExpectedCandidateSha)) {
            if (-not (Test-D32Sha40 -Value $ExpectedCandidateSha)) {
                Add-D32Finding -Findings $findings -Severity ERROR -Check 'git.expected-sha' -Message "expected SHA is not lowercase 40-hex: $ExpectedCandidateSha"
            }
            elseif ($null -ne $head -and $ExpectedCandidateSha -cne $head) {
                Add-D32Finding -Findings $findings -Severity ERROR -Check 'git.expected-sha' -Message "expected SHA=$ExpectedCandidateSha does not equal exact HEAD=$head"
            }
            else {
                Add-D32Finding -Findings $findings -Severity PASS -Check 'git.expected-sha' -Message "exact expected SHA=$ExpectedCandidateSha"
            }
        }
    }
    Test-D32Governance -Repository $Repository -Findings $findings

    $phase0PinValues = @($Phase0RecordPath, $Phase0RecordSha256, $ToolchainProfilePath, $ExpectedToolchainProfileSha256)
    $hasAnyPhase0Pin = @($phase0PinValues | Where-Object { -not [String]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0
    $hasAllPhase0Pins = @($phase0PinValues | Where-Object { [String]::IsNullOrWhiteSpace([string]$_) }).Count -eq 0
    if ($hasAnyPhase0Pin -and -not $hasAllPhase0Pins) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'phase0.record' -Message 'Phase0 record/profile path and independently expected hashes must be supplied as a complete set'
    }
    elseif ($hasAllPhase0Pins -and $trustedGit.IsValid -and $null -ne $head) {
        $phase0Validation = Test-D32Phase0MatrixRecord -RecordPath $Phase0RecordPath -ExpectedRecordSha256 $Phase0RecordSha256 -Repository $Repository -ExpectedCandidateSha $head -ToolchainProfilePath $ToolchainProfilePath -ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256 -GitPath $TrustedGitPath -GitSha256 $TrustedGitSha256
        if (-not $phase0Validation.IsValid) {
            Add-D32Finding -Findings $findings -Severity ERROR -Check 'phase0.record' -Message "independently pinned Phase0 record failed current validation: $($phase0Validation.Failure)"
        }
        else {
            Add-D32Finding -Findings $findings -Severity PASS -Check 'phase0.record' -Message "caller-pinned Phase0 local matrix and build profile validated; status=PASS; bundle hashes=PENDING; record SHA-256=$($phase0Validation.Digest)"
        }
    }
    else {
        Add-D32Finding -Findings $findings -Severity INFO -Check 'phase0.record' -Message 'no independent Phase0 record/profile pins supplied; this ValidateOnly result is ARTIFACT_ONLY'
    }

    $manifestObject = $null
    if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'provenance.file' -Message "provenance manifest is missing: $Manifest"
    }
    else {
        $manifestObject = Read-D32Json -Path $Manifest -Findings $findings -Check 'provenance.json'
    }

    $releaseImageInput = Join-Path $Repository 'vita-agent\target\release\vita-agent.exe'
    $expectedImagePath = $null
    try {
        $expectedImagePath = if (Test-Path -LiteralPath $releaseImageInput) {
            Get-D32CanonicalPath -Path $releaseImageInput
        }
        else {
            Get-D32AbsolutePath -Path $releaseImageInput
        }
    }
    catch {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'image.canonical' -Message $_.Exception.Message
        $expectedImagePath = Get-D32AbsolutePath -Path $releaseImageInput
    }
    if (-not [String]::IsNullOrWhiteSpace($Image) -and -not (Test-D32PathEqual -Left (Get-D32AbsolutePath -Path $Image) -Right (Get-D32AbsolutePath -Path $releaseImageInput))) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'image.input' -Message "ImagePath must identify the fixed release image under vita-agent\\target\\release\\vita-agent.exe"
    }
    $imageInputToRead = if ([String]::IsNullOrWhiteSpace($Image)) { $releaseImageInput } else { $Image }
    $imageDigest = Get-D32FileDigest -Path $imageInputToRead
    if ($null -eq $imageDigest) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'image.file' -Message "release image is missing or unreadable: $imageInputToRead"
    }
    else {
        try {
            $actualImageCanonical = Get-D32CanonicalPath -Path $imageInputToRead
            if (-not (Test-D32PathEqual -Left $actualImageCanonical -Right $expectedImagePath)) {
                Add-D32Finding -Findings $findings -Severity ERROR -Check 'image.canonical' -Message "release image resolved to $actualImageCanonical, expected $expectedImagePath"
            }
            else {
                Add-D32Finding -Findings $findings -Severity PASS -Check 'image.canonical' -Message 'release image canonical path matches the Host release contract'
            }
        }
        catch {
            Add-D32Finding -Findings $findings -Severity ERROR -Check 'image.canonical' -Message $_.Exception.Message
        }
        Add-D32Finding -Findings $findings -Severity PASS -Check 'image.hash' -Message "release image SHA-256=$($imageDigest.Hash), bytes=$($imageDigest.Length)"
    }
    $expectedSourceRepo = $null
    try {
        $expectedSourceRepo = Get-D32RustRepositoryPath -Path $Repository
    }
    catch {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'repository.canonical' -Message $_.Exception.Message
        $expectedSourceRepo = Get-D32AbsolutePath -Path $Repository
    }
    Test-D32ProvenanceManifest -Manifest $manifestObject -Head $head -ExpectedSourceRepo $expectedSourceRepo -ExpectedImagePath $expectedImagePath -ImageDigest $imageDigest -Findings $findings

    $fixtureManifestObject = $null
    if ([String]::IsNullOrWhiteSpace($FixtureManifest)) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'fixture-manifest.file' -Message 'fixture manifest path is mandatory for a complete local D32 gate'
    }
    elseif (-not (Test-Path -LiteralPath $FixtureManifest -PathType Leaf)) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'fixture-manifest.file' -Message "fixture manifest is missing: $FixtureManifest"
    }
    else {
        $fixtureManifestObject = Read-D32Json -Path $FixtureManifest -Findings $findings -Check 'fixture-manifest.json'
    }
    Test-D32FixtureManifest -FixtureManifest $fixtureManifestObject -FixtureManifestPath $FixtureManifest -Head $head -Repository $Repository -Findings $findings

    $bundleObject = $null
    $bundleLoaded = $null
    if (-not (Test-Path -LiteralPath $BundleManifest -PathType Leaf)) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.file' -Message "bundle manifest is missing: $BundleManifest"
    }
    else {
        $bundleLoaded = Read-D32EvidenceJson -Path $BundleManifest -Findings $findings -Check 'bundle.json'
        if ($null -ne $bundleLoaded) { $bundleObject = $bundleLoaded.Value }
    }

    $attestationObject = $null
    $attestationDigest = $null
    if ([String]::IsNullOrWhiteSpace($AttestationPath)) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.attestation' -Message 'explicit build-attestation path is mandatory for a complete D32 evidence bundle'
    }
    elseif (-not (Test-Path -LiteralPath $AttestationPath -PathType Leaf)) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.attestation' -Message "build attestation is missing: $AttestationPath"
    }
    else {
        $attestationLoaded = Read-D32EvidenceJson -Path $AttestationPath -Findings $findings -Check 'attestation.json'
        if ($null -ne $attestationLoaded) {
            $attestationObject = $attestationLoaded.Value
            $attestationDigest = $attestationLoaded.Digest
        }
    }
    if ($null -ne $bundleObject) {
        $attestationSha = if ($null -ne $attestationDigest) { [string]$attestationDigest.Hash } else { '' }
        $bundleValidationPins = @{}
        if ($hasAllPhase0Pins) {
            $bundleValidationPins = @{
                ExpectedPhase0RecordPath = $Phase0RecordPath
                ExpectedPhase0RecordSha256 = $Phase0RecordSha256
                ExpectedToolchainProfilePath = $ToolchainProfilePath
                ExpectedToolchainProfileSha256 = $ExpectedToolchainProfileSha256
            }
        }
        Test-D32ReleaseEvidenceBundle -Bundle $bundleObject -BundleFilePath $BundleManifest -Attestation $attestationObject -AttestationFilePath ([string]$AttestationPath) -AttestationSha256 $attestationSha -Head $head -Repository $Repository -Findings $findings @bundleValidationPins
    }

    $modeResult = Test-D32RequestedModes -Modes $Modes -Findings $findings
    Test-D32RunOutputRoot -RunRoot $RunRoot -Manifest $Manifest -BundleManifest $BundleManifest -Attestation $AttestationPath -Findings $findings
    Add-D32Finding -Findings $findings -Severity INFO -Check 'provider.credentials' -Message 'provider/credential validation is intentionally delegated to Host official preflight; no credential, token, or profile secret was read'
    Add-D32Finding -Findings $findings -Severity INFO -Check 'aggregate.status' -Message 'ARTIFACT_ONLY: this validation pass has no separately caller-pinned post-bundle pre-downstream aggregate pass record'

    $errors = @($findings | Where-Object { $_.Severity -eq 'ERROR' })
    return [PSCustomObject]@{
        Success        = $errors.Count -eq 0
        Status         = if ($errors.Count -eq 0) { 'ARTIFACT_ONLY' } else { 'BLOCKED' }
        Findings       = $findings
        ValidatedModes  = if ($modeResult.IsValid) { [string[]]$modeResult.Modes } else { [string[]]@() }
        SecurityClassification = $classification
    }
}

function Invoke-D32GeneratePostBundleAggregateRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Manifest,
        [Parameter(Mandatory = $true)][string]$Image,
        [Parameter(Mandatory = $true)][string]$BundleManifest,
        [Parameter(Mandatory = $true)][string]$AttestationPath,
        [Parameter(Mandatory = $true)][string]$FixtureManifest,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$RecordPath,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$TrustedGitPath,
        [Parameter(Mandatory = $true)][string]$TrustedGitSha256,
        [Parameter(Mandatory = $true)][string]$Phase0RecordPath,
        [Parameter(Mandatory = $true)][string]$Phase0RecordSha256,
        [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
        [Parameter(Mandatory = $true)][string]$ExpectedToolchainProfileSha256
    )

    $findings = New-D32FindingList
    $classification = Get-D32SecurityClassification
    try {
        $repo = Get-D32CanonicalPath -Path $Repository
        $evidence = Get-D32CanonicalPath -Path $EvidenceRoot
        $expectedRecord = Join-Path $evidence $script:D32PostBundleAggregateRecordName
        $expectedBundle = Join-Path (Join-Path $evidence $script:D32BundleDirectoryName) $script:D32BundleManifestName
        $expectedAttestation = Join-Path $evidence $script:D32AttestationName
        if ($ExpectedCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or $TrustedGitSha256 -cnotmatch '^[0-9a-f]{64}$' -or $Phase0RecordSha256 -cnotmatch '^[0-9a-f]{64}$' -or $ExpectedToolchainProfileSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'aggregate generation requires exact independent candidate, Git, Phase0, and profile pins' }
        if (-not (Test-D32NoReparseComponents -Path $evidence) -or (Test-D32PathInside -Child $evidence -Parent $repo) -or (Test-D32PathInside -Child $repo -Parent $evidence)) { throw 'aggregate EvidenceRoot must exist, be non-reparse, and be external/non-overlapping' }
        if (-not (Test-D32PathEqual -Left (Get-D32AbsolutePath -Path $BundleManifest) -Right $expectedBundle) -or -not (Test-D32PathEqual -Left (Get-D32AbsolutePath -Path $AttestationPath) -Right $expectedAttestation)) { throw 'bundle manifest and attestation must be the fixed siblings beneath EvidenceRoot' }
        if (-not (Test-D32PathEqual -Left (Get-D32AbsolutePath -Path $RecordPath) -Right $expectedRecord) -or -not (Test-D32NoReparseComponents -Path (Split-Path -Parent $expectedRecord))) { throw 'aggregate record output must be the fixed filename in the external EvidenceRoot' }
        if (Test-Path -LiteralPath $expectedRecord) { throw 'refusing to overwrite an existing post-bundle aggregate record' }
        if (-not (Test-D32PathInside -Child $Manifest -Parent $repo) -or -not (Test-D32PathInside -Child $FixtureManifest -Parent $repo) -or -not (Test-D32PathInside -Child $Phase0RecordPath -Parent $repo) -or -not (Test-D32PathInside -Child $ToolchainProfilePath -Parent $repo) -or -not (Test-D32PathInside -Child $TrustedGitPath -Parent $repo)) { throw 'provenance, fixture, Phase0, profile, and pinned Git inputs must all be external to the candidate repository' }

        $validation = Invoke-D32Validation -Repository $repo -Manifest $Manifest -Image $Image -BundleManifest $BundleManifest -AttestationPath $AttestationPath -FixtureManifest $FixtureManifest -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -ExpectedCandidateSha $ExpectedCandidateSha -Base $null -MergeBase $null -RunRoot $null -Modes $script:D32CanonicalModes -Phase0RecordPath $Phase0RecordPath -Phase0RecordSha256 $Phase0RecordSha256 -ToolchainProfilePath $ToolchainProfilePath -ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256
        foreach ($finding in $validation.Findings) { [void]$findings.Add($finding) }
        $readyFindings = New-D32FindingList
        $ready = Test-D32PostBundleAggregateReadiness -Validation $validation -Findings $readyFindings
        foreach ($finding in $readyFindings) { [void]$findings.Add($finding) }
        if (-not $ready -or @($findings | Where-Object { $_.Severity -eq 'ERROR' }).Count -gt 0) {
            return [PSCustomObject]@{ Success = $false; Status = 'BLOCKED'; Findings = $findings; SecurityClassification = $classification }
        }

        $references = [ordered]@{
            phase0_matrix = New-D32PostBundleAggregateFileReference -Path $Phase0RecordPath -Repository $repo
            toolchain_profile = New-D32PostBundleAggregateFileReference -Path $ToolchainProfilePath -Repository $repo
            fixture_manifest = New-D32PostBundleAggregateFileReference -Path $FixtureManifest -Repository $repo
            provenance_manifest = New-D32PostBundleAggregateFileReference -Path $Manifest -Repository $repo
            bundle_manifest = New-D32PostBundleAggregateFileReference -Path $BundleManifest -Repository $repo
            attestation = New-D32PostBundleAggregateFileReference -Path $AttestationPath -Repository $repo
            trusted_git = New-D32PostBundleAggregateFileReference -Path $TrustedGitPath -Repository $repo
        }
        $document = [ordered]@{
            schema_version = $script:D32PostBundleAggregateSchemaVersion
            record_type = $script:D32PostBundleAggregateRecordType
            scope = $script:D32PostBundleAggregateScope
            candidate_sha = $ExpectedCandidateSha
            source_repo = $repo
            evidence_root = $evidence
            status = 'PRE_DOWNSTREAM_AGGREGATE_PASS'
            bundle_hashes = 'VERIFIED'
            downstream_gates = 'NOT RUN'
            references = $references
        }
        Write-D32JsonCreateNew -Path $expectedRecord -Value $document
        $recordDigest = Get-D32EvidenceFileDigest -Path $expectedRecord
        if ($null -eq $recordDigest) { throw 'created post-bundle aggregate record is not a stable regular external file' }
        $reopenedFindings = New-D32FindingList
        $reopened = Test-D32PostBundleAggregateRecord -RecordPath $expectedRecord -ExpectedRecordSha256 $recordDigest.Hash -Repository $repo -ExpectedCandidateSha $ExpectedCandidateSha -EvidenceRoot $evidence -Phase0RecordPath $Phase0RecordPath -ToolchainProfilePath $ToolchainProfilePath -FixtureManifestPath $FixtureManifest -ManifestPath $Manifest -BundleManifestPath $BundleManifest -AttestationPath $AttestationPath -TrustedGitPath $TrustedGitPath -Findings $reopenedFindings
        foreach ($finding in $reopenedFindings) { [void]$findings.Add($finding) }
        if (-not $reopened.IsValid) { throw "created post-bundle aggregate record did not reopen and validate: $($reopened.Failure)" }
        $postHead = Get-D32Head -Repository $repo -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings
        $postClean = Test-D32GitClean -Repository $repo -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings
        if ($postHead -cne $ExpectedCandidateSha -or -not $postClean) { throw 'candidate SHA or clean state changed while binding aggregate evidence inputs' }
        Add-D32Finding -Findings $findings -Severity INFO -Check 'aggregate.record.generated' -Message "created no-overwrite pre-downstream aggregate pass record; independent SHA-256 pin for the subsequent ValidateOnly run is $($recordDigest.Hash)"
        return [PSCustomObject]@{ Success = $true; Status = 'ARTIFACT_ONLY'; Findings = $findings; RecordPath = $recordDigest.Path; RecordSha256 = $recordDigest.Hash; SecurityClassification = $classification }
    }
    catch {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'aggregate.record.generate' -Message $_.Exception.Message
        return [PSCustomObject]@{ Success = $false; Status = 'BLOCKED'; Findings = $findings; SecurityClassification = $classification }
    }
}

function Invoke-D32GenerateManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Manifest,
        [Parameter(Mandatory = $true)][string]$Image,
        [AllowNull()][string]$TrustedGitPath,
        [AllowNull()][string]$TrustedGitSha256
    )

    $findings = New-D32FindingList
    $classification = Get-D32SecurityClassification
    Add-D32Finding -Findings $findings -Severity INFO -Check 'security.classification' -Message 'advisory_only=true; host_official_preflight_required=true; path/hash Git checks are not retained-handle authority'
    $trustedGit = Test-D32TrustedGitImage -Path $TrustedGitPath -ExpectedSha256 $TrustedGitSha256
    if (-not $trustedGit.IsValid) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'git.trusted-image' -Message "explicit trusted Git image is required and failed validation: $($trustedGit.Failure)"
    }
    else {
        Add-D32Finding -Findings $findings -Severity PASS -Check 'git.trusted-image' -Message 'explicit trusted Git regular/non-reparse image and SHA-256 validated (advisory only)'
    }
    if (Test-Path -LiteralPath $Manifest) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'provenance.generate' -Message "refusing to overwrite existing target manifest: $Manifest"
        return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
    }
    if (-not (Test-Path -LiteralPath $Repository -PathType Container)) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'repository' -Message "repository root is not an existing directory: $Repository"
    }
    $head = $null
    if ((Test-Path -LiteralPath $Repository -PathType Container) -and $trustedGit.IsValid) {
        $head = Get-D32Head -Repository $Repository -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings
        [void](Test-D32GitClean -Repository $Repository -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings)
    }
    $releaseImageInput = Join-Path $Repository 'vita-agent\target\release\vita-agent.exe'
    if (-not (Test-D32PathEqual -Left (Get-D32AbsolutePath -Path $Image) -Right (Get-D32AbsolutePath -Path $releaseImageInput))) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'image.input' -Message 'ImagePath must identify the fixed release image under vita-agent\\target\\release\\vita-agent.exe'
    }
    $source = $null
    try { $source = Get-D32RustRepositoryPath -Path $Repository } catch { Add-D32Finding -Findings $findings -Severity ERROR -Check 'provenance.source_repo' -Message $_.Exception.Message }
    $imageCanonical = $null
    try { $imageCanonical = Get-D32CanonicalPath -Path $Image } catch { Add-D32Finding -Findings $findings -Severity ERROR -Check 'provenance.image_path' -Message $_.Exception.Message }
    $digest = Get-D32FileDigest -Path $Image
    if ($null -eq $digest) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'image.file' -Message "release image is missing or unreadable: $Image"
    }
    if ($null -eq $head -or $null -eq $source -or $null -eq $imageCanonical -or $null -eq $digest -or @($findings | Where-Object { $_.Severity -eq 'ERROR' }).Count -gt 0) {
        return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
    }
    $document = [ordered]@{
        candidate_sha = $head
        source_repo = $source
        image_path = $imageCanonical
        image_sha256 = $digest.Hash
        git_status = 'clean'
        build_profile = 'release'
        build_command = $script:D32BuildCommand
    }
    $parent = Split-Path -Parent $Manifest
    $temporary = $null
    try {
        if (-not [String]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
            [void](New-Item -ItemType Directory -Path $parent -Force)
        }
        $json = $document | ConvertTo-Json -Depth 4
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        $temporary = Join-Path $parent ('.' + [System.IO.Path]::GetFileName($Manifest) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
        [System.IO.File]::WriteAllBytes($temporary, $utf8.GetBytes($json + [Environment]::NewLine))
        # File.Move(source, destination) has no overwrite overload in the
        # supported Windows PowerShell/.NET surface.  A target race therefore
        # fails closed instead of replacing a previously generated manifest.
        [System.IO.File]::Move($temporary, $Manifest)
        Add-D32Finding -Findings $findings -Severity PASS -Check 'provenance.generate' -Message "atomically created $Manifest"
    }
    catch {
        if ($temporary -and (Test-Path -LiteralPath $temporary)) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'provenance.generate' -Message $_.Exception.Message
        return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
    }
    return [PSCustomObject]@{ Success = $true; Findings = $findings; Manifest = $Manifest; SecurityClassification = $classification }
}

function Write-D32JsonCreateNew {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Value
    )

    $json = $Value | ConvertTo-Json -Depth 16
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $temporary = Join-Path (Split-Path -Parent $Path) ('.' + [System.IO.Path]::GetFileName($Path) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [System.IO.File]::WriteAllBytes($temporary, $utf8.GetBytes($json + [Environment]::NewLine))
        [System.IO.File]::Move($temporary, $Path)
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-D32GenerateBundle {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][string]$TrustedGitPath,
        [Parameter(Mandatory = $true)][string]$TrustedGitSha256,
        [Parameter(Mandatory = $true)][string]$Phase0RecordPath,
        [Parameter(Mandatory = $true)][string]$Phase0RecordSha256,
        [Parameter(Mandatory = $true)][string]$ToolchainProfilePath,
        [Parameter(Mandatory = $true)][string]$ExpectedToolchainProfileSha256
    )

    $findings = New-D32FindingList
    $classification = Get-D32SecurityClassification
    $startedAt = [DateTimeOffset]::UtcNow.ToString('o')
    if (-not (Test-D32Windows)) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.platform' -Message 'release evidence attestation requires the fixed Windows exe/DLL outputs'
    }
    if (-not (Test-D32NoReparseComponents -Path $Repository)) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.repository' -Message 'repository path is missing or traverses a reparse point'
    }
    $trustedGit = Test-D32TrustedGitImage -Path $TrustedGitPath -ExpectedSha256 $TrustedGitSha256
    if (-not $trustedGit.IsValid) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'git.trusted-image' -Message "explicit trusted Git image is required: $($trustedGit.Failure)"
    }
    $head = $null
    if ($trustedGit.IsValid -and (Test-Path -LiteralPath $Repository -PathType Container)) {
        $head = Get-D32Head -Repository $Repository -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings
        [void](Test-D32GitClean -Repository $Repository -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings)
    }
    if (-not (Test-D32Sha40 -Value $ExpectedCandidateSha) -or $null -eq $head -or $head -cne $ExpectedCandidateSha) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.candidate' -Message 'expected candidate SHA must be lowercase exact HEAD'
    }

    $phase0Validation = Test-D32Phase0MatrixRecord -RecordPath $Phase0RecordPath -ExpectedRecordSha256 $Phase0RecordSha256 -Repository $Repository -ExpectedCandidateSha $ExpectedCandidateSha -ToolchainProfilePath $ToolchainProfilePath -ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256 -GitPath $TrustedGitPath -GitSha256 $TrustedGitSha256
    if (-not $phase0Validation.IsValid) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.phase0' -Message "release command blocked because the independently pinned Phase0 record is invalid: $($phase0Validation.Failure)"
    }
    else {
        Add-D32Finding -Findings $findings -Severity PASS -Check 'bundle.build.phase0' -Message "caller-pinned Phase0 local matrix and toolchain profile validated; record=$($phase0Validation.RecordPath) sha256=$($phase0Validation.Digest)"
    }
    $toolchainProfileValidation = $null
    if ($phase0Validation.IsValid) {
        $toolchainProfileValidation = Test-D32BuildToolchainProfile -ProfilePath $ToolchainProfilePath -ExpectedSha256 $ExpectedToolchainProfileSha256 -Repository $Repository -EvidenceRoot $phase0Validation.OutputRoot
        if (-not $toolchainProfileValidation.IsValid) { Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.toolchain' -Message "pinned build toolchain profile failed current validation: $($toolchainProfileValidation.Failure)" }
    }

    try {
        $repoCanonical = Get-D32CanonicalPath -Path $Repository
        $evidenceFull = [System.IO.Path]::GetFullPath($EvidenceRoot)
        $evidenceParent = [System.IO.Path]::GetDirectoryName($evidenceFull)
        if (-not (Test-D32AbsoluteFilesystemPath -Path $evidenceFull) -or [String]::IsNullOrWhiteSpace($evidenceParent) -or -not (Test-Path -LiteralPath $evidenceParent -PathType Container) -or -not (Test-D32NoReparseComponents -Path $evidenceParent)) {
            Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.output' -Message 'EvidenceRoot must be an absolute new directory beneath an existing non-reparse parent'
        }
        elseif ((Test-D32PathInside -Child (Get-D32AbsolutePath -Path $evidenceFull) -Parent $repoCanonical) -or (Test-D32PathInside -Child $repoCanonical -Parent (Get-D32AbsolutePath -Path $evidenceFull))) {
            Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.output' -Message 'EvidenceRoot must be outside and non-overlapping with the candidate clone'
        }
        if (Test-Path -LiteralPath $evidenceFull) {
            Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.output' -Message 'EvidenceRoot already exists; refusing to overwrite evidence or user data'
        }
    }
    catch {
        $repoCanonical = $null
        $evidenceFull = $null
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.output' -Message $_.Exception.Message
    }
    Test-D32TauriResourceMap -Repository $Repository -Findings $findings
    $tauriConfigPath = Join-Path $Repository 'src-tauri\tauri.conf.json'
    $tauriConfigDigestBefore = Get-D32EvidenceFileDigest -Path $tauriConfigPath
    if (@($findings | Where-Object { $_.Severity -eq 'ERROR' }).Count -gt 0) {
        return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
    }

    $freshOutputRecords = Get-D32FreshReleaseOutputRecords -Repository $Repository -Findings $findings
    if (@($findings | Where-Object { $_.Severity -eq 'ERROR' }).Count -gt 0 -or $freshOutputRecords.Count -ne $script:D32BundleArtifactNames.Count) {
        return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
    }

    $cargoPath = [string]$toolchainProfileValidation.Profile.toolchain.cargo.path
    $cargoTool = $toolchainProfileValidation.Profile.toolchain.cargo
    $cargoSnapshot = Get-D32ProfileFileSnapshot -Path $cargoPath
    if ($cargoSnapshot.Sha256 -cne $cargoTool.sha256 -or $cargoSnapshot.Bytes -ne [Int64]$cargoTool.bytes -or $cargoSnapshot.VolumeSerialHex -cne $cargoTool.volume_serial_hex -or $cargoSnapshot.FileIdHex -cne $cargoTool.file_id_hex) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.cargo' -Message 'direct Cargo executable differs from the independently pinned profile identity'
        return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
    }
    $cargoEnvironment = $null
    try {
        $cargoEnvironment = Get-D32BuildToolchainEnvironment -ValidatedProfile $toolchainProfileValidation -CargoHome ([string]$phase0Validation.Record.cargo_home.path) -TempRoot ([string]$phase0Validation.Record.cargo_home.temp_root) -Offline $true
        if (-not ('D32FixtureNativeProcessV2' -as [type])) {
            $fixtureLauncher = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-fixture-prebuild.ps1'))
            $launcherOutput = @(& { . $fixtureLauncher -D32LauncherLibraryOnly } *>&1)
            if ($launcherOutput.Count -gt 16 -or -not ('D32FixtureNativeProcessV2' -as [type])) { throw 'shared native Job Object launcher did not initialize cleanly' }
        }
        $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $toolchainProfileValidation
    }
    catch {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.toolchain' -Message $_.Exception.Message
        return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
    }

    try {
        [void][System.IO.Directory]::CreateDirectory($evidenceFull)
        if (-not (Test-D32NoReparseComponents -Path $evidenceFull) -or @(Get-ChildItem -LiteralPath $evidenceFull -Force -ErrorAction Stop).Count -ne 0) {
            throw 'new EvidenceRoot was not created as an empty non-reparse directory'
        }
        $releaseLogRoot = Join-Path $evidenceFull 'logs'
        [void][System.IO.Directory]::CreateDirectory($releaseLogRoot)
        if (-not (Test-D32NoReparseComponents -Path $releaseLogRoot) -or @(Get-ChildItem -LiteralPath $releaseLogRoot -Force -ErrorAction Stop).Count -ne 0) { throw 'release log root was not created as an empty non-reparse directory' }
        $bundleDirectory = Join-Path $evidenceFull $script:D32BundleDirectoryName
        [void][System.IO.Directory]::CreateDirectory($bundleDirectory)
        if (-not (Test-D32NoReparseComponents -Path $bundleDirectory) -or @(Get-ChildItem -LiteralPath $bundleDirectory -Force -ErrorAction Stop).Count -ne 0) {
            throw 'new bundle directory was not created as an empty non-reparse directory'
        }
    }
    catch {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.output' -Message $_.Exception.Message
        return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
    }

    $commandRecords = [System.Collections.Generic.List[object]]::new()
    for ($commandIndex = 0; $commandIndex -lt $script:D32ReleaseBuildCommands.Count; $commandIndex++) {
        $fixedCommand = $script:D32ReleaseBuildCommands[$commandIndex]
        $headBeforeCommand = Get-D32Head -Repository $Repository -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings
        $cleanBeforeCommand = Test-D32GitClean -Repository $Repository -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings
        if ($headBeforeCommand -cne $ExpectedCandidateSha -or -not $cleanBeforeCommand) {
            Add-D32Finding -Findings $findings -Severity ERROR -Check "bundle.build.$($fixedCommand.name).pre-state" -Message 'candidate SHA or clean working tree changed before this fixed release command'
            return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
        }
        $commandStart = [DateTimeOffset]::UtcNow.ToString('o')
        try {
            $result = Invoke-D32Phase0PinnedProcess -Name $fixedCommand.name -Executable $cargoPath -Arguments $fixedCommand.arguments -WorkingDirectory $repoCanonical -LogPath (Join-Path $releaseLogRoot ('release-{0:D2}-{1}' -f ($commandIndex + 1), $fixedCommand.name)) -Environment $cargoEnvironment -TimeoutSeconds 7200 -ValidatedProfile $toolchainProfileValidation -Repository $repoCanonical -ExpectedCandidateSha $ExpectedCandidateSha -GitPath $TrustedGitPath -GitSha256 $TrustedGitSha256
            $commandEnd = [DateTimeOffset]::UtcNow.ToString('o')
            $commandRecord = [ordered]@{
                name = $fixedCommand.name
                command = $fixedCommand.command
                working_directory = $repoCanonical
                argv = @($cargoPath) + @($fixedCommand.arguments)
                candidate_sha_before = $result.candidate_sha_before
                git_status_before = if ($result.clean_before) { 'clean' } else { 'dirty' }
                started_at_utc = $commandStart
                completed_at_utc = $commandEnd
                exit_code = $result.exit_code
                process_id = [int]$result.root_process.process_id
                root_process = $result.root_process
                descendant_processes = @($result.descendant_processes)
                process_trace = $result.process_trace
                process_tree_cleanup = $result.process_tree_cleanup
                stdout = $result.stdout
                stderr = $result.stderr
                candidate_sha_after = $result.candidate_sha_after
                git_status_after = if ($result.clean_after) { 'clean' } else { 'dirty' }
            }
            $commandRecords.Add($commandRecord)
            if ($result.exit_code -ne 0) {
                Add-D32Finding -Findings $findings -Severity ERROR -Check "bundle.build.$($fixedCommand.name)" -Message "fixed release command completed with exit code $($result.exit_code)"
                return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
            }
            if ($result.candidate_sha_before -cne $ExpectedCandidateSha -or -not $result.clean_before -or $result.candidate_sha_after -cne $ExpectedCandidateSha -or -not $result.clean_after) {
                Add-D32Finding -Findings $findings -Severity ERROR -Check "bundle.build.$($fixedCommand.name).post-state" -Message 'candidate SHA or clean working tree changed during this fixed release command'
                return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
            }
            Add-D32Finding -Findings $findings -Severity PASS -Check "bundle.build.$($fixedCommand.name)" -Message "fixed release command completed with pinned toolchain and verified Job Object cleanup; process_id=$($result.root_process.process_id)"
        }
        catch {
            Add-D32Finding -Findings $findings -Severity ERROR -Check "bundle.build.$($fixedCommand.name)" -Message $_.Exception.Message
            return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
        }
    }

    $artifactRecords = @()
    foreach ($name in $script:D32BundleArtifactNames) {
        $sourcePath = Join-Path $Repository $script:D32BundleSourceRelativePaths[$name]
        $sourceDigest = Get-D32EvidenceFileDigest -Path $sourcePath
        if ($null -eq $sourceDigest) {
            Add-D32Finding -Findings $findings -Severity ERROR -Check "bundle.build.artifact.$name" -Message 'fixed release output is missing, unstable, reparse-backed, or unreadable'
            return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
        }
        $artifactRecords += [ordered]@{
            name = $name
            build_path = Get-D32AbsolutePath -Path $sourcePath
            build_bytes = $sourceDigest.Length
            build_sha256 = $sourceDigest.Hash
            build_identity = $sourceDigest.Identity
        }
    }
    $afterHead = Get-D32Head -Repository $Repository -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings
    $cleanAfterBuild = Test-D32GitClean -Repository $Repository -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings
    if ($afterHead -cne $ExpectedCandidateSha -or -not $cleanAfterBuild) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.clean' -Message 'candidate HEAD changed or the working tree became dirty during release builds'
        return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
    }
    $tauriConfigDigestAfter = Get-D32EvidenceFileDigest -Path $tauriConfigPath
    if ($null -eq $tauriConfigDigestBefore -or $null -eq $tauriConfigDigestAfter -or $tauriConfigDigestBefore.Hash -cne $tauriConfigDigestAfter.Hash -or -not (Test-D32FileIdentityEqual -Left $tauriConfigDigestBefore.Identity -Right $tauriConfigDigestAfter.Identity)) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.tauri-config' -Message 'Tauri resource map file changed identity or bytes during release builds'
        return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
    }

    $completedAt = [DateTimeOffset]::UtcNow.ToString('o')
    try {
        $bundleArtifactRecords = @()
        foreach ($artifact in $artifactRecords) {
            $name = [string]$artifact.name
            $source = Join-Path $Repository $script:D32BundleSourceRelativePaths[$name]
            $destination = Join-Path $bundleDirectory $name
            [System.IO.File]::Copy($source, $destination, $false)
            $sourceAfter = Get-D32EvidenceFileDigest -Path $source
            $destinationDigest = Get-D32EvidenceFileDigest -Path $destination
            if ($null -eq $sourceAfter -or $null -eq $destinationDigest -or $sourceAfter.Hash -cne $artifact.build_sha256 -or -not (Test-D32FileIdentityEqual -Left $artifact.build_identity -Right $sourceAfter.Identity) -or $destinationDigest.Hash -cne $sourceAfter.Hash -or $destinationDigest.Length -ne $sourceAfter.Length) {
                throw "artifact changed during evidence copy or failed exact destination verification: $name"
            }
            $bundleArtifactRecords += [ordered]@{
                name = $name
                build_path = $artifact.build_path
                bundle_path = Get-D32AbsolutePath -Path $destination
                build_bytes = $sourceAfter.Length
                bundle_bytes = $destinationDigest.Length
                build_sha256 = $sourceAfter.Hash
                bundle_sha256 = $destinationDigest.Hash
                build_identity = $sourceAfter.Identity
                bundle_identity = $destinationDigest.Identity
                exact_match = $true
            }
        }

        $attestationPath = Join-Path $evidenceFull $script:D32AttestationName
        $bundleManifestPath = Join-Path $bundleDirectory $script:D32BundleManifestName
        $attestationDocument = [ordered]@{
            schema_version = $script:D32AttestationSchemaVersion
            attestation_type = 'D32_RELEASE_BUILD_ATTESTATION_V3'
            runner_process_id = [int]$PID
            candidate_sha = $ExpectedCandidateSha
            source_clone = $repoCanonical
            git_status = 'clean'
            build_profile = 'release'
            started_at_utc = $startedAt
            completed_at_utc = $completedAt
            cargo_path = $cargoPath
            cargo_sha256 = $cargoDigest.Hash
            cargo_identity = $cargoDigest.Identity
            toolchain_profile = [ordered]@{
                path = $toolchainProfileValidation.ProfilePath
                sha256 = $toolchainProfileValidation.Digest
                bytes = [Int64]$toolchainProfileValidation.Identity.Bytes
                volume_serial_hex = [string]$toolchainProfileValidation.Identity.VolumeSerialHex
                file_id_hex = [string]$toolchainProfileValidation.Identity.FileIdHex
            }
            phase0_matrix = [ordered]@{
                path = $phase0Validation.RecordPath
                sha256 = $phase0Validation.Digest
                bytes = [Int64]$phase0Validation.Identity.Bytes
                volume_serial_hex = [string]$phase0Validation.Identity.VolumeSerialHex
                file_id_hex = [string]$phase0Validation.Identity.FileIdHex
                candidate_sha = $ExpectedCandidateSha
                status = 'PASS'
            }
            cargo_home = [ordered]@{
                path = [string]$phase0Validation.Record.cargo_home.path
                temp_root = [string]$phase0Validation.Record.cargo_home.temp_root
                run_id = [string]$phase0Validation.Record.cargo_home.run_id
            }
            fresh_outputs = @($freshOutputRecords)
            commands = @($commandRecords)
            artifacts = @($artifactRecords)
        }
        Write-D32JsonCreateNew -Path $attestationPath -Value $attestationDocument
        $attestationDigest = Get-D32EvidenceFileDigest -Path $attestationPath
        if ($null -eq $attestationDigest) { throw 'created attestation is not a stable regular file' }
        $bundleDocument = [ordered]@{
            schema_version = $script:D32BundleSchemaVersion
            candidate_sha = $ExpectedCandidateSha
            source_clone = $repoCanonical
            bundle_path = Get-D32AbsolutePath -Path $bundleDirectory
            attestation_path = Get-D32AbsolutePath -Path $attestationPath
            attestation_sha256 = $attestationDigest.Hash
            build_targets = [ordered]@{
                vita = Get-D32AbsolutePath -Path (Join-Path $Repository 'vita-agent\target\release')
                host = Get-D32AbsolutePath -Path (Join-Path $Repository 'src-tauri\target\release')
            }
            artifacts = @($bundleArtifactRecords)
            total_bytes = [Int64](($artifactRecords | Measure-Object -Property build_bytes -Sum).Sum)
            runtime_resources = @()
        }
        Write-D32JsonCreateNew -Path $bundleManifestPath -Value $bundleDocument
        $generatedBundleLoaded = Read-D32EvidenceJson -Path $bundleManifestPath -Findings $findings -Check 'bundle.build.generated-manifest'
        $generatedAttestationLoaded = Read-D32EvidenceJson -Path $attestationPath -Findings $findings -Check 'bundle.build.generated-attestation'
        if ($null -eq $generatedBundleLoaded -or $null -eq $generatedAttestationLoaded) { throw 'new bundle manifest/attestation could not be reopened through the independent evidence reader' }
        $generatedValidationFindings = New-D32FindingList
        Test-D32ReleaseEvidenceBundle -Bundle $generatedBundleLoaded.Value -BundleFilePath $bundleManifestPath -Attestation $generatedAttestationLoaded.Value -AttestationFilePath $attestationPath -AttestationSha256 ([string]$generatedAttestationLoaded.Digest.Hash) -Head $ExpectedCandidateSha -Repository $Repository -ExpectedPhase0RecordPath $phase0Validation.RecordPath -ExpectedPhase0RecordSha256 $phase0Validation.Digest -ExpectedToolchainProfilePath $toolchainProfileValidation.ProfilePath -ExpectedToolchainProfileSha256 $toolchainProfileValidation.Digest -Findings $generatedValidationFindings
        foreach ($generatedFinding in $generatedValidationFindings) { [void]$findings.Add($generatedFinding) }
        $generatedBundleErrors = @($generatedValidationFindings | Where-Object { $_.Severity -eq 'ERROR' })
        if ($generatedBundleErrors.Count -gt 0) { throw "new bundle failed independent schema/hash/bytes/identity/layout/resource validation: $($generatedBundleErrors.Check -join ',')" }
        $postGenerationTauriFindings = New-D32FindingList
        Test-D32TauriResourceMap -Repository $Repository -Findings $postGenerationTauriFindings
        if (@($postGenerationTauriFindings | Where-Object { $_.Severity -eq 'ERROR' }).Count -gt 0) { throw 'Tauri shipping resource map failed the immediate post-generation check' }
        Add-D32Finding -Findings $findings -Severity PASS -Check 'bundle.build.output' -Message "created and independently validated separate gate evidence bundle and build attestation under $evidenceFull; Tauri package was not built or modified"
    }
    catch {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.output' -Message $_.Exception.Message
        return [PSCustomObject]@{ Success = $false; Findings = $findings; SecurityClassification = $classification }
    }

    $finalHead = Get-D32Head -Repository $Repository -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings
    $finalClean = Test-D32GitClean -Repository $Repository -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Findings $findings
    if ($finalHead -cne $ExpectedCandidateSha -or -not $finalClean) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.build.final-state' -Message 'candidate SHA or clean working tree changed before attestation completed'
    }
    $errors = @($findings | Where-Object { $_.Severity -eq 'ERROR' })
    return [PSCustomObject]@{
        Success = ($errors.Count -eq 0)
        Status = if ($errors.Count -eq 0) { 'ARTIFACT_ONLY' } else { 'BLOCKED' }
        Findings = $findings
        EvidenceRoot = $evidenceFull
        BundleManifest = (Join-Path (Join-Path $evidenceFull $script:D32BundleDirectoryName) $script:D32BundleManifestName)
        Attestation = (Join-Path $evidenceFull $script:D32AttestationName)
        SecurityClassification = $classification
    }
}

function Write-D32Result {
    param(
        [Parameter(Mandatory = $true)][string]$Operation,
        [Parameter(Mandatory = $true)][object]$Result
    )

    $status = if ($null -ne $Result.PSObject.Properties['Status']) { [string]$Result.Status } elseif ($Result.Success) { 'PASS' } else { 'BLOCKED' }
    Write-Output ("D32 aggregate {0}: {1}" -f $Operation, $status)
    if ($null -ne $Result.PSObject.Properties['SecurityClassification']) {
        $classification = $Result.SecurityClassification
        Write-Output ("security_classification.advisory_only={0}" -f ([bool]$classification.advisory_only).ToString().ToLowerInvariant())
        Write-Output ("security_classification.host_official_preflight_required={0}" -f ([bool]$classification.host_official_preflight_required).ToString().ToLowerInvariant())
        Write-Output ("security_classification.git_image_validation={0}" -f $classification.git_image_validation)
    }
    foreach ($finding in $Result.Findings) {
        Write-Output ("[{0}] {1}: {2}" -f $finding.Severity, $finding.Check, $finding.Message)
    }
    $validatedModes = @()
    if ($null -ne $Result.PSObject.Properties['ValidatedModes']) {
        $validatedModes = @($Result.ValidatedModes)
    }
    if ($validatedModes.Count -gt 0) {
        $modeJson = $validatedModes | ConvertTo-Json -Compress
        Write-Output ("validated_modes={0}" -f $modeJson)
    }
}

function Assert-D32SelfTest {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Failures
    )
    $script:D32SelfTestAssertionCount++
    if ($Condition) {
        Write-Host "SELFTEST PASS: $Name"
    }
    else {
        Write-Host "SELFTEST FAIL: $Name"
        [void]$Failures.Add($Name)
    }
}

function Test-D32ExpectedReparseFixtureUnavailable {
    param([Parameter(Mandatory = $true)][System.Exception]$Exception)

    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [PlatformNotSupportedException]) {
            return $true
        }
        if ($current -is [System.ComponentModel.Win32Exception] -and $current.NativeErrorCode -in @(1, 50, 1314)) {
            return $true
        }
        if (($current.HResult -band 0xFFFF) -in @(1, 50, 1314)) {
            return $true
        }
        $current = $current.InnerException
    }
    return $false
}

function Add-D32SelfTestUnavailable {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    $script:D32SelfTestUnavailableCount++
    [void]$script:D32SelfTestUnavailableCases.Add($Name)
    Write-Host "SELFTEST UNAVAILABLE: $Name — $Reason"
}

function Get-D32ReleaseBundleSelfTestFindings {
    param(
        [AllowNull()][object]$Bundle,
        [Parameter(Mandatory = $true)][string]$BundleManifest,
        [AllowNull()][object]$Attestation,
        [Parameter(Mandatory = $true)][string]$AttestationPath,
        [Parameter(Mandatory = $true)][string]$AttestationSha256,
        [Parameter(Mandatory = $true)][string]$Head,
        [Parameter(Mandatory = $true)][string]$Repository
    )

    $findings = New-D32FindingList
    Test-D32ReleaseEvidenceBundle -Bundle $Bundle -BundleFilePath $BundleManifest -Attestation $Attestation -AttestationFilePath $AttestationPath -AttestationSha256 $AttestationSha256 -Head $Head -Repository $Repository -Findings $findings
    return ,$findings
}

function Invoke-D32SelfTest {
    $script:D32SelfTestAssertionCount = 0
    $script:D32SelfTestUnavailableCount = 0
    $script:D32SelfTestUnavailableCases = New-Object System.Collections.ArrayList
    $failures = New-D32FindingList
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ('d32-preflight-selftest-' + [Guid]::NewGuid().ToString('N'))
    $rootToken = [Guid]::NewGuid().ToString('N')
    $rootMarker = Join-Path $root 'd32-selftest-owned.marker'
    $rootOwned = $false
    $fixture = Join-Path $root 'repo'
    $evidenceRoot = Join-Path $root 'evidence'
    $bundleRoot = Join-Path $evidenceRoot $script:D32BundleDirectoryName
    $attestationPath = Join-Path $evidenceRoot $script:D32AttestationName
    $bundleManifest = Join-Path $bundleRoot $script:D32BundleManifestName
    $buildRoot = Join-Path $root 'build'
    $provenance = Join-Path $root 'provenance.json'
    $fixtureManifest = Join-Path $root 'fixture-manifest.json'
    $generated = Join-Path $root 'generated.json'
    $existing = Join-Path $root 'existing.json'
    $image = Join-Path $fixture 'vita-agent\target\release\vita-agent.exe'
    try {
        Assert-D32SelfTest -Condition (Test-D32SupportedPowerShellVersion -Version $PSVersionTable.PSVersion) -Name 'supported PowerShell version is accepted' -Failures $failures
        Assert-D32SelfTest -Condition (-not (Test-D32SupportedPowerShellVersion -Version ([Version]'7.4.99'))) -Name 'PowerShell versions before 7.5 are rejected' -Failures $failures
        [void](New-Item -ItemType Directory -Path $fixture -Force)
        [System.IO.File]::WriteAllText($rootMarker, $rootToken, (New-Object System.Text.UTF8Encoding($false)))
        $rootOwned = $true
        $script:D32GitCaptureContext | Add-Member -NotePropertyName SelfTestOwnedRoot -NotePropertyValue $root -Force
        $script:D32GitCaptureContext | Add-Member -NotePropertyName SelfTestMarkerPath -NotePropertyValue $rootMarker -Force
        $script:D32GitCaptureContext | Add-Member -NotePropertyName SelfTestMarkerToken -NotePropertyValue $rootToken -Force
        $profileSelfTestCases = @(Test-D32BuildToolchainProfileSelfTest -Root $root -Repository (Split-Path -Parent $PSScriptRoot))
        foreach ($profileCase in $profileSelfTestCases) {
            if (-not $profileCase.Passed -and -not [String]::IsNullOrWhiteSpace([string]$profileCase.Detail)) { Write-Host "SELFTEST DETAIL: $($profileCase.Name): $($profileCase.Detail)" }
            Assert-D32SelfTest -Condition ([bool]$profileCase.Passed) -Name "build toolchain profile: $($profileCase.Name)" -Failures $failures
        }
        $candidateRepository = Split-Path -Parent $PSScriptRoot
        foreach ($lockInput in @(Get-D32BuildToolchainLockInputs -Repository $candidateRepository)) {
            foreach ($relativePath in @($lockInput.ManifestPath, $lockInput.LockPath)) {
                $sourcePath = Join-Path $candidateRepository $relativePath
                $fixturePath = Join-Path $fixture $relativePath
                if (Test-Path -LiteralPath $fixturePath) { throw "self-test fixture unexpectedly already contains profile-bound Cargo input: $relativePath" }
                [void][IO.Directory]::CreateDirectory((Split-Path -Parent $fixturePath))
                [IO.File]::WriteAllBytes($fixturePath, [IO.File]::ReadAllBytes($sourcePath))
            }
        }
        [void](New-Item -ItemType Directory -Path $bundleRoot -Force)
        [void](New-Item -ItemType Directory -Path $buildRoot -Force)
        foreach ($relative in @(
                'docs\governance\PROJECT_SOURCE_OF_TRUTH.md',
                'docs\governance\CURRENT_DEVELOPMENT_STATE.md',
                'docs\governance\FROZEN_INVARIANTS.md',
                'docs\governance\ARCHITECTURE_DECISIONS.md',
                'docs\governance\MODEL_ROUTING.md',
                'docs\governance\CODEX_DEVELOPMENT_PROTOCOL.md',
                'AGENTS.md',
                'src-tauri\tauri.conf.json')) {
            $path = Join-Path $fixture $relative
            [void](New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force)
            if ($relative -eq 'src-tauri\tauri.conf.json') {
                [System.IO.File]::WriteAllText($path, '{"bundle":{"resources":{"../vita-agent/target/release/vita-agent.exe":"vita-agent.exe"}}}', (New-Object System.Text.UTF8Encoding($false)))
            }
            else {
                $content = if ($relative -eq 'AGENTS.md') {
                    '# fixture index' + [Environment]::NewLine +
                    'docs/governance/PROJECT_SOURCE_OF_TRUTH.md' + [Environment]::NewLine +
                    'docs/governance/CURRENT_DEVELOPMENT_STATE.md' + [Environment]::NewLine +
                    'docs/governance/FROZEN_INVARIANTS.md' + [Environment]::NewLine +
                    'docs/governance/ARCHITECTURE_DECISIONS.md' + [Environment]::NewLine +
                    'docs/governance/CODEX_DEVELOPMENT_PROTOCOL.md' + [Environment]::NewLine
                }
                elseif ($relative -eq 'docs\governance\CODEX_DEVELOPMENT_PROTOCOL.md') {
                    '# fixture protocol' + [Environment]::NewLine + 'MODEL_ROUTING.md' + [Environment]::NewLine
                }
                else { '# fixture governance' + [Environment]::NewLine }
                [System.IO.File]::WriteAllText($path, $content)
            }
        }
        [void](New-Item -ItemType Directory -Path (Split-Path -Parent $image) -Force)
        [System.IO.File]::WriteAllBytes($image, [Text.Encoding]::UTF8.GetBytes('d32-selftest-release-image'))
        $selftestFixtureRecords = @()
        foreach ($fixtureSpec in $script:D32FixtureSpecs) {
            $fixtureArtifactPath = Join-Path $fixture $fixtureSpec.artifact
            [void](New-Item -ItemType Directory -Path (Split-Path -Parent $fixtureArtifactPath) -Force)
            [System.IO.File]::WriteAllBytes($fixtureArtifactPath, [Text.Encoding]::UTF8.GetBytes("fixture-$($fixtureSpec.name)"))
        }

        $trustedGitPath = [string]$script:D32GitCaptureContext.GitPath
        $trustedGitHash = [string]$script:D32GitCaptureContext.GitSha256
        $validTrustedGit = Test-D32TrustedGitImage -Path $trustedGitPath -ExpectedSha256 $trustedGitHash
        Assert-D32SelfTest -Condition $validTrustedGit.IsValid -Name 'Coordinator-approved direct Git root identity is accepted' -Failures $failures
        Assert-D32SelfTest -Condition (-not (Test-D32TrustedGitImage -Path $null -ExpectedSha256 $trustedGitHash).IsValid) -Name 'missing trusted Git path is rejected' -Failures $failures
        Assert-D32SelfTest -Condition (-not (Test-D32TrustedGitImage -Path $trustedGitPath -ExpectedSha256 ('0' * 64)).IsValid) -Name 'wrong trusted Git hash is rejected' -Failures $failures
        $vitaTargetIndex = [Array]::IndexOf([string[]]$script:D32ReleaseBuildCommands[0].arguments, '--target-dir')
        $hostTargetIndex = [Array]::IndexOf([string[]]$script:D32ReleaseBuildCommands[1].arguments, '--target-dir')
        $releaseTargetsPinned = $vitaTargetIndex -ge 0 -and $hostTargetIndex -ge 0 -and $script:D32ReleaseBuildCommands[0].arguments[$vitaTargetIndex + 1] -ceq 'vita-agent/target' -and $script:D32ReleaseBuildCommands[1].arguments[$hostTargetIndex + 1] -ceq 'src-tauri/target' -and $script:D32BuildCommand -ceq $script:D32ReleaseBuildCommands[0].command
        Assert-D32SelfTest -Condition $releaseTargetsPinned -Name 'fixed release commands pin outputs to their repository-local target directories' -Failures $failures
        $classification = Get-D32SecurityClassification
        Assert-D32SelfTest -Condition ([bool]$classification.advisory_only -and [bool]$classification.host_official_preflight_required) -Name 'Host-required advisory security classification is explicit' -Failures $failures
        $secret = 'D32-SECRET-CONFIG-OUTPUT'
        $safeOutput = ConvertTo-D32GitOutput -Arguments @('status', '--porcelain=v1') -StdOut ("?? $secret`n") -StdErr $secret
        Assert-D32SelfTest -Condition ((-not $safeOutput.Text.Contains($secret)) -and $safeOutput.HasOutput) -Name 'malicious Git output is bounded and not echoed' -Failures $failures

        $reparseGitPath = Join-Path $root 'reparse-git.exe'
        $reparseCreated = $false
        try {
            [void][System.IO.File]::CreateSymbolicLink($reparseGitPath, $trustedGitPath)
            $reparseCreated = $true
        }
        catch {
            if (Test-D32ExpectedReparseFixtureUnavailable -Exception $_.Exception) {
                Add-D32SelfTestUnavailable -Name 'trusted-Git file reparse rejection' -Reason 'the OS/filesystem reports symbolic-link creation unsupported or privilege unavailable'
            }
            else {
                Assert-D32SelfTest -Condition $false -Name 'trusted-Git file reparse fixture creation failed unexpectedly' -Failures $failures
            }
        }
        if ($reparseCreated) {
            Assert-D32SelfTest -Condition (-not (Test-D32TrustedGitImage -Path $reparseGitPath -ExpectedSha256 $trustedGitHash).IsValid) -Name 'reparse trusted Git image is rejected' -Failures $failures
        }
        $artifactSpecs = @(
            @{ Name = 'vita-agent.exe'; Build = (Join-Path $fixture $script:D32BundleSourceRelativePaths['vita-agent.exe']); Content = 'vita-artifact' },
            @{ Name = 'd32a-production-canary-host.exe'; Build = (Join-Path $fixture $script:D32BundleSourceRelativePaths['d32a-production-canary-host.exe']); Content = 'host-artifact' },
            @{ Name = 'digital_life_lib.dll'; Build = (Join-Path $fixture $script:D32BundleSourceRelativePaths['digital_life_lib.dll']); Content = 'lib-artifact' }
        )
        $freshOutputProbe = Join-Path $root 'fresh-output-probe'
        [void][System.IO.Directory]::CreateDirectory($freshOutputProbe)
        $freshOutputProbeFindings = New-D32FindingList
        $freshOutputProbeRecords = Get-D32FreshReleaseOutputRecords -Repository $freshOutputProbe -Findings $freshOutputProbeFindings
        Assert-D32SelfTest -Condition ($freshOutputProbeRecords.Count -eq 3 -and @($freshOutputProbeFindings | Where-Object { $_.Severity -eq 'ERROR' }).Count -eq 0) -Name 'all three absent fixed release outputs are recorded as fresh' -Failures $failures
        $bundleArtifacts = @()
        $attestedArtifacts = @()
        foreach ($spec in $artifactSpecs) {
            [void](New-Item -ItemType Directory -Path (Split-Path -Parent $spec.Build) -Force)
            [System.IO.File]::WriteAllBytes($spec.Build, [Text.Encoding]::UTF8.GetBytes($spec.Content))
            $bundleFile = Join-Path $bundleRoot $spec.Name
            [System.IO.File]::Copy($spec.Build, $bundleFile)
            $buildDigest = Get-D32EvidenceFileDigest -Path $spec.Build
            $bundleDigest = Get-D32EvidenceFileDigest -Path $bundleFile
            $attestedArtifacts += [ordered]@{
                name = $spec.Name
                build_path = Get-D32AbsolutePath -Path $spec.Build
                build_bytes = $buildDigest.Length
                build_sha256 = $buildDigest.Hash
                build_identity = $buildDigest.Identity
            }
            $bundleArtifacts += [ordered]@{
                name = $spec.Name
                build_path = Get-D32AbsolutePath -Path $spec.Build
                bundle_path = Get-D32AbsolutePath -Path $bundleFile
                build_bytes = $buildDigest.Length
                bundle_bytes = $bundleDigest.Length
                build_sha256 = $buildDigest.Hash
                bundle_sha256 = $bundleDigest.Hash
                build_identity = $buildDigest.Identity
                bundle_identity = $bundleDigest.Identity
                exact_match = $true
            }
        }
        $staleOutputFindings = New-D32FindingList
        $staleOutputRecords = Get-D32FreshReleaseOutputRecords -Repository $fixture -Findings $staleOutputFindings
        Assert-D32SelfTest -Condition ($staleOutputRecords.Count -lt 3 -and @($staleOutputFindings | Where-Object { $_.Check -like 'bundle.build.fresh-output.*' -and $_.Severity -eq 'ERROR' }).Count -eq 3) -Name 'any pre-existing exact release artifact fails fresh-output preflight' -Failures $failures
        $git = Invoke-D32Git -Repository $fixture -Arguments @('init', '-q') -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash
        if ($git.ExitCode -ne 0) { throw 'trusted Git init failed' }
        $git = Invoke-D32Git -Repository $fixture -Arguments @('add', '.') -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash
        if ($git.ExitCode -ne 0) { throw 'trusted Git add failed' }
        $git = Invoke-D32Git -Repository $fixture -Arguments @('commit', '-q', '-m', 'selftest fixture') -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash
        if ($git.ExitCode -ne 0) { throw 'trusted Git commit failed' }
        $head = (Invoke-D32Git -Repository $fixture -Arguments @('rev-parse', '--verify', 'HEAD') -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash).Text.Trim()
        foreach ($fixtureSpec in $script:D32FixtureSpecs) {
            $fixtureManifestPath = [System.IO.Path]::GetFullPath((Join-Path $fixture $fixtureSpec.manifest))
            $fixtureArtifactPath = [System.IO.Path]::GetFullPath((Join-Path $fixture $fixtureSpec.artifact))
            $fixtureDigest = Get-D32FileDigest -Path $fixtureArtifactPath
            $selftestFixtureRecords += [ordered]@{
                phase = $fixtureSpec.phase
                name = $fixtureSpec.name
                project = $fixtureSpec.project
                binary = $fixtureSpec.binary
                manifest_path = $fixtureManifestPath
                features = @($fixtureSpec.features)
                command = ConvertTo-D32FixtureCommand -Repository $fixture -Spec $fixtureSpec
                status = 'succeeded'
                exit_code = 0
                pid = 1
                descendant_pids = @()
                root_identity = [ordered]@{
                    process_id = 1
                    parent_process_id = $null
                    name = 'fixture-root.exe'
                    creation_date = '2026-09-22T00:00:00.0000000Z'
                    command_line = 'fixture-root'
                    observed_at_utc = '2026-09-22T00:00:00.0000000Z'
                    identity_verified = $true
                }
                descendant_identities = @()
                residual_descendant_identities = @()
                reap = $null
                elapsed_ms = 1
                phase_log = (Join-Path $root "logs\$($fixtureSpec.name)")
                stdout_log = (Join-Path $root "logs\$($fixtureSpec.name).stdout.log")
                stderr_log = (Join-Path $root "logs\$($fixtureSpec.name).stderr.log")
                error = $null
                artifact = [ordered]@{
                    path = $fixtureArtifactPath
                    bytes = $fixtureDigest.Length
                    sha256 = $fixtureDigest.Hash
                }
            }
        }
        $selftestFixtureRecords[0]['reap'] = [ordered]@{
            process_ids = @(1, 2)
            verified_at_utc = '2026-09-22T00:00:00.0000000Z'
            residual_identities = @([ordered]@{
                    process_id = 2
                    parent_process_id = 1
                    name = 'fixture-child.exe'
                    creation_date = '2026-09-22T00:00:00.0000000Z'
                    command_line = 'fixture-child'
                    observed_at_utc = '2026-09-22T00:00:00.0000000Z'
                    identity_verified = $true
                })
            native_cleanup = [ordered]@{
                job_terminate_call_succeeded = $true
                job_terminate_last_error = 0
                process_was_already_signaled = $false
                process_wait_signaled = $true
                job_active_process_count_verified = $true
                job_active_process_count = 0
                job_active_process_count_last_error = 0
                job_close_succeeded = $true
                cleanup_succeeded = $true
                already_closed = $false
                detail = ''
            }
            kill_output = @()
        }
        $fixtureDocument = [ordered]@{
            schema_version = $script:D32FixtureSchemaVersion
            candidate_sha = $head
            source_repo = [System.IO.Path]::GetFullPath($fixture)
            generated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            started_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            elapsed_ms = 1
            working_tree_status = ''
            build_policy = [ordered]@{
                timeout_seconds = 1
                cargo_build_jobs = 1
                nested_builds = $false
                process_tree_timeout_action = $script:D32FixtureProcessTreePolicy
            }
            environment = [ordered]@{
                original_userprofile = 'C:\selftest-user'
                codex_home = 'C:\selftest-codex'
                userprofile = 'C:\selftest-profile'
                cargo_home = 'C:\selftest-cargo'
                rustup_home = 'C:\selftest-rustup'
                rustup_toolchain = $null
            }
            process_tree_check = 'succeeded'
            process_tree_error = $null
            fixtures = @($selftestFixtureRecords)
        }
        Write-D32Json -Path $fixtureManifest -Value $fixtureDocument
        $profilePath = Join-Path $root 'd32-build-profile-selftest\caller-pinned-profile.json'
        $profileValidation = Test-D32BuildToolchainProfile -ProfilePath $profilePath -ExpectedSha256 (Get-D32ProfileFileSnapshot -Path $profilePath).Sha256 -Repository (Split-Path -Parent $PSScriptRoot) -EvidenceRoot $root
        if (-not $profileValidation.IsValid) { throw "self-test toolchain profile is not valid for evidence fixture: $($profileValidation.Failure)" }
        $profileSnapshot = Get-D32ProfileFileSnapshot -Path $profilePath
        $profileDocument = $profileValidation.Profile
        $fakeCargo = [string]$profileDocument.toolchain.cargo.path
        $fakeCargoDigest = Get-D32EvidenceFileDigest -Path $fakeCargo
        $phase0Root = Join-Path $root 'phase0'
        $phase0RunRoot = Join-Path $phase0Root 'phase0-run-selftest'
        $phase0CargoHome = Join-Path $phase0RunRoot 'cargo-home'
        $phase0TempRoot = Join-Path $phase0RunRoot 'temp'
        [void][System.IO.Directory]::CreateDirectory($phase0CargoHome)
        [void][System.IO.Directory]::CreateDirectory($phase0TempRoot)
        [System.IO.File]::WriteAllText((Join-Path $phase0CargoHome 'selftest-cache-marker'), 'fetched locked sources')
        $phase0ToolProfile = [ordered]@{
            path = $profileValidation.ProfilePath
            sha256 = $profileValidation.Digest
            file_identity = [ordered]@{
                bytes = [Int64]$profileValidation.Identity.Bytes
                volume_serial_hex = [string]$profileValidation.Identity.VolumeSerialHex
                file_id_hex = [string]$profileValidation.Identity.FileIdHex
            }
            target_triple = $profileValidation.Profile.target_triple
            toolchain = $profileValidation.Profile.toolchain
            executable_inventory = @($profileValidation.ExecutableInventory | ForEach-Object {
                    [ordered]@{
                        path = $_.Path
                        sha256 = $_.Sha256
                        bytes = [Int64]$_.Bytes
                        volume_serial_hex = $_.VolumeSerialHex
                        file_id_hex = $_.FileIdHex
                    }
                })
            script_inventory = @($profileValidation.ScriptInventory | ForEach-Object {
                    [ordered]@{
                        path = $_.Path
                        sha256 = $_.Sha256
                        bytes = [Int64]$_.Bytes
                        volume_serial_hex = $_.VolumeSerialHex
                        file_id_hex = $_.FileIdHex
                    }
                })
            windows_image_inventory = @($profileValidation.WindowsImageInventory | ForEach-Object {
                    [ordered]@{
                        path = $_.Path
                        sha256 = $_.Sha256
                        bytes = [Int64]$_.Bytes
                        volume_serial_hex = $_.VolumeSerialHex
                        file_id_hex = $_.FileIdHex
                    }
                })
            lock_inputs = @($profileValidation.LockInputs | ForEach-Object { [ordered]@{ manifest_path = $_.ManifestPath; lock_sha256 = $_.LockSha256 } })
            env_policy = $profileValidation.Profile.env_policy
        }
        $phase0RecordPath = Join-Path $phase0Root 'D32-PHASE0-MATRIX.json'
        $phase0Started = [DateTimeOffset]::UtcNow.ToString('o')
        $phase0Document = [ordered]@{
            schema_version = 2
            record_type = 'D32_PHASE0_MATRIX_RECORD_V2'
            runner_process_id = [int]$PID
            candidate_sha = $head
            source_repo = [IO.Path]::GetFullPath($fixture)
            output_root = [IO.Path]::GetFullPath($phase0Root)
            status = 'PASS'
            bundle_hashes = 'PENDING'
            started_at_utc = $phase0Started
            completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            final_candidate_sha = $head
            final_clean = $true
            powershell = $profileValidation.Profile.powershell
            toolchain_profile = $phase0ToolProfile
            cargo_home = [ordered]@{ path = [IO.Path]::GetFullPath($phase0CargoHome); temp_root = [IO.Path]::GetFullPath($phase0TempRoot); run_id = 'phase0-run-selftest'; nonempty_after_fetch = $true }
            fetches = @()
            fixture = [ordered]@{}
            commands = @()
            test_inventory = [ordered]@{}
            local_suites = @()
            focused_tests = @()
            deferred_d31_tests = @()
            deferred_d29g2_provider_tests = @()
            not_run_capture_tests = @()
            governance_inputs = [ordered]@{}
            phase0_scope = 'local-fixture-and-test-matrix-only; no release build, D31 real process, provider, or hardware capture'
        }
        Write-D32JsonCreateNew -Path $phase0RecordPath -Value $phase0Document
        $phase0Snapshot = Get-D32ProfileFileSnapshot -Path $phase0RecordPath
        $profileReference = [ordered]@{
            path = $profileSnapshot.Path
            sha256 = $profileSnapshot.Sha256
            bytes = [Int64]$profileSnapshot.Bytes
            volume_serial_hex = $profileSnapshot.VolumeSerialHex
            file_id_hex = $profileSnapshot.FileIdHex
        }
        $phase0Reference = [ordered]@{
            path = $phase0Snapshot.Path
            sha256 = $phase0Snapshot.Sha256
            bytes = [Int64]$phase0Snapshot.Bytes
            volume_serial_hex = $phase0Snapshot.VolumeSerialHex
            file_id_hex = $phase0Snapshot.FileIdHex
            candidate_sha = $head
            status = 'PASS'
        }
        $commandRecords = @()
        $selftestCommandIndex = 0
        $releaseLogRoot = Join-Path $evidenceRoot 'logs'
        [void][System.IO.Directory]::CreateDirectory($releaseLogRoot)
        foreach ($fixedCommand in $script:D32ReleaseBuildCommands) {
            $selftestCommandIndex++
            $commandTime = [DateTimeOffset]::UtcNow.ToString('o')
            $selftestRootPid = 1000 + $selftestCommandIndex
            $selftestProcessTrace = New-D32Phase0SelfTestDebugTrace -Profile $profileValidation -RunnerProcessId $PID -RootProcessId $selftestRootPid
            $selftestTraceRoot = $selftestProcessTrace.processes[0]
            $selftestCargoPath = [IO.Path]::GetFullPath($fakeCargo)
            $expectedArgv = @($selftestCargoPath) + @($fixedCommand.arguments)
            $stdoutPath = Join-Path $releaseLogRoot ("release-{0:D2}-{1}.stdout.log" -f $selftestCommandIndex, $fixedCommand.name)
            $stderrPath = Join-Path $releaseLogRoot ("release-{0:D2}-{1}.stderr.log" -f $selftestCommandIndex, $fixedCommand.name)
            [System.IO.File]::WriteAllText($stdoutPath, "D32 selftest simulated command $($fixedCommand.name)`n")
            [System.IO.File]::WriteAllText($stderrPath, '')
            $processIdentity = [ordered]@{
                process_id = $selftestRootPid
                parent_process_id = [int]$PID
                name = 'cargo.exe'
                image_path = $selftestCargoPath
                command_line = ConvertTo-D32Phase0CommandLine -Arguments $expectedArgv
                creation_date = [DateTime]::FromFileTimeUtc([Int64]$selftestTraceRoot.creation_filetime).ToString('o')
                observed_at_utc = [string]$selftestTraceRoot.created_at_utc
                sha256 = $fakeCargoDigest.Hash
                bytes = [Int64]$fakeCargoDigest.Length
                volume_serial_hex = $fakeCargoDigest.Identity.VolumeSerialHex
                file_id_hex = $fakeCargoDigest.Identity.FileIdHex
                allowed_image_reason = 'caller-pinned toolchain profile direct Cargo executable'
                identity_verified = $true
            }
            $commandRecords += [ordered]@{
                name = $fixedCommand.name
                command = $fixedCommand.command
                working_directory = Get-D32CanonicalPath -Path $fixture
                argv = $expectedArgv
                candidate_sha_before = $head
                git_status_before = 'clean'
                started_at_utc = $commandTime
                completed_at_utc = $commandTime
                exit_code = 0
                process_id = $selftestRootPid
                root_process = $processIdentity
                descendant_processes = [object[]]::new(0)
                process_trace = $selftestProcessTrace
                process_tree_cleanup = [ordered]@{
                    launch_mode = 'DedicatedOSDebuggerThread(CreateProcessW(DEBUG_PROCESS|CREATE_SUSPENDED)+DebugSetProcessKillOnExit(TRUE)+ResumeThread+WaitForDebugEvent+ContinueDebugEvent)+EXTENDED_STARTUP_INFO+HANDLE_LIST(stdout/stderr)+AssignProcessToJobObject(KILL_ON_JOB_CLOSE)'
                    job_close_succeeded = $true
                    process_wait_signaled = $true
                    active_process_count_verified = $true
                    active_process_count = 0
                    debugger_thread_id = [uint32]$selftestProcessTrace.debugger_thread_id
                    debugger_thread_exited = $true
                    debugger_thread_joined = $true
                    debugger_kill_on_exit_enabled = $true
                    retained_process_handle_count = [int]$selftestProcessTrace.retained_process_handle_count
                    retained_process_handles_signaled = $true
                    debugger_association_query_verified = $true
                    debugger_association_absent = $true
                    cleanup_succeeded = $true
                    detail = ''
                }
                stdout = Get-D32Phase0FileReference -Path $stdoutPath
                stderr = Get-D32Phase0FileReference -Path $stderrPath
                candidate_sha_after = $head
                git_status_after = 'clean'
            }
        }
        $attestationDocument = [ordered]@{
            schema_version = $script:D32AttestationSchemaVersion
            attestation_type = 'D32_RELEASE_BUILD_ATTESTATION_V3'
            candidate_sha = $head
            source_clone = Get-D32CanonicalPath -Path $fixture
            git_status = 'clean'
            build_profile = 'release'
            started_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            completed_at_utc = [DateTimeOffset]::UtcNow.AddSeconds(1).ToString('o')
            cargo_path = [IO.Path]::GetFullPath($fakeCargo)
            cargo_sha256 = $fakeCargoDigest.Hash
            cargo_identity = $fakeCargoDigest.Identity
            runner_process_id = [int]$PID
            toolchain_profile = $profileReference
            phase0_matrix = $phase0Reference
            cargo_home = [ordered]@{
                path = [IO.Path]::GetFullPath($phase0CargoHome)
                temp_root = [IO.Path]::GetFullPath($phase0TempRoot)
                run_id = 'phase0-run-selftest'
            }
            fresh_outputs = @($artifactSpecs | ForEach-Object {
                    [ordered]@{
                        name = $_.Name
                        build_path = Get-D32AbsolutePath -Path $_.Build
                        absent_before_build = $true
                    }
                })
            commands = @($commandRecords)
            artifacts = @($attestedArtifacts)
        }
        Write-D32JsonCreateNew -Path $attestationPath -Value $attestationDocument
        $attestationDigest = Get-D32EvidenceFileDigest -Path $attestationPath
        $bundleDocument = [ordered]@{
            schema_version = $script:D32BundleSchemaVersion
            candidate_sha = $head
            source_clone = Get-D32CanonicalPath -Path $fixture
            bundle_path = Get-D32AbsolutePath -Path $bundleRoot
            attestation_path = Get-D32AbsolutePath -Path $attestationPath
            attestation_sha256 = $attestationDigest.Hash
            build_targets = [ordered]@{
                vita = Get-D32AbsolutePath -Path (Join-Path $fixture 'vita-agent\target\release')
                host = Get-D32AbsolutePath -Path (Join-Path $fixture 'src-tauri\target\release')
            }
            artifacts = @($bundleArtifacts)
            total_bytes = [Int64](($bundleArtifacts | ForEach-Object { [Int64]$_.build_bytes } | Measure-Object -Sum).Sum)
            runtime_resources = @()
        }
        Write-D32Json -Path $bundleManifest -Value $bundleDocument
        $generatedResult = Invoke-D32GenerateManifest -Repository $fixture -Manifest $provenance -Image $image -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash
        Assert-D32SelfTest -Condition $generatedResult.Success -Name 'atomic generation on a missing target' -Failures $failures
        $generatedObject = [System.IO.File]::ReadAllText($provenance) | ConvertFrom-D32Json
        $sourceFormCorrect = $generatedObject.source_repo -ceq (Get-D32RustRepositoryPath -Path $fixture)
        $imageFormCorrect = -not (Test-D32Windows) -or $generatedObject.image_path.StartsWith('\\?\', [StringComparison]::Ordinal)
        Assert-D32SelfTest -Condition ($sourceFormCorrect -and $imageFormCorrect) -Name 'Host source_repo ordinary/image_path extended path asymmetry' -Failures $failures
        $validResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -AttestationPath $attestationPath -FixtureManifest $fixtureManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run') -Modes $null
        if (-not $validResult.Success) {
            foreach ($finding in $validResult.Findings) {
                Write-Host ("  VALID FIXTURE [{0}] {1}: {2}" -f $finding.Severity, $finding.Check, $finding.Message)
            }
        }
        Assert-D32SelfTest -Condition ($validResult.Success -and $validResult.Status -eq 'ARTIFACT_ONLY') -Name 'valid fixture bundle validation remains explicitly artifact-only' -Failures $failures
        $aggregateRecordPath = Join-Path $evidenceRoot $script:D32PostBundleAggregateRecordName
        $aggregateReferences = [ordered]@{
            phase0_matrix = New-D32PostBundleAggregateFileReference -Path $phase0RecordPath -Repository $fixture
            toolchain_profile = New-D32PostBundleAggregateFileReference -Path $profilePath -Repository $fixture
            fixture_manifest = New-D32PostBundleAggregateFileReference -Path $fixtureManifest -Repository $fixture
            provenance_manifest = New-D32PostBundleAggregateFileReference -Path $provenance -Repository $fixture
            bundle_manifest = New-D32PostBundleAggregateFileReference -Path $bundleManifest -Repository $fixture
            attestation = New-D32PostBundleAggregateFileReference -Path $attestationPath -Repository $fixture
            trusted_git = New-D32PostBundleAggregateFileReference -Path $trustedGitPath -Repository $fixture
        }
        $aggregateRecordDocument = [ordered]@{
            schema_version = $script:D32PostBundleAggregateSchemaVersion
            record_type = $script:D32PostBundleAggregateRecordType
            scope = $script:D32PostBundleAggregateScope
            candidate_sha = $head
            source_repo = Get-D32CanonicalPath -Path $fixture
            evidence_root = Get-D32CanonicalPath -Path $evidenceRoot
            status = 'PRE_DOWNSTREAM_AGGREGATE_PASS'
            bundle_hashes = 'VERIFIED'
            downstream_gates = 'NOT RUN'
            references = $aggregateReferences
        }
        Write-D32JsonCreateNew -Path $aggregateRecordPath -Value $aggregateRecordDocument
        $aggregateRecordDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
        $aggregateRecordFindings = New-D32FindingList
        $aggregateRecordValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $aggregateRecordDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $fixtureManifest -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $aggregateRecordFindings
        if (-not $aggregateRecordValidation.IsValid) {
            foreach ($finding in $aggregateRecordFindings) { Write-Host ("  AGGREGATE RECORD SELFTEST [{0}] {1}: {2}" -f $finding.Severity, $finding.Check, $finding.Message) }
        }
        Assert-D32SelfTest -Condition ($aggregateRecordValidation.IsValid -and @($aggregateRecordFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'PASS' }).Count -eq 1) -Name 'exact-SHA aggregate record schema binds current sources and explicitly defers downstream gates' -Failures $failures
        $legacyAggregateRecord = [System.IO.File]::ReadAllText($aggregateRecordPath) | ConvertFrom-D32Json
        $legacyAggregateRecord.schema_version = 1
        $legacyAggregateRecord.record_type = 'D32_POST_BUNDLE_AGGREGATE_RECORD_V1'
        Write-D32Json -Path $aggregateRecordPath -Value $legacyAggregateRecord
        $legacyAggregateDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
        $legacyAggregateFindings = New-D32FindingList
        $legacyAggregateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $legacyAggregateDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $fixtureManifest -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $legacyAggregateFindings
        Assert-D32SelfTest -Condition (-not $legacyAggregateValidation.IsValid -and @($legacyAggregateFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' }).Count -eq 1) -Name 'aggregate record rejects legacy V1 after the synchronized process-trace schema upgrade' -Failures $failures
        Write-D32Json -Path $aggregateRecordPath -Value $aggregateRecordDocument
        $invalidAggregateRecord = [System.IO.File]::ReadAllText($aggregateRecordPath) | ConvertFrom-D32Json
        $invalidAggregateRecord.status = 'ARTIFACT_ONLY'
        Write-D32Json -Path $aggregateRecordPath -Value $invalidAggregateRecord
        $invalidAggregateDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
        $invalidAggregateFindings = New-D32FindingList
        $invalidAggregateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $invalidAggregateDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $fixtureManifest -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $invalidAggregateFindings
        Assert-D32SelfTest -Condition (-not $invalidAggregateValidation.IsValid -and @($invalidAggregateFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' }).Count -eq 1) -Name 'aggregate record rejects an artifact-only status even with a fresh exact-SHA pin' -Failures $failures
        foreach ($invalidAggregateState in @(
                [PSCustomObject]@{ Field = 'bundle_hashes'; Value = 'PENDING'; Name = 'pending bundle hashes' },
                [PSCustomObject]@{ Field = 'downstream_gates'; Value = 'RUN'; Name = 'downstream gates claimed as run' }
            )) {
            Write-D32Json -Path $aggregateRecordPath -Value $aggregateRecordDocument
            $invalidAggregateStateDocument = [System.IO.File]::ReadAllText($aggregateRecordPath) | ConvertFrom-D32Json
            $invalidAggregateStateDocument.PSObject.Properties[[string]$invalidAggregateState.Field].Value = [string]$invalidAggregateState.Value
            Write-D32Json -Path $aggregateRecordPath -Value $invalidAggregateStateDocument
            $invalidAggregateStateDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
            $invalidAggregateStateFindings = New-D32FindingList
            $invalidAggregateStateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $invalidAggregateStateDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $fixtureManifest -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $invalidAggregateStateFindings
            Assert-D32SelfTest -Condition (-not $invalidAggregateStateValidation.IsValid -and @($invalidAggregateStateFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' }).Count -eq 1) -Name "aggregate record rejects $($invalidAggregateState.Name) even with a fresh exact-SHA pin" -Failures $failures
        }
        Assert-D32SelfTest -Condition (Test-D32JsonDuplicateKeys -Json '{"schema_version":1,"schema_version":1}') -Name 'duplicate JSON object keys are rejected before schema parsing' -Failures $failures
        $validBundleJson = [System.IO.File]::ReadAllText($bundleManifest)
        $validAttestationObject = ([System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json)
        $attestationSha = (Get-D32EvidenceFileDigest -Path $attestationPath).Hash

        $legacyAttestationObject = ([System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json)
        $legacyAttestationObject.schema_version = 2
        $legacyAttestationObject.attestation_type = 'D32_RELEASE_BUILD_ATTESTATION_V2'
        $legacyAttestationFindings = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $legacyAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($legacyAttestationFindings | Where-Object { $_.Check -eq 'attestation.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'release attestation rejects legacy V2 without synchronized process traces' -Failures $failures

        $phase0OriginalRaw = [System.IO.File]::ReadAllText($phase0RecordPath)
        $attestationOriginalRaw = [System.IO.File]::ReadAllText($attestationPath)
        $bundleOriginalRaw = [System.IO.File]::ReadAllText($bundleManifest)
        try {
            $legacyPhase0 = $phase0OriginalRaw | ConvertFrom-D32Json
            $legacyPhase0.schema_version = 1
            $legacyPhase0.record_type = 'D32_PHASE0_MATRIX_RECORD_V1'
            Write-D32Json -Path $phase0RecordPath -Value $legacyPhase0
            $legacyPhase0Snapshot = Get-D32ProfileFileSnapshot -Path $phase0RecordPath
            $legacyPhase0Attestation = $attestationOriginalRaw | ConvertFrom-D32Json
            $legacyPhase0Attestation.phase0_matrix.sha256 = $legacyPhase0Snapshot.Sha256
            $legacyPhase0Attestation.phase0_matrix.bytes = [Int64]$legacyPhase0Snapshot.Bytes
            $legacyPhase0Attestation.phase0_matrix.volume_serial_hex = [string]$legacyPhase0Snapshot.VolumeSerialHex
            $legacyPhase0Attestation.phase0_matrix.file_id_hex = [string]$legacyPhase0Snapshot.FileIdHex
            Write-D32Json -Path $attestationPath -Value $legacyPhase0Attestation
            $legacyAttestationSnapshot = Get-D32EvidenceFileDigest -Path $attestationPath
            $legacyBundle = $bundleOriginalRaw | ConvertFrom-D32Json
            $legacyBundle.attestation_sha256 = $legacyAttestationSnapshot.Hash
            Write-D32Json -Path $bundleManifest -Value $legacyBundle
            $legacyPhase0Findings = New-D32FindingList
            Test-D32ReleaseEvidenceBundle -Bundle $legacyBundle -BundleFilePath $bundleManifest -Attestation $legacyPhase0Attestation -AttestationFilePath $attestationPath -AttestationSha256 $legacyAttestationSnapshot.Hash -Head $head -Repository $fixture -ExpectedPhase0RecordPath $legacyPhase0Snapshot.Path -ExpectedPhase0RecordSha256 $legacyPhase0Snapshot.Sha256 -ExpectedToolchainProfilePath $profileSnapshot.Path -ExpectedToolchainProfileSha256 $profileSnapshot.Sha256 -Findings $legacyPhase0Findings
            Assert-D32SelfTest -Condition (@($legacyPhase0Findings | Where-Object { $_.Check -eq 'attestation.phase0-toolchain' -and $_.Severity -eq 'ERROR' -and $_.Message -like '*unsupported schema*' }).Count -gt 0) -Name 'Phase0 matrix rejects legacy V1 even when its current bytes are re-pinned' -Failures $failures
        }
        finally {
            [System.IO.File]::WriteAllText($phase0RecordPath, $phase0OriginalRaw, [Text.UTF8Encoding]::new($false))
            [System.IO.File]::WriteAllText($attestationPath, $attestationOriginalRaw, [Text.UTF8Encoding]::new($false))
            [System.IO.File]::WriteAllText($bundleManifest, $bundleOriginalRaw, [Text.UTF8Encoding]::new($false))
        }

        $pinnedBundleFindings = New-D32FindingList
        Test-D32ReleaseEvidenceBundle -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleFilePath $bundleManifest -Attestation $validAttestationObject -AttestationFilePath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture -ExpectedPhase0RecordPath $phase0Snapshot.Path -ExpectedPhase0RecordSha256 $phase0Snapshot.Sha256 -ExpectedToolchainProfilePath $profileSnapshot.Path -ExpectedToolchainProfileSha256 $profileSnapshot.Sha256 -Findings $pinnedBundleFindings
        Assert-D32SelfTest -Condition (@($pinnedBundleFindings | Where-Object { $_.Severity -eq 'ERROR' }).Count -eq 0) -Name 'bundle attestation references match independent Phase0/profile pins' -Failures $failures

        $wrongPhase0PinFindings = New-D32FindingList
        Test-D32ReleaseEvidenceBundle -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleFilePath $bundleManifest -Attestation $validAttestationObject -AttestationFilePath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture -ExpectedPhase0RecordPath (Join-Path $phase0Root 'unrelated-phase0.json') -ExpectedPhase0RecordSha256 $phase0Snapshot.Sha256 -ExpectedToolchainProfilePath $profileSnapshot.Path -ExpectedToolchainProfileSha256 $profileSnapshot.Sha256 -Findings $wrongPhase0PinFindings
        Assert-D32SelfTest -Condition (@($wrongPhase0PinFindings | Where-Object { $_.Check -eq 'attestation.phase0-toolchain' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'bundle attestation rejects a different caller-pinned Phase0 record path' -Failures $failures

        $wrongProfilePinFindings = New-D32FindingList
        Test-D32ReleaseEvidenceBundle -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleFilePath $bundleManifest -Attestation $validAttestationObject -AttestationFilePath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture -ExpectedPhase0RecordPath $phase0Snapshot.Path -ExpectedPhase0RecordSha256 $phase0Snapshot.Sha256 -ExpectedToolchainProfilePath $profileSnapshot.Path -ExpectedToolchainProfileSha256 ('0' * 64) -Findings $wrongProfilePinFindings
        Assert-D32SelfTest -Condition (@($wrongProfilePinFindings | Where-Object { $_.Check -eq 'attestation.phase0-toolchain' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'bundle attestation rejects a stale caller-pinned toolchain profile SHA' -Failures $failures

        $duplicateBundleKeysPath = Join-Path $root 'duplicate-bundle-keys.json'
        [System.IO.File]::WriteAllText($duplicateBundleKeysPath, '{"schema_version":1,"schema_version":1}', (New-Object System.Text.UTF8Encoding($false)))
        $duplicateBundleKeyFindings = New-D32FindingList
        $duplicateBundleKeyDocument = Read-D32EvidenceJson -Path $duplicateBundleKeysPath -Findings $duplicateBundleKeyFindings -Check 'bundle.selftest.duplicate-keys'
        Assert-D32SelfTest -Condition (($null -eq $duplicateBundleKeyDocument) -and @($duplicateBundleKeyFindings | Where-Object { $_.Check -eq 'bundle.selftest.duplicate-keys' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'duplicate JSON keys in evidence input are rejected before schema parsing' -Failures $failures

        $extraAttestationField = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
        $extraAttestationField | Add-Member -NotePropertyName unexpected -NotePropertyValue 'not-allowed'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $extraAttestationField -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'attestation.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'extra exact attestation schema field is rejected' -Failures $failures

        $missingBundleArtifactField = $validBundleJson | ConvertFrom-D32Json
        Remove-D32JsonProperty -Object $missingBundleArtifactField.artifacts[0] -Name 'bundle_identity'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $missingBundleArtifactField -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.artifact.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'missing exact bundle artifact schema field is rejected' -Failures $failures

        $extraAttestedArtifactField = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
        $extraAttestedArtifactField.artifacts[0] | Add-Member -NotePropertyName unexpected -NotePropertyValue 'not-allowed'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $extraAttestedArtifactField -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'attestation.artifact.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'extra exact attested artifact schema field is rejected' -Failures $failures

        for ($commandIndex = 0; $commandIndex -lt $commandRecords.Count; $commandIndex++) {
            $wrongPreCandidate = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
            $wrongPreCandidate.commands[$commandIndex].candidate_sha_before = '0' * 40
            $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $wrongPreCandidate -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
            Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq "attestation.command.$commandIndex.pre-state" -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name "release command $commandIndex wrong pre-build candidate is rejected" -Failures $failures

            $dirtyPreStatus = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
            $dirtyPreStatus.commands[$commandIndex].git_status_before = 'dirty'
            $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $dirtyPreStatus -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
            Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq "attestation.command.$commandIndex.pre-state" -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name "release command $commandIndex dirty pre-build state is rejected" -Failures $failures

            $wrongPostCandidate = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
            $wrongPostCandidate.commands[$commandIndex].candidate_sha_after = '0' * 40
            $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $wrongPostCandidate -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
            Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq "attestation.command.$commandIndex.post-state" -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name "release command $commandIndex wrong post-build candidate is rejected" -Failures $failures

            $dirtyPostStatus = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
            $dirtyPostStatus.commands[$commandIndex].git_status_after = 'dirty'
            $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $dirtyPostStatus -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
            Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq "attestation.command.$commandIndex.post-state" -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name "release command $commandIndex dirty post-build state is rejected" -Failures $failures
        }

        $missingBundleField = $validBundleJson | ConvertFrom-D32Json
        Remove-D32JsonProperty -Object $missingBundleField -Name 'attestation_sha256'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $missingBundleField -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'missing exact bundle schema field is rejected' -Failures $failures

        $extraBundleField = $validBundleJson | ConvertFrom-D32Json
        $extraBundleField | Add-Member -NotePropertyName unexpected -NotePropertyValue 'not-allowed'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $extraBundleField -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'extra exact bundle schema field is rejected' -Failures $failures

        $missingAttestationField = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
        Remove-D32JsonProperty -Object $missingAttestationField -Name 'commands'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $missingAttestationField -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'attestation.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'missing exact attestation schema field is rejected' -Failures $failures

        $duplicateArtifact = $validBundleJson | ConvertFrom-D32Json
        $duplicateArtifact.artifacts = @($duplicateArtifact.artifacts[0], $duplicateArtifact.artifacts[0], $duplicateArtifact.artifacts[2])
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $duplicateArtifact -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.artifacts' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'duplicate or missing artifact identity is rejected' -Failures $failures

        $wrongCommandAttestation = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
        $wrongCommandAttestation.commands[0].command = $wrongCommandAttestation.commands[0].command + ' --offline'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $wrongCommandAttestation -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'attestation.command.0' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'wrong release build command is rejected' -Failures $failures

        $missingNestedCommandField = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
        Remove-D32JsonProperty -Object $missingNestedCommandField.commands[0] -Name 'working_directory'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $missingNestedCommandField -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'attestation.command.0.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'nested command missing field is rejected' -Failures $failures

        $extraNestedCommandField = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
        $extraNestedCommandField.commands[0] | Add-Member -NotePropertyName unexpected -NotePropertyValue 'not-allowed'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $extraNestedCommandField -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'attestation.command.0.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'nested command extra field is rejected' -Failures $failures

        $wrongTypeNestedCommandField = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
        $wrongTypeNestedCommandField.commands[0].candidate_sha_before = [Int64]123
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $wrongTypeNestedCommandField -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'attestation.command.0.schema-types' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'nested command wrong scalar type is rejected' -Failures $failures

        $stringProcessIdCommand = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
        $stringProcessIdCommand.commands[0].process_id = '1001'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $stringProcessIdCommand -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'attestation.command.0' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'nested command integer field rejects numeric strings' -Failures $failures

        $dirtyAttestation = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
        $dirtyAttestation.git_status = 'dirty'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $dirtyAttestation -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'attestation.clean-build' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'dirty build attestation is rejected' -Failures $failures

        $wrongAttestationHashBundle = $validBundleJson | ConvertFrom-D32Json
        $wrongAttestationHashBundle.candidate_sha = '0' * 40
        $wrongAttestationHashBundle.attestation_sha256 = '0' * 64
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $wrongAttestationHashBundle -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition ((@($negative | Where-Object { $_.Check -eq 'bundle.attestation-hash' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -and (@($negative | Where-Object { $_.Check -eq 'bundle.candidate_sha' -and $_.Severity -eq 'ERROR' }).Count -gt 0)) -Name 'wrong candidate SHA and stale attestation SHA are rejected' -Failures $failures

        $wrongAttestedCandidate = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
        $wrongAttestedCandidate.candidate_sha = '0' * 40
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $wrongAttestedCandidate -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.candidate_sha' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'wrong attestation candidate SHA is rejected' -Failures $failures

        $missingAttestation = Join-Path $evidenceRoot 'missing-attestation.json'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $missingAttestation -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.attestation-hash' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'missing build attestation is rejected' -Failures $failures

        $nonemptyResources = $validBundleJson | ConvertFrom-D32Json
        $nonemptyResources.runtime_resources = @('vita-agent.exe')
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $nonemptyResources -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.runtime_resources' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'non-empty gate runtime_resources is rejected' -Failures $failures

        $wrongPathBundle = $validBundleJson | ConvertFrom-D32Json
        $wrongPathBundle.artifacts[0].build_path = $fakeCargo
        $wrongPathBundle.artifacts[1].bundle_path = Join-Path $bundleRoot 'nested\d32a-production-canary-host.exe'
        $wrongPathBundle.bundle_path = Join-Path $fixture 'evidence-inside-clone'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $wrongPathBundle -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition ((@($negative | Where-Object { $_.Check -like 'bundle.artifact.*.path' -and $_.Severity -eq 'ERROR' }).Count -ge 2) -and (@($negative | Where-Object { $_.Check -eq 'bundle.path' -and $_.Severity -eq 'ERROR' }).Count -gt 0)) -Name 'wrong fixed source, nested destination, and in-clone evidence root are rejected' -Failures $failures

        $renamedBundleRoot = Join-Path $evidenceRoot 'renamed-gate-bundle'
        [void](New-Item -ItemType Directory -Path $renamedBundleRoot)
        foreach ($artifactName in $script:D32BundleArtifactNames) {
            [System.IO.File]::Copy((Join-Path $bundleRoot $artifactName), (Join-Path $renamedBundleRoot $artifactName))
        }
        $renamedBundleManifest = Join-Path $renamedBundleRoot $script:D32BundleManifestName
        [System.IO.File]::Copy($bundleManifest, $renamedBundleManifest)
        $renamedBundle = $validBundleJson | ConvertFrom-D32Json
        $renamedBundle.bundle_path = Get-D32AbsolutePath -Path $renamedBundleRoot
        foreach ($artifact in $renamedBundle.artifacts) {
            $artifact.bundle_path = Get-D32AbsolutePath -Path (Join-Path $renamedBundleRoot ([string]$artifact.name))
        }
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $renamedBundle -BundleManifest $renamedBundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.path' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'non-canonical gate bundle directory name is rejected' -Failures $failures

        $wrongTargetBundle = $validBundleJson | ConvertFrom-D32Json
        $wrongTargetBundle.build_targets.vita = Join-Path $root 'build'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $wrongTargetBundle -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.build_targets' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'non-canonical release target directory is rejected' -Failures $failures

        $missingBuildTarget = $validBundleJson | ConvertFrom-D32Json
        Remove-D32JsonProperty -Object $missingBuildTarget.build_targets -Name 'host'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $missingBuildTarget -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.build_targets.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'nested build-target missing field is rejected' -Failures $failures

        $extraBuildTarget = $validBundleJson | ConvertFrom-D32Json
        $extraBuildTarget.build_targets | Add-Member -NotePropertyName unexpected -NotePropertyValue 'not-allowed'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $extraBuildTarget -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.build_targets.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'nested build-target extra field is rejected' -Failures $failures

        $wrongTypeBuildTarget = $validBundleJson | ConvertFrom-D32Json
        $wrongTypeBuildTarget.build_targets.vita = 7
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $wrongTypeBuildTarget -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.build_targets' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'nested build-target wrong type is rejected' -Failures $failures

        $wrongAttestedSource = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
        $wrongAttestedSource.artifacts[0].build_path = $fakeCargo
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $wrongAttestedSource -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.artifact.vita-agent.exe.path' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'attestation artifact source path is fixed to the expected release output' -Failures $failures

        $identityTamper = $validBundleJson | ConvertFrom-D32Json
        $identityTamper.artifacts[0].build_identity.Length = [Int64]$identityTamper.artifacts[0].build_identity.Length + 1
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $identityTamper -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.artifact.vita-agent.exe.build.identity.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'stale file identity is rejected' -Failures $failures

        $missingIdentityField = $validBundleJson | ConvertFrom-D32Json
        Remove-D32JsonProperty -Object $missingIdentityField.artifacts[0].build_identity -Name 'FileIdHex'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $missingIdentityField -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.artifact.vita-agent.exe.build.identity.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'nested identity missing field is rejected' -Failures $failures

        $extraIdentityField = $validBundleJson | ConvertFrom-D32Json
        $extraIdentityField.artifacts[0].build_identity | Add-Member -NotePropertyName unexpected -NotePropertyValue 'not-allowed'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $extraIdentityField -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.artifact.vita-agent.exe.build.identity.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'nested identity extra field is rejected' -Failures $failures

        $wrongTypeIdentityField = $validBundleJson | ConvertFrom-D32Json
        $wrongTypeIdentityField.artifacts[0].build_identity.Length = [string]$wrongTypeIdentityField.artifacts[0].build_identity.Length
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $wrongTypeIdentityField -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.artifact.vita-agent.exe.build.identity.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'nested identity numeric field rejects string coercion' -Failures $failures

        $relativeIdentityPath = $validBundleJson | ConvertFrom-D32Json
        $relativeIdentityPath.artifacts[0].build_identity.FullName = 'vita-agent/target/release/vita-agent.exe'
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle $relativeIdentityPath -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.artifact.vita-agent.exe.build.identity.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'nested identity relative path is rejected' -Failures $failures

        $staleFreshOutput = [System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json
        $staleFreshOutput.fresh_outputs[0].absent_before_build = $false
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $staleFreshOutput -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'attestation.fresh-outputs' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'pre-existing fixed output cannot be attested as fresh' -Failures $failures

        $identityMutationPath = Join-Path $fixture $script:D32BundleSourceRelativePaths['vita-agent.exe']
        $identityMutationAttributes = [System.IO.File]::GetAttributes($identityMutationPath)
        try {
            [System.IO.File]::SetAttributes($identityMutationPath, ($identityMutationAttributes -bor [System.IO.FileAttributes]::ReadOnly))
            $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
            Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.artifact.vita-agent.exe.build.identity.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'live source file identity mutation is rejected with bytes unchanged' -Failures $failures
        }
        finally {
            [System.IO.File]::SetAttributes($identityMutationPath, $identityMutationAttributes)
        }

        $bundleIdentityPath = Join-Path $bundleRoot 'vita-agent.exe'
        $replacementPath = Join-Path $bundleRoot 'same-bytes-replacement.tmp'
        $originalBackupPath = Join-Path $bundleRoot 'original-file.backup'
        $displacedReplacementPath = Join-Path $bundleRoot 'replacement.displaced'
        $originalBundleDigest = Get-D32EvidenceFileDigest -Path $bundleIdentityPath
        $originalBundleItem = Get-Item -LiteralPath $bundleIdentityPath -Force
        try {
            [System.IO.File]::WriteAllBytes($replacementPath, [System.IO.File]::ReadAllBytes($bundleIdentityPath))
            [System.IO.File]::SetCreationTimeUtc($replacementPath, $originalBundleItem.CreationTimeUtc)
            [System.IO.File]::SetLastWriteTimeUtc($replacementPath, $originalBundleItem.LastWriteTimeUtc)
            [System.IO.File]::SetAttributes($replacementPath, $originalBundleItem.Attributes)
            $replacementDigest = Get-D32EvidenceFileDigest -Path $replacementPath
            $replacementSameBytesAndMetadata = $null -ne $replacementDigest -and
                $replacementDigest.Hash -ceq $originalBundleDigest.Hash -and
                $replacementDigest.Identity.Length -eq $originalBundleDigest.Identity.Length -and
                $replacementDigest.Identity.CreationTimeUtcTicks -eq $originalBundleDigest.Identity.CreationTimeUtcTicks -and
                $replacementDigest.Identity.LastWriteUtcTicks -eq $originalBundleDigest.Identity.LastWriteUtcTicks -and
                $replacementDigest.Identity.Attributes -eq $originalBundleDigest.Identity.Attributes -and
                $replacementDigest.Identity.FileIdHex -cne $originalBundleDigest.Identity.FileIdHex
            Assert-D32SelfTest -Condition $replacementSameBytesAndMetadata -Name 'same-byte replacement fixture preserves metadata but changes opened-handle file ID' -Failures $failures
            [System.IO.File]::Replace($replacementPath, $bundleIdentityPath, $originalBackupPath)
            $replacementAtPath = Get-D32EvidenceFileDigest -Path $bundleIdentityPath
            Assert-D32SelfTest -Condition ($null -ne $replacementAtPath -and $replacementAtPath.Hash -ceq $originalBundleDigest.Hash -and $replacementAtPath.Identity.FileIdHex -cne $originalBundleDigest.Identity.FileIdHex) -Name 'same-byte replacement is installed at the attested path' -Failures $failures
            $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
            Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.artifact.vita-agent.exe.bundle.identity.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'same-byte replacement with restored metadata is rejected by file ID' -Failures $failures
        }
        finally {
            if (Test-Path -LiteralPath $originalBackupPath -PathType Leaf) {
                if (Test-Path -LiteralPath $bundleIdentityPath -PathType Leaf) {
                    [System.IO.File]::Replace($originalBackupPath, $bundleIdentityPath, $displacedReplacementPath)
                }
                else {
                    [System.IO.File]::Move($originalBackupPath, $bundleIdentityPath)
                }
            }
            foreach ($temporaryPath in @($replacementPath, $displacedReplacementPath)) {
                if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) { [System.IO.File]::Delete($temporaryPath) }
            }
        }

        $extraEntry = Join-Path $bundleRoot 'unexpected.txt'
        [System.IO.File]::WriteAllText($extraEntry, 'extra')
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Remove-Item -LiteralPath $extraEntry -Force
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.contents' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'extra evidence bundle entry is rejected' -Failures $failures

        $nestedEntry = Join-Path $bundleRoot 'unexpected-directory'
        [void](New-Item -ItemType Directory -Path $nestedEntry)
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Remove-Item -LiteralPath $nestedEntry -Recurse -Force
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.contents' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'nested bundle directory is rejected' -Failures $failures

        $reparseEntry = Join-Path $bundleRoot 'reparse-junction'
        $reparseBundleCreated = $false
        try {
            [void][System.IO.Directory]::CreateSymbolicLink($reparseEntry, $buildRoot)
            $reparseBundleCreated = $true
        }
        catch {
            if (Test-D32ExpectedReparseFixtureUnavailable -Exception $_.Exception) {
                Add-D32SelfTestUnavailable -Name 'bundle directory reparse rejection' -Reason 'the OS/filesystem reports symbolic-link creation unsupported or privilege unavailable'
            }
            else {
                Assert-D32SelfTest -Condition $false -Name 'bundle directory reparse fixture creation failed unexpectedly' -Failures $failures
            }
        }
        if ($reparseBundleCreated) {
            try {
                $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
                Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.contents' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'bundle reparse-point entry is rejected' -Failures $failures
            }
            finally {
                Remove-Item -LiteralPath $reparseEntry -Force -ErrorAction SilentlyContinue
            }
        }

        $tauriConfigPath = Join-Path $fixture 'src-tauri\tauri.conf.json'
        $validTauriConfig = [System.IO.File]::ReadAllText($tauriConfigPath)
        try {
            [System.IO.File]::WriteAllText($tauriConfigPath, '{"bundle":{"resources":{"../vita-agent/target/release/vita-agent.exe":"wrong.exe"}}}', (New-Object System.Text.UTF8Encoding($false)))
            $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        }
        finally {
            [System.IO.File]::WriteAllText($tauriConfigPath, $validTauriConfig, (New-Object System.Text.UTF8Encoding($false)))
        }
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.tauri-resources' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'changed Tauri sidecar map is rejected' -Failures $failures

        try {
            [System.IO.File]::WriteAllText($tauriConfigPath, '{"bundle":{"resources":{"../vita-agent/target/release/vita-agent.exe":"vita-agent.exe","unexpected.exe":"unexpected.exe"}}}', (New-Object System.Text.UTF8Encoding($false)))
            $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        }
        finally {
            [System.IO.File]::WriteAllText($tauriConfigPath, $validTauriConfig, (New-Object System.Text.UTF8Encoding($false)))
        }
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.tauri-resources' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'extra Tauri runtime resource is rejected' -Failures $failures

        $corruptArtifactPath = Join-Path $bundleRoot 'vita-agent.exe'
        [System.IO.File]::WriteAllBytes($corruptArtifactPath, [Text.Encoding]::UTF8.GetBytes('corrupt bundle bytes'))
        $negative = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $validAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($negative | Where-Object { $_.Check -eq 'bundle.artifact.vita-agent.exe.sha256' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'corrupted bundle bytes fail exact SHA validation' -Failures $failures

        $validFixtureJson = [System.IO.File]::ReadAllText($fixtureManifest)

        foreach ($missingField in @('generated_at_utc', 'started_at_utc', 'elapsed_ms', 'working_tree_status', 'process_tree_error')) {
            $missingTopLevel = $validFixtureJson | ConvertFrom-D32Json
            Remove-D32JsonProperty -Object $missingTopLevel -Name $missingField
            $missingTopLevelFindings = New-D32FindingList
            Test-D32FixtureManifest -FixtureManifest $missingTopLevel -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $missingTopLevelFindings
            Assert-D32SelfTest -Condition (@($missingTopLevelFindings | Where-Object { $_.Check -eq 'fixture-manifest.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name "fixture manifest missing top-level $missingField is rejected" -Failures $failures
        }

        foreach ($missingField in @('pid', 'root_identity', 'descendant_identities', 'residual_descendant_identities', 'reap', 'elapsed_ms', 'phase_log', 'stdout_log', 'stderr_log', 'error', 'exit_code', 'artifact')) {
            $missingRecordField = $validFixtureJson | ConvertFrom-D32Json
            Remove-D32JsonProperty -Object $missingRecordField.fixtures[0] -Name $missingField
            $missingRecordFieldFindings = New-D32FindingList
            Test-D32FixtureManifest -FixtureManifest $missingRecordField -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $missingRecordFieldFindings
            Assert-D32SelfTest -Condition (@($missingRecordFieldFindings | Where-Object { $_.Check -eq 'fixture-manifest.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name "fixture manifest missing record $missingField is rejected" -Failures $failures
        }

        $wrongTopLevelType = $validFixtureJson | ConvertFrom-D32Json
        $wrongTopLevelType.elapsed_ms = '1'
        $wrongTopLevelTypeFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest $wrongTopLevelType -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $wrongTopLevelTypeFindings
        Assert-D32SelfTest -Condition (@($wrongTopLevelTypeFindings | Where-Object { $_.Check -eq 'fixture-manifest.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest wrong top-level type is rejected' -Failures $failures

        $negativeElapsed = $validFixtureJson | ConvertFrom-D32Json
        $negativeElapsed.elapsed_ms = -1
        $negativeElapsedFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest $negativeElapsed -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $negativeElapsedFindings
        Assert-D32SelfTest -Condition (@($negativeElapsedFindings | Where-Object { $_.Check -eq 'fixture-manifest.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest negative elapsed is rejected' -Failures $failures

        $dirtyWorkingTreeStatus = $validFixtureJson | ConvertFrom-D32Json
        $dirtyWorkingTreeStatus.working_tree_status = 'dirty'
        $dirtyWorkingTreeFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest $dirtyWorkingTreeStatus -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $dirtyWorkingTreeFindings
        Assert-D32SelfTest -Condition (@($dirtyWorkingTreeFindings | Where-Object { $_.Check -eq 'fixture-manifest.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest non-empty working tree status is rejected' -Failures $failures

        $missingNullableField = $validFixtureJson | ConvertFrom-D32Json
        Remove-D32JsonProperty -Object $missingNullableField.environment -Name 'rustup_toolchain'
        Remove-D32JsonProperty -Object $missingNullableField.fixtures[0].reap.residual_identities[0] -Name 'parent_process_id'
        $missingNullableFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest $missingNullableField -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $missingNullableFindings
        Assert-D32SelfTest -Condition (@($missingNullableFindings | Where-Object { $_.Check -eq 'fixture-manifest.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest missing nullable properties is rejected' -Failures $failures

        $wrongRecordType = $validFixtureJson | ConvertFrom-D32Json
        $wrongRecordType.fixtures[0].pid = $true
        $wrongRecordTypeFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest $wrongRecordType -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $wrongRecordTypeFindings
        Assert-D32SelfTest -Condition (@($wrongRecordTypeFindings | Where-Object { $_.Check -eq 'fixture-manifest.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest wrong record type is rejected' -Failures $failures

        $wrongNullableType = $validFixtureJson | ConvertFrom-D32Json
        $wrongNullableType.fixtures[0].error = 7
        $wrongNullableTypeFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest $wrongNullableType -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $wrongNullableTypeFindings
        Assert-D32SelfTest -Condition (@($wrongNullableTypeFindings | Where-Object { $_.Check -eq 'fixture-manifest.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest nullable field wrong type is rejected' -Failures $failures

        $wrongNestedType = $validFixtureJson | ConvertFrom-D32Json
        $wrongNestedType.fixtures[0].reap.residual_identities[0].identity_verified = 'true'
        $wrongNestedTypeFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest $wrongNestedType -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $wrongNestedTypeFindings
        Assert-D32SelfTest -Condition (@($wrongNestedTypeFindings | Where-Object { $_.Check -eq 'fixture-manifest.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest nested identity wrong type is rejected' -Failures $failures

        $wrongFixtureSha = $validFixtureJson | ConvertFrom-D32Json
        $wrongFixtureSha.candidate_sha = ('0' * 40)
        Write-D32Json -Path $fixtureManifest -Value $wrongFixtureSha
        $wrongFixtureShaFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest (Read-D32Json -Path $fixtureManifest -Findings $wrongFixtureShaFindings -Check 'fixture-selftest.sha') -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $wrongFixtureShaFindings
        Assert-D32SelfTest -Condition (@($wrongFixtureShaFindings | Where-Object { $_.Check -eq 'fixture-manifest.candidate_sha' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest wrong candidate SHA is reported' -Failures $failures

        $wrongFixturePolicy = $validFixtureJson | ConvertFrom-D32Json
        $wrongFixturePolicy.build_policy.process_tree_timeout_action = 'taskkill /T /F then verify every captured descendant PID'
        Write-D32Json -Path $fixtureManifest -Value $wrongFixturePolicy
        $wrongFixturePolicyFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest (Read-D32Json -Path $fixtureManifest -Findings $wrongFixturePolicyFindings -Check 'fixture-selftest.policy') -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $wrongFixturePolicyFindings
        Assert-D32SelfTest -Condition (@($wrongFixturePolicyFindings | Where-Object { $_.Check -eq 'fixture-manifest.policy' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest non-canonical timeout action is reported' -Failures $failures

        $wrongFixtureHash = $validFixtureJson | ConvertFrom-D32Json
        $wrongFixtureHash.fixtures[0].artifact.sha256 = ('0' * 64)
        Write-D32Json -Path $fixtureManifest -Value $wrongFixtureHash
        $wrongFixtureHashFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest (Read-D32Json -Path $fixtureManifest -Findings $wrongFixtureHashFindings -Check 'fixture-selftest.hash') -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $wrongFixtureHashFindings
        Assert-D32SelfTest -Condition (@($wrongFixtureHashFindings | Where-Object { $_.Check -eq 'fixture-manifest.d29h1-authority-fixture' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest wrong artifact hash is reported' -Failures $failures

        $wrongFixturePath = $validFixtureJson | ConvertFrom-D32Json
        $wrongFixturePath.fixtures[0].artifact.path = $image
        Write-D32Json -Path $fixtureManifest -Value $wrongFixturePath
        $wrongFixturePathFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest (Read-D32Json -Path $fixtureManifest -Findings $wrongFixturePathFindings -Check 'fixture-selftest.path') -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $wrongFixturePathFindings
        Assert-D32SelfTest -Condition (@($wrongFixturePathFindings | Where-Object { $_.Check -eq 'fixture-manifest.d29h1-authority-fixture' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest wrong artifact path is reported' -Failures $failures

        $wrongFixtureFeature = $validFixtureJson | ConvertFrom-D32Json
        $wrongFixtureFeature.fixtures[0].features = @('wrong-feature')
        Write-D32Json -Path $fixtureManifest -Value $wrongFixtureFeature
        $wrongFixtureFeatureFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest (Read-D32Json -Path $fixtureManifest -Findings $wrongFixtureFeatureFindings -Check 'fixture-selftest.feature') -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $wrongFixtureFeatureFindings
        Assert-D32SelfTest -Condition (@($wrongFixtureFeatureFindings | Where-Object { $_.Check -eq 'fixture-manifest.d29h1-authority-fixture' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest wrong feature is reported' -Failures $failures

        $replacedArtifactPath = ($validFixtureJson | ConvertFrom-D32Json).fixtures[0].artifact.path
        $replacedArtifactBytes = [System.IO.File]::ReadAllBytes($replacedArtifactPath)
        [System.IO.File]::WriteAllBytes($replacedArtifactPath, [Text.Encoding]::UTF8.GetBytes('replaced-after-build'))
        $replacedFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest ($validFixtureJson | ConvertFrom-D32Json) -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $replacedFindings
        Assert-D32SelfTest -Condition (@($replacedFindings | Where-Object { $_.Check -eq 'fixture-manifest.d29h1-authority-fixture' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'replaced or stale fixture artifact is reported' -Failures $failures
        [System.IO.File]::WriteAllBytes($replacedArtifactPath, $replacedArtifactBytes)

        $unknownFixtureField = $validFixtureJson | ConvertFrom-D32Json
        Add-Member -InputObject $unknownFixtureField.fixtures[0] -MemberType NoteProperty -Name 'captured_descendant_pids' -Value @([int]1)
        Write-D32Json -Path $fixtureManifest -Value $unknownFixtureField
        $unknownFixtureFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest (Read-D32Json -Path $fixtureManifest -Findings $unknownFixtureFindings -Check 'fixture-selftest.unknown') -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $unknownFixtureFindings
        Assert-D32SelfTest -Condition (@($unknownFixtureFindings | Where-Object { $_.Check -eq 'fixture-manifest.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest unknown legacy field is rejected' -Failures $failures

        $unknownResidualIdentityField = $validFixtureJson | ConvertFrom-D32Json
        Add-Member -InputObject $unknownResidualIdentityField.fixtures[0].reap.residual_identities[0] -MemberType NoteProperty -Name 'unexpected_identity_field' -Value 'rejected'
        $unknownResidualIdentityFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest $unknownResidualIdentityField -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $unknownResidualIdentityFindings
        Assert-D32SelfTest -Condition (@($unknownResidualIdentityFindings | Where-Object { $_.Check -eq 'fixture-manifest.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'fixture manifest nested residual identity unknown field is rejected' -Failures $failures
        Write-D32Json -Path $fixtureManifest -Value ($validFixtureJson | ConvertFrom-D32Json)
        $missingTrustResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -FixtureManifest $fixtureManifest -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run-missing-trust') -Modes $null
        Assert-D32SelfTest -Condition ((-not $missingTrustResult.Success) -and @($missingTrustResult.Findings | Where-Object { $_.Check -eq 'git.trusted-image' -and $_.Severity -eq 'ERROR' }).Count -eq 1) -Name 'validation requires explicit trusted Git path and hash' -Failures $failures

        $validJson = [System.IO.File]::ReadAllText($provenance)
        $missingField = $validJson | ConvertFrom-D32Json
        [void]$missingField.PSObject.Properties.Remove('git_status')
        Write-D32Json -Path $provenance -Value $missingField
        $missingResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -FixtureManifest $fixtureManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run-2') -Modes $null
        Assert-D32SelfTest -Condition (-not $missingResult.Success) -Name 'missing provenance field is reported' -Failures $failures

        $wrongPath = $validJson | ConvertFrom-D32Json
        $wrongPath.image_path = [System.IO.Path]::GetFullPath($image)
        Write-D32Json -Path $provenance -Value $wrongPath
        $wrongPathResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -FixtureManifest $fixtureManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run-3') -Modes $null
        Assert-D32SelfTest -Condition (-not $wrongPathResult.Success) -Name 'ordinary image path is rejected' -Failures $failures

        $wrongHash = $validJson | ConvertFrom-D32Json
        $wrongHash.image_sha256 = ('0' * 64)
        Write-D32Json -Path $provenance -Value $wrongHash
        $wrongHashResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -FixtureManifest $fixtureManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run-4') -Modes $null
        Assert-D32SelfTest -Condition (-not $wrongHashResult.Success) -Name 'image hash mismatch is reported' -Failures $failures

        Write-D32Json -Path $provenance -Value ($validJson | ConvertFrom-D32Json)
        $dirtyMarker = Join-Path $fixture 'dirty-marker.txt'
        [System.IO.File]::WriteAllText($dirtyMarker, 'dirty')
        $dirtyResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -FixtureManifest $fixtureManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run-5') -Modes $null
        Assert-D32SelfTest -Condition (-not $dirtyResult.Success) -Name 'dirty repository is reported' -Failures $failures
        Remove-Item -LiteralPath $dirtyMarker -Force

        $unknownModes = @($script:D32CanonicalModes + @('unknown-mode'))
        $unknownModeResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -FixtureManifest $fixtureManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run-6') -Modes $unknownModes
        Assert-D32SelfTest -Condition (-not $unknownModeResult.Success) -Name 'unknown mode is reported' -Failures $failures

        [System.IO.File]::WriteAllText($existing, 'sentinel')
        $before = [System.IO.File]::ReadAllText($existing)
        $existingResult = Invoke-D32GenerateManifest -Repository $fixture -Manifest $existing -Image $image -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash
        $after = [System.IO.File]::ReadAllText($existing)
        Assert-D32SelfTest -Condition ((-not $existingResult.Success) -and $before -ceq $after) -Name 'existing target is never overwritten' -Failures $failures

        $existingRunRoot = Join-Path $root 'existing-run'
        [void](New-Item -ItemType Directory -Path $existingRunRoot -Force)
        $existingRunResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -FixtureManifest $fixtureManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot $existingRunRoot -Modes $null
        Assert-D32SelfTest -Condition (-not $existingRunResult.Success) -Name 'existing run output root is rejected' -Failures $failures
        # The existing-run fixture is deliberately inside the owned root; the
        # final exact-marker cleanup removes the one self-test root.
    }
    catch {
        Write-Host ("SELFTEST ERROR: setup or assertion failed: {0}" -f $_.Exception.Message)
        [void]$failures.Add('setup or assertion failed')
    }
    finally {
        if ($rootOwned -and -not (Remove-D32OwnedTempRoot -Root $root -Marker $rootMarker -Token $rootToken)) {
            Write-Host 'SELFTEST ERROR: owned temp root failed exact-marker/reparse cleanup'
            [void]$failures.Add('owned temp root cleanup failed')
        }
    }
    if ($failures.Count -eq 0) {
        if ($script:D32SelfTestUnavailableCount -eq 0) {
            Write-Host "D32 preflight self-test: PASS ($($script:D32SelfTestAssertionCount) assertions)"
            return $true
        }
        else {
            $unavailableNames = @($script:D32SelfTestUnavailableCases | ForEach-Object { [string]$_ }) -join ', '
            Write-Host "D32 preflight self-test: BLOCKED (required negative evidence unavailable: $unavailableNames; $($script:D32SelfTestAssertionCount) assertions)"
            return $false
        }
    }
    Write-Host "D32 preflight self-test: BLOCKED ($($failures.Count) failure(s), $($script:D32SelfTestAssertionCount) assertions)"
    return $false
}

if ($LibraryOnly) {
    return
}

if (-not (Test-D32SupportedPowerShellVersion -Version $PSVersionTable.PSVersion)) {
    Write-Output "D32 preflight: BLOCKED — PowerShell 7.5 or newer is required; current=$($PSVersionTable.PSVersion)"
    exit 2
}

if ([String]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}

if ($GitProcessSelfTest) {
    if ($SelfTest -or $GenerateManifest -or $GenerateBundle -or $GenerateAggregateRecord -or $ValidateOnly) {
        Write-Output 'D32 preflight Git process self-test: BLOCKED — choose only -GitProcessSelfTest'
        exit 2
    }
    if ([String]::IsNullOrWhiteSpace($TrustedGitPath) -or [String]::IsNullOrWhiteSpace($TrustedGitSha256)) {
        Write-Output 'D32 preflight Git process self-test: BLOCKED — exact Coordinator-pinned Git path/SHA are mandatory'
        exit 2
    }
    try {
        $null = Invoke-D32PreflightGitProcessSelfTest -Repository $RepoRoot -GitPath $TrustedGitPath -GitSha256 $TrustedGitSha256
        exit 0
    }
    catch {
        Write-Output "D32 preflight Git process self-test: BLOCKED — $($_.Exception.Message)"
        exit 1
    }
}

if ($SelfTest) {
    if ([String]::IsNullOrWhiteSpace($TrustedGitPath) -or [String]::IsNullOrWhiteSpace($TrustedGitSha256) -or
        [String]::IsNullOrWhiteSpace($ToolchainProfilePath) -or [String]::IsNullOrWhiteSpace($ExpectedToolchainProfileSha256)) {
        Write-Output 'D32 preflight self-test: BLOCKED — exact Git path/SHA and caller-pinned toolchain-profile path/SHA are mandatory for V2 capture'
        exit 2
    }
    $selfTestGitProfile = Test-D32BuildToolchainProfile -ProfilePath $ToolchainProfilePath -ExpectedSha256 $ExpectedToolchainProfileSha256 -Repository $RepoRoot -ExpectedTargetTriple 'x86_64-pc-windows-msvc'
    if (-not $selfTestGitProfile.IsValid) {
        Write-Output "D32 preflight self-test: BLOCKED — caller-pinned V2 Git profile failed validation: $($selfTestGitProfile.Failure)"
        exit 2
    }
    try { Set-D32GitCaptureContext -ValidatedProfile $selfTestGitProfile -GitPath $TrustedGitPath -GitSha256 $TrustedGitSha256 -TimeoutSeconds 120 }
    catch { Write-Output "D32 preflight self-test: BLOCKED — V2 capture context failed: $($_.Exception.Message)"; exit 2 }
    if (Invoke-D32SelfTest) { exit 0 }
    exit 1
}
if ([String]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $RepoRoot 'artifacts\d32-candidate-provenance.json'
}
if ([String]::IsNullOrWhiteSpace($ImagePath)) {
    $ImagePath = Join-Path $RepoRoot 'vita-agent\target\release\vita-agent.exe'
}
if ([String]::IsNullOrWhiteSpace($BundleManifestPath)) {
    $BundleManifestPath = Join-Path (Join-Path $RepoRoot ('artifacts\' + $script:D32BundleDirectoryName)) $script:D32BundleManifestName
}
if ([String]::IsNullOrWhiteSpace($AttestationPath)) {
    $AttestationPath = Join-Path (Split-Path -Parent (Split-Path -Parent $BundleManifestPath)) $script:D32AttestationName
}
if (-not $GenerateManifest -and -not $GenerateBundle -and -not $GenerateAggregateRecord -and -not $ValidateOnly) {
    $ValidateOnly = $true
}
if (@([bool]$GenerateManifest, [bool]$GenerateBundle, [bool]$GenerateAggregateRecord, [bool]$ValidateOnly | Where-Object { $_ }).Count -gt 1) {
    Write-Output 'D32 preflight: choose only one of -GenerateManifest, -GenerateBundle, -GenerateAggregateRecord, or -ValidateOnly'
    exit 2
}
if (-not $GenerateAggregateRecord -and -not [String]::IsNullOrWhiteSpace($AggregateRecordSha256) -and -not $ValidateOnly) {
    Write-Output 'D32 preflight: -AggregateRecordSha256 is accepted only with -ValidateOnly'
    exit 2
}

if ([String]::IsNullOrWhiteSpace($ToolchainProfilePath) -or [String]::IsNullOrWhiteSpace($ExpectedToolchainProfileSha256)) {
    Write-Output 'D32 preflight: BLOCKED — caller-pinned toolchain-profile path/SHA are mandatory for V2 Git process identity and the optional conhost child pin'
    exit 2
}
$gitCaptureProfile = Test-D32BuildToolchainProfile -ProfilePath $ToolchainProfilePath -ExpectedSha256 $ExpectedToolchainProfileSha256 -Repository $RepoRoot -ExpectedTargetTriple 'x86_64-pc-windows-msvc'
if (-not $gitCaptureProfile.IsValid) {
    Write-Output "D32 preflight: BLOCKED — caller-pinned V2 Git toolchain profile failed validation: $($gitCaptureProfile.Failure)"
    exit 2
}
try {
    Set-D32GitCaptureContext -ValidatedProfile $gitCaptureProfile -GitPath $TrustedGitPath -GitSha256 $TrustedGitSha256 -TimeoutSeconds ([int][Math]::Ceiling($script:D32GitTimeoutMilliseconds / 1000.0))
}
catch {
    Write-Output "D32 preflight: BLOCKED — caller-pinned V2 Git capture context failed: $($_.Exception.Message)"
    exit 2
}

if ($GenerateBundle) {
    if ([String]::IsNullOrWhiteSpace($EvidenceRoot) -or [String]::IsNullOrWhiteSpace($ExpectedSha) -or [String]::IsNullOrWhiteSpace($TrustedGitPath) -or [String]::IsNullOrWhiteSpace($TrustedGitSha256) -or [String]::IsNullOrWhiteSpace($Phase0RecordPath) -or [String]::IsNullOrWhiteSpace($Phase0RecordSha256) -or [String]::IsNullOrWhiteSpace($ToolchainProfilePath) -or [String]::IsNullOrWhiteSpace($ExpectedToolchainProfileSha256)) {
        Write-Output 'D32 bundle generation: EvidenceRoot, exact candidate/Git pins, and caller-pinned Phase0 record/profile path+SHA pins are mandatory'
        exit 2
    }
    $generation = Invoke-D32GenerateBundle -Repository $RepoRoot -EvidenceRoot $EvidenceRoot -ExpectedCandidateSha $ExpectedSha -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Phase0RecordPath $Phase0RecordPath -Phase0RecordSha256 $Phase0RecordSha256 -ToolchainProfilePath $ToolchainProfilePath -ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256
    Write-D32Result -Operation 'release evidence bundle generation' -Result $generation
    if ($generation.Success) {
        Write-Output "bundle_manifest=$($generation.BundleManifest)"
        Write-Output "build_attestation=$($generation.Attestation)"
        exit 3
    }
    exit 1
}

if ($GenerateManifest) {
    $generation = Invoke-D32GenerateManifest -Repository $RepoRoot -Manifest $ManifestPath -Image $ImagePath -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256
    Write-D32Result -Operation 'manifest generation' -Result $generation
    if ($generation.Success) { exit 0 }
    exit 1
}

if ($GenerateAggregateRecord) {
    if ([String]::IsNullOrWhiteSpace($EvidenceRoot) -or [String]::IsNullOrWhiteSpace($ExpectedSha) -or [String]::IsNullOrWhiteSpace($TrustedGitPath) -or [String]::IsNullOrWhiteSpace($TrustedGitSha256) -or [String]::IsNullOrWhiteSpace($Phase0RecordPath) -or [String]::IsNullOrWhiteSpace($Phase0RecordSha256) -or [String]::IsNullOrWhiteSpace($ToolchainProfilePath) -or [String]::IsNullOrWhiteSpace($ExpectedToolchainProfileSha256) -or [String]::IsNullOrWhiteSpace($FixtureManifestPath) -or [String]::IsNullOrWhiteSpace($AttestationPath)) {
        Write-Output 'D32 post-bundle aggregate record generation: EvidenceRoot, provenance/fixture/bundle/attestation paths, exact candidate/Git pins, and caller-pinned Phase0 record/profile path+SHA pins are mandatory'
        exit 2
    }
    if ([String]::IsNullOrWhiteSpace($AggregateRecordPath)) { $AggregateRecordPath = Join-Path $EvidenceRoot $script:D32PostBundleAggregateRecordName }
    $recordGeneration = Invoke-D32GeneratePostBundleAggregateRecord -Repository $RepoRoot -Manifest $ManifestPath -Image $ImagePath -BundleManifest $BundleManifestPath -AttestationPath $AttestationPath -FixtureManifest $FixtureManifestPath -EvidenceRoot $EvidenceRoot -RecordPath $AggregateRecordPath -ExpectedCandidateSha $ExpectedSha -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -Phase0RecordPath $Phase0RecordPath -Phase0RecordSha256 $Phase0RecordSha256 -ToolchainProfilePath $ToolchainProfilePath -ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256
    Write-D32Result -Operation 'post-bundle aggregate record generation' -Result $recordGeneration
    if ($recordGeneration.Success) {
        Write-Output "aggregate_record=$($recordGeneration.RecordPath)"
        Write-Output "aggregate_record_sha256=$($recordGeneration.RecordSha256)"
        Write-Output 'next=rerun -ValidateOnly with this record path and an independently supplied SHA-256 pin; this generation step is not an aggregate PASS'
        exit 3
    }
    exit 1
}

$validation = Invoke-D32Validation -Repository $RepoRoot -Manifest $ManifestPath -Image $ImagePath -BundleManifest $BundleManifestPath -AttestationPath $AttestationPath -FixtureManifest $FixtureManifestPath -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -ExpectedCandidateSha $ExpectedSha -Base $BaseSha -MergeBase $MergeBaseSha -RunRoot $RunOutputRoot -Modes $RequestedModes -Phase0RecordPath $Phase0RecordPath -Phase0RecordSha256 $Phase0RecordSha256 -ToolchainProfilePath $ToolchainProfilePath -ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256
if (-not [String]::IsNullOrWhiteSpace($AggregateRecordPath) -or -not [String]::IsNullOrWhiteSpace($AggregateRecordSha256)) {
    if ([String]::IsNullOrWhiteSpace($AggregateRecordPath) -or [String]::IsNullOrWhiteSpace($AggregateRecordSha256) -or [String]::IsNullOrWhiteSpace($EvidenceRoot) -or [String]::IsNullOrWhiteSpace($ExpectedSha) -or [String]::IsNullOrWhiteSpace($Phase0RecordPath) -or [String]::IsNullOrWhiteSpace($Phase0RecordSha256) -or [String]::IsNullOrWhiteSpace($ToolchainProfilePath) -or [String]::IsNullOrWhiteSpace($ExpectedToolchainProfileSha256) -or [String]::IsNullOrWhiteSpace($TrustedGitPath) -or [String]::IsNullOrWhiteSpace($TrustedGitSha256) -or [String]::IsNullOrWhiteSpace($FixtureManifestPath) -or [String]::IsNullOrWhiteSpace($AttestationPath)) {
        Add-D32Finding -Findings $validation.Findings -Severity ERROR -Check 'aggregate.record' -Message 'aggregate validation requires the record path/hash, external EvidenceRoot, exact candidate/Git pins, Phase0/profile pins, fixture manifest, and explicit bundle/attestation paths'
        $validation.Success = $false
        $validation.Status = 'BLOCKED'
    }
    elseif ($validation.Success) {
        $aggregatePinFindings = New-D32FindingList
        $aggregateRecord = Test-D32PostBundleAggregateRecord -RecordPath $AggregateRecordPath -ExpectedRecordSha256 $AggregateRecordSha256 -Repository $RepoRoot -ExpectedCandidateSha $ExpectedSha -EvidenceRoot $EvidenceRoot -Phase0RecordPath $Phase0RecordPath -ToolchainProfilePath $ToolchainProfilePath -FixtureManifestPath $FixtureManifestPath -ManifestPath $ManifestPath -BundleManifestPath $BundleManifestPath -AttestationPath $AttestationPath -TrustedGitPath $TrustedGitPath -Findings $aggregatePinFindings
        if ($aggregateRecord.IsValid) { $null = Test-D32PostBundleAggregateReadiness -Validation $validation -Findings $aggregatePinFindings }
        foreach ($finding in $aggregatePinFindings) { [void]$validation.Findings.Add($finding) }
        if ($aggregateRecord.IsValid -and @($aggregatePinFindings | Where-Object { $_.Severity -eq 'ERROR' }).Count -eq 0) {
            $statusFinding = @($validation.Findings | Where-Object { $_.Check -ceq 'aggregate.status' -and $_.Severity -eq 'INFO' }) | Select-Object -First 1
            if ($null -ne $statusFinding) {
                $statusFinding.Severity = 'PASS'
                $statusFinding.Message = 'POST_BUNDLE_AGGREGATE_PASS: current bundle hashes and complete pre-downstream local Phase0 evidence independently revalidated; downstream real gates remain NOT RUN'
            }
            $validation.Success = $true
            $validation.Status = 'POST_BUNDLE_AGGREGATE_PASS'
        }
        else {
            $validation.Success = $false
            $validation.Status = 'BLOCKED'
        }
    }
}
Write-D32Result -Operation 'preflight' -Result $validation
if ($validation.Success -and $validation.Status -eq 'ARTIFACT_ONLY') { exit 3 }
if ($validation.Success -and $validation.Status -eq 'POST_BUNDLE_AGGREGATE_PASS') { exit 0 }
if ($validation.Success) { exit 3 }
exit 1
