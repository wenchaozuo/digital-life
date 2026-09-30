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

    [string]$PowerShellModuleAuthorityPath,

    [string]$ExpectedPowerShellModuleAuthoritySha256,

    [string]$ModuleAuthorityCandidateSha,

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

. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
$null = Initialize-D32PowerShellModuleAuthority -CallerProfilePath $ToolchainProfilePath `
    -CallerExpectedProfileSha256 $ExpectedToolchainProfileSha256 `
    -CallerModuleAuthorityPath $PowerShellModuleAuthorityPath `
    -CallerExpectedModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
    -CallerCandidateSha $ModuleAuthorityCandidateSha -CallerRepository $RepoRoot `
    -CallerGitPath $TrustedGitPath -CallerGitSha256 $TrustedGitSha256 `
    -EntryScriptPath $PSCommandPath `
    -LocalSelfTestOnly:$SelfTest

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:D32PreflightGitCaptureModule = $null
$script:D32GitCaptureContext = $null
$script:D32LastPreflightGitCapture = $null
$script:D32LastPreflightGitCaptureFailure = $null
$script:D32LastPreflightGitProcessCapture = $null
. (Join-Path $PSScriptRoot 'd32-build-toolchain-profile.ps1')
if ($Phase0DependencyLibraryOnly -and -not $LibraryOnly) {
    throw 'PHASE0_DEPENDENCY_IMPORT_INVALID: dependency-only import requires -LibraryOnly'
}
if (-not $Phase0DependencyLibraryOnly) {
    . (Join-Path $PSScriptRoot 'd32-phase0-matrix.ps1') -Phase0LibraryOnly `
        -Phase0ToolchainProfilePath $ToolchainProfilePath -Phase0ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256 `
        -Phase0PowerShellModuleAuthorityPath $PowerShellModuleAuthorityPath -Phase0ExpectedPowerShellModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
        -Phase0ExpectedCandidateSha $ModuleAuthorityCandidateSha -Phase0RepoRoot $RepoRoot -Phase0PinnedGitPath $TrustedGitPath -Phase0PinnedGitSha256 $TrustedGitSha256
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
$script:D32AttestationSchemaVersion = 9
$script:D32PostBundleAggregateSchemaVersion = 8
$script:D32PostBundleAggregateRecordName = 'D32-POST-BUNDLE-AGGREGATE.json'
$script:D32PostBundleAggregateRecordType = 'D32_POST_BUNDLE_AGGREGATE_RECORD_V8'
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

function Protect-D32PreflightSelfTestDiagnosticText {
    param(
        [AllowNull()][string]$Text,
        [AllowNull()][string]$OwnedRoot,
        [AllowNull()][string]$FixtureRepository
    )

    $value = [string]$Text
    foreach ($path in @($OwnedRoot, $FixtureRepository)) {
        if (-not [String]::IsNullOrWhiteSpace([string]$path)) {
            $value = [regex]::Replace($value, [regex]::Escape([string]$path), '<selftest-root>', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }
    $value = [regex]::Replace($value, '(?i)[A-Z]:\\Users\\[^\\\s"<>]+\\AppData\\Local\\Temp\\[^\\\s"<>]+', '<selftest-temp>')
    $value = [regex]::Replace($value, '(?i)[A-Z]:\\\\Users\\\\[^"<>]*?\\\\AppData\\\\Local\\\\Temp\\\\[^"<>]*', '<selftest-temp>')
    $value = [regex]::Replace($value, '(?i)\b(?:https?|ssh|git)://[^\s''"<>]+', '<redacted-url>')
    $value = [regex]::Replace($value, '(?i)\b(password|passwd|token|secret|authorization|credential)\s*[:=]\s*[^\s,;]+', '$1=<redacted>')
    $value = [regex]::Replace($value, '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '<redacted-email>')
    $value = $value.Replace("`r", '\\r').Replace("`n", '\\n').Replace("`t", '\\t')
    return $value
}

function Format-D32PreflightGitSelfTestFailureEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][object]$Result,
        [AllowNull()][object]$RawCapture,
        [AllowNull()][object]$Attempt,
        [AllowNull()][string]$CaptureFailure,
        [AllowNull()][string]$AttemptValidationFailure,
        [Parameter(Mandatory = $true)][string]$OwnedRoot,
        [Parameter(Mandatory = $true)][string]$FixtureRepository
    )

    $stdoutBytes = if ($null -ne $RawCapture) { [long]$RawCapture.StdOutBytes } else { 0L }
    $stderrBytes = if ($null -ne $RawCapture) { [long]$RawCapture.StdErrBytes } else { 0L }
    $stdoutHash = if ($null -ne $RawCapture) { [string]$RawCapture.StdOutSha256 } else { 'unavailable' }
    $stderrHash = if ($null -ne $RawCapture) { [string]$RawCapture.StdErrSha256 } else { 'unavailable' }
    $stdoutText = if ($null -ne $RawCapture) { [string]$RawCapture.StdOutExcerpt } else { '' }
    $stderrText = if ($null -ne $RawCapture) { [string]$RawCapture.StdErrExcerpt } else { '' }
    $stdoutText = Protect-D32PreflightSelfTestDiagnosticText -Text $stdoutText -OwnedRoot $OwnedRoot -FixtureRepository $FixtureRepository
    $stderrText = Protect-D32PreflightSelfTestDiagnosticText -Text $stderrText -OwnedRoot $OwnedRoot -FixtureRepository $FixtureRepository
    $stdoutTruncated = ($null -ne $RawCapture -and [bool]$RawCapture.StdOutTruncated) -or $stdoutText.Length -gt 512
    $stderrTruncated = ($null -ne $RawCapture -and [bool]$RawCapture.StdErrTruncated) -or $stderrText.Length -gt 512
    if ($stdoutText.Length -gt 512) { $stdoutText = $stdoutText.Substring(0, 512) }
    if ($stderrText.Length -gt 512) { $stderrText = $stderrText.Substring(0, 512) }

    $attemptJson = 'unavailable'
    $attemptJsonTruncated = $false
    if ($null -ne $Attempt) {
        $attemptJson = ConvertTo-Json -InputObject $Attempt -Depth 32 -Compress
        $attemptJson = Protect-D32PreflightSelfTestDiagnosticText -Text $attemptJson -OwnedRoot $OwnedRoot -FixtureRepository $FixtureRepository
        if ($attemptJson.Length -gt 48000) {
            $attemptJson = $attemptJson.Substring(0, 48000)
            $attemptJsonTruncated = $true
        }
    }
    $captureFailureText = Protect-D32PreflightSelfTestDiagnosticText -Text $CaptureFailure -OwnedRoot $OwnedRoot -FixtureRepository $FixtureRepository
    $attemptFailureText = Protect-D32PreflightSelfTestDiagnosticText -Text $AttemptValidationFailure -OwnedRoot $OwnedRoot -FixtureRepository $FixtureRepository
    $resultFailureText = Protect-D32PreflightSelfTestDiagnosticText -Text ([string]$Result.Failure) -OwnedRoot $OwnedRoot -FixtureRepository $FixtureRepository
    if ($captureFailureText.Length -gt 512) { $captureFailureText = $captureFailureText.Substring(0, 512) }
    if ($attemptFailureText.Length -gt 512) { $attemptFailureText = $attemptFailureText.Substring(0, 512) }
    if ($resultFailureText.Length -gt 512) { $resultFailureText = $resultFailureText.Substring(0, 512) }
    $stdoutJson = ConvertTo-Json -InputObject ([string]$stdoutText) -Compress
    $stderrJson = ConvertTo-Json -InputObject ([string]$stderrText) -Compress

    return "name=$Name exitCode=$($Result.ExitCode) failure=$resultFailureText captureFailure=$captureFailureText attemptValidationFailure=$attemptFailureText rawStdout={bytes:$stdoutBytes,sha256:$stdoutHash,truncated:$stdoutTruncated,excerpt:$stdoutJson} rawStderr={bytes:$stderrBytes,sha256:$stderrHash,truncated:$stderrTruncated,excerpt:$stderrJson} attemptJsonTruncated=$attemptJsonTruncated attempt=$attemptJson"
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
    $script:D32LastPreflightGitCaptureFailure = $null
    $script:D32LastPreflightGitProcessCapture = $null
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
        if ($isSelfTestSetup) { $script:D32LastPreflightGitProcessCapture = $capture.RawCapture }
        $script:D32LastPreflightGitCaptureFailure = if ([bool]$capture.ProcessValidated) { $null } else { [string]$capture.Failure }
        if (-not [bool]$capture.ProcessValidated) {
            if ($isSelfTestSetup -and $null -ne $capture.RawCapture) {
                $result.ExitCode = [int]$capture.RawCapture.ExitCode
                $result.HasOutput = [bool]$capture.RawCapture.HasOutput
                $result.HasErrorOutput = [bool]$capture.RawCapture.HasErrorOutput
                $result.OutputTruncated = [bool]$capture.RawCapture.OutputTruncated
            }
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
        $script:D32LastPreflightGitCaptureFailure = $_.Exception.Message
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
                    RawCapture = $script:D32LastPinnedGitCaptureResult
                }
            }
            catch {
                return [PSCustomObject]@{
                    ProcessValidated = $false
                    ExitCode = if ($SelfTestFixtureSetup -and $null -ne $script:D32LastPinnedGitCaptureResult) { [int]$script:D32LastPinnedGitCaptureResult.ExitCode } else { -1 }
                    StdOut = if ($SelfTestFixtureSetup -and $null -ne $script:D32LastPinnedGitCaptureResult) { [string]$script:D32LastPinnedGitCaptureResult.StdOutExcerpt } else { '' }
                    StdErr = if ($SelfTestFixtureSetup -and $null -ne $script:D32LastPinnedGitCaptureResult) { [string]$script:D32LastPinnedGitCaptureResult.StdErrExcerpt } else { '' }
                    Attempt = $script:D32LastPinnedGitAttempt
                    RawCapture = if ($SelfTestFixtureSetup) { $script:D32LastPinnedGitCaptureResult } else { $null }
                    Failure = $_.Exception.Message
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
        $candidateRepository = Split-Path -Parent $PSScriptRoot
        foreach ($lockInput in @(Get-D32BuildToolchainLockInputs -Repository $candidateRepository)) {
            foreach ($relativePath in @($lockInput.ManifestPath, $lockInput.LockPath)) {
                $sourcePath = Join-Path $candidateRepository $relativePath
                $fixturePath = Join-Path $fixtureRepository $relativePath
                [void][IO.Directory]::CreateDirectory((Split-Path -Parent $fixturePath))
                [IO.File]::WriteAllBytes($fixturePath, [IO.File]::ReadAllBytes($sourcePath))
            }
        }
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
            $attempt = $script:D32LastPreflightGitCapture
            $attemptValidationFailure = $null
            if ($null -eq $attempt) {
                $attemptValidationFailure = 'V2 attempt trace was unavailable; no process identity or cleanup proof can be asserted'
            }
            else {
                try { Assert-D32PreflightGitCaptureAttempt -Attempt $attempt -Name "fixture-$($setup.Name)" }
                catch { $attemptValidationFailure = $_.Exception.Message }
            }
            if ($setupResult.ExitCode -ne 0 -or $null -ne $setupResult.Failure -or $null -eq $attempt -or $null -ne $attemptValidationFailure) {
                $failureEvidence = Format-D32PreflightGitSelfTestFailureEvidence `
                    -Name "fixture-$($setup.Name)" `
                    -Result $setupResult `
                    -RawCapture $script:D32LastPreflightGitProcessCapture `
                    -Attempt $attempt `
                    -CaptureFailure $script:D32LastPreflightGitCaptureFailure `
                    -AttemptValidationFailure $attemptValidationFailure `
                    -OwnedRoot $owned.Root `
                    -FixtureRepository $fixtureRepository
                throw "PREFLIGHT_GIT_SELFTEST_BLOCKED: marker-owned fixture setup failed with retained bounded Git and V2 evidence: $failureEvidence"
            }
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
        $timeoutProcess = [Diagnostics.Process]::GetCurrentProcess()
        try { $timeoutExecutablePath = [string]$timeoutProcess.MainModule.FileName }
        finally { $timeoutProcess.Dispose() }
        $timeoutImageSnapshot = & $module { param($Path) Get-D32BoundArtifactWithFileId -Path $Path } $timeoutExecutablePath
        $timeoutImage = [PSCustomObject]@{
            Path = [string]$timeoutImageSnapshot.path
            Bytes = [long]$timeoutImageSnapshot.bytes
            Sha256 = [string]$timeoutImageSnapshot.sha256
            VolumeSerialHex = [string]$timeoutImageSnapshot.volume_serial_hex
            FileIdHex = [string]$timeoutImageSnapshot.file_id_hex
        }
        $timeoutMarker = Join-Path $owned.Root 'wait-timeout-user-code-must-not-run.marker'
        $timeoutMarkerLiteral = $timeoutMarker.Replace("'", "''")
        $timeoutCommand = "Set-Content -LiteralPath '$timeoutMarkerLiteral' -Value ran"
        $timeoutResult = & $module {
            param($FilePath, $ExpectedRootPin, $WorkingDirectory, $Arguments)
            Invoke-D32DebugSelfTestProcess -FilePath $FilePath -Arguments $Arguments -WorkingDirectory $WorkingDirectory `
                -ExpectedRootPin $ExpectedRootPin -FailureInjection 'wait-timeout' -TimeoutMilliseconds 5000
        } $timeoutExecutablePath (& $module { param($Image) ConvertTo-D32DebugImagePinText -Image $Image } $timeoutImage) $owned.Root @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $timeoutCommand)
        $timeoutTrace = $timeoutResult.Trace
        $timeoutCleanup = $timeoutResult.Cleanup
        if ($timeoutTrace.State -cne 'BLOCKED' -or [bool]$timeoutTrace.EventChainComplete -or
            [int]$timeoutTrace.DebugEventCount -ne 0 -or [int]$timeoutResult.ContinueCalls -ne 0 -or
            [int]$timeoutTrace.UncontinuedCreateContinueCallCount -ne 0 -or [uint32]$timeoutTrace.JobActiveProcesses -ne 0 -or
            (Test-Path -LiteralPath $timeoutMarker) -or $null -eq $timeoutCleanup -or
            -not [bool]$timeoutCleanup.CleanupSucceeded -or -not [bool]$timeoutCleanup.JobActiveProcessCountVerified -or
            [uint32]$timeoutCleanup.JobActiveProcessCount -ne 0 -or -not [bool]$timeoutCleanup.DebuggerThreadExited -or
            -not [bool]$timeoutCleanup.DebuggerThreadJoined -or -not [bool]$timeoutCleanup.RetainedProcessHandlesSignaled -or
            -not [bool]$timeoutCleanup.DebuggerAssociationAbsent) {
            throw 'PREFLIGHT_GIT_SELFTEST_BLOCKED: injected V2 debugger timeout did not block before CREATE continuation and prove complete Job/debugger/handle cleanup'
        }
        Write-Host 'D32_PREFLIGHT_GIT_PROCESS_SELFTEST PASS (preflight and Phase0 consumers use V2 fast rev-parse/status/ls-files with exact clean-state semantics; wrapper and root-hash mismatch denied before launch; config/source and alternates indirection blocked pre-launch; pinned-root PID/parent/event/Job/descendant/cleanup negatives verified; injected V2 wait-timeout blocked before CREATE continuation with marker absent and complete cleanup)'
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

function Assert-D32Phase0FixtureManifestCorrelation {
    param(
        [Parameter(Mandatory = $true)][object]$Phase0Document,
        [Parameter(Mandatory = $true)][string]$FixtureManifestPath,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [AllowNull()][object]$AggregateReference
    )

    if (-not (Test-D32Phase0ExactProperties -Object $Phase0Document.fixture -Expected @('manifest', 'build_provenance', 'transcript', 'schema_version', 'process_tree_check', 'fixture_names', 'fixture_records', 'log_references', 'per_phase_git_states'))) {
        throw 'Phase0 fixture reference shape is invalid while binding the external fixture manifest'
    }
    Assert-D32Phase0FixtureSummarySchema -Fixture $Phase0Document.fixture
    $phase0Reference = $Phase0Document.fixture.manifest
    if (-not (Test-D32Phase0ExactProperties -Object $phase0Reference -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) {
        throw 'Phase0 fixture manifest reference has missing or extra fields'
    }
    if (-not (Test-D32ProfileCanonicalPathString -Path $FixtureManifestPath) -or -not (Test-D32ProfileNoReparsePath -Path $FixtureManifestPath) -or
        -not (Test-D32ProfilePathEqual -Left $FixtureManifestPath -Right ([string]$phase0Reference.path))) {
        throw 'supplied fixture manifest path is not the exact Phase0-recorded manifest path'
    }
    $null = Test-D32Phase0FileReference -Reference $phase0Reference -AllowedRoot $EvidenceRoot

    if ($null -ne $AggregateReference) {
        if (-not (Test-D32Phase0ExactProperties -Object $AggregateReference -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) {
            throw 'aggregate fixture manifest reference has missing or extra fields'
        }
        if ([Int64]$AggregateReference.bytes -ne [Int64]$phase0Reference.bytes) {
            throw 'aggregate fixture manifest bytes differ from the Phase0-recorded opened-file identity'
        }
        foreach ($field in @('sha256', 'volume_serial_hex', 'file_id_hex')) {
            if ([string]$AggregateReference.$field -cne [string]$phase0Reference.$field) {
                throw "aggregate fixture manifest $field differs from the Phase0-recorded opened-file identity"
            }
        }
        if (-not (Test-D32ProfilePathEqual -Left ([string]$AggregateReference.path) -Right ([string]$phase0Reference.path))) {
            throw 'aggregate fixture manifest path differs from the Phase0-recorded manifest path'
        }
    }
}

function Assert-D32Phase0FixtureSummarySchema {
    param([Parameter(Mandatory = $true)][object]$Fixture)
    if (-not (Test-D32Phase0Integer -Value $Fixture.schema_version) -or [Int64]$Fixture.schema_version -ne 3) {
        throw 'Phase0 fixture summary schema_version must be the JSON integer 3'
    }
}

function Test-D32PreflightPhase0VendoredProtocBinding {
    param(
        [Parameter(Mandatory = $true)][object]$Phase0Document,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile
    )
    if (-not (Test-D32Phase0ExactProperties -Object $Phase0Document.vendored_protoc -Expected @('authority', 'run_grant')) -or
        -not (Test-D32VendoredObjectExactProperties -Object $Phase0Document.vendored_protoc.authority -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32VendoredObjectExactProperties -Object $Phase0Document.vendored_protoc.run_grant -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) {
        throw 'Phase0 vendored-protoc authority/run-grant references are malformed'
    }
    $authorityReference = $Phase0Document.vendored_protoc.authority
    $authority = Test-D32VendoredProtocAuthority `
        -AuthorityPath ([string]$authorityReference.path) `
        -ExpectedAuthoritySha256 ([string]$authorityReference.sha256) `
        -Repository $Repository -CandidateSha $CandidateSha `
        -ValidatedProfile $ValidatedProfile -EvidenceRoot $OutputRoot
    if ((ConvertTo-Json -InputObject $authority.Reference -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $authorityReference -Depth 5 -Compress)) {
        throw 'Phase0 external vendored-protoc authority reference differs from current opened file bytes/identity'
    }
    $runId = [string]$Phase0Document.cargo_home.run_id
    $cargoHome = [string]$Phase0Document.cargo_home.path
    $grant = Test-D32VendoredProtocRunGrant `
        -Reference $Phase0Document.vendored_protoc.run_grant `
        -Repository $Repository -CandidateSha $CandidateSha `
        -ValidatedProfile $ValidatedProfile -EvidenceRoot $OutputRoot `
        -ExpectedRunId $runId -CargoHome $cargoHome `
        -AuthorityPath ([string]$authorityReference.path) `
        -AuthoritySha256 ([string]$authorityReference.sha256) `
        -OwnerMarkerReference $Phase0Document.owner_marker
    if (-not (Test-D32Phase0ExactProperties -Object $Phase0Document.fixture -Expected @('manifest', 'build_provenance', 'transcript', 'schema_version', 'process_tree_check', 'fixture_names', 'fixture_records', 'log_references', 'per_phase_git_states'))) {
        throw 'Phase0 fixture reference shape is invalid for vendored-protoc validation'
    }
    Assert-D32Phase0FixtureSummarySchema -Fixture $Phase0Document.fixture
    Assert-D32Phase0FixtureBuildBudgetRecord -Document $Phase0Document.fixture_build_budget -ExpectedPhase0TimeoutSeconds 14400
    $fixtureProvenance = Test-D32Phase0FixtureBuildProvenance `
        -SidecarPath ([string]$Phase0Document.fixture.build_provenance.path) `
        -ManifestPath ([string]$Phase0Document.fixture.manifest.path) `
        -Repository $Repository -OutputRoot $OutputRoot `
        -ExpectedCandidateSha $CandidateSha `
        -ExpectedRunnerProcessId ([int]$Phase0Document.runner_process_id) `
        -ValidatedProfile $ValidatedProfile `
        -VendoredAuthorityPath ([string]$authorityReference.path) `
        -ExpectedVendoredAuthoritySha256 ([string]$authorityReference.sha256) `
        -ValidatedVendoredGrant $grant `
        -TauriMacrosSourceAuthorityPath ([string]$Phase0Document.tauri_macros_source_patch.path) `
        -ExpectedTauriMacrosSourceAuthoritySha256 ([string]$Phase0Document.tauri_macros_source_patch.sha256)
    if ((ConvertTo-Json -InputObject $fixtureProvenance.Document.fixture_build_budget -Depth 5 -Compress) -cne
        (ConvertTo-Json -InputObject $Phase0Document.fixture_build_budget -Depth 5 -Compress)) {
        throw 'Phase0 matrix budget differs from fixture provenance capacity snapshot'
    }
    $fixtureManifestRaw = [IO.File]::ReadAllText([string]$Phase0Document.fixture.manifest.path, [Text.Encoding]::UTF8)
    if (Test-D32JsonDuplicateKeys -Json $fixtureManifestRaw) { throw 'Phase0 fixture manifest has duplicate or invalid JSON keys' }
    $fixtureManifestDocument = $fixtureManifestRaw | ConvertFrom-D32Json
    if (-not (Test-D32Phase0ExactProperties -Object $fixtureManifestDocument.build_policy -Expected @('timeout_seconds', 'cargo_build_jobs', 'nested_builds', 'process_tree_timeout_action')) -or
        -not (Test-D32Phase0Integer -Value $fixtureManifestDocument.build_policy.timeout_seconds) -or [Int64]$fixtureManifestDocument.build_policy.timeout_seconds -ne 28800 -or
        -not (Test-D32Phase0Integer -Value $fixtureManifestDocument.build_policy.cargo_build_jobs) -or [Int64]$fixtureManifestDocument.build_policy.cargo_build_jobs -ne 4) {
        throw 'Phase0 fixture manifest does not carry the exact owner-bound five-build jobs-4/28800-second policy'
    }
    if ((ConvertTo-Json -InputObject $fixtureProvenance.Document.vendored_protoc_run_grant -Depth 5 -Compress) -cne
        (ConvertTo-Json -InputObject $Phase0Document.vendored_protoc.run_grant -Depth 5 -Compress)) {
        throw 'Phase0 fixture provenance run-grant reference differs from matrix record'
    }
    if ((ConvertTo-Json -InputObject $fixtureProvenance.Reference -Depth 5 -Compress) -cne
        (ConvertTo-Json -InputObject $Phase0Document.fixture.build_provenance -Depth 5 -Compress)) {
        throw 'Phase0 fixture provenance sidecar reference changed from matrix record'
    }
    if (-not (Test-D32Phase0ExactProperties -Object $Phase0Document.tauri_macros_source_patch -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) {
        throw 'Phase0 tauri-macros source-patch authority reference is malformed'
    }
    $sourcePatchAuthority = Test-D32TauriMacrosSourcePatchAuthority `
        -AuthorityPath ([string]$Phase0Document.tauri_macros_source_patch.path) `
        -ExpectedAuthoritySha256 ([string]$Phase0Document.tauri_macros_source_patch.sha256) `
        -Repository $Repository -CandidateSha $CandidateSha -ValidatedProfile $ValidatedProfile -EvidenceRoot $OutputRoot
    if ((ConvertTo-Json -InputObject $sourcePatchAuthority.Reference -Depth 5 -Compress) -cne
        (ConvertTo-Json -InputObject $Phase0Document.tauri_macros_source_patch -Depth 5 -Compress) -or
        (ConvertTo-Json -InputObject $fixtureProvenance.Document.tauri_macros_source_patch -Depth 5 -Compress) -cne
        (ConvertTo-Json -InputObject $Phase0Document.tauri_macros_source_patch -Depth 5 -Compress)) {
        throw 'Phase0 source-patch authority differs from its external opened file or fixture provenance link'
    }
    if (-not (Test-D32Phase0ExactProperties -Object $Phase0Document.h7c_git_child_authority -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32Phase0ExactProperties -Object $Phase0Document.h7c_git_child_attestation -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) {
        throw 'Phase0 H7-C Git authority/companion references are malformed'
    }
    $h7Inputs = Get-D32H7CGitChildAttestationInputs -Reference $Phase0Document.h7c_git_child_attestation -EvidenceRoot $OutputRoot
    if ((ConvertTo-Json -InputObject $h7Inputs.AuthorityReference -Depth 6 -Compress) -cne
        (ConvertTo-Json -InputObject $Phase0Document.h7c_git_child_authority -Depth 6 -Compress)) {
        throw 'Phase0 H7-C Git authority is not the same independently pinned file referenced by its companion'
    }
    $gitImage = Get-D32ProfileFileSnapshot -Path $h7Inputs.GitImage.Path
    if ($gitImage.Bytes -ne $h7Inputs.GitImage.Bytes -or $gitImage.Sha256 -cne $h7Inputs.GitImage.Sha256 -or
        $gitImage.VolumeSerialHex -cne $h7Inputs.GitImage.VolumeSerialHex -or $gitImage.FileIdHex -cne $h7Inputs.GitImage.FileIdHex) {
        throw 'H7-C Git image current opened identity differs from the companion'
    }
    $h7Authority = Test-D32H7CGitAuthority -AuthorityPath ([string]$Phase0Document.h7c_git_child_authority.path) `
        -ExpectedAuthoritySha256 ([string]$Phase0Document.h7c_git_child_authority.sha256) -Repository $Repository `
        -CandidateSha $CandidateSha -ValidatedProfile $ValidatedProfile -EvidenceRoot $OutputRoot `
        -TempRoot ([string]$Phase0Document.cargo_home.temp_root) -GitImage $gitImage -TimeoutSeconds $h7Inputs.TimeoutSeconds
    if ((ConvertTo-Json -InputObject $h7Authority.Reference -Depth 6 -Compress) -cne
        (ConvertTo-Json -InputObject $Phase0Document.h7c_git_child_authority -Depth 6 -Compress)) {
        throw 'Phase0 external H7-C Git authority bytes/opened identity changed'
    }
    $h7RunGrant = Test-D32H7CGitRunGrant -Reference $h7Inputs.Document.run_grant -Authority $h7Authority `
        -Repository $Repository -CandidateSha $CandidateSha -ValidatedProfile $ValidatedProfile -EvidenceRoot $OutputRoot `
        -TempRoot ([string]$Phase0Document.cargo_home.temp_root) -RunId ([string]$Phase0Document.cargo_home.run_id) `
        -OwnerMarker $Phase0Document.owner_marker -GitImage $gitImage
    $rootIdentity = Test-D32ProfileDirectoryIdentity -Path $OutputRoot `
        -VolumeSerialHex ([string]$Phase0Document.evidence_root_identity.volume_serial_hex) -FileIdHex ([string]$Phase0Document.evidence_root_identity.file_id_hex)
    $ownerBinding = Test-D32Phase0OwnerBinding -EvidenceRoot $OutputRoot -ExpectedCandidateSha $CandidateSha `
        -ValidatedProfile $ValidatedProfile -ExpectedRunId ([string]$Phase0Document.cargo_home.run_id) `
        -ExpectedRootIdentity $rootIdentity -ExpectedMarkerReference $Phase0Document.owner_marker
    $vitaSuite = @($Phase0Document.commands | Where-Object { $_.name -ceq 'vita-full-local-suite' })
    if ($vitaSuite.Count -ne 1) { throw 'Phase0 H7-C companion requires exactly one fixed Vita full-local-suite command' }
    $null = Test-D32Phase0DebugProcessTrace -Trace $vitaSuite[0].process_trace `
        -ExpectedRootPath ([string]$ValidatedProfile.Profile.toolchain.cargo.path) `
        -ExpectedRootIdentity $ValidatedProfile.Profile.toolchain.cargo -ExpectedParentProcessId ([int]$Phase0Document.runner_process_id) `
        -ValidatedProfile $ValidatedProfile -Repository $Repository -VendoredProtocGrant $grant `
        -H7CGitAuthority $h7Authority -H7CGitRunGrant $h7RunGrant
    $h7Attestation = Test-D32H7CGitChildAttestation -Reference $Phase0Document.h7c_git_child_attestation `
        -Authority $h7Authority -RunGrant $h7RunGrant -OwnerBinding $ownerBinding -Phase0Command $vitaSuite[0] `
        -Repository $Repository -CandidateSha $CandidateSha -ValidatedProfile $ValidatedProfile -EvidenceRoot $OutputRoot `
        -TempRoot ([string]$Phase0Document.cargo_home.temp_root) -GitImage $gitImage
    if ((ConvertTo-Json -InputObject $h7Attestation.Reference -Depth 5 -Compress) -cne
        (ConvertTo-Json -InputObject $Phase0Document.h7c_git_child_attestation -Depth 5 -Compress)) {
        throw 'Phase0 H7-C Git companion bytes/opened identity changed'
    }
    return $grant
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
    $attestationFields = @('schema_version', 'attestation_type', 'runner_process_id', 'candidate_sha', 'source_clone', 'git_status', 'build_profile', 'started_at_utc', 'completed_at_utc', 'cargo_path', 'cargo_sha256', 'cargo_identity', 'toolchain_profile', 'phase0_matrix', 'test_inventory_authority', 'vendored_protoc', 'tauri_macros_source_patch', 'h7c_git_child_authority', 'h7c_git_child_attestation', 'cargo_home', 'fresh_outputs', 'commands', 'artifacts', 'powershell_module_admission')
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
    if (-not $attestationSchemaIsInteger -or -not (Test-D32NonNegativeInt64 -Value $attestationSchemaVersion -Parsed ([ref]$attestationSchemaValue)) -or $attestationSchemaValue -ne $script:D32AttestationSchemaVersion -or (Get-D32JsonProperty -Object $Attestation -Name 'attestation_type') -cne 'D32_RELEASE_BUILD_ATTESTATION_V9') {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.schema' -Message 'attestation schema version or type is not the fixed D32 release-build format'
    }
    $attestationRunnerPid = Get-D32JsonProperty -Object $Attestation -Name 'runner_process_id'
    $attestationRunnerPidValue = [Int64]0
    if (-not (Test-D32NonNegativeInt64 -Value $attestationRunnerPid -Parsed ([ref]$attestationRunnerPidValue)) -or $attestationRunnerPidValue -le 0) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.runner' -Message 'runner_process_id must be a positive JSON integer'
    }

    $candidate = Get-D32JsonProperty -Object $Bundle -Name 'candidate_sha'
    $attestedCandidate = Get-D32JsonProperty -Object $Attestation -Name 'candidate_sha'
    if (-not (Test-D32PowerShellModuleAdmissionRecord -Document $Attestation.powershell_module_admission -CandidateSha ([string]$candidate) -Repository $Repository -ExpectedContext $global:D32PowerShellModuleAuthorityState.Admission) -or
        -not (Test-D32PowerShellModuleAdmissionRunnerBinding -Document $Attestation.powershell_module_admission -ExpectedProcessId ([Int64]$Attestation.runner_process_id)) -or
        -not (Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $Attestation.powershell_module_admission -ProfileRecord $Attestation.toolchain_profile)) {
        Add-D32Finding -Findings $Findings -Severity ERROR -Check 'attestation.module-admission' -Message 'release attestation lacks the exact caller-pinned D32 PowerShell module admission'
    }
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
    $phase0VendoredGrant = $null
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
        $phase0ReadFindings = New-D32FindingList
        $phase0Read = Read-D32EvidenceJson -Path ([string]$phase0MatrixReference.path) -Findings $phase0ReadFindings -Check 'attestation.phase0.snapshot'
        if ($null -eq $phase0Read) { throw 'referenced Phase0 matrix could not be read from one stable opened-byte snapshot' }
        if ($phase0Read.Digest.Hash -cne $phase0Snapshot.Sha256 -or
            $phase0Read.Digest.Length -ne [Int64]$phase0Snapshot.Bytes -or
            $phase0Read.Digest.Identity.VolumeSerialHex -cne [string]$phase0Snapshot.VolumeSerialHex -or
            $phase0Read.Digest.Identity.FileIdHex -cne [string]$phase0Snapshot.FileIdHex) {
            throw 'referenced Phase0 opened bytes/identity changed between reference validation and schema parsing'
        }
        $phase0Document = $phase0Read.Value
        $phase0Fields = @('schema_version', 'record_type', 'runner_process_id', 'candidate_sha', 'source_repo', 'output_root', 'evidence_root_identity', 'owner_marker', 'vendored_protoc', 'tauri_macros_source_patch', 'h7c_git_child_authority', 'h7c_git_child_attestation', 'test_inventory_authority', 'powershell_module_admission', 'status', 'bundle_hashes', 'started_at_utc', 'completed_at_utc', 'final_candidate_sha', 'final_clean', 'powershell', 'toolchain_profile', 'cargo_home', 'fixture_build_budget', 'fetches', 'fixture', 'commands', 'test_inventory', 'local_suites', 'focused_tests', 'deferred_d31_tests', 'deferred_d29g2_provider_tests', 'not_run_capture_tests', 'governance_inputs', 'phase0_scope')
        if (-not (Test-D32Phase0ExactProperties -Object $phase0Document -Expected $phase0Fields) -or -not (Test-D32Phase0Integer -Value $phase0Document.schema_version) -or [Int64]$phase0Document.schema_version -ne 8 -or $phase0Document.record_type -cne 'D32_PHASE0_MATRIX_RECORD_V8' -or $phase0Document.candidate_sha -cne $candidate -or $phase0Document.final_candidate_sha -cne $candidate -or $phase0Document.status -cne 'PASS' -or $phase0Document.bundle_hashes -cne 'PENDING' -or $phase0Document.final_clean -isnot [bool] -or -not $phase0Document.final_clean) { throw 'referenced Phase0 matrix has unsupported schema, candidate, status, clean state, or bundle-hash status' }
        if (-not (Test-D32PowerShellModuleAdmissionRecord -Document $phase0Document.powershell_module_admission -CandidateSha $candidate -Repository $Repository -ExpectedContext $global:D32PowerShellModuleAuthorityState.Admission) -or
            -not (Test-D32PowerShellModuleAdmissionRunnerBinding -Document $phase0Document.powershell_module_admission -ExpectedProcessId ([Int64]$phase0Document.runner_process_id)) -or
            -not (Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $phase0Document.powershell_module_admission -ProfileRecord $phase0Document.toolchain_profile)) { throw 'referenced Phase0 matrix does not bind a current caller-pinned module admission to its producer process/Profile' }
        Assert-D32Phase0FixtureSummarySchema -Fixture $phase0Document.fixture
        Assert-D32Phase0FixtureBuildBudgetRecord -Document $phase0Document.fixture_build_budget -ExpectedPhase0TimeoutSeconds 14400
        $blockedDiagnosticPath = Join-Path $phase0OutputRoot 'D32-PHASE0-BLOCKED-DIAGNOSTIC.json'
        if (Test-D32Phase0DirectoryEntryExists -Path $blockedDiagnosticPath) { throw 'Phase0 blocked-diagnostic sidecar exists; failure evidence forbids release attestation/aggregate use' }
        if (-not (Test-D32ProfilePathEqual -Left $phase0Document.source_repo -Right $Repository) -or -not (Test-D32ProfilePathEqual -Left $phase0Document.output_root -Right $phase0OutputRoot)) { throw "referenced Phase0 source/output roots do not match current candidate and record path (source=$($phase0Document.source_repo); repository=$Repository; output=$($phase0Document.output_root); record_parent=$phase0OutputRoot)" }
        if (-not (Test-D32Phase0Integer -Value $phase0Document.schema_version) -or [Int64]$phase0Document.schema_version -ne 8 -or
            -not (Test-D32Phase0ExactProperties -Object $phase0Document.toolchain_profile -Expected @('path', 'sha256', 'file_identity', 'target_triple', 'toolchain', 'executable_inventory', 'script_inventory', 'windows_image_inventory', 'lock_inputs', 'env_policy')) -or
            -not (Test-D32Phase0ExactProperties -Object $phase0Document.toolchain_profile.file_identity -Expected @('bytes', 'volume_serial_hex', 'file_id_hex')) -or
            -not (Test-D32Phase0Integer -Value $phase0Document.toolchain_profile.file_identity.bytes -Positive) -or
            -not (Test-D32ProfilePathEqual -Left $phase0Document.toolchain_profile.path -Right $toolchainProfileReference.path) -or $phase0Document.toolchain_profile.sha256 -cne $toolchainProfileReference.sha256 -or
            $phase0Document.toolchain_profile.file_identity.bytes -ne $toolchainProfileReference.bytes -or $phase0Document.toolchain_profile.file_identity.volume_serial_hex -cne $toolchainProfileReference.volume_serial_hex -or $phase0Document.toolchain_profile.file_identity.file_id_hex -cne $toolchainProfileReference.file_id_hex) { throw 'Phase0 matrix does not bind the attested caller-pinned toolchain profile reference' }
        $releaseToolchainProfile = Test-D32BuildToolchainProfile -ProfilePath ([string]$toolchainProfileReference.path) -ExpectedSha256 ([string]$toolchainProfileReference.sha256) -Repository $Repository
        if (-not $releaseToolchainProfile.IsValid) { throw "caller-pinned v2 toolchain profile is not current: $($releaseToolchainProfile.Failure)" }
        if (-not (Test-D32Phase0ExactProperties -Object $phase0Document.evidence_root_identity -Expected @('path', 'volume_serial_hex', 'file_id_hex')) -or
            -not (Test-D32ProfilePathEqual -Left $phase0Document.evidence_root_identity.path -Right $phase0OutputRoot) -or
            $phase0Document.evidence_root_identity.volume_serial_hex -isnot [string] -or $phase0Document.evidence_root_identity.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
            $phase0Document.evidence_root_identity.file_id_hex -isnot [string] -or $phase0Document.evidence_root_identity.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { throw 'Phase0 EvidenceRoot opened-handle identity record is malformed' }
        $phase0RootIdentity = Test-D32ProfileDirectoryIdentity -Path $phase0OutputRoot -VolumeSerialHex ([string]$phase0Document.evidence_root_identity.volume_serial_hex) -FileIdHex ([string]$phase0Document.evidence_root_identity.file_id_hex)
        $null = Test-D32Phase0FileReference -Reference $phase0Document.owner_marker -AllowedRoot $phase0OutputRoot
        $phase0Owner = Test-D32Phase0OwnerBinding -EvidenceRoot $phase0OutputRoot -ExpectedCandidateSha $candidate -ValidatedProfile $releaseToolchainProfile -ExpectedRunId ([string]$phase0Document.cargo_home.run_id) -ExpectedRootIdentity $phase0RootIdentity -ExpectedMarkerReference $phase0Document.owner_marker
        if (-not (Test-D32Phase0ExactProperties -Object $phase0Document.cargo_home -Expected @('path', 'temp_root', 'run_root', 'run_id', 'nonempty_after_fetch', 'run_root_identity', 'cargo_home_identity', 'temp_root_identity')) -or
            $phase0Document.cargo_home.run_id -isnot [string] -or $phase0Document.cargo_home.run_id -cnotmatch '^[0-9a-f]{32}$' -or
            $phase0Document.cargo_home.run_id -cne $phase0Owner.RunId -or
            -not (Test-D32ProfilePathEqual -Left $phase0Document.cargo_home.run_root -Right (Join-Path $phase0OutputRoot 'r')) -or
            -not (Test-D32ProfilePathEqual -Left $phase0Document.cargo_home.path -Right (Join-Path $phase0OutputRoot 'r\c')) -or
            -not (Test-D32ProfilePathEqual -Left $phase0Document.cargo_home.temp_root -Right (Join-Path $phase0OutputRoot 'r\t'))) { throw 'Phase0 compact r\c and r\t paths/run_id do not match the fresh owner-bound evidence root' }
        foreach ($directoryField in @('run_root_identity', 'cargo_home_identity', 'temp_root_identity')) {
            $directoryIdentity = $phase0Document.cargo_home.$directoryField
            if (-not (Test-D32Phase0ExactProperties -Object $directoryIdentity -Expected @('volume_serial_hex', 'file_id_hex')) -or
                $directoryIdentity.volume_serial_hex -isnot [string] -or $directoryIdentity.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
                $directoryIdentity.file_id_hex -isnot [string] -or $directoryIdentity.file_id_hex -cnotmatch '^[0-9a-f]{32}$') { throw "Phase0 $directoryField is malformed" }
        }
        $null = Test-D32ProfileDirectoryIdentity -Path $phase0Document.cargo_home.run_root -VolumeSerialHex ([string]$phase0Document.cargo_home.run_root_identity.volume_serial_hex) -FileIdHex ([string]$phase0Document.cargo_home.run_root_identity.file_id_hex)
        $null = Test-D32ProfileDirectoryIdentity -Path $phase0Document.cargo_home.path -VolumeSerialHex ([string]$phase0Document.cargo_home.cargo_home_identity.volume_serial_hex) -FileIdHex ([string]$phase0Document.cargo_home.cargo_home_identity.file_id_hex)
        $null = Test-D32ProfileDirectoryIdentity -Path $phase0Document.cargo_home.temp_root -VolumeSerialHex ([string]$phase0Document.cargo_home.temp_root_identity.volume_serial_hex) -FileIdHex ([string]$phase0Document.cargo_home.temp_root_identity.file_id_hex)
        $expectedScripts = @($releaseToolchainProfile.ScriptInventory | ForEach-Object { [ordered]@{ path = $_.Path; sha256 = $_.Sha256; bytes = [Int64]$_.Bytes; volume_serial_hex = $_.VolumeSerialHex; file_id_hex = $_.FileIdHex } })
        $expectedWindowsImages = @($releaseToolchainProfile.WindowsImageInventory | ForEach-Object { [ordered]@{ path = $_.Path; sha256 = $_.Sha256; bytes = [Int64]$_.Bytes; volume_serial_hex = $_.VolumeSerialHex; file_id_hex = $_.FileIdHex } })
        if ((ConvertTo-Json -InputObject $phase0Document.toolchain_profile.script_inventory -Depth 12 -Compress) -cne (ConvertTo-Json -InputObject $expectedScripts -Depth 12 -Compress) -or
            (ConvertTo-Json -InputObject $phase0Document.toolchain_profile.windows_image_inventory -Depth 12 -Compress) -cne (ConvertTo-Json -InputObject $expectedWindowsImages -Depth 12 -Compress)) { throw 'Phase0 matrix dormant-script/Windows-child inventory differs from the independently revalidated profile' }
        if ($phase0Document.cargo_home.nonempty_after_fetch -isnot [bool] -or -not $phase0Document.cargo_home.nonempty_after_fetch -or
            -not (Test-D32Phase0ExactProperties -Object $cargoHomeEvidence -Expected @('path', 'temp_root', 'run_id')) -or $cargoHomeEvidence.path -isnot [string] -or $cargoHomeEvidence.temp_root -isnot [string] -or $cargoHomeEvidence.run_id -isnot [string] -or
            -not (Test-D32ProfileCanonicalPathString -Path $cargoHomeEvidence.path) -or -not (Test-D32ProfileCanonicalPathString -Path $cargoHomeEvidence.temp_root) -or
            -not (Test-D32ProfilePathWithin -Child $cargoHomeEvidence.path -Parent $phase0OutputRoot) -or -not (Test-D32ProfilePathWithin -Child $cargoHomeEvidence.temp_root -Parent $phase0OutputRoot) -or
            -not (Test-D32ProfilePathEqual -Left $phase0Document.cargo_home.path -Right $cargoHomeEvidence.path) -or -not (Test-D32ProfilePathEqual -Left $phase0Document.cargo_home.temp_root -Right $cargoHomeEvidence.temp_root) -or $phase0Document.cargo_home.run_id -cne $cargoHomeEvidence.run_id) { throw 'attested Cargo home/temp/run ID do not match the validated Phase0 matrix reference' }
        $cargoHomeCheck = Test-D32CargoHome -Path $cargoHomeEvidence.path -Repository $Repository
        if ($cargoHomeCheck.Empty -or -not (Test-D32ProfileNoReparsePath -Path $cargoHomeEvidence.temp_root)) { throw 'attested Phase0 Cargo home is empty or its temp root is missing/reparse-backed' }
        $phase0VendoredGrant = Test-D32PreflightPhase0VendoredProtocBinding `
            -Phase0Document $phase0Document -Repository $Repository -OutputRoot $phase0OutputRoot `
            -CandidateSha $candidate -ValidatedProfile $releaseToolchainProfile
        if (-not (Test-D32Phase0ExactProperties -Object $Attestation.vendored_protoc -Expected @('authority', 'run_grant')) -or
            (ConvertTo-Json -InputObject $Attestation.vendored_protoc -Depth 6 -Compress) -cne
            (ConvertTo-Json -InputObject $phase0Document.vendored_protoc -Depth 6 -Compress)) { throw 'release attestation does not bind the exact Phase0 authority and per-run protoc grant' }
        foreach ($referenceField in @('tauri_macros_source_patch', 'h7c_git_child_authority', 'h7c_git_child_attestation')) {
            if (-not (Test-D32Phase0ExactProperties -Object $Attestation.$referenceField -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
                (ConvertTo-Json -InputObject $Attestation.$referenceField -Depth 6 -Compress) -cne
                (ConvertTo-Json -InputObject $phase0Document.$referenceField -Depth 6 -Compress)) {
                throw "release attestation does not bind the exact Phase0 $referenceField reference"
            }
        }
        $null = Assert-D32PreflightTestInventoryBinding -Phase0Document $phase0Document -ExpectedAttestedAuthority $Attestation.test_inventory_authority `
            -Repository $Repository -Phase0OutputRoot $phase0OutputRoot -ValidatedProfile $releaseToolchainProfile
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
                $null = Test-D32Phase0DebugProcessTrace -Trace (Get-D32JsonProperty -Object $commandRecord -Name 'process_trace') -ExpectedRootPath $cargoPath -ExpectedRootIdentity $releaseToolchainProfile.Profile.toolchain.cargo -ExpectedParentProcessId ([int]$attestationRunnerPidValue) -ValidatedProfile $releaseToolchainProfile -Repository $Repository -VendoredProtocGrant $phase0VendoredGrant
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
                        $phase0ToolInventory = @($phase0Document.toolchain_profile.executable_inventory + $phase0Document.toolchain_profile.windows_image_inventory | ForEach-Object { [PSCustomObject]@{ Path = $_.path; Sha256 = $_.sha256; Bytes = $_.bytes; VolumeSerialHex = $_.volume_serial_hex; FileIdHex = $_.file_id_hex } }) + @([PSCustomObject]@{ Path = $phase0VendoredGrant.Image.Path; Sha256 = $phase0VendoredGrant.Image.Sha256; Bytes = $phase0VendoredGrant.Image.Bytes; VolumeSerialHex = $phase0VendoredGrant.Image.VolumeSerialHex; FileIdHex = $phase0VendoredGrant.Image.FileIdHex })
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

function Assert-D32PreflightPhase0InventoryListEvidence {
    param(
        [Parameter(Mandatory = $true)][object]$Phase0Document,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$BaselineEntries,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile
    )
    $expectedCommands = @(Get-D32TestInventoryExpectedCommands -Profile $ValidatedProfile.Profile)
    if ($expectedCommands.Count -ne 6 -or $Phase0Document.commands -isnot [Array]) { throw 'Phase0 inventory evidence must contain the exact six fixed listing commands' }
    $byName = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($command in $Phase0Document.commands) {
        if ($command.name -isnot [string] -or -not $byName.TryAdd([string]$command.name, $command)) { throw 'Phase0 command evidence contains an invalid or duplicate name' }
    }
    foreach ($package in @('protocol', 'vita', 'host')) {
        $packageEntries = @($BaselineEntries | Where-Object { $_.package -ceq $package })
        $allRows = @($packageEntries | ForEach-Object { [PSCustomObject][ordered]@{ package = [string]$_.package; kind = [string]$_.kind; full_name = [string]$_.full_name } })
        $ignoredRows = @($packageEntries | Where-Object { $_.category -ceq 'ignored' } | ForEach-Object { [PSCustomObject][ordered]@{ package = [string]$_.package; kind = [string]$_.kind; full_name = [string]$_.full_name } })
        $declared = $Phase0Document.test_inventory.$package
        if (-not (Test-D32Phase0ExactProperties -Object $declared -Expected @('all_rows', 'ignored_rows', 'entries', 'all_list_digest', 'ignored_list_digest', 'test_names', 'ignored_names', 'test_count', 'ignored_count', 'benchmark_count')) -or
            -not (Test-D32TestInventoryRowsEqual -Left $declared.entries -Right $packageEntries -IncludeCategory) -or
            -not (Test-D32TestInventoryRowsEqual -Left $declared.all_rows -Right $allRows) -or
            -not (Test-D32TestInventoryRowsEqual -Left $declared.ignored_rows -Right $ignoredRows) -or
            $declared.all_list_digest -cne (Get-D32TestInventoryDigest -Rows $allRows) -or
            $declared.ignored_list_digest -cne (Get-D32TestInventoryDigest -Rows $ignoredRows) -or
            ($declared.test_names -join "`0") -cne (@($allRows | Where-Object { $_.kind -ceq 'test' } | ForEach-Object { [string]$_.full_name }) -join "`0") -or
            ($declared.ignored_names -join "`0") -cne (@($ignoredRows | Where-Object { $_.kind -ceq 'test' } | ForEach-Object { [string]$_.full_name }) -join "`0") -or
            -not (Test-D32Phase0Integer -Value $declared.test_count) -or $declared.test_count -ne @($allRows | Where-Object { $_.kind -ceq 'test' }).Count -or
            -not (Test-D32Phase0Integer -Value $declared.ignored_count) -or $declared.ignored_count -ne @($ignoredRows | Where-Object { $_.kind -ceq 'test' }).Count -or
            -not (Test-D32Phase0Integer -Value $declared.benchmark_count) -or $declared.benchmark_count -ne @($allRows | Where-Object { $_.kind -ceq 'benchmark' }).Count) {
            throw "Phase0 $package structured inventory differs from the independently pinned baseline"
        }
    }
    for ($index = 0; $index -lt 6; $index++) {
        $expected = $expectedCommands[$index]
        if (-not $byName.ContainsKey([string]$expected.name)) { throw "Phase0 formal listing command is missing: $($expected.name)" }
        $actual = $byName[[string]$expected.name]
        if (-not (Test-D32Phase0Integer -Value $actual.timeout_seconds) -or [Int64]$actual.timeout_seconds -ne 28800 -or
            -not (Test-D32ProfilePathEqual -Left $actual.executable -Right $ValidatedProfile.Profile.toolchain.cargo.path) -or
            $actual.executable_sha256 -cne $ValidatedProfile.Profile.toolchain.cargo.sha256 -or
            ($actual.arguments -join "`0") -cne ($expected.arguments -join "`0") -or
            ($actual.argv -join "`0") -cne ((@($expected.executable) + @($expected.arguments)) -join "`0") -or
            -not (Test-D32ProfilePathEqual -Left $actual.working_directory -Right $Repository) -or
            $actual.candidate_sha_before -cne $Phase0Document.candidate_sha -or $actual.candidate_sha_after -cne $Phase0Document.candidate_sha -or
            $actual.clean_before -isnot [bool] -or -not $actual.clean_before -or $actual.clean_after -isnot [bool] -or -not $actual.clean_after -or
            -not (Test-D32Phase0Integer -Value $actual.exit_code) -or [Int64]$actual.exit_code -ne 0) {
            throw "Phase0 formal listing command differs from the fixed candidate/Profile/jobs-4/28800 plan: $($expected.name)"
        }
        $null = Test-D32Phase0FileReference -Reference $actual.stdout -AllowedRoot $EvidenceRoot
        $null = Test-D32Phase0FileReference -Reference $actual.stderr -AllowedRoot $EvidenceRoot
        $listingKind = [string]$expected.listing_kind
        $rawListLines = Read-D32TestInventoryLogReference -Reference $actual.stdout -AllowedRoot $EvidenceRoot
        $parsed = Get-D32TestInventoryListOutput -Lines $rawListLines -Package ([string]$expected.package) -ListingKind $listingKind
        [object[]]$expectedRows = @(
            if ($listingKind -ceq 'all') {
                $BaselineEntries | Where-Object { $_.package -ceq $expected.package } | ForEach-Object { [PSCustomObject][ordered]@{ package = [string]$_.package; kind = [string]$_.kind; full_name = [string]$_.full_name } }
            }
            else {
                $BaselineEntries | Where-Object { $_.package -ceq $expected.package -and $_.category -ceq 'ignored' } | ForEach-Object { [PSCustomObject][ordered]@{ package = [string]$_.package; kind = [string]$_.kind; full_name = [string]$_.full_name } }
            }
        )
        if (-not (Test-D32TestInventoryRowsEqual -Left $parsed.rows -Right $expectedRows) -or
            $parsed.row_count -ne $expectedRows.Count -or
            $parsed.test_count -ne @($expectedRows | Where-Object { $_.kind -ceq 'test' }).Count -or
            $parsed.benchmark_count -ne @($expectedRows | Where-Object { $_.kind -ceq 'benchmark' }).Count) {
            $expectedNames = @($expectedRows | ForEach-Object { [string]$_.kind + ':' + [string]$_.full_name }) -join '|'
            $observedNames = @($parsed.rows | ForEach-Object { [string]$_.kind + ':' + [string]$_.full_name }) -join '|'
            throw "Phase0 formal raw listing output differs from the Coordinator-pinned baseline: $($expected.name); expected_count=$($expectedRows.Count); observed_count=$($parsed.row_count); expected_digest=$(Get-D32TestInventoryDigest -Rows $expectedRows); observed_digest=$(Get-D32TestInventoryDigest -Rows $parsed.rows); expected_rows=$expectedNames; observed_rows=$observedNames"
        }
    }
    return $true
}

function Assert-D32PreflightPhase0SuiteInventoryEvidence {
    param(
        [Parameter(Mandatory = $true)][object]$Phase0Document,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$BaselineEntries,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile
    )

    if ($Phase0Document.commands -isnot [Array] -or $Phase0Document.local_suites -isnot [Array] -or
        $Phase0Document.local_suites.Count -ne 3 -or $Phase0Document.focused_tests -isnot [Array]) {
        throw 'Phase0 suite evidence is missing its fixed commands, three package summaries, or focused-test results'
    }
    $commands = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($command in $Phase0Document.commands) {
        if ($command.name -isnot [string] -or -not $commands.TryAdd([string]$command.name, $command)) {
            throw 'Phase0 suite command evidence contains an invalid or duplicate command name'
        }
    }
    $suiteRecords = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $packageOrder = @('protocol', 'vita', 'host')
    for ($index = 0; $index -lt $packageOrder.Count; $index++) {
        $package = $packageOrder[$index]
        $suite = $Phase0Document.local_suites[$index]
        if (-not (Test-D32Phase0ExactProperties -Object $suite -Expected @('package', 'command', 'status', 'summary_count', 'counts', 'exact_deferred_skip_count')) -or
            $suite.package -isnot [string] -or $suite.package -cne $package -or
            $suite.command -isnot [string] -or $suite.command -cne "$package-full-local-suite" -or
            $suite.status -isnot [string] -or $suite.status -cne 'PASS' -or
            -not (Test-D32Phase0Integer -Value $suite.summary_count -Positive) -or
            -not (Test-D32Phase0Integer -Value $suite.exact_deferred_skip_count)) {
            throw "Phase0 full-suite result record is malformed, reordered, or not PASS for $package"
        }
        $suiteRecords.Add($package, $suite)
    }

    foreach ($package in $packageOrder) {
        $commandName = "$package-full-local-suite"
        if (-not $commands.ContainsKey($commandName)) { throw "Phase0 full-suite Cargo command is absent: $commandName" }
        $command = $commands[$commandName]
        $expectedArguments = @(Get-D32Phase0TestCommand -Package $package -Kind suite)
        if (-not (Test-D32Phase0Integer -Value $command.timeout_seconds) -or [Int64]$command.timeout_seconds -ne 14400 -or
            -not (Test-D32ProfilePathEqual -Left $command.executable -Right $ValidatedProfile.Profile.toolchain.cargo.path) -or
            $command.executable_sha256 -cne $ValidatedProfile.Profile.toolchain.cargo.sha256 -or
            ($command.arguments -join "`0") -cne ($expectedArguments -join "`0") -or
            ($command.argv -join "`0") -cne ((@($ValidatedProfile.Profile.toolchain.cargo.path) + $expectedArguments) -join "`0") -or
            -not (Test-D32ProfilePathEqual -Left $command.working_directory -Right $Repository) -or
            $command.candidate_sha_before -cne $Phase0Document.candidate_sha -or $command.candidate_sha_after -cne $Phase0Document.candidate_sha -or
            $command.clean_before -isnot [bool] -or -not $command.clean_before -or $command.clean_after -isnot [bool] -or -not $command.clean_after -or
            -not (Test-D32Phase0Integer -Value $command.exit_code) -or [Int64]$command.exit_code -ne 0) {
            throw "Phase0 full-suite command differs from fixed candidate/Profile/14400 policy: $commandName"
        }
        $null = Test-D32Phase0FileReference -Reference $command.stdout -AllowedRoot $EvidenceRoot
        $null = Test-D32Phase0FileReference -Reference $command.stderr -AllowedRoot $EvidenceRoot
        $suiteLines = Read-D32TestInventoryLogReference -Reference $command.stdout -AllowedRoot $EvidenceRoot
        $expectedIgnored = [Int64]@($BaselineEntries | Where-Object { $_.package -ceq $package -and $_.kind -ceq 'test' -and $_.category -ceq 'ignored' }).Count
        $expectedDeferred = [Int64]@($BaselineEntries | Where-Object { $_.package -ceq $package -and $_.kind -ceq 'test' -and $_.category -ceq 'deferred' }).Count
        $result = Assert-D32TestInventorySuiteRows -Package $package -BaselineEntries $BaselineEntries -Lines $suiteLines `
            -ExpectedIgnored $expectedIgnored -ExpectedDeferred $expectedDeferred
        $record = $suiteRecords[$package]
        $expectedCounts = [ordered]@{
            passed = [Int64]$result.Counts.passed
            failed = [Int64]$result.Counts.failed
            ignored = [Int64]$result.Counts.ignored
            measured = [Int64]$result.Counts.measured
            filtered_out = [Int64]$result.Counts.filtered_out
        }
        if (-not (Test-D32Phase0ExactProperties -Object $record.counts -Expected @('passed', 'failed', 'ignored', 'measured', 'filtered_out')) -or
            (ConvertTo-Json -InputObject $record.counts -Depth 4 -Compress) -cne (ConvertTo-Json -InputObject $expectedCounts -Depth 4 -Compress) -or
            [Int64]$record.summary_count -ne $result.Summaries.Count -or [Int64]$record.exact_deferred_skip_count -ne $expectedDeferred) {
            throw "Phase0 full-suite structured summary differs from captured baseline-reconciled output: $package"
        }
    }

    $expectedFocused = @($BaselineEntries | Where-Object { $_.kind -ceq 'test' -and $_.category -ceq 'focused' } |
        ForEach-Object { [ordered]@{ package = [string]$_.package; full_name = [string]$_.full_name } })
    $actualFocused = [System.Collections.Generic.List[object]]::new()
    $seenFocused = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($focused in $Phase0Document.focused_tests) {
        if (-not (Test-D32Phase0ExactProperties -Object $focused -Expected @('package', 'full_name', 'command', 'status', 'passed', 'failed')) -or
            $focused.package -isnot [string] -or $focused.package -notin @('vita', 'host') -or
            $focused.full_name -isnot [string] -or $focused.command -isnot [string] -or
            $focused.status -isnot [string] -or $focused.status -cne 'PASS' -or
            -not (Test-D32Phase0Integer -Value $focused.passed) -or [Int64]$focused.passed -ne 1 -or
            -not (Test-D32Phase0Integer -Value $focused.failed) -or [Int64]$focused.failed -ne 0) {
            throw 'Phase0 focused-test record is malformed or not an exact single-test PASS'
        }
        $key = [string]$focused.package + "`0" + [string]$focused.full_name
        if (-not $seenFocused.Add($key)) { throw 'Phase0 focused-test records contain a duplicate package/full-name pair' }
        $actualFocused.Add([ordered]@{ package = [string]$focused.package; full_name = [string]$focused.full_name })
        if (-not $commands.ContainsKey([string]$focused.command)) { throw "Phase0 focused Cargo command is absent: $($focused.command)" }
        $command = $commands[[string]$focused.command]
        $expectedName = "$($focused.package)-focused-$(([string]$focused.full_name).Split('::')[-1])"
        $expectedArguments = @(Get-D32Phase0TestCommand -Package ([string]$focused.package) -Kind focused -ExactName ([string]$focused.full_name))
        if ($focused.command -cne $expectedName -or
            -not (Test-D32Phase0Integer -Value $command.timeout_seconds) -or [Int64]$command.timeout_seconds -ne 14400 -or
            -not (Test-D32ProfilePathEqual -Left $command.executable -Right $ValidatedProfile.Profile.toolchain.cargo.path) -or
            $command.executable_sha256 -cne $ValidatedProfile.Profile.toolchain.cargo.sha256 -or
            ($command.arguments -join "`0") -cne ($expectedArguments -join "`0") -or
            ($command.argv -join "`0") -cne ((@($ValidatedProfile.Profile.toolchain.cargo.path) + $expectedArguments) -join "`0") -or
            -not (Test-D32ProfilePathEqual -Left $command.working_directory -Right $Repository) -or
            $command.candidate_sha_before -cne $Phase0Document.candidate_sha -or $command.candidate_sha_after -cne $Phase0Document.candidate_sha -or
            $command.clean_before -isnot [bool] -or -not $command.clean_before -or $command.clean_after -isnot [bool] -or -not $command.clean_after -or
            -not (Test-D32Phase0Integer -Value $command.exit_code) -or [Int64]$command.exit_code -ne 0) {
            throw "Phase0 focused command differs from fixed candidate/Profile/exact-name/14400 policy: $expectedName"
        }
        $null = Test-D32Phase0FileReference -Reference $command.stdout -AllowedRoot $EvidenceRoot
        $null = Test-D32Phase0FileReference -Reference $command.stderr -AllowedRoot $EvidenceRoot
        $focusedParsed = Get-D32Phase0SuiteTestResultRows -Lines (Read-D32TestInventoryLogReference -Reference $command.stdout -AllowedRoot $EvidenceRoot)
        if ($focusedParsed.rows.Count -ne 1 -or $focusedParsed.rows[0].full_name -cne $focused.full_name -or $focusedParsed.rows[0].status -cne 'ok' -or
            $focusedParsed.summaries.Count -ne 1 -or $focusedParsed.summaries[0].status -cne 'ok' -or
            $focusedParsed.summaries[0].passed -ne 1 -or $focusedParsed.summaries[0].failed -ne 0 -or
            $focusedParsed.summaries[0].ignored -ne 0 -or $focusedParsed.summaries[0].measured -ne 0 -or $focusedParsed.summaries[0].filtered_out -ne 0) {
            throw "Phase0 focused raw test result differs from the exact baseline name: $($focused.full_name)"
        }
    }
    $actualFocusedKeys = [System.Collections.Generic.List[string]]::new()
    foreach ($focusedRow in $actualFocused) {
        if (-not (Test-D32Phase0ExactProperties -Object $focusedRow -Expected @('package', 'full_name')) -or
            $focusedRow.package -isnot [string] -or $focusedRow.full_name -isnot [string]) {
            throw 'Phase0 actual focused-test tuple schema is invalid'
        }
        $actualFocusedKeys.Add([string]$focusedRow.package + "`t" + [string]$focusedRow.full_name)
    }
    $expectedFocusedKeys = [System.Collections.Generic.List[string]]::new()
    foreach ($focusedRow in $expectedFocused) {
        if (-not (Test-D32Phase0ExactProperties -Object $focusedRow -Expected @('package', 'full_name')) -or
            $focusedRow.package -isnot [string] -or $focusedRow.full_name -isnot [string]) {
            throw 'Phase0 baseline focused-test tuple schema is invalid'
        }
        $expectedFocusedKeys.Add([string]$focusedRow.package + "`t" + [string]$focusedRow.full_name)
    }
    $actualFocusedArray = [string[]]$actualFocusedKeys.ToArray()
    $expectedFocusedArray = [string[]]$expectedFocusedKeys.ToArray()
    [Array]::Sort($actualFocusedArray, [StringComparer]::Ordinal)
    [Array]::Sort($expectedFocusedArray, [StringComparer]::Ordinal)
    if (($actualFocusedArray -join "`0") -cne ($expectedFocusedArray -join "`0")) {
        throw 'Phase0 focused test records differ from the exact Coordinator-pinned focused-name set'
    }
    return $true
}

function Assert-D32PreflightTestInventoryBinding {
    param(
        [Parameter(Mandatory = $true)][object]$Phase0Document,
        [Parameter(Mandatory = $true)][object]$ExpectedAttestedAuthority,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Phase0OutputRoot,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile
    )
    $authority = $Phase0Document.test_inventory_authority
    if (-not (Test-D32Phase0ExactProperties -Object $authority -Expected @('baseline', 'discovery')) -or
        (ConvertTo-Json -InputObject $authority -Depth 8 -Compress) -cne
            (ConvertTo-Json -InputObject $ExpectedAttestedAuthority -Depth 8 -Compress)) {
        throw 'test-inventory authority refs must be exactly bound to both Phase0 and release attestation'
    }
    foreach ($name in @('baseline', 'discovery')) {
        if (-not (Test-D32Phase0ExactProperties -Object $authority.$name -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) {
            throw "Phase0 test-inventory $name reference has missing/extra properties"
        }
    }
    if ([IO.Path]::GetFileName([string]$authority.baseline.path) -cne 'D32-TEST-INVENTORY-BASELINE.json' -or
        [IO.Path]::GetFileName([string]$authority.discovery.path) -cne 'D32-TEST-INVENTORY-DISCOVERY.json') {
        throw 'Phase0 inventory refs do not name the fixed create-new baseline/discovery records'
    }
    $baselineRead = Read-D32TestInventoryJsonReference -Reference $authority.baseline -ExpectedPath ([string]$authority.baseline.path) `
        -ExpectedSha256 ([string]$authority.baseline.sha256) -Repository $Repository
    $gitContext = $script:D32GitCaptureContext
    if ($null -eq $gitContext -or [String]::IsNullOrWhiteSpace([string]$gitContext.GitPath) -or [string]$gitContext.GitSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'test-inventory release/aggregate validation requires the current caller-pinned direct Git identity'
    }
    $discoveryValidated = Test-D32Phase0TestInventoryDiscoveryRecord -Reference $authority.discovery -ExpectedSha256 ([string]$authority.discovery.sha256) `
        -Repository $Repository -CandidateSha ([string]$Phase0Document.candidate_sha) -Profile $ValidatedProfile `
        -GitPath ([string]$gitContext.GitPath) -GitSha256 ([string]$gitContext.GitSha256)
    $discovery = $discoveryValidated.Document
    $discoveryRead = [PSCustomObject]@{ Document = $discovery; Reference = $discoveryValidated.Reference; Snapshot = $discoveryValidated.Snapshot }
    $discoveryFields = @('schema_version', 'record_type', 'status', 'gate_authority', 'runner_process_id', 'candidate_sha', 'source_repo', 'evidence_root_identity', 'owner_marker', 'run_id', 'toolchain_profile', 'lock_inputs', 'source_patch_authority', 'protoc', 'storage', 'fetches', 'inventory_commands', 'test_inventory', 'powershell_module_admission', 'started_at_utc', 'completed_at_utc', 'final_candidate_sha', 'final_clean')
    if (-not (Test-D32Phase0ExactProperties -Object $discovery -Expected $discoveryFields) -or
        -not (Test-D32Phase0Integer -Value $discovery.schema_version) -or [Int64]$discovery.schema_version -ne 2 -or
        $discovery.record_type -cne 'D32_TEST_INVENTORY_DISCOVERY_V2' -or $discovery.status -cne 'COMPLETE_FOR_COORDINATOR_REVIEW' -or
        $discovery.gate_authority -cne 'NONE' -or $discovery.candidate_sha -cne $Phase0Document.candidate_sha -or
        $discovery.final_candidate_sha -cne $Phase0Document.candidate_sha -or $discovery.final_clean -isnot [bool] -or -not $discovery.final_clean -or
        -not (Test-D32ProfilePathEqual -Left $discovery.source_repo -Right $Repository) -or
        -not (Test-D32Phase0Integer -Value $discovery.runner_process_id -Positive) -or
        $discovery.run_id -isnot [string] -or $discovery.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        $discovery.inventory_commands -isnot [Array] -or $discovery.inventory_commands.Count -ne 6 -or
        $discovery.fetches -isnot [Array] -or $discovery.fetches.Count -ne 3) {
        throw 'D32_TEST_INVENTORY_DISCOVERY_V2 is incomplete, non-current, or not candidate-bound'
    }
    if (-not (Test-D32PowerShellModuleAdmissionRecord -Document $discovery.powershell_module_admission -CandidateSha ([string]$Phase0Document.candidate_sha) -Repository $Repository -ExpectedContext $global:D32PowerShellModuleAuthorityState.Admission) -or
        -not (Test-D32PowerShellModuleAdmissionRunnerBinding -Document $discovery.powershell_module_admission -ExpectedProcessId ([Int64]$discovery.runner_process_id)) -or
        -not (Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $discovery.powershell_module_admission -ProfileRecord $discovery.toolchain_profile)) {
        throw 'D32_TEST_INVENTORY_DISCOVERY_V2 is not bound to the current caller-pinned PowerShell module closure'
    }
    $expectedProfileRecord = Get-D32TestInventoryProfileRecord -ValidatedProfile $ValidatedProfile
    if ((ConvertTo-Json -InputObject $discovery.toolchain_profile -Depth 20 -Compress) -cne
        (ConvertTo-Json -InputObject $expectedProfileRecord -Depth 20 -Compress)) {
        throw 'test-inventory discovery is not bound to the current complete Profile V2/image/lock inventory'
    }
    $discoveryRoot = [IO.Path]::GetDirectoryName([string]$authority.discovery.path)
    if (-not (Test-D32ProfileNoReparsePath -Path $discoveryRoot) -or
        (Test-D32ProfilePathWithin -Child $discoveryRoot -Parent $Repository) -or
        -not (Test-D32ProfilePathEqual -Left $discovery.evidence_root_identity.path -Right $discoveryRoot)) {
        throw 'test-inventory discovery must retain its own external non-reparse owner-bound root'
    }
    $null = Assert-D32TestInventoryRootsDisjoint -DiscoveryRoot $discoveryRoot -Phase0OutputRoot $Phase0OutputRoot
    if ((ConvertTo-Json -InputObject $discovery.source_patch_authority -Depth 6 -Compress) -cne
        (ConvertTo-Json -InputObject $Phase0Document.tauri_macros_source_patch -Depth 6 -Compress)) {
        throw 'test-inventory discovery source-patch reference differs from the independently validated Phase0 source-patch authority'
    }
    $null = Test-D32ProfileDirectoryIdentity -Path $discoveryRoot -VolumeSerialHex ([string]$discovery.evidence_root_identity.volume_serial_hex) -FileIdHex ([string]$discovery.evidence_root_identity.file_id_hex)
    $null = Test-D32Phase0FileReference -Reference $discovery.owner_marker -AllowedRoot $discoveryRoot
    $baseline = $baselineRead.Document
    $expectedCommands = @(Get-D32TestInventoryExpectedCommands -Profile $ValidatedProfile.Profile)
    $lockInputs = @(Get-D32BuildToolchainLockInputs -Repository $Repository)
    $null = Test-D32TestInventoryBaselineDocument -Document $baseline -Discovery $discovery -DiscoveryReference $discoveryRead.Reference `
        -ExpectedCandidateSha ([string]$Phase0Document.candidate_sha) -Repository $Repository -Profile $ValidatedProfile -LockInputs $lockInputs `
        -SourcePatchAuthorityReference $Phase0Document.tauri_macros_source_patch -ProtocAuthorityReference $discovery.protoc.authority `
        -ExpectedCommands $expectedCommands
    if ((ConvertTo-Json -InputObject $baseline.discovery.reference -Depth 8 -Compress) -cne
        (ConvertTo-Json -InputObject $authority.discovery -Depth 8 -Compress)) {
        throw 'pinned inventory baseline names a different discovery opened file identity'
    }
    $baselineEntries = @($baseline.entries)
    if (-not (Test-D32TestInventoryRowsEqual -Left $baselineEntries -Right @($discovery.test_inventory.entries) -IncludeCategory)) {
        throw 'pinned baseline complete test set differs from its candidate-bound discovery record'
    }
    $null = Assert-D32PreflightPhase0InventoryListEvidence -Phase0Document $Phase0Document -BaselineEntries $baselineEntries `
        -Repository $Repository -EvidenceRoot $Phase0OutputRoot -ValidatedProfile $ValidatedProfile
    $null = Assert-D32PreflightPhase0SuiteInventoryEvidence -Phase0Document $Phase0Document -BaselineEntries $baselineEntries `
        -Repository $Repository -EvidenceRoot $Phase0OutputRoot -ValidatedProfile $ValidatedProfile
    return [PSCustomObject]@{ Baseline = $baseline; BaselineReference = $authority.baseline; Discovery = $discovery; DiscoveryReference = $authority.discovery }
}

function New-D32PreflightSelfTestPhase0Command {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$LogRoot,
        [Parameter(Mandatory = $true)][string]$LogStem,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$StdoutLines,
        [ValidateSet('cargo', 'rustc')][string]$Tool = 'cargo',
        [int]$RootProcessId = 0,
        [AllowEmptyString()][string]$StartedAtUtc = ''
    )
    $toolIdentity = $ValidatedProfile.Profile.toolchain.$Tool
    $executable = [string]$toolIdentity.path
    if ($RootProcessId -le 0) { $RootProcessId = [int](40000 + [Math]::Abs($LogStem.GetHashCode() % 100000)) }
    $trace = New-D32Phase0SelfTestDebugTrace -Profile $ValidatedProfile -RunnerProcessId ([int]$PID) -RootProcessId $RootProcessId
    if ($Tool -cne 'cargo') {
        $trace.processes[0].image_path = [string]$toolIdentity.path
        $trace.processes[0].bytes = [Int64]$toolIdentity.bytes
        $trace.processes[0].sha256 = [string]$toolIdentity.sha256
        $trace.processes[0].volume_serial_hex = [string]$toolIdentity.volume_serial_hex
        $trace.processes[0].file_id_hex = [string]$toolIdentity.file_id_hex
    }
    $commandLine = ConvertTo-D32Phase0CommandLine -Arguments (@($executable) + @($Arguments))
    $stdoutPath = Join-Path $LogRoot ($LogStem + '.stdout.log')
    $stderrPath = Join-Path $LogRoot ($LogStem + '.stderr.log')
    foreach ($entry in @(
            [PSCustomObject]@{ Path = $stdoutPath; Bytes = [Text.UTF8Encoding]::new($false).GetBytes((@($StdoutLines) -join [Environment]::NewLine) + $(if (@($StdoutLines).Count -gt 0) { [Environment]::NewLine } else { '' })) },
            [PSCustomObject]@{ Path = $stderrPath; Bytes = [byte[]]@() }
        )) {
        $stream = [IO.File]::Open($entry.Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        try { if ($entry.Bytes.Length -gt 0) { $stream.Write($entry.Bytes, 0, $entry.Bytes.Length) }; $stream.Flush($true) }
        finally { $stream.Dispose() }
    }
    $rootTrace = $trace.processes[0]
    $process = [PSCustomObject]@{
        ProcessId = [int]$rootTrace.process_id
        ParentProcessId = [int]$rootTrace.parent_process_id
        Name = [IO.Path]::GetFileName($executable)
        ImagePath = $executable
        CommandLine = $commandLine
        CreationFileTime = [Int64]$rootTrace.creation_filetime
        CreatedAtUtc = [string]$rootTrace.created_at_utc
    }
    $rootProcess = ConvertFrom-D32Phase0DebugProcess -Process $process -CommandLine $commandLine
    $rootRecord = ConvertTo-D32Phase0ProcessRecord -Process $rootProcess -ValidatedProfile $ValidatedProfile -Repository $Repository `
        -ExpectedRootPath $executable -VendoredProtocGrant $null -H7CGitRunGrant $null
    $started = if ([String]::IsNullOrWhiteSpace($StartedAtUtc)) { [string]$trace.started_at_utc } else { $StartedAtUtc }
    $completed = [DateTimeOffset]::Parse($started, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).AddSeconds(1).ToString('o')
    return [ordered]@{
        name = $Name
        timeout_seconds = [Int64]$TimeoutSeconds
        executable = $executable
        executable_sha256 = [string]$toolIdentity.sha256
        executable_bytes = [Int64]$toolIdentity.bytes
        executable_volume_serial_hex = [string]$toolIdentity.volume_serial_hex
        executable_file_id_hex = [string]$toolIdentity.file_id_hex
        argv = @($executable) + @($Arguments)
        arguments = @($Arguments)
        command_line = $commandLine
        working_directory = [IO.Path]::GetFullPath($Repository)
        candidate_sha_before = $CandidateSha
        clean_before = $true
        started_at_utc = $started
        completed_at_utc = $completed
        exit_code = 0
        root_process = $rootRecord
        descendant_processes = @()
        process_trace = $trace
        process_tree_cleanup = [ordered]@{
            launch_mode = 'DedicatedOSDebuggerThread(CreateProcessW(DEBUG_PROCESS|CREATE_SUSPENDED)+DebugSetProcessKillOnExit(TRUE)+ResumeThread+WaitForDebugEvent+ContinueDebugEvent)+EXTENDED_STARTUP_INFO+HANDLE_LIST(stdout/stderr)+AssignProcessToJobObject(KILL_ON_JOB_CLOSE)'
            job_close_succeeded = $true
            process_wait_signaled = $true
            active_process_count_verified = $true
            active_process_count = [uint32]0
            debugger_thread_id = [uint32]$trace.debugger_thread_id
            debugger_thread_exited = $true
            debugger_thread_joined = $true
            debugger_kill_on_exit_enabled = $true
            retained_process_handle_count = [int]$trace.retained_process_handle_count
            retained_process_handles_signaled = $true
            debugger_association_query_verified = $true
            debugger_association_absent = $true
            cleanup_succeeded = $true
            detail = ''
        }
        stdout = Get-D32Phase0FileReference -Path $stdoutPath
        stderr = Get-D32Phase0FileReference -Path $stderrPath
        candidate_sha_after = $CandidateSha
        clean_after = $true
    }
}

function New-D32PreflightSelfTestInventoryRows {
    param([Parameter(Mandatory = $true)][object]$Inventory)
    $rows = [ordered]@{}
    $h7TestNames = @(Get-D32H7CGitCodeOwnedTestInventory)
    foreach ($package in @('protocol', 'vita', 'host')) {
        $names = [System.Collections.Generic.List[string]]::new()
        foreach ($name in @($Inventory.$package.all)) { $names.Add([string]$name) }
        if ($package -eq 'vita') {
            foreach ($name in $h7TestNames) { $names.Add("d29h7::tests::$name") }
            $names.Add('vita::tests::inventory_authority_ordinary_control')
        }
        elseif ($package -eq 'host') { $names.Add('vita_sidecar::tests::inventory_authority_ordinary_control') }
        $all = [System.Collections.Generic.List[object]]::new()
        foreach ($name in $names) { $all.Add([PSCustomObject][ordered]@{ package = $package; kind = 'test'; full_name = [string]$name }) }
        $ignored = [System.Collections.Generic.List[object]]::new()
        foreach ($name in @($Inventory.$package.ignored)) { $ignored.Add([PSCustomObject][ordered]@{ package = $package; kind = 'test'; full_name = [string]$name }) }
        $rows[$package] = [PSCustomObject]@{ all = @($all.ToArray()); ignored = @($ignored.ToArray()) }
    }
    return $rows
}

function New-D32PreflightSelfTestSuiteLines {
    param([Parameter(Mandatory = $true)][string]$Package, [Parameter(Mandatory = $true)][object[]]$Entries)
    $suiteEntries = @($Entries | Where-Object { $_.package -ceq $Package -and $_.kind -ceq 'test' -and $_.category -cne 'deferred' })
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("running $($suiteEntries.Count) tests")
    $passed = [Int64]0
    $ignored = [Int64]0
    foreach ($entry in $suiteEntries) {
        if ($entry.category -ceq 'ignored') { $status = 'ignored'; $ignored++ }
        else { $status = 'ok'; $passed++ }
        $lines.Add("test $($entry.full_name) ... $status")
    }
    $deferred = [Int64]@($Entries | Where-Object { $_.package -ceq $Package -and $_.kind -ceq 'test' -and $_.category -ceq 'deferred' }).Count
    $lines.Add("test result: ok. $passed passed; 0 failed; $ignored ignored; 0 measured; $deferred filtered out; finished in 0.01s")
    return @($lines.ToArray())
}

function New-D32PreflightSelfTestInventoryAuthorityArtifacts {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$PinnedGitPath,
        [Parameter(Mandatory = $true)][string]$PinnedGitSha256,
        [Parameter(Mandatory = $true)][string]$ArchiveSourcePath,
        [Parameter(Mandatory = $true)][object]$SourcePatchAuthority
    )

    $discoveryRoot = Join-Path $Root 'inventory-discovery'
    $discoveryRunId = 'abcdef0123456789abcdef0123456789'
    $authorityPath = Join-Path $Root 'D32-VENDORED-PROTOC-INVENTORY-DISCOVERY-AUTHORITY.json'
    $authorityDocument = New-D32VendoredProtocAuthorityDocument -Repository $Repository -CandidateSha $CandidateSha `
        -ValidatedProfile $ValidatedProfile -EvidenceRoot $discoveryRoot -Scope 'D32_TEST_INVENTORY_DISCOVERY_ONLY'
    $authorityReference = Write-D32VendoredProtocAuthorityCreateNew -Path $authorityPath -Document $authorityDocument
    $owner = New-D32Phase0FixtureOutputRoot -Path $discoveryRoot -Repository $Repository -ExpectedCandidateSha $CandidateSha `
        -ValidatedProfile $ValidatedProfile -RunId $discoveryRunId
    $runRoot = Join-Path $discoveryRoot 'r'
    $cargoHome = Join-Path $runRoot 'c'
    $tempRoot = Join-Path $runRoot 't'
    $runRootIdentity = New-D32ProfileDirectoryCreateNew -Path $runRoot
    $cargoHomeIdentity = New-D32ProfileDirectoryCreateNew -Path $cargoHome
    $tempRootIdentity = New-D32ProfileDirectoryCreateNew -Path $tempRoot
    $logsRoot = Join-Path $discoveryRoot 'logs'
    $logsIdentity = New-D32ProfileDirectoryCreateNew -Path $logsRoot
    $lockInputs = @(Get-D32BuildToolchainLockInputs -Repository $Repository)
    $cargo = [string]$ValidatedProfile.Profile.toolchain.cargo.path
    $ordinal = 0
    $fetches = [System.Collections.Generic.List[object]]::new()
    $inventoryTimelineStart = [DateTimeOffset]::UtcNow.AddSeconds(-80)
    foreach ($index in 0..2) {
        $lock = $lockInputs[$index]
        $arguments = @('fetch', '--locked', '--manifest-path', [string]$lock.ManifestFullPath, '--target', [string]$ValidatedProfile.Profile.target_triple)
        $fetches.Add((New-D32PreflightSelfTestPhase0Command -Name ('inventory-fetch-{0:D2}' -f ($index + 1)) `
            -Repository $Repository -CandidateSha $CandidateSha -ValidatedProfile $ValidatedProfile -LogRoot $logsRoot `
            -LogStem ('inventory-fetch-{0:D2}' -f ($index + 1)) -Arguments $arguments -TimeoutSeconds 14400 `
            -StdoutLines @('selftest locked fetch output') -RootProcessId (41000 + $index) `
            -StartedAtUtc $inventoryTimelineStart.AddSeconds(5 * $index).ToString('o')))
    }
    $archivePath = Join-Path $cargoHome $script:D32VendoredProtocArchiveRelativePath
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($archivePath))
    [IO.File]::Copy($ArchiveSourcePath, $archivePath)
    $grant = New-D32VendoredProtocRunGrant -AuthorityPath $authorityPath -AuthoritySha256 ([string]$authorityReference.sha256 `
        ) -Repository $Repository -CandidateSha $CandidateSha -ValidatedProfile $ValidatedProfile -EvidenceRoot $discoveryRoot `
        -OwnerMarkerReference $owner.OwnerMarker -RunId $discoveryRunId -CargoHome $cargoHome -Scope 'D32_TEST_INVENTORY_DISCOVERY_ONLY'
    $grant = Test-D32VendoredProtocRunGrant -Reference $grant.Reference -Repository $Repository -CandidateSha $CandidateSha `
        -ValidatedProfile $ValidatedProfile -EvidenceRoot $discoveryRoot -ExpectedRunId $discoveryRunId -CargoHome $cargoHome `
        -AuthorityPath $authorityPath -AuthoritySha256 ([string]$authorityReference.sha256) -OwnerMarkerReference $owner.OwnerMarker `
        -Scope 'D32_TEST_INVENTORY_DISCOVERY_ONLY'

    $selfTestRows = New-D32PreflightSelfTestInventoryRows -Inventory (New-D32Phase0SelfTestInventory)
    $expectedCommands = @(Get-D32TestInventoryExpectedCommands -Profile $ValidatedProfile.Profile)
    $inventoryCommands = [System.Collections.Generic.List[object]]::new()
    $packageRows = @{}
    for ($index = 0; $index -lt $expectedCommands.Count; $index++) {
        $expected = $expectedCommands[$index]
        $rows = if ($expected.listing_kind -ceq 'all') { @($selfTestRows[$expected.package].all) } else { @($selfTestRows[$expected.package].ignored) }
        $listLines = [System.Collections.Generic.List[string]]::new()
        foreach ($row in $rows) { $listLines.Add("$($row.full_name): $($row.kind)") }
        $testCount = [Int64]@($rows | Where-Object { $_.kind -ceq 'test' }).Count
        $benchmarkCount = [Int64]@($rows | Where-Object { $_.kind -ceq 'benchmark' }).Count
        $testLabel = if ($testCount -eq 1) { 'test' } else { 'tests' }
        $benchmarkLabel = if ($benchmarkCount -eq 1) { 'benchmark' } else { 'benchmarks' }
        $listLines.Add("$testCount $testLabel, $benchmarkCount $benchmarkLabel")
        $command = New-D32PreflightSelfTestPhase0Command -Name $expected.name -Repository $Repository -CandidateSha $CandidateSha `
            -ValidatedProfile $ValidatedProfile -LogRoot $logsRoot -LogStem ('inventory-list-{0:D2}' -f ($index + 1)) `
            -Arguments @($expected.arguments) -TimeoutSeconds 28800 -StdoutLines @($listLines.ToArray()) -RootProcessId (42000 + $index) `
            -StartedAtUtc $inventoryTimelineStart.AddSeconds(15 + 5 * $index).ToString('o')
        $parsed = Get-D32TestInventoryListOutput -Lines @($listLines.ToArray()) -Package $expected.package -ListingKind $expected.listing_kind
        $inventoryCommands.Add([ordered]@{
            package = [string]$expected.package
            listing_kind = [string]$expected.listing_kind
            features = @($expected.features)
            target_triple = [string]$expected.target_triple
            digest = Get-D32TestInventoryDigest -Rows $parsed.rows
            row_count = [Int64]$parsed.row_count
            test_count = [Int64]$parsed.test_count
            benchmark_count = [Int64]$parsed.benchmark_count
            rows = @($parsed.rows)
            command = $command
        })
        $packageRows[([string]$expected.package + '|' + [string]$expected.listing_kind)] = @($parsed.rows)
    }
    $packageInventories = [System.Collections.Generic.List[object]]::new()
    $classificationPolicy = Get-D32Phase0TestInventoryClassificationPolicy
    foreach ($package in @('protocol', 'vita', 'host')) {
        [string[]]$deferred = @()
        [string[]]$focused = @()
        if ($package -ceq 'vita') { $deferred = @($classificationPolicy.deferred_vita); $focused = @($classificationPolicy.focused_vita) }
        elseif ($package -ceq 'host') { $deferred = @($classificationPolicy.deferred_host); $focused = @($classificationPolicy.focused_host) }
        $packageInventories.Add((Get-D32TestInventoryCategoryAssignments -Package $package -AllRows $packageRows[($package + '|all')] `
            -IgnoredRows $packageRows[($package + '|ignored')] -DeferredNames $deferred -FocusedSuffixes $focused))
    }
    $allEntries = @(Sort-D32TestInventoryBaselineEntries -Entries @($packageInventories | ForEach-Object { $_.entries }))
    $packageDigests = [System.Collections.Generic.List[object]]::new()
    $categoryCounts = [ordered]@{}
    foreach ($assignment in $packageInventories) {
        $packageEntries = @($assignment.entries)
        $packageDigests.Add([ordered]@{ package = [string]$assignment.package; entry_count = [Int64]$packageEntries.Count; sha256 = Get-D32TestInventoryBaselineDigest -Entries $packageEntries })
        $categoryCounts[[string]$assignment.package] = $assignment.category_counts
    }
    $discoveryPre = Get-D32Phase0GitState -Repository $Repository -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256
    if ($discoveryPre.Head -cne $CandidateSha -or -not $discoveryPre.Clean) { throw 'preflight self-test inventory fixture must start at its exact clean candidate' }
    $toolchainProfile = Get-D32TestInventoryProfileRecord -ValidatedProfile $ValidatedProfile
    $discovery = [ordered]@{
        schema_version = 2
        record_type = 'D32_TEST_INVENTORY_DISCOVERY_V2'
        status = 'COMPLETE_FOR_COORDINATOR_REVIEW'
        gate_authority = 'NONE'
        runner_process_id = [int]$PID
        candidate_sha = $CandidateSha
        source_repo = [IO.Path]::GetFullPath($Repository)
        evidence_root_identity = [ordered]@{ path = [string]$owner.RootIdentity.Path; volume_serial_hex = [string]$owner.RootIdentity.VolumeSerialHex; file_id_hex = [string]$owner.RootIdentity.FileIdHex }
        owner_marker = $owner.OwnerMarker
        run_id = $discoveryRunId
        toolchain_profile = $toolchainProfile
        lock_inputs = @($lockInputs | ForEach-Object { [ordered]@{ manifest_path = [string]$_.ManifestPath; lock_sha256 = [string]$_.LockSha256; lock_bytes = [Int64]$_.LockBytes } })
        source_patch_authority = $SourcePatchAuthority.Reference
        protoc = [ordered]@{ authority = $authorityReference; run_grant = $grant.Reference }
        storage = [ordered]@{
            run_root = [ordered]@{ path = [string]$runRootIdentity.Path; volume_serial_hex = [string]$runRootIdentity.VolumeSerialHex; file_id_hex = [string]$runRootIdentity.FileIdHex }
            cargo_home = [ordered]@{ path = [string]$cargoHomeIdentity.Path; volume_serial_hex = [string]$cargoHomeIdentity.VolumeSerialHex; file_id_hex = [string]$cargoHomeIdentity.FileIdHex }
            temp_root = [ordered]@{ path = [string]$tempRootIdentity.Path; volume_serial_hex = [string]$tempRootIdentity.VolumeSerialHex; file_id_hex = [string]$tempRootIdentity.FileIdHex }
        }
        fetches = @($fetches.ToArray())
        inventory_commands = @($inventoryCommands.ToArray())
        test_inventory = [ordered]@{
            entries = $allEntries
            combined_digest = Get-D32TestInventoryBaselineDigest -Entries $allEntries
            package_digests = @($packageDigests.ToArray())
            category_counts = $categoryCounts
        }
        powershell_module_admission = $global:D32PowerShellModuleAuthorityState.Admission
        started_at_utc = $inventoryTimelineStart.AddSeconds(-10).ToString('o')
        completed_at_utc = $inventoryTimelineStart.AddSeconds(50).ToString('o')
        final_candidate_sha = $CandidateSha
        final_clean = $true
    }
    $discoveryPath = Join-Path $discoveryRoot 'D32-TEST-INVENTORY-DISCOVERY.json'
    Write-D32JsonCreateNew -Path $discoveryPath -Value $discovery
    $discoveryReference = Get-D32Phase0FileReference -Path $discoveryPath
    $validatedDiscovery = Test-D32Phase0TestInventoryDiscoveryRecord -Reference $discoveryReference -ExpectedSha256 ([string]$discoveryReference.sha256 `
        ) -Repository $Repository -CandidateSha $CandidateSha -Profile $ValidatedProfile -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256 -LockInputs $lockInputs
    $discoverySchemaMutationResults = [System.Collections.Generic.List[object]]::new()
    foreach ($schemaCase in @(
        [PSCustomObject]@{ Name = 'prior discovery schema'; Version = 0 },
        [PSCustomObject]@{ Name = 'unknown discovery schema'; Version = 99 }
    )) {
        $mutatedDiscoveryRoot = Join-Path $Root ('inventory-discovery-schema-' + ([string]$schemaCase.Version))
        if ([IO.Directory]::Exists($mutatedDiscoveryRoot) -or [IO.File]::Exists($mutatedDiscoveryRoot)) {
            throw 'preflight self-test discovery schema fixture root must be absent'
        }
        $null = New-D32ProfileDirectoryCreateNew -Path $mutatedDiscoveryRoot
        $mutatedDiscovery = ConvertFrom-D32Phase0Json -Json (ConvertTo-Json -InputObject $validatedDiscovery.Document -Depth 40 -Compress)
        $mutatedDiscovery.schema_version = [int]$schemaCase.Version
        $mutatedDiscoveryPath = Join-Path $mutatedDiscoveryRoot 'D32-TEST-INVENTORY-DISCOVERY.json'
        Write-D32JsonCreateNew -Path $mutatedDiscoveryPath -Value $mutatedDiscovery
        $mutatedDiscoveryReference = Get-D32Phase0FileReference -Path $mutatedDiscoveryPath
        $schemaRejected = $false
        try {
            $null = Test-D32Phase0TestInventoryDiscoveryRecord -Reference $mutatedDiscoveryReference `
                -ExpectedSha256 ([string]$mutatedDiscoveryReference.sha256) -Repository $Repository -CandidateSha $CandidateSha `
                -Profile $ValidatedProfile -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256 -LockInputs $lockInputs
        }
        catch { $schemaRejected = $_.Exception.Message -like 'TEST_INVENTORY_DISCOVERY_BLOCKED:*strict V1 schema*' }
        $discoverySchemaMutationResults.Add([PSCustomObject]@{ Name = [string]$schemaCase.Name; Rejected = $schemaRejected })
    }
    $discoveryOriginalRaw = [IO.File]::ReadAllText($discoveryPath, [Text.Encoding]::UTF8)
    $discoveryReferenceMutationResults = [System.Collections.Generic.List[object]]::new()
    $discoveryReferenceMutationCases = @(
        [PSCustomObject]@{ Name = 'source authority stale opened identity'; Expected = '*source-patch authority bytes/opened identity*'; Mutation = { param($doc) $doc.source_patch_authority.volume_serial_hex = '0000000000000000' } },
        [PSCustomObject]@{ Name = 'source authority extra reference field'; Expected = '*source-patch reference must retain complete opened-file identity*'; Mutation = { param($doc) $doc.source_patch_authority | Add-Member -NotePropertyName unexpected -NotePropertyValue 'unbound' -Force } }
    )
    foreach ($case in $discoveryReferenceMutationCases) {
        $mutatedDiscovery = ConvertFrom-D32Phase0Json -Json (ConvertTo-Json -InputObject $validatedDiscovery.Document -Depth 40 -Compress)
        & $case.Mutation $mutatedDiscovery
        [IO.File]::WriteAllText($discoveryPath, (ConvertTo-Json -InputObject $mutatedDiscovery -Depth 40 -Compress), [Text.UTF8Encoding]::new($false))
        $mutatedReference = Get-D32Phase0FileReference -Path $discoveryPath
        $sourceReferenceRejected = $false
        try {
            $null = Test-D32Phase0TestInventoryDiscoveryRecord -Reference $mutatedReference -ExpectedSha256 ([string]$mutatedReference.sha256) `
                -Repository $Repository -CandidateSha $CandidateSha -Profile $ValidatedProfile -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256 -LockInputs $lockInputs
        }
        catch { $sourceReferenceRejected = $_.Exception.Message -like ('TEST_INVENTORY_DISCOVERY_BLOCKED:' + [string]$case.Expected) }
        finally { [IO.File]::WriteAllText($discoveryPath, $discoveryOriginalRaw, [Text.UTF8Encoding]::new($false)) }
        $discoveryReferenceMutationResults.Add([PSCustomObject]@{ Name = [string]$case.Name; Rejected = $sourceReferenceRejected })
    }
    $discoveryTimestampMutationResults = [System.Collections.Generic.List[object]]::new()
    $discoveryTimestampMutationCases = @(
        [PSCustomObject]@{ Name = 'discovery completion precedes start'; Mutation = { param($doc) $doc.completed_at_utc = ([DateTimeOffset]::Parse([string]$doc.started_at_utc).AddSeconds(-1).ToString('o')) } },
        [PSCustomObject]@{ Name = 'fetch commands out of order'; Mutation = { param($doc) $doc.fetches[1].started_at_utc = [string]$doc.fetches[0].started_at_utc } },
        [PSCustomObject]@{ Name = 'list commands out of order'; Mutation = { param($doc) $doc.inventory_commands[1].command.started_at_utc = [string]$doc.inventory_commands[0].command.started_at_utc } },
        [PSCustomObject]@{ Name = 'command extends beyond discovery interval'; Mutation = { param($doc) $last = $doc.inventory_commands[5].command; $doc.completed_at_utc = [DateTimeOffset]::Parse([string]$last.completed_at_utc).AddSeconds(-1).ToString('o') } }
    )
    foreach ($case in $discoveryTimestampMutationCases) {
        $mutatedDiscovery = ConvertFrom-D32Phase0Json -Json (ConvertTo-Json -InputObject $validatedDiscovery.Document -Depth 40 -Compress)
        & $case.Mutation $mutatedDiscovery
        [IO.File]::WriteAllText($discoveryPath, (ConvertTo-Json -InputObject $mutatedDiscovery -Depth 40 -Compress), [Text.UTF8Encoding]::new($false))
        $mutatedReference = Get-D32Phase0FileReference -Path $discoveryPath
        $timestampRejected = $false
        try {
            $null = Test-D32Phase0TestInventoryDiscoveryRecord -Reference $mutatedReference -ExpectedSha256 ([string]$mutatedReference.sha256) `
                -Repository $Repository -CandidateSha $CandidateSha -Profile $ValidatedProfile -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256 -LockInputs $lockInputs
        }
        catch { $timestampRejected = $_.Exception.Message -like 'TEST_INVENTORY_DISCOVERY_BLOCKED:*' }
        finally { [IO.File]::WriteAllText($discoveryPath, $discoveryOriginalRaw, [Text.UTF8Encoding]::new($false)) }
        $discoveryTimestampMutationResults.Add([PSCustomObject]@{ Name = [string]$case.Name; Rejected = $timestampRejected })
    }
    $validatedDiscovery = Test-D32Phase0TestInventoryDiscoveryRecord -Reference $discoveryReference `
        -ExpectedSha256 ([string]$discoveryReference.sha256) -Repository $Repository -CandidateSha $CandidateSha `
        -Profile $ValidatedProfile -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256 -LockInputs $lockInputs
    $protocolProtocTraceAcceptedWithGrant = $false
    $protocolProtocTraceRejectedWithoutGrant = $false
    $protocolListExpected = @(Get-D32TestInventoryExpectedCommands -Profile $ValidatedProfile.Profile)[0]
    $protocolListCommand = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize(
        $validatedDiscovery.Document.inventory_commands[0].command))
    $protocolTrace = $protocolListCommand.process_trace
    $rootTraceProcess = $protocolTrace.processes[0]
    $childPid = [int]$rootTraceProcess.process_id + 1
    $childCreation = [Int64]$rootTraceProcess.creation_filetime + 10000000
    $protocImage = $validatedDiscovery.ProtocGrant.Image
    $childCreatedAt = [DateTime]::FromFileTimeUtc($childCreation).ToString('o')
    $protocolTrace.processes[0].exit_sequence = 4
    $protocolTrace.process_events = @(
        $protocolTrace.process_events[0],
        [ordered]@{ sequence = 2; kind = 'CREATE'; process_id = $childPid; parent_process_id = [int]$rootTraceProcess.process_id; creation_filetime = $childCreation; parent_creation_filetime = [Int64]$rootTraceProcess.creation_filetime; exit_code = 0 },
        [ordered]@{ sequence = 3; kind = 'EXIT'; process_id = $childPid; parent_process_id = [int]$rootTraceProcess.process_id; creation_filetime = $childCreation; parent_creation_filetime = [Int64]$rootTraceProcess.creation_filetime; exit_code = 0 },
        [ordered]@{ sequence = 4; kind = 'EXIT'; process_id = [int]$rootTraceProcess.process_id; parent_process_id = [int]$rootTraceProcess.parent_process_id; creation_filetime = [Int64]$rootTraceProcess.creation_filetime; parent_creation_filetime = [Int64]$rootTraceProcess.parent_creation_filetime; exit_code = 0 }
    )
    $protocolTrace.processes[0].exit_sequence = 4
    $protocolTrace.processes += [ordered]@{
        process_id = $childPid; parent_process_id = [int]$rootTraceProcess.process_id; creation_filetime = $childCreation
        parent_creation_filetime = [Int64]$rootTraceProcess.creation_filetime; image_path = [string]$protocImage.Path
        bytes = [Int64]$protocImage.Bytes; sha256 = [string]$protocImage.Sha256
        volume_serial_hex = [string]$protocImage.VolumeSerialHex; file_id_hex = [string]$protocImage.FileIdHex
        allowed_image_reason = 'caller-pinned-locked-vendored-protoc-descendant-of-fixed-cargo-root'; image_verified = $true; exited = $true; exit_code = 0
        create_sequence = 2; exit_sequence = 3; created_at_utc = $childCreatedAt; exited_at_utc = $childCreatedAt
    }
    $protocolTrace.debug_event_count = 4
    $protocolTrace.process_create_event_count = 2
    $protocolTrace.process_exit_event_count = 2
    $protocolTrace.process_event_count = 4
    $protocolTrace.job_total_processes = 2
    $protocolTrace.retained_process_handle_count = 3
    $protocolListCommand.process_tree_cleanup.retained_process_handle_count = 3
    $protocolListCommand.descendant_processes = @([ordered]@{
        process_id = $childPid; parent_process_id = [int]$rootTraceProcess.process_id; name = 'protoc.exe'
        image_path = [string]$protocImage.Path; command_line = 'protoc.exe --selftest'; creation_date = $childCreatedAt
        observed_at_utc = $childCreatedAt; sha256 = [string]$protocImage.Sha256; bytes = [Int64]$protocImage.Bytes
        volume_serial_hex = [string]$protocImage.VolumeSerialHex; file_id_hex = [string]$protocImage.FileIdHex; identity_verified = $true
    })
    try {
        $null = Test-D32Phase0InventoryProcessRecord -Command $protocolListCommand -Name $protocolListExpected.name -Executable $protocolListExpected.executable `
            -Arguments $protocolListExpected.arguments -TimeoutSeconds 28800 -RunnerProcessId ([int]$validatedDiscovery.Document.runner_process_id) `
            -Profile $ValidatedProfile -Repository $Repository -CandidateSha $CandidateSha -EvidenceRoot $discoveryRoot `
            -VendoredProtocGrant $validatedDiscovery.ProtocGrant
        $protocolProtocTraceAcceptedWithGrant = $true
    }
    catch { $protocolProtocTraceAcceptedWithGrant = $false }
    try {
        $null = Test-D32Phase0InventoryProcessRecord -Command $protocolListCommand -Name $protocolListExpected.name -Executable $protocolListExpected.executable `
            -Arguments $protocolListExpected.arguments -TimeoutSeconds 28800 -RunnerProcessId ([int]$validatedDiscovery.Document.runner_process_id) `
            -Profile $ValidatedProfile -Repository $Repository -CandidateSha $CandidateSha -EvidenceRoot $discoveryRoot -VendoredProtocGrant $null
    }
    catch { $protocolProtocTraceRejectedWithoutGrant = $_.Exception.Message -like '*PROCESS_TRACE_BLOCKED*' }
    $baseline = New-D32TestInventoryBaselineDocument -Discovery $validatedDiscovery.Document -DiscoveryReference $validatedDiscovery.Reference `
        -PackageInventories $validatedDiscovery.PackageInventories -GeneratedAtUtc ([DateTimeOffset]::UtcNow.ToString('o'))
    $expectedCommands = @(Get-D32TestInventoryExpectedCommands -Profile $ValidatedProfile.Profile)
    $null = Test-D32TestInventoryBaselineDocument -Document $baseline -Discovery $validatedDiscovery.Document -DiscoveryReference $validatedDiscovery.Reference `
        -ExpectedCandidateSha $CandidateSha -Repository $Repository -Profile $ValidatedProfile -LockInputs $lockInputs `
        -SourcePatchAuthorityReference $SourcePatchAuthority.Reference -ProtocAuthorityReference $authorityReference -ExpectedCommands $expectedCommands
    $baselinePath = Join-Path $Root 'D32-TEST-INVENTORY-BASELINE.json'
    $baselineReference = Write-D32TestInventoryJsonCreateNew -Path $baselinePath -Document $baseline -Repository $Repository -DiscoveryRoot $discoveryRoot
    $validatedAuthority = Test-D32Phase0TestInventoryAuthority -BaselinePath $baselinePath -BaselineSha256 ([string]$baselineReference.sha256 `
        ) -Repository $Repository -EvidenceRoot (Join-Path $Root 'phase0') -CandidateSha $CandidateSha -Profile $ValidatedProfile `
        -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256 -SourcePatchAuthorityReference $SourcePatchAuthority.Reference `
        -ExpectedBaselineReference $baselineReference
    $nestedPhase0Root = Join-Path $discoveryRoot 'nested-phase0-root'
    $nestedPhase0RootRejected = $false
    try {
        $null = Test-D32Phase0TestInventoryAuthority -BaselinePath $baselinePath -BaselineSha256 ([string]$baselineReference.sha256 `
            ) -Repository $Repository -EvidenceRoot $nestedPhase0Root -CandidateSha $CandidateSha -Profile $ValidatedProfile `
            -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256 -SourcePatchAuthorityReference $SourcePatchAuthority.Reference `
            -ExpectedBaselineReference $baselineReference
    }
    catch { $nestedPhase0RootRejected = $_.Exception.Message -like 'TEST_INVENTORY_ROOT_BLOCKED:*' }
    $nestedPhase0RootRejected = $nestedPhase0RootRejected -and -not [IO.Directory]::Exists($nestedPhase0Root)

    $expectedCommandsForMutation = @(Get-D32TestInventoryExpectedCommands -Profile $ValidatedProfile.Profile)
    $mutateAndValidateBaseline = {
        param([string]$Name, [scriptblock]$Mutation, [bool]$ResealInventory)
        $mutated = ConvertFrom-D32Phase0Json -Json (ConvertTo-Json -InputObject $baseline -Depth 40 -Compress)
        & $Mutation $mutated
        if ($ResealInventory) {
            $mutated.entries = @(Sort-D32TestInventoryBaselineEntries -Entries @($mutated.entries))
            $mutated.combined_digest = Get-D32TestInventoryBaselineDigest -Entries @($mutated.entries)
            for ($packageIndex = 0; $packageIndex -lt 3; $packageIndex++) {
                $package = @('protocol', 'vita', 'host')[$packageIndex]
                $packageEntries = @($mutated.entries | Where-Object { $_.package -ceq $package })
                $mutated.package_digests[$packageIndex].entry_count = [Int64]$packageEntries.Count
                $mutated.package_digests[$packageIndex].sha256 = Get-D32TestInventoryBaselineDigest -Entries $packageEntries
                foreach ($category in @('ordinary', 'ignored', 'deferred', 'focused')) {
                    $mutated.category_counts.$package.$category = [Int64]@($packageEntries | Where-Object { $_.category -ceq $category }).Count
                }
            }
        }
        $rejected = $false
        try {
            $null = Test-D32TestInventoryBaselineDocument -Document $mutated -Discovery $validatedDiscovery.Document `
                -DiscoveryReference $validatedDiscovery.Reference -ExpectedCandidateSha $CandidateSha -Repository $Repository `
                -Profile $ValidatedProfile -LockInputs $lockInputs -SourcePatchAuthorityReference $SourcePatchAuthority.Reference `
                -ProtocAuthorityReference $authorityReference -ExpectedCommands $expectedCommandsForMutation
        }
        catch { $rejected = $_.Exception.Message -like 'TEST_INVENTORY_BASELINE_BLOCKED:*' }
        return [PSCustomObject]@{ Name = $Name; Rejected = $rejected }
    }.GetNewClosure()
    $baselineMutationCases = @(
        [PSCustomObject]@{ Name = 'prior schema'; Reseal = $false; Mutation = { param($doc) $doc.schema_version = 0 } },
        [PSCustomObject]@{ Name = 'unknown schema'; Reseal = $false; Mutation = { param($doc) $doc.schema_version = 99 } },
        [PSCustomObject]@{ Name = 'self-pinned authority status'; Reseal = $false; Mutation = { param($doc) $doc.status = 'COORDINATOR_PINNED'; $doc.gate_authority = 'PASS' } },
        [PSCustomObject]@{ Name = 'stale candidate'; Reseal = $false; Mutation = { param($doc) $doc.candidate_sha = ('f' * 40) } },
        [PSCustomObject]@{ Name = 'stale profile identity'; Reseal = $false; Mutation = { param($doc) $doc.toolchain_profile.file_id_hex = ('0' * 32) } },
        [PSCustomObject]@{ Name = 'wrong target'; Reseal = $false; Mutation = { param($doc) $doc.target_triple = 'aarch64-pc-windows-msvc' } },
        [PSCustomObject]@{ Name = 'wrong discovery root'; Reseal = $false; Mutation = { param($doc) $doc.discovery.evidence_root.path = 'C:\other-discovery-root' } },
        [PSCustomObject]@{ Name = 'copied discovery completion timestamp mismatch'; Reseal = $false; Mutation = { param($doc) $doc.discovery.completed_at_utc = [DateTimeOffset]::Parse([string]$doc.discovery.completed_at_utc).AddSeconds(1).ToString('o') } },
        [PSCustomObject]@{ Name = 'baseline generated before discovery completion'; Reseal = $false; Mutation = { param($doc) $doc.generated_at_utc = [DateTimeOffset]::Parse([string]$doc.discovery.completed_at_utc).AddSeconds(-1).ToString('o') } },
        [PSCustomObject]@{ Name = 'malformed baseline generated timestamp'; Reseal = $false; Mutation = { param($doc) $doc.generated_at_utc = 'not-an-iso-timestamp' } },
        [PSCustomObject]@{ Name = 'wrong command jobs'; Reseal = $false; Mutation = { param($doc) $jobs = [Array]::IndexOf([string[]]$doc.commands[0].argv, '--jobs'); if ($jobs -lt 0) { throw 'self-test fixture command omitted --jobs' }; $doc.commands[0].argv[$jobs + 1] = '1' } },
        [PSCustomObject]@{ Name = 'wrong command timeout'; Reseal = $false; Mutation = { param($doc) $doc.commands[0].timeout_seconds = 28801 } },
        [PSCustomObject]@{ Name = 'added ordinary name'; Reseal = $true; Mutation = { param($doc) $doc.entries = @($doc.entries) + @([ordered]@{ package = 'protocol'; kind = 'test'; full_name = 'protocol::tests::added_ordinary'; category = 'ordinary' }) } },
        [PSCustomObject]@{ Name = 'removed ordinary name'; Reseal = $true; Mutation = { param($doc) $entry = @($doc.entries | Where-Object { $_.package -ceq 'protocol' -and $_.kind -ceq 'test' -and $_.category -ceq 'ordinary' })[0]; if ($null -eq $entry) { throw 'self-test fixture has no protocol ordinary test' }; $name = [string]$entry.full_name; $doc.entries = @($doc.entries | Where-Object { $_.full_name -cne $name -or $_.package -cne 'protocol' }) } },
        [PSCustomObject]@{ Name = 'renamed ordinary name'; Reseal = $true; Mutation = { param($doc) $entry = @($doc.entries | Where-Object { $_.package -ceq 'protocol' -and $_.kind -ceq 'test' -and $_.category -ceq 'ordinary' })[0]; if ($null -eq $entry) { throw 'self-test fixture has no protocol ordinary test' }; $entry.full_name = [string]$entry.full_name + '_renamed' } }
    )
    $baselineMutationResults = [System.Collections.Generic.List[object]]::new()
    foreach ($case in $baselineMutationCases) {
        $baselineMutationResults.Add((& $mutateAndValidateBaseline -Name $case.Name -Mutation $case.Mutation -ResealInventory ([bool]$case.Reseal)))
    }

    $lateBaselineRoot = Join-Path $Root 'phase0-late-baseline'
    if ([IO.Directory]::Exists($lateBaselineRoot) -or [IO.File]::Exists($lateBaselineRoot)) { throw 'preflight self-test late-baseline root must be absent' }
    $null = New-D32ProfileDirectoryCreateNew -Path $lateBaselineRoot
    $lateBaselinePath = Join-Path $lateBaselineRoot 'D32-TEST-INVENTORY-BASELINE.json'
    $lateBaselineReference = Write-D32TestInventoryJsonCreateNew -Path $lateBaselinePath -Document $baseline -Repository $Repository -DiscoveryRoot $discoveryRoot
    $lateBaselineRejected = $false
    try {
        $null = Test-D32Phase0TestInventoryAuthority -BaselinePath $lateBaselinePath -BaselineSha256 ([string]$lateBaselineReference.sha256 `
            ) -Repository $Repository -EvidenceRoot $lateBaselineRoot -CandidateSha $CandidateSha -Profile $ValidatedProfile `
            -GitPath $PinnedGitPath -GitSha256 $PinnedGitSha256 -SourcePatchAuthorityReference $SourcePatchAuthority.Reference `
            -ExpectedBaselineReference $lateBaselineReference
    }
    catch { $lateBaselineRejected = $_.Exception.Message -like 'TEST_INVENTORY_BASELINE_BLOCKED:*' }
    return [PSCustomObject]@{
        Discovery = $validatedDiscovery.Document
        DiscoveryReference = $validatedDiscovery.Reference
        Baseline = $validatedAuthority.Baseline
        BaselineReference = $validatedAuthority.BaselineReference
        BaselinePath = $baselinePath
        PackageInventories = @($validatedDiscovery.PackageInventories)
        DiscoverySchemaMutationResults = @($discoverySchemaMutationResults.ToArray())
        DiscoveryReferenceMutationResults = @($discoveryReferenceMutationResults.ToArray())
        DiscoveryTimestampMutationResults = @($discoveryTimestampMutationResults.ToArray())
        NestedPhase0RootRejectedWithoutCreation = $nestedPhase0RootRejected
        ProtocolProtocTraceAcceptedWithGrant = $protocolProtocTraceAcceptedWithGrant
        ProtocolProtocTraceRejectedWithoutGrant = $protocolProtocTraceRejectedWithoutGrant
        BaselineMutationResults = @($baselineMutationResults.ToArray())
        LateBaselineRejected = $lateBaselineRejected
    }
}

function Assert-D32PostBundleAggregateExternalSources {
    param(
        [Parameter(Mandatory = $true)][string[]]$Paths,
        [Parameter(Mandatory = $true)][string]$Repository
    )

    $canonicalRepository = Get-D32CanonicalPath -Path $Repository
    foreach ($path in $Paths) {
        if (-not (Test-D32NoReparseComponents -Path $path)) { throw "aggregate source is missing or reparse-backed: $path" }
        $canonicalSource = Get-D32CanonicalPath -Path $path
        if ((Test-D32PathInside -Child $canonicalSource -Parent $canonicalRepository) -or (Test-D32PathInside -Child $canonicalRepository -Parent $canonicalSource)) {
            throw "aggregate source must be external to and non-overlapping with the candidate repository: $path"
        }
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
        'fixture-manifest.candidate_sha', 'fixture-manifest.source_repo', 'fixture-manifest.policy', 'fixture-manifest.cleanup', 'fixture-manifest.phase0-binding',
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
        [Parameter(Mandatory = $true)][object]$ValidatedPhase0Snapshot,
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
        $recordReadFindings = New-D32FindingList
        $recordRead = Read-D32EvidenceJson -Path $RecordPath -Findings $recordReadFindings -Check 'aggregate.record.snapshot'
        if ($null -eq $recordRead) { throw 'aggregate record could not be read from one stable opened-byte snapshot' }
        $recordDigest = $recordRead.Digest
        if ($recordDigest.Hash -cne $ExpectedRecordSha256) { throw 'aggregate record bytes do not match the independently supplied SHA-256' }
        $record = $recordRead.Value
        $recordFields = @('schema_version', 'record_type', 'scope', 'candidate_sha', 'source_repo', 'evidence_root', 'status', 'bundle_hashes', 'downstream_gates', 'references', 'powershell_module_admission')
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
        if (-not (Test-D32PowerShellModuleAdmissionRecord -Document $record.powershell_module_admission -CandidateSha $ExpectedCandidateSha -Repository $repo -ExpectedContext $global:D32PowerShellModuleAuthorityState.Admission) -or
            -not (Test-D32PowerShellModuleAdmissionProfileBinding -Document $record.powershell_module_admission -ExpectedProfileReference $global:D32PowerShellModuleAuthorityState.Admission.profile_reference)) {
            throw 'aggregate record does not bind the current caller-pinned PowerShell module authority and producer admission'
        }
        $expectedBundleManifest = Join-Path (Join-Path $evidence $script:D32BundleDirectoryName) $script:D32BundleManifestName
        $expectedAttestation = Join-Path $evidence $script:D32AttestationName
        if (-not (Test-D32PathEqual -Left (Get-D32AbsolutePath -Path $BundleManifestPath) -Right $expectedBundleManifest) -or -not (Test-D32PathEqual -Left (Get-D32AbsolutePath -Path $AttestationPath) -Right $expectedAttestation)) { throw 'bundle manifest and attestation must be the fixed siblings under the aggregate evidence root' }
        $references = $record.references
        $referenceFields = @('phase0_matrix', 'toolchain_profile', 'fixture_manifest', 'provenance_manifest', 'bundle_manifest', 'attestation', 'trusted_git', 'test_inventory_baseline', 'test_inventory_discovery')
        if (-not (Test-D32Phase0ExactProperties -Object $references -Expected $referenceFields)) { throw 'aggregate record references object has missing or extra evidence sources' }
        $expectedSources = [ordered]@{
            phase0_matrix = $Phase0RecordPath
            toolchain_profile = $ToolchainProfilePath
            fixture_manifest = $FixtureManifestPath
            provenance_manifest = $ManifestPath
            bundle_manifest = $BundleManifestPath
            attestation = $AttestationPath
            trusted_git = $TrustedGitPath
            test_inventory_baseline = [string]$references.test_inventory_baseline.path
            test_inventory_discovery = [string]$references.test_inventory_discovery.path
        }
        foreach ($name in $referenceFields) {
            $null = Test-D32PostBundleAggregateFileReference -Reference $references.$name -Name "aggregate.references.$name" -ExpectedPath ([string]$expectedSources[$name]) -Repository $repo
        }
        if (-not (Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $record.powershell_module_admission -ProfileRecord $references.toolchain_profile) -or
            -not (Test-D32ProfilePathEqual -Left $record.powershell_module_admission.profile_reference.path -Right $ToolchainProfilePath) -or
            $record.powershell_module_admission.profile_reference.sha256 -cne [string]$global:D32PowerShellModuleAuthorityState.Admission.profile_reference.sha256) {
            throw 'aggregate producer admission is not cross-bound to the exact caller-pinned Profile V2 path/content/opened identity'
        }
        $requiredPhase0SnapshotFields = @('Path', 'Bytes', 'Sha256', 'VolumeSerialHex', 'FileIdHex')
        $presentPhase0SnapshotFields = if ($null -ne $ValidatedPhase0Snapshot) { @($ValidatedPhase0Snapshot.PSObject.Properties | ForEach-Object { [string]$_.Name }) } else { @() }
        if ($null -eq $ValidatedPhase0Snapshot -or
            @($requiredPhase0SnapshotFields | Where-Object { $presentPhase0SnapshotFields -cnotcontains $_ }).Count -gt 0 -or
            $ValidatedPhase0Snapshot.Path -isnot [string] -or
            -not (Test-D32Phase0Integer -Value $ValidatedPhase0Snapshot.Bytes -Positive) -or
            $ValidatedPhase0Snapshot.Sha256 -isnot [string] -or $ValidatedPhase0Snapshot.Sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $ValidatedPhase0Snapshot.VolumeSerialHex -isnot [string] -or $ValidatedPhase0Snapshot.VolumeSerialHex -cnotmatch '^[0-9a-f]{16}$' -or
            $ValidatedPhase0Snapshot.FileIdHex -isnot [string] -or $ValidatedPhase0Snapshot.FileIdHex -cnotmatch '^[0-9a-f]{32}$') {
            throw 'aggregate validation requires the exact opened-byte/identity snapshot returned by the full Phase0 validator'
        }
        $phase0Reference = $references.phase0_matrix
        if (-not (Test-D32ProfilePathEqual -Left ([string]$phase0Reference.path) -Right ([string]$ValidatedPhase0Snapshot.Path)) -or
            [Int64]$phase0Reference.bytes -ne [Int64]$ValidatedPhase0Snapshot.Bytes -or
            [string]$phase0Reference.sha256 -cne [string]$ValidatedPhase0Snapshot.Sha256 -or
            [string]$phase0Reference.volume_serial_hex -cne [string]$ValidatedPhase0Snapshot.VolumeSerialHex -or
            [string]$phase0Reference.file_id_hex -cne [string]$ValidatedPhase0Snapshot.FileIdHex) {
            throw 'aggregate Phase0 reference differs from the exact opened-byte/identity snapshot accepted by the full Phase0 validator'
        }
        $phase0Path = [string]$references.phase0_matrix.path
        $phase0OutputRoot = [IO.Path]::GetDirectoryName($phase0Path)
        $blockedDiagnosticPath = Join-Path $phase0OutputRoot 'D32-PHASE0-BLOCKED-DIAGNOSTIC.json'
        if (Test-D32Phase0DirectoryEntryExists -Path $blockedDiagnosticPath) { throw 'Phase0 blocked-diagnostic sidecar exists; failure evidence forbids aggregate use' }
        $phase0ReadFindings = New-D32FindingList
        $phase0Read = Read-D32EvidenceJson -Path $phase0Path -Findings $phase0ReadFindings -Check 'aggregate.phase0.snapshot'
        if ($null -eq $phase0Read) { throw 'aggregate-referenced Phase0 matrix could not be read from one stable opened-byte snapshot' }
        if ($phase0Read.Digest.Hash -cne [string]$phase0Reference.sha256 -or
            $phase0Read.Digest.Length -ne [Int64]$phase0Reference.bytes -or
            $phase0Read.Digest.Identity.VolumeSerialHex -cne [string]$phase0Reference.volume_serial_hex -or
            $phase0Read.Digest.Identity.FileIdHex -cne [string]$phase0Reference.file_id_hex -or
            $phase0Read.Digest.Hash -cne [string]$ValidatedPhase0Snapshot.Sha256 -or
            $phase0Read.Digest.Identity.VolumeSerialHex -cne [string]$ValidatedPhase0Snapshot.VolumeSerialHex -or
            $phase0Read.Digest.Identity.FileIdHex -cne [string]$ValidatedPhase0Snapshot.FileIdHex) {
            throw 'aggregate-referenced Phase0 bytes/opened-handle identity changed after full Phase0 validation'
        }
        $phase0Document = $phase0Read.Value
        $phase0Fields = @('schema_version', 'record_type', 'runner_process_id', 'candidate_sha', 'source_repo', 'output_root', 'evidence_root_identity', 'owner_marker', 'vendored_protoc', 'tauri_macros_source_patch', 'h7c_git_child_authority', 'h7c_git_child_attestation', 'test_inventory_authority', 'powershell_module_admission', 'status', 'bundle_hashes', 'started_at_utc', 'completed_at_utc', 'final_candidate_sha', 'final_clean', 'powershell', 'toolchain_profile', 'cargo_home', 'fixture_build_budget', 'fetches', 'fixture', 'commands', 'test_inventory', 'local_suites', 'focused_tests', 'deferred_d31_tests', 'deferred_d29g2_provider_tests', 'not_run_capture_tests', 'governance_inputs', 'phase0_scope')
        if (-not (Test-D32Phase0ExactProperties -Object $phase0Document -Expected $phase0Fields) -or
            -not (Test-D32Phase0Integer -Value $phase0Document.schema_version) -or [Int64]$phase0Document.schema_version -ne 8 -or
            $phase0Document.record_type -isnot [string] -or $phase0Document.record_type -cne 'D32_PHASE0_MATRIX_RECORD_V8' -or
            $phase0Document.candidate_sha -isnot [string] -or $phase0Document.candidate_sha -cne $ExpectedCandidateSha -or
            $phase0Document.final_candidate_sha -isnot [string] -or $phase0Document.final_candidate_sha -cne $ExpectedCandidateSha -or
            $phase0Document.status -cne 'PASS' -or $phase0Document.bundle_hashes -cne 'PENDING' -or
            $phase0Document.final_clean -isnot [bool] -or -not $phase0Document.final_clean) { throw 'aggregate-referenced Phase0 matrix is not the supported exact V8 local PASS schema' }
        if (-not (Test-D32PowerShellModuleAdmissionRecord -Document $phase0Document.powershell_module_admission -CandidateSha $ExpectedCandidateSha -Repository $repo -ExpectedContext $global:D32PowerShellModuleAuthorityState.Admission) -or
            -not (Test-D32PowerShellModuleAdmissionRunnerBinding -Document $phase0Document.powershell_module_admission -ExpectedProcessId ([Int64]$phase0Document.runner_process_id)) -or
            -not (Test-D32PowerShellModuleAdmissionProfileRecordBinding -Document $phase0Document.powershell_module_admission -ProfileRecord $phase0Document.toolchain_profile)) { throw 'aggregate-referenced Phase0 module admission is missing, stale or cross-bound' }
        if (-not (Test-D32Phase0ExactProperties -Object $phase0Document.test_inventory_authority -Expected @('baseline', 'discovery')) -or
            (ConvertTo-Json -InputObject $phase0Document.test_inventory_authority.baseline -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $references.test_inventory_baseline -Depth 6 -Compress) -or
            (ConvertTo-Json -InputObject $phase0Document.test_inventory_authority.discovery -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $references.test_inventory_discovery -Depth 6 -Compress)) {
            throw 'aggregate inventory baseline/discovery references differ from the independently revalidated Phase0 record'
        }
        Assert-D32Phase0FixtureManifestCorrelation -Phase0Document $phase0Document -FixtureManifestPath $FixtureManifestPath `
            -EvidenceRoot $phase0OutputRoot -AggregateReference $references.fixture_manifest
        Assert-D32Phase0FixtureBuildBudgetRecord -Document $phase0Document.fixture_build_budget -ExpectedPhase0TimeoutSeconds 14400
        $phase0ProfileRepository = Get-D32RustRepositoryPath -Path $repo
        $phase0Profile = Test-D32BuildToolchainProfile -ProfilePath ([string]$references.toolchain_profile.path) -ExpectedSha256 ([string]$references.toolchain_profile.sha256) -Repository $phase0ProfileRepository -EvidenceRoot $phase0OutputRoot
        if (-not $phase0Profile.IsValid) { throw "aggregate-referenced Phase0 caller-pinned profile is not current: $($phase0Profile.Failure)" }
        $aggregateInventoryAuthority = [ordered]@{
            baseline = $references.test_inventory_baseline
            discovery = $references.test_inventory_discovery
        }
        $null = Assert-D32PreflightTestInventoryBinding -Phase0Document $phase0Document -ExpectedAttestedAuthority $aggregateInventoryAuthority `
            -Repository $phase0ProfileRepository -Phase0OutputRoot $phase0OutputRoot -ValidatedProfile $phase0Profile
        if (-not (Test-D32Phase0ExactProperties -Object $phase0Document.evidence_root_identity -Expected @('path', 'volume_serial_hex', 'file_id_hex')) -or
            -not (Test-D32ProfilePathEqual -Left $phase0Document.evidence_root_identity.path -Right $phase0OutputRoot)) { throw 'aggregate-referenced Phase0 EvidenceRoot identity shape/path is invalid' }
        $phase0RootIdentity = Test-D32ProfileDirectoryIdentity -Path $phase0OutputRoot -VolumeSerialHex ([string]$phase0Document.evidence_root_identity.volume_serial_hex) -FileIdHex ([string]$phase0Document.evidence_root_identity.file_id_hex)
        $null = Test-D32Phase0FileReference -Reference $phase0Document.owner_marker -AllowedRoot $phase0OutputRoot
        $phase0Owner = Test-D32Phase0OwnerBinding -EvidenceRoot $phase0OutputRoot -ExpectedCandidateSha $ExpectedCandidateSha -ValidatedProfile $phase0Profile -ExpectedRunId ([string]$phase0Document.cargo_home.run_id) -ExpectedRootIdentity $phase0RootIdentity -ExpectedMarkerReference $phase0Document.owner_marker
        if (-not (Test-D32Phase0ExactProperties -Object $phase0Document.cargo_home -Expected @('path', 'temp_root', 'run_root', 'run_id', 'nonempty_after_fetch', 'run_root_identity', 'cargo_home_identity', 'temp_root_identity')) -or
            $phase0Document.cargo_home.run_id -cne $phase0Owner.RunId -or
            -not (Test-D32ProfilePathEqual -Left $phase0Document.cargo_home.run_root -Right (Join-Path $phase0OutputRoot 'r')) -or
            -not (Test-D32ProfilePathEqual -Left $phase0Document.cargo_home.path -Right (Join-Path $phase0OutputRoot 'r\c')) -or
            -not (Test-D32ProfilePathEqual -Left $phase0Document.cargo_home.temp_root -Right (Join-Path $phase0OutputRoot 'r\t'))) { throw 'aggregate-referenced Phase0 compact r\c and r\t owner/run binding is invalid' }
        $null = Test-D32PreflightPhase0VendoredProtocBinding `
            -Phase0Document $phase0Document -Repository $phase0ProfileRepository -OutputRoot $phase0OutputRoot `
            -CandidateSha $ExpectedCandidateSha -ValidatedProfile $phase0Profile
        Add-D32Finding -Findings $Findings -Severity PASS -Check 'aggregate.record' -Message "independently SHA-pinned pre-downstream aggregate record binds the validated local-scope pass, VERIFIED bundle hashes, NOT RUN downstream gates, this candidate, and all nine current external evidence references; record SHA-256=$($recordDigest.Hash)"
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
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings,
        [switch]$RequirePhase0BuildPolicy
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
        $phase0Policy = $timeout -is [ValueType] -and [double]$timeout -eq 28800 -and $jobs -is [ValueType] -and [double]$jobs -eq 4
        $standalonePolicy = $timeout -is [ValueType] -and [double]$timeout -eq 600 -and $jobs -is [ValueType] -and [double]$jobs -eq 1
        $policyInvalid = $nested -ne $false -or $action -cne $script:D32FixtureProcessTreePolicy -or
            ($RequirePhase0BuildPolicy -and -not $phase0Policy) -or
            (-not $RequirePhase0BuildPolicy -and -not ($phase0Policy -or $standalonePolicy))
        if ($policyInvalid) {
            $expectedPolicy = if ($RequirePhase0BuildPolicy) { 'exact owner-bound Phase0 jobs=4/timeout_seconds=28800' } else { 'exact standalone jobs=1/timeout_seconds=600 or owner-bound Phase0 jobs=4/timeout_seconds=28800' }
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'fixture-manifest.policy' -Message "bounded existing-only build policy must be $expectedPolicy"
        }
        else {
            $validatedPolicy = if ($phase0Policy) { 'owner-bound Phase0 jobs=4/timeout_seconds=28800' } else { 'non-Phase0 standalone jobs=1/timeout_seconds=600; not Phase0 evidence' }
            Add-D32Finding -Findings $Findings -Severity PASS -Check 'fixture-manifest.policy' -Message "fixed fixture manifest policy validates exact $validatedPolicy"
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
    $phase0Validation = $null
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
    if ($hasAnyPhase0Pin) {
        if ($null -eq $phase0Validation -or -not $phase0Validation.IsValid) {
            Add-D32Finding -Findings $findings -Severity ERROR -Check 'fixture-manifest.phase0-binding' -Message 'Phase0-bound fixture-manifest validation requires a fully validated caller-pinned Phase0 record'
        }
        else {
            try {
                Assert-D32Phase0FixtureManifestCorrelation -Phase0Document $phase0Validation.Record -FixtureManifestPath $FixtureManifest `
                    -EvidenceRoot $phase0Validation.OutputRoot -AggregateReference $null
                Add-D32Finding -Findings $findings -Severity PASS -Check 'fixture-manifest.phase0-binding' -Message 'fixture manifest path and current opened-file identity exactly match the validated Phase0 record'
            }
            catch {
                Add-D32Finding -Findings $findings -Severity ERROR -Check 'fixture-manifest.phase0-binding' -Message $_.Exception.Message
            }
        }
    }
    Test-D32FixtureManifest -FixtureManifest $fixtureManifestObject -FixtureManifestPath $FixtureManifest -Head $head -Repository $Repository -Findings $findings -RequirePhase0BuildPolicy:$hasAnyPhase0Pin

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
        Phase0RecordSnapshot = if ($null -ne $phase0Validation -and $phase0Validation.IsValid) { $phase0Validation.Identity } else { $null }
        Phase0Record = if ($null -ne $phase0Validation -and $phase0Validation.IsValid) { $phase0Validation.Record } else { $null }
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
        Assert-D32PostBundleAggregateExternalSources -Paths @($Manifest, $FixtureManifest, $Phase0RecordPath, $ToolchainProfilePath, $TrustedGitPath) -Repository $repo

        $validation = Invoke-D32Validation -Repository $repo -Manifest $Manifest -Image $Image -BundleManifest $BundleManifest -AttestationPath $AttestationPath -FixtureManifest $FixtureManifest -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -ExpectedCandidateSha $ExpectedCandidateSha -Base $null -MergeBase $null -RunRoot $null -Modes $script:D32CanonicalModes -Phase0RecordPath $Phase0RecordPath -Phase0RecordSha256 $Phase0RecordSha256 -ToolchainProfilePath $ToolchainProfilePath -ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256
        if ($null -eq $validation.Phase0RecordSnapshot) { throw 'aggregate generation did not retain the validated Phase0 record opened-byte/identity snapshot' }
        foreach ($finding in $validation.Findings) { [void]$findings.Add($finding) }
        $readyFindings = New-D32FindingList
        $ready = Test-D32PostBundleAggregateReadiness -Validation $validation -Findings $readyFindings
        foreach ($finding in $readyFindings) { [void]$findings.Add($finding) }
        if (-not $ready -or @($findings | Where-Object { $_.Severity -eq 'ERROR' }).Count -gt 0) {
            return [PSCustomObject]@{ Success = $false; Status = 'BLOCKED'; Findings = $findings; SecurityClassification = $classification }
        }

        $phase0Reference = New-D32PostBundleAggregateFileReference -Path $Phase0RecordPath -Repository $repo
        if (-not (Test-D32ProfilePathEqual -Left ([string]$phase0Reference.path) -Right ([string]$validation.Phase0RecordSnapshot.Path)) -or
            [Int64]$phase0Reference.bytes -ne [Int64]$validation.Phase0RecordSnapshot.Bytes -or
            [string]$phase0Reference.sha256 -cne [string]$validation.Phase0RecordSnapshot.Sha256 -or
            [string]$phase0Reference.volume_serial_hex -cne [string]$validation.Phase0RecordSnapshot.VolumeSerialHex -or
            [string]$phase0Reference.file_id_hex -cne [string]$validation.Phase0RecordSnapshot.FileIdHex) {
            throw 'Phase0 aggregate reference changed after the full caller-pinned Phase0 validation snapshot'
        }
        $phase0InventoryAuthority = $validation.Phase0Record.test_inventory_authority
        if (-not (Test-D32Phase0ExactProperties -Object $phase0InventoryAuthority -Expected @('baseline', 'discovery'))) {
            throw 'validated Phase0 record omitted its strict inventory baseline/discovery authority references'
        }
        $baselineReference = New-D32PostBundleAggregateFileReference -Path ([string]$phase0InventoryAuthority.baseline.path) -Repository $repo
        $discoveryReference = New-D32PostBundleAggregateFileReference -Path ([string]$phase0InventoryAuthority.discovery.path) -Repository $repo
        if ((ConvertTo-Json -InputObject $baselineReference -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $phase0InventoryAuthority.baseline -Depth 6 -Compress) -or
            (ConvertTo-Json -InputObject $discoveryReference -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $phase0InventoryAuthority.discovery -Depth 6 -Compress)) {
            throw 'inventory baseline/discovery bytes or opened identities changed after full Phase0 validation'
        }
        $references = [ordered]@{
            phase0_matrix = $phase0Reference
            toolchain_profile = New-D32PostBundleAggregateFileReference -Path $ToolchainProfilePath -Repository $repo
            fixture_manifest = New-D32PostBundleAggregateFileReference -Path $FixtureManifest -Repository $repo
            provenance_manifest = New-D32PostBundleAggregateFileReference -Path $Manifest -Repository $repo
            bundle_manifest = New-D32PostBundleAggregateFileReference -Path $BundleManifest -Repository $repo
            attestation = New-D32PostBundleAggregateFileReference -Path $AttestationPath -Repository $repo
            trusted_git = New-D32PostBundleAggregateFileReference -Path $TrustedGitPath -Repository $repo
            test_inventory_baseline = $baselineReference
            test_inventory_discovery = $discoveryReference
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
            powershell_module_admission = $global:D32PowerShellModuleAuthorityState.Admission
        }
        Write-D32JsonCreateNew -Path $expectedRecord -Value $document
        $recordDigest = Get-D32EvidenceFileDigest -Path $expectedRecord
        if ($null -eq $recordDigest) { throw 'created post-bundle aggregate record is not a stable regular external file' }
        $reopenedFindings = New-D32FindingList
        $reopened = Test-D32PostBundleAggregateRecord -RecordPath $expectedRecord -ExpectedRecordSha256 $recordDigest.Hash -Repository $repo -ExpectedCandidateSha $ExpectedCandidateSha -ValidatedPhase0Snapshot $validation.Phase0RecordSnapshot -EvidenceRoot $evidence -Phase0RecordPath $Phase0RecordPath -ToolchainProfilePath $ToolchainProfilePath -FixtureManifestPath $FixtureManifest -ManifestPath $Manifest -BundleManifestPath $BundleManifest -AttestationPath $AttestationPath -TrustedGitPath $TrustedGitPath -Findings $reopenedFindings
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
            $result = Invoke-D32Phase0PinnedProcess -Name $fixedCommand.name -Executable $cargoPath -Arguments $fixedCommand.arguments -WorkingDirectory $repoCanonical -LogPath (Join-Path $releaseLogRoot ('release-{0:D2}-{1}' -f ($commandIndex + 1), $fixedCommand.name)) -Environment $cargoEnvironment -TimeoutSeconds 7200 -ValidatedProfile $toolchainProfileValidation -Repository $repoCanonical -ExpectedCandidateSha $ExpectedCandidateSha -GitPath $TrustedGitPath -GitSha256 $TrustedGitSha256 -VendoredProtocRunGrant $phase0Validation.VendoredGrant
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
            attestation_type = 'D32_RELEASE_BUILD_ATTESTATION_V9'
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
            powershell_module_admission = $global:D32PowerShellModuleAuthorityState.Admission
            test_inventory_authority = $phase0Validation.Record.test_inventory_authority
            phase0_matrix = [ordered]@{
                path = $phase0Validation.RecordPath
                sha256 = $phase0Validation.Digest
                bytes = [Int64]$phase0Validation.Identity.Bytes
                volume_serial_hex = [string]$phase0Validation.Identity.VolumeSerialHex
                file_id_hex = [string]$phase0Validation.Identity.FileIdHex
                candidate_sha = $ExpectedCandidateSha
                status = 'PASS'
            }
            vendored_protoc = $phase0Validation.Record.vendored_protoc
            tauri_macros_source_patch = $phase0Validation.Record.tauri_macros_source_patch
            h7c_git_child_authority = $phase0Validation.Record.h7c_git_child_authority
            h7c_git_child_attestation = $phase0Validation.Record.h7c_git_child_attestation
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
        $candidateVendorRoot = Join-Path $candidateRepository 'src-tauri\vendor\tauri-macros-2.6.3'
        $fixtureVendorRoot = Join-Path $fixture 'src-tauri\vendor\tauri-macros-2.6.3'
        if (-not (Test-D32ProfileNoReparsePath -Path $candidateVendorRoot) -or (Test-Path -LiteralPath $fixtureVendorRoot)) {
            throw 'self-test fixture cannot bind the exact candidate-local tauri-macros source tree'
        }
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $fixtureVendorRoot))
        Copy-Item -LiteralPath $candidateVendorRoot -Destination $fixtureVendorRoot -Recurse -Force
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
                timeout_seconds = 28800
                cargo_build_jobs = 4
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
        $phase0ProfileEvidenceRoot = Join-Path $root 'profile-evidence'
        [void][System.IO.Directory]::CreateDirectory($phase0ProfileEvidenceRoot)
        $phase0ProfileValidation = Test-D32BuildToolchainProfile -ProfilePath $profilePath -ExpectedSha256 $profileSnapshot.Sha256 -Repository $fixture -EvidenceRoot $phase0ProfileEvidenceRoot -ExpectedTargetTriple 'x86_64-pc-windows-msvc'
        if (-not $phase0ProfileValidation.IsValid) { throw "self-test toolchain profile is not valid for fixture repository: $($phase0ProfileValidation.Failure)" }
        $profileDocument = $profileValidation.Profile
        $fakeCargo = [string]$profileDocument.toolchain.cargo.path
        $fakeCargoDigest = Get-D32EvidenceFileDigest -Path $fakeCargo
        $phase0Root = Join-Path $root 'phase0'
        $phase0RunId = '0123456789abcdef0123456789abcdef'
        $phase0AuthorityPath = Join-Path $root 'D32-VENDORED-PROTOC-AUTHORITY.json'
        $phase0AuthorityDocument = New-D32VendoredProtocAuthorityDocument -Repository $fixture -CandidateSha $head -ValidatedProfile $phase0ProfileValidation -EvidenceRoot $phase0Root
        $phase0AuthorityReference = Write-D32VendoredProtocAuthorityCreateNew -Path $phase0AuthorityPath -Document $phase0AuthorityDocument
        $phase0Binding = New-D32Phase0FixtureOutputRoot -Path $phase0Root -Repository $fixture -ExpectedCandidateSha $head -ValidatedProfile $phase0ProfileValidation -RunId $phase0RunId
        $phase0RunRoot = Join-Path $phase0Root 'r'
        $phase0CargoHome = Join-Path $phase0RunRoot 'c'
        $phase0TempRoot = Join-Path $phase0RunRoot 't'
        $phase0RunRootIdentity = New-D32ProfileDirectoryCreateNew -Path $phase0RunRoot
        $phase0CargoHomeIdentity = New-D32ProfileDirectoryCreateNew -Path $phase0CargoHome
        $phase0TempRootIdentity = New-D32ProfileDirectoryCreateNew -Path $phase0TempRoot
        [System.IO.File]::WriteAllText((Join-Path $phase0CargoHome 'selftest-cache-marker'), 'fetched locked sources')
        $archiveSourceCandidates = @()
        if (-not [String]::IsNullOrWhiteSpace($env:USERPROFILE)) {
            $archiveSourceCandidates += Join-Path (Join-Path $env:USERPROFILE '.cargo') $script:D32VendoredProtocArchiveRelativePath
        }
        $archiveSourcePath = $null
        foreach ($archiveCandidate in $archiveSourceCandidates) {
            if (-not (Test-D32ProfileNoReparsePath -Path $archiveCandidate)) { continue }
            $archiveCandidateSnapshot = Get-D32ProfileFileSnapshot -Path $archiveCandidate
            if ($archiveCandidateSnapshot.Bytes -eq $script:D32VendoredProtocArchiveBytes -and $archiveCandidateSnapshot.Sha256 -ceq $script:D32VendoredProtocWin32Checksum) {
                $archiveSourcePath = [string]$archiveCandidateSnapshot.Path
                break
            }
        }
        if ([String]::IsNullOrWhiteSpace($archiveSourcePath)) { throw 'self-test requires a read-only local copy of the exact locked protoc archive; no user Cargo cache bytes were changed' }
        $phase0ArchivePath = Join-Path $phase0CargoHome $script:D32VendoredProtocArchiveRelativePath
        [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $phase0ArchivePath))
        [System.IO.File]::Copy($archiveSourcePath, $phase0ArchivePath)
        $phase0VendoredGrant = New-D32VendoredProtocRunGrant -AuthorityPath $phase0AuthorityPath -AuthoritySha256 ([string]$phase0AuthorityReference.sha256) `
            -Repository $fixture -CandidateSha $head -ValidatedProfile $phase0ProfileValidation -EvidenceRoot $phase0Root `
            -OwnerMarkerReference $phase0Binding.OwnerMarker -RunId $phase0RunId -CargoHome $phase0CargoHome
        $tauriArchivePath = $null
        if (-not [String]::IsNullOrWhiteSpace($env:USERPROFILE)) {
            $tauriArchiveCandidate = Join-Path (Join-Path $env:USERPROFILE '.cargo\registry\cache\index.crates.io-1949cf8c6b5b557f') 'tauri-macros-2.6.3.crate'
            if (Test-D32ProfileNoReparsePath -Path $tauriArchiveCandidate) { $tauriArchivePath = [IO.Path]::GetFullPath($tauriArchiveCandidate) }
        }
        $tauriAttesterPath = Join-Path $PSScriptRoot 'd32-tauri-macros-source-attestation.ps1'
        if ([String]::IsNullOrWhiteSpace($tauriArchivePath) -or -not (Test-D32ProfileNoReparsePath -Path $tauriAttesterPath)) {
            throw 'self-test requires the read-only exact tauri-macros archive and source-patch facts generator'
        }
        $tauriSourceFactsLines = @(& $tauriAttesterPath -ArchivePath $tauriArchivePath -CandidateSha $head `
            -ToolchainProfilePath $phase0ProfileValidation.ProfilePath -ExpectedToolchainProfileSha256 $phase0ProfileValidation.Digest `
            -Repository $fixture -PowerShellModuleAuthorityPath $PowerShellModuleAuthorityPath `
            -ExpectedPowerShellModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
            -PinnedGitPath $trustedGitPath -PinnedGitSha256 $trustedGitSha256)
        if ($tauriSourceFactsLines.Count -ne 1 -or $tauriSourceFactsLines[0] -isnot [string]) {
            throw 'self-test source-patch facts generator did not emit exactly one JSON document'
        }
        $tauriSourceFacts = ConvertFrom-D32Phase0Json -Json ([string]$tauriSourceFactsLines[0])
        $tauriSourceAuthorityPath = Join-Path $root 'D32-TAURI-MACROS-SOURCE-PATCH-AUTHORITY.json'
        $tauriSourceAuthorityReference = Write-D32VendoredProtocAuthorityCreateNew -Path $tauriSourceAuthorityPath -Document $tauriSourceFacts
        $sourcePatchAuthority = Test-D32TauriMacrosSourcePatchAuthority -AuthorityPath $tauriSourceAuthorityPath `
            -ExpectedAuthoritySha256 ([string]$tauriSourceAuthorityReference.sha256) -Repository $fixture -CandidateSha $head `
            -ValidatedProfile $phase0ProfileValidation -EvidenceRoot $phase0Root
        $h7GitImage = Get-D32ProfileFileSnapshot -Path $trustedGitPath
        $h7AuthorityPath = Join-Path $root 'D32-H7C-GIT-CHILD-AUTHORITY.json'
        $h7AuthorityDocument = Get-D32H7CGitAuthorityTemplate -Repository $fixture -CandidateSha $head -ValidatedProfile $phase0ProfileValidation `
            -EvidenceRoot $phase0Root -TempRoot $phase0TempRoot -GitImage $h7GitImage -TimeoutSeconds 14400
        $h7AuthorityReference = Write-D32H7CGitJsonCreateNew -Path $h7AuthorityPath -Document $h7AuthorityDocument
        $h7Authority = Test-D32H7CGitAuthority -AuthorityPath $h7AuthorityPath -ExpectedAuthoritySha256 ([string]$h7AuthorityReference.sha256) `
            -Repository $fixture -CandidateSha $head -ValidatedProfile $phase0ProfileValidation -EvidenceRoot $phase0Root `
            -TempRoot $phase0TempRoot -GitImage $h7GitImage -TimeoutSeconds 14400
        $h7OwnerBinding = Test-D32Phase0OwnerBinding -EvidenceRoot $phase0Root -ExpectedCandidateSha $head -ValidatedProfile $phase0ProfileValidation `
            -ExpectedRunId $phase0RunId -ExpectedRootIdentity $phase0Binding.RootIdentity -ExpectedMarkerReference $phase0Binding.OwnerMarker
        $h7RunGrant = New-D32H7CGitRunGrant -Authority $h7Authority -Repository $fixture -CandidateSha $head -ValidatedProfile $phase0ProfileValidation `
            -EvidenceRoot $phase0Root -TempRoot $phase0TempRoot -RunId $phase0RunId -OwnerMarker $h7OwnerBinding.MarkerReference -GitImage $h7GitImage
        $inventoryArtifacts = New-D32PreflightSelfTestInventoryAuthorityArtifacts -Root $root -Repository $fixture -CandidateSha $head `
            -ValidatedProfile $phase0ProfileValidation -PinnedGitPath $trustedGitPath -PinnedGitSha256 $trustedGitHash `
            -ArchiveSourcePath $archiveSourcePath -SourcePatchAuthority $sourcePatchAuthority
        $discoverySchemaMutationFailures = @($inventoryArtifacts.DiscoverySchemaMutationResults | Where-Object { -not $_.Rejected })
        Assert-D32SelfTest -Condition ($inventoryArtifacts.DiscoverySchemaMutationResults.Count -eq 2 -and $discoverySchemaMutationFailures.Count -eq 0) `
            -Name 'discovery reader rejects prior and unknown schema versions even when each mutated record is correctly rehashed' -Failures $failures
        $discoveryReferenceMutationFailures = @($inventoryArtifacts.DiscoveryReferenceMutationResults | Where-Object { -not $_.Rejected })
        Assert-D32SelfTest -Condition ($inventoryArtifacts.DiscoveryReferenceMutationResults.Count -eq 2 -and $discoveryReferenceMutationFailures.Count -eq 0) `
            -Name 'discovery reader rejects rehashed stale source-authority opened identity and extra reference fields' -Failures $failures
        $discoveryTimestampMutationFailures = @($inventoryArtifacts.DiscoveryTimestampMutationResults | Where-Object { -not $_.Rejected })
        Assert-D32SelfTest -Condition ($inventoryArtifacts.DiscoveryTimestampMutationResults.Count -eq 4 -and $discoveryTimestampMutationFailures.Count -eq 0) `
            -Name 'discovery reader rejects rehashed invalid top-level interval, out-of-order fetch/list commands, and commands outside interval' -Failures $failures
        Assert-D32SelfTest -Condition $inventoryArtifacts.NestedPhase0RootRejectedWithoutCreation `
            -Name 'formal Phase0 EvidenceRoot nested beneath discovery is rejected before the root is created' -Failures $failures
        Assert-D32SelfTest -Condition ($inventoryArtifacts.ProtocolProtocTraceAcceptedWithGrant -and $inventoryArtifacts.ProtocolProtocTraceRejectedWithoutGrant) `
            -Name 'protocol inventory trace with the canonical pinned protoc identity passes only with its package-scoped grant and rejects without it' -Failures $failures
        $baselineMutationFailures = @($inventoryArtifacts.BaselineMutationResults | Where-Object { -not $_.Rejected })
        Assert-D32SelfTest -Condition ($inventoryArtifacts.BaselineMutationResults.Count -eq 15 -and $baselineMutationFailures.Count -eq 0) `
            -Name 'Coordinator baseline rejects prior/unknown/self-pinned, stale bindings, wrong budget, ordinary set drift, completion mismatch, and invalid generated timestamps' -Failures $failures
        Assert-D32SelfTest -Condition $inventoryArtifacts.LateBaselineRejected `
            -Name 'baseline placed inside the eventual Phase0 EvidenceRoot is rejected as late and cannot self-baseline' -Failures $failures
        $phase0LogRoot = Join-Path $phase0Root 'logs'
        $null = New-D32ProfileDirectoryCreateNew -Path $phase0LogRoot
        $h7SuiteStdoutPath = Join-Path $phase0LogRoot 'vita-full-local-suite.stdout.log'
        $h7SuiteStderrPath = Join-Path $phase0LogRoot 'vita-full-local-suite.stderr.log'
        $h7SuiteLines = [System.Collections.Generic.List[string]]::new()
        foreach ($line in @(New-D32PreflightSelfTestSuiteLines -Package 'vita' -Entries @($inventoryArtifacts.Baseline.entries))) { $h7SuiteLines.Add([string]$line) }
        [IO.File]::WriteAllLines($h7SuiteStdoutPath, $h7SuiteLines.ToArray(), [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($h7SuiteStderrPath, '', [Text.UTF8Encoding]::new($false))
        $h7SuiteArgs = @(Get-D32Phase0TestCommand -Package 'vita' -Kind 'suite')
        $h7SuiteTrace = New-D32Phase0SelfTestDebugTrace -Profile $phase0ProfileValidation -RunnerProcessId ([int]$PID) -RootProcessId 30099
        $h7SuiteRootTrace = @($h7SuiteTrace.processes | Where-Object { $_.create_sequence -eq 1 })[0]
        $h7SuiteCommandLine = ConvertTo-D32Phase0CommandLine -Arguments (@([string]$phase0ProfileValidation.Profile.toolchain.cargo.path) + $h7SuiteArgs)
        $h7SuiteRootProxy = [PSCustomObject]@{
            process_id = [int]$h7SuiteRootTrace.process_id
            parent_process_id = [int]$h7SuiteRootTrace.parent_process_id
            name = [IO.Path]::GetFileName([string]$phase0ProfileValidation.Profile.toolchain.cargo.path)
            image_path = [string]$phase0ProfileValidation.Profile.toolchain.cargo.path
            command_line = $h7SuiteCommandLine
            creation_date = [DateTime]::FromFileTimeUtc([Int64]$h7SuiteRootTrace.creation_filetime).ToString('o')
            observed_at_utc = [string]$h7SuiteRootTrace.created_at_utc
        }
        $h7SuiteRootRecord = ConvertTo-D32Phase0ProcessRecord -Process $h7SuiteRootProxy -ValidatedProfile $phase0ProfileValidation `
            -Repository $fixture -ExpectedRootPath ([string]$phase0ProfileValidation.Profile.toolchain.cargo.path) `
            -VendoredProtocGrant $phase0VendoredGrant -H7CGitRunGrant $h7RunGrant
        $h7SuiteCommand = [PSCustomObject][ordered]@{
            name = 'vita-full-local-suite'
            timeout_seconds = [Int64]14400
            executable = [string]$phase0ProfileValidation.Profile.toolchain.cargo.path
            executable_sha256 = [string]$phase0ProfileValidation.Profile.toolchain.cargo.sha256
            executable_bytes = [Int64]$phase0ProfileValidation.Profile.toolchain.cargo.bytes
            executable_volume_serial_hex = [string]$phase0ProfileValidation.Profile.toolchain.cargo.volume_serial_hex
            executable_file_id_hex = [string]$phase0ProfileValidation.Profile.toolchain.cargo.file_id_hex
            arguments = $h7SuiteArgs
            argv = @([string]$phase0ProfileValidation.Profile.toolchain.cargo.path) + $h7SuiteArgs
            command_line = $h7SuiteCommandLine
            working_directory = [IO.Path]::GetFullPath($fixture)
            candidate_sha_before = $head
            clean_before = $true
            started_at_utc = [string]$h7SuiteTrace.started_at_utc
            completed_at_utc = [string]$h7SuiteTrace.completed_at_utc
            exit_code = 0
            root_process = $h7SuiteRootRecord
            descendant_processes = @()
            process_trace = $h7SuiteTrace
            process_tree_cleanup = [ordered]@{
                launch_mode = 'DedicatedOSDebuggerThread(CreateProcessW(DEBUG_PROCESS|CREATE_SUSPENDED)+DebugSetProcessKillOnExit(TRUE)+ResumeThread+WaitForDebugEvent+ContinueDebugEvent)+EXTENDED_STARTUP_INFO+HANDLE_LIST(stdout/stderr)+AssignProcessToJobObject(KILL_ON_JOB_CLOSE)'
                job_close_succeeded = $true
                process_wait_signaled = $true
                active_process_count_verified = $true
                active_process_count = [uint32]0
                debugger_thread_id = [uint32]$h7SuiteTrace.debugger_thread_id
                debugger_thread_exited = $true
                debugger_thread_joined = $true
                debugger_kill_on_exit_enabled = $true
                retained_process_handle_count = [int]$h7SuiteTrace.retained_process_handle_count
                retained_process_handles_signaled = $true
                debugger_association_query_verified = $true
                debugger_association_absent = $true
                cleanup_succeeded = $true
                detail = 'synthetic no-Cargo selftest: debugger thread joined; handles signaled; debugger association absent; Job ActiveProcesses=0'
            }
            stdout = Get-D32Phase0FileReference -Path $h7SuiteStdoutPath
            stderr = Get-D32Phase0FileReference -Path $h7SuiteStderrPath
            candidate_sha_after = $head
            clean_after = $true
        }
        $null = Test-D32Phase0DebugProcessTrace -Trace $h7SuiteTrace -ExpectedRootPath ([string]$phase0ProfileValidation.Profile.toolchain.cargo.path) `
            -ExpectedRootIdentity $phase0ProfileValidation.Profile.toolchain.cargo -ExpectedParentProcessId ([int]$PID) `
            -ValidatedProfile $phase0ProfileValidation -Repository $fixture -VendoredProtocGrant $phase0VendoredGrant `
            -H7CGitAuthority $h7Authority -H7CGitRunGrant $h7RunGrant
        $h7Attestation = New-D32H7CGitChildAttestation -Authority $h7Authority -RunGrant $h7RunGrant -OwnerBinding $h7OwnerBinding `
            -Phase0Command $h7SuiteCommand -SuiteLines $h7SuiteLines.ToArray() -GitChildren @() -Repository $fixture -CandidateSha $head `
            -ValidatedProfile $phase0ProfileValidation -EvidenceRoot $phase0Root -TempRoot $phase0TempRoot -GitImage $h7GitImage
        $phase0ToolProfile = [ordered]@{
            path = $phase0ProfileValidation.ProfilePath
            sha256 = $phase0ProfileValidation.Digest
            file_identity = [ordered]@{
                bytes = [Int64]$phase0ProfileValidation.Identity.Bytes
                volume_serial_hex = [string]$phase0ProfileValidation.Identity.VolumeSerialHex
                file_id_hex = [string]$phase0ProfileValidation.Identity.FileIdHex
            }
            target_triple = $phase0ProfileValidation.Profile.target_triple
            toolchain = $phase0ProfileValidation.Profile.toolchain
            executable_inventory = @($phase0ProfileValidation.ExecutableInventory | ForEach-Object {
                    [ordered]@{
                        path = $_.Path
                        sha256 = $_.Sha256
                        bytes = [Int64]$_.Bytes
                        volume_serial_hex = $_.VolumeSerialHex
                        file_id_hex = $_.FileIdHex
                    }
                })
            script_inventory = @($phase0ProfileValidation.ScriptInventory | ForEach-Object {
                    [ordered]@{
                        path = $_.Path
                        sha256 = $_.Sha256
                        bytes = [Int64]$_.Bytes
                        volume_serial_hex = $_.VolumeSerialHex
                        file_id_hex = $_.FileIdHex
                    }
                })
            windows_image_inventory = @($phase0ProfileValidation.WindowsImageInventory | ForEach-Object {
                    [ordered]@{
                        path = $_.Path
                        sha256 = $_.Sha256
                        bytes = [Int64]$_.Bytes
                        volume_serial_hex = $_.VolumeSerialHex
                        file_id_hex = $_.FileIdHex
                    }
                })
            lock_inputs = @($phase0ProfileValidation.LockInputs | ForEach-Object { [ordered]@{ manifest_path = $_.ManifestPath; lock_sha256 = $_.LockSha256 } })
            env_policy = $phase0ProfileValidation.Profile.env_policy
        }
        $phase0TraceEntries = [System.Collections.Generic.List[object]]::new()
        $phase0FetchRecords = [System.Collections.Generic.List[object]]::new()
        $phase0TraceIndex = 0
        foreach ($lockInput in $phase0ProfileValidation.LockInputs) {
            $phase0TraceIndex++
            $traceName = 'fixture-{0:D2}-fetch' -f $phase0TraceIndex
            $rootProcessId = 30000 + $phase0TraceIndex
            $arguments = @('fetch', '--locked', '--manifest-path', [string]$lockInput.ManifestFullPath, '--target', [string]$phase0ProfileValidation.Profile.target_triple)
            $trace = New-D32Phase0SelfTestDebugTrace -Profile $phase0ProfileValidation -RunnerProcessId ([int]$PID) -RootProcessId $rootProcessId
            $rootProcess = $trace.processes[0]
            $commandLine = ConvertTo-D32Phase0CommandLine -Arguments (@([string]$fakeCargo) + $arguments)
            $phase0TraceEntries.Add([ordered]@{
                    name = $traceName
                    executable = [string]$fakeCargo
                    arguments = $arguments
                    command_line = $commandLine
                    working_directory = [IO.Path]::GetFullPath($fixture)
                    process_trace = $trace
                })
            $phase0FetchRecords.Add([ordered]@{
                    manifest_path = [string]$lockInput.ManifestPath
                    lock_sha256 = [string]$lockInput.LockSha256
                    command = $arguments
                    status = 'succeeded'
                    exit_code = 0
                    process_identity = [ordered]@{
                        process_id = $rootProcessId
                        parent_process_id = [int]$PID
                        name = 'cargo.exe'
                        image_path = [string]$fakeCargo
                        creation_date = [DateTime]::FromFileTimeUtc([Int64]$rootProcess.creation_filetime).ToString('o')
                        command_line = $commandLine
                        observed_at_utc = [string]$rootProcess.created_at_utc
                        identity_verified = $true
                    }
                })
        }
        foreach ($fixtureSpec in $script:D32Phase0FixtureBuildSpecs) {
            $phase0TraceIndex++
            $rootProcessId = 30000 + $phase0TraceIndex
            $manifestPath = [IO.Path]::GetFullPath((Join-Path $fixture ([string]$fixtureSpec.manifest)))
            $arguments = @('build', '--quiet', '--locked', '--manifest-path', $manifestPath, '--bin', [string]$fixtureSpec.binary)
            if (@($fixtureSpec.features).Count -gt 0) { $arguments += @('--features', (@($fixtureSpec.features) -join ' ')) }
            $arguments += @('--jobs', '4')
            $trace = New-D32Phase0SelfTestDebugTrace -Profile $phase0ProfileValidation -RunnerProcessId ([int]$PID) -RootProcessId $rootProcessId
            $phase0TraceEntries.Add([ordered]@{
                    name = [string]$fixtureSpec.name
                    executable = [string]$fakeCargo
                    arguments = $arguments
                    command_line = ConvertTo-D32Phase0CommandLine -Arguments (@([string]$fakeCargo) + $arguments)
                    working_directory = [IO.Path]::GetFullPath($fixture)
                    process_trace = $trace
                })
        }
        $phase0FixtureBuildBudget = [ordered]@{
            schema_version = 1
            record_type = 'D32_PHASE0_FIXTURE_BUILD_BUDGET_V1'
            phase0_command_timeout_seconds = 14400
            fixture_build_timeout_seconds = 28800
            cargo_build_jobs = 4
            logical_processor_count = 8
            available_physical_memory_bytes = 12L * 1024L * 1024L * 1024L
            evidence_volume_free_bytes = 200L * 1024L * 1024L * 1024L
            competing_target_writer_count = 0
            target_writer_check = 'Win32-CIM-active-build-process-census'
            checked_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        }
        Assert-D32Phase0FixtureBuildBudgetRecord -Document $phase0FixtureBuildBudget
        $phase0FixtureProvenancePath = Join-Path $phase0Root 'fixture-build-provenance.json'
        $phase0FixtureManifestPath = Join-Path $phase0Root 'fixture-manifest.json'
        [System.IO.File]::Copy($fixtureManifest, $phase0FixtureManifestPath)
        $fixtureManifestSnapshot = Get-D32ProfileFileSnapshot -Path $phase0FixtureManifestPath
        $phase0FixtureProvenanceDocument = [ordered]@{
            schema_version = 7
            record_type = 'D32_FIXTURE_BUILD_PROVENANCE_V7'
            candidate_sha = $head
            source_repo = [IO.Path]::GetFullPath($fixture)
            fixture_manifest_path = [string]$fixtureManifestSnapshot.Path
            fixture_manifest_sha256 = [string]$fixtureManifestSnapshot.Sha256
            fixture_manifest_bytes = [Int64]$fixtureManifestSnapshot.Bytes
            fixture_manifest_volume_serial_hex = [string]$fixtureManifestSnapshot.VolumeSerialHex
            fixture_manifest_file_id_hex = [string]$fixtureManifestSnapshot.FileIdHex
            environment = [ordered]@{
                toolchain_profile_path = [string]$phase0ProfileValidation.ProfilePath
                toolchain_profile_sha256 = [string]$phase0ProfileValidation.Digest
                target_triple = [string]$phase0ProfileValidation.Profile.target_triple
                env_policy = [string]$phase0ProfileValidation.Profile.env_policy
                cargo_policy = [string]$phase0ProfileValidation.Profile.cargo_policy
                cargo_home = [IO.Path]::GetFullPath($phase0CargoHome)
                temp_root = [IO.Path]::GetFullPath($phase0TempRoot)
                run_id = $phase0RunId
                fetch_manifests = @($phase0FetchRecords.ToArray())
                offline_after_fetch = $true
            }
            storage = [ordered]@{
                evidence_root = [ordered]@{ path = [string]$phase0Binding.RootIdentity.Path; volume_serial_hex = [string]$phase0Binding.RootIdentity.VolumeSerialHex; file_id_hex = [string]$phase0Binding.RootIdentity.FileIdHex }
                owner_marker = $phase0Binding.OwnerMarker
                run_root = [ordered]@{ path = [IO.Path]::GetFullPath($phase0RunRoot); volume_serial_hex = [string]$phase0RunRootIdentity.VolumeSerialHex; file_id_hex = [string]$phase0RunRootIdentity.FileIdHex }
                cargo_home = [ordered]@{ path = [IO.Path]::GetFullPath($phase0CargoHome); volume_serial_hex = [string]$phase0CargoHomeIdentity.VolumeSerialHex; file_id_hex = [string]$phase0CargoHomeIdentity.FileIdHex }
                temp_root = [ordered]@{ path = [IO.Path]::GetFullPath($phase0TempRoot); volume_serial_hex = [string]$phase0TempRootIdentity.VolumeSerialHex; file_id_hex = [string]$phase0TempRootIdentity.FileIdHex }
                run_id = $phase0RunId
            }
            process_traces = @($phase0TraceEntries.ToArray())
            fixture_build_budget = $phase0FixtureBuildBudget
            vendored_protoc_run_grant = $phase0VendoredGrant.Reference
            tauri_macros_source_patch = $sourcePatchAuthority.Reference
        }
        Write-D32JsonCreateNew -Path $phase0FixtureProvenancePath -Value $phase0FixtureProvenanceDocument
        $phase0TranscriptPath = Join-Path $phase0Root 'fixture-prebuild.log'
        [System.IO.File]::WriteAllText($phase0TranscriptPath, '', [Text.UTF8Encoding]::new($false))
        $phase0FixtureSummary = [ordered]@{
            manifest = Get-D32Phase0FileReference -Path $phase0FixtureManifestPath
            build_provenance = Get-D32Phase0FileReference -Path $phase0FixtureProvenancePath
            transcript = Get-D32Phase0FileReference -Path $phase0TranscriptPath
            schema_version = 3
            process_tree_check = 'succeeded'
            fixture_names = @($script:D32Phase0FixtureBuildSpecs | ForEach-Object { [string]$_.name })
            fixture_records = @($fixtureDocument.fixtures)
            log_references = @()
            per_phase_git_states = @()
        }
        $phase0Inventories = @{}
        $phase0TestInventory = [ordered]@{}
        foreach ($package in @('protocol', 'vita', 'host')) {
            $entries = @($inventoryArtifacts.Baseline.entries | Where-Object { $_.package -ceq $package })
            $allRows = @($entries | ForEach-Object { [PSCustomObject][ordered]@{ package = [string]$_.package; kind = [string]$_.kind; full_name = [string]$_.full_name } })
            $ignoredRows = @($entries | Where-Object { $_.category -ceq 'ignored' } | ForEach-Object { [PSCustomObject][ordered]@{ package = [string]$_.package; kind = [string]$_.kind; full_name = [string]$_.full_name } })
            $testNames = @($entries | Where-Object { $_.kind -ceq 'test' } | ForEach-Object { [string]$_.full_name })
            $ignoredNames = @($entries | Where-Object { $_.category -ceq 'ignored' -and $_.kind -ceq 'test' } | ForEach-Object { [string]$_.full_name })
            $phase0Inventories[$package] = [PSCustomObject]@{ all = $testNames; ignored = $ignoredNames; test_names = $testNames }
            $phase0TestInventory[$package] = [ordered]@{
                all_rows = $allRows
                ignored_rows = $ignoredRows
                entries = $entries
                all_list_digest = Get-D32TestInventoryDigest -Rows $allRows
                ignored_list_digest = Get-D32TestInventoryDigest -Rows $ignoredRows
                test_names = $testNames
                ignored_names = $ignoredNames
                test_count = [Int64]$testNames.Count
                ignored_count = [Int64]$ignoredNames.Count
                benchmark_count = [Int64]@($entries | Where-Object { $_.kind -ceq 'benchmark' }).Count
            }
        }
        $phase0ExpectedPlan = @(Get-D32Phase0ExpectedCommandPlan -Profile $phase0ProfileValidation.Profile -Inventory $phase0Inventories)
        $phase0Commands = [System.Collections.Generic.List[object]]::new()
        $phase0LocalSuites = [System.Collections.Generic.List[object]]::new()
        $phase0FocusedTests = [System.Collections.Generic.List[object]]::new()
        for ($commandIndex = 0; $commandIndex -lt $phase0ExpectedPlan.Count; $commandIndex++) {
            $expectedCommand = $phase0ExpectedPlan[$commandIndex]
            if ($expectedCommand.name -ceq 'vita-full-local-suite') {
                $commandRecord = $h7SuiteCommand
                $suiteLines = @($h7SuiteLines.ToArray())
            }
            else {
                $stdoutLines = [System.Collections.Generic.List[string]]::new()
                if ($expectedCommand.name -ceq 'rustc-target-probe') {
                    foreach ($line in @('target_arch="x86_64"', 'target_os="windows"', 'target_env="msvc"')) { $stdoutLines.Add($line) }
                }
                elseif ($expectedCommand.name -match '^(protocol|vita|host)-(test-list|ignored-list)$') {
                    $sourceCommand = @($inventoryArtifacts.Discovery.inventory_commands | Where-Object { $_.command.name -ceq $expectedCommand.name })
                    if ($sourceCommand.Count -ne 1) { throw "preflight self-test cannot map pinned discovery list command $($expectedCommand.name)" }
                    foreach ($line in @(Read-D32TestInventoryLogReference -Reference $sourceCommand[0].command.stdout -AllowedRoot (Join-Path $root 'inventory-discovery'))) { $stdoutLines.Add([string]$line) }
                }
                elseif ($expectedCommand.name -match '^(protocol|host)-full-local-suite$') {
                    foreach ($line in @(New-D32PreflightSelfTestSuiteLines -Package ([string]$Matches[1]) -Entries @($inventoryArtifacts.Baseline.entries))) { $stdoutLines.Add([string]$line) }
                    $suiteLines = @($stdoutLines.ToArray())
                }
                elseif ($expectedCommand.name -match '^(vita|host)-focused-') {
                    $exactIndex = [Array]::IndexOf([string[]]$expectedCommand.arguments, '--exact')
                    if ($exactIndex -lt 0 -or $exactIndex + 1 -ge $expectedCommand.arguments.Count) { throw "preflight self-test fixed focused command lacks its exact test name: $($expectedCommand.name)" }
                    $fullName = [string]$expectedCommand.arguments[$exactIndex + 1]
                    $stdoutLines.Add('running 1 test')
                    $stdoutLines.Add("test $fullName ... ok")
                    $stdoutLines.Add('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s')
                }
                $commandRecord = New-D32PreflightSelfTestPhase0Command -Name ([string]$expectedCommand.name) -Repository $fixture -CandidateSha $head `
                    -ValidatedProfile $phase0ProfileValidation -LogRoot $phase0LogRoot -LogStem ('phase0-command-{0:D2}-{1}' -f ($commandIndex + 1), $expectedCommand.name) `
                    -Arguments @($expectedCommand.arguments) -TimeoutSeconds ([int]$expectedCommand.timeout_seconds) -StdoutLines @($stdoutLines.ToArray()) `
                    -Tool $(if (Test-D32ProfilePathEqual -Left $expectedCommand.executable -Right $phase0ProfileValidation.Profile.toolchain.rustc.path) { 'rustc' } else { 'cargo' }) `
                    -RootProcessId (43000 + $commandIndex)
                if ($expectedCommand.name -match '^(protocol|host)-full-local-suite$') { $suiteLines = @($stdoutLines.ToArray()) }
            }
            $phase0Commands.Add($commandRecord)
            if ($expectedCommand.name -match '^(protocol|vita|host)-full-local-suite$') {
                $package = [string]$Matches[1]
                $suiteEvidence = Assert-D32TestInventorySuiteRows -Package $package -BaselineEntries @($inventoryArtifacts.Baseline.entries) `
                    -Lines $suiteLines -ExpectedIgnored ([Int64]$inventoryArtifacts.Baseline.category_counts.$package.ignored) `
                    -ExpectedDeferred ([Int64]$inventoryArtifacts.Baseline.category_counts.$package.deferred)
                $phase0LocalSuites.Add([ordered]@{
                    package = $package
                    command = [string]$expectedCommand.name
                    status = 'PASS'
                    summary_count = [Int64]$suiteEvidence.Summaries.Count
                    counts = [ordered]@{ passed = [Int64]$suiteEvidence.Counts.passed; failed = [Int64]$suiteEvidence.Counts.failed; ignored = [Int64]$suiteEvidence.Counts.ignored; measured = [Int64]$suiteEvidence.Counts.measured; filtered_out = [Int64]$suiteEvidence.Counts.filtered_out }
                    exact_deferred_skip_count = [Int64]$inventoryArtifacts.Baseline.category_counts.$package.deferred
                })
            }
            elseif ($expectedCommand.name -match '^(vita|host)-focused-') {
                $package = [string]$Matches[1]
                $exactIndex = [Array]::IndexOf([string[]]$expectedCommand.arguments, '--exact')
                $fullName = [string]$expectedCommand.arguments[$exactIndex + 1]
                $phase0FocusedTests.Add([ordered]@{ package = $package; full_name = $fullName; command = [string]$expectedCommand.name; status = 'PASS'; passed = [Int64]1; failed = [Int64]0 })
            }
        }
        $phase0RecordPath = Join-Path $phase0Root 'D32-PHASE0-MATRIX.json'
        $phase0Started = [DateTimeOffset]::UtcNow.ToString('o')
        $phase0Document = [ordered]@{
            schema_version = 8
            record_type = 'D32_PHASE0_MATRIX_RECORD_V8'
            runner_process_id = [int]$PID
            candidate_sha = $head
            source_repo = [IO.Path]::GetFullPath($fixture)
            output_root = [IO.Path]::GetFullPath($phase0Root)
            evidence_root_identity = [ordered]@{ path = [string]$phase0Binding.RootIdentity.Path; volume_serial_hex = [string]$phase0Binding.RootIdentity.VolumeSerialHex; file_id_hex = [string]$phase0Binding.RootIdentity.FileIdHex }
            owner_marker = $phase0Binding.OwnerMarker
            vendored_protoc = [ordered]@{
                authority = $phase0AuthorityReference
                run_grant = $phase0VendoredGrant.Reference
            }
            tauri_macros_source_patch = $sourcePatchAuthority.Reference
            h7c_git_child_authority = $h7Authority.Reference
            h7c_git_child_attestation = $h7Attestation.Reference
            test_inventory_authority = [ordered]@{ baseline = $inventoryArtifacts.BaselineReference; discovery = $inventoryArtifacts.DiscoveryReference }
            powershell_module_admission = $global:D32PowerShellModuleAuthorityState.Admission
            status = 'PASS'
            bundle_hashes = 'PENDING'
            started_at_utc = $phase0Started
            completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            final_candidate_sha = $head
            final_clean = $true
            powershell = $profileValidation.Profile.powershell
            toolchain_profile = $phase0ToolProfile
            cargo_home = [ordered]@{
                path = [IO.Path]::GetFullPath($phase0CargoHome)
                temp_root = [IO.Path]::GetFullPath($phase0TempRoot)
                run_root = [IO.Path]::GetFullPath($phase0RunRoot)
                run_id = $phase0RunId
                nonempty_after_fetch = $true
                run_root_identity = [ordered]@{ volume_serial_hex = [string]$phase0RunRootIdentity.VolumeSerialHex; file_id_hex = [string]$phase0RunRootIdentity.FileIdHex }
                cargo_home_identity = [ordered]@{ volume_serial_hex = [string]$phase0CargoHomeIdentity.VolumeSerialHex; file_id_hex = [string]$phase0CargoHomeIdentity.FileIdHex }
                temp_root_identity = [ordered]@{ volume_serial_hex = [string]$phase0TempRootIdentity.VolumeSerialHex; file_id_hex = [string]$phase0TempRootIdentity.FileIdHex }
            }
            fixture_build_budget = $phase0FixtureBuildBudget
            fetches = @($phase0FetchRecords.ToArray())
            fixture = $phase0FixtureSummary
            commands = @($phase0Commands.ToArray())
            test_inventory = $phase0TestInventory
            local_suites = @($phase0LocalSuites.ToArray())
            focused_tests = @($phase0FocusedTests.ToArray())
            deferred_d31_tests = @()
            deferred_d29g2_provider_tests = @()
            not_run_capture_tests = @()
            governance_inputs = [ordered]@{}
            phase0_scope = 'local-fixture-and-test-matrix-only; no release build, D31 real process, provider, or hardware capture'
        }
        Write-D32JsonCreateNew -Path $phase0RecordPath -Value $phase0Document
        $phase0Snapshot = Get-D32ProfileFileSnapshot -Path $phase0RecordPath
        $phase0BudgetVariant = (ConvertTo-Json -InputObject $phase0Document -Depth 24 -Compress) | ConvertFrom-D32Json
        $phase0BudgetVariant.fixture_build_budget.cargo_build_jobs = 1
        Write-D32Json -Path $phase0RecordPath -Value $phase0BudgetVariant
        $phase0BudgetVariantSnapshot = Get-D32ProfileFileSnapshot -Path $phase0RecordPath
        $phase0BudgetVariantValidation = Test-D32Phase0MatrixRecord -RecordPath $phase0RecordPath -ExpectedRecordSha256 $phase0BudgetVariantSnapshot.Sha256 `
            -Repository $fixture -ExpectedCandidateSha $head -ToolchainProfilePath $profileSnapshot.Path -ExpectedToolchainProfileSha256 $profileSnapshot.Sha256 `
            -GitPath $trustedGitPath -GitSha256 $trustedGitHash
        Assert-D32SelfTest -Condition (-not $phase0BudgetVariantValidation.IsValid -and $phase0BudgetVariantValidation.Failure -like '*FIXTURE_BUILD_BUDGET_BLOCKED*') `
            -Name 'Phase0 reader rejects jobs=1 with a fresh exact record digest' -Failures $failures
        Write-D32Json -Path $phase0RecordPath -Value $phase0Document
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
            attestation_type = 'D32_RELEASE_BUILD_ATTESTATION_V9'
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
            powershell_module_admission = $global:D32PowerShellModuleAuthorityState.Admission
            phase0_matrix = $phase0Reference
            test_inventory_authority = $phase0Document.test_inventory_authority
            vendored_protoc = $phase0Document.vendored_protoc
            tauri_macros_source_patch = $phase0Document.tauri_macros_source_patch
            h7c_git_child_authority = $phase0Document.h7c_git_child_authority
            h7c_git_child_attestation = $phase0Document.h7c_git_child_attestation
            cargo_home = [ordered]@{
                path = [IO.Path]::GetFullPath($phase0CargoHome)
                temp_root = [IO.Path]::GetFullPath($phase0TempRoot)
                run_id = $phase0RunId
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
        $fixtureSummaryCases = @(
            [PSCustomObject]@{ Value = [int]3; Expected = $true; Name = 'current integer' },
            [PSCustomObject]@{ Value = '3'; Expected = $false; Name = 'JSON string' },
            [PSCustomObject]@{ Value = [int]2; Expected = $false; Name = 'prior integer' },
            [PSCustomObject]@{ Value = [int]4; Expected = $false; Name = 'unknown integer' }
        )
        $fixtureSummarySchemaCasesPassed = $true
        foreach ($fixtureSummaryCase in $fixtureSummaryCases) {
            $fixtureSummaryAccepted = $true
            try { Assert-D32Phase0FixtureSummarySchema -Fixture ([PSCustomObject]@{ schema_version = $fixtureSummaryCase.Value }) }
            catch { $fixtureSummaryAccepted = $false }
            if ($fixtureSummaryAccepted -ne [bool]$fixtureSummaryCase.Expected) { $fixtureSummarySchemaCasesPassed = $false }
        }
        Assert-D32SelfTest -Condition $fixtureSummarySchemaCasesPassed -Name 'Phase0 nested fixture summary requires current JSON integer schema and rejects string/prior/unknown versions' -Failures $failures
        $aggregateRecordPath = Join-Path $evidenceRoot $script:D32PostBundleAggregateRecordName
        $inRepositoryManifestPath = Join-Path $fixture 'src-tauri\Cargo.toml'
        $inRepositoryGeneratorResult = Invoke-D32GeneratePostBundleAggregateRecord -Repository $fixture -Manifest $inRepositoryManifestPath -Image $image `
            -BundleManifest $bundleManifest -AttestationPath $attestationPath -FixtureManifest $phase0FixtureManifestPath -EvidenceRoot $evidenceRoot `
            -RecordPath $aggregateRecordPath -ExpectedCandidateSha $head -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash `
            -Phase0RecordPath $phase0RecordPath -Phase0RecordSha256 $phase0Snapshot.Sha256 -ToolchainProfilePath $profilePath `
            -ExpectedToolchainProfileSha256 $profileSnapshot.Sha256
        $inRepositorySourceRejected = @($inRepositoryGeneratorResult.Findings | Where-Object { $_.Check -eq 'aggregate.record.generate' -and $_.Message -like '*aggregate source must be external to and non-overlapping*' }).Count -eq 1 -and
            -not (Test-Path -LiteralPath $aggregateRecordPath)
        if (-not $inRepositorySourceRejected) {
            $inRepositoryGeneratorMessages = @($inRepositoryGeneratorResult.Findings | ForEach-Object { [string]$_.Message }) -join '; '
            Write-Host "SELFTEST DETAIL: in-repository aggregate-source generator probe findings: $inRepositoryGeneratorMessages"
        }
        Assert-D32SelfTest -Condition $inRepositorySourceRejected -Name 'actual aggregate generator rejects an in-repository source before writing its record' -Failures $failures
        $externalGeneratorResult = Invoke-D32GeneratePostBundleAggregateRecord -Repository $fixture -Manifest $provenance -Image $image `
            -BundleManifest $bundleManifest -AttestationPath $attestationPath -FixtureManifest $phase0FixtureManifestPath -EvidenceRoot $evidenceRoot `
            -RecordPath $aggregateRecordPath -ExpectedCandidateSha $head -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash `
            -Phase0RecordPath $phase0RecordPath -Phase0RecordSha256 $phase0Snapshot.Sha256 -ToolchainProfilePath $profilePath `
            -ExpectedToolchainProfileSha256 $profileSnapshot.Sha256
        $externalGeneratorPassedSourceGate = @($externalGeneratorResult.Findings | Where-Object { $_.Check -eq 'aggregate.record.generate' -and $_.Message -like '*aggregate source must be external to and non-overlapping*' }).Count -eq 0
        Assert-D32SelfTest -Condition $externalGeneratorPassedSourceGate -Name 'actual aggregate generator accepts its exact external source set and proceeds to full validation' -Failures $failures
        if (Test-Path -LiteralPath $aggregateRecordPath) {
            $aggregateRecordDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
            $aggregateRecordDocument = [IO.File]::ReadAllText($aggregateRecordPath, [Text.Encoding]::UTF8) | ConvertFrom-D32Json
        }
        else {
            $aggregateReferences = [ordered]@{
                phase0_matrix = New-D32PostBundleAggregateFileReference -Path $phase0RecordPath -Repository $fixture
                toolchain_profile = New-D32PostBundleAggregateFileReference -Path $profilePath -Repository $fixture
                fixture_manifest = New-D32PostBundleAggregateFileReference -Path $phase0FixtureManifestPath -Repository $fixture
                provenance_manifest = New-D32PostBundleAggregateFileReference -Path $provenance -Repository $fixture
                bundle_manifest = New-D32PostBundleAggregateFileReference -Path $bundleManifest -Repository $fixture
                attestation = New-D32PostBundleAggregateFileReference -Path $attestationPath -Repository $fixture
                trusted_git = New-D32PostBundleAggregateFileReference -Path $trustedGitPath -Repository $fixture
                test_inventory_baseline = $phase0Document.test_inventory_authority.baseline
                test_inventory_discovery = $phase0Document.test_inventory_authority.discovery
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
                powershell_module_admission = $global:D32PowerShellModuleAuthorityState.Admission
            }
            Write-D32JsonCreateNew -Path $aggregateRecordPath -Value $aggregateRecordDocument
            $aggregateRecordDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
        }
        $aggregateRecordFindings = New-D32FindingList
        $aggregateRecordValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $aggregateRecordDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -ValidatedPhase0Snapshot $phase0Snapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $phase0FixtureManifestPath -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $aggregateRecordFindings
        if (-not $aggregateRecordValidation.IsValid) {
            foreach ($finding in $aggregateRecordFindings) { Write-Host ("  AGGREGATE RECORD SELFTEST [{0}] {1}: {2}" -f $finding.Severity, $finding.Check, $finding.Message) }
        }
        Assert-D32SelfTest -Condition ($aggregateRecordValidation.IsValid -and @($aggregateRecordFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'PASS' }).Count -eq 1) -Name 'exact-SHA aggregate record schema binds current sources and explicitly defers downstream gates' -Failures $failures
        $mismatchedValidatedPhase0Snapshot = [PSCustomObject]@{
            Path = $phase0Snapshot.Path; Bytes = [Int64]$phase0Snapshot.Bytes; Sha256 = ('0' * 64)
            VolumeSerialHex = $phase0Snapshot.VolumeSerialHex; FileIdHex = $phase0Snapshot.FileIdHex
        }
        $mismatchedPhase0SnapshotFindings = New-D32FindingList
        $mismatchedPhase0SnapshotValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $aggregateRecordDigest.Hash `
            -Repository $fixture -ExpectedCandidateSha $head -ValidatedPhase0Snapshot $mismatchedValidatedPhase0Snapshot -EvidenceRoot $evidenceRoot `
            -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $phase0FixtureManifestPath -ManifestPath $provenance `
            -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $mismatchedPhase0SnapshotFindings
        Assert-D32SelfTest -Condition (-not $mismatchedPhase0SnapshotValidation.IsValid -and
            @($mismatchedPhase0SnapshotFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' -and $_.Message -like '*exact opened-byte/identity snapshot accepted by the full Phase0 validator*' }).Count -eq 1) `
            -Name 'aggregate reader rejects a Phase0 snapshot/hash changed after full caller-pinned validation' -Failures $failures

        $standaloneAggregateManifestPath = Join-Path $root 'standalone-fixture-manifest.json'
        $standaloneAggregateManifest = [IO.File]::ReadAllText($fixtureManifest, [Text.Encoding]::UTF8) | ConvertFrom-D32Json
        $standaloneAggregateManifest.build_policy.timeout_seconds = 600
        $standaloneAggregateManifest.build_policy.cargo_build_jobs = 1
        Write-D32Json -Path $standaloneAggregateManifestPath -Value $standaloneAggregateManifest
        $strictStandaloneFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest $standaloneAggregateManifest -FixtureManifestPath $standaloneAggregateManifestPath -Head $head -Repository $fixture -Findings $strictStandaloneFindings -RequirePhase0BuildPolicy
        Assert-D32SelfTest -Condition (@($strictStandaloneFindings | Where-Object { $_.Check -eq 'fixture-manifest.policy' -and $_.Severity -eq 'ERROR' }).Count -gt 0) `
            -Name 'standalone jobs=1/600-second fixture manifest is not Phase0 evidence' -Failures $failures

        $standaloneAggregateRecord = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($aggregateRecordDocument))
        $standaloneAggregateRecord.references.fixture_manifest = New-D32PostBundleAggregateFileReference -Path $standaloneAggregateManifestPath -Repository $fixture
        Write-D32Json -Path $aggregateRecordPath -Value $standaloneAggregateRecord
        $standaloneAggregateDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
        $standaloneAggregateFindings = New-D32FindingList
        $standaloneAggregateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $standaloneAggregateDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -ValidatedPhase0Snapshot $phase0Snapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $standaloneAggregateManifestPath -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $standaloneAggregateFindings
        Assert-D32SelfTest -Condition (-not $standaloneAggregateValidation.IsValid -and @($standaloneAggregateFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' -and $_.Message -like '*exact Phase0-recorded manifest path*' }).Count -eq 1) `
            -Name 'aggregate reader refuses an otherwise valid PRE_DOWNSTREAM record carrying standalone fixture evidence' -Failures $failures

        $copiedPhase0ManifestPath = Join-Path $root 'copied-phase0-fixture-manifest.json'
        [IO.File]::Copy($phase0FixtureManifestPath, $copiedPhase0ManifestPath)
        $copiedManifestAggregateRecord = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($aggregateRecordDocument))
        $copiedManifestAggregateRecord.references.fixture_manifest = New-D32PostBundleAggregateFileReference -Path $copiedPhase0ManifestPath -Repository $fixture
        Write-D32Json -Path $aggregateRecordPath -Value $copiedManifestAggregateRecord
        $copiedManifestAggregateDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
        $copiedManifestAggregateFindings = New-D32FindingList
        $copiedManifestAggregateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $copiedManifestAggregateDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -ValidatedPhase0Snapshot $phase0Snapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $copiedPhase0ManifestPath -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $copiedManifestAggregateFindings
        Assert-D32SelfTest -Condition (-not $copiedManifestAggregateValidation.IsValid -and @($copiedManifestAggregateFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' -and $_.Message -like '*exact Phase0-recorded manifest path*' }).Count -eq 1) `
            -Name 'aggregate reader rejects a byte-identical manifest copy with a different opened path and file identity' -Failures $failures

        foreach ($manifestIdentityField in @('sha256', 'file_id_hex')) {
            $staleManifestAggregateRecord = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($aggregateRecordDocument))
            $staleManifestAggregateRecord.references.fixture_manifest.$manifestIdentityField = '0' * $(if ($manifestIdentityField -ceq 'sha256') { 64 } else { 32 })
            Write-D32Json -Path $aggregateRecordPath -Value $staleManifestAggregateRecord
            $staleManifestAggregateDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
            $staleManifestAggregateFindings = New-D32FindingList
            $staleManifestAggregateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $staleManifestAggregateDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -ValidatedPhase0Snapshot $phase0Snapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $phase0FixtureManifestPath -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $staleManifestAggregateFindings
            Assert-D32SelfTest -Condition (-not $staleManifestAggregateValidation.IsValid -and @($staleManifestAggregateFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' -and $_.Message -like '*current bytes/opened-handle identity differ from the aggregate reference*' }).Count -eq 1) `
                -Name "aggregate reader rejects a stale fixture-manifest $manifestIdentityField even when its path is exact" -Failures $failures
        }

        Write-D32Json -Path $aggregateRecordPath -Value $aggregateRecordDocument
        $phase0RawForAggregateSchemaTests = [IO.File]::ReadAllText($phase0RecordPath, [Text.Encoding]::UTF8)
        $aggregateRawForPhase0SchemaTests = [IO.File]::ReadAllText($aggregateRecordPath, [Text.Encoding]::UTF8)
        try {
            foreach ($phase0SchemaCase in @(
                    [PSCustomObject]@{ Version = 7; Type = 'D32_PHASE0_MATRIX_RECORD_V7'; Name = 'prior V7' },
                    [PSCustomObject]@{ Version = 99; Type = 'D32_PHASE0_MATRIX_RECORD_V99'; Name = 'unknown V99' }
                )) {
                $phase0Variant = $phase0RawForAggregateSchemaTests | ConvertFrom-D32Json
                $phase0Variant.schema_version = [int]$phase0SchemaCase.Version
                $phase0Variant.record_type = [string]$phase0SchemaCase.Type
                Write-D32Json -Path $phase0RecordPath -Value $phase0Variant
                $phase0VariantSnapshot = Get-D32ProfileFileSnapshot -Path $phase0RecordPath
                $aggregateVariant = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($aggregateRecordDocument))
                $aggregateVariant.references.phase0_matrix.sha256 = [string]$phase0VariantSnapshot.Sha256
                $aggregateVariant.references.phase0_matrix.bytes = [Int64]$phase0VariantSnapshot.Bytes
                $aggregateVariant.references.phase0_matrix.volume_serial_hex = [string]$phase0VariantSnapshot.VolumeSerialHex
                $aggregateVariant.references.phase0_matrix.file_id_hex = [string]$phase0VariantSnapshot.FileIdHex
                Write-D32Json -Path $aggregateRecordPath -Value $aggregateVariant
                $aggregateVariantDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
                $phase0SchemaFindings = New-D32FindingList
                $phase0SchemaValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $aggregateVariantDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -ValidatedPhase0Snapshot $phase0VariantSnapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $phase0FixtureManifestPath -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $phase0SchemaFindings
                Assert-D32SelfTest -Condition (-not $phase0SchemaValidation.IsValid -and @($phase0SchemaFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' -and $_.Message -like '*not the supported exact V8 local PASS schema*' }).Count -eq 1) -Name "aggregate reader rejects $($phase0SchemaCase.Name) Phase0 after a fresh complete reference pin" -Failures $failures
            }
        }
        finally {
            [IO.File]::WriteAllText($phase0RecordPath, $phase0RawForAggregateSchemaTests, [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($aggregateRecordPath, $aggregateRawForPhase0SchemaTests, [Text.UTF8Encoding]::new($false))
        }
        $legacyAggregateRecord = [System.IO.File]::ReadAllText($aggregateRecordPath) | ConvertFrom-D32Json
        $legacyAggregateRecord.schema_version = 7
        $legacyAggregateRecord.record_type = 'D32_POST_BUNDLE_AGGREGATE_RECORD_V7'
        Write-D32Json -Path $aggregateRecordPath -Value $legacyAggregateRecord
        $legacyAggregateDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
        $legacyAggregateFindings = New-D32FindingList
        $legacyAggregateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $legacyAggregateDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -ValidatedPhase0Snapshot $phase0Snapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $phase0FixtureManifestPath -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $legacyAggregateFindings
        Assert-D32SelfTest -Condition (-not $legacyAggregateValidation.IsValid -and @($legacyAggregateFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' }).Count -eq 1) -Name 'aggregate record rejects prior V7 after module-admission migration' -Failures $failures
        $unknownAggregateRecord = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($aggregateRecordDocument))
        $unknownAggregateRecord.schema_version = 99
        $unknownAggregateRecord.record_type = 'D32_POST_BUNDLE_AGGREGATE_RECORD_V99'
        Write-D32Json -Path $aggregateRecordPath -Value $unknownAggregateRecord
        $unknownAggregateDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
        $unknownAggregateFindings = New-D32FindingList
        $unknownAggregateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $unknownAggregateDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -ValidatedPhase0Snapshot $phase0Snapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $phase0FixtureManifestPath -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $unknownAggregateFindings
        Assert-D32SelfTest -Condition (-not $unknownAggregateValidation.IsValid -and @($unknownAggregateFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' }).Count -eq 1) -Name 'aggregate record rejects an unknown future version with a fresh exact-SHA pin' -Failures $failures
        Write-D32Json -Path $aggregateRecordPath -Value $aggregateRecordDocument
        $invalidAggregateRecord = [System.IO.File]::ReadAllText($aggregateRecordPath) | ConvertFrom-D32Json
        $invalidAggregateRecord.status = 'ARTIFACT_ONLY'
        Write-D32Json -Path $aggregateRecordPath -Value $invalidAggregateRecord
        $invalidAggregateDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
        $invalidAggregateFindings = New-D32FindingList
        $invalidAggregateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $invalidAggregateDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -ValidatedPhase0Snapshot $phase0Snapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $phase0FixtureManifestPath -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $invalidAggregateFindings
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
            $invalidAggregateStateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $invalidAggregateStateDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -ValidatedPhase0Snapshot $phase0Snapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $phase0FixtureManifestPath -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $invalidAggregateStateFindings
            Assert-D32SelfTest -Condition (-not $invalidAggregateStateValidation.IsValid -and @($invalidAggregateStateFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' }).Count -eq 1) -Name "aggregate record rejects $($invalidAggregateState.Name) even with a fresh exact-SHA pin" -Failures $failures
        }
        Assert-D32SelfTest -Condition (Test-D32JsonDuplicateKeys -Json '{"schema_version":1,"schema_version":1}') -Name 'duplicate JSON object keys are rejected before schema parsing' -Failures $failures
        $validBundleJson = [System.IO.File]::ReadAllText($bundleManifest)
        $validAttestationObject = ([System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json)
        $attestationSha = (Get-D32EvidenceFileDigest -Path $attestationPath).Hash

        $blockedDiagnosticPath = Join-Path $phase0Root 'D32-PHASE0-BLOCKED-DIAGNOSTIC.json'
        try {
            $blockedDiagnosticJson = '{"schema_version":1,"record_type":"D32_PHASE0_BLOCKED_DIAGNOSTIC_V1","status":"PASS"}'
            $blockedDiagnosticBytes = [Text.UTF8Encoding]::new($false).GetBytes($blockedDiagnosticJson + [Environment]::NewLine)
            $blockedDiagnosticStream = [IO.File]::Open($blockedDiagnosticPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            try { $blockedDiagnosticStream.Write($blockedDiagnosticBytes, 0, $blockedDiagnosticBytes.Length); $blockedDiagnosticStream.Flush($true) }
            finally { $blockedDiagnosticStream.Dispose() }

            $blockedAttestationFindings = New-D32FindingList
            Test-D32ReleaseEvidenceBundle -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleFilePath $bundleManifest -Attestation $validAttestationObject -AttestationFilePath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture -ExpectedPhase0RecordPath $phase0Snapshot.Path -ExpectedPhase0RecordSha256 $phase0Snapshot.Sha256 -ExpectedToolchainProfilePath $profileSnapshot.Path -ExpectedToolchainProfileSha256 $profileSnapshot.Sha256 -Findings $blockedAttestationFindings
            Assert-D32SelfTest -Condition (@($blockedAttestationFindings | Where-Object { $_.Check -eq 'attestation.phase0-toolchain' -and $_.Severity -eq 'ERROR' -and $_.Message -like '*blocked-diagnostic sidecar exists*' }).Count -gt 0) -Name 'release attestor rejects any blocked-diagnostic sidecar, including forged PASS content' -Failures $failures

            Write-D32Json -Path $aggregateRecordPath -Value $aggregateRecordDocument
            $aggregateRecordDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
            $blockedAggregateFindings = New-D32FindingList
            $blockedAggregateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath -ExpectedRecordSha256 $aggregateRecordDigest.Hash -Repository $fixture -ExpectedCandidateSha $head -ValidatedPhase0Snapshot $phase0Snapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath -ToolchainProfilePath $profilePath -FixtureManifestPath $phase0FixtureManifestPath -ManifestPath $provenance -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $blockedAggregateFindings
            Assert-D32SelfTest -Condition (-not $blockedAggregateValidation.IsValid -and @($blockedAggregateFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' -and $_.Message -like '*blocked-diagnostic sidecar exists*' }).Count -eq 1) -Name 'aggregate reader refuses a forged PASS blocked-diagnostic sidecar' -Failures $failures
        }
        finally { if (Test-Path -LiteralPath $blockedDiagnosticPath) { [IO.File]::Delete($blockedDiagnosticPath) } }

        $legacyAttestationObject = ([System.IO.File]::ReadAllText($attestationPath) | ConvertFrom-D32Json)
        $legacyAttestationObject.schema_version = 8
        $legacyAttestationObject.attestation_type = 'D32_RELEASE_BUILD_ATTESTATION_V8'
        $legacyAttestationFindings = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $legacyAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($legacyAttestationFindings | Where-Object { $_.Check -eq 'attestation.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'release attestation rejects prior V8 after module-admission migration' -Failures $failures
        $unknownAttestationObject = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($validAttestationObject))
        $unknownAttestationObject.schema_version = 99
        $unknownAttestationObject.attestation_type = 'D32_RELEASE_BUILD_ATTESTATION_V99'
        $unknownAttestationFindings = Get-D32ReleaseBundleSelfTestFindings -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleManifest $bundleManifest -Attestation $unknownAttestationObject -AttestationPath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture
        Assert-D32SelfTest -Condition (@($unknownAttestationFindings | Where-Object { $_.Check -eq 'attestation.schema' -and $_.Severity -eq 'ERROR' }).Count -gt 0) -Name 'release attestation rejects an unknown future version instead of guessing its schema' -Failures $failures

        $phase0OriginalRaw = [System.IO.File]::ReadAllText($phase0RecordPath)
        $attestationOriginalRaw = [System.IO.File]::ReadAllText($attestationPath)
        $bundleOriginalRaw = [System.IO.File]::ReadAllText($bundleManifest)
        try {
            foreach ($phase0SchemaCase in @(
                    [PSCustomObject]@{ Version = 7; Type = 'D32_PHASE0_MATRIX_RECORD_V7'; Name = 'prior V7' },
                    [PSCustomObject]@{ Version = 99; Type = 'D32_PHASE0_MATRIX_RECORD_V99'; Name = 'unknown V99' }
                )) {
                $phase0Variant = $phase0OriginalRaw | ConvertFrom-D32Json
                $phase0Variant.schema_version = [int]$phase0SchemaCase.Version
                $phase0Variant.record_type = [string]$phase0SchemaCase.Type
                Write-D32Json -Path $phase0RecordPath -Value $phase0Variant
                $phase0VariantSnapshot = Get-D32ProfileFileSnapshot -Path $phase0RecordPath
                $phase0VariantAttestation = $attestationOriginalRaw | ConvertFrom-D32Json
                $phase0VariantAttestation.phase0_matrix.sha256 = $phase0VariantSnapshot.Sha256
                $phase0VariantAttestation.phase0_matrix.bytes = [Int64]$phase0VariantSnapshot.Bytes
                $phase0VariantAttestation.phase0_matrix.volume_serial_hex = [string]$phase0VariantSnapshot.VolumeSerialHex
                $phase0VariantAttestation.phase0_matrix.file_id_hex = [string]$phase0VariantSnapshot.FileIdHex
                Write-D32Json -Path $attestationPath -Value $phase0VariantAttestation
                $phase0VariantAttestationSnapshot = Get-D32EvidenceFileDigest -Path $attestationPath
                $phase0VariantBundle = $bundleOriginalRaw | ConvertFrom-D32Json
                $phase0VariantBundle.attestation_sha256 = $phase0VariantAttestationSnapshot.Hash
                Write-D32Json -Path $bundleManifest -Value $phase0VariantBundle
                $phase0VariantFindings = New-D32FindingList
                Test-D32ReleaseEvidenceBundle -Bundle $phase0VariantBundle -BundleFilePath $bundleManifest -Attestation $phase0VariantAttestation -AttestationFilePath $attestationPath -AttestationSha256 $phase0VariantAttestationSnapshot.Hash -Head $head -Repository $fixture -ExpectedPhase0RecordPath $phase0VariantSnapshot.Path -ExpectedPhase0RecordSha256 $phase0VariantSnapshot.Sha256 -ExpectedToolchainProfilePath $profileSnapshot.Path -ExpectedToolchainProfileSha256 $profileSnapshot.Sha256 -Findings $phase0VariantFindings
                Assert-D32SelfTest -Condition (@($phase0VariantFindings | Where-Object { $_.Check -eq 'attestation.phase0-toolchain' -and $_.Severity -eq 'ERROR' -and $_.Message -like '*unsupported schema*' }).Count -gt 0) -Name "Phase1 reader rejects $($phase0SchemaCase.Name) even when its current bytes are fully re-pinned" -Failures $failures
            }
        }
        finally {
            [System.IO.File]::WriteAllText($phase0RecordPath, $phase0OriginalRaw, [Text.UTF8Encoding]::new($false))
            [System.IO.File]::WriteAllText($attestationPath, $attestationOriginalRaw, [Text.UTF8Encoding]::new($false))
            [System.IO.File]::WriteAllText($bundleManifest, $bundleOriginalRaw, [Text.UTF8Encoding]::new($false))
        }

        $pinnedBundleFindings = New-D32FindingList
        Test-D32ReleaseEvidenceBundle -Bundle ($validBundleJson | ConvertFrom-D32Json) -BundleFilePath $bundleManifest -Attestation $validAttestationObject -AttestationFilePath $attestationPath -AttestationSha256 $attestationSha -Head $head -Repository $fixture -ExpectedPhase0RecordPath $phase0Snapshot.Path -ExpectedPhase0RecordSha256 $phase0Snapshot.Sha256 -ExpectedToolchainProfilePath $profileSnapshot.Path -ExpectedToolchainProfileSha256 $profileSnapshot.Sha256 -Findings $pinnedBundleFindings
        Assert-D32SelfTest -Condition (@($pinnedBundleFindings | Where-Object { $_.Severity -eq 'ERROR' }).Count -eq 0) -Name 'bundle attestation references match independent Phase0/profile pins' -Failures $failures

        $consumerAttestationRaw = [IO.File]::ReadAllText($attestationPath, [Text.Encoding]::UTF8)
        $consumerBundleRaw = [IO.File]::ReadAllText($bundleManifest, [Text.Encoding]::UTF8)
        $consumerAggregateRaw = [IO.File]::ReadAllText($aggregateRecordPath, [Text.Encoding]::UTF8)
        $consumerControlReleaseFindings = New-D32FindingList
        Test-D32ReleaseEvidenceBundle -Bundle ($consumerBundleRaw | ConvertFrom-D32Json) -BundleFilePath $bundleManifest `
            -Attestation ($consumerAttestationRaw | ConvertFrom-D32Json) -AttestationFilePath $attestationPath -AttestationSha256 $attestationSha `
            -Head $head -Repository $fixture -ExpectedPhase0RecordPath $phase0Snapshot.Path -ExpectedPhase0RecordSha256 $phase0Snapshot.Sha256 `
            -ExpectedToolchainProfilePath $profileSnapshot.Path -ExpectedToolchainProfileSha256 $profileSnapshot.Sha256 -Findings $consumerControlReleaseFindings
        $consumerControlReleasePassed = @($consumerControlReleaseFindings | Where-Object { $_.Severity -eq 'ERROR' }).Count -eq 0
        $consumerAggregateSnapshot = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
        $consumerControlAggregateFindings = New-D32FindingList
        $consumerControlAggregateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath `
            -ExpectedRecordSha256 ([string]$consumerAggregateSnapshot.Hash) -Repository $fixture -ExpectedCandidateSha $head `
            -ValidatedPhase0Snapshot $phase0Snapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath `
            -ToolchainProfilePath $profilePath -FixtureManifestPath $phase0FixtureManifestPath -ManifestPath $provenance `
            -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $consumerControlAggregateFindings
        $consumerControlAggregatePassed = $consumerControlAggregateValidation.IsValid -and
            @($consumerControlAggregateFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'PASS' }).Count -eq 1
        Assert-D32SelfTest -Condition ($consumerControlReleasePassed -and $consumerControlAggregatePassed) `
            -Name 'Release V8 and Aggregate V7 byte-mutation controls begin from independently valid clean consumer inputs' -Failures $failures
        $downstreamAuthorityTamperCasesPassed = $consumerControlReleasePassed -and $consumerControlAggregatePassed
        try {
            foreach ($authorityField in @('baseline', 'discovery')) {
                [IO.File]::WriteAllText($attestationPath, $consumerAttestationRaw, [Text.UTF8Encoding]::new($false))
                [IO.File]::WriteAllText($bundleManifest, $consumerBundleRaw, [Text.UTF8Encoding]::new($false))
                [IO.File]::WriteAllText($aggregateRecordPath, $consumerAggregateRaw, [Text.UTF8Encoding]::new($false))
                $mutatedAttestation = ConvertFrom-D32Phase0Json -Json $consumerAttestationRaw
                $mutatedAttestation.test_inventory_authority.$authorityField.sha256 = '0' * 64
                Write-D32Json -Path $attestationPath -Value $mutatedAttestation
                $mutatedAttestationDigest = Get-D32EvidenceFileDigest -Path $attestationPath
                $mutatedBundle = ConvertFrom-D32Phase0Json -Json $consumerBundleRaw
                $mutatedBundle.attestation_sha256 = [string]$mutatedAttestationDigest.Hash
                Write-D32Json -Path $bundleManifest -Value $mutatedBundle
                $releaseAuthorityFindings = New-D32FindingList
                Test-D32ReleaseEvidenceBundle -Bundle $mutatedBundle -BundleFilePath $bundleManifest -Attestation $mutatedAttestation `
                    -AttestationFilePath $attestationPath -AttestationSha256 ([string]$mutatedAttestationDigest.Hash) -Head $head -Repository $fixture `
                    -ExpectedPhase0RecordPath $phase0Snapshot.Path -ExpectedPhase0RecordSha256 $phase0Snapshot.Sha256 `
                    -ExpectedToolchainProfilePath $profileSnapshot.Path -ExpectedToolchainProfileSha256 $profileSnapshot.Sha256 -Findings $releaseAuthorityFindings
                $releaseRejected = @($releaseAuthorityFindings | Where-Object { $_.Check -eq 'attestation.phase0-toolchain' -and $_.Severity -eq 'ERROR' }).Count -gt 0
                if (-not $releaseRejected) { $downstreamAuthorityTamperCasesPassed = $false }

                # Restore the release inputs before exercising Aggregate, so its result can
                # only be caused by the aggregate reference under test.
                [IO.File]::WriteAllText($attestationPath, $consumerAttestationRaw, [Text.UTF8Encoding]::new($false))
                [IO.File]::WriteAllText($bundleManifest, $consumerBundleRaw, [Text.UTF8Encoding]::new($false))
                $mutatedAggregate = ConvertFrom-D32Phase0Json -Json $consumerAggregateRaw
                $aggregateReferenceName = 'test_inventory_{0}' -f [string]$authorityField
                $mutatedAggregate.references.$aggregateReferenceName.sha256 = '0' * 64
                Write-D32Json -Path $aggregateRecordPath -Value $mutatedAggregate
                $mutatedAggregateDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
                $aggregateAuthorityFindings = New-D32FindingList
                $mutatedAggregateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath `
                    -ExpectedRecordSha256 ([string]$mutatedAggregateDigest.Hash) -Repository $fixture -ExpectedCandidateSha $head `
                    -ValidatedPhase0Snapshot $phase0Snapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath `
                    -ToolchainProfilePath $profilePath -FixtureManifestPath $phase0FixtureManifestPath -ManifestPath $provenance `
                    -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $aggregateAuthorityFindings
                $aggregateRejected = -not $mutatedAggregateValidation.IsValid -and
                    @($aggregateAuthorityFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' }).Count -gt 0
                if (-not $aggregateRejected) { $downstreamAuthorityTamperCasesPassed = $false }
            }
        }
        finally {
            [IO.File]::WriteAllText($attestationPath, $consumerAttestationRaw, [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($bundleManifest, $consumerBundleRaw, [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($aggregateRecordPath, $consumerAggregateRaw, [Text.UTF8Encoding]::new($false))
        }
        $downstreamAuthorityTamperCasesPassed = $downstreamAuthorityTamperCasesPassed -and
            ([IO.File]::ReadAllText($attestationPath, [Text.Encoding]::UTF8) -ceq $consumerAttestationRaw) -and
            ([IO.File]::ReadAllText($bundleManifest, [Text.Encoding]::UTF8) -ceq $consumerBundleRaw) -and
            ([IO.File]::ReadAllText($aggregateRecordPath, [Text.Encoding]::UTF8) -ceq $consumerAggregateRaw)
        Assert-D32SelfTest -Condition $downstreamAuthorityTamperCasesPassed `
            -Name 'Release V8 and Aggregate V7 consumers reject changed baseline and discovery references after their enclosing records are rehashed' -Failures $failures

        $phase0ProtocolListCommands = @($phase0Document.commands | Where-Object { [string]$_.name -ceq 'protocol-test-list' })
        if ($phase0ProtocolListCommands.Count -ne 1 -or [String]::IsNullOrWhiteSpace([string]$phase0ProtocolListCommands[0].stdout.path)) {
            throw 'self-test expected exactly one formal Phase0 protocol-test-list stdout artifact'
        }
        $downstreamReferencedBytesCases = @(
            [PSCustomObject]@{
                Name = 'discovery protocol-test-list stdout'
                Path = [string]$inventoryArtifacts.Discovery.inventory_commands[0].command.stdout.path
                Marker = "tampered::discovery-unlisted-test: test`n"
            },
            [PSCustomObject]@{
                Name = 'formal Phase0 protocol-test-list stdout'
                Path = [string]$phase0ProtocolListCommands[0].stdout.path
                Marker = "tampered::phase0-unlisted-test: test`n"
            },
            [PSCustomObject]@{
                Name = 'referenced test-inventory baseline JSON'
                Path = [string]$inventoryArtifacts.BaselineReference.path
                Marker = "tampered-baseline-reference`n"
            },
            [PSCustomObject]@{
                Name = 'referenced test-inventory discovery JSON'
                Path = [string]$inventoryArtifacts.DiscoveryReference.path
                Marker = "tampered-discovery-reference`n"
            }
        )
        foreach ($referencedBytesCase in $downstreamReferencedBytesCases) {
            if ([String]::IsNullOrWhiteSpace([string]$referencedBytesCase.Path) -or -not (Test-Path -LiteralPath $referencedBytesCase.Path -PathType Leaf)) {
                throw "self-test referenced-byte case is missing its source artifact: $($referencedBytesCase.Name)"
            }
        }
        $referencedBytesControlReleaseFindings = New-D32FindingList
        Test-D32ReleaseEvidenceBundle -Bundle ($consumerBundleRaw | ConvertFrom-D32Json) -BundleFilePath $bundleManifest `
            -Attestation ($consumerAttestationRaw | ConvertFrom-D32Json) -AttestationFilePath $attestationPath -AttestationSha256 $attestationSha `
            -Head $head -Repository $fixture -ExpectedPhase0RecordPath $phase0Snapshot.Path -ExpectedPhase0RecordSha256 $phase0Snapshot.Sha256 `
            -ExpectedToolchainProfilePath $profileSnapshot.Path -ExpectedToolchainProfileSha256 $profileSnapshot.Sha256 -Findings $referencedBytesControlReleaseFindings
        $referencedBytesControlReleasePassed = @($referencedBytesControlReleaseFindings | Where-Object { $_.Severity -eq 'ERROR' }).Count -eq 0
        $referencedBytesControlAggregateDigest = Get-D32EvidenceFileDigest -Path $aggregateRecordPath
        $referencedBytesControlAggregateFindings = New-D32FindingList
        $referencedBytesControlAggregateValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath `
            -ExpectedRecordSha256 ([string]$referencedBytesControlAggregateDigest.Hash) -Repository $fixture -ExpectedCandidateSha $head `
            -ValidatedPhase0Snapshot $phase0Snapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath `
            -ToolchainProfilePath $profilePath -FixtureManifestPath $phase0FixtureManifestPath -ManifestPath $provenance `
            -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $referencedBytesControlAggregateFindings
        $referencedBytesControlAggregatePassed = $referencedBytesControlAggregateValidation.IsValid -and
            @($referencedBytesControlAggregateFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'PASS' }).Count -eq 1
        Assert-D32SelfTest -Condition ($referencedBytesControlReleasePassed -and $referencedBytesControlAggregatePassed) `
            -Name 'Release V8 and Aggregate V7 referenced-byte mutations have clean independently valid positive controls' -Failures $failures

        $downstreamReferencedBytesCasesPassed = $referencedBytesControlReleasePassed -and $referencedBytesControlAggregatePassed
        foreach ($referencedBytesCase in $downstreamReferencedBytesCases) {
            $originalReferencedBytes = [IO.File]::ReadAllBytes([string]$referencedBytesCase.Path)
            try {
                [IO.File]::AppendAllText([string]$referencedBytesCase.Path, [string]$referencedBytesCase.Marker, [Text.UTF8Encoding]::new($false))
                $releaseReferencedBytesFindings = New-D32FindingList
                Test-D32ReleaseEvidenceBundle -Bundle ($consumerBundleRaw | ConvertFrom-D32Json) -BundleFilePath $bundleManifest `
                    -Attestation ($consumerAttestationRaw | ConvertFrom-D32Json) -AttestationFilePath $attestationPath -AttestationSha256 $attestationSha `
                    -Head $head -Repository $fixture -ExpectedPhase0RecordPath $phase0Snapshot.Path -ExpectedPhase0RecordSha256 $phase0Snapshot.Sha256 `
                    -ExpectedToolchainProfilePath $profileSnapshot.Path -ExpectedToolchainProfileSha256 $profileSnapshot.Sha256 -Findings $releaseReferencedBytesFindings
                $releaseReferencedBytesRejected = @($releaseReferencedBytesFindings | Where-Object { $_.Check -eq 'attestation.phase0-toolchain' -and $_.Severity -eq 'ERROR' }).Count -gt 0

                $aggregateReferencedBytesFindings = New-D32FindingList
                $aggregateReferencedBytesValidation = Test-D32PostBundleAggregateRecord -RecordPath $aggregateRecordPath `
                    -ExpectedRecordSha256 ([string]$referencedBytesControlAggregateDigest.Hash) -Repository $fixture -ExpectedCandidateSha $head `
                    -ValidatedPhase0Snapshot $phase0Snapshot -EvidenceRoot $evidenceRoot -Phase0RecordPath $phase0RecordPath `
                    -ToolchainProfilePath $profilePath -FixtureManifestPath $phase0FixtureManifestPath -ManifestPath $provenance `
                    -BundleManifestPath $bundleManifest -AttestationPath $attestationPath -TrustedGitPath $trustedGitPath -Findings $aggregateReferencedBytesFindings
                $aggregateReferencedBytesRejected = -not $aggregateReferencedBytesValidation.IsValid -and
                    @($aggregateReferencedBytesFindings | Where-Object { $_.Check -eq 'aggregate.record' -and $_.Severity -eq 'ERROR' }).Count -gt 0
                if (-not ($releaseReferencedBytesRejected -and $aggregateReferencedBytesRejected)) {
                    $downstreamReferencedBytesCasesPassed = $false
                }
            }
            finally { [IO.File]::WriteAllBytes([string]$referencedBytesCase.Path, $originalReferencedBytes) }
            $restoredReferencedBytes = [IO.File]::ReadAllBytes([string]$referencedBytesCase.Path)
            if ([Convert]::ToBase64String($restoredReferencedBytes) -cne [Convert]::ToBase64String($originalReferencedBytes)) {
                $downstreamReferencedBytesCasesPassed = $false
            }
        }
        Assert-D32SelfTest -Condition $downstreamReferencedBytesCasesPassed `
            -Name 'Release V8 and Aggregate V7 independently reopen and reject tampered discovery stdout, formal Phase0 list stdout, baseline, and discovery bytes with pinned references unchanged' -Failures $failures

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

        $standaloneFixturePolicy = $validFixtureJson | ConvertFrom-D32Json
        $standaloneFixturePolicy.build_policy.timeout_seconds = 600
        $standaloneFixturePolicy.build_policy.cargo_build_jobs = 1
        $standalonePolicyFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest $standaloneFixturePolicy -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $standalonePolicyFindings
        Assert-D32SelfTest -Condition (@($standalonePolicyFindings | Where-Object { $_.Check -eq 'fixture-manifest.policy' -and $_.Severity -eq 'ERROR' }).Count -eq 0) `
            -Name 'non-Phase0 standalone manifest accepts only the frozen 600-second/jobs-1 policy without claiming Phase0 authority' -Failures $failures
        $standaloneStrictFindings = New-D32FindingList
        Test-D32FixtureManifest -FixtureManifest $standaloneFixturePolicy -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $standaloneStrictFindings -RequirePhase0BuildPolicy
        Assert-D32SelfTest -Condition (@($standaloneStrictFindings | Where-Object { $_.Check -eq 'fixture-manifest.policy' -and $_.Severity -eq 'ERROR' }).Count -gt 0) `
            -Name 'Phase0 manifest consumer rejects the standalone 600-second/jobs-1 policy' -Failures $failures

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

        foreach ($wrongBudget in @(
                [PSCustomObject]@{ Field = 'cargo_build_jobs'; Value = 2 },
                [PSCustomObject]@{ Field = 'cargo_build_jobs'; Value = 5 },
                [PSCustomObject]@{ Field = 'timeout_seconds'; Value = 14400 },
                [PSCustomObject]@{ Field = 'timeout_seconds'; Value = 28801 }
            )) {
            $wrongBudgetManifest = $validFixtureJson | ConvertFrom-D32Json
            $wrongBudgetManifest.build_policy.($wrongBudget.Field) = $wrongBudget.Value
            $wrongBudgetFindings = New-D32FindingList
            Test-D32FixtureManifest -FixtureManifest $wrongBudgetManifest -FixtureManifestPath $fixtureManifest -Head $head -Repository $fixture -Findings $wrongBudgetFindings -RequirePhase0BuildPolicy
            Assert-D32SelfTest -Condition (@($wrongBudgetFindings | Where-Object { $_.Check -eq 'fixture-manifest.policy' -and $_.Severity -eq 'ERROR' }).Count -gt 0) `
                -Name "fixture manifest rejects $($wrongBudget.Field)=$($wrongBudget.Value) after the owner-bound build-budget migration" -Failures $failures
        }

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
        if (-not [String]::IsNullOrWhiteSpace([string]$_.ScriptStackTrace)) { Write-Host ("SELFTEST ERROR STACK: {0}" -f $_.ScriptStackTrace) }
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
        $aggregateRecord = Test-D32PostBundleAggregateRecord -RecordPath $AggregateRecordPath -ExpectedRecordSha256 $AggregateRecordSha256 -Repository $RepoRoot -ExpectedCandidateSha $ExpectedSha -ValidatedPhase0Snapshot $validation.Phase0RecordSnapshot -EvidenceRoot $EvidenceRoot -Phase0RecordPath $Phase0RecordPath -ToolchainProfilePath $ToolchainProfilePath -FixtureManifestPath $FixtureManifestPath -ManifestPath $ManifestPath -BundleManifestPath $BundleManifestPath -AttestationPath $AttestationPath -TrustedGitPath $TrustedGitPath -Findings $aggregatePinFindings
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
