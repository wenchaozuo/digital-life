[CmdletBinding()]
param(
    [Alias('Generate')]
    [switch]$GenerateManifest,

    [Alias('Validate')]
    [switch]$ValidateOnly,

    [switch]$SelfTest,

    [Alias('Root')]
    [string]$RepoRoot,

    [Alias('ProvenancePath', 'TargetManifest')]
    [string]$ManifestPath,

    [Alias('ReleaseImage')]
    [string]$ImagePath,

    [Alias('BundleManifest')]
    [string]$BundleManifestPath,

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

$script:D32BuildCommand = 'cargo build --manifest-path vita-agent/Cargo.toml --release --locked --bin vita-agent'
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
    return $property.Value
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

function Read-D32Json {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings,
        [Parameter(Mandatory = $true)][string]$Check
    )

    try {
        $raw = [System.IO.File]::ReadAllText($Path)
        $value = $raw | ConvertFrom-Json
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
    param([Parameter(Mandatory = $true)][System.IO.FileInfo]$Item)

    return [PSCustomObject]@{
        FullName             = [string]$Item.FullName
        Length               = [Int64]$Item.Length
        CreationTimeUtcTicks = [Int64]$Item.CreationTimeUtc.Ticks
        LastWriteUtcTicks    = [Int64]$Item.LastWriteTimeUtc.Ticks
        Attributes           = [int]$Item.Attributes
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
        [int]$Left.Attributes -eq [int]$Right.Attributes
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

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer) {
            $result.Failure = 'trusted Git path is a directory, not a regular file'
            return [PSCustomObject]$result
        }
        if (([System.IO.FileAttributes]$item.Attributes).HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
            $result.Failure = 'trusted Git path is a reparse point'
            return [PSCustomObject]$result
        }
        $identity = Get-D32FileIdentity -Item $item
        $actual = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $result.Path = [string]$item.FullName
        $result.ActualSha256 = $actual
        $result.Identity = $identity
        if ($actual -cne $ExpectedSha256) {
            $result.Failure = 'trusted Git SHA-256 does not match the supplied digest'
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
    $before = Test-D32TrustedGitImage -Path $TrustedGitPath -ExpectedSha256 $TrustedGitSha256
    $result.TrustedGitBefore = $before
    if (-not $before.IsValid) {
        $result.Failure = $before.Failure
        return [PSCustomObject]$result
    }
    $owned = $null
    $process = $null
    try {
        $owned = New-D32OwnedTempRoot -Purpose 'git'
        $hooks = Join-Path $owned.Root 'hooks'
        [void](New-Item -ItemType Directory -Path $hooks -Force -ErrorAction Stop)

        $processArguments = @(
            '--no-optional-locks',
            '-c', 'core.fsmonitor=false',
            '-c', 'core.untrackedCache=false',
            '-c', "core.hooksPath=$hooks",
            '-C', $Repository
        ) + @($Arguments)
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $before.Path
        $startInfo.Arguments = ConvertTo-D32ProcessArguments -Arguments $processArguments
        $startInfo.WorkingDirectory = $Repository
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        # Remove ambient Git/credential/SSH controls before adding only the
        # fixed isolated values.  The executable itself is still the explicit
        # hash-checked path, never PATH lookup.
        $environmentKeys = @($startInfo.EnvironmentVariables.Keys)
        foreach ($key in $environmentKeys) {
            if ($key -like 'GIT_*' -or $key -like 'GCM_*' -or $key -like 'SSH_*' -or
                $key -in @('BASH_ENV', 'ENV', 'CDPATH', 'PROMPT_COMMAND', 'MSYS2_PATH_TYPE')) {
                [void]$startInfo.EnvironmentVariables.Remove($key)
            }
        }
        $startInfo.EnvironmentVariables['GIT_CONFIG_NOSYSTEM'] = '1'
        $startInfo.EnvironmentVariables['GIT_CONFIG_SYSTEM'] = 'NUL'
        $startInfo.EnvironmentVariables['GIT_CONFIG_GLOBAL'] = 'NUL'
        $startInfo.EnvironmentVariables['GIT_CONFIG_COUNT'] = '0'
        $startInfo.EnvironmentVariables['GIT_TERMINAL_PROMPT'] = '0'
        $startInfo.EnvironmentVariables['GCM_INTERACTIVE'] = 'Never'
        $startInfo.EnvironmentVariables['GIT_ASKPASS'] = ''
        $startInfo.EnvironmentVariables['GIT_EDITOR'] = 'd32-disabled-editor'
        $startInfo.EnvironmentVariables['GIT_PAGER'] = 'cat'
        $startInfo.EnvironmentVariables['PAGER'] = 'cat'
        $startInfo.EnvironmentVariables['GIT_OPTIONAL_LOCKS'] = '0'
        $startInfo.EnvironmentVariables['HOME'] = $owned.Root
        $startInfo.EnvironmentVariables['USERPROFILE'] = $owned.Root
        $startInfo.EnvironmentVariables['APPDATA'] = $owned.Root
        $startInfo.EnvironmentVariables['LOCALAPPDATA'] = $owned.Root
        $startInfo.EnvironmentVariables['XDG_CONFIG_HOME'] = $owned.Root
        $startInfo.EnvironmentVariables['TMP'] = $owned.Root
        $startInfo.EnvironmentVariables['TEMP'] = $owned.Root
        if ($env:SystemRoot) { $startInfo.EnvironmentVariables['SystemRoot'] = $env:SystemRoot }
        if ($env:WINDIR) { $startInfo.EnvironmentVariables['WINDIR'] = $env:WINDIR }
        if ($env:ComSpec) { $startInfo.EnvironmentVariables['ComSpec'] = $env:ComSpec }
        $gitDirectory = Split-Path -Parent $before.Path
        $startInfo.EnvironmentVariables['Path'] = $gitDirectory

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw 'process did not start'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($script:D32GitTimeoutMilliseconds)) {
            try { $process.Kill() } catch { }
            [void]$process.WaitForExit(5000)
            $result.Failure = 'trusted Git process timed out'
        }
        else {
            $stdout = ''
            $stderr = ''
            try { $stdout = $stdoutTask.Result } catch { }
            try { $stderr = $stderrTask.Result } catch { }
            $safeOutput = ConvertTo-D32GitOutput -Arguments $Arguments -StdOut $stdout -StdErr $stderr
            $result.ExitCode = $process.ExitCode
            $result.Text = $safeOutput.Text
            $result.HasOutput = $safeOutput.HasOutput
            $result.HasErrorOutput = $safeOutput.HasErrorOutput
            $result.OutputTruncated = $safeOutput.OutputTruncated
            if ($result.ExitCode -ne 0) {
                $result.Failure = 'trusted Git command returned a non-zero exit code'
            }
        }
    }
    catch {
        if ($null -eq $result.Failure) {
            $result.Failure = 'trusted Git process invocation failed'
        }
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
        if ($null -ne $owned -and -not (Remove-D32OwnedTempRoot -Root $owned.Root -Marker $owned.Marker -Token $owned.Token)) {
            $result.ExitCode = -1
            $result.Failure = 'owned Git environment cleanup failed'
        }
    }
    return [PSCustomObject]$result
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
    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [string]) {
        return $false
    }
    try {
        $doubleValue = [double]$Value
        if ([double]::IsNaN($doubleValue) -or [double]::IsInfinity($doubleValue) -or $doubleValue -lt 0 -or $doubleValue -ne [math]::Floor($doubleValue)) {
            return $false
        }
        $integerValue = [Int64]$Value
        if ([double]$integerValue -ne $doubleValue) {
            return $false
        }
        $Parsed.Value = $integerValue
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
        'docs/governance/FROZEN_INVARIANTS.md',
        'docs/governance/ARCHITECTURE_DECISIONS.md',
        'docs/governance/CURRENT_DEVELOPMENT_STATE.md',
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
            if ($agentsText -notmatch 'docs[/\\]governance[/\\]CODEX_DEVELOPMENT_PROTOCOL\.md') {
                Add-D32Finding -Findings $Findings -Severity ERROR -Check 'governance.index' -Message 'AGENTS.md does not index CODEX_DEVELOPMENT_PROTOCOL.md'
            }
            else {
                Add-D32Finding -Findings $Findings -Severity PASS -Check 'governance.index' -Message 'AGENTS.md indexes the complete governance protocol'
            }
        }
        catch {
            Add-D32Finding -Findings $Findings -Severity ERROR -Check 'governance.index' -Message $_.Exception.Message
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

function Invoke-D32Validation {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Manifest,
        [Parameter(Mandatory = $true)][string]$Image,
        [Parameter(Mandatory = $true)][string]$BundleManifest,
        [AllowNull()][string]$TrustedGitPath,
        [AllowNull()][string]$TrustedGitSha256,
        [AllowNull()][string]$ExpectedCandidateSha,
        [AllowNull()][string]$Base,
        [AllowNull()][string]$MergeBase,
        [AllowNull()][string]$RunRoot,
        [AllowNull()][string[]]$Modes
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

    $bundleObject = $null
    if (-not (Test-Path -LiteralPath $BundleManifest -PathType Leaf)) {
        Add-D32Finding -Findings $findings -Severity ERROR -Check 'bundle.file' -Message "bundle manifest is missing: $BundleManifest"
    }
    else {
        $bundleObject = Read-D32Json -Path $BundleManifest -Findings $findings -Check 'bundle.json'
        Test-D32BundleManifest -Bundle $bundleObject -BundleFilePath $BundleManifest -Head $head -Repository $Repository -Findings $findings
    }

    $modeResult = Test-D32RequestedModes -Modes $Modes -Findings $findings
    Test-D32RunOutputRoot -RunRoot $RunRoot -Manifest $Manifest -BundleManifest $BundleManifest -Findings $findings
    Add-D32Finding -Findings $findings -Severity INFO -Check 'provider.credentials' -Message 'provider/credential validation is intentionally delegated to Host official preflight; no credential, token, or profile secret was read'

    $errors = @($findings | Where-Object { $_.Severity -eq 'ERROR' })
    return [PSCustomObject]@{
        Success        = $errors.Count -eq 0
        Findings       = $findings
        ValidatedModes  = if ($modeResult.IsValid) { [string[]]$modeResult.Modes } else { [string[]]@() }
        SecurityClassification = $classification
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

function Write-D32Result {
    param(
        [Parameter(Mandatory = $true)][string]$Operation,
        [Parameter(Mandatory = $true)][object]$Result
    )

    $status = if ($Result.Success) { 'PASS' } else { 'BLOCKED' }
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
    if ($Condition) {
        Write-Host "SELFTEST PASS: $Name"
    }
    else {
        Write-Host "SELFTEST FAIL: $Name"
        [void]$Failures.Add($Name)
    }
}

function Invoke-D32SelfTest {
    $failures = New-D32FindingList
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ('d32-preflight-selftest-' + [Guid]::NewGuid().ToString('N'))
    $rootToken = [Guid]::NewGuid().ToString('N')
    $rootMarker = Join-Path $root 'd32-selftest-owned.marker'
    $rootOwned = $false
    $fixture = Join-Path $root 'repo'
    $bundleRoot = Join-Path $root 'bundle'
    $buildRoot = Join-Path $root 'build'
    $provenance = Join-Path $root 'provenance.json'
    $generated = Join-Path $root 'generated.json'
    $existing = Join-Path $root 'existing.json'
    $image = Join-Path $fixture 'vita-agent\target\release\vita-agent.exe'
    try {
        [void](New-Item -ItemType Directory -Path $fixture -Force)
        [System.IO.File]::WriteAllText($rootMarker, $rootToken, (New-Object System.Text.UTF8Encoding($false)))
        $rootOwned = $true
        [void](New-Item -ItemType Directory -Path $bundleRoot -Force)
        [void](New-Item -ItemType Directory -Path $buildRoot -Force)
        foreach ($relative in @(
                'docs\governance\FROZEN_INVARIANTS.md',
                'docs\governance\ARCHITECTURE_DECISIONS.md',
                'docs\governance\CURRENT_DEVELOPMENT_STATE.md',
                'docs\governance\CODEX_DEVELOPMENT_PROTOCOL.md',
                'AGENTS.md')) {
            $path = Join-Path $fixture $relative
            [void](New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force)
            $content = if ($relative -eq 'AGENTS.md') { '# fixture index`nSee docs/governance/CODEX_DEVELOPMENT_PROTOCOL.md`n' } else { '# fixture governance`n' }
            [System.IO.File]::WriteAllText($path, $content)
        }
        [void](New-Item -ItemType Directory -Path (Split-Path -Parent $image) -Force)
        [System.IO.File]::WriteAllBytes($image, [Text.Encoding]::UTF8.GetBytes('d32-selftest-release-image'))

        $gitCommand = Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1
        $trustedGitPath = [string]$gitCommand.Source
        if ([String]::IsNullOrWhiteSpace($trustedGitPath)) {
            $trustedGitPath = [string]$gitCommand.Path
        }
        $trustedGitHash = (Get-FileHash -LiteralPath $trustedGitPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $validTrustedGit = Test-D32TrustedGitImage -Path $trustedGitPath -ExpectedSha256 $trustedGitHash
        Assert-D32SelfTest -Condition $validTrustedGit.IsValid -Name 'explicit fixed trusted Git image is accepted' -Failures $failures
        Assert-D32SelfTest -Condition (-not (Test-D32TrustedGitImage -Path $null -ExpectedSha256 $trustedGitHash).IsValid) -Name 'missing trusted Git path is rejected' -Failures $failures
        Assert-D32SelfTest -Condition (-not (Test-D32TrustedGitImage -Path $trustedGitPath -ExpectedSha256 ('0' * 64)).IsValid) -Name 'wrong trusted Git hash is rejected' -Failures $failures
        $classification = Get-D32SecurityClassification
        Assert-D32SelfTest -Condition ([bool]$classification.advisory_only -and [bool]$classification.host_official_preflight_required) -Name 'Host-required advisory security classification is explicit' -Failures $failures
        $secret = 'D32-SECRET-CONFIG-OUTPUT'
        $safeOutput = ConvertTo-D32GitOutput -Arguments @('status', '--porcelain=v1') -StdOut ("?? $secret`n") -StdErr $secret
        Assert-D32SelfTest -Condition ((-not $safeOutput.Text.Contains($secret)) -and $safeOutput.HasOutput) -Name 'malicious Git output is bounded and not echoed' -Failures $failures

        $reparseGitPath = Join-Path $root 'reparse-git.exe'
        $reparseCreated = $false
        try {
            [void](New-Item -ItemType SymbolicLink -LiteralPath $reparseGitPath -Target $trustedGitPath -ErrorAction Stop)
            $reparseCreated = $true
        }
        catch {
            Write-Host 'SELFTEST INFO: reparse fixture unavailable; platform privilege did not allow a file symlink'
        }
        if ($reparseCreated) {
            Assert-D32SelfTest -Condition (-not (Test-D32TrustedGitImage -Path $reparseGitPath -ExpectedSha256 $trustedGitHash).IsValid) -Name 'reparse trusted Git image is rejected' -Failures $failures
        }
        $artifactSpecs = @(
            @{ Name = 'vita-agent.exe'; Build = (Join-Path $buildRoot 'vita\release\vita-agent.exe'); Content = 'vita-artifact' },
            @{ Name = 'd32a-production-canary-host.exe'; Build = (Join-Path $buildRoot 'host\release\d32a-production-canary-host.exe'); Content = 'host-artifact' },
            @{ Name = 'digital_life_lib.dll'; Build = (Join-Path $buildRoot 'host\release\digital_life_lib.dll'); Content = 'lib-artifact' }
        )
        $bundleArtifacts = @()
        foreach ($spec in $artifactSpecs) {
            [void](New-Item -ItemType Directory -Path (Split-Path -Parent $spec.Build) -Force)
            [System.IO.File]::WriteAllBytes($spec.Build, [Text.Encoding]::UTF8.GetBytes($spec.Content))
            $bundleFile = Join-Path $bundleRoot $spec.Name
            [System.IO.File]::Copy($spec.Build, $bundleFile)
            $buildDigest = Get-D32FileDigest -Path $spec.Build
            $bundleDigest = Get-D32FileDigest -Path $bundleFile
            $bundleArtifacts += [ordered]@{
                name = $spec.Name
                build_path = Get-D32AbsolutePath -Path $spec.Build
                bundle_path = Get-D32AbsolutePath -Path $bundleFile
                build_bytes = $buildDigest.Length
                bundle_bytes = $bundleDigest.Length
                build_sha256 = $buildDigest.Hash
                bundle_sha256 = $bundleDigest.Hash
                exact_match = $true
            }
        }
        $git = Invoke-D32Git -Repository $fixture -Arguments @('init', '-q') -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash
        if ($git.ExitCode -ne 0) { throw 'trusted Git init failed' }
        [void](Invoke-D32Git -Repository $fixture -Arguments @('config', 'user.email', 'd32-selftest@example.invalid') -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash)
        [void](Invoke-D32Git -Repository $fixture -Arguments @('config', 'user.name', 'D32 Selftest') -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash)
        $git = Invoke-D32Git -Repository $fixture -Arguments @('add', '.') -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash
        if ($git.ExitCode -ne 0) { throw 'trusted Git add failed' }
        $git = Invoke-D32Git -Repository $fixture -Arguments @('commit', '-q', '-m', 'selftest fixture') -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash
        if ($git.ExitCode -ne 0) { throw 'trusted Git commit failed' }
        $head = (Invoke-D32Git -Repository $fixture -Arguments @('rev-parse', '--verify', 'HEAD') -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash).Text.Trim()
        $bundleDocument = [ordered]@{
            candidate_sha = $head
            source_clone = Get-D32AbsolutePath -Path $fixture
            bundle_path = Get-D32AbsolutePath -Path $bundleRoot
            build_targets = [ordered]@{
                vita = Get-D32AbsolutePath -Path (Join-Path $buildRoot 'vita')
                host = Get-D32AbsolutePath -Path (Join-Path $buildRoot 'host')
            }
            artifacts = @($bundleArtifacts)
            total_bytes = ($bundleArtifacts | ForEach-Object { [Int64]$_.build_bytes } | Measure-Object -Sum).Sum
            runtime_resources = @()
        }
        $bundleManifest = Join-Path $bundleRoot 'BUNDLE-MANIFEST.json'
        Write-D32Json -Path $bundleManifest -Value $bundleDocument
        $generatedResult = Invoke-D32GenerateManifest -Repository $fixture -Manifest $provenance -Image $image -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash
        Assert-D32SelfTest -Condition $generatedResult.Success -Name 'atomic generation on a missing target' -Failures $failures
        $generatedObject = [System.IO.File]::ReadAllText($provenance) | ConvertFrom-Json
        $sourceFormCorrect = $generatedObject.source_repo -ceq (Get-D32RustRepositoryPath -Path $fixture)
        $imageFormCorrect = -not (Test-D32Windows) -or $generatedObject.image_path.StartsWith('\\?\', [StringComparison]::Ordinal)
        Assert-D32SelfTest -Condition ($sourceFormCorrect -and $imageFormCorrect) -Name 'Host source_repo ordinary/image_path extended path asymmetry' -Failures $failures
        $validResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run') -Modes $null
        if (-not $validResult.Success) {
            foreach ($finding in $validResult.Findings) {
                Write-Host ("  VALID FIXTURE [{0}] {1}: {2}" -f $finding.Severity, $finding.Check, $finding.Message)
            }
        }
        Assert-D32SelfTest -Condition $validResult.Success -Name 'valid fixture aggregate validation' -Failures $failures
        $missingTrustResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run-missing-trust') -Modes $null
        Assert-D32SelfTest -Condition ((-not $missingTrustResult.Success) -and @($missingTrustResult.Findings | Where-Object { $_.Check -eq 'git.trusted-image' -and $_.Severity -eq 'ERROR' }).Count -eq 1) -Name 'validation requires explicit trusted Git path and hash' -Failures $failures

        $validJson = [System.IO.File]::ReadAllText($provenance)
        $missingField = $validJson | ConvertFrom-Json
        [void]$missingField.PSObject.Properties.Remove('git_status')
        Write-D32Json -Path $provenance -Value $missingField
        $missingResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run-2') -Modes $null
        Assert-D32SelfTest -Condition (-not $missingResult.Success) -Name 'missing provenance field is reported' -Failures $failures

        $wrongPath = $validJson | ConvertFrom-Json
        $wrongPath.image_path = [System.IO.Path]::GetFullPath($image)
        Write-D32Json -Path $provenance -Value $wrongPath
        $wrongPathResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run-3') -Modes $null
        Assert-D32SelfTest -Condition (-not $wrongPathResult.Success) -Name 'ordinary image path is rejected' -Failures $failures

        $wrongHash = $validJson | ConvertFrom-Json
        $wrongHash.image_sha256 = ('0' * 64)
        Write-D32Json -Path $provenance -Value $wrongHash
        $wrongHashResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run-4') -Modes $null
        Assert-D32SelfTest -Condition (-not $wrongHashResult.Success) -Name 'image hash mismatch is reported' -Failures $failures

        Write-D32Json -Path $provenance -Value ($validJson | ConvertFrom-Json)
        $dirtyMarker = Join-Path $fixture 'dirty-marker.txt'
        [System.IO.File]::WriteAllText($dirtyMarker, 'dirty')
        $dirtyResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run-5') -Modes $null
        Assert-D32SelfTest -Condition (-not $dirtyResult.Success) -Name 'dirty repository is reported' -Failures $failures
        Remove-Item -LiteralPath $dirtyMarker -Force

        $unknownModes = @($script:D32CanonicalModes + @('unknown-mode'))
        $unknownModeResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot (Join-Path $root 'new-run-6') -Modes $unknownModes
        Assert-D32SelfTest -Condition (-not $unknownModeResult.Success) -Name 'unknown mode is reported' -Failures $failures

        [System.IO.File]::WriteAllText($existing, 'sentinel')
        $before = [System.IO.File]::ReadAllText($existing)
        $existingResult = Invoke-D32GenerateManifest -Repository $fixture -Manifest $existing -Image $image -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash
        $after = [System.IO.File]::ReadAllText($existing)
        Assert-D32SelfTest -Condition ((-not $existingResult.Success) -and $before -ceq $after) -Name 'existing target is never overwritten' -Failures $failures

        $existingRunRoot = Join-Path $root 'existing-run'
        [void](New-Item -ItemType Directory -Path $existingRunRoot -Force)
        $existingRunResult = Invoke-D32Validation -Repository $fixture -Manifest $provenance -Image $image -BundleManifest $bundleManifest -TrustedGitPath $trustedGitPath -TrustedGitSha256 $trustedGitHash -ExpectedCandidateSha $head -Base $null -MergeBase $null -RunRoot $existingRunRoot -Modes $null
        Assert-D32SelfTest -Condition (-not $existingRunResult.Success) -Name 'existing run output root is rejected' -Failures $failures
        # The existing-run fixture is deliberately inside the owned root; the
        # final exact-marker cleanup removes the one self-test root.
    }
    catch {
        Write-Host 'SELFTEST ERROR: setup or assertion failed'
        [void]$failures.Add('setup or assertion failed')
    }
    finally {
        if ($rootOwned -and -not (Remove-D32OwnedTempRoot -Root $root -Marker $rootMarker -Token $rootToken)) {
            Write-Host 'SELFTEST ERROR: owned temp root failed exact-marker/reparse cleanup'
            [void]$failures.Add('owned temp root cleanup failed')
        }
    }
    if ($failures.Count -eq 0) {
        Write-Host 'D32 preflight self-test: PASS'
        return $true
    }
    Write-Host "D32 preflight self-test: BLOCKED ($($failures.Count) failure(s))"
    return $false
}

if ($SelfTest) {
    if (Invoke-D32SelfTest) { exit 0 }
    exit 1
}

if ([String]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}
if ([String]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $RepoRoot 'artifacts\d32-candidate-provenance.json'
}
if ([String]::IsNullOrWhiteSpace($ImagePath)) {
    $ImagePath = Join-Path $RepoRoot 'vita-agent\target\release\vita-agent.exe'
}
if ([String]::IsNullOrWhiteSpace($BundleManifestPath)) {
    $BundleManifestPath = Join-Path $RepoRoot 'artifacts\BUNDLE-MANIFEST.json'
}
if (-not $GenerateManifest -and -not $ValidateOnly) {
    $ValidateOnly = $true
}
if ($GenerateManifest -and $ValidateOnly) {
    Write-Output 'D32 preflight: -GenerateManifest and -ValidateOnly are mutually exclusive'
    exit 2
}

if ($GenerateManifest) {
    $generation = Invoke-D32GenerateManifest -Repository $RepoRoot -Manifest $ManifestPath -Image $ImagePath -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256
    Write-D32Result -Operation 'manifest generation' -Result $generation
    if ($generation.Success) { exit 0 }
    exit 1
}

$validation = Invoke-D32Validation -Repository $RepoRoot -Manifest $ManifestPath -Image $ImagePath -BundleManifest $BundleManifestPath -TrustedGitPath $TrustedGitPath -TrustedGitSha256 $TrustedGitSha256 -ExpectedCandidateSha $ExpectedSha -Base $BaseSha -MergeBase $MergeBaseSha -RunRoot $RunOutputRoot -Modes $RequestedModes
Write-D32Result -Operation 'preflight' -Result $validation
if ($validation.Success) { exit 0 }
exit 1
