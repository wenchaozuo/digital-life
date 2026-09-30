#Requires -Version 5.1
<#
.SYNOPSIS
Builds D32 fixture artifacts for one independently pinned clean candidate.

.DESCRIPTION
Operational runs require -PinnedGitPath, -PinnedGitSha256,
-ExpectedCandidateSha, -ToolchainProfilePath, and
-ExpectedToolchainProfileSha256. Git is invoked only from that absolute executable after
path, identity, and SHA-256 verification; inherited GIT_* variables and user
Git configuration are excluded. The expected SHA must be the exact clean HEAD.

Optional D31 recovery-helper build:
  -BuildD31RecoverySeeder
The fixed build is `cargo build --quiet --locked --manifest-path
<repo>/vita-agent/Cargo.toml --bin vita-agent --features d29-h9-test-helper
--target-dir <OutputRoot>\d31-recovery-seeder-target`. The script writes the
sibling `d31-recovery-seeder-build.json` and reports its path, SHA-256, and a
unique run ID; pass them independently to the D31 test as
D31_RECOVERY_SEEDER_RECORD_PATH, D31_RECOVERY_SEEDER_RECORD_SHA256, and
D31_RECOVERY_SEEDER_RUN_ID.

.PARAMETER PinnedGitPath
Absolute path to the caller-selected Git executable.
.PARAMETER PinnedGitSha256
Caller-computed SHA-256 of PinnedGitPath.
.PARAMETER ExpectedCandidateSha
Exact lowercase 40-character candidate HEAD SHA.
.PARAMETER ToolchainProfilePath
Absolute path to the caller-pinned D32_BUILD_TOOLCHAIN_PROFILE_V2 document.
.PARAMETER ExpectedToolchainProfileSha256
Independent lowercase SHA-256 pin for the toolchain profile bytes.
.PARAMETER BuildD31RecoverySeeder
Build the test-only D31 recovery seeder using the fixed feature and external target,
after a pinned locked fetch into a fresh external Cargo home.
.PARAMETER D32LauncherLibraryOnly
Load the native bounded-process launcher and retain this script's helper functions
in the dot-sourcing caller, then return without starting fixture builds.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$OutputRoot,
    [string]$ManifestPath,
    [string]$PinnedGitPath,
    [string]$PinnedGitSha256,
    [string]$ExpectedCandidateSha,
    [string]$ToolchainProfilePath,
    [string]$ExpectedToolchainProfileSha256,
    [string]$PowerShellModuleAuthorityPath,
    [string]$ExpectedPowerShellModuleAuthoritySha256,
    [AllowNull()][object]$Phase0OwnerBinding,
    [string]$VendoredProtocAuthorityPath,
    [string]$ExpectedVendoredProtocAuthoritySha256,
    [string]$TauriMacrosSourceAuthorityPath,
    [string]$ExpectedTauriMacrosSourceAuthoritySha256,
    [AllowNull()][object]$Phase0FixtureBuildCapacity,
    [switch]$BuildD31RecoverySeeder,
    [ValidateRange(1, 14400)]
    [int]$TimeoutSeconds = 600,
    [ValidateRange(1, 28800)]
    [int]$Phase0FixtureBuildTimeoutSeconds = 600,
    [ValidateRange(1, 16)]
    [int]$BuildJobs = 1,
    [switch]$D32LauncherLibraryOnly,
    [switch]$SelfTest
)

. ([IO.Path]::Combine($PSScriptRoot, 'd32-powershell-module-authority.ps1'))
$null = Initialize-D32PowerShellModuleAuthority -CallerProfilePath $ToolchainProfilePath `
    -CallerExpectedProfileSha256 $ExpectedToolchainProfileSha256 `
    -CallerModuleAuthorityPath $PowerShellModuleAuthorityPath -CallerExpectedModuleAuthoritySha256 $ExpectedPowerShellModuleAuthoritySha256 `
    -CallerCandidateSha $ExpectedCandidateSha -CallerRepository $RepoRoot -CallerGitPath $PinnedGitPath -CallerGitSha256 $PinnedGitSha256 `
    -EntryScriptPath $PSCommandPath -LocalSelfTestOnly:$SelfTest

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-D32FixtureTimeoutScope {
    param(
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [AllowNull()][object]$OwnerBinding,
        [bool]$BuildD31RecoverySeeder
    )

    if ($TimeoutSeconds -gt 3600 -and ($null -eq $OwnerBinding -or $BuildD31RecoverySeeder)) {
        throw 'PHASE0_TIMEOUT_SCOPE_BLOCKED: timeouts above 3600 seconds require the fixed Phase0 owner binding and cannot include the D31 recovery seeder'
    }
}

function Test-D32FixtureBuildBudgetInteger {
    param([AllowNull()][object]$Value)
    return ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64])
}

function Assert-D32FixtureBuildBudgetRecord {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Document,
        [Parameter(Mandatory = $true)][int]$ExpectedPhase0TimeoutSeconds
    )

    $expected = @('schema_version', 'record_type', 'phase0_command_timeout_seconds', 'fixture_build_timeout_seconds',
        'cargo_build_jobs', 'logical_processor_count', 'available_physical_memory_bytes', 'evidence_volume_free_bytes',
        'competing_target_writer_count', 'target_writer_check', 'checked_at_utc')
    $actual = @(Get-D32ObjectFieldNames -Object $Document)
    if ($actual.Count -ne $expected.Count -or
        @($actual | Where-Object { $_ -notin $expected }).Count -ne 0 -or
        @($expected | Where-Object { $_ -notin $actual }).Count -ne 0 -or
        -not (Test-D32FixtureBuildBudgetInteger -Value $Document.schema_version) -or [int]$Document.schema_version -ne 1 -or
        $Document.record_type -isnot [string] -or $Document.record_type -cne 'D32_PHASE0_FIXTURE_BUILD_BUDGET_V1' -or
        -not (Test-D32FixtureBuildBudgetInteger -Value $Document.phase0_command_timeout_seconds) -or [int64]$Document.phase0_command_timeout_seconds -ne $ExpectedPhase0TimeoutSeconds -or
        -not (Test-D32FixtureBuildBudgetInteger -Value $Document.fixture_build_timeout_seconds) -or [int64]$Document.fixture_build_timeout_seconds -ne 28800 -or
        -not (Test-D32FixtureBuildBudgetInteger -Value $Document.cargo_build_jobs) -or [int64]$Document.cargo_build_jobs -ne 4 -or
        -not (Test-D32FixtureBuildBudgetInteger -Value $Document.logical_processor_count) -or [int64]$Document.logical_processor_count -lt 8 -or
        -not (Test-D32FixtureBuildBudgetInteger -Value $Document.available_physical_memory_bytes) -or [int64]$Document.available_physical_memory_bytes -lt (12L * 1024L * 1024L * 1024L) -or
        -not (Test-D32FixtureBuildBudgetInteger -Value $Document.evidence_volume_free_bytes) -or [int64]$Document.evidence_volume_free_bytes -lt (200L * 1024L * 1024L * 1024L) -or
        -not (Test-D32FixtureBuildBudgetInteger -Value $Document.competing_target_writer_count) -or [int64]$Document.competing_target_writer_count -ne 0 -or
        $Document.target_writer_check -isnot [string] -or $Document.target_writer_check -cne 'Win32-CIM-active-build-process-census' -or
        $Document.checked_at_utc -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Document.checked_at_utc)) {
        throw 'FIXTURE_BUILD_BUDGET_INVALID: strict V1 budget, fixed timeout/jobs, or resource-preflight capacity is invalid'
    }
    $parsedAt = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse([string]$Document.checked_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsedAt)) {
        throw 'FIXTURE_BUILD_BUDGET_INVALID: checked_at_utc is not a round-trip timestamp'
    }
}

function Assert-D32FixtureBuildBudgetScope {
    param(
        [AllowNull()][object]$OwnerBinding,
        [bool]$BuildD31RecoverySeeder,
        [int]$TimeoutSeconds,
        [int]$FixtureBuildTimeoutSeconds,
        [int]$BuildJobs,
        [AllowNull()][object]$Capacity
    )

    if ($null -ne $OwnerBinding -and -not $BuildD31RecoverySeeder) {
        if ($TimeoutSeconds -ne 14400 -or $FixtureBuildTimeoutSeconds -ne 28800 -or $BuildJobs -ne 4 -or $null -eq $Capacity) {
            throw 'FIXTURE_BUILD_BUDGET_BLOCKED: owner-bound Phase0 requires 14400-second Phase0 commands, exactly 28800-second fixture builds, four Cargo jobs, and recorded capacity'
        }
        Assert-D32FixtureBuildBudgetRecord -Document $Capacity -ExpectedPhase0TimeoutSeconds $TimeoutSeconds
        return
    }
    if ($FixtureBuildTimeoutSeconds -ne 600 -or $BuildJobs -ne 1) {
        throw 'FIXTURE_BUILD_BUDGET_BLOCKED: standalone and D31-seeder modes remain limited to the 600-second/jobs-1 defaults'
    }
}

function Get-D32FixtureBuildMode {
    param(
        [AllowNull()][object]$OwnerBinding,
        [bool]$BuildD31RecoverySeeder
    )

    if ($BuildD31RecoverySeeder) { return 'D31Seeder' }
    if ($null -ne $OwnerBinding) { return 'Phase0' }
    return 'Standalone'
}

function Assert-D32FixtureBuildModeAuthority {
    param([Parameter(Mandatory = $true)][ValidateSet('Phase0', 'Standalone', 'D31Seeder')][string]$Mode)

    switch ($Mode) {
        'Phase0' { return }
        'Standalone' { throw 'STANDALONE_FIXTURE_AUTHORITY_BLOCKED: the current locked source/image grants are Phase0/Phase1-only; a standalone run must not reuse them or emit Phase0 provenance' }
        'D31Seeder' { throw 'D31_RECOVERY_SEEDER_AUTHORITY_BLOCKED: the post-aggregate seeder requires its separate fresh run/home owner marker, per-run grant, and D32 companion attestation; Phase0 authority cannot be reused' }
    }
}

function Test-D32FixtureBuildModeEmitsPhase0Provenance {
    param([Parameter(Mandatory = $true)][ValidateSet('Phase0', 'Standalone', 'D31Seeder')][string]$Mode)
    return ($Mode -ceq 'Phase0')
}

$script:OwnerMarkerName = '.d32-fixture-prebuild-owned'
$script:OwnerMarker = 'D32_FIXTURE_PREBUILD_OWNER_V1'
$script:SchemaVersion = 3
$script:D32FixtureProcessTreePolicy = 'native Job Object kill-on-close, then verify every captured identity and relevant descendant'
$script:D32PinnedGitIdentitySelfTestOverride = $null
$script:D32LastProcessEvidence = $null
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $script:ScriptRoot 'd32-build-toolchain-profile.ps1')
. (Join-Path $script:ScriptRoot 'd32-vendored-protoc-authority.ps1')

$script:FixtureSpecs = @(
    [ordered]@{
        name             = 'd29h1-authority-fixture'
        project          = 'src-tauri'
        manifest         = 'src-tauri/Cargo.toml'
        binary           = 'd29h1-authority-fixture'
        features         = @('d29-h1-host-fixture')
        artifact         = 'src-tauri/target/debug/d29h1-authority-fixture.exe'
    },
    [ordered]@{
        name             = 'd29h7-authority-fixture'
        project          = 'src-tauri'
        manifest         = 'src-tauri/Cargo.toml'
        binary           = 'd29h7-authority-fixture'
        features         = @('d29-h7-host-fixture')
        artifact         = 'src-tauri/target/debug/d29h7-authority-fixture.exe'
    },
    [ordered]@{
        name             = 'd29h7-process-fixture'
        project          = 'vita-agent'
        manifest         = 'vita-agent/Cargo.toml'
        binary           = 'd29h7-process-fixture'
        features         = @()
        artifact         = 'vita-agent/target/debug/d29h7-process-fixture.exe'
    },
    [ordered]@{
        name             = 'd29h7-git-helper-fixture'
        project          = 'vita-agent'
        manifest         = 'vita-agent/Cargo.toml'
        binary           = 'd29h7-git-helper-fixture'
        features         = @('d29-h7-test-helper')
        artifact         = 'vita-agent/target/debug/d29h7-git-helper-fixture.exe'
    },
    [ordered]@{
        name             = 'd32a-sandbox-fixture'
        project          = 'vita-agent'
        manifest         = 'vita-agent/Cargo.toml'
        binary           = 'd32a-sandbox-fixture'
        features         = @('d32-a-test-helper')
        artifact         = 'vita-agent/target/debug/d32a-sandbox-fixture.exe'
    }
)

function Get-D32FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path))
}

function Test-D32PathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $pathFull = (Get-D32FullPath $Path).TrimEnd('\')
    $rootFull = (Get-D32FullPath $Root).TrimEnd('\')
    if ($pathFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $pathFull.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Ensure-D32OwnedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Get-D32FullPath $Path
    if (Test-Path -LiteralPath $full) {
        if (-not (Test-Path -LiteralPath $full -PathType Container)) {
            throw "OUTPUT_NOT_OWNED: output root is not a directory: $full"
        }
        $markerPath = Join-Path $full $script:OwnerMarkerName
        if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf) -or
            ([IO.File]::ReadAllText($markerPath).Trim() -ne $script:OwnerMarker)) {
            throw "OUTPUT_NOT_OWNED: refusing to reuse an unmarked output directory: $full"
        }
        return $full
    }

    New-Item -ItemType Directory -Path $full -Force:$false | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $full $script:OwnerMarkerName),
        $script:OwnerMarker,
        [Text.UTF8Encoding]::new($false)
    )
    return $full
}

function Assert-D32ManifestDestination {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OwnedRoot
    )

    $full = Get-D32FullPath $Path
    if (-not (Test-D32PathWithin -Path $full -Root $OwnedRoot) -or
        $full.Equals((Get-D32FullPath $OwnedRoot), [StringComparison]::OrdinalIgnoreCase)) {
        throw "OUTPUT_NOT_OWNED: manifest must be inside the owned output root: $full"
    }
    $parent = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force:$false | Out-Null
    }
    return $full
}

function Remove-D32OwnedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Get-D32FullPath $Path
    $markerPath = Join-Path $full $script:OwnerMarkerName
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf) -or
        ([IO.File]::ReadAllText($markerPath).Trim() -ne $script:OwnerMarker)) {
        throw "OUTPUT_NOT_OWNED: refusing to remove an unmarked directory: $full"
    }
    Remove-Item -LiteralPath $full -Recurse -Force
}

function Assert-D32NoReparsePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$AllowMissingLeaf
    )

    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw "PATH_INVALID: path must be absolute: $Path"
    }
    $full = Get-D32FullPath $Path
    $root = [IO.Path]::GetPathRoot($full)
    if ([String]::IsNullOrWhiteSpace($root)) {
        throw "PATH_INVALID: path has no volume root: $full"
    }
    $current = $root
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "PATH_REPARSE: path root is a reparse point: $root"
    }
    $relative = $full.Substring($root.Length)
    $components = @($relative -split '[\\/]+' | Where-Object { -not [String]::IsNullOrWhiteSpace($_) })
    for ($index = 0; $index -lt $components.Count; $index++) {
        $current = Join-Path $current $components[$index]
        try {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        }
        catch {
            if ($AllowMissingLeaf -and $index -eq ($components.Count - 1) -and
                -not (Test-Path -LiteralPath $current)) {
                return $full
            }
            throw "PATH_INVALID: path component is unavailable: $current"
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "PATH_REPARSE: path contains a reparse component: $current"
        }
        if ($index -lt ($components.Count - 1) -and
            ($item.Attributes -band [IO.FileAttributes]::Directory) -eq 0) {
            throw "PATH_INVALID: non-directory path component: $current"
        }
    }
    return $full
}

function Get-D32D31RecoverySeederPaths {
    param([Parameter(Mandatory = $true)][string]$OutputRoot)

    $root = Assert-D32NoReparsePath -Path $OutputRoot
    $target = Assert-D32NoReparsePath -Path (Join-Path $root 'd31-recovery-seeder-target') -AllowMissingLeaf
    $record = Assert-D32NoReparsePath -Path (Join-Path $root 'd31-recovery-seeder-build.json') -AllowMissingLeaf
    if ((Split-Path -Parent $target) -ne (Split-Path -Parent $record)) {
        throw 'D31_RECOVERY_SEEDER_OUTPUT_INVALID: target and build record must be canonical siblings beneath OutputRoot'
    }
    return [ordered]@{
        target = $target
        record = $record
    }
}

function Initialize-D32ArtifactIdentityType {
    if ($null -ne ([System.Management.Automation.PSTypeName]'D32FixtureArtifactIdentityV1').Type) {
        return
    }
    $savedLib = [Environment]::GetEnvironmentVariable('LIB', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('LIB', $null, 'Process')
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

[StructLayout(LayoutKind.Sequential)]
public struct D32NativeFileIdentityV1
{
    public uint volume_serial;
    public ulong file_index;
    public ulong file_size;
    public uint file_attributes;
    public uint link_count;
}

public struct D32NativeFileIdInfoV1
{
    public ulong volume_serial;
    public string file_id_hex;
}

public static class D32FixtureArtifactIdentityV1
{
    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime { public uint Low; public uint High; }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public FileTime CreationTime;
        public FileTime LastAccessTime;
        public FileTime LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle, out ByHandleFileInformation information);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle handle, int fileInformationClass, IntPtr information, uint bufferSize);

    public static D32NativeFileIdentityV1 Read(SafeFileHandle handle)
    {
        ByHandleFileInformation information;
        if (!GetFileInformationByHandle(handle, out information))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        return new D32NativeFileIdentityV1 {
            volume_serial = information.VolumeSerialNumber,
            file_index = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow,
            file_size = ((ulong)information.FileSizeHigh << 32) | information.FileSizeLow,
            file_attributes = information.FileAttributes,
            link_count = information.NumberOfLinks
        };
    }

    public static D32NativeFileIdInfoV1 ReadFileId(SafeFileHandle handle)
    {
        const int FileIdInfo = 18;
        const int BufferSize = 24;
        IntPtr buffer = Marshal.AllocHGlobal(BufferSize);
        try
        {
            if (!GetFileInformationByHandleEx(handle, FileIdInfo, buffer, BufferSize))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            ulong volume = unchecked((ulong)Marshal.ReadInt64(buffer, 0));
            byte[] id = new byte[16];
            Marshal.Copy(IntPtr.Add(buffer, 8), id, 0, id.Length);
            string hex = BitConverter.ToString(id).Replace("-", "").ToLowerInvariant();
            return new D32NativeFileIdInfoV1 { volume_serial = volume, file_id_hex = hex };
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
'@
    }
    finally {
        [Environment]::SetEnvironmentVariable('LIB', $savedLib, 'Process')
    }
}

function Get-D32NativeFileIdentity {
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)

    Initialize-D32ArtifactIdentityType
    return [D32FixtureArtifactIdentityV1]::Read($Stream.SafeFileHandle)
}

function Get-D32NativeFileIdInfo {
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)

    Initialize-D32ArtifactIdentityType
    return [D32FixtureArtifactIdentityV1]::ReadFileId($Stream.SafeFileHandle)
}

function Test-D32SameNativeFileIdentity {
    param(
        [Parameter(Mandatory = $true)][object]$Left,
        [Parameter(Mandatory = $true)][object]$Right
    )

    return ([uint32]$Left.volume_serial -eq [uint32]$Right.volume_serial -and
        [uint64]$Left.file_index -eq [uint64]$Right.file_index -and
        [uint64]$Left.file_size -eq [uint64]$Right.file_size -and
        [uint32]$Left.file_attributes -eq [uint32]$Right.file_attributes -and
        [uint32]$Left.link_count -eq [uint32]$Right.link_count)
}

function Test-D32SameArtifactFileIdentity {
    param(
        [Parameter(Mandatory = $true)][object]$Left,
        [Parameter(Mandatory = $true)][object]$Right
    )

    return ([uint32]$Left.volume_serial -eq [uint32]$Right.volume_serial -and
        [uint64]$Left.file_index -eq [uint64]$Right.file_index -and
        [uint64]$Left.file_size -eq [uint64]$Right.file_size -and
        [bool]$Left.directory -eq [bool]$Right.directory -and
        [bool]$Left.reparse -eq [bool]$Right.reparse)
}

function ConvertTo-D32FileIdentityRecord {
    param([Parameter(Mandatory = $true)][object]$Identity)

    $reparse = ([uint32]$Identity.file_attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0
    $directory = ([uint32]$Identity.file_attributes -band [uint32][IO.FileAttributes]::Directory) -ne 0
    if ($reparse -or $directory) {
        throw 'ARTIFACT_IDENTITY_INVALID: artifact handle is not a non-reparse regular file'
    }
    return [ordered]@{
        volume_serial = [uint32]$Identity.volume_serial
        file_index = [uint64]$Identity.file_index
        file_size = [uint64]$Identity.file_size
        directory = $false
        reparse = $false
    }
}

function Get-D32BoundArtifact {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Assert-D32NoReparsePath -Path $Path
    $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $before = Get-D32NativeFileIdentity $stream
        $beforeRecord = ConvertTo-D32FileIdentityRecord $before
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $hasher.ComputeHash($stream)
        }
        finally {
            $hasher.Dispose()
        }
        $length = [uint64]$stream.Length
        $after = Get-D32NativeFileIdentity $stream
        if (-not (Test-D32SameNativeFileIdentity -Left $before -Right $after) -or
            $length -ne [uint64]$after.file_size) {
            throw "ARTIFACT_IDENTITY_CHANGED: file identity changed while hashing: $full"
        }
        $stream.Dispose()
        $reopened = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $rebound = Get-D32NativeFileIdentity $reopened
        }
        finally {
            $reopened.Dispose()
        }
        [void](Assert-D32NoReparsePath -Path $full)
        if (-not (Test-D32SameNativeFileIdentity -Left $before -Right $rebound)) {
            throw "ARTIFACT_IDENTITY_CHANGED: path rebound to another file after hashing: $full"
        }
        return [ordered]@{
            path = $full
            bytes = $length
            sha256 = [BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant()
            file_identity = $beforeRecord
        }
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-D32BoundArtifactWithFileId {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Assert-D32NoReparsePath -Path $Path
    $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $before = Get-D32NativeFileIdentity $stream
        $beforeRecord = ConvertTo-D32FileIdentityRecord $before
        $beforeFileId = Get-D32NativeFileIdInfo -Stream $stream
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $hashBytes = $hasher.ComputeHash($stream) }
        finally { $hasher.Dispose() }
        $length = [uint64]$stream.Length
        $after = Get-D32NativeFileIdentity $stream
        $afterFileId = Get-D32NativeFileIdInfo -Stream $stream
        if (-not (Test-D32SameNativeFileIdentity -Left $before -Right $after) -or
            $length -ne [uint64]$after.file_size -or
            [uint64]$beforeFileId.volume_serial -ne [uint64]$afterFileId.volume_serial -or
            [string]$beforeFileId.file_id_hex -cne [string]$afterFileId.file_id_hex) {
            throw "ARTIFACT_IDENTITY_CHANGED: file identity changed while hashing: $full"
        }
        $pathSnapshot = Get-D32BoundArtifact -Path $full
        if ($pathSnapshot.sha256 -cne [BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant() -or
            -not (Test-D32SameArtifactFileIdentity -Left $pathSnapshot.file_identity -Right $beforeRecord)) {
            throw "ARTIFACT_IDENTITY_CHANGED: path did not remain bound to the opened manifest handle: $full"
        }
        return [ordered]@{
            path = $full
            bytes = $length
            sha256 = [BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant()
            file_identity = $beforeRecord
            volume_serial_hex = ([uint64]$beforeFileId.volume_serial).ToString('x16')
            file_id_hex = [string]$beforeFileId.file_id_hex
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-D32PinnedGit {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )

    if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'GIT_PIN_INVALID: PinnedGitSha256 must be a 64-character SHA-256 hex digest'
    }
    $full = Assert-D32NoReparsePath -Path $Path
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "GIT_PIN_INVALID: pinned Git executable is not a file: $full"
    }
    $artifact = Get-D32BoundArtifactWithFileId $full
    $expected = $ExpectedSha256.ToLowerInvariant()
    if ($artifact.sha256 -ne $expected) {
        throw 'GIT_PIN_INVALID: pinned Git executable did not match its independent SHA-256'
    }
    return [ordered]@{
        path = $full
        sha256 = $expected
        bytes = [uint64]$artifact.bytes
        volume_serial_hex = [string]$artifact.volume_serial_hex
        file_id_hex = [string]$artifact.file_id_hex
        file_identity = $artifact.file_identity
    }
}

function Assert-D32ApprovedPinnedGitRoot {
    $approved = [ordered]@{
        path = 'E:\Program Files\Git\mingw64\bin\git.exe'
        sha256 = '1f2ee2de971b6d0a7a13f053014998b66c22df47f30f1907a767346392eb8d78'
        bytes = [uint64]4238224
        volume_serial_hex = '749614a1961465c0'
        file_id_hex = '4aff000000000b000000000000000000'
    }
    if ($null -eq $script:PinnedGit) {
        throw 'GIT_ROOT_NOT_APPROVED: caller-pinned Git root is unavailable'
    }
    $isApproved = [string]::Equals((Get-D32FullPath ([string]$script:PinnedGit.path)), $approved.path, [StringComparison]::OrdinalIgnoreCase) -and
        [string]$script:PinnedGit.sha256 -ceq $approved.sha256 -and
        [uint64]$script:PinnedGit.bytes -eq [uint64]$approved.bytes -and
        [string]$script:PinnedGit.volume_serial_hex -ceq $approved.volume_serial_hex -and
        [string]$script:PinnedGit.file_id_hex -ceq $approved.file_id_hex
    if ($isApproved) { return }

    # This narrowly scoped alternate pin exists only to exercise the installed
    # wrapper's blocked descendant behavior inside the explicit identity self-test.
    $negativeTestPin = $script:D32PinnedGitIdentitySelfTestOverride
    $isExactNegativeTestPin = $null -ne $negativeTestPin -and
        [string]::Equals((Get-D32FullPath ([string]$script:PinnedGit.path)), [string]$negativeTestPin.path, [StringComparison]::OrdinalIgnoreCase) -and
        [string]$script:PinnedGit.sha256 -ceq [string]$negativeTestPin.sha256 -and
        [uint64]$script:PinnedGit.bytes -eq [uint64]$negativeTestPin.bytes -and
        [string]$script:PinnedGit.volume_serial_hex -ceq [string]$negativeTestPin.volume_serial_hex -and
        [string]$script:PinnedGit.file_id_hex -ceq [string]$negativeTestPin.file_id_hex
    if (-not $isExactNegativeTestPin) {
        throw 'GIT_ROOT_NOT_APPROVED: only the Coordinator-bound direct Git root identity is launchable'
    }
}

function Assert-D32PinnedGitCurrent {
    if ($null -eq $script:PinnedGit) {
        throw 'GIT_PIN_REQUIRED: operational Git calls require the caller-supplied path and SHA-256 pins'
    }
    $artifact = Get-D32BoundArtifactWithFileId $script:PinnedGit.path
    if ($artifact.sha256 -ne $script:PinnedGit.sha256 -or
        [uint64]$artifact.bytes -ne [uint64]$script:PinnedGit.bytes -or
        [string]$artifact.volume_serial_hex -cne [string]$script:PinnedGit.volume_serial_hex -or
        [string]$artifact.file_id_hex -cne [string]$script:PinnedGit.file_id_hex -or
        -not (Test-D32SameArtifactFileIdentity -Left $artifact.file_identity -Right $script:PinnedGit.file_identity)) {
        throw 'GIT_PIN_CHANGED: pinned Git executable bytes, SHA-256, volume, file ID, or native identity changed'
    }
}

function Initialize-D32PinnedGitHandleType {
    if ('D32PinnedGitImageHandleV1' -as [type]) { return }
    $savedLib = [Environment]::GetEnvironmentVariable('LIB', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('LIB', $null, 'Process')
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class D32PinnedGitImageHandleV1
{
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    public static FileStream OpenReadLocked(string path)
    {
        SafeFileHandle handle = CreateFileW(
            path, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (handle == null || handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            if (handle != null) handle.Dispose();
            throw new Win32Exception(error, "CreateFileW pinned Git image open failed (Win32 error " + error + ")");
        }
        try { return new FileStream(handle, FileAccess.Read); }
        catch { handle.Dispose(); throw; }
    }
}
'@ -Language CSharp
    }
    finally {
        [Environment]::SetEnvironmentVariable('LIB', $savedLib, 'Process')
    }
}

function Open-D32PinnedGitHandle {
    Assert-D32PinnedGitCurrent
    Initialize-D32PinnedGitHandleType
    $stream = [D32PinnedGitImageHandleV1]::OpenReadLocked($script:PinnedGit.path)
    try {
        $identity = Get-D32NativeFileIdentity $stream
        $identityRecord = ConvertTo-D32FileIdentityRecord $identity
        $fileId = Get-D32NativeFileIdInfo -Stream $stream
        $snapshot = Get-D32BoundArtifactWithFileId $script:PinnedGit.path
        if ($snapshot.sha256 -cne $script:PinnedGit.sha256 -or
            [uint64]$snapshot.bytes -ne [uint64]$script:PinnedGit.bytes -or
            [string]$snapshot.volume_serial_hex -cne [string]$script:PinnedGit.volume_serial_hex -or
            [string]$snapshot.file_id_hex -cne [string]$script:PinnedGit.file_id_hex -or
            -not (Test-D32SameArtifactFileIdentity -Left $identityRecord -Right $script:PinnedGit.file_identity) -or
            -not (Test-D32SameArtifactFileIdentity -Left $snapshot.file_identity -Right $identityRecord) -or
            [string]([uint64]$fileId.volume_serial).ToString('x16') -cne [string]$script:PinnedGit.volume_serial_hex -or
            [string]$fileId.file_id_hex -cne [string]$script:PinnedGit.file_id_hex) {
            throw 'GIT_PIN_CHANGED: pinned Git changed before the retained executable handle was acquired'
        }
        return $stream
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Initialize-D32NativeProcessIdentityType {
    if ('D32NativeProcessIdentityV1' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public sealed class D32NativeProcessIdentityRecordV1 {
    public int ProcessId;
    public int ParentProcessId;
    public string Name;
    public string ImagePath;
    public string CommandLine;
    public string CreationDate;
    public string ObservedAtUtc;
    public bool IdentityVerified;
}

public static class D32NativeProcessIdentityV1 {
    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME { public uint Low; public uint High; }

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern uint GetProcessId(IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool GetProcessTimes(IntPtr process, out FILETIME creation, out FILETIME exit, out FILETIME kernel, out FILETIME user);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder imagePath, ref uint size);

    public static D32NativeProcessIdentityRecordV1 Query(IntPtr processHandle, int parentProcessId, string commandLine) {
        if (IntPtr.Size != 8) throw new PlatformNotSupportedException("D32_NATIVE_PROCESS_IDENTITY_UNAVAILABLE: x64 PowerShell is required");
        if (processHandle == IntPtr.Zero || processHandle == new IntPtr(-1)) throw new InvalidOperationException("D32_NATIVE_PROCESS_IDENTITY_UNAVAILABLE: retained process handle is invalid");
        if (parentProcessId <= 0) throw new InvalidOperationException("D32_NATIVE_PROCESS_IDENTITY_UNAVAILABLE: caller parent process ID is invalid");
        if (String.IsNullOrWhiteSpace(commandLine)) throw new InvalidOperationException("D32_NATIVE_PROCESS_IDENTITY_UNAVAILABLE: caller launch command line is empty");

        uint handlePid = GetProcessId(processHandle);
        if (handlePid == 0 || handlePid > Int32.MaxValue)
            throw new InvalidOperationException("D32_NATIVE_PROCESS_IDENTITY_UNAVAILABLE: GetProcessId returned an invalid value for the retained process handle");
        int nativePid = (int)handlePid;
        FILETIME creation, exit, kernel, user;
        if (!GetProcessTimes(processHandle, out creation, out exit, out kernel, out user))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "D32_NATIVE_PROCESS_IDENTITY_UNAVAILABLE: GetProcessTimes failed");
        long creationFileTime = unchecked((long)(((ulong)creation.High << 32) | creation.Low));
        if (creationFileTime <= 0) throw new InvalidOperationException("D32_NATIVE_PROCESS_IDENTITY_UNAVAILABLE: process creation time is invalid");

        StringBuilder path = new StringBuilder(32768);
        uint pathLength = (uint)path.Capacity;
        if (!QueryFullProcessImageNameW(processHandle, 0, path, ref pathLength) || pathLength == 0)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "D32_NATIVE_PROCESS_IDENTITY_UNAVAILABLE: QueryFullProcessImageNameW failed");
        string imagePath = path.ToString();
        string imageName = Path.GetFileName(imagePath);
        if (String.IsNullOrWhiteSpace(imagePath) || String.IsNullOrWhiteSpace(imageName))
            throw new InvalidOperationException("D32_NATIVE_PROCESS_IDENTITY_UNAVAILABLE: process image name or path is empty");

        // PID, image path, and creation time are read through stable handle-based Kernel32 APIs.
        // Parent PID and argv come from this caller's exact ProcessStartInfo launch inputs; no
        // undocumented PEB/process-information class is used as identity evidence.
        return new D32NativeProcessIdentityRecordV1 {
            ProcessId = nativePid,
            ParentProcessId = parentProcessId,
            Name = imageName,
            ImagePath = imagePath,
            CommandLine = commandLine,
            CreationDate = DateTime.FromFileTimeUtc(creationFileTime).ToString("o", CultureInfo.InvariantCulture),
            ObservedAtUtc = DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture),
            IdentityVerified = true
        };
    }
}
'@ -ErrorAction Stop | Out-Null
}

function Assert-D32NativeProcessIdentityRecord {
    param(
        [Parameter(Mandatory = $true)][object]$ProcessIdentity,
        [Parameter(Mandatory = $true)][int]$ExpectedProcessId,
        [Parameter(Mandatory = $true)][int]$ExpectedParentProcessId,
        [Parameter(Mandatory = $true)][string]$ExpectedImagePath,
        [Parameter(Mandatory = $true)][string]$ExpectedCommandLine,
        [Parameter(Mandatory = $true)][DateTime]$ExpectedStartTime
    )

    if ($ExpectedProcessId -le 0 -or $ExpectedParentProcessId -le 0 -or
        $ProcessIdentity.IdentityVerified -isnot [bool] -or -not $ProcessIdentity.IdentityVerified -or
        $ProcessIdentity.ProcessId -isnot [int] -or [int]$ProcessIdentity.ProcessId -ne $ExpectedProcessId -or
        $ProcessIdentity.ParentProcessId -isnot [int] -or [int]$ProcessIdentity.ParentProcessId -ne $ExpectedParentProcessId -or
        $ProcessIdentity.Name -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$ProcessIdentity.Name) -or
        $ProcessIdentity.ImagePath -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$ProcessIdentity.ImagePath) -or
        $ProcessIdentity.CommandLine -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$ProcessIdentity.CommandLine) -or
        $ProcessIdentity.CreationDate -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$ProcessIdentity.CreationDate) -or
        $ProcessIdentity.ObservedAtUtc -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$ProcessIdentity.ObservedAtUtc)) {
        throw 'PROCESS_IDENTITY_MISMATCH: handle-bound process identity is incomplete or PID/parent differs'
    }

    $expectedFullPath = Get-D32FullPath $ExpectedImagePath
    if (-not [string]::Equals([string]$ProcessIdentity.Name, [IO.Path]::GetFileName($expectedFullPath), [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals((Get-D32FullPath ([string]$ProcessIdentity.ImagePath)), $expectedFullPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PROCESS_IDENTITY_MISMATCH: handle-bound process image name or path differs from the pinned image'
    }
    if (-not [string]::Equals([string]$ProcessIdentity.CommandLine, $ExpectedCommandLine, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PROCESS_IDENTITY_MISMATCH: handle-bound process command line differs from the exact requested argv'
    }

    try {
        $observedStart = [DateTime]::Parse([string]$ProcessIdentity.CreationDate,
            [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        $observedAt = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse([string]$ProcessIdentity.ObservedAtUtc,
                [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$observedAt)) {
            throw 'invalid observation timestamp'
        }
    }
    catch { throw 'PROCESS_IDENTITY_MISMATCH: handle-bound creation or observation timestamp is malformed' }
    $expectedStartUtc = $ExpectedStartTime.ToUniversalTime()
    if ($observedStart.Kind -ne [DateTimeKind]::Utc -or
        [Math]::Abs(($observedStart - $expectedStartUtc).Ticks) -gt [TimeSpan]::TicksPerMillisecond -or
        $observedAt.UtcDateTime -lt $observedStart -or $observedAt -gt [DateTimeOffset]::UtcNow.AddSeconds(1)) {
        throw 'PROCESS_IDENTITY_MISMATCH: handle-bound creation time differs from the retained Process handle or observation time is invalid'
    }
    return $ProcessIdentity
}

function Assert-D32PinnedGitProcessIdentity {
    param(
        [Parameter(Mandatory = $true)][object]$Trace,
        [Parameter(Mandatory = $true)][object]$Cleanup,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][int]$ExpectedParentProcessId,
        [Parameter(Mandatory = $true)][object[]]$ApprovedChildImages
    )

    Assert-D32ApprovedPinnedGitRoot
    if ($null -eq $Cleanup -or -not [bool]$Cleanup.CleanupSucceeded -or
        -not [bool]$Cleanup.JobCloseSucceeded -or -not [bool]$Cleanup.JobTerminateCallSucceeded -or
        -not [bool]$Cleanup.JobActiveProcessCountVerified -or [uint32]$Cleanup.JobActiveProcessCount -ne 0 -or
        -not [bool]$Cleanup.ProcessWaitSignaled -or -not [bool]$Cleanup.DebuggerThreadExited -or
        -not [bool]$Cleanup.DebuggerThreadJoined -or -not [bool]$Cleanup.DebuggerKillOnExitEnabled -or
        -not [bool]$Cleanup.RetainedProcessHandlesSignaled -or
        -not [bool]$Cleanup.DebuggerAssociationQueryVerified -or -not [bool]$Cleanup.DebuggerAssociationAbsent) {
        throw 'GIT_PROCESS_CLEANUP_FAILED: pinned Git process Job, retained-handle, debugger-thread, or zero-active-process cleanup proof is incomplete'
    }
    if ($null -eq $Trace -or $Trace.RecordType -cne 'D32_DEBUG_JOB_PROCESS_TRACE_V2' -or
        [int]$Trace.SchemaVersion -ne 2 -or $Trace.State -cne 'COMPLETED' -or
        -not [bool]$Trace.AccountingConsistent -or -not [bool]$Trace.EventChainComplete -or
        -not [bool]$Trace.DedicatedDebuggerThread -or -not [bool]$Trace.DebuggerKillOnExitEnabled -or
        -not [bool]$Trace.RootResumedAfterKillOnExit -or -not [bool]$Trace.DebuggerThreadExited -or
        -not [bool]$Trace.DebuggerThreadJoined -or -not [bool]$Trace.RetainedProcessHandlesSignaled -or
        -not [bool]$Trace.DebuggerAssociationQueryVerified -or -not [bool]$Trace.DebuggerAssociationAbsent -or
        -not [bool]$Trace.JobAccountingVerified -or
        [int]$Trace.ProcessCreateEventCount -lt 1 -or [int]$Trace.ProcessCreateEventCount -gt 2 -or
        [int]$Trace.ProcessExitEventCount -ne [int]$Trace.ProcessCreateEventCount -or
        [int]$Trace.ProcessEventCount -ne (2 * [int]$Trace.ProcessCreateEventCount) -or
        [int]$Trace.JobTotalProcesses -ne [int]$Trace.ProcessCreateEventCount -or [int]$Trace.JobActiveProcesses -ne 0 -or
        [int]$Trace.UncontinuedCreateProcessId -ne 0 -or [int]$Trace.UncontinuedCreateContinueCallCount -ne 0 -or
        @($Trace.ProcessEvents).Count -ne [int]$Trace.ProcessEventCount -or
        @($Trace.Processes).Count -ne [int]$Trace.ProcessCreateEventCount -or
        @($ApprovedChildImages).Count -ne 1) {
        throw "GIT_PROCESS_IDENTITY_MISMATCH: pinned Git process trace is incomplete, ambiguous, or contains an unexpected descendant (state=$($Trace.State); create=$($Trace.ProcessCreateEventCount); exit=$($Trace.ProcessExitEventCount); events=$($Trace.ProcessEventCount); total=$($Trace.JobTotalProcesses); active=$($Trace.JobActiveProcesses); processes=$(@($Trace.Processes).Count); eventRecords=$(@($Trace.ProcessEvents).Count); approvedChildImages=$(@($ApprovedChildImages).Count); block=$($Trace.BlockReason))"
    }

    $approvedChild = @($ApprovedChildImages)[0]
    foreach ($propertyName in @('Path', 'Bytes', 'Sha256', 'VolumeSerialHex', 'FileIdHex')) {
        if ($null -eq $approvedChild.PSObject.Properties[$propertyName] -or
            [String]::IsNullOrWhiteSpace([string]$approvedChild.$propertyName)) {
            throw 'GIT_PROCESS_IDENTITY_MISMATCH: caller-pinned Windows child-image identity is incomplete'
        }
    }
    $approvedChildPath = Get-D32FullPath ([string]$approvedChild.Path)
    if (-not [string]::Equals([IO.Path]::GetFileName($approvedChildPath), 'conhost.exe', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'GIT_PROCESS_IDENTITY_MISMATCH: caller-pinned Git child inventory is not the single approved conhost image'
    }

    $expectedPath = Get-D32FullPath $script:PinnedGit.path
    $expectedCommandLine = ConvertTo-D32CommandLine (@($expectedPath) + $Arguments)
    if (-not [string]::Equals($CommandLine, $expectedCommandLine, [StringComparison]::Ordinal)) {
        throw 'GIT_PROCESS_IDENTITY_MISMATCH: CreateProcessW command line differs from the exact caller-requested Git argv'
    }

    if ([int]$Trace.DebuggerProcessId -ne $ExpectedParentProcessId) {
        throw 'GIT_PROCESS_IDENTITY_MISMATCH: debug trace belongs to a different runner process'
    }
    $roots = @($Trace.Processes | Where-Object {
        [int]$_.ParentProcessId -eq $ExpectedParentProcessId -and
        [long]$_.ParentCreationFileTime -eq [long]$Trace.DebuggerCreationFileTime
    })
    if ($roots.Count -ne 1) { throw 'GIT_PROCESS_IDENTITY_MISMATCH: trace does not contain one exact pinned Git root identity' }
    $identity = $roots[0]
    $children = @($Trace.Processes | Where-Object { [int]$_.ProcessId -ne [int]$identity.ProcessId })
    if ($children.Count -gt 1) { throw 'GIT_PROCESS_IDENTITY_MISMATCH: pinned Git trace contains more than one child process' }
    if ($children.Count -eq 1) {
        $child = $children[0]
        if ([int]$child.ParentProcessId -ne [int]$identity.ProcessId -or
            [long]$child.ParentCreationFileTime -ne [long]$identity.CreationFileTime -or
            -not [bool]$child.ImageVerified -or -not [bool]$child.Exited -or
            -not [string]::Equals((Get-D32FullPath ([string]$child.ImagePath)), $approvedChildPath, [StringComparison]::OrdinalIgnoreCase) -or
            [long]$child.Bytes -ne [long]$approvedChild.Bytes -or [string]$child.Sha256 -cne [string]$approvedChild.Sha256 -or
            [string]$child.VolumeSerialHex -cne [string]$approvedChild.VolumeSerialHex -or
            [string]$child.FileIdHex -cne [string]$approvedChild.FileIdHex) {
            throw 'GIT_PROCESS_IDENTITY_MISMATCH: Git child process is not the exact caller-pinned Windows conhost image and direct descendant'
        }
    }
    foreach ($processIdentity in @($identity) + $children) {
        $createMatches = @($Trace.ProcessEvents | Where-Object {
            $_.Kind -ceq 'CREATE' -and [int]$_.ProcessId -eq [int]$processIdentity.ProcessId -and
            [long]$_.CreationFileTime -eq [long]$processIdentity.CreationFileTime
        })
        $exitMatches = @($Trace.ProcessEvents | Where-Object {
            $_.Kind -ceq 'EXIT' -and [int]$_.ProcessId -eq [int]$processIdentity.ProcessId -and
            [long]$_.CreationFileTime -eq [long]$processIdentity.CreationFileTime
        })
        if ($createMatches.Count -ne 1 -or $exitMatches.Count -ne 1) {
            throw 'GIT_PROCESS_IDENTITY_MISMATCH: process record lacks one matching CREATE and EXIT event for its exact PID/creation identity'
        }
        $createEvent = $createMatches[0]
        $exitEvent = $exitMatches[0]
        if ([long]$createEvent.Sequence -le 0 -or [long]$exitEvent.Sequence -le [long]$createEvent.Sequence -or
            [int]$createEvent.ParentProcessId -ne [int]$processIdentity.ParentProcessId -or
            [long]$createEvent.ParentCreationFileTime -ne [long]$processIdentity.ParentCreationFileTime -or
            [int]$exitEvent.ParentProcessId -ne [int]$processIdentity.ParentProcessId -or
            [long]$exitEvent.ParentCreationFileTime -ne [long]$processIdentity.ParentCreationFileTime -or
            [int]$exitEvent.ExitCode -ne [int]$processIdentity.ExitCode -or
            -not [bool]$processIdentity.ImageVerified -or -not [bool]$processIdentity.Exited -or
            [long]$processIdentity.CreateSequence -ne [long]$createEvent.Sequence -or
            [long]$processIdentity.ExitSequence -ne [long]$exitEvent.Sequence) {
            throw 'GIT_PROCESS_IDENTITY_MISMATCH: CREATE/EXIT event chain does not bind the exact process, parent, and creation identity'
        }
    }
    $rootCreateEvent = @($Trace.ProcessEvents | Where-Object {
        $_.Kind -ceq 'CREATE' -and [int]$_.ProcessId -eq [int]$identity.ProcessId -and
        [long]$_.CreationFileTime -eq [long]$identity.CreationFileTime
    })[0]
    if ([int]$rootCreateEvent.ParentProcessId -ne $ExpectedParentProcessId -or
        [long]$rootCreateEvent.ParentCreationFileTime -ne [long]$Trace.DebuggerCreationFileTime) {
        throw 'GIT_PROCESS_IDENTITY_MISMATCH: root CREATE event parent PID/creation identity differs from this runner'
    }

    $image = Get-D32BoundArtifactWithFileId -Path $expectedPath
    if (-not [string]::Equals((Get-D32FullPath ([string]$identity.ImagePath)), $expectedPath, [StringComparison]::OrdinalIgnoreCase) -or
        [long]$identity.Bytes -ne [long]$image.bytes -or [string]$identity.Sha256 -cne [string]$image.sha256 -or
        [string]$identity.VolumeSerialHex -cne [string]$image.volume_serial_hex -or
        [string]$identity.FileIdHex -cne [string]$image.file_id_hex -or
        [uint64]$image.bytes -ne [uint64]$script:PinnedGit.bytes -or
        [string]$image.volume_serial_hex -cne [string]$script:PinnedGit.volume_serial_hex -or
        [string]$image.file_id_hex -cne [string]$script:PinnedGit.file_id_hex -or
        [string]$image.sha256 -cne [string]$script:PinnedGit.sha256 -or
        -not (Test-D32SameArtifactFileIdentity -Left $image.file_identity -Right $script:PinnedGit.file_identity)) {
        throw 'GIT_PROCESS_IDENTITY_MISMATCH: pre-continuation Git image handle differs from the caller-pinned path, bytes, SHA-256, or file identity'
    }
    try { Assert-D32PinnedGitCurrent }
    catch { throw "GIT_PROCESS_IDENTITY_MISMATCH: caller-pinned Git changed after identity verification: $($_.Exception.Message)" }
}

function Assert-D32NoNestedGitReparse {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    [void](Assert-D32NoReparsePath -Path $Path)
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($Path)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "GIT_REPOSITORY_INVALID: nested Git metadata reparse point is forbidden: $($item.FullName)"
            }
            if (($item.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                $pending.Push($item.FullName)
            }
        }
    }
}

function Assert-D32RepositoryGitInfo {
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$GitDirectory)

    $infoDirectory = Join-Path $GitDirectory 'info'
    [void](Assert-D32NoReparsePath -Path $infoDirectory)
    if (-not (Test-Path -LiteralPath $infoDirectory -PathType Container)) {
        throw 'GIT_REPOSITORY_INVALID: direct .git/info directory is required'
    }
    Assert-D32NoNestedGitReparse -Path $infoDirectory
    $items = @(Get-ChildItem -LiteralPath $infoDirectory -Force -ErrorAction Stop)
    if ($items.Count -ne 1 -or $items[0].Name -cne 'exclude' -or
        ($items[0].Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or
        ($items[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'GIT_REPOSITORY_INVALID: .git/info may contain only the regular exclude file'
    }
    $excludePath = Join-Path $infoDirectory 'exclude'
    [void](Assert-D32NoReparsePath -Path $excludePath)
    $excludeLines = [IO.File]::ReadAllLines($excludePath)
    $approvedRuleCount = 0
    foreach ($line in $excludeLines) {
        if ([String]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
        if ($line -cne 'vita-agent/target/') {
            throw 'GIT_REPOSITORY_INVALID: .git/info/exclude contains a non-approved active pattern'
        }
        $approvedRuleCount++
    }
    if ($approvedRuleCount -ne 1) {
        throw 'GIT_REPOSITORY_INVALID: .git/info/exclude must contain exactly one active vita-agent/target/ rule'
    }

    $repoRoot = Assert-D32NoReparsePath -Path $Root
    $vitaAgentRoot = Assert-D32NoReparsePath -Path (Join-Path $repoRoot 'vita-agent')
    if (-not (Test-Path -LiteralPath $vitaAgentRoot -PathType Container) -or
        -not (Test-D32PathWithin -Path $vitaAgentRoot -Root $repoRoot)) {
        throw 'GIT_REPOSITORY_INVALID: repo-local vita-agent directory is not canonical beneath the candidate root'
    }
    $targetPath = Join-Path $vitaAgentRoot 'target'
    if (Test-Path -LiteralPath $targetPath) {
        [void](Assert-D32NoReparsePath -Path $targetPath)
        if (-not (Test-Path -LiteralPath $targetPath -PathType Container) -or
            -not (Test-D32PathWithin -Path $targetPath -Root $repoRoot)) {
            throw 'GIT_REPOSITORY_INVALID: vita-agent target is not a repo-local directory'
        }
    }
    else {
        [void](Assert-D32NoReparsePath -Path $targetPath -AllowMissingLeaf)
    }
}

function Assert-D32RepositoryGitConfig {
    param([Parameter(Mandatory = $true)][string]$Root)

    $rootFull = Assert-D32NoReparsePath -Path $Root
    $gitDirectory = Join-Path $rootFull '.git'
    [void](Assert-D32NoReparsePath -Path $gitDirectory)
    if (-not (Test-Path -LiteralPath $gitDirectory -PathType Container)) {
        throw 'GIT_REPOSITORY_INVALID: only a direct .git directory is accepted'
    }
    foreach ($name in @('HEAD', 'index', 'objects', 'objects/info')) {
        [void](Assert-D32NoReparsePath -Path (Join-Path $gitDirectory $name))
    }
    [void](Assert-D32NoReparsePath -Path (Join-Path $gitDirectory 'refs'))
    Assert-D32RepositoryGitInfo -Root $rootFull -GitDirectory $gitDirectory
    Assert-D32NoNestedGitReparse -Path (Join-Path $gitDirectory 'refs')
    Assert-D32NoNestedGitReparse -Path (Join-Path $gitDirectory 'objects')
    foreach ($name in @('packed-refs')) {
        $metadataPath = Join-Path $gitDirectory $name
        if (Test-Path -LiteralPath $metadataPath) {
            [void](Assert-D32NoReparsePath -Path $metadataPath)
        }
    }
    foreach ($name in @('config.worktree', 'gitdir', 'commondir')) {
        if (Test-Path -LiteralPath (Join-Path $gitDirectory $name)) {
            throw "GIT_REPOSITORY_INVALID: repository metadata indirection is forbidden: $name"
        }
    }
    foreach ($name in @('objects/info/alternates', 'objects/info/http-alternates', 'info/grafts')) {
        if (Test-Path -LiteralPath (Join-Path $gitDirectory $name)) {
            throw "GIT_REPOSITORY_INVALID: repository Git metadata indirection is forbidden: $name"
        }
    }
    $configPath = Join-Path $gitDirectory 'config'
    [void](Assert-D32NoReparsePath -Path $configPath)
    $section = ''
    $lines = [IO.File]::ReadAllLines($configPath)
    for ($lineNumber = 0; $lineNumber -lt $lines.Length; $lineNumber++) {
        if ($lineNumber -ge $lines.Length) { continue }
        $line = $lines[$lineNumber].Trim()
        if ([String]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }
        if ($line.StartsWith('[')) {
            if ($line -notmatch '^\[\s*([A-Za-z0-9]+)(?:\s|\])') {
                throw "GIT_CONFIG_INVALID: malformed repository Git config section at line $($lineNumber + 1)"
            }
            $section = $Matches[1].ToLowerInvariant()
            if ($section -notin @('core', 'remote', 'branch', 'extensions')) {
                throw "GIT_CONFIG_REJECTED: repository Git section is not allowed: $section"
            }
            continue
        }
        $key = ($line -split '[=\s]', 2)[0].ToLowerInvariant()
        $allowed = switch ($section) {
            'core' { $key -in @('repositoryformatversion', 'filemode', 'bare', 'logallrefupdates', 'ignorecase', 'precomposeunicode', 'symlinks', 'longpaths', 'quotepath') }
            'remote' { $key -in @('url', 'fetch', 'pushurl', 'tagopt', 'prune', 'mirror') }
            'branch' { $key -in @('remote', 'merge') }
            'extensions' { $key -eq 'objectformat' -and $line -match '=\s*sha1\s*$' }
            default { $false }
        }
        if (-not $allowed) {
            throw "GIT_CONFIG_REJECTED: repository Git key is not allowed: $section.$key"
        }
    }
    return $gitDirectory
}

function Get-D32GitMetadataDigest {
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)

    $Stream.Position = 0
    $before = Get-D32NativeFileIdentity $Stream
    $beforeRecord = ConvertTo-D32FileIdentityRecord $before
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $hashBytes = $hasher.ComputeHash($Stream) }
    finally { $hasher.Dispose() }
    $after = Get-D32NativeFileIdentity $Stream
    $length = [uint64]$Stream.Length
    $Stream.Position = 0
    if (-not (Test-D32SameNativeFileIdentity -Left $before -Right $after) -or $length -ne [uint64]$after.file_size) {
        throw 'GIT_METADATA_CHANGED: metadata handle identity or bytes changed while hashing'
    }
    return [ordered]@{
        file_identity = $beforeRecord
        bytes = $length
        sha256 = [BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant()
    }
}

function Open-D32GitMetadataFileLock {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Assert-D32NoReparsePath -Path $Path
    $snapshot = Get-D32BoundArtifact -Path $full
    $stream = [D32PinnedGitImageHandleV1]::OpenReadLocked($full)
    try {
        $digest = Get-D32GitMetadataDigest -Stream $stream
        if ($digest.sha256 -cne $snapshot.sha256 -or $digest.bytes -ne [uint64]$snapshot.bytes -or
            -not (Test-D32SameArtifactFileIdentity -Left $digest.file_identity -Right $snapshot.file_identity)) {
            throw 'GIT_METADATA_CHANGED: path and retained metadata handle do not bind the same bytes and identity'
        }
        return [pscustomobject]@{ Path = $full; Stream = $stream; Digest = $digest }
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Assert-D32GitMetadataFileLockCurrent {
    param([Parameter(Mandatory = $true)][object]$Lock)

    [void](Assert-D32NoReparsePath -Path ([string]$Lock.Path))
    $handleDigest = Get-D32GitMetadataDigest -Stream $Lock.Stream
    $pathDigest = Get-D32BoundArtifact -Path ([string]$Lock.Path)
    if ($handleDigest.sha256 -cne [string]$Lock.Digest.sha256 -or
        $handleDigest.bytes -ne [uint64]$Lock.Digest.bytes -or
        -not (Test-D32SameArtifactFileIdentity -Left $handleDigest.file_identity -Right $Lock.Digest.file_identity) -or
        $pathDigest.sha256 -cne [string]$Lock.Digest.sha256 -or
        $pathDigest.bytes -ne [uint64]$Lock.Digest.bytes -or
        -not (Test-D32SameArtifactFileIdentity -Left $pathDigest.file_identity -Right $Lock.Digest.file_identity)) {
        throw 'GIT_METADATA_CHANGED: locked metadata path or bytes changed across Git process creation'
    }
}

function Open-D32GitMetadataLocks {
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$GitDirectory)

    Initialize-D32PinnedGitHandleType
    [void](Assert-D32RepositoryGitConfig -Root $Root)
    $locks = [System.Collections.Generic.List[object]]::new()
    try {
        $locks.Add((Open-D32GitMetadataFileLock -Path (Join-Path $GitDirectory 'index')))
        $locks.Add((Open-D32GitMetadataFileLock -Path (Join-Path $GitDirectory 'info/exclude')))
        [void](Assert-D32RepositoryGitConfig -Root $Root)
        foreach ($lock in $locks) { Assert-D32GitMetadataFileLockCurrent -Lock $lock }
        return [pscustomobject]@{ Items = $locks }
    }
    catch {
        foreach ($lock in $locks) { $lock.Stream.Dispose() }
        throw
    }
}

function Assert-D32GitMetadataLocksCurrent {
    param([Parameter(Mandatory = $true)][object]$Locks, [Parameter(Mandatory = $true)][string]$Root)

    foreach ($lock in $Locks.Items) { Assert-D32GitMetadataFileLockCurrent -Lock $lock }
    [void](Assert-D32RepositoryGitConfig -Root $Root)
    foreach ($lock in $Locks.Items) { Assert-D32GitMetadataFileLockCurrent -Lock $lock }
}

function Close-D32GitMetadataLocks {
    param([Parameter(Mandatory = $true)][object]$Locks)

    foreach ($lock in $Locks.Items) { $lock.Stream.Dispose() }
}

function Assert-D32PreflightSelfTestGitSetup {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$OwnedRoot,
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][string]$MarkerToken,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$AfterExecution
    )

    $rootFull = Assert-D32NoReparsePath -Path $Root
    $ownedFull = Assert-D32NoReparsePath -Path $OwnedRoot
    $markerFull = Assert-D32NoReparsePath -Path $MarkerPath
    if (-not [String]::Equals((Split-Path -Parent $rootFull).TrimEnd('\'), $ownedFull.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) -or
        -not [String]::Equals((Split-Path -Parent $markerFull).TrimEnd('\'), $ownedFull.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $markerFull -PathType Leaf) -or
        -not [String]::Equals([IO.File]::ReadAllText($markerFull), $MarkerToken, [StringComparison]::Ordinal)) {
        throw 'SELFTEST_GIT_SETUP_BLOCKED: fixture root is not beneath the exact owned marker root'
    }
    $signature = @($Arguments) -join "`0"
    if (@("init`0-q", "add`0.", "commit`0-q`0-m`0selftest fixture") -cnotcontains $signature) {
        throw 'SELFTEST_GIT_SETUP_BLOCKED: Git fixture setup argv is outside the exact code-owned test allowlist'
    }
    $gitDirectory = Join-Path $rootFull '.git'
    if ($signature -ceq "init`0-q") {
        if (-not $AfterExecution -and (Test-Path -LiteralPath $gitDirectory)) { throw 'SELFTEST_GIT_SETUP_BLOCKED: init target already contains Git metadata' }
        if ($AfterExecution) {
            if (-not (Test-Path -LiteralPath $gitDirectory -PathType Container)) {
                throw 'SELFTEST_GIT_SETUP_BLOCKED: init did not create direct Git metadata beneath the exact owned marker root'
            }
            [void](Assert-D32NoReparsePath -Path $gitDirectory)
        }
        if ($AfterExecution) {
            $infoDirectory = Join-Path $gitDirectory 'info'
            if (-not (Test-Path -LiteralPath $infoDirectory -PathType Container)) {
                throw 'SELFTEST_GIT_SETUP_BLOCKED: init did not create direct non-reparse Git info metadata'
            }
            [void](Assert-D32NoReparsePath -Path $infoDirectory)
            $excludePath = Join-Path $infoDirectory 'exclude'
            if (Test-Path -LiteralPath $excludePath) { [void](Assert-D32NoReparsePath -Path $excludePath) }
            [IO.File]::WriteAllText($excludePath, "# allowed comments`nvita-agent/target/`n", [Text.UTF8Encoding]::new($false))
            $indexPath = Join-Path $gitDirectory 'index'
            if (Test-Path -LiteralPath $indexPath) {
                [void](Assert-D32NoReparsePath -Path $indexPath)
            }
            else {
                $emptyIndexHeader = [byte[]]@(0x44, 0x49, 0x52, 0x43, 0, 0, 0, 2, 0, 0, 0, 0)
                $emptyIndexHasher = [Security.Cryptography.SHA1]::Create()
                try { $emptyIndexChecksum = $emptyIndexHasher.ComputeHash($emptyIndexHeader) }
                finally { $emptyIndexHasher.Dispose() }
                [IO.File]::WriteAllBytes($indexPath, [byte[]]($emptyIndexHeader + $emptyIndexChecksum))
            }
        }
    }
    else {
        if (-not (Test-Path -LiteralPath $gitDirectory -PathType Container)) {
            throw 'SELFTEST_GIT_SETUP_BLOCKED: Git fixture metadata is absent or reparse-backed before add/commit'
        }
        [void](Assert-D32NoReparsePath -Path $gitDirectory)
        [void](Assert-D32RepositoryGitConfig -Root $rootFull)
    }
    return [PSCustomObject]@{ Root = $rootFull; GitDirectory = $gitDirectory }
}

function Get-D32GitOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [AllowNull()][object]$MetadataLocks,
        [switch]$PreserveOutput,
        [switch]$CaptureResult,
        [switch]$SelfTestFixtureSetup,
        [string]$SelfTestOwnedRoot,
        [string]$SelfTestMarkerPath,
        [string]$SelfTestMarkerToken
    )

    $script:D32LastPinnedGitAttempt = $null
    $script:D32LastPinnedGitCaptureResult = $null
    Assert-D32PinnedGitCurrent
    Assert-D32ApprovedPinnedGitRoot
    $rootFull = Assert-D32NoReparsePath -Path $Root
    $testSetup = $null
    if ($SelfTestFixtureSetup) {
        $testSetup = Assert-D32PreflightSelfTestGitSetup -Root $rootFull -OwnedRoot $SelfTestOwnedRoot -MarkerPath $SelfTestMarkerPath -MarkerToken $SelfTestMarkerToken -Arguments $Arguments
        $gitDirectory = [string]$testSetup.GitDirectory
    }
    else {
        $gitDirectory = Assert-D32RepositoryGitConfig -Root $rootFull
    }
    $temporaryRoot = Assert-D32NoReparsePath -Path ([IO.Path]::GetTempPath())
    $environmentRoot = Join-Path $temporaryRoot ('d32-fixture-git-env-' + [Guid]::NewGuid().ToString('N'))
    [void](Ensure-D32OwnedDirectory $environmentRoot)
    $emptyConfig = Join-Path $environmentRoot 'empty.gitconfig'
    $emptyHooks = Join-Path $environmentRoot 'empty-hooks'
    [IO.File]::WriteAllText($emptyConfig, '', [Text.UTF8Encoding]::new($false))
    New-Item -ItemType Directory -Path $emptyHooks -Force:$false | Out-Null
    $gitBin = Split-Path -Parent $script:PinnedGit.path
    $installRoot = Split-Path -Parent $gitBin
    $systemRoot = [Environment]::GetEnvironmentVariable('SystemRoot', 'Process')
    if ([String]::IsNullOrWhiteSpace($systemRoot)) {
        throw 'GIT_ENV_INVALID: Windows SystemRoot is unavailable'
    }
    $systemRoot = Assert-D32NoReparsePath -Path $systemRoot
    $searchDirectories = @($gitBin, (Join-Path $installRoot 'bin'), (Join-Path $installRoot 'mingw64/bin'), (Join-Path $installRoot 'usr/bin'), (Join-Path $systemRoot 'System32'))
    $searchDirectories = @($searchDirectories | Where-Object { Test-Path -LiteralPath $_ -PathType Container } | ForEach-Object { Assert-D32NoReparsePath -Path $_ })
    if ($searchDirectories.Count -eq 0) { throw 'GIT_ENV_INVALID: pinned Git has no safe executable search path' }
    $gitCommandArguments = @(
        '-c', 'core.fsmonitor=false',
        '-c', ('core.worktree=' + $rootFull),
        '-c', 'core.bare=false',
        '-c', ('core.attributesFile=' + $emptyConfig),
        '-c', ('core.hooksPath=' + $emptyHooks),
        '-c', ('safe.directory=' + $rootFull),
        '-C', $rootFull
    ) + @($Arguments)
    if ($null -ne $testSetup -and $Arguments.Count -gt 0 -and $Arguments[0] -ceq 'commit') {
        $gitCommandArguments = @(
            '-c', 'user.name=D32 Selftest',
            '-c', 'user.email=d32-selftest@example.invalid',
            '-c', 'maintenance.auto=false',
            '-c', 'gc.auto=0'
        ) + $gitCommandArguments
    }
    $commandLine = ConvertTo-D32CommandLine (@($script:PinnedGit.path) + $gitCommandArguments)
    $childEnvironment = [ordered]@{
        PATH = $searchDirectories -join [IO.Path]::PathSeparator
        SystemRoot = $systemRoot
        WINDIR = $systemRoot
        TEMP = $environmentRoot
        TMP = $environmentRoot
        HOME = $environmentRoot
        USERPROFILE = $environmentRoot
        XDG_CONFIG_HOME = $environmentRoot
        GIT_CONFIG_NOSYSTEM = '1'
        GIT_CONFIG_SYSTEM = $emptyConfig
        GIT_CONFIG_GLOBAL = $emptyConfig
        GIT_DIR = $gitDirectory
        GIT_WORK_TREE = $rootFull
        GIT_INDEX_FILE = Join-Path $gitDirectory 'index'
        GIT_OPTIONAL_LOCKS = '0'
        GIT_TERMINAL_PROMPT = '0'
        GIT_PAGER = 'cat'
    }
    $environmentBlock = ConvertTo-D32EnvironmentBlock -Environment $childEnvironment
    $nativeProcess = $null
    $trace = $null
    $cleanup = $null
    $stdoutBuffer = $null
    $stderrBuffer = $null
    $stdoutCopy = $null
    $stderrCopy = $null
    $pinnedGitHandle = $null
    $ownsMetadataLocks = $false
    $exitCode = $null
    $stdout = ''
    $stderr = ''
    $profileCurrent = $null
    try {
        if ($null -eq $testSetup) {
            if ($null -eq $MetadataLocks) {
                $MetadataLocks = Open-D32GitMetadataLocks -Root $rootFull -GitDirectory $gitDirectory
                $ownsMetadataLocks = $true
            }
            Assert-D32GitMetadataLocksCurrent -Locks $MetadataLocks -Root $rootFull
        }
        $pinnedGitHandle = Open-D32PinnedGitHandle
        Assert-D32PinnedGitCurrent
        if ($null -eq $script:ValidatedToolchainProfile -or -not [bool]$script:ValidatedToolchainProfile.IsValid) {
            throw 'GIT_TOOLCHAIN_PROFILE_REQUIRED: caller-pinned Windows child-image inventory is unavailable'
        }
        $profileCurrent = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $script:ValidatedToolchainProfile
        if (@($profileCurrent.WindowsImageInventory).Count -ne 1) {
            throw 'GIT_TOOLCHAIN_PROFILE_INVALID: pinned Git requires exactly one caller-pinned Windows child image'
        }
        $approvedChildImage = @($profileCurrent.WindowsImageInventory)[0]
        if (-not [string]::Equals([IO.Path]::GetFileName([string]$approvedChildImage.Path), 'conhost.exe', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'GIT_TOOLCHAIN_PROFILE_INVALID: pinned Git child inventory must be the exact conhost.exe profile image'
        }
        $approvedChildImagePin = @(
            [string]$approvedChildImage.Path,
            [string]$approvedChildImage.Bytes,
            [string]$approvedChildImage.Sha256,
            [string]$approvedChildImage.VolumeSerialHex,
            [string]$approvedChildImage.FileIdHex
        ) -join "`t"
        $image = Get-D32BoundArtifactWithFileId -Path $script:PinnedGit.path
        if ($image.sha256 -cne $script:PinnedGit.sha256 -or
            [uint64]$image.bytes -ne [uint64]$script:PinnedGit.bytes -or
            [string]$image.volume_serial_hex -cne [string]$script:PinnedGit.volume_serial_hex -or
            [string]$image.file_id_hex -cne [string]$script:PinnedGit.file_id_hex -or
            -not (Test-D32SameArtifactFileIdentity -Left $image.file_identity -Right $script:PinnedGit.file_identity)) {
            throw 'GIT_PIN_CHANGED: pinned Git image bytes, SHA-256, volume, file ID, or native identity differs before the suspended process launch'
        }
        $expectedRootPin = @(
            [string]$image.path,
            [string]$image.bytes,
            [string]$image.sha256,
            [string]$image.volume_serial_hex,
            [string]$image.file_id_hex
        ) -join "`t"
        Ensure-D32NativeLauncher
        $nativeProcess = [D32FixtureNativeProcessV2]::StartDebug(
            $script:PinnedGit.path,
            $commandLine,
            $rootFull,
            $environmentBlock)
        $stdoutBuffer = [IO.MemoryStream]::new()
        $stderrBuffer = [IO.MemoryStream]::new()
        $stdoutCopy = $nativeProcess.OpenStdoutStream().CopyToAsync($stdoutBuffer)
        $stderrCopy = $nativeProcess.OpenStderrStream().CopyToAsync($stderrBuffer)
        $timeoutMilliseconds = [int][Math]::Min([int]::MaxValue, ([long]$script:TimeoutSeconds * 1000))
        $nativeProcess.ConfigurePinnedGitDebugCapture($expectedRootPin, $approvedChildImagePin, $timeoutMilliseconds)
        $traceTimeoutMilliseconds = [int][Math]::Min([int]::MaxValue, ([long]$timeoutMilliseconds + 20000))
        $trace = $nativeProcess.WaitForDebugTrace($traceTimeoutMilliseconds)
        $cleanup = $nativeProcess.CloseJobAndWait(10000)
        $script:D32LastPinnedGitAttempt = [ordered]@{
            root_path = [string]$script:PinnedGit.path
            root_sha256 = [string]$script:PinnedGit.sha256
            root_bytes = [uint64]$script:PinnedGit.bytes
            root_volume_serial_hex = [string]$script:PinnedGit.volume_serial_hex
            root_file_id_hex = [string]$script:PinnedGit.file_id_hex
            arguments = @($gitCommandArguments)
            command_line = $commandLine
            process_trace = ConvertTo-D32DebugProcessTraceDocument -Trace $trace
            native_cleanup = ConvertTo-D32NativeCleanupDocument -Evidence $cleanup
            cleanup_runtime = [ordered]@{
                debugger_thread_exited = [bool]$cleanup.DebuggerThreadExited
                debugger_thread_joined = [bool]$cleanup.DebuggerThreadJoined
                debugger_kill_on_exit_enabled = [bool]$cleanup.DebuggerKillOnExitEnabled
                retained_process_handles_signaled = [bool]$cleanup.RetainedProcessHandlesSignaled
                debugger_association_query_verified = [bool]$cleanup.DebuggerAssociationQueryVerified
                debugger_association_absent = [bool]$cleanup.DebuggerAssociationAbsent
            }
        }
        if (-not $stdoutCopy.Wait(10000) -or $stdoutCopy.IsFaulted -or
            -not $stderrCopy.Wait(10000) -or $stderrCopy.IsFaulted) {
            throw 'GIT_CAPTURE_FAILED: pinned Git stdout/stderr raw-pipe capture did not complete'
        }
        $null = $stdoutCopy.GetAwaiter().GetResult()
        $null = $stderrCopy.GetAwaiter().GetResult()
        $stdoutRawBytes = [byte[]]$stdoutBuffer.ToArray()
        $stderrRawBytes = [byte[]]$stderrBuffer.ToArray()
        $stdout = [Text.Encoding]::UTF8.GetString($stdoutRawBytes)
        $stderr = [Text.Encoding]::UTF8.GetString($stderrRawBytes)
        $exitCode = $nativeProcess.ExitCode
        if ($SelfTestFixtureSetup) {
            $rawHasher = [Security.Cryptography.SHA256]::Create()
            try {
                $stdoutHash = ([BitConverter]::ToString($rawHasher.ComputeHash($stdoutRawBytes))).Replace('-', '').ToLowerInvariant()
                $stderrHash = ([BitConverter]::ToString($rawHasher.ComputeHash($stderrRawBytes))).Replace('-', '').ToLowerInvariant()
            }
            finally { $rawHasher.Dispose() }
            $stdoutExcerptLength = [Math]::Min(4096, $stdoutRawBytes.Length)
            $stderrExcerptLength = [Math]::Min(4096, $stderrRawBytes.Length)
            $stdoutExcerpt = [Text.Encoding]::UTF8.GetString($stdoutRawBytes, 0, $stdoutExcerptLength)
            $stderrExcerpt = [Text.Encoding]::UTF8.GetString($stderrRawBytes, 0, $stderrExcerptLength)
            $script:D32LastPinnedGitCaptureResult = [PSCustomObject]@{
                ExitCode = [int]$exitCode
                StdOutExcerpt = [string]$stdoutExcerpt
                StdErrExcerpt = [string]$stderrExcerpt
                StdOutBytes = [long]$stdoutRawBytes.Length
                StdErrBytes = [long]$stderrRawBytes.Length
                StdOutSha256 = [string]$stdoutHash
                StdErrSha256 = [string]$stderrHash
                StdOutTruncated = ($stdoutRawBytes.Length -gt $stdoutExcerptLength)
                StdErrTruncated = ($stderrRawBytes.Length -gt $stderrExcerptLength)
                HasOutput = ($stdoutRawBytes.Length -gt 0)
                HasErrorOutput = ($stderrRawBytes.Length -gt 0)
                OutputTruncated = $false
            }
        }
        Assert-D32PinnedGitProcessIdentity `
            -Trace $trace `
            -Cleanup $cleanup `
            -Arguments $gitCommandArguments `
            -CommandLine $commandLine `
            -ExpectedParentProcessId ([int]$PID) `
            -ApprovedChildImages @($profileCurrent.WindowsImageInventory)
        $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $profileCurrent
        if ($null -eq $testSetup) {
            Assert-D32GitMetadataLocksCurrent -Locks $MetadataLocks -Root $rootFull
        }
        else {
            $null = Assert-D32PreflightSelfTestGitSetup -Root $rootFull -OwnedRoot $SelfTestOwnedRoot -MarkerPath $SelfTestMarkerPath -MarkerToken $SelfTestMarkerToken -Arguments $Arguments -AfterExecution
        }
    }
    finally {
        if ($null -ne $nativeProcess) { $nativeProcess.Dispose() }
        if ($null -ne $stdoutBuffer) { $stdoutBuffer.Dispose() }
        if ($null -ne $stderrBuffer) { $stderrBuffer.Dispose() }
        if ($null -ne $pinnedGitHandle) { $pinnedGitHandle.Dispose() }
        if ($ownsMetadataLocks -and $null -ne $MetadataLocks) { Close-D32GitMetadataLocks -Locks $MetadataLocks }
        Remove-D32OwnedDirectory $environmentRoot
    }
    Assert-D32PinnedGitCurrent
    if ($CaptureResult) {
        return [PSCustomObject]@{
            ExitCode = [int]$exitCode
            StdOut = [string]$stdout
            StdErr = [string]$stderr
            Attempt = $script:D32LastPinnedGitAttempt
        }
    }
    if ($exitCode -ne 0) {
        throw "GIT_FAILED: pinned Git $($Arguments -join ' ') ($exitCode): $($stderr.Trim())"
    }
    if ($PreserveOutput) { return $stdout }
    return $stdout.Trim()
}

function Get-D32CandidateSha {
    param([Parameter(Mandatory = $true)][string]$Root, [AllowNull()][object]$MetadataLocks)

    $sha = Get-D32GitOutput -Root $Root -Arguments @('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}') -MetadataLocks $MetadataLocks
    if ($sha -notmatch '^[0-9a-fA-F]{40}$') {
        throw "GIT_FAILED: HEAD is not a full commit SHA: $sha"
    }
    return $sha.ToLowerInvariant()
}

function Assert-D32CandidateShaMatch {
    param(
        [Parameter(Mandatory = $true)][string]$ActualSha,
        [Parameter(Mandatory = $true)][string]$ExpectedSha
    )

    if ($ExpectedSha -cnotmatch '^[0-9a-f]{40}$') {
        throw 'CANDIDATE_SHA_INVALID: expected candidate SHA must be 40 lowercase hexadecimal characters'
    }
    if ($ActualSha -cnotmatch '^[0-9a-f]{40}$' -or $ActualSha -cne $ExpectedSha) {
        throw "CANDIDATE_SHA_MISMATCH: current HEAD does not match the caller-pinned candidate SHA $ExpectedSha"
    }
    return $ActualSha
}

function Assert-D32PinnedCleanCandidate {
    param([Parameter(Mandatory = $true)][string]$Root)

    $rootFull = Assert-D32NoReparsePath -Path $Root
    $gitDirectory = Assert-D32RepositoryGitConfig -Root $rootFull
    $metadataLocks = Open-D32GitMetadataLocks -Root $rootFull -GitDirectory $gitDirectory
    try {
        $sha = Get-D32CandidateSha -Root $rootFull -MetadataLocks $metadataLocks
        $sha = Assert-D32CandidateShaMatch -ActualSha $sha -ExpectedSha $script:ExpectedCandidateSha
        $status = Get-D32GitOutput -Root $rootFull -Arguments @('status', '--porcelain=v1', '--untracked-files=all') -MetadataLocks $metadataLocks
        Assert-D32CleanGitStatus -Status $status -Root $rootFull
        $indexFlags = Get-D32GitOutput -Root $rootFull -Arguments @('ls-files', '-v', '-z') -MetadataLocks $metadataLocks -PreserveOutput
        Assert-D32CleanGitIndexFlags -Output $indexFlags
        $headAfter = Get-D32CandidateSha -Root $rootFull -MetadataLocks $metadataLocks
        if ($headAfter -cne $sha) {
            throw 'CANDIDATE_SHA_CHANGED: HEAD changed across Git clean-state verification'
        }
        Assert-D32GitMetadataLocksCurrent -Locks $metadataLocks -Root $rootFull
        return $sha
    }
    finally {
        Close-D32GitMetadataLocks -Locks $metadataLocks
    }
}

function Assert-D32CleanGitIndexFlags {
    param([AllowNull()][string]$Output)

    if ([String]::IsNullOrEmpty($Output)) { return }
    if (-not $Output.EndsWith([string][char]0, [StringComparison]::Ordinal)) {
        throw 'WORKTREE_DIRTY: Git index flag inventory is not NUL-terminated'
    }
    $records = $Output.Split([char]0, [StringSplitOptions]::RemoveEmptyEntries)
    foreach ($record in $records) {
        if ($record.Length -lt 3 -or $record.Substring(0, 2) -cne 'H ' -or
            [String]::IsNullOrEmpty($record.Substring(2))) {
            throw 'WORKTREE_DIRTY: Git index includes assume-unchanged, skip-worktree, unmerged, or malformed flags'
        }
    }
}

function Write-D32FixtureGitState {
    param([Parameter(Mandatory = $true)][ValidateRange(1, 5)][int]$Phase, [Parameter(Mandatory = $true)][ValidateSet('before', 'after')][string]$Edge, [Parameter(Mandatory = $true)][string]$Root)

    $head = '0000000000000000000000000000000000000000'
    $clean = $false
    $failure = $null
    try {
        $head = Assert-D32PinnedCleanCandidate -Root $Root
        $clean = $true
    }
    catch {
        $failure = $_.Exception.Message
        try {
            $observedHead = Get-D32CandidateSha -Root $Root
            if ($observedHead -match '^[0-9a-f]{40}$') { $head = $observedHead }
        }
        catch { }
    }
    $cleanLiteral = if ($clean) { 'true' } else { 'false' }
    Write-Host "D32_FIXTURE_GIT_STATE phase=$Phase edge=$Edge head=$head clean=$cleanLiteral"
    if (-not $clean) {
        throw "WORKTREE_DIRTY: phase $Phase $Edge Git state is not the exact clean candidate: $failure"
    }
}

function Get-D32EnvironmentPlan {
    param([Parameter(Mandatory = $true)][string]$EnvironmentRoot)

    $originalUserProfile = [Environment]::GetEnvironmentVariable('USERPROFILE', 'Process')
    if ([String]::IsNullOrWhiteSpace($originalUserProfile)) {
        $originalUserProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    }
    if ([String]::IsNullOrWhiteSpace($originalUserProfile)) {
        throw 'ENVIRONMENT_INVALID: the real USERPROFILE could not be resolved'
    }
    $originalUserProfile = Get-D32FullPath $originalUserProfile

    $cargoHome = [Environment]::GetEnvironmentVariable('CARGO_HOME', 'Process')
    if ([String]::IsNullOrWhiteSpace($cargoHome)) {
        $cargoHome = Join-Path $originalUserProfile '.cargo'
    }
    $rustupHome = [Environment]::GetEnvironmentVariable('RUSTUP_HOME', 'Process')
    if ([String]::IsNullOrWhiteSpace($rustupHome)) {
        $rustupHome = Join-Path $originalUserProfile '.rustup'
    }
    $toolchain = [Environment]::GetEnvironmentVariable('RUSTUP_TOOLCHAIN', 'Process')

    $environmentRoot = Ensure-D32OwnedDirectory $EnvironmentRoot
    $codexHome = Ensure-D32OwnedDirectory (Join-Path $environmentRoot 'codex-home')
    $isolatedUserProfile = Ensure-D32OwnedDirectory (Join-Path $environmentRoot 'user-profile')

    return [ordered]@{
        original_userprofile = $originalUserProfile
        codex_home           = $codexHome
        userprofile          = $isolatedUserProfile
        cargo_home           = Get-D32FullPath $cargoHome
        rustup_home          = Get-D32FullPath $rustupHome
        rustup_toolchain     = $toolchain
    }
}

function Set-D32IsolatedEnvironment {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Plan,
        [Parameter(Mandatory = $true)][int]$Jobs
    )

    $names = @('CODEX_HOME', 'USERPROFILE', 'CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN', 'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL', 'CARGO_TERM_COLOR')
    $saved = @{}
    foreach ($name in $names) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    [Environment]::SetEnvironmentVariable('CODEX_HOME', $Plan.codex_home, 'Process')
    [Environment]::SetEnvironmentVariable('USERPROFILE', $Plan.userprofile, 'Process')
    [Environment]::SetEnvironmentVariable('CARGO_HOME', $Plan.cargo_home, 'Process')
    [Environment]::SetEnvironmentVariable('RUSTUP_HOME', $Plan.rustup_home, 'Process')
    [Environment]::SetEnvironmentVariable('RUSTUP_TOOLCHAIN', $Plan.rustup_toolchain, 'Process')
    [Environment]::SetEnvironmentVariable('CARGO_BUILD_JOBS', [string]$Jobs, 'Process')
    [Environment]::SetEnvironmentVariable('CARGO_INCREMENTAL', '0', 'Process')
    [Environment]::SetEnvironmentVariable('CARGO_TERM_COLOR', 'never', 'Process')
    return $saved
}

function Restore-D32Environment {
    param([Parameter(Mandatory = $true)][hashtable]$Saved)

    foreach ($entry in $Saved.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
}

function ConvertTo-D32EnvironmentBlock {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Environment)

    if ($null -eq $Environment -or $Environment -isnot [System.Collections.IDictionary]) {
        throw 'CHILD_ENVIRONMENT_INVALID: environment must be an IDictionary; values omitted'
    }

    $names = @($Environment.Keys | ForEach-Object { [string]$_ })
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $ordered = [System.Collections.Generic.SortedDictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $names) {
        if ([String]::IsNullOrWhiteSpace($name) -or $name.Contains('=') -or $name.Contains([char]0) -or -not $seen.Add($name)) {
            throw 'CHILD_ENVIRONMENT_INVALID: environment keys must be unique ordinary Windows names'
        }
        $value = [string]$Environment[$name]
        if ($value.Contains([char]0)) { throw "CHILD_ENVIRONMENT_INVALID: environment value contains NUL: $name" }
        $ordered.Add($name, $value)
    }
    $entries = @($ordered.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" })
    if ($entries.Count -eq 0) { return "`0`0" }
    return (($entries -join "`0") + "`0`0")
}

function New-D32ProfileChildEnvironment {
    param(
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$CargoHome,
        [Parameter(Mandatory = $true)][string]$TempRoot,
        [Parameter(Mandatory = $true)][bool]$Offline
    )

    $variables = Get-D32BuildToolchainEnvironment `
        -ValidatedProfile $ValidatedProfile `
        -CargoHome $CargoHome `
        -TempRoot $TempRoot `
        -Offline $Offline
    if ($variables -isnot [System.Collections.IDictionary]) {
        throw 'CHILD_ENVIRONMENT_INVALID: profile builder did not return an IDictionary; values omitted'
    }
    return ,$variables
}

function Start-D32FixtureBoundedNativeProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [AllowNull()][string]$EnvironmentBlock,
        [AllowNull()][string]$NativeTestFailure,
        [Parameter(Mandatory = $true)][bool]$RequireDebugEvents
    )

    $fullFilePath = Get-D32FullPath $FilePath
    $fullWorkingDirectory = Get-D32FullPath $WorkingDirectory
    if ($RequireDebugEvents) {
        return [D32FixtureNativeProcessV2]::StartDebug($fullFilePath, $CommandLine, $fullWorkingDirectory, $EnvironmentBlock)
    }
    return [D32FixtureNativeProcessV2]::Start($fullFilePath, $CommandLine, $fullWorkingDirectory, $EnvironmentBlock, $NativeTestFailure)
}

function Invoke-D32LockedCargoFetches {
    param(
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$CargoPath,
        [Parameter(Mandatory = $true)][string]$CargoHome,
        [Parameter(Mandatory = $true)][string]$TempRoot,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$LogRoot,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$LogPrefix,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$PhaseEvidence,
        [switch]$AllowPinnedCargoVctip
    )

    $fetchEnvironment = New-D32ProfileChildEnvironment `
        -ValidatedProfile $ValidatedProfile `
        -CargoHome $CargoHome `
        -TempRoot $TempRoot `
        -Offline $false
    $results = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($lock in $ValidatedProfile.LockInputs) {
        $index++
        $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $ValidatedProfile
        $null = Assert-D32PinnedCleanCandidate -Root $RepoRoot
        $arguments = @('fetch', '--locked', '--manifest-path', [string]$lock.ManifestFullPath, '--target', [string]$ValidatedProfile.Profile.target_triple)
        $phaseName = '{0}-{1:D2}-fetch' -f $LogPrefix, $index
        Write-Host "D32_FIXTURE_PHASE=fetch name=$phaseName lock=$($lock.ManifestPath)"
        $result = Invoke-D32BoundedProcess `
            -FilePath $CargoPath `
            -Arguments $arguments `
            -WorkingDirectory $RepoRoot `
            -PhaseLog (Join-Path $LogRoot $phaseName) `
            -TimeoutSeconds $TimeoutSeconds `
            -ChildEnvironment $fetchEnvironment `
            -RequireDebugEvents `
            -AllowPinnedCargoVctip:$AllowPinnedCargoVctip
        $PhaseEvidence.Add([pscustomobject]@{
                name = $phaseName
                executable = [IO.Path]::GetFullPath($CargoPath)
                arguments = @($arguments)
                command_line = ConvertTo-D32CommandLine (@($CargoPath) + $arguments)
                working_directory = [IO.Path]::GetFullPath($RepoRoot)
                root_record = $result.root_identity_record
                descendant_records = @($result.captured_descendant_records)
                process_trace = $result.process_trace
            })
        if ($result.status -ne 'succeeded' -or $result.exit_code -ne 0) {
            $failure = "CARGO_FETCH_FAILED: manifest=$($lock.ManifestPath) status=$($result.status) exit=$($result.exit_code); process_error=$($result.error); see $($result.phase_log)"
            try {
                Write-D32FixturePhase0FailurePayload -Name $phaseName -Executable $CargoPath -Arguments $arguments -WorkingDirectory $RepoRoot -ProcessResult $result -PrimaryError $failure -PhaseLogPath (Join-Path $LogRoot $phaseName)
            }
            catch { $failure += '; phase0 failure-capture error=' + $_.Exception.Message }
            throw $failure
        }
        try {
            Assert-D32PinnedCargoProcessIdentity `
                -ProcessIdentity $result.root_identity_record `
                -CargoPath $CargoPath `
                -Arguments $arguments `
                -ValidatedProfile $ValidatedProfile `
                -ProcessResult $result
        }
        catch {
            $failure = $_.Exception.Message
            try {
                Write-D32FixturePhase0FailurePayload -Name $phaseName -Executable $CargoPath -Arguments $arguments -WorkingDirectory $RepoRoot -ProcessResult $result -PrimaryError $failure -PhaseLogPath (Join-Path $LogRoot $phaseName)
            }
            catch { $failure += '; phase0 failure-capture error=' + $_.Exception.Message }
            throw $failure
        }
        $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $ValidatedProfile
        $null = Assert-D32PinnedCleanCandidate -Root $RepoRoot
        $results.Add([ordered]@{
                manifest_path = [string]$lock.ManifestPath
                lock_sha256 = [string]$lock.LockSha256
                command = @($arguments)
                status = [string]$result.status
                exit_code = [int]$result.exit_code
                process_identity = ConvertTo-D32D31ProcessIdentityDocument $result.root_identity_record
            })
    }
    return @($results.ToArray())
}

function ConvertTo-D32CommandLine {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    return (($Arguments | ForEach-Object {
                $argument = [string]$_
                if ($argument.Length -gt 0 -and $argument -notmatch '[\s"]') {
                    return $argument
                }
                $builder = [Text.StringBuilder]::new()
                [void]$builder.Append('"')
                $slashes = 0
                foreach ($character in $argument.ToCharArray()) {
                    if ($character -eq '\') {
                        $slashes++
                        continue
                    }
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
                if ($slashes -gt 0) {
                    [void]$builder.Append([char]'\', 2 * $slashes)
                }
                [void]$builder.Append('"')
                return $builder.ToString()
            }) -join ' ')
}

function Clear-D32ChildEnvironment {
    param([Parameter(Mandatory = $true)][Diagnostics.ProcessStartInfo]$StartInfo)

    $StartInfo.EnvironmentVariables.Clear()
}

function Assert-D32CleanGitStatus {
    param(
        [AllowNull()][string]$Status,
        [Parameter(Mandatory = $true)][string]$Root
    )

    if (-not [String]::IsNullOrWhiteSpace($Status)) {
        throw "WORKTREE_DIRTY: refusing fixture prebuild PASS for dirty repository $($Root): $Status"
    }
}

function Ensure-D32NativeLauncher {
    $type = ([System.Management.Automation.PSTypeName]'D32FixtureNativeProcessV2').Type
    if ($null -ne $type) { return }

    $savedLib = [Environment]::GetEnvironmentVariable('LIB', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('LIB', $null, 'Process')
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public sealed class D32NativeCleanupEvidenceV2
{
    public bool JobTerminateCallSucceeded { get; internal set; }
    public int JobTerminateLastError { get; internal set; }
    public bool ProcessWasAlreadySignaled { get; internal set; }
    public bool ProcessWaitSignaled { get; internal set; }
    public bool JobActiveProcessCountVerified { get; internal set; }
    public uint JobActiveProcessCount { get; internal set; }
    public int JobActiveProcessCountLastError { get; internal set; }
    public bool JobCloseSucceeded { get; internal set; }
    public bool CleanupSucceeded { get; internal set; }
    public bool AlreadyClosed { get; internal set; }
    public uint DebuggerThreadId { get; internal set; }
    public bool DebuggerThreadExited { get; internal set; }
    public bool DebuggerThreadJoined { get; internal set; }
    public bool DebuggerKillOnExitEnabled { get; internal set; }
    public int RetainedProcessHandleCount { get; internal set; }
    public bool RetainedProcessHandlesSignaled { get; internal set; }
    public bool DebuggerAssociationQueryVerified { get; internal set; }
    public bool DebuggerAssociationAbsent { get; internal set; }
    public string RetainedProcessHandleStates { get; internal set; }
    public string Detail { get; internal set; }
}

public sealed class D32DebugProcessEventV2
{
    public long Sequence { get; set; }
    public string Kind { get; set; }
    public uint ProcessId { get; set; }
    public uint ParentProcessId { get; set; }
    public long CreationFileTime { get; set; }
    public long ParentCreationFileTime { get; set; }
    public uint ExitCode { get; set; }
}

public sealed class D32DebugProcessRecordV2
{
    public uint ProcessId { get; set; }
    public uint ParentProcessId { get; set; }
    public long CreationFileTime { get; set; }
    public long ParentCreationFileTime { get; set; }
    public string ImagePath { get; set; }
    public long Bytes { get; set; }
    public string Sha256 { get; set; }
    public string VolumeSerialHex { get; set; }
    public string FileIdHex { get; set; }
    public string AllowedImageReason { get; set; }
    public bool ImageVerified { get; set; }
    public bool Exited { get; set; }
    public uint ExitCode { get; set; }
    public long CreateSequence { get; set; }
    public long ExitSequence { get; set; }
    public string CreatedAtUtc { get; set; }
    public string ExitedAtUtc { get; set; }
}

public sealed class D32DebugProcessTraceV2
{
    public string RecordType { get; set; }
    public int SchemaVersion { get; set; }
    public string EventSource { get; set; }
    public string State { get; set; }
    public string BlockReason { get; set; }
    public int DebuggerProcessId { get; set; }
    public uint UncontinuedCreateProcessId { get; set; }
    public int UncontinuedCreateContinueCallCount { get; set; }
    public uint DebuggerThreadId { get; set; }
    public bool DedicatedDebuggerThread { get; set; }
    public bool DebuggerKillOnExitEnabled { get; set; }
    public bool RootResumedAfterKillOnExit { get; set; }
    public bool DebuggerThreadExited { get; set; }
    public bool DebuggerThreadJoined { get; set; }
    public int RetainedProcessHandleCount { get; set; }
    public bool RetainedProcessHandlesSignaled { get; set; }
    public bool DebuggerAssociationQueryVerified { get; set; }
    public bool DebuggerAssociationAbsent { get; set; }
    public long DebuggerCreationFileTime { get; set; }
    public string DebuggerCreatedAtUtc { get; set; }
    public string StartedAtUtc { get; set; }
    public string CompletedAtUtc { get; set; }
    public int DebugEventCount { get; set; }
    public int ProcessCreateEventCount { get; set; }
    public int ProcessExitEventCount { get; set; }
    public int ProcessEventCount { get; set; }
    public int ThreadCreateEventCount { get; set; }
    public int ThreadExitEventCount { get; set; }
    public int ImageLoadEventCount { get; set; }
    public int ImageUnloadEventCount { get; set; }
    public int ExceptionEventCount { get; set; }
    public int DebugStringEventCount { get; set; }
    public int WaitTimeoutCount { get; set; }
    public int DebugApiErrorCount { get; set; }
    public bool EventChainComplete { get; set; }
    public bool JobAccountingVerified { get; set; }
    public uint JobTotalProcesses { get; set; }
    public uint JobActiveProcesses { get; set; }
    public bool AccountingConsistent { get; set; }
    public bool InjectedInterruption { get; set; }
    public List<D32DebugProcessEventV2> ProcessEvents { get; set; }
    public List<D32DebugProcessRecordV2> Processes { get; set; }
}

internal sealed class D32DebugLaunchCoordinator
{
    public readonly ManualResetEvent ProcessReady = new ManualResetEvent(false);
    public readonly ManualResetEvent CapturePlanReady = new ManualResetEvent(false);
    public readonly ManualResetEvent CaptureCompleted = new ManualResetEvent(false);
    public D32FixtureNativeProcessV2 Process;
    public Thread WorkerThread;
    public Exception Failure;
    public bool AbortRequested;
    public string ExpectedRootPin;
    public string[] ApprovedImagePins;
    public string[] CandidateImageRoots;
    public int TimeoutMilliseconds;
    public bool InjectFirstCreateInterruption;
    public bool InjectFirstCreateIdentityMismatch;
    public bool AllowPinnedGitRoot;
    public bool AllowPinnedCargoVctip;
    public bool AllowPinnedVendoredProtoc;
    public string VendoredProtocCargoHomePath;
    public string VendoredProtocPin;
    public string H7CGitNativePolicyText;
    public string FailureInjection;
}

public sealed class D32H7CGitChildObservationV1
{
    public string Slot { get; set; }
    public string Operation { get; set; }
    public uint ProcessId { get; set; }
    public long CreationFileTime { get; set; }
    public uint ParentProcessId { get; set; }
    public long ParentCreationFileTime { get; set; }
    public string ImagePath { get; set; }
    public long Bytes { get; set; }
    public string Sha256 { get; set; }
    public string VolumeSerialHex { get; set; }
    public string FileIdHex { get; set; }
    public string CommandLine { get; set; }
    public string[] Argv { get; set; }
    public string WorkingDirectory { get; set; }
    public Dictionary<string, string> Environment { get; set; }
}

public sealed class D32FixtureNativeProcessV2 : IDisposable
{
    private const uint DebugProcess = 0x00000001;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint HandleFlagInherit = 0x00000001;
    private const uint ProcThreadAttributeHandleList = 0x00020002;
    private const uint JobObjectExtendedLimitInformationClass = 9;
    private const uint JobObjectBasicAccountingInformationClass = 1;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint JobObjectLimitBreakawayOk = 0x00000800;
    private const uint JobObjectLimitSilentBreakawayOk = 0x00001000;
    private const string PinnedVctipPath = @"E:\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\vctip.exe";
    private const string PinnedVctipSha256 = "e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996";
    private const string PinnedVctipBytes = "335328";
    private const string PinnedVctipVolumeSerial = "749614a1961465c0";
    private const string PinnedVctipFileId = "0b5d2000000001000000000000000000";
    private const string PinnedVendoredProtocBytes = "11934496";
    private const string PinnedVendoredProtocSha256 = "cbd1ca1fd6afd1bb6ddd1c09c118ecd4c50f928980857f16fe6fc23704ea17e2";
    private const string PinnedVendoredProtocPathSuffix = @"\registry\src\index.crates.io-1949cf8c6b5b557f\protoc-bin-vendored-win32-3.2.0\bin\protoc.exe";
    private const uint WaitObject0 = 0x00000000;
    private const int ErrorInsufficientBuffer = 122;
    private const uint DebugEventException = 1;
    private const uint DebugEventCreateThread = 2;
    private const uint DebugEventCreateProcess = 3;
    private const uint DebugEventExitThread = 4;
    private const uint DebugEventExitProcess = 5;
    private const uint DebugEventLoadDll = 6;
    private const uint DebugEventUnloadDll = 7;
    private const uint DebugEventOutputDebugString = 8;
    private const uint DebugEventRip = 9;
    private const uint DebugContinue = 0x00010002;
    private const uint DebugExceptionNotHandled = 0x80010001;
    private const uint StatusBreakpoint = 0x80000003;
    private const int ErrorSemTimeout = 121;
    private const uint DuplicateSameAccess = 0x00000002;
    private const uint ProcessQueryInformation = 0x00000400;
    private const uint ProcessVmRead = 0x00000010;
    private const uint Synchronize = 0x00100000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public int Cb;
        public IntPtr Reserved;
        public IntPtr Desktop;
        public IntPtr Title;
        public int X;
        public int Y;
        public int XSize;
        public int YSize;
        public int XCountChars;
        public int YCountChars;
        public int FillAttribute;
        public uint Flags;
        public short ShowWindow;
        public short Reserved2;
        public IntPtr Reserved2Pointer;
        public IntPtr StandardInput;
        public IntPtr StandardOutput;
        public IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public IntPtr AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicAccountingInformation
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DebugFileTime { public uint Low; public uint High; }

    [StructLayout(LayoutKind.Sequential)]
    private struct DebugFileInformation
    {
        public uint Attributes;
        public DebugFileTime CreationTime;
        public DebugFileTime LastAccessTime;
        public DebugFileTime LastWriteTime;
        public uint VolumeSerial;
        public uint SizeHigh;
        public uint SizeLow;
        public uint Links;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DebugProcessBasicInformation
    {
        public int ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public int BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    private sealed class H7CGitSlotPolicy
    {
        public string Name;
        public string Path;
        public string Volume;
        public string FileId;
        public string Repo;
        public string RepoVolume;
        public string RepoFileId;
        public string GitHome;
        public string GitHomeVolume;
        public string GitHomeFileId;
        public string EmptyConfig;
        public string ConfigVolume;
        public string ConfigFileId;
        public int SetupNext;
        public int StatusCount;
    }

    private sealed class H7CGitNativePolicy
    {
        public string Repository;
        public string CargoPath;
        public string EvidenceRoot;
        public string EvidenceRootVolume;
        public string EvidenceRootFileId;
        public string TempRoot;
        public string TempRootVolume;
        public string TempRootFileId;
        public string OwnerMarkerPath;
        public long OwnerMarkerBytes;
        public string OwnerMarkerSha256;
        public string OwnerMarkerVolume;
        public string OwnerMarkerFileId;
        public string GitPath;
        public long GitBytes;
        public string GitSha256;
        public string GitVolume;
        public string GitFileId;
        public Dictionary<string, H7CGitSlotPolicy> Slots = new Dictionary<string, H7CGitSlotPolicy>(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class H7CGitDirectoryIdentity
    {
        public string Path;
        public string Volume;
        public string FileId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DebugCreateProcessInfo
    {
        public IntPtr File;
        public IntPtr Process;
        public IntPtr Thread;
        public IntPtr ImageBase;
        public uint DebugInfoFileOffset;
        public uint DebugInfoSize;
        public IntPtr ThreadLocalBase;
        public IntPtr StartAddress;
        public IntPtr ImageName;
        public ushort Unicode;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DebugExitProcessInfo { public uint ExitCode; }

    [StructLayout(LayoutKind.Sequential)]
    private struct DebugExceptionRecord
    {
        public uint ExceptionCode;
        public uint ExceptionFlags;
        public IntPtr NestedRecord;
        public IntPtr Address;
        public uint ParameterCount;
        public IntPtr Parameter0;
        public IntPtr Parameter1;
        public IntPtr Parameter2;
        public IntPtr Parameter3;
        public IntPtr Parameter4;
        public IntPtr Parameter5;
        public IntPtr Parameter6;
        public IntPtr Parameter7;
        public IntPtr Parameter8;
        public IntPtr Parameter9;
        public IntPtr Parameter10;
        public IntPtr Parameter11;
        public IntPtr Parameter12;
        public IntPtr Parameter13;
        public IntPtr Parameter14;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DebugExceptionInfo { public DebugExceptionRecord Exception; public uint FirstChance; }

    [StructLayout(LayoutKind.Sequential)]
    private struct DebugCreateThreadInfo { public IntPtr Thread; public IntPtr ThreadLocalBase; public IntPtr StartAddress; }

    [StructLayout(LayoutKind.Sequential)]
    private struct DebugLoadDllInfo
    {
        public IntPtr File;
        public IntPtr ImageBase;
        public uint DebugInfoFileOffset;
        public uint DebugInfoSize;
        public IntPtr ImageName;
        public ushort Unicode;
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct DebugEventUnion
    {
        [FieldOffset(0)] public DebugCreateProcessInfo CreateProcess;
        [FieldOffset(0)] public DebugExitProcessInfo ExitProcess;
        [FieldOffset(0)] public DebugExceptionInfo Exception;
        [FieldOffset(0)] public DebugCreateThreadInfo CreateThread;
        [FieldOffset(0)] public DebugLoadDllInfo LoadDll;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DebugEvent { public uint Code; public uint ProcessId; public uint ThreadId; public DebugEventUnion Data; }

    private sealed class DebugActiveProcess
    {
        public D32DebugProcessRecordV2 Record;
        public IntPtr Handle;
    }

    private sealed class DebugImageSnapshot
    {
        public string Path;
        public long Bytes;
        public string Sha256;
        public string VolumeSerialHex;
        public string FileIdHex;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObjectW(IntPtr jobAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        uint jobObjectInformationClass,
        ref JobObjectExtendedLimitInformation jobObjectInformation,
        uint jobObjectInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(
        out IntPtr readPipe,
        out IntPtr writePipe,
        ref SecurityAttributes pipeAttributes,
        uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetHandleInformation(IntPtr handle, out uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateEventW(
        ref SecurityAttributes eventAttributes,
        bool manualReset,
        bool initialState,
        string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(
        IntPtr job,
        uint jobObjectInformationClass,
        ref JobObjectBasicAccountingInformation jobObjectInformation,
        uint jobObjectInformationLength,
        out uint returnLength);

    [DllImport("kernel32.dll", EntryPoint = "QueryInformationJobObject", SetLastError = true)]
    private static extern bool QueryExtendedInformationJobObject(
        IntPtr job,
        uint jobObjectInformationClass,
        ref JobObjectExtendedLimitInformation jobObjectInformation,
        uint jobObjectInformationLength,
        out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WaitForDebugEvent(out DebugEvent debugEvent, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ContinueDebugEvent(uint processId, uint threadId, uint continueStatus);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugSetProcessKillOnExit(bool killOnExit);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr process, out DebugFileTime creation, out DebugFileTime exit, out DebugFileTime kernel, out DebugFileTime user);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(IntPtr file, out DebugFileInformation information);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(IntPtr file, int informationClass, IntPtr buffer, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr bytesRead);

    [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int argumentCount);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetWindowsDirectoryW(StringBuilder buffer, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetSystemDirectoryW(StringBuilder buffer, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(IntPtr file, StringBuilder path, uint size, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess, out IntPtr targetHandle, uint desiredAccess, bool inheritHandle, uint options);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr process, out bool wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentProcessId();

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr process, out bool debuggerPresent);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, int informationClass, out DebugProcessBasicInformation information, int length, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr attributeList,
        int attributeCount,
        int flags,
        ref IntPtr attributeListSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList,
        uint flags,
        IntPtr attribute,
        IntPtr value,
        IntPtr size,
        IntPtr previousValue,
        IntPtr returnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfoEx startupInfo,
        out ProcessInformation processInformation);

    private IntPtr _job;
    private IntPtr _parentJob;
    private IntPtr _process;
    private IntPtr _parentProcess;
    private IntPtr _thread;
    private SafeFileHandle _stdoutHandle;
    private SafeFileHandle _stderrHandle;
    private FileStream _stdoutStream;
    private FileStream _stderrStream;
    private bool _disposed;
    private bool _closedJobActiveProcessCountVerified;
    private uint _closedJobActiveProcessCount;
    private int _closedJobActiveProcessCountError;
    private bool _debugEnabled;
    private bool _jobNonBreakawayVerified;
    private bool _debugKillOnExitEnabled;
    private bool _debugRootResumedAfterKillOnExit;
    private bool _debugCleanupVerified;
    private bool _debugThreadJoined;
    private bool _debugRetainedProcessHandlesSignaled;
    private bool _debugAssociationQueryVerified;
    private bool _debugAssociationAbsent;
    private int _debugRetainedProcessHandleCount;
    private string _debugRetainedProcessHandleStates;
    private D32DebugLaunchCoordinator _debugCoordinator;
    private readonly object _observedProcessLock = new object();
    private readonly List<IntPtr> _observedProcessHandles = new List<IntPtr>();
    private readonly List<uint> _observedProcessIds = new List<uint>();
    private readonly List<string> _observedHandleDuplicationAudit = new List<string>();
    private readonly object _h7cGitChildLock = new object();
    private readonly List<D32H7CGitChildObservationV1> _h7cGitChildren = new List<D32H7CGitChildObservationV1>();
    private D32DebugProcessTraceV2 _debugTrace;

    public int ProcessId { get; private set; }
    public bool JobAssigned { get; private set; }
    public int DebugContinueCallCount { get; private set; }
    public uint DebuggerThreadId { get; private set; }
    public string LaunchMode { get { return (_debugEnabled ? "DedicatedOSDebuggerThread(CreateProcessW(DEBUG_PROCESS|CREATE_SUSPENDED)+DebugSetProcessKillOnExit(TRUE)+ResumeThread+WaitForDebugEvent+ContinueDebugEvent)+EXTENDED_STARTUP_INFO+HANDLE_LIST(stdout/stderr)+AssignProcessToJobObject(KILL_ON_JOB_CLOSE)" : "CreateProcessW(CREATE_SUSPENDED|EXTENDED_STARTUP_INFO)+HANDLE_LIST(stdout/stderr)+AssignProcessToJobObject(KILL_ON_JOB_CLOSE)+ResumeThread"); } }

    public static bool DebugCreateProcessIdentityMatches(uint eventProcessId, uint processHandleProcessId, int createProcessReturnedRootProcessId, bool isRootProcessEvent)
    {
        if (eventProcessId == 0 || processHandleProcessId == 0 || eventProcessId != processHandleProcessId) return false;
        if (!isRootProcessEvent) return true;
        return createProcessReturnedRootProcessId > 0 && eventProcessId == (uint)createProcessReturnedRootProcessId;
    }

    private D32FixtureNativeProcessV2(
        IntPtr job,
        IntPtr process,
        IntPtr thread,
        IntPtr stdoutRead,
        IntPtr stderrRead,
        uint processId,
        bool debugEnabled)
    {
        _job = job;
        _process = process;
        _thread = thread;
        _stdoutHandle = new SafeFileHandle(stdoutRead, true);
        _stderrHandle = new SafeFileHandle(stderrRead, true);
        ProcessId = checked((int)processId);
        _debugEnabled = debugEnabled;
        if (debugEnabled)
        {
            if (!DuplicateHandle(GetCurrentProcess(), job, GetCurrentProcess(), out _parentJob, 0, false, DuplicateSameAccess))
                ThrowLastError("DuplicateHandle(parent retained Job) failed");
            if (!DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), out _parentProcess, 0, false, DuplicateSameAccess))
            {
                int error = Marshal.GetLastWin32Error();
                CloseIfOpen(ref _parentJob, "CloseHandle(parent retained Job after duplicate failure)");
                throw new Win32Exception(error, "DuplicateHandle(parent retained root process) failed");
            }
        }
        JobAssigned = true;
    }

    private static void ThrowLastError(string prefix)
    {
        int error = Marshal.GetLastWin32Error();
        throw new Win32Exception(error, prefix + " (win32=" + error.ToString() + ")");
    }

    private static string CloseIfOpen(ref IntPtr handle, string label)
    {
        if (handle != IntPtr.Zero && handle != new IntPtr(-1))
        {
            if (!CloseHandle(handle))
            {
                int error = Marshal.GetLastWin32Error();
                return label + " failed (win32=" + error.ToString() + ")";
            }
            handle = IntPtr.Zero;
        }
        return null;
    }

    public static IntPtr CreateInheritableTestHandle()
    {
        SecurityAttributes attributes = new SecurityAttributes();
        attributes.Length = Marshal.SizeOf(typeof(SecurityAttributes));
        attributes.InheritHandle = 1;
        IntPtr handle = CreateEventW(ref attributes, false, false, null);
        if (handle == IntPtr.Zero) ThrowLastError("CreateEventW(test handle) failed");
        return handle;
    }

    public static bool CloseInheritableTestHandle(IntPtr handle)
    {
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return true;
        return CloseHandle(handle);
    }

    public static bool IsInheritableTestHandleSignaled(IntPtr handle)
    {
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            throw new ArgumentException("test event handle is invalid", "handle");
        uint result = WaitForSingleObject(handle, 0);
        if (result == WaitObject0) return true;
        if (result == 0x00000102) return false;
        ThrowLastError("WaitForSingleObject(test event) failed (result=" + result.ToString(CultureInfo.InvariantCulture) + ")");
        return false;
    }

    private static void RequireHandleInheritance(IntPtr handle, bool expected, string label)
    {
        uint flags;
        if (!GetHandleInformation(handle, out flags))
            ThrowLastError("GetHandleInformation(" + label + ") failed");
        bool actual = (flags & HandleFlagInherit) != 0;
        if (actual != expected)
            throw new InvalidOperationException(
                "HANDLE_INHERITANCE_MISMATCH: " + label + " expected=" + expected.ToString() + " actual=" + actual.ToString());
    }

    private static void ConfigureKillOnClose(IntPtr job)
    {
        JobObjectExtendedLimitInformation limits = new JobObjectExtendedLimitInformation();
        limits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
        if (!SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformationClass,
            ref limits,
            (uint)Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation))))
        {
            ThrowLastError("SetInformationJobObject(KILL_ON_JOB_CLOSE) failed");
        }
    }

    private static void RequireNonBreakawayJob(IntPtr job)
    {
        if (job == IntPtr.Zero || job == new IntPtr(-1)) throw new InvalidOperationException("JOB_CONTAINMENT_BLOCKED: owned Job handle is invalid");
        JobObjectExtendedLimitInformation limits = new JobObjectExtendedLimitInformation();
        uint returned;
        uint expectedLength = (uint)Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation));
        if (!QueryExtendedInformationJobObject(job, JobObjectExtendedLimitInformationClass, ref limits, expectedLength, out returned) || returned < expectedLength)
            ThrowLastError("QueryInformationJobObject(ExtendedLimitInformation) failed");
        uint flags = limits.BasicLimitInformation.LimitFlags;
        if (!HasRequiredNonBreakawayJobFlags(flags))
            throw new InvalidOperationException("JOB_CONTAINMENT_BLOCKED: owned Job is not exactly KILL_ON_JOB_CLOSE with breakaway disabled (flags=0x" + flags.ToString("x8", CultureInfo.InvariantCulture) + ")");
    }

    public static bool HasRequiredNonBreakawayJobFlags(uint flags)
    {
        return flags == JobObjectLimitKillOnJobClose &&
            (flags & (JobObjectLimitBreakawayOk | JobObjectLimitSilentBreakawayOk)) == 0;
    }

    private static bool ProcessIsInOwnedJob(IntPtr process, IntPtr job)
    {
        bool inJob;
        if (process == IntPtr.Zero || process == new IntPtr(-1) || job == IntPtr.Zero || job == new IntPtr(-1)) return false;
        if (!IsProcessInJob(process, job, out inJob)) return false;
        return inJob;
    }

    private bool TryGetActiveProcessCount(out uint count, out int error)
    {
        count = 0;
        error = 0;
        if (_job == IntPtr.Zero)
        {
            error = 6;
            return false;
        }
        JobObjectBasicAccountingInformation accounting = new JobObjectBasicAccountingInformation();
        uint returnLength;
        uint expectedLength = (uint)Marshal.SizeOf(typeof(JobObjectBasicAccountingInformation));
        if (!QueryInformationJobObject(
            _job,
            JobObjectBasicAccountingInformationClass,
            ref accounting,
            expectedLength,
            out returnLength))
        {
            error = Marshal.GetLastWin32Error();
            return false;
        }
        if (returnLength < expectedLength)
        {
            error = 122;
            return false;
        }
        count = accounting.ActiveProcesses;
        return true;
    }

    private bool WaitForJobActiveProcessZero(int timeoutMilliseconds, out uint count, out int error)
    {
        if (timeoutMilliseconds < 0) timeoutMilliseconds = 0;
        DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);
        do
        {
            if (!TryGetActiveProcessCount(out count, out error)) return false;
            if (count == 0) return true;
            int remaining = (int)Math.Max(0, (deadline - DateTime.UtcNow).TotalMilliseconds);
            if (remaining == 0) break;
            Thread.Sleep(Math.Min(50, remaining));
        }
        while (DateTime.UtcNow <= deadline);

        if (!TryGetActiveProcessCount(out count, out error)) return false;
        return count == 0;
    }

    public static D32FixtureNativeProcessV2 Start(
        string filePath,
        string commandLine,
        string workingDirectory,
        string environmentBlock,
        string testFailure)
    {
        return StartInternal(filePath, commandLine, workingDirectory, environmentBlock, testFailure, false);
    }

    public static D32FixtureNativeProcessV2 StartDebug(
        string filePath,
        string commandLine,
        string workingDirectory,
        string environmentBlock)
    {
        D32DebugLaunchCoordinator coordinator = new D32DebugLaunchCoordinator();
        Thread worker = new Thread(delegate() {
            try
            {
                D32FixtureNativeProcessV2 process = StartInternal(filePath, commandLine, workingDirectory, environmentBlock, null, true, true);
                process._debugCoordinator = coordinator;
                process.DebuggerThreadId = GetCurrentThreadId();
                coordinator.Process = process;
                coordinator.ProcessReady.Set();
                if (!coordinator.CapturePlanReady.WaitOne(30000))
                {
                    process.RequestDebugAbort("caller did not provide a capture plan before the bounded startup deadline");
                    return;
                }
                if (coordinator.AbortRequested)
                {
                    process.RequestDebugAbort("caller aborted before the debug capture plan was accepted");
                    return;
                }
                process._debugTrace = process.MonitorDebugEvents(
                    coordinator.ExpectedRootPin,
                    coordinator.ApprovedImagePins,
                    coordinator.CandidateImageRoots,
                    coordinator.TimeoutMilliseconds,
                    coordinator.InjectFirstCreateInterruption,
                    coordinator.InjectFirstCreateIdentityMismatch);
            }
            catch (Exception error)
            {
                coordinator.Failure = error;
                if (coordinator.Process == null) coordinator.ProcessReady.Set();
                else coordinator.Process.RequestDebugAbort("dedicated debugger worker failed: " + error.Message);
            }
            finally { coordinator.CaptureCompleted.Set(); }
        });
        worker.IsBackground = true;
        worker.Name = "D32-dedicated-debugger";
        coordinator.WorkerThread = worker;
        worker.Start();
        if (!coordinator.ProcessReady.WaitOne(30000))
        {
            coordinator.AbortRequested = true;
            coordinator.CapturePlanReady.Set();
            if (!worker.Join(5000)) throw new TimeoutException("dedicated debugger thread did not finish bounded process startup");
            throw new TimeoutException("dedicated debugger process startup deadline exceeded");
        }
        if (coordinator.Process == null)
        {
            worker.Join(5000);
            throw new InvalidOperationException("dedicated debugger process startup failed", coordinator.Failure);
        }
        return coordinator.Process;
    }

    public void ConfigureDebugCapture(string expectedRootPin, string[] approvedImagePins, string[] candidateImageRoots, int timeoutMilliseconds, bool injectFirstCreateInterruption, bool injectFirstCreateIdentityMismatch)
    {
        ConfigureDebugCapture(expectedRootPin, approvedImagePins, candidateImageRoots, timeoutMilliseconds, injectFirstCreateInterruption, injectFirstCreateIdentityMismatch, null);
    }

    public void ConfigureDebugCapture(string expectedRootPin, string[] approvedImagePins, string[] candidateImageRoots, int timeoutMilliseconds, bool injectFirstCreateInterruption, bool injectFirstCreateIdentityMismatch, string failureInjection)
    {
        ConfigureDebugCapture(expectedRootPin, approvedImagePins, candidateImageRoots, timeoutMilliseconds,
            injectFirstCreateInterruption, injectFirstCreateIdentityMismatch, failureInjection, false, false, false, null, null, null);
    }

    public static bool IsApprovedPinnedCargoVctipConfiguration(string expectedRootPin, string[] approvedImagePins)
    {
        try
        {
            string[] root = ParseDebugPin(expectedRootPin);
            if (!String.Equals(Path.GetFileName(root[0]), "cargo.exe", StringComparison.OrdinalIgnoreCase) || approvedImagePins == null) return false;
            List<string[]> vctipPins = new List<string[]>();
            for (int i = 0; i < approvedImagePins.Length; i++)
            {
                string[] pin = ParseDebugPin(approvedImagePins[i]);
                if (String.Equals(Path.GetFileName(pin[0]), "vctip.exe", StringComparison.OrdinalIgnoreCase) || IsPinnedVctipContentIdentity(pin[1], pin[2])) vctipPins.Add(pin);
            }
            return vctipPins.Count == 1 && IsExactPinnedVctipPin(vctipPins[0]);
        }
        catch { return false; }
    }

    public static bool IsPinnedCargoVctipChildAllowed(
        string expectedRootPath,
        bool allowPinnedCargoVctip,
        string imagePath,
        long imageBytes,
        string imageSha256,
        string imageVolumeSerialHex,
        string imageFileIdHex,
        string[] approvedImagePins)
    {
        if (!allowPinnedCargoVctip || String.IsNullOrWhiteSpace(expectedRootPath) ||
            !String.Equals(Path.GetFileName(expectedRootPath), "cargo.exe", StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(Path.GetFileName(imagePath), "vctip.exe", StringComparison.OrdinalIgnoreCase) ||
            approvedImagePins == null) return false;
        try
        {
            string[][] matches = approvedImagePins.Select(ParseDebugPin)
                .Where(pin => String.Equals(Path.GetFileName(pin[0]), "vctip.exe", StringComparison.OrdinalIgnoreCase) || IsPinnedVctipContentIdentity(pin[1], pin[2]))
                .ToArray();
            if (matches.Length != 1 || !IsExactPinnedVctipPin(matches[0])) return false;
            DebugImageSnapshot image = new DebugImageSnapshot {
                Path = NormalizeDebugPath(imagePath), Bytes = imageBytes, Sha256 = imageSha256,
                VolumeSerialHex = imageVolumeSerialHex, FileIdHex = imageFileIdHex
            };
            return DebugImageMatches(image, matches[0]);
        }
        catch { return false; }
    }

    public static bool IsApprovedPinnedCargoVendoredProtocConfiguration(string expectedRootPin, string[] approvedImagePins, string expectedCargoHome, string vendoredProtocPin)
    {
        try
        {
            string[] root = ParseDebugPin(expectedRootPin);
            if (!String.Equals(Path.GetFileName(root[0]), "cargo.exe", StringComparison.OrdinalIgnoreCase) || approvedImagePins == null || String.IsNullOrWhiteSpace(expectedCargoHome)) return false;
            string[] grantPin = ParseDebugPin(vendoredProtocPin);
            if (!IsExactPinnedVendoredProtocPin(grantPin, expectedCargoHome)) return false;
            List<string[]> protocPins = new List<string[]>();
            for (int i = 0; i < approvedImagePins.Length; i++)
            {
                string[] pin = ParseDebugPin(approvedImagePins[i]);
                if (String.Equals(Path.GetFileName(pin[0]), "protoc.exe", StringComparison.OrdinalIgnoreCase) || IsPinnedVendoredProtocContentIdentity(pin[1], pin[2]))
                    protocPins.Add(pin);
            }
            return protocPins.Count == 1 && DebugImagePinsEqual(protocPins[0], grantPin);
        }
        catch { return false; }
    }

    public static bool IsPinnedCargoVendoredProtocChildAllowed(
        string expectedRootPath,
        bool allowPinnedVendoredProtoc,
        string imagePath,
        long imageBytes,
        string imageSha256,
        string imageVolumeSerialHex,
        string imageFileIdHex,
        string expectedCargoHome,
        string vendoredProtocPin)
    {
        if (!allowPinnedVendoredProtoc || String.IsNullOrWhiteSpace(expectedRootPath) ||
            !String.Equals(Path.GetFileName(expectedRootPath), "cargo.exe", StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(Path.GetFileName(imagePath), "protoc.exe", StringComparison.OrdinalIgnoreCase) || String.IsNullOrWhiteSpace(expectedCargoHome)) return false;
        try
        {
            string[] pin = ParseDebugPin(vendoredProtocPin);
            if (!IsExactPinnedVendoredProtocPin(pin, expectedCargoHome)) return false;
            DebugImageSnapshot image = new DebugImageSnapshot {
                Path = NormalizeDebugPath(imagePath), Bytes = imageBytes, Sha256 = imageSha256,
                VolumeSerialHex = imageVolumeSerialHex, FileIdHex = imageFileIdHex
            };
            return DebugImageMatches(image, pin);
        }
        catch { return false; }
    }

    private static bool IsExactPinnedVendoredProtocPin(string[] pin, string expectedCargoHome)
    {
        string expectedPath = NormalizeDebugPath(Path.Combine(Path.GetFullPath(expectedCargoHome),
            @"registry\src\index.crates.io-1949cf8c6b5b557f\protoc-bin-vendored-win32-3.2.0\bin\protoc.exe"));
        if (pin == null || pin.Length != 5 ||
            !String.Equals(Path.GetFileName(pin[0]), "protoc.exe", StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(NormalizeDebugPath(pin[0]), expectedPath, StringComparison.OrdinalIgnoreCase) ||
            !NormalizeDebugPath(pin[0]).EndsWith(PinnedVendoredProtocPathSuffix, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(pin[1], PinnedVendoredProtocBytes, StringComparison.Ordinal) ||
            !String.Equals(pin[2], PinnedVendoredProtocSha256, StringComparison.Ordinal) ||
            !IsLowerHex(pin[3], 16) || !IsLowerHex(pin[4], 32)) return false;
        return true;
    }

    private static bool IsLowerHex(string value, int expectedLength)
    {
        if (String.IsNullOrWhiteSpace(value) || value.Length != expectedLength) return false;
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    private static bool IsPinnedVendoredProtocContentIdentity(string bytes, string sha256)
    {
        return String.Equals(bytes, PinnedVendoredProtocBytes, StringComparison.Ordinal) &&
            String.Equals(sha256, PinnedVendoredProtocSha256, StringComparison.Ordinal);
    }

    private static bool DebugImagePinsEqual(string[] left, string[] right)
    {
        if (left == null || right == null || left.Length != 5 || right.Length != 5) return false;
        return String.Equals(NormalizeDebugPath(left[0]), NormalizeDebugPath(right[0]), StringComparison.OrdinalIgnoreCase) &&
            String.Equals(left[1], right[1], StringComparison.Ordinal) &&
            String.Equals(left[2], right[2], StringComparison.Ordinal) &&
            String.Equals(left[3], right[3], StringComparison.Ordinal) &&
            String.Equals(left[4], right[4], StringComparison.Ordinal);
    }

    private static bool IsExactPinnedVctipPin(string[] pin)
    {
        return pin != null && pin.Length == 5 &&
            String.Equals(NormalizeDebugPath(pin[0]), NormalizeDebugPath(PinnedVctipPath), StringComparison.OrdinalIgnoreCase) &&
            String.Equals(pin[1], PinnedVctipBytes, StringComparison.Ordinal) &&
            String.Equals(pin[2], PinnedVctipSha256, StringComparison.Ordinal) &&
            String.Equals(pin[3], PinnedVctipVolumeSerial, StringComparison.Ordinal) &&
            String.Equals(pin[4], PinnedVctipFileId, StringComparison.Ordinal);
    }

    private static bool IsPinnedVctipContentIdentity(string bytes, string sha256)
    {
        return String.Equals(bytes, PinnedVctipBytes, StringComparison.Ordinal) &&
            String.Equals(sha256, PinnedVctipSha256, StringComparison.Ordinal);
    }

    private static bool IsPinnedVctipContentIdentity(long bytes, string sha256)
    {
        return bytes == 335328 && String.Equals(sha256, PinnedVctipSha256, StringComparison.Ordinal);
    }

    public void ConfigurePinnedCargoDebugCapture(string expectedRootPin, string[] approvedImagePins, string[] candidateImageRoots, int timeoutMilliseconds)
    {
        if (!IsApprovedPinnedCargoVctipConfiguration(expectedRootPin, approvedImagePins))
            throw new InvalidOperationException("D32_VCTIP_PROFILE_PIN_BLOCKED: only the exact approved caller-pinned Profile V2 VCTIP entry may be configured beneath a fixed Cargo root");
        ConfigureDebugCapture(expectedRootPin, approvedImagePins, candidateImageRoots, timeoutMilliseconds,
            false, false, null, false, true, false, null, null, null);
    }

    public void ConfigurePinnedCargoDebugCaptureWithVendoredProtoc(string expectedRootPin, string[] approvedImagePins, string[] candidateImageRoots, int timeoutMilliseconds, string expectedCargoHome, string vendoredProtocPin)
    {
        if (!IsApprovedPinnedCargoVctipConfiguration(expectedRootPin, approvedImagePins))
            throw new InvalidOperationException("D32_VCTIP_PROFILE_PIN_BLOCKED: only the exact approved caller-pinned Profile V2 VCTIP entry may be configured beneath a fixed Cargo root");
        if (!IsApprovedPinnedCargoVendoredProtocConfiguration(expectedRootPin, approvedImagePins, expectedCargoHome, vendoredProtocPin))
            throw new InvalidOperationException("VENDORED_PROTOC_GRANT_BLOCKED: native CREATE continuation requires the unique exact per-run locked protoc image pin beneath the fixed Cargo root");
        ConfigureDebugCapture(expectedRootPin, approvedImagePins, candidateImageRoots, timeoutMilliseconds,
            false, false, null, false, true, true, expectedCargoHome, vendoredProtocPin, null);
    }

    public void ConfigurePinnedCargoDebugCaptureWithVendoredProtocAndH7CGit(
        string expectedRootPin, string[] approvedImagePins, string[] candidateImageRoots, int timeoutMilliseconds,
        string expectedCargoHome, string vendoredProtocPin, string h7cGitNativePolicyText)
    {
        if (!IsApprovedPinnedCargoVctipConfiguration(expectedRootPin, approvedImagePins))
            throw new InvalidOperationException("D32_VCTIP_PROFILE_PIN_BLOCKED: only the exact approved caller-pinned Profile V2 VCTIP entry may be configured beneath a fixed Cargo root");
        if (!IsApprovedPinnedCargoVendoredProtocConfiguration(expectedRootPin, approvedImagePins, expectedCargoHome, vendoredProtocPin))
            throw new InvalidOperationException("VENDORED_PROTOC_GRANT_BLOCKED: native CREATE continuation requires the unique exact per-run locked protoc image pin beneath the fixed Cargo root");
        H7CGitNativePolicy policy = ParseH7CGitNativePolicy(h7cGitNativePolicyText);
        string[] root = ParseDebugPin(expectedRootPin);
        if (!String.Equals(Path.GetFileName(root[0]), "cargo.exe", StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(NormalizeDebugPath(policy.Repository), NormalizeDebugPath(Path.GetFullPath(policy.Repository)), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("H7C_GIT_GRANT_BLOCKED: Git child permission is limited to an exact Cargo-root policy and canonical candidate repository");
        ConfigureDebugCapture(expectedRootPin, approvedImagePins, candidateImageRoots, timeoutMilliseconds,
            false, false, null, false, true, true, expectedCargoHome, vendoredProtocPin, h7cGitNativePolicyText);
    }

    public void ConfigurePinnedGitDebugCapture(string expectedRootPin, string approvedWindowsImagePin, int timeoutMilliseconds)
    {
        string[] pin = ParseDebugPin(expectedRootPin);
        if (!String.Equals(Path.GetFileName(pin[0]), "git.exe", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("standalone pinned-Git capture requires an exact git.exe root image");
        string[] childPin = ParseDebugPin(approvedWindowsImagePin);
        if (!String.Equals(Path.GetFileName(childPin[0]), "conhost.exe", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("standalone pinned-Git capture requires the caller-pinned conhost.exe child image");
        ConfigureDebugCapture(expectedRootPin, new string[] { approvedWindowsImagePin }, new string[0], timeoutMilliseconds,
            false, false, null, true, false, false, null, null, null);
    }

    private void ConfigureDebugCapture(string expectedRootPin, string[] approvedImagePins, string[] candidateImageRoots, int timeoutMilliseconds, bool injectFirstCreateInterruption, bool injectFirstCreateIdentityMismatch, string failureInjection, bool allowPinnedGitRoot, bool allowPinnedCargoVctip, bool allowPinnedVendoredProtoc, string vendoredProtocCargoHomePath, string vendoredProtocPin, string h7cGitNativePolicyText)
    {
        if (!_debugEnabled || _debugCoordinator == null) throw new InvalidOperationException("dedicated debugger session is not initialized");
        if (String.IsNullOrWhiteSpace(expectedRootPin) || approvedImagePins == null || candidateImageRoots == null || timeoutMilliseconds <= 0)
            throw new ArgumentException("expected root pin, image inventories, and a positive deadline are mandatory");
        lock (_debugCoordinator)
        {
            if (_debugCoordinator.CapturePlanReady.WaitOne(0)) throw new InvalidOperationException("debug capture plan was already supplied");
            _debugCoordinator.ExpectedRootPin = expectedRootPin;
            _debugCoordinator.ApprovedImagePins = (string[])approvedImagePins.Clone();
            _debugCoordinator.CandidateImageRoots = (string[])candidateImageRoots.Clone();
            _debugCoordinator.TimeoutMilliseconds = timeoutMilliseconds;
            _debugCoordinator.InjectFirstCreateInterruption = injectFirstCreateInterruption;
            _debugCoordinator.InjectFirstCreateIdentityMismatch = injectFirstCreateIdentityMismatch;
            _debugCoordinator.FailureInjection = failureInjection;
            _debugCoordinator.AllowPinnedGitRoot = allowPinnedGitRoot;
            _debugCoordinator.AllowPinnedCargoVctip = allowPinnedCargoVctip;
            _debugCoordinator.AllowPinnedVendoredProtoc = allowPinnedVendoredProtoc;
            _debugCoordinator.VendoredProtocCargoHomePath = vendoredProtocCargoHomePath;
            _debugCoordinator.VendoredProtocPin = vendoredProtocPin;
            _debugCoordinator.H7CGitNativePolicyText = h7cGitNativePolicyText;
            _debugCoordinator.CapturePlanReady.Set();
        }
    }

    public D32DebugProcessTraceV2 WaitForDebugTrace(int timeoutMilliseconds)
    {
        if (!_debugEnabled || _debugCoordinator == null) throw new InvalidOperationException("dedicated debugger session is not initialized");
        if (timeoutMilliseconds <= 0) throw new ArgumentOutOfRangeException("timeoutMilliseconds");
        if (!_debugCoordinator.CapturePlanReady.WaitOne(0)) RequestDebugAbort("capture plan was not supplied before waiting for the trace");
        Thread worker = _debugCoordinator.WorkerThread;
        bool joined = worker != null && worker.Join(timeoutMilliseconds);
        if (!joined)
        {
            RequestDebugAbort("dedicated debugger thread join deadline exceeded");
            joined = worker != null && worker.Join(5000);
        }
        if (!joined) throw new TimeoutException("dedicated debugger thread failed to exit and join after Job termination");
        D32DebugProcessTraceV2 trace = _debugTrace;
        if (trace == null)
        {
            trace = CreateBlockedDebugTrace(_debugCoordinator.Failure == null ? "dedicated debugger worker returned without a trace" : _debugCoordinator.Failure.Message);
            _debugTrace = trace;
        }
        PopulatePostJoinDebugEvidence(trace, joined);
        return trace;
    }

    public D32H7CGitChildObservationV1[] GetH7CGitChildObservations()
    {
        lock (_h7cGitChildLock) return _h7cGitChildren.ToArray();
    }

    private static D32DebugProcessTraceV2 CreateBlockedDebugTrace(string reason)
    {
        DateTime now = DateTime.UtcNow;
        long debuggerCreation = GetDebugProcessCreationTime(GetCurrentProcess());
        return new D32DebugProcessTraceV2 {
            RecordType = "D32_DEBUG_JOB_PROCESS_TRACE_V2", SchemaVersion = 2,
            EventSource = "Win32-WaitForDebugEvent-dedicated-OS-thread", State = "BLOCKED", BlockReason = reason,
            DebuggerProcessId = (int)GetCurrentProcessId(), UncontinuedCreateProcessId = 0,
            UncontinuedCreateContinueCallCount = 0, DebuggerCreationFileTime = debuggerCreation,
            DebuggerCreatedAtUtc = DebugFileTimeUtc(debuggerCreation), StartedAtUtc = now.ToString("o", CultureInfo.InvariantCulture),
            CompletedAtUtc = now.ToString("o", CultureInfo.InvariantCulture), DebuggerThreadId = 0,
            DedicatedDebuggerThread = false, DebuggerKillOnExitEnabled = false, RootResumedAfterKillOnExit = false,
            DebuggerThreadExited = false, DebuggerThreadJoined = false, RetainedProcessHandleCount = 0,
            RetainedProcessHandlesSignaled = false, DebuggerAssociationQueryVerified = false, DebuggerAssociationAbsent = false,
            EventChainComplete = false, ProcessEvents = new List<D32DebugProcessEventV2>(), Processes = new List<D32DebugProcessRecordV2>()
        };
    }

    private void RequestDebugAbort(string reason)
    {
        if (_debugCoordinator != null)
        {
            lock (_debugCoordinator) _debugCoordinator.AbortRequested = true;
            _debugCoordinator.CapturePlanReady.Set();
        }
        IntPtr job = _parentJob != IntPtr.Zero ? _parentJob : _job;
        if (job != IntPtr.Zero && !TerminateJobObject(job, 0xD32010FF))
        {
            if (_debugCoordinator != null && _debugCoordinator.Failure == null)
                _debugCoordinator.Failure = new Win32Exception(Marshal.GetLastWin32Error(), "TerminateJobObject during debug abort failed: " + reason);
        }
    }

    private void PopulatePostJoinDebugEvidence(D32DebugProcessTraceV2 trace, bool joined)
    {
        Thread worker = _debugCoordinator == null ? null : _debugCoordinator.WorkerThread;
        trace.DebuggerThreadId = DebuggerThreadId;
        trace.DedicatedDebuggerThread = worker != null && worker != Thread.CurrentThread && worker.Name == "D32-dedicated-debugger";
        trace.DebuggerKillOnExitEnabled = _debugKillOnExitEnabled;
        trace.RootResumedAfterKillOnExit = _debugRootResumedAfterKillOnExit;
        trace.DebuggerThreadExited = worker != null && !worker.IsAlive;
        trace.DebuggerThreadJoined = joined && trace.DebuggerThreadExited;
        _debugThreadJoined = trace.DebuggerThreadJoined;

        List<IntPtr> handles = new List<IntPtr>();
        List<uint> processIds = new List<uint>();
        if (_parentProcess != IntPtr.Zero) { handles.Add(_parentProcess); processIds.Add((uint)ProcessId); }
        lock (_observedProcessLock) { handles.AddRange(_observedProcessHandles); processIds.AddRange(_observedProcessIds); }
        _debugRetainedProcessHandleCount = handles.Count;
        _debugRetainedProcessHandlesSignaled = handles.Count > 0;
        _debugAssociationQueryVerified = handles.Count > 0;
        _debugAssociationAbsent = handles.Count > 0;
        List<string> handleStates = new List<string>();
        DateTime processSignalDeadline = DateTime.UtcNow.AddSeconds(10);
        for (int i = 0; i < handles.Count; i++)
        {
            IntPtr handle = handles[i];
            uint pid = i < processIds.Count ? processIds[i] : 0;
            int remainingMilliseconds = Math.Max(0, (int)(processSignalDeadline - DateTime.UtcNow).TotalMilliseconds);
            uint waitResult = handle == IntPtr.Zero ? UInt32.MaxValue : WaitForSingleObject(handle, (uint)remainingMilliseconds);
            int waitError = waitResult == UInt32.MaxValue ? Marshal.GetLastWin32Error() : 0;
            bool present = true;
            bool debuggerQueryOk = handle != IntPtr.Zero && CheckRemoteDebuggerPresent(handle, out present);
            int debuggerQueryError = debuggerQueryOk ? 0 : Marshal.GetLastWin32Error();
            handleStates.Add(pid.ToString(CultureInfo.InvariantCulture) + ":h=0x" + handle.ToInt64().ToString("x", CultureInfo.InvariantCulture) + ":wait=" + waitResult.ToString(CultureInfo.InvariantCulture) + ":waitError=" + waitError.ToString(CultureInfo.InvariantCulture) + ":debuggerQuery=" + debuggerQueryOk.ToString() + ":queryError=" + debuggerQueryError.ToString(CultureInfo.InvariantCulture) + ":present=" + present.ToString());
            if (handle == IntPtr.Zero || waitResult != WaitObject0)
                _debugRetainedProcessHandlesSignaled = false;
            if (!debuggerQueryOk)
            {
                _debugAssociationQueryVerified = false;
                _debugAssociationAbsent = false;
            }
            else if (present) _debugAssociationAbsent = false;
        }
        _debugRetainedProcessHandleStates = String.Join(";", handleStates.ToArray());

        trace.RetainedProcessHandleCount = _debugRetainedProcessHandleCount;
        trace.RetainedProcessHandlesSignaled = _debugRetainedProcessHandlesSignaled;
        trace.DebuggerAssociationQueryVerified = _debugAssociationQueryVerified;
        trace.DebuggerAssociationAbsent = _debugAssociationAbsent;

        JobObjectBasicAccountingInformation accounting;
        if (_parentJob != IntPtr.Zero && TryGetDebugJobAccounting(_parentJob, out accounting))
        {
            DateTime settleDeadline = DateTime.UtcNow.AddSeconds(5);
            while (accounting.ActiveProcesses != 0 && DateTime.UtcNow < settleDeadline && TryGetDebugJobAccounting(_parentJob, out accounting))
                Thread.Sleep(20);
            trace.JobAccountingVerified = true;
            trace.JobTotalProcesses = accounting.TotalProcesses;
            trace.JobActiveProcesses = accounting.ActiveProcesses;
        }
        else
        {
            trace.DebugApiErrorCount++;
            trace.JobAccountingVerified = false;
            TraceBlock(trace, "independent post-join QueryInformationJobObject accounting was unavailable");
        }
        trace.AccountingConsistent = trace.JobAccountingVerified && trace.EventChainComplete && trace.DebugApiErrorCount == 0 &&
            trace.ProcessCreateEventCount == trace.ProcessExitEventCount && trace.ProcessCreateEventCount == trace.Processes.Count &&
            trace.ProcessEvents.Count == trace.ProcessCreateEventCount + trace.ProcessExitEventCount &&
            trace.ProcessCreateEventCount == trace.JobTotalProcesses && trace.JobActiveProcesses == 0 &&
            trace.DedicatedDebuggerThread && trace.DebuggerKillOnExitEnabled && trace.RootResumedAfterKillOnExit &&
            trace.DebuggerThreadExited && trace.DebuggerThreadJoined && trace.RetainedProcessHandlesSignaled &&
            trace.DebuggerAssociationQueryVerified && trace.DebuggerAssociationAbsent;
        const string accountingBlockReason = "CREATE/EXIT, dedicated-thread cleanup, retained handles, debugger association, and independent Job accounting do not reconcile";
        if (!trace.AccountingConsistent) TraceBlock(trace, accountingBlockReason);
        else if (trace.State == "RUNNING" || trace.BlockReason == accountingBlockReason)
        {
            trace.State = "COMPLETED";
            if (trace.BlockReason == accountingBlockReason) trace.BlockReason = null;
        }
        if (trace.State == "RUNNING") trace.State = "BLOCKED";
        trace.CompletedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
    }

    private static D32FixtureNativeProcessV2 StartInternal(
        string filePath,
        string commandLine,
        string workingDirectory,
        string environmentBlock,
        string testFailure,
        bool debugEnabled,
        bool deferDebugResume = false)
    {
        if (String.IsNullOrWhiteSpace(filePath)) throw new ArgumentException("filePath");
        if (String.IsNullOrWhiteSpace(workingDirectory)) throw new ArgumentException("workingDirectory");

        IntPtr job = IntPtr.Zero;
        IntPtr stdoutRead = IntPtr.Zero;
        IntPtr stdoutWrite = IntPtr.Zero;
        IntPtr stderrRead = IntPtr.Zero;
        IntPtr stderrWrite = IntPtr.Zero;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr attributeListSize = IntPtr.Zero;
        IntPtr handleList = IntPtr.Zero;
        IntPtr nativeEnvironment = IntPtr.Zero;
        ProcessInformation pi = new ProcessInformation();
        bool transferred = false;
        bool jobNonBreakawayVerified = false;
        bool debugKillOnExitEnabled = false;
        Exception failure = null;
        string cleanupErrors = null;
        D32FixtureNativeProcessV2 result = null;

        try
        {
            job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero) ThrowLastError("CreateJobObjectW failed");
            ConfigureKillOnClose(job);
            RequireNonBreakawayJob(job);
            jobNonBreakawayVerified = true;

            SecurityAttributes pipeAttributes = new SecurityAttributes();
            pipeAttributes.Length = Marshal.SizeOf(typeof(SecurityAttributes));
            pipeAttributes.InheritHandle = 1;
            if (!CreatePipe(out stdoutRead, out stdoutWrite, ref pipeAttributes, 0))
                ThrowLastError("CreatePipe(stdout) failed");
            RequireHandleInheritance(stdoutWrite, true, "stdout child end");
            if (!SetHandleInformation(stdoutRead, HandleFlagInherit, 0))
                ThrowLastError("SetHandleInformation(stdout read) failed");
            RequireHandleInheritance(stdoutRead, false, "stdout parent end");
            if (!CreatePipe(out stderrRead, out stderrWrite, ref pipeAttributes, 0))
                ThrowLastError("CreatePipe(stderr) failed");
            RequireHandleInheritance(stderrWrite, true, "stderr child end");
            if (!SetHandleInformation(stderrRead, HandleFlagInherit, 0))
                ThrowLastError("SetHandleInformation(stderr read) failed");
            RequireHandleInheritance(stderrRead, false, "stderr parent end");

            handleList = Marshal.AllocHGlobal(IntPtr.Size * 2);
            Marshal.WriteIntPtr(handleList, 0, stdoutWrite);
            Marshal.WriteIntPtr(handleList, IntPtr.Size, stderrWrite);
            bool initialAttributeProbe = InitializeProcThreadAttributeList(
                IntPtr.Zero,
                1,
                0,
                ref attributeListSize);
            int initialAttributeError = Marshal.GetLastWin32Error();
            if (initialAttributeProbe ||
                initialAttributeError != ErrorInsufficientBuffer ||
                attributeListSize == IntPtr.Zero) {
                throw new InvalidOperationException(
                    "InitializeProcThreadAttributeList probe failed (win32=" +
                    initialAttributeError.ToString() + ", size=" + attributeListSize.ToString() + ")");
            }
            attributeList = Marshal.AllocHGlobal(checked(attributeListSize.ToInt32()));
            if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeListSize))
                ThrowLastError("InitializeProcThreadAttributeList failed");
            if (String.Equals(testFailure, "attribute", StringComparison.Ordinal)) {
                if (UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    IntPtr.Zero,
                    handleList,
                    new IntPtr(IntPtr.Size * 2),
                    IntPtr.Zero,
                    IntPtr.Zero)) {
                    throw new InvalidOperationException("SELFTEST_INJECTED_ATTRIBUTE_API_UNEXPECTED_SUCCESS");
                }
                ThrowLastError("SELFTEST_INJECTED_ATTRIBUTE_API_FAILURE");
            }
            if (!UpdateProcThreadAttribute(
                attributeList,
                0,
                new IntPtr(ProcThreadAttributeHandleList),
                handleList,
                new IntPtr(IntPtr.Size * 2),
                IntPtr.Zero,
                IntPtr.Zero)) {
                ThrowLastError("UpdateProcThreadAttribute(HANDLE_LIST) failed");
            }

            StartupInfoEx startup = new StartupInfoEx();
            startup.StartupInfo.Cb = Marshal.SizeOf(typeof(StartupInfoEx));
            startup.StartupInfo.Flags = StartfUseStdHandles;
            startup.StartupInfo.StandardInput = IntPtr.Zero;
            startup.StartupInfo.StandardOutput = stdoutWrite;
            startup.StartupInfo.StandardError = stderrWrite;
            startup.AttributeList = attributeList;
            StringBuilder mutableCommandLine = new StringBuilder(commandLine ?? String.Empty);
            if (!String.IsNullOrEmpty(environmentBlock))
                nativeEnvironment = Marshal.StringToHGlobalUni(environmentBlock);
            uint creationFlags = CreateSuspended | CreateNoWindow | CreateUnicodeEnvironment | ExtendedStartupInfoPresent | (debugEnabled ? DebugProcess : 0u);
            if (!CreateProcessW(
                filePath,
                mutableCommandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                creationFlags,
                nativeEnvironment,
                workingDirectory,
                ref startup,
                out pi)) {
                ThrowLastError("CreateProcessW failed");
            }
            DeleteProcThreadAttributeList(attributeList);
            attributeList = IntPtr.Zero;

            string closeError = CloseIfOpen(ref stdoutWrite, "CloseHandle(stdout child end)");
            if (closeError != null) throw new InvalidOperationException(closeError);
            closeError = CloseIfOpen(ref stderrWrite, "CloseHandle(stderr child end)");
            if (closeError != null) throw new InvalidOperationException(closeError);

            if (!AssignProcessToJobObject(job, pi.Process))
                ThrowLastError("AssignProcessToJobObject failed");
            RequireNonBreakawayJob(job);
            if (!ProcessIsInOwnedJob(pi.Process, job))
                throw new InvalidOperationException("JOB_CONTAINMENT_BLOCKED: suspended root process is not a member of the exact owned non-breakaway Job");
            if (String.Equals(testFailure, "assign", StringComparison.Ordinal)) {
                bool assignedWithInvalidJob = AssignProcessToJobObject(IntPtr.Zero, pi.Process);
                int assignError = assignedWithInvalidJob ? 0 : Marshal.GetLastWin32Error();
                if (assignedWithInvalidJob)
                    throw new InvalidOperationException("SELFTEST_INJECTED_ASSIGN_API_UNEXPECTED_SUCCESS");
                throw new Win32Exception(assignError, "SELFTEST_INJECTED_ASSIGN_API_FAILURE (win32=" + assignError.ToString() + ")");
            }

            if (debugEnabled)
            {
                if (!DebugSetProcessKillOnExit(true)) ThrowLastError("DebugSetProcessKillOnExit(TRUE) failed on the dedicated debugger thread");
                debugKillOnExitEnabled = true;
            }

            if (!deferDebugResume)
            {
                uint resumeResult = ResumeThread(pi.Thread);
                if (resumeResult == UInt32.MaxValue)
                    ThrowLastError("ResumeThread failed");
            }

            result = new D32FixtureNativeProcessV2(
                job,
                pi.Process,
                pi.Thread,
                stdoutRead,
                stderrRead,
                pi.ProcessId,
                debugEnabled);
            result._debugKillOnExitEnabled = debugKillOnExitEnabled;
            result._jobNonBreakawayVerified = jobNonBreakawayVerified;
            job = IntPtr.Zero;
            pi.Process = IntPtr.Zero;
            pi.Thread = IntPtr.Zero;
            stdoutRead = IntPtr.Zero;
            stderrRead = IntPtr.Zero;
            transferred = true;
        }
        catch (Exception error)
        {
            failure = error;
            try
            {
                if (pi.Process != IntPtr.Zero)
                {
                    bool jobTerminated = false;
                    if (job != IntPtr.Zero)
                    {
                        jobTerminated = TerminateJobObject(job, 1);
                        if (!jobTerminated) {
                            int terminateJobError = Marshal.GetLastWin32Error();
                            cleanupErrors = "TerminateJobObject failed (win32=" + terminateJobError.ToString() + ")";
                        }
                    }
                    bool terminated = jobTerminated || TerminateProcess(pi.Process, 1);
                    if (!terminated && jobTerminated == false)
                    {
                        int terminateError = Marshal.GetLastWin32Error();
                        string terminateFailure = "TerminateProcess failed (win32=" + terminateError.ToString() + ")";
                        cleanupErrors = String.IsNullOrEmpty(cleanupErrors) ? terminateFailure : cleanupErrors + "; " + terminateFailure;
                    }
                    uint waitResult = WaitForSingleObject(pi.Process, 5000);
                    if (waitResult != WaitObject0) {
                        string waitError = "WaitForSingleObject(process) failed/timeout (" + waitResult.ToString() + ")";
                        cleanupErrors = String.IsNullOrEmpty(cleanupErrors) ? waitError : cleanupErrors + "; " + waitError;
                    }
                }
            }
            catch (Exception cleanupError)
            {
                string detail = "native cleanup exception: " + cleanupError.Message;
                cleanupErrors = String.IsNullOrEmpty(cleanupErrors) ? detail : cleanupErrors + "; " + detail;
            }
        }
        finally
        {
            if (nativeEnvironment != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(nativeEnvironment);
                nativeEnvironment = IntPtr.Zero;
            }
            if (attributeList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(attributeList);
                attributeList = IntPtr.Zero;
            }
            if (handleList != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(handleList);
                handleList = IntPtr.Zero;
            }
            if (!transferred)
            {
                string closeError = CloseIfOpen(ref stdoutWrite, "CloseHandle(stdout child end)");
                if (closeError != null) cleanupErrors = String.IsNullOrEmpty(cleanupErrors) ? closeError : cleanupErrors + "; " + closeError;
                closeError = CloseIfOpen(ref stderrWrite, "CloseHandle(stderr child end)");
                if (closeError != null) cleanupErrors = String.IsNullOrEmpty(cleanupErrors) ? closeError : cleanupErrors + "; " + closeError;
                closeError = CloseIfOpen(ref stdoutRead, "CloseHandle(stdout parent end)");
                if (closeError != null) cleanupErrors = String.IsNullOrEmpty(cleanupErrors) ? closeError : cleanupErrors + "; " + closeError;
                closeError = CloseIfOpen(ref stderrRead, "CloseHandle(stderr parent end)");
                if (closeError != null) cleanupErrors = String.IsNullOrEmpty(cleanupErrors) ? closeError : cleanupErrors + "; " + closeError;
                closeError = CloseIfOpen(ref pi.Thread, "CloseHandle(process thread)");
                if (closeError != null) cleanupErrors = String.IsNullOrEmpty(cleanupErrors) ? closeError : cleanupErrors + "; " + closeError;
                closeError = CloseIfOpen(ref pi.Process, "CloseHandle(process)");
                if (closeError != null) cleanupErrors = String.IsNullOrEmpty(cleanupErrors) ? closeError : cleanupErrors + "; " + closeError;
                closeError = CloseIfOpen(ref job, "CloseHandle(job)");
                if (closeError != null) cleanupErrors = String.IsNullOrEmpty(cleanupErrors) ? closeError : cleanupErrors + "; " + closeError;
            }
        }

        if (failure != null)
        {
            string detail = "D32_NATIVE_LAUNCH_FAILED: " + failure.Message;
            if (!String.IsNullOrEmpty(cleanupErrors)) detail += "; native cleanup=" + cleanupErrors;
            throw new InvalidOperationException(detail, failure);
        }
        return result;
    }

   public bool HasExited
    {
        get { IntPtr process = _debugEnabled && _parentProcess != IntPtr.Zero ? _parentProcess : _process; return WaitForSingleObject(process, 0) == WaitObject0; }
    }

    public bool WaitForExit(int timeoutMilliseconds)
    {
        if (timeoutMilliseconds < 0) timeoutMilliseconds = 0;
        IntPtr process = _debugEnabled && _parentProcess != IntPtr.Zero ? _parentProcess : _process;
        return WaitForSingleObject(process, (uint)timeoutMilliseconds) == WaitObject0;
    }

    public string GetDebugHandleDuplicationAudit()
    {
        lock (_observedProcessLock) return String.Join(";", _observedHandleDuplicationAudit.ToArray());
    }

    private bool VerifyObservedProcessHandles(out string invalidHandles)
    {
        List<string> invalid = new List<string>();
        lock (_observedProcessLock)
        {
            for (int i = 0; i < _observedProcessHandles.Count; i++)
            {
                uint flags;
                IntPtr handle = _observedProcessHandles[i];
                if (handle == IntPtr.Zero || !GetHandleInformation(handle, out flags))
                    invalid.Add(_observedProcessIds[i].ToString(CultureInfo.InvariantCulture) + ":0x" + handle.ToInt64().ToString("x", CultureInfo.InvariantCulture) + ":" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
            }
        }
        invalidHandles = String.Join(";", invalid.ToArray());
        return invalid.Count == 0;
    }

    public int ExitCode
    {
        get
        {
            uint code;
            IntPtr process = _debugEnabled && _parentProcess != IntPtr.Zero ? _parentProcess : _process;
            if (!GetExitCodeProcess(process, out code)) ThrowLastError("GetExitCodeProcess failed");
            return unchecked((int)code);
        }
    }

    public Stream StdoutStream
    {
        get
        {
            if (_stdoutStream == null)
                _stdoutStream = new FileStream(_stdoutHandle, FileAccess.Read, 4096, false);
            return _stdoutStream;
        }
    }

    public Stream StderrStream
    {
        get
        {
            if (_stderrStream == null)
                _stderrStream = new FileStream(_stderrHandle, FileAccess.Read, 4096, false);
            return _stderrStream;
        }
    }

    public Stream OpenStdoutStream()
    {
        return StdoutStream;
    }

    public Stream OpenStderrStream()
    {
        return StderrStream;
    }

    private static long DebugFileTimeValue(DebugFileTime value)
    {
        return unchecked((long)(((ulong)value.High << 32) | value.Low));
    }

    private static string DebugFileTimeUtc(long value)
    {
        return DateTime.FromFileTimeUtc(value).ToString("o", CultureInfo.InvariantCulture);
    }

    private static string NormalizeDebugPath(string value)
    {
        if (value.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase)) value = "\\\\" + value.Substring(8);
        else if (value.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase)) value = value.Substring(4);
        return value.Replace('/', '\\').TrimEnd('\\');
    }

    private static DebugImageSnapshot ReadDebugImage(IntPtr file)
    {
        if (file == IntPtr.Zero || file == new IntPtr(-1)) throw new InvalidOperationException("CREATE_PROCESS_DEBUG_EVENT hFile is null/invalid");
        DebugFileInformation before;
        if (!GetFileInformationByHandle(file, out before)) throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandle(image) failed");
        if ((before.Attributes & (uint)FileAttributes.Directory) != 0 || (before.Attributes & (uint)FileAttributes.ReparsePoint) != 0)
            throw new IOException("debug event image handle is not a regular non-reparse file");
        ulong byteCount = ((ulong)before.SizeHigh << 32) | before.SizeLow;
        if (byteCount == 0 || byteCount > Int64.MaxValue) throw new IOException("debug event image has an invalid byte length");
        StringBuilder path = new StringBuilder(32768);
        uint pathLength = GetFinalPathNameByHandleW(file, path, (uint)path.Capacity, 0);
        if (pathLength == 0 || pathLength >= path.Capacity) throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFinalPathNameByHandleW(image) failed");
        IntPtr idBuffer = Marshal.AllocHGlobal(24);
        string volume;
        string fileId;
        try
        {
            if (!GetFileInformationByHandleEx(file, 18, idBuffer, 24)) throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandleEx(FileIdInfo) failed");
            volume = unchecked((ulong)Marshal.ReadInt64(idBuffer, 0)).ToString("x16", CultureInfo.InvariantCulture);
            byte[] id = new byte[16];
            Marshal.Copy(IntPtr.Add(idBuffer, 8), id, 0, 16);
            fileId = BitConverter.ToString(id).Replace("-", "").ToLowerInvariant();
        }
        finally { Marshal.FreeHGlobal(idBuffer); }
        string hash;
        using (SafeFileHandle borrowedHandle = new SafeFileHandle(file, false))
        using (FileStream stream = new FileStream(borrowedHandle, FileAccess.Read, 4096, false))
        using (SHA256 sha = SHA256.Create())
        {
            stream.Position = 0;
            hash = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
            if (stream.Length != (long)byteCount) throw new IOException("debug event image length changed while hashing");
        }
        DebugFileInformation after;
        if (!GetFileInformationByHandle(file, out after) || after.SizeHigh != before.SizeHigh || after.SizeLow != before.SizeLow ||
            after.VolumeSerial != before.VolumeSerial || after.FileIndexHigh != before.FileIndexHigh || after.FileIndexLow != before.FileIndexLow ||
            DebugFileTimeValue(after.LastWriteTime) != DebugFileTimeValue(before.LastWriteTime))
            throw new IOException("debug event image identity/metadata changed while hashing");
        return new DebugImageSnapshot {
            Path = NormalizeDebugPath(path.ToString()), Bytes = (long)byteCount, Sha256 = hash,
            VolumeSerialHex = volume, FileIdHex = fileId
        };
    }

    private static bool DebugImageMatches(DebugImageSnapshot image, string[] pin)
    {
        return image != null && pin != null &&
            String.Equals(NormalizeDebugPath(image.Path), NormalizeDebugPath(pin[0]), StringComparison.OrdinalIgnoreCase) &&
            image.Bytes.ToString(CultureInfo.InvariantCulture) == pin[1] &&
            String.Equals(image.Sha256, pin[2], StringComparison.OrdinalIgnoreCase) &&
            String.Equals(image.VolumeSerialHex, pin[3], StringComparison.OrdinalIgnoreCase) &&
            String.Equals(image.FileIdHex, pin[4], StringComparison.OrdinalIgnoreCase);
    }

    private static string[] ParseDebugPin(string value)
    {
        string[] fields = value == null ? new string[0] : value.Split('\t');
        if (fields.Length != 5 || String.IsNullOrWhiteSpace(fields[0]) || fields[1].Length == 0 || fields[2].Length != 64 || fields[3].Length != 16 || fields[4].Length != 32)
            throw new InvalidOperationException("debug image pin record is malformed");
        return fields;
    }

    private static bool IsImageUnderRoot(string child, string root)
    {
        string normalizedChild = NormalizeDebugPath(child);
        string normalizedRoot = NormalizeDebugPath(root);
        return normalizedChild.Equals(normalizedRoot, StringComparison.OrdinalIgnoreCase) ||
            normalizedChild.StartsWith(normalizedRoot + "\\", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetHardDeniedImageReason(string imagePath)
    {
        string name = Path.GetFileName(imagePath).ToLowerInvariant();
        if (name == "cmd.exe" || name == "command.com" || name.StartsWith("powershell", StringComparison.Ordinal) || name.StartsWith("pwsh", StringComparison.Ordinal) ||
            name == "cscript.exe" || name == "wscript.exe" || name == "mshta.exe" || name == "bash.exe" || name == "sh.exe" || name == "dash.exe" ||
            name == "zsh.exe" || name == "fish.exe" || name == "nu.exe" || name.StartsWith("wsl", StringComparison.Ordinal)) return "command-processor or shell image is never launchable";
        if (name == "git.exe" || name.StartsWith("git-bash", StringComparison.Ordinal) || name.StartsWith("git-cmd", StringComparison.Ordinal) ||
            name.StartsWith("git-lfs", StringComparison.Ordinal) || name.StartsWith("git-remote-", StringComparison.Ordinal) ||
            name.StartsWith("git-credential", StringComparison.Ordinal) || name.Contains("credential") || name.StartsWith("ssh", StringComparison.Ordinal) ||
            name.StartsWith("plink", StringComparison.Ordinal) || name.StartsWith("putty", StringComparison.Ordinal) || name == "pageant.exe" ||
            name.StartsWith("tortoiseplink", StringComparison.Ordinal)) return "Git/SSH/credential helper image is never launchable";
        return null;
    }

    private static long GetDebugProcessCreationTime(IntPtr process)
    {
        DebugFileTime creation, exit, kernel, user;
        if (!GetProcessTimes(process, out creation, out exit, out kernel, out user)) throw new Win32Exception(Marshal.GetLastWin32Error(), "GetProcessTimes failed");
        long value = DebugFileTimeValue(creation);
        if (value <= 0) throw new InvalidOperationException("process creation FILETIME is absent");
        return value;
    }

    private static DebugProcessBasicInformation GetDebugProcessBasicInformation(IntPtr process)
    {
        DebugProcessBasicInformation info;
        int returned;
        int status = NtQueryInformationProcess(process, 0, out info, Marshal.SizeOf(typeof(DebugProcessBasicInformation)), out returned);
        if (status != 0 || returned < Marshal.SizeOf(typeof(DebugProcessBasicInformation)))
            throw new InvalidOperationException("NtQueryInformationProcess(ProcessBasicInformation) failed: 0x" + status.ToString("x8", CultureInfo.InvariantCulture));
        return info;
    }

    private static uint GetDebugProcessPid(DebugProcessBasicInformation info)
    {
        ulong value = unchecked((ulong)info.UniqueProcessId.ToInt64());
        if (value == 0 || value > UInt32.MaxValue) throw new InvalidOperationException("process handle PID is absent or outside the supported range");
        return (uint)value;
    }

    private static uint GetDebugParentPid(DebugProcessBasicInformation info)
    {
        ulong value = unchecked((ulong)info.InheritedFromUniqueProcessId.ToInt64());
        if (value > UInt32.MaxValue) throw new InvalidOperationException("parent PID is outside the supported range");
        return (uint)value;
    }

    private static byte[] ReadRemoteBytes(IntPtr process, IntPtr address, int count, string label)
    {
        if (process == IntPtr.Zero || address == IntPtr.Zero || count <= 0 || count > 131072)
            throw new InvalidOperationException("H7-C Git child has an invalid remote " + label + " address/length");
        byte[] buffer = new byte[count];
        UIntPtr read;
        if (!ReadProcessMemory(process, address, buffer, new UIntPtr((uint)count), out read) || read.ToUInt64() != (ulong)count)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "H7-C Git child remote " + label + " read failed");
        return buffer;
    }

    private static IntPtr ReadRemotePointer(IntPtr process, IntPtr address, string label)
    {
        if (IntPtr.Size != 8) throw new InvalidOperationException("H7-C Git CREATE requires the pinned x64 Windows process parameter layout");
        byte[] bytes = ReadRemoteBytes(process, address, 8, label);
        long value = BitConverter.ToInt64(bytes, 0);
        if (value == 0) throw new InvalidOperationException("H7-C Git child remote " + label + " pointer is null");
        return new IntPtr(value);
    }

    private static string ReadRemoteUnicodeString(IntPtr process, IntPtr structure, string label)
    {
        byte[] header = ReadRemoteBytes(process, structure, 16, label + " UNICODE_STRING");
        ushort length = BitConverter.ToUInt16(header, 0);
        ushort maximumLength = BitConverter.ToUInt16(header, 2);
        long bufferAddress = BitConverter.ToInt64(header, 8);
        if (length == 0 || (length & 1) != 0 || length > 32766 || maximumLength < length || bufferAddress == 0)
            throw new InvalidOperationException("H7-C Git child remote " + label + " UNICODE_STRING bounds are invalid");
        byte[] text = ReadRemoteBytes(process, new IntPtr(bufferAddress), length, label + " text");
        return Encoding.Unicode.GetString(text);
    }

    private static Dictionary<string, string> ReadRemoteEnvironment(IntPtr process, IntPtr environment)
    {
        if (environment == IntPtr.Zero) throw new InvalidOperationException("H7-C Git child has no remote environment block");
        List<byte> bytes = new List<byte>();
        int offset = 0;
        bool terminated = false;
        while (offset < 131072)
        {
            int chunk = Math.Min(256, 131072 - offset);
            byte[] part = null;
            while (chunk >= 2 && part == null)
            {
                try { part = ReadRemoteBytes(process, IntPtr.Add(environment, offset), chunk, "environment block"); }
                catch { chunk /= 2; }
            }
            if (part == null) throw new InvalidOperationException("H7-C Git child environment block cannot be read completely");
            bytes.AddRange(part);
            offset += part.Length;
            for (int end = 0; end + 3 < bytes.Count; end += 2)
            {
                if (bytes[end] == 0 && bytes[end + 1] == 0 && bytes[end + 2] == 0 && bytes[end + 3] == 0)
                {
                    terminated = true;
                    break;
                }
            }
            if (terminated) break;
        }
        if (!terminated) throw new InvalidOperationException("H7-C Git child environment block is unterminated or exceeds its evidence bound");
        int textBytes = bytes.Count - 4;
        for (int end = 0; end + 3 < bytes.Count; end += 2)
        {
            if (bytes[end] == 0 && bytes[end + 1] == 0 && bytes[end + 2] == 0 && bytes[end + 3] == 0) { textBytes = end; break; }
        }
        if ((textBytes & 1) != 0) throw new InvalidOperationException("H7-C Git child environment block has odd UTF-16 byte length");
        string block = Encoding.Unicode.GetString(bytes.ToArray(), 0, textBytes);
        Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string item in block.Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries))
        {
            int separator = item.IndexOf('=');
            if (separator <= 0 || separator == item.Length - 1)
                throw new InvalidOperationException("H7-C Git child environment contains an empty name/value or hidden drive variable");
            string name = item.Substring(0, separator);
            string value = item.Substring(separator + 1);
            if (name.IndexOfAny(new char[] { '\t', '\r', '\n' }) >= 0 || value.IndexOfAny(new char[] { '\t', '\r', '\n' }) >= 0 || result.ContainsKey(name))
                throw new InvalidOperationException("H7-C Git child environment contains a duplicate or non-canonical entry");
            result.Add(name, value);
        }
        return result;
    }

    private static string[] ReadRemoteArgv(IntPtr process, string commandLine)
    {
        int count;
        IntPtr vector = CommandLineToArgvW(commandLine, out count);
        if (vector == IntPtr.Zero || count <= 0 || count > 64)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "H7-C Git child CommandLineToArgvW failed or returned an invalid count");
        try
        {
            string[] args = new string[count];
            for (int i = 0; i < count; i++)
            {
                IntPtr item = Marshal.ReadIntPtr(vector, i * IntPtr.Size);
                args[i] = Marshal.PtrToStringUni(item);
                if (String.IsNullOrEmpty(args[i])) throw new InvalidOperationException("H7-C Git child argv contains a null/empty argument");
            }
            return args;
        }
        finally { LocalFree(vector); }
    }

    private static H7CGitNativePolicy ParseH7CGitNativePolicy(string raw)
    {
        if (String.IsNullOrEmpty(raw) || raw.IndexOf('\r') >= 0) throw new InvalidOperationException("H7-C Git native policy text is empty or non-canonical");
        string[] lines = raw.Split(new char[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length != 36) throw new InvalidOperationException("H7-C Git native policy must contain exactly one header and 35 slots");
        string[] header = lines[0].Split('\t');
        if (header.Length != 19 || header[0] != "D32_H7C_NATIVE_POLICY_V1") throw new InvalidOperationException("H7-C Git native policy header schema differs");
        H7CGitNativePolicy policy = new H7CGitNativePolicy();
        policy.Repository = NormalizeDebugPath(header[1]);
        policy.CargoPath = NormalizeDebugPath(header[2]);
        policy.EvidenceRoot = NormalizeDebugPath(header[3]);
        policy.EvidenceRootVolume = header[4];
        policy.EvidenceRootFileId = header[5];
        policy.TempRoot = NormalizeDebugPath(header[6]);
        policy.TempRootVolume = header[7];
        policy.TempRootFileId = header[8];
        policy.OwnerMarkerPath = NormalizeDebugPath(header[9]);
        if (!Int64.TryParse(header[10], NumberStyles.None, CultureInfo.InvariantCulture, out policy.OwnerMarkerBytes)) throw new InvalidOperationException("H7-C owner marker byte count is malformed");
        policy.OwnerMarkerSha256 = header[11];
        policy.OwnerMarkerVolume = header[12];
        policy.OwnerMarkerFileId = header[13];
        policy.GitPath = NormalizeDebugPath(header[14]);
        if (!Int64.TryParse(header[15], NumberStyles.None, CultureInfo.InvariantCulture, out policy.GitBytes)) throw new InvalidOperationException("H7-C Git image byte count is malformed");
        policy.GitSha256 = header[16];
        policy.GitVolume = header[17];
        policy.GitFileId = header[18];
        if (policy.GitBytes <= 0 || policy.GitSha256.Length != 64 || policy.GitVolume.Length != 16 || policy.GitFileId.Length != 32 ||
            policy.EvidenceRootVolume.Length != 16 || policy.EvidenceRootFileId.Length != 32 || policy.TempRootVolume.Length != 16 || policy.TempRootFileId.Length != 32 ||
            policy.OwnerMarkerBytes <= 0 || policy.OwnerMarkerSha256.Length != 64 || policy.OwnerMarkerVolume.Length != 16 || policy.OwnerMarkerFileId.Length != 32 ||
            !String.Equals(Path.GetFileName(policy.GitPath), "git.exe", StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(Path.GetFileName(policy.CargoPath), "cargo.exe", StringComparison.OrdinalIgnoreCase) ||
            !Path.IsPathRooted(policy.Repository) || !String.Equals(policy.Repository, NormalizeDebugPath(Path.GetFullPath(policy.Repository)), StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(Path.GetFileName(policy.OwnerMarkerPath), "D32-PHASE0-OWNER.json", StringComparison.Ordinal) ||
            !String.Equals(Path.GetDirectoryName(policy.OwnerMarkerPath), policy.EvidenceRoot, StringComparison.OrdinalIgnoreCase) ||
            !IsImageUnderRoot(policy.TempRoot, policy.EvidenceRoot) ||
            !String.Equals(policy.TempRoot, Path.Combine(policy.EvidenceRoot, "r", "t"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("H7-C Git native policy root, owner-marker, or pinned image identity is malformed");
        for (int i = 1; i < lines.Length; i++)
        {
            string[] f = lines[i].Split('\t');
            if (f.Length != 14 || f[0] != "SLOT") throw new InvalidOperationException("H7-C Git native slot schema differs at index " + (i - 1).ToString(CultureInfo.InvariantCulture));
            H7CGitSlotPolicy slot = new H7CGitSlotPolicy();
            slot.Name = f[1];
            slot.Path = NormalizeDebugPath(f[2]);
            slot.Volume = f[3];
            slot.FileId = f[4];
            slot.Repo = NormalizeDebugPath(f[5]);
            slot.RepoVolume = f[6];
            slot.RepoFileId = f[7];
            slot.GitHome = NormalizeDebugPath(f[8]);
            slot.GitHomeVolume = f[9];
            slot.GitHomeFileId = f[10];
            slot.EmptyConfig = NormalizeDebugPath(f[11]);
            slot.ConfigVolume = f[12];
            slot.ConfigFileId = f[13];
            string expected = "d32-h7c-slot-" + (i).ToString("D2", CultureInfo.InvariantCulture);
            if (!String.Equals(slot.Name, expected, StringComparison.Ordinal) ||
                slot.Volume.Length != 16 || slot.FileId.Length != 32 || slot.RepoVolume.Length != 16 || slot.RepoFileId.Length != 32 ||
                slot.GitHomeVolume.Length != 16 || slot.GitHomeFileId.Length != 32 || slot.ConfigVolume.Length != 16 || slot.ConfigFileId.Length != 32 ||
                !String.Equals(Path.GetDirectoryName(slot.Path), policy.TempRoot, StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(Path.GetDirectoryName(slot.Repo), slot.Path, StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(Path.GetDirectoryName(slot.GitHome), slot.Path, StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(slot.EmptyConfig, Path.Combine(slot.GitHome, "empty.gitconfig"), StringComparison.OrdinalIgnoreCase) ||
                !policy.Slots.TryAdd(slot.Name, slot))
                throw new InvalidOperationException("H7-C Git native slot paths/identities are invalid or duplicated at index " + (i - 1).ToString(CultureInfo.InvariantCulture));
        }
        return policy;
    }

    private static H7CGitDirectoryIdentity ReadH7CGitDirectoryHandle(IntPtr handle, string expectedPath)
    {
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) throw new InvalidOperationException("H7-C Git working-directory handle is absent");
        DebugFileInformation basic;
        if (!GetFileInformationByHandle(handle, out basic)) throw new Win32Exception(Marshal.GetLastWin32Error(), "H7-C Git directory GetFileInformationByHandle failed");
        if ((basic.Attributes & FileAttributeDirectory) == 0 || (basic.Attributes & FileAttributeReparsePoint) != 0)
            throw new InvalidOperationException("H7-C Git path is not a regular non-reparse directory");
        IntPtr attrBuffer = Marshal.AllocHGlobal(8);
        IntPtr idBuffer = Marshal.AllocHGlobal(24);
        try
        {
            if (!GetFileInformationByHandleEx(handle, 9, attrBuffer, 8)) throw new Win32Exception(Marshal.GetLastWin32Error(), "H7-C Git FileAttributeTagInfo failed");
            uint attributes = unchecked((uint)Marshal.ReadInt32(attrBuffer, 0));
            if ((attributes & FileAttributeDirectory) == 0 || (attributes & FileAttributeReparsePoint) != 0)
                throw new InvalidOperationException("H7-C Git directory handle identifies a reparse/non-directory entry");
            if (!GetFileInformationByHandleEx(handle, 18, idBuffer, 24)) throw new Win32Exception(Marshal.GetLastWin32Error(), "H7-C Git FileIdInfo failed");
            string volume = unchecked((ulong)Marshal.ReadInt64(idBuffer, 0)).ToString("x16", CultureInfo.InvariantCulture);
            byte[] id = new byte[16];
            Marshal.Copy(IntPtr.Add(idBuffer, 8), id, 0, 16);
            string fileId = BitConverter.ToString(id).Replace("-", "").ToLowerInvariant();
            StringBuilder finalPath = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandleW(handle, finalPath, (uint)finalPath.Capacity, 0);
            if (length == 0 || length >= finalPath.Capacity) throw new Win32Exception(Marshal.GetLastWin32Error(), "H7-C Git directory final path query failed");
            string path = NormalizeDebugPath(finalPath.ToString());
            if (!String.Equals(path, NormalizeDebugPath(expectedPath), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("H7-C Git directory opened-handle path differs from the authorized slot path");
            return new H7CGitDirectoryIdentity { Path = path, Volume = volume, FileId = fileId };
        }
        finally { Marshal.FreeHGlobal(attrBuffer); Marshal.FreeHGlobal(idBuffer); }
    }

    private static H7CGitDirectoryIdentity OpenH7CGitDirectory(string path)
    {
        using (SafeFileHandle handle = CreateFileW(path, FileReadAttributes, FileShareRead | FileShareWrite | FileShareDelete, IntPtr.Zero,
            OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero))
        {
            if (handle == null || handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "H7-C Git authorized directory could not be opened without following reparse points: " + path);
            return ReadH7CGitDirectoryHandle(handle.DangerousGetHandle(), path);
        }
    }

    private static void RequireH7CGitDirectory(H7CGitNativePolicy policy, string path, string volume, string fileId)
    {
        H7CGitDirectoryIdentity identity = OpenH7CGitDirectory(path);
        if (!String.Equals(identity.Volume, volume, StringComparison.OrdinalIgnoreCase) || !String.Equals(identity.FileId, fileId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("H7-C Git authorized directory opened-handle volume/file identity changed: " + path);
    }

    private static DebugImageSnapshot OpenH7CGitFile(string path)
    {
        using (SafeFileHandle handle = CreateFileW(path, FileReadAttributes | 0x80000000, FileShareRead, IntPtr.Zero, OpenExisting,
            FileFlagOpenReparsePoint, IntPtr.Zero))
        {
            if (handle == null || handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "H7-C Git authorized regular file could not be opened without following reparse points: " + path);
            return ReadDebugImage(handle.DangerousGetHandle());
        }
    }

    private static string GetWindowsDirectoryCanonical()
    {
        StringBuilder buffer = new StringBuilder(32768);
        uint count = GetWindowsDirectoryW(buffer, (uint)buffer.Capacity);
        if (count == 0 || count >= buffer.Capacity) throw new Win32Exception(Marshal.GetLastWin32Error(), "GetWindowsDirectoryW failed for H7-C Git environment validation");
        return NormalizeDebugPath(buffer.ToString());
    }

    private static string GetSystemDirectoryCanonical()
    {
        StringBuilder buffer = new StringBuilder(32768);
        uint count = GetSystemDirectoryW(buffer, (uint)buffer.Capacity);
        if (count == 0 || count >= buffer.Capacity) throw new Win32Exception(Marshal.GetLastWin32Error(), "GetSystemDirectoryW failed for H7-C Git environment validation");
        return NormalizeDebugPath(buffer.ToString());
    }

    private static bool H7CGitPathVariable(string name)
    {
        return String.Equals(name, "HOME", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(name, "USERPROFILE", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(name, "XDG_CONFIG_HOME", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(name, "TEMP", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(name, "TMP", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(name, "GIT_CEILING_DIRECTORIES", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(name, "GIT_CONFIG_GLOBAL", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(name, "GIT_CONFIG_SYSTEM", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(name, "SystemRoot", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(name, "WINDIR", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(name, "SystemDrive", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(name, "ComSpec", StringComparison.OrdinalIgnoreCase);
    }

    private static void RequireH7CGitEnvironment(Dictionary<string, string> actual, H7CGitNativePolicy policy, H7CGitSlotPolicy slot, bool status)
    {
        Dictionary<string, string> expected = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string windows = GetWindowsDirectoryCanonical();
        if (status)
        {
            expected.Add("ComSpec", Path.Combine(GetSystemDirectoryCanonical(), "cmd.exe"));
            expected.Add("GCM_INTERACTIVE", "Never");
            expected.Add("GIT_CEILING_DIRECTORIES", slot.Path);
            expected.Add("GIT_CONFIG_GLOBAL", slot.EmptyConfig);
            expected.Add("GIT_CONFIG_NOSYSTEM", "1");
            expected.Add("GIT_OPTIONAL_LOCKS", "0");
            expected.Add("GIT_TERMINAL_PROMPT", "0");
            expected.Add("HOME", slot.GitHome);
            expected.Add("SystemDrive", Path.GetPathRoot(windows).TrimEnd('\\'));
            expected.Add("SystemRoot", windows);
            expected.Add("windir", windows);
        }
        else
        {
            expected.Add("GCM_INTERACTIVE", "Never");
            expected.Add("GIT_CEILING_DIRECTORIES", slot.Path);
            expected.Add("GIT_CONFIG_GLOBAL", slot.EmptyConfig);
            expected.Add("GIT_CONFIG_NOSYSTEM", "1");
            expected.Add("GIT_CONFIG_SYSTEM", slot.EmptyConfig);
            expected.Add("GIT_NO_REPLACE_OBJECTS", "1");
            expected.Add("GIT_OPTIONAL_LOCKS", "0");
            expected.Add("GIT_PAGER", "cat");
            expected.Add("GIT_TERMINAL_PROMPT", "0");
            expected.Add("HOME", slot.GitHome);
            expected.Add("TEMP", policy.TempRoot);
            expected.Add("TMP", policy.TempRoot);
            expected.Add("USERPROFILE", slot.GitHome);
            expected.Add("WINDIR", windows);
            expected.Add("SystemRoot", windows);
            expected.Add("XDG_CONFIG_HOME", slot.GitHome);
        }
        if (actual.Count != expected.Count) throw new InvalidOperationException("H7-C Git child environment has missing or extra keys; PATH, config override, shell/helper, and ambient variables remain denied");
        foreach (KeyValuePair<string, string> entry in expected)
        {
            string value;
            if (!actual.TryGetValue(entry.Key, out value)) throw new InvalidOperationException("H7-C Git child environment omits required key " + entry.Key);
            bool pathValue = H7CGitPathVariable(entry.Key);
            if (!(pathValue ? String.Equals(NormalizeDebugPath(value), NormalizeDebugPath(entry.Value), StringComparison.OrdinalIgnoreCase) : String.Equals(value, entry.Value, StringComparison.Ordinal)))
                throw new InvalidOperationException("H7-C Git child environment value differs for " + entry.Key);
        }
    }

    private static string[][] H7CGitSetupArguments()
    {
        return new string[][] {
            new string[] { "init", "--quiet" },
            new string[] { "config", "user.name", "D29-H7-C" },
            new string[] { "config", "user.email", "d29h7c@example.invalid" },
            new string[] { "add", "--", "unchanged.txt", "modified.txt" },
            new string[] { "commit", "--quiet", "-m", "initial" }
        };
    }

    private static string[] H7CGitStatusArguments()
    {
        return new string[] { "--no-pager", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "submodule.recurse=false", "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=all" };
    }

    private D32H7CGitChildObservationV1 ValidateH7CGitCreate(
        H7CGitNativePolicy policy, DebugImageSnapshot image, IntPtr processHandle, D32DebugProcessRecordV2 parent,
        DebugActiveProcess rootProcess, uint processId, long creationFileTime, uint parentPid, long parentCreationFileTime)
    {
        if (policy == null || image == null || parent == null || rootProcess == null || processHandle == IntPtr.Zero)
            throw new InvalidOperationException("H7-C Git direct-child grant/process evidence is incomplete");
        if (!String.Equals(NormalizeDebugPath(image.Path), policy.GitPath, StringComparison.OrdinalIgnoreCase) || image.Bytes != policy.GitBytes ||
            !String.Equals(image.Sha256, policy.GitSha256, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(image.VolumeSerialHex, policy.GitVolume, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(image.FileIdHex, policy.GitFileId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("H7-C Git CREATE image differs from the exact authority-pinned path/bytes/SHA/volume/file identity");
        if (!String.Equals(Path.GetFileName(image.Path), "git.exe", StringComparison.OrdinalIgnoreCase) || parent.ProcessId != parentPid ||
            parent.CreationFileTime != parentCreationFileTime || rootProcess.Record.ProcessId == parentPid ||
            parent.ParentProcessId != rootProcess.Record.ProcessId || parent.ParentCreationFileTime != rootProcess.Record.CreationFileTime ||
            !String.Equals(Path.GetFileName(rootProcess.Record.ImagePath), "cargo.exe", StringComparison.OrdinalIgnoreCase) ||
            !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(parent.ImagePath), @"^vita_agent-[0-9a-f]+\.exe$", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant) ||
            !String.Equals(Path.GetFileName(Path.GetDirectoryName(parent.ImagePath)), "deps", StringComparison.OrdinalIgnoreCase) ||
            !IsImageUnderRoot(parent.ImagePath, Path.Combine(policy.Repository, "vita-agent", "target", "debug")))
            throw new InvalidOperationException("H7-C Git CREATE must be a direct child of the exact candidate Vita libtest, which is itself a direct child of the fixed Cargo Job root");
        bool wow64;
        if (!IsWow64Process(processHandle, out wow64) || wow64 || IntPtr.Size != 8)
            throw new InvalidOperationException("H7-C Git CREATE process is not a readable native x64 Windows image");
        DebugProcessBasicInformation information = GetDebugProcessBasicInformation(processHandle);
        IntPtr parameters = ReadRemotePointer(processHandle, IntPtr.Add(information.PebBaseAddress, 0x20), "ProcessParameters");
        string commandLine = ReadRemoteUnicodeString(processHandle, IntPtr.Add(parameters, 0x70), "CommandLine");
        string currentDirectory = NormalizeDebugPath(ReadRemoteUnicodeString(processHandle, IntPtr.Add(parameters, 0x38), "CurrentDirectory"));
        IntPtr remoteCurrentDirectoryHandle = Marshal.ReadIntPtr(parameters, 0x48);
        if (remoteCurrentDirectoryHandle == IntPtr.Zero || remoteCurrentDirectoryHandle == new IntPtr(-1)) throw new InvalidOperationException("H7-C Git CREATE has no child current-directory handle");
        IntPtr duplicatedCurrentDirectory = IntPtr.Zero;
        try
        {
            if (!DuplicateHandle(processHandle, remoteCurrentDirectoryHandle, GetCurrentProcess(), out duplicatedCurrentDirectory, 0, false, DuplicateSameAccess))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "H7-C Git CREATE current-directory handle could not be retained for identity validation");
            H7CGitDirectoryIdentity cwdIdentity = ReadH7CGitDirectoryHandle(duplicatedCurrentDirectory, currentDirectory);
            if (!String.Equals(cwdIdentity.Path, currentDirectory, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("H7-C Git CREATE cwd path differs from its opened current-directory handle");
        }
        finally { if (duplicatedCurrentDirectory != IntPtr.Zero) CloseHandle(duplicatedCurrentDirectory); }

        Dictionary<string, string> environment = ReadRemoteEnvironment(processHandle, ReadRemotePointer(processHandle, IntPtr.Add(parameters, 0x80), "Environment"));
        string[] argv = ReadRemoteArgv(processHandle, commandLine);
        if (argv.Length < 2 || !String.Equals(NormalizeDebugPath(argv[0]), policy.GitPath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("H7-C Git CREATE argv[0] differs from the exact pinned native image path");
        H7CGitSlotPolicy slot = null;
        foreach (H7CGitSlotPolicy candidate in policy.Slots.Values)
        {
            if (String.Equals(currentDirectory, candidate.Repo, StringComparison.OrdinalIgnoreCase)) { slot = candidate; break; }
        }
        if (slot == null) throw new InvalidOperationException("H7-C Git CREATE working directory is not one of the 35 owner-bound fresh workspace slots");
        RequireH7CGitDirectory(policy, policy.EvidenceRoot, policy.EvidenceRootVolume, policy.EvidenceRootFileId);
        RequireH7CGitDirectory(policy, policy.TempRoot, policy.TempRootVolume, policy.TempRootFileId);
        RequireH7CGitDirectory(policy, slot.Path, slot.Volume, slot.FileId);
        RequireH7CGitDirectory(policy, slot.Repo, slot.RepoVolume, slot.RepoFileId);
        RequireH7CGitDirectory(policy, slot.GitHome, slot.GitHomeVolume, slot.GitHomeFileId);
        DebugImageSnapshot owner = OpenH7CGitFile(policy.OwnerMarkerPath);
        if (owner.Bytes != policy.OwnerMarkerBytes || !String.Equals(owner.Sha256, policy.OwnerMarkerSha256, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(owner.VolumeSerialHex, policy.OwnerMarkerVolume, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(owner.FileIdHex, policy.OwnerMarkerFileId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("H7-C Git CREATE owner marker identity changed after per-run grant creation");
        DebugImageSnapshot emptyConfig = OpenH7CGitFile(slot.EmptyConfig);
        if (emptyConfig.Bytes != 0 || !String.Equals(emptyConfig.Sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", StringComparison.Ordinal) ||
            !String.Equals(emptyConfig.VolumeSerialHex, slot.ConfigVolume, StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(emptyConfig.FileIdHex, slot.ConfigFileId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("H7-C Git CREATE empty global/system config is no longer the exact owner-bound zero-byte file");

        string[] arguments = argv.Skip(1).ToArray();
        string operation;
        string[][] setup = H7CGitSetupArguments();
        if (slot.SetupNext < setup.Length && arguments.SequenceEqual(setup[slot.SetupNext], StringComparer.Ordinal))
        {
            RequireH7CGitEnvironment(environment, policy, slot, false);
            operation = "setup-" + (slot.SetupNext + 1).ToString("D2", CultureInfo.InvariantCulture);
            slot.SetupNext++;
        }
        else if (slot.SetupNext == setup.Length && slot.StatusCount == 0 && arguments.SequenceEqual(H7CGitStatusArguments(), StringComparer.Ordinal))
        {
            RequireH7CGitEnvironment(environment, policy, slot, true);
            operation = "status";
            slot.StatusCount++;
        }
        else throw new InvalidOperationException("H7-C Git CREATE argv is not the next fixed setup action or the one allowed fixed status action for this slot");
        return new D32H7CGitChildObservationV1 {
            Slot = slot.Name, Operation = operation, ProcessId = processId, CreationFileTime = creationFileTime,
            ParentProcessId = parentPid, ParentCreationFileTime = parentCreationFileTime, ImagePath = image.Path,
            Bytes = image.Bytes, Sha256 = image.Sha256, VolumeSerialHex = image.VolumeSerialHex, FileIdHex = image.FileIdHex,
            CommandLine = commandLine, Argv = argv, WorkingDirectory = currentDirectory, Environment = environment
        };
    }

    private static bool TryGetDebugJobAccounting(IntPtr job, out JobObjectBasicAccountingInformation accounting)
    {
        accounting = new JobObjectBasicAccountingInformation();
        uint returned;
        uint length = (uint)Marshal.SizeOf(typeof(JobObjectBasicAccountingInformation));
        return QueryInformationJobObject(job, JobObjectBasicAccountingInformationClass, ref accounting, length, out returned) && returned >= length;
    }

    private static void TraceBlock(D32DebugProcessTraceV2 trace, string reason)
    {
        if (trace.State != "BLOCKED") trace.BlockReason = reason;
        trace.State = "BLOCKED";
    }

    private void TraceCloseHandle(IntPtr handle, D32DebugProcessTraceV2 trace, string label)
    {
        if (handle != IntPtr.Zero)
        {
            lock (_observedProcessLock)
            {
                for (int i = 0; i < _observedProcessHandles.Count; i++)
                {
                    if (_observedProcessHandles[i] == handle)
                    {
                        _observedHandleDuplicationAudit.Add("CLOSE_ALIAS:" + label + ":handle=0x" + handle.ToInt64().ToString("x", CultureInfo.InvariantCulture) + ":retained_pid=" + _observedProcessIds[i].ToString(CultureInfo.InvariantCulture));
                        TraceBlock(trace, "debug event cleanup handle aliases a parent-retained process handle: " + label);
                        return;
                    }
                }
            }
        }
        if (handle != IntPtr.Zero && handle != new IntPtr(-1))
        {
            if (!CloseHandle(handle))
            {
                trace.DebugApiErrorCount++;
                TraceBlock(trace, "CloseHandle(" + label + ") failed: " + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
            }
            else
            {
                string invalidRetainedHandles;
                if (_debugEnabled && !VerifyObservedProcessHandles(out invalidRetainedHandles))
                {
                    lock (_observedProcessLock) _observedHandleDuplicationAudit.Add("INVALID_AFTER_CLOSE:" + label + ":" + invalidRetainedHandles);
                    TraceBlock(trace, "a parent-retained process handle became invalid while closing " + label + ": " + invalidRetainedHandles);
                }
            }
        }
    }

    public D32DebugProcessTraceV2 MonitorDebugEvents(string expectedRootPin, string[] approvedImagePins, string[] candidateImageRoots, int timeoutMilliseconds, bool injectFirstCreateInterruption, bool injectFirstCreateIdentityMismatch)
    {
        if (!_debugEnabled || _debugCoordinator == null || Thread.CurrentThread != _debugCoordinator.WorkerThread)
            throw new InvalidOperationException("CreateProcessW, WaitForDebugEvent, and ContinueDebugEvent must run on the dedicated joinable debugger OS thread");
        if (String.IsNullOrWhiteSpace(expectedRootPin) || approvedImagePins == null || candidateImageRoots == null || timeoutMilliseconds <= 0)
            throw new ArgumentException("expected root pin, image inventories, and a positive deadline are mandatory");
        string[] expectedRoot = ParseDebugPin(expectedRootPin);
        H7CGitNativePolicy h7cGitPolicy = String.IsNullOrEmpty(_debugCoordinator.H7CGitNativePolicyText) ? null : ParseH7CGitNativePolicy(_debugCoordinator.H7CGitNativePolicyText);
        if (h7cGitPolicy != null && !String.Equals(NormalizeDebugPath(expectedRoot[0]), h7cGitPolicy.CargoPath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("H7C_GIT_GRANT_BLOCKED: narrow Git child authority is not bound to the fixed caller-pinned Cargo root");
        string[][] pins = new string[approvedImagePins.Length][];
        for (int i = 0; i < approvedImagePins.Length; i++) pins[i] = ParseDebugPin(approvedImagePins[i]);
        string[] roots = new string[candidateImageRoots.Length];
        for (int i = 0; i < candidateImageRoots.Length; i++)
        {
            roots[i] = NormalizeDebugPath(candidateImageRoots[i]);
            if (!Path.IsPathRooted(roots[i])) throw new InvalidOperationException("candidate image root is not absolute");
        }
        DateTime start = DateTime.UtcNow;
        string failureInjection = _debugCoordinator.FailureInjection ?? String.Empty;
        long debuggerCreation = GetDebugProcessCreationTime(GetCurrentProcess());
        D32DebugProcessTraceV2 trace = new D32DebugProcessTraceV2 {
            RecordType = "D32_DEBUG_JOB_PROCESS_TRACE_V2", SchemaVersion = 2, EventSource = "Win32-WaitForDebugEvent-dedicated-OS-thread",
            State = "RUNNING", StartedAtUtc = start.ToString("o", CultureInfo.InvariantCulture), DebuggerProcessId = (int)GetCurrentProcessId(),
            UncontinuedCreateProcessId = 0, UncontinuedCreateContinueCallCount = 0,
            DebuggerThreadId = GetCurrentThreadId(), DedicatedDebuggerThread = true,
            DebuggerKillOnExitEnabled = _debugKillOnExitEnabled, RootResumedAfterKillOnExit = false,
            DebuggerThreadExited = false, DebuggerThreadJoined = false, RetainedProcessHandleCount = 0,
            RetainedProcessHandlesSignaled = false, DebuggerAssociationQueryVerified = false, DebuggerAssociationAbsent = false,
            DebuggerCreationFileTime = debuggerCreation, DebuggerCreatedAtUtc = DebugFileTimeUtc(debuggerCreation),
            EventChainComplete = true, InjectedInterruption = injectFirstCreateInterruption,
            ProcessEvents = new List<D32DebugProcessEventV2>(), Processes = new List<D32DebugProcessRecordV2>()
        };
        Dictionary<uint, DebugActiveProcess> active = new Dictionary<uint, DebugActiveProcess>();
        HashSet<string> identities = new HashSet<string>(StringComparer.Ordinal);
        HashSet<uint> startupBreakpoints = new HashSet<uint>();
        DateTime deadline = start.AddMilliseconds(timeoutMilliseconds);
        long sequence = 0;

        if (!_debugKillOnExitEnabled)
        {
            TraceBlock(trace, "DebugSetProcessKillOnExit(TRUE) was not established before root resume");
            trace.DebugApiErrorCount++;
            if (!TerminateJobObject(_job, 0xD3201000)) trace.DebugApiErrorCount++;
            trace.EventChainComplete = false;
            trace.CompletedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            return trace;
        }
        try
        {
            if (!_jobNonBreakawayVerified) throw new InvalidOperationException("owned Job non-breakaway configuration was not verified before root resume");
            RequireNonBreakawayJob(_job);
            if (!ProcessIsInOwnedJob(_process, _job)) throw new InvalidOperationException("suspended root is not a member of the exact owned non-breakaway Job");
        }
        catch (Exception error)
        {
            TraceBlock(trace, "JOB_CONTAINMENT_BLOCKED: " + error.Message);
            trace.DebugApiErrorCount++;
            if (!TerminateJobObject(_job, 0xD3201000)) trace.DebugApiErrorCount++;
            trace.EventChainComplete = false;
            trace.CompletedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            return trace;
        }
        uint resumeResult = ResumeThread(_thread);
        if (resumeResult == UInt32.MaxValue || resumeResult != 1)
        {
            int resumeError = resumeResult == UInt32.MaxValue ? Marshal.GetLastWin32Error() : 0;
            TraceBlock(trace, "root ResumeThread did not observe exactly one CREATE_SUSPENDED count after DebugSetProcessKillOnExit(TRUE); previous=" + resumeResult.ToString(CultureInfo.InvariantCulture) + "; win32=" + resumeError.ToString(CultureInfo.InvariantCulture));
            trace.DebugApiErrorCount++;
            if (!TerminateJobObject(_job, 0xD3201000)) trace.DebugApiErrorCount++;
            trace.EventChainComplete = false;
            trace.CompletedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            return trace;
        }
        _debugRootResumedAfterKillOnExit = true;
        trace.RootResumedAfterKillOnExit = true;

        while (true)
        {
            if (_debugCoordinator.AbortRequested)
            {
                trace.EventChainComplete = false;
                TraceBlock(trace, "debugger session was aborted before the pending event could be continued");
                if (!TerminateJobObject(_job, 0xD3201001)) trace.DebugApiErrorCount++;
                break;
            }
            if (DateTime.UtcNow >= deadline)
            {
                TraceBlock(trace, "WaitForDebugEvent deadline exceeded; the owned Job was terminated and debugger thread will exit without continuing a pending event");
                if (!TerminateJobObject(_job, 0xD3201002)) trace.DebugApiErrorCount++;
                trace.EventChainComplete = false;
                break;
            }
            if (failureInjection == "wait-timeout" && trace.DebugEventCount == 0)
            {
                TraceBlock(trace, "injected WaitForDebugEvent timeout before the first event");
                if (!TerminateJobObject(_job, 0xD3201002)) trace.DebugApiErrorCount++;
                trace.EventChainComplete = false;
                break;
            }
            if (trace.ProcessCreateEventCount > 0 && active.Count == 0 && trace.ProcessCreateEventCount == trace.ProcessExitEventCount && WaitForSingleObject(_process, 0) == WaitObject0)
                break;

            DebugEvent ev;
            if (failureInjection == "wait-api-failure" && trace.DebugEventCount == 0)
            {
                trace.DebugApiErrorCount++;
                TraceBlock(trace, "injected WaitForDebugEvent API failure before the first event");
                if (!TerminateJobObject(_job, 0xD3201003)) trace.DebugApiErrorCount++;
                trace.EventChainComplete = false;
                break;
            }
            if (!WaitForDebugEvent(out ev, 250))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == ErrorSemTimeout) { trace.WaitTimeoutCount++; continue; }
                trace.DebugApiErrorCount++;
                trace.EventChainComplete = false;
                TraceBlock(trace, "WaitForDebugEvent failed without a loss-recovery path: " + error.ToString(CultureInfo.InvariantCulture));
                if (!TerminateJobObject(_job, 0xD3201003)) trace.DebugApiErrorCount++;
                break;
            }
            trace.DebugEventCount++;
            uint continueStatus = DebugContinue;
            bool skipContinueForCreateIdentityFailure = false;
            try
            {
                if (ev.Code == DebugEventCreateProcess)
                {
                    skipContinueForCreateIdentityFailure = true;
                    trace.ProcessCreateEventCount++;
                    trace.ProcessEventCount++;
                    long createSequence = ++sequence;
                    uint parentPid = 0;
                    long creation = 0;
                    long parentCreation = 0;
                    DebugImageSnapshot image = null;
                    string reason = null;
                    bool verified = false;
                    DebugActiveProcess parent = null;
                    DebugActiveProcess retained = null;
                    IntPtr retainedHandle = IntPtr.Zero;
                    try
                    {
                        DebugCreateProcessInfo created = ev.Data.CreateProcess;
                        IntPtr eventImageHandle = created.File;
                        if (failureInjection == "null-image-file" && trace.ProcessCreateEventCount == 1) created.File = IntPtr.Zero;
                        try
                        {
                            if (created.Process == IntPtr.Zero) throw new InvalidOperationException("CREATE_PROCESS_DEBUG_EVENT hProcess is null");
                            DebugProcessBasicInformation processBasicInformation = GetDebugProcessBasicInformation(created.Process);
                            uint processHandlePid = GetDebugProcessPid(processBasicInformation);
                            bool isRootProcessEvent = trace.ProcessCreateEventCount == 1;
                            if (injectFirstCreateIdentityMismatch && isRootProcessEvent)
                                processHandlePid = processHandlePid == UInt32.MaxValue ? processHandlePid - 1 : processHandlePid + 1;
                            if (!DebugCreateProcessIdentityMatches(ev.ProcessId, processHandlePid, ProcessId, isRootProcessEvent))
                            {
                                throw new InvalidOperationException(isRootProcessEvent
                                    ? "CREATE_PROCESS_DEBUG_EVENT PID differs from the actual process handle PID or CreateProcessW returned root PID"
                                    : "CREATE_PROCESS_DEBUG_EVENT PID differs from the actual process handle PID");
                            }
                            creation = GetDebugProcessCreationTime(created.Process);
                            parentPid = GetDebugParentPid(processBasicInformation);
                            IntPtr independentProcessHandle = OpenProcess(ProcessQueryInformation | Synchronize, false, ev.ProcessId);
                            if (independentProcessHandle == IntPtr.Zero)
                                ThrowLastError("OpenProcess(parent-retained observed process identity) failed");
                            try
                            {
                                DebugProcessBasicInformation independentInformation = GetDebugProcessBasicInformation(independentProcessHandle);
                                uint independentPid = GetDebugProcessPid(independentInformation);
                                long independentCreation = GetDebugProcessCreationTime(independentProcessHandle);
                                uint independentParentPid = GetDebugParentPid(independentInformation);
                                if (independentPid != processHandlePid || independentCreation != creation || independentParentPid != parentPid)
                                    throw new InvalidOperationException("OpenProcess PID/creation/parent identity differs from the actual CREATE_PROCESS_DEBUG_EVENT hProcess identity");
                                retainedHandle = independentProcessHandle;
                                independentProcessHandle = IntPtr.Zero;
                                lock (_observedProcessLock)
                                    _observedHandleDuplicationAudit.Add(ev.ProcessId.ToString(CultureInfo.InvariantCulture) + ":open=parent-owned-retained-handle:retained=0x" + retainedHandle.ToInt64().ToString("x", CultureInfo.InvariantCulture));
                            }
                            finally
                            {
                                string openProcessCloseError = CloseIfOpen(ref independentProcessHandle, "CloseHandle(temporary OpenProcess identity)");
                                if (openProcessCloseError != null) throw new InvalidOperationException(openProcessCloseError);
                            }
                            lock (_observedProcessLock)
                            {
                                bool priorCollision = retainedHandle == _parentProcess || _observedProcessHandles.Contains(retainedHandle);
                            _observedHandleDuplicationAudit.Add(ev.ProcessId.ToString(CultureInfo.InvariantCulture) + ":source=0x" + created.Process.ToInt64().ToString("x", CultureInfo.InvariantCulture) + ":thread=0x" + created.Thread.ToInt64().ToString("x", CultureInfo.InvariantCulture) + ":file=0x" + eventImageHandle.ToInt64().ToString("x", CultureInfo.InvariantCulture) + ":retained=0x" + retainedHandle.ToInt64().ToString("x", CultureInfo.InvariantCulture) + ":same=" + (retainedHandle == created.Process).ToString() + ":priorCollision=" + priorCollision.ToString());
                                _observedProcessHandles.Add(retainedHandle);
                                _observedProcessIds.Add(ev.ProcessId);
                            }
                            if (failureInjection == "root-parent-mismatch" && isRootProcessEvent)
                                parentPid = parentPid == UInt32.MaxValue ? parentPid - 1 : parentPid + 1;
                            image = ReadDebugImage(created.File);
                            string identity = ev.ProcessId.ToString(CultureInfo.InvariantCulture) + "@" + creation.ToString(CultureInfo.InvariantCulture);
                            if (creation <= 0 || !identities.Add(identity)) throw new InvalidOperationException("process PID/creation identity is absent or duplicated");
                            if (active.ContainsKey(ev.ProcessId)) throw new InvalidOperationException("PID reused before the prior process identity exited");
                            if (!_jobNonBreakawayVerified) throw new InvalidOperationException("owned Job non-breakaway configuration was not verified before CREATE continuation");
                            RequireNonBreakawayJob(_job);
                            if (!ProcessIsInOwnedJob(created.Process, _job)) throw new InvalidOperationException("CREATE process handle is not a member of the exact owned non-breakaway Job");
                            if (trace.ProcessCreateEventCount == 1)
                            {
                                if (parentPid != (uint)trace.DebuggerProcessId) throw new InvalidOperationException("fixed root parent PID differs from the current runner");
                                parentCreation = debuggerCreation;
                                if (String.Equals(Path.GetFileName(image.Path), "protoc.exe", StringComparison.OrdinalIgnoreCase) ||
                                    IsPinnedVendoredProtocContentIdentity(image.Bytes.ToString(CultureInfo.InvariantCulture), image.Sha256))
                                    throw new InvalidOperationException("vendored protoc is authorized only as an exact per-run pinned descendant of the fixed Cargo root");
                                if (String.Equals(Path.GetFileName(image.Path), "vctip.exe", StringComparison.OrdinalIgnoreCase) ||
                                    IsPinnedVctipContentIdentity(image.Bytes, image.Sha256))
                                    throw new InvalidOperationException("MSVC VCTIP is authorized only as an exact pinned descendant of the fixed Cargo root");
                                string rootDeny = GetHardDeniedImageReason(image.Path);
                                bool pinnedGitRootAllowed = _debugCoordinator.AllowPinnedGitRoot &&
                                    String.Equals(Path.GetFileName(image.Path), "git.exe", StringComparison.OrdinalIgnoreCase);
                                if (rootDeny != null && !pinnedGitRootAllowed) throw new InvalidOperationException(rootDeny + ": " + image.Path);
                                if (!DebugImageMatches(image, expectedRoot)) throw new InvalidOperationException("fixed root image differs from its caller-pinned path/bytes/SHA/file ID");
                                reason = "exact-caller-pinned-fixed-root-image";
                                verified = true;
                            }
                            else
                            {
                                if (!active.TryGetValue(parentPid, out parent) || parent.Record.CreationFileTime <= 0)
                                    throw new InvalidOperationException("child parent PID lacks a unique active retained identity");
                                parentCreation = parent.Record.CreationFileTime;
                                // Each retained parent was itself admitted from this root's verified CREATE chain.
                                string denied = GetHardDeniedImageReason(image.Path);
                                bool exactH7GitName = String.Equals(Path.GetFileName(image.Path), "git.exe", StringComparison.OrdinalIgnoreCase);
                                if (denied != null && !(exactH7GitName && h7cGitPolicy != null)) throw new InvalidOperationException(denied + ": " + image.Path);
                                if (_debugCoordinator.AllowPinnedGitRoot &&
                                    (trace.ProcessCreateEventCount != 2 || trace.Processes.Count != 1 || parentPid != trace.Processes[0].ProcessId))
                                    throw new InvalidOperationException("standalone pinned Git permits only one direct caller-pinned Windows console-host child; observed " + image.Path + " parent=" + parent.Record.ImagePath);
                                if (exactH7GitName && h7cGitPolicy != null)
                                {
                                    DebugActiveProcess rootActive;
                                    if (trace.Processes.Count == 0 || !active.TryGetValue(trace.Processes[0].ProcessId, out rootActive))
                                        throw new InvalidOperationException("H7-C Git CREATE has no unique active root Cargo identity");
                                    D32H7CGitChildObservationV1 observation = ValidateH7CGitCreate(
                                        h7cGitPolicy, image, created.Process, parent.Record, rootActive,
                                        ev.ProcessId, creation, parentPid, parentCreation);
                                    lock (_h7cGitChildLock) _h7cGitChildren.Add(observation);
                                    reason = "narrow-caller-pinned-H7C-Git-child-v1";
                                }
                                else
                                {
                                bool protocName = String.Equals(Path.GetFileName(image.Path), "protoc.exe", StringComparison.OrdinalIgnoreCase);
                                bool protocContent = IsPinnedVendoredProtocContentIdentity(image.Bytes.ToString(CultureInfo.InvariantCulture), image.Sha256);
                                if (protocName || protocContent)
                                {
                                    if (!protocName)
                                        throw new InvalidOperationException("copied or renamed vendored protoc image content is not authorized under another path/name");
                                    reason = IsPinnedCargoVendoredProtocChildAllowed(expectedRoot[0], _debugCoordinator.AllowPinnedVendoredProtoc,
                                        image.Path, image.Bytes, image.Sha256, image.VolumeSerialHex, image.FileIdHex,
                                        _debugCoordinator.VendoredProtocCargoHomePath, _debugCoordinator.VendoredProtocPin)
                                        ? "caller-pinned-locked-vendored-protoc-descendant-of-fixed-cargo-root" : null;
                                    if (reason == null) throw new InvalidOperationException("vendored protoc descendant does not match the exact per-run locked Cargo source pin or opened hFile identity");
                                }
                                else
                                {
                                bool vctipName = String.Equals(Path.GetFileName(image.Path), "vctip.exe", StringComparison.OrdinalIgnoreCase);
                                bool vctipContent = IsPinnedVctipContentIdentity(image.Bytes, image.Sha256);
                                if (vctipName || vctipContent)
                                {
                                    if (!vctipName)
                                        throw new InvalidOperationException("copied or renamed MSVC VCTIP image content is not authorized under another path/name");
                                    reason = IsPinnedCargoVctipChildAllowed(expectedRoot[0], _debugCoordinator.AllowPinnedCargoVctip,
                                        image.Path, image.Bytes, image.Sha256, image.VolumeSerialHex, image.FileIdHex, approvedImagePins)
                                        ? "caller-pinned-msvc-vctip-descendant-of-fixed-cargo-root" : null;
                                    if (reason == null) throw new InvalidOperationException("MSVC VCTIP descendant does not match the exact caller-pinned Profile V2 entry, Cargo-root permission, or opened hFile identity");
                                }
                                else foreach (string[] pin in pins)
                                {
                                    if (DebugImageMatches(image, pin)) { reason = "caller-pinned-toolchain-native-or-Windows-image"; break; }
                                }
                                if (reason == null)
                                {
                                    foreach (string root in roots)
                                    {
                                        if (IsImageUnderRoot(image.Path, root)) { reason = "candidate-owned-target-image-observed-by-opened-handle"; break; }
                                    }
                                }
                                if (reason == null) throw new InvalidOperationException("unknown child/helper image outside pinned inventories and declared candidate target roots: " + image.Path);
                                }
                                }
                                verified = true;
                            }
                        }
                        finally
                        {
                            // CREATE_PROCESS_DEBUG_EVENT owns the process and initial-thread handles
                            // until their matching EXIT events are continued. Only hFile is debugger-owned.
                            TraceCloseHandle(eventImageHandle, trace, "CREATE_PROCESS_DEBUG_EVENT.hFile");
                        }
                        D32DebugProcessRecordV2 record = new D32DebugProcessRecordV2 {
                            ProcessId = ev.ProcessId, ParentProcessId = parentPid, CreationFileTime = creation, ParentCreationFileTime = parentCreation,
                            ImagePath = image == null ? null : image.Path, Bytes = image == null ? 0 : image.Bytes, Sha256 = image == null ? null : image.Sha256,
                            VolumeSerialHex = image == null ? null : image.VolumeSerialHex, FileIdHex = image == null ? null : image.FileIdHex,
                            AllowedImageReason = reason, ImageVerified = verified, Exited = false, ExitCode = 0,
                            CreateSequence = createSequence, ExitSequence = 0, CreatedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture), ExitedAtUtc = null
                        };
                        retained = new DebugActiveProcess { Record = record, Handle = retainedHandle };
                        if (!active.ContainsKey(ev.ProcessId)) active.Add(ev.ProcessId, retained);
                        trace.Processes.Add(record);
                        trace.ProcessEvents.Add(new D32DebugProcessEventV2 { Sequence = createSequence, Kind = "CREATE", ProcessId = ev.ProcessId,
                            ParentProcessId = parentPid, CreationFileTime = creation, ParentCreationFileTime = parentCreation, ExitCode = 0 });
                        if (trace.State != "BLOCKED") skipContinueForCreateIdentityFailure = false;
                    }
                    catch (Exception error)
                    {
                        trace.DebugApiErrorCount++;
                        string childIdentity = image == null
                            ? "opened_child_path=UNAVAILABLE opened_child_bytes=UNVERIFIED opened_child_sha256=UNVERIFIED opened_child_volume=UNVERIFIED opened_child_file_id=UNVERIFIED"
                            : "opened_child_path=" + image.Path + " opened_child_bytes=" + image.Bytes.ToString(CultureInfo.InvariantCulture) +
                                " opened_child_sha256=" + image.Sha256 + " opened_child_volume=" + image.VolumeSerialHex + " opened_child_file_id=" + image.FileIdHex;
                        string parentIdentity = parent == null
                            ? "parent_image_path=UNAVAILABLE"
                            : "parent_image_path=" + parent.Record.ImagePath;
                        TraceBlock(trace, "CREATE_PROCESS_DEBUG_EVENT verification failed: child_process_id=" + ev.ProcessId.ToString(CultureInfo.InvariantCulture) +
                            " child_creation_filetime=" + creation.ToString(CultureInfo.InvariantCulture) +
                            " parent_process_id=" + parentPid.ToString(CultureInfo.InvariantCulture) +
                            " parent_creation_filetime=" + parentCreation.ToString(CultureInfo.InvariantCulture) + " " + parentIdentity + " " + childIdentity + "; " + error.Message);
                    }
                    if (injectFirstCreateInterruption && trace.ProcessCreateEventCount == 1)
                    {
                        TraceBlock(trace, "debug chain interruption injected before ContinueDebugEvent; Job termination was requested");
                        if (!TerminateJobObject(_job, 0xD3201004)) trace.DebugApiErrorCount++;
                    }
                }
                else if (ev.Code == DebugEventExitProcess)
                {
                    if (failureInjection == "missing-exit")
                    {
                        trace.EventChainComplete = false;
                        TraceBlock(trace, "injected missing EXIT_PROCESS_DEBUG_EVENT ledger record; the received event was not continued");
                        if (!TerminateJobObject(_job, 0xD3201005)) trace.DebugApiErrorCount++;
                    }
                    else
                    {
                    trace.ProcessExitEventCount++;
                    trace.ProcessEventCount++;
                    long exitSequence = ++sequence;
                    DebugActiveProcess process;
                    if (!active.TryGetValue(ev.ProcessId, out process))
                    {
                        TraceBlock(trace, "EXIT_PROCESS_DEBUG_EVENT has no matching retained CREATE identity");
                    }
                    else
                    {
                        process.Record.Exited = true;
                        process.Record.ExitCode = ev.Data.ExitProcess.ExitCode;
                        process.Record.ExitSequence = exitSequence;
                        process.Record.ExitedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
                        trace.ProcessEvents.Add(new D32DebugProcessEventV2 { Sequence = exitSequence, Kind = "EXIT", ProcessId = ev.ProcessId,
                            ParentProcessId = process.Record.ParentProcessId, CreationFileTime = process.Record.CreationFileTime,
                            ParentCreationFileTime = process.Record.ParentCreationFileTime, ExitCode = ev.Data.ExitProcess.ExitCode });
                        active.Remove(ev.ProcessId);
                    }
                    }
                }
                else if (ev.Code == DebugEventException)
                {
                    trace.ExceptionEventCount++;
                    DebugExceptionInfo exception = ev.Data.Exception;
                    if (exception.Exception.ExceptionCode == StatusBreakpoint && exception.FirstChance != 0 && startupBreakpoints.Add(ev.ProcessId))
                    {
                        continueStatus = DebugContinue;
                    }
                    else if (exception.FirstChance != 0)
                    {
                        DebugActiveProcess owner;
                        if (!active.TryGetValue(ev.ProcessId, out owner) || !owner.Record.ImageVerified)
                        {
                            TraceBlock(trace, "first-chance exception has no verified active image identity");
                            if (!TerminateJobObject(_job, 0xD3201005)) trace.DebugApiErrorCount++;
                        }
                        continueStatus = DebugExceptionNotHandled;
                    }
                    else
                    {
                        TraceBlock(trace, "second-chance debug exception 0x" + exception.Exception.ExceptionCode.ToString("x8", CultureInfo.InvariantCulture));
                        if (!TerminateJobObject(_job, 0xD3201006)) trace.DebugApiErrorCount++;
                        continueStatus = DebugExceptionNotHandled;
                    }
                }
                else if (ev.Code == DebugEventCreateThread)
                {
                    trace.ThreadCreateEventCount++;
                    // hThread is closed by the system when ContinueDebugEvent processes EXIT_THREAD_DEBUG_EVENT.
                }
                else if (ev.Code == DebugEventExitThread) trace.ThreadExitEventCount++;
                else if (ev.Code == DebugEventLoadDll)
                {
                    trace.ImageLoadEventCount++;
                    TraceCloseHandle(ev.Data.LoadDll.File, trace, "LOAD_DLL_DEBUG_EVENT.hFile");
                }
                else if (ev.Code == DebugEventUnloadDll) trace.ImageUnloadEventCount++;
                else if (ev.Code == DebugEventOutputDebugString) trace.DebugStringEventCount++;
                else TraceBlock(trace, "unknown or unsupported Win32 debug event code " + ev.Code.ToString(CultureInfo.InvariantCulture));
            }
            catch (Exception error)
            {
                trace.DebugApiErrorCount++;
                TraceBlock(trace, "debug event processing failed: " + error.Message);
            }

            if (skipContinueForCreateIdentityFailure)
            {
                trace.EventChainComplete = false;
                TraceBlock(trace, "CREATE_PROCESS_DEBUG_EVENT was not fully validated; the Job was terminated and ContinueDebugEvent was not called");
                trace.UncontinuedCreateProcessId = ev.ProcessId;
                trace.UncontinuedCreateContinueCallCount = 0;
                if (!TerminateJobObject(_job, 0xD3201008)) trace.DebugApiErrorCount++;
                break;
            }
            if (failureInjection == "continue-api-failure" && ev.Code == DebugEventCreateProcess)
            {
                trace.DebugApiErrorCount++;
                trace.EventChainComplete = false;
                TraceBlock(trace, "injected ContinueDebugEvent API failure before continuation");
                trace.UncontinuedCreateProcessId = ev.ProcessId;
                trace.UncontinuedCreateContinueCallCount = 0;
                if (!TerminateJobObject(_job, 0xD3201009)) trace.DebugApiErrorCount++;
                break;
            }
            if (trace.State == "BLOCKED")
            {
                trace.EventChainComplete = false;
                if (ev.Code == DebugEventCreateProcess)
                {
                    trace.UncontinuedCreateProcessId = ev.ProcessId;
                    trace.UncontinuedCreateContinueCallCount = 0;
                }
                if (!TerminateJobObject(_job, 0xD320100A)) trace.DebugApiErrorCount++;
                break;
            }
            if (ev.Code == DebugEventCreateProcess)
            {
                try
                {
                    RequireNonBreakawayJob(_job);
                    DebugCreateProcessInfo created = ev.Data.CreateProcess;
                    if (!_jobNonBreakawayVerified || !ProcessIsInOwnedJob(created.Process, _job))
                        throw new InvalidOperationException("CREATE process is not in the verified owned non-breakaway Job immediately before continuation");
                }
                catch (Exception error)
                {
                    trace.DebugApiErrorCount++;
                    trace.EventChainComplete = false;
                    TraceBlock(trace, "CREATE_PROCESS_DEBUG_EVENT Job containment failed before ContinueDebugEvent: " + error.Message);
                    trace.UncontinuedCreateProcessId = ev.ProcessId;
                    trace.UncontinuedCreateContinueCallCount = 0;
                    if (!TerminateJobObject(_job, 0xD320100C)) trace.DebugApiErrorCount++;
                    break;
                }
            }
            DebugContinueCallCount++;
            if (!ContinueDebugEvent(ev.ProcessId, ev.ThreadId, continueStatus))
            {
                trace.DebugApiErrorCount++;
                trace.EventChainComplete = false;
                TraceBlock(trace, "ContinueDebugEvent failed; no polling fallback is permitted: " + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                if (!TerminateJobObject(_job, 0xD3201009)) trace.DebugApiErrorCount++;
                break;
            }
            string invalidRetainedHandles;
            if (!VerifyObservedProcessHandles(out invalidRetainedHandles))
            {
                trace.DebugApiErrorCount++;
                trace.EventChainComplete = false;
                TraceBlock(trace, "a parent-retained process handle became invalid after ContinueDebugEvent(event=" + ev.Code.ToString(CultureInfo.InvariantCulture) + ",pid=" + ev.ProcessId.ToString(CultureInfo.InvariantCulture) + ",tid=" + ev.ThreadId.ToString(CultureInfo.InvariantCulture) + "): " + invalidRetainedHandles);
                if (!TerminateJobObject(_job, 0xD320100B)) trace.DebugApiErrorCount++;
                break;
            }
        }
        trace.ProcessEventCount = trace.ProcessEvents.Count;
        trace.CompletedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
        return trace;
    }

    public D32NativeCleanupEvidenceV2 CloseJobAndWait(int timeoutMilliseconds)
    {
        if (_debugEnabled) return CloseDebugJobAndWait(timeoutMilliseconds);
        D32NativeCleanupEvidenceV2 evidence = new D32NativeCleanupEvidenceV2();
        if (_job == IntPtr.Zero)
        {
            evidence.AlreadyClosed = true;
            evidence.JobCloseSucceeded = true;
            evidence.JobActiveProcessCountVerified = _closedJobActiveProcessCountVerified;
            evidence.JobActiveProcessCount = _closedJobActiveProcessCount;
            evidence.JobActiveProcessCountLastError = _closedJobActiveProcessCountError;
            evidence.ProcessWaitSignaled = WaitForExit(timeoutMilliseconds);
            evidence.JobTerminateCallSucceeded = evidence.JobActiveProcessCountVerified && evidence.JobActiveProcessCount == 0;
            evidence.CleanupSucceeded = evidence.ProcessWaitSignaled &&
                evidence.JobActiveProcessCountVerified &&
                evidence.JobActiveProcessCount == 0;
            evidence.Detail = evidence.CleanupSucceeded
                ? "job handle already closed; active process count was verified at zero"
                : "job handle already closed without verified zero active process count";
            return evidence;
        }

        evidence.ProcessWasAlreadySignaled = HasExited;
        uint activeProcessCount;
        int activeProcessCountError;
        evidence.JobActiveProcessCountVerified = TryGetActiveProcessCount(
            out activeProcessCount,
            out activeProcessCountError);
        evidence.JobActiveProcessCount = activeProcessCount;
        evidence.JobActiveProcessCountLastError = activeProcessCountError;

        if (evidence.JobActiveProcessCountVerified && activeProcessCount == 0)
        {
            evidence.JobTerminateCallSucceeded = true;
        }
        else
        {
            evidence.JobTerminateCallSucceeded = TerminateJobObject(_job, 1);
            if (!evidence.JobTerminateCallSucceeded)
                evidence.JobTerminateLastError = Marshal.GetLastWin32Error();
            uint drainedCount;
            int drainedError;
            bool drained = WaitForJobActiveProcessZero(
                timeoutMilliseconds,
                out drainedCount,
                out drainedError);
            evidence.JobActiveProcessCountVerified = drained || (drainedCount == 0 && drainedError == 0);
            evidence.JobActiveProcessCount = drainedCount;
            evidence.JobActiveProcessCountLastError = drainedError;
        }

        evidence.ProcessWaitSignaled = WaitForExit(timeoutMilliseconds);
        string closeError = CloseIfOpen(ref _job, "CloseHandle(job)");
        evidence.JobCloseSucceeded = closeError == null;
        evidence.CleanupSucceeded = evidence.JobCloseSucceeded &&
            evidence.ProcessWaitSignaled &&
            evidence.JobTerminateCallSucceeded &&
            evidence.JobActiveProcessCountVerified &&
            evidence.JobActiveProcessCount == 0;
        if (evidence.JobCloseSucceeded)
        {
            _closedJobActiveProcessCountVerified = evidence.JobActiveProcessCountVerified;
            _closedJobActiveProcessCount = evidence.JobActiveProcessCount;
            _closedJobActiveProcessCountError = evidence.JobActiveProcessCountLastError;
        }
        evidence.Detail = evidence.CleanupSucceeded
            ? "owned job closed; root process signaled; job active process count reached zero"
            : "owned job close, root process wait, termination API, or job active process count verification failed" +
                (closeError == null ? String.Empty : "; " + closeError);
        return evidence;
    }

    private D32NativeCleanupEvidenceV2 CloseDebugJobAndWait(int timeoutMilliseconds)
    {
        D32NativeCleanupEvidenceV2 evidence = new D32NativeCleanupEvidenceV2();
        evidence.DebuggerThreadId = DebuggerThreadId;
        evidence.DebuggerKillOnExitEnabled = _debugKillOnExitEnabled;
        if (timeoutMilliseconds <= 0) timeoutMilliseconds = 1;

        Thread worker = _debugCoordinator == null ? null : _debugCoordinator.WorkerThread;
        bool joined = worker != null && !worker.IsAlive;
        if (!joined)
        {
            RequestDebugAbort("CloseJobAndWait requested fail-closed debugger shutdown");
            joined = worker != null && worker.Join(timeoutMilliseconds);
        }
        evidence.DebuggerThreadExited = worker != null && !worker.IsAlive;
        evidence.DebuggerThreadJoined = joined && evidence.DebuggerThreadExited;
        evidence.DebuggerThreadId = DebuggerThreadId;
        evidence.DebuggerKillOnExitEnabled = _debugKillOnExitEnabled;
        if (!evidence.DebuggerThreadJoined)
        {
            evidence.Detail = "dedicated debugger thread did not exit and join; retained Job and process handles were not closed";
            return evidence;
        }

        if (_debugTrace == null)
            _debugTrace = CreateBlockedDebugTrace(_debugCoordinator == null || _debugCoordinator.Failure == null
                ? "capture did not produce a trace before cleanup"
                : _debugCoordinator.Failure.Message);
        PopulatePostJoinDebugEvidence(_debugTrace, true);

        uint activeCount = UInt32.MaxValue;
        int activeError = 0;
        evidence.JobActiveProcessCountVerified = TryGetActiveProcessCountFromJob(
            _parentJob != IntPtr.Zero ? _parentJob : _job, out activeCount, out activeError);
        evidence.JobActiveProcessCount = activeCount;
        evidence.JobActiveProcessCountLastError = activeError;
        bool traceBlocked = _debugTrace.State != "COMPLETED" || !_debugTrace.AccountingConsistent;
        if (traceBlocked || !evidence.JobActiveProcessCountVerified || activeCount != 0)
        {
            IntPtr jobForTermination = _parentJob != IntPtr.Zero ? _parentJob : _job;
            evidence.JobTerminateCallSucceeded = jobForTermination != IntPtr.Zero && TerminateJobObject(jobForTermination, 0xD32010FE);
            if (!evidence.JobTerminateCallSucceeded && jobForTermination != IntPtr.Zero)
                evidence.JobTerminateLastError = Marshal.GetLastWin32Error();
        }
        else evidence.JobTerminateCallSucceeded = true;

        evidence.ProcessWaitSignaled = _parentProcess != IntPtr.Zero && WaitForSingleObject(_parentProcess, (uint)timeoutMilliseconds) == WaitObject0;
        List<IntPtr> handles = new List<IntPtr>();
        List<uint> processIds = new List<uint>();
        if (_parentProcess != IntPtr.Zero) { handles.Add(_parentProcess); processIds.Add((uint)ProcessId); }
        lock (_observedProcessLock) { handles.AddRange(_observedProcessHandles); processIds.AddRange(_observedProcessIds); }
        evidence.RetainedProcessHandleCount = handles.Count;
        evidence.RetainedProcessHandlesSignaled = handles.Count > 0;
        evidence.DebuggerAssociationQueryVerified = handles.Count > 0;
        evidence.DebuggerAssociationAbsent = handles.Count > 0;
        List<string> handleStates = new List<string>();
        DateTime waitDeadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);
        for (int i = 0; i < handles.Count; i++)
        {
            IntPtr handle = handles[i];
            uint pid = i < processIds.Count ? processIds[i] : 0;
            int remaining = Math.Max(0, (int)(waitDeadline - DateTime.UtcNow).TotalMilliseconds);
            uint waitResult = handle == IntPtr.Zero ? UInt32.MaxValue : WaitForSingleObject(handle, (uint)remaining);
            int waitError = waitResult == UInt32.MaxValue ? Marshal.GetLastWin32Error() : 0;
            bool present = true;
            bool debuggerQueryOk = handle != IntPtr.Zero && CheckRemoteDebuggerPresent(handle, out present);
            int debuggerQueryError = debuggerQueryOk ? 0 : Marshal.GetLastWin32Error();
            handleStates.Add(pid.ToString(CultureInfo.InvariantCulture) + ":h=0x" + handle.ToInt64().ToString("x", CultureInfo.InvariantCulture) + ":wait=" + waitResult.ToString(CultureInfo.InvariantCulture) + ":waitError=" + waitError.ToString(CultureInfo.InvariantCulture) + ":debuggerQuery=" + debuggerQueryOk.ToString() + ":queryError=" + debuggerQueryError.ToString(CultureInfo.InvariantCulture) + ":present=" + present.ToString());
            if (handle == IntPtr.Zero || waitResult != WaitObject0)
                evidence.RetainedProcessHandlesSignaled = false;
            if (!debuggerQueryOk)
            {
                evidence.DebuggerAssociationQueryVerified = false;
                evidence.DebuggerAssociationAbsent = false;
            }
            else if (present) evidence.DebuggerAssociationAbsent = false;
        }
        evidence.RetainedProcessHandleStates = String.Join(";", handleStates.ToArray());

        uint finalActive = UInt32.MaxValue;
        int finalActiveError = 0;
        bool finalJobVerified = TryGetActiveProcessCountFromJob(
            _parentJob != IntPtr.Zero ? _parentJob : _job, out finalActive, out finalActiveError);
        evidence.JobActiveProcessCountVerified = finalJobVerified;
        evidence.JobActiveProcessCount = finalActive;
        evidence.JobActiveProcessCountLastError = finalActiveError;
        bool cleanBeforeClose = evidence.DebuggerThreadExited && evidence.DebuggerThreadJoined &&
            evidence.DebuggerKillOnExitEnabled && evidence.ProcessWaitSignaled && evidence.RetainedProcessHandlesSignaled &&
            evidence.DebuggerAssociationQueryVerified && evidence.DebuggerAssociationAbsent &&
            finalJobVerified && finalActive == 0;
        if (cleanBeforeClose)
        {
            string parentJobError = CloseIfOpen(ref _parentJob, "CloseHandle(parent retained Job)");
            string debuggerJobError = CloseIfOpen(ref _job, "CloseHandle(debugger retained Job)");
            evidence.JobCloseSucceeded = parentJobError == null && debuggerJobError == null;
            if (evidence.JobCloseSucceeded)
            {
                lock (_observedProcessLock)
                {
                    foreach (IntPtr handle in _observedProcessHandles)
                    {
                        IntPtr observedHandle = handle;
                        string closeError = CloseIfOpen(ref observedHandle, "CloseHandle(observed process)");
                        if (closeError != null) evidence.JobCloseSucceeded = false;
                    }
                    _observedProcessHandles.Clear();
                }
                string rootCloseError = CloseIfOpen(ref _parentProcess, "CloseHandle(parent retained root process)");
                if (rootCloseError != null) evidence.JobCloseSucceeded = false;
            }
        }
        evidence.CleanupSucceeded = cleanBeforeClose && evidence.JobCloseSucceeded;
        _debugCleanupVerified = evidence.CleanupSucceeded;
        if (evidence.CleanupSucceeded)
        {
            _closedJobActiveProcessCountVerified = true;
            _closedJobActiveProcessCount = 0;
            _closedJobActiveProcessCountError = 0;
            evidence.Detail = "dedicated debugger thread exited and joined; kill-on-exit was enabled; retained process handles signaled; debugger association absent; Job ActiveProcesses=0; handles closed only after verification";
        }
        else
        {
            evidence.Detail = "dedicated debugger cleanup proof incomplete; TerminateJobObject result and/or Job ActiveProcesses=0 alone are insufficient; retained handles remain open; retained_handle_states=" + evidence.RetainedProcessHandleStates;
        }
        return evidence;
    }

    private static bool TryGetActiveProcessCountFromJob(IntPtr job, out uint count, out int error)
    {
        count = UInt32.MaxValue;
        error = 0;
        if (job == IntPtr.Zero) { error = 6; return false; }
        JobObjectBasicAccountingInformation accounting;
        if (!TryGetDebugJobAccounting(job, out accounting))
        {
            error = Marshal.GetLastWin32Error();
            return false;
        }
        count = accounting.ActiveProcesses;
        return true;
    }

    public void Dispose()
    {
        if (_disposed) return;
        if (_debugEnabled && !_debugCleanupVerified)
        {
            D32NativeCleanupEvidenceV2 cleanup = CloseDebugJobAndWait(15000);
            if (!cleanup.CleanupSucceeded)
                throw new InvalidOperationException("DEBUG_CLEANUP_UNVERIFIED: retained Job/process handles remain open: " + cleanup.Detail);
        }
        _disposed = true;
        string closeErrors = null;
        string parentJobError = CloseIfOpen(ref _parentJob, "CloseHandle(parent retained Job)");
        if (parentJobError != null) closeErrors = parentJobError;
        if (_job != IntPtr.Zero)
        {
            string closeError = CloseIfOpen(ref _job, "CloseHandle(job)");
            if (closeError != null) closeErrors = String.IsNullOrEmpty(closeErrors) ? closeError : closeErrors + "; " + closeError;
        }
        if (_stdoutStream != null) _stdoutStream.Dispose();
        if (_stderrStream != null) _stderrStream.Dispose();
        if (_stdoutHandle != null) _stdoutHandle.Dispose();
        if (_stderrHandle != null) _stderrHandle.Dispose();
        string threadError = CloseIfOpen(ref _thread, "CloseHandle(process thread)");
        if (threadError != null) closeErrors = String.IsNullOrEmpty(closeErrors) ? threadError : closeErrors + "; " + threadError;
        string processError = CloseIfOpen(ref _process, "CloseHandle(process)");
        if (processError != null) closeErrors = String.IsNullOrEmpty(closeErrors) ? processError : closeErrors + "; " + processError;
        string parentProcessError = CloseIfOpen(ref _parentProcess, "CloseHandle(parent retained process)");
        if (parentProcessError != null) closeErrors = String.IsNullOrEmpty(closeErrors) ? parentProcessError : closeErrors + "; " + parentProcessError;
        if (!String.IsNullOrEmpty(closeErrors))
            throw new InvalidOperationException("NATIVE_HANDLE_CLOSE_FAILED: " + closeErrors);
    }
}
'@ -Language CSharp
    }
    finally {
        [Environment]::SetEnvironmentVariable('LIB', $savedLib, 'Process')
    }
}

function New-D32ProcessIdentityRecord {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [AllowNull()][Nullable[int]]$ParentProcessId,
        [AllowNull()][string]$Name,
        [AllowNull()][string]$ImagePath,
        [AllowNull()][string]$CommandLine,
        [AllowNull()][string]$CreationDate,
        [Parameter(Mandatory = $true)][string]$ObservedAtUtc,
        [Parameter(Mandatory = $true)][bool]$IdentityVerified
    )

    return [pscustomobject][ordered]@{
        ProcessId       = $ProcessId
        ParentProcessId = $ParentProcessId
        Name            = $Name
        ImagePath       = $ImagePath
        CommandLine     = $CommandLine
        CreationDate    = $CreationDate
        ObservedAtUtc   = $ObservedAtUtc
        IdentityVerified = $IdentityVerified
    }
}

function Get-D32ProcessSnapshot {
    param([int]$ProcessId = 0)

    try {
        $observedAt = [DateTimeOffset]::UtcNow.ToString('o')
        $filter = if ($ProcessId -gt 0) { "ProcessId=$ProcessId" } else { $null }
        $items = if ($null -eq $filter) {
            @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
        }
        else {
            @(Get-CimInstance -ClassName Win32_Process -Filter $filter -ErrorAction Stop)
        }
        return @($items | ForEach-Object {
            $name = if ($null -eq $_.Name) { $null } else { [string]$_.Name }
            $imagePath = if ($null -eq $_.ExecutablePath) { $null } else { [string]$_.ExecutablePath }
            $creation = if ($null -eq $_.CreationDate) { $null } else { [string]$_.CreationDate }
            $parent = if ($null -eq $_.ParentProcessId) { $null } else { [int]$_.ParentProcessId }
            $commandLine = if ($null -eq $_.CommandLine) { $null } else { [string]$_.CommandLine }
            New-D32ProcessIdentityRecord `
                -ProcessId ([int]$_.ProcessId) `
                -ParentProcessId $parent `
                -Name $name `
                -ImagePath $imagePath `
                -CommandLine $commandLine `
                -CreationDate $creation `
                -ObservedAtUtc $observedAt `
                -IdentityVerified ($null -ne $name -and $name.Length -gt 0 -and
                    $null -ne $imagePath -and $imagePath.Length -gt 0 -and
                    $null -ne $commandLine -and $commandLine.Length -gt 0 -and
                    $null -ne $creation -and $creation.Length -gt 0)
        })
    }
    catch {
        throw "PROCESS_TREE_ENUMERATION_FAILED: $($_.Exception.Message)"
    }
}

function ConvertTo-D32DebugImagePinText {
    param([Parameter(Mandatory = $true)][object]$Image)
    return @([string]$Image.Path, [string]$Image.Bytes, [string]$Image.Sha256, [string]$Image.VolumeSerialHex, [string]$Image.FileIdHex) -join "`t"
}

function Get-D32DebugCandidateTargetRoots {
    param([Parameter(Mandatory = $true)][string]$Repository)
    return @(
        (Join-Path $Repository 'vita-agent\target\debug'),
        (Join-Path $Repository 'vita-agent\target\release'),
        (Join-Path $Repository 'src-tauri\target\debug'),
        (Join-Path $Repository 'src-tauri\target\release'),
        (Join-Path $Repository 'vita-agent-protocol\target\debug'),
        (Join-Path $Repository 'vita-agent-protocol\target\release')
    ) | ForEach-Object { [IO.Path]::GetFullPath($_) }
}

function ConvertTo-D32DebugProcessTraceDocument {
    param([Parameter(Mandatory = $true)][object]$Trace)
    return [ordered]@{
        record_type = [string]$Trace.RecordType
        schema_version = [int]$Trace.SchemaVersion
        event_source = [string]$Trace.EventSource
        state = [string]$Trace.State
        block_reason = $Trace.BlockReason
        debugger_process_id = [int]$Trace.DebuggerProcessId
        uncontinued_create_process_id = [uint32]$Trace.UncontinuedCreateProcessId
        uncontinued_create_continue_call_count = [int]$Trace.UncontinuedCreateContinueCallCount
        debugger_thread_id = [uint32]$Trace.DebuggerThreadId
        dedicated_debugger_thread = [bool]$Trace.DedicatedDebuggerThread
        debugger_kill_on_exit_enabled = [bool]$Trace.DebuggerKillOnExitEnabled
        root_resumed_after_kill_on_exit = [bool]$Trace.RootResumedAfterKillOnExit
        debugger_thread_exited = [bool]$Trace.DebuggerThreadExited
        debugger_thread_joined = [bool]$Trace.DebuggerThreadJoined
        retained_process_handle_count = [int]$Trace.RetainedProcessHandleCount
        retained_process_handles_signaled = [bool]$Trace.RetainedProcessHandlesSignaled
        debugger_association_query_verified = [bool]$Trace.DebuggerAssociationQueryVerified
        debugger_association_absent = [bool]$Trace.DebuggerAssociationAbsent
        debugger_creation_filetime = [Int64]$Trace.DebuggerCreationFileTime
        debugger_created_at_utc = [string]$Trace.DebuggerCreatedAtUtc
        started_at_utc = [string]$Trace.StartedAtUtc
        completed_at_utc = [string]$Trace.CompletedAtUtc
        debug_event_count = [int]$Trace.DebugEventCount
        process_create_event_count = [int]$Trace.ProcessCreateEventCount
        process_exit_event_count = [int]$Trace.ProcessExitEventCount
        process_event_count = [int]$Trace.ProcessEventCount
        thread_create_event_count = [int]$Trace.ThreadCreateEventCount
        thread_exit_event_count = [int]$Trace.ThreadExitEventCount
        image_load_event_count = [int]$Trace.ImageLoadEventCount
        image_unload_event_count = [int]$Trace.ImageUnloadEventCount
        exception_event_count = [int]$Trace.ExceptionEventCount
        debug_string_event_count = [int]$Trace.DebugStringEventCount
        wait_timeout_count = [int]$Trace.WaitTimeoutCount
        debug_api_error_count = [int]$Trace.DebugApiErrorCount
        event_chain_complete = [bool]$Trace.EventChainComplete
        job_accounting_verified = [bool]$Trace.JobAccountingVerified
        job_total_processes = [uint32]$Trace.JobTotalProcesses
        job_active_processes = [uint32]$Trace.JobActiveProcesses
        accounting_consistent = [bool]$Trace.AccountingConsistent
        injected_interruption = [bool]$Trace.InjectedInterruption
        process_events = @($Trace.ProcessEvents | ForEach-Object {
            [ordered]@{
                sequence = [Int64]$_.Sequence
                kind = [string]$_.Kind
                process_id = [uint32]$_.ProcessId
                parent_process_id = [uint32]$_.ParentProcessId
                creation_filetime = [Int64]$_.CreationFileTime
                parent_creation_filetime = [Int64]$_.ParentCreationFileTime
                exit_code = [uint32]$_.ExitCode
            }
        })
        processes = @($Trace.Processes | ForEach-Object {
            [ordered]@{
                process_id = [uint32]$_.ProcessId
                parent_process_id = [uint32]$_.ParentProcessId
                creation_filetime = [Int64]$_.CreationFileTime
                parent_creation_filetime = [Int64]$_.ParentCreationFileTime
                image_path = $_.ImagePath
                bytes = [Int64]$_.Bytes
                sha256 = $_.Sha256
                volume_serial_hex = $_.VolumeSerialHex
                file_id_hex = $_.FileIdHex
                allowed_image_reason = $_.AllowedImageReason
                image_verified = [bool]$_.ImageVerified
                exited = [bool]$_.Exited
                exit_code = [uint32]$_.ExitCode
                create_sequence = [Int64]$_.CreateSequence
                exit_sequence = [Int64]$_.ExitSequence
                created_at_utc = $_.CreatedAtUtc
                exited_at_utc = $_.ExitedAtUtc
            }
        })
    }
}

function ConvertFrom-D32DebugProcessRecord {
    param([Parameter(Mandatory = $true)][object]$Process, [AllowEmptyString()][string]$CommandLine = '')
    $creationDate = if ([Int64]$Process.CreationFileTime -gt 0) { [DateTime]::FromFileTimeUtc([Int64]$Process.CreationFileTime).ToString('o') } else { $null }
    return New-D32ProcessIdentityRecord `
        -ProcessId ([int]$Process.ProcessId) `
        -ParentProcessId ([int]$Process.ParentProcessId) `
        -Name ([IO.Path]::GetFileName([string]$Process.ImagePath)) `
        -ImagePath ([string]$Process.ImagePath) `
        -CommandLine $CommandLine `
        -CreationDate $creationDate `
        -ObservedAtUtc ([string]$Process.CreatedAtUtc) `
        -IdentityVerified ([bool]$Process.ImageVerified -and [bool]$Process.Exited)
}

function ConvertTo-D32IdentityDocument {
    param([AllowNull()][object]$Record)

    if ($null -eq $Record) { return $null }
    return [ordered]@{
        process_id        = if ($null -eq $Record.ProcessId) { $null } else { [int]$Record.ProcessId }
        parent_process_id = if ($null -eq $Record.ParentProcessId) { $null } else { [int]$Record.ParentProcessId }
        name              = $Record.Name
        creation_date     = $Record.CreationDate
        command_line      = $Record.CommandLine
        observed_at_utc   = $Record.ObservedAtUtc
        identity_verified = [bool]$Record.IdentityVerified
    }
}

function ConvertTo-D32D31ProcessIdentityDocument {
    param([AllowNull()][object]$Record)

    if ($null -eq $Record) { return $null }
    return [ordered]@{
        process_id = if ($null -eq $Record.ProcessId) { $null } else { [int]$Record.ProcessId }
        parent_process_id = if ($null -eq $Record.ParentProcessId) { $null } else { [int]$Record.ParentProcessId }
        name = $Record.Name
        image_path = $Record.ImagePath
        creation_date = $Record.CreationDate
        command_line = $Record.CommandLine
        observed_at_utc = $Record.ObservedAtUtc
        identity_verified = [bool]$Record.IdentityVerified
    }
}

function Assert-D32PinnedCargoProcessIdentity {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$ProcessIdentity,
        [Parameter(Mandatory = $true)][string]$CargoPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [AllowNull()][object]$ProcessResult
    )

    if ($null -eq $ProcessIdentity -or -not [bool]$ProcessIdentity.IdentityVerified -or [int]$ProcessIdentity.ProcessId -le 0) {
        $identityState = if ($null -eq $ProcessIdentity) {
            'root_identity=UNAVAILABLE'
        }
        else {
            'root_identity_verified={0}; process_id={1}; parent_process_id={2}; image_path={3}; name={4}' -f `
                [bool]$ProcessIdentity.IdentityVerified, $ProcessIdentity.ProcessId, $ProcessIdentity.ParentProcessId, $ProcessIdentity.ImagePath, $ProcessIdentity.Name
        }
        $processContext = ''
        if ($null -ne $ProcessResult) {
            $trace = $ProcessResult.process_trace
            $traceContext = if ($null -eq $trace) { 'trace=UNAVAILABLE' } else {
                'trace_state={0}; trace_block_reason={1}; event_chain_complete={2}; accounting_consistent={3}' -f `
                    [string]$trace.state, [string]$trace.block_reason, [bool]$trace.event_chain_complete, [bool]$trace.accounting_consistent
            }
            $processContext = '; process_status={0}; exit_code={1}; process_error={2}; {3}' -f `
                [string]$ProcessResult.status, $ProcessResult.exit_code, [string]$ProcessResult.error, $traceContext
        }
        throw "CARGO_PROCESS_IDENTITY_MISMATCH: Cargo process identity was not verified; $identityState$processContext"
    }
    $expectedPath = Get-D32FullPath $CargoPath
    if (-not [string]::Equals((Get-D32FullPath ([string]$ProcessIdentity.ImagePath)), $expectedPath, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$ProcessIdentity.Name, 'cargo.exe', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'CARGO_PROCESS_IDENTITY_MISMATCH: observed Cargo process name/image does not match the caller-pinned Cargo path'
    }
    $expectedTool = $ValidatedProfile.Profile.toolchain.cargo
    if (-not [string]::Equals((Get-D32FullPath ([string]$expectedTool.path)), $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'CARGO_PROCESS_IDENTITY_MISMATCH: process path differs from the profile-pinned direct Cargo executable'
    }
    $observedArtifact = Get-D32BoundArtifact -Path ([string]$ProcessIdentity.ImagePath)
    if ($observedArtifact.sha256 -cne [string]$expectedTool.sha256 -or
        [uint64]$observedArtifact.bytes -ne [uint64]$expectedTool.bytes) {
        throw 'CARGO_PROCESS_IDENTITY_MISMATCH: started process image bytes/hash differ from the profile-pinned Cargo identity'
    }
    $expectedCommand = ConvertTo-D32CommandLine (@($expectedPath) + $Arguments)
    if (-not [string]::Equals([string]$ProcessIdentity.CommandLine, $expectedCommand, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'CARGO_PROCESS_IDENTITY_MISMATCH: started Cargo process argv differs from the requested fixed command'
    }
    if ($null -eq $ProcessIdentity.ParentProcessId -or [int]$ProcessIdentity.ParentProcessId -ne [int]$PID -or
        [int]$ProcessIdentity.ParentProcessId -eq [int]$ProcessIdentity.ProcessId -or
        [String]::IsNullOrWhiteSpace([string]$ProcessIdentity.CreationDate) -or
        [String]::IsNullOrWhiteSpace([string]$ProcessIdentity.ObservedAtUtc)) {
        throw 'CARGO_PROCESS_IDENTITY_MISMATCH: Cargo parent must be this pinned PowerShell process and creation evidence must be complete'
    }
}

function ConvertTo-D32NativeCleanupDocument {
    param([AllowNull()][object]$Evidence)

    if ($null -eq $Evidence) { return $null }
    return [ordered]@{
        job_terminate_call_succeeded = [bool]$Evidence.JobTerminateCallSucceeded
        job_terminate_last_error     = [int]$Evidence.JobTerminateLastError
        process_was_already_signaled = [bool]$Evidence.ProcessWasAlreadySignaled
        process_wait_signaled        = [bool]$Evidence.ProcessWaitSignaled
        job_active_process_count_verified = [bool]$Evidence.JobActiveProcessCountVerified
        job_active_process_count     = [uint32]$Evidence.JobActiveProcessCount
        job_active_process_count_last_error = [int]$Evidence.JobActiveProcessCountLastError
        job_close_succeeded          = [bool]$Evidence.JobCloseSucceeded
        cleanup_succeeded            = [bool]$Evidence.CleanupSucceeded
        already_closed               = [bool]$Evidence.AlreadyClosed
        detail                       = [string]$Evidence.Detail
    }
}

function Get-D32DescendantProcessRecordsFromSnapshot {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Snapshot,
        [Parameter(Mandatory = $true)][int]$RootPid
    )
    if ($Snapshot.Count -eq 0) { throw 'PROCESS_TREE_REAP_FAILED: process identity snapshot is empty' }

    $byParent = @{}
    foreach ($record in $Snapshot) {
        if ($null -eq $record.ParentProcessId) { continue }
        $parent = [int]$record.ParentProcessId
        if (-not $byParent.ContainsKey($parent)) { $byParent[$parent] = @() }
        $byParent[$parent] += $record
    }
    $pending = [System.Collections.Generic.Queue[int]]::new()
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    $pending.Enqueue($RootPid)
    [void]$seen.Add($RootPid)
    $descendants = [System.Collections.Generic.List[object]]::new()
    while ($pending.Count -gt 0) {
        $parent = $pending.Dequeue()
        if (-not $byParent.ContainsKey($parent)) { continue }
        foreach ($record in $byParent[$parent]) {
            $child = [int]$record.ProcessId
            if ($seen.Add($child)) {
                $descendants.Add($record)
                $pending.Enqueue($child)
            }
        }
    }
    return @($descendants)
}

function Get-D32DescendantProcessRecords {
    param([Parameter(Mandatory = $true)][int]$RootPid)

    return @(Get-D32DescendantProcessRecordsFromSnapshot -Snapshot (Get-D32ProcessSnapshot) -RootPid $RootPid)
}

function Get-D32ProcessIdentityKey {
    param([Parameter(Mandatory = $true)][object]$Record)

    $creation = if ($null -eq $Record.CreationDate) { '<none>' } else { [string]$Record.CreationDate }
    return "$([int]$Record.ProcessId)|$creation"
}

function Merge-D32ProcessIdentityRecords {
    param(
        [AllowNull()][object[]]$Existing,
        [AllowNull()][object[]]$Incoming
    )

    $merged = [ordered]@{}
    foreach ($record in @($Existing) + @($Incoming)) {
        if ($null -eq $record) { continue }
        $key = Get-D32ProcessIdentityKey $record
        $merged[$key] = $record
    }
    return @($merged.Values)
}

function New-D32FallbackProcessIdentity {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][string]$ObservedAtUtc
    )

    return New-D32ProcessIdentityRecord `
        -ProcessId $ProcessId `
        -ParentProcessId $null `
        -Name ([IO.Path]::GetFileName($FilePath)) `
        -CommandLine $CommandLine `
        -CreationDate $null `
        -ObservedAtUtc $ObservedAtUtc `
        -IdentityVerified $false
}

function Test-D32CapturedProcessAlive {
    param([Parameter(Mandatory = $true)][object]$Record)

    $current = @(Get-D32ProcessSnapshot -ProcessId ([int]$Record.ProcessId))
    if ($current.Count -eq 0) { return $false }
    $candidate = $current[0]
    if (-not [bool]$Record.IdentityVerified) {
        throw "PROCESS_IDENTITY_UNVERIFIED: pid $($Record.ProcessId) is still present but its captured identity was incomplete"
    }
    if ([string]$candidate.Name -cne [string]$Record.Name -or
        [string]$candidate.CreationDate -cne [string]$Record.CreationDate) {
        throw "PROCESS_IDENTITY_MISMATCH: captured pid $($Record.ProcessId) no longer matches name/creation identity"
    }
    return $true
}

function Stop-D32ProcessTreeAndVerify {
    param(
        [Parameter(Mandatory = $true)][object]$RootRecord,
        [AllowNull()][object[]]$CapturedDescendantRecords = @(),
        [AllowNull()][object]$NativeProcess = $null
    )

    $records = @(Merge-D32ProcessIdentityRecords -Existing @($RootRecord) -Incoming $CapturedDescendantRecords)
    $killOutput = [System.Collections.Generic.List[string]]::new()
    $nativeCleanup = $null
    if ($null -ne $NativeProcess) {
        try {
            $nativeCleanup = $NativeProcess.CloseJobAndWait(10000)
            if (-not [bool]$nativeCleanup.CleanupSucceeded) {
                throw "native job close did not verify process termination: $($nativeCleanup.Detail)"
            }
        }
        catch {
            throw "PROCESS_GROUP_REAP_FAILED: $($_.Exception.Message)"
        }
    }
    $rootAlive = Test-D32CapturedProcessAlive -Record $RootRecord
    if ($rootAlive) {
        $killOutput.AddRange([string[]]@(& taskkill.exe /PID ([int]$RootRecord.ProcessId) /T /F 2>&1))
    }
    else {
        $killOutput.Add('root process identity was already gone; per-identity verification continues')
    }

    # Do not wait for a dead root to make a detached child disappear. The
    # retained name/creation identity is the authorization for each explicit
    # per-PID kill, so this remains safe across reparenting and PID reuse.
    foreach ($record in $records) {
        if ([int]$record.ProcessId -eq [int]$RootRecord.ProcessId) { continue }
        if (Test-D32CapturedProcessAlive -Record $record) {
            $killOutput.AddRange([string[]]@(& taskkill.exe /PID ([int]$record.ProcessId) /F 2>&1))
        }
    }

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
    do {
        $alive = [System.Collections.Generic.List[object]]::new()
        foreach ($record in $records) {
            if (Test-D32CapturedProcessAlive -Record $record) { $alive.Add($record) }
        }
        if ($alive.Count -eq 0) {
            return [ordered]@{
                ProcessIds = @($records | ForEach-Object { [int]$_.ProcessId })
                CapturedRecords = @($records)
                ResidualRecords = @()
                KillOutput = @($killOutput)
                NativeCleanup = $nativeCleanup
                VerifiedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    # The recursive taskkill is the first action. Explicitly target every
    # captured identity once more so a process that detached or raced the tree
    # capture cannot be silently inherited by the next phase. Never target a
    # PID whose name/creation identity no longer matches the capture.
    foreach ($record in $records) {
        if (Test-D32CapturedProcessAlive -Record $record) {
            $killOutput.AddRange([string[]]@(& taskkill.exe /PID ([int]$record.ProcessId) /F 2>&1))
        }
    }
    Start-Sleep -Milliseconds 250
    $residual = [System.Collections.Generic.List[object]]::new()
    foreach ($record in $records) {
        if (Test-D32CapturedProcessAlive -Record $record) { $residual.Add($record) }
    }
    if ($residual.Count -gt 0) {
        $details = ($residual | ForEach-Object { "$($_.Name):$($_.ProcessId):parent=$($_.ParentProcessId):creation=$($_.CreationDate)" }) -join ', '
        throw "PROCESS_TREE_REAP_FAILED: captured process identities remained alive after recursive and per-PID kill: $details"
    }
    return [ordered]@{
        ProcessIds = @($records | ForEach-Object { [int]$_.ProcessId })
        CapturedRecords = @($records)
        ResidualRecords = @()
        KillOutput = @($killOutput)
        NativeCleanup = $nativeCleanup
        VerifiedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
    }
}

function Test-D32NoOwnedCargoDescendants {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$PhaseEvidence,
        [Parameter(Mandatory = $true)][string]$CheckName
    )
    if ($PhaseEvidence.Count -eq 0) { throw "PROCESS_TREE_REAP_FAILED: $CheckName has no captured process identity evidence" }
    foreach ($evidence in $PhaseEvidence) {
        $rootRecord = if ($null -eq $evidence) { $null } else { $evidence.root_record }
        $identityVerified = if ($null -eq $rootRecord) { $null } else { $rootRecord.PSObject.Properties['IdentityVerified'] }
        if ($null -eq $identityVerified -or $identityVerified.Value -isnot [bool] -or -not $identityVerified.Value -or
            [int]$rootRecord.ProcessId -le 0 -or [String]::IsNullOrWhiteSpace([string]$rootRecord.CreationDate) -or
            [String]::IsNullOrWhiteSpace([string]$rootRecord.Name)) {
            throw "PROCESS_TREE_REAP_FAILED: $CheckName has a phase without verified root process identity evidence"
        }
    }

    $tracked = [System.Collections.Generic.List[object]]::new()
    foreach ($evidence in $PhaseEvidence) {
        if ($null -ne $evidence.root_record) { $tracked.Add($evidence.root_record) }
        foreach ($record in @($evidence.descendant_records)) {
            if ($null -ne $record) { $tracked.Add($record) }
        }
        if ($null -ne $evidence.root_record) {
            # Failed phases are deliberately included here. A normal phase
            # may have no descendants, while a process-tree error must retain
            # every identity captured before the error.
            [void](Stop-D32ProcessTreeAndVerify -RootRecord $evidence.root_record -CapturedDescendantRecords @($evidence.descendant_records))
        }
    }

    $snapshot = Get-D32ProcessSnapshot
    $byParent = @{}
    foreach ($record in $snapshot) {
        if ($null -eq $record.ParentProcessId) { continue }
        $parent = [int]$record.ParentProcessId
        if (-not $byParent.ContainsKey($parent)) { $byParent[$parent] = @() }
        $byParent[$parent] += $record
    }
    $residual = [System.Collections.Generic.List[object]]::new()
    foreach ($record in (Merge-D32ProcessIdentityRecords -Existing @() -Incoming @($tracked))) {
        if (Test-D32CapturedProcessAlive -Record $record) { $residual.Add($record) }
    }

    $rootQueue = [System.Collections.Generic.Queue[int]]::new()
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($evidence in $PhaseEvidence) {
        if ($null -eq $evidence.root_record) { continue }
        if (Test-D32CapturedProcessAlive -Record $evidence.root_record) {
            $rootQueue.Enqueue([int]$evidence.root_record.ProcessId)
        }
    }
    $relevantPattern = '(?i)(cargo|rustc|rustup|lld-link|(^|[-_])link([-.]|$)|fixture)'
    while ($rootQueue.Count -gt 0) {
        $parent = $rootQueue.Dequeue()
        if (-not $byParent.ContainsKey($parent)) { continue }
        foreach ($record in $byParent[$parent]) {
            $child = [int]$record.ProcessId
            if (-not $seen.Add($child)) { continue }
            $rootQueue.Enqueue($child)
            if ([string]$record.Name -match $relevantPattern) { $residual.Add($record) }
        }
    }
    if ($residual.Count -gt 0) {
        $details = ($residual | ForEach-Object { "$($_.Name):$($_.ProcessId):parent=$($_.ParentProcessId):creation=$($_.CreationDate)" }) -join ', '
        throw "PROCESS_TREE_REAP_FAILED: $CheckName found owned process descendants in relevant set ($relevantPattern): $details"
    }
    return [ordered]@{
        checked_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        relevant_pattern = $relevantPattern
        residual_identities = @()
    }
}

function Reset-D32FixturePhaseProcessEvidence {
    # A later phase can fail before its process launcher is reached. Clear the
    # previous phase's evidence so the single blocked payload never pairs a
    # new command/error with stale process, trace, or cleanup records.
    $script:D32LastProcessEvidence = $null
}

function Get-D32FixtureFailurePayloadSelection {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$PendingFailures,
        [AllowNull()][object]$TerminalFailure,
        [AllowNull()][string]$GlobalCleanupError
    )

    $selected = $TerminalFailure
    $secondary = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $selected) {
        if ($PendingFailures.Count -eq 0) { return $null }
        # For ordinary nonzero exits, all fixed phases are attempted. Bind the
        # one failure payload to the last failed phase in contract order and
        # retain earlier failures as secondary context.
        $selected = $PendingFailures[$PendingFailures.Count - 1]
        for ($index = 0; $index -lt ($PendingFailures.Count - 1); $index++) {
            $secondary.Add([string]$PendingFailures[$index].error)
        }
    }
    else {
        # A later fatal phase supersedes ordinary failures as the payload's
        # process/trace/cleanup source; prior ordinary failures remain secondary.
        foreach ($failure in $PendingFailures) { $secondary.Add([string]$failure.error) }
    }
    if (-not [String]::IsNullOrWhiteSpace($GlobalCleanupError)) { $secondary.Add($GlobalCleanupError) }
    return [PSCustomObject]@{
        Name = [string]$selected.name
        Arguments = @($selected.arguments)
        ProcessResult = $selected.process_result
        PhaseLogPath = [string]$selected.phase_log
        PrimaryError = [string]$selected.error
        SecondaryErrors = @($secondary.ToArray())
    }
}

function Write-D32FixturePhase0FailurePayload {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [AllowNull()][object]$ProcessResult,
        [Parameter(Mandatory = $true)][string]$PrimaryError,
        [AllowEmptyCollection()][string[]]$SecondaryErrors = @(),
        [AllowNull()][string]$PhaseLogPath
    )

    if ($null -eq $script:D32Phase0StorageContext -or $null -eq $Phase0OwnerBinding -or [bool]$script:D32Phase0FailurePayloadEmitted) { return }
    $image = @($script:ValidatedToolchainProfile.ExecutableInventory | Where-Object { Test-D32ProfilePathEqual -Left $_.Path -Right $Executable })
    if ($image.Count -ne 1) { throw 'PHASE0_FAILURE_CAPTURE_BLOCKED: failing executable is not uniquely present in the caller-pinned profile inventory' }
    $image = $image[0]
    $commandLine = ConvertTo-D32CommandLine (@($Executable) + @($Arguments))
    $stdoutPath = if ($null -ne $ProcessResult -and -not [String]::IsNullOrWhiteSpace([string]$ProcessResult.stdout_log)) { [string]$ProcessResult.stdout_log } elseif (-not [String]::IsNullOrWhiteSpace($PhaseLogPath)) { Get-D32FullPath "$PhaseLogPath.stdout.log" } else { $null }
    $stderrPath = if ($null -ne $ProcessResult -and -not [String]::IsNullOrWhiteSpace([string]$ProcessResult.stderr_log)) { [string]$ProcessResult.stderr_log } elseif (-not [String]::IsNullOrWhiteSpace($PhaseLogPath)) { Get-D32FullPath "$PhaseLogPath.stderr.log" } else { $null }
    $streams = @(
        [ordered]@{ ordinal = 1; stream = 'stdout'; path = $stdoutPath },
        [ordered]@{ ordinal = 2; stream = 'stderr'; path = $stderrPath }
    )
    $rawEvidence = if ($null -ne $ProcessResult -and $null -ne $ProcessResult.raw_debug_job_evidence) { $ProcessResult.raw_debug_job_evidence } else { $script:D32LastProcessEvidence }
    $rawDebugEvidence = $rawEvidence
    $processIdentity = if ($null -ne $ProcessResult) { $ProcessResult.root_identity } elseif ($null -ne $rawEvidence) { ConvertTo-D32IdentityDocument $rawEvidence.root_record } else { $null }
    $rawTrace = if ($null -ne $ProcessResult -and $null -ne $ProcessResult.process_trace) { $ProcessResult.process_trace } elseif ($null -ne $rawEvidence) { $rawEvidence.process_trace } else { $null }
    $nativeCleanup = if ($null -ne $ProcessResult -and $null -ne $ProcessResult.native_cleanup) { $ProcessResult.native_cleanup } elseif ($null -ne $rawEvidence -and $null -ne $rawEvidence.native_cleanup) { ConvertTo-D32NativeCleanupDocument $rawEvidence.native_cleanup } else { $null }
    $payload = [ordered]@{
        schema_version = 1
        record_type = 'D32_PHASE0_BLOCKED_DIAGNOSTIC_PAYLOAD_V1'
        candidate_sha = [string]$candidateSha
        toolchain_profile_path = [string]$script:ValidatedToolchainProfile.ProfilePath
        toolchain_profile_sha256 = [string]$script:ValidatedToolchainProfile.Digest
        run_id = [string]$script:D32Phase0StorageContext.run_id
        failing_fixed_command = [ordered]@{
            name = $Name
            executable = [string]$image.Path
            executable_sha256 = [string]$image.Sha256
            executable_bytes = [Int64]$image.Bytes
            executable_volume_serial_hex = [string]$image.VolumeSerialHex
            executable_file_id_hex = [string]$image.FileIdHex
            arguments = @($Arguments)
            command_line = $commandLine
            working_directory = [IO.Path]::GetFullPath($WorkingDirectory)
        }
        process_identity = $processIdentity
        raw_v2_trace = $rawTrace
        raw_job_debug_cleanup = [ordered]@{
            raw_native_cleanup = $nativeCleanup
            raw_process_evidence = $rawDebugEvidence
            trace_state = if ($null -eq $rawTrace) { $null } else { [string]$rawTrace.state }
            cleanup_status = if ($null -eq $nativeCleanup) { 'UNVERIFIED' } elseif ([bool]$nativeCleanup.cleanup_succeeded) { 'VERIFIED' } else { 'UNVERIFIED' }
        }
        ordered_stream_paths = $streams
        primary_error = $PrimaryError
        secondary_errors = @($SecondaryErrors)
    }
    $json = ConvertTo-Json -InputObject $payload -Depth 40 -Compress
    $script:D32Phase0FailurePayloadEmitted = $true
    Write-Output ('D32_PHASE0_BLOCKED_DIAGNOSTIC_PAYLOAD_V1:' + $json)
}

function Invoke-D32BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$PhaseLog,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [AllowNull()][object]$ChildEnvironment,
        [ValidateSet('none', 'spawn-init', 'cim-init', 'pipe-init', 'api-failure', 'attribute-failure', 'pipe-timeout')]
        [string]$FailureInjection = 'none',
        [switch]$RequireDebugEvents,
        [switch]$AllowPinnedCargoVctip,
        [AllowNull()][object]$VendoredProtocRunGrant,
        [string[]]$CandidateImageRoots
    )

    if ($null -ne $ChildEnvironment -and $ChildEnvironment -isnot [System.Collections.IDictionary]) {
        throw 'CHILD_ENVIRONMENT_INVALID: ChildEnvironment must be an IDictionary; values omitted'
    }
    $vendoredProtocBeforeStart = $null
    if ($null -ne $VendoredProtocRunGrant) {
        if (-not $RequireDebugEvents -or -not $AllowPinnedCargoVctip -or
            $null -eq $script:ValidatedToolchainProfile -or -not [bool]$script:ValidatedToolchainProfile.IsValid -or
            -not (Test-D32ProfilePathEqual -Left $FilePath -Right ([string]$script:ValidatedToolchainProfile.Profile.toolchain.cargo.path)) -or
            $null -eq $ChildEnvironment -or -not $ChildEnvironment.Contains('CARGO_HOME') -or
            -not (Test-D32ProfilePathEqual -Left ([string]$ChildEnvironment['CARGO_HOME']) -Right ([string]$VendoredProtocRunGrant.Document.cargo_home.path))) {
            throw 'VENDORED_PROTOC_GRANT_BLOCKED: exact grant requires debug capture under the fixed Cargo root, pinned VCTIP policy, and the same fresh owner-bound CargoHome before process creation'
        }
        $vendoredProtocBeforeStart = Get-D32ProfileFileSnapshot -Path ([string]$VendoredProtocRunGrant.Image.Path)
        if ($vendoredProtocBeforeStart.Bytes -ne [Int64]$VendoredProtocRunGrant.Image.Bytes -or $vendoredProtocBeforeStart.Sha256 -cne [string]$VendoredProtocRunGrant.Image.Sha256 -or
            $vendoredProtocBeforeStart.VolumeSerialHex -cne [string]$VendoredProtocRunGrant.Image.VolumeSerialHex -or $vendoredProtocBeforeStart.FileIdHex -cne [string]$VendoredProtocRunGrant.Image.FileIdHex) {
            throw 'VENDORED_PROTOC_GRANT_BLOCKED: opened protoc identity changed before fixed Cargo process creation'
        }
    }
    Ensure-D32NativeLauncher
    $stdoutPath = "$PhaseLog.stdout.log"
    $stderrPath = "$PhaseLog.stderr.log"
    $started = [DateTimeOffset]::UtcNow
    $commandLine = ConvertTo-D32CommandLine (@($FilePath) + $Arguments)
    $nativeProcess = $null
    $nativeCleanup = $null
    $processId = $null
    $rootIdentity = $null
    $capturedDescendantRecords = @()
    $residualDescendantRecords = @()
    $stdoutTarget = $null
    $stderrTarget = $null
    $stdoutStream = $null
    $stderrStream = $null
    $stdoutCopy = $null
    $stderrCopy = $null
    $initError = $null
    $treeError = $null
    $timedOut = $false
    $exitCode = $null
    $reap = $null
    $script:D32LastProcessEvidence = [ordered]@{
        root_record = $null
        descendant_records = @()
        process_trace = $null
        native_launch = $null
        native_cleanup = $null
        launch_request = [ordered]@{
            executable = [IO.Path]::GetFullPath($FilePath)
            arguments = @($Arguments)
            working_directory = [IO.Path]::GetFullPath($WorkingDirectory)
            phase_log = [IO.Path]::GetFullPath($PhaseLog)
            timeout_seconds = [int]$TimeoutSeconds
            child_environment_type = if ($null -eq $ChildEnvironment) { $null } else { $ChildEnvironment.GetType().FullName }
            require_debug_events = [bool]$RequireDebugEvents
        }
        started_at_utc = $started.ToString('o')
    }

    try {
        $nativeTestFailure = switch ($FailureInjection) {
            'api-failure' { 'assign'; break }
            'attribute-failure' { 'attribute'; break }
            default { $null; break }
        }
        $environmentBlock = if ($null -eq $ChildEnvironment) { $null } else { ConvertTo-D32EnvironmentBlock -Environment $ChildEnvironment }
        if ($RequireDebugEvents) {
            if ($FailureInjection -ne 'none') { throw 'DEBUG_PROCESS_TRACE_BLOCKED: failure injection is not permitted in an operational process trace' }
            $nativeProcess = Start-D32FixtureBoundedNativeProcess `
                -FilePath $FilePath `
                -CommandLine $commandLine `
                -WorkingDirectory $WorkingDirectory `
                -EnvironmentBlock $environmentBlock `
                -NativeTestFailure $nativeTestFailure `
                -RequireDebugEvents $true
        }
        else {
            $nativeProcess = Start-D32FixtureBoundedNativeProcess `
                -FilePath $FilePath `
                -CommandLine $commandLine `
                -WorkingDirectory $WorkingDirectory `
                -EnvironmentBlock $environmentBlock `
                -NativeTestFailure $nativeTestFailure `
                -RequireDebugEvents $false
        }
        $processId = [int]$nativeProcess.ProcessId
        $script:D32LastProcessEvidence.native_launch = [ordered]@{
            process_id = $processId
            job_assigned = [bool]$nativeProcess.JobAssigned
            launch_mode = [string]$nativeProcess.LaunchMode
            debug_process_required = [bool]$RequireDebugEvents
        }
        if ($FailureInjection -eq 'spawn-init') {
            throw 'SELFTEST_INJECTED_SPAWN_INIT_EXCEPTION'
        }

        if (-not $RequireDebugEvents) {
            for ($attempt = 0; $attempt -lt 5; $attempt++) {
                if ($FailureInjection -eq 'cim-init') { throw 'SELFTEST_INJECTED_CIM_INIT_EXCEPTION' }
                $rootCandidates = @(Get-D32ProcessSnapshot -ProcessId $processId)
                if ($rootCandidates.Count -eq 1) { $rootIdentity = $rootCandidates[0]; break }
                if ($nativeProcess.HasExited) { break }
                Start-Sleep -Milliseconds 50
            }
            if ($null -eq $rootIdentity) {
                $rootIdentity = New-D32FallbackProcessIdentity -ProcessId $processId -FilePath $FilePath -CommandLine $commandLine -ObservedAtUtc ([DateTimeOffset]::UtcNow.ToString('o'))
                if (-not $nativeProcess.HasExited) { throw "PROCESS_IDENTITY_UNVERIFIED: root pid $processId remained alive without a complete CIM identity" }
            }
            $script:D32LastProcessEvidence.root_record = $rootIdentity
        }

        $stdoutTarget = [IO.File]::Open(
            $stdoutPath,
            [IO.FileMode]::Create,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read)
        $stderrTarget = [IO.File]::Open(
            $stderrPath,
            [IO.FileMode]::Create,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read)
        $stdoutStream = $nativeProcess.OpenStdoutStream()
        if ($FailureInjection -eq 'pipe-init') {
            throw 'SELFTEST_INJECTED_PIPE_INIT_EXCEPTION'
        }
        $stderrStream = $nativeProcess.OpenStderrStream()
        if ($FailureInjection -eq 'pipe-timeout') {
            $neverCompletes = [System.Threading.Tasks.TaskCompletionSource[object]]::new()
            $stdoutCopy = $neverCompletes.Task
            $stderrCopy = $neverCompletes.Task
        }
        else {
            $stdoutCopy = $stdoutStream.CopyToAsync($stdoutTarget)
            $stderrCopy = $stderrStream.CopyToAsync($stderrTarget)
        }
    }
    catch {
        $initError = $_.Exception.Message
   }

   if ($null -ne $initError) {
        try {
            if ($null -ne $nativeProcess) {
                $nativeCleanup = $nativeProcess.CloseJobAndWait(10000)
                if (-not [bool]$nativeCleanup.CleanupSucceeded) {
                    $treeError = "PROCESS_GROUP_REAP_FAILED: $($nativeCleanup.Detail)"
                }
            }
        }
        catch {
            $treeError = "PROCESS_GROUP_REAP_FAILED: $($_.Exception.Message)"
        }
    }
    else {
        try {
            if ($RequireDebugEvents) {
                if ($null -eq $script:ValidatedToolchainProfile -or -not [bool]$script:ValidatedToolchainProfile.IsValid) { throw 'DEBUG_PROCESS_TRACE_BLOCKED: current caller-pinned profile is unavailable' }
                $profileCurrent = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $script:ValidatedToolchainProfile
                $rootImage = Get-D32ProfileFileSnapshot -Path $FilePath
                $rootPin = @($profileCurrent.ExecutableInventory | Where-Object { Test-D32ProfilePathEqual -Left $_.Path -Right $rootImage.Path })
                if ($rootPin.Count -ne 1 -or $rootPin[0].Sha256 -cne $rootImage.Sha256 -or $rootPin[0].Bytes -ne $rootImage.Bytes -or
                    $rootPin[0].VolumeSerialHex -cne $rootImage.VolumeSerialHex -or $rootPin[0].FileIdHex -cne $rootImage.FileIdHex) {
                    throw 'DEBUG_PROCESS_TRACE_BLOCKED: fixed root image is not an exact member of the current caller-pinned executable inventory'
                }
                $approvedImages = @($profileCurrent.ExecutableInventory) + @($profileCurrent.WindowsImageInventory)
                $approvedPinText = @($approvedImages | ForEach-Object { ConvertTo-D32DebugImagePinText -Image $_ })
                if ($null -ne $VendoredProtocRunGrant) {
                    $currentProtoc = Get-D32ProfileFileSnapshot -Path ([string]$VendoredProtocRunGrant.Image.Path)
                    if ($currentProtoc.Bytes -ne [Int64]$VendoredProtocRunGrant.Image.Bytes -or $currentProtoc.Sha256 -cne [string]$VendoredProtocRunGrant.Image.Sha256 -or
                        $currentProtoc.VolumeSerialHex -cne [string]$VendoredProtocRunGrant.Image.VolumeSerialHex -or $currentProtoc.FileIdHex -cne [string]$VendoredProtocRunGrant.Image.FileIdHex -or
                        $currentProtoc.Bytes -ne $vendoredProtocBeforeStart.Bytes -or $currentProtoc.Sha256 -cne $vendoredProtocBeforeStart.Sha256 -or
                        $currentProtoc.VolumeSerialHex -cne $vendoredProtocBeforeStart.VolumeSerialHex -or $currentProtoc.FileIdHex -cne $vendoredProtocBeforeStart.FileIdHex) {
                        throw 'VENDORED_PROTOC_GRANT_BLOCKED: image opened-handle identity changed before Cargo process creation'
                    }
                    $approvedPinText += ConvertTo-D32DebugImagePinText -Image $currentProtoc
                }
                $targetRoots = if ($CandidateImageRoots) { @($CandidateImageRoots | ForEach-Object { [IO.Path]::GetFullPath($_) }) } else { @(Get-D32DebugCandidateTargetRoots -Repository $profileCurrent.Repository) }
                $rootPinText = ConvertTo-D32DebugImagePinText -Image $rootImage
                $traceTimeout = [int][Math]::Min([int]::MaxValue, ([long]$TimeoutSeconds * 1000))
                if ($AllowPinnedCargoVctip) {
                    if (-not (Test-D32ProfilePathEqual -Left $rootImage.Path -Right ([string]$profileCurrent.Profile.toolchain.cargo.path))) {
                        throw 'D32_VCTIP_PROFILE_PIN_BLOCKED: VCTIP descendant authority is restricted to the exact caller-pinned Cargo root'
                    }
                    $null = Get-D32ProfileExactVctipImageRecord -ValidatedProfile $profileCurrent
                    if ($null -ne $VendoredProtocRunGrant) {
                        $protocPinText = ConvertTo-D32DebugImagePinText -Image $currentProtoc
                        $nativeProcess.ConfigurePinnedCargoDebugCaptureWithVendoredProtoc($rootPinText, [string[]]$approvedPinText, [string[]]$targetRoots, $traceTimeout,
                            [string]$VendoredProtocRunGrant.Document.cargo_home.path, $protocPinText)
                    }
                    else {
                        $nativeProcess.ConfigurePinnedCargoDebugCapture($rootPinText, [string[]]$approvedPinText, [string[]]$targetRoots, $traceTimeout)
                    }
                }
                else {
                    $nativeProcess.ConfigureDebugCapture($rootPinText, [string[]]$approvedPinText, [string[]]$targetRoots, $traceTimeout, $false, $false)
                }
                $debugJoinTimeout = [int][Math]::Min([int]::MaxValue, ([long]$TimeoutSeconds * 1000 + 20000))
                $traceNative = $nativeProcess.WaitForDebugTrace($debugJoinTimeout)
                $traceDocument = ConvertTo-D32DebugProcessTraceDocument -Trace $traceNative
                $script:D32LastProcessEvidence.process_trace = $traceDocument
                if ($traceNative.Processes.Count -gt 0) {
                    $rootIdentity = ConvertFrom-D32DebugProcessRecord -Process $traceNative.Processes[0] -CommandLine $commandLine
                    $capturedDescendantRecords = @($traceNative.Processes | Select-Object -Skip 1 | ForEach-Object { ConvertFrom-D32DebugProcessRecord -Process $_ })
                }
                $script:D32LastProcessEvidence.root_record = $rootIdentity
                $script:D32LastProcessEvidence.descendant_records = $capturedDescendantRecords
                if ($traceNative.State -cne 'COMPLETED' -or -not $traceNative.AccountingConsistent -or -not $traceNative.EventChainComplete) {
                    $treeError = "DEBUG_PROCESS_TRACE_BLOCKED: $($traceNative.BlockReason)"
                }
                if ($nativeProcess.HasExited) { $exitCode = [int]$nativeProcess.ExitCode }
                else { $treeError = 'DEBUG_PROCESS_TRACE_BLOCKED: root process handle remained active after event closure' }
                $nativeCleanup = $nativeProcess.CloseJobAndWait(15000)
                if (-not $nativeCleanup.CleanupSucceeded -or [uint32]$nativeCleanup.JobActiveProcessCount -ne 0) {
                    $treeError = if ($null -eq $treeError) { "DEBUG_PROCESS_TRACE_BLOCKED: $($nativeCleanup.Detail)" } else { "$treeError; $($nativeCleanup.Detail)" }
                }
                $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $profileCurrent
            }
            else {
            $deadline = $started.AddSeconds($TimeoutSeconds)
            while (-not $nativeProcess.HasExited) {
                try {
                    $capturedDescendantRecords = @(Merge-D32ProcessIdentityRecords `
                        -Existing $capturedDescendantRecords `
                        -Incoming (Get-D32DescendantProcessRecords -RootPid $processId))
                    $script:D32LastProcessEvidence.descendant_records = $capturedDescendantRecords
                }
                catch {
                    $treeError = $_.Exception.Message
                    break
                }
                if ([DateTimeOffset]::UtcNow -ge $deadline) {
                    $timedOut = $true
                    break
                }
                Start-Sleep -Milliseconds 250
            }

            $graceSamples = if ($timedOut) { 1 } else { 4 }
            for ($sample = 0; $sample -lt $graceSamples; $sample++) {
                try {
                    $capturedDescendantRecords = @(Merge-D32ProcessIdentityRecords `
                        -Existing $capturedDescendantRecords `
                        -Incoming (Get-D32DescendantProcessRecords -RootPid $processId))
                    $script:D32LastProcessEvidence.descendant_records = $capturedDescendantRecords
                }
                catch {
                    if ($null -eq $treeError) { $treeError = $_.Exception.Message }
                    break
                }
                if ($sample -lt ($graceSamples - 1)) { Start-Sleep -Milliseconds 100 }
            }

            if (-not $timedOut) {
                if (-not $nativeProcess.WaitForExit(1000)) {
                    if ($null -eq $treeError) {
                        $treeError = "PROCESS_EXIT_WAIT_FAILED: root pid $processId did not signal after observed exit"
                    }
                }
                else {
                    $exitCode = [int]$nativeProcess.ExitCode
                }
            }

            if ($timedOut -or $capturedDescendantRecords.Count -gt 0 -or $null -ne $treeError) {
                try {
                    $reap = Stop-D32ProcessTreeAndVerify `
                        -RootRecord $rootIdentity `
                        -CapturedDescendantRecords $capturedDescendantRecords `
                        -NativeProcess $nativeProcess
                    $nativeCleanup = $reap.NativeCleanup
                    $residualDescendantRecords = @($reap.ResidualRecords | Where-Object { [int]$_.ProcessId -ne [int]$rootIdentity.ProcessId })
                }
                catch {
                    if ($null -eq $treeError) { $treeError = $_.Exception.Message }
                    else { $treeError = "$treeError; $($_.Exception.Message)" }
                }
            }
            }
        }
        catch {
            $treeError = if ($null -eq $treeError) { $_.Exception.Message } else { "$treeError; $($_.Exception.Message)" }
        }
    }

    try {
        if ($null -ne $nativeProcess -and $null -eq $nativeCleanup) {
            $nativeCleanup = $nativeProcess.CloseJobAndWait(10000)
        }
        if ($null -ne $nativeCleanup -and -not [bool]$nativeCleanup.CleanupSucceeded -and $null -eq $treeError) {
            $treeError = "PROCESS_GROUP_REAP_FAILED: $($nativeCleanup.Detail)"
        }
    }
    catch {
        if ($null -eq $treeError) { $treeError = "PROCESS_GROUP_REAP_FAILED: $($_.Exception.Message)" }
        else { $treeError = "$treeError; PROCESS_GROUP_REAP_FAILED: $($_.Exception.Message)" }
    }
    finally {
        try {
            if ($null -ne $stdoutCopy) {
                if (-not $stdoutCopy.Wait(1000)) {
                    $pipeTimeoutError = 'PIPE_DRAIN_TIMEOUT: stdout copy did not complete within 1000ms'
                    $treeError = if ($null -eq $treeError) { $pipeTimeoutError } else { "$treeError; $pipeTimeoutError" }
                }
                elseif ($stdoutCopy.IsFaulted) {
                    throw "PIPE_DRAIN_FAILED: stdout copy task faulted: $($stdoutCopy.Exception.InnerException.Message)"
                }
                elseif ($stdoutCopy.IsCanceled) {
                    throw 'PIPE_DRAIN_FAILED: stdout copy task was canceled'
                }
            }
            if ($null -ne $stderrCopy) {
                if (-not $stderrCopy.Wait(1000)) {
                    $pipeTimeoutError = 'PIPE_DRAIN_TIMEOUT: stderr copy did not complete within 1000ms'
                    $treeError = if ($null -eq $treeError) { $pipeTimeoutError } else { "$treeError; $pipeTimeoutError" }
                }
                elseif ($stderrCopy.IsFaulted) {
                    throw "PIPE_DRAIN_FAILED: stderr copy task faulted: $($stderrCopy.Exception.InnerException.Message)"
                }
                elseif ($stderrCopy.IsCanceled) {
                    throw 'PIPE_DRAIN_FAILED: stderr copy task was canceled'
                }
            }
        }
        catch {
            if ($null -eq $treeError) { $treeError = "PIPE_DRAIN_FAILED: $($_.Exception.Message)" }
            else { $treeError = "$treeError; PIPE_DRAIN_FAILED: $($_.Exception.Message)" }
        }
        foreach ($stream in @($stdoutStream, $stderrStream, $stdoutTarget, $stderrTarget)) {
            if ($null -ne $stream) {
                try { $stream.Dispose() } catch {
                    if ($null -eq $treeError) { $treeError = "PIPE_CLOSE_FAILED: $($_.Exception.Message)" }
                    else { $treeError = "$treeError; PIPE_CLOSE_FAILED: $($_.Exception.Message)" }
                }
            }
        }
        if ($null -ne $nativeProcess) {
            try { $nativeProcess.Dispose() } catch {
                if ($null -eq $treeError) { $treeError = "NATIVE_HANDLE_CLOSE_FAILED: $($_.Exception.Message)" }
                else { $treeError = "$treeError; NATIVE_HANDLE_CLOSE_FAILED: $($_.Exception.Message)" }
            }
        }
    }

    $script:D32LastProcessEvidence.native_cleanup = ConvertTo-D32NativeCleanupDocument $nativeCleanup
    $residualDescendantPids = @($residualDescendantRecords | ForEach-Object { [int]$_.ProcessId } | Select-Object -Unique)
    $finished = [DateTimeOffset]::UtcNow
    return [ordered]@{
        status = if ($null -ne $treeError) { 'process_tree_error' } elseif ($null -ne $initError) { 'spawn_failed' } elseif ($timedOut) { 'timeout' } elseif ($exitCode -eq 0) { 'succeeded' } else { 'failed' }
        exit_code = $exitCode
        pid = $processId
        elapsed_ms = ($finished - $started).TotalMilliseconds
        phase_log = (Get-D32FullPath $PhaseLog)
        stdout_log = (Get-D32FullPath $stdoutPath)
        stderr_log = (Get-D32FullPath $stderrPath)
        root_identity = ConvertTo-D32IdentityDocument $rootIdentity
        root_identity_record = $rootIdentity
        captured_descendant_records = @($capturedDescendantRecords)
        descendant_pids = @($residualDescendantPids)
        descendant_identities = @($capturedDescendantRecords | ForEach-Object { ConvertTo-D32IdentityDocument $_ })
        residual_descendant_identities = @($residualDescendantRecords | ForEach-Object { ConvertTo-D32IdentityDocument $_ })
        native_launch = $script:D32LastProcessEvidence.native_launch
        native_cleanup = ConvertTo-D32NativeCleanupDocument $nativeCleanup
        process_trace = $script:D32LastProcessEvidence.process_trace
        raw_debug_job_evidence = $script:D32LastProcessEvidence
        reap = if ($null -eq $reap) { $null } else {
            [ordered]@{
                process_ids = @($reap.ProcessIds)
                verified_at_utc = $reap.VerifiedAtUtc
                residual_identities = @($reap.ResidualRecords | ForEach-Object { ConvertTo-D32IdentityDocument $_ })
                native_cleanup = ConvertTo-D32NativeCleanupDocument $reap.NativeCleanup
                kill_output = @($reap.KillOutput)
            }
        }
        error = if ($null -ne $treeError) { $treeError } elseif ($null -ne $initError) { $initError } elseif ($timedOut) { 'bounded timeout; process group was killed and every captured identity was reaped' } else { $null }
    }
}

function Get-D32Artifact {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Get-D32FullPath $Path
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "FIXTURE_MISSING: expected fixture output was not produced: $full"
    }
    $bound = Get-D32BoundArtifact -Path $full
    return [ordered]@{
        path   = $bound.path
        bytes  = [uint64]$bound.bytes
        sha256 = $bound.sha256
    }
}

function Write-D32Manifest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Document
    )

    $temporary = Join-Path (Split-Path -Parent $Path) ('.fixture-manifest.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $json = $Document | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($temporary, $json, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Assert-D32FixtureManifestEnvironmentShape {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.IDictionary]$Environment)

    $required = @('original_userprofile', 'codex_home', 'userprofile', 'cargo_home', 'rustup_home', 'rustup_toolchain')
    $actual = @($Environment.Keys | ForEach-Object { [string]$_ })
    if ($actual.Count -ne $required.Count -or
        @($actual | Where-Object { $_ -notin $required }).Count -ne 0 -or
        @($required | Where-Object { $_ -notin $actual }).Count -ne 0) {
        throw 'FIXTURE_MANIFEST_ENVIRONMENT_INVALID: schema-v3 environment must retain exactly the six consumer wire fields'
    }
}

function Test-D32FixtureExactProperties {
    param([AllowNull()][object]$Object, [Parameter(Mandatory = $true)][string[]]$Expected)

    if ($null -eq $Object -or $Object -is [string] -or $Object -is [Array] -or $Object -is [ValueType]) { return $false }
    $actual = @(Get-D32ObjectFieldNames -Object $Object)
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) { if ($actual -cnotcontains $name) { return $false } }
    return $true
}

function Test-D32FixturePhase0OwnerBinding {
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][object]$OwnerBinding
    )

    if (-not (Test-D32FixtureExactProperties -Object $OwnerBinding -Expected @('Path', 'RunId', 'RootIdentity', 'OwnerMarker')) -or
        -not (Test-D32PathEqual -Left ([string]$OwnerBinding.Path) -Right $OutputRoot) -or
        [string]$OwnerBinding.RunId -cnotmatch '^[0-9a-f]{32}$') { throw 'PHASE0_OWNER_BLOCKED: Phase0 runner did not supply an exact fresh owner binding' }
    $rootIdentityRecord = $OwnerBinding.RootIdentity
    if (-not (Test-D32FixtureExactProperties -Object $rootIdentityRecord -Expected @('Path', 'VolumeSerialHex', 'FileIdHex', 'Attributes'))) { throw 'PHASE0_OWNER_BLOCKED: EvidenceRoot opened-handle identity record is malformed' }
    $rootIdentity = Get-D32ProfileDirectoryIdentity -Path $OutputRoot
    if (-not (Test-D32PathEqual -Left ([string]$rootIdentityRecord.Path) -Right $OutputRoot) -or
        $rootIdentity.VolumeSerialHex -cne [string]$rootIdentityRecord.VolumeSerialHex -or $rootIdentity.FileIdHex -cne [string]$rootIdentityRecord.FileIdHex) {
        throw 'PHASE0_OWNER_BLOCKED: EvidenceRoot opened-handle identity changed before fixture setup'
    }
    $markerReference = $OwnerBinding.OwnerMarker
    if (-not (Test-D32FixtureExactProperties -Object $markerReference -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) { throw 'PHASE0_OWNER_BLOCKED: owner marker file reference is malformed' }
    $expectedMarkerPath = Join-Path $OutputRoot 'D32-PHASE0-OWNER.json'
    if (-not (Test-D32PathEqual -Left ([string]$markerReference.path) -Right $expectedMarkerPath)) { throw 'PHASE0_OWNER_BLOCKED: owner marker path is not fixed beneath EvidenceRoot' }
    $marker = Get-D32BoundArtifactWithFileId -Path $expectedMarkerPath
    if ([uint64]$marker.bytes -ne [uint64]$markerReference.bytes -or $marker.sha256 -cne [string]$markerReference.sha256 -or
        $marker.volume_serial_hex -cne [string]$markerReference.volume_serial_hex -or $marker.file_id_hex -cne [string]$markerReference.file_id_hex) {
        throw 'PHASE0_OWNER_BLOCKED: create-new owner marker bytes or opened-handle identity changed'
    }
    $null = Assert-D32NoReparsePath -Path $expectedMarkerPath
    if ([IO.File]::ReadAllText($expectedMarkerPath, [Text.Encoding]::UTF8) -notmatch '"record_type"\s*:\s*"D32_PHASE0_EVIDENCE_OWNER_V1"') {
        throw 'PHASE0_OWNER_BLOCKED: owner marker is missing, reparse-backed, or has an unsupported type'
    }
    $ownerDocument = [IO.File]::ReadAllText($expectedMarkerPath, [Text.Encoding]::UTF8) | ConvertFrom-Json -AsHashtable
    $ownerFields = @('schema_version', 'record_type', 'candidate_sha', 'toolchain_profile_path', 'toolchain_profile_sha256', 'toolchain_profile_bytes', 'toolchain_profile_volume_serial_hex', 'toolchain_profile_file_id_hex', 'evidence_root_path', 'evidence_root_volume_serial_hex', 'evidence_root_file_id_hex', 'run_id')
    $ownerActualFields = @(Get-D32ObjectFieldNames -Object $ownerDocument)
    if ($ownerActualFields.Count -ne $ownerFields.Count -or @($ownerActualFields | Where-Object { $_ -notin $ownerFields }).Count -ne 0 -or @($ownerFields | Where-Object { $_ -notin $ownerActualFields }).Count -ne 0 -or
        [int]$ownerDocument.schema_version -ne 1 -or $ownerDocument.record_type -cne 'D32_PHASE0_EVIDENCE_OWNER_V1' -or
        $ownerDocument.candidate_sha -cne $ExpectedCandidateSha -or
        -not (Test-D32PathEqual -Left ([string]$ownerDocument.toolchain_profile_path) -Right ([string]$ValidatedProfile.ProfilePath)) -or
        $ownerDocument.toolchain_profile_sha256 -cne [string]$ValidatedProfile.Digest -or
        [Int64]$ownerDocument.toolchain_profile_bytes -ne [Int64]$ValidatedProfile.Identity.Bytes -or
        $ownerDocument.toolchain_profile_volume_serial_hex -cne [string]$ValidatedProfile.Identity.VolumeSerialHex -or
        $ownerDocument.toolchain_profile_file_id_hex -cne [string]$ValidatedProfile.Identity.FileIdHex -or
        -not (Test-D32PathEqual -Left ([string]$ownerDocument.evidence_root_path) -Right $OutputRoot) -or
        $ownerDocument.evidence_root_volume_serial_hex -cne $rootIdentity.VolumeSerialHex -or
        $ownerDocument.evidence_root_file_id_hex -cne $rootIdentity.FileIdHex -or
        $ownerDocument.run_id -cne [string]$OwnerBinding.RunId) {
        throw 'PHASE0_OWNER_BLOCKED: marker content does not bind the exact candidate/profile/root/run identity'
    }
    $profileSnapshot = Get-D32ProfileFileSnapshot -Path ([string]$ValidatedProfile.ProfilePath)
    if ($profileSnapshot.Sha256 -cne [string]$ValidatedProfile.Digest -or $profileSnapshot.Bytes -ne [Int64]$ValidatedProfile.Identity.Bytes -or
        $profileSnapshot.VolumeSerialHex -cne [string]$ValidatedProfile.Identity.VolumeSerialHex -or $profileSnapshot.FileIdHex -cne [string]$ValidatedProfile.Identity.FileIdHex) {
        throw 'PHASE0_OWNER_BLOCKED: profile path/hash/opened-handle identity changed before fixture setup'
    }
    return [PSCustomObject]@{
        RunId = [string]$OwnerBinding.RunId
        EvidenceRoot = $OutputRoot
        EvidenceRootIdentity = $rootIdentity
        OwnerMarker = [ordered]@{
            path = [string]$marker.path
            bytes = [uint64]$marker.bytes
            sha256 = [string]$marker.sha256
            volume_serial_hex = [string]$marker.volume_serial_hex
            file_id_hex = [string]$marker.file_id_hex
        }
    }
}

function Initialize-D32FixturePhase0Storage {
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][object]$OwnerBinding
    )

    $ownerContext = Test-D32FixturePhase0OwnerBinding `
        -OutputRoot $OutputRoot `
        -ExpectedCandidateSha $ExpectedCandidateSha `
        -ValidatedProfile $ValidatedProfile `
        -OwnerBinding $OwnerBinding
    $runRoot = Join-Path $OutputRoot 'r'
    $runRootIdentity = New-D32ProfileDirectoryCreateNew -Path $runRoot
    $cargoHome = Join-Path $runRoot 'c'
    $cargoHomeIdentity = New-D32ProfileDirectoryCreateNew -Path $cargoHome
    $null = Test-D32CargoHome -Path $cargoHome -Repository $Repository -RequireEmpty
    $tempRoot = Join-Path $runRoot 't'
    $tempRootIdentity = New-D32ProfileDirectoryCreateNew -Path $tempRoot

    $null = Test-D32ProfileDirectoryIdentity `
        -Path $OutputRoot `
        -VolumeSerialHex $ownerContext.EvidenceRootIdentity.VolumeSerialHex `
        -FileIdHex $ownerContext.EvidenceRootIdentity.FileIdHex
    $null = Test-D32ProfileDirectoryIdentity -Path $runRoot -VolumeSerialHex $runRootIdentity.VolumeSerialHex -FileIdHex $runRootIdentity.FileIdHex
    $null = Test-D32ProfileDirectoryIdentity -Path $cargoHome -VolumeSerialHex $cargoHomeIdentity.VolumeSerialHex -FileIdHex $cargoHomeIdentity.FileIdHex
    $null = Test-D32ProfileDirectoryIdentity -Path $tempRoot -VolumeSerialHex $tempRootIdentity.VolumeSerialHex -FileIdHex $tempRootIdentity.FileIdHex

    $storageContext = [ordered]@{
        evidence_root = [ordered]@{
            path = [string]$ownerContext.EvidenceRootIdentity.Path
            volume_serial_hex = [string]$ownerContext.EvidenceRootIdentity.VolumeSerialHex
            file_id_hex = [string]$ownerContext.EvidenceRootIdentity.FileIdHex
        }
        owner_marker = $ownerContext.OwnerMarker
        run_root = [ordered]@{ path = [string]$runRootIdentity.Path; volume_serial_hex = [string]$runRootIdentity.VolumeSerialHex; file_id_hex = [string]$runRootIdentity.FileIdHex }
        cargo_home = [ordered]@{ path = [string]$cargoHomeIdentity.Path; volume_serial_hex = [string]$cargoHomeIdentity.VolumeSerialHex; file_id_hex = [string]$cargoHomeIdentity.FileIdHex }
        temp_root = [ordered]@{ path = [string]$tempRootIdentity.Path; volume_serial_hex = [string]$tempRootIdentity.VolumeSerialHex; file_id_hex = [string]$tempRootIdentity.FileIdHex }
        run_id = [string]$ownerContext.RunId
    }
    return [PSCustomObject]@{
        OwnerContext = $ownerContext
        RunRoot = [string]$runRootIdentity.Path
        CargoHome = [string]$cargoHomeIdentity.Path
        TempRoot = [string]$tempRootIdentity.Path
        StorageContext = $storageContext
    }
}

function Invoke-D32FixturePreCargoBoundary {
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][object]$OwnerBinding,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$StorageContext,
        [Parameter(Mandatory = $true)][scriptblock]$FetchAction
    )

    $ownerContext = Test-D32FixturePhase0OwnerBinding `
        -OutputRoot $OutputRoot `
        -ExpectedCandidateSha $ExpectedCandidateSha `
        -ValidatedProfile $ValidatedProfile `
        -OwnerBinding $OwnerBinding
    $expectedStorageFields = @('evidence_root', 'owner_marker', 'run_root', 'cargo_home', 'temp_root', 'run_id')
    $actualStorageFields = @($StorageContext.Keys | ForEach-Object { [string]$_ })
    if ($actualStorageFields.Count -ne $expectedStorageFields.Count -or
        @($actualStorageFields | Where-Object { $_ -cnotin $expectedStorageFields }).Count -ne 0 -or
        @($expectedStorageFields | Where-Object { $_ -cnotin $actualStorageFields }).Count -ne 0) {
        throw 'PHASE0_STORAGE_BLOCKED: pre-Cargo storage context has missing or extra fields'
    }
    if (-not (Test-D32FixtureExactProperties -Object $StorageContext.evidence_root -Expected @('path', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32FixtureExactProperties -Object $StorageContext.owner_marker -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32PathEqual -Left ([string]$StorageContext.evidence_root.path) -Right $OutputRoot) -or
        $StorageContext.evidence_root.volume_serial_hex -cne [string]$ownerContext.EvidenceRootIdentity.VolumeSerialHex -or
        $StorageContext.evidence_root.file_id_hex -cne [string]$ownerContext.EvidenceRootIdentity.FileIdHex -or
        $StorageContext.run_id -cne [string]$ownerContext.RunId -or
        -not (Test-D32PathEqual -Left ([string]$StorageContext.owner_marker.path) -Right ([string]$ownerContext.OwnerMarker.path)) -or
        $StorageContext.owner_marker.sha256 -cne [string]$ownerContext.OwnerMarker.sha256 -or
        $StorageContext.owner_marker.bytes -ne [Int64]$ownerContext.OwnerMarker.bytes -or
        $StorageContext.owner_marker.volume_serial_hex -cne [string]$ownerContext.OwnerMarker.volume_serial_hex -or
        $StorageContext.owner_marker.file_id_hex -cne [string]$ownerContext.OwnerMarker.file_id_hex) {
        throw 'PHASE0_STORAGE_BLOCKED: pre-Cargo root/owner/run binding changed'
    }

    $expectedDirectories = @(
        [PSCustomObject]@{ Name = 'run_root'; Path = (Join-Path $OutputRoot 'r') },
        [PSCustomObject]@{ Name = 'cargo_home'; Path = (Join-Path (Join-Path $OutputRoot 'r') 'c') },
        [PSCustomObject]@{ Name = 'temp_root'; Path = (Join-Path (Join-Path $OutputRoot 'r') 't') }
    )
    foreach ($directory in $expectedDirectories) {
        $record = $StorageContext.($directory.Name)
        if (-not (Test-D32FixtureExactProperties -Object $record -Expected @('path', 'volume_serial_hex', 'file_id_hex')) -or
            -not (Test-D32PathEqual -Left ([string]$record.path) -Right $directory.Path)) {
            throw "PHASE0_STORAGE_BLOCKED: pre-Cargo $($directory.Name) path/identity record is malformed"
        }
        $null = Test-D32ProfileDirectoryIdentity -Path $directory.Path -VolumeSerialHex ([string]$record.volume_serial_hex) -FileIdHex ([string]$record.file_id_hex)
    }
    $null = Test-D32CargoHome -Path ([string]$StorageContext.cargo_home.path) -Repository $Repository -RequireEmpty
    return & $FetchAction
}

function Write-D32NewFixtureBuildProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Document
    )

    $full = Assert-D32NoReparsePath -Path $Path -AllowMissingLeaf
    if (Test-Path -LiteralPath $full) {
        throw "OUTPUT_NOT_OWNED: refusing to overwrite fixture build provenance: $full"
    }
    $parent = Split-Path -Parent $full
    [void](Assert-D32NoReparsePath -Path $parent)
    $temporary = Join-Path $parent ('.fixture-build-provenance.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $json = $Document | ConvertTo-Json -Depth 12
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    try { [IO.File]::Move($temporary, $full) }
    catch {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
        throw
    }
    return Get-D32BoundArtifact -Path $full
}

function Assert-D32FixtureDebugTraceShape {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Traces)

    $expectedNames = @('fixture-01-fetch', 'fixture-02-fetch', 'fixture-03-fetch',
        'd29h1-authority-fixture', 'd29h7-authority-fixture', 'd29h7-process-fixture', 'd29h7-git-helper-fixture', 'd32a-sandbox-fixture')
    if ($Traces -isnot [Array] -or $Traces.Count -ne $expectedNames.Count) { throw 'FIXTURE_PROVENANCE_INVALID: process trace inventory must contain exactly three locked fetches and five fixture Cargo roots' }
    $traceFields = @('record_type', 'schema_version', 'event_source', 'state', 'block_reason', 'debugger_process_id', 'uncontinued_create_process_id', 'uncontinued_create_continue_call_count', 'debugger_thread_id',
        'dedicated_debugger_thread', 'debugger_kill_on_exit_enabled', 'root_resumed_after_kill_on_exit', 'debugger_thread_exited', 'debugger_thread_joined',
        'retained_process_handle_count', 'retained_process_handles_signaled', 'debugger_association_query_verified', 'debugger_association_absent', 'debugger_creation_filetime',
        'debugger_created_at_utc', 'started_at_utc', 'completed_at_utc', 'debug_event_count', 'process_create_event_count', 'process_exit_event_count',
        'process_event_count', 'thread_create_event_count', 'thread_exit_event_count', 'image_load_event_count', 'image_unload_event_count',
        'exception_event_count', 'debug_string_event_count', 'wait_timeout_count', 'debug_api_error_count', 'event_chain_complete',
        'job_accounting_verified', 'job_total_processes', 'job_active_processes', 'accounting_consistent', 'injected_interruption', 'process_events', 'processes')
    $wrapperFields = @('name', 'executable', 'arguments', 'command_line', 'working_directory', 'process_trace')
    for ($i = 0; $i -lt $expectedNames.Count; $i++) {
        $entry = $Traces[$i]
        $actualFields = @(Get-D32ObjectFieldNames -Object $entry)
        if ($actualFields.Count -ne $wrapperFields.Count -or @($actualFields | Where-Object { $_ -notin $wrapperFields }).Count -ne 0 -or @($wrapperFields | Where-Object { $_ -notin $actualFields }).Count -ne 0 -or
            $entry.name -isnot [string] -or $entry.name -cne $expectedNames[$i] -or $entry.executable -isnot [string] -or -not [IO.Path]::IsPathRooted([string]$entry.executable) -or
            $entry.arguments -isnot [Array] -or @($entry.arguments | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
            $entry.command_line -isnot [string] -or $entry.working_directory -isnot [string]) {
            throw "FIXTURE_PROVENANCE_INVALID: process trace wrapper schema/name is invalid at index $i"
        }
        if ($entry.command_line -cne (ConvertTo-D32CommandLine (@([string]$entry.executable) + @($entry.arguments)))) { throw "FIXTURE_PROVENANCE_INVALID: trace root command line does not match argv at index $i" }
        $trace = $entry.process_trace
        $traceActualFields = @(Get-D32ObjectFieldNames -Object $trace)
        if ($traceActualFields.Count -ne $traceFields.Count -or @($traceActualFields | Where-Object { $_ -notin $traceFields }).Count -ne 0 -or @($traceFields | Where-Object { $_ -notin $traceActualFields }).Count -ne 0 -or
            $trace.record_type -cne 'D32_DEBUG_JOB_PROCESS_TRACE_V2' -or [int]$trace.schema_version -ne 2 -or
            $trace.event_source -cne 'Win32-WaitForDebugEvent-dedicated-OS-thread' -or $trace.state -cne 'COMPLETED' -or $null -ne $trace.block_reason -or
            [int]$trace.debugger_thread_id -le 0 -or -not [bool]$trace.dedicated_debugger_thread -or
            [uint32]$trace.uncontinued_create_process_id -ne 0 -or [int]$trace.uncontinued_create_continue_call_count -ne 0 -or
            -not [bool]$trace.debugger_kill_on_exit_enabled -or -not [bool]$trace.root_resumed_after_kill_on_exit -or
            -not [bool]$trace.debugger_thread_exited -or -not [bool]$trace.debugger_thread_joined -or
            [int]$trace.retained_process_handle_count -lt ([int]$trace.process_create_event_count + 1) -or
            -not [bool]$trace.retained_process_handles_signaled -or -not [bool]$trace.debugger_association_query_verified -or -not [bool]$trace.debugger_association_absent -or
            [int]$trace.debug_api_error_count -ne 0 -or -not [bool]$trace.event_chain_complete -or -not [bool]$trace.job_accounting_verified -or
            -not [bool]$trace.accounting_consistent -or [bool]$trace.injected_interruption -or
            [int]$trace.process_create_event_count -le 0 -or [int]$trace.process_exit_event_count -ne [int]$trace.process_create_event_count -or
            [int]$trace.job_total_processes -ne [int]$trace.process_create_event_count -or [int]$trace.job_active_processes -ne 0 -or
            $trace.process_events -isnot [Array] -or $trace.processes -isnot [Array] -or
            $trace.process_events.Count -ne [int]$trace.process_event_count -or $trace.processes.Count -ne [int]$trace.process_create_event_count -or
            $trace.processes.Count -eq 0 -or -not (Test-D32ProfilePathEqual -Left $trace.processes[0].image_path -Right $entry.executable)) {
            throw "FIXTURE_PROVENANCE_INVALID: synchronized debug process trace is malformed or incomplete at index $i"
        }
    }
}

function Assert-D32FixtureBuildProvenanceShape {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.IDictionary]$Document)

    $expected = @('schema_version', 'record_type', 'candidate_sha', 'source_repo', 'fixture_manifest_path',
        'fixture_manifest_sha256', 'fixture_manifest_bytes', 'fixture_manifest_volume_serial_hex',
        'fixture_manifest_file_id_hex', 'environment', 'storage', 'process_traces', 'fixture_build_budget', 'vendored_protoc_run_grant', 'tauri_macros_source_patch', 'powershell_module_admission')
    $actual = @($Document.Keys | ForEach-Object { [string]$_ })
    if ($actual.Count -ne $expected.Count -or
        @($actual | Where-Object { $_ -notin $expected }).Count -ne 0 -or
        @($expected | Where-Object { $_ -notin $actual }).Count -ne 0 -or
        [int]$Document.schema_version -ne 7 -or $Document.record_type -cne 'D32_FIXTURE_BUILD_PROVENANCE_V7' -or
        [string]$Document.candidate_sha -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Document.fixture_manifest_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [uint64]$Document.fixture_manifest_bytes -le 0 -or
        [string]$Document.fixture_manifest_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        [string]$Document.fixture_manifest_file_id_hex -cnotmatch '^[0-9a-f]{32}$') {
        throw 'FIXTURE_PROVENANCE_INVALID: sidecar schema, version, manifest hash, bytes, or identity is invalid'
    }
    if (-not (Test-D32PowerShellModuleAdmissionProducerBinding -Document $Document.powershell_module_admission -CandidateSha ([string]$Document.candidate_sha) `
            -Repository ([string]$Document.source_repo) -ProducerRole fixture_provenance `
            -ExpectedAdmissionContext $global:D32PowerShellModuleAuthorityState.Admission -ExpectedProducerContext $global:D32PowerShellModuleAuthorityState.Admission) -or
        -not (Test-D32ProfilePathEqual -Left ([string]$Document.powershell_module_admission.profile_reference.path) -Right ([string]$Document.environment.toolchain_profile_path)) -or
        $Document.powershell_module_admission.profile_reference.sha256 -cne [string]$Document.environment.toolchain_profile_sha256) {
        throw 'FIXTURE_PROVENANCE_INVALID: fixture provenance must embed a strict current D32 PowerShell module admission'
    }
    Assert-D32FixtureBuildBudgetRecord -Document $Document.fixture_build_budget -ExpectedPhase0TimeoutSeconds 14400
    $grant = $Document.vendored_protoc_run_grant
    if (-not (Test-D32VendoredObjectExactProperties -Object $grant -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        $grant.path -isnot [string] -or -not (Test-D32ProfileCanonicalPathString -Path $grant.path) -or
        [IO.Path]::GetFileName([string]$grant.path) -cne 'D32-PHASE0-VENDORED-PROTOC-RUN-GRANT.json' -or
        $grant.bytes -isnot [int64] -or $grant.bytes -le 0 -or $grant.sha256 -isnot [string] -or $grant.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $grant.volume_serial_hex -isnot [string] -or $grant.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        $grant.file_id_hex -isnot [string] -or $grant.file_id_hex -cnotmatch '^[0-9a-f]{32}$') {
        throw 'FIXTURE_PROVENANCE_INVALID: strict per-run vendored-protoc grant reference is malformed'
    }
    $sourcePatch = $Document.tauri_macros_source_patch
    if (-not (Test-D32VendoredObjectExactProperties -Object $sourcePatch -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        $sourcePatch.path -isnot [string] -or -not (Test-D32ProfileCanonicalPathString -Path $sourcePatch.path) -or
        [IO.Path]::GetFileName([string]$sourcePatch.path) -cne 'D32-TAURI-MACROS-SOURCE-PATCH-AUTHORITY.json' -or
        $sourcePatch.bytes -isnot [int64] -or $sourcePatch.bytes -le 0 -or $sourcePatch.sha256 -isnot [string] -or $sourcePatch.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $sourcePatch.volume_serial_hex -isnot [string] -or $sourcePatch.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        $sourcePatch.file_id_hex -isnot [string] -or $sourcePatch.file_id_hex -cnotmatch '^[0-9a-f]{32}$') {
        throw 'FIXTURE_PROVENANCE_INVALID: strict candidate/Profile-bound source-patch authority reference is malformed'
    }
    Assert-D32FixtureDebugTraceShape -Traces $Document.process_traces
    $environmentFields = @('toolchain_profile_path', 'toolchain_profile_sha256', 'target_triple', 'env_policy',
        'cargo_policy', 'cargo_home', 'temp_root', 'run_id', 'fetch_manifests', 'offline_after_fetch')
    $environmentKeys = @($Document.environment.Keys | ForEach-Object { [string]$_ })
    if ($environmentKeys.Count -ne $environmentFields.Count -or
        @($environmentKeys | Where-Object { $_ -notin $environmentFields }).Count -ne 0 -or
        @($environmentFields | Where-Object { $_ -notin $environmentKeys }).Count -ne 0 -or
        [string]$Document.environment.toolchain_profile_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Document.environment.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        $Document.environment.fetch_manifests -isnot [Array] -or
        $Document.environment.fetch_manifests.Count -eq 0 -or
        -not [bool]$Document.environment.offline_after_fetch) {
        throw 'FIXTURE_PROVENANCE_INVALID: sidecar environment must match the exact ten-field versioned provenance shape'
    }
    if ($Document.environment.fetch_manifests.Count -ne 3) {
        throw 'FIXTURE_PROVENANCE_INVALID: exact three locked fetches are required before the five fixed fixture builds'
    }
    for ($i = 0; $i -lt $script:FixtureSpecs.Count; $i++) {
        $spec = $script:FixtureSpecs[$i]
        $manifest = [IO.Path]::GetFullPath((Join-Path ([string]$Document.source_repo) ([string]$spec.manifest)))
        $expectedArguments = @('build', '--quiet', '--locked', '--manifest-path', $manifest, '--bin', [string]$spec.binary)
        if ($spec.features.Count -gt 0) { $expectedArguments += @('--features', ($spec.features -join ' ')) }
        $expectedArguments += @('--jobs', '4')
        $entry = $Document.process_traces[$Document.environment.fetch_manifests.Count + $i]
        if (($entry.arguments -join "`0") -cne ($expectedArguments -join "`0")) {
            throw "FIXTURE_PROVENANCE_INVALID: fixed fixture command or jobs=4 budget differs at phase $($i + 1)"
        }
    }
    $storageFields = @('evidence_root', 'owner_marker', 'run_root', 'cargo_home', 'temp_root', 'run_id')
    $storage = $Document.storage
    $storageKeys = @(Get-D32ObjectFieldNames -Object $storage)
    if ($storageKeys.Count -ne $storageFields.Count -or
        @($storageKeys | Where-Object { $_ -notin $storageFields }).Count -ne 0 -or
        @($storageFields | Where-Object { $_ -notin $storageKeys }).Count -ne 0 -or
        $storage.run_id -isnot [string] -or $storage.run_id -cne [string]$Document.environment.run_id) {
        throw 'FIXTURE_PROVENANCE_INVALID: compact storage identity schema/run_id is invalid'
    }
    foreach ($directoryName in @('evidence_root', 'run_root', 'cargo_home', 'temp_root')) {
        $directory = $storage.$directoryName
        $directoryFields = @('path', 'volume_serial_hex', 'file_id_hex')
        $directoryKeys = @(Get-D32ObjectFieldNames -Object $directory)
        if ($directoryKeys.Count -ne $directoryFields.Count -or
            @($directoryKeys | Where-Object { $_ -notin $directoryFields }).Count -ne 0 -or
            @($directoryFields | Where-Object { $_ -notin $directoryKeys }).Count -ne 0 -or
            $directory.path -isnot [string] -or -not [IO.Path]::IsPathRooted([string]$directory.path) -or
            $directory.volume_serial_hex -isnot [string] -or [string]$directory.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
            $directory.file_id_hex -isnot [string] -or [string]$directory.file_id_hex -cnotmatch '^[0-9a-f]{32}$') {
            throw "FIXTURE_PROVENANCE_INVALID: compact storage $directoryName path/opened-handle identity is malformed"
        }
    }
    $ownerFields = @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')
    $ownerKeys = @(Get-D32ObjectFieldNames -Object $storage.owner_marker)
    if ($ownerKeys.Count -ne $ownerFields.Count -or
        @($ownerKeys | Where-Object { $_ -notin $ownerFields }).Count -ne 0 -or
        @($ownerFields | Where-Object { $_ -notin $ownerKeys }).Count -ne 0 -or
        $storage.owner_marker.path -isnot [string] -or
        [string]$storage.owner_marker.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [uint64]$storage.owner_marker.bytes -le 0 -or
        [string]$storage.owner_marker.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        [string]$storage.owner_marker.file_id_hex -cnotmatch '^[0-9a-f]{32}$') {
        throw 'FIXTURE_PROVENANCE_INVALID: create-new owner marker reference is malformed'
    }
    $storageRoot = [IO.Path]::GetFullPath([string]$storage.evidence_root.path)
    if (-not (Test-D32ProfilePathEqual -Left ([string]$storage.owner_marker.path) -Right (Join-Path $storageRoot 'D32-PHASE0-OWNER.json')) -or
        -not (Test-D32ProfilePathEqual -Left ([string]$storage.run_root.path) -Right (Join-Path $storageRoot 'r')) -or
        -not (Test-D32ProfilePathEqual -Left ([string]$storage.cargo_home.path) -Right (Join-Path $storageRoot 'r\c')) -or
        -not (Test-D32ProfilePathEqual -Left ([string]$storage.temp_root.path) -Right (Join-Path $storageRoot 'r\t')) -or
        -not (Test-D32ProfilePathEqual -Left ([string]$Document.environment.cargo_home) -Right ([string]$storage.cargo_home.path)) -or
        -not (Test-D32ProfilePathEqual -Left ([string]$Document.environment.temp_root) -Right ([string]$storage.temp_root.path))) {
        throw 'FIXTURE_PROVENANCE_INVALID: CARGO_HOME/TEMP must use the exact compact r\\c and r\\t layout beneath the bound EvidenceRoot'
    }
    foreach ($fetchManifest in @($Document.environment.fetch_manifests)) {
        $fetchFields = @(Get-D32ObjectFieldNames -Object $fetchManifest)
        $fetchRequired = @('manifest_path', 'lock_sha256', 'command', 'status', 'exit_code', 'process_identity')
        if ($fetchFields.Count -ne $fetchRequired.Count -or
            @($fetchFields | Where-Object { $_ -notin $fetchRequired }).Count -ne 0 -or
            @($fetchRequired | Where-Object { $_ -notin $fetchFields }).Count -ne 0 -or
            [string]$fetchManifest.manifest_path -cnotmatch '^[A-Za-z0-9._/-]+\.toml$' -or
            [string]$fetchManifest.lock_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $fetchManifest.command -isnot [Array] -or $fetchManifest.command.Count -ne 6 -or
            @($fetchManifest.command | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
            [string]$fetchManifest.command[0] -cne 'fetch' -or
            [string]$fetchManifest.command[1] -cne '--locked' -or
            [string]$fetchManifest.command[2] -cne '--manifest-path' -or
            [string]::IsNullOrWhiteSpace([string]$fetchManifest.command[3]) -or
            -not [IO.Path]::IsPathRooted([string]$fetchManifest.command[3]) -or
            [string]$fetchManifest.command[4] -cne '--target' -or
            [string]$fetchManifest.command[5] -cne [string]$Document.environment.target_triple -or
            [string]$fetchManifest.status -cne 'succeeded' -or [int]$fetchManifest.exit_code -ne 0) {
            throw 'FIXTURE_PROVENANCE_INVALID: sidecar fetch command/result is malformed or has missing/extra fields'
        }
        $identity = $fetchManifest.process_identity
        if ($null -eq $identity) {
            throw 'FIXTURE_PROVENANCE_INVALID: sidecar Cargo process identity is missing'
        }
        $identityRequired = @('process_id', 'parent_process_id', 'name', 'image_path', 'creation_date', 'command_line', 'observed_at_utc', 'identity_verified')
        $identityFields = @(Get-D32ObjectFieldNames -Object $identity)
        if ($identityFields.Count -ne $identityRequired.Count -or
            @($identityFields | Where-Object { $_ -notin $identityRequired }).Count -ne 0 -or
            @($identityRequired | Where-Object { $_ -notin $identityFields }).Count -ne 0 -or
            [int64]$identity.process_id -le 0 -or [int64]$identity.parent_process_id -le 0 -or
            [int64]$identity.parent_process_id -ne [int64]$PID -or
            [string]$identity.name -cne 'cargo.exe' -or
            [string]::IsNullOrWhiteSpace([string]$identity.image_path) -or
            -not [IO.Path]::IsPathRooted([string]$identity.image_path) -or
            [string]::IsNullOrWhiteSpace([string]$identity.creation_date) -or
            [string]::IsNullOrWhiteSpace([string]$identity.command_line) -or
            [string]::IsNullOrWhiteSpace([string]$identity.observed_at_utc) -or
            $identity.identity_verified -isnot [bool] -or -not $identity.identity_verified) {
            throw 'FIXTURE_PROVENANCE_INVALID: sidecar Cargo process identity is malformed or unverified'
        }
    }
}

function Write-D32NewRecoverySeederBuildRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Document
    )

    $full = Assert-D32NoReparsePath -Path $Path -AllowMissingLeaf
    if (Test-Path -LiteralPath $full) {
        throw "OUTPUT_NOT_OWNED: refusing to overwrite D31 seeder record: $full"
    }
    $parent = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "OUTPUT_NOT_OWNED: D31 seeder record parent must already exist: $parent"
    }
    [void](Assert-D32NoReparsePath -Path $parent)
    $temporary = Join-Path $parent ('.d31-recovery-seeder.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $json = $Document | ConvertTo-Json -Depth 12
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    try {
        [IO.File]::Move($temporary, $full)
    }
    catch {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
        throw
    }
    return Get-D32BoundArtifact -Path $full
}

function Get-D32ObjectFieldNames {
    param([Parameter(Mandatory = $true)][object]$Object)

    if ($Object -is [System.Collections.IDictionary]) {
        return @($Object.Keys | ForEach-Object { [string]$_ })
    }
    return @($Object.PSObject.Properties | ForEach-Object { [string]$_.Name })
}

function Assert-D32D31RecoverySeederRecordShape {
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Document,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OutputRoot
    )

    $required = @('schema_version', 'purpose', 'run_id', 'candidate_sha', 'runner_process_id', 'source_repo', 'manifest_path', 'feature',
        'command', 'target_dir', 'run_root', 'cargo_home', 'temp_root', 'toolchain_profile_path',
        'toolchain_profile_sha256', 'target_triple', 'powershell', 'toolchain', 'fetch_manifests',
        'fetch_phases', 'cargo_path', 'process_identity', 'status', 'exit_code', 'artifact')
    $keys = Get-D32ObjectFieldNames -Object $Document
    if ($keys.Count -ne $required.Count -or
        @($keys | Where-Object { $_ -notin $required }).Count -ne 0 -or
        @($required | Where-Object { $_ -notin $keys }).Count -ne 0 -or
        [int]$Document.schema_version -ne 2 -or
        [int64]$Document.runner_process_id -le 0 -or [int64]$Document.runner_process_id -ne [int64]$PID -or
        [string]$Document.purpose -cne 'd31-recovery-seeder-test-helper' -or
        [string]$Document.feature -cne 'd29-h9-test-helper' -or
        [string]$Document.run_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Document.candidate_sha -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Document.status -cne 'succeeded' -or [int]$Document.exit_code -ne 0) {
        throw 'D31_RECOVERY_SEEDER_RECORD_INVALID: record must match the exact schema-v2 top-level wire shape'
    }
    $expectedTarget = Assert-D32NoReparsePath -Path (Join-Path $OutputRoot 'd31-recovery-seeder-target') -AllowMissingLeaf
    $expectedRecord = Assert-D32NoReparsePath -Path (Join-Path $OutputRoot 'd31-recovery-seeder-build.json') -AllowMissingLeaf
    if (-not [string]::Equals((Get-D32FullPath ([string]$Document.target_dir)), $expectedTarget, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals((Get-D32FullPath $Path), $expectedRecord, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals((Get-D32FullPath ([string]$Document.manifest_path)), (Get-D32FullPath (Join-Path ([string]$Document.source_repo) 'vita-agent/Cargo.toml')), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'D31_RECOVERY_SEEDER_RECORD_INVALID: manifest, fixed external target, or sibling record path differs'
    }
    $expectedCommand = @('build', '--quiet', '--locked', '--manifest-path', [string]$Document.manifest_path,
        '--bin', 'vita-agent', '--features', 'd29-h9-test-helper', '--target-dir', [string]$Document.target_dir)
    $command = @($Document.command | ForEach-Object { [string]$_ })
    if ($command.Count -ne $expectedCommand.Count -or
        (($command -join "`0") -cne ($expectedCommand -join "`0"))) {
        throw 'D31_RECOVERY_SEEDER_RECORD_INVALID: exact fixed Cargo argv must not gain flags such as --offline'
    }
    $identity = $Document.process_identity
    if ($null -eq $identity) {
        throw 'D31_RECOVERY_SEEDER_RECORD_INVALID: Cargo process identity is missing'
    }
    $identityFields = @(Get-D32ObjectFieldNames -Object $identity)
    $identityRequired = @('process_id', 'parent_process_id', 'name', 'image_path', 'creation_date', 'command_line', 'observed_at_utc', 'identity_verified')
    if ($identityFields.Count -ne $identityRequired.Count -or
        @($identityFields | Where-Object { $_ -notin $identityRequired }).Count -ne 0 -or
        @($identityRequired | Where-Object { $_ -notin $identityFields }).Count -ne 0 -or
        [int64]$identity.process_id -le 0 -or
        [int64]$identity.parent_process_id -ne [int64]$Document.runner_process_id -or
        [int64]$identity.process_id -eq [int64]$Document.runner_process_id -or
        [string]$identity.name -cne 'cargo.exe' -or
        [string]::IsNullOrWhiteSpace([string]$identity.image_path) -or
        -not [IO.Path]::IsPathRooted([string]$identity.image_path) -or
        [string]::IsNullOrWhiteSpace([string]$identity.creation_date) -or
        [string]::IsNullOrWhiteSpace([string]$identity.command_line) -or
        [string]::IsNullOrWhiteSpace([string]$identity.observed_at_utc) -or
        $identity.identity_verified -isnot [bool] -or -not $identity.identity_verified) {
        throw 'D31_RECOVERY_SEEDER_RECORD_INVALID: Cargo process parent must equal the recorded current runner process'
    }
    $artifactFields = @(Get-D32ObjectFieldNames -Object $Document.artifact)
    if ($artifactFields.Count -ne 4 -or
        @($artifactFields | Where-Object { $_ -notin @('path', 'bytes', 'sha256', 'file_identity') }).Count -ne 0 -or
        @(@('path', 'bytes', 'sha256', 'file_identity') | Where-Object { $_ -notin $artifactFields }).Count -ne 0 -or
        -not [string]::Equals([string]$Document.artifact.path, (Join-Path $expectedTarget 'debug/vita-agent.exe'), [StringComparison]::OrdinalIgnoreCase) -or
        [uint64]$Document.artifact.bytes -le 0 -or [string]$Document.artifact.sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'D31_RECOVERY_SEEDER_RECORD_INVALID: artifact shape or fixed seeder image path is invalid'
    }
}

function Invoke-D32DebugSelfTestProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$ExpectedRootPin,
        [string[]]$ApprovedImagePins = @(),
        [string[]]$CandidateImageRoots = @(),
        [AllowNull()][string]$EnvironmentBlock,
        [bool]$InjectFirstCreateInterruption = $false,
        [bool]$InjectFirstCreateIdentityMismatch = $false,
        [AllowNull()][string]$FailureInjection,
        [int]$TimeoutMilliseconds = 10000
    )

    $commandLine = ConvertTo-D32CommandLine (@($FilePath) + $Arguments)
    $native = $null
    $trace = $null
    $cleanup = $null
    try {
        $native = [D32FixtureNativeProcessV2]::StartDebug($FilePath, $commandLine, $WorkingDirectory, $EnvironmentBlock)
        $native.ConfigureDebugCapture($ExpectedRootPin, [string[]]$ApprovedImagePins, [string[]]$CandidateImageRoots,
            $TimeoutMilliseconds, $InjectFirstCreateInterruption, $InjectFirstCreateIdentityMismatch, $FailureInjection)
        $trace = $native.WaitForDebugTrace([int]($TimeoutMilliseconds + 20000))
        $cleanup = $native.CloseJobAndWait(10000)
        return [PSCustomObject]@{
            Trace = $trace
            Cleanup = $cleanup
            ContinueCalls = [int]$native.DebugContinueCallCount
            LaunchMode = [string]$native.LaunchMode
        }
    }
    finally {
        if ($null -ne $native) {
            try { $native.Dispose() }
            catch {
                if ($null -ne $trace) {
                    $processDetails = @($trace.Processes | ForEach-Object { "$($_.ProcessId):$($_.ImagePath):parent=$($_.ParentProcessId):exited=$($_.Exited)" }) -join ';'
                    throw "DEBUG_SELFTEST_NATIVE_DISPOSE_FAILED: trace_state=$($trace.State); block_reason=$($trace.BlockReason); cleanup=$($cleanup.Detail); job_active=$($cleanup.JobActiveProcessCount); job_verified=$($cleanup.JobActiveProcessCountVerified); handles=$($cleanup.RetainedProcessHandleCount); handles_signaled=$($cleanup.RetainedProcessHandlesSignaled); debugger_absent=$($cleanup.DebuggerAssociationAbsent); processes=$processDetails; handle_audit=$($native.GetDebugHandleDuplicationAudit()); error=$($_.Exception.Message)"
                }
                throw
            }
        }
    }
}

function Invoke-D32SelfTest {
    if ($PSVersionTable.PSVersion -lt [Version]'7.5') {
        throw 'SELFTEST_REQUIRES_POWERSHELL_75: strict budget timestamp round-trip uses ConvertFrom-Json -DateKind String'
    }
    Ensure-D32NativeLauncher
    $root = Join-Path ([IO.Path]::GetTempPath()) ('d32-fixture-prebuild-selftest-' + [Guid]::NewGuid().ToString('N'))
    $passed = 0
    $owned = $false
    try {
        Assert-D32FixtureTimeoutScope -TimeoutSeconds 3600 -OwnerBinding $null -BuildD31RecoverySeeder $false
        try {
            Assert-D32FixtureTimeoutScope -TimeoutSeconds 3601 -OwnerBinding $null -BuildD31RecoverySeeder $false
            throw 'SELFTEST_FAILED: timeout above the non-Phase0 ceiling was accepted without an owner binding'
        }
        catch { if ($_.Exception.Message -notlike 'PHASE0_TIMEOUT_SCOPE_BLOCKED:*') { throw } }
        Assert-D32FixtureTimeoutScope -TimeoutSeconds 14400 -OwnerBinding ([PSCustomObject]@{}) -BuildD31RecoverySeeder $false
        try {
            Assert-D32FixtureTimeoutScope -TimeoutSeconds 14400 -OwnerBinding ([PSCustomObject]@{}) -BuildD31RecoverySeeder $true
            throw 'SELFTEST_FAILED: four-hour timeout was accepted for a D31 recovery-seeder run'
        }
        catch { if ($_.Exception.Message -notlike 'PHASE0_TIMEOUT_SCOPE_BLOCKED:*') { throw } }
        $passed++

        $validBuildBudget = [ordered]@{
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
        Assert-D32FixtureBuildBudgetScope -OwnerBinding ([PSCustomObject]@{}) -BuildD31RecoverySeeder $false -TimeoutSeconds 14400 -FixtureBuildTimeoutSeconds 28800 -BuildJobs 4 -Capacity $validBuildBudget
        foreach ($invalidBudget in @(
                [PSCustomObject]@{ Timeout = 14400; Jobs = 1; Phase0Timeout = $null },
                [PSCustomObject]@{ Timeout = 14400; Jobs = 2; Phase0Timeout = $null },
                [PSCustomObject]@{ Timeout = 14400; Jobs = 5; Phase0Timeout = $null },
                [PSCustomObject]@{ Timeout = 28801; Jobs = 4; Phase0Timeout = $null },
                [PSCustomObject]@{ Timeout = 14400; Jobs = 4; Phase0Timeout = 14399 },
                [PSCustomObject]@{ Timeout = 14400; Jobs = 4; Phase0Timeout = 28800 }
            )) {
            $badCapacity = [ordered]@{}
            foreach ($key in $validBuildBudget.Keys) { $badCapacity[$key] = $validBuildBudget[$key] }
            if ($null -ne $invalidBudget.Phase0Timeout) { $badCapacity.phase0_command_timeout_seconds = $invalidBudget.Phase0Timeout }
            $wrongBudgetRejected = $false
            try { Assert-D32FixtureBuildBudgetScope -OwnerBinding ([PSCustomObject]@{}) -BuildD31RecoverySeeder $false -TimeoutSeconds $(if ($null -ne $invalidBudget.Phase0Timeout) { [int]$invalidBudget.Phase0Timeout } else { 14400 }) -FixtureBuildTimeoutSeconds $invalidBudget.Timeout -BuildJobs $invalidBudget.Jobs -Capacity $badCapacity }
            catch { $wrongBudgetRejected = $_.Exception.Message -like 'FIXTURE_BUILD_BUDGET_BLOCKED:*' -or $_.Exception.Message -like 'FIXTURE_BUILD_BUDGET_INVALID:*' }
            if (-not $wrongBudgetRejected) { throw 'SELFTEST_FAILED: wrong Phase0 build budget was accepted' }
        }
        Assert-D32FixtureBuildBudgetScope -OwnerBinding $null -BuildD31RecoverySeeder $false -TimeoutSeconds 600 -FixtureBuildTimeoutSeconds 600 -BuildJobs 1 -Capacity $null
        Assert-D32FixtureBuildBudgetScope -OwnerBinding $null -BuildD31RecoverySeeder $true -TimeoutSeconds 600 -FixtureBuildTimeoutSeconds 600 -BuildJobs 1 -Capacity $null
        Assert-D32FixtureBuildBudgetScope -OwnerBinding ([PSCustomObject]@{}) -BuildD31RecoverySeeder $true -TimeoutSeconds 600 -FixtureBuildTimeoutSeconds 600 -BuildJobs 1 -Capacity $null
        if ((Get-D32FixtureBuildMode -OwnerBinding $null -BuildD31RecoverySeeder $false) -cne 'Standalone' -or
            (Get-D32FixtureBuildMode -OwnerBinding ([PSCustomObject]@{}) -BuildD31RecoverySeeder $false) -cne 'Phase0' -or
            (Get-D32FixtureBuildMode -OwnerBinding ([PSCustomObject]@{}) -BuildD31RecoverySeeder $true) -cne 'D31Seeder' -or
            (Test-D32FixtureBuildModeEmitsPhase0Provenance -Mode 'Phase0') -ne $true -or
            (Test-D32FixtureBuildModeEmitsPhase0Provenance -Mode 'Standalone') -ne $false -or
            (Test-D32FixtureBuildModeEmitsPhase0Provenance -Mode 'D31Seeder') -ne $false) {
            throw 'SELFTEST_FAILED: fixture build mode classification is not exclusive'
        }
        Assert-D32FixtureBuildModeAuthority -Mode 'Phase0'
        foreach ($blockedMode in @(
                [PSCustomObject]@{ Mode = 'Standalone'; Prefix = 'STANDALONE_FIXTURE_AUTHORITY_BLOCKED:' },
                [PSCustomObject]@{ Mode = 'D31Seeder'; Prefix = 'D31_RECOVERY_SEEDER_AUTHORITY_BLOCKED:' }
            )) {
            $modeBlocked = $false
            try { Assert-D32FixtureBuildModeAuthority -Mode $blockedMode.Mode }
            catch { $modeBlocked = $_.Exception.Message -like ($blockedMode.Prefix + '*') }
            if (-not $modeBlocked) { throw "SELFTEST_FAILED: $($blockedMode.Mode) mode was not stopped before using Phase0-only authority" }
        }
        $runtimeSource = [IO.File]::ReadAllText((Join-Path $script:ScriptRoot 'd32-fixture-prebuild.ps1'))
        $runtimeTokens = $null
        $runtimeParseErrors = $null
        $runtimeAst = [System.Management.Automation.Language.Parser]::ParseInput($runtimeSource, [ref]$runtimeTokens, [ref]$runtimeParseErrors)
        if ($runtimeParseErrors.Count -gt 0) { throw 'SELFTEST_FAILED: fixture runner source did not parse for the production mode-order check' }
        $allRuntimeCommands = @($runtimeAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
        $productionRuntimeCommands = @($allRuntimeCommands | Where-Object {
                $cursor = $_.Parent
                $insideFunction = $false
                while ($null -ne $cursor) {
                    if ($cursor -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $insideFunction = $true; break }
                    $cursor = $cursor.Parent
                }
                -not $insideFunction
            })
        $productionModeCalls = @($productionRuntimeCommands | Where-Object {
                $_.GetCommandName() -ceq 'Assert-D32FixtureBuildModeAuthority' -and
                $_.CommandElements.Count -eq 3 -and $_.CommandElements[1].Extent.Text -ceq '-Mode' -and $_.CommandElements[2].Extent.Text -ceq '$fixtureBuildMode'
            })
        $outputRootClaims = @($productionRuntimeCommands | Where-Object {
                $_.GetCommandName() -ceq 'Ensure-D32OwnedDirectory' -and @($_.CommandElements | Where-Object { $_.Extent.Text -ceq '$OutputRoot' }).Count -eq 1
            })
        $ownedDirectoryClaims = @($productionRuntimeCommands | Where-Object { $_.GetCommandName() -ceq 'Ensure-D32OwnedDirectory' })
        $phase0StorageClaims = @($productionRuntimeCommands | Where-Object { $_.GetCommandName() -ceq 'Initialize-D32FixturePhase0Storage' })
        $fixtureFetchBoundaries = @($productionRuntimeCommands | Where-Object { $_.GetCommandName() -ceq 'Invoke-D32FixturePreCargoBoundary' })
        if ($productionModeCalls.Count -ne 1 -or $outputRootClaims.Count -ne 1 -or $ownedDirectoryClaims.Count -eq 0 -or
            $phase0StorageClaims.Count -ne 1 -or $fixtureFetchBoundaries.Count -ne 1 -or
            @($ownedDirectoryClaims | Where-Object { $_.Extent.StartOffset -le $productionModeCalls[0].Extent.StartOffset }).Count -gt 0 -or
            $productionModeCalls[0].Extent.StartOffset -ge $outputRootClaims[0].Extent.StartOffset -or
            $productionModeCalls[0].Extent.StartOffset -ge $phase0StorageClaims[0].Extent.StartOffset -or
            $productionModeCalls[0].Extent.StartOffset -ge $fixtureFetchBoundaries[0].Extent.StartOffset) {
            throw 'SELFTEST_FAILED: non-Phase0 fixture modes must stop before output-root creation and any Cargo fetch/build boundary'
        }
        $passed++

        $priorProcessEvidence = $script:D32LastProcessEvidence
        try {
            $script:D32LastProcessEvidence = [ordered]@{ process_trace = 'prior-phase-trace'; native_cleanup = 'prior-phase-cleanup' }
            Reset-D32FixturePhaseProcessEvidence
            if ($null -ne $script:D32LastProcessEvidence) { throw 'SELFTEST_FAILED: starting a later fixture phase retained stale process evidence' }
            $passed++
        }
        finally { $script:D32LastProcessEvidence = $priorProcessEvidence }

        $ordinaryFailures = @(
            [PSCustomObject]@{ name = 'fixture-2'; arguments = @('build', '--bin', 'fixture-2'); process_result = [PSCustomObject]@{ process_trace = [PSCustomObject]@{ state = 'BLOCKED'; marker = 'ordinary-2' }; native_cleanup = [PSCustomObject]@{ cleanup_succeeded = $true } }; phase_log = 'fixture-2.log'; error = 'fixture-2 exited nonzero' },
            [PSCustomObject]@{ name = 'fixture-4'; arguments = @('build', '--bin', 'fixture-4'); process_result = [PSCustomObject]@{ process_trace = [PSCustomObject]@{ state = 'BLOCKED'; marker = 'ordinary-4' }; native_cleanup = [PSCustomObject]@{ cleanup_succeeded = $true } }; phase_log = 'fixture-4.log'; error = 'fixture-4 exited nonzero' }
        )
        $ordinarySelection = Get-D32FixtureFailurePayloadSelection -PendingFailures $ordinaryFailures -GlobalCleanupError 'global cleanup verification failed'
        $terminalFailure = [PSCustomObject]@{
            name = 'fixture-5'; arguments = @('build', '--bin', 'fixture-5')
            process_result = [PSCustomObject]@{ process_trace = [PSCustomObject]@{ state = 'BLOCKED'; marker = 'terminal-fatal-trace' }; native_cleanup = [PSCustomObject]@{ cleanup_succeeded = $false; marker = 'terminal-fatal-cleanup' } }
            phase_log = 'fixture-5.log'; error = 'fixture-5 failed fatally'
        }
        $terminalSelection = Get-D32FixtureFailurePayloadSelection -PendingFailures $ordinaryFailures -TerminalFailure $terminalFailure
        if ($ordinarySelection.Name -cne 'fixture-4' -or $ordinarySelection.PrimaryError -cne 'fixture-4 exited nonzero' -or
            $ordinarySelection.SecondaryErrors[0] -cne 'fixture-2 exited nonzero' -or $ordinarySelection.SecondaryErrors[1] -cne 'global cleanup verification failed' -or
            $terminalSelection.Name -cne 'fixture-5' -or $terminalSelection.ProcessResult.process_trace.marker -cne 'terminal-fatal-trace' -or
            $terminalSelection.ProcessResult.native_cleanup.marker -cne 'terminal-fatal-cleanup' -or
            $terminalSelection.SecondaryErrors.Count -ne 2 -or $terminalSelection.SecondaryErrors[0] -cne 'fixture-2 exited nonzero' -or
            $terminalSelection.SecondaryErrors[1] -cne 'fixture-4 exited nonzero') {
            throw 'SELFTEST_FAILED: blocked payload selection did not prefer the terminal failing phase trace/cleanup while retaining every earlier ordinary failure in order'
        }
        $passed++

        [void](Ensure-D32OwnedDirectory $root)
        $owned = $true
        Write-Host 'D32_FIXTURE_TRUST_CONTRACT=pins:-PinnedGitPath,-PinnedGitSha256,-ExpectedCandidateSha,-ToolchainProfilePath,-ExpectedToolchainProfileSha256; d31-target:OutputRoot\d31-recovery-seeder-target; d31-record:sibling-d31-recovery-seeder-build.json; d31-env:D31_RECOVERY_SEEDER_RECORD_PATH,D31_RECOVERY_SEEDER_RECORD_SHA256,D31_RECOVERY_SEEDER_RUN_ID,D32_BUILD_TOOLCHAIN_PROFILE_PATH,D32_EXPECTED_TOOLCHAIN_PROFILE_SHA256; profile:D32_BUILD_TOOLCHAIN_PROFILE_V2'

        $profileTestRepository = Get-D32FullPath (Join-Path $script:ScriptRoot '..')
        $validatedInterfaceProfile = $null
        $profileSelfTestCases = @(Test-D32BuildToolchainProfileSelfTest `
            -Root $root `
            -Repository $profileTestRepository `
            -ValidatedProfileOutput ([ref]$validatedInterfaceProfile))
        $profileSelfTestFailures = @($profileSelfTestCases | Where-Object { -not [bool]$_.Passed })
        if ($profileSelfTestFailures.Count -ne 0 -or $null -eq $validatedInterfaceProfile -or -not [bool]$validatedInterfaceProfile.IsValid) {
            $failedNames = @($profileSelfTestFailures | ForEach-Object { [string]$_.Name }) -join ', '
            throw "SELFTEST_FAILED: real validated profile fixture is unavailable for the child-launcher interface check: $failedNames"
        }
        $passed += $profileSelfTestCases.Count

        $interfaceRunRoot = Join-Path $root 'profile-child-launcher-interface'
        $interfaceCargoHome = Join-Path $interfaceRunRoot 'cargo-home'
        $interfaceTempRoot = Join-Path $interfaceRunRoot 'temp'
        $interfaceLogRoot = Join-Path $root 'profile-child-launcher-logs'
        [void][IO.Directory]::CreateDirectory($interfaceRunRoot)
        [void][IO.Directory]::CreateDirectory($interfaceCargoHome)
        [void][IO.Directory]::CreateDirectory($interfaceTempRoot)
        [void][IO.Directory]::CreateDirectory($interfaceLogRoot)
        foreach ($interfaceDirectory in @($interfaceRunRoot, $interfaceCargoHome, $interfaceTempRoot, $interfaceLogRoot)) {
            $null = Assert-D32NoReparsePath -Path $interfaceDirectory
        }

        $ambientName = 'D32_SELFTEST_AMBIENT_ENV_SENTINEL'
        $previousAmbientValue = [Environment]::GetEnvironmentVariable($ambientName, 'Process')
        $profileChildEnvironment = $null
        $expectedProfileChildEnvironment = $null
        try {
            [Environment]::SetEnvironmentVariable($ambientName, 'must-not-cross-the-child-boundary', 'Process')
            $profileChildEnvironment = New-D32ProfileChildEnvironment `
                -ValidatedProfile $validatedInterfaceProfile `
                -CargoHome $interfaceCargoHome `
                -TempRoot $interfaceTempRoot `
                -Offline $false
            $expectedProfileChildEnvironment = Get-D32BuildToolchainEnvironment `
                -ValidatedProfile $validatedInterfaceProfile `
                -CargoHome $interfaceCargoHome `
                -TempRoot $interfaceTempRoot `
                -Offline $false
        }
        finally {
            [Environment]::SetEnvironmentVariable($ambientName, $previousAmbientValue, 'Process')
        }
        if ($profileChildEnvironment -isnot [System.Collections.IDictionary] -or
            $profileChildEnvironment -is [string] -or
            $profileChildEnvironment.Count -ne $expectedProfileChildEnvironment.Count -or
            @($profileChildEnvironment.Keys | Where-Object { $ambientName -ceq [string]$_ }).Count -ne 0) {
            throw 'SELFTEST_FAILED: profile fetch child environment is not the exact scrubbed IDictionary contract'
        }
        foreach ($environmentKey in $expectedProfileChildEnvironment.Keys) {
            if (-not $profileChildEnvironment.Contains($environmentKey) -or
                [string]$profileChildEnvironment[$environmentKey] -cne [string]$expectedProfileChildEnvironment[$environmentKey]) {
                throw 'SELFTEST_FAILED: profile fetch child environment changed an allowlisted value'
            }
        }
        $passed++

        function Invoke-D32ProfileChildFetchLauncherProbe {
            param(
                [Parameter(Mandatory = $true)][object]$ValidatedProfile,
                [Parameter(Mandatory = $true)][string]$CargoHome,
                [Parameter(Mandatory = $true)][string]$TempRoot,
                [Parameter(Mandatory = $true)][string]$Repository,
                [Parameter(Mandatory = $true)][string]$LogRoot,
                [Parameter(Mandatory = $true)][int]$TimeoutSeconds
            )

            $script:D32SelfTestFixtureLaunchCapture = [System.Collections.Generic.List[object]]::new()
            function Assert-D32PinnedCleanCandidate {
                param([Parameter(Mandatory = $true)][string]$Root)
                return ('a' * 40)
            }
            function Start-D32FixtureBoundedNativeProcess {
                param(
                    [string]$FilePath,
                    [string]$CommandLine,
                    [string]$WorkingDirectory,
                    [AllowNull()][string]$EnvironmentBlock,
                    [AllowNull()][string]$NativeTestFailure,
                    [bool]$RequireDebugEvents
                )
                $script:D32SelfTestFixtureLaunchCapture.Add([PSCustomObject]@{
                    FilePath = $FilePath
                    CommandLine = $CommandLine
                    WorkingDirectory = $WorkingDirectory
                    EnvironmentBlock = $EnvironmentBlock
                    NativeTestFailure = $NativeTestFailure
                    RequireDebugEvents = $RequireDebugEvents
                })
                throw 'D32_SELFTEST_NATIVE_LAUNCH_CAPTURED_WITHOUT_START'
            }

            $phaseEvidence = [System.Collections.Generic.List[object]]::new()
            $failure = $null
            try {
                $null = Invoke-D32LockedCargoFetches `
                    -ValidatedProfile $ValidatedProfile `
                    -CargoPath ([string]$ValidatedProfile.Profile.toolchain.cargo.path) `
                    -CargoHome $CargoHome `
                    -TempRoot $TempRoot `
                    -RepoRoot $Repository `
                    -LogRoot $LogRoot `
                    -TimeoutSeconds $TimeoutSeconds `
                    -LogPrefix 'interface-fetch' `
                    -PhaseEvidence $phaseEvidence
            }
            catch {
                $failure = $_.Exception.Message
            }
            $captures = @($script:D32SelfTestFixtureLaunchCapture.ToArray())
            Remove-Variable -Name D32SelfTestFixtureLaunchCapture -Scope Script -ErrorAction SilentlyContinue
            return [PSCustomObject]@{
                PhaseEvidence = @($phaseEvidence.ToArray())
                Failure = $failure
                Captures = $captures
            }
        }

        $interfaceProbe = Invoke-D32ProfileChildFetchLauncherProbe `
            -ValidatedProfile $validatedInterfaceProfile `
            -CargoHome $interfaceCargoHome `
            -TempRoot $interfaceTempRoot `
            -Repository $profileTestRepository `
            -LogRoot $interfaceLogRoot `
            -TimeoutSeconds 17
        $firstFetch = $validatedInterfaceProfile.LockInputs[0]
        $firstFetchName = 'interface-fetch-01-fetch'
        $firstFetchLog = Get-D32FullPath (Join-Path $interfaceLogRoot $firstFetchName)
        $firstFetchArguments = @(
            'fetch', '--locked', '--manifest-path', [string]$firstFetch.ManifestFullPath,
            '--target', [string]$validatedInterfaceProfile.Profile.target_triple
        )
        $firstFetchCommandLine = ConvertTo-D32CommandLine (@([string]$validatedInterfaceProfile.Profile.toolchain.cargo.path) + $firstFetchArguments)
        $capturedFetchEnvironmentBlock = ConvertTo-D32EnvironmentBlock -Environment $profileChildEnvironment
        $expectedCapturedFilePath = Get-D32FullPath ([string]$validatedInterfaceProfile.Profile.toolchain.cargo.path)
        $capturedEnvironmentMatches = $false
        if ($interfaceProbe.Captures.Count -eq 1 -and
            $interfaceProbe.Captures[0].EnvironmentBlock -is [string] -and
            $interfaceProbe.Captures[0].EnvironmentBlock.EndsWith("`0`0") -and
            $interfaceProbe.Captures[0].EnvironmentBlock -ceq $capturedFetchEnvironmentBlock) {
            $serializedBody = $interfaceProbe.Captures[0].EnvironmentBlock.Substring(0, $interfaceProbe.Captures[0].EnvironmentBlock.Length - 2)
            $serializedEnvironment = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in $serializedBody.Split([char]0)) {
                $separator = $entry.IndexOf('=')
                if ($separator -le 0) { throw 'SELFTEST_FAILED: launcher received a malformed serialized child environment entry' }
                $serializedEnvironment.Add($entry.Substring(0, $separator), $entry.Substring($separator + 1))
            }
            $capturedEnvironmentMatches = $serializedEnvironment.Count -eq $profileChildEnvironment.Count
            foreach ($environmentKey in $profileChildEnvironment.Keys) {
                if (-not $serializedEnvironment.Contains($environmentKey) -or
                    [string]$serializedEnvironment[$environmentKey] -cne [string]$profileChildEnvironment[$environmentKey]) {
                    $capturedEnvironmentMatches = $false
                }
            }
        }
        $launchRequest = $script:D32LastProcessEvidence.launch_request
        if ($interfaceProbe.Failure -notlike 'CARGO_FETCH_FAILED:*status=spawn_failed*' -or
            $interfaceProbe.Captures.Count -ne 1 -or
            $interfaceProbe.PhaseEvidence.Count -ne 1 -or
            $interfaceProbe.PhaseEvidence[0].name -cne $firstFetchName -or
            $interfaceProbe.PhaseEvidence[0].executable -cne $expectedCapturedFilePath -or
            (@($interfaceProbe.PhaseEvidence[0].arguments) -join "`0") -cne ($firstFetchArguments -join "`0") -or
            $interfaceProbe.PhaseEvidence[0].command_line -cne $firstFetchCommandLine -or
            $interfaceProbe.PhaseEvidence[0].working_directory -cne $profileTestRepository -or
            $null -ne $interfaceProbe.PhaseEvidence[0].root_record -or
            $null -eq $launchRequest -or
            $launchRequest.executable -cne $expectedCapturedFilePath -or
            (@($launchRequest.arguments) -join "`0") -cne ($firstFetchArguments -join "`0") -or
            $launchRequest.working_directory -cne $profileTestRepository -or
            $launchRequest.phase_log -cne $firstFetchLog -or
            $launchRequest.timeout_seconds -ne 17 -or
            $launchRequest.child_environment_type -cne $profileChildEnvironment.GetType().FullName -or
            -not [bool]$launchRequest.require_debug_events -or
            $interfaceProbe.Captures[0].FilePath -cne $expectedCapturedFilePath -or
            $interfaceProbe.Captures[0].CommandLine -cne $firstFetchCommandLine -or
            $interfaceProbe.Captures[0].WorkingDirectory -cne $profileTestRepository -or
            -not [bool]$interfaceProbe.Captures[0].RequireDebugEvents -or
            -not $capturedEnvironmentMatches -or
            $interfaceProbe.Captures[0].EnvironmentBlock.Contains($ambientName)) {
            throw 'SELFTEST_FAILED: profile fetch did not preserve the typed bounded-launch request, exact argv/environment, timeout/log, and empty-list evidence semantics'
        }
        $passed++

        $cleanupFailureRejected = $false
        try {
            $null = Test-D32NoOwnedCargoDescendants -PhaseEvidence $interfaceProbe.PhaseEvidence -CheckName 'captured spawn-failure interface selftest'
        }
        catch {
            $cleanupFailureRejected = $_.Exception.Message -ceq 'PROCESS_TREE_REAP_FAILED: captured spawn-failure interface selftest has a phase without verified root process identity evidence'
        }
        if (-not $cleanupFailureRejected) {
            throw 'SELFTEST_FAILED: cleanup/error path did not bind captured fetch evidence and fail closed without root identity'
        }
        $passed++

        $badEnvironmentSentinel = 'D32_SELFTEST_CHILD_ENVIRONMENT_TYPE_SENTINEL'
        $invalidBoundedLog = Join-Path $root 'invalid-child-environment-type'
        $boundedTypeMismatchRejected = $false
        try {
            $null = Invoke-D32BoundedProcess `
                -FilePath $expectedCapturedFilePath `
                -Arguments @('version') `
                -WorkingDirectory $profileTestRepository `
                -PhaseLog $invalidBoundedLog `
                -TimeoutSeconds 1 `
                -ChildEnvironment $badEnvironmentSentinel
        }
        catch {
            $boundedTypeMismatchRejected = $_.Exception.Message -clike 'CHILD_ENVIRONMENT_INVALID:*' -and
                $_.Exception.Message -cnotlike "*$badEnvironmentSentinel*"
        }
        $serializerTypeMismatchRejected = $false
        try { $null = ConvertTo-D32EnvironmentBlock -Environment $badEnvironmentSentinel }
        catch {
            $serializerTypeMismatchRejected = $_.Exception.Message -clike 'CHILD_ENVIRONMENT_INVALID:*' -and
                $_.Exception.Message -cnotlike "*$badEnvironmentSentinel*"
        }
        if (-not $boundedTypeMismatchRejected -or -not $serializerTypeMismatchRejected -or
            (Test-Path -LiteralPath "$invalidBoundedLog.stdout.log") -or
            (Test-Path -LiteralPath "$invalidBoundedLog.stderr.log")) {
            throw 'SELFTEST_FAILED: mismatched child-environment type was not safely rejected before launch/log creation'
        }
        $passed++

        function Invoke-D32EmptyFetchEvidenceBindingProbe {
            function New-D32ProfileChildEnvironment { throw 'D32_SELFTEST_EMPTY_PHASE_EVIDENCE_BODY_REACHED' }
            $phaseEvidence = [System.Collections.Generic.List[object]]::new()
            try {
                $null = Invoke-D32LockedCargoFetches `
                    -ValidatedProfile ([PSCustomObject]@{ LockInputs = @() }) `
                    -CargoPath 'C:\d32-selftest\cargo.exe' `
                    -CargoHome 'C:\d32-selftest\cargo-home' `
                    -TempRoot 'C:\d32-selftest\temp' `
                    -RepoRoot 'C:\d32-selftest\repo' `
                    -LogRoot 'C:\d32-selftest\logs' `
                    -TimeoutSeconds 1 `
                    -LogPrefix 'empty-phase-evidence' `
                    -PhaseEvidence $phaseEvidence
                throw 'SELFTEST_FAILED: empty locked-fetch evidence accumulator unexpectedly returned'
            }
            catch {
                if ($_.Exception.Message -cne 'D32_SELFTEST_EMPTY_PHASE_EVIDENCE_BODY_REACHED') {
                    throw "SELFTEST_FAILED: empty locked-fetch evidence did not reach the bounded pre-process seam: $($_.Exception.Message)"
                }
            }
        }
        Invoke-D32EmptyFetchEvidenceBindingProbe
        $passed++

        $emptyCleanupEvidenceRejected = $false
        try {
            $null = Test-D32NoOwnedCargoDescendants -PhaseEvidence @() -CheckName 'empty-evidence selftest'
        }
        catch {
            $emptyCleanupEvidenceRejected = $_.Exception.Message -ceq 'PROCESS_TREE_REAP_FAILED: empty-evidence selftest has no captured process identity evidence'
        }
        if (-not $emptyCleanupEvidenceRejected) { throw 'SELFTEST_FAILED: empty process evidence was accepted as cleanup proof or failed before the explicit fail-closed check' }
        $passed++

        $incompleteCleanupEvidenceRejected = $false
        try {
            $null = Test-D32NoOwnedCargoDescendants `
                -PhaseEvidence @([PSCustomObject]@{ root_record = $null; descendant_records = @() }) `
                -CheckName 'incomplete-evidence selftest'
        }
        catch {
            $incompleteCleanupEvidenceRejected = $_.Exception.Message -ceq 'PROCESS_TREE_REAP_FAILED: incomplete-evidence selftest has a phase without verified root process identity evidence'
        }
        if (-not $incompleteCleanupEvidenceRejected) { throw 'SELFTEST_FAILED: incomplete process evidence was accepted as cleanup proof' }
        $passed++

        $emptySnapshotRejected = $false
        try { $null = Get-D32DescendantProcessRecordsFromSnapshot -Snapshot @() -RootPid 1 }
        catch { $emptySnapshotRejected = $_.Exception.Message -ceq 'PROCESS_TREE_REAP_FAILED: process identity snapshot is empty' }
        if (-not $emptySnapshotRejected) { throw 'SELFTEST_FAILED: an empty process snapshot was accepted as descendant evidence' }
        $passed++

        $emptyEnvironmentRejected = $false
        try { Assert-D32FixtureManifestEnvironmentShape -Environment @{} }
        catch { $emptyEnvironmentRejected = $_.Exception.Message -ceq 'FIXTURE_MANIFEST_ENVIRONMENT_INVALID: schema-v3 environment must retain exactly the six consumer wire fields' }
        if (-not $emptyEnvironmentRejected) { throw 'SELFTEST_FAILED: an empty fixture environment bypassed the exact schema check' }
        $passed++

        $emptyTraceInventoryRejected = $false
        try { Assert-D32FixtureDebugTraceShape -Traces @() }
        catch { $emptyTraceInventoryRejected = $_.Exception.Message -ceq 'FIXTURE_PROVENANCE_INVALID: process trace inventory must contain exactly three locked fetches and five fixture Cargo roots' }
        if (-not $emptyTraceInventoryRejected) { throw 'SELFTEST_FAILED: an empty process trace inventory bypassed the required eight-root check' }
        $passed++

        $emptyProvenanceRejected = $false
        try { Assert-D32FixtureBuildProvenanceShape -Document @{} }
        catch { $emptyProvenanceRejected = $_.Exception.Message -like 'FIXTURE_PROVENANCE_INVALID:*' }
        if (-not $emptyProvenanceRejected) { throw 'SELFTEST_FAILED: an empty fixture provenance document bypassed strict shape validation' }
        $passed++

        $fixedSeederPaths = Get-D32D31RecoverySeederPaths -OutputRoot $root
        if ((Split-Path -Parent $fixedSeederPaths.target) -ne (Split-Path -Parent $fixedSeederPaths.record) -or
            (Split-Path -Leaf $fixedSeederPaths.target) -ne 'd31-recovery-seeder-target' -or
            (Split-Path -Leaf $fixedSeederPaths.record) -ne 'd31-recovery-seeder-build.json') {
            throw 'SELFTEST_FAILED: D31 seeder target and record must be fixed canonical siblings'
        }
        $passed++

        $quotedArguments = ConvertTo-D32CommandLine @(
            'plain',
            'with spaces',
            'C:\path with space\\',
            'embedded\"quote'
        )
        if ($quotedArguments -cne 'plain "with spaces" "C:\path with space\\\\" "embedded\\\"quote"') {
            throw "SELFTEST_FAILED: Windows process argv quoting mismatch: $quotedArguments"
        }
        $passed++

        $nativeIdentityStart = [DateTime]::UtcNow.AddSeconds(-2)
        $nativeIdentityImage = Join-Path $root 'pinned-git-selftest.exe'
        $nativeIdentityExpectedCommand = ConvertTo-D32CommandLine @($nativeIdentityImage, 'rev-parse', '--verify', 'HEAD')
        $nativeIdentityRecord = [PSCustomObject]@{
            IdentityVerified = $true
            ProcessId = 2147483000
            ParentProcessId = [int]$PID
            Name = 'pinned-git-selftest.exe'
            ImagePath = $nativeIdentityImage
            CommandLine = $nativeIdentityExpectedCommand
            CreationDate = $nativeIdentityStart.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            ObservedAtUtc = [DateTimeOffset]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        }
        $null = Assert-D32NativeProcessIdentityRecord -ProcessIdentity $nativeIdentityRecord `
            -ExpectedProcessId 2147483000 -ExpectedParentProcessId ([int]$PID) `
            -ExpectedImagePath $nativeIdentityImage -ExpectedCommandLine $nativeIdentityExpectedCommand `
            -ExpectedStartTime $nativeIdentityStart
        $passed++
        $identityMismatchCases = @(
            [PSCustomObject]@{ Name = 'PID'; Property = 'ProcessId'; Value = 2147482999 },
            [PSCustomObject]@{ Name = 'parent PID'; Property = 'ParentProcessId'; Value = ([int]$PID + 1) },
            [PSCustomObject]@{ Name = 'image path'; Property = 'ImagePath'; Value = (Join-Path $root 'other.exe') },
            [PSCustomObject]@{ Name = 'command line'; Property = 'CommandLine'; Value = ($nativeIdentityExpectedCommand + ' --extra') },
            [PSCustomObject]@{ Name = 'creation time'; Property = 'CreationDate'; Value = $nativeIdentityStart.AddMilliseconds(5).ToString('o', [Globalization.CultureInfo]::InvariantCulture) },
            [PSCustomObject]@{ Name = 'verified flag'; Property = 'IdentityVerified'; Value = $false }
        )
        foreach ($case in $identityMismatchCases) {
            $mismatchedIdentity = [PSCustomObject]@{}
            foreach ($property in $nativeIdentityRecord.PSObject.Properties) {
                $mismatchedIdentity | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value
            }
            $mismatchedIdentity.($case.Property) = $case.Value
            try {
                $null = Assert-D32NativeProcessIdentityRecord -ProcessIdentity $mismatchedIdentity `
                    -ExpectedProcessId 2147483000 -ExpectedParentProcessId ([int]$PID) `
                    -ExpectedImagePath $nativeIdentityImage -ExpectedCommandLine $nativeIdentityExpectedCommand `
                    -ExpectedStartTime $nativeIdentityStart
                throw "SELFTEST_FAILED: native process identity mismatch for $($case.Name) was accepted"
            }
            catch { if ($_.Exception.Message -notlike 'PROCESS_IDENTITY_MISMATCH:*') { throw } }
            $passed++
        }

        $identityCargoPath = Join-Path $root 'cargo-identity-test.exe'
        [IO.File]::WriteAllBytes($identityCargoPath, [byte[]](0x4D, 0x5A, 0x11, 0x22))
        $identityCargoArtifact = Get-D32BoundArtifact -Path $identityCargoPath
        $identityCargoArguments = @(
            'fetch', '--locked', '--manifest-path', (Join-Path $root 'vita-agent/Cargo.toml'),
            '--target', 'x86_64-pc-windows-msvc'
        )
        $identityProfile = [PSCustomObject]@{
            Profile = [PSCustomObject]@{
                toolchain = [PSCustomObject]@{
                    cargo = [PSCustomObject]@{
                        path = $identityCargoPath
                        sha256 = $identityCargoArtifact.sha256
                        bytes = $identityCargoArtifact.bytes
                    }
                }
            }
        }
        $currentParentCargoIdentity = [PSCustomObject]@{
            IdentityVerified = $true
            ProcessId = [int]$PID + 1
            ParentProcessId = [int]$PID
            ImagePath = $identityCargoPath
            Name = 'cargo.exe'
            CommandLine = ConvertTo-D32CommandLine (@($identityCargoPath) + $identityCargoArguments)
            CreationDate = '2026-09-23T00:00:00.0000000Z'
            ObservedAtUtc = '2026-09-23T00:00:01.0000000Z'
        }
        Assert-D32PinnedCargoProcessIdentity -ProcessIdentity $currentParentCargoIdentity `
            -CargoPath $identityCargoPath -Arguments $identityCargoArguments -ValidatedProfile $identityProfile
        $passed++
        $wrongParentCargoIdentity = [PSCustomObject]@{}
        foreach ($property in $currentParentCargoIdentity.PSObject.Properties) {
            $wrongParentCargoIdentity | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value
        }
        $wrongParentCargoIdentity.ParentProcessId = if ([int]$PID -eq [int]::MaxValue) { [int]$PID - 1 } else { [int]$PID + 1 }
        try {
            Assert-D32PinnedCargoProcessIdentity -ProcessIdentity $wrongParentCargoIdentity `
                -CargoPath $identityCargoPath -Arguments $identityCargoArguments -ValidatedProfile $identityProfile
            throw 'SELFTEST_FAILED: Cargo identity with a parent other than this PowerShell process was accepted'
        }
        catch { if ($_.Exception.Message -notlike 'CARGO_PROCESS_IDENTITY_MISMATCH:*') { throw } }
        $passed++
        $unverifiedCargoIdentity = [PSCustomObject]@{ IdentityVerified = $false; ProcessId = 0; ParentProcessId = 0; ImagePath = $null; Name = $null }
        $unverifiedCargoResult = [PSCustomObject]@{
            status = 'process_tree_error'
            exit_code = $null
            error = 'DEBUG_PROCESS_TRACE_BLOCKED: root EXIT event missing'
            process_trace = [PSCustomObject]@{ state = 'BLOCKED'; block_reason = 'root EXIT event missing'; event_chain_complete = $false; accounting_consistent = $false }
        }
        $identityFailureContextPreserved = $false
        try {
            Assert-D32PinnedCargoProcessIdentity -ProcessIdentity $unverifiedCargoIdentity `
                -CargoPath $identityCargoPath -Arguments $identityCargoArguments -ValidatedProfile $identityProfile `
                -ProcessResult $unverifiedCargoResult
        }
        catch {
            $identityFailureContextPreserved = $_.Exception.Message.StartsWith('CARGO_PROCESS_IDENTITY_MISMATCH:', [StringComparison]::Ordinal) -and
                $_.Exception.Message.Contains('process_status=process_tree_error') -and
                $_.Exception.Message.Contains('process_error=DEBUG_PROCESS_TRACE_BLOCKED: root EXIT event missing') -and
                $_.Exception.Message.Contains('trace_block_reason=root EXIT event missing')
        }
        if (-not $identityFailureContextPreserved) { throw 'SELFTEST_FAILED: Cargo identity failure discarded the bounded process and V2 trace failure context' }
        $passed++

        if (-not [D32FixtureNativeProcessV2]::DebugCreateProcessIdentityMatches(713, 713, 713, $true)) {
            throw 'SELFTEST_FAILED: matching root CREATE event, process handle, and CreateProcessW PID were rejected'
        }
        $passed++
        if ([D32FixtureNativeProcessV2]::DebugCreateProcessIdentityMatches(713, 714, 713, $true)) {
            throw 'SELFTEST_FAILED: root CREATE event PID differing from the process handle PID was accepted'
        }
        $passed++
        if ([D32FixtureNativeProcessV2]::DebugCreateProcessIdentityMatches(713, 713, 714, $true)) {
            throw 'SELFTEST_FAILED: root CREATE event PID differing from CreateProcessW returned PID was accepted'
        }
        $passed++
        if ([D32FixtureNativeProcessV2]::DebugCreateProcessIdentityMatches(714, 713, 713, $false)) {
            throw 'SELFTEST_FAILED: child CREATE event PID differing from the actual process handle PID was accepted'
        }
        $passed++

        $debugRootPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $debugRootArtifact = Get-D32BoundArtifactWithFileId -Path $debugRootPath
        $debugRootImage = [PSCustomObject]@{
            Path = $debugRootArtifact.path
            Bytes = $debugRootArtifact.bytes
            Sha256 = $debugRootArtifact.sha256
            VolumeSerialHex = $debugRootArtifact.volume_serial_hex
            FileIdHex = $debugRootArtifact.file_id_hex
        }
        $debugIdentityMarker = Join-Path $root 'debug-create-mismatch-user-code.marker'
        $debugRootArguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', "Set-Content -LiteralPath '$debugIdentityMarker' -Value ran")
        $debugRootCommandLine = ConvertTo-D32CommandLine (@($debugRootPath) + $debugRootArguments)
        $debugRootProcess = $null
        $debugIdentityTrace = $null
        try {
            $debugRootProcess = [D32FixtureNativeProcessV2]::StartDebug($debugRootPath, $debugRootCommandLine, $root, $null)
            $debugRootProcess.ConfigureDebugCapture(
                (ConvertTo-D32DebugImagePinText -Image $debugRootImage), [string[]]@(), [string[]]@(), 10000, $false, $true)
            $debugIdentityTrace = $debugRootProcess.WaitForDebugTrace(15000)
            if ($debugIdentityTrace.State -cne 'BLOCKED' -or
                [bool]$debugIdentityTrace.EventChainComplete -or
                -not [bool]$debugIdentityTrace.DebuggerKillOnExitEnabled -or
                -not [bool]$debugIdentityTrace.DebuggerThreadExited -or
                -not [bool]$debugIdentityTrace.DebuggerThreadJoined -or
                [uint32]$debugIdentityTrace.UncontinuedCreateProcessId -le 0 -or
                [int]$debugIdentityTrace.UncontinuedCreateContinueCallCount -ne 0 -or
                [int]$debugRootProcess.DebugContinueCallCount -ne 0 -or
                (Test-Path -LiteralPath $debugIdentityMarker) -or
                $debugIdentityTrace.BlockReason -notmatch 'CREATE_PROCESS_DEBUG_EVENT PID differs') {
                throw "SELFTEST_FAILED: injected root CREATE PID mismatch did not terminate and stop before ContinueDebugEvent: state=$($debugIdentityTrace.State); chain_complete=$($debugIdentityTrace.EventChainComplete); continue_calls=$($debugRootProcess.DebugContinueCallCount); reason=$($debugIdentityTrace.BlockReason)"
            }
        }
        finally {
            if ($null -ne $debugRootProcess) {
                $debugIdentityCleanup = $debugRootProcess.CloseJobAndWait(10000)
                if (-not [bool]$debugIdentityCleanup.CleanupSucceeded -or
                    -not [bool]$debugIdentityCleanup.ProcessWaitSignaled -or
                    -not [bool]$debugIdentityCleanup.DebuggerThreadExited -or
                    -not [bool]$debugIdentityCleanup.DebuggerThreadJoined -or
                    -not [bool]$debugIdentityCleanup.DebuggerKillOnExitEnabled -or
                    -not [bool]$debugIdentityCleanup.RetainedProcessHandlesSignaled -or
                    -not [bool]$debugIdentityCleanup.DebuggerAssociationQueryVerified -or
                    -not [bool]$debugIdentityCleanup.DebuggerAssociationAbsent -or
                    -not [bool]$debugIdentityCleanup.JobCloseSucceeded -or
                    -not [bool]$debugIdentityCleanup.JobTerminateCallSucceeded -or
                    -not [bool]$debugIdentityCleanup.JobActiveProcessCountVerified -or
                    [uint32]$debugIdentityCleanup.JobActiveProcessCount -ne 0 -or
                    [uint32]$debugIdentityTrace.JobActiveProcesses -ne 0 -or
                    (Test-Path -LiteralPath $debugIdentityMarker)) {
                    throw "SELFTEST_FAILED: injected root CREATE PID mismatch did not prove joined thread/process/debugger/Job cleanup with no user-code marker: $($debugIdentityCleanup.Detail); process_signaled=$($debugIdentityCleanup.ProcessWaitSignaled); debugger_joined=$($debugIdentityCleanup.DebuggerThreadJoined); handles_signaled=$($debugIdentityCleanup.RetainedProcessHandlesSignaled); debugger_absent=$($debugIdentityCleanup.DebuggerAssociationAbsent); terminate_succeeded=$($debugIdentityCleanup.JobTerminateCallSucceeded); active_count=$($debugIdentityCleanup.JobActiveProcessCount); active_count_verified=$($debugIdentityCleanup.JobActiveProcessCountVerified); active_count_error=$($debugIdentityCleanup.JobActiveProcessCountLastError)"
                }
                Write-Host "D32_CREATE_ID_MISMATCH_NEGATIVE=PASS continue_calls=$($debugRootProcess.DebugContinueCallCount) marker_absent=$(-not (Test-Path -LiteralPath $debugIdentityMarker)) debugger_joined=$($debugIdentityCleanup.DebuggerThreadJoined) retained_process_handles_signaled=$($debugIdentityCleanup.RetainedProcessHandlesSignaled) debugger_absent=$($debugIdentityCleanup.DebuggerAssociationAbsent) job_active=$($debugIdentityCleanup.JobActiveProcessCount) root_process_signaled=$($debugIdentityCleanup.ProcessWaitSignaled)"
                $debugRootProcess.Dispose()
            }
        }
        $passed++

        $windowsDirectory = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows))
        $systemDirectory = Join-Path $windowsDirectory 'System32'
        $compilerPath = Join-Path $windowsDirectory 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        if (-not (Test-Path -LiteralPath $compilerPath -PathType Leaf)) { $compilerPath = Join-Path $windowsDirectory 'Microsoft.NET/Framework/v4.0.30319/csc.exe' }
        $compilerPath = Assert-D32NoReparsePath -Path $compilerPath
        $debugLauncherSourcePath = Join-Path $root 'd32-debug-selftest-launcher.cs'
        $debugLauncherPath = Join-Path $root 'd32-debug-selftest-launcher.exe'
        $debugLauncherSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

public static class D32DebugSelfTestLauncher
{
    private static string Quote(string value)
    {
        if (value.Length > 0 && value.IndexOfAny(new char[] { ' ', '\t', '"' }) < 0) return value;
        StringBuilder output = new StringBuilder();
        output.Append('"');
        int slashes = 0;
        foreach (char c in value)
        {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { output.Append('\\', slashes * 2 + 1); output.Append('"'); slashes = 0; continue; }
            output.Append('\\', slashes); slashes = 0; output.Append(c);
        }
        output.Append('\\', slashes * 2); output.Append('"');
        return output.ToString();
    }

    private static Process Start(string image, string[] arguments)
    {
        StringBuilder command = new StringBuilder();
        for (int i = 0; i < arguments.Length; i++)
        {
            if (i != 0) command.Append(' ');
            command.Append(Quote(arguments[i]));
        }
        ProcessStartInfo start = new ProcessStartInfo();
        start.FileName = image;
        start.Arguments = command.ToString();
        start.WorkingDirectory = Environment.CurrentDirectory;
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        return Process.Start(start);
    }

    public static int Main(string[] args)
    {
        if (args == null || args.Length < 2) return 41;
        string mode = args[0];
        File.WriteAllText(args[1], "root-ran");
        string system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
        if (mode == "spawn-churn")
        {
            Process[] children = new Process[16];
            for (int i = 0; i < children.Length; i++)
                children[i] = Start(Path.Combine(system, "where.exe"), new string[] { "D32_SELFTEST_NO_MATCH" });
            foreach (Process child in children)
            {
                if (!child.WaitForExit(10000)) return 42;
                child.Dispose();
            }
            return 0;
        }
        if (mode == "spawn-unknown")
        {
            using (Process child = Start(Path.Combine(system, "whoami.exe"), new string[0]))
                return child.WaitForExit(10000) ? 0 : 43;
        }
        if (mode == "spawn-vctip")
        {
            if (args.Length < 4) return 46;
            using (Process child = Start(args[2], new string[] { "exit", args[3] }))
                return child.WaitForExit(10000) ? 0 : 47;
        }
        if (mode == "spawn-protoc")
        {
            if (args.Length < 4) return 48;
            using (Process child = Start(args[2], new string[] { "exit", args[3] }))
                return child.WaitForExit(10000) ? 0 : 49;
        }
        if (mode == "spawn-git")
        {
            if (args.Length < 4) return 50;
            using (Process child = Start(args[2], new string[] { "exit", args[3] }))
                return child.WaitForExit(10000) ? 0 : 51;
        }
        if (mode == "spawn-cmd")
        {
            if (args.Length < 3) return 44;
            using (Process child = Start(Path.Combine(system, "cmd.exe"), new string[] { "/d", "/c", args[2] }))
                return child.WaitForExit(10000) ? 0 : 45;
        }
        return 0;
    }
}
'@
        [IO.File]::WriteAllText($debugLauncherSourcePath, $debugLauncherSource, [Text.UTF8Encoding]::new($false))
        $savedCompilerLib = [Environment]::GetEnvironmentVariable('LIB', 'Process')
        try {
            [Environment]::SetEnvironmentVariable('LIB', $null, 'Process')
            $compilerStart = [Diagnostics.ProcessStartInfo]::new()
            $compilerStart.FileName = $compilerPath
            $compilerStart.Arguments = ConvertTo-D32CommandLine @('/nologo', "/out:$debugLauncherPath", $debugLauncherSourcePath)
            $compilerStart.WorkingDirectory = $root
            $compilerStart.UseShellExecute = $false
            $compilerStart.CreateNoWindow = $true
            $compilerProcess = [Diagnostics.Process]::Start($compilerStart)
            if (-not $compilerProcess.WaitForExit(30000) -or $compilerProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $debugLauncherPath -PathType Leaf)) {
                throw 'SELFTEST_FAILED: pinned local .NET Framework compiler did not create the debug-abort test launcher'
            }
            $compilerProcess.Dispose()
        }
        finally { [Environment]::SetEnvironmentVariable('LIB', $savedCompilerLib, 'Process') }
        $debugLauncherArtifact = Get-D32BoundArtifactWithFileId -Path $debugLauncherPath
        $debugLauncherImage = [PSCustomObject]@{
            Path = $debugLauncherArtifact.path; Bytes = $debugLauncherArtifact.bytes; Sha256 = $debugLauncherArtifact.sha256
            VolumeSerialHex = $debugLauncherArtifact.volume_serial_hex; FileIdHex = $debugLauncherArtifact.file_id_hex
        }
        $debugLauncherPin = ConvertTo-D32DebugImagePinText -Image $debugLauncherImage
        $wherePath = Join-Path $systemDirectory 'where.exe'
        $whereArtifact = Get-D32BoundArtifactWithFileId -Path $wherePath
        $whereImage = [PSCustomObject]@{
            Path = $whereArtifact.path; Bytes = $whereArtifact.bytes; Sha256 = $whereArtifact.sha256
            VolumeSerialHex = $whereArtifact.volume_serial_hex; FileIdHex = $whereArtifact.file_id_hex
        }
        $wherePin = ConvertTo-D32DebugImagePinText -Image $whereImage
        $consoleHostArtifact = Get-D32BoundArtifactWithFileId -Path (Join-Path $systemDirectory 'conhost.exe')
        $consoleHostImage = [PSCustomObject]@{
            Path = $consoleHostArtifact.path; Bytes = $consoleHostArtifact.bytes; Sha256 = $consoleHostArtifact.sha256
            VolumeSerialHex = $consoleHostArtifact.volume_serial_hex; FileIdHex = $consoleHostArtifact.file_id_hex
        }
        $consoleHostPin = ConvertTo-D32DebugImagePinText -Image $consoleHostImage
        $cargoPolicyRoot = 'C:\selftest-profile\bin\cargo.exe'
        $cargoPolicyPin = @($cargoPolicyRoot, '1', ('a' * 64), ('0' * 16), ('0' * 32)) -join "`t"
        $vctipPolicyPath = 'E:\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\vctip.exe'
        $vctipPolicyPin = @(
            $vctipPolicyPath,
            '335328', 'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996',
            '749614a1961465c0', '0b5d2000000001000000000000000000'
        ) -join "`t"
        $exactVctipConfigAccepted = [D32FixtureNativeProcessV2]::IsApprovedPinnedCargoVctipConfiguration($cargoPolicyPin, @($vctipPolicyPin))
        $exactVctipChildAccepted = [D32FixtureNativeProcessV2]::IsPinnedCargoVctipChildAllowed(
            $cargoPolicyRoot, $true,
            $vctipPolicyPath, 335328,
            'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996',
            '749614a1961465c0', '0b5d2000000001000000000000000000', @($vctipPolicyPin))
        $invalidVctipPins = @(
            @('E:\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\vctip.exe', '335329', 'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996', '749614a1961465c0', '0b5d2000000001000000000000000000') -join "`t",
            @('E:\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\vctip.exe', '335328', ('0' * 64), '749614a1961465c0', '0b5d2000000001000000000000000000') -join "`t",
            @('E:\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\vctip.exe', '335328', 'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996', '749614a1961465c1', '0b5d2000000001000000000000000000') -join "`t",
            @('E:\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\vctip.exe', '335328', 'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996', '749614a1961465c0', '0b5d2000000001000000000000000001') -join "`t",
            @('E:\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\vctip-copy.exe', '335328', 'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996', '749614a1961465c0', '0b5d2000000001000000000000000001') -join "`t"
        )
        $vctipInvalidPinsRejected = @($invalidVctipPins | Where-Object {
            [D32FixtureNativeProcessV2]::IsApprovedPinnedCargoVctipConfiguration($cargoPolicyPin, @($_)) -or
            [D32FixtureNativeProcessV2]::IsPinnedCargoVctipChildAllowed($cargoPolicyRoot, $true,
                'E:\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\vctip.exe', 335328,
                'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996',
                '749614a1961465c0', '0b5d2000000001000000000000000000', @($_))
        }).Count -eq 0
        $vctipNegativePolicyValid = -not [D32FixtureNativeProcessV2]::IsPinnedCargoVctipChildAllowed(
            $cargoPolicyRoot, $false, 'E:\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\vctip.exe', 335328,
            'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996',
            '749614a1961465c0', '0b5d2000000001000000000000000000', @($vctipPolicyPin)) -and
            -not [D32FixtureNativeProcessV2]::IsPinnedCargoVctipChildAllowed(
                'C:\\selftest-profile\\bin\\other.exe', $true, 'E:\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\vctip.exe', 335328,
                'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996',
                '749614a1961465c0', '0b5d2000000001000000000000000000', @($vctipPolicyPin)) -and
            -not [D32FixtureNativeProcessV2]::IsPinnedCargoVctipChildAllowed(
                $cargoPolicyRoot, $true, 'E:\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\vctip-copy.exe', 335328,
                'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996',
                '749614a1961465c0', '0b5d2000000001000000000000000000', @($vctipPolicyPin))
        $duplicateVctipPinRejected = -not [D32FixtureNativeProcessV2]::IsApprovedPinnedCargoVctipConfiguration($cargoPolicyPin, @($vctipPolicyPin, $invalidVctipPins[-1]))
        $tab = [string][char]9
        $canonicalInvalidVctipPins = @(
            @($vctipPolicyPath, '335329', 'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996', '749614a1961465c0', '0b5d2000000001000000000000000000') -join $tab,
            @($vctipPolicyPath, '335328', ('0' * 64), '749614a1961465c0', '0b5d2000000001000000000000000000') -join $tab,
            @($vctipPolicyPath, '335328', 'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996', '749614a1961465c1', '0b5d2000000001000000000000000000') -join $tab,
            @($vctipPolicyPath, '335328', 'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996', '749614a1961465c0', '0b5d2000000001000000000000000001') -join $tab
        )
        $canonicalVctipDriftRejected = @($canonicalInvalidVctipPins | Where-Object {
            [D32FixtureNativeProcessV2]::IsApprovedPinnedCargoVctipConfiguration($cargoPolicyPin, @($_)) -or
            [D32FixtureNativeProcessV2]::IsPinnedCargoVctipChildAllowed($cargoPolicyRoot, $true,
                $vctipPolicyPath, 335328, 'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996',
                '749614a1961465c0', '0b5d2000000001000000000000000000', @($_))
        }).Count -eq 0
        $canonicalCopiedVctipPathRejected = -not [D32FixtureNativeProcessV2]::IsPinnedCargoVctipChildAllowed(
            $cargoPolicyRoot, $true, $vctipPolicyPath.Replace('vctip.exe', 'vctip-copy.exe'), 335328,
            'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996',
            '749614a1961465c0', '0b5d2000000001000000000000000000', @($vctipPolicyPin))
        if (-not $exactVctipConfigAccepted -or -not $exactVctipChildAccepted -or -not $vctipInvalidPinsRejected -or
            -not $vctipNegativePolicyValid -or -not $duplicateVctipPinRejected -or
            -not $canonicalVctipDriftRejected -or -not $canonicalCopiedVctipPathRejected) {
            throw "SELFTEST_FAILED: exact caller-pinned Cargo/VCTIP policy admitted drift/copy or rejected the approved identity (config=$exactVctipConfigAccepted child=$exactVctipChildAccepted invalid=$vctipInvalidPinsRejected negative=$vctipNegativePolicyValid duplicate=$duplicateVctipPinRejected canonicalDrift=$canonicalVctipDriftRejected copiedPath=$canonicalCopiedVctipPathRejected)"
        }
        Write-Host 'D32_VCTIP_POLICY=PASS exact_profile_record_and_opened_identity_only; drift_copy_wrong_root_and_unpermitted_denied'
        $passed++
        $protocPolicyCargoHome = Join-Path $root 'protoc-policy-cargo-home'
        $protocPolicyPath = Join-Path $protocPolicyCargoHome 'registry\src\index.crates.io-1949cf8c6b5b557f\protoc-bin-vendored-win32-3.2.0\bin\protoc.exe'
        $protocPolicyImage = [PSCustomObject]@{
            Path = $protocPolicyPath; Bytes = [Int64]11934496
            Sha256 = 'cbd1ca1fd6afd1bb6ddd1c09c118ecd4c50f928980857f16fe6fc23704ea17e2'
            VolumeSerialHex = '0123456789abcdef'; FileIdHex = '0123456789abcdef0123456789abcdef'
        }
        $protocPolicyPin = ConvertTo-D32DebugImagePinText -Image $protocPolicyImage
        $protocPolicyPins = @($vctipPolicyPin, $protocPolicyPin)
        $exactProtocConfigAccepted = [D32FixtureNativeProcessV2]::IsApprovedPinnedCargoVendoredProtocConfiguration(
            $cargoPolicyPin, [string[]]$protocPolicyPins, $protocPolicyCargoHome, $protocPolicyPin)
        $exactProtocChildAccepted = [D32FixtureNativeProcessV2]::IsPinnedCargoVendoredProtocChildAllowed(
            $cargoPolicyRoot, $true, $protocPolicyPath, [Int64]$protocPolicyImage.Bytes, $protocPolicyImage.Sha256,
            $protocPolicyImage.VolumeSerialHex, $protocPolicyImage.FileIdHex, $protocPolicyCargoHome, $protocPolicyPin)
        $protocPolicyNegatives = @(
            -not [D32FixtureNativeProcessV2]::IsApprovedPinnedCargoVendoredProtocConfiguration($cargoPolicyPin, [string[]]$protocPolicyPins, (Join-Path $root 'stale-cargo-home'), $protocPolicyPin),
            -not [D32FixtureNativeProcessV2]::IsApprovedPinnedCargoVendoredProtocConfiguration($cargoPolicyPin, [string[]](@($protocPolicyPins) + @($protocPolicyPin)), $protocPolicyCargoHome, $protocPolicyPin),
            -not [D32FixtureNativeProcessV2]::IsPinnedCargoVendoredProtocChildAllowed($cargoPolicyRoot, $false, $protocPolicyPath, [Int64]$protocPolicyImage.Bytes, $protocPolicyImage.Sha256, $protocPolicyImage.VolumeSerialHex, $protocPolicyImage.FileIdHex, $protocPolicyCargoHome, $protocPolicyPin),
            -not [D32FixtureNativeProcessV2]::IsPinnedCargoVendoredProtocChildAllowed('C:\\other\\not-cargo.exe', $true, $protocPolicyPath, [Int64]$protocPolicyImage.Bytes, $protocPolicyImage.Sha256, $protocPolicyImage.VolumeSerialHex, $protocPolicyImage.FileIdHex, $protocPolicyCargoHome, $protocPolicyPin),
            -not [D32FixtureNativeProcessV2]::IsPinnedCargoVendoredProtocChildAllowed($cargoPolicyRoot, $true, $protocPolicyPath, [Int64]$protocPolicyImage.Bytes + 1, $protocPolicyImage.Sha256, $protocPolicyImage.VolumeSerialHex, $protocPolicyImage.FileIdHex, $protocPolicyCargoHome, $protocPolicyPin),
            -not [D32FixtureNativeProcessV2]::IsPinnedCargoVendoredProtocChildAllowed($cargoPolicyRoot, $true, $protocPolicyPath, [Int64]$protocPolicyImage.Bytes, ('0' * 64), $protocPolicyImage.VolumeSerialHex, $protocPolicyImage.FileIdHex, $protocPolicyCargoHome, $protocPolicyPin),
            -not [D32FixtureNativeProcessV2]::IsPinnedCargoVendoredProtocChildAllowed($cargoPolicyRoot, $true, $protocPolicyPath, [Int64]$protocPolicyImage.Bytes, $protocPolicyImage.Sha256, '0123456789abcdee', $protocPolicyImage.FileIdHex, $protocPolicyCargoHome, $protocPolicyPin),
            -not [D32FixtureNativeProcessV2]::IsPinnedCargoVendoredProtocChildAllowed($cargoPolicyRoot, $true, $protocPolicyPath, [Int64]$protocPolicyImage.Bytes, $protocPolicyImage.Sha256, $protocPolicyImage.VolumeSerialHex, '0123456789abcdef0123456789abcdef1', $protocPolicyCargoHome, $protocPolicyPin),
            -not [D32FixtureNativeProcessV2]::IsPinnedCargoVendoredProtocChildAllowed($cargoPolicyRoot, $true, $protocPolicyPath.Replace('protoc.exe', 'protoc-copy.exe'), [Int64]$protocPolicyImage.Bytes, $protocPolicyImage.Sha256, $protocPolicyImage.VolumeSerialHex, $protocPolicyImage.FileIdHex, $protocPolicyCargoHome, $protocPolicyPin)
        )
        if (-not $exactProtocConfigAccepted -or -not $exactProtocChildAccepted -or @($protocPolicyNegatives | Where-Object { -not $_ }).Count -ne 0) {
            throw "SELFTEST_FAILED: locked protoc native admission was not unique, exact-home, exact-image, and fail-closed (config=$exactProtocConfigAccepted child=$exactProtocChildAccepted negatives=$(@($protocPolicyNegatives | Where-Object { -not $_ }).Count))"
        }
        Write-Host 'D32_VENDORED_PROTOC_POLICY=PASS exact_per_run_CargoHome_and_opened_identity_only; stale_home_duplicate_alias_drift_wrong_root_and_unpermitted_denied'
        $passed++
        $h7NativeType = [D32FixtureNativeProcessV2]
        $h7SlotType = $h7NativeType.GetNestedType('H7CGitSlotPolicy', [System.Reflection.BindingFlags]::NonPublic)
        $h7Slot = [Activator]::CreateInstance($h7SlotType, $true)
        $h7TempPath = Join-Path $root 'h7-environment-temp'
        $h7SlotPath = Join-Path $h7TempPath 'd32-h7c-slot-01'
        $h7HomePath = Join-Path $h7SlotPath 'git-home'
        $h7ConfigPath = Join-Path $h7HomePath 'empty.gitconfig'
        $setH7PrivateField = {
            param([object]$Target, [string]$Name, [object]$Value)
            $field = $Target.GetType().GetField($Name, [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::NonPublic)
            if ($null -eq $field) { throw "SELFTEST_FAILED: H7-C private native policy field is absent: $Name" }
            $field.SetValue($Target, $Value)
        }.GetNewClosure()
        & $setH7PrivateField $h7Slot 'Path' $h7SlotPath
        & $setH7PrivateField $h7Slot 'EmptyConfig' $h7ConfigPath
        & $setH7PrivateField $h7Slot 'GitHome' $h7HomePath
        $h7StatusMap = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
        $h7WindowsRoot = [Environment]::GetEnvironmentVariable('SystemRoot')
        $h7StatusMap.Add('ComSpec', (Join-Path (Join-Path $h7WindowsRoot 'System32') 'cmd.exe'))
        $h7StatusMap.Add('GCM_INTERACTIVE', 'Never')
        $h7StatusMap.Add('GIT_CEILING_DIRECTORIES', $h7SlotPath)
        $h7StatusMap.Add('GIT_CONFIG_GLOBAL', $h7ConfigPath)
        $h7StatusMap.Add('GIT_CONFIG_NOSYSTEM', '1')
        $h7StatusMap.Add('GIT_OPTIONAL_LOCKS', '0')
        $h7StatusMap.Add('GIT_TERMINAL_PROMPT', '0')
        $h7StatusMap.Add('HOME', $h7HomePath)
        $h7StatusMap.Add('SystemDrive', ([IO.Path]::GetPathRoot($h7WindowsRoot)).TrimEnd('\'))
        $h7StatusMap.Add('SystemRoot', $h7WindowsRoot)
        $h7StatusMap.Add('windir', $h7WindowsRoot)
        $h7EnvironmentMethod = $h7NativeType.GetMethod('RequireH7CGitEnvironment', [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic)
        if ($null -eq $h7EnvironmentMethod) { throw 'SELFTEST_FAILED: H7-C native environment validator is absent' }
        $h7EnvironmentMethod.Invoke($null, [object[]]@($h7StatusMap, $null, $h7Slot, $true))
        $h7MissingMap = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($key in $h7StatusMap.Keys) { $h7MissingMap.Add([string]$key, [string]$h7StatusMap[$key]) }
        $null = $h7MissingMap.Remove('GIT_CONFIG_GLOBAL')
        $h7MissingMapRejected = $false
        try { $h7EnvironmentMethod.Invoke($null, [object[]]@($h7MissingMap, $null, $h7Slot, $true)) }
        catch { $h7MissingMapRejected = $_.Exception.GetBaseException().Message -like '*missing or extra keys*' }
        $h7ExtraMap = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($key in $h7StatusMap.Keys) { $h7ExtraMap.Add([string]$key, [string]$h7StatusMap[$key]) }
        $h7ExtraMap.Add('PATH', 'C:\unexpected')
        $h7ExtraMapRejected = $false
        try { $h7EnvironmentMethod.Invoke($null, [object[]]@($h7ExtraMap, $null, $h7Slot, $true)) }
        catch { $h7ExtraMapRejected = $_.Exception.GetBaseException().Message -like '*missing or extra keys*' }
        if (-not $h7MissingMapRejected -or -not $h7ExtraMapRejected) { throw 'SELFTEST_FAILED: H7-C native status environment did not reject missing/extra keys' }
        Write-Host 'D32_H7C_NATIVE_ENVIRONMENT=PASS actual ComSpec casing and case-insensitive canonical path are accepted; missing/extra keys remain denied'
        $passed++
        $jobFlagsPolicyValid = [D32FixtureNativeProcessV2]::HasRequiredNonBreakawayJobFlags(0x00002000) -and
            -not [D32FixtureNativeProcessV2]::HasRequiredNonBreakawayJobFlags(0x00002800) -and
            -not [D32FixtureNativeProcessV2]::HasRequiredNonBreakawayJobFlags(0x00003000) -and
            -not [D32FixtureNativeProcessV2]::HasRequiredNonBreakawayJobFlags(0x00002004)
        if (-not $jobFlagsPolicyValid) { throw 'SELFTEST_FAILED: owned Job admitted breakaway or non-contract extended flags' }
        Write-Host 'D32_JOB_NONBREAKAWAY_FLAGS=PASS exact_kill_on_close_only'
        $passed++
        $debugScriptDirectory = Join-Path $root 'script-bin'
        [void](New-Item -ItemType Directory -Path $debugScriptDirectory)
        $cmdScriptPath = Join-Path $debugScriptDirectory 'd32-debug-no-launch.cmd'
        $cmdScriptMarker = Join-Path $root 'd32-debug-cmd-user-code.marker'
        [IO.File]::WriteAllText($cmdScriptPath, "@echo off`r`necho ran > `"$cmdScriptMarker`"`r`n", [Text.UTF8Encoding]::new($false))
        $debugTestEnvironment = ConvertTo-D32EnvironmentBlock ([ordered]@{
            SystemRoot = $windowsDirectory
            TEMP = $root
            TMP = $root
            PATH = $debugScriptDirectory + ';' + $systemDirectory
        })

        $debugAbortCases = @(
            [PSCustomObject]@{ Name = 'null-image-file'; Injection = 'null-image-file'; Interruption = $false; ExpectUncontinuedCreate = $true; ExpectedPin = $debugLauncherPin; Args = @('exit', (Join-Path $root 'd32-null-hfile-root.marker')); Marker = (Join-Path $root 'd32-null-hfile-root.marker') },
            [PSCustomObject]@{ Name = 'unknown-root-image'; Injection = $null; Interruption = $false; ExpectUncontinuedCreate = $true; ExpectedPin = $wherePin; Args = @('exit', (Join-Path $root 'd32-unknown-image-root.marker')); Marker = (Join-Path $root 'd32-unknown-image-root.marker') },
            [PSCustomObject]@{ Name = 'root-parent-mismatch'; Injection = 'root-parent-mismatch'; Interruption = $false; ExpectUncontinuedCreate = $true; ExpectedPin = $debugLauncherPin; Args = @('exit', (Join-Path $root 'd32-parent-mismatch-root.marker')); Marker = (Join-Path $root 'd32-parent-mismatch-root.marker') },
            [PSCustomObject]@{ Name = 'debug-chain-interruption'; Injection = $null; Interruption = $true; ExpectUncontinuedCreate = $true; ExpectedPin = $debugLauncherPin; Args = @('exit', (Join-Path $root 'd32-interruption-root.marker')); Marker = (Join-Path $root 'd32-interruption-root.marker') },
            [PSCustomObject]@{ Name = 'WaitForDebugEvent-API-error'; Injection = 'wait-api-failure'; Interruption = $false; ExpectUncontinuedCreate = $false; ExpectedPin = $debugLauncherPin; Args = @('exit', (Join-Path $root 'd32-wait-error-root.marker')); Marker = (Join-Path $root 'd32-wait-error-root.marker') },
            [PSCustomObject]@{ Name = 'WaitForDebugEvent-timeout'; Injection = 'wait-timeout'; Interruption = $false; ExpectUncontinuedCreate = $false; ExpectedPin = $debugLauncherPin; Args = @('exit', (Join-Path $root 'd32-wait-timeout-root.marker')); Marker = (Join-Path $root 'd32-wait-timeout-root.marker') },
            [PSCustomObject]@{ Name = 'ContinueDebugEvent-API-error'; Injection = 'continue-api-failure'; Interruption = $false; ExpectUncontinuedCreate = $true; ExpectedPin = $debugLauncherPin; Args = @('exit', (Join-Path $root 'd32-continue-error-root.marker')); Marker = (Join-Path $root 'd32-continue-error-root.marker') }
        )
        foreach ($case in $debugAbortCases) {
            $caseResult = Invoke-D32DebugSelfTestProcess -FilePath $debugLauncherPath -Arguments $case.Args -WorkingDirectory $root `
                -ExpectedRootPin $case.ExpectedPin -EnvironmentBlock $debugTestEnvironment -InjectFirstCreateInterruption $case.Interruption `
                -FailureInjection $case.Injection
            $cleanup = $caseResult.Cleanup
            $uncontinuedCreateRequired = [bool]$case.ExpectUncontinuedCreate
            if ($caseResult.Trace.State -cne 'BLOCKED' -or $caseResult.ContinueCalls -ne 0 -or
                ($uncontinuedCreateRequired -and [uint32]$caseResult.Trace.UncontinuedCreateProcessId -le 0) -or
                (-not $uncontinuedCreateRequired -and [uint32]$caseResult.Trace.UncontinuedCreateProcessId -ne 0) -or
                [int]$caseResult.Trace.UncontinuedCreateContinueCallCount -ne 0 -or
                (Test-Path -LiteralPath $case.Marker) -or
                -not $cleanup.CleanupSucceeded -or -not $cleanup.ProcessWaitSignaled -or -not $cleanup.DebuggerThreadExited -or
                -not $cleanup.DebuggerThreadJoined -or -not $cleanup.DebuggerKillOnExitEnabled -or
                -not $cleanup.RetainedProcessHandlesSignaled -or -not $cleanup.DebuggerAssociationQueryVerified -or
                -not $cleanup.DebuggerAssociationAbsent -or -not $cleanup.JobActiveProcessCountVerified -or
                [uint32]$cleanup.JobActiveProcessCount -ne 0) {
                throw "SELFTEST_FAILED: debug abort case '$($case.Name)' lacks zero-Continue/no-user-code/thread/handle/debugger/Job proof: trace=$($caseResult.Trace.BlockReason); cleanup=$($cleanup.Detail); continues=$($caseResult.ContinueCalls); uncontinued=$($caseResult.Trace.UncontinuedCreateProcessId); marker=$([bool](Test-Path -LiteralPath $case.Marker))"
            }
            Write-Host "D32_DEBUG_ABORT_NEGATIVE=$($case.Name):PASS uncontinued_create_calls=$($caseResult.Trace.UncontinuedCreateContinueCallCount) debugger_joined=$($cleanup.DebuggerThreadJoined) handles_signaled=$($cleanup.RetainedProcessHandlesSignaled) debugger_absent=$($cleanup.DebuggerAssociationAbsent) job_active=$($cleanup.JobActiveProcessCount)"
            $passed++
        }

        $unknownRootMarker = Join-Path $root 'd32-unknown-child-root.marker'
        $unknownChild = Invoke-D32DebugSelfTestProcess -FilePath $debugLauncherPath -Arguments @('spawn-unknown', $unknownRootMarker) -WorkingDirectory $root `
            -ExpectedRootPin $debugLauncherPin -ApprovedImagePins @($consoleHostPin) -EnvironmentBlock $debugTestEnvironment
        if ($unknownChild.Trace.State -cne 'BLOCKED' -or $unknownChild.Trace.BlockReason -notmatch 'unknown child/helper image' -or
            [uint32]$unknownChild.Trace.UncontinuedCreateProcessId -le 0 -or [int]$unknownChild.Trace.UncontinuedCreateContinueCallCount -ne 0 -or
            $unknownChild.ContinueCalls -le 0 -or -not (Test-Path -LiteralPath $unknownRootMarker) -or
            -not $unknownChild.Cleanup.CleanupSucceeded -or -not $unknownChild.Cleanup.DebuggerThreadJoined -or
            -not $unknownChild.Cleanup.RetainedProcessHandlesSignaled -or -not $unknownChild.Cleanup.DebuggerAssociationAbsent -or
            [uint32]$unknownChild.Cleanup.JobActiveProcessCount -ne 0) {
            throw "SELFTEST_FAILED: unknown child/helper was not blocked at its unvalidated CREATE with full cleanup: $($unknownChild.Trace.BlockReason); $($unknownChild.Cleanup.Detail)"
        }
        $passed++

        $copiedVctipPath = Join-Path $root 'vctip.exe'
        [IO.File]::Copy($debugLauncherPath, $copiedVctipPath)
        $copiedVctipRootMarker = Join-Path $root 'd32-copied-vctip-root.marker'
        $copiedVctipChildMarker = Join-Path $root 'd32-copied-vctip-child.marker'
        $copiedVctipAttempt = Invoke-D32DebugSelfTestProcess -FilePath $debugLauncherPath `
            -Arguments @('spawn-vctip', $copiedVctipRootMarker, $copiedVctipPath, $copiedVctipChildMarker) `
            -WorkingDirectory $root -ExpectedRootPin $debugLauncherPin -ApprovedImagePins @($consoleHostPin) -EnvironmentBlock $debugTestEnvironment
        if ($copiedVctipAttempt.Trace.State -cne 'BLOCKED' -or
            $copiedVctipAttempt.Trace.BlockReason -notmatch 'MSVC VCTIP descendant does not match the exact caller-pinned Profile V2 entry' -or
            [uint32]$copiedVctipAttempt.Trace.UncontinuedCreateProcessId -le 0 -or
            [int]$copiedVctipAttempt.Trace.UncontinuedCreateContinueCallCount -ne 0 -or
            $copiedVctipAttempt.ContinueCalls -le 0 -or -not (Test-Path -LiteralPath $copiedVctipRootMarker) -or
            (Test-Path -LiteralPath $copiedVctipChildMarker) -or
            -not $copiedVctipAttempt.Cleanup.CleanupSucceeded -or -not $copiedVctipAttempt.Cleanup.ProcessWaitSignaled -or
            -not $copiedVctipAttempt.Cleanup.DebuggerThreadExited -or -not $copiedVctipAttempt.Cleanup.DebuggerThreadJoined -or
            -not $copiedVctipAttempt.Cleanup.DebuggerKillOnExitEnabled -or -not $copiedVctipAttempt.Cleanup.RetainedProcessHandlesSignaled -or
            -not $copiedVctipAttempt.Cleanup.DebuggerAssociationQueryVerified -or -not $copiedVctipAttempt.Cleanup.DebuggerAssociationAbsent -or
            -not $copiedVctipAttempt.Cleanup.JobActiveProcessCountVerified -or [uint32]$copiedVctipAttempt.Cleanup.JobActiveProcessCount -ne 0) {
            throw "SELFTEST_FAILED: copied/unprofiled VCTIP did not remain uncontinued with no child marker and complete V2 cleanup: $($copiedVctipAttempt.Trace.BlockReason); $($copiedVctipAttempt.Cleanup.Detail)"
        }
        Write-Host 'D32_VCTIP_NEGATIVE=copied_unprofiled_child:PASS uncontinued_create_calls=0 child_marker=false job_active=0'
        $passed++

        $protocUnapprovedPath = Join-Path $root 'protoc.exe'
        [IO.File]::Copy($debugLauncherPath, $protocUnapprovedPath)
        $protocRootMarker = Join-Path $root 'd32-unapproved-protoc-root.marker'
        $protocChildMarker = Join-Path $root 'd32-unapproved-protoc-child.marker'
        $protocCreateDenied = Invoke-D32DebugSelfTestProcess -FilePath $debugLauncherPath `
            -Arguments @('spawn-protoc', $protocRootMarker, $protocUnapprovedPath, $protocChildMarker) `
            -WorkingDirectory $root -ExpectedRootPin $debugLauncherPin -ApprovedImagePins @($consoleHostPin) -EnvironmentBlock $debugTestEnvironment
        $protocDeniedTrace = ConvertTo-D32DebugProcessTraceDocument -Trace $protocCreateDenied.Trace
        $protocDeniedIdentityDetail = [string]$protocDeniedTrace.block_reason
        $protocCreateIdentityBound = $protocDeniedIdentityDetail.Contains('child_process_id=') -and
            $protocDeniedIdentityDetail.Contains('child_creation_filetime=') -and
            $protocDeniedIdentityDetail.Contains('parent_process_id=') -and
            $protocDeniedIdentityDetail.Contains('parent_creation_filetime=') -and
            $protocDeniedIdentityDetail.Contains('parent_image_path=') -and
            $protocDeniedIdentityDetail.Contains('opened_child_path=') -and
            $protocDeniedIdentityDetail.Contains('opened_child_sha256=') -and
            $protocDeniedIdentityDetail.Contains('opened_child_volume=') -and
            $protocDeniedIdentityDetail.Contains('opened_child_file_id=')
        $protocDeniedImageSnapshot = Get-D32ProfileFileSnapshot -Path $protocUnapprovedPath
        $protocCreateIdentityBound = $protocCreateIdentityBound -and
            $protocDeniedIdentityDetail.Contains('opened_child_path=' + $protocDeniedImageSnapshot.Path) -and
            $protocDeniedIdentityDetail.Contains('opened_child_sha256=' + $protocDeniedImageSnapshot.Sha256) -and
            $protocDeniedIdentityDetail.Contains('parent_image_path=' + $debugLauncherImage.Path)
        if ($protocDeniedTrace.record_type -cne 'D32_DEBUG_JOB_PROCESS_TRACE_V2' -or $protocDeniedTrace.schema_version -ne 2 -or
            $protocDeniedTrace.state -cne 'BLOCKED' -or $protocDeniedTrace.block_reason -notmatch 'vendored protoc descendant does not match the exact per-run locked Cargo source pin' -or
            -not $protocCreateIdentityBound -or
            $protocDeniedTrace.uncontinued_create_process_id -le 0 -or $protocDeniedTrace.uncontinued_create_continue_call_count -ne 0 -or
            $protocDeniedTrace.process_create_event_count -lt 1 -or -not [bool]$protocDeniedTrace.job_accounting_verified -or
            -not (Test-Path -LiteralPath $protocRootMarker) -or
            (Test-Path -LiteralPath $protocChildMarker) -or $protocCreateDenied.ContinueCalls -le 0 -or
            -not $protocCreateDenied.Cleanup.CleanupSucceeded -or -not $protocCreateDenied.Cleanup.ProcessWaitSignaled -or
            -not $protocCreateDenied.Cleanup.DebuggerThreadExited -or -not $protocCreateDenied.Cleanup.DebuggerThreadJoined -or
            -not $protocCreateDenied.Cleanup.DebuggerKillOnExitEnabled -or -not $protocCreateDenied.Cleanup.RetainedProcessHandlesSignaled -or
            -not $protocCreateDenied.Cleanup.DebuggerAssociationQueryVerified -or -not $protocCreateDenied.Cleanup.DebuggerAssociationAbsent -or
            -not $protocCreateDenied.Cleanup.JobActiveProcessCountVerified -or [uint32]$protocCreateDenied.Cleanup.JobActiveProcessCount -ne 0) {
            throw "SELFTEST_FAILED: ungranted protoc CREATE did not remain uncontinued with no child marker and complete V2 debugger/Job cleanup: $($protocDeniedTrace.block_reason); $($protocCreateDenied.Cleanup.Detail)"
        }
        Write-Host 'D32_PROTOC_CREATE_NEGATIVE=PASS uncontinued_create_calls=0 child_marker=false V2_trace=BLOCKED debugger_joined=true handles_signaled=true debugger_absent=true job_active=0'
        $passed++

        $ungrantedGitPath = Join-Path $root 'git.exe'
        [IO.File]::Copy($debugLauncherPath, $ungrantedGitPath)
        $gitRootMarker = Join-Path $root 'd32-ungranted-git-root.marker'
        $gitChildMarker = Join-Path $root 'd32-ungranted-git-child.marker'
        $gitCreateDenied = Invoke-D32DebugSelfTestProcess -FilePath $debugLauncherPath `
            -Arguments @('spawn-git', $gitRootMarker, $ungrantedGitPath, $gitChildMarker) `
            -WorkingDirectory $root -ExpectedRootPin $debugLauncherPin -ApprovedImagePins @($consoleHostPin) -EnvironmentBlock $debugTestEnvironment
        $gitDeniedTrace = ConvertTo-D32DebugProcessTraceDocument -Trace $gitCreateDenied.Trace
        if ($gitDeniedTrace.record_type -cne 'D32_DEBUG_JOB_PROCESS_TRACE_V2' -or $gitDeniedTrace.state -cne 'BLOCKED' -or
            $gitDeniedTrace.block_reason -notmatch 'Git/SSH/credential helper image is never launchable' -or
            $gitDeniedTrace.uncontinued_create_process_id -le 0 -or $gitDeniedTrace.uncontinued_create_continue_call_count -ne 0 -or
            -not $gitDeniedTrace.block_reason.Contains('opened_child_path=' + $ungrantedGitPath) -or
            -not $gitDeniedTrace.block_reason.Contains('parent_process_id=') -or
            -not (Test-Path -LiteralPath $gitRootMarker) -or (Test-Path -LiteralPath $gitChildMarker) -or $gitCreateDenied.ContinueCalls -le 0 -or
            -not $gitCreateDenied.Cleanup.CleanupSucceeded -or -not $gitCreateDenied.Cleanup.ProcessWaitSignaled -or
            -not $gitCreateDenied.Cleanup.DebuggerThreadExited -or -not $gitCreateDenied.Cleanup.DebuggerThreadJoined -or
            -not $gitCreateDenied.Cleanup.DebuggerKillOnExitEnabled -or -not $gitCreateDenied.Cleanup.RetainedProcessHandlesSignaled -or
            -not $gitCreateDenied.Cleanup.DebuggerAssociationQueryVerified -or -not $gitCreateDenied.Cleanup.DebuggerAssociationAbsent -or
            -not $gitCreateDenied.Cleanup.JobActiveProcessCountVerified -or [uint32]$gitCreateDenied.Cleanup.JobActiveProcessCount -ne 0) {
            throw "SELFTEST_FAILED: ungranted Git CREATE did not remain uncontinued with no child marker and complete V2 debugger/Job cleanup: $($gitDeniedTrace.block_reason); $($gitCreateDenied.Cleanup.Detail)"
        }
        Write-Host 'D32_GIT_CREATE_NEGATIVE=PASS ungranted_direct_child_uncontinued=true user_marker=false V2_trace=BLOCKED debugger_joined=true handles_signaled=true debugger_absent=true job_active=0'
        $passed++

        foreach ($commandTarget in @([PSCustomObject]@{ Name = 'absolute-cmd'; Command = $cmdScriptPath }, [PSCustomObject]@{ Name = 'PATH-cmd'; Command = 'd32-debug-no-launch.cmd' })) {
            $rootMarker = Join-Path $root ("d32-$($commandTarget.Name)-root.marker")
            $commandCase = Invoke-D32DebugSelfTestProcess -FilePath $debugLauncherPath -Arguments @('spawn-cmd', $rootMarker, $commandTarget.Command) `
                -WorkingDirectory $root -ExpectedRootPin $debugLauncherPin -ApprovedImagePins @($consoleHostPin) -EnvironmentBlock $debugTestEnvironment
            if ($commandCase.Trace.State -cne 'BLOCKED' -or $commandCase.Trace.BlockReason -notmatch 'never launchable' -or
                [uint32]$commandCase.Trace.UncontinuedCreateProcessId -le 0 -or [int]$commandCase.Trace.UncontinuedCreateContinueCallCount -ne 0 -or
                $commandCase.ContinueCalls -le 0 -or -not (Test-Path -LiteralPath $rootMarker) -or
                (Test-Path -LiteralPath $cmdScriptMarker) -or -not $commandCase.Cleanup.CleanupSucceeded -or
                -not $commandCase.Cleanup.DebuggerThreadJoined -or -not $commandCase.Cleanup.RetainedProcessHandlesSignaled -or
                -not $commandCase.Cleanup.DebuggerAssociationAbsent -or [uint32]$commandCase.Cleanup.JobActiveProcessCount -ne 0) {
                throw "SELFTEST_FAILED: $($commandTarget.Name) command processor/script launched or lacked debugger cleanup proof: $($commandCase.Trace.BlockReason); $($commandCase.Cleanup.Detail)"
            }
            $passed++
        }

        $missingExitRootMarker = Join-Path $root 'd32-missing-exit-root.marker'
        $missingExitCase = Invoke-D32DebugSelfTestProcess -FilePath $debugLauncherPath -Arguments @('exit', $missingExitRootMarker) -WorkingDirectory $root `
            -ExpectedRootPin $debugLauncherPin -ApprovedImagePins @($consoleHostPin) -EnvironmentBlock $debugTestEnvironment -FailureInjection 'missing-exit'
        if ($missingExitCase.Trace.State -cne 'BLOCKED' -or $missingExitCase.Trace.ProcessCreateEventCount -le 0 -or
            $missingExitCase.Trace.ProcessExitEventCount -ge $missingExitCase.Trace.ProcessCreateEventCount -or -not (Test-Path -LiteralPath $missingExitRootMarker) -or
            -not $missingExitCase.Cleanup.CleanupSucceeded -or -not $missingExitCase.Cleanup.DebuggerThreadJoined -or
            -not $missingExitCase.Cleanup.RetainedProcessHandlesSignaled -or -not $missingExitCase.Cleanup.DebuggerAssociationAbsent -or
            [uint32]$missingExitCase.Cleanup.JobActiveProcessCount -ne 0) {
            throw "SELFTEST_FAILED: missing EXIT event did not block and fully clean the actual process: $($missingExitCase.Trace.BlockReason); $($missingExitCase.Cleanup.Detail)"
        }
        $passed++

        $churnRootMarker = Join-Path $root 'd32-spawn-exit-churn-root.marker'
        $churnCase = Invoke-D32DebugSelfTestProcess -FilePath $debugLauncherPath -Arguments @('spawn-churn', $churnRootMarker) -WorkingDirectory $root `
            -ExpectedRootPin $debugLauncherPin -ApprovedImagePins @($wherePin, $consoleHostPin) -EnvironmentBlock $debugTestEnvironment -TimeoutMilliseconds 20000
        if ($churnCase.Trace.State -cne 'COMPLETED' -or -not $churnCase.Trace.AccountingConsistent -or
            $churnCase.Trace.ProcessCreateEventCount -lt 10 -or $churnCase.Trace.ProcessCreateEventCount -ne $churnCase.Trace.ProcessExitEventCount -or
            $churnCase.Trace.JobTotalProcesses -ne $churnCase.Trace.ProcessCreateEventCount -or $churnCase.Trace.JobActiveProcesses -ne 0 -or
            -not $churnCase.Cleanup.CleanupSucceeded -or -not $churnCase.Cleanup.DebuggerThreadJoined -or
            -not $churnCase.Cleanup.RetainedProcessHandlesSignaled -or -not $churnCase.Cleanup.DebuggerAssociationAbsent -or
            [uint32]$churnCase.Cleanup.JobActiveProcessCount -ne 0) {
            throw "SELFTEST_FAILED: normal rapid spawn/exit process identities did not reconcile with retained handles and Job accounting: $($churnCase.Trace.BlockReason); $($churnCase.Cleanup.Detail)"
        }
        $passed++

        $environmentBlock = ConvertTo-D32EnvironmentBlock ([ordered]@{ zLast = 'second'; AFirst = 'first' })
        if ($environmentBlock -cne "AFirst=first`0zLast=second`0`0") {
            throw 'SELFTEST_FAILED: explicit Unicode child environment block is not strictly sorted and double-terminated'
        }
        $duplicateEnvironmentNames = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::Ordinal)
        $duplicateEnvironmentNames.Add('Path', 'one')
        $duplicateEnvironmentNames.Add('PATH', 'two')
        try {
            [void](ConvertTo-D32EnvironmentBlock $duplicateEnvironmentNames)
            throw 'SELFTEST_FAILED: case-insensitive duplicate child environment names were accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'CHILD_ENVIRONMENT_INVALID:*') { throw }
        }
        $passed++
        $hostileGitEnvironment = [Diagnostics.ProcessStartInfo]::new()
        $hostileGitEnvironment.EnvironmentVariables['GIT_CONFIG_COUNT'] = '1'
        $hostileGitEnvironment.EnvironmentVariables['GIT_CONFIG_KEY_0'] = 'alias.status=write-marker'
        $hostileGitEnvironment.EnvironmentVariables['GIT_CONFIG_VALUE_0'] = '!write-marker'
        $hostileGitEnvironment.EnvironmentVariables['GIT_DIR'] = 'outside-metadata'
        $hostileGitEnvironment.EnvironmentVariables['GIT_TRACE'] = 'write-marker'
        Clear-D32ChildEnvironment -StartInfo $hostileGitEnvironment
        if ($hostileGitEnvironment.EnvironmentVariables.Count -ne 0) {
            throw 'SELFTEST_FAILED: inherited Git environment was not fully removed before spawn'
        }
        $passed++

        $fakeGit = Join-Path $root 'fake-git.exe'
        [IO.File]::WriteAllBytes($fakeGit, [byte[]](0x4D, 0x5A, 0x00, 0x01))
        $fakeGitHash = (Get-FileHash -LiteralPath $fakeGit -Algorithm SHA256).Hash.ToLowerInvariant()
        try {
            [void](Get-D32PinnedGit -Path $fakeGit -ExpectedSha256 ('0' * 64))
            throw 'SELFTEST_FAILED: fake Git with a mismatched SHA was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'GIT_PIN_INVALID:*') { throw }
        }
        $passed++

        $existingPinnedGitVariable = Get-Variable -Name PinnedGit -Scope Script -ErrorAction SilentlyContinue
        $savedPinnedGit = if ($null -eq $existingPinnedGitVariable) { $null } else { $existingPinnedGitVariable.Value }
        $pinnedFakeGit = Get-D32PinnedGit -Path $fakeGit -ExpectedSha256 $fakeGitHash
        $script:PinnedGit = $pinnedFakeGit
        $gitHandle = $null
        try {
            $gitHandle = Open-D32PinnedGitHandle
            $replacementDenied = $false
            try { [IO.File]::Move($fakeGit, (Join-Path $root 'fake-git-replaced.exe')) }
            catch { $replacementDenied = $true }
            if (-not $replacementDenied -or -not (Test-Path -LiteralPath $fakeGit -PathType Leaf)) {
                throw 'SELFTEST_FAILED: retained Git image handle did not deny replacement'
            }
        }
        finally {
            if ($null -ne $gitHandle) { $gitHandle.Dispose() }
            $script:PinnedGit = $savedPinnedGit
        }
        $passed++

        try {
            [void](Get-D32PinnedGit -Path 'git.exe' -ExpectedSha256 $fakeGitHash)
            throw 'SELFTEST_FAILED: relative pinned Git path was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'PATH_INVALID:*') { throw }
        }
        $passed++

        $fakeRepo = Join-Path $root 'fake-repository'
        $fakeGitDirectory = Join-Path $fakeRepo '.git'
        New-Item -ItemType Directory -Path (Join-Path $fakeGitDirectory 'objects/info') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $fakeGitDirectory 'refs/heads') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $fakeGitDirectory 'info') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $fakeRepo 'vita-agent') -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $fakeGitDirectory 'HEAD'), "ref: refs/heads/main`n", [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllBytes((Join-Path $fakeGitDirectory 'index'), [byte[]]@())
        [IO.File]::WriteAllText((Join-Path $fakeGitDirectory 'info/exclude'), "# allowed comments`n`nvita-agent/target/`n", [Text.UTF8Encoding]::new($false))
        $configPath = Join-Path $fakeGitDirectory 'config'
        [IO.File]::WriteAllText(
            $configPath,
            "[core]`n`t repositoryformatversion = 0`n`t filemode = false`n`t bare = false`n`t logallrefupdates = true`n`n[remote `"origin`"]`n`t url = https://example.invalid/repo.git`n`t fetch = +refs/heads/*:refs/remotes/origin/*`n`n[branch `"main`"]`n`t remote = origin`n`t merge = refs/heads/main`n",
            [Text.UTF8Encoding]::new($false)
        )
        [void](Assert-D32RepositoryGitConfig -Root $fakeRepo)
        $hiddenUntracked = Join-Path $fakeRepo 'hidden-source.rs'
        [IO.File]::WriteAllText($hiddenUntracked, 'untracked source', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $fakeGitDirectory 'info/exclude'), "# allowed comment`n`nvita-agent/target/`nhidden-source.rs`n", [Text.UTF8Encoding]::new($false))
        try {
            [void](Assert-D32RepositoryGitConfig -Root $fakeRepo)
            throw 'SELFTEST_FAILED: added .git/info/exclude rule hiding an untracked source was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'GIT_REPOSITORY_INVALID:*') { throw }
        }
        Remove-Item -LiteralPath $hiddenUntracked -Force
        [IO.File]::WriteAllText((Join-Path $fakeGitDirectory 'info/exclude'), "# allowed comment`n`nvita-agent/target/`n", [Text.UTF8Encoding]::new($false))
        $passed++

        $metadataLocks = Open-D32GitMetadataLocks -Root $fakeRepo -GitDirectory $fakeGitDirectory
        try {
            $windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
            $cmdPath = Assert-D32NoReparsePath -Path (Join-Path $windowsDirectory 'System32/cmd.exe')
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = $cmdPath
            $startInfo.Arguments = '/d /c exit 0'
            $startInfo.WorkingDirectory = $root
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $process = [Diagnostics.Process]::Start($startInfo)
            if ($null -eq $process) { throw 'SELFTEST_FAILED: metadata race probe process did not start' }
            $process.WaitForExit()
            if ($process.ExitCode -ne 0) { throw 'SELFTEST_FAILED: metadata race probe process did not exit successfully' }
            $process.Dispose()
            foreach ($metadataLock in $metadataLocks.Items) {
                $writeOpenRejected = $false
                try {
                    $writeStream = [IO.File]::Open([string]$metadataLock.Path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
                    $writeStream.Dispose()
                }
                catch { $writeOpenRejected = $true }
                if (-not $writeOpenRejected) {
                    throw 'SELFTEST_FAILED: retained metadata read handle allowed a writer after process creation'
                }
                $renameRejected = $false
                $movedPath = "$($metadataLock.Path).race-move"
                try { [IO.File]::Move([string]$metadataLock.Path, $movedPath) }
                catch { $renameRejected = $true }
                if (-not $renameRejected) {
                    [IO.File]::Move($movedPath, [string]$metadataLock.Path)
                    throw 'SELFTEST_FAILED: retained metadata read handle allowed pathname replacement after process creation'
                }
                Assert-D32GitMetadataFileLockCurrent -Lock $metadataLock
            }
        }
        finally { Close-D32GitMetadataLocks -Locks $metadataLocks }
        $passed++

        [IO.File]::WriteAllText($configPath, "[filter `"hostile`"]`n`t clean = write-marker`n", [Text.UTF8Encoding]::new($false))
        try {
            [void](Assert-D32RepositoryGitConfig -Root $fakeRepo)
            throw 'SELFTEST_FAILED: execution-capable Git filter config was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'GIT_CONFIG_REJECTED:*') { throw }
        }
        $passed++

        $ordinaryConfig = @'
[core]
	repositoryformatversion = 0
	filemode = false
	bare = false
	logallrefupdates = true
'@
        [IO.File]::WriteAllText($configPath, $ordinaryConfig, [Text.UTF8Encoding]::new($false))
        New-Item -ItemType Directory -Path (Join-Path $fakeGitDirectory 'info') -Force | Out-Null
        foreach ($relative in @(
                'gitdir',
                'commondir',
                'config.worktree',
                'objects/info/alternates',
                'objects/info/http-alternates',
                'info/grafts'
            )) {
            $metadataPath = Join-Path $fakeGitDirectory $relative
            $metadataParent = Split-Path -Parent $metadataPath
            if (-not (Test-Path -LiteralPath $metadataParent -PathType Container)) {
                New-Item -ItemType Directory -Path $metadataParent -Force | Out-Null
            }
            [IO.File]::WriteAllText($metadataPath, 'outside-metadata', [Text.UTF8Encoding]::new($false))
            try {
                [void](Assert-D32RepositoryGitConfig -Root $fakeRepo)
                throw "SELFTEST_FAILED: Git metadata indirection was accepted: $relative"
            }
            catch {
                if ($_.Exception.Message -notlike 'GIT_REPOSITORY_INVALID:*') { throw }
            }
            Remove-Item -LiteralPath $metadataPath -Force
            $passed++
        }
        $outsideRefs = Join-Path $root 'outside-refs'
        New-Item -ItemType Directory -Path $outsideRefs -Force | Out-Null
        $nestedRefsJunction = Join-Path $fakeGitDirectory 'refs/heads/external'
        try {
            New-Item -ItemType Junction -Path $nestedRefsJunction -Target $outsideRefs -ErrorAction Stop | Out-Null
        }
        catch {
            throw "SELFTEST_UNAVAILABLE: could not create nested Git metadata junction: $($_.Exception.Message)"
        }
        try {
            [void](Assert-D32RepositoryGitConfig -Root $fakeRepo)
            throw 'SELFTEST_FAILED: nested Git metadata reparse point was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'GIT_REPOSITORY_INVALID:*') { throw }
        }
        Remove-Item -LiteralPath $nestedRefsJunction -Force
        $passed++

        $outsideInfo = Join-Path $root 'outside-info'
        New-Item -ItemType Directory -Path $outsideInfo -Force | Out-Null
        $nestedInfoJunction = Join-Path $fakeGitDirectory 'info/external'
        try {
            New-Item -ItemType Junction -Path $nestedInfoJunction -Target $outsideInfo -ErrorAction Stop | Out-Null
        }
        catch {
            throw "SELFTEST_UNAVAILABLE: could not create nested Git info junction: $($_.Exception.Message)"
        }
        try {
            [void](Assert-D32RepositoryGitConfig -Root $fakeRepo)
            throw 'SELFTEST_FAILED: nested .git/info reparse point was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'GIT_REPOSITORY_INVALID:*') { throw }
        }
        Remove-Item -LiteralPath $nestedInfoJunction -Force
        $passed++

        $outsideTarget = Join-Path $root 'outside-target'
        New-Item -ItemType Directory -Path $outsideTarget -Force | Out-Null
        $targetJunction = Join-Path $fakeRepo 'vita-agent/target'
        try {
            New-Item -ItemType Junction -Path $targetJunction -Target $outsideTarget -ErrorAction Stop | Out-Null
        }
        catch {
            throw "SELFTEST_UNAVAILABLE: could not create repo-local target junction: $($_.Exception.Message)"
        }
        try {
            [void](Assert-D32RepositoryGitConfig -Root $fakeRepo)
            throw 'SELFTEST_FAILED: approved ignore rule accepted a target path that redirects outside the repository'
        }
        catch {
            if ($_.Exception.Message -notlike 'PATH_REPARSE:*') { throw }
        }
        Remove-Item -LiteralPath $targetJunction -Force
        $passed++

        $junction = Join-Path $root 'repo-junction'
        try {
            New-Item -ItemType Junction -Path $junction -Target $fakeRepo -ErrorAction Stop | Out-Null
        }
        catch {
            throw "SELFTEST_UNAVAILABLE: could not create a junction for the required reparse negative: $($_.Exception.Message)"
        }
        try {
            [void](Assert-D32NoReparsePath -Path (Join-Path $junction '.git'))
            throw 'SELFTEST_FAILED: reparse-point repository path was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'PATH_REPARSE:*') { throw }
        }
        $passed++

        $manifest = Assert-D32ManifestDestination -Path (Join-Path $root 'manifest.json') -OwnedRoot $root
        $sample = Join-Path $root 'sample.bin'
        [IO.File]::WriteAllBytes($sample, [byte[]](1, 2, 3, 4))
        $artifact = Get-D32Artifact $sample
        if ($artifact.bytes -ne 4 -or $artifact.sha256.Length -ne 64) {
            throw 'SELFTEST_FAILED: artifact manifest record'
        }
        $passed++
        $boundArtifact = Get-D32BoundArtifact $sample
        if ($boundArtifact.bytes -ne 4 -or
            $boundArtifact.sha256 -ne $artifact.sha256 -or
            $boundArtifact.file_identity.file_size -ne 4 -or
            $boundArtifact.file_identity.directory -or
            $boundArtifact.file_identity.reparse) {
            throw 'SELFTEST_FAILED: native artifact identity record'
        }
        $passed++

        $seederRecordPath = Join-Path $root 'd31-recovery-seeder-build.json'
        $seederRunId = '0123456789abcdef0123456789abcdef'
        $seederTarget = Join-Path $root 'd31-recovery-seeder-target'
        $seederTargetBin = Join-Path $seederTarget 'debug'
        New-Item -ItemType Directory -Path $seederTargetBin -Force | Out-Null
        $seederImagePath = Join-Path $seederTargetBin 'vita-agent.exe'
        [IO.File]::WriteAllBytes($seederImagePath, [byte[]](10, 20, 30, 40))
        $seederArtifact = Get-D32BoundArtifact -Path $seederImagePath
        $seederManifest = Join-Path $fakeRepo 'vita-agent/Cargo.toml'
        $seederPowerShellIdentity = [ordered]@{
            name = 'pwsh.exe'; path = (Join-Path $root 'pwsh.exe'); sha256 = ('a' * 64); bytes = 1
            volume_serial_hex = '0000000000000001'; file_id_hex = ('01' * 16); reason = 'direct pinned PowerShell host executable'
        }
        $seederCargoIdentity = [ordered]@{
            name = 'cargo.exe'; path = (Join-Path $root 'cargo.exe'); sha256 = ('b' * 64); bytes = 1
            volume_serial_hex = '0000000000000001'; file_id_hex = ('02' * 16); reason = 'direct pinned cargo executable'
        }
        $seederRustcIdentity = [ordered]@{
            name = 'rustc.exe'; path = (Join-Path $root 'rustc.exe'); sha256 = ('c' * 64); bytes = 1
            volume_serial_hex = '0000000000000001'; file_id_hex = ('03' * 16); reason = 'direct pinned rustc executable'
        }
        $seederRustdocIdentity = [ordered]@{
            name = 'rustdoc.exe'; path = (Join-Path $root 'rustdoc.exe'); sha256 = ('d' * 64); bytes = 1
            volume_serial_hex = '0000000000000001'; file_id_hex = ('04' * 16); reason = 'direct pinned rustdoc executable'
        }
        $seederBuildCommandLine = ConvertTo-D32CommandLine (@($seederCargoIdentity.path) + @(
            'build', '--quiet', '--locked', '--manifest-path', $seederManifest,
            '--bin', 'vita-agent', '--features', 'd29-h9-test-helper', '--target-dir', $seederTarget
        ))
        $seederRecordDocument = [ordered]@{
            schema_version = 2
            purpose = 'd31-recovery-seeder-test-helper'
            run_id = $seederRunId
            candidate_sha = '0123456789abcdef0123456789abcdef01234567'
            runner_process_id = [int]$PID
            source_repo = $fakeRepo
            manifest_path = $seederManifest
            feature = 'd29-h9-test-helper'
            command = @('build', '--quiet', '--locked', '--manifest-path', $seederManifest, '--bin', 'vita-agent', '--features', 'd29-h9-test-helper', '--target-dir', $seederTarget)
            target_dir = $seederTarget
            run_root = (Join-Path $root "d31-recovery-seeder-run-$seederRunId")
            cargo_home = (Join-Path $root "d31-recovery-seeder-run-$seederRunId/cargo-home")
            temp_root = (Join-Path $root "d31-recovery-seeder-run-$seederRunId/temp")
            toolchain_profile_path = (Join-Path $root 'profile.json')
            toolchain_profile_sha256 = ('e' * 64)
            target_triple = 'x86_64-pc-windows-msvc'
            powershell = $seederPowerShellIdentity
            toolchain = [ordered]@{ cargo = $seederCargoIdentity; rustc = $seederRustcIdentity; rustdoc = $seederRustdocIdentity }
            fetch_manifests = @([ordered]@{ manifest_path = 'vita-agent/Cargo.toml'; lock_sha256 = ('f' * 64) })
            fetch_phases = @()
            cargo_path = $seederCargoIdentity.path
            process_identity = [ordered]@{
                process_id = 1234; parent_process_id = [int]$PID; name = 'cargo.exe'; image_path = $seederCargoIdentity.path
                creation_date = '2026-09-23T00:00:00.0000000Z'; command_line = $seederBuildCommandLine
                observed_at_utc = '2026-09-23T00:00:00.0000000Z'; identity_verified = $true
            }
            status = 'succeeded'
            exit_code = 0
            artifact = $seederArtifact
        }
        Assert-D32D31RecoverySeederRecordShape -Document $seederRecordDocument -Path $seederRecordPath -OutputRoot $root
        $seederRecordWrongParent = [ordered]@{}
        foreach ($field in $seederRecordDocument.Keys) { $seederRecordWrongParent[$field] = $seederRecordDocument[$field] }
        $seederRecordWrongParent.process_identity = [ordered]@{}
        foreach ($field in $seederRecordDocument.process_identity.Keys) {
            $seederRecordWrongParent.process_identity[$field] = $seederRecordDocument.process_identity[$field]
        }
        $seederRecordWrongParent.process_identity.parent_process_id = if ([int]$PID -eq [int]::MaxValue) { [int]$PID - 1 } else { [int]$PID + 1 }
        try {
            Assert-D32D31RecoverySeederRecordShape -Document $seederRecordWrongParent -Path $seederRecordPath -OutputRoot $root
            throw 'SELFTEST_FAILED: D31 seeder v2 process identity parent other than this PowerShell process was accepted'
        }
        catch { if ($_.Exception.Message -notlike 'D31_RECOVERY_SEEDER_RECORD_INVALID:*') { throw } }
        $seederRecordWrongRunner = [ordered]@{}
        foreach ($field in $seederRecordDocument.Keys) { $seederRecordWrongRunner[$field] = $seederRecordDocument[$field] }
        $seederRecordWrongRunner.runner_process_id = if ([int]$PID -eq [int]::MaxValue) { [int]$PID - 1 } else { [int]$PID + 1 }
        try {
            Assert-D32D31RecoverySeederRecordShape -Document $seederRecordWrongRunner -Path $seederRecordPath -OutputRoot $root
            throw 'SELFTEST_FAILED: D31 seeder v2 runner PID other than this PowerShell process was accepted'
        }
        catch { if ($_.Exception.Message -notlike 'D31_RECOVERY_SEEDER_RECORD_INVALID:*') { throw } }
        $seederRecordV1 = [ordered]@{}
        foreach ($field in $seederRecordDocument.Keys) { $seederRecordV1[$field] = $seederRecordDocument[$field] }
        $seederRecordV1.schema_version = 1
        try {
            Assert-D32D31RecoverySeederRecordShape -Document $seederRecordV1 -Path $seederRecordPath -OutputRoot $root
            throw 'SELFTEST_FAILED: obsolete D31 seeder record schema v1 was accepted'
        }
        catch { if ($_.Exception.Message -notlike 'D31_RECOVERY_SEEDER_RECORD_INVALID:*') { throw } }
        $seederRecordMissingField = [ordered]@{}
        foreach ($field in $seederRecordDocument.Keys) { if ($field -cne 'fetch_git') { $seederRecordMissingField[$field] = $seederRecordDocument[$field] } }
        $seederRecordMissingField.Remove('toolchain_profile_path')
        try {
            Assert-D32D31RecoverySeederRecordShape -Document $seederRecordMissingField -Path $seederRecordPath -OutputRoot $root
            throw 'SELFTEST_FAILED: missing D31 seeder v2 field was accepted'
        }
        catch { if ($_.Exception.Message -notlike 'D31_RECOVERY_SEEDER_RECORD_INVALID:*') { throw } }
        $seederRecordExtraField = [ordered]@{}
        foreach ($field in $seederRecordDocument.Keys) { $seederRecordExtraField[$field] = $seederRecordDocument[$field] }
        $seederRecordExtraField['unexpected'] = $true
        try {
            Assert-D32D31RecoverySeederRecordShape -Document $seederRecordExtraField -Path $seederRecordPath -OutputRoot $root
            throw 'SELFTEST_FAILED: extra D31 seeder v2 field was accepted'
        }
        catch { if ($_.Exception.Message -notlike 'D31_RECOVERY_SEEDER_RECORD_INVALID:*') { throw } }
        $seederRecordExtraOffline = [ordered]@{}
        foreach ($field in $seederRecordDocument.Keys) { $seederRecordExtraOffline[$field] = $seederRecordDocument[$field] }
        $seederRecordExtraOffline.command = @($seederRecordDocument.command) + @('--offline')
        try {
            Assert-D32D31RecoverySeederRecordShape -Document $seederRecordExtraOffline -Path $seederRecordPath -OutputRoot $root
            throw 'SELFTEST_FAILED: D31 seeder argv with a non-ADR --offline token was accepted'
        }
        catch { if ($_.Exception.Message -notlike 'D31_RECOVERY_SEEDER_RECORD_INVALID:*') { throw } }
        $seederRecord = Write-D32NewRecoverySeederBuildRecord -Path $seederRecordPath -Document $seederRecordDocument
        $seederRecordOnDisk = Get-D32BoundArtifact -Path $seederRecordPath
        if ($seederRecord.sha256 -ne $seederRecordOnDisk.sha256 -or
            $seederRecord.bytes -ne $seederRecordOnDisk.bytes -or
            $seederRecord.file_identity.file_index -ne $seederRecordOnDisk.file_identity.file_index) {
            throw 'SELFTEST_FAILED: D31 seeder build record was not bound to its written file identity'
        }
        $seederRecordJson = [IO.File]::ReadAllText($seederRecordPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
        if ([int]$seederRecordJson.schema_version -ne 2 -or
            (Get-D32ObjectFieldNames -Object $seederRecordJson).Count -ne $seederRecordDocument.Count) {
            throw 'SELFTEST_FAILED: written D31 seeder record JSON is not exact schema v2'
        }
        $passed++
        try {
            [void](Write-D32NewRecoverySeederBuildRecord -Path $seederRecordPath -Document $seederRecordDocument)
            throw 'SELFTEST_FAILED: D31 seeder build record overwrite was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'OUTPUT_NOT_OWNED:*') { throw }
        }
        $passed++

        $currentPowerShellProcess = [Diagnostics.Process]::GetCurrentProcess()
        try { $powershell = [string]$currentPowerShellProcess.MainModule.FileName }
        finally { $currentPowerShellProcess.Dispose() }
        $encodedExitZero = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes('exit 0')
        )
        $zero = Invoke-D32BoundedProcess `
            -FilePath $powershell `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedExitZero) `
            -WorkingDirectory $root `
            -PhaseLog (Join-Path $root 'zero-phase') `
            -TimeoutSeconds 5
        if ($zero.status -ne 'succeeded' -or $zero.exit_code -ne 0) {
            throw "SELFTEST_FAILED: zero exit code was not captured exactly (status=$($zero.status), exit=$($zero.exit_code), error=$($zero.error))"
        }
        $passed++

        $explicitEnvironmentScript = Join-Path $root 'explicit-environment.ps1'
        [IO.File]::WriteAllText(
            $explicitEnvironmentScript,
            "if (`$env:D32_SELFTEST_ALLOWED -cne 'expected-value' -or `$null -ne `$env:D32_SELFTEST_INHERITED) { exit 13 }; exit 0`n",
            [Text.UTF8Encoding]::new($false)
        )
        $savedSelfTestInherited = [Environment]::GetEnvironmentVariable('D32_SELFTEST_INHERITED', 'Process')
        try {
            [Environment]::SetEnvironmentVariable('D32_SELFTEST_INHERITED', 'synthetic-ambient-secret', 'Process')
            $explicitChildEnvironment = [ordered]@{
                SystemRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows))
                TEMP = $root
                TMP = $root
                D32_SELFTEST_ALLOWED = 'expected-value'
            }
            $explicitEnvironment = Invoke-D32BoundedProcess `
                -FilePath $powershell `
                -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $explicitEnvironmentScript) `
                -WorkingDirectory $root `
                -PhaseLog (Join-Path $root 'explicit-environment-phase') `
                -TimeoutSeconds 5 `
                -ChildEnvironment $explicitChildEnvironment
        }
        finally {
            [Environment]::SetEnvironmentVariable('D32_SELFTEST_INHERITED', $savedSelfTestInherited, 'Process')
        }
        if ($explicitEnvironment.status -ne 'succeeded' -or $explicitEnvironment.exit_code -ne 0) {
            throw "SELFTEST_FAILED: explicit child environment was not isolated/applied (status=$($explicitEnvironment.status), exit=$($explicitEnvironment.exit_code), error=$($explicitEnvironment.error))"
        }
        $passed++

        if ($null -eq $zero.native_cleanup -or
            -not [bool]$zero.native_cleanup.cleanup_succeeded -or
            -not [bool]$zero.native_cleanup.job_close_succeeded -or
            -not [bool]$zero.native_cleanup.job_active_process_count_verified -or
            [uint32]$zero.native_cleanup.job_active_process_count -ne 0) {
            throw 'SELFTEST_FAILED: normal exit did not produce verified job-close cleanup evidence'
        }
        $passed++

        $encodedExitSeven = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes('exit 7')
        )
        $nonZero = Invoke-D32BoundedProcess `
            -FilePath $powershell `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedExitSeven) `
            -WorkingDirectory $root `
            -PhaseLog (Join-Path $root 'nonzero-phase') `
            -TimeoutSeconds 5
        if ($nonZero.status -ne 'failed' -or $nonZero.exit_code -ne 7) {
            throw "SELFTEST_FAILED: non-zero exit code was not captured exactly (status=$($nonZero.status), exit=$($nonZero.exit_code))"
        }
        $passed++

        $writeRawProcessScript = {
            param(
                [Parameter(Mandatory = $true)][string]$Path,
                [Parameter(Mandatory = $true)][string]$StdoutText,
                [Parameter(Mandatory = $true)][string]$StderrText,
                [Parameter(Mandatory = $true)][string[]]$Body
            )
            $stdoutBytes = [Text.Encoding]::UTF8.GetBytes($StdoutText)
            $stderrBytes = [Text.Encoding]::UTF8.GetBytes($StderrText)
            if (($stdoutBytes.Length -gt 0 -and $stdoutBytes[-1] -in @(10, 13)) -or
                ($stderrBytes.Length -gt 0 -and $stderrBytes[-1] -in @(10, 13))) {
                throw 'SELFTEST_FAILED: raw stream payload must not end with a newline'
            }
            $stdoutBase64 = [Convert]::ToBase64String($stdoutBytes)
            $stderrBase64 = [Convert]::ToBase64String($stderrBytes)
            $content = @(
                ('$raw = [Convert]::FromBase64String(''{0}'')' -f $stdoutBase64)
                '[Console]::OpenStandardOutput().Write($raw, 0, $raw.Length)'
                ('$raw = [Convert]::FromBase64String(''{0}'')' -f $stderrBase64)
                '[Console]::OpenStandardError().Write($raw, 0, $raw.Length)'
            ) + @($Body)
            [IO.File]::WriteAllText($Path, ($content -join [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
            return [PSCustomObject]@{ stdout = $stdoutBytes; stderr = $stderrBytes }
        }
        $assertRawProcessStreams = {
            param(
                [Parameter(Mandatory = $true)][object]$Result,
                [Parameter(Mandatory = $true)][object]$Payload,
                [Parameter(Mandatory = $true)][string]$CaseName
            )
            $actualStdout = [IO.File]::ReadAllBytes([string]$Result.stdout_log)
            $actualStderr = [IO.File]::ReadAllBytes([string]$Result.stderr_log)
            if ([Convert]::ToBase64String($actualStdout) -cne [Convert]::ToBase64String([byte[]]$Payload.stdout) -or
                [Convert]::ToBase64String($actualStderr) -cne [Convert]::ToBase64String([byte[]]$Payload.stderr)) {
                throw "SELFTEST_FAILED: $CaseName stdout/stderr logs were not byte-exact child streams"
            }
        }

        $rawSuccessScript = Join-Path $root 'raw-success.ps1'
        $rawSuccessPayload = & $writeRawProcessScript -Path $rawSuccessScript -StdoutText 'child-success-no-newline|D32_FIXTURE_EXIT_CODE=child|D32_FIXTURE_DESCENDANTS=child' -StderrText 'child-success-stderr-no-newline|D32_FIXTURE_PHASE=timeout|CAPTURED_DESCENDANT_PIDS=child|taskkill' -Body @('exit 0')
        $rawSuccess = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $rawSuccessScript) -WorkingDirectory $root -PhaseLog (Join-Path $root 'raw-success-phase') -TimeoutSeconds 5
        if ($rawSuccess.status -ne 'succeeded' -or $rawSuccess.exit_code -ne 0) {
            throw 'SELFTEST_FAILED: raw-stream success child status/exit code was not preserved'
        }
        & $assertRawProcessStreams -Result $rawSuccess -Payload $rawSuccessPayload -CaseName 'success'
        $passed++

        $rawNonZeroScript = Join-Path $root 'raw-nonzero.ps1'
        $rawNonZeroPayload = & $writeRawProcessScript -Path $rawNonZeroScript -StdoutText 'child-nonzero-no-newline|D32_FIXTURE_EXIT_CODE=child|D32_FIXTURE_DESCENDANTS=child' -StderrText 'child-nonzero-stderr-no-newline|D32_FIXTURE_PHASE=timeout|CAPTURED_DESCENDANT_PIDS=child|taskkill' -Body @('exit 7')
        $rawNonZero = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $rawNonZeroScript) -WorkingDirectory $root -PhaseLog (Join-Path $root 'raw-nonzero-phase') -TimeoutSeconds 5
        if ($rawNonZero.status -ne 'failed' -or $rawNonZero.exit_code -ne 7) {
            throw 'SELFTEST_FAILED: raw-stream non-zero child status/exit code was not preserved'
        }
        & $assertRawProcessStreams -Result $rawNonZero -Payload $rawNonZeroPayload -CaseName 'non-zero'
        $passed++

        $normalChildScript = Join-Path $root 'descendant-normal.ps1'
        $normalChildWorkerScript = Join-Path $root 'descendant-normal-worker.ps1'
        $normalChildReadyPath = Join-Path $root 'descendant-normal-ready.marker'
        $normalChildWorkerContent = @(
            ('[IO.File]::WriteAllText(''{0}'', ''D32_NORMAL_CHILD_READY_V1'', [Text.UTF8Encoding]::new($false))' -f $normalChildReadyPath)
            'Start-Sleep -Seconds 5'
        ) -join [Environment]::NewLine
        [IO.File]::WriteAllText($normalChildWorkerScript, $normalChildWorkerContent, [Text.UTF8Encoding]::new($false))
        $normalChildParentContent = @(
            '$null = Start-Process -FilePath ''__POWERSHELL__'' -ArgumentList ''-NoLogo'',''-NoProfile'',''-NonInteractive'',''-File'',''__WORKER__'' -WindowStyle Hidden -PassThru'
            '$deadline = [DateTimeOffset]::UtcNow.AddSeconds(4)'
            'while (-not (Test-Path -LiteralPath ''__READY__'' -PathType Leaf)) {'
            '    if ([DateTimeOffset]::UtcNow -ge $deadline) { throw ''SELFTEST_FAILED: normal child did not reach its ready barrier'' }'
            '    Start-Sleep -Milliseconds 10'
            '}'
            'exit 0'
        ) -join [Environment]::NewLine
        $normalChildParentContent = $normalChildParentContent.Replace('__POWERSHELL__', $powershell).Replace('__WORKER__', $normalChildWorkerScript).Replace('__READY__', $normalChildReadyPath)
        [IO.File]::WriteAllText($normalChildScript, $normalChildParentContent, [Text.UTF8Encoding]::new($false))
        $normalWithChild = Invoke-D32BoundedProcess `
            -FilePath $powershell `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $normalChildScript) `
            -WorkingDirectory $root `
            -PhaseLog (Join-Path $root 'normal-descendant-phase') `
            -TimeoutSeconds 5
        $normalChildIdentityCount = @($normalWithChild.descendant_identities).Count
        $normalChildReadyObserved = (Test-Path -LiteralPath $normalChildReadyPath -PathType Leaf) -and
            ([IO.File]::ReadAllText($normalChildReadyPath) -ceq 'D32_NORMAL_CHILD_READY_V1')
        if ($normalWithChild.status -ne 'succeeded' -or
            $normalWithChild.exit_code -ne 0 -or
            -not $normalChildReadyObserved -or
            $normalChildIdentityCount -lt 1 -or
            @($normalWithChild.descendant_pids).Count -ne 0 -or
            $null -eq $normalWithChild.native_cleanup -or
            -not [bool]$normalWithChild.native_cleanup.cleanup_succeeded -or
            -not [bool]$normalWithChild.native_cleanup.job_active_process_count_verified -or
            [uint32]$normalWithChild.native_cleanup.job_active_process_count -ne 0 -or
            $null -ne $normalWithChild.error) {
            $normalDiagnostic = [ordered]@{
                status = $normalWithChild.status
                exit_code = $normalWithChild.exit_code
                child_ready_marker_observed = $normalChildReadyObserved
                captured_descendant_count = $normalChildIdentityCount
                residual_descendant_pids = @($normalWithChild.descendant_pids)
                native_cleanup = $normalWithChild.native_cleanup
                error = $normalWithChild.error
                elapsed_ms = $normalWithChild.elapsed_ms
            }
            throw "SELFTEST_FAILED: normal exit with captured child was not cleanly reaped: $($normalDiagnostic | ConvertTo-Json -Compress -Depth 8)"
        }
        $normalIdentity = @($normalWithChild.descendant_identities)[0]
        foreach ($field in @('process_id', 'parent_process_id', 'name', 'creation_date', 'command_line', 'observed_at_utc', 'identity_verified')) {
            if (-not $normalIdentity.Contains($field)) {
                throw "SELFTEST_FAILED: descendant identity field was not persisted: $field"
            }
        }
        $passed++

        $nonZeroChildScript = Join-Path $root 'descendant-nonzero.ps1'
        [IO.File]::WriteAllText(
            $nonZeroChildScript,
            "Start-Process -FilePath '$powershell' -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 5' -WindowStyle Hidden | Out-Null`nStart-Sleep -Milliseconds 750`nexit 7`n",
            [Text.UTF8Encoding]::new($false)
        )
        $nonZeroWithChild = Invoke-D32BoundedProcess `
            -FilePath $powershell `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $nonZeroChildScript) `
            -WorkingDirectory $root `
            -PhaseLog (Join-Path $root 'nonzero-descendant-phase') `
            -TimeoutSeconds 5
        if ($nonZeroWithChild.status -ne 'failed' -or
            $nonZeroWithChild.exit_code -ne 7 -or
            @($nonZeroWithChild.descendant_identities).Count -lt 1 -or
            @($nonZeroWithChild.descendant_pids).Count -ne 0 -or
            $null -ne $nonZeroWithChild.error) {
            throw 'SELFTEST_FAILED: non-zero exit with captured child was not cleanly reaped'
        }
        $passed++

        $mismatch = New-D32ProcessIdentityRecord `
            -ProcessId $PID `
            -ParentProcessId $null `
            -Name 'd32-identity-mismatch.exe' `
            -CommandLine 'synthetic mismatch' `
            -CreationDate 'synthetic-mismatch' `
            -ObservedAtUtc ([DateTimeOffset]::UtcNow.ToString('o')) `
            -IdentityVerified $true
        try {
            [void](Test-D32CapturedProcessAlive -Record $mismatch)
            throw 'SELFTEST_FAILED: PID identity mismatch was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'PROCESS_IDENTITY_MISMATCH:*') { throw }
        }
        $passed++

        $outside = Join-Path ([IO.Path]::GetTempPath()) ('d32-fixture-prebuild-outside-' + [Guid]::NewGuid().ToString('N') + '.json')
        try {
            [void](Assert-D32ManifestDestination -Path $outside -OwnedRoot $root)
            throw 'SELFTEST_FAILED: unowned manifest destination was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'OUTPUT_NOT_OWNED:*') {
                throw
            }
        }
        $passed++

        $envPlan = Get-D32EnvironmentPlan (Join-Path $root 'env')
        Assert-D32FixtureManifestEnvironmentShape -Environment $envPlan
        $realCodexHome = Get-D32FullPath (Join-Path $envPlan.original_userprofile '.codex')
        if ($envPlan.codex_home -eq $envPlan.userprofile -or
            $envPlan.codex_home.Equals($realCodexHome, [StringComparison]::OrdinalIgnoreCase) -or
            $envPlan.userprofile.Equals($envPlan.original_userprofile, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'SELFTEST_FAILED: environment isolation plan'
        }
        $passed++

        $producerFixtureManifest = [ordered]@{ schema_version = 3; environment = $envPlan }
        $producerFixtureManifestJson = $producerFixtureManifest | ConvertTo-Json -Depth 12
        $parsedFixtureManifest = $producerFixtureManifestJson | ConvertFrom-Json
        $parsedEnvironmentFields = @(Get-D32ObjectFieldNames -Object $parsedFixtureManifest.environment)
        if ([int]$parsedFixtureManifest.schema_version -ne 3 -or $parsedEnvironmentFields.Count -ne 6 -or
            @($parsedEnvironmentFields | Where-Object { $_ -notin @('original_userprofile', 'codex_home', 'userprofile', 'cargo_home', 'rustup_home', 'rustup_toolchain') }).Count -ne 0) {
            throw 'SELFTEST_FAILED: schema-v3 producer JSON no longer matches the strict six-field Host environment wire shape'
        }
        $extraManifestEnvironment = [ordered]@{}
        foreach ($field in $envPlan.Keys) { $extraManifestEnvironment[$field] = $envPlan[$field] }
        $extraManifestEnvironment['toolchain_profile_sha256'] = ('f' * 64)
        try {
            Assert-D32FixtureManifestEnvironmentShape -Environment $extraManifestEnvironment
            throw 'SELFTEST_FAILED: toolchain provenance was accepted inside the strict schema-v3 environment'
        }
        catch { if ($_.Exception.Message -notlike 'FIXTURE_MANIFEST_ENVIRONMENT_INVALID:*') { throw } }

        $provenanceCargoPath = Join-Path $root 'cargo.exe'
        $provenanceManifestPath = Join-Path $fakeRepo 'vita-agent/Cargo.toml'
        $provenanceEvidenceRoot = Join-Path $root 'evidence'
        $provenanceRunRoot = Join-Path $provenanceEvidenceRoot 'r'
        $provenanceCargoHome = Join-Path $provenanceRunRoot 'c'
        $provenanceTempRoot = Join-Path $provenanceRunRoot 't'
        $provenanceLockManifests = @('vita-agent-protocol/Cargo.toml', 'vita-agent/Cargo.toml', 'src-tauri/Cargo.toml')
        $provenanceFetchManifests = [System.Collections.Generic.List[object]]::new()
        $provenanceFetchArguments = [System.Collections.Generic.List[object]]::new()
        for ($fetchIndex = 0; $fetchIndex -lt $provenanceLockManifests.Count; $fetchIndex++) {
            $fetchManifestPath = $provenanceLockManifests[$fetchIndex]
            $fetchManifestFullPath = [IO.Path]::GetFullPath((Join-Path $fakeRepo $fetchManifestPath))
            $fetchArguments = @('fetch', '--locked', '--manifest-path', $fetchManifestFullPath, '--target', 'x86_64-pc-windows-msvc')
            $provenanceFetchArguments.Add($fetchArguments)
            $provenanceFetchManifests.Add([ordered]@{
                    manifest_path = $fetchManifestPath
                    lock_sha256 = ('f' * 64)
                    command = $fetchArguments
                    status = 'succeeded'
                    exit_code = 0
                    process_identity = [ordered]@{
                        process_id = 1234 + $fetchIndex
                        parent_process_id = [int]$PID
                        name = 'cargo.exe'
                        image_path = $provenanceCargoPath
                        creation_date = '2026-09-23T00:00:00.0000000Z'
                        command_line = ConvertTo-D32CommandLine (@($provenanceCargoPath) + $fetchArguments)
                        observed_at_utc = '2026-09-23T00:00:01.0000000Z'
                        identity_verified = $true
                    }
                })
        }
        $provenanceEnvironment = [ordered]@{
            toolchain_profile_path = (Join-Path $root 'profile.json')
            toolchain_profile_sha256 = ('a' * 64)
            target_triple = 'x86_64-pc-windows-msvc'
            env_policy = 'D32_BUILD_ENV_V1'
            cargo_policy = 'FRESH_HOME_LOCKED_FETCH_OFFLINE_AFTER'
            cargo_home = $provenanceCargoHome
            temp_root = $provenanceTempRoot
            run_id = '0123456789abcdef0123456789abcdef'
            fetch_manifests = @($provenanceFetchManifests.ToArray())
            offline_after_fetch = $true
        }
        $debuggerCreation = [DateTime]::UtcNow.ToFileTimeUtc()
        $debuggerCreated = [DateTime]::FromFileTimeUtc($debuggerCreation).ToString('o')
        $traceStarted = [DateTime]::UtcNow.ToString('o')
        $fakeProcessTrace = [ordered]@{
            record_type = 'D32_DEBUG_JOB_PROCESS_TRACE_V2'
            schema_version = 2
            event_source = 'Win32-WaitForDebugEvent-dedicated-OS-thread'
            state = 'COMPLETED'
            block_reason = $null
            debugger_process_id = [int]$PID
            uncontinued_create_process_id = 0
            uncontinued_create_continue_call_count = 0
            debugger_thread_id = [int]$PID + 1
            dedicated_debugger_thread = $true
            debugger_kill_on_exit_enabled = $true
            root_resumed_after_kill_on_exit = $true
            debugger_thread_exited = $true
            debugger_thread_joined = $true
            retained_process_handle_count = 2
            retained_process_handles_signaled = $true
            debugger_association_query_verified = $true
            debugger_association_absent = $true
            debugger_creation_filetime = [Int64]$debuggerCreation
            debugger_created_at_utc = $debuggerCreated
            started_at_utc = $traceStarted
            completed_at_utc = [DateTime]::UtcNow.ToString('o')
            debug_event_count = 2
            process_create_event_count = 1
            process_exit_event_count = 1
            process_event_count = 2
            thread_create_event_count = 0
            thread_exit_event_count = 0
            image_load_event_count = 0
            image_unload_event_count = 0
            exception_event_count = 0
            debug_string_event_count = 0
            wait_timeout_count = 0
            debug_api_error_count = 0
            event_chain_complete = $true
            job_accounting_verified = $true
            job_total_processes = 1
            job_active_processes = 0
            accounting_consistent = $true
            injected_interruption = $false
            process_events = @(
                [ordered]@{ sequence = 1; kind = 'CREATE'; process_id = 1234; parent_process_id = [int]$PID; creation_filetime = $debuggerCreation + 1; parent_creation_filetime = $debuggerCreation; exit_code = 0 },
                [ordered]@{ sequence = 2; kind = 'EXIT'; process_id = 1234; parent_process_id = [int]$PID; creation_filetime = $debuggerCreation + 1; parent_creation_filetime = $debuggerCreation; exit_code = 0 }
            )
            processes = @([ordered]@{
                process_id = 1234; parent_process_id = [int]$PID; creation_filetime = $debuggerCreation + 1; parent_creation_filetime = $debuggerCreation
                image_path = $provenanceCargoPath; bytes = 100; sha256 = ('a' * 64); volume_serial_hex = ('b' * 16); file_id_hex = ('c' * 32)
                allowed_image_reason = 'exact-caller-pinned-fixed-root-image'; image_verified = $true; exited = $true; exit_code = 0
                create_sequence = 1; exit_sequence = 2; created_at_utc = $debuggerCreated; exited_at_utc = $debuggerCreated
            })
        }
        $traceNames = @('fixture-01-fetch', 'fixture-02-fetch', 'fixture-03-fetch', 'd29h1-authority-fixture', 'd29h7-authority-fixture', 'd29h7-process-fixture', 'd29h7-git-helper-fixture', 'd32a-sandbox-fixture')
        $traceRecords = [System.Collections.Generic.List[object]]::new()
        foreach ($traceIndex in 0..($traceNames.Count - 1)) {
            $traceName = $traceNames[$traceIndex]
            if ($traceIndex -lt 3) {
                $traceArguments = @($provenanceFetchArguments[$traceIndex])
            }
            else {
                $spec = $script:FixtureSpecs[$traceIndex - 3]
                $traceArguments = @('build', '--quiet', '--locked', '--manifest-path', [IO.Path]::GetFullPath((Join-Path $fakeRepo ([string]$spec.manifest))), '--bin', [string]$spec.binary)
                if ($spec.features.Count -gt 0) { $traceArguments += @('--features', ($spec.features -join ' ')) }
                $traceArguments += @('--jobs', '4')
            }
            $traceRecords.Add([ordered]@{
                name = $traceName
                executable = $provenanceCargoPath
                arguments = $traceArguments
                command_line = ConvertTo-D32CommandLine (@($provenanceCargoPath) + $traceArguments)
                working_directory = $fakeRepo
                process_trace = $fakeProcessTrace
            })
        }
        $boundManifestArtifact = Get-D32BoundArtifactWithFileId -Path $sample
        $fixtureSyntheticAdmission = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($global:D32PowerShellModuleAuthorityState.Admission))
        $fixtureSyntheticAdmission.candidate_sha = '0123456789abcdef0123456789abcdef01234567'
        $fixtureSyntheticAdmission.source_repo = $fakeRepo
        $provenanceDocument = [ordered]@{
            schema_version = 7
            record_type = 'D32_FIXTURE_BUILD_PROVENANCE_V7'
            candidate_sha = '0123456789abcdef0123456789abcdef01234567'
            source_repo = $fakeRepo
            fixture_manifest_path = $sample
            fixture_manifest_sha256 = $boundManifestArtifact.sha256
            fixture_manifest_bytes = $boundManifestArtifact.bytes
            fixture_manifest_volume_serial_hex = $boundManifestArtifact.volume_serial_hex
            fixture_manifest_file_id_hex = $boundManifestArtifact.file_id_hex
            environment = $provenanceEnvironment
            storage = [ordered]@{
                evidence_root = [ordered]@{ path = $provenanceEvidenceRoot; volume_serial_hex = '0000000000000001'; file_id_hex = ('01' * 16) }
                owner_marker = [ordered]@{ path = (Join-Path $provenanceEvidenceRoot 'D32-PHASE0-OWNER.json'); bytes = 1; sha256 = ('e' * 64); volume_serial_hex = '0000000000000001'; file_id_hex = ('02' * 16) }
                run_root = [ordered]@{ path = $provenanceRunRoot; volume_serial_hex = '0000000000000001'; file_id_hex = ('03' * 16) }
                cargo_home = [ordered]@{ path = $provenanceCargoHome; volume_serial_hex = '0000000000000001'; file_id_hex = ('04' * 16) }
                temp_root = [ordered]@{ path = $provenanceTempRoot; volume_serial_hex = '0000000000000001'; file_id_hex = ('05' * 16) }
                run_id = $provenanceEnvironment.run_id
            }
            process_traces = @($traceRecords.ToArray())
            fixture_build_budget = $validBuildBudget
            vendored_protoc_run_grant = [ordered]@{
                path = (Join-Path $provenanceEvidenceRoot 'D32-PHASE0-VENDORED-PROTOC-RUN-GRANT.json')
                bytes = [Int64]1
                sha256 = ('a' * 64)
                volume_serial_hex = ('0' * 16)
                file_id_hex = ('0' * 32)
            }
            tauri_macros_source_patch = [ordered]@{
                path = (Join-Path $provenanceEvidenceRoot 'D32-TAURI-MACROS-SOURCE-PATCH-AUTHORITY.json')
                bytes = [Int64]1
                sha256 = ('b' * 64)
                volume_serial_hex = ('0' * 16)
                file_id_hex = ('1' * 32)
            }
            powershell_module_admission = $fixtureSyntheticAdmission
        }
        Assert-D32FixtureBuildProvenanceShape -Document $provenanceDocument
        $oldTraceProvenance = [ordered]@{}
        foreach ($field in $provenanceDocument.Keys) { $oldTraceProvenance[$field] = $provenanceDocument[$field] }
        $oldTraceProvenance.process_traces = @($provenanceDocument.process_traces | ForEach-Object {
            $oldTraceEntry = [ordered]@{}
            foreach ($entryField in $_.Keys) { $oldTraceEntry[$entryField] = $_[$entryField] }
            $oldTrace = [ordered]@{}
            foreach ($traceField in $_.process_trace.Keys) { $oldTrace[$traceField] = $_.process_trace[$traceField] }
            $oldTrace.record_type = 'D32_DEBUG_JOB_PROCESS_TRACE_V2'
            $oldTrace.schema_version = 2
            $oldTrace.event_source = 'Win32-WaitForDebugEvent-synchronous'
            foreach ($traceField in @('uncontinued_create_process_id', 'uncontinued_create_continue_call_count', 'debugger_thread_id', 'dedicated_debugger_thread', 'debugger_kill_on_exit_enabled', 'root_resumed_after_kill_on_exit',
                    'debugger_thread_exited', 'debugger_thread_joined', 'retained_process_handle_count', 'retained_process_handles_signaled',
                    'debugger_association_query_verified', 'debugger_association_absent')) { $oldTrace.Remove($traceField) }
            $oldTraceEntry.process_trace = $oldTrace
            $oldTraceEntry
        })
        try {
            Assert-D32FixtureBuildProvenanceShape -Document $oldTraceProvenance
            throw 'SELFTEST_FAILED: previous synchronous process trace V2 shape was accepted under the approved dedicated-thread trace V2 contract'
        }
        catch { if ($_.Exception.Message -notlike 'FIXTURE_PROVENANCE_INVALID:*') { throw } }
        $oldTraceProvenance.process_traces[0].process_trace.record_type = 'D32_DEBUG_JOB_PROCESS_TRACE_V1'
        $oldTraceProvenance.process_traces[0].process_trace.schema_version = 1
        try {
            Assert-D32FixtureBuildProvenanceShape -Document $oldTraceProvenance
            throw 'SELFTEST_FAILED: previous process trace V1 was accepted'
        }
        catch { if ($_.Exception.Message -notlike 'FIXTURE_PROVENANCE_INVALID:*') { throw } }
        $oldProvenance = [ordered]@{}
        foreach ($field in $provenanceDocument.Keys) { $oldProvenance[$field] = $provenanceDocument[$field] }
        $oldProvenance.schema_version = 1
        $oldProvenance.record_type = 'D32_FIXTURE_BUILD_PROVENANCE_V1'
        try {
            Assert-D32FixtureBuildProvenanceShape -Document $oldProvenance
            throw 'SELFTEST_FAILED: old fixture provenance v1 was accepted without process event evidence'
        }
        catch { if ($_.Exception.Message -notlike 'FIXTURE_PROVENANCE_INVALID:*') { throw } }
        foreach ($oldProvenanceVersion in @(
                [PSCustomObject]@{ Version = 6; Type = 'D32_FIXTURE_BUILD_PROVENANCE_V6'; Name = 'previous V6' },
                [PSCustomObject]@{ Version = 99; Type = 'D32_FIXTURE_BUILD_PROVENANCE_V99'; Name = 'unknown V99' }
            )) {
            $versionedProvenance = [ordered]@{}
            foreach ($field in $provenanceDocument.Keys) { $versionedProvenance[$field] = $provenanceDocument[$field] }
            $versionedProvenance.schema_version = $oldProvenanceVersion.Version
            $versionedProvenance.record_type = $oldProvenanceVersion.Type
            $versionRejected = $false
            try { Assert-D32FixtureBuildProvenanceShape -Document $versionedProvenance }
            catch { $versionRejected = $_.Exception.Message -like 'FIXTURE_PROVENANCE_INVALID:*' }
            if (-not $versionRejected) { throw "SELFTEST_FAILED: $($oldProvenanceVersion.Name) fixture provenance was accepted" }
        }
        $budgetPreserved = [ordered]@{}
        foreach ($field in $provenanceDocument.fixture_build_budget.Keys) { $budgetPreserved[$field] = $provenanceDocument.fixture_build_budget[$field] }
        foreach ($budgetMutation in @(
                [PSCustomObject]@{ Field = 'fixture_build_timeout_seconds'; Value = 14400 },
                [PSCustomObject]@{ Field = 'fixture_build_timeout_seconds'; Value = 28801 },
                [PSCustomObject]@{ Field = 'cargo_build_jobs'; Value = 1 },
                [PSCustomObject]@{ Field = 'cargo_build_jobs'; Value = 2 },
                [PSCustomObject]@{ Field = 'cargo_build_jobs'; Value = 5 }
            )) {
            $provenanceDocument.fixture_build_budget = [ordered]@{}
            foreach ($field in $budgetPreserved.Keys) { $provenanceDocument.fixture_build_budget[$field] = $budgetPreserved[$field] }
            $provenanceDocument.fixture_build_budget[$budgetMutation.Field] = $budgetMutation.Value
            $budgetMutationRejected = $false
            try { Assert-D32FixtureBuildProvenanceShape -Document $provenanceDocument }
            catch { $budgetMutationRejected = $_.Exception.Message -like 'FIXTURE_PROVENANCE_INVALID:*' -or $_.Exception.Message -like 'FIXTURE_BUILD_BUDGET_INVALID:*' }
            if (-not $budgetMutationRejected) { throw "SELFTEST_FAILED: fixture provenance accepted $($budgetMutation.Field)=$($budgetMutation.Value)" }
        }
        $provenanceDocument.fixture_build_budget = [ordered]@{}
        foreach ($field in $budgetPreserved.Keys) { $provenanceDocument.fixture_build_budget[$field] = $budgetPreserved[$field] }
        $goodAccounting = $fakeProcessTrace.accounting_consistent
        $fakeProcessTrace.accounting_consistent = $false
        try {
            Assert-D32FixtureBuildProvenanceShape -Document $provenanceDocument
            throw 'SELFTEST_FAILED: fixture process trace with mismatched Job accounting was accepted'
        }
        catch { if ($_.Exception.Message -notlike 'FIXTURE_PROVENANCE_INVALID:*') { throw } }
        $fakeProcessTrace.accounting_consistent = $goodAccounting
        $validFetchCommand = @($provenanceEnvironment.fetch_manifests[0].command)
        $provenanceEnvironment.fetch_manifests[0].command = $validFetchCommand + @('--offline')
        try {
            Assert-D32FixtureBuildProvenanceShape -Document $provenanceDocument
            throw 'SELFTEST_FAILED: fixture sidecar fetch argv with an unapproved --offline token was accepted'
        }
        catch { if ($_.Exception.Message -notlike 'FIXTURE_PROVENANCE_INVALID:*') { throw } }
        $provenanceEnvironment.fetch_manifests[0].command = $validFetchCommand
        $validFetchIdentityVerified = $provenanceEnvironment.fetch_manifests[0].process_identity.identity_verified
        $provenanceEnvironment.fetch_manifests[0].process_identity.identity_verified = $false
        try {
            Assert-D32FixtureBuildProvenanceShape -Document $provenanceDocument
            throw 'SELFTEST_FAILED: fixture sidecar unverified Cargo process identity was accepted'
        }
        catch { if ($_.Exception.Message -notlike 'FIXTURE_PROVENANCE_INVALID:*') { throw } }
        $provenanceEnvironment.fetch_manifests[0].process_identity.identity_verified = $validFetchIdentityVerified
        $passed++
        $provenanceJsonPath = Join-Path $root 'fixture-build-provenance.json'
        $provenanceFile = Write-D32NewFixtureBuildProvenance -Path $provenanceJsonPath -Document $provenanceDocument
        $provenanceFileOnDisk = Get-D32BoundArtifact -Path $provenanceJsonPath
        if ($provenanceFile.sha256 -cne $provenanceFileOnDisk.sha256 -or
            $provenanceFile.bytes -ne $provenanceFileOnDisk.bytes) {
            throw 'SELFTEST_FAILED: separate versioned fixture provenance record was not written and bound'
        }
        $parsedProvenance = [IO.File]::ReadAllText($provenanceJsonPath, [Text.Encoding]::UTF8) | ConvertFrom-Json -AsHashtable -DateKind String
        Assert-D32FixtureBuildProvenanceShape -Document $parsedProvenance
        if ($parsedProvenance.environment.fetch_manifests[0].process_identity.command_line -cne
            $provenanceEnvironment.fetch_manifests[0].process_identity.command_line) {
            throw 'SELFTEST_FAILED: serialized sidecar fetch process identity did not round-trip as producer-shaped JSON'
        }
        $passed++

        $ambientHandle = [IntPtr]::Zero
        try {
            $ambientHandle = [D32FixtureNativeProcessV2]::CreateInheritableTestHandle()
            if ([D32FixtureNativeProcessV2]::IsInheritableTestHandleSignaled($ambientHandle)) {
                throw 'SELFTEST_FAILED: ambient inheritable test event unexpectedly started signaled'
            }
            $ambientProbeScript = Join-Path $root 'ambient-handle-probe.ps1'
            $ambientProbeResult = Join-Path $root 'ambient-handle-probe-result.txt'
            $ambientProbeContent = @(
                'Add-Type -TypeDefinition ''using System; using System.Runtime.InteropServices; public static class D32AmbientHandleProbe { [DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetEvent(IntPtr handle); }'' -Language CSharp'
                ('$handle = [IntPtr]{0}' -f $ambientHandle.ToInt64())
                '$setEventSucceeded = [D32AmbientHandleProbe]::SetEvent($handle)'
                ('[IO.File]::WriteAllText(''{0}'', [string]$setEventSucceeded)' -f $ambientProbeResult)
                'exit 0'
            ) -join [Environment]::NewLine
            [IO.File]::WriteAllText($ambientProbeScript, $ambientProbeContent, [Text.UTF8Encoding]::new($false))
            $ambient = Invoke-D32BoundedProcess `
                -FilePath $powershell `
                -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $ambientProbeScript) `
                -WorkingDirectory $root `
                -PhaseLog (Join-Path $root 'ambient-handle-phase') `
                -TimeoutSeconds 5
            $ambientEventSignaled = [D32FixtureNativeProcessV2]::IsInheritableTestHandleSignaled($ambientHandle)
            $ambientChildSetEvent = if (Test-Path -LiteralPath $ambientProbeResult -PathType Leaf) {
                [IO.File]::ReadAllText($ambientProbeResult).Trim()
            } else { '' }
            $ambientProbeCompleted = $ambientChildSetEvent -ceq 'True' -or $ambientChildSetEvent -ceq 'False'
            if ($ambient.status -ne 'succeeded' -or $ambient.exit_code -ne 0 -or -not $ambientProbeCompleted -or $ambientEventSignaled) {
                throw "SELFTEST_FAILED: ambient inheritable event escaped explicit handle list (status=$($ambient.status), exit=$($ambient.exit_code), parent_event_signaled=$ambientEventSignaled, child_set_event_return=$ambientChildSetEvent, error=$($ambient.error))"
            }
            Write-Host "D32_AMBIENT_HANDLE_NEGATIVE=PASS parent_event_signaled=$ambientEventSignaled child_set_event_return=$ambientChildSetEvent"
            $passed++
        }
        finally {
            if ($ambientHandle -ne [IntPtr]::Zero -and
                -not [D32FixtureNativeProcessV2]::CloseInheritableTestHandle($ambientHandle)) {
                throw 'SELFTEST_FAILED: ambient inheritable test handle could not be closed'
            }
        }

        $earlyChildPidPath = Join-Path $root 'early-child.pid'
        $earlyChildScript = Join-Path $root 'parent-early-exit.ps1'
        $earlyChildContent = @(
            '$child = Start-Process -FilePath ''{0}'' -ArgumentList ''-NoLogo'',''-NoProfile'',''-NonInteractive'',''-Command'',''Start-Sleep -Seconds 5'' -WindowStyle Hidden -PassThru'
            '[IO.File]::WriteAllText(''{1}'',[string]$child.Id)'
            'exit 0'
        ) -join [Environment]::NewLine
        [IO.File]::WriteAllText($earlyChildScript, ($earlyChildContent -f $powershell, $earlyChildPidPath), [Text.UTF8Encoding]::new($false))
        $earlyExitChild = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $earlyChildScript) -WorkingDirectory $root -PhaseLog (Join-Path $root 'parent-early-exit-phase') -TimeoutSeconds 5
        $earlyChildPid = [int][IO.File]::ReadAllText($earlyChildPidPath)
        if ($earlyExitChild.status -ne 'succeeded' -or
            $earlyExitChild.exit_code -ne 0 -or
            @(Get-D32ProcessSnapshot -ProcessId $earlyChildPid).Count -ne 0 -or
            $null -eq $earlyExitChild.native_cleanup -or
            -not [bool]$earlyExitChild.native_cleanup.cleanup_succeeded -or
            -not [bool]$earlyExitChild.native_cleanup.job_active_process_count_verified -or
            [uint32]$earlyExitChild.native_cleanup.job_active_process_count -ne 0) {
            throw 'SELFTEST_FAILED: parent early exit child was not closed by the owned job'
        }
        $passed++

        $detachedChildPidPath = Join-Path $root 'detached-child.pid'
        $detachedChildScript = Join-Path $root 'detached-reparent.ps1'
        $detachedChildContent = @(
            '$child = Start-Process -FilePath ''{0}'' -ArgumentList ''-NoLogo'',''-NoProfile'',''-NonInteractive'',''-Command'',''Start-Sleep -Seconds 5'' -WindowStyle Hidden -PassThru'
            '[IO.File]::WriteAllText(''{1}'',[string]$child.Id)'
            'exit 0'
        ) -join [Environment]::NewLine
        [IO.File]::WriteAllText($detachedChildScript, ($detachedChildContent -f $powershell, $detachedChildPidPath), [Text.UTF8Encoding]::new($false))
        $detachedChild = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $detachedChildScript) -WorkingDirectory $root -PhaseLog (Join-Path $root 'detached-reparent-phase') -TimeoutSeconds 5
        $detachedPid = [int][IO.File]::ReadAllText($detachedChildPidPath)
        if ($detachedChild.status -ne 'succeeded' -or
            @(Get-D32ProcessSnapshot -ProcessId $detachedPid).Count -ne 0 -or
            $null -eq $detachedChild.native_cleanup -or
            -not [bool]$detachedChild.native_cleanup.cleanup_succeeded -or
            -not [bool]$detachedChild.native_cleanup.job_active_process_count_verified -or
            [uint32]$detachedChild.native_cleanup.job_active_process_count -ne 0) {
            throw 'SELFTEST_FAILED: detached/reparented child was not closed by the owned job'
        }
        $passed++

        $spawnInit = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedExitZero) -WorkingDirectory $root -PhaseLog (Join-Path $root 'spawn-init-exception-phase') -TimeoutSeconds 5 -FailureInjection spawn-init
        if ($spawnInit.status -ne 'spawn_failed' -or
            $spawnInit.error -notlike '*SELFTEST_INJECTED_SPAWN_INIT_EXCEPTION*' -or
            $null -eq $spawnInit.native_cleanup -or
            -not [bool]$spawnInit.native_cleanup.cleanup_succeeded) {
            throw 'SELFTEST_FAILED: spawn initialization exception did not close its owned job'
        }
        $passed++

        $cimInit = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedExitZero) -WorkingDirectory $root -PhaseLog (Join-Path $root 'cim-init-exception-phase') -TimeoutSeconds 5 -FailureInjection cim-init
        if ($cimInit.status -ne 'spawn_failed' -or
            $cimInit.error -notlike '*SELFTEST_INJECTED_CIM_INIT_EXCEPTION*' -or
            $null -eq $cimInit.native_cleanup -or
            -not [bool]$cimInit.native_cleanup.cleanup_succeeded) {
            throw 'SELFTEST_FAILED: CIM initialization exception did not close its owned job'
        }
        $passed++

        $pipeInit = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedExitZero) -WorkingDirectory $root -PhaseLog (Join-Path $root 'pipe-init-exception-phase') -TimeoutSeconds 5 -FailureInjection pipe-init
        if ($pipeInit.status -ne 'spawn_failed' -or
            $pipeInit.error -notlike '*SELFTEST_INJECTED_PIPE_INIT_EXCEPTION*' -or
            $null -eq $pipeInit.native_cleanup -or
            -not [bool]$pipeInit.native_cleanup.cleanup_succeeded) {
            throw 'SELFTEST_FAILED: pipe initialization exception did not close its owned job'
        }
        $passed++

        $apiFailure = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedExitZero) -WorkingDirectory $root -PhaseLog (Join-Path $root 'api-failure-phase') -TimeoutSeconds 5 -FailureInjection api-failure
        if ($apiFailure.status -ne 'spawn_failed' -or
            $apiFailure.error -notlike '*D32_NATIVE_LAUNCH_FAILED*' -or
            $apiFailure.error -notlike '*SELFTEST_INJECTED_ASSIGN_API_FAILURE*' -or
            $null -ne $apiFailure.pid) {
            throw 'SELFTEST_FAILED: native API failure did not fail-closed after job/process cleanup'
        }
        $passed++

        $attributeFailure = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedExitZero) -WorkingDirectory $root -PhaseLog (Join-Path $root 'attribute-failure-phase') -TimeoutSeconds 5 -FailureInjection attribute-failure
        if ($attributeFailure.status -ne 'spawn_failed' -or
            $attributeFailure.error -notlike '*D32_NATIVE_LAUNCH_FAILED*' -or
            $attributeFailure.error -notlike '*SELFTEST_INJECTED_ATTRIBUTE_API_FAILURE*' -or
            $null -ne $attributeFailure.pid) {
            throw 'SELFTEST_FAILED: handle-list API failure did not fail-closed'
        }
        $passed++

        $pipeTimeout = Invoke-D32BoundedProcess -FilePath $powershell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedExitZero) -WorkingDirectory $root -PhaseLog (Join-Path $root 'pipe-timeout-phase') -TimeoutSeconds 5 -FailureInjection pipe-timeout
        if ($pipeTimeout.status -ne 'process_tree_error' -or
            $pipeTimeout.error -notlike '*PIPE_DRAIN_TIMEOUT*' -or
            $null -eq $pipeTimeout.native_cleanup -or
            -not [bool]$pipeTimeout.native_cleanup.cleanup_succeeded -or
            -not [bool]$pipeTimeout.native_cleanup.job_active_process_count_verified -or
            [uint32]$pipeTimeout.native_cleanup.job_active_process_count -ne 0 -or
            @($pipeTimeout.descendant_pids).Count -ne 0) {
            throw 'SELFTEST_FAILED: pipe copy timeout did not fail-closed after verified job cleanup'
        }
        $passed++

        try {
            [void](Assert-D32CandidateShaMatch `
                -ActualSha '1123456789abcdef0123456789abcdef01234567' `
                -ExpectedSha '0123456789abcdef0123456789abcdef01234567')
            throw 'SELFTEST_FAILED: changed candidate SHA was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'CANDIDATE_SHA_MISMATCH:*') { throw }
        }
        if ((Assert-D32CandidateShaMatch `
            -ActualSha '0123456789abcdef0123456789abcdef01234567' `
            -ExpectedSha '0123456789abcdef0123456789abcdef01234567') -cne '0123456789abcdef0123456789abcdef01234567') {
            throw 'SELFTEST_FAILED: exact candidate SHA pin was not preserved'
        }
        $passed++

        try {
            Assert-D32CleanGitStatus -Status ' M synthetic-dirty-file' -Root $root
            throw 'SELFTEST_FAILED: dirty worktree was accepted'
        }
        catch {
            if ($_.Exception.Message -notlike 'WORKTREE_DIRTY:*') { throw }
        }
        $passed++

        Assert-D32CleanGitIndexFlags -Output ("H tracked.rs`0H nested/source.rs`0")
        foreach ($indexFlagOutput in @("h tracked.rs`0", "S tracked.rs`0", "H tracked.rs")) {
            try {
                Assert-D32CleanGitIndexFlags -Output $indexFlagOutput
                throw 'SELFTEST_FAILED: assume-unchanged, skip-worktree, or malformed index inventory was accepted'
            }
            catch {
                if ($_.Exception.Message -notlike 'WORKTREE_DIRTY:*') { throw }
            }
        }
        $passed++

        $missingExecutable = Join-Path $root 'missing-fixture-executable.exe'
        $handleFailure = Invoke-D32BoundedProcess -FilePath $missingExecutable -Arguments @('-NoLogo') -WorkingDirectory $root -PhaseLog (Join-Path $root 'handle-failure-phase') -TimeoutSeconds 5
        if ($handleFailure.status -ne 'spawn_failed' -or
            $handleFailure.error -notlike '*D32_NATIVE_LAUNCH_FAILED*' -or
            $null -ne $handleFailure.pid) {
            throw 'SELFTEST_FAILED: native spawn/handle failure was not fail-closed'
        }
        $passed++

        $childScript = Join-Path $root 'descendant-timeout.ps1'
        $timeoutLaunch = "Start-Process -FilePath '$powershell' -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 5' -WindowStyle Hidden | Out-Null"
        $timeoutPayload = & $writeRawProcessScript -Path $childScript -StdoutText 'child-timeout-no-newline|D32_FIXTURE_EXIT_CODE=child|D32_FIXTURE_DESCENDANTS=child' -StderrText 'child-timeout-stderr-no-newline|D32_FIXTURE_PHASE=timeout|CAPTURED_DESCENDANT_PIDS=child|taskkill' -Body @($timeoutLaunch, 'Start-Sleep -Seconds 5')
        $bounded = Invoke-D32BoundedProcess `
            -FilePath $powershell `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $childScript) `
            -WorkingDirectory $root `
            -PhaseLog (Join-Path $root 'timeout-phase') `
            -TimeoutSeconds 1
        if ($bounded.status -ne 'timeout' -or
            $null -ne $bounded.exit_code -or
            $bounded.error -notlike '*captured identity*reaped*' -or
            $null -eq $bounded.root_identity_record -or
            [int]$bounded.root_identity_record.ProcessId -ne [int]$bounded.pid -or
            -not [bool]$bounded.root_identity_record.IdentityVerified -or
            @($bounded.descendant_identities).Count -lt 1 -or
            @($bounded.descendant_pids).Count -ne 0 -or
            $null -eq $bounded.native_launch -or
            [int]$bounded.native_launch.process_id -ne [int]$bounded.pid -or
            -not $bounded.Contains('process_trace') -or
            $null -eq $bounded.reap -or
            -not $bounded.reap.Contains('kill_output') -or
            @($bounded.reap.process_ids).Count -lt 2 -or
            @($bounded.reap.process_ids | Where-Object { [int]$_ -eq [int]$bounded.pid }).Count -ne 1 -or
            $null -eq $bounded.native_cleanup -or
            -not [bool]$bounded.native_cleanup.cleanup_succeeded -or
            -not [bool]$bounded.native_cleanup.job_active_process_count_verified -or
            [uint32]$bounded.native_cleanup.job_active_process_count -ne 0) {
            throw 'SELFTEST_FAILED: bounded timeout/tree reap structured status and cleanup evidence'
        }
        & $assertRawProcessStreams -Result $bounded -Payload $timeoutPayload -CaseName 'timeout with descendant cleanup'
        $passed++

        Write-Host "D32_FIXTURE_PREBUILD_SELFTEST PASS ($passed checks)"
    }
    finally {
        if ($owned -and (Test-Path -LiteralPath $root)) {
            Remove-D32OwnedDirectory $root
        }
    }
}

function Invoke-D32PinnedGitProcessIdentitySelfTest {
    param(
        [Parameter(Mandatory = $true)][string]$PinnedPath,
        [Parameter(Mandatory = $true)][string]$PinnedSha256,
        [Parameter(Mandatory = $true)][string]$Repository
    )

    if ($PSVersionTable.PSVersion -lt [version]'7.5') { throw 'SELFTEST_GIT_IDENTITY_BLOCKED: pinned Git identity test requires PowerShell 7.5 or newer' }
    $repo = Assert-D32NoReparsePath -Path $Repository
    if (-not (Test-Path -LiteralPath (Join-Path $repo '.git'))) { throw 'SELFTEST_GIT_IDENTITY_BLOCKED: supplied repository root is not a Git repository' }
    $script:PinnedGit = Get-D32PinnedGit -Path $PinnedPath -ExpectedSha256 $PinnedSha256
    $originalTimeout = [int]$script:TimeoutSeconds
    $profileVariable = Get-Variable -Name ValidatedToolchainProfile -Scope Script -ErrorAction SilentlyContinue
    $hadOriginalProfile = $null -ne $profileVariable
    $originalProfile = if ($hadOriginalProfile) { $profileVariable.Value } else { $null }
    $profileTestRoot = Join-Path ([IO.Path]::GetTempPath()) ('d32-git-identity-profile-' + [Guid]::NewGuid().ToString('N'))
    $profileRootOwned = $false
    try {
        [void](Ensure-D32OwnedDirectory $profileTestRoot)
        $profileRootOwned = $true
        $validatedProfile = $null
        $profileCases = @(Test-D32BuildToolchainProfileSelfTest `
            -Root $profileTestRoot `
            -Repository $repo `
            -ValidatedProfileOutput ([ref]$validatedProfile))
        $profileFailures = @($profileCases | Where-Object { -not [bool]$_.Passed })
        if ($profileFailures.Count -ne 0 -or $null -eq $validatedProfile -or -not [bool]$validatedProfile.IsValid -or
            @($validatedProfile.WindowsImageInventory).Count -ne 1) {
            $failedNames = @($profileFailures | ForEach-Object { [string]$_.Name }) -join ', '
            throw "SELFTEST_GIT_IDENTITY_BLOCKED: valid caller-pinned Windows child image profile unavailable: $failedNames"
        }
        $script:ValidatedToolchainProfile = $validatedProfile
        $script:TimeoutSeconds = 30
        $head = Get-D32GitOutput -Root $repo -Arguments @('rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}')
        if ($head -notmatch '^[0-9a-fA-F]{40}$') {
            throw 'SELFTEST_GIT_IDENTITY_BLOCKED: fast direct-root Git rev-parse returned no exact commit identity'
        }
        $statusOutput = Get-D32GitOutput -Root $repo -Arguments @('status', '--porcelain=v1', '--untracked-files=all') -PreserveOutput
        if ($statusOutput -isnot [string]) {
            throw 'SELFTEST_GIT_IDENTITY_BLOCKED: fast direct-root Git status output was not captured as raw text, including an empty clean result'
        }
        $indexOutput = Get-D32GitOutput -Root $repo -Arguments @('ls-files', '-v', '-z') -PreserveOutput
        if ($indexOutput -isnot [string] -or -not $indexOutput.Contains([char]0)) {
            throw 'SELFTEST_GIT_IDENTITY_BLOCKED: fast direct-root Git ls-files output was not preserved as raw NUL-delimited text'
        }
        $fastIdentityRuns = 3

        $image = Get-D32BoundArtifactWithFileId -Path $script:PinnedGit.path
        $expectedPath = Get-D32FullPath $script:PinnedGit.path
        $expectedArguments = @('--version')
        $expectedCommandLine = ConvertTo-D32CommandLine (@($expectedPath) + $expectedArguments)
        $debuggerProcess = [Diagnostics.Process]::GetCurrentProcess()
        try { $debuggerCreation = [long]$debuggerProcess.StartTime.ToUniversalTime().ToFileTimeUtc() }
        finally { $debuggerProcess.Dispose() }
        $rootCreation = [DateTime]::UtcNow.ToFileTimeUtc()
        $rootProcessId = if ([int]$PID -eq [int]::MaxValue) { [int]$PID - 1 } else { [int]$PID + 1 }
        $makeTrace = {
            param([object]$Image, [int]$RootProcessId, [int]$ParentProcessId, [long]$DebuggerCreation, [long]$RootCreation)
            $identity = [PSCustomObject]@{
                ProcessId = $RootProcessId
                ParentProcessId = $ParentProcessId
                CreationFileTime = $RootCreation
                ParentCreationFileTime = $DebuggerCreation
                ImagePath = [string]$Image.path
                Bytes = [long]$Image.bytes
                Sha256 = [string]$Image.sha256
                VolumeSerialHex = [string]$Image.volume_serial_hex
                FileIdHex = [string]$Image.file_id_hex
                ImageVerified = $true
                Exited = $true
                ExitCode = 0
                CreateSequence = 1
                ExitSequence = 2
            }
            $createEvent = [PSCustomObject]@{
                Kind = 'CREATE'; Sequence = 1; ProcessId = $RootProcessId; ParentProcessId = $ParentProcessId
                CreationFileTime = $RootCreation; ParentCreationFileTime = $DebuggerCreation; ExitCode = 0
            }
            $exitEvent = [PSCustomObject]@{
                Kind = 'EXIT'; Sequence = 2; ProcessId = $RootProcessId; ParentProcessId = $ParentProcessId
                CreationFileTime = $RootCreation; ParentCreationFileTime = $DebuggerCreation; ExitCode = 0
            }
            return [PSCustomObject]@{
                RecordType = 'D32_DEBUG_JOB_PROCESS_TRACE_V2'; SchemaVersion = 2; State = 'COMPLETED'
                BlockReason = $null
                AccountingConsistent = $true; EventChainComplete = $true; DedicatedDebuggerThread = $true
                DebuggerProcessId = $ParentProcessId; DebuggerCreationFileTime = $DebuggerCreation
                DebuggerKillOnExitEnabled = $true; RootResumedAfterKillOnExit = $true
                DebuggerThreadExited = $true; DebuggerThreadJoined = $true
                RetainedProcessHandlesSignaled = $true; DebuggerAssociationQueryVerified = $true
                DebuggerAssociationAbsent = $true; JobAccountingVerified = $true
                ProcessCreateEventCount = 1; ProcessExitEventCount = 1; ProcessEventCount = 2
                JobTotalProcesses = 1; JobActiveProcesses = 0
                UncontinuedCreateProcessId = 0; UncontinuedCreateContinueCallCount = 0
                ProcessEvents = @($createEvent, $exitEvent); Processes = @($identity)
            }
        }
        $makeTraceWithPinnedChild = {
            param([object]$Image, [object]$ChildImage, [int]$RootProcessId, [int]$ParentProcessId, [long]$DebuggerCreation, [long]$RootCreation)
            $trace = & $makeTrace $Image $RootProcessId $ParentProcessId $DebuggerCreation $RootCreation
            $childProcessId = if ($RootProcessId -lt [int]::MaxValue - 1) { $RootProcessId + 1 } else { $RootProcessId - 1 }
            $childCreation = $RootCreation + 100
            $rootIdentity = $trace.Processes[0]
            $rootIdentity.ExitSequence = 4
            $rootExitEvent = $trace.ProcessEvents[1]
            $rootExitEvent.Sequence = 4
            $childIdentity = [PSCustomObject]@{
                ProcessId = $childProcessId; ParentProcessId = $RootProcessId; CreationFileTime = $childCreation
                ParentCreationFileTime = $RootCreation; ImagePath = [string]$ChildImage.Path; Bytes = [long]$ChildImage.Bytes
                Sha256 = [string]$ChildImage.Sha256; VolumeSerialHex = [string]$ChildImage.VolumeSerialHex
                FileIdHex = [string]$ChildImage.FileIdHex; ImageVerified = $true; Exited = $true; ExitCode = 0
                CreateSequence = 2; ExitSequence = 3
            }
            $childCreateEvent = [PSCustomObject]@{
                Kind = 'CREATE'; Sequence = 2; ProcessId = $childProcessId; ParentProcessId = $RootProcessId
                CreationFileTime = $childCreation; ParentCreationFileTime = $RootCreation; ExitCode = 0
            }
            $childExitEvent = [PSCustomObject]@{
                Kind = 'EXIT'; Sequence = 3; ProcessId = $childProcessId; ParentProcessId = $RootProcessId
                CreationFileTime = $childCreation; ParentCreationFileTime = $RootCreation; ExitCode = 0
            }
            $trace.ProcessEvents = @($trace.ProcessEvents[0], $childCreateEvent, $childExitEvent, $rootExitEvent)
            $trace.Processes = @($rootIdentity, $childIdentity)
            $trace.ProcessCreateEventCount = 2; $trace.ProcessExitEventCount = 2; $trace.ProcessEventCount = 4
            $trace.JobTotalProcesses = 2; $trace.JobActiveProcesses = 0
            return $trace
        }
        $makeCleanup = {
            return [PSCustomObject]@{
                CleanupSucceeded = $true; JobCloseSucceeded = $true; JobTerminateCallSucceeded = $true
                JobActiveProcessCountVerified = $true; JobActiveProcessCount = 0; ProcessWaitSignaled = $true
                DebuggerThreadExited = $true; DebuggerThreadJoined = $true; DebuggerKillOnExitEnabled = $true
                RetainedProcessHandlesSignaled = $true; DebuggerAssociationQueryVerified = $true
                DebuggerAssociationAbsent = $true
            }
        }
        $validTrace = & $makeTrace $image $rootProcessId ([int]$PID) $debuggerCreation $rootCreation
        $validCleanup = & $makeCleanup
        Assert-D32PinnedGitProcessIdentity -Trace $validTrace -Cleanup $validCleanup `
            -Arguments $expectedArguments -CommandLine $expectedCommandLine -ExpectedParentProcessId ([int]$PID) `
            -ApprovedChildImages @($validatedProfile.WindowsImageInventory)
        $validPinnedChildTrace = & $makeTraceWithPinnedChild $image $validatedProfile.WindowsImageInventory[0] `
            $rootProcessId ([int]$PID) $debuggerCreation $rootCreation
        Assert-D32PinnedGitProcessIdentity -Trace $validPinnedChildTrace -Cleanup $validCleanup `
            -Arguments $expectedArguments -CommandLine $expectedCommandLine -ExpectedParentProcessId ([int]$PID) `
            -ApprovedChildImages @($validatedProfile.WindowsImageInventory)

        $directPinnedGit = $script:PinnedGit
        $gitInstallRoot = Get-D32FullPath (Join-Path (Split-Path -Parent (Split-Path -Parent $expectedPath)) '..')
        $wrapperPath = Join-Path $gitInstallRoot 'cmd\git.exe'
        if (-not (Test-Path -LiteralPath $wrapperPath -PathType Leaf)) {
            throw 'SELFTEST_GIT_IDENTITY_BLOCKED: installed Git wrapper path for the negative containment case is unavailable'
        }
        $wrapperImage = Get-D32BoundArtifactWithFileId -Path $wrapperPath
        $wrapperMarker = Join-Path $profileTestRoot 'wrapper-child-must-not-execute.marker'
        $wrapperMarkerUnixPath = '/' + $wrapperMarker.Substring(0, 1).ToLowerInvariant() + $wrapperMarker.Substring(2).Replace('\', '/')
        $wrapperAlias = "alias.d32-no-side-effect=!echo marker > '$wrapperMarkerUnixPath'"
        $script:PinnedGit = Get-D32PinnedGit -Path $wrapperPath -ExpectedSha256 ([string]$wrapperImage.sha256)
        $wrapperTestPin = $script:PinnedGit
        $script:D32LastPinnedGitAttempt = $null
        try {
            try {
                $null = Get-D32GitOutput -Root $repo -Arguments @('--version')
                throw 'SELFTEST_FAILED: wrapper Git root was launchable without the explicit descendant-test override'
            }
            catch { if ($_.Exception.Message -notlike 'GIT_ROOT_NOT_APPROVED:*') { throw } }
            if ($null -ne $script:D32LastPinnedGitAttempt) {
                throw 'SELFTEST_FAILED: unapproved wrapper root reached process creation before policy rejection'
            }
        }
        finally { $script:PinnedGit = $directPinnedGit }

        $script:PinnedGit = $wrapperTestPin
        $script:D32PinnedGitIdentitySelfTestOverride = $wrapperTestPin
        try {
            try {
                $null = Get-D32GitOutput -Root $repo -Arguments @('-c', $wrapperAlias, 'd32-no-side-effect')
                throw 'SELFTEST_FAILED: wrapper Git descendant was accepted as a pinned direct Git root'
            }
            catch {
                if ($_.Exception.Message -notlike 'GIT_PROCESS_IDENTITY_MISMATCH:*') { throw }
            }
        }
        finally {
            $script:PinnedGit = $directPinnedGit
            $script:D32PinnedGitIdentitySelfTestOverride = $null
        }

        $wrapperAttempt = $script:D32LastPinnedGitAttempt
        if ($null -eq $wrapperAttempt -or $wrapperAttempt.root_path -cne (Get-D32FullPath $wrapperPath) -or
            $wrapperAttempt.root_sha256 -cne [string]$wrapperImage.sha256) {
            throw 'SELFTEST_GIT_IDENTITY_BLOCKED: structured wrapper-rejection trace was not retained after the blocked launch'
        }
        $wrapperTrace = $wrapperAttempt.process_trace
        $wrapperCleanup = $wrapperAttempt.native_cleanup
        $wrapperCleanupRuntime = $wrapperAttempt.cleanup_runtime
        $wrapperRoot = @($wrapperTrace.processes | Where-Object { [string]::Equals([string]$_.image_path, (Get-D32FullPath $wrapperPath), [StringComparison]::OrdinalIgnoreCase) })
        $wrapperRootIdentityExact = $wrapperRoot.Count -eq 1 -and
            [long]$wrapperRoot[0].bytes -eq [long]$wrapperImage.bytes -and
            [string]$wrapperRoot[0].sha256 -ceq [string]$wrapperImage.sha256 -and
            [string]$wrapperRoot[0].volume_serial_hex -ceq [string]$wrapperImage.volume_serial_hex -and
            [string]$wrapperRoot[0].file_id_hex -ceq [string]$wrapperImage.file_id_hex
        if ($wrapperTrace.state -cne 'BLOCKED' -or
            $wrapperTrace.block_reason -notlike '*Git/SSH/credential helper image is never launchable*' -or
            [uint32]$wrapperTrace.uncontinued_create_process_id -le 0 -or
            [int]$wrapperTrace.uncontinued_create_continue_call_count -ne 0 -or
            -not $wrapperRootIdentityExact -or -not [bool]$wrapperRoot[0].image_verified -or
            -not [bool]$wrapperCleanupRuntime.debugger_thread_exited -or
            -not [bool]$wrapperCleanupRuntime.debugger_thread_joined -or
            -not [bool]$wrapperCleanupRuntime.debugger_kill_on_exit_enabled -or
            -not [bool]$wrapperCleanupRuntime.retained_process_handles_signaled -or
            -not [bool]$wrapperCleanupRuntime.debugger_association_query_verified -or
            -not [bool]$wrapperCleanupRuntime.debugger_association_absent -or
            -not [bool]$wrapperCleanup.cleanup_succeeded -or
            -not [bool]$wrapperCleanup.job_active_process_count_verified -or
            [uint32]$wrapperCleanup.job_active_process_count -ne 0 -or
            (Test-Path -LiteralPath $wrapperMarker)) {
            throw "SELFTEST_GIT_IDENTITY_BLOCKED: wrapper rejection lacks pre-continue, marker, or complete cleanup proof: $($wrapperAttempt | ConvertTo-Json -Depth 20 -Compress)"
        }
        Write-Host ('D32_PINNED_GIT_WRAPPER_REJECTION_TRACE=' + ($wrapperAttempt | ConvertTo-Json -Depth 20 -Compress))

        $identityNegativeCases = @(
            [PSCustomObject]@{ Name = 'stale or reused PID'; Kind = 'identity'; Property = 'ProcessId'; Value = $rootProcessId + 1 },
            [PSCustomObject]@{ Name = 'stale creation identity'; Kind = 'identity'; Property = 'CreationFileTime'; Value = $rootCreation + 1 },
            [PSCustomObject]@{ Name = 'image path mismatch'; Kind = 'identity'; Property = 'ImagePath'; Value = (Join-Path $repo 'other-git.exe') },
            [PSCustomObject]@{ Name = 'image byte-count mismatch'; Kind = 'identity'; Property = 'Bytes'; Value = [long]$image.bytes + 1 },
            [PSCustomObject]@{ Name = 'image hash mismatch'; Kind = 'identity'; Property = 'Sha256'; Value = ('0' * 64) },
            [PSCustomObject]@{ Name = 'image volume-serial mismatch'; Kind = 'identity'; Property = 'VolumeSerialHex'; Value = ('0' * 16) },
            [PSCustomObject]@{ Name = 'image file-ID mismatch'; Kind = 'identity'; Property = 'FileIdHex'; Value = ('0' * 32) },
            [PSCustomObject]@{ Name = 'parent identity mismatch'; Kind = 'identity'; Property = 'ParentProcessId'; Value = if ([int]$PID -eq [int]::MaxValue) { [int]$PID - 1 } else { [int]$PID + 1 } },
            [PSCustomObject]@{ Name = 'parent creation identity mismatch'; Kind = 'identity'; Property = 'ParentCreationFileTime'; Value = $debuggerCreation + 1 },
            [PSCustomObject]@{ Name = 'incomplete CREATE/EXIT event chain'; Kind = 'trace'; Property = 'EventChainComplete'; Value = $false },
            [PSCustomObject]@{ Name = 'debugger timeout'; Kind = 'trace'; Property = 'State'; Value = 'BLOCKED' },
            [PSCustomObject]@{ Name = 'unexpected descendant'; Kind = 'trace'; Property = 'JobTotalProcesses'; Value = 2 },
            [PSCustomObject]@{ Name = 'incomplete cleanup'; Kind = 'cleanup'; Property = 'DebuggerThreadJoined'; Value = $false }
        )
        foreach ($case in $identityNegativeCases) {
            $trace = & $makeTrace $image $rootProcessId ([int]$PID) $debuggerCreation $rootCreation
            $cleanup = & $makeCleanup
            $identity = $trace.Processes[0]
            $commandLine = $expectedCommandLine
            if ($case.Kind -ceq 'identity') { $identity.($case.Property) = $case.Value }
            elseif ($case.Kind -ceq 'trace') {
                $trace.($case.Property) = $case.Value
                $trace.AccountingConsistent = $false
            }
            else { $cleanup.($case.Property) = $case.Value }
            try {
                Assert-D32PinnedGitProcessIdentity -Trace $trace -Cleanup $cleanup `
                    -Arguments $expectedArguments -CommandLine $commandLine -ExpectedParentProcessId ([int]$PID) `
                    -ApprovedChildImages @($validatedProfile.WindowsImageInventory)
                throw "SELFTEST_FAILED: Git process identity negative '$($case.Name)' was accepted"
            }
            catch {
                $expectedPrefix = if ($case.Kind -ceq 'cleanup') { 'GIT_PROCESS_CLEANUP_FAILED:*' } else { 'GIT_PROCESS_IDENTITY_MISMATCH:*' }
                if ($_.Exception.Message -notlike $expectedPrefix) { throw }
            }
        }

        foreach ($case in @(
            [PSCustomObject]@{ Name = 'Windows child image path mismatch'; Property = 'ImagePath'; Value = (Join-Path $repo 'other-conhost.exe') },
            [PSCustomObject]@{ Name = 'Windows child image byte-count mismatch'; Property = 'Bytes'; Value = [long]$validatedProfile.WindowsImageInventory[0].Bytes + 1 },
            [PSCustomObject]@{ Name = 'Windows child image hash mismatch'; Property = 'Sha256'; Value = ('0' * 64) },
            [PSCustomObject]@{ Name = 'Windows child volume-serial mismatch'; Property = 'VolumeSerialHex'; Value = ('0' * 16) },
            [PSCustomObject]@{ Name = 'Windows child file-ID mismatch'; Property = 'FileIdHex'; Value = ('0' * 32) },
            [PSCustomObject]@{ Name = 'Windows child PID reuse'; Property = 'ProcessId'; Value = if ($rootProcessId -lt [int]::MaxValue - 1) { $rootProcessId + 2 } else { $rootProcessId - 2 } },
            [PSCustomObject]@{ Name = 'Windows child stale creation identity'; Property = 'CreationFileTime'; Value = $rootCreation + 101 },
            [PSCustomObject]@{ Name = 'Windows child parent PID mismatch'; Property = 'ParentProcessId'; Value = if ($rootProcessId -eq [int]::MaxValue) { $rootProcessId - 1 } else { $rootProcessId + 1 } },
            [PSCustomObject]@{ Name = 'Windows child parent creation mismatch'; Property = 'ParentCreationFileTime'; Value = $rootCreation + 1 }
        )) {
            $trace = & $makeTraceWithPinnedChild $image $validatedProfile.WindowsImageInventory[0] `
                $rootProcessId ([int]$PID) $debuggerCreation $rootCreation
            $cleanup = & $makeCleanup
            $trace.Processes[1].($case.Property) = $case.Value
            try {
                Assert-D32PinnedGitProcessIdentity -Trace $trace -Cleanup $cleanup `
                    -Arguments $expectedArguments -CommandLine $expectedCommandLine -ExpectedParentProcessId ([int]$PID) `
                    -ApprovedChildImages @($validatedProfile.WindowsImageInventory)
                throw "SELFTEST_FAILED: Git child-image negative '$($case.Name)' was accepted"
            }
            catch { if ($_.Exception.Message -notlike 'GIT_PROCESS_IDENTITY_MISMATCH:*') { throw } }
        }

        $commandLineMismatchTrace = & $makeTrace $image $rootProcessId ([int]$PID) $debuggerCreation $rootCreation
        $commandLineMismatchCleanup = & $makeCleanup
        try {
            Assert-D32PinnedGitProcessIdentity -Trace $commandLineMismatchTrace -Cleanup $commandLineMismatchCleanup `
                -Arguments $expectedArguments -CommandLine ($expectedCommandLine + ' --extra') -ExpectedParentProcessId ([int]$PID) `
                -ApprovedChildImages @($validatedProfile.WindowsImageInventory)
            throw 'SELFTEST_FAILED: Git process command-line mismatch was accepted'
        }
        catch { if ($_.Exception.Message -notlike 'GIT_PROCESS_IDENTITY_MISMATCH:*') { throw } }

        Assert-D32PinnedGitCurrent
    }
    finally {
        $script:TimeoutSeconds = $originalTimeout
        if ($hadOriginalProfile) { $script:ValidatedToolchainProfile = $originalProfile }
        else { Remove-Variable -Name ValidatedToolchainProfile -Scope Script -Force -ErrorAction SilentlyContinue }
        if ($profileRootOwned -and (Test-Path -LiteralPath $profileTestRoot)) { Remove-D32OwnedDirectory $profileTestRoot }
    }

    Write-Host "D32_FIXTURE_GIT_PROCESS_IDENTITY_SELFTEST PASS (direct-root fast Git exits=$fastIdentityRuns for rev-parse/status/ls-files; exact Coordinator-pinned image/process identity; unapproved wrapper root rejected before launch; test-only wrapper child hard-denied before Continue with marker absent and complete cleanup; path/bytes/hash/volume/file-ID/stale-PID/creation/parent/event/timeout/Job/descendant/cleanup negatives rejected)"
}

if ($D32LauncherLibraryOnly) {
    if ($SelfTest) {
        throw 'D32_LAUNCHER_LIBRARY_MODE_INVALID: -D32LauncherLibraryOnly and -SelfTest are mutually exclusive'
    }
    Ensure-D32NativeLauncher
    return
}

if ($SelfTest) {
    Invoke-D32SelfTest
    $hasPinnedGitPath = -not [String]::IsNullOrWhiteSpace($PinnedGitPath)
    $hasPinnedGitSha = -not [String]::IsNullOrWhiteSpace($PinnedGitSha256)
    if ($hasPinnedGitPath -ne $hasPinnedGitSha) {
        throw 'SELFTEST_GIT_IDENTITY_BLOCKED: -PinnedGitPath and -PinnedGitSha256 must be supplied together'
    }
    if ($hasPinnedGitPath) {
        if ([String]::IsNullOrWhiteSpace($RepoRoot)) { throw 'SELFTEST_GIT_IDENTITY_BLOCKED: -RepoRoot is required with Git identity selftest pins' }
        Invoke-D32PinnedGitProcessIdentitySelfTest -PinnedPath $PinnedGitPath -PinnedSha256 $PinnedGitSha256 -Repository $RepoRoot
    }
    exit 0
}

if ($PSVersionTable.PSVersion -lt [version]'7.5') {
    throw 'TOOLCHAIN_PROFILE_BLOCKED: operational D32 builds require PowerShell 7.5 or later for the shared pinned-profile validator'
}
Assert-D32FixtureTimeoutScope `
    -TimeoutSeconds $TimeoutSeconds `
    -OwnerBinding $Phase0OwnerBinding `
    -BuildD31RecoverySeeder ([bool]$BuildD31RecoverySeeder)
Assert-D32FixtureBuildBudgetScope `
    -OwnerBinding $Phase0OwnerBinding `
    -BuildD31RecoverySeeder ([bool]$BuildD31RecoverySeeder) `
    -TimeoutSeconds $TimeoutSeconds `
    -FixtureBuildTimeoutSeconds $Phase0FixtureBuildTimeoutSeconds `
    -BuildJobs $BuildJobs `
    -Capacity $Phase0FixtureBuildCapacity
$fixtureBuildMode = Get-D32FixtureBuildMode -OwnerBinding $Phase0OwnerBinding -BuildD31RecoverySeeder ([bool]$BuildD31RecoverySeeder)
Assert-D32FixtureBuildModeAuthority -Mode $fixtureBuildMode
if ([String]::IsNullOrWhiteSpace($PinnedGitPath) -or
    [String]::IsNullOrWhiteSpace($PinnedGitSha256) -or
    [String]::IsNullOrWhiteSpace($ExpectedCandidateSha) -or
    [String]::IsNullOrWhiteSpace($ToolchainProfilePath) -or
    [String]::IsNullOrWhiteSpace($ExpectedToolchainProfileSha256)) {
    throw 'TRUST_PINS_REQUIRED: operational runs require pinned Git, exact candidate SHA, and caller-pinned toolchain profile path/SHA; use -SelfTest only for local self-tests'
}
if ($ExpectedCandidateSha -notmatch '^[0-9a-f]{40}$') {
    throw 'CANDIDATE_SHA_INVALID: -ExpectedCandidateSha must be exactly 40 lowercase hexadecimal characters'
}
$script:ExpectedCandidateSha = $ExpectedCandidateSha
if ([String]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Join-Path $script:ScriptRoot '..'
}
$RepoRoot = Assert-D32NoReparsePath -Path $RepoRoot
if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot '.git'))) {
    throw "REPOSITORY_INVALID: not a Git repository root: $RepoRoot"
}
$earlyToolchainProfile = Test-D32BuildToolchainProfile `
    -ProfilePath $ToolchainProfilePath `
    -ExpectedSha256 $ExpectedToolchainProfileSha256 `
    -Repository $RepoRoot `
    -ExpectedTargetTriple 'x86_64-pc-windows-msvc'
if (-not [bool]$earlyToolchainProfile.IsValid) {
    throw "TOOLCHAIN_PROFILE_BLOCKED: $($earlyToolchainProfile.Failure)"
}
$script:ValidatedToolchainProfile = $earlyToolchainProfile
$script:PinnedGit = Get-D32PinnedGit -Path $PinnedGitPath -ExpectedSha256 $PinnedGitSha256

$candidateSha = Assert-D32PinnedCleanCandidate -Root $RepoRoot
Write-Host "D32_FIXTURE_CANDIDATE_SHA=$candidateSha"
Write-Host "D32_FIXTURE_PINNED_GIT_PATH=$($script:PinnedGit.path)"
Write-Host "D32_FIXTURE_PINNED_GIT_SHA256=$($script:PinnedGit.sha256)"
Write-Host "D32_PINNED_GIT_PATH=$($script:PinnedGit.path)"
Write-Host "D32_PINNED_GIT_SHA256=$($script:PinnedGit.sha256)"
Write-Host "D32_EXPECTED_CANDIDATE_SHA=$candidateSha"
if ([String]::IsNullOrWhiteSpace($OutputRoot)) {
    if (-not [String]::IsNullOrWhiteSpace($ManifestPath)) {
        $OutputRoot = Split-Path -Parent (Get-D32FullPath $ManifestPath)
    }
    else {
        $temporaryRoot = Assert-D32NoReparsePath -Path ([IO.Path]::GetTempPath())
        $fixtureOutputParent = Join-Path $temporaryRoot 'digital-life-d32-fixtures'
        if (Test-Path -LiteralPath $fixtureOutputParent) {
            [void](Assert-D32NoReparsePath -Path $fixtureOutputParent)
        }
        else {
            [void](Assert-D32NoReparsePath -Path $fixtureOutputParent -AllowMissingLeaf)
        }
        $fixtureOutputParent = Ensure-D32OwnedDirectory $fixtureOutputParent
        $OutputRoot = Join-Path $fixtureOutputParent $candidateSha
    }
}
$OutputRoot = Get-D32FullPath $OutputRoot
if (Test-D32PathWithin -Path $OutputRoot -Root $RepoRoot) {
    throw 'OUTPUT_NOT_OWNED: fixture output root must be outside the candidate repository'
}
$outputParent = Split-Path -Parent $OutputRoot
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    throw "OUTPUT_NOT_OWNED: fixture output parent must already exist: $outputParent"
}
[void](Assert-D32NoReparsePath -Path $outputParent)
if (Test-Path -LiteralPath $OutputRoot) {
    [void](Assert-D32NoReparsePath -Path $OutputRoot)
}
else {
    [void](Assert-D32NoReparsePath -Path $OutputRoot -AllowMissingLeaf)
}
$OutputRoot = Ensure-D32OwnedDirectory $OutputRoot
$OutputRoot = Assert-D32NoReparsePath -Path $OutputRoot
if ([String]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $OutputRoot 'fixture-manifest.json'
}
$ManifestPath = Assert-D32ManifestDestination -Path $ManifestPath -OwnedRoot $OutputRoot
$ManifestPath = Assert-D32NoReparsePath -Path $ManifestPath -AllowMissingLeaf
$fixtureProvenancePath = Assert-D32NoReparsePath -Path (Join-Path $OutputRoot 'fixture-build-provenance.json') -AllowMissingLeaf
if (Test-Path -LiteralPath $fixtureProvenancePath) {
    throw "FIXTURE_PROVENANCE_NOT_NEW: refusing to reuse an existing fixture build provenance sidecar: $fixtureProvenancePath"
}
$logRoot = Ensure-D32OwnedDirectory (Join-Path $OutputRoot 'logs')
$logRoot = Assert-D32NoReparsePath -Path $logRoot
$validatedToolchainProfile = Test-D32BuildToolchainProfile `
    -ProfilePath $ToolchainProfilePath `
    -ExpectedSha256 $ExpectedToolchainProfileSha256 `
    -Repository $RepoRoot `
    -EvidenceRoot $OutputRoot `
    -ExpectedTargetTriple 'x86_64-pc-windows-msvc'
if (-not [bool]$validatedToolchainProfile.IsValid) {
    throw "TOOLCHAIN_PROFILE_BLOCKED: $($validatedToolchainProfile.Failure)"
}
$script:ValidatedToolchainProfile = $validatedToolchainProfile
if ($null -eq $Phase0OwnerBinding) { throw 'PHASE0_OWNER_BLOCKED: Phase0 fixture builds require the fixed Phase0 runner owner binding' }
$script:D32TauriMacrosSourcePatchAuthority = Test-D32TauriMacrosSourcePatchAuthority `
    -AuthorityPath $TauriMacrosSourceAuthorityPath `
    -ExpectedAuthoritySha256 $ExpectedTauriMacrosSourceAuthoritySha256 `
    -Repository $RepoRoot `
    -CandidateSha $candidateSha `
    -ValidatedProfile $validatedToolchainProfile `
    -EvidenceRoot $OutputRoot
$cargo = [string]$validatedToolchainProfile.Profile.toolchain.cargo.path
$cargo = Assert-D32NoReparsePath -Path $cargo
$null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $validatedToolchainProfile
$phase0Storage = Initialize-D32FixturePhase0Storage `
    -OutputRoot $OutputRoot `
    -Repository $RepoRoot `
    -ExpectedCandidateSha $candidateSha `
    -ValidatedProfile $validatedToolchainProfile `
    -OwnerBinding $Phase0OwnerBinding
$phase0OwnerContext = $phase0Storage.OwnerContext
$toolchainRunRoot = [string]$phase0Storage.RunRoot
$fixtureCargoHome = [string]$phase0Storage.CargoHome
$fixtureTempRoot = [string]$phase0Storage.TempRoot
$script:D32Phase0StorageContext = $phase0Storage.StorageContext
$toolchainRunId = [string]$script:D32Phase0StorageContext.run_id
$script:D32Phase0FailurePayloadEmitted = $false
$fixtureManifestEnvironment = Get-D32EnvironmentPlan -EnvironmentRoot (Join-Path $toolchainRunRoot 'manifest-environment')
Assert-D32FixtureManifestEnvironmentShape -Environment $fixtureManifestEnvironment
$phaseEvidence = [System.Collections.Generic.List[object]]::new()
$fixtureFetches = Invoke-D32FixturePreCargoBoundary `
    -OutputRoot $OutputRoot `
    -Repository $RepoRoot `
    -ExpectedCandidateSha $candidateSha `
    -ValidatedProfile $validatedToolchainProfile `
    -OwnerBinding $Phase0OwnerBinding `
    -StorageContext $script:D32Phase0StorageContext `
    -FetchAction {
        Invoke-D32LockedCargoFetches `
            -ValidatedProfile $validatedToolchainProfile `
            -CargoPath $cargo `
            -CargoHome $fixtureCargoHome `
            -TempRoot $fixtureTempRoot `
            -RepoRoot $RepoRoot `
            -LogRoot $logRoot `
            -TimeoutSeconds $TimeoutSeconds `
            -LogPrefix 'fixture' `
            -PhaseEvidence $phaseEvidence `
            -AllowPinnedCargoVctip
    }
$script:D32VendoredProtocRunGrant = New-D32VendoredProtocRunGrant `
    -AuthorityPath $VendoredProtocAuthorityPath `
    -AuthoritySha256 $ExpectedVendoredProtocAuthoritySha256 `
    -Repository $RepoRoot `
    -CandidateSha $candidateSha `
    -ValidatedProfile $validatedToolchainProfile `
    -EvidenceRoot $OutputRoot `
    -OwnerMarkerReference $phase0OwnerContext.OwnerMarker `
    -RunId $toolchainRunId `
    -CargoHome $fixtureCargoHome
$null = Test-D32CargoHome -Path $fixtureCargoHome -Repository $RepoRoot
$offlineFixtureEnvironment = Get-D32BuildToolchainEnvironment `
    -ValidatedProfile $validatedToolchainProfile `
    -CargoHome $fixtureCargoHome `
    -TempRoot $fixtureTempRoot `
    -Offline $true
if ($offlineFixtureEnvironment.Contains('PROTOC')) { throw 'VENDORED_PROTOC_ENV_BLOCKED: caller profile/base environment must not supply ambient PROTOC' }
$null = Test-D32ProfileDirectoryIdentity -Path $OutputRoot -VolumeSerialHex $phase0OwnerContext.EvidenceRootIdentity.VolumeSerialHex -FileIdHex $phase0OwnerContext.EvidenceRootIdentity.FileIdHex
$null = Test-D32ProfileDirectoryIdentity -Path $toolchainRunRoot -VolumeSerialHex $script:D32Phase0StorageContext.run_root.volume_serial_hex -FileIdHex $script:D32Phase0StorageContext.run_root.file_id_hex
$null = Test-D32ProfileDirectoryIdentity -Path $fixtureCargoHome -VolumeSerialHex $script:D32Phase0StorageContext.cargo_home.volume_serial_hex -FileIdHex $script:D32Phase0StorageContext.cargo_home.file_id_hex
$null = Test-D32ProfileDirectoryIdentity -Path $fixtureTempRoot -VolumeSerialHex $script:D32Phase0StorageContext.temp_root.volume_serial_hex -FileIdHex $script:D32Phase0StorageContext.temp_root.file_id_hex
$fixtureEnvironmentPlan = [ordered]@{
    toolchain_profile_path = [string]$validatedToolchainProfile.ProfilePath
    toolchain_profile_sha256 = [string]$validatedToolchainProfile.Digest
    target_triple = [string]$validatedToolchainProfile.Profile.target_triple
    env_policy = [string]$validatedToolchainProfile.Profile.env_policy
    cargo_policy = [string]$validatedToolchainProfile.Profile.cargo_policy
    cargo_home = [string]$fixtureCargoHome
    temp_root = [string]$fixtureTempRoot
    run_id = $toolchainRunId
    fetch_manifests = @($fixtureFetches)
    offline_after_fetch = $true
}
$null = Assert-D32PinnedCleanCandidate -Root $RepoRoot
$gitStatus = ''
Write-Host "D32_BUILD_TOOLCHAIN_PROFILE_PATH=$($validatedToolchainProfile.ProfilePath)"
Write-Host "D32_EXPECTED_TOOLCHAIN_PROFILE_SHA256=$($validatedToolchainProfile.Digest)"
Write-Host "D32_BUILD_TOOLCHAIN_RUN_ID=$toolchainRunId"

$seederTargetDir = $null
$seederRecordPath = $null
$seederRunId = $null
if ($BuildD31RecoverySeeder) {
    $seederPaths = Get-D32D31RecoverySeederPaths -OutputRoot $OutputRoot
    $seederTargetDir = $seederPaths.target
    if (Test-Path -LiteralPath $seederTargetDir) {
        throw "D31_RECOVERY_SEEDER_TARGET_NOT_NEW: refusing to reuse an existing external Cargo target directory: $seederTargetDir"
    }
    if (Test-D32PathWithin -Path $seederTargetDir -Root $RepoRoot) {
        throw 'D31_RECOVERY_SEEDER_TARGET_INVALID: recovery-seeder target must be external to the repository'
    }
    $seederRecordPath = $seederPaths.record
    if (Test-Path -LiteralPath $seederRecordPath) {
        throw "D31_RECOVERY_SEEDER_RECORD_NOT_NEW: refusing to overwrite a D31 seeder record: $seederRecordPath"
    }
    if (Test-D32PathWithin -Path $seederRecordPath -Root $RepoRoot) {
        throw 'D31_RECOVERY_SEEDER_RECORD_INVALID: record must be external to the repository'
    }
    if ((Split-Path -Parent $seederTargetDir) -ne (Split-Path -Parent $seederRecordPath)) {
        throw 'D31_RECOVERY_SEEDER_OUTPUT_INVALID: target and build record must be siblings beneath OutputRoot'
    }
    $seederRunId = [Guid]::NewGuid().ToString('N').ToLowerInvariant()
}
$results = @()
$pendingFixtureFailures = [System.Collections.Generic.List[object]]::new()
$startedAt = [DateTimeOffset]::UtcNow
try {
    $phase = 0
    foreach ($spec in $script:FixtureSpecs) {
        Reset-D32FixturePhaseProcessEvidence
        $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $validatedToolchainProfile
        $phase++
        Write-D32FixtureGitState -Phase $phase -Edge before -Root $RepoRoot
        $manifest = Get-D32FullPath (Join-Path $RepoRoot $spec.manifest)
        $artifactPath = Get-D32FullPath (Join-Path $RepoRoot $spec.artifact)
        $arguments = @('build', '--quiet', '--locked', '--manifest-path', $manifest, '--bin', $spec.binary)
        if ($spec.features.Count -gt 0) {
            $arguments += @('--features', ($spec.features -join ' '))
        }
        $arguments += @('--jobs', [string]$BuildJobs)
        $phaseLog = Join-Path $logRoot (('{0:D2}-{1}' -f $phase, $spec.name))
        Write-Host "D32_FIXTURE_PHASE=$phase name=$($spec.name) timeout_seconds=$Phase0FixtureBuildTimeoutSeconds cargo_build_jobs=$BuildJobs"
        $phaseEnvironment = $offlineFixtureEnvironment
        $phaseVendoredGrant = $script:D32VendoredProtocRunGrant
        if ([string]$spec.project -ceq 'src-tauri') {
            $phaseEnvironment = New-D32VendoredProtocEnvironment -Environment $offlineFixtureEnvironment -RunGrant $script:D32VendoredProtocRunGrant
        }
        elseif ($phaseEnvironment.Contains('PROTOC')) {
            throw 'VENDORED_PROTOC_ENV_BLOCKED: PROTOC may be set only for fixed src-tauri Cargo commands'
        }
        $processResult = $null
        try {
            $processResult = Invoke-D32BoundedProcess `
                -FilePath $cargo `
                -Arguments $arguments `
                -WorkingDirectory $RepoRoot `
                -PhaseLog $phaseLog `
                -TimeoutSeconds $Phase0FixtureBuildTimeoutSeconds `
                -ChildEnvironment $phaseEnvironment `
                -RequireDebugEvents `
                -AllowPinnedCargoVctip `
                -VendoredProtocRunGrant $phaseVendoredGrant
            Assert-D32PinnedCargoProcessIdentity `
                -ProcessIdentity $processResult.root_identity_record `
                -CargoPath $cargo `
                -Arguments $arguments `
                -ValidatedProfile $validatedToolchainProfile `
                -ProcessResult $processResult
            $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $validatedToolchainProfile
            $null = Assert-D32PinnedCleanCandidate -Root $RepoRoot
            $phaseEvidence.Add([pscustomobject]@{
                name = [string]$spec.name
                executable = [IO.Path]::GetFullPath($cargo)
                arguments = @($arguments)
                command_line = ConvertTo-D32CommandLine (@($cargo) + $arguments)
                working_directory = [IO.Path]::GetFullPath($RepoRoot)
                root_record = $processResult.root_identity_record
                descendant_records = @($processResult.captured_descendant_records)
                process_trace = $processResult.process_trace
            })
            $artifact = $null
            $artifactError = $null
            if ($processResult.status -eq 'succeeded') {
                try {
                    $artifact = Get-D32Artifact $artifactPath
                }
                catch {
                    $artifactError = $_.Exception.Message
                }
            }
            $status = if ($processResult.status -eq 'succeeded' -and $null -ne $artifact) { 'succeeded' } else { $processResult.status }
            if ($null -ne $artifactError) {
                $status = 'artifact_missing'
            }
            if ($status -notin @('succeeded', 'failed') -or $null -eq $processResult.exit_code) {
                $primaryFailure = if ($null -ne $artifactError) { "FIXTURE_ARTIFACT_BLOCKED: $artifactError" } else { "FIXTURE_BUILD_BLOCKED: $($spec.name) status=$status exit=$($processResult.exit_code)" }
                throw $primaryFailure
            }
            if ($status -ne 'succeeded' -or $processResult.exit_code -ne 0 -or $null -ne $artifactError) {
                $failure = if ($null -ne $artifactError) { "FIXTURE_ARTIFACT_BLOCKED: $artifactError" } else { "FIXTURE_BUILD_BLOCKED: $($spec.name) status=$status exit=$($processResult.exit_code)" }
                $pendingFixtureFailures.Add([PSCustomObject]@{
                    name = [string]$spec.name
                    arguments = @($arguments)
                    process_result = $processResult
                    phase_log = $phaseLog
                    error = $failure
                })
            }
            $results += [ordered]@{
                phase          = $phase
                name           = $spec.name
                project        = $spec.project
                binary         = $spec.binary
                manifest_path  = $manifest
                features       = @($spec.features)
                command        = ('cargo ' + (ConvertTo-D32CommandLine $arguments))
                status         = $status
                exit_code      = $processResult.exit_code
                pid            = $processResult.pid
                descendant_pids = @($processResult.descendant_pids)
                root_identity  = $processResult.root_identity
                descendant_identities = @($processResult.descendant_identities)
                residual_descendant_identities = @($processResult.residual_descendant_identities)
                reap           = $processResult.reap
                elapsed_ms     = $processResult.elapsed_ms
                phase_log      = $processResult.phase_log
                stdout_log     = $processResult.stdout_log
                stderr_log     = $processResult.stderr_log
                error          = if ($null -ne $artifactError) { $artifactError } else { $processResult.error }
                artifact       = $artifact
            }
        }
        catch {
            $primaryFailure = $_.Exception.Message
            $terminalFailure = [PSCustomObject]@{
                name = [string]$spec.name
                arguments = @($arguments)
                process_result = $processResult
                phase_log = $phaseLog
                error = $primaryFailure
            }
            $payloadSelection = Get-D32FixtureFailurePayloadSelection -PendingFailures @($pendingFixtureFailures.ToArray()) -TerminalFailure $terminalFailure
            try {
                Write-D32FixturePhase0FailurePayload -Name $payloadSelection.Name -Executable $cargo -Arguments $payloadSelection.Arguments -WorkingDirectory $RepoRoot -ProcessResult $payloadSelection.ProcessResult -PrimaryError $payloadSelection.PrimaryError -SecondaryErrors $payloadSelection.SecondaryErrors -PhaseLogPath $payloadSelection.PhaseLogPath
            }
            catch { $primaryFailure += '; phase0 failure-capture error=' + $_.Exception.Message }
            throw $primaryFailure
        }
        finally {
            Write-D32FixtureGitState -Phase $phase -Edge after -Root $RepoRoot
        }
    }

    if ($BuildD31RecoverySeeder) {
        $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $validatedToolchainProfile
        $null = Assert-D32PinnedCleanCandidate -Root $RepoRoot
        if (Test-Path -LiteralPath $seederTargetDir) {
            throw 'D31_RECOVERY_SEEDER_TARGET_NOT_NEW: external target appeared before the pinned build'
        }
        [void](Assert-D32NoReparsePath -Path $seederTargetDir -AllowMissingLeaf)
        $seederManifest = Get-D32FullPath (Join-Path $RepoRoot 'vita-agent/Cargo.toml')
        $seederRunRoot = Ensure-D32OwnedDirectory (Join-Path $OutputRoot "d31-recovery-seeder-run-$seederRunId")
        $seederCargoHome = New-D32FreshCargoHome -RunRoot $seederRunRoot -Repository $RepoRoot
        $seederTempRoot = Join-Path $seederRunRoot 'temp'
        [void][IO.Directory]::CreateDirectory($seederTempRoot)
        $seederTempRoot = Assert-D32NoReparsePath -Path $seederTempRoot
        $seederFetches = Invoke-D32LockedCargoFetches `
            -ValidatedProfile $validatedToolchainProfile `
            -CargoPath $cargo `
            -CargoHome $seederCargoHome `
            -TempRoot $seederTempRoot `
            -RepoRoot $RepoRoot `
            -LogRoot $logRoot `
            -TimeoutSeconds $TimeoutSeconds `
            -LogPrefix 'd31-seeder' `
            -PhaseEvidence $phaseEvidence
        $null = Test-D32CargoHome -Path $seederCargoHome -Repository $RepoRoot
        $offlineSeederEnvironment = Get-D32BuildToolchainEnvironment `
            -ValidatedProfile $validatedToolchainProfile `
            -CargoHome $seederCargoHome `
            -TempRoot $seederTempRoot `
            -Offline $true
        $seederArtifactPath = Join-Path $seederTargetDir 'debug/vita-agent.exe'
        $seederArguments = @(
            'build', '--quiet', '--locked',
            '--manifest-path', $seederManifest,
            '--bin', 'vita-agent',
            '--features', 'd29-h9-test-helper',
            '--target-dir', $seederTargetDir
        )
        $seederPhaseLog = Join-Path $logRoot 'd31-recovery-seeder'
        Write-Host "D32_FIXTURE_PHASE=seeder name=d31-recovery-seeder candidate=$candidateSha run_id=$seederRunId"
        $seederBuild = Invoke-D32BoundedProcess `
            -FilePath $cargo `
            -Arguments $seederArguments `
            -WorkingDirectory $RepoRoot `
            -PhaseLog $seederPhaseLog `
            -TimeoutSeconds $TimeoutSeconds `
            -ChildEnvironment $offlineSeederEnvironment `
            -RequireDebugEvents `
            -CandidateImageRoots @((Get-D32DebugCandidateTargetRoots -Repository $RepoRoot) + $seederTargetDir)
        if ($null -ne $seederBuild.root_identity_record) {
            Assert-D32PinnedCargoProcessIdentity `
                -ProcessIdentity $seederBuild.root_identity_record `
                -CargoPath $cargo `
                -Arguments $seederArguments `
                -ValidatedProfile $validatedToolchainProfile `
                -ProcessResult $seederBuild
        }
        $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $validatedToolchainProfile
        $null = Assert-D32PinnedCleanCandidate -Root $RepoRoot
        $phaseEvidence.Add([pscustomobject]@{
            name = 'd31-recovery-seeder'
            executable = [IO.Path]::GetFullPath($cargo)
            arguments = @($seederArguments)
            command_line = ConvertTo-D32CommandLine (@($cargo) + $seederArguments)
            working_directory = [IO.Path]::GetFullPath($RepoRoot)
            root_record = $seederBuild.root_identity_record
            descendant_records = @($seederBuild.captured_descendant_records)
            process_trace = $seederBuild.process_trace
        })
        if ($seederBuild.status -ne 'succeeded' -or $seederBuild.exit_code -ne 0) {
            throw "D31_RECOVERY_SEEDER_BUILD_FAILED: status=$($seederBuild.status) exit=$($seederBuild.exit_code); see $($seederBuild.phase_log)"
        }
        $null = Assert-D32PinnedCleanCandidate -Root $RepoRoot
        [void](Assert-D32NoReparsePath -Path $seederTargetDir)
        if (Test-D32PathWithin -Path $seederTargetDir -Root $RepoRoot) {
            throw 'D31_RECOVERY_SEEDER_TARGET_INVALID: recovery-seeder target moved inside the repository'
        }
        $seederArtifact = Get-D32BoundArtifact -Path $seederArtifactPath
        $producerIdentityRecord = $seederBuild.root_identity_record
        $seederRecord = [ordered]@{
            schema_version = 2
            purpose = 'd31-recovery-seeder-test-helper'
            run_id = $seederRunId
            candidate_sha = $candidateSha
            runner_process_id = [int]$PID
            source_repo = $RepoRoot
            manifest_path = $seederManifest
            feature = 'd29-h9-test-helper'
            command = @($seederArguments)
            target_dir = $seederTargetDir
            run_root = $seederRunRoot
            cargo_home = $seederCargoHome
            temp_root = $seederTempRoot
            toolchain_profile_path = [string]$validatedToolchainProfile.ProfilePath
            toolchain_profile_sha256 = [string]$validatedToolchainProfile.Digest
            target_triple = [string]$validatedToolchainProfile.Profile.target_triple
            powershell = $validatedToolchainProfile.Profile.powershell
            toolchain = $validatedToolchainProfile.Profile.toolchain
            fetch_manifests = @($validatedToolchainProfile.LockInputs | ForEach-Object {
                    [ordered]@{ manifest_path = [string]$_.ManifestPath; lock_sha256 = [string]$_.LockSha256 }
                })
            fetch_phases = @($seederFetches)
            cargo_path = $cargo
            process_identity = ConvertTo-D32D31ProcessIdentityDocument $producerIdentityRecord
            status = $seederBuild.status
            exit_code = $seederBuild.exit_code
            artifact = $seederArtifact
        }
        Assert-D32D31RecoverySeederRecordShape -Document $seederRecord -Path $seederRecordPath -OutputRoot $OutputRoot
        $seederRecordDigest = Write-D32NewRecoverySeederBuildRecord -Path $seederRecordPath -Document $seederRecord
        Write-Host "D31_RECOVERY_SEEDER_RECORD_PATH=$seederRecordPath"
        Write-Host "D31_RECOVERY_SEEDER_RECORD_SHA256=$($seederRecordDigest.sha256)"
        Write-Host "D31_RECOVERY_SEEDER_RUN_ID=$seederRunId"
        Write-Host "D31_RECOVERY_SEEDER_PATH=$($seederArtifact.path)"
        Write-Host "D31_RECOVERY_SEEDER_SHA256=$($seederArtifact.sha256)"
    }
}
finally {
    $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $validatedToolchainProfile
}

$globalProcessError = $null
try {
    [void](Test-D32NoOwnedCargoDescendants -PhaseEvidence @($phaseEvidence.ToArray()) -CheckName 'final fixture prebuild cleanup')
}
catch {
    $globalProcessError = $_.Exception.Message
}

$phaseTreeErrors = @($results | Where-Object { $_.status -eq 'process_tree_error' } | ForEach-Object { $_.error })
$allProcessErrors = @($phaseTreeErrors)
if ($null -ne $globalProcessError) { $allProcessErrors += $globalProcessError }
$manifestProcessError = if ($allProcessErrors.Count -eq 0) { $null } else { $allProcessErrors -join ' | ' }

if ($pendingFixtureFailures.Count -gt 0) {
    $payloadSelection = Get-D32FixtureFailurePayloadSelection -PendingFailures @($pendingFixtureFailures.ToArray()) `
        -GlobalCleanupError $(if ($null -ne $manifestProcessError) { "FIXTURE_GLOBAL_CLEANUP_BLOCKED: $manifestProcessError" } else { $null })
    try {
        Write-D32FixturePhase0FailurePayload `
            -Name $payloadSelection.Name `
            -Executable $cargo `
            -Arguments $payloadSelection.Arguments `
            -WorkingDirectory $RepoRoot `
            -ProcessResult $payloadSelection.ProcessResult `
            -PrimaryError $payloadSelection.PrimaryError `
            -SecondaryErrors $payloadSelection.SecondaryErrors `
            -PhaseLogPath $payloadSelection.PhaseLogPath
    }
    catch { Write-Output "D32_PHASE0_BLOCKED_DIAGNOSTIC_CAPTURE_ERROR:$($_.Exception.Message)" }
}

$candidateShaAfterBuild = Assert-D32PinnedCleanCandidate -Root $RepoRoot
if ($candidateShaAfterBuild -ne $candidateSha) {
    throw 'CANDIDATE_SHA_MISMATCH: candidate HEAD changed before the final manifest write'
}

$manifestDocument = [ordered]@{
    schema_version = $script:SchemaVersion
    candidate_sha  = $candidateSha
    source_repo = $RepoRoot
    generated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    started_at_utc = $startedAt.ToString('o')
    elapsed_ms = ([DateTimeOffset]::UtcNow - $startedAt).TotalMilliseconds
    working_tree_status = $gitStatus
    build_policy = [ordered]@{
        timeout_seconds = if ($BuildD31RecoverySeeder) { 600 } else { $Phase0FixtureBuildTimeoutSeconds }
        cargo_build_jobs = $BuildJobs
        nested_builds = $false
        process_tree_timeout_action = $script:D32FixtureProcessTreePolicy
    }
    environment = $fixtureManifestEnvironment
    process_tree_check = if ($null -eq $manifestProcessError) { 'succeeded' } else { 'failed' }
    process_tree_error = $manifestProcessError
    fixtures = @($results)
}
Write-D32Manifest -Path $ManifestPath -Document $manifestDocument
$candidateShaAfterManifest = Assert-D32PinnedCleanCandidate -Root $RepoRoot
if ($candidateShaAfterManifest -ne $candidateSha) {
    throw 'CANDIDATE_SHA_MISMATCH: candidate HEAD changed after the final manifest write'
}
$manifestArtifact = Get-D32BoundArtifactWithFileId -Path $ManifestPath
$processTraceRecords = @($phaseEvidence | ForEach-Object {
    [ordered]@{
        name = [string]$_.name
        executable = [string]$_.executable
        arguments = @($_.arguments)
        command_line = [string]$_.command_line
        working_directory = [string]$_.working_directory
        process_trace = $_.process_trace
    }
})
$fixtureBuildProvenance = [ordered]@{
    schema_version = 7
    record_type = 'D32_FIXTURE_BUILD_PROVENANCE_V7'
    candidate_sha = $candidateSha
    source_repo = $RepoRoot
    fixture_manifest_path = $ManifestPath
    fixture_manifest_sha256 = [string]$manifestArtifact.sha256
    fixture_manifest_bytes = [uint64]$manifestArtifact.bytes
    fixture_manifest_volume_serial_hex = [string]$manifestArtifact.volume_serial_hex
    fixture_manifest_file_id_hex = [string]$manifestArtifact.file_id_hex
    environment = $fixtureEnvironmentPlan
    storage = $script:D32Phase0StorageContext
    process_traces = $processTraceRecords
    fixture_build_budget = $Phase0FixtureBuildCapacity
    vendored_protoc_run_grant = $script:D32VendoredProtocRunGrant.Reference
    tauri_macros_source_patch = $script:D32TauriMacrosSourcePatchAuthority.Reference
    powershell_module_admission = $global:D32PowerShellModuleAuthorityState.Admission
}
$fixtureBuildProvenanceArtifact = $null
if (Test-D32FixtureBuildModeEmitsPhase0Provenance -Mode $fixtureBuildMode) {
    Assert-D32FixtureBuildProvenanceShape -Document $fixtureBuildProvenance
    $fixtureBuildProvenanceArtifact = Write-D32NewFixtureBuildProvenance -Path $fixtureProvenancePath -Document $fixtureBuildProvenance
    $candidateShaAfterProvenance = Assert-D32PinnedCleanCandidate -Root $RepoRoot
    if ($candidateShaAfterProvenance -ne $candidateSha) {
        throw 'CANDIDATE_SHA_MISMATCH: candidate HEAD changed after the fixture provenance sidecar write'
    }
}

$failures = @($results | Where-Object { $_.status -ne 'succeeded' })
$failures += @([pscustomobject]@{ name = 'global-process-tree'; status = 'failed' } | Where-Object { $null -ne $globalProcessError })
Write-Host "D32_FIXTURE_PREBUILD_MANIFEST=$ManifestPath"
if ($null -ne $fixtureBuildProvenanceArtifact) {
    Write-Host "D32_FIXTURE_BUILD_PROVENANCE_PATH=$fixtureProvenancePath"
    Write-Host "D32_FIXTURE_BUILD_PROVENANCE_SHA256=$($fixtureBuildProvenanceArtifact.sha256)"
}
else {
    Write-Host 'D32_FIXTURE_BUILD_PROVENANCE=NOT_EMITTED_NON_PHASE0'
}
if ($failures.Count -gt 0) {
    $summary = ($failures | ForEach-Object { "$($_.name)=$($_.status)" }) -join ', '
    throw "FIXTURE_PREBUILD_BLOCKED: $summary; see manifest and phase logs: $ManifestPath"
}
Write-Host "D32_FIXTURE_PREBUILD PASS: $($results.Count) fixtures candidate=$candidateSha"
