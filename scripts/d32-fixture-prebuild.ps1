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
    [switch]$BuildD31RecoverySeeder,
    [ValidateRange(1, 3600)]
    [int]$TimeoutSeconds = 600,
    [ValidateRange(1, 16)]
    [int]$BuildJobs = 1,
    [switch]$D32LauncherLibraryOnly,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:OwnerMarkerName = '.d32-fixture-prebuild-owned'
$script:OwnerMarker = 'D32_FIXTURE_PREBUILD_OWNER_V1'
$script:SchemaVersion = 3
$script:D32FixtureProcessTreePolicy = 'native Job Object kill-on-close, then verify every captured identity and relevant descendant'
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $script:ScriptRoot 'd32-build-toolchain-profile.ps1')

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
    $artifact = Get-D32BoundArtifact $full
    $expected = $ExpectedSha256.ToLowerInvariant()
    if ($artifact.sha256 -ne $expected) {
        throw 'GIT_PIN_INVALID: pinned Git executable did not match its independent SHA-256'
    }
    return [ordered]@{
        path = $full
        sha256 = $expected
        file_identity = $artifact.file_identity
    }
}

function Assert-D32PinnedGitCurrent {
    if ($null -eq $script:PinnedGit) {
        throw 'GIT_PIN_REQUIRED: operational Git calls require the caller-supplied path and SHA-256 pins'
    }
    $artifact = Get-D32BoundArtifact $script:PinnedGit.path
    if ($artifact.sha256 -ne $script:PinnedGit.sha256 -or
        -not (Test-D32SameArtifactFileIdentity -Left $artifact.file_identity -Right $script:PinnedGit.file_identity)) {
        throw 'GIT_PIN_CHANGED: pinned Git executable identity or SHA-256 changed'
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
        $snapshot = Get-D32BoundArtifact $script:PinnedGit.path
        if ($snapshot.sha256 -cne $script:PinnedGit.sha256 -or
            -not (Test-D32SameArtifactFileIdentity -Left $identityRecord -Right $script:PinnedGit.file_identity) -or
            -not (Test-D32SameArtifactFileIdentity -Left $snapshot.file_identity -Right $identityRecord)) {
            throw 'GIT_PIN_CHANGED: pinned Git changed before the retained executable handle was acquired'
        }
        return $stream
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Assert-D32PinnedGitProcessIdentity {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process, [Parameter(Mandatory = $true)][string[]]$Arguments)

    $expectedPath = Get-D32FullPath $script:PinnedGit.path
    try {
        $modulePath = [string]$Process.MainModule.FileName
    }
    catch {
        throw "GIT_PROCESS_IDENTITY_UNAVAILABLE: cannot observe started Git process image: $($_.Exception.Message)"
    }
    if (-not [string]::Equals((Get-D32FullPath $modulePath), $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'GIT_PROCESS_IDENTITY_MISMATCH: started process image path does not match the caller-pinned Git executable'
    }
    $image = Get-D32BoundArtifact $modulePath
    if ($image.sha256 -cne $script:PinnedGit.sha256 -or
        -not (Test-D32SameArtifactFileIdentity -Left $image.file_identity -Right $script:PinnedGit.file_identity)) {
        throw 'GIT_PROCESS_IDENTITY_MISMATCH: started process image hash or native file identity differs from pinned Git'
    }
    $snapshot = @(Get-D32ProcessSnapshot -ProcessId $Process.Id)
    if ($snapshot.Count -ne 1 -or -not [bool]$snapshot[0].IdentityVerified -or
        -not [string]::Equals([string]$snapshot[0].Name, (Split-Path -Leaf $expectedPath), [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals((Get-D32FullPath ([string]$snapshot[0].ImagePath)), $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'GIT_PROCESS_IDENTITY_MISMATCH: started Git process name, PID, or observed image path is unverified'
    }
    $expectedCommand = ConvertTo-D32CommandLine (@($expectedPath) + $Arguments)
    if (-not [string]::Equals([string]$snapshot[0].CommandLine, $expectedCommand, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'GIT_PROCESS_IDENTITY_MISMATCH: started Git process argv differs from the requested pinned command'
    }
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

function Get-D32GitOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [AllowNull()][object]$MetadataLocks,
        [switch]$PreserveOutput
    )

    Assert-D32PinnedGitCurrent
    $rootFull = Assert-D32NoReparsePath -Path $Root
    $gitDirectory = Assert-D32RepositoryGitConfig -Root $rootFull
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
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $script:PinnedGit.path
    $startInfo.Arguments = ConvertTo-D32CommandLine (@(
        '-c', 'core.fsmonitor=false',
        '-c', ('core.worktree=' + $rootFull),
        '-c', 'core.bare=false',
        '-c', ('core.attributesFile=' + $emptyConfig),
        '-c', ('core.hooksPath=' + $emptyHooks),
        '-c', ('safe.directory=' + $rootFull),
        '-C', $rootFull
    ) + $Arguments)
    $startInfo.WorkingDirectory = $rootFull
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    Clear-D32ChildEnvironment -StartInfo $startInfo
    $childEnvironment = $startInfo.EnvironmentVariables
    $childEnvironment['PATH'] = $searchDirectories -join [IO.Path]::PathSeparator
    $childEnvironment['SystemRoot'] = $systemRoot
    $childEnvironment['WINDIR'] = $systemRoot
    $childEnvironment['TEMP'] = $environmentRoot
    $childEnvironment['TMP'] = $environmentRoot
    $childEnvironment['HOME'] = $environmentRoot
    $childEnvironment['USERPROFILE'] = $environmentRoot
    $childEnvironment['XDG_CONFIG_HOME'] = $environmentRoot
    $childEnvironment['GIT_CONFIG_NOSYSTEM'] = '1'
    $childEnvironment['GIT_CONFIG_SYSTEM'] = $emptyConfig
    $childEnvironment['GIT_CONFIG_GLOBAL'] = $emptyConfig
    $childEnvironment['GIT_DIR'] = $gitDirectory
    $childEnvironment['GIT_WORK_TREE'] = $rootFull
    $childEnvironment['GIT_INDEX_FILE'] = Join-Path $gitDirectory 'index'
    $childEnvironment['GIT_OPTIONAL_LOCKS'] = '0'
    $childEnvironment['GIT_TERMINAL_PROMPT'] = '0'
    $childEnvironment['GIT_PAGER'] = 'cat'
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $pinnedGitHandle = $null
    $ownsMetadataLocks = $false
    $exitCode = $null
    $stdout = ''
    $stderr = ''
    try {
        if ($null -eq $MetadataLocks) {
            $MetadataLocks = Open-D32GitMetadataLocks -Root $rootFull -GitDirectory $gitDirectory
            $ownsMetadataLocks = $true
        }
        Assert-D32GitMetadataLocksCurrent -Locks $MetadataLocks -Root $rootFull
        $pinnedGitHandle = Open-D32PinnedGitHandle
        Assert-D32PinnedGitCurrent
        if (-not $process.Start()) { throw 'GIT_FAILED: pinned Git process did not start' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        try {
            Assert-D32PinnedGitProcessIdentity -Process $process -Arguments (@(
                    '-c', 'core.fsmonitor=false',
                    '-c', ('core.worktree=' + $rootFull),
                    '-c', 'core.bare=false',
                    '-c', ('core.attributesFile=' + $emptyConfig),
                    '-c', ('core.hooksPath=' + $emptyHooks),
                    '-c', ('safe.directory=' + $rootFull),
                    '-C', $rootFull
                ) + $Arguments)
        }
        catch {
            try {
                if (-not $process.HasExited) {
                    $process.Kill()
                    $process.WaitForExit()
                }
            }
            catch { }
            try { $null = $stdoutTask.GetAwaiter().GetResult() } catch { }
            try { $null = $stderrTask.GetAwaiter().GetResult() } catch { }
            throw
        }
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
        Assert-D32GitMetadataLocksCurrent -Locks $MetadataLocks -Root $rootFull
    }
    finally {
        $process.Dispose()
        if ($null -ne $pinnedGitHandle) { $pinnedGitHandle.Dispose() }
        if ($ownsMetadataLocks -and $null -ne $MetadataLocks) { Close-D32GitMetadataLocks -Locks $MetadataLocks }
        Remove-D32OwnedDirectory $environmentRoot
    }
    Assert-D32PinnedGitCurrent
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
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Environment)

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
    return ConvertTo-D32EnvironmentBlock -Environment $variables
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
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$PhaseEvidence
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
            -RequireDebugEvents
        if ($null -ne $result.root_identity_record) {
            Assert-D32PinnedCargoProcessIdentity `
                -ProcessIdentity $result.root_identity_record `
                -CargoPath $CargoPath `
                -Arguments $arguments `
                -ValidatedProfile $ValidatedProfile
        }
        $null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $ValidatedProfile
        $null = Assert-D32PinnedCleanCandidate -Root $RepoRoot
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
            throw "CARGO_FETCH_FAILED: manifest=$($lock.ManifestPath) status=$($result.status) exit=$($result.exit_code); see $($result.phase_log)"
        }
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WaitForDebugEvent(out DebugEvent debugEvent, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ContinueDebugEvent(uint processId, uint threadId, uint continueStatus);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr process, out DebugFileTime creation, out DebugFileTime exit, out DebugFileTime kernel, out DebugFileTime user);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(IntPtr file, out DebugFileInformation information);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(IntPtr file, int informationClass, IntPtr buffer, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(IntPtr file, StringBuilder path, uint size, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess, out IntPtr targetHandle, uint desiredAccess, bool inheritHandle, uint options);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentProcessId();

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
    private IntPtr _process;
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

    public int ProcessId { get; private set; }
    public bool JobAssigned { get; private set; }
    public int DebugContinueCallCount { get; private set; }
    public string LaunchMode { get { return (_debugEnabled ? "CreateProcessW(DEBUG_PROCESS|" : "CreateProcessW(") + "CREATE_SUSPENDED|EXTENDED_STARTUP_INFO)+HANDLE_LIST(stdout/stderr)+AssignProcessToJobObject(KILL_ON_JOB_CLOSE)+ResumeThread"; } }

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
        return StartInternal(filePath, commandLine, workingDirectory, environmentBlock, null, true);
    }

    private static D32FixtureNativeProcessV2 StartInternal(
        string filePath,
        string commandLine,
        string workingDirectory,
        string environmentBlock,
        string testFailure,
        bool debugEnabled)
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
        Exception failure = null;
        string cleanupErrors = null;
        D32FixtureNativeProcessV2 result = null;

        try
        {
            job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero) ThrowLastError("CreateJobObjectW failed");
            ConfigureKillOnClose(job);

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
            if (String.Equals(testFailure, "assign", StringComparison.Ordinal)) {
                bool assignedWithInvalidJob = AssignProcessToJobObject(IntPtr.Zero, pi.Process);
                int assignError = assignedWithInvalidJob ? 0 : Marshal.GetLastWin32Error();
                if (assignedWithInvalidJob)
                    throw new InvalidOperationException("SELFTEST_INJECTED_ASSIGN_API_UNEXPECTED_SUCCESS");
                throw new Win32Exception(assignError, "SELFTEST_INJECTED_ASSIGN_API_FAILURE (win32=" + assignError.ToString() + ")");
            }

            uint resumeResult = ResumeThread(pi.Thread);
            if (resumeResult == UInt32.MaxValue)
                ThrowLastError("ResumeThread failed");

            result = new D32FixtureNativeProcessV2(
                job,
                pi.Process,
                pi.Thread,
                stdoutRead,
                stderrRead,
                pi.ProcessId,
                debugEnabled);
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
        get { return WaitForSingleObject(_process, 0) == WaitObject0; }
    }

    public bool WaitForExit(int timeoutMilliseconds)
    {
        if (timeoutMilliseconds < 0) timeoutMilliseconds = 0;
        return WaitForSingleObject(_process, (uint)timeoutMilliseconds) == WaitObject0;
    }

    public int ExitCode
    {
        get
        {
            uint code;
            if (!GetExitCodeProcess(_process, out code)) ThrowLastError("GetExitCodeProcess failed");
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
        if (name == "vctip.exe") return "MSVC VCTIP telemetry helper is explicitly denied";
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

    private static void TraceCloseHandle(IntPtr handle, D32DebugProcessTraceV2 trace, string label)
    {
        if (handle != IntPtr.Zero && handle != new IntPtr(-1) && !CloseHandle(handle))
        {
            trace.DebugApiErrorCount++;
            TraceBlock(trace, "CloseHandle(" + label + ") failed: " + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
        }
    }

    public D32DebugProcessTraceV2 MonitorDebugEvents(string expectedRootPin, string[] approvedImagePins, string[] candidateImageRoots, int timeoutMilliseconds, bool injectFirstCreateInterruption, bool injectFirstCreateIdentityMismatch)
    {
        if (!_debugEnabled) throw new InvalidOperationException("synchronous DEBUG_PROCESS capture is mandatory for this monitor");
        if (String.IsNullOrWhiteSpace(expectedRootPin) || approvedImagePins == null || candidateImageRoots == null || timeoutMilliseconds <= 0)
            throw new ArgumentException("expected root pin, image inventories, and a positive deadline are mandatory");
        string[] expectedRoot = ParseDebugPin(expectedRootPin);
        string[][] pins = new string[approvedImagePins.Length][];
        for (int i = 0; i < approvedImagePins.Length; i++) pins[i] = ParseDebugPin(approvedImagePins[i]);
        string[] roots = new string[candidateImageRoots.Length];
        for (int i = 0; i < candidateImageRoots.Length; i++)
        {
            roots[i] = NormalizeDebugPath(candidateImageRoots[i]);
            if (!Path.IsPathRooted(roots[i])) throw new InvalidOperationException("candidate image root is not absolute");
        }
        DateTime start = DateTime.UtcNow;
        long debuggerCreation = GetDebugProcessCreationTime(GetCurrentProcess());
        D32DebugProcessTraceV2 trace = new D32DebugProcessTraceV2 {
            RecordType = "D32_DEBUG_JOB_PROCESS_TRACE_V2", SchemaVersion = 2, EventSource = "Win32-WaitForDebugEvent-synchronous",
            State = "RUNNING", StartedAtUtc = start.ToString("o", CultureInfo.InvariantCulture), DebuggerProcessId = (int)GetCurrentProcessId(),
            DebuggerCreationFileTime = debuggerCreation, DebuggerCreatedAtUtc = DebugFileTimeUtc(debuggerCreation),
            EventChainComplete = true, InjectedInterruption = injectFirstCreateInterruption,
            ProcessEvents = new List<D32DebugProcessEventV2>(), Processes = new List<D32DebugProcessRecordV2>()
        };
        Dictionary<uint, DebugActiveProcess> active = new Dictionary<uint, DebugActiveProcess>();
        HashSet<string> identities = new HashSet<string>(StringComparer.Ordinal);
        HashSet<uint> startupBreakpoints = new HashSet<uint>();
        DateTime deadline = start.AddMilliseconds(timeoutMilliseconds);
        DateTime cleanupDeadline = DateTime.MaxValue;
        bool draining = false;
        long sequence = 0;

        while (true)
        {
            if (trace.State == "BLOCKED" && !draining)
            {
                if (!TerminateJobObject(_job, 0xD3201001)) trace.DebugApiErrorCount++;
                draining = true;
                cleanupDeadline = DateTime.UtcNow.AddSeconds(15);
            }
            if (!draining && DateTime.UtcNow >= deadline)
            {
                TraceBlock(trace, "WaitForDebugEvent deadline exceeded; the owned Job was terminated");
                if (!TerminateJobObject(_job, 0xD3201002)) trace.DebugApiErrorCount++;
                draining = true;
                cleanupDeadline = DateTime.UtcNow.AddSeconds(15);
            }
            if (draining && DateTime.UtcNow >= cleanupDeadline)
            {
                trace.EventChainComplete = false;
                TraceBlock(trace, "debug event chain did not close after Job termination");
                break;
            }
            if (trace.ProcessCreateEventCount > 0 && active.Count == 0 && trace.ProcessCreateEventCount == trace.ProcessExitEventCount && WaitForSingleObject(_process, 0) == WaitObject0)
                break;

            DebugEvent ev;
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
            IntPtr processHandleAfterExit = IntPtr.Zero;
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
                    DebugActiveProcess parent;
                    DebugActiveProcess retained = null;
                    try
                    {
                        DebugCreateProcessInfo created = ev.Data.CreateProcess;
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
                            skipContinueForCreateIdentityFailure = false;
                            creation = GetDebugProcessCreationTime(created.Process);
                            parentPid = GetDebugParentPid(processBasicInformation);
                            image = ReadDebugImage(created.File);
                            string identity = ev.ProcessId.ToString(CultureInfo.InvariantCulture) + "@" + creation.ToString(CultureInfo.InvariantCulture);
                            if (creation <= 0 || !identities.Add(identity)) throw new InvalidOperationException("process PID/creation identity is absent or duplicated");
                            if (active.ContainsKey(ev.ProcessId)) throw new InvalidOperationException("PID reused before the prior process identity exited");
                            if (trace.ProcessCreateEventCount == 1)
                            {
                                if (parentPid != (uint)trace.DebuggerProcessId) throw new InvalidOperationException("fixed root parent PID differs from the current runner");
                                parentCreation = debuggerCreation;
                                string rootDeny = GetHardDeniedImageReason(image.Path);
                                if (rootDeny != null) throw new InvalidOperationException(rootDeny + ": " + image.Path);
                                if (!DebugImageMatches(image, expectedRoot)) throw new InvalidOperationException("fixed root image differs from its caller-pinned path/bytes/SHA/file ID");
                                reason = "exact-caller-pinned-fixed-root-image";
                                verified = true;
                            }
                            else
                            {
                                if (!active.TryGetValue(parentPid, out parent) || parent.Record.CreationFileTime <= 0)
                                    throw new InvalidOperationException("child parent PID lacks a unique active retained identity");
                                parentCreation = parent.Record.CreationFileTime;
                                string denied = GetHardDeniedImageReason(image.Path);
                                if (denied != null) throw new InvalidOperationException(denied + ": " + image.Path);
                                foreach (string[] pin in pins)
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
                                verified = true;
                            }
                        }
                        finally
                        {
                            TraceCloseHandle(created.File, trace, "CREATE_PROCESS_DEBUG_EVENT.hFile");
                            TraceCloseHandle(created.Thread, trace, "CREATE_PROCESS_DEBUG_EVENT.hThread");
                        }
                        IntPtr retainedHandle;
                        if (!DuplicateHandle(GetCurrentProcess(), ev.Data.CreateProcess.Process, GetCurrentProcess(), out retainedHandle, 0, false, DuplicateSameAccess))
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "DuplicateHandle(retain process identity) failed");
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
                    }
                    catch (Exception error)
                    {
                        trace.DebugApiErrorCount++;
                        TraceBlock(trace, "CREATE_PROCESS_DEBUG_EVENT verification failed: " + error.Message);
                        if (creation > 0 && !active.ContainsKey(ev.ProcessId))
                        {
                            IntPtr retainedHandle;
                            if (ev.Data.CreateProcess.Process != IntPtr.Zero && DuplicateHandle(GetCurrentProcess(), ev.Data.CreateProcess.Process, GetCurrentProcess(), out retainedHandle, 0, false, DuplicateSameAccess))
                            {
                                D32DebugProcessRecordV2 record = new D32DebugProcessRecordV2 {
                                    ProcessId = ev.ProcessId, ParentProcessId = parentPid, CreationFileTime = creation, ParentCreationFileTime = parentCreation,
                                    ImagePath = image == null ? null : image.Path, Bytes = image == null ? 0 : image.Bytes,
                                    Sha256 = image == null ? null : image.Sha256, VolumeSerialHex = image == null ? null : image.VolumeSerialHex,
                                    FileIdHex = image == null ? null : image.FileIdHex, AllowedImageReason = null, ImageVerified = false,
                                    Exited = false, CreateSequence = createSequence, CreatedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture)
                                };
                                retained = new DebugActiveProcess { Record = record, Handle = retainedHandle };
                                active.Add(ev.ProcessId, retained);
                                trace.Processes.Add(record);
                                trace.ProcessEvents.Add(new D32DebugProcessEventV2 { Sequence = createSequence, Kind = "CREATE", ProcessId = ev.ProcessId,
                                    ParentProcessId = parentPid, CreationFileTime = creation, ParentCreationFileTime = parentCreation, ExitCode = 0 });
                            }
                        }
                    }
                    finally { TraceCloseHandle(ev.Data.CreateProcess.Process, trace, "CREATE_PROCESS_DEBUG_EVENT.hProcess"); }
                    if (injectFirstCreateInterruption && trace.ProcessCreateEventCount == 1)
                    {
                        TraceBlock(trace, "debug chain interruption injected before ContinueDebugEvent; Job termination was requested");
                        if (!TerminateJobObject(_job, 0xD3201004)) trace.DebugApiErrorCount++;
                    }
                }
                else if (ev.Code == DebugEventExitProcess)
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
                        processHandleAfterExit = process.Handle;
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
                    TraceCloseHandle(ev.Data.CreateThread.Thread, trace, "CREATE_THREAD_DEBUG_EVENT.hThread");
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

            if (trace.State == "BLOCKED" && !draining)
            {
                if (!TerminateJobObject(_job, 0xD3201007)) trace.DebugApiErrorCount++;
                draining = true;
                cleanupDeadline = DateTime.UtcNow.AddSeconds(15);
            }
            if (skipContinueForCreateIdentityFailure)
            {
                trace.EventChainComplete = false;
                TraceBlock(trace, "CREATE_PROCESS_DEBUG_EVENT identity mismatch; the Job was terminated and ContinueDebugEvent was not called");
                break;
            }
            DebugContinueCallCount++;
            if (!ContinueDebugEvent(ev.ProcessId, ev.ThreadId, continueStatus))
            {
                trace.DebugApiErrorCount++;
                trace.EventChainComplete = false;
                TraceBlock(trace, "ContinueDebugEvent failed; no polling fallback is permitted: " + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                if (!TerminateJobObject(_job, 0xD3201008)) trace.DebugApiErrorCount++;
                if (processHandleAfterExit != IntPtr.Zero) TraceCloseHandle(processHandleAfterExit, trace, "retained exited process");
                break;
            }
            if (processHandleAfterExit != IntPtr.Zero)
            {
                if (WaitForSingleObject(processHandleAfterExit, 5000) != WaitObject0)
                {
                    trace.DebugApiErrorCount++;
                    TraceBlock(trace, "process handle did not signal after EXIT_PROCESS_DEBUG_EVENT");
                }
                TraceCloseHandle(processHandleAfterExit, trace, "retained exited process");
            }
        }

        foreach (KeyValuePair<uint, DebugActiveProcess> remaining in active) TraceCloseHandle(remaining.Value.Handle, trace, "retained process identity");
        active.Clear();
        JobObjectBasicAccountingInformation accounting;
        if (TryGetDebugJobAccounting(_job, out accounting))
        {
            trace.JobAccountingVerified = true;
            trace.JobTotalProcesses = accounting.TotalProcesses;
            trace.JobActiveProcesses = accounting.ActiveProcesses;
            DateTime settleDeadline = DateTime.UtcNow.AddSeconds(5);
            while (trace.JobActiveProcesses != 0 && DateTime.UtcNow < settleDeadline && TryGetDebugJobAccounting(_job, out accounting))
            {
                Thread.Sleep(20);
                trace.JobTotalProcesses = accounting.TotalProcesses;
                trace.JobActiveProcesses = accounting.ActiveProcesses;
            }
        }
        else
        {
            trace.DebugApiErrorCount++;
            trace.JobAccountingVerified = false;
            TraceBlock(trace, "independent QueryInformationJobObject accounting was unavailable");
        }
        trace.AccountingConsistent = trace.JobAccountingVerified && trace.EventChainComplete && trace.DebugApiErrorCount == 0 &&
            trace.ProcessCreateEventCount == trace.ProcessExitEventCount && trace.ProcessCreateEventCount == trace.Processes.Count &&
            trace.ProcessEvents.Count == trace.ProcessCreateEventCount + trace.ProcessExitEventCount &&
            trace.ProcessCreateEventCount == trace.JobTotalProcesses && trace.JobActiveProcesses == 0;
        if (!trace.AccountingConsistent) TraceBlock(trace, "process CREATE/EXIT ledger does not reconcile with retained identities and independent Job counts");
        if (trace.State == "RUNNING") trace.State = "COMPLETED";
        trace.CompletedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
        return trace;
    }

    public D32NativeCleanupEvidenceV2 CloseJobAndWait(int timeoutMilliseconds)
    {
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

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        string closeErrors = null;
        if (_job != IntPtr.Zero)
        {
            string closeError = CloseIfOpen(ref _job, "CloseHandle(job)");
            if (closeError != null) closeErrors = closeError;
        }
        if (_stdoutStream != null) _stdoutStream.Dispose();
        if (_stderrStream != null) _stderrStream.Dispose();
        if (_stdoutHandle != null) _stdoutHandle.Dispose();
        if (_stderrHandle != null) _stderrHandle.Dispose();
        string threadError = CloseIfOpen(ref _thread, "CloseHandle(process thread)");
        if (threadError != null) closeErrors = String.IsNullOrEmpty(closeErrors) ? threadError : closeErrors + "; " + threadError;
        string processError = CloseIfOpen(ref _process, "CloseHandle(process)");
        if (processError != null) closeErrors = String.IsNullOrEmpty(closeErrors) ? processError : closeErrors + "; " + processError;
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
        [Parameter(Mandatory = $true)][object]$ProcessIdentity,
        [Parameter(Mandatory = $true)][string]$CargoPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile
    )

    if ($null -eq $ProcessIdentity -or -not [bool]$ProcessIdentity.IdentityVerified -or [int]$ProcessIdentity.ProcessId -le 0) {
        throw 'CARGO_PROCESS_IDENTITY_MISMATCH: Cargo process identity was not verified'
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
        [Parameter(Mandatory = $true)][object[]]$Snapshot,
        [Parameter(Mandatory = $true)][int]$RootPid
    )

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
        [Parameter(Mandatory = $true)][object[]]$PhaseEvidence,
        [Parameter(Mandatory = $true)][string]$CheckName
    )

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

function Invoke-D32BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$PhaseLog,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [AllowNull()][System.Collections.IDictionary]$ChildEnvironment,
        [ValidateSet('none', 'spawn-init', 'cim-init', 'pipe-init', 'api-failure', 'attribute-failure', 'pipe-timeout')]
        [string]$FailureInjection = 'none',
        [switch]$RequireDebugEvents,
        [string[]]$CandidateImageRoots
    )

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
    $killOutput = [System.Collections.Generic.List[string]]::new()
    $script:D32LastProcessEvidence = [ordered]@{
        root_record = $null
        descendant_records = @()
        process_trace = $null
        native_launch = $null
        native_cleanup = $null
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
            $nativeProcess = [D32FixtureNativeProcessV2]::StartDebug(
                (Get-D32FullPath $FilePath), $commandLine, (Get-D32FullPath $WorkingDirectory), $environmentBlock)
        }
        else {
            $nativeProcess = [D32FixtureNativeProcessV2]::Start(
                (Get-D32FullPath $FilePath), $commandLine, (Get-D32FullPath $WorkingDirectory), $environmentBlock, $nativeTestFailure)
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
                $targetRoots = if ($CandidateImageRoots) { @($CandidateImageRoots | ForEach-Object { [IO.Path]::GetFullPath($_) }) } else { @(Get-D32DebugCandidateTargetRoots -Repository $profileCurrent.Repository) }
                $traceNative = $nativeProcess.MonitorDebugEvents(
                    (ConvertTo-D32DebugImagePinText -Image $rootImage), [string[]]$approvedPinText, [string[]]$targetRoots,
                    [int][Math]::Min([int]::MaxValue, ([long]$TimeoutSeconds * 1000)), $false, $false)
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
                    $killOutput.AddRange([string[]]@($reap.KillOutput))
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
    $capturedDescendantPids = @($capturedDescendantRecords | ForEach-Object { [int]$_.ProcessId } | Select-Object -Unique)
    $residualDescendantPids = @($residualDescendantRecords | ForEach-Object { [int]$_.ProcessId } | Select-Object -Unique)
    if ($timedOut) {
        [IO.File]::AppendAllText(
            $stderrPath,
            "`nD32_FIXTURE_PHASE=timeout`nCAPTURED_DESCENDANT_PIDS=$($capturedDescendantPids -join ',')`n$($killOutput -join "`n")`n",
            [Text.UTF8Encoding]::new($false))
    }
    $finished = [DateTimeOffset]::UtcNow
    [IO.File]::AppendAllText(
        $stdoutPath,
        "`nD32_FIXTURE_EXIT_CODE=$exitCode`nD32_FIXTURE_DESCENDANTS=$($capturedDescendantPids -join ',')`n",
        [Text.UTF8Encoding]::new($false))
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
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Environment)

    $required = @('original_userprofile', 'codex_home', 'userprofile', 'cargo_home', 'rustup_home', 'rustup_toolchain')
    $actual = @($Environment.Keys | ForEach-Object { [string]$_ })
    if ($actual.Count -ne $required.Count -or
        @($actual | Where-Object { $_ -notin $required }).Count -ne 0 -or
        @($required | Where-Object { $_ -notin $actual }).Count -ne 0) {
        throw 'FIXTURE_MANIFEST_ENVIRONMENT_INVALID: schema-v3 environment must retain exactly the six consumer wire fields'
    }
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
    param([Parameter(Mandatory = $true)][object[]]$Traces)

    $expectedNames = @('fixture-01-fetch', 'fixture-02-fetch', 'fixture-03-fetch',
        'd29h1-authority-fixture', 'd29h7-authority-fixture', 'd29h7-process-fixture', 'd29h7-git-helper-fixture', 'd32a-sandbox-fixture')
    if ($Traces -isnot [Array] -or $Traces.Count -ne $expectedNames.Count) { throw 'FIXTURE_PROVENANCE_INVALID: process trace inventory must contain exactly three locked fetches and five fixture Cargo roots' }
    $traceFields = @('record_type', 'schema_version', 'event_source', 'state', 'block_reason', 'debugger_process_id', 'debugger_creation_filetime',
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
            $trace.event_source -cne 'Win32-WaitForDebugEvent-synchronous' -or $trace.state -cne 'COMPLETED' -or $null -ne $trace.block_reason -or
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
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Document)

    $expected = @('schema_version', 'record_type', 'candidate_sha', 'source_repo', 'fixture_manifest_path',
        'fixture_manifest_sha256', 'fixture_manifest_bytes', 'fixture_manifest_volume_serial_hex',
        'fixture_manifest_file_id_hex', 'environment', 'process_traces')
    $actual = @($Document.Keys | ForEach-Object { [string]$_ })
    if ($actual.Count -ne $expected.Count -or
        @($actual | Where-Object { $_ -notin $expected }).Count -ne 0 -or
        @($expected | Where-Object { $_ -notin $actual }).Count -ne 0 -or
        [int]$Document.schema_version -ne 2 -or $Document.record_type -cne 'D32_FIXTURE_BUILD_PROVENANCE_V2' -or
        [string]$Document.candidate_sha -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Document.fixture_manifest_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [uint64]$Document.fixture_manifest_bytes -le 0 -or
        [string]$Document.fixture_manifest_volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        [string]$Document.fixture_manifest_file_id_hex -cnotmatch '^[0-9a-f]{32}$') {
        throw 'FIXTURE_PROVENANCE_INVALID: sidecar schema, version, manifest hash, bytes, or identity is invalid'
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

function Invoke-D32SelfTest {
    Ensure-D32NativeLauncher
    $root = Join-Path ([IO.Path]::GetTempPath()) ('d32-fixture-prebuild-selftest-' + [Guid]::NewGuid().ToString('N'))
    $passed = 0
    $owned = $false
    try {
        [void](Ensure-D32OwnedDirectory $root)
        $owned = $true
        Write-Host 'D32_FIXTURE_TRUST_CONTRACT=pins:-PinnedGitPath,-PinnedGitSha256,-ExpectedCandidateSha,-ToolchainProfilePath,-ExpectedToolchainProfileSha256; d31-target:OutputRoot\d31-recovery-seeder-target; d31-record:sibling-d31-recovery-seeder-build.json; d31-env:D31_RECOVERY_SEEDER_RECORD_PATH,D31_RECOVERY_SEEDER_RECORD_SHA256,D31_RECOVERY_SEEDER_RUN_ID,D32_BUILD_TOOLCHAIN_PROFILE_PATH,D32_EXPECTED_TOOLCHAIN_PROFILE_SHA256; profile:D32_BUILD_TOOLCHAIN_PROFILE_V2'

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
        $debugRootArguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'exit 0')
        $debugRootCommandLine = ConvertTo-D32CommandLine (@($debugRootPath) + $debugRootArguments)
        $debugRootProcess = $null
        try {
            $debugRootProcess = [D32FixtureNativeProcessV2]::StartDebug($debugRootPath, $debugRootCommandLine, $root, $null)
            $debugIdentityTrace = $debugRootProcess.MonitorDebugEvents(
                (ConvertTo-D32DebugImagePinText -Image $debugRootImage), [string[]]@(), [string[]]@(), 10000, $false, $true)
            if ($debugIdentityTrace.State -cne 'BLOCKED' -or
                [bool]$debugIdentityTrace.EventChainComplete -or
                [int]$debugRootProcess.DebugContinueCallCount -ne 0 -or
                $debugIdentityTrace.BlockReason -notmatch 'CREATE_PROCESS_DEBUG_EVENT PID differs') {
                throw "SELFTEST_FAILED: injected root CREATE PID mismatch did not terminate and stop before ContinueDebugEvent: state=$($debugIdentityTrace.State); chain_complete=$($debugIdentityTrace.EventChainComplete); continue_calls=$($debugRootProcess.DebugContinueCallCount); reason=$($debugIdentityTrace.BlockReason)"
            }
        }
        finally {
            if ($null -ne $debugRootProcess) {
                $debugIdentityCleanup = $debugRootProcess.CloseJobAndWait(10000)
                if (-not [bool]$debugIdentityCleanup.JobCloseSucceeded -or
                    -not [bool]$debugIdentityCleanup.JobTerminateCallSucceeded -or
                    -not [bool]$debugIdentityCleanup.JobActiveProcessCountVerified -or
                    [uint32]$debugIdentityCleanup.JobActiveProcessCount -ne 0 -or
                    [uint32]$debugIdentityTrace.JobActiveProcesses -ne 0) {
                    throw "SELFTEST_FAILED: injected root CREATE PID mismatch did not close a zero-active Job: $($debugIdentityCleanup.Detail); process_signaled=$($debugIdentityCleanup.ProcessWaitSignaled); terminate_succeeded=$($debugIdentityCleanup.JobTerminateCallSucceeded); active_count=$($debugIdentityCleanup.JobActiveProcessCount); active_count_verified=$($debugIdentityCleanup.JobActiveProcessCountVerified); active_count_error=$($debugIdentityCleanup.JobActiveProcessCountLastError)"
                }
                Write-Host "D32_CREATE_ID_MISMATCH_NEGATIVE=PASS continue_calls=$($debugRootProcess.DebugContinueCallCount) job_total=$($debugIdentityTrace.JobTotalProcesses) job_active=$($debugIdentityCleanup.JobActiveProcessCount) root_process_signaled=$($debugIdentityCleanup.ProcessWaitSignaled)"
                $debugRootProcess.Dispose()
            }
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

        $powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
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

        $normalChildScript = Join-Path $root 'descendant-normal.ps1'
        [IO.File]::WriteAllText(
            $normalChildScript,
            "Start-Process -FilePath '$powershell' -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 5' -WindowStyle Hidden | Out-Null`nStart-Sleep -Milliseconds 750`nexit 0`n",
            [Text.UTF8Encoding]::new($false)
        )
        $normalWithChild = Invoke-D32BoundedProcess `
            -FilePath $powershell `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $normalChildScript) `
            -WorkingDirectory $root `
            -PhaseLog (Join-Path $root 'normal-descendant-phase') `
            -TimeoutSeconds 5
        if ($normalWithChild.status -ne 'succeeded' -or
            $normalWithChild.exit_code -ne 0 -or
            @($normalWithChild.descendant_identities).Count -lt 1 -or
            @($normalWithChild.descendant_pids).Count -ne 0 -or
            $null -eq $normalWithChild.native_cleanup -or
            -not [bool]$normalWithChild.native_cleanup.job_active_process_count_verified -or
            [uint32]$normalWithChild.native_cleanup.job_active_process_count -ne 0 -or
            $null -ne $normalWithChild.error) {
            throw 'SELFTEST_FAILED: normal exit with captured child was not cleanly reaped'
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
        $provenanceFetchArguments = @(
            'fetch', '--locked', '--manifest-path', $provenanceManifestPath,
            '--target', 'x86_64-pc-windows-msvc'
        )
        $provenanceEnvironment = [ordered]@{
            toolchain_profile_path = (Join-Path $root 'profile.json')
            toolchain_profile_sha256 = ('a' * 64)
            target_triple = 'x86_64-pc-windows-msvc'
            env_policy = 'D32_BUILD_ENV_V1'
            cargo_policy = 'FRESH_HOME_LOCKED_FETCH_OFFLINE_AFTER'
            cargo_home = (Join-Path $root 'run/cargo-home')
            temp_root = (Join-Path $root 'run/temp')
            run_id = '0123456789abcdef0123456789abcdef'
            fetch_manifests = @([ordered]@{
                    manifest_path = 'vita-agent/Cargo.toml'
                    lock_sha256 = ('f' * 64)
                    command = $provenanceFetchArguments
                    status = 'succeeded'
                    exit_code = 0
                    process_identity = [ordered]@{
                        process_id = 1234
                        parent_process_id = [int]$PID
                        name = 'cargo.exe'
                        image_path = $provenanceCargoPath
                        creation_date = '2026-09-23T00:00:00.0000000Z'
                        command_line = ConvertTo-D32CommandLine (@($provenanceCargoPath) + $provenanceFetchArguments)
                        observed_at_utc = '2026-09-23T00:00:01.0000000Z'
                        identity_verified = $true
                    }
                })
            offline_after_fetch = $true
        }
        $debuggerCreation = [DateTime]::UtcNow.ToFileTimeUtc()
        $debuggerCreated = [DateTime]::FromFileTimeUtc($debuggerCreation).ToString('o')
        $traceStarted = [DateTime]::UtcNow.ToString('o')
        $fakeProcessTrace = [ordered]@{
            record_type = 'D32_DEBUG_JOB_PROCESS_TRACE_V2'
            schema_version = 2
            event_source = 'Win32-WaitForDebugEvent-synchronous'
            state = 'COMPLETED'
            block_reason = $null
            debugger_process_id = [int]$PID
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
        foreach ($traceName in $traceNames) {
            $traceArguments = @($provenanceFetchArguments)
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
        $provenanceDocument = [ordered]@{
            schema_version = 2
            record_type = 'D32_FIXTURE_BUILD_PROVENANCE_V2'
            candidate_sha = '0123456789abcdef0123456789abcdef01234567'
            source_repo = $fakeRepo
            fixture_manifest_path = $sample
            fixture_manifest_sha256 = $boundManifestArtifact.sha256
            fixture_manifest_bytes = $boundManifestArtifact.bytes
            fixture_manifest_volume_serial_hex = $boundManifestArtifact.volume_serial_hex
            fixture_manifest_file_id_hex = $boundManifestArtifact.file_id_hex
            environment = $provenanceEnvironment
            process_traces = @($traceRecords.ToArray())
        }
        Assert-D32FixtureBuildProvenanceShape -Document $provenanceDocument
        $oldProvenance = [ordered]@{}
        foreach ($field in $provenanceDocument.Keys) { $oldProvenance[$field] = $provenanceDocument[$field] }
        $oldProvenance.schema_version = 1
        $oldProvenance.record_type = 'D32_FIXTURE_BUILD_PROVENANCE_V1'
        try {
            Assert-D32FixtureBuildProvenanceShape -Document $oldProvenance
            throw 'SELFTEST_FAILED: old fixture provenance v1 was accepted without process event evidence'
        }
        catch { if ($_.Exception.Message -notlike 'FIXTURE_PROVENANCE_INVALID:*') { throw } }
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
        $parsedProvenance = [IO.File]::ReadAllText($provenanceJsonPath, [Text.Encoding]::UTF8) | ConvertFrom-Json -AsHashtable
        Assert-D32FixtureBuildProvenanceShape -Document $parsedProvenance
        if ($parsedProvenance.environment.fetch_manifests[0].process_identity.command_line -cne
            $provenanceEnvironment.fetch_manifests[0].process_identity.command_line) {
            throw 'SELFTEST_FAILED: serialized sidecar fetch process identity did not round-trip as producer-shaped JSON'
        }
        $passed++

        $ambientHandle = [IntPtr]::Zero
        try {
            $ambientHandle = [D32FixtureNativeProcessV2]::CreateInheritableTestHandle()
            $ambientProbeScript = Join-Path $root 'ambient-handle-probe.ps1'
            $ambientProbeContent = @(
                'Add-Type -TypeDefinition ''using System; using System.Runtime.InteropServices; public static class D32AmbientHandleProbe { [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetHandleInformation(IntPtr handle, out uint flags); }'' -Language CSharp'
                '$flags = 0'
                ('if ([D32AmbientHandleProbe]::GetHandleInformation([IntPtr]{0}, [ref]$flags)) {{ exit 17 }} else {{ exit 0 }}' -f $ambientHandle.ToInt64())
            ) -join [Environment]::NewLine
            [IO.File]::WriteAllText($ambientProbeScript, $ambientProbeContent, [Text.UTF8Encoding]::new($false))
            $ambient = Invoke-D32BoundedProcess `
                -FilePath $powershell `
                -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $ambientProbeScript) `
                -WorkingDirectory $root `
                -PhaseLog (Join-Path $root 'ambient-handle-phase') `
                -TimeoutSeconds 5
            if ($ambient.status -ne 'succeeded' -or $ambient.exit_code -ne 0) {
                throw "SELFTEST_FAILED: ambient inheritable handle escaped explicit handle list (status=$($ambient.status), exit=$($ambient.exit_code), error=$($ambient.error))"
            }
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
        [IO.File]::WriteAllText(
            $childScript,
            "Start-Process -FilePath '$powershell' -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 5' -WindowStyle Hidden | Out-Null`nStart-Sleep -Seconds 5`n",
            [Text.UTF8Encoding]::new($false)
        )
        $bounded = Invoke-D32BoundedProcess `
            -FilePath $powershell `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $childScript) `
            -WorkingDirectory $root `
            -PhaseLog (Join-Path $root 'timeout-phase') `
            -TimeoutSeconds 1
        if ($bounded.status -ne 'timeout' -or $bounded.error -notlike '*captured identity*reaped*' -or @($bounded.descendant_identities).Count -lt 1 -or @($bounded.descendant_pids).Count -ne 0) {
            throw 'SELFTEST_FAILED: bounded timeout/tree reap'
        }
        $passed++

        Write-Host "D32_FIXTURE_PREBUILD_SELFTEST PASS ($passed checks)"
    }
    finally {
        if ($owned -and (Test-Path -LiteralPath $root)) {
            Remove-D32OwnedDirectory $root
        }
    }
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
    exit 0
}

if ($PSVersionTable.PSVersion -lt [version]'7.5') {
    throw 'TOOLCHAIN_PROFILE_BLOCKED: operational D32 builds require PowerShell 7.5 or later for the shared pinned-profile validator'
}
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
$cargo = [string]$validatedToolchainProfile.Profile.toolchain.cargo.path
$cargo = Assert-D32NoReparsePath -Path $cargo
$null = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $validatedToolchainProfile
$toolchainRunId = [Guid]::NewGuid().ToString('N').ToLowerInvariant()
$toolchainRunRoot = Ensure-D32OwnedDirectory (Join-Path $OutputRoot ("fixture-toolchain-run-$toolchainRunId"))
$fixtureCargoHome = New-D32FreshCargoHome -RunRoot $toolchainRunRoot -Repository $RepoRoot
$fixtureTempRoot = Join-Path $toolchainRunRoot 'temp'
[void][IO.Directory]::CreateDirectory($fixtureTempRoot)
$fixtureTempRoot = Assert-D32NoReparsePath -Path $fixtureTempRoot
$fixtureManifestEnvironment = Get-D32EnvironmentPlan -EnvironmentRoot (Join-Path $toolchainRunRoot 'manifest-environment')
Assert-D32FixtureManifestEnvironmentShape -Environment $fixtureManifestEnvironment
$phaseEvidence = [System.Collections.Generic.List[object]]::new()
$fixtureFetches = Invoke-D32LockedCargoFetches `
    -ValidatedProfile $validatedToolchainProfile `
    -CargoPath $cargo `
    -CargoHome $fixtureCargoHome `
    -TempRoot $fixtureTempRoot `
    -RepoRoot $RepoRoot `
    -LogRoot $logRoot `
    -TimeoutSeconds $TimeoutSeconds `
    -LogPrefix 'fixture' `
    -PhaseEvidence $phaseEvidence
$null = Test-D32CargoHome -Path $fixtureCargoHome -Repository $RepoRoot
$offlineFixtureEnvironment = Get-D32BuildToolchainEnvironment `
    -ValidatedProfile $validatedToolchainProfile `
    -CargoHome $fixtureCargoHome `
    -TempRoot $fixtureTempRoot `
    -Offline $true
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
$startedAt = [DateTimeOffset]::UtcNow
try {
    $phase = 0
    foreach ($spec in $script:FixtureSpecs) {
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
        Write-Host "D32_FIXTURE_PHASE=$phase name=$($spec.name) timeout_seconds=$TimeoutSeconds"
        try {
            $processResult = Invoke-D32BoundedProcess `
                -FilePath $cargo `
                -Arguments $arguments `
                -WorkingDirectory $RepoRoot `
                -PhaseLog $phaseLog `
                -TimeoutSeconds $TimeoutSeconds `
                -ChildEnvironment $offlineFixtureEnvironment `
                -RequireDebugEvents
            if ($null -ne $processResult.root_identity_record) {
                Assert-D32PinnedCargoProcessIdentity `
                    -ProcessIdentity $processResult.root_identity_record `
                    -CargoPath $cargo `
                    -Arguments $arguments `
                    -ValidatedProfile $validatedToolchainProfile
            }
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
            if ($_.Exception.Message -match '^(CANDIDATE_SHA_|WORKTREE_DIRTY:|GIT_PIN_|GIT_CONFIG_|GIT_REPOSITORY_|PATH_REPARSE:|TOOLCHAIN_PROFILE_|CARGO_FETCH_|CARGO_HOME_|CARGO_PROCESS_IDENTITY_)') {
                throw
            }
            $failureEvidence = $script:D32LastProcessEvidence
            $phaseEvidence.Add([pscustomobject]@{
                root_record = $failureEvidence.root_record
                descendant_records = @($failureEvidence.descendant_records)
            })
            $results += [ordered]@{
                phase          = $phase
                name           = $spec.name
                project        = $spec.project
                binary         = $spec.binary
                manifest_path  = $manifest
                features       = @($spec.features)
                command        = ('cargo ' + (ConvertTo-D32CommandLine $arguments))
                status         = 'phase_error'
                exit_code      = $null
                pid            = if ($null -eq $failureEvidence.root_record) { $null } else { [int]$failureEvidence.root_record.ProcessId }
                descendant_pids = @()
                root_identity  = ConvertTo-D32IdentityDocument $failureEvidence.root_record
                descendant_identities = @($failureEvidence.descendant_records | ForEach-Object { ConvertTo-D32IdentityDocument $_ })
                residual_descendant_identities = @()
                reap           = $null
                elapsed_ms     = $null
                phase_log      = (Get-D32FullPath $phaseLog)
                stdout_log     = (Get-D32FullPath "$phaseLog.stdout.log")
                stderr_log     = (Get-D32FullPath "$phaseLog.stderr.log")
                error          = $_.Exception.Message
                artifact       = $null
            }
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
                -ValidatedProfile $validatedToolchainProfile
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
        timeout_seconds = $TimeoutSeconds
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
    schema_version = 2
    record_type = 'D32_FIXTURE_BUILD_PROVENANCE_V2'
    candidate_sha = $candidateSha
    source_repo = $RepoRoot
    fixture_manifest_path = $ManifestPath
    fixture_manifest_sha256 = [string]$manifestArtifact.sha256
    fixture_manifest_bytes = [uint64]$manifestArtifact.bytes
    fixture_manifest_volume_serial_hex = [string]$manifestArtifact.volume_serial_hex
    fixture_manifest_file_id_hex = [string]$manifestArtifact.file_id_hex
    environment = $fixtureEnvironmentPlan
    process_traces = $processTraceRecords
}
Assert-D32FixtureBuildProvenanceShape -Document $fixtureBuildProvenance
$fixtureBuildProvenanceArtifact = Write-D32NewFixtureBuildProvenance -Path $fixtureProvenancePath -Document $fixtureBuildProvenance
$candidateShaAfterProvenance = Assert-D32PinnedCleanCandidate -Root $RepoRoot
if ($candidateShaAfterProvenance -ne $candidateSha) {
    throw 'CANDIDATE_SHA_MISMATCH: candidate HEAD changed after the fixture provenance sidecar write'
}

$failures = @($results | Where-Object { $_.status -ne 'succeeded' })
$failures += @([pscustomobject]@{ name = 'global-process-tree'; status = 'failed' } | Where-Object { $null -ne $globalProcessError })
Write-Host "D32_FIXTURE_PREBUILD_MANIFEST=$ManifestPath"
Write-Host "D32_FIXTURE_BUILD_PROVENANCE_PATH=$fixtureProvenancePath"
Write-Host "D32_FIXTURE_BUILD_PROVENANCE_SHA256=$($fixtureBuildProvenanceArtifact.sha256)"
if ($failures.Count -gt 0) {
    $summary = ($failures | ForEach-Object { "$($_.name)=$($_.status)" }) -join ', '
    throw "FIXTURE_PREBUILD_BLOCKED: $summary; see manifest and phase logs: $ManifestPath"
}
Write-Host "D32_FIXTURE_PREBUILD PASS: $($results.Count) fixtures candidate=$candidateSha"
