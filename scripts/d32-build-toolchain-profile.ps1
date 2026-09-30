# Shared, fail-closed verifier for the caller-pinned D32 build-toolchain profile.
# Dot-source from D32 PowerShell tooling; this file has no operational side effects.
$script:D32ProfileModuleFreeFences = $null

function Test-D32ProfileExactProperties {
    param([object]$Object, [string[]]$Expected)

    if ($null -eq $Object -or $Object -is [string] -or $Object -is [Array] -or $Object -is [ValueType]) {
        return $false
    }
    $actual = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($property in $Object.PSObject.Properties) { [void]$actual.Add([string]$property.Name) }
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) { if (-not $actual.Contains($name)) { return $false } }
    return $true
}

function ConvertFrom-D32ProfileJsonElement {
    param([Parameter(Mandatory = $true)][System.Text.Json.JsonElement]$Element)
    switch ($Element.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Object) {
            $properties = [ordered]@{}
            foreach ($property in $Element.EnumerateObject()) { $properties.Add($property.Name, (ConvertFrom-D32ProfileJsonElement -Element $property.Value)) }
            return [PSCustomObject]$properties
        }
        ([System.Text.Json.JsonValueKind]::Array) {
            $items = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $Element.EnumerateArray()) { $items.Add((ConvertFrom-D32ProfileJsonElement -Element $item)) }
            return ,$items.ToArray()
        }
        ([System.Text.Json.JsonValueKind]::String) { return $Element.GetString() }
        ([System.Text.Json.JsonValueKind]::Number) {
            $number = [Int64]0
            if (-not $Element.TryGetInt64([ref]$number)) { throw 'profile JSON numbers must be signed 64-bit integers' }
            return $number
        }
        ([System.Text.Json.JsonValueKind]::True) { return $true }
        ([System.Text.Json.JsonValueKind]::False) { return $false }
        ([System.Text.Json.JsonValueKind]::Null) { return $null }
        default { throw 'profile JSON contains an unsupported token' }
    }
}

function Test-D32ProfileJsonElementDuplicates {
    param([System.Text.Json.JsonElement]$Element)

    switch ($Element.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Object) {
            $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($property in $Element.EnumerateObject()) {
                if (-not $names.Add($property.Name)) { return $true }
                if (Test-D32ProfileJsonElementDuplicates -Element $property.Value) { return $true }
            }
        }
        ([System.Text.Json.JsonValueKind]::Array) {
            foreach ($item in $Element.EnumerateArray()) {
                if (Test-D32ProfileJsonElementDuplicates -Element $item) { return $true }
            }
        }
    }
    return $false
}

function Test-D32ProfileWindows {
    return [System.OperatingSystem]::IsWindows()
}

function Get-D32ProfileFullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        throw "profile path is not absolute: $Path"
    }
    return [System.IO.Path]::GetFullPath($Path)
}

function Test-D32ProfilePathEqual {
    param([string]$Left, [string]$Right)

    try {
        $leftFull = [System.IO.Path]::GetFullPath($Left).TrimEnd('\', '/')
        $rightFull = [System.IO.Path]::GetFullPath($Right).TrimEnd('\', '/')
        return $leftFull.Equals($rightFull, [StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

function Test-D32ProfileCanonicalPathString {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        if (-not [IO.Path]::IsPathRooted($Path)) { return $false }
        $full = [IO.Path]::GetFullPath($Path)
        $root = [IO.Path]::GetPathRoot($full)
        $canonical = if ($full.Length -gt $root.Length) { $full.TrimEnd('\', '/') } else { $root }
        return $Path.Equals($canonical, [StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

function Test-D32ProfilePathWithin {
    param([string]$Child, [string]$Parent)

    try {
        $childFull = [System.IO.Path]::GetFullPath($Child).TrimEnd('\', '/')
        $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\', '/')
        if ($childFull.Equals($parentFull, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        return $childFull.StartsWith($parentFull + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

function Test-D32ProfileNoReparsePath {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$AllowMissingLeaf)

    try {
        $full = Get-D32ProfileFullPath -Path $Path
        $root = [System.IO.Path]::GetPathRoot($full)
        if ([String]::IsNullOrWhiteSpace($root)) { return $false }
        $current = $root
        $remainder = $full.Substring($root.Length)
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($part in ($remainder -split '[\\/]+')) { if (-not [String]::IsNullOrWhiteSpace($part)) { $parts.Add($part) } }
        for ($index = 0; $index -lt $parts.Count; $index++) {
            $current = [IO.Path]::Combine($current, $parts[$index])
            try {
                $attributes = [System.IO.File]::GetAttributes($current)
            }
            catch [System.IO.FileNotFoundException] {
                return [bool]($AllowMissingLeaf -and $index -eq ($parts.Count - 1))
            }
            catch [System.IO.DirectoryNotFoundException] {
                return [bool]($AllowMissingLeaf -and $index -eq ($parts.Count - 1))
            }
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
            if ($index -lt ($parts.Count - 1) -and ($attributes -band [System.IO.FileAttributes]::Directory) -eq 0) { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Initialize-D32ProfileFileIdentityType {
    if ('D32BuildProfileFileIdentityV1' -as [type]) { return }
    $savedLib = [Environment]::GetEnvironmentVariable('LIB', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('LIB', $null, 'Process')
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

public sealed class D32BuildProfileFileRecordV1
{
    public string FullName { get; set; }
    public long Bytes { get; set; }
    public string Sha256 { get; set; }
    public string VolumeSerialHex { get; set; }
    public string FileIdHex { get; set; }
    public int Attributes { get; set; }
    public long CreationTimeUtcTicks { get; set; }
    public long LastWriteTimeUtcTicks { get; set; }
}

public sealed class D32BuildProfileDirectoryRecordV1
{
    public string FullName { get; set; }
    public string VolumeSerialHex { get; set; }
    public string FileIdHex { get; set; }
    public int Attributes { get; set; }
}

public static class D32BuildProfileFileIdentityV1
{
    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME { public uint Low; public uint High; }

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
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, IntPtr info, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateFileW", SetLastError = true)]
    private static extern SafeFileHandle CreateFileForDirectory(string path, uint access, uint share, IntPtr securityAttributes, uint creationDisposition, uint flags, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateDirectoryW", SetLastError = true)]
    private static extern bool CreateDirectoryExclusive(string path, IntPtr securityAttributes);

    private static long Ticks(FILETIME value)
    {
        long raw = unchecked((long)(((ulong)value.High << 32) | value.Low));
        return DateTime.FromFileTimeUtc(raw).Ticks;
    }

    private sealed class NativeRecord
    {
        public long Bytes;
        public int Attributes;
        public long CreationTicks;
        public long WriteTicks;
        public string Volume;
        public string FileId;
    }

    private static NativeRecord ReadNative(SafeFileHandle handle)
    {
        BY_HANDLE_FILE_INFORMATION basic;
        if (!GetFileInformationByHandle(handle, out basic)) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr buffer = Marshal.AllocHGlobal(24);
        try
        {
            // FILE_INFO_BY_HANDLE_CLASS.FileIdInfo = 18; FILE_ID_INFO is 24 bytes.
            if (!GetFileInformationByHandleEx(handle, 18, buffer, 24)) throw new Win32Exception(Marshal.GetLastWin32Error());
            byte[] fileId = new byte[16];
            Marshal.Copy(IntPtr.Add(buffer, 8), fileId, 0, fileId.Length);
            ulong size = ((ulong)basic.FileSizeHigh << 32) | basic.FileSizeLow;
            if (size > Int64.MaxValue) throw new IOException("file size exceeds supported identity range");
            return new NativeRecord {
                Bytes = (long)size,
                Attributes = unchecked((int)basic.FileAttributes),
                CreationTicks = Ticks(basic.CreationTime),
                WriteTicks = Ticks(basic.LastWriteTime),
                Volume = unchecked((ulong)Marshal.ReadInt64(buffer, 0)).ToString("x16", CultureInfo.InvariantCulture),
                FileId = BitConverter.ToString(fileId).Replace("-", "").ToLowerInvariant()
            };
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static bool Same(NativeRecord left, NativeRecord right)
    {
        return left.Bytes == right.Bytes && left.Attributes == right.Attributes &&
            left.CreationTicks == right.CreationTicks && left.WriteTicks == right.WriteTicks &&
            String.Equals(left.Volume, right.Volume, StringComparison.Ordinal) &&
            String.Equals(left.FileId, right.FileId, StringComparison.Ordinal);
    }

    public static D32BuildProfileFileRecordV1 Read(string path)
    {
        string full = Path.GetFullPath(path);
        using (FileStream stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            NativeRecord before = ReadNative(stream.SafeFileHandle);
            if ((before.Attributes & (int)FileAttributes.ReparsePoint) != 0 ||
                (before.Attributes & (int)FileAttributes.Directory) != 0)
                throw new IOException("expected a regular non-reparse file");
            string hash;
            using (SHA256 sha = SHA256.Create())
            {
                byte[] digest = sha.ComputeHash(stream);
                hash = BitConverter.ToString(digest).Replace("-", "").ToLowerInvariant();
            }
            if (stream.Length != before.Bytes) throw new IOException("file length changed while hashing");
            NativeRecord after = ReadNative(stream.SafeFileHandle);
            if (!Same(before, after)) throw new IOException("file identity or metadata changed while hashing");
            return new D32BuildProfileFileRecordV1 {
                FullName = full,
                Bytes = after.Bytes,
                Sha256 = hash,
                VolumeSerialHex = after.Volume,
                FileIdHex = after.FileId,
                Attributes = after.Attributes,
                CreationTimeUtcTicks = after.CreationTicks,
                LastWriteTimeUtcTicks = after.WriteTicks
            };
        }
    }

    public static string CreateDirectoryNew(string path)
    {
        string full = Path.GetFullPath(path);
        if (!CreateDirectoryExclusive(full, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return full;
    }

    public static D32BuildProfileDirectoryRecordV1 ReadDirectory(string path)
    {
        string full = Path.GetFullPath(path);
        const uint FileReadAttributes = 0x00000080;
        const uint ShareAll = 0x00000007;
        const uint OpenExisting = 3;
        const uint BackupSemantics = 0x02000000;
        const uint OpenReparsePoint = 0x00200000;
        using (SafeFileHandle handle = CreateFileForDirectory(full, FileReadAttributes, ShareAll, IntPtr.Zero,
            OpenExisting, BackupSemantics | OpenReparsePoint, IntPtr.Zero))
        {
            if (handle == null || handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            NativeRecord native = ReadNative(handle);
            if ((native.Attributes & (int)FileAttributes.Directory) == 0 ||
                (native.Attributes & (int)FileAttributes.ReparsePoint) != 0)
                throw new IOException("expected a regular non-reparse directory");
            return new D32BuildProfileDirectoryRecordV1 {
                FullName = full,
                VolumeSerialHex = native.Volume,
                FileIdHex = native.FileId,
                Attributes = native.Attributes
            };
        }
    }
}
'@
    }
    finally {
        [Environment]::SetEnvironmentVariable('LIB', $savedLib, 'Process')
    }
}

function Get-D32ProfileFileSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-D32ProfileWindows)) { throw 'profile executable file IDs require Windows opened-handle identity' }
    if (-not (Test-D32ProfileNoReparsePath -Path $Path)) { throw "path is missing or traverses a reparse point: $Path" }
    if ($null -ne $script:D32ProfileModuleFreeFences) {
        if (-not (Microsoft.PowerShell.Core\Get-Command -Name Open-D32PowerShellAuthorityFile -CommandType Function -ErrorAction SilentlyContinue)) { throw 'module-free Profile V2 validation requires the candidate-owned PowerShell bootstrap' }
        $opened = Open-D32PowerShellAuthorityFile -Path $Path -DirectoryFences $script:D32ProfileModuleFreeFences
        try {
            return [PSCustomObject]@{
                Path = [string]$opened.Record.path
                Bytes = [Int64]$opened.Record.bytes
                Sha256 = [string]$opened.Record.sha256
                VolumeSerialHex = [string]$opened.Record.volume_serial_hex
                FileIdHex = [string]$opened.Record.file_id_hex
                Attributes = 0
                CreationTimeUtcTicks = [Int64]0
                LastWriteTimeUtcTicks = [Int64]0
            }
        }
        finally { $opened.Stream.Dispose() }
    }
    Initialize-D32ProfileFileIdentityType
    $native = [D32BuildProfileFileIdentityV1]::Read($Path)
    return [PSCustomObject]@{
        Path = [string]$native.FullName
        Bytes = [Int64]$native.Bytes
        Sha256 = [string]$native.Sha256
        VolumeSerialHex = [string]$native.VolumeSerialHex
        FileIdHex = [string]$native.FileIdHex
        Attributes = [int]$native.Attributes
        CreationTimeUtcTicks = [Int64]$native.CreationTimeUtcTicks
        LastWriteTimeUtcTicks = [Int64]$native.LastWriteTimeUtcTicks
    }
}

function Get-D32ProfileDirectoryIdentity {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-D32ProfileWindows)) { throw 'profile directory IDs require Windows opened-handle identity' }
    if (-not (Test-D32ProfileNoReparsePath -Path $Path)) { throw "directory is missing or traverses a reparse point: $Path" }
    Initialize-D32ProfileFileIdentityType
    $native = [D32BuildProfileFileIdentityV1]::ReadDirectory($Path)
    if (-not (Test-D32ProfileNoReparsePath -Path $Path)) { throw "directory path changed or traverses a reparse point: $Path" }
    return [PSCustomObject]@{
        Path = [string]$native.FullName
        VolumeSerialHex = [string]$native.VolumeSerialHex
        FileIdHex = [string]$native.FileIdHex
        Attributes = [int]$native.Attributes
    }
}

function New-D32ProfileDirectoryCreateNew {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-D32ProfileWindows)) { throw 'exclusive directory creation requires Windows' }
    $full = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($full)
    if ([String]::IsNullOrWhiteSpace($parent) -or -not (Test-D32ProfileNoReparsePath -Path $parent)) { throw 'exclusive directory parent is missing or traverses a reparse point' }
    Initialize-D32ProfileFileIdentityType
    $null = [D32BuildProfileFileIdentityV1]::CreateDirectoryNew($full)
    return Get-D32ProfileDirectoryIdentity -Path $full
}

function Test-D32ProfileDirectoryIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$VolumeSerialHex,
        [Parameter(Mandatory = $true)][string]$FileIdHex
    )

    if ($VolumeSerialHex -cnotmatch '^[0-9a-f]{16}$' -or $FileIdHex -cnotmatch '^[0-9a-f]{32}$') { throw 'directory opened-handle identity is malformed' }
    $actual = Get-D32ProfileDirectoryIdentity -Path $Path
    if ($actual.VolumeSerialHex -cne $VolumeSerialHex -or $actual.FileIdHex -cne $FileIdHex) { throw "directory opened-handle identity changed: $Path" }
    return $actual
}

function Test-D32ProfileIdentityRecord {
    param(
        [Parameter(Mandatory = $true)][object]$Declared,
        [Parameter(Mandatory = $true)][string]$ExpectedName,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ExpectedReason,
        [Parameter(Mandatory = $true)][string]$AllowedRoot
    )

    $fields = @('name', 'path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex', 'reason')
    if (-not (Test-D32ProfileExactProperties -Object $Declared -Expected $fields)) { throw "identity $ExpectedName has missing/extra fields" }
    foreach ($field in @('name', 'path', 'sha256', 'volume_serial_hex', 'file_id_hex', 'reason')) {
        if ((Get-D32ProfileProperty -Object $Declared -Name $field) -isnot [string]) { throw "identity $ExpectedName.$field must be a JSON string" }
    }
    $bytes = Get-D32ProfileProperty -Object $Declared -Name 'bytes'
    if ($bytes -isnot [byte] -and $bytes -isnot [sbyte] -and $bytes -isnot [uint16] -and $bytes -isnot [int16] -and $bytes -isnot [uint32] -and $bytes -isnot [int32] -and $bytes -isnot [uint64] -and $bytes -isnot [int64]) { throw "identity $ExpectedName.bytes must be a JSON integer" }
    if ([Int64]$bytes -le 0) { throw "identity $ExpectedName.bytes must be positive" }
    $name = [string](Get-D32ProfileProperty -Object $Declared -Name 'name')
    $path = [string](Get-D32ProfileProperty -Object $Declared -Name 'path')
    $hash = [string](Get-D32ProfileProperty -Object $Declared -Name 'sha256')
    $volume = [string](Get-D32ProfileProperty -Object $Declared -Name 'volume_serial_hex')
    $fileId = [string](Get-D32ProfileProperty -Object $Declared -Name 'file_id_hex')
    $reason = [string](Get-D32ProfileProperty -Object $Declared -Name 'reason')
    if ($name -cne $ExpectedName -or [String]::IsNullOrWhiteSpace($reason)) { throw "identity $ExpectedName name/reason mismatch" }
    if ($ExpectedReason -and $reason -cne $ExpectedReason) { throw "identity $ExpectedName reason is not the fixed reason" }
    if ($hash -cnotmatch '^[0-9a-f]{64}$' -or $volume -cnotmatch '^[0-9a-f]{16}$' -or $fileId -cnotmatch '^[0-9a-f]{32}$') { throw "identity $ExpectedName hashes or native file ID are malformed" }
    $full = Get-D32ProfileFullPath -Path $path
    if (-not (Test-D32ProfileCanonicalPathString -Path $path) -or -not (Test-D32ProfilePathWithin -Child $full -Parent $AllowedRoot)) { throw "identity $ExpectedName path is not canonical beneath its approved root" }
    $snapshot = Get-D32ProfileFileSnapshot -Path $full
    if ($snapshot.Sha256 -cne $hash -or $snapshot.Bytes -ne [Int64]$bytes -or
        $snapshot.VolumeSerialHex -cne $volume -or $snapshot.FileIdHex -cne $fileId) {
        throw "identity $ExpectedName does not match current opened-handle bytes/file ID"
    }
    return [PSCustomObject]@{ Name = $name; Path = $full; Snapshot = $snapshot; Reason = $reason }
}

function Get-D32ProfileProperty {
    param([object]$Object, [string]$Name)
    $property = if ($null -ne $Object) { $Object.PSObject.Properties[$Name] } else { $null }
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Assert-D32ProfileString {
    param([Parameter(Mandatory = $true)][object]$Object, [Parameter(Mandatory = $true)][string]$Name)
    $value = Get-D32ProfileProperty -Object $Object -Name $Name
    if ($value -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$value)) { throw "$Name must be a nonempty JSON string" }
    return [string]$value
}

function Assert-D32ProfileDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-D32ProfileCanonicalPathString -Path $Path)) { throw "directory path is not canonical: $Path" }
    $full = Get-D32ProfileFullPath -Path $Path
    if (-not (Test-D32ProfileNoReparsePath -Path $full)) { throw "directory is missing or traverses reparse point: $Path" }
    $attributes = [IO.File]::GetAttributes($full)
    if (($attributes -band [IO.FileAttributes]::Directory) -eq 0) { throw "path is not a directory: $Path" }
    return [IO.Path]::GetFullPath($full)
}

function Get-D32ProfileCurrentExecutableInventory {
    param([string[]]$Directories)

    $records = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $enumerationOptions = [IO.EnumerationOptions]::new()
    $enumerationOptions.AttributesToSkip = [IO.FileAttributes]::None
    $enumerationOptions.RecurseSubdirectories = $false
    $enumerationOptions.IgnoreInaccessible = $false
    foreach ($directory in $Directories) {
        $fullDirectory = Assert-D32ProfileDirectory -Path $directory
        foreach ($itemPath in [IO.Directory]::EnumerateFiles($fullDirectory, '*', $enumerationOptions)) {
            $itemName = [IO.Path]::GetFileName([string]$itemPath)
            $extension = [IO.Path]::GetExtension($itemName)
            if ($extension -notin @('.exe', '.com')) { continue }
            $path = [IO.Path]::GetFullPath([string]$itemPath)
            if (-not $seen.Add($path)) { throw "duplicate PATH executable directory entry: $path" }
            $records.Add((Get-D32ProfileFileSnapshot -Path $path))
        }
    }
    return @($records.ToArray())
}

function Get-D32ProfileCurrentScriptInventory {
    param([string[]]$Directories)

    $records = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $enumerationOptions = [IO.EnumerationOptions]::new()
    $enumerationOptions.AttributesToSkip = [IO.FileAttributes]::None
    $enumerationOptions.RecurseSubdirectories = $false
    $enumerationOptions.IgnoreInaccessible = $false
    foreach ($directory in $Directories) {
        $fullDirectory = Assert-D32ProfileDirectory -Path $directory
        foreach ($itemPath in [IO.Directory]::EnumerateFiles($fullDirectory, '*', $enumerationOptions)) {
            $itemName = [IO.Path]::GetFileName([string]$itemPath)
            $extension = [IO.Path]::GetExtension($itemName)
            if ($extension -notin @('.bat', '.cmd')) { continue }
            $path = [IO.Path]::GetFullPath([string]$itemPath)
            if (-not $seen.Add($path)) { throw "duplicate PATH script directory entry: $path" }
            $records.Add((Get-D32ProfileFileSnapshot -Path $path))
        }
    }
    return @($records.ToArray())
}

function Get-D32CurrentPowerShellImagePath {
    if (-not (Test-D32ProfileWindows)) { throw 'D32 profile runner identity requires Windows' }
    $process = [Diagnostics.Process]::GetCurrentProcess()
    try { $path = $process.MainModule.FileName }
    finally { $process.Dispose() }
    if ([String]::IsNullOrWhiteSpace($path)) { throw 'current PowerShell process image path is unavailable' }
    return [IO.Path]::GetFullPath($path)
}

function Test-D32ProfileImageInventory {
    param(
        [Parameter(Mandatory = $true)][object[]]$DeclaredRecords,
        [Parameter(Mandatory = $true)][string[]]$Directories,
        [Parameter(Mandatory = $true)][string[]]$AllowedRoots,
        [Parameter(Mandatory = $true)][string]$InventoryName
    )

    if ($DeclaredRecords -isnot [Array]) { throw "$InventoryName must be an array" }
    $expected = @{}
    foreach ($record in $DeclaredRecords) {
        if ($null -eq $record) { throw "$InventoryName contains null" }
        $declaredName = Get-D32ProfileProperty -Object $record -Name 'name'
        $declaredPath = Get-D32ProfileProperty -Object $record -Name 'path'
        if ($declaredName -isnot [string] -or $declaredPath -isnot [string]) { throw "$InventoryName record name/path must be strings" }
        $base = [IO.Path]::GetFileName([string]$declaredPath)
        if ($base -match '^(?i:git|ssh|ssh-agent|git-credential[^.]*)\.exe$') { throw "$InventoryName may not expose Git/SSH/credential helper image $base" }
        $matchingRoots = [System.Collections.Generic.List[string]]::new()
        foreach ($root in $AllowedRoots) { if (Test-D32ProfilePathWithin -Child $declaredPath -Parent $root) { $matchingRoots.Add([string]$root) } }
        if ($matchingRoots.Count -ne 1) { throw "$InventoryName executable is not beneath exactly one allowed root: $declaredPath" }
        $validated = Test-D32ProfileIdentityRecord -Declared $record -ExpectedName ([string]$declaredName) -ExpectedReason '' -AllowedRoot $matchingRoots[0]
        $inConstructedPath = $false
        foreach ($directory in $Directories) { if (Test-D32ProfilePathWithin -Child $validated.Path -Parent $directory) { $inConstructedPath = $true; break } }
        if (-not $inConstructedPath) { throw "$InventoryName executable is outside the constructed PATH directories: $($validated.Path)" }
        $key = $validated.Path.ToLowerInvariant()
        if ($expected.ContainsKey($key)) { throw "$InventoryName contains a duplicate executable path" }
        $expected[$key] = $validated
        if ([IO.Path]::GetFileName($validated.Path) -ine $base) { throw "$InventoryName executable basename changed" }
    }
    $actual = @(Get-D32ProfileCurrentExecutableInventory -Directories $Directories)
    if ($actual.Count -ne $expected.Count) { throw "$InventoryName does not exactly cover every executable reachable through its directories" }
    foreach ($snapshot in $actual) {
        $key = $snapshot.Path.ToLowerInvariant()
        if (-not $expected.ContainsKey($key)) { throw "$InventoryName contains an unpinned executable: $($snapshot.Path)" }
        $declared = $expected[$key].Snapshot
        if ($snapshot.Sha256 -cne $declared.Sha256 -or $snapshot.Bytes -ne $declared.Bytes -or
            $snapshot.VolumeSerialHex -cne $declared.VolumeSerialHex -or $snapshot.FileIdHex -cne $declared.FileIdHex) {
            throw "$InventoryName executable identity changed: $($snapshot.Path)"
        }
    }
    return $actual
}

function Test-D32ProfileExactVctipImageRecord {
    param([AllowNull()][object]$Record)

    if ($null -eq $Record) { return $false }
    $path = Get-D32ProfileProperty -Object $Record -Name 'Path'
    $sha256 = Get-D32ProfileProperty -Object $Record -Name 'Sha256'
    $bytes = Get-D32ProfileProperty -Object $Record -Name 'Bytes'
    $volume = Get-D32ProfileProperty -Object $Record -Name 'VolumeSerialHex'
    $fileId = Get-D32ProfileProperty -Object $Record -Name 'FileIdHex'
    return $path -is [string] -and
        [String]::Equals([string]$path, 'E:\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\vctip.exe', [StringComparison]::OrdinalIgnoreCase) -and
        $sha256 -is [string] -and [String]::Equals([string]$sha256, 'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996', [StringComparison]::Ordinal) -and
        $bytes -is [ValueType] -and [Int64]$bytes -eq 335328 -and
        $volume -is [string] -and [String]::Equals([string]$volume, '749614a1961465c0', [StringComparison]::Ordinal) -and
        $fileId -is [string] -and [String]::Equals([string]$fileId, '0b5d2000000001000000000000000000', [StringComparison]::Ordinal)
}

function Test-D32ProfilePinnedVctipContentIdentity {
    param([AllowNull()][object]$Bytes, [AllowNull()][object]$Sha256)

    return $Bytes -is [ValueType] -and [Int64]$Bytes -eq 335328 -and
        $Sha256 -is [string] -and [String]::Equals([string]$Sha256, 'e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996', [StringComparison]::Ordinal)
}

function Get-D32ProfileExactVctipImageRecord {
    param([Parameter(Mandatory = $true)][object]$ValidatedProfile)

    $records = @($ValidatedProfile.ExecutableInventory) + @($ValidatedProfile.WindowsImageInventory)
    $vctip = @($records | Where-Object {
        [IO.Path]::GetFileName([string]$_.Path) -ieq 'vctip.exe' -or
        (Test-D32ProfilePinnedVctipContentIdentity -Bytes $_.Bytes -Sha256 $_.Sha256)
    })
    if ($vctip.Count -ne 1 -or -not (Test-D32ProfileExactVctipImageRecord -Record $vctip[0])) {
        throw 'D32_VCTIP_PROFILE_PIN_BLOCKED: the caller-pinned Profile V2 must contain exactly the approved MSVC VCTIP path/bytes/SHA/opened-handle identity'
    }
    return $vctip[0]
}

function Test-D32ProfileScriptInventory {
    param(
        [Parameter(Mandatory = $true)][object[]]$DeclaredRecords,
        [Parameter(Mandatory = $true)][string[]]$Directories,
        [Parameter(Mandatory = $true)][string[]]$AllowedRoots,
        [Parameter(Mandatory = $true)][string]$InventoryName
    )

    if ($DeclaredRecords -isnot [Array]) { throw "$InventoryName must be an array" }
    $expected = @{}
    foreach ($record in $DeclaredRecords) {
        if ($null -eq $record) { throw "$InventoryName contains null" }
        $declaredName = Get-D32ProfileProperty -Object $record -Name 'name'
        $declaredPath = Get-D32ProfileProperty -Object $record -Name 'path'
        if ($declaredName -isnot [string] -or $declaredPath -isnot [string]) { throw "$InventoryName record name/path must be strings" }
        $extension = [IO.Path]::GetExtension([string]$declaredPath)
        if ($extension -notin @('.bat', '.cmd') -or [IO.Path]::GetFileName([string]$declaredPath) -cne [string]$declaredName) { throw "$InventoryName may contain only exact .bat/.cmd basenames" }
        $matchingRoots = [System.Collections.Generic.List[string]]::new()
        foreach ($root in $AllowedRoots) { if (Test-D32ProfilePathWithin -Child $declaredPath -Parent $root) { $matchingRoots.Add([string]$root) } }
        if ($matchingRoots.Count -ne 1) { throw "$InventoryName script is not beneath exactly one approved toolchain/native root: $declaredPath" }
        $validated = Test-D32ProfileIdentityRecord -Declared $record -ExpectedName ([string]$declaredName) -ExpectedReason 'dormant script inventory only; never launchable' -AllowedRoot $matchingRoots[0]
        $inConstructedPath = $false
        foreach ($directory in $Directories) { if (Test-D32ProfilePathWithin -Child $validated.Path -Parent $directory) { $inConstructedPath = $true; break } }
        if (-not $inConstructedPath) { throw "$InventoryName script is outside the constructed PATH directories: $($validated.Path)" }
        $key = $validated.Path.ToLowerInvariant()
        if ($expected.ContainsKey($key)) { throw "$InventoryName contains a duplicate script path" }
        $expected[$key] = $validated
    }
    $actual = @(Get-D32ProfileCurrentScriptInventory -Directories $Directories)
    if ($actual.Count -ne $expected.Count) { throw "$InventoryName does not exactly cover every dormant .bat/.cmd reachable through its directories" }
    foreach ($snapshot in $actual) {
        $key = $snapshot.Path.ToLowerInvariant()
        if (-not $expected.ContainsKey($key)) { throw "$InventoryName contains an unpinned resident script: $($snapshot.Path)" }
        $declared = $expected[$key].Snapshot
        if ($snapshot.Sha256 -cne $declared.Sha256 -or $snapshot.Bytes -ne $declared.Bytes -or
            $snapshot.VolumeSerialHex -cne $declared.VolumeSerialHex -or $snapshot.FileIdHex -cne $declared.FileIdHex) {
            throw "$InventoryName script identity changed: $($snapshot.Path)"
        }
    }
    return $actual
}

function Get-D32BuildToolchainLockInputs {
    param([Parameter(Mandatory = $true)][string]$Repository)

    $expected = @(
        [ordered]@{ manifest_path = 'vita-agent-protocol/Cargo.toml'; lock_path = 'vita-agent-protocol/Cargo.lock' },
        [ordered]@{ manifest_path = 'vita-agent/Cargo.toml'; lock_path = 'vita-agent/Cargo.lock' },
        [ordered]@{ manifest_path = 'src-tauri/Cargo.toml'; lock_path = 'src-tauri/Cargo.lock' }
    )
    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $expected) {
        $manifest = [IO.Path]::Combine($Repository, [string]$entry.manifest_path)
        $lock = [IO.Path]::Combine($Repository, [string]$entry.lock_path)
        if (-not (Test-D32ProfileNoReparsePath -Path $manifest) -or -not (Test-D32ProfileNoReparsePath -Path $lock)) { throw "locked manifest input is missing or traverses reparse point: $($entry.manifest_path)" }
        $lockDigest = Get-D32ProfileFileSnapshot -Path $lock
        $lockText = [IO.File]::ReadAllText($lock, [Text.Encoding]::UTF8)
        $gitSourceCount = Test-D32CargoLockGitSources -LockText $lockText
        $result.Add([PSCustomObject]@{
            ManifestPath = $entry.manifest_path.Replace('\', '/')
            ManifestFullPath = [IO.Path]::GetFullPath($manifest)
            LockPath = $entry.lock_path.Replace('\', '/')
            LockFullPath = [IO.Path]::GetFullPath($lock)
            LockSha256 = $lockDigest.Sha256
            LockBytes = $lockDigest.Bytes
            GitSourceCount = $gitSourceCount
        })
    }
    return @($result.ToArray())
}

function Test-D32CargoLockGitSources {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$LockText)

    $count = 0
    foreach ($line in $LockText -split '\r?\n') {
        if ($line -notmatch '^\s*source\s*=\s*"(git\+[^"\r\n]+)"\s*$') { continue }
        $source = [string]$Matches[1]
        if ($source -notmatch '#([0-9a-f]{40})$') { throw 'Cargo.lock contains a Git source without a full immutable 40-hex commit object ID' }
        $commit = [string]$Matches[1]
        if ($source -match '(?:\?|&)rev=([0-9a-f]{40})(?:&|#)' -and [string]$Matches[1] -cne $commit) {
            throw 'Cargo.lock Git source rev query does not equal its locked commit object ID'
        }
        $count++
    }
    return $count
}

function Test-D32CargoConfigAbsent {
    param([Parameter(Mandatory = $true)][string]$Repository, [Parameter(Mandatory = $true)][string]$CargoHome)

    $repoFull = Get-D32ProfileFullPath -Path $Repository
    $cursor = $repoFull
    while (-not [String]::IsNullOrWhiteSpace($cursor)) {
        foreach ($name in @('config', 'config.toml')) {
            $candidate = Join-Path (Join-Path $cursor '.cargo') $name
            if (Test-Path -LiteralPath $candidate) { throw "Cargo configuration file is not permitted: $candidate" }
        }
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) { break }
        $cursor = $parent.FullName
    }
    foreach ($directoryName in @('vita-agent-protocol', 'vita-agent', 'src-tauri')) {
        foreach ($name in @('config', 'config.toml')) {
            $candidate = Join-Path (Join-Path (Join-Path $repoFull $directoryName) '.cargo') $name
            if (Test-Path -LiteralPath $candidate) { throw "Cargo configuration file is not permitted: $candidate" }
        }
    }
    if (Test-Path -LiteralPath $CargoHome -PathType Container) {
        foreach ($name in @('config', 'config.toml', 'credentials', 'credentials.toml', 'credentials.json')) {
            $candidate = Join-Path $CargoHome $name
            if (Test-Path -LiteralPath $candidate) { throw "Cargo-home config/credentials file is not permitted: $candidate" }
        }
    }
    return $true
}

function Test-D32CargoHome {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Repository,
        [switch]$RequireEmpty
    )

    $full = Assert-D32ProfileDirectory -Path $Path
    $repoFull = Get-D32ProfileFullPath -Path $Repository
    if (Test-D32ProfilePathWithin -Child $full -Parent $repoFull) { throw 'CARGO_HOME must be outside and non-overlapping with the repository' }
    Test-D32CargoConfigAbsent -Repository $repoFull -CargoHome $full | Out-Null
    if ($RequireEmpty -and @(Get-ChildItem -LiteralPath $full -Force -ErrorAction Stop).Count -ne 0) { throw 'fresh CARGO_HOME must be empty before locked fetch' }
    return [PSCustomObject]@{ Path = $full; Empty = (@(Get-ChildItem -LiteralPath $full -Force -ErrorAction Stop).Count -eq 0) }
}

function Test-D32BuildToolchainProfile {
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Repository,
        [AllowNull()][string]$EvidenceRoot,
        [string]$ExpectedTargetTriple = 'x86_64-pc-windows-msvc'
    )

    $result = [ordered]@{ IsValid = $false; Failure = $null; Profile = $null; ProfilePath = $null; Repository = $null; EvidenceRoot = $null; ExpectedTargetTriple = $null; Digest = $null; Identity = $null; ExecutableInventory = @(); ScriptInventory = @(); LockInputs = @() }
    try {
        if (-not (Test-D32ProfileWindows)) { throw 'caller-pinned MSVC toolchain profile is Windows-only' }
        if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'independent expected toolchain profile SHA-256 must be lowercase 64-hex' }
        $profileFull = Get-D32ProfileFullPath -Path $ProfilePath
        if (-not (Test-D32ProfileCanonicalPathString -Path $ProfilePath)) { throw 'profile path must be canonical' }
        if (-not (Test-D32ProfileNoReparsePath -Path $profileFull)) { throw 'profile path is missing or traverses a reparse point' }
        $profileSnapshot = Get-D32ProfileFileSnapshot -Path $profileFull
        if ($profileSnapshot.Sha256 -cne $ExpectedSha256) { throw 'profile bytes do not match the independently supplied expected SHA-256' }
        $raw = [IO.File]::ReadAllText($profileFull, [Text.UTF8Encoding]::new($false, $true))
        $document = [System.Text.Json.JsonDocument]::Parse($raw)
        try {
            if (Test-D32ProfileJsonElementDuplicates -Element $document.RootElement) { throw 'profile JSON has duplicate object keys' }
            if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'profile root must be a JSON object' }
            $profile = ConvertFrom-D32ProfileJsonElement -Element $document.RootElement
        }
        finally { $document.Dispose() }
        $topFields = @('schema_version', 'profile_type', 'target_triple', 'system_root', 'powershell_root', 'powershell', 'rust_toolchain_root', 'toolchain', 'rust_toolchain_bin_images', 'native_roots', 'native', 'windows_child_images', 'fetch_manifests', 'fetch_git', 'env_policy', 'cargo_policy')
        if (-not (Test-D32ProfileExactProperties -Object $profile -Expected $topFields)) { throw 'profile top-level schema has missing or extra fields' }
        if ($profile.schema_version -isnot [int] -and $profile.schema_version -isnot [long]) { throw 'profile schema_version must be a JSON integer' }
        if ([Int64]$profile.schema_version -ne 2) { throw 'profile schema_version is not supported; legacy v1 has no dormant-script identity inventory' }
        if ((Assert-D32ProfileString -Object $profile -Name 'profile_type') -cne 'D32_BUILD_TOOLCHAIN_PROFILE_V2') { throw 'profile profile_type is not supported' }
        if ((Assert-D32ProfileString -Object $profile -Name 'target_triple') -cne $ExpectedTargetTriple) { throw "profile target_triple must equal $ExpectedTargetTriple" }
        if ((Assert-D32ProfileString -Object $profile -Name 'env_policy') -cne 'D32_BUILD_ENV_V1' -or (Assert-D32ProfileString -Object $profile -Name 'cargo_policy') -cne 'FRESH_HOME_LOCKED_FETCH_OFFLINE_AFTER') { throw 'profile env_policy or cargo_policy is not the fixed D32 policy' }

        $repositoryFull = Assert-D32ProfileDirectory -Path $Repository
        if ((Test-D32ProfilePathWithin -Child $profileFull -Parent $repositoryFull) -or (Test-D32ProfilePathWithin -Child $repositoryFull -Parent $profileFull)) { throw 'toolchain profile file must be outside and non-overlapping with the repository' }
        if ($EvidenceRoot) {
            if (-not (Test-D32ProfileCanonicalPathString -Path $EvidenceRoot)) { throw 'evidence root path must be canonical' }
            $evidenceFull = Get-D32ProfileFullPath -Path $EvidenceRoot
            if ((Test-D32ProfilePathWithin -Child $evidenceFull -Parent $repositoryFull) -or (Test-D32ProfilePathWithin -Child $repositoryFull -Parent $evidenceFull)) { throw 'evidence root must be outside and non-overlapping with the repository' }
        }
        if (-not (Test-D32ProfileNoReparsePath -Path $profileFull)) { throw 'profile path traverses a reparse point' }

        $systemRoot = Assert-D32ProfileDirectory -Path (Assert-D32ProfileString -Object $profile -Name 'system_root')
        $actualSystemRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows))
        if (-not (Test-D32ProfilePathEqual -Left $systemRoot -Right $actualSystemRoot)) { throw 'profile system_root does not equal the current Windows directory' }
        $powershellRoot = Assert-D32ProfileDirectory -Path (Assert-D32ProfileString -Object $profile -Name 'powershell_root')
        if ((Test-D32ProfilePathWithin -Child $powershellRoot -Parent $repositoryFull) -or (Test-D32ProfilePathWithin -Child $repositoryFull -Parent $powershellRoot)) { throw 'PowerShell host root must be separate from the repository' }
        $currentPowerShellPath = Get-D32CurrentPowerShellImagePath
        if (-not (Test-D32ProfilePathEqual -Left $currentPowerShellPath -Right $profile.powershell.path)) { throw 'profile pinned PowerShell host is not the current process image' }
        $powershellIdentity = Test-D32ProfileIdentityRecord -Declared $profile.powershell -ExpectedName 'pwsh.exe' -ExpectedReason 'direct pinned PowerShell host executable' -AllowedRoot $powershellRoot
        if (-not (Test-D32ProfilePathEqual -Left $powershellIdentity.Path -Right $currentPowerShellPath)) { throw 'PowerShell opened-handle identity does not match the current host image' }
        $rustRoot = Assert-D32ProfileDirectory -Path (Assert-D32ProfileString -Object $profile -Name 'rust_toolchain_root')
        if ((Test-D32ProfilePathWithin -Child $rustRoot -Parent $repositoryFull) -or (Test-D32ProfilePathWithin -Child $repositoryFull -Parent $rustRoot) -or (Test-D32ProfilePathWithin -Child $rustRoot -Parent $systemRoot) -or (Test-D32ProfilePathWithin -Child $systemRoot -Parent $rustRoot) -or (Test-D32ProfilePathWithin -Child $rustRoot -Parent $powershellRoot) -or (Test-D32ProfilePathWithin -Child $powershellRoot -Parent $rustRoot)) { throw 'Rust toolchain root must be separate from repository, PowerShell host, and Windows system root' }
        $rustBin = Assert-D32ProfileDirectory -Path ([IO.Path]::Combine($rustRoot, 'bin'))
        if (-not (Test-D32ProfileExactProperties -Object $profile.toolchain -Expected @('cargo', 'rustc', 'rustdoc'))) { throw 'profile.toolchain has missing or extra tools' }
        $direct = @{}
        foreach ($toolName in @('cargo', 'rustc', 'rustdoc')) {
            $expectedName = "$toolName.exe"
            $reason = "direct pinned $toolName executable"
            $identity = Test-D32ProfileIdentityRecord -Declared $profile.toolchain.$toolName -ExpectedName $expectedName -ExpectedReason $reason -AllowedRoot $rustBin
            $direct[$toolName] = $identity
        }

        if ($profile.native_roots -isnot [Array] -or $profile.native_roots.Count -ne 2) { throw 'native_roots must contain exactly the approved msvc and windows-sdk roots' }
        $nativeRoots = @{}
        foreach ($rootRecord in $profile.native_roots) {
            if (-not (Test-D32ProfileExactProperties -Object $rootRecord -Expected @('name', 'path'))) { throw 'native root record has missing/extra fields' }
            if ($rootRecord.name -isnot [string] -or $rootRecord.path -isnot [string]) { throw 'native root name/path must be strings' }
            if ($rootRecord.name -cnotin @('msvc', 'windows-sdk') -or $nativeRoots.ContainsKey([string]$rootRecord.name)) { throw 'native root names must be unique fixed msvc/windows-sdk values' }
            $nativeRoots[[string]$rootRecord.name] = Assert-D32ProfileDirectory -Path ([string]$rootRecord.path)
        }
        if (-not $nativeRoots.ContainsKey('msvc') -or -not $nativeRoots.ContainsKey('windows-sdk')) { throw 'both msvc and windows-sdk roots are required' }
        foreach ($name in @('msvc', 'windows-sdk')) {
            if ((Test-D32ProfilePathWithin -Child $nativeRoots[$name] -Parent $repositoryFull) -or (Test-D32ProfilePathWithin -Child $repositoryFull -Parent $nativeRoots[$name])) { throw "native root $name overlaps the repository" }
            if ((Test-D32ProfilePathWithin -Child $nativeRoots[$name] -Parent $rustRoot) -or (Test-D32ProfilePathWithin -Child $rustRoot -Parent $nativeRoots[$name])) { throw "native root $name overlaps the Rust toolchain root" }
            if ((Test-D32ProfilePathWithin -Child $nativeRoots[$name] -Parent $powershellRoot) -or (Test-D32ProfilePathWithin -Child $powershellRoot -Parent $nativeRoots[$name])) { throw "native root $name overlaps the PowerShell host root" }
        }
        if ((Test-D32ProfilePathWithin -Child $nativeRoots['msvc'] -Parent $nativeRoots['windows-sdk']) -or (Test-D32ProfilePathWithin -Child $nativeRoots['windows-sdk'] -Parent $nativeRoots['msvc'])) { throw 'MSVC and Windows SDK roots must be distinct and non-overlapping' }

        $native = $profile.native
        if (-not (Test-D32ProfileExactProperties -Object $native -Expected @('path_entries', 'include_dirs', 'lib_dirs', 'libpath_dirs', 'environment', 'path_images', 'path_scripts'))) { throw 'profile.native has missing or extra fields' }
        foreach ($field in @('path_entries', 'include_dirs', 'lib_dirs', 'libpath_dirs')) {
            $values = Get-D32ProfileProperty -Object $native -Name $field
            if ($values -isnot [Array] -or $values.Count -eq 0) { throw "native.$field must be a non-empty array" }
            $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($path in $values) {
                if ($path -isnot [string]) { throw "native.$field entries must be strings" }
                $full = Assert-D32ProfileDirectory -Path $path
                $owners = 0
                foreach ($nativeRoot in $nativeRoots.Values) { if (Test-D32ProfilePathWithin -Child $full -Parent $nativeRoot) { $owners++ } }
                if ($owners -ne 1) { throw "native.$field directory is not under exactly one approved native root: $full" }
                if (-not $seen.Add($full)) { throw "native.$field contains a duplicate directory" }
            }
        }

        $allowedNativeEnvironment = @('VCINSTALLDIR', 'VCToolsInstallDir', 'VCToolsRedistDir', 'VSINSTALLDIR', 'WindowsSdkDir', 'UniversalCRTSdkDir', 'VCToolsVersion', 'WindowsSDKVersion', 'WindowsSDKLibVersion', 'UCRTVersion', 'VisualStudioVersion', 'VSCMD_VER', 'VSCMD_ARG_TGT_ARCH')
        $pathNativeEnvironment = @('VCINSTALLDIR', 'VCToolsInstallDir', 'VCToolsRedistDir', 'VSINSTALLDIR', 'WindowsSdkDir', 'UniversalCRTSdkDir')
        $nativeEnvironment = $native.environment
        if ($null -eq $nativeEnvironment -or $nativeEnvironment -is [Array] -or $nativeEnvironment -is [string]) { throw 'native.environment must be an object' }
        foreach ($property in $nativeEnvironment.PSObject.Properties) {
            if ($allowedNativeEnvironment -cnotcontains $property.Name) { throw "native environment variable is not approved: $($property.Name)" }
            if ($property.Value -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$property.Value)) { throw "native environment variable $($property.Name) must have a nonempty JSON string" }
            if ($pathNativeEnvironment -ccontains $property.Name) {
                $valuePath = Assert-D32ProfileDirectory -Path ([string]$property.Value)
                $owners = 0
                foreach ($nativeRoot in $nativeRoots.Values) { if (Test-D32ProfilePathWithin -Child $valuePath -Parent $nativeRoot) { $owners++ } }
                if ($owners -ne 1) { throw "native environment path $($property.Name) is outside approved roots" }
            }
            elseif ($property.Name -ceq 'VSCMD_ARG_TGT_ARCH') {
                if ($property.Value -cne 'x64') { throw 'VSCMD_ARG_TGT_ARCH must be exactly x64' }
            }
            elseif ($property.Value -cnotmatch '^[A-Za-z0-9._-]+\\?$') { throw "native environment version $($property.Name) has invalid characters" }
        }
        foreach ($forbidden in @('CL', '_CL_', 'LINK', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER')) {
            if ($nativeEnvironment.PSObject.Properties[$forbidden]) { throw "compiler/linker option injection environment variable is forbidden: $forbidden" }
        }

        $nativePathDirsList = [System.Collections.Generic.List[string]]::new()
        foreach ($nativePath in $native.path_entries) { $nativePathDirsList.Add((Assert-D32ProfileDirectory -Path ([string]$nativePath))) }
        $nativePathDirs = $nativePathDirsList.ToArray()
        if ($profile.rust_toolchain_bin_images -isnot [Array]) { throw 'rust_toolchain_bin_images must be a JSON array' }
        if ($native.path_images -isnot [Array]) { throw 'native.path_images must be a JSON array' }
        if ($native.path_scripts -isnot [Array]) { throw 'native.path_scripts must be a JSON array; every dormant .bat/.cmd in PATH requires an identity pin' }
        if ($profile.windows_child_images -isnot [Array]) { throw 'windows_child_images must be a JSON array' }
        $toolchainImages = Test-D32ProfileImageInventory -DeclaredRecords $profile.rust_toolchain_bin_images -Directories @($rustBin) -AllowedRoots @($rustRoot) -InventoryName 'rust_toolchain_bin_images'
        $nativeImages = Test-D32ProfileImageInventory -DeclaredRecords $native.path_images -Directories $nativePathDirs -AllowedRoots @($nativeRoots.Values) -InventoryName 'native.path_images'
        $allPathDirs = @($rustBin) + @($nativePathDirs)
        $allPathRoots = @($rustRoot) + @($nativeRoots.Values)
        $scriptInventory = Test-D32ProfileScriptInventory -DeclaredRecords $native.path_scripts -Directories $allPathDirs -AllowedRoots $allPathRoots -InventoryName 'native.path_scripts'
        if ($profile.windows_child_images.Count -ne 1) { throw 'windows_child_images must contain exactly one pinned System32 conhost.exe image' }
        $windowsRecord = $profile.windows_child_images[0]
        $windowsIdentity = Test-D32ProfileIdentityRecord -Declared $windowsRecord -ExpectedName 'conhost.exe' -ExpectedReason 'direct pinned Windows console host child image' -AllowedRoot ([IO.Path]::Combine($systemRoot, 'System32'))
        if ([IO.Path]::GetFileName($windowsIdentity.Path) -ine 'conhost.exe') { throw 'windows_child_images must identify System32 conhost.exe' }
        $windowsImages = @($windowsIdentity.Snapshot)
        foreach ($toolName in @('cargo', 'rustc', 'rustdoc')) {
            $match = [System.Collections.Generic.List[object]]::new()
            foreach ($image in $toolchainImages) { if (Test-D32ProfilePathEqual -Left $image.Path -Right $direct[$toolName].Path) { $match.Add($image) } }
            if ($match.Count -ne 1 -or $match[0].Sha256 -cne $direct[$toolName].Snapshot.Sha256 -or $match[0].FileIdHex -cne $direct[$toolName].Snapshot.FileIdHex) { throw "direct $toolName identity is not present exactly in the Rust PATH inventory" }
        }
        foreach ($core in @('cl.exe', 'link.exe', 'lib.exe', 'rc.exe', 'mt.exe')) {
            $matches = 0
            foreach ($image in $nativeImages) { if ([IO.Path]::GetFileName($image.Path) -ieq $core) { $matches++ } }
            if ($matches -ne 1) { throw "native PATH inventory must contain exactly one pinned $core" }
        }

        $expectedLocks = @(Get-D32BuildToolchainLockInputs -Repository $repositoryFull)
        if ($profile.fetch_manifests -isnot [Array] -or $profile.fetch_manifests.Count -ne $expectedLocks.Count) { throw 'fetch_manifests must contain the exact three locked D32 package manifests' }
        $validatedLocks = [System.Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $expectedLocks.Count; $index++) {
            $record = $profile.fetch_manifests[$index]
            if (-not (Test-D32ProfileExactProperties -Object $record -Expected @('manifest_path', 'lock_sha256'))) { throw "fetch_manifests[$index] has missing/extra fields" }
            if ($record.manifest_path -isnot [string] -or $record.lock_sha256 -isnot [string]) { throw "fetch_manifests[$index] fields must be strings" }
            if ($record.manifest_path.Replace('\', '/') -cne $expectedLocks[$index].ManifestPath -or $record.lock_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $record.lock_sha256 -cne $expectedLocks[$index].LockSha256) { throw "fetch_manifests[$index] does not bind the exact current manifest/lock SHA" }
            $validatedLocks.Add([PSCustomObject]@{
                ManifestPath = $expectedLocks[$index].ManifestPath
                ManifestFullPath = $expectedLocks[$index].ManifestFullPath
                LockPath = $expectedLocks[$index].LockPath
                LockSha256 = $expectedLocks[$index].LockSha256
                LockBytes = $expectedLocks[$index].LockBytes
            })
        }
        if ($null -ne $profile.fetch_git) { throw 'fetch_git must be null: only Cargo in-process libgit2 may fetch locked Git sources; no external Git CLI is admitted' }
        $profileSnapshotAfter = Get-D32ProfileFileSnapshot -Path $profileFull
        if ($profileSnapshotAfter.Sha256 -cne $profileSnapshot.Sha256 -or $profileSnapshotAfter.Bytes -ne $profileSnapshot.Bytes -or
            $profileSnapshotAfter.VolumeSerialHex -cne $profileSnapshot.VolumeSerialHex -or $profileSnapshotAfter.FileIdHex -cne $profileSnapshot.FileIdHex) { throw 'toolchain profile identity changed during validation' }
        $result.IsValid = $true
        $result.Profile = $profile
        $result.ProfilePath = $profileFull
        $result.Repository = $repositoryFull
        $result.EvidenceRoot = if ($EvidenceRoot) { [IO.Path]::GetFullPath($EvidenceRoot) } else { $null }
        $result.ExpectedTargetTriple = $ExpectedTargetTriple
        $result.Digest = $profileSnapshot.Sha256
        $result.Identity = $profileSnapshot
        $result.ExecutableInventory = @($toolchainImages) + @($nativeImages)
        $result.ScriptInventory = @($scriptInventory)
        $result.WindowsImageInventory = @($windowsImages)
        $result.LockInputs = @($validatedLocks.ToArray())
        return [PSCustomObject]$result
    }
    catch {
        $result.Failure = $_.Exception.Message
        return [PSCustomObject]$result
    }
}

function Test-D32BuildToolchainProfileModuleFree {
    param(
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Repository,
        [AllowNull()][string]$EvidenceRoot,
        [string]$ExpectedTargetTriple = 'x86_64-pc-windows-msvc'
    )
    if (-not (Microsoft.PowerShell.Core\Get-Command -Name Open-D32PowerShellAuthorityFile -CommandType Function -ErrorAction SilentlyContinue)) {
        throw 'module-free Profile V2 validation requires the candidate-owned PowerShell bootstrap to be dot-sourced first'
    }
    if ($null -ne $script:D32ProfileModuleFreeFences) { throw 'nested module-free Profile V2 validation is not supported' }
    $fences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
    $script:D32ProfileModuleFreeFences = $fences
    try {
        return Test-D32BuildToolchainProfile -ProfilePath $ProfilePath -ExpectedSha256 $ExpectedSha256 -Repository $Repository -EvidenceRoot $EvidenceRoot -ExpectedTargetTriple $ExpectedTargetTriple
    }
    finally {
        foreach ($fence in $fences.Values) { if ($null -ne $fence.Handle -and -not $fence.Handle.IsClosed) { $fence.Handle.Dispose() } }
        $script:D32ProfileModuleFreeFences = $null
    }
}

function Assert-D32BuildToolchainProfileCurrent {
    param([Parameter(Mandatory = $true)][object]$ValidatedProfile)

    if (-not [bool]$ValidatedProfile.IsValid) { throw 'validated profile object is not valid' }
    $again = Test-D32BuildToolchainProfile -ProfilePath ([string]$ValidatedProfile.ProfilePath) -ExpectedSha256 ([string]$ValidatedProfile.Digest) -Repository ([string]$ValidatedProfile.Repository) -EvidenceRoot ([string]$ValidatedProfile.EvidenceRoot) -ExpectedTargetTriple ([string]$ValidatedProfile.ExpectedTargetTriple)
    if (-not $again.IsValid) { throw "build toolchain profile changed or failed current identity validation: $($again.Failure)" }
    if ($again.ExecutableInventory.Count -ne $ValidatedProfile.ExecutableInventory.Count) { throw 'build executable inventory count changed' }
    if ($again.ScriptInventory.Count -ne $ValidatedProfile.ScriptInventory.Count) { throw 'dormant PATH script inventory count changed' }
    if ($again.WindowsImageInventory.Count -ne $ValidatedProfile.WindowsImageInventory.Count) { throw 'Windows child-image inventory count changed' }
    return $again
}

function Get-D32BuildToolchainEnvironment {
    param(
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$CargoHome,
        [Parameter(Mandatory = $true)][string]$TempRoot,
        [Parameter(Mandatory = $true)][bool]$Offline
    )

    if (-not [bool]$ValidatedProfile.IsValid) { throw 'cannot construct child environment from invalid toolchain profile' }
    $ValidatedProfile = Assert-D32BuildToolchainProfileCurrent -ValidatedProfile $ValidatedProfile
    $profile = $ValidatedProfile.Profile
    $cargoHomeFull = Get-D32ProfileFullPath -Path $CargoHome
    $tempFull = Get-D32ProfileFullPath -Path $TempRoot
    if (-not (Test-D32ProfileCanonicalPathString -Path $CargoHome) -or -not (Test-D32ProfileCanonicalPathString -Path $TempRoot)) { throw 'CARGO_HOME/TEMP paths must be canonical' }
    $null = Test-D32CargoHome -Path $cargoHomeFull -Repository $ValidatedProfile.Repository
    if (-not (Test-D32ProfileNoReparsePath -Path $cargoHomeFull) -or -not (Test-D32ProfileNoReparsePath -Path $tempFull)) { throw 'CARGO_HOME/TEMP paths are missing or traverse reparse points' }
    if (-not (Test-D32ProfilePathEqual -Left ([IO.Path]::GetDirectoryName($cargoHomeFull)) -Right ([IO.Path]::GetDirectoryName($tempFull)))) { throw 'CARGO_HOME and TEMP must be siblings within the external evidence run root' }
    $native = $profile.native
    $pathEntries = @((Join-Path ([string]$profile.rust_toolchain_root) 'bin')) + @($native.path_entries | ForEach-Object { [string]$_ })
    $environment = [ordered]@{
        SystemRoot = [string]$profile.system_root
        TEMP = $tempFull
        TMP = $tempFull
        PATH = $pathEntries -join [IO.Path]::PathSeparator
        INCLUDE = @($native.include_dirs | ForEach-Object { [string]$_ }) -join ';'
        LIB = @($native.lib_dirs | ForEach-Object { [string]$_ }) -join ';'
        LIBPATH = @($native.libpath_dirs | ForEach-Object { [string]$_ }) -join ';'
        CARGO_HOME = $cargoHomeFull
        RUSTC = [string]$profile.toolchain.rustc.path
        RUSTDOC = [string]$profile.toolchain.rustdoc.path
        CARGO_NET_OFFLINE = if ($Offline) { 'true' } else { 'false' }
    }
    foreach ($entry in $native.environment.PSObject.Properties) { $environment[[string]$entry.Name] = [string]$entry.Value }
    $allowed = @('SystemRoot', 'TEMP', 'TMP', 'PATH', 'INCLUDE', 'LIB', 'LIBPATH', 'CARGO_HOME', 'RUSTC', 'RUSTDOC', 'CARGO_NET_OFFLINE') + @($native.environment.PSObject.Properties | ForEach-Object { [string]$_.Name })
    if (@($environment.Keys | Where-Object { $allowed -cnotcontains $_ }).Count -ne 0) { throw 'constructed child environment contains an unapproved variable' }
    return $environment
}

function New-D32FreshCargoHome {
    param([Parameter(Mandatory = $true)][string]$RunRoot, [Parameter(Mandatory = $true)][string]$Repository)

    $root = Assert-D32ProfileDirectory -Path $RunRoot
    $path = Join-Path $root 'cargo-home'
    if (Test-Path -LiteralPath $path) { throw 'fresh external CARGO_HOME already exists' }
    [void][IO.Directory]::CreateDirectory($path)
    if (-not (Test-D32ProfileNoReparsePath -Path $path)) { throw 'fresh CARGO_HOME creation traversed a reparse point' }
    $check = Test-D32CargoHome -Path $path -Repository $Repository -RequireEmpty
    return $check.Path
}

function New-D32BuildToolchainProfileSelfTestIdentity {
    param([string]$Name, [string]$Path, [string]$Reason)

    $snapshot = Get-D32ProfileFileSnapshot -Path $Path
    return [ordered]@{
        name = $Name
        path = $snapshot.Path
        sha256 = $snapshot.Sha256
        bytes = [Int64]$snapshot.Bytes
        volume_serial_hex = $snapshot.VolumeSerialHex
        file_id_hex = $snapshot.FileIdHex
        reason = $Reason
    }
}

function Test-D32BuildToolchainProfileSelfTest {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Repository,
        [AllowNull()][ref]$ValidatedProfileOutput
    )

    $cases = [System.Collections.Generic.List[object]]::new()
    $case = { param([string]$Name, [bool]$Passed, [AllowNull()][string]$Detail = $null) $cases.Add([PSCustomObject]@{ Name = $Name; Passed = $Passed; Detail = $Detail }) }.GetNewClosure()
    $testRoot = Join-Path $Root 'd32-build-profile-selftest'
    if (Test-Path -LiteralPath $testRoot) { throw 'profile self-test root already exists under its owned outer root' }
    [void][IO.Directory]::CreateDirectory($testRoot)
    if (-not (Test-D32ProfileNoReparsePath -Path $testRoot)) { throw 'profile self-test root is missing or reparse-backed' }

    $rustRoot = Join-Path $testRoot 'rust'
    $rustBin = Join-Path $rustRoot 'bin'
    $msvcRoot = Join-Path $testRoot 'msvc'
    $sdkRoot = Join-Path $testRoot 'windows-sdk'
    $msvcBin = Join-Path $msvcRoot 'bin'
    $sdkBin = Join-Path $sdkRoot 'bin'
    foreach ($directory in @($rustBin, $msvcBin, $sdkBin, (Join-Path $msvcRoot 'include'), (Join-Path $sdkRoot 'include'), (Join-Path $msvcRoot 'lib'), (Join-Path $sdkRoot 'lib'), (Join-Path $msvcRoot 'libpath'), (Join-Path $sdkRoot 'libpath'))) {
        [void][IO.Directory]::CreateDirectory($directory)
    }
    $toolRecords = [System.Collections.Generic.List[object]]::new()
    $toolImages = [System.Collections.Generic.List[object]]::new()
    foreach ($name in @('cargo.exe', 'rustc.exe', 'rustdoc.exe')) {
        $path = Join-Path $rustBin $name
        [IO.File]::WriteAllBytes($path, [Text.Encoding]::UTF8.GetBytes("profile-selftest-$name"))
        $record = New-D32BuildToolchainProfileSelfTestIdentity -Name $name -Path $path -Reason "direct pinned $($name.Substring(0, $name.Length - 4)) executable"
        $toolRecords.Add($record)
        $toolImages.Add($record)
    }
    $nativeImages = [System.Collections.Generic.List[object]]::new()
    $nativeImagePaths = [ordered]@{}
    foreach ($name in @('cl.exe', 'link.exe', 'lib.exe')) {
        $path = Join-Path $msvcBin $name
        [IO.File]::WriteAllBytes($path, [Text.Encoding]::UTF8.GetBytes("profile-selftest-$name"))
        $nativeImagePaths[$name] = $path
        $nativeImages.Add((New-D32BuildToolchainProfileSelfTestIdentity -Name $name -Path $path -Reason "self-test pinned $name"))
    }
    foreach ($name in @('rc.exe', 'mt.exe')) {
        $path = Join-Path $sdkBin $name
        [IO.File]::WriteAllBytes($path, [Text.Encoding]::UTF8.GetBytes("profile-selftest-$name"))
        $nativeImagePaths[$name] = $path
        $nativeImages.Add((New-D32BuildToolchainProfileSelfTestIdentity -Name $name -Path $path -Reason "self-test pinned $name"))
    }
    $scriptPaths = @(
        (Join-Path $rustBin 'rust-windbg.cmd'),
        (Join-Path $sdkBin 'sdk-setup.cmd'),
        (Join-Path $sdkBin 'sdk-debug.cmd')
    )
    foreach ($scriptPath in $scriptPaths) { [IO.File]::WriteAllText($scriptPath, '@rem dormant profile self-test') }
    $scriptRecords = [System.Collections.Generic.List[object]]::new()
    foreach ($scriptSnapshot in @(Get-D32ProfileCurrentScriptInventory -Directories @($rustBin, $msvcBin, $sdkBin))) {
        $scriptRecords.Add([ordered]@{
            name = [IO.Path]::GetFileName($scriptSnapshot.Path)
            path = $scriptSnapshot.Path
            sha256 = $scriptSnapshot.Sha256
            bytes = [Int64]$scriptSnapshot.Bytes
            volume_serial_hex = $scriptSnapshot.VolumeSerialHex
            file_id_hex = $scriptSnapshot.FileIdHex
            reason = 'dormant script inventory only; never launchable'
        })
    }

    $lockInputs = @(Get-D32BuildToolchainLockInputs -Repository $Repository)
    $gitSourceCount = ($lockInputs | Measure-Object -Property GitSourceCount -Sum).Sum
    $validGitLockCount = Test-D32CargoLockGitSources -LockText "[[package]]`nname = `"pinned`"`nversion = `"1.0.0`"`nsource = `"git+https://example.invalid/repo?rev=0123456789abcdef0123456789abcdef01234567#0123456789abcdef0123456789abcdef01234567`""
    $badGitLockRejected = $false
    try { $null = Test-D32CargoLockGitSources -LockText "[[package]]`nname = `"unlocked`"`nversion = `"1.0.0`"`nsource = `"git+https://example.invalid/repo?branch=main#main`"" }
    catch { $badGitLockRejected = $_.Exception.Message -like '*without a full immutable*' }
    & $case 'Cargo.lock Git sources require an immutable full commit ID' ($validGitLockCount -eq 1 -and $badGitLockRejected -and $gitSourceCount -gt 0)
    $windowsRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows))
    $conhost = New-D32BuildToolchainProfileSelfTestIdentity -Name 'conhost.exe' -Path (Join-Path $windowsRoot 'System32\conhost.exe') -Reason 'direct pinned Windows console host child image'
    $currentPowerShellPath = Get-D32CurrentPowerShellImagePath
    $powershellRoot = [IO.Path]::GetDirectoryName($currentPowerShellPath)
    $powershellIdentity = New-D32BuildToolchainProfileSelfTestIdentity -Name 'pwsh.exe' -Path $currentPowerShellPath -Reason 'direct pinned PowerShell host executable'
    $document = [ordered]@{
        schema_version = 2
        profile_type = 'D32_BUILD_TOOLCHAIN_PROFILE_V2'
        target_triple = 'x86_64-pc-windows-msvc'
        system_root = $windowsRoot
        powershell_root = $powershellRoot
        powershell = $powershellIdentity
        rust_toolchain_root = $rustRoot
        toolchain = [ordered]@{ cargo = $toolRecords[0]; rustc = $toolRecords[1]; rustdoc = $toolRecords[2] }
        rust_toolchain_bin_images = @($toolImages.ToArray())
        native_roots = @(
            [ordered]@{ name = 'msvc'; path = $msvcRoot },
            [ordered]@{ name = 'windows-sdk'; path = $sdkRoot }
        )
        native = [ordered]@{
            path_entries = @($msvcBin, $sdkBin)
            include_dirs = @((Join-Path $msvcRoot 'include'), (Join-Path $sdkRoot 'include'))
            lib_dirs = @((Join-Path $msvcRoot 'lib'), (Join-Path $sdkRoot 'lib'))
            libpath_dirs = @((Join-Path $msvcRoot 'libpath'), (Join-Path $sdkRoot 'libpath'))
            environment = [ordered]@{
                VCToolsInstallDir = $msvcRoot
                WindowsSdkDir = $sdkRoot
                VCToolsVersion = '14.44.35207'
                WindowsSDKVersion = '10.0.26100.0'
                VSCMD_ARG_TGT_ARCH = 'x64'
            }
            path_images = @($nativeImages.ToArray())
            path_scripts = @($scriptRecords.ToArray())
        }
        windows_child_images = @($conhost)
        fetch_manifests = @($lockInputs | ForEach-Object { [ordered]@{ manifest_path = $_.ManifestPath; lock_sha256 = $_.LockSha256 } })
        fetch_git = $null
        env_policy = 'D32_BUILD_ENV_V1'
        cargo_policy = 'FRESH_HOME_LOCKED_FETCH_OFFLINE_AFTER'
    }
    $profilePath = Join-Path $testRoot 'caller-pinned-profile.json'
    $runDocument = {
        param([object]$Value, [AllowNull()][object]$RawJson)
        if ($RawJson -is [string]) { [IO.File]::WriteAllText($profilePath, $RawJson, [Text.UTF8Encoding]::new($false)) }
        else { [IO.File]::WriteAllText($profilePath, ($Value | ConvertTo-Json -Depth 20 -Compress), [Text.UTF8Encoding]::new($false)) }
        $hash = (Get-D32ProfileFileSnapshot -Path $profilePath).Sha256
        return Test-D32BuildToolchainProfile -ProfilePath $profilePath -ExpectedSha256 $hash -Repository $Repository -EvidenceRoot $Root
    }

    $valid = & $runDocument $document $null
    & $case 'valid caller-pinned profile and opened-handle identities' ([bool]$valid.IsValid)
    if (-not $valid.IsValid) { throw "profile self-test baseline profile was rejected: $($valid.Failure)" }
    $expectedManifestPaths = @($lockInputs | ForEach-Object { [string]$_.ManifestFullPath })
    $validatedLockShapesExact = @($valid.LockInputs | Where-Object {
        -not (Test-D32ProfileExactProperties -Object $_ -Expected @('ManifestPath', 'ManifestFullPath', 'LockPath', 'LockSha256', 'LockBytes'))
    }).Count -eq 0
    $validatedManifestPaths = @($valid.LockInputs | ForEach-Object {
        $manifestPathProperty = $_.PSObject.Properties['ManifestFullPath']
        if ($null -eq $manifestPathProperty) { '' } else { [string]$manifestPathProperty.Value }
    })
    $validatedManifestPathsExact = $validatedLockShapesExact -and
        $valid.LockInputs.Count -eq 3 -and $expectedManifestPaths.Count -eq 3 -and
        (($validatedManifestPaths -join "`0") -ceq ($expectedManifestPaths -join "`0"))
    & $case 'validated lock inputs preserve all three trusted full manifest paths' $validatedManifestPathsExact
    $wireLockShapesExact = @($valid.Profile.fetch_manifests | Where-Object {
        -not (Test-D32ProfileExactProperties -Object $_ -Expected @('manifest_path', 'lock_sha256'))
    }).Count -eq 0 -and $valid.Profile.fetch_manifests.Count -eq 3
    & $case 'profile v2 locked-fetch wire records remain exact two-field entries' $wireLockShapesExact
    $oldV1 = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $oldV1.schema_version = 1
    $oldV1.profile_type = 'D32_BUILD_TOOLCHAIN_PROFILE_V1'
    $oldResult = & $runDocument $oldV1 $null
    & $case 'profile rejects legacy v1 without dormant-script authority separation' (-not $oldResult.IsValid -and $oldResult.Failure -like '*legacy v1*')
    & $case 'profile accepts pinned resident .cmd/.bat files as dormant-only identities' ($valid.ScriptInventory.Count -eq 3 -and @($valid.ScriptInventory | Where-Object { [IO.Path]::GetExtension($_.Path) -notin @('.cmd', '.bat') }).Count -eq 0)
    $dormantScriptPath = $scriptPaths[0]
    $dormantScriptBytes = [IO.File]::ReadAllBytes($dormantScriptPath)
    [IO.File]::AppendAllText($dormantScriptPath, "`r`n@rem changed after pin")
    try {
        $scriptChanged = & $runDocument $document $null
        & $case 'profile revalidates dormant script bytes and file identity' (-not $scriptChanged.IsValid -and $scriptChanged.Failure -like '*does not match current opened-handle bytes/file ID*')
    }
    finally { [IO.File]::WriteAllBytes($dormantScriptPath, $dormantScriptBytes) }
    & $case 'profile rejects same-bytes replacement with restored metadata' $false
    $cargoPath = Join-Path $rustBin 'cargo.exe'
    $cargoOriginalSnapshot = Get-D32ProfileFileSnapshot -Path $cargoPath
    $cargoBytes = [IO.File]::ReadAllBytes($cargoPath)
    $backupPath = Join-Path $testRoot 'cargo-original.backup'
    $replacementPath = Join-Path $testRoot 'cargo-replacement.tmp'
    [IO.File]::WriteAllBytes($replacementPath, $cargoBytes)
    [IO.File]::Move($cargoPath, $backupPath)
    try {
        [IO.File]::Move($replacementPath, $cargoPath)
        [IO.File]::SetCreationTimeUtc($cargoPath, [DateTime]::new($cargoOriginalSnapshot.CreationTimeUtcTicks, [DateTimeKind]::Utc))
        [IO.File]::SetLastWriteTimeUtc($cargoPath, [DateTime]::new($cargoOriginalSnapshot.LastWriteTimeUtcTicks, [DateTimeKind]::Utc))
        $replacement = & $runDocument $document $null
        $caseText = [string]$replacement.Failure
        $cases[$cases.Count - 1].Passed = ($caseText -like '*does not match current opened-handle bytes/file ID*')
    }
    finally {
        if (Test-Path -LiteralPath $cargoPath) { [IO.File]::Delete($cargoPath) }
        if (Test-Path -LiteralPath $backupPath) { [IO.File]::Move($backupPath, $cargoPath) }
        if (Test-Path -LiteralPath $replacementPath) { [IO.File]::Delete($replacementPath) }
    }

    $badHash = Test-D32BuildToolchainProfile -ProfilePath $profilePath -ExpectedSha256 ('0' * 64) -Repository $Repository -EvidenceRoot $Root
    & $case 'profile requires independent exact SHA-256' (-not $badHash.IsValid -and $badHash.Failure -like '*independently supplied expected SHA-256*')
    $wrongPowerShell = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $wrongPowerShell.powershell.sha256 = '0' * 64
    $result = & $runDocument $wrongPowerShell $null
    & $case 'profile rejects current PowerShell host SHA mismatch' (-not $result.IsValid -and $result.Failure -like '*does not match current opened-handle bytes/file ID*')
    $extra = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $extra | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
    $result = & $runDocument $extra $null
    & $case 'profile rejects extra top-level fields' (-not $result.IsValid -and $result.Failure -like '*missing or extra fields*')
    $missing = ($document | ConvertTo-Json -Depth 20 -Compress) | ConvertFrom-Json -AsHashtable -DateKind String
    [void]$missing.Remove('fetch_git')
    $result = & $runDocument $missing $null
    & $case 'profile rejects missing top-level fields' (-not $result.IsValid -and $result.Failure -like '*missing or extra fields*')
    $wrongType = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $wrongType.toolchain.cargo.bytes = 'not-an-integer'
    $result = & $runDocument $wrongType $null
    & $case 'profile rejects wrong identity scalar types' (-not $result.IsValid -and $result.Failure -like '*must be a JSON integer*')
    $wrongToolHash = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $wrongToolHash.toolchain.rustc.sha256 = '0' * 64
    $result = & $runDocument $wrongToolHash $null
    & $case 'profile rejects pinned tool SHA mismatch' (-not $result.IsValid -and $result.Failure -like '*does not match current opened-handle bytes/file ID*')
    $wrongToolBytes = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $wrongToolBytes.toolchain.rustdoc.bytes = [Int64]$wrongToolBytes.toolchain.rustdoc.bytes + 1
    $result = & $runDocument $wrongToolBytes $null
    & $case 'profile rejects pinned tool byte-count mismatch' (-not $result.IsValid -and $result.Failure -like '*does not match current opened-handle bytes/file ID*')
    $wrongToolFileId = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $wrongToolFileId.toolchain.cargo.file_id_hex = '0' * 32
    $result = & $runDocument $wrongToolFileId $null
    & $case 'profile rejects pinned tool opened-handle file-ID mismatch' (-not $result.IsValid -and $result.Failure -like '*does not match current opened-handle bytes/file ID*')
    $missingInventoryImage = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $missingInventoryImage.rust_toolchain_bin_images = @($missingInventoryImage.rust_toolchain_bin_images | Where-Object { $_.name -cne 'rustdoc.exe' })
    $result = & $runDocument $missingInventoryImage $null
    & $case 'profile rejects missing executable from Rust PATH inventory' (-not $result.IsValid -and $result.Failure -like '*does not exactly cover every executable*')
    $wrongArray = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $wrongArray.rust_toolchain_bin_images = 'not-an-array'
    $result = & $runDocument $wrongArray $null
    & $case 'profile rejects wrong PATH-image array type' (-not $result.IsValid -and $result.Failure -like '*must be a JSON array*')
    $duplicateJson = $document | ConvertTo-Json -Depth 20 -Compress
    $duplicateJson = $duplicateJson.Replace('"schema_version":2', '"schema_version":2,"schema_version":2')
    $result = & $runDocument $null $duplicateJson
    & $case 'profile rejects duplicate JSON object keys' (-not $result.IsValid -and $result.Failure -like '*duplicate object keys*')

    $badEnvironment = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $badEnvironment.native.environment | Add-Member -NotePropertyName CL -NotePropertyValue '/Dunsafe'
    $result = & $runDocument $badEnvironment $null
    & $case 'profile rejects compiler/linker option injection variables' (-not $result.IsValid -and $result.Failure -like '*not approved*')
    $wrongNestedArray = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $wrongNestedArray.native.path_images = 'not-an-array'
    $result = & $runDocument $wrongNestedArray $null
    & $case 'profile rejects nested PATH-image array type mismatch' (-not $result.IsValid -and $result.Failure -like '*must be a JSON array*')
    $missingNativeImage = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $missingNativeImage.native.path_images = @($missingNativeImage.native.path_images | Where-Object { [IO.Path]::GetFileName($_.path) -ine 'mt.exe' })
    $result = & $runDocument $missingNativeImage $null
    & $case 'profile rejects missing executable from native PATH inventory' (-not $result.IsValid -and $result.Failure -like '*does not exactly cover every executable*')
    $wrongTarget = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $wrongTarget.target_triple = 'aarch64-pc-windows-msvc'
    $result = & $runDocument $wrongTarget $null
    & $case 'profile rejects wrong target triple' (-not $result.IsValid -and $result.Failure -like '*target_triple must equal*')
    $staleLock = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($document))
    $staleLock.fetch_manifests[0].lock_sha256 = '0' * 64
    $result = & $runDocument $staleLock $null
    $staleLockPassed = (-not $result.IsValid -and $result.Failure -match 'fetch_manifests\[0\].*manifest/lock SHA')
    & $case 'profile rejects changed/stale Cargo.lock SHA' $staleLockPassed ([string]$result.Failure)
    $unapprovedPathImage = Join-Path $msvcBin 'unapproved.exe'
    [IO.File]::WriteAllBytes($unapprovedPathImage, [Text.Encoding]::UTF8.GetBytes('unapproved-profile-selftest-image'))
    try {
        $result = & $runDocument $document $null
        & $case 'profile rejects an unpinned executable added to PATH' (-not $result.IsValid -and $result.Failure -like '*does not exactly cover every executable*')
    }
    finally { if (Test-Path -LiteralPath $unapprovedPathImage) { [IO.File]::Delete($unapprovedPathImage) } }

    $batchPath = Join-Path $rustBin 'implicit.cmd'
    [IO.File]::WriteAllText($batchPath, '@echo off')
    try {
        $result = & $runDocument $document $null
        & $case 'profile rejects an unpinned dormant command script reachable through PATH' (-not $result.IsValid -and $result.Failure -like '*does not exactly cover every dormant*')
    }
    finally { if (Test-Path -LiteralPath $batchPath) { [IO.File]::Delete($batchPath) } }

    $cargoHome = Join-Path $testRoot 'run\cargo-home'
    $tempRoot = Join-Path $testRoot 'run\temp'
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $cargoHome))
    [void][IO.Directory]::CreateDirectory($cargoHome)
    [void][IO.Directory]::CreateDirectory($tempRoot)
    $valid = & $runDocument $document $null
    if ($null -ne $ValidatedProfileOutput) { $ValidatedProfileOutput.Value = $valid }
    $environment = Get-D32BuildToolchainEnvironment -ValidatedProfile $valid -CargoHome $cargoHome -TempRoot $tempRoot -Offline $true
    $allowedEnvironment = @('SystemRoot', 'TEMP', 'TMP', 'PATH', 'INCLUDE', 'LIB', 'LIBPATH', 'CARGO_HOME', 'RUSTC', 'RUSTDOC', 'CARGO_NET_OFFLINE', 'VCToolsInstallDir', 'WindowsSdkDir', 'VCToolsVersion', 'WindowsSDKVersion', 'VSCMD_ARG_TGT_ARCH')
    & $case 'constructed child environment contains only explicit allowlisted variables' (@($environment.Keys | Where-Object { $allowedEnvironment -cnotcontains $_ }).Count -eq 0 -and $environment.CARGO_NET_OFFLINE -ceq 'true')
    $null = Test-D32CargoHome -Path $cargoHome -Repository $Repository -RequireEmpty
    [IO.File]::WriteAllText((Join-Path $cargoHome 'user-data'), 'seed')
    $emptyRejected = $false
    try { $null = Test-D32CargoHome -Path $cargoHome -Repository $Repository -RequireEmpty }
    catch { $emptyRejected = $_.Exception.Message -like '*must be empty*' }
    & $case 'fresh CARGO_HOME must be empty before the locked fetch' $emptyRejected

    return @($cases.ToArray())
}
